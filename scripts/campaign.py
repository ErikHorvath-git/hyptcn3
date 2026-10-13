#!/usr/bin/env python3
"""Frozen benign collection campaign: reboot, capture, audit, archive, index.

init/status need no root. launch/run need sudo for host eBPF, and use the
original user's libvirt session. A failed capture or rejected audit stops the
allocation; retries never silently replace a research session.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import collection
from scripts.collection_archive import (archive_session, digest, guard_mount, mount_identity,
                                        now, read_json, sync_dir, verify_archive, write_new)

BASE = ROOT / "data/campaigns"
COLLECTIONS = ROOT / "data/collections"
UNIT = "hyptcn-collection.service"


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def tree_hashes(directory):
    return {str(f.relative_to(directory)): digest(f) for f in sorted(directory.rglob("*")) if f.is_file()}


def extractor_hashes():
    return {str(f.relative_to(ROOT)): digest(f) for d in ("features", "guestparse")
            for f in (ROOT / d).rglob("*.py") if "tests" not in f.parts}


def runtime_identity():
    packages = subprocess.check_output(collection.user_command([
        sys.executable, "-c", "import importlib.metadata,json; "
        "print(json.dumps({p:importlib.metadata.version(p) for p in ('numpy','torch')}))"
    ]), text=True, timeout=30)
    return {"host": platform.platform(), "python": sys.version,
            "packages": json.loads(packages),
            "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect")}


def guest_environment(identity):
    return {k: v for k, v in identity.items() if k != "boot_id"}


def pilot_gate(path, protocol_path, p):
    report = read_json(path)
    v = report["values"]
    if (report.get("schema") != "hyptcn3/collection-audit/1" or v.get("accepted") is not True
            or v.get("role") != "pilot" or v["protocol_sha256"] != digest(protocol_path)
            or v["snapshots"] != p["pilot_cycles"]
            or v["score_coverage"] < p["min_score_coverage"]
            or v["quality"]["policy"] != p["quality_policy"]
            or v["quality"]["behavior_valid_rows"] != p["pilot_cycles"]
            or v["quality"]["integrity_findings"] != 0
            or v["extractor_sha256"] != extractor_hashes()):
        raise ValueError("accepted pilot with current extractor and frozen protocol required")
    session = Path(v["session_dir"]) / "session.json"
    if digest(session) != v["session_sha256"] or digest(v["features"]) != v["features_sha256"]:
        raise ValueError("pilot metadata or features changed since audit")
    meta = read_json(session)
    if (tree_hashes(ROOT / p["profile"]) != meta["profile_sha256"]
            or digest(ROOT / "vmicollect/build/vmicollect") != meta["collector_sha256"]):
        raise ValueError("pilot collector or profile differs from current environment")
    return meta, v["raw_bytes"] * p["cycles"] / p["pilot_cycles"] * 1.5


def capacity_guard(manifest, p, remaining):
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    reserve = p["min_free_gib"] * 2**30
    needed = manifest["estimated_session_bytes_with_reserve"]
    if shutil.disk_usage(COLLECTIONS).free < needed + reserve:
        raise ValueError("insufficient internal working space for the next session")
    if shutil.disk_usage(manifest["archive_root"]).free < needed * remaining + reserve:
        raise ValueError("insufficient external space for remaining campaign estimate")


def initialize(a):
    if git("status", "--porcelain"):
        raise ValueError("commit the source and documentation before freezing a campaign")
    p = collection.protocol(a.protocol)
    meta, needed = pilot_gate(a.pilot_report, a.protocol, p)
    identity = collection.guest_identity(p)
    if guest_environment(identity) != guest_environment(meta["guest_before"]):
        raise ValueError("guest environment differs from accepted pilot")
    name = a.name or stamp() + "_benign_v2"
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name):
        raise ValueError("invalid campaign name")
    archive_root = Path(a.archive_root).absolute()
    mount = mount_identity(archive_root)
    owner = pwd.getpwuid(int(os.environ.get("SUDO_UID", os.getuid())))
    directory = BASE / name
    planned = collection.plan(p)
    for i, row in enumerate(planned["sessions"]):
        row["session_id"] = f"{name}_{i + 1:02d}_{row['role']}_{row['scenario']}"
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": name, "date": now(),
                "commit": git("rev-parse", "HEAD"), "runtime": runtime_identity(),
                "owner": {"name": owner.pw_name, "uid": owner.pw_uid, "gid": owner.pw_gid},
                "workspace": str(ROOT), "protocol_sha256": digest(a.protocol),
                "pilot_report_sha256": digest(a.pilot_report), "pilot_source": str(Path(a.pilot_report).resolve()),
                "profile_sha256": meta["profile_sha256"], "extractor_sha256": extractor_hashes(),
                "guest_environment": guest_environment(identity),
                "archive_root": str(archive_root), "archive_mount": mount,
                "archive_dir": str(archive_root / "campaigns" / name),
                "estimated_session_bytes_with_reserve": needed,
                "sessions": planned["sessions"], "planned_capture_hours": planned["planned_hours"],
                "note": "Frozen allocation, not a measurement or a completed corpus."}
    COLLECTIONS.mkdir(exist_ok=True, parents=True)
    archive_root.mkdir(exist_ok=True, parents=True)
    capacity_guard(manifest, p, len(planned["sessions"]))
    # Reusing group names from another campaign would violate boot isolation.
    groups = {r["group"] for r in planned["sessions"]}
    for old in COLLECTIONS.glob("*/session.json"):
        if read_json(old)["group"] in groups:
            raise ValueError("planned group already has data; resume its original campaign: " + str(old))
    directory.mkdir(parents=True)
    for child in ("events", "groups", "attempts", "logs"):
        (directory / child).mkdir()
    copy_exclusive(Path(a.protocol), directory / "protocol.json")
    copy_exclusive(Path(a.pilot_report), directory / "pilot.json")
    write_new(directory / "plan.json", planned)
    write_new(directory / "campaign.json", manifest)
    external = Path(manifest["archive_dir"])
    guard_mount(archive_root, mount)
    external.mkdir(parents=True)
    for filename in ("campaign.json", "protocol.json", "pilot.json", "plan.json"):
        copy_exclusive(directory / filename, external / filename)
    update_state(directory, status="ready", stage="initialized", accepted_archived=0,
                 total=len(planned["sessions"]))
    print(json.dumps({"campaign": str(directory), "sessions": len(planned["sessions"]),
                      "capture_hours": planned["planned_hours"],
                      "archive": str(external)}, indent=2))
    return directory


def copy_exclusive(source, destination):
    if destination.exists():
        if digest(source) != digest(destination):
            raise ValueError("existing campaign backup differs: " + str(destination))
        return
    temp = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    before = digest(source)
    try:
        with source.open("rb") as src, temp.open("xb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        if digest(source) != before or digest(temp) != before:
            raise ValueError("campaign backup checksum mismatch")
        os.link(temp, destination)
        temp.unlink()
        sync_dir(destination.parent)
    finally:
        temp.unlink(missing_ok=True)


def load_campaign(directory):
    directory = Path(directory).resolve()
    m = read_json(directory / "campaign.json")
    if m.get("schema") != "hyptcn3/collection-campaign/1" or m["workspace"] != str(ROOT):
        raise ValueError("campaign schema/workspace mismatch")
    p = collection.protocol(directory / "protocol.json")
    expected = collection.plan(p)["sessions"]
    rows = [{k: v for k, v in row.items() if k != "session_id"} for row in m["sessions"]]
    if (m["id"] != directory.name or rows != expected
            or digest(directory / "protocol.json") != m["protocol_sha256"]
            or digest(directory / "pilot.json") != m["pilot_report_sha256"]):
        raise ValueError("campaign plan or frozen inputs changed")
    if len({r["session_id"] for r in m["sessions"]}) != len(rows):
        raise ValueError("duplicate campaign session IDs")
    for row in m["sessions"]:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}", row["session_id"]):
            raise ValueError("unsafe session ID")
    return m, p


def verify_frozen(directory, manifest, p):
    if git("rev-parse", "HEAD") != manifest["commit"] or git("status", "--porcelain"):
        raise ValueError("campaign source changed; restore frozen commit before resuming")
    if (runtime_identity() != manifest["runtime"]
            or tree_hashes(ROOT / p["profile"]) != manifest["profile_sha256"]
            or extractor_hashes() != manifest["extractor_sha256"]):
        raise ValueError("campaign runtime, profile or extractor changed")
    # External copy also detects accidental changes to the local immutable plan.
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    external = Path(manifest["archive_dir"])
    for name in ("campaign.json", "protocol.json", "pilot.json", "plan.json"):
        if digest(directory / name) != digest(external / name):
            raise ValueError("frozen campaign backup mismatch: " + name)


def update_state(directory, **values):
    path = directory / "status.json"
    previous = read_json(path) if path.exists() else {}
    state = {**previous, **values, "updated_at": now()}
    write_new(path, state, replace=True)
    event = {"schema": "hyptcn3/campaign-event/1", **state}
    write_new(directory / "events" / f"{stamp()}_{uuid.uuid4().hex[:8]}.json", event)
    print(json.dumps({k: state[k] for k in ("updated_at", "status", "stage", "session", "message")
                      if k in state}), flush=True)


def process_identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return {"host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "start_ticks": text.rsplit(")", 1)[1].split()[19]}
    except OSError:
        return None


def run_child(command, log, *, timeout, guard=lambda: None, lock_fd=None):
    env = dict(os.environ)
    env.pop("HYPTCN_COLLECTION_LOCK_FD", None)
    if lock_fd is not None:
        env["HYPTCN_COLLECTION_LOCK_FD"] = str(lock_fd)
    with log.open("x") as stream:
        process = subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   pass_fds=() if lock_fd is None else (lock_fd,))
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                guard()
                if time.monotonic() >= deadline:
                    raise TimeoutError("campaign stage timed out: " + str(log))
                time.sleep(2)
            return process.returncode
        finally:
            # A crashed parent script may leave traffic/capture grandchildren.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def ensure_group(directory, manifest, p, row):
    ready = directory / "groups" / (row["group"] + ".json")
    current = collection.guest_identity(p)
    if guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("guest environment changed")
    if ready.exists():
        if current != read_json(ready)["identity"]:
            raise ValueError("boot changed inside a group; preserve partial allocation for review")
        return current
    intent = ready.with_suffix(".reboot-intent.json")
    if intent.exists():
        before = read_json(intent)["previous_boot"]
    else:
        before = current["boot_id"]
        write_new(intent, {"group": row["group"], "previous_boot": before, "date": now()})
    update_state(directory, status="running", stage="reboot", group=row["group"])
    if current["boot_id"] == before:
        command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", "reboot",
                                           "--domain", p["domain"]])
        rc = run_child(command, directory / "logs" / f"reboot_{stamp()}.log", timeout=240)
        if rc:
            raise ValueError("lab reboot failed; see campaign reboot log")
        current = collection.guest_identity(p)
    if current["boot_id"] == before or guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("new group requires a new boot with the frozen guest environment")
    for existing in COLLECTIONS.glob("*/session.json"):
        if read_json(existing)["guest_before"]["boot_id"] == current["boot_id"]:
            raise ValueError("new group boot already belongs to another session")
    write_new(ready, {"schema": "hyptcn3/campaign-group/1", "date": now(), "group": row["group"],
                      "role": row["role"], "identity": current, "previous_boot": before})
    return current


def check_session(path, manifest, row, directory):
    meta = read_json(path / "session.json")
    for k in ("role", "group", "scenario", "seed", "session_id"):
        if meta[k] != row[k]:
            raise ValueError("session differs from frozen assignment: " + k)
    if (meta.get("campaign_id") != manifest["id"] or meta["commit"] != manifest["commit"]
            or meta["commit_dirty"] or meta["protocol_sha256"] != manifest["protocol_sha256"]
            or guest_environment(meta["guest_before"]) != manifest["guest_environment"]):
        raise ValueError("session provenance differs from frozen campaign")
    group = read_json(directory / "groups" / (row["group"] + ".json"))
    if meta["guest_before"] != group["identity"]:
        raise ValueError("session boot differs from recorded campaign group")
    end = read_json(path / "end.json") if (path / "end.json").exists() else {}
    return bool(end.get("completed") and end.get("guest_after") == meta["guest_before"])


def audit_capture(directory, manifest, p, row, session, guard):
    pointer = directory / "attempts" / (row["session_id"] + ".audit.json")
    if pointer.exists():
        selected = read_json(pointer)
        report = Path(selected["path"])
        if digest(report) != selected["sha256"]:
            raise ValueError("selected audit changed")
    else:
        # Recover a completed verdict if interrupted before pointer publication.
        reports = sorted(session.glob("campaign_audit_*.json"))
        complete = []
        for report in reports:
            try:
                doc = read_json(report)
            except json.JSONDecodeError:
                continue  # Interrupted write retained; next attempt uses a new path.
            if doc.get("schema") == "hyptcn3/collection-audit/1":
                complete.append(report)
        if len(complete) > 1:
            raise ValueError("multiple campaign audit verdicts require review")
        if complete:
            report = complete[0]
        else:
            report = session / f"campaign_audit_{stamp()}.json"
            update_state(directory, status="running", stage="audit", session=session.name)
            command = collection.user_command([sys.executable, ROOT / "scripts/collection.py",
                                               "--protocol", directory / "protocol.json",
                                               "audit", session, "--out", report])
            rc = run_child(command, directory / "logs" / f"audit_{stamp()}.log",
                           timeout=max(600, p["cycles"] * 15), guard=guard)
            if rc not in (0, 2) or not report.exists():
                raise ValueError("audit did not produce a verdict; see campaign log")
    doc = read_json(report)
    v = doc["values"]
    if (v["protocol_sha256"] != manifest["protocol_sha256"] or doc["commit"] != manifest["commit"]
            or doc["commit_dirty"] or v["extractor_sha256"] != manifest["extractor_sha256"]
            or v["session_dir"] != str(session) or v["role"] != row["role"]
            or v["session_sha256"] != digest(session / "session.json")
            or digest(v["features"]) != v["features_sha256"]):
        raise ValueError("audit provenance differs from campaign/session")
    if not pointer.exists():
        write_new(pointer, {"path": str(report), "sha256": digest(report)})
    return report, v


def archive_capture(directory, manifest, session, p, audit=None):
    update_state(directory, status="running", stage="archive", session=session.name)
    destination = Path(manifest["archive_dir"]) / "collections" / session.name
    guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
    return archive_session(session, destination, guard, reclaim=True, campaign_id=manifest["id"],
                           audit=audit, reserve_bytes=p["min_free_gib"] * 2**30)


def execute(directory, *, stop_after=None):
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("run with sudo from the campaign owner's account")
    def interrupted(signum, _frame):
        raise InterruptedError(f"campaign interrupted by signal {signum}")
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    owns_lock = False
    try:
        with collection.collection_lock(COLLECTIONS) as lock_fd:
            owns_lock = True
            verify_frozen(directory, manifest, p)
            update_state(directory, status="running", stage="preflight", pid=os.getpid(),
                         process_identity=process_identity(os.getpid()), message=None)
            reports = []
            processed = 0
            guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
            for i, row in enumerate(manifest["sessions"]):
                session = COLLECTIONS / row["session_id"]
                checkpoint = directory / "attempts" / (row["session_id"] + ".done.json")
                if checkpoint.exists():
                    done = read_json(checkpoint)
                    if not check_session(session, manifest, row, directory):
                        raise ValueError("completed session lost its provenance")
                    report, values = audit_capture(directory, manifest, p, row, session, guard)
                    destination = Path(manifest["archive_dir"]) / "collections" / session.name
                    if (not values["accepted"] or digest(destination / "archive-manifest.json") != done["manifest_sha256"]
                            or not (session / "raw").is_symlink()
                            or os.readlink(session / "raw") != str(destination / "raw")):
                        raise ValueError("completed archive checkpoint mismatch")
                    reports.append(report)
                    continue
                verify_frozen(directory, manifest, p)
                update_state(directory, status="running", stage="session-preflight", session=session.name,
                             group=row["group"], role=row["role"], scenario=row["scenario"],
                             position=i + 1, total=len(manifest["sessions"]), accepted_archived=len(reports))
                if not session.exists():
                    capacity_guard(manifest, p, len(manifest["sessions"]) - i)
                    identity = ensure_group(directory, manifest, p, row)
                    update_state(directory, status="running", stage="capture", capture_started_at=now())
                    command = [sys.executable, ROOT / "scripts/collection.py", "--protocol", directory / "protocol.json",
                               "run", "--role", row["role"], "--group", row["group"], "--scenario", row["scenario"],
                               "--seed", str(row["seed"]), "--pilot-report", directory / "pilot.json",
                               "--session-id", session.name, "--campaign-id", manifest["id"],
                               "--expected-boot-id", identity["boot_id"]]
                    rc = run_child(command, directory / "logs" / f"capture_{stamp()}.log", lock_fd=lock_fd,
                                   timeout=p["warmup_s"] + p["cycles"] * p["interval_s"] + 300, guard=guard)
                    if rc and not session.exists():
                        raise ValueError("capture could not start; see campaign log")
                if not check_session(session, manifest, row, directory):
                    archive_capture(directory, manifest, session, p)
                    raise ValueError("incomplete capture archived; allocation stopped, no automatic replacement")
                verify_frozen(directory, manifest, p)
                report, values = audit_capture(directory, manifest, p, row, session, guard)
                archive_capture(directory, manifest, session, p, report)
                if not values["accepted"]:
                    raise ValueError("audit rejected session; archived without replacement: " + "; ".join(values["reasons"]))
                destination = Path(manifest["archive_dir"]) / "collections" / session.name
                write_new(checkpoint, {"session": session.name, "audit": str(report), "audit_sha256": digest(report),
                                       "manifest_sha256": digest(destination / "archive-manifest.json"), "date": now()})
                reports.append(report)
                processed += 1
                update_state(directory, status="running", stage="session-complete", accepted_archived=len(reports))
                if stop_after and processed >= stop_after and i + 1 < len(manifest["sessions"]):
                    update_state(directory, status="stopped", stage="between-sessions", message="requested stop-after boundary")
                    return 0
            finish_corpus(directory, manifest, p, reports)
            return 0
    except BaseException as exc:
        if owns_lock:
            update_state(directory, status="stopped", stage="error", message=str(exc))
        raise
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def finish_corpus(directory, manifest, p, reports):
    from features.dataset import build
    update_state(directory, status="running", stage="index", accepted_archived=len(reports))
    index = directory / "corpus.json"
    doc = build(reports, p, manifest["protocol_sha256"])
    doc["protocol"] = str(directory / "protocol.json")
    if not doc["complete"]:
        raise ValueError("campaign ended without a complete corpus allocation")
    if index.exists():
        if read_json(index) != doc:
            raise ValueError("existing corpus index differs")
    else:
        write_new(index, doc)
    subprocess.run(collection.user_command([
        sys.executable, "-c", "from safeguard.training import validate_index; import sys; validate_index(sys.argv[1])",
        index]), check=True, cwd=ROOT, timeout=180)
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    copy_exclusive(index, Path(manifest["archive_dir"]) / "corpus.json")
    update_state(directory, status="complete", stage="complete", corpus=str(index), message=None)


def launch(directory, stop_after=None):
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("launch with sudo from the campaign owner's account")
    verify_frozen(directory, manifest, p)
    command = ["systemd-run", "--collect", f"--unit={UNIT}", "--description=hyptcn3 benign collection campaign",
               "--property=Type=exec", "--property=KillMode=control-group", "--property=TimeoutStopSec=45",
               "--property=Restart=no", f"--working-directory={ROOT}",
               f"--setenv=SUDO_USER={manifest['owner']['name']}", f"--setenv=SUDO_UID={manifest['owner']['uid']}",
               f"--setenv=SUDO_GID={manifest['owner']['gid']}",
               "systemd-inhibit", "--what=sleep", "--mode=block", "--who=hyptcn3 collection",
               "--why=Preserve the frozen RAM sampling timeline", sys.executable, ROOT / "scripts/campaign.py",
               "run", directory]
    if stop_after:
        command += ["--stop-after", str(stop_after)]
    subprocess.run(list(map(str, command)), check=True, timeout=30)
    print(f"Status: python3 scripts/campaign.py status {directory}")
    print(f"Log: journalctl -fu {UNIT}")


def status(directory):
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    state = read_json(directory / "status.json")
    state["running"] = (state.get("status") == "running" and state.get("process_identity") is not None
                        and process_identity(state.get("pid")) == state["process_identity"])
    state["campaign"] = str(directory)
    state["planned_capture_hours"] = manifest["planned_capture_hours"]
    if state.get("session"):
        raw = COLLECTIONS / state["session"] / "raw"
        state["snapshot_images_present"] = len(list(raw.glob("*.vmicd")))
        state["snapshots_expected"] = p["cycles"]
    print(json.dumps(state, indent=2, ensure_ascii=False))
    return state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Freeze accepted pilot, plan, source and external mount")
    init.add_argument("--protocol", type=Path, default=collection.DEFAULT)
    init.add_argument("--pilot-report", type=Path, required=True)
    init.add_argument("--archive-root", type=Path, required=True)
    init.add_argument("--name")
    for verb in ("run", "launch", "status", "verify-archives"):
        cmd = sub.add_parser(verb)
        cmd.add_argument("directory", type=Path)
        if verb in ("run", "launch"):
            cmd.add_argument("--stop-after", type=int, help="Stop after this many newly archived sessions")
    a = ap.parse_args(argv)
    if getattr(a, "stop_after", None) is not None and a.stop_after < 1:
        ap.error("stop-after must be positive")
    if a.command == "init":
        initialize(a)
    elif a.command == "status":
        status(a.directory)
    elif a.command == "launch":
        launch(a.directory, a.stop_after)
    elif a.command == "run":
        return execute(a.directory, stop_after=a.stop_after)
    else:
        manifest, _ = load_campaign(a.directory)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        for row in manifest["sessions"]:
            dest = Path(manifest["archive_dir"]) / "collections" / row["session_id"]
            if dest.exists():
                verify_archive(dest, COLLECTIONS / row["session_id"])
                print("verified " + row["session_id"], flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"campaign: {error}", file=sys.stderr)
        sys.exit(2)
