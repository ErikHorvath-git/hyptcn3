#!/usr/bin/env python3
"""Frozen benign collection campaign: reboot, capture, audit, archive, index.

init/status/request-stop/close need no root. launch/run need sudo for host
eBPF, and use the original user's libvirt session. A protocol with several VMs
has one runner per VM (run --vm, own systemd unit, status-<vm>.json); a boot
group belongs to one VM, audits and archiving are serialized over the VMs and
sessions live under data/collections/<campaign>/<vm>/. A failed capture or rejected
audit stops the allocation; retries never silently replace a research session.
Only an attempt that ended before its measured phase (no RAM image) is retried.
"""
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import fcntl
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
CAMPAIGN_NAME = r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}"
# Attempts of one assignment that may end before the measured phase (failed
# preflight, warmup or an operator stop there); the last one stops the campaign.
MAX_ATTEMPTS = 3
RETRY_PAUSE_S = 60
# Multi-VM: waiting for the audit lock or for earlier roles on the other VMs.
WAIT_POLL_S = 10
# Runners of one campaign are launched one after another; a runner that is not up yet is not a stopped one.
START_GRACE_S = 120


def vm_names(p):
    """VM names of the protocol; [None] for a single-VM protocol (original file names and layout)."""
    return [row["name"] for row in collection.vms(p)]


def vm_file(name, vm):
    """Per-VM variant of a campaign file: status.json -> status-a.json."""
    stem, suffix = name.rsplit(".", 1)
    return name if vm is None else f"{stem}-{vm}.{suffix}"


def vm_unit(vm):
    return UNIT if vm is None else UNIT.replace(".service", f"-{vm}.service")


def vm_view(manifest, p, vm):
    """Campaign and protocol as one VM's runner sees them: that VM's pilot, guest
    environment, estimates, domain and target under the single-VM keys."""
    if vm is None:
        return manifest, p
    return {**manifest, **manifest["vms"][vm], "vm": vm}, collection.for_vm(p, vm)


def session_dir(manifest, row):
    if "vm" not in row:
        return COLLECTIONS / row["session_id"]
    return COLLECTIONS / manifest["id"] / row["vm"] / row["session_id"]


def archive_dest(manifest, row):
    return Path(manifest["archive_dir"]) / "collections" / row.get("vm", "") / row["session_id"]


def frozen_files(manifest):
    return ["campaign.json", "protocol.json", "plan.json",
            *(vm_file("pilot.json", vm) for vm in manifest.get("vms", [None]))]


def rejection_file(directory, session_id):
    return directory / "attempts" / (session_id + ".rejected.json")


def chain(directory, row):
    """A plan row followed by the replacements of its audit-rejected sessions, oldest first.

    The last one is the assignment's current session. A replacement is the same
    assignment under the ID <plan session>-r<n>; rejection records name it.
    """
    rows = [row]
    while rejection_file(directory, rows[-1]["session_id"]).exists():
        record = read_json(rejection_file(directory, rows[-1]["session_id"]))
        if record.get("replacement") is None:
            break
        expected = f"{row['session_id']}-r{len(rows)}"
        if record["replacement"] != expected or record.get("session") != rows[-1]["session_id"]:
            raise ValueError("rejection record does not match the frozen plan: " + rows[-1]["session_id"])
        rows.append({**row, "session_id": expected, "replaces": rows[-1]["session_id"],
                     "plan_session": row["session_id"], "replacement": len(rows)})
    return rows


def rejections(directory, vm=None):
    """Audit rejections of the campaign with their causes, in time order (all VMs unless one is named)."""
    records = [read_json(path) for path in sorted((directory / "attempts").glob("*.rejected.json"))]
    return sorted((r for r in records if vm is None or r.get("vm") == vm), key=lambda r: r["date"])


def is_done(directory, row):
    """The assignment is archived and accepted: the plan session itself or its replacement."""
    return (directory / "attempts" / (chain(directory, row)[-1]["session_id"] + ".done.json")).exists()


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
            "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect"),
            # Swapped-out guest RAM stalls full snapshots (docs/LAB.sk.md); frozen with the campaign.
            "vm_swappiness": int(Path("/proc/sys/vm/swappiness").read_text())}


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
    from features.quality import require_log_audit
    require_log_audit(meta, v)
    if (tree_hashes(ROOT / p["profile"]) != meta["profile_sha256"]
            or digest(ROOT / "vmicollect/build/vmicollect") != meta["collector_sha256"]):
        raise ValueError("pilot collector or profile differs from current environment")
    changed = measurement_changes(meta)
    if changed:
        raise ValueError("measurement code changed since the pilot (new pilot required): " + ", ".join(changed[:12]))
    return meta, v["raw_bytes"] * p["cycles"] / p["pilot_cycles"] * 1.5


def measurement_changes(meta):
    """Capture/audit/archive code that differs from the pilot's; reports and docs may change."""
    recorded = meta.get("measurement_sha256")
    if recorded is None:
        return ["<pilot predates measurement provenance>"]
    current = collection.measurement_sources()
    return sorted(name for name in set(recorded) | set(current) if recorded.get(name) != current.get(name))


def raw_bytes(session):
    """Bytes of a session's RAM images still on the working disk (0 once archived and reclaimed)."""
    raw = session / "raw"
    if raw.is_symlink() or not raw.is_dir():
        return 0
    total = 0
    for path in raw.iterdir():
        try:
            total += path.stat().st_size
        except OSError:
            pass  # Published or renamed by the collector's writer thread meanwhile.
    return total


def capacity_guard(manifest, p, remaining, directory=None):
    """Space for the next session of this VM, next to what the other VMs still write.

    Every VM has its own estimate: raw bytes of its accepted pilot scaled to the
    session length, times 1.5 (pilot_gate). The working disk must hold this VM's
    next session, plus for every other VM with sessions left the part of its
    estimate not written yet (its current session may be in capture, waiting for
    the audit lock or about to start), plus the protocol reserve min_free_gib.
    At most one unarchived session per VM exists, because a runner archives and
    reclaims its session before the next capture and audits are serialized.

    Assumed numbers (collection PC, 2026-11-14, protocol v3 values): one session
    estimate ~16.8 GB (~11.2 GB raw x 1.5), reserve 30 GiB = 32.2 GB, i.e. the
    ~49 GB one VM needed so far. Two VMs starting together need 2 x 16.8 + 32.2 =
    65.8 GB, more than the 62.9 GB free on the SSD: either space is freed first or
    protocol v4 lowers min_free_gib (27 GiB gives 62.6 GB). The real estimates come
    from the per-VM pilots of the campaign, not from these numbers.
    """
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    reserve = p["min_free_gib"] * 2**30
    needed = manifest["estimated_session_bytes_with_reserve"]
    archived = manifest.get("estimated_archive_bytes_per_session", needed) * remaining
    for vm in manifest.get("vms", {}) if directory is not None else ():
        pending = [r for r in manifest["sessions"] if r["vm"] == vm and not is_done(directory, r)]
        if vm == manifest["vm"] or not pending:
            continue
        other = manifest["vms"][vm]
        current = chain(directory, pending[0])[-1]
        needed += max(0, other["estimated_session_bytes_with_reserve"] - raw_bytes(session_dir(manifest, current)))
        archived += other["estimated_archive_bytes_per_session"] * len(pending)
    if shutil.disk_usage(COLLECTIONS).free < needed + reserve:
        raise ValueError("insufficient working space for the next session")
    if shutil.disk_usage(manifest["archive_root"]).free < archived + reserve:
        raise ValueError("insufficient archive space for remaining campaign estimate")


@contextmanager
def audit_lock(directory, **state):
    """One audit/archive on the host at a time, over all VMs and campaigns.

    Feature extraction and the compressing archiver are the heavy host work
    between captures (CPU, memory, SSD and archive disk); two at once would
    load the other VM's running capture twice. Waits; interrupts end the wait.
    """
    COLLECTIONS.mkdir(parents=True, exist_ok=True)
    fd = os.open(COLLECTIONS / ".audit.lock", os.O_CREAT | os.O_RDWR, 0o644)
    try:
        waiting = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waiting:
                    update_state(directory, status="running", stage="audit-wait", **state,
                                 message="another VM's audit or archive is running")
                waiting = True
                time.sleep(WAIT_POLL_S)
        yield
    finally:
        os.close(fd)


def pilot_reports(p, values):
    """--pilot-report PATH (single VM) or one VM=PATH per VM of the protocol."""
    names = vm_names(p)
    if names == [None]:
        if len(values) != 1:
            raise ValueError("exactly one pilot report required")
        return {None: Path(values[0])}
    given = dict(str(value).split("=", 1) if "=" in str(value) else (None, value) for value in values)
    if len(given) != len(values) or set(given) != set(names):
        raise ValueError("one accepted pilot per VM required: --pilot-report VM=PATH for " + ", ".join(names))
    return {vm: Path(given[vm]) for vm in names}


def archive_estimate(session_dir, p, compression):
    """Archive bytes per hourly session from the accepted pilot itself.

    Raw images use the archive codec on every pilot image; all other session
    files count uncompressed (upper bound). The 1.5 planning margin is kept.
    """
    raw = Path(session_dir) / "raw"
    original = stored = 0
    for path in sorted(raw.glob("*.vmicd")):
        size = path.stat().st_size
        original += size
        if compression is None:
            stored += size
            continue
        with path.open("rb") as stream:
            process = subprocess.Popen(["zstd", "-q", "-3", "-T1", "-c"], stdin=stream, stdout=subprocess.PIPE)
            for chunk in iter(lambda: process.stdout.read(1 << 20), b""):
                stored += len(chunk)
            if process.wait():
                raise ValueError("zstd failed while estimating the archive size")
    if not original:
        raise ValueError("pilot raw images are not available for the archive estimate")
    other = sum(f.stat().st_size for f in Path(session_dir).rglob("*")
                if f.is_file() and not f.is_symlink() and raw not in f.parents)
    scale = p["cycles"] / p["pilot_cycles"]
    return {"codec": compression, "pilot_raw_bytes": original, "pilot_raw_stored_bytes": stored,
            "raw_ratio": stored / original, "pilot_other_bytes": other,
            "bytes_per_session": (stored + other) * scale * 1.5,
            "note": "Measured on the accepted pilot; heavier scenarios may exceed it."}


def initialize(a):
    if git("status", "--porcelain"):
        raise ValueError("commit the source and documentation before freezing a campaign")
    p = collection.protocol(a.protocol)
    pilots = pilot_reports(p, a.pilot_report)
    compression = None if a.archive_compression == "none" else a.archive_compression
    per_vm = {}
    for vm, pilot in pilots.items():  # One accepted pilot per VM: its own machine, estimate and memory.
        pv = collection.for_vm(p, vm)
        meta, needed = pilot_gate(pilot, a.protocol, pv)
        if meta.get("vm") != vm:
            raise ValueError("pilot was captured on a different VM")
        identity = collection.guest_identity(pv)
        if guest_environment(identity) != guest_environment(meta["guest_before"]):
            raise ValueError("guest environment differs from accepted pilot")
        if runtime_identity()["vm_swappiness"] != meta["host_context"].get("memory", {}).get("vm_swappiness"):
            raise ValueError("host vm.swappiness differs from accepted pilot")
        estimate = archive_estimate(read_json(pilot)["values"]["session_dir"], p, compression)
        per_vm[vm] = {"pilot_report_sha256": digest(pilot), "pilot_source": str(pilot.resolve()),
                      "guest_environment": guest_environment(identity),
                      "archive_estimate": estimate,
                      "estimated_archive_bytes_per_session": estimate["bytes_per_session"],
                      "estimated_session_bytes_with_reserve": needed}
        if vm is not None:
            per_vm[vm]["domain"] = pv["domain"]
    if len({v["guest_environment"]["machine_id"] for v in per_vm.values()}) != len(per_vm):
        raise ValueError("VMs share a machine-id; a clone needs its own identity (labctl clone)")
    name = a.name or stamp() + "_benign_v2"
    if not re.fullmatch(CAMPAIGN_NAME, name):
        raise ValueError("invalid campaign name")
    archive_root = Path(a.archive_root).absolute()
    mount = mount_identity(archive_root, allow_system=a.archive_on_system_disk)
    owner = pwd.getpwuid(int(os.environ.get("SUDO_UID", os.getuid())))
    directory = BASE / name
    planned = collection.plan(p)
    for i, row in enumerate(planned["sessions"]):
        row["session_id"] = "_".join([name, f"{i + 1:02d}", *([row["vm"]] if "vm" in row else []),
                                      row["role"], row["scenario"]])
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": name, "date": now(),
                "commit": git("rev-parse", "HEAD"), "runtime": runtime_identity(),
                "owner": {"name": owner.pw_name, "uid": owner.pw_uid, "gid": owner.pw_gid},
                "workspace": str(ROOT), "protocol_sha256": digest(a.protocol),
                "profile_sha256": meta["profile_sha256"], "extractor_sha256": extractor_hashes(),
                # Pilot, guest environment and estimates: per VM under "vms", or flat for one VM.
                **(per_vm[None] if None in per_vm else {"vms": per_vm}),
                "archive_root": str(archive_root), "archive_mount": mount,
                "archive_dir": str(archive_root / "campaigns" / name),
                "archive_compression": compression,
                "working_storage": collection.storage_identity(COLLECTIONS),
                "sessions": planned["sessions"], "planned_capture_hours": planned["planned_hours"],
                "note": "Frozen allocation, not a measurement or a completed corpus."}
    COLLECTIONS.mkdir(exist_ok=True, parents=True)
    archive_root.mkdir(exist_ok=True, parents=True)
    for vm in per_vm:
        capacity_guard(vm_view(manifest, p, vm)[0], p,
                       sum(r.get("vm") == vm for r in planned["sessions"]), directory)
    # Group names repeat in every campaign of a protocol. Only a campaign
    # explicitly closed by the operator releases them (its data stays).
    groups = {r["group"] for r in planned["sessions"]}
    for old, doc in collection.session_records(COLLECTIONS):
        if doc["group"] in groups and not closed_campaign(doc.get("campaign_id")):
            raise ValueError("planned group already has data; resume or close its campaign: " + str(old))
    directory.mkdir(parents=True)
    for child in ("events", "groups", "attempts", "logs"):
        (directory / child).mkdir()
    copy_exclusive(Path(a.protocol), directory / "protocol.json")
    for vm, pilot in pilots.items():
        copy_exclusive(pilot, directory / vm_file("pilot.json", vm))
    write_new(directory / "plan.json", planned)
    write_new(directory / "campaign.json", manifest)
    external = Path(manifest["archive_dir"])
    guard_mount(archive_root, mount)
    external.mkdir(parents=True)
    for filename in frozen_files(manifest):
        copy_exclusive(directory / filename, external / filename)
    for vm in per_vm:
        update_state(directory, vm=vm, status="ready", stage="initialized", accepted_archived=0,
                     total=sum(r.get("vm") == vm for r in planned["sessions"]))
    print(json.dumps({"campaign": str(directory), "sessions": len(planned["sessions"]),
                      "capture_hours": planned["planned_hours"],
                      "archive": str(external)}, indent=2))
    return directory


def closed_campaign(campaign_id):
    return (isinstance(campaign_id, str) and re.fullmatch(CAMPAIGN_NAME, campaign_id) is not None
            and (BASE / campaign_id / "closed.json").exists())


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
            or list(m.get("vms", [None])) != vm_names(p)
            or any(digest(directory / vm_file("pilot.json", vm)) != vm_view(m, p, vm)[0]["pilot_report_sha256"]
                   for vm in vm_names(p))):
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
    # A missing SSD must stop the run, not redirect it to another disk.
    if "working_storage" in manifest and collection.storage_identity(COLLECTIONS) != manifest["working_storage"]:
        raise ValueError("working storage for data/collections is not the frozen disk")
    # External copy also detects accidental changes to the local immutable plan.
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    external = Path(manifest["archive_dir"])
    for name in frozen_files(manifest):
        if digest(directory / name) != digest(external / name):
            raise ValueError("frozen campaign backup mismatch: " + name)


def update_state(directory, **values):
    if values.get("vm") is None:
        values.pop("vm", None)  # Single-VM campaign: status.json without a VM key, as before.
    path = directory / vm_file("status.json", values.get("vm"))
    previous = read_json(path) if path.exists() else {}
    state = {**previous, **values, "updated_at": now()}
    write_new(path, state, replace=True)
    event = {"schema": "hyptcn3/campaign-event/1", **state}
    write_new(directory / "events" / f"{stamp()}_{uuid.uuid4().hex[:8]}.json", event)
    print(json.dumps({k: state[k] for k in ("updated_at", "vm", "status", "stage", "session", "message")
                      if k in state}), flush=True)


def process_identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return {"host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "start_ticks": text.rsplit(")", 1)[1].split()[19]}
    except OSError:
        return None


def run_child(command, log, *, timeout, guard=lambda: None, lock_fd=None, grace=150):
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
        except InterruptedError:
            # One SIGTERM to the child only; it stops its own helpers in order and
            # writes a truthful end record. Group kills below are a last resort.
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
            raise
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


def hold_sleep_inhibitor():
    """Block sleep while the runner lives; the helper exits when its stdin pipe closes."""
    process = subprocess.Popen(["systemd-inhibit", "--what=sleep:idle", "--mode=block", "--who=hyptcn3 collection",
                                "--why=Preserve the frozen RAM sampling timeline", "cat"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(.5)
    if process.poll() is not None:
        raise ValueError("cannot take the sleep inhibitor lock")
    return process


def release_sleep_inhibitor(process):
    if process is None:
        return
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def sleep_inhibited():
    listing = subprocess.run(["systemd-inhibit", "--list", "--no-pager"], capture_output=True, text=True, timeout=10)
    return "hyptcn3 collection" in listing.stdout


def ensure_group(directory, manifest, p, row):
    ready = directory / "groups" / (row["group"] + ".json")
    current = collection.guest_identity(p)
    if guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("guest environment changed")
    if ready.exists():
        group = read_json(ready)
        if group.get("vm") != row.get("vm"):
            raise ValueError("group belongs to another VM")
        if current != group["identity"]:
            raise ValueError("boot changed inside a group; preserve partial allocation for review")
        # A save/restore keeps the guest boot ID; the QEMU process shows it.
        qemu = collection.qemu_process(p["domain"])
        if qemu != group.get("qemu"):
            raise ValueError(("VM process not found" if qemu is None else
                              "VM process changed inside a group (restart or restore)")
                             + "; preserve partial allocation for review")
        return group
    intent = ready.with_suffix(".reboot-intent.json")
    if intent.exists():
        before = read_json(intent)["previous_boot"]
    else:
        before = current["boot_id"]
        write_new(intent, {"group": row["group"], "previous_boot": before, "date": now()})
    update_state(directory, vm=row.get("vm"), status="running", stage="reboot", group=row["group"])
    if current["boot_id"] == before:
        command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", "reboot",
                                           *collection.labctl_args(p)])
        rc = run_child(command, directory / "logs" / f"reboot_{stamp()}.log", timeout=240)
        if rc:
            raise ValueError("lab reboot failed; see campaign reboot log")
        current = collection.guest_identity(p)
    if current["boot_id"] == before or guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("new group requires a new boot with the frozen guest environment")
    for _, existing in collection.session_records(COLLECTIONS):
        if existing["guest_before"]["boot_id"] == current["boot_id"]:
            raise ValueError("new group boot already belongs to another session")
    qemu = collection.qemu_process(p["domain"])
    if qemu is None:
        raise ValueError("VM process not found after the group reboot")
    group = {"schema": "hyptcn3/campaign-group/1", "date": now(), "group": row["group"],
             **({"vm": row["vm"], "domain": p["domain"]} if "vm" in row else {}),
             "role": row["role"], "identity": current, "qemu": qemu, "previous_boot": before}
    write_new(ready, group)
    return group


def check_session(path, manifest, row, directory):
    meta = read_json(path / "session.json")
    for k in ("role", "group", "scenario", "seed", "session_id"):
        if meta[k] != row[k]:
            raise ValueError("session differs from frozen assignment: " + k)
    if meta.get("vm") != row.get("vm"):
        raise ValueError("session differs from frozen assignment: vm")
    if meta.get("replaces") != row.get("replaces"):
        raise ValueError("session differs from frozen assignment: replaces")
    # Measurement sources, not the whole worktree: a note written meanwhile is not a different capture.
    if (meta.get("campaign_id") != manifest["id"] or meta["commit"] != manifest["commit"]
            or meta.get("measurement_dirty") != [] or meta["protocol_sha256"] != manifest["protocol_sha256"]
            or guest_environment(meta["guest_before"]) != manifest["guest_environment"]):
        raise ValueError("session provenance differs from frozen campaign")
    group = read_json(directory / "groups" / (row["group"] + ".json"))
    if meta["guest_before"] != group["identity"]:
        raise ValueError("session boot differs from recorded campaign group")
    if meta.get("host_context", {}).get("qemu") != group.get("qemu"):
        raise ValueError("session VM process differs from recorded campaign group")
    end = read_json(path / "end.json") if (path / "end.json").exists() else {}
    return bool(end.get("completed") and end.get("guest_after") == meta["guest_before"])


def audit_environment(doc, manifest):
    """The verdict came from the frozen code; files outside measurement sources do not matter."""
    v = doc["values"]
    return (doc["commit"] == manifest["commit"] and doc.get("measurement_dirty") == []
            and v["protocol_sha256"] == manifest["protocol_sha256"]
            and v["extractor_sha256"] == manifest["extractor_sha256"])


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
            if doc.get("schema") != "hyptcn3/collection-audit/1":
                continue
            if audit_environment(doc, manifest):
                complete.append(report)
            else:
                # Written while HEAD or measurement code differed: kept, never selected.
                # The frozen tree was verified before this call, so a new audit is valid.
                update_state(directory, vm=row.get("vm"), status="running", stage="audit", session=session.name,
                             message="ignored audit made from a changed source tree: " + report.name)
        if len(complete) > 1:
            raise ValueError("multiple campaign audit verdicts require review")
        if complete:
            report = complete[0]
        else:
            report = session / f"campaign_audit_{stamp()}.json"
            update_state(directory, vm=row.get("vm"), status="running", stage="audit", session=session.name,
                         message=None)
            command = collection.user_command([sys.executable, ROOT / "scripts/collection.py",
                                               "--protocol", directory / "protocol.json",
                                               "audit", session, "--out", report])
            rc = run_child(command, directory / "logs" / f"audit_{stamp()}.log",
                           timeout=max(600, p["cycles"] * 15), guard=guard)
            if rc not in (0, 2) or not report.exists():
                raise ValueError("audit did not produce a verdict; see campaign log")
    doc = read_json(report)
    v = doc["values"]
    if (not audit_environment(doc, manifest)
            or v["session_dir"] != str(session) or v["role"] != row["role"]
            or v["session_sha256"] != digest(session / "session.json")
            or digest(v["features"]) != v["features_sha256"]):
        raise ValueError("audit provenance differs from campaign/session")
    if not pointer.exists():
        write_new(pointer, {"path": str(report), "sha256": digest(report)})
    return report, v


def ended_before_measurement(session):
    """An attempt without measured phase or RAM image (failed preflight/warmup or a stop there)."""
    if not session.is_dir() or (session / "raw").exists():
        return False
    if not (session / "session.json").exists():
        return not (session / "end.json").exists()  # Failed while preparing its metadata.
    end = session / "end.json"
    return end.exists() and read_json(end).get("measurement_started") is False


def retire_attempt(directory, manifest, row, session):
    """Keep an attempt that never measured under a numbered name, so the assignment can run again."""
    meta = read_json(session / "session.json") if (session / "session.json").exists() else None
    if meta is not None and (meta.get("campaign_id"), meta.get("session_id")) != (manifest["id"], row["session_id"]):
        raise ValueError("unexpected metadata in assignment directory: " + str(session))
    end = read_json(session / "end.json") if (session / "end.json").exists() else {}
    reason = end.get("error") or ("no session metadata" if meta is None else "no error recorded")
    numbers = [int(n) for n in (p.name.rsplit("-", 1)[1] for p in session.parent.glob(session.name + ".attempt-*"))
               if n.isdigit()]
    number = max(numbers, default=0) + 1
    target = session.with_name(f"{session.name}.attempt-{number}")
    os.rename(session, target)
    sync_dir(session.parent)
    write_new(directory / "attempts" / f"{session.name}.attempt-{number}.json",
              {"schema": "hyptcn3/campaign-attempt/1", "session": session.name, "attempt": number,
               "directory": str(target), "reason": reason, "date": now(),
               "note": "Ended before the measured phase without a RAM image; the assignment runs again "
                       "in the same group boot. Kept for review, not part of the corpus."})
    update_state(directory, vm=row.get("vm"), status="running", stage="retry", session=session.name,
                 message=f"attempt {number} ended before measurement: {reason}")


def reject(directory, manifest, p, row, report, values):
    """Record an audit rejection with its cause; schedule its replacement if the protocol's rule allows.

    The rule is part of the frozen protocol (collection.check_replacement). The
    replacement is the same assignment - VM, role, group, scenario, seed, event
    schedule - captured again in the same boot of its group, right after the
    rejected session and before the group's next one. So a group stays one boot
    of one VM and the corpus still holds each group/scenario once: the rejected
    session is archived and kept, but never indexed. Called under the audit lock,
    so the per-campaign count is exact over all VMs. Returns the replacement row
    or None (no rule, or its maximum is used up: the allocation stops as before).
    """
    limit = (p.get("replacement") or {}).get("max_per_campaign", 0)
    used = sum(r.get("replacement") is not None for r in rejections(directory))
    plan_session, number = row.get("plan_session", row["session_id"]), row.get("replacement", 0) + 1
    replacement = f"{plan_session}-r{number}" if used < limit else None
    write_new(rejection_file(directory, row["session_id"]), {
        "schema": "hyptcn3/campaign-rejection/1", "date": now(), "session": row["session_id"],
        **{k: row[k] for k in ("vm", "role", "group", "scenario", "seed", "replaces") if k in row},
        "reasons": values["reasons"], "audit": str(report), "audit_sha256": digest(report),
        "replacement": replacement, "replacements_before": used, "max_per_campaign": limit,
        "note": "Rejected by the audit; archived, never part of the corpus or event index. "
                + ("Replaced by the same assignment in the same group boot (protocol replacement rule)."
                   if replacement else "Not replaced: no replacement left under the protocol; allocation stopped.")})
    if replacement is None:
        return None
    update_state(directory, vm=row.get("vm"), status="running", stage="replacement", session=row["session_id"],
                 replacements_used=used + 1,
                 message=f"audit rejected ({'; '.join(values['reasons'])}); replacement {used + 1} of {limit}: "
                         + replacement)
    return {**row, "session_id": replacement, "replaces": row["session_id"], "plan_session": plan_session,
            "replacement": number}


def take_stop_request(directory, vm=None):
    """Consume an operator request to stop before the next capture."""
    request = directory / vm_file("stop-request.json", vm)
    if not request.exists():
        return False
    os.replace(request, directory / "events" / f"{stamp()}_{request.name}")
    sync_dir(directory)
    return True


def earlier_roles(directory, manifest, p, row):
    """Other VMs' sessions of roles that precede this row's role and are not archived yet."""
    order = list(p["roles"])
    return [r for r in manifest["sessions"] if r.get("vm") != row.get("vm")
            and order.index(r["role"]) < order.index(row["role"]) and not is_done(directory, r)]


def wait_for_earlier_roles(directory, manifest, p, row):
    """Keep the role order of the plan across VMs, not only inside each VM.

    features/dataset.py accepts a corpus only if all train sessions end before
    the first dev session starts, and so on. Each VM takes its groups in role
    order; before the first group of a later role this runner waits until the
    other VMs have finished every earlier role. Returns a reason to stop instead
    (operator request, or the other runner is not running and nobody would end
    the wait), else None.
    """
    waiting, grace = False, time.monotonic() + START_GRACE_S
    while pending := earlier_roles(directory, manifest, p, row):
        if take_stop_request(directory, row["vm"]):
            return "operator stop request"
        for vm in sorted({r["vm"] for r in pending}):
            path = directory / vm_file("status.json", vm)
            if not campaign_running(read_json(path) if path.exists() else {}) and time.monotonic() >= grace:
                return f"VM {vm} has not finished the roles before {row['role']} and its runner is not active"
        if not waiting:
            update_state(directory, vm=row["vm"], status="running", stage="role-wait", group=row["group"],
                         role=row["role"], message="waiting for earlier roles on: "
                         + ", ".join(sorted({r["vm"] for r in pending})))
        waiting = True
        time.sleep(WAIT_POLL_S)
    return None


def archive_capture(directory, manifest, session, p, audit=None):
    update_state(directory, vm=manifest.get("vm"), status="running", stage="archive", session=session.name)
    destination = Path(manifest["archive_dir"]) / "collections" / manifest.get("vm", "") / session.name
    guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
    return archive_session(session, destination, guard, reclaim=True, campaign_id=manifest["id"],
                           audit=audit, reserve_bytes=p["min_free_gib"] * 2**30,
                           compress=manifest.get("archive_compression"))


def execute(directory, *, stop_after=None, vm=None):
    """Run the sessions of one VM in plan order (all sessions of a single-VM campaign).

    A multi-VM campaign has one runner process per VM; they share the frozen
    plan, the audit lock and the final index, nothing else.
    """
    directory = Path(directory).resolve()
    campaign, protocol = load_campaign(directory)
    if vm not in vm_names(protocol):
        raise ValueError("this campaign runs one VM per runner; --vm is one of: "
                         + ", ".join(map(str, vm_names(protocol))) if vm is None else "campaign has no VM " + vm)
    manifest, p = vm_view(campaign, protocol, vm)
    # Replacements of audit-rejected sessions follow their plan row; the list grows when one is scheduled.
    rows = [r for planned in manifest["sessions"] if planned.get("vm") == vm for r in chain(directory, planned)]
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("run with sudo from the campaign owner's account")
    if (directory / "closed.json").exists():
        raise ValueError("campaign was closed by the operator: " + read_json(directory / "closed.json")["reason"])
    interrupts = collection.Interrupts()
    owns_lock, inhibitor = False, None
    status_file = directory / vm_file("status.json", vm)
    stop_file = directory / vm_file("stop-request.json", vm)
    try:
        with collection.collection_lock(COLLECTIONS, p["domain"] if vm else None) as lock_fd:
            owns_lock = True
            verify_frozen(directory, manifest, p)
            last = read_json(status_file) if status_file.exists() else {}
            if last.get("status") == "running":
                # The lock was free, so that process is gone: SIGKILL, crash or power loss.
                update_state(directory, vm=vm, status="stopped", stage="unclean-end",
                             message="previous run ended without a final status; its session is incomplete")
            if stop_file.exists():
                # A request is meant for a running campaign; one left by a previous run is not.
                os.replace(stop_file, directory / "events" / f"{stamp()}_{stop_file.stem}-stale.json")
            inhibitor = hold_sleep_inhibitor()
            update_state(directory, vm=vm, status="running", stage="preflight", pid=os.getpid(),
                         process_identity=process_identity(os.getpid()), inhibitor_pid=getattr(inhibitor, "pid", None),
                         message=None, signals=[])
            reports = []
            processed = 0
            guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
            for i, row in enumerate(rows):
                session = session_dir(manifest, row)
                destination = archive_dest(manifest, row)
                checkpoint = directory / "attempts" / (row["session_id"] + ".done.json")
                if rejection_file(directory, row["session_id"]).exists():
                    record = read_json(rejection_file(directory, row["session_id"]))
                    if record.get("replacement") is None:
                        raise ValueError("audit rejected session; archived without replacement: "
                                         + "; ".join(record["reasons"]))
                    continue  # Its replacement is the next row.
                if checkpoint.exists():
                    done = read_json(checkpoint)
                    if not check_session(session, manifest, row, directory):
                        raise ValueError("completed session lost its provenance")
                    report, values = audit_capture(directory, manifest, p, row, session, guard)
                    if (not values["accepted"] or digest(destination / "archive-manifest.json") != done["manifest_sha256"]
                            or not (session / "raw").is_symlink()
                            or os.readlink(session / "raw") != str(destination / "raw")):
                        raise ValueError("completed archive checkpoint mismatch")
                    reports.append(report)
                    continue
                verify_frozen(directory, manifest, p)
                update_state(directory, vm=vm, status="running", stage="session-preflight", session=session.name,
                             group=row["group"], role=row["role"], scenario=row["scenario"],
                             position=i + 1, total=len(rows), accepted_archived=len(reports))
                if ended_before_measurement(session):
                    retire_attempt(directory, manifest, row, session)  # Left by a previous run.
                attempts = 0
                while not session.exists():
                    if take_stop_request(directory, vm):
                        update_state(directory, vm=vm, status="stopped", stage="between-sessions",
                                     message="operator stop request")
                        return 0
                    if vm is not None:
                        reason = wait_for_earlier_roles(directory, manifest, p, row)
                        if reason:
                            update_state(directory, vm=vm, status="stopped", stage="between-sessions", message=reason)
                            return 0
                    if attempts:
                        verify_frozen(directory, manifest, p)
                    attempts += 1
                    capacity_guard(manifest, p, len(rows) - i, directory)
                    group = ensure_group(directory, manifest, p, row)
                    update_state(directory, vm=vm, status="running", stage="capture", capture_started_at=now(),
                                 message=None)
                    command = [sys.executable, ROOT / "scripts/collection.py", "--protocol", directory / "protocol.json",
                               "run", "--role", row["role"], "--group", row["group"], "--scenario", row["scenario"],
                               "--seed", str(row["seed"]), "--pilot-report", directory / vm_file("pilot.json", vm),
                               "--session-id", session.name, "--campaign-id", manifest["id"],
                               "--expected-boot-id", group["identity"]["boot_id"],
                               "--expected-qemu", json.dumps(group["qemu"]),
                               *(["--vm", vm] if vm else []),
                               *(["--replaces", row["replaces"]] if "replaces" in row else [])]
                    rc = run_child(command, directory / "logs" / f"capture_{stamp()}.log", lock_fd=lock_fd,
                                   timeout=p["warmup_s"] + p["cycles"] * p["interval_s"] + 300, guard=guard)
                    if rc and not session.exists():
                        raise ValueError("capture could not start; see campaign log")
                    if ended_before_measurement(session):
                        if attempts >= MAX_ATTEMPTS:
                            raise ValueError(f"{attempts} attempts of {session.name} ended before measurement; "
                                             "see its end.json and the campaign logs")
                        retire_attempt(directory, manifest, row, session)
                        time.sleep(RETRY_PAUSE_S)
                # The session stays on the working disk while it waits; its VM starts nothing new.
                with audit_lock(directory, vm=vm, session=session.name):
                    if not check_session(session, manifest, row, directory):
                        archive_capture(directory, manifest, session, p)
                        raise ValueError("incomplete capture archived; allocation stopped, no automatic replacement")
                    verify_frozen(directory, manifest, p)
                    report, values = audit_capture(directory, manifest, p, row, session, guard)
                    archive_capture(directory, manifest, session, p, report)
                    replacement = None if values["accepted"] else reject(directory, manifest, p, row, report, values)
                if not values["accepted"]:
                    if replacement is None:
                        raise ValueError("audit rejected session; archived without replacement: "
                                         + "; ".join(values["reasons"]))
                    rows.insert(i + 1, replacement)
                    continue
                write_new(checkpoint, {"session": session.name, "audit": str(report), "audit_sha256": digest(report),
                                       "manifest_sha256": digest(destination / "archive-manifest.json"), "date": now()})
                reports.append(report)
                processed += 1
                update_state(directory, vm=vm, status="running", stage="session-complete",
                             accepted_archived=len(reports))
                if stop_after and processed >= stop_after and i + 1 < len(rows):
                    update_state(directory, vm=vm, status="stopped", stage="between-sessions",
                                 message="requested stop-after boundary")
                    return 0
            if vm is None:
                finish_corpus(directory, manifest, p, reports)
                return 0
            # The runner that archives the campaign's last session builds the index of all VMs.
            with audit_lock(directory, vm=vm):
                if not all(is_done(directory, r) for r in manifest["sessions"]):
                    update_state(directory, vm=vm, status="complete", stage="vm-complete", message=None,
                                 accepted_archived=len(reports))
                    return 0
                reports = [Path(read_json(directory / "attempts" / (chain(directory, r)[-1]["session_id"]
                                                                     + ".audit.json"))["path"])
                           for r in manifest["sessions"]]
                finish_corpus(directory, manifest, protocol, reports)
            return 0
    except BaseException as exc:
        try:
            interrupts.disarm()
        except InterruptedError:
            pass  # First signal arrived exactly here; the handler disarmed itself.
        if owns_lock:
            update_state(directory, vm=vm, status="stopped",
                         stage="interrupted" if isinstance(exc, InterruptedError) else "error",
                         message=str(exc), signals=interrupts.received)
        raise
    finally:
        release_sleep_inhibitor(inhibitor)
        interrupts.restore()


EVENT_INDEX = "hyptcn3/event-index/1"


def event_index(reports, p, protocol_sha):
    """Test-only protocol (v3, step A): accepted sessions with their event intervals.

    No training roles, so no corpus index: these sessions are only scored by an
    existing bundle (python3 -m tcn.eval udalosti).
    """
    from features.archive import load
    from features.quality import require_log_audit
    records, boots, groups = [], {}, {}
    for path in reports:
        v = read_json(path)["values"]
        if not v["accepted"] or v["protocol_sha256"] != protocol_sha:
            raise ValueError("unaccepted audit or protocol mismatch: " + str(path))
        session = Path(v["session_dir"])
        meta = read_json(session / "session.json")
        if v.get("session_sha256") != digest(session / "session.json") or digest(v["features"]) != v["features_sha256"]:
            raise ValueError("session metadata or features changed since audit: " + str(path))
        require_log_audit(meta, v)
        boot = meta["guest_before"]["boot_id"]
        if meta["role"] not in p["roles"] or boots.setdefault(boot, meta["group"]) != meta["group"] \
                or groups.setdefault(meta["group"], boot) != boot:
            raise ValueError("role or boot/group mapping outside the plan: " + str(path))
        casy = load(v["features"])["casy"]
        events = session / "events.json"
        records.append({"id": meta["session_id"], "role": meta["role"], "group": meta["group"], "boot_id": boot,
                        **({"vm": meta["vm"]} if meta.get("vm") else {}),
                        "scenario": meta["scenario"], "seed": meta["seed"],
                        "start": float(casy[0]), "end": float(casy[-1]),
                        "session": str(session / "session.json"), "session_sha256": v["session_sha256"],
                        "audit": str(Path(path).resolve()), "audit_sha256": digest(path),
                        "features": v["features"], "features_sha256": v["features_sha256"],
                        "events": str(events), "events_sha256": digest(events),
                        "guest": meta["guest_before"], "collector_sha256": meta["collector_sha256"],
                        "extractor_sha256": v["extractor_sha256"]})
    planned = sum(p["roles"].values()) * len(p["scenarios"])
    return {"schema": EVENT_INDEX, "complete": len(records) == planned, "planned_sessions": planned,
            "protocol_sha256": protocol_sha, "protocol_config": p, "sessions": records,
            "note": "Benign operational events; test-only sessions, never training data."}


def finish_corpus(directory, manifest, p, reports):
    vm = manifest.get("vm")  # Multi-VM: the status file of the runner that builds the index.
    if "train" not in p["roles"]:
        update_state(directory, vm=vm, status="running", stage="index", accepted_archived=len(reports))
        index = directory / "events_index.json"
        doc = event_index(reports, p, manifest["protocol_sha256"])
        doc["protocol"] = str(directory / "protocol.json")
        if not doc["complete"]:
            raise ValueError("campaign ended without a complete event allocation")
        if index.exists():
            if read_json(index) != doc:
                raise ValueError("existing event index differs")
        else:
            write_new(index, doc)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        copy_exclusive(index, Path(manifest["archive_dir"]) / "events_index.json")
        update_state(directory, vm=vm, status="complete", stage="complete", corpus=str(index), message=None)
        return
    from features.dataset import build
    update_state(directory, vm=vm, status="running", stage="index", accepted_archived=len(reports))
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
    update_state(directory, vm=vm, status="complete", stage="complete", corpus=str(index), message=None)


def launch(directory, stop_after=None, vm=None):
    """One systemd unit per VM; without --vm every VM of the campaign is launched."""
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if vm is not None and vm not in vm_names(p):
        raise ValueError("campaign has no VM " + vm)
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("launch with sudo from the campaign owner's account")
    if (directory / "closed.json").exists():
        raise ValueError("campaign was closed by the operator")
    verify_frozen(directory, manifest, p)
    # KillMode=mixed: SIGTERM reaches only the runner, which stops its child in
    # order; anything left after it exits (or after the timeout) gets SIGKILL.
    for name in vm_names(p) if vm is None else [vm]:
        unit = vm_unit(name)
        command = ["systemd-run", "--collect", f"--unit={unit}", "--description=hyptcn3 benign collection campaign",
                   "--property=Type=exec", "--property=KillMode=mixed", "--property=TimeoutStopSec=240",
                   "--property=Restart=no", f"--working-directory={ROOT}",
                   f"--setenv=SUDO_USER={manifest['owner']['name']}", f"--setenv=SUDO_UID={manifest['owner']['uid']}",
                   f"--setenv=SUDO_GID={manifest['owner']['gid']}",
                   sys.executable, ROOT / "scripts/campaign.py", "run", directory]
        if name is not None:
            command += ["--vm", name]
        if stop_after:
            command += ["--stop-after", str(stop_after)]
        subprocess.run(list(map(str, command)), check=True, timeout=30)
        print(f"Log: journalctl -fu {unit}")
    print(f"Status: python3 scripts/campaign.py status {directory}")


def campaign_running(state):
    return (state.get("status") == "running" and state.get("process_identity") is not None
            and process_identity(state.get("pid")) == state["process_identity"])


def request_stop(directory, vm=None):
    """Ask the running campaign to stop before its next capture; the current session is kept.

    Multi-VM: every running runner gets its own request, or only the one named.
    """
    directory = Path(directory).resolve()
    _, p = load_campaign(directory)
    if vm is not None and vm not in vm_names(p):
        raise ValueError("campaign has no VM " + vm)
    running = [name for name in (vm_names(p) if vm is None else [vm])
               if (directory / vm_file("status.json", name)).exists()
               and campaign_running(read_json(directory / vm_file("status.json", name)))]
    if not running:
        raise ValueError("campaign is not running")
    for name in running:
        try:
            write_new(directory / vm_file("stop-request.json", name), {
                "schema": "hyptcn3/campaign-stop-request/1", "date": now(), "uid": os.getuid(),
                **({} if name is None else {"vm": name}),
                "note": "The current session finishes, is audited and archived; no new capture starts."})
        except FileExistsError:
            raise ValueError("stop already requested") from None
    print(f"Stop requested; follow: python3 scripts/campaign.py status {directory}")


def close(directory, reason):
    """Operator decision to end a stopped campaign: its data stays, its group names become reusable."""
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if not reason.strip():
        raise ValueError("closing a campaign requires a reason")
    names = vm_names(p)
    with ExitStack() as locks:
        # No runner of any campaign may be active; multi-VM: no runner on any of its domains.
        for row in collection.vms(p):
            locks.enter_context(collection.collection_lock(COLLECTIONS, row["domain"] if row["name"] else None))
        states = {vm: read_json(directory / vm_file("status.json", vm))
                  if (directory / vm_file("status.json", vm)).exists() else {} for vm in names}
        state = states[None] if names == [None] else {"vms": states}
        # One VM's finished share (vm-complete) does not complete the campaign.
        for each in states.values():
            if each.get("status") == "closed" or (each.get("status") == "complete"
                                                  and each.get("stage") != "vm-complete"):
                raise ValueError("campaign is already " + each["status"])
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        write_new(directory / "closed.json", {
            "schema": "hyptcn3/campaign-closed/1", "id": manifest["id"], "date": now(), "reason": reason,
            "uid": os.getuid(), "status_before": state,
            "note": "Operator decision. Captured, audited and archived sessions remain; no corpus index."})
        copy_exclusive(directory / "closed.json", Path(manifest["archive_dir"]) / "closed.json")
        for vm in names:
            update_state(directory, vm=vm, status="closed", stage="closed", message=reason)


def status(directory):
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if vm_names(p) == [None]:
        state = vm_status(directory, manifest, p, None)
    else:
        state = {"campaign": str(directory), "vms": {vm: vm_status(directory, manifest, p, vm) for vm in vm_names(p)}}
    print(json.dumps(state, indent=2, ensure_ascii=False))
    return state


def vm_status(directory, manifest, p, vm):
    state = read_json(directory / vm_file("status.json", vm))
    state["running"] = campaign_running(state)
    # Every audit rejection with its cause and, if the protocol allowed one, its replacement.
    state["rejections"] = [{k: r.get(k) for k in ("date", "session", "reasons", "replacement")}
                           for r in rejections(directory, vm)]
    if state.get("status") == "running" and not state["running"]:
        state["stale"] = True
        state["note"] = ("recorded as running but that process is not alive (SIGKILL, crash or power loss); "
                         "the current session is incomplete and the next run records an unclean end")
    state["sleep_inhibitor_active"] = sleep_inhibited()
    state["campaign"] = str(directory)
    state["planned_capture_hours"] = manifest["planned_capture_hours"]
    if state.get("session"):
        raw = session_dir(manifest, {"session_id": state["session"], **({} if vm is None else {"vm": vm})}) / "raw"
        state["snapshot_images_present"] = len(list(raw.glob("*.vmicd")))
        state["snapshots_expected"] = p["cycles"]
    return state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Freeze accepted pilot, plan, source and external mount")
    init.add_argument("--protocol", type=Path, default=collection.DEFAULT)
    init.add_argument("--pilot-report", action="append", required=True, metavar="[VM=]PATH",
                      help="Accepted pilot audit; multi-VM protocol: one VM=PATH per VM")
    init.add_argument("--archive-root", type=Path, required=True)
    init.add_argument("--name")
    init.add_argument("--archive-on-system-disk", action="store_true",
                      help="Explicitly allow an archive on the root filesystem (no second disk)")
    init.add_argument("--archive-compression", choices=["zstd", "none"], default="zstd")
    for verb in ("run", "launch", "status", "verify-archives", "request-stop", "close"):
        cmd = sub.add_parser(verb)
        cmd.add_argument("directory", type=Path)
        if verb in ("run", "launch"):
            cmd.add_argument("--stop-after", type=int, help="Stop after this many newly archived sessions")
        if verb in ("run", "launch", "request-stop"):
            cmd.add_argument("--vm", help="Multi-VM campaign: this VM's runner (run requires it; "
                                          "launch and request-stop default to all VMs)")
        if verb == "close":
            cmd.add_argument("--reason", required=True, help="Recorded operator decision")
    a = ap.parse_args(argv)
    if getattr(a, "stop_after", None) is not None and a.stop_after < 1:
        ap.error("stop-after must be positive")
    if a.command == "init":
        initialize(a)
    elif a.command == "status":
        status(a.directory)
    elif a.command == "launch":
        launch(a.directory, a.stop_after, a.vm)
    elif a.command == "run":
        return execute(a.directory, stop_after=a.stop_after, vm=a.vm)
    elif a.command == "request-stop":
        request_stop(a.directory, a.vm)
    elif a.command == "close":
        close(a.directory, a.reason)
    else:
        manifest, _ = load_campaign(a.directory)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        for row in (r for planned in manifest["sessions"] for r in chain(a.directory.resolve(), planned)):
            dest = archive_dest(manifest, row)
            if dest.exists():
                verify_archive(dest, session_dir(manifest, row))
                print("verified " + row["session_id"], flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"campaign: {error}", file=sys.stderr)
        sys.exit(2)
