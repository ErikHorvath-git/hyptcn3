#!/usr/bin/env python3
"""Plan, capture and audit benign research sessions. Never runs attack samples.

Original protocol tooling for hyptcn3. Data and verdicts are written exclusively;
failed sessions remain on disk. Run audit again with a new output name.
"""
import argparse
from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.contract import validate_sidecar
from features.archive import load, save
from features.snapshot import retazec, MENA
from features.windows import okna, snimky_z_matice
from features.perbin import FeatureError
from features.windows import WindowError
from features.quality import protocol_policy, valid_for

DEFAULT = ROOT / "config/collection-v2.json"
COLLECTIONS = ROOT / "data/collections"  # Global lock; diagnostics only change the session base.
DIAGNOSTICS = ROOT / "data/diagnostics"
SESSION_SCHEMA = "hyptcn3/collection-session/2"
END_SCHEMA = "hyptcn3/collection-end/2"
MEASUREMENT_DIRS = ("features", "guestparse", "scripts", "lab", "vmicollect")
SOURCE_SUFFIXES = (".py", ".c", ".h", ".sh", ".sql", ".conf", ".service")
# Reporting/documentation tools do not take part in capture, audit or archival.
NOT_MEASUREMENT = {"scripts/campaign_report.py", "scripts/gen_prirucka.py", "scripts/check_claims.sh",
                   "scripts/check_prirucka.sh", "scripts/stamp_results.py"}
EVIDENCE = ("preflight_smoke.json", "host_monitor.jsonl", "traffic.json", "traffic.log", "traffic_before.json",
            "traffic_requests.jsonl", "traffic_intervals.jsonl", "capture.log", "guest/state_before.json",
            "guest/state_after.json", "guest/clock_before.json", "guest/clock_after.json",
            "guest/pre_segment.json", "guest/session_segment.json", "guest/journal_segment.json")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, doc):
    with Path(path).open("x") as stream:
        json.dump(doc, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def protocol(path):
    p = json.loads(Path(path).read_text())
    protocol_policy(p)
    gate = p.get("min_score_coverage", .85)
    if type(gate) not in (int, float) or not 0 < gate <= 1:
        raise ValueError("invalid minimum score coverage")
    for key in ("interval_s", "window_rows", "full_every", "cycles", "pilot_cycles", "bin_bytes"):
        if type(p[key]) is not int or p[key] < 1:
            raise ValueError("invalid " + key)
    if not p["interval_s"] < p["max_gap_s"] < 2 * p["interval_s"]:
        raise ValueError("gap must distinguish a missed sampling slot")
    if p["full_every"] <= p["window_rows"] or p["pilot_cycles"] <= p["full_every"] + p["window_rows"]:
        raise ValueError("pilot must cover two full snapshots and score after both")
    if p["bin_bytes"] != 16777216:
        raise ValueError("capture runner currently supports 16 MiB bins")
    return p


def plan(p):
    result = []
    # Each role/repetition is a separate boot group. Adjacent chunks of a
    # running VM cannot become independent train/calibration/test sessions.
    for role, count in p["roles"].items():
        for repetition in range(count):
            scenarios = list(p["scenarios"])
            seed = int.from_bytes(hashlib.sha256(f"{role}/{repetition}".encode()).digest()[:4], "big")
            random.Random(seed).shuffle(scenarios)
            for scenario in scenarios:
                result.append({"role": role, "group": f"{role}-{repetition + 1}",
                               "scenario": scenario, "seed": seed + len(result),
                               "cycles": p["cycles"]})
    return {"schema": "hyptcn3/collection-plan/1", "sessions": result,
            "planned_hours": len(result) * p["cycles"] * p["interval_s"] / 3600,
            "note": "Design allocation, not collected data; pilot and overhead runs are separate."}


def user_command(command):
    user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and user:
        import pwd
        uid = pwd.getpwnam(user).pw_uid
        # LIBVIRT_AUTOSTART=0: a missing session daemon is an error here. An
        # auto-spawned daemon would live (and die) inside the runner's cgroup.
        return ["runuser", "-u", user, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}", "LIBVIRT_AUTOSTART=0",
                *map(str, command)]
    return list(map(str, command))


def measurement_sources():
    """Hashes of code that captures, checks or archives data (tests and reports excluded)."""
    files = [f for d in MEASUREMENT_DIRS for f in (ROOT / d).rglob("*")
             if f.is_file() and f.suffix in SOURCE_SUFFIXES and "tests" not in f.relative_to(ROOT).parts
             and str(f.relative_to(ROOT)) not in NOT_MEASUREMENT]
    return {str(f.relative_to(ROOT)): digest(f) for f in sorted(files)}


def storage_identity(path):
    """Filesystem holding a working directory (bind mounts show their source)."""
    doc = json.loads(subprocess.check_output(["findmnt", "-J", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE,UUID"],
                                             text=True, timeout=10))
    return doc["filesystems"][0]


def lab_json(p, *args, timeout=600):
    """labctl as the VM owner (qemu:///session); its reply is one JSON document."""
    command = [sys.executable, ROOT / "scripts/labctl.py", "--domain", p["domain"], *args]
    return json.loads(subprocess.check_output(user_command(command), cwd=ROOT, text=True, timeout=timeout))


@contextmanager
def collection_lock(base):
    """A campaign passes the same open lock to its capture child only."""
    base.mkdir(parents=True, exist_ok=True)
    path = base / ".lock"
    inherited = os.environ.get("HYPTCN_COLLECTION_LOCK_FD")
    fd = os.dup(int(inherited)) if inherited else os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        stat, expected = os.fstat(fd), path.stat()
        if (stat.st_dev, stat.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError("inherited collection lock refers to another file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def guest_identity(p):
    identity_command = (
        "uname -r; cat /proc/sys/kernel/random/boot_id; cat /etc/machine-id; "
        "sha256sum /opt/hyptcn-lab/services.py /opt/hyptcn-lab/schema.sql /opt/hyptcn-lab/guest_state.py "
        "/etc/nginx/conf.d/hyptcn-lab.conf /etc/systemd/system/hyptcn-lab@.service && "
        "dpkg-query -W nginx postgresql python3 python3-psycopg2")
    command = [sys.executable, ROOT / "scripts/labctl.py", "exec", "--domain", p["domain"],
               "--guest-command", identity_command]
    lines = subprocess.check_output(user_command(command), cwd=ROOT, text=True, timeout=150).strip().splitlines()
    if len(lines) < 12:
        raise ValueError("cannot establish guest identity")
    return {**dict(zip(("kernel", "boot_id", "machine_id"), lines[:3])),
            "stack_sha256": hashlib.sha256("\n".join(lines[3:]).encode()).hexdigest(),
            "stack_manifest": lines[3:]}


class Interrupts:
    """The first SIGINT/SIGTERM/SIGHUP interrupts the run once; later ones are only recorded.

    Repeated signals (systemd plus a forwarding parent, or an impatient
    operator) must not cut the cleanup that writes the truthful end record.
    """

    def __init__(self):
        self.received, self.armed = [], True
        # SIGHUP (closed SSH terminal) also ends in an orderly, recorded stop.
        self.previous = {s: signal.signal(s, self.handle) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

    def handle(self, signum, _frame):
        self.received.append({"signal": signum, "unix": time.time()})
        if self.armed:
            self.armed = False
            raise InterruptedError(f"interrupted by signal {signum}")

    def disarm(self):
        self.armed = False

    def restore(self):
        for sig, handler in self.previous.items():
            signal.signal(sig, handler)


def _child_setup():
    """New session plus SIGTERM if the runner itself dies (even by SIGKILL)."""
    os.setsid()
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG


def start_child(command, log, env=None):
    with open(log, "x") as stream:
        return subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, preexec_fn=_child_setup)


def stop_child(process, grace, *, first=signal.SIGTERM):
    """Signal the child's own process group, wait, escalate; report what happened."""
    if process is None:
        return None
    if process.poll() is not None:
        return {"pid": process.pid, "rc": process.returncode, "stopped_by": "exited"}
    result = {"pid": process.pid, "stopped_by": signal.Signals(first).name}
    try:
        os.killpg(process.pid, first)
        process.wait(timeout=grace)
    except ProcessLookupError:
        process.wait()
    except subprocess.TimeoutExpired:
        result["stopped_by"] = "SIGKILL after %ss" % grace
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    result["rc"] = process.returncode
    return result


def generators(exclude=()):
    """Host generator processes not started by this session."""
    found = []
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if any(arg.endswith(b"host_traffic.py") for arg in argv) and int(proc.name) not in exclude:
            found.append(int(proc.name))
    return found


def qemu_process(domain):
    """Identity of the running QEMU process; changes when the VM is restarted or restored."""
    marker = f"guest={domain},".encode()
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            argv = (proc / "cmdline").read_bytes()
            stat = (proc / "stat").read_text()
        except OSError:
            continue
        if argv.startswith(b"/usr/bin/qemu-system") and marker in argv:
            return {"pid": int(proc.name), "start_ticks": int(stat.rsplit(")", 1)[1].split()[19]),
                    "host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    return None


def file_record(path, base):
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    record = {"size": path.stat().st_size, "sha256": sha}
    if path.suffix in (".jsonl", ".log"):
        with path.open("rb") as stream:
            data = stream.read()
        record["lines"] = data.count(b"\n")
        record["terminated"] = not data or data.endswith(b"\n")
    return record


def write_logs_manifest(out):
    """Hash every evidence file outside raw/; the audit recomputes and compares."""
    files = {}
    for path in sorted(out.rglob("*")):
        name = path.relative_to(out).as_posix()
        if (path.is_file() and not path.is_symlink() and not name.startswith("raw/")
                and name not in ("session.json", "end.json", "logs_manifest.json")
                and not re.fullmatch(r"(campaign_)?audit_.*", name)):
            files[name] = file_record(path, out)
    doc = {"schema": "hyptcn3/session-logs/1", "date": datetime.now(timezone.utc).isoformat(), "files": files}
    write_json(out / "logs_manifest.json", doc)
    return digest(out / "logs_manifest.json")


def smoke_rids(path):
    return {c["rid"]: c["status"] for c in json.loads(Path(path).read_text())["values"]["checks"]}


def nginx_lines(path):
    with gzip.open(path, "rt") as stream:
        for line in stream:
            yield json.loads(line)


def run_session(a, p):
    if os.geteuid() != 0:
        raise ValueError("host eBPF capture needs sudo; plan and audit do not")
    if a.scenario not in p["scenarios"]:
        raise ValueError("unknown benign scenario")
    base = Path(getattr(a, "collections_dir", None) or COLLECTIONS).absolute()
    diagnostic = a.role == "diagnostic"
    if diagnostic != base.is_relative_to(DIAGNOSTICS):
        raise ValueError("diagnostic runs (and only they) must use a directory under data/diagnostics")
    if getattr(a, "cycles", None) and not diagnostic:
        raise ValueError("--cycles is only allowed for diagnostic runs")
    base.mkdir(parents=True, exist_ok=True)
    with collection_lock(COLLECTIONS):
        before = guest_identity(p)
        if getattr(a, "expected_boot_id", None) and before["boot_id"] != a.expected_boot_id:
            raise ValueError("guest boot differs from campaign group")
        attempt = getattr(a, "group_attempt", 1) or 1
        if a.role not in ("pilot", "diagnostic"):
            assignment = {"role": a.role, "group": a.group, "scenario": a.scenario,
                          "seed": a.seed, "cycles": p["cycles"]}
            if assignment not in plan(p)["sessions"]:
                raise ValueError("assignment/seed not present in frozen collection plan")
            if not a.pilot_report:
                raise ValueError("corpus capture requires --pilot-report from an accepted pilot audit")
            report = json.loads(Path(a.pilot_report).read_text())
            if (not report["values"]["accepted"] or report["values"].get("role") != "pilot"
                    or report["values"]["protocol_sha256"] != digest(a.protocol)):
                raise ValueError("pilot report is not accepted for this protocol")
            needed = report["values"]["raw_bytes"] * p["cycles"] / p["pilot_cycles"] * 1.5
        else:
            needed = 0
        if shutil.disk_usage(base).free < needed + p["min_free_gib"] * 2**30:
            raise ValueError("insufficient disk budget; archive existing captures first")
        # Immutable start records, including unfinished/failed runs: a boot belongs to
        # one group attempt only, and a group (across its attempts) to one role.
        mine = (getattr(a, "campaign_id", None), a.group, attempt)
        for path in base.glob("*/session.json"):
            old = json.loads(path.read_text())
            theirs = (old.get("campaign_id"), old["group"], old.get("group_attempt", 1))
            if old["group"] == a.group and old["role"] != a.role:
                raise ValueError("group already belongs to a different split")
            if old["guest_before"]["boot_id"] == before["boot_id"] and theirs != mine:
                raise ValueError("same guest boot already belongs to another group or group attempt")
            if theirs == mine and old["guest_before"]["boot_id"] != before["boot_id"]:
                raise ValueError("one boot must correspond to exactly one collection group attempt")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        session_id = getattr(a, "session_id", None) or f"{stamp}_{a.role}_{a.scenario}"
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}", session_id):
            raise ValueError("invalid session ID")
        cycles = a.cycles if diagnostic and a.cycles else p["pilot_cycles"] if a.role in ("pilot", "diagnostic") else p["cycles"]
        out = base / session_id
        out.mkdir()
        shutil.copyfile(a.protocol, out / "protocol.json")
        prof = ROOT / p["profile"]
        shutil.copytree(prof, out / "profile")
        source_files = [f for directory in MEASUREMENT_DIRS for f in (ROOT / directory).rglob("*")
                        if f.is_file() and f.suffix in SOURCE_SUFFIXES]
        source_hashes = {str(f.relative_to(ROOT)): digest(f) for f in source_files}
        subprocess.run(user_command(["make", "-C", ROOT / "vmicollect"]), check=True)
        s = p["scenarios"][a.scenario]
        metadata = {"schema": SESSION_SCHEMA, "session_id": out.name,
                    "campaign_id": getattr(a, "campaign_id", None),
                    "role": a.role, "group": a.group, "group_attempt": attempt, "scenario": a.scenario,
                    "typ": "benign", "seed": a.seed, "cycles": cycles, "guest_before": before,
                    "protocol_sha256": digest(a.protocol), "source_sha256": source_hashes,
                    "measurement_sha256": measurement_sources(),
                    "profile_sha256": {str(f.relative_to(prof)): digest(f) for f in prof.rglob("*") if f.is_file()},
                    "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect"),
                    "collector_settings": {"writer": "delta", "fsync": True, "hash": "sha256",
                                           "interval_s": p["interval_s"], "full_every": p["full_every"],
                                           "bin_bytes": p["bin_bytes"]},
                    "traffic": {"generator": "scripts/host_traffic.py", "profile": "lab", "target": p["target"],
                                "seed": a.seed, "workers": s["workers"], "burst": s["burst"],
                                "catalog_share": s["catalog_share"], "write_share": s["write_share"],
                                "summary_interval_s": 5, "load_model": "closed loop, not a fixed request rate"},
                    "metadata_not_model_inputs": ["scenario", "seed", "traffic", "boot_id", "group", "session_id"],
                    "working_storage": storage_identity(base),
                    "host_context": {"host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                                     "qemu": qemu_process(p["domain"]), "python": sys.executable},
                    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                    "host": platform.platform(), "created_unix": time.time()}
        write_json(out / "session.json", metadata)
        subprocess.run(user_command(["virsh", "-c", "qemu:///session", "dumpxml", p["domain"]]),
                       stdout=(out / "domain.xml").open("x"), check=True)
        print(f"session: {out}", flush=True)
        capture_session(p, out, metadata, cycles)
        print(f"Audit: python3 scripts/collection.py audit {out}")


def capture_session(p, out, metadata, cycles):
    owner = (int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])) if "SUDO_UID" in os.environ else None
    guest = out / "guest"
    guest.mkdir()
    if owner:
        os.chown(guest, *owner)  # labctl runs as the VM owner and writes verified copies here.
    status = {"schema": END_SCHEMA, "completed": False, "interrupted": False, "steps": {}}
    children = {}
    interrupts = Interrupts()

    def step(name, **values):
        status["steps"][name] = {"unix": time.time(), **values}
        print(json.dumps({"step": name, **values}, default=str)[:400], flush=True)

    def write_guest(name, doc):
        write_json(guest / name, doc)

    try:
        # Preflight, all outside the measured interval: no other generator, a
        # functional stack, guest clock, guest state and a closed log segment.
        subprocess.run(user_command([sys.executable, ROOT / "scripts/labctl.py", "traffic-stop"]), check=True)
        if generators():
            raise ValueError("another host_traffic.py is running; refusing to mix traffic")
        clock = lab_json(p, "clock", timeout=60)
        if abs(clock["offset_s"]) > 1.0:
            synced = lab_json(p, "sync-clock", timeout=60)
            clock = {**synced["after"], "synced_from": synced["before"]}
            if abs(clock["offset_s"]) > 1.0:
                raise ValueError("guest clock offset above 1 s after synchronization")
        write_guest("clock_before.json", clock)
        step("clock", offset_s=clock["offset_s"], synced="synced_from" in clock)
        smoke = subprocess.run([sys.executable, ROOT / "scripts/lab_smoke.py", "--target", p["target"],
                                "--out", out / "preflight_smoke.json"], cwd=ROOT, capture_output=True,
                               text=True, timeout=120)
        if smoke.returncode:
            raise ValueError("preflight functional check failed: " + (smoke.stdout + smoke.stderr)[-500:])
        step("functional-check", result=smoke.stdout.strip()[-200:])
        write_guest("state_before.json", lab_json(p, "state"))
        pre = lab_json(p, "segment", "--label", out.name + "-pre", "--dest", guest)
        write_guest("pre_segment.json", pre)
        expected = smoke_rids(out / "preflight_smoke.json")
        seen = {line["rid"]: line["status"] for line in nginx_lines(guest / (out.name + "-pre-nginx-access.jsonl.gz"))
                if line["rid"] in expected}
        if seen != expected:
            raise ValueError("request ID correlation failed for the preflight checks")
        step("pre-segment", lines=pre["files"][0]["lines"], correlated=len(seen))
        s = p["scenarios"][metadata["scenario"]]
        children["monitor"] = start_child(
            [sys.executable, ROOT / "scripts/host_monitor.py", "run", "--out", out / "host_monitor.jsonl",
             "--interval-s", "1", "--session-id", out.name, "--path", str(out), "--path", "/",
             "--match", f"qemu=guest={p['domain']},", "--match", "vmicollect=vmicollect/build/vmicollect",
             "--match", "traffic=host_traffic.py", "--match", "passt=^passt ", "--match", "monitor=host_monitor.py"],
            out / "host_monitor.log")
        children["traffic"] = start_child(
            [sys.executable, ROOT / "scripts/host_traffic.py", "--profile", "lab", "--target", p["target"],
             "--dur", "0", "--seed", str(metadata["seed"]), "--vlakien", str(s["workers"]),
             "--burst", str(s["burst"]), "--catalog-share", str(s["catalog_share"]),
             "--write-share", str(s["write_share"]), "--session-id", out.name,
             "--requests-log", out / "traffic_requests.jsonl", "--intervals-log", out / "traffic_intervals.jsonl",
             "--summary-interval-s", "5", "--initial-phase", "warmup", "--out", out / "traffic.json"],
            out / "traffic.log")
        step("warmup", seconds=p["warmup_s"])
        deadline = time.monotonic() + p["warmup_s"]
        while time.monotonic() < deadline:
            for name in ("traffic", "monitor"):
                if children[name].poll() is not None:
                    raise ValueError(f"{name} exited during warmup")
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        metrics = json.loads((out / "traffic.json").read_text())
        if not metrics["ok"] or metrics["errors"] or metrics.get("logging_error"):
            raise ValueError("warmup traffic failed")
        write_json(out / "traffic_before.json", metrics)
        if generators(exclude={children["traffic"].pid}):
            raise ValueError("another host_traffic.py appeared during warmup")
        os.kill(children["traffic"].pid, signal.SIGUSR1)
        status["measure_start_unix"] = time.time()
        env = dict(os.environ, VMIC_DOMAIN=p["domain"], VMIC_INTERVAL=str(p["interval_s"]),
                   VMIC_FULL_EVERY=str(p["full_every"]), VMIC_OUT=str(out / "raw"), VMIC_FSYNC="true",
                   VMIC_MANAGED_SESSION="1")
        status["capture_started_unix"] = time.time()
        children["collector"] = start_child(["bash", "scripts/lab_capture.sh", str(cycles)], out / "capture.log", env)
        step("capture", cycles=cycles)
        checked = 0
        while children["collector"].poll() is None:
            for name in ("traffic", "monitor"):
                if children[name].poll() is not None:
                    raise ValueError(f"{name} exited during capture")
            if shutil.disk_usage(out).free < p["min_free_gib"] * 2**30:
                raise ValueError("disk reserve reached; preserving partial session")
            if time.monotonic() - checked > 15:
                checked = time.monotonic()
                if generators(exclude={children["traffic"].pid}):
                    raise ValueError("another host_traffic.py appeared during capture")
            time.sleep(1)
        status["capture_finished_unix"] = time.time()
        status["collector_rc"] = children["collector"].returncode
        if children["collector"].returncode:
            raise ValueError("collector failed; see capture.log")
        os.kill(children["traffic"].pid, signal.SIGUSR2)
        status["measure_end_unix"] = time.time()
        status["traffic"] = stop_child(children["traffic"], 30)
        children.pop("traffic")
        # Request errors or a logging failure (rc 1/3) are audit reasons, not a broken capture.
        status["traffic_rc"] = status["traffic"]["rc"]
        status["guest_after"] = guest_identity(p)
        if status["guest_after"] != metadata["guest_before"]:
            raise ValueError("guest rebooted or changed during capture")
        if qemu_process(p["domain"]) != metadata["host_context"]["qemu"]:
            raise ValueError("VM process restarted during capture")
        # Larger guest logs only now, between measurements.
        segment = lab_json(p, "segment", "--label", out.name, "--dest", guest)
        write_guest("session_segment.json", segment)
        journal = lab_json(p, "journal", "--label", out.name + "-journal", "--since",
                           str(metadata["created_unix"]), "--until", str(time.time()), "--dest", guest)
        write_guest("journal_segment.json", journal)
        write_guest("state_after.json", lab_json(p, "state"))
        write_guest("clock_after.json", lab_json(p, "clock", timeout=60))
        step("guest-evidence", nginx_lines=segment["files"][0]["lines"])
        status["monitor"] = stop_child(children["monitor"], 15)
        children.pop("monitor")
        status["completed"] = True
    except BaseException as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        status["interrupted"] = isinstance(exc, InterruptedError)
        raise
    finally:
        try:
            interrupts.disarm()
        except InterruptedError:
            pass  # The first signal landed exactly here; the handler disarmed itself.
        # Collector first, so no snapshot is taken without its generator.
        for name, grace in (("collector", 60), ("traffic", 30), ("monitor", 15)):
            if name in children:
                status[name] = stop_child(children.pop(name), grace)
        status["signals"] = interrupts.received
        if status["interrupted"]:
            status["note"] = ("Interrupted run: the guest log segment was not closed here; the next "
                              "session's pre-segment keeps those nginx lines. Not a usable capture.")
        try:
            status["logs_manifest_sha256"] = write_logs_manifest(out)
        except OSError as exc:
            status["logs_manifest_error"] = str(exc)
        status["written_unix"] = time.time()
        write_json(out / "end.json", status)
        interrupts.restore()
        if owner:
            for path in [out, *out.rglob("*")]:
                os.chown(path, *owner, follow_symlinks=False)


def analyze_windows(result, p, session):
    """Audit the frozen input policy while retaining independent integrity gaps."""
    policy = protocol_policy(p)
    if result["quality_policy"] != policy:
        raise ValueError("extraction quality policy differs from protocol")
    if result["valid"] != [valid_for(q, policy) for q in result["quality"]]:
        raise ValueError("valid mask differs from structured quality")
    rows = snimky_z_matice(session, result["matica"], MENA, result["casy"],
                          result["seq"], result["valid"])
    windows = okna(rows, dlzka=p["window_rows"], max_medzera_s=p["max_gap_s"])
    coverage = len(windows) / len(rows)
    reasons = []
    if not all(result["valid"]):
        reasons.append("incomplete model inputs under " + policy)
    if any(q["findings"] for q in result["quality"]):
        reasons.append("integrity findings require review before benign admission")
    gate = p.get("min_score_coverage", .85)
    if coverage < gate:
        reasons.append(f"score coverage below design gate {gate:g}")
    checks = {"syscall_table", "process_cross_view", "modules", "text_integrity"}
    checks.update(name for q in result["quality"] for name in q["inconclusive"])
    quality = {
        "policy": policy,
        "behavior_valid_rows": sum(q["behavior_valid"] for q in result["quality"]),
        "legacy_valid_rows": sum(q["model_valid"] for q in result["quality"]),
        "invalid_input_seq": [seq for seq, good in zip(result["seq"], result["valid"]) if not good],
        "integrity_inconclusive_rows": {
            name: sum(name in q["inconclusive"] for q in result["quality"]) for name in sorted(checks)},
        "integrity_finding_rows": sum(bool(q["findings"]) for q in result["quality"]),
        "integrity_findings": sum(len(q["findings"]) for q in result["quality"]),
    }
    return rows, windows, coverage, reasons, quality


def audit_session(directory, p, protocol_path, output=None):
    directory = Path(directory).resolve()
    native = (directory / "session.json").exists()
    raw = directory / "raw" if native else directory
    metadata = json.loads((directory / "session.json").read_text()) if native else {}
    reasons = []
    if not native:
        reasons.append("historical capture without protocol/session provenance; exploratory only")
    elif metadata["protocol_sha256"] != digest(protocol_path):
        reasons.append("protocol hash mismatch")
    end = json.loads((directory / "end.json").read_text()) if native and (directory / "end.json").exists() else {}
    if native and (not end.get("completed") or end.get("guest_after") != metadata["guest_before"]):
        reasons.append("incomplete capture or changed guest identity")
    if native:
        hashes = {str(f.relative_to(directory / "profile")): digest(f)
                  for f in (directory / "profile").rglob("*") if f.is_file()}
        if hashes != metadata["profile_sha256"]:
            reasons.append("kernel profile changed since capture")
        capture = json.loads((raw / "capture.json").read_text())
        if (capture["values"]["collector_sha256"] != metadata["collector_sha256"]
                or capture["values"]["full_every"] != p["full_every"]
                or capture["values"]["interval_s"] != p["interval_s"]):
            reasons.append("collector binary or temporal settings mismatch")
    sidecars = []
    for path in raw.glob("*.json"):
        doc = json.loads(path.read_text())
        if doc.get("schema") == "vmicollect/1":
            validate_sidecar(doc)
            if doc["features"]["bin_bytes"] != p["bin_bytes"]:
                reasons.append("bin width differs from protocol")
            sidecars.append((path, doc))
    sidecars.sort(key=lambda item: item[1]["seq"])
    if not sidecars:
        raise ValueError("no collector sidecars")
    if len(list(raw.glob("*.vmicd"))) != len(sidecars):
        reasons.append("image/sidecar count mismatch")
    # Diagnostic runs are shorter by design; their recorded length is the target.
    expected = (p["pilot_cycles"] if metadata.get("role") == "pilot" else
                metadata.get("cycles") if metadata.get("role") == "diagnostic" else p["cycles"])
    if len(sidecars) != expected:
        reasons.append("snapshot count differs from assigned protocol")
    if [d["seq"] for _, d in sidecars] != list(range(len(sidecars))):
        reasons.append("sequence must start at zero and be contiguous")
    source_hashes = {}
    total_bytes = 0
    for path, side in sidecars:
        image = path.with_suffix(".vmicd")
        sha = digest(image)
        source_hashes[image.name] = sha
        source_hashes[path.name] = digest(path)
        total_bytes += image.stat().st_size
        if native and side["output"]["full"] != (side["seq"] % p["full_every"] == 0):
            reasons.append("full snapshot cadence differs from protocol")
        if native and side["output"].get("sha256") != sha:
            reasons.append("image checksum mismatch: " + image.name)
        if side["stats"]["read_errors"] or side["stats"]["filled_zero"] or side["sched"]["skipped_before"]:
            reasons.append("read errors/fill/missed slots: " + image.name)
        if side["capture"]["total_ms"] >= p["interval_s"] * 1000:
            reasons.append("collector cycle exceeded period")
    result = retazec(str(raw), str(directory / "profile" if native else ROOT / p["profile"]),
                    p["max_gap_s"], quality_policy=protocol_policy(p))
    rows, windows, coverage, quality_reasons, quality = analyze_windows(result, p, directory.name)
    reasons.extend(quality_reasons)
    if any(b - a != 1 for a, b in zip(result["seq"], result["seq"][1:])):
        reasons.append("sequence gap")
    if any(not 0 < b - a <= p["max_gap_s"] for a, b in zip(result["casy"], result["casy"][1:])):
        reasons.append("timestamp gap")
    span = result["casy"][-1] - result["casy"][0]
    if abs(span - (len(rows) - 1) * p["interval_s"]) > p["interval_s"]:
        reasons.append("sampling period differs from protocol")
    if native:
        before = json.loads((directory / "traffic_before.json").read_text())
        after = json.loads((directory / "traffic.json").read_text())
        if after["started_at"] != before["started_at"] or after["ok"] <= before["ok"] or after["errors"] != before["errors"]:
            reasons.append("traffic failed or no successful requests during capture")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = Path(output).resolve() if output else directory / f"audit_{stamp}.json"
    feature_path = output.with_suffix(".npz")
    save(feature_path, result)
    values = {"accepted": not reasons, "reasons": sorted(set(reasons)),
              "role": metadata.get("role"), "protocol_sha256": digest(protocol_path),
              "snapshots": len(rows), "windows": len(windows), "score_coverage": coverage,
              "quality": quality,
              "raw_bytes": total_bytes, "source_sha256": source_hashes,
              "session_sha256": digest(directory / "session.json") if native else None,
              "extractor_sha256": {str(f.relative_to(ROOT)): digest(f)
                                    for d in ("features", "guestparse") for f in (ROOT / d).rglob("*.py")
                                    if "tests" not in f.parts},
              "features": str(feature_path), "features_sha256": digest(feature_path),
              "layout": result["layout"], "session_dir": str(directory),
              "text_integrity_inconclusive_rows": sum("text_integrity" in q["inconclusive"] for q in result["quality"]),
              "feature_extraction_s": result["trvanie_s"],
              "note": "Offline feature audit. Does not certify live scoring latency, integrity baseline or detection."}
    report = {"schema": "hyptcn3/collection-audit/1", "date": datetime.now(timezone.utc).isoformat(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "host": platform.platform(), "guest": metadata.get("guest_before"),
              "command": " ".join(sys.argv), "n": len(rows), "values": values}
    write_json(output, report)
    print(json.dumps({"report": str(output), **{k: values[k] for k in
                     ("accepted", "reasons", "snapshots", "windows", "score_coverage", "raw_bytes")}}, indent=2))
    return 0 if values["accepted"] else 2


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--protocol", type=Path, default=DEFAULT)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    run = sub.add_parser("run")
    run.add_argument("--role", choices=["pilot", "diagnostic", "train", "dev", "calibration", "test_benign"],
                     required=True)
    run.add_argument("--scenario", default="steady")
    run.add_argument("--group", required=True)
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--pilot-report", type=Path)
    run.add_argument("--session-id", help="Exclusive output name for a frozen campaign assignment")
    run.add_argument("--campaign-id")
    run.add_argument("--expected-boot-id", help="Refuse a boot change since campaign preflight")
    run.add_argument("--group-attempt", type=int, default=1, help="Campaign group generation after a recorded restart")
    run.add_argument("--collections-dir", type=Path, help="Diagnostic session base under data/diagnostics")
    run.add_argument("--cycles", type=int, help="Diagnostic runs only: number of snapshots")
    audit = sub.add_parser("audit")
    audit.add_argument("directory", type=Path)
    audit.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    p = protocol(a.protocol)
    if a.command == "plan":
        print(json.dumps(plan(p), indent=2))
        return 0
    if a.command == "run":
        run_session(a, p)
        return 0
    return audit_session(a.directory, p, a.protocol, a.out)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, FeatureError, WindowError, subprocess.SubprocessError) as error:
        print(f"collection: {error}", file=sys.stderr)
        sys.exit(2)
