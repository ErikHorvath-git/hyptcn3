#!/usr/bin/env python3
"""Guest-side evidence for the benign lab, run as root through qemu-guest-agent.

Orchestration helper only (not a security agent and not a RAM collector):
it reports service/database state and closes nginx/journal log segments
between measured sessions so that each segment belongs to exactly one run.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

LOGS = Path("/var/log/hyptcn-lab")
SEGMENTS = LOGS / "segments"
UNITS = ["hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@worker",
         "nginx", "postgresql@15-main", "qemu-guest-agent", "systemd-timesyncd", "systemd-journald"]
RETENTION = ("worker marks pending orders completed (batches of 50, ~1 s loop) and deletes "
             "completed orders with created_at older than 1 day; nothing else is deleted")


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=120).stdout


def label_ok(label):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,120}", label):
        raise SystemExit("invalid segment label")
    return label


def units():
    keys = ("ActiveState", "SubState", "NRestarts", "ExecMainPID", "ExecMainStartTimestampMonotonic",
            "ActiveEnterTimestampMonotonic", "InvocationID", "Result")
    result = {}
    for unit in UNITS:
        out = run("systemctl", "show", unit, "-p", ",".join(keys), check=False)
        result[unit] = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return result


def database():
    query = ("SELECT count(*), count(*) FILTER (WHERE status='pending'), count(*) FILTER (WHERE status='completed'), "
             "coalesce(max(id),0), extract(epoch FROM min(created_at)), extract(epoch FROM max(created_at)), "
             "pg_database_size('hyptcn_lab'), pg_total_relation_size('orders'), "
             "(SELECT extract(epoch FROM now() - updated_at) FROM worker_heartbeat WHERE id=1), "
             "(SELECT last_value FROM orders_id_seq) FROM orders")
    out = run("runuser", "-u", "postgres", "--", "psql", "-XtAF", "|", "hyptcn_lab", "-c", query).strip()
    names = ("orders", "pending", "completed", "max_id", "min_created_unix", "max_created_unix",
             "database_bytes", "orders_relation_bytes", "worker_heartbeat_age_s", "orders_id_seq_last")
    values = [None if v == "" else float(v) if "." in v else int(v) for v in out.split("|")]
    return dict(zip(names, values))


def state():
    stat = os.statvfs("/")
    meminfo = dict((line.split(":")[0], int(line.split()[1])) for line in Path("/proc/meminfo").read_text().splitlines()
                   if line.split(":")[0] in ("MemTotal", "MemAvailable", "Cached", "Dirty", "SwapTotal", "SwapFree"))
    timesync = dict(line.split("=", 1) for line in run("timedatectl", "show", check=False).splitlines() if "=" in line)
    doc = {"schema": "hyptcn3/guest-state/1", "utc_unix": time.time(),
           "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
           "uptime_s": float(Path("/proc/uptime").read_text().split()[0]),
           "kernel": os.uname().release, "units": units(), "database": database(),
           "retention_policy": RETENTION,
           "root_fs": {"total_bytes": stat.f_blocks * stat.f_frsize, "free_bytes": stat.f_bavail * stat.f_frsize},
           "meminfo_kb": meminfo, "loadavg": Path("/proc/loadavg").read_text().split()[:3],
           "timesync": {k: timesync.get(k) for k in ("NTP", "NTPSynchronized", "TimeUSec", "Timezone")},
           "journal_disk_usage": run("journalctl", "--disk-usage", check=False).strip(),
           "timers": run("systemctl", "list-timers", "--all", "--no-pager", check=False).splitlines(),
           "current_segment_bytes": {p.name: p.stat().st_size for p in LOGS.glob("nginx-*") if p.is_file()},
           "pending_segments": sorted(p.name for p in SEGMENTS.glob("*"))}
    print(json.dumps(doc, sort_keys=True))


def describe(path):
    """Hash the uncompressed segment, gzip it and hash the transfer copy."""
    digest, lines, first, last = hashlib.sha256(), 0, None, None
    with path.open("rb") as stream, gzip.open(str(path) + ".gz", "wb", compresslevel=1) as packed:
        for line in stream:
            digest.update(line)
            packed.write(line)
            lines += 1
            first = first if first is not None else line
            last = line
    packed_path = Path(str(path) + ".gz")
    with packed_path.open("rb") as stream:
        packed_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"name": path.name, "bytes": path.stat().st_size, "sha256": digest.hexdigest(), "lines": lines,
            "terminated": last is None or last.endswith(b"\n"),
            "first_line": first.decode(errors="replace")[:600] if first else None,
            "last_line": last.decode(errors="replace")[:600] if last else None,
            "gz_path": str(packed_path), "gz_bytes": packed_path.stat().st_size, "gz_sha256": packed_sha}


def segment(label):
    """Close the current nginx segment; nginx flushes buffers before reopening."""
    label = label_ok(label)
    SEGMENTS.mkdir(parents=True, exist_ok=True)
    moved = []
    for name in ("nginx-access.jsonl", "nginx-error.log"):
        source, target = LOGS / name, SEGMENTS / f"{label}-{name}"
        if target.exists() or Path(str(target) + ".gz").exists():
            raise SystemExit("segment already exists: " + target.name)
        if source.exists():
            os.rename(source, target)
        else:
            target.touch()
        moved.append(target)
    os.kill(int(Path("/run/nginx.pid").read_text()), signal.SIGUSR1)
    deadline = time.monotonic() + 15
    while not all((LOGS / name).exists() for name in ("nginx-access.jsonl", "nginx-error.log")):
        if time.monotonic() > deadline:
            raise SystemExit("nginx did not reopen its logs")
        time.sleep(.1)
    time.sleep(3)  # Worker buffers (flush=2s) are written to the old file on reopen.
    print(json.dumps({"schema": "hyptcn3/guest-log-segment/1", "label": label, "closed_unix": time.time(),
                      "files": [describe(path) for path in moved]}, sort_keys=True))


def journal(label, since, until):
    label = label_ok(label)
    since, until = float(since), float(until)
    SEGMENTS.mkdir(parents=True, exist_ok=True)
    target = SEGMENTS / f"{label}-journal.txt"
    if target.exists():
        raise SystemExit("journal segment already exists")
    with target.open("x") as stream:
        subprocess.run(["journalctl", "--utc", "--no-pager", "-o", "short-iso-precise",
                        "--since", f"@{since:.6f}", "--until", f"@{until:.6f}"],
                       check=True, stdout=stream, timeout=600)
    print(json.dumps({"schema": "hyptcn3/guest-journal-segment/1", "label": label, "since_unix": since,
                      "until_unix": until, "files": [describe(target)]}, sort_keys=True))


def cleanup(label):
    label = label_ok(label)
    removed = []
    for path in SEGMENTS.glob(f"{label}-*"):
        path.unlink()
        removed.append(path.name)
    print(json.dumps({"label": label, "removed": sorted(removed)}))


def main(argv):
    if not argv:
        raise SystemExit("usage: guest_state.py state|segment LABEL|journal LABEL SINCE UNTIL|cleanup LABEL")
    command, args = argv[0], argv[1:]
    if command == "state" and not args:
        state()
    elif command == "segment" and len(args) == 1:
        segment(*args)
    elif command == "journal" and len(args) == 3:
        journal(*args)
    elif command == "cleanup" and len(args) == 1:
        cleanup(*args)
    else:
        raise SystemExit("invalid guest_state.py arguments")


if __name__ == "__main__":
    os.umask(0o027)
    main(sys.argv[1:])
