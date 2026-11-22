#!/usr/bin/env python3
"""Guest-side evidence for the benign lab, run as root through qemu-guest-agent.

Orchestration helper only (not a security agent and not a RAM collector):
it reports service/database state and closes nginx/journal log segments
between measured sessions so that each segment belongs to exactly one run.
Protocol v5 (proposal 5.4): `reset --seed S` returns the database and the
documents to the seeded level of lab/seed.py, `pretouch` lets one process
touch as much memory as the largest event and exit, `levels` prints the
level values recorded at the start of each session.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import signal
import subprocess
import sys
import time

LOGS = Path("/var/log/hyptcn-lab")
SEGMENTS = LOGS / "segments"
DATA = Path("/var/lib/hyptcn-lab")  # lab/services.py DATA: documents, reports, report spool, document log.
PROC = Path("/proc")
LAB_USER = "hyptcnlab"
UNITS = ["hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@docs", "hyptcn-lab@worker",
         "hyptcn-lab-udrzba.timer", "hyptcn-lab-udrzba.service",
         "nginx", "postgresql@15-main", "qemu-guest-agent", "systemd-timesyncd", "systemd-journald"]
RETENTION = ("worker marks pending orders completed (batches of 50, 0.8-1.2 s loop) and deletes "
             "completed orders with created_at older than 1 day; it keeps the newest 100 reports and "
             "hyptcn-lab-udrzba the newest 12 compressed document logs; reset --seed returns the "
             "database and the documents to the seeded level; nothing else is deleted")
MEMINFO = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "Dirty", "Shmem", "AnonPages",
           "SwapTotal", "SwapFree")
LEVELS = ("SELECT (SELECT count(*) FROM products), (SELECT count(*) FROM customers), (SELECT count(*) FROM employees), "
          "(SELECT count(*) FROM orders), (SELECT count(*) FROM orders WHERE status='pending'), "
          "(SELECT count(*) FROM order_items), (SELECT count(*) FROM cart_items), (SELECT count(*) FROM documents), "
          "pg_database_size('hyptcn_lab'), (SELECT count(*) FROM pg_stat_activity WHERE datname='hyptcn_lab')")
LEVEL_NAMES = ("products", "customers", "employees", "orders", "pending", "order_items", "cart_items", "documents",
               "database_bytes", "connections")


def run(*args, check=True, input=None, timeout=120):
    return subprocess.run(args, check=check, capture_output=True, text=True, input=input, timeout=timeout).stdout


def holders(paths):
    """PIDs that still have one of these files open (also after unlink)."""
    targets = {str(path) for path in paths} | {f"{path} (deleted)" for path in paths}
    found = set()
    for fd in Path("/proc").glob("[0-9]*/fd/*"):
        try:
            if os.readlink(fd) in targets:
                found.add(int(fd.parts[2]))
        except OSError:
            continue
    return sorted(found)


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
           "log_holders": {p.name: holders([p]) for p in LOGS.glob("nginx-*") if p.is_file()},
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
    # A worker that failed to reopen keeps appending to the closed segment;
    # such a segment is incomplete and must not be transferred or deleted.
    still_open = holders(moved)
    if still_open:
        raise SystemExit(f"nginx processes {still_open} did not reopen their logs; segment left in place")
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
    paths = list(SEGMENTS.glob(f"{label}-*"))
    if holders(paths):
        raise SystemExit("segment files are still open; not deleting them")
    for path in paths:
        path.unlink()
        removed.append(path.name)
    print(json.dumps({"label": label, "removed": sorted(removed)}))


def _clear(directory):
    for path in directory.glob("*"):
        if path.is_file():
            path.unlink()


def reset(seed_value):
    """Database and documents to the seeded level of `seed_value` (lab/seed.py); reports, the report spool and
    the document logs emptied. Static files are written at deployment and stay."""
    import seed
    started = time.time()
    data = seed.generate(seed_value)
    run("runuser", "-u", LAB_USER, "--", "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", "hyptcn_lab", "-f", "-",
        input=seed.sql_script(data, started), timeout=600)
    owner = pwd.getpwnam(LAB_USER)
    for directory in (DATA / "docs", DATA / "reports", DATA / "spool/queued", DATA / "spool/running",
                      DATA / "spool/failed", DATA / "logs"):
        _clear(directory)
    written = 0
    for doc in data["documents"]:
        content = seed.document_content(seed_value, doc["id"], doc["bytes"])
        if hashlib.sha256(content).hexdigest() != doc["sha256"]:
            raise SystemExit(f"seeded document {doc['id']} differs from its hash")
        path = DATA / "docs" / f"{doc['id']}.bin"
        path.write_bytes(content)
        os.chown(path, owner.pw_uid, owner.pw_gid)
        written += len(content)
    print(json.dumps({"schema": "hyptcn3/guest-reset/1", "seed": seed_value, "data_sha256": seed.digest(data),
                      "counts": {name: len(data[name]) for name in ("products", "customers", "employees", "orders",
                                                                     "order_items", "cart_items", "documents")},
                      "documents_bytes": written, "started_unix": started, "finished_unix": time.time()},
                     sort_keys=True))


def meminfo():
    values = {line.split(":")[0]: int(line.split()[1]) for line in (PROC / "meminfo").read_text().splitlines()}
    return {name: values.get(name) for name in MEMINFO}


def pretouch():
    """One process touches as much memory as the largest event (lab/udalosti.py zataz_pamate) and exits; run once
    before the first session of a group (proposal 5.4), so that this first touch is not inside a session."""
    import udalosti
    before, started = meminfo(), time.monotonic()
    result = subprocess.run(["runuser", "-u", "nobody", "--", "python3", "-c", udalosti.load_program(0)],
                            capture_output=True, text=True, timeout=300)
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    print(json.dumps({"schema": "hyptcn3/guest-pretouch/1", "mib": udalosti.LOAD_MIB, "exit_code": result.returncode,
                      "peak_rss_kib": peak, "touched": result.returncode == 0 and peak >= udalosti.LOAD_MIN_KIB,
                      "seconds": round(time.monotonic() - started, 3), "meminfo_kb_before": before,
                      "meminfo_kb_after": meminfo(), "stderr": result.stderr[-300:]}, sort_keys=True))
    if result.returncode != 0 or peak < udalosti.LOAD_MIN_KIB:
        raise SystemExit("pretouch did not touch the memory of the largest event")


def files(directory, pattern="*"):
    found = [p for p in directory.glob(pattern) if p.is_file()]
    return {"files": len(found), "bytes": sum(p.stat().st_size for p in found)}


def levels():
    """Level values at the start of a session (proposal 5.4): processes, memory, database rows and sizes, files."""
    processes = threads = 0
    for status in PROC.glob("[0-9]*/status"):
        try:
            text = status.read_text()
        except OSError:
            continue
        processes += 1
        threads += next((int(line.split()[1]) for line in text.splitlines() if line.startswith("Threads:")), 0)
    out = run("runuser", "-u", "postgres", "--", "psql", "-XtAF", "|", "hyptcn_lab", "-c", LEVELS).strip()
    stat = os.statvfs("/")
    print(json.dumps({"schema": "hyptcn3/guest-levels/1", "utc_unix": time.time(), "processes": processes,
                      "threads": threads, "meminfo_kb": meminfo(),
                      "loadavg": (PROC / "loadavg").read_text().split()[:3],
                      "database": dict(zip(LEVEL_NAMES, map(int, out.split("|")))),
                      "files": {"documents": files(DATA / "docs", "*.bin"), "reports": files(DATA / "reports"),
                                "reports_queued": files(DATA / "spool/queued"), "static": files(DATA / "static"),
                                "document_logs": files(DATA / "logs")},
                      "root_fs": {"total_bytes": stat.f_blocks * stat.f_frsize,
                                  "free_bytes": stat.f_bavail * stat.f_frsize}}, sort_keys=True))


def main(argv):
    if not argv:
        raise SystemExit("usage: guest_state.py state|segment LABEL|journal LABEL SINCE UNTIL|cleanup LABEL|"
                         "reset --seed S|pretouch|levels")
    command, args = argv[0], argv[1:]
    if command == "state" and not args:
        state()
    elif command == "segment" and len(args) == 1:
        segment(*args)
    elif command == "journal" and len(args) == 3:
        journal(*args)
    elif command == "cleanup" and len(args) == 1:
        cleanup(*args)
    elif command == "reset" and len(args) == 2 and args[0] == "--seed" and re.fullmatch(r"[0-9]{1,18}", args[1]):
        reset(int(args[1]))
    elif command == "pretouch" and not args:
        pretouch()
    elif command == "levels" and not args:
        levels()
    else:
        raise SystemExit("invalid guest_state.py arguments")


if __name__ == "__main__":
    os.umask(0o027)
    main(sys.argv[1:])
