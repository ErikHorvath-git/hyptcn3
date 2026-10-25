"""Timing and host evidence of a capture with collector 1.1 (writer thread), from its saved files only.

usage: timing_record.py SESSION_DIR AUDIT_JSON AUDIT_TIME OUT_JSON [BALLAST_LOG]
AUDIT_TIME is the saved "rc=... seconds=..." line of the timed `collection.py audit` run. BALLAST_LOG (diagnostic only)
holds the UTC start and end of an induced SSD write load ("start <iso>" / "end <iso>" lines).
Collector 1.1 writes files on its vmic-writer thread after the cycle: the INFO 'citanie' value is capture_ms
(read + compare + features + copy into the queue), not a pure read time; the sidecars add backend_read_ms
(read_pa only), queue_wait_ms, rusage, write_ms/sha_ms (writer thread) and data_closed_ms (cycle start to complete
data, before the sidecar and both renames, so a lower bound of the publication time). The ballast block also holds
data_closed_ms of the snapshots that started after the load ended (after_*).
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path("/home/eh/projects/hyptcn3")
session, audit_path = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
audit_time, out = Path(sys.argv[3]).resolve(), Path(sys.argv[4])
ballast_log = Path(sys.argv[5]).resolve() if len(sys.argv) > 5 else None
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) (MiB|GiB|KiB|B)/[\d.]+ GiB\s+stranky (\d+)/\d+.*"
                  r"citanie ([\d.]+) ms\s+spolu ([\d.]+) ms$")
UNIT = {"B": 1 / 2**20, "KiB": 1 / 1024, "MiB": 1, "GiB": 1024}
COMMIT_NOTE = ("HEAD when this record was generated. The record script "
               "data/results/collection_writer_diagnostic_20261025/timing_record.py is not part of this commit; it is "
               "committed together with this file. The measured collector is the one of values.session_commit.")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def rank(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))] if values else None


log = (session / "raw/collect.log").read_text()
cycles = [{"seq": int(m[2]), "kind": m[3], "mib": round(float(m[4]) * UNIT[m[5]], 3), "pages": int(m[6]),
           "capture_ms": float(m[7]), "total_ms": float(m[8]), "end_unix": unix(m[1])}
          for m in map(LINE.match, log.splitlines()) if m]
if len(cycles) != log.count(" INFO  #"):
    raise SystemExit("unparsed collector cycle lines")
end_line = re.search(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
writer_line = re.search(r"INFO  zapisovac: (\d+) zverejnenych.*", log)
ops_line = re.search(r"INFO  zapisovac: najdlhsie operacie: (.*)", log)
lock_line = re.search(r"INFO  pamat procesu uzamknuta za ([\d.]+) s: VmRSS (\d+) MiB", log)
sides = sorted((json.loads(p.read_text()) for p in (session / "raw").glob("*.json")
                if json.loads(p.read_text()).get("schema") == "vmicollect/1"), key=lambda d: d["seq"])
records = [json.loads(l) for l in (session / "host_monitor.jsonl").read_text().splitlines()]
samples = [r for r in records if r.get("type") == "sample"]
gaps = [b["t_mono"] - a["t_mono"] for a, b in zip(samples, samples[1:])]
meta = json.loads((session / "session.json").read_text())
end = json.loads((session / "end.json").read_text())
audit = json.loads(audit_path.read_text())
capture_t0 = min(d["timestamp_unix"] for d in sides)
capture_t1 = max(c["end_unix"] for c in cycles)
during = [s for s in samples if capture_t0 <= unix(s["t_utc"]) <= capture_t1]


def qemu_swap(rows):
    vals = [p.get("swap_kb") for r in rows for p in r["procs"].get("qemu", []) if p.get("swap_kb") is not None]
    return {"min_kb": min(vals, default=None), "max_kb": max(vals, default=None)}


def sda(r):
    return r.get("disks_rate", {}).get("sda", {})


def cycles_in(start, stop):
    return [c for c in cycles if start <= c["end_unix"] - c["total_ms"] / 1000 and c["end_unix"] <= stop]


ballast = None
if ballast_log:
    text = ballast_log.read_text()
    b0 = unix(re.search(r"^start (\S+)", text, re.M)[1])
    b1 = unix(re.search(r"^end (\S+)", text, re.M)[1])
    rows = [s for s in samples if b0 <= unix(s["t_utc"]) <= b1]
    inside = cycles_in(b0, b1)
    pub = [d["output"]["data_closed_ms"] for d in sides if b0 <= d["timestamp_unix"] <= b1]
    after = [d["output"]["data_closed_ms"] for d in sides if d["timestamp_unix"] > b1]
    saturated = [s for s in rows if sda(s).get("util_pct", 0) >= 99]
    ballast = {
        "start_utc": datetime.fromtimestamp(b0, timezone.utc).isoformat(),
        "end_utc": datetime.fromtimestamp(b1, timezone.utc).isoformat(), "duration_s": round(b1 - b0, 1),
        "monitor_samples": len(rows), "samples_sda_util_ge_99": len(saturated),
        "sda_write_mb_s_min_when_saturated": min((sda(s).get("write_MBps", 0) for s in saturated), default=None),
        "dirty_mib_max": max((round(s["mem_kb"]["Dirty"] / 1024) for s in rows), default=None),
        "iowait_max_pct": max((s["cpu"].get("iowait_pct") or 0 for s in rows), default=None),
        "cycles": len(inside), "cycle_total_ms_max": max((c["total_ms"] for c in inside), default=None),
        "cycle_total_ms_p50": rank([c["total_ms"] for c in inside], .5),
        "data_closed_ms_max": max(pub, default=None), "data_closed_ms_p50": rank(pub, .5),
        "after_snapshots": len(after), "after_data_closed_ms_p50": rank(after, .5),
        "after_data_closed_ms_max": max(after, default=None),
        "queue_bytes_max": max((d["output"].get("queue_bytes", 0) for d in sides
                                if b0 <= d["timestamp_unix"] <= b1), default=None),
        "qemu_swap": qemu_swap(rows),
    }

fulls = [c for c in cycles if c["kind"] == "PLNA"]
deltas = sorted(c["total_ms"] for c in cycles if c["kind"] == "delta")
durations = sorted(r["duration_ms"] for r in map(json.loads, (session / "traffic_requests.jsonl").open())
                   if r.get("type") == "request" and r["phase"] == "measure")
traffic = json.loads((session / "traffic.json").read_text())
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(), "guest": meta["guest_before"],
    "command": " ".join(sys.argv), "n": len(cycles),
    "values": {
        "session": session.name, "role": meta["role"], "group": meta["group"], "scenario": meta.get("scenario"),
        "seed": meta.get("seed"), "session_commit": meta["commit"],
        "collector_settings": meta["collector_settings"],
        "audit": audit_path.name, "audit_sha256": sha(audit_path), "audit_accepted": audit["values"]["accepted"],
        "audit_reasons": audit["values"]["reasons"], "audit_publication": audit["values"].get("publication"),
        "host_memory_at_start": meta["host_context"]["memory"], "prefault": end.get("prefault"),
        "host_memory_after": end.get("host_memory_after"),
        "collector_mlock": {"seconds": float(lock_line[1]), "vmrss_mib": int(lock_line[2])} if lock_line else None,
        "full_snapshots": {f"seq_{c['seq']}": {"mib": c["mib"], "pages": c["pages"], "capture_ms": c["capture_ms"],
                                               "total_ms": c["total_ms"]} for c in fulls},
        "full_backend_read_ms": {f"seq_{d['seq']}": d["capture"].get("backend_read_ms")
                                 for d in sides if d["output"]["full"]},
        "delta_total_ms": {"n": len(deltas), "p50": rank(deltas, .5), "p99": rank(deltas, .99), "max": deltas[-1]},
        "cycle_total_ms_max": max(c["total_ms"] for c in cycles),
        "queue_wait_ms_max": max(d["capture"].get("queue_wait_ms", 0) for d in sides),
        "skipped_before_max": max(d["sched"]["skipped_before"] for d in sides),
        "rusage_max": {k: max(d["capture"]["rusage"][k] for d in sides)
                       for k in ("majflt", "minflt", "nvcsw", "nivcsw", "cpu_ms")} if "rusage" in sides[0]["capture"] else None,
        "data_closed_ms": {"p50": rank([d["output"]["data_closed_ms"] for d in sides], .5),
                       "p95": rank([d["output"]["data_closed_ms"] for d in sides], .95),
                       "max": max(d["output"]["data_closed_ms"] for d in sides),
                       "max_seq": max(sides, key=lambda d: d["output"]["data_closed_ms"])["seq"]},
        "writer": {"summary": writer_line[0].split("INFO  ", 1)[1] if writer_line else None,
                   "longest_operations": ops_line[1] if ops_line else None,
                   "sha_ms_max": max(d["output"].get("sha_ms", 0) for d in sides),
                   "write_ms_max": max(d["capture"].get("write_ms", 0) for d in sides),
                   "queue_jobs_max": max(d["output"].get("queue_jobs", 0) for d in sides),
                   "queue_bytes_max": max(d["output"].get("queue_bytes", 0) for d in sides),
                   "pool_bytes": sides[0]["output"].get("queue_pool_bytes")},
        "collector_end": {"snapshots": int(end_line[1]), "errors": int(end_line[2]), "missed_slots": int(end_line[3])},
        "log_error_lines": sum(" ERROR " in line for line in log.splitlines()),
        "long_cycles": [{k: c[k] for k in ("seq", "kind", "mib", "capture_ms", "total_ms")}
                        for c in cycles if c["total_ms"] > 1500],
        "during_capture": {"qemu_swap": qemu_swap(during),
                           "pswpout_delta": (during[-1]["vmstat"]["pswpout"] - during[0]["vmstat"]["pswpout"])
                           if during and "pswpout" in during[0].get("vmstat", {}) else None,
                           "mem_available_mib_min": min(round(s["mem_kb"]["MemAvailable"] / 1024) for s in during),
                           "mlocked_mib_max": max(round((s["mem_kb"].get("Mlocked") or 0) / 1024) for s in during),
                           "sda_util_ge_99_samples": sum(sda(s).get("util_pct", 0) >= 99 for s in during)},
        "ballast": ballast,
        "monitor_max_gap_s": round(max(gaps), 3), "monitor_samples": len(samples),
        "monitor_missed_ticks": records[-1].get("missed_ticks") if records[-1].get("type") == "end" else None,
        "measure_latency": {"n": len(durations), "max_ms": durations[-1],
                            "over_1s": sum(d > 1000 for d in durations), "over_2s": sum(d > 2000 for d in durations),
                            "over_4s": sum(d > 4000 for d in durations)},
        "clock_offset_s": end["steps"]["clock"]["offset_s"],
        "traffic": {k: traffic.get(k) for k in ("requests", "ok", "errors", "ok_per_s", "log_backpressure_s")},
        "audit_timing": {"wall_s": float(re.search(r"seconds=([\d.]+)", audit_time.read_text())[1]),
                         "rc": int(re.search(r"rc=(\d+)", audit_time.read_text())[1]),
                         "extraction_s_sum": round(sum(audit["values"]["feature_extraction_s"]), 1),
                         "extraction_s_max": round(max(audit["values"]["feature_extraction_s"]), 2)},
        "inputs_sha256": {name: sha(session / name) for name in
                          ("session.json", "end.json", "raw/collect.log", "host_monitor.jsonl", "traffic.json",
                           "traffic_requests.jsonl")}
                         | {"audit_time": sha(audit_time)} | ({"ballast_log": sha(ballast_log)} if ballast_log else {}),
        "note": ("Evidence summary of a capture with the writer-thread collector; the audit report is the verdict. "
                 "Not a corpus session."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k not in ("inputs_sha256", "long_cycles")},
                 indent=1, ensure_ascii=False))
