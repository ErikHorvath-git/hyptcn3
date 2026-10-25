"""SSD writeback stalls behind the long collector cycles of campaign benign-v4-20261022, from saved files only
(values.host_at_record_time is read live from the host).

usage: record.py CAMPAIGN_DIR OUT_JSON
For every delta cycle of 2 s or more (raw/collect.log; full 'PLNA' cycles are skipped) the host monitor samples
(1 s) inside the cycle are summarised: SSD (sda) utilisation and write rate, Dirty/Writeback memory, iowait and the
collector's CPU. Utilisation, write rate, iowait and CPU are averages over the interval since the previous sample,
so they are taken only from samples whose whole interval lies inside the cycle. The two samples whose interval
straddles the cycle start or end are listed separately as 'boundary' and 'end_boundary' (in_cycle_s = the part of
their interval inside the cycle). Dirty is the first sample inside the cycle and Writeback the maximum over the
samples inside it (both instantaneous). The logged 'citanie' time of
this collector version includes the delta writer's write() calls of every changed page, so a long 'citanie' does
not by itself say whether the memory read or the file writes waited. Full snapshot sizes are the exact file sizes
from the session's archive-manifest.json.
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
campaign, out = Path(sys.argv[1]), Path(sys.argv[2])
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) (MiB|GiB)/[\d.]+ GiB\s+stranky (\d+)/(\d+).*"
                  r"citanie ([\d.]+) ms\s+spolu ([\d.]+) ms")
SNAPSHOT = re.compile(r"^raw/[^/]+_(\d{6})_[^/]+\.vmicd$")
LONG_MS = 2000
COMMIT_NOTE = ("HEAD when this record was generated. The record script "
               "data/results/collection_writeback_stall_20261024/record.py is not part of this commit; it is "
               "committed together with this file. The analysed cycles come from campaign benign-v4-20261022, "
               "captured with the collector of commit cbea764. values.host_at_record_time is read live from the host.")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def cycles_of(log, sizes):
    rows, last_full = [], None
    for line in log.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        if m[3] == "PLNA":
            last_full = (int(m[2]), unix(m[1]), round(sizes[int(m[2])] / 2**20, 2), int(m[6]))
        rows.append({"seq": int(m[2]), "kind": m[3], "read_ms": float(m[8]), "total_ms": float(m[9]),
                     "end_unix": unix(m[1]), "end_utc": m[1], "full": last_full})
    if len(rows) != sum(" INFO  #" in line for line in log.splitlines()):
        raise SystemExit("unparsed collector cycle line")
    return rows


def samples_of(path):
    rows = []
    with open(path) as monitor:
        for line in monitor:
            rec = json.loads(line)
            if rec.get("type") == "sample":
                rows.append(rec)
    return rows


def window(samples, start, end):
    return [s for s in samples if start <= unix(s["t_utc"]) <= end]


def vmi_cpu(sample):
    procs = sample["procs"].get("vmicollect") or []
    return procs[0].get("cpu_pct") if procs else None


def summary(samples, start, end):
    rows = window(samples, start, end)
    # Rate fields average the interval since the previous sample: keep only samples whose interval starts inside.
    pairs = [(a, b) for a, b in zip(samples, samples[1:]) if start <= unix(b["t_utc"]) <= end]
    inner = [b for a, b in pairs if unix(a["t_utc"]) >= start]
    edge = [(a, b) for a, b in pairs if unix(a["t_utc"]) < start]
    tail = [(a, b) for a, b in zip(samples, samples[1:]) if unix(a["t_utc"]) <= end < unix(b["t_utc"])]
    sda = [r.get("disks_rate", {}).get("sda", {}) for r in inner]
    cpu = [c for c in map(vmi_cpu, inner) if c is not None]

    def straddling(a, b, inside):
        rate = b.get("disks_rate", {}).get("sda", {})
        return {"t_utc": b["t_utc"], "interval_s": round(unix(b["t_utc"]) - unix(a["t_utc"]), 3),
                "in_cycle_s": round(inside, 3), "sda_util_pct": rate.get("util_pct"),
                "sda_write_mb_s": rate.get("write_MBps"), "collector_cpu_pct": vmi_cpu(b)}

    boundary = straddling(*edge[0], unix(edge[0][1]["t_utc"]) - start) if edge else None
    end_boundary = (straddling(*tail[0], end - max(start, unix(tail[0][0]["t_utc"]))) if tail else None)
    return {"samples": len(rows), "samples_whole_interval": len(inner),
            "sda_util_max_pct": max((d.get("util_pct", 0) for d in sda), default=None),
            "sda_write_mb_s_min": min((d.get("write_MBps", 0) for d in sda), default=None),
            "sda_write_mb_s_max": max((d.get("write_MBps", 0) for d in sda), default=None),
            "iowait_max_pct": max((r["cpu"].get("iowait_pct") or 0 for r in inner), default=None),
            "dirty_mib_first": round(rows[0]["mem_kb"]["Dirty"] / 1024) if rows else None,
            "writeback_mib_max": max((round(r["mem_kb"]["Writeback"] / 1024) for r in rows), default=None),
            "collector_cpu_min_pct": min(cpu, default=None), "boundary": boundary, "end_boundary": end_boundary}


def series(samples, start, end):
    return [{"t_utc": s["t_utc"], "dirty_mib": round(s["mem_kb"]["Dirty"] / 1024),
             "writeback_mib": round(s["mem_kb"]["Writeback"] / 1024),
             "sda_write_mb_s": round(s.get("disks_rate", {}).get("sda", {}).get("write_MBps", 0), 1),
             "sda_util_pct": round(s.get("disks_rate", {}).get("sda", {}).get("util_pct", 0), 1),
             "iowait_pct": s["cpu"].get("iowait_pct"), "collector_cpu_pct": vmi_cpu(s)}
            for s in window(samples, start, end)]


manifest = json.loads((campaign / "campaign.json").read_text())
long_cycles, inputs, events = [], {}, {}
n_cycles = 0
for row in manifest["sessions"]:
    sid = row["session_id"]
    directory = ROOT / "data/collections" / sid
    if not (campaign / "attempts" / (sid + ".audit.json")).exists():
        continue
    log = (directory / "raw/collect.log").read_text()
    archive = Path(manifest["archive_dir"]) / "collections" / sid / "archive-manifest.json"
    sizes = {int(m[1]): f["size"] for name, f in json.loads(archive.read_text())["files"].items()
             if (m := SNAPSHOT.match(name))}
    cycles = cycles_of(log, sizes)
    n_cycles += len(cycles)
    samples = samples_of(directory / "host_monitor.jsonl")
    inputs[sid] = {"collect.log": sha(directory / "raw/collect.log"),
                   "host_monitor.jsonl": sha(directory / "host_monitor.jsonl"),
                   "archive-manifest.json": sha(archive)}
    for c in cycles:
        if c["kind"] != "delta" or c["total_ms"] < LONG_MS:
            continue
        start = c["end_unix"] - c["total_ms"] / 1000
        entry = {"session": sid, "seq": c["seq"], "read_ms": c["read_ms"], "total_ms": c["total_ms"],
                 "end_utc": c["end_utc"], "since_full": c["seq"] - c["full"][0],
                 "seconds_after_full": round(start - c["full"][1], 1), "full_mib": c["full"][2],
                 "full_pages": c["full"][3], **summary(samples, start, c["end_unix"])}
        long_cycles.append(entry)
        if c["total_ms"] >= 4500:
            events[f"{sid}#{c['seq']}"] = {**entry, "series": series(samples, start - 25, c["end_unix"] + 5)}
skips = re.findall(r"zahadzujem (\d+) slotov", "\n".join(
    (ROOT / "data/collections" / r["session_id"] / "raw/collect.log").read_text()
    for r in manifest["sessions"] if (campaign / "attempts" / (r["session_id"] + ".audit.json")).exists()))
saturated = [c for c in long_cycles if (c["sda_util_max_pct"] or 0) >= 99]
straddling_only = [c for c in long_cycles if c not in saturated
                   and any(((c[k] or {}).get("sda_util_pct") or 0) >= 99 for k in ("boundary", "end_boundary"))]
ext4 = Path("/proc/fs/ext4/sda2/options")
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": manifest["guest_environment"], "command": " ".join(sys.argv), "n": n_cycles,
    "values": {
        "campaign": manifest["id"], "long_cycle_threshold_ms": LONG_MS,
        "long_delta_cycles": len(long_cycles),
        "long_delta_cycles_with_sda_util_ge_99": len(saturated),
        "long_delta_cycles_sda_util_ge_99_only_in_straddling_samples": [f"{c['session']}#{c['seq']}"
                                                                         for c in straddling_only],
        "long_delta_cycles_sda_util_never_ge_99": sum(c not in saturated and c not in straddling_only
                                                      for c in long_cycles),
        "long_delta_cycles_without_whole_interval_sample": sum(c["samples_whole_interval"] == 0 for c in long_cycles),
        "long_delta_cycles_over_4000_ms": sum(c["total_ms"] > 4000 for c in long_cycles),
        "missed_slots": sum(map(int, skips)),
        "cycles": long_cycles, "events_over_4500_ms": events,
        "host_at_record_time": {
            "vm": {k: int(Path(f"/proc/sys/vm/{k}").read_text()) for k in
                   ("dirty_background_ratio", "dirty_ratio", "dirty_expire_centisecs",
                    "dirty_writeback_centisecs", "swappiness")},
            "sda2_ext4_options": ext4.read_text().split() if ext4.exists() else None,
            "sda_model": Path("/sys/block/sda/device/model").read_text().strip(),
            "sda_scheduler": Path("/sys/block/sda/queue/scheduler").read_text().strip()},
        "inputs_sha256": {"campaign.json": sha(campaign / "campaign.json"), "sessions": inputs},
        "note": ("Every delta cycle of 2 s or more is listed with the host monitor samples taken inside it (summary "
                 "rate fields only from samples whose whole 1 s interval lies inside the cycle); the two samples "
                 "whose interval straddles the cycle start or end are listed separately as boundary and "
                 "end_boundary, with in_cycle_s the part of their interval inside the cycle. The "
                 "snapshot data of a full snapshot stays dirty in the page cache and is written back in bursts; "
                 "during such a burst the DRAM-less SATA SSD runs at 100 % utilisation with the write rate "
                 "falling to a few MB/s, and the collector uses no CPU for seconds. Within the measured cycle "
                 "(total_ms) the collector of commit cbea764 creates, writes and renames snapshot files and "
                 "hashes delta files on the sampling thread, so these waits extend the cycle; the SHA-256 of a "
                 "full snapshot is computed by a separate thread after the cycle (output.hash_async), and the "
                 "delta sidecar and the log line follow total_ms on the sampling thread and count only toward "
                 "the scheduler slot. Which call waited is not recorded."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k not in ("cycles", "events_over_4500_ms", "inputs_sha256")},
                 indent=1))
for c in long_cycles:
    print(c["session"][19:], c["seq"], c["total_ms"], c["since_full"], c["seconds_after_full"], c["full_pages"],
          c["sda_util_max_pct"], c["sda_write_mb_s_min"], c["dirty_mib_first"], c["collector_cpu_min_pct"])
