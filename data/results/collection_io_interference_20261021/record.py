"""Host memory and I/O interference in the 2026-10-21 pilot, from its saved evidence only.

usage: stall_record.py SESSION_DIR OUT_JSON
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
session, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) MiB/[\d.]+ GiB\s+stranky (\d+)/(\d+).*"
                  r"citanie ([\d.]+) ms\s+spolu ([\d.]+) ms")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


log = (session / "raw/collect.log").read_text()
cycles = []
for line in log.splitlines():
    m = LINE.match(line)
    if m:
        cycles.append({"seq": int(m[2]), "kind": m[3], "mib": float(m[4]), "read_ms": float(m[7]),
                       "total_ms": float(m[8]), "end_unix": unix(m[1])})
records = [json.loads(l) for l in (session / "host_monitor.jsonl").read_text().splitlines()]
samples = [r for r in records if r.get("type") == "sample" and "iowait_pct" in r.get("cpu", {})]
times = [unix(s["t_utc"]) for s in samples]


def around(start, end):
    return [s for s, t in zip(samples, times) if start <= t <= end]


def full(seq):
    c = next(c for c in cycles if c["seq"] == seq and c["kind"] == "PLNA")
    rows = around(c["end_unix"] - c["total_ms"] / 1000 - 1, c["end_unix"] + 1)
    return {"seq": seq, "mib": c["mib"], "read_ms": c["read_ms"], "cycle_ms": c["total_ms"],
            "end_utc": iso(c["end_unix"]),
            "swapped_in_mib": round((rows[-1]["vmstat"]["pswpin"] - rows[0]["vmstat"]["pswpin"]) * 4096 / 2**20, 1),
            "iowait_max_pct": max(r["cpu"]["iowait_pct"] for r in rows)}


def burst_after(seq):
    """First run of >= 3 one-second samples with iowait > 15 % within 5 min after a full snapshot."""
    c = next(c for c in cycles if c["seq"] == seq and c["kind"] == "PLNA")
    rows = around(c["end_unix"], c["end_unix"] + 300)
    run = []
    for r in rows:
        if r["cpu"]["iowait_pct"] > 15:
            run.append(r)
        elif len(run) >= 3:
            break
        else:
            run = []
    if len(run) < 3:
        return None
    before = around(unix(run[0]["t_utc"]) - 3, unix(run[0]["t_utc"]) - 1)
    after = around(unix(run[-1]["t_utc"]) + 1, unix(run[-1]["t_utc"]) + 3)
    return {"start_utc": run[0]["t_utc"], "end_utc": run[-1]["t_utc"],
            "seconds_after_full": round(unix(run[0]["t_utc"]) - c["end_unix"], 1),
            "duration_s": round(unix(run[-1]["t_utc"]) - unix(run[0]["t_utc"]) + 1, 1),
            "iowait_max_pct": max(r["cpu"]["iowait_pct"] for r in run),
            "dirty_mib_before": round(before[0]["mem_kb"]["Dirty"] / 1024) if before else None,
            "dirty_mib_after": round(after[-1]["mem_kb"]["Dirty"] / 1024) if after else None}


requests = [json.loads(l) for l in (session / "traffic_requests.jsonl").read_text().splitlines()]
failed = [r for r in requests if r.get("type") == "request" and r.get("outcome") != "ok"]
gaps = [{"after_utc": a["t_utc"], "seconds": round(b["t_mono"] - a["t_mono"], 3)}
        for a, b in zip(samples, samples[1:]) if b["t_mono"] - a["t_mono"] > 1.5]
qemu = [(r["t_utc"], r["procs"]["qemu"][0]["swap_kb"]) for r in samples if r["procs"].get("qemu")]
first = full(0)
end = json.loads((session / "end.json").read_text())
measure = around(end["measure_start_unix"], end["measure_end_unix"])
written = {disk: round((measure[-1]["disks"][disk]["sectors_written"] - measure[0]["disks"][disk]["sectors_written"])
                       * 512 / 2**30, 3) for disk in ("sda", "sdb")}
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": json.loads((session / "session.json").read_text())["guest_before"],
    "command": " ".join(sys.argv), "n": len(cycles),
    "values": {
        "session": session.name,
        "inputs_sha256": {name: sha(session / name) for name in
                          ("session.json", "end.json", "raw/collect.log", "host_monitor.jsonl",
                           "traffic_requests.jsonl")},
        "host": {"vm_swappiness_after_run": int(Path("/proc/sys/vm/swappiness").read_text()),
                 "swap_devices_after_run": Path("/proc/swaps").read_text().splitlines()[1:],
                 "working_disk": "sda2 ext4 (SanDisk SDSSDA24): snapshots, session logs and the VM disk (qcow2)",
                 "swap_disk": "sdb3 (Seagate ST500LM021, system HDD)"},
        "qemu_swap_kb_first_sample": qemu[0][1],
        "qemu_swap_kb_after_first_full": next(sw for t, sw in qemu if unix(t) > unix(first["end_utc"]) + 1),
        "first_full": first, "second_full": full(360),
        "missed_slots": sum(int(n) for n in re.findall(r"zahadzujem (\d+) slotov", log)),
        "writeback_burst_after_first_full": burst_after(0),
        "writeback_burst_after_second_full": burst_after(360),
        "request_failures": {"count": len(failed), "outcomes": sorted({r["outcome"] for r in failed}),
                             "routes": sorted({r["method"] + " " + r["route"] for r in failed}),
                             "first_start_utc": min((r["t_start_utc"] for r in failed), default=None),
                             "last_start_utc": max((r["t_start_utc"] for r in failed), default=None),
                             "client_timeout_ms_observed": max((r["duration_ms"] for r in failed), default=None)},
        "monitor_sample_gaps": gaps,
        "measure_phase_written_gib": written,
        "raw_snapshot_gib": round(sum(f.stat().st_size for f in (session / "raw").glob("*.vmicd")) / 2**30, 3),
        "note": ("Diagnostic of a pilot that the audit rejects; not a corpus session. A full snapshot reads all "
                 "guest RAM: QEMU memory swapped out on the host was read back from the HDD swap partition and "
                 "the first full snapshot overran the 5 s period. The ~920 MiB of each full snapshot stayed "
                 "dirty in the page cache and was then written back in one burst; the guest disk image is on "
                 "the same ext4 file system, and guest commits waited behind that writeback (request timeouts)."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k not in ("inputs_sha256",)}, indent=1))
