"""Timing and host evidence of an accepted-candidate pilot, from its saved files only.

usage: pilot_timing_record.py SESSION_DIR AUDIT_JSON OUT_JSON
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
session, audit_path, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3])
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) MiB/[\d.]+ GiB.*spolu ([\d.]+) ms")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


log = (session / "raw/collect.log").read_text()
cycles = [{"seq": int(m[2]), "kind": m[3], "mib": float(m[4]), "total_ms": float(m[5])}
          for m in map(LINE.match, log.splitlines()) if m]
fulls = [c for c in cycles if c["kind"] == "PLNA"]
deltas = sorted(c["total_ms"] for c in cycles if c["kind"] == "delta")
end_line = re.search(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
records = [json.loads(l) for l in (session / "host_monitor.jsonl").read_text().splitlines()]
samples = [r for r in records if r.get("type") == "sample"]
gaps = [b["t_mono"] - a["t_mono"] for a, b in zip(samples, samples[1:])]
traffic = json.loads((session / "traffic.json").read_text())
meta = json.loads((session / "session.json").read_text())
end = json.loads((session / "end.json").read_text())
audit = json.loads(audit_path.read_text())
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(), "guest": meta["guest_before"],
    "command": " ".join(sys.argv), "n": len(cycles),
    "values": {
        "session": session.name, "group": meta["group"], "session_commit": meta["commit"],
        "audit": audit_path.name, "audit_sha256": sha(audit_path), "audit_accepted": audit["values"]["accepted"],
        "host_memory_at_start": meta["host_context"]["memory"], "prefault": end.get("prefault"),
        "host_memory_after": end.get("host_memory_after"),
        "full_snapshots": {f"seq_{c['seq']}": {"mib": c["mib"], "cycle_ms": c["total_ms"]} for c in fulls},
        "delta_cycle_ms": {"n": len(deltas), "p50": deltas[len(deltas) // 2], "max": deltas[-1]},
        "collector_end": {"snapshots": int(end_line[1]), "errors": int(end_line[2]), "missed_slots": int(end_line[3])},
        "monitor_max_gap_s": round(max(gaps), 3), "monitor_samples": len(samples),
        "traffic": {k: traffic.get(k) for k in ("requests", "ok", "errors", "ok_per_s", "log_backpressure_s")},
        "inputs_sha256": {name: sha(session / name) for name in
                          ("session.json", "end.json", "raw/collect.log", "host_monitor.jsonl", "traffic.json")},
        "note": "Pilot evidence summary; the audit report is the verdict. Not a corpus session.",
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(doc["values"], indent=1, ensure_ascii=False))
