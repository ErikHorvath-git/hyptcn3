"""Closed campaign benign-v3-20261022: sessions, stage times and archive checks from saved files.

usage: record.py CAMPAIGN_DIR VERIFY_LOG OUT_JSON
VERIFY_LOG is the saved output of `campaign.py verify-archives` with its wall time.
Request latencies are read from each session's traffic_requests.jsonl (measure phase).
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
campaign, verify_log, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) MiB/[\d.]+ GiB.*citanie ([\d.]+) ms\s+spolu ([\d.]+) ms")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def measure_latency(path):
    durations = []
    with open(path) as requests:
        for line in requests:
            rec = json.loads(line)
            if rec.get("type") == "request" and rec["phase"] == "measure":
                durations.append(rec["duration_ms"])
    durations.sort()
    return {"n": len(durations), "max_ms": durations[-1],
            "p99_ms": durations[min(len(durations) - 1, int(0.99 * len(durations)))],
            "over_1s": sum(d > 1000 for d in durations), "over_2s": sum(d > 2000 for d in durations)}


manifest = json.loads((campaign / "campaign.json").read_text())
events = sorted((json.loads(p.read_text()) for p in (campaign / "events").glob("*.json")),
                key=lambda e: e["updated_at"])
stages = {}
for a, b in zip(events, events[1:]):
    if a.get("session") and a["status"] == "running":
        stages.setdefault(a["session"], {})[a["stage"]] = round(unix(b["updated_at"]) - unix(a["updated_at"]), 1)
sessions = []
for row in manifest["sessions"]:
    sid = row["session_id"]
    directory = ROOT / "data/collections" / sid
    attempt = campaign / "attempts" / (sid + ".audit.json")
    if not attempt.exists():
        continue
    report = json.loads(Path(json.loads(attempt.read_text())["path"]).read_text())["values"]
    log = (directory / "raw/collect.log").read_text()
    cycles = [m for m in map(LINE.match, log.splitlines()) if m]
    deltas = sorted(float(m[6]) for m in cycles if m[3] == "delta")
    end = re.search(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
    archive = Path(manifest["archive_dir"]) / "collections" / sid / "archive-manifest.json"
    stored = json.loads(archive.read_text())
    traffic = json.loads((directory / "traffic.json").read_text())
    monitor = report["logs"]["sections"]["monitor"]
    sessions.append({
        "session": sid, "group": row.get("group"), "role": row.get("role"), "scenario": row.get("scenario"),
        "accepted": report["accepted"], "reasons": report["reasons"], "snapshots": report["snapshots"],
        "windows": report["windows"], "score_coverage": report["score_coverage"],
        "logs_accepted": report["logs"]["accepted"],
        "integrity_findings": report["quality"]["integrity_findings"],
        "invalid_input_seq": report["quality"]["invalid_input_seq"],
        "integrity_unconfirmed_seq": report["quality"]["integrity_unconfirmed_seq"],
        "collector_end": {"snapshots": int(end[1]), "errors": int(end[2]), "missed_slots": int(end[3])},
        "full_snapshots_ms": [float(m[6]) for m in cycles if m[3] == "PLNA"],
        "full_snapshots_mib": [float(m[4]) for m in cycles if m[3] == "PLNA"],
        "delta_ms": {"p50": deltas[len(deltas) // 2], "max": deltas[-1]},
        # Cycles over 1.5 s with their read part: a long total with a normal read is a slow write.
        "long_cycles": [{"seq": int(m[2]), "kind": m[3], "mib": float(m[4]), "read_ms": float(m[5]),
                         "total_ms": float(m[6])} for m in cycles if float(m[6]) > 1500],
        "monitor_max_gap_s": monitor["max_gap_s"], "monitor_missed_ticks": monitor["missed_ticks"],
        "requests": traffic["requests"], "request_errors": traffic["errors"],
        "measure_latency": measure_latency(directory / "traffic_requests.jsonl"),
        "raw_bytes": report["raw_bytes"], "archive_stored_bytes": stored.get("stored_bytes"),
        "stage_s": stages.get(sid, {}),
        "inputs_sha256": {"audit": sha(json.loads(attempt.read_text())["path"]),
                          "collect.log": sha(directory / "raw/collect.log"),
                          "traffic_requests.jsonl": sha(directory / "traffic_requests.jsonl"),
                          "archive-manifest.json": sha(archive)},
    })
closed = campaign / "closed.json"
verify = verify_log.read_text()
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": manifest["guest_environment"], "command": " ".join(sys.argv), "n": len(sessions),
    "values": {
        "campaign": manifest["id"], "campaign_commit": manifest["commit"],
        "planned_sessions": len(manifest["sessions"]),
        "final_status": {k: json.loads((campaign / "status.json").read_text()).get(k)
                         for k in ("status", "stage", "message", "accepted_archived", "session")},
        "closed": json.loads(closed.read_text()) if closed.exists() else None,
        "sessions": sessions,
        "verify_archives": {"verified": re.findall(r"^verified (\S+)$", verify, re.M),
                            "wall_s": float(re.search(r"seconds=([\d.]+)", verify)[1]),
                            "rc": int(re.search(r"rc=(\d+)", verify)[1])},
        "inputs_sha256": {"campaign.json": sha(campaign / "campaign.json"), "verify_log": sha(verify_log)},
        "note": "Closed after the session 3 audit rejection; see collection_process_walk_race_20261022.json.",
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(doc["values"], indent=1, ensure_ascii=False)[:6000])
