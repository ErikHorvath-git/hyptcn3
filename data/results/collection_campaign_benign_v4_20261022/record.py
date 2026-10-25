"""Closed campaign benign-v4-20261022: sessions, groups, operator stops and archive checks from saved files.

usage: record.py CAMPAIGN_DIR VERIFY_LOG OUT_JSON
VERIFY_LOG is the saved output of `campaign.py verify-archives` with its wall time.
Request latencies are read from each session's traffic_requests.jsonl (measure phase). Collector cycles
come from raw/collect.log; every per-cycle ' INFO  #' line must parse. Until the fix that follows this
campaign, the logged 'citanie' (read) time also contained the delta writer's write() calls of every changed
page, so read_ms is not a pure memory-read time. QEMU swap during a session comes from host_monitor.jsonl (1 s samples).
Snapshot sizes (bytes, mib) are the exact file sizes from the session's archive-manifest.json; logged_size is the
collector's own rounded figure of the space on disk (two decimals, i.e. 10.24 MiB steps above 1 GiB).
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
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) (MiB|GiB)/[\d.]+ GiB\s+stranky (\d+)/(\d+).*"
                  r"citanie ([\d.]+) ms\s+spolu ([\d.]+) ms")
SKIP = re.compile(r"^(\S+) WARN  planovac: cyklus (\d+) trval ([\d.]+) s \(perioda ([\d.]+) s\) - zahadzujem (\d+) slotov")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


SNAPSHOT = re.compile(r"^raw/[^/]+_(\d{6})_[^/]+\.vmicd$")
COMMIT_NOTE = ("HEAD when this record was generated. The record script "
               "data/results/collection_campaign_benign_v4_20261022/record.py is not part of this commit; it is "
               "committed together with this file. The campaign was captured with the code of commit cbea764 "
               "(values.campaign_commit), not with the collector of this commit.")


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


def cycles_of(log, sizes):
    rows, last_full = [], None
    for line in log.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        seq = int(m[2])
        if m[3] == "PLNA":
            last_full = seq
        size = sizes.get(seq)
        rows.append({"seq": seq, "kind": m[3], "bytes": size, "mib": None if size is None else round(size / 2**20, 2),
                     "logged_size": f"{m[4]} {m[5]}", "pages_changed": int(m[6]),
                     "pages_total": int(m[7]), "read_ms": float(m[8]), "total_ms": float(m[9]),
                     "since_full": None if last_full is None else seq - last_full, "end_utc": m[1]})
    if len(rows) != sum(" INFO  #" in line for line in log.splitlines()):
        raise SystemExit("unparsed collector cycle line")
    return rows


def qemu_swap(path):
    """Swapped-out QEMU memory and host swap-outs over the session, from the 1 s host monitor samples."""
    samples = [r for r in map(json.loads, path.open()) if r.get("type") == "sample"]
    swap = [max((q.get("swap_kb") or 0 for q in r["procs"].get("qemu", [])), default=0) for r in samples]
    return {"kb_max": max(swap), "samples_over_0": sum(v > 0 for v in swap),
            "pswpout_delta": samples[-1]["vmstat"]["pswpout"] - samples[0]["vmstat"]["pswpout"]}


manifest = json.loads((campaign / "campaign.json").read_text())
# Stop requests moved into events/ have no updated_at; only status events time the stages.
records = [(p.name, json.loads(p.read_text())) for p in sorted((campaign / "events").glob("*.json"))]
events = sorted((e for _, e in records if e.get("schema") == "hyptcn3/campaign-event/1"),
                key=lambda e: e["updated_at"])
stops = [{"event_file": name, "date": e["date"], "uid": e["uid"]}
         for name, e in records if e.get("schema") == "hyptcn3/campaign-stop-request/1"]
stages = {}
for a, b in zip(events, events[1:]):
    if a.get("session") and a["status"] == "running":
        stage = stages.setdefault(a["session"], {})
        stage[a["stage"]] = round(stage.get(a["stage"], 0) + unix(b["updated_at"]) - unix(a["updated_at"]), 1)
stopped = [{"updated_at": e["updated_at"], "stage": e["stage"], "position": e.get("position"),
            "session": e.get("session"), "message": e.get("message")}
           for e in events if e["status"] == "stopped"]
groups = {}
for path in sorted((campaign / "groups").glob("*.json")):
    if path.name.endswith(".reboot-intent.json"):
        continue
    g = json.loads(path.read_text())
    groups[g["group"]] = {"qemu": g["qemu"], "previous_boot": g["previous_boot"],
                          "boot_id": g["identity"]["boot_id"], "date": g["date"]}
sessions = []
for row in manifest["sessions"]:
    sid = row["session_id"]
    directory = ROOT / "data/collections" / sid
    attempt = campaign / "attempts" / (sid + ".audit.json")
    if not attempt.exists():
        continue
    report = json.loads(Path(json.loads(attempt.read_text())["path"]).read_text())["values"]
    meta = json.loads((directory / "session.json").read_text())
    log = (directory / "raw/collect.log").read_text()
    archive = Path(manifest["archive_dir"]) / "collections" / sid / "archive-manifest.json"
    stored = json.loads(archive.read_text())
    sizes = {int(m[1]): f["size"] for name, f in stored["files"].items() if (m := SNAPSHOT.match(name))}
    cycles = cycles_of(log, sizes)
    if any(c["bytes"] is None for c in cycles if c["kind"] == "PLNA" or c["total_ms"] > 1500):
        raise SystemExit(f"{sid}: snapshot file missing from the archive manifest")
    deltas = sorted(c["total_ms"] for c in cycles if c["kind"] == "delta")
    end = re.search(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
    traffic = json.loads((directory / "traffic.json").read_text())
    monitor = report["logs"]["sections"]["monitor"]
    sessions.append({
        "session": sid, "group": row.get("group"), "role": row.get("role"), "scenario": row.get("scenario"),
        "group_attempt": meta["group_attempt"], "guest_boot": meta["guest_before"]["boot_id"],
        "qemu": meta["host_context"]["qemu"],
        "qemu_swap_kb_at_start": meta["host_context"]["memory"].get("qemu_swap_kb"),
        "qemu_swap_during": qemu_swap(directory / "host_monitor.jsonl"),
        "accepted": report["accepted"], "reasons": report["reasons"], "snapshots": report["snapshots"],
        "windows": report["windows"], "score_coverage": report["score_coverage"],
        "logs_accepted": report["logs"]["accepted"],
        "integrity_findings": report["quality"]["integrity_findings"],
        "invalid_input_seq": report["quality"]["invalid_input_seq"],
        "integrity_unconfirmed_seq": report["quality"]["integrity_unconfirmed_seq"],
        "process_walk_prev_seq": report["quality"].get("process_walk_prev_seq"),
        "collector_end": {"snapshots": int(end[1]), "errors": int(end[2]), "missed_slots": int(end[3])},
        "scheduler_skips": [{"seq": int(m[2]), "cycle_s": float(m[3]), "period_s": float(m[4]),
                             "slots": int(m[5]), "utc": m[1]} for m in map(SKIP.match, log.splitlines()) if m],
        "full_snapshots": [{"seq": c["seq"], "pages": c["pages_changed"], "bytes": c["bytes"], "mib": c["mib"],
                            "logged_size": c["logged_size"], "read_ms": c["read_ms"], "total_ms": c["total_ms"]}
                           for c in cycles if c["kind"] == "PLNA"],
        "delta_ms": {"n": len(deltas), "p50": deltas[len(deltas) // 2], "max": deltas[-1]},
        # Over 1.5 s; read_ms includes the page writes of the delta writer (see the docstring).
        "long_cycles": [{k: c[k] for k in ("seq", "kind", "bytes", "mib", "logged_size", "read_ms", "total_ms",
                                           "since_full", "end_utc")}
                        for c in cycles if c["total_ms"] > 1500],
        "monitor_max_gap_s": monitor["max_gap_s"], "monitor_missed_ticks": monitor["missed_ticks"],
        "requests": traffic["requests"], "request_errors": traffic["errors"],
        "measure_latency": measure_latency(directory / "traffic_requests.jsonl"),
        "raw_bytes": report["raw_bytes"], "archive_stored_bytes": stored.get("stored_bytes"),
        "stage_s": stages.get(sid, {}),
        "inputs_sha256": {"audit": sha(json.loads(attempt.read_text())["path"]),
                          "session.json": sha(directory / "session.json"),
                          "collect.log": sha(directory / "raw/collect.log"),
                          "traffic.json": sha(directory / "traffic.json"),
                          "traffic_requests.jsonl": sha(directory / "traffic_requests.jsonl"),
                          "host_monitor.jsonl": sha(directory / "host_monitor.jsonl"),
                          "archive-manifest.json": sha(archive)},
    })
closed = campaign / "closed.json"
verify = verify_log.read_text()
accepted = [s for s in sessions if s["accepted"]]
all_long = [c for s in sessions for c in s["long_cycles"] if c["kind"] == "delta"]
by_group = {}
for s in sessions:
    g = by_group.setdefault(s["group"], {"guest_boots": [], "qemu_pids": [], "sessions": 0,
                                        "first_full_pages": s["full_snapshots"][0]["pages"]})
    g["sessions"] += 1
    if s["guest_boot"] not in g["guest_boots"]:
        g["guest_boots"].append(s["guest_boot"])
    if s["qemu"]["pid"] not in g["qemu_pids"]:
        g["qemu_pids"].append(s["qemu"]["pid"])
    g["last_full_pages"] = s["full_snapshots"][-1]["pages"]
    g["max_full_pages"] = max(g.get("max_full_pages", 0), *(f["pages"] for f in s["full_snapshots"]))
summary = {
    "accepted_sessions": len(accepted),
    "windows_min": min(s["windows"] for s in accepted), "windows_max": max(s["windows"] for s in accepted),
    "integrity_findings": sum(s["integrity_findings"] for s in sessions),
    "accepted_missed_slots": sum(s["collector_end"]["missed_slots"] for s in accepted),
    "accepted_collector_errors": sum(s["collector_end"]["errors"] for s in accepted),
    "full_pages_min": min(f["pages"] for s in sessions for f in s["full_snapshots"]),
    "full_pages_max": max(f["pages"] for s in sessions for f in s["full_snapshots"]),
    "full_ms_min": min(f["total_ms"] for s in sessions for f in s["full_snapshots"]),
    "full_ms_max": max(f["total_ms"] for s in sessions for f in s["full_snapshots"]),
    "delta_ms_max_accepted": max(s["delta_ms"]["max"] for s in accepted),
    "delta_ms_max_accepted_session": max(accepted, key=lambda s: s["delta_ms"]["max"])["session"],
    "delta_ms_max_all": max(s["delta_ms"]["max"] for s in sessions),
    "long_delta_cycles": {f"over_{t}_ms": sum(c["total_ms"] > t for c in all_long) for t in (1500, 2000, 3000, 4000, 5000)},
    "monitor_max_gap_s": max(s["monitor_max_gap_s"] for s in sessions),
    "monitor_missed_ticks": sum(s["monitor_missed_ticks"] for s in sessions),
    "qemu_swap_kb_max": max(s["qemu_swap_during"]["kb_max"] for s in sessions),
    "qemu_swap_sessions": [s["session"] for s in sessions if s["qemu_swap_during"]["kb_max"] > 0],
    # VmSwap of QEMU when the session started, before the prefault step reads swapped guest memory back in.
    "qemu_swap_at_start_count": sum((s["qemu_swap_kb_at_start"] or 0) > 0 for s in sessions),
    "qemu_swap_kb_at_start_max": max(s["qemu_swap_kb_at_start"] or 0 for s in sessions),
    "requests": sum(s["requests"] for s in sessions),
    "request_errors": sum(s["request_errors"] for s in sessions),
    "measure_latency_max_ms": max(s["measure_latency"]["max_ms"] for s in sessions),
    "measure_latency_over_2s": sum(s["measure_latency"]["over_2s"] for s in sessions),
    "process_walk_prev_rows": sum(len(s["process_walk_prev_seq"] or []) for s in sessions),
    "integrity_unconfirmed_rows": sum(len(s["integrity_unconfirmed_seq"] or []) for s in sessions),
    "by_group": by_group,
}
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": manifest["guest_environment"], "command": " ".join(sys.argv), "n": len(sessions),
    "values": {
        "campaign": manifest["id"], "campaign_commit": manifest["commit"],
        "planned_sessions": len(manifest["sessions"]),
        "accepted_sessions": sum(s["accepted"] for s in sessions),
        "rejected_sessions": [s["session"] for s in sessions if not s["accepted"]],
        "final_status": {k: json.loads((campaign / "status.json").read_text()).get(k)
                         for k in ("status", "stage", "message", "accepted_archived", "session")},
        "closed": json.loads(closed.read_text()) if closed.exists() else None,
        "summary": summary,
        "groups": groups,
        "qemu_processes": sorted({(g["qemu"]["pid"], g["qemu"]["start_ticks"]) for g in groups.values()}),
        "operator_stop_requests": stops,
        "stopped_states": stopped,
        "sessions": sessions,
        "verify_archives": {"verified": re.findall(r"^verified (\S+)$", verify, re.M),
                            "n_verified": len(re.findall(r"^verified (\S+)$", verify, re.M)),
                            "wall_s": float(re.search(r"seconds=([\d.]+)", verify)[1]),
                            "rc": int(re.search(r"rc=(\d+)", verify)[1])},
        "inputs_sha256": {"campaign.json": sha(campaign / "campaign.json"), "verify_log": sha(verify_log),
                          "closed.json": sha(closed), "status.json": sha(campaign / "status.json"),
                          "events": {name: sha(campaign / "events" / name) for name, _ in records},
                          "groups": {p.name: sha(p) for p in sorted((campaign / "groups").glob("*.json"))
                                     if not p.name.endswith(".reboot-intent.json")}},
        "note": ("Closed after the session 37 audit rejection (one missed collector slot); see "
                 "collection_writeback_stall_20261024.json. The operator stopped the runner twice between "
                 "sessions (request-stop): after session 33 for an fstrim of the snapshot file system (started "
                 "2026-10-24T18:30:59Z, 61.5 GiB trimmed), and after session 36 for a planned VM power-cycle "
                 "before group test_benign-1 (clean guest shutdown, libvirt state 'shut off (shutdown)' at "
                 "2026-10-24T23:14:19Z, started again at 23:14:19Z) followed by a second fstrim (started "
                 "23:15:08Z, 23 GiB trimmed). Both stops are listed in operator_stop_requests and stopped_states, "
                 "the new QEMU process in groups. A VM power-cycle at the calibration-1/calibration-2 boundary "
                 "(after session 30), planned with the user's approval because full snapshots grew with the age "
                 "of the QEMU process, was missed, so groups train-1 to calibration-2 ran on one QEMU process. "
                 "The stop reasons, the shutdown and fstrim times and the missed power-cycle are operator "
                 "statements from the session log, not machine records."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k != "sessions"}, indent=1, ensure_ascii=False)[:5000])
