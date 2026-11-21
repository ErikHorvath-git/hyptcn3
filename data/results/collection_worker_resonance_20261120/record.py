#!/usr/bin/env python3
"""Record: restarts of the lab worker during zamok_tabulky against the capture times (campaign normal-v4c-20261117).

Read-only over the campaign's own audits, events.json, feature archives and guest journals on the
collection PC:  .venv/bin/python record.py > collection_worker_resonance_20261120.json
No snapshot is parsed again and nothing is scored.
"""
import datetime
import glob
import gzip
import json
import os
import subprocess
import sys

import numpy as np

ROOT = os.path.expanduser("~/projects/hyptcn3")
CAMPAIGN = "normal-v4c-20261117"
EVENT = "zamok_tabulky"
sys.path.insert(0, ROOT)
from scripts import collection  # noqa: E402


def stamp(text):
    return datetime.datetime.strptime(text[:26], "%Y-%m-%dT%H:%M:%S.%f").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def main():
    base = os.path.join(ROOT, "data/campaigns", CAMPAIGN)
    p = collection.protocol(os.path.join(base, "protocol.json"))
    grace = p["events"]["grace_s"]
    rows = invalid = 0
    closed = {"prev": 0, "tail": 0, "meet": 0}
    inside = {"invalid": 0, "closed": 0, "exposure_rows": 0, "attempts": 0}
    outside_invalid, in_step, periods, offsets = [], {}, [], []
    attempts = sorted(glob.glob(os.path.join(base, "attempts/*.audit.json")))
    for name in attempts:
        sid = os.path.basename(name)[:-len(".audit.json")]
        audit = json.load(open(json.load(open(name))["path"]))
        v = audit["values"]
        q, sd = v["quality"], v["session_dir"]
        data = np.load(os.path.join(sd, os.path.basename(v["features"])) if not os.path.isabs(v["features"])
                       else v["features"], allow_pickle=False)
        times = dict(zip((int(s) for s in data["seq"]), (float(t) for t in data["casy"])))
        rows += len(times)
        marks = [("invalid", s) for s in q["invalid_input_seq"]]
        for rule in closed:
            closed[rule] += len(q["process_walk_%s_seq" % rule])
            marks += [(rule, s) for s in q["process_walk_%s_seq" % rule]]
        invalid += len(q["invalid_input_seq"])
        events = [e for e in json.load(open(os.path.join(sd, "events.json")))["events"] if e["type"] == EVENT]
        starts = []
        if events:
            journal = glob.glob(os.path.join(sd, "guest", "*-journal-journal.txt.gz"))[0]
            with gzip.open(journal, "rt", errors="replace") as stream:
                starts = [stamp(line) for line in stream if "Started hyptcn-lab@worker.service" in line]
        clock = json.load(open(os.path.join(sd, "guest", "clock_before.json")))
        torn = []
        for event in events:
            a, b = event["host_start_unix"], event["host_stopped_unix"]
            inside["attempts"] += 1
            inside["exposure_rows"] += sum(a <= t <= b for t in times.values())
            during = [x for x in starts if a <= x <= b + grace]
            if len(during) > 2:
                periods.append((during[-1] - during[0]) / (len(during) - 1))
            for kind, seq in marks:
                if a <= times[seq] <= b + grace:
                    near = min((x - times[seq] for x in starts), key=abs)
                    torn.append({"seq": seq, "row": kind, "worker_start_after_capture_s": round(near, 2)})
        torn.sort(key=lambda r: r["seq"])
        inside["invalid"] += sum(r["row"] == "invalid" for r in torn)
        inside["closed"] += sum(r["row"] != "invalid" for r in torn)
        hit = {r["seq"] for r in torn}
        outside_invalid += [{"session": sid, "seq": s} for s in q["invalid_input_seq"] if s not in hit]
        if len(torn) >= 3:
            offsets += [r["worker_start_after_capture_s"] for r in torn]
            in_step[sid] = {"accepted": v["accepted"], "score_coverage": round(v["score_coverage"], 4),
                            "reasons": [r for r in v["reasons"] if "coverage" in r or "model inputs" in r],
                            "guest_clock_offset_s": clock["offset_s"], "rows": torn}
    ideal = collection.ideal_windows(p["cycles"], p["window_rows"], p["full_every"])
    lost = p["window_rows"] + 1
    plan = collection.plan(p)["sessions"]
    remaining = [s for s in plan if s["role"] in ("calibration", "test_benign") or s["group"].endswith("dev-2")]
    values = {
        "campaign": CAMPAIGN, "attempts": len(attempts), "rows": rows, "invalid_rows": invalid,
        "rows_closed_by_rule": closed,
        "lock_event": {"type": EVENT, "attempts": inside["attempts"], "exposure_rows": inside["exposure_rows"],
                       "invalid_rows_inside": inside["invalid"], "rows_closed_by_rule_inside": inside["closed"],
                       "attempts_in_step": len(in_step),
                       "attempts_in_step_rejected_by_coverage": sum(
                           any("coverage" in r for r in s["reasons"]) for s in in_step.values()),
                       "window": "host_start_unix .. host_stopped_unix + grace_s of the event"},
        "invalid_rows_outside_lock_event": outside_invalid,
        "worker_restart": {"sessions": len(periods), "period_s_mean": round(sum(periods) / len(periods), 3),
                           "period_s_min": round(min(periods), 3), "period_s_max": round(max(periods), 3),
                           "four_periods_s": round(4 * sum(periods) / len(periods), 2),
                           "capture_interval_s": p["interval_s"],
                           "start_after_capture_s_min": min(offsets), "start_after_capture_s_max": max(offsets)},
        "in_step_sessions": in_step,
        "coverage_gate": {"cycles": p["cycles"], "ideal_windows": ideal, "windows_lost_per_isolated_invalid_row": lost,
                          "min_score_coverage": p["min_score_coverage"], "invalid_rows_max": p["invalid_rows"]["max"],
                          "coverage_by_isolated_invalid_rows": {
                              str(n): round((ideal - n * lost) / p["cycles"], 4) for n in range(4)}},
        "plan": {"sessions": len(plan), "with_lock_event": sum(any(e["type"] == EVENT for e in s["events"]) for s in plan),
                 "not_captured": len(remaining),
                 "not_captured_with_lock_event": sum(any(e["type"] == EVENT for e in s["events"]) for s in remaining)},
    }
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    json.dump({
        "schema": "hyptcn3/worker-restart-resonance/1", "date": "2026-11-20", "commit": commit,
        "host": "zberove PC (Debian 13), bez roota", "guest": "Debian 12, jadro 6.1.0-42-cloud-amd64 (hyptcn-lab-a, hyptcn-lab-b)",
        "command": ".venv/bin/python data/results/collection_worker_resonance_20261120/record.py",
        "n": len(attempts), "values": values,
        "note": "Citanie auditov, events.json, archivov priznakov a zurnalu hosta kampane; ziadna snimka sa neparsovala "
                "znova. Cas snimky je cas hostitela, cas startu sluzby je cas hosta (posun hodin je pri kazdej session "
                "v guest_clock_offset_s). 'in step' = aspon 3 roztrhnute riadky (neplatne alebo uzavrete pravidlom) "
                "v okne udalosti. Rozbor priciny zamietnuti, nie meranie detekcie (HONESTY P4)."},
        sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


main()
