"""E2 per event type and per memory drift, from the saved E2 result and its replays (no new scoring).

usage: summary.py E2_JSON OUT_JSON

Reads data/results/safeguard_far_events_v3_20261114.json (tcn.eval udalosti), the replay rows it names
(values.relacie.*.prehratie/events.jsonl, hashes checked against values.relacie.*.subory_sha256), the event index it
names and each session's features archive (column mem_zero_ratio, valid rows). Every model alarm event is placed in
the category tcn.eval itself uses (tcn.eval.kategorie_udalosti: event type, po_udalosti or prevadzka). Per event type
it gives the occurrences with a model alarm and the delay of the first one (priebeh of the E2 result). The drift
split compares groups 1-4 and 5-8 (the session median of mem_zero_ratio falls during the campaign); it is
descriptive, not a test. For reference, the same column is summarized over the roles train, dev and calibration of
the bundle's corpus benign-v6-20261026 (role test_benign is not read: it was used once, for seed 0).
"""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys

import numpy as np

ROOT = Path("/home/eh/projects/hyptcn3")
sys.path.insert(0, str(ROOT))
from tcn.eval import kategorie_udalosti  # noqa: E402

e2_path, out = Path(sys.argv[1]), Path(sys.argv[2])
COMMIT_NOTE = ("HEAD when this record was generated. The script "
               "data/results/safeguard_far_events_v3_20261114/summary.py is not part of this commit; it is committed "
               "together with this file. It only reads saved files; the E2 result names its own commit.")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


e2 = json.loads(e2_path.read_text())
v = e2["values"]
index = json.loads(Path(v["index"]).read_text())
if sha(v["index"]) != v["index_sha256"]:
    raise SystemExit("event index changed since E2")
records = {r["id"]: r for r in index["sessions"]}
perioda, okno = v["perioda_s"], v["okno_riadkov"]
first_half = {f"v3-test_events-{g}" for g in (1, 2, 3, 4)}
sessions, alarms = {}, []
for sid, rel in sorted(v["relacie"].items()):
    replay = Path(rel["prehratie"])
    if sha(replay / "events.jsonl") != rel["subory_sha256"]["events.jsonl"]:
        raise SystemExit(f"{sid}: replay rows changed since E2")
    rows = [json.loads(line) for line in (replay / "events.jsonl").read_text().splitlines()]
    events = json.loads(Path(records[sid]["events"]).read_text())["events"]
    cats = kategorie_udalosti(rows, events, perioda, okno)
    t0 = float(rows[0]["timestamp"])
    for r, c in zip(rows, cats):
        if r["alarm_event"] and "model_anomaly" in r["alarm_sources"]:
            alarms.append({"session": sid, "group": rel["skupina"], "t_s": round(float(r["timestamp"]) - t0, 1),
                           "category": c})
    with np.load(records[sid]["features"], allow_pickle=False) as z:
        zero = z["matica"][:, [str(n) for n in z["mena"]].index("mem_zero_ratio")][z["valid"].astype(bool)]
    sessions[sid] = {"group": rel["skupina"], "scenario": rel["scenario"],
                     "mem_zero_ratio_p50": round(float(np.median(zero)), 4),
                     "model_alarm_events": rel["udalosti_model"]}
by_type = defaultdict(list)
for p in v["udalosti"]["priebeh"]:
    by_type[p["type"]].append(p)


def occurrences(ps):
    delays = sorted(p["oneskorenie_s"] for p in ps if p["alarm_modelu"])
    return {"occurrences": len(ps), "with_model_alarm": len(delays),
            "delay_s": {"min": round(delays[0], 1), "median": round(statistics.median(delays), 1),
                        "max": round(delays[-1], 1)} if delays else None,
            "alarm_rows": sum(p["alarm_riadkov"] for p in ps),
            "alarm_rows_in_afterglow": sum(p["alarm_v_dozvuku_riadkov"] for p in ps),
            "alarm_at_end_of_afterglow": sum(p["alarm_na_konci_dozvuku"] for p in ps)}


types = {}
for t, ps in sorted(by_type.items()):
    executed = [p for p in ps if p["executed"]]
    types[t] = {"class": ps[0]["class"], **occurrences(executed),
                "groups_1_4": occurrences([p for p in executed if p["skupina"] in first_half]),
                "groups_5_8": occurrences([p for p in executed if p["skupina"] not in first_half])}
zero_half = {h: [s["mem_zero_ratio_p50"] for s in sessions.values() if (s["group"] in first_half) == (h == "1_4")]
             for h in ("1_4", "5_8")}
corpus_path = ROOT / "data/campaigns/benign-v6-20261026/corpus.json"
corpus = json.loads(corpus_path.read_text())
reference = {}
for role in ("train", "dev", "calibration"):
    p50, low, high = [], [], []
    for s in corpus["sessions"]:
        if s["role"] != role:
            continue
        if sha(s["features"]) != s["features_sha256"]:
            raise SystemExit(f"{s['id']}: features changed since the corpus index")
        with np.load(s["features"], allow_pickle=False) as z:
            zero = z["matica"][:, [str(n) for n in z["mena"]].index("mem_zero_ratio")][z["valid"].astype(bool)]
        p50.append(float(np.median(zero)))
        low.append(float(zero.min()))
        high.append(float(zero.max()))
    reference[role] = {"sessions": len(p50), "p50_min": round(min(p50), 4), "p50_max": round(max(p50), 4),
                       "row_min": round(min(low), 4), "row_max": round(max(high), 4)}
executed = [p for ps in by_type.values() for p in ps if p["executed"]]
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(), "guest": e2["guest"],
    "command": " ".join(sys.argv), "n": len(sessions),
    "values": {
        "e2": {"path": str(e2_path.resolve()), "sha256": sha(e2_path), "commit": e2["commit"],
               "alokacia_uplna": v["alokacia"]["uplna"]},
        "events": {"occurrences": len(executed), "with_model_alarm": sum(p["alarm_modelu"] for p in executed)},
        "sessions_with_model_alarm": sum(s["model_alarm_events"] > 0 for s in sessions.values()),
        "groups_with_model_alarm": len({s["group"] for s in sessions.values() if s["model_alarm_events"] > 0}),
        "by_type": types,
        "alarm_events_by_category": {c: sum(a["category"] == c for a in alarms)
                                     for c in sorted({str(a["category"]) for a in alarms})},
        "alarm_events_outside_events": [a for a in alarms if a["category"] == "prevadzka"],
        "mem_zero_ratio_p50": {"groups_1_4": {"min": min(zero_half["1_4"]), "max": max(zero_half["1_4"]),
                                              "sessions": len(zero_half["1_4"])},
                               "groups_5_8": {"min": min(zero_half["5_8"]), "max": max(zero_half["5_8"]),
                                              "sessions": len(zero_half["5_8"])}},
        "mem_zero_ratio_benign_v6": reference,
        "sessions": sessions,
        "inputs_sha256": {"e2": sha(e2_path), "index": v["index_sha256"], "benign_v6_corpus": sha(corpus_path),
                          "features": {sid: records[sid]["features_sha256"] for sid in sessions}},
        "note": ("Descriptive split of the E2 result; FAR, intervals and tests are in the E2 result. "
                 "with_model_alarm counts event occurrences whose window held a model alarm event (priebeh), "
                 "alarm events are the rising edges of the k of n rule. The groups 1-4 and 5-8 differ in time, "
                 "boot and memory drift at once, so the split cannot separate the drift from other changes."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: doc["values"][k] for k in ("events", "by_type", "alarm_events_by_category",
                                                  "alarm_events_outside_events", "mem_zero_ratio_p50")},
                 indent=1, ensure_ascii=False)[:6000])
