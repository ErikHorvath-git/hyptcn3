"""Torn process list of one live snapshot that stopped campaign benign-v3-20261022.

Reads saved evidence only: the campaign close record, the campaign audit of
session 3 (forward walk only), the two-direction walk of snapshots 503-507
(walk_probe.jsonl), the two-direction walk of all 720 snapshots
(walk_all.jsonl), the restore receipt and a re-audit of the same restored
session with the confirmed backward walk.

usage: record.py CAMPAIGN_DIR SESSION_DIR AUDIT_JSON RESTORE_OUT REAUDIT_JSON OUT_JSON
RESTORE_OUT is the JSON printed by `collection_archive restore`.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import numpy as np

ROOT = Path("/home/eh/projects/hyptcn3")
HERE = Path(__file__).resolve().parent
campaign, session, audit_path, restore_path, reaudit_path = map(Path, sys.argv[1:6])
out = Path(sys.argv[6])


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rows(npz):
    with np.load(npz, allow_pickle=False) as z:
        return ([int(s) for s in z["seq"]], json.loads(str(z["quality_json"])),
                z["matica"].copy(), z["valid"].copy(), [str(name) for name in z["mena"]])


def quality_summary(values):
    q = values["quality"]
    return {"accepted": values["accepted"], "reasons": values["reasons"], "windows": values["windows"],
            "score_coverage": values["score_coverage"],
            "quality": {k: q.get(k) for k in ("behavior_valid_rows", "invalid_input_seq", "integrity_findings",
                                               "integrity_unconfirmed_seq", "process_walk_prev_seq",
                                               "integrity_inconclusive_rows")}}


status = json.loads((campaign / "closed.json").read_text())["status_before"]
audit = json.loads(audit_path.read_text())
reaudit = json.loads(reaudit_path.read_text())
seq, quality, matrix, valid, names = rows(audit["values"]["features"])
seq2, quality2, matrix2, valid2, _ = rows(reaudit["values"]["features"])
assert seq == seq2
probe = {r["seq"]: r for r in map(json.loads, (HERE / "walk_probe.jsonl").read_text().splitlines())}
survey = [json.loads(line) for line in (HERE / "walk_all.jsonl").read_text().splitlines()]
dead = probe[505]["only_forward"][0]
# The new rule adds process_walk to every row; compare the remaining quality fields.
quality_changed = [s for s, a, b in zip(seq, quality, quality2)
                   if a != {k: v for k, v in b.items() if k != "process_walk"}]
vector_changed = [{"seq": s, "columns": {n: [float(a[i]), float(b[i])] for i, n in enumerate(names) if a[i] != b[i]}}
                  for s, a, b in zip(seq, matrix, matrix2) if (a != b).any()]
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": json.loads((session / "session.json").read_text())["guest_before"],
    "command": " ".join(sys.argv), "n": len(survey),
    "values": {
        "campaign_halt": {k: status.get(k) for k in ("status", "stage", "message", "accepted_archived", "session")},
        "forward_walk_audit": dict(quality_summary(audit["values"]), commit=audit["commit"]),
        "snapshot_505": {
            "forward_count": probe[505]["forward_count"], "forward_stop": probe[505]["forward_stop"],
            "backward_count": probe[505]["backward_count"], "backward_stop": probe[505]["backward_stop"],
            "first_inconsistent_forward_link": probe[505]["asymmetric_forward_links"][0],
            "forward_only_task": {"task_va": dead[0], "pid": dead[1], "comm": dead[2], "mm_null": dead[3],
                                  "pf_exiting": dead[4], "exit_state": dead[5]},
            "neighbors": {str(s): {"forward_count": probe[s]["forward_count"],
                                   "backward_count": probe[s]["backward_count"],
                                   "forward_stop": probe[s]["forward_stop"], "backward_stop": probe[s]["backward_stop"]}
                          for s in (503, 504, 506, 507)},
        },
        "both_directions_all_snapshots": {
            "snapshots": len(survey),
            "forward_stops": dict(Counter(str(r["fwd_stop"]) for r in survey)),
            "backward_stops": dict(Counter(str(r["bwd_stop"]) for r in survey)),
            "forward_inconsistent_link_seq": [r["seq"] for r in survey if r["asym"]],
            "directions_differ": [{"seq": r["seq"], "forward": r["fwd"], "backward": r["bwd"],
                                   "only_forward": len(r["only_fwd"]), "only_backward": len(r["only_bwd"])}
                                  for r in survey if r["fwd"] != r["bwd"] or r["only_fwd"] or r["only_bwd"]],
            "note": "Both walks closed in every snapshot except the forward walk of 505; the backward walk of 529 "
                    "closed over 78 tasks while the forward walk and the neighbors had 110.",
        },
        "restore": json.loads(restore_path.read_text()),
        "confirmed_walk_reaudit": dict(quality_summary(reaudit["values"]), commit=reaudit["commit"],
                                       commit_dirty=reaudit["commit_dirty"],
                                       measurement_dirty=reaudit["measurement_dirty"]),
        "reaudit_vs_audit": {"quality_changed_seq": quality_changed, "vector_changed": vector_changed},
        "inputs_sha256": {"audit": sha(audit_path), "audit_npz": sha(audit["values"]["features"]),
                          "reaudit": sha(reaudit_path), "reaudit_npz": sha(reaudit["values"]["features"]),
                          "restore_out": sha(restore_path), "walk_probe.jsonl": sha(HERE / "walk_probe.jsonl"),
                          "walk_all.jsonl": sha(HERE / "walk_all.jsonl")},
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(doc["values"], indent=1, ensure_ascii=False)[:6000])
