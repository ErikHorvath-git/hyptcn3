"""Torn process list of one live snapshot that stopped campaign benign-v5-20261025 (tail insertion).

Reads saved evidence only: the campaign close record, the campaign audit of
session 18 (rule of 0b61ffd), the two-direction walk of snapshots 611-615
(walk_probe.jsonl), task_struct fields of the nodes around the torn link in
snapshots 612-614 (node_probe.jsonl), the same two probes around snapshot 70
whose backward walk differed (walk_probe_70.jsonl, node_probe_70.jsonl), the two-direction walk of all 720
snapshots (walk_all.jsonl), the restore receipt, the sidecar of snapshot 613
and a re-audit of the same restored session with the tail rule.

usage: record.py CAMPAIGN_DIR SESSION_DIR AUDIT_JSON RESTORE_OUT REAUDIT_JSON OUT_JSON
RESTORE_OUT is the JSON printed by `collection_archive restore`. SESSION_DIR is the
restored copy whose raw/ holds the sidecars.
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
SEQ = 613
CHUNK = 1 << 20
COMMIT_NOTE = ("HEAD when this record was generated. The record script "
               "data/results/collection_process_walk_insert_20261026/record.py and its probe outputs are not part "
               "of this commit; they are committed together with this file. The re-audit ran on the commit in "
               "values.tail_walk_reaudit.commit.")


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
                                               "process_walk_tail_seq", "integrity_inconclusive_rows")}}


closed = json.loads((campaign / "closed.json").read_text())
status = closed["status_before"]
audit = json.loads(audit_path.read_text())
reaudit = json.loads(reaudit_path.read_text())
seq, quality, matrix, valid, names = rows(audit["values"]["features"])
seq2, quality2, matrix2, valid2, _ = rows(reaudit["values"]["features"])
assert seq == seq2
probe = {r["seq"]: r for r in map(json.loads, (HERE / "walk_probe.jsonl").read_text().splitlines())}
nodes = {r["seq"]: r for r in map(json.loads, (HERE / "node_probe.jsonl").read_text().splitlines())}
survey = [json.loads(line) for line in (HERE / "walk_all.jsonl").read_text().splitlines()]
probe70 = {r["seq"]: r for r in map(json.loads, (HERE / "walk_probe_70.jsonl").read_text().splitlines())}
nodes70 = {r["seq"]: {n["node"]: n for n in r["nodes"]} for r in
           map(json.loads, (HERE / "node_probe_70.jsonl").read_text().splitlines())}
init70 = {r["seq"]: r["init_task"] for r in map(json.loads, (HERE / "node_probe_70.jsonl").read_text().splitlines())}
x70 = probe70[70]["only_backward"][0][0]
tail70 = probe70[70]["forward_tail"][-1][0]
link = probe[SEQ]["asymmetric_forward_links"][0]
by_node = {s: {n["node"]: n for n in nodes[s]["nodes"]} for s in nodes}
x, tail = link["node"], link["came_from"]
side = json.loads(next((session / "raw").glob(f"*_{SEQ:06d}_*.json")).read_text())
pages = {"x_task_struct": by_node[SEQ][x]["pa"], "tail_task_struct": by_node[SEQ][tail]["pa"],
         "init_task": nodes[SEQ]["init_task"]["pa"]}
quality_changed = [s for s, a, b in zip(seq, quality, quality2) if a != b]
vector_changed = [{"seq": s, "columns": {n: [float(a[i]), float(b[i])] for i, n in enumerate(names) if a[i] != b[i]}}
                  for s, a, b in zip(seq, matrix, matrix2) if (a != b).any()]
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": json.loads((session / "session.json").read_text())["guest_before"],
    "command": " ".join(sys.argv), "n": len(survey),
    "values": {
        "campaign_halt": {k: status.get(k) for k in ("status", "stage", "message", "accepted_archived", "session")},
        "campaign_close": {k: closed.get(k) for k in ("date", "reason")},
        "campaign_audit": dict(quality_summary(audit["values"]), commit=audit["commit"]),
        f"snapshot_{SEQ}": {
            "timestamp": side["timestamp"], "full": side["output"]["full"], "paused": side["capture"]["paused"],
            "capture_ms": side["capture"]["capture_ms"], "backend_read_ms": side["capture"]["backend_read_ms"],
            "chunk_bytes": side["capture"]["chunk_size"], "chunks": side["stats"]["chunks"],
            "forward_count": probe[SEQ]["forward_count"], "forward_stop": probe[SEQ]["forward_stop"],
            "backward_count": probe[SEQ]["backward_count"], "backward_stop": probe[SEQ]["backward_stop"],
            "first_inconsistent_forward_link": link,
            "forward_only": len(probe[SEQ]["only_forward"]), "backward_only": len(probe[SEQ]["only_backward"]),
            # The collector reads guest RAM in ascending physical address order, chunk by chunk.
            "page_read_order": {k: {"pa": v, "chunk": int(v, 16) // CHUNK} for k, v in pages.items()},
            "init_task_links": {str(s): nodes[s]["init_task"] for s in sorted(nodes)},
            "node_x": {str(s): by_node[s][x] for s in sorted(nodes)},
            "tail_node": {str(s): by_node[s][tail] for s in sorted(nodes)},
            "neighbors": {str(s): {"forward_count": probe[s]["forward_count"],
                                   "backward_count": probe[s]["backward_count"],
                                   "forward_stop": probe[s]["forward_stop"], "backward_stop": probe[s]["backward_stop"]}
                          for s in sorted(probe) if s != SEQ},
        },
        # The same insertion seen only by the backward walk: the tail was read before the new node was linked.
        "snapshot_70": {
            "forward_count": probe70[70]["forward_count"], "forward_stop": probe70[70]["forward_stop"],
            "backward_count": probe70[70]["backward_count"], "backward_stop": probe70[70]["backward_stop"],
            "asymmetric_forward_links": len(probe70[70]["asymmetric_forward_links"]),
            "page_read_order": {k: {"pa": v, "chunk": int(v, 16) // CHUNK} for k, v in
                                {"x_task_struct": nodes70[70][x70]["pa"], "tail_task_struct": nodes70[70][tail70]["pa"],
                                 "init_task": init70[70]["pa"]}.items()},
            "init_task_links": {str(s): init70[s] for s in sorted(init70)},
            "node_x": {str(s): nodes70[s][x70] for s in sorted(nodes70)},
            "tail_node": {str(s): nodes70[s][tail70] for s in sorted(nodes70)},
        },
        "both_directions_all_snapshots": {
            "snapshots": len(survey),
            "forward_stops": dict(Counter(str(r["fwd_stop"]) for r in survey)),
            "backward_stops": dict(Counter(str(r["bwd_stop"]) for r in survey)),
            "forward_inconsistent_link_seq": [r["seq"] for r in survey if r["asym"]],
            "directions_differ": [{"seq": r["seq"], "forward": r["fwd"], "backward": r["bwd"],
                                   "only_forward": len(r["only_fwd"]), "only_backward": len(r["only_bwd"])}
                                  for r in survey if r["fwd"] != r["bwd"] or r["only_fwd"] or r["only_bwd"]],
        },
        "restore": json.loads(restore_path.read_text()),
        "tail_walk_reaudit": dict(quality_summary(reaudit["values"]), commit=reaudit["commit"],
                                  commit_dirty=reaudit["commit_dirty"],
                                  measurement_dirty=reaudit["measurement_dirty"]),
        "reaudit_vs_audit": {"quality_changed_seq": quality_changed, "vector_changed": vector_changed},
        "inputs_sha256": {"audit": sha(audit_path), "audit_npz": sha(audit["values"]["features"]),
                          "reaudit": sha(reaudit_path), "reaudit_npz": sha(reaudit["values"]["features"]),
                          "restore_out": sha(restore_path), "closed.json": sha(campaign / "closed.json"),
                          "sidecar_613": sha(next((session / "raw").glob(f"*_{SEQ:06d}_*.json"))),
                          "walk_probe.jsonl": sha(HERE / "walk_probe.jsonl"),
                          "node_probe.jsonl": sha(HERE / "node_probe.jsonl"),
                          "walk_probe_70.jsonl": sha(HERE / "walk_probe_70.jsonl"),
                          "node_probe_70.jsonl": sha(HERE / "node_probe_70.jsonl"),
                          "walk_all.jsonl": sha(HERE / "walk_all.jsonl")},
        "note": ("Evidence of the torn process list that stopped campaign benign-v5-20261025. The probes and the "
                 "re-audit read a copy of session 18 restored from its verified archive (values.restore). The "
                 "restored directory was then moved to data/diagnostics/torn-walk-20261026/"
                 "benign-v5-20261025_18_train_quiet/raw, next to copies of the session's metadata files, because the "
                 "parser takes the guest boot identity from session.json beside raw/; the session directory "
                 "and the archive of the campaign are unchanged. page_read_order relies on the collector reading "
                 "guest physical memory in ascending order in chunk_bytes pieces (vmicollect/src/backend.c, "
                 "vmic_capture_timed). node_x and tail_node hold the task_struct fields as read from each snapshot "
                 "image: in snapshot 613 node_x is the stale page, not the task linked there. The re-audit ran on "
                 "the clean measurement code of its commit (measurement_dirty empty); its commit_dirty is true "
                 "because untracked record files were already in data/results. It checks the rule on the failing "
                 "session and does not change the campaign verdict."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k != "inputs_sha256"}, indent=1,
                 ensure_ascii=False)[:8000])
