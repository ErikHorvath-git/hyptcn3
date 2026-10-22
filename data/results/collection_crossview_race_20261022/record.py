"""Cross-view difference of one live snapshot that stopped campaign benign-v2-20261022.

Reads saved evidence only: the campaign status, the campaign audit of session 3
(old rule), the probe of the restored raw chain (probe.jsonl), the restore
receipt and a re-audit of the same restored session with the confirmation rule.

usage: record.py CAMPAIGN_DIR SESSION_DIR AUDIT_JSON RESTORE_OUT REAUDIT_JSON OUT_JSON
RESTORE_OUT is the JSON printed by `collection_archive restore`.
"""
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


def quality_rows(npz):
    with np.load(npz, allow_pickle=False) as z:
        return ([int(s) for s in z["seq"]], json.loads(str(z["quality_json"])),
                z["matica"].copy(), z["valid"].copy(), [str(name) for name in z["mena"]])


# After `close`, the halt itself is kept as status_before in closed.json.
closed = campaign / "closed.json"
status_file = closed if closed.exists() else campaign / "status.json"
status = json.loads(status_file.read_text())
status = status.get("status_before", status)
audit = json.loads(audit_path.read_text())["values"]
reaudit = json.loads(reaudit_path.read_text())["values"]
seq, quality, matrix, valid, names = quality_rows(audit["features"])
seq2, quality2, matrix2, valid2, _ = quality_rows(reaudit["features"])
probe = [json.loads(line) for line in (HERE / "probe.jsonl").read_text().splitlines()]
at = {row["seq"]: row for row in probe}
task = at[645]["task"][0]
# The new rule adds unconfirmed_findings to every row; compare the remaining fields.
changed = [s for s, a, b in zip(seq, quality, quality2)
           if a != {k: v for k, v in b.items() if k != "unconfirmed_findings"}]
with_unconfirmed = [s for s, b in zip(seq2, quality2) if b.get("unconfirmed_findings")]
column = names.index("chk_crossview")
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": json.loads((session / "session.json").read_text())["guest_before"],
    "command": " ".join(sys.argv), "n": len(seq),
    "values": {
        "campaign_halt": {k: status.get(k) for k in ("status", "stage", "message", "accepted_archived", "session")},
        "session": session.name,
        "session_commit": json.loads((session / "session.json").read_text())["commit"],
        "old_rule_audit": {
            "accepted": audit["accepted"], "reasons": audit["reasons"], "snapshots": audit["snapshots"],
            "windows": audit["windows"], "score_coverage": audit["score_coverage"], "quality": audit["quality"],
            "finding_rows": [{"seq": s, "findings": q["findings"]} for s, q in zip(seq, quality) if q["findings"]],
            "process_cross_view_inconclusive_seq": [s for s, q in zip(seq, quality)
                                                    if "process_cross_view" in q["inconclusive"]],
        },
        "probe": {
            "pid": 450961,
            "by_seq": [{"seq": r["seq"], "tasks": r["list_count"], "tree": r["tree_count"],
                        "conclusive": r["conclusive"], "findings": len(r["findings"]),
                        "pid_in_tasks": bool(r["pid_in_tasks"]), "pid_in_tree": bool(r["pid_in_tree"])}
                       for r in probe],
            "task_at_645": {"pid": task["pid"], "comm": task["comm"], "parent_pid": task["parent_pid"],
                            "parent_comm": task["parent_comm"], "flags": hex(task["flags"]),
                            "exit_state": task["exit_state"], "state": task["__state"],
                            "pf_exiting": task["PF_EXITING"], "start_time_ns": task["start_time"]},
            "parent_children_at_645": at[645]["parent_children_count"],
        },
        "restore": {k: json.loads(restore_path.read_text())[k] for k in ("files", "bytes", "stored_bytes")},
        "confirmation_rule_reaudit": {
            "accepted": reaudit["accepted"], "reasons": reaudit["reasons"], "snapshots": reaudit["snapshots"],
            "windows": reaudit["windows"], "score_coverage": reaudit["score_coverage"],
            "quality": {k: v for k, v in reaudit["quality"].items() if k != "coverage"},
            "logs_accepted": reaudit["logs"]["accepted"],
            "matrix_identical_to_old_rule": bool(np.array_equal(matrix, matrix2)),
            "valid_mask_identical": bool(np.array_equal(valid, valid2)) and seq == seq2,
            "quality_rows_changed_seq": changed,
            "rows_with_unconfirmed_seq": with_unconfirmed,
            "chk_crossview_at_645": float(matrix2[seq2.index(645), column]),
            "quality_at_645": quality2[seq2.index(645)],
        },
        "inputs_sha256": {status_file.name: sha(status_file), "audit": sha(audit_path),
                          "audit_features": sha(audit["features"]), "probe.jsonl": sha(HERE / "probe.jsonl"),
                          "restore.out": sha(restore_path), "reaudit": sha(reaudit_path),
                          "reaudit_features": sha(reaudit["features"])},
        "note": ("A live snapshot read the tasks and children/sibling links of a short-lived postmaster "
                 "child at different moments. The re-audit runs on a restored copy of the archived raw "
                 "chain; the historical verdict of the campaign stays rejected."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k != "inputs_sha256"}, indent=1, ensure_ascii=False)[:6000])
