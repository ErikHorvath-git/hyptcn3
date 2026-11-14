"""Torn process list of one live snapshot that stopped campaign events-v3-20261108 (deletion and tail insertion).

Reads saved evidence only: the campaign close record, the campaign audit of session 46 (rules of 0b61ffd and
b065ee4), the two-direction walk of snapshots 269-271 (walk_probe.jsonl), task_struct fields of the nodes around the
torn links in the same snapshots (node_probe.jsonl), the full forward walks of the same snapshots (walk_lists.jsonl),
the restore receipt, the sidecar of snapshot 270 and an excerpt of the guest journal around it (journal_excerpt.txt).
No re-audit: the owner decided on 2026-11-13 not to change guestparse, so no rule covers this shape.

usage: record.py CAMPAIGN_DIR SESSION_DIR AUDIT_JSON RESTORE_OUT OUT_JSON
RESTORE_OUT is the output of `collection_archive restore`. SESSION_DIR is the restored copy whose raw/ holds the
sidecars.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

import numpy as np

ROOT = Path("/home/eh/projects/hyptcn3")
HERE = Path(__file__).resolve().parent
campaign, session, audit_path, restore_path = map(Path, sys.argv[1:5])
out = Path(sys.argv[5])
SEQ = 270
CHUNK = 1 << 20
LIST_POISON2 = "0xdead000000000122"
COMMIT_NOTE = ("HEAD when this record was generated. The record script "
               "data/results/collection_process_walk_combined_20261112/record.py and its probe outputs are not part "
               "of this commit; they are committed together with this file. The campaign audit ran on the campaign "
               "commit in values.campaign_audit.commit.")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def jsonl(name):
    return [json.loads(line) for line in (HERE / name).read_text().splitlines()]


closed = json.loads((campaign / "closed.json").read_text())
audit = json.loads(audit_path.read_text())
v = audit["values"]
q = v["quality"]
with np.load(v["features"], allow_pickle=False) as z:
    seq = [int(s) for s in z["seq"]]
    notes = [str(n) for n in z["poznamky"]]
    rows = json.loads(str(z["quality_json"]))
probe = {r["seq"]: r for r in jsonl("walk_probe.jsonl")}
nodes = {r["seq"]: r for r in jsonl("node_probe.jsonl")}
lists = {r["seq"]: r for r in jsonl("walk_lists.jsonl")}
by_node = {s: {n["node"]: n for n in nodes[s]["nodes"]} for s in nodes}
side = json.loads(next((session / "raw").glob(f"*_{SEQ:06d}_*.json")).read_text())
links = probe[SEQ]["asymmetric_forward_links"]
middle, tail_x, dead = (link["node"] for link in links)
came_middle, came_tail = links[0]["came_from"], links[1]["came_from"]
stale_prev = by_node[SEQ][middle]["prev"]
# The walk before the second torn link: every node up to the one whose next is the tail node.
cut = lists[SEQ]["nodes"][:links[1]["at_index"]]
pids = {s: {n["pid"] for n in lists[s]["nodes"]} for s in lists}
pids_cut = {n["pid"] for n in cut}
role = {"middle_node": middle, "middle_node_prev": stale_prev, "middle_node_came_from": came_middle,
        "tail_node": tail_x, "tail_node_came_from": came_tail, "dead_node": dead}
page_order = sorted(({"role": k, "node": n, "pa": by_node[SEQ][n]["pa"],
                      "chunk": int(by_node[SEQ][n]["pa"], 16) // CHUNK} for k, n in role.items()),
                    key=lambda r: int(r["pa"], 16))
page_order.append({"role": "init_task", "pa": nodes[SEQ]["init_task"]["pa"],
                   "chunk": int(nodes[SEQ]["init_task"]["pa"], 16) // CHUNK})
page_order.sort(key=lambda r: int(r["pa"], 16))
journal = (HERE / "journal_excerpt.txt").read_text().splitlines()
source = re.search(r"^# sha256: (\w+)$", journal[1])[1]
journal_source = re.search(r"^# source: (\S+)$", journal[0])[1]
if sha(journal_source) != source:
    raise SystemExit("journal excerpt does not match its source")
pick = lambda needle: next(line.split(" ", 1)[0] for line in journal if needle in line)
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": json.loads((session / "session.json").read_text())["guest_before"],
    "command": " ".join(sys.argv), "n": len(probe),
    "values": {
        "campaign_halt": {k: closed["status_before"].get(k)
                          for k in ("status", "stage", "message", "accepted_archived", "session", "updated_at")},
        "campaign_close": {k: closed.get(k) for k in ("date", "reason")},
        "campaign_audit": {"accepted": v["accepted"], "reasons": v["reasons"], "windows": v["windows"],
                           "commit": audit["commit"], "measurement_dirty": audit["measurement_dirty"],
                           "quality": {k: q.get(k) for k in ("behavior_valid_rows", "invalid_input_seq",
                                                              "integrity_findings", "integrity_unconfirmed_seq",
                                                              "process_walk_prev_seq", "process_walk_tail_seq",
                                                              "integrity_inconclusive_rows")},
                           "row_quality": {k: rows[seq.index(SEQ)][k] for k in ("traversals_complete",
                                                                                 "behavior_valid", "process_walk",
                                                                                 "inconclusive")},
                           "row_note": notes[seq.index(SEQ)]},
        f"snapshot_{SEQ}": {
            "timestamp": side["timestamp"], "full": side["output"]["full"], "paused": side["capture"]["paused"],
            "capture_ms": side["capture"]["capture_ms"], "backend_read_ms": side["capture"]["backend_read_ms"],
            "chunk_bytes": side["capture"]["chunk_size"], "chunks": side["stats"]["chunks"],
            "forward_count": probe[SEQ]["forward_count"], "forward_stop": probe[SEQ]["forward_stop"],
            "backward_count": probe[SEQ]["backward_count"], "backward_stop": probe[SEQ]["backward_stop"],
            "inconsistent_forward_links": links,
            "forward_only": len(probe[SEQ]["only_forward"]), "backward_only": len(probe[SEQ]["only_backward"]),
            "backward_head": probe[SEQ]["backward_head"],
            "middle_node_prev_is_deleted": by_node[SEQ][stale_prev]["prev"] == LIST_POISON2
                                           and by_node[SEQ][stale_prev]["next"] == middle,
            "tail_node_is_thread": by_node[SEQ][tail_x]["pid"] != by_node[SEQ][tail_x]["tgid"],
            "init_task_prev_is_tail_node": nodes[SEQ]["init_task"]["tasks_prev"] == tail_x,
            # The collector reads guest RAM in ascending physical address order, chunk by chunk.
            "page_read_order": page_order,
            "init_task_links": {str(s): nodes[s]["init_task"] for s in sorted(nodes)},
            "nodes": {str(s): nodes[s]["nodes"] for s in sorted(nodes)},
            "neighbors": {str(s): {"forward_count": probe[s]["forward_count"],
                                   "backward_count": probe[s]["backward_count"],
                                   "forward_stop": probe[s]["forward_stop"], "backward_stop": probe[s]["backward_stop"]}
                          for s in sorted(probe) if s != SEQ},
        },
        "forward_before_tail_node": {
            "count": len(cut),
            "vs_previous_snapshot": {"gone_pids": sorted(pids[SEQ - 1] - pids_cut),
                                     "new_pids": sorted(pids_cut - pids[SEQ - 1])},
            "vs_next_snapshot": {"gone_pids": sorted(pids_cut - pids[SEQ + 1]),
                                 "new_pids": sorted(pids[SEQ + 1] - pids_cut)},
            "counts": {str(s): lists[s]["count"] for s in sorted(lists)},
        },
        "guest_journal": {"event_start": pick("udalosti.py start zamok_tabulky"),
                          "worker_traceback": pick("Traceback"),
                          "worker_exit": pick("Main process exited"),
                          "worker_restart": pick("Started hyptcn-lab@worker"),
                          "source": journal_source, "source_sha256": source},
        "restore": json.loads(restore_path.read_text().split("\n\nreal")[0]),
        "inputs_sha256": {"audit": sha(audit_path), "audit_npz": sha(v["features"]),
                          "restore_out": sha(restore_path), "closed.json": sha(campaign / "closed.json"),
                          f"sidecar_{SEQ}": sha(next((session / "raw").glob(f"*_{SEQ:06d}_*.json"))),
                          "walk_probe.jsonl": sha(HERE / "walk_probe.jsonl"),
                          "node_probe.jsonl": sha(HERE / "node_probe.jsonl"),
                          "walk_lists.jsonl": sha(HERE / "walk_lists.jsonl"),
                          "journal_excerpt.txt": sha(HERE / "journal_excerpt.txt")},
        "note": ("Evidence of the torn process list that stopped campaign events-v3-20261108. The probes read a copy "
                 "of session 46 restored from its archive (values.restore), moved to data/diagnostics/"
                 "torn-walk-20261112/events-v3-20261108_46_test_events_write_heavy/raw next to copies of the "
                 "session's metadata files, because the parser takes the guest boot identity from session.json "
                 "beside raw/; the session directory and the archive of the campaign are unchanged. page_read_order "
                 "relies on the collector reading guest physical memory in ascending order in chunk_bytes pieces "
                 "(vmicollect/src/backend.c, vmic_capture_timed). nodes hold the task_struct fields as read from each "
                 "snapshot image. The forward walk has two torn spots. At the middle node its prev still names a "
                 "node that the same image shows deleted from the list (prev LIST_POISON2, next the middle node): "
                 "the worker process and its database backend left the list during the read, after the middle "
                 "node's page and before the pages of the nodes around them. A stale prev alone does not stop the "
                 "forward walk. At the tail node the page holds a live thread of the orders process (exit_state 0, "
                 "PF_EXITING clear, mm set), while init_task.prev and the previous node's next, read later, already "
                 "name it: during the read that thread exited, its task_struct was reused and a new task was linked "
                 "at the tail into it (snapshot 271 shows kworker/1:2 in it). Alone, that tail insertion is the "
                 "shape the rule tail of b065ee4 closes. Together, the first torn link is the middle node, which "
                 "init_task.prev does not name, so the rule tail does not apply; and the backward walk starts on the "
                 "stale tail page and jumps from it to the leader's predecessor, so it does not pass the forward "
                 "nodes before the first torn link and the rule prev of 0b61ffd does not apply either. The row was "
                 "refused. forward_before_tail_node shows that the forward nodes up to the tail node differ from "
                 "both neighbours only by the processes that ended or started around the event; it is a "
                 "consistency check, not an accepted list. The owner decided not to change guestparse "
                 "(extractor_sha256 of the bundle and of corpus benign-v6), so this shape stays a known limitation."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k not in ("inputs_sha256", "campaign_close")}, indent=1,
                 ensure_ascii=False)[:9000])
