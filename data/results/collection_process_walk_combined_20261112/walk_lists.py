"""Read-only: the full forward walk of init_task.tasks (node, pid, tgid, comm) in chosen snapshots.

usage: walk_lists.py RAW_DIR PROFILE_DIR SEQ [SEQ ...] > walk_lists.jsonl
The walk follows tasks.next from init_task and stops at init_task, at a repeated node or at an untranslatable node;
"prev_ok" tells whether the node's tasks.prev points to the node the walk came from.
"""
import json
import sys

sys.path.insert(0, "/home/eh/projects/hyptcn3")
from guestparse.image import ChainCursor  # noqa: E402
from guestparse.view import build_view  # noqa: E402

raw, profile = sys.argv[1], sys.argv[2]
cursor = ChainCursor(raw)
try:
    for seq in (int(s) for s in sys.argv[3:]):
        view, _ = build_view(raw, profile, until_seq=seq, image=cursor.image_at(seq))
        if view.profile_boot_mismatch():
            ok, info = view.reanchor()
            assert ok, info
        p = view.p
        o = {f: p.member("task_struct", f) for f in ("tasks", "pid", "tgid", "comm")}
        init_va = p.addr("init_task")
        head = init_va + o["tasks"]
        nodes, seen, stop, came = [], set(), None, head
        nxt = view.u64(view.ktext_pa(init_va) + o["tasks"])
        while nxt != head:
            if nxt in seen:
                stop = "cycle at index %d" % [n["node"] for n in nodes].index(hex(nxt))
                break
            seen.add(nxt)
            tpa = view.to_pa(nxt - o["tasks"])
            if tpa is None:
                stop = "untranslatable"
                break
            nodes.append({"node": hex(nxt), "pid": view.i32(tpa + o["pid"]), "tgid": view.i32(tpa + o["tgid"]),
                          "comm": view.cstr(tpa + o["comm"], 16), "prev_ok": view.u64(tpa + o["tasks"] + 8) == came})
            came, nxt = nxt, view.u64(tpa + o["tasks"])
        print(json.dumps({"seq": seq, "count": len(nodes), "stop": stop, "nodes": nodes}), flush=True)
finally:
    cursor.close()
