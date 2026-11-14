"""Read-only probe of the init_task.tasks list around one snapshot, in both directions.

usage: walk_probe.py RAW_DIR PROFILE_DIR SEQ [SEQ ...] > walk_probe.jsonl
"""
import json
import sys

sys.path.insert(0, "/home/eh/projects/hyptcn3")
from guestparse.image import ChainCursor  # noqa: E402
from guestparse.view import build_view  # noqa: E402

raw, profile = sys.argv[1], sys.argv[2]
seqs = [int(s) for s in sys.argv[3:]]
PF_EXITING = 0x4


def walk(view, field_off):
    """Follow tasks.next (field_off 0) or tasks.prev (8) from init_task; return nodes and stop."""
    p = view.p
    o_tasks = p.member("task_struct", "tasks")
    init_va = p.addr("init_task")
    head = init_va + o_tasks
    nodes, seen, stop = [], set(), None
    nxt = view.u64(view.ktext_pa(init_va) + o_tasks + field_off)
    while True:
        if nxt == head:
            break
        if not view._plausible_va(nxt):
            stop = "implausible 0x%x" % (nxt or 0)
            break
        if nxt in seen:
            stop = "cycle at node 0x%x (index %d)" % (nxt, [n["node"] for n in nodes].index(nxt))
            break
        seen.add(nxt)
        tpa = view.to_pa(nxt - o_tasks)
        if tpa is None:
            stop = "untranslatable"
            break
        info = {"node": nxt, "pid": view.i32(tpa + p.member("task_struct", "pid")),
                "comm": view.cstr(tpa + p.member("task_struct", "comm"), 16),
                "kthread": view.u64(tpa + p.member("task_struct", "mm")) == 0,
                "flags": (view.i32(tpa + p.member("task_struct", "flags")) or 0) & 0xffffffff,
                "next": view.u64(tpa + o_tasks), "prev": view.u64(tpa + o_tasks + 8)}
        info["exiting"] = bool(info["flags"] & PF_EXITING)
        es = p.member("task_struct", "exit_state")
        if es is not None:
            info["exit_state"] = view.i32(tpa + es)
        nodes.append(info)
        nxt = info["next"] if field_off == 0 else info["prev"]
    return nodes, stop


cursor = ChainCursor(raw)
try:
    for seq in seqs:
        image = cursor.image_at(seq)
        view, _ = build_view(raw, profile, until_seq=seq, image=image)
        if view.profile_boot_mismatch():
            ok, info = view.reanchor()
            assert ok, info
        fwd, fstop = walk(view, 0)
        bwd, bstop = walk(view, 8)
        fset = {n["node"] for n in fwd}
        bset = {n["node"] for n in bwd}
        # Links whose reverse pointer disagrees: a.next = b but b.prev != a.
        by = {n["node"]: n for n in fwd + bwd}
        asym = []
        prevnode = None
        for n in fwd:
            if prevnode is not None and n["prev"] != prevnode:
                asym.append({"at_index": fwd.index(n), "node": hex(n["node"]), "pid": n["pid"], "comm": n["comm"],
                             "prev": hex(n["prev"]), "came_from": hex(prevnode)})
            prevnode = n["node"]
        row = {"seq": seq, "forward_count": len(fwd), "forward_stop": fstop,
               "backward_count": len(bwd), "backward_stop": bstop,
               "only_forward": [(hex(n["node"]), n["pid"], n["comm"], n["kthread"], n["exiting"], n.get("exit_state"))
                                for n in fwd if n["node"] not in bset],
               "only_backward": [(hex(n["node"]), n["pid"], n["comm"], n["kthread"], n["exiting"], n.get("exit_state"))
                                 for n in bwd if n["node"] not in fset],
               "asymmetric_forward_links": asym[:10],
               "forward_tail": [(hex(n["node"]), n["pid"], n["comm"]) for n in fwd[-4:]],
               "backward_head": [(hex(n["node"]), n["pid"], n["comm"]) for n in bwd[:4]]}
        print(json.dumps(row, default=str), flush=True)
finally:
    cursor.close()
