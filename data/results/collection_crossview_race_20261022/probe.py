"""Read-only probe of the process cross-view difference around one snapshot.

usage: probe.py RAW_DIR PROFILE_DIR PID SEQ [SEQ ...] > probe.jsonl
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, "/home/eh/projects/hyptcn3")
from guestparse import checks  # noqa: E402
from guestparse.image import ChainCursor  # noqa: E402
from guestparse.view import build_view  # noqa: E402

raw, profile, pid = sys.argv[1], sys.argv[2], int(sys.argv[3])
seqs = [int(s) for s in sys.argv[4:]]
PF_EXITING = 0x4


def member(view, name):
    return view.p.member("task_struct", name)


def task_info(view, tva):
    tpa = view.to_pa(tva)
    if tpa is None:
        return None
    out = {"task_va": hex(tva), "pid": view.i32(tpa + member(view, "pid")),
           "comm": view.cstr(tpa + member(view, "comm"), 16)}
    for field in ("flags", "exit_state", "__state", "start_time", "real_start_time", "start_boottime"):
        off = member(view, field)
        if off is not None:
            out[field] = view.u64(tpa + off) if field in ("start_time", "real_start_time", "start_boottime") \
                else (view.i32(tpa + off) or 0) & 0xffffffff
    off = member(view, "real_parent")
    if off is not None:
        parent = view.u64(tpa + off)
        ppa = view.to_pa(parent) if parent else None
        out["real_parent"] = hex(parent) if parent else None
        if ppa is not None:
            out["parent_pid"] = view.i32(ppa + member(view, "pid"))
            out["parent_comm"] = view.cstr(ppa + member(view, "comm"), 16)
    if "flags" in out:
        out["PF_EXITING"] = bool(out["flags"] & PF_EXITING)
    return out


def children(view, tva):
    o_child, o_sib = member(view, "children"), member(view, "sibling")
    tpa = view.to_pa(tva)
    head = tva + o_child
    nxt = view.u64(tpa + o_child)
    out = []
    while nxt != head and nxt is not None and len(out) < 4096:
        child = nxt - o_sib
        cpa = view.to_pa(child)
        if cpa is None:
            out.append(("untranslatable", hex(child)))
            break
        out.append((view.i32(cpa + member(view, "pid")), view.cstr(cpa + member(view, "comm"), 16), hex(child)))
        nxt = view.u64(cpa + o_sib)
    return out


cursor = ChainCursor(raw)
try:
    for seq in seqs:
        image = cursor.image_at(seq)
        view, _ = build_view(raw, profile, until_seq=seq, image=image)
        if view.profile_boot_mismatch():
            ok, info = view.reanchor()
            assert ok, info
        plist = view.processes()
        tree, stop = checks._task_tree(view)
        cv = checks.process_cross_view(view, plist)
        target = [p for p in plist["processes"] if p["pid"] == pid]
        in_tree = [hex(va) for va, t in tree.items() if t["pid"] == pid]
        row = {"seq": seq, "list_count": plist["count"], "list_truncated": plist["truncated"],
               "tree_count": len(tree) - 1, "tree_stop": stop, "conclusive": cv["conclusive"],
               "findings": cv["findings"], "inconclusive_differences": cv["inconclusive_differences"],
               "pid_in_tasks": [hex(p["task_va"]) for p in target], "pid_in_tree": in_tree}
        vas = {p["task_va"] for p in target} | {int(v, 16) for v in in_tree}
        row["task"] = [task_info(view, va) for va in sorted(vas)]
        for t in row["task"]:
            if t and t.get("real_parent"):
                kids = children(view, int(t["real_parent"], 16))
                row["parent_children_tail"] = kids[-6:]
                row["parent_children_count"] = len(kids)
        postgres = sorted((p["pid"], hex(p["task_va"])) for p in plist["processes"] if p["comm"] == "postgres")
        row["postgres_in_tasks"] = postgres[-8:]
        row["postgres_count"] = len(postgres)
        side = json.loads(next(Path(raw).glob("hyptcn-lab_%06d_*.json" % seq)).read_text())
        row["sidecar"] = {k: side.get(k) for k in ("timestamp_unix", "seq")}
        row["sidecar_stats"] = side.get("stats")
        print(json.dumps(row, default=str))
finally:
    cursor.close()
