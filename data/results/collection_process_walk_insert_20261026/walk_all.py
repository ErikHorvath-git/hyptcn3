"""Both-direction tasks walk for every snapshot of a restored session (read-only).

usage: walk_all.py RAW_DIR PROFILE_DIR > walk_all.jsonl
One line per seq: forward/backward counts and stop reasons, asymmetric forward
links (node.prev != node reached from), nodes seen in only one direction.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, "/home/eh/projects/hyptcn3")
from guestparse.image import ChainCursor  # noqa: E402
from guestparse.view import build_view  # noqa: E402

raw, profile = sys.argv[1], sys.argv[2]


def walk(view, off):
    p = view.p
    o = p.member("task_struct", "tasks")
    init_va = p.addr("init_task")
    head = init_va + o
    nodes, seen, stop = [], set(), None
    nxt = view.u64(view.ktext_pa(init_va) + o + off)
    while True:
        if nxt == head:
            break
        if not view._plausible_va(nxt):
            stop = "implausible"
            break
        if nxt in seen:
            stop = "cycle"
            break
        seen.add(nxt)
        tpa = view.to_pa(nxt - o)
        if tpa is None:
            stop = "untranslatable"
            break
        nodes.append((nxt, view.i32(tpa + p.member("task_struct", "pid")),
                      view.cstr(tpa + p.member("task_struct", "comm"), 16),
                      view.u64(tpa + o), view.u64(tpa + o + 8)))
        nxt = nodes[-1][3] if off == 0 else nodes[-1][4]
    return nodes, stop, head


seqs = sorted(int(f.name.split("_")[1]) for f in Path(raw).glob("*.vmicd"))
cursor = ChainCursor(raw)
try:
    for seq in seqs:
        view, _ = build_view(raw, profile, until_seq=seq, image=cursor.image_at(seq))
        if view.profile_boot_mismatch():
            ok, info = view.reanchor()
            assert ok, info
        fwd, fstop, head = walk(view, 0)
        bwd, bstop, _ = walk(view, 8)
        came, asym, first_asym = head, 0, None
        for i, n in enumerate(fwd):
            if n[4] != came:
                asym += 1
                first_asym = i if first_asym is None else first_asym
            came = n[0]
        fset, bset = {n[0] for n in fwd}, {n[0] for n in bwd}
        prefix = fwd[:first_asym] if first_asym is not None else fwd
        print(json.dumps({"seq": seq, "fwd": len(fwd), "fwd_stop": fstop, "bwd": len(bwd), "bwd_stop": bstop,
                          "asym": asym, "first_asym": first_asym,
                          "prefix_in_bwd": all(n[0] in bset for n in prefix),
                          "only_fwd": [(n[1], n[2]) for n in fwd if n[0] not in bset],
                          "only_bwd": [(n[1], n[2]) for n in bwd if n[0] not in fset]}), flush=True)
finally:
    cursor.close()
