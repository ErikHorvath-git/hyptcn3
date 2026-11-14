"""Read-only: task_struct fields of chosen list nodes in snapshots around a torn tasks walk.

usage: node_probe.py RAW_DIR PROFILE_DIR SEQS NODE_VA [NODE_VA ...]
SEQS is comma-separated. Prints JSON lines: physical address, pid/tgid/comm, tasks.next/prev, real_parent pid,
flags, exit_state of every node, plus init_task's tasks links.
"""
import json
import sys

sys.path.insert(0, "/home/eh/projects/hyptcn3")
from guestparse.image import ChainCursor  # noqa: E402
from guestparse.view import build_view  # noqa: E402

raw, profile = sys.argv[1], sys.argv[2]
seqs = [int(s) for s in sys.argv[3].split(",")]
nodes = [int(v, 16) for v in sys.argv[4:]]
cursor = ChainCursor(raw)
try:
    for seq in seqs:
        view, _ = build_view(raw, profile, until_seq=seq, image=cursor.image_at(seq))
        if view.profile_boot_mismatch():
            ok, info = view.reanchor()
            assert ok, info
        p = view.p
        m = {f: p.member("task_struct", f) for f in ("tasks", "pid", "tgid", "comm", "real_parent", "flags",
                                                    "exit_state", "mm", "start_time")}
        init_va = p.addr("init_task")
        init_pa = view.ktext_pa(init_va)
        out = {"seq": seq, "init_task": {"pa": hex(init_pa), "tasks_next": hex(view.u64(init_pa + m["tasks"])),
                                         "tasks_prev": hex(view.u64(init_pa + m["tasks"] + 8))}, "nodes": []}
        for node in nodes:
            tva = node - m["tasks"]
            tpa = view.to_pa(tva)
            row = {"node": hex(node), "pa": None if tpa is None else hex(tpa)}
            if tpa is not None:
                rp = view.u64(tpa + m["real_parent"])
                rpa = view.to_pa(rp) if view._plausible_va(rp) else None
                row.update(pid=view.i32(tpa + m["pid"]), tgid=view.i32(tpa + m["tgid"]),
                           comm=view.cstr(tpa + m["comm"], 16),
                           next=hex(view.u64(tpa + m["tasks"])), prev=hex(view.u64(tpa + m["tasks"] + 8)),
                           real_parent_pid=None if rpa is None else view.i32(rpa + m["pid"]),
                           flags=hex((view.i32(tpa + m["flags"]) or 0) & 0xffffffff),
                           exit_state=view.i32(tpa + m["exit_state"]),
                           mm_null=view.u64(tpa + m["mm"]) == 0,
                           start_time=view.u64(tpa + m["start_time"]) if m["start_time"] is not None else None)
            out["nodes"].append(row)
        print(json.dumps(out), flush=True)
finally:
    cursor.close()
