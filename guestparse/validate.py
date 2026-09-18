"""
Porovnanie rekonstrukcie zo snimky s pozemnou pravdou z hosta.

Pozemna prava sa berie z prikazov spustenych V HOSTOVI tesne pred snimkou a
tesne po nej (ps, lsmod, ss). PRECO dva behy: VM sa pri zbere nezastavuje,
takze procesy vznikaju a zanikaju pocas odberu. Porovnavat sa da poctivo iba
STABILNA mnozina - to, co bolo v hostovi pred aj po. Proces, ktory sa objavi
len v jednom behu `ps`, nie je ani chyba parsera, ani nalez.

Mena procesov: jadro drzi v task_struct.comm 16 bajtov, teda 15 znakov.
`ps` ale tlaci pri vlaknach jadra dlhsie meno (/proc/PID/stat ho sklada z
kthread full_name a popisu pracovneho vlakna). Porovnanie preto pozna tri
pravidla a kazde pouzitie zaratava, aby bolo v reporte vidno, kolko zhod je
doslovnych a kolko len po orezani.
"""

import ipaddress
import os
import time

from .checks import check_all

COMM_LEN = 15          # TASK_COMM_LEN 16 vratane koncovej nuly


# ------------------------------------------------- citanie pozemnej pravdy


def read_ps(path):
    """`ps -eo pid,comm` -> {pid: meno}. Hlavicka aj prazdne riadky sa preskocia."""
    out = {}
    with open(path, errors="replace") as fh:
        for ln in fh:
            parts = ln.split(None, 1)
            if len(parts) != 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue            # hlavicka "PID COMMAND"
            out[pid] = parts[1].strip()
    return out


def read_lsmod(path):
    """`lsmod` -> mnozina mien modulov."""
    out = set()
    with open(path, errors="replace") as fh:
        for ln in fh:
            parts = ln.split()
            if not parts or parts[0] == "Module":
                continue
            out.add(parts[0])
    return out


def _norm_addr(text):
    """'[::]' , '127.0.0.53%lo' , '0.0.0.0' -> kanonicka adresa, alebo None."""
    a = text.strip().strip("[]").split("%")[0]
    if not a or a == "*":
        return None
    try:
        return str(ipaddress.ip_address(a))
    except ValueError:
        return None


def _norm_port(text):
    # '*' u `ss` znamena "lubovolny", v pamati je to nula
    t = text.strip()
    if t in ("*", ""):
        return 0
    try:
        return int(t)
    except ValueError:
        return None


def read_ss(path):
    """
    `ss -tuanp` -> mnozina n-tic (proto, saddr, sport, daddr, dport).

    Riadky, ktore sa nedaju rozobrat (iny netid, chybajuci port), sa vracaju
    zvlast - zahodit ich potichu by nafuklo zhodu.
    """
    rows, skipped = set(), []
    with open(path, errors="replace") as fh:
        for ln in fh:
            parts = ln.split()
            if len(parts) < 6 or parts[0] == "Netid":
                continue
            proto = parts[0].upper()
            if proto not in ("TCP", "UDP"):
                skipped.append(ln.rstrip())
                continue
            local, peer = parts[4], parts[5]
            sa, _, sp = local.rpartition(":")
            da, _, dp = peer.rpartition(":")
            key = (proto, _norm_addr(sa), _norm_port(sp),
                   _norm_addr(da), _norm_port(dp))
            if None in key:
                skipped.append(ln.rstrip())
                continue
            rows.add(key)
    return rows, skipped


# ------------------------------------------------------------- porovnania


def _name_match(snapshot_comm, gt_name):
    """
    Zhoda mena procesu. Vracia (bool, pravidlo).
      exact    - retazce su totozne
      truncated- `ps` tlaci dlhsie meno, comm je jeho prvych 15 znakov
      worker   - `ps` pripaja popis pracovneho vlakna ("kworker/0:0H-events...")
    """
    if snapshot_comm == gt_name:
        return True, "exact"
    if gt_name[:COMM_LEN] == snapshot_comm:
        return True, "truncated"
    if snapshot_comm and gt_name.startswith(snapshot_comm + "-"):
        return True, "worker"
    return False, None


def compare_processes(snap_procs, before, after):
    """
    Stabilna mnozina = pid pritomny v oboch behoch `ps`, teda proces, ktory
    bezal cez cele okno odberu. Meno sa porovnava proti OBOM behom: `ps`
    dopisuje pracovnym vlaknam popis aktualnej prace ("kworker/1:0-events" vs.
    "kworker/1:0-mm_percpu_wq") a ten sa medzi dvoma behmi bezne zmeni, hoci
    comm v pamati je po cely cas rovnake. Kolko pidov malo v oboch behoch
    doslovne to iste meno, hlasi 'stable_name_identical'.
    """
    stable = {pid: (nm, after[pid]) for pid, nm in before.items()
              if pid in after}
    identical = sum(1 for a, b in stable.values() if a == b)
    snap = {}
    duplicates = []
    for p in snap_procs:
        if p["pid"] in snap:
            duplicates.append(p["pid"])
        snap[p["pid"]] = p["comm"]

    found, missing, mismatch, rules = [], [], [], {}
    for pid, names in sorted(stable.items()):
        if pid not in snap:
            missing.append({"pid": pid, "ps_before": names[0],
                            "ps_after": names[1]})
            continue
        found.append(pid)
        hit = None
        for nm in names:
            ok, rule = _name_match(snap[pid], nm)
            if ok and (hit is None or rule == "exact"):
                hit = rule
        if hit is None:
            mismatch.append({"pid": pid, "ps_before": names[0],
                             "ps_after": names[1], "snapshot": snap[pid]})
        else:
            rules[hit] = rules.get(hit, 0) + 1

    known = set(before) | set(after)
    false_pos = [{"pid": pid, "comm": snap[pid]}
                 for pid in sorted(set(snap) - known)]
    return {
        "ps_before": len(before),
        "ps_after": len(after),
        "stable": len(stable),
        "stable_name_identical": identical,
        "snapshot": len(snap),
        "found": len(found),
        "missing": len(missing),
        "false_positive": len(false_pos),
        "name_mismatch": len(mismatch),
        "recall_percent": round(100.0 * len(found) / len(stable), 1)
                          if stable else None,
        "name_match_rules": rules,
        "duplicate_pids": duplicates,
        "missing_list": missing,
        "false_positive_list": false_pos,
        "name_mismatch_list": mismatch,
    }


def compare_modules(snap_mods, gt_names):
    snap = {m["name"] for m in snap_mods}
    return {
        "ground_truth": len(gt_names),
        "snapshot": len(snap),
        "matched": len(snap & gt_names),
        "missing": len(gt_names - snap),
        "extra": len(snap - gt_names),
        "missing_list": sorted(gt_names - snap),
        "extra_list": sorted(snap - gt_names),
    }


def _sock(key):
    proto, saddr, sport, daddr, dport = key
    return {"proto": proto, "saddr": saddr, "sport": sport,
            "daddr": daddr, "dport": dport}


def compare_sockets(snap_sockets, gt_rows, gt_skipped):
    snap = set()
    other_proto = {}
    for s in snap_sockets:
        if s["proto"] not in ("TCP", "UDP"):
            # `ss -tuanp` vidi len TCP a UDP; RAW socket teda nema s cim
            # porovnat a do 'extra' by sa zaratal ako chyba, ktorou nie je
            other_proto[s["proto"]] = other_proto.get(s["proto"], 0) + 1
            continue
        snap.add((s["proto"], s["saddr"], s["sport"], s["daddr"], s["dport"]))
    return {
        "ground_truth": len(gt_rows),
        "snapshot_tcp_udp": len(snap),
        "snapshot_other_protocols": other_proto,
        "matched": len(snap & gt_rows),
        "missing": len(gt_rows - snap),
        "extra": len(snap - gt_rows),
        "ground_truth_unparsed": len(gt_skipped),
        "missing_list": [_sock(k) for k in sorted(gt_rows - snap)],
        "extra_list": [_sock(k) for k in sorted(snap - gt_rows)],
    }


# --------------------------------------------------------------- vstup CLI


def _stamp(path):
    return {"path": os.path.abspath(path),
            "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(os.path.getmtime(path)))}


def run(args, view):
    """Vstupna funkcia pre 'python3 -m guestparse validate' (viz cli.py)."""
    procs = view.processes()
    mods = view.modules()
    socks = view.sockets(procs=procs["processes"])
    checks = check_all(view, procs=procs, mods=mods)

    before = read_ps(args.ps_before)
    after = read_ps(args.ps_after)
    gt = {"ps_before": _stamp(args.ps_before), "ps_after": _stamp(args.ps_after)}

    out = {
        "schema": "hyptcn3/guestparse-validate/1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "snapshot": {
            "path": os.path.abspath(args.snapshot),
            "files": [os.path.basename(p) for p in view.img.paths],
            "pages_present": view.img.page_count(),
            "kernel": view.banner,
            "ktext_shift": view.ktext_shift,
        },
        "profile": os.path.abspath(args.profile),
        "ground_truth": gt,
        "traversal": {
            "processes_truncated": procs["truncated"],
            "processes_stop_reason": procs["stop_reason"],
            "modules_truncated": mods["truncated"],
            "modules_stop_reason": mods["stop_reason"],
            "sockets_truncated": socks["truncated"],
            "sockets_skipped_tasks": socks.get("skipped_tasks"),
        },
        "processes": compare_processes(procs["processes"], before, after),
        "checks": checks["summary"],
    }

    if args.lsmod:
        gt["lsmod"] = _stamp(args.lsmod)
        out["modules"] = compare_modules(mods["modules"], read_lsmod(args.lsmod))
    else:
        out["modules"] = {"compared": False,
                          "reason": "bez --lsmod nie je s cim porovnat",
                          "snapshot": len(mods["modules"])}
    if args.ss:
        gt["ss"] = _stamp(args.ss)
        rows, skipped = read_ss(args.ss)
        out["sockets"] = compare_sockets(socks["sockets"], rows, skipped)
    else:
        out["sockets"] = {"compared": False,
                          "reason": "bez --ss nie je s cim porovnat",
                          "snapshot": len(socks["sockets"])}
    return out
