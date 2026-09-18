"""
Kontroly integrity nad jednou snimkou.

PRECO tieto tri a nie "detekcia malveru": zo samotnej pamate sa da overit
len to, co ma jadro invariantne dane. Kazda kontrola nizsie porovnava dva
zdroje, ktore musia sediet, a nalez je ich rozdiel - nie skore, nie odhad.

  (a) sys_call_table  - kazda polozka musi ukazovat do [_stext, _etext).
      Handler prepisany na kod v oblasti modulov je klasicky hook; rozsah
      textu jadra je pevny a je v kallsyms, takze kontrola nema volny
      parameter.
  (b) procesy krizovo - zoznam init_task.tasks proti stromu potomkov
      (children/sibling). Su to dve NEZAVISLE spojkove struktury toho isteho
      task_struct; rootkit, ktory odpoji uzol z jednej, musi odpojit aj druhu,
      inak vznikne rozdiel.
  (c) moduly krizovo  - zoznam `modules` proti kobjektom v module_kset
      (to, co vidno ako /sys/module). Plus meno modulu ako tlacitelny retazec
      a adresa struct module v oblasti modulov.

Snimka je ziva (VM sa nezastavuje), takze prechod zoznamu sa moze roztrhnut.
Kazda kontrola preto hlasi 'conclusive': ked je niektory prechod neuplny,
rozdiel dvoch zoznamov nie je dokaz skryvania a nesmie sa tak citat.
"""

import bisect

from .profile import btf_offsets

# oblast modulov na x86_64: MODULES_VADDR .. MODULES_END (arch/x86/mm/...)
MODULES_VADDR = 0xFFFFFFFFC0000000
MODULES_END = 0xFFFFFFFFFF000000

# Struktury, ktore potrebuje iba krizova kontrola modulov - v zakladnom
# profile nie su, aby si ich nemusel platit kazdy prikaz.
SYSFS_STRUCTS = ("kset", "kobject", "module_kobject")


# --------------------------------------------------------------- pomocne


def _symtab(prof):
    """Zoradene pole adries pre spatne hladanie mena k adrese."""
    tab = getattr(prof, "_checks_symtab", None)
    if tab is None:
        pairs = sorted((a, n) for n, a in prof.sym.items())
        tab = ([a for a, _ in pairs], [n for _, n in pairs])
        prof._checks_symtab = tab
    return tab


# Nad tento posun uz "najblizsi symbol" nic nehovori: adresa lezi v diere
# medzi obrazom jadra a modulmi, teda nepatri ziadnemu symbolu z kallsyms.
NEAREST_MAX_OFFSET = 1 << 20


def _nearest(prof, addr):
    """Meno symbolu, do ktoreho adresa spada, a posun v nom (inak None, None)."""
    addrs, names = _symtab(prof)
    i = bisect.bisect_right(addrs, addr) - 1
    if i < 0 or addr - addrs[i] > NEAREST_MAX_OFFSET:
        return None, None
    return names[i], addr - addrs[i]


def _sysfs_offsets(prof):
    """Offsety kset/kobject/module_kobject; None ked ich BTF nema."""
    cached = getattr(prof, "_checks_sysfs_off", "miss")
    if cached != "miss":
        return cached
    # btf_offsets si vypis BTF drzi v cache, takze druhe citanie nestoji nic
    off = btf_offsets(prof.btf_path, set(SYSFS_STRUCTS))
    if any(s not in off for s in SYSFS_STRUCTS):
        off = None
    prof._checks_sysfs_off = off
    return off


def _finding(check, detail):
    out = {"check": check}
    out.update(detail)
    return out


# ------------------------------------------------- (a) tabulka volani jadra


def _table_length(prof, table_va):
    """
    Pocet poloziek tabulky. Dlzka sa neberie z hlavickovych suborov ani sa
    nehada z konstanty __NR_syscalls - odvodi sa zo vzdialenosti k najblizsiemu
    dalsiemu symbolu v kallsyms. Zarovnavacia vypln na konci sa odstrihne az
    podla obsahu (nulove polozky); hook je nenulovy ukazovatel, takze sa
    odstrihnut nemoze.
    """
    addrs, _ = _symtab(prof)
    i = bisect.bisect_right(addrs, table_va)
    while i < len(addrs) and addrs[i] == table_va:
        i += 1
    if i >= len(addrs):
        return None
    span = addrs[i] - table_va
    return span // 8 if span > 0 else None


def syscall_table(view, name="sys_call_table"):
    """
    Kontrola jednej tabulky volani jadra: kazda polozka musi ukazovat do
    rozsahu textu jadra [_stext, _etext).
    """
    prof = view.p
    res = {"name": name, "available": False, "reason": None,
           "entries": 0, "findings": []}
    table_va = prof.addr(name)
    stext = prof.addr("_stext")
    etext = prof.addr("_etext")
    if table_va is None:
        res["reason"] = "profil nema symbol %s" % name
        return res
    if stext is None or etext is None:
        res["reason"] = "profil nema _stext/_etext"
        return res
    nr = _table_length(prof, table_va)
    if not nr:
        res["reason"] = "dlzka tabulky sa z kallsyms neda odvodit"
        return res
    pa = view.to_pa(table_va)
    if pa is None:
        res["reason"] = "tabulka sa neda prelozit na fyzicku adresu"
        return res

    raw = [view.u64(pa + i * 8) for i in range(nr)]
    padding = 0
    while raw and not raw[-1]:
        raw.pop()
        padding += 1
    res.update({
        "available": True,
        "table_va": table_va,
        "table_pa": pa,
        "text_range": [stext, etext],
        "entries": len(raw),
        "entries_from_symbol_gap": nr,
        "padding_trimmed": padding,
    })
    for i, val in enumerate(raw):
        if val is not None and stext <= val < etext:
            continue
        sym, delta = _nearest(prof, val) if val else (None, None)
        res["findings"].append(_finding("syscall_table", {
            "table": name,
            "index": i,
            "value": val,
            "nearest_symbol": sym,
            "symbol_offset": delta,
            "in_module_area": bool(val and MODULES_VADDR <= val < MODULES_END),
            "note": "polozka ukazuje mimo [_stext, _etext)",
        }))
    return res


def syscall_tables(view):
    """Vsetky tabulky volani, ktore host ma (32-bitove ABI nemusi mat vobec)."""
    out = []
    for name in ("sys_call_table", "ia32_sys_call_table", "x32_sys_call_table"):
        if view.p.addr(name) is None:
            continue
        out.append(syscall_table(view, name))
    if not out:
        out.append(syscall_table(view))          # vrati dovod, preco to nejde
    return out


# ------------------------------------------------- (b) krizovy pohlad na procesy


def _task_tree(view, limit=8192):
    """
    Druhy pohlad na procesy: prechod stromu potomkov z init_task cez
    children/sibling. Kazdy proces ma rodica az po init_task, takze uplny
    zostup musi dat tu istu mnozinu ako zoznam init_task.tasks.

    Vracia (mapa task_va -> {pid, comm}, dovod prerusenia alebo None).
    """
    o_child = view.p.member("task_struct", "children")
    o_sib = view.p.member("task_struct", "sibling")
    o_pid = view.p.member("task_struct", "pid")
    o_comm = view.p.member("task_struct", "comm")
    if None in (o_child, o_sib, o_pid, o_comm):
        return {}, "profil nema task_struct.children/sibling"
    init_va = view.p.addr("init_task")
    if init_va is None:
        return {}, "profil nema init_task"

    found, stack, stop = {}, [init_va], None
    while stack:
        tva = stack.pop()
        if tva in found:
            continue
        tpa = view.to_pa(tva)
        if tpa is None:
            stop = "task_struct 0x%x sa neda prelozit" % tva
            break
        found[tva] = {
            "pid": view.i32(tpa + o_pid),
            "comm": view.cstr(tpa + o_comm, 16),
        }
        if len(found) > limit:
            stop = "strop %d poloziek" % limit
            break
        head = tva + o_child
        nxt = view.u64(tpa + o_child)
        steps = 0
        while nxt is not None and nxt != head:
            if not view._plausible_va(nxt) or steps > limit:
                stop = "nerozumny ukazovatel v children 0x%x" % (nxt or 0)
                break
            child = nxt - o_sib
            cpa = view.to_pa(child)
            if cpa is None:
                stop = "potomok 0x%x sa neda prelozit" % child
                break
            if child not in found:
                stack.append(child)
            nxt = view.u64(cpa + o_sib)
            steps += 1
        if stop:
            break
    return found, stop


def process_cross_view(view, procs=None):
    """
    Porovna zoznam init_task.tasks so stromom potomkov. Rozdiel je nalez iba
    vtedy, ked sa OBA prechody uzavreli - inak je to roztrhnuty zivy zoznam.

    `procs` je cely vysledok view.processes() (nie len zoznam), aby sa spolu s
    nim preniesol aj priznak 'truncated' - bez neho by sa neuplny prechod dal
    omylom vyhlasit za uzavretu kontrolu.
    """
    res = {"available": False, "conclusive": False, "reason": None,
           "findings": []}
    plist = view.processes() if procs is None else procs
    tree, tree_stop = _task_tree(view)
    if not tree:
        res["reason"] = tree_stop or "strom potomkov je prazdny"
        return res

    init_va = view.p.addr("init_task")
    tree_va = set(tree) - {init_va}      # init_task v zozname `tasks` nie je
    list_va = {p["task_va"]: p for p in plist["processes"]}

    res.update({
        "available": True,
        "list_count": len(list_va),
        "tree_count": len(tree_va),
        "list_truncated": bool(plist["truncated"]),
        "list_stop_reason": plist["stop_reason"],
        "tree_stop_reason": tree_stop,
    })
    res["conclusive"] = not plist["truncated"] and tree_stop is None
    if not res["conclusive"]:
        res["reason"] = ("prechod sa prerusil (zoznam: %s, strom: %s) - "
                         "rozdiel nie je dokaz skryvania"
                         % (plist["stop_reason"], tree_stop))

    for va in sorted(set(list_va) - tree_va):
        p = list_va[va]
        res["findings"].append(_finding("process_cross_view", {
            "task_va": va, "pid": p["pid"], "comm": p["comm"],
            "seen_in": "tasks", "missing_in": "children/sibling",
        }))
    for va in sorted(tree_va - set(list_va)):
        t = tree[va]
        res["findings"].append(_finding("process_cross_view", {
            "task_va": va, "pid": t["pid"], "comm": t["comm"],
            "seen_in": "children/sibling", "missing_in": "tasks",
        }))
    return res


# ------------------------------------------------- (c) moduly


def _sysfs_modules(view):
    """
    Druhy pohlad na moduly: kobjekty v module_kset (to, co je v /sys/module).
    Kset obsahuje aj vstavane moduly s parametrami - tie maju mkobj.mod == NULL
    a do porovnania so zoznamom `modules` nepatria.

    Vracia (mapa struct_module_va -> meno, dovod nedostupnosti alebo None).
    """
    off = _sysfs_offsets(view.p)
    if off is None:
        return None, "BTF nema kset/kobject/module_kobject"
    sym = view.p.addr("module_kset")
    if sym is None:
        return None, "profil nema module_kset"
    o_list = off["kset"]["members"]["list"]
    o_entry = off["kobject"]["members"]["entry"]
    o_name = off["kobject"]["members"]["name"]
    o_kobj = off["module_kobject"]["members"]["kobj"]
    o_mod = off["module_kobject"]["members"]["mod"]

    spa = view.to_pa(sym)
    kset_va = view.u64(spa) if spa is not None else None
    kpa = view.to_pa(kset_va) if view._plausible_va(kset_va) else None
    if kpa is None:
        return None, "module_kset sa neda prelozit"

    head = kset_va + o_list
    nxt = view.u64(kpa + o_list)
    out, seen, unnamed = {}, set(), 0
    while nxt is not None and nxt != head and view._plausible_va(nxt):
        if nxt in seen or len(seen) > 4096:
            return None, "cyklus alebo strop v module_kset"
        seen.add(nxt)
        kobj = nxt - o_entry
        kobj_pa = view.to_pa(kobj)
        if kobj_pa is None:
            return None, "kobject 0x%x sa neda prelozit" % kobj
        mod = view.u64(kobj_pa - o_kobj + o_mod)
        if mod:
            npt = view.u64(kobj_pa + o_name)
            npa = view.to_pa(npt) if view._plausible_va(npt) else None
            name = view.cstr(npa, 64) if npa is not None else ""
            if not name:
                unnamed += 1
            out[mod] = name
        nxt = view.u64(kobj_pa + o_entry)
    return {"modules": out, "kset_entries": len(seen), "unnamed": unnamed}, None


def module_checks(view, mods=None):
    """
    Moduly: meno ako tlacitelny retazec, adresa struct module v oblasti
    modulov a krizove porovnanie so sysfs (module_kset).

    `mods` je cely vysledok view.modules(), z rovnakeho dovodu ako pri procesoch.
    """
    res = {"available": False, "conclusive": False, "reason": None,
           "findings": []}
    mres = view.modules() if mods is None else mods
    res.update({
        "available": True,
        "list_count": len(mres["modules"]),
        "list_truncated": bool(mres["truncated"]),
        "list_stop_reason": mres["stop_reason"],
    })

    for m in mres["modules"]:
        name, va = m["name"], m["module_va"]
        if not (name.isascii() and name.isprintable()):
            res["findings"].append(_finding("module_name", {
                "name": name, "module_va": va,
                "note": "meno modulu nie je tlacitelny ASCII retazec",
            }))
        if not (MODULES_VADDR <= va < MODULES_END):
            res["findings"].append(_finding("module_address", {
                "name": name, "module_va": va,
                "expected_range": [MODULES_VADDR, MODULES_END],
                "note": "struct module nelezi v oblasti modulov",
            }))

    sysfs, why = _sysfs_modules(view)
    if sysfs is None:
        res["sysfs_available"] = False
        res["reason"] = "krizovy pohlad cez sysfs nie je k dispozicii: %s" % why
        return res

    res["sysfs_available"] = True
    res["sysfs_count"] = len(sysfs["modules"])
    res["sysfs_kset_entries"] = sysfs["kset_entries"]
    res["sysfs_unnamed"] = sysfs["unnamed"]
    res["conclusive"] = not mres["truncated"]
    if not res["conclusive"]:
        res["reason"] = ("prechod zoznamu modulov sa prerusil (%s) - rozdiel "
                         "nie je dokaz skryvania" % mres["stop_reason"])

    by_va = {m["module_va"]: m["name"] for m in mres["modules"]}
    for va in sorted(set(by_va) - set(sysfs["modules"])):
        res["findings"].append(_finding("module_cross_view", {
            "module_va": va, "name": by_va[va],
            "seen_in": "modules", "missing_in": "module_kset",
        }))
    for va in sorted(set(sysfs["modules"]) - set(by_va)):
        res["findings"].append(_finding("module_cross_view", {
            "module_va": va, "name": sysfs["modules"][va],
            "seen_in": "module_kset", "missing_in": "modules",
        }))
    # rozdiel mien pri rovnakom struct module by znamenal prepisane meno
    for va, nm in sysfs["modules"].items():
        if va in by_va and nm and by_va[va] != nm:
            res["findings"].append(_finding("module_name_mismatch", {
                "module_va": va, "modules_name": by_va[va], "sysfs_name": nm,
            }))
    return res


# --------------------------------------------------------------- spolu


def check_all(view, procs=None, mods=None):
    """
    Vsetky kontroly nad jednou snimkou; vracia slovnik na vypis aj do JSON.

    `procs` a `mods` su cele vysledky view.processes() a view.modules() -
    daju sa podat, ked ich volajuci uz ma, aby sa snimka nemusela prechadzat
    druhy raz.
    """
    tables = syscall_tables(view)
    proc = process_cross_view(view, procs)
    mod = module_checks(view, mods)

    findings = []
    for t in tables:
        findings.extend(t["findings"])
    findings.extend(proc["findings"])
    findings.extend(mod["findings"])

    hooks = sum(len(t["findings"]) for t in tables)
    return {
        "schema": "hyptcn3/guestparse-checks/1",
        "syscall_tables": tables,
        "process_cross_view": proc,
        "modules": mod,
        "findings": findings,
        "finding_count": len(findings),
        "summary": {
            "syscall_hooks": hooks,
            "syscall_entries_checked": sum(t["entries"] for t in tables),
            "process_cross_view_findings": len(proc["findings"]),
            "module_findings": len(mod["findings"]),
            # kontrola, ktora sa neuzavrela, je "neviem", nie "ciste"
            "inconclusive": sorted(
                n for n, ok in (("syscall_table",
                                 all(t["available"] for t in tables)),
                                ("process_cross_view", proc["conclusive"]),
                                ("modules", mod["conclusive"])) if not ok),
        },
    }


def run(args, view):
    """Vstupna funkcia pre 'python3 -m guestparse checks' (viz cli.py)."""
    return check_all(view)
