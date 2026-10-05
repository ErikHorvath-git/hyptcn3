"""
Kontroly integrity nad jednou snimkou.

PRECO tieto styri a nie "detekcia malveru": zo samotnej pamate sa da overit
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
  (d) text jadra      - obsah stranok [_stext, _etext) proti baseline,
      ktoru si profil drzi z CISTEJ snimky toho isteho bootu. Text sa po
      boote nema menit, takze rozdiel je inline hook alebo iny zapis do
      textu - presne to, co kontrola (a) NEVIDI, ked hook ukazuje do vnutra
      textu. (Zname obmedzenie: jump labels/static keys text naozaj
      prepisuju - rozdiel sa preto hlasi s najblizsim symbolom a hodnoti sa
      v kontexte, pozri docs/kontroly.md.)

Snimka je ziva (VM sa nezastavuje), takze prechod zoznamu sa moze roztrhnut.
Kazda kontrola preto hlasi 'conclusive': ked je niektory prechod neuplny,
rozdiel dvoch zoznamov nie je dokaz skryvania a nesmie sa tak citat. Pri
kontrole (d) 'conclusive' znamena, ze kazda stranka baseline bola v snimke
precitana - chybajuca stranka je 'neviem', nie 'ciste'.
"""

import bisect
import hashlib
import json
import os
import struct

from .profile import btf_offsets
from .view import MODULES_VADDR, START_KERNEL_MAP

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

# ------------------------------------------------- (d) text jadra sa nemeni

TEXT_BASELINE_SCHEMA = "hyptcn3/text-baseline/1"
TEXT_BASELINE_FILE = "text_baseline.json"
PAGE_SIZE = 4096


def _baseline_path(prof):
    return os.path.join(prof.dir, TEXT_BASELINE_FILE)


def load_text_baseline(prof):
    """
    Baseline textu jadra z profilu: zoznam {va, sha256} stranok [_stext,
    _etext) odobraty z cistej snimky. Vrati dict, alebo None, ked ho profil
    nema (starsie profily) - kontrola sa potom prizna ako nedostupna.
    """
    path = _baseline_path(prof)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("schema") != TEXT_BASELINE_SCHEMA:
        raise ValueError("%s: schema %r, cakam %r"
                         % (path, doc.get("schema"), TEXT_BASELINE_SCHEMA))
    return doc


# ---- static keys (jump labels): jedina zname runtime-patch v texte ----
# Pri boote sa do TEXTU jadra patchuju 5-bajtove skoky statickych klucov
# (jump label) podla runtime stavu - preto sa text medzi bootmi lisi presne
# na tychto miestach (docs/kontroly.md). Baseline aj kontrola tieto miesta
# pri hasovani maskuju: zoznam adries dava __jump_table (static data v
# obrazе, preto ju da precitat z kazdej snimky cez profil).
JUMP_ENTRY = 16          # {s32 code; s32 target; u64 key} - 16 B
JUMP_PATCH_LEN = 5       # najdlhsi patch (JMP rel32)

def _jump_sites(view):
    """Zoznam VA patchenych instrukcii statickych klucov, alebo None.

    Cita __jump_table zo SNIMKY (cez profil a preklad VA->PA). Rozlozenie
    zaznamu je merane na jadre 6.1.0-42-cloud-amd64: s32 code a s32 target
    su RELATIVNE voci vlastnej adrese zaznamu, key je u64, zaznam ma 16 B.
    Ked sa tabulka necita zmysluplne, vracia None - maskovanie sa potom
    NESPUSTI a text_integrity hlasi neuzavretost namiesto tichej zhody.
    """
    start = view.p.addr("__start___jump_table")
    stop = view.p.addr("__stop___jump_table")
    if not start or not stop or stop < start:
        return None
    if stop == start:
        return []                 # prazdna tabulka = ziadne patche
    if (stop - start) % JUMP_ENTRY:
        return None
    sites = set()
    for va in range(start, stop, JUMP_ENTRY):
        pa = view.to_pa(va)
        b = view.img.read(pa, 4) if pa is not None else None
        if b is None or len(b) < 4:
            return None
        code32 = int.from_bytes(b, "little")
        if code32 == 0:
            continue
        # s32 relativne: code_addr = adresa_zaznamu + sext(code32)
        code = (va + ((code32 ^ 0x80000000) - 0x80000000)) & 0xFFFFFFFFFFFFFFFF
        if not (START_KERNEL_MAP <= code < MODULES_VADDR):
            return None
        sites.add(code)
    return sorted(sites)

# Alternatives (boot-time CPU-feature patchy): dalsia trieda patchov, ktore
# sa v texte prejavia az PO boote - preto ich baseline z vmlinux-u musi
# maskovat. Tabuľka .altinstructions je STATICKA (rodata) a jej instr_offset
# su relativne -> cita sa priamo zo suboru vmlinux, bez potreby citat ju zo
# snimky (layout runtime tabulky sa pri niektorych jadrach lisi od sekcie v
# subore, napr. pri PE/stripped image - preto subor ako jediny zdroj).
ALT_ENTRY = 12


def _alt_masky_z_vmlinux(data):
    """[(rel_offset_v_text, dlzka_patchu)] zo sekcie .altinstructions."""
    secs = {s["meno"]: s for s in _elf_sekcie(data)}
    text = secs.get(".text")
    alt = secs.get(".altinstructions")
    if text is None or alt is None or alt["size"] % ALT_ENTRY:
        raise ValueError("vmlinux nema citatelne .altinstructions")
    stext_file = text["addr"]          # _stext == .text vaddr (overene)
    out = []
    for i in range(alt["size"] // ALT_ENTRY):
        b = data[alt["off"] + i * ALT_ENTRY:alt["off"] + i * ALT_ENTRY + 12]
        instr32 = struct.unpack("<i", b[0:4])[0]
        instrlen = b[10]
        va = (alt["addr"] + i * ALT_ENTRY + instr32) & 0xFFFFFFFFFFFFFFFF
        rel = va - stext_file
        if 0 <= rel < text["size"] and 0 < instrlen <= 16:
            out.append([rel, instrlen])
    out.sort()
    return out


# Static calls: dalsia trieda boot-patchov - miesta v texte sa prepisuju
# priamym volanim/retpoline podla kluca (runtime stav). Sekcia
# .static_call_sites ma zaznamy {s32 addr; s32 key} (8 B), addr je
# RELATIVNY k zaznamu; plus rezervovany usek __static_call_text_start..end.
STATIC_CALL_ENTRY = 8


def _static_call_sites(view):
    """Zoznam VA patchenych static-call miest z __start_static_call_sites
    SNIMKY (zaznam {s32 addr rel; s32 key}, 8 B). Sekcia v subore vmlinux
    pri tomto jadre nie je, preto snimka (tabula je v rodata, staticka)."""
    start = view.p.addr("__start_static_call_sites")
    stop = view.p.addr("__stop_static_call_sites")
    if not start or not stop or stop < start:
        return None
    if stop == start:
        return []
    if (stop - start) % STATIC_CALL_ENTRY:
        return None
    sites = set()
    for va in range(start, stop, STATIC_CALL_ENTRY):
        pa = view.to_pa(va)
        b = view.img.read(pa, 4) if pa is not None else None
        if b is None or len(b) < 4:
            return None
        addr32 = int.from_bytes(b, "little")
        addr = (va + ((addr32 ^ 0x80000000) - 0x80000000)) & 0xFFFFFFFFFFFFFFFF
        if not (START_KERNEL_MAP <= addr < MODULES_VADDR):
            return None
        sites.add(addr)
    return sorted(sites)


def _mask_rel(view, sites):
    """Relativne offsety patchenych miest voci _stext (boot-independent)."""
    stext = view.p.addr("_stext")
    etext = view.p.addr("_etext")
    out = []
    for va in sites:
        if stext <= va < etext:
            off = va - stext
            ln = min(JUMP_PATCH_LEN, PAGE_SIZE - (off % PAGE_SIZE))
            out.append([off, ln])
    return out

def _hash_masked(view, pa, mask):
    """SHA-256 stranky s vynulovanymi patchovanymi miestami (mask)."""
    b = bytearray(view.img.read(pa, PAGE_SIZE))
    for off, ln in mask.get(pa, ()):
        for i in range(off, min(off + ln, PAGE_SIZE)):
            b[i] = 0
    return hashlib.sha256(bytes(b)).hexdigest()

def _mask_by_pa(view, mask_rel):
    """{pa_stranky: [(offset_v_stranke, dlzka)]} z relativnych offsetov."""
    stext = view.p.addr("_stext")
    out = {}
    for off, ln in mask_rel:
        va = stext + off
        pa = view.to_pa(va)
        if pa is not None:
            out.setdefault(pa - (pa % PAGE_SIZE), []).append((va % PAGE_SIZE,
                                                              ln))
    return out


# ---- vmlinux (linkovany obraz) ako referencny obsah textu ----
# Text jadra sa medzi bootmi lisi na miestach, ktore boot patchuje:
#   - static keys (jump labels): __jump_table (maskuje sa z runtime tabulky)
#   - absolutne relokacie (R_X86_64_64/32/32S): hodnoty zavisia od KASLR
#     slidu - ich zoznam je binarno konstantny, cita sa z .rela sekcii
#     vmlinux-u (linkovane VAs su v subore, offsety voci _stext su rovnake
#     ako v runtime)
# Baseline z vmlinux-u preto NEPOTREBUJE cistu snimku z kazdeho bootu a je
# silnejsia nez baseline zo snimky (kontroluje sa priamo linkovany obsah).

R_X86_64_NONE = 0
R_X86_64_64 = 1
R_X86_64_PC32 = 2
R_X86_64_32 = 10
R_X86_64_32S = 11
# absolutne typy -> dlzka patchenych bajtov (PC32/PLT32 su slide-invariant)
RELA_ABS = {R_X86_64_64: 8, R_X86_64_32: 4, R_X86_64_32S: 4}
SHT_RELA = 4


def _elf_hlavicka(data):
    """(e_shoff, e_shentsize, e_shnum, e_shstrndx) - len zakladne polia."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("vmlinux nie je ELF64")
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize = struct.unpack("<H", data[0x3A:0x3C])[0]
    e_shnum = struct.unpack("<H", data[0x3C:0x3E])[0]
    e_shstrndx = struct.unpack("<H", data[0x3E:0x40])[0]
    return (e_shoff, e_shentsize, e_shnum, e_shstrndx)


def _elf_sekcie(data):
    shoff, shentsize, shnum, shstrndx = _elf_hlavicka(data)
    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        name, typ, flags, addr, off, size, link, info, align, entsz = \
            struct.unpack("<IIQQQQIIQQ", data[o:o + 64])
        secs.append({"i": i, "name": name, "typ": typ, "addr": addr,
                     "off": off, "size": size, "link": link, "info": info})
    strtab = secs[shstrndx]
    stab = data[strtab["off"]:strtab["off"] + strtab["size"]]
    for s in secs:
        b = stab[s["name"]:]
        s["meno"] = b.split(b"\0")[0].decode("ascii", "replace")
    return secs


def _relokacne_masky(data, text_i, text_addr, text_size):
    """Relativne offsety (voci _stext) absolutnych relokacii v .text."""
    secs = _elf_sekcie(data)
    out = []
    for s in secs:
        if s["typ"] != SHT_RELA or s["info"] != text_i:
            continue
        n = s["size"] // 24
        for j in range(n):
            o = s["off"] + j * 24
            r_off, r_info = struct.unpack("<QQ", data[o:o + 16])
            typ = r_info & 0xFFFFFFFF
            if typ in RELA_ABS:
                rel = r_off - text_addr
                if 0 <= rel < text_size:
                    out.append([rel, RELA_ABS[typ]])
    out.sort()
    return out


def _vmlinux_text_a_masky(view, vmlinux_path):
    """(data, text_off, n_stranok, mask_relok) z LINKOVANEHO vmlinux-u.

    Obsah textu sa NEhashuje tu - hash musi ist cez ROVNAKU masku ako
    kontrola, preto sa vracia surovy subor + offset .text.
    """
    with open(vmlinux_path, "rb") as fh:
        data = fh.read()
    secs = _elf_sekcie(data)
    by_name = {s["meno"]: s for s in secs}
    text = by_name.get(".text")
    if text is None:
        raise ValueError("vmlinux nema sekciu .text")
    stext = view.p.addr("_stext")
    etext = view.p.addr("_etext")
    if stext is None or etext is None:
        raise ValueError("profil nema _stext/_etext")
    # _stext je prvy symbol .text (0xffffffff81000000) - offsety voci nemu
    # su v subore rovnake ako v runtime
    n_stranok = (etext - stext) // PAGE_SIZE
    if text["off"] + n_stranok * PAGE_SIZE > len(data):
        raise ValueError("vmlinux ma .text kratsi nez profilovy rozsah")
    masky = _relokacne_masky(data, text["i"], text["addr"], text["size"])
    return data, text["off"], n_stranok, masky


def build_text_baseline(view, vmlinux_path=None):
    """
    Baseline textu jadra: SHA-256 kazdej stranky [_stext, _etext).

    Dva zdroje obsahu:
      - vmlinux_path: LINKOVANY obraz (najsilnejsi) - obsah ide zo suboru,
        nepotrebuje ziadnu "cistu" snimku; snimka sluzi len na runtime
        tabulky static keys (__jump_table). Maskuju sa aj absolutne
        relokacie zo suboru (R_X86_64_64/32/32S - ich hodnoty zavisia od
        KASLR slidu).
      - bez vmlinux_path: z CISTEJ snimky (stare spravanie). Odmietne
        neuplnu snimku: baseline, ktorej cast chyba, by kontrolu umelo
        zuzila a hook v chybajucej stranke by nevidela - preto sa neda
        vyrobit z polovicnej snimky a hovori to chybou, nie tichym
        orezanim.
    """
    prof = view.p
    stext = prof.addr("_stext")
    etext = prof.addr("_etext")
    if stext is None or etext is None:
        raise ValueError("profil nema _stext/_etext")
    if stext % PAGE_SIZE:
        raise ValueError("_stext 0x%x nie je zarovnany na stranku" % stext)
    if etext <= stext:
        raise ValueError("prazdny rozsah textu jadra")

    # 1) uplnost: kazda stranka textu musi byt v snimke (inak by baseline
    # ticho kontrolu zuzila). Citanie vracia za chybajucu stranku NULY,
    # preto sa pritomnost zistuje zvlast.
    pages_raw, missing = [], 0
    has_pp = hasattr(view.img, "page_present")
    for va in range(stext, etext, PAGE_SIZE):
        pa = view.to_pa(va)
        if pa is None or (has_pp and not view.img.page_present(pa)):
            missing += 1
            continue
        b = view.img.read(pa, PAGE_SIZE)
        if b is None or len(b) < PAGE_SIZE:
            missing += 1
            continue
        pages_raw.append((va, pa))
    if missing:
        raise ValueError(
            "%d z %d stranok textu v snimke nie je; baseline sa da vyrobit "
            "len z uplnej snimky tohto bootu" % (missing,
                                                 (etext - stext) // PAGE_SIZE))

    # 2) maskovanie boot-VARIANTNYCH miest: static keys (jump labels),
    # absolutne relokacie (KASLR slide), alternative a static calls. Bez
    # nich by sa baseline lisila medzi bootmi aj bez hooku. Obsah ide zo
    # SNIMKY (ma uz vsetky boot-INVARIANTNE patche - tie medzi bootmi sedia),
    # maskuju sa len miesta, ktore sa medzi bootmi LEGITIMNE lisia.
    sites = _jump_sites(view)
    if sites is None:
        raise ValueError("__jump_table sa zo snimky necita zmysluplne - "
                         "baseline bez maskovania statickych klucov by bola "
                         "chybna")
    mask_rel = _mask_rel(view, sites)
    mask_extra = {}
    mask_jump = list(mask_rel)
    if vmlinux_path:
        with open(vmlinux_path, "rb") as fh:
            data = fh.read()
        mask_extra["relok"] = _vmlinux_text_a_masky(view, vmlinux_path)[3]
        mask_extra["alt"] = _alt_masky_z_vmlinux(data)
        sc = _static_call_sites(view)
        if sc is None:
            raise ValueError("static-call tabulka sa zo snimky necita")
        mask_extra["sc"] = [[va - stext, 5] for va in sc
                            if stext <= va < etext]
        for m in mask_extra.values():
            mask_rel.extend(m)
        mask_rel.sort()
    mask = _mask_by_pa(view, mask_rel)

    pages = [{"va": va, "sha256": _hash_masked(view, pa, mask)}
             for va, pa in pages_raw]
    boot_id = (prof.meta or {}).get("boot_id")
    return {
        "schema": TEXT_BASELINE_SCHEMA,
        "zdroj": "snimka",
        "mask_rel": mask_rel,
        "mask_sites": len(sites),
        "mask_jump_pocet": len(mask_jump),
        "mask_extra": {k: len(v) for k, v in mask_extra.items()},
        "mask_poznamka": ("relativne offsety static-key patchov voci _stext; "
                          "pri hasovani sa tieto 5-bajtove miesta maskuju, "
                          "lebo sa pri boote patchuju podla runtime stavu "
                          "(docs/kontroly.md)"),
        "page_size": PAGE_SIZE,
        "stext": stext,
        "etext": etext,
        "boot_id": boot_id,
        "pages": pages,
    }


def text_integrity(view, baseline=None):
    """
    Porovna obsah textu jadra v snimke s baseline z profilu (cista snimka
    toho isteho bootu). Kazda stranka, ktora sa lisi, je nalez - text sa po
    boote nesmie menit a rozdiel znamena zapis do textu (inline hook).

    `conclusive` = kazda stranka baseline bola precitana. Chybajuce stranky
    sa neohlasuju ako ciste: je to 'neviem' (pozri modulovu hlavicku).
    """
    res = {"available": False, "conclusive": False, "reason": None,
           "pages_total": 0, "pages_checked": 0, "pages_missing": 0,
           "findings": []}
    if baseline is None:
        baseline = load_text_baseline(view.p)
    if not baseline:
        res["reason"] = (
            "profil nema %s (baseline z cistej snimky); vyrob ho prikazom "
            "'python3 -m guestparse textbaseline --snapshot <cista> "
            "--profile <profil>'" % TEXT_BASELINE_FILE)
        return res

    stext = view.p.addr("_stext")
    etext = view.p.addr("_etext")
    # Baseline je na OBSAH textu, nie na boot: po preukotveni (A2) sa jej
    # virtualne adresy posunu o rovnaky rozdiel ako profil. Rozsah teda
    # musi sediet az PO posune - inak je baseline z ineho JADRA.
    delta = getattr(view, "reanchored", 0)
    if (baseline.get("stext", 0) + delta != stext or
            baseline.get("etext", 0) + delta != etext):
        res["reason"] = ("baseline textu nesedi s profilom ani po posune o "
                         "KASLR rozdiel (ine jadro); obnov ju nad cistou "
                         "snimkou")
        return res

    # static keys: maskovane miesta musi dat rovnako aj tabulka TEJTO
    # snimky (pocet in-text patchov) - inak je jadro ine a maskovanie by
    # klamalo
    sites = _jump_sites(view)
    mask_rel = baseline.get("mask_rel")
    if sites is None:
        res["reason"] = ("__jump_table sa zo snimky necita - maskovanie "
                         "static keys sa neda overit, 4. kontrola je "
                         "neuzavreta")
        return res
    n_rel = sum(1 for va in sites if stext <= va < etext)
    ocakavane = baseline.get("mask_jump_pocet", len(mask_rel or []))
    if mask_rel is None or n_rel != ocakavane:
        res["reason"] = ("jump tabulka snimky (%d patchov v texte) nesedi s "
                         "baseline (%s) - ine jadro; obnov baseline"
                         % (n_rel, ocakavane))
        return res
    mask = _mask_by_pa(view, mask_rel)

    pages = baseline.get("pages") or []
    res["pages_total"] = len(pages)
    has_pp = hasattr(view.img, "page_present")
    for pg in pages:
        pa = view.to_pa(pg["va"] + delta)
        if pa is None or (has_pp and not view.img.page_present(pa)):
            res["pages_missing"] += 1
            continue
        b = view.img.read(pa, PAGE_SIZE)
        if b is None or len(b) < PAGE_SIZE:
            res["pages_missing"] += 1
            continue
        res["pages_checked"] += 1
        sha = _hash_masked(view, pa, mask)
        if sha != pg["sha256"]:
            sym, d = _nearest(view.p, pg["va"] + delta)
            res["findings"].append(_finding("text_integrity", {
                "va": pg["va"] + delta,
                "baseline_va": pg["va"],
                "nearest_symbol": sym,
                "symbol_offset": d,
                "note": ("obsah textu jadra na tejto stranke sa lisi od "
                         "cistej snimky (baseline)"),
            }))
    res["available"] = True
    res["conclusive"] = res["pages_missing"] == 0
    if not res["conclusive"]:
        res["reason"] = ("%d z %d stranok textu v snimke nie je - nula "
                         "nalezov nic nedokazuje"
                         % (res["pages_missing"], res["pages_total"]))
    return res


def check_all(view, procs=None, mods=None, text_baseline=None):
    """
    Vsetky kontroly nad jednou snimkou; vracia slovnik na vypis aj do JSON.

    `procs` a `mods` su cele vysledky view.processes() a view.modules() -
    daju sa podat, ked ich volajuci uz ma, aby sa snimka nemusela prechadzat
    druhy raz. `text_baseline` je baseline textu jadra (default: z profilu).
    """
    tables = syscall_tables(view)
    proc = process_cross_view(view, procs)
    mod = module_checks(view, mods)
    text = text_integrity(view, text_baseline)

    findings = []
    for t in tables:
        findings.extend(t["findings"])
    findings.extend(proc["findings"])
    findings.extend(mod["findings"])
    findings.extend(text["findings"])

    hooks = sum(len(t["findings"]) for t in tables)
    return {
        "schema": "hyptcn3/guestparse-checks/1",
        "syscall_tables": tables,
        "process_cross_view": proc,
        "modules": mod,
        "text_integrity": text,
        "findings": findings,
        "finding_count": len(findings),
        "summary": {
            "syscall_hooks": hooks,
            "syscall_entries_checked": sum(t["entries"] for t in tables),
            "process_cross_view_findings": len(proc["findings"]),
            "module_findings": len(mod["findings"]),
            "text_integrity_findings": len(text["findings"]),
            # kontrola, ktora sa neuzavrela, je "neviem", nie "ciste"
            "inconclusive": sorted(
                n for n, ok in (("syscall_table",
                                 all(t["available"] for t in tables)),
                                ("process_cross_view", proc["conclusive"]),
                                ("modules", mod["conclusive"]),
                                ("text_integrity", text["conclusive"])) if not ok),
        },
    }


def run(args, view):
    """Vstupna funkcia pre 'python3 -m guestparse checks' (viz cli.py)."""
    return check_all(view)
