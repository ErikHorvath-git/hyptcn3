"""
procmap.py - blok A4: ktoremu procesu patria zmenene stranky binu.

Alarm ma povedat "ktory proces", nie len "ktora oblast". Tento modul prejde
cele uzivatelske tabulky stranok kazdeho procesu (koren = mm->pgd, prelozeny
cez to_pa) a kazdej pritomnej uzivatelskej stranke priradi jej proces.
Zmenene stranky binu (zo zaznamov poslednej casti retazca) sa potom priradia:
stranka v ziadnej uzivatelskej mape = jadro/nezmapovane.

PRECO CELE TABULKY A NIE ZOZNAM VMA: mm_struct.mmap ani vm_area_struct.vm_next
v BTF tohto jadra (Debian 6.1.159, maple tree) NIE SU - klasicky prechod cez
VMA zoznam by na nom nefungoval. Zostup cez tabulky je navyse nezavisly od
verzie jadra (staci mm->pgd, ktory v BTF je) a vidi presne to, co proces
naozaj mapuje.

PRIZNANE OBMEDZENIA
-------------------
- mapa sa stavia nad JEDNOU snimkou; cena je jedna read() na celu tabulku
  (4 KiB) na pritomnu polozku - meria sa a je vo vysledku (cas_s). Pri alarme
  to patri do pracovneho vlakna mimo periody zberu (hooks.c: hook bezi
  synchronne);
- zdielana stranka (mmap) sa priradi prvemu procesu, ktory ju ma
  v mape - pri viacnasobnom zdielani je to spodna hranica informacie;
- funguje len pre 4-urovnove tabulky (x86_64 bez LA57), rovnako ako
  zvysok guestparse.
"""

import struct
import time

from .image import VMICD_HDR, VmicdImage

PAGE = 4096
ENTRY_MASK = 0x000FFFFFFFFFF000
PTE_PRESENT = 1
PTE_PSE = 1 << 7


def changed_pages_of_last_part(img):
    """
    Indexy stranok zapisanych v POSLEDNEJ casti retazca - to su presne
    stranky zmenene oproti predchadzajucej snimke (pri jednej plnej snimke
    = vsetky nenulove stranky). Vracia set.
    """
    hdr = VmicdImage.header(img.headers[-1]["path"])
    idxs = set()
    psz = hdr["page_size"]
    with open(img.headers[-1]["path"], "rb") as f:
        off = VMICD_HDR
        for _ in range(hdr["records"]):
            f.seek(off)
            raw = f.read(8)
            if len(raw) != 8:
                break
            idxs.add(struct.unpack("<Q", raw)[0])
            off += 8 + psz
    return idxs


def _table(view, pa):
    """Cela 4 KiB tabulka ako 512 u64 (jedno citanie; None ked v snimke nie je)."""
    b = view.img.read(pa, PAGE)
    if b is None or len(b) < PAGE:
        return None
    return struct.unpack("<512Q", b)


def walk_user_pages(view, root_pa, out, limit_pages):
    """
    Zostup celymi uzivatelskymi tabulkami z mm->pgd. Vracia True, ked sa
    dosiahol strop limit_pages (mapa je dolna hranica, nie tichy orez).

    Velke stranky (1 GiB na PUD, 2 MiB na PMD) sa rozpisu na jednotlive
    4 KiB stranky - rovnaka granularita, aku ma delta zber.
    """
    stack = [(root_pa, 0)]          # (tabulka, uroven 0=PGD .. 3=PTE)
    while stack:
        tbl, lvl = stack.pop()
        entries = _table(view, tbl)
        if entries is None:
            continue
        for e in entries:
            if not (e & PTE_PRESENT):
                continue
            phys = e & ENTRY_MASK
            if lvl == 3:                              # PTE -> stranka
                out.setdefault(phys, True)
                if len(out) >= limit_pages:
                    return True
            elif lvl == 1 and (e & PTE_PSE):          # PUD: 1 GiB stranka
                for i in range(1 << 18):              # 262144 stranok
                    out.setdefault(phys + i * PAGE, True)
                    if len(out) >= limit_pages:
                        return True
            elif lvl == 2 and (e & PTE_PSE):          # PMD: 2 MiB stranka
                for i in range(512):
                    out.setdefault(phys + i * PAGE, True)
                    if len(out) >= limit_pages:
                        return True
            elif lvl < 3:
                stack.append((phys, lvl + 1))
    return False


def process_mappings(view, procs=None, limit_pages=300000):
    """
    {pa_stranky: (pid, comm)} pre vsetky pouzivatelske mapovania procesov.
    Vracia (mapa, capped); capped = dosiahol sa strop limit_pages (mapa je
    dolna hranica). Prva zhodna stranka vyhrava (pozri hlavicku modulu).
    """
    o_mm = view.p.member("task_struct", "mm")
    o_pgd = view.p.member("mm_struct", "pgd")
    if o_mm is None or o_pgd is None:
        raise ValueError("profil nema offsety task_struct.mm/mm_struct.pgd")

    if procs is None:
        procs = view.processes()
    out = {}
    capped = False
    for p in procs["processes"]:
        if p.get("kernel_thread"):
            continue
        tpa = view.to_pa(p["task_va"])
        if tpa is None:
            continue
        mm = view.u64(tpa + o_mm)
        if not mm:
            continue
        mmpa = view.to_pa(mm)
        if mmpa is None:
            continue
        pgd = view.u64(mmpa + o_pgd)
        root = view.to_pa(pgd) if pgd else None
        if root is None:
            continue
        fresh = {}
        if walk_user_pages(view, root, fresh, limit_pages):
            capped = True
        for pa in fresh:
            out.setdefault(pa, (p["pid"], p["comm"]))
        if capped:
            break
    return out, capped


def bins_report(view, bin_bytes, mappings=None, changed=None, bins=None):
    """
    Zmenene stranky -> biny -> procesy. Jeden prechod cez zmenene stranky.

    `bins` = obmedz sa na tieto indexy binov (None = vsetky, v ktorych sa
    nieco zmenilo). Vracia dict s klucmi bins (zoradene), pola procesov,
    jadra a meranim casu.
    """
    t0 = time.time()
    if changed is None:
        changed = changed_pages_of_last_part(view.img)
    if mappings is None:
        mappings, capped = process_mappings(view)
    else:
        capped = False

    shift = bin_bytes.bit_length() - 1
    agg = {}
    for idx in changed:
        pa = idx * PAGE
        b = pa >> shift
        if bins is not None and b not in bins:
            continue
        owner = mappings.get(pa)
        slot = agg.setdefault(b, {"procesy": {}, "jadro": 0, "zmenenych": 0})
        slot["zmenenych"] += 1
        if owner is None:
            slot["jadro"] += 1
        else:
            slot["procesy"][owner] = slot["procesy"].get(owner, 0) + 1

    out = {}
    for b in sorted(agg):
        slot = agg[b]
        top = sorted(slot["procesy"].items(), key=lambda kv: -kv[1])
        out[b] = {
            "bin": b,
            "gpa_od": b << shift,
            "gpa_do": (b + 1) << shift,
            "zmenenych_stranok": slot["zmenenych"],
            "jadro_stranky": slot["jadro"],
            "procesy": [{"pid": pid, "comm": comm, "stranky": n}
                        for (pid, comm), n in top],
        }
    return {
        "bin_bytes": bin_bytes,
        "bins": out,
        "mapovane_stranky": len(mappings),
        "sposob": ("zostup uzivatelskymi tabulkami z mm->pgd (VMA zoznam nie "
                   "je v BTF tohto jadra)"),
        "capped": capped,
        "cas_s": time.time() - t0,
    }


def run(args, view):
    """Vstupna funkcia pre 'python3 -m guestparse procmap' (viz cli.py)."""
    bin_bytes = getattr(args, "bin_bytes", 16 * 1024 * 1024)
    bins = None
    if getattr(args, "bin", None):
        bins = set(args.bin)
    return bins_report(view, bin_bytes, bins=bins)
