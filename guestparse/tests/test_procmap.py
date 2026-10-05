"""
Testy mapovania bin -> proces (blok A4).

Dve casti:
  - synteticka: kompletne 4-urovnove tabulky stranok jedneho procesu postavene
    v dict-bilde a prejdene SKUTOCNYM walk (GuestView.walk_pa_detail s vlastnym
    korenom) - dokaze, ze uzivatelsky priestor sa preklada z mm->pgd, nie z
    init_top_pgt;
  - integracna: realna snimka z 18. 9. (data/sessions/...) s preukotvenym
    profilom - mapa procesov je neprazdna, systemd (pid 1) ma stranky, text
    jadra je "jadro", cas behu sa meria.
"""

import os
import struct

import pytest

from guestparse.procmap import (PAGE, changed_pages_of_last_part,
                                bins_report, process_mappings)
from guestparse.view import MODULES_VADDR, START_KERNEL_MAP, GuestView

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
PROFILE_DIR = os.path.join(REPO, "profiles", "debian12-6.1.0-42-cloud-amd64")
SESS = os.path.join(REPO, "data", "sessions", "20260918T154914Z_validate")
SNAP = os.path.join(SESS, "snap",
                    "hyptcn-guest_000000_20260918T154916673Z.vmicd")


# ------------------------------------------------------- synteticke tabulky

class FakeImg:
    """Stranky v dict pa -> bytes (4096); index = cisla stranok (pa//PAGE),
    rovnako ako VmicdImage.index."""

    def __init__(self, pages):
        self.pages = pages
        self.page_size = PAGE
        self.index = {pa // PAGE for pa in pages}

    def read(self, pa, n):
        b = self.pages.get(pa & ~(PAGE - 1))
        if b is None:
            return None
        off = pa & (PAGE - 1)
        if off + n > PAGE:
            return None
        return b[off:off + n]


class FakeProf:
    """Offsety: task.mm, mm.pgd (VMA zoznam netreba - prechod ide priamo
    tabulkami)."""

    def __init__(self):
        self.off = {
            "task_struct": {"mm": 0x800},
            "mm_struct": {"pgd": 0x600},
        }
        self.meta = {}

    def member(self, struct, field):
        return self.off.get(struct, {}).get(field)


def _page(*u64s):
    """Stranka z 64-bitovych hodnot (zvyšok nuly)."""
    b = bytearray(PAGE)
    for i, v in enumerate(u64s):
        struct.pack_into("<Q", b, i * 8, v)
    return bytes(b)


def _s_pole(*pairs):
    """Stranka s hodnotami na danych offsetoch (dvojice (offset, hodnota))."""
    b = bytearray(PAGE)
    for off, v in pairs:
        struct.pack_into("<Q", b, off, v)
    return bytes(b)


def _synteticky_view():
    """View, v ktorom jediny proces (pid 7) mapuje 4 stranky od VA 0x1000000
    na PA 0x2000000..0x2003000 (4-urovnove tabulky postavene rucne)."""
    # adresy struktur: kernel VA -> PA = VA - START (ktext_shift = 0)
    T = START_KERNEL_MAP + 0x500000     # task_struct
    MM = START_KERNEL_MAP + 0x510000    # mm_struct
    PGDV = START_KERNEL_MAP + 0x600000  # pgd (VA; PA = R = 0x600000)
    VMA = START_KERNEL_MAP + 0x530000   # vm_area_struct
    R, U, M, PT = 0x600000, 0x610000, 0x620000, 0x630000   # PGD/PUD/PMD/PTE
    F0 = 0x2000000                       # prva mapaovana stranka

    # FakeImg je indexovany FYZICKYMI adresami (VA - START pre kernel)
    pages = {}
    pages[0x500000] = _s_pole((0x800, MM))                     # task.mm
    pages[0x510000] = _s_pole((0x600, PGDV))                  # pgd
    pages[0x530000] = _s_pole((0x200, 0x1000000),              # vm_start
                              (0x208, 0x1004000),              # vm_end
                              (0x210, MM + 0x700))             # vm_next=head
    # tabulky: VA 0x1000000 -> PGD[0] PUD[0] PMD[8] PTE[0..3]
    pages[R] = _page(U | 1)
    pages[U] = _page(M | 1)
    pages[M] = _page(*([0] * 8 + [PT | 1] + [0] * 503))
    pte = [F0 + i * PAGE | 3 for i in range(4)]
    pages[PT] = _page(*pte)
    for i in range(4):
        pages[F0 + i * PAGE] = _page(0x41414141)

    img = FakeImg(pages)
    view = GuestView.__new__(GuestView)
    view.img = img
    view.p = FakeProf()
    view.ktext_shift = 0
    view.page_offset_base = None
    view.max_pa = 0x100000000
    view.reanchored = 0
    return view, T


def _procs(T):
    return {"processes": [{"pid": 7, "comm": "test", "task_va": T,
                           "kernel_thread": False}],
            "truncated": False, "stop_reason": None}


def test_process_mappings_prejde_uzivatelske_tabulky():
    view, T = _synteticky_view()
    out, capped = process_mappings(view, procs=_procs(T))
    assert not capped
    assert len(out) == 4
    for i in range(4):
        assert out[0x2000000 + i * PAGE] == (7, "test")


def test_bins_report_priradi_proces_a_jadro():
    view, T = _synteticky_view()
    mappings, _ = process_mappings(view, procs=_procs(T))
    changed = {0x2000000 >> 12, 0x2001000 >> 12, 0x3000000 >> 12}
    res = bins_report(view, 16 * 1024 * 1024, mappings=mappings,
                      changed=changed)
    # 0x2000000 >> 24 = 2, 0x3000000 >> 24 = 3
    assert set(res["bins"]) == {2, 3}
    b2 = res["bins"][2]
    assert b2["zmenenych_stranok"] == 2
    assert b2["procesy"] == [{"pid": 7, "comm": "test", "stranky": 2}]
    assert b2["jadro_stranky"] == 0
    b3 = res["bins"][3]
    assert b3["jadro_stranky"] == 1 and b3["procesy"] == []
    assert res["cas_s"] >= 0.0


def test_profil_bez_mm_offsets_je_chyba():
    view, T = _synteticky_view()
    view.p.off["mm_struct"] = {}
    with pytest.raises(ValueError):
        process_mappings(view, procs=_procs(T))


# ------------------------------------------------------------ realna snimka


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_realna_snimka_mapa_procesov():
    from guestparse.view import build_view
    view, img = build_view(SNAP, PROFILE_DIR)
    try:
        assert view.resolve()
        ok, info = view.reanchor()
        assert ok, info
        out, capped = process_mappings(view, limit_pages=80000)
        assert len(out) > 10000, out
        # systemd (pid 1) je prvy proces - jeho stranky musia byt v mape
        assert any(pid == 1 for pid, _ in out.values())
    finally:
        img.close()


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_realna_snimka_biny_text_jadro_a_procesy():
    from guestparse.view import build_view
    view, img = build_view(SNAP, PROFILE_DIR)
    try:
        assert view.resolve()
        assert view.reanchor()[0]
        mappings, _ = process_mappings(view, limit_pages=80000)
        res = bins_report(view, 16 * 1024 * 1024, mappings=mappings)
        # bin 21 drzi text jadra (PA ~0x15e00000), ale aj uzivatelske
        # stranky - biny su fyzicke, vlastnictvo sa MIESA a presne to ma
        # report ukazat: jadro + procesy v jednom bine
        assert res["bins"][21]["jadro_stranky"] > 0
        assert any(p["pid"] == 1 for p in res["bins"][21]["procesy"])
        # niekde musia byt stranky systemd (pid 1)
        systemd = [(b, p["stranky"])
                   for b in res["bins"]
                   for p in res["bins"][b]["procesy"] if p["pid"] == 1]
        assert systemd, "pid 1 nema v ziadnom bine zmenene stranky"
        assert res["cas_s"] > 0.0
    finally:
        img.close()


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_changed_pages_citaju_poslednu_cast_retazca():
    from guestparse.image import open_image
    img = open_image(SNAP)
    try:
        changed = changed_pages_of_last_part(img)
        # plna snimka: zmenene = vsetky zaznamenane stranky
        assert len(changed) == img.headers[-1]["records"]
        assert len(changed) > 100000
    finally:
        img.close()
