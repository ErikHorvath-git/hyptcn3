"""
Testy GuestView.memory_patterns nad umelou pamatou: stranky W+X z tabuliek
stranok a subory memfd z tabulky deskriptorov a mm->exe_file.
"""

import struct

from guestparse.tests.test_defensive import (
    INIT_VA, KBASE, O_MM, O_TASKS, TASK_VA, FakeProfile, _obojsmerny, _pa)

O_FILES = 0x40
MM_VA = KBASE + 0x70000
FILES_VA, FDT_VA, FDARR_VA = KBASE + 0x71000, KBASE + 0x71100, KBASE + 0x71200
FILE_VA, DENTRY_VA, NAME_VA = KBASE + 0x72000, KBASE + 0x72100, KBASE + 0x72200
PGD, PUD, PMD, PTE = 0x80000, 0x81000, 0x82000, 0x83000
P, RW, US, PS, NX = 1, 2, 4, 1 << 7, 1 << 63
TABLE = P | RW | US


class Profile(FakeProfile):
    def __init__(self):
        super().__init__()
        self.off["task_struct"]["members"]["files"] = O_FILES
        self.off.update({
            "mm_struct": {"members": {"pgd": 0x48, "exe_file": 0x50}},
            "files_struct": {"members": {"fdt": 0x20}},
            "fdtable": {"members": {"max_fds": 0x0, "fd": 0x8}},
            "file": {"members": {"f_path": 0x10}},
            "path": {"members": {"dentry": 0x8}},
            "dentry": {"members": {"d_name": 0x20}},
            "qstr": {"members": {"name": 0x8}},
        })

    def require(self, s, *fields):
        return [self.off[s]["members"][f] for f in fields]


def _pamat(meno="memfd:payload", exe=False, fd=True):
    """
    Proces t0 ma mm s tabulkami PGD -> PUD -> PMD -> PTE a deskriptor 3 na
    subor `meno`. PGD ma NX ako kopia pre jadro s PTI. Ostatne procesy su bez
    mm (vlakna jadra), aby test videl iba t0.
    """
    view, img = _obojsmerny(INIT_VA + O_TASKS)
    view.p = Profile()
    for va in TASK_VA:
        img.u64(_pa(va) + O_MM, 0)
    t0 = _pa(TASK_VA[0])
    img.u64(t0 + O_MM, MM_VA)
    img.u64(t0 + O_FILES, FILES_VA)
    img.u64(_pa(MM_VA) + 0x48, KBASE + PGD)
    img.u64(_pa(MM_VA) + 0x50, FILE_VA if exe else 0)
    img.u64(PGD, PUD | TABLE | NX)
    img.u64(PUD, PMD | TABLE)
    img.u64(PMD, PTE | TABLE)
    for i, flags in enumerate((TABLE, TABLE, TABLE, TABLE | NX, P | US, P | RW)):
        img.u64(PTE + 8 * i, 0x90000 + i * 0x1000 | flags)
    img.u64(_pa(FILES_VA) + 0x20, FDT_VA)
    img.write(_pa(FDT_VA), struct.pack("<i", 8))
    img.u64(_pa(FDT_VA) + 0x8, FDARR_VA)
    if fd:
        img.u64(_pa(FDARR_VA) + 3 * 8, FILE_VA)
    img.u64(_pa(FILE_VA) + 0x10 + 0x8, DENTRY_VA)
    img.u64(_pa(DENTRY_VA) + 0x20 + 0x8, NAME_VA)
    img.write(_pa(NAME_VA), meno.encode() + b"\0")
    return view, img


def _procs(view):
    return view.processes()["processes"]


def test_wx_stranky_a_memfd_deskriptor():
    view, _ = _pamat()
    res = view.memory_patterns(_procs(view))
    assert res["truncated"] is False and res["stop_reason"] is None
    assert res["wx_pages"] == 3 and res["wx_processes"] == 1
    assert res["memfd_processes"] == 1
    kinds = sorted(p["kind"] for p in res["patterns"])
    assert kinds == ["memfd_fd", "wx"]
    assert [p["fd"] for p in res["patterns"] if p["kind"] == "memfd_fd"] == [3]


def test_iny_subor_nie_je_memfd():
    view, _ = _pamat(meno="libc.so.6")
    res = view.memory_patterns(_procs(view))
    assert res["memfd_processes"] == 0 and res["wx_processes"] == 1


def test_spustenie_z_memfd():
    view, _ = _pamat(exe=True, fd=False)
    res = view.memory_patterns(_procs(view))
    assert [p["kind"] for p in res["patterns"] if p["kind"] != "wx"] == ["memfd_exe"]
    assert res["memfd_processes"] == 1


def test_nx_na_pmd_zakaze_cely_podstrom():
    view, img = _pamat()
    img.u64(PMD, PTE | TABLE | NX)
    res = view.memory_patterns(_procs(view))
    assert res["wx_pages"] == 0 and res["wx_processes"] == 0


def test_bez_zapisu_na_pud_nie_je_wx():
    view, img = _pamat()
    img.u64(PUD, PMD | P | US)
    assert view.memory_patterns(_procs(view))["wx_pages"] == 0


def test_velka_stranka_2mib_sa_rata_po_4kib():
    view, img = _pamat()
    img.u64(PMD, 0x200000 | TABLE | PS)
    assert view.memory_patterns(_procs(view))["wx_pages"] == 512


def test_jadrova_polovica_pgd_sa_ignoruje():
    view, img = _pamat()
    img.u64(PGD, 0)
    img.u64(PGD + 300 * 8, PUD | TABLE)
    assert view.memory_patterns(_procs(view))["wx_pages"] == 0


def test_zdielane_mm_sa_rata_raz():
    view, img = _pamat()
    img.u64(_pa(TASK_VA[1]) + O_MM, MM_VA)
    res = view.memory_patterns(_procs(view))
    assert res["wx_processes"] == 1 and res["wx_pages"] == 3


def test_strop_tabuliek_je_neuplny_vysledok():
    view, _ = _pamat()
    res = view.memory_patterns(_procs(view), max_tables=2)
    assert res["truncated"] is True and "strop" in res["stop_reason"]


def test_neuplny_zoznam_procesov_je_neuplny_vysledok():
    view, img = _pamat()
    img.u64(_pa(TASK_VA[2]) + O_TASKS, 0)           # dopredu roztrhnute
    img.u64(_pa(INIT_VA) + O_TASKS + 8, 0)          # aj dozadu
    res = view.memory_patterns()
    assert res["truncated"] is True
