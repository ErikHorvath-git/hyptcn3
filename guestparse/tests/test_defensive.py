"""
Testy defenzivneho prechodu zoznamov nad umelou pamatou.

Snimka je ziva - VM sa nezastavuje - takze spajany zoznam sa moze roztrhnut
uprostred. Tieto testy stavaju pamat rucne a overuju, ze parser sa v takom
pripade zastavi a POVIE to ('truncated'), namiesto tichej polovice zoznamu.
"""

import struct

from guestparse.view import GuestView

KBASE = 0xFFFFFFFF80000000      # VA zaciatku umeleho obrazu jadra
MEMSIZE = 1 << 20

# offsety poli v umelom task_struct
O_TASKS, O_COMM, O_PID, O_TGID, O_MM = 0x10, 0x20, 0x30, 0x34, 0x38

INIT_VA = KBASE + 0x10000
TASK_VA = [KBASE + 0x20000, KBASE + 0x30000, KBASE + 0x40000]


class FakeImage:
    """Pamat v bajtovom poli; offset == fyzicka adresa."""

    kind = "fake"
    paths = []

    def __init__(self, size=MEMSIZE):
        self.buf = bytearray(size)
        self.page_size = 4096
        self.memsize = size

    def read(self, pa, n):
        if pa is None or pa < 0 or n <= 0 or pa + n > len(self.buf):
            return None
        return bytes(self.buf[pa:pa + n])

    def write(self, pa, data):
        self.buf[pa:pa + len(data)] = data

    def u64(self, pa, val):
        self.write(pa, struct.pack("<Q", val))

    def pages(self):
        for i in range(len(self.buf) // self.page_size):
            pg = bytes(self.buf[i * 4096:(i + 1) * 4096])
            if pg.strip(b"\0"):
                yield i, pg

    def page_count(self):
        return len(self.buf) // self.page_size

    def close(self):
        pass


class FakeProfile:
    """Minimalny profil: iba to, co processes() potrebuje."""

    kallsyms_path = "(umely)"
    btf_path = "(umely)"

    def __init__(self):
        self.sym = {"init_task": INIT_VA}
        self.off = {"task_struct": {"size": 0x100, "members": {
            "tasks": O_TASKS, "comm": O_COMM, "pid": O_PID,
            "tgid": O_TGID, "mm": O_MM}}}

    def addr(self, name):
        return self.sym.get(name)

    def member(self, s, f):
        return self.off.get(s, {}).get("members", {}).get(f)


def _pa(va):
    return va - KBASE


def _task(img, va, pid, comm):
    img.write(_pa(va) + O_PID, struct.pack("<i", pid))
    img.write(_pa(va) + O_TGID, struct.pack("<i", pid))
    img.write(_pa(va) + O_COMM, comm.encode() + b"\0")
    img.u64(_pa(va) + O_MM, 0x1000)


def _view(next_of_last):
    """
    Postavi zoznam init_task -> t0 -> t1 -> t2 -> (parameter).
    'next_of_last' urcuje, ako sa zoznam skonci alebo pokazi.
    """
    img = FakeImage()
    prof = FakeProfile()
    _task(img, INIT_VA, 0, "swapper/0")
    img.u64(_pa(INIT_VA) + O_TASKS, TASK_VA[0] + O_TASKS)
    for i, va in enumerate(TASK_VA):
        _task(img, va, i + 1, "proces%d" % i)
        nxt = (TASK_VA[i + 1] + O_TASKS) if i + 1 < len(TASK_VA) else next_of_last
        img.u64(_pa(va) + O_TASKS, nxt)
    view = GuestView(img, prof)
    view.ktext_shift = 0
    return view, img


def test_uzavrety_zoznam_nie_je_truncated():
    view, _ = _view(INIT_VA + O_TASKS)
    res = view.processes()
    assert res["count"] == 3
    assert res["truncated"] is False
    assert res["stop_reason"] is None
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]
    assert res["processes"][0]["kernel_thread"] is False


def test_cyklus_sa_zachyti():
    view, _ = _view(TASK_VA[0] + O_TASKS)      # posledny ukazuje na prveho
    res = view.processes()
    assert res["truncated"] is True
    assert "cyklus" in res["stop_reason"]
    assert res["count"] == 3                   # co sa precitalo, to sa vrati


def test_roztrhnuty_ukazovatel():
    view, _ = _view(0xDEADBEEF)                # nekanonicka adresa
    res = view.processes()
    assert res["truncated"] is True
    assert "ukazovatel" in res["stop_reason"]
    assert res["count"] == 3


def test_nulovy_ukazovatel():
    view, _ = _view(0)
    res = view.processes()
    assert res["truncated"] is True
    assert res["count"] == 3


def test_strop_poloziek():
    view, _ = _view(INIT_VA + O_TASKS)
    res = view.processes(limit=2)
    assert res["count"] == 2
    assert res["truncated"] is True
    assert "strop" in res["stop_reason"]


def test_nerozumny_pid():
    view, img = _view(INIT_VA + O_TASKS)
    img.write(_pa(TASK_VA[2]) + O_PID, struct.pack("<i", 99_000_000))
    res = view.processes()
    assert res["truncated"] is True
    assert "pid" in res["stop_reason"]
    assert res["count"] == 2


def test_prazdne_comm():
    view, img = _view(INIT_VA + O_TASKS)
    img.write(_pa(TASK_VA[1]) + O_COMM, b"\0" * 16)
    res = view.processes()
    assert res["truncated"] is True
    assert "comm" in res["stop_reason"]
    assert res["count"] == 1


def test_citanie_mimo_pamate_neda_nuly():
    """Adresa za koncom RAM musi byt chyba, nie ticho precitane nuly."""
    view, img = _view(INIT_VA + O_TASKS)
    assert view.u64(MEMSIZE - 4) is None
    assert view.cstr(MEMSIZE + 16, 8) == ""


# ---------------------------------------------------- prechod dozadu (prev)

DEAD_VA = KBASE + 0x50000           # ukonceny proces so starymi ukazovatelmi


def _obojsmerny(next_of_last):
    """
    init_task <-> t0 <-> t1 <-> t2 so spravnymi `prev`; `next` posledneho je
    parameter (init_task = uzavrety zoznam, DEAD_VA = roztrhnute spojenie).
    """
    view, img = _view(next_of_last)
    ring = [INIT_VA] + TASK_VA
    for i, va in enumerate(ring):
        img.u64(_pa(va) + O_TASKS + 8, ring[i - 1] + O_TASKS)
    _task(img, DEAD_VA, 388899, "python3")
    img.u64(_pa(DEAD_VA) + O_MM, 0)
    return view, img


def test_uzavrety_zoznam_ide_dopredu():
    view, _ = _obojsmerny(INIT_VA + O_TASKS)
    res = view.processes()
    assert res["walk"] == "next" and res["truncated"] is False
    assert "forward_stop_reason" not in res


def test_roztrhnute_spojenie_na_konci_uzavrie_prechod_dozadu():
    """Snimka 505 session benign-v3-20261022_03_train_bursty v malom."""
    view, img = _obojsmerny(DEAD_VA + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[0] + O_TASKS)      # spat dopredu: cyklus
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)  # prev nesedi s t2
    res = view.processes()
    assert res["truncated"] is False and res["stop_reason"] is None
    assert res["walk"] == "prev"
    assert "cyklus" in res["forward_stop_reason"]
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]
    assert res["count"] == 3


def test_prechod_dozadu_bez_uzla_zo_zhodnych_spojeni_neplati():
    """Dozadu uzavrety zoznam, ktoremu chyba t1 dosiahnuty zhodnym spojenim."""
    view, img = _obojsmerny(DEAD_VA + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[0] + O_TASKS)
    img.u64(_pa(TASK_VA[2]) + O_TASKS + 8, TASK_VA[0] + O_TASKS)  # dozadu t2 -> t0
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "cyklus" in res["stop_reason"]
    assert "ine uzly" in res["backward_stop_reason"]
    assert res["count"] == 4                    # dopredu vratane ukonceneho procesu


def test_roztrhnutie_uprostred_prechod_dozadu_nedoplni():
    """Uzly za roztrhnutym spojenim pozna iba prechod dozadu: zoznam zostava neuplny."""
    view, img = _obojsmerny(INIT_VA + O_TASKS)
    img.u64(_pa(TASK_VA[0]) + O_TASKS, DEAD_VA + O_TASKS)      # t0 -> ukonceny proces
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[0] + O_TASKS)      # a spat na t0: cyklus
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "ine uzly" in res["backward_stop_reason"]
    assert [p["comm"] for p in res["processes"]] == ["proces0", "python3"]


def test_oba_smery_roztrhnute_ostava_dolna_hranica():
    view, _ = _view(TASK_VA[0] + O_TASKS)      # prev su nuly
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "cyklus" in res["stop_reason"]
    assert "ukazovatel" in res["backward_stop_reason"]
    assert res["count"] == 3
