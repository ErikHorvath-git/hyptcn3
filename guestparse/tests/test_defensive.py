"""
Testy defenzivneho prechodu zoznamov nad umelou pamatou.

Snimka je ziva - VM sa nezastavuje - takze spajany zoznam sa moze roztrhnut
uprostred. Tieto testy stavaju pamat rucne a overuju, ze parser sa v takom
pripade zastavi a POVIE to ('truncated'), namiesto tichej polovice zoznamu.
"""

import struct

import pytest

from guestparse.view import GuestView

KBASE = 0xFFFFFFFF80000000      # VA zaciatku umeleho obrazu jadra
MEMSIZE = 1 << 20

# offsety poli v umelom task_struct
O_TASKS, O_COMM, O_PID, O_TGID, O_MM, O_EXIT = 0x10, 0x20, 0x30, 0x34, 0x38, 0x40

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
            "tgid": O_TGID, "mm": O_MM, "exit_state": O_EXIT}}}

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
    # Od 2026-11-17 pravidlo 'meet': dopredu aj dozadu sa zhodne casti stretnu
    # na t2 (t2.prev aj t2.next su z ineho okamihu); t2 je zivy, zapocita sa.
    assert res["truncated"] is False and res["walk"] == "meet"
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]
    assert res["stale_node"]["pid"] == 3 and res["stale_node"]["counted"] is True


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


# ------------------------------------------- vlozenie na koniec (tail)

def _vkladany_na_konci():
    """
    Snimka 613 session benign-v5-20261025_18_train_quiet v malom: t2.next aj
    init_task.prev uz ukazuju na novy uzol, ale jeho stranka je z casu pred
    vlozenim - ukonceny thread procesu t1 so spojeniami skopirovanymi od
    neho (prev t0, next t2), ako thread pid 740794 procesu 427 so
    spojeniami 426 <- 427 -> 428.
    """
    view, img = _obojsmerny(DEAD_VA + O_TASKS)
    img.u64(_pa(INIT_VA) + O_TASKS + 8, DEAD_VA + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[2] + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    img.write(_pa(DEAD_VA) + O_TGID, struct.pack("<i", 2))
    return view, img


def test_vkladany_posledny_uzol_potvrdi_init_task_prev():
    view, _ = _vkladany_na_konci()
    res = view.processes()
    assert res["truncated"] is False and res["stop_reason"] is None
    assert res["walk"] == "tail"
    assert "cyklus" in res["forward_stop_reason"]
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]
    assert res["count"] == 3


def test_vkladany_uzol_bez_zhodnej_predpony_neplati():
    """init_task.prev ukazuje na nezhodny uzol, ale prve nezhodne spojenie je skor (t1.prev)."""
    view, img = _vkladany_na_konci()
    img.u64(_pa(TASK_VA[1]) + O_TASKS + 8, INIT_VA + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "cyklus" in res["stop_reason"]
    assert res["count"] == 4


def test_vkladany_uzol_s_obsahom_vodcu_skupiny_nepotvrdi():
    """Bez obsahu vlakna moze ist o uzol, pred ktorym sa medzi citaniami odstranili ine."""
    view, img = _vkladany_na_konci()
    img.write(_pa(DEAD_VA) + O_TGID, struct.pack("<i", 388899))
    res = view.processes()
    # 'tail' to stale nepotvrdi; 'meet' uzol so zivym obsahom zapocita, takze
    # ani pri uzle, pred ktorym sa odstranili ine, sa ziadny proces nestrati.
    assert res["walk"] == "meet" and res["truncated"] is False
    assert [p["pid"] for p in res["processes"]] == [1, 2, 3, 388899]
    assert res["stale_node"]["counted"] is True


def test_vlakno_bez_vodcu_v_zozname_nepotvrdi():
    """
    Exec z vedlajsieho vlakna (de_thread): vlakno nahradilo vodcu na konci
    zoznamu a jeho stranka je z casu pred exec. Vodca (pid 4) v zozname nie
    je a proces tam bol cely cas, takze zoznam bez uzla by bol nespravny.
    """
    view, img = _vkladany_na_konci()
    img.write(_pa(DEAD_VA) + O_TGID, struct.pack("<i", 4))
    res = view.processes()
    # 'meet' uzol zapocita (zivy obsah), takze proces vlakna v zozname ostane.
    assert res["walk"] == "meet" and res["count"] == 4
    assert res["processes"][-1]["tgid"] == 4


def test_init_task_prev_na_inom_uzle_vkladanie_nepotvrdi():
    view, img = _vkladany_na_konci()
    img.u64(_pa(INIT_VA) + O_TASKS + 8, TASK_VA[1] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "ine uzly" in res["backward_stop_reason"]


def test_neprecitatelny_vkladany_uzol_nepotvrdi():
    """Uzol, ktory sa neda precitat ako proces, nie je dokaz vkladania na koniec."""
    view, img = _vkladany_na_konci()
    img.write(_pa(DEAD_VA) + O_COMM, b"\0" * 16)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "comm" in res["stop_reason"]
    assert res["count"] == 3


# ------------------- odstranenie uprostred spolu s vlozenim na koniec

GONE_VA = KBASE + 0x60000           # proces odstraneny cez list_del_rcu pocas citania
LIST_POISON2 = 0xDEAD000000000122


def _odstraneny_a_vkladany():
    """
    Snimka 270 session events-v3-20261108_46_test_events_write_heavy v malom:
    medzi t0 a t1 bol proces, ktory pocas citania zanikol. t0.next ho uz
    obchadza, stranka t1 sa vsak precitala skor a jej prev na neho este
    ukazuje; jeho stranka ma prev LIST_POISON2 a next t1. Zaroven je na
    konci zoznamu vkladany uzol ako v _vkladany_na_konci.
    """
    view, img = _vkladany_na_konci()
    _task(img, GONE_VA, 190491, "postgres")
    img.u64(_pa(GONE_VA) + O_TASKS, TASK_VA[1] + O_TASKS)
    img.u64(_pa(GONE_VA) + O_TASKS + 8, LIST_POISON2)
    img.u64(_pa(TASK_VA[1]) + O_TASKS + 8, GONE_VA + O_TASKS)
    return view, img


def test_odstraneny_uzol_pred_vkladanim_uzavrie_tail():
    view, _ = _odstraneny_a_vkladany()
    res = view.processes()
    assert res["truncated"] is False and res["stop_reason"] is None
    assert res["walk"] == "tail" and res["deleted_links"] == 1
    assert "cyklus" in res["forward_stop_reason"]
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]


def test_vkladany_bez_odstranenia_nema_deleted_links():
    res = _vkladany_na_konci()[0].processes()
    assert res["walk"] == "tail" and "deleted_links" not in res


def test_odstraneny_uzol_bez_poison_nevysvetli():
    """prev uzla D je platny: D je v zozname a t0.next ho preskocil, mohol sa skryt."""
    view, img = _odstraneny_a_vkladany()
    img.u64(_pa(GONE_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"


def test_odstraneny_uzol_s_inym_next_nevysvetli():
    """D bol odstraneny, ale nestal tesne pred t1: medzi nimi mohol byt iny uzol."""
    view, img = _odstraneny_a_vkladany()
    img.u64(_pa(GONE_VA) + O_TASKS, TASK_VA[2] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"


def test_odstraneny_uzol_bez_vkladania_na_konci_neuzavrie():
    """
    Samotne odstranenie uprostred neuzavrie zoznam, ktory sa dopredu zacyklil
    inde: init_task.prev na t1 nie je ani posledny nezhodny uzol ('tail'),
    ani zaciatok prechodu dozadu cez vsetky uzly dopredu ('prev').
    """
    view, img = _odstraneny_a_vkladany()
    img.u64(_pa(INIT_VA) + O_TASKS + 8, TASK_VA[1] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "ine uzly" in res["backward_stop_reason"]


def test_odstraneny_uzol_s_init_task_prev_na_t2_uzavrie_prev():
    """
    init_task.prev na t2 je tvar snimky 505 s odstranenym uzlom uprostred:
    do 2026-11-14 zamietnuty, teraz ho uzavrie pravidlo 'prev' s obchadzkou.
    """
    view, img = _odstraneny_a_vkladany()
    img.u64(_pa(INIT_VA) + O_TASKS + 8, TASK_VA[2] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is False and res["walk"] == "prev"
    assert res["deleted_links"] == 1 and res["count"] == 3


def test_odstraneny_uzol_v_uplnom_zozname_nemeni_next():
    """Zoznam uzavrety dopredu ostava 'next' aj so zastaranym prev."""
    view, img = _obojsmerny(INIT_VA + O_TASKS)
    _task(img, GONE_VA, 190491, "postgres")
    img.u64(_pa(GONE_VA) + O_TASKS, TASK_VA[1] + O_TASKS)
    img.u64(_pa(GONE_VA) + O_TASKS + 8, LIST_POISON2)
    img.u64(_pa(TASK_VA[1]) + O_TASKS + 8, GONE_VA + O_TASKS)
    res = view.processes()
    assert res["walk"] == "next" and res["truncated"] is False and res["count"] == 3


# ------------- odstranenie uprostred spolu so zastaranym `next` na konci (prev)

def _odstraneny_a_zastarany_next():
    """
    Tvar snimky 505 (t2.next ukazuje na ukonceny proces so starymi
    ukazovatelmi, init_task.prev je spravne t2) a k tomu proces odstraneny
    medzi t0 a t1 ako v snimke 270: t1.prev este ukazuje na neho.
    """
    view, img = _obojsmerny(DEAD_VA + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[0] + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    _task(img, GONE_VA, 190491, "postgres")
    img.u64(_pa(GONE_VA) + O_TASKS, TASK_VA[1] + O_TASKS)
    img.u64(_pa(GONE_VA) + O_TASKS + 8, LIST_POISON2)
    img.u64(_pa(TASK_VA[1]) + O_TASKS + 8, GONE_VA + O_TASKS)
    return view, img


def test_odstraneny_uzol_pred_zastaranym_next_uzavrie_prev():
    view, _ = _odstraneny_a_zastarany_next()
    res = view.processes()
    assert res["truncated"] is False and res["stop_reason"] is None
    assert res["walk"] == "prev" and res["deleted_links"] == 1
    assert "cyklus" in res["forward_stop_reason"]
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]


def test_prev_bez_odstranenia_nema_deleted_links():
    view, img = _obojsmerny(DEAD_VA + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[0] + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    res = view.processes()
    assert res["walk"] == "prev" and "deleted_links" not in res


def test_prev_odstraneny_uzol_s_inym_next_nevysvetli():
    """D nestal tesne pred t1 (D.next je t2): medzi t0 a t1 mohol byt skryty uzol."""
    view, img = _odstraneny_a_zastarany_next()
    img.u64(_pa(GONE_VA) + O_TASKS, TASK_VA[2] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "deleted_links" not in res
    assert "ukazovatel" in res["backward_stop_reason"]


def test_prev_odstraneny_uzol_bez_poison_nevysvetli():
    """D ma platny prev: je v zozname dozadu a t0.next ho preskocil."""
    view, img = _odstraneny_a_zastarany_next()
    img.u64(_pa(GONE_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"


def test_prev_s_odstranenym_uzlom_a_chybajucim_uzlom_dozadu_neplati():
    """Obchadzka nenahradi zhodu mnozin: dozadu t2 -> t0 vynecha t1."""
    view, img = _odstraneny_a_zastarany_next()
    img.u64(_pa(TASK_VA[2]) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    res = view.processes()
    # Ani 'prev', ani 'tail'; 'meet' na zivom t2, ktory sa zapocita.
    assert res["walk"] == "meet" and res["count"] == 3
    assert res["stale_node"]["pid"] == 3 and res["stale_node"]["counted"] is True


# ------------------ vlozenie na koniec: stranka s odstranenym vodcom skupiny

def _vkladany_s_odstranenym_vodcom():
    """
    Ako _vkladany_na_konci, ale recyklovany task_struct drzal ukonceneho
    vodcu skupiny (tgid == pid, napr. backend postgres): jeho tasks.prev je
    LIST_POISON2 a next ostal stary.
    """
    view, img = _vkladany_na_konci()
    img.write(_pa(DEAD_VA) + O_TGID, struct.pack("<i", 388899))
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, LIST_POISON2)
    return view, img


def test_vkladany_uzol_s_odstranenym_vodcom_uzavrie_tail():
    view, _ = _vkladany_s_odstranenym_vodcom()
    res = view.processes()
    assert res["truncated"] is False and res["stop_reason"] is None
    assert res["walk"] == "tail" and res["tail_content"] == "deleted"
    assert "cyklus" in res["forward_stop_reason"]
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]


def test_vkladany_uzol_s_vlaknom_ma_tail_content_thread():
    res = _vkladany_na_konci()[0].processes()
    assert res["walk"] == "tail" and res["tail_content"] == "thread"


def test_odstraneny_vodca_bez_init_task_prev_neuzavrie():
    """Otraveny prev nestaci: init_task.prev musi ukazovat prave na ten uzol."""
    view, img = _vkladany_s_odstranenym_vodcom()
    img.u64(_pa(INIT_VA) + O_TASKS + 8, TASK_VA[1] + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"


def test_odstraneny_vodca_po_skorsom_nezhodnom_spojeni_neuzavrie():
    """Prve nevysvetlene nezhodne spojenie je skor (t1.prev), nie na konci zoznamu."""
    view, img = _vkladany_s_odstranenym_vodcom()
    img.u64(_pa(TASK_VA[1]) + O_TASKS + 8, INIT_VA + O_TASKS)
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"


# ------------------------------ tvary, ktore ostavaju zamietnute (A9, A10)

NEW2_VA = KBASE + 0x70000


def test_dve_vlozenia_na_koniec_ostavaju_neuplne():
    """
    Dva nove uzly za jednu snimku: t2.next ukazuje na prvy (stranka z casu
    pred vlozenim), init_task.prev na druhy. Prvy nezhodny uzol nie je
    posledny podla init_task.prev, takze 'tail' neplati.
    """
    view, img = _vkladany_na_konci()
    _task(img, NEW2_VA, 999, "kworker/1:2")
    img.u64(_pa(NEW2_VA) + O_TASKS, INIT_VA + O_TASKS)
    img.u64(_pa(NEW2_VA) + O_TASKS + 8, DEAD_VA + O_TASKS)
    img.u64(_pa(INIT_VA) + O_TASKS + 8, NEW2_VA + O_TASKS)
    res = view.processes()
    # 'tail' neplati; 'meet': zhodna cast dozadu je [kworker/1:2], stretnu sa na
    # prvom novom uzle, ktory ma zivy obsah a zapocita sa.
    assert res["walk"] == "meet" and res["truncated"] is False
    assert [p["pid"] for p in res["processes"]] == [1, 2, 3, 388899, 999]


def test_vkladany_uzol_s_nulovou_strankou_ostava_neuplny():
    """Stranka posledneho uzla je cela nulova: neda sa citat ako proces."""
    view, img = _vkladany_na_konci()
    img.write(_pa(DEAD_VA), bytes(0x100))
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"
    assert "comm" in res["stop_reason"] and "comm" in res["backward_stop_reason"]
    assert res["count"] == 3


# ------------------ pravidlo 'meet' (normal-v4-20261115, 2026-11-17)

EXTRA_VA = KBASE + 0x80000


def _kruh(uzly):
    """init_task <-> uzly v poradi, so spravnymi next aj prev."""
    view, img = _view(INIT_VA + O_TASKS)
    ring = [INIT_VA] + uzly
    for i, va in enumerate(ring):
        img.u64(_pa(va) + O_TASKS, ring[(i + 1) % len(ring)] + O_TASKS)
        img.u64(_pa(va) + O_TASKS + 8, ring[i - 1] + O_TASKS)
    return view, img


def test_meet_snimka_120_odstraneny_uprostred_a_recyklovany_na_konci():
    """
    12_b snimka 120: t1 skoncil pocas citania (t0.next aj t1.next su stare,
    t2.prev uz preskakuje t1), novy proces na konci je v recyklovanom
    task_struct, ktoreho stranka je este ukonceny postmaster (prev
    LIST_POISON2, next doprostred zoznamu, exit_state EXIT_DEAD).
    """
    _task_extra = lambda img: _task(img, EXTRA_VA, 50, "postgres")
    view, img = _kruh(TASK_VA + [EXTRA_VA, DEAD_VA])
    _task_extra(img)
    _task(img, DEAD_VA, 112488, "postgres")
    img.u64(_pa(TASK_VA[2]) + O_TASKS + 8, TASK_VA[0] + O_TASKS)     # t2.prev preskakuje t1
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[0] + O_TASKS)            # next doprostred: cyklus
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, LIST_POISON2)
    img.write(_pa(DEAD_VA) + O_EXIT, struct.pack("<i", 16))
    res = view.processes()
    assert res["walk"] == "meet" and res["truncated"] is False
    assert [p["pid"] for p in res["processes"]] == [1, 2, 3, 50]
    assert res["skipped_links"] == 1
    assert res["stale_node"] == {"pid": 112488, "comm": "postgres", "task_va": DEAD_VA,
                                 "counted": False, "exit_state": 16}


def test_meet_snimka_306_kratko_zijuci_uzol_medzi_castami():
    """
    11_b snimka 306: dopredu ... t2 -> D, D.prev aj D.next su spojenia jeho
    rodica z ineho okamihu; dozadu init_task <- N <- D. Obe zhodne casti sa
    stretnu na D, ktory uz skoncil (exit_state 16) a nezapocita sa.
    """
    view, img = _kruh(TASK_VA + [DEAD_VA, NEW2_VA])
    _task(img, DEAD_VA, 620354, "python3")
    _task(img, NEW2_VA, 620155, "postgres")
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[1] + O_TASKS)            # next do stredu
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)        # prev do stredu
    img.write(_pa(DEAD_VA) + O_EXIT, struct.pack("<i", 16))
    res = view.processes()
    assert res["walk"] == "meet"
    assert [p["pid"] for p in res["processes"]] == [1, 2, 3, 620155]
    assert res["stale_node"]["counted"] is False and "skipped_links" not in res


def test_meet_nezapocita_kopiu_s_rovnakym_pid():
    view, img = _kruh(TASK_VA + [DEAD_VA, NEW2_VA])
    _task(img, DEAD_VA, 2, "proces1")                                # kopia rodica t1
    _task(img, NEW2_VA, 77, "postgres")
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[1] + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    res = view.processes()
    assert res["walk"] == "meet" and [p["pid"] for p in res["processes"]] == [1, 2, 3, 77]
    assert res["stale_node"]["counted"] is False


def test_meet_neplati_ked_sa_casti_stretnu_na_roznych_uzloch():
    """Dozadu sa zhoda zlomi uz pred D: kruh nie je uzavrety, riadok ostava neuplny."""
    view, img = _kruh(TASK_VA + [DEAD_VA, NEW2_VA, EXTRA_VA])
    _task(img, DEAD_VA, 620354, "python3")
    _task(img, NEW2_VA, 620155, "postgres")
    _task(img, EXTRA_VA, 620156, "postgres")
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[1] + O_TASKS)
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)
    img.u64(_pa(NEW2_VA) + O_TASKS, INIT_VA + O_TASKS)              # NEW2.next nesedi s EXTRA
    res = view.processes()
    assert res["truncated"] is True and res["walk"] == "next"


def test_preskok_dozadu_bez_zhodneho_pokracovania_nevysvetli():
    """Uzol so starym prev, za ktorym spojenie nesedi, nie je odstranenie uprostred."""
    view, img = _kruh(TASK_VA + [DEAD_VA])
    _task(img, DEAD_VA, 9, "python3")
    img.u64(_pa(DEAD_VA) + O_TASKS + 8, TASK_VA[0] + O_TASKS)        # preskakuje t1, t2
    img.u64(_pa(DEAD_VA) + O_TASKS, TASK_VA[1] + O_TASKS)            # a pokracuje do stredu
    img.write(_pa(DEAD_VA) + O_EXIT, struct.pack("<i", 16))
    res = view.processes()
    # Bez preskoku je D prvy nezhodny uzol; dozadu init_task <- D, D.next nesedi:
    # 'meet' ho ako ukonceny nezapocita a zoznam ostane t0, t1, t2.
    assert "skipped_links" not in res
    assert res["walk"] == "meet" and res["count"] == 3 and res["stale_node"]["counted"] is False


# ------------ prechod dozadu pri kazdom vysledku (navrh protokolu v5, kap. 6.2)

def _closed_list_with_deleted_node():
    """_odstraneny_a_zastarany_next, ale t2.next uz vedie do init_task: zoznam sa uzavrie dopredu."""
    view, img = _odstraneny_a_zastarany_next()
    img.u64(_pa(TASK_VA[2]) + O_TASKS, INIT_VA + O_TASKS)
    return view


@pytest.mark.parametrize("build, walk", [
    (lambda: _obojsmerny(INIT_VA + O_TASKS)[0], "next"),
    # Spojenie, ktore vysvetli odstranenie uzla v tom istom obraze, nie je
    # nezhoda: prechod dozadu ide tou istou obchadzkou ako pravidla.
    (_closed_list_with_deleted_node, "next"),
    # Pri 'prev' sa prechod dozadu porovnava so zoznamom riadku, nie s
    # prechodom dopredu (ten presiel aj ukonceny proces na konci).
    (lambda: _odstraneny_a_zastarany_next()[0], "prev"),
], ids=["closed", "deleted-node", "prev"])
def test_backward_walk_agrees_with_the_row_list(build, walk):
    """Prechod dozadu bezi pri kazdom vysledku a zhoduje sa so zoznamom riadku."""
    res = build().processes()
    assert res["walk"] == walk and res["truncated"] is False
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]
    assert res["backward"] == {"closed": True, "agrees": True}


@pytest.mark.parametrize("prev, backward", [
    # Snimka 529 session benign-v3-20261022_03_train_bursty v malom: t2.prev
    # preskakuje t1, dozadu sa zoznam uzavrie cez ine ulohy.
    ([(TASK_VA[2], TASK_VA[0])], {"closed": True, "agrees": False}),
    # t0.prev ukazuje na t2: dozadu tie iste ulohy v opacnom poradi, ale
    # prechod sa zacykli namiesto navratu do init_task.
    ([(TASK_VA[0], TASK_VA[2])], {"closed": False, "agrees": False}),
    # Dozadu sa zoznam uzavrie cez tie iste ulohy, ale v inom poradi.
    ([(INIT_VA, TASK_VA[1]), (TASK_VA[1], TASK_VA[2]), (TASK_VA[2], TASK_VA[0])],
     {"closed": True, "agrees": False}),
], ids=["other-tasks", "cycle", "other-order"])
def test_inconsistent_prev_in_forward_closed_list_is_recorded(prev, backward):
    """
    Nezhodne spojenie `prev` v zozname, ktory sa dopredu uzavrel, sa predtym
    zahodilo. Vysledok ostava rovnaky ('next', tie iste procesy); zapise sa
    iba prechod dozadu.
    """
    view, img = _obojsmerny(INIT_VA + O_TASKS)
    for va, target in prev:
        img.u64(_pa(va) + O_TASKS + 8, target + O_TASKS)
    res = view.processes()
    assert res["walk"] == "next" and res["truncated"] is False and res["stop_reason"] is None
    assert [p["comm"] for p in res["processes"]] == ["proces0", "proces1", "proces2"]
    assert res["backward"] == backward
