"""
Testy skladania okien.

Vstupy su synteticke - testy musia bezat aj bez zozbieraneho korpusu, inak by
sa dali spustit iba na tomto stroji a iba po roote. Poradie priznakov je vsak
skutocny kontrakt z features/snapshot.py (MENA), nie vymyslene mena: prave
podla neho sa rozhoduje, ktory riadok do okna nepatri.

Co sa overuje: tvar, pocty, styri hranice (hranica sedenia, diera v seq,
casova medzera, plna snimka), riadok bez predchodcu, determinizmus.
"""

import hashlib

import numpy as np
import pytest

from features.snapshot import MENA
from features.windows import (DLZKA_OKNA, DOVOD_PLNA, DOVOD_PREDCHODCA,
                              Snimka, WindowError, okna, segmenty,
                              snimky_z_matice)

F = len(MENA)
I_PLNA = MENA.index("je_plna")
I_PRED = MENA.index("ma_predchodcu")


def vektor(session, seq):
    """Deterministicky vektor: rovnaky vstup da vzdy rovnake cisla.

    Seed sa odvodzuje z SHA-256, nie z vstavaneho hash() - ten je pre retazce
    randomizovany na proces, takze test determinizmu by porovnaval iba dva
    behy v tom istom procese.
    """
    kluc = hashlib.sha256(("%s|%d" % (session, seq)).encode()).digest()
    rng = np.random.default_rng(int.from_bytes(kluc[:8], "big"))
    x = rng.random(F)
    x[I_PLNA] = 0.0
    x[I_PRED] = 1.0
    return x


def snimka(session, seq, t0=1_000_000.0, perioda=2.0, je_plna=False,
           ma_predchodcu=True, cas_unix=None):
    t = t0 + seq * perioda if cas_unix is None else cas_unix
    x = vektor(session, seq)
    x[I_PLNA] = 1.0 if je_plna else 0.0
    x[I_PRED] = 0.0 if not ma_predchodcu else 1.0
    return Snimka(session=session, seq=seq, x=x, priznaky=MENA, cas_unix=t,
                  je_plna=je_plna, ma_predchodcu=ma_predchodcu)


def session(meno, n, od=0, plne=(), bez_predchodcu=(), **kw):
    """n snimok jedneho sedenia; `plne` a `bez_predchodcu` su cisla seq."""
    return [snimka(meno, s, je_plna=s in plne,
                   ma_predchodcu=s not in bez_predchodcu, **kw)
            for s in range(od, od + n)]


# -- tvar a pocty --------------------------------------------------------


def test_tvar_je_okna_cas_priznaky():
    o = okna(session("a", 20), dlzka=8)
    assert o.X.shape == (13, 8, F)
    assert len(o) == 13
    assert o.priznaky == MENA


def test_pocet_okien_pri_kroku_1_a_2():
    snimky = session("a", 20)
    assert len(okna(snimky, dlzka=8, krok=1)) == 13
    assert len(okna(snimky, dlzka=8, krok=2)) == 7


def test_metadata_okna():
    o = okna(session("a", 10, perioda=2.0), dlzka=4)
    m = o.meta[0]
    assert m["session"] == "a"
    assert (m["seq_od"], m["seq_do"]) == (0, 3)
    assert m["n_snimok"] == 4
    assert m["trvanie_s"] == pytest.approx(6.0)
    assert o.meta[-1]["seq_do"] == 9


# -- hranice -------------------------------------------------------------


def test_okno_nepresahuje_hranicu_sedenia():
    snimky = session("a", 10) + session("b", 10)
    o = okna(snimky, dlzka=4)
    # 7 okien na sedenie, ziadne cez hranicu
    assert len(o) == 14
    for m in o.meta:
        assert m["seq_do"] - m["seq_od"] == 3
    assert {m["session"] for m in o.meta} == {"a", "b"}
    a = [m for m in o.meta if m["session"] == "a"]
    b = [m for m in o.meta if m["session"] == "b"]
    assert a[-1]["seq_do"] == 9 and b[0]["seq_od"] == 0


def test_hranica_sedenia_plati_aj_ked_seq_plynulo_nadvazuje():
    # 'b' pokracuje v cislovani po 'a'; spojit ich by bola presne ta chyba,
    # ktora v predchadzajucom projekte urobila confound
    snimky = session("a", 6) + session("b", 6, od=6)
    o = okna(snimky, dlzka=6)
    assert len(o) == 2
    assert {(m["session"], m["seq_od"]) for m in o.meta} == {("a", 0), ("b", 6)}


def test_diera_v_seq_reze_usek():
    snimky = session("a", 5) + session("a", 5, od=6)
    assert len(segmenty(snimky)) == 2
    o = okna(snimky, dlzka=5)
    assert len(o) == 2
    assert [m["seq_od"] for m in o.meta] == [0, 6]


def test_casova_medzera_reze_usek_iba_ked_je_zadana():
    snimky = session("a", 8, perioda=2.0)
    # zmeskany slot: seq je spojite, ale medzi seq 3 a 4 je 20 s
    for s in snimky[4:]:
        s.cas_unix += 18.0
    assert len(okna(snimky, dlzka=4)) == 5
    o = okna(snimky, dlzka=4, max_medzera_s=5.0)
    assert len(o) == 2
    assert [m["seq_od"] for m in o.meta] == [0, 4]


def test_medzera_bez_casov_snimok_je_chyba():
    """Bez casov sa medzera overit neda a nesmie sa dopocitat z seq."""
    snimky = [Snimka("a", i, vektor("a", i), MENA) for i in range(6)]
    assert len(okna(snimky, dlzka=3)) == 4
    with pytest.raises(WindowError) as e:
        okna(snimky, dlzka=3, max_medzera_s=5.0)
    assert "cas" in str(e.value)


# -- riadky, ktore v okne byt nesmu --------------------------------------


def test_plna_snimka_uprostred_vynecha_okna_ktore_ju_obsahuju():
    """Plna snimka ma v priznakoch 1 az 7 iny vyznam nez delta riadky.

    Nie je to rez: snimky pred nou a po nej sa do okna skladaju dalej, iba
    okno, v ktorom ten riadok je, nevznikne.
    """
    o = okna(session("a", 20, plne=(10,)), dlzka=4)
    assert len(o) == 13                      # 17 kandidatov minus 4
    for m in o.meta:
        assert not (m["seq_od"] <= 10 <= m["seq_do"])
    assert o.pocty_vynechanych() == {DOVOD_PLNA: 4}
    assert {(v["seq_od"], v["seq_do"]) for v in o.vynechane} == {
        (7, 10), (8, 11), (9, 12), (10, 13)}
    # okna tesne pred plnou snimkou a tesne za nou existuju
    assert (6, 9) in {(m["seq_od"], m["seq_do"]) for m in o.meta}
    assert (11, 14) in {(m["seq_od"], m["seq_do"]) for m in o.meta}


def test_prva_snimka_retazca_je_plna_aj_bez_predchodcu():
    """Realny retazec: seq 0 je plna a zaroven nema predchodcu."""
    o = okna(session("a", 10, plne=(0,), bez_predchodcu=(0,)), dlzka=4)
    assert len(o) == 6                       # 7 kandidatov minus okno 0..3
    assert o.meta[0]["seq_od"] == 1
    assert o.pocty_vynechanych() == {DOVOD_PLNA: 1, DOVOD_PREDCHODCA: 1}
    assert o.vynechane[0]["dovody"] == sorted([DOVOD_PLNA,
                                               DOVOD_PREDCHODCA])


def test_riadok_bez_predchodcu_vynecha_okno():
    o = okna(session("a", 10, bez_predchodcu=(0,)), dlzka=4)
    assert len(o) == 6
    assert o.pocty_vynechanych() == {DOVOD_PREDCHODCA: 1}


def test_kratke_sedenie_nedava_okno_a_je_v_preskocenych():
    # realny retazec z 2026-09-19 ma 6 snimok; pri vychodzej dlzke 16 z neho
    # ziadne okno nevznikne a musi to byt vidno, nie odhalit sa prazdnym polom
    o = okna(session("a", 6), dlzka=DLZKA_OKNA)
    assert len(o) == 0
    assert o.X.shape == (0, DLZKA_OKNA, F)
    assert len(o.preskocene) == 1
    p = o.preskocene[0]
    assert p["session"] == "a" and p["n_snimok"] == 6
    assert "16" in p["dovod"]


# -- vyber a chyby vstupu ------------------------------------------------


def test_vyber_sessions_je_po_sedeniach():
    o = okna(session("a", 8) + session("b", 8, plne=(3,)), dlzka=4)
    iba_a = o.vyber_sessions(["a"])
    assert len(iba_a) == 5
    assert set(iba_a.sessions) == {"a"}
    # vynechane okna sa vyberaju s nimi, inak by sa pocty pripisali cudziemu
    # sedeniu
    assert iba_a.pocty_vynechanych() == {}
    assert o.vyber_sessions(["b"]).pocty_vynechanych() == {DOVOD_PLNA: 4}


def test_ine_poradie_priznakov_je_chyba():
    zle = list(MENA[1:]) + [MENA[0]]
    s = snimka("a", 0)
    s2 = Snimka("a", 1, vektor("a", 1), zle)
    with pytest.raises(WindowError):
        okna([s, s2], dlzka=2)


def test_prazdny_vstup_je_chyba():
    with pytest.raises(WindowError):
        okna([], dlzka=4)


# -- snimky z matice -----------------------------------------------------


def test_snimky_z_matice_citaju_priznaky_z_riadku():
    X = np.zeros((5, F))
    X[:, I_PRED] = 1.0
    X[0, I_PRED] = 0.0
    X[0, I_PLNA] = 1.0
    X[3, I_PLNA] = 1.0
    snimky = snimky_z_matice("a", X, MENA)
    assert [s.seq for s in snimky] == [0, 1, 2, 3, 4]
    assert [s.je_plna for s in snimky] == [True, False, False, True, False]
    assert [s.ma_predchodcu for s in snimky] == [False, True, True, True, True]
    assert snimky[0].dovody() == (DOVOD_PLNA, DOVOD_PREDCHODCA)
    assert snimky[1].dovody() == ()
    assert snimky[0].cas_unix is None


def test_snimky_z_matice_bez_priznaku_je_plna_je_chyba():
    bez = tuple(m for m in MENA if m != "je_plna")
    with pytest.raises(WindowError) as e:
        snimky_z_matice("a", np.zeros((3, len(bez))), bez)
    assert "je_plna" in str(e.value)


def test_snimky_z_matice_odmietnu_iny_tvar():
    with pytest.raises(WindowError):
        snimky_z_matice("a", np.zeros((3, F - 1)), MENA)


def test_indikator_mimo_0_1_je_chyba():
    X = np.zeros((2, F))
    X[:, I_PRED] = 1.0
    X[1, I_PLNA] = 0.5
    with pytest.raises(WindowError) as e:
        snimky_z_matice("a", X, MENA)
    assert "je_plna" in str(e.value)


# -- determinizmus -------------------------------------------------------


def test_determinizmus_dvoch_behov():
    s1 = session("a", 12) + session("b", 12)
    s2 = session("a", 12) + session("b", 12)
    o1 = okna(s1, dlzka=5)
    o2 = okna(s2, dlzka=5)
    assert np.array_equal(o1.X, o2.X)
    assert o1.meta == o2.meta


def test_poradie_na_vstupe_nemeni_vysledok():
    snimky = session("a", 10) + session("b", 10, plne=(4,))
    o1 = okna(snimky, dlzka=4)
    o2 = okna(list(reversed(snimky)), dlzka=4)
    assert np.array_equal(o1.X, o2.X)
    assert o1.meta == o2.meta
    assert o1.vynechane == o2.vynechane
