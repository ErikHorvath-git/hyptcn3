"""
Testy per-bin okien (blok D): tvar (N, L, F + B*4) popri agregovanom (N, L, F).

Synteticke casti bezia vzdy; test nad realnym retazcom s C sidecarmi
(/var/tmp/perbin_c/on) sa preskoci, ked data na stroji nie su - rovnaky vzor
ako pri ostatnych testoch, ktore potrebuju retazce z /var/tmp.
"""

import hashlib
import json
import os

import numpy as np
import pytest

from features.snapshot import MENA
from features.windows import (BIN_PRIZNAKY, Snimka, WindowError, okna,
                              okna_s_perbin, perbin_zo_sidecaru)

F = len(MENA)
I_PLNA = MENA.index("je_plna")
I_PRED = MENA.index("ma_predchodcu")

BINY_REAL = (0, 1, 2)          # synteticke biny testu (realne je ich 131)
B = len(BINY_REAL)
RETAZEC_C = "/var/tmp/perbin_c/on"


def _rng(kluc):
    """Seed zo SHA-256, nie z hash(): ten je pre retazce randomizovany na
    proces, takze dva behy testu by mohli dat ine cisla."""
    digest = hashlib.sha256(kluc.encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "big"))


def vektor(session, seq):
    x = _rng("%s|%d" % (session, seq)).random(F)
    x[I_PLNA] = 0.0
    x[I_PRED] = 1.0
    return x


def perbin(session, seq):
    """Deterministicka (B, 4) matica s rozpoznatelnymi hodnotami."""
    return _rng("pb|%s|%d" % (session, seq)).random((B, 4))


def snimka(session, seq, s_perbin=True):
    x = vektor(session, seq)
    if s_perbin:
        return Snimka(session=session, seq=seq, x=x, priznaky=MENA,
                      x_perbin=perbin(session, seq), biny=BINY_REAL)
    return Snimka(session=session, seq=seq, x=x, priznaky=MENA)


def session(meno, n, s_perbin=True):
    return [snimka(meno, s, s_perbin=s_perbin) for s in range(n)]


# -- tvar -----------------------------------------------------------------


def test_tvar_okna_s_perbin_je_okna_cas_priznaky_plus_biny():
    o = okna_s_perbin(session("a", 20), dlzka=8)
    assert o.X.shape == (13, 8, F + B * 4)
    assert o.tvar == "snimka+perbin"
    assert o.b == B
    assert o.biny == BINY_REAL
    assert o.bin_priznaky == BIN_PRIZNAKY
    assert o.priznaky == MENA
    # agregovany tvar sa nezmenil
    o2 = okna(session("a", 20), dlzka=8)
    assert o2.X.shape == (13, 8, F)
    assert o2.tvar == "snimka"


def test_poradie_stlpcov_snimka_potom_perbin_bin_major():
    """Stlpce: najprv F snimkovych priznakov, potom per-bin bin-major v poradi
    BIN_PRIZNAKY - presne v tomto poradi ich musi citat model."""
    o = okna_s_perbin(session("a", 10), dlzka=4)
    prva = o.X[0, 0]                      # riadok prvej snimky prveho okna
    s0 = snimka("a", 0)
    assert np.array_equal(prva[:F], s0.x)
    assert np.array_equal(prva[F:], s0.x_perbin.reshape(-1))
    # bunka binu i, priznaku j sedi s maticou vstupu
    i_bin, j = 1, 2
    idx = F + i_bin * 4 + j
    assert prva[idx] == s0.x_perbin[i_bin, j]
    assert BIN_PRIZNAKY[j] == "entropy_mean"


def test_okna_s_perbin_dedi_hranice_a_zamietane_riadky():
    """Plna snimka a riadok bez predchodcu zamietaju okno aj pri per-bin
    tvare - per-bin blok na tom nic nemeni."""
    sn = session("a", 20)
    sn[10] = Snimka(session="a", seq=10, x=vektor("a", 10), priznaky=MENA,
                    je_plna=True, x_perbin=perbin("a", 10), biny=BINY_REAL)
    o = okna_s_perbin(sn, dlzka=4)
    assert len(o) == 13
    for m in o.meta:
        assert not (m["seq_od"] <= 10 <= m["seq_do"])
    assert o.pocty_vynechanych() == {"plna snimka": 4}


# -- chyby vstupu ----------------------------------------------------------


def test_rozlicne_biny_v_retazci_su_chyba():
    sn = session("a", 5)
    sn[2] = Snimka(session="a", seq=2, x=vektor("a", 2), priznaky=MENA,
                   x_perbin=perbin("a", 2), biny=(0, 1, 3))
    with pytest.raises(WindowError) as e:
        okna_s_perbin(sn, dlzka=3)
    assert "biny" in str(e.value)


def test_chybajuci_perbin_blok_je_chyba():
    with pytest.raises(WindowError) as e:
        okna_s_perbin(session("a", 5, s_perbin=False), dlzka=3)
    assert "per-bin" in str(e.value)


def test_snimka_odmietne_neusporiadane_alebo_duplicitne_biny():
    with pytest.raises(WindowError):
        Snimka("a", 0, vektor("a", 0), MENA, x_perbin=np.zeros((2, 4)),
               biny=(1, 0))
    with pytest.raises(WindowError):
        Snimka("a", 0, vektor("a", 0), MENA, x_perbin=np.zeros((2, 4)),
               biny=(0, 0))


def test_snimka_odmietne_zly_tvar_perbin_matice():
    with pytest.raises(WindowError):
        Snimka("a", 0, vektor("a", 0), MENA, x_perbin=np.zeros((3, 3)),
               biny=(0, 1, 2))
    with pytest.raises(WindowError):
        Snimka("a", 0, vektor("a", 0), MENA, x_perbin=np.zeros((3, 4)),
               biny=(0, 1))


# -- loader zo sidecaru -----------------------------------------------------


def test_perbin_zo_sidecaru_cita_a_radi_biny(tmp_path):
    doc = {
        "features": {
            "bin_bytes": 16 * 1024 * 1024,
            "bins": [
                {"bin": 9, "gpa": 0, "pages_total": 10, "pages_changed": 2,
                 "changed_ratio": 0.2, "zero_ratio": 0.8, "entropy_mean": 1.5,
                 "has_changed": 1},
                {"bin": 1, "gpa": 0, "pages_total": 10, "pages_changed": 0,
                 "changed_ratio": 0.0, "zero_ratio": 1.0, "entropy_mean": 0.0,
                 "has_changed": 0},
            ],
        },
    }
    p = tmp_path / "side.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    biny, matica = perbin_zo_sidecaru(str(p))
    assert biny == (1, 9)
    assert matica.shape == (2, 4)
    assert list(matica[1]) == pytest.approx([0.2, 0.8, 1.5, 1.0])
    assert list(matica[0]) == pytest.approx([0.0, 1.0, 0.0, 0.0])


def test_perbin_zo_sidecaru_odmietne_blok_bez_bins(tmp_path):
    p = tmp_path / "side.json"
    p.write_text(json.dumps({"features": {}}), encoding="utf-8")
    with pytest.raises(WindowError) as e:
        perbin_zo_sidecaru(str(p))
    assert "bins" in str(e.value)


def test_perbin_zo_sidecaru_odmietne_entropiu_pri_has_changed_0(tmp_path):
    doc = {"features": {"bins": [
        {"bin": 0, "gpa": 0, "pages_total": 10, "pages_changed": 0,
         "changed_ratio": 0.0, "zero_ratio": 1.0, "entropy_mean": 0.5,
         "has_changed": 0}]}}
    p = tmp_path / "side.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(WindowError) as e:
        perbin_zo_sidecaru(str(p))
    assert "has_changed=0" in str(e.value)


# -- crosscheck s C: per-bin blok okna = blok z C sidecaru -------------------


@pytest.mark.skipif(not os.path.isdir(RETAZEC_C),
                    reason="retazec delta snimok s C sidecarmi nie je na "
                           "tomto stroji: %s" % RETAZEC_C)
def test_okno_nesie_perbin_hodnoty_z_c_sidecaru_bez_zmeny():
    """Hodnoty per-bin bloku v okne sa rovnaju bloku, ktory zapisal C modul do
    sidecaru (riadok po riadku, po zoradeni binov). Snimkova cast sa tu
    nekontroluje - na nu je features/crosscheck a testy snapshot.py."""
    parts = sorted(os.listdir(RETAZEC_C))
    sides = [f for f in parts if f.endswith(".json")]
    sn = []
    for i, f in enumerate(sides):
        biny, matica = perbin_zo_sidecaru(os.path.join(RETAZEC_C, f))
        x = np.zeros(F)
        x[I_PRED] = 1.0
        sn.append(Snimka(session="c", seq=i, x=x, priznaky=MENA,
                         x_perbin=matica, biny=biny))
    o = okna_s_perbin(sn, dlzka=4)
    # realna VM: 131 binov @ 16 MiB (hyptcn-guest)
    assert o.b == 131
    assert o.X.shape == (3, 4, F + 131 * 4)
    for i, f in enumerate(sides):
        biny, matica = perbin_zo_sidecaru(os.path.join(RETAZEC_C, f))
        videna = False
        for n in range(len(o)):
            for t in range(o.dlzka):
                if o.meta[n]["seq_od"] + t == i:
                    assert np.array_equal(
                        o.X[n, t, F:], matica.reshape(-1)), \
                        "snimka %s: per-bin blok okna sa lisi od sidecaru C" % f
                    videna = True
        assert videna, "snimka %s nie je v ziadnom okne" % f
