"""
Testy detekcnych metrik (blok H): FAR/h, cas-do-detekcie, per-technika.

Vsetko na syntetickych skore - overuje sa LOGIKA vyhladavania alarmu a
pocitania, nie detekcia (HONESTY P4).
"""

import numpy as np
import pytest

from tcn.eval import cas_do_detekcie, detekcia_per_technika, far_h


def test_far_h_prepocet_na_hodiny():
    # 3600 okien pri 1 s = 1 hodina; 10 nad prahom -> 10 FAR/h
    skore = np.zeros(3600)
    skore[:10] = 1.0
    res = far_h(skore, prah=0.5, perioda_s=1.0)
    assert res["n"] == 3600
    assert res["nad_prahom"] == 10
    assert res["far_h"] == pytest.approx(10.0)


def test_far_h_prazdny_vstup():
    res = far_h([], prah=0.5)
    assert res["far_h"] is None and "ziadne" in res["poznamka"]


def test_cas_do_detekcie_k_z_n():
    # 20 okien, 2 s; 1 od indexu 10 - prve okno s 3 z 5 je i=8
    # (8,9,10,11,12 -> tri jednotky) -> t = 8*2 = 16 s
    skore = np.zeros(20)
    skore[10:16] = 1.0
    r = cas_do_detekcie(skore, prah=0.5, k=3, n=5, perioda_s=2.0)
    assert r["detegovany"] is True
    assert r["cas_s"] == pytest.approx(16.0)


def test_cas_do_detekcie_bez_alarmu():
    skore = np.zeros(20)
    r = cas_do_detekcie(skore, prah=0.5, k=3, n=5)
    assert r["detegovany"] is False
    assert r["cas_s"] is None


def test_cas_do_detekcie_samotny_skok_nedeteguje():
    # jedno okno nad prahom nikdy nesplni 3 z 5
    skore = np.zeros(20)
    skore[10] = 1.0
    r = cas_do_detekcie(skore, prah=0.5, k=3, n=5)
    assert r["detegovany"] is False


def test_detekcia_per_technika_agreguje():
    behy = [
        {"label": "diamorphine", "skore": np.r_[np.zeros(9), np.ones(6)],
         "t0_s": 0.0},
        {"label": "diamorphine", "skore": np.zeros(15), "t0_s": 0.0},
        {"label": "hider", "skore": np.r_[np.zeros(9), np.ones(6)],
         "t0_s": 0.0},
    ]
    out = detekcia_per_technika(behy, prah=0.5, k=3, n=5, perioda_s=5.0)
    assert out["diamorphine"]["n_behov"] == 2
    assert out["diamorphine"]["detegovanych"] == 1
    assert out["diamorphine"]["detekcia_podiel"] == 0.5
    # ttd = prve okno s 3 z 5 jednotiek (indexy 9..14 -> i=7 -> 35 s);
    # nedetegovany beh sa do medianu ttd NEPOCITA
    assert out["diamorphine"]["ttd_s"] == [35.0]
    assert out["hider"]["detegovanych"] == 1
    assert out["hider"]["ttd_median_s"] == pytest.approx(35.0)
