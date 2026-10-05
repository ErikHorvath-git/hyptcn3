"""
Testy hodnotenia z artefaktov (H): kalibracia -> FAR/h -> detekcia per
technika nad syntetickymi skore. Overuje sa LOGIKA skladania, nie detekcia.
"""

import numpy as np
import pytest

from tcn.hodnotenie import hodnotenie


def _sedenia(n_benign=4, n_malicious=2, n_okien=2000, seed=0,
              aktivne=True):
    rng = np.random.default_rng(seed)
    sed = {}
    for i in range(n_benign):
        m = "202601%02dT000000Z_idle_benign" % i
        sed[m] = {"typ": "benign", "label": "idle",
                  "skore": rng.exponential(1.0, size=n_okien)}
    for i in range(n_malicious):
        m = "202602%02dT000000Z_utok_malicious" % i
        skore = rng.exponential(1.0, size=n_okien)
        skore[n_okien // 2:] += 5.0          # jasna anomalia v druhej polke
        sed[m] = {"typ": "malicious", "label": "utok", "skore": skore,
                  "aktivny": aktivne}
    return sed


def test_hodnotenie_sklada_kalibraciu_far_a_detekciu():
    sed = _sedenia(seed=0)
    # fp_za_den=50 pri 200 okien/5s: FPR*200 = 5.8 okien nad prahom -
    # kvantil ma z coho byt kvantilom aj na takto malej syntetike
    res = hodnotenie(sed, perioda_s=5.0, fp_za_den=50.0, k=2, n=4)
    kal = res["kalibracia"]
    assert kal["n_okien"] > 0
    assert res["far_h"]["far_h"] is not None
    # utok ma jasnu anomaliu -> detekcia musi najst vsetky aktivne behy
    det = res["detekcia_per_technika"]["utok"]
    assert det["n_behov"] == 2
    assert det["detegovanych"] == 2
    assert det["ttd_median_s"] is not None


def test_neaktivny_beh_sa_do_detekcie_nepocita():
    sed = _sedenia(n_malicious=2, aktivne=False)
    res = hodnotenie(sed, perioda_s=5.0, fp_za_den=50.0, k=2, n=4)
    assert res["detekcia_per_technika"] == {}
    assert len(res["neaktivne_vynechane"]) == 2


def test_malo_benignych_sedeni_je_chyba():
    sed = _sedenia(n_benign=1, n_malicious=0)
    with pytest.raises(ValueError):
        hodnotenie(sed, fp_za_den=50.0)
