"""
Testy predikcie normalu (E1/E2) a kalibracie (E3).

Overuje sa MECHANIKA na syntetike - ziadne cislo tu nie je vysledok detekcie
(HONESTY P4): kauzalita prediktora, posun vstup/ciel (ciel NESMIE byt v
okne - inak sa uloha zdegeneruje na kopirovanie), pokles MSE pod rozptyl
ciela na predpovedatelnej syntetike, vylucenie indikatorov zo skore a
kvantilova kalibracia s rozpoctom FP.
"""

import numpy as np
import pytest
import torch

from tcn.kalibracia import kalibracia, okien_za_den, skore_okna_z_chyb
from tcn.model import TCNPrediktor
from tcn.train import (beh_predikcia, chyba_predikcie, priprav_predikcia,
                       syn_sessions_predikcia)


def test_prediktor_je_kauzalny():
    """Zmena vstupu v case t+1 nesmie zmenit predpoved v case t."""
    torch.manual_seed(0)
    m = TCNPrediktor(4, kanaly=4, dlzka_okna=8)
    m.eval()
    x = torch.randn(2, 8, 4)
    y1 = m(x, po_krokoch=True)
    x[:, 7, :] += 100.0
    y2 = m(x, po_krokoch=True)
    assert torch.allclose(y1[:, :7, :], y2[:, :7, :], atol=1e-5)


def test_priprav_predikcia_posuva_vstup_oproti_cielu():
    """Ciel (krok t) nesmie byt sucastou vstupu - vstup ma L-1 krokov."""
    sessions = syn_sessions_predikcia(seed=1, na_sessions=4, dlzka=40)
    data = priprav_predikcia(sessions, dlzka=16, podiel=0.6)
    assert data["X_train"].shape[1] == 15
    assert data["y_train"].shape == (data["X_train"].shape[0],
                                     data["X_train"].shape[2])
    # y_test su kroky 16..39 sedeni - ziadne prelievanie medzi castami
    assert set(data["train_sessions"]).isdisjoint(data["test_sessions"])


def test_beh_predikcia_sa_nauci_predpovedat_sinusoidu():
    """Predpovedatelna syntetika: MSE musi klesnut vyrazne pod var ciela."""
    sessions = syn_sessions_predikcia(seed=2, na_sessions=4, dlzka=60)
    data = priprav_predikcia(sessions, dlzka=16, podiel=0.5)
    vysledky = beh_predikcia(data, seed=0, epochy=80)
    assert vysledky["mse_na_var"] < 0.5, vysledky


def test_priprav_predikcia_odmietne_sedenia_bez_peciatky():
    sessions = syn_sessions_predikcia(seed=1, na_sessions=2)
    sessions[0]["meno"] = "bez_peciatky"
    with pytest.raises(ValueError):
        priprav_predikcia(sessions)


# ---------------------------------------------------------------- E3


def test_okien_za_den_zakladne_periody():
    assert okien_za_den(1.0) == 86400
    assert okien_za_den(5.0) == 17280
    assert okien_za_den(2.0) == 43200


def test_kalibracia_kvantil_a_rozpocet():
    """FPR okna zmerany na validacii musi sediet s rozpoctom (kvantil)."""
    rng = np.random.default_rng(0)
    chyby = rng.exponential(1.0, size=17280)      # den benígnych okien pri 5 s
    res = kalibracia(chyby, perioda_s=5.0, fp_za_den=1.0, k=2, n=4)
    assert res["fpr_okno_rozpocet"] == pytest.approx(1.0 / 17280)
    # zmerane: ~1 okno z 17280 je nad prahom (kvantil z konstrukcie)
    assert 0 < res["fpr_okno_odmerane"] <= 5e-4
    assert res["alarm_k_z_n"] == [2, 4]
    assert res["far_h_odhad"] is not None and res["far_h_odhad"] >= 0


def test_kalibracia_k_z_n_neprepocitava_nezavisle_okna():
    """Okna sa prekryvaju - teoreticka binomicka veta sa NEPOUZIVA, alarmy
    sa meraju na validacii (toto drzi kontrakt rozhrania, nie cislo)."""
    rng = np.random.default_rng(1)
    chyby = rng.exponential(1.0, size=2000)
    # 2000 okien pri 1 s = 0,023 dna; rozpočet 200 FP/den da ~4,6 okna nad
    # prahom - kvantil ma z coho byt kvantilom
    res = kalibracia(chyby, perioda_s=1.0, fp_za_den=200.0, k=3, n=5)
    assert res["alarmov_odmerane"] >= 0
    assert res["n_okien"] == 2000


def test_kalibracia_odmietne_malu_validaciu():
    with pytest.raises(ValueError):
        kalibracia(np.ones(50), perioda_s=5.0)


def test_kalibracia_odmietne_rozpocet_bez_okna_nad_prahom():
    with pytest.raises(ValueError):
        kalibracia(np.ones(100), perioda_s=5.0, fp_za_den=1e-9)


def test_skore_okna_z_chyb_priemeruje():
    chyby = np.array([[1.0, 2.0], [3.0, 5.0]])
    assert np.allclose(skore_okna_z_chyb(chyby), [1.5, 4.0])


# ---------------------------------------------------------------- E2


def test_chyba_predikcie_okna_vynechava_indikatory():
    from tcn.score import chyba_predikcie_okna
    from features.normalize import Normalizer
    from features.snapshot import MENA

    class NulovyModel:
        def __call__(self, x):
            return torch.zeros(x.shape[0], len(MENA))

    norm = Normalizer(priznaky=MENA, nenormalizovane=("ma_predchodcu",
                                                      "je_plna"))
    # mu=0, sd=1 pre vsetko -> transform = identita
    m = Manifest_stub()
    norm._mu = np.zeros(len(MENA))
    norm._sd = np.ones(len(MENA))
    norm._manifest = m

    okno = [np.ones(len(MENA)) for _ in range(4)]
    sk1, chyby1, _ = chyba_predikcie_okna(NulovyModel(), norm, okno)

    # zmen iba indikator je_plna v poslednom kroku - skore sa nesmie zmenit
    okno2 = [np.array(v) for v in okno]
    okno2[-1][MENA.index("je_plna")] = 0.0
    sk2, chyby2, _ = chyba_predikcie_okna(NulovyModel(), norm, okno2)
    assert sk1 == pytest.approx(sk2)
    assert chyby1[MENA.index("je_plna")] != pytest.approx(
        chyby2[MENA.index("je_plna")])


class Manifest_stub:
    """Normalizer.transform potrebuje len manifest.overit (tu ziadne kontroly)."""
    def overit(self, priznaky=None):
        return None
