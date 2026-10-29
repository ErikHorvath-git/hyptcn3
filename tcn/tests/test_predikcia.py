"""
Testy predikcie normalu (E1/E2) a anomalnych baselinov (F).

Overuje sa MECHANIKA na syntetike - ziadne cislo tu nie je vysledok detekcie
(HONESTY P4): kauzalita prediktora, posun vstup/ciel (ciel NESMIE byt v
okne - inak sa uloha zdegeneruje na kopirovanie), pokles MSE pod rozptyl
ciela na predpovedatelnej syntetike a vylucenie indikatorov zo skore.
"""

import numpy as np
import pytest
import torch

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
    assert vysledky["tcn_prediktor"]["mse_na_var"] < 0.5, vysledky
    # GRU baseline bezi na tych istych datach a tiez musi nieco vediet
    assert vysledky["gru_prediktor"]["mse_na_var"] < 0.8, vysledky
    assert vysledky["zscore"]["skore_test"]["n"] > 0


def test_konfunder_podskupina_sa_nauci_iba_predpovedatelny_signal():
    """Orezana podmnozina priznakov: mechanika funguje (signalova podskupina
    sa nauci). Samotne porovnanie 'zatazove priznaky nesmu dorovnat plny
    model' patri do H nad realnymi datami - tu sa overuje len to, ze
    podskupinovy beh bez stitkov bezi a reportuje."""
    from tcn.train import beh_konfunder
    from features.snapshot import MENA
    sessions = syn_sessions_predikcia(seed=5, na_sessions=4, dlzka=60)
    data = priprav_predikcia(sessions, dlzka=16, podiel=0.5)
    v = beh_konfunder(data, ("mem_changed_ratio", "proc_total"), epochy=60)
    assert v["priznakov"] == 2
    assert v["podskupina"] == ["mem_changed_ratio", "proc_total"]
    assert v["tcn_prediktor"]["mse_na_var"] >= 0.0
    v2 = beh_konfunder(data, MENA[:2], epochy=60)
    assert v2["tcn_prediktor"]["mse_na_var"] < 0.5


def test_priprav_predikcia_odmietne_sedenia_bez_peciatky():
    sessions = syn_sessions_predikcia(seed=1, na_sessions=2)
    sessions[0]["meno"] = "bez_peciatky"
    with pytest.raises(ValueError):
        priprav_predikcia(sessions)


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


# ------------------------------------------------------- F: anomálne baseliny


def test_zscore_ignoruje_indikatory():
    from tcn.baselines import ZScoreAnomalia
    priznaky = ("proc_total", "je_plna", "ma_predchodcu")
    zs = ZScoreAnomalia(priznaky)
    rng = np.random.default_rng(0)
    X = rng.normal(size=(50, 4, 3))
    X[:, :, 1] = 0.0
    X[:, :, 2] = 1.0
    zs.fit(X)
    assert zs.mask.tolist() == [True, False, False]
    s1 = zs.skore(X)
    X2 = X.copy()
    X2[:, :, 1] = 1.0                       # zmen len indikator je_plna
    s2 = zs.skore(X2)
    assert np.allclose(s1, s2)


def test_isolation_forest_deterministicky_s_rovnakym_seedom():
    from tcn.baselines import IsolationForestAnomalia
    rng = np.random.default_rng(3)
    X = rng.normal(size=(120, 8, 4))
    a = IsolationForestAnomalia(seed=7).fit(X).skore(X)
    b = IsolationForestAnomalia(seed=7).fit(X).skore(X)
    assert np.allclose(a, b)
    c = IsolationForestAnomalia(seed=8).fit(X).skore(X)
    assert not np.allclose(a, c)


def test_gru_prediktor_je_kauzalny():
    from tcn.baselines import GRUPrediktor
    torch.manual_seed(0)
    m = GRUPrediktor(4, 8)
    m.eval()
    x = torch.randn(2, 8, 4)
    y1 = m(x, po_krokoch=True)
    x[:, 7, :] += 100.0
    y2 = m(x, po_krokoch=True)
    assert torch.allclose(y1[:, :7, :], y2[:, :7, :], atol=1e-5)
