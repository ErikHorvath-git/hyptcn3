"""
Testy modelu a celeho retazca nad SYNTETICKYMI datami.

Korpus zatial neexistuje, tak sa testuje to, co od dat nezavisi: kauzalita,
recepcne pole, ze sa split nemiesa, ze je beh deterministicky a ze sa model
na trivialnej ulohe naozaj nauci. Ziadne cislo z tychto testov nie je
vysledok prace - synteticke data nic o detekcii nehovoria.
"""

import numpy as np
import pytest
import torch

from features.snapshot import MENA
from tcn.baselines import BagOfFrames, skryte_pre_parametre
from tcn.model import TCN, pocet_parametrov, recepcne_pole, skontroluj_rf
from tcn.train import (beh, okna_zo_session, priprav, split_chronologicky,
                       syn_sessions)

F = len(MENA)


def _model(seed=0, **kw):
    torch.manual_seed(seed)
    m = TCN(F, 2, **kw)
    m.eval()          # bez dropoutu, aby bol vystup funkciou vstupu
    return m


def test_kauzalita():
    """Zmena vstupu v case t+1 nesmie zmenit vystup v case t."""
    m = _model()
    torch.manual_seed(1)
    x = torch.randn(2, 16, F)
    with torch.no_grad():
        y = m(x, po_krokoch=True)
        for t in range(15):
            x2 = x.clone()
            x2[:, t + 1:, :] += 5.0          # zmena vsetkeho po case t
            y2 = m(x2, po_krokoch=True)
            assert torch.allclose(y[:, :t + 1], y2[:, :t + 1], atol=1e-6), \
                "vystup v case %d sa zmenil po zmene vstupu v case %d" % (t, t + 1)


def test_recepcne_pole():
    """Zmerany dosah cez gradienty sedi so vzorcom RF = 1+2*(k-1)*(2^B-1)."""
    k, blokov, L = 3, 3, 64
    rf = recepcne_pole(k, blokov)
    assert rf == 29
    m = _model(seed=2, k=k, blokov=blokov, dropout=0.0)
    x = torch.randn(1, L, F, requires_grad=True)
    m(x)[0, 0].backward()
    dotknute = (x.grad.abs().sum(dim=2)[0] > 0).nonzero().flatten().tolist()
    assert min(dotknute) == L - rf, \
        "model siaha do %d krokov, vzorec hovori %d" % (L - min(dotknute), rf)
    assert max(dotknute) == L - 1


def test_rf_kratsie_nez_okno_je_chyba():
    with pytest.raises(ValueError):
        skontroluj_rf(64, 3, 3)          # RF 29 < okno 64
    with pytest.raises(ValueError):
        TCN(F, 2, k=3, blokov=3, dlzka_okna=64)


def test_maly_pocet_parametrov():
    n = pocet_parametrov(TCN(F, 2))
    assert n == 5330, n                  # radovo tisice, nie miliony


def test_gru_ma_porovnatelny_pocet_parametrov():
    ciel = pocet_parametrov(TCN(F, 2))
    _, n = skryte_pre_parametre(F, 2, ciel)
    assert abs(n - ciel) / ciel < 0.05


def test_split_nemiesa_sessions():
    s = syn_sessions(0)
    tr, te = split_chronologicky(s, 0.6)
    assert set(tr) & set(te) == set()
    assert set(tr) | set(te) == {x["meno"] for x in s}
    trieda = {x["meno"]: x["trieda"] for x in s}
    for t in {x["trieda"] for x in s}:            # obe casti maju vsetky triedy
        assert any(trieda[m] == t for m in tr) and any(trieda[m] == t for m in te)
    for m in tr:                                  # trenovacie su starsie
        assert all(m < n for n in te if trieda[n] == trieda[m])
    d = priprav(s)
    assert set(d["train_sessions"]) & set(d["test_sessions"]) == set()
    assert all(d["triedy"][i] == "idle" for i in [d["benigna"]])


def test_okna_bez_predchodcu_sa_vynechaju():
    """Riadok s ma_predchodcu=0 nesmie zostat v datach."""
    s = syn_sessions(0)
    d = priprav(s, dlzka=16)
    assert d["okien_bez_predchodcu"] == len(s)    # prva snimka kazdej session
    i = MENA.index("ma_predchodcu")
    # po normalizacii je stlpec nemeneny (je v nenormalizovanych), takze 1.0
    assert (d["X_train"][:, :, i] == 1.0).all()
    assert (d["X_test"][:, :, i] == 1.0).all()


def test_okna_neprekrocia_session():
    X = np.arange(40 * F, dtype=np.float64).reshape(40, F)
    W = okna_zo_session(X, 16)
    assert W.shape == (25, 16, F)
    assert okna_zo_session(X[:10], 16).shape == (0, 16, F)


def test_bag_of_frames_nevidi_poradie():
    """Permutacia casu nesmie zmenit vstup bag-of-frames modelu."""
    rng = np.random.default_rng(0)
    X = rng.normal(size=(5, 16, F))
    b = BagOfFrames(2)
    assert np.allclose(b.vstup(X), b.vstup(X[:, ::-1, :]))


def test_trening_konverguje():
    """Trivialna uloha (trieda urcena jednym priznakom) sa ma naucit."""
    d = priprav(syn_sessions(0))
    v = beh(d, seed=0, epochy=20)
    assert v["tcn"]["binarne"]["f1"] > 0.9, v["tcn"]["binarne"]


def test_determinizmus():
    d = priprav(syn_sessions(0))
    a = beh(d, seed=0, epochy=5)
    b = beh(d, seed=0, epochy=5)
    for meno in a:
        assert a[meno]["viactriedne"] == b[meno]["viactriedne"], meno
        assert a[meno]["binarne"] == b[meno]["binarne"], meno


def test_tcn_prekona_bag_of_frames_ked_rozhoduje_poradie():
    """Kontrola kontroly: na ulohe, kde rozhoduje iba poradie, ma TCN vyhrat.

    Obe triedy maju rovnaky priemer aj odchylku cez okno, takze bag-of-frames
    a logisticka regresia na nich nemaju z coho rozhodnut. Keby aj tak vyhrali,
    znamenalo by to, ze do dat unikol iny rozdiel - a potom by ten baseline
    nemeral to, co ma merat.
    """
    d = priprav(syn_sessions(0, na_triedu=6, dlzka=64, rezim="poradie"))
    v = beh(d, seed=0, epochy=40)
    assert v["tcn"]["viactriedne"]["presnost"] > 0.9
    assert v["bag_of_frames"]["viactriedne"]["presnost"] < 0.7
    assert v["logreg_priemer"]["viactriedne"]["presnost"] < 0.7


def test_split_neprepusta_identitu_session():
    """Bez signalu nesmie ziadny model prekonat nahodu.

    V rezime "sum" nesie label iba to, z ktorej session okno pochadza. Susedne
    okna zdielaju 15 zo 16 snimok, takze model si session zapamata lahko - a
    presne tak vznikli nafuknute cisla v hypTcn002 (HONESTY.md, kapitola 2).
    Ked je split po sessions, testovacia session v treningu nebola a presnost
    musi spadnut k nahode. Toto je behavioralny test splitu: test_split_nemiesa_
    sessions kontroluje mnoziny mien, tento kontroluje dosledok.
    """
    d = priprav(syn_sessions(0, na_triedu=6, dlzka=64, rezim="sum"))
    v = beh(d, seed=0, epochy=40)
    for meno, r in v.items():
        assert r["viactriedne"]["presnost"] < 0.75, (meno, r["viactriedne"])


def test_trieda_bez_testovacich_okien_nema_metriky():
    """Trieda, ktora v teste nie je, ma null a poznamku, nie nulu."""
    s = syn_sessions(0, na_triedu=2)
    s.append({"meno": "20260109T000000Z_vzacna", "trieda": "vzacna",
              "matica": s[0]["matica"].copy()})       # jedina session triedy
    d = priprav(s)
    v = beh(d, seed=0, epochy=2)["tcn"]["viactriedne"]
    assert v["na_triedu"]["vzacna"]["f1"] is None
    assert v["na_triedu"]["vzacna"]["n"] == 0
    assert "vzacna" not in v["f1_macro_nad_triedami"]
