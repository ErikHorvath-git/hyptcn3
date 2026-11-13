"""
Testy porovnania s baselinmi nad vstupmi safeguardu (tcn/porovnanie.py, E4).

Iba MECHANIKA na syntetickom diagnostickom korpuse (safeguard.demo) - ziadne
cislo tu nie je vysledok detekcie (HONESTY P4): pocet parametrov LSTM/GRU
voci TCN, ten isty prah a pravidlo k z n ako safeguard, tvar prehratia
citatelny evaluatorom tcn.eval a 8 globalnych stlpcov pamatovej ablacie.
"""

import json
from collections import deque

import numpy as np
import pytest
import torch
from torch import nn

from safeguard.demo import create_corpus
from safeguard.model import Predictor, architecture
from safeguard.training import calibrate
from tcn import eval as ev
from tcn import porovnanie as po
from tcn.baselines import GRUPrediktor, LSTMPrediktor, skryte_pre_prediktor
from tcn.model import pocet_parametrov


@pytest.fixture(scope="module")
def korpus(tmp_path_factory):
    torch.set_num_threads(2)
    return create_corpus(tmp_path_factory.mktemp("porovnanie") / "korpus")


@pytest.fixture(scope="module")
def modely(korpus, tmp_path_factory):
    koren = tmp_path_factory.mktemp("modely")
    out = {}
    for meno in ("zscore", "lstm", "tcn_pamat"):
        po.fit(korpus, meno, koren / meno, seed=0, epochy=1, davka=64, fpr=0.05, diagnostic=True)
        out[meno] = koren / meno
    return out


def test_lstm_a_gru_maju_pocet_parametrov_najblizsie_k_tcn():
    ciel = pocet_parametrov(Predictor(architecture(32)))
    for trieda in (GRUPrediktor, LSTMPrediktor):
        h, n = skryte_pre_prediktor(trieda, len(po.ZLUCENE), len(po.CIEL), ciel)
        vedla = [pocet_parametrov(trieda(len(po.ZLUCENE), x, len(po.CIEL))) for x in (h - 1, h + 1)]
        assert n == pocet_parametrov(trieda(len(po.ZLUCENE), h, len(po.CIEL)))
        assert all(abs(n - ciel) <= abs(v - ciel) for v in vedla)
        assert abs(n - ciel) / ciel < 0.05
    assert isinstance(LSTMPrediktor(26, 8, 24).gru, nn.LSTM)
    assert LSTMPrediktor(26, 8, 24)(torch.zeros(2, 7, 26)).shape == (2, 24)
    assert GRUPrediktor(4, 3)(torch.zeros(1, 5, 4)).shape == (1, 4)  # povodne spravanie


def test_neznamy_model_a_existujuci_vystup(korpus, tmp_path):
    with pytest.raises(ValueError, match="neznamy model"):
        po.fit(korpus, "svm", tmp_path / "x", diagnostic=True)
    (tmp_path / "y").mkdir()
    with pytest.raises(FileExistsError):
        po.fit(korpus, "zscore", tmp_path / "y", diagnostic=True)


def test_prah_je_ten_isty_ako_safeguard_na_tych_istych_skore(korpus, modely):
    d = po.nacitaj_role(korpus, diagnostic=True)
    for meno, adresar in modely.items():
        balik = po.nacitaj(adresar, allow_diagnostic=True)
        kal = d["data"]["calibration"]
        w = kal.window_rows
        # Skore cez rozhranie balika (to iste, ktore vola Detector) po jednom okne.
        skore = [balik.score(kal.sessions[s][1][e + 1 - w:e + 1])["score"] for s, e in kal.indices]
        ocakavane = calibrate(skore, kal, fpr=0.05, k=3, n=5, interval_s=5, diagnostic=True)
        ulozene = balik.manifest["calibration"]
        assert ulozene["threshold"] == pytest.approx(ocakavane["threshold"], rel=1e-5)
        assert ulozene["threshold"] == pytest.approx(float(np.quantile(skore, 0.95, method="higher")), rel=1e-5)
        assert ulozene["alarm_events"] == ocakavane["alarm_events"]
        assert balik.manifest["training"]["test_feature_arrays_loaded"] is False


def test_prehratie_ma_tvar_safeguard_replay_a_pravidlo_k_z_n(korpus, modely, tmp_path):
    index = json.loads(korpus.read_text())
    test = next(z for z in index["sessions"] if z["role"] == "dev")
    out = tmp_path / "replay"
    stav = po.replay(modely["lstm"], test["features"], out, allow_diagnostic=True)
    assert stav["ok"] and stav["scored"] > 0
    konf, stav2, riadky, _ = ev._nacitaj_prehratie(str(out))
    assert konf["bundle_manifest"]["model"] == "lstm"
    s = ev.suhrn_relacie(riadky, 5, 7.5)
    assert s["skorovanych"] == stav2["scored"] and s["udalosti"] == stav2["alarm_events"]
    assert riadky[0]["timestamp"] == test["start"] and riadky[-1]["timestamp"] == test["end"]
    # Prah je kalibracny prah modelu a model_alarm je k z n nad nim, s resetom na barierach.
    prah = konf["bundle_manifest"]["calibration"]["threshold"]
    historia = deque(maxlen=5)
    for r in riadky:
        assert r["schema"] == ev.SCHEMA_RIADOK and r["threshold"] == prah
        if r["score"] is None:      # kazda bariera je nasledovana zahrievanim bez skore
            historia.clear()
            continue
        historia.append(r["score"] > prah)
        assert r["vote_count"] == len(historia)
        assert r["model_alarm"] == (len(historia) == 5 and sum(historia) >= 3)
    # Kategorie udalosti (dataset 2) nad tymi istymi riadkami - ten isty evaluator.
    udalost = {"type": "zamok", "executed": True, "host_start_unix": test["start"] + 100,
               "host_stopped_unix": test["start"] + 200}
    kategorie = ev.kategorie_udalosti(riadky, [udalost], 5, 8)
    assert set(ev._expozicia(riadky, kategorie, 5)) == {"zamok", "po_udalosti", "prevadzka"}


def test_vyhodnot_udalosti_prijme_prehratie_baselinu(korpus, modely, tmp_path):
    """Cely evaluator datasetu 2; diagnosticky priznak sa pre test zmeni v kopii konfiguracie."""
    import hashlib
    index = json.loads(korpus.read_text())
    zaznam = next(z for z in index["sessions"] if z["role"] == "dev")
    out = tmp_path / "replay"
    po.replay(modely["zscore"], zaznam["features"], out, allow_diagnostic=True)
    konf = json.loads((out / "configuration.json").read_text())
    konf["bundle_manifest"]["diagnostic"] = False
    (out / "configuration.json").write_text(json.dumps(konf))
    udalosti = tmp_path / "events.json"
    udalosti.write_text(json.dumps({"events": [{"type": "zamok", "class": "chyba", "executed": True,
                                                "host_start_unix": zaznam["start"] + 100,
                                                "host_stopped_unix": zaznam["start"] + 200}]}))
    sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
    env = konf["bundle_manifest"]["environment"]
    ei = tmp_path / "events_index.json"
    ei.write_text(json.dumps({"schema": "hyptcn3/event-index/1", "complete": True, "protocol_sha256": "p",
                              "protocol_config": {"name": "v3", "interval_s": 5, "max_gap_s": 7.5,
                                                  "window_rows": 8, "events": {"classes": {"zamok": "chyba"}}},
                              "sessions": [{**zaznam, "events": str(udalosti), "events_sha256": sha(udalosti),
                                            "guest": {"kernel": env["kernel"], "stack_sha256": env["stack_sha256"]},
                                            "collector_sha256": env["collector_sha256"],
                                            "extractor_sha256": env["extractor_sha256"]}]}))
    values, _ = ev.vyhodnot_udalosti(str(ei), [str(out)])
    assert values["merane"]["prevadzka"]["spolu"]["skorovanych"] > 0
    assert set(values["prostredie_voci_baliku"].values()) == {"zhodne"}


def test_pamatova_ablacia_vidi_presne_8_globalnych_stlpcov(modely, korpus):
    balik = po.nacitaj(modely["tcn_pamat"], allow_diagnostic=True)
    siet = balik.model.siet
    assert isinstance(siet, Predictor)
    assert siet.global_tcn.bloky[0].c1.in_channels == 8 and siet.global_tcn.hlava.out_features == 8
    assert balik.manifest["vstup"]["globalne"] == list(po.PAMAT)
    assert all(m.startswith("mem_") for m in po.PAMAT) and len(po.PAMAT) == 8
    videne = []
    siet.global_tcn.register_forward_hook(lambda m, x, y: videne.append(x[0].shape[-1]))
    d = po.nacitaj_role(korpus, diagnostic=True)
    s, e = d["data"]["dev"].indices[0]
    balik.score(d["data"]["dev"].sessions[s][1][e - 7:e + 1])
    assert videne == [8]
    with pytest.raises(ValueError, match="8"):
        siet(torch.zeros(1, 7, 18), torch.zeros(1, 7, 3, 4))


def test_iforest_skore_je_nezaporne_a_kalibrovatelne(korpus, tmp_path):
    vysledok = po.fit(korpus, "iforest", tmp_path / "if", seed=1, fpr=0.05, diagnostic=True)
    assert vysledok["calibration"]["threshold"] >= 0
    balik = po.nacitaj(tmp_path / "if", allow_diagnostic=True)
    (tmp_path / "if" / "iforest.pkl").write_bytes(b"poskodene")
    with pytest.raises(ValueError, match="sucet"):
        po.nacitaj(tmp_path / "if", allow_diagnostic=True)
    assert balik.manifest["training"]["checkpoint_selection_role"] is None
