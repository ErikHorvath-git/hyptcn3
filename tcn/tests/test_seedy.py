"""
Testy rozptylu cez seedy (tcn/seedy.py). Offline: ziadny trening, iba
poistky (zle seedy, seedy mimo planu analyzy, test_benign) a vypocet suhrnu
nad syntetickymi manifestmi.
"""

import json
from pathlib import Path
import re

import numpy as np
import pytest

from tcn import seedy
from tcn.eval import _manifest_sha


def manifest(seed, strata, korpus="k"):
    # Od balika B6b ma klasifikator vlastnu krivku ucenia (training.classifier_history).
    return {"training": {"seed": seed, "selected_predictor_epoch": 2, "selected_classifier_epoch": 1,
                         "history": [{"epoch": 1, "dev_prediction_loss": 9.0},
                                     {"epoch": 2, "dev_prediction_loss": strata}],
                         "classifier_history": [{"epoch": 1, "dev_classification_loss": 0.5 + seed},
                                                {"epoch": 2, "dev_classification_loss": 7.0}]},
            "calibration": {"threshold": 1.0 + seed, "calibration_alarm_events_per_hour": 0.1,
                            "window_exceedance_fraction": 0.01},
            "provenance": {"corpus_index_sha256": korpus}}


def far_dev(m, udalosti_h, rola="dev", final=False):
    spolu = {"spolu": {"udalosti_model": 1}, "far_h": {"skorovany": {"udalosti_h": udalosti_h}}}
    return {"schema": "hyptcn3/safeguard-far/2", "rola": rola, "final": final,
            "balik": {"manifest_sha256": _manifest_sha(m)}, "merane": {"spolu": spolu},
            "klasifikacia_aktivit": {"okna": {"presnost": 0.9, "f1_macro": 0.8}, "relacie": {"presnost": 1.0}}}


@pytest.mark.parametrize("zle", [[1, 1], [], [-1], [1.0]])
def test_zle_seedy_sa_netrenuju(zle, tmp_path):
    # Seed 0 je od balika B6b dovoleny (D14: balik na nasadenie ma seed 0); pozri test_seedy_z_planu_analyzy.
    with pytest.raises(ValueError):
        seedy.trenuj_seedy(tmp_path / "k.json", tmp_path / "out", zle)


V5 = Path(__file__).resolve().parents[2] / "config/collection-v5.json"


@pytest.mark.parametrize("schema, zadane, ocakavane", [
    (3, None, [0, 1, 2, 3, 4]),
    (3, [0], [0]),
    (3, [7], "seed 7 nie je v analysis.seeds [0, 1, 2, 3, 4] protokolu schemy 3; seed mimo planu analyzy sa trenuje "
             "iba pre diagnosticky balik (--diagnostic)"),
    (2, None, [1, 2, 3, 4]),
], ids=["plan", "seed_0", "mimo_planu", "legacy_schema_2"])
def test_seedy_z_planu_analyzy(schema, zadane, ocakavane, tmp_path, monkeypatch):
    """Balik B6b (navrh 1.6): pri scheme 3 su seedy z analysis.seeds (0 az 4, seed 0 vratane), seed mimo planu sa
    odmietne este pred prvym treningom; schemy 1 a 2 ostavaju pri SEEDY (legacy_schema_2)."""
    from safeguard import training
    protokol = json.loads(V5.read_text()) if schema == 3 else {"schema": "hyptcn3/collection-protocol/2"}
    korpus = tmp_path / "k.json"
    korpus.write_text(json.dumps({"protocol_config": protokol}))
    trenovane = []
    monkeypatch.setattr(training, "train_bundle", lambda k, ciel, *, seed, **kw: trenovane.append(seed) or {})
    if isinstance(ocakavane, str):
        with pytest.raises(ValueError, match="^" + re.escape(ocakavane) + "$"):
            seedy.trenuj_seedy(korpus, tmp_path / "out", zadane)
        assert trenovane == []
        return
    assert list(seedy.trenuj_seedy(korpus, tmp_path / "out", zadane)) == ocakavane == trenovane


def test_existujuci_vystup_sa_neprepise_pred_treningom(tmp_path):
    (tmp_path / "out" / "seed-2").mkdir(parents=True)
    with pytest.raises(FileExistsError):
        seedy.trenuj_seedy(tmp_path / "k.json", tmp_path / "out", [1, 2])


def test_suhrn_priemer_sd_min_max_a_priradenie_podla_manifestu():
    m = [manifest(s, l) for s, l in ((0, 1.0), (1, 2.0), (2, 4.0))]
    vysledky = {"d1dev": [far_dev(m[2], 0.3), far_dev(m[0], 0.1), far_dev(m[1], 0.2)]}
    out = seedy.suhrn(m, vysledky)
    assert out["seedy"] == [0, 1, 2]
    strata = out["metriky"]["dev.dev_prediction_loss"]
    assert strata["priemer"] == pytest.approx(7 / 3)
    assert strata["sd"] == pytest.approx(np.std([1, 2, 4], ddof=1))
    assert (strata["min"], strata["max"], strata["n"]) == (1.0, 4.0, 3)
    assert out["metriky"]["dev.dev_classification_loss"]["seedy"] == {"0": 0.5, "1": 1.5, "2": 2.5}  # vybrata epocha 1
    far = out["metriky"]["d1dev.far_h"]
    assert far["seedy"] == {"0": 0.1, "1": 0.2, "2": 0.3}
    assert far["priemer"] == pytest.approx(0.2)
    json.dumps(out, allow_nan=False)


def test_suhrn_odmietne_test_benign_cudzi_balik_a_duplicity():
    m = [manifest(1, 1.0), manifest(2, 2.0)]
    with pytest.raises(ValueError, match="test_benign"):
        seedy.suhrn(m, {"t": [far_dev(m[0], 0.1, rola="test_benign", final=True)]})
    with pytest.raises(ValueError, match="nie je v zozname"):
        seedy.suhrn(m, {"x": [far_dev(manifest(3, 1.0), 0.1)]})
    with pytest.raises(ValueError, match="viackrat"):
        seedy.suhrn(m, {"x": [far_dev(m[0], 0.1), far_dev(m[0], 0.2)]})
    with pytest.raises(ValueError, match="viackrat"):
        seedy.suhrn([manifest(1, 1.0), manifest(1, 2.0)], {})
    with pytest.raises(ValueError, match="korpus"):
        seedy.suhrn([manifest(1, 1.0), manifest(2, 1.0, korpus="iny")], {})


def test_suhrn_udalosti_datasetu_2():
    m = [manifest(1, 1.0), manifest(2, 2.0)]

    def udalosti(mm, h):
        blok = {"far_h": {"skorovany": {"udalosti_h": h}}}
        return {"schema": "hyptcn3/safeguard-event-far/1", "balik": {"manifest_sha256": _manifest_sha(mm)},
                "merane": {"prevadzka": blok, "po_udalosti": None, "vsetky_udalosti": blok,
                           "triedy": {"udrzba": blok}},
                "udalosti": {"s_alarmom_modelu": 1, "vykonanych": 4}}
    out = seedy.suhrn(m, {"d2": [udalosti(m[0], 1.0), udalosti(m[1], 3.0)]})
    assert out["metriky"]["d2.prevadzka_far_h"]["priemer"] == 2.0
    assert out["metriky"]["d2.po_udalosti_far_h"]["chyba"] == 2
    assert out["metriky"]["d2.trieda_udrzba_far_h"]["max"] == 3.0
    assert out["metriky"]["d2.udalosti_s_alarmom_podiel"]["priemer"] == 0.25


@pytest.mark.parametrize("schemy, ocakavane", [
    ((3, 3), "analysis"),
    ((2, 2), "legacy_schema_2"),
    ((3, 2), "baliky protokolu schemy 3 aj inej schemy: rozptyl seedov je nad balikmi jedneho protokolu"),
], ids=["schema_3", "legacy_schema_2", "zmiesane"])
def test_pravidlo_testovacej_roly_podla_schemy_balikov(schemy, ocakavane):
    """Balik B7c (navrh NAVRH_B7c 1.4, mapa kodu B7 par. 9 bod 7): pri balikoch protokolu schemy 3 suhrn uz nehovori,
    ze test_benign sa vyhodnocuje iba pre seed 0: testovaciu rolu vyhodnoti raz finalny prikaz tcn.finalne so vsetkymi
    seedmi analysis.seeds (SULAD, D14). Schemy 1 a 2 drzia legacy_schema_2; baliky oboch druhov naraz su chyba."""
    manifesty = []
    for seed, schema in zip((0, 1), schemy):
        m = manifest(seed, 1.0 + seed)
        m["provenance"]["protocol"] = (json.loads(V5.read_text()) if schema == 3
                                       else {"schema": "hyptcn3/collection-protocol/2"})
        manifesty.append(m)
    if ocakavane not in seedy.PRAVIDLO_TESTU:
        with pytest.raises(ValueError, match="^" + re.escape(ocakavane) + "$"):
            seedy.suhrn(manifesty, {})
        return
    out = seedy.suhrn(manifesty, {})
    assert out["pravidlo_testu"] == ocakavane and out["poznamka"].endswith(seedy.PRAVIDLO_TESTU[ocakavane])
    if ocakavane == "analysis":
        assert "tcn.finalne" in out["poznamka"] and "seed 0" not in out["poznamka"]
        assert out["deploy_seed"] == 0 and "finalny_seed" not in out
    else:
        assert out["finalny_seed"] == 0 and "iba pre finalny seed 0" in out["poznamka"]


def test_suhrn_odmietne_vysledok_roly_test_controls():
    """Balik B7c: aj druha zapecatena rola (test_controls) do rozptylu seedov nepatri."""
    m = [manifest(1, 1.0), manifest(2, 2.0)]
    with pytest.raises(ValueError, match="^rola test_controls je zapecateny zaverecny test; do rozptylu seedov "
                                         "nepatri"):
        seedy.suhrn(m, {"t": [far_dev(m[0], 0.1, rola="test_controls")]})


@pytest.mark.parametrize("rola", ["test_benign", "test_controls"])
def test_suhrn_odmietne_vysledok_udalosti_zapecatenej_roly(rola):
    """Nalez F11 overenia B7c: vysledok tcn.eval udalosti zapecatenej roly (korpus_rola) do rozptylu seedov nepatri,
    rovnako ako vysledok far; vysledok udalosti indexu bez roly (dataset 2) prejde (test_suhrn_udalosti_datasetu_2)."""
    m = [manifest(1, 1.0), manifest(2, 2.0)]
    blok = {"far_h": {"skorovany": {"udalosti_h": 1.0}}}
    vysledok = {"schema": "hyptcn3/safeguard-event-far/1", "korpus_rola": rola,
                "balik": {"manifest_sha256": _manifest_sha(m[0])},
                "merane": {"prevadzka": blok, "po_udalosti": None, "vsetky_udalosti": blok, "triedy": {}},
                "udalosti": {"s_alarmom_modelu": 1, "vykonanych": 4}}
    with pytest.raises(ValueError, match="^" + re.escape(
            f"rola {rola} je zapecateny zaverecny test; do rozptylu seedov nepatri ani vysledok tcn.eval udalosti "
            "(PRAVIDLO_TESTU: pri scheme 3 ju vyhodnoti raz tcn.finalne so vsetkymi seedmi analysis.seeds, pri "
            "schemach 1 a 2 tcn.eval udalosti --final)") + "$"):
        seedy.suhrn(m, {"t": [vysledok]})
