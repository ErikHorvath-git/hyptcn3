"""
Testy rozptylu cez seedy (tcn/seedy.py). Offline: ziadny trening, iba
poistky (seed 0, test_benign) a vypocet suhrnu nad syntetickymi manifestmi.
"""

import json

import numpy as np
import pytest

from tcn import seedy
from tcn.eval import _manifest_sha


def manifest(seed, strata, korpus="k"):
    return {"training": {"seed": seed, "selected_predictor_epoch": 2, "selected_classifier_epoch": 1,
                         "history": [{"epoch": 1, "dev_prediction_loss": 9.0, "dev_classification_loss": 0.5 + seed},
                                     {"epoch": 2, "dev_prediction_loss": strata, "dev_classification_loss": 7.0}]},
            "calibration": {"threshold": 1.0 + seed, "calibration_alarm_events_per_hour": 0.1,
                            "window_exceedance_fraction": 0.01},
            "provenance": {"corpus_index_sha256": korpus}}


def far_dev(m, udalosti_h, rola="dev", final=False):
    spolu = {"spolu": {"udalosti_model": 1}, "far_h": {"skorovany": {"udalosti_h": udalosti_h}}}
    return {"schema": "hyptcn3/safeguard-far/2", "rola": rola, "final": final,
            "balik": {"manifest_sha256": _manifest_sha(m)}, "merane": {"spolu": spolu},
            "klasifikacia_aktivit": {"okna": {"presnost": 0.9, "f1_macro": 0.8}, "relacie": {"presnost": 1.0}}}


@pytest.mark.parametrize("zle", [[0, 1], [1, 1], [], [-1], [1.0]])
def test_seed_0_ani_zle_seedy_sa_netrenuju(zle, tmp_path):
    with pytest.raises(ValueError):
        seedy.trenuj_seedy(tmp_path / "k.json", tmp_path / "out", zle)


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
