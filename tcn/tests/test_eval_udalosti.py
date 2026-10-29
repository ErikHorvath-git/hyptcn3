"""
Testy FAR z udalosti detektora (tcn/eval.py, prikaz `far`).

Overuje sa MECHANIKA na syntetickych riadkoch events.jsonl - ziadne cislo tu
nie je meranie (HONESTY P4): ze sa pocitaju udalosti a nie okna, casy a
vypadky, exaktny interval a poistky, ktore drzia rolu, korpus, balik a
jednorazovost zaverecneho testu. Tvar indexu, konfiguracie, stavu a riadkov
je ten, ktory zapisuju features/dataset.py, scripts/campaign.py a
safeguard/cli.py.
"""

import hashlib
import json
import shutil

import pytest

from tcn import eval as ev
from tcn.eval import _hlavny, far, poissonov_interval, suhrn_relacie, vyhodnot_far

PROTOKOL = {"interval_s": 5.0, "max_gap_s": 7.5, "window_rows": 32}


def riadok(t, score=0.1, alarm_event=False, sources=(), model_state="monitoring", conclusive=True):
    return {"schema": "hyptcn3/safeguard-events/1", "timestamp": t, "score": score,
            "alarm_event": alarm_event, "alarm_sources": list(sources), "model_state": model_state,
            "integrity": {"conclusive": conclusive, "inconclusive": [] if conclusive else ["text_integrity"]}}


def test_poissonov_interval_pri_nule_a_jednej_udalosti():
    assert poissonov_interval(0) == (0.0, pytest.approx(3.6889, abs=1e-4))
    dolna, horna = poissonov_interval(1)
    assert dolna == pytest.approx(0.0253, abs=1e-4)
    assert horna == pytest.approx(5.5716, abs=1e-4)


@pytest.mark.parametrize("alfa", [0, 1, 1.5, -0.1, float("nan"), True])
def test_poissonov_interval_odmietne_zlu_alfu(alfa):
    with pytest.raises(ValueError):
        poissonov_interval(0, alfa)


def test_suhrn_rata_udalosti_nie_okna_nad_prahom():
    riadky = [riadok(5.0 * i) for i in range(10)]
    for i in (5, 6, 7):                       # trvajuci alarm: iba prvy riadok je udalost
        riadky[i]["alarm_event"] = i == 5
        riadky[i]["alarm_sources"] = ["model_anomaly"] if i == 5 else []
    riadky[8].update(alarm_event=True, alarm_sources=["kernel_integrity"])
    riadky[9].update(alarm_event=True, alarm_sources=["model_anomaly", "kernel_integrity"])
    s = suhrn_relacie(riadky, perioda_s=5.0, max_medzera_s=7.5)
    assert s["udalosti"] == 3                 # riadok s oboma zdrojmi je jedna udalost
    assert s["udalosti_model"] == 2 and s["udalosti_integrita"] == 2
    assert s["casy_udalosti_model_s"] == [25.0, 45.0]


def test_suhrn_casy_bez_skore_vypadky_a_dostupnost_integrity():
    casy = [0.0, 5.0, 10.0, 30.0, 35.0]       # jeden vypadok: odstup 20 s pri periode 5 s
    riadky = [riadok(t, score=None if i < 2 else 0.1, conclusive=i != 0,
                     model_state="warming_up" if i < 2 else "monitoring") for i, t in enumerate(casy)]
    riadky[4].update(model_state="input_error", score=None)
    s = suhrn_relacie(riadky, perioda_s=5.0, max_medzera_s=7.5)
    assert s["sledovany_s"] == 40.0
    assert s["skorovanych"] == 2 and s["skorovany_s"] == 10.0
    assert s["bez_skore_cas_podiel"] == pytest.approx(0.75)      # vypadok sa rata do casu bez skore
    assert s["bez_skore_riadkov_podiel"] == pytest.approx(0.6)
    assert s["chyb_vstupu"] == 1 and s["chyb_vstupu_s"] == 5.0
    assert s["vypadkov"] == 1 and s["vypadky_s"] == 15.0
    assert s["integrita_uzavretych_riadkov"] == 4
    assert s["integrita_neuzavrete"] == {"text_integrity": 1}


def test_suhrn_odmietne_nerastuce_casy_a_cudziu_schemu():
    with pytest.raises(ValueError):
        suhrn_relacie([riadok(5.0), riadok(5.0)], perioda_s=5.0, max_medzera_s=7.5)
    zly = riadok(0.0)
    zly["schema"] = "ina"
    with pytest.raises(ValueError):
        suhrn_relacie([zly], perioda_s=5.0, max_medzera_s=7.5)


def test_far_scita_relacie_interval_aj_pri_nule_a_rozptyl():
    a = suhrn_relacie([riadok(5.0 * i) for i in range(720)], 5.0, 7.5)
    b = suhrn_relacie([riadok(5.0 * i, alarm_event=i == 10, sources=["model_anomaly"] if i == 10 else [])
                       for i in range(720)], 5.0, 7.5)
    out = far([a, b])
    assert out["spolu"]["udalosti_model"] == 1 and out["spolu"]["relacii"] == 2
    hodina = out["far_h"]["skorovany"]
    assert hodina["udalosti_h"] == pytest.approx(0.5)          # 1 udalost za 2 h skorovania
    assert hodina["dolna_h"] < 0.5 < hodina["horna_h"]
    assert out["disperzia"]["df"] == 1 and 0 < out["disperzia"]["p"] <= 1
    nula = far([a])
    assert nula["far_h"]["skorovany"]["udalosti_h"] == 0
    assert nula["far_h"]["skorovany"]["horna_h"] == pytest.approx(3.6889, abs=1e-4)
    assert nula["disperzia"]["x2"] is None and nula["disperzia"]["dovod"]


# ---------------------------------------------------------------- prikaz far


def _korpus(tmp_path, roly=("dev", "dev")):
    sessions = []
    for i, rola in enumerate(roly):
        archiv = tmp_path / f"features_{i}.npz"
        archiv.write_bytes(b"archiv %d" % i)
        sessions.append({"id": f"s{i}", "role": rola, "group": f"{rola}-{i}", "scenario": "steady",
                         "features": str(archiv), "start": 0.0, "end": 15.0,
                         "features_sha256": hashlib.sha256(archiv.read_bytes()).hexdigest()})
    korpus = tmp_path / "corpus.json"
    korpus.write_text(json.dumps({"schema": "hyptcn3/corpus-index/1", "complete": True,
                                  "protocol": str(tmp_path / "protocol.json"), "protocol_config": PROTOKOL,
                                  "sessions": sessions}))
    return korpus, sessions


def _prehratie(tmp_path, korpus, zaznam, weights="w1", diagnostic=False, udalost=False, archiv=None):
    out = tmp_path / ("replay_" + zaznam["id"] + "_" + weights)
    out.mkdir()
    manifest = {"diagnostic": diagnostic, "weights": {"predictor": weights}, "calibration": {"threshold": 1.0},
                "created_utc": "2026-10-29T00:00:00+00:00",
                "feature_contract": {"max_gap_s": 7.5, "window_rows": 32},
                "training": {"seed": 0, "epochs": 10, "batch_size": 32},
                "environment": {"kernel": "6.1.0-42-cloud-amd64", "stack_sha256": "x"},
                "provenance": {"corpus_index_sha256": hashlib.sha256(korpus.read_bytes()).hexdigest(),
                               "source_sha256": {}}}
    (out / "configuration.json").write_text(json.dumps({"schema": "hyptcn3/safeguard-configuration/1",
                                                        "bundle_manifest": manifest,
                                                        "archive": archiv or zaznam["features"]}))
    riadky = [riadok(5.0 * i, alarm_event=udalost and i == 2,
                     sources=["model_anomaly"] if udalost and i == 2 else []) for i in range(4)]
    (out / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in riadky))
    (out / "status.json").write_text(json.dumps({"schema": "hyptcn3/safeguard-run/1", "processed": 4,
                                                 "scored": 4, "input_errors": 0,
                                                 "alarm_events": int(udalost), "fatal": False,
                                                 "stop_reason": "replay_complete"}))
    return out


def test_prikaz_far_zapise_hlavicku_a_vysledok(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    prehratia = [_prehratie(tmp_path, korpus, z, udalost=i == 0) for i, z in enumerate(sessions)]
    out = tmp_path / "far.json"
    assert _hlavny(["far", "--corpus", str(korpus), "--role", "dev",
                    "--replay", *map(str, prehratia), "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    for kluc in ("commit", "date", "host", "guest", "command", "n", "values", "evaluator_sha256", "cwd"):
        assert kluc in doc
    v = doc["values"]
    assert doc["n"] == 2 and v["merane"]["skupin"] == 2
    assert v["merane"]["spolu"]["spolu"]["udalosti_model"] == 1
    assert set(v["merane"]["skupiny"]) == {"dev-0", "dev-1"}
    assert set(v["relacie"]) == {"s0", "s1"}
    assert "nie je drzane bokom" in v["poznamka"]
    assert v["kampan"]["zaznam"] is None and v["predpoklady"]
    with pytest.raises(FileExistsError):              # vysledok sa nikdy neprepise
        _hlavny(["far", "--corpus", str(korpus), "--role", "dev",
                 "--replay", *map(str, prehratia), "--out", str(out)])


def test_far_paruje_podla_obsahu_archivu(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    kopia = tmp_path / "kopia.npz"
    shutil.copy(sessions[1]["features"], kopia)        # ta ista relacia z inej cesty
    prehratia = [_prehratie(tmp_path, korpus, sessions[0]), _prehratie(tmp_path, korpus, sessions[1], archiv=str(kopia))]
    values, _ = vyhodnot_far(korpus, "dev", prehratia)
    assert set(values["relacie"]) == {"s0", "s1"}


def test_far_odmietne_chybajucu_relaciu(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    with pytest.raises(ValueError, match="chybaju"):
        vyhodnot_far(korpus, "dev", [_prehratie(tmp_path, korpus, sessions[0])])


def test_far_odmietne_rozne_baliky(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    prehratia = [_prehratie(tmp_path, korpus, sessions[0], weights="w1"),
                 _prehratie(tmp_path, korpus, sessions[1], weights="w2")]
    with pytest.raises(ValueError, match="rozne baliky"):
        vyhodnot_far(korpus, "dev", prehratia)


def test_far_odmietne_diagnosticky_balik(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    prehratia = [_prehratie(tmp_path, korpus, z, diagnostic=True) for z in sessions]
    with pytest.raises(ValueError, match="diagnosticky"):
        vyhodnot_far(korpus, "dev", prehratia)


def test_far_odmietne_zmeneny_archiv(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    prehratia = [_prehratie(tmp_path, korpus, z) for z in sessions]
    with open(sessions[1]["features"], "ab") as fh:
        fh.write(b"!")
    with pytest.raises(ValueError, match="nie je relaciou"):
        vyhodnot_far(korpus, "dev", prehratia)


def test_far_odmietne_status_nesediaci_s_riadkami(tmp_path):
    korpus, sessions = _korpus(tmp_path)
    prehratia = [_prehratie(tmp_path, korpus, z) for z in sessions]
    stav = json.loads((prehratia[0] / "status.json").read_text())
    stav["alarm_events"] = 3
    (prehratia[0] / "status.json").write_text(json.dumps(stav))
    with pytest.raises(ValueError, match="nesedi"):
        vyhodnot_far(korpus, "dev", prehratia)


def test_final_iba_pre_test_benign(tmp_path):
    korpus, sessions = _korpus(tmp_path, roly=("test_benign",))
    prehratia = [_prehratie(tmp_path, korpus, sessions[0])]
    with pytest.raises(ValueError, match="--final"):
        vyhodnot_far(korpus, "test_benign", prehratia)
    d = tmp_path / "dev"
    d.mkdir()
    dkorpus, dsessions = _korpus(d)
    with pytest.raises(ValueError, match="--final"):
        vyhodnot_far(dkorpus, "dev", [_prehratie(d, dkorpus, z) for z in dsessions], final=True)
    values, _ = vyhodnot_far(korpus, "test_benign", prehratia, final=True)
    assert values["final"] is True and values["rola"] == "test_benign"


def test_final_vyzaduje_commitnuty_kod_a_pusti_sa_raz(tmp_path, monkeypatch):
    korpus, sessions = _korpus(tmp_path, roly=("test_benign",))
    prehratia = [_prehratie(tmp_path, korpus, sessions[0])]
    argv = ["far", "--corpus", str(korpus), "--role", "test_benign", "--final", "--replay", *map(str, prehratia)]
    monkeypatch.setattr(ev, "_git_stav", lambda: ("abc", ["tcn/eval.py"]))
    with pytest.raises(SystemExit, match="commitnuty"):
        _hlavny(argv + ["--out", str(tmp_path / "a.json")])
    monkeypatch.setattr(ev, "_git_stav", lambda: ("abc", []))
    assert _hlavny(argv + ["--out", str(tmp_path / "b.json")]) == 0
    assert (tmp_path / "corpus.json.test_benign-final.json").is_file()
    with pytest.raises(FileExistsError):              # druhe zaverecne FAR toho isteho korpusu
        _hlavny(argv + ["--out", str(tmp_path / "c.json")])
    assert not (tmp_path / "c.json").exists()
