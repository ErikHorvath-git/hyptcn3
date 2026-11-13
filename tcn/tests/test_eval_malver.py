"""
Testy vyhodnotenia malveru (tcn/eval.py, prikaz `malver`, dataset 3).

Overuje sa MECHANIKA na syntetickych riadkoch events.jsonl: detekcia v
horizonte a mimo neho, TTD, vylucenie neaktivovaneho behu, Clopperov-Pearsonov
interval, nahodny alarm z kontrol, tabulka ocakavanej a pozorovanej reakcie,
oddelene ratanie nalezov integrity a poistky indexu a prehrati. Ziadne cislo
tu nie je meranie (HONESTY P4).
"""

import copy
import hashlib
import json
import math

import pytest

from tcn import eval as ev
from tcn.eval import _hlavny, aktivacia_behu, clopper_pearson, vyhodnot_malver
from tcn.tests.test_eval_udalosti import riadok

T = 5.0
PROTOKOL = {"interval_s": T, "max_gap_s": 7.5, "window_rows": 4}
KONFIG = json.load(open(ev.os.path.join(ev.REPO, "config", "malver-v1.json"), encoding="utf-8"))
START, SPUSTENIE, AKTIVACIA, KONIEC = 0.0, 600.0, 620.0, 1300.0
HOST = [{"source": "inetsim", "kind": "dns_query"}, {"source": "guest", "kind": "new_process"}]


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _beh(tmp_path, bid, kind="vzorka", group="ransomver", family="f0", model=(), integrita=(),
         aktivacia=AKTIVACIA, dokazy=HOST, koniec=KONIEC, weights="w1", spustenie=SPUSTENIE):
    """Zaznam indexu a prehratie; model = casy udalosti modelu, integrita = (cas, kontrola)."""
    d = tmp_path / bid
    d.mkdir()
    (d / "f.npz").write_bytes(bid.encode())
    riadky = []
    integ = dict(integrita)
    for i in range(int((koniec - START) / T) + 1):
        t = START + T * i
        zdroje = (["model_anomaly"] if t in model else []) + (["kernel_integrity"] if t in integ else [])
        r = riadok(t, alarm_event=bool(zdroje), sources=zdroje)
        r["integrity"]["findings"] = [{"check": integ[t]}] if t in integ else []
        r["model_alarm"] = any(a <= t <= a + 20 for a in model)
        riadky.append(r)
    beh = {"id": bid, "kind": kind, "archive": str(d / "f.npz"), "archive_sha256": _sha(d / "f.npz"),
           "start": START, "end": riadky[-1]["timestamp"]}
    if kind == "kontrola":
        beh.update(sample_sha256=None, group=None, launch_unix=None, activation=None)
    else:
        beh.update(group=group, family=family, launch_unix=spustenie,
                   activation={"timestamp_unix": aktivacia, "evidence": list(dokazy)})
        if kind == "vzorka":
            beh["sample_sha256"] = hashlib.sha256(b"vzorka " + bid.encode()).hexdigest()
        else:
            beh.update(sample_sha256=None, scenario=family)
    out = d / "replay"
    out.mkdir()
    manifest = {"diagnostic": False, "weights": {"predictor": weights},
                "calibration": {"threshold": 1.0, "k": 3, "n": 5}, "classes": ["quiet"],
                "created_utc": "2026-11-01T00:00:00+00:00",
                "feature_contract": {"max_gap_s": 7.5, "window_rows": 4},
                "environment": {"kernel": "6.1.0-42-cloud-amd64", "stack_sha256": "x"},
                "provenance": {"corpus_index_sha256": "c" * 64, "source_sha256": {}}}
    (out / "configuration.json").write_text(json.dumps({"schema": "hyptcn3/safeguard-configuration/1",
                                                        "bundle_manifest": manifest, "archive": beh["archive"]}))
    (out / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in riadky))
    (out / "status.json").write_text(json.dumps({
        "schema": "hyptcn3/safeguard-run/1", "processed": len(riadky), "scored": len(riadky), "input_errors": 0,
        "alarm_events": sum(r["alarm_event"] for r in riadky), "fatal": False, "stop_reason": "replay_complete"}))
    return beh, out


def _index(tmp_path, behy):
    cesta = tmp_path / "malver_index.json"
    cesta.write_text(json.dumps({"schema": "hyptcn3/malver-index/1", "complete": True,
                                 "protocol_config": PROTOKOL, "runs": behy}))
    return cesta


def _sada(tmp_path):
    specs = [
        ("r1", dict(group="ransomver", family="lockbit", model=(650.0,))),          # TTD 30 s
        ("r2", dict(group="ransomver", family="lockbit", model=(1250.0,))),         # po horizonte
        ("r3", dict(group="kryptominer", family="xmrig", model=(700.0,))),          # TTD 80 s
        ("r4", dict(group="rootkit_jadra", family="diamorphine-like", integrita=((630.0, "syscall_table"),))),
        ("r5", dict(group="rootkit_userspace", family="hider", integrita=((640.0, "modules"),))),
        ("r6", dict(group="tichy_backdoor", family="tinyshell", model=(300.0,))),    # alarm pred spustenim
        ("r7", dict(group="botnet", family="mirai", dokazy=[{"source": "guest", "kind": "new_process"}])),
        ("s1", dict(kind="scenar", group="kryptominer", family="miner", model=(640.0,))),
        ("k1", dict(kind="kontrola", koniec=1795.0, model=(100.0,))),
        ("k2", dict(kind="kontrola", koniec=1795.0)),
    ]
    behy, prehratia = [], []
    for bid, kw in specs:
        b, p = _beh(tmp_path, bid, **kw)
        behy.append(b)
        prehratia.append(p)
    return _index(tmp_path, behy), prehratia, behy


def test_clopper_pearson_hodnoty():
    dolna, horna = clopper_pearson(10, 10)
    assert dolna == pytest.approx(0.6915, abs=1e-4) and horna == 1.0
    assert clopper_pearson(0, 10)[0] == 0.0 and clopper_pearson(0, 10)[1] == pytest.approx(0.3085, abs=1e-4)
    assert clopper_pearson(0, 0) is None


def test_pravidlo_aktivacie_vyzaduje_dokaz_zo_strany_hosta():
    beh = {"activation": {"timestamp_unix": 5.0, "evidence": [{"source": "guest", "kind": "x"}]}}
    assert aktivacia_behu(beh) == (False, None, "bez_dokazu_zo_strany_hosta")
    beh["activation"]["evidence"].append({"source": "host", "kind": "qemu_cpu"})
    assert aktivacia_behu(beh) == (True, 5.0, None)
    assert aktivacia_behu({"activation": {"timestamp_unix": None, "evidence": []}})[0] is False


def test_malver_detekcia_ttd_vylucenie_a_reakcie(tmp_path):
    index, prehratia, _ = _sada(tmp_path)
    v, _ = vyhodnot_malver(index, prehratia, KONFIG)
    assert v["pocty"] == {"vzorka": 7, "scenar": 1, "kontrola": 2}
    s = v["vzorky"]["spolu"]
    assert s["spustenych"] == 7 and s["aktivovanych"] == 6 and s["neaktivovanych"] == ["r7"]
    m = s["model"]
    assert m["detegovanych"] == 2 and m["ttd_s"] == {"r1": 30.0, "r3": 80.0}
    assert m["ttd_median_s"] == 55.0 and m["ttd_min_mozny_s"] == 15.0
    lo, hi = m["interval"]
    assert (lo, hi) == pytest.approx(clopper_pearson(2, 6))
    assert v["relacie"]["r2"]["priebeh"]["model"]["detekcia"] is False          # alarm po horizonte
    assert v["relacie"]["r6"]["priebeh"]["model"]["pred_spustenim"] == 1
    # Integrita je zvlast; pri rootkit_userspace sa rata iba process_cross_view.
    assert s["integrita"]["detegovanych"] == 1 and s["integrita"]["ttd_s"] == {"r4": 10.0}
    assert v["relacie"]["r5"]["priebeh"]["integrita"]["udalosti"] == 0
    # Scenare su oddelene.
    assert v["scenare"]["spolu"]["aktivovanych"] == 1 and v["scenare"]["podla_scenara"]["miner"]["model"]["detegovanych"] == 1
    assert "r1" not in str(v["scenare"]["spolu"]["model"]["ttd_s"])
    # Ocakavana proti pozorovanej reakcii.
    r = v["vzorky"]["reakcie"]
    assert r["ransomver"]["zdroje"]["model"]["pozorovane"] is True and r["ransomver"]["zhoda"] is True  # 1 z 2 >= 0.5
    assert r["kryptominer"]["zhoda"] is True
    assert r["rootkit_jadra"]["zdroje"]["integrita"]["zhoda"] is True and r["rootkit_jadra"]["zhoda"] is True
    assert r["rootkit_userspace"]["zdroje"]["integrita"]["zhoda"] is False and r["rootkit_userspace"]["zhoda"] is False
    assert r["tichy_backdoor"]["zhoda"] is True
    assert r["botnet"]["aktivovanych"] == 0 and r["botnet"]["zhoda"] is None
    assert v["vzorky"]["podla_rodiny"]["lockbit"]["aktivovanych"] == 2
    # Minima sa hlasia, ale neodmietnu.
    assert v["minima"]["vzorky"] == {"aktivovanych": 6, "minimum": 10, "splnene": False}
    assert v["minima"]["na_skupinu"]["aktivovanych"]["botnet"] == 0 and v["minima"]["vsetky_splnene"] is False


def test_malver_nahodny_alarm_z_kontrol(tmp_path):
    index, prehratia, _ = _sada(tmp_path)
    v, _ = vyhodnot_malver(index, prehratia, KONFIG)
    n = v["nahodny_alarm"]
    assert n["kontrol"] == 2 and n["sledovany_s"] == 3600.0
    assert n["model"]["udalosti"] == 1 and n["model"]["miera_h"] == pytest.approx(1.0)
    assert n["model"]["p_poisson"] == pytest.approx(1 - math.exp(-1 / 6))
    dolna, horna = ev.poissonov_interval(1)
    assert n["model"]["p_poisson_interval"] == pytest.approx([1 - math.exp(-dolna / 6), 1 - math.exp(-horna / 6)])
    assert n["model"]["empiricky"]["usekov"] == 6 and n["model"]["empiricky"]["s_alarmom"] == 1
    assert n["integrita"]["udalosti"] == 0 and n["integrita"]["p_poisson"] == 0.0
    vn = v["vzorky"]["spolu"]["model"]["voci_nahode"]
    assert vn["p_nahody"] == n["model"]["p_poisson"] and 0 < vn["p"] < 1


def test_prikaz_malver_zapise_hlavicku(tmp_path):
    index, prehratia, _ = _sada(tmp_path)
    out = tmp_path / "malver.json"
    konfig = ev.os.path.join(ev.REPO, "config", "malver-v1.json")
    argv = ["malver", "--index", str(index), "--config", konfig, "--replay", *map(str, prehratia), "--out", str(out)]
    assert _hlavny(argv) == 0
    doc = json.loads(out.read_text())
    for kluc in ("commit", "date", "host", "guest", "command", "n", "values", "evaluator_sha256", "cwd"):
        assert kluc in doc
    assert doc["n"] == 10 and doc["values"]["konfiguracia_subor_sha256"] and doc["values"]["index_sha256"]
    with pytest.raises(FileExistsError):
        _hlavny(argv)


def test_malver_odmietne_dvojite_prehratie_a_rozne_baliky(tmp_path):
    index, prehratia, behy = _sada(tmp_path)
    with pytest.raises(ValueError, match="dvakrat"):
        vyhodnot_malver(index, prehratia + [prehratia[0]], KONFIG)
    with pytest.raises(ValueError, match="chybaju"):
        vyhodnot_malver(index, prehratia[1:], KONFIG)
    d = tmp_path / "iny"
    d.mkdir()
    b, p = _beh(d, "x1", weights="w2")
    index2 = _index(d, [behy[0], b])
    with pytest.raises(ValueError, match="rozne baliky"):
        vyhodnot_malver(index2, [prehratia[0], p], KONFIG)


def test_malver_odmietne_nejednoznacny_index(tmp_path):
    index, prehratia, behy = _sada(tmp_path)

    def skus(zmena, vzor):
        zle = copy.deepcopy(behy)
        zmena(zle)
        with pytest.raises(ValueError, match=vzor):
            vyhodnot_malver(_index(tmp_path, zle), prehratia, KONFIG)

    skus(lambda b: b[1].update(sample_sha256=b[0]["sample_sha256"]), "viac nez raz")
    skus(lambda b: b[0].update(launch_unix=300.0, activation={"timestamp_unix": 320.0, "evidence": HOST}),
         "cisty usek")
    skus(lambda b: b[0]["activation"].update(timestamp_unix=1000.0), "horizont")
    skus(lambda b: b[0].update(group="neznama"), "skupina")
    skus(lambda b: b[0].update(kind="iny"), "kind")
    skus(lambda b: b[7].update(scenario="nieco"), "scenar")
    skus(lambda b: b[0]["activation"]["evidence"].append({"source": "satelit", "kind": "x"}), "dokaz")


def test_malver_odmietne_neuplne_pokrytie(tmp_path):
    index, prehratia, behy = _sada(tmp_path)
    zle = copy.deepcopy(behy)
    zle[0]["end"] = KONIEC + T
    with pytest.raises(ValueError, match="nepokryva"):
        vyhodnot_malver(_index(tmp_path, zle), prehratia, KONFIG)
