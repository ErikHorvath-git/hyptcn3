"""
Testy FAR pocas prevadzkovych udalosti (tcn/eval.py, prikaz `udalosti`, protokol v3 krok A).

Overuje sa MECHANIKA na syntetickych riadkoch: priradenie okien k udalosti,
dozvuku a cistej prevadzke, vylucenie nevykonanej udalosti, oneskorenie
alarmu a poistky indexu. Ziadne cislo tu nie je meranie (HONESTY P4).
Tvar indexu je ten, ktory zapisuje scripts/campaign.py event_index.
"""

import hashlib
import json

import pytest

from tcn import eval as ev
from tcn.tests.test_eval_udalosti import riadok

W, T = 4, 5.0
PROTOKOL = {"name": "server-events-v3", "interval_s": T, "max_gap_s": 7.5, "window_rows": W,
            "events": {"classes": {"zamok_tabulky": "chyba_aplikacie", "udrzba_zaloha": "udrzba"}}}
GUEST = {"kernel": "6.1.0-42-cloud-amd64", "stack_sha256": "x"}


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relacia(tmp_path, meno, udalost, alarmy=()):
    d = tmp_path / meno
    d.mkdir()
    (d / "f.npz").write_bytes(meno.encode())
    (d / "events.json").write_text(json.dumps({"events": [udalost]}))
    riadky = []
    for i in range(200):  # Kazdy alarm modelu trva 20 s od svojej udalosti.
        t = T * i
        r = riadok(t, alarm_event=t in alarmy, sources=["model_anomaly"] if t in alarmy else [])
        r["model_alarm"] = any(a <= t <= a + 20 for a in alarmy)
        riadky.append(r)
    zaznam = {"id": meno, "group": "v3-test_events-" + meno, "scenario": "quiet",
              "start": 0.0, "end": T * 199, "features": str(d / "f.npz"), "features_sha256": _sha(d / "f.npz"),
              "events": str(d / "events.json"), "events_sha256": _sha(d / "events.json"),
              "guest": GUEST, "collector_sha256": "c", "extractor_sha256": {"features/a.py": "e"}}
    return zaznam, riadky


def _prehratie(tmp_path, zaznam, riadky):
    out = tmp_path / ("replay_" + zaznam["id"])
    out.mkdir()
    manifest = {"diagnostic": False, "created_utc": "2026-10-29T00:00:00+00:00", "calibration": {"threshold": 1.0},
                "feature_contract": {"max_gap_s": 7.5, "window_rows": W},
                "environment": {**GUEST, "collector_sha256": "iny", "extractor_sha256": {"features/a.py": "e"}},
                "provenance": {"corpus_index_sha256": "v6"}}
    (out / "configuration.json").write_text(json.dumps({"schema": "hyptcn3/safeguard-configuration/1",
                                                        "bundle_manifest": manifest, "archive": zaznam["features"]}))
    (out / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in riadky))
    (out / "status.json").write_text(json.dumps({
        "schema": "hyptcn3/safeguard-run/1", "processed": len(riadky), "scored": len(riadky), "input_errors": 0,
        "alarm_events": sum(r["alarm_event"] for r in riadky), "fatal": False, "stop_reason": "replay_complete"}))
    return out


@pytest.fixture
def kampan(tmp_path):
    zamok = {"type": "zamok_tabulky", "class": "chyba_aplikacie", "start_s": 300, "duration_s": 100,
             "executed": True, "host_start_unix": 300.0, "host_stopped_unix": 400.0}
    udrzba = {"type": "udrzba_zaloha", "class": "udrzba", "start_s": 200, "duration_s": 100,
              "executed": False, "host_start_unix": 200.0, "host_stopped_unix": 300.0}
    a = _relacia(tmp_path, "a", zamok, alarmy=(320.0, 900.0))
    b = _relacia(tmp_path, "b", udrzba)
    index = tmp_path / "events_index.json"
    index.write_text(json.dumps({"schema": "hyptcn3/event-index/1", "complete": True, "protocol_sha256": "p",
                                 "protocol_config": PROTOKOL, "sessions": [a[0], b[0]]}))
    return index, [_prehratie(tmp_path, *a), _prehratie(tmp_path, *b)]


def test_okna_patria_udalosti_dozvuku_alebo_prevadzke():
    udalost = {"type": "zamok_tabulky", "executed": True, "host_start_unix": 300.0, "host_stopped_unix": 400.0}
    riadky = [riadok(t) for t in (295.0, 300.0, 415.0, 420.0, 715.0, 720.0)]
    assert ev.kategorie_udalosti(riadky, [udalost], T, W) == [
        "prevadzka", "zamok_tabulky", "zamok_tabulky", "po_udalosti", "po_udalosti", "prevadzka"]
    udalost["executed"] = False
    assert ev.kategorie_udalosti(riadky, [udalost], T, W) == ["prevadzka", None, None, None, None, "prevadzka"]


def test_far_po_typoch_triedach_a_voci_prevadzke(kampan):
    index, prehratia = kampan
    values, _ = ev.vyhodnot_udalosti(index, prehratia)
    m = values["merane"]
    zamok = m["typy"]["zamok_tabulky"]
    assert zamok["spolu"]["udalosti_model"] == 1 and zamok["spolu"]["skorovany_s"] == 24 * T
    assert zamok["trieda"] == "chyba_aplikacie" and list(m["triedy"]) == ["chyba_aplikacie"]
    assert "udrzba_zaloha" not in m["typy"]  # Nevykonana udalost do metrik nevstupuje.
    assert m["prevadzka"]["spolu"]["udalosti_model"] == 1
    assert m["prevadzka"]["spolu"]["skorovany_s"] == (116 + 116) * T
    assert m["po_udalosti"]["spolu"]["skorovany_s"] == 60 * T
    assert 0 < zamok["voci_prevadzke"]["p"] < 1 and zamok["voci_prevadzke"]["pomer_mier"] > 1
    assert values["relacie"]["b"]["vylucenych_riadkov"] == 24 + 60
    priebeh = values["udalosti"]["priebeh"][0]
    assert priebeh["oneskorenie_s"] == 20.0 and not priebeh["alarm_na_konci_dozvuku"]
    assert (values["udalosti"]["planovanych"], values["udalosti"]["vykonanych"]) == (2, 1)
    assert values["prostredie_voci_baliku"] == {"kernel": "zhodne", "stack_sha256": "zhodne",
                                                "collector_sha256": "ine", "extractor_sha256": "zhodne"}


def test_odmietne_zmeneny_zaznam_udalosti_a_chybajuce_prehratie(kampan):
    index, prehratia = kampan
    with pytest.raises(ValueError, match="chybaju"):
        ev.vyhodnot_udalosti(index, prehratia[:1])
    doc = json.loads(index.read_text())
    path = doc["sessions"][0]["events"]
    with open(path, "a") as fh:
        fh.write(" ")
    with pytest.raises(ValueError, match="events.json"):
        ev.vyhodnot_udalosti(index, prehratia)


def _neuplny(index, **zmena):
    """Index s complete false a blokom, aky zostavi zaznam uzavretej kampane (jedna zamietnuta, jedna chyba)."""
    doc = json.loads(index.read_text())
    blok = {"accepted": True, "decision": "rozhodnutie vlastnika", "planned_sessions": 4, "indexed_sessions": 2,
            "sessions_per_group": {"v3-test_events-a": 1, "v3-test_events-b": 1},
            "rejected": [{"id": "c", "reasons": ["incomplete model inputs under behavioral-inputs-v1"]}],
            "not_captured": [{"id": "d"}]}
    blok.update(zmena)
    doc.update(complete=False, planned_sessions=4, incomplete_allocation=blok)
    index.write_text(json.dumps(doc))


def test_uplny_index_ma_uplnu_alokaciu(kampan):
    index, prehratia = kampan
    values, _ = ev.vyhodnot_udalosti(index, prehratia)
    assert values["alokacia"] == {"uplna": True}


def test_neuplny_index_iba_s_vyslovnym_prijatim(kampan):
    index, prehratia = kampan
    doc = json.loads(index.read_text())
    index.write_text(json.dumps(dict(doc, complete=False)))
    with pytest.raises(ValueError, match="bez vyslovne prijatej"):
        ev.vyhodnot_udalosti(index, prehratia)
    _neuplny(index, accepted="ano")
    with pytest.raises(ValueError, match="bez vyslovne prijatej"):
        ev.vyhodnot_udalosti(index, prehratia)
    _neuplny(index, decision=" ")
    with pytest.raises(ValueError, match="rozhodnutie"):
        ev.vyhodnot_udalosti(index, prehratia)
    _neuplny(index)
    values, _ = ev.vyhodnot_udalosti(index, prehratia)
    assert values["alokacia"] == {"uplna": False, "planovanych": 4, "indexovanych": 2, "zamietnute": ["c"],
                                  "nezozbierane": ["d"], "relacii_v_skupinach": {"v3-test_events-a": 1,
                                                                                  "v3-test_events-b": 1},
                                  "rozhodnutie": "rozhodnutie vlastnika"}
    assert set(values["relacie"]) == {"a", "b"}


@pytest.mark.parametrize("complete", ["<chyba>", None, 0, "false", 1, True])
def test_blok_neuplnej_alokacie_iba_pri_complete_false(kampan, complete):
    index, prehratia = kampan
    _neuplny(index)
    doc = json.loads(index.read_text())
    if complete == "<chyba>":
        del doc["complete"]
    else:
        doc["complete"] = complete
    index.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="bez vyslovne prijatej|uplny a zaroven"):
        ev.vyhodnot_udalosti(index, prehratia)


@pytest.mark.parametrize("zmena", [
    {"planned_sessions": 5}, {"indexed_sessions": 3}, {"not_captured": []}, {"not_captured": [{"id": "a"}]},
    {"sessions_per_group": {"v3-test_events-a": 2}}, {"rejected": "c"}, {"rejected": [{"meno": "c"}]}])
def test_neuplny_index_s_nesediacimi_poctami_odmietne(kampan, zmena):
    index, prehratia = kampan
    _neuplny(index, **zmena)
    with pytest.raises(ValueError, match="pocty|zoznam relacii"):
        ev.vyhodnot_udalosti(index, prehratia)


def test_prikaz_udalosti_zapise_novy_subor(kampan, tmp_path):
    index, prehratia = kampan
    out = tmp_path / "far_udalosti.json"
    argv = ["udalosti", "--index", str(index), "--replay", *map(str, prehratia), "--out", str(out)]
    assert ev._hlavny(argv) == 0
    doc = json.loads(out.read_text())
    assert doc["values"]["schema"] == "hyptcn3/safeguard-event-far/1" and doc["n"] == 2 and "_zmeny" not in doc
    with pytest.raises(FileExistsError):
        ev._hlavny(argv)


def _korpus(index, prehratia, rola="test_benign", provenance=True):
    """Korpus protokolu v4 (krok B, E2'): tie iste relacie ako role korpusu s udalostami."""
    doc = json.loads(index.read_text())
    sessions = [dict(s, role=rola) for s in doc["sessions"]] + [
        dict(doc["sessions"][0], id="tr", role="train", features_sha256="iny")]
    korpus = index.with_name("corpus.json")
    korpus.write_text(json.dumps({"schema": "hyptcn3/corpus-index/1", "complete": True, "protocol_sha256": "p",
                                  "protocol_config": PROTOKOL, "sessions": sessions}))
    if provenance:
        for out in prehratia:
            konf = json.loads((out / "configuration.json").read_text())
            konf["bundle_manifest"]["provenance"]["corpus_index_sha256"] = _sha(korpus)
            (out / "configuration.json").write_text(json.dumps(konf))
    return korpus


def test_e2_z_korpusu_iba_rola_a_balik_z_toho_korpusu(kampan):
    index, prehratia = kampan
    korpus = _korpus(index, prehratia)
    values, _ = ev.vyhodnot_udalosti(korpus, prehratia, rola="test_benign")
    assert set(values["relacie"]) == {"a", "b"} and values["korpus_rola"] == "test_benign"
    assert values["merane"]["typy"]["zamok_tabulky"]["spolu"]["udalosti_model"] == 1
    with pytest.raises(ValueError, match="urcit rolu"):
        ev.vyhodnot_udalosti(korpus, prehratia)
    with pytest.raises(ValueError, match="iba pre korpus"):
        ev.vyhodnot_udalosti(index, prehratia, rola="dev")
    with pytest.raises(ValueError, match="nemaju zaznam udalosti|archiv nie je"):
        ev.vyhodnot_udalosti(korpus, prehratia, rola="dev")


def test_e2_z_korpusu_odmietne_cudzi_balik_a_korpus_bez_udalosti(kampan):
    index, prehratia = kampan
    korpus = _korpus(index, prehratia, provenance=False)
    with pytest.raises(ValueError, match="nie je natrenovany na tomto korpuse"):
        ev.vyhodnot_udalosti(korpus, prehratia, rola="test_benign")
    doc = json.loads(korpus.read_text())
    doc["protocol_config"] = {k: v for k, v in PROTOKOL.items() if k != "events"}
    korpus.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="nema udalosti"):
        ev.vyhodnot_udalosti(korpus, prehratia, rola="test_benign")


def test_prikaz_e2_test_benign_iba_s_final(kampan, tmp_path):
    index, prehratia = kampan
    korpus = _korpus(index, prehratia)
    argv = ["udalosti", "--index", str(korpus), "--role", "test_benign", "--replay", *map(str, prehratia),
            "--out", str(tmp_path / "e2.json")]
    with pytest.raises(SystemExit, match="--final"):
        ev._hlavny(argv)
    with pytest.raises(SystemExit, match="--final"):
        ev._hlavny(["udalosti", "--index", str(index), "--final", "--replay", *map(str, prehratia),
                    "--out", str(tmp_path / "x.json")])
