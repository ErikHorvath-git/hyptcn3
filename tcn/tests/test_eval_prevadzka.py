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


def test_prikaz_udalosti_zapise_novy_subor(kampan, tmp_path):
    index, prehratia = kampan
    out = tmp_path / "far_udalosti.json"
    argv = ["udalosti", "--index", str(index), "--replay", *map(str, prehratia), "--out", str(out)]
    assert ev._hlavny(argv) == 0
    doc = json.loads(out.read_text())
    assert doc["values"]["schema"] == "hyptcn3/safeguard-event-far/1" and doc["n"] == 2 and "_zmeny" not in doc
    with pytest.raises(FileExistsError):
        ev._hlavny(argv)
