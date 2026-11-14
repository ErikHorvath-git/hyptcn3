"""Pilotna pozitivna kontrola W+X a memfd (protokol v4, events.pilot_controls).

Mechanika na syntetickych riadkoch: rozvrh pilota, validacia protokolu a brana
auditu pilota. Ziadne cislo tu nie je meranie (HONESTY P4).
"""
import json
from pathlib import Path

import pytest

from scripts import collection

ROOT = Path(__file__).resolve().parents[2]
V4 = ROOT / "config/collection-v4.json"


def test_kontrola_je_iba_v_pilote_v4():
    p = collection.protocol(V4)
    pilot = collection.pilot_events(p)
    assert [e["type"] for e in pilot][-1] == "kontrola_wx_memfd"
    assert pilot[-1]["class"] == collection.CONTROL_CLASS
    assert all("kontrola_wx_memfd" not in {e["type"] for e in s.get("events", [])}
               for s in collection.plan(p)["sessions"])
    assert collection.pilot_events(collection.protocol(ROOT / "config/collection-v3.json"))[-1]["type"] \
        == "restart_databazy"


@pytest.mark.parametrize("zmena", [
    [{"type": "zataz_pamate", "start_s": 2280, "duration_s": 120}],
    [{"type": "kontrola_wx_memfd", "start_s": 2280}],
    [{"type": "kontrola_wx_memfd", "start_s": 1600, "duration_s": 120}],   # Bez medzery po udalosti.
    [{"type": "kontrola_wx_memfd", "start_s": 2900, "duration_s": 120}],   # Nezmesti sa do pilota.
])
def test_neplatna_kontrola_v_protokole(tmp_path, zmena):
    doc = json.loads(V4.read_text())
    doc["events"]["pilot_controls"] = zmena
    path = tmp_path / "p.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        collection.protocol(path)


def _vysledok(vzory_po_riadkoch):
    return {"casy": [100.0 + 5 * i for i in range(len(vzory_po_riadkoch))],
            "quality": [{"memory_patterns": v} for v in vzory_po_riadkoch]}


def _udalosti(tmp_path, executed=True, start=110.0, stop=125.0):
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"events": [
        {"type": "restart_databazy", "executed": True, "host_started_unix": 100.0, "host_stop_unix": 105.0},
        {"type": "kontrola_wx_memfd", "executed": executed, "host_started_unix": start, "host_stop_unix": stop}]}))
    return path


OBA = [{"pid": 9, "comm": "python3", "kind": "wx"}, {"pid": 9, "comm": "python3", "kind": "memfd_fd"}]


def test_kontrola_zachytena_vo_vsetkych_riadkoch(tmp_path):
    p = collection.protocol(V4)
    # Riadky 115, 120, 125 su vnutri [110 + 5, 125]; riadok 130 je mimo a ma vzor (len sa hlasi).
    out = collection.positive_controls(_vysledok([[], [], [], OBA, OBA, OBA, OBA[:1]]), _udalosti(tmp_path), p)
    assert out["problems"] == []
    assert out["controls"] == [{"type": "kontrola_wx_memfd", "executed": True, "rows": 3, "rows_with_patterns": 3}]
    assert out["rows_with_patterns_outside"] == 1


@pytest.mark.parametrize("riadky,sprava", [
    ([[], [], [], OBA, OBA[:1], OBA], "not detected"),                      # Jeden riadok bez memfd.
    ([[], [], [], OBA, [dict(OBA[0], pid=1), OBA[1]], OBA], "not detected"),  # Vzory v dvoch procesoch.
])
def test_kontrola_nezachytena(tmp_path, riadky, sprava):
    out = collection.positive_controls(_vysledok(riadky), _udalosti(tmp_path), collection.protocol(V4))
    assert any(sprava in x for x in out["problems"])


def test_nevykonana_alebo_chybajuca_kontrola(tmp_path):
    p = collection.protocol(V4)
    out = collection.positive_controls(_vysledok([OBA] * 6), _udalosti(tmp_path, executed=False), p)
    assert any("not executed" in x for x in out["problems"])
    out = collection.positive_controls(_vysledok([OBA] * 6), tmp_path / "chyba.json", p)
    assert any("events.json" in x for x in out["problems"])
    empty = tmp_path / "e.json"
    empty.write_text(json.dumps({"events": []}))
    assert any("missing" in x for x in collection.positive_controls(_vysledok([]), empty, p)["problems"])
