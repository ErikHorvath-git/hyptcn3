"""The table of the occurrences of the events of G2 (scripts/campaign_report.py events, package H1b6a) on recorded
files: the 38 sessions of the deck (skuska/g2.py draw_deck) as scripts/tests/g2_tabulky.py records them, with the
driver's records written by skuska/g2.py Block.record. Nothing outside tmp_path is written.
"""
import json

import pytest

from scripts import campaign_report
from scripts.tests import g2_tabulky as tab
from scripts.tests import protokol_g0
from skuska import g2, poruchy, pozemna_pravda

TYPES = sorted(tab.P["events"]["types"])
EMPTY = campaign_report.EMPTY_EVENT


def table(tmp_path, recorder, dirs, *extra, protocol=tab.REAL):
    return tab.run("events", dirs, recorder, tmp_path / "out" / "udalosti.json", "--protocol", str(protocol), *extra)


def naprazdno_index(item):
    return next(i for i, x in enumerate(item["events"]) if x["type"] == EMPTY)


def test_every_type_19_times_with_its_predicate_meets_the_criterion(tmp_path, capsys):
    """The deck: every type 19 times on both VMs together, 9 or 10 on each, every occurrence valid, naprazdno without
    an effect: exit 0; the header of check E with the stage G2; every session named with the sha256 of each file it
    read; one row per occurrence with its times and real phases."""
    rec = tab.Recorder(tmp_path)
    dirs = rec.deck()
    code, doc = table(tmp_path, rec, dirs)
    assert code == 0, doc["values"]["findings"] if doc else None
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"]) == ("hyptcn3/g2-events-table/1", 114)
    assert doc["command"].startswith("scripts/campaign_report.py events ")
    v = doc["values"]
    assert (v["stage"], v["criterion"], v["types"], v["needed"], v["needed_per_vm"]) == (
        "G2", "event_effects", TYPES, 19, 8)
    assert v["result"] == {"met": True, "minimums_met": True, "invalid": 0}
    assert (v["missing"], v["findings"]) == ([], [])
    for name in TYPES:
        assert v["counts"][name]["occurrences"] == v["counts"][name]["valid"] == 19
        assert sorted(n["occurrences"] for n in v["counts"][name]["by_vm"].values()) == [9, 10]
    assert len(v["sessions"]) == 38 and all(s["status"] == "counted" for s in v["sessions"])
    first = v["sessions"][0]
    names = {f["name"] for f in first["files"]}
    assert {"session.json", "protocol.json", "record", "audit", "events.json"} <= names
    assert all(len(f["sha256"]) == 64 for f in first["files"])
    assert first["record"]["sha256"] == tab.sha(rec.g2_dir / "zaznamy" / f"{first['session_id']}.json")
    row = v["occurrences"][0]
    item = g2.draw_deck(tab.P)["sessions"][0]["events"][0]
    start = tab.T0 + tab.SPAN
    assert (row["session"], row["vm"], row["type"], row["index"]) == ("g2-a-e01-1", "a", item["type"], 0)
    assert row["times"]["host_start_unix"] == start + item["start_s"]
    assert row["times"]["host_stop_unix"] == start + item["start_s"] + item["duration_s"]
    assert row["phase"]["start_s"] == round((start + item["start_s"] - tab.GRID) % 5, 6)
    assert row["phase"]["stop_s"] == round((row["times"]["host_stop_unix"] - tab.GRID) % 5, 6)
    assert row["planned"]["tenths"] == list(campaign_report.protocol_v5.item_tenths(tab.P, item))
    assert sum(v["phases_per_tenth"]["starts"]) == sum(v["phases_per_tenth"]["stops"]) == 114
    empty = [r for r in v["occurrences"] if r["type"] == EMPTY]
    assert len(empty) == 19 and all(r["no_effect"] == {"ok": True, "violations": []} for r in empty)
    names = {f["name"] for s in v["sessions"] for f in s["files"]}
    assert {"traffic_requests.jsonl", "guest/journal_segment.json", "guest/session_segment.json"} <= names
    out = capsys.readouterr().out
    assert "event_effects: met" in out and f"{TYPES[0]}: 19/19" in out


def test_a_missing_occurrence_and_a_session_without_audit_miss_the_minimum(tmp_path):
    """One deck session not given and one the driver's record names no audit of, both on VM a: their types have fewer
    than 19 on both VMs together and, where they fall so far, fewer than 8 on VM a; exit 1, every missing minimum
    named, the session without audit listed as left out."""
    rec = tab.Recorder(tmp_path)
    deck = {s["id"]: s for s in g2.draw_deck(tab.P)["sessions"]}
    dirs = rec.deck(change=lambda item: {"audit": False} if item["id"] == "e03" else None, skip=("e01",))
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    assert not v["minimums_met"] and v["findings"] == [] and not v["result"]["met"]
    left = [s for s in v["sessions"] if s["status"] == "left_out"]
    assert [(s["session_id"], s["why"]) for s in left] == [("g2-a-e03-1", "the driver's record names no audit of it")]
    short = [x["type"] for x in deck["e01"]["events"]] + [x["type"] for x in deck["e03"]["events"]]
    for name in TYPES:
        assert v["counts"][name]["occurrences"] == 19 - short.count(name)
    for name in set(short):
        assert any(text.startswith(f"{name}: {19 - short.count(name)} occurrence(s) on both VMs together")
                   for text in v["missing"])
    for name in TYPES:
        on_a = sum(x["type"] == name for s in deck.values() if s["vm"] == "a" and s["id"] not in ("e01", "e03")
                   for x in s["events"])
        assert v["counts"][name]["by_vm"]["a"]["occurrences"] == on_a
        assert (f"{name} on VM a: {on_a} occurrence(s), fewer than 8" in v["missing"]) is (on_a < 8)


def test_the_sessions_the_records_leave_out_count_for_nothing(tmp_path):
    """A ground-truth session (values.excluded of H1b1) and a fault session (H4) with invalid events are left out by
    name: no finding of theirs, the counts of the deck alone, exit 0."""
    rec = tab.Recorder(tmp_path)
    dirs = rec.deck()
    item = g2.draw_deck(tab.P)["sessions"][0]
    bad = {0: {**tab.record_of(item["events"][0], tab.T0), "executed": False}}
    truth, _ = rec.session("a", "p01", kind=pozemna_pravda.KIND, items=item["events"], records=bad,
                           excluded={"criteria": list(pozemna_pravda.EXCLUDED), "rule": pozemna_pravda.EXCLUDED_RULE})
    fault, _ = rec.session("b", "f02", kind=poruchy.KIND_FAULT, items=item["events"], records=bad)
    code, doc = table(tmp_path, rec, [*dirs, truth, fault])
    assert code == 0, doc["values"]["findings"]
    v = doc["values"]
    left = {s["session_id"]: s["why"] for s in v["sessions"] if s["status"] == "left_out"}
    assert set(left) == {"g2-a-p01-1", "g2-b-f02-1"}
    assert "its record leaves it out of event_effects" in left["g2-a-p01-1"]
    assert left["g2-b-f02-1"] == "a session of H4 (its record's kind fault)"
    assert all(v["counts"][name]["occurrences"] == 19 for name in TYPES) and len(v["occurrences"]) == 114


def test_an_invalid_predicate_is_a_finding_and_never_left_out(tmp_path):
    """An occurrence whose guest effect did not hold in a session the audit refused, and one not executed in a session
    the load rule leaves uncounted: both findings (Q51), exit 1; the uncounted session's occurrences count towards no
    minimum."""
    rec = tab.Recorder(tmp_path)
    by_id = {s["id"]: s for s in g2.draw_deck(tab.P)["sessions"]}
    j = next(k for k, x in enumerate(by_id["e05"]["events"]) if x["type"] != EMPTY)
    first, second = by_id["e05"]["events"][j], by_id["e06"]["events"][1]

    def change(item):
        if item["id"] == "e05":
            return {"accepted": False, "records": {j: tab.record_of(first, tab.T0 + 5 * tab.SPAN, ok=False)}}
        if item["id"] == "e06":
            return {"counted": False, "records": {1: tab.record_of(second, tab.T0 + 6 * tab.SPAN, executed=False)}}
        return None

    code, doc = table(tmp_path, rec, rec.deck(change=change))
    assert code == 1
    v = doc["values"]
    assert v["minimums_met"] is False  # e06 counts for nothing: its three types have 18.
    assert v["findings"] == [
        f"g2-a-e05-1 #{j} {first['type']} (VM a): the guest's effect predicate did not hold "
        f"({tab.PREDICATE[first['type']]})",
        f"g2-b-e06-1 #1 {second['type']} (VM b, its session counted false): not executed (scripts/collection.py "
        "Events: a call failed or health was not 200 after the stop)"]
    status = {s["session_id"]: (s["status"], s["why"]) for s in v["sessions"]}
    assert status["g2-a-e05-1"] == ("counted", None)
    assert status["g2-b-e06-1"][0] == "load" and "tcn.suchy_beh" in status["g2-b-e06-1"][1]
    e05 = [r for r in v["occurrences"] if r["session"] == "g2-a-e05-1"]
    assert all(r["audit_accepted"] is False and r["counted"] for r in e05)
    for x in by_id["e06"]["events"]:
        assert v["counts"][x["type"]]["occurrences"] == 18
        assert f"{x['type']}: 18 occurrence(s) on both VMs together, fewer than 19 (1 missing)" in v["missing"]


def test_an_occurrence_that_never_started_is_a_finding(tmp_path):
    """An occurrence whose record has no host start (its session ended before its time) is invalid by name and counts
    as an occurrence (Q51: never left out)."""
    rec = tab.Recorder(tmp_path)
    item = g2.draw_deck(tab.P)["sessions"][0]
    j = next(k for k, x in enumerate(item["events"]) if x["type"] != EMPTY)
    x = item["events"][j]
    code, doc = table(tmp_path, rec, rec.deck(change=lambda it: {"records": {j: {**x, "executed": False}}}
                                              if it["id"] == item["id"] else None))
    assert code == 1
    v = doc["values"]
    assert v["minimums_met"] is True and v["counts"][x["type"]]["occurrences"] == 19
    assert v["findings"] == [f"g2-a-e01-1 #{j} {x['type']} (VM a): not started: no host start (the session ended "
                             "before its time; Q51: a finding, never left out); the guest's effect predicate did not "
                             "hold (no effect)"]
    row = next(r for r in v["occurrences"] if r["session"] == "g2-a-e01-1" and r["index"] == j)
    assert (row["window"], row["phase"]["start_s"], row["times"]["host_start_utc"]) == (None, None, None)


EFFECTS = {  # What each effect of naprazdno is named by, and how many violations it gives.
    "request": ("request bad-in POST /api/orders", 1),
    "restart": ("hyptcn-lab@orders: ", 2),
    "traceback": ("traceback or worker error: ", 1),
    "nginx": ("nginx error: ", 1),
    "health": ("health 502, not 200", 2),
}


@pytest.mark.parametrize("effect", sorted(EFFECTS))
def test_naprazdno_with_an_effect_is_a_finding(tmp_path, effect):
    """Q50: an occurrence of naprazdno with an effect (a request in its window outside its intended state, a unit that
    restarted between its start and its stop, a traceback in its window, an nginx error in its window, health not 200
    in its replies) is invalid by name, exit 1; the same evidence outside its window changes nothing."""
    rec = tab.Recorder(tmp_path)
    deck = g2.draw_deck(tab.P)["sessions"]
    number, target = next((n, s) for n, s in enumerate(deck, 1) if any(x["type"] == EMPTY for x in s["events"]))
    i = naprazdno_index(target)
    x = target["events"][i]
    start = tab.T0 + number * tab.SPAN
    inside, outside = start + x["start_s"] + 10, start + x["start_s"] - 200

    def change(item):
        if item["id"] != target["id"]:
            return None
        if effect == "request":
            bad = {"type": "request", "method": "POST", "route": "/api/orders", "outcome": "http_error",
                   "status": 503, "intended_status": None}
            return {"requests": [{**bad, "rid": rid, "t_start_utc": tab.iso(t), "t_end_utc": tab.iso(t + 0.1)}
                                 for rid, t in (("bad-in", inside), ("bad-out", outside))]}
        if effect == "restart":
            return {"records": {i: tab.record_of(x, start, stop_units=tab.units(
                {"hyptcn-lab@orders": {"NRestarts": "1", "ExecMainPID": "999"}}))}}
        if effect == "traceback":
            return {"journal": [(t, "python3[805]: Traceback (most recent call last):") for t in (inside, outside)]}
        if effect == "nginx":
            return {"nginx_errors": [(t, "*1 connect() failed (111: Connection refused)") for t in (inside, outside)]}
        return {"records": {i: tab.record_of(x, start, health=502)}}

    code, doc = table(tmp_path, rec, rec.deck(change=change))
    assert code == 1
    v = doc["values"]
    sid = f"g2-{target['vm']}-{target['id']}-1"
    assert v["minimums_met"] is True and len(v["findings"]) == 1
    assert v["findings"][0].startswith(f"{sid} #{i} {EMPTY} (VM {target['vm']}): an effect of naprazdno "
                                       "(NO_EFFECT_RULE): ")
    row = next(r for r in v["occurrences"] if r["session"] == sid and r["index"] == i)
    assert row["valid"] is False and row["no_effect"]["ok"] is False
    marker, count = EFFECTS[effect]
    assert len(row["no_effect"]["violations"]) == count
    assert all(marker in text for text in row["no_effect"]["violations"]), row["no_effect"]["violations"]


def test_naprazdno_without_its_evidence_is_never_a_pass(tmp_path):
    """Q50 fails closed: a session with naprazdno whose journal segment is missing has an invalid occurrence."""
    rec = tab.Recorder(tmp_path)
    deck = g2.draw_deck(tab.P)["sessions"]
    target = next(s for s in deck if any(x["type"] == EMPTY for x in s["events"]))
    dirs = rec.deck()
    d = next(d for d in dirs if d.name == f"g2-{target['vm']}-{target['id']}-1")
    (d / "guest" / "journal_segment.json").unlink()
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    row = next(r for r in doc["values"]["occurrences"] if r["session"] == d.name and r["type"] == EMPTY)
    assert row["no_effect"]["violations"] == ["the journal: guest/journal_segment.json is missing (a capture that did "
                                              "not complete fetches none)"]


def test_copies_of_the_protocol_that_differ_in_later_values_are_one_protocol(tmp_path):
    """Sessions whose protocol.json is the file as G0 bound it (the rates null) against --protocol after Zápis 1: the
    same outside the paths of G1 and later stages, so the table reads them (gates.stage_sha256 G0)."""
    from scripts import gates
    rec = tab.Recorder(tmp_path)
    dirs = rec.deck(change=lambda item: {"protocol_bytes": protokol_g0.g0_bytes()})
    assert tab.sha(dirs[0] / "protocol.json") != tab.sha(tab.REAL)
    code, doc = table(tmp_path, rec, dirs)
    assert code == 0
    assert doc["values"]["protocol"]["binding_G0"] == gates.stage_sha256(tab.REAL, "G0") == gates.stage_sha256(
        dirs[0] / "protocol.json", "G0")


def test_refusals_are_data_errors_and_nothing_is_written(tmp_path, capsys):
    """A protocol.json that differs from --protocol outside the paths of G1, a record of another session, an audit
    record that differs from the one the record names, a directory named twice, an --out that exists: exit 2, each
    named, nothing written."""
    rec = tab.Recorder(tmp_path)
    p = json.loads(tab.REAL.read_text())
    p["events"]["grace_s"] = 61
    other = tmp_path / "other.json"
    other.write_text(json.dumps(p, indent=2))
    deck = g2.draw_deck(tab.P)["sessions"]
    d1, _ = rec.session("a", "e01", items=deck[0]["events"], protocol_bytes=other.read_bytes())
    d2, _ = rec.session("b", "e02", items=deck[1]["events"])
    record = rec.g2_dir / "zaznamy" / f"{d2.name}.json"
    doc = json.loads(record.read_text())
    doc["values"]["session_json_sha256"] = "0" * 64
    record.write_text(json.dumps(doc))
    d3, _ = rec.session("a", "e03", items=deck[2]["events"])
    audit = next(d3.glob("audit_*.json"))
    audit.write_text(audit.read_text() + " ")
    out = tmp_path / "out" / "udalosti.json"
    assert table(tmp_path, rec, [d1, d2, d3]) == (2, None)
    err = capsys.readouterr().err
    assert "differs from --protocol" in err and "outside the paths of G1 and later stages" in err
    assert "the driver's record is not of this session" in err
    assert "not the audit record of this session that the driver's record names" in err
    assert "3 refusal(s): no table, nothing written" in err and not out.exists()
    assert table(tmp_path, rec, [d1, d1]) == (2, None)
    assert "named more than once" in capsys.readouterr().err
    out.parent.mkdir(exist_ok=True)
    out.write_text("{}")
    assert campaign_report.main(["events", str(d3), "--protocol", str(tab.REAL), "--g2-dir", str(rec.g2_dir),
                                 "--out", str(out)]) == 2
    assert out.read_text() == "{}"
