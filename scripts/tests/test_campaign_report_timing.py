"""The mode timing of scripts/campaign_report.py (criterion worst_case_timing of G2, package H1b4) on recorded files:
the records, session files, sidecars and audits a timing block of skuska/cas.py wrote with the fakes of
skuska/tests/cas_fakes.py (no VM, no root, nothing outside tmp_path).
"""
import hashlib
import json
from pathlib import Path

import pytest

from scripts import campaign_report
from skuska import cas
from skuska.tests import cas_fakes


def run_block(tmp_path, only=None, **lab_options):
    driver, labs, clock = cas_fakes.setup(tmp_path, only=only, **lab_options)
    result = driver.run()
    return driver, labs, result


def report(records, out, *others, capsys=None):
    argv = ["timing", *map(str, records), *(["--others", *map(str, others)] if others else []), "--out", str(out)]
    code = campaign_report.main(argv)
    doc = json.loads(out.read_text()) if out.exists() else None
    return code, doc


@pytest.fixture(scope="module")
def full_block(tmp_path_factory):
    """All four pairs; VM b's preflight 3.5 s longer, so each at-once pair starts again once (RESTART_RULE (1))."""
    tmp_path = tmp_path_factory.mktemp("cas")
    driver, labs, result = run_block(tmp_path, b={"pre": 153.5})
    assert result["stopped"] is None
    return driver, sorted(driver.places.records.glob("g2-*-cas*.json"))


def test_the_report_of_the_four_pairs_meets_the_criterion(full_block, tmp_path, capsys):
    """Every mode has its 2 pairs, each VM collected once during the other's audit and archive, no maximum above its
    bound: exit 0; the attempts stopped by the restart rule are listed, not judged; both definitions of Q58 are in the
    record, which has check E's header."""
    driver, records = full_block
    code, doc = report(records, tmp_path / "timing.json")
    assert code == 0
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    v = doc["values"]
    assert v["definitions"] == {"modes": cas.MODES_RULE, "windows": cas.WINDOWS_RULE}
    assert v["result"]["met_pairs"] == {"at_once": ["cas1", "cas2"], "shifted": ["cas3", "cas4"]}
    assert v["result"]["collecting_vms"] == ["a", "b"] and v["result"]["met"] is True and v["findings"] == []
    rows = {(r["pair"], r["attempt"]): r for r in v["attempts"]}
    assert {key: r["status"] for key, r in rows.items()} == {
        ("cas1", 1): "restarted", ("cas1", 2): "judged", ("cas2", 1): "restarted", ("cas2", 2): "judged",
        ("cas3", 1): "judged", ("cas4", 1): "judged"}
    at_once = rows[("cas1", 2)]
    assert at_once["met"] and at_once["mode"] == {"measured": "at_once", "met": True}
    assert at_once["full_snapshots"]["shift_s"] == pytest.approx(0.0, abs=1e-3)
    assert at_once["grids"]["shift_s"] == pytest.approx(0.0, abs=1e-3) and at_once["grids"]["vms"] == ["a", "b"]
    assert at_once["windows"]["load"] == {"a": True, "b": True}
    shifted = rows[("cas3", 1)]
    assert shifted["mode"] == {"measured": "shifted", "met": True} and shifted["judgment"]["collecting"] == "b"
    assert (shifted["windows"]["audit"], shifted["windows"]["archive"]) == (True, False)
    assert rows[("cas4", 1)]["windows"]["archive"] is True and rows[("cas4", 1)]["judgment"]["collecting"] == "a"
    timing = shifted["sessions"]["b"]
    assert timing["timing"] == {"lateness_s_max": 0.004, "delta_ms_max": 900.0, "full_ms_max": 2200.0}
    assert timing["bounds"] == {"lateness_s_max": 0.5, "delta_ms_max": 1500, "full_ms_max": 3500}
    assert timing["over_bounds"] == []
    assert rows[("cas1", 1)]["why"][0].startswith("Restart: RESTART_RULE (1)")
    out = capsys.readouterr().out
    assert "worst_case_timing: met; at_once 2/2 pair(s); shifted 2/2 pair(s); 0 finding(s)" in out
    assert "cas3 attempt 1 (shifted, target audit): met, measured shifted" in out


def test_a_cycle_over_its_bound_is_a_finding(tmp_path):
    """A full cycle of 3600 ms (bound 3500) in the collecting session of cas3: the row names it, exit 1; the missing
    at-once pairs and VM a's missing collection are findings too."""
    driver, labs, result = run_block(tmp_path, only=["cas3"], b={"timing": {"g2-b-cas3-1": {"full_ms_max": 3600.0}}})
    records = sorted(driver.places.records.glob("g2-*-cas*.json"))
    code, doc = report(records, tmp_path / "timing.json")
    assert code == 1
    v = doc["values"]
    assert v["result"]["met"] is False and v["result"]["over_bounds"] == [
        "cas3 attempt 1: VM b: full_ms_max 3600.0 above 3500"]
    assert v["findings"] == ["cas3 attempt 1: VM b: full_ms_max 3600.0 above 3500",
                             "mode at_once: 0 pair(s) met their plan, fewer than 2",
                             "mode shifted: 1 pair(s) met their plan, fewer than 2",
                             "VM a never collected the target full snapshot of a met shifted pair during the other "
                             "VM's audit and archive"]


def test_a_pair_that_misses_its_mode_is_listed_with_its_reasons(tmp_path):
    """cas2's first attempt ran to its end with VM b's target 3 s late: judged; its seq-0 cycles overlap, its targets
    not, so it is in neither mode (MODES_RULE); missed, no finding by itself; its second attempt met."""
    driver, labs, result = run_block(tmp_path, only=["cas2"], b={"late": {"g2-b-cas2-1": 3.0}})
    records = sorted(driver.places.records.glob("g2-*-cas*.json"))
    code, doc = report(records, tmp_path / "timing.json")
    rows = {(r["pair"], r["attempt"]): r for r in doc["values"]["attempts"]}
    first = rows[("cas2", 1)]
    assert (first["status"], first["met"], first["mode"]) == ("judged", False, {"measured": "neither", "met": False})
    assert first["full_snapshots"]["overlaps"] == [{"a": 0, "b": 0, "overlap_s": 2.0}]
    assert first["why"] == ["the target full cycles (seq 360) of VM a and VM b do not overlap"]
    assert first["full_snapshots"]["shift_s"] == pytest.approx(3.0, abs=1e-3)
    assert rows[("cas2", 2)]["met"] is True
    assert not any(text.startswith("cas2 attempt 1") for text in doc["values"]["findings"]) and code == 1


def test_an_attempt_whose_run_failed_is_a_finding(tmp_path):
    """RESTART_RULE (4) of skuska/cas.py: VM a's run of cas1 exited 1 and the block stopped; both sessions were audited
    (as skuska/g2.py audits a run that exits non-zero), but the attempt is failed, not judged, and a finding."""
    driver, labs, result = run_block(tmp_path, only=["cas1"], a={"rc": {"g2-a-cas1-1": 1}})
    assert "exited 1" in result["stopped"]
    records = sorted(driver.places.records.glob("g2-*-cas*.json"))
    code, doc = report(records, tmp_path / "timing.json")
    [row] = doc["values"]["attempts"]
    assert (row["status"], row["why"], code) == ("failed", ["VM a: the run exited 1"], 1)
    assert "cas1 attempt 1: failed: VM a: the run exited 1" in doc["values"]["findings"]


def other_run(tmp_path, vm, name, count, protocol_sha):
    """The audit record of another error-free G2 run as P2 reads it: its session.json names the VM and the domain."""
    session = tmp_path / "ostatne" / name
    session.mkdir(parents=True)
    (session / "session.json").write_text(json.dumps({"session_id": name, "vm": vm, "domain": f"hyptcn-lab-{vm}"}))
    audit = session / "audit_20261126T000000000000Z.json"
    audit.write_text(json.dumps({"schema": campaign_report.AUDIT_SCHEMA, "values": {
        "protocol_sha256": protocol_sha, "accepted": True, "reasons": [], "session_dir": str(session),
        "session_sha256": hashlib.sha256((session / "session.json").read_bytes()).hexdigest(),
        "collector_majflt": {"max": count, "max_seq": 12, "sum": count, "cycles": 720}}}))
    return audit


def test_the_major_faults_beside_the_other_error_free_runs(tmp_path):
    """Q59: per VM the worst case's largest count, through P2, beside P2's largest over the other runs; on VM a the
    worst case (4) sets the maximum, on VM b not (0 against 5), and the value P2 proposes over both VMs stays 5; an
    audit of a timing session given among the others is refused there."""
    majflt = {"g2-a-cas3-1": 4}
    driver, labs, result = run_block(tmp_path, only=["cas3"], a={"majflt": majflt})
    records = sorted(driver.places.records.glob("g2-*-cas*.json"))
    sha = hashlib.sha256(driver.protocol_path.read_bytes()).hexdigest()
    ours = json.loads((driver.places.records / "g2-b-cas3-1.json").read_text())["values"]["audit"]["report"]
    others = [other_run(tmp_path, "a", "g2-a-e01-1", 2, sha), other_run(tmp_path, "b", "g2-b-e02-1", 5, sha), ours]
    code, doc = report(records, tmp_path / "timing.json", *others)
    m = doc["values"]["majflt"]
    assert m["p2"] == "applied" and m["others_given"] == 3
    assert (m["timing"]["a"]["max"], m["timing"]["a"]["seq"], m["timing"]["a"]["counted_by_p2"]) == (4, 360, True)
    assert m["timing"]["b"]["max"] == 0 and {vm: x["max"] for vm, x in m["others"].items()} == {"a": 2, "b": 5}
    assert m["sets_maximum"] == ["VM a: the worst case sets the maximum, 4 in session g2-a-cas3-1 seq 360 (the other "
                                 "runs: 2)"]
    assert len(m["others_refused"]) == 1 and "the audit of a timing session" in m["others_refused"][0]


def test_refusals_of_the_mode(full_block, tmp_path, capsys):
    """Each a data error, nothing written: a record named twice, a record that is no timing record, a session.json
    that changed after its record, and an --out that exists."""
    driver, records = full_block
    assert report([records[0], records[0]], tmp_path / "a.json")[0] == 2
    deck_like = tmp_path / "g2-a-e01-1.json"
    doc = json.loads(records[0].read_text())
    doc["values"]["kind"] = "deck"
    deck_like.write_text(json.dumps(doc))
    assert report([deck_like], tmp_path / "b.json")[0] == 2
    assert "no record of a timing session" in capsys.readouterr().err
    copy = tmp_path / "copy"
    session = Path(json.loads(records[-1].read_text())["values"]["session_dir"])
    meta = (session / "session.json").read_bytes()
    try:
        (session / "session.json").write_bytes(meta.replace(b'"campaign_id": "g2"', b'"campaign_id": "g3"'))
        assert report(records, tmp_path / "c.json")[0] == 2
        assert "is not the one the record names" in capsys.readouterr().err
    finally:
        (session / "session.json").write_bytes(meta)
    existing = tmp_path / "d.json"
    existing.write_text("{}")
    assert report(records, existing)[0] == 2
    assert not any((tmp_path / name).exists() for name in ("a.json", "b.json", "c.json")) and not copy.exists()
