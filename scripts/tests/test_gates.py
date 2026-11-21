"""scripts/gates.py: a stage counts only with a complete, verified record for this protocol and code."""
from datetime import datetime, timedelta, timezone
import json

import pytest

from scripts import gates

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def world(tmp_path, monkeypatch):
    protocol = tmp_path / "protocol.json"
    protocol.write_text('{"name": "p"}\n')
    results = tmp_path / "results"
    results.mkdir()
    state = {"measurement": "m1"}
    monkeypatch.setattr(gates, "measurement_sha256", lambda: state["measurement"])
    monkeypatch.setattr(gates, "commit", lambda: "c" * 40)
    return protocol, results, state


def passed(stage, **change):
    criteria = {name: {"passed": True, "evidence": "data/results/x.json"} for name in gates.CRITERIA[stage]}
    criteria.update(change)
    return criteria


def verified(stage, **change):
    verdicts = {name: "confirmed" for name in gates.CRITERIA[stage]}
    verdicts.update(change)
    return {"independent": True, "by": "second reader", "verdicts": verdicts}


def write(world, stage, minutes=0, criteria=None, verification=None):
    protocol, results, _ = world
    return gates.write_record(results, protocol, stage, criteria or passed(stage), verification or verified(stage),
                              "command", now=T0 + timedelta(minutes=minutes))


def valid(world):
    protocol, results, _ = world
    return [row["stage"] for row in gates.status(results, protocol) if row["passed"]]


def test_stages_pass_in_order_and_only_with_their_predecessors(world):
    protocol, results, _ = world
    assert valid(world) == []
    with pytest.raises(ValueError, match="stage G0 is not valid: no record"):
        write(world, "G1")
    path, why = write(world, "G0")
    assert why == [] and json.loads(path.read_text())["values"]["passed"] is True
    write(world, "G1", 1)
    assert valid(world) == ["G0", "G1"]
    gates.require(results, protocol, "G2")
    with pytest.raises(ValueError, match="stage G2 is not valid"):
        gates.require(results, protocol, "G3a")


@pytest.mark.parametrize("criteria,verification,problem", [
    ({"tests": {"passed": False, "evidence": "log"}}, {}, "criterion not passed: tests"),
    ({"tests": {"passed": True, "evidence": " "}}, {}, "criterion without evidence: tests"),
    ({"tests": {"passed": "yes", "evidence": "log"}}, {}, "criterion not passed: tests"),
    ({}, {"tests": "refuted"}, "verification refuted: tests"),
    ({}, {"tests": "unverifiable"}, "verification unverifiable: tests"),
])
def test_a_failed_unproven_or_refuted_criterion_keeps_the_stage_open(world, criteria, verification, problem):
    path, why = write(world, "G0", criteria=passed("G0", **criteria), verification=verified("G0", **verification))
    assert problem in why and json.loads(path.read_text())["values"]["passed"] is False
    assert valid(world) == []


def test_record_must_list_exactly_the_criteria_of_the_stage_and_be_verified_independently(world):
    short = passed("G0")
    del short["tests"]
    assert write(world, "G0", 0, criteria=short)[1] == ["criteria differ from the stage definition"]
    extra = dict(passed("G0"), invented={"passed": True, "evidence": "x"})
    assert write(world, "G0", 1, criteria=extra)[1] == ["criteria differ from the stage definition"]
    own = dict(verified("G0"), independent=False)
    assert write(world, "G0", 2, verification=own)[1] == ["no independent verification"]
    partial = verified("G0")
    del partial["verdicts"]["tests"]
    assert write(world, "G0", 3, verification=partial)[1] == ["verification does not cover every criterion"]
    assert valid(world) == []


def test_changed_measurement_code_or_protocol_reopens_every_stage(world):
    protocol, results, state = world
    write(world, "G0")
    write(world, "G1", 1)
    state["measurement"] = "m2"
    rows = gates.status(results, protocol)
    assert rows[0]["problems"] == ["measurement code changed since the record"] and not rows[1]["passed"]
    state["measurement"] = "m1"
    protocol.write_text('{"name": "other"}\n')
    assert gates.status(results, protocol)[0]["problems"] == ["protocol file changed since the record"]


def test_the_newest_record_decides_and_records_are_never_overwritten(world):
    write(world, "G0")
    write(world, "G0", 5, criteria=passed("G0", tests={"passed": False, "evidence": "log"}))
    assert valid(world) == []
    write(world, "G0", 9)
    assert valid(world) == ["G0"]
    with pytest.raises(FileExistsError):
        write(world, "G0", 9)


def test_cli_reports_status_and_refuses_a_stage_without_its_predecessor(world, capsys):
    protocol, results, _ = world
    assert gates.main(["status", "--protocol", str(protocol), "--results", str(results)]) == 2
    assert json.loads(capsys.readouterr().out)[0]["problems"] == ["no record"]
    assert gates.main(["require", "G1", "--protocol", str(protocol), "--results", str(results)]) == 2
    assert "stage G0 is not valid" in capsys.readouterr().err
    write(world, "G0")
    assert gates.main(["require", "G1", "--protocol", str(protocol), "--results", str(results)]) == 0


def test_gate_records_carry_the_header_the_claims_check_requires(world):
    record = json.loads(write(world, "G0")[0].read_text())
    assert {"schema", "date", "commit", "host", "guest", "command", "n", "values"} <= set(record)
    assert record["values"]["harness_sha256"] == gates.sha256(gates.__file__)
