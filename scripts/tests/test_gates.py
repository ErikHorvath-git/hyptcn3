"""scripts/gates.py: a stage counts only with a complete, verified record for this protocol and code."""
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from scripts import gates

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
# A small schema-3-like protocol: values of later stages are null or preliminary, determined_at says which.
STAGED = {
    "schema": "hyptcn3/collection-protocol/3", "name": "p", "note": "úsudok autora",
    "invalid_rows": {"max": 3, "traversals": ["processes"]}, "min_score_coverage": 557 / 720,
    "scenarios": {"low": {"intensity": "low", "rate": None}, "high": {"intensity": "high", "rate": None}},
    "analysis": {"k1": {"m": None, "rule": "95th percentile"}, "methods": {"Z1": {"grid": None}, "M": {"grid": None}}},
    "replacement": {"max_per_campaign": None, "same": ["vm"]},
    "determined_at": {"G1": ["analysis.k1.m"], "G2": ["invalid_rows.max", "min_score_coverage", "scenarios.*.rate"],
                      "G3a": ["analysis.methods.*.grid"], "G3b": ["replacement.max_per_campaign"]},
}


def text(doc, **dumps):
    return json.dumps(doc, ensure_ascii=False, **(dumps or {"indent": 1})) + "\n"


def changed(doc, values):
    """`doc` written with the value at each dotted path of `values` replaced."""
    doc = json.loads(json.dumps(doc))
    for path, value in values.items():
        *parents, key = path.split(".")
        node = doc
        for name in parents:
            node = node[name]
        node[key] = value
    return text(doc)


@pytest.fixture
def world(tmp_path, monkeypatch):
    protocol = tmp_path / "protocol.json"
    protocol.write_text('{"name": "p"}\n')
    results = tmp_path / "results"
    results.mkdir()
    # Since package B5b a record of a schema-3 protocol runs its self-check first (selfcheck_problems). The tests of
    # the stage chain and of the hash binding record small schema-3-like documents, which no self-check admits, so
    # it is stubbed here; the tests of the self-check before a record put the real one back (state["selfcheck"]).
    state = {"measurement": "m1", "selfcheck": getattr(gates, "selfcheck_problems", None)}
    monkeypatch.setattr(gates, "measurement_sha256", lambda: state["measurement"])
    monkeypatch.setattr(gates, "commit", lambda: "c" * 40)
    monkeypatch.setattr(gates, "selfcheck_problems", lambda protocol, stage: [], raising=False)
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


@pytest.mark.parametrize("before,after,valid_after", [
    # G2 determines its values (a '*' path among them): G0 and G1 stay valid
    (text(STAGED), changed(STAGED, {"scenarios.low.rate": 120.5, "scenarios.high.rate": 410.0, "invalid_rows.max": 4,
                                    "min_score_coverage": 524 / 720}), ["G0", "G1"]),
    # a changed G1 value reopens G1 and every later stage, not G0
    (text(STAGED), changed(STAGED, {"analysis.k1.m": 0.04}), ["G0"]),
    # G3b determines its value: G0 to G3a stay valid
    (text(STAGED), changed(STAGED, {"replacement.max_per_campaign": 2}), ["G0", "G1", "G2", "G3a"]),
    # a value outside determined_at reopens every stage, also beside a path of a later stage
    (text(STAGED), changed(STAGED, {"invalid_rows.traversals": []}), []),
    # moving a path to another stage changes determined_at itself
    (text(STAGED), changed(STAGED, {"determined_at.G1": [], "determined_at.G2": [
        "invalid_rows.max", "min_score_coverage", "scenarios.*.rate", "analysis.k1.m"]}), []),
    # the same document in other bytes: only G4 and later hash the file
    (text(STAGED), text(STAGED, indent=None), ["G0", "G1", "G2", "G3a", "G3b"]),
    # without determined_at (schemas 1 and 2) every stage hashes the file, as before stage hashes
    (text({"name": "p"}), text({"name": "p"}, indent=None), []),
], ids=["G2_determined", "G1_changed", "G3b_determined", "outside", "determined_at_moved", "bytes_only",
        "no_determined_at"])
def test_a_stage_binds_the_protocol_without_the_values_of_later_stages(world, before, after, valid_after):
    protocol, results, _ = world
    protocol.write_text(before)
    for minutes, stage in enumerate(gates.STAGES):
        assert write(world, stage, minutes)[1] == []
    assert valid(world) == list(gates.STAGES)
    protocol.write_text(after)
    reopened = [row["stage"] for row in gates.status(results, protocol)
                if row["problems"] == ["protocol file changed since the record"]]
    assert valid(world) == valid_after and reopened == [s for s in gates.STAGES if s not in valid_after]


def test_a_record_carries_its_stage_hash_and_names_the_rule(world):
    protocol, _, _ = world
    protocol.write_text(text(STAGED))
    values = json.loads(write(world, "G0")[0].read_text())["values"]
    view = {"schema": "hyptcn3/collection-protocol/3", "name": "p", "note": "úsudok autora",
            "invalid_rows": {"traversals": ["processes"]},
            "scenarios": {"low": {"intensity": "low"}, "high": {"intensity": "high"}},
            "analysis": {"k1": {"rule": "95th percentile"}, "methods": {"Z1": {}, "M": {}}},
            "replacement": {"same": ["vm"]}, "determined_at": STAGED["determined_at"]}
    canonical = json.dumps(view, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert values["protocol_sha256"] == hashlib.sha256(canonical).hexdigest() == gates.stage_sha256(protocol, "G0")
    assert values["protocol_hash_rule"] == (
        "sha256 of the UTF-8 of json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False) of the "
        "protocol without the paths that determined_at assigns to stages after G0")
    assert gates.stage_binding(protocol, "G4") == (gates.sha256(protocol), "sha256 of the file bytes")


@pytest.mark.parametrize("determined_at,error", [
    ({"G2": ["invalid_rows.max"], "G7": ["name"]}, "determined_at must map stage names to lists of dotted paths"),
    ({"G2": ["determined_at.G1"]}, "determined_at path must start with a protocol key other than determined_at: "
                                   "determined_at.G1"),
    ({"G1": ["analysis.k1.m"], "G2": ["analysis.k1"]},
     "determined_at path analysis.k1 (G2) would delete analysis.k1.m (G1)"),
], ids=["unknown_stage", "itself", "deletes_earlier"])
def test_a_determined_at_that_could_unbind_a_value_of_its_own_stage_is_refused(world, determined_at, error):
    protocol, results, _ = world
    protocol.write_text(text(dict(STAGED, determined_at=determined_at)))
    with pytest.raises(ValueError) as refused:
        write(world, "G0")
    assert str(refused.value) == error and list(results.iterdir()) == []


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


# Package B5b: `gates.py record Gk` runs the self-check of a schema-3 protocol for Gk first and writes nothing unless
# every check passed (lead's remarks on B4, part 1, section 2); CRITERIA stay as they are.

V5 = gates.ROOT / "config/collection-v5.json"


def v5_copy(protocol):
    """config/collection-v5.json written to the world's protocol file, the bounds m of G1 null (as today, stated)."""
    doc = json.loads(V5.read_text())
    for name in ("k1", "k2a", "k2b"):
        doc["analysis"][name]["m"] = None
    protocol.write_text(text(doc))
    return doc


def test_a_record_of_a_schema_3_protocol_writes_nothing_unless_its_self_check_passes_for_the_stage(world,
                                                                                                  monkeypatch):
    from scripts import protocol_v5
    protocol, results, state = world
    monkeypatch.setattr(gates, "selfcheck_problems", state["selfcheck"])
    doc = v5_copy(protocol)
    known = {"event type": set(doc["events"]["types"]), "profile": {s["profile"] for s in doc["scenarios"].values()},
             "control kind": set(doc["controls"]["kinds"])}
    # One event type unknown to lab/: the check lab_register fails, and no record is written.
    monkeypatch.setattr(protocol_v5, "lab_names", lambda: dict(known, **{"event type": known["event type"] - {
        "naprazdno"}}))
    with pytest.raises(ValueError) as refused:
        write(world, "G0")
    assert str(refused.value) == ("protocol self-check for stage G0 did not pass, nothing recorded: lab_register "
                                  "failed: unknown to lab/: naprazdno")
    assert list(results.iterdir()) == []
    # Every name known: G0 passes and is recorded; G1 is refused while its bounds m are null.
    monkeypatch.setattr(protocol_v5, "lab_names", lambda: known)
    path, why = write(world, "G0")
    assert why == [] and json.loads(path.read_text())["values"]["criteria"] == passed("G0")
    with pytest.raises(ValueError) as refused:
        write(world, "G1", 1)
    assert str(refused.value) == ("protocol self-check for stage G1 did not pass, nothing recorded: analysis failed: "
                                  + "; ".join(f"null at analysis.{name}.m determined at G1 (stage G1)"
                                              for name in ("k1", "k2a", "k2b")))
    assert list(results.iterdir()) == [path]


def test_the_self_check_before_a_record_reads_schema_3_only(world, tmp_path):
    """Schemas 1 and 2, and a file that is no JSON object, are recorded as before: no self-check applies."""
    protocol, _, state = world
    other = tmp_path / "other.json"
    for content in ('{"name": "p"}\n', '{"schema": "hyptcn3/collection-protocol/2", "name": "p"}\n', "not json\n",
                    "[1, 2]\n"):
        other.write_text(content)
        assert state["selfcheck"](other, "G0") == []


# Package B11 (agent G): the lead's answer to Q24 (2026-11-24), the numbers of the model of the early stop in the record
# of stage G3b, for the owner's decision; no criterion.

def test_a_g3b_record_carries_the_numbers_of_the_early_stop_model_and_no_new_criterion(world, capsys):
    """Every record of stage G3b carries values.owner_information: features/audit_policy.py EARLY_STOP_MODEL (0.12 to
    0.28 false stops per healthy campaign, a model and not a measurement) with its source and note, and no other stage
    carries it. The owner sees it before deciding: the first G3b record, with owner_decision not yet passed, is
    written with passed false and the stage stays open; the record with owner_decision passed follows and passes. The
    criteria of G3b are those of the stage (no new criterion), and the command that writes the record prints the
    numbers beside its result."""
    from features.audit_policy import EARLY_STOP_MODEL
    protocol, results, _ = world
    for minutes, stage in enumerate(("G0", "G1", "G2", "G3a")):
        assert write(world, stage, minutes)[1] == []
    first, why = write(world, "G3b", 4, criteria=passed("G3b", owner_decision={"passed": False, "evidence": "open"}))
    record = json.loads(first.read_text())
    information = record["values"]["owner_information"]
    assert information["early_stop_model"] == EARLY_STOP_MODEL
    assert information["early_stop_model"]["false_stops_per_campaign"] == [0.12, 0.28]
    assert information["source"] == "features/audit_policy.py EARLY_STOP_MODEL" and "Q24" in information["note"]
    assert "no criterion" in information["note"] and "not a measurement" in EARLY_STOP_MODEL["kind"]
    assert why == record["values"]["problems"] == ["criterion not passed: owner_decision"]
    assert record["values"]["passed"] is False and "G3b" not in valid(world)
    final, why = write(world, "G3b", 5)
    assert why == [] and valid(world) == ["G0", "G1", "G2", "G3a", "G3b"]
    assert json.loads(final.read_text())["values"]["owner_information"] == information
    for path in sorted(results.glob("gate_*.json")):
        values = json.loads(path.read_text())["values"]
        assert ("owner_information" in values) == (values["stage"] == "G3b"), path.name
    assert gates.CRITERIA["G3b"] == ("candidate_commit_untouched", "chain_end_to_end", "replacement_limit",
                                     "no_unexplained_periodicity", "audit_bounds_hold", "owner_decision")
    criteria, verification = results.parent / "criteria.json", results.parent / "verification.json"
    criteria.write_text(json.dumps(passed("G3b", owner_decision={"passed": False, "evidence": "open"})))
    verification.write_text(json.dumps(verified("G3b")))
    capsys.readouterr()
    assert gates.main(["record", "G3b", "--protocol", str(protocol), "--results", str(results), "--criteria",
                       str(criteria), "--verification", str(verification), "--command", "command"]) == 2
    printed = json.loads(capsys.readouterr().out)
    assert printed["owner_information"] == information and printed["problems"] == [
        "criterion not passed: owner_decision"]
    assert gates.main(["record", "G0", "--protocol", str(protocol), "--results", str(results), "--criteria",
                       str(criteria), "--verification", str(verification), "--command", "command"]) == 2
    assert "owner_information" not in json.loads(capsys.readouterr().out)
