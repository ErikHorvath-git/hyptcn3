"""
The protocol's invalid_rows rule as its consumers read it (features/quality.py, features/acceptance.py).

The audit (scripts/collection.py), corpus building, training and the comparison
methods, both archive replays and the FAR evaluation all call the functions
tested here. Synthetic rows only; nothing here is a measurement.
"""
import json

import numpy as np
import pytest

from features import acceptance, quality
from features.coverage import ideal_windows
from features.snapshot import MENA, SCHEMA
from scripts import collection

RULE = {"invalid_rows": {"max": 2, "traversals": ["processes"]}}
OPEN = {"truncated_traversals": ["processes"], "read_errors": 0, "filled_zero": 0}
GOOD = {"truncated_traversals": [], "read_errors": 0, "filled_zero": 0}
RECORD = dict(GOOD, model_valid=True, behavior_valid=True, traversals_complete=True, inconclusive=["text_integrity"],
              findings=[])
LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 4096]],
          "regions": [{"gpa": 0, "bytes": 16777216}], "memsize": 16777216, "vcpus": 1}
# One chain of 8 rows (a full snapshot at seq 0): windows of 2 rows end at seq 2..7, an invalid row at s silences
# those ending at s..s+2, so rows 1 and 6, the honest case with the fewest windows, leave 2 of 8 (at seq 4 and 5).
PROTOCOL = {"schema": "hyptcn3/collection-protocol/2", "quality_policy": "behavioral-inputs-v1", "roles": {"train": 1},
            "cycles": 8, "full_every": 8, "window_rows": 2, "stride": 1, "interval_s": 5, "max_gap_s": 7.5,
            "min_score_coverage": 2 / 8}
RULED = dict(PROTOCOL, **RULE)
INCOMPLETE = "incomplete features in accepted audit"


def rows(bad, n=8):
    """seq, valid and quality of an archive with n rows; bad = {seq: quality of the invalid row}."""
    return (list(range(n)), [i not in bad for i in range(n)], [dict(bad.get(i, GOOD)) for i in range(n)])


def pairs(bad):
    """The invalid rows as the kernel of the rule reads them: (seq, quality) pairs."""
    return sorted((seq, dict(q)) for seq, q in bad.items())


def archive(bad, n=8):
    """Loaded feature archive of session s with n rows; bad = {seq: quality fields of the invalid row}.

    Like features.snapshot, the row after an invalid one has no predecessor.
    """
    records = [dict(RECORD, model_valid=False, behavior_valid=False, traversals_complete=False, **bad[i])
               if i in bad else dict(RECORD) for i in range(n)]
    matrix = np.zeros((n, len(MENA)))
    matrix[0, MENA.index("je_plna")] = 1
    matrix[:, MENA.index("ma_predchodcu")] = [i > 0 and i - 1 not in bad for i in range(n)]
    return {"schema": np.array(SCHEMA), "mena": np.array(MENA), "matica": matrix, "seq": np.arange(n),
            "casy": 1700000000. + PROTOCOL["interval_s"] * np.arange(n),
            "valid": np.array([q["behavior_valid"] for q in records]), "perbin": np.zeros((n, 1, 4)),
            "biny": np.array([0]), "chain_ids": np.array(["chain"] * n), "quality_json": np.array(json.dumps(records)),
            "quality_policy": np.array("behavioral-inputs-v1"), "layout_json": np.array(json.dumps(LAYOUT))}


def audit(data, protocol, *listed):
    """Audit values written from the verdict of the archive, as the session audit writes them.

    With `listed` the record is the forgery of a refused case: a clean acceptance whose verdict tolerates `listed`.
    """
    verdict = acceptance.judge(data, protocol, "s", "train")[0]
    if listed:
        verdict = dict(verdict, accepted=True, reasons=[], codes=[], tolerated_invalid_seq=listed[0])
    return {"accepted": True, "reasons": [], "role": "train", "snapshots": verdict["snapshots"],
            "windows": verdict["windows"], "score_coverage": verdict["score_coverage"],
            "quality": {"tolerated_invalid_seq": verdict["tolerated_invalid_seq"]}, "acceptance": verdict}


def replay(bad, n=8, **changes):
    """Detector rows of an archive replay: an invalid row is an unscored input error with reason invalid_input."""
    out = []
    for seq in range(n):
        row = {"seq": seq, "model_state": "monitoring", "reason": None, "fatal": False}
        if seq in bad:
            row.update({"model_state": "input_error", "reason": "invalid_input", "quality": dict(bad[seq])}, **changes)
        out.append(row)
    return out


def test_the_audit_and_its_consumers_share_one_rule():
    assert collection.tolerated_invalid_rows is quality.tolerated_invalid_rows
    assert collection.invalid_rows_rule is quality.invalid_rows_rule
    # A tracked record script (data/results/collection_worker_resonance_20261120/record.py) reads this one there.
    assert collection.ideal_windows is ideal_windows


def test_rule_as_its_readers_get_it():
    assert quality.invalid_rows_rule({}) is None
    assert quality.invalid_rows_rule(RULE) == RULE["invalid_rows"]
    assert quality.invalid_rows_rule({"invalid_rows": dict(RULE["invalid_rows"], max=0, note="x")})["max"] == 0


MALFORMED = {
    "null": None,
    "list": ["processes"],
    "without_max": {"traversals": ["processes"]},
    "without_traversals": {"max": 2},
    "negative_max": {"max": -1, "traversals": ["processes"]},
    "text_max": {"max": "2", "traversals": ["processes"]},
    "bool_max": {"max": True, "traversals": ["processes"]},
    "float_max": {"max": 2.0, "traversals": ["processes"]},
    "no_traversal": {"max": 2, "traversals": []},
    "text_traversals": {"max": 2, "traversals": "processes"},
    "object_traversals": {"max": 2, "traversals": {"processes": 1}},
    "unknown_traversal": {"max": 2, "traversals": ["processes", "slots"]},
    "unknown_key": {"max": 2, "traversals": ["processes"], "min": 0},
}


@pytest.mark.parametrize("rule", MALFORMED.values(), ids=MALFORMED)
@pytest.mark.parametrize("bad", [{}, {3: OPEN}], ids=["all_rows_valid", "one_invalid_row"])
def test_malformed_rule_is_refused_wherever_it_is_read(rule, bad):
    """The protocol loader refuses such a rule; an index or a bundle manifest can still carry one.

    The loader's own check (collection.check_invalid_rows) is the first reader in the list. The record and the
    archive the acceptance readers get are honest under a well-formed rule.
    """
    protocol = {"invalid_rows": rule}
    seq, valid, quality_ = rows(bad)
    data = archive(bad)
    record = audit(data, RULED)
    for call in (lambda: collection.check_invalid_rows(dict(protocol, schema="hyptcn3/collection-protocol/2")),
                 lambda: quality.invalid_rows_rule(protocol),
                 lambda: quality.tolerated_invalid_rows({"seq": seq, "valid": valid, "quality": quality_}, protocol),
                 lambda: acceptance.assignment(protocol, "train"),
                 lambda: acceptance.decide(protocol, "train", record["acceptance"]["facts"]),
                 lambda: acceptance.require_recorded(protocol, "train", record),
                 lambda: acceptance.require_accepted(data, protocol, "s", "train", record),
                 lambda: quality.tolerated_input_errors(replay(bad), protocol)):
        with pytest.raises(ValueError, match="invalid invalid_rows rule"):
            call()


@pytest.mark.parametrize("protocol", [None, [], "invalid_rows"], ids=["none", "list", "text"])
def test_protocol_that_is_not_an_object_is_refused(protocol):
    data = archive({})
    record = audit(data, RULED)
    for call in (lambda: quality.invalid_rows_rule(protocol),
                 lambda: acceptance.assignment(protocol, "train"),
                 lambda: acceptance.decide(protocol, "train", record["acceptance"]["facts"]),
                 lambda: acceptance.require_recorded(protocol, "train", record),
                 lambda: acceptance.require_accepted(data, protocol, "s", "train", record),
                 lambda: quality.tolerated_input_errors(replay({}), protocol)):
        with pytest.raises(ValueError, match="invalid invalid_rows rule"):
            call()


def test_accepted_archive_without_invalid_rows_needs_no_rule():
    """An honest record of a clean archive is accepted with or without a rule.

    An empty record, or a list naming rows the archive does not have, is not the record of that archive.
    """
    data = archive({})
    assert quality.tolerated_rows([], None) == [] and quality.tolerated_rows([], RULE["invalid_rows"]) == []
    for protocol in (PROTOCOL, RULED):
        assert acceptance.require_accepted(data, protocol, "s", "train", audit(data, protocol))[
            "tolerated_invalid_seq"] == []
    with pytest.raises(ValueError, match="unaccepted audit: the record does not state a clean acceptance"):
        acceptance.require_accepted(data, PROTOCOL, "s", "train", {})
    with pytest.raises(ValueError, match="audit record differs from the acceptance decision"):
        acceptance.require_accepted(data, RULED, "s", "train", audit(data, RULED, [3]))


def test_accepted_archive_keeps_the_rows_the_audit_tolerated():
    for bad, seqs in (({3: OPEN}, [3]), ({1: OPEN, 6: OPEN}, [1, 6])):
        data = archive(bad)
        assert quality.row_rule_failure(pairs(bad), RULE["invalid_rows"]) is None
        assert quality.tolerated_rows(pairs(bad), RULE["invalid_rows"]) == seqs
        assert acceptance.require_accepted(data, RULED, "s", "train", audit(data, RULED))[
            "tolerated_invalid_seq"] == seqs


@pytest.mark.parametrize("bad, listed, protocol, code, message", [
    ({3: OPEN}, [], RULE, None, INCOMPLETE),
    ({3: OPEN}, None, RULE, None, INCOMPLETE),
    ({1: OPEN, 6: OPEN}, [1], RULE, None, INCOMPLETE),
    ({3: OPEN}, [3], {}, "no_rule", "more invalid rows than the protocol tolerates"),
    ({1: OPEN, 3: OPEN, 6: OPEN}, [1, 3, 6], RULE, "over_max", "more invalid rows than the protocol tolerates"),
    ({3: dict(OPEN, truncated_traversals=["modules"])}, [3], RULE, "cause", "cause the protocol does not tolerate"),
    ({3: dict(OPEN, truncated_traversals=["processes", "modules"])}, [3], RULE, "cause",
     "cause the protocol does not tolerate"),
    ({3: dict(OPEN, read_errors=1)}, [3], RULE, "cause", "cause the protocol does not tolerate"),
    ({3: dict(OPEN, filled_zero=4096)}, [3], RULE, "cause", "cause the protocol does not tolerate"),
    ({3: GOOD}, [3], RULE, "cause", "cause the protocol does not tolerate"),
    ({3: {"truncated_traversals": {"processes": 1}}}, [3], RULE, "cause", "cause the protocol does not tolerate"),
    ({3: {"truncated_traversals": "processes"}}, [3], RULE, "cause", "cause the protocol does not tolerate"),
], ids=["not_listed", "audit_without_list", "one_not_listed", "no_rule", "over_max", "other_traversal",
        "two_traversals", "read_error", "filled_zero", "no_traversal", "traversals_as_object", "traversals_as_text"])
def test_accepted_archive_outside_the_rule_is_refused(bad, listed, protocol, code, message):
    """The kernel names why the rule does not cover the rows; the forged record states the rest of an acceptance.

    Code None: the rule covers the rows and the record omits some of them.
    """
    rule = quality.invalid_rows_rule(protocol)
    assert quality.row_rule_failure(pairs(bad), rule) == code
    assert quality.tolerated_rows(pairs(bad), rule) == (None if code else sorted(bad))
    data, protocol = archive(bad), dict(PROTOCOL, **protocol)
    values = dict(audit(data, protocol, []), quality={}) if listed is None else audit(data, protocol, listed)
    with pytest.raises(ValueError, match=message):
        acceptance.require_accepted(data, protocol, "s", "train", values)


@pytest.mark.parametrize("values, message", [
    ({"quality": {"tolerated_invalid_seq": [3.0]}}, INCOMPLETE),
    ({"quality": {"tolerated_invalid_seq": [True, 3.5]}}, INCOMPLETE),
    ({"quality": {"tolerated_invalid_seq": [True]}}, INCOMPLETE),
    ({"quality": {"tolerated_invalid_seq": "3"}}, INCOMPLETE),
    ({"quality": {"tolerated_invalid_seq": {"3": True}}}, INCOMPLETE),
    ({"quality": {"tolerated_invalid_seq": None}}, INCOMPLETE),
    ({"quality": [3]}, INCOMPLETE), ({"quality": None}, INCOMPLETE),
    (None, "unaccepted audit: the record is not an object"), ([3], "unaccepted audit: the record is not an object"),
], ids=["float_seq", "bool_seq", "only_bool", "text", "object", "null", "quality_as_list", "quality_null",
        "no_audit_values", "audit_values_as_list"])
def test_audit_list_of_another_shape_admits_nothing(values, message):
    """Only a list of integers is the audit's list of tolerated rows; 3.0 and true are not row numbers.

    True alone equals 1, so a list holding only it would otherwise admit the invalid row 1. The rest of the record
    is the honest record of the archive; audit values that are not an object are no clean acceptance at all.
    """
    for bad in ({3: OPEN}, {1: OPEN}):
        data = archive(bad)
        record = dict(audit(data, RULED), **values) if type(values) is dict else values
        with pytest.raises(ValueError, match=message):
            acceptance.require_accepted(data, RULED, "s", "train", record)


@pytest.mark.parametrize("row_quality", [None, [], "processes", 0], ids=["null", "list", "text", "number"])
def test_invalid_row_without_a_quality_record_is_not_tolerated(row_quality):
    """The kernel finds no tolerable cause; an archive holding such a quality record cannot be read at all."""
    seq, valid, quality_ = rows({3: OPEN})
    quality_[3] = row_quality
    assert quality.tolerated_invalid_rows({"seq": seq, "valid": valid, "quality": quality_}, RULE) is None
    assert quality.row_rule_failure([(3, row_quality)], RULE["invalid_rows"]) == "cause"
    assert quality.tolerated_rows([(3, row_quality)], RULE["invalid_rows"]) is None
    data = archive({3: OPEN})
    record = audit(data, RULED)
    records = json.loads(str(data["quality_json"]))
    records[3] = row_quality
    data["quality_json"] = np.array(json.dumps(records))
    with pytest.raises(ValueError, match="invalid quality record"):
        acceptance.require_accepted(data, RULED, "s", "train", record)


def test_rows_validity_and_quality_of_different_length_are_refused():
    """A shorter column must not hide an invalid row behind zip(); it is refused also when every row is valid."""
    for bad in ({7: dict(OPEN, read_errors=1)}, {}):
        seq, valid, quality_ = rows(bad)
        for cut in ((seq[:7], valid, quality_), (seq, valid[:7], quality_), (seq, valid, quality_[:7])):
            with pytest.raises(ValueError, match="differ in length"):
                quality.tolerated_invalid_rows(dict(zip(("seq", "valid", "quality"), cut)), RULE)
        data = archive(bad)
        record, records = audit(data, RULED, sorted(bad)), json.loads(str(data["quality_json"]))
        for cut in (dict(data, seq=data["seq"][:7]), dict(data, valid=data["valid"][:7]),
                    dict(data, quality_json=np.array(json.dumps(records[:7])))):
            with pytest.raises(ValueError, match="differ in length"):
                acceptance.require_accepted(cut, RULED, "s", "train", record)


def test_replay_input_errors_within_the_rule():
    assert quality.tolerated_input_errors(replay({}), {}) == []
    assert quality.tolerated_input_errors(replay({}), RULE) == []
    assert quality.tolerated_input_errors(replay({3: OPEN}), RULE) == [3]
    assert quality.tolerated_input_errors(replay({1: OPEN, 6: OPEN}), RULE) == [1, 6]


@pytest.mark.parametrize("rows_, protocol", [
    (replay({3: OPEN}), {}),
    (replay({1: OPEN, 3: OPEN, 6: OPEN}), RULE),
    (replay({3: dict(OPEN, truncated_traversals=["sockets"])}), RULE),
    (replay({3: dict(OPEN, read_errors=1)}), RULE),
    (replay({3: OPEN}, fatal=True), RULE),
    (replay({3: OPEN}, reason="frame_order: sequence did not advance"), RULE),
    (replay({3: OPEN}, reason=None), RULE),
    ([{"seq": 3, "model_state": "input_error", "reason": "invalid_input", "fatal": False}], RULE),
], ids=["no_rule", "over_max", "other_traversal", "read_error", "fatal", "other_reason", "no_reason", "no_quality"])
def test_replay_input_errors_outside_the_rule(rows_, protocol):
    assert quality.tolerated_input_errors(rows_, protocol) is None
