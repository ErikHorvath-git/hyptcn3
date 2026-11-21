"""
The protocol's invalid_rows rule as its consumers read it (features/quality.py).

The audit (scripts/collection.py), corpus building, training and the comparison
methods, both archive replays and the FAR evaluation all call the functions
tested here. Synthetic rows only; nothing here is a measurement.
"""
import pytest

from features import quality
from scripts import collection

RULE = {"invalid_rows": {"max": 2, "traversals": ["processes"]}}
OPEN = {"truncated_traversals": ["processes"], "read_errors": 0, "filled_zero": 0}
GOOD = {"truncated_traversals": [], "read_errors": 0, "filled_zero": 0}


def rows(bad, n=8):
    """seq, valid and quality of an archive with n rows; bad = {seq: quality of the invalid row}."""
    return (list(range(n)), [i not in bad for i in range(n)], [dict(bad.get(i, GOOD)) for i in range(n)])


def audit(listed):
    return {"quality": {"tolerated_invalid_seq": listed}}


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

    The loader's own check (collection.check_invalid_rows) is the first reader in the list.
    """
    protocol = {"invalid_rows": rule}
    seq, valid, quality_ = rows(bad)
    for call in (lambda: collection.check_invalid_rows(dict(protocol, schema="hyptcn3/collection-protocol/2")),
                 lambda: quality.invalid_rows_rule(protocol),
                 lambda: quality.tolerated_invalid_rows({"seq": seq, "valid": valid, "quality": quality_}, protocol),
                 lambda: quality.accepted_invalid_rows(seq, valid, quality_, audit(sorted(bad)), protocol),
                 lambda: quality.tolerated_input_errors(replay(bad), protocol)):
        with pytest.raises(ValueError, match="invalid invalid_rows rule"):
            call()


@pytest.mark.parametrize("protocol", [None, [], "invalid_rows"], ids=["none", "list", "text"])
def test_protocol_that_is_not_an_object_is_refused(protocol):
    for call in (lambda: quality.invalid_rows_rule(protocol),
                 lambda: quality.accepted_invalid_rows(*rows({}), audit([]), protocol),
                 lambda: quality.tolerated_input_errors(replay({}), protocol)):
        with pytest.raises(ValueError, match="invalid invalid_rows rule"):
            call()


def test_accepted_archive_without_invalid_rows_needs_no_rule():
    assert quality.accepted_invalid_rows(*rows({}), {}, {}) == []
    assert quality.accepted_invalid_rows(*rows({}), audit([3]), RULE) == []


def test_accepted_archive_keeps_the_rows_the_audit_tolerated():
    assert quality.accepted_invalid_rows(*rows({3: OPEN}), audit([3]), RULE) == [3]
    assert quality.accepted_invalid_rows(*rows({1: OPEN, 6: OPEN}), audit([1, 6]), RULE) == [1, 6]


@pytest.mark.parametrize("bad, listed, protocol, message", [
    ({3: OPEN}, [], RULE, "incomplete features in accepted audit"),
    ({3: OPEN}, None, RULE, "incomplete features in accepted audit"),
    ({1: OPEN, 6: OPEN}, [1], RULE, "incomplete features in accepted audit"),
    ({3: OPEN}, [3], {}, "more invalid rows than the protocol tolerates"),
    ({1: OPEN, 3: OPEN, 6: OPEN}, [1, 3, 6], RULE, "more invalid rows than the protocol tolerates"),
    ({3: dict(OPEN, truncated_traversals=["modules"])}, [3], RULE, "cause the protocol does not tolerate"),
    ({3: dict(OPEN, truncated_traversals=["processes", "modules"])}, [3], RULE, "cause the protocol does not tolerate"),
    ({3: dict(OPEN, read_errors=1)}, [3], RULE, "cause the protocol does not tolerate"),
    ({3: dict(OPEN, filled_zero=4096)}, [3], RULE, "cause the protocol does not tolerate"),
    ({3: GOOD}, [3], RULE, "cause the protocol does not tolerate"),
    ({3: {"truncated_traversals": {"processes": 1}}}, [3], RULE, "cause the protocol does not tolerate"),
    ({3: {"truncated_traversals": "processes"}}, [3], RULE, "cause the protocol does not tolerate"),
], ids=["not_listed", "audit_without_list", "one_not_listed", "no_rule", "over_max", "other_traversal",
        "two_traversals", "read_error", "filled_zero", "no_traversal", "traversals_as_object", "traversals_as_text"])
def test_accepted_archive_outside_the_rule_is_refused(bad, listed, protocol, message):
    values = {} if listed is None else audit(listed)
    with pytest.raises(ValueError, match=message):
        quality.accepted_invalid_rows(*rows(bad), values, protocol)


@pytest.mark.parametrize("values", [
    audit([3.0]), audit([True, 3.5]), audit([True]), audit("3"), audit({"3": True}), audit(None),
    {"quality": [3]}, {"quality": None}, None, [3],
], ids=["float_seq", "bool_seq", "only_bool", "text", "object", "null", "quality_as_list", "quality_null",
        "no_audit_values", "audit_values_as_list"])
def test_audit_list_of_another_shape_admits_nothing(values):
    """Only a list of integers is the audit's list of tolerated rows; 3.0 and true are not row numbers.

    True alone equals 1, so a list holding only it would otherwise admit the invalid row 1.
    """
    for bad in ({3: OPEN}, {1: OPEN}):
        with pytest.raises(ValueError, match="incomplete features in accepted audit"):
            quality.accepted_invalid_rows(*rows(bad), values, RULE)


@pytest.mark.parametrize("row_quality", [None, [], "processes", 0], ids=["null", "list", "text", "number"])
def test_invalid_row_without_a_quality_record_is_not_tolerated(row_quality):
    seq, valid, quality_ = rows({3: OPEN})
    quality_[3] = row_quality
    assert quality.tolerated_invalid_rows({"seq": seq, "valid": valid, "quality": quality_}, RULE) is None
    with pytest.raises(ValueError, match="cause the protocol does not tolerate"):
        quality.accepted_invalid_rows(seq, valid, quality_, audit([3]), RULE)


def test_rows_validity_and_quality_of_different_length_are_refused():
    """A shorter column must not hide an invalid row behind zip(); it is refused also when every row is valid."""
    for bad in ({7: dict(OPEN, read_errors=1)}, {}):
        seq, valid, quality_ = rows(bad)
        for cut in ((seq[:7], valid, quality_), (seq, valid[:7], quality_), (seq, valid, quality_[:7])):
            with pytest.raises(ValueError, match="differ in length"):
                quality.tolerated_invalid_rows(dict(zip(("seq", "valid", "quality"), cut)), RULE)
            with pytest.raises(ValueError, match="differ in length"):
                quality.accepted_invalid_rows(*cut, audit(sorted(bad)), RULE)


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
