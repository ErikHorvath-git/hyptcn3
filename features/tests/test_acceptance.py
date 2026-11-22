"""
The one acceptance decision of a collected session (features/acceptance.py) as a unit.

The kernel of the invalid_rows rule and the list check of require_accepted are tested in test_quality.py; here
the role table, the verdict, the two record checks and the worst case the protocol loader asks for. Expected
values come from the oracle below (chains, runs of valid rows), never from the function under test. Synthetic
rows only; nothing here is a measurement.
"""
import copy
from itertools import combinations
import json
import math
from pathlib import Path
import re

import numpy as np
import pytest

from features import acceptance, archive, quality
from features.snapshot import MENA, SCHEMA

CONFIG_V4 = Path(__file__).resolve().parents[2] / "config" / "collection-v4.json"
BIN_BYTES = 16777216
LAYOUT = {"bin_bytes": BIN_BYTES, "page_size": 4096, "bins": [[0, 4096]], "regions": [{"gpa": 0, "bytes": BIN_BYTES}],
          "memsize": BIN_BYTES, "vcpus": 1}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "truncated_traversals": [],
        "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0, "process_walk": "next"}
# The one cause the rule tolerates: the process walk did not close. The others are invalid for another cause.
UNCLOSED = dict(GOOD, model_valid=False, behavior_valid=False, traversals_complete=False,
                truncated_traversals=["processes"])
OTHER_WALK = dict(UNCLOSED, truncated_traversals=["modules"])
READ_ERROR = dict(GOOD, model_valid=False, behavior_valid=False, read_errors=1)
FINDING = dict(GOOD, findings=[{"check": "syscall_table", "detail": "synthetic"}])
TWO_FINDINGS = dict(GOOD, findings=FINDING["findings"] + [{"check": "idt", "detail": "synthetic"}])
T0 = 1700000000.

# Shape S3 of the plan: 96 rows, windows of 8, a full snapshot every 64 rows, pilot of 80, at most 3 open walks.
N, W, F, PILOT, MAX = 96, 8, 64, 80, 3
STEP = F // 6


def window_count(rows, window_rows, full_every, invalid=()):
    """Oracle: over chains, over maximal runs of valid rows inside a chain, max(0, len(run) - window_rows)."""
    total = 0
    for start in range(0, rows, full_every):
        run = 0
        for seq in range(start, min(start + full_every, rows)):
            if seq in invalid:
                total, run = total + max(0, run - window_rows), 0
            else:
                run += 1
        total += max(0, run - window_rows)
    return total


def isolated(k):
    """k invalid rows inside chain 0, each with at least W valid rows of the chain on both sides."""
    assert STEP - 1 >= W and STEP * k + W < F
    return [STEP * (j + 1) for j in range(k)]


def clustered(k):
    return list(range(F // 2, F // 2 + k))


CLEAN = window_count(N, W, F)
# Three isolated rows land exactly on the gate (accepted on equality); the ratio is computed, never written.
GATE = (CLEAN - MAX * (W + 1)) / N
BEHAVIOR, LEGACY = quality.BEHAVIOR_POLICY, quality.LEGACY_POLICY
REASON = {"role": "session role is not assigned by the protocol",
          "rows": "snapshot count differs from assigned protocol",
          "sequence": "sequence must start at zero and be contiguous",
          "timing:gap": "timestamp gap",
          "integrity": "integrity findings require review before benign admission",
          "coverage": f"score coverage below design gate {GATE:g}"}
ORDER = ("role", "rows", "sequence", "invalid_rows", "integrity", "coverage")
REJECTS = "accepted audit of a session the protocol rejects: "
DIFFERS = "audit record differs from the acceptance decision"
INCOMPLETE = "incomplete features in accepted audit"
TOO_MANY = "more invalid rows than the protocol tolerates"
CAUSE = "invalid rows have a cause the protocol does not tolerate"


def sections():
    """The audit and exceptions sections schema 3 states since package B3 (features/audit_policy.py). No
    construction here meets their bounds: rows lie on the 1 s grid, none is closed by a parser rule, and the
    flagged rows are adjacent or STEP apart, below the smallest spacing the periodicity rule counts."""
    from features import audit_policy
    return {"audit": {"lateness_max_s": .1, "cycle_ms_max": {"delta": 300, "full": 700},
                      "periodicity": {"equal_spacings": 3, "min_spacing_rows": STEP + 1, "note": "test bounds"},
                      "warnings_allowed": None, "rule_closed_rows_max": None},
            "exceptions": {name: {"cause": "synthetic", "decision": "synthetic", "expected": None}
                           for name in audit_policy.TOLERATED}}


def protocol(version=3, **changes):
    p = {"schema": f"hyptcn3/collection-protocol/{version}", "quality_policy": BEHAVIOR, "interval_s": 1,
         "max_gap_s": 1.5, "stride": 1, "bin_bytes": BIN_BYTES, "window_rows": W, "full_every": F, "cycles": N,
         "pilot_cycles": PILOT, "min_score_coverage": GATE,
         "roles": {"train": 3, "dev": 3, "calibration": 3, "test_benign": 3},
         "invalid_rows": {"max": MAX, "traversals": ["processes"]}}
    if version == 1:
        del p["quality_policy"]
    p.update(changes)
    if p.get("schema") == "hyptcn3/collection-protocol/3":
        p = {**sections(), **p}  # A change may still replace or drop a section.
    return {k: v for k, v in p.items() if v is not DROP}


DROP = object()


def row(seq, q=UNCLOSED):
    return {"seq": seq, "truncated_traversals": q["truncated_traversals"], "read_errors": q["read_errors"],
            "filled_zero": q["filled_zero"]}


def facts(rows=N, invalid=(), *, contiguous=True, findings=0, windows=None, q=UNCLOSED):
    """Facts of a session written by hand; windows default to the oracle of the S3 shape. The rows lie on the
    protocol's 1 s grid and none is closed by a parser rule."""
    return {"snapshots": rows, "sequence_contiguous": contiguous, "invalid_rows": [row(s, q) for s in sorted(invalid)],
            "integrity_findings": findings,
            "windows": window_count(rows, W, F, set(invalid)) if windows is None else windows,
            "rule_closed_seq": [], "smallest_gap_s": 1. if rows > 1 else None,
            "largest_gap_s": 1. if rows > 1 else None, "span_s": float(rows - 1) if rows else None}


def extraction(rows=N, invalid=None, *, seqs=None, policy=BEHAVIOR, full_every=F):
    """What features.snapshot.retazec returns for a session; invalid = {seq: quality of the row}.

    As in retazec, a row has a predecessor only when the row before it in the archive is the previous seq and
    valid; a full snapshot inside the session keeps it. Missing seqs are absent rows, the others keep their seq
    and time. One 16 MiB bin, zero per-bin values.
    """
    invalid = invalid or {}
    seqs = list(range(rows)) if seqs is None else list(seqs)
    n = len(seqs)
    q = [copy.deepcopy(invalid.get(s, GOOD)) for s in seqs]
    valid = [quality.valid_for(x, policy) for x in q]
    matrix = np.zeros((n, len(MENA)))
    matrix[:, MENA.index("je_plna")] = [s % full_every == 0 for s in seqs]
    matrix[:, MENA.index("ma_predchodcu")] = [i > 0 and seqs[i - 1] == s - 1 and valid[i - 1]
                                              for i, s in enumerate(seqs)]
    return {"schema": SCHEMA, "mena": list(MENA), "matica": matrix.tolist(), "snimky": [f"frame{s}" for s in seqs],
            "poznamky": [[] for _ in seqs], "trvanie_s": [0.] * n, "seq": seqs, "casy": [T0 + s for s in seqs],
            "quality": q, "valid": valid, "quality_policy": policy, "perbin": np.zeros((n, 1, 4)).tolist(),
            "biny": [0], "chain_ids": [f"s-chain-{s // full_every}" for s in seqs], "layout": copy.deepcopy(LAYOUT),
            "max_medzera_s": 1.5}


def stored(result, directory):
    """The archive as the audit writes it (features.archive.save) and as every consumer reads it (archive.load)."""
    return archive.load(archive.save(Path(directory) / "features.npz", result))


def record(verdict):
    """Audit values as audit_session writes them from the verdict, read back from the JSON file."""
    return json.loads(json.dumps({
        "accepted": verdict["accepted"], "reasons": sorted(set(verdict["reasons"])), "role": verdict["role"],
        "snapshots": verdict["snapshots"], "windows": verdict["windows"], "score_coverage": verdict["score_coverage"],
        "quality": {"tolerated_invalid_seq": verdict["tolerated_invalid_seq"] or []}, "acceptance": verdict},
        allow_nan=False))


def honest(data, p, role="train", recorded_rows=None):
    return record(acceptance.judge(data, p, "s", role, recorded_rows)[0])


def flipped(values, listed=None):
    """F1b of the plan (the refused record restated as a clean acceptance, its verdict too); with `listed` F1c."""
    out = copy.deepcopy(values)
    out.update(accepted=True, reasons=[])
    out["acceptance"].update(accepted=True, reasons=[], codes=[])
    if listed is not None:
        out["quality"]["tolerated_invalid_seq"] = out["acceptance"]["tolerated_invalid_seq"] = sorted(listed)
    return out


def codes(verdict):
    return [c.split(":")[0] for c in verdict["codes"]]


# T04: role table.

@pytest.mark.parametrize("schema", [1, 2, 3])
@pytest.mark.parametrize("rule", ["with_rule", "without_rule"])
def test_pilot_has_its_own_length_and_no_tolerance_under_every_schema(schema, rule):
    p = protocol(schema, **({} if rule == "with_rule" else {"invalid_rows": DROP}))
    assigned, resolved, known = acceptance.assignment(p, "pilot", recorded_rows=N)
    assert (assigned, known) == (PILOT, True) and resolved is quality.NO_TOLERANCE
    clean = acceptance.decide(p, "pilot", facts(PILOT), recorded_rows=N)
    assert clean["accepted"] and clean["assigned_rows"] == PILOT
    assert clean["score_coverage"] == window_count(PILOT, W, F) / PILOT
    # One tolerable row mid-chain: coverage still passes, the pilot tolerates nothing.
    one = acceptance.decide(p, "pilot", facts(PILOT, [F // 2]))
    assert one["score_coverage"] >= GATE
    assert one["codes"] == ["invalid_rows:no_tolerance"] and one["tolerated_invalid_seq"] is None
    assert one["reasons"] == ["incomplete model inputs under " + (LEGACY if schema == 1 else BEHAVIOR)]


def test_every_role_the_protocol_plans_gets_cycles_and_the_protocol_rule():
    p = protocol()
    for role in p["roles"]:
        assert acceptance.assignment(p, role, recorded_rows=PILOT) == (N, p["invalid_rows"], True)
        assert acceptance.decide(p, role, facts(), recorded_rows=PILOT)["accepted"]
        one = acceptance.decide(p, role, facts(N, [F // 2]))
        assert one["accepted"] and one["assigned_rows"] == N and one["tolerated_invalid_seq"] == [F // 2]
        free = protocol(invalid_rows=DROP)
        assert acceptance.assignment(free, role) == (N, None, True)
        assert acceptance.decide(free, role, facts(N, [F // 2]))["codes"] == ["invalid_rows:no_rule"]


def test_diagnostic_session_has_its_recorded_length_and_the_protocol_rule():
    p, rows = protocol(), F + W
    assert acceptance.assignment(p, "diagnostic", rows) == (rows, p["invalid_rows"], True)
    for invalid in ([], [F // 2]):
        verdict = acceptance.decide(p, "diagnostic", facts(rows, invalid), recorded_rows=rows)
        assert verdict["accepted"] and verdict["assigned_rows"] == rows and verdict["tolerated_invalid_seq"] == invalid
        assert verdict["score_coverage"] == window_count(rows, W, F, invalid) / rows
    assert acceptance.decide(protocol(invalid_rows=DROP), "diagnostic", facts(rows, [F // 2]), rows)["codes"] == [
        "invalid_rows:no_rule"]


@pytest.mark.parametrize("recorded", [None, 0, -1, True, float(F + W), str(F + W)],
                         ids=["none", "zero", "negative", "bool", "float", "text"])
def test_diagnostic_session_without_a_usable_recorded_length_has_no_target(recorded):
    """The number of rows a session happens to have is never its target."""
    p = protocol()
    assert acceptance.assignment(p, "diagnostic", recorded) == (None, p["invalid_rows"], True)
    verdict = acceptance.decide(p, "diagnostic", facts(F + W), recorded)
    assert verdict["codes"] == ["rows"] and verdict["reasons"] == [REASON["rows"]]
    assert verdict["assigned_rows"] is None and verdict["score_coverage"] is None


# A role from JSON session metadata may also be a list or an object: no string, not even hashable.
@pytest.mark.parametrize("role", [None, "", 7, "unassigned", "dev", ["train"], {"role": "train"}],
                         ids=["none", "empty", "number", "unknown", "not_in_this_protocol", "list", "object"])
def test_role_the_protocol_does_not_assign_gets_a_rejecting_verdict(role):
    p = protocol(roles={"train": 3, "calibration": 3, "test_benign": 3})
    assigned, resolved, known = acceptance.assignment(p, role, recorded_rows=N)
    assert (assigned, known) == (None, False) and resolved is quality.NO_TOLERANCE
    clean = acceptance.decide(p, role, facts(), recorded_rows=N)
    assert not clean["accepted"] and clean["codes"] == ["role"] and clean["reasons"] == [REASON["role"]]
    assert clean["assigned_rows"] is None and clean["score_coverage"] is None and clean["role"] == role
    one = acceptance.decide(p, role, facts(N, [F // 2]), recorded_rows=N)
    assert one["codes"] == ["role", "invalid_rows:no_tolerance"] and one["tolerated_invalid_seq"] is None


# T05: malformed protocol parameters and malformed facts raise; they never become a verdict.

GATES = {"nan": math.nan, "infinite": math.inf, "zero": 0, "negative": -1, "above_one": 2, "null": None,
         "text": str(GATE), "bool": True, "list": [GATE]}


@pytest.mark.parametrize("gate", GATES.values(), ids=GATES)
def test_malformed_gate_raises(gate, tmp_path):
    good = protocol()
    result = extraction()
    values = honest(result, good)
    p = protocol(min_score_coverage=gate)
    for call in (lambda: acceptance.decide(p, "train", facts()), lambda: acceptance.decide(p, None, facts()),
                 lambda: acceptance.decide(p, "pilot", facts(PILOT)), lambda: acceptance.judge(result, p, "s", "train"),
                 lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(stored(result, tmp_path), p, "s", "train", values)):
        with pytest.raises(ValueError, match="invalid minimum score coverage"):
            call()


def test_schema_3_without_a_gate_raises():
    with pytest.raises(ValueError, match="protocol schema 3 requires min_score_coverage"):
        acceptance.decide(protocol(min_score_coverage=DROP), "train", facts())


@pytest.mark.parametrize("changes, message", [
    ({"schema": "hyptcn3/collection-protocol/4"}, "unsupported collection protocol/quality policy"),
    ({"schema": DROP}, "unsupported collection protocol/quality policy"),
    ({"quality_policy": LEGACY}, "unsupported collection protocol/quality policy"),
    ({"quality_policy": DROP}, "unsupported collection protocol/quality policy"),
    ({"schema": "hyptcn3/collection-protocol/1"}, "quality policy changes require protocol version 2"),
], ids=["unknown_schema", "no_schema", "legacy_policy_in_schema_3", "no_policy", "policy_in_schema_1"])
def test_malformed_policy_raises(changes, message):
    for role in ("train", None):
        with pytest.raises(ValueError, match=message):
            acceptance.decide(protocol(**changes), role, facts())


LENGTHS = {"zero": 0, "negative": -1, "bool": True, "float": float(N), "text": str(N), "null": None, "missing": DROP}


@pytest.mark.parametrize("value", LENGTHS.values(), ids=LENGTHS)
def test_malformed_length_of_the_role_raises(value):
    """Each role needs its own length only: a planned role cycles, the pilot pilot_cycles."""
    for key, role, other in (("cycles", "train", "pilot"), ("pilot_cycles", "pilot", "train")):
        p = protocol(**{key: value})
        with pytest.raises(ValueError, match="invalid " + key + "$"):
            acceptance.assignment(p, role)
        with pytest.raises(ValueError, match="invalid " + key + "$"):
            acceptance.decide(p, role, facts())
        assert acceptance.decide(p, other, facts(PILOT if other == "pilot" else N))["accepted"]


def _drop(d, key):
    return {k: v for k, v in d.items() if k != key}


BAD_FACTS = {
    "null": None, "list": [], "missing_key": _drop(facts(), "windows"), "extra_key": dict(facts(), gate=GATE),
    "snapshots_bool": dict(facts(), snapshots=True), "snapshots_negative": dict(facts(), snapshots=-1),
    "snapshots_float": dict(facts(), snapshots=float(N)), "contiguous_number": dict(facts(), sequence_contiguous=1),
    "contiguous_null": dict(facts(), sequence_contiguous=None), "rows_tuple": dict(facts(), invalid_rows=()),
    "rows_object": dict(facts(), invalid_rows={}), "findings_negative": dict(facts(), integrity_findings=-1),
    "findings_bool": dict(facts(), integrity_findings=False), "windows_float": dict(facts(), windows=float(CLEAN)),
    "windows_above_rows": dict(facts(), windows=N + 1),
    "more_invalid_rows_than_rows": facts(2, [0, 1, 2], windows=0),
    "row_not_object": dict(facts(), invalid_rows=[F // 2]),
    "row_missing_key": dict(facts(), invalid_rows=[_drop(row(F // 2), "filled_zero")]),
    "row_extra_key": dict(facts(), invalid_rows=[dict(row(F // 2), findings=[])]),
    "row_seq_negative": dict(facts(), invalid_rows=[row(-1)]), "row_seq_bool": dict(facts(), invalid_rows=[row(True)]),
    "row_seq_float": dict(facts(), invalid_rows=[row(float(F // 2))]),
    "duplicate_seq": dict(facts(), invalid_rows=[row(F // 2), row(F // 2)]),
}


@pytest.mark.parametrize("bad", BAD_FACTS.values(), ids=BAD_FACTS)
def test_malformed_facts_raise_also_when_read_from_a_record(bad):
    p = protocol()
    values = record(acceptance.decide(p, "train", facts()))
    values["acceptance"]["facts"] = bad
    for call in (lambda: acceptance.decide(p, "train", bad), lambda: acceptance.decide(p, None, bad),
                 lambda: acceptance.require_recorded(p, "train", values)):
        with pytest.raises(ValueError, match="invalid session facts"):
            call()


@pytest.mark.parametrize("changes, message", [
    ({"interval_s": 0}, "invalid interval_s"), ({"interval_s": True}, "invalid interval_s"),
    ({"interval_s": "1"}, "invalid interval_s"), ({"interval_s": DROP}, "invalid interval_s"),
    ({"full_every": 0}, "invalid full_every"), ({"full_every": float(F)}, "invalid full_every"),
], ids=["interval_zero", "interval_bool", "interval_text", "interval_missing", "full_every_zero", "full_every_float"])
def test_synthetic_session_needs_a_valid_grid(changes, message):
    with pytest.raises(ValueError, match=message):
        acceptance.synthetic_windows(protocol(**changes), N)


# T06: the tolerated list in the record equals the verdict's.

@pytest.mark.parametrize("listed, d2_message", [
    ([F // 2, F // 2 + STEP], DIFFERS), (list(range(N)), DIFFERS), ([], INCOMPLETE),
], ids=["superset", "every_row", "empty"])
@pytest.mark.parametrize("where", ["record_and_verdict", "record_only"])
def test_tolerated_list_must_equal_the_verdicts(listed, d2_message, where, tmp_path):
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    values = honest(data, p)
    assert values["quality"]["tolerated_invalid_seq"] == [F // 2]
    assert acceptance.require_recorded(p, "train", values) == acceptance.require_accepted(data, p, "s", "train", values)
    values["quality"]["tolerated_invalid_seq"] = listed
    if where == "record_and_verdict":
        values["acceptance"]["tolerated_invalid_seq"] = listed
    with pytest.raises(ValueError, match=DIFFERS):
        acceptance.require_recorded(p, "train", values)
    with pytest.raises(ValueError, match=d2_message):
        acceptance.require_accepted(data, p, "s", "train", values)


# T07: strict record.

STRICT = {
    "null": (None, "the record is not an object"), "list": ([], "the record is not an object"),
    "text": ("accepted", "the record is not an object"), "number": (1, "the record is not an object"),
    "accepted_missing": ({"accepted": DROP}, "the record does not state a clean acceptance"),
    "accepted_one": ({"accepted": 1}, "the record does not state a clean acceptance"),
    "accepted_text": ({"accepted": "yes"}, "the record does not state a clean acceptance"),
    "accepted_false": ({"accepted": False}, "the record does not state a clean acceptance"),
    "reasons_given": ({"reasons": ["timestamp gap"]}, "the record does not state a clean acceptance"),
    "reasons_missing": ({"reasons": DROP}, "the record does not state a clean acceptance"),
    "reasons_null": ({"reasons": None}, "the record does not state a clean acceptance"),
    "reasons_tuple": ({"reasons": ()}, "the record does not state a clean acceptance"),
    "no_verdict_and_accepted_one": ({"accepted": 1, "acceptance": DROP},
                                    "the record does not state a clean acceptance"),
    "other_role": ({"role": "dev"}, "recorded for another role"),
    "role_missing": ({"role": DROP}, "recorded for another role"),
    "role_null": ({"role": None}, "recorded for another role"),
    # Two conditions broken at once: the order of plan section 14 (D1 step 1) decides the message.
    "accepted_false_and_other_role": ({"accepted": False, "role": "dev"},
                                      "the record does not state a clean acceptance"),
    "reasons_given_and_other_role": ({"reasons": ["timestamp gap"], "role": "dev"},
                                     "the record does not state a clean acceptance"),
}


@pytest.mark.parametrize("change, message", STRICT.values(), ids=STRICT)
def test_record_that_is_no_clean_acceptance_of_the_role_is_refused(change, message, tmp_path):
    p = protocol()
    data = stored(extraction(), tmp_path)
    values = honest(data, p)
    if type(change) is dict:
        values.update(change)
        values = {k: v for k, v in values.items() if v is not DROP}
    else:
        values = change
    for call in (lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(data, p, "s", "train", values)):
        with pytest.raises(ValueError, match="^unaccepted audit: " + message + "$"):
            call()


def test_record_of_another_role_is_refused_although_it_is_honest_for_its_own(tmp_path):
    p = protocol()
    data = stored(extraction(), tmp_path)
    values = honest(data, p, "dev")
    assert acceptance.require_accepted(data, p, "s", "dev", values)["role"] == "dev"
    for role in ("train", "pilot", None):
        with pytest.raises(ValueError, match="recorded for another role"):
            acceptance.require_recorded(p, role, values)
        with pytest.raises(ValueError, match="recorded for another role"):
            acceptance.require_accepted(data, p, "s", role, values)


# T08: short, gappy and long sessions get a reason, not an exception.

SHAPES = {
    "last_row_missing": (list(range(N - 1)), ["rows"]),
    "last_20_rows_missing": (list(range(N - 20)), ["rows"]),
    "row_missing_mid_chain": ([s for s in range(N) if s != F // 2], ["rows", "sequence", "timing:gap"]),
    "one_seq_skipped": ([s for s in range(N + 1) if s != F // 2], ["sequence", "timing:gap"]),
    "starts_at_one": (list(range(1, N + 1)), ["sequence"]),
    "one_row_too_many": (list(range(N + 1)), ["rows"]),
    "first_chain_only": (list(range(F)), ["rows"]),
}


@pytest.mark.parametrize("seqs, expected", SHAPES.values(), ids=SHAPES)
def test_short_gappy_and_long_sessions_get_a_reason(seqs, expected, tmp_path):
    p = protocol()
    result = extraction(seqs=seqs)
    for data in (result, stored(result, tmp_path)):
        verdict, windows, _ = acceptance.judge(data, p, "s", "train")
        assert verdict["codes"] == expected and verdict["reasons"] == [REASON[c] for c in expected]
        assert verdict["snapshots"] == len(seqs) and verdict["assigned_rows"] == N and not verdict["accepted"]
        assert len(windows) == verdict["windows"] and verdict["score_coverage"] == verdict["windows"] / N
        if seqs == list(range(len(seqs))):  # Window counts are asserted for present rows only (plan, section 2).
            assert verdict["windows"] == window_count(len(seqs), W, F)
        values = flipped(record(verdict))
        message = REJECTS + REASON[expected[0]]
        with pytest.raises(ValueError, match=message):
            acceptance.require_recorded(p, "train", values)
        with pytest.raises(ValueError, match=message):
            acceptance.require_accepted(data, p, "s", "train", values)


# As many invalid rows as rows are well-formed facts: the session gets its reasons, never "invalid session facts".
EVERY_ROW_INVALID = {
    "two_rows_both_open_walks": (2, ["rows", "coverage"], REJECTS + REASON["rows"]),
    "assigned_length_all_open_walks": (N, ["invalid_rows:over_max", "coverage"], TOO_MANY),
}


@pytest.mark.parametrize("rows, expected, message", EVERY_ROW_INVALID.values(), ids=EVERY_ROW_INVALID)
def test_session_whose_every_row_is_invalid_gets_a_reason(rows, expected, message, tmp_path):
    p = protocol()
    given = facts(rows, range(rows))
    assert len(given["invalid_rows"]) == given["snapshots"] == rows and given["windows"] == 0
    result = extraction(rows, dict.fromkeys(range(rows), UNCLOSED))
    data = stored(result, tmp_path)
    for verdict in (acceptance.decide(p, "train", given), acceptance.judge(result, p, "s", "train")[0],
                    acceptance.judge(data, p, "s", "train")[0]):
        assert verdict["codes"] == expected and not verdict["accepted"] and verdict["facts"] == given
        assert verdict["reasons"] == ["incomplete model inputs under " + BEHAVIOR if c.startswith("invalid_rows:")
                                      else REASON[c] for c in expected]
    # F1c: restated as a clean acceptance that lists every row; both checks refuse it by the first code.
    values = flipped(record(acceptance.decide(p, "train", given)), listed=range(rows))
    for call in (lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(data, p, "s", "train", values)):
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            call()


def test_coverage_report_of_a_short_session_is_made_against_the_assigned_length(tmp_path):
    """Its missing rows stay in the report's denominator (design part 2); the span it happens to have is no target."""
    p = protocol()
    result = extraction(seqs=range(N - 20))
    for data in (result, stored(result, tmp_path)):
        assert acceptance.judge(data, p, "s", "train")[2]["expected_snapshots"] == N


# T10: an extraction result and its loaded archive give one verdict.

CELLS = {
    "clean": ({}, "train"), "one_open_walk": ({F // 2: UNCLOSED}, "train"),
    "three_isolated": (dict.fromkeys(isolated(3), UNCLOSED), "train"),
    "four_clustered": (dict.fromkeys(clustered(4), UNCLOSED), "train"),
    "four_isolated": (dict.fromkeys(isolated(4), UNCLOSED), "train"),
    "other_walk": ({F // 2: OTHER_WALK}, "train"), "read_error": ({F // 2: READ_ERROR}, "train"),
    "finding": ({F // 2: FINDING}, "train"), "last_row": ({N - 1: UNCLOSED}, "train"),
    "first_row_of_chain_1": ({F: UNCLOSED}, "train"), "pilot_one_open_walk": ({F // 2: UNCLOSED}, "pilot"),
    "unknown_role": ({F // 2: UNCLOSED}, None),
}


@pytest.mark.parametrize("invalid, role", CELLS.values(), ids=CELLS)
def test_extraction_result_and_its_archive_give_one_verdict(invalid, role, tmp_path):
    p = protocol()
    rows = PILOT if role == "pilot" else N
    result = extraction(rows, invalid)
    first, windows, _ = acceptance.judge(result, p, "s", role)
    second, again, _ = acceptance.judge(stored(result, tmp_path), p, "s", role)
    assert json.dumps(first, sort_keys=True, allow_nan=False) == json.dumps(second, sort_keys=True, allow_nan=False)
    assert len(windows) == len(again) == first["windows"]
    bad = {s for s, q in invalid.items() if not q["behavior_valid"]}
    assert first["windows"] == window_count(rows, W, F, bad)
    assert first["facts"]["invalid_rows"] == [row(s, invalid[s]) for s in sorted(bad)]
    assert first["facts"]["integrity_findings"] == sum(len(q["findings"]) for q in invalid.values())
    for verdict in (first, second):
        assert all(type(r[k]) is int for r in verdict["facts"]["invalid_rows"] for k in ("seq", "read_errors",
                                                                                       "filled_zero"))
        assert all(type(verdict["facts"][k]) is int for k in ("snapshots", "integrity_findings", "windows"))


def test_integrity_findings_are_counted_per_finding(tmp_path):
    """Two valid rows carry three findings: the facts hold three findings, the verdict the integrity code alone."""
    p = protocol()
    result = extraction(invalid={F // 2: TWO_FINDINGS, F // 2 + STEP: FINDING})
    for data in (result, stored(result, tmp_path)):
        verdict = acceptance.judge(data, p, "s", "train")[0]
        assert verdict["facts"]["integrity_findings"] == 3 and verdict["facts"]["invalid_rows"] == []
        assert verdict["codes"] == ["integrity"] and verdict["reasons"] == [REASON["integrity"]]


def _flip_first_valid(data):
    out = dict(data)
    out["valid"] = np.array([not data["valid"][0]] + list(data["valid"][1:]), dtype=bool)
    return out


def _quality_rows(data):
    return json.loads(str(data["quality_json"])) if "quality_json" in data else data["quality"]


def _with_quality(data, change):
    q = copy.deepcopy(_quality_rows(data))
    change(q)
    out = dict(data)
    if "quality_json" in data:
        out["quality_json"] = np.array(json.dumps(q))
    else:
        out["quality"] = q
    return out


UNREADABLE = {
    "mask_differs": (_flip_first_valid, "valid mask differs from structured quality", True),
    "policy_differs": (lambda d: dict(d, quality_policy=np.array(LEGACY)),
                       "extraction quality policy differs from protocol", True),
    "policy_missing": (lambda d: _drop(d, "quality_policy"), "extraction quality policy differs from protocol", True),
    "no_rows": (lambda d: dict(d, seq=np.array([], dtype=np.int64)), "no feature rows", True),
    "seq_float": (lambda d: dict(d, seq=np.asarray(d["seq"], dtype=np.float64)),
                  "invalid sequence, validity or quality types", True),
    "valid_numbers": (lambda d: dict(d, valid=np.asarray(d["valid"], dtype=np.int64)),
                      "invalid sequence, validity or quality types", True),
    "findings_missing": (lambda d: _with_quality(d, lambda q: q[1].pop("findings")), "invalid quality record", True),
    "validity_missing": (lambda d: _with_quality(d, lambda q: q[1].pop("behavior_valid")), "invalid quality record",
                         True),
    # A counter that is no JSON value exists only in an extraction result; an archive stores quality as JSON.
    "counter_not_json": (lambda d: _with_quality(d, lambda q: q[F // 2].update(read_errors=np.int64(0))),
                         "invalid quality record", False),
}


@pytest.mark.parametrize("change, message, archive_too", UNREADABLE.values(), ids=UNREADABLE)
def test_data_that_cannot_be_read_as_a_session_raises(change, message, archive_too, tmp_path):
    p = protocol()
    result = extraction(invalid={F // 2: UNCLOSED})
    for data in [result] + ([stored(result, tmp_path)] if archive_too else []):
        with pytest.raises(ValueError, match=message):
            acceptance.judge(change(data), p, "s", "train")


# T11: a record written from judge passes both record checks.

WRITTEN = {
    "train_clean": ({}, "train", None), "dev_one_open_walk": ({F // 2: UNCLOSED}, "dev", None),
    "calibration_three_isolated_on_the_gate": (dict.fromkeys(isolated(3), UNCLOSED), "calibration", None),
    "test_benign_three_clustered": (dict.fromkeys(clustered(3), UNCLOSED), "test_benign", None),
    "pilot_clean": ({}, "pilot", None), "diagnostic_one_open_walk": ({F // 2: UNCLOSED}, "diagnostic", F + W),
}


@pytest.mark.parametrize("invalid, role, recorded", WRITTEN.values(), ids=WRITTEN)
def test_record_written_from_judge_passes_both_checks(invalid, role, recorded, tmp_path):
    p = protocol()
    rows = recorded or (PILOT if role == "pilot" else N)
    data = stored(extraction(rows, invalid), tmp_path)
    values = honest(data, p, role, recorded)
    assert values["accepted"] and values["quality"]["tolerated_invalid_seq"] == sorted(invalid)
    assert values["windows"] == window_count(rows, W, F, set(invalid))
    first = acceptance.require_recorded(p, role, values, recorded)
    second = acceptance.require_accepted(data, p, "s", role, values, recorded)
    assert first == second == values["acceptance"]
    # Key order is not part of the record: the stored verdict compares as canonical JSON.
    values["acceptance"] = dict(reversed(list(values["acceptance"].items())))
    assert acceptance.require_accepted(data, p, "s", role, values, recorded) == first


# T16: every reason that applies, in the fixed order, with the fixed codes.

VIOLATIONS = ("rows", "sequence", "invalid_rows", "integrity", "coverage")


@pytest.mark.parametrize("kind, row_code, q", [("over_max", "invalid_rows:over_max", UNCLOSED),
                                                ("cause", "invalid_rows:cause", READ_ERROR)], ids=["over_max", "cause"])
@pytest.mark.parametrize("mask", range(2 ** len(VIOLATIONS)))
def test_all_reasons_in_the_fixed_order(mask, kind, row_code, q):
    broken = {v for i, v in enumerate(VIOLATIONS) if mask >> i & 1}
    invalid = (clustered(MAX + 1) if kind == "over_max" else [F // 2]) if "invalid_rows" in broken else []
    given = facts(N + 1 if "rows" in broken else N, invalid, contiguous="sequence" not in broken,
                  findings=2 if "integrity" in broken else 0, windows=0 if "coverage" in broken else CLEAN, q=q)
    verdict = acceptance.decide(protocol(), "train", given)
    expected = [c for c in ORDER if c in broken]
    assert verdict["codes"] == [row_code if c == "invalid_rows" else c for c in expected]
    assert verdict["reasons"] == ["incomplete model inputs under " + BEHAVIOR if c == "invalid_rows" else REASON[c]
                                  for c in expected]
    assert verdict["accepted"] is not broken
    assert verdict["tolerated_invalid_seq"] == (None if "invalid_rows" in broken else [])
    assert verdict["facts"] == given and verdict["score_coverage"] == given["windows"] / N


@pytest.mark.parametrize("mask", range(2 ** 3))
def test_all_reasons_of_a_role_the_protocol_does_not_assign(mask):
    """Without an assigned length there is no row count to differ from and no coverage."""
    broken = {v for i, v in enumerate(("sequence", "invalid_rows", "integrity")) if mask >> i & 1}
    given = facts(N + 1, [F // 2] if "invalid_rows" in broken else [], contiguous="sequence" not in broken,
                  findings=1 if "integrity" in broken else 0, windows=0)
    verdict = acceptance.decide(protocol(), None, given)
    assert codes(verdict) == [c for c in ORDER if c == "role" or c in broken]
    assert "invalid_rows" not in broken or "invalid_rows:no_tolerance" in verdict["codes"]


def test_session_that_violates_everything_through_its_archive(tmp_path):
    """A row missing mid-chain, four isolated open walks, one finding and coverage far below the gate."""
    p = protocol()
    invalid = dict.fromkeys(isolated(MAX + 1), UNCLOSED)
    invalid[F + 2 * W] = FINDING
    result = extraction(invalid=invalid, seqs=[s for s in range(N) if s != F // 2 + STEP])
    for data in (result, stored(result, tmp_path)):
        verdict = acceptance.judge(data, p, "s", "train")[0]
        assert verdict["codes"] == ["rows", "sequence", "timing:gap", "invalid_rows:over_max", "integrity",
                                    "coverage"]
        assert verdict["reasons"] == [REASON["rows"], REASON["sequence"], REASON["timing:gap"],
                                      "incomplete model inputs under " + BEHAVIOR, REASON["integrity"],
                                      REASON["coverage"]]
        assert acceptance.judge(data, p, "s", None)[0]["codes"] == [
            "role", "sequence", "timing:gap", "invalid_rows:no_tolerance", "integrity"]


def test_clustered_rows_over_the_maximum_are_refused_by_their_count_only(tmp_path):
    """The trap: four adjacent rows cost little coverage, so only the count of rows can refuse them."""
    p = protocol()
    for rows, expected in ((clustered(MAX + 1), ["invalid_rows:over_max"]),
                           (isolated(MAX + 1), ["invalid_rows:over_max", "coverage"])):
        verdict = acceptance.judge(stored(extraction(invalid=dict.fromkeys(rows, UNCLOSED)), tmp_path / str(rows[0])),
                                   p, "s", "train")[0]
        assert verdict["windows"] == window_count(N, W, F, set(rows)) and verdict["codes"] == expected


# T17: equality at the gate.

def test_equality_at_the_gate_with_the_v4_numbers():
    v4 = json.loads(CONFIG_V4.read_text())
    p = protocol(**{k: v4[k] for k in ("schema", "cycles", "pilot_cycles", "window_rows", "full_every",
                                       "min_score_coverage", "invalid_rows", "quality_policy")})
    gate = p["min_score_coverage"]
    for role, key in (("train", "cycles"), ("pilot", "pilot_cycles")):
        rows = p[key]
        smallest = min(w for w in range(rows + 1) if w / rows >= gate)
        assert smallest / rows == gate  # The v4 numbers reach the gate exactly.
        at = acceptance.decide(p, role, facts(rows, windows=smallest))
        below = acceptance.decide(p, role, dict(at["facts"], windows=smallest - 1))
        assert at["accepted"] and at["score_coverage"] == gate
        assert below["codes"] == ["coverage"] and below["reasons"] == [f"score coverage below design gate {gate:g}"]


def test_three_isolated_rows_are_accepted_on_the_gate(tmp_path):
    p = protocol()
    rows = isolated(MAX)
    assert window_count(N, W, F, set(rows)) == CLEAN - MAX * (W + 1)  # Each isolated row costs W + 1 windows.
    data = stored(extraction(invalid=dict.fromkeys(rows, UNCLOSED)), tmp_path)
    verdict = acceptance.judge(data, p, "s", "train")[0]
    assert verdict["accepted"] and verdict["windows"] / N == GATE and verdict["tolerated_invalid_seq"] == rows
    one_more = protocol(min_score_coverage=(CLEAN - MAX * (W + 1) + 1) / N)
    assert acceptance.judge(data, one_more, "s", "train")[0]["codes"] == ["coverage"]


# T18: the legacy-policy archive (panel C11): windows by features.windows.okna, no coverage report.

@pytest.mark.parametrize("invalid", [{}, {F // 2: UNCLOSED}], ids=["clean", "one_open_walk"])
def test_legacy_policy_archive_is_judged_under_schema_1(invalid, tmp_path):
    p = protocol(1)
    result = extraction(invalid=invalid, policy=LEGACY)
    data = stored(result, tmp_path)
    for shape in (result, data):
        verdict, windows, report = acceptance.judge(shape, p, "s", "train")
        assert report is None and len(windows) == verdict["windows"] == window_count(N, W, F, set(invalid))
        assert verdict["accepted"] and verdict["tolerated_invalid_seq"] == sorted(invalid)
    values = honest(data, p)
    assert acceptance.require_accepted(data, p, "s", "train", values) == acceptance.require_recorded(p, "train", values)
    with pytest.raises(ValueError, match="extraction quality policy differs from protocol"):
        acceptance.judge(data, protocol(2), "s", "train")
    with pytest.raises(ValueError, match="extraction quality policy differs from protocol"):
        acceptance.judge(stored(extraction(invalid=invalid), tmp_path / "behavior"), p, "s", "train")


# Every branch of _refusal: the first code decides the message.

REFUSALS = {
    "no_tolerance": (protocol(), "pilot", facts(PILOT, [F // 2]), TOO_MANY),
    "no_rule": (protocol(invalid_rows=DROP), "train", facts(N, [F // 2]), TOO_MANY),
    "over_max": (protocol(), "train", facts(N, clustered(MAX + 1)), TOO_MANY),
    "cause_read_error": (protocol(), "train", facts(N, [F // 2], q=READ_ERROR), CAUSE),
    "cause_other_walk": (protocol(), "train", facts(N, [F // 2], q=OTHER_WALK), CAUSE),
    "role": (protocol(), None, facts(), REJECTS + REASON["role"]),
    "rows": (protocol(), "train", facts(N - 1), REJECTS + REASON["rows"]),
    "sequence": (protocol(), "train", facts(contiguous=False), REJECTS + REASON["sequence"]),
    "integrity": (protocol(), "train", facts(findings=1), REJECTS + REASON["integrity"]),
    "coverage": (protocol(), "train", facts(windows=CLEAN - (MAX + 1) * (W + 1)), REJECTS + REASON["coverage"]),
    "rows_before_rule": (protocol(), "train", facts(N - 1, clustered(MAX + 1)), REJECTS + REASON["rows"]),
    "sequence_before_cause": (protocol(), "train", facts(contiguous=False, invalid=[F // 2], q=READ_ERROR),
                              REJECTS + REASON["sequence"]),
    "role_before_tolerance": (protocol(), None, facts(N, [F // 2]), REJECTS + REASON["role"]),
    "cause_before_integrity_and_coverage": (protocol(), "train", facts(findings=1, windows=0, invalid=[F // 2],
                                                                       q=OTHER_WALK), CAUSE),
    "count_before_coverage": (protocol(), "train", facts(N, isolated(MAX + 1)), TOO_MANY),
    "integrity_before_coverage": (protocol(), "train", facts(findings=1, windows=0), REJECTS + REASON["integrity"]),
}


@pytest.mark.parametrize("p, role, given, message", REFUSALS.values(), ids=REFUSALS)
def test_refusal_message_follows_the_first_code(p, role, given, message):
    verdict = acceptance.decide(p, role, given)
    assert not verdict["accepted"]
    assert acceptance._refusal(verdict) == message
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        acceptance.require_recorded(p, role, flipped(record(verdict)))


@pytest.mark.parametrize("invalid, message", [
    (dict.fromkeys(clustered(MAX + 1), UNCLOSED), TOO_MANY), (dict.fromkeys(isolated(MAX + 1), UNCLOSED), TOO_MANY),
    ({F // 2: READ_ERROR}, CAUSE), ({F // 2: OTHER_WALK}, CAUSE), ({F // 2: FINDING}, REJECTS + REASON["integrity"]),
], ids=["four_clustered", "four_isolated", "read_error", "other_walk", "finding"])
def test_listed_forgery_is_refused_by_the_archive_check_with_the_same_message(invalid, message, tmp_path):
    """F1c: the refused record restated as a clean acceptance that lists every invalid row of the archive."""
    p = protocol()
    data = stored(extraction(invalid=invalid), tmp_path)
    bad = [s for s, q in invalid.items() if not q["behavior_valid"]]
    values = flipped(honest(data, p), listed=bad)
    for call in (lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(data, p, "s", "train", values)):
        with pytest.raises(ValueError, match="^" + message + "$"):
            call()
    if bad:  # Without the list the archive check names the rows the record does not list.
        with pytest.raises(ValueError, match=INCOMPLETE):
            acceptance.require_accepted(data, p, "s", "train", flipped(honest(data, p)))


# Every branch of _same: the stored verdict and the summary fields repeat the verdict derived now.

def _set(path, value):
    def change(values):
        target = values
        for key in path[:-1]:
            target = target[key]
        if value is DROP:
            del target[path[-1]]
        else:
            target[path[-1]] = value
    return change


SAME = {
    "verdict_missing": (_set(("acceptance",), DROP), "audit record carries no acceptance verdict"),
    "verdict_null": (_set(("acceptance",), None), "audit record carries no acceptance verdict"),
    "verdict_list": (_set(("acceptance",), []), "audit record carries no acceptance verdict"),
    "verdict_gate": (_set(("acceptance", "gate"), GATE / 2), DIFFERS),
    "verdict_schema": (_set(("acceptance", "schema"), "hyptcn3/session-acceptance/0"), DIFFERS),
    "verdict_assigned_rows": (_set(("acceptance", "assigned_rows"), N + 1), DIFFERS),
    "verdict_windows": (_set(("acceptance", "windows"), CLEAN), DIFFERS),
    "verdict_score_coverage": (_set(("acceptance", "score_coverage"), CLEAN / N), DIFFERS),
    "verdict_extra_key": (_set(("acceptance", "note"), "reviewed"), DIFFERS),
    "verdict_key_missing": (_set(("acceptance", "schema"), DROP), DIFFERS),
    "verdict_fact_windows": (_set(("acceptance", "facts", "windows"), CLEAN), DIFFERS),
    # With these, each key of the stored verdict is changed alone once (its facts through their windows).
    "verdict_accepted": (_set(("acceptance", "accepted"), False), DIFFERS),
    "verdict_codes": (_set(("acceptance", "codes"), ["coverage"]), DIFFERS),
    "verdict_reasons": (_set(("acceptance", "reasons"), [REASON["coverage"]]), DIFFERS),
    "verdict_role": (_set(("acceptance", "role"), "dev"), DIFFERS),
    "verdict_snapshots": (_set(("acceptance", "snapshots"), N + 1), DIFFERS),
    "verdict_tolerated_invalid_seq": (_set(("acceptance", "tolerated_invalid_seq"), []), DIFFERS),
    "snapshots": (_set(("snapshots",), N + 1), DIFFERS),
    "snapshots_missing": (_set(("snapshots",), DROP), DIFFERS),
    "windows_embellished": (_set(("windows",), CLEAN), DIFFERS),
    "windows_as_float": (_set(("windows",), float(CLEAN - W - 1)), DIFFERS),
    "score_coverage_embellished": (_set(("score_coverage",), CLEAN / N), DIFFERS),
    "score_coverage_rounded": (_set(("score_coverage",), round((CLEAN - W - 1) / N, 3)), DIFFERS),
}


@pytest.mark.parametrize("change, message", SAME.values(), ids=SAME)
def test_record_that_differs_from_the_verdict_is_refused(change, message, tmp_path):
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    values = honest(data, p)
    change(values)
    for call in (lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(data, p, "s", "train", values)):
        with pytest.raises(ValueError, match="^" + message + "$"):
            call()


def test_record_of_a_dev_session_relabelled_as_train_differs_from_the_verdict(tmp_path):
    """The honest dev record with its top-level role alone rewritten to train passes the strict check; its stored
    verdict still names dev, and that alone refuses it for train."""
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    values = honest(data, p, "dev")
    assert acceptance.require_recorded(p, "dev", values) == acceptance.require_accepted(data, p, "s", "dev", values)
    values["role"] = "train"
    assert dict(values, acceptance=dict(values["acceptance"], role="train")) == honest(data, p)
    for call in (lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(data, p, "s", "train", values)):
        with pytest.raises(ValueError, match="^" + DIFFERS + "$"):
            call()


def test_embellished_numbers_are_refused(tmp_path):
    """F3: the honest record of one open walk with the windows and coverage of the clean session."""
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    clean = honest(stored(extraction(), tmp_path / "clean"), p)
    values = dict(honest(data, p), windows=clean["windows"], score_coverage=clean["score_coverage"])
    for call in (lambda: acceptance.require_recorded(p, "train", values),
                 lambda: acceptance.require_accepted(data, p, "s", "train", values)):
        with pytest.raises(ValueError, match=DIFFERS):
            call()


def test_record_without_a_quality_object_differs_from_the_verdict(tmp_path):
    p = protocol()
    data = stored(extraction(), tmp_path)
    for q in (None, [], DROP):
        values = honest(data, p)
        _set(("quality",), q)(values)
        for call in (lambda: acceptance.require_recorded(p, "train", values),
                     lambda: acceptance.require_accepted(data, p, "s", "train", values)):
            with pytest.raises(ValueError, match=DIFFERS):
                call()


def test_consistent_forgery_of_the_numbers_passes_the_record_check_and_not_the_archive_check(tmp_path):
    """require_recorded never opens the archive (its docstring): numbers forged consistently everywhere in the
    record reach it unseen; the verdict derived from the archive refuses them."""
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    honest_values = honest(data, p)
    forged = record(acceptance.decide(p, "train", dict(honest_values["acceptance"]["facts"], windows=CLEAN)))
    assert forged["quality"] == honest_values["quality"] and forged["windows"] == CLEAN
    assert acceptance.require_recorded(p, "train", forged)["windows"] == CLEAN
    with pytest.raises(ValueError, match=DIFFERS):
        acceptance.require_accepted(data, p, "s", "train", forged)


# A value JSON cannot state (NaN, an infinity) in a record read back from its file: _same refuses the record.

INVALID_FACTS = "invalid session facts"
UNSTATABLE = {"nan": math.nan, "inf": math.inf, "minus_inf": -math.inf}
# Path in the record -> message of require_recorded; require_accepted judges the archive and always says DIFFERS.
UNSTATABLE_PATHS = {
    ("windows",): DIFFERS, ("score_coverage",): DIFFERS, ("snapshots",): DIFFERS, ("acceptance", "gate"): DIFFERS,
    ("acceptance", "score_coverage"): DIFFERS, ("acceptance", "windows"): DIFFERS,
    ("acceptance", "snapshots"): DIFFERS, ("acceptance", "assigned_rows"): DIFFERS,
    # The stored facts are decided again first: a count that is no int is malformed facts, before any comparison.
    ("acceptance", "facts", "windows"): INVALID_FACTS, ("acceptance", "facts", "snapshots"): INVALID_FACTS,
}
UNSTATABLE_CASES = [pytest.param(path, value, message, id=".".join(path) + "-" + name)
                    for path, message in UNSTATABLE_PATHS.items() for name, value in UNSTATABLE.items()]
# The honest stored row of one open walk at F // 2, written by hand.
STORED_ROW = {"seq": F // 2, "truncated_traversals": ["processes"], "read_errors": 0, "filled_zero": 0}


def _read_back(values):
    """The record as a reader gets it from the audit file: json writes NaN and the infinities and reads them back."""
    return json.loads(json.dumps(values))


def _at(values, path):
    for key in path:
        values = values[key]
    return values


@pytest.mark.parametrize("path, value, recorded_message", UNSTATABLE_CASES)
def test_value_json_cannot_state_is_refused(path, value, recorded_message, tmp_path):
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    values = honest(data, p)
    _set(path, value)(values)
    values = _read_back(values)
    assert repr(_at(values, path)) == repr(value)  # The record read back still holds the value.
    with pytest.raises(ValueError, match="^" + recorded_message + "$"):
        acceptance.require_recorded(p, "train", values)
    with pytest.raises(ValueError, match="^" + DIFFERS + "$"):
        acceptance.require_accepted(data, p, "s", "train", values)


@pytest.mark.parametrize("key, recorded_message", [("read_errors", CAUSE), ("filled_zero", CAUSE),
                                                   ("seq", INVALID_FACTS)], ids=["read_errors", "filled_zero", "seq"])
def test_nan_in_a_stored_row_is_pinned(key, recorded_message, tmp_path):
    """NaN in the first stored invalid row: a counter the row rule reads is a cause, the seq malformed facts."""
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    values = honest(data, p)
    assert values["acceptance"]["facts"]["invalid_rows"] == [STORED_ROW]
    values["acceptance"]["facts"]["invalid_rows"][0][key] = math.nan
    values = _read_back(values)
    assert math.isnan(values["acceptance"]["facts"]["invalid_rows"][0][key])
    with pytest.raises(ValueError, match="^" + recorded_message + "$"):
        acceptance.require_recorded(p, "train", values)
    with pytest.raises(ValueError, match="^" + DIFFERS + "$"):
        acceptance.require_accepted(data, p, "s", "train", values)


def test_round_trip_twin_is_accepted(tmp_path):
    """Positive twin of the two tests above: the same construction without a change is accepted at both depths."""
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    before = honest(data, p)
    assert before["acceptance"]["facts"]["invalid_rows"] == [STORED_ROW]
    values = _read_back(before)
    assert values == before
    assert acceptance.require_recorded(p, "train", values) == before["acceptance"]
    assert acceptance.require_accepted(data, p, "s", "train", values) == before["acceptance"]


# worst_invalid_rows and synthetic_windows against a brute force over every placement.

SMALL = [(1, 1, 4), (6, 2, 3), (9, 1, 4), (12, 2, 5), (13, 3, 13), (16, 3, 3), (17, 2, 6), (20, 3, 7), (24, 2, 12),
         (25, 4, 9), (29, 2, 10), (30, 3, 12), (30, 1, 30), (30, 5, 8)]


def grid(length, window_rows, full_every):
    return {"full_every": full_every, "window_rows": window_rows, "interval_s": 1, "max_gap_s": 1.5}


@pytest.mark.parametrize("length, window_rows, full_every", SMALL, ids=[f"{a}_{b}_{c}" for a, b, c in SMALL])
def test_worst_invalid_rows_cost_the_most_windows(length, window_rows, full_every):
    for count in range(4):
        worst = acceptance.worst_invalid_rows(length, window_rows, full_every, count)
        assert worst == sorted(set(worst)) and set(worst) <= set(range(length)) and len(worst) <= count
        fewest = min(window_count(length, window_rows, full_every, set(c))
                     for c in combinations(range(length), min(count, length)))
        assert window_count(length, window_rows, full_every, set(worst)) == fewest


@pytest.mark.parametrize("length, window_rows, full_every", SMALL, ids=[f"{a}_{b}_{c}" for a, b, c in SMALL])
def test_synthetic_windows_count_as_the_oracle(length, window_rows, full_every):
    p = grid(length, window_rows, full_every)
    for count in range(3):
        for placement in combinations(range(length), min(count, length)):
            assert acceptance.synthetic_windows(p, length, placement) == window_count(
                length, window_rows, full_every, set(placement))
    worst = acceptance.worst_invalid_rows(length, window_rows, full_every, 3)
    assert acceptance.synthetic_windows(p, length, worst) == window_count(length, window_rows, full_every, set(worst))


@pytest.mark.parametrize("length, window_rows, full_every, pilot, count", [
    (24, 2, 12, 15, 2), (30, 3, 12, 16, 3), (29, 2, 10, 13, 1), (96, 8, 64, 80, 3)])
def test_reachability_cases_are_decided_on_the_oracles_worst_session(length, window_rows, full_every, pilot, count):
    fewest = min(window_count(length, window_rows, full_every, set(c)) for c in combinations(range(length), count)) \
        if length < 40 else CLEAN - count * (window_rows + 1)
    clean = window_count(length, window_rows, full_every)
    for gate in (fewest / length, (fewest + 1) / length):
        p = dict(protocol(), cycles=length, window_rows=window_rows, full_every=full_every, pilot_cycles=pilot,
                 min_score_coverage=gate, invalid_rows={"max": count, "traversals": ["processes"]})
        cases = {(c["key"], c["case"]): c for c in acceptance.protocol_reachability(p)}
        assert set(cases) == {("pilot_cycles", "clean"), ("cycles", "clean"), ("cycles", "worst")}
        expected = {("pilot_cycles", "clean"): window_count(pilot, window_rows, full_every),
                    ("cycles", "clean"): clean, ("cycles", "worst"): fewest}
        for key, windows in expected.items():
            rows = pilot if key[0] == "pilot_cycles" else length
            assert cases[key]["windows"] == windows and cases[key]["rows"] == rows
            assert cases[key]["accepted"] is (windows / rows >= gate)
        assert len(cases[("cycles", "worst")]["invalid_seq"]) == count


# Addendum 4a (K4-A): NaN in the recorded lists and counts that the cases of test_value_json_cannot_state_is_refused
# do not reach, one message per depth. Positive twin: test_round_trip_twin_is_accepted.
NAN_PATHS = {
    "quality_tolerated": (("quality", "tolerated_invalid_seq"), [math.nan], DIFFERS, INCOMPLETE),
    "stored_tolerated": (("acceptance", "tolerated_invalid_seq"), [math.nan], DIFFERS, DIFFERS),
    "stored_findings": (("acceptance", "facts", "integrity_findings"), math.nan, INVALID_FACTS, DIFFERS),
}


@pytest.mark.parametrize("case", NAN_PATHS)
def test_nan_among_recorded_lists_and_counts_is_refused(case, tmp_path):
    path, value, recorded_message, accepted_message = NAN_PATHS[case]
    p = protocol()
    data = stored(extraction(invalid={F // 2: UNCLOSED}), tmp_path)
    values = honest(data, p)
    _set(path, value)(values)
    values = _read_back(values)
    assert repr(_at(values, path)) == repr(value)  # The record read back still holds the value.
    with pytest.raises(ValueError, match="^" + recorded_message + "$"):
        acceptance.require_recorded(p, "train", values)
    with pytest.raises(ValueError, match="^" + accepted_message + "$"):
        acceptance.require_accepted(data, p, "s", "train", values)
