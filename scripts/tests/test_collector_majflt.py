"""The major faults of the collector per cycle (protocol v5, package B10, agent Q; the lead's answer to question Q29,
2026-11-24; risk capture R4 of the code audit, data/results/audit_kodu_v5_20261120.json).

The audit of a session of protocol schema 3 reads capture.rusage.majflt of every sidecar, the major faults of the
collector's sampling thread during that cycle (vmicollect/src/meta.c, collector.c). It records the largest count of
one cycle, the seq of the first cycle with it, the sum and the cycles counted in values.collector_majflt, prints them
in its summary, and names a missing or malformed count as a reason, never as 0 (scripts/collection.py audit_session,
majflt_record). The bound is the protocol value audit.collector_majflt_max: null until G2 (determined_at), with its
rule in audit.collector_majflt_note. A number refuses a session with a cycle above it, and the audit self-test then
builds the case of one cycle at bound + 1 (scripts/tests/audit_cases.py cases). Schemas 1 and 2 do not read the count.
The names this package adds are imported inside the tests, so this file collects on the code before it and fails
there test by test. Synthetic sessions only: the bound 7 and the counts 500 and 7 are numbers of these tests, not
measurements, and 0 is the rule's bound at zero.
"""
import copy
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
FRAME = 3  # The sidecar a test edits: a delta snapshot of the small protocol (scripts/tests/audit_cases.py FRAME).
# The reasons, written here and never taken from the code under test.
BOUND = "collector major faults per cycle above the audit bound"
NOT_A_COUNT = "collector major fault count is not an integer of at least 0: frame3.json:capture.rusage.majflt"
MISSING = "missing key: frame3.json:capture.rusage.majflt"
CASE_ID = "collector_majflt_above_bound"


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    """(protocol, its path) of the small schema-3 protocol of the audit self-test (interval 1 s, 96 cycles, windows of
    8, a full snapshot every 64; scripts/tests/test_audit_selftest.py small_doc) with the bound of the G0 file."""
    from scripts import collection
    from scripts.tests import boundary_sessions as bs
    from scripts.tests.test_audit_selftest import small_doc
    root = tmp_path_factory.mktemp("majflt")
    path = bs.write_protocol(root / "protocol.json", small_doc(bs.profile_dir(root / "profile")))
    return collection.protocol(path), path


def bounded(p, directory, bound):
    """A copy of protocol p with audit.collector_majflt_max = bound, written below directory: (protocol, path)."""
    from scripts import collection
    from scripts.tests import boundary_sessions as bs
    doc = copy.deepcopy(p)
    doc["audit"]["collector_majflt_max"] = bound
    path = bs.write_protocol(Path(directory) / f"protocol-majflt-{bound}.json", doc)
    return collection.protocol(path), path


def _edit_sidecar(directory, seq, change):
    path = directory / "raw" / f"frame{seq}.json"
    side = json.loads(path.read_text())
    change(side)
    path.write_text(json.dumps(side))


def _count(count):
    def change(side):
        side["capture"].setdefault("rusage", {})["majflt"] = count
    return change


def audited(root, p, path, counts=(), change=None):
    """The clean session of the audit self-test under (p, path) below root (scripts/tests/audit_cases.py
    clean_session), with the major faults `counts` ({seq: count}) in those sidecars and `change` applied to the
    sidecar of FRAME, audited by the real audit: a boundary_sessions.Audit."""
    from scripts.tests import audit_cases, boundary_sessions as bs
    session = audit_cases.clean_session(root, p, path, audit_cases.SESSION)
    for seq, count in dict(counts).items():
        _edit_sidecar(session.directory, seq, _count(count))
    if change is not None:
        _edit_sidecar(session.directory, FRAME, change)
    return bs.audit(session, p)


def v5(**audit):
    """config/collection-v5.json with the keys of its audit section given replaced."""
    doc = json.loads(V5.read_text())
    doc["audit"].update(audit)
    return doc


# ------------------------------------------------------------------ the protocol key


def test_the_v5_file_states_the_bound_null_until_g2_with_the_rule_of_q29(tmp_path):
    """The lead's answer to Q29: audit.collector_majflt_max is null in the G0 file and determined at G2 (determined_at
    names it there and nowhere else), and its note holds the lead's rule (in English) with the question it answers.
    The self-check of stage G0 finds no null outside determined_at; the one of stage G2 names this null, and no longer
    once G2 sets the bound. A bound set at G2 keeps the records of G0 and G1 and reopens G2 and every later stage."""
    from features.audit_policy import audit_bounds
    from scripts import gates, protocol_v5
    doc = json.loads(V5.read_text())
    bounds = audit_bounds(doc)
    assert bounds["collector_majflt_max"] is None
    assert all(text in bounds["collector_majflt_note"] for text in (
        "Q29", "capture R4", "capture.rusage.majflt", "null until G2",
        "the largest count per cycle observed in the error-free runs of G2 on both VMs; at zero the bound is 0",
        "is a reason, never 0", "never a reason", "bound + 1"))
    assert "audit.collector_majflt_max" in doc["determined_at"]["G2"]
    assert [stage for stage, paths in doc["determined_at"].items() for path in paths if "collector_majflt" in path] == [
        "G2"]
    assert protocol_v5.check_analysis(doc) == []
    assert [r for r in protocol_v5.check_analysis(doc, stage="G2") if "collector_majflt" in r] == [
        "null at audit.collector_majflt_max determined at G2 (stage G2)"]
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_bytes(V5.read_bytes())
    doc["audit"]["collector_majflt_max"] = 0
    after.write_text(json.dumps(doc, indent=2) + "\n")
    assert [stage for stage in gates.STAGES
            if gates.stage_binding(before, stage) == gates.stage_binding(after, stage)] == ["G0", "G1"]
    assert [r for r in protocol_v5.check_analysis(doc, stage="G2") if "collector_majflt" in r] == []


@pytest.mark.parametrize("value", [None, 0, 7], ids=["null", "zero", "seven"])
def test_the_bound_is_null_or_an_integer_of_at_least_0(value):
    """Null until G2, then the largest count of G2 (0 at zero; 7 a number of this test only)."""
    from features.audit_policy import audit_bounds
    assert audit_bounds(v5(collector_majflt_max=value))["collector_majflt_max"] == value


@pytest.mark.parametrize("value", [-1, 1.5, True, "3"], ids=["negative", "fraction", "true", "string"])
def test_a_bound_that_is_no_integer_of_at_least_0_is_refused_by_its_name(value):
    """The value check of features/audit_policy.py audit_bounds, the only reader of the audit section: a count below
    0, a fraction, a boolean (no count, though Python counts it an int) and a string are each refused by the key's
    name."""
    from features.audit_policy import audit_bounds
    with pytest.raises(ValueError) as error:
        audit_bounds(v5(collector_majflt_max=value))
    assert str(error.value) == "invalid audit bounds: collector_majflt_max"


def test_the_bound_and_its_note_are_required_and_the_note_says_something():
    """No silent default: without the bound or without its note the audit section is refused as a whole, and a note
    of white space by the note's name."""
    from features.audit_policy import audit_bounds
    for key in ("collector_majflt_max", "collector_majflt_note"):
        doc = v5()
        del doc["audit"][key]
        with pytest.raises(ValueError) as error:
            audit_bounds(doc)
        assert str(error.value) == "invalid audit bounds"
    with pytest.raises(ValueError) as error:
        audit_bounds(v5(collector_majflt_note=" "))
    assert str(error.value) == "invalid audit bounds: collector_majflt_note"


# ------------------------------------------------------------------ the audit


def test_the_audit_records_the_largest_count_its_seq_the_sum_and_the_cycles_counted(small, tmp_path):
    """Three cycles with major faults, the largest count twice: values.collector_majflt names the largest count (500),
    the seq of the first cycle with it (3, not 10), the sum over the 96 cycles (500 + 500 + 7) and the cycles counted
    (all 96); under the null bound of G0 the session is accepted."""
    p, path = small
    audit = audited(tmp_path, p, path, counts={FRAME: 500, 10: 500, 20: 7})
    assert (audit.code, audit.values["reasons"]) == (0, [])
    assert audit.values["collector_majflt"] == {"max": 500, "max_seq": 3, "sum": 1007, "cycles": 96}


def test_under_the_null_bound_500_faults_in_every_cycle_are_printed_and_never_a_reason(small, tmp_path):
    """The verifier's probe of risk capture R4, 500 collector major faults per cycle, under the null bound of G0: the
    session is accepted, and the counts stand in the record and in the summary the audit prints. A clean session
    counts 0 in each cycle (its first cycle is the first with the largest count)."""
    p, path = small
    assert p["audit"]["collector_majflt_max"] is None
    audit = audited(tmp_path / "probe", p, path, counts={seq: 500 for seq in range(p["cycles"])})
    expected = {"max": 500, "max_seq": 0, "sum": 500 * 96, "cycles": 96}
    assert (audit.code, audit.values["accepted"], audit.values["reasons"]) == (0, True, [])
    assert audit.values["collector_majflt"] == expected
    assert json.loads(audit.stdout)["collector_majflt"] == expected
    assert audit.values["audit_bounds"]["collector_majflt_max"] is None
    clean = audited(tmp_path / "clean", p, path)
    assert clean.values["collector_majflt"] == {"max": 0, "max_seq": 0, "sum": 0, "cycles": 96}


@pytest.mark.parametrize("bound", [0, 7], ids=["zero", "seven"])
def test_a_bound_refuses_one_cycle_above_it_and_accepts_a_cycle_at_it(small, tmp_path, bound):
    """From G2, under a copy of the small protocol with a bound (0, the rule's bound at zero, or 7, a number of this
    test only): one cycle at the bound is accepted, one cycle at bound + 1 refuses the session with exactly the bound's
    reason, and the record names that cycle."""
    p, _ = small
    capped, path = bounded(p, tmp_path, bound)
    at = audited(tmp_path / "at", capped, path, counts={FRAME: bound})
    assert (at.code, at.values["accepted"], at.values["reasons"]) == (0, True, [])
    assert at.values["collector_majflt"] == {"max": bound, "max_seq": FRAME if bound else 0, "sum": bound, "cycles": 96}
    above = audited(tmp_path / "above", capped, path, counts={FRAME: bound + 1})
    assert (above.code, above.values["accepted"], above.values["reasons"]) == (2, False, [BOUND])
    assert above.values["collector_majflt"] == {"max": bound + 1, "max_seq": FRAME, "sum": bound + 1, "cycles": 96}


@pytest.mark.parametrize("change, reason", [
    (lambda side: side["capture"]["rusage"].pop("majflt"), MISSING),
    (lambda side: side["capture"].pop("rusage"), MISSING),
    (lambda side: side["capture"].update(rusage=None), MISSING),
    (lambda side: side["capture"]["rusage"].update(majflt=None), NOT_A_COUNT),
    (lambda side: side["capture"]["rusage"].update(majflt=-1), NOT_A_COUNT),
    (lambda side: side["capture"]["rusage"].update(majflt=1.5), NOT_A_COUNT),
    (lambda side: side["capture"]["rusage"].update(majflt=0.), NOT_A_COUNT),
    (lambda side: side["capture"]["rusage"].update(majflt=True), NOT_A_COUNT),
    (lambda side: side["capture"]["rusage"].update(majflt="0"), NOT_A_COUNT),
], ids=["no_count", "no_rusage", "rusage_null", "null", "negative", "fraction", "float_zero", "true", "string"])
def test_a_missing_or_malformed_count_is_named_and_never_taken_as_0(small, tmp_path, change, reason):
    """Under the null bound of G0, which a count of 0 passes: a sidecar without capture.rusage.majflt (no count, no
    rusage, rusage null) or with a value that is no integer of at least 0 (null, -1, 1.5, 0.0, true, a string)
    refuses the session with exactly the reason that names its file and key; the record counts the other 95 cycles."""
    p, path = small
    audit = audited(tmp_path, p, path, change=change)
    assert (audit.code, audit.values["accepted"], audit.values["reasons"]) == (2, False, [reason])
    assert audit.values["collector_majflt"] == {"max": 0, "max_seq": 0, "sum": 0, "cycles": 95}


def test_no_usable_count_records_null_and_never_0(small, tmp_path):
    """A session whose sidecars hold no count at all: every one is a reason, and the largest count, its seq and the
    sum are null over 0 cycles counted."""
    from scripts.tests import audit_cases, boundary_sessions as bs
    p, path = small
    session = audit_cases.clean_session(tmp_path, p, path, audit_cases.SESSION)
    for seq in range(p["cycles"]):
        _edit_sidecar(session.directory, seq, lambda side: side["capture"].pop("rusage"))
    audit = bs.audit(session, p)
    assert (audit.code, audit.values["reasons"]) == (
        2, sorted(f"missing key: frame{seq}.json:capture.rusage.majflt" for seq in range(p["cycles"])))
    assert audit.values["collector_majflt"] == {"max": None, "max_seq": None, "sum": None, "cycles": 0}


def test_schemas_1_and_2_do_not_read_the_count(tmp_path):
    """Schemas 1 and 2 stay as they were (the lead's answer to Q29 binds schema 3): a train session of the schema-2
    family S2G whose sidecar of FRAME has a count below 0 and whose sidecar 5 has none is accepted with no reason,
    and the record and the printed summary state null: the count is not read."""
    from scripts import collection
    from scripts.tests import boundary_sessions as bs
    path = bs.write_protocol(tmp_path / "S2G.json", bs.family("S2G", bs.profile_dir(tmp_path / "profile")))
    p = collection.protocol(path)
    session = bs.build_session(tmp_path / "sessions", p, path, bs.places(p, "train")[0], session_id="majflt-schema2",
                               base=bs.time_base(p, "train", 0))
    _edit_sidecar(session.directory, FRAME, _count(-1))
    _edit_sidecar(session.directory, 5, lambda side: side["capture"].pop("rusage", None))
    audit = bs.audit(session, p)
    assert (audit.code, audit.values["reasons"], audit.values["audit_bounds"]) == (0, [], None)
    assert audit.values["collector_majflt"] is None
    assert json.loads(audit.stdout)["collector_majflt"] is None


# ------------------------------------------------------------------ the self-test


@pytest.mark.parametrize("bound", [0, 7], ids=["zero", "seven"])
def test_the_self_test_builds_the_case_of_the_bound_only_once_the_bound_is_a_number(small, tmp_path, bound):
    """Under the null bound of G0 (the small protocol and the v5 file) the self-test's list (audit_cases.cases) is
    CASES, which holds no case of the bound, and UNREACHABLE names the bound's reason. Under a copy with a bound (0, or
    7, a number of this test only) the list holds the case of one cycle at bound + 1 right after the RAM cases, the
    real audit refuses it with exactly the bound's reason, UNREACHABLE no longer names it, and require_selftest asks a
    record for that list. With the cap of rule-closed rows set too, the case of the cap comes first."""
    from scripts import audit_selftest, collection
    from scripts.tests import audit_cases
    p, _ = small
    for null in (p, collection.protocol(V5)):
        assert null["audit"]["collector_majflt_max"] is None
        assert (audit_cases.cases(null), BOUND in audit_cases.unreachable(null)) == (audit_cases.CASES, True)
    assert CASE_ID not in [case.id for case in audit_cases.CASES]
    capped, path = bounded(p, tmp_path, bound)
    ram, logs = [case.id for case in audit_cases.RAM_CASES], [case.id for case in audit_cases.LOG_CASES]
    listed = audit_cases.cases(capped)
    assert [case.id for case in listed] == ram + [CASE_ID] + logs
    assert BOUND not in audit_cases.unreachable(capped)
    case = listed[len(ram)]
    assert audit_cases.expected(case, capped) == [BOUND]
    audit = audit_cases.run_case(tmp_path / "cases", capped, path, case)
    assert (audit.code, audit.values["reasons"]) == (2, [BOUND])
    assert audit.values["collector_majflt"] == {"max": bound + 1, "max_seq": FRAME, "sum": bound + 1, "cycles": 96}
    both = copy.deepcopy(capped)
    both["audit"]["rule_closed_rows_max"] = 2
    assert [case.id for case in audit_cases.cases(both)] == ram + ["rule_closed_above_cap", CASE_ID] + logs
    record = {"schema": audit_selftest.SCHEMA, "date": "2026-11-24T00:00:00+00:00", "passed": True,
              "protocol_sha256": audit_selftest.digest(path), "measurement_sha256": audit_selftest.measurement_sha256(),
              "cases_sha256": audit_selftest.cases_sha256()}
    for name, cases in (("without_the_case", audit_cases.CASES), ("self_test", listed)):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "audit_selftest_a.json").write_text(json.dumps(dict(record, cases=[{"id": c.id} for c in cases])))
        if name == "without_the_case":
            with pytest.raises(ValueError, match="^no valid audit self-test record for the current code and protocol$"):
                audit_selftest.require_selftest(path, directory)
        else:
            assert audit_selftest.require_selftest(path, directory)["cases"] == [{"id": c.id} for c in cases]


def test_the_self_test_names_a_count_that_is_no_count_under_the_null_bound(small, tmp_path):
    """The case of a malformed count is one of the RAM cases under every schema-3 protocol, the null bound of G0
    included, and the real audit refuses it with exactly its reason; the case of a missing count is the mandatory-key
    case of the sidecar key capture.rusage.majflt."""
    from scripts.tests import audit_cases
    p, path = small
    by_id = {case.id: case for case in audit_cases.cases(p)}
    for case_id, reason in (("collector_majflt_not_a_count", NOT_A_COUNT),
                            ("missing_key:frame3.json:capture.rusage.majflt", MISSING)):
        case = by_id[case_id]
        assert audit_cases.expected(case, p) == [reason]
        audit = audit_cases.run_case(tmp_path / "cases", p, path, case)
        assert (audit.code, audit.values["reasons"]) == (2, [reason])
