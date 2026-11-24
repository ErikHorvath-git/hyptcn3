"""The self-test of the audit checks (protocol v5, package B3; proposal 6.2, chapter 11 point 4).

Every case of scripts/tests/audit_cases.py is built under a small schema-3 protocol (interval 1 s, 96 cycles,
windows of 8, a full snapshot every 64, like family S3) and audited by the real audit: refused with exactly its
reasons; the clean session is accepted. Then the record of scripts/audit_selftest.py and what run_session asks of
it, the register of exceptions, and the rules of the verdict no buildable session reaches. Names package B3 adds
are imported inside the tests, so this file also runs on the code before B3 and fails there test by test.
Synthetic sessions only; nothing here is a measurement.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
REFUSED = "no valid audit self-test record for the current code and protocol"
SELFTEST_PROTOCOL = ROOT / "config/collection-v5.json"  # The self-test protocol since package B4.


def pytest_generate_tests(metafunc):
    """One test id per case; before B3 (no case module) a single id that fails."""
    if "case_id" in metafunc.fixturenames:
        try:
            from scripts.tests.audit_cases import CASES
            ids = [case.id for case in CASES]
        except ImportError:
            ids = ["audit_cases_missing"]
        metafunc.parametrize("case_id", ids)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def small_doc(profile):
    """The small protocol with four scenarios, which take the four v5 entries of the file (eshop and corp, low and
    high): the cases of the v5 traffic need a scenario of each profile (package B5b)."""
    from scripts.tests import boundary_sessions as bs
    doc = bs.protocol_doc(profile, schema="hyptcn3/collection-protocol/3", cycles=96, pilot_cycles=80,
                          window_rows=8, full_every=64, gate=bs.worst_gate(96, 8, 64, bs.RULE["max"]),
                          group_prefix="st-", name="audit-selftest-small",
                          scenarios={name: {} for name in ("steady", "bursty", "office", "office_busy")})
    return dict(doc, **bs.audit_sections(1))


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    """(protocol, its path, a work directory) of the small schema-3 protocol."""
    from scripts import collection
    from scripts.tests import boundary_sessions as bs
    root = tmp_path_factory.mktemp("selftest")
    path = bs.write_protocol(root / "protocol.json", small_doc(bs.profile_dir(root / "profile")))
    return collection.protocol(path), path, root


def case_of(case_id):
    from scripts.tests import audit_cases
    return {case.id: case for case in audit_cases.CASES}[case_id]


# Each check refuses its bad session with exactly the expected reasons; the clean session passes.

def test_bad_session_is_refused_with_exactly_its_reasons(small, case_id):
    from scripts.tests import audit_cases
    p, path, root = small
    case = case_of(case_id)
    audit = audit_cases.run_case(root / "cases", p, path, case)
    assert (audit.code, audit.values["reasons"]) == (2, audit_cases.expected(case, p))
    assert audit.values["accepted"] is False


def test_clean_session_is_accepted_with_every_registered_exception(small):
    from features import audit_policy
    from scripts.tests import audit_cases
    p, path, root = small
    audit = audit_cases.run_case(root / "clean", p, path)
    v = audit.values
    assert (audit.code, v["accepted"], v["reasons"]) == (0, True, [])
    assert list(v["exceptions"]) == list(audit_policy.TOLERATED)
    assert all(type(e["observed"]) is int and e["expected"] is None for e in v["exceptions"].values())
    assert v["exceptions"]["inconclusive_integrity"]["observed"] == p["cycles"]  # text_integrity in every row
    # Both walks closed every process list over the same tasks and no traversal skipped a task (recorded only).
    assert (v["quality"]["process_walk_backward_disagrees_seq"], v["quality"]["skipped_tasks"],
            v["quality"]["skipped_tasks_unrecorded_seq"]) == ([], {"sockets": 0, "memory_patterns": 0}, [])
    assert v["audit_bounds"] == p["audit"]
    assert v["timing"]["periodic_run"] == {"equal_spacings": 0, "spacing": None, "min_spacing_rows": 2,
                                           "flagged_rows": 0}
    assert v["timing"]["spacing_mode"] == {"spacing": None, "count": 0, "spacings": 0}
    assert v["timing"]["delta_ms_max"] < p["audit"]["cycle_ms_max"]["delta"] < v["timing"]["full_ms_max"]
    assert v["timing"]["full_ms_max"] <= p["audit"]["cycle_ms_max"]["full"]


def test_grid_phase_is_recorded_from_the_first_frame(small):
    """(timestamp_unix - lateness_s) of frame 0 modulo interval_s: 0.05 s late, the grid is 0.05 s earlier."""
    from scripts.tests import audit_cases, boundary_sessions as bs
    p, path, root = small
    session = audit_cases.clean_session(root / "phase", p, path, audit_cases.SESSION)
    frame = session.directory / "raw" / "frame0.json"
    side = json.loads(frame.read_text())
    side["sched"]["lateness_s"] = .05
    frame.write_text(json.dumps(side))
    audit = bs.audit(session, p)
    assert audit.code == 0
    assert audit.values["timing"]["grid_phase_s"] == round((side["timestamp_unix"] - .05) % p["interval_s"], 6)
    assert audit.values["timing"]["lateness_s_max"] == .05


def test_every_reason_of_the_audit_and_the_verdict_has_a_case():
    """Each reason audit_session and the verdict write (its literal text up to the first formatted part) is the
    start of a reason some case expects, or of a reason UNREACHABLE names with its why."""
    from scripts.tests import audit_cases
    from scripts.tests.audit_cases import CASES, RAM_CASES, UNREACHABLE

    def prefix(node):
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.BinOp):
            return prefix(node.left)
        if isinstance(node, ast.JoinedStr):
            return "".join(v.value for v in node.values[:1] if isinstance(v, ast.Constant))
        return None

    written = set()
    for source, functions, calls in (("scripts/collection.py", ("audit_session", "positive_controls", "required"),
                                      ("append",)),
                                     ("features/acceptance.py", ("_verdict",), ("reject",))):
        tree = ast.parse((ROOT / source).read_text())
        for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in functions):
            for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
                name = getattr(call.func, "attr", getattr(call.func, "id", None))
                if name in calls and call.args:
                    text = prefix(call.args[-1])
                    if text:
                        written.add(text)
    assert len(written) >= 30 and len({case.id for case in CASES}) == len(CASES)  # One id, one case.
    p = json.loads(SELFTEST_PROTOCOL.read_text())
    covered = [reason for case in RAM_CASES for reason in audit_cases.expected(case, p)] + list(UNREACHABLE)
    assert sorted(text for text in written if not any(reason.startswith(text) for reason in covered)) == []
    assert all(type(why) is str and why.strip() for why in UNREACHABLE.values())


# The record of scripts/audit_selftest.py and require_selftest.

@pytest.fixture
def recorded(small, tmp_path, monkeypatch):
    """main() run under the small protocol with two cases (the full list is the parametrized test above)."""
    from scripts import audit_selftest
    from scripts.tests import audit_cases
    two = audit_cases.RAM_CASES[:2]
    monkeypatch.setattr(audit_selftest, "cases", lambda p: two)  # The self-test's list under p (B10, S1 of B3).
    p, path, _ = small
    out = tmp_path / "records" / "audit_selftest_a.json"
    out.parent.mkdir()
    code = audit_selftest.main(["--protocol", str(path), "--out", str(out)])
    return SimpleNamespace(code=code, out=out, doc=json.loads(out.read_text()), path=path, ids=[c.id for c in two])


def test_main_writes_a_passed_record_bound_to_protocol_code_and_cases(recorded):
    from scripts import audit_selftest, gates
    doc = recorded.doc
    assert recorded.code == 0 and doc["passed"] is True
    assert doc["schema"] == "hyptcn3/audit-selftest/1"
    assert doc["protocol_sha256"] == sha256(recorded.path)
    assert doc["measurement_sha256"] == gates.measurement_sha256()
    assert doc["cases_sha256"] == audit_selftest.cases_sha256() and len(doc["cases_sha256"]) == 64
    assert doc["commit"] == subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
                                           text=True).stdout.strip()
    assert doc["clean"] == {"code": 0, "reasons": []}
    # The provenance of every record of data/results (scripts/check_claims.sh, check E).
    assert doc["n"] == len(doc["cases"]) and doc["guest"] == audit_selftest.GUEST and doc["host"].count(", kernel ") == 1
    assert [c["id"] for c in doc["cases"]] == recorded.ids and all(c["passed"] and c["code"] == 2 for c in doc["cases"])
    assert all(c["reasons"] == c["expected"] for c in doc["cases"])
    assert "collection.retazec" in doc["replaced"]
    assert audit_selftest.require_selftest(recorded.path, recorded.out.parent) == doc
    with pytest.raises(FileExistsError):  # A record is never overwritten.
        audit_selftest.main(["--protocol", str(recorded.path), "--out", str(recorded.out)])


def _another(recorded, name, **changes):
    path = recorded.out.parent / name
    path.write_text(json.dumps(dict(recorded.doc, **changes)))
    return path


@pytest.mark.parametrize("case", ["absent", "other_protocol", "measurement_changed", "cases_changed",
                                  "newest_not_passed", "case_ids_differ"])
def test_require_selftest_refuses_without_a_valid_record(recorded, case, tmp_path, monkeypatch):
    from scripts import audit_selftest
    directory, path = recorded.out.parent, recorded.path
    if case == "absent":
        directory = tmp_path / "empty"
        directory.mkdir()
    elif case == "other_protocol":
        path = tmp_path / "other.json"
        path.write_text(json.dumps(dict(json.loads(recorded.path.read_text()), name="another")))
    elif case == "measurement_changed":
        monkeypatch.setattr(audit_selftest, "measurement_sha256", lambda: "0" * 64)
    elif case == "cases_changed":
        monkeypatch.setattr(audit_selftest, "cases_sha256", lambda: "1" * 64)
    elif case == "newest_not_passed":  # A newer record of the same code and protocol that failed.
        _another(recorded, "audit_selftest_b.json", passed=False, date="9999-01-01T00:00:00+00:00")
    else:
        _another(recorded, "audit_selftest_b.json", cases=recorded.doc["cases"][:1], date="9999-01-01T00:00:00+00:00")
    with pytest.raises(ValueError, match="^" + REFUSED + "$"):
        audit_selftest.require_selftest(path, directory)


def test_run_session_refuses_to_start_without_a_valid_record(small, tmp_path, monkeypatch):
    """The first thing run_session asks, as root and before any guest access; with a valid record it goes on."""
    from scripts import audit_selftest, collection
    p, path, _ = small
    touched = []
    for name in ("guest_identity", "qemu_process", "collection_lock", "lab_json"):
        monkeypatch.setattr(collection, name, lambda *a, _name=name, **kw: touched.append(_name))
    monkeypatch.setattr(audit_selftest, "RESULTS", tmp_path / "results")
    (tmp_path / "results").mkdir()
    monkeypatch.setattr("os.geteuid", lambda: 0)
    a = SimpleNamespace(protocol=path, role="train", scenario="steady", group="st-train-1", seed=1,
                        collections_dir=tmp_path / "collections")
    with pytest.raises(ValueError, match="^" + REFUSED + "$"):
        collection.run_session(a, p)
    assert touched == [] and not (tmp_path / "collections").exists()
    # Twin: with a record the self-test passes and the run stops at the next check (here: no root).
    monkeypatch.setattr(audit_selftest, "require_selftest", lambda protocol_path, directory=None: None)
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="sudo"):
        collection.run_session(a, p)


def _root_run(p, path, tmp_path, monkeypatch, identity, memory):
    """run_session as root up to its guest and host checks: the guest identity, the QEMU process and its memory
    are given; it must refuse before the session directory exists."""
    from scripts import audit_selftest, collection
    monkeypatch.setattr(audit_selftest, "require_selftest", lambda protocol_path, directory=None: None)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(collection, "COLLECTIONS", tmp_path / "collections")
    monkeypatch.setattr(collection, "guest_identity", lambda pv: copy.deepcopy(identity))
    monkeypatch.setattr(collection, "qemu_process", lambda domain: {"pid": 4242, "start_ticks": 1, "host_boot": "b"})
    monkeypatch.setattr(collection, "host_memory", lambda qemu: dict(memory))
    a = SimpleNamespace(protocol=path, role="train", scenario="steady", group="st-train-1", seed=1, mode="campaign",
                        attempt=1)  # Package B9: a session of a planned role names its plan and attempt.
    with pytest.raises(ValueError) as caught:
        collection.run_session(a, p)
    assert [f for f in (tmp_path / "collections").iterdir() if not f.name.startswith(".lock")] == []
    return str(caught.value)


def _identity(lab):
    from scripts import collection
    return {"kernel": "k", "boot_id": "b", "machine_id": "m", "stack_sha256": "s",
            "stack_manifest": [f"{lab[source]}  {path}" for path, source in collection.deployed_paths(lab).items()]
            + ["timers: "]}


def test_run_session_refuses_guest_files_that_differ_from_lab(small, tmp_path, monkeypatch):
    from scripts import collection
    p, path, _ = small
    lab = collection.lab_sha256()
    identity = _identity(dict(lab, **{"lab/services.py": "0" * 64}))
    message = _root_run(p, path, tmp_path, monkeypatch, identity, {"qemu_swap_max": "0"})
    assert message == ("deployed guest files differ from lab/ in this commit: "
                       "/opt/hyptcn-lab/services.py")


@pytest.mark.parametrize("value", ["max", None])
def test_run_session_refuses_qemu_swap_that_is_not_forbidden(small, tmp_path, monkeypatch, value):
    from scripts import collection
    p, path, _ = small
    message = _root_run(p, path, tmp_path, monkeypatch, _identity(collection.lab_sha256()),
                        {"vm_swappiness": 1, "qemu_swap_kb": 0, "qemu_swap_max": value})
    assert message == "QEMU swap was not disabled before start: memory.swap.max is " + repr(value)


@pytest.mark.parametrize("value", [8592, None])
def test_run_session_refuses_qemu_memory_that_was_swapped_before_start(small, tmp_path, monkeypatch, value):
    """memory.swap.max 0 is not enough: a QEMU moved into its cgroup late keeps the pages swapped out before (KOSTRA
    B5, addendum 20:50Z); unreadable (None) is not 0 either."""
    from scripts import collection
    p, path, _ = small
    message = _root_run(p, path, tmp_path, monkeypatch, _identity(collection.lab_sha256()),
                        {"vm_swappiness": 1, "qemu_swap_kb": value, "qemu_swap_max": "0"})
    assert message == "QEMU memory was swapped before start: qemu_swap_kb is " + repr(value)


def test_guest_identity_hashes_every_deployed_file(monkeypatch):
    """Every top-level file of lab/ under /opt/hyptcn-lab and the two copies lab/install.sh installs."""
    from scripts import collection
    names = sorted(f.name for f in (ROOT / "lab").iterdir() if f.is_file())
    deployed = ["/opt/hyptcn-lab/" + name for name in names] + ["/etc/nginx/conf.d/hyptcn-lab.conf",
                                                                 "/etc/systemd/system/hyptcn-lab@.service"]
    lab = {"lab/" + name: sha256(ROOT / "lab" / name) for name in names}
    source = {**{"/opt/hyptcn-lab/" + name: "lab/" + name for name in names},
              "/etc/nginx/conf.d/hyptcn-lab.conf": "lab/nginx.conf",
              "/etc/systemd/system/hyptcn-lab@.service": "lab/hyptcn-lab@.service"}
    lines = ["6.1.0-test", "boot", "machine", *(f"{lab[source[path]]}  {path}" for path in deployed),
             "nginx\t1", "postgresql\t15", "python3\t3", "python3-psycopg2\t2", "timers:"]
    commands = []

    def reply(command, **kwargs):
        commands.append(command)
        return "\n".join(reply.lines) + "\n"
    reply.lines = lines
    monkeypatch.setattr(collection.subprocess, "check_output", reply)
    identity = collection.guest_identity({"domain": "hyptcn-test"})
    hashed = commands[0][-1].split("sha256sum ", 1)[1].split(" && ", 1)[0].split()
    assert sorted(hashed) == sorted(deployed)
    assert identity["stack_manifest"] == lines[3:] and identity["boot_id"] == "boot"
    assert collection.lab_sha256() == lab and collection.guest_mismatch(identity, lab) == []
    reply.lines = lines[:3] + lines[4:]  # One hashed file fewer: sha256sum failed, so did the identity.
    with pytest.raises(ValueError, match="cannot establish guest identity"):
        collection.guest_identity({"domain": "hyptcn-test"})


def test_qemu_swap_max_reads_the_cgroup_v2_of_the_process(tmp_path):
    from scripts import collection
    proc, cgroups = tmp_path / "proc", tmp_path / "cgroup"
    (proc / "7").mkdir(parents=True)
    (proc / "7" / "cgroup").write_text("0::/machine.slice/qemu-1.scope\n")
    (cgroups / "machine.slice/qemu-1.scope").mkdir(parents=True)
    (cgroups / "machine.slice/qemu-1.scope/memory.swap.max").write_text("0\n")
    assert collection.qemu_swap_max(7, proc, cgroups) == "0"
    (proc / "7" / "cgroup").write_text("4:memory:/machine.slice/qemu-1.scope\n")  # cgroup v1 only
    assert collection.qemu_swap_max(7, proc, cgroups) is None
    assert collection.qemu_swap_max(8, proc, cgroups) is None  # no such process
    assert collection.host_memory(None)["qemu_swap_max"] is None


# The register of exceptions (features/audit_policy.py) and the protocol sections.

def unregistered(paths):
    """Ids of tolerate() calls that are no string literal (None) or not in TOLERATED."""
    from features import audit_policy
    return sorted(str(name) for _, _, name in audit_policy.sites(paths) if name not in audit_policy.TOLERATED)


def test_every_tolerated_condition_of_the_audit_is_registered(tmp_path):
    from features import audit_policy
    sources = [ROOT / "scripts/collection.py", ROOT / "scripts/collection_logs.py"]
    assert unregistered(sources) == []
    ram = {name for _, _, name in audit_policy.sites(sources[:1])}
    assert ram == {"invalid_rows", "rule_closed_rows", "unconfirmed_findings", "inconclusive_integrity"}
    planted = tmp_path / "planted.py"
    planted.write_text("tolerate(counts, 'new_exception')\npolicy.tolerate(counts, name)\n")
    assert unregistered([*sources, planted]) == ["None", "new_exception"]
    assert {name for _, _, name in audit_policy.sites(sources)} == set(audit_policy.TOLERATED)


# Package B5b (lead's answer to Q2): per id the record says whether the observed count is over the expected one;
# false wherever expected is null, and never a reason.

def test_the_record_of_exceptions_marks_a_count_over_the_expected_one():
    from collections import Counter
    from features import audit_policy
    from scripts import collection
    p = copy.deepcopy(collection.protocol(SELFTEST_PROTOCOL))
    p["exceptions"]["invalid_rows"]["expected"] = 2
    p["exceptions"]["rule_closed_rows"]["expected"] = 0
    counts = Counter(invalid_rows=3, rule_closed_rows=0, collector_warnings=5)
    record = audit_policy.exceptions_record(p, counts)
    assert list(record) == list(audit_policy.TOLERATED)
    assert record["invalid_rows"] == {"observed": 3, "expected": 2, "over": True}
    assert record["rule_closed_rows"] == {"observed": 0, "expected": 0, "over": False}
    assert record["collector_warnings"] == {"observed": 5, "expected": None, "over": False}  # null: never over
    assert audit_policy.exceptions_record(p, Counter(invalid_rows=2))["invalid_rows"]["over"] is False  # equal
    assert audit_policy.exceptions_record({"schema": "hyptcn3/collection-protocol/2"}, counts)["invalid_rows"] == {
        "observed": 3, "expected": None, "over": False}  # no register


def test_a_count_over_the_expected_one_is_printed_and_the_session_still_accepted(small, tmp_path):
    from scripts import collection
    from scripts.tests import audit_cases, boundary_sessions as bs
    p, _, root = small
    doc = copy.deepcopy(p)
    doc["exceptions"]["inconclusive_integrity"]["expected"] = 0  # text_integrity is inconclusive in every row
    path = bs.write_protocol(tmp_path / "protocol.json", doc)
    audit = audit_cases.run_case(tmp_path / "clean", collection.protocol(path), path)
    v = audit.values
    assert (audit.code, v["accepted"], v["reasons"]) == (0, True, [])
    assert v["exceptions"]["inconclusive_integrity"] == {"observed": p["cycles"], "expected": 0, "over": True}
    assert all(e["over"] is False for name, e in v["exceptions"].items() if name != "inconclusive_integrity")


# Since package B4 the loader names a missing section of the v5 layout first; the section's reader keeps its message.
@pytest.mark.parametrize("change, message, reader", [
    (lambda doc: doc.pop("audit"), "missing protocol key: audit", "protocol schema 3 requires the audit section"),
    (lambda doc: doc.pop("exceptions"), "missing protocol key: exceptions",
     "protocol schema 3 requires the exceptions section"),
    (lambda doc: doc["exceptions"].pop("rule_closed_rows"),
     "register of exceptions differs from the exceptions the audit admits",
     "register of exceptions differs from the exceptions the audit admits"),
], ids=["no_audit", "no_exceptions", "register_misses_an_id"])
def test_schema_3_protocol_without_its_sections_is_refused(small, tmp_path, change, message, reader):
    from features import audit_policy
    from scripts import collection
    p, _, _ = small
    doc = copy.deepcopy(p)
    change(doc)
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="^" + message + "$"):
        collection.protocol(path)
    with pytest.raises(ValueError, match="^" + reader + "$"):
        audit_policy.audit_bounds(doc)
        audit_policy.register(doc)


def test_selftest_protocol_carries_the_bounds_of_g0_and_the_whole_register():
    from features import audit_policy
    from scripts import collection
    p = collection.protocol(SELFTEST_PROTOCOL)
    assert (p["schema"], p["interval_s"], p["max_gap_s"], p["window_rows"], p["full_every"], p["cycles"]) == (
        "hyptcn3/collection-protocol/3", 5, 7.5, 32, 360, 720)
    assert {k: v for k, v in p["audit"].items() if k not in ("periodicity", "traffic", "early_stop")} == {
        "lateness_max_s": .5, "cycle_ms_max": {"delta": 1500, "full": 3500}, "warnings_allowed": None,
        "rule_closed_rows_max": None}
    # Package B9b and its fix (Q24): the rule of the early stop, one rate per event type of the file, each null until
    # G3b, and the stop for periodicity of the lead's skeleton B9 (row skoré zastavenie).
    early_stop = p["audit"]["early_stop"]
    assert set(early_stop) == {"marked_rows_rate_per_type", "periodicity_stops", "note"}
    assert early_stop["marked_rows_rate_per_type"] == dict.fromkeys(sorted(p["events"]["types"]))
    assert early_stop["periodicity_stops"] is True
    assert all(text in early_stop["note"] for text in ("judgment", "G3b", "10.9", "7.5"))
    assert (p["audit"]["periodicity"]["equal_spacings"], p["audit"]["periodicity"]["min_spacing_rows"]) == (3, 2)
    assert "judgment" in p["audit"]["periodicity"]["note"]
    # Package B5b: the bounds of proposals 5.3 and 5.7 and the tolerances of the author's judgment, named so.
    traffic = p["audit"]["traffic"]
    assert {k: v for k, v in traffic.items() if k not in ("background", "note")} == {
        "offered_load_tolerance": .2, "arrival_cv": [.8, 1.2], "top_objects_share": .1, "top_objects_min_requests": .5,
        "success_min": .88, "response_size_orders": 2, "think_mean_tolerance_se": 4, "order_share_tolerance_se": 4}
    assert {k: v for k, v in traffic["background"].items() if k != "note"} == {
        "logins_min": 1, "reports_min": 1, "document_max_to_median": 10}
    assert all("judgment" in note for note in (traffic["note"], traffic["background"]["note"]))
    assert list(p["exceptions"]) == list(audit_policy.TOLERATED)
    assert all(e["cause"].strip() and e["decision"].strip() and e["expected"] is None
               for e in p["exceptions"].values())


# Rules of the verdict that no buildable session reaches through the audit (features/acceptance.py).

def _facts(**changes):
    """Facts of a faultless session of the small protocol's shape, sampled on its 1 s grid."""
    facts = {"snapshots": 96, "sequence_contiguous": True, "invalid_rows": [], "integrity_findings": 0,
             "windows": 80, "rule_closed_seq": [], "smallest_gap_s": 1., "largest_gap_s": 1., "span_s": 95.}
    return dict(facts, **changes)


def _open(seq):
    return {"seq": seq, "truncated_traversals": ["processes"], "read_errors": 0, "filled_zero": 0}


@pytest.mark.parametrize("changes, codes", [
    ({}, []),
    # The window buffer refuses rows whose time does not increase before facts exist; decide() still rejects it.
    ({"smallest_gap_s": 0.}, ["timing:gap"]),
    ({"smallest_gap_s": -1.}, ["timing:gap"]),
    ({"largest_gap_s": 1.5}, []),  # max_gap_s itself is no gap
    ({"largest_gap_s": 1.6}, ["timing:gap"]),
    ({"span_s": 96.}, []),  # one interval off is still the grid
    ({"span_s": 96.5}, ["timing:period"]),
    ({"rule_closed_seq": [10, 20]}, []),  # no cap until G3b: recorded only
    ({"rule_closed_seq": [10, 11, 12, 13]}, []),  # adjacent rows are a burst, not periodicity
    ({"rule_closed_seq": [10, 12, 14]}, []),  # two equal spacings
    ({"rule_closed_seq": [10, 12, 14, 16]}, ["periodicity"]),
    ({"invalid_rows": [_open(10), _open(14)], "rule_closed_seq": [12, 16], "windows": 67}, ["periodicity"]),
    ({"rule_closed_seq": [0, 1, 5, 6, 10, 11, 15, 16]}, ["periodicity"]),  # bursts every 5 rows (must_fix 3, B4)
    ({"smallest_gap_s": 0., "span_s": 120., "rule_closed_seq": [10, 12, 14, 16], "sequence_contiguous": False},
     ["sequence", "timing:gap", "timing:period", "periodicity"]),
], ids=["clean", "gap_zero", "gap_negative", "gap_at_max", "gap_above_max", "span_one_off", "span_beyond",
        "rule_closed_without_cap", "burst", "two_spacings", "periodic", "periodic_union", "periodic_bursts", "order"])
def test_timing_and_flagged_rows_rules_of_the_verdict(small, changes, codes):
    from features import acceptance
    p, _, _ = small
    verdict = acceptance.decide(p, "train", _facts(**changes))
    assert verdict["codes"] == codes and verdict["accepted"] is (not codes)


@pytest.mark.parametrize("closed, codes", [([10, 30], []), ([10, 30, 50], ["rule_closed"])], ids=["at_cap", "above"])
def test_cap_of_rule_closed_rows_once_it_is_set(small, closed, codes):
    """Under a protocol with rule_closed_rows_max (G3b): the reason UNREACHABLE names for the self-test protocol."""
    from features import acceptance
    p, _, _ = small
    capped = dict(p, audit=dict(p["audit"], rule_closed_rows_max=2))
    verdict = acceptance.decide(capped, "train", _facts(rule_closed_seq=closed))
    assert verdict["codes"] == codes
    assert verdict["reasons"] == ["rows closed by a parser rule above the cap"] * len(codes)


CAP_REASON = "rows closed by a parser rule above the cap"


@pytest.mark.parametrize("cap", [0, 3, 4, 96], ids=["zero", "three", "four", "every_row"])
def test_the_self_test_builds_the_case_of_the_cap_once_the_cap_is_a_number(small, tmp_path, cap):
    """Finding S1 of B3 (package B10): once G3b sets audit.rule_closed_rows_max to a number, the self-test's list
    (audit_cases.cases) holds the case of cap + 1 rule-closed rows after the RAM cases, the periodicity cases give the
    cap's reason where their rule-closed rows (4 and 2) exceed the cap, UNREACHABLE no longer names it, and
    require_selftest asks a record for that list. With a cap no session of the protocol exceeds (96 of 96 rows) the
    list is that of a null cap and the reason stays unreachable. Under the null cap of G0 nothing changes."""
    from scripts import audit_selftest, collection
    from scripts.tests import audit_cases, boundary_sessions as bs
    p, _, _ = small
    assert (audit_cases.cases(p), audit_cases.unreachable(p)) == (audit_cases.CASES, audit_cases.UNREACHABLE)
    doc = copy.deepcopy(p)
    doc["audit"]["rule_closed_rows_max"] = cap
    path = bs.write_protocol(tmp_path / "protocol.json", doc)
    capped = collection.protocol(path)
    reachable = cap < capped["cycles"]
    listed = audit_cases.cases(capped)
    ids = [case.id for case in listed]
    assert ids == [case.id for case in audit_cases.RAM_CASES] + ["rule_closed_above_cap"] * reachable + [
        case.id for case in audit_cases.LOG_CASES]
    unreachable = audit_cases.unreachable(capped)
    assert (CAP_REASON in unreachable) is not reachable
    assert reachable or unreachable[CAP_REASON] == ("audit.rule_closed_rows_max is 96, and a session of 96 rows cannot "
                                                    "hold more rule-closed rows")
    expected = {"periodicity_rule_closed": ["periodic flagged rows", *[CAP_REASON] * (cap < 4)],
                "periodicity_union": ["periodic flagged rows", *[CAP_REASON] * (cap < 2)],
                "rule_closed_above_cap": [CAP_REASON]}
    for case in (case for case in listed if case.id in expected):
        audit = audit_cases.run_case(tmp_path / "cases", capped, path, case)
        assert (audit.code, audit.values["reasons"]) == (2, sorted(expected[case.id]))
        assert audit_cases.expected(case, capped) == sorted(expected[case.id])
    # require_selftest under the capped protocol: a passed record of the list without the case of the cap is refused
    # while a session can exceed the cap; one of the self-test's list is accepted.
    record = {"schema": audit_selftest.SCHEMA, "date": "2026-11-24T00:00:00+00:00", "passed": True,
              "protocol_sha256": sha256(path), "measurement_sha256": audit_selftest.measurement_sha256(),
              "cases_sha256": audit_selftest.cases_sha256()}
    for name, cases in (("without_the_cap", audit_cases.CASES), ("self_test", listed)):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "audit_selftest_a.json").write_text(json.dumps(dict(record, cases=[{"id": c.id} for c in cases])))
        if name == "without_the_cap" and reachable:
            with pytest.raises(ValueError, match="^" + REFUSED + "$"):
                audit_selftest.require_selftest(path, directory)
        else:
            assert audit_selftest.require_selftest(path, directory)["cases"] == [{"id": c.id} for c in cases]


@pytest.mark.parametrize("seqs, spacing, run", [
    ([], 2, (0, None)), ([5], 2, (0, None)), ([5, 6, 7, 8, 9], 2, (0, None)), ([5, 7, 9, 11], 2, (3, 2)),
    ([5, 7, 9, 11], 3, (0, None)), ([11, 5, 9, 7, 7], 2, (3, 2)),
    ([0, 5, 10, 11, 16, 21, 26], 2, (2, 5)),  # the burst 10, 11 starts at 10: spacings 5, 5, 6, 5, 5
    ([0, 4, 8, 20, 32], 2, (2, 4)),
    # The lead's cases (must_fix 3 on B3): two rows every five, and four of five on 20 rows.
    ([0, 1, 5, 6, 10, 11, 15, 16], 2, (3, 5)), ([seq for seq in range(20) if seq % 5 != 4], 2, (3, 5)),
], ids=["none", "one", "burst", "run", "below_min_spacing", "any_order", "spacing_from_burst_start",
        "first_of_equal_runs", "two_every_five", "four_of_five"])
def test_periodic_run_is_the_longest_run_of_one_spacing_between_burst_starts(seqs, spacing, run):
    from features import acceptance
    assert acceptance.periodic_run(seqs, spacing) == run


# Rule-closed rows in bursts of two whose starts are 5, 5, 6, 5, 5, 6 rows apart: a resonance that scatters.
RESONANCE = [10, 11, 15, 16, 20, 21, 26, 27, 31, 32, 36, 37, 42, 43]


@pytest.mark.parametrize("seqs, mode", [
    ([], {"spacing": None, "count": 0, "spacings": 0}), ([3, 4, 5], {"spacing": None, "count": 0, "spacings": 0}),
    (RESONANCE, {"spacing": 5, "count": 4, "spacings": 6}),
    ([0, 4, 8, 14, 20], {"spacing": 4, "count": 2, "spacings": 4}),
], ids=["none", "one_burst", "scattered_resonance", "tie_takes_the_smaller"])
def test_spacing_mode_is_the_most_frequent_spacing_between_burst_starts(seqs, mode):
    from features import acceptance
    assert acceptance.spacing_mode(seqs) == mode


def test_spacing_mode_is_recorded_and_never_a_reason(small):
    """The scattered resonance as rule-closed rows: no three equal spacings in a row, so the session is accepted;
    the record says spacing 5 four times in six (lead's remarks on B3, part 2)."""
    from scripts.tests import audit_cases, boundary_sessions as bs
    from scripts.tests.audit_case import Case
    p, path, root = small
    case = Case("resonance", "rule-closed rows of a scattered resonance", [],
                audit_cases._rows_quality(lambda p: {seq: bs.rule_closed_row() for seq in RESONANCE}))
    audit = audit_cases.run_case(root / "resonance", p, path, case)
    assert (audit.code, audit.values["accepted"], audit.values["reasons"]) == (0, True, [])
    assert audit.values["timing"]["spacing_mode"] == {"spacing": 5, "count": 4, "spacings": 6}
    assert audit.values["timing"]["periodic_run"]["equal_spacings"] == 2
    assert audit.values["exceptions"]["rule_closed_rows"]["observed"] == len(RESONANCE)


def test_the_counts_the_audit_only_records_are_those_of_a_session_that_has_them(small):
    """Findings S3 and S4 of B3 (package B10; mutants m16, m17, m18 and m29): four rule-closed rows of the walks prev,
    tail, meet and prev at the spacing of the pattern, a row whose backward walk closed over other tasks and two rows
    with tasks skipped. The session is refused for the pattern alone; the record counts the four rows as rule-closed,
    in the register's exception and in the facts, lists the row of the backward walk, sums the skipped tasks and
    states the run of three equal spacings of 2 rows (none of these is a reason)."""
    from scripts.tests import audit_cases, boundary_sessions as bs
    from scripts.tests.audit_case import Case
    p, path, root = small
    pattern = audit_cases._periodic("rtmr")(p)
    assert {seq: q["process_walk"] for seq, q in pattern.items()} == {9: "prev", 11: "tail", 13: "meet", 15: "prev"}
    quality = {**pattern, 40: dict(bs.complete_row(), process_walk_backward={"closed": True, "agrees": False}),
               50: dict(bs.complete_row(), skipped_tasks={"sockets": 2, "memory_patterns": 0}),
               60: dict(bs.complete_row(), skipped_tasks={"sockets": 1, "memory_patterns": 3})}
    case = Case("recorded_counts", "counts the audit records and never judges", ["periodic flagged rows"],
                audit_cases._rows_quality(lambda p: quality))
    v = audit_cases.run_case(root / "recorded", p, path, case).values
    assert (v["accepted"], v["reasons"]) == (False, ["periodic flagged rows"])
    assert (v["exceptions"]["rule_closed_rows"]["observed"], v["acceptance"]["facts"]["rule_closed_seq"]) == (
        4, [9, 11, 13, 15])
    assert (v["quality"]["process_walk_backward_disagrees_seq"], v["quality"]["skipped_tasks"]) == (
        [40], {"sockets": 3, "memory_patterns": 3})
    assert v["timing"]["periodic_run"] == {"equal_spacings": 3, "spacing": 2, "min_spacing_rows": 2,
                                           "flagged_rows": 4}


def test_the_rate_of_the_generator_is_judged_against_the_protocol_once_the_protocol_has_one(small, tmp_path):
    """F4 of the B5b verification (package B10, mutant M36): from G2 every corpus session runs at the rate of its
    scenario in the protocol (scenarios.*.rate, null until G2). Under a copy of the small protocol with a rate for
    every scenario (1 user session a second, a number of this test only) the clean session's generator states that
    rate with the source protocol and is accepted, and the self-test's case that gives the header the other source
    is refused with traffic_config:rate, as it is under a null rate."""
    from scripts import collection
    from scripts.tests import audit_cases, boundary_sessions as bs
    p, _, _ = small
    doc = copy.deepcopy(p)
    for scenario in doc["scenarios"].values():
        scenario["rate"] = 1.
    path = bs.write_protocol(tmp_path / "protocol.json", doc)
    rated = collection.protocol(path)
    clean = audit_cases.run_case(tmp_path / "cases", rated, path)
    assert (clean.code, clean.values["reasons"]) == (0, [])
    header = json.loads((Path(clean.values["session_dir"]) / "traffic_requests.jsonl").read_text().splitlines()[0])
    assert (header["rate_source"], header["rate"]) == ("protocol", 1.)
    case = case_of("logs:traffic_config:rate")
    audit = audit_cases.run_case(tmp_path / "cases", rated, path, case)
    assert (audit.code, audit.values["reasons"]) == (2, ["logs: traffic_config:rate"])


def test_the_audit_records_the_summary_of_every_column_and_never_a_reason(small, recorded):
    """Design B6a 1.5 and its test 3: the clean session with the known matrix of audit_cases.py is accepted with no
    reason and the exceptions of the clean session, and values.columns holds the summary audit_cases.py writes for
    the grid (96 cycles, full snapshots at seq 0 and 64: 94 measured rows); column proc_user (pattern 1: 5 in the
    fourth measured row, else 0) by hand. The record of the self-test holds the case, passed."""
    import math
    from scripts.tests import audit_cases, boundary_sessions as bs
    p, path, root = small
    session = audit_cases.clean_session(root / "summary", p, path, audit_cases.SESSION)
    audit = bs.audit(session, p, result=audit_cases.known_matrix(session.result))
    v = audit.values
    assert (audit.code, v["accepted"], v["reasons"]) == (0, True, [])
    assert v["exceptions"] == audit_cases.run_case(root / "summary-clean", p, path).values["exceptions"]
    assert audit_cases._same(v["columns"], audit_cases.expected_summary(p))
    assert v["columns"]["proc_user"] == pytest.approx({
        "rows": 94, "min": 0, "max": 5, "mean": 5 / 94, "std": 5 * math.sqrt(93) / 94, "mode": 0,
        "off_mode_share": 1 / 94, "diff_std": math.sqrt(50 / 93)}, rel=1e-12)
    assert "never a reason" in v["columns_note"]
    summary = recorded.doc["summary"]
    assert (recorded.code, summary["id"], summary["code"], summary["passed"]) == (0, "column_summary", 0, True)
