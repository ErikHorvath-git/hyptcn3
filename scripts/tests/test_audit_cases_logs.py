"""The log audit's part of the audit self-test (protocol v5, package B3).

The cases of scripts/tests/audit_cases_logs.py run with the rest of CASES in scripts/tests/test_audit_selftest.py.
Here the clean session of the self-test must pass with every exception of the log audit counted, and every problem
key of scripts/collection_logs.py must have a case or a reason why no session reaches it. Names package B3 adds are
imported inside the tests, so the file also runs on the code before B3 and fails there test by test (the case
module itself reads only names older than B3).
"""
import pytest

from scripts import collection
from scripts.tests import boundary_sessions as bs
from scripts.tests.audit_cases_logs import LOG_CASES


def _run(root, p, protocol_path, case=None):
    """Audit of the clean session of the self-test after case.mutate (the clean session itself without a case)."""
    from scripts.tests.audit_cases import run_case
    return run_case(root, p, protocol_path, case)


@pytest.fixture(scope="module")
def protocol(tmp_path_factory):
    root = tmp_path_factory.mktemp("protocol")
    path = bs.write_protocol(root / "protocol.json", bs.family("S3", bs.profile_dir(root / "profile")))
    return collection.protocol(path), path


def test_clean_session_passes_and_counts_every_exception_of_the_log_audit(protocol, tmp_path):
    """The clean session's event admits each condition of an event once, the failed order and the two requests
    inside its window included; no collector warning."""
    p, path = protocol
    audit = _run(tmp_path, p, path)
    assert (audit.code, audit.values["reasons"]) == (0, [])
    assert audit.values["logs"]["tolerated"] == {
        "collector_warnings": 0, "event_traffic_exit": 1, "event_unit_restarts": 1, "event_window_requests": 2,
        "event_window_health_checks": 1, "event_window_journal": 1, "event_window_nginx_errors": 1}
    assert audit.values["logs"]["sections"]["audit_bounds"] == p["audit"]


def test_cases_cover_every_problem_key_of_the_log_audit():
    """Each problem key scripts/collection_logs.py can give has a case or a reason why no session reaches it."""
    import ast
    from scripts import collection_logs
    from scripts.tests.audit_cases_logs import UNREACHABLE
    tree = ast.parse(open(collection_logs.__file__).read())
    keys = {node.args[1].value for node in ast.walk(tree) if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "check" and isinstance(node.args[1], ast.Constant)}
    keys |= {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
             and getattr(node.func, "attr", None) == "add" and node.args and isinstance(node.args[0], ast.Constant)}
    keys |= {node.args[0].value + ":unreadable" for node in ast.walk(tree) if isinstance(node, ast.Call)
             and getattr(node.func, "id", None) == "section" and isinstance(node.args[0], ast.Constant)}
    assert len(keys) > 70  # The parse found the audit's keys, not a handful.
    covered = {case.check for case in LOG_CASES}
    assert keys == covered | set(UNREACHABLE), (keys - covered - set(UNREACHABLE), covered - keys)
    assert len({case.id for case in LOG_CASES}) == len(LOG_CASES)
    assert all(case.expected == sorted(set(case.expected)) for case in LOG_CASES if not callable(case.expected))
