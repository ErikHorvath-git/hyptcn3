import json
from types import SimpleNamespace

import pytest

from scripts.collection import DEFAULT, plan, protocol, run_session, analyze_windows


def test_plan_balances_scenarios_and_assigns_whole_groups():
    p = protocol(DEFAULT)
    result = plan(p)
    assert result["planned_hours"] == 48
    assert len(result["sessions"]) == 48
    groups = {}
    for s in result["sessions"]:
        assert groups.setdefault(s["group"], s["role"]) == s["role"]
    assert len({s["seed"] for s in result["sessions"]}) == 48
    for role, count in p["roles"].items():
        for scenario in p["scenarios"]:
            assert sum(s["role"] == role and s["scenario"] == scenario for s in result["sessions"]) == count
    assert plan(p) == result


def test_protocol_rejects_pilot_without_rotation(tmp_path):
    p = protocol(DEFAULT)
    p["pilot_cycles"] = 24
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError, match="two full"):
        protocol(path)


def test_unprivileged_run_fails_before_mutating(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="sudo"):
        run_session(SimpleNamespace(), protocol(DEFAULT))


def test_v1_cannot_silently_change_input_policy(tmp_path):
    p = protocol(DEFAULT)
    p["schema"] = "hyptcn3/collection-protocol/1"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError, match="version 2"):
        protocol(path)


@pytest.mark.parametrize("primary_complete", [True, False])
@pytest.mark.parametrize("integrity_finding", [False, True])
def test_pilot_gate_distinguishes_input_loss_from_integrity_gap(primary_complete, integrity_finding):
    from features.snapshot import MENA
    p = protocol(DEFAULT)
    matrix = [[0.] * len(MENA) for _ in range(p["pilot_cycles"])]
    quality = [{"model_valid": True, "behavior_valid": True, "inconclusive": [], "findings": []}
               for _ in matrix]
    for i, row in enumerate(matrix):
        row[-2:] = [i != 0, i % p["full_every"] == 0]
    for i in (81, 331):
        quality[i].update(model_valid=False, behavior_valid=primary_complete,
                          inconclusive=["process_cross_view"])
        if not primary_complete:
            matrix[i + 1][-2] = 0
    if integrity_finding:
        quality[7]["findings"] = [{"check": "synthetic-hook"}]
    result = {"matica": matrix, "seq": list(range(len(matrix))),
              "casy": [float(i * p["interval_s"]) for i in range(len(matrix))],
              "quality": quality, "valid": [q["behavior_valid"] for q in quality],
              "quality_policy": p["quality_policy"]}
    _, windows, coverage, reasons, report = analyze_windows(result, p, "synthetic-pilot")
    assert not reasons if primary_complete and not integrity_finding else reasons
    assert (coverage >= p["min_score_coverage"]) is primary_complete
    assert report["integrity_inconclusive_rows"]["process_cross_view"] == 2
    assert report["legacy_valid_rows"] == len(matrix) - 2
    assert report["integrity_finding_rows"] == int(integrity_finding)
    assert len(windows) == (416 if primary_complete else 354)


def test_interrupts_raise_once_and_record_every_signal():
    import os
    import signal
    from scripts.collection import Interrupts
    interrupts = Interrupts()
    try:
        with pytest.raises(InterruptedError):
            os.kill(os.getpid(), signal.SIGTERM)
            for _ in range(100):
                pass  # The handler runs between bytecodes.
        os.kill(os.getpid(), signal.SIGTERM)  # Second signal during cleanup must not raise.
        os.kill(os.getpid(), signal.SIGHUP)
        for _ in range(100):
            pass
        assert [r["signal"] for r in interrupts.received] == [signal.SIGTERM, signal.SIGTERM, signal.SIGHUP]
    finally:
        interrupts.restore()


def test_hangup_interrupts_like_sigterm():
    import os
    import signal
    from scripts.collection import Interrupts
    interrupts = Interrupts()
    try:
        with pytest.raises(InterruptedError, match="signal 1"):
            os.kill(os.getpid(), signal.SIGHUP)
            for _ in range(100):
                pass
    finally:
        interrupts.restore()
