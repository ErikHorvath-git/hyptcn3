import json
from types import SimpleNamespace

import pytest

from scripts.collection import DEFAULT, plan, protocol, run_session


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
