"""Protocol schema 3: the acceptance rule must be reachable (the v4 rule was not)."""
import json
from pathlib import Path

import pytest

from features.coverage import ideal_windows, scorable_windows
from features.tests.test_coverage import data
from safeguard.tests.test_features import sample
from scripts import collection

ROOT = Path(__file__).resolve().parents[2]
V4 = ROOT / "config/collection-v4.json"


def schema3(tmp_path, **changes):
    """The v4 protocol under schema 3; no v5 protocol file exists until the proposal is approved."""
    doc = json.loads(V4.read_text())
    doc.update(schema="hyptcn3/collection-protocol/3", **changes)
    path = tmp_path / "p.json"
    path.write_text(json.dumps(doc))
    return path


def session(p, invalid=()):
    """A full session as the audit sees it: a full snapshot opens every chain, `invalid` rows did not close."""
    frames = []
    for seq in range(p["cycles"]):
        full = seq % p["full_every"] == 0
        previous_usable = seq > 0 and seq - 1 not in invalid
        frame = sample(seq, full=full, predecessor=previous_usable, valid=seq not in invalid)
        frames.append(frame.__class__(**{**frame.__dict__, "chain_id": f"chain-{seq // p['full_every']}"}))
    return scorable_windows(data(frames), p, "synthetic", p["cycles"])[1]


def test_an_isolated_invalid_row_costs_what_the_loader_assumes():
    p = collection.protocol(V4)
    ideal = ideal_windows(p["cycles"], p["window_rows"], p["full_every"])
    assert session(p)["scorable_windows"] == ideal == 656
    assert session(p, {100})["scorable_windows"] == ideal - (p["window_rows"] + 1)
    assert session(p, {100, 250, 500})["scorable_windows"] == ideal - 3 * (p["window_rows"] + 1)


def test_v4_allowed_three_invalid_rows_and_its_gate_admitted_one():
    p = collection.protocol(V4)
    assert p["invalid_rows"]["max"] == 3 and p["schema"].endswith("/2")  # the frozen file still loads as it is
    assert session(p, {100})["score_coverage"] >= p["min_score_coverage"]
    assert session(p, {100, 250})["score_coverage"] < p["min_score_coverage"]


def test_schema_3_refuses_a_rule_the_gate_cannot_admit(tmp_path):
    with pytest.raises(ValueError, match="invalid_rows.max is unreachable"):
        collection.protocol(schema3(tmp_path))
    one = json.loads(V4.read_text())["invalid_rows"] | {"max": 1}  # what the v4 gate really admitted
    assert collection.protocol(schema3(tmp_path, invalid_rows=one))["invalid_rows"]["max"] == 1
    p = collection.protocol(schema3(tmp_path, min_score_coverage=.77))
    assert session(p, {100, 250, 500})["score_coverage"] >= p["min_score_coverage"]
    assert session(p, {100, 250, 400, 550})["score_coverage"] < p["min_score_coverage"]


def test_schema_3_keeps_the_plan(tmp_path):
    a, b = collection.protocol(V4), collection.protocol(schema3(tmp_path, min_score_coverage=.77))
    assert collection.plan(a) == collection.plan(b)
