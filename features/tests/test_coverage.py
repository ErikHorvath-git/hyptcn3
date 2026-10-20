from dataclasses import replace

import numpy as np
import pytest

from features.coverage import scorable_windows
from features.snapshot import MENA, SCHEMA
from safeguard.features import WindowBuffer
from safeguard.tests.test_features import sample


def data(frames):
    return {"schema": SCHEMA, "mena": MENA, "quality_policy": "behavioral-inputs-v1",
            "matica": [f.vector for f in frames], "quality": [f.quality for f in frames],
            "valid": [f.valid for f in frames], "seq": [f.seq for f in frames],
            "casy": [f.timestamp for f in frames], "perbin": [f.perbin for f in frames],
            "biny": frames[0].biny, "layout": frames[0].layout,
            "chain_ids": [f.chain_id for f in frames]}


P = {"window_rows": 3, "interval_s": 5, "full_every": 10, "max_gap_s": 7.5, "stride": 1,
     "min_score_coverage": .85}


def test_explains_full_rotation_and_invalid_input_recovery_without_double_counting():
    frames = [sample(i) for i in range(20)]
    frames[0] = sample(0, full=True, predecessor=False)
    frames[6] = sample(6, valid=False)
    frames[7] = sample(7, predecessor=False)
    frames[10] = sample(10, full=True)
    frames[10:] = [replace(f, chain_id="b") for f in frames[10:]]
    windows, report = scorable_windows(data(frames), P, "synthetic", 20)
    assert [m["seq_do"] for m in windows.meta] == [3, 4, 5, 13, 14, 15, 16, 17, 18, 19]
    assert report["ideal_windows"] == 14
    assert report["lost_windows_vs_ideal"] == 4
    assert report["score_coverage"] == .5
    assert report["unscored_rows_by_cause"] == {"full_snapshot": 6, "invalid_input": 4}
    assert sum(report["state_rows"].values()) == 20
    assert report["nominal_scored_s"] + report["nominal_unscored_s"] == 100


def test_missing_slots_and_partial_run_keep_assigned_denominator():
    frames = [sample(i) for i in [0, 1, 2, 4, 5, 6]]
    windows, report = scorable_windows(data(frames), P, "synthetic", 10)
    assert [m["seq_do"] for m in windows.meta] == [2, 6]
    assert report["missing_snapshots"] == 4
    assert report["score_coverage"] == 2 / 10
    assert report["observed_score_coverage"] == 2 / 6
    assert "sequence_gap" in report["barriers"][0]["causes"]


def test_chain_and_time_gap_match_live_buffer_with_unchanged_feature_values():
    frames = [sample(i, timestamp=i * 5. + (8 if i >= 5 else 0)) for i in range(15)]
    frames[10:] = [replace(f, chain_id="b") for f in frames[10:]]
    buffer = WindowBuffer(3, 7.5)
    reference = [window for f in frames if (window := buffer.push(f)) is not None]
    windows, report = scorable_windows(data(frames), P, "synthetic", 15)
    np.testing.assert_array_equal(windows.X, [[f.vector for f in w] for w in reference])
    assert report["unscored_rows_by_cause"] == {"startup": 2, "timestamp_gap": 2, "chain_change": 2}


@pytest.mark.parametrize("field", ["perbin", "quality", "casy"])
def test_invalid_features_cannot_claim_coverage(field):
    d = data([sample(i) for i in range(5)])
    if field == "perbin":
        d[field][2] = np.full((2, 4), np.nan)
    elif field == "quality":
        d[field][2] = {}
    else:
        d[field][2] = d[field][1]
    with pytest.raises(ValueError):
        scorable_windows(d, P, "synthetic", 5)


def test_diagnostic_400_slots_cannot_reach_85_percent_even_with_perfect_rows():
    frames = [sample(i, full=i % 360 == 0, predecessor=i != 0) for i in range(400)]
    windows, report = scorable_windows(data(frames), dict(P, window_rows=32, full_every=360), "synthetic", 400)
    assert len(windows) == report["ideal_windows"] == 336
    assert report["score_coverage"] == .84
