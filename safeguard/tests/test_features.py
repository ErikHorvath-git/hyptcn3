from copy import deepcopy
from dataclasses import replace
import json

import numpy as np
import pytest

from features import archive
from features.snapshot import MENA
from features.windows import okna, snimky_z_matice
from safeguard import features
from safeguard.features import (Frame, FeatureNormalizer, WindowBuffer, arrays,
                                check_frame, feature_contract, frames_from_archive)


def sample(seq=0, *, session="synthetic", full=False, predecessor=True,
           valid=True, timestamp=None, perbin=None):
    vector = np.zeros(len(MENA))
    vector[:18] = np.arange(18) + seq
    vector[-2:] = [predecessor, full]
    return Frame(session, seq, seq * 5. if timestamp is None else timestamp,
                 vector,
                 [[.5, .5, 2., 1.], [0., 1., 0., 0.]] if perbin is None else perbin,
                 (0, 1),
                 {"model_valid": valid, "behavior_valid": valid, "traversals_complete": valid,
                  "inconclusive": ["text_integrity"], "findings": [],
                  "read_errors": 0, "filled_zero": 0}, "chain-a",
                 {"bin_bytes": 8192, "page_size": 4096, "bins": [[0, 2], [1, 2]],
                  "regions": [{"gpa": 0, "bytes": 16384}], "memsize": 16384, "vcpus": 2})


def test_window_stream_matches_existing_offline_rules_at_all_barriers():
    frames = [sample(i) for i in range(30)]
    frames[0] = sample(0, full=True, predecessor=False)
    frames[8] = sample(8, full=True)
    frames[14] = sample(14, valid=False)
    frames[15] = sample(15, predecessor=False)
    for i in range(20, 30):
        frames[i] = sample(i + 1, timestamp=(i + 1) * 5. + (10 if i >= 25 else 0))
    matrix = np.stack([f.vector for f in frames])
    old_rows = snimky_z_matice("synthetic", matrix, MENA,
                              [f.timestamp for f in frames], [f.seq for f in frames],
                              [f.valid for f in frames])
    reference = okna(old_rows, dlzka=3, max_medzera_s=7.5)
    buffer = WindowBuffer(3, 7.5)
    actual, ends = [], []
    for frame in frames:
        window = buffer.push(frame)
        if window is not None:
            global_values, local_values = arrays(window)
            actual.append(global_values)
            ends.append(window[-1].seq)
            np.testing.assert_array_equal(local_values, np.stack([f.perbin for f in window]))
    np.testing.assert_array_equal(actual, reference.X[..., :18])
    assert ends == [m["seq_do"] for m in reference.meta]


def test_session_boundary_and_invalid_rows_reset_evidence_window():
    buffer = WindowBuffer(2)
    buffer.push(sample(1))
    assert buffer.push(sample(2)) is not None
    assert buffer.push(sample(0, session="new")) is None
    assert buffer.reset
    assert buffer.push(sample(1, session="new", valid=False)) is None
    assert buffer.reset and buffer.reason == "invalid_input"
    assert not buffer.rows
    buffer.push(sample(2, session="new"))
    assert buffer.push(sample(3, session="new")) is not None


def test_chain_boundary_resets_window_even_if_full_row_was_not_supplied():
    buffer = WindowBuffer(2)
    buffer.push(sample(1))
    assert buffer.push(sample(2)) is not None
    assert buffer.push(replace(sample(3), chain_id="chain-b")) is None
    assert buffer.reset
    window = buffer.push(replace(sample(4), chain_id="chain-b"))
    assert [row.seq for row in window] == [3, 4]


@pytest.mark.parametrize("corruption", ["duplicate", "time", "layout"])
def test_window_rejects_and_clears_incompatible_continuation(corruption):
    buffer = WindowBuffer(2)
    buffer.push(sample(1))
    next_frame = sample(2)
    if corruption == "duplicate":
        next_frame = sample(1)
    elif corruption == "time":
        next_frame = sample(2, timestamp=4.)
    else:
        layout = deepcopy(next_frame.layout)
        layout["vcpus"] = 4
        next_frame = replace(next_frame, layout=layout)
    with pytest.raises(ValueError):
        buffer.push(next_frame)
    assert buffer.reset and not buffer.rows


@pytest.mark.parametrize("corruption", ["quality", "valid_lie", "mask", "missing_entropy", "ratio",
                                       "nan", "geometry", "identity", "flags", "sequence"])
def test_frame_rejects_missing_or_malformed_contract(corruption):
    frame = sample()
    kwargs = {name: deepcopy(getattr(frame, name)) for name in frame.__dataclass_fields__}
    if corruption == "quality":
        kwargs["quality"].pop("read_errors")
    elif corruption == "valid_lie":
        kwargs["quality"]["read_errors"] = 1
    elif corruption == "mask":
        kwargs["perbin"][0, 3] = .5
    elif corruption == "missing_entropy":
        kwargs["perbin"][1, 2] = 1
    elif corruption == "ratio":
        kwargs["perbin"][1, 0] = .5
    elif corruption == "nan":
        kwargs["vector"][0] = np.nan
    elif corruption == "geometry":
        kwargs["layout"]["regions"][0]["bytes"] += 4096
    elif corruption == "identity":
        kwargs["biny"] = (0, 2)
    elif corruption == "flags":
        kwargs["vector"][-1] = .5
    else:
        kwargs["seq"] = 1.2
    with pytest.raises(ValueError):
        Frame(**kwargs)


def test_normalization_pools_only_observed_entropy_and_preserves_masks():
    first = sample(1)
    second = sample(2, perbin=[[.5, .5, 6., 1.], [1., 0., 0., 1.]])
    normalizer = FeatureNormalizer.fit([first, second])
    assert normalizer.fit_rows == 2
    assert normalizer.entropy_observations == 3
    assert normalizer.local_mean[2] == pytest.approx(8. / 3.)
    assert normalizer.local_scale[2] == pytest.approx(np.std([2., 6., 0.]))
    global_values, local_values = arrays([first, second])
    norm_global, norm_local = normalizer.transform(global_values, local_values)
    np.testing.assert_array_equal(norm_local[..., 3], local_values[..., 3])
    assert norm_local[0, 1, 2] == 0.  # Unobserved zero remains the missing marker.
    assert norm_local[1, 1, 2] < 0.   # Observed entropy zero is a genuine measurement.
    np.testing.assert_allclose(norm_global.mean(axis=0), 0)
    restored = FeatureNormalizer.from_dict(json.loads(json.dumps(normalizer.to_dict())))
    again = restored.transform(global_values, local_values)
    np.testing.assert_array_equal(again[0], norm_global)
    np.testing.assert_array_equal(again[1], norm_local)


def test_constant_or_entirely_unobserved_training_channels_are_finite():
    frame = sample(1, perbin=[[0., 1., 0., 0.], [0., 1., 0., 0.]])
    normalizer = FeatureNormalizer.fit([frame])
    assert normalizer.entropy_observations == 0
    assert normalizer.local_mean[2] == 0 and normalizer.local_scale[2] == 1
    global_values, local_values = arrays([frame])
    a, b = normalizer.transform(global_values[None], local_values[None])
    assert a.shape == (1, 1, 18) and b.shape == (1, 1, 2, 4)
    assert np.isfinite(a).all() and np.isfinite(b).all()


def test_normalizer_cannot_fit_repeated_windows_or_ineligible_rows():
    with pytest.raises(ValueError, match="duplicate"):
        FeatureNormalizer.fit([sample(1), sample(1)])
    for frame in (sample(1, full=True), sample(1, valid=False), sample(1, predecessor=False)):
        with pytest.raises(ValueError, match="eligible"):
            FeatureNormalizer.fit([frame])
    manifest = FeatureNormalizer.fit([sample(1)]).to_dict()
    manifest["local_scale"][3] = 2
    with pytest.raises(ValueError, match="mask"):
        FeatureNormalizer.from_dict(manifest)


def test_behavior_arrays_exclude_integrity_and_acquisition_flags():
    first = sample(1)
    vector = first.vector.copy()
    vector[18:] = [999, 999, 0, 1]
    second = replace(first, vector=vector)
    a, _ = arrays([first, second])
    np.testing.assert_array_equal(a[0], a[1])
    assert a.shape[-1] == 18


def test_saved_contract_rejects_feature_order_bin_geometry_and_temporal_corruption():
    frame = sample()
    contract = feature_contract(frame, 4, 7.5)
    check_frame(frame, json.loads(json.dumps(contract)))
    for key, value in (("global_names", list(reversed(contract["global_names"]))),
                       ("biny", [0, 2]), ("window_rows", 0), ("max_gap_s", float("nan"))):
        corrupt = deepcopy(contract)
        corrupt[key] = value
        with pytest.raises(ValueError):
            check_frame(frame, corrupt)


def test_archive_roundtrip_preserves_frames_and_requires_quality(tmp_path):
    frames = [sample(i, full=i == 0, predecessor=i != 0) for i in range(5)]
    result = {"matica": [f.vector for f in frames], "seq": [f.seq for f in frames],
              "casy": [f.timestamp for f in frames], "valid": [f.valid for f in frames],
              "perbin": [f.perbin for f in frames], "biny": frames[0].biny,
              "chain_ids": [f.chain_id for f in frames], "snimky": [str(f.seq) for f in frames],
              "trvanie_s": [0.] * len(frames), "poznamky": [[]] * len(frames),
              "quality": [f.quality for f in frames], "layout": frames[0].layout,
              "max_medzera_s": 7.5, "quality_policy": "behavioral-inputs-v1"}
    imported = archive.load(archive.save(tmp_path / "features.npz", result))
    restored = frames_from_archive(imported, "synthetic")
    for before, after in zip(frames, restored):
        assert before.seq == after.seq and before.timestamp == after.timestamp
        assert before.quality == after.quality and before.layout == after.layout
        np.testing.assert_array_equal(before.vector, after.vector)
        np.testing.assert_array_equal(before.perbin, after.perbin)
    imported["quality_json"] = json.dumps([{"model_valid": True}] * len(frames))
    with pytest.raises(ValueError, match="quality"):
        frames_from_archive(imported, "synthetic")


@pytest.mark.parametrize("cross_view_complete", [True, False])
def test_live_extraction_resets_predecessor_on_gap_and_preserves_checks(monkeypatch, tmp_path, cross_view_complete):
    calls, keys = [], []
    frame = sample(1)
    def extract(raw, profile, seq, previous, predch_krizove=None):
        calls.append(previous)
        keys.append(predch_krizove)
        row = sample(seq, predecessor=previous is not None)
        state = {"pids": {1, 2}, "mod_total": 1, "quality": deepcopy(row.quality),
                 "layout": row.layout, "krizove_kluce": frozenset({f"k{seq}"})}
        if not cross_view_complete:
            state["quality"]["model_valid"] = False
            state["quality"]["inconclusive"].append("process_cross_view")
        return row.vector, state, ["synthetic extraction"]
    heads = [{"seq": seq, "full": False, "chain_id": "chain-a", "path": str(tmp_path / f"{seq}.vmicd")}
             for seq in (1, 2, 4)]
    for head in heads:
        side = {"schema": "vmicollect/1", "seq": head["seq"], "timestamp_unix": head["seq"] * 5.,
                "vm": {"memsize": 16384, "num_vcpus": 2},
                "stats": {"read_errors": 0, "filled_zero": 0},
                "output": {"full": False, "chain_id": "chain-a", "pages_total": 4,
                           "pages_changed": 1, "page_size": 4096},
                "features": {"schema": "hyptcn3/perbin/1", "entropy": True,
                             "bin_bytes": 8192, "page_size": 4096, "bins_total": 2,
                             "regions": frame.layout["regions"], "bins": [
                                 {"bin": 0, "gpa": 0, "pages_total": 2, "pages_changed": 1,
                                  "changed_ratio": .5, "zero_ratio": .5, "entropy_mean": 2., "has_changed": 1},
                                 {"bin": 1, "gpa": 8192, "pages_total": 2, "pages_changed": 0,
                                  "changed_ratio": 0., "zero_ratio": 1., "entropy_mean": 0., "has_changed": 0}]}}
        (tmp_path / f"{head['seq']}.json").write_text(json.dumps(side))
    monkeypatch.setattr(features, "_vsetky_hlavicky", lambda _: heads)
    monkeypatch.setattr(features, "vektor_snimky", extract)
    one, state = features.frame_from_snapshot(tmp_path, "unused", 1)
    two, state = features.frame_from_snapshot(tmp_path, "unused", 2, state)
    four, state = features.frame_from_snapshot(tmp_path, "unused", 4, state)
    assert calls[0] is None and calls[1] is not None and calls[2] is None
    assert keys == [None, frozenset({"k1"}), None]
    assert not one.has_predecessor and two.has_predecessor and not four.has_predecessor
    assert four.quality["process_ids"] == [1, 2]
    assert four.quality["inconclusive"] == (["text_integrity"] if cross_view_complete
                                           else ["text_integrity", "process_cross_view"])
    with pytest.raises(ValueError, match="non-increasing"):
        features.frame_from_snapshot(tmp_path, "unused", 4, state)


def _live_sidecars(tmp_path, seqs):
    layout = sample(1).layout
    heads = [{"seq": seq, "full": False, "chain_id": "chain-a", "path": str(tmp_path / f"{seq}.vmicd")}
             for seq in seqs]
    for head in heads:
        side = {"schema": "vmicollect/1", "seq": head["seq"], "timestamp_unix": head["seq"] * 5.,
                "vm": {"memsize": 16384, "num_vcpus": 2},
                "stats": {"read_errors": 0, "filled_zero": 0},
                "output": {"full": False, "chain_id": "chain-a", "pages_total": 4,
                           "pages_changed": 1, "page_size": 4096},
                "features": {"schema": "hyptcn3/perbin/1", "entropy": True,
                             "bin_bytes": 8192, "page_size": 4096, "bins_total": 2,
                             "regions": layout["regions"], "bins": [
                                 {"bin": 0, "gpa": 0, "pages_total": 2, "pages_changed": 1,
                                  "changed_ratio": .5, "zero_ratio": .5, "entropy_mean": 2., "has_changed": 1},
                                 {"bin": 1, "gpa": 8192, "pages_total": 2, "pages_changed": 0,
                                  "changed_ratio": 0., "zero_ratio": 1., "entropy_mean": 0., "has_changed": 0}]}}
        (tmp_path / f"{head['seq']}.json").write_text(json.dumps(side))
    return heads


def test_live_extraction_confirms_cross_view_after_invalid_predecessor(monkeypatch, tmp_path):
    calls = []
    def extract(raw, profile, seq, previous, predch_krizove=None):
        calls.append((previous, predch_krizove))
        row = sample(seq, predecessor=previous is not None, valid=seq != 1)
        state = {"pids": {1}, "mod_total": 1, "quality": deepcopy(row.quality),
                 "layout": row.layout, "krizove_kluce": frozenset({"hidden"})}
        return row.vector, state, []
    heads = _live_sidecars(tmp_path, (1, 2))
    monkeypatch.setattr(features, "_vsetky_hlavicky", lambda _: heads)
    monkeypatch.setattr(features, "vektor_snimky", extract)
    _, state = features.frame_from_snapshot(tmp_path, "unused", 1)
    features.frame_from_snapshot(tmp_path, "unused", 2, state)
    # The invalid predecessor drops out of the model inputs, not out of the
    # cross-view confirmation.
    assert calls == [(None, None), (None, frozenset({"hidden"}))]


@pytest.mark.parametrize("field,value", [("read_errors", 1), ("filled_zero", 1),
                                          ("traversals_complete", False)])
def test_behavior_valid_cannot_override_failed_input_evidence(field, value):
    row = sample(1)
    quality = {**row.quality, "model_valid": False, field: value}
    with pytest.raises(ValueError, match="behavior_valid"):
        replace(row, quality=quality)
    invalid = replace(row, quality={**quality, "behavior_valid": False})
    buffer = WindowBuffer(2)
    buffer.push(sample(0))
    assert buffer.push(invalid) is None
    assert buffer.reason == "invalid_input" and buffer.reset


def test_behavior_archive_rejects_legacy_quality_policy(tmp_path):
    from features.tests.test_collection_contract import archive_result
    data = archive.load(archive.save(tmp_path / "legacy-policy.npz", archive_result()))
    with pytest.raises(ValueError, match="quality policy"):
        frames_from_archive(data, "legacy")
