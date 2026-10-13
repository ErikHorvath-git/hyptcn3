import copy
import json
from pathlib import Path

import numpy as np
import pytest

from features import archive
from features.contract import validate_sidecar
from features.perbin import FeatureError
from features.snapshot import MENA
from features.stream import WindowStream
from features.windows import okna, snimky_z_matice, WindowError


def matrix(n):
    x = np.arange(n * len(MENA), dtype=float).reshape(n, len(MENA))
    x[:, -2:] = [1, 0]
    return x


def test_live_and_offline_windows_are_identical_through_barriers():
    x = matrix(30)
    x[0, -2:] = [0, 1]
    x[8, -1] = 1
    valid = np.ones(30, bool)
    valid[14] = False
    seq = np.arange(30)
    seq[20:] += 1
    times = seq * 5.
    times[25:] += 10
    rows = snimky_z_matice("test", x, MENA, times, seq, valid)
    offline = okna(rows, dlzka=3, max_medzera_s=7.5)
    stream = WindowStream(3)
    online, ends = [], []
    for s, t, vector, good in zip(seq, times, x, valid):
        window = stream.push(s, t, vector, good)
        if window is not None:
            online.append(window)
            ends.append(s)
    np.testing.assert_array_equal(np.stack(online), offline.X)
    assert ends == [m["seq_do"] for m in offline.meta]


@pytest.mark.parametrize("kind", ["duplicate_seq", "backwards_time", "nan"])
def test_corrupt_window_metadata_rejected(kind):
    x = matrix(3)
    seq, times = [0, 1, 2], [0., 5., 10.]
    if kind == "duplicate_seq":
        seq[2] = 1
    elif kind == "backwards_time":
        times[2] = 4
    else:
        x[1, 0] = np.nan
    with pytest.raises(WindowError):
        okna(snimky_z_matice("x", x, MENA, times, seq), dlzka=2, max_medzera_s=7.5)


def sample_sidecar():
    return {"schema": "vmicollect/1", "seq": 0, "timestamp_unix": 12.,
            "vm": {"memsize": 4096, "num_vcpus": 2},
            "stats": {"read_errors": 0, "filled_zero": 0},
            "output": {"pages_total": 1, "pages_changed": 1, "page_size": 4096},
            "features": {"schema": "hyptcn3/perbin/1", "entropy": True,
                         "bin_bytes": 16777216, "page_size": 4096, "bins_total": 1,
                         "regions": [{"gpa": 0, "bytes": 4096}],
                         "bins": [{"bin": 0, "gpa": 0, "pages_total": 1, "pages_changed": 1,
                                   "changed_ratio": 1., "zero_ratio": 0., "entropy_mean": 2.,
                                   "has_changed": 1}]}}


@pytest.mark.parametrize("mutation", ["sum", "nan", "mask", "entropy", "identity"])
def test_collector_feature_contract_rejects_corruption(mutation):
    doc = sample_sidecar()
    validate_sidecar(doc)
    b = doc["features"]["bins"][0]
    if mutation == "sum":
        doc["output"]["pages_total"] = 2
    elif mutation == "nan":
        b["entropy_mean"] = float("nan")
    elif mutation == "mask":
        b["has_changed"] = .5
    elif mutation == "entropy":
        doc["features"]["entropy"] = False
    else:
        b["gpa"] = 4096
    with pytest.raises(FeatureError):
        validate_sidecar(doc)


def archive_result():
    return {"matica": matrix(5), "seq": [0, 1, 3, 4, 5], "casy": [0., 5., 15., 20., 25.],
            "valid": [True] * 5, "perbin": np.zeros((5, 1, 4)), "biny": [0],
            "chain_ids": ["a"] * 5, "snimky": [str(i) for i in range(5)],
            "trvanie_s": [0.] * 5, "poznamky": [[]] * 5,
            "quality": [{"model_valid": True, "behavior_valid": True}] * 5,
            "quality_policy": "legacy-vector-v1", "layout": {}, "max_medzera_s": 7.5}


def test_archive_preserves_actual_gaps_bins_and_quality(tmp_path):
    result = archive_result()
    path = archive.save(tmp_path / "features.npz", result)
    data = archive.load(path)
    assert list(data["seq"]) == [0, 1, 3, 4, 5]
    windows = okna(snimky_z_matice("x", data["matica"], MENA, data["casy"], data["seq"], data["valid"]), dlzka=3)
    assert len(windows) == 1
    assert windows.meta[0]["seq_od"] == 3
    with pytest.raises(FileExistsError):
        archive.save(path, result)


def test_legacy_archive_must_be_reextracted(tmp_path):
    path = tmp_path / "old.npz"
    np.savez(path, schema="hyptcn3/snapshot-vektor/1", matica=matrix(3), mena=MENA)
    with pytest.raises(ValueError, match="re-extract"):
        archive.load(path)


def test_header_sort_is_by_sequence_not_chain_id(monkeypatch, tmp_path):
    from features.snapshot import _vsetky_hlavicky
    from guestparse.image import VmicdImage
    for name in ("a.vmicd", "b.vmicd"):
        (tmp_path / name).touch()
    monkeypatch.setattr(VmicdImage, "header", lambda p: {
        "seq": 0 if Path(p).name == "a.vmicd" else 1,
        "chain_id": 999 if Path(p).name == "a.vmicd" else 1})
    assert [h["seq"] for h in _vsetky_hlavicky(str(tmp_path))] == [0, 1]
