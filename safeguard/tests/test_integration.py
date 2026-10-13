"""Cross-module software checks using clearly marked synthetic artifacts."""
from dataclasses import replace
import json

import numpy as np
import pytest
import torch

from features.archive import load
from safeguard.bundle import load_bundle
from safeguard.cli import main
from safeguard.demo import smoke
from safeguard.features import frames_from_archive
from safeguard.runtime import Detector, replay_archive


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    root = tmp_path_factory.mktemp("integration") / "smoke"
    old = torch.get_num_threads()
    torch.set_num_threads(2)
    report = smoke(root)
    yield root, report
    torch.set_num_threads(old)


def test_entire_synthetic_cycle_and_cli(demo, tmp_path, capsys):
    root, report = demo
    assert report["ok"] and report["diagnostic"]
    assert report["normal_load_rejected_diagnostic"]
    assert not report["test_arrays_loaded_during_training"]
    assert report["rows"] == 96 and report["scored"] == 80
    assert report["training"]["classes"] == ["quiet", "steady"]
    bundle = root / "bundle"
    assert main(["inspect", "--bundle", str(bundle)]) == 2
    assert "diagnostic" in capsys.readouterr().err
    assert main(["inspect", "--bundle", str(bundle), "--allow-diagnostic"]) == 0
    assert json.loads(capsys.readouterr().out)["diagnostic"]
    archive = root / "corpus/synthetic-test_benign-quiet/features.npz"
    output = tmp_path / "replay"
    assert main(["replay", "--bundle", str(bundle), "--allow-diagnostic", "--archive",
                 str(archive), "--out", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["processed"] == 96 and result["scored"] == 80
    assert (output / "configuration.json").is_file()
    assert main(["status", "--out", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["running"] is False
    assert main(["replay", "--bundle", str(bundle), "--allow-diagnostic", "--archive",
                 str(archive), "--out", str(output)]) == 2


def test_loaded_model_shared_replay_exactness_and_recovery(demo):
    root, _ = demo
    bundle = load_bundle(root / "bundle", allow_diagnostic=True)
    path = root / "corpus/synthetic-test_benign-quiet/features.npz"
    frames = frames_from_archive(load(path), "integration")
    replay = replay_archive(bundle, path, "integration")
    first = next(row for row in replay if row["score"] is not None)
    assert first["seq"] == 8
    direct = bundle.score(frames[1:9])
    assert direct["score"] == first["score"]
    assert direct["activity_probabilities"] == first["activity_probabilities"]
    assert all(r["score"] is None for r in replay[64:72])
    detector = Detector(bundle, preserve=False)
    for frame in frames[:12]:
        detector.process(frame)
    invalid = replace(frames[12], quality={**frames[12].quality, "model_valid": False,
                                           "behavior_valid": False, "read_errors": 1})
    assert detector.process(invalid)["state"] == "input_error"
    assert detector.process(frames[13])["score"] is None
    row = None
    for frame in frames[14:21]:
        row = detector.process(frame)
    assert row["score"] is not None
    broken = replace(frames[21], layout={**frames[21].layout, "vcpus": 3})
    failure = detector.process(broken)
    assert failure["fatal"] and failure["state"] == "input_error"
    assert "feature_contract_mismatch" in failure["reason"]


def test_integrity_can_alarm_before_model_warmup(demo):
    root, _ = demo
    bundle = load_bundle(root / "bundle", allow_diagnostic=True)
    frames = frames_from_archive(load(root / "corpus/synthetic-test_benign-quiet/features.npz"), "integrity")
    frame = replace(frames[0], quality={**frames[0].quality, "findings": [{"check": "synthetic-integrity-fixture"}]})
    row = Detector(bundle, preserve=False).process(frame)
    assert row["state"] == "alarm" and row["model_state"] == "warming_up"
    assert row["score"] is None and row["alarm_sources"] == ["kernel_integrity"]
    assert row["integrity"]["conclusive"] is False
    assert row["evidence"]["status"] == "disabled"
    assert np.isfinite(bundle.threshold)


def test_status_exposes_failed_collector_even_if_detector_drained(tmp_path, capsys):
    (tmp_path / "detector").mkdir()
    (tmp_path / "detector/status.json").write_text(json.dumps({"ok": True, "running": False}))
    (tmp_path / "result.json").write_text(json.dumps({"ok": False, "collector_returncode": -15,
                                                    "stop_reason": "disk_reserve_reached"}))
    assert main(["status", "--out", str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["stop_reason"] == "disk_reserve_reached"
