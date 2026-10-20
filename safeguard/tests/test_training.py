"""Synthetic mechanics checks; none of these are malware detection experiments."""
import copy
import json
from pathlib import Path

import numpy as np
import pytest
import torch

from features.archive import load, save
from safeguard.bundle import digest, load_bundle
from safeguard.features import arrays, frames_from_archive
from safeguard.model import (Classifier, Predictor, anomaly_score, architecture,
                             prediction_errors)
from safeguard.training import train_bundle, validate_index, calibrate, _validate_current_semantics


def write_json(path, value):
    Path(path).write_text(json.dumps(value))


def make_corpus(directory, session_schema="hyptcn3/collection-session/1"):
    """All four explicit roles with checkable, labeled synthetic provenance."""
    directory.mkdir(parents=True, exist_ok=True)
    protocol = {"schema": "hyptcn3/collection-protocol/2", "window_rows": 8,
                "quality_policy": "behavioral-inputs-v1",
                "max_gap_s": 1.5, "interval_s": 1,
                "roles": {role: 1 for role in ("train", "dev", "calibration", "test_benign")},
                "scenarios": {"quiet": {}, "busy": {}}}
    protocol_path = directory / "protocol.json"
    write_json(protocol_path, protocol)
    protocol_hash = digest(protocol_path)
    layout = {"bin_bytes": 4096, "page_size": 4096, "bins": [[0, 1], [1, 1], [2, 1]],
              "regions": [{"gpa": 0, "bytes": 12288}], "memsize": 12288, "vcpus": 2}
    records = []
    for role_index, role in enumerate(protocol["roles"]):
        for scenario_index, scenario in enumerate(protocol["scenarios"]):
            name = f"{role}-{scenario}"
            location = directory / name
            location.mkdir()
            rng = np.random.default_rng(10 * role_index + scenario_index)
            rows = 48
            matrix = rng.normal(1 + scenario_index, 0.1, size=(rows, 22))
            matrix[:, 18:] = 0
            matrix[1:, -2] = 1
            matrix[0, -1] = 1
            local = np.zeros((rows, 3, 4))
            local[..., 0] = rng.uniform(0.1, 0.3, size=(rows, 3))
            local[..., 1] = rng.uniform(0.2, 0.6, size=(rows, 3))
            local[..., 2] = rng.uniform(2, 5, size=(rows, 3))
            local[..., 3] = 1
            times = 1000 + 1000 * role_index + 100 * scenario_index + np.arange(rows, dtype=float)
            quality = [{"model_valid": True, "behavior_valid": True, "traversals_complete": True,
                        "inconclusive": ["text_integrity"], "findings": [],
                        "read_errors": 0, "filled_zero": 0} for _ in range(rows)]
            feature_path = save(location / "features.npz", {
                "matica": matrix, "seq": list(range(rows)), "casy": times,
                "valid": [True] * rows, "perbin": local, "biny": [0, 1, 2],
                "chain_ids": [name] * rows, "snimky": [str(i) for i in range(rows)],
                "trvanie_s": [0] * rows, "poznamky": [[] for _ in range(rows)],
                "quality": quality, "quality_policy": "behavioral-inputs-v1",
                "layout": layout, "max_medzera_s": 1.5})
            guest = {"boot_id": role + "-boot", "kernel": "synthetic-kernel", "stack_sha256": "synthetic-stack"}
            metadata = {"schema": session_schema, "session_id": name,
                        "role": role, "group": role + "-1", "scenario": scenario,
                        "typ": "benign", "guest_before": guest, "diagnostic": True,
                        "protocol_sha256": protocol_hash, "collector_sha256": "synthetic-collector"}
            meta_path, audit_path = location / "session.json", location / "audit.json"
            write_json(meta_path, metadata)
            values = {"accepted": True, "reasons": [], "role": role,
                      "protocol_sha256": protocol_hash, "session_sha256": digest(meta_path),
                      "features": str(feature_path), "features_sha256": digest(feature_path),
                      "layout": layout, "extractor_sha256": {"fixture": "synthetic"}, "diagnostic": True}
            write_json(audit_path, {"schema": "hyptcn3/collection-audit/1", "values": values})
            records.append({"id": name, "role": role, "group": metadata["group"],
                            "boot_id": guest["boot_id"], "scenario": scenario, "typ": "benign",
                            "session": str(meta_path), "session_sha256": digest(meta_path),
                            "audit": str(audit_path), "audit_sha256": digest(audit_path),
                            "features": str(feature_path), "features_sha256": digest(feature_path),
                            "protocol_sha256": protocol_hash, "start": float(times[0]), "end": float(times[-1])})
    path = directory / "index.json"
    write_json(path, {"schema": "hyptcn3/corpus-index/1", "protocol": str(protocol_path),
                      "protocol_sha256": protocol_hash, "protocol_config": protocol,
                      "complete": False, "diagnostic": True, "sessions": records})
    return path


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    directory = tmp_path_factory.mktemp("safeguard-training")
    corpus = make_corpus(directory / "corpus")
    output = directory / "bundle"
    old = torch.get_num_threads()
    torch.set_num_threads(2)
    report = train_bundle(corpus, output, window_rows=8, max_gap_s=1.5,
                          epochs=1, batch_size=16, fpr=0.1, diagnostic=True)
    yield corpus, output, report
    torch.set_num_threads(old)


def test_train_load_score_normalizer_and_immutable_bundle(trained):
    corpus, output, report = trained
    with pytest.raises(ValueError, match="diagnostic"):
        load_bundle(output)
    bundle = load_bundle(output, allow_diagnostic=True)
    assert report["training"]["normalization_fit_role"] == "train"
    assert report["training"]["test_feature_arrays_loaded"] is False
    index = json.loads(corpus.read_text())
    train = [record for record in index["sessions"] if record["role"] == "train"]
    expected_mean = np.concatenate([load(record["features"])["matica"][1:, :18] for record in train]).mean(axis=0)
    np.testing.assert_allclose(bundle.normalizer.global_mean, expected_mean)
    dev = next(record for record in index["sessions"] if record["role"] == "dev")
    frames = frames_from_archive(load(dev["features"]), dev["id"])
    score = bundle.score(frames[1:9])
    assert np.isfinite(score["score"])
    assert len(score["bin_errors"]) == 3
    assert set(score["activity_probabilities"]) == {"quiet", "busy"}
    assert sum(score["activity_probabilities"].values()) == pytest.approx(1)
    assert load_bundle(output, allow_diagnostic=True).score(frames[1:9]) == score
    with pytest.raises(ValueError, match="discontinuous"):
        bundle.score(frames[:8])
    with pytest.raises(FileExistsError):
        train_bundle(corpus, output, diagnostic=True)


def test_training_never_opens_test_arrays(tmp_path, monkeypatch):
    import safeguard.training as training
    corpus = make_corpus(tmp_path / "corpus")
    opened = []
    original = training.load_archive
    def checked(path):
        assert "test_benign" not in str(path)
        opened.append(str(path))
        return original(path)
    monkeypatch.setattr(training, "load_archive", checked)
    train_bundle(corpus, tmp_path / "bundle", window_rows=8, max_gap_s=1.5,
                 epochs=1, batch_size=32, fpr=0.1, diagnostic=True)
    assert len(opened) == 6


@pytest.mark.parametrize("version", [2, 3])
def test_index_accepts_session_schema_2_and_rejects_unknown(tmp_path, version):
    corpus = make_corpus(tmp_path / "corpus", f"hyptcn3/collection-session/{version}")
    if version == 2:
        validate_index(corpus, diagnostic=True)
    else:
        with pytest.raises(ValueError, match="unsupported session"):
            validate_index(corpus, diagnostic=True)


def test_index_rejects_leakage_and_modified_artifact(tmp_path):
    corpus = make_corpus(tmp_path / "corpus")
    index = json.loads(corpus.read_text())
    with pytest.raises(ValueError, match="complete"):
        validate_index(corpus)
    leaked = copy.deepcopy(index)
    leaked["sessions"][2]["boot_id"] = leaked["sessions"][0]["boot_id"]
    write_json(corpus, leaked)
    with pytest.raises(ValueError, match="shared"):
        validate_index(corpus, diagnostic=True)
    write_json(corpus, index)
    with Path(index["sessions"][0]["features"]).open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        validate_index(corpus, diagnostic=True)


def test_bundle_rejects_weight_and_contract_tampering(trained, tmp_path):
    import shutil
    _, original, _ = trained
    broken = tmp_path / "broken"
    shutil.copytree(original, broken)
    with (broken / "predictor.pt").open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        load_bundle(broken, allow_diagnostic=True)
    altered = tmp_path / "altered"
    shutil.copytree(original, altered)
    manifest = json.loads((altered / "manifest.json").read_text())
    manifest["feature_contract"]["global_names"].reverse()
    write_json(altered / "manifest.json", manifest)
    with pytest.raises(ValueError, match="feature contract"):
        load_bundle(altered, allow_diagnostic=True)


def test_prediction_mask_and_shared_bin_equivariance():
    torch.manual_seed(123)
    config = architecture(32)
    assert config["blocks"] >= 4
    predictor, classifier = Predictor(config).eval(), Classifier(config, 2).eval()
    global_values = torch.randn(2, 8, 18)
    local_values = torch.randn(2, 8, 3, 4)
    local_values[..., 3] = 1
    permutation = torch.tensor([2, 0, 1])
    with torch.inference_mode():
        before = predictor(global_values[:, :-1], local_values[:, :-1])
        after = predictor(global_values[:, :-1], local_values[:, :-1, permutation])
        torch.testing.assert_close(before[0], after[0])
        torch.testing.assert_close(before[1][:, permutation], after[1])
        torch.testing.assert_close(classifier(global_values, local_values),
                                   classifier(global_values, local_values[:, :, permutation]))
    target = torch.zeros(2, 3, 4)
    target[..., 2] = 100
    global_error, bins = prediction_errors((torch.zeros(2, 18), torch.zeros(2, 3, 3)),
                                          torch.zeros(2, 18), target)
    assert torch.count_nonzero(bins) == 0  # Unobserved entropy has no regression loss.
    target[..., 3] = 1
    _, observed = prediction_errors((torch.zeros(2, 18), torch.zeros(2, 3, 3)),
                                    torch.zeros(2, 18), target)
    assert (observed > 0).all()
    assert (anomaly_score(global_error, observed) > 0).all()


def test_scoring_excludes_target_from_predictor_input(trained, monkeypatch):
    from dataclasses import replace
    corpus, output, _ = trained
    record = json.loads(corpus.read_text())["sessions"][2]
    frames = frames_from_archive(load(record["features"]), record["id"])[1:9]
    bundle = load_bundle(output, allow_diagnostic=True)
    captured = []
    original = bundle.predictor.forward
    def capture(global_context, local_context):
        captured.append((global_context.clone(), local_context.clone()))
        return original(global_context, local_context)
    monkeypatch.setattr(bundle.predictor, "forward", capture)
    bundle.score(frames)
    vector = frames[-1].vector.copy()
    vector[8] += 7
    changed = frames[:-1] + [replace(frames[-1], vector=vector)]
    bundle.score(changed)
    assert captured[0][0].shape[1] == 7
    torch.testing.assert_close(captured[0][0], captured[1][0])
    torch.testing.assert_close(captured[0][1], captured[1][1])


def test_calibration_event_edges_reset_and_sample_gate():
    from types import SimpleNamespace
    frames = [SimpleNamespace(seq=i, timestamp=float(i), chain_id="a" if i < 11 else "b")
              for i in range(40)]
    dataset = SimpleNamespace(indices=[(0, i) for i in range(40)],
                              sessions=[(None, frames)], max_gap_s=1.5)
    scores = np.zeros(40)
    # Two consecutive exceedances would alarm without the chain reset.
    scores[10:12] = 10
    scores[20:23] = 10
    result = calibrate(scores, dataset, fpr=0.5, k=2, n=2, interval_s=1, diagnostic=True)
    assert result["threshold"] == 0
    assert result["alarm_events"] == 1
    assert result["scorable_hours"] == pytest.approx(40 / 3600)
    assert result["role"] == "calibration"
    with pytest.raises(ValueError, match="at least"):
        calibrate(scores, dataset, fpr=0.01, k=2, n=2, interval_s=1, diagnostic=False)
    with pytest.raises(ValueError, match="score index"):
        calibrate(scores[:-1], dataset, fpr=0.5, k=2, n=2, interval_s=1, diagnostic=True)


def test_production_semantics_refuse_stale_extractor_and_profile(tmp_path):
    root = Path(__file__).resolve().parents[2]
    extractors = {str(file.relative_to(root)): digest(file)
                  for directory in (root / "features", root / "guestparse")
                  for file in directory.rglob("*.py") if "tests" not in file.parts}
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "symbols.txt").write_text("synthetic profile for validation mechanics")
    profile_hash = {"symbols.txt": digest(profile / "symbols.txt")}
    protocol = {"profile": str(profile)}
    _validate_current_semantics(extractors, profile_hash, protocol)
    changed = dict(extractors)
    changed["features/snapshot.py"] = "stale"
    with pytest.raises(ValueError, match="stale extractor"):
        _validate_current_semantics(changed, profile_hash, protocol)
    (profile / "symbols.txt").write_text("changed profile")
    with pytest.raises(ValueError, match="stale guest profile"):
        _validate_current_semantics(extractors, profile_hash, protocol)


def test_loaded_bundle_normalizer_fit_role_is_strict(trained, tmp_path):
    import shutil
    _, original, _ = trained
    altered = tmp_path / "bad-normalizer"
    shutil.copytree(original, altered)
    manifest = json.loads((altered / "manifest.json").read_text())
    manifest["training"]["normalization_fit_role"] = "calibration"
    write_json(altered / "manifest.json", manifest)
    with pytest.raises(ValueError, match="normalization/training"):
        load_bundle(altered, allow_diagnostic=True)


def test_calibration_batch_and_bundle_score_agree(trained):
    corpus, output, _ = trained
    index = json.loads(corpus.read_text())
    record = next(r for r in index["sessions"] if r["role"] == "calibration")
    frames = frames_from_archive(load(record["features"]), record["id"])
    bundle = load_bundle(output, allow_diagnostic=True)
    windows = [frames[1:9], frames[2:10]]
    normalized = [bundle.normalizer.transform(*arrays(window)) for window in windows]
    global_values = torch.tensor(np.stack([pair[0] for pair in normalized]), dtype=torch.float32)
    local_values = torch.tensor(np.stack([pair[1] for pair in normalized]), dtype=torch.float32)
    with torch.inference_mode():
        errors = prediction_errors(bundle.predictor(global_values[:, :-1], local_values[:, :-1]),
                                   global_values[:, -1], local_values[:, -1])
        scores = anomaly_score(*errors).numpy()
    np.testing.assert_allclose(scores, [bundle.score(window)["score"] for window in windows], rtol=1e-6)
