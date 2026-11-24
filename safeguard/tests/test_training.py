"""Synthetic mechanics checks; none of these are malware detection experiments."""
import copy
import json
from pathlib import Path

import numpy as np
import pytest
import torch

from features.archive import load, save
from features.acceptance import judge
from safeguard.bundle import digest, load_bundle
from safeguard.features import GLOBAL_NAMES, MENA, arrays, frames_from_archive

G = len(GLOBAL_NAMES)
from safeguard.model import (Classifier, Predictor, anomaly_score, architecture,
                             prediction_errors)
from safeguard.training import train_bundle, validate_index, calibrate, _validate_current_semantics


def write_json(path, value):
    Path(path).write_text(json.dumps(value))


def make_corpus(directory, session_schema="hyptcn3/collection-session/1"):
    """All four explicit roles with checkable, labeled synthetic provenance."""
    directory.mkdir(parents=True, exist_ok=True)
    rows = 48
    # One chain per session, full snapshot only at seq 0: ideal 40 of 48 windows.
    protocol = {"schema": "hyptcn3/collection-protocol/2", "window_rows": 8,
                "quality_policy": "behavioral-inputs-v1",
                "max_gap_s": 1.5, "interval_s": 1,
                "cycles": rows, "full_every": rows, "stride": 1, "min_score_coverage": 0.8,
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
            matrix = rng.normal(1 + scenario_index, 0.1, size=(rows, len(MENA)))
            matrix[:, G:] = 0
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
                        "read_errors": 0, "filled_zero": 0, "process_walk": "next"} for _ in range(rows)]
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
            verdict, _, _ = judge(load(feature_path), protocol, name, role)
            values = {"accepted": True, "reasons": [], "role": role,
                      "snapshots": verdict["snapshots"], "windows": verdict["windows"],
                      "score_coverage": verdict["score_coverage"],
                      "quality": {"tolerated_invalid_seq": verdict["tolerated_invalid_seq"]}, "acceptance": verdict,
                      "protocol_sha256": protocol_hash, "session_sha256": digest(meta_path),
                      "features": str(feature_path), "features_sha256": digest(feature_path),
                      "layout": layout, "extractor_sha256": {"fixture": "synthetic"}, "diagnostic": True}
            if session_schema == "hyptcn3/collection-session/2":
                values["logs"] = {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True,
                                  "problems": [], "sections": {"metadata": {"session_sha256": digest(meta_path)}},
                                  "note": "Synthetic provenance fixture, no real traffic."}
            write_json(audit_path, {"schema": "hyptcn3/collection-audit/1", "values": values})
            records.append({"id": name, "role": role, "group": metadata["group"],
                            "boot_id": guest["boot_id"], "scenario": scenario, "typ": "benign",
                            "session": str(meta_path), "session_sha256": digest(meta_path),
                            "audit": str(audit_path), "audit_sha256": digest(audit_path),
                            "features": str(feature_path), "features_sha256": digest(feature_path),
                            "protocol_sha256": protocol_hash, "start": float(times[0]), "end": float(times[-1])})
    path = directory / "index.json"
    # A protocol of schema 2: its allocation rule, no plan mode (features/dataset.py, package B6a).
    write_json(path, {"schema": "hyptcn3/corpus-index/1", "protocol": str(protocol_path),
                      "allocation_rule": "every_scenario_every_group", "plan_mode": None,
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
    expected_mean = np.concatenate([load(record["features"])["matica"][1:, :G] for record in train]).mean(axis=0)
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


def test_training_rejects_managed_session_without_logs_even_with_accepted_features(tmp_path):
    corpus = make_corpus(tmp_path / "corpus", "hyptcn3/collection-session/2")
    index = json.loads(corpus.read_text())
    record = index["sessions"][0]
    report = json.loads(Path(record["audit"]).read_text())
    del report["values"]["logs"]
    write_json(record["audit"], report)
    record["audit_sha256"] = digest(record["audit"])
    write_json(corpus, index)
    with pytest.raises(ValueError, match="log audit"):
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
    global_values = torch.randn(2, 8, G)
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
    global_error, bins = prediction_errors((torch.zeros(2, G), torch.zeros(2, 3, 3)),
                                          torch.zeros(2, G), target)
    assert torch.count_nonzero(bins) == 0  # Unobserved entropy has no regression loss.
    target[..., 3] = 1
    _, observed = prediction_errors((torch.zeros(2, G), torch.zeros(2, 3, 3)),
                                    torch.zeros(2, G), target)
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


# ------------------------------------------------------------------ package B6b (design NAVRH_B6b 1.3 to 1.6)
# The names package B6b adds are imported inside the tests, so this file collects on the code before it.

V5 = Path(__file__).resolve().parents[2] / "config/collection-v5.json"
REPEAT = "once with twice the cap"


def v5_protocol(changes=()):
    """config/collection-v5.json with the given keys of its analysis section replaced ("stopping.rule": one level
    down)."""
    protocol = json.loads(V5.read_text())
    for key, value in dict(changes).items():
        section, _, inner = key.partition(".")
        if inner:
            protocol["analysis"][section][inner] = value
        else:
            protocol["analysis"][section] = value
    return protocol


def refused(reason):
    import re
    return pytest.raises(ValueError, match="^" + re.escape(reason) + "$")


@pytest.mark.parametrize("schema, changes, given, reason", [
    (3, {}, {"fpr": 0.05}, "analysis parameter fpr is given (0.05) under protocol schema 3, whose analysis plan fixes "
     "analysis.fpr = 0.01; a given analysis parameter is applied only to a diagnostic bundle (--diagnostic)"),
    (3, {}, {"seed": 7}, "analysis parameter seed is given (7) under protocol schema 3, whose analysis plan fixes "
     "analysis.seeds = [0, 1, 2, 3, 4]; a given analysis parameter is applied only to a diagnostic bundle "
     "(--diagnostic)"),
    (3, {"architecture.weight_norm": True}, {}, "analysis.architecture.weight_norm is true: the TCN of the thesis "
     "has no weight normalization (SULAD_S_TEXTOM_PRACE table 1) and safeguard/model.py builds none"),
    (3, {"stopping.rule": "last epoch"}, {}, "analysis.stopping.rule is 'last epoch'; this training implements "
     "'best dev loss, patience'"),
    (4, {}, {}, "protocol schema 'hyptcn3/collection-protocol/4' states no training parameters: schema 3 gives them "
     "in its analysis section, schemas 1 and 2 keep legacy_schema_2"),
], ids=["fpr_outside_diagnostic", "seed_outside_plan", "weight_norm", "stopping_rule", "schema_4"])
def test_analysis_parameters_are_refused_by_name(schema, changes, given, reason):
    """Design B6b 1.4 and 1.6: under schema 3 a given analysis parameter outside --diagnostic, a seed outside
    analysis.seeds, weight normalization and a stopping rule this training does not implement are refused by name;
    a schema without training parameters too."""
    from safeguard.training import training_parameters
    protocol = dict(v5_protocol(changes), schema=f"hyptcn3/collection-protocol/{schema}")
    with refused(reason):
        training_parameters(protocol, given, window_rows=32, diagnostic=False)


def test_analysis_parameters_come_from_the_plan_and_overrides_are_recorded():
    """The good side of the refusals above: the plan of config/collection-v5.json, a planned seed chosen (no
    override), a diagnostic bundle that overrides fpr and a seed outside the plan (both recorded), and schema 2
    with today's values under the name legacy_schema_2."""
    from safeguard.training import training_parameters
    plan = v5_protocol()["analysis"]
    out = training_parameters(v5_protocol(), {}, window_rows=32, diagnostic=False)
    assert (out["rule"], out["seed"], out["fpr"], out["k"], out["n"], out["batch_size"]) == (
        "analysis", plan["deploy_seed"], plan["fpr"], plan["alarm_rule"]["k"], plan["alarm_rule"]["n"],
        plan["architecture"]["batch_size"])
    assert out["stopping"] == {key: plan["stopping"][key] for key in ("rule", "patience_epochs", "max_epochs",
                                                                     "repeat_if_last_epoch")}
    assert out["model"] == {key: plan["architecture"][key] for key in ("kernel", "blocks", "channels", "dropout",
                                                                      "weight_norm")}
    assert [out[key] for key in ("learning_rate", "gradient_clip", "classifier_gradient_clip")] == [
        plan["architecture"][key] for key in ("learning_rate", "gradient_clip", "classifier_gradient_clip")]
    assert (out["given"], out["overrides"]) == ({}, {})
    from safeguard.training import model_config
    other = training_parameters(v5_protocol({"architecture.channels": 8, "architecture.kernel": 5}), {},
                                window_rows=32, diagnostic=False)
    config = model_config(other, 32, G)
    assert (config["channels"], config["kernel"], config["blocks"], config["dropout"]) == (8, 5, 4, 0.1)
    Predictor(config)  # safeguard/model.py builds the TCN of the plan
    chosen = training_parameters(v5_protocol(), {"seed": 3}, window_rows=32, diagnostic=False)
    assert (chosen["seed"], chosen["given"], chosen["overrides"]) == (3, {"seed": 3}, {})
    diagnostic = training_parameters(v5_protocol(), {"fpr": 0.05, "seed": 7}, window_rows=32, diagnostic=True)
    assert (diagnostic["fpr"], diagnostic["seed"]) == (0.05, 7)
    assert diagnostic["overrides"] == {"fpr": {"path": "analysis.fpr", "planned": 0.01, "applied": 0.05},
                                       "seed": {"path": "analysis.seeds", "planned": [0, 1, 2, 3, 4], "applied": 7}}
    legacy = training_parameters({"schema": "hyptcn3/collection-protocol/2"}, {"epochs": 2}, window_rows=32,
                                 diagnostic=False)
    assert (legacy["rule"], legacy["stopping"]["max_epochs"], legacy["stopping"]["patience_epochs"],
            legacy["stopping"]["repeat_if_last_epoch"], legacy["batch_size"], legacy["seed"], legacy["fpr"],
            legacy["k"], legacy["n"], legacy["given"]) == ("legacy_schema_2", 2, None, None, 32, 0, 0.01, 3, 5,
                                                           {"epochs": 2})


@pytest.mark.parametrize("schema, diagnostic, expected", [
    (3, False, "normalization rule: analysis.columns is null until G3a; production training needs the classes of the "
               "columns (diagnostic training takes the rule all_neural_diagnostic, every column neural)"),
    (3, True, "all_neural_diagnostic"),
    (2, False, "legacy_schema_2"),
], ids=["schema_3_production", "schema_3_diagnostic", "schema_2"])
def test_normalization_rule_is_named_or_refused(schema, diagnostic, expected):
    """Contract 1.1: while analysis.columns is null (until G3a) production is refused by name and a diagnostic
    training takes all_neural_diagnostic; schemas 1 and 2 take legacy_schema_2. Every column is neural in both. Since
    the merge with agent N the rule is safeguard.features.NormalizationRule.from_protocol, which training calls."""
    from safeguard.features import NormalizationRule
    protocol = v5_protocol() if schema == 3 else {"schema": "hyptcn3/collection-protocol/2"}
    if expected.startswith("normalization rule:"):
        with refused(expected):
            NormalizationRule.from_protocol(protocol, diagnostic=diagnostic)
        return
    rule = NormalizationRule.from_protocol(protocol, diagnostic=diagnostic)
    assert rule.name == expected and rule.classes == dict.fromkeys(GLOBAL_NAMES, "neural")


def test_rule_channel_ranges_come_from_the_measured_rows_of_train_and_calibration():
    """Contract 1.3: the range of a rule column's raw value and of a rule_differenced column's change since the
    session's first measured row (question Q8, its revised proposal accepted by the lead 2026-11-24) over the measured
    rows of train and calibration (dev never; an invalid row, a full snapshot and a row without a predecessor never),
    with k of n of the neural channel. The one builder is safeguard.features.rule_channel since the merge with agent N.
    The lead's answer to Q8 (package B11): with a column of class rule_differenced the rule channel states its
    limitation (SESSION_START_LIMITATION), without one its limitation is None."""
    from types import SimpleNamespace
    from safeguard.features import SESSION_START_LIMITATION, rule_channel
    value, level = GLOBAL_NAMES.index("sock_listen"), GLOBAL_NAMES.index("mod_total")

    def session(rows):
        frames = []
        for seq, (a, b, valid, full, predecessor) in enumerate(rows):
            vector = np.zeros(len(MENA))
            vector[value], vector[level] = a, b
            frames.append(SimpleNamespace(seq=seq, vector=vector, valid=valid, full=full,
                                          has_predecessor=predecessor))
        return None, frames
    good = (True, False, True)
    sessions = {"train": [session([(2, 10, *good), (2, 11, *good), (9, 50, False, False, True), (3, 13, *good),
                                   (8, 90, True, True, False)])],
                "calibration": [session([(1, 20, *good), (2, 20, *good)])],
                "dev": [session([(100, 0, *good), (100, 500, *good)])]}
    classes = dict.fromkeys(GLOBAL_NAMES, "neural")
    classes.update(sock_listen="rule", mod_total="rule_differenced")
    out = rule_channel(sessions, classes, k=3, n=5)
    assert (out["columns"], out["k"], out["n"], out["roles"]) == (["mod_total", "sock_listen"], 3, 5,
                                                                    ["train", "calibration"])
    assert out["ranges"] == {"sock_listen": {"quantity": "value", "min": 1.0, "max": 3.0, "rows": 5},
                             "mod_total": {"quantity": "since_session_start", "min": 0.0, "max": 3.0, "rows": 5}}
    assert out["limitation"] == SESSION_START_LIMITATION
    assert SESSION_START_LIMITATION.startswith("A column of class rule_differenced is judged by its change since the "
                                               "session's first measured row, so a state already present in that row "
                                               "is never seen by this rule; in a live run that row is the first "
                                               "measured row after the detector starts")
    values_only = dict(classes, mod_total="rule")
    assert rule_channel(sessions, values_only, k=3, n=5)["limitation"] is None
    excluded = {role: [session([(2, 10, False, False, True)])] for role in ("train", "calibration")}  # No measured row.
    with refused("rule channel: column mod_total has no measured row in train and calibration"):
        rule_channel(excluded, classes, k=3, n=5)


@pytest.mark.parametrize("dev, stopping, expected", [
    ([3, 2, 2.5, 2.6], {"max_epochs": 6, "patience_epochs": 2},
     dict(epochs_run=4, selected_epoch=2, stopped_by="patience_epochs", repeated=False, selected_is_last=False)),
    ([3, 2, 1.5, 1.4], {"max_epochs": 2, "patience_epochs": 10},
     dict(epochs_run=4, selected_epoch=4, stopped_by="max_epochs", repeated=True, selected_is_last=True)),
    ([3, 2, 2.5], {"max_epochs": 2, "patience_epochs": 1},
     dict(epochs_run=3, selected_epoch=2, stopped_by="patience_epochs", repeated=True, selected_is_last=False)),
    ([3, 2, 1], {"max_epochs": 3, "patience_epochs": None, "repeat_if_last_epoch": None},
     dict(epochs_run=3, selected_epoch=3, stopped_by="max_epochs", repeated=False, selected_is_last=True)),
], ids=["patience", "last_epoch_repeated_once", "patience_after_the_repeat", "legacy_schema_2"])
def test_stopping_rule_repeats_once_with_twice_the_cap(monkeypatch, dev, stopping, expected):
    """Skeleton B6 test 8 and proposal 8.3: a model stops on its own dev loss with the patience; when its selected
    epoch is the last one the cap allows, training goes on once to twice the cap, and the record says so (a selected
    epoch that is last again after the repeat is recorded, and nothing is repeated twice). legacy_schema_2 runs every
    epoch and repeats nothing. The dev losses are scripted; a further epoch would exhaust them."""
    import safeguard.training as training
    from types import SimpleNamespace
    losses = iter(dev)
    monkeypatch.setattr(training, "_dev_loss", lambda model, loss, dataset, batch_size: float(next(losses)))
    data = SimpleNamespace(indices=[0, 1], batches=lambda batch_size, order=None: iter(
        [(torch.ones(2, 1), torch.ones(2, 1), torch.zeros(2, dtype=torch.long))]))
    stopping = {"repeat_if_last_epoch": REPEAT, **stopping}
    record, history = training._fit(torch.nn.Linear(1, 1), lambda model, g, local, labels: model(g).square().mean(),
                                    data, data, learning_rate=0.001, clip=5, batch_size=2, stopping=stopping, seed=0,
                                    name="predictor")
    assert {key: record[key] for key in expected} == expected
    assert record["max_epochs"] == stopping["max_epochs"]
    assert record["max_epochs_after_repeat"] == (2 * stopping["max_epochs"] if expected["repeated"] else None)
    assert [epoch for epoch, _, _ in history] == list(range(1, expected["epochs_run"] + 1))
    assert record["best_dev_loss"] == dev[expected["selected_epoch"] - 1]


def test_predictor_weights_do_not_depend_on_the_classifier(trained, tmp_path, monkeypatch):
    """Skeleton B6 test 6: at the same seed the predictor's weights are the same with the classifier head trained and
    without it (its training replaced by an untrained head that draws from torch's global generator as a training
    would). The head has its own optimizer, clip and random streams (proposal 8.2)."""
    import safeguard.training as training
    corpus, output, _ = trained

    def without(config, classes, datasets, parameters):
        torch.rand(1000)
        classifier = training.Classifier(config, classes).eval()
        record = {"selected_epoch": 1, "note": "not trained (test)"}
        return classifier, record, [{"epoch": 1, "train_classification_loss": 0.0, "dev_classification_loss": 0.0}]
    monkeypatch.setattr(training, "_train_classifier", without)
    train_bundle(corpus, tmp_path / "bundle", window_rows=8, max_gap_s=1.5, epochs=1, batch_size=16, fpr=0.1,
                 diagnostic=True)
    with_head = torch.load(output / "predictor.pt", weights_only=True)
    without_head = torch.load(tmp_path / "bundle" / "predictor.pt", weights_only=True)
    assert with_head.keys() == without_head.keys()
    assert all(torch.equal(with_head[key], without_head[key]) for key in with_head)
    first, second = (json.loads((path / "manifest.json").read_text()) for path in (output, tmp_path / "bundle"))
    assert first["calibration"]["threshold"] == second["calibration"]["threshold"]
    assert second["training"]["stopping"]["classifier"]["note"] == "not trained (test)"


def test_sensitivity_table_on_a_linear_model_equals_the_hand_calculation():
    """Skeleton B6 test 3: on a linear model with a known scale the table equals the hand calculation. The model
    predicts p for every column whatever the context and normalizes with mean m and scale s, so moving column c of
    the last row by d gives the score R_c + 0.5 / G * (e_c - d / s_c)^2, e_c = p_c - (x_c - m_c) / s_c. The score
    exceeds the threshold t when |e_c - d / s_c| > D_c = sqrt(2 G (t - R_c)): up at d = s_c (D_c + e_c), down at
    s_c (D_c - e_c). One unit suffices when a move of one unit crosses in either direction."""
    from dataclasses import dataclass
    from safeguard.training import SENSITIVITY_RTOL, sensitivity_table
    mean, scale = np.linspace(1, 3, G), 0.5 + np.arange(G) / 10
    p, bins = np.linspace(-0.3, 0.3, G), 0.2

    @dataclass(frozen=True)
    class Row:
        vector: np.ndarray

    class Linear:
        def score(self, window):
            error = p - (window[-1].vector[:G] - mean) / scale
            return {"score": 0.5 * float(np.mean(error ** 2)) + 0.5 * bins}
    last = np.concatenate([mean + 0.1 * scale, np.zeros(len(MENA) - G)])
    window = [Row(np.zeros(len(MENA)))] * 3 + [Row(last)]
    error = p - 0.1
    base = 0.5 * float(np.mean(error ** 2)) + 0.5 * bins
    threshold = base + 0.05
    units = {GLOBAL_NAMES[0]: 10.0, GLOBAL_NAMES[1]: 0.01}
    table = sensitivity_table(Linear(), window, threshold, list(GLOBAL_NAMES), dict(zip(GLOBAL_NAMES, scale)), units)
    assert table["base_score"] == pytest.approx(base)
    for c, row in enumerate(table["columns"]):
        rest = base - 0.5 / G * error[c] ** 2
        reach = np.sqrt(2 * G * (threshold - rest))
        up, down = scale[c] * (reach + error[c]), scale[c] * (reach - error[c])
        assert (row["name"], row["scale"], row["value"]) == (GLOBAL_NAMES[c], scale[c], last[c])
        for found, expected in ((row["up"], up), (row["down"], down)):
            assert expected * (1 - 1e-12) <= found <= expected * (1 + 1.5 * SENSITIVITY_RTOL)
        assert row["unit"] == units.get(GLOBAL_NAMES[c])
        assert row["one_unit_suffices"] == {0: True, 1: False}.get(c)


def test_one_unit_suffices_when_only_the_move_down_crosses_the_threshold():
    """F3 of the B6b verification (package B10, mutant X3): one_unit_suffices scores a move of one unit in either
    direction (SENSITIVITY_METHOD). A score that falls as proc_total rises: no move up crosses the threshold 0.5, the
    smallest move down is 0.5, and one unit down crosses it."""
    from dataclasses import dataclass
    from safeguard.training import SENSITIVITY_RTOL, sensitivity_table
    column = MENA.index("proc_total")

    @dataclass(frozen=True)
    class Row:
        vector: np.ndarray

    class Falling:
        def score(self, window):
            return {"score": 10. - float(window[-1].vector[column])}
    window = [Row(np.full(len(MENA), 10.))] * 2
    row, = sensitivity_table(Falling(), window, .5, ["proc_total"], {"proc_total": 1.}, {"proc_total": 1.})["columns"]
    assert (row["up"], row["one_unit_suffices"]) == (None, True)
    assert .5 <= row["down"] <= .5 * (1 + 1.5 * SENSITIVITY_RTOL)


def test_the_classifier_is_clipped_with_its_own_norm(monkeypatch):
    """F3 of the B6b verification (package B10, mutant T1): the head is trained apart from the predictor with its own
    clip (proposal 8.2). The plan holds both norms at 5, so here they differ: the predictor's training gets
    gradient_clip 5 and the classifier's classifier_gradient_clip 2."""
    import safeguard.training as training
    clips = []
    monkeypatch.setattr(training, "_fit", lambda model, loss, train, dev, *, clip, **settings: (
        clips.append(clip), ({"selected_epoch": 1}, []))[1])
    parameters = {"learning_rate": .001, "gradient_clip": 5, "classifier_gradient_clip": 2, "batch_size": 32,
                  "stopping": {"max_epochs": 1}, "seed": 0}
    config = architecture(8, global_features=G)
    training._train_predictor(config, {"train": None, "dev": None}, parameters)
    training._train_classifier(config, 2, {"train": None, "dev": None}, parameters)
    assert clips == [5, 2]


def test_manifest_carries_the_sensitivity_table_of_the_median_calibration_window(trained):
    """Skeleton B6 section 5 and test 3: the manifest has the table for every TCN column, on the calibration window
    with the (lower) median score; every change it records lifts the row above the threshold on the saved bundle and
    a change 0.1 % smaller does not. The table says that the alarm needs k of n."""
    from dataclasses import replace
    corpus, output, _ = trained
    bundle = load_bundle(output, allow_diagnostic=True)
    table = bundle.manifest["sensitivity"]
    index = json.loads(corpus.read_text())
    windows = []
    for record in (r for r in index["sessions"] if r["role"] == "calibration"):
        frames = frames_from_archive(load(record["features"]), record["id"])
        windows += [frames[end - 7:end + 1] for end in range(8, len(frames))]  # Row 0 is the full snapshot.
    scores = [bundle.score(window)["score"] for window in windows]
    order = sorted(range(len(scores)), key=lambda i: (scores[i], i))
    median = windows[order[(len(order) - 1) // 2]]
    assert table["window"] == {"role": "calibration", "session": median[-1].session, "first_seq": median[0].seq,
                               "last_seq": median[-1].seq, "calibration_score": pytest.approx(scores[order[39]]),
                               "rank": 39, "of": 80}
    assert table["threshold"] == bundle.threshold and table["base_score"] == bundle.score(median)["score"]
    assert [row["name"] for row in table["columns"]] == bundle.manifest["normalization"]["tcn_columns"]
    assert "k of the last n scored rows" in table["note"]

    def score(name, move):
        vector = median[-1].vector.copy()
        vector[MENA.index(name)] += move
        return bundle.score([*median[:-1], replace(median[-1], vector=vector)])["score"]
    for row in table["columns"]:
        for direction, sign in (("up", 1), ("down", -1)):
            change = row[direction]
            assert score(row["name"], sign * change) > table["threshold"] >= score(row["name"],
                                                                                 sign * change * (1 - 1e-3)), row


def test_manifest_records_classes_mask_scale_rule_ranges_wording_and_sources(trained):
    """Design B6b 1.4 and section 5: under schema 2 the manifest names legacy_schema_2 for the parameters (with the
    arguments given) and for the normalization (every column neural and in the mask, the pooled scale), an empty rule
    channel with the alarm rule, the wording of question Q6 with its source mark (the lead's, 2026-11-24), both
    learning curves, and the source hash of scripts/protocol_v5.py. Package B11: with no column of class
    rule_differenced the rule channel has no limitation and the manifest only its two limitations, and the bundle
    extracts from every bin (Bundle.min_bin_pages None, question Q10)."""
    from safeguard.training import LEGACY_SCALE, RULE_CHANNEL_ONLY
    _, output, _ = trained
    manifest = json.loads((output / "manifest.json").read_text())
    parameters = manifest["parameters"]
    assert (parameters["rule"], parameters["given"], parameters["overrides"]) == (
        "legacy_schema_2", {"epochs": 1, "batch_size": 16, "fpr": 0.1}, {})
    assert manifest["normalization"] == {"rule": "legacy_schema_2", "columns": dict.fromkeys(GLOBAL_NAMES, "neural"),
                                         "tcn_columns": list(GLOBAL_NAMES), "scale": {"rule": LEGACY_SCALE}}
    assert {key: manifest["rule_channel"][key] for key in ("columns", "ranges", "k", "n")} == {
        "columns": [], "ranges": {}, "k": 3, "n": 5}
    wording = manifest["analysis_wording"]["rule_channel_only"]
    assert wording == RULE_CHANNEL_ONLY and wording["source"] == (
        "NAVRH kap. 8.2, zložené vykonávateľom, potvrdené vedúcim 2026-11-24")
    assert wording["text"].startswith("Všetku detekciu nesie pravidlový kanál: deklarované pravidlá s rozsahom z "
                                      "`train` a `calibration`; nikdy sa neuvádzajú ako neurónová detekcia.")
    assert manifest["rule_channel"]["limitation"] is None
    assert manifest["limitations"] == [
        "No attack detection or held-out false-alarm metric is inferred from training.",
        "Classifier labels describe collection workload settings; they are not per-process ground truth."]
    assert load_bundle(output, allow_diagnostic=True).min_bin_pages is None
    training = manifest["training"]
    assert [h["epoch"] for h in training["history"]] == [1] == [h["epoch"] for h in training["classifier_history"]]
    assert set(training["history"][0]) == {"epoch", "train_prediction_loss", "dev_prediction_loss"}
    root = Path(__file__).resolve().parents[2]
    assert manifest["provenance"]["source_sha256"]["scripts/protocol_v5.py"] == digest(root / "scripts/protocol_v5.py")


def test_the_wording_of_the_rule_channel_is_proposal_8_2_word_for_word_with_the_leads_source():
    """Question Q6, the lead's answer (2026-11-24): the pre-written wording is accepted, its source mark is exactly the
    lead's string, and chapter 8.2 of the proposal holds the same wording word for word (whitespace collapsed, since
    the Markdown wraps its lines), with that source sentence and the mark of the change (closes F1 of the B6b
    verification, 'not verbatim'). The status keeps its key with the confirmed text."""
    from safeguard.training import RULE_CHANNEL_ONLY
    text = (Path(__file__).resolve().parents[2] / "docs/NAVRH_PROTOKOL_V5.sk.md").read_text(encoding="utf-8")
    chapter = " ".join(text[text.index("### 8.2 "):text.index("### 8.3 ")].split())
    start = chapter.index("„Všetku detekciu nesie pravidlový kanál:")
    assert chapter[start + 1:chapter.index("“", start)] == " ".join(RULE_CHANNEL_ONLY["text"].split())
    assert RULE_CHANNEL_ONLY["source"] == "NAVRH kap. 8.2, zložené vykonávateľom, potvrdené vedúcim 2026-11-24"
    assert RULE_CHANNEL_ONLY["source"] in chapter
    assert "(zmena vedúceho 2026-11-24, odpoveď na otázku Q6)" in chapter
    assert set(RULE_CHANNEL_ONLY) == {"text", "source", "status"}
    assert RULE_CHANNEL_ONLY["status"].startswith("pre-written: confirmed by the lead 2026-11-24 (question Q6")
