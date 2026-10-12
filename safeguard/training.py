"""Train, select and calibrate from explicit, disjoint corpus roles.

Original hyptcn3 integration. No test feature arrays are loaded during fitting.
Diagnostic bundles demonstrate mechanics only and cannot be loaded for normal
deployment. Workload classification is distinct from maliciousness detection.
"""
from collections import deque
from datetime import datetime, timezone
import copy
import json
import math
import os
from pathlib import Path
import random
import shutil
import tempfile

import numpy as np
import torch
from torch import nn

from features.archive import load as load_archive
from .bundle import SCHEMA, digest
from .features import (FeatureNormalizer, WindowBuffer, arrays, check_frame,
                       feature_contract, frames_from_archive)
from .model import (Classifier, Predictor, SCORE_FORMULA, LOSS_FORMULA,
                    anomaly_score, architecture, prediction_errors)

ROLES = ("train", "dev", "calibration", "test_benign")


def _json(path):
    return json.loads(Path(path).read_text())


def _resolve(base, path):
    path = Path(path)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _validate_current_semantics(extractor_hashes, profile_hashes, protocol):
    """A schema name alone cannot establish unchanged extraction semantics."""
    root = Path(__file__).resolve().parents[1]
    current_extractors = {str(file.relative_to(root)): digest(file)
                          for directory in (root / "features", root / "guestparse")
                          for file in directory.rglob("*.py") if "tests" not in file.parts}
    if extractor_hashes != current_extractors:
        raise ValueError("stale extractor implementation; re-audit raw captures with current source")
    if not isinstance(protocol.get("profile"), str):
        raise ValueError("production protocol lacks guest profile path")
    profile = _resolve(root, protocol["profile"])
    if not profile.is_dir():
        raise ValueError("current guest profile is missing")
    current_profile = {str(file.relative_to(profile)): digest(file)
                       for file in profile.rglob("*") if file.is_file()}
    if not current_profile or profile_hashes != current_profile:
        raise ValueError("stale guest profile; restore the captured profile before training")


def validate_index(path, diagnostic=False):
    """Recheck frozen artifacts; inspecting test metadata/hashes is not fitting."""
    path = Path(path).resolve()
    doc = _json(path)
    if doc.get("schema") != "hyptcn3/corpus-index/1":
        raise ValueError("unsupported corpus index")
    if not diagnostic and (doc.get("complete") is not True or doc.get("diagnostic", False)):
        raise ValueError("production training requires a complete non-diagnostic corpus")
    if (doc.get("normalization_fit_role", "train") != "train"
            or doc.get("threshold_fit_role", "calibration") != "calibration"):
        raise ValueError("unsupported corpus fitting roles")
    protocol_path = _resolve(path.parent, doc["protocol"])
    protocol_hash = digest(protocol_path)
    protocol = _json(protocol_path)
    if protocol_hash != doc["protocol_sha256"] or protocol != doc["protocol_config"]:
        raise ValueError("corpus protocol checksum/configuration mismatch")
    if protocol.get("schema") != "hyptcn3/collection-protocol/1":
        raise ValueError("unsupported collection protocol")
    records = copy.deepcopy(doc["sessions"])
    if not records:
        raise ValueError("empty corpus")
    ids, files, hashes, assignments = set(), set(), set(), set()
    boot_roles, group_roles, boot_groups, group_boots = {}, {}, {}, {}
    layouts, extractors, environments, profiles = set(), set(), set(), set()
    for record in records:
        role, group, boot = record["role"], record["group"], record["boot_id"]
        if role not in ROLES or record.get("typ") != "benign":
            raise ValueError("only explicit benign corpus roles are accepted")
        if not all(isinstance(value, str) and value for value in (record["id"], group, boot, record["scenario"])):
            raise ValueError("missing session identity")
        if record["id"] in ids:
            raise ValueError("duplicate session identity")
        ids.add(record["id"])
        for registry, key in ((boot_roles, boot), (group_roles, group)):
            if registry.setdefault(key, role) != role:
                raise ValueError("boot/group shared across dataset roles")
        if boot_groups.setdefault(boot, group) != group or group_boots.setdefault(group, boot) != boot:
            raise ValueError("boot/group mapping must be one to one")
        assignment = (group, record["scenario"])
        if assignment in assignments:
            raise ValueError("duplicate group/scenario assignment")
        assignments.add(assignment)
        if record.get("protocol_sha256") != protocol_hash:
            raise ValueError("session protocol mismatch")
        for field in ("session", "audit", "features"):
            file = _resolve(path.parent, record[field])
            record[field] = str(file)
            if digest(file) != record[field + "_sha256"]:
                raise ValueError(field + " checksum mismatch")
        if record["features"] in files or record["features_sha256"] in hashes:
            raise ValueError("duplicate feature archive")
        files.add(record["features"])
        hashes.add(record["features_sha256"])
        meta, audit = _json(record["session"]), _json(record["audit"])
        if meta.get("schema") != "hyptcn3/collection-session/1" or audit.get("schema") != "hyptcn3/collection-audit/1":
            raise ValueError("unsupported session/audit provenance")
        for key in ("role", "group", "scenario", "typ", "protocol_sha256"):
            if meta.get(key) != record[key]:
                raise ValueError("index/session mismatch: " + key)
        if meta.get("session_id") != record["id"] or meta["guest_before"]["boot_id"] != boot:
            raise ValueError("index/session identity mismatch")
        if not diagnostic and (meta.get("diagnostic") or audit["values"].get("diagnostic")):
            raise ValueError("diagnostic artifacts cannot be used in production training")
        values = audit["values"]
        if (values.get("accepted") is not True or values.get("reasons")
                or values.get("role") != role or values.get("protocol_sha256") != protocol_hash
                or values.get("session_sha256") != record["session_sha256"]
                or values.get("features_sha256") != record["features_sha256"]
                or _resolve(Path(record["audit"]).parent, values["features"]) != Path(record["features"])):
            raise ValueError("audit provenance mismatch or unaccepted audit")
        layouts.add(json.dumps(values["layout"], sort_keys=True))
        extractors.add(json.dumps(values["extractor_sha256"], sort_keys=True))
        profiles.add(json.dumps(meta.get("profile_sha256", {}), sort_keys=True))
        if not diagnostic and (not meta.get("profile_sha256") or not values["extractor_sha256"]):
            raise ValueError("production corpus lacks profile/extractor provenance")
        guest = meta["guest_before"]
        environments.add((guest["kernel"], guest["stack_sha256"], meta["collector_sha256"]))
        if not all(math.isfinite(record[k]) for k in ("start", "end")) or record["end"] < record["start"]:
            raise ValueError("invalid session time range")
        if record["scenario"] not in protocol["scenarios"]:
            raise ValueError("scenario outside protocol")
    if len(layouts) != 1 or len(extractors) != 1 or len(environments) != 1 or len(profiles) != 1:
        raise ValueError("mixed layout, extractor or guest/collector environment")
    if not diagnostic:
        _validate_current_semantics(json.loads(next(iter(extractors))),
                                    json.loads(next(iter(profiles))), protocol)
    for role in ROLES:
        selected = [r for r in records if r["role"] == role]
        if not selected:
            raise ValueError("missing corpus role: " + role)
        if not diagnostic:
            expected = {f"{role}-{i + 1}" for i in range(protocol["roles"][role])}
            for scenario in protocol["scenarios"]:
                if {r["group"] for r in selected if r["scenario"] == scenario} != expected:
                    raise ValueError("incomplete planned allocation")
    for left, right in zip(ROLES, ROLES[1:]):
        if max(r["end"] for r in records if r["role"] == left) >= min(r["start"] for r in records if r["role"] == right):
            raise ValueError("corpus roles must be chronologically separated")
    return doc, protocol, records


class Windows:
    """Normalized session arrays and small indices, not copied sliding tensors."""

    def __init__(self, sessions, normalizer, contract, classes):
        self.sessions, self.indices = [], []
        self.window_rows = contract["window_rows"]
        self.max_gap_s = contract["max_gap_s"]
        for record, frames in sessions:
            if record["scenario"] not in classes:
                raise ValueError("workload class absent from training role")
            values = normalizer.transform(*arrays(frames))
            session_index = len(self.sessions)
            self.sessions.append((record, frames, *values, classes.index(record["scenario"])))
            buffer = WindowBuffer(contract["window_rows"], contract["max_gap_s"])
            for position, frame in enumerate(frames):
                check_frame(frame, contract)
                if buffer.push(frame) is not None:
                    self.indices.append((session_index, position))
        if not self.indices:
            raise ValueError("role has no eligible windows")

    def batch(self, selection):
        global_values, local_values, labels = [], [], []
        for index in selection:
            session, end = self.indices[int(index)]
            _, _, global_array, local_array, label = self.sessions[session]
            start = end + 1 - self.window_rows
            global_values.append(global_array[start:end + 1])
            local_values.append(local_array[start:end + 1])
            labels.append(label)
        return (torch.as_tensor(np.stack(global_values), dtype=torch.float32),
                torch.as_tensor(np.stack(local_values), dtype=torch.float32),
                torch.tensor(labels, dtype=torch.long))

    def batches(self, batch_size, order=None):
        if order is None:
            order = np.arange(len(self.indices))
        for start in range(0, len(order), batch_size):
            yield self.batch(order[start:start + batch_size])


def _loss(predictor, classifier, global_values, local_values, labels):
    prediction = predictor(global_values[:, :-1], local_values[:, :-1])
    global_error, bin_error = prediction_errors(prediction, global_values[:, -1], local_values[:, -1])
    pred_loss = 0.5 * global_error.mean() + 0.5 * bin_error.mean()
    class_loss = nn.functional.cross_entropy(classifier(global_values, local_values), labels)
    return pred_loss, class_loss


def _evaluate(predictor, classifier, dataset, batch_size):
    total = np.zeros(2)
    predictor.eval()
    classifier.eval()
    with torch.inference_mode():
        for g, local, labels in dataset.batches(batch_size):
            loss = _loss(predictor, classifier, g, local, labels)
            total += np.array([float(value) for value in loss]) * len(labels)
    result = total / len(dataset.indices)
    if not np.isfinite(result).all():
        raise ValueError("non-finite development loss")
    return result


def calibrate(scores, dataset, *, fpr, k, n, interval_s, diagnostic):
    scores = np.asarray(scores, dtype=np.float64)
    if (not math.isfinite(fpr) or not 0 < fpr < 1 or not 1 <= k <= n
            or not math.isfinite(interval_s) or interval_s <= 0
            or scores.ndim != 1 or len(scores) != len(dataset.indices)):
        raise ValueError("invalid calibration parameters or score index")
    required = 20 if diagnostic else max(100, math.ceil(10 / fpr))
    if len(scores) < required or not np.isfinite(scores).all() or (scores < 0).any():
        raise ValueError(f"calibration needs at least {required} finite nonnegative scores")
    threshold = float(np.quantile(scores, 1 - fpr, method="higher"))
    history, previous, active, events = deque(maxlen=n), None, False, 0
    for score, (session, end) in zip(scores, dataset.indices):
        frame = dataset.sessions[session][1][end]
        current = (session, frame.seq, frame.timestamp, frame.chain_id)
        if (previous is None or current[0] != previous[0] or current[1] != previous[1] + 1
                or current[3] != previous[3] or not 0 < current[2] - previous[2] <= dataset.max_gap_s):
            history.clear()
            active = False
        history.append(bool(score > threshold))
        condition = len(history) == n and sum(history) >= k
        events += int(condition and not active)
        active, previous = condition, current
    exposure_hours = len(scores) * interval_s / 3600
    return {"role": "calibration", "threshold": threshold, "k": k, "n": n,
            "method": "benign_score_quantile_higher", "comparison": ">",
            "fpr_design": fpr, "n_scores": len(scores), "minimum_scores": required,
            "window_exceedance_fraction": float((scores > threshold).mean()),
            "alarm_events": events, "scorable_hours": exposure_hours,
            "calibration_alarm_events_per_hour": events / exposure_hours,
            "exposure_definition": "scored targets times nominal interval; warmup/gaps excluded",
            "event_definition": "k of n after n scored targets; rising edges; reset at barriers",
            "diagnostic": diagnostic,
            "note": "Calibration frequency is not a held-out false-alarm measurement or guarantee."}


def train_bundle(corpus_path, output_dir, *, window_rows=32, max_gap_s=7.5,
                 epochs=10, seed=0, batch_size=32, fpr=0.01, k=3, n=5,
                 diagnostic=False):
    if (type(window_rows) is not int or window_rows < 2 or type(epochs) is not int or epochs < 1
            or type(batch_size) is not int or batch_size < 1 or type(seed) is not int
            or not math.isfinite(max_gap_s) or max_gap_s <= 0
            or not math.isfinite(fpr) or not 0 < fpr < 1
            or type(k) is not int or type(n) is not int or not 1 <= k <= n):
        raise ValueError("invalid training parameters")
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise FileExistsError("bundle output exists; choose a new immutable path")
    index, protocol, records = validate_index(corpus_path, diagnostic)
    if window_rows != protocol["window_rows"] or max_gap_s != protocol["max_gap_s"]:
        raise ValueError("training temporal settings differ from frozen protocol")
    sessions = {role: [] for role in ROLES[:-1]}
    contract = None
    for record in records:
        if record["role"] == "test_benign":
            continue  # No array/statistic from final test enters fitting.
        frames = list(frames_from_archive(load_archive(record["features"]), record["id"]))
        if not frames or frames[0].timestamp != record["start"] or frames[-1].timestamp != record["end"]:
            raise ValueError("feature times differ from frozen session index")
        if any(not frame.valid for frame in frames):
            raise ValueError("accepted corpus archive contains invalid model rows")
        if contract is None:
            contract = feature_contract(frames[0], window_rows, max_gap_s)
        if frames[0].layout != _json(record["audit"])["values"]["layout"]:
            raise ValueError("feature/audit layout mismatch")
        for frame in frames:
            check_frame(frame, contract)
        sessions[record["role"]].append((record, frames))
    fit_frames = [frame for _, frames in sessions["train"] for frame in frames
                  if frame.valid and frame.has_predecessor and not frame.full]
    normalizer = FeatureNormalizer.fit(fit_frames)
    classes = sorted({record["scenario"] for record, _ in sessions["train"]})
    if len(classes) < 2:
        raise ValueError("activity classification requires at least two train workload classes")
    datasets = {role: Windows(data, normalizer, contract, classes) for role, data in sessions.items()}
    required_calibration = 20 if diagnostic else max(100, math.ceil(10 / fpr))
    if len(datasets["calibration"].indices) < required_calibration:
        raise ValueError(f"calibration needs at least {required_calibration} eligible windows")
    config = architecture(window_rows)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    old_threads = torch.get_num_threads()
    torch.set_num_threads(min(old_threads, 4))
    try:
        predictor, classifier = Predictor(config), Classifier(config, len(classes))
        optimizer = torch.optim.Adam([*predictor.parameters(), *classifier.parameters()], lr=0.001)
        generator = np.random.default_rng(seed)
        best = [float("inf"), float("inf")]
        states, selected_epochs, history = [None, None], [None, None], []
        for epoch in range(1, epochs + 1):
            predictor.train()
            classifier.train()
            losses, count = np.zeros(2), 0
            for g, local, labels in datasets["train"].batches(batch_size, generator.permutation(len(datasets["train"].indices))):
                optimizer.zero_grad(set_to_none=True)
                pred_loss, class_loss = _loss(predictor, classifier, g, local, labels)
                loss = pred_loss + class_loss
                if not torch.isfinite(loss):
                    raise ValueError("non-finite training loss")
                loss.backward()
                nn.utils.clip_grad_norm_([*predictor.parameters(), *classifier.parameters()], 5)
                optimizer.step()
                losses += np.array([float(pred_loss.detach()), float(class_loss.detach())]) * len(labels)
                count += len(labels)
            dev = _evaluate(predictor, classifier, datasets["dev"], batch_size)
            history.append({"epoch": epoch, "train_prediction_loss": float(losses[0] / count),
                            "train_classification_loss": float(losses[1] / count),
                            "dev_prediction_loss": float(dev[0]), "dev_classification_loss": float(dev[1])})
            for i, model in enumerate((predictor, classifier)):
                if dev[i] < best[i]:
                    best[i], states[i], selected_epochs[i] = float(dev[i]), copy.deepcopy(model.state_dict()), epoch
        predictor.load_state_dict(states[0])
        classifier.load_state_dict(states[1])
        predictor.eval()
        classifier.eval()
        scores = []
        with torch.inference_mode():
            for g, local, _ in datasets["calibration"].batches(batch_size):
                errors = prediction_errors(predictor(g[:, :-1], local[:, :-1]), g[:, -1], local[:, -1])
                scores.extend(anomaly_score(*errors).tolist())
        calibration = calibrate(scores, datasets["calibration"], fpr=fpr, k=k, n=n,
                                interval_s=protocol["interval_s"], diagnostic=diagnostic)
        root = Path(__file__).resolve().parents[1]
        source_hashes = {str(path.relative_to(root)): digest(path)
                         for directory in (root / "safeguard", root / "tcn", root / "features", root / "guestparse")
                         for path in directory.rglob("*.py") if "tests" not in path.parts}
        first_meta = _json(records[0]["session"])
        first_audit = _json(records[0]["audit"])
        environment = {"kernel": first_meta["guest_before"]["kernel"],
                       "stack_sha256": first_meta["guest_before"]["stack_sha256"],
                       "collector_sha256": first_meta["collector_sha256"],
                       "profile_sha256": first_meta.get("profile_sha256", {}),
                       "extractor_sha256": first_audit["values"]["extractor_sha256"]}
        manifest = {"schema": SCHEMA, "diagnostic": diagnostic,
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "feature_contract": contract, "normalizer": normalizer.to_dict(),
                    "architecture": config, "classes": classes,
                    "environment": environment,
                    "classification_task": "recorded benign workload scenario; not maliciousness or malware family",
                    "score_formula": SCORE_FORMULA, "loss_formula": LOSS_FORMULA,
                    "calibration": calibration, "weights": {},
                    "training": {"seed": seed, "epochs": epochs, "batch_size": batch_size,
                                 "normalization_fit_role": "train", "checkpoint_selection_role": "dev",
                                 "selected_predictor_epoch": selected_epochs[0],
                                 "selected_classifier_epoch": selected_epochs[1], "history": history,
                                 "windows": {role: len(data.indices) for role, data in datasets.items()},
                                 "normalization_rows": len(fit_frames), "test_feature_arrays_loaded": False},
                    "provenance": {"corpus_index": str(Path(corpus_path).resolve()),
                                   "corpus_index_sha256": digest(corpus_path),
                                   "protocol_sha256": index["protocol_sha256"], "protocol": protocol,
                                   "source_sha256": source_hashes, "sessions": records},
                    "limitations": ["No attack detection or held-out false-alarm metric is inferred from training.",
                                    "Classifier labels describe collection workload settings; they are not per-process ground truth."]}
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        lock = output_dir.with_name(output_dir.name + ".lock")
        with lock.open("x"):
            temporary = Path(tempfile.mkdtemp(prefix="." + output_dir.name + ".", dir=output_dir.parent))
            try:
                if output_dir.exists():
                    raise FileExistsError("bundle output already exists")
                for name, model in (("predictor", predictor), ("classifier", classifier)):
                    file = temporary / (name + ".pt")
                    torch.save(model.state_dict(), file)
                    manifest["weights"][name] = {"file": file.name, "sha256": digest(file)}
                (temporary / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
                # Verify serialized form before publishing the directory.
                from .bundle import load_bundle
                loaded = load_bundle(temporary, allow_diagnostic=diagnostic)
                sample = datasets["dev"]
                s, end = sample.indices[0]
                loaded.score(sample.sessions[s][1][end + 1 - window_rows:end + 1])
                os.rename(temporary, output_dir)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
                lock.unlink()
        return {"bundle": str(output_dir), "diagnostic": diagnostic, "classes": classes,
                "calibration": calibration, "training": manifest["training"]}
    finally:
        torch.set_num_threads(old_threads)
