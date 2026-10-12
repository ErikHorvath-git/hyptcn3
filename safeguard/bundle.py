"""Versioned model bundle with explicit feature, provenance and scoring contracts.

Original integration for hyptcn3. Loading verifies hashes for corruption and
compatibility; hashes do not authenticate a bundle obtained from an untrusted party.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import torch

from .features import FeatureNormalizer, WindowBuffer, Frame, arrays, check_frame
from .model import Classifier, Predictor, SCORE_FORMULA, LOSS_FORMULA, anomaly_score, prediction_errors

SCHEMA = "hyptcn3/safeguard-bundle/1"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass
class Bundle:
    manifest: dict
    predictor: Predictor
    classifier: Classifier
    normalizer: FeatureNormalizer

    @property
    def contract(self):
        return self.manifest["feature_contract"]

    @property
    def threshold(self):
        return float(self.manifest["calibration"]["threshold"])

    @property
    def k(self):
        return self.manifest["calibration"]["k"]

    @property
    def n(self):
        return self.manifest["calibration"]["n"]

    def score(self, window):
        if len(window) != self.contract["window_rows"]:
            raise ValueError("window length differs from bundle")
        buffer = WindowBuffer(self.contract["window_rows"], self.contract["max_gap_s"])
        accepted = None
        for frame in window:
            check_frame(frame, self.contract)
            accepted = buffer.push(frame)
        if accepted is None:
            raise ValueError("invalid or discontinuous scoring window: " + str(buffer.reason))
        global_values, local_values = self.normalizer.transform(*arrays(window))
        global_tensor = torch.as_tensor(global_values, dtype=torch.float32).unsqueeze(0)
        local_tensor = torch.as_tensor(local_values, dtype=torch.float32).unsqueeze(0)
        with torch.inference_mode():
            prediction = self.predictor(global_tensor[:, :-1], local_tensor[:, :-1])
            global_error, bin_errors = prediction_errors(prediction, global_tensor[:, -1], local_tensor[:, -1])
            score = anomaly_score(global_error, bin_errors)
            probabilities = self.classifier(global_tensor, local_tensor).softmax(dim=-1)[0]
        values = [float(score[0]), float(global_error[0]), *bin_errors[0].tolist(), *probabilities.tolist()]
        if not all(math.isfinite(v) for v in values):
            raise ValueError("non-finite model output")
        classes = self.manifest["classes"]
        return {"score": values[0], "global_error": values[1], "bin_errors": bin_errors[0].tolist(),
                "activity": classes[int(probabilities.argmax())],
                "activity_probabilities": dict(zip(classes, probabilities.tolist()))}


def load_bundle(path, allow_diagnostic=False):
    path = Path(path)
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported safeguard bundle")
    if type(manifest.get("diagnostic")) is not bool:
        raise ValueError("missing bundle diagnostic status")
    if manifest["diagnostic"] and not allow_diagnostic:
        raise ValueError("diagnostic bundle is not enabled for deployment")
    if manifest.get("score_formula") != SCORE_FORMULA or manifest.get("loss_formula") != LOSS_FORMULA:
        raise ValueError("unsupported scoring contract")
    classes = manifest.get("classes")
    if (not isinstance(classes, list) or not classes or any(not isinstance(c, str) or not c for c in classes)
            or len(set(classes)) != len(classes)):
        raise ValueError("invalid classifier classes")
    contract = manifest["feature_contract"]
    architecture = manifest["architecture"]
    if architecture["window_rows"] != contract["window_rows"]:
        raise ValueError("model and feature window mismatch")
    normalizer = FeatureNormalizer.from_dict(manifest["normalizer"])
    training = manifest["training"]
    if (training.get("normalization_fit_role") != "train"
            or training.get("checkpoint_selection_role") != "dev"
            or training.get("test_feature_arrays_loaded") is not False
            or training.get("normalization_rows") != normalizer.fit_rows):
        raise ValueError("invalid normalization/training provenance")
    calibration = manifest["calibration"]
    threshold = calibration["threshold"]
    if not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or threshold < 0:
        raise ValueError("invalid calibrated threshold")
    if (type(calibration.get("k")) is not int or type(calibration.get("n")) is not int
            or not 1 <= calibration["k"] <= calibration["n"]):
        raise ValueError("invalid alarm rule")
    if calibration.get("diagnostic") != manifest["diagnostic"]:
        raise ValueError("inconsistent calibration status")
    if calibration.get("role") != "calibration":
        raise ValueError("threshold must come from calibration role")
    fpr = calibration.get("fpr_design")
    if not isinstance(fpr, (int, float)) or not math.isfinite(fpr) or not 0 < fpr < 1:
        raise ValueError("invalid calibration quantile")
    minimum = 20 if manifest["diagnostic"] else max(100, math.ceil(10 / fpr))
    if type(calibration.get("n_scores")) is not int or calibration["n_scores"] < minimum:
        raise ValueError("insufficient calibration evidence")
    if training.get("windows", {}).get("calibration") != calibration["n_scores"]:
        raise ValueError("calibration count differs from training provenance")
    protocol = manifest["provenance"]["protocol"]
    if (protocol.get("window_rows") != contract["window_rows"]
            or protocol.get("max_gap_s") != contract["max_gap_s"]):
        raise ValueError("feature timing differs from frozen protocol")
    if (calibration.get("method") != "benign_score_quantile_higher"
            or calibration.get("comparison") != ">"):
        raise ValueError("unsupported calibration rule")
    if contract.get("schema") != "hyptcn3/safeguard-features/1":
        raise ValueError("unsupported feature contract")
    if not math.isfinite(contract["max_gap_s"]) or contract["max_gap_s"] <= 0:
        raise ValueError("invalid temporal contract")
    # Validate names, physical geometry and types before accepting a bundle,
    # independently of the first incoming frame.
    dummy = Frame("contract-validation", 0, 0.0, np.zeros(22),
                  np.zeros((len(contract["biny"]), 4)), tuple(contract["biny"]),
                  {"model_valid": True, "traversals_complete": True,
                   "inconclusive": [], "findings": [], "read_errors": 0, "filled_zero": 0},
                  "contract-validation", contract["layout"])
    check_frame(dummy, contract)
    predictor, classifier = Predictor(architecture), Classifier(architecture, len(classes))
    for name, model in (("predictor", predictor), ("classifier", classifier)):
        expected = name + ".pt"
        record = manifest["weights"][name]
        if record.get("file") != expected or digest(path / expected) != record.get("sha256"):
            raise ValueError("bundle weight checksum mismatch: " + name)
        model.load_state_dict(torch.load(path / expected, map_location="cpu", weights_only=True), strict=True)
        model.eval()
    return Bundle(manifest, predictor, classifier, normalizer)
