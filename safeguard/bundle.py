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
from features.quality import BEHAVIOR_POLICY, protocol_policy

from .features import (CONTRACT_SCHEMA, MENA, RULE_RANGE_ROLES, FeatureNormalizer, WindowBuffer, Frame, check_frame,
                       rule_quantity)
from .model import (Classifier, Predictor, SCORE_FORMULA, LOSS_FORMULA, OLD_SCORE_FORMULA, OLD_LOSS_FORMULA,
                    anomaly_score, column_errors, prediction_errors, top_bin_mean)

SCHEMA = "hyptcn3/safeguard-bundle/1"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def window_inputs(window, contract, normalizer):
    """The normalized inputs (window_rows, len(input_names)) and (window_rows, len(bins), 4) of one scoring window,
    checked as every scorer checks it (design B6b 1.1): every frame matches the contract, the window is window_rows
    continuous measured rows (WindowBuffer), and under a rule with a differenced input it is [anchor, *rows], the
    anchor the last measured row of the same session before rows[0] (DIFFERENCE_POLICY of safeguard/features.py)."""
    window = list(window)
    rows, anchored = contract["window_rows"], int(normalizer.rule.anchored)
    if len(window) != rows + anchored:
        raise ValueError(f"window length differs from bundle: {len(window)} frames, the bundle takes {rows + anchored}"
                         + (f" (the measured row before the window and window_rows {rows}, rule "
                            f"{normalizer.rule.name})" if anchored else ""))
    buffer = WindowBuffer(rows, contract["max_gap_s"])
    accepted = None
    for frame in window:
        check_frame(frame, contract)
    for frame in window[anchored:]:
        accepted = buffer.push(frame)
    if accepted is None:
        raise ValueError("invalid or discontinuous scoring window: " + str(buffer.reason))
    if anchored and not (window[0].measured and window[0].session == window[1].session
                         and window[0].seq < window[1].seq and window[0].timestamp < window[1].timestamp):
        raise ValueError("the first frame of the window must be a measured row of its session before the window (the "
                         "anchor of its first differences)")
    global_values, local_values = normalizer.inputs(window)
    return global_values[anchored:], local_values[anchored:]


def _range(value, quantity):
    """A range of the rule channel: {quantity, min, max, ...}, min <= max finite (safeguard/features.py
    rule_channel)."""
    return (type(value) is dict and value.get("quantity") == quantity
            and all(not isinstance(value.get(key), bool) and isinstance(value.get(key), (int, float))
                    and math.isfinite(value[key]) for key in ("min", "max"))
            and value["min"] <= value["max"])


def check_rule_channel(manifest, normalizer):
    """The manifest's rule_channel (design B6b 1.3) against the normalization rule and the neural alarm rule."""
    spec, rule = manifest.get("rule_channel"), normalizer.rule
    if type(spec) is not dict:
        raise ValueError("bundle has no rule_channel (package B6b): the ranges of the rule channel over "
                         + " and ".join(RULE_RANGE_ROLES))
    if spec.get("columns") != list(rule.rule_names):
        raise ValueError(f"rule_channel columns differ from the columns of class rule or rule_differenced of rule "
                         f"{rule.name}")
    ranges = spec.get("ranges")
    if (type(ranges) is not dict or set(ranges) != set(rule.rule_names)
            or not all(_range(ranges[name], rule_quantity(rule, name)) for name in rule.rule_names)):
        raise ValueError("rule_channel ranges: for each of its columns {quantity, min, max}, the quantity of its "
                         "class (value or since_session_start) and finite min <= max")
    calibration = manifest["calibration"]
    if (spec.get("k"), spec.get("n")) != (calibration.get("k"), calibration.get("n")):
        raise ValueError("rule_channel alarm rule differs from the neural channel's k of n (calibration)")
    if spec.get("roles") != list(RULE_RANGE_ROLES):
        raise ValueError("rule_channel ranges come from the roles " + " and ".join(RULE_RANGE_ROLES))


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

    @property
    def anchored(self):
        """True when a window needs the measured row before it (a differenced input of the TCN)."""
        return self.normalizer.rule.anchored

    @property
    def required_rows(self):
        """The frames score() takes: window_rows, and the measured row before them when anchored."""
        return self.contract["window_rows"] + int(self.anchored)

    @property
    def min_bin_pages(self):
        """The bins the eight memory columns of a live frame come from (question Q10 to the lead, 2026-11-24): the
        normalization rule's min_bin_pages, the bins it scores (analysis.scale.min_bin_pages, features/snapshot.py
        counted_bin), as the audit extracted the bundle's archives; None under legacy_schema_2 (every bin).
        safeguard/runtime.py run_directory passes it to every extraction."""
        return self.normalizer.rule.min_bin_pages

    @property
    def rule_channel(self):
        """The rule channel for the runtime (safeguard/runtime.py RuleChannel): columns, the quantity each is judged
        by, ranges, k and n."""
        spec = self.manifest["rule_channel"]
        return {"columns": list(spec["columns"]),
                "quantity": {name: spec["ranges"][name]["quantity"] for name in spec["columns"]},
                "ranges": {name: [spec["ranges"][name]["min"], spec["ranges"][name]["max"]] for name in spec["columns"]},
                "k": spec["k"], "n": spec["n"]}

    def window_buffer(self):
        """The WindowBuffer whose windows score() takes."""
        return WindowBuffer(self.contract["window_rows"], self.contract["max_gap_s"], anchored=self.anchored)

    def score(self, window):
        """The score of the last row of `window` (required_rows frames, as window_buffer() returns them), with its
        attribution (design B6b 1.2): the error of each input column (they sum to global_error), of each scored bin,
        the worst bin (its error is the bin part of the score) and the mean of the three worst bins."""
        global_values, local_values = window_inputs(window, self.contract, self.normalizer)
        global_tensor = torch.as_tensor(global_values, dtype=torch.float32).unsqueeze(0)
        local_tensor = torch.as_tensor(local_values, dtype=torch.float32).unsqueeze(0)
        with torch.inference_mode():
            prediction = self.predictor(global_tensor[:, :-1], local_tensor[:, :-1])
            global_error, bin_errors = prediction_errors(prediction, global_tensor[:, -1], local_tensor[:, -1])
            columns = column_errors(prediction[0], global_tensor[:, -1])[0].tolist()
            score = anomaly_score(global_error, bin_errors)
            top = float(top_bin_mean(bin_errors)[0])
            probabilities = self.classifier(global_tensor, local_tensor).softmax(dim=-1)[0]
        bins = bin_errors[0].tolist()
        values = [float(score[0]), float(global_error[0]), top, *bins, *columns, *probabilities.tolist()]
        if not all(math.isfinite(v) for v in values):
            raise ValueError("non-finite model output")
        classes = self.manifest["classes"]
        per_bin = [{"bin": b, "pages": pages, "error": error} for (b, pages), error in zip(self.normalizer.bins, bins)]
        worst = max(range(len(bins)), key=bins.__getitem__)  # The first of equal errors.
        return {"score": values[0], "global_error": values[1], "bin_errors": bins,
                "activity": classes[int(probabilities.argmax())],
                "activity_probabilities": dict(zip(classes, probabilities.tolist())),
                "attribution": {"columns": dict(zip(self.normalizer.input_names, columns)), "bins": per_bin,
                                "worst_bin": dict(per_bin[worst]), "top3_bin_mean": top}}


def load_bundle(path, allow_diagnostic=False):
    path = Path(path)
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported safeguard bundle")
    if type(manifest.get("diagnostic")) is not bool:
        raise ValueError("missing bundle diagnostic status")
    if manifest["diagnostic"] and not allow_diagnostic:
        raise ValueError("diagnostic bundle is not enabled for deployment")
    if manifest.get("score_formula") == OLD_SCORE_FORMULA or manifest.get("loss_formula") == OLD_LOSS_FORMULA:
        raise ValueError(f"bundle of the score formula before package B6b ({OLD_SCORE_FORMULA!r}: every column and every "
                         "bin, no normalization rule) is refused; retrain it")
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
    if protocol_policy(protocol) != BEHAVIOR_POLICY:
        raise ValueError("bundle requires the behavioral input protocol")
    if (protocol.get("window_rows") != contract["window_rows"]
            or protocol.get("max_gap_s") != contract["max_gap_s"]):
        raise ValueError("feature timing differs from frozen protocol")
    if (calibration.get("method") != "benign_score_quantile_higher"
            or calibration.get("comparison") != ">"):
        raise ValueError("unsupported calibration rule")
    if contract.get("schema") != CONTRACT_SCHEMA:
        raise ValueError("unsupported feature contract")
    if not math.isfinite(contract["max_gap_s"]) or contract["max_gap_s"] <= 0:
        raise ValueError("invalid temporal contract")
    # Validate names, physical geometry and types before accepting a bundle,
    # independently of the first incoming frame.
    dummy = Frame("contract-validation", 0, 0.0, np.zeros(len(MENA)),
                  np.zeros((len(contract["biny"]), 4)), tuple(contract["biny"]),
                  {"model_valid": True, "behavior_valid": True, "traversals_complete": True,
                   "inconclusive": [], "findings": [], "read_errors": 0, "filled_zero": 0},
                  "contract-validation", contract["layout"])
    check_frame(dummy, contract)
    normalizer.check_contract(contract)
    if architecture.get("global_features") != len(normalizer.input_names):
        raise ValueError(f"model inputs differ from the inputs of normalization rule {normalizer.rule.name}")
    check_rule_channel(manifest, normalizer)
    predictor, classifier = Predictor(architecture), Classifier(architecture, len(classes))
    for name, model in (("predictor", predictor), ("classifier", classifier)):
        expected = name + ".pt"
        record = manifest["weights"][name]
        if record.get("file") != expected or digest(path / expected) != record.get("sha256"):
            raise ValueError("bundle weight checksum mismatch: " + name)
        model.load_state_dict(torch.load(path / expected, map_location="cpu", weights_only=True), strict=True)
        model.eval()
    return Bundle(manifest, predictor, classifier, normalizer)
