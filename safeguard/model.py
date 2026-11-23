"""Shared-bin predictor and workload classifier for the safeguard.

Original integration using the causal TCN blocks in tcn.model (Bai et al.,
2018 architecture). These models predict behavior; they do not identify
malware families or establish detection accuracy without held-out experiments.

Package B6b (design B6b 1.2): the global branch takes the inputs of the normalization rule (the columns of class
neural or differenced, safeguard.features.NormalizationRule), the bins are the scored bins only, and the score is
attributed to each input column and each scored bin.
"""
import torch
from torch import nn

from features.archive import BEHAVIOR_NAMES
from tcn.model import TCN, TCNPrediktor, skontroluj_rf

GLOBAL_FEATURES = len(BEHAVIOR_NAMES)


# Package B6b: the global part is the mean over the TCN's input columns, the bin part over the scored bins (a bin of
# fewer than analysis.scale.min_bin_pages pages is no input). A bundle of the strings before B6b is refused by name
# (safeguard/bundle.py load_bundle).
SCORE_FORMULA = "0.5 * mean(squared_error of the tcn input columns) + 0.5 * max(masked_mse of the scored bins)"
LOSS_FORMULA = "0.5 * mean(squared_error of the tcn input columns) + 0.5 * mean(masked_mse of the scored bins)"
OLD_SCORE_FORMULA = "0.5 * mean(global_squared_error) + 0.5 * max(bin_masked_mse)"
OLD_LOSS_FORMULA = "0.5 * mean(global_squared_error) + 0.5 * mean(bin_masked_mse)"
# The sensitivity analysis next to the maximum over the bins (skeleton B6 section 4; three is the lead's judgment): the
# mean of the three worst scored bins (of all of them when fewer are scored).
TOP_BINS = 3


def architecture(window_rows=32, *, global_features=GLOBAL_FEATURES):
    """global_features: the number of global inputs, len(normalizer.input_names) (every column under the rule
    legacy_schema_2)."""
    blocks = 1
    while 1 + 4 * (2 ** blocks - 1) < window_rows:
        blocks += 1
    return {"global_features": global_features, "local_features": 4, "channels": 16,
            "kernel": 3, "blocks": max(4, blocks), "window_rows": window_rows,
            "dropout": 0.1, "classifier_pooling": "bin_mean_and_max"}


def validate_architecture(config):
    if (config.get("local_features") != 4 or config.get("classifier_pooling") != "bin_mean_and_max"):
        raise ValueError("unsupported safeguard architecture")
    if type(config.get("global_features")) is not int or not 1 <= config["global_features"] <= GLOBAL_FEATURES:
        raise ValueError(f"invalid architecture: global_features (the inputs of the normalization rule, 1 to "
                         f"{GLOBAL_FEATURES})")
    for key in ("channels", "kernel", "blocks", "window_rows"):
        if type(config.get(key)) is not int or not 1 <= config[key] <= 1024:
            raise ValueError("invalid architecture: " + key)
    if config["window_rows"] < 2 or config["blocks"] > 12 or config["kernel"] > 15:
        raise ValueError("invalid architecture bounds")
    if not 0 <= config.get("dropout", -1) < 1:
        raise ValueError("invalid dropout")
    skontroluj_rf(config["window_rows"], config["kernel"], config["blocks"])


def _kwargs(config):
    validate_architecture(config)
    return dict(kanaly=config["channels"], k=config["kernel"],
                blokov=config["blocks"], dropout=config["dropout"],
                dlzka_okna=config["window_rows"])


def _width(values, expected, what):
    if values.shape[-1] != expected:
        raise ValueError(f"the {what} takes {expected} global inputs (architecture global_features), the window has "
                         f"{values.shape[-1]}: build the architecture with global_features=len(normalizer.input_names)")


class Predictor(nn.Module):
    """Global branch plus one temporal model shared across physical bins."""

    def __init__(self, config):
        super().__init__()
        kwargs = _kwargs(config)
        self.global_features = config["global_features"]
        self.global_tcn = TCNPrediktor(self.global_features, **kwargs)
        # has_changed is an input mask, never a regression target.
        self.bin_tcn = TCN(4, 3, **kwargs)

    def forward(self, global_context, local_context):
        _width(global_context, self.global_features, "predictor")
        batch, steps, bins, channels = local_context.shape
        per_bin = local_context.permute(0, 2, 1, 3).reshape(batch * bins, steps, channels)
        return self.global_tcn(global_context), self.bin_tcn(per_bin).reshape(batch, bins, 3)


class Classifier(nn.Module):
    """Classifies recorded workload scenarios, not maliciousness."""

    def __init__(self, config, classes):
        super().__init__()
        if type(classes) is not int or classes < 1:
            raise ValueError("classifier needs at least one class")
        kwargs = _kwargs(config)
        self.global_features = config["global_features"]
        self.tcn = TCN(self.global_features + 8, classes, **kwargs)

    def forward(self, global_window, local_window):
        _width(global_window, self.global_features, "classifier")
        pooled = torch.cat((global_window, local_window.mean(dim=2),
                            local_window.max(dim=2).values), dim=-1)
        return self.tcn(pooled)


def prediction_errors(prediction, global_target, local_target):
    """Entropy is measured only for changed bins; masks are not targets."""
    global_prediction, bin_prediction = prediction
    global_error = (global_prediction - global_target).square().mean(dim=-1)
    mask = torch.stack((torch.ones_like(local_target[..., 3]),
                        torch.ones_like(local_target[..., 3]), local_target[..., 3]), dim=-1)
    bin_error = ((bin_prediction - local_target[..., :3]).square() * mask).sum(dim=-1) / mask.sum(dim=-1)
    return global_error, bin_error


def column_errors(global_prediction, global_target):
    """The error of each global input column: its squared error divided by the number of inputs, so the columns sum
    to the global part of prediction_errors (skeleton B6 section 6 test 4)."""
    return (global_prediction - global_target).square() / global_target.shape[-1]


def anomaly_score(global_error, bin_errors):
    return 0.5 * global_error + 0.5 * bin_errors.max(dim=-1).values


def top_bin_mean(bin_errors):
    """The mean of the TOP_BINS worst bins (of every bin when fewer), the sensitivity analysis beside the maximum."""
    return bin_errors.topk(min(TOP_BINS, bin_errors.shape[-1]), dim=-1).values.mean(dim=-1)
