"""Shared-bin predictor and workload classifier for the safeguard.

Original integration using the causal TCN blocks in tcn.model (Bai et al.,
2018 architecture). These models predict behavior; they do not identify
malware families or establish detection accuracy without held-out experiments.
"""
import torch
from torch import nn

from tcn.model import TCN, TCNPrediktor, skontroluj_rf


SCORE_FORMULA = "0.5 * mean(global_squared_error) + 0.5 * max(bin_masked_mse)"
LOSS_FORMULA = "0.5 * mean(global_squared_error) + 0.5 * mean(bin_masked_mse)"


def architecture(window_rows=32):
    blocks = 1
    while 1 + 4 * (2 ** blocks - 1) < window_rows:
        blocks += 1
    return {"global_features": 18, "local_features": 4, "channels": 16,
            "kernel": 3, "blocks": max(4, blocks), "window_rows": window_rows,
            "dropout": 0.1, "classifier_pooling": "bin_mean_and_max"}


def validate_architecture(config):
    if (config.get("global_features") != 18 or config.get("local_features") != 4
            or config.get("classifier_pooling") != "bin_mean_and_max"):
        raise ValueError("unsupported safeguard architecture")
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


class Predictor(nn.Module):
    """Global branch plus one temporal model shared across physical bins."""

    def __init__(self, config):
        super().__init__()
        kwargs = _kwargs(config)
        self.global_tcn = TCNPrediktor(18, **kwargs)
        # has_changed is an input mask, never a regression target.
        self.bin_tcn = TCN(4, 3, **kwargs)

    def forward(self, global_context, local_context):
        batch, steps, bins, channels = local_context.shape
        per_bin = local_context.permute(0, 2, 1, 3).reshape(batch * bins, steps, channels)
        return self.global_tcn(global_context), self.bin_tcn(per_bin).reshape(batch, bins, 3)


class Classifier(nn.Module):
    """Classifies recorded workload scenarios, not maliciousness."""

    def __init__(self, config, classes):
        super().__init__()
        if type(classes) is not int or classes < 1:
            raise ValueError("classifier needs at least one class")
        self.tcn = TCN(26, classes, **_kwargs(config))

    def forward(self, global_window, local_window):
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


def anomaly_score(global_error, bin_errors):
    return 0.5 * global_error + 0.5 * bin_errors.max(dim=-1).values
