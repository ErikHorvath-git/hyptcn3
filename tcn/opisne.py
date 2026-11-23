"""The descriptive methods of the core in the method interface: the z-score, the isolation forest and the GRU and LSTM
predictors of tcn/baselines.py (protocol v5, package B7a, agent D; design dokazy/B7/navrh/NAVRH_B7a.md sections 1.1,
1.3, 1.6 and 4, the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 2 and addendum 2 point 1).

The text of the thesis promises these four comparison models (SULAD_S_TEXTOM_PRACE section 3). Since 2026-11-22 they
are in the core as descriptive methods (proposal 8.3): they run in the wrapper of Z0 to Z5 and M (tcn/metody.py: the
same windows, the normalizer of bundle M, the rule k of n and the matched alarm rate) and decide neither K1 nor K2.
The wrapper reports for each the loss on a role's windows (the predictors, from losses()), the alarms per hour at the
matched rate (from scores()) and, from package B7b, the share of interventions caught.

INTERFACE (design 1.1; duck-typed, this module does not import tcn.metody). A method has `name` (its key in
analysis.descriptive_methods), `kind` ("detector" or "predictor"), fit(train, dev, *, protocol, seed) -> the record of
what was chosen on dev and why, scores(windows) -> one score per window (float64, higher is more anomalous), and
losses(windows) -> the loss of each window for a predictor (design 1.3), None for a detector. No method fits a
normalizer or a threshold of its own: its inputs are the windows of M's normalizer and its threshold is the one of the
matched alarm rate (design 1.2).

WINDOW SETS (window_set). A window set is an object with batches(batch_size, order=None) and indices, as
safeguard.training.Windows built with M's normalizer (each batch: the global inputs (n, L, G), the bins (n, L, B, 4)
and labels, which no method here reads), or the pair (global inputs (N, L, G), bin inputs (N, L, B, 4)) of arrays. Any
other form is refused by name. tcn.metody.Okna, the window set of the wrapper, is such an object (merge of B7a). A
fitted method takes only windows of the shape (L rows, G global inputs, B bins) it was fitted on.

BINDING (package B7b, F4 of the verification of B7a). Fitted on window sets of the wrapper (tcn.metody.Okna, known
here by their normalizer_sha256, role, window_rows, max_gap_s and interval_s), a method is bound to their normalizer
and window as tcn.metody.Metoda._bind and _check bind Z0 to Z5: train is of role train and dev of role dev, both of one
normalizer and window, and it scores and loses only window sets of the same; its record names the normalizer and the
roles. Fitted on the pair of arrays or on safeguard.training.Windows, which carry neither, it is unbound (the record
says so) and refuses a window set of the wrapper. The label of a method that draws from a seed carries the seed
("gru:seed 3", as tcn.metody.MetodaM's "M:seed 3"), so the records of the matched rate of its seeds differ.

INPUT (addendum 2 point 1: the behaviour features and the bin summary): tcn.baselines.zluc_biny, per row the G global
inputs, the mean over the bins of each of the four per-bin channels and their maximum over the bins, G + 8 columns.
- zscore: ZSCORE. Nothing is drawn, nothing is selected.
- iforest: IFOREST. Nothing is selected.
- gru, lstm: tcn.baselines.GRUPrediktor and LSTMPrediktor predict TARGET. The loss of a window is M's training loss
  (design 1.3, safeguard.model LOSS_FORMULA) and its score M's score (SCORE_RULE), both from
  safeguard.model.prediction_errors; the hidden size follows SIZE_RULE and the training TRAINING_RULE.

SEEDS (design 1.6). The seed of a fit is one of analysis.descriptive_methods.<name>.seeds. A method whose seeds are
null draws nothing and takes seed None; only the z-score may. runs(protocol) lists every (name, seed) of the plan.

PROTOCOL. analysis.descriptive_methods (agent K's key, design 1.6) is read by descriptive_methods() alone, M's training
(analysis.architecture and analysis.stopping) by training_settings(). Both read the protocol dict as given and refuse by
name what they need and cannot read.
"""
import math

import numpy as np
import torch
from torch import nn

from safeguard.model import LOSS_FORMULA, SCORE_FORMULA, Predictor, anomaly_score, prediction_errors
from safeguard.training import REPEAT, STOPPING, _fit, _prediction_loss, model_config, stream_seed
from tcn.baselines import (GRUPrediktor, IsolationForestAnomalia, LSTMPrediktor, ZScoreAnomalia, skryte_pre_prediktor,
                           zluc_biny)
from tcn.model import pocet_parametrov

NAMES = ("zscore", "iforest", "gru", "lstm")  # The keys of analysis.descriptive_methods (design B7a 1.6).
ENTRY = ("what", "seeds", "note")
SEEDED = ("iforest", "gru", "lstm")  # They draw from a seed; the z-score draws nothing.
CELLS = {"gru": GRUPrediktor, "lstm": LSTMPrediktor}
SUMMARY = 8  # tcn.baselines.zluc_biny: the mean and the maximum over the bins of each of the four per-bin channels.
TARGETS = 3  # The values of a bin a predictor predicts: changed_ratio, zero_ratio, entropy_mean (M's bin targets).
# Judgment: the windows of one batch when a detector is fitted and when any method scores; it sets memory and time,
# not the values beyond float rounding.
BATCH = 256
# The values of M's training that GRU and LSTM read (training_settings).
ARCHITECTURE = ("window_rows", "kernel", "blocks", "channels", "dropout", "learning_rate", "gradient_clip",
                "batch_size")
STOP = ("rule", "patience_epochs", "max_epochs", "repeat_if_last_epoch")

INPUT = ("tcn.baselines.zluc_biny of the windows of M's normalizer: per row the G global inputs, the mean over the "
         "bins of each of the four per-bin channels and their maximum over the bins (G + 8 columns; skeleton B7 "
         "addendum 2 point 1: the behaviour features and the bin summary)")
ZSCORE = ("tcn.baselines.ZScoreAnomalia: the mean over the G + 8 columns of the squared z-value of the window mean "
          "against the mean and the deviation of the window means of train (a deviation under 1e-12 is 1e-12)")
IFOREST = ("tcn.baselines.IsolationForestAnomalia over the flattened window of L x (G + 8) values: 200 trees and "
           "max_samples auto (the fixed values of tcn/baselines.py, the judgment of its author), random_state the "
           "seed; the score is -score_samples, nonnegative and in the order of -decision_function (the forest's own "
           "threshold, contamination, is not used)")
TARGET = ("row L from rows 1 to L - 1 of the summary, by one linear head of G + 3B outputs: the G global inputs and "
          "the three values of each of the B scored bins (changed_ratio, zero_ratio, entropy_mean; has_changed masks "
          "the entropy and is no target)")
SCORE_RULE = SCORE_FORMULA + " (judgment: the score of M, the model they are compared with)"
SIZE_RULE = ("the hidden size whose parameter count is closest to M's predictor, safeguard.model.Predictor of "
             "analysis.architecture with the G global inputs (tcn.baselines.skryte_pre_prediktor)")
BINDING = ("fitted on window sets of the wrapper (tcn.metody.Okna), the method is bound to their normalizer and window "
           "(normalizer_sha256, window_rows, max_gap_s, interval_s), takes train of role train and dev of role dev of "
           "one of them and scores only window sets of the same; fitted on the pair of arrays or on "
           "safeguard.training.Windows, which carry neither, it is unbound and scores no window set of the wrapper (F4 "
           "of the verification of B7a, as tcn.metody.Metoda._bind and _check)")
IDENTITY = ("normalizer_sha256", "window_rows", "max_gap_s", "interval_s")  # What binds a window set of the wrapper.
TRAINING_RULE = ("as M (safeguard.training._fit with _prediction_loss): Adam at analysis.architecture.learning_rate, "
                 "the gradient clip analysis.architecture.gradient_clip, batches of analysis.architecture.batch_size "
                 "and the epoch of the best dev loss with the stop of analysis.stopping, repeated once with twice the "
                 "cap when it is the last (proposal 8.3); the initialization and the batch order come from the streams "
                 "predictor_init and predictor_order of the seed (safeguard.training.STREAMS; judgment: M's batch "
                 "order at the same seed)")


# ------------------------------------------------------------------ the protocol


def _at(protocol, path):
    """The value at analysis.<path> of a protocol dict; ValueError names a path that is not there."""
    value = protocol.get("analysis") if type(protocol) is dict else None
    for key in path.split("."):
        if type(value) is not dict or key not in value:
            raise ValueError(f"the protocol has no analysis.{path}")
        value = value[key]
    return value


def descriptive_methods(protocol):
    """analysis.descriptive_methods (design B7a 1.6, agent K's key): {name: {what, seeds, note}} for exactly NAMES.
    seeds is null or a list of distinct integers >= 0, a list for each method of SEEDED. ValueError names what is
    wrong."""
    plan = _at(protocol, "descriptive_methods")
    if type(plan) is not dict or set(plan) != set(NAMES):
        raise ValueError("analysis.descriptive_methods names exactly zscore, iforest, gru and lstm (design B7a 1.6)")
    for name in NAMES:
        entry = plan[name]
        if type(entry) is not dict or set(entry) != set(ENTRY):
            raise ValueError(f"analysis.descriptive_methods.{name} has exactly the keys what, seeds and note")
        seeds = entry["seeds"]
        if seeds is None:
            if name in SEEDED:
                raise ValueError(f"analysis.descriptive_methods.{name}.seeds is null, but {name} draws from a seed")
        elif (type(seeds) is not list or not seeds or any(type(seed) is not int or seed < 0 for seed in seeds)
              or len(set(seeds)) != len(seeds)):
            raise ValueError(f"analysis.descriptive_methods.{name}.seeds is null or a list of distinct integers >= 0")
    return {name: dict(plan[name], seeds=None if plan[name]["seeds"] is None else list(plan[name]["seeds"]))
            for name in NAMES}


def runs(protocol):
    """Every (name, seed) of the plan, in the order of NAMES and of the seeds; (name, None) for seeds null."""
    plan = descriptive_methods(protocol)
    return [(name, seed) for name in NAMES for seed in ([None] if plan[name]["seeds"] is None else plan[name]["seeds"])]


def _registered(name, protocol, seed):
    """The entry of `name` in analysis.descriptive_methods, after the seed of a fit is checked against its seeds."""
    entry = descriptive_methods(protocol)[name]
    seeds = entry["seeds"]
    if seeds is None and seed is not None:
        raise ValueError(f"{name}: analysis.descriptive_methods.{name}.seeds is null ({name} draws nothing): its fit "
                         f"takes seed None, not {seed!r}")
    if seeds is not None and (type(seed) is not int or seed not in seeds):
        raise ValueError(f"{name}: seed {seed!r} is not one of analysis.descriptive_methods.{name}.seeds {seeds}")
    return entry


def training_settings(protocol):
    """M's training, which GRU and LSTM share (TRAINING_RULE): {architecture: the values of ARCHITECTURE, stopping: the
    values of STOP} of analysis.architecture and analysis.stopping. ValueError names a value they cannot be trained by;
    the values of the reference TCN are checked where it is built (tcn_parameters)."""
    architecture = {key: _at(protocol, "architecture." + key) for key in ARCHITECTURE}
    stopping = {key: _at(protocol, "stopping." + key) for key in STOP}
    if (stopping["rule"], stopping["repeat_if_last_epoch"]) != (STOPPING, REPEAT):
        raise ValueError(f"analysis.stopping gives the rule {stopping['rule']!r} and the repeat "
                         f"{stopping['repeat_if_last_epoch']!r}; GRU and LSTM are trained as M by "
                         f"safeguard.training._fit, which implements {STOPPING!r} and {REPEAT!r}")
    for key in ("learning_rate", "gradient_clip"):
        value = architecture[key]
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"analysis.architecture.{key} is a positive number, not {value!r}")
    for path, value in (("architecture.batch_size", architecture["batch_size"]),
                        ("stopping.patience_epochs", stopping["patience_epochs"]),
                        ("stopping.max_epochs", stopping["max_epochs"])):
        if type(value) is not int or value < 1:
            raise ValueError(f"analysis.{path} is an integer >= 1, not {value!r}")
    return {"architecture": architecture, "stopping": stopping}


def tcn_parameters(settings, inputs):
    """The parameter count of M's predictor: safeguard.model.Predictor of analysis.architecture (`settings` of
    training_settings) with `inputs` global inputs, built as safeguard/training.py builds it (model_config), from a fork
    of torch's generator so that no draw of the caller moves. ValueError when analysis.architecture builds none."""
    architecture = settings["architecture"]
    try:
        with torch.random.fork_rng(devices=[]):
            return pocet_parametrov(Predictor(model_config({"model": architecture}, architecture["window_rows"],
                                                           inputs)))
    except (TypeError, ValueError) as error:
        raise ValueError(f"analysis.architecture builds no predictor of safeguard/model.py with {inputs} global "
                         f"inputs: {error}") from None


def recurrent_size(name, inputs, bins, settings):
    """(hidden size, its parameter count, the parameter count of M's predictor) of the predictor `name` (gru or lstm) at
    `inputs` global inputs and `bins` scored bins (SIZE_RULE); the trial nets are built from a fork of torch's
    generator."""
    target = tcn_parameters(settings, inputs)
    with torch.random.fork_rng(devices=[]):
        hidden, parameters = skryte_pre_prediktor(CELLS[name], inputs + SUMMARY, inputs + TARGETS * bins, target)
    return hidden, parameters, target


# ------------------------------------------------------------------ the window sets


class _Pair:
    """A window set given as the pair (global inputs (N, L, G), bin inputs (N, L, B, 4)) of arrays, read as
    safeguard.training.Windows is read: indices, and batches(batch_size, order) of float32 tensors with the labels 0
    (no method here reads them)."""

    def __init__(self, global_inputs, bin_inputs):
        g = np.asarray(global_inputs, dtype=np.float64)
        local = np.asarray(bin_inputs, dtype=np.float64)
        if (g.ndim != 3 or local.ndim != 4 or local.shape[-1] != 4 or g.shape[:2] != local.shape[:2]
                or min(*g.shape, local.shape[2]) < 1 or not np.isfinite(g).all() or not np.isfinite(local).all()):
            raise ValueError("a window set pair is the global inputs (N, L, G) and the bin inputs (N, L, B, 4) of one "
                             "N and one L, with N, L, G and B at least 1, all finite")
        self.global_inputs, self.bin_inputs = g, local
        self.indices = range(len(g))

    def batches(self, batch_size, order=None):
        if order is None:
            order = np.arange(len(self.indices))
        for start in range(0, len(order), batch_size):
            selection = np.asarray(order[start:start + batch_size])
            yield (torch.as_tensor(self.global_inputs[selection], dtype=torch.float32),
                   torch.as_tensor(self.bin_inputs[selection], dtype=torch.float32),
                   torch.zeros(len(selection), dtype=torch.long))


def window_set(windows):
    """A window set of design B7a 1.1 (module docstring): an object with batches and indices as it is, the pair of
    arrays as _Pair; ValueError for any other form."""
    if callable(getattr(windows, "batches", None)) and hasattr(windows, "indices"):
        return windows
    if type(windows) in (tuple, list) and len(windows) == 2:
        return _Pair(*windows)
    raise ValueError("a window set is a safeguard.training.Windows (batches and indices) or the pair (global inputs "
                     "(N, L, G), bin inputs (N, L, B, 4)) (design B7a 1.1)")


def _shape(batch):
    """(L, G, B) of one batch (global inputs, bin inputs, ...) of a window set."""
    g, local = batch[0], batch[1]
    if g.ndim != 3 or local.ndim != 4 or local.shape[-1] != 4 or tuple(g.shape[:2]) != tuple(local.shape[:2]):
        raise ValueError("a batch of a window set is the global inputs (n, L, G) and the bin inputs (n, L, B, 4)")
    return int(g.shape[1]), int(g.shape[2]), int(local.shape[2])


def _first_shape(windows):
    """(L, G, B) of the first window of a window set."""
    batch = next(iter(window_set(windows).batches(1)), None)
    if batch is None:
        raise ValueError("a window set has at least one window")
    return _shape(batch)


def _same(name, shape, found):
    if found != shape:
        raise ValueError(f"{name}: its windows have {shape[0]} rows, {shape[1]} global inputs and {shape[2]} bins; "
                         f"these have {found[0]}, {found[1]} and {found[2]}")


def _batches(windows, name, shape):
    """The (global inputs, bin inputs) tensors of each batch of BATCH windows of a window set, every batch of the
    shape (L, G, B) of the method `name`."""
    for batch in window_set(windows).batches(BATCH):
        _same(name, shape, _shape(batch))
        yield batch[0], batch[1]


def _record(method, entry, seed, shape, windows, binding, roles, **fields):
    """The record of a fit: the method, its label, its registered entry's text, the seed, the input, the shape, the
    windows, the binding (BINDING: the normalizer and the roles, None for unbound window sets), then what was chosen
    on dev and why (`fields`)."""
    return {"name": method.name, "variant": method.variant, "label": method.label, "kind": method.kind,
            "what": entry["what"], "seed": seed, "input": INPUT,
            "shape": {"window_rows": shape[0], "inputs": shape[1], "bins": shape[2]}, "windows": windows,
            "normalizer_sha256": None if binding is None else binding[0], "roles": roles, "binding": BINDING,
            **fields}


def _bound(windows):
    """Whether `windows` is a window set of the wrapper (tcn.metody.Okna: it has its normalizer's fingerprint, its role
    and its window), read by duck typing (this module does not import tcn.metody)."""
    return all(hasattr(windows, key) for key in IDENTITY + ("role",))


def _identity(windows):
    return tuple(getattr(windows, key) for key in IDENTITY)


# ------------------------------------------------------------------ the methods


class _Method:
    name = kind = None

    def __init__(self):
        self.shape = None
        self.seed = None
        self.binding = None  # IDENTITY of the window sets of the fit, None when they carry none (BINDING).

    @property
    def variant(self):
        """The seed of a method that draws from one, as "seed 3" (None for the z-score or before the fit)."""
        return None if self.seed is None else f"seed {self.seed}"

    @property
    def label(self):
        """name, or name:variant ("gru:seed 3"), as tcn.metody.Metoda.label (F4 of the verification of B7a)."""
        return self.name if self.variant is None else f"{self.name}:{self.variant}"

    def _bind(self, train, dev):
        """(binding, roles) of the window sets of a fit (BINDING): for window sets of the wrapper their IDENTITY and
        {train, dev: role} after the roles and the identity are checked, else (None, None)."""
        if not _bound(train):
            if dev is not None and _bound(dev):
                raise ValueError(f"{self.name}: train and dev are both window sets of the wrapper (tcn.metody.Okna) or "
                                 "neither")
            return None, None
        if not _bound(dev):
            raise ValueError(f"{self.name}: train and dev are both window sets of the wrapper (tcn.metody.Okna) or "
                             "neither")
        if (train.role, dev.role) != ("train", "dev"):
            raise ValueError(f"{self.name}: fit takes the window sets of roles train and dev (analysis.selection: "
                             f"never on a test role), not {train.role} and {dev.role}")
        if _identity(train) != _identity(dev):
            raise ValueError(f"{self.name}: train and dev hold windows of different normalizers or windows; every "
                             "method sees M's")
        return _identity(train), {"train": train.role, "dev": dev.role}

    def _fitted(self):
        if self.shape is None:
            raise ValueError(f"{self.name}: fit has not run")
        return self.shape

    def _check(self, windows):
        """The shape of the fit, after the window set to score is checked against the binding of the fit (BINDING)."""
        shape = self._fitted()
        if self.binding is None:
            if _bound(windows):
                raise ValueError(f"{self.label} was fitted on windows without a normalizer (the pair of arrays or "
                                 "safeguard.training.Windows): it scores no window set of the wrapper "
                                 "(tcn.metody.Okna)")
        elif not _bound(windows):
            raise ValueError(f"{self.label} is bound to the normalizer of the window sets of its fit: it scores window "
                             "sets of the wrapper (tcn.metody.Okna) only")
        elif _identity(windows) != self.binding:
            raise ValueError(f"{self.label} was fitted on windows of another normalizer or window; every method sees "
                             "the windows of its bundle M")
        # The seal (package B7c, tcn/pecat.py GUARD_RULE): the archives the window set names are looked up in the
        # ledger, a sealed archive of a campaign outside the final run that consumed its seal is refused by name.
        from tcn import pecat
        pecat.kontrola_okien(windows, f"{self.label} scores a window set of role {getattr(windows, 'role', None)}")
        return shape

    def losses(self, windows):
        """None: a detector gives no loss (design B7a 1.1)."""
        return None


class ZScoreMethod(_Method):
    """The z-score of the window mean (ZSCORE)."""
    name, kind = "zscore", "detector"

    @staticmethod
    def _means(g, local):
        return zluc_biny(g, local).double().numpy().mean(axis=1, keepdims=True)

    def fit(self, train, dev, *, protocol, seed):
        """The mean and the deviation of the window means of train; dev is not read (no free parameter), only bound
        (BINDING)."""
        entry = _registered(self.name, protocol, seed)
        binding, roles = self._bind(train, dev)
        train = window_set(train)
        shape = _first_shape(train)
        means = np.concatenate([self._means(g, local) for g, local in _batches(train, self.name, shape)])
        self.model = ZScoreAnomalia(tuple(range(means.shape[-1])), indikatory=()).fit(means)
        self.shape, self.seed, self.binding = shape, seed, binding
        return _record(self, entry, seed, shape, {"train": len(train.indices)}, binding, roles, statistic=ZSCORE,
                       chosen=None, why="no free parameter: nothing is selected on dev, which is not read")

    def scores(self, windows):
        shape = self._check(windows)
        return np.concatenate([self.model.skore(self._means(g, local)) for g, local in _batches(windows, self.name,
                                                                                               shape)])


class IForestMethod(_Method):
    """The isolation forest over the flattened window (IFOREST)."""
    name, kind = "iforest", "detector"

    @staticmethod
    def _windows(g, local):
        return zluc_biny(g, local).double().numpy()

    def fit(self, train, dev, *, protocol, seed):
        """The forest of the seed over the windows of train; dev is not read (fixed hyperparameters), only bound
        (BINDING)."""
        entry = _registered(self.name, protocol, seed)
        binding, roles = self._bind(train, dev)
        train = window_set(train)
        shape = _first_shape(train)
        self.model = IsolationForestAnomalia(seed=seed).fit(
            np.concatenate([self._windows(g, local) for g, local in _batches(train, self.name, shape)]))
        self.shape, self.seed, self.binding = shape, seed, binding
        return _record(self, entry, seed, shape, {"train": len(train.indices)}, binding, roles, statistic=IFOREST,
                       chosen=None, why="fixed hyperparameters of tcn/baselines.py (200 trees, max_samples auto): "
                                        "nothing is selected on dev, which is not read",
                       trees=self.model.m.n_estimators, random_state=seed)

    def scores(self, windows):
        shape = self._check(windows)
        return np.concatenate([self.model.skore_nezaporne(self._windows(g, local))
                               for g, local in _batches(windows, self.name, shape)])


class _Net(nn.Module):
    """A GRU or LSTM predictor over the bin summary with the call of safeguard.model.Predictor: (global context
    (n, L - 1, G), bin context (n, L - 1, B, 4)) -> (global prediction (n, G), bin prediction (n, B, 3)), so that M's
    loss (safeguard.training._prediction_loss) and score (safeguard.model.anomaly_score) apply unchanged."""

    def __init__(self, name, inputs, bins, hidden):
        super().__init__()
        self.inputs, self.bins = inputs, bins
        self.rnn = CELLS[name](inputs + SUMMARY, hidden, inputs + TARGETS * bins)

    def forward(self, global_context, local_context):
        prediction = self.rnn(zluc_biny(global_context, local_context))
        return prediction[:, :self.inputs], prediction[:, self.inputs:].reshape(len(prediction), self.bins, TARGETS)


class _Recurrent(_Method):
    """A GRU or LSTM predictor (TARGET, SIZE_RULE, TRAINING_RULE)."""
    kind = "predictor"

    def __init__(self):
        super().__init__()
        self.net = None

    def fit(self, train, dev, *, protocol, seed):
        """Trained on train with the epoch of the best dev loss, as M (TRAINING_RULE)."""
        entry = _registered(self.name, protocol, seed)
        settings = training_settings(protocol)
        binding, roles = self._bind(train, dev)
        train, dev = window_set(train), window_set(dev)
        shape = _first_shape(train)
        if shape[0] < 2:
            raise ValueError(f"{self.name}: a window of {shape[0]} row has no row before its last; a predictor needs 2 "
                             "rows at least")
        _same(self.name, shape, _first_shape(dev))
        hidden, parameters, target = recurrent_size(self.name, shape[1], shape[2], settings)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(stream_seed(seed, "predictor_init"))
            net = _Net(self.name, shape[1], shape[2], hidden)
        architecture = settings["architecture"]
        stop, history = _fit(net, _prediction_loss, train, dev, learning_rate=architecture["learning_rate"],
                             clip=architecture["gradient_clip"], batch_size=architecture["batch_size"],
                             stopping=settings["stopping"], seed=seed, name="predictor")
        self.net, self.shape, self.seed, self.binding = net, shape, seed, binding
        return _record(self, entry, seed, shape, {"train": len(train.indices), "dev": len(dev.indices)}, binding,
                       roles, target=TARGET, loss_formula=LOSS_FORMULA, score_formula=SCORE_RULE, hidden=hidden,
                       parameters=parameters, tcn_parameters=target, size_rule=SIZE_RULE, training=TRAINING_RULE,
                       chosen={"epoch": stop["selected_epoch"]},
                       why="the epoch of the lowest dev loss under analysis.stopping, as M (proposal 8.3)", stop=stop,
                       history=[{"epoch": epoch, "train_loss": loss, "dev_loss": dev_loss}
                                for epoch, loss, dev_loss in history])

    def _errors(self, windows):
        """safeguard.model.prediction_errors of each window: (global error (N,), bin errors (N, B))."""
        shape = self._check(windows)
        self.net.eval()
        global_errors, bin_errors = [], []
        with torch.inference_mode():
            for g, local in _batches(windows, self.name, shape):
                global_error, bin_error = prediction_errors(self.net(g[:, :-1], local[:, :-1]), g[:, -1], local[:, -1])
                global_errors.append(global_error)
                bin_errors.append(bin_error)
        return torch.cat(global_errors), torch.cat(bin_errors)

    def scores(self, windows):
        """M's score of each window (SCORE_RULE): 0.5 x the global error + 0.5 x the worst bin's masked error."""
        return anomaly_score(*self._errors(windows)).double().numpy()

    def losses(self, windows):
        """M's training loss of each window (design B7a 1.3, LOSS_FORMULA): 0.5 x the global error + 0.5 x the mean of
        the scored bins' masked errors."""
        global_error, bin_error = self._errors(windows)
        return (0.5 * global_error + 0.5 * bin_error.mean(dim=-1)).double().numpy()


class GRUMethod(_Recurrent):
    """The GRU predictor (tcn.baselines.GRUPrediktor)."""
    name = "gru"


class LSTMMethod(_Recurrent):
    """The LSTM predictor (tcn.baselines.LSTMPrediktor)."""
    name = "lstm"


METHODS = {"zscore": ZScoreMethod, "iforest": IForestMethod, "gru": GRUMethod, "lstm": LSTMMethod}


def method(name):
    """A new, unfitted method of NAMES."""
    if name not in METHODS:
        raise ValueError(f"unknown descriptive method {name!r}; the methods are zscore, iforest, gru and lstm")
    return METHODS[name]()
