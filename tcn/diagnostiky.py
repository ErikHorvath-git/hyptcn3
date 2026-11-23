"""The descriptive diagnostics of the model (protocol v5, package B7b, agent G).

Binding texts: the design dokazy/B7/navrh/NAVRH_B7b.md sections 1.3 and 3, the lead's skeleton
dokazy/B7/kostra/KOSTRA.md section 6 and point 3 of its addendum of 2026-11-22T20:55Z, and proposal 8.5 and 8.7
(docs/NAVRH_PROTOKOL_V5.sk.md). Descriptive only (proposal 9.1, result O5): nothing here decides K1 or K2. Every
diagnostic runs in the wrapper of tcn/metody.py: the window sets (Okna) of bundle M with its normalizer, the alarm rule
k of n and the matched alarm rate. Package B7b reads no test role: everything here runs on the window sets it is given
(the final command of package B7c gives them).

    diagnostics(protocol)       analysis.diagnostics (agent F's key, design 1.4), the one accessor of this module
    tree, one_member            what the exceedances of a method's threshold have in common (TREE_RULE,
                                ONE_MEMBER_RULE); threshold_likeness both for M and for Z1 to Z3, and whether each is
                                used (USE_RULE); fewer than min_positive_episodes give UNEVALUATED
    Siet(variant)               a TCN of M's architecture by M's training (TRAINING_RULE): the network with random
                                weights (RANDOM_RULE), the partial models mem_* only, global only and bins only
                                (PARTIAL_RULE), and the retrained model of the context truncation and of the shuffle
    truncated, Truncated        the context cut to its last rows (CONTEXT_RULE), for Siet, Z3 and Z5;
                                context_truncation the curve over analysis.diagnostics.contexts
    shuffled, Shuffled          the context shuffled but its last row (SHUFFLE_RULE): Shuffled(Siet("retrained")) is
                                the model with shuffled context, Shuffled(Z3()) and Shuffled(Z5()) the same for Z3 and
                                Z5
    alarm_rules                 the sensitivity to k of n (ALARM_RULES_RULE), M's seeds also walked to the budget as in
                                K2 (SEED_WALK_RULE)
    leave_one_boot_out          the threshold when one boot of calibration is left out (LEAVE_ONE_OUT_RULE)
    clean_threshold             the threshold from clean traffic only next to the main one (CLEAN_THRESHOLD_RULE)

Context truncation and the variants of k of n do not go through safeguard.training.train_bundle or
safeguard.runtime.Detector (window_rows is the protocol's there, and the rule channel's k and n must equal the neural
one's; code map section 5): they are built on the wrapper's window sets and losses, and neither M's training
(safeguard/training.py) nor the runtime changes. Siet calls the functions of M's training unchanged.

The models of M are the bundles of every seed (tcn.metody.MetodaM, or any object with its seed, threshold and
scores), exactly analysis.seeds; a method is any object of the interface of tcn.metody.Metoda. The boots are given as
{session id: boot name} for every session of a window set (the corpus index gives them; a boot is one boot of the VM).
The traffic of every window set is the caller's (tcn.metody.traffic): a rate is per observed hour of clean traffic
(tcn.metody RATE_RULE), so alarm_rules and clean_threshold take the Traffic of calibration and of every role, and the
other diagnostics a clean mask or the Traffic; this module computes none. The detection of the interventions enters as
a function given by the caller (tcn.k2.detection: merge of B7b); this module computes none.

truncated, shuffled and the left-out boot build window sets from the session arrays of Okna through its public
accessor (tcn.metody.Okna.sessions, merge of B7b); members reads the fitted state of Z1, Z2 and Z3 (and
tcn.metody._z3_predict), for which no public accessor exists; members refuses a score it cannot compose (MEMBERS_RULE).
"""
import math
import zlib

import numpy as np
import torch
from torch import nn

from safeguard.model import LOSS_FORMULA, SCORE_FORMULA, anomaly_score, column_errors, prediction_errors
from tcn.metody import (ALARM_RULE, BUDGET_RULE, RATE_RULE, THRESHOLD_RULE, UNEVALUATED, Metoda, Okna, Traffic,
                        alarm_count, budget, matched_rate, matched_threshold, rate)

KEYS = ("tree_depth", "min_positive_episodes", "contexts", "alarm_rules", "note")  # analysis.diagnostics, design 1.4.
# UNEVALUATED (tcn.metody, one constant with tcn/k2.py): proposal 8.5, fewer than min_positive_episodes episodes.
THRESHOLD_LIKE, NOT_THRESHOLD_LIKE = "threshold-like", "not threshold-like"
# Judgment: the level at which the tree's F1 and the share of one member call a method threshold-like (proposal 8.5
# names no number; analysis.diagnostics of design 1.4 has none, so it is this module's).
THRESHOLD_LEVEL = 0.8
REFERENCE = ("Z1", "Z2", "Z3")  # Proposal 8.5: both diagnostics are computed for Z1 to Z3 too.
TREE_RANDOM_STATE = 0  # Judgment: the fixed state of the tree's ties between equal splits (sklearn random_state).
SHUFFLE_ENTROPY = 0x73687566  # The word "shuf": it only separates the shuffle's generator from every other stream.
VARIANTS = {"retrained": "retrained", "random": "random weights", "mem": "mem_* only", "global": "global only",
            "bins": "bins only"}
PARTS = {"retrained": "all", "random": "all", "mem": "mem", "global": "global", "bins": "bins"}
MEMORY = "mem_"  # The prefix of the memory aggregates (features/snapshot.py MENA; tcn/porovnanie.py PAMAT).
TRAIN_THREADS = 4  # safeguard/training.py train_bundle: torch on at most 4 threads while it trains.
# Judgment: the float32 tolerance of tcn/metody.py's tests of M, for the score composed of its members (MEMBERS_RULE).
COMPOSE_RTOL, COMPOSE_ATOL = 1e-5, 1e-6

# ------------------------------------------------------------------ the rules (written into the records)

EPISODE_RULE = ("a positive episode is a maximal run of windows whose score exceeds the threshold (strictly, as "
                "ALARM_RULE) with no reset of ALARM_RULE between them")
TREE_INPUTS = (
    "the raw columns of the window's last row, their differences and the largest change of a bin (proposal 8.5): for "
    "each TCN input its raw value at the last row (the normalized input times the normalizer's scale plus its mean: "
    "the value of a neural column, the first difference of a differenced one), its raw difference from the row before "
    "it, and the largest raw changed_ratio of the scored bins at the last row; a column that is no TCN input (the rule "
    "channel, dropped) is in no window set and enters no tree")
TREE_RULE = (
    "a decision tree of depth at most analysis.diagnostics.tree_depth reproduces the exceedances of a method's "
    "threshold (proposal 8.5): its classes are the windows whose score exceeds the threshold (strictly) and the "
    "others, its inputs TREE_INPUTS; sklearn.tree.DecisionTreeClassifier(max_depth=tree_depth, "
    "class_weight='balanced', random_state=0) (judgment: the exceedances are rare, and an unweighted tree may mark "
    "none); cross-validated by boots: the windows of each boot are predicted by the tree fitted on the windows of "
    "every other boot; the measure is the F1 of the exceeding windows over the predictions of all boots (judgment: "
    "the exceedances are rare, so the accuracy would count mostly the windows below the threshold; the balanced "
    "accuracy is reported beside it), threshold-like when it is at least THRESHOLD_LEVEL (judgment); fewer than "
    "analysis.diagnostics.min_positive_episodes positive episodes (EPISODE_RULE) give nevyhodnotené; the tree fitted "
    "on every boot is reported as text")
MEMBERS_RULE = (
    "the score of one member alone: for Z1 the standardized statistic of each TCN input (Z1_RULE; the score is their "
    "maximum), for Z2 |x - mode| of each count (Z2_RULE; their maximum), for Z3 and M 0.5 x the squared error of each "
    "TCN input over the number of inputs (safeguard.model.column_errors; they sum to the global part of "
    "SCORE_FORMULA) and 0.5 x the masked error of each scored bin (the bin part is their maximum); the score composed "
    "of the members must equal the method's score (relative tolerance 1e-5, absolute 1e-6), else the fitted state of "
    "the method is not the one this rule reads and the diagnostic is refused")
ONE_MEMBER_RULE = (
    "the share of one member (proposal 8.5): of the windows whose score exceeds the threshold, the share in which one "
    "member (a TCN input or a scored bin) alone exceeds it, a member's score being MEMBERS_RULE; threshold-like when "
    "it is at least THRESHOLD_LEVEL (judgment); fewer than analysis.diagnostics.min_positive_episodes positive "
    "episodes (EPISODE_RULE) give nevyhodnotené")
USE_RULE = (
    "proposal 8.5: the tree and the share of one member are computed for Z1 to Z3 as well, where they must come out "
    "threshold-like; each is used (for M) only when Z1, Z2 and Z3 each come out threshold-like by it, otherwise it is "
    "not used and the record names every one that did not (not threshold-like or nevyhodnotené)")
TRAINING_RULE = (
    "M's training (safeguard/training.py, package B6b), its functions unchanged: the network is built after "
    "torch.manual_seed of the stream predictor_init of the seed (safeguard.training.stream_seed), then "
    "safeguard.training._fit trains it with M's loss (_prediction_loss; a partial model the part of it that it "
    "predicts, PARTIAL_RULE) at analysis.architecture.learning_rate, gradient_clip and batch_size, its dropout and its "
    "batch order from the streams predictor_dropout and predictor_order of the seed, and keeps the epoch of the best "
    "dev loss under analysis.stopping, repeated once with twice the cap when that epoch is the last "
    "(tcn.opisne.training_settings reads the values); torch runs on at most 4 threads, as in train_bundle")
RANDOM_RULE = (
    "the network with random weights (proposal 8.5): safeguard.model.Predictor of analysis.architecture built after "
    "torch.manual_seed of the stream predictor_init of the seed, which is M before its first epoch, and never trained; "
    "its loss and its score are M's (LOSS_FORMULA, SCORE_FORMULA)")
SHUFFLE_RULE = (
    "the shuffled context (proposal 8.5: a shuffle of the context that keeps the last row): in every window the rows "
    "of the context but its last one (the row just before the window's last row) take a random order of their own; "
    "the last row of the context and the window's last row (the target) stay in place (judgment: 'the last row' is "
    "read as the last row of the context, since the target is no row of the context); the order of window i of a "
    "window set is the argsort of row i of numpy.random.default_rng([seed, SHUFFLE_ENTROPY, crc32 of the set's "
    "role]).random((windows, window_rows - 2)), seed the seed of the fit, fixed for the set (the same in every epoch); "
    "the predictor (Siet retrained: the model with shuffled context, trained by TRAINING_RULE; Z3, Z5: the same "
    "modification for them, proposal 8.5) is fitted, selected on dev and scored on the shuffled windows by its own "
    "rule, unchanged")
PARTIAL_RULE = (
    "a partial model (skeleton B7 addendum 2 point 3, proposal 8.5): one branch of M's predictor, "
    "safeguard.model.Predictor of analysis.architecture built after torch.manual_seed of the stream predictor_init of "
    "the seed, so that the branch starts from M's initial weights of it: mem is the global branch over the TCN inputs "
    "whose name begins with mem_ (the memory aggregates; tcn/porovnanie.py tcn_pamat keeps the bin branch and is not "
    "this model), predicting them; global the global branch over every TCN input, predicting them; bins the bin "
    "branch, shared by the scored bins, over the four channels of each bin, predicting its three values; no other "
    "input enters; its loss and its score are LOSS_FORMULA and SCORE_FORMULA with the error of the part it does not "
    "predict set to 0 (safeguard.model.prediction_errors with that part's target in place of its prediction): 0.5 x "
    "the mean squared error of its global inputs, or 0.5 x the mean (the score: the maximum) of the masked errors of "
    "the scored bins; trained by TRAINING_RULE, with its optimizer and its gradient clip over its own parameters "
    "(M clips its two branches together)")
CONTEXT_RULE = (
    "the context truncated to its last c rows (proposal 8.5, skeleton B7 section 6): every window keeps its last row "
    "(the target) and the c rows before it, so the set holds the same windows by their last rows, in the same order "
    "(the masks and the alarm resets of the full set apply to it), with window_rows c + 1; in an anchored set the "
    "anchor of a window is the row before its first, a measured row of the full window that enters no input (the "
    "inputs of a differenced column are those of the full session); c = window_rows - 1 is the full set itself. The "
    "predictor (Z3, Z5, Siet retrained) is fitted, selected on dev and scored on those windows by its own rule, "
    "unchanged")
SEED_WALK_RULE = (
    "each seed of M also at its matched threshold at the budget (tcn.metody.matched_rate, THRESHOLD_RULE), beside its "
    "bundle threshold: in K2 every seed of M walks to the budget like every method (tcn/k2.py DETECTION_RULE; "
    "judgment, analysis.matched_rate), so these rows reproduce K2's M (verification of B7b, F4)")
ALARM_RULES_RULE = (
    "the sensitivity to the alarm rule (proposal 8.5): for each [k, n] of analysis.diagnostics.alarm_rules, ALARM_RULE "
    "at k of n: M's alarms on the clean windows of calibration, each seed at its own threshold (the bundle's; the "
    "quantile does not depend on k and n), the budget (BUDGET_RULE: their median, rounded up), each method's matched "
    "rate at that budget under k of n (tcn.metody.matched_rate) and M's own rates on every role given; each seed of M "
    "also at its matched threshold at the budget (SEED_WALK_RULE)")
LEAVE_ONE_OUT_RULE = (
    "the threshold when one boot of calibration is left out (proposal 8.5): for each boot b, calibration without the "
    "sessions of b; each seed of M at the threshold of safeguard.training.calibrate on the windows left (the quantile "
    "1 - analysis.fpr of its scores, numpy method higher, over every window left, events included) and its alarms on "
    "the clean windows left under analysis.alarm_rule; the budget (BUDGET_RULE) and each method's matched threshold on "
    "the windows left (THRESHOLD_RULE); the score of a window left is its score on all of calibration (a method that "
    "draws per window set, the random variant of Z0, keeps its numbers); the range of a threshold is its minimum and "
    "maximum over the boots")
CLEAN_THRESHOLD_RULE = (
    "the threshold from clean traffic only, next to the main one (proposal 8.7): the main threshold of each seed of M "
    "is its bundle's (safeguard.training.calibrate: the quantile 1 - analysis.fpr of its scores over every window of "
    "calibration, events included; main_recomputed is that quantile over the window set given), the clean threshold "
    "the same quantile over the clean windows of calibration only; at each, M's alarms on the clean windows of "
    "calibration under analysis.alarm_rule, the budget (BUDGET_RULE), every method's matched rate at it "
    "(THRESHOLD_RULE, RATE_RULE) and the detection given at every threshold (the sensitivity at both); at the main "
    "threshold each seed of M also at its matched threshold at the budget (SEED_WALK_RULE), as K2 takes it; the clean "
    "variant keeps every seed at its clean threshold, which is that variant's point (proposal 8.7)")
NO_DETECTION = ("no detection function given: the share of the interventions detected (tcn/zasahy.py of agent I, "
                "package B7b) is not computed in this record")
CONTEXT_LOSS = "the mean loss (LOSS_FORMULA, the predictor's losses()) over the windows of the mask of each role"


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


# ------------------------------------------------------------------ the protocol key (design 1.4)


def _value(protocol, path):
    value = protocol
    for part in path.split("."):
        if type(value) is not dict or part not in value:
            raise ValueError(f"protocol key {path} is missing (design B7b 1.4)")
        value = value[part]
    return value


def diagnostics(protocol):
    """analysis.diagnostics (design B7b 1.4, agent F's key, G0), checked: {tree_depth, min_positive_episodes,
    contexts, alarm_rules} (the lead's numbers, skeleton B7 section 6; note is the protocol's text). A missing key and
    every value this module cannot use are refused by name; the contexts lie in 1 to window_rows - 1."""
    value = _value(protocol, "analysis.diagnostics")
    if type(value) is not dict or set(value) != set(KEYS):
        raise ValueError("analysis.diagnostics must be an object of exactly the keys " + ", ".join(KEYS))
    for key in ("tree_depth", "min_positive_episodes"):
        if type(value[key]) is not int or value[key] < 1:
            raise ValueError(f"analysis.diagnostics.{key} must be an integer of at least 1")
    rows = _value(protocol, "window_rows")
    contexts = value["contexts"]
    if (type(rows) is not int or type(contexts) is not list or not contexts
            or not all(type(c) is int for c in contexts) or contexts != sorted(set(contexts))
            or contexts[0] < 1 or contexts[-1] > rows - 1):
        raise ValueError("analysis.diagnostics.contexts must be an increasing list of integers from 1 to window_rows "
                         f"- 1 ({rows - 1 if type(rows) is int else '?'})")
    rules = value["alarm_rules"]
    if (type(rules) is not list or not rules or not all(
            type(r) is list and len(r) == 2 and all(type(x) is int for x in r) and 1 <= r[0] <= r[1] for r in rules)
            or len({tuple(r) for r in rules}) != len(rules)):
        raise ValueError("analysis.diagnostics.alarm_rules must be a non-empty list of distinct pairs [k, n] of "
                         "integers with 1 <= k <= n")
    return {"tree_depth": value["tree_depth"], "min_positive_episodes": value["min_positive_episodes"],
            "contexts": list(contexts), "alarm_rules": [tuple(r) for r in rules]}


def _fpr(protocol):
    fpr = _value(protocol, "analysis.fpr")
    if not _number(fpr) or not 0 < fpr < 1:
        raise ValueError("analysis.fpr must be a number in (0, 1)")
    return fpr


def _rule(protocol):
    k, n = (_value(protocol, "analysis.alarm_rule." + key) for key in ("k", "n"))
    if type(k) is not int or type(n) is not int or not 1 <= k <= n:
        raise ValueError("analysis.alarm_rule needs integers with 1 <= k <= n")
    return k, n


# ------------------------------------------------------------------ window sets and inputs


def _okna(windows, what="windows"):
    if not isinstance(windows, Okna):
        raise ValueError(f"{what} must be a window set (tcn.metody.Okna)")
    return windows


def _sessions(windows):
    """The sessions of a window set as Okna takes them (tcn.metody.SESSION_KEYS), sharing its arrays (read-only views of
    tcn.metody.Okna.sessions)."""
    return windows.sessions()


def truncated(windows, rows):
    """The window set of `windows` with the context truncated to its last `rows` rows (CONTEXT_RULE); `windows`
    itself at rows = window_rows - 1."""
    _okna(windows)
    if type(rows) is not int or not 1 <= rows <= windows.window_rows - 1:
        raise ValueError(f"a context of {rows!r} rows: the windows of {windows.window_rows} rows have contexts of 1 to "
                         f"{windows.window_rows - 1} rows")
    if rows == windows.window_rows - 1:
        return windows
    items = [(int(s), int(end), int(end) - rows - 1 if windows.anchored else None) for s, end, _ in windows.index]
    return Okna(_sessions(windows), items, role=windows.role, normalizer=windows.normalizer, window_rows=rows + 1,
                max_gap_s=windows.max_gap_s, interval_s=windows.interval_s)


def _subset(windows, keep):
    """The window set of the sessions `keep` (positions in windows.session_ids, increasing) with their windows in
    order, and the mask of those windows in `windows`."""
    position = {s: i for i, s in enumerate(keep)}
    items = [(position[int(s)], int(end), None if anchor < 0 else int(anchor)) for s, end, anchor in windows.index
             if int(s) in position]
    sessions = _sessions(windows)
    return (Okna([sessions[s] for s in keep], items, role=windows.role, normalizer=windows.normalizer,
                 window_rows=windows.window_rows, max_gap_s=windows.max_gap_s, interval_s=windows.interval_s),
            np.isin(windows.window_session, keep))


def _boots(windows, boots):
    """The boot of every window of the set from {session id: boot name} of every session of it."""
    if (type(boots) is not dict or set(boots) != set(windows.session_ids)
            or not all(type(b) is str and b for b in boots.values())):
        raise ValueError("boots maps the id of every session of the window set, and no other, to the name of its boot "
                         "(a non-empty text)")
    return np.array([boots[ident] for ident in windows.session], dtype=str)


def _mask(mask, windows, what="clean"):
    """A boolean mask of the windows, or the clean mask of the Traffic of this window set."""
    if isinstance(mask, Traffic):
        return _traffic(mask, windows).clean
    values = np.asarray(mask)
    if values.shape != (len(windows),) or values.dtype != bool:
        raise ValueError(f"{what} is a boolean mask of the {len(windows)} windows of role {windows.role}")
    return values


def _traffic(traffic, windows, what="the traffic"):
    """The Traffic of this window set (tcn.metody.traffic): the rates are per observed hour of its clean traffic."""
    if not isinstance(traffic, Traffic) or traffic.windows is not windows:
        raise ValueError(f"{what} of role {windows.role} is the Traffic of its window set (tcn.metody.traffic): a rate "
                         "is per observed hour of clean traffic (tcn.metody RATE_RULE)")
    return traffic


def _roles(roles, calibration):
    if type(roles) is not dict or "calibration" in roles or not all(
            type(v) is tuple and len(v) == 2 and isinstance(v[0], Okna) and v[0].role == name and calibration.same(v[0])
            for name, v in roles.items()):
        raise ValueError("roles maps each role other than calibration to (its window set, of calibration's "
                         "normalizer, its Traffic)")
    return {name: (windows, _traffic(traffic, windows)) for name, (windows, traffic) in roles.items()}


def _scores(method, windows):
    values = np.asarray(method.scores(windows), dtype=np.float64)
    if values.shape != (len(windows),) or not np.isfinite(values).all():
        raise ValueError(f"{_label(method)} gives no finite score for every window")
    return values


def _label(method):
    return getattr(method, "label", None) or getattr(method, "name", type(method).__name__)


class _Cached:
    """A method of the interface whose scores are computed once per window set (the window sets of one call stay
    alive, so their identity keys the cache)."""

    def __init__(self, method):
        self.method, self.name, self.kind = method, method.name, method.kind
        self.label, self._seen = _label(method), {}

    def scores(self, windows):
        key = id(windows)
        if key not in self._seen:
            self._seen[key] = (windows, _scores(self.method, windows))
        return self._seen[key][1]


def _methods(methods):
    if type(methods) not in (list, tuple) or not all(
            type(getattr(m, "name", None)) is str and getattr(m, "kind", None) in ("detector", "predictor")
            and callable(getattr(m, "scores", None)) for m in methods):
        raise ValueError("methods is a list of fitted methods of the interface of tcn.metody.Metoda")
    labels = [_label(m) for m in methods]
    if len(set(labels)) != len(labels):
        raise ValueError("every method of one diagnostic has its own label")
    return [_Cached(m) for m in methods]


def _models(models, protocol):
    """M of every seed: exactly analysis.seeds, each once, each with its seed, threshold and scores."""
    seeds = _value(protocol, "analysis.seeds")
    if type(models) not in (list, tuple) or not models or not all(
            type(getattr(m, "seed", None)) is int and _number(getattr(m, "threshold", None))
            and callable(getattr(m, "scores", None)) for m in models):
        raise ValueError("the models are M of every seed: objects of the interface of tcn.metody.MetodaM (seed, "
                         "threshold, scores)")
    if type(seeds) is not list or sorted(m.seed for m in models) != sorted(seeds) or len(set(seeds)) != len(seeds):
        raise ValueError(f"the models are M of exactly the seeds of analysis.seeds {seeds}, each once")
    return [(m, _Cached(m)) for m in models]


def _detect(detection, method, threshold, k, n):
    if detection is None:
        return None
    if not callable(detection):
        raise ValueError("detection is None or a function (method, threshold, k, n) -> its record")
    return detection(method, threshold, k, n)


# ------------------------------------------------------------------ what the exceedances have in common


def episodes(positive, windows):
    """The number of positive episodes of a boolean mask of the windows (EPISODE_RULE)."""
    positive = _mask(positive, windows, "positive")
    before = np.concatenate(([False], positive[:-1]))
    return int((positive & (windows.resets | ~before)).sum())


def tree_inputs(windows):
    """(names, values (n, 2 G + 1)): the inputs of the tree of every window (TREE_INPUTS)."""
    _okna(windows)
    norm, out = windows.normalizer, []
    for _, g, local in windows.arrays():
        g, local = windows.rows(g), windows.rows(local)
        changed = local[:, -1, :, 0] * norm.local_scale[:, 0] + norm.local_mean[:, 0]
        out.append(np.column_stack((g[:, -1] * norm.global_scale + norm.global_mean,
                                    (g[:, -1] - g[:, -2]) * norm.global_scale, changed.max(axis=1))))
    names = ([f"{name} at the last row" for name in windows.input_names]
             + [f"{name} difference at the last row" for name in windows.input_names]
             + ["largest changed_ratio of a scored bin at the last row"])
    return names, np.concatenate(out)


def _exceedances(method, windows, threshold, protocol):
    """(the plan of analysis.diagnostics, the scores, the exceeding windows, the head of the record)."""
    plan = diagnostics(protocol)
    _okna(windows)
    if not _number(threshold):
        raise ValueError("the threshold is a finite number")
    scores = _scores(method, windows)
    positive = scores > threshold
    found = episodes(positive, windows)
    head = {"label": _label(method), "name": method.name, "role": windows.role, "threshold": float(threshold),
            "windows": len(windows), "positive_windows": int(positive.sum()), "positive_episodes": found,
            "min_positive_episodes": plan["min_positive_episodes"], "episode_rule": EPISODE_RULE}
    return plan, scores, positive, head


def _confusion(truth, predicted):
    tp, fp = int((truth & predicted).sum()), int((~truth & predicted).sum())
    fn, tn = int((truth & ~predicted).sum()), int((~truth & ~predicted).sum())
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn}


def tree(method, windows, threshold, boots, *, protocol):
    """TREE_RULE for a fitted method at `threshold` on the windows of one set; boots: {session id: boot name}."""
    from sklearn.tree import DecisionTreeClassifier, export_text
    plan, _, positive, record = _exceedances(method, windows, threshold, protocol)
    record.update(depth=plan["tree_depth"], inputs=TREE_INPUTS, level=THRESHOLD_LEVEL, rule=TREE_RULE)
    window_boots = _boots(windows, boots)
    names = sorted(set(window_boots))
    if len(names) < 2:
        raise ValueError("the tree is cross-validated by boots: the window set needs two boots at least")
    if record["positive_episodes"] < plan["min_positive_episodes"]:
        return dict(record, outcome=UNEVALUATED, why=f"{record['positive_episodes']} positive episodes, fewer than "
                                                     f"{plan['min_positive_episodes']}")
    feature_names, features = tree_inputs(windows)

    def fitted(selection):
        return DecisionTreeClassifier(max_depth=plan["tree_depth"], class_weight="balanced",
                                      random_state=TREE_RANDOM_STATE).fit(features[selection], positive[selection])
    predicted, folds = np.zeros(len(windows), dtype=bool), []
    for boot in names:
        held = window_boots == boot
        predicted[held] = fitted(~held).predict(features[held])
        folds.append({"boot": boot, "windows": int(held.sum()), **_confusion(positive[held], predicted[held])})
    pooled = _confusion(positive, predicted)
    tp, fp, fn, tn = (pooled[key] for key in ("true_positive", "false_positive", "false_negative", "true_negative"))
    f1 = 2 * tp / (2 * tp + fp + fn)
    balanced = None if not tn + fp else (tp / (tp + fn) + tn / (tn + fp)) / 2
    whole = fitted(np.ones(len(windows), dtype=bool))
    return dict(record, boots=folds, pooled=pooled, f1=f1, balanced_accuracy=balanced,
                outcome=THRESHOLD_LIKE if f1 >= THRESHOLD_LEVEL else NOT_THRESHOLD_LIKE,
                tree=export_text(whole, feature_names=feature_names),
                splits=sorted({feature_names[i] for i in whole.tree_.feature if i >= 0}))


def _composed(method, windows, names, solo, composed):
    expected = _scores(method, windows)
    if not np.allclose(composed, expected, rtol=COMPOSE_RTOL, atol=COMPOSE_ATOL):
        raise ValueError(f"{_label(method)}: the score composed of its members differs from its score "
                         "(MEMBERS_RULE): its fitted state is not the one this module reads")
    return list(names), solo


def members(method, windows):
    """(names, solo (n, members)): the score of each member alone in every window (MEMBERS_RULE) of a fitted Z1,
    Z2, Z3 or M (tcn.metody); any other method is refused by name. Reads their fitted state (Z1's chosen candidate,
    its center and spread; Z2's counts and modes; Z3's chosen predictor; M's predictor)."""
    from tcn.metody import TWO_SIDED, MetodaM, Z1, Z2, Z3, _z3_predict
    _okna(windows)
    if isinstance(method, Z1):
        chosen = method if method.statistic is not None else method._chosen
        if chosen is None or chosen._center is None:
            raise ValueError("Z1 is not fitted")
        chosen._check(windows)
        standard = (chosen._values(windows) - chosen._center) / chosen._spread
        solo = np.abs(standard) if chosen.statistic in TWO_SIDED else standard
        return _composed(method, windows, [windows.input_names[j] for j in chosen._columns], solo, solo.max(axis=1))
    if isinstance(method, Z2):
        method._check(windows)
        solo = np.concatenate([np.abs(windows.rows(g)[:, -1, method._columns] - method._modes)
                               for _, g, _ in windows.arrays(bins=False)])
        return _composed(method, windows, [windows.input_names[j] for j in method._columns], solo, solo.max(axis=1))
    if isinstance(method, (MetodaM, Z3)):
        method._check(windows)
        if isinstance(method, MetodaM):  # In float32 on tensors, as MetodaM scores.
            predictor, dtype = method.bundle.predictor.eval(), torch.float32
        else:  # In float64 on numpy rows, as tcn.metody._predictor_errors.
            if method._chosen is None:
                raise ValueError("Z3 is not fitted")
            predictor, dtype = _z3_predict(method._chosen), torch.float64
        parts = []
        with torch.inference_mode():
            for _, g, local in windows.arrays():
                g, local = windows.rows(g), windows.rows(local)
                if dtype == torch.float32:
                    g, local = torch.as_tensor(g, dtype=dtype), torch.as_tensor(local, dtype=dtype)
                prediction = [torch.as_tensor(p, dtype=dtype) for p in predictor(g[:, :-1], local[:, :-1])]
                g, local = torch.as_tensor(g, dtype=dtype), torch.as_tensor(local, dtype=dtype)
                _, bin_error = prediction_errors(prediction, g[:, -1], local[:, -1])
                parts.append(torch.cat((0.5 * column_errors(prediction[0], g[:, -1]), 0.5 * bin_error), dim=1)
                             .double().numpy())
        solo, width = np.concatenate(parts), len(windows.input_names)
        names = list(windows.input_names) + [f"bin {b}" for b, _ in windows.bins]
        return _composed(method, windows, names, solo, solo[:, :width].sum(axis=1) + solo[:, width:].max(axis=1))
    raise ValueError(f"{_label(method)}: MEMBERS_RULE decomposes the score of Z1, Z2, Z3 and M only")


def one_member(method, windows, threshold, *, protocol):
    """ONE_MEMBER_RULE for a fitted Z1, Z2, Z3 or M at `threshold` on the windows of one set."""
    plan, _, positive, record = _exceedances(method, windows, threshold, protocol)
    names, solo = members(method, windows)
    record.update(level=THRESHOLD_LEVEL, members_rule=MEMBERS_RULE, rule=ONE_MEMBER_RULE)
    if record["positive_episodes"] < plan["min_positive_episodes"]:
        return dict(record, outcome=UNEVALUATED, why=f"{record['positive_episodes']} positive episodes, fewer than "
                                                     f"{plan['min_positive_episodes']}")
    alone = solo[positive] > threshold
    share = float(alone.any(axis=1).mean())
    counts = alone.sum(axis=0)
    return dict(record, share=share, outcome=THRESHOLD_LIKE if share >= THRESHOLD_LEVEL else NOT_THRESHOLD_LIKE,
                alone={names[j]: int(counts[j]) for j in np.argsort(-counts, kind="stable") if counts[j]})


def threshold_likeness(entries, windows, boots, *, protocol):
    """Both diagnostics (TREE_RULE, ONE_MEMBER_RULE) for every (fitted method, its threshold) of `entries`, which hold
    Z1, Z2 and Z3 once each and M of one seed or more (and no other method), on the windows of one set, and whether
    each diagnostic is used (USE_RULE)."""
    if type(entries) not in (list, tuple) or not all(type(e) in (list, tuple) and len(e) == 2 for e in entries):
        raise ValueError("entries is a list of (fitted method, its threshold)")
    names = [getattr(method, "name", None) for method, _ in entries]
    if sorted(n for n in names if n in REFERENCE) != list(REFERENCE) or "M" not in names or not set(names) <= {
            *REFERENCE, "M"}:
        raise ValueError("the diagnostics take Z1, Z2 and Z3 once each and M of one seed or more (proposal 8.5)")
    rows = [{"label": _label(method), "name": method.name,
             "tree": tree(method, windows, threshold, boots, protocol=protocol),
             "one_member": one_member(method, windows, threshold, protocol=protocol)} for method, threshold in entries]
    use = {}
    for diagnostic in ("tree", "one_member"):
        failed = {row["label"]: row[diagnostic]["outcome"] for row in rows
                  if row["name"] in REFERENCE and row[diagnostic]["outcome"] != THRESHOLD_LIKE}
        use[diagnostic] = {"used": not failed, "failed": failed}
    return {"methods": rows, "use": use, "rule": USE_RULE}


# ------------------------------------------------------------------ the networks of M's architecture


def shuffle_order(windows, seed):
    """The order of the rows of the context of every window (SHUFFLE_RULE): (n, window_rows - 1) positions, the last
    one kept."""
    _okna(windows)
    context = windows.window_rows - 1
    rng = np.random.default_rng([seed, SHUFFLE_ENTROPY, zlib.crc32(windows.role.encode())])
    order = rng.random((len(windows), context - 1)).argsort(axis=1)
    return np.concatenate((order, np.full((len(windows), 1), context - 1)), axis=1)


def _shuffled(values, order):
    """The rows of a batch (m, window_rows, ...) with its context in `order` (m, window_rows - 1)."""
    out = values.copy()
    out[:, :-1] = values[np.arange(len(values))[:, None], order]
    return out


class _ShuffledOkna(Okna):
    """A window set whose batches hold the shuffled context of SHUFFLE_RULE (the rows after the anchor; an anchor
    stays first); every other part is that of tcn.metody.Okna."""
    order = None

    def batch(self, selection, *, bins=True):
        g, local = super().batch(selection, bins=bins)
        order, first = self.order[np.asarray(selection, dtype=np.int64)], int(self.anchored)
        g[:, first:] = _shuffled(g[:, first:], order)
        if local is not None:
            local[:, first:] = _shuffled(local[:, first:], order)
        return g, local


def shuffled(windows, seed):
    """The window set of `windows` with its context shuffled (SHUFFLE_RULE): the same windows in the same order (the
    masks, the boots and the alarm resets of `windows` apply)."""
    _okna(windows)
    out = _ShuffledOkna(_sessions(windows), [(int(s), int(e), None if a < 0 else int(a)) for s, e, a in windows.index],
                        role=windows.role, normalizer=windows.normalizer, window_rows=windows.window_rows,
                        max_gap_s=windows.max_gap_s, interval_s=windows.interval_s)
    out.order = shuffle_order(windows, seed)
    return out


class _Branch(nn.Module):
    """One branch of M's predictor with the call of safeguard.model.Predictor (PARTIAL_RULE): (global context, bin
    context) -> the prediction of its part: the global inputs `columns` (mem, global) or the three values of each scored
    bin (bins)."""

    def __init__(self, part, predictor, columns):
        super().__init__()
        self.part, self.columns = part, list(columns)
        self.net = predictor.bin_tcn if part == "bins" else predictor.global_tcn

    def forward(self, global_context, local_context):
        if self.part != "bins":
            return self.net(global_context[..., self.columns])
        batch, steps, bins, channels = local_context.shape
        per_bin = local_context.permute(0, 2, 1, 3).reshape(batch * bins, steps, channels)
        return self.net(per_bin).reshape(batch, bins, 3)


def _errors(net, g, local):
    """(global error, bin error) of a batch by safeguard.model.prediction_errors: a part a branch does not predict has
    its target in place of its prediction, so its error is 0 (PARTIAL_RULE)."""
    if not isinstance(net, _Branch):
        return prediction_errors(net(g[:, :-1], local[:, :-1]), g[:, -1], local[:, -1])
    prediction = net(g[:, :-1], local[:, :-1])
    if net.part == "bins":
        return prediction_errors((g[:, -1], prediction), g[:, -1], local[:, -1])
    return prediction_errors((prediction, local[:, -1, :, :3]), g[:, -1][:, net.columns], local[:, -1])


def _branch_loss(net, g, local, labels=None):
    """The training loss of a partial model: LOSS_FORMULA of _errors (safeguard.training._prediction_loss's form)."""
    global_error, bin_error = _errors(net, g, local)
    return 0.5 * global_error.mean() + 0.5 * bin_error.mean()


class Siet(Metoda):
    """A TCN of M's architecture trained by M's training (TRAINING_RULE), Siet(variant):

        retrained   safeguard.model.Predictor on the windows given (the model of the context truncation, CONTEXT_RULE,
                    and of the shuffled context, SHUFFLE_RULE; on M's windows it is M's training again)
        random      the network with random weights (RANDOM_RULE)
        mem, global, bins
                    the partial models (PARTIAL_RULE)

    The interface of tcn.metody.Metoda: fit(train, dev, *, protocol, seed), scores, losses (a predictor); the label
    carries the variant and the seed."""
    name, kind = "M", "predictor"

    def __init__(self, variant):
        super().__init__()
        if variant not in VARIANTS:
            raise ValueError("Siet is one of " + ", ".join(VARIANTS) + "; name one")
        self.diagnostic, self.part = variant, PARTS[variant]
        self.seed = self.net = None

    @property
    def variant(self):
        return VARIANTS[self.diagnostic] if self.seed is None else f"{VARIANTS[self.diagnostic]}, seed {self.seed}"

    def fit(self, train, dev, *, protocol, seed):
        from safeguard.model import Predictor
        from safeguard.training import _fit, _prediction_loss, model_config, stream_seed
        from tcn.model import pocet_parametrov
        from tcn.opisne import training_settings
        record = self._bind(train, dev, seed)
        settings = training_settings(protocol)
        inputs = list(train.input_names)
        columns = ([j for j, name in enumerate(inputs) if name.startswith(MEMORY)] if self.part == "mem"
                   else [] if self.part == "bins" else list(range(len(inputs))))
        if self.part == "mem" and not columns:
            raise ValueError("Siet mem: no mem_* column is an input of the TCN under rule "
                             f"{train.normalizer.rule.name}")
        config = model_config({"model": settings["architecture"]}, train.window_rows,
                              len(columns) if self.part == "mem" else len(inputs))
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(stream_seed(seed, "predictor_init"))
            predictor = Predictor(config)
        net = predictor if self.part == "all" else _Branch(self.part, predictor, columns)
        self.seed, self.net = seed, net
        record.update(variant=self.variant, label=self.label)
        common = {"diagnostic": self.diagnostic, "part": self.part,
                  "inputs": ([] if self.part == "bins" else [inputs[j] for j in columns]),
                  "bins": self.part in ("all", "bins"), "architecture": config, "parameters": pocet_parametrov(net),
                  "loss_formula": LOSS_FORMULA, "score_formula": SCORE_FORMULA}
        if self.diagnostic == "random":
            net.eval()
            return dict(record, **common, chosen=None, why="untrained: the initial weights of the seed (RANDOM_RULE)",
                        rule=RANDOM_RULE)
        architecture, threads = settings["architecture"], torch.get_num_threads()
        torch.set_num_threads(min(threads, TRAIN_THREADS))
        try:
            stop, history = _fit(net, _prediction_loss if self.part == "all" else _branch_loss, train, dev,
                                 learning_rate=architecture["learning_rate"], clip=architecture["gradient_clip"],
                                 batch_size=architecture["batch_size"], stopping=settings["stopping"], seed=seed,
                                 name="predictor")
        finally:
            torch.set_num_threads(threads)
        return dict(record, **common, chosen={"epoch": stop["selected_epoch"]},
                    why="the epoch of the best dev loss under analysis.stopping, as M (TRAINING_RULE)", stop=stop,
                    history=[{"epoch": e, "train_loss": t, "dev_loss": d} for e, t, d in history],
                    training=TRAINING_RULE, rule=TRAINING_RULE if self.part == "all" else PARTIAL_RULE)

    def _errors(self, windows):
        self._check(windows)
        self.net.eval()
        losses, scores = [], []
        with torch.inference_mode():
            for _, g, local in windows.arrays():
                global_error, bin_error = _errors(self.net, torch.as_tensor(windows.rows(g), dtype=torch.float32),
                                                  torch.as_tensor(windows.rows(local), dtype=torch.float32))
                losses.append((0.5 * global_error + 0.5 * bin_error.mean(dim=-1)).double().numpy())
                scores.append(anomaly_score(global_error, bin_error).double().numpy())
        return np.concatenate(losses), np.concatenate(scores)

    def scores(self, windows):
        return self._errors(windows)[1]

    def losses(self, windows):
        return self._errors(windows)[0]


# ------------------------------------------------------------------ the context (proposal 8.5)


class _Context(Metoda):
    """An unfitted predictor (Z3, Z5, Siet("retrained")) fitted, selected on dev and scored by its own rule on the
    windows of the sets given with their context changed (_view); it takes the full window sets of every method (the
    masks and the boots of the full set apply)."""
    what = rule = None

    def __init__(self, inner):
        super().__init__()
        if not isinstance(inner, Metoda) or inner.kind != "predictor" or isinstance(inner, _Context):
            raise ValueError(f"the context is {self.what} for an unfitted predictor of the interface of "
                             "tcn.metody.Metoda (Z3, Z5, Siet)")
        self.inner, self.name, self.kind, self.seed = inner, inner.name, inner.kind, None

    def _view(self, windows):
        raise NotImplementedError

    def _change(self):
        raise NotImplementedError

    @property
    def variant(self):
        inner = self.inner.variant
        return self._change() + ("" if inner is None else f", {inner}")

    def fit(self, train, dev, *, protocol, seed):
        record = self._bind(train, dev, seed)
        self.seed = seed
        inner = self.inner.fit(self._view(train), self._view(dev), protocol=protocol, seed=seed)
        record.update(variant=self.variant, label=self.label)
        return dict(record, chosen=inner.get("chosen"), why=inner.get("why"), inner=inner, rule=self.rule)

    def scores(self, windows):
        return self.inner.scores(self._view(self._check(windows)))

    def losses(self, windows):
        return self.inner.losses(self._view(self._check(windows)))


class Truncated(_Context):
    """CONTEXT_RULE: Truncated(inner, rows), the predictor `inner` on the windows with the context cut to its last
    `rows` rows."""
    what, rule = "truncated", CONTEXT_RULE

    def __init__(self, inner, rows):
        super().__init__(inner)
        if type(rows) is not int or rows < 1:
            raise ValueError("the context is an integer of at least 1 row")
        self.rows = rows

    def _view(self, windows):
        return truncated(windows, self.rows)

    def _change(self):
        return f"context {self.rows}"

    def fit(self, train, dev, *, protocol, seed):
        return dict(super().fit(train, dev, protocol=protocol, seed=seed), rows=self.rows)


class Shuffled(_Context):
    """SHUFFLE_RULE: Shuffled(inner), the predictor `inner` on the windows with the context shuffled but its last row,
    by the seed of the fit."""
    what, rule = "shuffled", SHUFFLE_RULE

    def _view(self, windows):
        return shuffled(windows, self.seed)

    def _change(self):
        return "shuffled context"


def context_truncation(make, train, dev, roles, *, protocol, seed):
    """CONTEXT_RULE over analysis.diagnostics.contexts: for each context c, Truncated(make(), c) fitted on train and
    dev at `seed`, and its mean loss (CONTEXT_LOSS) over the windows of the mask of each role of `roles` ({name:
    (window set, boolean mask)}). make() gives a new unfitted predictor (Z3, Z5, or Siet("retrained") for M). Returns
    ({c: the fitted method}, the record)."""
    plan = diagnostics(protocol)
    if not callable(make):
        raise ValueError("make is a function that gives a new unfitted predictor")
    if type(roles) is not dict or not all(type(v) is tuple and len(v) == 2 and isinstance(v[0], Okna)
                                          for v in roles.values()):
        raise ValueError("roles maps each role to (its window set, a boolean mask of the windows whose loss counts)")
    masks = {name: _mask(mask, windows, "the mask") for name, (windows, mask) in roles.items()}
    fitted, rows = {}, []
    for c in plan["contexts"]:
        method = Truncated(make(), c)
        record = method.fit(train, dev, protocol=protocol, seed=seed)
        loss = {}
        for name, (windows, _) in roles.items():
            values = method.losses(windows)[masks[name]]
            loss[name] = float(values.mean()) if len(values) else None
        fitted[c] = method
        rows.append({"rows": c, "label": method.label, "chosen": record["chosen"], "loss": loss, "fit": record})
    return fitted, {"contexts": rows, "loss_rule": CONTEXT_LOSS, "rule": CONTEXT_RULE}


# ------------------------------------------------------------------ the alarm rule and the threshold


def _matched(methods, calibration, traffic, budget_value, k, n, roles, detection):
    out = []
    for method in methods:
        found = matched_rate(method, calibration, traffic, budget_value, k=k, n=n, roles=roles)
        out.append(dict(found, detection=_detect(detection, method.method, found["threshold"], k, n)))
    return out


def _seeds(models, calibration, clean, k, n, roles, detection, thresholds):
    """M of every seed at its threshold (`thresholds` by seed): its clean alarms on calibration, its rates on the
    roles given and the detection."""
    rows = []
    for model, cached in models:
        threshold = thresholds[model.seed]
        rows.append({"label": _label(model), "seed": model.seed, "threshold": threshold,
                     "alarms": alarm_count(cached.scores(calibration), calibration, threshold, k=k, n=n, clean=clean),
                     "rates": {name: rate(cached.scores(windows), windows, threshold, k=k, n=n, traffic=traffic)
                               for name, (windows, traffic) in roles.items()},
                     "detection": _detect(detection, model, threshold, k, n)})
    return rows


def _walked(seeds, models, calibration, traffic, budget_value, k, n, roles, detection):
    """SEED_WALK_RULE: every row of `seeds` (M of each seed at its own threshold, _seeds) gets "matched", the seed's
    matched rate at the budget with the detection at that threshold."""
    for row, (model, cached) in zip(seeds, models):
        found = matched_rate(cached, calibration, traffic, budget_value, k=k, n=n, roles=roles)
        row["matched"] = dict(found, detection=_detect(detection, model, found["threshold"], k, n))
    return seeds


def _calibration_set(calibration, clean):
    _okna(calibration, "calibration")
    if calibration.role != "calibration":
        raise ValueError(f"the budget and the thresholds come from role calibration, not {calibration.role}")
    return _mask(clean, calibration)


def alarm_rules(models, methods, calibration, traffic, *, protocol, roles, detection):
    """ALARM_RULES_RULE: for each [k, n] of analysis.diagnostics.alarm_rules the budget, M of every seed and each
    method's matched rate under k of n. traffic: the Traffic of calibration (tcn.metody.traffic); roles: {name: (window
    set, its Traffic)} other than calibration; detection: None (NO_DETECTION, recorded) or a function (method,
    threshold, k, n) -> its record (tcn.k2.detection), called at every threshold."""
    plan = diagnostics(protocol)
    clean = _calibration_set(calibration, traffic)
    _traffic(traffic, calibration, "the traffic of calibration")
    models, methods, roles = _models(models, protocol), _methods(methods), _roles(roles, calibration)
    rows = []
    for k, n in plan["alarm_rules"]:
        seeds = _seeds(models, calibration, clean, k, n, roles, detection, {m.seed: m.threshold for m, _ in models})
        value = budget([row["alarms"] for row in seeds])
        rows.append({"k": k, "n": n, "budget": value,
                     "seeds": _walked(seeds, models, calibration, traffic, value, k, n, roles, detection),
                     "methods": _matched(methods, calibration, traffic, value, k, n, roles, detection)})
    return {"main": dict(zip(("k", "n"), _rule(protocol))), "rules": rows,
            "detection": "given" if detection is not None else NO_DETECTION, "alarm_rule": ALARM_RULE,
            "budget_rule": BUDGET_RULE, "seed_walk_rule": SEED_WALK_RULE, "rule": ALARM_RULES_RULE}


def _quantile(values, fpr):
    """The threshold of safeguard.training.calibrate: the quantile 1 - fpr, numpy method higher."""
    return float(np.quantile(values, 1 - fpr, method="higher"))


def leave_one_boot_out(models, methods, calibration, clean, boots, *, protocol):
    """LEAVE_ONE_OUT_RULE: for each boot of calibration (boots: {session id: boot name}) the thresholds of M of every
    seed and of each method on the calibration without it, and the range of each threshold over the boots; clean: the
    clean mask of calibration or its Traffic."""
    clean = _calibration_set(calibration, clean)
    models, methods = _models(models, protocol), _methods(methods)
    fpr, (k, n) = _fpr(protocol), _rule(protocol)
    window_boots = _boots(calibration, boots)
    names = sorted(set(window_boots))
    if len(names) < 2:
        raise ValueError("one boot of calibration is left out: calibration needs two boots at least")
    session_boots = [boots[ident] for ident in calibration.session_ids]
    rows = []
    for boot in names:
        left, kept = _subset(calibration, [s for s, b in enumerate(session_boots) if b != boot])
        mask = clean[kept]
        seeds = []
        for model, cached in models:
            scores = cached.scores(calibration)[kept]
            threshold = _quantile(scores, fpr)
            seeds.append({"seed": model.seed, "threshold": threshold,
                          "alarms": alarm_count(scores, left, threshold, k=k, n=n, clean=mask)})
        value = budget([row["alarms"] for row in seeds])
        found = [{"label": method.label, **matched_threshold(method.scores(calibration)[kept], left, value, k=k, n=n,
                                                             clean=mask)} for method in methods]
        rows.append({"left_out": boot, "windows": len(left), "clean_windows": int(mask.sum()), "budget": value,
                     "seeds": seeds, "methods": [{key: row[key] for key in ("label", "threshold", "alarms",
                                                                            "exhausted")} for row in found]})

    def spread(values):
        return {"min": min(values), "max": max(values)}
    ranges = {"seeds": {model.seed: dict(spread([r["seeds"][i]["threshold"] for r in rows]), main=model.threshold)
                        for i, (model, _) in enumerate(models)},
              "methods": {method.label: spread([r["methods"][j]["threshold"] for r in rows])
                          for j, method in enumerate(methods)}}
    return {"boots": rows, "range": ranges, "fpr": fpr, "k": k, "n": n, "threshold_rule": THRESHOLD_RULE,
            "rule": LEAVE_ONE_OUT_RULE}


def clean_threshold(models, methods, calibration, traffic, *, protocol, roles, detection):
    """CLEAN_THRESHOLD_RULE: M of every seed and each method at the main threshold of M and at the threshold from the
    clean windows of calibration only. traffic: the Traffic of calibration; roles and detection as alarm_rules."""
    clean = _calibration_set(calibration, traffic)
    _traffic(traffic, calibration, "the traffic of calibration")
    if not clean.any():
        raise ValueError("calibration has no clean window: the threshold from clean traffic only has no score")
    models, methods, roles = _models(models, protocol), _methods(methods), _roles(roles, calibration)
    fpr, (k, n) = _fpr(protocol), _rule(protocol)
    recomputed = {m.seed: _quantile(cached.scores(calibration), fpr) for m, cached in models}
    variants = []
    for name, thresholds in (("main", {m.seed: m.threshold for m, _ in models}),
                             ("clean", {m.seed: _quantile(cached.scores(calibration)[clean], fpr)
                                        for m, cached in models})):
        seeds = _seeds(models, calibration, clean, k, n, roles, detection, thresholds)
        if name == "main":
            for row in seeds:
                row["main_recomputed"] = recomputed[row["seed"]]
        value = budget([row["alarms"] for row in seeds])
        if name == "main":
            _walked(seeds, models, calibration, traffic, value, k, n, roles, detection)
        variants.append({"threshold": name, "budget": value, "seeds": seeds,
                         "methods": _matched(methods, calibration, traffic, value, k, n, roles, detection)})
    return {"variants": variants, "fpr": fpr, "k": k, "n": n, "calibration_windows": len(calibration),
            "clean_windows": int(clean.sum()), "detection": "given" if detection is not None else NO_DETECTION,
            "rate_rule": RATE_RULE, "seed_walk_rule": SEED_WALK_RULE, "rule": CLEAN_THRESHOLD_RULE}
