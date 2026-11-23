"""The methods of the comparison in one wrapper, and the matched alarm rate (protocol v5, package B7a, agent W).

Binding texts: the lead's skeleton dokazy/B7/kostra/KOSTRA.md sections 2 and 3 with point 1 of its addendum of
2026-11-22T20:55Z, the design dokazy/B7/navrh/NAVRH_B7a.md sections 1.1 to 1.4 and 2, and proposal 8.3
(docs/NAVRH_PROTOKOL_V5.sk.md). Package B7a reads no test role: everything here runs on the window sets it is given.

    Okna                        the window set every method sees (design 1.1)
    Metoda                      the interface: fit(train, dev, *, protocol, seed) -> record, scores(windows),
                                losses(windows)
    Z0, Z0Random, Z1, Z2, Z3, Z4, Z5, MetodaM
                                the methods of skeleton section 2 (design 1.4); the descriptive methods of the
                                addendum (z-score, isolation forest, GRU, LSTM) are tcn/opisne.py
    errors(...)                 the loss (LOSS_FORMULA) and the score (SCORE_FORMULA) of predictions of the last row,
                                by safeguard.model.prediction_errors (design 1.3)
    clean_windows(...)          the clean traffic (CLEAN_RULE)
    alarm_edges, alarm_count    the alarm rule (ALARM_RULE)
    model_budget, budget        the budget (BUDGET_RULE)
    matched_threshold, rate     the threshold of a method at the budget (THRESHOLD_RULE), its alarms per hour on a
                                role (RATE_RULE)
    matched_rate(method, ...)   both for one fitted method: the threshold, the alarms at it and the rate on every
                                role given
    z0_random(...)              the random variant of Z0 at the matched rate over its repetitions (Z0_RANDOM_RULE)
    grid, z0_repetitions, alarm_rule, stream_seed, protocol_value
                                the accessor of the protocol keys of design 1.6 (agent K writes them)

The windows (design 1.1). Every method sees the same windows with the same normalized inputs: those of the bundle M
it is compared with. Okna.from_sessions builds them by safeguard.training.Windows, the bundle's WindowBuffer (anchored
when the normalization rule has a differenced column), with M's normalizer, for one role. A batch (Okna.arrays)
holds the global inputs (n, L, G) and the bin inputs (n, L, B, 4): L is window_rows + 1 when anchored (the anchor, the
measured row before the window, first) and window_rows otherwise, G = len(normalizer.input_names), B the scored bins.
The rows a method reads are the window_rows rows after the anchor (Okna.rows): the anchor enters only through the first
differences of a differenced input, as in M, so every predictor predicts the window's last row from the same
window_rows - 1 rows as M. Okna.batches and Okna.indices are the protocol of safeguard.training.Windows over those rows,
for code written against it (tcn/opisne.py). A method fitted under one normalizer refuses a window set of another
(normalizer_sha256). No method fits a normalizer or a threshold of its own: its threshold is the matched one, on role
calibration.

The methods (skeleton section 2, design 1.4): Z0 never alarms, Z0Random alarms at random at the matched rate, Z1 is a
threshold per column, Z2 some count off its mode, Z3 prediction without learning, Z4 the offered load, Z5 a linear
autoregression, MetodaM the TCN bundle of one seed. The rule of each is its *_RULE below, word for word in its fit
record; the grids of Z1, Z3 and Z5 come from analysis.methods.<m>.grid (null until G3a) with the parameters of
scripts/protocol_v5.py GRID_PARAMETERS (each holds what GRID_VALUES says), and the selection of each is its
*_SELECTION. A detector's losses() is None.
"""
import hashlib
import json
import math

import numpy as np
import torch

from safeguard.model import LOSS_FORMULA, SCORE_FORMULA, anomaly_score, prediction_errors

KINDS = ("detector", "predictor")
MODES = ("campaign", "rehearsal")  # The plan modes of scripts/protocol_v5.py: the name of an analysis stream.
# The floats of the bins in one batch of a window set: memory only, no result depends on it.
BATCH_ELEMENTS = 2 ** 22

# ------------------------------------------------------------------ the rules (design 1.2, written into the records)

ALARM_RULE = (
    "an alarm is a rising edge of k of n: a window exceeds when its score is above the threshold (strictly, as "
    "safeguard.runtime); the alarm is up at a window when its last n windows since the last reset include at least k "
    "that exceed; an edge is a window where the alarm is up and was not up at the window before it; the history and "
    "the alarm state reset where safeguard.training.calibrate resets them: at a new session, at a seq that is not the "
    "one before plus one and at a time step outside (0, max_gap_s] (a barrier, a chain change and every other "
    "discontinuity of the WindowBuffer break the run of window ends); an alarm counts at the window of its edge")
CLEAN_RULE = (
    "a window is clean when the span of its frames, from its first frame (the anchor of an anchored window) to its "
    "last row, meets none of these closed or half-open intervals of its session: an event from host_start_unix to "
    "host_stopped_unix plus analysis.reverberation_s (the event and its reverberation, joined as tcn/eval.py "
    "kategorie_udalosti joins them), and the full-snapshot band [T - full_snapshot_guard.before_s, T + window_rows * "
    "interval_s) of each full snapshot of the session at T (scripts/protocol_v5.py guards: up to the first scored row "
    "after it); judgment: one overlap rule for the three, over every frame the window's inputs depend on")
BUDGET_RULE = (
    "the median over the seeds of M's alarms (ALARM_RULE) on the clean windows of calibration (CLEAN_RULE), each seed "
    "at its own calibrated threshold, rounded up (skeleton B7 section 3, design 1.2); safeguard.training.calibrate() "
    "alarm_events counts every calibration window, events included, and is not the budget")
THRESHOLD_RULE = (
    "the distinct scores of the method on the windows of calibration are walked from the top down as thresholds; the "
    "threshold is the last one before the first at which the alarms on the clean windows (ALARM_RULE, CLEAN_RULE) "
    "exceed the budget (skeleton B7 section 3, the lead's judgment); the count is not monotonic in the threshold, so "
    "the walk stops at the first excess; with a budget of 0 the threshold is the most sensitive one before the first "
    "alarm; when no threshold exceeds the budget, the walk ends at the lowest score (exhausted)")
RATE_RULE = (
    "the alarms (ALARM_RULE) on the clean windows of a role at a threshold, per hour of those windows: their number "
    "times interval_s (the scored clean time)")
STREAM_RULE = (
    "a stream of the analysis takes scripts/protocol_v5.py seed(name, purpose, unit, -1, 0) with the protocol name of "
    "the plan mode (the rehearsal's own name in rehearsal mode), the unit of z0_alarms being the role on whose windows "
    "the random variant of Z0 places its alarms (streams.rule as package B7a writes it, agent K; its "
    "scripts/protocol_v5.py analysis_seed gives the same seed)")
Z0_RULE = ("never alarms: the score of every window is 0, its only observed value, so at its matched threshold (0) "
           "no window exceeds")
Z0_RANDOM_RULE = (
    "random alarms at the matched rate: the repetitions of a role come in order from one generator, "
    "numpy.random.default_rng(seed) of the role's stream z0_alarms (STREAM_RULE, streams.rule), each repetition one "
    "uniform number of [0, 1) for every window of the role in the order of its window set (random((repetitions, "
    "windows)), row r being repetition r); the threshold of a repetition is THRESHOLD_RULE on calibration and its "
    "alarms are RATE_RULE on each role; the mean over analysis.matched_rate.z0_repetitions repetitions is reported. "
    "The numbers of a window depend on the window set they are drawn for: the set of a role is every window of its "
    "sessions in the order of Okna.from_sessions")
Z1_RULE = (
    "a threshold per column (proposal 8.3): for each TCN input c the statistic s_c of the window's rows at its last "
    "row (value: the last row; difference: the last row minus the row before it; moving_average w: the mean of the "
    "last w rows; cusum d: the two-sided tabular CUSUM over the window's rows from 0, S+ = max(0, S+ + x - d) and "
    "S- = max(0, S- - x - d), max(S+, S-) at the last row; mem_changed_max: the last row of the input mem_changed_max "
    "alone), on M's normalized inputs (centred at the train mean, so the CUSUM's reference is that mean); each s_c is "
    "standardized (judgment: design 1.4's normalized exceedance, so that every column's threshold lies at the same "
    "multiple of the train spread of its statistic) by its mean m_c and standard deviation v_c over the windows of "
    "train, v_c at least the column's floor in normalized units (analysis.scale.floor over the normalizer's scale, so "
    "that as in M's normalizer a change below one step of the quantity never weighs much); the score is the largest "
    "|s_c - m_c| / v_c over the inputs (value, difference, moving_average) or the largest (s_c - m_c) / v_c (cusum, "
    "mem_changed_max, where a high value is the anomaly)")
Z1_SELECTION = (
    "the candidate with the highest value of the given criterion on dev (skeleton section 2: the share of the "
    "interventions inserted into dev that it detects, package B7b); ties to the first candidate in the order value, "
    "difference, moving_average by the grid, cusum by the grid, mem_changed_max; mem_changed_max is a candidate only "
    "when it is an input of the TCN")
Z2_RULE = (
    "some count differs from its mode (proposal 8.3): the counts are the TCN inputs whose analysis.scale.floor is 1 "
    "(a differenced count by its first difference); the mode of each over the last rows of the train windows is the "
    "smallest of its most frequent values (features/qualification.py _mode); the score of a window is the largest "
    "|x_c - mode_c| over the counts at its last row in M's normalized units (judgment: as M weighs a count, by its "
    "train scale of at least one unit), 0 exactly when every count is at its mode")
Z3_RULE = (
    "prediction without learning (proposal 8.3): the window's last row from the rows before it, by the last value (the "
    "row before it), the window mean (the mean of the rows before it) or the EWMA (s = the first row, then s = a x + "
    "(1 - a) s over the rows before the last; a from analysis.methods.Z3.grid.ewma_alpha), for the global inputs and "
    "the three values of each scored bin alike; loss and score by errors()")
Z3_SELECTION = ("the candidate with the lowest mean loss on dev (LOSS_FORMULA); ties to the first in the order last, "
                "mean, ewma by the grid")
Z4_RULE = (
    "is the model a load meter (proposal 8.3): variant load scores a window by the offered load of its last row "
    "(features/qualification.py offered_load: the user sessions offered in its interval; a high load is the "
    "anomaly); variant residual regresses each TCN input on the offered load of the same row over the last rows of "
    "the train windows (least squares with an intercept) and scores a window by the largest |residual_c| / v_c at its "
    "last row, v_c the standard deviation of the train residuals of input c, at least its floor in normalized units "
    "as in Z1; neither has a free parameter and the skeleton names both, so both are reported (judgment)")
Z5_RULE = (
    "linear autoregression (ridge) on the same window (proposal 8.3), the linear counterpart of M's two branches: the "
    "global inputs of the window's last row from those of the rows before it (all of them, flattened, with an "
    "intercept), and the three values of each scored bin from the four channels of the same bin in the rows before it "
    "(one model shared by the bins, as M's bin branch); each output minimizes the mean over the train windows (and "
    "bins) of its squared error, weighted as LOSS_FORMULA weighs it (judgment: the loss M is trained on; each value "
    "of a bin by one over the measured "
    "values of the bin, the entropy only where the bin changed), plus a (analysis.methods.Z5.grid.ridge_alpha) times "
    "the sum of its squared coefficients but the intercept; a bin value with no train observation is predicted 0, the "
    "normalizer's mean")
Z5_SELECTION = "the strength with the lowest mean loss on dev (LOSS_FORMULA); ties to the first by the grid"
# The reason of a choice, `why` in every fit record (the key of tcn/opisne.py's records too; merge of B7a).
NO_PARAMETER = "no free parameter (analysis.selection): nothing is chosen on dev"
M_WHY = "the epoch of the best dev loss under analysis.stopping, chosen when the bundle was trained (B6)"
M_RULE = (
    "the TCN of the bundle of one seed (its predictor at the epoch B6 selected by the dev loss): SCORE_FORMULA and "
    "LOSS_FORMULA of its prediction of the window's last row, as safeguard/bundle.py Bundle.score and "
    "safeguard/training.py compute them (float32)")

# What the list of each parameter of a grid holds (analysis.methods.<m>.grid, null until G3a; design 1.4). The
# parameters of each method are scripts/protocol_v5.py GRID_PARAMETERS, one constant for the protocol and this module
# (merge of B7a); Z0, Z2, Z4 and M have no free parameter (grid {}, never read here).
GRID_VALUES = {"moving_average_rows": "integers of at least 1 and at most window_rows",
               "cusum_shift": "numbers of at least 0 (normalized units)",
               "ewma_alpha": "numbers in (0, 1]",
               "ridge_alpha": "positive numbers"}


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


GRID_CHECKS = {"moving_average_rows": lambda v: type(v) is int and v >= 1,
               "cusum_shift": lambda v: _number(v) and v >= 0,
               "ewma_alpha": lambda v: _number(v) and 0 < v <= 1,
               "ridge_alpha": lambda v: _number(v) and v > 0}

# ------------------------------------------------------------------ the protocol keys (design 1.6)


def protocol_value(protocol, path):
    """The value at the dotted `path` of the protocol: the one accessor of this module for the keys agent K writes
    (analysis.methods.<m>.grid, analysis.matched_rate, streams.purposes with z0_alarms) and for the existing ones. A
    missing key is refused by name."""
    value = protocol
    for part in path.split("."):
        if type(value) is not dict or part not in value:
            raise ValueError(f"protocol key {path} is missing (design B7a 1.6)")
        value = value[part]
    return value


def grid(protocol, method):
    """analysis.methods.<method>.grid of Z1, Z3 or Z5, checked: null until G3a is refused by name (the method has free
    parameters, design 1.4), and so is a grid without exactly the parameters of scripts/protocol_v5.py GRID_PARAMETERS,
    each a non-empty list of distinct values as GRID_VALUES says."""
    from scripts.protocol_v5 import GRID_PARAMETERS
    if method not in GRID_PARAMETERS:
        raise ValueError(f"method {method!r} reads no grid; the grids are those of {', '.join(GRID_PARAMETERS)}")
    unknown = [name for name in GRID_PARAMETERS[method] if name not in GRID_VALUES]
    if unknown:
        raise ValueError(f"scripts/protocol_v5.py GRID_PARAMETERS names the parameter {unknown[0]} of {method}, which "
                         "tcn/metody.py does not read")
    path = f"analysis.methods.{method}.grid"
    value = protocol_value(protocol, path)
    keys = {name: GRID_VALUES[name] for name in GRID_PARAMETERS[method]}
    if value is None:
        raise ValueError(f"{path} is null: the grid of {method} is determined in G3a (determined_at), so {method} is "
                         "not fitted before it")
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(f"{path} must be an object of exactly the keys {', '.join(keys)}")
    for key, what in keys.items():
        items = value[key]
        if (type(items) is not list or not items or not all(map(GRID_CHECKS[key], items))
                or len(set(items)) != len(items)):
            raise ValueError(f"{path}.{key} must be a non-empty list of distinct {what}")
    return value


def z0_repetitions(protocol):
    """analysis.matched_rate.z0_repetitions: the repetitions of the random variant of Z0 (design 1.6: 200)."""
    value = protocol_value(protocol, "analysis.matched_rate.z0_repetitions")
    if type(value) is not int or value < 1:
        raise ValueError("analysis.matched_rate.z0_repetitions must be an integer of at least 1")
    return value


def alarm_rule(protocol):
    """(k, n) of analysis.alarm_rule, the alarm rule of every method."""
    k, n = (protocol_value(protocol, "analysis.alarm_rule." + key) for key in ("k", "n"))
    _check_rule(k, n)
    return k, n


def stream_seed(protocol, purpose, unit, *, mode):
    """The seed of the stream `purpose` of the analysis for `unit` (STREAM_RULE): `purpose` must be one of
    streams.purposes (agent K adds z0_alarms and bootstrap), the unit of z0_alarms a role of the protocol's roles;
    `mode` is the plan mode of the corpus, campaign or rehearsal, with no default."""
    purposes = protocol_value(protocol, "streams.purposes")
    if type(purposes) is not list or purpose not in purposes:
        raise ValueError(f"streams.purposes has no {purpose}: the stream of design B7a 1.6 (agent K adds it)")
    if purpose == "z0_alarms" and unit not in protocol_value(protocol, "roles"):
        raise ValueError(f"the unit of the stream z0_alarms is a role of the protocol, not {unit!r}")
    if type(unit) is not str or not unit:
        raise ValueError("the unit of a stream of the analysis is a non-empty name")
    if mode not in MODES:
        raise ValueError(f"the plan mode is campaign or rehearsal, not {mode!r}: it names the stream")
    name = protocol_value(protocol, "name")
    if mode == "rehearsal":
        name += protocol_value(protocol, "rehearsal.name_suffix")
    from scripts.protocol_v5 import seed
    return seed(name, purpose, unit, -1, 0)


# ------------------------------------------------------------------ the window set (design 1.1)


def fingerprint(normalizer):
    """sha256 of the normalizer (its to_dict, keys sorted): the identity of the inputs a method sees."""
    return hashlib.sha256(json.dumps(normalizer.to_dict(), sort_keys=True).encode()).hexdigest()


SESSION_KEYS = ("id", "global", "local", "seq", "timestamp", "full_times", "load")


class Okna:
    """A set of scoring windows of one role with the inputs of one normalizer (module docstring, design 1.1).

    role: the role of the sessions (a role of the protocol; the unit of the stream z0_alarms). sessions: per session
    {id, global (T, G), local (T, B, 4), seq (T,), timestamp (T,), full_times, load}: the normalized inputs of every
    frame of the session (normalizer.inputs), its seq and time, the times of its full snapshots (the bands of
    CLEAN_RULE) and its offered load per frame (Z4; None for every session when it is not given). windows: per window
    (session index, position of its last row, position of its anchor or None), in the order of the sessions and of
    seq within one. The batches are built from the session arrays when asked, never copied as sliding tensors (as
    safeguard.training.Windows): arrays() gives float64 numpy batches with the anchor first (design 1.1), batches()
    and indices the protocol of safeguard.training.Windows (the rows after the anchor as float32 tensors)."""

    def __init__(self, sessions, windows, *, role, normalizer, window_rows, max_gap_s, interval_s):
        from safeguard.features import FeatureNormalizer
        if not isinstance(normalizer, FeatureNormalizer):
            raise ValueError("a window set needs the FeatureNormalizer of the bundle M it is compared with")
        if type(role) is not str or not role:
            raise ValueError("a window set names the role of its sessions")
        self.role = role
        if type(window_rows) is not int or window_rows < 2:
            raise ValueError("window_rows must be an integer of at least 2")
        for name, value in (("max_gap_s", max_gap_s), ("interval_s", interval_s)):
            if not _number(value) or value <= 0:
                raise ValueError(f"{name} must be a positive number")
        self.normalizer = normalizer
        self.normalizer_sha256 = fingerprint(normalizer)
        self.input_names = tuple(normalizer.input_names)
        self.bins = tuple(normalizer.bins)
        self.anchored = bool(normalizer.rule.anchored)
        self.window_rows, self.max_gap_s, self.interval_s = window_rows, float(max_gap_s), float(interval_s)
        self.length = window_rows + int(self.anchored)
        width, bins = len(self.input_names), len(self.bins)
        self.session_ids, self._global, self._local, self._load, self.full_times = [], [], [], [], []
        self._seq, self._times = [], []
        loads = set()
        for session in sessions:
            if type(session) is not dict or set(session) != set(SESSION_KEYS):
                raise ValueError("a session of a window set has exactly the keys " + ", ".join(SESSION_KEYS))
            ident = session["id"]
            if type(ident) is not str or not ident or ident in self.session_ids:
                raise ValueError("every session of a window set has its own non-empty id")
            g = np.asarray(session["global"], dtype=np.float64)
            local = np.asarray(session["local"], dtype=np.float64)
            seq = np.asarray(session["seq"])
            times = np.asarray(session["timestamp"], dtype=np.float64)
            rows = len(g)
            if (g.shape != (rows, width) or local.shape != (rows, bins, 4) or seq.shape != (rows,)
                    or times.shape != (rows,) or not rows):
                raise ValueError(f"session {ident}: global ({rows}, {width}), local ({rows}, {bins}, 4), seq and "
                                 "timestamp of its rows, at least one")
            if not (np.isfinite(g).all() and np.isfinite(local).all() and np.isfinite(times).all()):
                raise ValueError(f"session {ident}: non-finite inputs or times")
            if not np.isin(local[..., 3], (0, 1)).all():
                raise ValueError(f"session {ident}: the mask has_changed of a bin is 0 or 1")
            if seq.dtype.kind not in "iu" or np.any(np.diff(seq) <= 0) or np.any(np.diff(times) <= 0):
                raise ValueError(f"session {ident}: seq are integers and seq and times increase")
            full = session["full_times"]
            if type(full) not in (list, tuple) or not all(map(_number, full)):
                raise ValueError(f"session {ident}: full_times is the list of the times of its full snapshots")
            load = session["load"]
            loads.add(load is None)
            if load is not None:
                load = np.asarray(load, dtype=np.float64)
                if load.shape != (rows,) or not np.isfinite(load).all() or (load < 0).any():
                    raise ValueError(f"session {ident}: load is the offered load of each of its {rows} rows, finite "
                                     "and at least 0")
            self.session_ids.append(ident)
            self._global.append(g)
            self._local.append(local)
            self._load.append(load)
            self.full_times.append([float(t) for t in full])
            self._seq.append(seq.astype(np.int64))
            self._times.append(times)
        if len(loads) > 1:
            raise ValueError("the offered load is given for some sessions only: give it for every session or none")
        self.has_load = loads == {False}
        index, seqs, ends, starts = [], [], [], []
        previous = None
        for item in windows:
            if type(item) not in (list, tuple) or len(item) != 3:
                raise ValueError("a window is (session index, position of its last row, position of its anchor)")
            s, end, anchor = item
            if type(s) is not int or not 0 <= s < len(self.session_ids) or type(end) is not int:
                raise ValueError("a window names a session of the set and the integer position of its last row")
            seq, times = self._seq[s], self._times[s]
            first = end - window_rows + 1
            if not 0 <= first <= end < len(seq):
                raise ValueError(f"window ending at position {end} of session {self.session_ids[s]} does not hold "
                                 f"{window_rows} rows")
            if self.anchored != (anchor is not None) or (
                    anchor is not None and (type(anchor) is not int or not 0 <= anchor < first)):
                raise ValueError("an anchored window set names the anchor of each window, a row before its first; "
                                 "a set without a differenced input names none")
            if previous is not None and (s < previous[0] or s == previous[0] and end <= previous[1]):
                raise ValueError("the windows come session by session, in the order of the sessions and of their "
                                 "last rows")
            previous = (s, end)
            index.append((s, end, -1 if anchor is None else anchor))
            seqs.append(seq[end])
            ends.append(times[end])
            starts.append(times[first if anchor is None else anchor])
        if not index:
            raise ValueError("a window set holds at least one window")
        self.index = np.array(index, dtype=np.int64)
        self.indices = [(s, end) for s, end, _ in index]  # As safeguard.training.Windows.indices.
        self.window_session = self.index[:, 0].copy()
        self.session = np.array(self.session_ids, dtype=object)[self.window_session]
        self.seq = np.array(seqs, dtype=np.int64)
        self.timestamp = np.array(ends, dtype=np.float64)
        self.start = np.array(starts, dtype=np.float64)
        step = self.timestamp[1:] - self.timestamp[:-1]
        continued = ((self.window_session[1:] == self.window_session[:-1]) & (self.seq[1:] == self.seq[:-1] + 1)
                     & (step > 0) & (step <= self.max_gap_s))
        # The resets of ALARM_RULE and the position of each window since the last one.
        self.resets = np.concatenate(([True], ~continued))
        first = np.maximum.accumulate(np.where(self.resets, np.arange(len(self.index)), 0))
        self.positions = np.arange(len(self.index)) - first

    @classmethod
    def from_sessions(cls, sessions, normalizer, contract, *, role, interval_s, load=None):
        """The windows of bundle M over `sessions` [(record, frames)] of one role: safeguard.training.Windows with M's
        normalizer and feature contract (window_rows, max_gap_s; the WindowBuffer anchored when the rule has a
        differenced column), interval_s the protocol's; a record that names a role must name `role`. load: None (Z4
        then refuses) or {session id: the offered load of each of its frames} for every session
        (features/qualification.py offered_load over its traffic_intervals.jsonl)."""
        from safeguard.training import Windows
        sessions = list(sessions)
        if any(record.get("role", role) != role for record, _ in sessions):
            raise ValueError(f"the sessions of a window set of role {role} are of that role")
        classes = sorted({record["scenario"] for record, _ in sessions})
        built = Windows(sessions, normalizer, contract, classes)
        if load is not None and (type(load) is not dict or set(load) != {frames[0].session for _, frames in sessions}):
            raise ValueError("load maps the id of every session to the offered load of each of its frames")
        rows = []
        for record, frames, g, local, _ in built.sessions:
            ident = frames[0].session
            if any(frame.session != ident for frame in frames):
                raise ValueError("the frames of one session carry its id")
            rows.append({"id": ident, "global": g, "local": local, "seq": np.array([f.seq for f in frames]),
                         "timestamp": np.array([f.timestamp for f in frames]),
                         "full_times": [f.timestamp for f in frames if f.full],
                         "load": None if load is None else load[ident]})
        windows = [(s, end, anchor) for (s, end), anchor in zip(built.indices, built.anchors)]
        return cls(rows, windows, role=role, normalizer=normalizer, window_rows=contract["window_rows"],
                   max_gap_s=contract["max_gap_s"], interval_s=interval_s)

    def __len__(self):
        return len(self.index)

    def _batch_size(self):
        return max(1, BATCH_ELEMENTS // (self.length * (len(self.input_names) + 4 * len(self.bins))))

    def batch(self, selection, *, bins=True):
        """(global (n, L, G), local (n, L, B, 4) or None) of the windows `selection`, the anchor first when
        anchored."""
        global_rows, local_rows = [], []
        for i in np.asarray(selection, dtype=np.int64):
            s, end, anchor = self.index[i]
            first = end - self.window_rows + 1
            take = np.arange(first, end + 1) if anchor < 0 else np.concatenate(([anchor], np.arange(first, end + 1)))
            global_rows.append(self._global[s][take])
            if bins:
                local_rows.append(self._local[s][take])
        return np.stack(global_rows), (np.stack(local_rows) if bins else None)

    def arrays(self, *, bins=True):
        """Yield (selection, global, local) of batch() over every window in order (local None without bins)."""
        size = self._batch_size()
        for start in range(0, len(self), size):
            selection = np.arange(start, min(start + size, len(self)))
            yield (selection, *self.batch(selection, bins=bins))

    def batches(self, batch_size, order=None):
        """The protocol of safeguard.training.Windows (indices, batches) for code written against it (tcn/opisne.py,
        safeguard.training _fit and _scores): float32 tensors (n, window_rows, G) and (n, window_rows, B, 4) of the
        rows of the windows after the anchor, what M's training reads, and labels 0 (the scenario class of
        safeguard.training.Windows, which no method reads), in the order `order` of windows (every window in order
        when None, as safeguard.training.Windows)."""
        if type(batch_size) is not int or batch_size < 1:
            raise ValueError("the batch size is an integer of at least 1")
        order = np.arange(len(self)) if order is None else np.asarray(order, dtype=np.int64)
        for start in range(0, len(order), batch_size):
            g, local = self.batch(order[start:start + batch_size])
            yield (torch.as_tensor(self.rows(g), dtype=torch.float32),
                   torch.as_tensor(self.rows(local), dtype=torch.float32), torch.zeros(len(g), dtype=torch.long))

    def rows(self, values):
        """The window_rows rows of a batch after its anchor (the rows a method reads)."""
        return values[:, int(self.anchored):]

    def last_load(self, selection):
        """The offered load of the last row of each window of `selection`; refused when the set has none."""
        if not self.has_load:
            raise ValueError("the window set has no offered load (Okna load): Z4 needs it")
        return np.array([self._load[s][end] for s, end, _ in self.index[np.asarray(selection, dtype=np.int64)]])

    def units(self):
        """The floor of each input in normalized units: analysis.scale.floor of its column over the normalizer's scale
        of it; refused under a rule without a floor (legacy_schema_2)."""
        floor = self.normalizer.rule.floor
        if floor is None:
            raise ValueError(f"normalization rule {self.normalizer.rule.name} has no floor (analysis.scale.floor)")
        return np.array([floor[name] for name in self.input_names]) / self.normalizer.global_scale

    def same(self, other):
        """Whether `other` holds windows of the same inputs and alarm resets: normalizer, window_rows, max_gap_s."""
        return (isinstance(other, Okna) and other.normalizer_sha256 == self.normalizer_sha256
                and (other.window_rows, other.max_gap_s, other.interval_s)
                == (self.window_rows, self.max_gap_s, self.interval_s))


def _okna(windows, what):
    if not isinstance(windows, Okna):
        raise ValueError(f"{what} must be a window set (tcn.metody.Okna)")
    return windows


def _calibration(windows):
    """The window set of role calibration, where the budget and every threshold come from (skeleton section 3)."""
    if _okna(windows, "calibration").role != "calibration":
        raise ValueError(f"the budget and the matched threshold come from role calibration, not {windows.role}")
    return windows


# ------------------------------------------------------------------ the loss and the score (design 1.3)


def errors(global_prediction, bin_prediction, global_target, local_target):
    """(loss, score) of each window as float64 numpy arrays (n,): LOSS_FORMULA (0.5 the mean squared error of the TCN
    inputs + 0.5 the mean over the scored bins of their masked error) and SCORE_FORMULA (the maximum over the bins in
    place of the mean) of the predictions of the window's last row, by safeguard.model.prediction_errors and
    anomaly_score. global (n, G), bins (n, B, 3), targets (n, G) and (n, B, 4); computed in the dtype given (M in
    float32, as Bundle.score)."""
    gp, bp, gt, lt = (torch.as_tensor(value) for value in (global_prediction, bin_prediction, global_target,
                                                           local_target))
    if gp.shape != gt.shape or gt.ndim != 2 or lt.ndim != 3 or bp.shape != (*lt.shape[:2], 3) or (
            len(gt) != len(lt)):
        raise ValueError("predictions (n, G) and (n, B, 3) against targets (n, G) and (n, B, 4)")
    global_error, bin_error = prediction_errors((gp, bp), gt, lt)
    loss = 0.5 * global_error + 0.5 * bin_error.mean(dim=-1)
    score = anomaly_score(global_error, bin_error)
    return loss.double().numpy(), score.double().numpy()


# ------------------------------------------------------------------ the alarm rule, the clean traffic (design 1.2)


def _check_rule(k, n):
    if type(k) is not int or type(n) is not int or not 1 <= k <= n:
        raise ValueError("the alarm rule k of n needs integers with 1 <= k <= n")


def _scores(scores, windows):
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (len(windows),) or not np.isfinite(values).all():
        raise ValueError(f"scores are {len(windows)} finite numbers, one per window")
    return values


def _mask(clean, windows):
    mask = np.asarray(clean)
    if mask.shape != (len(windows),) or mask.dtype != bool:
        raise ValueError(f"clean is a boolean mask of the {len(windows)} windows (clean_windows)")
    return mask


def _edges(exceed, windows, k, n):
    """The edges of ALARM_RULE for each row of `exceed` (thresholds x windows)."""
    count = exceed.shape[1]
    total = np.zeros((exceed.shape[0], count + 1), dtype=np.int32)
    np.cumsum(exceed, axis=1, dtype=np.int32, out=total[:, 1:])
    ends = np.arange(count)
    window = total[:, ends + 1] - total[:, np.maximum(ends + 1 - n, 0)]
    up = (windows.positions >= n - 1)[None, :] & (window >= k)
    before = np.zeros_like(up)
    before[:, 1:] = up[:, :-1]
    before[:, windows.resets] = False
    return up & ~before


def alarm_edges(scores, windows, threshold, *, k, n):
    """The windows where an alarm begins (ALARM_RULE) at `threshold`."""
    _check_rule(k, n)
    values = _scores(scores, _okna(windows, "windows"))
    if not _number(threshold):
        raise ValueError("the threshold is a finite number")
    return _edges((values > threshold)[None, :], windows, k, n)[0]


def alarm_count(scores, windows, threshold, *, k, n, clean):
    """The alarms (ALARM_RULE) at `threshold` that begin in a clean window (`clean`, CLEAN_RULE)."""
    edges = alarm_edges(scores, windows, threshold, k=k, n=n)
    return int((edges & _mask(clean, windows)).sum())


def clean_windows(windows, events, protocol):
    """The clean windows of a window set (CLEAN_RULE): `events` maps the id of every session of the set to the records
    of its events (events.json: host_start_unix, host_stopped_unix; [] for a session without one); reverberation_s,
    the band before a full snapshot, window_rows and interval_s are the protocol's."""
    _okna(windows, "windows")
    reverberation = protocol_value(protocol, "analysis.reverberation_s")
    before = protocol_value(protocol, "full_snapshot_guard.before_s")
    interval, rows = protocol_value(protocol, "interval_s"), protocol_value(protocol, "window_rows")
    if not (_number(reverberation) and reverberation >= 0 and _number(before) and before >= 0):
        raise ValueError("analysis.reverberation_s and full_snapshot_guard.before_s are numbers of at least 0")
    if (interval, rows) != (windows.interval_s, windows.window_rows):
        raise ValueError(f"the window set has window_rows {windows.window_rows} and interval_s {windows.interval_s}, "
                         f"the protocol {rows} and {interval}")
    if type(events) is not dict or set(events) != set(windows.session_ids):
        raise ValueError("events maps the id of every session of the window set, and no other, to its event records "
                         "([] for a session without events)")
    clean = np.ones(len(windows), dtype=bool)
    for s, ident in enumerate(windows.session_ids):
        mine = windows.window_session == s
        start, end = windows.start[mine], windows.timestamp[mine]
        hit = np.zeros(len(start), dtype=bool)
        for record in events[ident]:
            a, b = (record.get(key) if type(record) is dict else None for key in ("host_start_unix",
                                                                                  "host_stopped_unix"))
            if not (_number(a) and _number(b) and a <= b):
                raise ValueError(f"an event of session {ident} needs host_start_unix <= host_stopped_unix")
            hit |= (end >= a) & (start <= b + reverberation)
        for t in windows.full_times[s]:
            hit |= (end >= t - before) & (start < t + rows * interval)
        clean[mine] = ~hit
    return clean


# ------------------------------------------------------------------ the budget, the threshold, the rate (design 1.2)


def budget(counts):
    """BUDGET_RULE over M's clean calibration alarms of each seed: the median, rounded up."""
    if type(counts) not in (list, tuple) or not counts or not all(type(c) is int and c >= 0 for c in counts):
        raise ValueError("the budget takes the alarms of every seed of M, integers of at least 0")
    return int(math.ceil(float(np.median(counts))))


def model_budget(models, calibration, clean):
    """BUDGET_RULE: the clean calibration alarms of each seed's bundle (MetodaM) at its own threshold and alarm rule,
    and the budget."""
    if type(models) not in (list, tuple) or not models or not all(isinstance(m, MetodaM) for m in models):
        raise ValueError("the budget takes M of every seed (MetodaM)")
    _calibration(calibration)
    rules = {(m.k, m.n) for m in models}
    if len(rules) != 1:
        raise ValueError("the bundles of M differ in their alarm rule k of n")
    rows = []
    for m in models:
        rows.append({"seed": m.seed, "threshold": m.threshold,
                     "alarms": alarm_count(m.scores(calibration), calibration, m.threshold, k=m.k, n=m.n,
                                           clean=clean)})
    k, n = rules.pop()
    return {"seeds": rows, "budget": budget([row["alarms"] for row in rows]), "k": k, "n": n,
            "clean_windows": int(_mask(clean, calibration).sum()), "windows": len(calibration), "rule": BUDGET_RULE}


def matched_threshold(scores, calibration, budget_value, *, k, n, clean):
    """THRESHOLD_RULE: {threshold, alarms (at it, on the clean windows), budget, walked (thresholds tried, the first
    excess included), first_excess {threshold, alarms} or None, exhausted, rule}."""
    _check_rule(k, n)
    values = _scores(scores, _calibration(calibration))
    mask = _mask(clean, calibration)
    if type(budget_value) is not int or budget_value < 0:
        raise ValueError("the budget is an integer of at least 0")
    walk = np.unique(values)[::-1]
    block = max(1, min(256, BATCH_ELEMENTS // len(values)))
    last = None
    for start in range(0, len(walk), block):
        part = walk[start:start + block]
        counts = (_edges(values[None, :] > part[:, None], calibration, k, n) & mask[None, :]).sum(axis=1)
        over = np.flatnonzero(counts > budget_value)
        if len(over):
            i = int(over[0])
            # At the highest score no window exceeds, so the first excess has a threshold before it.
            alarms = int(counts[i - 1]) if i else last
            return {"threshold": float(walk[start + i - 1]), "alarms": alarms, "budget": budget_value,
                    "walked": start + i + 1, "first_excess": {"threshold": float(walk[start + i]),
                                                              "alarms": int(counts[i])},
                    "exhausted": False, "rule": THRESHOLD_RULE}
        last = int(counts[-1])
    return {"threshold": float(walk[-1]), "alarms": last, "budget": budget_value, "walked": len(walk),
            "first_excess": None, "exhausted": True, "rule": THRESHOLD_RULE}


def rate(scores, windows, threshold, *, k, n, clean):
    """RATE_RULE: {alarms, windows (clean), hours, per_hour (None when no window is clean), rule}."""
    mask = _mask(clean, _okna(windows, "windows"))
    alarms = alarm_count(scores, windows, threshold, k=k, n=n, clean=mask)
    hours = int(mask.sum()) * windows.interval_s / 3600
    return {"alarms": alarms, "windows": int(mask.sum()), "hours": hours,
            "per_hour": alarms / hours if hours > 0 else None, "rule": RATE_RULE}


def matched_rate(method, calibration, clean, budget_value, *, k, n, roles):
    """The matched alarm rate of one fitted method (design 1.2): its threshold at the budget on calibration
    (matched_threshold, THRESHOLD_RULE) with the alarms at it, and its alarms per hour (RATE_RULE) on calibration and
    on every role of `roles` ({name: (window set, its clean mask)}; {} for none). The method is any object of the
    interface of Metoda (name, kind, scores), a subclass or not (tcn/opisne.py's are not); label defaults to name."""
    if not (type(getattr(method, "name", None)) is str and getattr(method, "kind", None) in KINDS
            and callable(getattr(method, "scores", None))):
        raise ValueError("the matched rate takes a fitted method of the interface of tcn.metody.Metoda (name, kind, "
                         "scores)")
    _calibration(calibration)
    if type(roles) is not dict or "calibration" in roles or not all(
            type(v) is tuple and len(v) == 2 and isinstance(v[0], Okna) and v[0].role == name
            for name, v in roles.items()):
        raise ValueError("roles maps each role other than calibration to (its window set, its clean mask)")
    scores = method.scores(calibration)
    found = matched_threshold(scores, calibration, budget_value, k=k, n=n, clean=clean)
    rates = {"calibration": rate(scores, calibration, found["threshold"], k=k, n=n, clean=clean)}
    for name, (windows, mask) in roles.items():
        rates[name] = rate(method.scores(windows), windows, found["threshold"], k=k, n=n, clean=mask)
    return {"name": method.name, "label": getattr(method, "label", method.name), "kind": method.kind, "k": k,
            "n": n, **found, "rates": rates}


# ------------------------------------------------------------------ the interface (design 1.1)


class Metoda:
    """The interface of every method (design 1.1), the descriptive ones of tcn/opisne.py included.

    name: "Z0".."Z5", "M" or a descriptive name; kind: "detector" or "predictor" (a predictor also gives losses);
    variant: what distinguishes methods of one name (None, or e.g. Z4's "load" and "residual"); label: name, or
    name:variant.
    fit(train, dev, *, protocol, seed) -> dict: the window sets of the roles train and dev under M's normalizer (the
        same normalizer, refused otherwise); selection on dev only; returns what was chosen and why (JSON).
    scores(windows) -> np.ndarray (len(windows),): one finite score per window, higher is more anomalous; a window set
        of another normalizer or window is refused.
    losses(windows) -> np.ndarray | None: a predictor's loss of each window (LOSS_FORMULA by errors()); None for a
        detector.
    No method fits a normalizer or a threshold of its own (matched_threshold gives the threshold).

    A subclass sets name and kind (and variant where it has one), begins fit with record = self._bind(train, dev,
    seed), which checks both window sets and binds the method to their normalizer, returns dict(record, chosen=...,
    why=..., rule=...) (name, kind, seed, chosen and why are the keys tcn/opisne.py's records share too), and begins
    scores and losses with self._check(windows), which refuses an unfitted method and a window set of another
    normalizer or window. It reads its batches by windows.arrays() and their rows by windows.rows() (or, written
    against safeguard.training.Windows, by windows.batches(batch_size, order)), and a predictor scores and loses by
    errors() of its prediction of rows[:, -1] from rows[:, :-1]."""

    name = None
    kind = None
    variant = None

    def __init__(self):
        self._normalizer_sha256 = None
        self._windows = None

    @property
    def label(self):
        return self.name if self.variant is None else f"{self.name}:{self.variant}"

    def fit(self, train, dev, *, protocol, seed):
        raise NotImplementedError

    def scores(self, windows):
        raise NotImplementedError

    def losses(self, windows):
        if self.kind == "detector":
            return None
        raise NotImplementedError(f"{self.label} is a predictor and gives its losses")

    def _bind(self, train, dev, seed):
        """The record every fit begins with; binds the method to the normalizer of train, which dev must share."""
        _okna(train, "train")
        _okna(dev, "dev")
        if not train.same(dev):
            raise ValueError("train and dev hold windows of different normalizers or windows; every method sees M's")
        if type(seed) is not int or seed < 0:
            raise ValueError("the seed is an integer of at least 0")
        if self._normalizer_sha256 is not None and self._normalizer_sha256 != train.normalizer_sha256:
            raise ValueError(f"{self.label} is bound to another normalizer than that of train")
        self._normalizer_sha256 = train.normalizer_sha256
        self._windows = (train.window_rows, train.max_gap_s, train.interval_s)
        return {"name": self.name, "variant": self.variant, "label": self.label, "kind": self.kind, "seed": seed,
                "normalizer_sha256": train.normalizer_sha256, "windows": {"train": len(train), "dev": len(dev)}}

    def _check(self, windows):
        _okna(windows, "windows")
        if self._normalizer_sha256 is None:
            raise ValueError(f"{self.label} is not fitted")
        if (windows.normalizer_sha256 != self._normalizer_sha256
                or (windows.window_rows, windows.max_gap_s, windows.interval_s) != self._windows):
            raise ValueError(f"{self.label} was fitted on windows of another normalizer or window; every method sees "
                             "the windows of its bundle M")
        return windows


# ------------------------------------------------------------------ Z0


class Z0(Metoda):
    """Z0_RULE."""
    name, kind = "Z0", "detector"

    def fit(self, train, dev, *, protocol, seed):
        return dict(self._bind(train, dev, seed), chosen=None, why=NO_PARAMETER, rule=Z0_RULE)

    def scores(self, windows):
        return np.zeros(len(self._check(windows)))


def uniform_scores(windows, stream, repetitions):
    """The numbers of Z0_RANDOM_RULE for the windows of a set, (repetitions, len(windows)): row r is repetition r, drawn
    after the rows before it from numpy.random.default_rng(stream), the seed of the set's role."""
    _okna(windows, "windows")
    if type(stream) is not int or type(repetitions) is not int or stream < 0 or repetitions < 1:
        raise ValueError("the stream seed is an integer of at least 0 and the repetitions one of at least 1")
    return np.random.default_rng(stream).random((repetitions, len(windows)))


class Z0Random(Metoda):
    """Z0_RANDOM_RULE: one repetition."""
    name, kind, variant = "Z0", "detector", "random"

    def __init__(self, repetition, *, mode):
        super().__init__()
        if type(repetition) is not int or repetition < 0:
            raise ValueError("the repetition is an integer of at least 0")
        if mode not in MODES:
            raise ValueError(f"the plan mode is campaign or rehearsal, not {mode!r}: it names the stream")
        self.repetition, self.mode, self.streams = repetition, mode, None

    def fit(self, train, dev, *, protocol, seed):
        record = self._bind(train, dev, seed)
        self.streams = {role: stream_seed(protocol, "z0_alarms", role, mode=self.mode)
                        for role in protocol_value(protocol, "roles")}
        return dict(record, why=NO_PARAMETER + "; the repetition and the stream of each role draw the numbers",
                    chosen={"repetition": self.repetition, "stream": "z0_alarms", "mode": self.mode,
                                    "stream_seeds": dict(self.streams)}, rule=Z0_RANDOM_RULE, stream_rule=STREAM_RULE)

    def scores(self, windows):
        self._check(windows)
        if windows.role not in self.streams:
            raise ValueError(f"the window set is of role {windows.role}, which the protocol does not plan")
        return uniform_scores(windows, self.streams[windows.role], self.repetition + 1)[self.repetition]


def z0_random(calibration, budget_value, *, protocol, mode, k, n, clean, roles):
    """Z0_RANDOM_RULE over analysis.matched_rate.z0_repetitions repetitions: each repetition's threshold on
    `calibration` (its clean mask `clean`) at `budget_value`, then its alarms on calibration and on each role of
    `roles` ({name: (window set, clean mask)}); the alarms of every repetition and their means."""
    _calibration(calibration)
    if type(roles) is not dict or "calibration" in roles or not all(
            type(v) is tuple and len(v) == 2 and calibration.same(v[0]) and v[0].role == name
            for name, v in roles.items()):
        raise ValueError("roles maps each role other than calibration to (its window set, of calibration's "
                         "normalizer, its clean mask)")
    repetitions = z0_repetitions(protocol)
    streams = {name: stream_seed(protocol, "z0_alarms", name, mode=mode) for name in ("calibration", *roles)}
    sets = {"calibration": (calibration, clean), **roles}
    numbers = {name: uniform_scores(windows, streams[name], repetitions) for name, (windows, _) in sets.items()}
    found = {name: [] for name in sets}
    hours = dict.fromkeys(sets)
    for repetition in range(repetitions):
        chosen = matched_threshold(numbers["calibration"][repetition], calibration, budget_value, k=k, n=n,
                                   clean=clean)
        for name, (windows, mask) in sets.items():
            result = rate(numbers[name][repetition], windows, chosen["threshold"], k=k, n=n, clean=mask)
            found[name].append(result["alarms"])
            hours[name] = result["hours"]
    return {"rule": Z0_RANDOM_RULE, "stream": "z0_alarms", "stream_seeds": streams, "stream_rule": STREAM_RULE,
            "mode": mode, "repetitions": repetitions, "budget": budget_value, "k": k, "n": n,
            "roles": {name: {"alarms": counts, "mean_alarms": float(np.mean(counts)), "hours": hours[name],
                             "mean_per_hour": float(np.mean(counts)) / hours[name] if hours[name] else None}
                      for name, counts in found.items()}}


# ------------------------------------------------------------------ Z1


STATISTICS = ("value", "difference", "moving_average", "cusum", "mem_changed_max")
TWO_SIDED = ("value", "difference", "moving_average")


def _statistic(rows, statistic, parameter):
    """s of Z1_RULE for every column of `rows` (n, window_rows, C)."""
    if statistic in ("value", "mem_changed_max"):
        return rows[:, -1]
    if statistic == "difference":
        return rows[:, -1] - rows[:, -2]
    if statistic == "moving_average":
        return rows[:, -parameter:].mean(axis=1)
    up = down = np.zeros(rows[:, 0].shape)
    for i in range(rows.shape[1]):
        up = np.maximum(0., up + rows[:, i] - parameter)
        down = np.maximum(0., down - rows[:, i] - parameter)
    return np.maximum(up, down)


class Z1(Metoda):
    """Z1_RULE, selected by Z1_SELECTION.

    Z1(criterion): the method of skeleton section 2; fit builds every candidate of the grid
    (analysis.methods.Z1.grid: moving_average_rows, cusum_shift), fits each on train and keeps the best by
    criterion(candidate, dev) -> number, higher better (B7b: the share of the interventions inserted into dev that the
    candidate detects at its matched threshold). Z1(statistic=..., parameter=...): one candidate."""
    name, kind = "Z1", "detector"

    def __init__(self, criterion=None, *, statistic=None, parameter=None):
        super().__init__()
        if statistic is None:
            if parameter is not None or (criterion is not None and not callable(criterion)):
                raise ValueError("Z1 selects its statistic by a criterion, a callable; one candidate is "
                                 "Z1(statistic=..., parameter=...)")
        else:
            needs = {"moving_average": GRID_CHECKS["moving_average_rows"], "cusum": GRID_CHECKS["cusum_shift"]}
            if criterion is not None or statistic not in STATISTICS or (
                    not needs[statistic](parameter) if statistic in needs else parameter is not None):
                raise ValueError("a candidate of Z1 is one of " + ", ".join(STATISTICS) + " with the length of the "
                                 "moving average or the shift of the CUSUM and no criterion")
        self.criterion, self.statistic, self.parameter = criterion, statistic, parameter
        self._chosen = self._center = self._spread = self._columns = None

    @property
    def variant(self):
        chosen = self._chosen if self.statistic is None else self
        if chosen is None:
            return None
        return chosen.statistic if chosen.parameter is None else f"{chosen.statistic}({chosen.parameter})"

    def _values(self, windows):
        out = []
        for _, g, _ in windows.arrays(bins=False):
            out.append(_statistic(windows.rows(g)[:, :, self._columns], self.statistic, self.parameter))
        return np.concatenate(out)

    def fit(self, train, dev, *, protocol, seed):
        if self.statistic is None:
            return self._select(train, dev, protocol, seed)
        record = self._bind(train, dev, seed)
        if self.statistic == "moving_average" and self.parameter > train.window_rows:
            raise ValueError(f"a moving average of {self.parameter} rows exceeds the window of {train.window_rows}")
        if self.statistic == "mem_changed_max":
            if "mem_changed_max" not in train.input_names:
                raise ValueError("Z1 on mem_changed_max needs it as an input of the TCN; under rule "
                                 f"{train.normalizer.rule.name} it is of class "
                                 f"{train.normalizer.rule.classes['mem_changed_max']}")
            self._columns = [train.input_names.index("mem_changed_max")]
        else:
            self._columns = list(range(len(train.input_names)))
        values = self._values(train)
        self._center = values.mean(axis=0)
        self._spread = np.maximum(values.std(axis=0), train.units()[self._columns])
        return dict(record, chosen={"statistic": self.statistic, "parameter": self.parameter},
                    why="one candidate of Z1, its statistic given (Z1_SELECTION chooses among them)",
                    columns=[train.input_names[j] for j in self._columns], center=self._center.tolist(),
                    spread=self._spread.tolist(), rule=Z1_RULE)

    def _select(self, train, dev, protocol, seed):
        record = self._bind(train, dev, seed)
        if self.criterion is None:
            raise ValueError("Z1 is selected by the share of the interventions inserted into dev that it detects "
                             "(skeleton section 2, package B7b): its fit needs that criterion")
        values = grid(protocol, "Z1")
        candidates = ([("value", None), ("difference", None)]
                      + [("moving_average", w) for w in values["moving_average_rows"]]
                      + [("cusum", d) for d in values["cusum_shift"]])
        omitted = []
        if "mem_changed_max" in train.input_names:
            candidates.append(("mem_changed_max", None))
        else:
            omitted.append({"statistic": "mem_changed_max",
                            "why": f"not an input of the TCN: of class "
                                   f"{train.normalizer.rule.classes['mem_changed_max']} under rule "
                                   f"{train.normalizer.rule.name}"})
        rows, best = [], None
        for statistic, parameter in candidates:
            candidate = Z1(statistic=statistic, parameter=parameter)
            candidate.fit(train, dev, protocol=protocol, seed=seed)
            value = self.criterion(candidate, dev)
            if not _number(value):
                raise ValueError(f"the criterion of Z1 gave {value!r} for {candidate.variant}; it gives a number")
            rows.append({"statistic": statistic, "parameter": parameter, "criterion": float(value)})
            if best is None or value > best[0]:
                best = (value, candidate)
        self._chosen = best[1]
        return dict(record, chosen={"statistic": self._chosen.statistic, "parameter": self._chosen.parameter},
                    why=Z1_SELECTION,
                    candidates=rows, omitted=omitted, grid=values,
                    criterion=getattr(self.criterion, "__name__", type(self.criterion).__name__),
                    selection=Z1_SELECTION, rule=Z1_RULE)

    def scores(self, windows):
        if self.statistic is None:
            if self._chosen is None:
                raise ValueError("Z1 is not fitted")
            return self._chosen.scores(windows)
        self._check(windows)
        standard = (self._values(windows) - self._center) / self._spread
        return (np.abs(standard) if self.statistic in TWO_SIDED else standard).max(axis=1)


# ------------------------------------------------------------------ Z2


class Z2(Metoda):
    """Z2_RULE."""
    name, kind = "Z2", "detector"

    def fit(self, train, dev, *, protocol, seed):
        from features.qualification import _mode
        record = self._bind(train, dev, seed)
        floor = train.normalizer.rule.floor
        if floor is None:
            raise ValueError(f"normalization rule {train.normalizer.rule.name} has no floor: the counts of Z2 are the "
                             "columns of analysis.scale.floor 1")
        self._columns = [j for j, name in enumerate(train.input_names) if floor[name] == 1]
        if not self._columns:
            raise ValueError("Z2 has no count (a column of analysis.scale.floor 1) among the TCN inputs")
        last = np.concatenate([train.rows(g)[:, -1, self._columns] for _, g, _ in train.arrays(bins=False)])
        self._modes = np.array([_mode(last[:, c])[0] for c in range(len(self._columns))])
        normalizer = train.normalizer
        raw = self._modes * normalizer.global_scale[self._columns] + normalizer.global_mean[self._columns]
        return dict(record, chosen=None, why=NO_PARAMETER, counts=[train.input_names[j] for j in self._columns],
                    modes=self._modes.tolist(), modes_in_units=raw.tolist(), rule=Z2_RULE)

    def scores(self, windows):
        self._check(windows)
        out = [np.abs(windows.rows(g)[:, -1, self._columns] - self._modes).max(axis=1)
               for _, g, _ in windows.arrays(bins=False)]
        return np.concatenate(out)


# ------------------------------------------------------------------ the predictors Z3 and Z5


def _predictor_errors(windows, predict):
    """(loss, score) of every window of the set by errors() of predict(global rows before the last, bin rows before
    the last) -> (global (n, G), bins (n, B, 3))."""
    losses, scores = [], []
    for _, g, local in windows.arrays():
        g, local = windows.rows(g), windows.rows(local)
        prediction = predict(g[:, :-1], local[:, :-1])
        loss, score = errors(*prediction, g[:, -1], local[:, -1])
        losses.append(loss)
        scores.append(score)
    return np.concatenate(losses), np.concatenate(scores)


def _z3_predict(candidate):
    kind, alpha = candidate

    def predict(g, local):
        local = local[..., :3]
        if kind == "last":
            return g[:, -1], local[:, -1]
        if kind == "mean":
            return g.mean(axis=1), local.mean(axis=1)
        sg, sl = g[:, 0], local[:, 0]
        for i in range(1, g.shape[1]):
            sg, sl = alpha * g[:, i] + (1 - alpha) * sg, alpha * local[:, i] + (1 - alpha) * sl
        return sg, sl
    return predict


class Z3(Metoda):
    """Z3_RULE, selected by Z3_SELECTION (analysis.methods.Z3.grid: ewma_alpha)."""
    name, kind = "Z3", "predictor"

    def __init__(self):
        super().__init__()
        self._chosen = None

    @property
    def variant(self):
        if self._chosen is None:
            return None
        return self._chosen[0] if self._chosen[1] is None else f"ewma({self._chosen[1]})"

    def fit(self, train, dev, *, protocol, seed):
        record = self._bind(train, dev, seed)
        values = grid(protocol, "Z3")
        candidates = [("last", None), ("mean", None)] + [("ewma", a) for a in values["ewma_alpha"]]
        rows, best = [], None
        for candidate in candidates:
            loss = float(_predictor_errors(dev, _z3_predict(candidate))[0].mean())
            rows.append({"predictor": candidate[0], "ewma_alpha": candidate[1], "dev_loss": loss})
            if best is None or loss < best[0]:
                best = (loss, candidate)
        self._chosen = best[1]
        return dict(record, chosen={"predictor": self._chosen[0], "ewma_alpha": self._chosen[1]}, why=Z3_SELECTION,
                    candidates=rows,
                    grid=values, selection=Z3_SELECTION, rule=Z3_RULE, loss_formula=LOSS_FORMULA,
                    score_formula=SCORE_FORMULA)

    def _errors(self, windows):
        self._check(windows)
        return _predictor_errors(windows, _z3_predict(self._chosen))

    def scores(self, windows):
        return self._errors(windows)[1]

    def losses(self, windows):
        return self._errors(windows)[0]


def _design(context):
    """[1, the flattened rows] of each sample: context (m, rows, width) -> (m, 1 + rows * width)."""
    flat = context.reshape(len(context), -1)
    return np.concatenate((np.ones((len(flat), 1)), flat), axis=1)


def _bin_samples(local):
    """(design, targets (m, 3), weights (m, 3)) of every (window, bin): the four channels of the bin in the rows
    before the last, its three values in the last row and their weights in LOSS_FORMULA."""
    context = local[:, :-1].transpose(0, 2, 1, 3)  # (n, B, rows, 4)
    n, bins = context.shape[:2]
    design = _design(context.reshape(n * bins, *context.shape[2:]))
    target = local[:, -1].reshape(n * bins, 4)
    changed = target[:, 3]
    weights = np.stack((1 / (2 + changed), 1 / (2 + changed), changed / (2 + changed)), axis=1)
    return design, target[:, :3], weights


class Z5(Metoda):
    """Z5_RULE, selected by Z5_SELECTION (analysis.methods.Z5.grid: ridge_alpha)."""
    name, kind = "Z5", "predictor"

    def __init__(self):
        super().__init__()
        self._chosen = None

    @property
    def variant(self):
        return None if self._chosen is None else f"ridge({self._chosen['alpha']})"

    def _sums(self, train):
        """The weighted second moments of the design and the targets over train (one pass)."""
        sums = None
        for _, g, local in train.arrays():
            g, local = train.rows(g), train.rows(local)
            design = _design(g[:, :-1])
            bins, targets, weights = _bin_samples(local)
            part = {"global": (design.T @ design, design.T @ g[:, -1], float(len(design)))}
            for c in range(3):
                weighted = bins * weights[:, c:c + 1]
                part[c] = (weighted.T @ bins, weighted.T @ targets[:, c], float(weights[:, c].sum()))
            sums = part if sums is None else {key: tuple(a + b for a, b in zip(sums[key], part[key])) for key in sums}
        return sums

    @staticmethod
    def _solve(sums, alpha):
        """The coefficients at strength `alpha`: (global (1 + rows G, G), bins (1 + rows 4, 3))."""
        def ridge(moment, right, total):
            penalty = alpha * np.eye(len(moment))
            penalty[0, 0] = 0.  # The intercept is not penalized.
            return np.linalg.solve(moment / total + penalty, right / total)
        coefficients = []
        for c in range(3):
            moment, right, total = sums[c]
            # No train observation of this bin value (the entropy where no bin changed): the normalizer's mean, 0.
            coefficients.append(np.zeros(len(moment)) if total <= 0 else ridge(moment, right, total))
        return ridge(*sums["global"]), np.stack(coefficients, axis=1)

    @staticmethod
    def _predict(coefficients):
        global_coefficients, bin_coefficients = coefficients

        def predict(g, local):
            n, rows, bins = local.shape[:3]
            design = _design(local.transpose(0, 2, 1, 3).reshape(n * bins, rows, 4))
            return _design(g) @ global_coefficients, (design @ bin_coefficients).reshape(n, bins, 3)
        return predict

    def fit(self, train, dev, *, protocol, seed):
        record = self._bind(train, dev, seed)
        values = grid(protocol, "Z5")
        sums = self._sums(train)
        rows, best = [], None
        for alpha in values["ridge_alpha"]:
            coefficients = self._solve(sums, alpha)
            loss = float(_predictor_errors(dev, self._predict(coefficients))[0].mean())
            rows.append({"ridge_alpha": alpha, "dev_loss": loss})
            if best is None or loss < best[0]:
                best = (loss, {"alpha": alpha, "coefficients": coefficients})
        self._chosen = best[1]
        return dict(record, chosen={"ridge_alpha": self._chosen["alpha"]}, why=Z5_SELECTION, candidates=rows,
                    grid=values,
                    unobserved=[name for c, name in enumerate(("changed_ratio", "zero_ratio", "entropy_mean"))
                                if sums[c][2] <= 0],
                    selection=Z5_SELECTION, rule=Z5_RULE, loss_formula=LOSS_FORMULA, score_formula=SCORE_FORMULA)

    @property
    def coefficients(self):
        """(global, bins) of the chosen strength: row 0 the intercept, then the rows before the last in order."""
        return None if self._chosen is None else self._chosen["coefficients"]

    def _errors(self, windows):
        self._check(windows)
        return _predictor_errors(windows, self._predict(self._chosen["coefficients"]))

    def scores(self, windows):
        return self._errors(windows)[1]

    def losses(self, windows):
        return self._errors(windows)[0]


# ------------------------------------------------------------------ Z4


Z4_VARIANTS = ("load", "residual")


class Z4(Metoda):
    """Z4_RULE: Z4(variant), variant load or residual, with no default (both are reported)."""
    name, kind = "Z4", "detector"

    def __init__(self, variant):
        super().__init__()
        if variant not in Z4_VARIANTS:
            raise ValueError("Z4 has the variants " + " and ".join(Z4_VARIANTS) + "; name one")
        self.variant = variant

    def _last(self, windows):
        """(the last rows of the global inputs, the offered load of each) of every window."""
        rows, loads = [], []
        for selection, g, _ in windows.arrays(bins=False):
            rows.append(windows.rows(g)[:, -1])
            loads.append(windows.last_load(selection))
        return np.concatenate(rows), np.concatenate(loads)

    def fit(self, train, dev, *, protocol, seed):
        record = self._bind(train, dev, seed)
        for name, windows in (("train", train), ("dev", dev)):
            if not windows.has_load:
                raise ValueError(f"Z4 needs the offered load of every row; the window set of {name} has none")
        if self.variant == "load":
            return dict(record, chosen=None, why=NO_PARAMETER, rule=Z4_RULE)
        values, load = self._last(train)
        if np.ptp(load) == 0:
            raise ValueError("the offered load does not vary over the train windows: Z4 residual has no regression")
        design = np.stack((np.ones(len(load)), load), axis=1)
        self._coefficients = np.linalg.lstsq(design, values, rcond=None)[0]
        residual = values - design @ self._coefficients
        self._spread = np.maximum(residual.std(axis=0), train.units())
        return dict(record, chosen=None, why=NO_PARAMETER, intercept=self._coefficients[0].tolist(),
                    slope=self._coefficients[1].tolist(), spread=self._spread.tolist(), rule=Z4_RULE)

    def scores(self, windows):
        self._check(windows)
        values, load = self._last(windows)
        if self.variant == "load":
            return load
        residual = values - np.stack((np.ones(len(load)), load), axis=1) @ self._coefficients
        return (np.abs(residual) / self._spread).max(axis=1)


# ------------------------------------------------------------------ M


class MetodaM(Metoda):
    """M_RULE: MetodaM(bundle), a loaded safeguard.bundle.Bundle of one seed; bound to its normalizer and window when
    built, so its scores need no fit (the budget reads them). threshold, k, n: its calibration."""
    name, kind = "M", "predictor"

    def __init__(self, bundle):
        super().__init__()
        from safeguard.bundle import Bundle
        if not isinstance(bundle, Bundle):
            raise ValueError("MetodaM takes a loaded bundle (safeguard.bundle.Bundle)")
        training = bundle.manifest.get("training")
        if type(training) is not dict or type(training.get("seed")) is not int:
            raise ValueError("the bundle's manifest names no training seed (training.seed)")
        self.bundle = bundle
        self.seed = training["seed"]
        self._normalizer_sha256 = fingerprint(bundle.normalizer)
        self._contract = (bundle.contract["window_rows"], float(bundle.contract["max_gap_s"]))

    @property
    def variant(self):
        return f"seed {self.seed}"

    @property
    def threshold(self):
        return self.bundle.threshold

    @property
    def k(self):
        return self.bundle.k

    @property
    def n(self):
        return self.bundle.n

    def _check(self, windows):
        _okna(windows, "windows")
        if (windows.normalizer_sha256 != self._normalizer_sha256
                or (windows.window_rows, windows.max_gap_s) != self._contract):
            raise ValueError("the window set is not of the bundle M's normalizer and window")
        return windows

    def fit(self, train, dev, *, protocol, seed):
        self._check(train)
        record = self._bind(train, dev, seed)
        if seed != self.seed:
            raise ValueError(f"the bundle is of seed {self.seed}, not {seed}")
        return dict(record, why=M_WHY, chosen={"seed": self.seed,
                                    "selected_predictor_epoch": self.bundle.manifest["training"].get(
                                        "selected_predictor_epoch")},
                    threshold=self.threshold, k=self.k, n=self.n, rule=M_RULE, loss_formula=LOSS_FORMULA,
                    score_formula=SCORE_FORMULA)

    def _errors(self, windows):
        self._check(windows)
        predictor = self.bundle.predictor
        predictor.eval()
        losses, scores = [], []
        with torch.inference_mode():
            for _, g, local in windows.arrays():
                g = torch.as_tensor(windows.rows(g), dtype=torch.float32)
                local = torch.as_tensor(windows.rows(local), dtype=torch.float32)
                loss, score = errors(*predictor(g[:, :-1], local[:, :-1]), g[:, -1], local[:, -1])
                losses.append(loss)
                scores.append(score)
        return np.concatenate(losses), np.concatenate(scores)

    def scores(self, windows):
        return self._errors(windows)[1]

    def losses(self, windows):
        return self._errors(windows)[0]
