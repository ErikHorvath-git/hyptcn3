"""The feature interventions of classes C and D (protocol v5, package B7b, agent I).

Binding texts: the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 5 (with sections 8 and 9), the design
dokazy/B7/navrh/NAVRH_B7b.md sections 1.1, 1.2 and 2, and proposal 7.4 (docs/NAVRH_PROTOKOL_V5.sk.md). Package B7b
reads no test role: everything here runs on the window sets it is given; the final command of package B7c gives it
those of test_benign and test_controls. tcn/k2.py detects the interventions and decides K2 on them.

    protocol_keys(protocol)     the keys of design 1.4, which agent F writes; one accessor, KEYS names every path
    Carriers(windows, placeable, sessions)
                                the sessions of one role that interventions are placed in or take a segment from: a
                                window set of M's normalizer (tcn.metody.Okna), its Traffic (tcn.metody.traffic, whose
                                placeable mask PLACEABLE_RULE is design 1.1's) or that mask, and the boot, scenario and
                                position of every session
    train_ranges(train, protocol)
                                the train quantiles of the validity predicate (VALIDITY_RULE)
    plan(carriers, *, protocol, mode, ranges, donors)
                                the interventions of one role (UNIT_RULE, DEAL_RULE, PLACEMENT_RULE, C_RULE, D_RULE,
                                DONOR_RULE, VALIDITY_RULE), each on its own copy of a session: Plan.copies holds the
                                copies as one window set that every method scores, Plan.horizons the windows of each
                                copy at which an alarm detects it (tcn/k2.py DETECTION_RULE)
    violations(ranges, original, copy, block, length)
                                the validity predicate of one copy

WHAT AN INTERVENTION CHANGES (design 1.2: only the inputs of the neural channel). An intervention acts on the inputs as
the window set holds them: the TCN inputs of M's normalizer (a column of class differenced by its normalized first
difference) and the four channels of every scored bin. The columns of the rule channel, the dropped columns, the
unscored bins, the offered load and the integrity checks are not in the window set and never change. Every input of
every row outside the block stays bit for bit; so a differenced column keeps its first differences after the block,
and after a block of class C the level they imply is the original one (the block's differences are the same multiset).

The merge of B7b: the classes, the orders of C, the carrier roles, the insertion into dev and the shortest blocks are
scripts/protocol_v5.py's constants (INTERVENTION_CLASSES, ORDERS, CARRIERS, DEV_INSERTION, MIN_BLOCK_ROWS), one for the
protocol's check and this module; the stream injections is protocol_v5.analysis_seed's, which refuses a unit outside
protocol_v5.INJECTION_UNITS; the session arrays of a window set come through tcn.metody.Okna.session_arrays.

Package B11 (agent E; the lead's answer to question Q14, 2026-11-24, valid from G1 on and never tuned): the validity
predicate is the lead's new deviation (VALIDITY_RULE): every value of the block and of its edges is judged, and a value
fails only outside the train quantiles and outside the range the same quantity of the same input had at the same rows
before the intervention; a violation records both ranges; the moving average is the mean of the sorted window; and the
counts of a plan give every status by class and length (by_length), whose share of the volume class G3a reports
(tcn/k2.py VOLUME_FINDING_RULE).
"""
import math

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from features.windows import BIN_PRIZNAKY
from scripts import protocol_v5
from tcn.metody import ARCHIVE_KEY, Okna, Traffic

SCHEMA = "hyptcn3/interventions/1"
CLASSES = protocol_v5.INTERVENTION_CLASSES  # ("C", "D")
ORDERS = protocol_v5.ORDERS  # The order variants of class C (proposal 7.4): reversed, random.
PURPOSE = "injections"  # The stream of the interventions (design 1.4: streams.purposes).
CARRIER_ROLES = protocol_v5.CARRIERS  # The carriers of K2 (skeleton section 5): test_benign, test_controls.
DEV_ROLE = protocol_v5.DEV_INSERTION  # The insertion that selects Z1 (skeleton sections 2 and 9); never in K2.
# The roles whose sessions may donate the segment of an intervention of class D (DONOR_RULE; judgment).
DONOR_ROLES = {"test_benign": CARRIER_ROLES, "test_controls": CARRIER_ROLES, DEV_ROLE: ("train",)}
STATUSES = ("evaluable", "volume", "not_placed")
QUANTITIES = ("value", "difference", "moving_average")
META = ("boot", "scenario", "position")
MIN_LENGTH = protocol_v5.MIN_BLOCK_ROWS  # Judgment: {"C": 2, "D": 1}, a block of one row has no order to change.

# The paths of the keys of design 1.4 this module reads (agent F's layout in config/collection-v5.json, merged in B7b).
KEYS = {"boots": "analysis.interventions.boots",
        "lengths": "analysis.interventions.{cls}.lengths",
        "per_boot": "analysis.interventions.{cls}.per_boot",
        "orders": "analysis.interventions.C.orders",
        "groups": "analysis.interventions.D.groups",
        "quantiles": "analysis.interventions.validity.quantiles",
        "moving_average_rows": "analysis.interventions.validity.moving_average_rows",
        "min_evaluable": "analysis.interventions.min_evaluable",
        "volume": "analysis.interventions.volume_class",
        "horizon_s": "analysis.horizon_s",
        "first_s": "analysis.evaluable.first_s",
        "window_rows": "window_rows",
        "interval_s": "interval_s"}
# The paths that design 1.4 adds (the others exist in the base of package B7b).
NEW_KEYS = {KEYS[name] for name in ("orders", "groups", "quantiles", "moving_average_rows", "min_evaluable", "volume")}
# The four channels of a bin (features/windows.py BIN_PRIZNAKY): a group of D that holds them swaps every scored bin.
BIN_CHANNELS = tuple(BIN_PRIZNAKY)

# ------------------------------------------------------------------ the rules (written into every plan's record)

UNIT_RULE = (
    "the stream injections (design 1.4, streams.rule) is drawn per unit: numpy.random.default_rng of "
    "scripts/protocol_v5.py analysis_seed(protocol, injections, unit, mode) (the plan's name in this mode, the unit as "
    "group, session -1, attempt 0; a unit outside protocol_v5.INJECTION_UNITS is refused); a class of a carrier role "
    "has the unit <role>/<class>, the insertion into dev the one unit dev for both classes, C drawn first and then D "
    "from the same generator; within a unit and a class the draws come in this order: the deal of the lengths "
    "(DEAL_RULE: the lengths that get one more, generator.choice without replacement, when the count is no multiple of "
    "their number; then the order of the deck, generator.permutation), the deal of the orders of C or of the groups of "
    "D (the same two draws), then for every intervention in the order of the deal (the boots in the order of their "
    "names, per_boot each) its start (generator.integers below the number of rows that meet PLACEMENT_RULE; no draw "
    "when there is none), for D its donor (generator.integers below the number of donors of that start), for C of the "
    "order random the permutation of its block (generator.permutation, drawn again while it is the identity)")
DEAL_RULE = (
    "in each class the lengths of analysis.interventions.<class>.lengths are dealt over the per_boot times boots "
    "interventions of the role: each length floor(count / lengths) times or once more, the lengths that get one more "
    "drawn without replacement, the deck in a random order, so that the counts differ by at most 1 within the role "
    "(skeleton section 5); the order variants of C and the groups of D are dealt alike after the lengths (judgment: "
    "balanced as the lengths); the boots then take per_boot interventions each in the order of their names")
PLACEMENT_RULE = (
    "a block of L rows begins at a row of a session of its boot at which every window of one run (consecutive seq, no "
    "reset of the alarm rule) whose last row lies from window_rows rows before the block's first row (the history of "
    "the alarm state, judgment: every alarm rule k of n with n up to window_rows) to the later of the last window that "
    "reads a row of the block and the first window whose last row lies at or after t + analysis.horizon_s, t the time "
    "of the block's first row (so the session holds a row at or after t + horizon_s in the same run, and every window "
    "of the horizon of tcn/k2.py DETECTION_RULE exists: verification of B7b, F6) exists and is placeable (design 1.1: "
    "clean, outside the controls and the full-snapshot band); the start is drawn uniformly over those "
    "rows of the boot's sessions in their order, for class D over those with a donor (DONOR_RULE) and then the donor "
    "uniformly among them; an intervention without such a row is not placed and stays in the denominator of its "
    "class (proposal 6.4); one intervention per copy of a session, the session itself never changes")
C_RULE = (
    "class C, only temporal (proposal 7.4): the rows of the block, every TCN input and every channel of every scored "
    "bin together, in reversed order or in a random order (a uniform permutation of the stream, drawn again while it "
    "is the identity: judgment, the identity changes no order); every value of every input in the block is kept, only "
    "its row changes")
D_RULE = (
    "class D, only between groups of features (proposal 7.4): the inputs of one group of "
    "analysis.interventions.D.groups in the rows of the block are replaced by those of the same rows (the same seq) of"
    " the donor (DONOR_RULE): its columns that are TCN inputs under M's normalization rule and, when the group holds "
    "the four channels of a bin, every scored bin with its four channels; a column of the rule channel or dropped is "
    "no input and stays, a group with no input is left out and recorded; every other input is kept")
DONOR_RULE = (
    "the donor of an intervention of class D is another session of the same scenario and position (proposal 7.4) among "
    "the sessions of the donor roles of its role (judgment): for test_benign and test_controls both test roles, held "
    "out alike and interleaved in time (proposal 7.3), so that a scenario and position has another session in the "
    "rehearsal's two groups per role as well; for dev the role train, since dev holds one session of each scenario "
    "and position (one block of four groups, proposal 7.3); the rows of its segment are each the last row of a "
    "placeable window of one run of the donor")
VALIDITY_RULE = (
    "the validity predicate, a new deviation (the lead's answer to question Q14, 2026-11-24: valid from G1 on and "
    "never tuned; proposal 7.4; from the features only): an intervention is invalid when after it some value of the "
    "block or of its edges, of a TCN input, of its first difference (the row minus the row before it) or of its moving "
    "average (the mean of the last analysis.interventions.validity.moving_average_rows rows), lies outside [the "
    "quantile lo, the quantile hi] (analysis.interventions.validity.quantiles) of the same quantity at the last rows "
    "of the windows of role train (numpy, linear) and also outside the range that the same quantity of the same input "
    "had at the same rows before the intervention (judgment: that range is its minimum to its maximum over those rows "
    "of the session); the rows are those of the block and after it up to the last row whose moving average reads a row "
    "of the block; every value at those rows is judged, not only the changed ones, and a value the intervention leaves "
    "in place lies in its own range, so it never fails; the moving average is the mean of the sorted rows of its "
    "window, in train and in the copies alike (judgment: a permutation of the rows of a window keeps its mean bit for "
    "bit, so class C makes no new deviation from rounding); every column is every TCN input, the bins are no columns "
    "(judgment); an intervention that fails goes to the volume class (analysis.interventions.volume_class), reported "
    "apart and never a success of its class, and G3a reports the share of the volume class by class and length "
    "(tcn/k2.py VOLUME_FINDING_RULE); a placed intervention has every window of its horizon (PLACEMENT_RULE), so it is "
    "evaluable (proposal 6.4: analysis.evaluable) exactly when it is valid")


# ------------------------------------------------------------------ the protocol keys (design 1.4)


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _value(protocol, path):
    value = protocol
    for part in path.split("."):
        if type(value) is not dict or part not in value:
            raise ValueError(f"protocol key {path} is missing" + (" (design B7b 1.4)" if path in NEW_KEYS else ""))
        value = value[part]
    return value


def _distinct(items, ok):
    return type(items) is list and bool(items) and all(map(ok, items)) and len(set(map(repr, items))) == len(items)


def _groups(groups, path):
    """{name: [columns]}: each group a non-empty list of distinct columns of features.archive.BEHAVIOR_NAMES and
    channels of a bin, the four channels of a bin together in one group, no column in two groups."""
    from features.archive import BEHAVIOR_NAMES
    if not (type(groups) is dict and groups and all(type(name) is str and name for name in groups)):
        raise ValueError(f"{path} must be a non-empty object of named groups {{name: [columns]}}")
    seen = set()
    for name, columns in groups.items():
        if not _distinct(columns, lambda c: c in BEHAVIOR_NAMES or c in BIN_CHANNELS):
            raise ValueError(f"{path}.{name} must be a non-empty list of distinct columns of "
                             "features.archive.BEHAVIOR_NAMES and channels of a bin")
        if set(columns) & set(BIN_CHANNELS) not in (set(), set(BIN_CHANNELS)):
            raise ValueError(f"{path}.{name}: the four channels of a bin " + ", ".join(BIN_CHANNELS)
                             + " lie in one group (a bin stays whole)")
        if seen & set(columns):
            raise ValueError(f"{path}.{name}: the groups share no column (D swaps one group against the others)")
        seen |= set(columns)
    return {name: list(columns) for name, columns in groups.items()}


def protocol_keys(protocol):
    """The keys of design 1.4 that the interventions read, checked; KEYS gives the path of each. A missing key and a
    malformed one are refused by name."""
    keys = {}
    boots = _value(protocol, KEYS["boots"])
    if type(boots) is not int or boots < 1:
        raise ValueError(f"{KEYS['boots']} must be an integer of at least 1")
    keys["boots"] = boots
    rows = _value(protocol, KEYS["window_rows"])
    if type(rows) is not int or rows < 2:
        raise ValueError("window_rows must be an integer of at least 2")
    keys["window_rows"] = rows
    interval = _value(protocol, KEYS["interval_s"])
    if not _number(interval) or interval <= 0:
        raise ValueError("interval_s must be a positive number")
    keys["interval_s"] = float(interval)
    classes = {}
    for cls in CLASSES:
        path = KEYS["lengths"].format(cls=cls)
        lengths = _value(protocol, path)
        low = MIN_LENGTH[cls]
        if not _distinct(lengths, lambda n: type(n) is int and n >= low):
            raise ValueError(f"{path} must be a non-empty list of distinct integers of at least {low}")
        path = KEYS["per_boot"].format(cls=cls)
        per_boot = _value(protocol, path)
        if type(per_boot) is not int or per_boot < 1:
            raise ValueError(f"{path} must be an integer of at least 1")
        classes[cls] = {"lengths": list(lengths), "per_boot": per_boot}
    orders = _value(protocol, KEYS["orders"])
    if not _distinct(orders, lambda o: o in ORDERS):
        raise ValueError(f"{KEYS['orders']} must be a non-empty list of distinct order variants of "
                         + " and ".join(ORDERS))
    classes["C"]["orders"] = list(orders)
    classes["D"]["groups"] = _groups(_value(protocol, KEYS["groups"]), KEYS["groups"])
    keys["classes"] = classes
    levels = _value(protocol, KEYS["quantiles"])
    if not (type(levels) is list and len(levels) == 2 and all(map(_number, levels))
            and 0 <= levels[0] < levels[1] <= 1):
        raise ValueError(f"{KEYS['quantiles']} must be [lo, hi] with 0 <= lo < hi <= 1")
    keys["quantiles"] = [float(levels[0]), float(levels[1])]
    average = _value(protocol, KEYS["moving_average_rows"])
    if type(average) is not int or not 1 <= average <= rows:
        raise ValueError(f"{KEYS['moving_average_rows']} must be an integer of at least 1 and at most window_rows")
    keys["moving_average_rows"] = average
    minimum = _value(protocol, KEYS["min_evaluable"])
    if type(minimum) is not int or minimum < 1:
        raise ValueError(f"{KEYS['min_evaluable']} must be an integer of at least 1")
    keys["min_evaluable"] = minimum
    volume = _value(protocol, KEYS["volume"])
    if type(volume) is not str or not volume.strip():
        raise ValueError(f"{KEYS['volume']} must be the rule of the volume class, a non-empty text")
    keys["volume"] = volume
    horizon = _value(protocol, KEYS["horizon_s"])
    if not _number(horizon) or horizon <= 0:
        raise ValueError(f"{KEYS['horizon_s']} must be a positive number")
    keys["horizon_s"] = float(horizon)
    first = _value(protocol, KEYS["first_s"])
    if not _number(first) or not 0 < first <= horizon:
        raise ValueError(f"{KEYS['first_s']} must be a positive number of at most {KEYS['horizon_s']}: a placed "
                         "intervention has every window of its horizon, so its first first_s seconds are scored")
    keys["first_s"] = float(first)
    return keys


def units(role):
    """{class: the unit of the stream injections} of the interventions of `role` (UNIT_RULE)."""
    if role in CARRIER_ROLES:
        return {cls: f"{role}/{cls}" for cls in CLASSES}
    if role == DEV_ROLE:
        return dict.fromkeys(CLASSES, DEV_ROLE)
    raise ValueError(f"interventions go into {', '.join(CARRIER_ROLES)} (K2) and {DEV_ROLE} (the selection of Z1), "
                     f"not into {role!r}")


# ------------------------------------------------------------------ the carriers and the train ranges


def _okna(windows, what):
    if not isinstance(windows, Okna):
        raise ValueError(f"{what} must be a window set (tcn.metody.Okna)")
    return windows


class Carriers:
    """The sessions of one window set (tcn.metody.Okna) that interventions are placed in or take segments from.

    placeable: the Traffic of the window set (tcn.metody.traffic: its placeable mask, PLACEABLE_RULE, design 1.1: clean,
    outside the controls and the full-snapshot band) or that boolean mask of its windows. sessions: {session id: {boot,
    scenario, position}} for exactly the sessions of the set; the boot is the session's boot group (the corpus index's
    group: one boot of a VM), position its place in it. The window set's arrays (tcn.metody.Okna.session_arrays,
    read-only views) are read here and never written (an intervention changes a copy)."""

    def __init__(self, windows, placeable, sessions):
        self.windows = _okna(windows, "the window set of carriers")
        self.role = windows.role
        if isinstance(placeable, Traffic):
            if placeable.windows is not windows:
                raise ValueError("the Traffic of the carriers is of another window set")
            placeable = placeable.placeable
        mask = np.asarray(placeable)
        if mask.shape != (len(windows),) or mask.dtype != bool:
            raise ValueError(f"placeable is a boolean mask of the {len(windows)} windows (design 1.1)")
        self.placeable = mask.copy()
        if type(sessions) is not dict or set(sessions) != set(windows.session_ids):
            raise ValueError("sessions maps the id of every session of the window set, and no other, to its boot, "
                             "scenario and position")
        self.meta = {}
        for ident in windows.session_ids:
            item = sessions[ident]
            if (type(item) is not dict or set(item) != set(META) or type(item["boot"]) is not str or not item["boot"]
                    or type(item["scenario"]) is not str or not item["scenario"]
                    or type(item["position"]) is not int or item["position"] < 0):
                raise ValueError(f"session {ident}: {{boot, scenario, position}}, the boot and the scenario non-empty "
                                 "names and the position an integer of at least 0")
            self.meta[ident] = dict(item)
        self.boots = sorted({item["boot"] for item in self.meta.values()})
        self.arrays = windows.sessions()  # The session arrays (tcn.metody.Okna.session_arrays), read-only views.
        run = np.cumsum(windows.resets)
        self._at, self._ok, self._run = [], [], []
        for s, session in enumerate(self.arrays):
            times = session["timestamp"]
            mine = np.flatnonzero(windows.window_session == s)
            ends = windows.index[mine, 1]
            at = np.full(len(times), -1)
            at[ends] = mine
            ok = np.zeros(len(times), dtype=bool)
            ok[ends] = self.placeable[mine]
            runs = np.full(len(times), -1)
            runs[ends] = run[mine]
            self._at.append(at)
            self._ok.append(np.concatenate(([0], np.cumsum(ok))))
            self._run.append(runs)

    def sessions_of(self, boot):
        """The session indices of `boot` in the order of the window set."""
        return [s for s, ident in enumerate(self.windows.session_ids) if self.meta[ident]["boot"] == boot]

    def _whole(self, s, lo, hi):
        """Whether every row lo..hi of session s ends a placeable window and they are of one run (arrays)."""
        count = len(self._at[s])
        good = (lo >= 0) & (hi < count) & (lo <= hi)
        lo, hi = np.clip(lo, 0, count - 1), np.clip(hi, 0, count - 1)
        full = self._ok[s][hi + 1] - self._ok[s][lo] == hi - lo + 1
        return good & full & (self._run[s][lo] == self._run[s][hi])

    def starts(self, s, length, horizon_s):
        """(starts, last): the block starts of PLACEMENT_RULE in session s for a block of `length` rows, and for each
        the last row of its needed windows (its first is the start minus window_rows)."""
        rows, times = self.windows.window_rows, self.arrays[s]["timestamp"]
        start = np.arange(len(times))
        # The first row at or after t + horizon_s, len(times) when the session ends before it (no start there): its
        # window closes the horizon, so every window of the horizon [t, t + horizon_s] exists in the same run.
        reach = np.searchsorted(times, times + horizon_s, side="left")
        last = np.maximum(start + length + rows - 2, reach)
        valid = self._whole(s, start - rows, last)
        return start[valid], last[valid]

    def segment(self, s, first, length):
        """The position in session s of the rows of seq first .. first + length - 1 for each of `first` (an array),
        -1 where they are not each the last row of a placeable window of one run (DONOR_RULE)."""
        seq = self.arrays[s]["seq"]
        where = np.searchsorted(seq, first)
        end = where + length - 1
        inside = end < len(seq)
        safe_where, safe_end = np.minimum(where, len(seq) - 1), np.minimum(end, len(seq) - 1)
        match = inside & (seq[safe_where] == first) & (seq[safe_end] == first + length - 1)
        return np.where(match & self._whole(s, safe_where, safe_end), where, -1)


class Ranges:
    """The ranges of VALIDITY_RULE: per quantity (QUANTITIES) the quantiles lo and hi of every TCN input over the last
    rows of the windows of role train (train_ranges)."""

    def __init__(self, normalizer_sha256, input_names, levels, rows, bounds, windows):
        self.normalizer_sha256, self.input_names = normalizer_sha256, tuple(input_names)
        self.levels, self.rows, self.bounds, self.windows = list(levels), rows, bounds, windows

    def record(self):
        return {"levels": self.levels, "moving_average_rows": self.rows, "normalizer_sha256": self.normalizer_sha256,
                "train_windows": self.windows, "inputs": list(self.input_names),
                "bounds": {q: {"lo": lo.tolist(), "hi": hi.tolist()} for q, (lo, hi) in self.bounds.items()},
                "rule": VALIDITY_RULE}


def _quantities(values, ends, rows):
    """value, difference and moving average (over `rows` rows) of the global inputs `values` (T, G) at the rows
    `ends`; the moving average is the mean of each window of rows sorted first (VALIDITY_RULE, judgment: the sum of
    numpy depends on the order of its terms in the last bit, so a window whose rows a block of class C only permutes
    keeps its mean bit for bit; identical inputs give identical values)."""
    means = np.sort(sliding_window_view(values, rows, axis=0)[ends - rows + 1], axis=-1).mean(axis=-1)
    return {"value": values[ends], "difference": values[ends] - values[ends - 1], "moving_average": means}


def train_ranges(train, protocol):
    """The ranges of VALIDITY_RULE from the window set of role train (the windows of M's normalizer)."""
    keys = protocol_keys(protocol)
    if _okna(train, "train").role != "train":
        raise ValueError(f"the ranges of the validity predicate come from role train, not {train.role}")
    rows = keys["moving_average_rows"]
    if rows > train.window_rows:
        raise ValueError(f"a moving average of {rows} rows exceeds the window of {train.window_rows}")
    parts = {q: [] for q in QUANTITIES}
    for s, session in enumerate(train.sessions()):
        values = session["global"]
        ends = train.index[train.window_session == s, 1]
        if len(ends):
            for q, found in _quantities(values, ends, rows).items():
                parts[q].append(found)
    lo, hi = keys["quantiles"]
    bounds = {}
    for q in QUANTITIES:
        found = np.concatenate(parts[q])
        bounds[q] = (np.quantile(found, lo, axis=0), np.quantile(found, hi, axis=0))
    return Ranges(train.normalizer_sha256, train.input_names, keys["quantiles"], rows, bounds, len(train))


def violations(ranges, original, copy, block, length):
    """VALIDITY_RULE on one copy: `original` and `copy` are the global inputs (rows, G) of the same rows of a session,
    the block at row `block` of them with `length` rows, at least moving_average_rows rows before it and every row up
    to the last one a moving average reads the block. Every value of every quantity at the judged rows (the block's
    first row to the last one whose moving average reads the block) is judged: it violates the predicate when it lies
    outside the train range of its quantity and input (range: the quantiles lo and hi) and outside the range of the
    same quantity of the same input at the judged rows of the original (before: its minimum and maximum there), the
    lead's new deviation (question Q14). [{quantity, input, row (from the block's first), value, range, before}] in the
    order of QUANTITIES, rows and inputs; [] when the copy is valid."""
    rows = ranges.rows
    original, copy = np.asarray(original, dtype=np.float64), np.asarray(copy, dtype=np.float64)
    if original.shape != copy.shape or original.ndim != 2 or original.shape[1] != len(ranges.input_names):
        raise ValueError(f"original and copy are the (rows, {len(ranges.input_names)}) global inputs of the same rows")
    last = block + length + rows - 2
    if block < rows or last >= len(copy):
        raise ValueError(f"the rows hold {rows} rows before the block and every row to {last}")
    ends = np.arange(block, last + 1)
    before, after = _quantities(original, ends, rows), _quantities(copy, ends, rows)
    found = []
    for q in QUANTITIES:
        lo, hi = ranges.bounds[q]
        own_lo, own_hi = before[q].min(axis=0), before[q].max(axis=0)
        bad = ((after[q] < lo) | (after[q] > hi)) & ((after[q] < own_lo) | (after[q] > own_hi))
        for row, column in zip(*np.nonzero(bad)):
            found.append({"quantity": q, "input": ranges.input_names[column], "row": int(row),
                          "value": float(after[q][row, column]),
                          "range": [float(lo[column]), float(hi[column])],
                          "before": [float(own_lo[column]), float(own_hi[column])]})
    return found


# ------------------------------------------------------------------ the plan of one role


def _deal(values, count, rng):
    """DEAL_RULE: `count` items of `values`, each floor(count / len) times or once more, in a random order."""
    base, extra = divmod(count, len(values))
    plus = set(rng.choice(len(values), size=extra, replace=False).tolist()) if extra else set()
    deck = [value for i, value in enumerate(values) for _ in range(base + (i in plus))]
    return [deck[i] for i in rng.permutation(len(deck))]


class Plan:
    """The interventions of one role (plan()): `interventions` their records (JSON) in the order of the deal, `copies`
    the window set of their copies (None when none is placed; the session of a copy is named by its intervention's
    id), `horizons` {id: the indices of the copy's windows in its horizon}, `boots` the boots in order, `keys` the
    protocol keys read, record() the JSON of all of it."""

    def __init__(self, carriers, mode, keys, interventions, copies, horizons, header):
        self.carriers, self.role, self.mode, self.keys = carriers, carriers.role, mode, keys
        self.interventions, self.copies, self.horizons, self._header = interventions, copies, horizons, header
        self.boots = list(carriers.boots)

    def record(self):
        return dict(self._header, interventions=[dict(item) for item in self.interventions])


def _check_donors(carriers, donors):
    role = carriers.role
    if type(donors) is not dict or set(donors) != set(DONOR_ROLES[role]):
        raise ValueError(f"the donors of {role} are the carriers of exactly the roles "
                         f"{', '.join(DONOR_ROLES[role])} (DONOR_RULE)")
    for name, pool in donors.items():
        if not isinstance(pool, Carriers) or pool.role != name or not pool.windows.same(carriers.windows):
            raise ValueError(f"the donors of role {name} are its carriers of the same normalizer and window")
        if name == role and pool is not carriers:
            raise ValueError(f"the donors of role {role} are its own carriers (the same object)")
    return [donors[name] for name in DONOR_ROLES[role]]


def _usable_groups(groups, windows):
    """(the groups of D with their TCN inputs and whether they swap the bins, the groups left out): D_RULE."""
    rule = windows.normalizer.rule
    used, left = [], []
    for name, columns in groups.items():
        inputs = [column for column in columns if column in windows.input_names]
        bins = set(BIN_CHANNELS) <= set(columns)
        if inputs or bins:
            used.append({"name": name, "inputs": inputs, "bins": bins,
                         "columns": [windows.input_names.index(column) for column in inputs]})
        else:
            left.append({"name": name, "columns": {column: rule.classes[column] for column in columns},
                         "why": f"no column is a TCN input under rule {rule.name}"})
    return used, left


def _stream(protocol, unit, mode):
    """The seed of the stream injections for `unit` (UNIT_RULE): scripts/protocol_v5.py analysis_seed, which reads the
    checked analysis plan of the schema-3 protocol and refuses a unit outside INJECTION_UNITS and an unknown mode."""
    purposes = _value(protocol, "streams.purposes")
    if type(purposes) is not list or PURPOSE not in purposes:
        raise ValueError(f"streams.purposes has no {PURPOSE}: the stream of the interventions (design B7b 1.4)")
    return protocol_v5.analysis_seed(protocol, PURPOSE, unit, mode=mode)


def plan(carriers, *, protocol, mode, ranges, donors):
    """The interventions of the role of `carriers` (PLACEMENT_RULE and the rules it names): per class
    analysis.interventions.<class>.per_boot in every boot, each placed, applied to its own copy of a session and
    judged by the validity predicate. ranges: train_ranges() of the same normalizer. donors: {role: Carriers} for
    exactly the donor roles of the role (DONOR_ROLES), the role's own carriers being `carriers` itself. mode: the plan
    mode of the corpus (campaign or rehearsal), which names the stream; no default."""
    keys = protocol_keys(protocol)
    if not isinstance(carriers, Carriers):
        raise ValueError("the interventions go into carriers (tcn.zasahy.Carriers)")
    role, windows = carriers.role, carriers.windows
    unit_of = units(role)
    if (windows.window_rows, windows.interval_s) != (keys["window_rows"], keys["interval_s"]):
        raise ValueError(f"the window set has window_rows {windows.window_rows} and interval_s {windows.interval_s}, "
                         f"the protocol {keys['window_rows']} and {keys['interval_s']}")
    if not isinstance(ranges, Ranges) or ranges.normalizer_sha256 != windows.normalizer_sha256:
        raise ValueError("the ranges of the validity predicate are train_ranges() of the same normalizer")
    if ranges.rows != keys["moving_average_rows"] or ranges.levels != keys["quantiles"]:
        raise ValueError("the ranges were taken under other analysis.interventions quantiles or moving_average_rows")
    pools = _check_donors(carriers, donors)
    groups, left_out = _usable_groups(keys["classes"]["D"]["groups"], windows)
    if not groups:
        raise ValueError("no group of analysis.interventions.D.groups has a TCN input or the bins under rule "
                         f"{windows.normalizer.rule.name}: class D has nothing to swap")
    seeds = {unit: _stream(protocol, unit, mode) for unit in dict.fromkeys(unit_of.values())}
    generators = {unit: np.random.default_rng(seed) for unit, seed in seeds.items()}
    by_cell = {}
    for pool in pools:
        for d, ident in enumerate(pool.windows.session_ids):
            item = pool.meta[ident]
            by_cell.setdefault((item["scenario"], item["position"]), []).append((pool, d))
    rows, horizon = windows.window_rows, keys["horizon_s"]
    interventions, copy_rows, copy_windows, spans = [], [], [], {}
    for cls in CLASSES:
        rng, spec = generators[unit_of[cls]], keys["classes"][cls]
        count = spec["per_boot"] * len(carriers.boots)
        lengths = _deal(spec["lengths"], count, rng)
        variants = _deal(spec["orders"] if cls == "C" else [g["name"] for g in groups], count, rng)
        cache = {}
        for b, boot in enumerate(carriers.boots):
            for j in range(spec["per_boot"]):
                number = b * spec["per_boot"] + j
                length, variant = lengths[number], variants[number]
                ident = f"{role}/{cls}/{number:03d}"
                item = {"id": ident, "role": role, "class": cls, "boot": boot, "length": length,
                        ("order" if cls == "C" else "group"): variant}
                if (boot, length) not in cache:
                    cache[boot, length] = _candidates(carriers, boot, length, horizon, by_cell if cls == "D" else None)
                candidates = cache[boot, length]
                if not candidates:
                    interventions.append(dict(item, status="not_placed", placed=False, valid=None,
                                              why="no row of the boot's sessions meets PLACEMENT_RULE"
                                                  + (" with a donor (DONOR_RULE)" if cls == "D" else "")))
                    continue
                s, start, last, donor_list = candidates[int(rng.integers(len(candidates)))]
                donor = donor_list[int(rng.integers(len(donor_list)))] if cls == "D" else None
                order = None
                if cls == "C":
                    order = np.arange(length)[::-1]
                    if variant == "random":
                        order = rng.permutation(length)
                        while np.array_equal(order, np.arange(length)):
                            order = rng.permutation(length)
                group = next((g for g in groups if g["name"] == variant), None) if cls == "D" else None
                made = _apply(carriers, s, start, last, length, order, group, donor, ranges, horizon, ident)
                item.update(made["record"])
                if cls == "C":
                    item["permutation"] = order.tolist()
                else:
                    item.update(inputs=list(group["inputs"]), bins=group["bins"])
                interventions.append(item)
                copy_rows.append(made["session"])
                spans[ident] = (len(copy_windows), made["windows"], made["horizon"])
                copy_windows += [(len(copy_rows) - 1, *w) for w in made["windows"]]
    copies, horizons = None, {}
    if copy_rows:
        copies = Okna(copy_rows, copy_windows, role=role, normalizer=windows.normalizer, window_rows=rows,
                      max_gap_s=windows.max_gap_s, interval_s=windows.interval_s)
        horizons = {ident: first + np.asarray(mine, dtype=np.int64) for ident, (first, _, mine) in spans.items()}
    header = {"schema": SCHEMA, "role": role, "mode": mode, "purpose": PURPOSE, "units": unit_of,
              "stream_seeds": seeds, "donor_roles": list(DONOR_ROLES[role]), "boots": list(carriers.boots),
              "keys": keys, "groups": {"used": [{"name": g["name"], "inputs": g["inputs"], "bins": g["bins"]}
                                                for g in groups], "left_out": left_out},
              "ranges": ranges.record(),
              "counts": _counts(interventions, keys, [g["name"] for g in groups]),
              "rules": {"unit": UNIT_RULE, "deal": DEAL_RULE, "placement": PLACEMENT_RULE, "C": C_RULE, "D": D_RULE,
                        "donor": DONOR_RULE, "validity": VALIDITY_RULE, "volume": keys["volume"]}}
    return Plan(carriers, mode, keys, interventions, copies, horizons, header)


def _candidates(carriers, boot, length, horizon, by_cell):
    """[(session, start, last row of the needed windows, donors)] of PLACEMENT_RULE in `boot`; with by_cell (class D)
    only the starts with a donor, each donor (carriers, session, position of its segment)."""
    out = []
    for s in carriers.sessions_of(boot):
        starts, lasts = carriers.starts(s, length, horizon)
        if not len(starts):
            continue
        if by_cell is None:
            out += [(s, int(a), int(z), None) for a, z in zip(starts, lasts)]
            continue
        ident = carriers.windows.session_ids[s]
        item = carriers.meta[ident]
        first = carriers.arrays[s]["seq"][starts]
        found = []
        for pool, d in by_cell.get((item["scenario"], item["position"]), []):
            if pool is carriers and d == s:
                continue
            found.append((pool, d, pool.segment(d, first, length)))
        for i, (a, z) in enumerate(zip(starts, lasts)):
            donors = [(pool, d, int(where[i])) for pool, d, where in found if where[i] >= 0]
            if donors:
                out.append((s, int(a), int(z), donors))
    return out


def _apply(carriers, s, start, last, length, order, group, donor, ranges, horizon, ident):
    """The copy of session s with one intervention (C_RULE or D_RULE), its windows and horizon, and its record."""
    windows = carriers.windows
    rows = windows.window_rows
    arrays = carriers.arrays[s]
    g, local = arrays["global"], arrays["local"]
    seq, times, load = arrays["seq"], arrays["timestamp"], arrays["load"]
    at = carriers._at[s]
    needed = at[start - rows:last + 1]
    anchors = windows.index[needed, 2]
    first = int(anchors[0]) if anchors[0] >= 0 else start - 2 * rows + 1
    take = slice(first, last + 1)
    copy_g, copy_local = g[take].copy(), local[take].copy()
    block = start - first
    inside = slice(block, block + length)
    record = {"session": windows.session_ids[s], "scenario": carriers.meta[windows.session_ids[s]]["scenario"],
              "position": carriers.meta[windows.session_ids[s]]["position"], "placed": True,
              "start": {"position": start, "seq": int(seq[start]), "time": float(times[start])}}
    if order is not None:
        copy_g[inside] = g[start:start + length][order]
        copy_local[inside] = local[start:start + length][order]
    else:
        pool, d, where = donor
        copy_g[inside, group["columns"]] = pool.arrays[d]["global"][where:where + length][:, group["columns"]]
        if group["bins"]:
            copy_local[inside] = pool.arrays[d]["local"][where:where + length]
        record["donor"] = {"role": pool.role, "session": pool.windows.session_ids[d], "position": where,
                           "boot": pool.meta[pool.windows.session_ids[d]]["boot"]}
    found = violations(ranges, g[take], copy_g, block, length)
    record.update(valid=not found, status="evaluable" if not found else "volume", violations=len(found),
                  first_violation=found[0] if found else None,
                  changed_values=int((copy_g != g[take]).sum() + (copy_local != local[take]).sum()))
    ends = windows.index[needed, 1]
    mine = [(int(e) - first, None if a < 0 else int(a) - first) for e, a in zip(ends, anchors)]
    in_horizon = [i for i, e in enumerate(ends) if e >= start and times[e] <= times[start] + horizon]
    record["windows"] = {"needed": len(mine), "horizon": len(in_horizon), "history": rows}
    session = {"id": ident, "global": copy_g, "local": copy_local, "seq": seq[take].copy(),
               "timestamp": times[take].copy(), "full_times": list(windows.full_times[s]),
               "load": None if load is None else load[take].copy()}
    if ARCHIVE_KEY in arrays:  # The copy of a sealed session stays sealed (package B7c, tcn/pecat.py GUARD_RULE).
        session[ARCHIVE_KEY] = arrays[ARCHIVE_KEY]
    return {"session": session, "windows": mine, "horizon": in_horizon, "record": record}


def _count_statuses(items):
    """planned and the count of each status of STATUSES among `items`."""
    return {"planned": len(items), **{status: sum(item["status"] == status for item in items) for status in STATUSES}}


def _counts(interventions, keys, groups):
    """Per class: planned, each status, the planned count of each length and variant (DEAL_RULE), and by_length the
    planned count and each status per length (the share of the volume class by class and length that G3a reports,
    the lead's answer to Q14; tcn/k2.py VOLUME_FINDING_RULE), so the plan of dev shows it too."""
    out = {}
    for cls in CLASSES:
        mine = [item for item in interventions if item["class"] == cls]
        variant, names = ("order", keys["classes"]["C"]["orders"]) if cls == "C" else ("group", groups)
        lengths = keys["classes"][cls]["lengths"]
        out[cls] = {**_count_statuses(mine),
                    "lengths": {str(n): sum(item["length"] == n for item in mine) for n in lengths},
                    "variants": {name: sum(item[variant] == name for item in mine) for name in names},
                    "by_length": {str(n): _count_statuses([item for item in mine if item["length"] == n])
                                  for n in lengths}}
    return out
