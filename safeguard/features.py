"""Shared, fail-closed feature handling for fitting, replay and monitoring.

Original implementation for this project. Behavioral inputs deliberately omit
integrity findings, collection flags and machine identities. These remain in
the frame metadata for independent checks and explanations.
"""
from collections import deque
from copy import deepcopy
from dataclasses import dataclass
import json
import math
from pathlib import Path

import numpy as np

from features.archive import BEHAVIOR_NAMES
from features.contract import validate_sidecar
from features.perbin import Memslots
from features.qualification import CLASSES, LOCAL_SCALED
from features.snapshot import MENA, SCHEMA, _vsetky_hlavicky, counted_bin, sidecar_cesta, vektor_snimky
from features.windows import BIN_PRIZNAKY, perbin_zo_sidecaru
from features.quality import BEHAVIOR_POLICY


CONTRACT_SCHEMA = "hyptcn3/safeguard-features/3"
# Package B6b (design B6b 1.1): the normalizer follows the classes of the columns and the scale rule of the protocol.
NORMALIZER_SCHEMA = "hyptcn3/safeguard-normalizer/2"
OLD_NORMALIZER_SCHEMAS = ("hyptcn3/safeguard-normalizer/1",)
GLOBAL_NAMES = tuple(BEHAVIOR_NAMES)
LOCAL_NAMES = tuple(BIN_PRIZNAKY)
# The classes of analysis.columns (features/qualification.py CLASSES) by what they feed: an input of the TCN (the
# value; the first difference, DIFFERENCE_POLICY), the rule channel (each class with the quantity it judges, the value
# or the change since the session's first measured row, SESSION_START_POLICY), nothing (dropped).
TCN_CLASSES = ("neural", "differenced")
RULE_CLASSES = {"rule": "value", "rule_differenced": "since_session_start"}
LEGACY_SCHEMAS = ("hyptcn3/collection-protocol/1", "hyptcn3/collection-protocol/2")
PROTOCOL_SCHEMA_3 = "hyptcn3/collection-protocol/3"
LEGACY_RULE, DIAGNOSTIC_RULE, ANALYSIS_RULE = "legacy_schema_2", "all_neural_diagnostic", "analysis.columns"
RULE_NOTES = {
    LEGACY_RULE: "protocol schema 1 or 2: every column neural, one pooled scale of the bins, a scale at or below the "
                 "machine epsilon replaced by 1, every bin fitted and scored (the normalizer before package B6b)",
    DIAGNOSTIC_RULE: "protocol schema 3 while analysis.columns is null (before G3a), diagnostic only: every column "
                     "neural; the scale rule of analysis.scale",
    ANALYSIS_RULE: "protocol schema 3: the classes of analysis.columns and the scale rule of analysis.scale",
}
DIFFERENCE_POLICY = (
    "a column of class differenced enters the TCN as its first difference: its value minus the value of the last "
    "measured row before it in the same session (valid, no full snapshot, with a predecessor), across an excluded row "
    "too, as features/qualification.py takes it; a scoring window with a differenced column needs that row before its "
    "first row (WindowBuffer anchored), at a session's start one measured row more than window_rows")
# Question Q8, its revised proposal (2026-11-23T07:51Z), accepted by the lead 2026-11-24: the rule channel judges a
# column of class rule_differenced by its change since the session's first measured row, so a boot with another
# constant level changes nothing while a persistent step stays outside the range for every row after it.
SESSION_START_POLICY = (
    "a column of class rule_differenced is judged by its change since the session's first measured row: its value "
    "minus the value of the first measured row of the same session (0 in that row)")
# The lead's answer to question Q8 (2026-11-24): the manifest states what this rule cannot see. rule_channel() gives it
# as the rule channel's limitation when a column of class rule_differenced exists, and safeguard/training.py adds it
# to the manifest's limitations.
SESSION_START_LIMITATION = (
    "A column of class rule_differenced is judged by its change since the session's first measured row, so a state "
    "already present in that row is never seen by this rule; in a live run that row is the first measured row after "
    "the detector starts (the lead's answer to question Q8, 2026-11-24).")
MEASURED_ROWS = (
    "valid, no full snapshot and with a predecessor, in the order of seq (as the normalizer's rows of train and "
    "features/qualification.py); a change since the session's first measured row is taken over those rows of one "
    "session")
# The roles whose measured rows give the ranges of the rule channel (skeleton B6 section 4, design B6b 1.3).
RULE_RANGE_ROLES = ("train", "calibration")
RULE_CHANNEL_RULE = (
    "a measured row exceeds when the value (class rule) or the change since the session's first measured row (class "
    "rule_differenced) of one of the rule channel's columns lies outside its range over the measured rows of train "
    "and calibration; the alarm is k of n exceeding rows (the neural channel's k and n, so that both channels define "
    "an alarm alike: the lead's judgment, skeleton B6 section 4), with the history of the rule channel, cleared where "
    "the neural channel's is (barriers, discontinuities, input errors); never reported as neural detection")


def _integer(value, name, minimum=0):
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, np.integer)) or value < minimum:
        raise ValueError(f"invalid {name}: expected integer >= {minimum}")
    return int(value)


def _temporal(window_rows, max_gap_s):
    window_rows = _integer(window_rows, "window_rows", 1)
    if isinstance(max_gap_s, bool) or not isinstance(max_gap_s, (int, float, np.number)):
        raise ValueError("max_gap_s must be finite and positive")
    max_gap_s = float(max_gap_s)
    if not math.isfinite(max_gap_s) or max_gap_s <= 0:
        raise ValueError("max_gap_s must be finite and positive")
    return window_rows, max_gap_s


def _layout(layout, biny):
    """Verify that physical regions and bin page counts describe one geometry."""
    if not isinstance(layout, dict):
        raise ValueError("missing layout metadata")
    required = {"bin_bytes", "page_size", "bins", "regions", "memsize", "vcpus"}
    if not required <= layout.keys():
        raise ValueError("incomplete layout metadata")
    size = _integer(layout["bin_bytes"], "bin_bytes", 1)
    page = _integer(layout["page_size"], "page_size", 1)
    if page != 4096 or size < page or size & (size - 1):
        raise ValueError("invalid bin/page geometry")
    memory = _integer(layout["memsize"], "memsize", page)
    _integer(layout["vcpus"], "vcpus", 1)
    if memory % page:
        raise ValueError("unaligned memory size")
    if not isinstance(layout["regions"], list) or not layout["regions"]:
        raise ValueError("missing physical regions")
    regions = []
    for region in layout["regions"]:
        if not isinstance(region, dict) or not {"gpa", "bytes"} <= region.keys():
            raise ValueError("invalid physical region")
        regions.append((_integer(region["gpa"], "region GPA"),
                        _integer(region["bytes"], "region bytes", page)))
    slots = Memslots(regions, "feature contract")
    if slots.pages_total * page > memory:
        raise ValueError("physical regions exceed VM memory")
    expected = slots.bin_pages(size)
    if not isinstance(layout["bins"], list):
        raise ValueError("invalid layout bins")
    actual = []
    for entry in layout["bins"]:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError("invalid layout bin entry")
        actual.append((_integer(entry[0], "bin index"),
                       _integer(entry[1], "bin pages", 1)))
    if actual != sorted(expected.items()) or tuple(b for b, _ in actual) != biny:
        raise ValueError("bin identity/page counts do not match physical geometry")


def _quality(quality):
    required = {"model_valid", "behavior_valid", "traversals_complete", "inconclusive", "findings",
                "read_errors", "filled_zero"}
    if not isinstance(quality, dict) or not required <= quality.keys():
        raise ValueError("missing structured quality metadata")
    for key in ("model_valid", "behavior_valid", "traversals_complete"):
        if type(quality[key]) is not bool:
            raise ValueError(f"quality {key} must be boolean")
    if not isinstance(quality["inconclusive"], list) or not all(
            isinstance(name, str) for name in quality["inconclusive"]):
        raise ValueError("invalid inconclusive checks")
    if not isinstance(quality["findings"], list) or not all(
            isinstance(finding, dict) for finding in quality["findings"]):
        raise ValueError("invalid integrity findings")
    for name in ("read_errors", "filled_zero"):
        _integer(quality[name], name)
    complete = (quality["traversals_complete"] and not quality["read_errors"]
                and not quality["filled_zero"])
    if quality["behavior_valid"] and not complete:
        raise ValueError("behavior_valid contradicts structured quality metadata")
    if quality["model_valid"] and (not quality["behavior_valid"] or not complete
            or (set(quality["inconclusive"]) - {"text_integrity"})):
        raise ValueError("model_valid contradicts structured quality metadata")


def _local(values):
    if values.ndim < 2 or values.shape[-1] != len(LOCAL_NAMES) or values.shape[-2] < 1:
        raise ValueError("invalid per-bin shape")
    if not np.isfinite(values).all():
        raise ValueError("non-finite per-bin features")
    if (np.any(values[..., :2] < 0) or np.any(values[..., :2] > 1)
            or np.any(values[..., 2] < 0) or np.any(values[..., 2] > 8)):
        raise ValueError("per-bin value outside its physical range")
    mask = values[..., 3]
    if not np.isin(mask, [0, 1]).all():
        raise ValueError("invalid entropy measurement mask")
    if np.any((mask == 0) & (values[..., 2] != 0)):
        raise ValueError("entropy value without measurement")
    if np.any((values[..., 0] > 0) != (mask == 1)):
        raise ValueError("change ratio contradicts measurement mask")


@dataclass(frozen=True)
class Frame:
    session: str
    seq: int
    timestamp: float
    vector: np.ndarray
    perbin: np.ndarray
    biny: tuple[int, ...]
    quality: dict
    chain_id: str
    layout: dict

    def __post_init__(self):
        if not isinstance(self.session, str) or not self.session:
            raise ValueError("missing session identity")
        object.__setattr__(self, "seq", _integer(self.seq, "sequence"))
        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, (int, float, np.number)):
            raise ValueError("invalid snapshot timestamp")
        if not math.isfinite(self.timestamp):
            raise ValueError("non-finite snapshot timestamp")
        object.__setattr__(self, "timestamp", float(self.timestamp))
        vector = np.array(self.vector, dtype=np.float64, copy=True)
        local = np.array(self.perbin, dtype=np.float64, copy=True)
        if vector.shape != (len(MENA),) or not np.isfinite(vector).all():
            raise ValueError("invalid raw feature vector")
        if not np.isin(vector[-2:], [0, 1]).all():
            raise ValueError("invalid predecessor/full flags")
        ids = tuple(_integer(b, "bin identity") for b in self.biny)
        if not ids or ids != tuple(sorted(set(ids))) or local.shape != (len(ids), len(LOCAL_NAMES)):
            raise ValueError("invalid bin identities or per-bin shape")
        if not isinstance(self.chain_id, str) or not self.chain_id:
            raise ValueError("missing chain identity")
        _local(local)
        _quality(self.quality)
        _layout(self.layout, ids)
        vector.setflags(write=False)
        local.setflags(write=False)
        object.__setattr__(self, "vector", vector)
        object.__setattr__(self, "perbin", local)
        object.__setattr__(self, "biny", ids)
        object.__setattr__(self, "quality", deepcopy(self.quality))
        object.__setattr__(self, "layout", deepcopy(self.layout))

    @property
    def valid(self):
        _quality(self.quality)
        return self.quality["behavior_valid"]

    @property
    def full(self):
        return bool(self.vector[MENA.index("je_plna")])

    @property
    def has_predecessor(self):
        return bool(self.vector[MENA.index("ma_predchodcu")])

    @property
    def measured(self):
        """A row the model, the normalizer, the rule channel and the qualification read: valid, no full snapshot and
        with a predecessor (features/qualification.py measured)."""
        return self.valid and not self.full and self.has_predecessor


def frames_from_archive(data, session_id):
    """Import the versioned archive without guessing missing timing or quality."""
    if str(data["schema"]) != SCHEMA or tuple(data["mena"]) != MENA:
        raise ValueError("incompatible feature archive schema/order")
    if str(data.get("quality_policy", "")) != BEHAVIOR_POLICY:
        raise ValueError("incompatible feature quality policy; re-extract for behavioral inputs")
    quality = (json.loads(str(data["quality_json"])) if "quality_json" in data
               else data["quality"])
    layout = (json.loads(str(data["layout_json"])) if "layout_json" in data
              else data["layout"])
    matrix = np.asarray(data["matica"])
    seq = np.asarray(data["seq"])
    times = np.asarray(data["casy"])
    valid = np.asarray(data["valid"])
    local = np.asarray(data["perbin"])
    ids = tuple(data["biny"])
    if matrix.ndim != 2 or matrix.shape[1] != len(MENA):
        raise ValueError("invalid archive matrix")
    n = len(matrix)
    if (seq.shape != (n,) or times.shape != (n,) or valid.shape != (n,)
            or len(quality) != n or len(data["chain_ids"]) != n
            or local.shape != (n, len(ids), len(LOCAL_NAMES))):
        raise ValueError("archive metadata row count mismatch")
    if seq.dtype.kind not in "iu" or valid.dtype != np.dtype(bool):
        raise ValueError("invalid archive sequence/valid types")
    result = [Frame(str(session_id), seq[i], times[i], matrix[i], local[i], ids,
                    quality[i], str(data["chain_ids"][i]), layout) for i in range(n)]
    if [row.valid for row in result] != valid.tolist():
        raise ValueError("archive valid mask disagrees with quality")
    for previous, current in zip(result, result[1:]):
        if current.seq <= previous.seq or current.timestamp <= previous.timestamp:
            raise ValueError("non-increasing archive sequence/time")
    return result


def frame_from_snapshot(raw_dir, profile, seq, previous=None, session_id=None, *, max_gap_s=7.5, min_bin_pages):
    """Extract one raw frame using the same semantic parser as archive creation. min_bin_pages has no default
    (question Q10 to the lead, 2026-11-24): the bins the eight memory columns come from (features/snapshot.py
    pamat_zo_sidecaru), the live run's from its bundle (safeguard/bundle.py Bundle.min_bin_pages) as the audit's from
    the protocol; None means every bin (schemas 1 and 2), and a legacy caller passes it explicitly."""
    _, gap = _temporal(1, max_gap_s)
    seq = _integer(seq, "sequence")
    raw_dir = str(raw_dir)
    session = str(session_id) if session_id is not None else str(Path(raw_dir).resolve())
    matches = [head for head in _vsetky_hlavicky(raw_dir) if head["seq"] == seq]
    if len(matches) != 1:
        raise ValueError("snapshot sequence missing or ambiguous")
    head = matches[0]
    sidepath = sidecar_cesta(head["path"])
    side = json.loads(Path(sidepath).read_text())
    layout = validate_sidecar(side)
    if (side["seq"] != seq or side["output"]["full"] != head["full"]
            or str(side["output"]["chain_id"]) != str(head["chain_id"])):
        raise ValueError("sidecar does not match snapshot header")
    timestamp = float(side["timestamp_unix"])
    cross_view = None
    if previous is not None:
        meta = previous.get("_safeguard")
        if not isinstance(meta, dict):
            raise ValueError("predecessor lacks continuity metadata")
        if previous.get("layout") != layout:
            raise ValueError("memory layout changed")
        if meta["session"] != session:
            previous = None
        elif seq <= meta["seq"] or timestamp <= meta["timestamp"]:
            raise ValueError("non-increasing snapshot sequence/time")
        else:
            adjacent = seq == meta["seq"] + 1 and timestamp - meta["timestamp"] <= gap
            # A cross-view difference is confirmed by the adjacent snapshot even
            # when that snapshot's behavioral inputs were invalid.
            cross_view = previous.get("krizove_kluce") if adjacent else None
            if not adjacent or not previous["quality"]["behavior_valid"]:
                previous = None
    vector, state, notes = vektor_snimky(raw_dir, str(profile), seq, previous,
                                         predch_krizove=cross_view, min_bin_pages=min_bin_pages)
    ids, local = perbin_zo_sidecaru(sidepath)
    quality = deepcopy(state["quality"])
    quality.update(read_errors=side["stats"]["read_errors"],
                   filled_zero=side["stats"]["filled_zero"], notes=list(notes),
                   process_ids=sorted(state["pids"]), snapshot_path=str(head["path"]))
    quality["model_valid"] = (quality["model_valid"] and not quality["read_errors"]
                              and not quality["filled_zero"])
    quality["behavior_valid"] = (quality["behavior_valid"] and not quality["read_errors"]
                                and not quality["filled_zero"])
    frame = Frame(session, seq, timestamp, vector, local, ids, quality,
                  str(side["output"]["chain_id"]), layout)
    state["quality"] = quality
    state["_safeguard"] = {"session": session, "seq": seq, "timestamp": timestamp}
    return frame, state


def arrays(window):
    """Return separate global and per-bin axes, excluding verdict/quality columns."""
    if not window:
        raise ValueError("empty feature window")
    layout, ids = window[0].layout, window[0].biny
    if any(frame.layout != layout or frame.biny != ids for frame in window):
        raise ValueError("memory layout/bin identities changed")
    return (np.stack([frame.vector[:len(GLOBAL_NAMES)] for frame in window]),
            np.stack([frame.perbin for frame in window]))


class WindowBuffer:
    """Ordered temporal eligibility rules shared by every model consumer.

    A window is window_rows continuous measured rows. Anchored (a normalization rule with a differenced column,
    DIFFERENCE_POLICY), a window also needs the last measured row of its session before its first row, the anchor,
    which may lie across a barrier, and push returns [anchor, *rows]: window_rows + 1 frames. So after a barrier inside
    a session window_rows continuous rows suffice again, and at a session's start window_rows + 1 measured rows are
    needed.
    """
    def __init__(self, window_rows, max_gap_s=7.5, *, anchored=False):
        self.window_rows, self.max_gap_s = _temporal(window_rows, max_gap_s)
        if type(anchored) is not bool:
            raise ValueError("anchored must be True or False")
        self.anchored = anchored
        self.rows = deque(maxlen=self.window_rows)
        self.last = None
        self.layout = None
        self.biny = None
        self.reason = "warmup"
        self.reset = False
        self.last_measured = None  # The last measured row of the current session.
        self.anchor = None    # The measured row of the session before rows[0].

    def discontinuity(self, frame):
        return self.last is not None and (
            frame.session != self.last.session or frame.seq != self.last.seq + 1
            or frame.chain_id != self.last.chain_id
            or not 0 < frame.timestamp - self.last.timestamp <= self.max_gap_s
            or frame.layout != self.last.layout or frame.biny != self.last.biny)

    def _reject(self, reason):
        self.rows.clear()
        self.last_measured = self.anchor = None
        self.reset = True
        self.reason = reason
        raise ValueError(reason)

    def push(self, frame):
        self.reset = False
        if self.layout is not None and (frame.layout != self.layout or frame.biny != self.biny):
            self._reject("memory layout/bin identities changed")
        if self.last is not None and self.last.session == frame.session and (
                frame.seq <= self.last.seq or frame.timestamp <= self.last.timestamp):
            self._reject("non-increasing snapshot sequence/time")
        if self.last is not None and frame.session != self.last.session:
            self.last_measured = self.anchor = None
        self.reset = self.discontinuity(frame)
        if self.reset:
            self.rows.clear()
        self.last = frame
        self.layout, self.biny = frame.layout, frame.biny
        # Not frame.measured: features/acceptance.py and features/coverage.py push rows that only carry these flags.
        if not frame.valid or frame.full or not frame.has_predecessor:
            self.rows.clear()
            self.reset = True
            self.reason = ("invalid_input" if not frame.valid else "full_snapshot"
                           if frame.full else "no_predecessor")
            return None
        if not self.rows:
            self.anchor = self.last_measured  # A new run: the anchor may lie before the barrier.
        elif len(self.rows) == self.window_rows:
            self.anchor = self.rows[0]   # The row the window slides past.
        self.last_measured = frame
        self.rows.append(frame)
        self.reason = "warmup"
        if len(self.rows) < self.window_rows or (self.anchored and self.anchor is None):
            return None
        self.reason = "ready"
        return [self.anchor, *self.rows] if self.anchored else list(self.rows)


def feature_contract(frame, window_rows, max_gap_s):
    rows, gap = _temporal(window_rows, max_gap_s)
    _layout(frame.layout, frame.biny)
    return {"schema": CONTRACT_SCHEMA, "quality_policy": BEHAVIOR_POLICY, "raw_names": list(MENA),
            "global_names": list(GLOBAL_NAMES), "local_names": list(LOCAL_NAMES),
            "biny": list(frame.biny), "layout": deepcopy(frame.layout),
            "window_rows": rows, "max_gap_s": gap}


def check_frame(frame, contract):
    expected = feature_contract(frame, contract["window_rows"], contract["max_gap_s"])
    if contract != expected:
        raise ValueError("frame does not match saved feature contract")
    _quality(frame.quality)


def _positive(value):
    return (not isinstance(value, (bool, np.bool_)) and isinstance(value, (int, float, np.integer, np.floating))
            and math.isfinite(value) and value > 0)


@dataclass(frozen=True)
class NormalizationRule:
    """Which column enters what, and how the normalizer scales (package B6b, design B6b 1.1).

    classes: the class of every column of GLOBAL_NAMES (analysis.columns): neural and differenced are the inputs of
    the TCN (the value; the first difference, DIFFERENCE_POLICY), rule and rule_differenced the rule channel (the
    value; the change since the session's first measured row, SESSION_START_POLICY), dropped is in nothing. floor: the lower bound of each column's scale
    (analysis.scale.floor; one unit for counts), None under legacy_schema_2 (a scale at or below the machine epsilon is
    1). per_bin: every scored bin has a scale of its own, else one pooled scale. min_bin_pages: a bin of fewer pages is
    neither fitted nor scored; None: every bin is. local_floor: the lower bound of each scaled per-bin value.
    The name says where the rule came from (RULE_NOTES) and goes into the manifest with the rule."""
    name: str
    classes: dict
    floor: dict | None
    per_bin: bool
    min_bin_pages: int | None
    local_floor: dict | None

    def __post_init__(self):
        if self.name not in RULE_NOTES:
            raise ValueError(f"normalization rule: unknown rule {self.name!r}; the rules are {', '.join(RULE_NOTES)}")
        classes = self.classes
        if (type(classes) is not dict or set(classes) != set(GLOBAL_NAMES)
                or any(cls not in CLASSES for cls in classes.values())):
            raise ValueError("normalization rule: classes must give every column of features.archive.BEHAVIOR_NAMES "
                             "one of " + ", ".join(CLASSES))
        object.__setattr__(self, "classes", {name: classes[name] for name in GLOBAL_NAMES})
        if self.name != ANALYSIS_RULE and set(self.classes.values()) != {"neural"}:
            raise ValueError(f"normalization rule {self.name}: every column is neural")
        if self.name == LEGACY_RULE:
            if (self.floor, self.per_bin, self.min_bin_pages, self.local_floor) != (None, False, None, None):
                raise ValueError(f"normalization rule {LEGACY_RULE}: no floor, one pooled scale of the bins and no "
                                 "bin minimum (the normalizer before package B6b)")
        else:
            if (type(self.floor) is not dict or set(self.floor) != set(GLOBAL_NAMES)
                    or not all(map(_positive, self.floor.values()))
                    or type(self.local_floor) is not dict or set(self.local_floor) != set(LOCAL_SCALED)
                    or not all(map(_positive, self.local_floor.values()))):
                raise ValueError(f"normalization rule {self.name}: floor must give a positive number for every "
                                 "column and local_floor for " + ", ".join(LOCAL_SCALED) + " (analysis.scale)")
            if type(self.per_bin) is not bool or type(self.min_bin_pages) is not int or self.min_bin_pages < 1:
                raise ValueError(f"normalization rule {self.name}: per_bin is true or false and min_bin_pages an "
                                 "integer >= 1 (analysis.scale)")
            object.__setattr__(self, "floor", {name: float(self.floor[name]) for name in GLOBAL_NAMES})
            object.__setattr__(self, "local_floor", {name: float(self.local_floor[name]) for name in LOCAL_SCALED})
        if not self.tcn_names:
            raise ValueError(f"normalization rule {self.name}: no column of class neural or differenced; the TCN "
                             "needs one global input at least")

    @classmethod
    def legacy(cls):
        """legacy_schema_2: today's behaviour before package B6b, the rule of a protocol of schema 1 or 2."""
        return cls(LEGACY_RULE, dict.fromkeys(GLOBAL_NAMES, "neural"), None, False, None, None)

    @classmethod
    def from_protocol(cls, protocol, *, diagnostic):
        """The rule of a protocol (design B6b 1.1). Schema 3: the classes of analysis.columns and the scale rule of
        analysis.scale; while analysis.columns is null (before G3a) a production call is refused and a diagnostic one
        takes all_neural_diagnostic. Schemas 1 and 2: legacy_schema_2. Any other schema is refused by name."""
        if type(diagnostic) is not bool:
            raise ValueError("normalization rule: diagnostic must be True or False")
        schema = protocol.get("schema") if isinstance(protocol, dict) else None
        if schema in LEGACY_SCHEMAS:
            return cls.legacy()
        if schema != PROTOCOL_SCHEMA_3:
            raise ValueError(f"normalization rule: protocol schema {schema!r} has none (schemas 1 and 2: "
                             f"{LEGACY_RULE}; schema 3: analysis.columns and analysis.scale)")
        from scripts.protocol_v5 import analysis_plan  # Inside, as features/dataset.py imports scripts/ (no cycle).
        analysis = analysis_plan(protocol)
        scale, columns = analysis["scale"], analysis["columns"]
        if columns is None:
            if not diagnostic:
                raise ValueError("normalization rule: analysis.columns is null until G3a; production training needs "
                                 "the classes of the columns (diagnostic training takes the rule "
                                 f"{DIAGNOSTIC_RULE}, every column neural)")
            name, columns = DIAGNOSTIC_RULE, dict.fromkeys(GLOBAL_NAMES, "neural")
        else:
            name = ANALYSIS_RULE
        return cls(name, dict(columns), dict(scale["floor"]), scale["per_bin"], scale["min_bin_pages"],
                   dict(scale["local_floor"]))

    @property
    def tcn_names(self):
        """The global inputs of the TCN in the order of GLOBAL_NAMES: the columns of class neural or differenced."""
        return tuple(name for name in GLOBAL_NAMES if self.classes[name] in TCN_CLASSES)

    @property
    def rule_names(self):
        """The columns of the rule channel: class rule or rule_differenced."""
        return tuple(name for name in GLOBAL_NAMES if self.classes[name] in RULE_CLASSES)

    @property
    def anchored(self):
        """True when a TCN input is a first difference: a window then needs the measured row before it."""
        return "differenced" in self.classes.values()

    @property
    def floor_policy(self):
        return "machine_epsilon_to_one" if self.floor is None else "at_least_floor"

    def scale(self, deviation, name):
        """The scale of a column or a scaled per-bin value from its standard deviation over the fit rows."""
        floors = self.floor if name in GLOBAL_NAMES else self.local_floor
        if floors is None:
            return float(deviation) if deviation > np.finfo(np.float64).eps else 1.
        return max(float(deviation), floors[name])

    def split_bins(self, bins):
        """(scored, unscored) of a layout's bins [(bin, pages), ...] in their order: a bin of fewer than min_bin_pages
        pages is neither fitted nor scored; without a minimum (legacy_schema_2) every bin is scored. The predicate is
        features/snapshot.py counted_bin, the one the extractor's eight memory columns take (question Q10 to the
        lead, 2026-11-24), with the same boundary."""
        bins = tuple((int(b), int(pages)) for b, pages in bins)
        scored = tuple(b for b in bins if counted_bin(b[1], self.min_bin_pages))
        return scored, tuple(b for b in bins if b not in scored)

    def to_dict(self):
        return {"name": self.name, "note": RULE_NOTES[self.name], "classes": dict(self.classes),
                "floor": None if self.floor is None else dict(self.floor), "floor_policy": self.floor_policy,
                "per_bin": self.per_bin, "min_bin_pages": self.min_bin_pages,
                "local_floor": None if self.local_floor is None else dict(self.local_floor),
                "difference_policy": DIFFERENCE_POLICY}

    @classmethod
    def from_dict(cls, data):
        keys = ("name", "note", "classes", "floor", "floor_policy", "per_bin", "min_bin_pages", "local_floor",
                "difference_policy")
        if type(data) is not dict or set(data) != set(keys):
            raise ValueError("normalization rule: needs exactly the keys " + ", ".join(keys))
        rule = cls(data["name"], data["classes"], data["floor"], data["per_bin"], data["min_bin_pages"],
                   data["local_floor"])
        if (data["floor_policy"] != rule.floor_policy or type(data["note"]) is not str
                or data["difference_policy"] != DIFFERENCE_POLICY):
            raise ValueError(f"normalization rule {rule.name}: its floor policy or first difference differs from this "
                             "code")
        return rule


def _previous_rows(frames, global_values):
    """The raw global values of the last measured frame before each frame of `frames` in its session
    (DIFFERENCE_POLICY), and whether there is one; a frame without one gets its own values (first difference 0)."""
    previous, found = global_values.copy(), np.zeros(len(frames), dtype=bool)
    last, session = None, None
    for i, frame in enumerate(frames):
        if frame.session != session:
            last, session = None, frame.session
        if last is not None:
            previous[i], found[i] = global_values[last], True
        if frame.measured:
            last = i
    return previous, found


class FeatureNormalizer:
    """Fit once on the measured rows of train by a NormalizationRule (package B6b, design B6b 1.1).

    The global inputs of the TCN are rule.tcn_names (input_names): a neural column by its value, a differenced one by
    its first difference (DIFFERENCE_POLICY), each centred by its mean and divided by its scale over the fit rows (the
    standard deviation, at least the column's floor). The bins: a bin of fewer than min_bin_pages pages is neither
    fitted nor scored and leaves the inputs (`unscored`); every other bin (`bins`, in the contract's order) has its own
    scale (per_bin) or one pooled scale. Entropy is fitted only where the bin changed and stays 0 where it did not
    (none observed: mean 0, scale 1 or its floor); the mask has_changed is never normalized."""

    def __init__(self, rule, global_mean, global_scale, bins, unscored, local_mean, local_scale, fit_rows,
                 entropy_observations):
        if not isinstance(rule, NormalizationRule):
            raise ValueError("the normalizer needs its NormalizationRule")
        self.rule = rule
        self.input_names = rule.tcn_names
        self.global_mean = np.asarray(global_mean, dtype=np.float64)
        self.global_scale = np.asarray(global_scale, dtype=np.float64)
        self.local_mean = np.asarray(local_mean, dtype=np.float64)
        self.local_scale = np.asarray(local_scale, dtype=np.float64)
        self.fit_rows = _integer(fit_rows, "normalizer fit_rows", 1)
        self.entropy_observations = _integer(entropy_observations, "entropy_observations")
        try:
            self.bins = tuple((_integer(b, "bin identity"), _integer(p, "bin pages", 1)) for b, p in bins)
            self.unscored = tuple((_integer(b, "bin identity"), _integer(p, "bin pages", 1)) for b, p in unscored)
        except (TypeError, ValueError):
            raise ValueError("invalid normalizer bins: [[bin, pages], ...]") from None
        self.layout_bins = tuple(sorted(self.bins + self.unscored))
        if (not self.bins or len({b for b, _ in self.layout_bins}) != len(self.layout_bins)
                or rule.split_bins(self.layout_bins) != (self.bins, self.unscored)):
            raise ValueError(f"normalizer bins differ from rule {rule.name}: at least one scored bin, every bin once, a "
                             "bin of fewer than min_bin_pages pages never scored and every other bin scored")
        self.positions = [self.layout_bins.index(b) for b in self.bins]
        width, bins = len(self.input_names), len(self.bins)
        for name, shape in (("global_mean", (width,)), ("global_scale", (width,)),
                            ("local_mean", (bins, len(LOCAL_NAMES))), ("local_scale", (bins, len(LOCAL_NAMES)))):
            value = getattr(self, name)
            if value.shape != shape or not np.isfinite(value).all():
                raise ValueError("invalid normalizer " + name)
        if np.any(self.global_scale <= 0) or np.any(self.local_scale <= 0):
            raise ValueError("normalizer scales must be positive")
        if np.any(self.local_mean[:, 3] != 0) or np.any(self.local_scale[:, 3] != 1):
            raise ValueError("measurement mask must not be normalized")
        if rule.floor is not None and (
                np.any(self.global_scale < [rule.floor[name] for name in self.input_names])
                or np.any(self.local_scale[:, :3] < [rule.local_floor[name] for name in LOCAL_NAMES[:3]])):
            raise ValueError(f"normalizer scale below the floor of rule {rule.name}")
        if not rule.per_bin and (np.any(self.local_mean != self.local_mean[0])
                                 or np.any(self.local_scale != self.local_scale[0])):
            raise ValueError(f"rule {rule.name} has one pooled scale of the bins; the normalizer's bins differ")

    @classmethod
    def fit(cls, frames, rule):
        """Fit on `frames`, every measured row of each training session in order, by `rule`
        (NormalizationRule.from_protocol). A differenced column is fitted over the rows that have a measured row before
        them in their session (every row but the first of each session), as features/qualification.py judges it."""
        if not isinstance(rule, NormalizationRule):
            raise ValueError("normalization needs its rule: NormalizationRule.from_protocol(protocol, diagnostic=...)")
        frames = list(frames)
        if not frames:
            raise ValueError("no eligible training rows")
        seen, order = set(), {}
        for previous, frame in zip([None, *frames], frames):
            if not frame.measured:
                raise ValueError("normalization requires eligible training rows")
            identity = (frame.session, frame.seq)
            if identity in seen:
                raise ValueError("duplicate training row; do not fit overlapping windows")
            seen.add(identity)
            if frame.seq < order.get(frame.session, -1) or (
                    frame.session in order and previous.session != frame.session):
                raise ValueError("normalization rows come session by session in the order of seq (first differences)")
            order[frame.session] = frame.seq
        global_values, local_values = arrays(frames)
        bins, unscored = rule.split_bins(frames[0].layout["bins"])
        if not bins:
            raise ValueError(f"no bin of the layout has at least min_bin_pages {rule.min_bin_pages} pages: rule "
                             f"{rule.name} scores no bin")
        index = [GLOBAL_NAMES.index(name) for name in rule.tcn_names]
        inputs = global_values[:, index]
        global_mean, deviation = inputs.mean(axis=0), inputs.std(axis=0)
        differenced = [j for j, name in enumerate(rule.tcn_names) if rule.classes[name] == "differenced"]
        if differenced:
            previous, found = _previous_rows(frames, global_values)
            if not found.any():
                raise ValueError("no first difference to fit: every training session has one measured row")
            steps = (global_values - previous)[found][:, [index[j] for j in differenced]]
            global_mean[differenced], deviation[differenced] = steps.mean(axis=0), steps.std(axis=0)
        global_scale = np.array([rule.scale(d, name) for d, name in zip(deviation, rule.tcn_names)])
        positions = [[tuple(b) for b in frames[0].layout["bins"]].index(b) for b in bins]
        local = local_values[:, positions]
        if rule.per_bin:
            groups = [local[:, [b]] for b in range(len(bins))]
        else:
            groups = [local]
        local_mean, local_scale, observations = [], [], 0
        for group in groups:
            flat = group.reshape(-1, len(LOCAL_NAMES))
            mean, scale = np.zeros(len(LOCAL_NAMES)), np.ones(len(LOCAL_NAMES))
            mean[:2] = flat[:, :2].mean(axis=0)
            scale[:2] = [rule.scale(d, name) for d, name in zip(flat[:, :2].std(axis=0), LOCAL_NAMES[:2])]
            entropy = flat[flat[:, 3] == 1, 2]
            observations += len(entropy)
            if len(entropy):
                mean[2], scale[2] = entropy.mean(), rule.scale(entropy.std(), LOCAL_NAMES[2])
            elif rule.local_floor is not None:
                scale[2] = max(1., rule.local_floor[LOCAL_NAMES[2]])
            local_mean.append(mean)
            local_scale.append(scale)
        if not rule.per_bin:
            local_mean, local_scale = local_mean * len(bins), local_scale * len(bins)
        return cls(rule, global_mean, global_scale, bins, unscored, local_mean, local_scale, len(frames), observations)

    def transform(self, global_values, local_values, previous=None):
        """The normalized inputs of raw rows: global (..., 20) and per-bin (..., B, 4) over the contract's bins give
        (..., len(input_names)) and (..., len(bins), 4). `previous`: the raw global values of each row's last measured
        row before it (DIFFERENCE_POLICY), required exactly when a TCN input is differenced (inputs() gives it)."""
        global_values = np.asarray(global_values, dtype=np.float64)
        local_values = np.asarray(local_values, dtype=np.float64)
        if (global_values.ndim < 1 or global_values.shape[-1] != len(GLOBAL_NAMES)
                or local_values.shape[:-2] != global_values.shape[:-1]):
            raise ValueError("global/per-bin normalization axes mismatch")
        if local_values.ndim < 2 or local_values.shape[-2] != len(self.layout_bins):
            raise ValueError("per-bin axis differs from the normalizer's bins")
        if not np.isfinite(global_values).all():
            raise ValueError("non-finite global features")
        _local(local_values)
        index = [GLOBAL_NAMES.index(name) for name in self.input_names]
        inputs = global_values[..., index]
        if self.rule.anchored:
            if previous is None:
                raise ValueError(f"normalization rule {self.rule.name}: a differenced column needs the measured row "
                                 "before each row; use FeatureNormalizer.inputs(frames)")
            previous = np.asarray(previous, dtype=np.float64)
            if previous.shape != global_values.shape or not np.isfinite(previous).all():
                raise ValueError("previous rows differ in shape from the rows or are not finite")
            for j, name in enumerate(self.input_names):
                if self.rule.classes[name] == "differenced":
                    inputs[..., j] -= previous[..., index[j]]
        elif previous is not None:
            raise ValueError(f"normalization rule {self.rule.name} has no differenced column; previous rows are not an "
                             "input")
        global_result = (inputs - self.global_mean) / self.global_scale
        local = local_values[..., self.positions, :]
        local_result = (local - self.local_mean) / self.local_scale
        local_result[..., 2] = np.where(local[..., 3] == 1, local_result[..., 2], 0.)
        local_result[..., 3] = local[..., 3]
        if not np.isfinite(global_result).all() or not np.isfinite(local_result).all():
            raise ValueError("non-finite normalized features")
        return global_result, local_result

    def inputs(self, frames):
        """The normalized inputs (T, len(input_names)) and (T, len(bins), 4) of consecutive frames of one session
        (DIFFERENCE_POLICY: a differenced column against the last measured frame before it in `frames`; a frame
        without one gets 0 there, and an anchored WindowBuffer never lets it begin a window)."""
        frames = list(frames)
        global_values, local_values = arrays(frames)
        previous = _previous_rows(frames, global_values)[0] if self.rule.anchored else None
        return self.transform(global_values, local_values, previous)

    def check_contract(self, contract):
        """The normalizer's bins are the contract's bins with their pages."""
        if [list(b) for b in self.layout_bins] != contract["layout"]["bins"]:
            raise ValueError("normalizer bins differ from the feature contract's layout")

    def to_dict(self):
        return {"schema": NORMALIZER_SCHEMA, "rule": self.rule.to_dict(), "global_names": list(GLOBAL_NAMES),
                "input_names": list(self.input_names), "local_names": list(LOCAL_NAMES),
                "global_mean": self.global_mean.tolist(), "global_scale": self.global_scale.tolist(),
                "bins": [list(b) for b in self.bins], "unscored_bins": [list(b) for b in self.unscored],
                "local_mean": self.local_mean.tolist(), "local_scale": self.local_scale.tolist(),
                "fit_rows": self.fit_rows, "entropy_observations": self.entropy_observations,
                "entropy_policy": "fit_observed_only_missing_to_zero", "mask_policy": "identity"}

    @classmethod
    def from_dict(cls, data):
        if data.get("schema") in OLD_NORMALIZER_SCHEMAS:
            raise ValueError(f"normalizer of schema {data['schema']} (before package B6b: every column and one pooled "
                             "bin scale, no normalization rule) is refused; retrain under the rule of the protocol")
        if (data.get("schema") != NORMALIZER_SCHEMA or data.get("global_names") != list(GLOBAL_NAMES)
                or data.get("local_names") != list(LOCAL_NAMES)
                or data.get("entropy_policy") != "fit_observed_only_missing_to_zero"
                or data.get("mask_policy") != "identity"):
            raise ValueError("incompatible normalization schema/order/policy")
        rule = NormalizationRule.from_dict(data.get("rule"))
        if data.get("input_names") != list(rule.tcn_names):
            raise ValueError(f"normalizer inputs differ from the columns of class neural or differenced of rule "
                             f"{rule.name}")
        return cls(rule, *(data[name] for name in ("global_mean", "global_scale", "bins", "unscored_bins",
                                                   "local_mean", "local_scale", "fit_rows", "entropy_observations")))


def rule_quantity(rule, name):
    """What the rule channel judges of a column of rule.rule_names: its value (class rule) or its change since the
    session's first measured row (class rule_differenced, SESSION_START_POLICY); RULE_CLASSES."""
    return RULE_CLASSES[rule.classes[name]]


def _measured(frame):
    """A measured row (MEASURED_ROWS), from the flags alone (a row of any shape that has them)."""
    return frame.valid and not frame.full and frame.has_predecessor


def rule_channel(sessions, classes, *, k, n):
    """The rule channel of a bundle (skeleton B6 section 4, design B6b 1.3), the manifest's rule_channel: for every
    column of a class of RULE_CLASSES, the range [min, max] of the quantity it judges over the measured rows
    (MEASURED_ROWS) of the sessions of RULE_RANGE_ROLES: the value (class rule) or the change since the session's
    first measured row (class rule_differenced, SESSION_START_POLICY). `sessions` maps each role to [(record, frames)]
    (another role is not read), `classes` the 20 columns of GLOBAL_NAMES to their classes; k and n are the alarm rule
    of the neural channel (RULE_CHANNEL_RULE). `limitation` is SESSION_START_LIMITATION when a column of class
    rule_differenced exists, otherwise None (the lead's answer to question Q8)."""
    if type(k) is not int or type(n) is not int or not 1 <= k <= n:
        raise ValueError("rule channel: k and n are integers with 1 <= k <= n")
    ranges = {}
    for j, name in enumerate(GLOBAL_NAMES):
        quantity = RULE_CLASSES.get(classes[name])
        if quantity is None:
            continue
        values = []
        for role in RULE_RANGE_ROLES:
            for _, frames in sessions[role]:
                rows = np.array([float(frame.vector[j]) for frame in frames if _measured(frame)])
                values += (rows - rows[:1]).tolist() if quantity == "since_session_start" else rows.tolist()
        if not values:
            raise ValueError(f"rule channel: column {name} has no measured row in " + " and ".join(RULE_RANGE_ROLES))
        ranges[name] = {"quantity": quantity, "min": float(min(values)), "max": float(max(values)),
                        "rows": len(values)}
    differenced = any(classes[name] == "rule_differenced" for name in GLOBAL_NAMES)
    return {"columns": list(ranges), "ranges": ranges, "k": k, "n": n, "roles": list(RULE_RANGE_ROLES),
            "rows": MEASURED_ROWS, "rule": RULE_CHANNEL_RULE,
            "limitation": SESSION_START_LIMITATION if differenced else None}
