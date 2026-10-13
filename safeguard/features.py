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
from features.snapshot import MENA, SCHEMA, _vsetky_hlavicky, sidecar_cesta, vektor_snimky
from features.windows import BIN_PRIZNAKY, perbin_zo_sidecaru
from features.quality import BEHAVIOR_POLICY


CONTRACT_SCHEMA = "hyptcn3/safeguard-features/2"
NORMALIZER_SCHEMA = "hyptcn3/safeguard-normalizer/1"
GLOBAL_NAMES = tuple(BEHAVIOR_NAMES)
LOCAL_NAMES = tuple(BIN_PRIZNAKY)


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


def frame_from_snapshot(raw_dir, profile, seq, previous=None, session_id=None, *, max_gap_s=7.5):
    """Extract one raw frame using the same semantic parser as archive creation."""
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
        elif (seq != meta["seq"] + 1 or timestamp - meta["timestamp"] > gap
              or not previous["quality"]["behavior_valid"]):
            previous = None
    vector, state, notes = vektor_snimky(raw_dir, str(profile), seq, previous)
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
    """Ordered temporal eligibility rules shared by every model consumer."""
    def __init__(self, window_rows, max_gap_s=7.5):
        self.window_rows, self.max_gap_s = _temporal(window_rows, max_gap_s)
        self.rows = deque(maxlen=self.window_rows)
        self.last = None
        self.layout = None
        self.biny = None
        self.reason = "warmup"
        self.reset = False

    def discontinuity(self, frame):
        return self.last is not None and (
            frame.session != self.last.session or frame.seq != self.last.seq + 1
            or frame.chain_id != self.last.chain_id
            or not 0 < frame.timestamp - self.last.timestamp <= self.max_gap_s
            or frame.layout != self.last.layout or frame.biny != self.last.biny)

    def _reject(self, reason):
        self.rows.clear()
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
        self.reset = self.discontinuity(frame)
        if self.reset:
            self.rows.clear()
        self.last = frame
        self.layout, self.biny = frame.layout, frame.biny
        if not frame.valid or frame.full or not frame.has_predecessor:
            self.rows.clear()
            self.reset = True
            self.reason = ("invalid_input" if not frame.valid else "full_snapshot"
                           if frame.full else "no_predecessor")
            return None
        self.rows.append(frame)
        self.reason = "warmup"
        if len(self.rows) < self.window_rows:
            return None
        self.reason = "ready"
        return list(self.rows)


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


class FeatureNormalizer:
    """Fit rows once; pool bins, keeping unobserved entropy and its mask separate."""
    def __init__(self, global_mean, global_scale, local_mean, local_scale,
                 fit_rows, entropy_observations):
        self.global_mean = np.asarray(global_mean, dtype=np.float64)
        self.global_scale = np.asarray(global_scale, dtype=np.float64)
        self.local_mean = np.asarray(local_mean, dtype=np.float64)
        self.local_scale = np.asarray(local_scale, dtype=np.float64)
        self.fit_rows = _integer(fit_rows, "normalizer fit_rows", 1)
        self.entropy_observations = _integer(entropy_observations, "entropy_observations")
        for name, length in (("global_mean", len(GLOBAL_NAMES)), ("global_scale", len(GLOBAL_NAMES)),
                             ("local_mean", len(LOCAL_NAMES)), ("local_scale", len(LOCAL_NAMES))):
            value = getattr(self, name)
            if value.shape != (length,) or not np.isfinite(value).all():
                raise ValueError("invalid normalizer " + name)
        if np.any(self.global_scale <= 0) or np.any(self.local_scale <= 0):
            raise ValueError("normalizer scales must be positive")
        if self.local_mean[3] != 0 or self.local_scale[3] != 1:
            raise ValueError("measurement mask must not be normalized")

    @classmethod
    def fit(cls, frames):
        frames = list(frames)
        if not frames:
            raise ValueError("no eligible training rows")
        seen = set()
        for frame in frames:
            if not frame.valid or frame.full or not frame.has_predecessor:
                raise ValueError("normalization requires eligible training rows")
            identity = (frame.session, frame.seq)
            if identity in seen:
                raise ValueError("duplicate training row; do not fit overlapping windows")
            seen.add(identity)
        global_values, local_values = arrays(frames)
        global_mean = global_values.mean(axis=0)
        global_scale = global_values.std(axis=0)
        local_flat = local_values.reshape(-1, len(LOCAL_NAMES))
        local_mean, local_scale = np.zeros(len(LOCAL_NAMES)), np.ones(len(LOCAL_NAMES))
        local_mean[:2] = local_flat[:, :2].mean(axis=0)
        local_scale[:2] = local_flat[:, :2].std(axis=0)
        entropy = local_flat[local_flat[:, 3] == 1, 2]
        if len(entropy):
            local_mean[2], local_scale[2] = entropy.mean(), entropy.std()
        global_scale[global_scale <= np.finfo(np.float64).eps] = 1.
        local_scale[local_scale <= np.finfo(np.float64).eps] = 1.
        return cls(global_mean, global_scale, local_mean, local_scale, len(frames), len(entropy))

    def transform(self, global_values, local_values):
        global_values = np.asarray(global_values, dtype=np.float64)
        local_values = np.asarray(local_values, dtype=np.float64)
        if (global_values.ndim < 1 or global_values.shape[-1] != len(GLOBAL_NAMES)
                or local_values.shape[:-2] != global_values.shape[:-1]):
            raise ValueError("global/per-bin normalization axes mismatch")
        if not np.isfinite(global_values).all():
            raise ValueError("non-finite global features")
        _local(local_values)
        global_result = (global_values - self.global_mean) / self.global_scale
        local_result = (local_values - self.local_mean) / self.local_scale
        local_result[..., 2] = np.where(local_values[..., 3] == 1, local_result[..., 2], 0.)
        local_result[..., 3] = local_values[..., 3]
        if not np.isfinite(global_result).all() or not np.isfinite(local_result).all():
            raise ValueError("non-finite normalized features")
        return global_result, local_result

    def to_dict(self):
        return {"schema": NORMALIZER_SCHEMA, "global_names": list(GLOBAL_NAMES),
                "local_names": list(LOCAL_NAMES), "global_mean": self.global_mean.tolist(),
                "global_scale": self.global_scale.tolist(), "local_mean": self.local_mean.tolist(),
                "local_scale": self.local_scale.tolist(), "fit_rows": self.fit_rows,
                "entropy_observations": self.entropy_observations,
                "entropy_policy": "fit_observed_only_missing_to_zero", "mask_policy": "identity"}

    @classmethod
    def from_dict(cls, data):
        if (data.get("schema") != NORMALIZER_SCHEMA or data.get("global_names") != list(GLOBAL_NAMES)
                or data.get("local_names") != list(LOCAL_NAMES)
                or data.get("entropy_policy") != "fit_observed_only_missing_to_zero"
                or data.get("mask_policy") != "identity"):
            raise ValueError("incompatible normalization schema/order/policy")
        return cls(*(data[name] for name in ("global_mean", "global_scale", "local_mean", "local_scale",
                                            "fit_rows", "entropy_observations")))
