"""Host-side detection and replay using the same feature/model contract.

Original implementation for this project. An anomaly is not a malware verdict.
Kernel checks, missing evidence and model warmup remain separate in every row.

Channels (package B6b, the lead's skeleton B6 section 4, design B6b 1.3): the neural channel (the model's score
against the calibrated threshold, k of n; model_alarm, source model_anomaly), the rule channel (the value of a column
of class rule, the change since the session's first measured row of one of class rule_differenced, against their
ranges over train and calibration, k of n with its own history; rule_alarm, source rule_anomaly, never reported as
neural detection) and kernel_integrity (findings alarm on their own). Every row carries `channel`: the channels whose
alarm is up on this row.
"""
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time

import numpy as np

from .features import GLOBAL_NAMES, WindowBuffer, check_frame, frame_from_snapshot, frames_from_archive


SCHEMA = "hyptcn3/safeguard-events/1"
CHANNELS = ("rule", "neural", "kernel_integrity")  # The values of a row's `channel`, in this order.
SOURCES = ("model_anomaly", "rule_anomaly", "kernel_integrity")  # alarm_sources: the rising edge of each channel.
_POLL_SECONDS = 0.2
_INCOMPLETE_GRACE = 15.0
_SEQUENCE = re.compile(r"_(\d+)_")


def _json(value):
    """Reject nonfinite output, including numpy values supplied by a model."""
    def convert(item):
        if isinstance(item, np.ndarray):
            return item.tolist()
        if isinstance(item, np.generic):
            return item.item()
        if isinstance(item, Path):
            return str(item)
        raise TypeError("not JSON serializable: " + type(item).__name__)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, default=convert)


def _atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        output.write(_json(value) + "\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


@contextmanager
def _failure_status(output, summary):
    """Leave an honest stopped status even when the supervisor interrupts us."""
    try:
        yield
    except BaseException as exc:
        interrupted = isinstance(exc, (KeyboardInterrupt, SystemExit))
        summary.update(running=False, ok=False, state="input_error",
                       stop_reason="interrupted" if interrupted else "runtime_error",
                       fatal=not interrupted, error=type(exc).__name__ + ": " + str(exc))
        _atomic_json(output / "status.json", summary)
        raise


def _integrity(frame):
    quality = frame.quality
    findings = quality.get("findings", [])
    inconclusive = list(quality.get("inconclusive", []))
    if "findings" not in quality or "inconclusive" not in quality:
        inconclusive.append("integrity_not_recorded")
    if quality.get("read_errors") or quality.get("filled_zero"):
        inconclusive.append("memory_read_errors")
    if not quality.get("traversals_complete", False):
        inconclusive.append("object_traversals_incomplete")
    return {
        "status": "findings" if findings else ("inconclusive" if inconclusive else "no_findings"),
        "findings": findings,
        # Cross-view differences seen in this snapshot only (no alarm).
        "unconfirmed": list(quality.get("unconfirmed_findings", [])),
        "inconclusive": sorted(set(inconclusive)),
        "conclusive": not bool(inconclusive),
    }


class RuleChannel:
    """The rule channel (design B6b 1.3, RULE_CHANNEL_RULE of safeguard/features.py) of a bundle's rule_channel:
    {columns, quantity {column: "value" | "since_session_start"}, ranges {column: [low, high]}, k, n}. Every measured
    row is judged, from the first row after a barrier: the neural warmup does not hold it back. A column of quantity
    since_session_start is judged by its value minus that of the session's first measured row (question Q8, the
    revised proposal accepted by the lead 2026-11-24), which the channel keeps for the session across resets; the
    history is cleared where the neural channel's is (barriers, discontinuities, input errors). The session's first
    measured row here is the first one this detector sees, so a state already present in it is never seen
    (SESSION_START_LIMITATION of safeguard/features.py, which the manifest states)."""

    def __init__(self, spec):
        if type(spec) is not dict or {"columns", "quantity", "ranges", "k", "n"} - set(spec):
            raise ValueError("bundle rule channel needs columns, quantity, ranges, k and n")
        columns, quantity, ranges, self.k, self.n = (spec[key] for key in ("columns", "quantity", "ranges", "k", "n"))
        if (type(columns) is not list or len(set(columns)) != len(columns) or any(c not in GLOBAL_NAMES for c in columns)
                or type(quantity) is not dict or type(ranges) is not dict or set(quantity) != set(columns)
                or set(ranges) != set(columns) or any(quantity[c] not in ("value", "since_session_start")
                                                      for c in columns)
                or any(type(ranges[c]) not in (list, tuple) or len(ranges[c]) != 2 or not all(
                    isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in ranges[c])
                    or ranges[c][0] > ranges[c][1] for c in columns)
                or type(self.k) is not int or type(self.n) is not int or not 1 <= self.k <= self.n):
            raise ValueError("invalid bundle rule channel")
        self.columns = [(name, GLOBAL_NAMES.index(name), quantity[name], tuple(map(float, ranges[name])))
                        for name in columns]
        self.history = deque(maxlen=self.n)
        self.session, self.start = None, None  # The session and its first measured row.

    def clear(self):
        self.history.clear()

    def judge(self, frame, reason):
        """{rule_alarm, rule} of one row; `reason` says why a row that is not measured is not judged."""
        if frame.session != self.session:
            self.session, self.start = frame.session, None
        if not self.columns:
            return {"rule_alarm": False, "rule": {"state": "no_columns", "reason": "the rule channel has no column",
                                                  "exceeded": [], "vote_count": 0}}
        if not frame.measured:
            return {"rule_alarm": False, "rule": {"state": "not_judged", "reason": reason, "exceeded": [],
                                                  "vote_count": len(self.history)}}
        if self.start is None:
            self.start = frame
        exceeded = []
        for name, j, quantity, (low, high) in self.columns:
            value = float(frame.vector[j] - self.start.vector[j] if quantity == "since_session_start"
                          else frame.vector[j])
            if not low <= value <= high:
                exceeded.append({"column": name, "quantity": quantity, "value": value, "range": [low, high]})
        self.history.append(bool(exceeded))
        alarm = len(self.history) == self.n and sum(self.history) >= self.k
        return {"rule_alarm": alarm, "rule": {"state": "judged", "reason": None, "exceeded": exceeded,
                                              "vote_count": len(self.history)}}


class Detector:
    """Stateful processor; fatal contract/model errors require a new instance.

    Full snapshots and missing predecessors are warmup barriers. Invalid input
    and time/sequence discontinuities reset the model and its k-of-n history,
    and the rule channel's history with it.
    Integrity findings are emitted even when a model window is unavailable.
    Under a normalization rule with a differenced input (bundle.anchored) a
    window also needs the measured row before it: required_rows is window_rows + 1.
    """

    def __init__(self, bundle, raw_dir=None,
                 hold_binary="vmicollect/build/vmicollect", preserve=True):
        self.bundle = bundle
        self.window_rows = int(bundle.contract["window_rows"])
        self.max_gap_s = float(bundle.contract["max_gap_s"])
        self.k, self.n = int(bundle.k), int(bundle.n)
        self.threshold = float(bundle.threshold)
        if not 1 <= self.k <= self.n or not math.isfinite(self.threshold) or self.threshold < 0:
            raise ValueError("invalid calibrated threshold or k/n rule")
        self.anchored = bundle.anchored
        if type(self.anchored) is not bool:
            raise ValueError("bundle must state whether a window needs the measured row before it (anchored)")
        self.required_rows = self.window_rows + int(self.anchored)
        self.rules = RuleChannel(bundle.rule_channel)
        if (self.rules.k, self.rules.n) != (self.k, self.n):
            raise ValueError("the rule channel's k of n differs from the neural channel's")
        self.buffer = WindowBuffer(self.window_rows, self.max_gap_s, anchored=self.anchored)
        self.history = deque(maxlen=self.n)
        # The n voting windows overlap; this is their full input context.
        self.context = deque(maxlen=self.required_rows + self.n - 1)
        self.raw_dir = Path(raw_dir) if raw_dir is not None else None
        self.hold_binary = str(hold_binary)
        self.preserve = bool(preserve)
        self.held = set()
        self.event_count = 0
        self.model_active = False
        self.rule_active = False
        self.integrity_active = False
        self.fatal = False
        self.last = None

    def _reset(self):
        self.buffer = WindowBuffer(self.window_rows, self.max_gap_s, anchored=self.anchored)
        self.history.clear()
        self.rules.clear()
        self.model_active = self.rule_active = self.integrity_active = False
        self.last = None

    def input_error(self, seq, reason):
        self._reset()
        return {
            "schema": SCHEMA, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "seq": seq, "state": "input_error", "model_state": "input_error",
            "reason": str(reason), "fatal": self.fatal, "recoverable": not self.fatal,
            "diagnostic": bool(self.bundle.manifest.get("calibration", {}).get("diagnostic", False)),
            "alarm": False, "alarm_event": False, "alarm_sources": [], "channel": [],
            "model_alarm": False, "rule_alarm": False,
            "rule": {"state": "not_judged", "reason": "input_error", "exceeded": [], "vote_count": 0},
            "integrity_alarm": False, "score": None,
            "integrity": {"status": "inconclusive", "conclusive": False,
                          "findings": [], "unconfirmed": [], "inconclusive": ["input_error"]},
            "evidence": {"status": "not_requested", "chain_ids": [], "error": None},
        }

    def _hold(self):
        chains = sorted({str(frame.chain_id) for frame in self.context})
        evidence = {"status": "disabled" if not self.preserve else "held",
                    "chain_ids": chains, "held_chain_ids": sorted(self.held), "error": None}
        if not self.preserve:
            return evidence
        new = sorted(set(chains) - self.held)
        if not new:
            return evidence
        if self.raw_dir is None:
            evidence.update(status="error", error="raw directory required for evidence HOLD")
            return evidence
        try:
            result = subprocess.run([self.hold_binary, "hold", str(self.raw_dir), *new],
                                    capture_output=True, text=True, timeout=30, check=False)
            evidence["returncode"] = result.returncode
            if result.returncode != 0:
                evidence.update(status="error", error=result.stderr.strip() or
                                result.stdout.strip() or "vmicollect HOLD failed")
            else:
                self.held.update(new)
        except (OSError, subprocess.TimeoutExpired) as exc:
            evidence.update(status="error", error=str(exc))
        evidence["held_chain_ids"] = sorted(self.held)
        return evidence

    def process(self, frame):
        if self.fatal:
            raise RuntimeError("detector stopped after a fatal model/feature-contract error")
        started = time.monotonic()
        if self.context and frame.session != self.context[-1].session:
            self.context.clear()
            self.integrity_active = False
        integrity = _integrity(frame)
        try:
            check_frame(frame, self.bundle.contract)
        except (TypeError, ValueError, KeyError) as exc:
            self.fatal = True
            row = self.input_error(frame.seq, "feature_contract_mismatch: " + str(exc))
            row.update(integrity=integrity, session=frame.session,
                       timestamp=frame.timestamp, chain_id=str(frame.chain_id))
            return self._finish(row, frame, started)

        try:
            window = self.buffer.push(frame)
        except ValueError as exc:
            row = self.input_error(frame.seq, "frame_order: " + str(exc))
            # Order errors discard this row. The next row may begin a fresh
            # window, without inheriting an incorrect predecessor.
            row.update(integrity=integrity, session=frame.session,
                       timestamp=frame.timestamp, chain_id=str(frame.chain_id))
            return self._finish(row, frame, started)
        if self.buffer.reset:
            self.history.clear()
            self.rules.clear()
            self.model_active = self.rule_active = False
        self.context.append(frame)
        self.last = frame
        model_state = "input_error" if not frame.valid else "warming_up"
        row = {
            "schema": SCHEMA, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "session": frame.session, "seq": frame.seq, "timestamp": frame.timestamp,
            "chain_id": str(frame.chain_id), "state": model_state, "model_state": model_state,
            "reason": self.buffer.reason, "fatal": False, "recoverable": True,
            "window_rows": len(self.buffer.rows), "required_rows": self.required_rows,
            "threshold": self.threshold, "k": self.k, "n": self.n,
            "score": None, "model_alarm": False, "integrity": integrity,
            "quality": frame.quality,
        }
        row.update(self.rules.judge(frame, self.buffer.reason))
        if window is not None:
            try:
                score = self.bundle.score(window)
                if not isinstance(score, dict) or not math.isfinite(float(score["score"])):
                    raise ValueError("model returned an invalid score")
                _json(score)  # No silent NaN in auxiliary scores/probabilities.
                shadowed = sorted((set(score) - {"score"}) & set(row))
                if shadowed:  # A model output never overwrites a field of the row.
                    raise ValueError("model output would overwrite row fields: " + ", ".join(shadowed))
                self.history.append(float(score["score"]))
                row.update(model_state="monitoring", reason="scored", **score)
                row["model_alarm"] = len(self.history) == self.n and sum(
                    item > self.threshold for item in self.history) >= self.k
            except (ValueError, TypeError, KeyError, RuntimeError) as exc:
                self.fatal = True
                row = self.input_error(frame.seq, "model_error: " + str(exc))
                row.update(integrity=integrity, session=frame.session,
                           timestamp=frame.timestamp, chain_id=str(frame.chain_id))
        return self._finish(row, frame, started)

    def _finish(self, row, frame, started):
        integrity_alarm = bool(row["integrity"]["findings"])
        model_alarm = bool(row.get("model_alarm", False))
        rule_alarm = bool(row.get("rule_alarm", False))
        up = {"model_anomaly": model_alarm, "rule_anomaly": rule_alarm, "kernel_integrity": integrity_alarm}
        active = {"model_anomaly": self.model_active, "rule_anomaly": self.rule_active,
                  "kernel_integrity": self.integrity_active}
        sources = [source for source in SOURCES if up[source] and not active[source]]
        alarm = model_alarm or rule_alarm or integrity_alarm
        self.model_active, self.rule_active, self.integrity_active = model_alarm, rule_alarm, integrity_alarm
        row.update(alarm=alarm, alarm_event=bool(sources), alarm_sources=sources,
                   integrity_alarm=integrity_alarm, rule_alarm=rule_alarm,
                   channel=[name for name, on in zip(CHANNELS, (rule_alarm, model_alarm, integrity_alarm)) if on],
                   state="alarm" if alarm else row["model_state"],
                   vote_count=len(self.history), rule_vote_count=len(self.rules.history))
        if sources:
            self.event_count += 1
            row["event_number"] = self.event_count
        if alarm:
            if not self.context or self.context[-1] is not frame:
                self.context.append(frame)
            row["evidence"] = self._hold()
        else:
            row["evidence"] = {"status": "not_requested", "chain_ids": [], "error": None}
        row["processing_ms"] = (time.monotonic() - started) * 1000
        row["diagnostic"] = bool(self.bundle.manifest.get("calibration", {}).get("diagnostic", False))
        # Snapshot wall-clock age is also backlog/replay age, not processing
        # latency. It is intentionally named separately.
        row["snapshot_age_ms"] = ((time.time() - frame.timestamp) * 1000
                                  if math.isfinite(frame.timestamp) else None)
        return row


def replay_archive(bundle, archive_path, session_id=None):
    """Feature replay never modifies raw evidence or performs a reaction.

    The seal comes first (package B7c, tcn/pecat.py GUARD_RULE): a sealed archive of a campaign is refused by name
    (tcn.pecat.Zapecatene, a ValueError) outside the final run that consumed its seal, before it is opened."""
    from tcn import pecat
    pecat.kontrola(archive_path, purpose="safeguard.runtime.replay_archive")
    detector = Detector(bundle, preserve=False)
    with np.load(archive_path, allow_pickle=False) as data:
        frames = frames_from_archive(data, session_id or Path(archive_path).stem)
    rows = []
    for frame in frames:
        row = detector.process(frame)
        rows.append(row)
        if row.get("fatal"):
            break
    return rows


# Proposal 6.4 and 10.2 (G1, "vložené neskórované úseky"): an unscored stretch is in the output as unevaluated, never
# as silence (package B7c; the same word as tcn/metody.py UNEVALUATED).
UNEVALUATED = "nevyhodnotené"
UNSCORED_RULE = (
    "a row is unscored when the detector gave it no score (score null: warming up at the session start or after a "
    "full snapshot, a row without a predecessor, an invalid row, a discontinuity, an input error); a stretch is a run "
    "of unscored rows of one session in replay order with consecutive seq; every stretch is reported nevyhodnotené "
    "with the reasons of its rows (proposal 6.4: the unscored time of every session is reported; proposal 10.2: an "
    "unscored stretch is in the output as nevyhodnotené, not as silence); its time is one interval_s per row (as "
    "tcn/metody.py OBSERVED_RULE counts the observed time); interval_s is the bundle protocol's, and without one the "
    "seconds are null")


def unscored(rows, interval_s):
    """The unscored stretches of the rows of a replay (UNSCORED_RULE): {rule, status, rows, seconds, share,
    stretches: [{session, first_seq, last_seq, rows, seconds, first_unix, last_unix, reasons {reason: rows},
    status}]}. interval_s: the bundle protocol's interval, or None (seconds null)."""
    if interval_s is not None and (isinstance(interval_s, bool) or not isinstance(interval_s, (int, float))
                                   or not math.isfinite(interval_s) or interval_s <= 0):
        raise ValueError("interval_s is a positive number or None")
    stretches, current = [], None
    for row in rows:
        if row.get("score") is not None:
            current = None
            continue
        session, seq = row.get("session"), row.get("seq")
        if current is None or current["session"] != session or seq != current["last_seq"] + 1:
            current = {"session": session, "first_seq": seq, "last_seq": seq, "rows": 0,
                       "first_unix": row.get("timestamp"), "last_unix": row.get("timestamp"), "reasons": {},
                       "status": UNEVALUATED}
            stretches.append(current)
        reason = str(row.get("reason") or row.get("model_state"))
        current["reasons"][reason] = current["reasons"].get(reason, 0) + 1
        current.update(last_seq=seq, last_unix=row.get("timestamp"), rows=current["rows"] + 1)
    for stretch in stretches:
        stretch["seconds"] = None if interval_s is None else stretch["rows"] * float(interval_s)
    total = sum(s["rows"] for s in stretches)
    return {"rule": UNSCORED_RULE, "status": UNEVALUATED, "rows": total,
            "seconds": None if interval_s is None else total * float(interval_s),
            "share": total / len(rows) if rows else None, "stretches": stretches}


def _candidate_files(directory):
    """Only collector snapshots; capture/traffic/status JSON are not inputs."""
    candidates = {p.with_suffix(".json") for p in directory.glob("*.vmicd")}
    for path in directory.glob("*.json"):
        if _SEQUENCE.search(path.stem):
            candidates.add(path)
    return sorted(candidates)


def _sequence_hint(path):
    match = _SEQUENCE.search(path.stem)
    return int(match.group(1)) if match else None


def run_directory(bundle, snapshots, profile, output_dir, *, follow=False,
                  idle_timeout=None, stop_event=None, preserve=True,
                  hold_binary="vmicollect/build/vmicollect"):
    """Process each snapshot once and write a new auditable run directory.

    A following reader retries partially written sidecars for a bounded grace
    period. A finite replay reports them immediately. Duplicate sequences are
    input errors; they are never silently scored twice. ``follow=True`` without
    idle_timeout follows indefinitely until stop_event is set.

    The seal comes first (package B7c, tcn/pecat.py SNAPSHOT_RULE): the snapshots of a session that the ledger seals
    for a campaign (by the session_id of the session.json of the directory or of its parent) are refused by name
    (tcn.pecat.Zapecatene, a ValueError) outside the final run that consumed its archive, before anything is written;
    the decision is in configuration.json and status.json (a rehearsal's session carries the rehearsal mark).

    Every frame is extracted from the bins the bundle scores (question Q10 to the lead, 2026-11-24): its eight memory
    columns come from the bins of at least bundle.min_bin_pages pages (None under legacy_schema_2: every bin), as the
    audit extracted the archives the bundle was trained on.
    """
    if idle_timeout is not None and (not math.isfinite(idle_timeout) or idle_timeout <= 0):
        raise ValueError("idle_timeout must be finite and positive")
    directory = Path(snapshots)
    if not directory.is_dir():
        raise ValueError("snapshot directory does not exist: " + str(directory))
    from tcn import pecat
    seal = pecat.kontrola_snimok(directory, purpose="safeguard.runtime.run_directory")
    min_bin_pages = bundle.min_bin_pages  # After the seal: a refused directory never reads its bundle.
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    (output / "evidence").mkdir()
    with (output / "configuration.json").open("x", encoding="utf-8") as configuration:
        configuration.write(_json({
            "created_at": datetime.now(timezone.utc).isoformat(),
            "bundle_manifest": bundle.manifest, "snapshots": str(directory.resolve()),
            "profile": str(Path(profile).resolve()), "preserve": bool(preserve),
            "hold_binary": str(hold_binary), "follow": bool(follow), "idle_timeout": idle_timeout, "seal": seal,
        }) + "\n")
    detector = Detector(bundle, directory, hold_binary, preserve)
    seen_paths, seen_seq, pending = set(), set(), {}
    previous = None
    last_activity = time.monotonic()
    summary = {"schema": "hyptcn3/safeguard-run/1", "state": "warming_up",
               "running": True, "processed": 0, "scored": 0, "input_errors": 0,
               "alarm_events": 0, "alarm_events_by_source": dict.fromkeys(SOURCES, 0),
               "evidence_errors": 0, "pending": 0, "backlog": 0,
               "snapshots": str(directory.resolve()), "output": str(output.resolve()),
               "stop_reason": None, "fatal": False, "last": None,
               "diagnostic": bool(bundle.manifest.get("calibration", {}).get("diagnostic", False)),
               "seal": {key: seal[key] for key in ("allowed", "session", "stage", "rehearsal", "mark", "identity")}}

    def emit(row, stream):
        stream.write(_json(row) + "\n")
        stream.flush()
        summary["processed"] += 1
        summary["scored"] += row.get("score") is not None
        summary["input_errors"] += row["model_state"] == "input_error"
        summary["alarm_events"] += bool(row["alarm_event"])
        for source in row.get("alarm_sources", []):
            summary["alarm_events_by_source"][source] += 1
        summary["evidence_errors"] += row["evidence"]["status"] == "error"
        summary.update(state=row["state"], last=row, fatal=row["fatal"])
        if row["alarm_event"]:
            evidence_file = output / "evidence" / ("event-%06d.json" % summary["alarm_events"])
            with evidence_file.open("x", encoding="utf-8") as evidence:
                evidence.write(_json(row) + "\n")
        _atomic_json(output / "status.json", summary)

    _atomic_json(output / "status.json", summary)
    with _failure_status(output, summary), (output / "events.jsonl").open("x", encoding="utf-8") as stream:
        while True:
            stopping = stop_event is not None and stop_event.is_set()
            timed_out = (idle_timeout is not None and
                         time.monotonic() - last_activity >= idle_timeout)
            ready, failures = [], []
            candidates = [p for p in _candidate_files(directory) if p.name not in seen_paths]
            summary["backlog"] = len(candidates)
            for path in candidates:
                try:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(document, dict):
                        raise ValueError("collector sidecar must be a JSON object")
                    if document.get("schema") != "vmicollect/1":
                        raise ValueError("unsupported collector sidecar schema")
                    seq, timestamp = document["seq"], document["timestamp_unix"]
                    if (type(seq) is not int or seq < 0 or isinstance(timestamp, bool)
                            or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp)):
                        raise ValueError("invalid sequence or timestamp")
                    if not path.with_suffix(".vmicd").is_file():
                        raise FileNotFoundError("snapshot file missing for " + path.name)
                    ready.append((seq, path, document))
                    pending.pop(path.name, None)
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    first = pending.setdefault(path.name, time.monotonic())
                    incomplete = isinstance(exc, (OSError, json.JSONDecodeError))
                    if (follow and incomplete and not stopping and not timed_out
                            and time.monotonic() - first < _INCOMPLETE_GRACE):
                        continue
                    failures.append((_sequence_hint(path), path, str(exc)))
            # Do not overtake an incomplete predecessor whose filename gives
            # a sequence. Once its grace expires it becomes an explicit error.
            waiting_seq = [_sequence_hint(p) for p in candidates if p.name in pending
                           and not any(f[1] == p for f in failures)]
            waiting_seq = [seq for seq in waiting_seq if seq is not None]
            if waiting_seq:
                ready = [item for item in ready if item[0] < min(waiting_seq)]
            summary["pending"] = len(pending)
            items = [(seq, path, doc, None) for seq, path, doc in ready]
            items += [(seq, path, None, error) for seq, path, error in failures]
            items.sort(key=lambda item: (item[0] is None, item[0] or 0, item[1].name))
            counts = {}
            for seq, _, _, _ in items:
                if seq is not None:
                    counts[seq] = counts.get(seq, 0) + 1
            duplicate_reported = set()
            for seq, path, document, error in items:
                seen_paths.add(path.name)
                pending.pop(path.name, None)
                last_activity = time.monotonic()
                if seq is not None and (seq in seen_seq or counts[seq] > 1):
                    previous = None
                    if seq in duplicate_reported:
                        continue
                    duplicate_reported.add(seq)
                    row = detector.input_error(seq, "duplicate snapshot sequence: " + str(seq))
                elif seq is not None and seen_seq and seq < max(seen_seq):
                    previous = None
                    row = detector.input_error(seq, "late out-of-order snapshot sequence: " + str(seq))
                elif error is not None:
                    previous = None
                    row = detector.input_error(seq, error)
                else:
                    started = time.monotonic()
                    try:
                        frame, state = frame_from_snapshot(
                            directory, profile, seq, previous=previous,
                            session_id=directory.name, max_gap_s=detector.max_gap_s,
                            min_bin_pages=min_bin_pages)
                        extracted = time.monotonic()
                        row = detector.process(frame)
                        row["detector_processing_ms"] = row["processing_ms"]
                        row["extraction_ms"] = (extracted - started) * 1000
                        row["processing_ms"] = (time.monotonic() - started) * 1000
                        previous = state if frame.valid and row["model_state"] != "input_error" else None
                    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
                        previous = None
                        row = detector.input_error(seq, "snapshot_extraction: " + str(exc))
                if seq is not None:
                    seen_seq.add(seq)
                summary["backlog"] = max(0, summary["backlog"] - 1)
                summary["pending"] = len(pending)
                row["sidecar"] = str(path)
                emit(row, stream)
                if row["fatal"]:
                    break
            if summary["fatal"]:
                summary["stop_reason"] = "fatal_error"
                break
            if stopping or timed_out or not follow:
                summary["stop_reason"] = "stop_requested" if stopping else (
                    "idle_timeout" if timed_out else "replay_complete")
                break
            _atomic_json(output / "status.json", summary)
            if stop_event is not None:
                stop_event.wait(_POLL_SECONDS)
            else:
                time.sleep(_POLL_SECONDS)
        if not summary["processed"]:
            emit(detector.input_error(None, "no snapshots were processed"), stream)
            summary["stop_reason"] = "empty_input"
    summary["running"] = False
    summary["pending"] = len(pending)
    summary["backlog"] = len([p for p in _candidate_files(directory) if p.name not in seen_paths])
    summary["ok"] = not (summary["input_errors"] or summary["evidence_errors"] or summary["fatal"])
    _atomic_json(output / "status.json", summary)
    return summary
