"""Host-side detection and replay using the same feature/model contract.

Original implementation for this project. An anomaly is not a malware verdict.
Kernel checks, missing evidence and model warmup remain separate in every row.
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

from .features import WindowBuffer, check_frame, frame_from_snapshot, frames_from_archive


SCHEMA = "hyptcn3/safeguard-events/1"
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
        "inconclusive": sorted(set(inconclusive)),
        "conclusive": not bool(inconclusive),
    }


class Detector:
    """Stateful processor; fatal contract/model errors require a new instance.

    Full snapshots and missing predecessors are warmup barriers. Invalid input
    and time/sequence discontinuities reset the model and its k-of-n history.
    Integrity findings are emitted even when a model window is unavailable.
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
        self.buffer = WindowBuffer(self.window_rows, self.max_gap_s)
        self.history = deque(maxlen=self.n)
        # The n voting windows overlap; this is their full input context.
        self.context = deque(maxlen=self.window_rows + self.n - 1)
        self.raw_dir = Path(raw_dir) if raw_dir is not None else None
        self.hold_binary = str(hold_binary)
        self.preserve = bool(preserve)
        self.held = set()
        self.event_count = 0
        self.model_active = False
        self.integrity_active = False
        self.fatal = False
        self.last = None

    def _reset(self):
        self.buffer = WindowBuffer(self.window_rows, self.max_gap_s)
        self.history.clear()
        self.model_active = self.integrity_active = False
        self.last = None

    def input_error(self, seq, reason):
        self._reset()
        return {
            "schema": SCHEMA, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "seq": seq, "state": "input_error", "model_state": "input_error",
            "reason": str(reason), "fatal": self.fatal, "recoverable": not self.fatal,
            "diagnostic": bool(self.bundle.manifest.get("calibration", {}).get("diagnostic", False)),
            "alarm": False, "alarm_event": False, "model_alarm": False,
            "integrity_alarm": False, "score": None,
            "integrity": {"status": "inconclusive", "conclusive": False,
                          "findings": [], "inconclusive": ["input_error"]},
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
            self.model_active = False
        self.context.append(frame)
        self.last = frame
        model_state = "input_error" if not frame.valid else "warming_up"
        row = {
            "schema": SCHEMA, "recorded_at": datetime.now(timezone.utc).isoformat(),
            "session": frame.session, "seq": frame.seq, "timestamp": frame.timestamp,
            "chain_id": str(frame.chain_id), "state": model_state, "model_state": model_state,
            "reason": self.buffer.reason, "fatal": False, "recoverable": True,
            "window_rows": len(self.buffer.rows), "required_rows": self.window_rows,
            "threshold": self.threshold, "k": self.k, "n": self.n,
            "score": None, "model_alarm": False, "integrity": integrity,
            "quality": frame.quality,
        }
        if window is not None:
            try:
                score = self.bundle.score(window)
                if not isinstance(score, dict) or not math.isfinite(float(score["score"])):
                    raise ValueError("model returned an invalid score")
                _json(score)  # No silent NaN in auxiliary scores/probabilities.
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
        sources = []
        if model_alarm and not self.model_active:
            sources.append("model_anomaly")
        if integrity_alarm and not self.integrity_active:
            sources.append("kernel_integrity")
        alarm = model_alarm or integrity_alarm
        self.model_active, self.integrity_active = model_alarm, integrity_alarm
        row.update(alarm=alarm, alarm_event=bool(sources), alarm_sources=sources,
                   integrity_alarm=integrity_alarm,
                   state="alarm" if alarm else row["model_state"],
                   vote_count=len(self.history))
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
    """Feature replay never modifies raw evidence or performs a reaction."""
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
    """
    if idle_timeout is not None and (not math.isfinite(idle_timeout) or idle_timeout <= 0):
        raise ValueError("idle_timeout must be finite and positive")
    directory = Path(snapshots)
    if not directory.is_dir():
        raise ValueError("snapshot directory does not exist: " + str(directory))
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    (output / "evidence").mkdir()
    with (output / "configuration.json").open("x", encoding="utf-8") as configuration:
        configuration.write(_json({
            "created_at": datetime.now(timezone.utc).isoformat(),
            "bundle_manifest": bundle.manifest, "snapshots": str(directory.resolve()),
            "profile": str(Path(profile).resolve()), "preserve": bool(preserve),
            "hold_binary": str(hold_binary), "follow": bool(follow), "idle_timeout": idle_timeout,
        }) + "\n")
    detector = Detector(bundle, directory, hold_binary, preserve)
    seen_paths, seen_seq, pending = set(), set(), {}
    previous = None
    last_activity = time.monotonic()
    summary = {"schema": "hyptcn3/safeguard-run/1", "state": "warming_up",
               "running": True, "processed": 0, "scored": 0, "input_errors": 0,
               "alarm_events": 0, "evidence_errors": 0, "pending": 0, "backlog": 0,
               "snapshots": str(directory.resolve()), "output": str(output.resolve()),
               "stop_reason": None, "fatal": False, "last": None,
               "diagnostic": bool(bundle.manifest.get("calibration", {}).get("diagnostic", False))}

    def emit(row, stream):
        stream.write(_json(row) + "\n")
        stream.flush()
        summary["processed"] += 1
        summary["scored"] += row.get("score") is not None
        summary["input_errors"] += row["model_state"] == "input_error"
        summary["alarm_events"] += bool(row["alarm_event"])
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
                            session_id=directory.name, max_gap_s=detector.max_gap_s)
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
