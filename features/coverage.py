"""Explain offline score eligibility using the live detector's window buffer.

Counts are sampling slots, not measured online availability or detection rates.
The prediction target is the last of window_rows rows (not an extra row).
"""
from collections import Counter

import numpy as np

from .snapshot import MENA
from .windows import Okna


def ideal_windows(cycles, window_rows, full_every):
    """Slot budget after excluding each full row and refilling its window."""
    chains, tail = divmod(cycles, full_every)
    return chains * max(0, full_every - window_rows) + max(0, tail - window_rows)


def scorable_windows(data, protocol, session, expected_rows=None):
    # Lazy import: safeguard.features itself imports the archive primitives.
    from safeguard.features import WindowBuffer, frames_from_archive

    frames = frames_from_archive(data, session)
    if not frames:
        raise ValueError("no feature rows")
    expected = len(frames) if expected_rows is None else expected_rows
    if type(expected) is not int or expected < 1:
        raise ValueError("expected snapshot count must be a positive integer")
    if any(frame.seq >= expected for frame in frames):
        raise ValueError("snapshot sequence outside assigned collection")
    if protocol.get("stride", 1) != 1:
        raise ValueError("score coverage requires stride 1")
    length, interval = protocol["window_rows"], protocol["interval_s"]
    buffer = WindowBuffer(length, protocol["max_gap_s"])
    blocks, meta, barriers, ranges = [], [], [], []
    counts, losses = Counter(), Counter()
    cause, previous = "startup", None
    longest = current_run = 0
    notes_by_row = data.get("poznamky")
    for i, frame in enumerate(frames):
        reset_causes = []
        if previous is not None:
            if frame.seq != previous.seq + 1:
                reset_causes.append("sequence_gap")
            if frame.timestamp - previous.timestamp > protocol["max_gap_s"]:
                reset_causes.append("timestamp_gap")
            if frame.chain_id != previous.chain_id:
                reset_causes.append("chain_change")
        if not frame.valid:
            reset_causes.append("invalid_input")
        if frame.full:
            reset_causes.append("full_snapshot")
        if not frame.has_predecessor:
            reset_causes.append("no_predecessor")
        window = buffer.push(frame)
        if reset_causes:
            # A missing predecessor immediately after a bad row is part of
            # that same loss; it must not conceal the original invalid input.
            cause = ("invalid_input" if not frame.valid else "full_snapshot" if frame.full
                     else reset_causes[0] if reset_causes != ["no_predecessor"]
                     else cause if previous is not None and not previous.valid else "no_predecessor")
            notes = notes_by_row[i] if notes_by_row is not None else None
            barriers.append({"seq": frame.seq, "timestamp": frame.timestamp,
                             "causes": reset_causes, "notes": notes.tolist() if isinstance(notes, np.ndarray)
                             else str(notes) if isinstance(notes, np.str_) else notes})
        state = "scorable" if window is not None else buffer.reason
        counts[state] += 1
        if window is None:
            losses[cause] += 1
            current_run += 1
            longest = max(longest, current_run)
        else:
            current_run = 0
            blocks.append(np.stack([row.vector for row in window]))
            meta.append({"session": session, "seq_od": window[0].seq, "seq_do": frame.seq,
                         "n_snimok": length, "cas_unix_od": window[0].timestamp,
                         "cas_unix_do": frame.timestamp, "trvanie_s": frame.timestamp - window[0].timestamp})
        label = "scorable" if window is not None else cause
        if ranges and ranges[-1]["cause"] == label and frame.seq == ranges[-1]["seq_to"] + 1:
            ranges[-1].update(seq_to=frame.seq, time_to=frame.timestamp,
                              rows=ranges[-1]["rows"] + 1)
        else:
            ranges.append({"cause": label, "seq_from": frame.seq, "seq_to": frame.seq,
                           "time_from": frame.timestamp, "time_to": frame.timestamp, "rows": 1})
        previous = frame
    rotation = protocol["full_every"]
    ideal = ideal_windows(expected, length, rotation)
    windows = Okna(np.stack(blocks) if blocks else np.empty((0, length, len(MENA))),
                  meta, MENA, length, 1)
    report = {"schema": "hyptcn3/score-coverage/1", "session": session,
              "window_rows": length, "prediction_context_rows": length - 1,
              "observed_snapshots": len(frames), "expected_snapshots": expected,
              "missing_snapshots": expected - len(frames), "scorable_windows": len(windows),
              "score_coverage": len(windows) / expected,
              "observed_score_coverage": len(windows) / len(frames),
              "ideal_windows": ideal, "ideal_score_coverage": ideal / expected,
              "gate_possible_at_assigned_length": ideal / expected >= protocol.get("min_score_coverage", .85),
              "lost_windows_vs_ideal": max(0, ideal - len(windows)),
              "state_rows": dict(counts), "unscored_rows_by_cause": dict(losses),
              "first_score_seq": meta[0]["seq_do"] if meta else None,
              "longest_observed_unscored_run_rows": longest,
              "nominal_scored_s": len(windows) * interval,
              "nominal_unscored_s": (expected - len(windows)) * interval,
              "observed_span_s": frames[-1].timestamp - frames[0].timestamp,
              "barriers": barriers, "ranges": ranges,
              "note": "Eligibility only, no inference executed. Nominal seconds = slots * protocol period; "
                      "missing slots stay in the denominator. No online latency or detection claim."}
    return windows, report
