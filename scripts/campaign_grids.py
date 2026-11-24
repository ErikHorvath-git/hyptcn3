"""The grids of the two collectors of a campaign (protocol v5, package B9b, agent Z).

Binding texts: the lead's skeleton dokazy/B9/kostra/KOSTRA.md, row "mriežky dvoch VM" (record only: the grid phase of
both collectors of concurrent sessions and their mutual shift), and the design dokazy/B9/navrh/NAVRH_B9b.md 1.3.
scripts/host_periods.json names the drift of the two collectors' grids as a period of the host that the campaign
records per pair; nothing here judges it.

    grid_session(directory, audit)        the row of grid_pairs of one measured session: its session.json, its
                                          end.json and its audit record (None when it has no measured phase)
    grid_pairs(sessions, interval_s=None) one record per pair of sessions of two VMs whose measured phases overlap
    GRID_RULE                             what grid_pairs records, written beside its result

The campaign's ending record (scripts/campaign.py, package B9b agent R) puts grid_pairs into its values. This module
imports nothing of scripts/, so scripts/campaign.py and scripts/campaign_report.py import it without a cycle.
"""
import json
import math
from pathlib import Path

GRID_RULE = (
    "the grids of the two collectors (the lead's skeleton B9 row mriežky dvoch VM, design B9b 1.3; record only, never "
    "a reason): for every pair of sessions of two VMs whose measured phases overlap (end.json measure_start_unix to "
    "measure_end_unix, an overlap above 0 s), the grid phase of each session (the audit's values.timing.grid_phase_s: "
    "the time frame 0 was due, its timestamp minus its lateness, modulo interval_s) and their mutual shift, the phase "
    "of the session of the later VM (in sorted order of the VM names) minus that of the earlier one, modulo "
    "interval_s, in [0, interval_s); the shift is null, with the reason, when a phase was not recorded or the two "
    "intervals differ; a session without a measured phase (no start or end of its measurement) is in no pair")
ROW_KEYS = ("session", "vm", "start", "end", "grid_phase_s")  # And interval_s, unless grid_pairs is given it.
DIGITS = 6  # The rounding of the audit's grid_phase_s (scripts/collection.py audit_session), kept for the shift.


def _seconds(value):
    return type(value) in (int, float) and math.isfinite(value)


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def grid_session(directory, audit):
    """The row {session, vm, start, end, grid_phase_s, interval_s} of grid_pairs for the session in `directory`: its
    session_id, vm and collector_settings.interval_s from session.json, its measured phase from end.json
    (measure_start_unix, measure_end_unix) and its grid phase from the audit record at `audit` (values.timing.
    grid_phase_s), given explicitly as None for a capture that was not audited (then the phase is null and the pair
    says why). None when the session has no measured phase (no end.json, or one without both times: it ended before
    its measurement). ValueError by name for a session.json without its session_id, vm or interval."""
    directory = Path(directory)
    meta = _read(directory / "session.json")
    sid, vm = meta.get("session_id"), meta.get("vm")
    interval = (meta.get("collector_settings") or {}).get("interval_s")
    if type(sid) is not str or type(vm) is not str or not _seconds(interval) or interval <= 0:
        raise ValueError(f"{directory}/session.json names no session_id, vm and collector_settings.interval_s")
    if not (directory / "end.json").is_file():
        return None
    end = _read(directory / "end.json")
    start, stop = end.get("measure_start_unix"), end.get("measure_end_unix")
    if not (_seconds(start) and _seconds(stop)):
        return None
    phase = None
    if audit is not None:
        timing = _read(audit).get("values", {}).get("timing")
        phase = timing.get("grid_phase_s") if type(timing) is dict else None
    return {"session": sid, "vm": vm, "start": start, "end": stop, "grid_phase_s": phase, "interval_s": interval}


def _row(row, interval_s):
    """The row with its interval: its own interval_s, else the interval_s given to grid_pairs; None for a session
    without a measured phase (start or end null); ValueError by name for a malformed row."""
    ok = (type(row) is dict and set(ROW_KEYS) <= set(row) <= {*ROW_KEYS, "interval_s"}
          and type(row["session"]) is str and type(row["vm"]) is str)
    if ok and (row["start"] is None or row["end"] is None):
        return None
    interval = row.get("interval_s", interval_s) if ok else None
    if not (ok and _seconds(row["start"]) and _seconds(row["end"]) and row["start"] <= row["end"]
            and _seconds(interval) and interval > 0 and (row["grid_phase_s"] is None or _seconds(row["grid_phase_s"]))):
        raise ValueError("a row of grid_pairs is {" + ", ".join(ROW_KEYS) + "} of one session (grid_session), with its "
                         f"interval_s or the one given to grid_pairs: {row!r}")
    return dict(row, interval_s=interval)


def _shift(first, second):
    """(the mutual shift of the two grids, the reason when it is null)."""
    if first["interval_s"] != second["interval_s"]:
        return None, (f"the intervals differ ({first['interval_s']} s and {second['interval_s']} s): no shift modulo "
                      "one interval")
    missing = [row["session"] for row in (first, second) if row["grid_phase_s"] is None]
    if missing:
        return None, "no grid phase recorded by the audit of " + ", ".join(missing)
    interval = first["interval_s"]
    shift = round((second["grid_phase_s"] - first["grid_phase_s"]) % interval, DIGITS)
    return (0.0 if shift >= interval else shift), None


def grid_pairs(sessions, interval_s=None):
    """GRID_RULE: [{sessions, vms, overlap_s, grid_phase_s, interval_s, shift_s, why}] for every pair of rows of
    `sessions` (grid_session, or {session, vm, start, end, grid_phase_s} with the protocol's interval_s given here) of
    two VMs whose measured phases overlap by more than 0 s, in the order of the start of their overlap; sessions, vms
    and grid_phase_s list the two in sorted order of their VM names, interval_s is that of the first session, shift_s
    the shift of the second grid against the first modulo interval_s (null with the reason in why). A row whose start
    or end is null (no measured phase) is in no pair. ValueError by name for a malformed row, a row without an
    interval when none is given, and a session named twice."""
    rows = [row for row in (_row(item, interval_s) for item in sessions) if row is not None]
    names = [row["session"] for row in rows]
    if len(set(names)) != len(names):
        raise ValueError("grid_pairs names a session twice: " + ", ".join(sorted({n for n in names
                                                                                 if names.count(n) > 1})))
    pairs = []
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            if a["vm"] == b["vm"]:
                continue
            first, second = sorted((a, b), key=lambda row: row["vm"])
            begin, finish = max(a["start"], b["start"]), min(a["end"], b["end"])
            if finish - begin <= 0:
                continue
            shift, why = _shift(first, second)
            pairs.append({"sessions": [first["session"], second["session"]], "vms": [first["vm"], second["vm"]],
                          "overlap_s": round(finish - begin, DIGITS),
                          "grid_phase_s": [first["grid_phase_s"], second["grid_phase_s"]],
                          "interval_s": first["interval_s"], "shift_s": shift, "why": why, "_begin": begin})
    pairs.sort(key=lambda pair: (pair["_begin"], pair["sessions"]))
    return [{key: value for key, value in pair.items() if key != "_begin"} for pair in pairs]
