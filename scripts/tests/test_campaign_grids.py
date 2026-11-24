"""The grids of the two collectors of a campaign (protocol v5, package B9b, agent Z; the lead's skeleton
dokazy/B9/kostra/KOSTRA.md row mriežky dvoch VM, design dokazy/B9/navrh/NAVRH_B9b.md 1.3): scripts/campaign_grids.py.

For every pair of sessions of two VMs whose measured phases overlap, the grid phase of both and their mutual shift
modulo interval_s, a record only. The module is imported inside the tests, so this file collects on the code before
it. Mechanics only; no number here is a measurement (HONESTY P4).
"""
import json

import pytest


def row(session, vm, start, end, phase, interval=5):
    return {"session": session, "vm": vm, "start": start, "end": end, "grid_phase_s": phase, "interval_s": interval}


def test_every_pair_of_concurrent_sessions_of_two_vms_has_both_phases_and_their_shift():
    """Sessions a1, a2 of VM a and b1, b2 of VM b: a1 overlaps b1, a2 overlaps b1 and b2, a1 and b2 do not; two
    sessions of one VM never pair. The shift is the phase of VM b minus that of VM a modulo the interval (a2 against
    b1 wraps around), the pairs in the order of the start of their overlap, VM a first in each."""
    from scripts.campaign_grids import grid_pairs
    sessions = [row("b1", "b", 50, 150, 3.5), row("a1", "a", 0, 100, 1.25), row("a2", "a", 120, 220, 4.0),
                row("b2", "b", 150, 250, 1.0)]
    assert grid_pairs(sessions) == [
        {"sessions": ["a1", "b1"], "vms": ["a", "b"], "overlap_s": 50, "grid_phase_s": [1.25, 3.5], "interval_s": 5,
         "shift_s": 2.25, "why": None},
        {"sessions": ["a2", "b1"], "vms": ["a", "b"], "overlap_s": 30, "grid_phase_s": [4.0, 3.5], "interval_s": 5,
         "shift_s": 4.5, "why": None},
        {"sessions": ["a2", "b2"], "vms": ["a", "b"], "overlap_s": 70, "grid_phase_s": [4.0, 1.0], "interval_s": 5,
         "shift_s": 2.0, "why": None}]


def test_sessions_that_only_touch_do_not_pair_and_a_shift_is_never_the_interval():
    """An overlap of 0 s is none, and two sessions of one VM never pair, even overlapping (the record pairs the grids
    of the two VMs); a difference that rounds to the interval is a shift of 0 (the range [0, interval))."""
    from scripts.campaign_grids import grid_pairs
    assert grid_pairs([row("a1", "a", 0, 100, 1.0), row("b1", "b", 100, 200, 2.0)]) == []
    assert grid_pairs([row("a1", "a", 0, 100, 1.0), row("a2", "a", 50, 150, 2.0)]) == []
    assert grid_pairs([row("a1", "a", 0, 100, 1.0), row("b1", "b", 10, 20, 0.9999999)])[0]["shift_s"] == 0.0


def test_the_protocol_interval_serves_rows_without_their_own_and_an_unmeasured_session_pairs_with_none():
    """The rows of a campaign's record may leave the interval to the call (the protocol's interval_s); a row whose
    start or end is null (no measured phase) is in no pair; without any interval a row is refused by name."""
    from scripts.campaign_grids import grid_pairs
    rows = [{k: v for k, v in r.items() if k != "interval_s"}
            for r in (row("a1", "a", 0, 100, 1.25), row("b1", "b", 50, 150, 3.5), row("b2", "b", 60, None, 2.0))]
    assert grid_pairs(rows, 5) == grid_pairs([row("a1", "a", 0, 100, 1.25), row("b1", "b", 50, 150, 3.5)])
    assert len(grid_pairs(rows, interval_s=5)) == 1
    with pytest.raises(ValueError) as error:
        grid_pairs(rows)
    assert str(error.value).startswith("a row of grid_pairs is {session, vm, start, end, grid_phase_s} of one session")


def test_a_shift_without_a_phase_or_with_two_intervals_is_null_with_its_reason():
    from scripts.campaign_grids import grid_pairs
    missing = grid_pairs([row("a1", "a", 0, 100, None), row("b1", "b", 50, 150, 2.0)])[0]
    assert (missing["grid_phase_s"], missing["shift_s"], missing["why"]) == (
        [None, 2.0], None, "no grid phase recorded by the audit of a1")
    other = grid_pairs([row("a1", "a", 0, 100, 1.0), row("b1", "b", 50, 150, 0.5, interval=1)])[0]
    assert (other["interval_s"], other["shift_s"], other["why"]) == (
        5, None, "the intervals differ (5 s and 1 s): no shift modulo one interval")


@pytest.mark.parametrize("sessions, message", [
    ([dict(row("a1", "a", 0, 100, 1.0), extra=1)], "a row of grid_pairs is"),
    ([row("a1", "a", 100, 0, 1.0)], "a row of grid_pairs is"),
    ([row("a1", "a", 0, 100, "1.0")], "a row of grid_pairs is"),
    ([row("a1", "a", 0, 100, 1.0, interval=0)], "a row of grid_pairs is"),
    ([row("a1", "a", 0, 100, 1.0), row("a1", "b", 0, 100, 2.0)], "grid_pairs names a session twice: a1"),
    ([dict(row("a1", "a", 0, 100, 1.0), vm=None, start=None)], "a row of grid_pairs is"),
], ids=["extra_key", "end_before_start", "phase_text", "interval_0", "session_twice", "unmeasured_without_vm"])
def test_a_malformed_row_is_refused_by_name(sessions, message):
    from scripts.campaign_grids import grid_pairs
    with pytest.raises(ValueError) as error:
        grid_pairs(sessions)
    assert str(error.value).startswith(message)


def write(path, doc):
    path.write_text(json.dumps(doc))
    return path


def test_the_row_of_a_session_comes_from_its_records(tmp_path):
    """grid_session: session.json (session_id, vm, the collector's interval), end.json (the measured phase) and the
    audit (values.timing.grid_phase_s); no row without a measured phase, a null phase without an audit, and a
    session.json without its identity refused by name."""
    from scripts.campaign_grids import grid_pairs, grid_session
    rows = []
    for name, vm, start, phase in (("s-a", "a", 1000.0, 1.25), ("s-b", "b", 1100.0, 4.0)):
        d = tmp_path / name
        d.mkdir()
        write(d / "session.json", {"session_id": name, "vm": vm, "collector_settings": {"interval_s": 5}})
        write(d / "end.json", {"measure_start_unix": start, "measure_end_unix": start + 3600})
        audit = write(d / "audit.json", {"values": {"timing": {"grid_phase_s": phase}}})
        rows.append(grid_session(d, audit))
    assert rows[0] == row("s-a", "a", 1000.0, 4600.0, 1.25)
    assert grid_pairs(rows)[0]["shift_s"] == 2.75
    assert grid_session(tmp_path / "s-a", None)["grid_phase_s"] is None
    write(tmp_path / "s-a" / "end.json", {"measure_start_unix": 1000.0})  # It ended before its measurement.
    assert grid_session(tmp_path / "s-a", None) is None
    (tmp_path / "s-a" / "end.json").unlink()
    assert grid_session(tmp_path / "s-a", None) is None
    write(tmp_path / "s-a" / "session.json", {"session_id": "s-a", "collector_settings": {"interval_s": 5}})
    with pytest.raises(ValueError) as error:
        grid_session(tmp_path / "s-a", None)
    assert str(error.value) == (f"{tmp_path / 's-a'}/session.json names no session_id, vm and "
                                "collector_settings.interval_s")
