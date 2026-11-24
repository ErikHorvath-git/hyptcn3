"""The audit records the marked rows of a session by event type (protocol v5, package B9b, agent Z, and its fix round:
F5 and F8 of the verification of B9b, question Q24; design dokazy/B9/navrh/NAVRH_B9b.md 1.3, the count of the early
stop).

Sessions of scripts/tests/boundary_sessions.py audited by the real scripts/collection.py audit_session (only the
extraction from guest RAM is replaced): the rows the periodicity rule reads (invalid and rule-closed rows) counted by
the event type whose event window (the log audit's, scripts/collection_logs.py event_window) holds their time, the
windowed occurrences of each type, and the rows outside every window (values.marked_rows_by_type,
event_occurrences_by_type, marked_rows_outside_events, marked_rows_note); the counts the campaign sums for the rule of
early stop (features/audit_policy.py early_stop). The names of package B9b are imported inside the tests, so this file
collects on the code before it. Mechanics only; no number here is a measurement (HONESTY P4).
"""
import copy
import itertools
import json

import pytest

from scripts import collection
from scripts.tests import boundary_sessions as bs
from scripts.tests import test_collection_logs as evidence

SLOT = itertools.count()  # Every session of this module has its own time slot.
# The one event of test_collection_logs.build(event=True) holds the host times base + 1.45 (start) to base + 1.6 s
# (stop done) with event_grace_s 0.1, so its window is base + 0.45 to base + 1.7 s, and the first snapshot of a
# boundary session lies at base + 1.5 s, on the grid of 1 s: row 0 is inside it, rows 5 and 10 are not. Row 0 and
# row 10 are invalid (a traversal did not close), row 5 a parser rule closed.
MARKED = {0: bs.unclosed_row(), 5: bs.rule_closed_row(), 10: bs.unclosed_row()}


@pytest.fixture(scope="module")
def families(tmp_path_factory):
    """The loaded protocols of the families S3 (schema 3, the event types of config/collection-v5.json) and S2G
    (schema 2): {name: (protocol, path)}, and the root for their sessions."""
    root = tmp_path_factory.mktemp("marked")
    profile = bs.profile_dir(root / "profile")
    loaded = {}
    for name in ("S3", "S2G"):
        path = bs.write_protocol(root / f"{name}.json", bs.family(name, profile))
        loaded[name] = collection.protocol(path), path
    return loaded, root


def audited(families, name, session_id, *, event):
    """The values of the audit of the first train session of `name` with the marked rows MARKED (and the one event of
    test_collection_logs.build when event)."""
    (p, path), root = families[0][name], families[1]
    session = bs.build_session(root / "sessions", p, path, bs.places(p, "train")[0], session_id=session_id,
                               base=bs.time_base(p, "train", next(SLOT)), quality=MARKED, event=event)
    return p, session, bs.audit(session, p).values


def test_the_audit_counts_the_marked_rows_by_the_event_whose_window_holds_them(families, monkeypatch):
    """Row 0 lies inside the event window of the occurrence (the log audit's window, host start - 1 s to host stop done
    + the session's event_grace_s), rows 5 and 10 outside every window; every event type of the protocol is counted,
    0 when no marked row lies in it, with the windowed occurrences of each type, and the rule is the note. While the
    rates are null (the v5 file until G3b) the count stops nothing; at a rate of 0.01 per occurrence the same count as
    a campaign of one session (1 marked row in 1 occurrence, above the bound 0 of Poisson(0.01)) stops it."""
    from features.acceptance import MARKED_ROWS_RULE
    from features.audit_policy import early_stop
    monkeypatch.setattr(evidence, "EVENT", dict(evidence.EVENT, type="zamok_tabulky", **{"class": "chyba_aplikacie"}))
    p, _, values = audited(families, "S3", "marked-event", event=True)
    types = sorted(p["events"]["types"])
    assert (values["marked_rows_by_type"], values["event_occurrences_by_type"], values["marked_rows_outside_events"],
            values["marked_rows_note"]) == ({**dict.fromkeys(types, 0), "zamok_tabulky": 1},
                                            {**dict.fromkeys(types, 0), "zamok_tabulky": 1}, 2, MARKED_ROWS_RULE)
    assert values["timing"]["periodic_run"]["flagged_rows"] == 3  # The same rows the periodicity rule reads.
    totals = {kind: {"marked": values["marked_rows_by_type"][kind],
                     "occurrences": values["event_occurrences_by_type"][kind]} for kind in types}
    assert early_stop(values, p, totals) is None
    rated = copy.deepcopy(p)
    rated["audit"]["early_stop"]["marked_rows_rate_per_type"]["zamok_tabulky"] = 0.01
    assert {k: v for k, v in early_stop(values, rated, totals).items() if k != "rule"} == {
        "cause": "marked_rows", "type": "zamok_tabulky", "count": 1, "bound": 0, "occurrences": 1, "rate": 0.01}


def test_a_session_without_events_has_its_marked_rows_outside_every_event(families):
    """A session that plans no event (as one of role test_controls, whose controls are no events) counts every
    marked row apart, and every event type of the protocol 0 rows in 0 occurrences; an occurrence of a type the
    protocol does not name keeps its own name."""
    p, _, values = audited(families, "S3", "marked-none", event=False)
    zero = dict.fromkeys(sorted(p["events"]["types"]), 0)
    assert (values["marked_rows_by_type"], values["event_occurrences_by_type"],
            values["marked_rows_outside_events"]) == (zero, zero, 3)
    p, _, values = audited(families, "S3", "marked-other", event=True)  # restart_sluzby, a type of protocol v3.
    assert (values["marked_rows_by_type"], values["event_occurrences_by_type"],
            values["marked_rows_outside_events"]) == ({**zero, "restart_sluzby": 1}, {**zero, "restart_sluzby": 1}, 2)


def test_the_marked_rows_are_not_counted_when_they_cannot_be_told_by_type(families):
    """Null with the reason, never 0: under protocol schema 2 (no event types) and in a session that plans events
    whose events.json is missing, cannot be read, or cannot be windowed as the log audit windows it (no event_grace_s
    in session.json) (marked_rows_record)."""
    nothing = (None, None, None)
    _, _, values = audited(families, "S2G", "marked-schema2", event=True)
    assert (values["marked_rows_by_type"], values["event_occurrences_by_type"], values["marked_rows_outside_events"],
            values["marked_rows_note"]) == (*nothing, "the protocol names no event types (protocol schema 1 or 2): "
                                                      "the marked rows are not counted by type")
    p, session, _ = audited(families, "S3", "marked-lost", event=True)
    events = (session.directory / "events.json").read_text()
    (session.directory / "events.json").unlink()
    values = bs.audit(session, p, output=session.directory / "again.json").values
    assert (values["marked_rows_by_type"], values["event_occurrences_by_type"], values["marked_rows_outside_events"],
            values["marked_rows_note"]) == (*nothing, "the session plans events and has no events.json: the marked "
                                                      "rows cannot be told by type")
    for text, name, error in (("{not json", "third", "JSONDecodeError"),
                              (json.dumps({"events": {"type": "zamok_tabulky"}}), "fourth", "TypeError")):
        (session.directory / "events.json").write_text(text)
        values = bs.audit(session, p, output=session.directory / f"{name}.json").values
        assert (values["marked_rows_by_type"], values["event_occurrences_by_type"], values["marked_rows_note"]) == (
            None, None, f"events.json cannot be read or windowed ({error}): the marked rows cannot be told by type")
    (session.directory / "events.json").write_text(events)
    meta = json.loads((session.directory / "session.json").read_text())
    del meta["event_grace_s"]
    (session.directory / "session.json").write_text(json.dumps(meta))
    values = bs.audit(session, p, output=session.directory / "fifth.json").values
    assert (values["marked_rows_by_type"], values["marked_rows_note"]) == (
        None, "events.json cannot be read or windowed (KeyError): the marked rows cannot be told by type")
