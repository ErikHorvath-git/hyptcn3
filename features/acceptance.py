"""One acceptance decision for a collected session.

A session is accepted for a role the protocol assigns when it has the assigned number of rows in an unbroken
sequence sampled on the protocol's grid (no gap between row times above max_gap_s, none of zero or less, and a
span that differs from (rows - 1) * interval_s by at most one interval), every invalid row is covered by the rule
of that role (the protocol's invalid_rows rule; none for the pilot), no integrity finding is recorded and its
scorable windows reach the protocol's coverage gate. A protocol of schema 3 adds the bounds of its audit section
(features/audit_policy.py): at most rule_closed_rows_max rows whose process list a parser rule closed, and no
periodic pattern among the flagged rows. _verdict(), reached through decide(), judge() and
protocol_reachability(), is the only place that turns these facts into a verdict. The session audit records the
verdict; the protocol loader, the corpus build, the event index, training, the comparison methods and the pilot
gate ask the same function instead of repeating a part of the rule:

    session_facts()          what an extraction result or a feature archive shows
    decide()                 protocol + role + facts -> verdict
    judge()                  the verdict of what session_facts() finds (the audit, require_accepted())
    require_recorded()       an audit record still means acceptance (the archive is not opened)
    require_accepted()       the same, and the archive itself yields the recorded verdict
    protocol_reachability()  whether a faultless session, and the worst one the rule tolerates, can be accepted
    worst_witness()          where max tolerable rows cost the most windows, without two equal spacings
    gate_interval()          the coverage gates that admit exactly invalid_rows.max such rows
    max_witness_cases()      the verdicts of the witness of max and of max + 1 rows (the protocol self-check)
    periodic_run()           the longest run of one spacing between the starts of bursts of flagged rows (the
                             audit records it always)
    spacing_mode()           the most frequent of those spacings (the audit records it; never a reason)
    marked_rows_by_type()    the flagged rows inside the event windows of each event type, the windowed
                             occurrences of each type, and the flagged rows outside every window (MARKED_ROWS_RULE;
                             the audit records them, the campaign sums them for its early stop through
                             features/audit_policy.py early_stop, package B9b and its fix)

The time gap and the sampling period are decided here from the row times of the archive. What no reader of an
archive can derive, and what therefore stays with the audit alone: the sidecars, the logs, the cadence of full
snapshots and the image hashes.
"""
from collections import Counter
import json
import math
from types import SimpleNamespace

import numpy as np

from .audit_policy import audit_bounds
from .quality import (BEHAVIOR_POLICY, NO_TOLERANCE, coverage_gate, invalid_rows_rule, protocol_policy,
                      row_rule_failure, valid_for)

SCHEMA = "hyptcn3/session-acceptance/1"
FACT_KEYS = ("snapshots", "sequence_contiguous", "invalid_rows", "integrity_findings", "windows",
             "rule_closed_seq", "smallest_gap_s", "largest_gap_s", "span_s")
ROW_KEYS = ("seq", "truncated_traversals", "read_errors", "filled_zero")
# Process lists that a parser rule closed instead of the forward walk (guestparse/view.py processes, the quality
# field process_walk): the backward walk (prev), a cut before a stale tail node (tail), the parts meeting (meet).
RULE_CLOSED_WALKS = ("prev", "tail", "meet")


def _length(protocol, key):
    value = protocol.get(key)
    if type(value) is not int or value < 1:
        raise ValueError("invalid " + key)
    return value


def assignment(protocol, role, recorded_rows=None):
    """What the protocol assigns to a role: (row count, resolved invalid_rows rule, whether the role is assigned).

    The pilot has its own length and no tolerance under any protocol version. A diagnostic session is as long
    as its own record says (no length when the record says nothing usable) and falls under the protocol's rule.
    The roles the protocol plans share its `cycles` and its rule. Any other role, and a missing one, has no
    length and no tolerance; the number of rows a session happens to have is never its target.
    """
    rule = invalid_rows_rule(protocol)
    if type(role) is not str:
        return None, NO_TOLERANCE, False
    if role == "pilot":
        return _length(protocol, "pilot_cycles"), NO_TOLERANCE, True
    if role == "diagnostic":
        return (recorded_rows if type(recorded_rows) is int and recorded_rows > 0 else None), rule, True
    roles = protocol.get("roles")
    if type(roles) is dict and role in roles:
        return _length(protocol, "cycles"), rule, True
    return None, NO_TOLERANCE, False


def _count(value):
    return type(value) is int and value >= 0


def _seconds(value):
    """A time in seconds as JSON states it: a finite int or float (never a bool)."""
    return type(value) in (int, float) and math.isfinite(value)


def _grid(protocol):
    """The sampling grid the timing rules read: (interval_s, max_gap_s), both positive and finite."""
    interval, gap = protocol.get("interval_s"), protocol.get("max_gap_s")
    if not _seconds(interval) or interval <= 0:
        raise ValueError("invalid interval_s")
    if not _seconds(gap) or gap <= 0:
        raise ValueError("invalid max_gap_s")
    return interval, gap


def _check_facts(facts):
    if (type(facts) is not dict or set(facts) != set(FACT_KEYS) or not _count(facts["snapshots"])
            or type(facts["sequence_contiguous"]) is not bool or type(facts["invalid_rows"]) is not list
            or not _count(facts["integrity_findings"]) or not _count(facts["windows"])
            or len(facts["invalid_rows"]) > facts["snapshots"] or facts["windows"] > facts["snapshots"]):
        raise ValueError("invalid session facts")
    seen = set()
    for row in facts["invalid_rows"]:
        if type(row) is not dict or set(row) != set(ROW_KEYS) or not _count(row["seq"]) or row["seq"] in seen:
            raise ValueError("invalid session facts")
        seen.add(row["seq"])
    closed, rows = facts["rule_closed_seq"], facts["snapshots"]
    if (type(closed) is not list or len(closed) > rows or not all(_count(seq) for seq in closed)
            or closed != sorted(set(closed))):
        raise ValueError("invalid session facts")
    # Gaps exist between two rows and more, the span from one row on; a time JSON cannot state is no fact.
    smallest, largest, span = facts["smallest_gap_s"], facts["largest_gap_s"], facts["span_s"]
    if (rows < 2 and (smallest, largest) != (None, None)
            or rows >= 2 and not (_seconds(smallest) and _seconds(largest) and smallest <= largest)
            or (span is not None if rows < 1 else not _seconds(span))):
        raise ValueError("invalid session facts")


def _burst_starts(seqs):
    """The first row of every burst of flagged rows (adjacent flagged rows form one burst), in seq order."""
    rows = sorted(set(seqs))
    return [b for a, b in zip([None] + rows, rows) if a is None or b - a > 1]


def periodic_run(seqs, min_spacing):
    """The longest run of one spacing between the starts of consecutive bursts: (run, spacing), (0, None) if none.

    `seqs` are the flagged rows in any order. Adjacent flagged rows form a burst, and the rule reads the spacings
    between the first rows of consecutive bursts (lead's must_fix 3 on B3): "two rows every five" (spacings 1, 4,
    1, 4) and "four of five" (1, 1, 1, 2), the resonance of a periodic guest process with the sampling grid, run at
    spacing 5. Only a spacing of at least `min_spacing` rows counts; a shorter one breaks the run. How long a burst
    is the invalid_rows rule and the cap of rule-closed rows judge, not periodicity. On runs of equal length the
    first one is reported.
    """
    starts = _burst_starts(seqs)
    best, run, last = (0, None), 0, None
    for step in (b - a for a, b in zip(starts, starts[1:])):
        if step < min_spacing:
            run, last = 0, None
            continue
        run, last = (run + 1 if step == last else 1), step
        if run > best[0]:
            best = (run, step)
    return best


def spacing_mode(seqs):
    """The most frequent spacing between the starts of consecutive bursts of flagged rows (ties: the smallest).

    {"spacing": that spacing, "count": how often it occurs, "spacings": how many such spacings there are}; None,
    0 and 0 without two bursts. The audit records it next to periodic_run() and it is never a reason: a real
    resonance scatters (5, 5, 6, 5, 5, 6 has no three equal spacings in a row), and G3a decides from this count
    whether the rule of equal spacings in a row suffices (lead's remarks on B3, part 2).
    """
    starts = _burst_starts(seqs)
    steps = Counter(b - a for a, b in zip(starts, starts[1:]))
    if not steps:
        return {"spacing": None, "count": 0, "spacings": 0}
    spacing = min(steps, key=lambda step: (-steps[step], step))
    return {"spacing": spacing, "count": steps[spacing], "spacings": sum(steps.values())}


def flagged_seq(facts):
    """Rows the periodicity rule reads: the invalid rows and the rows a parser rule closed (v4c gave both)."""
    return sorted({row["seq"] for row in facts["invalid_rows"]} | set(facts["rule_closed_seq"]))


# Package B9b, agent Z (design B9b 1.3; the early stop of proposal 7.5 and 10.9, features/audit_policy.py early_stop).
MARKED_ROWS_RULE = (
    "the marked rows of a session by event type (design B9b 1.3 and its fix: F5 and F8 of the verification of B9b, "
    "question Q24; the early stop of proposal 7.5 and 10.9): the rows flagged_seq gives (the invalid rows and the rows "
    "a parser rule closed, as features/acceptance.py marks them for the periodicity rule), each counted under every "
    "event type one of whose occurrences in the session's events.json holds the row's time (its snapshot time, casy "
    "of the archive) in the occurrence's event window, the window in which the log audit of the same session judges "
    "the event (scripts/collection_logs.py event_window, one function for both: host_start_unix - 1 s to "
    "host_stopped_unix + the session's event_grace_s, events.grace_s of its protocol, both ends included), since the "
    "stop call of an event restores the lab until host_stopped_unix and the same audit admits the event's warnings in "
    "that window; an occurrence the log audit does not window (no host start, or no host stop done) holds no row and "
    "is no occurrence; a row inside no window is counted apart (outside events), as is every marked row of a session "
    "without events (the controls of role test_controls are no events); beside the rows, the windowed occurrences of "
    "each type are counted (event_occurrences_by_type); every event type of the protocol is in both counts, 0 when "
    "none, and a type the protocol does not name is counted under its own name. The early stop does not judge one "
    "session: the campaign sums both counts over its audited sessions (a continuation with those of the paused "
    "campaign it continues) and compares the sum per type with a bound at "
    "its rate per occurrence (scripts/campaign.py early_stop_check, features/audit_policy.py EARLY_STOP_RULE: Q24, "
    "accepted by the lead 2026-11-24). The window is that of the log audit by F8; that a row counts under every type "
    "whose window holds it is the executor's judgment (windows of one session do not overlap: min_gap_s)")


def marked_rows_by_type(flagged, times, windows, types):
    """MARKED_ROWS_RULE: ({event type: count of marked rows inside its windows}, {event type: windowed occurrences},
    count of the marked rows inside no window).

    flagged: the seq of the marked rows (flagged_seq of the verdict's facts); times: {seq: snapshot time} of the rows
    of the session; windows: [(event type, start, end)] of the occurrences of the session that the log audit windows
    (scripts/collection_logs.py event_window), [] for a session without events; types: the event types of the
    protocol (events.types), each in both results. A marked row without a time is refused by name (ValueError),
    never placed."""
    counts, occurrences, outside = dict.fromkeys(types, 0), dict.fromkeys(types, 0), 0
    for kind, _, _ in windows:
        counts.setdefault(kind, 0)
        occurrences[kind] = occurrences.get(kind, 0) + 1
    for seq in flagged:
        if seq not in times or not _seconds(times[seq]):
            raise ValueError(f"marked row {seq} has no snapshot time")
        inside = {kind for kind, start, end in windows if start <= times[seq] <= end}
        for kind in inside:
            counts[kind] += 1
        outside += not inside
    return dict(sorted(counts.items())), dict(sorted(occurrences.items())), outside


def _verdict(protocol, role, assigned, rule, known, facts):
    policy = protocol_policy(protocol)
    gate = coverage_gate(protocol)
    interval, max_gap = _grid(protocol)
    bounds = audit_bounds(protocol)
    _check_facts(facts)
    reasons, codes = [], []

    def reject(code, reason):
        codes.append(code)
        reasons.append(reason)

    # The order of the reasons and their codes is fixed; consumers map a refusal to its message by the code.
    if not known:
        reject("role", "session role is not assigned by the protocol")
    elif facts["snapshots"] != assigned:
        reject("rows", "snapshot count differs from assigned protocol")
    if not facts["sequence_contiguous"]:
        reject("sequence", "sequence must start at zero and be contiguous")
    if facts["smallest_gap_s"] is not None and (facts["smallest_gap_s"] <= 0 or facts["largest_gap_s"] > max_gap):
        reject("timing:gap", "timestamp gap")
    if facts["span_s"] is not None and abs(facts["span_s"] - (facts["snapshots"] - 1) * interval) > interval:
        reject("timing:period", "sampling period differs from protocol")
    bad = [(row["seq"], row) for row in facts["invalid_rows"]]
    failure = row_rule_failure(bad, rule)
    if failure:
        reject("invalid_rows:" + failure, "incomplete model inputs under " + policy)
    if bounds is not None:
        # Until G3b the cap is null: the count is recorded by the audit and never a reason (audit_policy).
        cap = bounds["rule_closed_rows_max"]
        if type(cap) is int and len(facts["rule_closed_seq"]) > cap:
            reject("rule_closed", "rows closed by a parser rule above the cap")
        periodicity = bounds["periodicity"]
        if periodic_run(flagged_seq(facts), periodicity["min_spacing_rows"])[0] >= periodicity["equal_spacings"]:
            reject("periodicity", "periodic flagged rows")
    if facts["integrity_findings"]:
        reject("integrity", "integrity findings require review before benign admission")
    # Coverage is the share of the assigned rows that end a scorable window; without an assignment there is none.
    coverage = None if assigned is None else facts["windows"] / assigned
    if coverage is not None and coverage < gate:
        reject("coverage", f"score coverage below design gate {gate:g}")
    return {"schema": SCHEMA, "accepted": not reasons, "reasons": reasons, "codes": codes, "role": role,
            "assigned_rows": assigned, "gate": gate, "snapshots": facts["snapshots"], "windows": facts["windows"],
            "score_coverage": coverage, "tolerated_invalid_seq": None if failure else [seq for seq, _ in bad],
            "facts": facts}


def decide(protocol, role, facts, recorded_rows=None):
    """The acceptance verdict of one session; it depends on the protocol object, the role and the facts only.

    `facts` is what session_facts() returns, `recorded_rows` the length a diagnostic session recorded for itself.
    The protocol is read as it is and never completed, so a protocol taken from a corpus index or a bundle
    manifest gives the verdict its file gave. A malformed protocol (rule, policy, gate, grid, audit bounds, the
    length the role needs) and malformed facts raise ValueError; everything else is a verdict, also for a session
    the protocol does not accept. Its reasons keep one order: role, rows, sequence, timing:gap, timing:period,
    invalid_rows, rule_closed, periodicity, integrity, coverage.
    """
    assigned, rule, known = assignment(protocol, role, recorded_rows)
    return _verdict(protocol, role, assigned, rule, known, facts)


def _rows(data):
    """seq, valid and quality of an extraction result or a loaded feature archive as plain lists."""
    if len(data["seq"]) == 0:
        raise ValueError("no feature rows")
    seq, valid = np.asarray(data["seq"]), np.asarray(data["valid"])
    quality = json.loads(str(data["quality_json"])) if "quality_json" in data else data["quality"]
    if (seq.ndim != 1 or valid.ndim != 1 or seq.dtype.kind not in "iu" or valid.dtype != np.bool_
            or type(quality) is not list):
        raise ValueError("invalid sequence, validity or quality types")
    if not len(seq) == len(valid) == len(quality):
        raise ValueError("rows, validity and quality differ in length")
    # Without process_walk a row could hide a list closed by a parser rule: such a record is not read.
    if any(type(q) is not dict or type(q.get("findings")) is not list or "process_walk" not in q for q in quality):
        raise ValueError("invalid quality record")
    return seq.tolist(), valid.tolist(), quality


def _times(data, rows):
    """Row times of an extraction result or a loaded feature archive as float64, one per row."""
    try:
        times = np.asarray(data["casy"], dtype=np.float64)
    except (TypeError, ValueError):
        raise ValueError("invalid row times") from None
    if times.shape != (rows,) or not np.isfinite(times).all():
        raise ValueError("invalid row times")
    return times


def session_facts(data, protocol, session, assigned=None):
    """What an extraction result or a loaded feature archive shows: (facts, windows, coverage report).

    The facts are plain JSON values, so the audit can record them and a later reader can decide from the record
    again. An invalid row carries exactly the quality fields the row rule reads; a field the quality record
    lacks is None and is never tolerated. Rows whose process list a parser rule closed (quality process_walk
    prev, tail or meet) are listed by seq; the smallest and largest difference of consecutive row times (None for
    one row) and the span from the first to the last row time are what the timing rules read. Windows are
    counted by the code that feeds the model: under the behavioral policy by safeguard.features.WindowBuffer (with
    the coverage report of features.coverage), under the legacy policy by features.windows.okna (no report). The
    report is made against the assigned length when the session fits into it and against the observed span
    otherwise; such a session is rejected by its row count or its role, never by an exception. Data that cannot
    be read as frames stays an error.
    """
    policy = protocol_policy(protocol)
    if (str(data["quality_policy"]) if "quality_policy" in data else "") != policy:
        raise ValueError("extraction quality policy differs from protocol")
    seq, valid, quality = _rows(data)
    times = _times(data, len(seq))
    gaps = np.diff(times)
    try:
        mask = [valid_for(q, policy) for q in quality]
    except KeyError:
        raise ValueError("invalid quality record") from None
    if valid != mask:
        raise ValueError("valid mask differs from structured quality")
    if policy == BEHAVIOR_POLICY:
        from .coverage import scorable_windows
        span = max(seq) + 1
        windows, report = scorable_windows(data, protocol, session,
                                           assigned if type(assigned) is int and assigned >= span else span)
    else:
        from .snapshot import MENA
        from .windows import okna, snimky_z_matice
        rows = snimky_z_matice(session, data["matica"], MENA, data["casy"], data["seq"], data["valid"])
        windows, report = okna(rows, dlzka=protocol["window_rows"], max_medzera_s=protocol["max_gap_s"]), None
    try:
        # A feature archive holds quality as JSON; the round trip makes an extraction result read the same.
        invalid = json.loads(json.dumps([
            {"seq": s, "truncated_traversals": q.get("truncated_traversals"), "read_errors": q.get("read_errors"),
             "filled_zero": q.get("filled_zero")} for s, good, q in zip(seq, valid, quality) if not good]))
    except TypeError:
        raise ValueError("invalid quality record") from None
    facts = {"snapshots": len(seq), "sequence_contiguous": seq == list(range(len(seq))), "invalid_rows": invalid,
             "integrity_findings": sum(len(q["findings"]) for q in quality), "windows": len(windows),
             "rule_closed_seq": sorted({s for s, q in zip(seq, quality) if q["process_walk"] in RULE_CLOSED_WALKS}),
             "smallest_gap_s": float(gaps.min()) if len(gaps) else None,
             "largest_gap_s": float(gaps.max()) if len(gaps) else None,
             "span_s": float(times[-1] - times[0])}
    return facts, windows, report


def judge(data, protocol, session, role, recorded_rows=None):
    """Verdict of an extraction result or a loaded feature archive: (verdict, windows, coverage report)."""
    assigned, rule, known = assignment(protocol, role, recorded_rows)
    facts, windows, report = session_facts(data, protocol, session, assigned)
    return _verdict(protocol, role, assigned, rule, known, facts), windows, report


def _strict(values, role):
    if type(values) is not dict:
        raise ValueError("unaccepted audit: the record is not an object")
    if values.get("accepted") is not True or values.get("reasons") != []:
        raise ValueError("unaccepted audit: the record does not state a clean acceptance")
    if values.get("role") != role:
        raise ValueError("unaccepted audit: recorded for another role")


def _refusal(verdict):
    """Message for an accepted record whose session the protocol rejects; the first reason decides."""
    code = verdict["codes"][0]
    if code in ("invalid_rows:over_max", "invalid_rows:no_rule", "invalid_rows:no_tolerance"):
        return "more invalid rows than the protocol tolerates"
    if code == "invalid_rows:cause":
        return "invalid rows have a cause the protocol does not tolerate"
    return "accepted audit of a session the protocol rejects: " + verdict["reasons"][0]


def _canonical(value):
    return json.dumps(value, sort_keys=True, allow_nan=False)


def _same(values, verdict):
    """Refuse a record whose stored verdict or summary fields differ from the verdict derived now."""
    if type(values.get("acceptance")) is not dict:
        raise ValueError("audit record carries no acceptance verdict")
    quality = values.get("quality")
    recorded = dict({key: values.get(key) for key in ("role", "snapshots", "windows", "score_coverage")},
                    tolerated_invalid_seq=quality.get("tolerated_invalid_seq") if type(quality) is dict else None)
    try:
        same = (_canonical(values["acceptance"]) == _canonical(verdict)
                and _canonical(recorded) == _canonical({key: verdict[key] for key in recorded}))
    except ValueError:
        same = False  # a value JSON cannot state (NaN, an infinity) is in no verdict derived here
    if not same:
        raise ValueError("audit record differs from the acceptance decision")


def require_recorded(protocol, role, values, recorded_rows=None):
    """An audit record still means acceptance under this protocol; returns the verdict. The archive stays closed.

    The record must state a clean acceptance of this role and carry the audit's verdict; the facts stored with
    it, decided again, must give that very verdict and accept; the record's own summary fields must repeat it.
    This cannot notice an archive that was exchanged after the audit: use require_accepted() where the archive
    is loaded anyway.
    """
    _strict(values, role)
    if type(values.get("acceptance")) is not dict:
        raise ValueError("audit record carries no acceptance verdict")
    verdict = decide(protocol, role, values["acceptance"].get("facts"), recorded_rows)
    if not verdict["accepted"]:
        raise ValueError(_refusal(verdict))
    _same(values, verdict)
    return verdict


def require_accepted(data, protocol, session, role, values, recorded_rows=None):
    """An accepted audit record and the session's own features give one accepting verdict; returns it.

    `data` is the loaded feature archive of the session (or its extraction result). Every reader of accepted
    archives admits through this check what the audit admitted and nothing else: the record must be a clean
    acceptance of this role, it must name every invalid row of the archive, the verdict derived from the
    archive must accept, and the record must equal that verdict (a list naming rows the archive does not have
    is a difference too).
    """
    _strict(values, role)
    verdict, _, _ = judge(data, protocol, session, role, recorded_rows)
    invalid = {row["seq"] for row in verdict["facts"]["invalid_rows"]}
    quality = values.get("quality")
    listed = quality.get("tolerated_invalid_seq") if type(quality) is dict else None
    if invalid and (type(listed) is not list or any(type(s) is not int for s in listed) or invalid - set(listed)):
        raise ValueError("incomplete features in accepted audit")
    if not verdict["accepted"]:
        raise ValueError(_refusal(verdict))
    _same(values, verdict)
    return verdict


def worst_invalid_rows(length, window_rows, full_every, count):
    """Seq of at most `count` invalid rows that cost a session of this shape the most scorable windows.

    A chain of n rows has windows ending at its offsets W..n-1. One invalid row at offset s silences those
    ending at s..s+W: its own, the next row's (no predecessor) and the W-1 after it that are still warming up.
    Rows placed W+1 apart from offset W on therefore each silence W+1 windows and never the same one; what is
    left at the end of a chain is one shorter slot. Taking the largest slots of all chains is the worst case,
    since every further row in a chain can add at most what its next slot holds.
    """
    slots = []
    for start in range(0, length, full_every):
        n = min(full_every, length - start)
        whole, rest = divmod(max(0, n - window_rows), window_rows + 1)
        slots += [(window_rows + 1, start + window_rows + i * (window_rows + 1)) for i in range(whole)]
        if rest:
            slots.append((rest, start + n - rest))
    slots.sort(key=lambda slot: (-slot[0], slot[1]))
    return sorted(seq for _, seq in slots[:count])


# Placements worst_witness() examines before it gives up: a bound of the computation, not of any protocol (author's
# judgment). The witnesses of the protocols in this repository take a few hundred at most (v5: 33 per row, 231 for
# the 7 rows of max 6 + 1); examining all 200000 takes about 0.2 s.
WITNESS_STEPS = 200000


class _NoWitness(ValueError):
    """worst_witness() found no placement with its property."""


def _chain_windows(length, window_rows, full_every, invalid):
    """Windows of a session on the grid with these invalid rows: over chains and the maximal runs of valid rows of
    a chain, max(0, len(run) - window_rows); synthetic_windows() counts the same with the buffer of the model."""
    invalid, total = set(invalid), 0
    for start in range(0, length, full_every):
        run = 0
        for seq in range(start, min(start + full_every, length)):
            if seq in invalid:
                total, run = total + max(0, run - window_rows), 0
            else:
                run += 1
        total += max(0, run - window_rows)
    return total


def worst_witness(length, window_rows, full_every, count):
    """Seq of `count` invalid rows that cost as many windows as worst_invalid_rows() and have no two equal spacings.

    worst_invalid_rows() places its rows window_rows + 1 apart, so four of them in a chain repeat one spacing three
    times and the audit refuses them as periodic (v5: equal_spacings 3). The coverage gate is bound to a session
    the audit can accept (lead's answer to Q1, 2026-11-22): this witness costs exactly as many windows, and since
    no two of its spacings are equal it is periodic under no bound the audit section admits (equal_spacings 2 and
    more); its rows are isolated, so each one starts a burst of its own. The rows are taken in seq order, each at
    the smallest spacing not used yet that still lets the remaining rows cost the worst case (a bound from the
    slots of the rest of the session, as worst_invalid_rows() counts them), going back when none does; in the first
    chain of a long session that gives the offsets W, W + (W + 1), W + (W + 1) + (W + 2), ... ValueError when no
    such placement exists or none is found within WITNESS_STEPS placements.
    """
    w, f = window_rows, full_every
    refusal = f"no placement of {count} invalid rows costs the worst case without two equal spacings"
    # k - 1 distinct spacings need a span of 1 + 2 + ... + (k - 1) rows at least.
    if count > length or count * (count - 1) // 2 > length - 1:
        raise _NoWitness(refusal)
    target = _chain_windows(length, w, f, worst_invalid_rows(length, w, f, count))
    chains = [(start, min(f, length - start)) for start in range(0, length, f)]

    def run(n):
        """Windows of n valid rows that start a chain or follow an invalid row."""
        return max(0, n - w)

    before = [0]  # before[c]: windows of the chains before chain c without invalid rows
    for _, n in chains:
        before.append(before[-1] + run(n))
    whole_after = [sum(run(n) // (w + 1) for _, n in chains[c + 1:]) for c in range(len(chains))]
    rest_after = [[run(n) % (w + 1) for _, n in chains[c + 1:] if run(n) % (w + 1)] for c in range(len(chains))]

    def fewest(x, r):
        """Fewest windows the rows after row x keep with r more invalid rows there (each costs at most one slot)."""
        c = x // f
        tail = chains[c][1] - (x - chains[c][0]) - 1
        windows = run(tail) + before[-1] - before[c + 1]
        whole = run(tail) // (w + 1) + whole_after[c]
        if r <= whole:
            return windows - r * (w + 1)
        rests = sorted([run(tail) % (w + 1)] + rest_after[c], reverse=True)
        return windows - whole * (w + 1) - sum(rests[:r - whole])

    def between(x, y):
        """Windows that end after row x (None: from the start of the session) and before row y."""
        cy = y // f
        if x is not None and x // f == cy:
            return run(y - x - 1)
        if x is None:
            done = before[cy]
        else:
            cx = x // f
            done = run(chains[cx][1] - (x - chains[cx][0]) - 1) + before[cy] - before[cx + 1]
        return done + run(y - chains[cy][0])

    rows, used, steps = [], set(), [0]

    def place(x, kept):
        left = count - len(rows)
        if left == 0:
            return kept + fewest(x, 0) == target
        for y in range(0 if x is None else x + 1, length):
            spacing = () if x is None else (y - x,)  # the first row has no spacing
            if used.intersection(spacing):
                continue
            steps[0] += 1
            if steps[0] > WITNESS_STEPS:
                raise _NoWitness(refusal + f" within {WITNESS_STEPS} placements")
            here = kept + between(x, y)
            if here + fewest(y, left - 1) > target:
                continue
            rows.append(y)
            used.update(spacing)
            if place(y, here):
                return True
            rows.pop()
            used.difference_update(spacing)
        return False

    if count and not place(None, 0):
        raise _NoWitness(refusal)
    return rows


def _worst_rows(length, window_rows, full_every, count):
    """(rows, witness): the rows the verdicts of the worst case read and the function that placed them.

    worst_witness() ("worst_witness"), and where no placement without two equal spacings costs as much,
    worst_invalid_rows() ("worst_invalid_rows"). That happens when the rows fill all or nearly all slots of
    window_rows + 1 windows of the session (short test sessions; on the v5 grid above 16 rows), or when the
    search gives up after WITNESS_STEPS placements. Both leave the same windows; the verdict then says whether the
    protocol's periodicity bound refuses rows with equal spacings, and the self-check of a schema-3 file refuses
    the fallback (lead's remarks on B4, part 1, section 1)."""
    try:
        return worst_witness(length, window_rows, full_every, count), "worst_witness"
    except _NoWitness:
        return worst_invalid_rows(length, window_rows, full_every, count), "worst_invalid_rows"


def synthetic_windows(protocol, length, invalid=()):
    """Scorable windows of a session sampled exactly on the protocol's grid, with the given invalid rows.

    The rows are bare stand-ins for frames (a full snapshot every `full_every` rows, a row after an invalid one
    has no predecessor); the windows are counted by the buffer that feeds the model.
    """
    from safeguard.features import WindowBuffer
    full_every, interval = _length(protocol, "full_every"), protocol.get("interval_s")
    if type(interval) not in (int, float) or not interval > 0:
        raise ValueError("invalid interval_s")
    buffer = WindowBuffer(protocol.get("window_rows"), protocol.get("max_gap_s"))
    invalid = set(invalid)
    count = 0
    for seq in range(length):
        full = seq % full_every == 0
        count += buffer.push(SimpleNamespace(
            session="reachability", seq=seq, timestamp=seq * interval, chain_id=seq // full_every, layout=None,
            biny=None, valid=seq not in invalid, full=full,
            has_predecessor=not full and seq - 1 not in invalid)) is not None
    return count


def _synthetic_case(protocol, key, case, rule, count):
    """The entry of one case of protocol_reachability(): `count` rows where they cost the most (_worst_rows()),
    decided under the resolved `rule` as the audit decides a session of protocol[key] rows; its witness field
    names the function that placed the rows."""
    length = _length(protocol, key)
    invalid, witness = _worst_rows(length, _length(protocol, "window_rows"), _length(protocol, "full_every"), count)
    windows = synthetic_windows(protocol, length, invalid)  # It refuses an interval_s that is no grid.
    interval = protocol["interval_s"]
    facts = {"snapshots": length, "sequence_contiguous": True, "integrity_findings": 0,
             "invalid_rows": [{"seq": seq, "truncated_traversals": [str(rule["traversals"][0])],
                               "read_errors": 0, "filled_zero": 0} for seq in invalid],
             "windows": windows, "rule_closed_seq": [],
             "smallest_gap_s": interval if length > 1 else None, "largest_gap_s": interval if length > 1 else None,
             "span_s": (length - 1) * interval}
    verdict = _verdict(protocol, None, length, rule, True, facts)
    return {"key": key, "case": case, "rows": length, "invalid_seq": invalid, "windows": verdict["windows"],
            "score_coverage": verdict["score_coverage"], "gate": verdict["gate"],
            "accepted": verdict["accepted"], "codes": verdict["codes"], "witness": witness}


def protocol_reachability(protocol):
    """Can the sessions this protocol assigns be accepted at all? One entry per case, decided as the audit decides.

    Cases: a faultless pilot and a faultless session of `cycles` rows ("clean"), and when the protocol has an
    invalid_rows rule also the session of `cycles` rows with `max` tolerable rows where they cost the most, with
    no two equal spacings where such a placement exists ("worst", worst_witness()). Every case is sampled exactly
    on the grid (each gap one interval, the span (rows - 1) intervals) and has no row closed by a parser rule.
    Each entry holds key, case, rows, invalid_seq, windows, score_coverage, gate, accepted, codes and witness
    ("worst_witness", or "worst_invalid_rows" where the rows fell back to it: _worst_rows()).
    """
    rule = invalid_rows_rule(protocol)
    cases = [("pilot_cycles", "clean", NO_TOLERANCE, 0), ("cycles", "clean", rule, 0)]
    if rule is not None:
        cases.append(("cycles", "worst", rule, rule["max"]))
    return [_synthetic_case(protocol, key, case, role_rule, count) for key, case, role_rule, count in cases]


def _max_rule(protocol):
    rule = invalid_rows_rule(protocol)
    if rule is None:
        raise ValueError("protocol has no invalid_rows rule")
    return rule


def gate_interval(protocol):
    """(low, high): a coverage gate admits exactly invalid_rows.max isolated rows in a session of `cycles` rows iff
    low < gate <= high (POKYNY 2026-11-22 section 4).

    high is the coverage of the witness of max rows, low that of max + 1 rows (worst_witness(), the rows of
    max_witness_cases()): whole windows of the buffer that feeds the model divided by cycles, the division the
    verdict makes, so the two inequalities hold exactly when the coverage gate admits the first and refuses the
    second. ValueError for a protocol without an invalid_rows rule.
    """
    rule = _max_rule(protocol)
    length = _length(protocol, "cycles")
    window_rows, full_every = _length(protocol, "window_rows"), _length(protocol, "full_every")
    high, low = (synthetic_windows(protocol, length, _worst_rows(length, window_rows, full_every, count)[0]) / length
                 for count in (rule["max"], rule["max"] + 1))
    return low, high


def max_witness_cases(protocol):
    """The verdicts of the witness of invalid_rows.max rows ("worst") and of max + 1 rows ("worst+1") in a session
    of `cycles` rows, as protocol_reachability() entries, for the self-check of the protocol.

    The first is decided under the protocol's rule and must be accepted. The second is decided under the rule
    with max + 1, since the rule's own count refuses max + 1 rows anyway: what refuses it there is the coverage
    gate or the periodicity bound, and the self-check wants the gate alone (refused, and no "periodicity" among
    its codes). Where no placement without two equal spacings costs the worst case, the entry holds the rows of
    worst_invalid_rows() and its witness field says so (_worst_rows()). ValueError for a protocol without an
    invalid_rows rule.
    """
    rule = _max_rule(protocol)
    return [_synthetic_case(protocol, "cycles", "worst", rule, rule["max"]),
            _synthetic_case(protocol, "cycles", "worst+1", dict(rule, max=rule["max"] + 1), rule["max"] + 1)]
