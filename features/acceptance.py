"""One acceptance decision for a collected session.

A session is accepted for a role the protocol assigns when it has the assigned number of rows in an unbroken
sequence, every invalid row is covered by the rule of that role (the protocol's invalid_rows rule; none for the
pilot), no integrity finding is recorded and its scorable windows reach the protocol's coverage gate. _verdict(),
reached through decide(), judge() and protocol_reachability(), is the only place that turns these facts into a
verdict. The session audit records the verdict; the protocol loader, the corpus build, the event index, training,
the comparison methods and the pilot gate ask the same function instead of repeating a part of the rule:

    session_facts()          what an extraction result or a feature archive shows
    decide()                 protocol + role + facts -> verdict
    judge()                  the verdict of what session_facts() finds (the audit, require_accepted())
    require_recorded()       an audit record still means acceptance (the archive is not opened)
    require_accepted()       the same, and the archive itself yields the recorded verdict
    protocol_reachability()  whether a faultless session, and the worst one the rule tolerates, can be accepted

What no reader of an archive can derive, and what therefore stays with the audit alone: the sidecars and logs,
the sampling period and cadence, the gaps between sidecar timestamps and the image hashes.
"""
import json
from types import SimpleNamespace

import numpy as np

from .quality import (BEHAVIOR_POLICY, NO_TOLERANCE, coverage_gate, invalid_rows_rule, protocol_policy,
                      row_rule_failure, valid_for)

SCHEMA = "hyptcn3/session-acceptance/1"
FACT_KEYS = ("snapshots", "sequence_contiguous", "invalid_rows", "integrity_findings", "windows")
ROW_KEYS = ("seq", "truncated_traversals", "read_errors", "filled_zero")


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


def _verdict(protocol, role, assigned, rule, known, facts):
    policy = protocol_policy(protocol)
    gate = coverage_gate(protocol)
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
    bad = [(row["seq"], row) for row in facts["invalid_rows"]]
    failure = row_rule_failure(bad, rule)
    if failure:
        reject("invalid_rows:" + failure, "incomplete model inputs under " + policy)
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
    manifest gives the verdict its file gave. A malformed protocol (rule, policy, gate, the length the role
    needs) and malformed facts raise ValueError; everything else is a verdict, also for a session the protocol
    does not accept. Its reasons keep one order: role, rows, sequence, invalid_rows, integrity, coverage.
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
    if any(type(q) is not dict or type(q.get("findings")) is not list for q in quality):
        raise ValueError("invalid quality record")
    return seq.tolist(), valid.tolist(), quality


def session_facts(data, protocol, session, assigned=None):
    """What an extraction result or a loaded feature archive shows: (facts, windows, coverage report).

    The facts are plain JSON values, so the audit can record them and a later reader can decide from the record
    again. An invalid row carries exactly the quality fields the row rule reads; a field the quality record
    lacks is None and is never tolerated. Windows are counted by the code that feeds the model: under the
    behavioral policy by safeguard.features.WindowBuffer (with the coverage report of features.coverage), under
    the legacy policy by features.windows.okna (no report). The report is made against the assigned length
    when the session fits into it and against the observed span otherwise; such a session is rejected by its
    row count or its role, never by an exception. Data that cannot be read as frames stays an error.
    """
    policy = protocol_policy(protocol)
    if (str(data["quality_policy"]) if "quality_policy" in data else "") != policy:
        raise ValueError("extraction quality policy differs from protocol")
    seq, valid, quality = _rows(data)
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
             "integrity_findings": sum(len(q["findings"]) for q in quality), "windows": len(windows)}
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


def protocol_reachability(protocol):
    """Can the sessions this protocol assigns be accepted at all? One entry per case, decided as the audit decides.

    Cases: a faultless pilot and a faultless session of `cycles` rows ("clean"), and when the protocol has an
    invalid_rows rule also the session of `cycles` rows with `max` tolerable rows where they cost the most
    ("worst"). Each entry holds key, case, rows, invalid_seq, windows, score_coverage, gate, accepted and codes.
    """
    rule = invalid_rows_rule(protocol)
    cases = [("pilot_cycles", "clean", NO_TOLERANCE, 0), ("cycles", "clean", rule, 0)]
    if rule is not None:
        cases.append(("cycles", "worst", rule, rule["max"]))
    out = []
    for key, case, role_rule, count in cases:
        length = _length(protocol, key)
        invalid = worst_invalid_rows(length, _length(protocol, "window_rows"), _length(protocol, "full_every"), count)
        facts = {"snapshots": length, "sequence_contiguous": True, "integrity_findings": 0,
                 "invalid_rows": [{"seq": seq, "truncated_traversals": [str(rule["traversals"][0])],
                                   "read_errors": 0, "filled_zero": 0} for seq in invalid],
                 "windows": synthetic_windows(protocol, length, invalid)}
        verdict = _verdict(protocol, None, length, role_rule, True, facts)
        out.append({"key": key, "case": case, "rows": length, "invalid_seq": invalid, "windows": verdict["windows"],
                    "score_coverage": verdict["score_coverage"], "gate": verdict["gate"],
                    "accepted": verdict["accepted"], "codes": verdict["codes"]})
    return out
