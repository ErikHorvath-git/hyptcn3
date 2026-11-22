"""Bounds of the session audit checks and the register of exceptions (proposal 6.2 and chapter 11 point 4).

A protocol of schema 3 states both in sections of its own:

    "audit": {"lateness_max_s": 0.5, "cycle_ms_max": {"delta": 1500, "full": 3500},
              "periodicity": {"equal_spacings": 3, "min_spacing_rows": 2, "note": "author's judgment, G0"},
              "warnings_allowed": null, "rule_closed_rows_max": null}
    "exceptions": {"<id>": {"cause": "...", "decision": "...", "expected": null}, ...}

audit_bounds() is the only reader of "audit" and register() the only reader of "exceptions". Protocols of schema 1
and 2 have neither (None); the checks that need a bound are then not applied and the audit record says so. A value
that a later stage determines (proposal 10.9) is null until then: warnings_allowed null allows no collector warning,
rule_closed_rows_max null leaves that count unevaluated (printed next to the others, never a reason).

Every place of the audit code that admits a condition which would otherwise reject a session calls tolerate() with
the condition's id. TOLERATED lists the ids; the register of a schema-3 protocol names exactly these, each with its
cause, the decision that admits it and the count expected per session, and the audit prints the observed count
next to the expected one (exceptions_record). sites() finds the tolerate() calls in source code, so a test fails on
a tolerance site whose id is not registered.
"""
import ast
import math
from pathlib import Path
import re

SCHEMA_3 = "hyptcn3/collection-protocol/3"
AUDIT_KEYS = ("lateness_max_s", "cycle_ms_max", "periodicity", "warnings_allowed", "rule_closed_rows_max")
CYCLE_KEYS = ("delta", "full")
PERIODICITY_KEYS = ("equal_spacings", "min_spacing_rows", "note")
REGISTER_KEYS = ("cause", "decision", "expected")
# Conditions the audit admits instead of rejecting the session; the comment names where tolerate() counts each.
TOLERATED = (
    "invalid_rows",                # scripts/collection.py: invalid rows the invalid_rows rule covers (acceptance)
    "rule_closed_rows",            # scripts/collection.py: process lists a parser rule closed (prev, tail, meet)
    "unconfirmed_findings",        # scripts/collection.py: cross-view differences seen in one snapshot only
    "inconclusive_integrity",      # scripts/collection.py: integrity checks that could not conclude
    "collector_warnings",          # scripts/collection_logs.py: collector warnings that match an allowed pattern
    "event_traffic_exit",          # scripts/collection_logs.py: traffic generator exit code 1 in an event session
    "event_unit_restarts",         # scripts/collection_logs.py: units an event type restarts by design
    "event_window_requests",       # scripts/collection_logs.py: requests inside an event window
    "event_window_health_checks",  # scripts/collection_logs.py: health polls without request id inside a window
    "event_window_journal",        # scripts/collection_logs.py: tracebacks and worker errors inside a window
    "event_window_nginx_errors",   # scripts/collection_logs.py: nginx error lines inside a window
)


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _section(protocol, key):
    if type(protocol) is not dict:
        raise ValueError("invalid protocol")
    if protocol.get("schema") != SCHEMA_3:
        if key in protocol:
            raise ValueError(key + " section requires protocol schema 3")
        return None
    if key not in protocol:
        raise ValueError("protocol schema 3 requires the " + key + " section")
    return protocol[key]


def audit_bounds(protocol):
    """The protocol's audit bounds (schema 3), None for older schemas; ValueError when the section is malformed."""
    a = _section(protocol, "audit")
    if a is None:
        return None
    interval = protocol.get("interval_s")
    if type(a) is not dict or set(a) != set(AUDIT_KEYS) or not _number(interval) or interval <= 0:
        raise ValueError("invalid audit bounds")
    late, cycle, period = a["lateness_max_s"], a["cycle_ms_max"], a["periodicity"]
    if not _number(late) or not 0 < late < interval:
        raise ValueError("invalid audit bounds: lateness_max_s")
    if (type(cycle) is not dict or set(cycle) != set(CYCLE_KEYS) or not all(_number(cycle[k]) for k in CYCLE_KEYS)
            or not 0 < cycle["delta"] <= cycle["full"] < interval * 1000):
        raise ValueError("invalid audit bounds: cycle_ms_max")
    if (type(period) is not dict or set(period) != set(PERIODICITY_KEYS)
            or type(period["equal_spacings"]) is not int or period["equal_spacings"] < 2
            or type(period["min_spacing_rows"]) is not int or period["min_spacing_rows"] < 2
            or type(period["note"]) is not str or not period["note"].strip()):
        raise ValueError("invalid audit bounds: periodicity")
    allowed = a["warnings_allowed"]
    if allowed is not None:
        if (type(allowed) is not list or len(set(map(str, allowed))) != len(allowed)
                or any(type(x) is not str or not x for x in allowed)):
            raise ValueError("invalid audit bounds: warnings_allowed")
        for pattern in allowed:
            try:
                re.compile(pattern)
            except re.error:
                raise ValueError("invalid audit bounds: warnings_allowed") from None
    cap = a["rule_closed_rows_max"]
    if cap is not None and (type(cap) is not int or cap < 0):
        raise ValueError("invalid audit bounds: rule_closed_rows_max")
    return a


def register(protocol):
    """The protocol's register of exceptions (schema 3), None for older schemas; ValueError when malformed.

    It names exactly the ids of TOLERATED: an exception the audit code admits without an entry here, and an entry
    for nothing the code admits, both refuse the protocol.
    """
    r = _section(protocol, "exceptions")
    if r is None:
        return None
    if type(r) is not dict or set(r) != set(TOLERATED):
        raise ValueError("register of exceptions differs from the exceptions the audit admits")
    for entry in r.values():
        if (type(entry) is not dict or set(entry) != set(REGISTER_KEYS)
                or any(type(entry[k]) is not str or not entry[k].strip() for k in ("cause", "decision"))
                or entry["expected"] is not None and (not _number(entry["expected"]) or entry["expected"] < 0)):
            raise ValueError("invalid register of exceptions")
    return r


def tolerate(counts, name, n=1):
    """Count `n` occurrences of the registered exception `name` in `counts` (a collections.Counter)."""
    if name not in TOLERATED:
        raise ValueError("unregistered exception: " + str(name))
    if type(n) is not int or n < 0:
        raise ValueError("invalid exception count")
    counts[name] += n


def exceptions_record(protocol, counts):
    """{id: {"observed": n, "expected": e}} for every registered exception; expected is None without a register."""
    unknown = set(counts) - set(TOLERATED)
    if unknown:
        raise ValueError("unregistered exception: " + ", ".join(sorted(map(str, unknown))))
    entries = register(protocol)
    return {name: {"observed": counts.get(name, 0), "expected": entries[name]["expected"] if entries else None}
            for name in TOLERATED}


def sites(paths):
    """Every tolerate() call in the given source files: (path, line, id), id None when it is not a string literal."""
    found = []
    for path in paths:
        for node in ast.walk(ast.parse(Path(path).read_text(), str(path))):
            if isinstance(node, ast.Call) and (getattr(node.func, "id", None) == "tolerate"
                                               or getattr(node.func, "attr", None) == "tolerate"):
                arg = node.args[1] if len(node.args) > 1 else None
                name = arg.value if isinstance(arg, ast.Constant) and type(arg.value) is str else None
                found.append((str(path), node.lineno, name))
    return found
