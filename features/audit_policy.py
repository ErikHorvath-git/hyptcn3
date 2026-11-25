"""Bounds of the session audit checks and the register of exceptions (proposal 6.2 and chapter 11 point 4).

A protocol of schema 3 states both in sections of its own:

    "audit": {"lateness_max_s": 0.5, "cycle_ms_max": {"delta": 1500, "full": 3500},
              "periodicity": {"equal_spacings": 3, "min_spacing_rows": 2, "note": "author's judgment, G0"},
              "warnings_allowed": null, "rule_closed_rows_max": null,
              "collector_majflt_max": null, "collector_majflt_note": "...",
              "early_stop": {"marked_rows_rate_per_type": {"<event type>": null, ...}, "periodicity_stops": true,
                             "note": "..."},
              "traffic": {"offered_load_tolerance": 0.2, "arrival_cv": [0.8, 1.2], "top_objects_share": 0.1,
                          "top_objects_min_requests": 0.5, "success_min": 0.88, "response_size_orders": 2,
                          "think_mean_tolerance_se": 4, "order_share_tolerance_se": 4,
                          "order_share_session_max_s": 242,
                          "background": {"logins_min": 1, "reports_min": 1, "document_max_to_median": 10,
                                         "note": "..."},
                          "note": "..."}}
    "exceptions": {"<id>": {"cause": "...", "decision": "...", "expected": null}, ...}

audit_bounds() is the only reader of "audit" and register() the only reader of "exceptions". Protocols of schema 1
and 2 have neither (None); the checks that need a bound are then not applied and the audit record says so. A value
that a later stage determines (proposal 10.9) is null until then: warnings_allowed null allows no collector warning,
rule_closed_rows_max null leaves that count unevaluated (printed next to the others, never a reason), and so does
collector_majflt_max null (the lead's answer to question Q29, 2026-11-24): the major faults of the collector per cycle,
capture.rusage.majflt of every sidecar, are recorded and printed by the audit of a schema-3 session
(scripts/collection.py majflt_record) and a reason only above a number, which G2 sets by the rule of
collector_majflt_note (null or an integer of at least 0, and a note that says something). "traffic"
holds the bounds of the realism requirements of proposal 5.7 and of the offered-load check of proposal 5.3
(scripts/traffic_log.py realism; package B5b), all determined in G0 (proposal 10.9); order_share_session_max_s is
D_max of the order share (package B13, the lead's answer to Q73 point 1): a user session that starts in [window start
- D_max, window end] of an event window is left out of it, by its start alone.

"early_stop" (package B9b, agent Z, and its fix: F5 of the verification, question Q24; the lead's skeleton B9 row
skoré zastavenie) holds the rule of the early stop of a campaign (proposal 7.5): one rate of marked rows per occurrence
for every event type of events.types (features/acceptance.py MARKED_ROWS_RULE), each null until G3b (proposal 10.9),
and whether a session rejected for periodicity stops the campaign. early_stop(values, protocol, totals) applies it
after every audit to the values of that audit and to the campaign's count since its restart point (EARLY_STOP_RULE;
scripts/campaign.py early_stop_check sums the count), and poisson_quantile gives its bound. EARLY_STOP_MODEL holds the
false-stop rates of the executor's model of the rule, a model and not a measurement, which every record of stage G3b
carries for the owner's decision (the lead's answer to Q24; scripts/gates.py write_record).

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
AUDIT_KEYS = ("lateness_max_s", "cycle_ms_max", "periodicity", "warnings_allowed", "rule_closed_rows_max",
              "collector_majflt_max", "collector_majflt_note", "traffic", "early_stop")
CYCLE_KEYS = ("delta", "full")
PERIODICITY_KEYS = ("equal_spacings", "min_spacing_rows", "note")
# Package B9b (design B9b 1.3) and its fix (F5 of its verification, question Q24): the keys of audit.early_stop.
# marked_rows_rate_per_type has one key per event type of events.types (none without an events section), each the
# rate of marked rows per occurrence (a number of at least 0) or null until G3b (determined_at).
EARLY_STOP_KEYS = ("marked_rows_rate_per_type", "periodicity_stops", "note")
EARLY_STOP_LEVEL = 0.99  # Proposal 10.9: the bound of the early stop is the 99th percentile of a Poisson distribution.
EARLY_STOP_RULE = (
    "the early stop of a campaign (proposal 7.5 and 10.9; the lead's skeleton B9 row skoré zastavenie and its section "
    "5; design B9b 1.3 and its fix, F5 of the verification of B9b, question Q24, accepted by the lead 2026-11-24; "
    "features/audit_policy.py early_stop): after every audit of a completed capture the campaign stops when the audit "
    "rejected the session with the code periodicity and audit.early_stop.periodicity_stops holds (one such session "
    "suffices, the lead's judgment: periodicity is the sign of a systematic cause, and more sessions would fill the "
    "limit of replacements with the same fault), or when the campaign's count C_T of marked rows at an event type T "
    "is above b, the smallest count with P(X <= b) >= 0.99 for X ~ Poisson(rate_T x n_T) (poisson_quantile, Poisson(0) "
    "gives 0): C_T and n_T are the sums of values.marked_rows_by_type and values.event_occurrences_by_type "
    "(features/acceptance.py MARKED_ROWS_RULE) over the audited sessions of both VMs since the count's restart point, "
    "accepted and rejected, replacements included (scripts/campaign.py early_stop_check, one file per session), and "
    "rate_T is the rate of marked rows per occurrence in audit.early_stop.marked_rows_rate_per_type (proposal 10.9: "
    "the rate of G2 and G3b together, determined at G3b); a null rate stops nothing, and C_T and n_T stay printed in "
    "the runner's state. Q24 reads the count of proposal 7.5 as the campaign's, not one session's: the audit of a "
    "session already judges one session (the tolerance of invalid rows, the cap of rule-closed rows), and the early "
    "stop follows a systematic shift of the whole campaign. The count starts at the start of the campaign and starts "
    "again after the campaign's latest recorded ending with an early-stop trigger, which a written analysis answers "
    "before the campaign runs again (scripts/campaign.py RESUME_RULE); a continuation counts on: until its own first "
    "ending with an early-stop trigger its count also holds the audited sessions of the paused campaign it continues "
    "since that campaign's restart point (the accepted text of Q24, 's náhradami aj s pokračovaním', package B11). In "
    "a model of "
    "Poisson counts at one rate per type, not a measurement (the executor's model of Q24, 36 occurrences per type and "
    "six types as in the campaign plan): one comparison stops falsely at most 1 % per type; checked after every "
    "occurrence, 0.12 to 0.28 of healthy campaigns stop falsely at rates of 0.01 to 3 per occurrence, where the count "
    "of one session against one bound per type would stop 0.23 to 0.88 of them (EARLY_STOP_MODEL, which every record "
    "of stage G3b carries for the owner's decision: the lead's answer to Q24). A protocol of schema 1 or 2 has no "
    "audit section and no early stop")
# The lead's answer to Q24 (2026-11-24): the numbers of the model of the early stop, which every record of stage G3b
# carries for the owner's decision (scripts/gates.py write_record, values.owner_information); no criterion. Each range
# is the smallest and the largest value over the rates 0.01, 0.05, 0.1, 0.3, 1 and 3 per occurrence of the exact model,
# rounded to two decimals (features/tests/test_early_stop.py recomputes them).
EARLY_STOP_MODEL = {
    "kind": "a model of Poisson counts at one rate of marked rows per occurrence and event type, not a measurement",
    "premise": {"occurrences_per_type": 36, "types": 6, "rates_per_occurrence": [0.01, 3], "level": EARLY_STOP_LEVEL,
                "rates_note": "the range of rates the executor's model examined (judgment: the real rates are set at "
                              "G3b from G2 and G3b together, proposal 10.9)",
                "plan": "the campaign plan of config/collection-v5.json without replacements (protocol_v5.plan, mode "
                        "campaign: 36 occurrences of each of its 6 event types)",
                "checked": "after every audit, so after every occurrence of each type"},
    "per_comparison_max": 0.01,
    "false_stops_per_type": [0.02, 0.05],
    "false_stops_per_campaign": [0.12, 0.28],
    "per_session_reading": [0.23, 0.88],
    "caveats": ["replacements add occurrences beyond the 36 per type of the plan, and every one more comparison",
                "overdispersion of the marked rows per occurrence against the Poisson model raises the false-stop "
                "rates (G3b checks the dispersion, dokazy/B9/odlozene_B9b.md)",
                "every restart after an early stop starts a new count, the premise again",
                "the count of a continuation runs on from the paused campaign, so a pause and its continuation keep "
                "one count (package B11)"],
    "source": "the executor's exact model of Q24 (dokazy/B9/navrh/skore_zastavenie_model.py and its .txt), confirmed "
              "by the verifier's Monte Carlo of 40000 campaigns with poisson_quantile (dokazy/B9/overenie_B9b, F5)",
}
TRAFFIC_KEYS = ("offered_load_tolerance", "arrival_cv", "top_objects_share", "top_objects_min_requests", "success_min",
                "response_size_orders", "think_mean_tolerance_se", "order_share_tolerance_se",
                "order_share_session_max_s", "background", "note")
BACKGROUND_KEYS = ("logins_min", "reports_min", "document_max_to_median", "note")
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
    # Q29: the bound of the collector's major faults per cycle, null until G2 or a count (a bool is no count).
    faults = a["collector_majflt_max"]
    if faults is not None and (type(faults) is not int or faults < 0):
        raise ValueError("invalid audit bounds: collector_majflt_max")
    if not _text(a["collector_majflt_note"]):
        raise ValueError("invalid audit bounds: collector_majflt_note")
    _traffic_bounds(a["traffic"])
    _early_stop_bounds(a["early_stop"], protocol)
    return a


def _text(value):
    return type(value) is str and bool(value.strip())


def event_types(protocol):
    """The event types of a protocol, the keys of events.types (sorted), [] for a protocol without an events section;
    None when its events section names no types as an object (malformed: the value check of audit.early_stop
    refuses it)."""
    if "events" not in protocol:
        return []
    events = protocol["events"]
    types = events.get("types") if type(events) is dict else None
    return sorted(types) if type(types) is dict else None


def _early_stop_bounds(e, protocol):
    """ValueError `invalid audit bounds: early_stop[.<key>]` for the first malformed key of audit.early_stop (package
    B9b and its fix, Q24): exactly the keys of EARLY_STOP_KEYS; marked_rows_rate_per_type an object with one rate per
    event type of events.types (event_types: none without an events section), each null (until G3b, proposal 10.9) or
    a finite number of at least 0 (marked rows per occurrence); periodicity_stops a boolean (true by the lead's
    skeleton B9 row skoré zastavenie: false would turn that stop off, a change of a G0 value); a note that says
    something."""
    def refuse(key):
        raise ValueError("invalid audit bounds: early_stop" + ("." + key if key else ""))
    if type(e) is not dict or set(e) != set(EARLY_STOP_KEYS):
        refuse("")
    rates, types = e["marked_rows_rate_per_type"], event_types(protocol)
    if (type(rates) is not dict or types is None or sorted(rates) != types
            or any(r is not None and not (_number(r) and r >= 0) for r in rates.values())):
        refuse("marked_rows_rate_per_type")
    if type(e["periodicity_stops"]) is not bool:
        refuse("periodicity_stops")
    if not _text(e["note"]):
        refuse("note")


def poisson_quantile(mean):
    """The bound of the early stop (EARLY_STOP_RULE, proposal 10.9): the smallest b with P(X <= b) >= EARLY_STOP_LEVEL
    for X ~ Poisson(mean), 0 for a mean of 0; ValueError for a mean that is no finite number of at least 0. Summed in
    logarithms, so a large mean does not underflow."""
    if not (_number(mean) and mean >= 0):
        raise ValueError(f"the mean of a Poisson distribution is a finite number of at least 0, not {mean!r}")
    if mean == 0:
        return 0
    bound, cdf = 0, 0.0
    while True:
        cdf += math.exp(bound * math.log(mean) - mean - math.lgamma(bound + 1))
        if cdf >= EARLY_STOP_LEVEL:
            return bound
        bound += 1


def _count(value):
    return type(value) is int and value >= 0


def early_stop(values, protocol, totals):
    """EARLY_STOP_RULE after the audit of one session (scripts/collection.py audit_session) under `protocol`: None (no
    stop), or the stop {rule, cause, type, count, bound, occurrences, rate}.

    values: the values of the audit record (its acceptance codes). totals: the campaign's count since its restart
    point, this session included (scripts/campaign.py early_stop_check): {event type: {"marked": C_T, "occurrences":
    n_T}}. cause periodicity: values.acceptance.codes name periodicity and audit.early_stop.periodicity_stops holds;
    type null, count the longest run of equal spacings the audit recorded (values.timing.periodic_run.equal_spacings,
    null when the record holds none), bound audit.periodicity.equal_spacings, the run that rejects; occurrences and
    rate null. cause marked_rows: the first event type (sorted) whose C_T is above b = poisson_quantile(rate_T x n_T),
    with C_T, b, n_T and rate_T; a type with a null rate is not judged. None under a protocol of schema 1 or 2.
    ValueError by name for values without the acceptance codes, and for a type with a rate whose C_T or n_T the totals
    do not hold as counts: a count is never taken as 0."""
    bounds = audit_bounds(protocol)
    if bounds is None:
        return None
    acceptance = values.get("acceptance") if type(values) is dict else None
    codes = acceptance.get("codes") if type(acceptance) is dict else None
    if type(codes) is not list:
        raise ValueError("early stop: the audit record holds no acceptance codes (values.acceptance.codes)")
    rule = bounds["early_stop"]
    if rule["periodicity_stops"] and "periodicity" in codes:
        timing = values.get("timing")
        run = timing.get("periodic_run") if type(timing) is dict else None
        count = run.get("equal_spacings") if type(run) is dict else None
        return {"rule": EARLY_STOP_RULE, "cause": "periodicity", "type": None,
                "count": count if type(count) is int else None, "bound": bounds["periodicity"]["equal_spacings"],
                "occurrences": None, "rate": None}
    for kind, rate in sorted(rule["marked_rows_rate_per_type"].items()):
        if rate is None:
            continue
        total = totals.get(kind) if type(totals) is dict else None
        marked, occurrences = (total.get("marked"), total.get("occurrences")) if type(total) is dict else (None, None)
        if not (_count(marked) and _count(occurrences)):
            raise ValueError(f"early stop: the campaign's count holds no marked rows and occurrences of event type "
                             f"{kind} (scripts/campaign.py early_stop_check), whose rate is {rate}")
        bound = poisson_quantile(rate * occurrences)
        if marked > bound:
            return {"rule": EARLY_STOP_RULE, "cause": "marked_rows", "type": kind, "count": marked, "bound": bound,
                    "occurrences": occurrences, "rate": rate}
    return None


def _traffic_bounds(t):
    """ValueError `invalid audit bounds: traffic[.<key>]` for the first malformed key of audit.traffic: every key of
    TRAFFIC_KEYS and no other; shares strictly between 0 and 1; the CV interval contains 1 (unit Poisson spacings);
    the top objects' minimum share of the requests above their share of the objects; positive orders of magnitude
    and tolerances in standard errors; D_max of the order share (order_share_session_max_s, package B13) a positive
    number of seconds; the background bounds of corp with counts of at least 1 and a document ratio above 1; notes
    that say something."""
    def refuse(key):
        raise ValueError("invalid audit bounds: traffic" + ("." + key if key else ""))
    if type(t) is not dict or set(t) != set(TRAFFIC_KEYS):
        refuse("")
    for key in ("offered_load_tolerance", "top_objects_share", "success_min"):
        if not (_number(t[key]) and 0 < t[key] < 1):
            refuse(key)
    cv = t["arrival_cv"]
    if not (type(cv) is list and len(cv) == 2 and all(map(_number, cv)) and 0 < cv[0] <= 1 <= cv[1]):
        refuse("arrival_cv")
    if not (_number(t["top_objects_min_requests"]) and t["top_objects_share"] < t["top_objects_min_requests"] <= 1):
        refuse("top_objects_min_requests")
    for key in ("response_size_orders", "think_mean_tolerance_se", "order_share_tolerance_se",
                "order_share_session_max_s"):
        if not (_number(t[key]) and t[key] > 0):
            refuse(key)
    b = t["background"]
    if (type(b) is not dict or set(b) != set(BACKGROUND_KEYS)
            or any(type(b[key]) is not int or b[key] < 1 for key in ("logins_min", "reports_min"))
            or not (_number(b["document_max_to_median"]) and b["document_max_to_median"] > 1) or not _text(b["note"])):
        refuse("background")
    if not _text(t["note"]):
        refuse("note")


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
    """{id: {"observed": n, "expected": e, "over": n > e}} for every registered exception; expected is None
    without a register.

    over is false wherever expected is None (lead's answer to Q2): the expected count is the largest count of the
    exception in one accepted session of the last G3a run, so until then nothing is over it. It is printed only and
    never a reason for refusal; the record at closing (B9) counts the sessions over it.
    """
    unknown = set(counts) - set(TOLERATED)
    if unknown:
        raise ValueError("unregistered exception: " + ", ".join(sorted(map(str, unknown))))
    entries = register(protocol)
    record = {}
    for name in TOLERATED:
        observed, expected = counts.get(name, 0), entries[name]["expected"] if entries else None
        record[name] = {"observed": observed, "expected": expected,
                        "over": expected is not None and observed > expected}
    return record


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
