"""The functions package B18 replaced, frozen as they were at df3cee5 (a test-only reference, decision 2 of B18).

They read the traffic logs whole, as before B18: scripts/traffic_log.py read_jsonl (read_bytes and split), _routes,
wall_clock, _v5_problems, summarize and realism; scripts/collection_logs.py audit_logs (its sections metadata with the
exit code of the generator, manifest, segments, traffic, realism and correlation read the request log and the guest
segments whole); scripts/lab_trial.py measure_phase, traffic_summary, analysis and peak_of; scripts/campaign_report.py
load_traffic; scripts/collection.py file_record (the logs manifest of a capture). Each function is the text of its
source at df3cee5, unchanged; what it calls that B18 left unchanged comes from the module itself, and `traffic_log`
here is scripts/traffic_log.py with these functions in place of its own (_TrafficLog).
scripts/tests/test_traffic_stream_b18.py compares the new functions with these: every result must be the same, the
problems in their order with their details, and every exception of the same type with the same text. Not measurement
code (scripts/tests): it holds as much memory as the code before B18 did, so the tests run it on small logs.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import re

from features.audit_policy import audit_bounds, tolerate
from scripts import host_monitor
from scripts import traffic_log as _traffic_log
from scripts.campaign_report import DataError, _g2t_hash, _g2t_ratio, _number, unix_of
from scripts.collection_logs import (CALL_MARGIN_S, CONTROL_CALLS, EVENT_UNITS, LOG_EXCEPTIONS, NEGATIVE_PROPERTY,
                                     NGINX_TIME, REQUIRED, REQUIRED_UNITS, RESTART_KEYS, SCHEMA, SERVICE_LINE, SERVICES,
                                     SHA256, UNIT_LINE, WORKER_ERROR, auth_checked, collector_line, digest,
                                     event_window, finite, local_file, qemu_unswapped, read_json, unix, upstream)
from scripts.lab_trial import INTERVALS, NO_DROP_REASON, PEAK_TOLERANCE, REQUESTS, drop_reasons, expected, failure
from scripts.protocol_v5 import (CONTROL_RECORD_CLASS, CONTROL_ROLE, CONTROLS_SCHEMA, SCHEMA as SCHEMA_3,
                                 plans_events)
from scripts.traffic_log import (ARRIVAL_KEYS, CUSTOMER_NAME, DROP_REASONS, INTERVAL_SCHEMA_2, OUTCOMES, PHASES,
                                 RATE_SOURCES, REQUEST_SCHEMA, REQUEST_SCHEMA_2, SCHEMA_PAIRS, SEED_PURPOSES,
                                 SUMMARY_SCHEMA, THINK_LAG_S, TIME_EPS, V5_END_KEYS, V5_HEADER_KEYS, V5_INTERVAL_KEYS,
                                 V5_PROFILES, V5_REQUEST_KEYS, WALL_CLOCK_FIELDS, WALL_CLOCK_TOLERANCE_S, Envelope,
                                 Problems, _finite, _latency, _record_id, _requirement, _round, _unix, bucket_index,
                                 envelope_problem, first_schema, hist_percentile, merge_hist, object_kind, percentile)


# ------------------------------------------------------------------ scripts/traffic_log.py at df3cee5

def read_jsonl(path, schema=None):
    """Parse a log into (records, problems) without trusting its completeness.

    Problems: empty_file, torn_last_line (unterminated or invalid last line),
    corrupt_line:<lineno>, missing_header, schema_mismatch:<header schema or lineno>
    (header differs from `schema`, or a record differs from the header) and
    n_discontinuous:<lineno> (record numbers must run 0, 1, 2, ...).
    """
    raw = Path(path).read_bytes()
    problems = []
    if not raw:
        return [], ["empty_file"]
    lines = raw.split(b"\n")
    if lines.pop():
        problems.append("torn_last_line")  # bytes after the final newline
    numbered = []
    for lineno, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("not an object")
        except ValueError:
            last = lineno == len(lines) and "torn_last_line" not in problems
            problems.append("torn_last_line" if last else f"corrupt_line:{lineno}")
            continue
        numbered.append((lineno, record))
    records = [record for _, record in numbered]
    if not records:
        return records, problems + ["missing_header"]
    header = records[0]
    if header.get("type") != "header" or not header.get("schema"):
        problems.append("missing_header")
    if schema and header.get("schema") != schema:
        problems.append(f"schema_mismatch:{header.get('schema')}")
    previous = None
    for lineno, record in numbered:
        if record is not header and record.get("schema") != header.get("schema"):
            problems.append(f"schema_mismatch:{lineno}")
        n = record.get("n")
        if not isinstance(n, int) or n != (0 if previous is None else previous + 1):
            problems.append(f"n_discontinuous:{lineno}")
        previous = n if isinstance(n, int) else previous
    return records, problems


def _routes(records):
    routes = {}
    for record in records:
        entry = routes.setdefault(f"{record.get('method')} {record.get('route')}",
                                  {"requests": 0, "ok": 0, "errors": 0, "status_codes": Counter()})
        entry["requests"] += 1
        entry["ok" if record.get("outcome") == "ok" else "errors"] += 1
        entry["status_codes"][str(record.get("status", "none")) if record.get("status") is not None else "none"] += 1
    return {key: dict(entry, status_codes=dict(entry["status_codes"])) for key, entry in sorted(routes.items())}


def wall_clock(origin, log, records):
    """Package B16: "<kind>:<id>" of the first of `records` (the records of one log of a /2 pair, `log` its name)
    whose wall time differs from `origin`, the start_unix of the request log's header, plus its own monotonic time by
    more than WALL_CLOCK_TOLERANCE_S, by the fields of WALL_CLOCK_FIELDS; None when none does. A wall time that is
    missing, or no ISO-8601 time with a timezone, differs; an interval's wall times count where it carries them (the
    generator derives them from start_unix). A field pair whose monotonic time is no finite number is left out: the
    check that reads that time names it (arrival_malformed, request_malformed, interval_v5_malformed,
    requests:end_mono_mismatch, intervals_not_to_end, and for the post marker the session audit's traffic_stop)."""
    for record in records:
        kind = record.get("type")
        for wall, mono in WALL_CLOCK_FIELDS.get(kind, ()):
            if not _finite(record.get(mono)) or kind == "interval" and wall not in record:
                continue
            try:
                agrees = abs(_unix(record[wall]) - (origin + record[mono])) <= WALL_CLOCK_TOLERANCE_S
            except (KeyError, TypeError, ValueError, OverflowError):
                agrees = False
            if not agrees:
                return f"{kind}:{_record_id(kind, log, record)}"
    return None


def _v5_problems(problems, header_r, header_i, requests, reqs, ivs, end_r):
    """The cross-checks of a /2 log pair (design B5b 1.4) into `problems`; returns the counts of its arrivals.

    The header names every v5 field, the same in both logs, with a valid envelope, rate, rate source, seeds and
    warmup and the profile's max_concurrent and client error statuses. Arrival records: complete, ids
    <run_id>-u<n> once each, in time order; an admitted one found fewer than max_concurrent user sessions in
    progress, a dropped one exactly max_concurrent. Interval records: their offered, admitted and dropped counts
    are the arrivals by arrival time (within TIME_EPS of a bound either side counts), offered = admitted +
    dropped, planned = rate x the integral of the envelope over the interval (6 decimals; intervals after D are
    not compared), 0 <= active_max <= max_concurrent. Requests: the v5 fields, a user session that arrived before
    and was admitted, think_s null exactly for the first request of its user session, an intended status among
    the profile's client error statuses. The end record of the request log counts the arrivals, the admitted and
    the dropped ones, and completed + in progress at stop = admitted.

    The customers and the drops (finding F1 of the B5c verification, package B10): an arrival names its customer and
    its drop reason (both keys, null where none); exactly a dropped one has a reason of DROP_REASONS; max_concurrent
    with exactly max_concurrent in progress (arrival_cap), all_customers_held only under profile eshop and below the
    cap with at least as many user sessions in progress as lab/seed.py has customers, the fewest that can hold them
    all (arrival_customers); a customer is one of lab/seed.py's, of an admitted user session only (arrival_customer);
    and no customer is held by two user sessions at once, each from its arrival to the end of its last request
    (customer_held_twice: the later one).
    """
    from lab import seed  # The customers of the lab (lab/seed.py SIZES), as scripts/host_traffic.py Lab reads them.
    customers = seed.SIZES["customers"]
    head = header_r or {}
    for key in V5_HEADER_KEYS:
        if header_r is not None and key not in header_r:
            problems.add("v5_header_missing", key)
        elif header_r is not None and header_i is not None and header_i.get(key) != header_r[key]:
            problems.add("v5_header_mismatch", key)
    if head.get("profile") not in V5_PROFILES:
        problems.add("profile_unknown", head.get("profile"))
    why = envelope_problem(head.get("envelope"))
    if why:
        problems.add("envelope_invalid", why)
    envelope = None if why else Envelope(head["envelope"])
    rate = head.get("rate")
    if not (_finite(rate) and rate > 0):
        problems.add("rate_invalid")
        rate = None
    if head.get("rate_source") not in RATE_SOURCES:
        problems.add("rate_source_invalid")
    seeds = head.get("seeds")
    if type(seeds) is not dict or not all(type(seeds.get(key)) is int for key in SEED_PURPOSES):
        problems.add("seeds_invalid")
    warmup = head.get("warmup_s")
    if not (_finite(warmup) and 0 <= warmup and (envelope is None or warmup < envelope.end)):
        problems.add("warmup_invalid")
    params = head.get("profile_parameters")
    cap = params.get("max_concurrent") if type(params) is dict else None
    if type(cap) is not int or cap < 1:
        problems.add("profile_parameters_invalid", "max_concurrent")
        cap = None
    errors = params.get("client_errors") if type(params) is dict else None
    statuses = errors.get("statuses") if type(errors) is dict else None
    if not (type(statuses) is list and statuses and all(type(s) is int for s in statuses)):
        problems.add("profile_parameters_invalid", "client_errors")
        statuses = None

    # Arrival records. A drop for held customers is judged under a known profile (an unknown one is its own problem).
    known, eshop = head.get("profile") in V5_PROFILES, head.get("profile") == "eshop"
    pattern = re.compile(re.escape(str(head.get("run_id"))) + r"-u\d+")
    arrivals, sessions, latest = [], {}, None
    for record in (r for r in requests if r.get("type") == "arrival"):
        uid = record.get("user_session")
        if (any(key not in record for key in ARRIVAL_KEYS) or type(uid) is not str
                or type(record["admitted"]) is not bool or type(record["active"]) is not int or record["active"] < 0
                or not _finite(record["t_mono"]) or record["phase"] not in PHASES
                or type(record["customer"]) not in (str, type(None))
                or type(record["drop_reason"]) not in (str, type(None))):
            problems.add("arrival_malformed", uid if type(uid) is str else None)
            continue
        if not pattern.fullmatch(uid):
            problems.add("user_session_id", uid)
        if uid in sessions:
            problems.add("duplicate_user_session", uid)
        sessions[uid] = record
        if latest is not None and record["t_mono"] < latest:
            problems.add("arrival_order", uid)
        latest = record["t_mono"] if latest is None else max(latest, record["t_mono"])
        reason = record["drop_reason"]
        if record["admitted"] is (reason is not None) or reason not in (None, *DROP_REASONS):
            problems.add("arrival_drop_reason", uid)
        elif reason == DROP_REASONS[1]:  # Judged by the profile and the cap, once both are known.
            if known and cap is not None and not (eshop and customers <= record["active"] < cap):
                problems.add("arrival_customers", uid)
        elif cap is not None and (record["active"] >= cap if record["admitted"] else record["active"] != cap):
            problems.add("arrival_cap", uid)
        name = CUSTOMER_NAME.fullmatch(record["customer"]) if record["customer"] is not None else None
        if record["customer"] is not None and not (record["admitted"] and name and 1 <= int(name[1]) <= customers):
            problems.add("arrival_customer", uid)
        arrivals.append(record)

    # Interval records: the arrivals in time order fill the intervals in their order, each with as many as it
    # claims; every one must lie in its interval.
    queue, position = sorted(arrivals, key=lambda a: a["t_mono"]), 0
    for iv in ivs:
        index = iv.get("interval")
        if (any(type(iv.get(key)) is not int or iv[key] < 0 for key in V5_INTERVAL_KEYS if key != "planned_sessions")
                or not _finite(iv.get("planned_sessions")) or iv["planned_sessions"] < 0
                or not _finite(iv.get("mono_start")) or not _finite(iv.get("mono_end"))):
            problems.add("interval_v5_malformed", index)
            position = None  # The counts of later intervals can no longer be followed.
            continue
        if position is not None:
            block = queue[position:position + iv["offered_sessions"]]
            position += iv["offered_sessions"]
            if len(block) < iv["offered_sessions"] or not all(
                    iv["mono_start"] - TIME_EPS <= a["t_mono"] <= iv["mono_end"] + TIME_EPS for a in block):
                problems.add("interval_arrivals", index)
            else:
                admitted = sum(a["admitted"] for a in block)
                for key, count in (("admitted_sessions", admitted), ("dropped_sessions", len(block) - admitted)):
                    if iv[key] != count:
                        problems.add("interval_sessions", f"{index}:{key}:{iv[key]}!={count}")
                for a in block:
                    if a["phase"] != iv.get("phase"):
                        problems.add("arrival_phase_mismatch", f"{index}:{a['user_session']}")
        if iv["offered_sessions"] != iv["admitted_sessions"] + iv["dropped_sessions"]:
            problems.add("interval_sessions", f"{index}:offered")
        if envelope is not None and rate is not None and iv["mono_end"] <= envelope.end + TIME_EPS:
            # Both bounds and the count carry 6 decimals: the planned count is exact to 1e-6 (1 + rate).
            planned = rate * envelope.integral(iv["mono_start"], iv["mono_end"])
            if abs(iv["planned_sessions"] - planned) > 1e-6 * (1 + rate):
                problems.add("planned_sessions", index)
        if cap is not None and iv["active_max"] > cap:
            problems.add("active_max", index)
    if position is not None and position < len(queue):
        problems.add("arrivals_outside_intervals", len(queue) - position)

    # Requests of user sessions.
    admitted_ids = {uid for uid, a in sessions.items() if a["admitted"]}
    by_session = defaultdict(list)
    for r in reqs:
        rid = r.get("rid")
        if (any(key not in r for key in V5_REQUEST_KEYS) or type(r["user_session"]) is not str
                or type(r["step"]) is not str or not r["step"] or type(r["object"]) not in (int, str, type(None))
                or type(r["intended_status"]) not in (int, type(None))
                or r["think_s"] is not None and not (_finite(r["think_s"]) and r["think_s"] >= 0)):
            problems.add("request_v5_malformed", rid)
            continue
        uid = r["user_session"]
        if r["intended_status"] is not None and (statuses is None or r["intended_status"] not in statuses):
            problems.add("intended_status_unknown", rid)
        if uid not in sessions:
            problems.add("request_user_session_unknown", rid)
        elif uid not in admitted_ids:
            problems.add("request_user_session_dropped", rid)
        elif _finite(r.get("t_start_mono")):
            if r["t_start_mono"] < sessions[uid]["t_mono"] - TIME_EPS:
                problems.add("request_before_arrival", rid)
            by_session[uid].append(r)  # The order of think times is judged in admitted user sessions only.
    for rows in by_session.values():
        rows.sort(key=lambda r: r["t_start_mono"])
        for i, r in enumerate(rows):
            if i == 0 and r["think_s"] is not None:
                problems.add("think_s_first", r.get("rid"))
            elif i > 0 and r["think_s"] is None:
                problems.add("think_s_missing", r.get("rid"))
    # One customer per user session in progress (finding F1 of B5c): each holds its customer from its arrival to the
    # end of its last request; a user session whose arrival lies before the end of the one that held it before shares
    # that customer's cart.
    held = defaultdict(list)
    for uid, a in sessions.items():
        if a["admitted"] and a["customer"] is not None:
            ends = [r["t_end_mono"] for r in by_session.get(uid, ()) if _finite(r.get("t_end_mono"))]
            held[a["customer"]].append((a["t_mono"], max([a["t_mono"], *ends]), uid))
    for spans in held.values():
        latest = None  # The latest end of the user sessions that held the customer before.
        for start, end, uid in sorted(spans):
            if latest is not None and start < latest - TIME_EPS:
                problems.add("customer_held_twice", uid)
            latest = end if latest is None else max(latest, end)

    offered = sum(1 for r in requests if r.get("type") == "arrival")
    admitted = sum(a["admitted"] for a in arrivals)
    if end_r is not None:
        invalid = [key for key in V5_END_KEYS if type(end_r.get(key)) is not int or end_r[key] < 0]
        for key in invalid:
            problems.add("requests:end_v5_invalid", key)
        if not invalid:
            for key, count in (("arrivals", offered), ("admitted", admitted), ("dropped", len(arrivals) - admitted)):
                if end_r[key] != count:
                    problems.add("requests:end_arrivals_mismatch", f"{key}:{end_r[key]}!={count}")
            if end_r["user_sessions_completed"] + end_r["user_sessions_in_progress_at_stop"] != end_r["admitted"]:
                problems.add("requests:end_user_sessions_mismatch")
    measure = [a for a in arrivals if a["phase"] == "measure"]
    return {"offered": offered, "admitted": admitted, "dropped": len(arrivals) - admitted,
            "measure": {"offered": len(measure), "admitted": sum(a["admitted"] for a in measure),
                        "dropped": sum(not a["admitted"] for a in measure)}}


def summarize(requests_path, intervals_path, *, session_id=None, schema=None):
    """Audit a request log + interval log pair and summarize the measured phase.

    Every inconsistency becomes a string in result["problems"]; result["clean"] is
    True only when both end records are present and clean. Measured-phase
    percentiles are exact over all request records of that phase. `schema` is the
    request log schema the pair must have (REQUEST_SCHEMA or REQUEST_SCHEMA_2,
    the interval log the matching one); None takes the one the request log names
    when it is one of these, else REQUEST_SCHEMA. A /2 pair is cross-checked
    further (_v5_problems) and its summary counts the arrivals; since package B16
    its headers name a finite start_unix and its records' wall times agree with
    the request log's start_unix plus their monotonic time (wall_clock,
    WALL_CLOCK_TOLERANCE_S). The generator's stop is bound from above by the
    session audit (scripts/collection_logs.py traffic_stop), not here:
    scripts/lab_trial.py drains longer than a session's runner.
    """
    if schema is not None and schema not in SCHEMA_PAIRS:
        raise ValueError("unknown traffic log schema: " + str(schema))
    problems = Problems()
    if schema is None:
        found = first_schema(requests_path)
        schema = found if found in SCHEMA_PAIRS else REQUEST_SCHEMA
    requests, bad = read_jsonl(requests_path, schema)
    for item in bad:
        problems.add("requests", item)
    intervals, bad = read_jsonl(intervals_path, SCHEMA_PAIRS[schema])
    for item in bad:
        problems.add("intervals", item)

    def kind(records, name):
        return [record for record in records if record.get("type") == name]

    def edge(records, index, name):
        return records[index] if records and records[index].get("type") == name else None

    header_r, header_i = edge(requests, 0, "header"), edge(intervals, 0, "header")
    end_r, end_i = edge(requests, -1, "end"), edge(intervals, -1, "end")
    reqs, ivs = kind(requests, "request"), kind(intervals, "interval")
    marks_r, marks_i = kind(requests, "phase"), kind(intervals, "phase")

    # host_traffic.py writes every field read below into both end records; a missing one is a problem.
    for name, end, records in (("requests", end_r, requests), ("intervals", end_i, intervals)):
        if end is None:
            problems.add(f"{name}:end_missing")
            continue
        if not end.get("clean") or end.get("write_errors") != 0:
            problems.add(f"{name}:end_not_clean")
        if end.get("records") != len(records):
            problems.add(f"{name}:records_mismatch", f"{end.get('records')}!={len(records)}")
        if end.get("requests_logged") != len(reqs):
            problems.add(f"{name}:requests_logged_mismatch", f"{end.get('requests_logged')}!={len(reqs)}")
        if end.get("requests_started") != len(reqs):
            problems.add(f"{name}:requests_started_mismatch", f"{end.get('requests_started')}!={len(reqs)}")
        if end.get("in_flight_at_stop") != 0:
            problems.add(f"{name}:in_flight_at_stop", end.get("in_flight_at_stop"))
        if end.get("worker_errors") != 0:
            problems.add(f"{name}:worker_errors", end.get("worker_errors"))
    if header_r and header_i:
        if header_r.get("run_id") != header_i.get("run_id"):
            problems.add("run_id_mismatch")
        if header_r.get("session_id") != header_i.get("session_id"):
            problems.add("session_id_mismatch_between_logs")
    if session_id is not None and header_r and header_r.get("session_id") != session_id:
        problems.add("session_id_mismatch", header_r.get("session_id"))

    # Phase markers: identical in both logs and strictly forward (warmup < measure < post).
    if [(m.get("phase"), m.get("interval")) for m in marks_r] != [(m.get("phase"), m.get("interval")) for m in marks_i]:
        problems.add("phase_marker_mismatch")
    initial = ((header_r or {}).get("config") or {}).get("initial_phase")
    order = [initial] + [m.get("phase") for m in marks_r]
    for previous, current in zip(order, order[1:]):
        if current not in PHASES or previous not in PHASES or PHASES.index(current) <= PHASES.index(previous):
            problems.add("phase_order", f"{previous}->{current}")
    if ivs and initial and ivs[0].get("phase") != initial:
        problems.add("initial_phase_mismatch", ivs[0].get("phase"))

    # Request records: unique ids, known phases/outcomes, durations matching the timestamps.
    by_interval = defaultdict(list)
    for rid, count in Counter(r.get("rid") for r in reqs).items():
        if count > 1:
            problems.add("duplicate_rid", rid)
    for r in reqs:
        by_interval[r.get("interval")].append(r)
        if r.get("phase") not in PHASES:
            problems.add("request_phase_unknown", r.get("rid"))
        if r.get("outcome") not in OUTCOMES:
            problems.add("request_outcome_unknown", r.get("rid"))
        try:
            if abs((r["t_end_mono"] - r["t_start_mono"]) * 1000 - r["duration_ms"]) > .01:
                problems.add("duration_mismatch", r.get("rid"))
        except (KeyError, TypeError):
            problems.add("request_malformed", r.get("rid"))

    # Interval records: contiguous coverage, counts equal to the request records they claim.
    seen, previous = set(), None
    for position, iv in enumerate(ivs):
        index = iv.get("interval")
        if index != position:
            problems.add("interval_index", f"{position}!={index}")
        if index in seen:
            problems.add("interval_duplicate", index)
        seen.add(index)
        members = by_interval.get(index, [])
        try:
            start, end, duration = iv["mono_start"], iv["mono_end"], iv["duration_s"]
            if end < start:
                problems.add("interval_order", index)
            if abs(duration - (end - start)) > 1e-5:
                problems.add("interval_duration", index)
            if previous is not None and abs(start - previous["mono_end"]) > 1e-9:
                problems.add("interval_gap", f"{previous.get('interval')}->{index}")
            if iv.get("phase") not in PHASES:
                problems.add("interval_phase_unknown", index)
            outcomes = Counter(r.get("outcome") for r in members)
            if iv.get("requests") != len(members):
                problems.add("interval_count_mismatch", f"{index}:requests:{iv.get('requests')}!={len(members)}")
            for outcome in OUTCOMES:
                if iv.get(outcome) != outcomes[outcome]:
                    problems.add("interval_count_mismatch", f"{index}:{outcome}:{iv.get(outcome)}!={outcomes[outcome]}")
            buckets = Counter(str(bucket_index(r["duration_ms"])) for r in members)
            buckets_ok = Counter(str(bucket_index(r["duration_ms"])) for r in members if r.get("outcome") == "ok")
            if {k: v for k, v in iv["hist"].items() if v} != dict(buckets) or \
                    {k: v for k, v in iv["hist_ok"].items() if v} != dict(buckets_ok):
                problems.add("interval_hist_mismatch", index)
            codes = Counter("none" if r.get("status") is None else str(r.get("status")) for r in members)
            if {k: v for k, v in iv["status_codes"].items() if v} != dict(codes):
                problems.add("interval_status_mismatch", index)
            for r in members:
                if r.get("phase") != iv.get("phase"):
                    problems.add("interval_phase_mismatch", f"{index}:{r.get('rid')}")
                if not start <= r["t_start_mono"] <= end:
                    problems.add("request_outside_interval", r.get("rid"))
        except (KeyError, TypeError):
            problems.add("interval_malformed", index)
        previous = iv
    for index in by_interval:
        if index not in seen:
            problems.add("interval_missing", index)
    # Package B16 (should_fix 3 of the fifth G0 verification): both bounds are numbers first, so a value that is none
    # (null, a string, a bool, NaN, missing) is refused by name and raises no TypeError; the detail of the end then
    # names the value that is no number.
    if ivs and not (_finite(ivs[0].get("mono_start")) and abs(ivs[0]["mono_start"]) <= 1e-9):
        problems.add("intervals_not_from_origin", ivs[0].get("mono_start"))
    if ivs and end_i:
        last, stop = ivs[-1].get("mono_end"), end_i.get("end_mono")
        if not (_finite(last) and _finite(stop)):
            problems.add("intervals_not_to_end", ",".join(f"{name}:{value!r}" for name, value in
                                                          (("mono_end", last), ("end_mono", stop))
                                                          if not _finite(value)))
        elif not abs(last - stop) <= 1e-9:
            problems.add("intervals_not_to_end", f"{last}!={stop}")

    phases = {}
    for phase in PHASES:
        members = [r for r in reqs if r.get("phase") == phase]
        phase_ivs = [iv for iv in ivs if iv.get("phase") == phase]
        from_intervals = sum(iv.get("requests") or 0 for iv in phase_ivs)
        if from_intervals != len(members):
            problems.add("phase_count_mismatch", f"{phase}:{from_intervals}!={len(members)}")
        if members or phase_ivs:
            phases[phase] = {"requests": len(members), "intervals": len(phase_ivs),
                             "duration_s": round(sum(iv.get("duration_s") or 0 for iv in phase_ivs), 6),
                             **{o: sum(1 for r in members if r.get("outcome") == o) for o in OUTCOMES}}

    # Measured phase: exact percentiles, rate, and the longest pause between successes.
    measure = [r for r in reqs if r.get("phase") == "measure"]
    oks = [r for r in measure if r.get("outcome") == "ok"]
    if not measure:
        problems.add("no_measure_requests")
    elif not oks:
        problems.add("no_ok_requests_in_measure")
    measure_ivs = [iv for iv in ivs if iv.get("phase") == "measure"]
    summary = {"requests": len(measure), "ok": len(oks), "errors": len(measure) - len(oks),
               **{o: sum(1 for r in measure if r.get("outcome") == o) for o in OUTCOMES},
               "intervals": len(measure_ivs),
               "phase_duration_s": round(sum(iv.get("duration_s") or 0 for iv in measure_ivs), 6),
               "phase_mono_start": min((iv["mono_start"] for iv in measure_ivs), default=None),
               "phase_mono_end": max((iv["mono_end"] for iv in measure_ivs), default=None),
               "latency_ms": _latency(sorted(r["duration_ms"] for r in measure)),
               "latency_ok_ms": _latency(sorted(r["duration_ms"] for r in oks)),
               "hist_p95_ms": hist_percentile(merge_hist(*(iv.get("hist", {}) for iv in measure_ivs)), .95),
               "hist_ok_p95_ms": hist_percentile(merge_hist(*(iv.get("hist_ok", {}) for iv in measure_ivs)), .95),
               "routes": _routes(measure)}
    if measure:
        first_start = min(measure, key=lambda r: r["t_start_mono"])
        last_start = max(measure, key=lambda r: r["t_start_mono"])
        first_end = min(measure, key=lambda r: r["t_end_mono"])
        last_end = max(measure, key=lambda r: r["t_end_mono"])
        duration = last_end["t_end_mono"] - first_start["t_start_mono"]
        completions = sorted(r["t_end_mono"] for r in oks)
        summary.update(first_start_utc=first_start["t_start_utc"], last_start_utc=last_start["t_start_utc"],
                       first_end_utc=first_end["t_end_utc"], last_end_utc=last_end["t_end_utc"],
                       first_start_mono=first_start["t_start_mono"], last_end_mono=last_end["t_end_mono"],
                       duration_s=round(duration, 6),
                       request_rate_rps=round(len(measure) / duration, 3) if duration > 0 else None,
                       ok_rate_rps=round(len(oks) / duration, 3) if duration > 0 else None,
                       phase_request_rate_rps=(round(len(measure) / summary["phase_duration_s"], 3)
                                               if summary["phase_duration_s"] > 0 else None),
                       max_ok_completion_gap_s=round(max((b - a for a, b in zip(completions, completions[1:])),
                                                         default=0), 6) if completions else None)

    v5 = schema == REQUEST_SCHEMA_2
    arrivals = _v5_problems(problems, header_r, header_i, requests, reqs, ivs, end_r) if v5 else None
    # Package B15 (should_fix 1 of the fourth G0 verification): realism takes the generator's stop from the request
    # log's end record, and intervals_not_to_end binds only the interval log's copy of end_mono. host_traffic.py
    # (Writer.finish) writes one record into both logs, so the two copies must be equal.
    if v5 and end_r is not None and end_i is not None and not (
            _finite(end_r.get("end_mono")) and _finite(end_i.get("end_mono"))
            and abs(end_r["end_mono"] - end_i["end_mono"]) <= 1e-9):
        problems.add("requests:end_mono_mismatch")
    # Package B16 (should_fix 1 of the fifth G0 verification, Q82): realism places the intervals of the offered load at
    # start_unix of the request log's header plus their monotonic time, and features/qualification.py offered_load at
    # the interval log's (the log audit refuses two headers with different ones: traffic_headers_disagree). Every
    # header names a finite start_unix, and every record's wall time lies within WALL_CLOCK_TOLERANCE_S of the
    # request log's start_unix plus its monotonic time; the first that does not names the refusal.
    if v5:
        for name, header in (("requests", header_r), ("intervals", header_i)):
            if header is not None and not _finite(header.get("start_unix")):
                problems.add(f"{name}:start_unix_invalid")
        origin = (header_r or {}).get("start_unix")
        found = _finite(origin) and (wall_clock(origin, "requests", requests)
                                     or wall_clock(origin, "intervals", intervals))
        if found:
            problems.add("wall_clock", found)
    clean = all(end is not None and end.get("clean") and not end.get("write_errors") for end in (end_r, end_i))
    return {"schema": SUMMARY_SCHEMA, "log_schema": schema, "requests_path": str(requests_path),
            "intervals_path": str(intervals_path),
            "session_id": (header_r or {}).get("session_id"), "run_id": (header_r or {}).get("run_id"),
            "header_present": {"requests": header_r is not None, "intervals": header_i is not None},
            "end_present": {"requests": end_r is not None, "intervals": end_i is not None},
            "clean": clean, "problems": problems.result(),
            "records": {"requests": len(requests), "intervals": len(intervals), "request_records": len(reqs),
                        "interval_records": len(ivs), "phase_markers": len(marks_r),
                        **({"arrival_records": arrivals["offered"]} if v5 else {})},
            **({"arrivals": arrivals} if v5 else {}),
            "phases": phases, "phase_markers": [{"phase": m.get("phase"), "previous": m.get("previous"),
                                                  "t_utc": m.get("t_utc"), "t_mono": m.get("t_mono"),
                                                  "interval": m.get("interval")} for m in marks_r],
            "routes": _routes(reqs), "measure": summary,
            "intervals": {"count": len(ivs), "zero_request_intervals": sum(1 for iv in ivs if not iv.get("requests")),
                          "mono_start": ivs[0].get("mono_start") if ivs else None,
                          "mono_end": ivs[-1].get("mono_end") if ivs else None,
                          "coverage_s": round(sum(iv.get("duration_s") or 0 for iv in ivs), 6)},
            "end": {"requests": end_r, "intervals": end_i}}


def realism(requests_path, intervals_path, protocol, scenario, *, windows=()):
    """The realism requirements of proposal 5.7 and the offered-load check of proposal 5.3 for one session.

    The logs are a /2 pair of the scenario `scenario` of `protocol` (a schema-3 protocol with the profiles section);
    the bounds come from its audit.traffic (features/audit_policy.py audit_bounds), the design values from
    profiles[<the scenario's profile>] and the peak-to-mean bound from scenario_rule.min_peak_to_mean. `windows`
    are the event windows as the log audit has them: (start, end) pairs of unix times. Everything is computed over
    the measure phase (the records' own phase); a request lies in a window when its start or end does, as in the
    log audit. Returns {"requirements": [{"name", "value", "bound", "ok", "note"}, ...] in the order of REALISM,
    "offered_load": {"offered", "planned", "ratio", "ok"}}; a requirement that cannot be computed has value None and
    ok False. ValueError names a protocol, scenario, profile or log this function cannot judge.

      arrival_cv            coefficient of variation (population standard deviation over the mean) of the spacings
                            of the arrivals, each arrival time t rescaled by the planned envelope to its integral
                            from 0 to t (time rescaling: an open loop with intensity rate x envelope gives unit
                            Poisson spacings, CV 1; skeleton B5 section 4); all offered arrivals; within
                            audit.traffic.arrival_cv
      think_time (eshop)    the realized think times of the requests of the measure phase but the first of each
                            user session: its start minus the end of the request before it in its user session
                            (t_start_mono - t_end_mono, 6 decimals; finding F6 of the B5b verification: not the
                            drawn think_s), their mean within think_mean_tolerance_se standard errors (sample standard
                            deviation over sqrt(n)) of profiles.eshop.think_s.mean, their maximum at most think_s.max
                            plus THINK_LAG_S
      order_share (eshop)   of the admitted user sessions that arrived in the measure phase and did not start in
                            [window start - D_max, window end] of any window nor in [stop - D_max, stop], the share
                            that place an order (POST /api/orders without an intended status), within
                            order_share_tolerance_se standard errors (sqrt(p (1 - p) / n)) of
                            p = profiles.eshop.order_share[<intensity>]; D_max is order_share_session_max_s, an upper
                            bound of a user session's duration, one for every kind of user session (package B13, the
                            lead's answer to Q73 point 1): a user session is left out by its start, its arrival,
                            alone, whatever its later requests touch, because a selection by overlap with a window
                            depends on the length of a user session, and an ordering one is longer. The stop is the
                            generator's (package B14, Q77: the executor's decision, approved by the lead on
                            2026-11-26): the request log's end record. scripts/collection.py stops the generator right
                            after the measure phase, so a buyer that starts less than D_max before the stop may be cut
                            before its order; it is left out as one that starts less than D_max before a window is.
                            The stop and the starts are compared in the generator's monotonic time, the end record's
                            end_mono against each arrival's t_mono (package B15, should_fix 1 of the fourth G0
                            verification), and summarize refuses a pair whose two copies of end_mono differ; the
                            session audit refuses an end_mono before the post marker's t_mono or more than
                            TRAFFIC_STOP_GRACE_S of scripts/collection.py after it (package B16, should_fix 2 of the
                            fifth G0 verification: scripts/collection_logs.py traffic_stop). A
                            request log that does not end with an end record with a finite end_mono gives no share
                            (value None, ok False). The numbers behind the rule, on the 16 eshop sessions of the C4
                            pass (scripts/tests/test_order_share_c4.py; the executor's in OTAZKY_VEDUCEMU.md, "K Q77
                            a Q78", 2026-11-26): the mean z of the share is -0.892 under B13's rule and +0.198 with
                            the stop at the rates of the first Zápis 1 of G2 (26e49ab), -1.689 and -0.032 at those
                            of the second (3ce9b72), the file's since. With the stop the z of the orders equals the z
                            of the buyers its seeds draw in all 16 sessions at the second rates, and in 15 of 16 at
                            the first, where the stop cuts one buyer of the D_max tail before its order (should_fix 2
                            of the fourth G0 verification)
      object_concentration  the requests that name an object (object not null; an object is its kind by route and
                            its id): the most requested top_objects_share of the distinct objects (rounded up) get at
                            least top_objects_min_requests of these requests
      success_rate          the share of requests outside every window answered 2xx: at least success_min and below 1
      response_sizes        log10(largest / smallest response_bytes) of the 2xx answers outside every window with a
                            positive size: at least response_size_orders
      peak_to_mean          the planned envelope over the measure phase (its intervals, clamped to [0, D]): the
                            largest level over the mean level, at least scenario_rule.min_peak_to_mean
      background (corp)     outside every window: at least logins_min 2xx POST /api/auth/login, at least reports_min
                            2xx POST /api/reports, and the largest 2xx download of a document (GET /api/docs/<id>)
                            at least document_max_to_median times their median (nearest rank)
      offered_load          the offered user sessions over the planned ones, both summed over the measure-phase
                            intervals that overlap no window: within offered_load_tolerance of 1. The windows are
                            unix times, and an interval is placed at start_unix of the request log's header plus its
                            mono_start and mono_end, which summarize binds since package B16 (should_fix 1 of the
                            fifth G0 verification): every record's wall time lies within WALL_CLOCK_TOLERANCE_S of
                            start_unix plus its monotonic time (wall_clock)
    """
    from features.audit_policy import audit_bounds  # The only reader of the audit section.
    bounds = audit_bounds(protocol)
    if bounds is None:
        raise ValueError("the realism requirements need a protocol of schema 3")
    limit = bounds["traffic"]
    scenarios = protocol.get("scenarios")
    if type(scenarios) is not dict or type(scenario) is not str or type(scenarios.get(scenario)) is not dict:
        raise ValueError("unknown scenario: " + str(scenario))
    profile, intensity = scenarios[scenario].get("profile"), scenarios[scenario].get("intensity")
    if profile not in V5_PROFILES:
        raise ValueError("unknown profile: " + str(profile))
    profiles = protocol.get("profiles")
    if type(profiles) is not dict or type(profiles.get(profile)) is not dict:
        raise ValueError("protocol has no profiles section entry: " + profile)
    params = profiles[profile]
    min_peak_to_mean = protocol["scenario_rule"]["min_peak_to_mean"]
    if not (_finite(min_peak_to_mean) and min_peak_to_mean > 0):
        raise ValueError("invalid scenario_rule.min_peak_to_mean")
    if any(type(w) not in (list, tuple) or len(w) != 2 or not all(map(_finite, w)) for w in windows):
        raise ValueError("an event window is a pair of unix times")
    records, _ = read_jsonl(requests_path)
    intervals, _ = read_jsonl(intervals_path)
    if (not records or records[0].get("schema") != REQUEST_SCHEMA_2 or not intervals
            or intervals[0].get("schema") != INTERVAL_SCHEMA_2):
        raise ValueError(f"the realism requirements need the logs of a v5 profile ({REQUEST_SCHEMA_2}, "
                         f"{INTERVAL_SCHEMA_2})")
    header = records[0]
    envelope = Envelope(header.get("envelope"))
    origin = header["start_unix"]
    if not _finite(origin):
        raise ValueError("invalid start_unix")

    def inside(*times):
        return any(lo <= t <= hi for t in times for lo, hi in windows)

    def overlaps(start, end):
        return any(lo <= end and start <= hi for lo, hi in windows)

    arrivals = sorted((r for r in records if r.get("type") == "arrival" and r["phase"] == "measure"),
                      key=lambda a: a["t_mono"])
    every = [r for r in records if r.get("type") == "request"]
    requests = [r for r in every if r["phase"] == "measure"]
    outside = [r for r in requests if not inside(_unix(r["t_start_utc"]), _unix(r["t_end_utc"]))]
    measure_ivs = [iv for iv in intervals if iv.get("type") == "interval" and iv["phase"] == "measure"]
    out = []

    # Spacings of the arrivals after time rescaling by the planned envelope.
    points = [envelope.cumulative(a["t_mono"]) for a in arrivals]
    spacings = [b - a for a, b in zip(points, points[1:])]
    cv = None
    if len(spacings) >= 2 and sum(spacings) > 0:
        mean = sum(spacings) / len(spacings)
        cv = math.sqrt(sum((d - mean) ** 2 for d in spacings) / len(spacings)) / mean
    low, high = limit["arrival_cv"]
    out.append(_requirement("arrival_cv", _round(cv), [low, high], cv is not None and low <= cv <= high,
                            f"{len(spacings)} spacings of the measure phase's arrivals rescaled by the planned "
                            "envelope (population standard deviation over the mean; unit Poisson spacings give 1)"))

    if profile == "eshop":
        design = params["think_s"]
        by_session = defaultdict(list)
        for r in every:
            by_session[r["user_session"]].append(r)
        thinks = []  # The realized think times (finding F6 of B5b): from the end of the request before.
        for rows in by_session.values():
            rows.sort(key=lambda r: r["t_start_mono"])
            thinks += [round(r["t_start_mono"] - before["t_end_mono"], 6) for before, r in zip(rows, rows[1:])
                       if r["phase"] == "measure"]
        mean = tolerance = largest = None
        if len(thinks) >= 2:
            mean = sum(thinks) / len(thinks)
            sd = math.sqrt(sum((x - mean) ** 2 for x in thinks) / (len(thinks) - 1))
            tolerance, largest = limit["think_mean_tolerance_se"] * sd / math.sqrt(len(thinks)), max(thinks)
        good = (mean is not None and abs(mean - design["mean"]) <= tolerance
                and largest <= design["max"] + THINK_LAG_S)
        out.append(_requirement("think_time", {"mean": _round(mean), "max": largest, "n": len(thinks)},
                                {"mean": design["mean"], "tolerance": _round(tolerance), "max": design["max"],
                                 "lag_s": THINK_LAG_S}, good,
                                f"{len(thinks)} think times of the measure phase, each from the end of the request "
                                "before it in its user session to its own start; the mean within "
                                f"{limit['think_mean_tolerance_se']:g} standard errors of the profile's mean, the "
                                f"maximum at most its max plus {THINK_LAG_S:g} s of the generator's own delay"))

        share_design = params["order_share"][intensity]
        # Package B13 (the lead's answer to Q73 point 1): left out by the start alone. Before, a user session that
        # touched a window with its arrival or a request was left out, so an ordering user session, which lasts
        # longer, was left out more often (the C4 pass, dokazy/G1/kod/vysledok_C3b.json: 15 of 16 shares low).
        d_max = limit["order_share_session_max_s"]
        sessions = {a["user_session"]: {"start": _unix(a["t_utc"]), "start_mono": a["t_mono"], "orders": 0}
                    for a in arrivals if a["admitted"]}
        for r in every:
            if r["user_session"] in sessions:
                sessions[r["user_session"]]["orders"] += (r["method"] == "POST" and r["route"] == "/api/orders"
                                                          and r["intended_status"] is None)
        outside_windows = [s for s in sessions.values()
                           if not any(lo - d_max <= s["start"] <= hi for lo, hi in windows)]
        # Package B14 (Q77: the executor's decision, approved by the lead on 2026-11-26): the same rule at the
        # generator's stop. scripts/collection.py sends SIGUSR2 and at once stops the generator (stop_child) after the
        # measure phase, so a buyer that starts in its last minutes is cut before the order. The stop is the request
        # log's end record: its end_mono against each arrival's t_mono, both in the generator's monotonic time, so
        # start_unix does not place it (package B15, should_fix 1 of the fourth G0 verification; summarize refuses a
        # pair whose two copies of end_mono differ). Without it there is no share to judge.
        end = records[-1] if records[-1].get("type") == "end" else None
        stop = end["end_mono"] if end is not None and _finite(end.get("end_mono")) else None
        kept = [] if stop is None else [s for s in outside_windows if not stop - d_max <= s["start_mono"] <= stop]
        share = sum(1 for s in kept if s["orders"]) / len(kept) if kept else None
        tolerance = (limit["order_share_tolerance_se"] * math.sqrt(share_design * (1 - share_design) / len(kept))
                     if kept else None)
        if stop is None:
            note = (f"no share: the request log does not end with an end record with a finite end_mono, so the "
                    f"generator's stop is unknown (intensity {intensity}); none of the {len(sessions)} user sessions "
                    "judged")
        else:
            note = (f"{sum(1 for s in kept if s['orders'])} of {len(kept)} user sessions ordered (intensity "
                    f"{intensity}); {len(sessions) - len(outside_windows)} starting in a window or less than D_max "
                    f"{d_max:g} s before one, and {len(outside_windows) - len(kept)} more starting less than D_max "
                    "before the generator's stop (the request log's end record), left out")
        out.append(_requirement("order_share", _round(share), {"share": share_design, "tolerance": _round(tolerance)},
                                share is not None and abs(share - share_design) <= tolerance, note))

    counts = Counter((object_kind(r["route"]), json.dumps(r["object"])) for r in requests if r["object"] is not None)
    total = sum(counts.values())
    top = max(1, math.ceil(round(limit["top_objects_share"] * len(counts), 9))) if counts else 0
    concentration = sum(sorted(counts.values(), reverse=True)[:top]) / total if total else None
    out.append(_requirement("object_concentration", _round(concentration), limit["top_objects_min_requests"],
                            concentration is not None and concentration >= limit["top_objects_min_requests"],
                            f"the {top} most requested of {len(counts)} objects got this share of {total} requests "
                            f"(top {limit['top_objects_share']:g} of the objects)"))

    success = sum(r["outcome"] == "ok" for r in outside) / len(outside) if outside else None
    out.append(_requirement("success_rate", _round(success), {"min": limit["success_min"], "below": 1},
                            success is not None and limit["success_min"] <= success < 1,
                            f"{len(outside)} requests of the measure phase outside every window"))

    sizes = [r["response_bytes"] for r in outside if r["outcome"] == "ok"]
    if any(type(size) is not int or size < 0 for size in sizes):
        raise ValueError("response_bytes is not a byte count")
    positive = [size for size in sizes if size > 0]
    orders = math.log10(max(positive) / min(positive)) if len(positive) >= 2 else None
    out.append(_requirement("response_sizes", _round(orders), limit["response_size_orders"],
                            orders is not None and orders >= limit["response_size_orders"],
                            f"{len(positive)} 2xx answers outside every window ({len(sizes) - len(positive)} empty "
                            "ones left out): orders of magnitude between the smallest and the largest"))

    start = max(min((iv["mono_start"] for iv in measure_ivs), default=0.0), 0.0)
    end = min(max((iv["mono_end"] for iv in measure_ivs), default=0.0), envelope.end)
    level = envelope.integral(start, end) / (end - start) if end > start else 0.0
    ratio = envelope.peak(start, end) / level if level > 0 else None
    out.append(_requirement("peak_to_mean", _round(ratio), min_peak_to_mean,
                            ratio is not None and ratio >= min_peak_to_mean,
                            f"planned envelope over the measure phase [{start:g}, {end:g}] s"))

    if profile == "corp":
        b = limit["background"]
        def posted(route):
            return sum(r["method"] == "POST" and r["route"] == route and r["outcome"] == "ok" for r in outside)
        logins, reports = posted("/api/auth/login"), posted("/api/reports")
        downloads = sorted(r["response_bytes"] for r in outside if r["method"] == "GET" and r["outcome"] == "ok"
                           and r["route"].startswith("/api/docs/") and r["response_bytes"] > 0)
        tail = downloads[-1] / percentile(downloads, .5) if downloads else None
        good = (logins >= b["logins_min"] and reports >= b["reports_min"] and tail is not None
                and tail >= b["document_max_to_median"])
        out.append(_requirement("background", {"logins": logins, "reports": reports,
                                               "document_max_to_median": _round(tail)},
                                {key: b[key] for key in ("logins_min", "reports_min", "document_max_to_median")}, good,
                                f"outside every window: {len(downloads)} document downloads; the maintenance timer "
                                "runs in the guest and is not in this log"))

    kept = [iv for iv in measure_ivs if not overlaps(origin + iv["mono_start"], origin + iv["mono_end"])]
    offered = sum(iv["offered_sessions"] for iv in kept)
    planned = sum(iv["planned_sessions"] for iv in kept)
    load = offered / planned if planned > 0 else None
    return {"requirements": out,
            "offered_load": {"offered": offered, "planned": round(planned, 6), "ratio": _round(load),
                             "ok": load is not None and abs(load - 1) <= limit["offered_load_tolerance"]}}


class _TrafficLog:
    """scripts/traffic_log.py as the frozen functions below read it: read_jsonl, summarize and realism of df3cee5 above,
    every other name the module's own."""
    read_jsonl, summarize, realism = staticmethod(read_jsonl), staticmethod(summarize), staticmethod(realism)

    def __getattr__(self, name):
        return getattr(_traffic_log, name)


traffic_log = _TrafficLog()


# ------------------------------------------------------------------ scripts/collection_logs.py at df3cee5

def audit_logs(directory, *, snapshot_times=(), archived_raw=False):
    """The log audit of a session directory. archived_raw: the session's raw/ is the link scripts/collection_archive.py
    reclaim_raw leaves to the verified archive copy, and the evidence under raw/ is read through it (the repeat of
    features/quality.py require_log_audit while the archive is attached, finding S9 of B3, package B9a); the audit of
    a capture never passes it, so there a raw/ that leads out of the session is refused as before."""
    directory = Path(directory).resolve()
    raw_target = (directory / "raw").resolve() if archived_raw and (directory / "raw").is_symlink() else None
    problems = traffic_log.Problems()
    result = {"schema": SCHEMA, "session_dir": str(directory), "sections": {}}
    # Protocol v3: [host start - 1 s, host stop done + grace] of each event. Failures inside a window
    # are expected evidence of the event; outside every window the checks stay as strict as in v2.
    windows, event_types, known_pids = [], [], {}
    # Package B8: [host start - 1 s, host done + 1 s] of each start and stop call of a control; only the guest's
    # health polls without a request id are admitted there (lab/udalosti.py polls them in every control call).
    calls = []
    # Requests inside an event window: one exception each, counted in traffic(); traffic() and correlation()
    # relax their checks for exactly these.
    during = set()
    # Package B12: each unit an event type of the session restarts by design, whether its RESTART_KEYS changed between
    # the guest's states (guest()); correlation() times its restarts in the guest's journal.
    changed_units = {}
    counts = Counter()  # Exceptions admitted, by id of features/audit_policy.py TOLERATED.
    # The session's protocol and its audit bounds (None: schema 1 or 2). Until protocol.json has been read the
    # bounds are unknown and admit nothing. v5: a schema-3 protocol with the profiles section, whose sessions run
    # the open-loop profiles (traffic logs /2).
    protocol, limits, limits_read, v5 = {}, None, False, False

    def in_window(*times):
        return any(lo <= t <= hi for t in times for lo, hi in windows)

    def in_call(*times):
        return any(lo <= t <= hi for t in times for lo, hi in calls)

    def timed_units():
        """Package B12: the units an event type of the session restarts by design (EVENT_UNITS), in REQUIRED_UNITS
        order; only an occurrence with a window counts (events() names one without)."""
        restarted = {unit for kind in event_types for unit in EVENT_UNITS.get(kind, ())}
        return [unit for unit in REQUIRED_UNITS if unit in restarted]

    def admitting_window(unit, stamp):
        """Package B12: the index (in windows) of the first occurrence whose type restarts `unit` and whose window
        holds the journal time `stamp`; None outside every such window. ValueError when the time cannot be read."""
        t = unix(stamp)
        return next((i for i, (kind, (lo, hi)) in enumerate(zip(event_types, windows))
                     if unit in EVENT_UNITS.get(kind, ()) and lo <= t <= hi), None)

    def check(condition, key, detail=None):
        if not condition:
            problems.add(key, detail)

    def section(name, function):
        # Malformed evidence rejects that section, but still checks the others.
        try:
            value = function()
            json.dumps(value, allow_nan=False)
            result["sections"][name] = value
        except (OSError, EOFError, ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as exc:
            problems.add(name + ":unreadable", f"{type(exc).__name__}: {exc}")

    def read_bounds():
        nonlocal protocol, limits, limits_read, v5
        protocol = read_json(directory / "protocol.json")
        v5 = protocol.get("schema") == SCHEMA_3 and "profiles" in protocol
        limits, limits_read = audit_bounds(protocol), True
        return limits

    def metadata():
        meta = read_json(directory / "session.json")
        end = read_json(directory / "end.json")
        check(meta.get("schema") == "hyptcn3/collection-session/2", "session_schema")
        check(end.get("schema") == "hyptcn3/collection-end/2", "end_schema")
        check(meta.get("session_id") == directory.name, "session_identity")
        # capture_session writes "interrupted" always and "error" only when the capture failed.
        check(end.get("completed") is True and end.get("interrupted") is False and "error" not in end,
              "incomplete_capture")
        check("guest_after" in end and "guest_before" in meta and end["guest_after"] == meta["guest_before"],
              "guest_identity_changed")
        for name in ("collector", "traffic", "monitor"):
            rc = end.get(name + "_rc", end.get(name, {}).get("rc"))
            if name == "traffic" and v5:
                # Under v5 host_traffic.py exits 1 when a request did not get its expected result (a 2xx, or the
                # status a deliberate client error intends, proposal 5.3) or no request succeeded, so the code must
                # be the one its request log implies; traffic() judges every such request (inside an event window
                # it is admitted, elsewhere refused).
                logged = traffic_log.read_jsonl(directory / "traffic_requests.jsonl")[0]
                rows = [r for r in logged if r.get("type") == "request"]
                unexpected = [r for r in rows if (r.get("outcome") != "ok" if r.get("intended_status") is None
                                                  else r.get("status") != r.get("intended_status"))]
                implied = 0 if rows and not unexpected and any(r.get("outcome") == "ok" for r in rows) else 1
                check(type(rc) is int and rc == implied, "child_exit", f"{name}:{rc}")
                continue
            # host_traffic exits 1 after any failed request; outside the event windows those still fail below.
            if name == "traffic" and type(rc) is int and rc == 1 and meta.get("events"):
                tolerate(counts, "event_traffic_exit")
                continue
            check(type(rc) is int and rc == 0, "child_exit", f"{name}:{rc}")
        start, stop = finite(end["measure_start_unix"]), finite(end["measure_end_unix"])
        check(start < stop, "invalid_measure_interval")
        check(all(start <= finite(t) <= stop for t in snapshot_times), "snapshot_outside_measure")
        check(digest(directory / "protocol.json") == meta.get("protocol_sha256"), "protocol_hash")
        return {"session_sha256": digest(directory / "session.json"), "end_sha256": digest(directory / "end.json"),
                "measure_start_unix": start, "measure_end_unix": stop}

    def manifest():
        doc = read_json(directory / "logs_manifest.json")
        end = read_json(directory / "end.json")
        check(doc.get("schema") == "hyptcn3/session-logs/1", "logs_manifest_schema")
        check(digest(directory / "logs_manifest.json") == end.get("logs_manifest_sha256"), "logs_manifest_hash")
        files = doc["files"]
        for name in REQUIRED:
            check(name in files, "missing_manifest_entry", name)
            check(local_file(directory, name).is_file(), "missing_evidence", name)
        verified = 0
        for name, expected in files.items():
            try:
                path = local_file(directory, name, raw_target)
                check(path.stat().st_size == expected["size"] and digest(path) == expected["sha256"],
                      "evidence_hash", name)
                # write_logs_manifest records lines and termination of every .jsonl and .log file.
                if name.endswith((".jsonl", ".log")) or "lines" in expected or "terminated" in expected:
                    data = path.read_bytes()
                    check(data.count(b"\n") == expected.get("lines") and (not data or data.endswith(b"\n"))
                          == expected.get("terminated"), "evidence_lines", name)
                    check(not data or data.endswith(b"\n"), "torn_evidence", name)
                verified += 1
            except (OSError, ValueError, KeyError, TypeError) as exc:
                problems.add("evidence_unreadable", f"{name}:{exc}")
        return {"files_checked": verified, "sha256": digest(directory / "logs_manifest.json")}

    def guest():
        meta = read_json(directory / "session.json")
        before, after = (read_json(directory / "guest" / f"state_{when}.json") for when in ("before", "after"))
        for when, state in (("before", before), ("after", after)):
            check(state.get("schema") == "hyptcn3/guest-state/1", "guest_state_schema", when)
            check(state["boot_id"] == meta["guest_before"]["boot_id"], "guest_boot_changed", when)
            check(state["kernel"] == meta["guest_before"]["kernel"], "guest_kernel_changed", when)
            for unit in REQUIRED_UNITS:
                current = state["units"].get(unit, {})
                check(current.get("ActiveState") == "active" and current.get("Result") == "success",
                      "service_unhealthy", f"{when}:{unit}")
            clock = read_json(directory / "guest" / f"clock_{when}.json")
            check(abs(finite(clock["offset_s"])) <= 1.0 and 0 <= finite(clock["uncertainty_s"]) <= 1.0,
                  "guest_clock", when)
        # A unit an event type of the session restarts by design keeps its RESTART_KEYS unjudged here: the journal
        # pass of correlation() admits its restart only inside the window of an occurrence of such a type and wants a
        # start line of it where they changed (package B12, the lead's answer to Q67). Every other unit keeps them.
        timed = timed_units()
        for unit in REQUIRED_UNITS:
            a, b = before["units"].get(unit, {}), after["units"].get(unit, {})
            kept = all(k in a and k in b and a[k] == b[k] for k in RESTART_KEYS)
            if unit in timed:
                changed_units[unit] = not kept
            else:
                check(kept, "service_restarted", unit)
        for name in SERVICES:
            unit = "hyptcn-lab@" + name
            known_pids.setdefault(name, set()).update(str(state["units"][unit]["ExecMainPID"]) for state in (before, after))
        return {"boot_id": after["boot_id"], "database_before": before["database"],
                "database_after": after["database"], "units_checked": [u for u in REQUIRED_UNITS if u not in timed],
                "units_timed": timed}

    def segments():
        files, counts = {}, {}
        for name, schema in (("pre", "hyptcn3/guest-log-segment/1"),
                             ("session", "hyptcn3/guest-log-segment/1"),
                             ("journal", "hyptcn3/guest-journal-segment/1")):
            doc = read_json(directory / "guest" / (name + "_segment.json"))
            check(doc.get("schema") == schema, "segment_schema", name)
            expected_suffixes = ("journal.txt",) if name == "journal" else ("nginx-access.jsonl", "nginx-error.log")
            for suffix in expected_suffixes:
                check(sum(entry["name"].endswith("-" + suffix) for entry in doc["files"]) == 1,
                      "segment_file_missing_or_duplicate", f"{name}:{suffix}")
            for entry in doc["files"]:
                path = local_file(directory, "guest/" + entry["file"])
                check(digest(path) == entry["gz_sha256"] == entry["file_sha256"] and
                      path.stat().st_size == entry["gz_bytes"], "segment_compressed_hash", entry["file"])
                with gzip.open(path, "rb") as stream:
                    content = stream.read()
                check(len(content) == entry["bytes"] and hashlib.sha256(content).hexdigest() == entry["sha256"],
                      "segment_content_hash", entry["file"])
                check(content.count(b"\n") == entry["lines"] and (not content or content.endswith(b"\n"))
                      and entry["terminated"] is True, "segment_lines", entry["file"])
                suffix = next((suffix for suffix in expected_suffixes if entry["name"].endswith("-" + suffix)), None)
                if suffix:
                    files[name + ":" + suffix] = content.decode("utf-8")
                counts[entry["file"]] = entry["lines"]
        return files, counts

    def traffic():
        nonlocal requests
        meta, end = read_json(directory / "session.json"), read_json(directory / "end.json")
        records, _ = traffic_log.read_jsonl(directory / "traffic_requests.jsonl")
        requests = [r for r in records if r.get("type") == "request"]
        # The protocol decides the schema (/2 for the v5 profiles, /1 otherwise); summarize refuses the other one.
        schema = traffic_log.REQUEST_SCHEMA_2 if v5 else traffic_log.REQUEST_SCHEMA
        summary = traffic_log.summarize(directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl",
                                        session_id=directory.name, schema=schema)
        for problem in summary["problems"]:
            problems.add("traffic", problem)
        header = records[0]
        intervals, _ = traffic_log.read_jsonl(directory / "traffic_intervals.jsonl")
        check("config" in header and "start_unix" in header and intervals[0].get("config") == header["config"]
              and intervals[0].get("start_unix") == header["start_unix"], "traffic_headers_disagree")
        phase_fields = lambda rows: [{k: v for k, v in r.items() if k not in ("schema", "n")}
                                     for r in rows if r.get("type") == "phase"]
        check(phase_fields(records) == phase_fields(intervals), "traffic_phase_times_disagree")
        if v5:
            # The generator's header against the protocol and session.json (design B5b 1.3 and 1.4): the scenario
            # with its profile, intensity and rate (from the protocol, or from the command line where the protocol
            # has none), the session's traffic seeds, the protocol it read, the profile's parameters verbatim, the
            # warmup, the span of its envelope, and the target, summary interval and initial phase of every
            # collection run. Finding F3 of the B5b verification (package B10): every seed of the header, the rate
            # with its source and config.dur equal the traffic block of session.json, from which run_session made
            # the command line (collection.traffic_command), and that block's dur_s is the planned run of the
            # protocol, warmup_s and cycles intervals (collection._v5_traffic). The envelope is not redrawn from the
            # protocol here; its inputs are bound, the frozen generator determines it from them, and a tool outside
            # the measurement code redraws it over the G2 sessions, the rehearsals, and every accepted session of a
            # closed campaign (the lead's answer to Q30, 2026-11-24).
            s = protocol["scenarios"].get(meta["scenario"], {})
            config, run, seeds, rate = header["config"], meta["traffic"], header.get("seeds"), s.get("rate")
            parameters, cycles = header.get("profile_parameters"), meta.get("cycles")
            planned_s = (protocol["warmup_s"] + cycles * protocol["interval_s"]
                         if type(cycles) is int and cycles > 0 else None)
            fields = {
                "profile": header.get("profile") == s.get("profile"),
                "scenario": header.get("scenario") == meta["scenario"],
                "intensity": header.get("intensity") == s.get("intensity"),
                "rate": header.get("rate_source") == run.get("rate_source") and header.get("rate") == run.get("rate")
                and ((header.get("rate_source") == "protocol" and header.get("rate") == rate) if rate is not None
                     else (header.get("rate_source") == "command line" and type(header.get("rate")) in (int, float)
                           and header["rate"] > 0)),
                "seeds": type(seeds) is dict and seeds == run.get("seeds") and type(seeds.get("traffic")) is int
                and seeds["traffic"] == meta["seed"],
                "dur": planned_s is not None and config.get("dur") == run.get("dur_s") == planned_s,
                "protocol_sha256": type(header.get("protocol_sha256")) is str
                and header["protocol_sha256"] == meta.get("protocol_sha256"),
                "profile_parameters": type(parameters) is dict
                and parameters == protocol["profiles"].get(s.get("profile")),
                "warmup_s": header.get("warmup_s") == protocol["warmup_s"] == run.get("warmup_s"),
                "target": config.get("target") == run["target"],
                "summary_interval_s": config.get("summary_interval_s") == run["summary_interval_s"],
                "initial_phase": config.get("initial_phase") == "warmup"}
            for key, good in fields.items():
                check(good, "traffic_config", key)
        else:
            expected = dict(meta["traffic"], seed=meta["seed"], initial_phase="warmup")
            for key in ("target", "profile", "seed", "workers", "burst", "catalog_share", "write_share",
                        "summary_interval_s", "initial_phase"):
                check(key in header["config"] and header["config"][key] == expected[key], "traffic_config", key)
        check([m["phase"] for m in summary["phase_markers"]] == ["measure", "post"], "traffic_phases")
        bounds = {m["phase"]: unix(m["t_utc"]) for m in summary["phase_markers"]}
        check(abs(bounds["measure"] - finite(end["measure_start_unix"])) <= 1 and
              abs(bounds["post"] - finite(end["measure_end_unix"])) <= 1, "traffic_measure_bounds")
        if v5:
            # Package B16 (should_fix 2 of the fifth G0 verification, Q82: the executor's decision, for the lead's
            # review): the generator's stop from above. The order share leaves out the user sessions that start less
            # than D_max before the request log's end record (scripts/traffic_log.py realism), so a stop moved later
            # in both end records and the last interval would keep the buyers it cut. scripts/collection.py stops the
            # generator right after the post marker within TRAFFIC_STOP_GRACE_S, and one that runs longer is killed
            # without an end record: end_mono lies at the post marker's t_mono or at most that much after it, both
            # in the generator's monotonic time. A request log without an end record or with an end_mono that is no
            # number is refused by summarize already (requests:end_missing, requests:end_mono_mismatch).
            from scripts.collection import TRAFFIC_STOP_GRACE_S  # Inside: scripts/collection.py imports this module.
            post = next((m for m in summary["phase_markers"] if m["phase"] == "post"), None)
            stop = (summary["end"]["requests"] or {}).get("end_mono")
            if post is not None and type(stop) in (int, float) and math.isfinite(stop):
                start = post["t_mono"]
                check(type(start) in (int, float) and math.isfinite(start)
                      and start <= stop <= start + TRAFFIC_STOP_GRACE_S, "traffic_stop")
        check(all(bounds["measure"] <= t <= bounds["post"] for t in snapshot_times), "traffic_snapshot_coverage")
        reqs = requests
        for row in reqs:
            check(row.get("session_id") == directory.name and row.get("run_id") == header["run_id"],
                  "request_identity", row.get("rid"))
            check(isinstance(row.get("rid"), str) and bool(row["rid"]), "request_id_missing")
            check(0 <= finite(row["t_start_mono"]) <= finite(row["t_end_mono"]) and finite(row["duration_ms"]) >= 0,
                  "request_timing", row.get("rid"))
            check(unix(row["t_start_utc"]) <= unix(row["t_end_utc"]), "request_wall_clock", row.get("rid"))
            if in_window(unix(row["t_start_utc"]), unix(row["t_end_utc"])):
                tolerate(counts, "event_window_requests")  # May fail; nginx and services are not correlated.
                during.add(row.get("rid"))
                continue
            if v5 and row.get("intended_status") is not None:
                # A deliberate client error of the v5 profiles (proposal 5.3) passes only with its own status; the
                # success rate is a realism requirement (section realism), not a rule per request.
                check(row.get("status") == row["intended_status"], "intended_status_differs", row.get("rid"))
                continue
            check(row["outcome"] == "ok" and type(row["status"]) is int and 200 <= row["status"] < 300,
                  "request_failed", row.get("rid"))
        status = read_json(directory / "traffic.json")
        before = read_json(directory / "traffic_before.json")
        # host_traffic.py writes both fields in every status: logging_error null, worker_errors 0 when clean.
        check(status.get("final") is True and "logging_error" in status and not status["logging_error"]
              and status.get("worker_errors") == 0, "traffic_status_incomplete")
        check(status.get("session_id") == directory.name and status.get("run_id") == header["run_id"] and
              before.get("run_id") == header["run_id"] and before["started_at"] == status["started_at"],
              "traffic_status_identity")
        check(status["requests"] == status["requests_logged"] == len(reqs) and
              status["ok"] == sum(r["outcome"] == "ok" for r in reqs) and
              status["errors"] == sum(r["outcome"] != "ok" for r in reqs), "traffic_status_counts")
        return summary, reqs

    def correlation(contents, requests):
        expected = {r["rid"]: r for r in requests}
        matched, tolerated = Counter(), Counter()
        for line in contents["session:nginx-access.jsonl"].splitlines():
            row = json.loads(line)
            check(row.get("schema") == "hyptcn3/nginx-access/1", "nginx_schema")
            rid = row["rid"]
            if (rid == "" and row["method"] == "GET" and row["uri"] == "/healthz"
                    and (in_window(finite(row["msec"])) or in_call(finite(row["msec"])))):
                # lab/udalosti.py polls health with no request id, in an event and in a control's call.
                tolerated["event_health_checks" if in_window(row["msec"]) else "control_health_checks"] += 1
                tolerate(counts, "event_window_health_checks")
                continue
            if rid not in expected:
                problems.add("nginx_unknown_request", rid)
                continue
            req = expected[rid]
            matched[rid] += 1
            if rid in during:
                continue  # A client timeout leaves nginx 499 and a late timestamp.
            check(row["forwarded_rid"] == rid and row["status"] == req["status"] and
                  row["method"] == req["method"] and row["uri"] == req["route"], "nginx_mismatch", rid)
            check(unix(req["t_start_utc"]) - 1 <= finite(row["msec"]) <= unix(req["t_end_utc"]) + 1,
                  "nginx_timestamp", rid)
        for rid in expected:
            check(matched[rid] == 1, "nginx_request_count", f"{rid}:{matched[rid]}")
        smoke = read_json(directory / "preflight_smoke.json")
        check(smoke.get("schema") == "hyptcn3/lab-smoke/1" and smoke["values"].get("order_completed") is True
              and bool(smoke["values"]["checks"]), "preflight_incomplete")
        pre = defaultdict(list)
        for line in contents["pre:nginx-access.jsonl"].splitlines():
            row = json.loads(line)
            pre[row["rid"]].append(row["status"])
        for row in smoke["values"]["checks"]:
            check("expected" in row and row["status"] == row["expected"], "preflight_failed", row["rid"])
            check(pre[row["rid"]] == [row["status"]], "preflight_correlation", row["rid"])
        pids = {name: known_pids[name] for name in SERVICES}
        service, catalog_calls = Counter(), Counter()
        # Package B12: the systemd lines of each unit an event type of the session restarts by design, by the window
        # that admits them (an index of windows), outside every window of a type that restarts it, or without a time;
        # and the units with a start line.
        timed = timed_units()
        admitted, outside, untimed, started = defaultdict(Counter), Counter(), Counter(), set()
        journal = contents["journal:journal.txt"]
        for line in journal.splitlines():
            m = SERVICE_LINE.search(line)
            if m and m[2] in expected:
                service[(m[2], m[1], m[3], m[4], int(m[5]))] += 1
                if m[1] in pids["catalog"] and m[3] == "GET" and m[4].startswith("/api/catalog/") and m[5] == "200":
                    catalog_calls[m[2]] += 1
            if re.search(r"Suppressed \d+ messages|Missed \d+ journal messages", line):
                problems.add("journal_error_or_loss", line[:180])
            elif "Traceback (most recent call last)" in line or WORKER_ERROR in line:
                if windows and in_window(unix(line.split(" ", 1)[0])):
                    tolerated["worker_errors" if WORKER_ERROR in line else "journal_tracebacks"] += 1
                    tolerate(counts, "event_window_journal")
                else:
                    problems.add("journal_error_or_loss", line[:180])
            u = UNIT_LINE.match(line)
            unit = u[3] or u[4] if u else None
            if unit in timed:
                try:
                    where = admitting_window(unit, u[1])
                except ValueError:
                    untimed[unit] += 1
                    continue
                if where is None:
                    outside[unit] += 1
                else:
                    admitted[where][unit] += 1
                if u[2] == "Started":
                    started.add(unit)
        # A line outside every window of a type that restarts the unit refuses it by name; a line without a readable
        # time, or a change of its RESTART_KEYS (guest()) without a start line of it, is a restart the audit cannot
        # place in time: refused as any other restart (fail closed). Where the section guest could not be read the
        # change is unknown, and that section refuses the session. Each window counts the units it admitted.
        for unit in timed:
            if outside[unit]:
                problems.add("service_restarted_outside_event", unit)
            if untimed[unit] or changed_units.get(unit) is True and unit not in started:
                problems.add("service_restarted", unit)
        for where in sorted(admitted):
            for unit in admitted[where]:
                tolerate(counts, "event_unit_restarts")

        def served(rid, name, method, route, status):
            return sum(service[(rid, pid, method, route, status)] for pid in pids[name])
        for rid, req in expected.items():
            route, method, status = req["route"], req["method"], req["status"]
            if v5:  # Every route of lab/nginx.conf; nginx alone answers /, /static/ and the paths it does not pass.
                name = upstream(route)
            else:
                name = ("auth" if route.startswith("/api/auth/") else "catalog" if route.startswith("/api/catalog")
                        else None if route == "/" else "orders")
            if name is None:
                continue  # nginx serves this route without an API call.
            if rid in during:  # Counted as an exception in traffic().
                tolerated["requests_in_events"] += 1
                tolerated["failed_in_events"] += req["outcome"] != "ok" or not 200 <= req["status"] < 300
                continue
            check(served(rid, name, method, route, status) == 1, "service_request_count", rid)
            # orders and docs ask auth about the token first (lab/services.py); a token it refuses is answered 401.
            if (auth_checked(method, route) if v5 else route == "/api/orders"):
                check(served(rid, "auth", "GET", "/api/auth/check", 401 if v5 and status == 401 else 200) == 1,
                      "service_auth_call", rid)
            if route == "/api/orders" and method == "POST" and status == 201:
                check(catalog_calls[rid] == 1, "service_catalog_call", rid)
            if route == "/healthz":
                for dependency in ("auth", "catalog"):
                    check(served(rid, dependency, "GET", "/healthz", 200) == 1,
                          "service_health_call", f"{rid}:{dependency}")
        for line in contents["session:nginx-error.log"].splitlines():
            # nginx writes guest local time; the lab guest runs in UTC.
            m = NGINX_TIME.match(line)
            stamp = m and datetime.strptime(m[1], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            if stamp and windows and in_window(stamp, stamp + 1):
                tolerated["nginx_error_lines"] += 1
                tolerate(counts, "event_window_nginx_errors")
            elif line.strip():
                problems.add("nginx_error_log_nonempty", line[:180])
        return {"requests": len(expected), "nginx_matched_once": sum(matched[rid] == 1 for rid in expected),
                "service_records": sum(service.values()), "preflight_requests": len(smoke["values"]["checks"]),
                **({"tolerated_in_events": dict(tolerated)} if windows or calls else {}),
                # Package B12: per window that admitted a restart, its type and the systemd lines of each unit in it.
                **({"event_unit_restarts": [{"window": where, "type": event_types[where],
                                             "units": dict(admitted[where])} for where in sorted(admitted)]}
                   if timed else {})}

    def monitor():
        end = read_json(directory / "end.json")
        summary = host_monitor.summarize(directory / "host_monitor.jsonl", end["measure_start_unix"], end["measure_end_unix"])
        for problem in summary["problems"]:
            problems.add("monitor", problem)
        records = [json.loads(line) for line in (directory / "host_monitor.jsonl").read_text().splitlines()]
        samples = [r for r in records if r.get("type") == "sample"]
        check(records[0].get("session_id") == directory.name, "monitor_session_identity")
        check(records[-1].get("type") == "end" and records[-1].get("clean") is True and
              records[-1].get("samples") == len(samples) and bool(samples), "monitor_end_counts")
        check(all(b["i"] > a["i"] and finite(b["t_mono"]) > finite(a["t_mono"])
                  and unix(b["t_utc"]) > unix(a["t_utc"]) for a, b in zip(samples, samples[1:])), "monitor_order")
        # Proposal 6.2: swapped QEMU memory stalls a full snapshot (missed slots of campaigns v4 and v4c).
        check(all(qemu_unswapped(sample) for sample in samples), "qemu_swap")
        return summary

    def collector():
        capture = read_json(directory / "raw/capture.json")["values"]
        meta = read_json(directory / "session.json")
        log = (directory / "raw/collect.log").read_text()
        check(log.endswith("\n"), "collector_torn_log")
        ends = re.findall(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
        check(len(ends) == 1, "collector_end_missing_or_duplicate")
        if ends:
            snapshots, errors, skipped = map(int, ends[-1])
            check(snapshots == meta["cycles"] == capture["snapshots"] == capture["requested_cycles"],
                  "collector_snapshot_count")
            check(errors == skipped == 0, "collector_errors_or_missed_slots")
        check(capture["collector_exit_code"] == 0, "collector_exit_code")
        check(capture["collector_sha256"] == meta["collector_sha256"], "collector_hash")
        lines = [(line, *collector_line(line)) for line in log.splitlines()]
        errors = [line for line, level, _ in lines if level == "ERROR" or re.search(r"\sERROR\s", line)]
        check(not errors, "collector_error_log")
        warnings = [(line, message) for line, level, message in lines
                    if level == "WARN" or level is None and re.search(r"\sWARN\s", line)]
        # Proposal 6.2: a warning no pattern of warnings_allowed matches in full rejects (null: none matches).
        # Protocols of schema 1 and 2 have no bounds: their warnings are recorded only.
        if limits is not None or not limits_read:
            allowed = limits["warnings_allowed"] if limits else None
            for _, message in warnings:
                if any(re.fullmatch(pattern, message) for pattern in allowed or ()):
                    tolerate(counts, "collector_warnings")
                else:
                    problems.add("collector_warning_unlisted", message[:180])
        return {"sha256": digest(directory / "raw/collect.log"), "warnings": [line for line, _ in warnings],
                "errors": errors, "end": ends[-1] if ends else None}

    def events():
        meta = read_json(directory / "session.json")
        doc = read_json(directory / "events.json")
        check(doc.get("schema") == "hyptcn3/session-events/1", "events_schema")
        # Every key of each planned event in session.json (under schema 3 the items of the plan as they are: type,
        # class, start_s, duration_s, start_phase_s, stop_phase_s; at least the first four) has the same value in
        # its record of events.json.
        planned = meta["events"]
        check(type(planned) is list and len(planned) == len(doc["events"]) and all(
            type(item) is dict and {"type", "class", "start_s", "duration_s"} <= set(item) and type(record) is dict
            and all(key in record and record[key] == item[key] for key in item)
            for item, record in zip(planned, doc["events"])), "events_differ_from_plan")
        for record in doc["events"]:
            check(record.get("executed") is True, "event_not_executed", record["type"])
            # The predicate of the event type fills effect (package B5): {"ok": bool, "predicate": str, ...}.
            effect = record.get("effect")
            check(type(effect) is dict and effect.get("ok") is True, "event_without_effect", record["type"])
            if "host_start_unix" not in record:
                problems.add("event_not_started", record["type"])
                continue
            if "host_stopped_unix" not in record:
                problems.add("event_not_stopped", record["type"])
                continue
            windows.append(event_window(record, meta["event_grace_s"]))
            event_types.append(record["type"])
            # The deployed guest script must be the one hashed at session start: a SHA-256 on both sides.
            script = meta["source_sha256"].get("lab/udalosti.py")
            check(type(script) is str and SHA256.fullmatch(script) is not None
                  and all(type(record.get(step)) is dict and record[step].get("script_sha256") == script
                          for step in ("start", "stop")), "event_script_differs", record["type"])
            for state in (record.get("start", {}), record["stop"]):
                for name in SERVICES:
                    pid = state.get("units", {}).get("hyptcn-lab@" + name, {}).get("ExecMainPID")
                    if pid and pid != "0":
                        known_pids.setdefault(name, set()).add(str(pid))
        return {"events": len(doc["events"]), "executed": sum(r.get("executed") is True for r in doc["events"]),
                "windows": windows, "types": event_types}

    def controls():
        """Package B8 (design B8 1.4): the records of controls.json against the planned controls of session.json,
        and for each occurrence whether it ran and the guest's three predicates, nothing else (the sealed role)."""
        meta = read_json(directory / "session.json")
        if not (directory / "controls.json").is_file():
            raise ValueError("no controls.json")  # Finding S2 of B3: as an events.json missing in an event session.
        doc = read_json(directory / "controls.json")
        check(doc.get("schema") == CONTROLS_SCHEMA, "controls_schema")
        # Every key of each planned control (as the plan states it) has its value in the record, but its class A or
        # B, which the record keeps as kind_class; the record's class is the occurrence's by its polarity.
        planned, records = meta["controls"], doc["controls"]
        check(type(planned) is list and type(records) is list and len(planned) == len(records) and all(
            type(item) is dict and type(record) is dict
            and all(key in record and record[key] == item[key] for key in item if key != "class")
            and record.get("kind_class") == item.get("class")
            and record.get("class") == CONTROL_RECORD_CLASS.get(item.get("polarity"))
            for item, record in zip(planned, records)), "controls_differ_from_plan")
        # The level part of the return predicate is judged once the protocol has a tolerance (design B8 1.3).
        tolerance = protocol.get("controls", {}).get("baseline") if type(protocol.get("controls")) is dict else None
        script = meta["source_sha256"].get("lab/udalosti.py")
        for record in records:
            kind = record.get("kind")
            times = [record.get(key) for pair in CONTROL_CALLS for key in pair]
            check(record.get("executed") is True and all(type(t) in (int, float) and math.isfinite(t) for t in times),
                  "control_not_executed", kind)
            baseline = record.get("baseline")
            level = baseline.get("level") if type(baseline) is dict else None
            check(type(baseline) is dict and baseline.get("ok") is True
                  and (tolerance is None or type(level) is dict and level.get("judged") is True),
                  "control_without_baseline", kind)
            # A start the return predicate refused started nothing (lab/udalosti.py control_start), so the stop that
            # follows it stopped nothing: its effect and its cleanup are not the occurrence's (finding S1 of B8).
            start = record.get("start")
            refused = (type(start) is dict and start.get("started") is False and type(baseline) is dict
                       and baseline.get("ok") is False)
            effect = record.get("effect")
            effective = type(effect) is dict and effect.get("ok") is True
            if refused:
                pass
            elif record.get("polarity") == "negative":  # Its tree ran and the property was absent (skeleton B8 §2).
                if not effective:
                    evidence = effect.get("evidence") if type(effect) is dict else None
                    failed = evidence.get("failed") if type(evidence) is dict else None
                    named = failed if type(failed) is list and all(type(x) is str for x in failed) else []
                    seen = [x for x in named if x in NEGATIVE_PROPERTY.get(kind, ())]
                    if seen:
                        problems.add("negative_with_property", kind)
                    if len(seen) < len(named) or not named:
                        problems.add("negative_not_in_place", kind)
            else:
                check(effective, "control_without_effect", kind)
            cleanup = record.get("cleanup")
            check(refused or type(cleanup) is dict and cleanup.get("ok") is True, "control_not_cleaned", kind)
            # The deployed guest script must be the one hashed at session start, as for an event.
            check(type(script) is str and SHA256.fullmatch(script) is not None
                  and all(type(record.get(step)) is dict and record[step].get("script_sha256") == script
                          for step in ("start", "stop")), "control_script_differs", kind)
            for start, done in CONTROL_CALLS:
                if all(type(record.get(key)) in (int, float) and math.isfinite(record[key]) for key in (start, done)):
                    calls.append((record[start] - CALL_MARGIN_S, record[done] + CALL_MARGIN_S))
        return {"controls": len(records), "executed": sum(r.get("executed") is True for r in records
                                                          if type(r) is dict), "calls": calls}

    section("audit_bounds", read_bounds)
    section("metadata", metadata)
    section("manifest", manifest)
    try:
        meta = read_json(directory / "session.json")
        planned, controlled = "events" in meta, "controls" in meta or meta.get("role") == CONTROL_ROLE
    except (OSError, ValueError):
        planned = controlled = False  # The metadata section has already recorded why.
    # A protocol that plans events plans them for each of its sessions (collection.run_session): a session.json
    # without them fails the events section instead of skipping it (under schema 3: per_session above 0).
    if planned or plans_events(protocol):
        section("events", events)
    # A session of test_controls holds its planned controls (package B8): without them the section fails too.
    if controlled:
        section("controls", controls)
    section("guest", guest)
    contents, requests = {}, []

    def read_segments():
        nonlocal contents
        contents, counts = segments()
        return {"lines": counts}

    def read_traffic():
        nonlocal requests
        summary, requests = traffic()
        return summary

    def realism():
        """Protocol v5: the realism requirements of proposal 5.7 and the offered-load check of proposal 5.3
        (scripts/traffic_log.py realism) over the measure phase, outside the event windows where they judge the
        lab's answers."""
        meta = read_json(directory / "session.json")
        found = traffic_log.realism(directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl",
                                    protocol, meta["scenario"], windows=windows)
        for requirement in found["requirements"]:
            check(requirement["ok"], "traffic_realism", requirement["name"])
        check(found["offered_load"]["ok"], "offered_load_differs_from_plan")
        return found

    section("segments", read_segments)
    section("traffic", read_traffic)
    if v5:
        section("realism", realism)
    section("correlation", lambda: correlation(contents, requests))
    section("monitor", monitor)
    section("collector", collector)
    result.update(problems=problems.result(), problem_counts=dict(problems.counts), accepted=not problems.counts,
                  tolerated={name: counts[name] for name in LOG_EXCEPTIONS},
                  note="Evidence only. RAM, feature coverage and model validation require separate checks.")
    return result


# ------------------------------------------------------------------ scripts/lab_trial.py at df3cee5

def measure_phase(run):
    """(the reasons of the drops, the most concurrent user sessions) of the run's measure phase: {drop_reason: count}
    of its dropped arrival records (NO_DROP_REASON for one that names none), and the largest active_max of its
    intervals (None without one)."""
    records, _ = traffic_log.read_jsonl(run / REQUESTS)
    intervals, _ = traffic_log.read_jsonl(run / INTERVALS)
    reasons = Counter(r.get("drop_reason") or NO_DROP_REASON for r in records
                      if r.get("type") == "arrival" and r.get("phase") == "measure" and r.get("admitted") is False)
    active = [iv["active_max"] for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"]
    return dict(sorted(reasons.items())), max(active, default=None)


def traffic_summary(run):
    """scripts/traffic_log.py summarize of the run's logs, its problems and the measure phase, with the reasons of
    its drops and its most concurrent user sessions (measure_phase)."""
    s = traffic_log.summarize(run / REQUESTS, run / INTERVALS, session_id=run.name)
    m = s["measure"]
    reasons, active_max = measure_phase(run)
    return {"problems": s["problems"][:20], "problem_count": len(s["problems"]), "clean": s["clean"],
            "arrivals": s.get("arrivals"), "drop_reasons": reasons, "active_max": active_max, "phases": s["phases"],
            "measure": {key: m.get(key) for key in ("requests", "ok", "errors", "phase_duration_s",
                                                    "phase_request_rate_rps", "latency_ms",
                                                    "max_ok_completion_gap_s")}}


def analysis(run, p, scenario, windows):
    found = {"windows": [list(w) for w in windows], "summary": traffic_summary(run)}
    try:
        found["realism"] = traffic_log.realism(run / REQUESTS, run / INTERVALS, p, scenario, windows=windows)
    except (ValueError, KeyError, TypeError) as error:
        found["realism"] = {"error": failure(error)}
    return found


def peak_of(run):
    """The peak of one step's logs: the intervals of the measure phase whose planned level (the header's envelope)
    is 1 over all of them, with the user sessions offered, admitted and dropped there (the interval log) and the
    reasons of the drops (drop_reasons), the requests that started in them, how many lacked their expected result,
    their p95 latency (exact nearest rank), and the delivered user sessions and requests per second of the peak."""
    records, _ = traffic_log.read_jsonl(run / REQUESTS)
    intervals, _ = traffic_log.read_jsonl(run / INTERVALS)
    envelope = traffic_log.Envelope(next(r for r in records if r.get("type") == "header")["envelope"])
    peaks = [iv for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"
             and iv["mono_end"] > iv["mono_start"] and envelope.integral(iv["mono_start"], iv["mono_end"])
             >= (iv["mono_end"] - iv["mono_start"]) * (1 - PEAK_TOLERANCE)]
    ids = {iv["interval"] for iv in peaks}
    requests = [r for r in records if r.get("type") == "request" and r.get("interval") in ids]
    seconds = sum(iv["mono_end"] - iv["mono_start"] for iv in peaks)
    admitted = sum(iv["admitted_sessions"] for iv in peaks)
    return {"intervals": len(peaks), "seconds": round(seconds, 6),
            "offered": sum(iv["offered_sessions"] for iv in peaks), "admitted": admitted,
            "dropped": sum(iv["dropped_sessions"] for iv in peaks),
            "drop_reasons": drop_reasons(records, intervals, ids),
            "active_max": max((iv["active_max"] for iv in peaks), default=None), "requests": len(requests),
            "unexpected": sum(not expected(r) for r in requests),
            "p95_ms": traffic_log.percentile(sorted(r["duration_ms"] for r in requests), .95),
            "sessions_per_s": round(admitted / seconds, 6) if seconds else None,
            "requests_per_s": round(len(requests) / seconds, 6) if seconds else None}


# ------------------------------------------------------------------ scripts/collection.py at df3cee5

def file_record(path):
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    record = {"size": path.stat().st_size, "sha256": sha}
    if path.suffix in (".jsonl", ".log"):
        with path.open("rb") as stream:
            data = stream.read()
        record["lines"] = data.count(b"\n")
        record["terminated"] = not data or data.endswith(b"\n")
    return record


# ------------------------------------------------------------------ scripts/campaign_report.py at df3cee5

def load_traffic(directory, sid, windows, files):
    """The load of a session's measure phase from its /2 traffic logs, read through scripts/traffic_log.py
    (LOAD_RULE)."""
    requests_path, intervals_path = directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl"
    _g2t_hash(requests_path, files, "traffic_requests.jsonl")
    _g2t_hash(intervals_path, files, "traffic_intervals.jsonl")
    try:
        summary = traffic_log.summarize(requests_path, intervals_path, session_id=sid,
                                        schema=traffic_log.REQUEST_SCHEMA_2)
        records, _ = traffic_log.read_jsonl(requests_path)
        intervals, _ = traffic_log.read_jsonl(intervals_path)
    except (OSError, ValueError) as error:
        raise DataError(f"{directory}: the traffic logs cannot be read ({type(error).__name__}: {error})") from None
    header = records[0] if records and records[0].get("type") == "header" else {}
    origin = header.get("start_unix")
    measure = [iv for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"]
    if not _number(origin) or not measure or not all(_number(iv.get(k)) for iv in measure
                                                     for k in ("mono_start", "mono_end", "planned_sessions")):
        raise DataError(f"{requests_path}: no header with start_unix or no measure intervals with their times and "
                        "planned sessions (a log of schema /2 of a v5 profile)")
    seconds = sum(iv["mono_end"] - iv["mono_start"] for iv in measure)
    span = (origin + min(iv["mono_start"] for iv in measure), origin + max(iv["mono_end"] for iv in measure))
    clipped = sorted((max(lo, span[0]), min(hi, span[1])) for lo, hi in windows if hi > span[0] and lo < span[1])
    window_s, end = 0.0, None
    for lo, hi in clipped:  # The union of the windows within the measure phase.
        lo = lo if end is None else max(lo, end)
        window_s += max(0.0, hi - lo)
        end = hi if end is None else max(end, hi)

    def inside(*times):
        return any(t is not None and lo <= t <= hi for t in times for lo, hi in windows)

    arrivals = [r for r in records if r.get("type") == "arrival"]
    measured = [a for a in arrivals if a.get("phase") == "measure"]
    requests = [r for r in records if r.get("type") == "request" and r.get("phase") == "measure"]
    in_window = [r for r in requests if inside(unix_of(r.get("t_start_utc")), unix_of(r.get("t_end_utc")))]
    windowed = [a for a in measured if inside(unix_of(a.get("t_utc")))]
    by_phase = {phase: dict(Counter(str(a.get("drop_reason")) for a in arrivals
                                    if a.get("phase") == phase and a.get("admitted") is False))
                for phase in traffic_log.PHASES}
    ok = sum(r.get("outcome") == "ok" for r in requests)
    ok_in = sum(r.get("outcome") == "ok" for r in in_window)
    planned = sum(iv["planned_sessions"] for iv in measure)
    outside_s = seconds - window_s
    return {"run_id": header.get("run_id"), "rate": header.get("rate"), "rate_source": header.get("rate_source"),
            "measure_s": round(seconds, 6),
            "offered": {"user_sessions": len(measured), "per_s": _g2t_ratio(len(measured), seconds),
                        "planned": round(planned, 6), "ratio": _g2t_ratio(len(measured), planned)},
            "delivered": {"admitted_user_sessions": sum(a.get("admitted") is True for a in measured),
                          "requests": len(requests), "ok": ok, "per_s": _g2t_ratio(len(requests), seconds),
                          "ok_per_s": _g2t_ratio(ok, seconds), "ok_share": _g2t_ratio(ok, len(requests))},
            "event_windows": {"windows": len(windows), "seconds": round(window_s, 6), "requests": len(in_window),
                              "ok": ok_in, "per_s": _g2t_ratio(len(in_window), window_s),
                              "ok_per_s": _g2t_ratio(ok_in, window_s), "ok_share": _g2t_ratio(ok_in, len(in_window)),
                              "arrivals": {"offered": len(windowed),
                                           "admitted": sum(a.get("admitted") is True for a in windowed),
                                           "dropped": sum(a.get("admitted") is False for a in windowed)}},
            "outside_windows": {"seconds": round(outside_s, 6), "requests": len(requests) - len(in_window),
                                "ok": ok - ok_in, "per_s": _g2t_ratio(len(requests) - len(in_window), outside_s),
                                "ok_per_s": _g2t_ratio(ok - ok_in, outside_s),
                                "ok_share": _g2t_ratio(ok - ok_in, len(requests) - len(in_window))},
            "dropped": {"measure": by_phase["measure"], "by_phase": by_phase,
                        "all": dict(Counter(str(a.get("drop_reason")) for a in arrivals
                                            if a.get("admitted") is False))},
            "arrivals": summary.get("arrivals"), "log_problems": summary.get("problems") or []}
