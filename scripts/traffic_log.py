#!/usr/bin/env python3
"""Read, check and summarize the JSONL logs written by scripts/host_traffic.py.

A run produces a request log (one record per HTTP request) and an interval log
(one record per summary interval). Both start with a header record, end with an
end record and carry the file schema plus a contiguous record number n on every
line, so a torn or incomplete log is detectable. summarize() recomputes every
cross-check and reports each inconsistency as a string in `problems`;
percentiles are exact nearest-rank over the request records, and interval
histograms are only ever merged by adding counts, never averaged.

CLI: python3 scripts/traffic_log.py summarize --requests A --intervals B [--session-id X]
prints the summary as JSON and exits 0 when there are no problems, else 2.

Protocol v5 (package B5b): the profiles eshop and corp write schemas /2 (design B5b 1.4), the profiles legacy
and lab keep /1. A /2 request log also holds one arrival record per offered user session; its header states the
load model, the scenario, the rate, the seeds, the profile's parameters and the planned envelope, its intervals
count the offered, admitted and dropped user sessions and the planned ones. summarize() reads both schemas and
cross-checks the new counts; realism() computes the realism requirements of proposal 5.7 and the offered-load
check of proposal 5.3 from a /2 pair (design B5b 1.5).
"""
import argparse
import bisect
from collections import Counter, defaultdict
from datetime import datetime
import json
import math
from pathlib import Path
import re
import sys

REQUEST_SCHEMA = "hyptcn3/traffic-request/1"
INTERVAL_SCHEMA = "hyptcn3/traffic-interval/1"
# The open-loop logs of the v5 profiles (design B5b 1.4); every /1 field stays, new fields and the arrival record
# come in addition.
REQUEST_SCHEMA_2 = "hyptcn3/traffic-request/2"
INTERVAL_SCHEMA_2 = "hyptcn3/traffic-interval/2"
SCHEMA_PAIRS = {REQUEST_SCHEMA: INTERVAL_SCHEMA, REQUEST_SCHEMA_2: INTERVAL_SCHEMA_2}
SUMMARY_SCHEMA = "hyptcn3/traffic-summary/1"
PHASES = ("warmup", "measure", "post")
OUTCOMES = ("ok", "http_error", "timeout", "transport_error")
# Design B5b 1.4: what a /2 log adds to the /1 records.
V5_HEADER_KEYS = ("load_model", "profile", "scenario", "intensity", "rate", "rate_source", "seeds", "protocol_sha256",
                  "profile_parameters", "warmup_s", "envelope")
SEED_PURPOSES = ("traffic", "traffic_arrivals", "traffic_choices", "traffic_sizes")  # Design B5b 1.2 and 1.3.
RATE_SOURCES = ("protocol", "command line")
ARRIVAL_KEYS = ("user_session", "t_mono", "t_utc", "phase", "admitted", "active")
V5_REQUEST_KEYS = ("user_session", "step", "object", "intended_status", "think_s")
V5_INTERVAL_KEYS = ("offered_sessions", "admitted_sessions", "dropped_sessions", "planned_sessions", "active_max")
V5_END_KEYS = ("arrivals", "admitted", "dropped", "user_sessions_completed", "user_sessions_in_progress_at_stop")
# t_mono and the interval bounds are rounded to 6 decimals: an arrival within this of a bound may belong to either
# interval.
TIME_EPS = 1e-6
V5_PROFILES = ("eshop", "corp")
# The requirements realism() returns, in this order (design B5b 1.5); each failing one is the log-audit reason
# traffic_realism:<name>. A requirement of one profile only is listed only for that profile (proposal 5.7).
REALISM = ("arrival_cv", "think_time", "order_share", "object_concentration", "success_rate", "response_sizes",
           "peak_to_mean", "background")
REALISM_PROFILES = {"think_time": ("eshop",), "order_share": ("eshop",), "background": ("corp",)}
# The kind of the object a request names, by route (lab/nginx.conf and lab/services.py): the same product in its
# detail and in the cart is one object; ids of different kinds never collide.
OBJECT_KINDS = (("/static/", "static file"), ("/api/catalog", "product"), ("/api/cart", "product"),
                ("/api/orders", "product"), ("/api/docs", "document"), ("/api/reports", "report"))
HIST_FIRST_MS, HIST_RATIO, HIST_MAX_MS = .05, 1.05, 60000.0
HIST_PRECISION = ("log-spaced buckets: bucket i holds durations in (edge[i-1], edge[i]] ms with "
                  "edge[i] = 0.05 * 1.05**i (bucket 0 starts at 0 ms); bucket len(edges) is the "
                  "overflow bucket above the last edge (>= 60 s). Relative bucket width 5 %, so a "
                  "percentile read from the bucket upper edge overestimates the exact nearest-rank "
                  "value by at most 5 %. Histograms merge across intervals by adding counts.")


def bucket_edges():
    """Bucket upper edges in ms (0.05 * 1.05**k); the last edge is >= 60 s."""
    edges, k = [], 0
    while True:
        edges.append(HIST_FIRST_MS * HIST_RATIO ** k)
        if edges[-1] >= HIST_MAX_MS:
            return edges
        k += 1


EDGES = bucket_edges()
OVERFLOW = len(EDGES)


def bucket_index(ms):
    """Bucket holding a duration: smallest i with ms <= EDGES[i], or OVERFLOW."""
    return bisect.bisect_left(EDGES, ms)


def merge_hist(*hists):
    """Add sparse histograms {bucket index (str or int): count} into one with str keys."""
    total = Counter()
    for hist in hists:
        for key, count in hist.items():
            total[str(key)] += count
    return dict(total)


def hist_percentile(hist, q):
    """Upper edge (ms) of the bucket holding the nearest-rank q-quantile, 0 < q <= 1.

    The exact value lies in (edge / 1.05, edge], so the result overestimates it by
    less than 5 %. None for an empty histogram or when the rank falls into the
    overflow bucket.
    """
    total = sum(hist.values())
    if not total:
        return None
    rank, seen = max(1, math.ceil(q * total)), 0
    for key in sorted(hist, key=int):
        seen += hist[key]
        if seen >= rank:
            return EDGES[int(key)] if int(key) < OVERFLOW else None
    return None


def percentile(sorted_values, q):
    """Exact nearest-rank q-quantile (0 < q <= 1) of an ascending list; None when empty."""
    if not sorted_values:
        return None
    return sorted_values[max(1, math.ceil(q * len(sorted_values))) - 1]


def first_schema(path):
    """The schema of a log's first record, None when it is no JSON object with one (read_jsonl says why)."""
    with Path(path).open("rb") as stream:
        line = stream.readline()
    try:
        record = json.loads(line)
    except ValueError:
        return None
    return record.get("schema") if isinstance(record, dict) else None


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


class Problems:
    """Problem strings; at most LIMIT details per key, the rest is counted."""
    LIMIT = 10

    def __init__(self):
        self.items, self.counts = [], Counter()

    def add(self, key, detail=None):
        self.counts[key] += 1
        if self.counts[key] <= self.LIMIT:
            self.items.append(key if detail is None else f"{key}:{detail}")

    def result(self):
        return self.items + [f"{key}:more:{count - self.LIMIT}"
                             for key, count in sorted(self.counts.items()) if count > self.LIMIT]


def _latency(values):
    """Exact nearest-rank percentiles of an ascending list of durations."""
    return {"n": len(values), "p50": percentile(values, .5), "p90": percentile(values, .9),
            "p95": percentile(values, .95), "p99": percentile(values, .99),
            "max": values[-1] if values else None}


def _routes(records):
    routes = {}
    for record in records:
        entry = routes.setdefault(f"{record.get('method')} {record.get('route')}",
                                  {"requests": 0, "ok": 0, "errors": 0, "status_codes": Counter()})
        entry["requests"] += 1
        entry["ok" if record.get("outcome") == "ok" else "errors"] += 1
        entry["status_codes"][str(record.get("status", "none")) if record.get("status") is not None else "none"] += 1
    return {key: dict(entry, status_codes=dict(entry["status_codes"])) for key, entry in sorted(routes.items())}


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def envelope_problem(envelope):
    """Why a planned envelope is not the one of design B5b 1.4, None when it is: {"t_s": [...], "level": [...]},
    the level piecewise linear over [0, D], t_s strictly increasing from 0 to D, every level in [0, 1], the maximum
    exactly 1."""
    if type(envelope) is not dict or set(envelope) != {"t_s", "level"}:
        return "keys"
    t, level = envelope["t_s"], envelope["level"]
    if type(t) is not list or type(level) is not list or len(t) < 2 or len(t) != len(level):
        return "length"
    if not all(map(_finite, t + level)):
        return "values"
    if t[0] != 0 or any(b <= a for a, b in zip(t, t[1:])):
        return "times"
    if not all(0 <= x <= 1 for x in level) or max(level) != 1:
        return "levels"
    return None


class Envelope:
    """The planned envelope of a /2 header as a function of the time since the generator's origin (t_mono): linear
    between its points, 0 outside [0, D]. The generator draws arrivals from rate x this level."""

    def __init__(self, envelope):
        why = envelope_problem(envelope)
        if why:
            raise ValueError("invalid envelope: " + why)
        self.t, self.level = list(envelope["t_s"]), list(envelope["level"])
        self.end = self.t[-1]
        self.area = [0.0]  # The integral of the level from 0 to each point.
        for i in range(1, len(self.t)):
            self.area.append(self.area[-1] + (self.t[i] - self.t[i - 1]) * (self.level[i] + self.level[i - 1]) / 2)

    def _segment(self, x):
        return min(max(bisect.bisect_right(self.t, x) - 1, 0), len(self.t) - 2)

    def at(self, x):
        """The planned level at time x."""
        if not 0 <= x <= self.end:
            return 0.0
        i = self._segment(x)
        t0, t1, l0, l1 = self.t[i], self.t[i + 1], self.level[i], self.level[i + 1]
        return l0 + (l1 - l0) * (x - t0) / (t1 - t0)

    def cumulative(self, x):
        """The integral of the level from 0 to x."""
        x = min(max(x, 0.0), self.end)
        i = self._segment(x)
        return self.area[i] + (x - self.t[i]) * (self.level[i] + self.at(x)) / 2

    def integral(self, a, b):
        """The integral of the level over [a, b]."""
        return self.cumulative(b) - self.cumulative(a) if b > a else 0.0

    def peak(self, a, b):
        """The largest level on [a, b], both clamped to [0, D]."""
        a, b = max(a, 0.0), min(b, self.end)
        return max([self.at(a), self.at(b), *(level for t, level in zip(self.t, self.level) if a < t < b)])


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
    """
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

    # Arrival records.
    pattern = re.compile(re.escape(str(head.get("run_id"))) + r"-u\d+")
    arrivals, sessions, latest = [], {}, None
    for record in (r for r in requests if r.get("type") == "arrival"):
        uid = record.get("user_session")
        if (any(key not in record for key in ARRIVAL_KEYS) or type(uid) is not str
                or type(record["admitted"]) is not bool or type(record["active"]) is not int or record["active"] < 0
                or not _finite(record["t_mono"]) or record["phase"] not in PHASES):
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
        if cap is not None and (record["active"] >= cap if record["admitted"] else record["active"] != cap):
            problems.add("arrival_cap", uid)
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
    further (_v5_problems) and its summary counts the arrivals.
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
    if ivs and not abs(ivs[0].get("mono_start", math.nan)) <= 1e-9:  # NaN (a missing key) fails too
        problems.add("intervals_not_from_origin", ivs[0].get("mono_start"))
    if ivs and end_i and not abs(ivs[-1].get("mono_end", math.nan) - end_i.get("end_mono", math.nan)) <= 1e-9:
        problems.add("intervals_not_to_end", f"{ivs[-1].get('mono_end')}!={end_i.get('end_mono')}")

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


def _unix(value):
    time = datetime.fromisoformat(value)
    if time.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return time.timestamp()


def _round(value):
    return None if value is None else round(value, 6)


def _requirement(name, value, bound, ok, note):
    return {"name": name, "value": value, "bound": bound, "ok": bool(ok), "note": note}


def object_kind(route):
    """The kind of the object a request of this route names (OBJECT_KINDS); the route itself for any other."""
    return next((kind for prefix, kind in OBJECT_KINDS if route.startswith(prefix)), route)


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
      think_time (eshop)    the drawn think times (think_s): their mean within think_mean_tolerance_se standard
                            errors (sample standard deviation over sqrt(n)) of profiles.eshop.think_s.mean, their
                            maximum at most think_s.max
      order_share (eshop)   the share of the admitted user sessions that arrived in the measure phase, lie outside
                            every window (arrival and every request) and place an order (POST /api/orders without
                            an intended status), within order_share_tolerance_se standard errors
                            (sqrt(p (1 - p) / n)) of p = profiles.eshop.order_share[<intensity>]
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
                            intervals that overlap no window: within offered_load_tolerance of 1
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
        thinks = [r["think_s"] for r in requests if r["think_s"] is not None]
        mean = tolerance = largest = None
        if len(thinks) >= 2:
            mean = sum(thinks) / len(thinks)
            sd = math.sqrt(sum((x - mean) ** 2 for x in thinks) / (len(thinks) - 1))
            tolerance, largest = limit["think_mean_tolerance_se"] * sd / math.sqrt(len(thinks)), max(thinks)
        good = mean is not None and abs(mean - design["mean"]) <= tolerance and largest <= design["max"]
        out.append(_requirement("think_time", {"mean": _round(mean), "max": largest, "n": len(thinks)},
                                {"mean": design["mean"], "tolerance": _round(tolerance), "max": design["max"]}, good,
                                f"{len(thinks)} think times of the measure phase; the mean within "
                                f"{limit['think_mean_tolerance_se']:g} standard errors of the profile's mean"))

        share_design = params["order_share"][intensity]
        sessions = {a["user_session"]: {"times": [_unix(a["t_utc"])], "orders": 0} for a in arrivals if a["admitted"]}
        for r in every:
            if r["user_session"] in sessions:
                entry = sessions[r["user_session"]]
                entry["times"] += [_unix(r["t_start_utc"]), _unix(r["t_end_utc"])]
                entry["orders"] += (r["method"] == "POST" and r["route"] == "/api/orders"
                                    and r["intended_status"] is None)
        kept = [s for s in sessions.values() if not overlaps(min(s["times"]), max(s["times"]))]
        share = sum(1 for s in kept if s["orders"]) / len(kept) if kept else None
        tolerance = (limit["order_share_tolerance_se"] * math.sqrt(share_design * (1 - share_design) / len(kept))
                     if kept else None)
        out.append(_requirement("order_share", _round(share), {"share": share_design, "tolerance": _round(tolerance)},
                                share is not None and abs(share - share_design) <= tolerance,
                                f"{sum(1 for s in kept if s['orders'])} of {len(kept)} user sessions ordered "
                                f"(intensity {intensity}); {len(sessions) - len(kept)} touching a window left out"))

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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("summarize", help="audit a request/interval log pair and print JSON")
    audit.add_argument("--requests", required=True, type=Path)
    audit.add_argument("--intervals", required=True, type=Path)
    audit.add_argument("--session-id", help="expected session id (header must match)")
    real = commands.add_parser("realism", help="realism requirements and offered load of a /2 pair, as JSON")
    real.add_argument("--requests", required=True, type=Path)
    real.add_argument("--intervals", required=True, type=Path)
    real.add_argument("--protocol", required=True, type=Path, help="the schema-3 protocol the generator read")
    real.add_argument("--scenario", required=True)
    real.add_argument("--windows", default="[]", help="JSON list of [start, end] unix times of event windows")
    args = parser.parse_args(argv)
    if args.command == "realism":
        root = str(Path(__file__).resolve().parents[1])
        if root not in sys.path:  # features/audit_policy.py when run as a script
            sys.path.insert(0, root)
        try:
            result = realism(args.requests, args.intervals, json.loads(args.protocol.read_text()), args.scenario,
                             windows=[tuple(w) for w in json.loads(args.windows)])
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"traffic_log: {type(error).__name__}: {error}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2))
        return 0 if all(r["ok"] for r in result["requirements"]) and result["offered_load"]["ok"] else 2
    result = summarize(args.requests, args.intervals, session_id=args.session_id)
    print(json.dumps(result, indent=2))
    return 0 if not result["problems"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
