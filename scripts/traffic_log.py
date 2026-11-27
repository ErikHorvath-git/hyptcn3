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

Package B18 (Q87: the executor's decision, for the lead's review; the lead's rule to Q86): the request log is read as a
stream. Before B18 summarize and realism held every record of it (read_jsonl), and the session audit of one session of
eshop_high at the protocol file's rate 93.9016 (a request log of about 700 MB, 1.1 million requests) peaked at 8.8 GB
beside two lab VMs whose memory the kernel would take back by killing one; the bound is 1.5 GB. JsonlStream parses one
line at a time and finds exactly read_jsonl's problems; summarize and realism read the request log in one pass (a
second one only where an arrival record follows a request of its own user session) and hold counters, the histograms,
the state of each user session and compact arrays of the numbers a statistic reads every one of. The interval log, one
record per summary interval, is read whole as before, and read_jsonl stays for it and the other small logs. Every
result equals the one of the code before B18, its problems in their order with their details, its exceptions too:
scripts/tests/traffic_log_pred_b18.py holds that code frozen, scripts/tests/test_traffic_stream_b18.py compares.
"""
import argparse
from array import array
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
ARRIVAL_KEYS = ("user_session", "t_mono", "t_utc", "phase", "admitted", "active", "customer", "drop_reason")
# Package B5c (finding F2 of B5b): the named reasons of a dropped arrival (scripts/host_traffic.py DROP_MAX_CONCURRENT,
# DROP_CUSTOMERS) and the user name of a customer of lab/seed.py (host_traffic customer_name); the audit reads both
# (finding F1 of the B5c verification, package B10).
DROP_REASONS = ("max_concurrent", "all_customers_held")
CUSTOMER_NAME = re.compile(r"zakaznik(\d{4,})")
V5_REQUEST_KEYS = ("user_session", "step", "object", "intended_status", "think_s")
V5_INTERVAL_KEYS = ("offered_sessions", "admitted_sessions", "dropped_sessions", "planned_sessions", "active_max")
V5_END_KEYS = ("arrivals", "admitted", "dropped", "user_sessions_completed", "user_sessions_in_progress_at_stop")
# t_mono and the interval bounds are rounded to 6 decimals: an arrival within this of a bound may belong to either
# interval.
TIME_EPS = 1e-6
# Package B16 (should_fix 1 of the fifth G0 verification, Q82: the executor's decision, for the lead's review): the
# most by which a wall time of a /2 log pair may differ from the start_unix of the request log's header plus the
# record's own monotonic time; summarize refuses a pair with a record beyond it (wall_clock). The rule: 1 s is the
# bound of the log audit's traffic_measure_bounds (scripts/collection_logs.py: the phase markers against end.json).
# Honest logs differ by less than 2 ms (the arrivals of the 74 log pairs of the H2 runs of G2: -0.0019 to +1.5068 ms),
# and CLOCK_MONOTONIC follows NTP's slew, so only a step of the wall clock moves the difference. realism places the
# event windows by the records' wall times and the intervals of the offered load by start_unix plus their monotonic
# time (features/qualification.py offered_load as well); bound to each other, either may place them.
WALL_CLOCK_TOLERANCE_S = 1.0
# Package B16: the (wall time, monotonic time) fields of each kind of record that summarize binds by
# WALL_CLOCK_TOLERANCE_S, in both logs of a /2 pair (the phase markers and the end record are in both).
WALL_CLOCK_FIELDS = {"arrival": (("t_utc", "t_mono"),), "phase": (("t_utc", "t_mono"),),
                     "request": (("t_start_utc", "t_start_mono"), ("t_end_utc", "t_end_mono")),
                     "interval": (("t_start_utc", "mono_start"), ("t_end_utc", "mono_end")),
                     "end": (("end_utc", "end_mono"),)}
# The executor's judgment (package B10, finding F6 of B5b): the think time realism() judges is the realized one,
# from the end of a request to the start of the next request of its user session; the generator's scheduler and its
# pool add their own delay to a drawn think time, so the realized maximum may lie this much above the profile's
# think_s.max (a drawn time is cut at it) before the requirement fails. Proposal 5.7 and audit.traffic.note of the
# protocol state the allowance.
THINK_LAG_S = 1.0
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


class JsonlStream:
    """Package B18 (Q87): a log read as a stream, one line at a time, never whole and never split as a whole.

    Iterating it (once) yields (line number, record) for every complete line that is a JSON object, in the order of
    the file; a line is read up to its newline and parsed alone, and the bytes after the final newline are never
    parsed, as read_jsonl leaves them. Afterwards problems() gives exactly the problems read_jsonl gives, in its order.
    It holds only the first record (the header), the last record, the counts, and in compact arrays the line numbers
    of the lines that are no JSON object and of the records whose schema or n is wrong (none in an honest log); no
    record besides. Opening it (open, or the first iteration) raises the OSError read_jsonl's read raises, and a line
    json.loads cannot parse for any other reason (a RecursionError) raises as there."""

    def __init__(self, path, schema=None):
        self.path, self.schema = path, schema
        self.size = self.lines = self.records = 0  # Bytes read, complete lines, JSON objects.
        self.tail = False  # Bytes after the final newline.
        self.header = self.last = None  # The first and the last record.
        self._bad = array("q")  # Line numbers of the complete lines that are no JSON object.
        self._later = array("q")  # 2 * line number + 1 for n_discontinuous, + 0 for schema_mismatch, in line order.
        self._stream, self._read = None, False

    def open(self):
        """Open the log now, so that a log that cannot be opened raises before anything else is read."""
        if self._stream is None and not self._read:
            self._stream = open(self.path, "rb")
        return self

    def __iter__(self):
        if self._read:
            raise RuntimeError("a JsonlStream is read once")
        self.open()
        self._read = True
        stream, self._stream = self._stream, None
        with stream:
            previous = schema = None
            for line in stream:
                self.size += len(line)
                if line[-1:] != b"\n":
                    self.tail = True  # The last piece: bytes after the final newline, never parsed.
                    break
                self.lines += 1
                lineno = self.lines
                try:
                    record = json.loads(line[:-1])
                    if not isinstance(record, dict):
                        raise ValueError("not an object")
                except ValueError:
                    self._bad.append(lineno)
                    continue
                self.records += 1
                if self.records == 1:
                    self.header, schema = record, record.get("schema")
                elif record.get("schema") != schema:
                    self._later.append(2 * lineno)
                n = record.get("n")
                if not isinstance(n, int) or n != (0 if previous is None else previous + 1):
                    self._later.append(2 * lineno + 1)
                previous = n if isinstance(n, int) else previous
                self.last = record
                yield lineno, record

    def problems(self):
        """The problems of read_jsonl after a complete iteration, in its order (a generator: a broken log can have one
        a line)."""
        if not self.size:
            yield "empty_file"
            return
        if self.tail:
            yield "torn_last_line"
        for lineno in self._bad:
            yield "torn_last_line" if lineno == self.lines and not self.tail else f"corrupt_line:{lineno}"
        if not self.records:
            yield "missing_header"
            return
        header = self.header
        if header.get("type") != "header" or not header.get("schema"):
            yield "missing_header"
        if self.schema and header.get("schema") != self.schema:
            yield f"schema_mismatch:{header.get('schema')}"
        for code in self._later:
            yield f"n_discontinuous:{code >> 1}" if code & 1 else f"schema_mismatch:{code >> 1}"


def read_jsonl(path, schema=None):
    """Parse a log into (records, problems) without trusting its completeness.

    Problems: empty_file, torn_last_line (unterminated or invalid last line),
    corrupt_line:<lineno>, missing_header, schema_mismatch:<header schema or lineno>
    (header differs from `schema`, or a record differs from the header) and
    n_discontinuous:<lineno> (record numbers must run 0, 1, 2, ...).

    Package B18: built on JsonlStream and kept for the small logs (the interval log, one record per summary interval)
    and its other callers; it holds every record, so the request log of a session is read as a JsonlStream instead
    (summarize, realism, scripts/collection_logs.py RequestIndex).
    """
    stream = JsonlStream(path, schema)
    records = [record for _, record in stream]
    return records, list(stream.problems())


class LogPair:
    """Package B18: both logs of a pair as read_jsonl of the request log, then of the interval log, reads them, the
    request log as a stream (JsonlStream, `requests`) and the interval log whole (`intervals` and `interval_problems`,
    read first: summarize and realism set up their checks of the requests from it). A log that cannot be read raises
    in the order of the two reads: the request log's open and read errors first, then the interval log's, which
    records() raises after the last record of the request log."""

    def __init__(self, requests_path, intervals_path, schema=None, intervals_schema=None):
        self.requests = JsonlStream(requests_path, schema).open()
        try:
            self.intervals, self.interval_problems = read_jsonl(intervals_path, intervals_schema)
            self._failed = None
        except Exception as error:  # noqa: BLE001 - raised once the request log is read, as there
            self.intervals = self.interval_problems = None
            self._failed = error

    def records(self):
        """The records of the request log in order; then the interval log's read error, if it had one."""
        if self._failed is None:
            for _, record in self.requests:
                yield record
            return
        for _ in self.requests:
            pass
        raise self._failed


class _Missing:
    """A field a record lacks, in the compact columns of package B18 (record[key] raises KeyError there)."""
    __slots__ = ()

    def __repr__(self):
        return "<missing>"


MISSING = _Missing()


class Values:
    """Package B18: the values of one field of records in their order, compact: an array of doubles (8 bytes a value)
    while every value is a float, else the objects themselves (MISSING where a record lacks the field), so every value
    read back is the record's own, of its type."""
    __slots__ = ("_floats", "_objects", "missing")

    def __init__(self):
        self._floats, self._objects, self.missing = array("d"), None, False

    def append(self, value):
        if self._objects is None:
            if type(value) is float:
                self._floats.append(value)
                return
            self._objects, self._floats = self._floats.tolist(), None
        self.missing = self.missing or value is MISSING
        self._objects.append(value)

    def __len__(self):
        return len(self._objects if self._objects is not None else self._floats)

    def __getitem__(self, i):
        return (self._objects if self._objects is not None else self._floats)[i]

    def __iter__(self):
        return iter(self._objects if self._objects is not None else self._floats)


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


class _Recorder:
    """Package B18: the problems of one step of summarize, recorded while the request log streams by and added to the
    result's Problems in that step's place of the order: (key, detail) of at most Problems.LIMIT of each key, in the
    order added, and the count of every key. replay(problems) adds them as if they had been added there one by one
    (a detail beyond the limit is only counted there too)."""

    def __init__(self):
        self.items, self.counts = [], Counter()

    def add(self, key, detail=None):
        self.counts[key] += 1
        if self.counts[key] <= Problems.LIMIT:
            self.items.append((key, detail))

    def replay(self, problems):
        for key, detail in self.items:
            problems.add(key, detail)
        for key, count in self.counts.items():
            problems.counts[key] += count - min(count, Problems.LIMIT)


def _latency(values):
    """Exact nearest-rank percentiles of an ascending list of durations."""
    return {"n": len(values), "p50": percentile(values, .5), "p90": percentile(values, .9),
            "p95": percentile(values, .95), "p99": percentile(values, .99),
            "max": values[-1] if values else None}


class _RouteCounts:
    """_routes() fed one record at a time (package B18): one entry per route, never the records; the first exception
    (a value str() cannot show) is raised by result(), where _routes raised it."""

    def __init__(self):
        self.routes, self.error = {}, None

    def add(self, record):
        if self.error is not None:
            return
        try:
            entry = self.routes.setdefault(f"{record.get('method')} {record.get('route')}",
                                           {"requests": 0, "ok": 0, "errors": 0, "status_codes": Counter()})
            entry["requests"] += 1
            entry["ok" if record.get("outcome") == "ok" else "errors"] += 1
            entry["status_codes"][str(record.get("status", "none")) if record.get("status") is not None
                                  else "none"] += 1
        except Exception as error:  # noqa: BLE001 - raised at its place (result)
            self.error = error

    def result(self):
        if self.error is not None:
            raise self.error
        return {key: dict(entry, status_codes=dict(entry["status_codes"]))
                for key, entry in sorted(self.routes.items())}


def _routes(records):
    counts = _RouteCounts()
    for record in records:
        counts.add(record)
    return counts.result()


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _record_id(kind, log, record):
    """The id of a record in the detail of wall_clock: the user session of an arrival, the request id, the interval
    index, and for a phase marker and an end record, which both logs hold, the log (with the phase)."""
    if kind == "arrival":
        return record.get("user_session")
    if kind == "request":
        return record.get("rid")
    if kind == "interval":
        return record.get("interval")
    return f"{log}:{record.get('phase')}" if kind == "phase" else log


def wall_clock(origin, log, records):
    """Package B16: "<kind>:<id>" of the first of `records` (the records of one log of a /2 pair, `log` its name)
    whose wall time differs from `origin`, the start_unix of the request log's header, plus its own monotonic time by
    more than WALL_CLOCK_TOLERANCE_S, by the fields of WALL_CLOCK_FIELDS; None when none does. A wall time that is
    missing, or no ISO-8601 time with a timezone, differs; an interval's wall times count where it carries them (the
    generator derives them from start_unix). A field pair whose monotonic time is no finite number is left out: the
    check that reads that time names it (arrival_malformed, request_malformed, interval_v5_malformed,
    requests:end_mono_mismatch, intervals_not_to_end, and for the post marker the session audit's traffic_stop).
    Package B18: summarize applies wall_clock_of to each record of the request log as it streams by."""
    for record in records:
        found = wall_clock_of(origin, log, record)
        if found is not None:
            return found
    return None


def wall_clock_of(origin, log, record):
    """wall_clock of one record: its "<kind>:<id>" when one of its wall times differs, else None (package B18)."""
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


def _v5_header(problems, header_r, header_i):
    """The checks of the headers of a /2 pair, the first part of _v5_problems, into `problems`; returns (envelope,
    rate, cap, statuses) as its checks of the records read them: the planned Envelope, the rate, the profile's
    max_concurrent and its client error statuses, each None where it is invalid."""
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
    return envelope, rate, cap, statuses


class _User:
    """Package B18: what _v5_problems keeps of the requests of one admitted user session (its by_session): the first by
    t_start_mono (the earliest of equal ones, as the stable sort puts it first) with its think_s and rid, (t_start_mono,
    position, rid) of the ones without think_s, and the latest finite t_end_mono, or the exception reading one raised
    (raised where the check of held customers reads the ends)."""
    __slots__ = ("start", "position", "think", "rid", "nones", "end", "end_error")

    def __init__(self):
        self.start = self.position = self.think = self.rid = self.end = self.end_error = None
        self.nones = []

    def add(self, r, position):
        start = r["t_start_mono"]
        if self.position is None or start < self.start:
            self.start, self.position, self.think, self.rid = start, position, r["think_s"], r.get("rid")
        if r["think_s"] is None:
            self.nones.append((start, position, r.get("rid")))
        if self.end_error is None:
            try:
                if _finite(r.get("t_end_mono")) and (self.end is None or r["t_end_mono"] > self.end):
                    self.end = r["t_end_mono"]
            except Exception as error:  # noqa: BLE001 - raised at its place (_V5Scan.problems)
                self.end_error = error


class _V5Scan:
    """Package B18: _v5_problems over the records of the request log as they stream by (the docstring of _v5_problems
    states the checks). Each arrival record is checked as it comes. Each request is checked against the user sessions
    whose arrival records came before it, which in an honest log are all of them: where an arrival record follows a
    request of its user session, or repeats an earlier one (again), the loop over the requests runs once more over the
    log once every arrival is known. Held: one small record per well-formed arrival (its user session, t_mono,
    admitted, phase and customer), per admitted user session a _User, the user sessions the requests named, the
    problems of the two loops (_Recorder) and the first exception of each, which problems() raises at its place."""

    def __init__(self, header_r, header_i):
        from lab import seed  # The customers of the lab (lab/seed.py SIZES), as scripts/host_traffic.py Lab reads them.
        self.customers = seed.SIZES["customers"]
        self.header_r, self.header_i = header_r, header_i
        self.offered, self.arrivals, self.sessions, self.latest = 0, [], {}, None
        self.arrival_problems, self.arrival_error, self.asked, self.again = _Recorder(), None, set(), False
        self._reset_requests()
        try:  # The checks of the records read the header's values; an exception of the header is raised at its place.
            _, _, self.cap, self.statuses = _v5_header(_Recorder(), header_r, header_i)
            head = header_r or {}
            self.known, self.eshop = head.get("profile") in V5_PROFILES, head.get("profile") == "eshop"
            self.pattern = re.compile(re.escape(str(head.get("run_id"))) + r"-u\d+")
            self.header_error = None
        except Exception as error:  # noqa: BLE001
            self.header_error = error

    def _reset_requests(self):
        self.request_problems, self.request_error, self.users, self.position = _Recorder(), None, {}, 0

    def arrival(self, record):
        self.offered += 1
        if self.header_error is None and self.arrival_error is None:
            try:
                self._arrival(record)
            except Exception as error:  # noqa: BLE001 - raised at its place (problems)
                self.arrival_error = error

    def _arrival(self, record):
        problems, cap = self.arrival_problems, self.cap
        uid = record.get("user_session")
        if (any(key not in record for key in ARRIVAL_KEYS) or type(uid) is not str
                or type(record["admitted"]) is not bool or type(record["active"]) is not int or record["active"] < 0
                or not _finite(record["t_mono"]) or record["phase"] not in PHASES
                or type(record["customer"]) not in (str, type(None))
                or type(record["drop_reason"]) not in (str, type(None))):
            problems.add("arrival_malformed", uid if type(uid) is str else None)
            return
        if not self.pattern.fullmatch(uid):
            problems.add("user_session_id", uid)
        if uid in self.sessions:
            problems.add("duplicate_user_session", uid)
        self.again = self.again or uid in self.asked  # A request of this user session read the arrivals before it.
        arrival = {key: record[key] for key in ("user_session", "t_mono", "admitted", "phase", "customer")}
        self.sessions[uid] = arrival
        if self.latest is not None and record["t_mono"] < self.latest:
            problems.add("arrival_order", uid)
        self.latest = record["t_mono"] if self.latest is None else max(self.latest, record["t_mono"])
        reason = record["drop_reason"]
        if record["admitted"] is (reason is not None) or reason not in (None, *DROP_REASONS):
            problems.add("arrival_drop_reason", uid)
        elif reason == DROP_REASONS[1]:  # Judged by the profile and the cap, once both are known.
            if self.known and cap is not None and not (self.eshop and self.customers <= record["active"] < cap):
                problems.add("arrival_customers", uid)
        elif cap is not None and (record["active"] >= cap if record["admitted"] else record["active"] != cap):
            problems.add("arrival_cap", uid)
        name = CUSTOMER_NAME.fullmatch(record["customer"]) if record["customer"] is not None else None
        if record["customer"] is not None and not (record["admitted"] and name and 1 <= int(name[1]) <= self.customers):
            problems.add("arrival_customer", uid)
        self.arrivals.append(arrival)

    def request(self, r):
        if self.header_error is None and self.request_error is None:
            try:
                self._request(r)
            except Exception as error:  # noqa: BLE001 - raised at its place (problems)
                self.request_error = error

    def _request(self, r):
        problems = self.request_problems
        self.position += 1
        rid = r.get("rid")
        if (any(key not in r for key in V5_REQUEST_KEYS) or type(r["user_session"]) is not str
                or type(r["step"]) is not str or not r["step"] or type(r["object"]) not in (int, str, type(None))
                or type(r["intended_status"]) not in (int, type(None))
                or r["think_s"] is not None and not (_finite(r["think_s"]) and r["think_s"] >= 0)):
            problems.add("request_v5_malformed", rid)
            return
        uid = r["user_session"]
        if r["intended_status"] is not None and (self.statuses is None or r["intended_status"] not in self.statuses):
            problems.add("intended_status_unknown", rid)
        self.asked.add(uid)
        arrival = self.sessions.get(uid)
        if arrival is None:
            problems.add("request_user_session_unknown", rid)
        elif not arrival["admitted"]:
            problems.add("request_user_session_dropped", rid)
        elif _finite(r.get("t_start_mono")):
            if r["t_start_mono"] < arrival["t_mono"] - TIME_EPS:
                problems.add("request_before_arrival", rid)
            user = self.users.get(uid)
            if user is None:
                user = self.users[uid] = _User()
            user.add(r, self.position)  # The order of think times is judged in admitted user sessions only.

    def problems(self, problems, ivs, end_r, again):
        """The problems of _v5_problems into `problems` in its order; returns the counts of its arrivals. again(): the
        records of the request log anew, read where the loop over the requests runs once more."""
        envelope, rate, cap, statuses = _v5_header(problems, self.header_r, self.header_i)
        if self.arrival_error is not None:
            raise self.arrival_error
        self.arrival_problems.replay(problems)
        arrivals = self.arrivals

        # Interval records: the arrivals in time order fill the intervals in their order, each with as many as it
        # claims; every one must lie in its interval.
        queue, position = sorted(arrivals, key=lambda a: a["t_mono"]), 0
        for iv in ivs:
            index = iv.get("interval")
            if (any(type(iv.get(key)) is not int or iv[key] < 0 for key in V5_INTERVAL_KEYS
                    if key != "planned_sessions")
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

        # Requests of user sessions, against every arrival: once more where an arrival followed a request of its own.
        if self.again:
            self._reset_requests()
            for record in again():
                if record.get("type") == "request":
                    self._request(record)
        elif self.request_error is not None:
            raise self.request_error
        self.request_problems.replay(problems)
        for user in self.users.values():
            if user.think is not None:
                problems.add("think_s_first", user.rid)
            for _, position, rid in sorted(user.nones, key=lambda item: item[:2]):
                if position != user.position:
                    problems.add("think_s_missing", rid)
        # One customer per user session in progress (finding F1 of B5c): each holds its customer from its arrival to
        # the end of its last request; a user session whose arrival lies before the end of the one that held it before
        # shares that customer's cart.
        held = defaultdict(list)
        for uid, a in self.sessions.items():
            if a["admitted"] and a["customer"] is not None:
                user = self.users.get(uid)
                if user is not None and user.end_error is not None:
                    raise user.end_error
                ends = [] if user is None or user.end is None else [user.end]
                held[a["customer"]].append((a["t_mono"], max([a["t_mono"], *ends]), uid))
        for spans in held.values():
            latest = None  # The latest end of the user sessions that held the customer before.
            for start, end, uid in sorted(spans):
                if latest is not None and start < latest - TIME_EPS:
                    problems.add("customer_held_twice", uid)
                latest = end if latest is None else max(latest, end)

        offered = self.offered
        admitted = sum(a["admitted"] for a in arrivals)
        if end_r is not None:
            invalid = [key for key in V5_END_KEYS if type(end_r.get(key)) is not int or end_r[key] < 0]
            for key in invalid:
                problems.add("requests:end_v5_invalid", key)
            if not invalid:
                for key, count in (("arrivals", offered), ("admitted", admitted),
                                   ("dropped", len(arrivals) - admitted)):
                    if end_r[key] != count:
                        problems.add("requests:end_arrivals_mismatch", f"{key}:{end_r[key]}!={count}")
                if end_r["user_sessions_completed"] + end_r["user_sessions_in_progress_at_stop"] != end_r["admitted"]:
                    problems.add("requests:end_user_sessions_mismatch")
        measure = [a for a in arrivals if a["phase"] == "measure"]
        return {"offered": offered, "admitted": admitted, "dropped": len(arrivals) - admitted,
                "measure": {"offered": len(measure), "admitted": sum(a["admitted"] for a in measure),
                            "dropped": sum(not a["admitted"] for a in measure)}}


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

    Package B18 (Q87): `requests` are the records of the request log in order and `reqs` its request records, each an
    iterable read once; summarize gives them as its stream goes and calls _V5Scan itself, which this wraps.
    """
    scan = _V5Scan(header_r, header_i)
    for record in requests:
        if record.get("type") == "arrival":
            scan.arrival(record)
    for r in reqs:
        scan.request(r)
    return scan.problems(problems, ivs, end_r, lambda: reqs)


class _Extreme:
    """Package B18: min() (lowest) or max() of the measure-phase requests by one field, fed one record at a time with
    the comparisons min() and max() make: the first of equal ones; the first exception, raised by result()."""
    __slots__ = ("key", "lowest", "record", "value", "error")

    def __init__(self, key, lowest):
        self.key, self.lowest, self.record, self.value, self.error = key, lowest, None, None, None

    def add(self, record):
        if self.error is None:
            try:
                value = record[self.key]
                if self.record is None or (value < self.value if self.lowest else value > self.value):
                    self.record, self.value = record, value
            except Exception as error:  # noqa: BLE001 - raised at its place (result)
                self.error = error

    def result(self):
        if self.error is not None:
            raise self.error
        return self.record


class _Members:
    """Package B18: the request records of one interval value as summarize's check of each interval record with it
    reads them (by_interval): their count and a Counter of their outcomes, of their histogram buckets (all and ok ones)
    and of their status codes, in the order of the records, and the first exception each of these raised (an outcome
    that cannot be counted, a duration_ms that is no number), which that check raises at its place."""
    __slots__ = ("count", "outcomes", "outcome_error", "buckets", "buckets_ok", "bucket_error", "codes", "code_error")

    def __init__(self):
        self.count = 0
        self.outcomes, self.buckets, self.buckets_ok, self.codes = Counter(), Counter(), Counter(), Counter()
        self.outcome_error = self.bucket_error = self.code_error = None

    def add(self, r):
        self.count += 1
        if self.outcome_error is None:
            try:
                self.outcomes[r.get("outcome")] += 1
            except Exception as error:  # noqa: BLE001 - raised at its place, as each of these below
                self.outcome_error = error
        if self.bucket_error is None:
            try:
                bucket = str(bucket_index(r["duration_ms"]))
                self.buckets[bucket] += 1
                if r.get("outcome") == "ok":
                    self.buckets_ok[bucket] += 1
            except Exception as error:  # noqa: BLE001
                self.bucket_error = error
        if self.code_error is None:
            try:
                self.codes["none" if r.get("status") is None else str(r.get("status"))] += 1
            except Exception as error:  # noqa: BLE001
                self.code_error = error

    def outcome_counts(self):
        if self.outcome_error is not None:
            raise self.outcome_error
        return self.outcomes

    def bucket_counts(self):
        if self.bucket_error is not None:
            raise self.bucket_error
        return self.buckets, self.buckets_ok

    def code_counts(self):
        if self.code_error is not None:
            raise self.code_error
        return self.codes


_NO_MEMBERS = _Members()  # by_interval.get(index, []) of an interval value no request names.


class _MemberChecks:
    """Package B18: the loop of summarize's check of one interval record over its members, run as the requests stream
    by: the problems it adds (a _Recorder) and the first exception it raised; replay() adds the problems and raises
    the exception at the loop's place."""
    __slots__ = ("index", "phase", "start", "end", "problems", "error")

    def __init__(self, iv):
        self.index, self.phase = iv.get("interval"), iv.get("phase")
        self.start, self.end = iv["mono_start"], iv["mono_end"]
        self.problems, self.error = _Recorder(), None

    def add(self, r):
        if self.error is None:
            try:
                if r.get("phase") != self.phase:
                    self.problems.add("interval_phase_mismatch", f"{self.index}:{r.get('rid')}")
                if not self.start <= r["t_start_mono"] <= self.end:
                    self.problems.add("request_outside_interval", r.get("rid"))
            except Exception as error:  # noqa: BLE001 - raised at its place (replay)
                self.error = error

    def replay(self, problems):
        self.problems.replay(problems)
        if self.error is not None:
            raise self.error


class _MeasureScan:
    """Package B18: the request records of the measure phase as summarize reads them: their counts by outcome, their
    routes, the records with the earliest and the latest start and end (_Extreme), and as compact Values their
    durations and the ends of the ok ones, which the exact percentiles and the gaps between successes read whole."""

    def __init__(self):
        self.count = self.ok = 0
        self.outcomes = dict.fromkeys(OUTCOMES, 0)
        self.durations, self.ok_flags, self.ok_ends = Values(), bytearray(), Values()
        self.extremes = (_Extreme("t_start_mono", True), _Extreme("t_start_mono", False),
                         _Extreme("t_end_mono", True), _Extreme("t_end_mono", False))
        self.routes = _RouteCounts()

    def add(self, r):
        self.count += 1
        outcome = r.get("outcome")
        for name in OUTCOMES:
            if outcome == name:
                self.outcomes[name] += 1
        ok = outcome == "ok"
        self.ok += ok
        self.durations.append(r.get("duration_ms", MISSING))
        self.ok_flags.append(ok)
        if ok:
            self.ok_ends.append(r.get("t_end_mono", MISSING))
        for extreme in self.extremes:
            extreme.add(r)
        self.routes.add(r)

    def latencies(self, ok=False):
        """sorted(r["duration_ms"] for r in measure), of the oks only with ok, as summarize sorts them."""
        if self.durations.missing:
            raise KeyError("duration_ms")
        if not ok:
            return sorted(self.durations)
        return sorted(value for value, flag in zip(self.durations, self.ok_flags) if flag)

    def completions(self):
        """sorted(r["t_end_mono"] for r in oks)."""
        if self.ok_ends.missing:
            raise KeyError("t_end_mono")
        return sorted(self.ok_ends)


class _SummaryScan:
    """Package B18: what summarize reads of the request log, from its records as they stream by (see summarize): the
    phase markers and the counts, the rids of the requests (duplicate_rid, a Counter as before), the problems of its
    loop over the requests, their members of each interval value and of each interval record (_Members,
    _MemberChecks), their counts by phase and route, the measure phase (_MeasureScan), the first record whose wall time
    differs (wall_clock_of) and the cross-checks of a /2 pair (_V5Scan); and the first exception of each step, which
    summarize raises at that step's place."""

    def __init__(self, intervals, v5):
        self.v5, self.records, self.requests = v5, 0, 0
        self.header_i = intervals[0] if intervals and intervals[0].get("type") == "header" else None
        self.ivs = [iv for iv in intervals if iv.get("type") == "interval"]
        self.marks, self.rids, self.rid_error = [], {}, None
        self.loop_problems, self.loop_error, self.members = _Recorder(), None, {}
        self.checks, self.checks_at = {}, [None] * len(self.ivs)
        for position, iv in enumerate(self.ivs):
            if not all(key in iv for key in ("mono_start", "mono_end", "duration_s")):
                continue  # Its check is malformed before its loop over its members.
            try:
                hash(iv.get("interval"))
            except TypeError:
                continue  # The loop over the intervals raises there (index in seen).
            check = self.checks_at[position] = _MemberChecks(iv)
            self.checks.setdefault(iv.get("interval"), []).append(check)
        self.phases = {phase: [0, dict.fromkeys(OUTCOMES, 0)] for phase in PHASES}
        self.measure, self.routes = _MeasureScan(), _RouteCounts()
        self.origin = self.wall = self.wall_error = self.v5_scan = None

    def feed(self, record):
        self.records += 1
        if self.records == 1:
            header_r = record if record.get("type") == "header" else None
            if self.v5:
                self.v5_scan = _V5Scan(header_r, self.header_i)
                origin = (header_r or {}).get("start_unix")
                try:
                    self.origin = origin if _finite(origin) else None
                except Exception:  # noqa: BLE001 - summarize's own check of start_unix raises it
                    self.origin = None
        if self.origin is not None and self.wall is None and self.wall_error is None:
            try:
                self.wall = wall_clock_of(self.origin, "requests", record)
            except Exception as error:  # noqa: BLE001 - raised at its place (wall_clock)
                self.wall_error = error
        kind = record.get("type")
        if kind == "phase":
            self.marks.append(record)
        elif kind == "request":
            self.request(record)
        elif kind == "arrival" and self.v5:
            self.v5_scan.arrival(record)

    def request(self, r):
        self.requests += 1
        if self.rid_error is None:
            rid = r.get("rid")
            try:
                self.rids[rid] = self.rids.get(rid, 0) + 1
            except Exception as error:  # noqa: BLE001 - raised at its place (duplicates)
                self.rid_error = error
        if self.loop_error is None:
            try:
                self._loop(r)
            except Exception as error:  # noqa: BLE001 - raised at its place (loop)
                self.loop_error = error
        phase = r.get("phase")
        for name in PHASES:
            if phase == name:
                counts = self.phases[name]
                counts[0] += 1
                outcome = r.get("outcome")
                for key in OUTCOMES:
                    if outcome == key:
                        counts[1][key] += 1
        if phase == "measure":
            self.measure.add(r)
        self.routes.add(r)
        if self.v5:
            self.v5_scan.request(r)

    def _loop(self, r):
        """summarize's loop over the requests for one of them: by_interval, the phase, the outcome, the duration."""
        value = r.get("interval")
        members = self.members.get(value)
        if members is None:
            members = self.members[value] = _Members()
        members.add(r)
        for check in self.checks.get(value, ()):
            check.add(r)
        if r.get("phase") not in PHASES:
            self.loop_problems.add("request_phase_unknown", r.get("rid"))
        if r.get("outcome") not in OUTCOMES:
            self.loop_problems.add("request_outcome_unknown", r.get("rid"))
        try:
            if abs((r["t_end_mono"] - r["t_start_mono"]) * 1000 - r["duration_ms"]) > .01:
                self.loop_problems.add("duration_mismatch", r.get("rid"))
        except (KeyError, TypeError):
            self.loop_problems.add("request_malformed", r.get("rid"))

    def duplicates(self):
        """The rids of more than one request, in the order of the first of each (as the Counter gave them)."""
        if self.rid_error is not None:
            raise self.rid_error
        return [rid for rid, count in self.rids.items() if count > 1]

    def loop(self, problems):
        if self.loop_error is not None:
            raise self.loop_error
        self.loop_problems.replay(problems)

    def wall_clock(self):
        if self.wall_error is not None:
            raise self.wall_error
        return self.wall


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

    Package B18 (Q87: the executor's decision, for the lead's review): the request log is read as a stream
    (JsonlStream through LogPair), in one pass, a second one only where an arrival record follows a request of its
    user session (_V5Scan); the interval log, one record per summary interval, is read whole first. Held while the
    request log streams by (_SummaryScan): the counts, the phase markers, the header and the last record, a Counter of
    the rids, the counts and histograms of each interval value, the counts by phase and route, the four extreme
    records of the measure phase and its durations and the ends of its ok requests as compact arrays (8 bytes a
    request), one small record per arrival and the state of each user session, and the problems found (at most
    Problems.LIMIT details of a key); never the records. Each step adds its problems and raises its exception at its
    place in the order of the code before B18, so the result is that code's in every case (the frozen copy
    scripts/tests/traffic_log_pred_b18.py, compared by scripts/tests/test_traffic_stream_b18.py). The bound of B18:
    the session audit of one eshop_high session below 1.5 GB.
    """
    if schema is not None and schema not in SCHEMA_PAIRS:
        raise ValueError("unknown traffic log schema: " + str(schema))
    problems = Problems()
    if schema is None:
        found = first_schema(requests_path)
        schema = found if found in SCHEMA_PAIRS else REQUEST_SCHEMA
    v5 = schema == REQUEST_SCHEMA_2
    pair = LogPair(requests_path, intervals_path, schema, SCHEMA_PAIRS[schema])
    intervals = pair.intervals
    scan = _SummaryScan(intervals or [], v5)
    for record in pair.records():
        scan.feed(record)
    log = pair.requests
    for item in log.problems():
        problems.add("requests", item)
    for item in pair.interval_problems:
        problems.add("intervals", item)

    def kind(records, name):
        return [record for record in records if record.get("type") == name]

    def edge(records, index, name):
        return records[index] if records and records[index].get("type") == name else None

    header_r = log.header if log.records and log.header.get("type") == "header" else None
    end_r = log.last if log.records and log.last.get("type") == "end" else None
    header_i, end_i = edge(intervals, 0, "header"), edge(intervals, -1, "end")
    ivs, marks_r, marks_i = scan.ivs, scan.marks, kind(intervals, "phase")

    # host_traffic.py writes every field read below into both end records; a missing one is a problem.
    for name, end, count in (("requests", end_r, log.records), ("intervals", end_i, len(intervals))):
        if end is None:
            problems.add(f"{name}:end_missing")
            continue
        if not end.get("clean") or end.get("write_errors") != 0:
            problems.add(f"{name}:end_not_clean")
        if end.get("records") != count:
            problems.add(f"{name}:records_mismatch", f"{end.get('records')}!={count}")
        if end.get("requests_logged") != scan.requests:
            problems.add(f"{name}:requests_logged_mismatch", f"{end.get('requests_logged')}!={scan.requests}")
        if end.get("requests_started") != scan.requests:
            problems.add(f"{name}:requests_started_mismatch", f"{end.get('requests_started')}!={scan.requests}")
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
    for rid in scan.duplicates():
        problems.add("duplicate_rid", rid)
    scan.loop(problems)

    # Interval records: contiguous coverage, counts equal to the request records they claim.
    seen, previous = set(), None
    for position, iv in enumerate(ivs):
        index = iv.get("interval")
        if index != position:
            problems.add("interval_index", f"{position}!={index}")
        if index in seen:
            problems.add("interval_duplicate", index)
        seen.add(index)
        members = scan.members.get(index, _NO_MEMBERS)
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
            outcomes = members.outcome_counts()
            if iv.get("requests") != members.count:
                problems.add("interval_count_mismatch", f"{index}:requests:{iv.get('requests')}!={members.count}")
            for outcome in OUTCOMES:
                if iv.get(outcome) != outcomes[outcome]:
                    problems.add("interval_count_mismatch", f"{index}:{outcome}:{iv.get(outcome)}!={outcomes[outcome]}")
            buckets, buckets_ok = members.bucket_counts()
            if {k: v for k, v in iv["hist"].items() if v} != dict(buckets) or \
                    {k: v for k, v in iv["hist_ok"].items() if v} != dict(buckets_ok):
                problems.add("interval_hist_mismatch", index)
            codes = members.code_counts()
            if {k: v for k, v in iv["status_codes"].items() if v} != dict(codes):
                problems.add("interval_status_mismatch", index)
            scan.checks_at[position].replay(problems)  # interval_phase_mismatch, request_outside_interval
        except (KeyError, TypeError):
            problems.add("interval_malformed", index)
        previous = iv
    for index in scan.members:
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
        count, outcome_counts = scan.phases[phase]
        phase_ivs = [iv for iv in ivs if iv.get("phase") == phase]
        from_intervals = sum(iv.get("requests") or 0 for iv in phase_ivs)
        if from_intervals != count:
            problems.add("phase_count_mismatch", f"{phase}:{from_intervals}!={count}")
        if count or phase_ivs:
            phases[phase] = {"requests": count, "intervals": len(phase_ivs),
                             "duration_s": round(sum(iv.get("duration_s") or 0 for iv in phase_ivs), 6),
                             **{o: outcome_counts[o] for o in OUTCOMES}}

    # Measured phase: exact percentiles, rate, and the longest pause between successes.
    measure = scan.measure
    if not measure.count:
        problems.add("no_measure_requests")
    elif not measure.ok:
        problems.add("no_ok_requests_in_measure")
    measure_ivs = [iv for iv in ivs if iv.get("phase") == "measure"]
    summary = {"requests": measure.count, "ok": measure.ok, "errors": measure.count - measure.ok,
               **{o: measure.outcomes[o] for o in OUTCOMES},
               "intervals": len(measure_ivs),
               "phase_duration_s": round(sum(iv.get("duration_s") or 0 for iv in measure_ivs), 6),
               "phase_mono_start": min((iv["mono_start"] for iv in measure_ivs), default=None),
               "phase_mono_end": max((iv["mono_end"] for iv in measure_ivs), default=None),
               "latency_ms": _latency(measure.latencies()),
               "latency_ok_ms": _latency(measure.latencies(ok=True)),
               "hist_p95_ms": hist_percentile(merge_hist(*(iv.get("hist", {}) for iv in measure_ivs)), .95),
               "hist_ok_p95_ms": hist_percentile(merge_hist(*(iv.get("hist_ok", {}) for iv in measure_ivs)), .95),
               "routes": measure.routes.result()}
    if measure.count:
        first_start, last_start, first_end, last_end = (extreme.result() for extreme in measure.extremes)
        duration = last_end["t_end_mono"] - first_start["t_start_mono"]
        completions = measure.completions()
        summary.update(first_start_utc=first_start["t_start_utc"], last_start_utc=last_start["t_start_utc"],
                       first_end_utc=first_end["t_end_utc"], last_end_utc=last_end["t_end_utc"],
                       first_start_mono=first_start["t_start_mono"], last_end_mono=last_end["t_end_mono"],
                       duration_s=round(duration, 6),
                       request_rate_rps=round(measure.count / duration, 3) if duration > 0 else None,
                       ok_rate_rps=round(measure.ok / duration, 3) if duration > 0 else None,
                       phase_request_rate_rps=(round(measure.count / summary["phase_duration_s"], 3)
                                               if summary["phase_duration_s"] > 0 else None),
                       max_ok_completion_gap_s=round(max((b - a for a, b in zip(completions, completions[1:])),
                                                         default=0), 6) if completions else None)

    if v5 and scan.v5_scan is None:  # A request log without records.
        scan.v5_scan = _V5Scan(header_r, header_i)
    arrivals = (scan.v5_scan.problems(problems, ivs, end_r, lambda: (r for _, r in JsonlStream(requests_path)))
                if v5 else None)
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
        found = _finite(origin) and (scan.wall_clock() or wall_clock(origin, "intervals", intervals))
        if found:
            problems.add("wall_clock", found)
    clean = all(end is not None and end.get("clean") and not end.get("write_errors") for end in (end_r, end_i))
    return {"schema": SUMMARY_SCHEMA, "log_schema": schema, "requests_path": str(requests_path),
            "intervals_path": str(intervals_path),
            "session_id": (header_r or {}).get("session_id"), "run_id": (header_r or {}).get("run_id"),
            "header_present": {"requests": header_r is not None, "intervals": header_i is not None},
            "end_present": {"requests": end_r is not None, "intervals": end_i is not None},
            "clean": clean, "problems": problems.result(),
            "records": {"requests": log.records, "intervals": len(intervals), "request_records": scan.requests,
                        "interval_records": len(ivs), "phase_markers": len(marks_r),
                        **({"arrival_records": arrivals["offered"]} if v5 else {})},
            **({"arrivals": arrivals} if v5 else {}),
            "phases": phases, "phase_markers": [{"phase": m.get("phase"), "previous": m.get("previous"),
                                                  "t_utc": m.get("t_utc"), "t_mono": m.get("t_mono"),
                                                  "interval": m.get("interval")} for m in marks_r],
            "routes": scan.routes.result(), "measure": summary,
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

    Package B18 (Q87: the executor's decision, for the lead's review): the request log is read as a stream in one pass
    (JsonlStream through LogPair; the interval log, one record per summary interval, whole). Held while it streams by
    (_RealismScan): one small record per arrival of the measure phase; under eshop per request the number of its user
    session, its start and end as compact arrays (8 bytes each) and whether it lies in the measure phase, and per user
    session its orders; the Counter of the objects; counts and the smallest and largest sizes of the answers outside
    every window, and under corp the sizes of the document downloads; never the records. The think times are formed
    after the pass, user session by user session, in the order and with the arithmetic of the code before B18, and
    every step raises its exception at its place in that code's order, so the result is that code's in every case
    (scripts/tests/traffic_log_pred_b18.py holds it, scripts/tests/test_traffic_stream_b18.py compares). The bound of
    B18: the session audit of one eshop_high session, which calls this, below 1.5 GB.
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
    pair = LogPair(requests_path, intervals_path)
    scan = _RealismScan(profile, windows)
    for record in pair.records():
        scan.feed(record)
    log, intervals = pair.requests, pair.intervals
    if (not log.records or log.header.get("schema") != REQUEST_SCHEMA_2 or not intervals
            or intervals[0].get("schema") != INTERVAL_SCHEMA_2):
        raise ValueError(f"the realism requirements need the logs of a v5 profile ({REQUEST_SCHEMA_2}, "
                         f"{INTERVAL_SCHEMA_2})")
    header = log.header
    envelope = Envelope(header.get("envelope"))
    origin = header["start_unix"]
    if not _finite(origin):
        raise ValueError("invalid start_unix")

    def overlaps(start, end):
        return any(lo <= end and start <= hi for lo, hi in windows)

    arrivals = sorted(scan.measure_arrivals(), key=lambda a: a["t_mono"])
    scan.measure_requests()  # The requests of the measure phase and those outside every window.
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
        thinks = scan.thinks()  # The realized think times (finding F6 of B5b): from the end of the request before.
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
        scan.count_orders(sessions)  # The orders of each user session: its POST /api/orders without intended status.
        outside_windows = [s for s in sessions.values()
                           if not any(lo - d_max <= s["start"] <= hi for lo, hi in windows)]
        # Package B14 (Q77: the executor's decision, approved by the lead on 2026-11-26): the same rule at the
        # generator's stop. scripts/collection.py sends SIGUSR2 and at once stops the generator (stop_child) after the
        # measure phase, so a buyer that starts in its last minutes is cut before the order. The stop is the request
        # log's end record: its end_mono against each arrival's t_mono, both in the generator's monotonic time, so
        # start_unix does not place it (package B15, should_fix 1 of the fourth G0 verification; summarize refuses a
        # pair whose two copies of end_mono differ). Without it there is no share to judge.
        end = log.last if log.last.get("type") == "end" else None
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

    counts = scan.object_counts()  # (kind, object) of each request of the measure phase that names one
    total = sum(counts.values())
    top = max(1, math.ceil(round(limit["top_objects_share"] * len(counts), 9))) if counts else 0
    concentration = sum(sorted(counts.values(), reverse=True)[:top]) / total if total else None
    out.append(_requirement("object_concentration", _round(concentration), limit["top_objects_min_requests"],
                            concentration is not None and concentration >= limit["top_objects_min_requests"],
                            f"the {top} most requested of {len(counts)} objects got this share of {total} requests "
                            f"(top {limit['top_objects_share']:g} of the objects)"))

    outside, ok = scan.success()  # The requests of the measure phase outside every window, and the 2xx ones.
    success = ok / outside if outside else None
    out.append(_requirement("success_rate", _round(success), {"min": limit["success_min"], "below": 1},
                            success is not None and limit["success_min"] <= success < 1,
                            f"{outside} requests of the measure phase outside every window"))

    sizes, positive, smallest, largest = scan.response_sizes()  # Of the 2xx answers outside every window.
    orders = math.log10(largest / smallest) if positive >= 2 else None
    out.append(_requirement("response_sizes", _round(orders), limit["response_size_orders"],
                            orders is not None and orders >= limit["response_size_orders"],
                            f"{positive} 2xx answers outside every window ({sizes - positive} empty "
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
        logins, reports = scan.posted("/api/auth/login"), scan.posted("/api/reports")
        downloads = sorted(scan.document_downloads())
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


class _RealismScan:
    """Package B18: what realism reads of the request log, from its records as they stream by. Held: one small record
    per arrival of the measure phase (its user session, t_mono, admitted and t_utc, the keys it has); under eshop per
    request the number of its user session (in the order of their first requests), its t_start_mono and t_end_mono
    (Values) and whether it is of the measure phase, and per user session the orders it placed; a Counter of the
    objects requested in the measure phase; of the requests outside every window their count, the 2xx ones, the count,
    smallest and largest of their response sizes, and under corp the 2xx logins and reports and the sizes of the
    document downloads; and the first exception of each of realism's steps, which it raises at that step's place."""

    def __init__(self, profile, windows):
        self.eshop, self.corp, self.windows = profile == "eshop", profile == "corp", windows
        self.arrivals, self.arrival_error = [], None
        self.phase_error = self.outside_error = None
        self.user_ids, self.user_of, self.measure = {}, array("l"), bytearray()
        self.starts, self.ends = Values(), Values()
        self.user_error, self.orders, self.order_errors, self.position = None, array("l"), {}, 0
        self.objects, self.object_error = Counter(), None
        self.outside, self.outside_ok, self.outcome_error = 0, 0, None
        self.sizes, self.size_error, self.sizes_invalid, self.positive = 0, None, False, 0
        self.smallest = self.largest = None
        self.logins, self.reports, self.downloads = [0, None], [0, None], [[], None]

    def feed(self, r):
        kind = r.get("type")
        if kind == "arrival" and self.arrival_error is None:
            try:  # sorted(r for r in records if r.get("type") == "arrival" and r["phase"] == "measure")
                if r["phase"] == "measure":
                    self.arrivals.append({key: r[key] for key in ("user_session", "t_mono", "admitted", "t_utc")
                                          if key in r})
            except Exception as error:  # noqa: BLE001 - raised at its place, as every one of this class
                self.arrival_error = error
        elif kind == "request":
            self.position += 1
            if self.eshop:
                self._user(r)
            if self.phase_error is None:
                try:  # requests = [r for r in every if r["phase"] == "measure"]
                    measure = r["phase"] == "measure"
                except Exception as error:  # noqa: BLE001
                    self.phase_error = error
                    return
                if measure:
                    self._measured(r)

    def _user(self, r):
        """by_session of think_time (every request in the order of the log) and the orders of order_share."""
        if self.user_error is not None:
            return
        try:
            uid = r["user_session"]
            user = self.user_ids.get(uid)
            if user is None:
                user = self.user_ids[uid] = len(self.user_ids)
                self.orders.append(0)
        except Exception as error:  # noqa: BLE001
            self.user_error = error
            return
        self.user_of.append(user)
        self.starts.append(r.get("t_start_mono", MISSING))
        self.ends.append(r.get("t_end_mono", MISSING))
        self.measure.append(r.get("phase") == "measure")
        try:
            self.orders[user] += r["method"] == "POST" and r["route"] == "/api/orders" and r["intended_status"] is None
        except Exception as error:  # noqa: BLE001 - raised where the user session is one of the share (count_orders)
            self.order_errors.setdefault(user, (self.position, error))

    def _measured(self, r):
        if self.object_error is None:
            try:
                if r["object"] is not None:
                    self.objects[(object_kind(r["route"]), json.dumps(r["object"]))] += 1
            except Exception as error:  # noqa: BLE001
                self.object_error = error
        if self.outside_error is not None:
            return
        try:  # outside = [r for r in requests if not inside(_unix(r["t_start_utc"]), _unix(r["t_end_utc"]))]
            times = (_unix(r["t_start_utc"]), _unix(r["t_end_utc"]))
            outside = not any(lo <= t <= hi for t in times for lo, hi in self.windows)
        except Exception as error:  # noqa: BLE001
            self.outside_error = error
            return
        if outside:
            self._outside(r)

    def _outside(self, r):
        self.outside += 1
        if self.outcome_error is not None:
            return
        try:
            ok = r["outcome"] == "ok"
        except Exception as error:  # noqa: BLE001
            self.outcome_error = error
            return
        self.outside_ok += ok
        if ok and self.size_error is None:
            try:
                size = r["response_bytes"]
            except Exception as error:  # noqa: BLE001
                self.size_error = error
            else:
                self.sizes += 1
                if type(size) is not int or size < 0:
                    self.sizes_invalid = True
                elif size > 0:
                    self.positive += 1
                    self.smallest = size if self.smallest is None else min(self.smallest, size)
                    self.largest = size if self.largest is None else max(self.largest, size)
        if self.corp:
            for count, route in ((self.logins, "/api/auth/login"), (self.reports, "/api/reports")):
                if count[1] is None:
                    try:
                        count[0] += r["method"] == "POST" and r["route"] == route and r["outcome"] == "ok"
                    except Exception as error:  # noqa: BLE001
                        count[1] = error
            if self.downloads[1] is None:
                try:
                    if (r["method"] == "GET" and r["outcome"] == "ok" and r["route"].startswith("/api/docs/")
                            and r["response_bytes"] > 0):
                        self.downloads[0].append(r["response_bytes"])
                except Exception as error:  # noqa: BLE001
                    self.downloads[1] = error

    def measure_arrivals(self):
        if self.arrival_error is not None:
            raise self.arrival_error
        return self.arrivals

    def measure_requests(self):
        for error in (self.phase_error, self.outside_error):
            if error is not None:
                raise error

    def thinks(self):
        """The realized think times of think_time in its order: the user sessions in the order of their first requests,
        the requests of each sorted by t_start_mono (stable), the start of each of the measure phase but the first minus
        the end of the one before it, to 6 decimals; what that computation raises, at its place."""
        if self.user_error is not None:
            raise self.user_error
        users = len(self.user_ids)
        bounds = [0] * (users + 1)  # The requests of user session u lie at bounds[u]:bounds[u + 1] of order.
        for user in self.user_of:
            bounds[user + 1] += 1
        for user in range(users):
            bounds[user + 1] += bounds[user]
        order, fill = array("l", [0]) * len(self.user_of), bounds[:-1]
        for position, user in enumerate(self.user_of):
            order[fill[user]] = position
            fill[user] += 1
        starts, ends, measure, thinks = self.starts, self.ends, self.measure, []

        def start(i):
            value = starts[i]
            if value is MISSING:
                raise KeyError("t_start_mono")
            return value
        for user in range(users):
            rows = order[bounds[user]:bounds[user + 1]].tolist()
            rows.sort(key=start)
            for before, i in zip(rows, rows[1:]):
                if measure[i]:
                    if ends[before] is MISSING:
                        raise KeyError("t_end_mono")
                    thinks.append(round(starts[i] - ends[before], 6))
        return thinks

    def count_orders(self, sessions):
        """The loop of order_share over every request: the orders of each user session of `sessions` added there; the
        exception of the first request of one of them that raises it, raised."""
        names = list(self.user_ids)
        failing = [found for user, found in self.order_errors.items() if names[user] in sessions]
        if failing:
            raise min(failing, key=lambda found: found[0])[1]
        for uid, s in sessions.items():
            user = self.user_ids.get(uid)
            if user is not None:
                s["orders"] += self.orders[user]

    def object_counts(self):
        if self.object_error is not None:
            raise self.object_error
        return self.objects

    def success(self):
        if self.outcome_error is not None:
            raise self.outcome_error
        return self.outside, self.outside_ok

    def response_sizes(self):
        """(the 2xx answers outside every window, those of a positive size, the smallest and the largest of these)."""
        if self.size_error is not None:
            raise self.size_error
        if self.sizes_invalid:
            raise ValueError("response_bytes is not a byte count")
        return self.sizes, self.positive, self.smallest, self.largest

    def posted(self, route):
        count, error = self.logins if route == "/api/auth/login" else self.reports
        if error is not None:
            raise error
        return count

    def document_downloads(self):
        sizes, error = self.downloads
        if error is not None:
            raise error
        return sizes


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
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path:  # features/audit_policy.py and lab/seed.py when run as a script
        sys.path.insert(0, root)
    if args.command == "realism":
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
