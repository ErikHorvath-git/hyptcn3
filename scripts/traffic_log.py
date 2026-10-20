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
"""
import argparse
import bisect
from collections import Counter, defaultdict
import json
import math
from pathlib import Path

REQUEST_SCHEMA = "hyptcn3/traffic-request/1"
INTERVAL_SCHEMA = "hyptcn3/traffic-interval/1"
SUMMARY_SCHEMA = "hyptcn3/traffic-summary/1"
PHASES = ("warmup", "measure", "post")
OUTCOMES = ("ok", "http_error", "timeout", "transport_error")
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


def summarize(requests_path, intervals_path, *, session_id=None):
    """Audit a request log + interval log pair and summarize the measured phase.

    Every inconsistency becomes a string in result["problems"]; result["clean"] is
    True only when both end records are present and clean. Measured-phase
    percentiles are exact over all request records of that phase.
    """
    problems = Problems()
    requests, bad = read_jsonl(requests_path, REQUEST_SCHEMA)
    for item in bad:
        problems.add("requests", item)
    intervals, bad = read_jsonl(intervals_path, INTERVAL_SCHEMA)
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

    for name, end, records in (("requests", end_r, requests), ("intervals", end_i, intervals)):
        if end is None:
            problems.add(f"{name}:end_missing")
            continue
        if not end.get("clean") or end.get("write_errors"):
            problems.add(f"{name}:end_not_clean")
        if end.get("records") != len(records):
            problems.add(f"{name}:records_mismatch", f"{end.get('records')}!={len(records)}")
        if end.get("requests_logged") != len(reqs):
            problems.add(f"{name}:requests_logged_mismatch", f"{end.get('requests_logged')}!={len(reqs)}")
        if end.get("requests_started") != len(reqs):
            problems.add(f"{name}:requests_started_mismatch", f"{end.get('requests_started')}!={len(reqs)}")
        if end.get("in_flight_at_stop"):
            problems.add(f"{name}:in_flight_at_stop", end["in_flight_at_stop"])
        if end.get("worker_errors"):
            problems.add(f"{name}:worker_errors", end["worker_errors"])
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
    if ivs and abs(ivs[0].get("mono_start", math.nan)) > 1e-9:
        problems.add("intervals_not_from_origin", ivs[0].get("mono_start"))
    if ivs and end_i and abs(ivs[-1].get("mono_end", math.nan) - end_i.get("end_mono", math.nan)) > 1e-9:
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

    clean = all(end is not None and end.get("clean") and not end.get("write_errors") for end in (end_r, end_i))
    return {"schema": SUMMARY_SCHEMA, "requests_path": str(requests_path), "intervals_path": str(intervals_path),
            "session_id": (header_r or {}).get("session_id"), "run_id": (header_r or {}).get("run_id"),
            "header_present": {"requests": header_r is not None, "intervals": header_i is not None},
            "end_present": {"requests": end_r is not None, "intervals": end_i is not None},
            "clean": clean, "problems": problems.result(),
            "records": {"requests": len(requests), "intervals": len(intervals), "request_records": len(reqs),
                        "interval_records": len(ivs), "phase_markers": len(marks_r)},
            "phases": phases, "phase_markers": [{"phase": m.get("phase"), "previous": m.get("previous"),
                                                  "t_utc": m.get("t_utc"), "t_mono": m.get("t_mono"),
                                                  "interval": m.get("interval")} for m in marks_r],
            "routes": _routes(reqs), "measure": summary,
            "intervals": {"count": len(ivs), "zero_request_intervals": sum(1 for iv in ivs if not iv.get("requests")),
                          "mono_start": ivs[0].get("mono_start") if ivs else None,
                          "mono_end": ivs[-1].get("mono_end") if ivs else None,
                          "coverage_s": round(sum(iv.get("duration_s") or 0 for iv in ivs), 6)},
            "end": {"requests": end_r, "intervals": end_i}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("summarize", help="audit a request/interval log pair and print JSON")
    audit.add_argument("--requests", required=True, type=Path)
    audit.add_argument("--intervals", required=True, type=Path)
    audit.add_argument("--session-id", help="expected session id (header must match)")
    args = parser.parse_args(argv)
    result = summarize(args.requests, args.intervals, session_id=args.session_id)
    print(json.dumps(result, indent=2))
    return 0 if not result["problems"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
