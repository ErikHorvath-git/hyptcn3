from collections import Counter
import json
import math
import random
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import traffic_log as tl

REPO = Path(__file__).resolve().parents[2]
RUN = "0123456789ab"
UTC = "2026-01-01T00:00:00.000000+00:00"


def brute_force_percentile(values, q):
    """Nearest rank by definition: the smallest value with at least ceil(q * n) values <= it."""
    need = max(1, math.ceil(q * len(values)))
    for candidate in sorted(values):
        if sum(1 for value in values if value <= candidate) >= need:
            return candidate


def test_bucket_edges_are_log_spaced_and_cover_60s():
    edges = tl.bucket_edges()
    assert edges == tl.EDGES and edges[0] == .05 and edges[-2] < 60000 <= edges[-1]
    assert all(abs(b / a - 1.05) < 1e-9 for a, b in zip(edges, edges[1:]))
    assert tl.bucket_index(0) == 0 and tl.bucket_index(.05) == 0 and tl.bucket_index(.0500001) == 1
    assert tl.bucket_index(edges[10]) == 10 and tl.bucket_index(edges[10] * 1.001) == 11
    assert tl.bucket_index(1e9) == tl.OVERFLOW == len(edges)
    assert tl.hist_percentile({str(tl.OVERFLOW): 1}, .5) is None and tl.hist_percentile({}, .5) is None
    assert "5 %" in tl.HIST_PRECISION


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_percentile_is_exact_nearest_rank(seed):
    rng = random.Random(seed)
    for n in (1, 2, 3, 7, 100, 1001):
        values = [round(rng.lognormvariate(1, 1.2), 3) for _ in range(n)]
        for q in (.5, .9, .95, .99, 1):
            assert tl.percentile(sorted(values), q) == brute_force_percentile(values, q)
    assert tl.percentile([], .5) is None
    assert tl.percentile([5.0], .99) == 5.0


def test_hist_percentile_overestimates_by_at_most_5_percent_and_merges():
    rng = random.Random(5)
    values = [rng.lognormvariate(2, 1.5) for _ in range(5000)]
    hist = Counter(str(tl.bucket_index(v)) for v in values)
    first, second = values[:2000], values[2000:]
    merged = tl.merge_hist(Counter(str(tl.bucket_index(v)) for v in first), Counter(tl.bucket_index(v) for v in second))
    assert merged == dict(hist)
    for q in (.5, .9, .95, .99, 1):
        exact, approx = tl.percentile(sorted(values), q), tl.hist_percentile(hist, q)
        assert exact <= approx <= exact * 1.05 + 1e-9


# --- synthetic log pair with the generator's record layout -------------------------------------

def header(schema, session_id="S", initial="warmup"):
    rec = {"type": "header", "session_id": session_id, "run_id": RUN, "generator": "test",
           "config": {"initial_phase": initial, "summary_interval_s": 1.0, "workers": 1}}
    if schema == tl.INTERVAL_SCHEMA:
        rec.update(hist_edges_ms=tl.EDGES, hist_precision=tl.HIST_PRECISION)
    return rec


def request(seq, interval, phase, start, ms, outcome="ok", status=200, method="GET", route="/api/catalog"):
    return {"type": "request", "session_id": "S", "run_id": RUN, "rid": f"{RUN}-00-{seq:08d}", "worker": 0,
            "worker_seq": seq, "interval": interval, "phase": phase, "method": method, "route": route,
            "status": status, "outcome": outcome, "error": None if outcome == "ok" else "HTTPError: HTTP Error 503",
            "t_start_utc": UTC, "t_end_utc": UTC, "t_start_mono": start, "t_end_mono": round(start + ms / 1000, 6),
            "duration_ms": ms, "response_bytes": 10}


def interval(index, phase, start, end, members):
    ok = [r for r in members if r["outcome"] == "ok"]
    key = lambda r: f"{r['method']} {r['route']}"  # noqa: E731
    return {"type": "interval", "interval": index, "phase": phase, "t_start_utc": UTC, "t_end_utc": UTC,
            "mono_start": start, "mono_end": end, "duration_s": round(end - start, 6), "requests": len(members),
            "ok": len(ok), **{o: sum(1 for r in members if r["outcome"] == o) for o in tl.OUTCOMES if o != "ok"},
            "status_codes": dict(Counter("none" if r["status"] is None else str(r["status"]) for r in members)),
            "routes": dict(Counter(key(r) for r in members)),
            "route_errors": dict(Counter(key(r) for r in members if r["outcome"] != "ok")),
            "throughput_rps": len(members) / (end - start), "ok_rps": len(ok) / (end - start),
            "sum_ms": sum(r["duration_ms"] for r in members),
            "min_ms": min((r["duration_ms"] for r in members), default=None),
            "max_ms": max((r["duration_ms"] for r in members), default=None),
            "hist": dict(Counter(str(tl.bucket_index(r["duration_ms"])) for r in members)),
            "hist_ok": dict(Counter(str(tl.bucket_index(r["duration_ms"])) for r in ok))}


def marker(phase, previous, t_mono, index):
    return {"type": "phase", "phase": phase, "previous": previous, "t_utc": UTC, "t_mono": t_mono, "interval": index}


def end(requests, records, phase="post", end_mono=3.5):
    return {"type": "end", "requests_started": len(requests), "requests_completed": len(requests),
            **{o: sum(1 for r in requests if r["outcome"] == o) for o in tl.OUTCOMES}, "in_flight_at_stop": 0,
            "worker_errors": 0, "log_backpressure_s": 0, "phase": phase, "end_utc": UTC, "end_mono": end_mono,
            "records": records + 1, "requests_logged": len(requests), "write_errors": 0, "clean": True}


def build():
    """warmup [0,1) -> measure [1,2),[2,3) -> post [3,3.5); returns (request records, interval records)."""
    r0 = [request(0, 0, "warmup", .1, 3.0), request(1, 0, "warmup", .5, 2.0)]
    r1 = [request(2, 1, "measure", 1.1, 2.5), request(3, 1, "measure", 1.3, 9.0),
          request(4, 1, "measure", 1.7, 2.2, method="POST", route="/api/orders", status=201)]
    r2 = [request(5, 2, "measure", 2.2, 4.0, outcome="http_error", status=503), request(6, 2, "measure", 2.4, 2.8)]
    r3 = [request(7, 3, "post", 3.1, 2.1)]
    requests = r0 + r1 + r2 + r3
    marks = [marker("measure", "warmup", 1.0, 1), marker("post", "measure", 3.0, 3)]
    req_log = [header(tl.REQUEST_SCHEMA), *r0, marks[0], *r1, *r2, marks[1], *r3]
    ivl_log = [header(tl.INTERVAL_SCHEMA), interval(0, "warmup", 0.0, 1.0, r0), marks[0],
               interval(1, "measure", 1.0, 2.0, r1), interval(2, "measure", 2.0, 3.0, r2), marks[1],
               interval(3, "post", 3.0, 3.5, r3)]
    req_log.append(end(requests, len(req_log)))
    ivl_log.append(end(requests, len(ivl_log)))
    return req_log, ivl_log


def write(path, schema, records):
    path.write_text("".join(json.dumps({"schema": schema, "n": n, **r}) + "\n" for n, r in enumerate(records)))
    return path


def write_pair(tmp_path, req_log, ivl_log):
    return (write(tmp_path / "requests.jsonl", tl.REQUEST_SCHEMA, req_log),
            write(tmp_path / "intervals.jsonl", tl.INTERVAL_SCHEMA, ivl_log))


def test_summarize_consistent_logs_has_no_problems(tmp_path):
    req, ivl = write_pair(tmp_path, *build())
    summary = tl.summarize(req, ivl, session_id="S")
    assert summary["problems"] == [] and summary["clean"]
    assert summary["session_id"] == "S" and summary["run_id"] == RUN
    assert summary["header_present"] == summary["end_present"] == {"requests": True, "intervals": True}
    assert summary["records"] == {"requests": 12, "intervals": 8, "request_records": 8, "interval_records": 4,
                                  "phase_markers": 2}
    assert {p: v["requests"] for p, v in summary["phases"].items()} == {"warmup": 2, "measure": 5, "post": 1}
    assert summary["phases"]["measure"] == {"requests": 5, "intervals": 2, "duration_s": 2.0, "ok": 4,
                                            "http_error": 1, "timeout": 0, "transport_error": 0}
    measure = summary["measure"]
    durations = [2.5, 9.0, 2.2, 4.0, 2.8]
    assert measure["latency_ms"] == {"n": 5, "p50": 2.8, "p90": 9.0, "p95": 9.0, "p99": 9.0, "max": 9.0}
    assert measure["latency_ms"]["p95"] == brute_force_percentile(durations, .95)
    assert measure["latency_ok_ms"] == {"n": 4, "p50": 2.5, "p90": 9.0, "p95": 9.0, "p99": 9.0, "max": 9.0}
    assert 9.0 <= measure["hist_p95_ms"] <= 9.0 * 1.05
    assert measure["first_start_mono"] == 1.1 and measure["last_end_mono"] == 2.4028
    assert measure["duration_s"] == round(2.4028 - 1.1, 6) and measure["phase_duration_s"] == 2.0
    assert measure["request_rate_rps"] == round(5 / (2.4028 - 1.1), 3) and measure["phase_request_rate_rps"] == 2.5
    assert measure["max_ok_completion_gap_s"] == round(2.4028 - 1.7022, 6)  # 1.1025, 1.309, 1.7022, 2.4028
    assert measure["routes"]["POST /api/orders"] == {"requests": 1, "ok": 1, "errors": 0, "status_codes": {"201": 1}}
    assert summary["routes"]["GET /api/catalog"]["errors"] == 1 and summary["routes"]["GET /api/catalog"]["requests"] == 7
    assert summary["intervals"] == {"count": 4, "zero_request_intervals": 0, "mono_start": 0.0, "mono_end": 3.5,
                                    "coverage_s": 3.5}
    assert [m["phase"] for m in summary["phase_markers"]] == ["measure", "post"]
    assert summary["end"]["requests"]["requests_logged"] == 8


def test_torn_last_line_is_detected(tmp_path):
    req, ivl = write_pair(tmp_path, *build())
    data = req.read_bytes()
    req.write_bytes(data[:-10])  # the end record is cut mid-line
    records, problems = tl.read_jsonl(req)
    assert problems == ["torn_last_line"] and records[-1]["type"] == "request"
    summary = tl.summarize(req, ivl)
    assert not summary["clean"] and not summary["end_present"]["requests"]
    assert {"requests:torn_last_line", "requests:end_missing"} <= set(summary["problems"])
    req.write_bytes(data[:-1])  # complete JSON but no terminating newline
    assert tl.read_jsonl(req)[1] == ["torn_last_line"]
    req.write_bytes(data[:-len(data.splitlines()[-1]) - 1] + b'{"broken": \n')  # invalid but terminated
    assert tl.read_jsonl(req)[1] == ["torn_last_line"]


def test_missing_end_record_is_detected(tmp_path):
    req_log, ivl_log = build()
    req, ivl = write_pair(tmp_path, req_log[:-1], ivl_log)
    assert tl.read_jsonl(req)[1] == []
    summary = tl.summarize(req, ivl)
    assert not summary["clean"] and summary["problems"] == ["requests:end_missing"]
    req, ivl = write_pair(tmp_path, req_log[:-1], ivl_log[:-1])
    assert tl.summarize(req, ivl)["problems"] == ["requests:end_missing", "intervals:end_missing"]


def test_corrupt_line_schema_and_record_numbering_are_detected(tmp_path):
    req, ivl = write_pair(tmp_path, *build())
    lines = req.read_text().splitlines(keepends=True)
    lines[2] = "not json\n"
    req.write_text("".join(lines))
    records, problems = tl.read_jsonl(req, tl.REQUEST_SCHEMA)
    assert problems == ["corrupt_line:3", "n_discontinuous:4"] and len(records) == 11
    lines = ivl.read_text().splitlines(keepends=True)
    lines[0] = lines[0].replace(tl.INTERVAL_SCHEMA, "hyptcn3/other/9")
    ivl.write_text("".join(lines))
    _, problems = tl.read_jsonl(ivl, tl.INTERVAL_SCHEMA)
    assert problems == ["schema_mismatch:hyptcn3/other/9"] + [f"schema_mismatch:{n}" for n in range(2, 9)]
    (tmp_path / "empty").write_bytes(b"")
    assert tl.read_jsonl(tmp_path / "empty", tl.REQUEST_SCHEMA) == ([], ["empty_file"])
    (tmp_path / "noheader.jsonl").write_text('{"schema": "x", "n": 0, "type": "request"}\n')
    assert "missing_header" in tl.read_jsonl(tmp_path / "noheader.jsonl")[1]
    bumped = [dict(r) for r in build()[0]]
    text = "".join(json.dumps({"schema": tl.REQUEST_SCHEMA, "n": n + (n >= 5), **r}) + "\n" for n, r in enumerate(bumped))
    (tmp_path / "gap.jsonl").write_text(text)
    assert tl.read_jsonl(tmp_path / "gap.jsonl")[1] == ["n_discontinuous:6"]


def mutate(name, req_log, ivl_log):
    """Return (req_log, ivl_log, session_id) with one inconsistency injected."""
    session = "S"
    if name == "interval_count":
        ivl_log[3]["requests"] += 1
    elif name == "interval_outcome":
        ivl_log[3]["ok"] -= 1
        ivl_log[3]["timeout"] += 1
    elif name == "duplicate_rid":
        req_log[2]["rid"] = req_log[1]["rid"]
    elif name == "interval_gap":
        ivl_log[4]["mono_start"] = 2.000001
    elif name == "interval_duration":
        ivl_log[4]["duration_s"] = .5
    elif name == "request_phase":
        req_log[4]["phase"] = "warmup"
    elif name == "requests_logged":
        req_log[-1]["requests_logged"] = 7
    elif name == "records":
        ivl_log[-1]["records"] = 99
    elif name == "not_clean":
        ivl_log[-1]["clean"] = False
    elif name == "write_errors":
        req_log[-1]["write_errors"] = 1
    elif name == "in_flight":
        req_log[-1]["in_flight_at_stop"] = 1
    elif name == "session_id":
        session = "other"
    elif name == "run_id":
        ivl_log[0]["run_id"] = "ffffffffffff"
    elif name == "outside_interval":
        req_log[4]["t_start_mono"] = 2.5
    elif name == "phase_order":  # markers (shared dicts) swapped: warmup -> post -> measure
        req_log[3]["phase"] = ivl_log[2]["phase"] = "post"
        req_log[9]["phase"] = ivl_log[5]["phase"] = "measure"
    elif name == "marker_mismatch":
        del ivl_log[2]
        ivl_log[-1]["records"] -= 1
    elif name == "hist":
        ivl_log[3]["hist"] = {"0": 1}
    elif name == "status_codes":
        ivl_log[3]["status_codes"] = {"200": 3}
    elif name == "duration":
        req_log[2]["duration_ms"] = 99.0
    elif name == "interval_missing":
        del ivl_log[4]
        ivl_log[-1]["records"] -= 1
    elif name == "initial_phase":
        req_log[0]["config"]["initial_phase"] = "measure"
    elif name == "not_to_end":
        ivl_log[-1]["end_mono"] = 3.6
    elif name == "no_measure":
        for r in req_log:
            if r.get("phase") == "measure":
                r["phase"] = "warmup"
        for r in ivl_log:
            if r.get("phase") == "measure":
                r["phase"] = "warmup"
        req_log[3]["phase"] = ivl_log[2]["phase"] = "warmup"
    return req_log, ivl_log, session


EXPECTED = {
    "interval_count": ["interval_count_mismatch:1:requests:4!=3"],
    "interval_outcome": ["interval_count_mismatch:1:ok:2!=3", "interval_count_mismatch:1:timeout:1!=0"],
    "duplicate_rid": [f"duplicate_rid:{RUN}-00-00000000"],
    "interval_gap": ["interval_gap:1->2"],
    "interval_duration": ["interval_duration:2"],
    "request_phase": ["interval_phase_mismatch:1:", "phase_count_mismatch:warmup:2!=3", "phase_count_mismatch:measure:5!=4"],
    "requests_logged": ["requests:requests_logged_mismatch:7!=8"],
    "records": ["intervals:records_mismatch:99!=8"],
    "not_clean": ["intervals:end_not_clean"],
    "write_errors": ["requests:end_not_clean"],
    "in_flight": ["requests:in_flight_at_stop:1"],
    "session_id": ["session_id_mismatch:S"],
    "run_id": ["run_id_mismatch"],
    "outside_interval": [f"request_outside_interval:{RUN}-00-00000002"],
    "phase_order": ["phase_order:post->measure"],
    "marker_mismatch": ["phase_marker_mismatch"],
    "hist": ["interval_hist_mismatch:1"],
    "status_codes": ["interval_status_mismatch:1"],
    "duration": [f"duration_mismatch:{RUN}-00-00000001", "interval_hist_mismatch:0"],
    "interval_missing": ["interval_index:2!=3", "interval_gap:1->3", "interval_missing:2", "phase_count_mismatch:measure:3!=5"],
    "initial_phase": ["phase_order:measure->measure", "initial_phase_mismatch:warmup"],
    "not_to_end": ["intervals_not_to_end:3.5!=3.6"],
    "no_measure": ["no_measure_requests"],
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_summarize_flags_every_inconsistency(tmp_path, name):
    req_log, ivl_log, session = mutate(name, *build())
    req, ivl = write_pair(tmp_path, req_log, ivl_log)
    problems = tl.summarize(req, ivl, session_id=session)["problems"]
    for expected in EXPECTED[name]:
        assert any(problem.startswith(expected) for problem in problems), (expected, problems)
    if name in ("not_clean", "write_errors", "in_flight"):
        assert tl.summarize(req, ivl)["clean"] is (name == "in_flight")


def test_problem_details_are_capped_per_key(tmp_path):
    req_log, ivl_log = build()
    for r in req_log[1:-1]:
        if r["type"] == "request":
            r["duration_ms"] = 123.0
    req, ivl = write_pair(tmp_path, req_log, ivl_log)
    problems = tl.summarize(req, ivl)["problems"]
    assert sum(p.startswith("duration_mismatch:") for p in problems) == 8
    issues = tl.Problems()
    for i in range(25):
        issues.add("x", i)
    issues.add("y")
    assert issues.result() == [f"x:{i}" for i in range(10)] + ["y", "x:more:15"]


def test_cli_prints_json_and_uses_exit_codes(tmp_path):
    req_log, ivl_log = build()
    req, ivl = write_pair(tmp_path, req_log, ivl_log)
    command = [sys.executable, REPO / "scripts/traffic_log.py", "summarize", "--requests", req, "--intervals", ivl]
    result = subprocess.run([*command, "--session-id", "S"], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["problems"] == []
    result = subprocess.run([*command, "--session-id", "other"], capture_output=True, timeout=20)
    assert result.returncode == 2 and json.loads(result.stdout)["problems"] == ["session_id_mismatch:S"]
    write_pair(tmp_path, req_log[:-1], ivl_log)
    result = subprocess.run(command, capture_output=True, timeout=20)
    assert result.returncode == 2 and json.loads(result.stdout)["clean"] is False
