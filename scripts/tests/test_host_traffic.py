from collections import Counter, defaultdict
import http.client
import json
import math
import random
import re
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from types import SimpleNamespace
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts import host_traffic
from scripts.traffic_log import read_jsonl, summarize

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/host_traffic.py"
SECRET = "sekret-token-9f3c2a-must-not-be-logged"


class LabHandler(BaseHTTPRequestHandler):
    """Fake lab: token, catalog, bearer-protected orders, healthz; records every X-Request-ID."""
    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def handle_any(self):
        with self.server.lock:
            self.server.rids.append(self.headers.get("X-Request-ID"))
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.server.fail:
            return self.reply(503, {"error": "unavailable"})
        if self.path == "/api/auth/token":
            return self.reply(200, {"token": SECRET})
        if self.path.startswith("/api/orders"):
            if self.headers.get("Authorization") != f"Bearer {SECRET}":
                return self.reply(401, {"error": "unauthorized"})
            return self.reply(201 if self.command == "POST" else 200, {"orders": []})
        if self.path == "/api/catalog":
            return self.reply(200, {"items": [1, 2, 3]})
        return self.reply(200, {"ok": True})  # /healthz and legacy paths

    do_GET = do_POST = handle_any

    def log_message(self, *_):
        pass


@pytest.fixture
def server():
    http = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    http.fail, http.rids, http.lock = False, [], threading.Lock()
    thread = threading.Thread(target=http.serve_forever)
    thread.start()
    yield http, f"http://127.0.0.1:{http.server_port}"
    http.shutdown()
    http.server_close()
    thread.join()


def wait_until(condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        time.sleep(.02)
    assert condition()


def run_generator(*args, timeout=15):
    return subprocess.run([sys.executable, SCRIPT, *map(str, args)], timeout=timeout, capture_output=True)


def log_records(path, kind):
    records, problems = read_jsonl(path)
    assert problems == []
    return [r for r in records if r["type"] == kind]


@pytest.mark.parametrize("failure", [False, True])
def test_traffic_reports_http_failures_and_observed_time(server, tmp_path, failure):
    http, target = server
    http.fail = failure
    out = tmp_path / "metrics.json"
    result = run_generator("--target", target, "--dur", ".4", "--vlakien", "2", "--out", out, timeout=10)
    doc = json.loads(out.read_text())
    assert result.returncode == int(failure)
    assert doc["final"]
    assert doc["requests"] > 0
    assert doc["ok"] + doc["errors"] == doc["requests"]
    assert doc["elapsed_s"] >= .4
    assert doc["status_codes"]["503" if failure else "200"] == doc["requests"]
    assert doc["schema"] == "hyptcn3/host-traffic/3" and doc["requests_log"] is None and doc["requests_logged"] == 0


def test_continuous_traffic_flushes_on_sigterm(server, tmp_path):
    _, target = server
    out = tmp_path / "metrics.json"
    process = subprocess.Popen([sys.executable, SCRIPT, "--target", target, "--dur", "0", "--vlakien", "1",
                                "--out", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_until(out.exists, timeout=10)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=6) == 0
        assert json.loads(out.read_text())["final"]
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


# Verbatim copy of CESTY and worker() from scripts/host_traffic.py as of commit bdcd791, i.e. before
# per-request logging existed. `request` is the network function it called; here a recording stub.
CESTY = ["/auth", "/orders", "/", "/auth?u=%d", "/orders?page=%d"]
REFERENCE_WORKER = '''\
def worker(args, index, stop, metrics):
    rng = random.Random(args.seed + index * 1009)
    token, expires = "", 0
    while not stop.is_set():
        if args.profile == "lab" and time.monotonic() >= expires:
            login = request(args.target, "/api/auth/token", metrics, "POST", {"user": f"demo{index}"})
            if not login or "token" not in login:
                stop.wait(1)
                continue
            token, expires = login["token"], time.monotonic() + 3000
        burst = rng.random() < args.burst
        for _ in range(rng.randint(1, 4 if burst else 2)):
            if stop.is_set():
                break
            if args.profile == "legacy":
                path = rng.choice(CESTY)
                if "%d" in path:
                    path %= rng.randint(1, 999)
                request(args.target, path, metrics)
            else:
                choice = rng.random()
                catalog_share = getattr(args, "catalog_share", .5)
                write_share = getattr(args, "write_share", .2)
                if choice < catalog_share:
                    request(args.target, "/api/catalog", metrics)
                elif choice < .95 - write_share:
                    request(args.target, "/api/orders", metrics, token=token)
                elif choice < .95:
                    request(args.target, "/api/orders", metrics, "POST",
                            {"product_id": rng.randint(1, 5), "quantity": rng.randint(1, 3)}, token)
                else:
                    request(args.target, "/healthz", metrics)
        stop.wait(rng.uniform(.15, .6) if burst else rng.uniform(.5, 1.5))
'''


class FakeStop:
    """Deterministic stand-in for the stop Event: ends after `cycles` waits, records think times."""
    def __init__(self, cycles):
        self.cycles, self.waits = cycles, []

    def is_set(self):
        return self.cycles <= 0

    def wait(self, timeout):
        self.waits.append(timeout)
        self.cycles -= 1
        return self.is_set()


def reference_calls(args, index, stop):
    calls = []

    def request(target, path, metrics, method="GET", body=None, token=""):
        metrics.append((method, path, body, bool(token)))
        return {"token": "reference-token"}
    namespace = {"random": random, "time": time, "CESTY": CESTY, "request": request}
    exec(REFERENCE_WORKER, namespace)
    namespace["worker"](args, index, stop, calls)
    return calls


def new_calls(args, index, stop, monkeypatch):
    calls, headers = [], []

    class Response:
        status, headers = 200, {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _limit=-1):
            return b'{"token": "new-token"}'

    def urlopen(req, timeout=None):
        calls.append((req.get_method(), req.selector, json.loads(req.data) if req.data else None,
                      req.has_header("Authorization")))
        headers.append(dict(req.header_items()))
        return Response()
    monkeypatch.setattr(host_traffic.urllib.request, "urlopen", urlopen)
    recorder = host_traffic.Recorder(args, threading.Event())
    client = host_traffic.Client(args.target, index, host_traffic.Metrics(recorder.origin, "t0"), recorder)
    host_traffic.worker(args, index, stop, client)
    return calls, headers, recorder


@pytest.mark.parametrize("seed,index,profile,burst,catalog,write", [
    (1, 0, "lab", 1, .5, .2), (1, 3, "lab", 0, .5, .2), (42, 7, "lab", .5, .3, .4), (7, 2, "lab", .3, 0, .95),
    (1, 0, "legacy", 1, .5, .2), (99, 5, "legacy", .5, .5, .2)])
def test_worker_request_sequence_matches_original_load_model(monkeypatch, seed, index, profile, burst, catalog, write):
    args = SimpleNamespace(target="http://fake", seed=seed, profile=profile, burst=burst, catalog_share=catalog,
                           write_share=write, vlakien=8, dur=0, session_id="rng", requests_log=None,
                           intervals_log=None, summary_interval_s=5, initial_phase="measure", out=None)
    reference_stop, new_stop = FakeStop(40), FakeStop(40)
    reference = reference_calls(args, index, reference_stop)
    calls, headers, recorder = new_calls(args, index, new_stop, monkeypatch)
    assert len(reference) >= 40
    assert calls == reference
    assert new_stop.waits == reference_stop.waits
    # request ids are per worker and sequential; they must not touch the worker RNG (checked above)
    assert [h["X-request-id"] for h in headers] == [f"{recorder.run_id}-{index:02d}-{n:08d}" for n in range(len(calls))]
    assert re.fullmatch(r"[0-9a-f]{12}", recorder.run_id)


@pytest.mark.parametrize("exc,expected", [
    (TimeoutError("timed out"), "timeout"),
    (urllib.error.URLError(TimeoutError("timed out")), "timeout"),
    (urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")), "transport_error"),
    (ConnectionResetError(104, "Connection reset by peer"), "transport_error"),
    (http.client.RemoteDisconnected("Remote end closed connection without response"), "transport_error"),
    (ValueError("Expecting value: line 1 column 1 (char 0)"), "transport_error")])
def test_classify_outcomes(exc, expected):
    outcome, error = host_traffic.classify(exc)
    assert outcome == expected
    assert error.startswith(type(exc).__name__)


def test_lab_session_with_phase_signals_produces_complete_consistent_logs(server, tmp_path):
    http, target = server
    req, ivl, out = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl", tmp_path / "traffic.json"
    process = subprocess.Popen([sys.executable, SCRIPT, "--profile", "lab", "--target", target, "--dur", "0",
                                "--vlakien", "4", "--seed", "7", "--session-id", "S-test", "--initial-phase",
                                "warmup", "--summary-interval-s", "0.25", "--requests-log", req,
                                "--intervals-log", ivl, "--out", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_until(lambda: req.exists() and req.stat().st_size > 0)
        time.sleep(.7)
        process.send_signal(signal.SIGUSR1)
        time.sleep(1)
        process.send_signal(signal.SIGUSR2)
        time.sleep(.8)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=8) == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()

    summary = summarize(req, ivl, session_id="S-test")
    assert summary["problems"] == [] and summary["clean"]
    assert set(summary["phases"]) == {"warmup", "measure", "post"}
    assert all(phase["requests"] > 0 and phase["requests"] == phase["ok"] for phase in summary["phases"].values())
    assert [m["phase"] for m in summary["phase_markers"]] == ["measure", "post"]

    requests = log_records(req, "request")
    rids = [r["rid"] for r in requests]
    assert sorted(rids) == sorted(http.rids) and len(set(rids)) == len(rids)
    assert all(re.fullmatch(rf"{summary['run_id']}-\d{{2}}-\d{{8}}", rid) for rid in rids)
    per_worker = defaultdict(list)
    for r in sorted(requests, key=lambda r: r["worker_seq"]):
        per_worker[r["worker"]].append(r["worker_seq"])
    assert all(seqs == list(range(len(seqs))) for seqs in per_worker.values()) and len(per_worker) == 4
    text = req.read_text() + ivl.read_text()
    assert SECRET not in text and "Bearer" not in text and "Authorization" not in text
    assert {r["method"] + " " + r["route"] for r in requests} >= {"POST /api/auth/token", "GET /api/catalog",
                                                                   "GET /api/orders", "POST /api/orders"}
    assert all(r["schema"] == "hyptcn3/traffic-request/1" and r["session_id"] == "S-test" for r in requests)
    assert all(abs((r["t_end_mono"] - r["t_start_mono"]) * 1000 - r["duration_ms"]) < .01 for r in requests)

    measured = sorted(r["duration_ms"] for r in requests if r["phase"] == "measure")
    p95 = summary["measure"]["latency_ms"]["p95"]
    assert p95 == measured[math.ceil(.95 * len(measured)) - 1]
    assert p95 <= summary["measure"]["hist_p95_ms"] <= p95 * 1.05 + 1e-9
    assert summary["measure"]["request_rate_rps"] > 0 and summary["measure"]["max_ok_completion_gap_s"] >= 0

    intervals = log_records(ivl, "interval")
    assert [iv["interval"] for iv in intervals] == list(range(len(intervals)))
    assert intervals[0]["mono_start"] == 0
    assert all(a["mono_end"] == b["mono_start"] for a, b in zip(intervals, intervals[1:]))
    counts = Counter(r["interval"] for r in requests)
    assert all(iv["requests"] == counts[iv["interval"]] for iv in intervals)
    assert sum(iv["requests"] for iv in intervals) == len(requests)
    for marker in summary["phase_markers"]:  # a phase switch closes the running interval early
        assert intervals[marker["interval"]]["mono_start"] == marker["t_mono"]
        assert intervals[marker["interval"]]["phase"] == marker["phase"]
        assert intervals[marker["interval"] - 1]["mono_end"] == marker["t_mono"]
    header = read_jsonl(ivl)[0][0]
    assert header["type"] == "header" and header["hist_edges_ms"][-1] >= 60000 and "5 %" in header["hist_precision"]
    assert header["config"]["initial_phase"] == "warmup" and header["load_model"].startswith("closed loop")

    doc = json.loads(out.read_text())
    assert doc["schema"] == "hyptcn3/host-traffic/3" and doc["final"] and doc["phase"] == "post"
    assert doc["session_id"] == "S-test" and doc["run_id"] == summary["run_id"]
    assert doc["requests_logged"] == len(requests) == doc["requests"] == doc["ok"]
    assert doc["logging_error"] is None and doc["errors"] == 0
    assert "latency_p95_ms" not in doc and doc["latency_recent_window"] == 10000 and "sliding" in doc["latency_note"]
    assert set(doc["status_codes"]) <= {"200", "201"} and doc["routes"] == summary_routes(requests)


def summary_routes(requests):
    return dict(Counter(f"{r['method']} {r['route']}" for r in requests))


def test_http_503_is_http_error_and_counted_as_failure(server, tmp_path):
    http, target = server
    http.fail = True
    req, ivl, out = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl", tmp_path / "traffic.json"
    result = run_generator("--profile", "lab", "--target", target, "--dur", ".5", "--vlakien", "2",
                           "--requests-log", req, "--intervals-log", ivl, "--out", out)
    assert result.returncode == 1
    requests = log_records(req, "request")
    assert requests and all(r["outcome"] == "http_error" and r["status"] == 503 for r in requests)
    assert all(r["error"].startswith("HTTPError") and "503" in r["error"] for r in requests)
    intervals = log_records(ivl, "interval")
    assert sum(iv["http_error"] for iv in intervals) == len(requests) == sum(iv["requests"] for iv in intervals)
    assert sum(iv["status_codes"].get("503", 0) for iv in intervals) == len(requests)
    assert all(iv["hist_ok"] == {} for iv in intervals)
    doc = json.loads(out.read_text())
    assert doc["errors"] == len(requests) and doc["ok"] == 0 and doc["logging_error"] is None
    summary = summarize(req, ivl)
    assert summary["clean"] and summary["problems"] == ["no_ok_requests_in_measure"]


def test_connection_refused_is_transport_error_and_counted_as_failure(tmp_path):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    req, ivl, out = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl", tmp_path / "traffic.json"
    result = run_generator("--target", f"http://127.0.0.1:{port}", "--dur", ".4", "--vlakien", "2",
                           "--requests-log", req, "--intervals-log", ivl, "--out", out)
    assert result.returncode == 1
    requests = log_records(req, "request")
    assert requests and all(r["outcome"] == "transport_error" and r["status"] is None for r in requests)
    assert all(r["error"].startswith("URLError") and "refused" in r["error"].lower() for r in requests)
    intervals = log_records(ivl, "interval")
    assert sum(iv["transport_error"] for iv in intervals) == len(requests)
    assert sum(iv["status_codes"].get("none", 0) for iv in intervals) == len(requests)
    doc = json.loads(out.read_text())
    assert doc["status_codes"] == {"none": len(requests)} and doc["errors"] == len(requests)
    assert summarize(req, ivl)["problems"] == ["no_ok_requests_in_measure"]


def test_zero_request_intervals_cover_idle_time(server, tmp_path):
    _, target = server
    req, ivl = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl"
    result = run_generator("--profile", "lab", "--target", target, "--dur", ".5", "--vlakien", "1", "--burst", "0",
                           "--summary-interval-s", ".05", "--requests-log", req, "--intervals-log", ivl)
    assert result.returncode == 0
    summary = summarize(req, ivl)
    assert summary["problems"] == [] and summary["clean"]
    assert summary["intervals"]["zero_request_intervals"] > 0 and summary["intervals"]["count"] >= 10
    intervals = log_records(ivl, "interval")
    assert all(a["mono_end"] == b["mono_start"] for a, b in zip(intervals, intervals[1:]))
    end = read_jsonl(ivl)[0][-1]
    assert end["type"] == "end" and end["end_mono"] == intervals[-1]["mono_end"] >= .5


def test_log_write_failure_exits_3_and_is_never_claimed_clean(server, tmp_path):
    _, target = server
    req, ivl, out = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl", tmp_path / "traffic.json"
    code = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {str(REPO)!r})
        from scripts import host_traffic
        def full(fd):
            raise OSError(28, "No space left on device")
        os.fsync = full
        sys.exit(host_traffic.main(sys.argv[1:]))
    """)
    result = subprocess.run([sys.executable, "-c", code, "--target", target, "--profile", "lab", "--dur", ".4",
                             "--vlakien", "2", "--summary-interval-s", ".1", "--requests-log", req,
                             "--intervals-log", ivl, "--out", out], timeout=15, capture_output=True)
    assert result.returncode == 3
    doc = json.loads(out.read_text())
    assert doc["final"] and doc["logging_error"].startswith("OSError") and "No space" in doc["logging_error"]
    assert doc["ok"] > 0 and doc["errors"] == 0  # the HTTP side was fine: the exit code is about the log
    summary = summarize(req, ivl)
    assert not summary["clean"] and not summary["end_present"]["requests"]
    assert {"requests:end_missing", "intervals:end_missing"} <= set(summary["problems"])
    assert read_jsonl(req)[1] == []  # what was written is intact, it is just incomplete


def test_existing_log_path_is_refused(server, tmp_path):
    _, target = server
    req, ivl = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl"
    req.write_text("old\n")
    result = run_generator("--target", target, "--dur", ".2", "--requests-log", req, "--intervals-log", ivl)
    assert result.returncode == 2 and b"cannot create log" in result.stderr
    assert req.read_text() == "old\n" and not ivl.exists()
    assert run_generator("--target", target, "--dur", ".2", "--requests-log", tmp_path / "x.jsonl").returncode == 2


@pytest.mark.parametrize("attempt", range(3))
def test_back_to_back_signals_never_deadlock_the_main_loop(server, tmp_path, attempt):
    """Runner sends SIGUSR2 and SIGTERM back to back; a burst of signals must still end cleanly."""
    _, target = server
    req, ivl = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl"
    process = subprocess.Popen([sys.executable, SCRIPT, "--profile", "lab", "--target", target, "--dur", "0",
                                "--vlakien", "3", "--session-id", "S-burst", "--initial-phase", "measure",
                                "--summary-interval-s", "0.25", "--requests-log", req, "--intervals-log", ivl],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_until(lambda: req.exists() and req.stat().st_size > 0)
        time.sleep(.5)
        for _ in range(300):
            process.send_signal(signal.SIGUSR2)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()
    summary = summarize(req, ivl, session_id="S-burst")
    assert summary["problems"] == [] and summary["clean"]
    assert [m["phase"] for m in summary["phase_markers"]] == ["post"]
