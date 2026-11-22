#!/usr/bin/env python3
"""Host-to-VM HTTP traffic. --profile lab drives the persistent demo services.

Legacy paths remain compatible with experiment manifests. --dur 0 runs until
SIGTERM. JSON metrics count HTTP failures and use actual elapsed wall time.

With --requests-log and --intervals-log every request and every summary interval
is appended to JSONL logs (format and audit: scripts/traffic_log.py). SIGUSR1
switches the phase to "measure", SIGUSR2 to "post"; SIGTERM/SIGINT stop. Logging
never touches the per-worker RNG, so the load model is unchanged by it.
Exit codes: 0 clean, 1 request errors or no successful request, 2 bad arguments
or log files that could not be created, 3 logging failure.

Protocol v5 (package B5b; design dokazy/B5/navrh/NAVRH_B5b.md 1.3 and 1.4): the
profiles eshop and corp are an open loop with the parameters of the protocol's
profiles section:

  host_traffic.py --profile eshop|corp --protocol P --scenario S --seeds JSON [--rate R]
      --target URL --dur D --warmup-s W --session-id ID --requests-log A --intervals-log B
      --summary-interval-s 5 --initial-phase warmup|measure --out STATUS

User sessions arrive as a non-homogeneous Poisson process with intensity
rate x envelope(t): the envelope over [0, D] is drawn from the seed traffic
(draw_envelope), the arrival times by inversion of its integral from
traffic_arrivals; an arrival over max_concurrent user sessions in progress is
dropped and logged. Each admitted user session runs its profile's state machine
on its own streams of traffic_choices and traffic_sizes, waits the drawn think
time before every request but the first, and makes the deliberate client errors
of its profile. Logs hyptcn3/traffic-request/2 and hyptcn3/traffic-interval/2
(arrival records, the user session fields of a request, the session counts of an
interval). No user session arrives after D; the run ends on SIGTERM or SIGINT
only (the runner stops it after the measured phase). Exit code 1 means a request whose
result was not the expected one (a 2xx, or the status a deliberate error intends)
or no successful request; a v5 option with a legacy profile, or a legacy option
with a v5 profile, is refused with exit code 2.
"""
import argparse
import bisect
from collections import Counter, deque, namedtuple
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import heapq
import http.client
import itertools
import json
import math
import os
from pathlib import Path
import platform
import queue
import random
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
from urllib.parse import quote
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.traffic_log import (EDGES, HIST_PRECISION, INTERVAL_SCHEMA, OUTCOMES, PHASES,  # noqa: E402
                                 REQUEST_SCHEMA, bucket_index)

SIGNAL_POLL_S = .2
CESTY = ["/auth", "/orders", "/", "/auth?u=%d", "/orders?page=%d"]
GENERATOR = "hyptcn3 host_traffic 3"
STATUS_SCHEMA = "hyptcn3/host-traffic/3"
# Benign requests reached 2.35 s (POST /api/orders, bursty, 2026-10-22) while the
# guest disk sits on the system HDD; a client timeout would itself leave 499s and
# service tracebacks in the guest, so the limit only catches a stuck server.
TIMEOUT_S = 10
QUEUE_SIZE = 50000
LATENCY_DEFINITION = ("duration_ms: client-side monotonic clock around urlopen + reading the response "
                      "(same measurement as the status-file latency); includes failed requests; "
                      f"timeouts are capped by the {TIMEOUT_S} s client timeout")
INTERVAL_ASSIGNMENT = ("by request start time; an interval is emitted only after all requests started "
                       "in it have completed; an interval never spans a phase change")
OUTCOME_DEFINITION = ("ok = 2xx response; http_error = HTTP response with another status; timeout = client "
                      f"timeout ({TIMEOUT_S} s) while connecting or reading; transport_error = any other failure "
                      "(connection refused/reset, protocol error, undecodable 2xx JSON body)")
TIME_DEFINITION = ("t_*_utc: wall clock, ISO-8601 UTC with microseconds; t_*_mono / mono_*: seconds since the "
                   "generator's monotonic origin (header mono_origin); interval UTC bounds are derived from "
                   "the monotonic bounds via the origin")


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="microseconds")


def classify(exc):
    """Outcome and short error text for a failed request; never includes request data."""
    timeout = (isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)
               or "timed out" in str(exc).lower())
    return ("timeout" if timeout else "transport_error"), f"{type(exc).__name__}: {exc}"[:200]


class Metrics:
    """Aggregate status for --out; its p95 covers a sliding window of recent requests only."""
    def __init__(self, started, started_at):
        self.lock = threading.RLock()  # Reentrant: SessionMetrics extends record() and snapshot() under it.
        self.started, self.started_at = started, started_at
        self.ok = self.errors = 0
        self.statuses, self.paths = Counter(), Counter()
        self.latencies = deque(maxlen=10000)
        self.last_error = None

    def record(self, method, route, status, outcome, error, elapsed):
        with self.lock:
            if outcome == "ok":
                self.ok += 1
            else:
                self.errors += 1
                self.last_error = error or f"HTTP {status}"
            self.statuses["none" if status is None else str(status)] += 1
            self.paths[f"{method} {route}"] += 1
            self.latencies.append(elapsed * 1000)

    def snapshot(self):
        with self.lock:
            elapsed = time.monotonic() - self.started
            latencies = sorted(self.latencies)
            return {"schema": STATUS_SCHEMA, "started_at": self.started_at, "updated_at": utc(time.time()),
                    "elapsed_s": round(elapsed, 3), "ok": self.ok, "errors": self.errors,
                    "requests": self.ok + self.errors, "ok_per_s": round(self.ok / max(elapsed, .001), 3),
                    "status_codes": dict(self.statuses), "routes": dict(self.paths),
                    "latency_sample_n": len(latencies),
                    "latency_recent_p95_ms": round(latencies[math.ceil(.95 * len(latencies)) - 1], 3) if latencies else None,
                    "latency_recent_window": self.latencies.maxlen,
                    "latency_note": "p95 of the most recent requests (sliding window), not a whole-session "
                                    "percentile; session percentiles come from the request log",
                    "last_error": self.last_error}


class Interval:
    """One summary interval: requests join by start time, it is emitted once none is in flight."""
    def __init__(self, index, start, end, phase):
        self.index, self.start, self.end, self.phase = index, start, end, phase
        self.closed, self.in_flight = False, 0
        self.counts, self.statuses, self.routes, self.route_errors = Counter(), Counter(), Counter(), Counter()
        self.hist, self.hist_ok = Counter(), Counter()
        self.sum_ms, self.min_ms, self.max_ms = 0.0, None, None

    def add(self, rec):
        ms, key, bucket = rec["duration_ms"], f"{rec['method']} {rec['route']}", str(bucket_index(rec["duration_ms"]))
        self.counts["requests"] += 1
        self.counts[rec["outcome"]] += 1
        self.statuses["none" if rec["status"] is None else str(rec["status"])] += 1
        self.routes[key] += 1
        self.hist[bucket] += 1
        if rec["outcome"] == "ok":
            self.hist_ok[bucket] += 1
        else:
            self.route_errors[key] += 1
        self.sum_ms += ms
        self.min_ms = ms if self.min_ms is None else min(self.min_ms, ms)
        self.max_ms = ms if self.max_ms is None else max(self.max_ms, ms)

    def record(self, to_utc):
        duration, n, ok = self.end - self.start, self.counts["requests"], self.counts["ok"]
        return {"type": "interval", "interval": self.index, "phase": self.phase,
                "t_start_utc": to_utc(self.start), "t_end_utc": to_utc(self.end),
                "mono_start": round(self.start, 6), "mono_end": round(self.end, 6), "duration_s": round(duration, 6),
                "requests": n, **{outcome: self.counts[outcome] for outcome in OUTCOMES},
                "status_codes": dict(self.statuses), "routes": dict(self.routes), "route_errors": dict(self.route_errors),
                "throughput_rps": round(n / duration, 3) if duration > 0 else None,
                "ok_rps": round(ok / duration, 3) if duration > 0 else None,
                "sum_ms": round(self.sum_ms, 3), "min_ms": self.min_ms, "max_ms": self.max_ms,
                "hist": dict(self.hist), "hist_ok": dict(self.hist_ok)}


class Writer(threading.Thread):
    """Single log writer: numbers records per file, flushes every second, fsyncs only at the end (finish)."""
    def __init__(self, files, items, fail, schemas=None):
        super().__init__(name="log-writer", daemon=True)
        self.files, self.items, self.fail = files, items, fail
        self.schemas = schemas or {"requests": REQUEST_SCHEMA, "intervals": INTERVAL_SCHEMA}
        self.counts = {key: 0 for key in files}
        self.requests_logged, self.broken = 0, False

    def guard(self, action, *args):
        """Run one file operation; the first failure breaks the log for good."""
        if self.broken:
            return False
        try:
            action(*args)
            return True
        except Exception as exc:  # any failure makes the log untrustworthy
            self.broken = True
            self.fail(exc)
            return False

    def _write(self, key, rec):
        self.files[key].write(json.dumps({"schema": self.schemas[key], "n": self.counts[key], **rec}) + "\n")
        self.counts[key] += 1
        if rec["type"] == "request":
            self.requests_logged += 1

    def _sync(self, fsync):
        for handle in self.files.values():
            handle.flush()
            if fsync:
                os.fsync(handle.fileno())

    def run(self):
        last_flush = time.monotonic()
        while True:
            try:
                item = self.items.get(timeout=max(.05, 1 - (time.monotonic() - last_flush)))
            except queue.Empty:
                item = None
            if item and item[0] == "end":
                return self.finish(item[1])
            if item:
                self.guard(self._write, *item)
            now = time.monotonic()
            if now - last_flush >= 1:
                # The page cache only, as the host monitor: an fsync during the run waits for the collector's writeback.
                self.guard(self._sync, False)
                last_flush = now

    def finish(self, end):
        """Make everything durable, then append the end records, then close."""
        if self.guard(self._sync, True):
            for key in self.files:
                self.guard(self._write, key, dict(end, records=self.counts[key] + 1,
                                                  requests_logged=self.requests_logged, write_errors=0, clean=True))
            self.guard(self._sync, True)
        for handle in self.files.values():
            try:
                handle.close()
            except OSError:
                pass


class Clock:
    """The real clocks. The recorder and the open loop read time only through a clock; tests pass a fake one."""
    mono = staticmethod(time.monotonic)
    wall = staticmethod(time.time)

    @staticmethod
    def wait(cond, timeout):
        """Sleep on the held condition until notified or `timeout` seconds passed (None: until notified)."""
        cond.wait(timeout)


CLOCK = Clock()


class Recorder:
    """Phase and interval bookkeeping plus JSONL logging shared by all workers."""
    SCHEMAS = {"requests": REQUEST_SCHEMA, "intervals": INTERVAL_SCHEMA}

    def __init__(self, args, stop, files=None, wake=None, clock=CLOCK):
        self.args, self.stop, self.wake, self.clock = args, stop, wake or threading.Event(), clock
        self.run_id = uuid.uuid4().hex[:12]
        self.lock = threading.Lock()
        self.origin, self.origin_wall = clock.mono(), clock.wall()
        self.phase, self.interval_s = args.initial_phase, args.summary_interval_s
        self.intervals = deque([self._interval(0, 0.0, self.interval_s, self.phase)])
        self.started = self.completed = self.worker_errors = self.write_errors = 0
        self.outcomes, self.blocked_s, self.error = Counter(), 0.0, None
        self.queue, self.writer = queue.Queue(maxsize=QUEUE_SIZE), None
        if files:
            self.writer = Writer(files, self.queue, self.fail, self.SCHEMAS)
            for key in files:
                self.put(key, self.header(key))
            self.writer.start()

    def header(self, key):
        a = self.args
        rec = {"type": "header", "session_id": a.session_id, "run_id": self.run_id, "generator": GENERATOR,
               "config": {"target": a.target, "profile": a.profile, "seed": a.seed, "workers": a.vlakien,
                          "burst": a.burst, "catalog_share": a.catalog_share, "write_share": a.write_share,
                          "dur": a.dur, "summary_interval_s": a.summary_interval_s, "initial_phase": a.initial_phase,
                          "timeout_s": TIMEOUT_S, "requests_log": str(a.requests_log), "intervals_log": str(a.intervals_log)},
               "python": platform.python_version(), "hostname": socket.gethostname(), "pid": os.getpid(),
               "start_utc": utc(self.origin_wall), "start_unix": self.origin_wall, "mono_origin": self.origin,
               "latency_definition": LATENCY_DEFINITION, "phase_assignment": "by request start time",
               "interval_assignment": INTERVAL_ASSIGNMENT,
               "load_model": f"closed loop: {a.vlakien} workers, each sends one request at a time followed by "
                             "think time; not a fixed request rate",
               "outcome_definition": OUTCOME_DEFINITION, "time_definition": TIME_DEFINITION}
        if key == "intervals":
            rec.update(hist_edges_ms=EDGES, hist_precision=HIST_PRECISION)
        return rec

    def utc(self, rel):
        return utc(self.origin_wall + rel)

    def now(self):
        """Seconds since the origin."""
        return self.clock.mono() - self.origin

    def _interval(self, index, start, end, phase):
        return Interval(index, start, end, phase)

    def fail(self, exc):
        """Writer failure: remember it and stop the run; main() exits with code 3."""
        self.error = self.error or f"{type(exc).__name__}: {exc}"
        self.write_errors += 1
        self.stop.set()
        self.wake.set()

    def put(self, key, rec):
        """Blocking enqueue (backpressure, never a silent drop); blocked time is accumulated."""
        if not self.writer:
            return
        try:
            self.queue.put_nowait((key, rec))
        except queue.Full:
            t0 = time.monotonic()
            while self.writer.is_alive():
                try:
                    self.queue.put((key, rec), timeout=.5)
                    break
                except queue.Full:
                    continue
            with self.lock:
                self.blocked_s += time.monotonic() - t0

    def _roll(self, rel):
        """Open the interval containing rel; earlier ones close at their planned end."""
        current = self.intervals[-1]
        while rel >= current.end:
            current.closed = True
            current = self._interval(current.index + 1, current.end, current.end + self.interval_s, self.phase)
            self.intervals.append(current)

    def _ready(self):
        """Pop closed intervals with nothing in flight, oldest first."""
        ready = []
        while self.intervals and self.intervals[0].closed and not self.intervals[0].in_flight:
            ready.append(self.intervals.popleft().record(self.utc))
        return ready

    def begin(self):
        """Stamp a request start under the lock so phase and interval are consistent with switches."""
        with self.lock:
            mono, wall = self.clock.mono(), self.clock.wall()
            rel = mono - self.origin
            self._roll(rel)
            current = self.intervals[-1]
            current.in_flight += 1
            self.started += 1
            return mono, wall, rel, current, self.phase

    def end(self, start, rec):
        self.put("requests", rec)  # queued before the interval can be emitted
        with self.lock:
            start[3].add(rec)
            start[3].in_flight -= 1
            self.completed += 1
            self.outcomes[rec["outcome"]] += 1
            ready = self._ready()
        for record in ready:
            self.put("intervals", record)

    def switch(self, phase):
        """Main thread: close the current interval now and start the new phase (marker in both logs)."""
        with self.lock:
            if phase == self.phase:
                return
            mono, wall = self.clock.mono(), self.clock.wall()
            rel = mono - self.origin
            self._roll(rel)
            current = self.intervals[-1]
            if current.start < rel or current.in_flight or current.counts["requests"]:
                current.closed, current.end = True, rel
                current = self._interval(current.index + 1, rel, rel + self.interval_s, phase)
                self.intervals.append(current)
            else:
                current.phase = phase  # opened at this very instant: relabel instead of a zero-length interval
            previous, self.phase = self.phase, phase
            marker = {"type": "phase", "phase": phase, "previous": previous, "t_utc": utc(wall),
                      "t_mono": round(rel, 6), "interval": current.index}
            ready = self._ready()
        self.put("requests", marker)
        self.put("intervals", marker)
        for record in ready:
            self.put("intervals", record)

    def tick(self):
        with self.lock:
            self._roll(self.clock.mono() - self.origin)
            ready = self._ready()
        for record in ready:
            self.put("intervals", record)

    def close(self, extra=None):
        """After the workers stopped: close coverage at stop time, emit everything, write end records (with the
        fields of `extra`)."""
        with self.lock:
            mono, wall = self.clock.mono(), self.clock.wall()
            rel = mono - self.origin
            self._roll(rel)
            current = self.intervals[-1]
            current.closed, current.end = True, rel
            if current.start == rel and not current.counts["requests"] and not current.in_flight:
                self.intervals.pop()  # empty zero-length tail
            in_flight = sum(interval.in_flight for interval in self.intervals)
            records = [interval.record(self.utc) for interval in self.intervals]
            self.intervals.clear()
            end = {"type": "end", "requests_started": self.started, "requests_completed": self.completed,
                   **{outcome: self.outcomes[outcome] for outcome in OUTCOMES}, "in_flight_at_stop": in_flight,
                   "worker_errors": self.worker_errors, "log_backpressure_s": round(self.blocked_s, 3),
                   "phase": self.phase, "end_utc": utc(wall), "end_mono": round(rel, 6), **(extra or {})}
        for record in records:
            self.put("intervals", record)
        if self.writer:
            self.put("end", end)
            self.writer.join()

    def requests_logged(self):
        return self.writer.requests_logged if self.writer else 0


class Client:
    """Per-worker HTTP client: numbers, measures and records each request."""
    def __init__(self, target, index, metrics, recorder):
        self.target, self.index, self.metrics, self.recorder, self.seq = target.rstrip("/"), index, metrics, recorder, 0

    def request(self, path, method="GET", body=None, token=""):
        data = json.dumps(body).encode() if body is not None else None
        rid = f"{self.recorder.run_id}-{self.index:02d}-{self.seq:08d}"
        headers = {"Content-Type": "application/json", "User-Agent": "hyptcn-host-traffic/3", "X-Request-ID": rid}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.target + path, data=data, headers=headers, method=method)
        start = self.recorder.begin()
        status, outcome, error, payload, nbytes = None, "ok", None, None, 0
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as response:
                status = response.status
                raw = response.read(1024 * 1024)
                nbytes = len(raw)
                if "application/json" in response.headers.get("Content-Type", ""):
                    payload = json.loads(raw)
                if not 200 <= status < 300:
                    outcome = "http_error"
        except urllib.error.HTTPError as exc:
            status, outcome, error = exc.code, "http_error", f"HTTPError: {exc}"
        except (OSError, ValueError, http.client.HTTPException) as exc:
            outcome, error = classify(exc)
        end_mono, end_wall = time.monotonic(), time.time()
        elapsed, route = end_mono - start[0], path.split("?")[0]
        self.metrics.record(method, route, status, outcome, error, elapsed)
        self.recorder.end(start, {"type": "request", "session_id": self.recorder.args.session_id,
                                  "run_id": self.recorder.run_id, "rid": rid, "worker": self.index,
                                  "worker_seq": self.seq, "interval": start[3].index, "phase": start[4],
                                  "method": method, "route": route, "status": status, "outcome": outcome,
                                  "error": error, "t_start_utc": utc(start[1]), "t_end_utc": utc(end_wall),
                                  "t_start_mono": round(start[2], 6),
                                  "t_end_mono": round(end_mono - self.recorder.origin, 6),
                                  "duration_ms": round(elapsed * 1000, 3), "response_bytes": nbytes})
        self.seq += 1
        return payload


def worker(args, index, stop, client):
    rng = random.Random(args.seed + index * 1009)
    token, expires = "", 0
    while not stop.is_set():
        if args.profile == "lab" and time.monotonic() >= expires:
            login = client.request("/api/auth/token", "POST", {"user": f"demo{index}"})
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
                client.request(path)
            else:
                choice = rng.random()
                catalog_share = getattr(args, "catalog_share", .5)
                write_share = getattr(args, "write_share", .2)
                if choice < catalog_share:
                    client.request("/api/catalog")
                elif choice < .95 - write_share:
                    client.request("/api/orders", token=token)
                elif choice < .95:
                    client.request("/api/orders", "POST",
                                   {"product_id": rng.randint(1, 5), "quantity": rng.randint(1, 3)}, token)
                else:
                    client.request("/healthz")
        stop.wait(rng.uniform(.15, .6) if burst else rng.uniform(.5, 1.5))


def run_worker(args, index, stop, client):
    try:
        worker(args, index, stop, client)
    except Exception as exc:  # a silently dead worker would change the load model: report it
        with client.recorder.lock:
            client.recorder.worker_errors += 1
        print(f"host_traffic: worker {index} failed: {exc!r}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ protocol v5: the open loop (package B5b)

V5_GENERATOR = "hyptcn3 host_traffic 4"
V5_STATUS_SCHEMA = "hyptcn3/host-traffic/4"
V5_REQUEST_SCHEMA = "hyptcn3/traffic-request/2"  # design B5b 1.4; scripts/traffic_log.py reads /1 and /2
V5_INTERVAL_SCHEMA = "hyptcn3/traffic-interval/2"
PROTOCOL_SCHEMA = "hyptcn3/collection-protocol/3"
V5_LOAD_MODEL = ("open loop: user sessions arrive as a non-homogeneous Poisson process with intensity rate x "
                 "envelope(t), at most max_concurrent in progress")
V5_CONCURRENCY = ("one scheduler thread offers each arrival at its time and sends each step of a user session after "
                  "its think time; the requests run in a pool of at most max_concurrent threads, so the request of an "
                  "admitted user session never waits for a thread")
V5_PHASE_ASSIGNMENT = "by request start time; an arrival by its time"
V5_INTERVAL_ASSIGNMENT = (INTERVAL_ASSIGNMENT + "; arrivals by their time; planned_sessions is rate x the integral "
                          "of the envelope over the interval, the envelope being 0 outside [0, dur]")
V5_SEEDS = ("traffic", "traffic_arrivals", "traffic_choices", "traffic_sizes")  # design B5b 1.2
V5_START_PHASES = ("warmup", "measure")  # design B5b 1.3
# The options of the legacy and lab profiles a v5 profile refuses, and those of the v5 profiles they refuse; with
# the defaults the legacy profiles keep.
LEGACY_OPTIONS = {"vlakien": 8, "burst": 1, "catalog_share": .5, "write_share": .2, "seed": 1}
V5_OPTIONS = ("protocol", "scenario", "seeds", "rate", "warmup_s")
# Options with a legacy default that a v5 run must state (design B5b 1.3 lists them without brackets).
STATED = {"target": "http://192.168.122.100", "dur": 120, "session_id": "", "summary_interval_s": 5,
          "initial_phase": "measure"}
V5_REQUIRED = ("protocol", "scenario", "seeds", "warmup_s", "requests_log", "intervals_log", "out", *STATED)
MAX_DRAWS = 1000  # Judgment, as the plan's redraws (scripts/protocol_v5.py MAX_DRAWS): envelope draws, then refused.
MISSING_DOCUMENT = 10 ** 9  # Judgment: no document id from 10**9 on exists (uploads count up from the 500 seeded).
MAX_ARRIVALS = 10 ** 7  # Judgment: a plan of more arrivals is a mistyped rate, not a lab run (refused, exit 2).
ROUND = 6  # Times, levels and think times are rounded once to 1 us (the 6 decimals of the logs' times), then used.
SAFE_ID = re.compile(r"[A-Za-z0-9-]{1,64}")  # A report id the status check may put into its path.
# The status file counts the requests of these steps under one route each (its keys stay bounded); the request and
# interval records keep the real path.
STATUS_ROUTES = {"detail": "/api/catalog/<id>", "static": "/static/<file>", "doc_get": "/api/docs/<id>",
                 "report_status": "/api/reports/<id>"}

Step = namedtuple("Step", "step method path body object intended_status think_s token")
Upload = namedtuple("Upload", "size seed")  # An upload body: `size` bytes of random.Random(seed).randbytes.
Reply = namedtuple("Reply", "status outcome payload end_rel")  # What the request of a step got; end_rel its end.


class Envelope:
    """The planned level over [0, dur]: piecewise linear through the knots (t_s strictly increasing from 0 to dur,
    every level in [0, 1], the maximum 1) and 0 outside [0, dur]. The arrivals are drawn from exactly these knots,
    and the logs carry them as they are."""

    def __init__(self, t_s, level):
        self.t, self.level = list(t_s), list(level)
        self.cum = [0.0]
        for i in range(len(self.t) - 1):
            self.cum.append(self.cum[-1] + (self.level[i] + self.level[i + 1]) / 2 * (self.t[i + 1] - self.t[i]))

    def as_dict(self):
        return {"t_s": list(self.t), "level": list(self.level)}

    def _segment(self, x):
        j = min(bisect.bisect_right(self.t, x), len(self.t) - 1) - 1
        return j, (self.level[j + 1] - self.level[j]) / (self.t[j + 1] - self.t[j])

    def at(self, x):
        """The level at time x."""
        if not self.t[0] <= x <= self.t[-1]:
            return 0.0
        j, slope = self._segment(x)
        return self.level[j] + slope * (x - self.t[j])

    def cumulative(self, x):
        """The integral of the level over [0, x]."""
        if x <= self.t[0]:
            return 0.0
        if x >= self.t[-1]:
            return self.cum[-1]
        j, slope = self._segment(x)
        u = x - self.t[j]
        return self.cum[j] + self.level[j] * u + slope * u * u / 2

    def integral(self, a, b):
        return self.cumulative(b) - self.cumulative(a)

    def inverse(self, y):
        """The time x with cumulative(x) = y, for 0 <= y <= cumulative(dur) (the root of the segment's quadratic in
        the form that stays exact on flat and falling segments)."""
        j = min(bisect.bisect_right(self.cum, y), len(self.t) - 1) - 1
        slope = (self.level[j + 1] - self.level[j]) / (self.t[j + 1] - self.t[j])
        d = y - self.cum[j]
        if d <= 0:
            return self.t[j]
        root = math.sqrt(max(0.0, self.level[j] ** 2 + 2 * slope * d))
        return min(self.t[j + 1], self.t[j] + 2 * d / (self.level[j] + root))

    def peak_to_mean(self, a, b):
        """The maximum of the level over [a, b] divided by its mean there."""
        top = max([level for t, level in zip(self.t, self.level) if a <= t <= b] + [self.at(a), self.at(b)])
        return top / (self.integral(a, b) / (b - a))


def _knots(a, dur, wave, at, peak):
    """The envelope through the ramp, the slow wave every step_s and the four corners of the peak at `at`."""
    ramp, step, edge = a["ramp_s"], a["step_s"], peak * a["peak_edge_share"]
    knots = {0.0: 0.0 if ramp > 0 else wave(0.0)}
    if ramp > 0:
        knots[ramp] = wave(ramp)
    k = math.floor(ramp / step) + 1
    while k * step < dur:
        if not at <= k * step <= at + peak:
            knots[k * step] = wave(k * step)
        k += 1
    knots[dur] = wave(dur)
    knots.update({at: wave(at), at + edge: 1.0, at + peak - edge: 1.0, at + peak: wave(at + peak)})
    rounded = {}
    for t in sorted(knots):  # A knot that rounds onto an earlier one is that knot (equal levels to 1e-6).
        rounded.setdefault(round(t, ROUND), round(knots[t], ROUND))
    times = sorted(rounded)
    return Envelope(times, [rounded[t] for t in times])


def draw_envelope(arrivals, rng, dur, warmup, min_peak_to_mean):
    """(Envelope, draws) of a v5 run over [0, dur] from the stream of the seed traffic (profiles.*.arrivals).

    A ramp from level 0 over [0, ramp_s] (ramp_s <= warmup: the ramp lies in the warmup); one slow wave
    mean * (1 - amplitude * cos(2 pi (t - start) / period)), with a cycle starting (lowest level) at `start` in
    [warmup, warmup + period); one short peak of level 1 lasting peak_s inside [warmup, dur]: a trapezoid whose
    flanks take peak_edge_share of it each, starting anywhere (peak_at uniform) or at `start` (peak_at wave_start:
    the login wave of corp at the beginning of the slow wave, skeleton B5 section 2). Drawn again until the
    peak-to-mean over [warmup, dur] is at least min_peak_to_mean (skeleton section 2); ValueError after MAX_DRAWS.
    """
    a = arrivals
    for draw in range(1, MAX_DRAWS + 1):
        period, mean = rng.uniform(*a["wave_period_s"]), rng.uniform(*a["wave_mean"])
        amplitude, peak = rng.uniform(*a["wave_amplitude"]), rng.uniform(*a["peak_s"])
        start = rng.uniform(warmup, warmup + period)
        at = rng.uniform(warmup, dur - peak) if a["peak_at"] == "uniform" else start
        if at + peak > dur:
            continue

        def wave(t, mean=mean, amplitude=amplitude, start=start, period=period):
            return mean * (1 - amplitude * math.cos(2 * math.pi * (t - start) / period))
        envelope = _knots(a, dur, wave, at, peak)
        if envelope.peak_to_mean(warmup, dur) >= min_peak_to_mean:
            return envelope, draw
    raise ValueError(f"no envelope with peak-to-mean >= {min_peak_to_mean} over [{warmup}, {dur}] s in {MAX_DRAWS} "
                     "draws")


def arrival_times(envelope, rate, rng):
    """The arrival times over [0, dur]: unit exponential spacings mapped through the inverse of rate x the
    envelope's integral (inversion of a non-homogeneous Poisson process), rounded to 1 us."""
    total, times, y = rate * envelope.cum[-1], [], 0.0
    while True:
        y += rng.expovariate(1.0)
        if y >= total:
            return times
        times.append(round(envelope.inverse(y / rate), ROUND))


def substream(seed, n):
    """The own stream of user session n within the stream of one purpose (its seed): sha256 of [seed, n]."""
    return random.Random(int.from_bytes(hashlib.sha256(json.dumps([seed, n]).encode()).digest()[:8], "big"))


class Zipf:
    """Ranks 1..n with a probability proportional to rank ** -s (inverse transform on the cumulative weights)."""

    def __init__(self, n, s):
        self.cum = list(itertools.accumulate(k ** -s for k in range(1, n + 1)))

    def draw(self, rng):
        return min(bisect.bisect_right(self.cum, rng.random() * self.cum[-1]), len(self.cum) - 1) + 1


def document_size(rng, d):
    """An upload size of profiles.corp.document_sizes: with tail_share a Pareto size from tail_from_bytes, else
    lognormal around median_bytes; cut to [min_bytes, max_bytes]."""
    if rng.random() < d["tail_share"]:
        size = d["tail_from_bytes"] * rng.paretovariate(d["tail_alpha"])
    else:
        size = math.exp(rng.gauss(math.log(d["median_bytes"]), d["sigma"]))
    return int(min(d["max_bytes"], max(d["min_bytes"], size)))


class Lab:
    """What the guest's seeded level holds (lab/seed.py), so a user session requests objects that exist, and the
    profile's Zipf laws over them (product, catalog page, static file; document, document page)."""

    def __init__(self, profile, params):
        from lab import seed  # The guest's seeded level; it imports nothing outside the standard library.
        self.products, self.customers = seed.SIZES["products"], seed.SIZES["customers"]
        self.employees, self.documents = seed.SIZES["employees"], seed.SIZES["documents"]
        self.static = [name for name, _ in seed.static_files(0)]  # The names do not depend on the seed.
        self.terms, self.password = seed.NOUNS, seed.employee_password
        s = params["zipf_s"]
        if profile == "eshop":
            self.product_law, self.static_law = Zipf(self.products, s), Zipf(len(self.static), s)
            self.page_law = Zipf(math.ceil(self.products / params["funnel"]["page_size"]), s)
        else:
            self.document_law = Zipf(self.documents, s)
            self.page_law = Zipf(math.ceil(self.documents / params["page_size"]), s)


class UserSession:
    """One user session of a v5 profile: steps() yields its requests in order and gets each reply back.

    Every draw comes from the session's own streams of traffic_choices and traffic_sizes in an order no reply
    changes: a reply only fills the token, or the report id of a status check (without one the check is left out
    after the same draws), so equal seeds give equal steps however the lab answers. After every request one
    deliberate client error follows with the odds share / (1 - share), so that share of all requests is deliberate
    (client_errors; proposal 5.3)."""

    def __init__(self, params, intensity, n, seeds, lab, run_id):
        self.p, self.intensity, self.n, self.lab, self.run_id = params, intensity, n, lab, run_id
        self.rng, self.sizes = substream(seeds["traffic_choices"], n), substream(seeds["traffic_sizes"], n)
        share = params["client_errors"]["share"]
        self.error_odds, self.statuses = share / (1 - share), list(params["client_errors"]["statuses"])
        self.token, self.first, self.seq = "", True, 0
        self._steps = self.steps()

    def start(self):
        return self._steps.send(None)

    def reply(self, reply):
        """The next step after `reply`, None when the user session is done."""
        try:
            return self._steps.send(reply)
        except StopIteration:
            return None

    def think(self):
        """None before the first request; else exponential with mean think_s.mean, cut at think_s.max."""
        if self.first:
            self.first = False
            return None
        t = self.p["think_s"]
        return round(min(self.rng.expovariate(1 / t["mean"]), t["max"]), ROUND)

    def make(self, step, path, method="GET", body=None, obj=None, token=False, intended=None, auth=None):
        """A step; its think time is drawn now. token: send the session's token; auth: send this one instead."""
        return Step(step, method, path, body, obj, intended, self.think(),
                    auth if auth is not None else self.token if token else "")

    def request(self, step, login=False):
        """Yield the step, then maybe a deliberate client error (whose reply is not used); returns the step's reply.
        login: the reply's token is the session's from now on, already for that error."""
        reply = yield step
        if login:
            self.token = self.token_of(reply)
        error = self.error()
        if error:
            yield error
        return reply

    def error(self):
        """The deliberate client error after a request, or None; the draws are the same whether it is sent or not."""
        if self.rng.random() >= self.error_odds:
            return None
        return self.wrong(self.statuses[self.rng.randrange(len(self.statuses))])

    @staticmethod
    def token_of(reply):
        token = reply.payload.get("token") if reply is not None and isinstance(reply.payload, dict) else None
        return token if isinstance(token, str) else ""


class Eshop(UserSession):
    """Profile eshop: a customer's funnel (skeleton B5 section 2; profiles.eshop.funnel)."""

    def steps(self):
        p, f, rng, lab = self.p, self.p["funnel"], self.rng, self.lab
        size, viewed = f["page_size"], []
        buyer = rng.random() < p["order_share"][self.intensity]
        yield from self.page(self.make("home", "/"))
        for _ in range(rng.randint(*f["pages"])):
            if rng.random() < f["search_share"]:
                term = lab.terms[rng.randrange(len(lab.terms))]
                yield from self.page(self.make("search", f"/api/catalog?q={quote(term)}&page=1&size={size}"))
            else:
                yield from self.page(self.make("browse", f"/api/catalog?page={lab.page_law.draw(rng)}&size={size}"))
            for _ in range(rng.randint(*f["details_per_page"])):
                product = lab.product_law.draw(rng)
                viewed.append(product)
                yield from self.page(self.make("detail", f"/api/catalog/{product}", obj=product))
        if not buyer:
            return
        customer = f"zakaznik{rng.randint(1, lab.customers):04d}"
        yield from self.request(self.make("login", "/api/auth/token", "POST", {"user": customer}), login=True)
        for _ in range(rng.randint(*f["cart_items"])):
            product = viewed[rng.randrange(len(viewed))] if viewed else lab.product_law.draw(rng)
            yield from self.request(self.make("cart_add", "/api/cart", "POST", {"product_id": product, "quantity": 1},
                                              obj=product, token=True))
        yield from self.request(self.make("cart", "/api/cart", token=True))
        yield from self.request(self.make("order", "/api/orders", "POST", {"cart": True}, token=True))

    def page(self, step):
        """A page view (home, catalog page, detail), then a static file with funnel.static_share."""
        reply = yield from self.request(step)
        if self.rng.random() < self.p["funnel"]["static_share"]:
            path = "/static/" + self.lab.static[self.lab.static_law.draw(self.rng) - 1]
            yield from self.request(self.make("static", path, obj=path))
        return reply

    def wrong(self, status):
        """400 a catalog page 0, 401 the cart with an invalid token, 404 a product beyond the catalog."""
        if status == 400:
            return self.make("browse", f"/api/catalog?page=0&size={self.p['funnel']['page_size']}", intended=400)
        if status == 401:
            return self.make("cart", "/api/cart", intended=401, auth="invalid")
        missing = self.lab.products + self.rng.randint(1, self.lab.products)
        return self.make("detail", f"/api/catalog/{missing}", obj=missing, intended=404)


class Corp(UserSession):
    """Profile corp: an employee's login and document actions (skeleton B5 section 2; profiles.corp)."""
    ACTIONS = ("doc_list", "doc_get", "doc_put", "report")

    def steps(self):
        p, rng, lab = self.p, self.rng, self.lab
        user = f"zamestnanec{rng.randint(1, lab.employees):03d}"
        yield from self.request(self.make("login", "/api/auth/login", "POST",
                                          {"user": user, "password": lab.password(user)}), login=True)
        weights = list(itertools.accumulate(p["shares"][action] for action in self.ACTIONS))
        for k in range(rng.randint(*p["actions"])):
            action = self.ACTIONS[min(bisect.bisect_right(weights, rng.random() * weights[-1]), len(weights) - 1)]
            if action == "doc_list":
                page = lab.page_law.draw(rng)
                yield from self.request(self.make("doc_list", f"/api/docs?page={page}&size={p['page_size']}",
                                                  token=True))
            elif action == "doc_get":
                document = lab.document_law.draw(rng)
                yield from self.request(self.make("doc_get", f"/api/docs/{document}", obj=document, token=True))
            elif action == "doc_put":
                body = Upload(document_size(self.sizes, p["document_sizes"]), self.sizes.getrandbits(64))
                name = f"upload-{self.run_id}-u{self.n}-{k}.bin"
                yield from self.request(self.make("doc_put", f"/api/docs?name={name}", "POST", body, token=True))
            else:
                reply = yield from self.request(self.make("report", "/api/reports", "POST", token=True))
                think = self.think()
                report = reply.payload.get("report") if reply is not None and isinstance(reply.payload, dict) else None
                if isinstance(report, str) and SAFE_ID.fullmatch(report):
                    yield from self.request(Step("report_status", "GET", f"/api/reports/{report}", None, report, None,
                                                 think, self.token))
                else:
                    self.error()  # The draws the status check's request makes; without a report id it is left out.

    def wrong(self, status):
        """400 a document list page 0, 401 a login with a wrong password, 404 a document that never exists."""
        if status == 400:
            return self.make("doc_list", f"/api/docs?page=0&size={self.p['page_size']}", intended=400, token=True)
        if status == 401:
            user = f"zamestnanec{self.rng.randint(1, self.lab.employees):03d}"
            return self.make("login", "/api/auth/login", "POST",
                             {"user": user, "password": "wrong-" + self.lab.password(user)}, intended=401)
        missing = MISSING_DOCUMENT + self.rng.randrange(10 ** 6)  # Judgment: a million ids, none of them exists.
        return self.make("doc_get", f"/api/docs/{missing}", obj=missing, intended=404, token=True)


# The traffic profiles of protocol v5 (scripts/protocol_v5.py PROFILE_KEYS has their keys; lab_names reads these).
PROFILES = {"eshop": Eshop, "corp": Corp}


class V5Run:
    """A checked v5 command line with its protocol: the profile, its parameters, the rate, the seeds, the envelope
    and the planned arrival times."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


def _seeds(text):
    try:
        seeds = json.loads(text)
    except ValueError:
        raise ValueError("--seeds is not JSON") from None
    if type(seeds) is not dict:
        raise ValueError("--seeds is not a JSON object")
    for key in V5_SEEDS:
        if key not in seeds:
            raise ValueError(f"--seeds has no {key}")
    for key, value in seeds.items():
        if type(value) is not int or value < 0:
            raise ValueError(f"--seeds: {key} is not an integer >= 0")
    return seeds


def _rate(scenario, s, given):
    """(rate, rate_source): the protocol's rate, or --rate when the protocol leaves it null."""
    if "rate" not in s:
        raise ValueError(f"scenarios.{scenario} has no rate")
    if s["rate"] is None:
        if given is None:
            raise ValueError(f"scenarios.{scenario}.rate is null: --rate is required")
        rate, source = given, "command line"
    else:
        if given is not None:
            raise ValueError(f"scenarios.{scenario}.rate is set by the protocol: --rate is refused")
        rate, source = s["rate"], "protocol"
    if type(rate) not in (int, float) or not math.isfinite(rate) or rate <= 0:
        raise ValueError(f"the rate ({source}) is not a finite number > 0")
    return rate, source


def prepare_v5(args):
    """The run of a v5 command line (design B5b 1.3): every option and the protocol are checked; a ValueError
    names the first reason the command line is refused."""
    from scripts import protocol_v5  # The profiles section's layout and value check (the loader's own).
    for name in LEGACY_OPTIONS:
        if getattr(args, name) is not None:
            raise ValueError(f"--{name.replace('_', '-')} is not an option of profile {args.profile}")
    for name in V5_REQUIRED:
        if getattr(args, name) is None:
            raise ValueError(f"profile {args.profile} requires --{name.replace('_', '-')}")
    if args.initial_phase not in V5_START_PHASES:
        raise ValueError(f"--initial-phase {args.initial_phase} is not a start phase of profile {args.profile}")
    if not math.isfinite(args.dur) or args.dur <= 0:
        raise ValueError("--dur must be a number > 0: the envelope spans [0, dur]")
    if not math.isfinite(args.warmup_s) or not 0 <= args.warmup_s < args.dur:
        raise ValueError("--warmup-s must lie in [0, --dur)")
    try:
        raw = Path(args.protocol).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot read protocol: {error}") from None
    if type(doc) is not dict or doc.get("schema") != PROTOCOL_SCHEMA:
        raise ValueError(f"protocol schema is not {PROTOCOL_SCHEMA}: the v5 profiles are its profiles section")
    problems = protocol_v5.profiles_problems(doc)
    if problems:
        raise ValueError("invalid profiles: " + problems[0])
    scenarios = doc.get("scenarios")
    if type(scenarios) is not dict or type(scenarios.get(args.scenario)) is not dict:
        raise ValueError(f"unknown scenario: {args.scenario}")
    s = scenarios[args.scenario]
    if s.get("profile") != args.profile:
        raise ValueError(f"--profile {args.profile} differs from scenarios.{args.scenario}.profile {s.get('profile')}")
    if s.get("intensity") not in ("low", "high"):
        raise ValueError(f"scenarios.{args.scenario}.intensity is not low or high")
    rate, source = _rate(args.scenario, s, args.rate)
    rule = doc.get("scenario_rule")
    ratio = rule.get("min_peak_to_mean") if type(rule) is dict else None
    if type(ratio) not in (int, float) or not math.isfinite(ratio) or ratio < 1:
        raise ValueError("scenario_rule.min_peak_to_mean is not a number >= 1")
    seeds = _seeds(args.seeds)
    params = doc["profiles"][args.profile]
    a = params["arrivals"]
    if a["ramp_s"] > args.warmup_s:
        raise ValueError(f"the ramp of profile {args.profile} (arrivals.ramp_s {a['ramp_s']}) is longer than "
                         f"--warmup-s {args.warmup_s}")
    if args.dur - args.warmup_s < a["peak_s"][1]:
        raise ValueError(f"[--warmup-s, --dur] is shorter than the longest peak (arrivals.peak_s {a['peak_s'][1]} s)")
    envelope, draws = draw_envelope(a, random.Random(seeds["traffic"]), args.dur, args.warmup_s, ratio)
    if rate * envelope.cum[-1] > MAX_ARRIVALS:
        raise ValueError(f"rate {rate} plans more than {MAX_ARRIVALS} arrivals over [0, --dur]")
    return V5Run(profile=args.profile, params=params, scenario=args.scenario, intensity=s["intensity"], rate=rate,
                 rate_source=source, seeds=seeds, protocol_sha256=hashlib.sha256(raw).hexdigest(),
                 warmup_s=args.warmup_s, dur=args.dur, envelope=envelope, draws=draws, cap=params["max_concurrent"],
                 arrivals=arrival_times(envelope, rate, random.Random(seeds["traffic_arrivals"])),
                 lab=Lab(args.profile, params))


class SessionMetrics(Metrics):
    """The status of a v5 run: also the deliberate client errors, and the requests whose result was not the one
    expected (a 2xx, or the status a deliberate error intends) - exit code 1 when there is any."""

    def __init__(self, started, started_at):
        super().__init__(started, started_at)
        self.intended = self.intended_matched = self.unexpected = 0

    def record(self, method, route, status, outcome, error, elapsed, intended=None):
        with self.lock:
            super().record(method, route, status, outcome, error, elapsed)
            if intended is None:
                self.unexpected += outcome != "ok"
            else:
                self.intended += 1
                self.intended_matched += status == intended
                self.unexpected += status != intended

    def snapshot(self):
        with self.lock:
            return dict(super().snapshot(), schema=V5_STATUS_SCHEMA, intended_errors=self.intended,
                        intended_errors_matched=self.intended_matched, unexpected_results=self.unexpected)


class SessionInterval(Interval):
    """A summary interval of a v5 run: also the arrivals by their time and the most user sessions in progress."""

    def __init__(self, index, start, end, phase, active, planned):
        super().__init__(index, start, end, phase)
        self.sessions, self.active_max, self.planned = Counter(), active, planned

    def record(self, to_utc):
        return dict(super().record(to_utc), offered_sessions=self.sessions["offered"],
                    admitted_sessions=self.sessions["admitted"], dropped_sessions=self.sessions["dropped"],
                    planned_sessions=self.planned(round(self.start, 6), round(self.end, 6)),  # The logged bounds.
                    active_max=self.active_max)


class SessionRecorder(Recorder):
    """The recorder of a v5 run (design B5b 1.4): schemas /2, the v5 header, the arrival records and the session
    counts of every interval."""
    SCHEMAS = {"requests": V5_REQUEST_SCHEMA, "intervals": V5_INTERVAL_SCHEMA}

    def __init__(self, args, run, stop, files=None, wake=None, clock=CLOCK):
        self.run, self.active = run, 0  # The interval factory needs both before the first interval.
        super().__init__(args, stop, files, wake, clock)

    def _interval(self, index, start, end, phase):
        return SessionInterval(index, start, end, phase, self.active, self.planned)

    def planned(self, start, end):
        return round(self.run.rate * self.run.envelope.integral(start, end), ROUND)

    def header(self, key):
        a, run = self.args, self.run
        rec = {"type": "header", "session_id": a.session_id, "run_id": self.run_id, "generator": V5_GENERATOR,
               "config": {"target": a.target, "profile": a.profile, "protocol": str(a.protocol),
                          "scenario": a.scenario, "seed": run.seeds["traffic"], "rate": a.rate, "dur": a.dur,
                          "warmup_s": a.warmup_s, "summary_interval_s": a.summary_interval_s,
                          "initial_phase": a.initial_phase, "timeout_s": TIMEOUT_S,
                          "requests_log": str(a.requests_log), "intervals_log": str(a.intervals_log)},
               "python": platform.python_version(), "hostname": socket.gethostname(), "pid": os.getpid(),
               "start_utc": utc(self.origin_wall), "start_unix": self.origin_wall, "mono_origin": self.origin,
               "latency_definition": LATENCY_DEFINITION, "phase_assignment": V5_PHASE_ASSIGNMENT,
               "interval_assignment": V5_INTERVAL_ASSIGNMENT, "load_model": V5_LOAD_MODEL,
               "outcome_definition": OUTCOME_DEFINITION, "time_definition": TIME_DEFINITION,
               "profile": run.profile, "scenario": run.scenario, "intensity": run.intensity, "rate": run.rate,
               "rate_source": run.rate_source, "seeds": dict(run.seeds), "protocol_sha256": run.protocol_sha256,
               "profile_parameters": run.params, "warmup_s": run.warmup_s, "envelope": run.envelope.as_dict(),
               "concurrency": V5_CONCURRENCY}
        if key == "intervals":
            rec.update(hist_edges_ms=EDGES, hist_precision=HIST_PRECISION)
        return rec

    def arrival(self, n, admitted, active):
        """Log the arrival of user session n, `active` in progress just before it, and count it in its interval."""
        with self.lock:
            mono, wall = self.clock.mono(), self.clock.wall()
            rel = mono - self.origin
            self._roll(rel)
            current = self.intervals[-1]
            current.sessions["offered"] += 1
            current.sessions["admitted" if admitted else "dropped"] += 1
            self.active = active + admitted
            current.active_max = max(current.active_max, self.active)
            rec = {"type": "arrival", "user_session": f"{self.run_id}-u{n}", "t_mono": round(rel, ROUND),
                   "t_utc": utc(wall), "phase": self.phase, "admitted": admitted, "active": active}
        self.put("requests", rec)

    def session_end(self, active):
        """A user session ended; `active` are still in progress."""
        with self.lock:
            self._roll(self.clock.mono() - self.origin)
            self.active = active


class UserClient:
    """The HTTP side of a v5 run: sends one step, measures it and logs its request record (design B5b 1.4)."""

    def __init__(self, target, metrics, recorder, opener=urllib.request.urlopen):
        self.target, self.metrics, self.recorder, self.opener = target.rstrip("/"), metrics, recorder, opener

    def request(self, n, seq, step):
        rec = self.recorder
        user_session = f"{rec.run_id}-u{n}"
        rid = f"{user_session}-{seq:04d}"
        headers = {"User-Agent": "hyptcn-host-traffic/4", "X-Request-ID": rid}
        data = None
        if isinstance(step.body, Upload):
            data = random.Random(step.body.seed).randbytes(step.body.size)
            headers["Content-Type"] = "application/octet-stream"
        elif step.body is not None:
            data = json.dumps(step.body).encode()
            headers["Content-Type"] = "application/json"
        if step.token:
            headers["Authorization"] = f"Bearer {step.token}"
        req = urllib.request.Request(self.target + step.path, data=data, headers=headers, method=step.method)
        start = rec.begin()
        status, outcome, error, payload, nbytes = None, "ok", None, None, 0
        try:
            with self.opener(req, timeout=TIMEOUT_S) as response:
                status = response.status
                raw = response.read()  # Whole bodies: documents reach 8 MiB, static files 2 MiB.
                nbytes = len(raw)
                if "application/json" in response.headers.get("Content-Type", ""):
                    payload = json.loads(raw)
                if not 200 <= status < 300:
                    outcome = "http_error"
        except urllib.error.HTTPError as exc:
            status, outcome, error = exc.code, "http_error", f"HTTPError: {exc}"
            try:
                nbytes = len(exc.read())
            except (OSError, ValueError, AttributeError, http.client.HTTPException):
                pass
        except (OSError, ValueError, http.client.HTTPException) as exc:
            outcome, error = classify(exc)
        end_mono, end_wall = rec.clock.mono(), rec.clock.wall()
        elapsed, route = end_mono - start[0], step.path.split("?")[0]
        self.metrics.record(step.method, STATUS_ROUTES.get(step.step, route), status, outcome, error, elapsed,
                            step.intended_status)
        rec.end(start, {"type": "request", "session_id": rec.args.session_id, "run_id": rec.run_id, "rid": rid,
                        "worker": n, "worker_seq": seq, "interval": start[3].index, "phase": start[4],
                        "method": step.method, "route": route, "status": status, "outcome": outcome, "error": error,
                        "t_start_utc": utc(start[1]), "t_end_utc": utc(end_wall),
                        "t_start_mono": round(start[2], 6), "t_end_mono": round(end_mono - rec.origin, 6),
                        "duration_ms": round(elapsed * 1000, 3), "response_bytes": nbytes,
                        "user_session": user_session, "step": step.step, "object": step.object,
                        "intended_status": step.intended_status, "think_s": step.think_s})
        return Reply(status, outcome, payload, round(end_mono - rec.origin, ROUND))


class OpenLoop:
    """The scheduler of a v5 run: offers every arrival at its time, admits it while fewer than max_concurrent user
    sessions are in progress (else drops it), and sends each step of a user session after its think time, counted
    from the end of the step before. Only its own thread changes its state; the requests run through `submit` (a
    thread pool; a test passes a synchronous call) and come back as replies."""

    def __init__(self, run, recorder, client, stop, submit, clock=CLOCK):
        self.run, self.recorder, self.client, self.stop, self.submit, self.clock = (run, recorder, client, stop,
                                                                                     submit, clock)
        self.cond = threading.Condition()
        self.heap = [(t, n, "arrival", n, None) for n, t in enumerate(run.arrivals)]
        heapq.heapify(self.heap)
        self.order = itertools.count(len(run.arrivals))  # Ties of time keep the order of scheduling.
        self.replies, self.sessions, self.pending, self.counts = deque(), {}, 0, Counter()

    def wake(self):
        with self.cond:
            self.cond.notify_all()

    def serve(self):
        try:
            self._serve()
        except Exception as exc:  # a dead scheduler would end the load model silently: report it and stop the run
            with self.recorder.lock:
                self.recorder.worker_errors += 1
            print(f"host_traffic: scheduler failed: {exc!r}", file=sys.stderr, flush=True)
            self.stop.set()
            self.recorder.wake.set()

    def _serve(self):
        while True:
            with self.cond:
                while True:
                    if self.stop.is_set():
                        return
                    if self.replies:
                        replies, due = list(self.replies), []
                        self.replies.clear()
                        break
                    if not self.heap and not self.pending:
                        return  # Every arrival was offered and every admitted user session is done.
                    now = self.recorder.now()
                    if self.heap and self.heap[0][0] <= now:
                        replies, due = [], []
                        while self.heap and self.heap[0][0] <= now:
                            due.append(heapq.heappop(self.heap))
                        break
                    self.clock.wait(self.cond, self.heap[0][0] - now if self.heap else None)
            for n, reply in replies:
                self._reply(n, reply)
            for item in due:
                self._due(item)

    def _due(self, item):
        _, _, kind, n, step = item
        if kind == "arrival":
            active = len(self.sessions)
            admitted = active < self.run.cap
            self.recorder.arrival(n, admitted, active)
            self.counts["arrivals"] += 1
            self.counts["admitted" if admitted else "dropped"] += 1
            if not admitted:
                return
            self.sessions[n] = PROFILES[self.run.profile](self.run.params, self.run.intensity, n, self.run.seeds,
                                                          self.run.lab, self.recorder.run_id)
            try:
                step = self.sessions[n].start()
            except Exception as exc:  # noqa: BLE001 - a broken state machine is a worker error
                return self._fail(n, exc)
        self._send(n, step)

    def _send(self, n, step):
        session = self.sessions[n]
        seq, session.seq = session.seq, session.seq + 1
        self.pending += 1
        self.submit(self._execute, n, seq, step)

    def _execute(self, n, seq, step):
        """In the pool: one request; its reply (None when the run stopped before it was sent) goes back."""
        try:
            reply = None if self.stop.is_set() else self.client.request(n, seq, step)
        except Exception as exc:  # noqa: BLE001 - reported by the scheduler as a worker error
            reply = exc
        with self.cond:
            self.replies.append((n, reply))
            self.cond.notify()

    def _reply(self, n, reply):
        self.pending -= 1
        if reply is None:
            return  # Not sent: the run stops and the user session stays in progress.
        if isinstance(reply, Exception):
            return self._fail(n, reply)
        try:
            step = self.sessions[n].reply(reply)
        except Exception as exc:  # noqa: BLE001 - a broken state machine is a worker error
            return self._fail(n, exc)
        if step is None:
            self._end(n, "completed")
        else:
            heapq.heappush(self.heap, (reply.end_rel + step.think_s, next(self.order), "step", n, step))

    def _fail(self, n, exc):
        with self.recorder.lock:
            self.recorder.worker_errors += 1
        print(f"host_traffic: user session {n} failed: {exc!r}", file=sys.stderr, flush=True)
        self._end(n, "failed")

    def _end(self, n, how):
        del self.sessions[n]
        self.counts[how] += 1
        self.recorder.session_end(len(self.sessions))

    def status(self):
        """Counts for the status file (read by the main thread while the scheduler runs)."""
        return {"arrivals": self.counts["arrivals"], "admitted": self.counts["admitted"],
                "dropped": self.counts["dropped"], "active": len(self.sessions),
                "user_sessions_completed": self.counts["completed"]}

    def end_fields(self):
        """The user session counts of the end records (design B5b 1.4); admitted = user_sessions_completed +
        user_sessions_in_progress_at_stop + the user sessions that failed (worker_errors)."""
        return {"arrivals": self.counts["arrivals"], "admitted": self.counts["admitted"],
                "dropped": self.counts["dropped"], "user_sessions_completed": self.counts["completed"],
                "user_sessions_in_progress_at_stop": len(self.sessions)}


# ------------------------------------------------------------------ command line


def _signals():
    """(stop, wake, pending): SIGINT/SIGTERM/SIGUSR1/SIGUSR2 are only recorded in pending."""
    stop, wake, pending = threading.Event(), threading.Event(), []

    def on_signal(signum, _frame):
        # Only record the signal. Event.set() takes a lock; a second signal landing
        # while the main thread holds that same lock (inside wake.wait/clear)
        # deadlocks it - observed with SIGUSR2 + SIGTERM sent back to back.
        pending.append(signum)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(sig, on_signal)
    return stop, wake, pending


def _open_logs(parser, args):
    files = {}
    try:
        for key, path in (("requests", args.requests_log), ("intervals", args.intervals_log)):
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                files[key] = open(path, "x")
    except OSError as exc:
        parser.error(f"cannot create log: {exc}")
    return files


def _write_status(path, result):
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(result, indent=2) + "\n")
        temp.replace(path)


def _drive(args, recorder, stop, wake, pending, save, dur=None):
    """The main thread: apply pending signals within SIGNAL_POLL_S, refresh the status every summary interval and
    return at `dur` (default --dur; 0: never) or on SIGINT/SIGTERM."""
    dur = args.dur if dur is None else dur
    next_save = time.monotonic()
    while not stop.is_set():
        if dur and time.monotonic() - recorder.origin >= dur:
            break
        wake.wait(SIGNAL_POLL_S)  # pending signals are applied within this poll period
        wake.clear()
        while pending:
            signum = pending.pop(0)
            if signum in (signal.SIGINT, signal.SIGTERM):
                stop.set()
            else:
                recorder.switch("measure" if signum == signal.SIGUSR1 else "post")
        if time.monotonic() >= next_save:
            recorder.tick()
            save()
            next_save = time.monotonic() + args.summary_interval_s


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", help="default http://192.168.122.100 (legacy and lab)")
    parser.add_argument("--dur", type=float, help="seconds; 0 = continuous (legacy and lab, default 120)")
    parser.add_argument("--seed", type=int, help="legacy and lab (default 1)")
    parser.add_argument("--vlakien", type=int, help="legacy and lab (default 8)")
    parser.add_argument("--burst", type=float, help="legacy and lab (default 1)")
    parser.add_argument("--profile", choices=["legacy", "lab", *PROFILES], default="legacy")
    parser.add_argument("--catalog-share", type=float, help="lab (default .5)")
    parser.add_argument("--write-share", type=float, help="lab (default .2)")
    parser.add_argument("--protocol", type=Path, help="v5: the protocol file (schema 3) with the profiles section")
    parser.add_argument("--scenario", help="v5: a scenario of the protocol, of this profile")
    parser.add_argument("--seeds", help="v5: JSON object with at least the seeds " + ", ".join(V5_SEEDS))
    parser.add_argument("--rate", type=float, help="v5: user sessions per second at envelope level 1, required "
                                                   "exactly when the scenario's rate is null")
    parser.add_argument("--warmup-s", type=float, help="v5: the ramp lies in [0, W], wave and peak in [W, dur]")
    parser.add_argument("--out", type=Path, help="atomic JSON status, refreshed every summary interval")
    parser.add_argument("--session-id", help="recorded in every log record and the status file")
    parser.add_argument("--requests-log", type=Path, help="JSONL per-request log, created exclusively")
    parser.add_argument("--intervals-log", type=Path, help="JSONL per-interval log, created exclusively")
    parser.add_argument("--summary-interval-s", type=float, help="interval length and status refresh (default 5)")
    parser.add_argument("--initial-phase", choices=PHASES,
                        help="phase until SIGUSR1 (measure) / SIGUSR2 (post) arrives (legacy default measure)")
    args = parser.parse_args(argv)
    if args.profile in PROFILES:
        try:
            run = prepare_v5(args)
        except ValueError as error:
            parser.error(str(error))
        return main_v5(parser, args, run)
    given = [name for name in V5_OPTIONS if getattr(args, name) is not None]
    if given:
        parser.error(f"--{given[0].replace('_', '-')} is an option of the v5 profiles {', '.join(PROFILES)} only")
    for name, default in {**LEGACY_OPTIONS, **STATED}.items():
        if getattr(args, name) is None:
            setattr(args, name, default)
    if not math.isfinite(args.dur) or args.dur < 0 or not 1 <= args.vlakien <= 64 or not 0 <= args.burst <= 1:
        parser.error("Require duration >= 0, 1..64 workers and burst in [0,1]")
    if not (0 <= args.catalog_share <= .95 and 0 <= args.write_share <= .95
            and args.catalog_share + args.write_share <= .95):
        parser.error("catalog-share + write-share must be <= .95 and nonnegative")
    if not .01 <= args.summary_interval_s <= 3600:
        parser.error("summary-interval-s must be in [0.01, 3600]")
    if bool(args.requests_log) != bool(args.intervals_log):
        parser.error("--requests-log and --intervals-log must be given together")
    stop, wake, pending = _signals()
    files = _open_logs(parser, args)
    recorder = Recorder(args, stop, files, wake)
    metrics = Metrics(recorder.origin, utc(recorder.origin_wall))
    clients = [Client(args.target, index, metrics, recorder) for index in range(args.vlakien)]
    threads = [threading.Thread(target=run_worker, args=(args, index, stop, clients[index]))
               for index in range(args.vlakien)]

    def save(final=False):
        result = metrics.snapshot()
        result.update(target=args.target, profile=args.profile, seed=args.seed, workers=args.vlakien, final=final,
                      session_id=args.session_id, run_id=recorder.run_id, phase=recorder.phase,
                      requests_logged=recorder.requests_logged(), logging_error=recorder.error,
                      log_backpressure_s=round(recorder.blocked_s, 3), worker_errors=recorder.worker_errors,
                      requests_log=str(args.requests_log) if args.requests_log else None,
                      intervals_log=str(args.intervals_log) if args.intervals_log else None)
        _write_status(args.out, result)
        return result

    print(f"host_traffic: {args.vlakien} workers -> {args.target} ({args.profile}) run_id={recorder.run_id} "
          f"session={args.session_id!r} phase={recorder.phase}", flush=True)
    for thread in threads:
        thread.start()
    try:
        _drive(args, recorder, stop, wake, pending, save)
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        recorder.close()
        result = save(final=True)
        print(json.dumps(result), flush=True)
    if recorder.error:
        return 3
    return 0 if result["errors"] == 0 and result["ok"] > 0 else 1


def main_v5(parser, args, run):
    """A v5 run: the open loop until SIGTERM or SIGINT; exit 0 when every request got its expected result.

    The arrivals are planned over [0, --dur] and none comes after it; the user sessions in progress finish. The run
    does not end at --dur: the runner stops it after the measured phase, whose end lies some seconds after
    warmup_s + cycles x interval_s (the collector starts after the warmup), so the envelope spans the planned
    measured hour and the post phase is the runner's."""
    if not .01 <= args.summary_interval_s <= 3600:
        parser.error("summary-interval-s must be in [0.01, 3600]")
    stop, wake, pending = _signals()
    files = _open_logs(parser, args)
    recorder = SessionRecorder(args, run, stop, files, wake)
    metrics = SessionMetrics(recorder.origin, utc(recorder.origin_wall))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=run.cap, thread_name_prefix="user-session")
    loop = OpenLoop(run, recorder, UserClient(args.target, metrics, recorder), stop, pool.submit)
    scheduler = threading.Thread(target=loop.serve, name="scheduler")

    def save(final=False):
        result = metrics.snapshot()
        result.update(target=args.target, profile=run.profile, scenario=run.scenario, seed=run.seeds["traffic"],
                      rate=run.rate, final=final, session_id=args.session_id, run_id=recorder.run_id,
                      phase=recorder.phase, requests_logged=recorder.requests_logged(), logging_error=recorder.error,
                      log_backpressure_s=round(recorder.blocked_s, 3), worker_errors=recorder.worker_errors,
                      requests_log=str(args.requests_log), intervals_log=str(args.intervals_log), **loop.status())
        _write_status(args.out, result)
        return result

    print(f"host_traffic: {run.profile} open loop, {len(run.arrivals)} planned arrivals at {run.rate} user "
          f"sessions/s at level 1 -> {args.target} run_id={recorder.run_id} session={args.session_id!r} "
          f"phase={recorder.phase}", flush=True)
    scheduler.start()
    try:
        _drive(args, recorder, stop, wake, pending, save, dur=0)
    finally:
        stop.set()
        loop.wake()
        scheduler.join()
        pool.shutdown(wait=True, cancel_futures=True)
        recorder.close(loop.end_fields())
        result = save(final=True)
        print(json.dumps(result), flush=True)
    if recorder.error:
        return 3
    return 0 if result["unexpected_results"] == 0 and result["ok"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
