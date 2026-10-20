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
"""
import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import http.client
import json
import math
import os
from pathlib import Path
import platform
import queue
import random
import signal
import socket
import sys
import threading
import time
import urllib.error
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
TIMEOUT_S = 4
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
        self.lock = threading.Lock()
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
    """Single log writer: numbers records per file, flushes every second, fsyncs every ~5 s."""
    def __init__(self, files, items, fail):
        super().__init__(name="log-writer", daemon=True)
        self.files, self.items, self.fail = files, items, fail
        self.schemas = {"requests": REQUEST_SCHEMA, "intervals": INTERVAL_SCHEMA}
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
        last_flush = last_sync = time.monotonic()
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
                fsync = now - last_sync >= 5
                self.guard(self._sync, fsync)
                last_flush, last_sync = now, now if fsync else last_sync

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


class Recorder:
    """Phase and interval bookkeeping plus JSONL logging shared by all workers."""
    def __init__(self, args, stop, files=None, wake=None):
        self.args, self.stop, self.wake = args, stop, wake or threading.Event()
        self.run_id = uuid.uuid4().hex[:12]
        self.lock = threading.Lock()
        self.origin, self.origin_wall = time.monotonic(), time.time()
        self.phase, self.interval_s = args.initial_phase, args.summary_interval_s
        self.intervals = deque([Interval(0, 0.0, self.interval_s, self.phase)])
        self.started = self.completed = self.worker_errors = self.write_errors = 0
        self.outcomes, self.blocked_s, self.error = Counter(), 0.0, None
        self.queue, self.writer = queue.Queue(maxsize=QUEUE_SIZE), None
        if files:
            self.writer = Writer(files, self.queue, self.fail)
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
            current = Interval(current.index + 1, current.end, current.end + self.interval_s, self.phase)
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
            mono, wall = time.monotonic(), time.time()
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
            mono, wall = time.monotonic(), time.time()
            rel = mono - self.origin
            self._roll(rel)
            current = self.intervals[-1]
            if current.start < rel or current.in_flight or current.counts["requests"]:
                current.closed, current.end = True, rel
                current = Interval(current.index + 1, rel, rel + self.interval_s, phase)
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
            self._roll(time.monotonic() - self.origin)
            ready = self._ready()
        for record in ready:
            self.put("intervals", record)

    def close(self):
        """After the workers stopped: close coverage at stop time, emit everything, write end records."""
        with self.lock:
            mono, wall = time.monotonic(), time.time()
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
                   "phase": self.phase, "end_utc": utc(wall), "end_mono": round(rel, 6)}
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="http://192.168.122.100")
    parser.add_argument("--dur", type=float, default=120, help="seconds; 0 = continuous")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--vlakien", type=int, default=8)
    parser.add_argument("--burst", type=float, default=1)
    parser.add_argument("--profile", choices=["legacy", "lab"], default="legacy")
    parser.add_argument("--catalog-share", type=float, default=.5)
    parser.add_argument("--write-share", type=float, default=.2)
    parser.add_argument("--out", type=Path, help="atomic JSON status, refreshed every summary interval")
    parser.add_argument("--session-id", default="", help="recorded in every log record and the status file")
    parser.add_argument("--requests-log", type=Path, help="JSONL per-request log, created exclusively")
    parser.add_argument("--intervals-log", type=Path, help="JSONL per-interval log, created exclusively")
    parser.add_argument("--summary-interval-s", type=float, default=5, help="interval length and status refresh")
    parser.add_argument("--initial-phase", choices=PHASES, default="measure",
                        help="phase until SIGUSR1 (measure) / SIGUSR2 (post) arrives")
    args = parser.parse_args(argv)
    if not math.isfinite(args.dur) or args.dur < 0 or not 1 <= args.vlakien <= 64 or not 0 <= args.burst <= 1:
        parser.error("Require duration >= 0, 1..64 workers and burst in [0,1]")
    if not (0 <= args.catalog_share <= .95 and 0 <= args.write_share <= .95
            and args.catalog_share + args.write_share <= .95):
        parser.error("catalog-share + write-share must be <= .95 and nonnegative")
    if not .01 <= args.summary_interval_s <= 3600:
        parser.error("summary-interval-s must be in [0.01, 3600]")
    if bool(args.requests_log) != bool(args.intervals_log):
        parser.error("--requests-log and --intervals-log must be given together")
    stop, wake, pending = threading.Event(), threading.Event(), []

    def on_signal(signum, _frame):
        # Only record the signal. Event.set() takes a lock; a second signal landing
        # while the main thread holds that same lock (inside wake.wait/clear)
        # deadlocks it - observed with SIGUSR2 + SIGTERM sent back to back.
        pending.append(signum)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(sig, on_signal)
    files = {}
    try:
        for key, path in (("requests", args.requests_log), ("intervals", args.intervals_log)):
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                files[key] = open(path, "x")
    except OSError as exc:
        parser.error(f"cannot create log: {exc}")
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
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            temp = args.out.with_suffix(args.out.suffix + ".tmp")
            temp.write_text(json.dumps(result, indent=2) + "\n")
            temp.replace(args.out)
        return result

    print(f"host_traffic: {args.vlakien} workers -> {args.target} ({args.profile}) run_id={recorder.run_id} "
          f"session={args.session_id!r} phase={recorder.phase}", flush=True)
    for thread in threads:
        thread.start()
    try:
        next_save = time.monotonic()
        while not stop.is_set():
            if args.dur and time.monotonic() - recorder.origin >= args.dur:
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


if __name__ == "__main__":
    raise SystemExit(main())
