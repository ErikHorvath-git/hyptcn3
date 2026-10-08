#!/usr/bin/env python3
"""Host-to-VM HTTP traffic. --profile lab drives the persistent demo services.

Legacy paths remain compatible with experiment manifests. --dur 0 runs until
SIGTERM. JSON metrics count HTTP failures and use actual elapsed wall time.
"""
import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import random
import signal
import threading
import time
import urllib.error
import urllib.request

CESTY = ["/auth", "/orders", "/", "/auth?u=%d", "/orders?page=%d"]


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.ok = self.errors = 0
        self.statuses, self.paths = Counter(), Counter()
        self.latencies = deque(maxlen=10000)
        self.last_error = None

    def record(self, method, path, status, elapsed, error=None):
        with self.lock:
            if 200 <= status < 300 and error is None:
                self.ok += 1
            else:
                self.errors += 1
                self.last_error = error or f"HTTP {status}"
            self.statuses[str(status)] += 1
            self.paths[f"{method} {path.split('?')[0]}"] += 1
            self.latencies.append(elapsed * 1000)

    def snapshot(self):
        with self.lock:
            elapsed = time.monotonic() - self.started
            latencies = sorted(self.latencies)
            return {"schema": "hyptcn3/host-traffic/2", "started_at": self.started_at,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "elapsed_s": round(elapsed, 3), "ok": self.ok, "errors": self.errors,
                    "requests": self.ok + self.errors, "ok_per_s": round(self.ok / max(elapsed, .001), 3),
                    "status_codes": dict(self.statuses), "routes": dict(self.paths),
                    "latency_sample_n": len(latencies),
                    "latency_p95_ms": round(latencies[math.ceil(.95 * len(latencies)) - 1], 3) if latencies else None,
                    "last_error": self.last_error}


def request(target, path, metrics, method="GET", body=None, token=""):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "User-Agent": "hyptcn-host-traffic/2"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(target.rstrip("/") + path, data=data, headers=headers, method=method)
    started, status, error, payload = time.monotonic(), 0, None, None
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            status = response.status
            raw = response.read(1024 * 1024)
            if "application/json" in response.headers.get("Content-Type", ""):
                payload = json.loads(raw)
    except urllib.error.HTTPError as exc:
        status, error = exc.code, str(exc)
    except (OSError, ValueError) as exc:
        error = str(exc)
    metrics.record(method, path, status, time.monotonic() - started, error)
    return payload


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
                if choice < .5:
                    request(args.target, "/api/catalog", metrics)
                elif choice < .75:
                    request(args.target, "/api/orders", metrics, token=token)
                elif choice < .95:
                    request(args.target, "/api/orders", metrics, "POST",
                            {"product_id": rng.randint(1, 5), "quantity": rng.randint(1, 3)}, token)
                else:
                    request(args.target, "/healthz", metrics)
        stop.wait(rng.uniform(.15, .6) if burst else rng.uniform(.5, 1.5))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://192.168.122.100")
    parser.add_argument("--dur", type=float, default=120, help="seconds; 0 = continuous")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--vlakien", type=int, default=8)
    parser.add_argument("--burst", type=float, default=1)
    parser.add_argument("--profile", choices=["legacy", "lab"], default="legacy")
    parser.add_argument("--out", type=Path, help="atomic JSON metrics, refreshed every 5 seconds")
    args = parser.parse_args(argv)
    if not math.isfinite(args.dur) or args.dur < 0 or not 1 <= args.vlakien <= 64 or not 0 <= args.burst <= 1:
        parser.error("Require duration >= 0, 1..64 workers and burst in [0,1]")
    stop, metrics = threading.Event(), Metrics()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    threads = [threading.Thread(target=worker, args=(args, index, stop, metrics)) for index in range(args.vlakien)]

    def save(final=False):
        result = metrics.snapshot()
        result.update(target=args.target, profile=args.profile, seed=args.seed,
                      workers=args.vlakien, final=final)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            temp = args.out.with_suffix(args.out.suffix + ".tmp")
            temp.write_text(json.dumps(result, indent=2) + "\n")
            temp.replace(args.out)
        return result

    print(f"host_traffic: {args.vlakien} workers -> {args.target} ({args.profile})", flush=True)
    for thread in threads:
        thread.start()
    try:
        while not stop.is_set():
            remaining = args.dur - (time.monotonic() - metrics.started) if args.dur else 5
            if remaining <= 0:
                break
            stop.wait(min(5, remaining))
            save()
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        result = save(final=True)
        print(json.dumps(result), flush=True)
    return 0 if result["errors"] == 0 and result["ok"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
