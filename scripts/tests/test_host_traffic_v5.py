"""The open-loop generator of protocol v5 (package B5b): profiles eshop and corp of scripts/host_traffic.py.

The column "Hotové, keď" of B5 (docs/HARNESS_V5.sk.md chapter 3: unit tests of the generator) and the lead's skeleton
dokazy/B5/kostra/KOSTRA.md section 5 items 1 and 2, against the design dokazy/B5/navrh/NAVRH_B5b.md 1.1 to 1.4:

- the envelope and the arrivals: the logged envelope is the one drawn (ramp, slow wave, one peak of level 1,
  peak-to-mean at least the protocol's), the arrival count matches its integral, the login wave of corp;
- the open loop on a fake clock and a fake HTTP layer: the same seeds give the same run, an arrival over the cap is
  dropped and logged, offered = admitted + dropped in every record that counts them;
- the state machines on 10 000 user sessions: the order share, the think time (mean and cut), the share of the top
  tenth of objects, the deliberate client errors, the corp actions and upload sizes;
- the profiles section the generator reads (each malformed value has its named reason) and the command line of 1.3
  (each refusal exits 2 with its named reason);
- one real run against a local fake lab whose logs are exactly 1.4 (every field, both schemas).

Expected values are counted here from the parameters (Poisson, binomial and Zipf laws), never by the product code.
Names package B5b adds are imported inside the tests and helpers, so this file collects on the code before B5b.
"""
from collections import Counter
import hashlib
import io
import json
import math
from pathlib import Path
import random
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import urllib.error
from urllib.parse import parse_qs, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host_traffic.py"
V5 = ROOT / "config/collection-v5.json"
SEEDS = {"traffic": 11, "traffic_arrivals": 12, "traffic_choices": 13, "traffic_sizes": 14}
JSON_TYPE = "application/json"
REPORT = "20261122T120000000000Z-0123abcd"  # The form of a report id of lab/services.py (REPORT_ID).
STEPS = {"eshop": {"home", "browse", "search", "detail", "static", "login", "cart_add", "cart", "order"},
         "corp": {"login", "doc_list", "doc_get", "doc_put", "report", "report_status"}}
# Design B5b 1.4: today's fields of each record type (scripts/host_traffic.py before B5b) and what v5 adds.
TODAY = {
    "header": {"schema", "n", "type", "session_id", "run_id", "generator", "config", "python", "hostname", "pid",
               "start_utc", "start_unix", "mono_origin", "latency_definition", "phase_assignment",
               "interval_assignment", "load_model", "outcome_definition", "time_definition"},
    "request": {"schema", "n", "type", "session_id", "run_id", "rid", "worker", "worker_seq", "interval", "phase",
                "method", "route", "status", "outcome", "error", "t_start_utc", "t_end_utc", "t_start_mono",
                "t_end_mono", "duration_ms", "response_bytes"},
    "interval": {"schema", "n", "type", "interval", "phase", "t_start_utc", "t_end_utc", "mono_start", "mono_end",
                 "duration_s", "requests", "ok", "http_error", "timeout", "transport_error", "status_codes", "routes",
                 "route_errors", "throughput_rps", "ok_rps", "sum_ms", "min_ms", "max_ms", "hist", "hist_ok"},
    "end": {"schema", "n", "type", "requests_started", "requests_completed", "ok", "http_error", "timeout",
            "transport_error", "in_flight_at_stop", "worker_errors", "log_backpressure_s", "phase", "end_utc",
            "end_mono", "records", "requests_logged", "write_errors", "clean"},
    "phase": {"schema", "n", "type", "phase", "previous", "t_utc", "t_mono", "interval"},
}
ADDED = {
    # concurrency: section 2 of the design asks the header to record one thread per user session or a pool.
    "header": {"profile", "scenario", "intensity", "rate", "rate_source", "seeds", "protocol_sha256",
               "profile_parameters", "warmup_s", "envelope", "concurrency"},
    "request": {"user_session", "step", "object", "intended_status", "think_s"},
    "interval": {"offered_sessions", "admitted_sessions", "dropped_sessions", "planned_sessions", "active_max"},
    "end": {"arrivals", "admitted", "dropped", "user_sessions_completed", "user_sessions_in_progress_at_stop"},
    "phase": set(),
}
ARRIVAL = {"schema", "n", "type", "user_session", "t_mono", "t_utc", "phase", "admitted", "active"}
LOAD_MODEL = ("open loop: user sessions arrive as a non-homogeneous Poisson process with intensity rate x "
              "envelope(t), at most max_concurrent in progress")


def v5_doc():
    return json.loads(V5.read_text())


def write_doc(tmp_path, doc, name="protocol.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc, indent=2))
    return path


# ------------------------------------------------------------------ a fake lab: the routes of lab/services.py

def lab_answer(method, path, query, auth, body):
    """(status, content type, body) of the fake lab: what lab/services.py and lab/nginx.conf answer to the requests
    of both profiles, the deliberate client errors with their status."""
    from lab import seed
    reply = lambda status, doc: (status, JSON_TYPE, json.dumps(doc).encode())  # noqa: E731
    page = int(query.get("page", ["1"])[0])
    if (method, path) == ("GET", "/"):
        return reply(200, {"lab": "fake"})
    if method == "GET" and path == "/api/catalog":
        return reply(400, {"error": "page"}) if page < 1 else reply(200, {"products": [{"id": 1}] * 20})
    if method == "GET" and path.startswith("/api/catalog/"):
        known = 1 <= int(path.rsplit("/", 1)[1]) <= seed.SIZES["products"]
        return reply(200, {"id": 1, "name": "x"}) if known else reply(404, {"error": "unknown product"})
    if method == "GET" and path.startswith("/static/"):
        return 200, "text/css", b"s" * 3000
    if (method, path) == ("POST", "/api/auth/token"):
        return reply(200, {"token": "c-token"})
    if (method, path) == ("POST", "/api/auth/login"):
        doc = json.loads(body)
        good = doc["password"] == seed.employee_password(doc["user"])
        return reply(200, {"token": "e-token"}) if good else reply(401, {"error": "wrong user or password"})
    if path in ("/api/cart", "/api/orders"):
        if auth != "Bearer c-token":
            return reply(401, {"error": "upstream rejected request"})
        return reply(201 if (method, path) == ("POST", "/api/orders") else 200, {"items": []})
    if path == "/api/docs" or path.startswith(("/api/docs/", "/api/reports")):
        if auth != "Bearer e-token":
            return reply(401, {"error": "upstream rejected request"})
        if (method, path) == ("GET", "/api/docs"):
            return reply(400, {"error": "page"}) if page < 1 else reply(200, {"documents": []})
        if (method, path) == ("POST", "/api/docs"):
            return reply(201, {"id": 501, "bytes": len(body)})
        if method == "GET" and path.startswith("/api/docs/"):
            known = 1 <= int(path.rsplit("/", 1)[1]) <= seed.SIZES["documents"]
            if not known:
                return reply(404, {"error": "unknown document"})
            return 200, "application/octet-stream", b"d" * 5000
        if (method, path) == ("POST", "/api/reports"):
            return reply(202, {"report": REPORT, "status": "queued"})
        if method == "GET" and path.startswith("/api/reports/"):
            return reply(200, {"report": path.rsplit("/", 1)[1], "status": "queued"})
    return reply(404, {"error": "unknown route"})


class FakeResponse:
    def __init__(self, status, content_type, body):
        self.status, self.headers, self.body = status, {"Content-Type": content_type}, body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _limit=-1):
        return self.body


def fake_opener(req, timeout=None):
    """urllib.request.urlopen of the fake lab: answers at once, a 4xx as urllib raises it."""
    split = urlsplit(req.full_url)
    status, content_type, body = lab_answer(req.get_method(), split.path, parse_qs(split.query),
                                            req.get_header("Authorization"), req.data)
    if status >= 400:
        raise urllib.error.HTTPError(req.full_url, status, "fake", {"Content-Type": content_type}, io.BytesIO(body))
    return FakeResponse(status, content_type, body)


class FakeClock:
    """Simulated time from 0: wait() jumps to the next scheduled time at once; at `limit` it stops the run as the
    main loop does at --dur; `events` [(time, callback)] run when time reaches them (the phase signals)."""

    def __init__(self, limit, stop, events=()):
        self.now, self.limit, self.stop, self.events = 0.0, limit, stop, sorted(events, key=lambda e: e[0])

    def mono(self):
        return self.now

    def wall(self):
        return 1.8e9 + self.now

    def wait(self, cond, timeout):
        assert timeout is not None  # The fake lab answers at once: nothing is ever in flight while waiting.
        target = self.now + timeout
        if self.events and self.events[0][0] <= min(target, self.limit):
            when, callback = self.events.pop(0)
            self.now = max(self.now, when)
            callback()
        elif target >= self.limit:
            self.now = self.limit
            self.stop.set()
        else:
            self.now = target


def v5_args(tmp_path, protocol, profile="eshop", scenario="eshop_low", **changes):
    """The namespace of a v5 command line (design B5b 1.3) as main() parses it."""
    args = dict(profile=profile, protocol=protocol, scenario=scenario, seeds=json.dumps(SEEDS), rate=1.0,
                target="http://lab.invalid", dur=1320.0, warmup_s=120.0, session_id="S-v5",
                requests_log=tmp_path / "requests.jsonl", intervals_log=tmp_path / "intervals.jsonl",
                summary_interval_s=5.0, initial_phase="warmup", out=tmp_path / "status.json",
                vlakien=None, burst=None, catalog_share=None, write_share=None, seed=None)
    args.update(changes)
    return SimpleNamespace(**args)


def fake_run(tmp_path, profile="eshop", scenario="eshop_low", cap=None, **changes):
    """One v5 run on the fake clock and the fake lab: the real prepare_v5, SessionRecorder, UserClient and OpenLoop,
    requests sent synchronously; the measure phase from warmup_s, post 60 s before the end. Returns (run, request
    records, interval records)."""
    from scripts import host_traffic as ht
    tmp_path.mkdir(parents=True, exist_ok=True)
    doc = v5_doc()
    if cap is not None:
        doc["profiles"][profile]["max_concurrent"] = cap
    args = v5_args(tmp_path, write_doc(tmp_path, doc), profile, scenario, **changes)
    run = ht.prepare_v5(args)
    stop = threading.Event()
    recorder = None
    clock = FakeClock(args.dur, stop, [(args.warmup_s, lambda: recorder.switch("measure")),
                                       (args.dur - 60, lambda: recorder.switch("post"))])
    files = {"requests": open(args.requests_log, "x"), "intervals": open(args.intervals_log, "x")}
    recorder = ht.SessionRecorder(args, run, stop, files, clock=clock)
    client = ht.UserClient(args.target, ht.SessionMetrics(0.0, "t0"), recorder, opener=fake_opener)
    loop = ht.OpenLoop(run, recorder, client, stop, lambda fn, *a: fn(*a), clock=clock)
    loop.serve()
    recorder.close(loop.end_fields())
    return run, records(args.requests_log), records(args.intervals_log)


def records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def integral(t, level, a, b):
    """The integral of the piecewise linear envelope over [a, b], 0 outside [t[0], t[-1]] (counted here)."""
    total = 0.0
    for x0, x1, y0, y1 in zip(t, t[1:], level, level[1:]):
        lo, hi = max(a, x0), min(b, x1)
        if lo < hi:
            at = lambda x: y0 + (y1 - y0) * (x - x0) / (x1 - x0)  # noqa: E731
            total += (at(lo) + at(hi)) / 2 * (hi - lo)
    return total


def level_at(t, level, x):
    for x0, x1, y0, y1 in zip(t, t[1:], level, level[1:]):
        if x0 <= x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return 0.0


def peak_to_mean(t, level, a, b):
    """Maximum over mean of the envelope over [a, b] (a piecewise linear function peaks at a knot or an end)."""
    top = max([y for x, y in zip(t, level) if a <= x <= b] + [level_at(t, level, a), level_at(t, level, b)])
    return top / (integral(t, level, a, b) / (b - a))


def of_type(rows, kind):
    return [r for r in rows if r["type"] == kind]


# ------------------------------------------------------------------ the envelope and the arrivals (item 1)

@pytest.mark.parametrize("profile", ["eshop", "corp"])
def test_envelope_is_a_ramp_a_slow_wave_and_one_peak_of_level_1(profile):
    from scripts import host_traffic as ht
    a = v5_doc()["profiles"][profile]["arrivals"]
    warmup, dur = 120.0, 3720.0
    for seed in range(20):
        envelope, _ = ht.draw_envelope(a, random.Random(seed), dur, warmup, 2)
        t, level = envelope.t, envelope.level
        assert t[0] == 0 and t[-1] == dur and all(x < y for x, y in zip(t, t[1:]))
        assert min(level) >= 0 and max(level) == 1
        assert level[0] == 0 and t[1] == a["ramp_s"]  # The ramp: from 0 to the wave over [0, ramp_s].
        top = [x for x, y in zip(t, level) if y == 1]
        assert len(top) == 2 and warmup <= top[0] < top[1] <= dur  # The plateau of the one peak.
        assert peak_to_mean(t, level, warmup, dur) >= 2  # scenario_rule.min_peak_to_mean of the v5 file
        if profile == "corp":
            # The login wave: the peak starts where a cycle of the slow wave starts, at its lowest level.
            start = t.index(top[0]) - 1
            wave = [y for x, y in zip(t, level) if a["ramp_s"] <= x and not t[start] < x <= t[t.index(top[1]) + 1]]
            assert level[start] <= min(wave) + 1e-6


def test_envelope_is_drawn_again_until_peak_to_mean_holds():
    from scripts import host_traffic as ht
    a = v5_doc()["profiles"]["eshop"]["arrivals"]
    # Under the file's bound 2 a session's first draw passes (peak-to-mean 2.2 to 3.9 over an hour); under 3 about
    # half of the first draws fail and are drawn again.
    draws = [ht.draw_envelope(a, random.Random(seed), 3720.0, 120.0, 3) for seed in range(40)]
    assert max(d for _, d in draws) > 1 and all(peak_to_mean(e.t, e.level, 120.0, 3720.0) >= 3 for e, _ in draws)
    with pytest.raises(ValueError) as error:
        ht.draw_envelope(a, random.Random(1), 3720.0, 120.0, 50)
    assert str(error.value) == "no envelope with peak-to-mean >= 50 over [120.0, 3720.0] s in 1000 draws"


def test_arrivals_match_the_integral_of_the_envelope():
    """Inversion of rate x the integral: the count over [0, dur] and over each tenth of it is Poisson with the
    integral as its mean, and the spacings rescaled by the integral are unit exponential (CV 1)."""
    from scripts import host_traffic as ht
    envelope, _ = ht.draw_envelope(v5_doc()["profiles"]["eshop"]["arrivals"], random.Random(3), 3720.0, 120.0, 2)
    t, level, rate = envelope.t, envelope.level, 5.0
    arrivals = ht.arrival_times(envelope, rate, random.Random(4))
    expected = rate * integral(t, level, 0, 3720.0)
    assert abs(len(arrivals) - expected) <= 4 * math.sqrt(expected)
    assert arrivals == sorted(arrivals) and 0 <= arrivals[0] and arrivals[-1] < 3720.0
    for k in range(10):
        a, b = 372.0 * k, 372.0 * (k + 1)
        part = rate * integral(t, level, a, b)
        assert abs(sum(a <= x < b for x in arrivals) - part) <= 4 * math.sqrt(part)
    rescaled = [rate * integral(t, level, x0, x1) for x0, x1 in zip(arrivals, arrivals[1:])]
    mean = sum(rescaled) / len(rescaled)
    cv = math.sqrt(sum((x - mean) ** 2 for x in rescaled) / len(rescaled)) / mean
    assert abs(mean - 1) <= 4 / math.sqrt(len(rescaled)) and abs(cv - 1) <= .05
    assert ht.arrival_times(envelope, rate, random.Random(4)) == arrivals  # The same seed, the same arrivals.


# ------------------------------------------------------------------ the open loop on a fake clock (item 1)

def normalized(rows, run_id):
    """Records with the run id and the log paths taken out (they differ between two runs by design)."""
    out = json.loads(json.dumps(rows).replace(run_id, "RUN"))
    for row in out:
        if row["type"] == "header":
            row["config"].pop("requests_log")
            row["config"].pop("intervals_log")
            row["config"].pop("protocol")
        if row["type"] == "end":
            row.pop("log_backpressure_s")
    return out


@pytest.mark.parametrize("profile, scenario", [("eshop", "eshop_high"), ("corp", "corp_low")])
def test_same_seeds_give_the_same_run(tmp_path, profile, scenario):
    runs = [fake_run(tmp_path / str(i), profile, scenario, dur=720.0) for i in range(2)]
    (run, req_a, ivl_a), (_, req_b, ivl_b) = runs
    a = normalized(req_a + ivl_a, req_a[0]["run_id"])
    b = normalized(req_b + ivl_b, req_b[0]["run_id"])
    assert a == b and len(of_type(req_a, "request")) > 100
    _, req_c, _ = fake_run(tmp_path / "other", profile, scenario, dur=720.0,
                           seeds=json.dumps(dict(SEEDS, traffic_choices=99)))
    assert normalized(of_type(req_c, "request"), req_c[0]["run_id"]) != normalized(of_type(req_a, "request"),
                                                                                    req_a[0]["run_id"])
    # The arrivals were offered at exactly the planned times (the fake clock jumps to them).
    assert [r["t_mono"] for r in of_type(req_a, "arrival")] == run.arrivals


def test_arrivals_over_the_cap_are_dropped_and_logged(tmp_path):
    run, req, ivl = fake_run(tmp_path, "eshop", "eshop_low", cap=4, rate=2.0)
    arrivals, requests, end = of_type(req, "arrival"), of_type(req, "request"), req[-1]
    dropped = [a for a in arrivals if not a["admitted"]]
    assert dropped and len(dropped) < len(arrivals)
    assert all(a["admitted"] == (a["active"] < 4) and 0 <= a["active"] <= 4 for a in arrivals)
    assert [a["user_session"] for a in arrivals] == [f"{req[0]['run_id']}-u{n}" for n in range(len(arrivals))]
    admitted = {a["user_session"] for a in arrivals if a["admitted"]}
    assert {r["user_session"] for r in requests} == admitted  # A dropped user session sends nothing.
    # Offered = admitted + dropped: the arrival records, every interval and the end records agree.
    intervals = of_type(ivl, "interval")
    for iv in intervals:
        inside = [a for a in arrivals if iv["mono_start"] <= a["t_mono"] < iv["mono_end"]]
        assert iv["offered_sessions"] == len(inside) == iv["admitted_sessions"] + iv["dropped_sessions"]
        assert iv["dropped_sessions"] == sum(not a["admitted"] for a in inside)
        assert iv["active_max"] <= 4 and all(iv["active_max"] >= a["active"] + a["admitted"] for a in inside)
    for last in (end, ivl[-1]):
        assert last["arrivals"] == len(arrivals) == last["admitted"] + last["dropped"]
        assert (last["admitted"], last["dropped"]) == (len(admitted), len(dropped))
        assert last["admitted"] == last["user_sessions_completed"] + last["user_sessions_in_progress_at_stop"]
    planned = sum(iv["planned_sessions"] for iv in intervals)
    assert abs(planned - run.rate * integral(run.envelope.t, run.envelope.level, 0, 1320)) <= 1e-6 * len(intervals)
    assert {r["phase"] for r in arrivals} == {"warmup", "measure", "post"}


# ------------------------------------------------------------------ the state machines (item 2)

def drive(profile, params, intensity, sessions, answer=None, statuses=None):
    """The steps of `sessions` user sessions of a profile, every reply from the fake lab (or `answer`); the status
    of each step's reply is appended to `statuses` when given."""
    from scripts import host_traffic as ht
    lab, out = ht.Lab(profile, params), []
    for n in range(sessions):
        session = ht.PROFILES[profile](params, intensity, n, SEEDS, lab, "0123456789ab")
        steps, step = [], session.start()
        while step is not None:
            steps.append(step)
            reply = answer(step) if answer else reply_of(step)
            if statuses is not None:
                statuses.append(reply.status)
            step = session.reply(reply)
        out.append(steps)
    return out


def reply_of(step):
    from scripts import host_traffic as ht
    split = urlsplit(step.path)
    body = None if step.body is None else b"upload" if isinstance(step.body, ht.Upload) else json.dumps(
        step.body).encode()
    status, content_type, raw = lab_answer(step.method, split.path, parse_qs(split.query),
                                           f"Bearer {step.token}" if step.token else None, body)
    payload = json.loads(raw) if content_type == JSON_TYPE else None
    return ht.Reply(status, "ok" if 200 <= status < 300 else "http_error", payload, 0.0)


def top_tenth_share(objects):
    """The share of requests the most requested tenth of the objects requested gets (proposal 5.7)."""
    counts = sorted(Counter(objects).values(), reverse=True)
    return sum(counts[:math.ceil(len(counts) / 10)]) / len(objects)


def within(value, expected, n, p=None, sd=None):
    """value within 4 standard errors of `expected` (judgment: wide enough for any seed, narrow enough to see a wrong
    law): a binomial share p of n, or a mean of n values with the standard deviation sd."""
    error = math.sqrt(p * (1 - p) / n) if p is not None else sd / math.sqrt(n)
    return abs(value - expected) <= 4 * error


@pytest.mark.parametrize("intensity, think_max", [("low", 70), ("high", 70), ("low", 14)])
def test_eshop_on_10000_user_sessions(intensity, think_max):
    params = v5_doc()["profiles"]["eshop"]
    params["think_s"]["max"] = think_max  # 14 s: a cut that a seventh of the draws meet (e^-2), so the cut shows.
    statuses = []
    sessions = drive("eshop", params, intensity, 10000, statuses=statuses)
    steps = [s for steps in sessions for s in steps]
    share = params["order_share"][intensity]
    ordered = sum(any(s.step == "order" for s in steps) for steps in sessions)
    assert within(ordered / 10000, share, 10000, p=share)
    assert all(steps[0].step == "home" and steps[0].think_s is None for steps in sessions)
    assert all(s.step in STEPS["eshop"] for s in steps)
    thinks = [s.think_s for steps in sessions for s in steps[1:]]
    mean, cut = params["think_s"]["mean"], think_max
    assert all(s.think_s is not None for steps in sessions for s in steps[1:]) and max(thinks) <= cut
    expected = mean * (1 - math.exp(-cut / mean))  # The mean of min(Exp(mean), cut).
    assert within(sum(thinks) / len(thinks), expected, len(thinks), sd=mean)
    assert within(thinks.count(cut) / len(thinks), math.exp(-cut / mean), len(thinks), p=math.exp(-cut / mean))
    intended = [s for s in steps if s.intended_status is not None]
    assert within(len(intended) / len(steps), .02, len(steps), p=.02)
    assert {s.intended_status for s in intended} == {400, 401, 404}
    assert all(status == s.intended_status if s.intended_status else 200 <= status < 300  # As the lab answers.
               for s, status in zip(steps, statuses))
    for kind in ("detail", "static"):
        objects = [s.object for s in steps if s.step == kind and s.intended_status is None]
        assert top_tenth_share(objects) >= .5
    products = [s.object for s in steps if s.step == "detail" and s.intended_status is None]
    harmonic = sum(1 / k for k in range(1, 5001))  # Zipf s = 1 over the 5000 products of lab/seed.py
    assert within(products.count(1) / len(products), 1 / harmonic, len(products), p=1 / harmonic)


def test_corp_on_10000_user_sessions():
    params = v5_doc()["profiles"]["corp"]
    statuses = []
    sessions = drive("corp", params, "low", 10000, statuses=statuses)
    steps = [s for steps in sessions for s in steps]
    assert all(steps[0].step == "login" and steps[0].think_s is None for steps in sessions)
    assert all(s.step in STEPS["corp"] for s in steps)
    actions = [s.step for s in steps if s.intended_status is None and s.step not in ("login", "report_status")]
    for action, share in params["shares"].items():
        assert within(actions.count(action) / len(actions), share, len(actions), p=share)
    lows, highs = params["actions"]
    per_session = [sum(s.intended_status is None and s.step in params["shares"] for s in ss) for ss in sessions]
    assert min(per_session) == lows and max(per_session) == highs
    thinks = [s.think_s for ss in sessions for s in ss[1:]]
    t = params["think_s"]
    expected = t["mean"] * (1 - math.exp(-t["max"] / t["mean"]))  # The mean of min(Exp(mean), max).
    assert max(thinks) <= t["max"] and within(sum(thinks) / len(thinks), expected, len(thinks), sd=t["mean"])
    intended = [s for s in steps if s.intended_status is not None]
    assert within(len(intended) / len(steps), .02, len(steps), p=.02)
    assert {s.intended_status for s in intended} == {400, 401, 404}
    assert all(status == s.intended_status if s.intended_status else 200 <= status < 300  # As the lab answers.
               for s, status in zip(steps, statuses))
    reports = sum(s.step == "report" for s in steps)
    assert sum(s.step == "report_status" and s.object == REPORT for s in steps) == reports
    documents = [s.object for s in steps if s.step == "doc_get" and s.intended_status is None]
    assert top_tenth_share(documents) >= .5
    d = params["document_sizes"]
    sizes = sorted(s.body.size for s in steps if s.step == "doc_put")
    assert d["min_bytes"] <= sizes[0] and sizes[-1] <= d["max_bytes"]
    # A Pareto tail of tail_share from tail_from_bytes, the rest lognormal with its median and sigma.
    above = d["tail_share"] + (1 - d["tail_share"]) * .5 * math.erfc(math.log(d["tail_from_bytes"] / d["median_bytes"])
                                                                      / d["sigma"] / math.sqrt(2))
    tail = sum(size >= d["tail_from_bytes"] for size in sizes) / len(sizes)
    assert within(tail, above, len(sizes), p=above)


def test_a_reply_never_changes_the_draws():
    """With every request failing the same steps follow; only the status check of a report without an id is left
    out (with the deliberate error that may follow it)."""
    from scripts import host_traffic as ht
    fail = lambda step: ht.Reply(503, "http_error", None, 0.0)  # noqa: E731
    fields = lambda s: (s.step, s.method, s.path, s.object, s.intended_status, s.think_s)  # noqa: E731
    for profile in ("eshop", "corp"):
        params = v5_doc()["profiles"][profile]
        for good, bad in zip(drive(profile, params, "high", 300), drive(profile, params, "high", 300, fail)):
            kept = [s for i, s in enumerate(good) if s.step != "report_status"
                    and not (i and good[i - 1].step == "report_status" and s.intended_status is not None)]
            assert [fields(s) for s in kept] == [fields(s) for s in bad]


# ------------------------------------------------------------------ the profiles section and the lab register

def test_profiles_are_those_of_the_protocol_layout_and_of_the_lab():
    import ast
    from scripts import host_traffic as ht, protocol_v5
    assert set(ht.PROFILES) == set(protocol_v5.PROFILE_KEYS) == set(v5_doc()["profiles"]) == {"eshop", "corp"}
    assert protocol_v5.lab_names()["profile"] == {"eshop", "corp"}
    assert set(protocol_v5.PENDING_IN_LAB) & {"eshop", "corp"} == set()
    for profile in ht.PROFILES:  # Every status of the protocol has a deliberate error of each profile.
        params = v5_doc()["profiles"][profile]
        session = ht.PROFILES[profile](params, "low", 0, SEEDS, ht.Lab(profile, params), "0123456789ab")
        session.first, session.token = False, {"eshop": "c-token", "corp": "e-token"}[profile]  # After the login.
        for status in protocol_v5.CLIENT_STATUSES:
            step = session.wrong(status)
            assert step.intended_status == status and reply_of(step).status == status
    values = {}  # PAGE_SIZE, MAX_PAGE_SIZE, ... = 20, 100, ... in lab/services.py (it imports psycopg2: parse it).
    for node in ast.parse((ROOT / "lab/services.py").read_text()).body:
        names = [x.id for x in getattr(node.targets[0], "elts", [])] if isinstance(node, ast.Assign) else []
        if "MAX_PAGE_SIZE" in names:
            values.update(zip(names, map(ast.literal_eval, node.value.elts)))
    assert values["MAX_PAGE_SIZE"] == protocol_v5.MAX_PAGE_SIZE
    assert ht.SAFE_ID.fullmatch(REPORT)


def _set(path, value):
    def change(doc):
        node = doc
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return change


PROFILE_ERRORS = [  # (change of config/collection-v5.json, the named reason of profiles_problems)
    (_set(("scenarios", "corp_low", "profile"), "batch"),
     "scenarios.corp_low.profile: 'batch' is not a profile of the profiles section"),
    (_set(("profiles", "eshop", "arrivals", "ramp_s"), -1), "profiles.eshop.arrivals.ramp_s: not a number >= 0"),
    (_set(("profiles", "eshop", "arrivals", "ramp_s"), 121),
     "profiles.eshop.arrivals.ramp_s: longer than warmup_s: the ramp lies in the warmup"),
    (_set(("profiles", "corp", "arrivals", "wave_period_s"), [2400, 1200]),
     "profiles.corp.arrivals.wave_period_s: not [min, max] with 0 < min <= max"),
    (_set(("profiles", "eshop", "arrivals", "peak_s"), [0, 240]),
     "profiles.eshop.arrivals.peak_s: not [min, max] with 0 < min <= max"),
    (_set(("profiles", "eshop", "arrivals", "wave_amplitude"), [.2, 1]),
     "profiles.eshop.arrivals.wave_amplitude: not [min, max] with 0 <= min <= max < 1"),
    (_set(("profiles", "eshop", "arrivals", "wave_mean"), [.25, .7]),
     "profiles.eshop.arrivals.wave_mean: the slow wave reaches level 1, which only the peak has"),
    (_set(("profiles", "eshop", "arrivals", "peak_edge_share"), .5),
     "profiles.eshop.arrivals.peak_edge_share: not a number in (0, 0.5)"),
    (_set(("profiles", "corp", "arrivals", "peak_at"), "start"),
     "profiles.corp.arrivals.peak_at: not one of uniform, wave_start"),
    (_set(("profiles", "eshop", "arrivals", "step_s"), 0), "profiles.eshop.arrivals.step_s: not a number > 0"),
    (_set(("profiles", "eshop", "max_concurrent"), 0), "profiles.eshop.max_concurrent: not an integer >= 1"),
    (_set(("profiles", "eshop", "client_errors", "share"), .05),
     "profiles.eshop.client_errors.share: outside 1 to 3 % (proposal 5.3)"),
    (_set(("profiles", "corp", "client_errors", "statuses"), [400, 500]),
     "profiles.corp.client_errors.statuses: not distinct statuses of 400, 401, 404"),
    (_set(("profiles", "eshop", "think_s", "max"), 5), "profiles.eshop.think_s: not mean > 0 and max >= mean"),
    (_set(("profiles", "eshop", "zipf_s"), 0), "profiles.eshop.zipf_s: not a number > 0"),
    (_set(("profiles", "eshop", "order_share", "high"), 1), "profiles.eshop.order_share: not shares in (0, 1)"),
    (_set(("profiles", "eshop", "funnel", "pages"), [0, 4]),
     "profiles.eshop.funnel.pages: not integers [min, max] with 1 <= min <= max"),
    (_set(("profiles", "eshop", "funnel", "static_share"), 1.5),
     "profiles.eshop.funnel.static_share: not a share in [0, 1]"),
    (_set(("profiles", "eshop", "funnel", "page_size"), 101),
     "profiles.eshop.funnel.page_size: not an integer in 1..100"),
    (_set(("profiles", "corp", "actions"), [2.5, 8]),
     "profiles.corp.actions: not integers [min, max] with 1 <= min <= max"),
    (_set(("profiles", "corp", "shares", "report"), .2), "profiles.corp.shares: not shares in [0, 1] that sum to 1"),
    (_set(("profiles", "corp", "document_sizes", "sigma"), -1),
     "profiles.corp.document_sizes: not a lognormal body (median_bytes, sigma) with a Pareto tail (tail_share, "
     "tail_from_bytes, tail_alpha)"),
    (_set(("profiles", "corp", "document_sizes", "max_bytes"), 8388609),
     "profiles.corp.document_sizes: not integers 1 <= min_bytes <= max_bytes <= 8388608 (the upload cap of "
     "lab/services.py)"),
    (_set(("profiles", "corp", "note"), None), "profiles.corp.note: every note is a string"),
    (_set(("profiles", "corp", "think_s", "extra"), 1), "unknown protocol key: profiles.corp.think_s.extra"),
    (lambda doc: doc["profiles"]["eshop"].pop("funnel"), "missing protocol key: profiles.eshop.funnel"),
]


@pytest.mark.parametrize("change, reason", PROFILE_ERRORS, ids=[r for _, r in PROFILE_ERRORS])
def test_profiles_section_names_each_malformed_value(change, reason):
    from scripts import protocol_v5
    assert protocol_v5.profiles_problems(v5_doc()) == []
    doc = v5_doc()
    change(doc)
    assert protocol_v5.profiles_problems(doc) == [reason]


def test_plan_draws_the_traffic_streams_of_every_session_and_attempt():
    from scripts import protocol_v5
    doc = v5_doc()
    plan = protocol_v5.plan(doc)
    for s in plan["sessions"][:6]:
        for purpose in ("traffic", "traffic_arrivals", "traffic_choices", "traffic_sizes"):
            assert s["seeds"][purpose] == protocol_v5.seed(doc["name"], purpose, s["group"], s["position"], 1)
        again = protocol_v5.replacement(doc, s, 2)
        assert all(again["seeds"][p] == protocol_v5.seed(doc["name"], p, s["group"], s["position"], 2)
                   for p in ("traffic_arrivals", "traffic_choices", "traffic_sizes"))
    assert doc["streams"]["purposes"][-3:] == ["traffic_arrivals", "traffic_choices", "traffic_sizes"]


# ------------------------------------------------------------------ the command line of design 1.3

def command(tmp_path, **changes):
    """A good v5 command line (eshop_low, --rate, a measured hour after the warmup) with changes: a value replaces
    an option, None leaves it out, a list is appended."""
    options = {"--profile": "eshop", "--protocol": str(V5), "--scenario": "eshop_low", "--seeds": json.dumps(SEEDS),
               "--rate": "2", "--target": "http://127.0.0.1:9", "--dur": "3720", "--warmup-s": "120",
               "--session-id": "S", "--requests-log": str(tmp_path / "r.jsonl"),
               "--intervals-log": str(tmp_path / "i.jsonl"), "--summary-interval-s": "5",
               "--initial-phase": "warmup", "--out": str(tmp_path / "s.json")}
    extra = changes.pop("extra", [])
    options.update(changes)
    return [x for key, value in options.items() if value is not None for x in (key, value)] + extra


def protocol_with(tmp_path, change):
    doc = v5_doc()
    change(doc)
    return str(write_doc(tmp_path, doc, "changed.json"))


REFUSALS = [  # (changes of the good command line, protocol change or None, the named reason)
    *[({"extra": [flag, "1"]}, None, f"{flag} is not an option of profile eshop")
      for flag in ("--vlakien", "--burst", "--catalog-share", "--write-share", "--seed")],
    *[({flag: None}, None, f"profile eshop requires {flag}")
      for flag in ("--protocol", "--scenario", "--seeds", "--warmup-s", "--requests-log", "--intervals-log", "--out",
                   "--target", "--dur", "--session-id", "--summary-interval-s", "--initial-phase")],
    ({"--initial-phase": "post"}, None, "--initial-phase post is not a start phase of profile eshop"),
    ({"--dur": "0"}, None, "--dur must be a number > 0: the envelope spans [0, dur]"),
    ({"--warmup-s": "3720"}, None, "--warmup-s must lie in [0, --dur)"),
    ({"--protocol": "/nonexistent/protocol.json"}, None, "cannot read protocol: [Errno 2] No such file or directory"),
    ({}, _set(("schema",), "hyptcn3/collection-protocol/2"),
     "protocol schema is not hyptcn3/collection-protocol/3: the v5 profiles are its profiles section"),
    ({}, _set(("profiles", "eshop", "think_s", "max"), 5),
     "invalid profiles: profiles.eshop.think_s: not mean > 0 and max >= mean"),
    ({"--scenario": "nope"}, None, "unknown scenario: nope"),
    ({"--profile": "corp"}, None, "--profile corp differs from scenarios.eshop_low.profile eshop"),
    ({}, _set(("scenarios", "eshop_low", "intensity"), "medium"), "scenarios.eshop_low.intensity is not low or high"),
    ({"--rate": None}, None, "scenarios.eshop_low.rate is null: --rate is required"),
    ({}, _set(("scenarios", "eshop_low", "rate"), 2), "scenarios.eshop_low.rate is set by the protocol: --rate is "
                                                      "refused"),
    ({"--rate": "-1"}, None, "the rate (command line) is not a finite number > 0"),
    ({}, _set(("scenario_rule", "min_peak_to_mean"), .5), "scenario_rule.min_peak_to_mean is not a number >= 1"),
    ({"--seeds": "{"}, None, "--seeds is not JSON"),
    ({"--seeds": "[1]"}, None, "--seeds is not a JSON object"),
    ({"--seeds": json.dumps({k: v for k, v in SEEDS.items() if k != "traffic_sizes"})}, None,
     "--seeds has no traffic_sizes"),
    ({"--seeds": json.dumps(dict(SEEDS, traffic=True))}, None, "--seeds: traffic is not an integer >= 0"),
    ({"--warmup-s": "60"}, None, "the ramp of profile eshop (arrivals.ramp_s 120) is longer than --warmup-s 60.0"),
    ({"--dur": "300"}, None, "[--warmup-s, --dur] is shorter than the longest peak (arrivals.peak_s 240 s)"),
    ({}, _set(("scenario_rule", "min_peak_to_mean"), 50),
     "no envelope with peak-to-mean >= 50 over [120.0, 3720.0] s in 1000 draws"),
    ({"--rate": "1e9"}, None, "rate 1000000000.0 plans more than 10000000 arrivals over [0, --dur]"),
    ({"--summary-interval-s": "0"}, None, "summary-interval-s must be in [0.01, 3600]"),
    ({"--profile": "lab", "--scenario": None, "--seeds": None, "--rate": None, "--warmup-s": None}, None,
     "--protocol is an option of the v5 profiles eshop, corp only"),
]


@pytest.mark.parametrize("changes, change, reason", REFUSALS, ids=[r for _, _, r in REFUSALS])
def test_command_line_refusals_exit_2_with_their_reason(tmp_path, capsys, changes, change, reason):
    from scripts import host_traffic
    argv = command(tmp_path, **dict(changes, **({"--protocol": protocol_with(tmp_path, change)} if change else {})))
    with pytest.raises(SystemExit) as exit_:
        host_traffic.main(argv)
    assert exit_.value.code == 2
    assert f"error: {reason}" in capsys.readouterr().err
    assert not (tmp_path / "r.jsonl").exists()  # Nothing is written before the command line is good.


def test_good_command_line_and_the_rate_of_the_protocol(tmp_path):
    from scripts import host_traffic
    run = host_traffic.prepare_v5(v5_args(tmp_path, V5, dur=3720.0))
    assert (run.rate, run.rate_source, run.intensity, run.cap) == (1.0, "command line", "low", 500)
    doc = v5_doc()
    doc["scenarios"]["eshop_low"]["rate"] = 1.5
    run = host_traffic.prepare_v5(v5_args(tmp_path, write_doc(tmp_path, doc), rate=None, dur=3720.0))
    assert (run.rate, run.rate_source) == (1.5, "protocol")


# ------------------------------------------------------------------ one real run: the logs are exactly 1.4

class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def answer(self):
        split = urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        status, content_type, raw = lab_answer(self.command, split.path, parse_qs(split.query),
                                               self.headers.get("Authorization"), body)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = answer

    def log_message(self, *_):
        pass


@pytest.fixture
def lab_server():
    http = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = threading.Thread(target=http.serve_forever)
    thread.start()
    yield f"http://127.0.0.1:{http.server_port}"
    http.shutdown()
    http.server_close()
    thread.join()


def small_protocol(tmp_path):
    """config/collection-v5.json on a scale of seconds: a 1 s warmup and ramp, a wave of 4 to 8 s, a peak of 0.5 to
    1 s, think times of 0.05 s on average."""
    doc = v5_doc()
    doc["warmup_s"] = 1
    for params in doc["profiles"].values():
        params["arrivals"].update(ramp_s=1, wave_period_s=[4, 8], peak_s=[.5, 1], step_s=.25)
        params["think_s"].update(mean=.05, max=.5)
    return write_doc(tmp_path, doc, "small.json"), doc


@pytest.mark.parametrize("profile, scenario", [("eshop", "eshop_high"), ("corp", "corp_high")])
def test_real_run_writes_exactly_the_logs_of_design_1_4(tmp_path, lab_server, profile, scenario):
    from lab import seed
    path, doc = small_protocol(tmp_path)
    req, ivl, out = tmp_path / "requests.jsonl", tmp_path / "intervals.jsonl", tmp_path / "status.json"
    argv = ["--profile", profile, "--protocol", path, "--scenario", scenario, "--seeds", json.dumps(SEEDS),
            "--rate", "12", "--target", lab_server, "--dur", "4", "--warmup-s", "1", "--session-id", "S-14",
            "--requests-log", req, "--intervals-log", ivl, "--summary-interval-s", ".5", "--initial-phase", "warmup",
            "--out", out]
    process = subprocess.Popen([sys.executable, SCRIPT, *map(str, argv)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 20  # The log exists once the signal handlers are installed.
        while not req.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        time.sleep(.5)
        process.send_signal(signal.SIGUSR1)
        # The run does not end at --dur (4 s): no user session arrives after it, the runner sends SIGTERM.
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=6)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=30) == 0
    finally:
        if process.poll() is None:
            process.kill()
        stderr = process.communicate()[1]
    assert stderr == b""
    requests, intervals = records(req), records(ivl)
    for rows, schema in ((requests, "hyptcn3/traffic-request/2"), (intervals, "hyptcn3/traffic-interval/2")):
        assert [r["n"] for r in rows] == list(range(len(rows))) and {r["schema"] for r in rows} == {schema}
        assert rows[0]["type"] == "header" and rows[-1]["type"] == "end"
    header = requests[0]
    run_id, params = header["run_id"], doc["profiles"][profile]
    # Every record has exactly the fields of 1.4: today's plus the added ones.
    kinds = {"header", "phase", "arrival", "request", "end"}
    assert {r["type"] for r in requests} == kinds and {r["type"] for r in intervals} == {"header", "phase", "interval",
                                                                                         "end"}
    for row in requests + intervals:
        kind = row["type"]
        expected = ARRIVAL if kind == "arrival" else TODAY[kind] | ADDED[kind]
        if kind == "header" and row is intervals[0]:
            expected = expected | {"hist_edges_ms", "hist_precision"}
        assert set(row) == expected, kind
    # The header (both files alike, as today, apart from the histogram fields).
    assert {k: v for k, v in intervals[0].items() if k not in ("schema", "hist_edges_ms", "hist_precision")} == \
        {k: v for k, v in header.items() if k != "schema"}
    assert (header["profile"], header["scenario"], header["intensity"], header["rate"], header["rate_source"]) == \
        (profile, scenario, "high", 12, "command line")
    assert header["seeds"] == SEEDS and header["warmup_s"] == 1 and header["load_model"] == LOAD_MODEL
    assert header["protocol_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert header["profile_parameters"] == params and header["config"]["seed"] == SEEDS["traffic"]
    t, level = header["envelope"]["t_s"], header["envelope"]["level"]
    assert set(header["envelope"]) == {"t_s", "level"} and t[0] == 0 and t[-1] == 4
    assert all(a < b for a, b in zip(t, t[1:])) and min(level) >= 0 and max(level) == 1
    # Arrivals: one per offered user session in arrival order; requests only of admitted ones.
    arrivals = of_type(requests, "arrival")
    assert [a["user_session"] for a in arrivals] == [f"{run_id}-u{n}" for n in range(len(arrivals))]
    assert len(arrivals) >= 5 and all(type(a["admitted"]) is bool and type(a["active"]) is int for a in arrivals)
    assert all(a["admitted"] == (a["active"] < params["max_concurrent"]) for a in arrivals)
    assert [a["t_mono"] for a in arrivals] == sorted(a["t_mono"] for a in arrivals) and arrivals[-1]["t_mono"] < 4
    admitted = {a["user_session"] for a in arrivals if a["admitted"]}
    rows = of_type(requests, "request")
    assert {r["user_session"] for r in rows} <= admitted and rows
    for r in rows:
        assert r["step"] in STEPS[profile] and r["rid"] == f"{r['user_session']}-{r['worker_seq']:04d}"
        assert r["user_session"] == f"{run_id}-u{r['worker']}" and r["session_id"] == "S-14"
        assert (r["think_s"] is None) == (r["worker_seq"] == 0)
        assert r["think_s"] is None or 0 <= r["think_s"] <= params["think_s"]["max"]
        assert r["intended_status"] in (None, *params["client_errors"]["statuses"])
        assert r["status"] == r["intended_status"] if r["intended_status"] else r["outcome"] == "ok"
        objects = {"detail": int, "cart_add": int, "doc_get": int, "static": str, "report_status": str}
        assert type(r["object"]) is objects[r["step"]] if r["step"] in objects else r["object"] is None
        if r["step"] == "static":
            assert r["object"] == r["route"] and r["object"][len("/static/"):] in dict(seed.static_files(0))
    # Intervals: the arrivals by their time and the plan of the envelope.
    ivs = of_type(intervals, "interval")
    for iv in ivs:
        inside = [a for a in arrivals if iv["mono_start"] <= a["t_mono"] < iv["mono_end"]]
        assert iv["offered_sessions"] == len(inside) == iv["admitted_sessions"] + iv["dropped_sessions"]
        assert type(iv["active_max"]) is int and iv["active_max"] >= max([a["active"] + a["admitted"] for a in inside]
                                                                         + [0])
        assert abs(iv["planned_sessions"] - 12 * integral(t, level, iv["mono_start"], iv["mono_end"])) <= 1e-6
    for end in (requests[-1], intervals[-1]):
        assert end["arrivals"] == len(arrivals) == end["admitted"] + end["dropped"] and end["clean"]
        assert end["admitted"] == end["user_sessions_completed"] + end["user_sessions_in_progress_at_stop"]
        assert end["requests_logged"] == len(rows) == end["requests_started"] == end["requests_completed"]
    status = json.loads(out.read_text())
    assert status["schema"] == "hyptcn3/host-traffic/4" and status["final"] and status["unexpected_results"] == 0
    assert status["requests"] == len(rows) and status["intended_errors"] == status["intended_errors_matched"] == \
        sum(r["intended_status"] is not None for r in rows)
    assert (status["arrivals"], status["dropped"]) == (len(arrivals), len(arrivals) - len(admitted))
