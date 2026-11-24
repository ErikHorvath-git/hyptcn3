from collections import namedtuple
import copy
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import collection_logs as logs, host_monitor, traffic_log as tl
from scripts.collection import write_logs_manifest
from scripts.tests import test_traffic_log as sample


def write(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc) + "\n")


def jsonl(path, records):
    path.write_text("".join(json.dumps(row) + "\n" for row in records))


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()


def utc(offset, base=BASE):
    return datetime.fromtimestamp(base + offset, timezone.utc).isoformat()


def pack(directory, name, text):
    content = text.encode()
    path = directory / "guest" / (name + ".gz")
    path.write_bytes(gzip.compress(content))
    return {"name": name, "file": path.name, "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "lines": content.count(b"\n"), "terminated": content.endswith(b"\n") or not content,
            "gz_bytes": path.stat().st_size, "gz_sha256": logs.digest(path), "file_sha256": logs.digest(path)}


# Protocol v3 variant: restart_sluzby of orders, host bounds 1.45-1.6 s, grace .1 s -> window .45-1.7 s.
EVENT = {"type": "restart_sluzby", "class": "restart_sluzby", "start_s": 0, "duration_s": 1}
# SHA-256 of lab/udalosti.py in session.json and in both replies of the event script.
SCRIPT_SHA256 = hashlib.sha256(b"synthetic lab/udalosti.py").hexdigest()
QEMU_PID = 4242  # The session VM's QEMU in every host monitor sample (label qemu), never swapped.


@pytest.fixture
def session(tmp_path):
    return build(tmp_path)


def build(tmp_path, event=False, *, session_name="synthetic-session", base=BASE, snapshots=10, measure_s=2):
    # Offsets from base: warmup [0, 1), measurement [1, 1 + measure_s], post until 1.5 + measure_s.
    # The caller's snapshot times must lie inside the measurement; the logs claim `snapshots` of them.
    if type(snapshots) is not int or snapshots < 1 or type(measure_s) is not int or measure_s < 1:
        raise ValueError("snapshots and measure_s must be positive integers")
    base, stop = float(base), 1 + measure_s
    # Interval and end records carry one stamp, the start of the session (the default equals sample.UTC).
    start = datetime.fromtimestamp(base, timezone.utc).isoformat(timespec="microseconds")

    def at(offset):
        return utc(offset, base)
    d = tmp_path / session_name
    (d / "guest").mkdir(parents=True)
    (d / "raw").mkdir()
    config = {"target": "http://lab", "profile": "lab", "seed": 1, "workers": 1, "burst": 0,
              "catalog_share": .5, "write_share": .2, "summary_interval_s": 1, "initial_phase": "warmup"}
    identity = {"kernel": "synthetic-kernel", "boot_id": "synthetic-boot"}
    write(d / "protocol.json", {"synthetic": True})
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": d.name, "cycles": snapshots,
                               "guest_before": identity, "seed": 1, "traffic": config,
                               "protocol_sha256": logs.digest(d / "protocol.json"), "collector_sha256": "test",
                               **({"events": [EVENT], "event_grace_s": .1,
                                   "source_sha256": {"lab/udalosti.py": SCRIPT_SHA256}} if event else {})})
    write(d / "end.json", {"schema": "hyptcn3/collection-end/2", "completed": True, "interrupted": False,
                           "guest_after": identity, "collector_rc": 0, "traffic_rc": int(event),
                           "monitor": {"rc": 0}, "measure_start_unix": base + 1, "measure_end_unix": base + stop})
    reqs = [sample.request(0, 0, "warmup", .1, 3, method="POST", route="/api/auth/token"),
            sample.request(1, 1, "measure", 1.1, 2),
            sample.request(2, 1, "measure", 1.5, 2, method="POST", route="/api/orders", status=201),
            sample.request(3, measure_s, "measure", measure_s + .2, 2, route="/healthz"),
            sample.request(4, stop, "post", stop + .1, 2, route="/api/orders")]
    for r in reqs:
        r.update(session_id=d.name, t_start_utc=at(r["t_start_mono"]), t_end_utc=at(r["t_end_mono"]))
    if event:  # The order placed while orders restarts gets 502 from nginx.
        reqs[2].update(status=502, outcome="http_error", error="HTTPError: HTTP Error 502")
    marks = [dict(sample.marker("measure", "warmup", 1., 1), t_utc=at(1)),
             dict(sample.marker("post", "measure", float(stop), stop), t_utc=at(stop))]
    heads = [dict(sample.header(schema, d.name), config=config, start_utc=at(0), start_unix=base)
             for schema in (tl.REQUEST_SCHEMA, tl.INTERVAL_SCHEMA)]
    rs = [heads[0], reqs[0], marks[0], *reqs[1:4], marks[1], reqs[4]]
    ivs = [dict(sample.interval(i, phase, float(i), float(i + 1) if i < stop else stop + .5,
                                [r for r in reqs if r["interval"] == i]), t_start_utc=start, t_end_utc=start)
           for i, phase in enumerate(("warmup", *["measure"] * measure_s, "post"))]
    iv = [heads[1], ivs[0], marks[0], *ivs[1:stop], marks[1], ivs[stop]]
    rs.append(dict(sample.end(reqs, len(rs), end_mono=stop + .5), end_utc=start))
    iv.append(dict(sample.end(reqs, len(iv), end_mono=stop + .5), end_utc=start))
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA, rs)
    sample.write(d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA, iv)
    write(d / "traffic_before.json", {"run_id": sample.RUN, "started_at": at(0)})
    write(d / "traffic.json", {"run_id": sample.RUN, "session_id": d.name, "started_at": at(0),
                              "final": True, "requests": len(reqs), "requests_logged": len(reqs),
                              "ok": sum(r["outcome"] == "ok" for r in reqs),
                              "errors": sum(r["outcome"] != "ok" for r in reqs), "logging_error": None,
                              "worker_errors": 0})
    units = {name: {"ActiveState": "active", "Result": "success", "NRestarts": "0", "InvocationID": name,
                    "ExecMainPID": str(100 + i), "ExecMainStartTimestampMonotonic": "1"}
             for i, name in enumerate(logs.REQUIRED_UNITS)}
    restarted = {**units, "hyptcn-lab@orders": dict(units["hyptcn-lab@orders"], InvocationID="new", ExecMainPID="999")}
    for when in ("before", "after"):
        write(d / "guest" / f"state_{when}.json", {"schema": "hyptcn3/guest-state/1", **identity,
                                                   "units": restarted if event and when == "after" else units,
                                                   "database": {}})
        write(d / "guest" / f"clock_{when}.json", {"offset_s": .01, "uncertainty_s": .01})
    nginx = [dict(schema="hyptcn3/nginx-access/1", rid=r["rid"], forwarded_rid=r["rid"],
                  method=r["method"], uri=r["route"], status=r["status"], msec=base + r["t_end_mono"]) for r in reqs]
    if event:  # lab/udalosti.py checks health without a request id while the event runs.
        nginx.append(dict(schema="hyptcn3/nginx-access/1", rid="", forwarded_rid="x", method="GET",
                          uri="/healthz", status=502, msec=base + 1.55))
    write(d / "preflight_smoke.json", {"schema": "hyptcn3/lab-smoke/1", "values": {
        "order_completed": True, "checks": [{"rid": "smoke", "status": 401, "expected": 401}]}})
    journal = []

    def call(r, service, method, route, status):
        pid = units["hyptcn-lab@" + service]["ExecMainPID"]
        if event and service == "orders" and r["t_start_mono"] > 1.7:
            pid = "999"
        journal.append(f"{at(2)} guest python3[{pid}]: client request rid={r['rid']} method={method} path={route} status={status}\n")

    for r in reqs:
        service = "auth" if "auth" in r["route"] else "catalog" if "catalog" in r["route"] else "orders"
        call(r, service, r["method"], r["route"], r["status"])
        if r["route"] == "/api/orders":
            call(r, "auth", "GET", "/api/auth/check", 200)
            if r["method"] == "POST":
                call(r, "catalog", "GET", "/api/catalog/1", 200)
        if r["route"] == "/healthz":
            for name in ("auth", "catalog"):
                call(r, name, "GET", "/healthz", 200)
    errors = ""
    if event:
        journal.append(f"{at(1.5)} guest python3[999]: Traceback (most recent call last):\n")
        errors = (f"{datetime.fromtimestamp(base + 1, timezone.utc):%Y/%m/%d %H:%M:%S} [error] 7#7: *1 connect() "
                  "failed (111: Connection refused) while connecting to upstream\n")
        write(d / "events.json", {"schema": "hyptcn3/session-events/1", "events": [dict(
            EVENT, executed=True, effect={"ok": True, "predicate": "synthetic"}, host_start_unix=base + 1.45,
            host_started_unix=base + 1.5, host_stop_unix=base + 1.55, host_stopped_unix=base + 1.6,
            start={"ok": True, "script_sha256": SCRIPT_SHA256},
            stop={"ok": True, "health": 200, "script_sha256": SCRIPT_SHA256,
                  "units": {"hyptcn-lab@orders": {"ExecMainPID": "999"}}})]})
    for name, suffix, text in (("pre", "nginx-access.jsonl", json.dumps({"rid": "smoke", "status": 401}) + "\n"),
                               ("session", "nginx-access.jsonl", "".join(json.dumps(r) + "\n" for r in nginx)),
                               ("journal", "journal.txt", "".join(journal))):
        entries = [pack(d, name + "-" + suffix, text)]
        if name != "journal":
            entries.append(pack(d, name + "-nginx-error.log", errors if name == "session" else ""))
        write(d / "guest" / (name + "_segment.json"), {
            "schema": "hyptcn3/guest-journal-segment/1" if name == "journal" else "hyptcn3/guest-log-segment/1",
            "files": entries})
    jsonl(d / "host_monitor.jsonl", [
        {"schema": host_monitor.SCHEMA, "type": "header", "session_id": d.name, "interval_s": 1},
        *[{"type": "sample", "i": i, "t_mono": float(i), "t_utc": at(i), "cpu": {},
           "procs": {"qemu": [{"pid": QEMU_PID, "rss_kb": 1048576, "swap_kb": 0}]}} for i in range(stop + 2)],
        {"type": "end", "samples": stop + 2, "clean": True, "missed_ticks": 0}])
    write(d / "raw/capture.json", {"values": {"snapshots": snapshots, "requested_cycles": snapshots,
                                               "collector_exit_code": 0, "collector_sha256": "test"}})
    # The collector's text format (vmicollect/src/log.c): milliseconds, the level padded to five characters.
    (d / "raw/collect.log").write_text(f"{datetime.fromtimestamp(base + stop, timezone.utc):%Y-%m-%dT%H:%M:%S}.000Z "
                                       f"INFO  koniec: {snapshots} snimok, 0 chyb, 0 zmeskanych slotov, najvacsie "
                                       "meskanie 0.000 s, spolu 0 B\n")
    for name in ("traffic.log", "capture.log", "host_monitor.log", "domain.xml"):
        (d / name).touch()
    seal(d)
    return d


def seal(directory):
    (directory / "logs_manifest.json").unlink(missing_ok=True)
    sha = write_logs_manifest(directory)
    end = logs.read_json(directory / "end.json")
    write(directory / "end.json", dict(end, logs_manifest_sha256=sha))


# --- Protocol v5 (package B5b): the traffic of the open-loop profiles eshop and corp, logs of schema /2 -----------
# v5_traffic() is the one helper that gives a built session (build above) this traffic; build_session of
# scripts/tests/boundary_sessions.py calls it under every protocol with the profiles section. Its numbers are
# chosen so that every realism requirement of proposal 5.7 and the offered-load check hold with a margin, and
# its arguments break one of them at a time.

LOAD_MODEL = ("open loop: user sessions arrive as a non-homogeneous Poisson process with intensity rate x "
              "envelope(t), at most max_concurrent in progress")
# Spacings between the arrivals of the user sessions of the measure phase, in units of the planned envelope's
# integral: coefficient of variation sqrt(1.125) = 1.06 (population standard deviation over the mean).
SPACINGS = (.25, .25, 2.5) * 3
# Think times (s) before the second and later requests of those user sessions, in turn (none above 70 s).
THINKS = (1.5, 3., 4.5, 6., 7.5, 9., 10.5, 12.)
Step = namedtuple("Step", "step method route object status bytes intended", defaults=(None,))
HOME, BROWSE = Step("home", "GET", "/", None, 200, 320), Step("browse", "GET", "/api/catalog", None, 200, 1800)
SEARCH = Step("search", "GET", "/api/catalog", None, 200, 900)
DETAIL = Step("detail", "GET", "/api/catalog/7", 7, 200, 240)  # The most requested object.
LOGO = Step("static", "GET", "/static/logo.png", "logo.png", 200, 150000)
CART_ADD, CART = Step("cart_add", "POST", "/api/cart", 7, 200, 160), Step("cart", "GET", "/api/cart", None, 200, 160)
ORDER = Step("order", "POST", "/api/orders", None, 201, 90)
UNKNOWN = Step("detail", "GET", "/api/catalog/999999", 999999, 404, 40, 404)  # The deliberate client error.
# One user session per list, ten of them: one orders (from its cart), one makes the deliberate error.
ESHOP = ([HOME, BROWSE, DETAIL, LOGO], [HOME, SEARCH, DETAIL, Step("detail", "GET", "/api/catalog/12", 12, 200, 250)],
         [BROWSE, DETAIL, LOGO], [HOME, DETAIL, CART_ADD, CART, ORDER], [HOME, UNKNOWN],
         [BROWSE, DETAIL, Step("detail", "GET", "/api/catalog/3", 3, 200, 230)],
         [HOME, Step("static", "GET", "/static/style.css", "style.css", 200, 4000), DETAIL], [SEARCH, DETAIL],
         [HOME, BROWSE, DETAIL], [HOME, DETAIL, LOGO])
LOGIN = Step("login", "POST", "/api/auth/login", None, 200, 300)
LIST = Step("doc_list", "GET", "/api/docs", None, 200, 2500)
DOC = Step("doc_get", "GET", "/api/docs/5", 5, 200, 64000)  # The most requested object.
REPORT = Step("report", "POST", "/api/reports", None, 202, 80)
REPORT_ID = "20260101T000000000000Z-0123abcd"
WRONG_PASSWORD = Step("login", "POST", "/api/auth/login", None, 401, 40, 401)  # The deliberate client error.
# Nine logins, two report requests, ten document downloads with a largest 14 times the median one.
CORP = ([LOGIN, LIST, DOC], [LOGIN, LIST, DOC, Step("doc_get", "GET", "/api/docs/17", 17, 200, 900000)],
        [LOGIN, Step("doc_put", "POST", "/api/docs", None, 201, 120), DOC],
        [LOGIN, REPORT, Step("report_status", "GET", "/api/reports/" + REPORT_ID, REPORT_ID, 200, 60)],
        [WRONG_PASSWORD], [LOGIN, DOC, Step("doc_get", "GET", "/api/docs/8", 8, 200, 30000)], [LOGIN, LIST, DOC],
        [LOGIN, DOC, Step("doc_get", "GET", "/api/docs/2", 2, 200, 50000)], [LOGIN, LIST], [LOGIN, DOC, REPORT])
# The five requests of build(): r0 alone, r1 and r2 one user session, r3 alone, r4 alone (steps of the lab routes).
LEGACY = (("token",), ("browse", "order"), ("health",), ("orders",))
# lab/nginx.conf and lab/services.py, written out here (never taken from the code under test): the service a route
# reaches and whether it first asks auth about the token.
UPSTREAM = (("/api/catalog", "catalog"), ("/api/auth/", "auth"), ("/api/orders", "orders"), ("/api/cart", "orders"),
            ("/api/docs", "docs"), ("/api/reports", "docs"), ("/healthz", "orders"))


def _service(route):
    return None if route == "/" else next((name for prefix, name in UPSTREAM if route.startswith(prefix)), None)


def _asks_auth(method, route):
    return (route in ("/api/orders", "/api/cart", "/api/docs") or route.startswith("/api/docs/")
            or route.startswith("/api/reports/") or route == "/api/reports" and method == "POST")


def area(t, level, a, b):
    """The integral over [a, b] of the level linear between the points (t, level), 0 outside them; the tests'
    oracle of the planned envelope (never scripts/traffic_log.py)."""
    total = 0.
    for t0, t1, l0, l1 in zip(t, t[1:], level, level[1:]):
        lo, hi = max(a, t0), min(b, t1)
        if hi > lo:
            at = lambda x: l0 + (l1 - l0) * (x - t0) / (t1 - t0)  # noqa: E731
            total += (hi - lo) * (at(lo) + at(hi)) / 2
    return total


def _inverse(t, level, value, lo, hi):
    """The time in [lo, hi] at which the integral of the level from 0 reaches value (bisection)."""
    for _ in range(200):
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if area(t, level, 0, mid) < value else (lo, mid)
    return round(hi, 6)


def _segment(d, name, suffix, change):
    """Replace the lines of the guest log segment guest/<name>-<suffix> by change(lines), its record too."""
    path = d / "guest" / (name + "_segment.json")
    doc = logs.read_json(path)
    index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith("-" + suffix))
    entry = doc["files"][index]
    lines = gzip.decompress((d / "guest" / entry["file"]).read_bytes()).decode().splitlines(keepends=True)
    doc["files"][index] = pack(d, entry["name"], "".join(change(lines)))
    write(path, doc)


def _append_segment(d, name, suffix, lines):
    _segment(d, name, suffix, lambda old: [*old, *lines])


def _filter_segment(d, name, suffix, keep):
    _segment(d, name, suffix, lambda old: [line for line in old if keep(line)])


def v5_traffic(d, p, *, scenario=None, sessions=None, spacings=SPACINGS, thinks=THINKS, flat=False, rate_factor=1,
               legacy=LEGACY):
    """Give the session directory d (built by build(), its protocol.json and session.json already final, sealed or
    not) the traffic of a v5 profile under protocol p: logs of schema /2 (design B5b 1.4) and everything that counts
    or serves their requests (nginx and journal segments, traffic.json, the exit code in end.json, the traffic block
    of session.json). Without the profiles section in p nothing changes (returns None); else the request log's
    header. The caller seals d.

    The five requests of build() stay as they are, each in a user session that arrived in the warmup (LEGACY).
    The user sessions of `sessions` (default ESHOP or CORP by the scenario's profile) arrive in the measure phase
    after build()'s event window, at the times where the integral of the planned envelope makes the spacings
    `spacings` (one fewer than sessions); their requests follow within milliseconds, think times from `thinks`. The
    envelope is 0 but for one triangle of level 1 (flat: level 1 throughout); the rate (when the scenario has none)
    makes the offered load of the intervals outside every window equal the planned one, rate_factor times off.
    scenario: another scenario of p for the session (session.json follows).
    """
    if "profiles" not in p:
        return None
    meta, end = logs.read_json(d / "session.json"), logs.read_json(d / "end.json")
    if scenario is not None:
        meta["scenario"] = scenario
    s = p["scenarios"][meta["scenario"]]
    profile = s["profile"]
    params = p["profiles"][profile]
    sessions = sessions if sessions is not None else ESHOP if profile == "eshop" else CORP
    if len(spacings) != len(sessions) - 1:
        raise ValueError("one spacing between each two user sessions of the measure phase")
    names = ("traffic_requests.jsonl", "traffic_intervals.jsonl")
    log_r, log_i = ([{k: v for k, v in r.items() if k not in ("schema", "n")} for r in
                     (json.loads(line) for line in (d / name).read_text().splitlines())] for name in names)
    # Run again on traffic it gave before: back to the requests of build(), the others leave nginx and the journal.
    legacy_rid = f"{sample.RUN}-00-"
    gone = {r["rid"] for r in log_r if r.get("type") == "request" and not r["rid"].startswith(legacy_rid)}
    log_r = [r for r in log_r if r.get("type") != "arrival" and r.get("rid") not in gone]
    if gone:
        _filter_segment(d, "session", "nginx-access.jsonl", lambda line: json.loads(line)["rid"] not in gone)
        _filter_segment(d, "journal", "journal.txt",
                        lambda line: not any(f"rid={rid} " in line for rid in gone))
    base = log_r[0]["start_unix"]
    stop = next(r["t_mono"] for r in log_r if r.get("type") == "phase" and r["phase"] == "post")
    end_mono = log_r[-1]["end_mono"]
    windows = []
    if meta.get("events") and (d / "events.json").exists():
        windows = [(e["host_start_unix"] - 1 - base, e["host_stopped_unix"] + meta["event_grace_s"] - base)
                   for e in logs.read_json(d / "events.json")["events"] if "host_stopped_unix" in e]
    first = max([2.01, *(hi + .01 for _, hi in windows)])  # After the first interval and every window.
    last = stop - .05
    if last - first < .1:
        raise ValueError("no room for the user sessions of the measure phase")
    warmup = p["warmup_s"]
    # D: the envelope spans [0, D], the planned run of the protocol (collection._v5_traffic: warmup_s and cycles
    # intervals), which the log audit binds since package B10 (finding F3 of B5b); warmup_s < D.
    span = warmup + meta["cycles"] * p["interval_s"]
    if span <= max(end_mono, warmup):
        raise ValueError("the planned run of the protocol ends before the logs of build() do")
    # Peak-to-mean twice the bound: a triangle of width (measure length / bound); flat: level 1 everywhere.
    width = min(last - first, (stop - 1) / p["scenario_rule"]["min_peak_to_mean"])
    rate = s["rate"]
    if rate is not None and not flat:
        width = 2 * len(sessions) / rate  # Its area holds the user sessions at the protocol's rate.
        if width > last - first:
            raise ValueError("the protocol's rate is too low for this session's measure phase")
    if flat:
        t_s, level = [0, round(span, 6)], [1, 1]
    else:
        t_s, level = [0, first, round(first + width / 2, 6), round(first + width, 6), round(span, 6)], [0, 0, 1, 0, 0]
    start_area = area(t_s, level, 0, first)
    total = area(t_s, level, first, last if flat else first + width) * (.9 if flat else 1)
    unit = total / sum(spacings)
    cumulative = [start_area + unit * sum(spacings[:k]) for k in range(len(sessions))]
    arrive = [round(first, 6)] + [_inverse(t_s, level, c, first, last) for c in cumulative[1:]]

    # The user sessions: (arrival time, the requests in time order).
    requests = [r for r in log_r if r.get("type") == "request"]
    if len(requests) != sum(map(len, legacy)):
        raise ValueError("the requests of build() differ from LEGACY")
    users, position = [], 0
    for index, steps in enumerate(legacy):
        mine = requests[position:position + len(steps)]
        position += len(steps)
        for j, (r, step) in enumerate(zip(mine, steps)):
            r.update(step=step, object=None, intended_status=None,
                     think_s=None if j == 0 else round(r["t_start_mono"] - mine[j - 1]["t_end_mono"], 6))
        users.append((round(.01 * (index + 1), 6), mine))

    def phase(t):
        return "warmup" if t < 1 else "measure" if t < stop else "post"
    turn = 0
    for k, (at, steps) in enumerate(zip(arrive, sessions)):
        mine = []
        for j, step in enumerate(steps):
            start = round(at + .001 + .002 * j, 6)
            r = sample.request(j, math.floor(start), phase(start), start, 1., status=step.status, method=step.method,
                               route=step.route)
            failed = not 200 <= step.status < 300
            r.update(session_id=d.name, rid=f"{sample.RUN}-{k + 1:02d}-{j:08d}", worker=k + 1,
                     outcome="http_error" if failed else "ok", error=f"HTTPError: HTTP Error {step.status}" if failed
                     else None, t_start_utc=utc(start, base), t_end_utc=utc(r["t_end_mono"], base),
                     response_bytes=step.bytes, step=step.step, object=step.object, intended_status=step.intended,
                     think_s=None if j == 0 else thinks[turn % len(thinks)])
            turn += j > 0
            mine.append(r)
        users.append((at, mine))
    users.sort(key=lambda user: user[0])
    ends = [max(r["t_end_mono"] for r in mine) for _, mine in users]
    arrivals, buyers = [], 0
    for n, (at, mine) in enumerate(users):
        uid = f"{sample.RUN}-u{n}"
        for r in mine:
            r["user_session"] = uid
        active = sum(1 for m in range(n) if ends[m] > at)
        if active >= params["max_concurrent"]:
            raise ValueError("the user sessions of this traffic need a larger max_concurrent")
        # Package B5c: an eshop user session that orders holds a customer of its own (scripts/host_traffic.py
        # Customers; the log audit checks it since package B10, finding F1 of B5c), every other one none.
        orders = profile == "eshop" and any(r["method"] == "POST" and r["route"] == "/api/orders"
                                            and r.get("intended_status") is None for r in mine)
        buyers += orders
        arrivals.append({"type": "arrival", "user_session": uid, "t_mono": at, "t_utc": utc(at, base),
                         "phase": phase(at), "admitted": True, "active": active,
                         "customer": f"zakaznik{buyers:04d}" if orders else None, "drop_reason": None})
    requests = sorted((r for _, mine in users for r in mine), key=lambda r: r["t_start_mono"])

    # The rate: the offered load of the measure intervals outside every window equals the plan (rate_factor off).
    def outside(lo, hi):
        return not any(a <= hi and lo <= b for a, b in windows)
    ivs = [r for r in log_i if r.get("type") == "interval"]
    kept = [iv for iv in ivs if iv["phase"] == "measure" and outside(iv["mono_start"], iv["mono_end"])]
    if rate is None:
        offered = sum(1 for a in arrivals if any(iv["mono_start"] <= a["t_mono"] < iv["mono_end"] for iv in kept))
        rate = offered / sum(area(t_s, level, iv["mono_start"], iv["mono_end"]) for iv in kept)
    rate = rate * rate_factor
    for iv in ivs:
        lo, hi = iv["mono_start"], iv["mono_end"]
        members = [r for r in requests if r["interval"] == iv["interval"]]
        inside = [a for a in arrivals if lo <= a["t_mono"] < hi or iv is ivs[-1] and a["t_mono"] == hi]
        peak = max(sum(1 for m, (at, _) in enumerate(users) if at <= c < ends[m])
                   for c in [lo, *(a["t_mono"] for a in inside)])
        iv.update({**sample.interval(iv["interval"], iv["phase"], lo, hi, members),
                   "t_start_utc": utc(lo, base), "t_end_utc": utc(hi, base),
                   "offered_sessions": len(inside), "admitted_sessions": len(inside), "dropped_sessions": 0,
                   "planned_sessions": round(rate * area(t_s, level, lo, hi), 6), "active_max": peak})

    seeds = {"traffic": meta["seed"], "traffic_arrivals": meta["seed"] + 1, "traffic_choices": meta["seed"] + 2,
             "traffic_sizes": meta["seed"] + 3}
    config = dict(log_r[0]["config"], profile=profile, seed=meta["seed"], workers=None, burst=None,
                  catalog_share=None, write_share=None, dur=round(span, 6))
    v5 = {"config": config, "load_model": LOAD_MODEL, "profile": profile, "scenario": meta["scenario"],
          "intensity": s["intensity"], "rate": rate, "rate_source": "protocol" if s["rate"] is not None
          else "command line", "seeds": seeds, "protocol_sha256": meta["protocol_sha256"],
          "profile_parameters": copy.deepcopy(params), "warmup_s": warmup, "envelope": {"t_s": t_s, "level": level}}
    counts = {"arrivals": len(arrivals), "admitted": len(arrivals), "dropped": 0,
              "user_sessions_completed": len(arrivals), "user_sessions_in_progress_at_stop": 0}
    body_r = sorted([*arrivals, *requests, *(r for r in log_r if r.get("type") == "phase")],
                    key=lambda r: r.get("t_mono", r.get("t_start_mono")))
    log_r = [dict(log_r[0], **v5), *body_r, log_r[-1]]
    log_i = [dict(log_i[0], **v5), *log_i[1:]]
    for records in (log_r, log_i):
        records[-1] = {**records[-1], **sample.end(requests, len(records) - 1, end_mono=end_mono), **counts,
                       "end_utc": records[-1]["end_utc"], "phase": records[-1]["phase"]}
    sample.write(d / names[0], tl.REQUEST_SCHEMA_2, log_r)
    sample.write(d / names[1], tl.INTERVAL_SCHEMA_2, log_i)

    status = logs.read_json(d / "traffic.json")
    ok = sum(r["outcome"] == "ok" for r in requests)
    write(d / "traffic.json", dict(status, requests=len(requests), requests_logged=len(requests), ok=ok,
                                   errors=len(requests) - ok))
    # host_traffic.py's exit code rule for v5: 1 when a request did not get its expected result (a 2xx, or the
    # status a deliberate error intends) or none succeeded.
    unexpected = [r for r in requests if (r["outcome"] != "ok" if r.get("intended_status") is None
                                          else r["status"] != r["intended_status"])]
    write(d / "end.json", dict(end, traffic_rc=int(bool(unexpected) or not ok)))
    meta["traffic"] = {"generator": "scripts/host_traffic.py", "profile": profile, "scenario": meta["scenario"],
                       "intensity": s["intensity"], "rate": rate, "rate_source": v5["rate_source"], "seeds": seeds,
                       "seed": meta["seed"], "target": meta["traffic"]["target"],
                       "summary_interval_s": meta["traffic"]["summary_interval_s"], "warmup_s": warmup,
                       "dur_s": config["dur"], "load_model": LOAD_MODEL}
    write(d / "session.json", meta)

    # nginx and the services for the new requests (build() wrote those of the legacy ones).
    units = logs.read_json(d / "guest/state_before.json")["units"]
    added = [r for r in requests if not r["rid"].startswith(f"{sample.RUN}-00-")]
    nginx, journal = [], []

    def call(r, name, method, route, status):
        pid = units["hyptcn-lab@" + name]["ExecMainPID"]
        if windows and name == "orders" and r["t_start_mono"] > 1.7:
            pid = "999"  # build(): orders restarted in the event and runs as 999 since
        journal.append(f"{utc(r['t_end_mono'], base)} guest python3[{pid}]: client request rid={r['rid']} "
                       f"method={method} path={route} status={status}\n")
    for r in added:
        nginx.append(json.dumps(dict(schema="hyptcn3/nginx-access/1", rid=r["rid"], forwarded_rid=r["rid"],
                                     method=r["method"], uri=r["route"], status=r["status"],
                                     msec=base + r["t_end_mono"], bytes=r["response_bytes"])) + "\n")
        name = _service(r["route"])
        if name is None:
            continue
        if _asks_auth(r["method"], r["route"]):
            call(r, "auth", "GET", "/api/auth/check", 401 if r["status"] == 401 else 200)
        call(r, name, r["method"], r["route"], r["status"])
        if r["route"] == "/api/orders" and r["method"] == "POST" and r["status"] == 201:
            call(r, "catalog", "GET", "/api/catalog/prices", 200)  # One catalog call per order.
    _append_segment(d, "session", "nginx-access.jsonl", nginx)
    _append_segment(d, "journal", "journal.txt", journal)
    return log_r[0]


def test_consistent_managed_session_checks_all_evidence(session):
    result = logs.audit_logs(session, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert result["accepted"], result["problems"]
    assert result["sections"]["correlation"]["nginx_matched_once"] == 5
    assert result["sections"]["collector"]["end"] == ("10", "0", "0")


@pytest.mark.parametrize("case,problem", [
    ("modified", "evidence_hash"), ("missing", "missing_evidence"), ("killed", "child_exit"),
    ("restart", "service_restarted"), ("clock", "guest_clock"), ("torn", "traffic"),
    ("missing_nginx", "nginx_request_count"), ("missing_service", "service_catalog_call"),
    ("duplicate_nginx", "nginx_request_count"), ("status_mismatch", "nginx_mismatch"),
    ("missing_monitor", "monitor"), ("skipped_slot", "collector_errors_or_missed_slots"),
    ("malformed", "traffic:unreadable"), ("gzip_corrupt", "segments:unreadable"),
])
def test_rejects_independent_evidence_failures(session, case, problem):
    if case == "modified":
        (session / "traffic.log").write_text("changed\n")
    elif case == "missing":
        (session / "traffic.log").unlink()
    elif case == "killed":
        end = logs.read_json(session / "end.json")
        write(session / "end.json", dict(end, traffic_rc=-9))
    elif case in ("restart", "clock"):
        path = session / "guest" / ("state_after.json" if case == "restart" else "clock_after.json")
        doc = logs.read_json(path)
        if case == "restart":
            doc["units"]["hyptcn-lab@orders"]["InvocationID"] = "new"
        else:
            doc["offset_s"] = 8
        write(path, doc)
    elif case in ("torn", "malformed"):
        with (session / "traffic_requests.jsonl").open("a") as stream:
            stream.write('{"type":' if case == "torn" else '{"type":"request","rid":[],"interval":{}}\n')
    elif case in ("missing_nginx", "duplicate_nginx", "status_mismatch", "missing_service", "gzip_corrupt"):
        name = "journal" if case == "missing_service" else "session"
        suffix = "journal.txt" if case == "missing_service" else "nginx-access.jsonl"
        path = session / "guest" / (name + "-" + suffix + ".gz")
        if case == "gzip_corrupt":
            path.write_bytes(b"broken gzip")
        else:
            lines = gzip.decompress(path.read_bytes()).decode().splitlines(keepends=True)
            if case == "missing_service":
                lines = [line for line in lines if "path=/api/catalog/1 " not in line]
            elif case == "missing_nginx":
                lines.pop()
            elif case == "duplicate_nginx":
                lines.append(lines[-1])
            else:
                lines[-1] = json.dumps(dict(json.loads(lines[-1]), status=503)) + "\n"
            path.write_bytes(gzip.compress("".join(lines).encode()))
            doc_path = session / "guest" / (name + "_segment.json")
            doc = logs.read_json(doc_path)
            doc["files"][0] = pack(session, name + "-" + suffix, "".join(lines))
            write(doc_path, doc)
    elif case == "missing_monitor":
        path = session / "host_monitor.jsonl"
        path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    else:
        path = session / "raw/collect.log"
        path.write_text(path.read_text().replace("0 zmeskanych", "1 zmeskanych"))
    result = logs.audit_logs(session)
    assert not result["accepted"]
    assert problem in result["problem_counts"], result["problems"]


def test_event_window_tolerates_expected_failures_only(tmp_path):
    d = build(tmp_path, event=True)
    result = logs.audit_logs(d, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert result["accepted"], result["problems"]
    assert result["sections"]["events"]["executed"] == 1
    assert result["sections"]["correlation"]["tolerated_in_events"] == {
        "event_health_checks": 1, "journal_tracebacks": 1, "nginx_error_lines": 1,
        "requests_in_events": 2, "failed_in_events": 1}
    assert "hyptcn-lab@orders" not in result["sections"]["guest"]["units_checked"]


@pytest.mark.parametrize("event", [False, True])
@pytest.mark.parametrize("session_name,base,snapshots,measure_s", [
    ("v5-train-1-steady", BASE + 5000, 96, 100), ("s2", BASE + 100000, 720, 725)])
def test_renamed_shifted_longer_session_passes_the_log_audit_like_the_default(
        tmp_path, event, session_name, base, snapshots, measure_s):
    default = logs.audit_logs(build(tmp_path / "default", event), snapshot_times=[BASE + 1.1, BASE + 2.5])
    d = build(tmp_path / "custom", event, session_name=session_name, base=base, snapshots=snapshots,
              measure_s=measure_s)
    result = logs.audit_logs(d, snapshot_times=[base + 1.5 + i for i in range(snapshots)])  # 1 s apart
    assert result["accepted"], result["problems"]
    assert result["sections"]["correlation"]["nginx_matched_once"] == 5
    assert result["sections"]["collector"]["end"] == (str(snapshots), "0", "0")
    assert default["accepted"] and result["sections"].keys() == default["sections"].keys()
    assert result["sections"]["correlation"] == default["sections"]["correlation"]
    assert result["sections"]["guest"]["units_checked"] == default["sections"]["guest"]["units_checked"]


def test_builder_parameters_reach_the_audited_evidence(tmp_path):
    base, snapshots, measure_s = BASE + 5000, 96, 100
    d = build(tmp_path, True, session_name="v5-train-1-steady", base=base, snapshots=snapshots, measure_s=measure_s)
    result = logs.audit_logs(d, snapshot_times=[base + 1, base + 1 + measure_s])
    assert result["accepted"], result["problems"]
    sections = result["sections"]
    assert Path(result["session_dir"]).name == sections["traffic"]["session_id"] == "v5-train-1-steady"
    assert logs.read_json(d / "session.json")["session_id"] == "v5-train-1-steady"
    assert sections["collector"]["end"] == ("96", "0", "0")
    assert logs.read_json(d / "raw/capture.json")["values"]["snapshots"] == 96
    assert (sections["metadata"]["measure_start_unix"], sections["metadata"]["measure_end_unix"]) == (
        base + 1, base + 101)
    assert [m["t_utc"] for m in sections["traffic"]["phase_markers"]] == [utc(1, base), utc(101, base)]
    assert sections["traffic"]["measure"]["intervals"] == measure_s
    assert sections["monitor"]["window_samples"] == measure_s + 1
    (lo, hi), = sections["events"]["windows"]
    assert (lo, hi) == (pytest.approx(base + .45), pytest.approx(base + 1.7))
    # Times the audit does not bound must follow base and the length of the measurement as well.
    traffic = [[json.loads(line) for line in (d / name).read_text().splitlines()]
               for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl")]
    stamps = [r[k] for log in traffic for r in log
              for k in ("t_start_utc", "t_end_utc", "t_utc", "start_utc", "end_utc") if k in r]
    journal = gzip.decompress((d / "guest/journal-journal.txt.gz").read_bytes()).decode().splitlines()
    stamps += [line.split(" ", 1)[0] for line in journal]
    assert len(stamps) > 2 * measure_s and all(base <= logs.unix(s) <= base + 101.5 for s in stamps)
    for log in traffic:
        assert (log[0]["start_unix"], log[0]["start_utc"]) == (base, utc(0, base))
        assert (log[-1]["type"], log[-1]["end_mono"]) == ("end", measure_s + 1.5)
    happened, = logs.read_json(d / "events.json")["events"]
    assert [happened[k] - base for k in ("host_start_unix", "host_started_unix", "host_stop_unix",
                                         "host_stopped_unix")] == pytest.approx([1.45, 1.5, 1.55, 1.6])
    assert (d / "raw/collect.log").read_text().startswith(utc(101, base)[:19] + ".000Z ")
    # Snapshots in the default window, or after the default end, show which window the evidence claims.
    for times in ([BASE + 1.1], [base + 1 + measure_s + 1]):
        problems = logs.audit_logs(d, snapshot_times=times)["problem_counts"]
        assert {"snapshot_outside_measure", "traffic_snapshot_coverage"} <= set(problems), problems
    assert logs.audit_logs(d, snapshot_times=[base + 3.5])["accepted"]
    for bad in ({"snapshots": 0}, {"measure_s": 0}, {"measure_s": 1.5}):
        with pytest.raises(ValueError):
            build(tmp_path / "bad", **bad)


@pytest.mark.parametrize("case,problem", [
    ("other_unit", "service_restarted"), ("late_traceback", "journal_error_or_loss"),
    ("late_nginx_error", "nginx_error_log_nonempty"), ("not_stopped", "event_not_stopped"),
    ("plan", "events_differ_from_plan"), ("no_events_file", "events:unreadable"),
    ("script", "event_script_differs"), ("late_health_check", "nginx_unknown_request"),
])
def test_event_session_stays_strict_outside_windows(tmp_path, case, problem):
    d = build(tmp_path, event=True)
    if case == "other_unit":
        path = d / "guest/state_after.json"
        doc = logs.read_json(path)
        doc["units"]["hyptcn-lab@auth"]["InvocationID"] = "new"
        write(path, doc)
    elif case in ("late_traceback", "late_nginx_error"):
        name, suffix = ("journal", "journal.txt") if case == "late_traceback" else ("session", "nginx-error.log")
        path = d / "guest" / (name + "-" + suffix + ".gz")
        text = gzip.decompress(path.read_bytes()).decode() + (
            f"{utc(2.5)} guest python3[999]: Traceback (most recent call last):\n" if name == "journal"
            else "2026/01/01 00:00:03 [error] 7#7: upstream timed out\n")
        doc_path = d / "guest" / (name + "_segment.json")
        doc = logs.read_json(doc_path)
        index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith(suffix))
        doc["files"][index] = pack(d, name + "-" + suffix, text)
        write(doc_path, doc)
    elif case == "late_health_check":
        doc_path = d / "guest/session_segment.json"
        path = d / "guest/session-nginx-access.jsonl.gz"
        row = dict(schema="hyptcn3/nginx-access/1", rid="", forwarded_rid="y", method="GET", uri="/healthz",
                   status=200, msec=BASE + 2.5)
        text = gzip.decompress(path.read_bytes()).decode() + json.dumps(row) + "\n"
        doc = logs.read_json(doc_path)
        index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith("nginx-access.jsonl"))
        doc["files"][index] = pack(d, "session-nginx-access.jsonl", text)
        write(doc_path, doc)
    elif case in ("not_stopped", "plan", "script"):
        doc = logs.read_json(d / "events.json")
        if case == "plan":
            doc["events"][0]["start_s"] = 30
        elif case == "script":
            doc["events"][0]["stop"]["script_sha256"] = "other"
        else:
            del doc["events"][0]["host_stopped_unix"]
        write(d / "events.json", doc)
    else:
        (d / "events.json").unlink()
    seal(d)
    result = logs.audit_logs(d)
    assert not result["accepted"]
    assert problem in result["problem_counts"], result["problems"]


def add_journal_line(d, line):
    path, doc_path = d / "guest/journal-journal.txt.gz", d / "guest/journal_segment.json"
    doc = logs.read_json(doc_path)
    index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith("journal.txt"))
    doc["files"][index] = pack(d, "journal-journal.txt", gzip.decompress(path.read_bytes()).decode() + line)
    write(doc_path, doc)
    seal(d)


def test_worker_statement_timeout_is_admitted_only_inside_an_event_window(tmp_path):
    """lab/services.py reports a round that hit the statement timeout instead of exiting (protocol v5)."""
    line = "guest python3[5]: " + logs.WORKER_ERROR + "canceling statement due to statement timeout\n"
    d = build(tmp_path / "inside", event=True)
    add_journal_line(d, f"{utc(1.5)} {line}")
    result = logs.audit_logs(d, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert result["accepted"], result["problems"]
    assert result["sections"]["correlation"]["tolerated_in_events"]["worker_errors"] == 1
    d = build(tmp_path / "outside", event=True)
    add_journal_line(d, f"{utc(2.5)} {line}")
    result = logs.audit_logs(d, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert not result["accepted"] and "journal_error_or_loss" in result["problem_counts"], result["problems"]
    d = build(tmp_path / "no-events")
    add_journal_line(d, f"{utc(1.5)} {line}")
    assert "journal_error_or_loss" in logs.audit_logs(d)["problem_counts"]


def test_failed_request_outside_event_window_is_rejected(tmp_path):
    d = build(tmp_path, event=True)
    events = logs.read_json(d / "events.json")
    events["events"][0].update(host_start_unix=BASE + 3.5, host_started_unix=BASE + 3.5,
                               host_stop_unix=BASE + 3.6, host_stopped_unix=BASE + 3.6)
    write(d / "events.json", events)
    seal(d)
    result = logs.audit_logs(d)
    assert {"request_failed", "journal_error_or_loss", "nginx_error_log_nonempty"} <= set(result["problem_counts"])


WARN_LINE = "2026-01-01T00:00:03.000Z WARN  planovac: cyklus 7 trval 5.200 s (perioda 5.000 s)"


@pytest.mark.parametrize("schema,allowed,unlisted", [
    (3, None, True),                                   # null until G2: no warning is allowed
    (3, [r"planovac: cyklus \d+ trval [0-9.]+ s \(perioda [0-9.]+ s\)"], False),
    (3, ["planovac: cyklus"], True),                   # a pattern must match the whole message
    (2, None, False),                                  # no audit bounds: warnings are recorded only
], ids=["null", "full_match", "partial_match", "schema2"])
def test_collector_warning_is_judged_by_the_allowed_patterns(session, schema, allowed, unlisted):
    doc = {"schema": f"hyptcn3/collection-protocol/{schema}", "interval_s": 5}
    if schema == 3:  # Since package B5b the audit section also holds the traffic bounds (from the v5 file).
        bounds = json.loads((logs.ROOT / "config/collection-v5.json").read_text())["audit"]
        # Package B9b: and the early stop of the v5 file; this protocol has no events section, so no type to bound.
        early_stop = dict(bounds["early_stop"], marked_rows_rate_per_type={})
        doc["audit"] = {"lateness_max_s": .5, "cycle_ms_max": {"delta": 1500, "full": 3500},
                        "periodicity": {"equal_spacings": 3, "min_spacing_rows": 2, "note": "test"},
                        "warnings_allowed": allowed, "rule_closed_rows_max": None, "traffic": bounds["traffic"],
                        "early_stop": early_stop}
    write(session / "protocol.json", doc)
    meta = logs.read_json(session / "session.json")
    write(session / "session.json", dict(meta, protocol_sha256=logs.digest(session / "protocol.json")))
    with (session / "raw/collect.log").open("a") as stream:
        stream.write(WARN_LINE + "\n")
    seal(session)
    result = logs.audit_logs(session)
    message = WARN_LINE.split("WARN  ", 1)[1]
    assert result["problems"] == (["collector_warning_unlisted:" + message] if unlisted else [])
    assert result["tolerated"]["collector_warnings"] == int(schema == 3 and not unlisted)
    assert result["sections"]["collector"]["warnings"] == [WARN_LINE]


def test_snapshot_must_be_inside_traffic_phase(session):
    result = logs.audit_logs(session, snapshot_times=[BASE + 3.1])
    assert not result["accepted"] and "traffic_snapshot_coverage" in result["problem_counts"]


def test_manifest_cannot_reference_external_file(session):
    path = session / "logs_manifest.json"
    doc = logs.read_json(path)
    doc["files"]["../outside"] = {"sha256": "", "size": 0}
    write(path, doc)
    result = logs.audit_logs(session)
    assert not result["accepted"] and "evidence_unreadable" in result["problem_counts"]


def test_cli_works_without_numpy_and_refuses_overwrite(session, tmp_path):
    script = Path(logs.__file__)
    out = tmp_path / "report.json"
    result = subprocess.run([sys.executable, "-S", script, session, "--out", out], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    before = out.read_bytes()
    assert subprocess.run([sys.executable, "-S", script, session, "--out", out], capture_output=True).returncode != 0
    assert out.read_bytes() == before


def test_missing_session_still_returns_reviewable_rejection(tmp_path):
    result = logs.audit_logs(tmp_path)
    assert result["accepted"] is False
    assert "metadata:unreadable" in result["problem_counts"]


def test_full_collection_audit_cannot_accept_good_features_with_failed_logs(session, monkeypatch):
    from scripts import collection
    from features.tests.test_collection_contract import sample_sidecar
    from features.tests.test_coverage import data
    from safeguard.tests.test_features import sample as frame
    from scripts.tests import boundary_sessions as bs

    # Fake only expensive RAM parsing. Real sidecar, window and log validators
    # plus the immutable JSON/NPZ writer are exercised together.
    p = dict(collection.protocol(collection.DEFAULT), interval_s=.1, max_gap_s=.15,
             window_rows=3, min_score_coverage=.5)
    write(session / "protocol.json", p)
    meta = logs.read_json(session / "session.json")
    # The fields of a managed capture the audit reads (package B3), clean; the guest's after the capture too.
    meta.update(role="diagnostic", profile_sha256={}, protocol_sha256=logs.digest(session / "protocol.json"),
                **bs.managed_fields(p, meta["guest_before"]))
    write(session / "session.json", meta)
    write(session / "end.json", dict(logs.read_json(session / "end.json"), guest_after=meta["guest_before"]))
    (session / "profile").mkdir()
    capture = logs.read_json(session / "raw/capture.json")
    capture["values"].update(interval_s=p["interval_s"], full_every=p["full_every"], mlock=True)
    write(session / "raw/capture.json", capture)
    frames = [frame(i, full=i == 0, predecessor=i != 0, timestamp=BASE + 1.1 + i * .1) for i in range(10)]
    result = data(frames)
    result.update(snimky=[str(i) for i in range(10)], poznamky=[[]] * 10, trvanie_s=[0.] * 10,
                  max_medzera_s=.15)
    for quality in result["quality"]:
        quality["process_walk"] = "next"  # The forward walk closed every process list.
    for f in frames:
        image = session / "raw" / f"frame{f.seq}.vmicd"
        image.write_bytes(b"synthetic RAM")
        side = sample_sidecar()
        side.update(seq=f.seq, timestamp_unix=f.timestamp, sched={"skipped_before": 0}, capture={"total_ms": .1})
        side["output"].update(full=f.full, sha256=logs.digest(image))
        write(image.with_suffix(".json"), bs.clean_sidecar(side, meta["domain"]))
    monkeypatch.setattr(collection, "retazec", lambda *a, **kw: result)
    seal(session)
    good = session / "audit_good.json"
    assert collection.audit_session(session, p, session / "protocol.json", good) == 0
    end = logs.read_json(session / "end.json")
    write(session / "end.json", dict(end, traffic_rc=-9))
    rejected = session / "audit_rejected.json"
    assert collection.audit_session(session, p, session / "protocol.json", rejected) == 2
    values = logs.read_json(rejected)["values"]
    assert values["quality"]["behavior_valid_rows"] == 10
    assert values["coverage"]["scorable_windows"] == 7
    assert "logs: child_exit:traffic:-9" in values["reasons"]
    assert logs.read_json(good)["values"]["accepted"] is True
