"""The realism metrics of proposal 5.7, the offered-load check of proposal 5.3 and the log audit of the traffic of
the v5 profiles (package B5b, agent M; skeleton B5 section 5 item 5).

Synthetic sessions only: scripts/tests/test_collection_logs.py build() and v5_traffic(), the one helper every
schema-3 test session takes its /2 traffic from. The protocol documents here are schema-3 documents of the S3
shape with the four v5 scenarios; they take the profiles section of config/collection-v5.json, which agent T of
B5b adds, and until it is there a stand-in of design B5b 1.1 (STAND_IN). The log audit reads protocol.json
itself, so no loader is involved. Known answers are computed here from the logs with the statistics module and
the envelope oracle test_collection_logs.area, never with scripts/traffic_log.py. Names package B5b adds are
imported or read inside the tests, so this file collects on the code before B5b and fails there test by test.
"""
import ast
import copy
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys

import pytest

from scripts import collection_logs as logs, traffic_log as tl
from scripts.tests import boundary_sessions as bs, test_collection_logs as evidence
from scripts.tests import test_traffic_log as sample

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ("steady", "bursty", "office", "office_busy")  # v5_sections: eshop low and high, corp low and high.
MEASURE_S = 60
# The keys of design B5b 1.1 this package reads (agent T names the rest); used until the file has the section.
STAND_IN = {name: {"arrivals": {"ramp_s": 120, "wave_period_s": [1200, 2400], "peak_s": [120, 240], "note": "test"},
                   "max_concurrent": 50, "client_errors": {"share": .02, "statuses": [400, 401, 404], "note": "test"},
                   "think_s": {"mean": 7, "max": 70, "note": "test"}, "note": "test",
                   **({"order_share": {"low": .05, "high": .2}, "zipf_s": 1} if name == "eshop" else {})}
            for name in ("eshop", "corp")}


@pytest.fixture(scope="module")
def p(tmp_path_factory):
    """A schema-3 protocol of the S3 shape with the four v5 scenarios and the profiles section."""
    doc = bs.protocol_doc(bs.profile_dir(tmp_path_factory.mktemp("realism") / "profile"),
                          schema="hyptcn3/collection-protocol/3", cycles=96, pilot_cycles=80, window_rows=8,
                          full_every=64, gate=bs.worst_gate(96, 8, 64, bs.RULE["max"]), name="realism",
                          scenarios={name: {} for name in SCENARIOS})
    doc.update(bs.audit_sections(1))
    doc.setdefault("profiles", copy.deepcopy(json.loads(bs.V5.read_text()).get("profiles", STAND_IN)))
    return doc


def session(root, p, scenario, *, event=False, measure_s=MEASURE_S, snapshots=10, **variant):
    """A sealed session of build() under p in `scenario` (`snapshots` cycles), its traffic that of the profile
    (v5_traffic)."""
    d = evidence.build(Path(root), event=event, measure_s=measure_s, snapshots=snapshots)
    evidence.write(d / "protocol.json", p)
    meta = json.loads((d / "session.json").read_text())
    evidence.write(d / "session.json", dict(meta, scenario=scenario, protocol_sha256=logs.digest(d / "protocol.json")))
    evidence.v5_traffic(d, p, **variant)
    evidence.seal(d)
    return d


def audit(d):
    return logs.audit_logs(d, snapshot_times=[evidence.BASE + 1.1, evidence.BASE + 2.5])


def records(d, name="traffic_requests.jsonl"):
    return [json.loads(line) for line in (d / name).read_text().splitlines()]


def requirement(found, name):
    return next(r for r in found["requirements"] if r["name"] == name)


def realism(d, p, windows=()):
    meta = json.loads((d / "session.json").read_text())
    return tl.realism(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", p, meta["scenario"],
                      windows=windows)


def windows_of(d):
    """The event windows as the log audit has them: [host start - 1 s, host stop done + grace]."""
    meta = json.loads((d / "session.json").read_text())
    return [(e["host_start_unix"] - 1, e["host_stopped_unix"] + meta["event_grace_s"])
            for e in json.loads((d / "events.json").read_text())["events"]]


# The clean traffic of each scenario passes the whole log audit; the realism section says why.

@pytest.mark.parametrize("scenario, event", [("steady", True), ("bursty", False), ("office", True),
                                             ("office_busy", False)])
def test_clean_v5_session_passes_the_log_audit_with_every_requirement(tmp_path, p, scenario, event):
    d = session(tmp_path, p, scenario, event=event)
    result = audit(d)
    assert result["accepted"], result["problems"]
    found = result["sections"]["realism"]
    profile = p["scenarios"][scenario]["profile"]
    names = [r["name"] for r in found["requirements"]]
    assert names == [n for n in tl.REALISM if profile in tl.REALISM_PROFILES.get(n, (profile,))]
    assert all(r["ok"] for r in found["requirements"]) and found["offered_load"]["ok"]
    assert set(found) == {"requirements", "offered_load"}
    assert result["sections"]["traffic"]["log_schema"] == tl.REQUEST_SCHEMA_2
    assert result["tolerated"]["event_traffic_exit"] == 0
    # The exit code the request log implies: 0 when every request got its expected result (the deliberate errors
    # their intended status), 1 with a failure inside an event window.
    rows = [r for r in records(d) if r.get("type") == "request"]
    unexpected = [r for r in rows if (r["outcome"] != "ok" if r.get("intended_status") is None
                                      else r["status"] != r["intended_status"])]
    assert json.loads((d / "end.json").read_text())["traffic_rc"] == int(bool(unexpected)) == int(event)


def test_realism_of_a_synthetic_log_gives_exactly_its_known_values(tmp_path, p):
    """eshop with the event of build(): every value recomputed here from the logs (skeleton B5 section 5 item 5)."""
    d = session(tmp_path, p, "steady", event=True)
    found = realism(d, p, windows_of(d))
    rows, ivs = records(d), [r for r in records(d, "traffic_intervals.jsonl") if r.get("type") == "interval"]
    header = rows[0]
    t, level = header["envelope"]["t_s"], header["envelope"]["level"]
    base, low = header["start_unix"], [lo for lo, _ in windows_of(d)]
    arrivals = [r for r in rows if r.get("type") == "arrival" and r["phase"] == "measure"]
    points = [evidence.area(t, level, 0, a["t_mono"]) for a in arrivals]
    spacings = [b - a for a, b in zip(points, points[1:])]
    cv = statistics.pstdev(spacings) / statistics.mean(spacings)
    assert len(spacings) == len(evidence.SPACINGS) and cv == pytest.approx(math.sqrt(1.125), abs=1e-4)
    requests = [r for r in rows if r.get("type") == "request" and r["phase"] == "measure"]
    thinks = [r["think_s"] for r in requests if r["think_s"] is not None]
    outside = [r for r in requests if r["t_start_mono"] > 1.7]  # build()'s window ends 1.7 s after the start
    sizes = [r["response_bytes"] for r in outside if r["outcome"] == "ok"]
    measure = [iv for iv in ivs if iv["phase"] == "measure"]
    start, end = measure[0]["mono_start"], measure[-1]["mono_end"]
    kept = [iv for iv in measure if iv["mono_start"] >= 2]  # The intervals after the window
    assert low and all(base + 2 > hi for _, hi in windows_of(d))
    design = p["profiles"]["eshop"]
    expected = {
        "arrival_cv": round(cv, 6),
        "think_time": {"mean": round(statistics.mean(thinks), 6), "max": max(thinks), "n": len(thinks)},
        "order_share": round(1 / 10, 6), "object_concentration": round(10 / 17, 6),
        "success_rate": round((len(outside) - 1) / len(outside), 6),
        "response_sizes": round(math.log10(max(sizes) / min(sizes)), 6),
        "peak_to_mean": round(max(level) / (evidence.area(t, level, start, end) / (end - start)), 6)}
    assert {r["name"]: r["value"] for r in found["requirements"]} == expected
    assert (len(thinks), max(thinks), len(outside), max(sizes), min(sizes)) == (23, 12., 33, 150000, 10)
    assert requirement(found, "think_time")["bound"] == {
        "mean": design["think_s"]["mean"], "max": design["think_s"]["max"],
        "tolerance": round(4 * statistics.stdev(thinks) / math.sqrt(len(thinks)), 6),
        "lag_s": 1.0}  # Package B10: the generator's own delay a realized maximum may add (judgment, THINK_LAG_S).
    assert requirement(found, "order_share")["bound"] == {
        "share": design["order_share"]["low"],
        "tolerance": round(4 * math.sqrt(design["order_share"]["low"] * (1 - design["order_share"]["low"]) / 10), 6)}
    assert requirement(found, "peak_to_mean")["value"] == pytest.approx(MEASURE_S / evidence.area(t, level, 0, 1e9),
                                                                        abs=1e-6)
    planned = sum(iv["planned_sessions"] for iv in kept)
    assert found["offered_load"] == {"offered": 10, "planned": round(planned, 6), "ratio": round(10 / planned, 6),
                                     "ok": True}
    assert planned == pytest.approx(header["rate"] * evidence.area(t, level, 2, end), abs=1e-5)


def test_background_of_corp_gives_exactly_its_known_values(tmp_path, p):
    d = session(tmp_path, p, "office")
    found = realism(d, p)
    assert requirement(found, "background")["value"] == {"logins": 9, "reports": 2,
                                                         "document_max_to_median": round(900000 / 64000, 6)}
    assert requirement(found, "background")["bound"] == {"logins_min": 1, "reports_min": 1,
                                                         "document_max_to_median": 10}
    assert requirement(found, "object_concentration")["value"] == round(7 / 11, 6)
    assert {"think_time", "order_share"}.isdisjoint(r["name"] for r in found["requirements"])


BROKEN = ("arrival_cv", "think_time", "order_share", "object_concentration", "success_rate", "response_sizes",
          "peak_to_mean", "background", "offered_load_differs_from_plan")


def broken(name):
    """(scenario, arguments of v5_traffic) of a log that breaks the requirement `name` and nothing else."""
    from scripts.tests.audit_cases_logs import _distinct
    e = evidence
    return {
        "arrival_cv": ("steady", {"spacings": (1.,) * (len(e.ESHOP) - 1)}),  # Evenly spaced: CV 0.
        # Four think times of 75 s in a user session need a longer measure phase than 60 s, and the protocol's
        # planned run of the session's cycles covers it (package B10: the realized think times, F6 of B5b).
        "think_time": ("steady", {"thinks": (75.,), "measure_s": 400, "snapshots": 400}),
        "order_share": ("steady", {"sessions": tuple(s if e.ORDER in s else [*s, e.CART_ADD, e.ORDER]
                                                     for s in e.ESHOP)}),
        "object_concentration": ("steady", {"sessions": _distinct(e.ESHOP)}),
        "success_rate": ("steady", {"sessions": tuple([e.DETAIL if s == e.UNKNOWN else s for s in steps]
                                                      for steps in e.ESHOP)}),
        "response_sizes": ("steady", {"sessions": tuple([s._replace(bytes=200) for s in steps] for steps in e.ESHOP)}),
        "peak_to_mean": ("steady", {"flat": True}),
        "background": ("office", {"sessions": tuple([s for s in steps if s != e.REPORT] for steps in e.CORP)}),
        "offered_load_differs_from_plan": ("bursty", {"rate_factor": 2}),
    }[name]


@pytest.mark.parametrize("name", BROKEN)
def test_a_log_that_breaks_one_requirement_is_refused_with_its_name(tmp_path, p, name):
    """One log per requirement that breaks it, and nothing else: its named reason (skeleton B5 section 5 item 5)."""
    scenario, variant = broken(name)
    d = session(tmp_path, p, scenario, **variant)
    result = audit(d)
    reason = name if name == "offered_load_differs_from_plan" else "traffic_realism:" + name
    assert result["problems"] == [reason]
    found = result["sections"]["realism"]
    failed = [r["name"] for r in found["requirements"] if not r["ok"]] + (
        ["offered_load_differs_from_plan"] if not found["offered_load"]["ok"] else [])
    assert failed == [name]


def test_the_think_time_is_that_of_the_request_times_not_the_logged_draw(tmp_path, p):
    """Finding F6 of the B5b verification (package B10): think_time judges the realized think times, the start of a
    request minus the end of the request before it in its user session, not the drawn think_s the generator logs. The
    verifier's probe: the clean session of eshop, its requests of the measure phase moved to 1 ms after the end of
    the one before, think_s unchanged, fails think_time with the realized times as its value; the clean session,
    whose requests follow by their think times, passes with the same times as think_s says."""
    d = session(tmp_path, p, "steady")

    def realized(rows):
        out = []
        for uid in sorted({r["user_session"] for r in rows if r.get("type") == "request"}):
            mine = sorted((r for r in rows if r.get("type") == "request" and r["user_session"] == uid),
                          key=lambda r: r["t_start_mono"])
            out += [round(b["t_start_mono"] - a["t_end_mono"], 6) for a, b in zip(mine, mine[1:])
                    if b["phase"] == "measure"]
        return out
    rows = records(d)
    logged = [r["think_s"] for r in rows if r.get("type") == "request" and r["phase"] == "measure"
              and r["think_s"] is not None]
    assert sorted(realized(rows)) == sorted(logged) and requirement(realism(d, p), "think_time")["ok"]
    for uid in {r["user_session"] for r in rows if r.get("type") == "request" and r["phase"] == "measure"}:
        mine = sorted((r for r in rows if r.get("type") == "request" and r["user_session"] == uid),
                      key=lambda r: r["t_start_mono"])
        for before, r in zip(mine, mine[1:]):
            r["t_start_mono"] = round(before["t_end_mono"] + .001, 6)
            r["t_end_mono"] = round(r["t_start_mono"] + r["duration_ms"] / 1000, 6)
    evidence.jsonl(d / "traffic_requests.jsonl", rows)
    times = realized(rows)
    found = requirement(realism(d, p), "think_time")
    assert [r["think_s"] for r in rows if r.get("type") == "request" and r["phase"] == "measure"
            and r["think_s"] is not None] == logged  # The draws as logged.
    assert found["value"] == {"mean": round(statistics.mean(times), 6), "max": max(times), "n": len(times)}
    assert max(times) < 1 and not found["ok"]


# Package B10, F7 of the B5b verification (its mutants M18 to M21, M23, M28 and M29): the other side of each two-sided
# bound, and each part of the background on its own; one log each that breaks the requirement and nothing else.
GONE = evidence.Step("detail", "GET", "/api/catalog/7", 7, 404, 40, 404)  # A deliberate 404 on the top object.
OTHER_SIDE = {
    # Eight spacings of 0.25 and one of 4: CV 1.77, above 1.2.
    "arrival_cv:above": ("steady", {"spacings": (.25,) * (len(evidence.ESHOP) - 2) + (4.,)}),
    # Every drawn think 20 s: the mean 19.1 s lies far from the profile's 7 s, and every think is below its 70 s.
    # The requests follow by their think times (F6 of B5b), so the measure phase is 200 s of 200 cycles.
    "think_time:mean": ("steady", {"thinks": (20.,), "measure_s": 200, "snapshots": 200}),
    # Four more deliberate 404s (on the most requested object, so the concentration holds): 34 of 39 answered 2xx,
    # 0.872, below success_min 0.88.
    "success_rate:below_min": ("steady", {"sessions": tuple([*steps, GONE] if i < 4 else steps
                                                            for i, steps in enumerate(evidence.ESHOP))}),
    # 70 user sessions of eshop high, none of them orders: 0 against 0.2 within 0.19 (4 standard errors of 70).
    "order_share:too_few": ("bursty", {"sessions": tuple([s for s in steps if s not in (evidence.ORDER, evidence.CART,
                                                                                         evidence.CART_ADD)]
                                                         for steps in evidence.ESHOP) * 7,
                                       "spacings": (.25, .25, 2.5) * 23}),
    "offered_load_differs_from_plan:above": ("bursty", {"rate_factor": .5}),  # Twice the planned user sessions.
    "background:logins": ("office", {"sessions": tuple([s for s in steps if s != evidence.LOGIN]
                                                       for steps in evidence.CORP)}),  # No login at all.
    # The largest download 200000 bytes, 3.1 times the median one (64000): no tail of 10 times.
    "background:tail": ("office", {"sessions": tuple([s._replace(bytes=200000) if s.bytes == 900000 else s
                                                      for s in steps] for steps in evidence.CORP)}),
}


@pytest.mark.parametrize("case", OTHER_SIDE)
def test_a_log_that_breaks_the_other_side_of_a_requirement_is_refused_with_its_name(tmp_path, p, case):
    name = case.split(":")[0]
    scenario, variant = OTHER_SIDE[case]
    d = session(tmp_path, p, scenario, **variant)
    result = audit(d)
    reason = name if name == "offered_load_differs_from_plan" else "traffic_realism:" + name
    assert result["problems"] == [reason]
    found = result["sections"]["realism"]
    failed = [r["name"] for r in found["requirements"] if not r["ok"]] + (
        ["offered_load_differs_from_plan"] if not found["offered_load"]["ok"] else [])
    assert failed == [name]


def test_the_offered_load_is_summed_over_the_intervals_outside_every_window(tmp_path, p):
    """F7 of the B5b verification (package B10, mutant M27): the offered and the planned user sessions are both summed
    over the measure-phase intervals that overlap no window. The clean log offers its plan exactly over every
    interval; windows inside the two intervals that hold two arrivals each leave 6 offered of about 8.93 planned,
    a ratio below the tolerance of 0.2."""
    d = session(tmp_path, p, "steady")
    start = records(d)[0]["start_unix"]
    ivs = [r for r in records(d, "traffic_intervals.jsonl") if r.get("type") == "interval" and r["phase"] == "measure"]
    busy = [iv for iv in ivs if iv["offered_sessions"] == 2]
    kept = [iv for iv in ivs if iv["offered_sessions"] != 2]
    offered, planned = sum(iv["offered_sessions"] for iv in kept), sum(iv["planned_sessions"] for iv in kept)
    assert (len(busy), offered, realism(d, p)["offered_load"]["ok"]) == (2, 6, True)
    windows = [(start + iv["mono_start"] + .1, start + iv["mono_end"] - .1) for iv in busy]
    assert realism(d, p, windows)["offered_load"] == {"offered": 6, "planned": round(planned, 6),
                                                      "ratio": round(6 / planned, 6), "ok": False}


def test_the_cv_is_computed_on_spacings_rescaled_by_the_envelope(tmp_path, p):
    """The same arrival times judged against a flat envelope give another CV: the rescaling is the planned one."""
    d = session(tmp_path, p, "steady")
    rescaled = requirement(realism(d, p), "arrival_cv")["value"]
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
        rows = records(d, name)
        rows[0]["envelope"] = {"t_s": [0, rows[0]["envelope"]["t_s"][-1]], "level": [1, 1]}
        evidence.jsonl(d / name, rows)
    times = [r["t_mono"] for r in records(d) if r.get("type") == "arrival" and r["phase"] == "measure"]
    raw = [b - a for a, b in zip(times, times[1:])]
    assert requirement(realism(d, p), "arrival_cv")["value"] == round(statistics.pstdev(raw) / statistics.mean(raw), 6)
    assert rescaled == pytest.approx(math.sqrt(1.125), abs=1e-4) != requirement(realism(d, p), "arrival_cv")["value"]


@pytest.mark.parametrize("change, message", [
    (lambda p: p["scenarios"].pop("steady"), "unknown scenario: steady"),
    (lambda p: p["scenarios"]["steady"].update(profile="batch"), "unknown profile: batch"),
    (lambda p: p.pop("profiles"), "protocol has no profiles section entry: eshop"),
    (lambda p: p.update(schema="hyptcn3/collection-protocol/2", audit=None) or p.pop("audit"),
     "the realism requirements need a protocol of schema 3"),
], ids=["scenario", "profile", "profiles", "schema"])
def test_realism_refuses_what_it_cannot_judge(tmp_path, p, change, message):
    d = session(tmp_path, p, "steady")
    q = copy.deepcopy(p)
    change(q)
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        realism(d, q)


def test_realism_refuses_logs_of_schema_1(tmp_path, p):
    d = evidence.build(tmp_path)
    with pytest.raises(ValueError, match="need the logs of a v5 profile"):
        tl.realism(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", p, "steady")


def test_cli_prints_the_requirements_and_exits_by_them(tmp_path, p):
    d = session(tmp_path, p, "steady")
    (tmp_path / "p.json").write_text(json.dumps(p))
    command = [sys.executable, ROOT / "scripts/traffic_log.py", "realism", "--requests", d / "traffic_requests.jsonl",
               "--intervals", d / "traffic_intervals.jsonl", "--protocol", tmp_path / "p.json", "--scenario"]
    good = subprocess.run([*command, "steady"], capture_output=True, text=True, timeout=60)
    assert good.returncode == 0, good.stderr
    assert set(json.loads(good.stdout)) == {"requirements", "offered_load"}
    other = subprocess.run([*command, "office"], capture_output=True, text=True, timeout=60)  # corp: no background
    assert other.returncode == 2 and not requirement(json.loads(other.stdout), "background")["ok"]
    bad = subprocess.run([*command, "nothing"], capture_output=True, text=True, timeout=60)
    assert bad.returncode == 2 and "unknown scenario: nothing" in bad.stderr


# summarize() on /2 logs: the cross-checks of the new counts, one inconsistency each with its exact problem.

def _arrivals(rows):
    return [r for r in rows if r.get("type") == "arrival"]


def _requests(rows):
    return [r for r in rows if r.get("type") == "request"]


def _user(n):
    return f"{sample.RUN}-u{n}"  # User session n in arrival order: u0 to u3 those of build()'s requests.


FIRST = f"{sample.RUN}-01-00000000"  # The first request of the first user session of the measure phase (u4),
EXTRA = f"{sample.RUN}-01-00000001"  # and its second one.
LAST = 13  # The last user session (u13), alone in its interval: removing or doubling it touches nothing else.


def _headers(r, i, change):
    for rows in (r, i):
        change(rows[0])


def _rid_of(r, rid):
    return next(x for x in _requests(r) if x["rid"] == rid)


def _interval_of(i, t):
    return next(x for x in i if x.get("type") == "interval" and x["mono_start"] <= t < x["mono_end"])


def _requests_of(r, n):
    return [x["rid"] for x in _requests(r) if x["user_session"] == _user(n)]


def m_header_missing(r, i, p):
    r[0].pop("load_model")
    return ["v5_header_missing:load_model"]


def m_header_mismatch(r, i, p):
    i[0]["warmup_s"] += 1
    return ["v5_header_mismatch:warmup_s"]


def m_envelope(r, i, p):
    _headers(r, i, lambda h: h["envelope"]["t_s"].__setitem__(0, 1))
    return ["envelope_invalid:times"]


def m_rate(r, i, p):
    _headers(r, i, lambda h: h.update(rate=0))
    return ["rate_invalid"]


def m_rate_source(r, i, p):
    _headers(r, i, lambda h: h.update(rate_source="guess"))
    return ["rate_source_invalid"]


def m_seeds(r, i, p):
    _headers(r, i, lambda h: h["seeds"].pop("traffic_sizes"))
    return ["seeds_invalid"]


def m_warmup(r, i, p):
    _headers(r, i, lambda h: h.update(warmup_s=h["envelope"]["t_s"][-1]))  # Not before D.
    return ["warmup_invalid"]


def m_profile(r, i, p):
    _headers(r, i, lambda h: h.update(profile="lab"))
    return ["profile_unknown:lab"]


def m_max_concurrent(r, i, p):
    _headers(r, i, lambda h: h["profile_parameters"].pop("max_concurrent"))
    return ["profile_parameters_invalid:max_concurrent"]


def m_statuses(r, i, p):
    _headers(r, i, lambda h: h["profile_parameters"]["client_errors"].update(statuses=[]))
    return ["profile_parameters_invalid:client_errors",
            *(f"intended_status_unknown:{x['rid']}" for x in _requests(r) if x["intended_status"] is not None)]


def m_arrival_malformed(r, i, p):
    last = _arrivals(r)[LAST]
    last.pop("active")
    return [f"arrival_malformed:{_user(LAST)}", f"interval_arrivals:{_interval_of(i, last['t_mono'])['interval']}",
            *(f"request_user_session_unknown:{rid}" for rid in _requests_of(r, LAST)),
            f"requests:end_arrivals_mismatch:admitted:{LAST + 1}!={LAST}"]


def m_user_session_id(r, i, p):
    for x in r:
        if x.get("user_session") == _user(4):
            x["user_session"] = "u4"
    return ["user_session_id:u4"]


def m_duplicate(r, i, p):
    r.insert(r.index(_arrivals(r)[LAST]) + 1, dict(_arrivals(r)[LAST]))
    r[-1]["records"] += 1  # Written by the generator: the end record counts it.
    return [f"duplicate_user_session:{_user(LAST)}", "arrivals_outside_intervals:1",
            f"requests:end_arrivals_mismatch:arrivals:{LAST + 1}!={LAST + 2}",
            f"requests:end_arrivals_mismatch:admitted:{LAST + 1}!={LAST + 2}"]


def m_order(r, i, p):
    fifth, fourth = _arrivals(r)[5], _arrivals(r)[4]
    index = _interval_of(i, fifth["t_mono"])["interval"]
    fifth["t_mono"] = fourth["t_mono"] - 1e-3  # Still in u4's interval, before it: u4 lands in u5's interval.
    return [f"arrival_order:{_user(5)}", f"interval_arrivals:{index}"]


def m_cap(r, i, p):
    _arrivals(r)[4]["active"] = p["profiles"]["eshop"]["max_concurrent"]  # Admitted at the cap.
    return [f"arrival_cap:{_user(4)}"]


def m_dropped(r, i, p):
    last = _arrivals(r)[LAST]
    last.update(admitted=False, active=p["profiles"]["eshop"]["max_concurrent"],  # Dropped at the cap, but counted
                drop_reason="max_concurrent")  # as admitted, and its requests were sent.
    index = _interval_of(i, last["t_mono"])["interval"]
    return [f"interval_sessions:{index}:admitted_sessions:1!=0", f"interval_sessions:{index}:dropped_sessions:0!=1",
            *(f"request_user_session_dropped:{rid}" for rid in _requests_of(r, LAST)),
            f"requests:end_arrivals_mismatch:admitted:{LAST + 1}!={LAST}",
            f"requests:end_arrivals_mismatch:dropped:0!=1"]


# Finding F1 of the B5c verification (package B10): the drop reason and the customer of an arrival are read.

def m_drop_reason(r, i, p):
    _arrivals(r)[4]["drop_reason"] = "max_concurrent"  # Admitted, with the reason of a drop.
    return [f"arrival_drop_reason:{_user(4)}"]


def m_customers_held(r, i, p):
    last = _arrivals(r)[LAST]  # All customers held while fewer user sessions than customers are in progress.
    last.update(admitted=False, drop_reason="all_customers_held")
    return [f"arrival_customers:{_user(LAST)}", *_dropped_counts(r, i, last)]


def _dropped_counts(r, i, last):
    index = _interval_of(i, last["t_mono"])["interval"]
    return [f"interval_sessions:{index}:admitted_sessions:1!=0", f"interval_sessions:{index}:dropped_sessions:0!=1",
            *(f"request_user_session_dropped:{rid}" for rid in _requests_of(r, LAST)),
            f"requests:end_arrivals_mismatch:admitted:{LAST + 1}!={LAST}",
            f"requests:end_arrivals_mismatch:dropped:0!=1"]


def m_customer_unknown(r, i, p):
    _arrivals(r)[4]["customer"] = "zakaznik9999"  # lab/seed.py has 2000 customers.
    return [f"arrival_customer:{_user(4)}"]


def m_customer_held_twice(r, i, p):
    # u1 of build() orders and holds zakaznik0001 until its order ends at 1.5 s; u2 arrives in that time.
    assert _arrivals(r)[1]["customer"] == "zakaznik0001" and _arrivals(r)[2]["customer"] is None
    _arrivals(r)[2]["customer"] = "zakaznik0001"
    return [f"customer_held_twice:{_user(2)}"]


def m_interval_offered(r, i, p):
    iv = _interval_of(i, _arrivals(r)[LAST]["t_mono"])
    iv.update(offered_sessions=2, admitted_sessions=2)  # One more than arrived in it, and in no other.
    return [f"interval_arrivals:{iv['interval']}"]


def m_interval_admitted(r, i, p):
    iv = _interval_of(i, _arrivals(r)[LAST]["t_mono"])
    iv.update(admitted_sessions=0, dropped_sessions=1)
    return [f"interval_sessions:{iv['interval']}:admitted_sessions:0!=1",
            f"interval_sessions:{iv['interval']}:dropped_sessions:1!=0"]


def m_interval_sum(r, i, p):
    iv = _interval_of(i, _arrivals(r)[LAST]["t_mono"])
    iv["dropped_sessions"] = 1
    return [f"interval_sessions:{iv['interval']}:dropped_sessions:1!=0", f"interval_sessions:{iv['interval']}:offered"]


def m_planned(r, i, p):
    iv = _interval_of(i, _arrivals(r)[LAST]["t_mono"])
    iv["planned_sessions"] += .01
    return [f"planned_sessions:{iv['interval']}"]


def m_active_max(r, i, p):
    iv = _interval_of(i, _arrivals(r)[LAST]["t_mono"])
    iv["active_max"] = p["profiles"]["eshop"]["max_concurrent"] + 1
    return [f"active_max:{iv['interval']}"]


def m_interval_malformed(r, i, p):
    iv = _interval_of(i, _arrivals(r)[LAST]["t_mono"])
    iv.pop("planned_sessions")
    return [f"interval_v5_malformed:{iv['interval']}"]


def m_request_malformed(r, i, p):
    _rid_of(r, EXTRA).pop("step")
    return [f"request_v5_malformed:{EXTRA}"]


def m_unknown(r, i, p):
    _rid_of(r, EXTRA).update(user_session="unknown")
    return [f"request_user_session_unknown:{EXTRA}"]


def m_before_arrival(r, i, p):
    _arrivals(r)[4]["t_mono"] += .0015  # After its first request, before the second.
    return [f"request_before_arrival:{FIRST}"]


def m_think_first(r, i, p):
    _rid_of(r, FIRST)["think_s"] = 1.
    return [f"think_s_first:{FIRST}"]


def m_think_missing(r, i, p):
    _rid_of(r, EXTRA)["think_s"] = None
    return [f"think_s_missing:{EXTRA}"]


def m_intended(r, i, p):
    _rid_of(r, EXTRA)["intended_status"] = 500
    return [f"intended_status_unknown:{EXTRA}"]


def m_end_invalid(r, i, p):
    r[-1].pop("dropped")
    return ["requests:end_v5_invalid:dropped"]


def m_end_arrivals(r, i, p):
    r[-1]["arrivals"] -= 1
    return [f"requests:end_arrivals_mismatch:arrivals:{LAST}!={LAST + 1}"]


def m_end_user_sessions(r, i, p):
    r[-1]["user_sessions_completed"] -= 1
    return ["requests:end_user_sessions_mismatch"]


MUTATIONS = {name[2:]: function for name, function in sorted(globals().items()) if name.startswith("m_")}


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_summarize_cross_checks_the_counts_of_v5_logs(tmp_path, p, name):
    """Each inconsistency of a /2 pair, and only it, gives its exact problems (design B5b 1.4)."""
    d = session(tmp_path, p, "steady")
    r, i = ([{k: v for k, v in x.items() if k not in ("schema", "n")} for x in records(d, file)]
            for file in ("traffic_requests.jsonl", "traffic_intervals.jsonl"))
    assert len(_arrivals(r)) == LAST + 1 and len({x["interval"] for x in i if x.get("offered_sessions")}) > 5
    expected = MUTATIONS[name](r, i, p)
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA_2, r)
    sample.write(d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA_2, i)
    found = tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", schema=tl.REQUEST_SCHEMA_2)
    assert found["problems"] == expected


def test_summarize_keeps_the_schema_the_caller_names(tmp_path, p):
    """/1 logs as before; with the /2 schema named they are refused, and so are /2 logs as /1."""
    old = evidence.build(tmp_path / "old")
    pair = (old / "traffic_requests.jsonl", old / "traffic_intervals.jsonl")
    assert tl.summarize(*pair)["problems"] == [] and tl.summarize(*pair)["log_schema"] == tl.REQUEST_SCHEMA
    assert tl.summarize(*pair, schema=tl.REQUEST_SCHEMA_2)["problems"][:2] == [
        "requests:schema_mismatch:" + tl.REQUEST_SCHEMA, "intervals:schema_mismatch:" + tl.INTERVAL_SCHEMA]
    new = session(tmp_path / "new", p, "steady")
    pair = (new / "traffic_requests.jsonl", new / "traffic_intervals.jsonl")
    assert tl.summarize(*pair)["problems"] == [] and tl.summarize(*pair)["arrivals"] == {
        "offered": 14, "admitted": 14, "dropped": 0, "measure": {"offered": 10, "admitted": 10, "dropped": 0}}
    assert tl.summarize(*pair, schema=tl.REQUEST_SCHEMA)["problems"][:2] == [
        "requests:schema_mismatch:" + tl.REQUEST_SCHEMA_2, "intervals:schema_mismatch:" + tl.INTERVAL_SCHEMA_2]
    with pytest.raises(ValueError, match="^unknown traffic log schema: x$"):
        tl.summarize(*pair, schema="x")


def test_an_arrival_on_an_interval_bound_may_belong_to_either_interval(tmp_path, p):
    d = session(tmp_path, p, "steady")
    rows = [{k: v for k, v in r.items() if k not in ("schema", "n")} for r in records(d)]
    ivs = [{k: v for k, v in r.items() if k not in ("schema", "n")} for r in records(d, "traffic_intervals.jsonl")]
    first = next(a for a in _arrivals(rows) if a["phase"] == "measure")
    iv = next(r for r in ivs if r.get("type") == "interval" and r["mono_start"] <= first["t_mono"] < r["mono_end"])
    first["t_mono"] = iv["mono_end"] + 5e-7  # Counted in its interval, after its end within the rounding
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA_2, rows)
    found = tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", schema=tl.REQUEST_SCHEMA_2)
    assert [x for x in found["problems"] if not x.startswith("request_before_arrival")] == []
    first["t_mono"] = iv["mono_end"] + 1e-3
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA_2, rows)
    found = tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", schema=tl.REQUEST_SCHEMA_2)
    assert f"interval_arrivals:{iv['interval']}" in found["problems"]


# The log audit under a protocol with the profiles section.

def _change(d, rid, **fields):
    from scripts.tests.audit_cases_logs import change_request
    change_request(rid, **fields)(d, None, None)


def test_a_deliberate_client_error_passes_only_with_its_own_status(tmp_path, p):
    d = session(tmp_path, p, "steady")
    error = f"{sample.RUN}-05-00000001"  # The 404 of an unknown product.
    row = next(r for r in records(d) if r.get("rid") == error)
    assert (row["status"], row["intended_status"], row["outcome"]) == (404, 404, "http_error")
    _change(d, error, status=400)
    assert audit(d)["problems"] == ["intended_status_differs:" + error]
    d = session(tmp_path / "plain", p, "steady")
    plain = f"{sample.RUN}-01-00000002"  # A product detail without an intended status.
    _change(d, plain, status=404, outcome="http_error")
    assert audit(d)["problems"] == ["request_failed:" + plain]


def test_the_exit_code_must_be_the_one_the_request_log_implies(tmp_path, p):
    d = session(tmp_path, p, "steady", **broken("success_rate")[1])  # No failed request at all
    assert json.loads((d / "end.json").read_text())["traffic_rc"] == 0
    assert audit(d)["problems"] == ["traffic_realism:success_rate"]
    end = json.loads((d / "end.json").read_text())
    evidence.write(d / "end.json", dict(end, traffic_rc=1))
    assert audit(d)["problems"] == ["child_exit:traffic:1", "traffic_realism:success_rate"]


@pytest.mark.parametrize("rid, unit, path, problem", [
    (f"{sample.RUN}-01-00000002", "hyptcn-lab@docs", "/api/docs/5", "service_request_count"),  # docs serves it
    (f"{sample.RUN}-01-00000002", "hyptcn-lab@auth", "/api/auth/check", "service_auth_call"),  # after the token check
    (f"{sample.RUN}-04-00000001", "hyptcn-lab@docs", "/api/reports", "service_request_count"),  # a report request
    (f"{sample.RUN}-01-00000000", "hyptcn-lab@auth", "/api/auth/login", "service_request_count"),  # a login
], ids=["docs", "docs_token", "report", "login"])
def test_the_services_of_corp_are_correlated(tmp_path, p, rid, unit, path, problem):
    from scripts.tests.audit_cases_logs import drop_service_line
    d = session(tmp_path, p, "office")
    method = next(r["method"] for r in records(d) if r.get("rid") == rid)
    if method != "GET":  # drop_service_line names GET lines; the same for another method
        def lines(text):
            return [line for line in text if not (f"rid={rid} method={method} path={path} " in line)]
        evidence._segment(d, "journal", "journal.txt", lines)
        evidence.seal(d)
    else:
        drop_service_line(rid, unit, path)(d, p, None)
    assert audit(d)["problems"] == [f"{problem}:{rid}"]


def test_the_cart_and_a_refused_token_are_correlated(tmp_path, p):
    """The orders service checks the token for the cart; a token auth refuses is a 401 of both."""
    from scripts.tests.audit_cases_logs import drop_service_line
    e = evidence
    refused = e.Step("doc_get", "GET", "/api/docs/5", 5, 401, 40, 401)
    d = session(tmp_path, p, "office", sessions=(*e.CORP[:-1], [e.LOGIN, refused]))
    assert audit(d)["accepted"]
    rid = f"{sample.RUN}-10-00000001"
    journal = evidence.gzip.decompress((d / "guest/journal-journal.txt.gz").read_bytes()).decode()
    assert f"rid={rid} method=GET path=/api/auth/check status=401" in journal
    check = f"rid={rid} method=GET path=/api/auth/check status="
    evidence._segment(d, "journal", "journal.txt", lambda text: [line.replace(check + "401", check + "200")
                                                                 for line in text])
    evidence.seal(d)
    assert audit(d)["problems"] == ["service_auth_call:" + rid]
    d = session(tmp_path / "cart", p, "steady")
    cart = f"{sample.RUN}-04-00000003"
    drop_service_line(cart, "hyptcn-lab@orders", "/api/cart")(d, p, None)
    assert audit(d)["problems"] == ["service_request_count:" + cart]


def test_static_files_and_the_home_page_are_served_by_nginx_alone(tmp_path, p):
    d = session(tmp_path, p, "steady")
    journal = evidence.gzip.decompress((d / "guest/journal-journal.txt.gz").read_bytes()).decode()
    static = [r["rid"] for r in records(d) if r.get("type") == "request" and r["route"].startswith("/static/")]
    assert static and not any(f"rid={rid} " in journal for rid in static) and audit(d)["accepted"]
    assert [logs.upstream(route) for route in ("/", "/static/logo.png", "/nothing", "/api/orders/5")] == [None] * 4


def test_the_route_table_is_the_one_of_lab_nginx_conf():
    """Every location of lab/nginx.conf: the service of its proxy_pass port (lab/services.py PORTS), or nginx."""
    ports = next(ast.literal_eval(node.value) for node in ast.parse((ROOT / "lab/services.py").read_text()).body
                 if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "PORTS")
    by_port = {port: name for name, port in ports.items()}
    found = re.findall(r"location (=\s*)?(\S+) \{([^}]*)\}", (ROOT / "lab/nginx.conf").read_text())
    assert len(found) >= 10
    for exact, prefix, body in found:
        port = re.search(r"proxy_pass http://127\.0\.0\.1:(\d+);", body)
        expected = by_port[int(port[1])] if port else None
        route = prefix if exact else prefix + ("x" if prefix.endswith("/") else "/x")
        assert logs.upstream(route) == expected, route
    assert set(logs.SERVICES) == set(ports)


@pytest.mark.parametrize("method, route, checked", [
    ("GET", "/api/orders", True), ("POST", "/api/orders", True), ("POST", "/api/cart", True),
    ("GET", "/api/docs", True), ("POST", "/api/docs", True), ("GET", "/api/docs/5", True),
    ("POST", "/api/reports", True), ("GET", "/api/reports/x", True), ("GET", "/api/reports", False),
    ("GET", "/api/catalog/5", False), ("POST", "/api/auth/login", False), ("GET", "/healthz", False),
])
def test_the_token_check_follows_lab_services(method, route, checked):
    assert logs.auth_checked(method, route) is checked


def test_the_docs_unit_is_required_like_the_others(tmp_path):
    d = evidence.build(tmp_path)  # Schema 1: the units are the lab's in every protocol.
    path = d / "guest/state_after.json"
    state = json.loads(path.read_text())
    state["units"]["hyptcn-lab@docs"]["ActiveState"] = "failed"
    evidence.write(path, state)
    evidence.seal(d)
    assert logs.audit_logs(d)["problems"] == ["service_unhealthy:after:hyptcn-lab@docs"]
    assert "hyptcn-lab@docs" in logs.REQUIRED_UNITS and "hyptcn-lab@docs" in logs.APPS


def test_logs_of_the_other_schema_are_refused(tmp_path, p):
    """Under the v5 protocol /1 logs fail the traffic section and realism; /2 logs under schema 2 fail too."""
    d = evidence.build(tmp_path / "old")
    evidence.write(d / "protocol.json", p)
    meta = json.loads((d / "session.json").read_text())
    evidence.write(d / "session.json", dict(meta, scenario="steady", protocol_sha256=logs.digest(d / "protocol.json")))
    evidence.seal(d)
    problems = audit(d)["problems"]
    assert "traffic:requests:schema_mismatch:" + tl.REQUEST_SCHEMA in problems
    assert any(x.startswith("realism:unreadable:ValueError: the realism requirements need the logs") for x in problems)
    d = session(tmp_path / "new", p, "steady")
    evidence.write(d / "protocol.json", {"synthetic": True})
    meta = json.loads((d / "session.json").read_text())
    evidence.write(d / "session.json", dict(meta, protocol_sha256=logs.digest(d / "protocol.json")))
    evidence.seal(d)
    result = audit(d)
    assert "traffic:requests:schema_mismatch:" + tl.REQUEST_SCHEMA_2 in result["problems"]
    assert "realism" not in result["sections"]


def test_the_closed_loop_fields_stay_compared_for_logs_of_schema_1(tmp_path):
    """Schema 1 and 2 keep their traffic checks: the closed loop's workers too (since B5b the self-test case of
    traffic_config breaks the target, which both kinds of traffic compare)."""
    d = evidence.build(tmp_path)
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
        rows = records(d, name)
        rows[0]["config"]["workers"] = 99
        evidence.jsonl(d / name, rows)
    evidence.seal(d)
    assert logs.audit_logs(d)["problems"] == ["traffic_config:workers"]


def test_the_helper_gives_the_same_traffic_when_run_again(tmp_path, p):
    """v5_traffic on its own traffic: the cases of the self-test regenerate it with one requirement broken."""
    d = session(tmp_path, p, "steady")
    before = {name: (d / name).read_text() for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl")}
    segments = [evidence.gzip.decompress(f.read_bytes()) for f in sorted((d / "guest").glob("*.gz"))]
    evidence.v5_traffic(d, p)
    assert {name: (d / name).read_text() for name in before} == before
    assert [evidence.gzip.decompress(f.read_bytes()) for f in sorted((d / "guest").glob("*.gz"))] == segments


# The bounds (features/audit_policy.py audit_bounds reads audit.traffic).

@pytest.mark.parametrize("key, value", [
    ("offered_load_tolerance", 1), ("arrival_cv", [1.1, 1.2]), ("arrival_cv", [.8]), ("top_objects_share", 0),
    ("top_objects_min_requests", .1), ("success_min", 1.), ("response_size_orders", 0),
    ("think_mean_tolerance_se", -1), ("order_share_tolerance_se", None), ("background", {"logins_min": 1}),
    ("note", " "), ("extra", 1),
])
def test_a_malformed_traffic_bound_is_refused_with_its_name(p, key, value):
    from features.audit_policy import audit_bounds
    doc = copy.deepcopy(p)
    doc["audit"]["traffic"][key] = value
    name = "" if key == "extra" else "." + key
    with pytest.raises(ValueError, match="^" + re.escape("invalid audit bounds: traffic" + name) + "$"):
        audit_bounds(doc)
    doc = copy.deepcopy(p)
    del doc["audit"]["traffic"]
    with pytest.raises(ValueError, match="^invalid audit bounds$"):
        audit_bounds(doc)


@pytest.mark.parametrize("key, value", [("logins_min", 0), ("reports_min", 1.5), ("document_max_to_median", 1),
                                        ("note", "")])
def test_a_malformed_background_bound_is_refused(p, key, value):
    from features.audit_policy import audit_bounds
    doc = copy.deepcopy(p)
    doc["audit"]["traffic"]["background"][key] = value
    with pytest.raises(ValueError, match="^invalid audit bounds: traffic.background$"):
        audit_bounds(doc)


def test_the_v5_file_bounds_name_their_origin():
    from features.audit_policy import audit_bounds
    doc = json.loads(bs.V5.read_text())
    traffic = audit_bounds(doc)["traffic"]
    assert "judgment" in traffic["note"] and "judgment" in traffic["background"]["note"]
    assert all(chapter in traffic["note"] for chapter in ("5.3", "5.7"))
