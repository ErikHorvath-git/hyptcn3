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
from types import SimpleNamespace

import pytest

from scripts import collection_logs as logs, traffic_log as tl
from scripts.tests import boundary_sessions as bs, test_collection_logs as evidence
from scripts.tests import protokol_g0, test_traffic_log as sample

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
    """A schema-3 protocol of the S3 shape with the four v5 scenarios and the profiles section, taken over from the
    protocol file as the G0 record holds it (scripts/tests/protokol_g0.py): the known answers here are those of the
    null rate, while G2 writes the rates into config/collection-v5.json from its Zápis 1 on. Its audit sections are
    those of the grid of 1 s (boundary_sessions.audit_sections): since package B16 D_max of the order share is the
    file's 242 s scaled to it, 48.4 s, so that the generator's stop of a session of 60 s of measure phase lies within
    scripts/collection.py TRAFFIC_STOP_GRACE_S of its post marker and its order share still has user sessions."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(bs, "V5", protokol_g0.g0_file())
        bs._v5_file.cache_clear()
        try:
            doc = bs.protocol_doc(bs.profile_dir(tmp_path_factory.mktemp("realism") / "profile"),
                                  schema="hyptcn3/collection-protocol/3", cycles=96, pilot_cycles=80, window_rows=8,
                                  full_every=64, gate=bs.worst_gate(96, 8, 64, bs.RULE["max"]), name="realism",
                                  scenarios={name: {} for name in SCENARIOS})
            doc.update(bs.audit_sections(1))
            doc.setdefault("profiles", copy.deepcopy(json.loads(bs.V5.read_text()).get("profiles", STAND_IN)))
        finally:
            bs._v5_file.cache_clear()  # The next reader takes the file itself again.
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
    # One drawn think of 71.5 s among 22 of 4 s: the mean stays within its tolerance of the profile's 7 s, and the
    # realized maximum lies 0.5 s above think_s.max plus THINK_LAG_S, 71 s (finding F4 of the B10 verification; its
    # mutant C6 drops the check of the maximum).
    "think_time:max": ("steady", {"thinks": (71.5,) + (4.,) * 22, "measure_s": 200, "snapshots": 200}),
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


def test_a_think_time_at_the_maximum_plus_the_generators_lag_is_admitted(tmp_path, p):
    """Finding F4 of the B10 verification: a realized think time of exactly think_s.max plus THINK_LAG_S (the
    executor's judgment, package B10, F6 of B5b), 71 s, among 22 of 4 s keeps the requirement and the session
    accepted; its mutant C5 leaves the lag out. One 0.5 s above it is OTHER_SIDE['think_time:max'], refused."""
    top = p["profiles"]["eshop"]["think_s"]["max"] + tl.THINK_LAG_S
    d = session(tmp_path, p, "steady", thinks=(top,) + (4.,) * 22, measure_s=200, snapshots=200)
    found = requirement(realism(d, p), "think_time")
    assert (found["value"]["max"], found["bound"]["max"] + found["bound"]["lag_s"], found["ok"]) == (top, top, True)
    assert audit(d)["problems"] == []


def test_the_protocol_states_the_allowance_of_the_maximum_think_time():
    """Finding F4 of the B10 verification: audit.traffic.note of the v5 file states THINK_LAG_S, by which the realized
    maximum think time may exceed profiles.eshop.think_s.max, and whose judgment it is (proposal 5.7 says the same)."""
    note = json.loads(bs.V5.read_text())["audit"]["traffic"]["note"]
    assert f"may lie at most {tl.THINK_LAG_S:g} s above profiles.eshop.think_s.max" in note
    assert "scripts/traffic_log.py THINK_LAG_S, the executor's judgment, package B10" in note


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


def test_the_order_share_leaves_a_user_session_out_by_its_start_and_not_by_its_length(tmp_path, p):
    """Package B13 (the lead's answer to Q73 point 1): 25 user sessions 20.96 s apart, every fifth one orders and
    lasts 40 s, the others 10 s; two windows, each opening 35 s after a user session that orders starts and closing
    1 s after the fifth one from it. By the start (D_max 41 s, the longest user session's 40 s and a second) each
    window leaves out its five user sessions, one of them ordering: 3 of 15, the share of all 25 (0.2). By the
    overlap of before B13 it left out the ordering one, still running, and only the three short ones after the next:
    3 of 17, low, as in the C4 pass (dokazy/G1/kod/vysledok_C3b.json)."""
    e = evidence
    buyer, other = [e.HOME, e.DETAIL, e.CART_ADD, e.CART, e.ORDER], [e.HOME, e.DETAIL]
    d = session(tmp_path, p, "bursty", sessions=tuple(buyer if k % 5 == 0 else other for k in range(25)),
                spacings=(1.,) * 24, thinks=(10.,), flat=True, measure_s=600, snapshots=600)
    rows = records(d)
    base = rows[0]["start_unix"]
    ends = {}
    for r in rows:
        if r.get("type") == "request":
            ends[r["user_session"]] = max(ends.get(r["user_session"], 0), r["t_end_mono"])
    users = sorted((a["t_mono"], ends[a["user_session"]], a["user_session"]) for a in rows
                   if a.get("type") == "arrival" and a["phase"] == "measure")
    ordering = {r["user_session"] for r in rows if r.get("type") == "request" and r["step"] == "order"
                and r["user_session"] in {uid for _, _, uid in users}}  # Not build()'s order of the warmup.
    starts = [start for start, _, _ in users]
    assert len(users) == 25 and len(ordering) == 5 and {users[k][2] for k in range(0, 25, 5)} == ordering
    assert {round(b - a, 2) for a, b in zip(starts, starts[1:])} == {20.96}
    assert {round(end - start, 2) for start, end, uid in users} == {40.01, 10.0}
    windows = [(starts[5 * j] + 35, starts[5 * j + 4] + 1) for j in (1, 3)]
    q = copy.deepcopy(p)
    q["audit"]["traffic"]["order_share_session_max_s"] = 41
    by_start = [u for u in users if not any(lo - 41 <= u[0] <= hi for lo, hi in windows)]
    by_overlap = [u for u in users if not any(lo <= u[1] and u[0] <= hi for lo, hi in windows)]
    share = [sum(u[2] in ordering for u in kept) / len(kept) for kept in (by_start, by_overlap)]
    assert (len(by_start), len(by_overlap), share) == (15, 17, [3 / 15, 3 / 17]) and share[0] == 5 / 25
    found = requirement(realism(d, q, [(base + lo, base + hi) for lo, hi in windows]), "order_share")
    assert (found["value"], found["ok"]) == (round(3 / 15, 6), True)
    assert found["bound"] == {"share": .2, "tolerance": round(4 * math.sqrt(.2 * .8 / 15), 6)}
    assert found["note"] == ("3 of 15 user sessions ordered (intensity high); 10 starting in a window or less than "
                             "D_max 41 s before one, and 0 more starting less than D_max before the generator's stop "
                             "(the request log's end record), left out")  # Package B14: the stop's count.


@pytest.mark.parametrize("shift", [0, 5000])
def test_the_order_share_leaves_out_the_user_sessions_the_generators_stop_cuts(tmp_path, p, shift):
    """Package B14 (Q77: the executor's decision, approved by the lead on 2026-11-26): 25 user sessions 20.96 s apart,
    every fifth one a buyer. The buyer that starts less than D_max before the end record of the request log, the
    generator's stop, is cut before its order (its funnel without the order), as the stop of scripts/collection.py
    right after the measure phase cuts the buyers of its last minutes. D_max reaches from the end record back to the
    middle between user sessions 19 and 20. B13's rule, which knows no stop, keeps all 25, and 4 of them ordered:
    0.16, low. B14's rule leaves out the five that start less than D_max before the stop: 4 of 20, the design share
    0.2. No window. Package B15 (should_fix 1 of the fourth G0 verification): the stop is compared with the starts in
    the generator's monotonic time, so start_unix 5000 s later in both headers leaves the same five out; B14 placed
    the stop at start_unix + end_mono against the arrivals' t_utc, and then left out none, 4 of 25."""
    e = evidence
    buyer, cut, other = [e.HOME, e.DETAIL, e.CART_ADD, e.CART, e.ORDER], [e.HOME, e.DETAIL, e.CART_ADD, e.CART], [
        e.HOME, e.DETAIL]
    d = session(tmp_path, p, "bursty", sessions=tuple((cut if k == 20 else buyer) if k % 5 == 0 else other
                                                      for k in range(25)),
                spacings=(1.,) * 24, thinks=(10.,), flat=True, measure_s=600, snapshots=600)
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):  # Only start_unix moves, nothing else.
        moved = records(d, name)
        moved[0]["start_unix"] += shift
        evidence.jsonl(d / name, moved)
    rows = records(d)
    end = rows[-1]["end_mono"]  # The stop, after the generator's origin start_unix (the arrivals' t_mono alike).
    users = sorted((a["t_mono"], a["user_session"]) for a in rows if a.get("type") == "arrival"
                   and a["phase"] == "measure")
    ordering = {r["user_session"] for r in rows if r.get("type") == "request" and r["step"] == "order"
                and r["user_session"] in {uid for _, uid in users}}  # Not build()'s order of the warmup.
    starts = [start for start, _ in users]
    assert len(users) == 25 and {users[k][1] for k in (0, 5, 10, 15)} == ordering  # User session 20: no order.
    assert {round(b - a, 2) for a, b in zip(starts, starts[1:])} == {20.96}
    d_max = round(end - (starts[19] + starts[20]) / 2)
    assert starts[19] + 10 < end - d_max < starts[20] - 10
    q = copy.deepcopy(p)
    q["audit"]["traffic"]["order_share_session_max_s"] = d_max
    by_b13 = users  # No window: the start rule of B13 keeps every one.
    by_b14 = [u for u in users if not end - d_max <= u[0] <= end]
    share = [sum(uid in ordering for _, uid in kept) / len(kept) for kept in (by_b13, by_b14)]
    assert (len(by_b13), len(by_b14), share) == (25, 20, [4 / 25, 4 / 20]) and share[1] == .2
    found = requirement(realism(d, q), "order_share")
    assert (found["value"], found["ok"]) == (round(4 / 20, 6), True)
    assert found["bound"] == {"share": .2, "tolerance": round(4 * math.sqrt(.2 * .8 / 20), 6)}
    assert found["note"] == (f"4 of 20 user sessions ordered (intensity high); 0 starting in a window or less than "
                             f"D_max {d_max} s before one, and 5 more starting less than D_max before the generator's "
                             "stop (the request log's end record), left out")


@pytest.mark.parametrize("change", ["no end record", "end_mono not a number"])
def test_a_request_log_without_the_time_of_its_end_record_gives_no_order_share(tmp_path, p, change):
    """Package B14 (Q77: the executor's decision, approved by the lead on 2026-11-26): without the generator's stop no
    user session can be judged, so the order share has no value and fails, the stricter side, with the reason in its
    note; every other requirement is judged as before. The log audit already refuses a request log without its end
    record (summarize: requests:end_missing). Since package B15 it also refuses an end record whose end_mono is no
    number, because that end_mono differs from the interval log's (summarize: requests:end_mono_mismatch)."""
    d = session(tmp_path, p, "steady")
    rows = records(d)
    if change == "no end record":
        rows.pop()
    else:
        rows[-1]["end_mono"] = None
    evidence.jsonl(d / "traffic_requests.jsonl", rows)
    evidence.seal(d)
    found = realism(d, p)
    share = requirement(found, "order_share")
    assert (share["value"], share["ok"], share["bound"]) == (None, False, {"share": .05, "tolerance": None})
    assert share["note"] == ("no share: the request log does not end with an end record with a finite end_mono, so "
                             "the generator's stop is unknown (intensity low); none of the 10 user sessions judged")
    assert all(r["ok"] for r in found["requirements"] if r["name"] != "order_share") and found["offered_load"]["ok"]
    assert audit(d)["problems"] == {"no end record": ["traffic:requests:end_missing", "traffic_realism:order_share"],
                                    "end_mono not a number": ["traffic:requests:end_mono_mismatch",
                                                              "traffic_realism:order_share"]}[change]


def test_the_synthetic_logs_end_at_least_d_max_after_their_last_user_session_starts(tmp_path, p):
    """Package B14: v5_traffic moves the end records to D_max and one second after the arrival of the last user session
    of the measure phase, on the grid of build()'s intervals (the post phase in intervals of 1 s from its marker, the
    last one closed half a second in), so the stop leaves out none of them and the clean session keeps its order share
    of 1 in 10. build()'s end stays where it lies late enough (600 s of measure phase). Package B16 (Q82): under p,
    whose D_max is the file's scaled to its grid of 1 s (boundary_sessions.traffic_bounds: 48.4 s), the moved end lies
    within scripts/collection.py TRAFFIC_STOP_GRACE_S of the post marker, as the runner stops the generator, and the
    log audit finds nothing. Under the file's 242 s the end of the same session lies 214.5 s after the post marker, as
    a run of scripts/lab_trial.py, which drains longer, may end: summarize and every realism requirement accept it,
    and the session audit refuses it by the stop alone (traffic_stop). That session of 10 cycles, whose planned run of
    130 s ends before its moved logs, under a protocol rate: the envelope's level 1 lies at D with a knot at the end of
    the measure phase, every warmup and measure interval plans what the null rate plans, and the log audit finds what
    it finds under the null rate."""
    from scripts.collection import TRAFFIC_STOP_GRACE_S
    d_max = p["audit"]["traffic"]["order_share_session_max_s"]
    assert (d_max, json.loads(bs.V5.read_text())["audit"]["traffic"]["order_share_session_max_s"]) == (48.4, 242)

    def timeline(d):
        rows, ivs = records(d), records(d, "traffic_intervals.jsonl")
        last = max(a["t_mono"] for a in rows if a.get("type") == "arrival" and a["phase"] == "measure")
        stop = next(r["t_mono"] for r in rows if r.get("type") == "phase" and r["phase"] == "post")
        post = [(iv["mono_start"], iv["mono_end"]) for iv in ivs if iv.get("type") == "interval"
                and iv["phase"] == "post"]
        return last, stop, rows[-1]["end_mono"], ivs[-1]["end_mono"], post
    short = session(tmp_path / "short", p, "steady")
    last, stop, end, end_i, post = timeline(short)
    assert d_max + 1 <= end - last < d_max + 2 and end == end_i and end - stop == len(post) - .5
    assert post == [(stop + k, min(stop + k + 1, end)) for k in range(len(post))]
    assert (end - stop, end - stop <= TRAFFIC_STOP_GRACE_S) == (20.5, True)
    share = requirement(realism(short, p), "order_share")
    assert (share["value"], share["ok"]) == (round(1 / 10, 6), True) and "and 0 more" in share["note"]
    assert audit(short)["problems"] == []
    long_last, long_stop, long_end, _, long_post = timeline(session(tmp_path / "long", p, "steady", measure_s=600,
                                                                    snapshots=600))
    assert (long_end - long_stop, long_post, long_end - long_last > d_max + 1) == (evidence.POST_S,
                                                                                   [(long_stop, long_end)], True)
    far = copy.deepcopy(p)  # The file's D_max on the same grid.
    far["audit"]["traffic"]["order_share_session_max_s"] = 242
    drained = session(tmp_path / "drained", far, "steady")
    last, stop, end, end_i, post = timeline(drained)
    assert 243 <= end - last < 244 and end == end_i and end - stop == len(post) - .5 == 214.5
    found = realism(drained, far)
    assert all(r["ok"] for r in found["requirements"]) and found["offered_load"]["ok"]
    assert requirement(found, "order_share")["value"] == round(1 / 10, 6)
    assert tl.summarize(drained / "traffic_requests.jsonl", drained / "traffic_intervals.jsonl",
                        schema=tl.REQUEST_SCHEMA_2)["problems"] == []
    assert audit(drained)["problems"] == ["traffic_stop"]
    rated = copy.deepcopy(far)
    for scenario in rated["scenarios"].values():
        scenario["rate"] = 3.7
    at = session(tmp_path / "rated", rated, "steady")
    a, b = records(drained), records(at)
    t_s, level = a[0]["envelope"]["t_s"], a[0]["envelope"]["level"]
    assert b[1:] == a[1:] and end > t_s[-1] == 130  # The moved logs run past D.
    scale = a[0]["rate"] / 3.7
    assert b[0]["envelope"] == {"t_s": [*t_s[:-1], round(stop, 6), t_s[-1]],
                                "level": [*(scale * x for x in level), 1]}
    ivs = [[r for r in records(x, "traffic_intervals.jsonl") if r.get("type") == "interval"] for x in (drained, at)]
    planned = [[iv["planned_sessions"] for iv in x if iv["phase"] != "post"] for x in ivs]
    assert planned[1] == pytest.approx(planned[0], abs=1e-6) and len(planned[0]) == int(stop)
    assert audit(at)["problems"] == audit(drained)["problems"] == ["traffic_stop"]


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
    # Package B16: its t_utc stays where it was, seconds after start_unix plus the new t_mono (wall_clock).
    return [f"arrival_order:{_user(5)}", f"interval_arrivals:{index}", f"wall_clock:arrival:{_user(5)}"]


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


def m_customer_held_twice_briefly(r, i, p):
    # The verification of B10 (its mutant C9): an overlap under 1 s counts too. u0 holds its customer from its arrival
    # at 0.01 s to the end of its request at 0.103 s; u1 arrives at 0.02 s holding zakaznik0001, given to u0 as well.
    u0, u1 = _arrivals(r)[0], _arrivals(r)[1]
    end = max(x["t_end_mono"] for x in _requests(r) if x["user_session"] == _user(0))
    assert u0["customer"] is None and u1["customer"] == "zakaznik0001" and 0 < end - u1["t_mono"] < 1
    u0["customer"] = "zakaznik0001"
    return [f"customer_held_twice:{_user(1)}"]


def m_customers_held_at_customers(r, i, p):
    # The verification of B10 (its mutant C8): a drop for held customers with exactly as many user sessions in
    # progress as lab/seed.py has customers is one, the fewest that can hold them all, below a cap above that.
    from lab import seed
    customers = seed.SIZES["customers"]
    _headers(r, i, lambda h: h["profile_parameters"].update(max_concurrent=customers + 1))
    last = _arrivals(r)[LAST]
    last.update(admitted=False, drop_reason="all_customers_held", active=customers)
    return _dropped_counts(r, i, last)


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


def m_end_mono(r, i, p):
    r[-1]["end_mono"] += 1000  # Package B15: the request log's copy of the stop, which the order share reads.
    return ["requests:end_mono_mismatch", "wall_clock:end:requests"]  # B16: its end_utc stays 1000 s earlier.


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


# Package B16 (Q82: the executor's decision, for the lead's review): should_fix 1 to 3 of the fifth G0 verification
# (data/results/overenie_G0_20261127T055151Z.json). summarize binds the wall times of a /2 pair to the request log
# header's start_unix plus their monotonic time (WALL_CLOCK_TOLERANCE_S), the session audit bounds the generator's
# stop from above (traffic_stop), and a bound of the intervals that is no number is refused by name.

def _pair(d):
    """Both logs of session d, their records without schema and n (sample.write numbers them again)."""
    return tuple([{k: v for k, v in x.items() if k not in ("schema", "n")} for x in records(d, name)]
                 for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"))


def _write_pair(d, r, i, seal=True):
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA_2, r)
    sample.write(d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA_2, i)
    if seal:
        evidence.seal(d)


def _summarize(d):
    return tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl",
                        schema=tl.REQUEST_SCHEMA_2)["problems"]


def _later(stamp, seconds):
    return evidence.datetime.fromtimestamp(logs.unix(stamp) + seconds, evidence.timezone.utc).isoformat()


def _record(r, i, kind, log):
    """The record of each kind the tests below move: the first arrival of the measure phase (u4), the post marker of
    the log `log`, the second request of u4, the interval holding u4, the end record of the log `log`."""
    rows = r if log == "requests" else i
    if kind == "arrival":
        return _arrivals(r)[4], _user(4)
    if kind == "phase":
        return next(x for x in rows if x.get("type") == "phase" and x["phase"] == "post"), f"{log}:post"
    if kind == "request":
        return _rid_of(r, EXTRA), EXTRA
    if kind == "interval":
        iv = _interval_of(i, _arrivals(r)[4]["t_mono"])
        return iv, iv["interval"]
    return rows[-1], log


WALL_FIELDS = [("arrival", "t_utc", "requests"), ("phase", "t_utc", "requests"), ("phase", "t_utc", "intervals"),
               ("request", "t_start_utc", "requests"), ("request", "t_end_utc", "requests"),
               ("interval", "t_start_utc", "intervals"), ("interval", "t_end_utc", "intervals"),
               ("end", "end_utc", "requests"), ("end", "end_utc", "intervals")]


@pytest.mark.parametrize("seconds", [-1.001, -.999, .999, 1.001])
@pytest.mark.parametrize("kind, field, log", WALL_FIELDS, ids=["-".join(x) for x in WALL_FIELDS])
def test_summarize_binds_each_wall_time_of_a_v5_pair_to_start_unix(tmp_path, p, kind, field, log, seconds):
    """Package B16 (should_fix 1): every wall time the decision names, of every kind of record and in both logs where a
    kind is in both, moved alone by just less than WALL_CLOCK_TOLERANCE_S keeps the pair clean, and by just more is
    refused by that record's kind and id (wall_clock)."""
    assert tl.WALL_CLOCK_TOLERANCE_S == 1.0
    d = session(tmp_path, p, "steady")
    r, i = _pair(d)
    record, ident = _record(r, i, kind, log)
    record[field] = _later(record[field], seconds)
    _write_pair(d, r, i, seal=False)
    assert _summarize(d) == ([] if abs(seconds) < 1 else [f"wall_clock:{kind}:{ident}"])


@pytest.mark.parametrize("shift", [-5000, -30, -10, -5, -1.001, 1.001, 5, 10, 30, 5000])
def test_a_start_unix_moved_in_both_headers_is_refused_by_the_first_record_it_misplaces(tmp_path, p, shift):
    """Package B16 (should_fix 1, the verifier's probe test_sonda_b15.py, test_probe_start_unix_still_places_the_
    offered_load): the F7 session with windows on its two measure intervals that hold two arrivals each, placed from
    the honest start_unix, offers 6 of about 8.93 planned user sessions and fails the offered load. start_unix moved
    in both headers, and nothing else, places the intervals elsewhere: from 5 s on the windows miss those intervals and
    the offered load passes. summarize refuses every such pair by the first record after the request log's header,
    the arrival of build()'s first user session (u0), and the log audit with it; 0.999 s either way stays clean."""
    d = session(tmp_path, p, "steady")
    start = records(d)[0]["start_unix"]
    ivs = [x for x in records(d, "traffic_intervals.jsonl") if x.get("type") == "interval" and x["phase"] == "measure"]
    windows = [(start + iv["mono_start"] + .1, start + iv["mono_end"] - .1) for iv in ivs
               if iv["offered_sessions"] == 2]
    assert len(windows) == 2 and realism(d, p, windows)["offered_load"]["ok"] is False
    r, i = _pair(d)
    for header in (r[0], i[0]):
        header["start_unix"] = start + .999
    _write_pair(d, r, i)
    assert _summarize(d) == [] and audit(d)["problems"] == []
    for header in (r[0], i[0]):
        header["start_unix"] = start + shift
    _write_pair(d, r, i)
    if abs(shift) >= 5:  # The probe's shifts: the windows miss the two intervals, and B15's audit accepted it.
        assert realism(d, p, windows)["offered_load"]["ok"] is True
    assert _summarize(d) == [f"wall_clock:arrival:{_user(0)}"]
    assert audit(d)["problems"] == [f"traffic:wall_clock:arrival:{_user(0)}"]


@pytest.mark.parametrize("value", [None, "1767225600.0", True, math.nan, math.inf, "missing"],
                         ids=["null", "string", "bool", "nan", "inf", "missing"])
@pytest.mark.parametrize("log", ["requests", "intervals"])
def test_a_header_without_a_finite_start_unix_is_refused_by_name(tmp_path, p, log, value):
    """Package B16: a /2 header whose start_unix is no finite number is refused by name. Without the request log's no
    wall time can be compared; the interval log's records are compared with the request log's start_unix (the one
    realism places them with), and the log audit compares the two headers (traffic_headers_disagree)."""
    d = session(tmp_path, p, "steady")
    r, i = _pair(d)
    header = (r if log == "requests" else i)[0]
    if value == "missing":
        del header["start_unix"]
    else:
        header["start_unix"] = value
    _write_pair(d, r, i, seal=False)
    assert _summarize(d) == [f"{log}:start_unix_invalid"]


@pytest.mark.parametrize("value", ["missing", None, "garbage", "2026-01-01T00:00:01.100000", 1767225601.1],
                         ids=["missing", "null", "garbage", "no_timezone", "number"])
@pytest.mark.parametrize("kind, field, log", [("request", "t_start_utc", "requests"), ("phase", "t_utc", "intervals"),
                                              ("end", "end_utc", "requests"), ("interval", "t_end_utc", "intervals")],
                         ids=["request", "phase", "end", "interval"])
def test_a_wall_time_that_cannot_be_read_differs(tmp_path, p, kind, field, log, value):
    """Package B16: a wall time that is missing or no ISO-8601 time with a timezone cannot agree with start_unix plus
    its monotonic time, and refuses the pair by the record's kind and id; but an interval's, which the generator derives
    from start_unix and which nothing reads, is compared only where the interval carries it."""
    d = session(tmp_path, p, "steady")
    r, i = _pair(d)
    record, ident = _record(r, i, kind, log)
    if value == "missing":
        del record[field]
    else:
        record[field] = value
    _write_pair(d, r, i, seal=False)
    gone = kind == "interval" and value == "missing"
    assert _summarize(d) == ([] if gone else [f"wall_clock:{kind}:{ident}"])


def test_the_wall_times_of_logs_of_schema_1_stay_unbound(tmp_path):
    """Package B16: /1 is unchanged. build()'s /1 logs stamp every interval and both end records with the start of the
    session, seconds before start_unix plus their monotonic time; summarize and the log audit accept them as before."""
    d = evidence.build(tmp_path)
    ivs = [x for x in records(d, "traffic_intervals.jsonl") if x.get("type") == "interval"]
    assert len({x["t_end_utc"] for x in ivs}) == 1
    assert logs.unix(ivs[-1]["t_end_utc"]) + 3 < records(d)[0]["start_unix"] + ivs[-1]["mono_end"]
    assert tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl")["problems"] == []
    assert logs.audit_logs(d)["problems"] == []


BAD_NUMBERS = {"null": None, "string": "275.5", "true": True, "false": False, "nan": math.nan, "inf": math.inf,
               "missing": "<missing>"}


@pytest.mark.parametrize("bad", list(BAD_NUMBERS))
def test_an_end_mono_of_the_interval_log_that_is_no_number_is_refused_by_name(tmp_path, p, bad):
    """Package B16 (should_fix 3, the verifier's probe test_sonda_unreadable.py): intervals_not_to_end reads the last
    interval's mono_end and the interval log's end_mono as numbers first. One that is none raises no TypeError, which
    the log audit turned into traffic:unreadable and scripts/lab_trial.py traffic_summary did not catch: the pair is
    refused by name, with the value that is no number, and by B15's requests:end_mono_mismatch. The wall time of an
    end record whose end_mono is no number is not compared (wall_clock). NaN and an infinity, no numbers of JSON, also
    make the log audit's section traffic unreadable, whose summary holds the end records (as before B16)."""
    from scripts import lab_trial
    d = session(tmp_path, p, "steady")
    r, i = _pair(d)
    if BAD_NUMBERS[bad] == "<missing>":
        del i[-1]["end_mono"]
    else:
        i[-1]["end_mono"] = BAD_NUMBERS[bad]
    _write_pair(d, r, i)
    shown = repr(None if bad == "missing" else BAD_NUMBERS[bad])
    expected = [f"intervals_not_to_end:end_mono:{shown}", "requests:end_mono_mismatch"]
    assert _summarize(d) == expected
    unreadable = [f"traffic:unreadable:ValueError: Out of range float values are not JSON compliant: {shown}"]
    assert audit(d)["problems"] == ["traffic:" + x for x in expected] + (unreadable if bad in ("nan", "inf") else [])
    assert lab_trial.traffic_summary(d)["problems"][-2:] == expected


@pytest.mark.parametrize("bad", ["null", "string", "true", "false"])
def test_a_first_interval_that_starts_at_no_number_is_refused_by_name(tmp_path, bad):
    """Package B16 (should_fix 3): the same for the origin of the intervals (intervals_not_from_origin), here on logs
    of schema /1, which share the line with /2: B3's line raised TypeError for null and a string, and let false pass
    as 0."""
    req, ivl = sample.build()
    ivl[1]["mono_start"] = BAD_NUMBERS[bad]
    pair = sample.write_pair(tmp_path, req, ivl)
    problems = tl.summarize(*pair)["problems"]
    assert ("intervals_not_from_origin" if BAD_NUMBERS[bad] is None else
            f"intervals_not_from_origin:{BAD_NUMBERS[bad]}") in problems


def _stop_at(d, t):
    """The generator's stop at monotonic time t, consistently: both end records (end_mono and end_utc) and the last
    interval (mono_end, duration_s and t_end_utc); the logs resealed."""
    r, i = _pair(d)
    last = [x for x in i if x.get("type") == "interval"][-1]
    seconds = round(t - last["mono_end"], 6)
    last.update(mono_end=round(t, 6), t_end_utc=_later(last["t_end_utc"], seconds))
    last["duration_s"] = round(last["mono_end"] - last["mono_start"], 6)
    for end in (r[-1], i[-1]):
        end.update(end_mono=round(t, 6), end_utc=_later(end["end_utc"], seconds))
    _write_pair(d, r, i)


def _post(d):
    return next(x["t_mono"] for x in records(d) if x.get("type") == "phase" and x["phase"] == "post")


@pytest.mark.parametrize("after, problems", [(.5, []), (30, []), (30.001, ["traffic_stop"]), (1000, ["traffic_stop"])])
def test_the_session_audit_bounds_the_generators_stop_by_the_post_marker(tmp_path, p, after, problems):
    """Package B16 (should_fix 2, the verifier's probes test_sonda_stop3.py and test_sonda_stop3b.py): the stop moved
    consistently in both end records and the last interval, which summarize cannot tell from an honest one, to `after`
    seconds after the post marker. The session audit admits it up to scripts/collection.py TRAFFIC_STOP_GRACE_S (30 s),
    the grace capture_session gives the generator after SIGUSR2, and refuses it beyond (traffic_stop alone); before B16
    a stop 1000 s later passed, and the order share cut no buyer at it. summarize keeps no such bound
    (scripts/lab_trial.py drains longer). The session of 600 s of measure phase holds one interval of the post phase,
    the generator's stop half a second in, as build() places it."""
    from scripts import collection
    assert collection.TRAFFIC_STOP_GRACE_S == 30
    d = session(tmp_path, p, "steady", event=True, measure_s=600, snapshots=600)
    assert records(d)[-1]["end_mono"] - _post(d) == evidence.POST_S
    _stop_at(d, _post(d) + after)
    assert _summarize(d) == [] and audit(d)["problems"] == problems


@pytest.mark.parametrize("later, problems", [(0, []), (.1, ["traffic_stop"])])
def test_a_stop_before_the_post_marker_or_beside_a_post_marker_out_of_time_is_refused(tmp_path, p, later, problems):
    """Package B16: the post marker moved to the end record or `later` after it, in both logs and its wall time with
    it (within the 1 s of traffic_measure_bounds): a stop at the marker is admitted, one before it is refused by
    traffic_stop alone. A post marker whose t_mono is no number in both logs, which no other check reads, places no
    stop either: traffic_stop alone."""
    d = session(tmp_path / "long", p, "steady", measure_s=600, snapshots=600)  # End records half a second in post.
    end = records(d)[-1]["end_mono"]
    r, i = _pair(d)
    for rows in (r, i):
        marker = next(x for x in rows if x.get("type") == "phase" and x["phase"] == "post")
        moved = round(end + later, 6)
        marker.update(t_mono=moved, t_utc=_later(marker["t_utc"], round(moved - marker["t_mono"], 6)))
    _write_pair(d, r, i)
    assert _summarize(d) == [] and audit(d)["problems"] == problems
    d = session(tmp_path / "null", p, "steady")
    r, i = _pair(d)
    for rows in (r, i):
        next(x for x in rows if x.get("type") == "phase" and x["phase"] == "post")["t_mono"] = None
    _write_pair(d, r, i)
    assert _summarize(d) == [] and audit(d)["problems"] == ["traffic_stop"]


def test_the_stop_bound_is_the_grace_the_runner_gives_the_generator(tmp_path, p, monkeypatch):
    """Package B16: TRAFFIC_STOP_GRACE_S of scripts/collection.py is the grace of each stop_child of the generator in
    capture_session (after SIGUSR2, and in its finally block), and the session audit reads that constant: the clean
    session, whose end records lie 20.5 s after the post marker, is refused once the grace is 20 s and accepted at
    21 s."""
    from scripts import collection
    tree = ast.parse((ROOT / "scripts/collection.py").read_text())
    stops = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and getattr(node.func, "id", None) ==
             "stop_child" and isinstance(node.args[0], ast.Subscript)
             and getattr(node.args[0].slice, "value", None) == "traffic"]
    pairs = [node for node in ast.walk(tree) if isinstance(node, ast.Tuple) and len(node.elts) == 2
             and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "traffic"
             and not (isinstance(node.elts[1], ast.Constant) and type(node.elts[1].value) is str)]  # Its grace.
    assert len(stops) == len(pairs) == 1
    assert [getattr(x, "id", None) for x in (stops[0].args[1], pairs[0].elts[1])] == ["TRAFFIC_STOP_GRACE_S"] * 2
    d = session(tmp_path, p, "steady")
    assert records(d)[-1]["end_mono"] - _post(d) == 20.5
    monkeypatch.setattr(collection, "TRAFFIC_STOP_GRACE_S", 20)
    assert audit(d)["problems"] == ["traffic_stop"]
    monkeypatch.setattr(collection, "TRAFFIC_STOP_GRACE_S", 21)
    assert audit(d)["problems"] == []


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


@pytest.mark.parametrize("variant", [{}, {"flat": True}, {"rate_factor": 2}], ids=["clean", "flat", "twice_the_plan"])
def test_under_a_rate_of_the_protocol_the_helper_keeps_the_plan_of_the_null_rate(tmp_path, p, variant):
    """Item P3 of the G2 preparation (D [9] of B10): from G2 every scenario has a rate. Under a copy of p with a rate
    for every scenario (3.7 user sessions a second, a number of this test only) v5_traffic states that rate with the
    source protocol, and everything else of its logs is what the null rate of the file gives: every arrival, request,
    marker and end record, and every interval with its planned count. The envelope's level is the null one scaled by
    its rate over 3.7, and its level 1 lies after the logs end. So the log audit gives the problems of the null rate:
    none, peak_to_mean alone for the flat envelope, the offered load alone for the plan of twice the offered user
    sessions. A protocol rate 1 % below the null rate (the scale above 1) raises. Package B14: the sessions plan 200
    cycles, a planned run of 320 s, which holds their logs, whose end v5_traffic moves to D_max and a second after the
    last user session of the measure phase (81.5 to 84.5 s under p's D_max of 48.4 s since package B16, 276 to 283 s
    under the file's 242 s before); the logs of fewer cycles that run past D are
    test_the_synthetic_logs_end_at_least_d_max_after_their_last_user_session_starts."""
    def rated(rate):
        doc = copy.deepcopy(p)
        for scenario in doc["scenarios"].values():
            scenario["rate"] = rate
        return doc
    variant = dict(variant, snapshots=200)
    null = session(tmp_path / "null", p, "steady", **variant)
    at = session(tmp_path / "rated", rated(3.7), "steady", **variant)
    a, b = records(null), records(at)
    assert b[1:] == a[1:]
    assert {key for key in a[0] if b[0][key] != a[0][key]} == {"rate", "rate_source", "envelope", "protocol_sha256"}
    assert (a[0]["rate_source"], b[0]["rate_source"], b[0]["rate"]) == ("command line", "protocol", 3.7)
    ivs = [[r for r in records(d, "traffic_intervals.jsonl") if r.get("type") == "interval"] for d in (null, at)]
    assert [dict(iv, planned_sessions=None) for iv in ivs[1]] == [dict(iv, planned_sessions=None) for iv in ivs[0]]
    assert [iv["planned_sessions"] for iv in ivs[1]] == pytest.approx([iv["planned_sessions"] for iv in ivs[0]],
                                                                       abs=1e-6)
    scale, envelope = a[0]["rate"] / 3.7, a[0]["envelope"]
    assert b[0]["envelope"] == {"t_s": [*envelope["t_s"][:-1], round(b[-1]["end_mono"], 6), envelope["t_s"][-1]],
                                "level": [*(scale * x for x in envelope["level"]), 1]}
    assert round(b[-1]["end_mono"], 6) < envelope["t_s"][-1]  # The logs end before D (package B14).
    expected = {"flat": ["traffic_realism:peak_to_mean"], "rate_factor": ["offered_load_differs_from_plan"]}
    assert audit(at)["problems"] == audit(null)["problems"] == next((expected[k] for k in variant if k in expected),
                                                                    [])
    with pytest.raises(ValueError, match="^the protocol's rate is too low for this session's measure phase$"):
        session(tmp_path / "too_low", rated(a[0]["rate"] * .99), "steady", **variant)


# The bounds (features/audit_policy.py audit_bounds reads audit.traffic).

@pytest.mark.parametrize("key, value", [
    ("offered_load_tolerance", 1), ("arrival_cv", [1.1, 1.2]), ("arrival_cv", [.8]), ("top_objects_share", 0),
    ("top_objects_min_requests", .1), ("success_min", 1.), ("response_size_orders", 0),
    ("think_mean_tolerance_se", -1), ("order_share_tolerance_se", None), ("background", {"logins_min": 1}),
    ("note", " "), ("extra", 1),
    # Package B13: D_max of the order share, a positive number of seconds.
    ("order_share_session_max_s", 0), ("order_share_session_max_s", "242"),
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


def _ordering_requests(funnel, errors):
    """{N: probability} of the number of requests of an eshop user session that orders, as scripts/host_traffic.py
    Eshop draws them (its code read, never run here): home and a number of catalog pages from funnel.pages, each page
    followed by a number of details from funnel.details_per_page, each of these views by a static file with
    funnel.static_share; then the login, a number of products from funnel.cart_items into the cart, the cart and the
    order; after every one of these requests one deliberate client error with the odds share / (1 - share)."""
    def uniform(lo, hi):
        return {k: 1 / (hi - lo + 1) for k in range(lo, hi + 1)}

    def add(a, b):
        out = {}
        for x, pa in a.items():
            for y, pb in b.items():
                out[x + y] = out.get(x + y, 0) + pa * pb
        return out

    def with_each(dist, share):  # n and one more request after each of them with `share`: n + Binomial(n, share).
        out = {}
        for n, pn in dist.items():
            for k in range(n + 1):
                out[n + k] = out.get(n + k, 0) + pn * math.comb(n, k) * share ** k * (1 - share) ** (n - k)
        return out
    views = {}
    for pages, pp in uniform(*funnel["pages"]).items():
        details = {0: 1.}
        for _ in range(pages):
            details = add(details, uniform(*funnel["details_per_page"]))
        for k, pk in details.items():
            views[1 + pages + k] = views.get(1 + pages + k, 0) + pp * pk
    ordering = {c + 3: pc for c, pc in uniform(*funnel["cart_items"]).items()}  # login, the cart items, cart, order
    regular = add(with_each(views, funnel["static_share"]), ordering)
    return with_each(regular, errors["share"] / (1 - errors["share"]))


def _erlang_survival(k, mean, t):
    """P(the sum of k exponential think times of `mean` > t)."""
    term, total, x = math.exp(-t / mean), 0., t / mean
    for j in range(k):
        term = term * x / j if j else term
        total += term
    return total


def test_d_max_is_the_duration_an_ordering_user_session_of_the_profile_exceeds_with_probability_0_001():
    """Package B13 (the lead's answer to Q73 point 1): audit.traffic.order_share_session_max_s of the file, D_max, is
    the duration that an ordering user session of profiles.eshop, the longest kind, exceeds with probability 0.001
    (the executor's judgment), rounded up to whole seconds: its N - 1 think times exponential with the mean
    think_s.mean (their cut at think_s.max only shortens a user session), N its requests (_ordering_requests), the
    requests' own duration left out. The note of audit.traffic names the derivation. The distribution of N is that of
    the generator: a run of its state machine on 4000 ordering user sessions has its mean within 4 standard errors."""
    from scripts import host_traffic as ht
    doc = json.loads(bs.V5.read_text())
    eshop, traffic = doc["profiles"]["eshop"], doc["audit"]["traffic"]
    requests = _ordering_requests(eshop["funnel"], eshop["client_errors"])
    assert sum(requests.values()) == pytest.approx(1, abs=1e-12) and (min(requests), max(requests)) == (6, 64)

    def survival(t):
        return sum(pn * _erlang_survival(n - 1, eshop["think_s"]["mean"], t) for n, pn in requests.items())
    d_max = next(t for t in range(1, 5000) if survival(t) <= .001)
    assert (d_max, round(survival(d_max - 1), 6), round(survival(d_max), 6)) == (242, .001041, .000981)
    assert traffic["order_share_session_max_s"] == d_max
    assert all(text in traffic["note"] for text in ("order_share_session_max_s", "Q73", "probability 0.001",
                                                    "241.68 s", "the executor's judgment (package B13)"))
    lab, counts, n = ht.Lab("eshop", eshop), [], 0
    while len(counts) < 4000:
        user = ht.Eshop(eshop, "high", n, {"traffic_choices": 7, "traffic_sizes": 8}, lab, "0123456789ab")
        n += 1
        if not user.buyer:
            continue
        user.customer, steps, step = 1, 0, user.start()
        while step is not None:
            steps += 1
            step = user.reply(SimpleNamespace(status=200, payload={"token": "t"}))
        counts.append(steps)
    mean = sum(k * pk for k, pk in requests.items())
    sd = math.sqrt(sum(k * k * pk for k, pk in requests.items()) - mean ** 2)
    assert abs(statistics.mean(counts) - mean) < 4 * sd / math.sqrt(len(counts)) and set(counts) <= set(requests)
