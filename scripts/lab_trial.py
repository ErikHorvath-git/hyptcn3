#!/usr/bin/env python3
"""The lab test on one VM after package B5 (docs/HARNESS_V5.sk.md chapter 5 point 11, RIADENIE point 4).

Not binding and evidence of no criterion of G0 or G2: no collector, no sudo, no session and nothing in
data/collections. Each step writes its raw outputs into a new run directory (--out, created exclusively) and its
result into result.json there; `record` assembles the results of run directories into one record of stage skuska
in data/results (proposal 11.1). The tool wraps the protocol's tools and reimplements none: scripts/labctl.py
(deploy; event, segment and journal through scripts/collection.py lab_json), the v5 generator
scripts/host_traffic.py with the command line a session gives it (collection.traffic_command, design B5b 1.3) and
its own check of that command line (prepare_v5), scripts/traffic_log.py summarize and realism, the event runner of
sessions (collection.Events) and the event windows of the log audit.

  deploy      --protocol P --vm a --out DIR
  saturation  --protocol P --vm a --profile eshop|corp --scenario S --rates R1,R2,... --out DIR
  scenario    --protocol P --vm a --scenario S --rate R --minutes 10 --out DIR
  long        --protocol P --vm a --scenario S --rate R --minutes 60 --events N [--postgres-debug1] --out DIR
  periods     --run DIR [DIR ...]
  record      --out-record data/results/skuska_labu_<UTC>.json DIR [DIR ...]

deploy: labctl deploy (its JSON lines and exit code are kept; a failed swap step is recorded, not fatal), the
health check, the guest's identity and where the VM's QEMU stands (memory.swap.max, VmSwap and the cgroups its
memory is charged to). A traffic run (a step of saturation, scenario, long) starts the generator with the
protocol's warmup, sends SIGUSR1 at the end of the warmup and SIGUSR2 at --dur, both from the generator's own
origin (the header of its request log), and SIGTERM after a drain. saturation is the series of the lead's answer
to Q5 (SATURATION_RULE): on a copy of the protocol whose max_concurrent does not bind, its rates in order up to the
first step that fails on the server, then bisection to a bracket narrower than STEP_RATIO_MAX. scenario and long
compute the summary and the realism requirements of their logs; long also runs N events of its own draw
(draw_events) through labctl event, fetches the guest journal and the nginx logs of the run, measures the periods
(periods) and judges the spacing of the autovacuum launcher (autovacuum_property, the lead's answer to Q9); with
--postgres-debug1 PostgreSQL logs at debug1 for that run only (DEBUG1_RULE). record also proposes max_concurrent per
profile (MAX_CONCURRENT_RULE). Every number that is the executor's judgment is marked so below and stated in each
result, every number of the lead's answers as well (lead()).

Exit codes: 0 the step ran and wrote its result, 1 it could not complete (its result says why), 2 the input was
refused (nothing written).
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shlex
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import collection, collection_logs, labctl, protocol_v5, traffic_log  # noqa: E402

RESULT_SCHEMA = "hyptcn3/lab-trial-run/1"
RECORD_SCHEMA = "hyptcn3/lab-trial/1"
PERIODS_SCHEMA = "hyptcn3/lab-trial-periods/1"
STAGE = "skuska"  # Proposal 11.1: the stage of every record.
# The lead's answer to Q64 (2026-11-24): the saturation series runs per VM and profile, one VM at a time, and one rate
# holds for both VMs, so a profile's rate comes from the smaller served rate.
SATURATION_COMBINE_RULE = ("Q64: the series of each VM and profile; a profile's proposed rate is that of the VM with "
                           "the smaller served rate (rate), since one rate holds for both VMs")
NOTE = ("Lab test on one VM after package B5 (docs/HARNESS_V5.sk.md chapter 5 point 11, RIADENIE point 4), stage "
        "skuska: evidence of no criterion of G0 or G2. No collector, no sudo, no session, nothing in "
        "data/collections. The proposed rates are proposals: G2 determines scenarios.*.rate.")
LABCTL = ROOT / "scripts/labctl.py"
REQUESTS, INTERVALS, STATUS, LOG = "traffic_requests.jsonl", "traffic_intervals.jsonl", "traffic.json", "traffic.log"
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,120}")  # lab/guest_state.py label_ok: a guest segment label.
SWAP_FAILED = "QEMU swap is not disabled"  # scripts/labctl.py main ends with this when only the swap step failed.

# The executor's judgment, each stated in every result (judgment()):
DEPLOY_TIMEOUT_S = 1800  # Judgment: labctl deploy installs packages, seeds the lab and waits for its services.
HEADER_TIMEOUT_S = 60  # Judgment: the generator writes its log header within seconds of its start.
POLL_S = .1  # Judgment: the wait for that header.
TICK_S = 1  # One round of a traffic run (signals and events), as the session runner's capture loop.
DRAIN_S = 300  # Judgment: after --dur no user session arrives; five user sessions of about a minute (the note of
# profiles.eshop.max_concurrent), so nearly every one that arrived in the measure phase completes (order share).
STOP_GRACE_S = 60  # Judgment: SIGTERM to SIGKILL; the generator ends its requests in flight (client timeout 10 s).
SATURATION_MEASURE_S = 360  # Judgment: the measured part of a step holds a peak of up to 4 minutes
# (profiles.*.arrivals.peak_s) with room for the peak-to-mean of 2 the generator draws (draw_envelope).
SATURATION_DRAIN_S = 30  # Judgment: a step is judged in its measure phase; the drain lets the requests in flight end.
LATENCY_P95_BOUND_MS = 1000  # Judgment: a served peak answers 95 % of its requests within 1 s; near saturation the
# latency grows steeply, so the rate found depends little on this bound.
PEAK_TOLERANCE = 1e-6  # An interval of the peak has the planned level 1 over all of it (bounds rounded to 1 us).
# Judgment of the lab test, accepted by the lead in his answer to Q26: labctl's check of where QEMU's memory is
# charged (scripts/labctl.py charge) and this record share it.
CHARGED_SHARE = labctl.CHARGED_SHARE
HOLDER_SHARE = .5  # Judgment: a leaf cgroup of the user slice holding this share of QEMU's RssAnon is a holder.
RESTART_WINDOW_S = 60  # lab/hyptcn-lab@.service StartLimitIntervalSec: restarts further apart are separate loops.
MIDPOINT_DECIMALS = 3  # Judgment: the rate of a bisection step, user sessions per second at envelope level 1.
GUEST_SQL_TIMEOUT_S = 180  # Judgment: one labctl exec of psql in the guest; labctl's own guest command bound is 120 s.

# The lead's answer to Q5 (2026-11-24) for the saturation series of G2, which this tool runs ahead of G2:
STEP_RATIO_MAX = 1.15  # The lead's judgment: bisection until neighbouring steps are closer than 15 %; reading it
# as the failed rate over the served rate below 1.15 is the executor's (package B11; V2 of its deferred list).
CAP_FACTOR_S = 240  # Judgment, 4 x 60 s: the series runs on a copy whose max_concurrent is at least this times its
# highest rate (a user session lasts about a minute, 4 is the margin; the executor's point 1, accepted by the lead).
PROPOSED_CAP_FACTOR = 2  # Judgment: max_concurrent for collection is twice the most concurrent user sessions at rate
# high in the long run (the executor's point 2, accepted by the lead; a value of G2, determined_at).
# The lead's answer to Q9 (2026-11-24), his judgment: the measured spacing of the autovacuum launcher's worker starts
# lies 1 to 4 s from a multiple of interval_s (2.33 s at 22.33 s). Read as the remainder of the median spacing modulo
# interval_s in [1, 4] s, which is at least 1 s from every multiple.
AUTOVACUUM_REMAINDER_S = (1, 4)


class Refused(ValueError):
    """An input the tool refuses before it writes anything (exit code 2)."""


def judgment():
    return {"deploy_timeout_s": DEPLOY_TIMEOUT_S, "header_timeout_s": HEADER_TIMEOUT_S, "tick_s": TICK_S,
            "drain_s": DRAIN_S, "stop_grace_s": STOP_GRACE_S, "saturation_measure_s": SATURATION_MEASURE_S,
            "saturation_drain_s": SATURATION_DRAIN_S, "latency_p95_bound_ms": LATENCY_P95_BOUND_MS,
            "charged_share": CHARGED_SHARE, "holder_share": HOLDER_SHARE, "restart_window_s": RESTART_WINDOW_S,
            "midpoint_decimals": MIDPOINT_DECIMALS, "guest_sql_timeout_s": GUEST_SQL_TIMEOUT_S,
            "note": "the executor's judgment (scripts/lab_trial.py), none of them a value of the protocol; "
                    "charged_share is accepted by the lead (Q26)"}


def lead():
    """The lead's numbers of his answers to Q5 and Q9 (2026-11-24) that this tool applies, stated in every result."""
    return {"step_ratio_max": STEP_RATIO_MAX, "cap_factor_s": CAP_FACTOR_S, "proposed_cap_factor": PROPOSED_CAP_FACTOR,
            "autovacuum_remainder_s": list(AUTOVACUUM_REMAINDER_S),
            "note": "the lead's answers to Q5 and Q9 (2026-11-24), none of them a value of the protocol"}


def commit():
    from scripts.audit_selftest import commit as head
    return head()


def finite(doc):
    """doc with every float that is not finite as None (the results are strict JSON)."""
    if type(doc) is float:
        return doc if math.isfinite(doc) else None
    if type(doc) is dict:
        return {key: finite(value) for key, value in doc.items()}
    if type(doc) in (list, tuple):
        return [finite(value) for value in doc]
    return doc


def write(path, doc):
    with Path(path).open("x") as stream:
        json.dump(finite(doc), stream, indent=1, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


# ------------------------------------------------------------------ inputs (refused before anything is written)

def load(path):
    """(bytes, protocol) of a schema-3 protocol file, read and checked as a session reads it."""
    try:
        raw, p = Path(path).read_bytes(), collection.protocol(path)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Refused(f"cannot read the protocol {path}: {error}") from None
    if p.get("schema") != protocol_v5.SCHEMA:
        raise Refused(f"the lab test needs a protocol of schema 3 ({protocol_v5.SCHEMA}), the one with the v5 profiles")
    return raw, p


def for_vm(p, name):
    try:
        return collection.for_vm(p, name)
    except ValueError as error:
        raise Refused(str(error)) from None


def scenario_of(p, name):
    if name not in p["scenarios"]:
        raise Refused(f"unknown scenario: {name} (the protocol has {', '.join(p['scenarios'])})")
    return p["scenarios"][name]


def new_dir(path):
    out = Path(path).absolute()
    if out.exists():
        raise Refused(f"the run directory exists: {out} (every step writes a new one)")
    if out.resolve().is_relative_to(collection.COLLECTIONS.resolve()):
        raise Refused("the lab test writes nothing in data/collections")
    return out


def measured(p, minutes):
    """(seconds, cycles) of the measured part: --minutes as a whole number of collection intervals."""
    cycles = minutes * 60 / p["interval_s"]
    if not (math.isfinite(minutes) and minutes > 0 and cycles.is_integer()):
        raise Refused(f"--minutes {minutes:g} is not a positive whole number of collection intervals "
                      f"({p['interval_s']} s)")
    return int(cycles) * p["interval_s"], int(cycles)


def rates_of(text):
    try:
        rates = [float(x) for x in text.split(",")]
    except ValueError:
        rates = []
    if not rates or not all(math.isfinite(r) and r > 0 for r in rates) or any(b <= a for a, b in zip(rates, rates[1:])):
        raise Refused("--rates is a comma-separated list of rates above 0 in increasing order (user sessions per "
                      "second at envelope level 1)")
    return rates


def traffic_block(pv, scenario, profile, rate, kind, position, seconds):
    """The traffic block of one run, with the fields of a session's (collection.py _v5_traffic): the scenario,
    --rate (the protocol's rate when None), seeds by the plan's rule (protocol_v5.seed) with the group
    skuska/<kind>/<scenario>, the position and attempt 1, so no stream of the plan has them, and --dur = the
    protocol's warmup + `seconds`."""
    s, group = pv["scenarios"][scenario], f"skuska/{kind}/{scenario}"
    return {"generator": "scripts/host_traffic.py", "load_model": collection.V5_LOAD_MODEL, "profile": profile,
            "scenario": scenario, "intensity": s["intensity"], "rate": s["rate"] if rate is None else rate,
            "rate_source": "protocol" if rate is None else "command line", "seed_group": group,
            "seeds": {purpose: protocol_v5.seed(pv["name"], purpose, group, position, 1)
                      for purpose in collection.traffic_purposes()},
            "target": pv["target"], "dur_s": pv["warmup_s"] + seconds, "warmup_s": pv["warmup_s"],
            "summary_interval_s": pv["interval_s"], "initial_phase": "warmup"}


def precheck(protocol_path, run, t):
    """The generator's own check of the command line the run will give it (host_traffic.prepare_v5: profile and
    scenario, rate, warmup, the envelope draw), before anything is written."""
    from scripts import host_traffic
    args = SimpleNamespace(**dict.fromkeys(host_traffic.LEGACY_OPTIONS), profile=t["profile"],
                           protocol=Path(protocol_path), scenario=t["scenario"],
                           seeds=json.dumps(t["seeds"], sort_keys=True),
                           rate=t["rate"] if t["rate_source"] == "command line" else None, target=t["target"],
                           dur=float(t["dur_s"]), warmup_s=float(t["warmup_s"]), session_id=run.name,
                           requests_log=run / REQUESTS, intervals_log=run / INTERVALS,
                           summary_interval_s=float(t["summary_interval_s"]), initial_phase=t["initial_phase"],
                           out=run / STATUS)
    try:
        host_traffic.prepare_v5(args)
    except ValueError as error:
        raise Refused("the generator refuses the run: " + str(error)) from None


def quiet(pv):
    """No other generator against this VM and no collector reading it: the lab test neither mixes traffic nor runs
    beside a session."""
    others = collection.foreign_traffic(pv)
    if others:
        raise Refused(f"another host_traffic.py runs against {pv['target']} (pids {others}): the lab test does not "
                      "mix traffic")
    readers = collection.collectors(pv["domain"])
    if readers:
        raise Refused(f"a collector reads {pv['domain']} (pids {readers}): a session runs there")


def draw_events(p, scenario, n, cycles):
    """The N events of a long run, as the plan draws a session's (the executor's choice, scripts/protocol_v5.py
    _items and _times) and checked by the rules of a diagnostic run (collection.diagnostic_events), which return
    them as the plan states them.

    Types: one deck over all runs of the lab test, full rounds of the protocol's types each shuffled from the stream
    event_deck of the group skuska/long; the run of the k-th scenario of the protocol takes cards k*N to (k+1)*N,
    so with three events and six types each type runs twice in the four long runs. Times: durations uniform in
    duration_s, the free time of the run split by uniform spacings (first_s before, min_gap_s between, tail_s
    after), on the 1 ms grid, from the stream event_times of the group skuska/long/<scenario>; a draw a diagnostic
    run would refuse (the full-snapshot guard) is drawn again, at most protocol_v5.MAX_DRAWS times."""
    e = p["events"]
    if n not in e["per_session"]:
        raise Refused(f"--events {n}: the protocol allows {json.dumps(e['per_session'])} events in a session")
    if n == 0:
        return []
    types, k = list(e["types"]), list(p["scenarios"]).index(scenario)
    deck_rng, deck = random.Random(protocol_v5.seed(p["name"], "event_deck", "skuska/long", -1, 0)), []
    while len(deck) < (k + 1) * n:
        deck += deck_rng.sample(types, len(types))
    kinds = deck[k * n:(k + 1) * n]
    rng = random.Random(protocol_v5.seed(p["name"], "event_times", "skuska/long/" + scenario, 0, 1))
    low, high = (round(x * 1000) for x in e["duration_s"])
    first, gap, tail = (round(e[key] * 1000) for key in ("first_s", "min_gap_s", "tail_s"))
    reason = None
    for _ in range(protocol_v5.MAX_DRAWS):
        durations = [rng.randint(low, high) for _ in kinds]
        free = cycles * p["interval_s"] * 1000 - first - tail - sum(durations) - (n - 1) * gap
        if free < 0:
            raise Refused(f"{n} events do not fit a run of {cycles} collection intervals")
        offsets = sorted(rng.randint(0, free) for _ in kinds)
        items = [{"type": kind, "start_s": (first + offsets[i] + sum(durations[:i]) + i * gap) / 1000,
                  "duration_s": durations[i] / 1000} for i, kind in enumerate(kinds)]
        try:
            return collection.diagnostic_events(p, json.dumps(items), cycles)
        except ValueError as error:
            reason = str(error)
    raise Refused(f"no events a diagnostic run admits in {protocol_v5.MAX_DRAWS} draws: {reason}")


# ------------------------------------------------------------------ one run of the generator

def started(step, argv, protocol_path, raw, pv):
    return {"schema": RESULT_SCHEMA, "step": step, "command": shlex.join(["scripts/lab_trial.py", *map(str, argv)]),
            "protocol": str(Path(protocol_path).absolute()), "protocol_sha256": hashlib.sha256(raw).hexdigest(),
            "protocol_name": pv["name"], "vm": pv["vm"], "domain": pv["domain"], "target": pv["target"],
            "commit": commit(), "measurement_dirty": collection.measurement_dirty(),
            "qemu": collection.qemu_process(pv["domain"]), "started_unix": time.time(), "judgment": judgment(),
            "lead": lead(), "completed": False, "error": None}


def create(out, raw):
    out.mkdir(parents=True)
    (out / "protocol.json").write_bytes(raw)  # The generator reads this copy (collection.traffic_command).


def failure(error):
    return f"{type(error).__name__}: {error}"[:500]


def finish(out, result, problems):
    result["ended_unix"] = time.time()
    result["qemu_after"] = collection.qemu_process(result["domain"])  # record: the same QEMU in every run of a VM
    result["problems"] = problems(result)
    write(out / "result.json", result)
    print(json.dumps({"result": str(out / "result.json"), "completed": result["completed"],
                      "problems": len(result["problems"])}), flush=True)
    return 0 if result["completed"] else 1


def progress(name, **values):
    print(json.dumps({"step": name, **values}, default=str)[:400], flush=True)


def wait_header(child, path):
    """The request log's header once the generator wrote it, None when the generator exited first or none came
    within HEADER_TIMEOUT_S. The generator opens its logs after installing its signal handlers
    (host_traffic.py main_v5), so the signals sent from then on are handled."""
    deadline = time.monotonic() + HEADER_TIMEOUT_S
    while time.monotonic() < deadline and child.poll() is None:
        try:
            with path.open() as stream:
                line = stream.readline()
            if line.endswith("\n"):
                return json.loads(line)
        except (OSError, ValueError):
            pass
        time.sleep(POLL_S)
    return None


def drive(child, origin, t, drain_s, events=None):
    """SIGUSR1 at the end of the warmup and SIGUSR2 at --dur, from the generator's origin (its header's start_unix),
    as a session's runner does; the events at their times from the start of the measured part (collection.Events,
    one action per round). Returns ([the signals sent], error) when the drain after --dur is over and no event is
    due or active, when an event leaves the lab unrestored, or when the generator exits. The lab test runs outside
    every session (RIADENIE point 4), so this loop is none of the host's periodic processes during a session
    (scripts/host_periods.json)."""
    measure, end = origin + t["warmup_s"], origin + t["dur_s"]
    due, sent, length = [(measure, signal.SIGUSR1), (end, signal.SIGUSR2)], [], t["dur_s"] - t["warmup_s"]
    while child.poll() is None:
        now = time.time()
        while due and now >= due[0][0]:
            os.kill(child.pid, due[0][1])
            sent.append({"signal": due.pop(0)[1].name, "unix": time.time()})
        pending = False
        if events is not None:
            try:
                events.tick(measure)
            except ValueError as error:  # The lab was not restored after an event.
                return sent, str(error)
            pending = events.active is not None or any(
                "host_start_unix" not in r and r["start_s"] <= length for r in events.records)
        if not due and now >= end + drain_s and not pending:
            return sent, None
        time.sleep(TICK_S)
    return sent, f"the generator exited before its stop (exit code {child.returncode}); see {LOG}"


def final_status(path):
    try:
        status = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    keys = ("final", "phase", "requests", "ok", "errors", "intended_errors", "intended_errors_matched",
            "unexpected_results", "arrivals", "admitted", "dropped", "user_sessions_completed", "logging_error",
            "worker_errors")
    return {key: status.get(key) for key in keys}


def traffic_run(pv, run, t, drain_s, events=None):
    """One generator run in `run`, whose copy of the protocol is there: the health check, the generator with the
    command line of a session (collection.traffic_command), its signals (drive) and its stop
    (collection.stop_child, SIGTERM to its process group). Never raises after the generator started: what went
    wrong is its error."""
    out = {"traffic": t, "error": None}
    try:
        out["health_attempts"] = collection.wait_healthy(pv["target"])
    except ValueError as error:
        out["error"] = f"the lab is not healthy: {error}"
        return out
    command = [str(x) for x in collection.traffic_command(pv, {"traffic": t}, run)]
    out["generator_command"] = command
    child = collection.start_child(command, run / LOG)
    try:
        header = wait_header(child, run / REQUESTS)
        if header is None:
            out["error"] = f"the generator wrote no log header (exit code {child.poll()}); see {LOG}"
        else:
            out["run_id"], out["start_unix"] = header.get("run_id"), header.get("start_unix")
            out["signals"], out["error"] = drive(child, header["start_unix"], t, drain_s, events)
    finally:
        out["stop"] = collection.stop_child(child, STOP_GRACE_S)
    out["status"] = final_status(run / STATUS)
    return out


def measure_phase(run):
    """(the reasons of the drops, the most concurrent user sessions) of the run's measure phase: {drop_reason: count}
    of its dropped arrival records (NO_DROP_REASON for one that names none), and the largest active_max of its
    intervals (None without one)."""
    records, _ = traffic_log.read_jsonl(run / REQUESTS)
    intervals, _ = traffic_log.read_jsonl(run / INTERVALS)
    reasons = Counter(r.get("drop_reason") or NO_DROP_REASON for r in records
                      if r.get("type") == "arrival" and r.get("phase") == "measure" and r.get("admitted") is False)
    active = [iv["active_max"] for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"]
    return dict(sorted(reasons.items())), max(active, default=None)


def traffic_summary(run):
    """scripts/traffic_log.py summarize of the run's logs, its problems and the measure phase, with the reasons of
    its drops and its most concurrent user sessions (measure_phase)."""
    s = traffic_log.summarize(run / REQUESTS, run / INTERVALS, session_id=run.name)
    m = s["measure"]
    reasons, active_max = measure_phase(run)
    return {"problems": s["problems"][:20], "problem_count": len(s["problems"]), "clean": s["clean"],
            "arrivals": s.get("arrivals"), "drop_reasons": reasons, "active_max": active_max, "phases": s["phases"],
            "measure": {key: m.get(key) for key in ("requests", "ok", "errors", "phase_duration_s",
                                                    "phase_request_rate_rps", "latency_ms",
                                                    "max_ok_completion_gap_s")}}


def analysis(run, p, scenario, windows):
    found = {"windows": [list(w) for w in windows], "summary": traffic_summary(run)}
    try:
        found["realism"] = traffic_log.realism(run / REQUESTS, run / INTERVALS, p, scenario, windows=windows)
    except (ValueError, KeyError, TypeError) as error:
        found["realism"] = {"error": failure(error)}
    return found


# ------------------------------------------------------------------ deploy

def json_objects(text):
    """The JSON objects labctl printed, one per line or indented over lines (its health state), and the other lines."""
    decoder, found, other, pos = json.JSONDecoder(), [], [], 0
    while pos < len(text):
        stop = text.find("\n", pos)
        stop = len(text) if stop < 0 else stop + 1
        if text.startswith("{", pos):
            try:
                doc, end = decoder.raw_decode(text, pos)
            except ValueError:
                doc = None
            if type(doc) is dict:
                found.append(doc)
                newline = text.find("\n", end)
                pos = len(text) if newline < 0 else newline + 1
                continue
        other.append(text[pos:stop].rstrip("\n"))
        pos = stop
    return found, other


def cgroup_memory(path):
    """What the cgroup v2 `path` (as /proc/<pid>/cgroup names it) holds: memory.current, anon of memory.stat,
    memory.swap.current and memory.swap.max (None where unreadable)."""
    base = labctl.CGROUPS / path.lstrip("/")

    def read(name):
        try:
            return (base / name).read_text().strip()
        except OSError:
            return None

    def number(name):
        text = read(name) or ""
        return int(text) if text.isdigit() else None
    anon = re.search(r"^anon (\d+)$", read("memory.stat") or "", re.M)
    return {"cgroup": path, "memory_current": number("memory.current"), "anon": int(anon[1]) if anon else None,
            "swap_current": number("memory.swap.current"), "swap_max": read("memory.swap.max")}


def qemu_memory(domain):
    """Where the VM's QEMU stands after labctl deploy (finding F4 of the B5a verification): its cgroup and
    memory.swap.max there, VmSwap, RssAnon, what its own cgroup is charged with (scripts/labctl.py charge, the check
    labctl's start makes: anon over the RssAnon of every QEMU process in the cgroup, at least CHARGED_SHARE; the
    lead's answer to Q26), and every leaf cgroup of its user's slice that holds at least HOLDER_SHARE of its RssAnon:
    a process moved into a scope keeps its pages charged where they were faulted. Reads /proc and /sys/fs/cgroup only
    (scripts/labctl.py PROC and CGROUPS), no root."""
    try:
        pid = labctl.qemu_pid(domain)
    except RuntimeError as error:
        return {"domain": domain, "error": str(error)}
    if pid is None:
        return {"domain": domain, "qemu_pid": None}
    cgroup, swap = labctl.swap_max(pid)
    status = (labctl.PROC / str(pid) / "status").read_text()
    rss = re.search(r"^RssAnon:\s+(\d+) kB$", status, re.M)
    uid = re.search(r"^Uid:\s+(\d+)", status, re.M)
    rss_bytes = int(rss[1]) << 10 if rss else None
    own = cgroup_memory(cgroup) if cgroup else None
    holders = []
    root = labctl.CGROUPS / f"user.slice/user-{uid[1] if uid else os.getuid()}.slice"
    for leaf in sorted(d for d in root.rglob("*") if d.is_dir() and not any(c.is_dir() for c in d.iterdir())):
        found = cgroup_memory("/" + leaf.relative_to(labctl.CGROUPS).as_posix())
        if rss_bytes and found["anon"] is not None and found["anon"] >= HOLDER_SHARE * rss_bytes:
            holders.append(found)
    charge = labctl.charge(cgroup)
    try:
        swappiness = int((labctl.PROC / "sys/vm/swappiness").read_text())
    except (OSError, ValueError):
        swappiness = None
    return {"domain": domain, "qemu_pid": pid, "cgroup": cgroup, "memory_swap_max": swap,
            "vm_swap_kb": labctl.vm_swap_kb(pid), "rss_anon_kb": int(rss[1]) if rss else None, "own": own,
            "charge": charge, "own_anon_share": charge["share"], "charged_to_own_cgroup": charge["charged"],
            "holders": holders, "vm_swappiness": swappiness}


def deploy(a, argv):
    raw, p = load(a.protocol)
    pv = for_vm(p, a.vm)
    out = new_dir(a.out)
    quiet(pv)
    create(out, raw)
    result = started("deploy", argv, a.protocol, raw, pv)
    try:
        command = collection.user_command([sys.executable, LABCTL, "deploy", *collection.labctl_args(pv)])
        reply = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=DEPLOY_TIMEOUT_S)
        (out / "labctl_deploy.stdout").write_text(reply.stdout)
        (out / "labctl_deploy.stderr").write_text(reply.stderr)
        objects, other = json_objects(reply.stdout)
        swap_failed = reply.returncode != 0 and SWAP_FAILED in reply.stderr
        result["labctl"] = {"command": command, "rc": reply.returncode, "swap_failed": swap_failed,
                            **{key: next((o[key] for o in objects if key in o), None)
                               for key in ("libvirtd", "qemu_swap")},
                            "state": next((o for o in objects if "health" in o), None), "other_lines": len(other),
                            "stderr": reply.stderr.strip()[-2000:]}
        if reply.returncode and not swap_failed:
            raise RuntimeError(f"labctl deploy exited with {reply.returncode}; see labctl_deploy.stderr")
        try:
            result["health"] = {"ok": True, "attempts": collection.wait_healthy(pv["target"])}
        except ValueError as error:
            result["health"] = {"ok": False, "error": str(error)}
        identity = collection.guest_identity(pv)
        result["guest"] = {**{key: identity[key] for key in ("kernel", "boot_id", "machine_id", "stack_sha256")},
                           "mismatch": collection.guest_mismatch(identity, collection.lab_sha256())}
        result["qemu_memory"] = qemu_memory(pv["domain"])
        result["completed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = failure(error)
    return finish(out, result, deploy_problems)


def deploy_problems(r):
    out = [f"deploy did not complete: {r['error']}"] if r["error"] else []
    lab = r.get("labctl") or {}
    if lab.get("swap_failed"):
        out.append("the swap step of labctl deploy failed: " + lab["stderr"][-300:])
    swap = lab.get("qemu_swap") or {}
    if lab and (swap.get("memory_swap_max") != "0" or swap.get("vm_swap_kb") != 0):
        out.append(f"labctl's qemu_swap record: memory.swap.max {swap.get('memory_swap_max')!r}, VmSwap "
                   f"{swap.get('vm_swap_kb')} kB (both must be 0)")
    if r.get("health", {}).get("ok") is False:
        out.append("health check after deploy: " + r["health"]["error"])
    if r.get("guest", {}).get("mismatch"):
        out.append("the guest does not run the lab/ files of this commit: " + ", ".join(r["guest"]["mismatch"]))
    memory = r.get("qemu_memory") or {}
    if memory and memory.get("charged_to_own_cgroup") is not True:
        holders = ", ".join(f"{h['cgroup']} (swap_max {h['swap_max']})" for h in memory.get("holders", []))
        charge = memory.get("charge") or {}  # The RssAnon of every QEMU process in the cgroup (labctl.charge).
        out.append(f"QEMU's memory is not charged to its own cgroup {memory.get('cgroup')}: it holds "
                   f"{memory.get('own_anon_share')} of RssAnon {charge.get('rss_anon_kb')} kB"
                   + (f" ({charge['error']})" if charge.get("error") else "") + "; holders " + (holders or "none"))
    return out


# ------------------------------------------------------------------ saturation

def expected(r):
    """A request got its expected result: a 2xx, or the status a deliberate client error intends (the generator's
    exit-code rule, scripts/host_traffic.py SessionMetrics)."""
    return r.get("outcome") == "ok" if r.get("intended_status") is None else r.get("status") == r["intended_status"]


NO_DROP_REASON = "no drop_reason"  # A dropped arrival record that names no reason (a generator before package B5c).


def drop_reasons(records, intervals, ids):
    """{drop_reason: count} of the arrivals dropped in the intervals `ids`: the generator names the reason of each
    (package B5c: max_concurrent or all_customers_held; NO_DROP_REASON for one that names none). The arrivals in time
    order fill the intervals in their order, each with as many as it offered, as the log audit assigns them
    (scripts/traffic_log.py)."""
    queue = sorted((r for r in records if r.get("type") == "arrival"), key=lambda r: r["t_mono"])
    found, position = Counter(), 0
    for iv in (iv for iv in intervals if iv.get("type") == "interval"):
        block = queue[position:position + iv["offered_sessions"]]
        position += iv["offered_sessions"]
        if iv["interval"] in ids:
            found.update(a.get("drop_reason") or NO_DROP_REASON for a in block if a.get("admitted") is False)
    return dict(sorted(found.items()))


def peak_of(run):
    """The peak of one step's logs: the intervals of the measure phase whose planned level (the header's envelope)
    is 1 over all of them, with the user sessions offered, admitted and dropped there (the interval log) and the
    reasons of the drops (drop_reasons), the requests that started in them, how many lacked their expected result,
    their p95 latency (exact nearest rank), and the delivered user sessions and requests per second of the peak."""
    records, _ = traffic_log.read_jsonl(run / REQUESTS)
    intervals, _ = traffic_log.read_jsonl(run / INTERVALS)
    envelope = traffic_log.Envelope(next(r for r in records if r.get("type") == "header")["envelope"])
    peaks = [iv for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"
             and iv["mono_end"] > iv["mono_start"] and envelope.integral(iv["mono_start"], iv["mono_end"])
             >= (iv["mono_end"] - iv["mono_start"]) * (1 - PEAK_TOLERANCE)]
    ids = {iv["interval"] for iv in peaks}
    requests = [r for r in records if r.get("type") == "request" and r.get("interval") in ids]
    seconds = sum(iv["mono_end"] - iv["mono_start"] for iv in peaks)
    admitted = sum(iv["admitted_sessions"] for iv in peaks)
    return {"intervals": len(peaks), "seconds": round(seconds, 6),
            "offered": sum(iv["offered_sessions"] for iv in peaks), "admitted": admitted,
            "dropped": sum(iv["dropped_sessions"] for iv in peaks),
            "drop_reasons": drop_reasons(records, intervals, ids),
            "active_max": max((iv["active_max"] for iv in peaks), default=None), "requests": len(requests),
            "unexpected": sum(not expected(r) for r in requests),
            "p95_ms": traffic_log.percentile(sorted(r["duration_ms"] for r in requests), .95),
            "sessions_per_s": round(admitted / seconds, 6) if seconds else None,
            "requests_per_s": round(len(requests) / seconds, 6) if seconds else None}


def named_drops(dropped, reasons):
    return f"{dropped} user sessions dropped (drop_reason: " + (
        ", ".join(f"{reason} {n}" for reason, n in reasons.items()) or "no dropped arrival record") + ")"


def step_errors(peak):
    """Why a step cannot be judged, [] when it can (the lead's answer to Q5): no interval of the measure phase wholly
    at envelope level 1, no request in the peak, or a user session dropped there, named by its drop_reason (package
    B5c, finding F1: the lab_trial half). A drop is a limit of the generator (its max_concurrent, its customers), not
    of the server, so the series ends at such a step with an error, never with a saturation."""
    errors = []
    if not peak["intervals"]:
        errors.append("no interval of the measure phase lies wholly at envelope level 1")
    elif not peak["requests"]:
        errors.append("no request started in the peak")
    if peak["dropped"]:
        errors.append(named_drops(peak["dropped"], peak["drop_reasons"]) + " in the peak: a limit of the generator, "
                      "not of the server")
    return errors


def step_reasons(peak):
    """Why a judged step failed on the server, [] when its peak was served (the lead's answer to Q5): a request of the
    peak intervals without its expected result, or a p95 latency of at least LATENCY_P95_BOUND_MS (judgment)."""
    reasons = []
    if peak["unexpected"]:
        reasons.append(f"{peak['unexpected']} requests without their expected result")
    if peak["p95_ms"] is not None and peak["p95_ms"] >= LATENCY_P95_BOUND_MS:
        reasons.append(f"p95 latency {peak['p95_ms']:g} ms, not below {LATENCY_P95_BOUND_MS:g} ms")
    return reasons


SERIES_RULE = ("the steps run on a copy of the protocol whose profiles.<profile>.max_concurrent is max(the "
               f"protocol's, ceil({CAP_FACTOR_S} x the highest rate of --rates)), so the generator's ceiling does "
               "not bind (the lead's answer to Q5); the series directory keeps the given file, every step directory "
               "the copy")
SATURATION_RULE = (
    "the server's throughput at saturation (the lead's answer to Q5, 2026-11-24): a diagnostic series, no session, on "
    "the series copy of the protocol; a step fails on the server when a request of its peak intervals lacks its "
    "expected result or their p95 latency is at least the bound; a step without a peak or with a user session dropped "
    "in it is invalid and ends the series with an error (finding F1 of the B5c verification); the steps of --rates "
    "run in increasing order up to the first failed one, then the bisection (the lead's answer to Q5) at the "
    f"geometric midpoint of the highest served and the lowest failed rate, rounded to {MIDPOINT_DECIMALS} decimals "
    "(the executor's judgment, package B11), until the failed rate is less than "
    f"{STEP_RATIO_MAX} times the served one (the executor's reading of the lead's 15 %, package B11); the "
    "throughput is the highest served rate, and proposed_rate is scenario_rule.peak_share of it")


def bracket(steps):
    """(served, failed) of the judged steps: the lowest failed one and the highest served one below it (None: none)."""
    judged = [s for s in steps if "reasons" in s]
    failed = min((s for s in judged if s["reasons"]), key=lambda s: s["rate"], default=None)
    served = max((s for s in judged if not s["reasons"] and (failed is None or s["rate"] < failed["rate"])),
                 key=lambda s: s["rate"], default=None)
    return served, failed


def midpoint(low, high):
    """The rate of the next bisection step: the geometric midpoint of the served and the failed rate (the criterion
    STEP_RATIO_MAX is relative), rounded to MIDPOINT_DECIMALS (judgment)."""
    return round(math.sqrt(low * high), MIDPOINT_DECIMALS)


def saturation_rule(steps, peak_share):
    """The saturation of the judged steps and the rates proposed from it (scenario_rule.peak_share of it per
    intensity): SATURATION_RULE. bracket is [served, failed] and ratio failed / served while both exist."""
    served, failed = bracket(steps)
    rate = served["rate"] if served else None
    return {"rule": SATURATION_RULE, "latency_p95_bound_ms": LATENCY_P95_BOUND_MS, "step_ratio_max": STEP_RATIO_MAX,
            "rate": rate, "failure": None if failed is None else {"rate": failed["rate"], "reasons": failed["reasons"]},
            "bracket": [rate, failed["rate"]] if served and failed else None,
            "ratio": round(failed["rate"] / rate, 6) if served and failed else None,
            "delivered_sessions_per_s": served["peak"]["sessions_per_s"] if served else None,
            "requests_per_s": served["peak"]["requests_per_s"] if served else None,
            "proposed_rate": {name: None if rate is None else round(share * rate, 6)
                              for name, share in peak_share.items()}}


def series_protocol(raw, profile, rates):
    """(bytes, record) of the copy of the protocol the steps of a saturation series run on: SERIES_RULE. The copy is
    the given file itself when its cap is high enough already; the record names the cap before and after and the
    sha256 of both files."""
    doc = json.loads(raw)
    before = doc["profiles"][profile]["max_concurrent"]
    after = max(before, math.ceil(CAP_FACTOR_S * max(rates)))
    if after != before:
        doc["profiles"][profile]["max_concurrent"] = after
    copy = raw if after == before else (json.dumps(doc, indent=2) + "\n").encode()
    return copy, {"rule": SERIES_RULE, "path": f"profiles.{profile}.max_concurrent", "before": before, "after": after,
                  "sha256_before": hashlib.sha256(raw).hexdigest(), "sha256_after": hashlib.sha256(copy).hexdigest()}


def saturation(a, argv):
    raw, p = load(a.protocol)
    pv = for_vm(p, a.vm)
    s = scenario_of(p, a.scenario)
    if a.profile not in p["profiles"]:
        raise Refused(f"unknown profile: {a.profile} (the protocol has {', '.join(p['profiles'])})")
    if s["profile"] != a.profile:
        raise Refused(f"--profile {a.profile} differs from scenarios.{a.scenario}.profile {s['profile']}")
    rates = rates_of(a.rates)
    out = new_dir(a.out)
    for k, rate in enumerate(rates):
        precheck(a.protocol, out / f"step-{k + 1:02d}",
                 traffic_block(pv, a.scenario, a.profile, rate, "saturation", k, SATURATION_MEASURE_S))
    copy, series = series_protocol(raw, a.profile, rates)
    quiet(pv)
    create(out, raw)
    result = started("saturation", argv, a.protocol, raw, pv)
    result.update(profile=a.profile, scenario=a.scenario, intensity=s["intensity"], rates=rates,
                  series_protocol=series, steps=[])

    def step(rate, kind):
        """One step of the series: 'served', 'failed' or 'error' (its run, its logs or step_errors)."""
        k = len(result["steps"])
        run = out / f"step-{k + 1:02d}"
        entry = {"step": run.name, "kind": kind, "rate": rate}
        result["steps"].append(entry)
        t = traffic_block(pv, a.scenario, a.profile, rate, "saturation", k, SATURATION_MEASURE_S)
        try:
            if kind == "bisection":  # The initial steps were checked before anything was written.
                precheck(a.protocol, run, t)
            create(run, copy)
            entry["run"] = traffic_run(pv, run, t, SATURATION_DRAIN_S)
            if entry["run"]["error"]:
                return "error"
            entry["log_problems"] = traffic_summary(run)["problems"][:10]
            entry["peak"] = peak_of(run)
            entry["errors"] = step_errors(entry["peak"])
            if entry["errors"]:
                return "error"
            entry["reasons"] = step_reasons(entry["peak"])
        except (OSError, ValueError, KeyError, StopIteration) as error:  # Refused is a ValueError.
            entry["error"] = failure(error)
            return "error"
        progress("saturation-step", rate=rate, kind=kind, served=not entry["reasons"])
        return "failed" if entry["reasons"] else "served"

    outcome = None
    for rate in rates:
        outcome = step(rate, "initial")
        if outcome != "served":
            break
    if outcome == "failed":  # Bisection of the bracket; every step lies strictly inside it, so it narrows.
        while True:
            served, failed = bracket(result["steps"])
            if served is None or failed["rate"] / served["rate"] < STEP_RATIO_MAX:
                break
            rate = midpoint(served["rate"], failed["rate"])
            if not served["rate"] < rate < failed["rate"]:
                result["bisection_stop"] = (f"no rate of {MIDPOINT_DECIMALS} decimals lies between "
                                            f"{served['rate']:g} and {failed['rate']:g}")
                break
            if step(rate, "bisection") == "error":
                break
    result["saturation"] = saturation_rule(result["steps"], p["scenario_rule"]["peak_share"])
    bad = [e for e in result["steps"] if e.get("error") or e.get("errors") or (e.get("run") or {}).get("error")]
    result["error"] = (f"{bad[0]['step']} (rate {bad[0]['rate']:g}): " + (
        bad[0].get("error") or "; ".join(bad[0].get("errors") or []) or bad[0]["run"]["error"])) if bad else None
    result["completed"] = not bad
    return finish(out, result, saturation_problems)


def saturation_problems(r):
    """What the series leaves open: an invalid step (the error), the lowest rate failing (nothing to bisect), every
    step served (a lower bound), and a bracket still at least STEP_RATIO_MAX wide."""
    sat, judged, out = r["saturation"], [s for s in r["steps"] if "reasons" in s], []
    if r["error"]:  # The series ended at an invalid step: what it found is a lower bound.
        out.append(f"saturation did not complete: {r['error']}" + (
            f"; the steps before it put the saturation at {sat['rate']:g} or above"
            if sat["rate"] is not None and sat["failure"] is None else ""))
    if judged and sat["rate"] is None:
        out.append(f"no step served its peak: the lowest rate {judged[0]['rate']:g} fails ("
                   + "; ".join(judged[0]["reasons"]) + "), so there is no bracket to bisect")
    if judged and sat["failure"] is None and not r["error"]:
        out.append(f"every step served its peak: the throughput lies above the highest rate {judged[-1]['rate']:g}; "
                   "the proposed rates are lower bounds")
    if sat["ratio"] is not None and sat["ratio"] >= STEP_RATIO_MAX:
        out.append(f"the bracket [{sat['bracket'][0]:g}, {sat['bracket'][1]:g}] is still {sat['ratio']:g} wide, not "
                   f"below {STEP_RATIO_MAX:g}" + (f" ({r['bisection_stop']})" if r.get("bisection_stop") else ""))
    for s in r["steps"]:
        if s.get("log_problems"):
            out.append(f"{s['step']} (rate {s['rate']:g}): traffic log problems: " + ", ".join(s["log_problems"][:3]))
    return out


# ------------------------------------------------------------------ scenario and long

def traffic_problems(r):
    """What does not hold in a scenario or long run: the generator, its logs and the realism requirements."""
    out = [f"the run did not complete: {r['error']}"] if r["error"] else []
    run = r.get("run") or {}
    if run.get("error") and run["error"] != r["error"]:
        out.append(f"the run: {run['error']}")
    rc = (run.get("stop") or {}).get("rc")
    if rc not in (None, 0):
        out.append(f"generator exit code {rc} (1: a request without its expected result or no success; 3: a logging "
                   "failure)")
    summary = r.get("summary") or {}
    if summary.get("problems"):
        out.append("traffic log problems: " + ", ".join(summary["problems"][:3]))
    dropped = ((summary.get("arrivals") or {}).get("measure") or {}).get("dropped")
    if dropped:  # Named by their drop_reason (package B5c, finding F1: the lab_trial half).
        out.append(named_drops(dropped, summary.get("drop_reasons") or {}) + " in the measure phase")
    realism = r.get("realism") or {}
    if "error" in realism:
        out.append("realism not computed: " + realism["error"])
    for req in realism.get("requirements", []):
        if not req["ok"]:
            out.append(f"realism {req['name']}: {json.dumps(req['value'])} against {json.dumps(req['bound'])}")
    load = realism.get("offered_load")
    if load and not load["ok"]:
        out.append(f"offered load {load['ratio']} of the plan ({load['offered']} of {load['planned']} user sessions)")
    return out


def scenario(a, argv):
    raw, p = load(a.protocol)
    pv = for_vm(p, a.vm)
    s = scenario_of(p, a.scenario)
    seconds, _ = measured(p, a.minutes)
    out = new_dir(a.out)
    t = traffic_block(pv, a.scenario, s["profile"], a.rate, "scenario", 0, seconds)
    precheck(a.protocol, out, t)
    quiet(pv)
    create(out, raw)
    result = started("scenario", argv, a.protocol, raw, pv)
    result.update(scenario=a.scenario, profile=s["profile"], intensity=s["intensity"], rate=t["rate"],
                  minutes=a.minutes)
    try:
        result["run"] = traffic_run(pv, out, t, DRAIN_S)
        if (out / REQUESTS).exists():
            result.update(analysis(out, p, a.scenario, []))
        result["error"] = result["run"]["error"]
        result["completed"] = result["error"] is None
    except (OSError, ValueError, KeyError) as error:
        result["error"] = failure(error)
    return finish(out, result, traffic_problems)


JOURNAL_LOSS = re.compile(r"Suppressed \d+ messages|Missed \d+ journal messages")  # As the log audit reads it.


def in_windows(windows, *times):
    return any(lo <= t <= hi for t in times for lo, hi in windows)


def segment_file(guest, doc, suffix):
    entry = next(f for f in doc["files"] if f["name"].endswith(suffix))
    return guest / entry["file"]


def nginx_errors(path, windows):
    """The lines of the run's nginx error log, each inside an event window or not, as the log audit judges them
    (scripts/collection_logs.py: guest local time, the lab guest runs in UTC, a line's second may reach into a
    window)."""
    with gzip.open(path, "rt", errors="replace") as stream:
        lines = [line.rstrip("\n") for line in stream if line.strip()]
    outside = []
    for line in lines:
        m = collection_logs.NGINX_TIME.match(line)
        stamp = m and datetime.strptime(m[1], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        if not (stamp and in_windows(windows, stamp, stamp + 1)):
            outside.append(line[:180])
    return {"lines": len(lines), "in_event_windows": len(lines) - len(outside), "outside_count": len(outside),
            "outside": outside[:20]}


def journal_lines(path):
    """(unix time, line) of every line of a fetched journal segment (journalctl -o short-iso-precise --utc,
    lab/guest_state.py journal); continuation lines without a time are left out."""
    with gzip.open(path, "rt", errors="replace") as stream:
        for line in stream:
            stamp = line.split(" ", 1)[0]
            try:
                yield datetime.fromisoformat(stamp).timestamp(), line.rstrip("\n")
            except ValueError:
                continue


def journal_errors(path, windows):
    """Lost journal lines, and tracebacks and worker errors outside the event windows (as the log audit)."""
    loss, errors, tolerated = [], [], 0
    for t, line in journal_lines(path):
        if JOURNAL_LOSS.search(line):
            loss.append(line[:180])
        elif "Traceback (most recent call last)" in line or collection_logs.WORKER_ERROR in line:
            if in_windows(windows, t):
                tolerated += 1
            else:
                errors.append(line[:180])
    return {"loss": loss[:20], "errors_in_event_windows": tolerated, "errors_outside_count": len(errors),
            "errors_outside": errors[:20]}


def event_summary(r):
    keys = ("type", "class", "start_s", "duration_s", "start_phase_s", "stop_phase_s", "executed", "host_start_unix",
            "host_started_unix", "host_stop_unix", "host_stopped_unix")
    return {**{key: r.get(key) for key in keys}, "effect_ok": (r.get("effect") or {}).get("ok")}


# lab_trial long --postgres-debug1 (the lead's answers to Q9 and Q27): for one run PostgreSQL in the guest logs every
# worker start of the autovacuum launcher into the journal, as entry 4 of docs/ODCHYLKY_V5.sk.md did by hand, so the
# spacing after the change to 67 s is measured the same way; after the run both settings go back. ALTER SYSTEM writes
# postgresql.auto.conf, which is no deployed file: the guest's lab/ files stay as deployed.
DEBUG1_SET = ("ALTER SYSTEM SET log_min_messages = 'debug1'", "ALTER SYSTEM SET log_destination = 'stderr,syslog'",
              "SELECT pg_reload_conf()")
DEBUG1_RESET = ("ALTER SYSTEM RESET log_min_messages", "ALTER SYSTEM RESET log_destination", "SELECT pg_reload_conf()")
DEBUG1_SHOW = ("SHOW log_min_messages", "SHOW log_destination")
DEBUG1_DURING = ["debug1", "stderr,syslog"]  # What DEBUG1_SHOW gives after the set step.
DEBUG1_RULE = ("the step set (" + "; ".join(DEBUG1_SET) + ") before the run and the step reset ("
               + "; ".join(DEBUG1_RESET) + ") after it, also when the run fails; " + " and ".join(DEBUG1_SHOW)
               + " before the set, after it (must give " + " and ".join(DEBUG1_DURING) + ") and after the reset (must "
               "give what they gave before the set); each through labctl exec as the user postgres")


def psql(statements):
    """The guest command that runs `statements` in order with psql as the user postgres, one -c each."""
    return shlex.join(["runuser", "-u", "postgres", "--", "psql", "-XtA",
                       *(part for statement in statements for part in ("-c", statement))])


def guest_sql(pv, statements):
    """One labctl exec of psql (psql) in the guest: {command, rc, output lines, stderr}. Never raises: a command that
    cannot run has rc None and its error."""
    command = psql(statements)
    step = {"command": command, "rc": None, "output": None, "stderr": None}
    try:
        reply = subprocess.run(collection.user_command([sys.executable, LABCTL, "exec", *collection.labctl_args(pv),
                                                        "--guest-command", command]),
                               cwd=ROOT, capture_output=True, text=True, timeout=GUEST_SQL_TIMEOUT_S)
        step.update(rc=reply.returncode, output=reply.stdout.splitlines(), stderr=reply.stderr.strip()[-500:])
    except (OSError, subprocess.SubprocessError) as error:
        step["error"] = failure(error)
    return step


def debug1_on(pv, record):
    """The steps before the run (DEBUG1_RULE): show, set, show again. ValueError when the set step failed or debug1
    logging is not on after it, so the run does not start; debug1_off follows either way."""
    record["before"] = guest_sql(pv, DEBUG1_SHOW)
    record["set"] = guest_sql(pv, DEBUG1_SET)
    record["during"] = guest_sql(pv, DEBUG1_SHOW)
    if record["set"]["rc"] != 0 or record["during"]["output"] != DEBUG1_DURING:
        raise ValueError(f"PostgreSQL debug1 logging is not on: the set step ended with rc {record['set']['rc']}, and "
                         f"{' and '.join(DEBUG1_SHOW)} give {record['during']['output']}")


def debug1_off(pv, record):
    """The steps after the run (DEBUG1_RULE): reset, then show."""
    record["reset"] = guest_sql(pv, DEBUG1_RESET)
    record["after"] = guest_sql(pv, DEBUG1_SHOW)


def debug1_problems(record):
    """What does not hold of DEBUG1_RULE in the record of a run."""
    out = [f"step {name} ended with rc {record[name]['rc']}" + (f": {record[name]['error']}"
                                                                 if record[name].get("error") else "")
           for name in ("before", "set", "during", "reset", "after") if name in record and record[name]["rc"] != 0]
    if "during" in record and record["during"]["output"] != DEBUG1_DURING:
        out.append(f"after the set step {' and '.join(DEBUG1_SHOW)} give {record['during']['output']}, not "
                   + " and ".join(DEBUG1_DURING))
    before, after = ((record.get(name) or {}).get("output") for name in ("before", "after"))
    if after != before:
        out.append(f"after the reset step {' and '.join(DEBUG1_SHOW)} give {after}, not what they gave before the run "
                   f"{before}")
    return out


AUTOVACUUM = "PostgreSQL autovacuum launcher"  # Its entry of lab/periods.json.
AUTOVACUUM_RULE = (f"the median spacing of the worker starts modulo interval_s lies in [{AUTOVACUUM_REMAINDER_S[0]}, "
                   f"{AUTOVACUUM_REMAINDER_S[1]}] s: at least {AUTOVACUUM_REMAINDER_S[0]} s from every multiple of the "
                   "collection interval (the lead's answer to Q9, 2026-11-24)")


def autovacuum_property(periods, interval_s):
    """The property of the lead's answer to Q9 on the measured spacing of the autovacuum launcher's worker starts
    (`periods` as periods_of gives them): AUTOVACUUM_RULE, with the median, its remainder modulo interval_s and ok;
    ok is None, with why, when the spacing was not measured."""
    item = next((e for e in periods if e["name"] == AUTOVACUUM), None)
    out = {"rule": AUTOVACUUM_RULE, "interval_s": interval_s, "bounds_s": list(AUTOVACUUM_REMAINDER_S),
           "median_s": None, "remainder_s": None, "ok": None}
    if item is None or not item["spacings"]:
        return {**out, "why": f"spacing not measured: {item['why']}" if item else f"no register entry {AUTOVACUUM}"}
    median = item["spacings"]["median"]
    remainder = round(median % interval_s, 6)
    low, high = AUTOVACUUM_REMAINDER_S
    return {**out, "median_s": median, "remainder_s": remainder, "ok": low <= remainder <= high}


def autovacuum_problems(found):
    """The problem of a measured spacing that does not have the property of Q9; none when it was not measured."""
    if not found or found["ok"] is not False:
        return []
    return [f"{AUTOVACUUM}: the median spacing {found['median_s']:g} s of the worker starts lies "
            f"{found['remainder_s']:g} s past a multiple of interval_s {found['interval_s']:g} s, outside "
            f"[{found['bounds_s'][0]:g}, {found['bounds_s'][1]:g}] s (the lead's answer to Q9)"]


def long_run(a, argv):
    raw, p = load(a.protocol)
    pv = for_vm(p, a.vm)
    s = scenario_of(p, a.scenario)
    seconds, cycles = measured(p, a.minutes)
    out = new_dir(a.out)
    if not LABEL.fullmatch(out.name + "-journal"):
        raise Refused(f"the run directory's name {out.name} is no guest segment label ({LABEL.pattern} with "
                      "-pre and -journal added)")
    events = draw_events(p, a.scenario, a.events, cycles)
    t = traffic_block(pv, a.scenario, s["profile"], a.rate, "long", 0, seconds)
    precheck(a.protocol, out, t)
    quiet(pv)
    create(out, raw)
    guest = out / "guest"
    guest.mkdir()
    result = started("long", argv, a.protocol, raw, pv)
    result.update(scenario=a.scenario, profile=s["profile"], intensity=s["intensity"], rate=t["rate"],
                  minutes=a.minutes, events_planned=events)
    runner = collection.Events(pv, events, progress)
    debug1 = {"rule": DEBUG1_RULE} if a.postgres_debug1 else None
    if debug1 is not None:
        result["postgres_debug1"] = debug1
    try:
        try:
            if debug1 is not None:
                debug1_on(pv, debug1)
            result["pre_segment"] = collection.lab_json(pv, "segment", "--label", out.name + "-pre", "--dest", guest)
            since = time.time()
            try:
                result["run"] = traffic_run(pv, out, t, DRAIN_S, runner)
            finally:
                runner.close(out / "events.json")
        finally:
            if debug1 is not None:  # Also when the set step or the run failed: back to what was there before.
                debug1_off(pv, debug1)
        result["events"] = [event_summary(r) for r in runner.records]
        windows = [(r["host_start_unix"] - 1, r["host_stopped_unix"] + p["events"]["grace_s"])
                   for r in runner.records if "host_start_unix" in r and "host_stopped_unix" in r]
        segment = collection.lab_json(pv, "segment", "--label", out.name, "--dest", guest)
        journal = collection.lab_json(pv, "journal", "--label", out.name + "-journal", "--since", f"{since:.6f}",
                                      "--until", f"{time.time():.6f}", "--dest", guest)
        result["segment"], result["journal"] = segment, journal
        if (out / REQUESTS).exists():
            result.update(analysis(out, p, a.scenario, windows))
        result["nginx_errors"] = nginx_errors(segment_file(guest, segment, "-nginx-error.log"), windows)
        result["journal_errors"] = journal_errors(segment_file(guest, journal, "-journal.txt"), windows)
        result["periods"] = periods_of([out])
        result["autovacuum_property"] = autovacuum_property(result["periods"], p["interval_s"])
        result["error"] = result["run"]["error"]
        result["completed"] = result["error"] is None
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        result["error"] = failure(error)
    return finish(out, result, long_problems)


def long_problems(r):
    out = traffic_problems(r)
    debug1 = r.get("postgres_debug1")
    if debug1 is not None:
        out += [f"PostgreSQL debug1 logging (--postgres-debug1): {problem}" for problem in debug1_problems(debug1)]
    out += autovacuum_problems(r.get("autovacuum_property"))
    for e in r.get("events", []):
        if e["executed"] is not True or e["effect_ok"] is not True:
            out.append(f"event {e['type']} at {e['start_s']:g} s: executed {e['executed']}, effect ok {e['effect_ok']}")
    nginx = r.get("nginx_errors") or {}
    if nginx.get("outside_count"):
        out.append(f"{nginx['outside_count']} nginx error log lines outside the event windows, the first: "
                   + nginx["outside"][0])
    journal = r.get("journal_errors") or {}
    if journal.get("loss"):
        out.append("the guest journal lost lines: " + journal["loss"][0])
    if journal.get("errors_outside_count"):
        out.append(f"{journal['errors_outside_count']} tracebacks or worker errors in the journal outside the event "
                   "windows, the first: " + journal["errors_outside"][0])
    return out


# ------------------------------------------------------------------ periods

RESTART_LINE = re.compile(r"systemd\[1\]: (hyptcn-lab@[\w.-]+\.service): Scheduled restart job")
UDRZBA_LINE = re.compile(r'(\{"service": "udrzba".*\})\s*$')
WORKER_LINE = re.compile(r'\{"service": "worker", "completed": \d+\}')
AUTOVACUUM_LINE = re.compile(r'autovacuum: processing database "')


def _restarts(lines):
    """Per hyptcn-lab@ unit the times of its restarts, split into loops where two lie over RESTART_WINDOW_S apart."""
    by_unit, loops = defaultdict(list), []
    for t, line in lines:
        m = RESTART_LINE.search(line)
        if m:
            by_unit[m[1]].append(t)
    for times in by_unit.values():
        loop = times[:1]
        for before, now in zip(times, times[1:]):
            if now - before > RESTART_WINDOW_S:
                loops.append(loop)
                loop = []
            loop.append(now)
        loops.append(loop)
    return loops


def _udrzba(lines):
    """The starts of the maintenance runs: the time of each run's own line less the seconds it states."""
    starts = []
    for t, line in lines:
        m = UDRZBA_LINE.search(line)
        if m:
            try:
                starts.append(round(t - float(json.loads(m[1])["seconds"]), 6))
            except (ValueError, KeyError, TypeError):
                continue
    return [starts]


def _matching(pattern):
    return lambda lines: [[t for t, line in lines if pattern.search(line)]]


# The entries of lab/periods.json whose processes leave a line in the guest journal: (the line, the times of the
# line in a run's journal as sequences whose spacings count, why there may be fewer than two lines).
JOURNAL = {
    "hyptcn-lab@ restart loop": (
        "systemd's line 'Scheduled restart job' of each hyptcn-lab@ unit; spacings within one loop "
        "(restarts at most StartLimitIntervalSec apart)", _restarts,
        "no restart loop in this journal: only zla_konfiguracia_sluzby or a crash starts one"),
    "hyptcn-lab-udrzba.timer": (
        'the run\'s own line {"service": "udrzba", ...} (lab/services.py udrzba): its time less its seconds is the '
        "start of the run", _udrzba, "fewer than two maintenance runs in this journal"),
    "worker loop": (
        'the worker\'s line {"service": "worker", "completed": n} (lab/services.py worker): only a round that '
        "completed orders prints one, so a round lasts at most the smallest spacings", _matching(WORKER_LINE),
        "fewer than two rounds of the worker completed orders"),
    "PostgreSQL autovacuum launcher": (
        "the line 'autovacuum: processing database' of each worker start, when PostgreSQL logs it into the journal",
        _matching(AUTOVACUUM_LINE),
        "at its default logging PostgreSQL on Debian logs into its own file (/var/log/postgresql, pg_ctlcluster), not "
        "into the journal, and a worker's start only at log_min_messages debug1 (lab_trial long --postgres-debug1 sets "
        "both for one run): no line marks a worker start"),
}
# The entries whose processes leave no line in the guest journal, and why.
NOT_IN_JOURNAL = {
    "nginx access log flush": "nginx writes its buffered access log without a line of its own; the access log's "
                              "lines carry the times of the requests, not of the flushes",
    "HTTP server poll": "socketserver's poll timeout runs inside the services and logs nothing",
    "event stop health wait": "runs in labctl event stop; its output goes back to the host (events.json), not into "
                              "the journal",
    "control start and stop wait": "runs in labctl event start and stop of a control; its output goes back to the "
                                   "host (controls.json), not into the journal",
    "control memory writer loop": "the writer's rounds go into its output file in /run/hyptcn-udalosti, which the "
                                  "stop reads into the effect; it writes no journal line",
    "control process batch loop": "the batch's reports go into its output file in /run/hyptcn-udalosti, which the "
                                  "stop reads into the effect; its short processes write no journal line",
    "log segment reopen wait": "runs in labctl segment between runs; its output goes back to the host",
    "deployment health wait": "runs in lab/install.sh under labctl deploy; its output is the deploy step's "
                              "(labctl_deploy.stdout)",
    "PostgreSQL checkpointer": "PostgreSQL on Debian logs its checkpoints into its own file (/var/log/postgresql, "
                               "pg_ctlcluster), not into the journal",
    "PostgreSQL background and WAL writers": "they log nothing when they wake",
    "systemd-journald sync": "journald logs no line for its sync",
    "kernel writeback": "the kernel's flusher threads log nothing",
    "systemd-timesyncd poll": "timesyncd logs a change of its synchronization, not every poll",
}


def spacing(values):
    s = sorted(values)
    return None if not s else {"n": len(s), "min": round(s[0], 6), "median": round(traffic_log.percentile(s, .5), 6),
                               "mean": round(sum(s) / len(s), 6), "max": round(s[-1], 6)}


def periods_of(dirs):
    """The real spacings of every entry of lab/periods.json that leaves a journal line, from the guest journals
    fetched into the run directories (guest/*-journal.txt.gz), next to the register's nominal values; spacings never
    reach from one run into another. Every other entry says why the journal cannot show it."""
    register = json.loads((ROOT / "lab/periods.json").read_text())["periods"]
    runs = [list(journal_lines(path)) for d in dirs for path in sorted((Path(d) / "guest").glob("*-journal.txt.gz"))]
    out = []
    for entry in register:
        item = {key: entry[key] for key in ("name", "source", "kind", "period_s", "random_s")}
        if entry["name"] in JOURNAL:
            line, times, why = JOURNAL[entry["name"]]
            sequences = [sequence for lines in runs for sequence in times(lines)]
            spacings = [b - a for sequence in sequences for a, b in zip(sequence, sequence[1:])]
            item.update(journal_line=line, lines=sum(map(len, sequences)), spacings=spacing(spacings),
                        why=None if spacings else why)
        else:
            why = NOT_IN_JOURNAL.get(entry["name"], "no rule in scripts/lab_trial.py for this register entry")
            item.update(journal_line=None, lines=None, spacings=None, why=why)
        out.append(item)
    return out


def run_interval(dirs):
    """(interval_s, why) of the run directories: the interval_s of the protocol.json every long step writes; None and
    why when one of them has none or they differ."""
    found = set()
    for d in dirs:
        try:
            found.add(json.loads((Path(d) / "protocol.json").read_text())["interval_s"])
        except (OSError, ValueError, KeyError, TypeError) as error:
            return None, f"no interval_s from {Path(d) / 'protocol.json'} ({type(error).__name__})"
    if len(found) != 1:
        return None, "the run directories' protocols differ in interval_s: " + ", ".join(map(str, sorted(found)))
    return found.pop(), None


def periods(a, argv):
    for d in a.run:
        if not sorted((Path(d) / "guest").glob("*-journal.txt.gz")):
            raise Refused(f"no fetched guest journal in {d} (guest/*-journal.txt.gz, which the long step fetches)")
    found = periods_of(a.run)
    interval, why = run_interval(a.run)
    prop = autovacuum_property(found, interval) if why is None else {
        "rule": AUTOVACUUM_RULE, "interval_s": None, "bounds_s": list(AUTOVACUUM_REMAINDER_S), "median_s": None,
        "remainder_s": None, "ok": None, "why": why}
    print(json.dumps({"schema": PERIODS_SCHEMA, "runs": [str(d) for d in a.run], "periods": found,
                      "autovacuum_property": prop}, indent=1))
    return 0


# ------------------------------------------------------------------ record

MAX_CONCURRENT_RULE = (
    f"per profile {PROPOSED_CAP_FACTOR} x the most concurrent user sessions (active_max) of the measure phase of the "
    "long run of the profile's high scenario, the last one given (the lead's answer to Q5: max_concurrent is a value "
    "of G2, determined_at); a long run that reached its protocol's max_concurrent, or dropped a user session, gives a "
    "lower bound only")


def proposed_max_concurrent(p, longs, problems):
    """MAX_CONCURRENT_RULE over the long runs `longs` ([(dir, result)]) of the record, the protocol `p`; a run that
    did not measure gives null with why, a bound cap a problem."""
    out = {"rule": MAX_CONCURRENT_RULE, "profiles": {}}
    for profile in p["profiles"]:
        high = [name for name, s in p["scenarios"].items() if s["profile"] == profile and s["intensity"] == "high"]
        found = [(d, doc) for d, doc in longs if doc["scenario"] in high]
        entry = {"scenarios": high, "run": None, "rate": None, "active_max": None, "max_concurrent": None,
                 "protocol_max_concurrent": p["profiles"][profile]["max_concurrent"]}
        if not found:
            out["profiles"][profile] = {**entry, "why": "no long run of " + " or ".join(high)}
            continue
        d, doc = found[-1]
        summary = doc.get("summary") or {}
        active = summary.get("active_max")
        dropped = ((summary.get("arrivals") or {}).get("measure") or {}).get("dropped")
        entry.update(run=d.name, rate=doc.get("rate"), active_max=active,
                     max_concurrent=None if active is None else PROPOSED_CAP_FACTOR * active)
        if active is None:
            entry["why"] = f"{d.name} measured no active_max in its measure phase"
        elif dropped or active >= entry["protocol_max_concurrent"]:
            problems.append(f"{d.name}: the long run reached max_concurrent {entry['protocol_max_concurrent']} "
                            f"(active_max {active}, {dropped or 0} user sessions of the measure phase dropped): "
                            f"{entry['max_concurrent']} for profile {profile} is a lower bound; G2 runs it with a cap "
                            "that does not bind (proposal 10.3)")
        out["profiles"][profile] = entry
    return out


def read_result(d):
    try:
        doc = json.loads((Path(d) / "result.json").read_text())
    except (OSError, ValueError) as error:
        raise Refused(f"{d} holds no result of this tool: {error}") from None
    if type(doc) is not dict or doc.get("schema") != RESULT_SCHEMA:
        raise Refused(f"{d} holds no result of this tool (schema {RESULT_SCHEMA})")
    return doc


def record(a, argv):
    """One record of stage skuska from the results of the run directories (data/results provenance: commit, date,
    host, guest, command, n; scripts/check_claims.sh check E): every step's results, the saturation per profile,
    the proposed rate of every scenario, the periods pooled over the long runs, and the problems: what does not
    hold."""
    target = Path(a.out_record).absolute()
    if target.exists():
        raise Refused(f"the record exists: {target}")
    if target.resolve().is_relative_to(collection.COLLECTIONS.resolve()):
        raise Refused("the lab test writes nothing in data/collections")
    runs = [(Path(d), read_result(d)) for d in a.dirs]
    protocols = sorted({doc["protocol_sha256"] for _, doc in runs})
    if len(protocols) != 1:
        raise Refused("run directories of different protocols: " + ", ".join(protocols))
    p = json.loads((runs[0][0] / "protocol.json").read_text())
    problems = [f"{d.name}: {problem}" for d, doc in runs for problem in doc["problems"]]
    steps = defaultdict(list)
    for d, doc in runs:
        steps[doc["step"]].append((d, doc))
    # A record of both VMs (stage G2, L1 and L2 of dokazy/G2p/odlozene_G2p.md): the VMs in the order the runs first
    # name them; with one VM the record keeps the shapes of the lab test after B5.
    vms = list(dict.fromkeys(doc["vm"] for _, doc in runs))
    several = len(vms) > 1
    on = (lambda v: f" on VM {v}") if several else (lambda v: "")
    by_vm = defaultdict(dict)
    for d, doc in steps["saturation"]:
        if doc["profile"] in by_vm[doc["vm"]]:
            problems.append(f"several saturation runs of profile {doc['profile']}{on(doc['vm'])}: the last one given "
                            f"counts ({d.name})")
        by_vm[doc["vm"]][doc["profile"]] = {"run": d.name, "scenario": doc["scenario"], **doc["saturation"]}
    if not several:
        saturation = by_vm[vms[0]] if vms else {}
        combined = saturation
    else:
        # The lead's answer to Q64: one rate holds for both VMs, so a profile's rate comes from the VM with the smaller
        # served rate of its series; it needs a series on every VM.
        saturation, combined = {}, {}
        for profile in dict.fromkeys(prof for v in vms for prof in by_vm[v]):
            found = {v: by_vm[v][profile] for v in vms if profile in by_vm[v]}
            entry = {"by_vm": found, "rule": SATURATION_COMBINE_RULE}
            missing = [v for v in vms if v not in found]
            if missing:
                problems.append(f"no saturation run of profile {profile} on VM {', '.join(missing)}: the rate needs "
                                "a series on every VM")
            elif all(s.get("proposed_rate") for s in found.values()):
                v = min(found, key=lambda v: (found[v]["rate"], vms.index(v)))
                entry["combined"] = {"vm": v, "rate": found[v]["rate"], "proposed_rate": found[v]["proposed_rate"]}
                combined[profile] = entry["combined"]
            saturation[profile] = entry
    proposed = {}
    for name, s in p["scenarios"].items():
        found = combined.get(s["profile"])
        proposed[name] = found["proposed_rate"][s["intensity"]] if found and found.get("proposed_rate") else None
        if not found:
            problems.append(f"no saturation run of profile {s['profile']}: no rate proposed for {name}")
        for v in vms:
            for step in ("scenario", "long"):
                if not any(doc["scenario"] == name and doc["vm"] == v for _, doc in steps[step]):
                    problems.append(f"no {step} run of scenario {name}{on(v)}")
    for v in vms:
        if not any(doc["vm"] == v for _, doc in steps["deploy"]):
            problems.append(f"no deploy run{on(v)}")
    if not vms:
        problems.append("no deploy run")
    commits = sorted({doc["commit"] for _, doc in runs})
    if len(commits) > 1:
        problems.append("the runs ran on different commits: " + ", ".join(commits))
    if any(doc["measurement_dirty"] for _, doc in runs):
        problems.append("measurement sources differed from the commit in: "
                        + ", ".join(d.name for d, doc in runs if doc["measurement_dirty"]))
    # The QEMU at the start and the end of every run, compared per VM (a deploy may start the VM, so its start does
    # not count): a record may hold the runs of both VMs, as the one of the VM window of Q27 held both deploys. A run's
    # QEMU is the process of its domain (collection.qemu_process), so the runs are grouped by their domain; the problem
    # names the VM by the vm of its runs (one name: the record's one protocol has unique names and domains). One
    # problem per VM, in the order in which the runs first name the VMs (the executor's judgment, G2 preparation).
    qemus, names = defaultdict(set), defaultdict(set)
    for _, doc in runs:
        names[doc["domain"]].add(doc["vm"])
        qemus[doc["domain"]].update(json.dumps(q, sort_keys=True) for q in
                                    ([] if doc["step"] == "deploy" else [doc["qemu"]]) + [doc["qemu_after"]])
    problems += [f"VM {', '.join(sorted(names[domain]))} ({domain}): its QEMU process changed between or during its "
                 "runs (a restart of the VM)" for domain, found in qemus.items() if len(found) > 1]
    def periods_and_property(longs, where=""):
        pooled = periods_of([d for d, _ in longs]) if longs else None
        for item in pooled or []:
            if item["name"] in ("hyptcn-lab-udrzba.timer", AUTOVACUUM) and not item["spacings"]:
                problems.append(f"{item['name']}{where}: spacing not measured: {item['why']}")
        found = autovacuum_property(pooled, p["interval_s"]) if pooled else None
        problems.extend(f"{problem}{where}" for problem in autovacuum_problems(found))
        return pooled, found

    def identity(v):
        deploys = [doc for _, doc in steps["deploy"] if doc["vm"] == v]
        return deploys[-1].get("guest") if deploys else None

    domains = {doc["vm"]: doc["domain"] for _, doc in runs}
    if not several:
        pooled, autovacuum = periods_and_property(steps["long"])
        caps = proposed_max_concurrent(p, steps["long"], problems)
        guest = {"vm": runs[0][1]["vm"], "domain": runs[0][1]["domain"],
                 "identity": steps["deploy"][-1][1].get("guest") if steps["deploy"] else None}
    else:
        # L1 and L2: the guest, the periods with the property of Q9, and the proposed max_concurrent of each VM from
        # its own runs; max_concurrent of a profile is the largest of the VMs (MAX_CONCURRENT_RULE, one cap for both).
        pooled, autovacuum, by_vm_caps = {}, {}, {}
        for v in vms:
            longs = [(d, doc) for d, doc in steps["long"] if doc["vm"] == v]
            pooled[v], autovacuum[v] = periods_and_property(longs, f" (VM {v})")
            by_vm_caps[v] = proposed_max_concurrent(p, longs, problems)
        caps = {"rule": MAX_CONCURRENT_RULE, "by_vm": by_vm_caps, "profiles": {}}
        for profile in p["profiles"]:
            values = [c["profiles"][profile]["max_concurrent"] for c in by_vm_caps.values()]
            caps["profiles"][profile] = {"max_concurrent": None if None in values else max(values),
                                         "by_vm": dict(zip(by_vm_caps, values))}
        guest = {"vms": [{"vm": v, "domain": domains[v], "identity": identity(v)} for v in vms]}
    # n: the run directories assembled (each one step of the lab test).
    doc = {"schema": RECORD_SCHEMA, "stage": STAGE, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "commit": commit(), "host": host(), "guest": guest,
           "command": shlex.join(["scripts/lab_trial.py", *map(str, argv)]), "n": len(runs),
           "protocol": runs[0][1]["protocol"], "protocol_sha256": protocols[0],
           "values": {"runs": [{"dir": str(d), **doc} for d, doc in runs], "saturation": saturation,
                      "proposed_rate": proposed, "proposed_max_concurrent": caps, "periods": pooled,
                      "autovacuum_property": autovacuum, "judgment": judgment(), "lead": lead()},
           "problems": problems, "note": NOTE}
    write(target, doc)
    print(json.dumps({"record": str(target), "runs": len(runs), "problems": len(problems)}), flush=True)
    return 0


def host():
    from scripts.audit_selftest import host as name
    return name()


# ------------------------------------------------------------------ command line

COMMANDS = {"deploy": deploy, "saturation": saturation, "scenario": scenario, "long": long_run, "periods": periods,
            "record": record}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else [str(x) for x in argv]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def vm_step(name, what):
        q = sub.add_parser(name, help=what)
        q.add_argument("--protocol", type=Path, required=True, help="the protocol file (schema 3)")
        q.add_argument("--vm", required=True, help="the protocol's VM (vms[].name)")
        q.add_argument("--out", type=Path, required=True, help="the run directory: new, outside data/collections")
        return q
    vm_step("deploy", "labctl deploy, the health check, the guest's identity and the QEMU's swap state")
    q = vm_step("saturation", "the saturation series (Q5): increasing rates up to the first step that fails on the "
                              "server, then bisection, on a copy of the protocol whose max_concurrent does not bind")
    q.add_argument("--profile", required=True)
    q.add_argument("--scenario", required=True, help="a scenario of the profile: its mix is run")
    q.add_argument("--rates", required=True, help="comma-separated, increasing: user sessions per second at envelope "
                                                  "level 1")
    for name in ("scenario", "long"):
        q = vm_step(name, "one run of a scenario: summary and realism" + (", N events, journal, nginx logs and "
                                                                          "periods" if name == "long" else ""))
        q.add_argument("--scenario", required=True)
        q.add_argument("--rate", type=float, help="user sessions per second at envelope level 1 (while the "
                                                  "protocol's rate is null)")
        q.add_argument("--minutes", type=float, required=True, help="the measured part, after the protocol's warmup")
        if name == "long":
            q.add_argument("--events", type=int, required=True, help="events of the run, a count of events.per_session")
            q.add_argument("--postgres-debug1", action="store_true",
                           help="PostgreSQL in the guest logs at debug1 into the journal for this run only, so the "
                                "worker starts of autovacuum are measured; reset after it (DEBUG1_RULE, recorded)")
    q = sub.add_parser("periods", help="the real periods of lab/periods.json from the journals of long runs")
    q.add_argument("--run", type=Path, nargs="+", required=True)
    q = sub.add_parser("record", help="one record of stage skuska from run directories")
    q.add_argument("--out-record", type=Path, required=True)
    q.add_argument("dirs", type=Path, nargs="+")
    a = parser.parse_args(argv)
    try:
        return COMMANDS[a.command](a, argv)
    except Refused as error:
        print(f"lab_trial: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
