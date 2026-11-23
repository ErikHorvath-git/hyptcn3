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
  long        --protocol P --vm a --scenario S --rate R --minutes 60 --events N --out DIR
  periods     --run DIR [DIR ...]
  record      --out-record data/results/skuska_labu_<UTC>.json DIR [DIR ...]

deploy: labctl deploy (its JSON lines and exit code are kept; a failed swap step is recorded, not fatal), the
health check, the guest's identity and where the VM's QEMU stands (memory.swap.max, VmSwap and the cgroups its
memory is charged to). A traffic run (a step of saturation, scenario, long) starts the generator with the
protocol's warmup, sends SIGUSR1 at the end of the warmup and SIGUSR2 at --dur, both from the generator's own
origin (the header of its request log), and SIGTERM after a drain. saturation runs its rates in order and stops
after the first step whose peak was not served (saturation_rule). scenario and long compute the summary and the
realism requirements of their logs; long also runs N events of its own draw (draw_events) through labctl event,
fetches the guest journal and the nginx logs of the run, and measures the periods (periods). Every number that
is the executor's judgment is marked so below and stated in each result.

Exit codes: 0 the step ran and wrote its result, 1 it could not complete (its result says why), 2 the input was
refused (nothing written).
"""
import argparse
from collections import defaultdict
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
CHARGED_SHARE = .9  # Judgment: QEMU's memory is charged to its own cgroup when that holds this share of its RssAnon.
HOLDER_SHARE = .5  # Judgment: a leaf cgroup of the user slice holding this share of QEMU's RssAnon is a holder.
RESTART_WINDOW_S = 60  # lab/hyptcn-lab@.service StartLimitIntervalSec: restarts further apart are separate loops.


class Refused(ValueError):
    """An input the tool refuses before it writes anything (exit code 2)."""


def judgment():
    return {"deploy_timeout_s": DEPLOY_TIMEOUT_S, "header_timeout_s": HEADER_TIMEOUT_S, "tick_s": TICK_S,
            "drain_s": DRAIN_S, "stop_grace_s": STOP_GRACE_S, "saturation_measure_s": SATURATION_MEASURE_S,
            "saturation_drain_s": SATURATION_DRAIN_S, "latency_p95_bound_ms": LATENCY_P95_BOUND_MS,
            "charged_share": CHARGED_SHARE, "holder_share": HOLDER_SHARE, "restart_window_s": RESTART_WINDOW_S,
            "note": "the executor's judgment (scripts/lab_trial.py), none of them a value of the protocol"}


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
            "completed": False, "error": None}


def create(out, raw):
    out.mkdir(parents=True)
    (out / "protocol.json").write_bytes(raw)  # The generator reads this copy (collection.traffic_command).


def failure(error):
    return f"{type(error).__name__}: {error}"[:500]


def finish(out, result, problems):
    result["ended_unix"] = time.time()
    result["qemu_after"] = collection.qemu_process(result["domain"])  # record: the same QEMU in every run
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


def traffic_summary(run):
    """scripts/traffic_log.py summarize of the run's logs, its problems and the measure phase."""
    s = traffic_log.summarize(run / REQUESTS, run / INTERVALS, session_id=run.name)
    m = s["measure"]
    return {"problems": s["problems"][:20], "problem_count": len(s["problems"]), "clean": s["clean"],
            "arrivals": s.get("arrivals"), "phases": s["phases"],
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
    memory.swap.max there, VmSwap, RssAnon, and the anonymous memory charged to its own cgroup and to every leaf
    cgroup of its user's slice that holds at least HOLDER_SHARE of the RssAnon: a process moved into a scope keeps
    its pages charged where they were faulted. Reads /proc and /sys/fs/cgroup only (scripts/labctl.py PROC and
    CGROUPS), no root."""
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
    share = own["anon"] / rss_bytes if own and own["anon"] is not None and rss_bytes else None
    try:
        swappiness = int((labctl.PROC / "sys/vm/swappiness").read_text())
    except (OSError, ValueError):
        swappiness = None
    return {"domain": domain, "qemu_pid": pid, "cgroup": cgroup, "memory_swap_max": swap,
            "vm_swap_kb": labctl.vm_swap_kb(pid), "rss_anon_kb": int(rss[1]) if rss else None, "own": own,
            "own_anon_share": None if share is None else round(share, 3),
            "charged_to_own_cgroup": None if share is None else share >= CHARGED_SHARE, "holders": holders,
            "vm_swappiness": swappiness}


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
        out.append(f"QEMU's memory is not charged to its own cgroup {memory.get('cgroup')}: it holds "
                   f"{memory.get('own_anon_share')} of RssAnon {memory.get('rss_anon_kb')} kB; holders "
                   + (holders or "none"))
    return out


# ------------------------------------------------------------------ saturation

def expected(r):
    """A request got its expected result: a 2xx, or the status a deliberate client error intends (the generator's
    exit-code rule, scripts/host_traffic.py SessionMetrics)."""
    return r.get("outcome") == "ok" if r.get("intended_status") is None else r.get("status") == r["intended_status"]


def peak_of(run):
    """The peak of one step's logs: the intervals of the measure phase whose planned level (the header's envelope)
    is 1 over all of them, with the user sessions offered, admitted and dropped there (the interval log), the
    requests that started in them, how many lacked their expected result, their p95 latency (exact nearest rank),
    and the delivered user sessions and requests per second of the peak."""
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
            "active_max": max((iv["active_max"] for iv in peaks), default=None), "requests": len(requests),
            "unexpected": sum(not expected(r) for r in requests),
            "p95_ms": traffic_log.percentile(sorted(r["duration_ms"] for r in requests), .95),
            "sessions_per_s": round(admitted / seconds, 6) if seconds else None,
            "requests_per_s": round(len(requests) / seconds, 6) if seconds else None}


def step_reasons(peak):
    """Why a step's peak was not served, [] when it was: every request with its expected result, no user session
    dropped and the p95 latency below LATENCY_P95_BOUND_MS (judgment)."""
    reasons = []
    if not peak["intervals"]:
        reasons.append("no interval of the measure phase lies wholly at envelope level 1")
    elif not peak["requests"]:
        reasons.append("no request started in the peak")
    if peak["dropped"]:
        reasons.append(f"{peak['dropped']} user sessions dropped over max_concurrent")
    if peak["unexpected"]:
        reasons.append(f"{peak['unexpected']} requests without their expected result")
    if peak["p95_ms"] is not None and peak["p95_ms"] >= LATENCY_P95_BOUND_MS:
        reasons.append(f"p95 latency {peak['p95_ms']:g} ms, not below {LATENCY_P95_BOUND_MS:g} ms")
    return reasons


SATURATION_RULE = ("the highest offered rate whose peak was served (every request of the peak intervals with its "
                   "expected result, no user session dropped, p95 latency below the bound) below the first step "
                   "whose peak was not; the steps run in increasing order and stop after the first failure")


def saturation_rule(steps, peak_share):
    """The saturation of the judged steps (in run order) and the rates proposed from it (scenario_rule.peak_share of
    it per intensity): SATURATION_RULE."""
    served, failed = None, None
    for step in steps:
        if step["reasons"]:
            failed = step
            break
        served = step
    rate = served["rate"] if served else None
    return {"rule": SATURATION_RULE, "latency_p95_bound_ms": LATENCY_P95_BOUND_MS, "rate": rate,
            "first_failure": None if failed is None else {"rate": failed["rate"], "reasons": failed["reasons"]},
            "delivered_sessions_per_s": served["peak"]["sessions_per_s"] if served else None,
            "requests_per_s": served["peak"]["requests_per_s"] if served else None,
            "proposed_rate": {name: None if rate is None else round(share * rate, 6)
                              for name, share in peak_share.items()}}


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
    blocks = [traffic_block(pv, a.scenario, a.profile, rate, "saturation", k, SATURATION_MEASURE_S)
              for k, rate in enumerate(rates)]
    for k, t in enumerate(blocks):
        precheck(a.protocol, out / f"step-{k + 1:02d}", t)
    quiet(pv)
    create(out, raw)
    result = started("saturation", argv, a.protocol, raw, pv)
    result.update(profile=a.profile, scenario=a.scenario, intensity=s["intensity"], rates=rates, steps=[])
    for k, t in enumerate(blocks):
        run = out / f"step-{k + 1:02d}"
        step = {"step": run.name, "rate": t["rate"]}
        result["steps"].append(step)
        try:
            create(run, raw)
            step["run"] = traffic_run(pv, run, t, SATURATION_DRAIN_S)
            if step["run"]["error"]:
                break
            step["log_problems"] = traffic_summary(run)["problems"][:10]
            step["peak"] = peak_of(run)
            step["reasons"] = step_reasons(step["peak"])
        except (OSError, ValueError, KeyError, StopIteration) as error:
            step["error"] = failure(error)
            break
        progress("saturation-step", rate=t["rate"], served=not step["reasons"])
        if step["reasons"]:
            break
    judged = [step for step in result["steps"] if "reasons" in step]
    result["saturation"] = saturation_rule(judged, p["scenario_rule"]["peak_share"])
    failed = [step for step in result["steps"] if step.get("error") or step.get("run", {}).get("error")]
    result["error"] = (failed[0].get("error") or failed[0]["run"]["error"]) if failed else None
    result["completed"] = not failed
    return finish(out, result, saturation_problems)


def saturation_problems(r):
    sat, judged, out = r["saturation"], [s for s in r["steps"] if "reasons" in s], []
    if r["error"]:  # The series ended without a failed peak: what it found is a lower bound.
        out.append(f"saturation did not complete: {r['error']}" + (
            f"; the steps before it put the saturation at {sat['rate']:g} or above"
            if sat["rate"] is not None and sat["first_failure"] is None else ""))
    if judged and sat["rate"] is None:
        out.append(f"no step served its peak: the lowest rate {judged[0]['rate']:g} fails ("
                   + "; ".join(judged[0]["reasons"]) + ")")
    if judged and sat["first_failure"] is None and not r["error"]:
        out.append(f"every step served its peak: the throughput lies above the highest rate {judged[-1]['rate']:g}; "
                   "the proposed rates are lower bounds")
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
    if dropped:
        out.append(f"{dropped} user sessions of the measure phase dropped over max_concurrent")
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
    try:
        result["pre_segment"] = collection.lab_json(pv, "segment", "--label", out.name + "-pre", "--dest", guest)
        since = time.time()
        try:
            result["run"] = traffic_run(pv, out, t, DRAIN_S, runner)
        finally:
            runner.close(out / "events.json")
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
        result["error"] = result["run"]["error"]
        result["completed"] = result["error"] is None
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        result["error"] = failure(error)
    return finish(out, result, long_problems)


def long_problems(r):
    out = traffic_problems(r)
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
        "at its defaults PostgreSQL on Debian logs into its own file (/var/log/postgresql, pg_ctlcluster), not into "
        "the journal, and a worker's start only at log_min_messages debug1: no line marks a worker start"),
}
# The entries whose processes leave no line in the guest journal, and why.
NOT_IN_JOURNAL = {
    "nginx access log flush": "nginx writes its buffered access log without a line of its own; the access log's "
                              "lines carry the times of the requests, not of the flushes",
    "HTTP server poll": "socketserver's poll timeout runs inside the services and logs nothing",
    "event stop health wait": "runs in labctl event stop; its output goes back to the host (events.json), not into "
                              "the journal",
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


def periods(a, argv):
    for d in a.run:
        if not sorted((Path(d) / "guest").glob("*-journal.txt.gz")):
            raise Refused(f"no fetched guest journal in {d} (guest/*-journal.txt.gz, which the long step fetches)")
    print(json.dumps({"schema": PERIODS_SCHEMA, "runs": [str(d) for d in a.run], "periods": periods_of(a.run)},
                     indent=1))
    return 0


# ------------------------------------------------------------------ record

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
    saturation = {}
    for d, doc in steps["saturation"]:
        if doc["profile"] in saturation:
            problems.append(f"several saturation runs of profile {doc['profile']}: the last one given counts "
                            f"({d.name})")
        saturation[doc["profile"]] = {"run": d.name, "scenario": doc["scenario"], **doc["saturation"]}
    proposed = {}
    for name, s in p["scenarios"].items():
        found = saturation.get(s["profile"])
        proposed[name] = found["proposed_rate"][s["intensity"]] if found else None
        if not found:
            problems.append(f"no saturation run of profile {s['profile']}: no rate proposed for {name}")
        for step in ("scenario", "long"):
            if not any(doc["scenario"] == name for _, doc in steps[step]):
                problems.append(f"no {step} run of scenario {name}")
    if not steps["deploy"]:
        problems.append("no deploy run")
    commits = sorted({doc["commit"] for _, doc in runs})
    if len(commits) > 1:
        problems.append("the runs ran on different commits: " + ", ".join(commits))
    if any(doc["measurement_dirty"] for _, doc in runs):
        problems.append("measurement sources differed from the commit in: "
                        + ", ".join(d.name for d, doc in runs if doc["measurement_dirty"]))
    # The QEMU at the start and the end of every run (a deploy may start the VM, so its start does not count).
    qemus = {json.dumps(q, sort_keys=True) for _, doc in runs
             for q in ([] if doc["step"] == "deploy" else [doc["qemu"]]) + [doc["qemu_after"]]}
    if len(qemus) > 1:
        problems.append("the VM's QEMU process changed between or during the runs (a restart of the VM)")
    pooled = periods_of([d for d, _ in steps["long"]]) if steps["long"] else None
    for item in pooled or []:
        if item["name"] in ("hyptcn-lab-udrzba.timer", "PostgreSQL autovacuum launcher") and not item["spacings"]:
            problems.append(f"{item['name']}: spacing not measured: {item['why']}")
    guest = {"vm": runs[0][1]["vm"], "domain": runs[0][1]["domain"],
             "identity": steps["deploy"][-1][1].get("guest") if steps["deploy"] else None}
    # n: the run directories assembled (each one step of the lab test).
    doc = {"schema": RECORD_SCHEMA, "stage": STAGE, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "commit": commit(), "host": host(), "guest": guest,
           "command": shlex.join(["scripts/lab_trial.py", *map(str, argv)]), "n": len(runs),
           "protocol": runs[0][1]["protocol"], "protocol_sha256": protocols[0],
           "values": {"runs": [{"dir": str(d), **doc} for d, doc in runs], "saturation": saturation,
                      "proposed_rate": proposed, "periods": pooled, "judgment": judgment()},
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
    q = vm_step("saturation", "a step test over increasing rates; stops after the first step whose peak fails")
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
