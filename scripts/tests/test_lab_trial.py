"""The tool of the lab test on a VM, scripts/lab_trial.py (assignment dokazy/skuska_labu/ZADANIE_nastroj.md).

Fakes only, no VM. labctl is faked as scripts/tests/test_run_session_v5.py fakes it: a script in place of
scripts/labctl.py for `labctl deploy` (its JSON lines, an indented health state, the exit code of a failed swap step)
and collection.lab_json for event, segment and journal (the files a fetch leaves in --dest). The generator is a fake
process started in place of scripts/host_traffic.py with the command line the tool made: it copies synthetic logs of
scripts/tests/test_collection_logs.py (build and v5_traffic) to the paths of that command line, records the signals
it gets and ends on SIGTERM. The QEMU's /proc and /sys/fs/cgroup are trees in tmp_path. One test per subcommand with
its exact outputs, the saturation rule on a synthetic step series with a known answer, the record through
scripts/check_claims.sh --json-hlavicky on a copy, and refused inputs with their named reasons. scripts/lab_trial.py
is imported inside the tests, so this file collects on the code before it.
"""
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()  # The synthetic logs' time (test_collection_logs).
QEMU = {"pid": 4242, "start_ticks": 1, "host_boot": "host-boot"}
COMMIT = "c" * 40
SCRIPT_SHA256 = hashlib.sha256(b"synthetic lab/udalosti.py").hexdigest()
TRAFFIC_SEEDS = ("traffic", "traffic_arrivals", "traffic_choices", "traffic_sizes")

FAKE_GENERATOR = """
import json, os, shutil, signal, sys, time
from pathlib import Path
argv = sys.argv[1:]
option = lambda name: Path(argv[argv.index(name) + 1])
got = []
for number in (signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM):
    signal.signal(number, lambda signum, frame: got.append(signum))
source = Path(os.environ["FAKE_LOGS"]) / argv[argv.index("--session-id") + 1]
shutil.copyfile(source / "traffic_intervals.jsonl", option("--intervals-log"))
shutil.copyfile(source / "traffic_requests.jsonl", option("--requests-log"))
deadline = time.monotonic() + 30
while signal.SIGTERM not in got and time.monotonic() < deadline:
    time.sleep(.005)
option("--out").write_text(json.dumps(dict(json.loads((source / "traffic.json").read_text()), final=True)))
names = sorted(signal.Signals(n).name for n in got)  # The set it got: its own handlers nest when signals come at once.
(option("--out").parent / "fake_generator.json").write_text(json.dumps({"argv": argv, "signals": names}))
"""

LIBVIRTD = {"unit": "hyptcn-libvirtd.service", "found": "unit", "qemu_way": "unit", "memory_swap_max": "0"}
QEMU_SWAP = {"domain": "hyptcn-lab-a", "memory_swap_max": None,
             "error": "QEMU 4242 (hyptcn-lab-a) has VmSwap 12 kB with memory.swap.max '0'"}
STATE = {"uri": "qemu:///session", "domain": "hyptcn-lab-a", "target": "http://127.0.0.1:18080",
         "health": {"status": "ok"}, "vm": "a"}
SWAP_ERROR = "labctl: QEMU swap is not disabled: QEMU 4242 (hyptcn-lab-a) has VmSwap 12 kB with memory.swap.max '0'"
FAKE_LABCTL = f"""
import json, os, sys
open(os.environ["FAKE_LABCTL_ARGV"], "w").write(json.dumps(sys.argv[1:]))
print(json.dumps({{"libvirtd": {LIBVIRTD!r}}}, sort_keys=True))
print(json.dumps({{"qemu_swap": {QEMU_SWAP!r}}}, sort_keys=True))
print("Setting up hyptcn-lab (install.sh)")
print(json.dumps({STATE!r}, indent=2))
print({SWAP_ERROR!r}, file=sys.stderr)
sys.exit(1)
"""
SCOPE = "/user.slice/user-1000.slice/user@1000.service/app.slice/hyptcn-qemu-hyptcn-lab-a-4242.scope"
SESSION_SCOPE = "/user.slice/user-1000.slice/session-2730.scope"
CGROUPS = {SCOPE: ("209715200", "anon 104857600\nfile 0\n", "0", "0"),
           SESSION_SCOPE: ("2147483648", "anon 2000000000\nfile 4096\n", "12288", "0"),
           "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux-spawn-1.scope": ("2097152", "anon 1048576\n",
                                                                                          "0", "max")}


def utc(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="microseconds")


def pack(dest, name, text):
    """A file a labctl fetch leaves in --dest, and its entry in the reply (lab/guest_state.py describe)."""
    data = text.encode()
    (dest / (name + ".gz")).write_bytes(gzip.compress(data))
    return {"name": name, "file": name + ".gz", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "lines": data.count(b"\n")}


def journal_text(now):
    """A guest journal (journalctl -o short-iso-precise --utc) with known spacings: worker rounds 1.1 and 0.9 s
    apart, maintenance runs starting 599.5 and 702 s apart (their lines' times less their seconds), one restart
    loop of three restarts 3.25 s apart and a lone restart later, a traceback outside every event window and one
    inside (at `now`, right after the run's events)."""
    rows = [(BASE + 10, 'python3[801]: {"service": "worker", "completed": 2}'),
            (BASE + 11.1, 'python3[801]: {"service": "worker", "completed": 1}'),
            (BASE + 12, 'python3[801]: {"service": "worker", "completed": 4}'),
            (BASE + 50, "python3[805]: Traceback (most recent call last):"),
            *[(BASE + t, f'python3[{900 + i}]: {{"service": "udrzba", "vacuum_rc": 0, "vacuum_error": null, '
                         f'"log_compressed": null, "seconds": {s}}}')
              for i, (t, s) in enumerate(((100, 2.5), (700, 3.0), (1400, 1.0)))],
            *[(BASE + t, f"systemd[1]: hyptcn-lab@catalog.service: Scheduled restart job, restart counter is at {n}.")
              for n, t in ((1, 2000), (2, 2003.25), (3, 2006.5), (1, 3000))],
            (now, "python3[806]: Traceback (most recent call last):")]
    return "".join(f"{utc(t)} hyptcn-lab-a {line}\n" for t, line in sorted(rows))


NGINX_OUTSIDE = "2026/01/01 00:00:00 [error] 7#7: *1 connect() failed (111: Connection refused) while connecting"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Every place lab_trial reaches beyond its run directory, faked."""
    from scripts import collection, lab_trial, labctl
    monkeypatch.setattr(lab_trial, "TICK_S", 0)
    monkeypatch.setattr(lab_trial, "POLL_S", .01)
    monkeypatch.setattr(lab_trial, "commit", lambda: COMMIT)
    monkeypatch.setattr(collection, "measurement_dirty", lambda: [])
    monkeypatch.setattr(collection, "qemu_process", lambda domain: dict(QEMU))
    monkeypatch.setattr(collection, "foreign_traffic", lambda p, exclude=(): [])
    monkeypatch.setattr(collection, "collectors", lambda domain: [])
    health = []
    monkeypatch.setattr(collection, "wait_healthy", lambda target, timeout=30: health.append(target) or 1)
    lab = collection.lab_sha256()
    manifest = [f"{lab[source]}  {path}" for path, source in collection.deployed_paths(lab).items()]
    identity = {"kernel": "6.1.0-42-cloud-amd64", "boot_id": "boot-1", "machine_id": "m-1", "stack_sha256": "5" * 64,
                "stack_manifest": manifest}
    monkeypatch.setattr(collection, "guest_identity", lambda p: dict(identity))
    calls, started, journal_more = [], [], []  # journal_more: lines a test adds to every fetched guest journal.

    def lab_json(p, *args, timeout=600):
        args = [str(x) for x in args]
        calls.append(args)
        if args[0] == "event":
            action, kind = args[2], args[3]
            if action == "start":
                return {"ok": True, "type": kind, "script_sha256": SCRIPT_SHA256}
            return {"ok": True, "type": kind, "health": 200, "script_sha256": SCRIPT_SHA256,
                    "effect": {"ok": True, "predicate": "synthetic " + kind, "evidence": {}}}
        label, dest = args[args.index("--label") + 1], Path(args[args.index("--dest") + 1])
        now = datetime.now(timezone.utc).timestamp()
        if args[0] == "segment":
            errors = "" if label.endswith("-pre") else (
                f"{datetime.fromtimestamp(now, timezone.utc):%Y/%m/%d %H:%M:%S} [error] 7#7: *9 upstream timed out\n"
                + NGINX_OUTSIDE + "\n")
            return {"schema": "hyptcn3/guest-log-segment/1", "label": label, "closed_unix": now,
                    "files": [pack(dest, label + "-nginx-access.jsonl", ""), pack(dest, label + "-nginx-error.log",
                                                                                  errors)]}
        return {"schema": "hyptcn3/guest-journal-segment/1", "label": label,
                "since_unix": float(args[args.index("--since") + 1]),
                "until_unix": float(args[args.index("--until") + 1]),
                "files": [pack(dest, label + "-journal.txt", journal_text(now) + "".join(journal_more))]}
    monkeypatch.setattr(collection, "lab_json", lab_json)
    fake = tmp_path / "fake_host_traffic.py"
    fake.write_text(FAKE_GENERATOR)
    real_start = collection.start_child

    def start_child(command, log, env=None):
        started.append([str(x) for x in command])
        return real_start([command[0], fake, *command[2:]], log, env)
    monkeypatch.setattr(collection, "start_child", start_child)
    labctl_fake = tmp_path / "fake_labctl.py"
    labctl_fake.write_text(FAKE_LABCTL)
    monkeypatch.setattr(lab_trial, "LABCTL", labctl_fake)
    monkeypatch.setenv("FAKE_LABCTL_ARGV", str(tmp_path / "labctl_argv.json"))
    monkeypatch.setenv("FAKE_LOGS", str(tmp_path / "synthetic"))
    proc, cgroups = tmp_path / "proc", tmp_path / "cgroup"
    (proc / "4242").mkdir(parents=True)
    (proc / "4242/cmdline").write_bytes(b"/usr/bin/qemu-system-x86_64\0-name\0guest=hyptcn-lab-a,debug-threads=on\0")
    (proc / "4242/cgroup").write_text(f"0::{SCOPE}\n")
    (proc / "4242/status").write_text("Name:\tqemu-system-x86\nUid:\t1000\t1000\t1000\t1000\nVmSwap:\t      12 kB\n"
                                      "VmRSS:\t 2100000 kB\nRssAnon:\t 2000000 kB\n")
    (proc / "sys/vm").mkdir(parents=True)
    (proc / "sys/vm/swappiness").write_text("1\n")
    for path, (current, stat, swap, swap_max) in CGROUPS.items():
        d = cgroups / path.lstrip("/")
        d.mkdir(parents=True)
        for name, value in (("memory.current", current), ("memory.stat", stat), ("memory.swap.current", swap),
                            ("memory.swap.max", swap_max), ("cgroup.procs", "4242" if path == SCOPE else "")):
            (d / name).write_text(value + ("" if value.endswith("\n") else "\n"))
    monkeypatch.setattr(labctl, "PROC", proc)
    monkeypatch.setattr(labctl, "CGROUPS", cgroups)
    p = collection.protocol(V5)
    return type("Env", (), dict(tmp=tmp_path, runs=tmp_path / "runs", calls=calls, started=started, health=health,
                                journal_more=journal_more,
                                identity=identity, p=p, pv=collection.for_vm(p, "a")))


def synthetic(env, name, scenario, **traffic):
    """Synthetic logs of a v5 profile for the run named `name` (test_collection_logs build and v5_traffic)."""
    from scripts.tests import test_collection_logs as evidence
    # 60 s of measure phase: the user sessions of v5_traffic follow by their think times (package B10, F6 of B5b).
    d = evidence.build(env.tmp / "synthetic", session_name=name, measure_s=60)
    evidence.v5_traffic(d, env.p, scenario=scenario, **traffic)
    return d


def run(*argv):
    from scripts import lab_trial
    return lab_trial.main([str(x) for x in argv])


def result(directory):
    return json.loads((directory / "result.json").read_text())


def seeds(env, kind, scenario, position):
    from scripts import protocol_v5
    return {name: protocol_v5.seed(env.p["name"], name, f"skuska/{kind}/{scenario}", position, 1)
            for name in TRAFFIC_SEEDS}


def generator_argv(env, run_dir, scenario, profile, rate, dur, position, kind):
    """The generator's command line of design B5b 1.3 for a run of the tool, written out here."""
    return [sys.executable, str(ROOT / "scripts/host_traffic.py"), "--profile", profile,
            "--protocol", str(run_dir / "protocol.json"), "--scenario", scenario,
            "--seeds", json.dumps(seeds(env, kind, scenario, position), sort_keys=True), "--rate", str(rate),
            "--target", "http://127.0.0.1:18080", "--dur", str(dur), "--warmup-s", "120", "--session-id",
            run_dir.name, "--requests-log", str(run_dir / "traffic_requests.jsonl"),
            "--intervals-log", str(run_dir / "traffic_intervals.jsonl"), "--summary-interval-s", "5",
            "--initial-phase", "warmup", "--out", str(run_dir / "traffic.json")]


def fake_seen(run_dir):
    return json.loads((run_dir / "fake_generator.json").read_text())


def records_of(path, kind):
    return [r for r in map(json.loads, Path(path).read_text().splitlines()) if r.get("type") == kind]


# ------------------------------------------------------------------ deploy

def run_deploy(env):
    out = env.runs / "deploy"
    assert run("deploy", "--protocol", V5, "--vm", "a", "--out", out) == 0
    return out


def test_deploy_keeps_labctls_lines_records_a_failed_swap_step_and_where_qemus_memory_is_charged(env):
    from scripts import collection
    out = run_deploy(env)
    r = result(out)
    labctl_command = [sys.executable, str(env.tmp / "fake_labctl.py"), "deploy", "--domain", "hyptcn-lab-a", "--vm",
                      "a", "--port", "18080"]
    assert json.loads((env.tmp / "labctl_argv.json").read_text()) == labctl_command[2:]
    assert r["labctl"] == {"command": labctl_command, "rc": 1, "swap_failed": True, "libvirtd": LIBVIRTD,
                           "qemu_swap": QEMU_SWAP, "state": STATE, "other_lines": 1, "stderr": SWAP_ERROR}
    assert (out / "labctl_deploy.stderr").read_text() == SWAP_ERROR + "\n"
    assert r["health"] == {"ok": True, "attempts": 1} and env.health == ["http://127.0.0.1:18080"]
    assert r["guest"] == {"kernel": "6.1.0-42-cloud-amd64", "boot_id": "boot-1", "machine_id": "m-1",
                          "stack_sha256": "5" * 64, "mismatch": []}
    own = {"cgroup": SCOPE, "memory_current": 209715200, "anon": 104857600, "swap_current": 0, "swap_max": "0"}
    holder = {"cgroup": SESSION_SCOPE, "memory_current": 2147483648, "anon": 2000000000, "swap_current": 12288,
              "swap_max": "0"}
    # Package B11: the share is labctl's charge of the cgroup (the lead's answer to Q26), over every QEMU in it.
    charge = {"cgroup": SCOPE, "memory_current": 209715200, "anon": 104857600,
              "qemu": [{"pid": 4242, "vm_rss_kb": 2100000, "rss_anon_kb": 2000000}], "rss_anon_kb": 2000000,
              "share": .051, "charged": False, "charged_share": .9}
    assert r["qemu_memory"] == {"domain": "hyptcn-lab-a", "qemu_pid": 4242, "cgroup": SCOPE, "memory_swap_max": "0",
                                "vm_swap_kb": 12, "rss_anon_kb": 2000000, "own": own, "charge": charge,
                                "own_anon_share": .051, "charged_to_own_cgroup": False, "holders": [holder],
                                "vm_swappiness": 1}
    assert (r["completed"], r["error"], r["step"], r["commit"], r["qemu"], r["qemu_after"]) == (
        True, None, "deploy", COMMIT, QEMU, QEMU)
    assert r["problems"] == [
        "the swap step of labctl deploy failed: " + SWAP_ERROR,
        "labctl's qemu_swap record: memory.swap.max None, VmSwap None kB (both must be 0)",
        f"QEMU's memory is not charged to its own cgroup {SCOPE}: it holds 0.051 of RssAnon 2000000 kB; holders "
        f"{SESSION_SCOPE} (swap_max 0)"]
    assert (out / "protocol.json").read_bytes() == V5.read_bytes() and env.calls == [] and env.started == []
    assert collection.guest_mismatch(env.identity, collection.lab_sha256()) == []


# ------------------------------------------------------------------ saturation

def peak(**change):
    return {"intervals": 12, "seconds": 60.0, "offered": 30, "admitted": 30, "dropped": 0, "drop_reasons": {},
            "active_max": 40, "requests": 270, "unexpected": 0, "p95_ms": 120.5, "sessions_per_s": .5,
            "requests_per_s": 4.5, **change}


INVALID = "in the peak: a limit of the generator, not of the server"


@pytest.mark.parametrize("third, errors, reasons", [
    ({"dropped": 2, "drop_reasons": {"all_customers_held": 1, "max_concurrent": 1}},
     ["2 user sessions dropped (drop_reason: all_customers_held 1, max_concurrent 1) " + INVALID], []),
    ({"unexpected": 3}, [], ["3 requests without their expected result"]),
    ({"p95_ms": 1000}, [], ["p95 latency 1000 ms, not below 1000 ms"]),
    ({"intervals": 0, "requests": 0, "p95_ms": None},
     ["no interval of the measure phase lies wholly at envelope level 1"], []),
    ({"requests": 0, "p95_ms": None}, ["no request started in the peak"], []),
], ids=["dropped", "unexpected", "latency", "no_peak", "no_request"])
def test_saturation_rule_on_a_synthetic_step_series_with_a_known_answer(third, errors, reasons):
    """Four steps: the third fails by one criterion, the fourth would pass again; the saturation is the second.
    Package B11 (the lead's answer to Q5): only the server fails a step, by an answer without its expected result or
    by the latency; a drop, named by its drop_reason (B5c F1), or an empty peak makes the step invalid instead."""
    from scripts import lab_trial
    series = [(.5, peak()), (1., peak(p95_ms=999.9, sessions_per_s=1., requests_per_s=9.)), (2., peak(**third)),
              (4., peak())]
    assert [lab_trial.step_errors(p) for _, p in series] == [[], [], errors, []]
    assert [lab_trial.step_reasons(p) for _, p in series] == [[], [], reasons, []]
    if errors:
        return
    steps = [{"rate": rate, "peak": p, "reasons": lab_trial.step_reasons(p)} for rate, p in series]
    share = {"low": .3, "high": .8}
    assert lab_trial.saturation_rule(steps, share) == {
        "rule": lab_trial.SATURATION_RULE, "latency_p95_bound_ms": 1000, "step_ratio_max": 1.15, "rate": 1.,
        "failure": {"rate": 2., "reasons": reasons}, "bracket": [1., 2.], "ratio": 2., "delivered_sessions_per_s": 1.,
        "requests_per_s": 9., "proposed_rate": {"low": .3, "high": .8}}
    first_fails = lab_trial.saturation_rule(steps[2:], share)
    assert (first_fails["rate"], first_fails["bracket"], first_fails["proposed_rate"]) == (
        None, None, {"low": None, "high": None})
    all_pass = lab_trial.saturation_rule(steps[:2], share)
    assert (all_pass["rate"], all_pass["failure"], all_pass["proposed_rate"]) == (1., None, share)


def drop_one(d):
    """The first user session of the measure phase in the synthetic logs of `d` dropped, all_customers_held (the
    generator's drop_reason, package B5c): its arrival record and the counts of its interval."""
    paths = (d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl")
    requests, intervals = ([json.loads(line) for line in path.read_text().splitlines()] for path in paths)
    arrival = next(r for r in requests if r.get("type") == "arrival" and r["phase"] == "measure")
    arrival.update(admitted=False, drop_reason="all_customers_held")
    interval = next(iv for iv in intervals if iv.get("type") == "interval"
                    and iv["mono_start"] <= arrival["t_mono"] < iv["mono_end"])
    interval.update(admitted_sessions=interval["admitted_sessions"] - 1,
                    dropped_sessions=interval["dropped_sessions"] + 1)
    for path, records in zip(paths, (requests, intervals)):
        path.write_text("".join(json.dumps(r) + "\n" for r in records))


def series(env, outcomes, rates):
    """A saturation series of eshop_high over --rates `rates` whose steps, in run order, have synthetic logs by
    `outcomes`: "served" (level 1 throughout), "failed" (one request answered 503), "dropped" (one user session of the
    peak dropped) or "no_peak" (level 1 only at the apex of a triangle). (run directory, exit code)."""
    from scripts.tests import test_collection_logs as evidence
    failing = (*evidence.ESHOP[:-1], [evidence.HOME, evidence.Step("detail", "GET", "/api/catalog/9", 9, 503, 40)])
    for k, outcome in enumerate(outcomes):
        d = synthetic(env, f"step-{k + 1:02d}", "eshop_high", flat=outcome != "no_peak",
                      sessions=failing if outcome == "failed" else None)
        if outcome == "dropped":
            drop_one(d)
    out = env.runs / "saturation-eshop"
    return out, run("saturation", "--protocol", V5, "--vm", "a", "--profile", "eshop", "--scenario", "eshop_high",
                    "--rates", rates, "--out", out)


SERIES = ["served", "served", "failed", "served", "failed", "failed"]  # Served up to 3 user sessions per second.
SERIES_RATES = (1., 2., 4., 2.828, 3.363, 3.084)  # --rates 1,2,4,8, then the geometric midpoints of the bracket.


def run_saturation(env):
    """--rates 1,2,4,8 served up to 3 (SERIES): the first failure at 4, then the bisection of [2, 4]."""
    out, code = series(env, SERIES, "1,2,4,8")
    assert code == 0
    return out


def oracle_peak(run_dir):
    """The peak of logs whose envelope is level 1 throughout: every interval of the measure phase."""
    ivs = [iv for iv in records_of(run_dir / "traffic_intervals.jsonl", "interval") if iv["phase"] == "measure"]
    ids = {iv["interval"] for iv in ivs}
    reqs = [r for r in records_of(run_dir / "traffic_requests.jsonl", "request") if r["interval"] in ids]
    seconds = sum(iv["mono_end"] - iv["mono_start"] for iv in ivs)
    bad = sum(r["status"] != r["intended_status"] if r["intended_status"] else r["outcome"] != "ok" for r in reqs)
    durations = sorted(r["duration_ms"] for r in reqs)
    admitted = sum(iv["admitted_sessions"] for iv in ivs)
    return {"intervals": len(ivs), "seconds": round(seconds, 6), "offered": sum(iv["offered_sessions"] for iv in ivs),
            "admitted": admitted, "dropped": 0, "drop_reasons": {}, "active_max": max(iv["active_max"] for iv in ivs),
            "requests": len(reqs), "unexpected": bad, "p95_ms": durations[-(-95 * len(durations) // 100) - 1],
            "sessions_per_s": round(admitted / seconds, 6), "requests_per_s": round(len(reqs) / seconds, 6)}


def test_saturation_runs_its_rates_in_order_then_bisects_the_bracket_on_a_copy_whose_cap_does_not_bind(env):
    """Package B11 (the lead's answer to Q5): the steps run on a copy of the protocol whose eshop max_concurrent is
    max(500, ceil(240 x 8)) = 1920; after the first failure, at 4, the bracket [2, 4] is bisected at its geometric
    midpoint, 3 decimals: 2.828 served, 3.363 and 3.084 failed; 3.084 / 2.828 < 1.15 ends the series, and the
    throughput is 2.828. The series directory keeps the given file, so the record reads one protocol."""
    from scripts import lab_trial
    out = run_saturation(env)
    r = result(out)
    steps = [out / f"step-0{k}" for k in range(1, 7)]
    assert [(s["step"], s["kind"], s["rate"]) for s in r["steps"]] == [
        (d.name, "initial" if k < 3 else "bisection", rate) for k, (d, rate) in enumerate(zip(steps, SERIES_RATES))]
    assert env.started == [generator_argv(env, d, "eshop_high", "eshop", rate, 480, k, "saturation")
                           for k, (d, rate) in enumerate(zip(steps, SERIES_RATES))] and not (out / "step-07").exists()
    assert [fake_seen(d)["signals"] for d in steps] == [["SIGTERM", "SIGUSR1", "SIGUSR2"]] * 6
    assert [([x["signal"] for x in s["run"]["signals"]], s["run"]["stop"]["stopped_by"]) for s in r["steps"]] == [
        (["SIGUSR1", "SIGUSR2"], "SIGTERM")] * 6
    peaks = [oracle_peak(d) for d in steps]
    assert [s["peak"] for s in r["steps"]] == peaks and peaks[2]["unexpected"] == 1 and peaks[0]["requests"] > 0
    failed = ["1 requests without their expected result"]
    assert [s["reasons"] for s in r["steps"]] == [[], [], failed, [], failed, failed]
    assert [(s["errors"], s["log_problems"]) for s in r["steps"]] == [([], [])] * 6
    assert r["saturation"] == {
        "rule": lab_trial.SATURATION_RULE, "latency_p95_bound_ms": 1000, "step_ratio_max": 1.15, "rate": 2.828,
        "failure": {"rate": 3.084, "reasons": failed}, "bracket": [2.828, 3.084], "ratio": round(3.084 / 2.828, 6),
        "delivered_sessions_per_s": peaks[3]["sessions_per_s"], "requests_per_s": peaks[3]["requests_per_s"],
        "proposed_rate": {"low": round(.3 * 2.828, 6), "high": round(.8 * 2.828, 6)}}  # scenario_rule.peak_share
    copy = json.loads(V5.read_text())
    copy["profiles"]["eshop"]["max_concurrent"] = 1920
    assert (out / "protocol.json").read_bytes() == V5.read_bytes()
    assert all(json.loads((d / "protocol.json").read_text()) == copy for d in steps)
    assert r["series_protocol"] == {
        "rule": lab_trial.SERIES_RULE, "path": "profiles.eshop.max_concurrent", "before": 500, "after": 1920,
        "sha256_before": hashlib.sha256(V5.read_bytes()).hexdigest(),
        "sha256_after": hashlib.sha256((steps[0] / "protocol.json").read_bytes()).hexdigest()}
    assert (r["completed"], r["error"], r["problems"], r["rates"]) == (True, None, [], [1., 2., 4., 8.])
    assert r["protocol_sha256"] == hashlib.sha256(V5.read_bytes()).hexdigest() and r["lead"]["step_ratio_max"] == 1.15
    assert r["steps"][0]["run"]["stop"]["rc"] == 0 and env.health == ["http://127.0.0.1:18080"] * 6


@pytest.mark.parametrize("outcomes, rates, code, problems", [
    (["failed"], "1,2", 0, ["no step served its peak: the lowest rate 1 fails (1 requests without their expected "
                            "result), so there is no bracket to bisect"]),
    (["served", "served"], "1,2", 0, ["every step served its peak: the throughput lies above the highest rate 2; the "
                                      "proposed rates are lower bounds"]),
    (["served", "dropped"], "1,2", 1, ["saturation did not complete: step-02 (rate 2): 1 user sessions dropped "
                                       "(drop_reason: all_customers_held 1) " + INVALID + "; the steps before it put "
                                       "the saturation at 1 or above"]),
    (["no_peak"], "1,2", 1, ["saturation did not complete: step-01 (rate 1): no interval of the measure phase lies "
                             "wholly at envelope level 1"]),
    (["served", "failed", "dropped"], "1,4", 1, [
        "saturation did not complete: step-03 (rate 2): 1 user sessions dropped (drop_reason: all_customers_held 1) "
        + INVALID, "the bracket [1, 4] is still 4 wide, not below 1.15"]),
    (["served", "failed"], "0.001,0.002", 0, [
        "the bracket [0.001, 0.002] is still 2 wide, not below 1.15 (no rate of 3 decimals lies between 0.001 and "
        "0.002)"]),
    (["served", "failed", "served"], "2,2.3", 0, []),  # 2.3 / 2 = 1.15 is not below it: one midpoint, 2.145.
], ids=["fail_first", "all_served", "dropped", "no_peak", "bracket_wide", "no_midpoint", "ratio_at_bound"])
def test_a_series_that_cannot_bracket_or_bisect_names_why(env, outcomes, rates, code, problems):
    """The lowest rate failing leaves nothing to bisect, every step served is a lower bound, an invalid step (a drop,
    no peak) ends the series with its error, and a bracket still 1.15 wide or more at the end is a problem."""
    out, rc = series(env, outcomes, rates)
    r = result(out)
    assert rc == code and len(r["steps"]) == len(outcomes) and r["completed"] is (code == 0)
    assert [p for p in r["problems"] if ": traffic log problems: " not in p] == problems
    # The series copy is the given file itself while its cap does not bind (240 x 2 = 480 is below 500).
    high = float(rates.split(",")[-1])
    assert r["series_protocol"]["after"] == max(500, math.ceil(240 * high))
    assert ((out / "step-01/protocol.json").read_bytes() == V5.read_bytes()) is (240 * high <= 500)


# ------------------------------------------------------------------ scenario

def run_scenario(env):
    synthetic(env, "scenario-eshop_low", "eshop_low")
    out = env.runs / "scenario-eshop_low"
    assert run("scenario", "--protocol", V5, "--vm", "a", "--scenario", "eshop_low", "--rate", "1.5",
               "--minutes", "10", "--out", out) == 0
    return out


def test_scenario_runs_the_generator_as_a_session_does_and_reports_every_realism_requirement(env):
    from scripts import traffic_log
    out = run_scenario(env)
    r = result(out)
    assert env.started == [generator_argv(env, out, "eshop_low", "eshop", 1.5, 720, 0, "scenario")]
    seen = fake_seen(out)
    assert seen["signals"] == ["SIGTERM", "SIGUSR1", "SIGUSR2"] and seen["argv"] == env.started[0][2:]
    realism = traffic_log.realism(out / "traffic_requests.jsonl", out / "traffic_intervals.jsonl", env.p, "eshop_low")
    assert r["realism"] == json.loads(json.dumps(realism)) and r["windows"] == []
    assert [q["name"] for q in r["realism"]["requirements"]] == [
        "arrival_cv", "think_time", "order_share", "object_concentration", "success_rate", "response_sizes",
        "peak_to_mean"]  # eshop: all but background
    assert all(q["ok"] for q in r["realism"]["requirements"]) and r["realism"]["offered_load"]["ok"]
    arrivals = records_of(out / "traffic_requests.jsonl", "arrival")
    assert r["summary"]["problems"] == [] and r["summary"]["arrivals"]["offered"] == len(arrivals)
    assert r["summary"]["measure"]["requests"] == sum(
        x["phase"] == "measure" for x in records_of(out / "traffic_requests.jsonl", "request"))
    assert [s["signal"] for s in r["run"]["signals"]] == ["SIGUSR1", "SIGUSR2"]  # in this order, then the stop
    assert (r["run"]["stop"]["stopped_by"], r["run"]["stop"]["rc"]) == ("SIGTERM", 0)
    assert r["run"]["start_unix"] == BASE and r["run"]["traffic"]["dur_s"] == 720  # warmup 120 s + 10 minutes
    synthetic_status = json.loads((env.tmp / "synthetic/scenario-eshop_low/traffic.json").read_text())
    assert r["run"]["status"]["requests"] == synthetic_status["requests"] and r["run"]["status"]["final"] is True
    assert (r["scenario"], r["profile"], r["intensity"], r["rate"], r["minutes"]) == ("eshop_low", "eshop", "low",
                                                                                       1.5, 10.)
    assert (r["completed"], r["error"], r["problems"], env.calls) == (True, None, [], [])
    assert r["judgment"]["drain_s"] == 300 and r["judgment"]["latency_p95_bound_ms"] == 1000


# ------------------------------------------------------------------ long

def run_long(env):
    synthetic(env, "long-eshop_low", "eshop_low")
    out = env.runs / "long-eshop_low"
    assert run("long", "--protocol", V5, "--vm", "a", "--scenario", "eshop_low", "--rate", "1.5", "--minutes", "60",
               "--events", "3", "--out", out) == 0
    return out


def test_long_runs_its_events_through_labctl_and_judges_the_journal_and_the_nginx_error_log(env):
    from scripts import collection, lab_trial, protocol_v5, traffic_log
    out = run_long(env)
    r = result(out)
    assert env.started == [generator_argv(env, out, "eshop_low", "eshop", 1.5, 3720, 0, "long")]
    # The draw: the first three cards of the deck of full rounds of the protocol's types (eshop_low is the first
    # scenario), times a diagnostic run admits, as the plan states them.
    types = list(env.p["events"]["types"])
    deck = random.Random(protocol_v5.seed(env.p["name"], "event_deck", "skuska/long", -1, 0)).sample(types, len(types))
    planned = r["events_planned"]
    assert [e["type"] for e in planned] == deck[:3]
    items = [{key: e[key] for key in ("type", "start_s", "duration_s")} for e in planned]
    assert collection.diagnostic_events(env.p, json.dumps(items), 720) == planned
    assert env.calls[0] == ["segment", "--label", "long-eshop_low-pre", "--dest", str(out / "guest")]
    assert env.calls[1:7] == [["event", "--event", action, e["type"]] for e in planned for action in ("start", "stop")]
    assert [c[:3] for c in env.calls[7:]] == [["segment", "--label", "long-eshop_low"],
                                             ["journal", "--label", "long-eshop_low-journal"]]
    events = json.loads((out / "events.json").read_text())["events"]
    assert [(e["type"], e["executed"], e["effect"]["ok"]) for e in events] == [(e["type"], True, True) for e in planned]
    assert r["events"] == [lab_trial.event_summary(e) for e in events]
    windows = [[e["host_start_unix"] - 1, e["host_stopped_unix"] + 60] for e in events]  # events.grace_s 60
    assert r["windows"] == windows
    realism = traffic_log.realism(out / "traffic_requests.jsonl", out / "traffic_intervals.jsonl", env.p, "eshop_low",
                                  windows=[tuple(w) for w in windows])
    assert r["realism"] == json.loads(json.dumps(realism))
    assert r["nginx_errors"] == {"lines": 2, "in_event_windows": 1, "outside_count": 1, "outside": [NGINX_OUTSIDE]}
    outside = f"{utc(BASE + 50)} hyptcn-lab-a python3[805]: Traceback (most recent call last):"
    assert r["journal_errors"] == {"loss": [], "errors_in_event_windows": 1, "errors_outside_count": 1,
                                   "errors_outside": [outside]}
    assert r["periods"] == lab_trial.periods_of([out])  # Its values: test_periods_...
    assert fake_seen(out)["signals"] == ["SIGTERM", "SIGUSR1", "SIGUSR2"]
    assert [x["signal"] for x in r["run"]["signals"]] == ["SIGUSR1", "SIGUSR2"]
    assert (r["completed"], r["error"]) == (True, None)
    assert r["problems"] == ["1 nginx error log lines outside the event windows, the first: " + NGINX_OUTSIDE,
                             "1 tracebacks or worker errors in the journal outside the event windows, the first: "
                             + outside]


# ------------------------------------------------------------------ periods

def test_periods_measures_every_register_entry_the_journal_shows_and_says_why_for_the_others(env, capsys):
    from scripts import lab_trial
    d = env.tmp / "long-run"
    (d / "guest").mkdir(parents=True)
    pack(d / "guest", "long-run-journal-journal.txt", journal_text(BASE + 5000))
    assert run("periods", "--run", d) == 0
    doc = json.loads(capsys.readouterr().out)
    register = json.loads((ROOT / "lab/periods.json").read_text())["periods"]
    assert doc["schema"] == "hyptcn3/lab-trial-periods/1" and doc["runs"] == [str(d)]
    assert [e["name"] for e in doc["periods"]] == [e["name"] for e in register]
    assert set(lab_trial.JOURNAL) | set(lab_trial.NOT_IN_JOURNAL) == {e["name"] for e in register}
    found = {e["name"]: e for e in doc["periods"]}
    measured = {"worker loop": (3, {"n": 2, "min": .9, "median": .9, "mean": 1., "max": 1.1}),
                "hyptcn-lab-udrzba.timer": (3, {"n": 2, "min": 599.5, "median": 599.5, "mean": 650.75, "max": 702.}),
                "hyptcn-lab@ restart loop": (4, {"n": 2, "min": 3.25, "median": 3.25, "mean": 3.25, "max": 3.25}),
                "PostgreSQL autovacuum launcher": (0, None)}
    for entry in register:
        e = found[entry["name"]]
        assert {k: e[k] for k in ("source", "kind", "period_s", "random_s")} == {
            k: entry[k] for k in ("source", "kind", "period_s", "random_s")}
        if entry["name"] in measured:
            assert (e["lines"], e["spacings"]) == measured[entry["name"]], entry["name"]
            assert e["journal_line"] == lab_trial.JOURNAL[entry["name"]][0]
            assert e["why"] == (lab_trial.JOURNAL[entry["name"]][2] if e["spacings"] is None else None)
        else:
            assert (e["journal_line"], e["lines"], e["spacings"]) == (None, None, None)
            assert e["why"] == lab_trial.NOT_IN_JOURNAL[entry["name"]]
    assert "log_min_messages debug1" in found["PostgreSQL autovacuum launcher"]["why"]


# ------------------------------------------------------------------ record

def test_record_assembles_every_step_with_the_provenance_of_data_results_and_passes_check_e(env):
    from scripts import lab_trial
    dirs = [run_deploy(env), run_saturation(env), run_scenario(env), run_long(env)]
    target = env.tmp / "results/skuska_labu_20261123T000000Z.json"
    target.parent.mkdir()
    assert run("record", "--out-record", target, *dirs) == 0
    doc = json.loads(target.read_text())
    assert {k: doc[k] for k in ("schema", "stage", "commit", "n", "protocol_sha256", "note")} == {
        "schema": "hyptcn3/lab-trial/1", "stage": "skuska", "commit": COMMIT, "n": 4,
        "protocol_sha256": hashlib.sha256(V5.read_bytes()).hexdigest(), "note": lab_trial.NOTE}
    assert "evidence of no criterion" in doc["note"] and type(doc["host"]) is str and doc["date"].endswith("+00:00")
    assert doc["command"] == "scripts/lab_trial.py record --out-record " + " ".join(map(str, [target, *dirs]))
    assert doc["guest"] == {"vm": "a", "domain": "hyptcn-lab-a", "identity": result(dirs[0])["guest"]}
    assert doc["values"]["runs"] == [{"dir": str(d), **result(d)} for d in dirs]
    assert doc["values"]["saturation"] == {"eshop": {"run": "saturation-eshop", "scenario": "eshop_high",
                                                     **result(dirs[1])["saturation"]}}
    # scenario_rule.peak_share 0.3 and 0.8 of the throughput 2.828 that the bisection found (package B11, Q5).
    assert doc["values"]["proposed_rate"] == {"eshop_low": .8484, "eshop_high": 2.2624, "corp_low": None,
                                              "corp_high": None}
    assert doc["values"]["periods"] == lab_trial.periods_of([dirs[3]])
    assert doc["problems"] == [
        *(f"deploy: {x}" for x in result(dirs[0])["problems"]),
        *(f"long-eshop_low: {x}" for x in result(dirs[3])["problems"]),
        "no scenario run of scenario eshop_high", "no long run of scenario eshop_high",
        "no saturation run of profile corp: no rate proposed for corp_low", "no scenario run of scenario corp_low",
        "no long run of scenario corp_low",
        "no saturation run of profile corp: no rate proposed for corp_high", "no scenario run of scenario corp_high",
        "no long run of scenario corp_high",
        "PostgreSQL autovacuum launcher: spacing not measured: "
        + lab_trial.JOURNAL["PostgreSQL autovacuum launcher"][2]]
    copy = env.tmp / "results_copy"
    copy.mkdir()
    shutil.copy(target, copy)
    check = subprocess.run(["bash", str(ROOT / "scripts/check_claims.sh"), "--json-hlavicky"], capture_output=True,
                           text=True, env={**os.environ, "VMIC_RESULTS_DIR": str(copy), "TMPDIR": str(env.tmp)})
    assert (check.returncode, check.stdout) == (0, f"check_claims.sh: hlavicky JSON v {copy} su v poriadku\n")


# ------------------------------------------------------------------ package B11: Q9, Q5 and the protocol

def autovacuum_lines(spacings):
    """Worker starts of the autovacuum launcher `spacings` s apart (a number: three times), as PostgreSQL logs them
    at debug1."""
    spacings = [spacings] * 3 if type(spacings) is float else list(spacings)
    times = [BASE + 4000 + sum(spacings[:k]) for k in range(len(spacings) + 1)]
    return "".join(f"{utc(t)} hyptcn-lab-a postgres[{700 + k}]: [{700 + k}] DEBUG:  "
                   f'autovacuum: processing database "hyptcn_lab"\n' for k, t in enumerate(times))


@pytest.mark.parametrize("spacings, spacing, ok", [
    (22.333, 22.333, True), (20., 20., False), (21., 21., True), (24., 24., True), (24.5, 24.5, False),
    ((22.333, 22.333, 22.333, 30.), 22.333, True),  # The median, not the mean (24.25, 4.25 s past 20).
], ids=["takt_67_s", "default_60_s", "at_1_s", "at_4_s", "past_4_s", "median_not_mean"])
def test_the_spacing_of_the_autovacuum_launcher_is_judged_by_the_property_of_q9(env, capsys, spacings, spacing,
                                                                               ok):
    """The lead's answer to Q9: the median spacing of the worker starts modulo interval_s lies in [1, 4] s; 22.333 s
    (67 s over three databases) holds it, 20 s (the default 60 s) does not. long, periods and record judge it alike,
    and only a measured spacing outside the bounds is a problem."""
    from scripts import lab_trial
    env.journal_more.append(autovacuum_lines(spacings))
    out = run_long(env)
    r = result(out)
    remainder = round(spacing % 5, 6)
    expected = {"rule": lab_trial.AUTOVACUUM_RULE, "interval_s": 5, "bounds_s": [1, 4], "median_s": spacing,
                "remainder_s": remainder, "ok": ok}
    assert r["autovacuum_property"] == expected
    assert remainder == {22.333: 2.333, 20.: 0, 21.: 1, 24.: 4, 24.5: 4.5}[spacing]  # The bounds hold, inclusive.
    problem = (f"PostgreSQL autovacuum launcher: the median spacing {spacing:g} s of the worker starts lies "
               f"{remainder:g} s past a multiple of interval_s 5 s, outside [1, 4] s (the lead's answer to Q9)")
    assert (problem in r["problems"]) is not ok
    capsys.readouterr()  # The long step's own lines.
    assert run("periods", "--run", out) == 0
    assert json.loads(capsys.readouterr().out)["autovacuum_property"] == expected
    target = env.tmp / "results/skuska_labu_20261124T000000Z.json"
    target.parent.mkdir()
    assert run("record", "--out-record", target, out) == 0
    doc = json.loads(target.read_text())
    assert doc["values"]["autovacuum_property"] == expected and (problem in doc["problems"]) is not ok
    assert doc["values"]["lead"]["autovacuum_remainder_s"] == [1, 4]


def test_periods_without_the_protocol_of_its_runs_does_not_judge_the_property(env, capsys):
    """No silent interval: a run directory without protocol.json (the long step writes one) leaves the property
    unjudged, with why."""
    d = env.tmp / "long-run"
    (d / "guest").mkdir(parents=True)
    pack(d / "guest", "long-run-journal-journal.txt", journal_text(BASE + 5000) + autovacuum_lines(22.333))
    assert run("periods", "--run", d) == 0
    found = json.loads(capsys.readouterr().out)["autovacuum_property"]
    assert (found["ok"], found["why"]) == (None, f"no interval_s from {d / 'protocol.json'} (FileNotFoundError)")


class Postgres:
    """PostgreSQL of the guest as lab_trial.guest_sql reaches it: the two settings, ALTER SYSTEM SET and RESET of
    them, pg_reload_conf and SHOW; every call goes into env.calls, so its order with the labctl calls of the run is
    seen. `fails`: the statement whose call ends with rc 1; `ignored`: SET answers rc 0 and changes nothing."""
    DEFAULTS = {"log_min_messages": "warning", "log_destination": "stderr"}

    def __init__(self, env, fails=None, ignored=False):
        self.env, self.fails, self.ignored, self.values = env, fails, ignored, dict(self.DEFAULTS)

    def __call__(self, pv, statements):
        from scripts import lab_trial
        self.env.calls.append(["psql", *statements])
        output = []
        for statement in statements:
            if statement == self.fails:
                return {"command": lab_trial.psql(statements), "rc": 1, "output": output, "stderr": "ERROR"}
            words = statement.split()
            if words[:3] == ["ALTER", "SYSTEM", "SET"] and not self.ignored:
                self.values[words[3]] = statement.split("'")[1]
            elif words[:2] == ["ALTER", "SYSTEM"] and words[2] == "SET":
                pass
            elif words[:3] == ["ALTER", "SYSTEM", "RESET"]:
                self.values[words[3]] = self.DEFAULTS[words[3]]
            elif words[0] == "SHOW":
                output.append(self.values[words[1]])
            else:
                output.append("t")  # SELECT pg_reload_conf()
        return {"command": lab_trial.psql(statements), "rc": 0, "output": output, "stderr": ""}


def sql_calls(env):
    return [call[1].split()[0] + " " + call[1].split()[2 if call[1].startswith("ALTER") else 0]
            if call[0] == "psql" else call[0] for call in env.calls]


@pytest.mark.parametrize("fails, ignored", [
    (None, False), ("ALTER SYSTEM SET log_destination = 'stderr,syslog'", False), (None, True),
], ids=["set", "refused", "not_applied"])
def test_postgres_debug1_is_on_for_the_long_run_only_and_named_step_by_step(env, monkeypatch, fails, ignored):
    """lab_trial long --postgres-debug1 (the lead's answers to Q9 and Q27): show, set and show before the run, reset
    and show after it, also when the set step fails, in which case the run does not start; the result names every
    step, and the settings after the run are those before it."""
    from scripts import lab_trial
    postgres = Postgres(env, fails, ignored)
    monkeypatch.setattr(lab_trial, "guest_sql", postgres)
    synthetic(env, "long-eshop_low", "eshop_low")
    out = env.runs / "long-eshop_low"
    code = run("long", "--protocol", V5, "--vm", "a", "--scenario", "eshop_low", "--rate", "1.5", "--minutes", "60",
               "--events", "3", "--postgres-debug1", "--out", out)
    r = result(out)
    record = r["postgres_debug1"]
    assert [name for name in record if name != "rule"] == ["before", "set", "during", "reset", "after"]
    assert record["rule"] == lab_trial.DEBUG1_RULE and postgres.values == Postgres.DEFAULTS
    assert record["before"]["output"] == record["after"]["output"] == ["warning", "stderr"]
    assert [record[name]["command"] for name in ("set", "reset")] == [lab_trial.psql(lab_trial.DEBUG1_SET),
                                                                      lab_trial.psql(lab_trial.DEBUG1_RESET)]
    if ignored:  # rc 0, but debug1 logging is not on: the run does not start either.
        assert code == 1 and env.started == [] and record["during"]["output"] == ["warning", "stderr"]
        assert r["error"] == ("ValueError: PostgreSQL debug1 logging is not on: the set step ended with rc 0, and "
                              "SHOW log_min_messages and SHOW log_destination give ['warning', 'stderr']")
    elif fails is None:
        assert code == 0 and record["during"]["output"] == ["debug1", "stderr,syslog"]
        assert sql_calls(env)[:3] == ["SHOW SHOW", "ALTER SET", "SHOW SHOW"]
        assert sql_calls(env)[3:] == ["segment", *["event"] * 6, "ALTER RESET", "SHOW SHOW", "segment", "journal"]
        assert not [p for p in r["problems"] if "debug1" in p] and r["completed"] is True
    else:
        # The first statement of the set step took effect before the second failed: the reset undoes it.
        assert code == 1 and env.started == [] and record["during"]["output"] == ["debug1", "stderr"]
        assert sql_calls(env) == ["SHOW SHOW", "ALTER SET", "SHOW SHOW", "ALTER RESET", "SHOW SHOW"]
        assert r["error"] == ("ValueError: PostgreSQL debug1 logging is not on: the set step ended with rc 1, and SHOW "
                              "log_min_messages and SHOW log_destination give ['debug1', 'stderr']")
        assert [p for p in r["problems"] if p.startswith("PostgreSQL debug1")] == [
            "PostgreSQL debug1 logging (--postgres-debug1): step set ended with rc 1",
            "PostgreSQL debug1 logging (--postgres-debug1): after the set step SHOW log_min_messages and SHOW "
            "log_destination give ['debug1', 'stderr'], not debug1 and stderr,syslog"]


FAKE_EXEC = """
import json, os, sys
open(os.environ["FAKE_LABCTL_ARGV"], "w").write(json.dumps(sys.argv[1:]))
print("warning")
print("stderr")
"""


def test_guest_sql_runs_psql_as_postgres_through_labctl_exec(env, monkeypatch):
    from scripts import lab_trial
    fake = env.tmp / "fake_exec.py"
    fake.write_text(FAKE_EXEC)
    monkeypatch.setattr(lab_trial, "LABCTL", fake)
    step = lab_trial.guest_sql(env.pv, lab_trial.DEBUG1_SHOW)
    command = "runuser -u postgres -- psql -XtA -c 'SHOW log_min_messages' -c 'SHOW log_destination'"
    assert step == {"command": command, "rc": 0, "output": ["warning", "stderr"], "stderr": ""}
    assert json.loads((env.tmp / "labctl_argv.json").read_text()) == [
        "exec", "--domain", "hyptcn-lab-a", "--vm", "a", "--port", "18080", "--guest-command", command]


@pytest.mark.parametrize("cap_reached", [False, True], ids=["cap_free", "cap_reached"])
def test_record_proposes_twice_the_most_concurrent_user_sessions_of_the_long_run_at_rate_high(env, cap_reached):
    """The lead's answer to Q5, point 2: max_concurrent is 2 x active_max of the measure phase of the long run of
    the profile's high scenario; a run that reached its cap gives a lower bound, a profile without such a run null with
    why."""
    from scripts import lab_trial
    d = synthetic(env, "long-eshop_high", "eshop_high")
    if cap_reached:
        intervals = [json.loads(line) for line in (d / "traffic_intervals.jsonl").read_text().splitlines()]
        next(iv for iv in intervals if iv.get("type") == "interval" and iv["phase"] == "measure")["active_max"] = 500
        (d / "traffic_intervals.jsonl").write_text("".join(json.dumps(iv) + "\n" for iv in intervals))
    out = env.runs / "long-eshop_high"
    assert run("long", "--protocol", V5, "--vm", "a", "--scenario", "eshop_high", "--rate", "3.2", "--minutes", "60",
               "--events", "3", "--out", out) == 0
    active = max(iv["active_max"] for iv in records_of(out / "traffic_intervals.jsonl", "interval")
                 if iv["phase"] == "measure")
    assert result(out)["summary"]["active_max"] == active and (active == 500) is cap_reached
    target = env.tmp / "results/skuska_labu_20261124T000000Z.json"
    target.parent.mkdir()
    assert run("record", "--out-record", target, out) == 0
    doc = json.loads(target.read_text())
    assert doc["values"]["proposed_max_concurrent"] == {"rule": lab_trial.MAX_CONCURRENT_RULE, "profiles": {
        "eshop": {"scenarios": ["eshop_high"], "run": "long-eshop_high", "rate": 3.2, "active_max": active,
                  "max_concurrent": 2 * active, "protocol_max_concurrent": 500},
        "corp": {"scenarios": ["corp_high"], "run": None, "rate": None, "active_max": None, "max_concurrent": None,
                 "protocol_max_concurrent": 250, "why": "no long run of corp_high"}}}
    assert [p for p in doc["problems"] if "lower bound" in p] == (
        ["long-eshop_high: the long run reached max_concurrent 500 (active_max 500, 0 user sessions of the measure "
         "phase dropped): 1000 for profile eshop is a lower bound; G2 runs it with a cap that does not bind (proposal "
         "10.3)"] if cap_reached else [])


def test_the_series_copy_is_the_given_file_byte_for_byte_while_its_cap_does_not_bind(env):
    """A protocol file in another layout than the repository's (indent 1): with --rates 1,2 its cap 500 is above
    240 x 2, so every step runs on the given bytes, not on a rewritten file."""
    given = env.tmp / "protocol-indent-1.json"
    given.write_text(json.dumps(json.loads(V5.read_text()), indent=1) + "\n")
    for name in ("step-01", "step-02"):
        synthetic(env, name, "eshop_high", flat=True)
    out = env.runs / "saturation-eshop"
    assert run("saturation", "--protocol", given, "--vm", "a", "--profile", "eshop", "--scenario", "eshop_high",
               "--rates", "1,2", "--out", out) == 0
    r = result(out)
    assert all((out / name / "protocol.json").read_bytes() == given.read_bytes() for name in ("step-01", "step-02"))
    assert (r["series_protocol"]["before"], r["series_protocol"]["after"]) == (500, 500)
    assert r["series_protocol"]["sha256_after"] == r["series_protocol"]["sha256_before"] == hashlib.sha256(
        given.read_bytes()).hexdigest()


def test_a_dropped_user_session_of_a_scenario_run_is_named_by_its_drop_reason(env):
    """Package B5c, finding F1, the lab_trial half (taken over by B11 from B10): a drop of the measure phase is named by
    the generator's drop_reason, not called one over max_concurrent."""
    drop_one(synthetic(env, "scenario-eshop_low", "eshop_low"))
    out = env.runs / "scenario-eshop_low"
    assert run("scenario", "--protocol", V5, "--vm", "a", "--scenario", "eshop_low", "--rate", "1.5", "--minutes", "10",
               "--out", out) == 0
    r = result(out)
    assert r["summary"]["drop_reasons"] == {"all_customers_held": 1}
    assert "1 user sessions dropped (drop_reason: all_customers_held 1) in the measure phase" in r["problems"]


def test_the_cap_of_a_profile_is_a_value_of_g2_and_preliminary_until_then(tmp_path):
    """The lead's answer to Q5: determined_at G2 names profiles.*.max_concurrent; 500 and 250 stay as preliminary
    values, and the notes say so; a changed cap keeps the records of G0 and G1 and reopens G2 and the later ones.
    The basis of scenario_rule names the series of G2 and the latency bound as the tool's judgment, its note the
    checks of rate high against the cycle time and D12."""
    from scripts import gates
    doc = json.loads(V5.read_text())
    assert "profiles.*.max_concurrent" in doc["determined_at"]["G2"]
    assert [doc["profiles"][name]["max_concurrent"] for name in ("eshop", "corp")] == [500, 250]
    assert all("preliminary until G2" in doc["profiles"][name]["note"] for name in ("eshop", "corp"))
    rule = doc["scenario_rule"]
    assert "1000 ms" in rule["basis"] and "judgment" in rule["basis"] and "1.15" in rule["basis"]
    assert "audit.cycle_ms_max" in rule["note"] and "D12" in rule["note"]
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_bytes(V5.read_bytes())
    doc["profiles"]["eshop"]["max_concurrent"] = 1600
    after.write_text(json.dumps(doc, indent=2) + "\n")
    assert [stage for stage in gates.STAGES
            if gates.stage_binding(before, stage) == gates.stage_binding(after, stage)] == ["G0", "G1"]


def test_the_executors_choices_of_the_saturation_series_are_named_as_such():
    """V2 of dokazy/B11/odlozene_B11.md (package B10): the lead's answer to Q5 asks a bisection until neighbouring
    steps are closer than 15 %; the geometric midpoint, its three decimals and the reading of 15 % as failed / served
    below 1.15 are the executor's (package B11), and the rule that a dropped user session or a step without a peak
    invalidates the step is finding F1 of the B5c verification. scenario_rule.basis of the file, proposal 10.3 and the
    tool's rule (SATURATION_RULE) name each as such, and the tool's numbers are the ones named."""
    from scripts import lab_trial
    assert ("ends the series with an error (finding F1 of the B5c verification)" in lab_trial.SATURATION_RULE
            and "rounded to 3 decimals (the executor's judgment, package B11)" in lab_trial.SATURATION_RULE
            and "(the executor's reading of the lead's 15 %, package B11)" in lab_trial.SATURATION_RULE)
    basis = json.loads(V5.read_text())["scenario_rule"]["basis"]
    assert ("is invalid (finding F1 of the B5c verification)" in basis
            and "bisected (the lead's answer to Q5) at the geometric midpoint, rounded to three decimals (the "
                "executor's judgment, package B11)" in basis
            and "less than 1.15 times the served one (the executor's reading, package B11, of the lead's \"until "
                "neighbouring steps are closer than 15 %\")" in basis)
    text = (V5.parents[1] / "docs/NAVRH_PROTOKOL_V5.sk.md").read_text(encoding="utf-8")
    section = " ".join(text[text.index("### 10.3 "):text.index("### 10.4 ")].split())
    assert ("rad skončí chybou (nález F1 overenia B5c)" in section
            and "v geometrickom strede, zaokrúhlenom na tri desatinné miesta (úsudok vykonávateľa, balík B11)"
            in section
            and "1,15-násobok obslúženého (čítanie vykonávateľa, balík B11: vedúci píše „kým susedné kroky nie sú "
                "bližšie než 15 %“)" in section)
    assert (lab_trial.STEP_RATIO_MAX, lab_trial.MIDPOINT_DECIMALS) == (1.15, 3)


# ------------------------------------------------------------------ G2 preparation (P5): the QEMU of each VM

QEMU_CHANGED = "VM {vm} (hyptcn-lab-{vm}): its QEMU process changed between or during its runs (a restart of the VM)"


def qemu_process(pid):
    """A QEMU process as collection.qemu_process names it."""
    return {"pid": pid, "start_ticks": pid, "host_boot": "host-boot"}


def fake_run(env, monkeypatch, name, step, vm, start, end):
    """A run directory of `step` on VM `vm`, written by the tool's own create(), started() and finish() with no VM and
    no lab command: its QEMU was `start` at its start and `end` at its end (collection.qemu_process faked, None for the
    other VM's domain). A traffic step is a run of eshop_low without a fetched journal; record reads nothing else of
    it."""
    from scripts import collection, lab_trial
    pv, raw, out = collection.for_vm(env.p, vm), V5.read_bytes(), env.runs / name
    lab_trial.create(out, raw)
    monkeypatch.setattr(collection, "qemu_process", lambda domain: start if domain == pv["domain"] else None)
    result = lab_trial.started(step, [step, "--protocol", V5, "--vm", vm, "--out", out], V5, raw, pv)
    if step != "deploy":
        result.update(scenario="eshop_low", profile="eshop", intensity="low", rate=1.2, minutes=60)
    result["completed"] = True
    monkeypatch.setattr(collection, "qemu_process", lambda domain: end if domain == pv["domain"] else None)
    assert lab_trial.finish(out, result, lambda r: []) == 0
    return out


def qemu_problems(env, *dirs):
    """The problems of the record of `dirs` that say a QEMU process changed."""
    target = env.tmp / "results/skuska_labu_20261124T200000Z.json"
    target.parent.mkdir()
    assert run("record", "--out-record", target, *dirs) == 0
    return [x for x in json.loads(target.read_text())["problems"] if "QEMU process changed" in x]


@pytest.mark.parametrize("deploy_start", ["running", "started"])
def test_record_compares_the_qemu_of_each_vm_with_its_own_runs_only(env, monkeypatch, deploy_start):
    """G2 preparation, P5 (the VM window of Q27): a record of the deploys and runs of both VMs, each VM on one QEMU
    process, reports no change of QEMU; the processes of both VMs in one set made a false "QEMU changed". A deploy may
    start its VM ("started": no QEMU at the deploy's start), so its start does not count, per VM as before."""
    qa, qb = qemu_process(4242), qemu_process(4343)
    dirs = [fake_run(env, monkeypatch, "deploy-a", "deploy", "a", qa if deploy_start == "running" else None, qa),
            fake_run(env, monkeypatch, "deploy-b", "deploy", "b", qb if deploy_start == "running" else None, qb),
            fake_run(env, monkeypatch, "long-a", "long", "a", qa, qa),
            fake_run(env, monkeypatch, "scenario-b", "scenario", "b", qb, qb)]
    assert qemu_problems(env, *dirs) == []


@pytest.mark.parametrize("when", ["during", "between"])
@pytest.mark.parametrize("vm", ["a", "b"])
def test_a_qemu_that_changed_within_one_vm_is_the_problem_of_that_vm_only(env, monkeypatch, vm, when):
    """G2 preparation, P5: a restart of one VM during one of its runs (a new QEMU at the run's end) or between two of
    its runs (a new QEMU at the start of the later one) is one problem, which names that VM; the other VM, on one QEMU,
    has none."""
    first, new = {"a": qemu_process(4242), "b": qemu_process(4343)}, qemu_process(4444)
    traffic = {x: (first[x], first[x]) for x in "ab"}
    traffic[vm] = (first[vm], new) if when == "during" else (new, new)
    dirs = [fake_run(env, monkeypatch, "deploy-a", "deploy", "a", first["a"], first["a"]),
            fake_run(env, monkeypatch, "deploy-b", "deploy", "b", first["b"], first["b"]),
            fake_run(env, monkeypatch, "long-a", "long", "a", *traffic["a"]),
            fake_run(env, monkeypatch, "scenario-b", "scenario", "b", *traffic["b"])]
    assert qemu_problems(env, *dirs) == [QEMU_CHANGED.format(vm=vm)]


def test_a_restart_of_each_vm_is_one_problem_each_in_the_order_of_the_runs(env, monkeypatch):
    """G2 preparation, P5: when the QEMU of both VMs changed, each VM has its own problem, in the order in which the
    record's runs first name the VMs (the executor's judgment, G2 preparation), here VM b before VM a."""
    qa, qb, qa_new, qb_new = (qemu_process(pid) for pid in (4242, 4343, 4444, 4545))
    dirs = [fake_run(env, monkeypatch, "deploy-b", "deploy", "b", qb, qb),
            fake_run(env, monkeypatch, "deploy-a", "deploy", "a", qa, qa),
            fake_run(env, monkeypatch, "long-a", "long", "a", qa, qa_new),
            fake_run(env, monkeypatch, "scenario-b", "scenario", "b", qb_new, qb_new)]
    assert qemu_problems(env, *dirs) == [QEMU_CHANGED.format(vm="b"), QEMU_CHANGED.format(vm="a")]


@pytest.mark.parametrize("steps, changed", [
    ([("deploy", 1, 1), ("long", 1, 1), ("scenario", 1, 1)], False),
    ([("deploy", None, 1), ("long", 1, 1)], False),
    ([("deploy", 1, 2), ("long", 2, 2)], False),
    ([("deploy", 1, 1), ("long", 1, 2)], True),
    ([("deploy", 1, 1), ("long", 2, 2)], True),
    ([("long", 1, 2)], True),
], ids=["same_qemu", "deploy_starts_the_vm", "deploy_restarts_the_vm", "during_a_run", "between_runs",
        "during_the_only_run"])
def test_the_qemu_of_a_single_vm_is_judged_as_before(env, monkeypatch, steps, changed):
    """G2 preparation, P5: the runs of one VM keep the rule of the tool's first version (82f26cc). The QEMU at the
    start and the end of every run is one process, and a deploy's start does not count (it may start or restart the
    VM). The same runs give a problem exactly when they gave one before; the problem now names the VM."""
    process = {None: None, 1: qemu_process(4242), 2: qemu_process(4444)}
    dirs = [fake_run(env, monkeypatch, f"{k}-{step}", step, "a", process[start], process[end])
            for k, (step, start, end) in enumerate(steps)]
    assert qemu_problems(env, *dirs) == ([QEMU_CHANGED.format(vm="a")] if changed else [])


# ------------------------------------------------------------------ refused inputs

@pytest.mark.parametrize("case", ["unknown_scenario", "run_directory_exists", "profile_mismatch", "no_rate",
                                  "events_count"])
def test_a_refused_input_names_its_reason_and_writes_nothing(env, capsys, case):
    out = env.runs / "refused"
    common = ["--protocol", V5, "--vm", "a", "--out", out]
    argv, reason = {
        "unknown_scenario": (["scenario", *common, "--scenario", "steady", "--rate", "1", "--minutes", "10"],
                             "unknown scenario: steady (the protocol has eshop_low, eshop_high, corp_low, corp_high)"),
        "run_directory_exists": (["deploy", *common], f"the run directory exists: {out} (every step writes a new one)"),
        "profile_mismatch": (["saturation", *common, "--profile", "corp", "--scenario", "eshop_high", "--rates", "1,2"],
                             "--profile corp differs from scenarios.eshop_high.profile eshop"),
        "no_rate": (["scenario", *common, "--scenario", "eshop_low", "--minutes", "10"],
                    "the generator refuses the run: scenarios.eshop_low.rate is null: --rate is required"),
        "events_count": (["long", *common, "--scenario", "eshop_low", "--rate", "1", "--minutes", "60",
                          "--events", "2"],
                         "--events 2: the protocol allows [0, 3] events in a session"),
    }[case]
    if case == "run_directory_exists":
        out.mkdir(parents=True)
    assert run(*argv) == 2
    assert capsys.readouterr().err == f"lab_trial: {reason}\n"
    assert (list(out.iterdir()) == []) if out.exists() else case != "run_directory_exists"
    assert (env.calls, env.started, env.health) == ([], [], [])
    assert not (env.tmp / "labctl_argv.json").exists()
