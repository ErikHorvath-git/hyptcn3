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
    calls, started = [], []

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
                "files": [pack(dest, label + "-journal.txt", journal_text(now))]}
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
                                      "RssAnon:\t 2000000 kB\n")
    (proc / "sys/vm").mkdir(parents=True)
    (proc / "sys/vm/swappiness").write_text("1\n")
    for path, (current, stat, swap, swap_max) in CGROUPS.items():
        d = cgroups / path.lstrip("/")
        d.mkdir(parents=True)
        for name, value in (("memory.current", current), ("memory.stat", stat), ("memory.swap.current", swap),
                            ("memory.swap.max", swap_max)):
            (d / name).write_text(value + ("" if value.endswith("\n") else "\n"))
    monkeypatch.setattr(labctl, "PROC", proc)
    monkeypatch.setattr(labctl, "CGROUPS", cgroups)
    p = collection.protocol(V5)
    return type("Env", (), dict(tmp=tmp_path, runs=tmp_path / "runs", calls=calls, started=started, health=health,
                                identity=identity, p=p, pv=collection.for_vm(p, "a")))


def synthetic(env, name, scenario, **traffic):
    """Synthetic logs of a v5 profile for the run named `name` (test_collection_logs build and v5_traffic)."""
    from scripts.tests import test_collection_logs as evidence
    d = evidence.build(env.tmp / "synthetic", session_name=name)
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
    assert r["qemu_memory"] == {"domain": "hyptcn-lab-a", "qemu_pid": 4242, "cgroup": SCOPE, "memory_swap_max": "0",
                                "vm_swap_kb": 12, "rss_anon_kb": 2000000, "own": own, "own_anon_share": .051,
                                "charged_to_own_cgroup": False, "holders": [holder], "vm_swappiness": 1}
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
    return {"intervals": 12, "seconds": 60.0, "offered": 30, "admitted": 30, "dropped": 0, "active_max": 40,
            "requests": 270, "unexpected": 0, "p95_ms": 120.5, "sessions_per_s": .5, "requests_per_s": 4.5, **change}


@pytest.mark.parametrize("third, reason", [
    ({"dropped": 2}, "2 user sessions dropped over max_concurrent"),
    ({"unexpected": 3}, "3 requests without their expected result"),
    ({"p95_ms": 1000}, "p95 latency 1000 ms, not below 1000 ms"),
    ({"intervals": 0, "requests": 0, "p95_ms": None},
     "no interval of the measure phase lies wholly at envelope level 1"),
], ids=["dropped", "unexpected", "latency", "no_peak"])
def test_saturation_rule_on_a_synthetic_step_series_with_a_known_answer(third, reason):
    """Four steps: the third fails by one criterion, the fourth would pass again; the saturation is the second."""
    from scripts import lab_trial
    series = [(.5, peak()), (1., peak(p95_ms=999.9, sessions_per_s=1., requests_per_s=9.)), (2., peak(**third)),
              (4., peak())]
    steps = [{"rate": rate, "peak": p, "reasons": lab_trial.step_reasons(p)} for rate, p in series]
    assert [s["reasons"] for s in steps] == [[], [], [reason], []]
    share = {"low": .3, "high": .8}
    assert lab_trial.saturation_rule(steps, share) == {
        "rule": lab_trial.SATURATION_RULE, "latency_p95_bound_ms": 1000, "rate": 1.,
        "first_failure": {"rate": 2., "reasons": [reason]}, "delivered_sessions_per_s": 1., "requests_per_s": 9.,
        "proposed_rate": {"low": .3, "high": .8}}
    first_fails = lab_trial.saturation_rule(steps[2:], share)
    assert (first_fails["rate"], first_fails["proposed_rate"]) == (None, {"low": None, "high": None})
    all_pass = lab_trial.saturation_rule(steps[:2], share)
    assert (all_pass["rate"], all_pass["first_failure"], all_pass["proposed_rate"]) == (1., None, share)


def run_saturation(env):
    """Three steps of --rates 1,2,4,8 have synthetic logs, level 1 throughout; the third answers one request 503."""
    from scripts.tests import test_collection_logs as evidence
    failing = (*evidence.ESHOP[:-1], [evidence.HOME, evidence.Step("detail", "GET", "/api/catalog/9", 9, 503, 40)])
    for name, sessions in (("step-01", None), ("step-02", None), ("step-03", failing)):
        synthetic(env, name, "eshop_high", flat=True, sessions=sessions)
    out = env.runs / "saturation-eshop"
    assert run("saturation", "--protocol", V5, "--vm", "a", "--profile", "eshop", "--scenario", "eshop_high",
               "--rates", "1,2,4,8", "--out", out) == 0
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
            "admitted": admitted, "dropped": 0, "active_max": max(iv["active_max"] for iv in ivs),
            "requests": len(reqs), "unexpected": bad, "p95_ms": durations[-(-95 * len(durations) // 100) - 1],
            "sessions_per_s": round(admitted / seconds, 6), "requests_per_s": round(len(reqs) / seconds, 6)}


def test_saturation_runs_the_steps_in_order_and_stops_after_the_first_peak_not_served(env):
    from scripts import lab_trial
    out = run_saturation(env)
    r = result(out)
    steps = [out / f"step-0{k}" for k in (1, 2, 3)]
    assert env.started == [generator_argv(env, d, "eshop_high", "eshop", rate, 480, k, "saturation")
                           for k, (d, rate) in enumerate(zip(steps, (1., 2., 4.)))]
    assert [fake_seen(d)["signals"] for d in steps] == [["SIGTERM", "SIGUSR1", "SIGUSR2"]] * 3
    assert [([x["signal"] for x in s["run"]["signals"]], s["run"]["stop"]["stopped_by"]) for s in r["steps"]] == [
        (["SIGUSR1", "SIGUSR2"], "SIGTERM")] * 3
    peaks = [oracle_peak(d) for d in steps]
    assert [s["peak"] for s in r["steps"]] == peaks and peaks[2]["unexpected"] == 1 and peaks[0]["requests"] > 0
    assert [s["reasons"] for s in r["steps"]] == [[], [], ["1 requests without their expected result"]]
    assert [s["log_problems"] for s in r["steps"]] == [[], [], []] and not (out / "step-04").exists()
    assert r["saturation"] == {
        "rule": lab_trial.SATURATION_RULE, "latency_p95_bound_ms": 1000, "rate": 2.,
        "first_failure": {"rate": 4., "reasons": ["1 requests without their expected result"]},
        "delivered_sessions_per_s": peaks[1]["sessions_per_s"], "requests_per_s": peaks[1]["requests_per_s"],
        "proposed_rate": {"low": .6, "high": 1.6}}  # scenario_rule.peak_share 0.3 and 0.8 of the saturation
    assert (r["completed"], r["error"], r["problems"], r["rates"]) == (True, None, [], [1., 2., 4., 8.])
    assert r["steps"][0]["run"]["stop"]["rc"] == 0 and env.health == ["http://127.0.0.1:18080"] * 3


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
    assert doc["values"]["proposed_rate"] == {"eshop_low": .6, "eshop_high": 1.6, "corp_low": None, "corp_high": None}
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
