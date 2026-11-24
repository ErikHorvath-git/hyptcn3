"""run_session under protocol schema 3 (package B5b, design section 4; lead's remarks on B4, part 1, section 3).

A scenario of schema 3 is {profile, intensity, rate}. v5 has no pilot: --role pilot ends with a named reason and a
trial session runs as --role diagnostic, with profile and intensity from --scenario, the rate from the protocol or
--rate, events from --events (checked against the protocol's events) or none. A session of a planned role takes
the protocol's rate, the seeds and the events of its planned session (the items of the plan as they are) and needs
the readiness records up to G4. session.json records the v5 traffic block, from which the generator's command line
of design 1.3 is made, and the host's timers. The log audit compares every key of the planned events of
session.json with events.json. Fakes only: no VM, no collector, no sudo. Names package B5b adds are read inside the
tests, so this file collects on the code before B5b.
"""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
LOAD_MODEL = ("open loop: user sessions arrive as a non-homogeneous Poisson process with intensity rate x "
              "envelope(t), at most max_concurrent in progress")  # Design B5b 1.4.
PLAN_KEYS = {"type", "class", "start_s", "duration_s", "start_phase_s", "stop_phase_s"}
# Three events of a diagnostic run of 600 rows (3000 s; full snapshots at 0 and 1800 s, guards [-60, 160) and
# [1740, 1960) s): first_s 300, 480 s between an end and the next start, tail_s 360 before 3000 s.
EVENTS = [{"type": "zamok_tabulky", "start_s": 300, "duration_s": 120.5},
          {"type": "naprazdno", "start_s": 901, "duration_s": 200},
          {"type": "zataz_pamate", "start_s": 1600, "duration_s": 360}]
STATED = [{"type": "zamok_tabulky", "class": "chyba_aplikacie", "start_s": 300.0, "duration_s": 120.5,
           "start_phase_s": 0.0, "stop_phase_s": 0.5},
          {"type": "naprazdno", "class": "naprazdno", "start_s": 901.0, "duration_s": 200.0, "start_phase_s": 1.0,
           "stop_phase_s": 1.0},
          {"type": "zataz_pamate", "class": "zataz_pamate", "start_s": 1600.0, "duration_s": 360.0,
           "start_phase_s": 0.0, "stop_phase_s": 0.0}]


def v5_doc(rate=None, profile=None):
    """config/collection-v5.json; every scenario with `rate` when given (G2 determines it), the profile directory
    `profile` when given."""
    doc = json.loads(V5.read_text())
    if rate is not None:
        for scenario in doc["scenarios"].values():
            scenario["rate"] = rate
    if profile is not None:
        doc["profile"] = str(profile)
    return doc


def loaded(tmp_path, doc, vm="a"):
    """(path, the protocol of VM `vm` as run_session gets it)."""
    from scripts import collection
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(doc, indent=2))
    return path, collection.for_vm(collection.protocol(path), vm)


def args(path, **changes):
    """The namespace of `collection.py run` for a diagnostic run of eshop_low on VM a. A session of another role
    names its plan and attempt (package B9): mode campaign and attempt 1 unless `changes` give them."""
    values = dict(protocol=path, role="diagnostic", scenario="eshop_low", group="trial-1", vm="a", seed=7,
                  pilot_report=None, session_id=None, campaign_id=None, replaces=None, expected_boot_id=None,
                  expected_qemu=None, group_attempt=1, collections_dir=None, cycles=None, rate=None, events=None,
                  mode=None, attempt=None)
    if changes.get("role", "diagnostic") != "diagnostic":
        values.update(mode="campaign", attempt=1)
    values.update(changes)
    return SimpleNamespace(**values)


def planned_session(p):
    from scripts import collection
    return next(s for s in collection.plan(p)["sessions"] if s["vm"] == p["vm"] and s.get("events"))


def traffic_seeds(seeds):
    return {name: value for name, value in seeds.items() if name == "traffic" or name.startswith("traffic_")}


def test_v5_has_no_pilot_and_run_session_says_so_before_it_touches_anything(tmp_path, monkeypatch):
    """After the self-test record and root (the first things run_session asks, package B3), before any guest access
    and before a directory exists."""
    from scripts import collection
    path, p = loaded(tmp_path, v5_doc())
    touched = []
    monkeypatch.setattr("scripts.audit_selftest.require_selftest", lambda *a, **k: touched.append("self-test"))
    monkeypatch.setattr("os.geteuid", lambda: 0)
    for name in ("guest_identity", "qemu_process", "collection_lock", "lab_json"):
        monkeypatch.setattr(collection, name, lambda *a, _name=name, **kw: touched.append(_name))
    with pytest.raises(ValueError) as refused:
        collection.run_session(args(path, role="pilot", collections_dir=tmp_path / "collections"), p)
    assert str(refused.value) == "protocol schema 3 has no pilot: a trial session runs as --role diagnostic"
    assert touched == ["self-test"] and not (tmp_path / "collections").exists()


NULL_RATE = "scenario eshop_low has no rate (null until G2)"


@pytest.mark.parametrize("rate, change, reason", [
    (None, {"scenario": "steady"}, "unknown benign scenario"),
    (None, {"pilot_report": Path("pilot.json")}, "protocol schema 3 has no pilot: --pilot-report is not read"),
    (None, {"role": "train", "rate": 2.}, "--rate is only allowed for diagnostic runs"),
    (None, {"role": "train", "events": "[]"}, "--events is only allowed for diagnostic runs"),
    (None, {"role": "train", "cycles": 10}, "--cycles is only allowed for diagnostic runs"),
    (None, {"role": "train"}, NULL_RATE + ": a session of a planned role runs at the protocol's rate"),
    (2., {"role": "train", "group": "v5-train-1", "seed": 1}, "assignment/seed not present in frozen collection plan"),
    (2., "planned", "a session of a planned role needs valid readiness records up to G4: stage G0 is not valid: "
                    "no record"),
    (None, {}, NULL_RATE + ": a diagnostic run passes --rate"),
    (2., {"rate": 3.}, "scenario eshop_low has the rate 2 in the protocol: --rate is refused"),
    (None, {"rate": 0.}, "invalid --rate: user sessions per second at envelope level 1, a finite number above 0"),
    (None, {"rate": 1., "cycles": -1}, "invalid --cycles: a positive number of snapshots"),
], ids=["unknown_scenario", "pilot_report", "planned_rate", "planned_events", "planned_cycles", "planned_null_rate",
        "not_planned", "no_readiness_records", "diagnostic_without_rate", "diagnostic_rate_twice",
        "diagnostic_rate", "diagnostic_cycles"])
def test_what_a_v5_session_runs_is_refused_with_its_reason(tmp_path, monkeypatch, rate, change, reason):
    from scripts import collection, gates
    path, p = loaded(tmp_path, v5_doc(rate))
    monkeypatch.setattr(gates, "ROOT", tmp_path)  # No readiness record below tmp_path/data/results.
    if change == "planned":
        s = planned_session(p)
        change = {"role": s["role"], "group": s["group"], "scenario": s["scenario"], "seed": s["seed"]}
    with pytest.raises(ValueError) as refused:
        collection.v5_run(args(path, **change), p)
    assert str(refused.value) == reason


def test_rate_and_events_are_refused_under_schemas_1_and_2(monkeypatch):
    from scripts import collection
    monkeypatch.setattr("scripts.audit_selftest.require_selftest", lambda *a, **k: None)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    for change in ({"rate": 1.}, {"events": "[]"}):
        with pytest.raises(ValueError) as refused:
            collection.run_session(args(collection.DEFAULT, scenario="steady", **change),
                                   collection.protocol(collection.DEFAULT))
        assert str(refused.value) == "--rate and --events are only allowed for diagnostic runs under protocol schema 3"


def test_a_planned_session_runs_at_the_protocols_rate_with_the_seeds_and_events_of_its_plan(tmp_path, monkeypatch):
    from scripts import collection, gates
    path, p = loaded(tmp_path, v5_doc(2.5))
    s = planned_session(p)
    required = []
    monkeypatch.setattr(gates, "require", lambda results, protocol, stage: required.append((results, protocol, stage)))
    run = collection.v5_run(args(path, role=s["role"], group=s["group"], scenario=s["scenario"], seed=s["seed"]), p)
    assert required == [(gates.ROOT / "data/results", path, "G5")]
    assert run["cycles"] == 720 and run["events"] == s["events"] and len(s["events"]) == 3
    assert all(set(event) == PLAN_KEYS for event in run["events"])  # The items of the plan as they are.
    scenario = p["scenarios"][s["scenario"]]
    assert run["traffic"] == {
        "generator": "scripts/host_traffic.py", "load_model": LOAD_MODEL, "profile": scenario["profile"],
        "scenario": s["scenario"], "intensity": scenario["intensity"], "rate": 2.5, "rate_source": "protocol",
        "seeds": traffic_seeds(s["seeds"]), "target": "http://127.0.0.1:18080",
        "dur_s": 3720, "warmup_s": 120,  # 120 s of warmup and 720 intervals of 5 s
        "summary_interval_s": 5, "initial_phase": "warmup"}
    assert run["traffic"]["seeds"]["traffic"] == s["seed"]


def test_a_diagnostic_run_takes_rate_events_and_seeds_from_its_command_line(tmp_path):
    from scripts import collection, protocol_v5
    path, p = loaded(tmp_path, v5_doc())
    run = collection.v5_run(args(path, rate=.5, events=json.dumps(EVENTS)), p)
    assert (run["cycles"], run["events"]) == (600, STATED)  # pilot_cycles without --cycles, as before
    seeds = run["traffic"]["seeds"]
    assert seeds == {name: 7 if name == "traffic" else protocol_v5.seed(p["name"], name, "diagnostic/trial-1", 7, 1)
                     for name in protocol_v5.PURPOSES if name == "traffic" or name.startswith("traffic_")}
    assert len(set(seeds.values())) == len(seeds)
    assert {k: v for k, v in run["traffic"].items() if k != "seeds"} == {
        "generator": "scripts/host_traffic.py", "load_model": LOAD_MODEL, "profile": "eshop", "scenario": "eshop_low",
        "intensity": "low", "rate": .5, "rate_source": "command line", "target": "http://127.0.0.1:18080",
        "dur_s": 3120, "warmup_s": 120, "summary_interval_s": 5, "initial_phase": "warmup"}  # 120 s + 600 x 5 s
    short = collection.v5_run(args(path, rate=.5, cycles=400), p)
    assert (short["cycles"], short["events"], short["traffic"]["dur_s"]) == (400, [], 2120)


def _events(change):
    events = json.loads(json.dumps(EVENTS))
    change(events)
    return json.dumps(events)


@pytest.mark.parametrize("text, cycles, reason", [
    ("[", 600, "not JSON"),
    (_events(lambda e: e[0].update({"class": "chyba_aplikacie"})), 600, "not a JSON list of {type, start_s, duration_s}"),
    (json.dumps(EVENTS[:1]), 600, "1 events, the protocol allows [0, 3]"),
    (_events(lambda e: e[0].update(type="zamok_databazy")), 600, "unknown event type zamok_databazy"),
    (_events(lambda e: e[0].update(start_s="300")), 600, "zamok_tabulky: start_s and duration_s are seconds"),
    (_events(lambda e: e[0].update(duration_s=100)), 600, "zamok_tabulky lasts 100 s, outside duration_s [120, 360]"),
    (_events(lambda e: e[0].update(start_s=200)), 600, "zamok_tabulky starts at 200 s, before first_s 300 s"),
    (_events(lambda e: e[1].update(start_s=900)), 600,
     "naprazdno starts less than min_gap_s 480 s after the event before it ends"),
    (_events(lambda e: e[2].update(start_s=1750)), 600,
     "zataz_pamate starts at 1750 s inside the guard of the full snapshot at 1800 s"),
    (json.dumps(EVENTS), 400, "the last event ends less than tail_s 360 s before the end of the session (2000 s)"),
], ids=["not_json", "not_a_list_of_events", "count", "type", "not_seconds", "duration", "first_s", "min_gap_s",
        "guard", "tail_s"])
def test_events_of_a_diagnostic_run_are_checked_against_the_protocols_events(tmp_path, text, cycles, reason):
    from scripts import collection
    _, p = loaded(tmp_path, v5_doc())
    with pytest.raises(ValueError) as refused:
        collection.diagnostic_events(p, text, cycles)
    assert str(refused.value) == "invalid --events: " + reason


def test_events_of_a_diagnostic_run_as_the_plan_states_them(tmp_path):
    from scripts import collection
    _, p = loaded(tmp_path, v5_doc())
    assert collection.diagnostic_events(p, json.dumps(EVENTS), 600) == STATED
    assert collection.diagnostic_events(p, "[]", 600) == collection.diagnostic_events(p, None, 600) == []


def test_the_generator_command_line_of_a_v5_session(tmp_path):
    """Design B5b 1.3, with the session's copy of the protocol; --rate only when the rate is the command line's."""
    from scripts import collection
    out = tmp_path / "session-1"
    path, p = loaded(tmp_path, v5_doc())
    traffic = collection.v5_run(args(path, rate=.5), p)["traffic"]
    argv = [str(x) for x in collection.traffic_command(p, {"scenario": "eshop_low", "seed": 7, "traffic": traffic}, out)]
    assert argv == [sys.executable, str(ROOT / "scripts/host_traffic.py"), "--profile", "eshop",
                    "--protocol", str(out / "protocol.json"), "--scenario", "eshop_low",
                    "--seeds", json.dumps(traffic["seeds"], sort_keys=True), "--rate", "0.5",
                    "--target", "http://127.0.0.1:18080", "--dur", "3120", "--warmup-s", "120",
                    "--session-id", "session-1", "--requests-log", str(out / "traffic_requests.jsonl"),
                    "--intervals-log", str(out / "traffic_intervals.jsonl"), "--summary-interval-s", "5",
                    "--initial-phase", "warmup", "--out", str(out / "traffic.json")]
    path, p = loaded(tmp_path, v5_doc(2.))
    traffic = collection.v5_run(args(path), p)["traffic"]
    argv = [str(x) for x in collection.traffic_command(p, {"scenario": "eshop_low", "seed": 7, "traffic": traffic}, out)]
    assert "--rate" not in argv and argv[argv.index("--dur") + 1] == "3120"


def test_the_generator_command_line_under_schema_2_is_unchanged(tmp_path):
    from scripts import collection
    out = tmp_path / "session-1"
    p = collection.protocol(collection.DEFAULT)
    argv = [str(x) for x in collection.traffic_command(p, {"scenario": "steady", "seed": 3}, out)]
    assert argv == [sys.executable, str(ROOT / "scripts/host_traffic.py"), "--profile", "lab",
                    "--target", "http://127.0.0.1:18080", "--dur", "0", "--seed", "3", "--vlakien", "4",
                    "--burst", "0.2", "--catalog-share", "0.5", "--write-share", "0.2", "--session-id", "session-1",
                    "--requests-log", str(out / "traffic_requests.jsonl"),
                    "--intervals-log", str(out / "traffic_intervals.jsonl"), "--summary-interval-s", "5",
                    "--initial-phase", "warmup", "--out", str(out / "traffic.json")]


def _request(rid, status, outcome, **extra):
    return {"type": "request", "rid": rid, "status": status, "outcome": outcome, **extra}


@pytest.mark.parametrize("record, problem", [
    (_request("r3", 200, "ok", intended_status=404), "r3: status 200, intended 404"),
    (_request("r4", None, "timeout", intended_status=None), "r4: timeout None"),
    (_request("r5", 200, "ok"), "r5: no intended_status"),
    ("{", "unreadable request log line"),
], ids=["intended_status_missed", "failed", "no_intended_status", "unreadable"])
def test_the_warmup_of_a_v5_session_tells_deliberate_client_errors_from_failures(tmp_path, record, problem):
    from scripts import collection
    good = [{"type": "header"}, _request("r1", 200, "ok", intended_status=None),
            _request("r2", 404, "http_error", intended_status=404), {"type": "phase"}]
    log = tmp_path / "traffic_requests.jsonl"
    log.write_text("".join(json.dumps(r) + "\n" for r in good) + json.dumps(_request("r9", 500, "http_error")))
    assert collection.warmup_failures(tmp_path) == []  # The last line is still being written.
    line = record if type(record) is str else json.dumps(record)
    log.write_text("".join(json.dumps(r) + "\n" for r in good) + line + "\n")
    assert collection.warmup_failures(tmp_path) == [problem]


WARMUP = [_request("r1", 200, "ok", intended_status=None), _request("r2", 404, "http_error", intended_status=404)]


@pytest.mark.parametrize("schema3, status, requests, reason", [
    (True, {"ok": 1, "errors": 1, "logging_error": None}, WARMUP, None),
    (True, {"ok": 1, "errors": 2, "logging_error": None}, [*WARMUP, _request("r3", 502, "http_error",
                                                                            intended_status=None)],
     "warmup traffic failed; r3: http_error 502"),
    (True, {"ok": 0, "errors": 1, "logging_error": None}, WARMUP[1:], "warmup traffic failed"),
    (True, {"ok": 1, "errors": 1, "logging_error": "disk full"}, WARMUP, "warmup traffic failed"),
    (False, {"ok": 1, "errors": 0, "logging_error": None}, [], None),
    (False, {"ok": 1, "errors": 1, "logging_error": None}, [], "warmup traffic failed"),
], ids=["v5_deliberate_errors", "v5_failure", "v5_no_success", "v5_logging_error", "v2_clean", "v2_error"])
def test_the_warmup_check_admits_only_the_deliberate_client_errors_of_a_v5_profile(tmp_path, schema3, status,
                                                                                   requests, reason):
    from scripts import collection
    p = {"schema": "hyptcn3/collection-protocol/" + ("3" if schema3 else "2")}
    (tmp_path / "traffic.json").write_text(json.dumps(status))
    (tmp_path / "traffic_requests.jsonl").write_text("".join(json.dumps(r) + "\n" for r in requests))
    if reason is None:
        assert collection.check_warmup(p, tmp_path) == status
    else:
        with pytest.raises(ValueError) as refused:
            collection.check_warmup(p, tmp_path)
        assert str(refused.value) == reason


def test_the_host_timers_are_recorded_and_never_refuse(monkeypatch):
    from scripts import collection
    answers = {"system": subprocess.CompletedProcess([], 0, "NEXT LEFT LAST PASSED UNIT ACTIVATES\nx.timer\n", ""),
               "user": FileNotFoundError(2, "No such file or directory", "systemctl")}

    def run(command, **kw):
        answer = answers["user" if "--user" in command else "system"]
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(collection.subprocess, "run", run)
    monkeypatch.delenv("SUDO_USER", raising=False)
    timers = collection.host_timers()
    assert timers == {"system": {"command": ["systemctl", "list-timers", "--all", "--no-pager"], "rc": 0,
                                 "lines": ["NEXT LEFT LAST PASSED UNIT ACTIVATES", "x.timer"], "stderr": ""},
                      "user": {"command": ["systemctl", "--user", "list-timers", "--all", "--no-pager"],
                               "error": "FileNotFoundError: [Errno 2] No such file or directory: 'systemctl'"}}
    answers["user"] = subprocess.CompletedProcess([], 1, "", "Failed to connect to bus\n")
    assert collection.host_timers()["user"] == {"command": ["systemctl", "--user", "list-timers", "--all",
                                                            "--no-pager"], "rc": 1, "lines": [],
                                                "stderr": "Failed to connect to bus"}


IDENTITY = {"kernel": "synthetic-kernel", "boot_id": "boot-1", "machine_id": "m", "stack_sha256": "5" * 64,
            "stack_manifest": ["timers: "]}


@pytest.fixture
def host(tmp_path, monkeypatch):
    """Everything run_session touches beyond the protocol and the session directory, faked: the self-test record,
    root, the guest and its QEMU, the disk, the source hashes, the commands it runs and capture_session itself."""
    from scripts import collection
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "symbols.txt").write_text("synthetic profile\n")
    real_digest, real_run, calls, captured = collection.digest, subprocess.run, [], []
    monkeypatch.setattr("scripts.audit_selftest.require_selftest", lambda *a, **k: None)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(collection, "DIAGNOSTICS", tmp_path / "data/diagnostics")
    monkeypatch.setattr(collection, "COLLECTIONS", tmp_path / "data/collections")
    monkeypatch.setattr(collection, "guest_identity", lambda p: dict(IDENTITY))
    monkeypatch.setattr(collection, "lab_sha256", lambda: {"lab/services.py": "0" * 64})
    monkeypatch.setattr(collection, "guest_mismatch", lambda identity, lab: [])
    monkeypatch.setattr(collection, "qemu_process", lambda domain: {"pid": 4242, "start_ticks": 1, "host_boot": "h"})
    monkeypatch.setattr(collection, "host_memory", lambda qemu: {"vm_swappiness": 1, "qemu_swap_kb": 0,
                                                                 "qemu_swap_max": "0"})
    monkeypatch.setattr(collection.shutil, "disk_usage", lambda path: SimpleNamespace(free=1 << 50))
    monkeypatch.setattr(collection, "measurement_sources", lambda: {})
    monkeypatch.setattr(collection, "measurement_dirty", lambda: [])
    monkeypatch.setattr(collection, "storage_identity", lambda path: {"target": "/synthetic"})
    monkeypatch.setattr(collection, "other_vms", lambda p: [])
    monkeypatch.setattr(collection, "digest", lambda path: "0" * 64 if Path(path).name == "vmicollect" else
                        real_digest(path))

    def run(command, **kw):
        if str(command[0]) not in ("make", "virsh", "systemctl"):  # git and uname (check_output) run for real
            return real_run(command, **kw)
        calls.append([str(x) for x in command])
        if "dumpxml" in calls[-1]:
            kw["stdout"].write("<domain/>\n")
            kw["stdout"].close()
        if "list-timers" in calls[-1]:
            return subprocess.CompletedProcess(command, 0, "x.timer\n", "")
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(collection.subprocess, "run", run)
    monkeypatch.setattr(collection, "capture_session", lambda p, out, metadata, cycles: captured.append(
        (out, metadata, cycles)))
    return SimpleNamespace(profile=profile, calls=calls, captured=captured, tmp=tmp_path)


@pytest.mark.parametrize("role", ["diagnostic", "planned"])
def test_session_json_records_the_v5_traffic_block_the_events_and_the_host_timers(host, monkeypatch, role):
    from scripts import collection, gates
    if role == "diagnostic":
        path, p = loaded(host.tmp, v5_doc(profile=host.profile))
        a = args(path, rate=.5, events=json.dumps(EVENTS), collections_dir=host.tmp / "data/diagnostics/trial")
        events, cycles = STATED, 600
    else:
        path, p = loaded(host.tmp, v5_doc(2.5, profile=host.profile))
        monkeypatch.setattr(gates, "require", lambda results, protocol, stage: None)
        s = planned_session(p)
        a = args(path, role=s["role"], group=s["group"], scenario=s["scenario"], seed=s["seed"])
        events, cycles = s["events"], 720
    expected = collection.v5_run(a, p)
    collection.run_session(a, p)
    (out, metadata, captured_cycles), = host.captured
    assert json.loads((out / "session.json").read_text()) == metadata
    assert (metadata["role"], metadata["cycles"], captured_cycles) == (a.role, cycles, cycles)
    assert metadata["traffic"] == expected["traffic"] and metadata["seed"] == a.seed == expected["traffic"]["seeds"][
        "traffic"]
    assert (metadata["events"], metadata["event_grace_s"]) == (events, 60)
    assert all(set(event) == PLAN_KEYS for event in metadata["events"])
    assert metadata["host_context"]["timers"] == {
        "system": {"command": ["systemctl", "list-timers", "--all", "--no-pager"], "rc": 0, "lines": ["x.timer"],
                   "stderr": ""},
        "user": {"command": ["systemctl", "--user", "list-timers", "--all", "--no-pager"], "rc": 0,
                 "lines": ["x.timer"], "stderr": ""}}
    assert (out / "protocol.json").read_bytes() == path.read_bytes()
    # Finding S7 of B3 (F6 of the B5a verification): every file labctl deploys is among the source hashes.
    assert {"lab/periods.json", "lab/hyptcn-lab-udrzba.timer", "lab/dependencies.json"} <= set(metadata["source_sha256"])
    assert out.parent == (host.tmp / "data/diagnostics/trial" if role == "diagnostic"
                          else host.tmp / "data/collections" / collection.STANDALONE / "a")
    assert [call[0] for call in host.calls] == ["make", "systemctl", "systemctl", "virsh"]  # capture_session is faked


def test_a_diagnostic_run_never_becomes_corpus(host):
    """Its directory lies under data/diagnostics, and a planned role's never does."""
    from scripts import collection
    path, p = loaded(host.tmp, v5_doc(profile=host.profile))
    with pytest.raises(ValueError) as refused:
        collection.run_session(args(path, rate=.5, collections_dir=host.tmp / "data/collections"), p)
    assert str(refused.value) == "diagnostic runs (and only they) must use a directory under data/diagnostics"
    assert host.captured == []


def test_the_log_audit_compares_every_key_of_the_planned_events(tmp_path):
    """Under schema 3 session.json lists the plan's items with their phases; a record of events.json that differs
    in any of them differs from the plan (before B5b only type, class, start_s and duration_s were compared)."""
    from scripts import collection_logs as logs
    from scripts.tests import test_collection_logs as evidence
    d = evidence.build(tmp_path, event=True)
    meta, doc = logs.read_json(d / "session.json"), logs.read_json(d / "events.json")
    phases = {"start_phase_s": 0.0, "stop_phase_s": 1.0}
    meta["events"] = [dict(meta["events"][0], **phases)]
    doc["events"] = [dict(doc["events"][0], **phases)]
    evidence.write(d / "session.json", meta)
    evidence.write(d / "events.json", doc)
    evidence.seal(d)
    assert logs.audit_logs(d)["accepted"]
    doc["events"][0]["stop_phase_s"] = 2.0
    evidence.write(d / "events.json", doc)
    evidence.seal(d)
    result = logs.audit_logs(d)
    assert result["problem_counts"] == {"events_differ_from_plan": 1}
