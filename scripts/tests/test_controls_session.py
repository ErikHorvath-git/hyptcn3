"""The host side of the controls on the VM (protocol v5, package B8; design B8 section 3, skeleton B8 section 5).

labctl runs a control with the guest's command line of design B8 1.3 and keeps the guest's return predicate, effect
and cleanup in its reply, a malformed one as false; its options for a control belong together, and up and
traffic-start require the protocol the lab serves (finding F5 of the B5b verification). The runner plans a session of
role test_controls (`run --role test_controls`), records its planned controls in session.json and runs them like
the events (collection.Controls), writing controls.json. The log audit of such a session reads only whether each
occurrence ran and the guest's three predicates (design B8 1.4): the clean session passes, a control not executed,
without the return predicate or without its effect and a negative with its property are refused with their exact
reasons (skeleton section 5 item 4), and once controls.baseline is measured the level part must have been judged.
Fakes only: no VM, no labctl call, no sudo. Names package B8 adds are read inside the tests, so this file collects on
the code before B8.
"""
import json
from pathlib import Path
import shlex
import subprocess
from types import SimpleNamespace

import pytest

from scripts import collection, labctl
from scripts.tests import boundary_sessions as bs
from scripts.tests import test_collection_logs as evidence
from scripts.tests.test_run_session_v5 import args, host, loaded, v5_doc  # noqa: F401 - host is a fixture

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
WRITER, WX = "kontrola_zapisovac_pamate", "kontrola_wx_memfd"
LEVELS = {"schema": "hyptcn3/guest-levels/1", "processes": 101, "meminfo_kb": {"MemAvailable": 1500000}}
UNJUDGED = {"judged": False, "why": "controls.baseline null until G2"}
BASELINE = {"ok": True, "exact": {"ok": True, "residues": []}, "level": UNJUDGED, "evidence": []}
EFFECT = {"ok": True, "predicate": "the writer holds the dose", "evidence": {"members": [41, 42]}}
CLEANUP = {"ok": True, "residues": [], "evidence": []}
PLAN_KEYS = {"kind", "polarity", "class", "dose", "start_s", "duration_s", "start_phase_s", "stop_phase_s"}


def guest_reply(kind, action, **fields):
    """A reply of lab/udalosti.py for a control (schema hyptcn3/lab-event/1 with the fields of design B8 1.3)."""
    return {"schema": "hyptcn3/lab-event/1", "type": kind, "action": action, "ok": True, "error": None,
            "guest_started_unix": 1., "guest_finished_unix": 2., "background_pid": 4321, "health": 200, "units": {},
            "script_sha256": "5" * 64, **fields}


# labctl: the guest's command line of a control and its reply (design B8 1.3 and 1.4).

def test_labctl_runs_a_control_with_the_guests_command_line_and_keeps_its_predicates(monkeypatch):
    commands, replies = [], {
        "start": guest_reply(WRITER, "start", polarity="negative", dose=64, baseline=BASELINE, started=True),
        "stop": guest_reply(WRITER, "stop", polarity="negative", dose=64, effect=EFFECT, cleanup=CLEANUP)}

    def guest(self, command, timeout=120):
        commands.append(shlex.split(command))
        return json.dumps(replies[commands[-1][2]])
    monkeypatch.setattr(labctl.Lab, "guest", guest)
    lab = labctl.Lab()
    start = lab.event("start", WRITER, polarity="negative", dose=64, levels=LEVELS, tolerance=None)
    stop = lab.event("stop", WRITER, polarity="negative", dose=64)
    tolerance = {"processes": [-5, 5], "MemAvailable_kb": [-1000, 1000]}
    lab.event("start", WX, polarity="control", levels=LEVELS, tolerance=tolerance)
    udalosti = ["python3", "/opt/hyptcn-lab/udalosti.py"]
    assert commands == [
        [*udalosti, "start", WRITER, "--polarity", "negative", "--dose", "64", "--levels",
         json.dumps(LEVELS, sort_keys=True), "--tolerance", "null"],
        [*udalosti, "stop", WRITER, "--polarity", "negative", "--dose", "64"],
        [*udalosti, "start", WX, "--polarity", "control", "--levels", json.dumps(LEVELS, sort_keys=True),
         "--tolerance", json.dumps(tolerance)]]
    names = {"kind": WRITER, "polarity": "negative", "dose": 64, "class": "control_negative"}
    assert start == {**replies["start"], **names} and stop == {**replies["stop"], **names}
    assert labctl.CONTROL_CLASS == collection.protocol_v5.CONTROL_RECORD_CLASS


@pytest.mark.parametrize("action, key, value", [
    ("start", "baseline", None),
    ("start", "baseline", dict(BASELINE, exact={"ok": False, "residues": [{"residue": "module", "name": "crc7"}]})),
    ("start", "baseline", dict(BASELINE, level={"judged": True})),
    ("stop", "effect", {"ok": "yes", "evidence": {}}),
    ("stop", "cleanup", None),
    ("stop", "cleanup", {"ok": True, "residues": []}),
], ids=["no_baseline", "ok_against_its_exact_part", "judged_without_ok", "effect_ok_not_boolean", "no_cleanup",
        "cleanup_without_evidence"])
def test_a_malformed_predicate_of_a_control_is_kept_as_a_false_one(monkeypatch, action, key, value):
    """The record never claims a return to the baseline, an effect or a cleanup the guest did not report."""
    reply = guest_reply(WX, action, polarity="control", dose=None, started=True)
    reply.update({"effect": EFFECT, "cleanup": CLEANUP} if action == "stop" else {"baseline": BASELINE})
    reply[key] = value
    monkeypatch.setattr(labctl.Lab, "guest", lambda self, command, timeout=120: json.dumps(reply))
    record = labctl.Lab().event(action, WX, polarity="control",
                                **({"levels": LEVELS, "tolerance": None} if action == "start" else {}))
    assert record[key]["ok"] is False and record[key]["evidence"]["guest_" + key] == value


@pytest.mark.parametrize("options, message", [
    (["--event", "stop", "naprazdno", "--dose", "16"],
     "--dose, --levels and --tolerance belong to the event of a control (--polarity)"),
    (["--event", "stop", WX, "--polarity", "control", "--levels", "{}", "--tolerance", "null"],
     "--levels and --tolerance belong to the start of a control, and it needs both"),
    (["--event", "start", WX, "--polarity", "control", "--levels", "{}"],
     "--levels and --tolerance belong to the start of a control, and it needs both"),
    (["--event", "start", WX, "--polarity", "control", "--levels", "[]", "--tolerance", "null"],
     "--levels is a JSON object (guest_state.py levels) and --tolerance null or an object"),
    (["--event", "start", WX, "--polarity", "control", "--levels", "{", "--tolerance", "null"],
     "--levels and --tolerance are JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"),
    (["--event", "start", WRITER, "--polarity", "control", "--dose", "0", "--levels", "{}", "--tolerance", "null"],
     "--dose is a positive number"),
], ids=["dose_of_an_event", "levels_at_a_stop", "start_without_tolerance", "levels_not_an_object", "levels_not_json",
        "dose_not_positive"])
def test_the_options_of_a_control_belong_together(monkeypatch, capsys, options, message):
    """Usage errors before the VM is touched."""
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: pytest.fail("the VM was touched"))
    with pytest.raises(SystemExit) as stopped:
        labctl.main(["event", *options])
    assert stopped.value.code == 2 and capsys.readouterr().err.rstrip().endswith("error: " + message)


def test_the_event_command_of_a_control_prints_its_record(monkeypatch, capsys):
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: None)
    calls = []
    monkeypatch.setattr(labctl.Lab, "event", lambda self, *a, **k: calls.append((a, k)) or {"ok": True})
    labctl.main(["event", "--event", "start", WRITER, "--polarity", "control", "--dose", "256", "--levels",
                 json.dumps(LEVELS), "--tolerance", "null"])
    assert calls == [(("start", WRITER), {"polarity": "control", "dose": 256, "levels": LEVELS, "tolerance": None})]
    assert json.loads(capsys.readouterr().out) == {"ok": True}
    labctl.main(["event", "--event", "stop", "restart_databazy"])  # An event keeps its command line.
    assert calls[-1] == (("stop", "restart_databazy"), {})


def test_the_levels_command_prints_the_guests_levels(monkeypatch, capsys):
    """The session's starting levels the controls start against (lab/guest_state.py levels)."""
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: None)
    calls = []
    monkeypatch.setattr(labctl.Lab, "helper", lambda self, *a, timeout=600: calls.append(a) or LEVELS)
    labctl.main(["levels"])
    assert calls == [("levels",)] and json.loads(capsys.readouterr().out) == LEVELS


@pytest.mark.parametrize("command", ["up", "traffic-start"])
def test_up_and_traffic_start_require_the_protocol_the_lab_serves(monkeypatch, capsys, command):
    """Finding F5 of the B5b verification: without --protocol the old generator unit would start under v5 as well."""
    steps = []
    for name in ("clone", "start", "swap_step", "deploy", "health", "traffic"):
        monkeypatch.setattr(labctl.Lab, name, lambda self, *a, name=name: steps.append(name))
    with pytest.raises(SystemExit) as stopped:
        labctl.main([command])
    assert stopped.value.code == 2 and steps == []
    assert capsys.readouterr().err.rstrip().endswith(f"error: {command} requires --protocol (the protocol the lab "
                                                     "serves)")
    labctl.main([command, "--protocol", str(ROOT / "config/collection-v2.json")])
    assert steps[-1] == "traffic"


def test_make_lab_up_passes_the_protocol_of_the_default_lab():
    """The Makefile names the schema-2 protocol of the one lab VM labctl defaults to (hyptcn-lab, port 18080)."""
    lines = (ROOT / "Makefile").read_text().split("lab-up:\n", 1)[1].splitlines()
    assert lines[0].split() == ["python3", "scripts/labctl.py", "up", "--protocol", "config/collection-v2.json"]
    protocol = json.loads((ROOT / "config/collection-v2.json").read_text())
    assert (protocol["schema"], protocol["domain"], protocol["target"]) == (
        "hyptcn3/collection-protocol/2", "hyptcn-lab", f"http://127.0.0.1:{labctl.PORT}")


# The runner: a session of role test_controls (design B8 section 3).

def _control_session(p):
    """The first planned session of role test_controls on VM a whose deck left a slot empty."""
    return next(s for s in collection.plan(p)["sessions"] if s["role"] == "test_controls" and s["vm"] == p["vm"]
                and any(x["kind"] is None for x in s["controls"]))


def test_run_accepts_the_role_test_controls(monkeypatch):
    seen = []
    monkeypatch.setattr(collection, "run_session", lambda a, p: seen.append((a.role, p.get("vm"))))
    assert collection.main(["--protocol", str(V5), "run", "--role", "test_controls", "--scenario", "eshop_low",
                            "--group", "v5-test_controls-1", "--vm", "a", "--seed", "1"]) == 0
    assert seen == [("test_controls", "a")]


def test_a_planned_session_of_test_controls_runs_its_planned_controls(tmp_path, monkeypatch):
    """v5_run: the plan's controls of the session as they are (kind, polarity, class, dose, times), the slot the deck
    left empty out, and no event."""
    from scripts import gates
    path, p = loaded(tmp_path, v5_doc(2.5))
    s = _control_session(p)
    monkeypatch.setattr(gates, "require", lambda results, protocol, stage: None)
    run = collection.v5_run(args(path, role=s["role"], group=s["group"], scenario=s["scenario"], seed=s["seed"]), p)
    assert run["events"] == [] and run["controls"] == [x for x in s["controls"] if x["kind"] is not None]
    assert len(run["controls"]) == 2 and all(set(x) == PLAN_KEYS for x in run["controls"])


def test_session_json_records_the_planned_controls(host, monkeypatch):
    from scripts import gates
    path, p = loaded(host.tmp, v5_doc(2.5, profile=host.profile))
    monkeypatch.setattr(gates, "require", lambda results, protocol, stage: None)
    s = _control_session(p)
    collection.run_session(args(path, role=s["role"], group=s["group"], scenario=s["scenario"], seed=s["seed"]), p)
    (out, metadata, cycles), = host.captured
    assert json.loads((out / "session.json").read_text()) == metadata
    assert (metadata["role"], metadata["events"], cycles) == ("test_controls", [], 720)
    assert metadata["controls"] == [x for x in s["controls"] if x["kind"] is not None]
    assert "controls" in metadata["metadata_not_model_inputs"]


ITEMS = [{"kind": WX, "polarity": "control", "class": "A", "dose": None, "start_s": 10., "duration_s": 3.,
          "start_phase_s": 0., "stop_phase_s": 3.},
         {"kind": WRITER, "polarity": "negative", "class": "B", "dose": 64, "start_s": 20., "duration_s": 3.,
          "start_phase_s": 0., "stop_phase_s": 3.}]


class Lab:
    """labctl as the runner calls it (collection.lab_json), faked with a clock: the reply of a start and of a stop
    from start(kind) and stop(kind) where given, else the guest's faultless one."""

    def __init__(self, monkeypatch, start=None, stop=None):
        self.calls, self.clock = [], [1000.]
        self.start, self.stop = start, stop
        monkeypatch.setattr(collection, "lab_json", self.call)
        monkeypatch.setattr(collection, "time", SimpleNamespace(time=lambda: self.clock[0]))

    def call(self, p, *arguments, timeout=600):
        self.calls.append(list(arguments))
        action, kind = arguments[2], arguments[3]
        if action == "start":
            return self.start(kind) if self.start else guest_reply(kind, "start", baseline=BASELINE, started=True)
        return self.stop(kind) if self.stop else guest_reply(kind, "stop", effect=EFFECT, cleanup=CLEANUP)

    def run(self, controls, *times):
        for t in times:
            self.clock[0] = t
            controls.tick(1000.)


def test_the_runner_starts_and_stops_each_control_with_the_sessions_levels(tmp_path, monkeypatch):
    """Like the events: one at a time, at start_s and start_s + duration_s after the measurement starts; the start
    with the session's starting levels and the protocol's tolerance (null until G2), a dose for class B only. The
    record of controls.json (design B8 1.4): the plan's item with its class A or B as kind_class, the occurrence's
    class, executed, the host times, labctl's replies and the guest's baseline, effect and cleanup at its top."""
    p = collection.for_vm(collection.protocol(V5), "a")
    lab, steps = Lab(monkeypatch), []
    controls = collection.Controls(p, ITEMS, lambda name, **values: steps.append((name, values)), levels=LEVELS)
    lab.run(controls, 1005, 1010, 1012, 1013, 1014, 1020, 1023)
    controls.close(tmp_path / "controls.json")
    levels = json.dumps(LEVELS, sort_keys=True)
    assert lab.calls == [
        ["event", "--event", "start", WX, "--polarity", "control", "--levels", levels, "--tolerance", "null"],
        ["event", "--event", "stop", WX, "--polarity", "control"],
        ["event", "--event", "start", WRITER, "--polarity", "negative", "--dose", "64", "--levels", levels,
         "--tolerance", "null"],
        ["event", "--event", "stop", WRITER, "--polarity", "negative", "--dose", "64"]]
    doc = json.loads((tmp_path / "controls.json").read_text())
    assert doc["schema"] == "hyptcn3/session-controls/1"
    for item, record, (start, stop) in zip(ITEMS, doc["controls"], ((1010, 1013), (1020, 1023))):
        assert record == {**{k: v for k, v in item.items() if k != "class"}, "kind_class": item["class"],
                          "class": "control" if item["polarity"] == "control" else "control_negative",
                          "executed": True, "host_start_unix": start, "host_started_unix": start,
                          "host_stop_unix": stop, "host_stopped_unix": stop,
                          "start": guest_reply(item["kind"], "start", baseline=BASELINE, started=True),
                          "stop": guest_reply(item["kind"], "stop", effect=EFFECT, cleanup=CLEANUP),
                          "baseline": BASELINE, "effect": EFFECT, "cleanup": CLEANUP}
    assert [name for name, _ in steps] == ["control-start", "control-stop"] * 2


def test_a_control_the_guest_refuses_to_start_is_stopped_at_once_and_not_executed(tmp_path, monkeypatch):
    """Skeleton B8 section 3: without the return predicate nothing starts, nothing waits and nothing is retried; the
    stop still runs (as after a failed event start) and the record keeps the refused baseline."""
    refused = dict(BASELINE, ok=False, exact={"ok": False, "residues": [{"residue": "unit", "unit": "x.service"}]},
                   evidence=["unit x.service is failed"])
    p = collection.for_vm(collection.protocol(V5), "a")
    lab = Lab(monkeypatch, start=lambda kind: guest_reply(kind, "start", ok=False, baseline=refused, started=False,
                                                          error="the return predicate does not hold"))
    controls = collection.Controls(p, ITEMS[:1], lambda name, **values: None, levels=LEVELS)
    lab.run(controls, 1010)
    assert [call[2] for call in lab.calls] == ["start", "stop"] and controls.active is None
    record = controls.records[0]
    assert (record["executed"], record["baseline"], record["host_stop_unix"]) == (False, refused, 1010)


@pytest.mark.parametrize("stop, executed, raised", [
    (lambda kind: guest_reply(kind, "stop", effect=EFFECT, cleanup=CLEANUP, health=502), False,
     "lab not restored after control kontrola_wx_memfd"),
    (lambda kind: {"ok": False, "error": "CalledProcessError: Command 'labctl' returned non-zero exit status 1."},
     False, "lab not restored after control kontrola_wx_memfd"),
], ids=["unhealthy_after_stop", "stop_call_failed"])
def test_a_stop_that_does_not_restore_the_lab_ends_the_capture(monkeypatch, stop, executed, raised):
    p = collection.for_vm(collection.protocol(V5), "a")
    lab = Lab(monkeypatch, stop=stop)
    controls = collection.Controls(p, ITEMS[:1], lambda name, **values: None, levels=LEVELS)
    lab.run(controls, 1010)
    with pytest.raises(ValueError) as failed:
        lab.run(controls, 1013)
    assert str(failed.value) == raised and controls.records[0]["executed"] is executed


def test_a_failed_labctl_call_is_recorded_and_the_control_stopped(monkeypatch):
    p = collection.for_vm(collection.protocol(V5), "a")
    lab = Lab(monkeypatch)

    def failing(kind):
        raise subprocess.CalledProcessError(1, ["labctl"])
    lab.start = failing
    controls = collection.Controls(p, ITEMS[:1], lambda name, **values: None, levels=LEVELS)
    lab.run(controls, 1010)
    record = controls.records[0]
    assert record["start"] == {"ok": False, "error": "CalledProcessError: Command '['labctl']' returned non-zero exit "
                                                     "status 1."}
    assert (record["baseline"], record["executed"], record["effect"]) == (None, False, EFFECT)


# The log audit of a session of test_controls (design B8 1.4; skeleton section 5 item 4).

@pytest.fixture(scope="module")
def v5():
    return collection.protocol(V5), V5


def test_the_clean_session_of_test_controls_is_accepted(v5, tmp_path):
    """A control of class A and a negative of class B that ran faultlessly; the guest's health polls without request
    id inside their start and stop calls are admitted as inside an event window. One more poll 5 s after the last
    call is not."""
    from scripts.tests.audit_cases_logs import controls_session
    p, path = v5
    session = controls_session(tmp_path, p, path, "controls-clean")
    audit = bs.audit(session, p)
    assert (audit.code, audit.values["reasons"]) == (0, [])
    logs = audit.values["logs"]
    assert (logs["sections"]["controls"]["controls"], logs["sections"]["controls"]["executed"]) == (2, 2)
    assert len(logs["sections"]["controls"]["calls"]) == 4 and logs["tolerated"]["event_window_health_checks"] == 6
    assert logs["sections"]["correlation"]["tolerated_in_events"] == {"control_health_checks": 6}
    d = session.directory
    last = json.loads((d / "controls.json").read_text())["controls"][-1]["host_stopped_unix"]
    evidence._append_segment(d, "session", "nginx-access.jsonl", [json.dumps(
        {"schema": "hyptcn3/nginx-access/1", "rid": "", "forwarded_rid": "x", "method": "GET", "uri": "/healthz",
         "status": 200, "msec": last + 5}) + "\n"])
    evidence.seal(d)
    audit = bs.audit(session, p, output=d / "audit-2.json")
    assert (audit.code, audit.values["reasons"]) == (2, ["logs: nginx_unknown_request:"])


def _session_json(change):
    def mutate(d, p, result):
        meta = json.loads((d / "session.json").read_text())
        change(meta)
        evidence.write(d / "session.json", meta)
    return mutate


@pytest.mark.parametrize("case_id, reasons", [
    ("logs:control_not_executed", ["logs: control_not_executed:kontrola_wx_memfd"]),
    ("logs:control_without_baseline", ["logs: control_without_baseline:kontrola_wx_memfd"]),
    ("logs:control_without_effect", ["logs: control_without_effect:kontrola_wx_memfd"]),
    ("logs:negative_with_property", ["logs: negative_with_property:kontrola_zapisovac_pamate"]),
    (_session_json(lambda meta: meta.pop("controls")),
     ["logs: controls:unreadable:KeyError: 'controls'", "logs: nginx_unknown_request:"]),
], ids=["not_executed", "without_baseline", "without_effect", "negative_with_property", "role_without_controls"])
def test_a_session_of_test_controls_is_refused_with_its_exact_reason(v5, tmp_path, case_id, reasons):
    """Skeleton B8 section 5 item 4 under the real protocol file (the self-test runs every case of the controls
    section under its small protocol): one fault at a time, each refused with exactly its reason. A session of the
    role whose session.json lists no controls fails the section (and its calls admit no health poll)."""
    from scripts.tests import audit_cases
    from scripts.tests.audit_case import Case
    from scripts.tests.audit_cases_logs import CONTROL_CASES, controls_session
    p, path = v5
    case = ({c.id: c for c in CONTROL_CASES}[case_id] if type(case_id) is str
            else Case("role_without_controls", "controls:unreadable", reasons, case_id, controls_session))
    audit = audit_cases.run_case(tmp_path, p, path, case)
    assert (audit.code, audit.values["reasons"]) == (2, reasons)


@pytest.mark.parametrize("judged", [False, True], ids=["level_not_judged", "level_judged"])
def test_with_a_measured_tolerance_the_level_part_must_have_been_judged(tmp_path, judged):
    """Design B8 1.3: once controls.baseline holds the bands G2 measured, an occurrence whose return predicate did not
    judge the level part is refused as one without the return predicate."""
    from scripts.tests.audit_cases_logs import controls_session
    doc = json.loads(V5.read_text())
    doc["controls"]["baseline"] = {"processes": [-50, 50], "MemAvailable_kb": [-500000, 500000]}
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(doc, indent=2))
    p = collection.protocol(path)
    session = controls_session(tmp_path / "s", p, path, "controls")
    d = session.directory
    if judged:
        part = {"start": 101, "now": 102, "change": 1, "tolerance": [-50, 50], "ok": True}
        level = {"judged": True, "processes": part, "MemAvailable_kb": dict(part, tolerance=[-500000, 500000]),
                 "ok": True}
        records = json.loads((d / "controls.json").read_text())
        for record in records["controls"]:
            record["baseline"]["level"] = record["start"]["baseline"]["level"] = level
        evidence.write(d / "controls.json", records)
        evidence.seal(d)
    audit = bs.audit(session, p)
    assert (audit.code, audit.values["reasons"]) == ((0, []) if judged else (2, [
        "logs: control_without_baseline:kontrola_wx_memfd",
        "logs: control_without_baseline:kontrola_zapisovac_pamate"]))
