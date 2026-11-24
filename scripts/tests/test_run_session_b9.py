"""`collection.py run` under protocol schema 3 in package B9 (design B9a section 1.2): the plan and the attempt.

A session of a planned role names the plan it belongs to and its attempt, --mode campaign|rehearsal and --attempt N,
both required with no default, both refused for a diagnostic run and under schemas 1 and 2. Attempt 1 is the planned
session of protocol_v5.plan(p, mode), attempt N >= 2 protocol_v5.replacement of it: --seed is that attempt's seed,
and its events, controls and traffic seeds are the attempt's. The readiness records depend on the mode: G0 to G4
for the campaign (gates.require of G5), G0 to G2 for the rehearsal (G3a). session.json records the attempt and the
plan's mode. Every session under schema 3 reads the guest's levels at its start (proposal 5.4), with the names of
the loaded modules (finding S2 of B8). Fakes only: no VM, no labctl call, no sudo. Names package B9 adds are read
inside the tests, so this file collects on the code before B9.
"""
import json
from pathlib import Path
import subprocess

import pytest

from scripts.tests.test_run_session_v5 import args, host, loaded, v5_doc  # noqa: F401 - host is a fixture

ROOT = Path(__file__).resolve().parents[2]
NEEDS = "a session of a planned role needs "
ATTEMPTS = "1 for the planned session, 2 or later for a replacement (protocol_v5.replacement)"
PLANNED_ONLY = " is only allowed for a session of a planned role under protocol schema 3"
LEVELS = {"schema": "hyptcn3/guest-levels/1", "processes": 101, "meminfo_kb": {"MemAvailable": 1500000},
          "modules": ["fuse", "virtio_net"]}


def planned(p, role, mode="campaign", events=True):
    """The first planned session of `role` on VM a in the plan of `mode`, one with events (or with controls)."""
    from scripts import protocol_v5
    return next(s for s in protocol_v5.plan(p, mode=mode)["sessions"]
                if s["role"] == role and s["vm"] == p["vm"] and (bool(s.get("events")) or not events))


def namespace(path, s, **changes):
    """The namespace of `run` for the planned session `s`."""
    return args(path, role=s["role"], group=s["group"], scenario=s["scenario"], seed=s["seed"], **changes)


def untouched(monkeypatch):
    """What run_session touches after the self-test and root, faked to a record; the list of what was touched."""
    from scripts import collection
    touched = []
    monkeypatch.setattr("scripts.audit_selftest.require_selftest", lambda *a, **k: None)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    for name in ("guest_identity", "qemu_process", "collection_lock", "lab_json"):
        monkeypatch.setattr(collection, name, lambda *a, _name=name, **kw: touched.append(_name))
    return touched


@pytest.mark.parametrize("change, reason", [
    ({"mode": None}, NEEDS + "--mode (campaign or rehearsal, the plan the session belongs to)"),
    ({"attempt": None}, NEEDS + f"--attempt ({ATTEMPTS})"),
    ({"mode": "pilot"}, "invalid --mode: campaign or rehearsal"),
    ({"attempt": 0}, "invalid --attempt: " + ATTEMPTS),
], ids=["no_mode", "no_attempt", "unknown_mode", "attempt_0"])
def test_a_planned_session_names_its_mode_and_attempt_before_anything_is_touched(tmp_path, monkeypatch, change,
                                                                                 reason):
    """Refused by name (no default) right after the self-test and root, before any guest access and before a
    directory exists, like the other arguments v5_arguments decides alone."""
    from scripts import collection
    path, p = loaded(tmp_path, v5_doc(2.5))
    touched = untouched(monkeypatch)
    a = namespace(path, planned(p, "train"), collections_dir=tmp_path / "collections", **change)
    with pytest.raises(ValueError) as refused:
        collection.run_session(a, p)
    assert str(refused.value) == reason
    assert touched == [] and not (tmp_path / "collections").exists()


@pytest.mark.parametrize("flag", ["mode", "attempt"])
@pytest.mark.parametrize("schema", [3, 2])
def test_mode_and_attempt_are_refused_for_a_diagnostic_run_and_under_schemas_1_and_2(tmp_path, monkeypatch, flag,
                                                                                    schema):
    """A diagnostic run has no planned session; schemas 1 and 2 have no plan modes and no attempts."""
    from scripts import collection
    touched = untouched(monkeypatch)
    monkeypatch.setattr(collection, "COLLECTIONS", tmp_path / "collections")
    value = {"mode": "campaign", "attempt": 1}[flag]
    if schema == 3:
        path, p = loaded(tmp_path, v5_doc())
        a = args(path, rate=.5, collections_dir=tmp_path / "diagnostics", **{flag: value})
    else:
        path, p = collection.DEFAULT, collection.protocol(collection.DEFAULT)
        a = args(path, role="train", scenario="steady", group="train-1", vm=None,
                 **dict({"mode": None, "attempt": None}, **{flag: value}))
    with pytest.raises(ValueError) as refused:
        collection.run_session(a, p)
    assert str(refused.value) == "--" + flag + PLANNED_ONLY and touched == []


@pytest.mark.parametrize("role", ["train", "test_controls"])
def test_attempt_1_is_the_planned_session_and_attempt_n_its_replacement(tmp_path, monkeypatch, role):
    """The same checks for both: the attempt's seed, a seed for every traffic purpose, its events and controls as it
    states them. A replacement keeps the types or kinds and draws new times and traffic seeds (protocol_v5)."""
    from scripts import collection, gates, protocol_v5
    path, p = loaded(tmp_path, v5_doc(2.5))
    monkeypatch.setattr(gates, "require", lambda results, protocol, stage: None)
    s = planned(p, role, events=role != "test_controls")
    third = protocol_v5.replacement(p, s, 3, mode="campaign")
    field = "controls" if role == "test_controls" else "events"
    for attempt, session in ((1, s), (3, third)):
        run = collection.v5_run(namespace(path, session, attempt=attempt), p)
        assert (run["plan_mode"], run["attempt"]) == ("campaign", attempt)
        assert run[field] == [x for x in session[field] if x.get("kind", "") is not None]
        assert run["traffic"]["seeds"] == {name: value for name, value in session["seeds"].items()
                                           if name in collection.traffic_purposes()}
        assert run["traffic"]["seeds"]["traffic"] == session["seed"]
    assert third["seed"] != s["seed"] and run[field] != [x for x in s[field] if x.get("kind", "") is not None]
    for attempt, seed in ((2, s["seed"]), (1, third["seed"])):  # The plan's seed is not attempt 2's, nor the reverse.
        with pytest.raises(ValueError) as refused:
            collection.v5_run(namespace(path, dict(s, seed=seed), attempt=attempt), p)
        assert str(refused.value) == "assignment/seed not present in frozen collection plan" + (
            " as attempt 2 of a planned session" if attempt == 2 else "")


@pytest.mark.parametrize("mode, stage, reason", [
    ("campaign", "G5", "a session of a planned role needs valid readiness records up to G4: "),
    ("rehearsal", "G3a", "a session of the rehearsal needs valid readiness records up to G2: "),
])
def test_the_plan_and_the_readiness_records_follow_the_mode(tmp_path, monkeypatch, mode, stage, reason):
    """The rehearsal's sessions are those of protocol_v5.plan(p, "rehearsal"), under its prefix; a group of one mode
    is not planned in the other. The campaign needs valid records of G0 to G4, the rehearsal of G0 to G2."""
    from scripts import collection, gates
    path, p = loaded(tmp_path, v5_doc(2.5))
    s = planned(p, "test_benign", mode)
    other = planned(p, "test_benign", "rehearsal" if mode == "campaign" else "campaign")
    assert s["group"].startswith(p["group_prefix"] if mode == "campaign" else p["rehearsal"]["group_prefix"])
    required = []
    monkeypatch.setattr(gates, "require", lambda results, protocol, wanted: required.append((results, protocol,
                                                                                             wanted)))
    run = collection.v5_run(namespace(path, s, mode=mode), p)
    assert required == [(gates.ROOT / "data/results", path, stage)] and run["events"] == s["events"]
    assert (run["plan_mode"], run["attempt"]) == (mode, 1)
    with pytest.raises(ValueError) as refused:
        collection.v5_run(namespace(path, other, mode=mode), p)
    assert str(refused.value) == "assignment/seed not present in frozen collection plan"
    monkeypatch.undo()
    monkeypatch.setattr(gates, "ROOT", tmp_path)  # No readiness record below tmp_path/data/results.
    with pytest.raises(ValueError) as refused:
        collection.v5_run(namespace(path, s, mode=mode), p)
    assert str(refused.value) == reason + "stage G0 is not valid: no record"


@pytest.mark.parametrize("mode, attempt", [("campaign", 1), ("rehearsal", 2)])
def test_session_json_records_the_attempt_and_the_plan_mode(host, monkeypatch, mode, attempt):
    """With the attempt's own seed and events; both names are metadata, never model inputs. A diagnostic run, which
    has no planned session, records neither."""
    from scripts import collection, gates, protocol_v5
    path, p = loaded(host.tmp, v5_doc(2.5, profile=host.profile))
    monkeypatch.setattr(gates, "require", lambda results, protocol, stage: None)
    s = planned(p, "train", mode)
    session = s if attempt == 1 else protocol_v5.replacement(p, s, attempt, mode=mode)
    collection.run_session(namespace(path, session, mode=mode, attempt=attempt), p)
    (out, metadata, cycles), = host.captured
    assert json.loads((out / "session.json").read_text()) == metadata
    assert (metadata["attempt"], metadata["plan_mode"], metadata["seed"]) == (attempt, mode, session["seed"])
    assert metadata["events"] == session["events"] and metadata["group"] == s["group"]
    assert {"attempt", "plan_mode"} <= set(metadata["metadata_not_model_inputs"])
    path, p = loaded(host.tmp, v5_doc(profile=host.profile))
    collection.run_session(args(path, rate=.5, collections_dir=host.tmp / "data/diagnostics/trial"), p)
    assert not {"attempt", "plan_mode"} & set(host.captured[-1][1])


@pytest.mark.parametrize("role", ["train", "test_controls"])
def test_every_session_under_schema_3_reads_its_starting_levels(tmp_path, monkeypatch, role):
    """Proposal 5.4 and skeleton B9 row "začiatok bootu": the levels at the start of each session, in its preflight
    after the guest state (as for test_controls since B8), written to guest/levels_before.json and counted in the step
    record, modules included. The capture is stopped at the next guest call."""
    from scripts import collection

    class Stop(Exception):
        pass
    _, p = loaded(tmp_path, v5_doc(2.5))
    out = tmp_path / "session-1"
    out.mkdir()
    metadata = {"events": [], "event_grace_s": 60, "host_context": {"qemu": {"pid": 4242}},
                **({"controls": []} if role == "test_controls" else {})}
    calls = []

    def lab_json(p, *arguments, timeout=600):
        calls.append(arguments[0])
        if arguments[0] == "segment":
            raise Stop
        return {"clock": {"offset_s": 0.}, "state": {"schema": "hyptcn3/guest-state/1"}, "levels": LEVELS}[
            arguments[0]]
    monkeypatch.setattr(collection, "lab_json", lab_json)
    monkeypatch.setattr(collection.subprocess, "run", lambda command, **kw: subprocess.CompletedProcess(command, 0,
                                                                                                         "", ""))
    monkeypatch.setattr(collection, "foreign_traffic", lambda p, exclude=(): [])
    monkeypatch.setattr(collection, "collectors", lambda domain: [])
    monkeypatch.setattr(collection, "wait_healthy", lambda target: 1)
    for name in ("SUDO_UID", "SUDO_GID", "SUDO_USER"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(Stop):
        collection.capture_session(p, out, metadata, 720)
    assert calls == ["clock", "state", "levels", "segment"]
    assert json.loads((out / "guest/levels_before.json").read_text()) == LEVELS
    step = json.loads((out / "end.json").read_text())["steps"]["levels"]
    assert {key: value for key, value in step.items() if key != "unix"} == {"processes": 101, "modules": 2}
