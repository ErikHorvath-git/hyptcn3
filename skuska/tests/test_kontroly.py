"""The draw of the controls of G2, the wrapper of Q46 and the block with controls (skuska/kontroly.py, package H1b2).

Fakes of every lab and root step: no test touches a VM, runs as root, uses the network or writes outside tmp_path
(checked after every test for data/results, data/diagnostics, data/collections and docs/MERANIA.md). The protocol is
config/collection-v5.json as it stands (the rates of Zápis 1, controls.baseline null until Zápis 2): neither the draw
nor a test needs the baseline's value; the block that runs sessions gets a synthetic band. The lead's test of equality
(his condition on Q46) builds the campaign's arguments through the campaign's own code path: the real
scripts/campaign.py on the fakes of scripts/tests/kampan_v5.py, its command line parsed by collection.py's own parser
and planned by collection.v5_run.
"""
import copy
import hashlib
import json
from pathlib import Path
import random
import re
import sys

import pytest

from scripts import collection, protocol_v5
from scripts.tests.test_run_session_v5 import IDENTITY, host, loaded  # noqa: F401 - host is a fixture
from skuska import g2, kontroly
from skuska.tests.test_g2 import FakeLab

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
P = collection.protocol(REAL)
KINDS = sorted(P["controls"]["kinds"])
QEMU = {"pid": 4242, "start_ticks": 1, "host_boot": "h"}  # scripts/tests/test_run_session_v5.py host: qemu_process.
BAND = {"processes": [-50, 50], "MemAvailable_kb": [-500000, 500000]}  # A synthetic band, not the G2 value.
WATCHED = [ROOT / "data/results", ROOT / "data/diagnostics", ROOT / "data/collections"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def listing(path):
    return sorted(str(p.relative_to(path)) for p in path.rglob("*")) if path.exists() else None


@pytest.fixture(autouse=True)
def _repository_unchanged():
    """No test leaves a file in data/results, data/diagnostics or data/collections, or changes docs/MERANIA.md."""
    before = {path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")
    yield
    assert ({path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")) == before


@pytest.fixture(scope="module")
def draw():
    return kontroly.draw_controls(P)


@pytest.fixture
def draw_file(tmp_path):
    path = tmp_path / "kontroly.json"
    kontroly.write_draw(REAL, path, "python -m skuska.kontroly draw --protocol config/collection-v5.json --out x")
    return path


def protocol_with_band(tmp_path):
    """config/collection-v5.json with a synthetic controls.baseline (what Zápis 2 writes; any band serves here)."""
    doc = json.loads(REAL.read_text())
    doc["controls"]["baseline"] = copy.deepcopy(BAND)
    path = tmp_path / "collection-v5.json"
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return path


def spec_of(session, vm="a", attempt=1):
    """The spec of a block with controls for a draw session (kontroly.ControlsBlock.specs)."""
    return {"kind": kontroly.KIND, "id": session["id"], "deck": dict(session), "scenario": session["scenario"],
            "seed": session["seed"], "events": None, "controls": session["controls"], "attempt": attempt,
            "session_id": f"g2-{vm}-{session['id']}-{attempt}"}


GROUP = {"name": "g2-a-20261126T120000Z-1", "identity": {"boot_id": IDENTITY["boot_id"]}, "qemu": QEMU}


# ------------------------------------------------------------------ the draw

def test_the_draw_counts_per_kind_polarity_and_vm(draw):
    """Q47 and map row 8: 5 kinds x (3 controls + 3 negatives) = 30 occurrences in 10 sessions of 3 slots,
    alternating over the VMs; no session holds a kind twice; every card (kind, polarity) lies within 1 per VM (2 + 1);
    class A has no dose and class B each of its doses once among the controls and once among the negatives."""
    sessions = draw["sessions"]
    assert [s["id"] for s in sessions] == [f"k{n:02d}" for n in range(1, 11)]
    assert [s["vm"] for s in sessions] == ["a", "b"] * 5
    assert all(len(s["controls"]) == 3 == len({x["kind"] for x in s["controls"]}) for s in sessions)
    items = [(s, x) for s in sessions for x in s["controls"]]
    for kind in KINDS:
        k = P["controls"]["kinds"][kind]
        for polarity in kontroly.POLARITIES:
            mine = [(s, x) for s, x in items if x["kind"] == kind and x["polarity"] == polarity]
            assert len(mine) == 3
            assert sorted(sum(s["vm"] == vm for s, _ in mine) for vm in "ab") == [1, 2]
            doses = sorted((x["dose"] for _, x in mine), key=str)
            assert doses == (sorted(k["doses"], key=str) if k["class"] == "B" else [None] * 3)
            assert all(x["class"] == k["class"] for _, x in mine)
    cycle = g2.scenario_cycle(P)
    for v, vm in enumerate("ab"):
        assert [s["scenario"] for s in sessions if s["vm"] == vm] == [cycle[(i + v) % 4] for i in range(5)]
    assert draw["counts"]["occurrences_by_kind"] == {kind: {"control": 3, "negative": 3} for kind in KINDS}
    assert draw["counts"]["sessions_by_vm"] == {"a": 5, "b": 5}


def test_the_draw_times_guards_and_tenths_are_the_plans(draw):
    """The times as protocol_v5._items draws them for role test_controls with the session's stream event_times, in
    the tenths of two decks of full rounds (3 starts and 3 stops in every tenth), no start inside the guard of a full
    snapshot, first_s, min_gap_s and tail_s held; the wrapper admits every session's controls as they are."""
    guards = protocol_v5.guards(P)
    assert [(t, low, high) for t, low, high in guards] == [(0, -60000, 160000), (1800000, 1740000, 1960000)]
    starts, stops = [0] * 10, [0] * 10
    e, interval = P["events"], P["interval_s"]
    for s in draw["sessions"]:
        labels = [(x["kind"], x["polarity"], x["dose"]) for x in s["controls"]]
        again = protocol_v5._items(P, protocol_v5.CONTROL_ROLE, labels, [tuple(t) for t in s["tenths"]],
                                   random.Random(s["seeds"]["event_times"]))
        assert again == s["controls"] and json.loads(s["argument"]) == s["controls"]
        assert [list(protocol_v5.item_tenths(P, x)) for x in s["controls"]] == s["tenths"]
        for start, stop in s["tenths"]:
            starts[start] += 1
            stops[stop] += 1
        assert kontroly.check_controls(P, s["controls"], P["cycles"]) == s["controls"]
        end = None
        for x in s["controls"]:
            ms = round(x["start_s"] * 1000)
            assert not any(low <= ms < high for _, low, high in guards)
            assert P["controls"]["duration_s"][0] <= x["duration_s"] <= P["controls"]["duration_s"][1]
            assert x["start_s"] >= e["first_s"] and (end is None or x["start_s"] >= end + e["min_gap_s"])
            end = x["start_s"] + x["duration_s"]
        assert end + e["tail_s"] <= P["cycles"] * interval
        assert set(s["controls"][0]) == set(kontroly.PLAN_KEYS)
    assert starts == stops == [3] * 10 == draw["counts"]["per_tenth"]["starts"]


def test_the_draw_seed_rule(draw):
    """Its own streams (STREAMS_RULE): protocol_v5.seed with the protocol's name and the groups G2/controls and
    G2/<id>; no seed of the draw is a seed of the campaign's or the rehearsal's plan or of the deck of events, and the
    same protocol draws the same draw."""
    seed = protocol_v5.seed
    assert draw["streams"]["seeds"] == {purpose: seed(P["name"], purpose, "G2/controls", -1, 0)
                                        for purpose in ("control_deck", "phase_deck")}
    assert draw["streams"]["rule"] == kontroly.STREAMS_RULE and draw["streams"]["name"] == P["name"]
    ours = set(draw["streams"]["seeds"].values())
    for s in draw["sessions"]:
        assert s["seeds"] == {purpose: seed(P["name"], purpose, f"G2/{s['id']}", s["number"], 1)
                              for purpose in ("event_times", "traffic")}
        assert s["seed"] == s["seeds"]["traffic"]
        ours |= set(s["seeds"].values())
    others = set()
    for mode in protocol_v5.MODES:
        for s in protocol_v5.plan(P, mode)["sessions"]:
            others |= set(s["seeds"].values())
    deck = g2.draw_deck(P)
    others |= set(deck["streams"]["seeds"].values()) | {v for s in deck["sessions"] for v in s["seeds"].values()}
    assert len(ours) == 2 + 2 * 10 and not ours & others
    assert kontroly.draw_controls(P) == draw


def test_the_draw_does_not_read_the_baseline(draw):
    """The draw is the same with controls.baseline null and with any band Zápis 2 may write."""
    doc = copy.deepcopy(P)
    doc["controls"]["baseline"] = copy.deepcopy(BAND)
    assert kontroly.draw_controls(doc) == draw


def test_the_draw_file_is_written_once_and_a_changed_draw_is_refused(tmp_path, draw_file, draw):
    """The draw file carries check E's header and the draw; it is refused when it exists, and a draw that differs from
    what its rule draws from the protocol is refused by name."""
    doc = json.loads(draw_file.read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"], doc["values"]["stage"]) == (kontroly.DRAW_SCHEMA, 10, "G2")
    assert doc["values"]["sessions"] == draw["sessions"] and doc["values"]["protocol_sha256"] == sha(REAL)
    from scripts import gates
    assert doc["values"]["protocol_g0_binding"] == gates.stage_sha256(REAL, "G0")
    with pytest.raises(g2.Refused, match="exists: the draw of the controls is drawn once and never changed"):
        kontroly.write_draw(REAL, draw_file, "again")
    assert kontroly.load_draw(draw_file, P) == (doc, sha(draw_file))
    for key, change in (("sessions", lambda v: v["sessions"][0]["controls"][0].update(dose=99)),
                        ("streams", lambda v: v["streams"]["seeds"].update(control_deck=1))):
        edited = copy.deepcopy(doc)
        change(edited["values"])
        path = tmp_path / f"edited-{key}.json"
        path.write_text(json.dumps(edited))
        with pytest.raises(g2.Refused, match=rf"differs from the draw its rule draws from this protocol \({key}\)"):
            kontroly.load_draw(path, P)
    deck = tmp_path / "balicek.json"
    g2.write_deck(REAL, deck, "deck")
    with pytest.raises(g2.Refused, match="is no draw of the controls of G2"):
        kontroly.load_draw(deck, P)


# ------------------------------------------------------------------ the wrapper

def test_the_wrapper_inserts_its_controls_into_session_json_and_writes_its_record_beside(host, draw):
    """collection.py run through the wrapper (the real run_session on the fakes of host): session.json lists the
    draw session's controls in the plan's form and no event, capture_session gets them (and so starts
    collection.Controls for them), collection.v5_arguments is the measurement code's own again afterwards, and the
    wrapper's record beside the session, outside its directory, has check E's header, the sha256 of the wrapper's
    source and the list it inserted."""
    doc = json.loads(REAL.read_text())
    doc["profile"] = str(host.profile)
    path, p = loaded(host.tmp, doc)
    s = draw["sessions"][0]
    places = g2.Places(host.tmp / "G2", diagnostics=host.tmp / "data/diagnostics/G2")
    b = g2.Block(path, host.tmp / "balicek.json", "a", other_vm="g2", sessions=1, places=places, lab=FakeLab(path),
                 command="test")
    command = b.run_command(spec_of(s), GROUP)
    original = collection.v5_arguments
    assert kontroly.main(command[2:]) == 0
    assert collection.v5_arguments is original
    (out, metadata, cycles), = host.captured
    assert json.loads((out / "session.json").read_text()) == metadata
    assert (metadata["role"], metadata["events"], metadata["controls"], cycles) == ("diagnostic", [], s["controls"],
                                                                                    720)
    assert "controls" in metadata["metadata_not_model_inputs"] and metadata["campaign_id"] == "g2"
    records = collection.Controls(p, metadata["controls"], lambda name, **values: None).records
    assert [r["kind_class"] for r in records] == [x["class"] for x in s["controls"]]
    beside = places.root / "kontroly" / f"{out.name}.json"
    record = json.loads(beside.read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(record)
    assert (record["schema"], record["n"]) == (kontroly.WRAP_SCHEMA, 3)
    assert record["values"]["inserted"] == s["controls"]
    assert record["values"]["wrapper"] == {"path": "skuska/kontroly.py", "sha256": sha(ROOT / "skuska/kontroly.py")}
    assert record["values"]["session_dir"] == str(out) and not beside.is_relative_to(out)
    assert record["values"]["protocol_sha256"] == sha(path)


def wrapper_argv(command, *, drop=(), add=(), replace=None):
    """The wrapper's arguments of a command line with options of collection.py dropped (option and value), added or
    replaced ({option: value})."""
    argv = [str(x) for x in command[2:]]
    for option in drop:
        i = argv.index(option)
        del argv[i:i + 2]
    for option, value in (replace or {}).items():
        argv[argv.index(option) + 1] = value
    return argv + list(add)


@pytest.mark.parametrize("change, said", [
    (lambda c, s, t: wrapper_argv(c, add=["--events", g2.draw_deck(P)["sessions"][0]["argument"]]),
     "a session with controls holds no events (role test_controls holds controls and no events, proposal 7.2): "
     "--events is refused beside --controls"),
    (lambda c, s, t: wrapper_argv(c, drop=["--cycles"], replace={"--role": "test_controls"},
                                  add=["--mode", "campaign", "--attempt", "1"]),
     "the controls wrapper serves a diagnostic run only, not role test_controls (a session of a planned role takes its "
     "controls from the plan, collection.v5_planned)"),
    (lambda c, s, t: wrapper_argv(c, drop=["--session-id"]),
     "the controls wrapper needs --session-id: its record lies beside the session's directory"),
    (lambda c, s, t: wrapper_argv(c, replace={"--beside": str(t / "data/diagnostics/G2/a/g2-a-k01-1/x.json")}),
     "lies inside the session's directory"),
    (lambda c, s, t: wrapper_argv(c, replace={"--controls": "[{"}), "invalid --controls: not JSON"),
    (lambda c, s, t: wrapper_argv(c, replace={"--controls": json.dumps([s["controls"][0]] * 2)}),
     "invalid --controls: a session holds a kind twice"),
    (lambda c, s, t: wrapper_argv(c, replace={"--protocol": str(collection.DEFAULT)}),
     "the controls wrapper serves a protocol of schema 3 (collection.v5_arguments)"),
    (lambda c, s, t: [*wrapper_argv(c)[:5], str(ROOT / "scripts/collection.py"), "--protocol", "x", "plan"],
     "the controls wrapper runs `scripts/collection.py --protocol P run ...` only"),
    (lambda c, s, t: [*wrapper_argv(c)[:5], str(ROOT / "scripts/labctl.py"), *wrapper_argv(c)[6:]],
     "the controls wrapper runs " + str(ROOT / "scripts/collection.py")),
], ids=["events", "planned_role", "no_session_id", "beside_inside", "not_json", "kind_twice", "schema_2",
        "not_run", "not_collection"])
def test_the_wrapper_refuses_by_name_before_the_capture(host, draw, capsys, change, said):
    """Each refusal on stderr as collection.py prints its own (`collection: ...`, exit 2): no capture, no session
    directory and no record beside it; collection.v5_arguments is the original again."""
    doc = json.loads(REAL.read_text())
    doc["profile"] = str(host.profile)
    path, _ = loaded(host.tmp, doc)
    s = draw["sessions"][0]
    places = g2.Places(host.tmp / "G2", diagnostics=host.tmp / "data/diagnostics/G2")
    b = g2.Block(path, host.tmp / "balicek.json", "a", other_vm="g2", sessions=1, places=places, lab=FakeLab(path),
                 command="test")
    original = collection.v5_arguments
    assert kontroly.main(change(b.run_command(spec_of(s), GROUP), s, host.tmp)) == 2
    assert said in capsys.readouterr().err
    assert collection.v5_arguments is original and host.captured == []
    assert not (places.root / "kontroly").exists() and not (host.tmp / "data/diagnostics/G2/a/g2-a-k01-1").exists()


def test_a_record_beside_that_exists_is_refused(host, draw, capsys):
    doc = json.loads(REAL.read_text())
    doc["profile"] = str(host.profile)
    path, _ = loaded(host.tmp, doc)
    places = g2.Places(host.tmp / "G2", diagnostics=host.tmp / "data/diagnostics/G2")
    b = g2.Block(path, host.tmp / "balicek.json", "a", other_vm="g2", sessions=1, places=places, lab=FakeLab(path),
                 command="test")
    beside = places.root / "kontroly" / "g2-a-k01-1.json"
    beside.parent.mkdir(parents=True)
    beside.write_text("{}\n")
    assert kontroly.main(b.run_command(spec_of(draw["sessions"][0]), GROUP)[2:]) == 2
    assert f"the wrapper's record {beside} exists: a session id runs once" in capsys.readouterr().err
    assert host.captured == [] and beside.read_text() == "{}\n"


def _moved(item, start):
    """The control `item` started at `start` s, its phases as the plan states them."""
    return {**item, **protocol_v5._timing(P, round(start * 1000), round(item["duration_s"] * 1000))}


@pytest.mark.parametrize("change, said", [
    (lambda x: x[:1] + [{**x[1], "kind": "kontrola_x"}] + x[2:], "unknown control kind kontrola_x"),
    (lambda x: [{**x[0], "polarity": "kontrola"}, *x[1:]], "polarity 'kontrola', not control or negative"),
    (lambda x: [{**x[0], "class": "A" if x[0]["class"] == "B" else "B"}, *x[1:]], "the kind's class is"),
    (lambda x: [{**x[1], "dose": 16}] if x[1]["dose"] is None else [{**x[1], "dose": None}],
     "class A has no dose, not 16"),
    (lambda x: [{**x[0], "dose": 17}], "dose 17 is not one of the kind's doses [16, 64, 256]"),
    (lambda x: [_moved({**x[0], "duration_s": 100.0}, x[0]["start_s"])], "lasts 100 s, outside controls.duration_s"),
    (lambda x: [_moved(x[0], 299.0)], "starts at 299 s, before first_s 300 s"),
    (lambda x: [x[0], _moved(x[1], x[0]["start_s"] + x[0]["duration_s"] + 479)],
     "starts less than min_gap_s 480 s after the control before it ends"),
    (lambda x: [x[0], _moved(x[1], 1800.5)], "starts at 1800.5 s inside the guard of the full snapshot at 1800 s"),
    (lambda x: [x[0], _moved(x[1], 3600 - 360 - x[1]["duration_s"] + .001)],
     "the last control ends less than tail_s 360 s before the end of the session (3600 s)"),
    (lambda x: [{**x[0], "start_phase_s": (x[0]["start_phase_s"] + 1) % 5}],
     "start_phase_s and stop_phase_s are not the phases of start_s and duration_s"),
    (lambda x: [{**x[0], "start_s": x[0]["start_s"] + .0004}], "not on the plan's grid of 1 ms"),
    (lambda x: [*x, x[0]], "4 controls, a session has 3 slots"),
    (lambda x: [{k: v for k, v in x[0].items() if k != "stop_phase_s"}], "not a JSON list of controls"),
    (lambda x: [], "not a JSON list of controls"),
    (lambda x: [{**x[0], "start_s": "300"}], "its times are not seconds"),
], ids=["kind", "polarity", "class", "dose_of_class_a", "dose_of_class_b", "duration", "first_s", "min_gap_s",
        "guard", "tail_s", "phase", "grid", "slots", "keys", "empty", "not_seconds"])
def test_the_wrapper_admits_only_controls_the_plan_would_state(draw, change, said):
    """check_controls: one rule broken at a time, each refused with its reason."""
    writer = next(s for s in draw["sessions"] if s["controls"][0]["kind"] == "kontrola_zapisovac_pamate")
    assert kontroly.check_controls(P, writer["controls"], P["cycles"]) == writer["controls"]
    items = change(copy.deepcopy(writer["controls"]))
    with pytest.raises(ValueError) as refused:
        kontroly.check_controls(P, items, P["cycles"])
    assert str(refused.value).startswith("invalid --controls: ") and said in str(refused.value)


def test_the_audit_compares_controls_json_with_session_json_on_a_fake_session(tmp_path, draw):
    """Map F 3: the real audit of a fake diagnostic session whose session.json lists the controls the wrapper inserts
    and whose controls.json holds their records after a faultless run (scripts/tests/audit_cases_logs.py) accepts it,
    its section controls counting 3 controls, all executed; the same session with one record that differs from
    session.json is refused with controls_differ_from_plan alone."""
    from scripts.tests import audit_cases_logs as cases
    from scripts.tests import boundary_sessions as bs
    from scripts.tests import test_collection_logs as evidence
    s = draw["sessions"][0]
    place = {"role": "diagnostic", "group": "g2-a-20261126T120000Z-1", "scenario": s["scenario"], "seed": s["seed"],
             "vm": "a"}
    session = bs.build_session(tmp_path, collection.for_vm(P, "a"), REAL, place, session_id="g2-a-k01-1",
                               base=bs.time_base(P, "diagnostic", 0), profile=bs.profile_dir(tmp_path / "profile"),
                               meta={"events": [], "event_grace_s": P["events"]["grace_s"], "campaign_id": "g2",
                                     "source_sha256": {"lab/udalosti.py": evidence.SCRIPT_SHA256},
                                     "controls": s["controls"]})
    d = session.directory
    records = cases.control_records(s["controls"], json.loads((d / "end.json").read_text())["measure_start_unix"])
    cases._write(d, "events.json", {"schema": "hyptcn3/session-events/1", "events": []})
    cases._write(d, "controls.json", {"schema": protocol_v5.CONTROLS_SCHEMA, "controls": records})
    cases._set_segment(d, "session", "nginx-access.jsonl", lambda lines: [*lines, *cases.health_polls(records)])
    evidence.seal(d)
    audit = bs.audit(session, P)
    assert (audit.code, audit.values["reasons"]) == (0, [])
    section = audit.values["logs"]["sections"]["controls"]
    assert (section["controls"], section["executed"], len(section["calls"])) == (3, 3, 6)
    records[1]["start_s"] += 1
    cases._write(d, "controls.json", {"schema": protocol_v5.CONTROLS_SCHEMA, "controls": records})
    evidence.seal(d)
    audit = bs.audit(session, P, output=d / "audit-2.json")
    assert (audit.code, audit.values["reasons"]) == (2, ["logs: controls_differ_from_plan"])


# ------------------------------------------------------------------ the block

def test_the_command_line_of_a_session_with_controls(tmp_path, draw_file, monkeypatch):
    """Block.run_command of a spec with controls: the wrapper around the command line of map point A without
    --events, its record in kontroly/<session>.json of the G2 directory; the wrapper's parser and collection.py's own
    take it and v5_arguments gives the draw session's controls; the load sampler of skuska/g2.py sees the process as
    the session's own run, and from the other VM as a G2 session beside it or a run outside its plan."""
    deck = tmp_path / "balicek.json"
    g2.write_deck(REAL, deck, "deck")
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    b = kontroly.ControlsBlock(REAL, deck, draw_file, "a", other_vm="g2", sessions=1, places=places,
                               lab=FakeLab(REAL), command="test")
    b.deck, b.deck_sha256 = g2.load_deck(deck, P)
    [spec] = b.specs()
    assert (spec["kind"], spec["id"], spec["session_id"], spec["events"]) == ("controls", "k01", "g2-a-k01-1", None)
    assert spec["deck"]["draw"] == str(draw_file) and spec["deck"]["draw_sha256"] == sha(draw_file)
    command = b.run_command(spec, GROUP)
    plain = b.run_command(dict(spec, controls=None), GROUP)
    beside = tmp_path / "G2" / "kontroly" / "g2-a-k01-1.json"
    assert command[:7] == [sys.executable, str(ROOT / "skuska/kontroly.py"), "wrap", "--controls",
                           json.dumps(spec["controls"]), "--beside", str(beside)]
    assert command[7:] == plain[1:] and plain[1] == str(ROOT / "scripts/collection.py") and "--events" not in plain
    assert "--rate" not in plain  # The protocol has the rates since Zápis 1.
    seen = {}

    def run_session(a, p):
        seen.update(a=a, run=collection.v5_arguments(a, p))
    monkeypatch.setattr(collection, "run_session", run_session)
    monkeypatch.setattr(collection, "COLLECTIONS", tmp_path / "collections")
    assert kontroly.main(command[2:]) == 0
    a, run = seen["a"], seen["run"]
    assert (a.role, a.vm, a.session_id, a.campaign_id, a.cycles, a.events) == ("diagnostic", "a", "g2-a-k01-1", "g2",
                                                                               720, None)
    assert run["controls"] == spec["controls"] and run["events"] == []
    assert json.loads(beside.read_text())["values"]["inserted"] == spec["controls"]
    assert re.search(g2.LOAD_PATTERN, " ".join(command))
    assert g2.classify(command, vm="a", others=["b"], other_vm="g2", session_id="g2-a-k01-1")[0] == "own"
    assert g2.classify(command, vm="b", others=["a"], other_vm="g2")[0] == "outside"  # Base not data/diagnostics/G2.
    real = kontroly.wrapper_command([sys.executable, str(ROOT / "scripts/collection.py"), *plain[2:]],
                                    spec["controls"], beside)
    real[real.index("--collections-dir") + 1] = str(g2.DIAGNOSTICS / "a")
    assert g2.classify(real, vm="b", others=["a"], other_vm="g2")[0] == "beside"
    assert g2.classify(real, vm="b", others=["a"], other_vm="idle")[0] == "outside"


class WrapperLab(FakeLab):
    """skuska/tests/test_g2.py FakeLab whose child takes the wrapper's command line: it records it, writes the
    wrapper's record as the wrapper writes it, and runs the capture of collection.py's command line inside it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wrapped = []

    def child(self, command, log, *, timeout, lock_fd=None):
        command = [str(x) for x in command]
        if len(command) > 1 and command[1] == str(kontroly.WRAPPER):
            self.wrapped.append(command)
            beside = Path(command[command.index("--beside") + 1])
            beside.parent.mkdir(parents=True, exist_ok=True)
            beside.write_text(json.dumps({"values": {"inserted": json.loads(command[command.index("--controls") + 1]),
                                                     "wrapper": {"sha256": "w" * 64}}}))
            command = [command[0], *command[command.index("--beside") + 2:]]
        return super().child(command, log, timeout=timeout, lock_fd=lock_fd)


def test_a_block_runs_the_draw_sessions_of_its_vm_through_the_wrapper(tmp_path, draw_file):
    """Two sessions of VM a (k01, k03) as every G2 block runs a session, each capture through the wrapper; the record
    of a session names its kind, the draw's item, the wrapper's command line and the wrapper's record beside it."""
    protocol = protocol_with_band(tmp_path)
    deck = tmp_path / "balicek.json"
    g2.write_deck(protocol, deck, "deck")
    lab = WrapperLab(protocol)
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    b = kontroly.ControlsBlock(protocol, deck, draw_file, "a", other_vm="g2", sessions=2, places=places, lab=lab,
                               command="python -m skuska.kontroly block --vm a")
    result = b.run()
    assert result["stopped"] is None
    assert [s["session_id"] for s in result["sessions"]] == ["g2-a-k01-1", "g2-a-k03-1"]
    assert [command[command.index("--session-id") + 1] for command in lab.wrapped] == ["g2-a-k01-1", "g2-a-k03-1"]
    sessions = {s["id"]: s for s in json.loads(draw_file.read_text())["values"]["sessions"]}
    for sid, key in (("g2-a-k01-1", "k01"), ("g2-a-k03-1", "k03")):
        values = json.loads((places.records / f"{sid}.json").read_text())["values"]
        assert (values["kind"], values["deck_session"], values["events"], values["done"]) == ("controls", key, None,
                                                                                              True)
        assert values["deck"]["item"]["controls"] == sessions[key]["controls"]
        assert values["deck"]["item"]["draw_sha256"] == sha(draw_file) and values["deck"]["path"] == str(deck)
        assert values["commands"][0][1] == str(kontroly.WRAPPER)
        hook = next(x for x in values["beside"] if x["hook"] == "controls")
        assert hook["file"] == str(places.root / "kontroly" / f"{sid}.json") and hook["inserted"] == 3
        assert hook["matches_spec"] is True and hook["error"] is None
    again = kontroly.ControlsBlock(protocol, deck, draw_file, "a", other_vm="g2", sessions=1, places=places, lab=lab,
                                   command="again")
    assert [s["id"] for s in again.specs()] == ["k05"]  # DONE_RULE: k01 and k03 are done.


def test_the_command_lines_of_the_draw_and_of_the_block(tmp_path, monkeypatch, capsys):
    """python -m skuska.kontroly draw writes the draw once (exit 2 the second time); block --dry-run prints the
    sessions of the VM with the wrapper's command lines and the refusals (the lab a fake), and starts nothing."""
    out = tmp_path / "kontroly.json"
    argv = ["draw", "--protocol", str(REAL), "--out", str(out)]
    assert kontroly.main(argv) == 0
    doc = json.loads(out.read_text())
    assert doc["command"] == "python -m skuska.kontroly " + " ".join(argv) and doc["n"] == 10
    assert json.loads(capsys.readouterr().out)["counts"] == doc["values"]["counts"]
    assert kontroly.main(argv) == 2 and "exists: the draw of the controls is drawn once" in capsys.readouterr().err
    deck = tmp_path / "balicek.json"
    g2.write_deck(REAL, deck, "deck")
    monkeypatch.setattr(g2, "Lab", lambda protocol_path, p: FakeLab(protocol_path))
    assert kontroly.main(["block", "--protocol", str(REAL), "--deck", str(deck), "--draw", str(out), "--vm", "b",
                          "--sessions", "2", "--other-vm", "idle", "--g2-dir", str(tmp_path / "G2"),
                          "--dry-run"]) == 2
    plan = json.loads(capsys.readouterr().out)
    assert plan["refusals"] == [kontroly.BASELINE_NULL] and [row["deck"] for row in plan["sessions"]] == ["k02", "k04"]
    assert all(row["command"][1:3] == [str(kontroly.WRAPPER), "wrap"] for row in plan["sessions"])
    assert not (tmp_path / "G2").exists()
    with pytest.raises(ValueError, match="the controls wrapper runs"):
        kontroly.wrapper_command([sys.executable, str(ROOT / "scripts/labctl.py")], [], tmp_path / "x.json")


def test_a_block_with_controls_refuses_a_null_baseline_and_a_changed_draw(tmp_path, draw_file):
    """controls.baseline null (until Zápis 2): the dry run names the refusal and the block does not start; a draw
    that differs from its rule is refused before anything is checked."""
    deck = tmp_path / "balicek.json"
    g2.write_deck(REAL, deck, "deck")
    lab = FakeLab(REAL)
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    b = kontroly.ControlsBlock(REAL, deck, draw_file, "a", other_vm="g2", sessions=5, places=places, lab=lab,
                               command="test")
    plan = b.plan()
    assert plan["refusals"] == [kontroly.BASELINE_NULL]
    assert [row["command"][1] for row in plan["sessions"]] == [str(kontroly.WRAPPER)] * 5
    assert [row["deck"] for row in plan["sessions"]] == ["k01", "k03", "k05", "k07", "k09"]
    with pytest.raises(g2.Refused, match="controls.baseline is null"):
        b.run()
    assert not places.root.exists() and not any(e[0] == "run" for e in lab.events)
    doc = json.loads(draw_file.read_text())
    doc["values"]["sessions"][1]["controls"][0]["start_s"] += 1
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(doc))
    b = kontroly.ControlsBlock(REAL, deck, changed, "a", other_vm="g2", sessions=1, places=places, lab=lab,
                               command="test")
    with pytest.raises(g2.Refused, match=r"differs from the draw its rule draws from this protocol \(sessions\)"):
        b.run()


# ------------------------------------------------------------------ the test of equality (Q46)

def test_the_wrapper_takes_the_arguments_the_campaign_gives_a_row_of_test_controls(host, tmp_path):
    """The lead's condition on Q46: for a plan row of role test_controls the arguments of the wrapper equal those the
    campaign gives for the same row, but for the seed of the draw. The campaign's: the real scripts/campaign.py runs a
    rehearsal on the fakes of scripts/tests/kampan_v5.py until it captures a session of test_controls; its command
    line, parsed by collection.py's own parser, gives collection.v5_run (spied) the row's arguments. The wrapper's: the
    command line Block.run_command makes for a spec with the row's controls, run through the wrapper into the real
    run_session (the fakes of host). Equal: the cycles, the events, the controls (and so the collection.Controls the
    capture starts) and the traffic block but its seeds, which are the draw's (--seed) and diagnostic_seeds'; the
    campaign's arguments have plan_mode and attempt beside them, the identity of a planned session, which a
    diagnostic run refuses."""
    from scripts.tests.kampan_v5 import VMS, Harness
    rows = []
    with pytest.MonkeyPatch.context() as mp:
        h = Harness(tmp_path / "kampan", mp)
        protocol = h.protocol("protocol", limit=None)
        p = collection.protocol(protocol)
        real = collection.v5_run

        def spy(a, q):
            run = real(a, q)
            rows.append((copy.deepcopy(vars(a)), q, copy.deepcopy(run)))
            return run
        mp.setattr(collection, "v5_run", spy)
        rehearsal = h.init(protocol, "rehearsal", p["name"] + p["rehearsal"]["name_suffix"])
        for _ in range(40):
            if any(a["role"] == protocol_v5.CONTROL_ROLE for a, _, _ in rows):
                break
            for vm in VMS:
                h.step(rehearsal, vm)
    a, q, planned = next(row for row in rows if row[0]["role"] == protocol_v5.CONTROL_ROLE)
    row = next(s for s in protocol_v5.plan(p, "rehearsal")["sessions"]
               if (s["group"], s["scenario"]) == (a["group"], a["scenario"]))
    assert (a["mode"], a["attempt"], a["seed"], a["vm"]) == ("rehearsal", 1, row["seed"], row["vm"])
    assert row["controls"] and all(x["kind"] is not None for x in row["controls"])
    places = g2.Places(tmp_path / "G2", diagnostics=host.tmp / "data/diagnostics/G2")
    b = g2.Block(protocol, tmp_path / "balicek.json", a["vm"], other_vm="g2", sessions=1, places=places,
                 lab=FakeLab(protocol), command="test")
    seed = kontroly.draw_seed(p, "traffic", "G2/k01", 1, 1)
    spec = {"kind": kontroly.KIND, "id": "k01", "scenario": a["scenario"], "seed": seed, "events": None,
            "controls": row["controls"], "attempt": 1, "session_id": f"g2-{a['vm']}-k01-1"}
    assert kontroly.main(b.run_command(spec, GROUP)[2:]) == 0
    (out, metadata, cycles), = host.captured
    wrapper = {key: metadata[key] for key in ("cycles", "events", "controls", "traffic")}
    assert set(planned) - set(wrapper) == {"plan_mode", "attempt"} and cycles == planned["cycles"]

    def but_seeds(run):
        return {**{key: run[key] for key in ("cycles", "events", "controls")},
                "traffic": {key: value for key, value in run["traffic"].items() if key != "seeds"}}
    assert but_seeds(wrapper) == but_seeds(planned)
    assert wrapper["traffic"]["seeds"]["traffic"] == seed != planned["traffic"]["seeds"]["traffic"]
    assert set(wrapper["traffic"]["seeds"]) == set(planned["traffic"]["seeds"])
    assert (metadata["role"], a["role"]) == ("diagnostic", "test_controls")

    def started(items):
        return collection.Controls(q, items, lambda name, **values: None).records
    assert started(metadata["controls"]) == started(planned["controls"])
