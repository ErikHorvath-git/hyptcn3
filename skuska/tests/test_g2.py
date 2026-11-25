"""The deck and the driver of G2 sessions (skuska/g2.py, package H1a), with fakes of every lab and root step.

No test touches a VM, runs as root or writes outside tmp_path: the block's lab is FakeLab, its places lie under
tmp_path, and the protocol file is read only.
"""
from contextlib import contextmanager, nullcontext
import hashlib
import json
from pathlib import Path
import random
import re
import time

import pytest

from scripts import campaign, collection, protocol_v5
from scripts.tests import protokol_g0
from skuska import g2

ROOT = Path(__file__).resolve().parents[2]
# The protocol file as the G0 record holds it (scripts/tests/protokol_g0.py): these tests give the rate by --rate
# while the file's is null, and G2 writes the rates and the caps into config/collection-v5.json from Zápis 1 on.
V5 = protokol_g0.g0_file()
P = collection.protocol(V5)
MEASURED = 3600  # The fake measured phase of a session, in fake seconds.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def deck():
    return g2.draw_deck(P)


@pytest.fixture
def deck_file(tmp_path):
    path = tmp_path / "balicek.json"
    g2.write_deck(V5, path, "python -m skuska.g2 deck --protocol config/collection-v5.json --out balicek.json")
    return path


# ------------------------------------------------------------------ the deck

def test_the_deck_counts_per_type_vm_and_scenario(deck):
    """Q43: 6 types x 19 in 38 sessions of 3 distinct types, 9 or 10 of each type on each VM (at least 8); the
    sessions alternate over the VMs and, on each VM, over the cycle of scenarios, every scenario at least 8 times."""
    sessions = deck["sessions"]
    assert [s["id"] for s in sessions] == [f"e{n:02d}" for n in range(1, 39)]
    assert [s["vm"] for s in sessions] == ["a", "b"] * 19
    assert all(len({x["type"] for x in s["events"]}) == len(s["events"]) == 3 for s in sessions)
    types = sorted(P["events"]["types"])
    assert {t: sum(x["type"] == t for s in sessions for x in s["events"]) for t in types} == dict.fromkeys(types, 19)
    for t in types:
        per_vm = [sum(x["type"] == t for s in sessions if s["vm"] == vm for x in s["events"]) for vm in "ab"]
        assert sorted(per_vm) == [9, 10] and min(per_vm) >= g2.MIN_PER_VM
    cycle = g2.scenario_cycle(P)
    assert cycle == ["corp_high", "eshop_high", "corp_low", "eshop_low"]
    for v, vm in enumerate("ab"):
        mine = [s for s in sessions if s["vm"] == vm]
        assert [s["scenario"] for s in mine] == [cycle[(k + v) % 4] for k in range(19)]
        profiles = [P["scenarios"][s["scenario"]]["profile"] for s in mine]
        assert all(a != b for a, b in zip(profiles, profiles[1:]))
    by_scenario = {name: sum(s["scenario"] == name for s in sessions) for name in cycle}
    assert min(by_scenario.values()) >= g2.MIN_PER_SCENARIO and sum(by_scenario.values()) == 38
    assert deck["counts"]["occurrences_by_type"] == dict.fromkeys(types, 19)


def test_the_deck_phases_by_tenths_and_times_as_the_plan_draws_them(deck):
    """The tenths of the starts and the stops: full rounds of the 10 tenths over the 114 occurrences, so the counts per
    tenth differ by at most 1; each event lies in its tenths, its times are protocol_v5._items' with the session's
    stream event_times, and collection.diagnostic_events admits the deck's argument and gives back the same events."""
    starts, stops = [0] * 10, [0] * 10
    for s in deck["sessions"]:
        assert [list(protocol_v5.item_tenths(P, x)) for x in s["events"]] == s["tenths"]
        for start, stop in s["tenths"]:
            starts[start] += 1
            stops[stop] += 1
        again = protocol_v5._items(P, g2.ROLE, [x["type"] for x in s["events"]], [tuple(t) for t in s["tenths"]],
                                   random.Random(s["seeds"]["event_times"]))
        assert again == s["events"]
        assert collection.diagnostic_events(P, s["argument"], P["cycles"]) == s["events"]
        assert json.loads(s["argument"]) == [{k: x[k] for k in ("type", "start_s", "duration_s")} for x in s["events"]]
    assert max(starts) - min(starts) <= 1 and max(stops) - min(stops) <= 1 and sum(starts) == 114
    assert deck["counts"]["per_tenth"] == {"starts": starts, "stops": stops}


def test_the_deck_seed_rule(deck):
    """Its own streams (STREAMS_RULE): protocol_v5.seed with the protocol's name and the groups G2/deck and
    G2/<id>; no seed of the deck is a seed of the campaign's or the rehearsal's plan; the same protocol draws the same
    deck, and the deck names its streams."""
    seed = protocol_v5.seed
    assert deck["streams"]["seeds"] == {purpose: seed(P["name"], purpose, "G2/deck", -1, 0)
                                        for purpose in ("event_deck", "phase_deck")}
    assert deck["streams"]["name"] == P["name"] and "G2/deck" in deck["streams"]["rule"]
    ours = set(deck["streams"]["seeds"].values())
    for s in deck["sessions"]:
        assert s["seeds"] == {purpose: seed(P["name"], purpose, f"G2/{s['id']}", s["number"], 1)
                              for purpose in ("event_times", "traffic")}
        assert s["seed"] == s["seeds"]["traffic"]
        ours |= set(s["seeds"].values())
    plan = set()
    for mode in protocol_v5.MODES:
        for s in protocol_v5.plan(P, mode)["sessions"]:
            plan |= set(s["seeds"].values())
    assert not ours & plan
    assert g2.draw_deck(P) == deck


def test_the_deck_file_is_written_once_and_never_changed(tmp_path, deck_file, deck):
    """The deck file carries check E's header and the deck; it is refused when it exists, and a block refuses a deck
    that differs from what its rule draws."""
    doc = json.loads(deck_file.read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"], doc["values"]["stage"]) == (g2.DECK_SCHEMA, 38, "G2")
    assert doc["values"]["sessions"] == deck["sessions"] and doc["values"]["protocol_sha256"] == sha(V5)
    with pytest.raises(g2.Refused, match="exists: a deck is drawn once and never changed"):
        g2.write_deck(V5, deck_file, "again")
    assert g2.load_deck(deck_file, P) == (doc, sha(deck_file))
    doc["values"]["sessions"][0]["events"][0]["start_s"] += 5
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(doc))
    with pytest.raises(g2.Refused, match=r"differs from the deck its rule draws from this protocol \(sessions\)"):
        g2.load_deck(edited, P)


# ------------------------------------------------------------------ the fake lab

LAB = collection.lab_sha256()
MANIFEST = [f"{LAB[source]}  {path}" for path, source in collection.deployed_paths(LAB).items()]
COMMIT = "c" * 40
CODE = {"scripts/collection.py": "1" * 64, "features/archive.py": "2" * 64}


class FakeSampler:
    """Samples every interval over the fake measured phase of the session the run made, plus `extra` processes at
    given fake times."""

    def __init__(self, lab, path, interval):
        self.lab, self.path, self.interval = lab, Path(path), interval

    def start(self):
        self.lab.events.append(("load-start", self.path.name))
        return self

    def stop(self):
        start, end = self.lab.window
        lines = []
        t = start - self.interval
        while t <= end + self.interval:
            procs = [{"pid": 7, "argv": argv} for when, argv in self.lab.extra if abs(when - t) < self.interval / 2]
            lines.append(json.dumps({"t": g2.utc(t), "unix": t, "loadavg": "1.50 1.20 1.00 2/300 999",
                                     "procs": procs}))
            t += self.interval
        self.path.write_text("\n".join(lines) + "\n")
        self.lab.events.append(("load-stop", self.path.name))
        return {"hook": "load", "file": str(self.path), "samples": len(lines), "error": None}


class FakeLab:
    """The lab of a block without a VM or root (the methods of g2.Lab): a session's run makes its directory as
    scripts/collection.py run does (session.json, protocol.json, end.json, raw/), the audit writes a verdict, the
    archive records its call."""

    def __init__(self, protocol_path, *, rc=None, output=None, no_directory=(), procs=None, extra=(), accepted=True,
                 start_failure=None, root=True, dirty=(), readiness=None):
        self.protocol_path, self.events, self.boot, self.window = Path(protocol_path), [], 0, (0, 0)
        self.rc, self.output, self.no_directory = rc or {}, output or {}, set(no_directory)
        self.procs, self.extra, self.accepted = list(procs or []), list(extra), accepted
        self.start_failure, self.root, self.dirty, self.ready = start_failure, root, list(dirty), readiness
        self.clock, self.archives, self.sessions, self.code = 0.0, [], 0, "m" * 64

    def readiness(self):
        self.events.append(("readiness",))
        if self.ready:
            raise ValueError(self.ready)

    def measurement_dirty(self):
        return self.dirty

    def measurement(self):
        return self.code

    def is_root(self):
        return self.root

    def identity(self):
        return {"kernel": "6.1.0-42-cloud-amd64", "boot_id": f"boot-{self.boot}", "machine_id": "m" * 32,
                "stack_sha256": "s" * 64, "stack_manifest": MANIFEST}

    def qemu(self):
        return {"pid": 1000 + self.boot, "start_ticks": 5, "host_boot": "host"}

    def lab_sha256(self):
        return LAB

    def start_group(self, directory, name, before, environment, steps):
        self.events.append(("start_group", name))
        if self.start_failure:
            raise campaign.GroupStartFailed("start", self.start_failure)
        assert environment == campaign.guest_environment(self.identity())
        self.boot += 1
        steps += [{"step": step} for step in ("stop", "start", "reset", "pretouch")]
        return {"schema": "hyptcn3/campaign-group/1", "group": name, "identity": self.identity(),
                "qemu": self.qemu(), "start": {"steps": steps}}

    def child(self, command, log, *, timeout, lock_fd=None):
        command = [str(x) for x in command]
        if "levels" in command:
            self.events.append(("levels",))
            log.write_text('{"MemAvailable_kb": 900000, "modules": [], "processes": 120}\n')
            return 0
        if "audit" in command:
            return self.audit(command, log)
        sid = command[command.index("--session-id") + 1]
        self.events.append(("run", sid, lock_fd))
        assert command[1].endswith("scripts/collection.py") and timeout == 120 + 720 * 5 + 300
        log.write_text(self.output.get(sid, "session: ...\n"))
        if sid not in self.no_directory:
            out = Path(command[command.index("--collections-dir") + 1]) / sid
            (out / "raw").mkdir(parents=True)
            (out / "raw" / "000001.vmicd").write_bytes(b"ram")
            (out / "protocol.json").write_bytes(Path(command[command.index("--protocol") + 1]).read_bytes())
            (out / "session.json").write_text(json.dumps({"session_id": sid, "campaign_id": "g2", "commit": COMMIT,
                                                          "guest_before": self.identity(),
                                                          "measurement_sha256": {**CODE, "lab/x.py": "3" * 64}}))
            start = 10000.0 * (self.sessions + 1)
            self.window = (start, start + MEASURED)
            (out / "end.json").write_text(json.dumps({"measure_start_unix": start, "measure_end_unix": start + MEASURED,
                                                      "completed": self.rc.get(sid, 0) == 0}))
        self.sessions += 1
        return self.rc.get(sid, 0)

    def audit(self, command, log):
        out = Path(command[command.index("audit") + 1])
        report = Path(command[command.index("--out") + 1])
        self.events.append(("audit", out.name))
        assert command[command.index("--protocol") + 1] == str(out / "protocol.json")
        features = report.with_suffix(".npz")
        features.write_bytes(b"npz")
        report.write_text(json.dumps({"schema": "hyptcn3/collection-audit/1", "commit": COMMIT,
                                      "measurement_dirty": [], "values": {
                                          "accepted": self.accepted, "reasons": [] if self.accepted else ["x"],
                                          "session_dir": str(out), "session_sha256": sha(out / "session.json"),
                                          "protocol_sha256": sha(out / "protocol.json"), "features": str(features),
                                          "features_sha256": sha(features),
                                          "auditor_sha256": {"scripts/collection.py": CODE["scripts/collection.py"]},
                                          "extractor_sha256": {"features/archive.py": CODE["features/archive.py"]}}}))
        log.write_text("audit\n")
        return 0 if self.accepted else 2

    @contextmanager
    def collection_lock(self):
        self.events.append(("lock",))
        yield 99

    def audit_lock(self, log):
        return nullcontext()

    def archive(self, source, destination, guard, **options):
        guard()
        self.events.append(("archive", Path(source).name))
        self.archives.append((Path(source), Path(destination), options))
        destination.mkdir(parents=True)
        (destination / "archive-manifest.json").write_text("{}\n")
        return {"bytes": 3, "stored_bytes": 2}

    def mount(self, root):
        return {"target": "/", "system_disk": True}

    def guard(self, root, mount):
        assert mount == {"target": "/", "system_disk": True}

    def processes(self):
        return list(self.procs)

    def loadavg(self):
        return "0.50 0.40 0.30 1/200 99"

    def sampler(self, path, interval):
        return FakeSampler(self, path, interval)

    def inhibitor(self):
        self.events.append(("inhibit",))
        return lambda: self.events.append(("release",))

    def interrupts(self):
        class Quiet:
            def restore(self):
                pass

            def disarm(self):
                pass
        return Quiet()

    def sleep(self, seconds):
        self.clock += seconds
        self.events.append(("sleep", seconds))

    def monotonic(self):
        return self.clock

    def owner(self):
        return None


def block(tmp_path, deck_file, *, lab=None, sessions=2, rates=None, protocol=V5, **options):
    """A block of VM a under tmp_path with the fake lab; the rates of the scenarios of its sessions unless given."""
    lab = lab or FakeLab(protocol)
    if rates is None:
        scenarios = [s["scenario"] for s in g2.draw_deck(P)["sessions"] if s["vm"] == "a"][:sessions]
        rates = {name: 4.0 for name in scenarios}
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    b = g2.Block(protocol, deck_file, "a", other_vm=options.pop("other_vm", "g2"), sessions=sessions, rates=rates,
                 places=places, lab=lab, command="python -m skuska.g2 block --vm a", **options)
    return b, lab


def records(b):
    return {p.stem: json.loads(p.read_text()) for p in sorted(b.places.records.glob("g2-a-*.json"))}


def steps_of(lab):
    return [e for e in lab.events if e[0] in ("start_group", "run", "levels", "audit", "archive")]


# ------------------------------------------------------------------ the command lines

MAP_A = {"--protocol", "--role", "--vm", "--group", "--scenario", "--seed", "--rate", "--cycles", "--events",
         "--collections-dir", "--session-id"}  # Map point A.
ADDED = {"--campaign-id", "--expected-boot-id", "--expected-qemu"}  # Q55, and the group's boot as the campaign.


def parsed(command, monkeypatch):
    """The arguments scripts/collection.py's own parser and loader make of a command line (run_session replaced)."""
    seen = {}
    monkeypatch.setattr(collection, "run_session", lambda a, p: seen.update(a=a, p=p))
    assert collection.main(command[2:]) == 0
    return seen["a"], seen["p"]


def test_the_command_line_of_a_session_is_map_point_a(tmp_path, deck_file, monkeypatch):
    """The capture's command is map point A's with --campaign-id g2 (Q55) and the group's boot and QEMU process:
    collection.py's argparse and loader take it, v5_arguments gives the deck's events, the protocol's cycles and the
    rate of --rate while the protocol's is null, and the base lies under data/diagnostics/G2/<vm>."""
    b = g2.Block(V5, deck_file, "a", other_vm="g2", sessions=1, rates={"corp_high": 4.4}, lab=FakeLab(V5),
                 command="test")
    b.deck, b.deck_sha256 = g2.load_deck(deck_file, P)
    [spec] = b.specs()
    group = {"name": "g2-a-20261125T120000Z-1", "identity": {"boot_id": "boot-1"},
             "qemu": {"pid": 1001, "start_ticks": 5, "host_boot": "host"}}
    command = b.run_command(spec, group)
    assert command[:5] == [g2.sys.executable, str(ROOT / "scripts/collection.py"), "--protocol", str(V5), "run"]
    assert {x for x in command if x.startswith("--")} == MAP_A | ADDED
    a, p = parsed(command, monkeypatch)
    assert (a.role, a.vm, a.group, a.scenario, a.seed, a.rate, a.cycles, a.session_id, a.campaign_id) == (
        "diagnostic", "a", group["name"], "corp_high", spec["seed"], 4.4, 720, "g2-a-e01-1", "g2")
    assert a.collections_dir == g2.DIAGNOSTICS / "a" and a.collections_dir.is_relative_to(collection.DIAGNOSTICS)
    assert (a.expected_boot_id, json.loads(a.expected_qemu)) == ("boot-1", group["qemu"])
    assert (a.mode, a.attempt, a.pilot_report) == (None, None, None)
    run = collection.v5_arguments(a, p)
    assert run["cycles"] == 720 and run["events"] == spec["deck"]["events"]
    assert (run["traffic"]["rate"], run["traffic"]["rate_source"], run["traffic"]["seeds"]["traffic"]) == (
        4.4, "command line", spec["seed"])


def test_with_the_rate_in_the_protocol_the_command_has_no_rate(tmp_path, deck_file, monkeypatch):
    """Once G2 wrote the rate, the command takes the protocol's (no --rate) and --rate for that scenario is refused."""
    doc = json.loads(V5.read_text())
    doc["scenarios"]["corp_high"]["rate"] = 9.392
    protocol = tmp_path / "collection-v5.json"
    protocol.write_text(json.dumps(doc, indent=2) + "\n")
    b = g2.Block(protocol, deck_file, "a", other_vm="g2", sessions=1, lab=FakeLab(protocol), command="test")
    b.deck, b.deck_sha256 = g2.load_deck(deck_file, collection.protocol(protocol))
    [spec] = b.specs()
    command = b.run_command(spec, {"name": "g", "identity": {"boot_id": "x"}, "qemu": {"pid": 1}})
    assert "--rate" not in command
    a, p = parsed(command, monkeypatch)
    assert collection.v5_arguments(a, p)["traffic"]["rate_source"] == "protocol"
    b.rates = {"corp_high": 4.4}
    with pytest.raises(g2.Refused, match=r"has the rate 9\.392 in the protocol: --rate corp_high is refused"):
        b.run_command(spec, {"name": "g", "identity": {"boot_id": "x"}, "qemu": {"pid": 1}})


def test_the_audit_and_levels_commands_are_the_campaigns(tmp_path, deck_file):
    """The audit runs under the session's protocol.json with campaign.audit_capture's wrapping (background_command,
    user_command); labctl levels names the VM as collection.labctl_args does."""
    b, _ = block(tmp_path, deck_file)
    session = tmp_path / "diag" / "a" / "s"
    report = session / "audit_x.json"
    assert b.audit_command(session, report) == collection.background_command(collection.user_command(
        [g2.sys.executable, ROOT / "scripts/collection.py", "--protocol", session / "protocol.json", "audit",
         session, "--out", report]))
    assert [str(x) for x in b.levels_command()][-7:] == [
        str(ROOT / "scripts/labctl.py"), "levels", "--domain", "hyptcn-lab-a", "--vm", "a", "--port", "18080"][-7:]


# ------------------------------------------------------------------ the block

def test_the_order_of_steps_of_a_block(tmp_path, deck_file):
    """Four sessions of VM a: a group of group_sessions (3) sessions started as the campaign starts one, then a new
    group; per session run, labctl levels, the audit and the archive in this order; the run holds the VM's lock and
    the load sampler is beside it; the archive goes to session/a/<session> with zstd, bound to the audit, the reclaim
    with the campaign id g2."""
    b, lab = block(tmp_path, deck_file, sessions=4)
    result = b.run()
    assert result["stopped"] is None
    sids = [f"g2-a-{i}-1" for i in ("e01", "e03", "e05", "e07")]
    group = f"g2-a-{b.block_id}"
    expected = [("start_group", f"{group}-1")]
    for i, sid in enumerate(sids):
        if i == 3:
            expected.append(("start_group", f"{group}-2"))
        expected += [("run", sid, 99), ("levels",), ("audit", sid), ("archive", sid)]
    assert steps_of(lab) == expected
    assert lab.events[:2] == [("readiness",), ("lock",)] and lab.events[2] == ("inhibit",)
    assert lab.events[-1] == ("release",)
    i = lab.events.index(("run", sids[0], 99))
    assert lab.events[i - 1] == ("load-start", sids[0] + ".jsonl") and lab.events[i + 1] == ("load-stop",
                                                                                              sids[0] + ".jsonl")
    for source, destination, options in lab.archives:
        assert destination == tmp_path / "G2" / "session" / "a" / source.name
        assert options == {"reclaim": True, "campaign_id": "g2", "audit": options["audit"],
                           "reserve_bytes": 30 * 2 ** 30, "compress": "zstd"}
        assert options["audit"].parent == source and options["audit"].name.startswith("audit_")
    found = records(b)
    assert sorted(found) == sids
    for sid, doc in found.items():
        v = doc["values"]
        assert [s["step"] for s in v["steps"]] == ["run", "levels", "audit", "archive"]
        assert (v["done"], v["counted"], v["stop"], v["group"]["name"]) == (
            True, True, None, f"{group}-{2 if sid == sids[3] else 1}")
        assert v["exit_codes"] == {"run": 0, "levels": 0, "audit": 0}
        assert v["levels_after"] == {"MemAvailable_kb": 900000, "modules": [], "processes": 120}
    groups = sorted((b.block_dir / "groups").glob("*.json"))
    assert [g.name for g in groups] == [f"{group}-1.json", f"{group}-2.json"]
    log = b.log_path.read_text()
    assert "block " + b.block_id in log and log.count("audit True") == 4 and log.strip().endswith("4 sessions recorded")


def test_a_new_group_when_the_boot_of_the_group_is_gone(tmp_path, deck_file):
    """A session whose group lost its boot (a reboot of the VM) runs in a new group."""
    b, lab = block(tmp_path, deck_file, sessions=2)
    real = lab.child

    def reboot_after_first(command, log, **options):
        rc = real(command, log, **options)
        if "levels" in [str(x) for x in command] and lab.sessions == 1:
            lab.boot += 10  # Another boot id and QEMU process than the group's.
        return rc
    lab.child = reboot_after_first
    b.run()
    assert [e[1] for e in steps_of(lab) if e[0] == "start_group"] == [f"g2-a-{b.block_id}-1", f"g2-a-{b.block_id}-2"]


def test_a_run_that_exits_non_zero_is_recorded_audited_and_the_block_goes_on(tmp_path, deck_file):
    b, lab = block(tmp_path, deck_file, lab=FakeLab(V5, rc={"g2-a-e01-1": 1}), sessions=2)
    result = b.run()
    assert result["stopped"] is None
    assert [e for e in steps_of(lab) if e[0] in ("run", "audit")] == [
        ("run", "g2-a-e01-1", 99), ("audit", "g2-a-e01-1"), ("run", "g2-a-e03-1", 99), ("audit", "g2-a-e03-1")]
    first, second = records(b)["g2-a-e01-1"]["values"], records(b)["g2-a-e03-1"]["values"]
    assert (first["exit_codes"]["run"], first["done"], first["audit"]["accepted"], first["archive"] is None) == (
        1, False, True, False)
    assert (second["done"], second["stop"]) == (True, None)


@pytest.mark.parametrize("text, name", [
    ("collection: deployed guest files differ from lab/ in this commit: /opt/hyptcn-lab/services.py\n",
     "guest_mismatch"),
    ("collection: QEMU swap was not disabled before start: memory.swap.max is 'max'\n", "qemu_swap"),
    ("collection: QEMU memory was swapped before start: qemu_swap_kb is 512\n", "qemu_swap")])
def test_a_guest_mismatch_or_a_qemu_swap_refusal_stops_the_block(tmp_path, deck_file, text, name):
    """The run's refusal is named in the record and the block stops: no levels, no audit, no next session."""
    lab = FakeLab(V5, rc={"g2-a-e01-1": 2}, output={"g2-a-e01-1": text}, no_directory={"g2-a-e01-1"})
    b, lab = block(tmp_path, deck_file, lab=lab, sessions=2)
    result = b.run()
    assert result["stopped"] == name and [s["stop"] for s in result["sessions"]] == [name]
    assert steps_of(lab) == [("start_group", f"g2-a-{b.block_id}-1"), ("run", "g2-a-e01-1", 99)]
    v = records(b)["g2-a-e01-1"]["values"]
    assert (v["stop"], v["done"], v["counted"], v["exit_codes"]) == (name, False, False, {"run": 2})
    assert b.log_path.read_text().strip().endswith(f"stopped: {name}; 1 sessions recorded")


def test_a_failed_group_start_stops_the_block_by_name(tmp_path, deck_file):
    """GroupStartFailed of campaign.start_steps (here labctl's refusal of the QEMU swap) is recorded beside the group
    and stops the block; the session is recorded without a run."""
    lab = FakeLab(V5, start_failure="labctl start exited 1: labctl: QEMU swap is not disabled: memory.swap.max max")
    b, lab = block(tmp_path, deck_file, lab=lab)
    result = b.run()
    assert result["stopped"].startswith("Stop: qemu_swap: the start of group")
    assert steps_of(lab) == [("start_group", f"g2-a-{b.block_id}-1")]
    failure = json.loads((b.block_dir / "groups" / f"g2-a-{b.block_id}-1.start-failed.json").read_text())
    assert (failure["step"], failure["schema"]) == ("start", g2.GROUP_FAILURE_SCHEMA)
    v = records(b)["g2-a-e01-1"]["values"]
    assert (v["steps"], v["done"]) == ([], False) and v["stop"].startswith("Stop: qemu_swap")


def test_an_audit_of_other_measurement_code_stops_the_block(tmp_path, deck_file):
    """The audit's provenance binds the session's measurement code (auditor_sha256 and extractor_sha256 against the
    session's measurement_sha256), not the commit, which may move during a block: another commit with the same code
    passes and is recorded, another auditor stops the block before the archive."""
    lab = FakeLab(V5)
    real = lab.audit

    def other(command, log):
        rc = real(command, log)
        report = Path(command[command.index("--out") + 1])
        doc = json.loads(report.read_text())
        doc["commit"] = "d" * 40
        if "e03" in str(report):
            doc["values"]["auditor_sha256"]["scripts/collection.py"] = "9" * 64
        report.write_text(json.dumps(doc))
        return rc
    lab.audit = other
    b, lab = block(tmp_path, deck_file, lab=lab)
    result = b.run()
    assert "the audit of g2-a-e03-1 differs from the session: measurement code" in result["stopped"]
    assert [e[0] for e in steps_of(lab)] == ["start_group"] + ["run", "levels", "audit", "archive"] + [
        "run", "levels", "audit"]
    first, second = records(b)["g2-a-e01-1"]["values"], records(b)["g2-a-e03-1"]["values"]
    assert first["audit"]["commits"] == {"session": COMMIT, "audit": "d" * 40} and first["done"] is True
    assert second["archive"] is None and second["done"] is False


def test_measurement_code_that_changes_during_the_block_stops_it(tmp_path, deck_file):
    lab = FakeLab(V5)
    real = lab.child

    def change(command, log, **options):
        rc = real(command, log, **options)
        if "audit" in [str(x) for x in command]:
            lab.code = "n" * 64
        return rc
    lab.child = change
    b, lab = block(tmp_path, deck_file, lab=lab, sessions=2)
    result = b.run()
    assert result["stopped"].startswith("Stop: the measurement code changed during the block")
    assert [e[1] for e in steps_of(lab) if e[0] == "run"] == ["g2-a-e01-1"]


def test_the_readiness_the_code_the_rates_and_root_are_checked_before_the_block(tmp_path, deck_file):
    """Refused by name before anything starts: gates.require G1 (a valid G0), measurement code that differs from the
    commit, a missing --rate, a --rate no session uses, and a run without root."""
    lab = FakeLab(V5, readiness="stage G0 is not valid: no record", dirty=["scripts/collection.py"], root=False)
    b, lab = block(tmp_path, deck_file, lab=lab, rates={"corp_high": 4.0, "corp_low": 3.0})
    with pytest.raises(g2.Refused) as refused:
        b.run()
    text = str(refused.value)
    for words in ("readiness: stage G0 is not valid", "differs from the commit: scripts/collection.py",
                  "--rate of a scenario no session of the block runs: corp_low",
                  "scenario eshop_high has no rate in the protocol (null until G2): --rate eshop_high=R",
                  "runs as root through sudo"):
        assert words in text
    assert steps_of(lab) == [] and not b.log_path.exists() and not b.places.records.exists()


def test_another_capture_of_the_vm_refuses_the_block(tmp_path, deck_file):
    """The VM's collection lock is taken first, as the campaign's runner does: when another capture holds it the
    block is refused by name and nothing is written."""
    lab = FakeLab(V5)

    @contextmanager
    def held():
        raise BlockingIOError(11, "Resource temporarily unavailable")
        yield
    lab.collection_lock = held
    b, lab = block(tmp_path, deck_file, lab=lab)
    with pytest.raises(g2.Refused, match="another capture holds the collection lock of hyptcn-lab-a"):
        b.run()
    assert steps_of(lab) == [] and not (tmp_path / "G2").exists()


def test_an_interrupted_run_is_recorded_with_its_step_and_stops_the_block(tmp_path, deck_file):
    lab = FakeLab(V5)
    real = lab.child

    def interrupted(command, log, **options):
        if "--session-id" in [str(x) for x in command]:
            log.write_text("session: ...\n")
            raise InterruptedError("interrupted by signal 15")
        return real(command, log, **options)
    lab.child = interrupted
    b, lab = block(tmp_path, deck_file, lab=lab)
    result = b.run()
    assert result["stopped"] == "InterruptedError: interrupted by signal 15"
    v = records(b)["g2-a-e01-1"]["values"]
    [run] = v["steps"]
    assert (run["step"], run["exit_code"], run["error"]) == ("run", None, "interrupted: interrupted by signal 15")
    assert v["beside"][0]["hook"] == "load" and v["done"] is False


def test_a_deployed_guest_that_differs_from_lab_refuses_the_block(tmp_path, deck_file):
    lab = FakeLab(V5)
    lab.identity = lambda: {"boot_id": "x", "stack_manifest": MANIFEST[1:]}
    b, lab = block(tmp_path, deck_file, lab=lab)
    with pytest.raises(g2.Refused, match="the deployed guest differs from lab/ of this commit: /"):
        b.run()
    assert steps_of(lab) == [] and not b.log_path.exists()


# ------------------------------------------------------------------ the load rule

OWN = ["/home/eh/projects/hyptcn3/.venv/bin/python", "/home/eh/projects/hyptcn3/scripts/collection.py", "--protocol",
       "/home/eh/projects/hyptcn3/config/collection-v5.json", "run", "--role", "diagnostic", "--vm", "a", "--group",
       "g", "--scenario", "corp_high", "--seed", "1", "--cycles", "720", "--collections-dir",
       "/home/eh/projects/hyptcn3/data/diagnostics/G2/a", "--session-id", "g2-a-e01-1", "--campaign-id", "g2"]
OTHER = [x.replace("G2/a", "G2/b").replace("g2-a-e01-1", "g2-b-e02-1") if x != "a" else "b" for x in OWN]
CASES = [
    (["/home/eh/projects/hyptcn3/.venv/bin/python", "-m", "pytest", "-q"], "heavy"),
    ([".venv/bin/python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp", "/tmp/x",
      "tcn/tests/test_hodnoty.py", "skuska/tests/test_g2.py::test_the_deck_seed_rule"], "light"),
    ([".venv/bin/python", "-m", "pytest", "-q", "tcn/tests/test_prijatie_session.py"], "heavy"),
    (["python3", "-m", "pytest", "-q", "scripts/tests"], "heavy"),
    (["timeout", "900", "python3", "-m", "pytest", "-q"], "heavy"),
    (["/home/eh/projects/hyptcn3/.venv/bin/pytest", "-q", "tcn/tests/test_seedy.py"], "light"),
    ([".venv/bin/python", "-m", "tcn.suchy_beh", "--seed", "0"], "heavy"),
    ([".venv/bin/python", "scripts/gen_prirucka.py"], "heavy"),
    (["bash", "scripts/check_claims.sh"], "heavy"),
    (["bash", "-x", "scripts/check_prirucka.sh"], "heavy"),
    ([".venv/bin/python", "scripts/audit_selftest.py", "--protocol", "config/collection-v5.json"], "heavy"),
    ([".venv/bin/python", "-m", "safeguard", "--threads", "1", "train", "--index", "x"], "heavy"),
    ([".venv/bin/python", "-m", "tcn.train", "--config", "x"], "heavy"),
    ([".venv/bin/python", "-B", "scripts/lab_trial.py", "saturation", "--vm", "b", "--profile", "eshop"], "outside"),
    ([".venv/bin/python", "scripts/lab_trial.py", "record", "--out-record", "r.json", "dir"], "listed"),
    (OTHER, "beside"),
    ([x for x in OTHER if x not in ("--campaign-id", "g2")], "outside"),
    (OWN, "own"),
    ([x.replace("g2-a-e01-1", "g2-a-e03-1") for x in OWN], "outside"),
    (["grep", "-rn", "pytest", "scripts"], "listed"),
    (["/bin/bash", "-c", "source snap.sh && eval '.venv/bin/python -m pytest -q'"], "listed"),
    (["sudo", "-S", ".venv/bin/python", "scripts/lab_trial.py", "long", "--vm", "a"], "outside"),
]


@pytest.mark.parametrize("argv, kind", CASES, ids=[f"{i:02d}-{kind}" for i, (_, kind) in enumerate(CASES)])
def test_the_load_rule_classifies_what_a_process_runs(argv, kind):
    """Q70: heavy processes and runs outside the block's plan, against a light pytest of named files, the other VM's
    G2 session (--other-vm g2), this session's own run and a process that only names the list."""
    assert re.search(g2.LOAD_PATTERN, " ".join(argv)) or kind == "listed"
    assert g2.classify(argv, vm="a", others=["b"], other_vm="g2", session_id="g2-a-e01-1")[0] == kind


def test_the_other_vms_g2_session_is_outside_the_plan_of_an_idle_other_vm():
    assert g2.classify(OTHER, vm="a", others=["b"], other_vm="idle")[0] == "outside"


def samples(times, at=None, argv=None, interval=5):
    return [{"t": g2.utc(t), "unix": t, "loadavg": "1.0 1.0 1.0 1/1 1",
             "procs": [{"pid": 1, "argv": argv}] if at is not None and t == at else []} for t in times]


@pytest.mark.parametrize("at, argv, counted", [
    (None, None, True),
    (50, CASES[0][0], False),
    (95, CASES[0][0], True),
    (50, CASES[1][0], True),
    (50, CASES[13][0], False),
    (50, OTHER, True),
], ids=["quiet", "heavy-inside", "heavy-after", "light-inside", "outside-inside", "beside-inside"])
def test_the_session_is_counted_unless_its_measured_phase_holds_a_heavy_process(at, argv, counted):
    summary = g2.load_summary(samples(range(0, 105, 5), at, argv), 10, 90, interval=5, vm="a", others=["b"],
                              other_vm="g2", session_id="g2-a-e01-1")
    assert summary["counted"] is counted
    assert summary["inside"] == 17 and summary["loadavg_1min"] == {"max": 1.0, "mean": 1.0}
    if argv is not None and 10 <= at <= 90:
        [row] = summary["processes"]
        assert (row["samples"], row["class"]) == (1, g2.classify(argv, vm="a", others=["b"], other_vm="g2",
                                                                 session_id="g2-a-e01-1")[0])


@pytest.mark.parametrize("times, start, end, why", [
    ([t for t in range(0, 105, 5) if not 40 < t < 65], 10, 90, "do not cover"),
    (range(30, 105, 5), 10, 90, "do not cover"),
    (range(0, 70, 5), 10, 90, "do not cover"),
    (range(0, 105, 5), None, None, "no measured phase")])
def test_samples_that_do_not_cover_the_measured_phase_leave_the_session_not_counted(times, start, end, why):
    summary = g2.load_summary(samples(times), start, end, interval=5, vm="a", others=["b"], other_vm="g2")
    assert summary["counted"] is False and why in summary["reasons"][0]


def test_a_sample_holds_the_fixed_list_without_pgrep_zataz_and_itself():
    procs = [(1, CASES[0][0]), (2, ["pgrep", "-a", "-f", "--", g2.LOAD_PATTERN]),
             (3, ["bash", "/home/eh/hyptcn3-logs/v5/dokazy/G2/zataz.sh", "out"]), (4, ["sleep", "5"]),
             (5, CASES[7][0])]
    s = g2.sample(lambda: procs, lambda: "0.1 0.2 0.3 1/2 3", clock=lambda: 1764072000.0, exclude={5})
    assert s == {"t": "2025-11-25T12:00:00+00:00", "unix": 1764072000.0, "loadavg": "0.1 0.2 0.3 1/2 3",
                 "procs": [{"pid": 1, "argv": CASES[0][0]}]}


def test_the_load_sampler_writes_its_samples_and_stops(tmp_path):
    path = tmp_path / "zataz.jsonl"
    sampler = g2.LoadSampler(path, 0.01, lambda: [(1, CASES[1][0])], lambda: "1 2 3 4/5 6").start()
    time.sleep(0.05)
    done = sampler.stop()
    lines = g2.read_samples(path)
    assert done["samples"] == len(lines) >= 1 and done["error"] is None
    assert all(set(line) == {"t", "unix", "loadavg", "procs"} and line["procs"] == [{"pid": 1, "argv": CASES[1][0]}]
               for line in lines)


def test_a_heavy_process_blocks_the_start(tmp_path, deck_file):
    """No block starts while a heavy process (here the whole suite) runs: refused by name, nothing started, nothing
    written."""
    lab = FakeLab(V5, procs=[(4242, CASES[0][0])])
    b, lab = block(tmp_path, deck_file, lab=lab)
    with pytest.raises(g2.Refused, match="the block does not start: .*heavy: a pytest that names no test file"):
        b.run()
    assert steps_of(lab) == [] and ("lock",) not in lab.events and not b.places.records.exists()


def test_before_a_later_session_the_driver_waits_for_a_heavy_process_then_stops(tmp_path, deck_file):
    """A heavy process that appears between sessions: the driver waits while it runs and goes on after its end; one
    that stays HEAVY_WAIT_S stops the block by name."""
    lab = FakeLab(V5)
    real = lab.child

    def heavy_after_first(command, log, **options):
        rc = real(command, log, **options)
        if "audit" in [str(x) for x in command]:
            lab.procs = [(4242, CASES[6][0])] if lab.sessions == 1 else []
        return rc
    lab.child = heavy_after_first
    real_sleep = lab.sleep

    def sleep(seconds):
        real_sleep(seconds)
        if lab.clock >= 3 * g2.HEAVY_POLL_S:
            lab.procs = []
    lab.sleep = sleep
    b, lab = block(tmp_path, deck_file, lab=lab, sessions=2)
    assert b.run()["stopped"] is None
    assert [e for e in lab.events if e[0] == "sleep"] == [("sleep", g2.HEAVY_POLL_S)] * 3
    assert "waits before the next session: heavy: C4 (tcn.suchy_beh)" in b.log_path.read_text()
    lab2 = FakeLab(V5)
    real2 = lab2.child

    def heavy_for_good(command, log, **options):
        rc = real2(command, log, **options)
        if "audit" in [str(x) for x in command]:
            lab2.procs = [(4242, CASES[6][0])]
        return rc
    lab2.child = heavy_for_good
    b2, lab2 = block(tmp_path / "2", deck_file, lab=lab2, sessions=2)
    result = b2.run()
    assert result["stopped"].startswith(f"Stop: heavy processes for {g2.HEAVY_WAIT_S} s before the next session")
    assert [e[1] for e in steps_of(lab2) if e[0] == "run"] == ["g2-a-e01-1"]


def test_a_heavy_process_in_the_measured_phase_leaves_the_session_not_counted(tmp_path, deck_file):
    lab = FakeLab(V5, extra=[(10000.0 + 1800, CASES[0][0])])
    b, lab = block(tmp_path, deck_file, lab=lab, sessions=2)
    b.run()
    first, second = (records(b)[sid]["values"] for sid in ("g2-a-e01-1", "g2-a-e03-1"))
    assert (first["counted"], first["done"], second["counted"]) == (False, True, True)
    assert first["load"]["summary"]["reasons"] == [
        "heavy: a pytest that names no test file (the whole suite or a directory): " + " ".join(CASES[0][0])]


# ------------------------------------------------------------------ the records and the selection

def test_the_session_record_header(tmp_path, deck_file):
    """Check E's header (commit, date, host, guest, command, n, values) with the schema of a G2 session; n counts its
    steps; the record names the deck by sha256, the load file by sha256, the commands and exit codes."""
    b, lab = block(tmp_path, deck_file, sessions=1, rates={"corp_high": 4.0})
    b.run()
    doc = records(b)["g2-a-e01-1"]
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"], doc["command"]) == (g2.SESSION_SCHEMA, 4, "python -m skuska.g2 block --vm a")
    assert doc["commit"] == g2.git("rev-parse", "HEAD").strip()
    assert doc["guest"] == {"vm": "a", "domain": "hyptcn-lab-a", "kernel": "6.1.0-42-cloud-amd64",
                            "boot_id": "boot-1", "machine_id": "m" * 32, "stack_sha256": "s" * 64}
    v = doc["values"]
    assert (v["stage"], v["kind"], v["deck_session"], v["attempt"], v["other_vm"]) == ("G2", "deck", "e01", 1, "g2")
    assert v["deck"]["sha256"] == sha(deck_file) and v["deck"]["item"]["id"] == "e01"
    assert v["load"]["file"] == str(tmp_path / "G2" / "zataz" / "g2-a-e01-1.jsonl")
    assert v["load"]["sha256"] == sha(v["load"]["file"])
    run, levels, audit = v["commands"]
    assert run[4] == "run" and "levels" in levels and "audit" in audit and v["exit_codes"] == {
        "run": 0, "levels": 0, "audit": 0}
    assert v["rate"] == {"value": 4.0, "source": "command line"}
    assert v["audit"]["sha256"] == sha(v["audit"]["report"]) and v["archive"]["compression"] == "zstd"


def test_the_next_block_takes_the_sessions_that_are_not_done_as_their_next_attempt(tmp_path, deck_file):
    """A session that is done is not run again; one that is not done runs as its next attempt; --only runs named
    sessions again; --sessions above what is left is refused."""
    lab = FakeLab(V5, rc={"g2-a-e01-1": 1})
    b, lab = block(tmp_path, deck_file, lab=lab, sessions=2)
    b.run()
    b2, _ = block(tmp_path, deck_file, sessions=1)
    b2.deck, b2.deck_sha256 = g2.load_deck(deck_file, P)
    assert [s["session_id"] for s in b2.specs()] == ["g2-a-e01-2"]
    b2.count = 18
    assert [s["session_id"] for s in b2.specs()][:2] == ["g2-a-e01-2", "g2-a-e05-1"]
    b2.count = 19
    with pytest.raises(g2.Refused, match="--sessions 19: 18 deck sessions of VM a are not done"):
        b2.specs()
    b2.only = ["e03"]
    assert [s["session_id"] for s in b2.specs()] == ["g2-a-e03-2"]
    b2.only = ["e02"]
    with pytest.raises(g2.Refused, match="--only names deck sessions of VM a, each once; not of it: e02"):
        b2.specs()


def test_the_dry_run_starts_nothing(tmp_path, deck_file, capsys):
    """--dry-run: the checks and the commands of the block's sessions; nothing started, nothing written."""
    b, lab = block(tmp_path, deck_file, sessions=2)
    plan = b.plan()
    assert plan["refusals"] == [] and [r["session_id"] for r in plan["sessions"]] == ["g2-a-e01-1", "g2-a-e03-1"]
    assert all(r["command"][4] == "run" for r in plan["sessions"])
    assert steps_of(lab) == [] and not (tmp_path / "G2").exists()

