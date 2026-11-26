"""The ground truth of G2 under load (skuska/pozemna_pravda.py, package H1b1), with fakes of every lab and root step.

No test touches a VM, runs as root or writes outside tmp_path: the block's lab is skuska/tests/test_g2.py FakeLab, the
sampler's clock, collector and guest commands are World (fake time), and the comparison restores a tiny archive made
under tmp_path and runs guestparse validate in-process on guestparse/tests/data/mini.vmicd; the protocol file is read
only.
"""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import getpass
import hashlib
import json
from pathlib import Path
import threading

import pytest

from features import cli as features_cli
from guestparse import cli as guest_cli, validate as guest_validate, view as guest_view
from scripts import collection, collection_archive, labctl, protocol_v5
from skuska import g2, pozemna_pravda as pp
from skuska.tests import test_g2 as base

ROOT = Path(__file__).resolve().parents[2]
V5, P = base.V5, base.P  # The protocol file as the G0 record holds it (null rates, given by --rate).
RATES = {"corp_high": 4.0, "eshop_high": 4.0}
MINI = ROOT / "guestparse/tests/data/mini.vmicd"
PROFILE = ROOT / "profiles/debian12-6.1.0-42-cloud-amd64"
NAME = "hyptcn-lab-a"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def drawn():
    return pp.draw_plan(P)


@pytest.fixture
def deck_file(tmp_path):
    path = tmp_path / "balicek.json"
    g2.write_deck(V5, path, "python -m skuska.g2 deck --protocol config/collection-v5.json --out balicek.json")
    return path


@pytest.fixture
def plan_file(tmp_path):
    path = tmp_path / "pravda.json"
    pp.write_plan(V5, path, "python -m skuska.pozemna_pravda plan --protocol config/collection-v5.json "
                            "--out pravda.json")
    return path


def block(tmp_path, deck_file, lab=None, vm="a"):
    lab = lab or base.FakeLab(V5)
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    return g2.Block(V5, deck_file, vm, other_vm="g2", rates=RATES, places=places, lab=lab,
                    command=f"python -m skuska.pozemna_pravda block --vm {vm}"), lab


def specs_of(b, plan_file):
    doc, digest = pp.load_plan(plan_file, P)
    return pp.truth_specs(b, doc, plan_file, digest)


# ------------------------------------------------------------------ the draw and the plan of moments

def test_the_draw_of_the_dedicated_sessions(drawn):
    """Q62: 4 sessions, eshop_high and corp_high on each VM, the first sessions of the two VMs in different profiles;
    3 distinct types in each, the 5 types with an effect once on each VM and one of them twice (a different one on
    each VM, once in each session), naprazdno never; collection.diagnostic_events admits every session's argument."""
    sessions = drawn["sessions"]
    assert [(s["id"], s["vm"]) for s in sessions] == [("p01", "a"), ("p02", "b"), ("p03", "a"), ("p04", "b")]
    for vm in "ab":
        assert sorted(s["scenario"] for s in sessions if s["vm"] == vm) == ["corp_high", "eshop_high"]
    assert P["scenarios"][sessions[0]["scenario"]]["profile"] != P["scenarios"][sessions[1]["scenario"]]["profile"]
    types = sorted(t for t in P["events"]["types"] if t != "naprazdno")
    twice = []
    for vm in "ab":
        mine = [s for s in sessions if s["vm"] == vm]
        counts = {t: sum(x["type"] == t for s in mine for x in s["events"]) for t in types}
        assert sum(counts.values()) == 6 and min(counts.values()) == 1 and "naprazdno" not in {
            x["type"] for s in mine for x in s["events"]}
        [(double, _)] = [(t, n) for t, n in counts.items() if n == 2]
        assert all(double in {x["type"] for x in s["events"]} for s in mine)
        twice.append(double)
    assert twice[0] != twice[1] and drawn["counts"]["occurrences_by_type_and_vm"]["a"][twice[0]] == 2
    for s in sessions:
        assert len({x["type"] for x in s["events"]}) == len(s["events"]) == 3
        assert collection.diagnostic_events(P, s["argument"], P["cycles"]) == s["events"]
        assert [list(protocol_v5.item_tenths(P, x)) for x in s["events"]] == s["tenths"]
    starts = [t[0] for s in sessions for t in s["tenths"]]
    assert max(starts.count(d) for d in range(10)) - min(starts.count(d) for d in range(10)) <= 1


def test_the_draw_has_its_own_streams(drawn):
    """deck_seed with the groups G2/pravda and G2/<id>: no seed of the draw is a seed of the deck of the 38 sessions or
    of the campaign's or the rehearsal's plan, and the same protocol draws the same sessions."""
    seed = protocol_v5.seed
    assert drawn["streams"]["seeds"] == {purpose: seed(P["name"], purpose, "G2/pravda", -1, 0)
                                         for purpose in ("event_deck", "phase_deck")}
    ours = set(drawn["streams"]["seeds"].values())
    for s in drawn["sessions"]:
        assert s["seeds"] == {purpose: seed(P["name"], purpose, f"G2/{s['id']}", s["number"], 1)
                              for purpose in ("event_times", "traffic")} and s["seed"] == s["seeds"]["traffic"]
        ours |= set(s["seeds"].values())
    deck = g2.draw_deck(P)
    theirs = set(deck["streams"]["seeds"].values()) | {x for s in deck["sessions"] for x in s["seeds"].values()}
    for mode in protocol_v5.MODES:
        theirs |= {x for s in protocol_v5.plan(P, mode)["sessions"] for x in s["seeds"].values()}
    assert not ours & theirs
    assert pp.draw_plan(P) == drawn


def test_the_plan_of_moments_and_the_count_in_the_windows(drawn):
    """MOMENTS_RULE: 16 moments a session, 6 of them in its events (2 in each, inside [start + 30 s, stop - 20 s]), 10
    outside the audit's windows widened by 30 s, none in the first 60 s or the last 30 s, at least 20 s apart; per VM
    over its two sessions 32 moments and 12 in events, above the criterion's 30 and 10."""
    interval, grace = P["interval_s"], P["events"]["grace_s"]
    for s in drawn["sessions"]:
        moments = s["moments"]
        assert len(moments) == pp.SAMPLES == 16 and [m["seq"] for m in moments] == sorted({m["seq"] for m in moments})
        inside = [m for m in moments if m["where"] == "event"]
        assert len(inside) == pp.IN_EVENTS == 6
        assert sorted(m["event"] for m in inside) == [0, 0, 1, 1, 2, 2]
        for m in moments:
            t = m["seq"] * interval
            half = interval / 2  # A moment is the nearest sequence number of its time.
            assert m["t_s"] == t and pp.FIRST_S - half <= t <= P["cycles"] * interval - pp.LAST_S + half
            if m["where"] == "event":
                x = s["events"][m["event"]]
                assert x["start_s"] + 30 - half <= t <= x["start_s"] + x["duration_s"] - 20 + half
                assert m["type"] == x["type"]
            else:
                assert all(not x["start_s"] - 1 - 30 + half < t < x["start_s"] + x["duration_s"] + grace + 30 - half
                           for x in s["events"]) and m["type"] is None
        assert all((b["seq"] - a["seq"]) * interval >= pp.MIN_SPACING_S for a, b in zip(moments, moments[1:]))
    assert drawn["counts"]["moments_by_vm"] == {vm: {"all": 32, "event": 12} for vm in "ab"}


def test_the_plan_file_is_written_once_and_never_changed(tmp_path, plan_file, drawn):
    doc = json.loads(plan_file.read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"], doc["values"]["stage"]) == (pp.PLAN_SCHEMA, 4, "G2")
    assert doc["values"]["sessions"] == drawn["sessions"] and doc["values"]["protocol_sha256"] == sha(V5)
    with pytest.raises(pp.Refused, match="exists: the plan of the ground truth is drawn once"):
        pp.write_plan(V5, plan_file, "again")
    assert pp.load_plan(plan_file, P) == (doc, sha(plan_file))
    doc["values"]["sessions"][0]["moments"][0]["seq"] += 1
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(doc))
    with pytest.raises(pp.Refused, match=r"differs from the plan its rule draws from this protocol \(sessions\)"):
        pp.load_plan(edited, P)


def test_the_specs_of_a_vm(tmp_path, deck_file, plan_file):
    """The kind of spec of the dedicated sessions (beside Block.specs()): the VM's sessions with their argument, seed,
    the excluded criteria (Q62) and the draw; a done session is not run again, --only runs one as its next attempt."""
    b, _ = block(tmp_path, deck_file)
    specs = specs_of(b, plan_file)
    assert [s["session_id"] for s in specs] == ["g2-a-p01-1", "g2-a-p03-1"]
    item = json.loads(plan_file.read_text())["values"]["sessions"][0]
    assert specs[0] == {"kind": "pozemna_pravda", "id": "p01", "deck": None, "scenario": item["scenario"],
                        "seed": item["seed"], "events": item["argument"], "attempt": 1, "session_id": "g2-a-p01-1",
                        "excluded": {"criteria": ["event_effects", "marked_rows_per_event", "invalid_rows.max"],
                                     "rule": pp.EXCLUDED_RULE},
                        "draw": {"path": str(plan_file), "sha256": sha(plan_file), "item": item}}
    b.places.records.mkdir(parents=True)
    (b.places.records / "g2-a-p01-1.json").write_text(json.dumps({"schema": g2.SESSION_SCHEMA, "values": {
        "vm": "a", "deck_session": "p01", "attempt": 1, "done": True}}))
    assert [s["session_id"] for s in specs_of(b, plan_file)] == ["g2-a-p03-1"]
    doc, digest = pp.load_plan(plan_file, P)
    assert [s["session_id"] for s in pp.truth_specs(b, doc, plan_file, digest, only=["p01"])] == ["g2-a-p01-2"]
    with pytest.raises(pp.Refused, match="not of it: p02"):
        pp.truth_specs(b, doc, plan_file, digest, only=["p02"])


# ------------------------------------------------------------------ the command lines

class FakeLabctl:
    """scripts/labctl.py Lab without a VM: what main() asks of it is recorded."""
    seen = []

    def __init__(self, uri, domain, vm, port):
        self.uri, self.domain, self.vm, self.port, self.swap_error, self.unit = uri, domain, vm, port, None, "unit"

    def owned(self):
        FakeLabctl.seen.append(("owned", self.domain, self.vm, self.port))

    def guest(self, command):
        FakeLabctl.seen.append(("guest", command))
        return "1 systemd\n"


@pytest.mark.parametrize("command", [pp.PS, pp.SS, pp.LSMOD])
def test_the_guest_commands_are_labctl_exec(command, monkeypatch, capsys):
    """Every guest command of a sample is scripts/labctl.py exec --guest-command for the session's VM, which labctl's
    own main() parses and runs (its Lab replaced); as root it runs as the VM's owner (collection.user_command)."""
    p = collection.for_vm(P, "a")
    argv = pp.guest_argv(p, command)
    assert argv[:3] == [pp.sys.executable, str(ROOT / "scripts/labctl.py"), "exec"]
    FakeLabctl.seen = []
    monkeypatch.setattr(labctl, "Lab", FakeLabctl)
    assert labctl.main(argv[2:]) == 0
    assert FakeLabctl.seen == [("owned", "hyptcn-lab-a", "a", 18080), ("guest", command)]
    assert capsys.readouterr().out == "1 systemd\n"
    monkeypatch.setattr(collection.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", getpass.getuser())
    rooted = pp.guest_argv(p, command)
    assert rooted[:3] == ["runuser", "-u", getpass.getuser()] and rooted[-len(argv):] == argv


def test_the_validate_and_crosscheck_lines_parse_with_their_argparse(tmp_path):
    """The comparison's command lines are what guestparse's and features' own parsers take; crosscheck names the
    sidecar as --c, without which it would take the .vmicd for the collector's vector and compare nothing."""
    files = {"ps_pred": tmp_path / "a", "ps_po": tmp_path / "b", "lsmod": tmp_path / "c"}
    argv = pp.validate_argv(tmp_path / "raw", tmp_path / "profile", 123, files, tmp_path / "s", tmp_path / "o.json")
    assert argv[:4] == [pp.sys.executable, "-m", "guestparse", "validate"]
    a = guest_cli.build_parser().parse_args(argv[3:])
    assert (a.cmd, a.snapshot, a.profile, a.chain_until, a.ps_before, a.ps_after, a.lsmod, a.ss, a.out) == (
        "validate", str(tmp_path / "raw"), str(tmp_path / "profile"), 123, str(files["ps_pred"]),
        str(files["ps_po"]), str(files["lsmod"]), str(tmp_path / "s"), str(tmp_path / "o.json"))
    argv = pp.crosscheck_argv(tmp_path / "x.vmicd", tmp_path / "x.json", P["bin_bytes"], tmp_path / "c.json")
    assert argv[:4] == [pp.sys.executable, "-m", "features", "crosscheck"]
    a = features_cli.build_parser().parse_args(argv[3:])
    assert (a.cmd, a.snapshot, a.c, a.bin_bytes, a.out) == (
        "crosscheck", str(tmp_path / "x.vmicd"), str(tmp_path / "x.json"), 16777216, str(tmp_path / "c.json"))
    block_, source, why = features_cli._c_features_for(str(MINI), "mini")
    assert (block_, source) == (None, None) and why


def test_the_comparisons_children_run_in_the_background(tmp_path, monkeypatch):
    seen = {}

    def fake(argv, **options):
        seen.update(argv=argv, **options)
        return type("Done", (), {"returncode": 0})()
    monkeypatch.setattr(pp.subprocess, "run", fake)
    assert pp.run_child(["python", "-m", "guestparse"], tmp_path / "log") == 0
    assert seen["argv"] == collection.background_command(["python", "-m", "guestparse"]) and seen["cwd"] == ROOT


# ------------------------------------------------------------------ the sampler in fake time

def ts_name(unix):
    return datetime.fromtimestamp(unix, timezone.utc).strftime("%Y%m%dT%H%M%S") + f"{round(unix * 1000) % 1000:03d}Z"


class World:
    """Fake time with the collector of one session (its sidecars appear in raw/ as time passes) and the guest (each
    command takes command_s, or slow[kind], and gets the next pids); the sampler's Env."""

    def __init__(self, raw, start, *, slow=None, fail=None, command_s=0.8, lateness=0.02, delta_ms=400.0,
                 full_ms=2500.0, publish_s=0.3, t=None):
        self.raw, self.start, self.slow, self.fail = Path(raw), start, dict(slow or {}), dict(fail or {})
        self.command_s, self.lateness, self.delta_ms, self.full_ms, self.publish_s = (
            command_s, lateness, delta_ms, full_ms, publish_s)
        self.t = start - 150.0 if t is None else t
        self.next, self.stopped, self.pid, self.calls = 0, False, 4000, []

    def capture(self, seq):
        """(start, total_ms) of the capture of seq."""
        return self.start + seq * P["interval_s"] + self.lateness, (
            self.full_ms if seq % P["full_every"] == 0 else self.delta_ms)

    def publish(self):
        while self.raw.is_dir() and self.next < P["cycles"]:
            ts, total = self.capture(self.next)
            if ts + total / 1000 + self.publish_s > self.t:
                return
            doc = {"schema": "vmicollect/1", "seq": self.next, "timestamp_unix": round(ts, 3),
                   "sched": {"lateness_s": self.lateness, "skipped_before": 0}, "capture": {"total_ms": total},
                   "output": {"full": self.next % P["full_every"] == 0}}
            (self.raw / f"{NAME}_{self.next:06d}_{ts_name(ts)}.json").write_text(json.dumps(doc))
            self.next += 1

    def now(self):
        return self.t

    def wait(self, seconds):
        if self.stopped:
            return True
        self.t += max(0.0, seconds)
        self.publish()
        return False

    def guest(self, command, out):
        kind = {pp.PS: "ps", pp.SS: "ss", pp.LSMOD: "lsmod"}[command]
        result = {"argv": ["labctl", "exec", "--guest-command", command], "start_unix": None, "end_unix": None,
                  "exit_code": None, "stderr": ""}
        if self.stopped:
            result["stderr"] = "not started: the sampler was stopped"
            return result
        result["start_unix"] = self.t
        self.t += self.slow.get(kind, self.command_s)
        self.pid += 3
        text = {"ps": f"1 systemd\n2 kthreadd\n300 nginx\n{self.pid} ps\n",
                "ss": ("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                       'tcp LISTEN 0 511 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=300,fd=6))\n'),
                "lsmod": "Module Size Used by\nnls_ascii 16384 1\n"}[kind]
        with Path(out).open("x") as stream:
            stream.write(text)
        self.publish()
        code = self.fail.get(kind, 0)
        result.update(end_unix=self.t, exit_code=code, stderr="" if code == 0 else "labctl: Guest command failed")
        self.calls.append((kind, result["start_unix"], self.t))
        return result

    def stop(self):
        self.stopped = True


def session_dir(b, spec):
    """A session's directory as collection.py run leaves it, with its logs manifest."""
    out = b.base / spec["session_id"]
    (out / "raw").mkdir(parents=True)
    for name, text in (("session.json", "{}"), ("end.json", "{}"), ("traffic.log", "x\n"), ("raw/collect.log", "y\n")):
        (out / name).write_text(text)
    collection.write_logs_manifest(out)
    return out


def listing(directory):
    return sorted(str(p.relative_to(directory)) for p in Path(directory).rglob("*"))


def sampler(tmp_path, deck_file, plan_file, **world):
    b, _ = block(tmp_path, deck_file)
    spec = specs_of(b, plan_file)[0]
    out = session_dir(b, spec)
    w = World(out / "raw", 1_800_000_000.0, **world)
    s = pp.Sampler(b, spec, {"session": out, "load": tmp_path / "load.jsonl"}, w, threaded=False)
    return b, spec, out, w, s


def test_the_sampler_samples_every_moment_outside_the_sessions_directory(tmp_path, deck_file, plan_file):
    """SAMPLER_RULE in fake time: the moments come from the sidecars; per moment ss and ps end before the capture of
    its seq starts and ps, ss and lsmod start after it ended (no discard); every file lies under
    <g2-dir>/pozemna_pravda/<session>/ with host times and sha256, and the session's directory and its logs manifest
    do not change."""
    b, spec, out, w, s = sampler(tmp_path, deck_file, plan_file)
    before = listing(out)
    manifest = json.loads((out / "logs_manifest.json").read_text())["files"]
    s.start()
    w.publish()
    summary = s.stop()
    lines = g2.read_samples(s.dir / pp.SAMPLES_FILE)
    assert [x["seq"] for x in lines] == [m["seq"] for m in spec["draw"]["item"]["moments"]]
    assert all(x["status"] == "sampled" and x["sidecar"]["seq"] == x["seq"] for x in lines)
    for x in lines:
        assert [c["name"] for c in x["commands"]] == ["ss_pred", "ps_pred", "ps_po", "ss_po", "lsmod"]
        start, total = w.capture(x["seq"])
        assert x["commands"][1]["end_unix"] < start and x["commands"][2]["start_unix"] >= start + total / 1000
        assert x["due_unix"] == round(w.start + x["seq"] * 5, 3) and pp.discard(x, x["sidecar"]) == []
        for c in x["commands"]:
            assert Path(c["file"]).parent == s.dir and c["sha256"] == sha(c["file"])
    assert summary == {"hook": "pozemna_pravda", "dir": str(s.dir), "summary": str(s.dir / pp.SUMMARY_FILE),
                       "sha256": sha(s.dir / pp.SUMMARY_FILE), "planned": 16, "sampled": 16, "error": None}
    doc = json.loads((s.dir / pp.SUMMARY_FILE).read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert doc["values"]["files"][pp.SAMPLES_FILE] == sha(s.dir / pp.SAMPLES_FILE)
    assert len(doc["values"]["files"]) == 2 + 16 * 5
    sidecars = sorted(p.name for p in (out / "raw").glob("*.json"))
    assert listing(out) == sorted(before + [f"raw/{n}" for n in sidecars])
    (out / "logs_manifest.json").rename(tmp_path / "first_manifest.json")
    collection.write_logs_manifest(out)
    assert json.loads((out / "logs_manifest.json").read_text())["files"] == manifest
    assert s.dir.is_relative_to(tmp_path / "G2" / "pozemna_pravda") and not s.dir.is_relative_to(out)


def test_a_slow_phase_before_the_moment_is_discarded_and_the_lead_grows(tmp_path, deck_file, plan_file):
    """Commands of 4 s each: the first sample's ps before ends after the capture of its seq started (discard (d)); the
    lead grows to the phase + LEAD_MARGIN_S and the next sample is on time."""
    b, spec, out, w, s = sampler(tmp_path, deck_file, plan_file, slow={"ps": 4.0, "ss": 4.0})
    s.start()
    s.stop()
    first, second = g2.read_samples(s.dir / pp.SAMPLES_FILE)[:2]
    assert first["lead_s"] == pp.LEAD_S and second["lead_s"] == 8.0 + pp.LEAD_MARGIN_S
    [reason] = pp.discard(first, first["sidecar"])
    assert reason.startswith("(d) ps_pred ended 1.980 s after the start of the capture")
    assert pp.discard(second, second["sidecar"]) == []


def test_a_moment_reached_too_late_is_not_sampled_and_a_failed_command_ends_its_sample(tmp_path, deck_file,
                                                                                        plan_file):
    """The sampler reaches its first moment after the moment's start time (the chain is already near it): not
    sampled; lsmod failing makes a sample failed, discarded by (a)."""
    b, spec, out, w, s = sampler(tmp_path, deck_file, plan_file)
    first = spec["draw"]["item"]["moments"][0]["seq"]
    w.t = w.start + first * 5 - 3.0
    w.fail = {"lsmod": 1}
    s.start()
    s.stop()
    lines = g2.read_samples(s.dir / pp.SAMPLES_FILE)
    assert lines[0]["status"] == "not_sampled" and lines[0]["why"].startswith("too late")
    assert lines[1]["status"] == "failed" and [c["name"] for c in lines[1]["commands"]][-1] == "lsmod"
    assert pp.discard(lines[1], lines[1]["sidecar"])[0].startswith("(a) a guest command failed")
    assert pp.discard(lines[0], None) == [f"(a) not sampled: {lines[0]['why']}",
                                          f"(b) the chain has no snapshot of seq {first}"]


class Waiting(World):
    """A world whose waits take real time: the sampler's thread waits for a snapshot until it is stopped."""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.event = threading.Event()

    def wait(self, seconds):
        return self.event.wait(5)

    def stop(self):
        self.stopped = True
        self.event.set()


def test_the_threaded_sampler_stops_with_the_run(tmp_path, deck_file, plan_file):
    """With its thread: no snapshot appears, the run ends, stop() ends the thread and records every moment as not
    sampled."""
    b, _ = block(tmp_path, deck_file)
    spec = specs_of(b, plan_file)[0]
    out = session_dir(b, spec)
    s = pp.make_hook(lambda p: Waiting(out / "raw", 1_800_000_000.0))(b, spec, {"session": out})
    assert s._thread.is_alive()
    result = s.stop()
    assert not s._thread.is_alive() and (result["planned"], result["sampled"], result["error"]) == (16, 0, None)
    lines = g2.read_samples(s.dir / pp.SAMPLES_FILE)
    assert len(lines) == 16 and {x["status"] for x in lines} == {"not_sampled"}
    assert pp.make_hook()(b, {"kind": "deck"}, {}).stop() == {"hook": "pozemna_pravda",
                                                              "skipped": "no ground-truth session"}


class TruthLab(base.FakeLab):
    """test_g2's FakeLab whose run leaves the raw/ the fake world of its session fills."""

    def child(self, command, log, *, timeout, lock_fd=None):
        rc = super().child(command, log, timeout=timeout, lock_fd=lock_fd)
        command = [str(x) for x in command]
        if "--session-id" in command:
            self.last = (Path(command[command.index("--collections-dir") + 1])
                         / command[command.index("--session-id") + 1] / "raw", self.window[0] + 1.0)
        return rc


class LabWorld(World):
    """The world of the session the lab ran last, made at its first use (the hook makes it before the run)."""

    def __init__(self, lab):
        self.lab, self.ready = lab, False

    def __getattribute__(self, name):
        if name in ("now", "wait", "guest", "stop") and not object.__getattribute__(self, "ready"):
            lab = object.__getattribute__(self, "lab")
            World.__init__(self, *lab.last)
            self.ready = True
        return object.__getattribute__(self, name)


def test_a_block_runs_the_dedicated_sessions_with_the_sampler_beside(tmp_path, deck_file, plan_file):
    """skuska/g2.py Block.run(specs) with the specs of the VM and the sampler in Block.beside: every record has the
    kind pozemna_pravda, values.excluded with the three tables of Q62 and the draw, and the sampler's entry beside the
    load sampler's; the sampler's files lie in <g2-dir>/pozemna_pravda/<session>/ and none in the session's
    directory."""
    lab = TruthLab(V5)
    b, lab = block(tmp_path, deck_file, lab=lab)
    b.beside.append(pp.make_hook(lambda p: LabWorld(lab), threaded=False))
    result = b.run(specs_of(b, plan_file))
    assert result["stopped"] is None and [s["session_id"] for s in result["sessions"]] == ["g2-a-p01-1", "g2-a-p03-1"]
    for sid in ("g2-a-p01-1", "g2-a-p03-1"):
        doc = json.loads((b.places.records / f"{sid}.json").read_text())
        v = doc["values"]
        assert (v["kind"], v["deck_session"], v["deck"]["item"], v["done"]) == ("pozemna_pravda", sid[5:8], None, True)
        assert v["excluded"] == {"criteria": list(pp.EXCLUDED), "rule": pp.EXCLUDED_RULE}
        assert v["draw"]["sha256"] == sha(plan_file) and v["draw"]["item"]["id"] == sid[5:8]
        load, truth = v["beside"]
        assert load["hook"] == "load" and (truth["hook"], truth["planned"], truth["sampled"]) == (
            "pozemna_pravda", 16, 16)
        directory = pp.truth_dir(b.places.root, sid)
        assert truth["summary"] == str(directory / pp.SUMMARY_FILE) and truth["sha256"] == sha(truth["summary"])
        session = b.base / sid
        assert not [p for p in listing(session) if "_pred" in p or "_po" in p or "vzork" in p or "lsmod" in p]
        assert len(list(directory.glob("*.txt"))) == 16 * 5 and (directory / pp.MOMENTS_FILE).is_file()


# ------------------------------------------------------------------ the rules of discard and of explanation

def line(**changes):
    commands = [{"name": name, "start_unix": start, "end_unix": start + 0.8, "exit_code": 0, "sha256": "s",
                 "file": f"/x/{name}"} for name, start in (("ss_pred", 990.0), ("ps_pred", 992.0), ("ps_po", 1003.0),
                                                           ("ss_po", 1004.0), ("lsmod", 1005.0))]
    doc = {"seq": 40, "status": "sampled", "why": None, "commands": commands, "sidecar": {"sha256": "side"}}
    for key, value in changes.items():
        doc[key] = value
    return doc


SIDE = {"name": "x.json", "sha256": "side", "seq": 40, "timestamp_unix": 1000.0, "lateness_s": 0.02,
        "total_ms": 2500.0, "full": False}


def test_the_discard_rule():
    """DISCARD_RULE, every reason: (a) not sampled or a failed command, (b) no snapshot of the seq, (c) another
    sidecar, (d) a command before the moment ended after the capture started, (e) one after it started before the
    capture ended; a sample on time is compared."""
    assert pp.discard(line(), SIDE) == []
    late = line()
    late["commands"][1]["end_unix"] = 1000.5
    assert pp.discard(late, SIDE) == ["(d) ps_pred ended 0.500 s after the start of the capture"]
    early = line()
    early["commands"][2]["start_unix"] = 1002.0
    assert pp.discard(early, SIDE) == ["(e) ps_po started 0.500 s before the end of the capture"]
    failed = line()
    failed["commands"][4]["exit_code"] = 1
    assert pp.discard(failed, SIDE)[0].startswith("(a) a guest command failed")
    assert pp.discard(line(status="not_sampled", why="too late", commands=[]), SIDE) == ["(a) not sampled: too late"]
    assert pp.discard(line(), None) == ["(b) the chain has no snapshot of seq 40"]
    assert pp.discard(line(), {**SIDE, "total_ms": None}) == [
        "(b) the sidecar of seq 40 has no timestamp_unix or capture.total_ms"]
    assert pp.discard(line(sidecar={"sha256": "other"}), SIDE) == [
        "(c) the sidecar the sampler read differs from the archive's"]


SS_HEAD = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"


def ss_line(proto, state, local, peer, pid=None):
    users = f' users:(("p",pid={pid},fd=3))' if pid else ""
    return f"{proto} {state} 0 0 {local} {peer}{users}\n"


def test_the_stable_sockets(tmp_path):
    """SS_STABLE_RULE: the sockets of both runs that a process holds in both, lines of the run after verbatim; what
    guestparse's read_ss reads of the file is that set."""
    before = tmp_path / "pred.txt"
    after = tmp_path / "po.txt"
    before.write_text(SS_HEAD + ss_line("tcp", "LISTEN", "0.0.0.0:8080", "0.0.0.0:*", 300)
                      + ss_line("tcp", "ESTAB", "127.0.0.1:5432", "127.0.0.1:40000", 400)
                      + ss_line("tcp", "TIME-WAIT", "127.0.0.1:8081", "127.0.0.1:40100")
                      + ss_line("udp", "UNCONN", "127.0.0.1:323", "0.0.0.0:*", 500)
                      + ss_line("tcp", "ESTAB", "10.0.2.15:8080", "10.0.2.2:50000", 300))
    after.write_text(SS_HEAD + ss_line("tcp", "LISTEN", "0.0.0.0:8080", "0.0.0.0:*", 300)
                     + ss_line("tcp", "ESTAB", "127.0.0.1:5432", "127.0.0.1:40000", 401)
                     + ss_line("tcp", "TIME-WAIT", "127.0.0.1:8081", "127.0.0.1:40100")
                     + ss_line("udp", "UNCONN", "[::]:323", "[::]:*", 500)
                     + ss_line("tcp", "ESTAB", "10.0.2.15:8080", "10.0.2.2:50001", 300))
    out = tmp_path / "stable.txt"
    assert pp.stable_sockets(before, after, out) == {"sockets": 2}
    rows, skipped = guest_validate.read_ss(out)
    assert rows == {("TCP", "0.0.0.0", 8080, "0.0.0.0", 0), ("TCP", "127.0.0.1", 5432, "127.0.0.1", 40000)}
    assert skipped == [] and out.read_text().splitlines()[0] == SS_HEAD.strip()


def test_the_event_rule():
    events = [{"type": "zataz_pamate", "host_start_unix": 100.0, "host_started_unix": 103.0, "host_stop_unix": 300.0,
               "host_stopped_unix": 302.0, "start": {"ok": True}},
              {"type": "restart_databazy", "host_start_unix": 900.0, "host_started_unix": 920.0,
               "host_stop_unix": 1100.0, "host_stopped_unix": 1101.0, "start": {"ok": False}}]
    assert pp.during((150.0, 150.4), events, 60) == {"class": "event", "occurrence": 0, "type": "zataz_pamate"}
    assert pp.during((101.0, 101.4), events, 60)["class"] == "window"
    assert pp.during((330.0, 330.4), events, 60)["class"] == "window"
    assert pp.during((1000.0, 1000.4), events, 60) == {"class": "window", "occurrence": 1, "type": "restart_databazy"}
    assert pp.during((500.0, 500.4), events, 60) == {"class": "outside", "occurrence": None, "type": None}


# ------------------------------------------------------------------ the table on recorded files

def validate_doc(**parts):
    """A recorded output of guestparse validate (guestparse/validate.py run) with the given lists."""
    doc = {"schema": "hyptcn3/guestparse-validate/1",
           "traversal": {"processes_truncated": False, "processes_stop_reason": None, "modules_truncated": False,
                         "modules_stop_reason": None, "sockets_truncated": False, "sockets_skipped_tasks": 0},
           "processes": {"ps_before": 5, "ps_after": 5, "stable": 4, "stable_name_identical": 4, "snapshot": 4,
                         "found": 4, "missing": 0, "false_positive": 0, "name_mismatch": 0, "recall_percent": 100.0,
                         "name_match_rules": {"exact": 4}, "duplicate_pids": [], "missing_list": [],
                         "false_positive_list": [], "name_mismatch_list": []},
           "modules": {"ground_truth": 2, "snapshot": 2, "matched": 2, "missing": 0, "extra": 0, "missing_list": [],
                       "extra_list": []},
           "sockets": {"ground_truth": 1, "snapshot_tcp_udp": 1, "snapshot_other_protocols": {}, "matched": 1,
                       "missing": 0, "extra": 0, "ground_truth_unparsed": 0, "missing_list": [], "extra_list": []},
           "checks": {}}
    for path, value in parts.items():
        section, key = path.split("__")
        doc[section][key] = value
    return doc


def sock(proto, saddr, sport, daddr, dport):
    return {"proto": proto, "saddr": saddr, "sport": sport, "daddr": daddr, "dport": dport}


def recorded_sample(work, seq, result, *, ps=((650, 660),), ss_before="", ss_after="", start=None, late=False):
    """The files of one compared sample and its row of a comparison record."""
    start = 1000.0 + seq * 5 if start is None else start
    low, high = ps[0]
    texts = {"ss_pred": SS_HEAD + ss_before, "ps_pred": f"1 systemd\n300 nginx\n{low} ps\n",
             "ps_po": f"1 systemd\n300 nginx\n{high} ps\n", "ss_po": SS_HEAD + ss_after,
             "lsmod": "Module Size Used by\nnls_ascii 16384 1\n"}
    commands = []
    for name, at in (("ss_pred", start - 6), ("ps_pred", start - 4.5 + (5 if late else 0)), ("ps_po", start + 1),
                     ("ss_po", start + 2), ("lsmod", start + 3)):
        path = work / f"{seq:06d}_{name}.txt"
        path.write_text(texts[name])
        commands.append({"name": name, "command": "x", "start_unix": at, "end_unix": at + 0.8, "exit_code": 0,
                         "file": str(path), "sha256": sha(path)})
    side = {"name": f"{NAME}_{seq:06d}_x.json", "sha256": "s", "seq": seq, "timestamp_unix": start,
            "lateness_s": 0.02, "total_ms": 400.0, "full": False}
    sampled = {"seq": seq, "status": "sampled", "why": None, "commands": commands, "sidecar": side}
    row = {"seq": seq, "where": "event", "event": 0, "sampler": {"status": "sampled"}, "sidecar": side,
           "commands": commands, "discarded": pp.discard(sampled, side)}
    if not row["discarded"]:
        stable = work / f"{seq:06d}_ss_stabilne.txt"
        row["stable_ss"] = {"file": str(stable), **pp.stable_sockets(work / f"{seq:06d}_ss_pred.txt",
                                                                     work / f"{seq:06d}_ss_po.txt", stable)}
        row["stable_ss"]["sha256"] = sha(stable)
        out = work / f"{seq:06d}_validate.json"
        out.write_text(json.dumps(result))
        row["validate"] = {"argv": [], "exit_code": 0, "out": str(out), "sha256": sha(out)}
    return row


def comparison(tmp_path, samples, full, *, vm="a", session_id="g2-a-p01-1"):
    path = tmp_path / f"porovnanie_{session_id}.json"
    values = {"stage": "G2", "session_id": session_id, "vm": vm, "kind": "pozemna_pravda", "scenario": "corp_high",
              "intensity": "high", "events": [{"type": "zataz_pamate", "host_start_unix": 1000.0,
                                               "host_started_unix": 1002.0, "host_stop_unix": 1600.0,
                                               "host_stopped_unix": 1601.0, "start": {"ok": True}}],
              "grace_s": 60, "interval_s": 5, "samples": samples, "full": full}
    path.write_text(json.dumps(pp.header(pp.COMPARE_SCHEMA, "test", len(samples), values, guest={"vm": vm})))
    return path


def crosscheck_doc(work, seq, agree=True):
    path = work / f"crosscheck_{seq:06d}.json"
    path.write_text(json.dumps({"schema": "hyptcn3/vysledok-hlavicka/1", "values": {"snimky": [{
        "snapshot": "x", "seq": seq, "full": True, "invariant": {"zhoda": True},
        "porovnanie": {"zhoda": agree, "rozdielov": 0 if agree else 3}, "c_vystup": {"dostupny": True}}]}}))
    return {"seq": seq, "sidecar": {}, "argv": [], "exit_code": 0 if agree else 1, "out": str(path),
            "sha256": sha(path)}


def test_the_table_on_recorded_files(tmp_path):
    """One agreeing sample, one whose differences each have an explanation (a pid shorter than the window, a name
    changed within it, a module list that did not close, a socket of one run, an unbound one, a short connection of a
    listening port, a missing socket of a missing process) and one unexplained difference in every source, a
    discarded sample, a full snapshot that agrees and one that does not; the counts show the criterion's minimums,
    and the table has check E's header."""
    work = tmp_path / "work"
    work.mkdir()
    listen = ss_line("tcp", "LISTEN", "0.0.0.0:8080", "0.0.0.0:*", 300)
    agree = recorded_sample(work, 40, validate_doc(), ss_before=listen, ss_after=listen)
    explained = recorded_sample(work, 60, validate_doc(
        processes__false_positive_list=[{"pid": 655, "comm": "bash"}],
        processes__name_mismatch_list=[{"pid": 700, "ps_before": "bash", "ps_after": "python3", "snapshot": "sh"}],
        processes__missing_list=[{"pid": 420, "ps_before": "postgres", "ps_after": "postgres"}],
        traversal__processes_truncated=True, traversal__processes_stop_reason="cyklus",
        traversal__modules_truncated=True, traversal__modules_stop_reason="cyklus",
        modules__missing_list=["nls_cp437"],
        sockets__extra_list=[sock("TCP", "127.0.0.1", 8081, "127.0.0.1", 41000),
                             sock("UDP", "0.0.0.0", 0, "0.0.0.0", 0),
                             sock("TCP", "10.0.2.15", 8080, "10.0.2.2", 51000)],
        sockets__missing_list=[sock("TCP", "127.0.0.1", 5432, "127.0.0.1", 40000)]),
        ss_before=listen + ss_line("tcp", "ESTAB", "127.0.0.1:8081", "127.0.0.1:41000", 600)
        + ss_line("tcp", "ESTAB", "127.0.0.1:5432", "127.0.0.1:40000", 420),
        ss_after=listen + ss_line("tcp", "ESTAB", "127.0.0.1:5432", "127.0.0.1:40000", 420))
    unexplained = recorded_sample(work, 80, validate_doc(
        processes__missing_list=[{"pid": 300, "ps_before": "nginx", "ps_after": "nginx"}],
        processes__false_positive_list=[{"pid": 12, "comm": "ghost"}],
        modules__extra_list=["rootkit"], sockets__extra_list=[sock("TCP", "10.0.2.15", 43210, "1.2.3.4", 4444)]),
        ss_before=listen, ss_after=listen)
    discarded = recorded_sample(work, 100, validate_doc(), late=True)
    path = comparison(tmp_path, [agree, explained, unexplained, discarded],
                      [crosscheck_doc(work, 0), crosscheck_doc(work, 360, agree=False)])
    doc = pp.build_table([path], "python -m skuska.pozemna_pravda table --compare x --out y")
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert doc["schema"] == pp.TABLE_SCHEMA
    rows = {r["seq"]: r for r in doc["values"]["samples"]}
    assert all(rows[40][name]["verdict"] == "agree" for name in ("ps", "lsmod", "ss"))
    assert rows[40]["during"] == {"class": "event", "occurrence": 0, "type": "zataz_pamate"}
    assert {name: rows[60][name]["verdict"] for name in ("ps", "lsmod", "ss")} == dict.fromkeys(
        ("ps", "lsmod", "ss"), "explained")
    why = {(d["kind"], json.dumps(d["item"], sort_keys=True)): d["explanation"] for name in ("ps", "lsmod", "ss")
           for d in rows[60][name]["differences"]}
    assert [w.split(":")[0] for w in why.values()] == [
        "TRUNCATED_RULE", "PS_SHORT_RULE", "PS_NAME_RULE", "TRUNCATED_RULE", "SS_HOLDER_RULE", "SS_ONE_RUN_RULE",
        "SS_UNBOUND_RULE", "SS_SHORT_RULE"]
    assert {name: rows[80][name]["verdict"] for name in ("ps", "lsmod", "ss")} == dict.fromkeys(
        ("ps", "lsmod", "ss"), "unexplained")
    assert all(d["explanation"] is None for name in ("ps", "lsmod", "ss") for d in rows[80][name]["differences"])
    assert rows[100]["status"] == "discarded" and rows[100]["discarded"][0].startswith("(d) ps_pred ended")
    full = {r["seq"]: r["verdict"] for r in doc["values"]["full"]}
    assert full == {0: "agree", 360: "unexplained"}
    counts = doc["values"]["counts"]["a"]
    assert (counts["samples"], counts["compared"], counts["discarded"], counts["discarded_by_reason"]) == (
        4, 3, 1, {"(d)": 1})
    assert counts["sources"]["ps"] == {"agree": 1, "explained": 1, "unexplained": 1}
    assert counts["minimums"] == {"compared": {"n": 3, "min": 30, "met": False},
                                  "during_event": {"n": 3, "min": 10, "met": False},
                                  "full_crosschecked": {"n": 2, "min": 5, "met": False},
                                  "unexplained": {"n": 4, "max": 0, "met": False}}
    assert doc["values"]["met"] is False and counts["during_by_type"] == {"zataz_pamate": 3}
    with pytest.raises(pp.Refused, match="two comparisons of the session"):
        pp.build_table([path, path])
    Path(agree["commands"][0]["file"]).write_text("changed\n")
    with pytest.raises(pp.Refused, match="differs from its recorded sha256"):
        pp.build_table([path])


def test_the_minimums_are_met_by_two_sessions_of_a_vm(tmp_path):
    """32 agreeing samples of two sessions, 12 of them during an event, and 5 agreeing full snapshots: the VM meets
    the criterion; a session at low intensity does not count toward it."""
    paths = []
    for k, sid in enumerate(("g2-a-p01-1", "g2-a-p03-1")):
        work = tmp_path / sid
        work.mkdir()
        samples = [recorded_sample(work, 40 + 10 * j, validate_doc(), start=(1100.0 if j < 6 else 2000.0) + j * 50)
                   for j in range(16)]
        full = [crosscheck_doc(work, seq) for seq in ((0, 360, 720) if k == 0 else (0, 360))]
        paths.append(comparison(work, samples, full, session_id=sid))
    doc = pp.build_table(paths)
    assert doc["values"]["counts"]["a"]["minimums"] == {
        "compared": {"n": 32, "min": 30, "met": True}, "during_event": {"n": 12, "min": 10, "met": True},
        "full_crosschecked": {"n": 5, "min": 5, "met": True}, "unexplained": {"n": 0, "max": 0, "met": True}}
    assert doc["values"]["met"] is True


# ------------------------------------------------------------------ the comparison on a restored copy

def archived_session(tmp_path):
    """A recorded ground-truth session: raw/ with guestparse/tests/data/mini.vmicd as the full snapshot of seq 0 and
    its sidecar, archived by collection_archive.archive_session (the profile beside it afterwards, as links to the
    repository's profile, which work across file systems);
    the sampler's files of one sample of seq 0 and the session's record as skuska/g2.py writes it."""
    g2_dir = tmp_path / "G2"
    sid = "g2-a-p01-1"
    session = tmp_path / "diag" / "a" / sid
    (session / "raw").mkdir(parents=True)
    image = session / "raw" / f"{NAME}_000000_20261126T120000000Z.vmicd"
    image.write_bytes(MINI.read_bytes())
    side = {"schema": "vmicollect/1", "seq": 0, "timestamp_unix": 1000.0, "sched": {"lateness_s": 0.02},
            "capture": {"total_ms": 2500.0}, "output": {"full": True}}
    (session / "raw" / f"{NAME}_000000_20261126T120000000Z.json").write_text(json.dumps(side))
    (session / "protocol.json").write_bytes(V5.read_bytes())
    profile = {p.name: sha(p) for p in PROFILE.iterdir() if p.is_file()}
    meta = {"schema": collection.SESSION_SCHEMA, "session_id": sid, "campaign_id": "g2", "profile_sha256": profile,
            "guest_before": {"boot_id": "00000000-0000-4000-8000-000000000001"}}
    (session / "session.json").write_text(json.dumps(meta))
    (session / "events.json").write_text(json.dumps({"schema": "hyptcn3/session-events/1", "events": [
        {"type": "zataz_pamate", "host_start_unix": 900.0, "host_started_unix": 902.0, "host_stop_unix": 1100.0,
         "host_stopped_unix": 1101.0, "start": {"ok": True}}]}))
    archive = g2_dir / "session" / "a" / sid
    collection_archive.archive_session(session, archive, lambda: None)
    (session / "profile").mkdir()
    for p in PROFILE.iterdir():
        if p.is_file():
            (session / "profile" / p.name).symlink_to(p)
    truth = pp.truth_dir(g2_dir, sid)
    truth.mkdir(parents=True)
    pids = "\n".join(f"{x['pid']} {x['comm']}" for x in json.loads(
        (ROOT / "guestparse/tests/data/mini.json").read_text())["observed"]["processes"])
    texts = {"ss_pred": SS_HEAD + ss_line("tcp", "LISTEN", "0.0.0.0:8080", "0.0.0.0:*", 500), "ss_po": SS_HEAD,
             "ps_pred": pids + "\n700 ps\n", "ps_po": pids + "\n710 ps\n",
             "lsmod": "Module Size Used by\nbinfmt_misc 24576 1\nnls_ascii 16384 1\nnls_cp437 20480 1\n"}
    commands = []
    for name, at in (("ss_pred", 993.0), ("ps_pred", 995.0), ("ps_po", 1003.0), ("ss_po", 1004.0), ("lsmod", 1005.0)):
        path = truth / f"000000_{name}.txt"
        path.write_text(texts[name])
        commands.append({"name": name, "command": "x", "start_unix": at, "end_unix": at + 0.8, "exit_code": 0,
                         "stderr": "", "file": str(path), "sha256": sha(path), "bytes": 1, "stderr_file": None})
    sidecar = pp.sidecar_record(session / "raw" / f"{NAME}_000000_20261126T120000000Z.json")
    (truth / pp.SAMPLES_FILE).write_text(json.dumps({"seq": 0, "where": "event", "event": 0, "status": "sampled",
                                                     "why": None, "commands": commands, "sidecar": sidecar}) + "\n")
    summary = truth / pp.SUMMARY_FILE
    summary.write_text(json.dumps({"values": {"files": {pp.SAMPLES_FILE: sha(truth / pp.SAMPLES_FILE)}}}))
    record = g2_dir / "zaznamy" / f"{sid}.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps(g2.header(g2.SESSION_SCHEMA, "block", 4, {
        "session_id": sid, "vm": "a", "kind": "pozemna_pravda", "scenario": "corp_high", "session_dir": str(session),
        "session_json_sha256": sha(session / "session.json"),
        "archive": {"destination": str(archive), "manifest_sha256": sha(archive / collection_archive.MANIFEST)},
        "beside": [{"hook": "load"}, {"hook": "pozemna_pravda", "summary": str(summary), "sha256": sha(summary)}],
        "excluded": {"criteria": list(pp.EXCLUDED), "rule": pp.EXCLUDED_RULE}}, guest={"vm": "a"})))
    return {"g2_dir": g2_dir, "sid": sid, "session": session, "truth": truth, "record": record}


def run_validate(ran):
    """The comparison's children in-process: the real guestparse validate, and a recorded output of crosscheck (its
    shape as features/cli.py cmd_crosscheck writes it; mini.vmicd has no sidecar of the collector to compare)."""
    def run(argv, log):
        ran.append(argv)
        if argv[2] == "guestparse":
            assert Path(argv[argv.index("--snapshot") + 1]).name == "raw"
            with Path(log).open("x") as stream, redirect_stdout(stream):
                return guest_cli.main(argv[3:])
        assert argv[argv.index("--c") + 1].endswith(".json") and argv[argv.index("--bin-bytes") + 1] == "16777216"
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps({"values": {"snimky": [{
            "seq": 0, "invariant": {"zhoda": True}, "porovnanie": {"zhoda": True, "rozdielov": 0},
            "c_vystup": {"dostupny": True}}]}}))
        return 0
    return run


def test_the_comparison_restores_the_archive_and_runs_validate(tmp_path, monkeypatch):
    """End to end on recorded files: compare restores the archive with restore_raw (the reserve of the protocol's
    min_free_gib asked for), runs the real guestparse validate on the restored raw/ (in-process; mini.vmicd holds no
    page of the boot id, so the recorded boot is not checked here) and crosscheck on its full snapshot, writes its
    record outside the session's directory and removes the restored copy; the table reads it."""
    s = archived_session(tmp_path)
    g2_dir, sid, session, truth, record = (s[k] for k in ("g2_dir", "sid", "session", "truth", "record"))
    monkeypatch.setattr(guest_view, "capture_boot_id", lambda image_path, explicit=None: None)
    asked, ran = {}, []

    def restore(destination, target, reserve_bytes):
        asked["reserve"] = reserve_bytes
        return collection_archive.restore_raw(destination, target, reserve_bytes=0)
    run = run_validate(ran)
    with pytest.raises(pp.Refused, match=r"the host is not quiet \(collector of hyptcn-lab-b: \[77\]\)"):
        pp.compare(record, g2_dir=g2_dir, run=run, restore=restore,
                   running=lambda p: {"collector of hyptcn-lab-b": [77]})
    assert not list(truth.glob("porovnanie_*")) and ran == []
    out = pp.compare(record, g2_dir=g2_dir, run=run, restore=restore, running=lambda p: {}, command="compare")
    assert asked["reserve"] == P["min_free_gib"] * 2 ** 30 and [argv[3] for argv in ran] == ["validate", "crosscheck"]
    doc = json.loads(out.read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc) and out.parent.parent == truth
    v = doc["values"]
    assert v["restored"]["removed"] is True and not (out.parent / "obnova").exists()
    assert v["restored"]["session_id"] == sid and v["intensity"] == "high"
    [row] = v["samples"]
    assert row["discarded"] == [] and row["validate"]["exit_code"] == 0 and row["stable_ss"]["sockets"] == 0
    result = json.loads(Path(row["validate"]["out"]).read_text())
    assert (result["processes"]["found"], result["processes"]["stable"], result["modules"]["matched"]) == (8, 8, 3)
    assert [f["seq"] for f in v["full"]] == [0]
    assert not [p for p in listing(session) if "porovnanie" in p or "validate" in p]
    table = pp.build_table([out])
    [sample] = table["values"]["samples"]
    assert {name: sample[name]["verdict"] for name in ("ps", "lsmod", "ss")} == dict.fromkeys(("ps", "lsmod", "ss"),
                                                                                             "agree")
    assert sample["during"]["class"] == "event" and table["values"]["full"][0]["verdict"] == "agree"


def test_a_failed_comparison_removes_its_restored_copy(tmp_path, monkeypatch):
    """An error after the restore leaves no restored copy (its marker names the session) and no comparison record;
    with --keep-restored the copy stays."""
    s = archived_session(tmp_path)
    monkeypatch.setattr(guest_view, "capture_boot_id", lambda image_path, explicit=None: None)
    stamps = iter(["20261126T000001Z", "20261126T000002Z"])
    monkeypatch.setattr(g2, "stamp", lambda: next(stamps))

    def restore(destination, target, reserve_bytes):
        return collection_archive.restore_raw(destination, target, reserve_bytes=0)

    def broken(argv, log):
        raise OSError("disk full")
    with pytest.raises(OSError, match="disk full"):
        pp.compare(s["record"], g2_dir=s["g2_dir"], run=broken, restore=restore, running=lambda p: {})
    work = s["truth"] / "porovnanie_20261126T000001Z"
    assert work.is_dir() and not (work / "obnova").exists() and not (work / "porovnanie.json").exists()
    out = pp.compare(s["record"], g2_dir=s["g2_dir"], keep=True, run=run_validate([]), restore=restore,
                     running=lambda p: {})
    v = json.loads(out.read_text())["values"]
    assert v["restored"]["removed"] is False and (out.parent / "obnova" / "raw" / "restored_from.json").is_file()
    assert v["restored"]["marker_sha256"] == sha(out.parent / "obnova" / "raw" / "restored_from.json")
    assert pp.remove_restored(out.parent / "obnova", "another session") is False
    assert pp.remove_restored(out.parent / "obnova", s["sid"]) is True and not (out.parent / "obnova").exists()


def test_a_quiet_host_has_no_collector_and_no_lab_trial_on_a_vm():
    """COMPARE_RULE: the comparison waits for a host where no collector reads a VM of the protocol and no lab trial
    runs on a VM; a lab trial without a VM (record) and a process that only names them do not count."""
    procs = [(10, [b"vmicollect/build/vmicollect", b"run", b"-o", b"vm.domain=hyptcn-lab-b", b"-o", b"x"]),
             (11, [b"/usr/bin/python3", b"scripts/lab_trial.py", b"long", b"--vm", b"a", b"--minutes", b"60"]),
             (12, [b"/usr/bin/python3", b"scripts/lab_trial.py", b"record", b"--out-record", b"r.json"]),
             (13, [b"grep", b"lab_trial.py --vm a"]), (14, [b"vmicollect/build/vmicollect", b"vm.domain=other"])]
    assert pp.busy_host(P, lambda: procs) == {"collector of hyptcn-lab-b": [10], "lab_trial.py on a VM": [11]}
    assert pp.busy_host(P, lambda: procs[2:]) == {}


def test_the_comparison_reads_only_an_archived_session(tmp_path):
    record = tmp_path / "zaznamy" / "g2-a-p01-1.json"
    record.parent.mkdir()
    record.write_text(json.dumps({"schema": g2.SESSION_SCHEMA, "values": {"session_id": "g2-a-p01-1",
                                                                          "archive": None}}))
    with pytest.raises(pp.Refused, match="has no archive: the comparison reads a restored copy only"):
        pp.compare(record, g2_dir=tmp_path, running=lambda p: {})
    record.write_text("{}")
    with pytest.raises(pp.Refused, match="is no record of a G2 session"):
        pp.compare(record, g2_dir=tmp_path)


def test_the_plan_command_writes_the_plan_once(tmp_path, capsys):
    out = tmp_path / "pravda.json"
    assert pp.main(["plan", "--protocol", str(V5), "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["sessions"] == 4
    assert pp.main(["plan", "--protocol", str(V5), "--out", str(out)]) == 2
    assert "drawn once and never changed" in capsys.readouterr().err


def test_the_dry_run_of_a_block_starts_nothing(tmp_path, deck_file, plan_file):
    b, lab = block(tmp_path, deck_file)
    b.deck, b.deck_sha256 = g2.load_deck(deck_file, P)
    plan = pp.block_plan(b, specs_of(b, plan_file))
    assert plan["refusals"] == [] and [s["session_id"] for s in plan["sessions"]] == ["g2-a-p01-1", "g2-a-p03-1"]
    assert all(s["command"][4] == "run" and "--events" in s["command"] for s in plan["sessions"])
    assert plan["guest_commands"]["ps_pred"][-1] == pp.PS
    assert base.steps_of(lab) == [] and not (tmp_path / "G2").exists()
