"""The worst case of time of G2 (skuska/cas.py, package H1b4): the plan of the 4 pairs, the definitions of the modes
on fake sidecars, the timing of a pair, the restart rule, and the audit and archive of a session against the
campaign's own, with fakes of every lab and root step (no VM, no root, no process, nothing outside tmp_path).
"""
import fcntl
import json
import os
from pathlib import Path
import signal

import pytest

from scripts import campaign, collection, protocol_v5
from skuska import cas, g2
from skuska.tests import cas_fakes, test_g2

ROOT = Path(__file__).resolve().parents[2]
V5 = test_g2.V5
P = test_g2.P


def side(seq, start, total_ms=2000.0, late=0.002, full=True):
    """A sidecar as vmicollect writes it, only the keys the definitions read."""
    return {"schema": cas.SIDECAR_SCHEMA, "seq": seq, "timestamp_unix": start, "sched": {"lateness_s": late},
            "capture": {"total_ms": total_ms}, "output": {"full": full}}


def cycles(due0, total_ms=(2000.0, 2200.0)):
    """{seq: cycle} of the two full snapshots of a session whose seq 0 was due at due0."""
    return {seq: cas.cycle(side(seq, due0 + seq * 5 + 0.002, total)) for seq, total in zip((0, 360), total_ms)}


def windows(due0, audit=None, archive=None):
    """The data of judge() for one session: its full cycles, its zataz_pamate window and its audit and archive."""
    start = due0 - 1.0
    return {"full": cycles(due0), "load": [start + 1682, start + 1980], "audit": audit, "archive": archive}


# ------------------------------------------------------------------ the plan

def test_the_plan_has_four_pairs_two_per_mode_with_the_vms_swapped():
    """Q58: 2 pairs per mode; cas3 and cas4 shifted with the VMs swapped (each VM collects once during the other's
    audit and archive), the target audit in cas3 and archive in cas4; the high scenarios once in each mode; 8
    sessions, 4 per VM."""
    plan = cas.draw_plan(P)
    pairs = {x["id"]: x for x in plan["pairs"]}
    assert list(pairs) == ["cas1", "cas2", "cas3", "cas4"]
    assert [x["mode"] for x in plan["pairs"]] == [cas.AT_ONCE, cas.AT_ONCE, cas.SHIFTED, cas.SHIFTED]
    assert (pairs["cas3"]["order"], pairs["cas4"]["order"]) == (["a", "b"], ["b", "a"])
    assert [s["role"] for s in pairs["cas3"]["sessions"]] == [cas.FIRST, cas.SECOND]
    assert (pairs["cas3"]["target"], pairs["cas4"]["target"], pairs["cas1"]["target"]) == ("audit", "archive", None)
    collecting = {pairs[pid]["sessions"][1]["vm"] for pid in ("cas3", "cas4")}
    assert collecting == {"a", "b"}
    high = cas.high_scenarios(P)
    assert high == ["corp_high", "eshop_high"]
    for mode in (cas.AT_ONCE, cas.SHIFTED):
        assert sorted(x["scenario"] for x in plan["pairs"] if x["mode"] == mode) == high
    sessions = [(s["vm"], x["id"]) for x in plan["pairs"] for s in x["sessions"]]
    assert len(sessions) == 8 and all(sum(vm == v for v, _ in sessions) == 4 for vm in "ab")
    assert plan["target_seq"] == P["full_every"] == 360


def test_the_plan_s_events_and_seeds():
    """Map row 10: the three events, admitted by collection.diagnostic_events as --events, zataz_pamate across seq
    360 with a minute on each side; the seeds are deck_seed with the group G2/<pair>, none of the plan's or the
    deck's."""
    plan = cas.draw_plan(P)
    assert json.loads(plan["argument"]) == [dict(x) for x in cas.EVENTS]
    assert collection.diagnostic_events(P, plan["argument"], P["cycles"]) == plan["events"]
    load = next(x for x in plan["events"] if x["type"] == cas.LOAD)
    assert load["start_s"] + 60 <= 360 * 5 <= load["start_s"] + load["duration_s"] - 60
    ours = set()
    for pair in plan["pairs"]:
        for s in pair["sessions"]:
            assert s["seed"] == protocol_v5.seed(P["name"], "traffic", f"G2/{pair['id']}", ["a", "b"].index(s["vm"]), 1)
            ours.add(s["seed"])
    assert len(ours) == 8
    deck = g2.draw_deck(P)
    theirs = {seed for s in deck["sessions"] for seed in s["seeds"].values()}
    for mode in protocol_v5.MODES:
        theirs |= {seed for s in protocol_v5.plan(P, mode)["sessions"] for seed in s["seeds"].values()}
    assert not ours & theirs
    assert cas.draw_plan(P) == plan


def test_the_plan_file_is_written_once_and_refused_when_edited(tmp_path):
    path = tmp_path / "cas_plan.json"
    doc = cas.write_plan(V5, path, "python -m skuska.cas plan")
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc) and doc["n"] == 4
    assert doc["values"]["rules"]["modes"] == cas.MODES_RULE and doc["values"]["protocol_sha256"] == test_g2.sha(V5)
    with pytest.raises(cas.Refused, match="exists: it is drawn once and never changed"):
        cas.write_plan(V5, path, "again")
    assert cas.load_plan(path, P)[1] == test_g2.sha(path)
    doc = json.loads(path.read_text())
    doc["values"]["pairs"][2]["order"] = ["b", "a"]
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(doc))
    with pytest.raises(cas.Refused, match=r"differs from the plan its rule draws from this protocol \(pairs\)"):
        cas.load_plan(edited, P)


def test_a_protocol_whose_load_misses_the_target_is_refused():
    """zataz_pamate must hold across seq full_every: a protocol whose second full snapshot is at 3000 s (the events
    still admitted) cannot hold the plan."""
    p = dict(P, full_every=600)
    assert collection.diagnostic_events(p, cas.argument(), p["cycles"])
    with pytest.raises(ValueError, match=r"zataz_pamate does not hold across seq 600 \(3000 s\)"):
        cas.draw_plan(p)


# ------------------------------------------------------------------ the definitions on fake sidecars

AT = {"id": "cas1", "mode": cas.AT_ONCE, "order": ["a", "b"], "target": None}
SH = {"id": "cas3", "mode": cas.SHIFTED, "order": ["a", "b"], "target": "audit"}


def test_at_once_met_when_the_target_cycles_overlap():
    t = 1_790_000_000.0
    data = {"a": windows(t), "b": windows(t + 0.8)}
    j = cas.judge(AT, data, 360)
    assert (j["mode"], j["met_mode"], j["met"], j["why"]) == (cas.AT_ONCE, True, True, [])
    assert j["shift_full_s"] == pytest.approx(0.8) and j["collecting"] == "a"
    assert [(o["a"], o["b"]) for o in j["overlaps"]] == [(0, 0), (360, 360)]
    assert j["windows"]["load"] == {"a": True, "b": True}


def test_at_once_misses_its_mode_when_the_target_cycles_do_not_overlap():
    """A pair that misses its mode: the full cycles of a and b are 3 s apart (each takes 2 to 2.2 s)."""
    t = 1_790_000_000.0
    j = cas.judge(AT, {"a": windows(t), "b": windows(t + 3.0)}, 360)
    assert (j["mode"], j["met_mode"], j["met"]) == (cas.SHIFTED, False, False)
    assert j["why"] == ["the target full cycles (seq 360) of VM a and VM b do not overlap"]
    assert j["shift_full_s"] == pytest.approx(3.0) and j["overlaps"] == []


def test_at_once_misses_its_plan_outside_the_load_window():
    t = 1_790_000_000.0
    data = {"a": windows(t), "b": dict(windows(t + 0.5), load=[t + 10, t + 1000])}
    j = cas.judge(AT, data, 360)
    assert j["met_mode"] and not j["met"]
    assert j["why"] == ["the target full snapshot of VM b lies outside its zataz_pamate window"]


def test_shifted_met_when_the_second_s_target_falls_into_the_first_s_audit():
    t = 1_790_000_000.0
    second = t + 2220.0  # The second's seq 0 was due 2220 s after the first's.
    target = second + 1800
    data = {"a": windows(t, audit=[target - 60, target + 840], archive=[target + 840, target + 1140]),
            "b": windows(second)}
    j = cas.judge(SH, data, 360)
    assert (j["mode"], j["met_mode"], j["met"], j["collecting"]) == (cas.SHIFTED, True, True, "b")
    assert j["windows"] == {"load": {"a": True, "b": True}, "audit": True, "archive": False,
                            "audit_and_archive": True}
    assert j["nearest"]["seq"] == 360 and j["shift_full_s"] == pytest.approx(second - t)


def test_shifted_misses_its_plan_outside_the_audit_and_archive():
    """The first's audit started after the second's target full snapshot: the pair meets its mode, not its plan."""
    t = 1_790_000_000.0
    target = t + 2220.0 + 1800
    data = {"a": windows(t, audit=[target + 30, target + 900], archive=[target + 900, target + 1200]),
            "b": windows(t + 2220.0)}
    j = cas.judge(SH, data, 360)
    assert j["met_mode"] and not j["met"]
    assert j["why"] == ["the target full snapshot of VM b lies outside the audit and archive of VM a's session"]


def test_shifted_misses_its_mode_when_full_cycles_overlap():
    """A shifted pair whose second session started half a session later: b's seq 0 falls on a's seq 360, so full
    cycles overlap, but not the targets: neither mode."""
    t = 1_790_000_000.0
    target = t + 1800.5 + 1800
    data = {"a": windows(t, audit=[target - 60, target + 900], archive=[target + 900, target + 1200]),
            "b": windows(t + 1800.5)}
    j = cas.judge(SH, data, 360)
    assert (j["mode"], j["met_mode"], j["met"]) == (cas.NEITHER, False, False)
    assert j["overlaps"] == [{"a": 360, "b": 0, "overlap_s": pytest.approx(1.7)}]
    assert j["why"] == ["a full cycle of one session overlaps a full cycle of the other"]


def test_the_sidecars_of_the_full_snapshots_are_read_from_raw(tmp_path):
    """sidecar() finds {domain}_{seq:06d}_{time}.json; one written in part is none yet; a sidecar at a seq of
    full_every that is no full snapshot is refused."""
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "hyptcn-lab-a_000000_20260921T000000000Z.json").write_text(json.dumps(side(0, 100.0)))
    (raw / "hyptcn-lab-a_000001_20260921T000005000Z.json").write_text(json.dumps(side(1, 105.0, full=False)))
    (raw / "hyptcn-lab-a_000360_20260921T003000000Z.json").write_text('{"schema": "vmicollect/1", "se')
    assert cas.sidecar(raw, 0)["timestamp_unix"] == 100.0 and cas.sidecar(raw, 360) is None
    assert cas.full_cycles(raw, 360, 720) == {0: cas.cycle(side(0, 100.0)), 360: None}
    (raw / "hyptcn-lab-a_000360_20260921T003000000Z.json").write_text(json.dumps(side(360, 1900.0, full=False)))
    with pytest.raises(ValueError, match="the sidecar of seq 360 is no full snapshot"):
        cas.full_cycles(raw, 360, 720)
    assert cas.cycle(side(0, 100.0, 1500.0, 0.25)) == {"seq": 0, "full": True, "start": 100.0, "end": 101.5,
                                                      "total_ms": 1500.0, "lateness_s": 0.25, "due": 99.75}


def test_the_timing_of_a_shifted_pair():
    """TIMING_RULE: the second run starts so that its target falls LEAD_S after the earliest audit (+ AUDIT_EST_S
    for the archive) of the first; the first's work starts LEAD_S before the second's target."""
    audit, archive = (dict(SH, target=t) for t in ("audit", "archive"))
    assert cas.second_start(P, audit, 1000.0, 150.0) == 1000.0 + 1800 + 300 + 60 + 60 - 150
    assert cas.second_start(P, archive, 1000.0, 150.0) == 1000.0 + 1800 + 300 + 60 + 60 + 1800 - 150
    assert cas.work_start(P, 5000.0) == 5000.0 + 1800 - 60


# ------------------------------------------------------------------ the block with fakes

def test_an_at_once_pair_restarts_by_the_rule_and_then_meets_its_plan(tmp_path):
    """RESTART_RULE (1): VM b's preflight is 3.5 s longer, so the seq-0 cycles of attempt 1 do not overlap: both
    sessions are archived without an audit, and attempt 2 starts b's run 3.5 s before a's; its full snapshots fall
    together, both under zataz_pamate, and the pair is done."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas1"], b={"pre": 153.5})
    result = driver.run()
    assert result["stopped"] is None
    assert [(x["attempt"], x["done"]) for x in result["attempts"]] == [(1, False), (2, True)]
    pairs = cas_fakes.pair_records(driver)
    first, second = pairs["cas1-1"]["values"], pairs["cas1-2"]["values"]
    assert first["restart"].startswith("RESTART_RULE (1): the seq-0 full cycles of VM a and VM b overlap by")
    assert first["seq0"]["go"] is False and first["seq0"]["shift_s"] == pytest.approx(3.5)
    assert (first["timing"]["delay_s"], first["timing"]["next_delay_s"]) == (0.0, -3.5)
    assert second["timing"]["delay_s"] == -3.5 and second["seq0"]["go"] is True
    starts = second["timing"]["starts_unix"]
    assert starts["a"] - starts["b"] == pytest.approx(3.5)
    assert second["judgment"]["met"] and second["judgment"]["mode"] == cas.AT_ONCE and second["done"]
    for vm, lab in labs.items():
        assert lab.unaudited == [f"g2-{vm}-cas1-1"]
        assert [e[1] for e in lab.events if e[0] == "audit"] == [f"g2-{vm}-cas1-2"]
    records = cas_fakes.session_records(driver)
    assert sorted(records) == ["g2-a-cas1-1", "g2-a-cas1-2", "g2-b-cas1-1", "g2-b-cas1-2"]
    stopped = records["g2-a-cas1-1"]["values"]
    assert stopped["error"].startswith("Restart: RESTART_RULE (1)") and stopped["done"] is False
    assert stopped["archive"]["audit"] is None and stopped["archive"]["rule"] == cas.UNAUDITED_RULE
    done = records["g2-b-cas1-2"]["values"]
    assert (done["kind"], done["deck_session"], done["attempt"], done["done"], done["counted"]) == (
        "cas", "cas1", 2, True, True)
    assert done["excluded"] == {"criteria": list(cas.EXCLUDED), "rule": cas.EXCLUDED_RULE}
    assert done["draw"]["item"] == {"pair": "cas1", "mode": cas.AT_ONCE, "role": cas.TOGETHER, "target": None,
                                    "order": ["a", "b"], "attempt": 2}
    assert [s["step"] for s in done["steps"]] == ["run", "levels", "audit", "archive"]
    assert all("started_unix" in s and "ended_unix" in s for s in done["steps"])


def test_a_shifted_pair_times_the_first_s_audit_to_the_second_s_target(tmp_path):
    """TIMING_RULE: VM b's run starts after a's seq 0, a's audit starts LEAD_S before b's target full snapshot,
    which falls into a's audit and into b's zataz_pamate window; the pair is done in one attempt."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas3"], b={"pre": 152.0})
    result = driver.run()
    assert result["stopped"] is None and [x["done"] for x in result["attempts"]] == [True]
    v = cas_fakes.pair_records(driver)["cas3-1"]["values"]
    a, b = labs["a"].runs["g2-a-cas3-1"], labs["b"].runs["g2-b-cas3-1"]
    t = v["timing"]
    assert t["first_due0_unix"] == pytest.approx(a["due0"]) and t["first_pre_s"] == pytest.approx(150.0)
    assert t["second_start_unix"] == pytest.approx(a["due0"] + 1800 + 420 - 150.0)
    assert b["start"] == pytest.approx(t["second_start_unix"], abs=1.0)
    assert t["work_unix"] == pytest.approx(b["due0"] + 1800 - 60) and t["work"] == "audit"
    audit = next(s for s in json.loads(Path(v["sessions"]["a"]["record"]).read_text())["values"]["steps"]
                 if s["step"] == "audit")
    assert audit["started_unix"] == pytest.approx(t["work_unix"], abs=1.0)
    j = v["judgment"]
    assert (j["met"], j["collecting"], j["windows"]["audit"], j["windows"]["archive"]) == (True, "b", True, False)
    assert j["grids"]["sessions"] == ["g2-a-cas3-1", "g2-b-cas3-1"]  # campaign_grids.grid_pairs: b's phase minus a's.
    assert j["grids"]["shift_s"] == pytest.approx((b["due0"] - a["due0"]) % 5, abs=1e-6)
    assert labs["b"].events.index(("run", "g2-b-cas3-1", None)) >= 0
    order = [e for e in labs["a"].events if e[0] in ("run", "levels", "audit", "archive")]
    assert order == [("run", "g2-a-cas3-1", None), ("levels",), ("audit", "g2-a-cas3-1"), ("archive", "g2-a-cas3-1")]


def test_a_shifted_pair_with_the_archive_as_its_target(tmp_path):
    """cas4: VM a collects during VM b's archive; b's audit runs as soon as its run ended, its archive waits for
    a's target."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas4"])
    driver.run()
    v = cas_fakes.pair_records(driver)["cas4-1"]["values"]
    j = v["judgment"]
    assert (v["done"], v["order"], j["collecting"], j["windows"]["audit"], j["windows"]["archive"]) == (
        True, ["b", "a"], "a", False, True)
    steps = json.loads(Path(v["sessions"]["b"]["record"]).read_text())["values"]["steps"]
    archive = next(s for s in steps if s["step"] == "archive")
    assert archive["started_unix"] == pytest.approx(v["timing"]["work_unix"], abs=1.0)


def test_an_attempt_that_misses_its_plan_at_the_end_starts_again_in_full(tmp_path):
    """RESTART_RULE (2): the seq-0 cycles overlap, but b's target cycle starts 3 s late (beyond a's): the attempt is
    judged, missed and run again; attempt 2 meets."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas2"], b={"late": {"g2-b-cas2-1": 3.0}})
    result = driver.run()
    assert [(x["attempt"], x["done"]) for x in result["attempts"]] == [(1, False), (2, True)]
    first = cas_fakes.pair_records(driver)["cas2-1"]["values"]
    assert first["restart"] is None and first["judgment"]["met"] is False
    assert first["why"] == ["the target full cycles (seq 360) of VM a and VM b do not overlap"]
    assert [e[1] for e in labs["a"].events if e[0] == "audit"] == ["g2-a-cas2-1", "g2-a-cas2-2"]


def test_the_attempts_of_a_pair_are_limited(tmp_path):
    """RESTART_RULE (3): after MAX_ATTEMPTS the block stops by name, and a pair that used them is refused."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas1"], b={"pre": 160.0})
    for lab in labs.values():  # The delay never catches up: every attempt's b runs 10 s later than a.
        lab.offsets = {f"g2-b-cas1-{k}": 10.0 * k for k in range(1, 20)}
    result = driver.run()
    assert result["stopped"].startswith("pair cas1 did not meet its plan in 8 attempts (RESTART_RULE)")
    assert len(cas_fakes.pair_records(driver)) == 8
    again, _, _ = cas_fakes.setup(tmp_path / "x", only=["cas1"])
    again.dir.mkdir(parents=True)
    for name, doc in cas_fakes.pair_records(driver).items():
        (again.dir / f"{name}.json").write_text(json.dumps(doc))
    with pytest.raises(cas.Refused, match="pair cas1 used its 8 attempts"):
        again.run()


def test_a_run_that_exits_non_zero_stops_the_block_after_the_records(tmp_path):
    """RESTART_RULE (4): a failed run is a finding, never a restart: both sessions recorded, the block stops."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas1", "cas2"], a={"rc": {"g2-a-cas1-1": 1}})
    result = driver.run()
    assert "the run of g2-a-cas1-1 exited 1" in result["stopped"]
    assert [x["pair"] for x in result["attempts"]] == ["cas1"]
    v = cas_fakes.pair_records(driver)["cas1-1"]["values"]
    assert v["judgment"] is None and v["done"] is False and v["stop"] == result["stopped"]
    assert sorted(cas_fakes.session_records(driver)) == ["g2-a-cas1-1", "g2-b-cas1-1"]


def test_refusals_before_the_block(tmp_path):
    """A null rate high, a run without root and a heavy process refuse the block before anything starts."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas1"])
    doc = json.loads(driver.protocol_path.read_text())
    doc["scenarios"]["corp_high"]["rate"] = None
    driver.protocol_path.write_text(json.dumps(doc, indent=2) + "\n")
    plan = tmp_path / "plan2.json"
    cas.write_plan(driver.protocol_path, plan, "test")
    labs["a"].root = False
    labs["b"].procs = [(5, ["python3", "-m", "pytest", "-q"])]
    again = cas.Driver(driver.protocol_path, driver.deck_path, plan, only=["cas1"], places=driver.places, labs=labs,
                       clock=clock, command="test", threads=False)
    with pytest.raises(cas.Refused) as refused:
        again.run()
    text = str(refused.value)
    for words in ("scenario corp_high has no rate (Zápis 1 of G2 first)", "runs as root through sudo",
                  "VM b: heavy: a pytest that names no test file"):
        assert words in text
    assert not again.dir.exists() and all(not lab.commands for lab in labs.values())


def test_a_block_without_a_pair_left_is_refused(tmp_path, monkeypatch):
    """Every pair has a done attempt: the block refuses to start, and --only runs a pair again."""
    driver, labs, clock = cas_fakes.setup(tmp_path, only=["cas3"])
    driver.run()
    again = cas.Driver(driver.protocol_path, driver.deck_path, driver.plan_path, places=driver.places, labs=labs,
                       clock=clock, command="test", threads=False)
    again.dir.mkdir(exist_ok=True)
    for pid in ("cas1", "cas2", "cas4"):
        (again.dir / f"{pid}-1.json").write_text(json.dumps({"schema": cas.PAIR_SCHEMA, "values": {
            "pair": pid, "attempt": 1, "done": True, "timing": {}}}))
    with pytest.raises(cas.Refused, match="every pair of the plan is done"):
        again.run()
    monkeypatch.setattr(g2, "stamp", lambda: "20990101T000000Z")  # Another block id than the first block's second.
    once_more = cas.Driver(driver.protocol_path, driver.deck_path, driver.plan_path, only=["cas3"],
                           places=driver.places, labs=labs, clock=clock, command="test", threads=False)
    assert [x["attempt"] for x in once_more.run()["attempts"]] == [2]


def test_the_dry_run_names_the_commands_of_the_next_attempt(tmp_path):
    driver, labs, clock = cas_fakes.setup(tmp_path)
    view = driver.plan_view()
    assert view["refusals"] == [] and [x["pair"] for x in view["pairs"]] == ["cas1", "cas2", "cas3", "cas4"]
    row = view["pairs"][3]
    assert (row["order"], row["target"], row["attempt"], row["delay_s"]) == (["b", "a"], "archive", 1, None)
    command = row["commands"]["a"]
    assert command[command.index("--session-id") + 1] == "g2-a-cas4-1"
    assert json.loads(command[command.index("--events") + 1]) == [dict(x) for x in cas.EVENTS]
    assert "--rate" not in command and command[command.index("--campaign-id") + 1] == "g2"
    assert all(not lab.commands for lab in labs.values()) and not driver.dir.exists()


# ------------------------------------------------------------------ the campaign's own audit, archive and lock

def root_view(monkeypatch):
    """collection's view of a run as root through sudo, so background_command and user_command give the campaign's
    command lines in full (the scope, the priority, runuser); nothing is run."""
    monkeypatch.setattr(collection.os, "geteuid", lambda: 0)
    monkeypatch.setattr(collection.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setenv("SUDO_USER", os.environ.get("USER") or "eh")


class Captured(Exception):
    pass


def campaign_audit_command(tmp_path, monkeypatch, session):
    """The audit command line of campaign.audit_capture, built by campaign.py's own code (run_child replaced)."""
    directory = tmp_path / "kampan"
    (directory / "events").mkdir(parents=True)
    (directory / "attempts").mkdir()
    (directory / "protocol.json").write_bytes(V5.read_bytes())
    seen = {}

    def run_child(command, log, *, timeout, guard=lambda: None, lock_fd=None, grace=150):
        seen.update(command=[str(x) for x in command], timeout=timeout)
        raise Captured()
    monkeypatch.setattr(campaign, "run_child", run_child)
    with pytest.raises(Captured):
        campaign.audit_capture(directory, {"id": "kampan", "vm": "a"}, P, {"session_id": session.name, "vm": "a"},
                               session, lambda: None)
    return seen


def masked(command):
    """A command line with the paths that differ between two sessions masked: the protocol, the session, the out."""
    names = {"--protocol": "<protocol>", "audit": "<session>", "--out": "<out>"}
    return [names.get(before, x) for before, x in zip([None, *command[:-1]], command)]


def test_the_audit_of_a_timing_session_is_the_campaign_s_command_line(tmp_path, monkeypatch):
    """The audit of the other VM's session runs as campaign.audit_capture runs it: background_command's scope
    (MemoryHigh=3G, MemorySwapMax=0, CPUWeight, IOWeight), its priority (nice 19, ionice), user_command's runuser, the
    same timeout; only the paths of the protocol copy, the session and the report differ."""
    root_view(monkeypatch)
    session = tmp_path / "diag" / "a" / "g2-a-cas3-1"
    session.mkdir(parents=True)
    campaign_side = campaign_audit_command(tmp_path, monkeypatch, session)
    driver, labs, clock = cas_fakes.setup(tmp_path / "blok", only=["cas3"])
    ours = [str(x) for x in driver.blocks["a"].audit_command(session, session / "audit_x.json")]
    assert masked(ours) == masked(campaign_side["command"])
    for words in (["systemd-run", "--scope"], ["-p", "MemoryHigh=3G"], ["-p", "MemorySwapMax=0"],
                  ["nice", "-n", "19"], ["ionice", "-c", "2", "-n", "7"], ["runuser", "-u"]):
        assert any(ours[i:i + len(words)] == words for i in range(len(ours)))
    assert ours[ours.index("--protocol") + 1] == str(session / "protocol.json")
    driver.run()  # The timeout of the driver's audit child is the campaign's.
    timeouts = [t for command, t in labs["a"].commands if "audit" in command]
    assert timeouts == [campaign_side["timeout"]] == [max(600, P["cycles"] * 15)]


def test_the_archive_of_a_timing_session_is_the_campaign_s(tmp_path, monkeypatch):
    """The archive runs collection_archive.archive_session with campaign.archive_capture's options (the reclaim, the
    reserve of min_free_gib, zstd, bound to the audit; without an audit for a stopped run, as the campaign archives
    an incomplete capture); only the campaign id (g2) and the paths differ."""
    seen = []
    monkeypatch.setattr(campaign, "archive_session", lambda *a, **k: seen.append((a, k)) or {})
    directory = tmp_path / "kampan"
    (directory / "events").mkdir(parents=True)
    manifest = {"id": "kampan", "vm": "a", "archive_dir": str(tmp_path / "hdd"), "archive_root": str(tmp_path),
                "archive_mount": {}, "archive_compression": "zstd"}
    session = tmp_path / "s"
    campaign.archive_capture(directory, manifest, session, P, audit=session / "campaign_audit_x.json")
    campaign.archive_capture(directory, manifest, session, P)
    driver, labs, clock = cas_fakes.setup(tmp_path / "blok", only=["cas1"], b={"pre": 153.5})
    driver.run()
    ours = [options for source, _, options in labs["a"].archives]
    assert [o["audit"] is None for o in ours] == [True, False]  # Attempt 1 stopped by the rule, attempt 2 audited.
    for (_, theirs), mine in zip(reversed(seen), ours):  # The campaign's call without an audit first.
        assert set(theirs) == set(mine)
        assert {k: v for k, v in theirs.items() if k not in ("campaign_id", "audit")} == {
            k: v for k, v in mine.items() if k not in ("campaign_id", "audit")}
        assert (theirs["audit"] is None) == (mine["audit"] is None)
        assert (theirs["campaign_id"], mine["campaign_id"]) == ("kampan", g2.CAMPAIGN_ID)
    assert ours[1]["reclaim"] is True and ours[1]["compress"] == "zstd" and ours[1]["reserve_bytes"] == 30 * 2 ** 30


def test_the_timing_lab_takes_campaign_audit_lock_and_passes_the_guard(tmp_path, monkeypatch):
    """TimingLab.audit_lock is campaign.audit_lock (one audit or archive on the host at a time: the lock file of
    data/collections, here under tmp_path), and TimingLab.child passes the run's guard to campaign.run_child, which
    stops the child with SIGTERM when the guard raises Restart (RESTART_RULE (1))."""
    monkeypatch.setattr(campaign, "COLLECTIONS", tmp_path / "collections")
    lab = cas.TimingLab(V5, collection.for_vm(P, "a"), tmp_path / "state")
    (tmp_path / "state" / "events").mkdir(parents=True)
    with lab.audit_lock(print):
        fd = os.open(tmp_path / "collections" / ".audit.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    signals, groups = [], []

    class Process:
        pid = 424242

        def poll(self):
            return None if not signals else -15

        def send_signal(self, sig):
            signals.append(sig)

        def wait(self, timeout=None):
            return -15

    monkeypatch.setattr(campaign.subprocess, "Popen", lambda *a, **k: Process())

    def killpg(pid, sig):
        groups.append((pid, sig))
        raise ProcessLookupError
    monkeypatch.setattr(campaign.os, "killpg", killpg)

    def guard():
        raise cas.Restart("the seq-0 cycles do not overlap")
    lab.stop_check = guard
    with pytest.raises(cas.Restart, match="do not overlap"):
        lab.child(["true"], tmp_path / "run.log", timeout=60)
    assert signals == [signal.SIGTERM] and groups == [(424242, signal.SIGTERM), (424242, signal.SIGKILL)]
