"""The mode load of scripts/campaign_report.py (package H1b6b of stage G2): the offered and delivered load of the G2
sessions per scenario and VM, the load delivered in the event windows, the drop reasons and the return to the defined
state, criterion profiles_load (map row 5, the lead's answer to Q63).

The traffic logs are those of the real generator: scripts/host_traffic.py prepare_v5, SessionRecorder, UserClient and
OpenLoop on the fake clock and the fake lab of scripts/tests/test_host_traffic_v5.py fake_run (one run per scenario at
--rate 0.5 for 480 s, and one eshop run with a cap of 3 user sessions, which drops), copied into each session with its
session id. Around them the files the capture, the driver and the start of a group leave are written here: session.json
of a diagnostic run, protocol.json (the generator's copy), events.json with one occurrence in the measure phase,
guest/levels_before.json and guest/state_after.json, the record of the group's start with its reset, and the session's
G2 record with the levels after it. The expected counts are counted here from the logs, never by the mode's code. No
VM, no network, nothing written outside the test's directories.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from scripts import campaign_report as cr
from scripts.collection_logs import REQUIRED_UNITS
from scripts.tests import test_host_traffic_v5 as gen

ROOT = Path(__file__).resolve().parents[2]
P = json.loads(gen.V5.read_text())  # The protocol the fake runs read: the file as G0 recorded it.
SCENARIOS = sorted(P["scenarios"])
PROVENANCE = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.
LOGS = ("traffic_requests.jsonl", "traffic_intervals.jsonl")
WALL = 1.8e9  # The fake clock's wall time at its 0 (test_host_traffic_v5.FakeClock).
DUR, RATE = 480.0, 0.5
EVENT = (200.0, 260.0)  # The start and the stop call of the one occurrence, in the fake clock's time.
GRACE = P["events"]["grace_s"]
RESET = {"schema": "hyptcn3/guest-reset/1", "seed": 0, "data_sha256": "ab" * 32,
         "counts": {"products": 5000, "customers": 2000, "employees": 200, "orders": 3000, "order_items": 7000,
                    "cart_items": 400, "documents": 500}, "documents_bytes": 123456789, "started_unix": 1.79e9,
         "finished_unix": 1.79e9 + 40}


@pytest.fixture(autouse=True)
def one_git_state(monkeypatch):
    monkeypatch.setattr(cr, "git_identity", lambda: {"commit": "synthetic", "dirty": False, "changed_paths": 0})


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=1) + "\n")


def iso(unix):
    return datetime.fromtimestamp(unix, timezone.utc).isoformat(timespec="seconds")


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """{scenario or "capped": the directory of one fake run}: its two logs and its protocol.json."""
    base = tmp_path_factory.mktemp("runs")
    out = {}
    for name, (profile, scenario, cap) in {**{s: (P["scenarios"][s]["profile"], s, None) for s in SCENARIOS},
                                           "capped": ("eshop", "eshop_high", 3)}.items():
        d = base / name
        gen.fake_run(d, profile, scenario, cap=cap, session_id="RUN", dur=DUR, rate=RATE, requests_log=d / LOGS[0],
                     intervals_log=d / LOGS[1])
        out[name] = d
    return out


def levels(products=5000, orders=3001, order_items=7001, processes=120, documents=500, documents_bytes=123456789):
    return {"schema": "hyptcn3/guest-levels/1", "utc_unix": WALL, "processes": processes, "threads": 300,
            "meminfo_kb": {"MemAvailable": 900000, "MemFree": 400000}, "modules": ["ext4"], "loadavg": ["0.1"] * 3,
            "database": {"products": products, "customers": 2000, "employees": 200, "orders": orders, "pending": 0,
                         "order_items": order_items, "cart_items": 400, "documents": documents,
                         "database_bytes": 50000000, "connections": 5},
            "files": {"documents": {"files": documents, "bytes": documents_bytes},
                      "reports": {"files": 0, "bytes": 0}},
            "root_fs": {"total_bytes": 10 ** 10, "free_bytes": 5 * 10 ** 9}}


def session(root, g2_dir, run, vm, scenario, number, *, group=None, first=None, kind="deck", excluded=None,
            counted=True, beside=(), before=None, after=None, unit=None, reset=None, done=True):
    """The recorded files of one G2 session (the module docstring) from the fake run `run`, its G2 record and the
    record of its group's start (written once per group). Returns the session directory."""
    sid = f"g2-{vm}-{scenario}-{number}"
    d = Path(root) / vm / sid
    d.mkdir(parents=True)
    for name in LOGS:
        (d / name).write_text((run / name).read_text().replace('"session_id": "RUN"', f'"session_id": "{sid}"'))
    (d / "protocol.json").write_bytes((run / "protocol.json").read_bytes())
    planned = [{"type": "naprazdno", "class": "naprazdno", "start_s": EVENT[0] - 120,
                "duration_s": EVENT[1] - EVENT[0]}]
    write(d / "events.json", {"schema": "hyptcn3/session-events/1", "events": [
        dict(planned[0], executed=True, effect={"ok": True}, host_start_unix=WALL + EVENT[0],
             host_started_unix=WALL + EVENT[0] + .4, host_stop_unix=WALL + EVENT[1],
             host_stopped_unix=WALL + EVENT[1] + 1.5)]})
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": "g2",
                               "vm": vm, "role": "diagnostic", "scenario": scenario, "events": planned,
                               "event_grace_s": GRACE, "protocol_sha256": sha(d / "protocol.json")})
    write(d / "guest" / "levels_before.json", before or levels())
    units = {u: {"ActiveState": "active", "SubState": "running", "Result": "success", "NRestarts": "0"}
             for u in REQUIRED_UNITS}
    if unit:
        units[unit] = {"ActiveState": "failed", "SubState": "failed", "Result": "exit-code", "NRestarts": "5"}
    write(d / "guest" / "state_after.json", {"schema": "hyptcn3/guest-state/1", "units": units})
    group = group or f"g2-{vm}-blk-1"
    record = Path(g2_dir) / "bloky" / "blk" / "groups" / f"{group}.json"
    if not record.exists():
        write(record, {"schema": "hyptcn3/campaign-group/1", "group": group, "vm": vm,
                       "start": {"reset_seed": 0, "steps": [{"step": "stop"}, {"step": "start"},
                                                            {"step": "reset", "seed": 0, "output": reset or RESET},
                                                            {"step": "pretouch"}]}})
    started = 1.9e9 + 1800 * number  # A run of 1500 s every 1800 s: a group of 16 sessions spans under 18 h.
    write(Path(g2_dir) / "zaznamy" / f"{sid}.json", {
        "schema": "hyptcn3/g2-session/1", "commit": "c" * 40, "date": iso(started), "host": "pcc",
        "guest": {"vm": vm}, "command": "python -m skuska.g2 block (recorded by the test)", "n": 4,
        "values": {"stage": "G2", "kind": kind, "vm": vm, "session_id": sid, "session_dir": str(d),
                   "session_json_sha256": sha(d / "session.json"), "excluded": excluded, "counted": counted,
                   "load": {"summary": {"counted": counted, "reasons": [] if counted else
                                        ["outside: collection.py run on another VM: collection.py run --vm b"]}},
                   "done": done, "stop": None if done else "error: the run failed", "beside": list(beside),
                   "group": {"name": group, "record": str(record), "sha256": sha(record)},
                   "levels_after": after or levels(orders=3041, order_items=7090, processes=122),
                   "steps": [{"step": "run", "started": iso(started if first is None else first),
                              "ended": iso((started if first is None else first) + 1500)}]}})
    return d


def deck(root, g2_dir, runs, per_vm=4, changes=None):
    """per_vm sessions of every scenario on each VM, numbered in order; changes {session id: keyword arguments}."""
    out, number = [], 0
    for scenario in SCENARIOS:
        for vm in "ab":
            for _ in range(per_vm):
                number += 1
                sid = f"g2-{vm}-{scenario}-{number}"
                out.append(session(root, g2_dir, runs[scenario], vm, scenario, number,
                                   **(changes or {}).get(sid, {})))
    return out


def table(tmp_path, dirs, capsys, *extra, out=None):
    out = tmp_path / "load.json" if out is None else out
    code = cr.main(["load", *map(str, dirs), "--g2-dir", str(tmp_path / "g2"), *map(str, extra), "--out", str(out)])
    captured = capsys.readouterr()
    doc = json.loads(Path(out).read_text()) if Path(out).exists() else None
    return code, doc, captured.out.splitlines(), captured.err


def counted_here(d):
    """What the logs of d hold in their measure phase, counted here: offered, admitted, drops by reason, requests,
    ok, the requests whose start or end lies in the occurrence's window, the planned user sessions."""
    rows = [json.loads(line) for line in (d / LOGS[0]).read_text().splitlines()]
    intervals = [json.loads(line) for line in (d / LOGS[1]).read_text().splitlines()]
    arrivals = [r for r in rows if r["type"] == "arrival" and r["phase"] == "measure"]
    requests = [r for r in rows if r["type"] == "request" and r["phase"] == "measure"]
    lo, hi = WALL + EVENT[0] - 1, WALL + EVENT[1] + 1.5 + GRACE
    inside = [r for r in requests if any(lo <= datetime.fromisoformat(r[key]).timestamp() <= hi
                                         for key in ("t_start_utc", "t_end_utc"))]
    return {"offered": len(arrivals), "admitted": sum(a["admitted"] for a in arrivals),
            "dropped": dict(Counter(a["drop_reason"] for a in arrivals if not a["admitted"])),
            "requests": len(requests), "ok": sum(r["outcome"] == "ok" for r in requests), "inside": len(inside),
            "planned": sum(iv["planned_sessions"] for iv in intervals
                           if iv["type"] == "interval" and iv["phase"] == "measure")}


# ---------------------------------------------------------------- the table

def test_every_scenario_and_vm_with_its_offered_and_delivered_load(tmp_path, capsys, runs):
    """4 sessions of every scenario on each VM: per scenario and VM the offered and delivered load summed over its
    sessions, the load in the event windows apart, no drop; the groups start from the same reset and the levels of
    each group's first session match it; every unit is active at the end; every minimum is met; check E's header."""
    dirs = deck(tmp_path / "s", tmp_path / "g2", runs)
    code, doc, lines, err = table(tmp_path, dirs, capsys)
    assert code == 0, err
    assert set(PROVENANCE) <= set(doc) and (doc["schema"], doc["n"]) == ("hyptcn3/g2-load-table/1", 32)
    v = doc["values"]
    assert (v["stage"], v["criterion"], v["scenarios"], v["vms"]) == ("G2", "profiles_load", SCENARIOS, ["a", "b"])
    assert (v["minimums_met"], v["missing"], v["findings"], v["apart"]) == (True, [], [], [])
    for scenario in SCENARIOS:
        here = counted_here(runs[scenario])
        for vm in "ab":
            row = v["by_scenario_and_vm"][scenario][vm]
            assert len(row["sessions"]) == 4
            assert row["offered"]["user_sessions"] == 4 * here["offered"]
            assert row["offered"]["planned"] == pytest.approx(4 * here["planned"])
            assert row["delivered"]["admitted_user_sessions"] == 4 * here["admitted"]
            assert (row["delivered"]["requests"], row["delivered"]["ok"]) == (4 * here["requests"], 4 * here["ok"])
            assert row["event_windows"]["requests"] == 4 * here["inside"]
            assert row["outside_windows"]["requests"] == 4 * (here["requests"] - here["inside"])
            assert row["event_windows"]["seconds"] == pytest.approx(4 * (EVENT[1] + 1.5 + GRACE - EVENT[0] + 1))
            assert row["dropped_measure"] == {}
        assert len(v["by_scenario"][scenario]["sessions"]) == 8
        assert here["offered"] > 0 and here["inside"] > 0
    entry = v["sessions"][0]
    assert {f["name"] for f in entry["files"]} == {"session.json", "protocol.json", "G2 record", "events.json",
                                                  *LOGS, "guest/levels_before.json", "guest/state_after.json",
                                                  "group record"}
    assert all(f["sha256"] == sha(f["path"]) for f in entry["files"])
    assert entry["growth"]["database.orders"] == 40 and entry["growth"]["processes"] == 2
    assert v["by_scenario"][SCENARIOS[0]]["growth"]["database.orders"] == {"n": 8, "min": 40, "median": 40, "max": 40}
    assert [g["group"] for g in v["groups"]] == ["g2-a-blk-1", "g2-b-blk-1"]
    assert all(g["levels_ok"] and g["differs_from"] is None for g in v["groups"])
    assert v["groups"][0]["first_session"] == dirs[0].name
    assert lines[-1] == "profiles_load minimums: met; 32 of 32 session(s) counted, 2 group(s), 0 finding(s)"


def test_drops_after_the_final_cap_are_a_finding_and_before_it_shown_apart(tmp_path, capsys, runs):
    """The capped run (eshop, a cap of 3) drops for max_concurrent. With --final-protocol whose eshop cap is 3 the
    session ran after the final cap: a finding with the counts; with the file's own cap it ran before it, and its
    drops are shown apart without a finding."""
    here = counted_here(runs["capped"])
    assert here["dropped"].get("max_concurrent", 0) > 0
    d = session(tmp_path / "s", tmp_path / "g2", runs["capped"], "a", "eshop_high", 1)
    rows = [json.loads(line) for line in (d / LOGS[0]).read_text().splitlines()]
    drops = dict(Counter(r["drop_reason"] for r in rows if r["type"] == "arrival" and not r["admitted"]))
    final = tmp_path / "final.json"
    final.write_bytes((runs["capped"] / "protocol.json").read_bytes())
    code, doc, _, err = table(tmp_path, [d], capsys, "--final-protocol", final)
    v = doc["values"]
    assert code == 1 and v["sessions"][0]["cap"] == {"max_concurrent": 3, "final": True}, err
    assert v["sessions"][0]["load"]["dropped"]["measure"] == here["dropped"]
    assert v["findings"] == [f"session {d.name} ran after the final cap 3 of eshop and dropped user sessions: "
                             + ", ".join(f"{k} {n}" for k, n in sorted(drops.items()))]
    assert v["drops_not_judged"] == []
    code, doc, _, _ = table(tmp_path, [d], capsys, "--final-protocol", gen.V5, out=tmp_path / "other.json")
    v = doc["values"]
    assert v["sessions"][0]["cap"]["final"] is False and v["findings"] == []
    assert v["drops_not_judged"][0]["session_id"] == d.name


def test_a_reset_that_differs_and_levels_that_do_not_match_it_are_named(tmp_path, capsys, runs):
    """Q63 (a): the group of VM b reset to other data (its data_sha256), and the first session of VM a's group shows
    one product more than its reset: both named, the criterion not met."""
    other = dict(RESET, data_sha256="cd" * 32, started_unix=1.795e9)
    first_a = f"g2-a-{SCENARIOS[0]}-1"
    first_b = f"g2-b-{SCENARIOS[0]}-5"
    dirs = deck(tmp_path / "s", tmp_path / "g2", runs, changes={first_a: {"before": levels(products=5001)},
                                                                first_b: {"reset": other}})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    assert code == 1
    assert v["missing"] == [
        f"group g2-a-blk-1: the levels of its first session {first_a} do not match its reset in products 5001 "
        "(expected 5000)",
        "group g2-b-blk-1: its reset differs from that of group g2-a-blk-1 in data_sha256"]
    assert v["groups"][1]["differs_from"] == {"group": "g2-a-blk-1", "keys": ["data_sha256"]}


def test_the_first_session_of_a_group_is_the_first_run_of_its_records(tmp_path, capsys, runs):
    """The first session of a group is the one whose run started first among the group's records, not the first
    input; a group whose first session is not read is named as not judged."""
    dirs = deck(tmp_path / "s", tmp_path / "g2", runs, per_vm=1)
    code, doc, _, _ = table(tmp_path, dirs[2:], capsys)
    v = doc["values"]
    assert code == 1 and v["groups"][0]["first_session"] == dirs[0].name
    assert f"group g2-a-blk-1: the levels after its reset are not judged: its first session {dirs[0].name} is not " \
           "among the sessions read" in v["missing"]


def test_a_unit_that_is_not_active_at_the_end_is_named(tmp_path, capsys, runs):
    sid = f"g2-a-{SCENARIOS[1]}-9"
    dirs = deck(tmp_path / "s", tmp_path / "g2", runs, changes={sid: {"unit": "hyptcn-lab@docs"}})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    assert code == 1 and v["missing"] == [f"session {sid}: at the end of its segment hyptcn-lab@docs failed/exit-code"]
    entry = next(e for e in v["sessions"] if e["session_id"] == sid)
    assert entry["units_end"]["ok"] is False and entry["units_end"]["units"]["hyptcn-lab@docs"]["NRestarts"] == "5"


@pytest.mark.parametrize("change, status, why", [
    ({"excluded": {"criteria": ["marked_rows_per_event", "profiles_load", "traffic_realism"], "rule": "Q61"}},
     "left_out", "its record leaves it out of profiles_load (values.excluded: Q61)"),
    ({"counted": False}, "left_out",
     "not counted by the host load (skuska/g2.py LOAD_RULE): outside: collection.py run on another VM: collection.py "
     "run --vm b"),
    ({"kind": "fault", "beside": [{"hook": "fault", "fault": "zastaveny_generator", "induced": True}]}, "fault",
     "a session of the fault plan with its fault (zastaveny_generator, induced True): shown apart"),
    ({"done": False}, "not_done", "not done (skuska/g2.py DONE_RULE): error: the run failed"),
], ids=["excluded", "heavy", "fault", "not_done"])
def test_a_session_the_records_leave_out_is_shown_apart(tmp_path, capsys, runs, change, status, why):
    """One session of a scenario is left out by its record: listed apart with the record's words, and the scenario has
    7 of its 8 sessions: exit 1, named."""
    sid = f"g2-b-{SCENARIOS[2]}-{4 * 4 + 4 + 1}"
    dirs = deck(tmp_path / "s", tmp_path / "g2", runs, changes={sid: change})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    assert code == 1 and v["apart"] == [{"session_id": sid, "status": status, "why": why}]
    assert v["missing"] == [f"scenario {SCENARIOS[2]}: 7 of 8 sessions counted on both VMs together (1 missing)"]
    assert len(v["by_scenario_and_vm"][SCENARIOS[2]]["b"]["sessions"]) == 3


def test_a_group_longer_than_18_hours_and_a_session_not_done_are_findings(tmp_path, capsys, runs):
    """Q63's risk: a group whose runs span more than 18 h drifts from the seeded level by itself (named with its span);
    a session that is not done is listed and named, its files beyond the record not read."""
    late = f"g2-a-{SCENARIOS[3]}-7"
    failed = f"g2-b-{SCENARIOS[3]}-8"
    dirs = deck(tmp_path / "s", tmp_path / "g2", runs, per_vm=1,
                changes={late: {"first": 1.9e9 + 1800 + 20 * 3600}, failed: {"done": False}})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    assert code == 1
    assert v["findings"] == [f"group g2-a-blk-1 spans {round((20 * 3600 + 1500) / 3600, 3)} h, more than 18 h: it "
                             "drifts from the seeded level by itself (Q63)",
                             f"session {failed}: not done (skuska/g2.py DONE_RULE): error: the run failed"]
    entry = next(e for e in v["sessions"] if e["session_id"] == failed)
    assert entry["status"] == "not_done" and {f["name"] for f in entry["files"]} == {"session.json", "protocol.json",
                                                                                     "G2 record"}


# ---------------------------------------------------------------- data and usage errors

def test_a_group_record_other_than_the_one_named_is_a_data_error(tmp_path, capsys, runs):
    d = session(tmp_path / "s", tmp_path / "g2", runs[SCENARIOS[0]], "a", SCENARIOS[0], 1)
    record = tmp_path / "g2" / "bloky" / "blk" / "groups" / "g2-a-blk-1.json"
    record.write_text(record.read_text() + " ")
    code, doc, lines, err = table(tmp_path, [d], capsys)
    assert (code, doc, lines) == (2, None, [])
    assert f"{record}: not the record of group g2-a-blk-1 that the G2 record names" in err


def test_sessions_of_protocols_with_another_g0_binding_are_refused(tmp_path, capsys, runs):
    a = session(tmp_path / "s", tmp_path / "g2", runs[SCENARIOS[0]], "a", SCENARIOS[0], 1)
    b = session(tmp_path / "s", tmp_path / "g2", runs[SCENARIOS[1]], "b", SCENARIOS[1], 2)
    doc = json.loads((b / "protocol.json").read_text())
    doc["window_rows"] = 30
    (b / "protocol.json").write_text(json.dumps(doc, indent=2) + "\n")
    meta = json.loads((b / "session.json").read_text())
    meta["protocol_sha256"] = sha(b / "protocol.json")
    write(b / "session.json", meta)
    path = tmp_path / "g2" / "zaznamy" / f"{b.name}.json"
    record = json.loads(path.read_text())
    record["values"]["session_json_sha256"] = sha(b / "session.json")
    write(path, record)
    code, doc, _, err = table(tmp_path, [a, b], capsys)
    assert (code, doc) == (2, None) and "the sessions (and --final-protocol) are of protocols with different G0 " \
                                        "bindings" in err


def test_an_existing_out_and_a_directory_named_twice_are_refused_before_anything_is_read(tmp_path, capsys,
                                                                                          monkeypatch):
    out = tmp_path / "load.json"
    out.write_text("kept\n")
    monkeypatch.setattr(cr, "load_session", lambda *a: (_ for _ in ()).throw(AssertionError("read")))
    assert cr.main(["load", str(tmp_path / "none"), "--out", str(out)]) == 2
    assert out.read_text() == "kept\n" and "--out already exists" in capsys.readouterr().err
    assert cr.main(["load", str(tmp_path), str(tmp_path / "x" / ".."), "--out", str(tmp_path / "new.json")]) == 2
    assert f"a session directory is named more than once: {tmp_path}" in capsys.readouterr().err
