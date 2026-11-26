"""The mode realism of scripts/campaign_report.py (package H1b6b of stage G2): the realism requirements of proposal 5.7
over the G2 sessions per scenario and VM, the sessions with a fault apart, the maintenance timer of corp from the guest
journal, and P1 (the mode envelope) grouped by the bytes of each session's protocol.json; criterion traffic_realism
(map row 6, the lead's answer to Q65).

The sessions come through the producers' code as in scripts/tests/test_campaign_report_envelope.py make_session (the
traffic block of session.json, protocol.json, the header of both traffic logs drawn by the generator), so P1 matches;
around them the files of the capture and the driver are written here: end.json, the guest journal of the segment with
the lines of lab/services.py udrzba, the audit record with a section realism as scripts/traffic_log.py realism returns
it (values written by the test), and the G2 record naming that audit. Expected values are written out here, never made
by the mode's code. No VM, no network, nothing written outside the test's directories.
"""
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from scripts import campaign_report as cr
from scripts.tests import test_campaign_report_envelope as env

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
P = json.loads(REAL.read_text())
SCENARIOS = sorted(P["scenarios"])
PROVENANCE = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.
M0 = 1.9e9  # The start of the measured phase of every session (synthetic).
MEASURED = 3600.0
STARTS = (100.0, 790.0, 1300.0, 2050.0, 2500.0, 3150.0)  # Maintenance runs: spacings 690, 510, 750, 450, 650 s.


@pytest.fixture(autouse=True)
def one_git_state(monkeypatch):
    monkeypatch.setattr(cr, "git_identity", lambda: {"commit": "synthetic", "dirty": False, "changed_paths": 0})


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=1) + "\n")


def requirements(profile, i, fail=None):
    """The section realism of an audit (scripts/traffic_log.py realism's shape) for the i-th session; `fail` the name
    of one requirement that fails."""
    rows = [{"name": "arrival_cv", "value": round(.9 + .01 * i, 6), "bound": [.8, 1.2], "ok": True, "note": "test"}]
    if profile == "eshop":
        rows += [{"name": "think_time", "value": {"mean": 7 + .1 * i, "max": 69.5, "n": 900 + i},
                  "bound": {"mean": 7, "tolerance": 1.2, "max": 70, "lag_s": 1.0}, "ok": True, "note": "test"},
                 {"name": "order_share", "value": .2, "bound": {"share": .2, "tolerance": .05}, "ok": True,
                  "note": "test"}]
    rows += [{"name": "object_concentration", "value": .6, "bound": .5, "ok": True, "note": "test"},
             {"name": "success_rate", "value": round(.95 + .001 * i, 6), "bound": {"min": .88, "below": 1}, "ok": True,
              "note": "test"},
             {"name": "response_sizes", "value": 3.2, "bound": 2, "ok": True, "note": "test"},
             {"name": "peak_to_mean", "value": 2.5, "bound": 2, "ok": True, "note": "test"}]
    if profile == "corp":
        rows.append({"name": "background", "value": {"logins": 40 + i, "reports": 9, "document_max_to_median": 30.0},
                     "bound": {"logins_min": 1, "reports_min": 1, "document_max_to_median": 10}, "ok": True,
                     "note": "test"})
    for row in rows:
        if row["name"] == fail:
            row["ok"] = False
    return {"requirements": rows, "offered_load": {"offered": 1000 + i, "planned": 1000.0,
                                                   "ratio": round((1000 + i) / 1000, 6), "ok": True}}


def journal(d, sid, starts):
    """The guest journal of the segment with one line of lab/services.py udrzba per maintenance run (its start
    measured from M0), as journalctl -o short-iso-precise --utc writes it."""
    lines = []
    for start in starts:
        stamp = datetime.fromtimestamp(M0 + start + 1.5, timezone.utc).isoformat(timespec="microseconds")
        lines.append(f'{stamp} hyptcn-lab python3[4242]: {{"service": "udrzba", "vacuum_rc": 0, "vacuum_error": null, '
                     f'"log_compressed": null, "seconds": 1.5}}')
        lines.append(f"{stamp} hyptcn-lab systemd[1]: hyptcn-lab-udrzba.service: Deactivated successfully.")
    name = f"{sid}-journal-journal.txt"
    with gzip.open(d / "guest" / (name + ".gz"), "wt") as stream:
        stream.write("\n".join(lines) + "\n")
    write(d / "guest" / "journal_segment.json", {"schema": "hyptcn3/guest-journal-segment/1",
                                                  "files": [{"name": name, "file": name + ".gz"}]})


def session(root, g2_dir, vm, scenario, i, *, protocol=REAL, fail=None, kind="deck", excluded=None, counted=True,
            beside=(), starts=STARTS, section=True, number=0):
    """One G2 session (the module docstring); returns its directory."""
    sid = f"g2-{vm}-{scenario}-{i}"
    d = env.make_session(Path(root) / vm, sid, scenario, dict(env.SEEDS, traffic=100 + number), protocol=protocol)
    meta = json.loads((d / "session.json").read_text())
    meta.update(vm=vm, role="diagnostic")
    write(d / "session.json", meta)
    write(d / "end.json", {"schema": "hyptcn3/collection-end/2", "completed": True, "measure_start_unix": M0,
                           "measure_end_unix": M0 + MEASURED})
    profile = P["scenarios"][scenario]["profile"]
    if profile == "corp":
        (d / "guest").mkdir()
        journal(d, sid, starts)
    logs = {"sections": {"realism": requirements(profile, i, fail)}, "problems": []} if section else \
        {"sections": {}, "problems": ["realism:unreadable:KeyError: 'phase'"]}
    audit = d / "audit_20261126T120000000000Z.json"
    write(audit, {"schema": "hyptcn3/collection-audit/1", "commit": "c" * 40, "date": "2026-11-26T12:00:00+00:00",
                  "host": "test-host", "guest": None, "command": "scripts/collection.py audit (recorded by the test)",
                  "n": P["cycles"], "values": {"accepted": fail is None, "reasons": [], "session_dir": str(d),
                                               "session_sha256": sha(d / "session.json"),
                                               "protocol_sha256": sha(d / "protocol.json"), "logs": logs}})
    write(Path(g2_dir) / "zaznamy" / f"{sid}.json", {
        "schema": "hyptcn3/g2-session/1", "commit": "c" * 40, "date": "2026-11-26T12:00:00+00:00", "host": "pcc",
        "guest": {"vm": vm}, "command": "python -m skuska.g2 block (recorded by the test)", "n": 4,
        "values": {"stage": "G2", "kind": kind, "vm": vm, "session_id": sid, "session_dir": str(d),
                   "session_json_sha256": sha(d / "session.json"), "excluded": excluded, "counted": counted,
                   "load": {"summary": {"counted": counted, "reasons": [] if counted else ["heavy: a training "
                                                                                           "(tcn.train): x"]}},
                   "done": True, "beside": list(beside), "audit": {"report": str(audit), "sha256": sha(audit)}}})
    return d


def deck(root, g2_dir, changes=None, protocols=None):
    """4 sessions of every scenario on each VM (i 0 to 7 within the scenario); changes {session id: arguments},
    protocols {session id: protocol file}."""
    out, number = [], 0
    for scenario in SCENARIOS:
        for i in range(8):
            vm = "ab"[i % 2]
            sid = f"g2-{vm}-{scenario}-{i}"
            out.append(session(root, g2_dir, vm, scenario, i, number=number,
                               protocol=(protocols or {}).get(sid, REAL), **(changes or {}).get(sid, {})))
            number += 1
    return out


def table(tmp_path, dirs, capsys, out=None):
    out = tmp_path / "realism.json" if out is None else out
    code = cr.main(["realism", *map(str, dirs), "--g2-dir", str(tmp_path / "g2"), "--out", str(out)])
    captured = capsys.readouterr()
    doc = json.loads(Path(out).read_text()) if Path(out).exists() else None
    return code, doc, captured.out.splitlines(), captured.err


# ---------------------------------------------------------------- the table

def test_every_scenario_with_eight_sessions_without_a_fault_meets_the_criterion(tmp_path, capsys):
    """8 sessions of every scenario, every requirement passed, the timer of corp in its band, P1 a match in one group:
    exit 0; per scenario the minimum, the nearest-rank median and the maximum of every requirement (arrival_cv 0.90 to
    0.97, median the 4th of 8, 0.93), per scenario and VM too; check E's header with the stage G2."""
    dirs = deck(tmp_path / "s", tmp_path / "g2")
    code, doc, lines, err = table(tmp_path, dirs, capsys)
    assert code == 0, err
    assert set(PROVENANCE) <= set(doc) and (doc["schema"], doc["n"]) == ("hyptcn3/g2-realism-table/1", 32)
    v = doc["values"]
    assert (v["stage"], v["criterion"], v["scenarios"], v["vms"]) == ("G2", "traffic_realism", SCENARIOS, ["a", "b"])
    assert (v["minimums_met"], v["missing"], v["findings"], v["apart"], v["faults"]) == (True, [], [], [], [])
    for scenario in SCENARIOS:
        row = v["by_scenario"][scenario]
        assert len(row["sessions"]) == 8
        cv = row["requirements"]["arrival_cv"]
        assert (cv["sessions"], cv["passed"], cv["failed"]) == (8, 8, [])
        assert cv["values"]["value"] == {"n": 8, "min": .9, "median": .93, "max": .97}
        assert cv["bounds"] == [[.8, 1.2]]
        assert row["requirements"]["offered_load"]["values"]["value"]["max"] == 1.007
        names = set(row["requirements"])
        if P["scenarios"][scenario]["profile"] == "corp":
            assert {"background", "maintenance_timer"} <= names and "think_time" not in names
            timer = row["requirements"]["maintenance_timer"]
            assert timer["values"]["runs"] == {"n": 8, "min": 6, "median": 6, "max": 6}
            assert timer["bounds"] == [{"runs_min": 2, "spacing_s": [298.0, 902.0], "period_s": 600,
                                        "random_s": [0, 300]}]
        else:
            assert {"think_time", "order_share"} <= names and "maintenance_timer" not in names
            assert row["requirements"]["think_time"]["values"]["mean"]["min"] == 7
        assert len(v["by_scenario_and_vm"][scenario]["a"]["sessions"]) == 4
    corp = next(e for e in v["sessions"] if e["profile"] == "corp")
    assert corp["timer"]["value"]["spacings_s"] == {"n": 5, "min": 450.0, "median": 650.0, "max": 750.0}
    assert corp["timer"]["value"]["starts_unix"] == [M0 + s for s in STARTS] and corp["timer"]["ok"]
    assert {f["name"] for f in corp["files"]} == {"session.json", "protocol.json", "G2 record", "audit record",
                                                 "end.json", "guest/journal_segment.json", "guest journal"}
    assert all(f["sha256"] == sha(f["path"]) for f in corp["files"])
    (group,) = v["envelope"]["groups"]
    assert (group["protocol_sha256"], group["counts"]) == (sha(REAL), {"match": 32, "mismatch": 0, "data_error": 0})
    assert all(e["envelope"]["result"] == "match" for e in v["sessions"])
    assert lines[-1] == "traffic_realism minimums: met; 32 of 32 session(s) counted, 0 with a fault apart"


def test_p1_runs_over_the_sessions_of_two_protocol_byte_states(tmp_path, capsys):
    """Half of the sessions ran under a protocol file with a value of G2 written (invalid_rows.max 4 and its gate):
    other bytes, the same G0 binding. The mode envelope over all of them with one --protocol calls the other half a
    data error; the mode realism groups them by the sha256 of protocol.json and every session matches."""
    doc = json.loads(REAL.read_text())
    doc["invalid_rows"]["max"], doc["min_score_coverage"] = 4, 524 / 720
    written = tmp_path / "written.json"
    written.write_text(json.dumps(doc, indent=2) + "\n")
    later = {f"g2-{'ab'[i % 2]}-{s}-{i}": written for s in SCENARIOS for i in range(4, 8)}
    dirs = deck(tmp_path / "s", tmp_path / "g2", protocols=later)
    code = cr.main(["envelope", *map(str, dirs), "--protocol", str(REAL), "--out", str(tmp_path / "p1.json")])
    p1 = json.loads((tmp_path / "p1.json").read_text())["values"]
    assert code == 2 and p1["counts"] == {"match": 16, "mismatch": 0, "data_error": 16}
    capsys.readouterr()
    code, record, lines, err = table(tmp_path, dirs, capsys)
    assert code == 0, err
    groups = record["values"]["envelope"]["groups"]
    assert sorted((g["protocol_sha256"], len(g["sessions"]), g["counts"]["match"]) for g in groups) == sorted(
        [(sha(REAL), 16, 16), (sha(written), 16, 16)])
    assert {g["protocol_sha256"]: g["protocol"] for g in groups}[sha(written)].endswith("protocol.json")
    assert lines[-2].startswith("P1: protocol ")


def test_a_requirement_that_fails_is_named_and_goes_to_the_lead(tmp_path, capsys):
    sid = f"g2-a-{SCENARIOS[2]}-2"
    dirs = deck(tmp_path / "s", tmp_path / "g2", changes={sid: {"fail": "success_rate"}})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    text = f'success_rate 0.952 against {{"below": 1, "min": 0.88}}'
    assert code == 1 and v["missing"] == [f"session {sid} ({SCENARIOS[2]}, VM a): fails {text}"]
    assert v["findings"] == [f"for the lead first (Q65): session {sid} ({SCENARIOS[2]}, VM a): fails {text}"]
    assert v["by_scenario"][SCENARIOS[2]]["requirements"]["success_rate"]["failed"] == [sid]


def test_a_session_with_an_induced_fault_is_apart(tmp_path, capsys):
    """A ninth session of eshop_high on VM b with its fault (the stopped generator): its failed arrival_cv is shown with
    it apart and counts for no minimum; its P1 is judged."""
    dirs = deck(tmp_path / "s", tmp_path / "g2")
    fault = session(tmp_path / "s", tmp_path / "g2", "b", "eshop_high", 9, number=99, fail="arrival_cv", kind="fault",
                    beside=[{"hook": "fault", "fault": "zastaveny_generator", "induced": True}])
    code, doc, _, err = table(tmp_path, [*dirs, fault], capsys)
    v = doc["values"]
    assert code == 0, err
    assert v["faults"] == [{"session_id": fault.name, "vm": "b", "scenario": "eshop_high",
                            "fault": "zastaveny_generator", "induced": True,
                            "failed": ["arrival_cv 0.99 against [0.8, 1.2]"], "envelope": "match"}]
    assert v["apart"] == [{"session_id": fault.name, "status": "fault", "why": "a session of the fault plan with its "
                                                                              "fault (zastaveny_generator, induced "
                                                                              "True): shown apart"}]
    assert len(v["by_scenario"]["eshop_high"]["sessions"]) == 8


@pytest.mark.parametrize("starts, why", [
    ((100.0, 1060.0, 1700.0), "spacings outside the band: [960.0]"),
    ((100.0,), "every spacing within the band"),
], ids=["spacing", "one_run"])
def test_the_maintenance_timer_of_corp_comes_from_the_journal(tmp_path, capsys, starts, why):
    sid = f"g2-b-{SCENARIOS[0]}-3"
    dirs = deck(tmp_path / "s", tmp_path / "g2", changes={sid: {"starts": starts}})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    entry = next(e for e in v["sessions"] if e["session_id"] == sid)
    assert code == 1 and entry["timer"]["ok"] is False and entry["timer"]["note"].endswith(why)
    assert entry["timer"]["value"]["runs"] == len(starts)
    (missing,) = v["missing"]
    assert missing.startswith(f"session {sid} ({SCENARIOS[0]}, VM b): fails maintenance_timer {{\"runs\": "
                              f"{len(starts)}, ") and " against {\"period_s\": 600, " in missing


@pytest.mark.parametrize("change, why", [
    ({"excluded": {"criteria": ["marked_rows_per_event", "profiles_load", "traffic_realism"], "rule": "Q61"}},
     "its record leaves it out of traffic_realism (values.excluded: Q61)"),
    ({"counted": False}, "not counted by the host load (skuska/g2.py LOAD_RULE): heavy: a training (tcn.train): x"),
], ids=["excluded", "heavy"])
def test_a_session_the_records_leave_out_is_apart(tmp_path, capsys, change, why):
    sid = f"g2-b-{SCENARIOS[3]}-5"
    dirs = deck(tmp_path / "s", tmp_path / "g2", changes={sid: change})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    assert code == 1 and v["apart"] == [{"session_id": sid, "status": "left_out", "why": why}]
    assert v["missing"] == [f"scenario {SCENARIOS[3]}: 7 of 8 sessions without a fault counted with values (1 "
                            "missing)"]


def test_a_session_whose_audit_has_no_section_realism_has_no_values(tmp_path, capsys):
    sid = f"g2-a-{SCENARIOS[1]}-4"
    dirs = deck(tmp_path / "s", tmp_path / "g2", changes={sid: {"section": False}})
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    assert code == 1 and v["missing"] == [
        f"scenario {SCENARIOS[1]}: 7 of 8 sessions without a fault counted with values (1 missing)",
        f"session {sid}: no values of the requirements (the audit has no section realism: realism:unreadable:"
        "KeyError: 'phase')"]


def test_a_mismatch_of_p1_is_named(tmp_path, capsys):
    sid = f"g2-a-{SCENARIOS[0]}-0"
    dirs = deck(tmp_path / "s", tmp_path / "g2")
    for log in env.LOGS:
        env.edit_header(dirs[0], log, env.move_knot("level"))
    code, doc, _, _ = table(tmp_path, dirs, capsys)
    v = doc["values"]
    (missing,) = v["missing"]
    assert code == 1 and missing.startswith(f"session {sid}: P1 mismatch: header of traffic_requests.jsonl: "
                                            "envelope.level")


# ---------------------------------------------------------------- data and usage errors

@pytest.mark.parametrize("case", ["audit_bytes", "audit_of_another"])
def test_an_audit_other_than_the_one_the_record_names_is_a_data_error(tmp_path, capsys, case):
    d = session(tmp_path / "s", tmp_path / "g2", "a", SCENARIOS[0], 0)
    audit = d / "audit_20261126T120000000000Z.json"
    doc = json.loads(audit.read_text())
    if case == "audit_bytes":
        doc["values"]["accepted"] = True
        doc["note"] = "changed"
    else:
        doc["values"]["session_sha256"] = "0" * 64
    write(audit, doc)
    if case == "audit_of_another":  # The record names the changed bytes, which audit another session.
        path = tmp_path / "g2" / "zaznamy" / f"{d.name}.json"
        record = json.loads(path.read_text())
        record["values"]["audit"]["sha256"] = sha(audit)
        write(path, record)
    code, record, lines, err = table(tmp_path, [d], capsys)
    assert (code, record, lines) == (2, None, [])
    assert f"{audit}: not the audit the G2 record names or not one of this session" in err


def test_an_existing_out_is_refused_before_anything_is_read(tmp_path, capsys, monkeypatch):
    out = tmp_path / "realism.json"
    out.write_text("kept\n")
    monkeypatch.setattr(cr, "realism_session", lambda *a: (_ for _ in ()).throw(AssertionError("read")))
    assert cr.main(["realism", str(tmp_path / "none"), "--out", str(out)]) == 2
    assert out.read_text() == "kept\n" and "--out already exists" in capsys.readouterr().err
