"""The table of the faults of G2 (scripts/campaign_report.py faults, package H1b3) on recorded files.

Each session directory is written as collection.py run and audit leave one (session.json, protocol.json, end.json, an
audit record binding session.json) and the injector's record beside it as skuska/poruchy.py FaultHook writes it
(Injector.values with check E's header). The reasons are those the code gives for each fault (skuska/poruchy.py
FAULTS) and the other reasons such a session gets. Nothing outside tmp_path is written.
"""
import hashlib
import json
from pathlib import Path

import pytest

from scripts import campaign_report
from skuska import g2, poruchy

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
T0 = 1_800_000_000.0
# What each fault's session received besides its expected names: (end.json error or None, the audit's reasons).
RECEIVED = {
    "zabity_zberac": ("ValueError: collector failed; see capture.log",
                      ["incomplete capture or changed guest identity", "logs: collector_end_missing_or_duplicate",
                       "logs: collector_exit_code", "missing key: end.json:guest_after"]),
    "zdrzany_procesor": (None, ["cycle start later than the audit bound"]),
    "tlak_na_pamat": (None, ["collector cycle time above the audit bound", "logs: qemu_swap"]),
    "restart_vm": ("ValueError: guest rebooted or changed during capture",
                   ["incomplete capture or changed guest identity", "logs: guest_identity_changed"]),
    "zastaveny_generator": (None, ["logs: traffic_realism:arrival_cv", "logs: traffic_realism:success_rate"]),
    "zabita_sluzba": (None, ["logs: request_failed:r1", "logs: service_restarted:hyptcn-lab@docs"]),
}
CLEAN_REASONS = ["logs: collector_warning_unlisted:synthetic"]  # The clean session of VM a is refused for this.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc):
    path.write_text(json.dumps(doc, indent=1))
    return path


def session(root, records, item, *, error=None, reasons=(), accepted=None, audit=True, induced=True, why_not=None,
            role="diagnostic", expected=None):
    """A recorded session of the fault plan and the injector's record of it."""
    sid = f"g2-{item['vm']}-{item['id']}-1"
    d = root / "diag" / item["vm"] / sid
    d.mkdir(parents=True)
    (d / "protocol.json").write_bytes(REAL.read_bytes())
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": sid, "vm": item["vm"],
                               "role": role, "scenario": item["scenario"], "cycles": 600, "seed": item["seed"],
                               "protocol_sha256": sha(d / "protocol.json")})
    end = {"completed": error is None, "interrupted": False, "measure_start_unix": T0}
    if error is None:
        end["measure_end_unix"] = T0 + 3000
    else:
        end["error"] = error
    write(d / "end.json", end)
    if audit:
        accepted = (not reasons) if accepted is None else accepted
        write(d / "audit_20261126T120000000000Z.json", {
            "schema": "hyptcn3/collection-audit/1", "values": {
                "accepted": accepted, "reasons": sorted(reasons), "session_dir": str(d),
                "session_sha256": sha(d / "session.json"), "protocol_sha256": sha(d / "protocol.json")}})
    inj = poruchy.Injector(item["fault"], {"vm": item["vm"], "domain": f"hyptcn-lab-{item['vm']}"}, d, [], 1, 600,
                           None)
    if item["fault"] is not None:
        inj.induced, inj.why_not, inj.window = induced, why_not, [T0 + 60, T0 + 61]
    spec = {"kind": poruchy.KIND_FAULT if item["fault"] else poruchy.KIND_CLEAN, "session_id": sid,
            "deck": {**item, "cycles": 600}}
    values = inj.values(spec, "python -m skuska.poruchy block --vm " + item["vm"], "idle")
    if expected is not None:
        values["expected"] = expected
    records.mkdir(parents=True, exist_ok=True)
    doc = g2.header(poruchy.FAULT_SCHEMA, "python -m skuska.poruchy block", 2, values)
    write(records / f"{sid}.json", doc)
    return d


def recorded(tmp_path, change=None):
    """The 14 sessions of the plan, each fault refused with its names, the clean session of VM a refused for a
    warning, of VM b accepted; `change(fault, vm)` gives other options for one session."""
    records = tmp_path / "G2" / "poruchy"
    dirs = []
    for item in poruchy.plan(json.loads(REAL.read_text())):
        options = {}
        if item["fault"] is None:
            options["reasons"] = CLEAN_REASONS if item["vm"] == "a" else []
        else:
            error, reasons = RECEIVED[item["fault"]]
            options.update(error=error, reasons=reasons + (CLEAN_REASONS if item["vm"] == "a" else []))
        if change:
            options.update(change(item["fault"], item["vm"]) or {})
        dirs.append(session(tmp_path, records, item, **options))
    return dirs, records


def table(tmp_path, dirs, records):
    out = tmp_path / "out" / "poruchy.json"
    code = campaign_report.main(["faults", *map(str, dirs), "--records", str(records), "--out", str(out)])
    return code, (json.loads(out.read_text()) if out.exists() else None)


def test_every_fault_refused_by_its_names_on_both_vms(tmp_path, capsys):
    """Twelve fault sessions, each loud and named: every fault counted once on each VM, exit 0; the table has fault,
    VM, session, expected and received reasons, other reasons, loud and named; check E's header."""
    dirs, records = recorded(tmp_path)
    code, doc = table(tmp_path, dirs, records)
    assert code == 0
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"]) == ("hyptcn3/g2-faults-table/1", 12)
    v = doc["values"]
    assert (v["criterion"], v["vms"], v["minimums_met"], v["missing"], v["g2_values"]) == (
        "live_fault_injections", ["a", "b"], True, [], False)
    assert v["faults"] == list(poruchy.FAULTS) and v["faults_sha256"] == poruchy.faults_sha256()
    assert [(row["fault"], row["vm"]) for row in v["table"]] == [(f, vm) for f in poruchy.FAULTS for vm in "ab"]
    for row in v["table"]:
        assert set(row) == {"fault", "vm", "session", "expected", "received", "other_reasons", "loud", "named",
                            "counted"}
        assert row["loud"] and row["named"] and row["counted"]
        assert row["expected"] == poruchy.FAULTS[row["fault"]]["expected"]
        assert all(name in row["received"] for name in row["expected"])
    killed = next(row for row in v["sessions"] if row["fault"] == "zabity_zberac" and row["vm"] == "a")
    assert killed["received"][0] == "ValueError: collector failed; see capture.log"  # incomplete_reasons first.
    assert killed["other_reasons_not_in_clean"] == ["incomplete capture or changed guest identity",
                                                    "logs: collector_end_missing_or_duplicate",
                                                    "missing key: end.json:guest_after"]
    assert CLEAN_REASONS[0] in killed["other_reasons"] and killed["clean_session"] == "g2-a-c01-1"
    assert {f: {vm: c["counted"] for vm, c in by.items()} for f, by in v["counts"].items()} == {
        f: {"a": 1, "b": 1} for f in poruchy.FAULTS}
    assert [row["session"] for row in v["clean_sessions"]] == ["g2-a-c01-1", "g2-b-c02-1"]
    assert v["shapes_without_clean_session"] == [] and v["absorbed"] == [] and v["other_names"] == []
    printed = capsys.readouterr().out
    assert "zabity_zberac: VM a 1/1, VM b 1/1" in printed and "live_fault_injections minimums: met" in printed


def test_a_fault_refused_with_another_name_is_shown_and_not_counted(tmp_path):
    """The VM restart on VM b refused by the collector's name (a cycle failed during the reset): loud, not named, its
    minimum on VM b missing, exit 1; the received name is in the table."""
    def change(fault, vm):
        if (fault, vm) == ("restart_vm", "b"):
            return {"error": "ValueError: collector failed; see capture.log",
                    "reasons": ["incomplete capture or changed guest identity", "logs: collector_exit_code"]}
    dirs, records = recorded(tmp_path, change)
    code, doc = table(tmp_path, dirs, records)
    assert code == 1
    v = doc["values"]
    row = next(r for r in v["table"] if (r["fault"], r["vm"]) == ("restart_vm", "b"))
    assert (row["loud"], row["named"], row["counted"]) == (True, False, False)
    assert row["received"] == ["ValueError: collector failed; see capture.log",
                               "incomplete capture or changed guest identity", "logs: collector_exit_code"]
    assert row["other_reasons"] == row["received"]
    assert v["counts"]["restart_vm"]["b"]["missing"] == 1 and v["minimums_met"] is False
    assert v["missing"] == ["restart_vm on VM b: 0 of 1 refused by its names (1 session(s): g2-b-f08-1: refused "
                            "without the expected name(s): ValueError: guest rebooted or changed during capture)"]
    assert v["other_names"] == ["restart_vm on VM b (g2-b-f08-1): refused with ValueError: collector failed; see "
                                "capture.log; incomplete capture or changed guest identity; logs: collector_exit_code, "
                                "not with ValueError: guest rebooted or changed during capture"]


def test_a_fault_the_guards_absorbed_is_a_finding_not_a_pass(tmp_path):
    """The memory pressure on VM a induced and the session accepted: not loud, absorbed, not counted (map question
    11)."""
    dirs, records = recorded(tmp_path, lambda f, vm: {"reasons": []} if (f, vm) == ("tlak_na_pamat", "a") else None)
    code, doc = table(tmp_path, dirs, records)
    assert code == 1
    v = doc["values"]
    row = next(r for r in v["sessions"] if (r["fault"], r["vm"]) == ("tlak_na_pamat", "a"))
    assert (row["loud"], row["named"], row["counted"], row["audit"]["accepted"]) == (False, False, False, True)
    assert row["why_not_counted"].startswith("the session was not refused: the audit accepted it")
    assert v["absorbed"] == ["tlak_na_pamat on VM a (g2-a-f05-1): induced, and the audit accepted the session"]


def test_a_fault_that_was_not_induced_does_not_count(tmp_path):
    dirs, records = recorded(tmp_path, lambda f, vm: {"induced": False, "why_not": "the other VM is not idle"}
                             if (f, vm) == ("tlak_na_pamat", "b") else None)
    code, doc = table(tmp_path, dirs, records)
    row = next(r for r in doc["values"]["sessions"] if (r["fault"], r["vm"]) == ("tlak_na_pamat", "b"))
    assert code == 1 and row["counted"] is False
    assert row["why_not_counted"] == "the fault was not induced: the other VM is not idle"


def test_a_session_without_an_error_and_without_an_audit_has_no_verdict(tmp_path):
    dirs, records = recorded(tmp_path, lambda f, vm: {"audit": False} if (f, vm) == ("zdrzany_procesor", "a") else None)
    code, doc = table(tmp_path, dirs, records)
    row = next(r for r in doc["values"]["sessions"] if (r["fault"], r["vm"]) == ("zdrzany_procesor", "a"))
    assert code == 1 and (row["audit"], row["loud"], row["received"]) == (None, False, [])
    assert row["why_not_counted"] == "the session was not refused: no error of the capture and no audit (no verdict)"


def test_a_capture_without_end_json_is_named_as_the_campaign_names_it(tmp_path):
    """The killed collector on VM b whose end.json is missing: incomplete_reasons' name is received, the names expected
    are not all there, so it does not count."""
    dirs, records = recorded(tmp_path)
    victim = next(d for d in dirs if d.name == "g2-b-f02-1")
    (victim / "end.json").unlink()
    code, doc = table(tmp_path, dirs, records)
    row = next(r for r in doc["values"]["sessions"] if r["session"] == "g2-b-f02-1")
    assert code == 1
    assert row["received"][0] == "no end.json: the capture recorded no end (crash, SIGKILL or power loss)"
    assert row["expected_received"] == {"ValueError: collector failed; see capture.log": False,
                                        "logs: collector_exit_code": True}


@pytest.mark.parametrize("breaks, words", [
    (lambda dirs, records: (records / "g2-a-f01-1.json").unlink(), "g2-a-f01-1.json: cannot be read"),
    (lambda dirs, records: write(records / "g2-a-f03-1.json", {**json.loads((records / "g2-a-f03-1.json")
                                                                             .read_text()), "schema": "x"}),
     "its schema is \"x\", not hyptcn3/g2-fault/1"),
    (lambda dirs, records: None, "the names committed before the runs (Q56)"),
    (lambda dirs, records: dirs.append(dirs[0]), "a session directory is named more than once"),
    (lambda dirs, records: write(dirs[3] / "session.json", {**json.loads((dirs[3] / "session.json").read_text()),
                                                            "role": "test_events"}), "not diagnostic"),
], ids=["no-record", "record-schema", "other-names", "twice", "role"])
def test_data_errors_write_nothing(tmp_path, capsys, breaks, words):
    expected = {"expected": ["cycle start later"]} if words.endswith("(Q56)") else {}
    dirs, records = recorded(tmp_path, lambda f, vm: expected if (f, vm) == ("zdrzany_procesor", "a") else None)
    breaks(dirs, records)
    code, doc = table(tmp_path, dirs, records)
    assert (code, doc) == (2, None)
    assert words in capsys.readouterr().err


def test_an_out_that_exists_is_refused_before_anything_is_read(tmp_path, capsys):
    out = tmp_path / "exists.json"
    out.write_text("{}")
    assert campaign_report.main(["faults", str(tmp_path / "none"), "--records", str(tmp_path), "--out", str(out)]) == 2
    assert "already exists, nothing was read or written" in capsys.readouterr().err and out.read_text() == "{}"


def test_the_mode_is_no_measurement_code():
    from scripts import collection
    assert collection.is_measurement("scripts/campaign_report.py") is False
    assert collection.is_measurement("skuska/poruchy.py") is False
