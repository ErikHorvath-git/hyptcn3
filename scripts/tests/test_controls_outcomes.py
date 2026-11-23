"""The outcomes of one control occurrence (protocol v5, package B8): design B8 section 4, skeleton section 5 item 3.

scripts/controls.py outcomes() on a synthetic extraction result (scripts/tests/boundary_sessions.extraction_result:
the shape of features.snapshot.retazec, whose rows the live detector's windows accept) under a synthetic protocol:
the timing of config/collection-v5.json with a controls section in the shape of contract 1.1 of design B8 (agent H
writes the real one). Its doses are the skeleton's (the lead's judgment); its columns' levels and shifts and the
guest's records are test values, not the protocol's judgment. The cases of the skeleton: a control with its shift
(each kind), a control without, a negative with a shift, a horizon without a scored row; beside them one bad input
per rule of the two outcomes (a row without the object, a column unmoved, a change below the writer's dose, a negative
showing its property in one row or moving one column, patterns of a process outside the negative's tree, a column
expected to fall) and a negative without a shift as the good one, the outcomes that cannot be judged, the same
outcomes from the feature archive, the sealed role (design B8 section 4), and one refusal per check of the record, the
controls section and the rows. Names package B8 adds are imported inside the tests, so this file collects on the code
before B8.
"""
import copy
import json
from pathlib import Path

import pytest

from features.snapshot import MENA
from scripts.tests import boundary_sessions as bs

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
T0, ROWS, BINS = 10000., 120, 32  # Row seq is taken at T0 + 5 seq; 32 bins of 16 MiB: a guest of 512 MiB.
# host_start_unix lies 1 s before row 60 and host_started_unix 1 s after it: the reference ends before the start
# call, the horizon begins with it and the rows wholly inside one interval after its end. The occurrence lasts 150 s.
START = T0 + 299.
STARTED, STOP = START + 2, START + 150
BEFORE = list(range(48, 60))  # The 12 rows with t <= START.
INSIDE = list(range(62, 90))  # STARTED + 5 <= t <= STOP: the rows wholly inside.
HORIZON = list(range(60, 96))  # START < t <= START + 180.
DECOYS = [*range(39, 48), 60, 61, 90]  # In neither mean: rows before the reference and the partly inside ones.
PID = 4321  # The python3 child of the control's process tree (effect.evidence.members); PID - 1 is its leader.
KIND = "kontrola_wx_memfd"


def up(shift):
    return {"shift": shift, "direction": "up"}


# Contract 1.1: controls.kinds.<kind>. The doses are the skeleton's (section 1, the lead's judgment); the shifts are
# test values. kontrola_modul_jadra lists mod_total only: mod_delta changes in the row of the load, which is not
# wholly inside (reported in the problems of agent O).
KINDS = {
    "kontrola_wx_memfd": {"class": "A", "doses": None, "columns": ["proc_wx", "proc_memfd"],
                          "expect": {"proc_wx": up(1), "proc_memfd": up(1)}, "note": "test values"},
    "kontrola_modul_jadra": {"class": "A", "doses": None, "columns": ["mod_total"], "expect": {"mod_total": up(1)},
                             "candidates": ["modul_a", "modul_b", "modul_c"], "note": "test values"},
    "kontrola_pocuvajuci_soket": {"class": "A", "doses": None, "columns": ["sock_listen"],
                                  "expect": {"sock_listen": up(1)}, "note": "test values"},
    "kontrola_zapisovac_pamate": {"class": "B", "doses": [16, 64, 256],
                                  "columns": ["mem_changed_ratio", "mem_changed_max", "mem_entropy_mean"],
                                  "expect": {"mem_changed_ratio": up([.03, .12, .5]), "mem_changed_max": up(.1),
                                             "mem_entropy_mean": up(.5)}, "note": "test values"},
    "kontrola_davka_procesov": {"class": "B", "doses": [2, 10, 50], "columns": ["proc_new", "proc_gone", "proc_total"],
                                "expect": {"proc_new": up([1, 4, 20]), "proc_gone": up([1, 4, 20]),
                                           "proc_total": up(3)}, "note": "test values"},
}
DOSE = {"kontrola_zapisovac_pamate": 64, "kontrola_davka_procesov": 10}  # Class A: no dose.
# Every column of the occurrence at LEVEL, plus SHIFT in the rows wholly inside of a shifted session: 64 MiB of a
# 512 MiB guest is a change ratio of .125, so .13 shows the writer's dose in each row and reaches the expected .12.
LEVEL = {"proc_wx": 0, "proc_memfd": 0, "mod_total": 30, "sock_listen": 7, "mem_changed_ratio": .02,
         "mem_changed_max": .1, "mem_entropy_mean": 3., "proc_new": 0, "proc_gone": 0, "proc_total": 120}
SHIFT = {"proc_wx": 1, "proc_memfd": 1, "mod_total": 1, "sock_listen": 1, "mem_changed_ratio": .13,
         "mem_changed_max": .15, "mem_entropy_mean": 1., "proc_new": 5, "proc_gone": 5, "proc_total": 6}
PATTERNS = [{"pid": PID, "comm": "python3", "kind": "wx"}, {"pid": PID, "comm": "python3", "kind": "memfd_fd"}]
SEALED = ("sealed role test_controls: only the final evaluation computes the outcomes of its controls "
          "(final_evaluation=True)")


def protocol():
    """The real file's timing and roles with the synthetic controls section (contract 1.1)."""
    doc = json.loads(V5.read_text())
    doc["controls"] = dict(doc["controls"], kinds=copy.deepcopy(KINDS), baseline=None)
    return doc


def session(kind, shifted=INSIDE, columns=None, wx_only=(), invalid=(), full_every=360):
    """The extraction result of a session with one occurrence of `kind`: every column of the kind at LEVEL, the
    `columns` (default: all of them) plus SHIFT in the rows `shifted` and plus 5 SHIFT in the DECOYS, the W+X and memfd
    patterns of PID in the shifted rows and the DECOYS (in the rows `wx_only` W+X alone), the rows `invalid` unclosed
    and a full snapshot every `full_every` rows."""
    result, _ = bs.extraction_result("s", ROWS, full_every, t0=T0, interval_s=5, bins=BINS,
                                     quality={seq: bs.unclosed_row() for seq in invalid})
    columns = KINDS[kind]["columns"] if columns is None else columns
    for seq, row in enumerate(result["matica"]):
        for column in KINDS[kind]["columns"]:
            times = 5 if seq in DECOYS else 1 if seq in shifted and column in columns else 0
            row[MENA.index(column)] = LEVEL[column] + times * SHIFT[column]
        if kind == "kontrola_wx_memfd" and (seq in DECOYS or seq in shifted):
            result["quality"][seq]["memory_patterns"] = copy.deepcopy(PATTERNS[:1] if seq in wx_only else PATTERNS)
    return result


def occurrence(kind, polarity="control", **changes):
    """The record of an occurrence that ran, in controls.json as contract 1.4 describes it."""
    record = {"kind": kind, "class": "control" if polarity == "control" else "control_negative",
              "polarity": polarity, "dose": DOSE.get(kind), "executed": True, "host_start_unix": START,
              "host_started_unix": STARTED, "host_stop_unix": STOP, "host_stopped_unix": STOP + 3,
              "baseline": {"ok": True, "exact": {"ok": True}, "evidence": {},
                           "level": {"judged": False, "why": "controls.baseline null until G2"}},
              "effect": {"ok": True, "evidence": {"members": [PID - 1, PID]}}, "cleanup": {"ok": True, "evidence": {}}}
    return dict(record, **changes)


BUT_75 = [seq for seq in INSIDE if seq != 75]
# Row 59 before the start is invalid; inside, row 70 is invalid, 71 has no predecessor and 80 is a full snapshot.
GAPS = {"invalid": (59, 70), "full_every": 80}
MEASURED = [seq for seq in INSIDE if seq not in (70, 71, 80)]


@pytest.mark.parametrize("kind,polarity,record,change,showing,saw,moved,scored", [
    ("kontrola_wx_memfd", "control", {}, {}, INSIDE, True, True, True),  # A control with its shift, each kind.
    ("kontrola_modul_jadra", "control", {}, {}, INSIDE, True, True, True),
    ("kontrola_pocuvajuci_soket", "control", {}, {}, INSIDE, True, True, True),
    ("kontrola_zapisovac_pamate", "control", {}, {}, INSIDE, True, True, True),
    ("kontrola_davka_procesov", "control", {}, {}, INSIDE, True, True, True),
    ("kontrola_pocuvajuci_soket", "control", {}, {"shifted": []}, [], False, False, True),  # A control without it.
    ("kontrola_wx_memfd", "control", {}, {"wx_only": [75]}, BUT_75, False, True, True),  # A row with W+X, no memfd.
    ("kontrola_wx_memfd", "control", {}, {"columns": ["proc_wx"]}, INSIDE, True, False, True),  # A column unmoved.
    # The same change as at 64 MiB stays below the dose of 256 MiB and below the dose's expected shift.
    ("kontrola_zapisovac_pamate", "control", {"dose": 256}, {}, [], False, False, True),
    ("kontrola_zapisovac_pamate", "negative", {}, {}, INSIDE, False, False, True),  # A negative with a shift.
    # The patterns belong to a process outside the negative's tree: the parser shows none of its own, while the
    # columns count every process.
    ("kontrola_wx_memfd", "negative", {"effect": {"ok": True, "evidence": {"members": [PID + 1]}}}, {}, [], True,
     False, True),
    ("kontrola_zapisovac_pamate", "negative", {}, {"shifted": [75]}, [75], False, True, True),  # In one row.
    ("kontrola_davka_procesov", "negative", {}, {"shifted": []}, [], True, True, True),  # A negative without one.
    ("kontrola_davka_procesov", "negative", {}, {"columns": ["proc_total"]}, [], True, False, True),  # A column moved.
    # A horizon without a scored row: no 32 measured rows in a row end in it. The outcomes from the features are
    # judged on the measured rows alone.
    ("kontrola_modul_jadra", "control", {}, GAPS, MEASURED, True, True, False),
])
def test_outcomes(kind, polarity, record, change, showing, saw, moved, scored):
    from scripts.controls import outcomes
    dose = record.get("dose", DOSE.get(kind))
    out = outcomes(occurrence(kind, polarity, **record), session(kind, **change), protocol(), role="test_controls",
                   final_evaluation=True)
    assert out["window"] == {"start_unix": START, "started_unix": STARTED, "stop_unix": STOP,
                             "horizon_end_unix": START + 180, "before": BEFORE, "inside": INSIDE,
                             "horizon": HORIZON, "scored": HORIZON if scored else []}
    assert (out["kind"], out["class"], out["polarity"], out["dose"]) == (kind, KINDS[kind]["class"], polarity, dose)
    assert (out["parser_saw"]["ok"], out["column_moved"]["ok"], out["sensor_scored"]) == (saw, moved, scored)
    rows = MEASURED if change is GAPS else INSIDE
    assert out["parser_saw"]["rows"] == rows and out["parser_saw"]["showing"] == showing
    assert out["column_moved"]["reference"] == [seq for seq in BEFORE if seq not in change.get("invalid", ())]
    columns, doses = out["column_moved"]["columns"], KINDS[kind]["doses"]
    assert list(columns) == KINDS[kind]["columns"]
    for name, column in columns.items():  # The expected shift of the record's dose.
        shift = KINDS[kind]["expect"][name]["shift"]
        assert column["expect"] == (shift[doses.index(dose)] if type(shift) is list else shift)


@pytest.mark.parametrize("fall,reached", [(False, False), (True, True)])
def test_expectation_down(fall, reached):
    """A column expected to fall: one socket more does not reach the expected shift, one fewer does."""
    from scripts.controls import outcomes
    kind, doc, result = "kontrola_pocuvajuci_soket", protocol(), session("kontrola_pocuvajuci_soket")
    doc["controls"]["kinds"][kind]["expect"]["sock_listen"]["direction"] = "down"
    for seq in INSIDE if fall else ():
        result["matica"][seq][MENA.index("sock_listen")] -= 2
    column = outcomes(occurrence(kind), result, doc, role="pilot")["column_moved"]["columns"]["sock_listen"]
    assert (column["shift"], column["direction"], column["reached"]) == (-1 if fall else 1, "down", reached)


@pytest.mark.parametrize("kind,record,change,why,moved,moved_why", [
    ("kontrola_pocuvajuci_soket", {"effect": {"ok": False, "evidence": {}}}, {},
     "the guest's effect predicate did not hold", True, None),
    ("kontrola_wx_memfd", {"effect": {"ok": True, "evidence": {}}}, {},
     "the effect evidence names no process (members)", True, None),
    ("kontrola_pocuvajuci_soket", {}, {"invalid": tuple(INSIDE)}, "no measured row wholly inside the occurrence",
     None, "no measured row wholly inside the occurrence"),
    ("kontrola_pocuvajuci_soket", {}, {"invalid": tuple(BEFORE)}, "no measured row among the rows before the start",
     None, "no measured row among the rows before the start"),
])
def test_not_judged(kind, record, change, why, moved, moved_why):
    from scripts.controls import outcomes
    out = outcomes(occurrence(kind, **record), session(kind, **change), protocol(), role="pilot")
    assert (out["parser_saw"]["ok"], out["parser_saw"]["why"], out["parser_saw"]["showing"]) == (None, why, [])
    assert (out["column_moved"]["ok"], out["column_moved"]["why"]) == (moved, moved_why)


def test_feature_archive_gives_the_same_outcomes(tmp_path):
    from features.archive import load, save
    from scripts.controls import outcomes
    record, result, doc = occurrence(KIND), session(KIND), protocol()
    out = outcomes(record, result, doc, role="pilot")
    assert out["parser_saw"]["ok"] is out["column_moved"]["ok"] is out["sensor_scored"] is True
    assert outcomes(record, load(save(tmp_path / "s.npz", result)), doc, role="pilot") == out
    assert json.loads(json.dumps(out)) == out  # Plain JSON values: B7 records the outcomes as they are.


@pytest.mark.parametrize("role,stage,final_evaluation,reason", [
    ("test_controls", "final", False, SEALED),  # Outside the final evaluation.
    ("test_controls", "final", True, None),  # The final evaluation (G6).
    ("test_controls", "generalka", False, None),  # A rehearsal, never a dataset (skeleton section 4).
    ("test_control", "final", False, "unknown session role: 'test_control'"),  # A misspelt role opens nothing.
    ("test_controls", "G6", True, "unknown stage of the record: 'G6' (proposal 11.1: suchy, skuska, generalka, "
                                  "final)"),
])
def test_sealed_role(role, stage, final_evaluation, reason):
    from scripts.controls import outcomes
    if reason is None:
        out = outcomes(occurrence(KIND), session(KIND), protocol(), role=role, stage=stage,
                       final_evaluation=final_evaluation)
        assert out["parser_saw"]["ok"] is True
        return
    with pytest.raises(ValueError) as error:  # Refused before the record or the features are read.
        outcomes(None, None, protocol(), role=role, stage=stage, final_evaluation=final_evaluation)
    assert str(error.value) == reason


def kind_spec(doc, **changes):
    doc["controls"]["kinds"][KIND].update(changes)


@pytest.mark.parametrize("change,reason", [
    (lambda r, s, p: r.update(kind="kontrola_neznama"), "unknown control kind: 'kontrola_neznama'"),
    (lambda r, s, p: (r.update(kind="kontrola_nova"), p["controls"]["kinds"].update(kontrola_nova=KINDS[KIND])),
     "no object in the parser's view for control kind 'kontrola_nova'"),
    (lambda r, s, p: kind_spec(p, **{"class": "C"}), f"controls.kinds.{KIND}.class: needs A or B"),
    (lambda r, s, p: kind_spec(p, columns=["proc_wx", "je_plna"]),
     f"controls.kinds.{KIND}.columns: needs distinct feature columns of features.snapshot.MENA"),
    (lambda r, s, p: kind_spec(p, doses=[16]),
     f"controls.kinds.{KIND}.doses: class A has none (null), class B distinct positive doses"),
    (lambda r, s, p: kind_spec(p, expect={"proc_wx": up(1)}),
     f"controls.kinds.{KIND}.expect: needs one expectation for each of its columns"),
    (lambda r, s, p: kind_spec(p, expect={"proc_wx": up(1), "proc_memfd": {"shift": 1}}),
     f"controls.kinds.{KIND}.expect.proc_memfd: needs a positive shift (class B: or one per dose) and the direction "
     f"up or down"),
    (lambda r, s, p: r.update(polarity="negative"),
     f"{KIND}: the record names no polarity, two or an unknown one (class 'control', polarity 'negative')"),
    (lambda r, s, p: r.update(kind="kontrola_zapisovac_pamate", dose=32),
     "kontrola_zapisovac_pamate: dose 32 is not one of the kind's doses [16, 64, 256]"),
    (lambda r, s, p: r.update(executed=False), "control not executed: " + KIND),
    (lambda r, s, p: r.update(baseline={"ok": False, "evidence": {"processes": [PID]}}),
     "control without baseline: " + KIND),
    (lambda r, s, p: r.update(effect={"evidence": {}}), "control without a well-formed effect: " + KIND),
    (lambda r, s, p: r.update(host_stop_unix=START - 1), "control without ordered host times: " + KIND),
    (lambda r, s, p: r.update(host_start_unix=T0 + 600, host_started_unix=T0 + 602, host_stop_unix=T0 + 750),
     "the extraction result does not cover the occurrence of " + KIND),
    (lambda r, s, p: s["quality"][70].pop("memory_patterns"),
     "row quality without memory_patterns (features/snapshot.py, snapshot-vektor/4)"),
])
def test_refusals(change, reason):
    from scripts.controls import outcomes
    record, result, doc = occurrence(KIND), session(KIND), protocol()
    change(record, result, doc)
    with pytest.raises(ValueError) as error:
        outcomes(record, result, doc, role="pilot")
    assert str(error.value) == reason
