"""The qualification of the feature columns (protocol v5, package B6a; proposal 8.1, the lead's skeleton
dokazy/B6/kostra/KOSTRA.md sections 3 and 6 test 1, design B6a 1.4 and 1.5 and its section 2 tests 1 to 3).

One synthetic corpus of 12 sessions of train and dev, four groups of three positions with 120 measured rows each, on
the real protocol file: every column is noise that tells no group, VM or half of the session order apart, except
  mod_total     constant 31                                         rule (constant)
  sock_listen   20, and 21 in 7 of the 1440 rows                     rule (near-constant)
  proc_kernel   proc_total - proc_user                               dropped (duplicate)
  mem_changed_ratio  0.2 x group index + noise (no level column)     dropped (identity)
  sock_total    100 x group index + noise (a level column)           differenced
  proc_wx       1000 x group index + (group index + 1) x row index   dropped (its first difference tells the group)
Every stratum (profile, position) holds two sessions of two groups, one on each VM. Names of package B6a are
imported inside the tests, so this file collects on the code before it.

The fix after the verification of B6a (dokazy/B6/ZADANIE_oprava_B6a.md) adds: the strata of the real rehearsal plan,
where no stratum compares the VM (finding F1); the stage of the command against the plan mode of the index (F4); a
column exactly at near_constant_share and at identity_auc, and the rank test of a differenced column by its first
difference (F6).
"""
import json
import math
from pathlib import Path
import re

import numpy as np
import pytest

from features.archive import BEHAVIOR_NAMES, save
from features.snapshot import MENA

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
GROUPS = ("v5-train-1", "v5-train-2", "v5-dev-1", "v5-dev-2")
VMS = ("a", "a", "b", "b")
ROWS = 120


def corpus():
    """(rows, sessions) of the corpus of the module docstring; group index g, position q, profile eshop when g + q
    is even, corp otherwise (scenario <profile>_low), start by role (train first), then group and position."""
    rng = np.random.default_rng(20261123)
    rows, sessions = {}, []
    near = iter(range(7))  # Rows with sock_listen 21: the row 5 of the first 7 sessions.
    for g, group in enumerate(GROUPS):
        for q in range(3):
            name = f"{group}#{q}"
            profile = "eshop" if (g + q) % 2 == 0 else "corp"
            sessions.append({"id": name, "role": group.split("-")[1], "group": group, "vm": VMS[g],
                             "scenario": f"{profile}_low", "profile": profile, "position": q,
                             "start": float(g * 10000 + q * 3600)})
            x = np.zeros((ROWS, len(BEHAVIOR_NAMES)))
            x[:, :8] = rng.uniform(0, 1, (ROWS, 8))
            x[:, 8:] = rng.integers(20, 40, (ROWS, 12))
            column = {name: k for k, name in enumerate(BEHAVIOR_NAMES)}
            x[:, column["proc_total"]] = rng.integers(60, 80, ROWS)
            x[:, column["mod_total"]] = 31
            x[:, column["sock_listen"]] = 20
            if next(near, None) is not None:
                x[5, column["sock_listen"]] = 21
            x[:, column["proc_kernel"]] = x[:, column["proc_total"]] - x[:, column["proc_user"]]
            x[:, column["mem_changed_ratio"]] = .2 * g + rng.uniform(0, .1, ROWS)
            x[:, column["sock_total"]] = 100 * g + rng.integers(0, 10, ROWS)
            x[:, column["proc_wx"]] = 1000 * g + (g + 1) * np.arange(ROWS)
            rows[name] = x
    return rows, sessions


@pytest.fixture(scope="module")
def qualified():
    from features.qualification import qualify
    rows, sessions = corpus()
    result = qualify(rows, sessions, json.loads(V5.read_text()))
    return result, {row["column"]: row for row in result["table"]}


SPECIAL = {"mod_total", "sock_listen", "proc_kernel", "mem_changed_ratio", "sock_total", "proc_wx"}
WORST = "group v5-dev-2 against group v5-train-2, stratum corp/0"  # The first comparison of score 1 in the order.


def test_each_column_gets_its_class_with_the_numbers_in_the_table(qualified):
    """Skeleton section 6 test 1: the constant and the near-constant column go to the rule channel, the duplicate
    and the column that tells the group are dropped, every other column is neural. The proposal is a valid value of
    analysis.columns of the protocol."""
    from scripts import protocol_v5
    result, table = qualified
    assert result["schema"] == "hyptcn3/feature-qualification/1" and list(table) == list(BEHAVIOR_NAMES)
    assert {name: row["class"] for name, row in table.items() if name in SPECIAL or row["class"] != "neural"} == {
        "mod_total": "rule", "sock_listen": "rule", "proc_kernel": "dropped", "mem_changed_ratio": "dropped",
        "sock_total": "differenced", "proc_wx": "dropped"}
    assert result["proposed_columns"] == {name: row["class"] for name, row in table.items()}
    constant, near = table["mod_total"], table["sock_listen"]
    assert (constant["variance"], constant["mode"], constant["off_mode_share"], constant["reason"]) == (
        0.0, 31.0, 0.0, "constant: zero variance")
    assert (near["mode"], near["off_mode_share"], near["identity"]) == (20.0, 7 / 1440, None)
    assert near["reason"] == "near-constant: 7 of 1440 rows off the mode 20, fewer than near_constant_share 0.01"
    tells = table["mem_changed_ratio"]
    assert (tells["identity"]["score"], tells["identity"]["auc"], tells["identity"]["rows"]) == (1.0, 1.0, [120, 120])
    assert tells["reason"] == f"identity: max(AUC, 1 - AUC) 1.0000 above identity_auc 0.75 ({WORST})"
    duplicate = table["proc_kernel"]
    kept = [name for name in BEHAVIOR_NAMES[:BEHAVIOR_NAMES.index("proc_kernel")] if name != "mem_changed_ratio"]
    assert duplicate["rank_test"]["kept_before"] == kept and duplicate["rank_test"]["relative_singular_value"] < 1e-12
    assert duplicate["reason"].startswith("duplicate: exact linear combination of the 9 columns kept before it")
    assert all(row["identity"]["score"] <= .75 and row["rank_test"]["relative_singular_value"] > .1
               and row["reason"] == "neural: passed every check" for row in table.values() if row["class"] == "neural")
    assert result["inputs"]["rows"] == 1440 and result["inputs"]["rank_test_rows"] == 12 * 119
    assert table["proc_total"]["load"] == {"available": False, "why": "no offered load supplied to qualify()"}
    doc = json.loads(V5.read_text())
    doc["analysis"]["columns"] = result["proposed_columns"]
    protocol_v5.check_layout(doc)


@pytest.mark.parametrize("column, cls, difference", [
    ("sock_total", "differenced", None),
    ("proc_wx", "dropped", f"1.0000 above 0.75 ({WORST})"),
    ("mem_changed_ratio", "dropped", "not judged"),
], ids=["level_difference_passes", "level_difference_tells", "not_a_level"])
def test_a_column_that_tells_the_group_is_differenced_only_as_a_level_whose_difference_passes(qualified, column,
                                                                                               cls, difference):
    """Design B6a test 2: a failing level column is judged again by its first difference (differenced when that
    passes, dropped when it fails); a failing column outside level_columns is dropped without one."""
    _, table = qualified
    row = table[column]
    failed = f"identity: max(AUC, 1 - AUC) 1.0000 above identity_auc 0.75 ({WORST})"
    assert (row["class"], row["identity"]["score"]) == (cls, 1.0)
    again = row["identity_of_difference"]
    if difference == "not judged":
        assert (column in json.loads(V5.read_text())["analysis"]["qualification"]["level_columns"], again,
                row["reason"]) == (False, None, failed)
    elif difference is None:
        assert again["score"] <= .75 and row["reason"] == failed + (
            f"; its first difference scores {again['score']:.4f}, at most 0.75")
    else:
        assert row["reason"] == failed + "; its first difference scores " + difference


@pytest.mark.parametrize("column, shape, difference", [
    ("proc_memfd", "constant", {"rows": 1428, "variance": 0.0, "mode": 0.0, "off_mode_share": 0.0}),
    ("sock_estab", "near_constant", {"rows": 1428, "variance": pytest.approx(4 / 1428), "mode": 0.0,
                                     "off_mode_share": 4 / 1428}),
], ids=["constant_difference", "near_constant_difference"])
def test_a_level_column_whose_first_difference_is_constant_or_near_constant_is_rule_differenced(column, shape,
                                                                                                 difference):
    """Question Q8 to the lead, its proposal (provisional until the lead answers; package B6b): a level column that
    tells the group is qualified again by its first difference by the whole qualification, the variance rule first.
    proc_memfd is 5 + group index in every row of a session: its first difference is 0 everywhere, which the rank
    test dropped as a constant "duplicate" before. sock_estab is 10 + 10 x group index, one lower in rows 50 and 51
    of the first two sessions: 4 of the 12 x 119 first differences are off the mode 0, a near-constant first
    difference that was a TCN input (differenced) before. Both go to the rule channel over their first difference
    and never reach the rank test; sock_total, whose first difference is noise, stays differenced, and the proposal
    is a valid analysis.columns of the protocol."""
    from features.qualification import qualify
    from scripts import protocol_v5
    rows, sessions = corpus()
    j = BEHAVIOR_NAMES.index(column)
    for i, (name, x) in enumerate(rows.items()):
        g = GROUPS.index(name.split("#")[0])
        x[:, j] = 5 + g if shape == "constant" else 10 + 10 * g
        if shape == "near_constant" and i < 2:
            x[50:52, j] -= 1
    result = qualify(rows, sessions, json.loads(V5.read_text()))
    table = {row["column"]: row for row in result["table"]}
    row = table[column]
    assert (row["class"], row["identity"]["score"], row["identity_of_difference"], row["rank_test"]) == (
        "rule_differenced", 1.0, None, None)
    assert row["difference"] == difference
    because = ("constant: zero variance" if shape == "constant" else
               "near-constant: 4 of 1428 differences off the mode 0, fewer than near_constant_share 0.01")
    assert re.fullmatch(re.escape("identity: max(AUC, 1 - AUC) 1.0000 above identity_auc 0.75 (") + r".*"
                        + re.escape("); its first difference is " + because), row["reason"])
    assert table["sock_total"]["class"] == "differenced" and table["sock_total"]["difference"]["off_mode_share"] > .5
    doc = json.loads(V5.read_text())
    doc["analysis"]["columns"] = result["proposed_columns"]
    protocol_v5.check_layout(doc)


def comparison_corpus():
    """Every session of profile eshop: each position is a stratum of the four groups, by start v5-train-1 (VM a),
    v5-train-2 (b), v5-dev-1 (a), v5-dev-2 (b). Noise in every column but three: mem_changed_ratio tells the group
    (0.2 x group index), mem_bins_active the VM (0.5 on VM b) and mem_changed_max the half of the session order (0.5
    in the last two sessions), each plus noise of width 0.1."""
    rng = np.random.default_rng(7)
    rows, sessions = {}, []
    for g, group in enumerate(GROUPS):
        vm = "ab"[g % 2]
        for q in range(3):
            name = f"{group}#{q}"
            sessions.append({"id": name, "role": group.split("-")[1], "group": group, "vm": vm,
                             "scenario": "eshop_low", "profile": "eshop", "position": q,
                             "start": float(g * 10000 + q * 3600)})
            x = np.concatenate((rng.uniform(0, 1, (ROWS, 8)), rng.integers(20, 40, (ROWS, 12))), axis=1)
            x[:, :3] = rng.uniform(0, .1, (ROWS, 3)) + [.2 * g, .5 * (vm == "b"), .5 * (g >= 2)]
            rows[name] = x
    return rows, sessions


@pytest.mark.parametrize("column, comparison, sides", [
    ("mem_changed_ratio", "group v5-dev-2 against the other groups", [120, 360]),
    ("mem_bins_active", "vm a against vm b", [240, 240]),
    ("mem_changed_max", "first 2 against last 2 of 4 sessions by start", [240, 240]),
], ids=["group", "vm", "session_order"])
def test_the_table_names_the_worst_comparison_of_the_identity_test(column, comparison, sides):
    """Design B6a 1.4 point 4: within each stratum (profile, position) each group against the other groups, VM a
    against b and the first against the second half of the session order; the column fails on the comparison that
    tells its sides apart (score 1), and the table names it (the first such in the order of strata and comparisons),
    while every other column passes."""
    from features.qualification import qualify
    rows, sessions = comparison_corpus()
    result = qualify(rows, sessions, json.loads(V5.read_text()))
    table = {row["column"]: row for row in result["table"]}
    worst = table[column]["identity"]
    assert (table[column]["class"], worst["score"], worst["comparison"]) == ("dropped", 1.0, comparison)
    assert (worst["stratum"], worst["rows"]) == ({"profile": "eshop", "position": 0}, sides)
    assert {name for name, row in table.items() if row["class"] != "neural"} == {
        "mem_changed_ratio", "mem_bins_active", "mem_changed_max"}
    assert result["inputs"]["comparisons"] == 3 * (4 + 1 + 1)


def rehearsal_corpus():
    """(rows, sessions) on the strata of the real rehearsal plan (G3a, where proposal 8.1 runs the qualification): the
    sessions of train and dev of protocol_v5.planned_rows(p, "rehearsal") of config/collection-v5.json, started in the
    plan's order, 120 rows each. Every stratum (profile, position) holds two sessions of two groups on one VM. Noise in
    every column but mod_total (constant 31), mem_entropy_mean (1 more in group g5-train-1: it tells the group) and
    mem_changed_ratio (0.5 more on VM b: it tells the VM)."""
    from scripts import protocol_v5
    p = json.loads(V5.read_text())
    rng = np.random.default_rng(20261124)
    column = {name: k for k, name in enumerate(BEHAVIOR_NAMES)}
    rows, sessions = {}, []
    for i, row in enumerate(r for r in protocol_v5.planned_rows(p, "rehearsal") if r["role"] in ("train", "dev")):
        sessions.append({"id": row["label"], "role": row["role"], "group": row["group"], "vm": row["vm"],
                         "scenario": row["scenario"], "profile": p["scenarios"][row["scenario"]]["profile"],
                         "position": row["position"], "start": float(i * 3600)})
        x = np.concatenate((rng.uniform(0, 1, (ROWS, 8)), rng.integers(20, 40, (ROWS, 12))), axis=1)
        x[:, column["mod_total"]] = 31
        x[:, column["mem_entropy_mean"]] += 1. * (row["group"] == "g5-train-1")
        x[:, column["mem_changed_ratio"]] += .5 * (row["vm"] == "b")
        rows[row["label"]] = x
    return rows, sessions


VM_UNTESTED = "not tested, no stratum (profile, position) of train and dev holds two VMs"
INCOMPLETE = ("qualification: incomplete ({}): proposal 8.1 compares the group, the VM and the session order in every "
              "stratum; acknowledge_incomplete=True (the command's --acknowledge-incomplete) records an incomplete "
              "qualification")


@pytest.mark.parametrize("case", ["complete", "one_stratum_on_one_vm", "rehearsal_refused", "rehearsal_acknowledged"])
def test_a_kind_of_comparison_that_a_stratum_lacks_never_reads_as_passed(qualified, case):
    """Verification of B6a, finding F1. Proposal 8.1 compares the group, the VM and the session order within every
    stratum (profile, position). complete: in the corpus above every stratum compares all three, inputs and every row
    that the identity test judged count 6 strata of each kind (a rule column: null), and a neural column passed every
    check. one_stratum_on_one_vm: that corpus with v5-dev-1#0 on VM a, so stratum eshop/0 compares no VM. rehearsal:
    on the strata of the real rehearsal plan the two sessions of every stratum run on one VM, so no stratum compares
    the VM, and qualify() refuses unless the caller acknowledges it. Acknowledged, an incomplete result says complete
    false and why, counts the strata of vm in inputs and in every row that the identity test judged, and the reason of
    each such row ends with why; no row says it passed every check. In the rehearsal the column that tells the group is
    dropped, the constant one keeps its reason, and the one that tells the VM is not caught."""
    from features.qualification import qualify
    kinds = ("group", "vm", "order")  # Proposal 8.1: the group, the VM and the session order.
    protocol = json.loads(V5.read_text())
    if case == "complete":
        result, untested, no_vm = qualified[0], {}, []
    elif case == "one_stratum_on_one_vm":
        rows, sessions = corpus()
        moved = [dict(s, vm="a") if s["id"] == "v5-dev-1#0" else s for s in sessions]
        result = qualify(rows, moved, protocol, acknowledge_incomplete=True)
        untested, no_vm = {"vm": "not tested in 1 of 6 strata (eshop/0), each holds one VM"}, ["eshop/0"]
    else:
        rows, sessions = rehearsal_corpus()
        if case == "rehearsal_refused":
            with pytest.raises(ValueError, match="^" + re.escape(INCOMPLETE.format("vm: " + VM_UNTESTED)) + "$"):
                qualify(rows, sessions, protocol)
            return
        result = qualify(rows, sessions, protocol, acknowledge_incomplete=True)
        untested, no_vm = {"vm": VM_UNTESTED}, [f"{p}/{q}" for p in ("corp", "eshop") for q in range(3)]
    table = {row["column"]: row for row in result["table"]}
    assert (result["complete"], result["untested"], result["acknowledge_incomplete"]) == (
        not untested, untested, case != "complete")
    strata = {f"{s['profile']}/{s['position']}": s["compared"] for s in result["inputs"]["strata"]}
    assert strata == {name: [kind for kind in kinds if kind != "vm" or name not in no_vm] for name in strata}
    counts = {"group": 6, "vm": 6 - len(no_vm), "order": 6}
    assert len(strata) == 6 and result["inputs"]["strata_compared"] == counts
    assert all(row["strata_compared"] == (None if row["class"] == "rule" else counts) for row in table.values())
    gap = "".join(f"; {kind}: {why}" for kind, why in untested.items())
    for row in table.values():
        if row["class"] == "neural":
            assert row["reason"] == ("neural: passed the checks that ran" + gap if untested else
                                     "neural: passed every check")
        elif row["class"] == "rule":
            assert row["reason"].startswith(("constant", "near-constant")) and (not gap or gap not in row["reason"])
        else:
            assert row["reason"].endswith(gap) and "passed every check" not in row["reason"]
    if case == "rehearsal_acknowledged":
        assert {name: table[name]["class"] for name in ("mod_total", "mem_entropy_mean", "mem_changed_ratio")} == {
            "mod_total": "rule", "mem_entropy_mean": "dropped", "mem_changed_ratio": "neural"}
        assert table["mem_entropy_mean"]["reason"].startswith(
            "identity: max(AUC, 1 - AUC) 1.0000 above identity_auc 0.75 (group ")
        assert {row["class"] for row in table.values()} == {"rule", "dropped", "neural"}


@pytest.mark.parametrize("column", ["sock_listen", "mem_entropy_mean"], ids=["near_constant_share", "identity_auc"])
def test_a_column_exactly_at_a_bound_is_neural(column):
    """Verification of B6a, finding F6 (mutants Q1 and Q2), on the corpus above cut to the first 100 rows of each
    session (1200 rows). Near-constant means fewer than near_constant_share of the rows off the mode: sock_listen is
    20, and 21 in row 5 of every session, 12 of the 1200 rows, exactly 0.01. A column fails the identity test when
    max(AUC, 1 - AUC) exceeds identity_auc: mem_entropy_mean is 0, and 1 in the first 50 rows of v5-train-1#0, so its
    stratum eshop/0 compares half ones against none (AUC 0.25 and 0.75) and every other stratum zeros against zeros.
    Both columns are neural."""
    from features.qualification import qualify
    rows, sessions = corpus()
    j = BEHAVIOR_NAMES.index(column)
    for name in rows:
        x = rows[name] = rows[name][:100]
        if column == "sock_listen":
            x[:, j] = 20
            x[5, j] = 21
        else:
            x[:, j] = 0
            x[:50, j] = 1 if name == "v5-train-1#0" else 0
    row = {r["column"]: r for r in qualify(rows, sessions, json.loads(V5.read_text()))["table"]}[column]
    assert (row["class"], row["reason"]) == ("neural", "neural: passed every check")
    worst = row["identity"]
    if column == "sock_listen":
        assert (row["off_mode_share"], worst["score"]) == (.01, .5)
    else:
        assert (row["off_mode_share"], worst["score"], worst["auc"], worst["comparison"], worst["stratum"]) == (
            50 / 1200, .75, .25, "group v5-dev-1 against group v5-train-1", {"profile": "eshop", "position": 0})


def test_the_rank_test_takes_the_first_difference_of_a_differenced_column():
    """Verification of B6a, finding F6 (mutant Q9): sock_total, a level column, is 100 x group index plus the running
    sum of mem_changed_max over the session's rows, so its value tells the group (score 1) and its first difference,
    mem_changed_max of the later row, tells nothing: the identity test makes it differenced. The rank test takes that
    first difference, an exact copy of mem_changed_max, which is kept before it, and drops the column; its value is no
    linear combination of the columns kept before it."""
    from features.qualification import qualify
    rows, sessions = corpus()
    total, source = BEHAVIOR_NAMES.index("sock_total"), BEHAVIOR_NAMES.index("mem_changed_max")
    for name, x in rows.items():
        x[:, total] = 100 * GROUPS.index(name.split("#")[0]) + np.cumsum(x[:, source])
    row = {r["column"]: r for r in qualify(rows, sessions, json.loads(V5.read_text()))["table"]}["sock_total"]
    kept = row["rank_test"]["kept_before"]
    assert (row["class"], row["identity"]["score"], "mem_changed_max" in kept) == ("dropped", 1.0, True)
    assert row["identity_of_difference"]["score"] <= .75 and row["rank_test"]["relative_singular_value"] < 1e-9
    assert row["reason"].startswith(f"duplicate: exact linear combination of the {len(kept)} columns kept before it")


def test_a_session_with_one_measured_row_is_refused():
    """Every session needs a first difference (the module docstring of features/qualification.py), so every
    comparison of a first difference holds the sessions of the comparison of the value, and strata_compared holds for
    both."""
    from features.qualification import qualify
    rows, sessions = corpus()
    rows["v5-dev-2#1"] = rows["v5-dev-2#1"][:1]
    reason = ("qualification: rows of session v5-dev-2#1: needs at least two rows of 20 finite values (a first "
              "difference)")
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        qualify(rows, sessions, json.loads(V5.read_text()))


@pytest.mark.parametrize("matrix, summary", [
    # Rows 0 (full, no predecessor), 3 (invalid) and 5 (full) are not measured and hold 99; rows 1, 2, 4 and 6 are.
    ([(99, 99, 99, 1, 0, 1), (.5, 10, 20, 1, 1, 0), (.5, 12, 21, 1, 1, 0), (99, 99, 99, 0, 1, 0),
      (.5, 12, 20, 1, 1, 0), (99, 99, 99, 1, 1, 1), (.5, 14, 21, 1, 1, 0)],
     {"mem_changed_ratio": dict(rows=4, min=.5, max=.5, mean=.5, std=0, mode=.5, off_mode_share=0, diff_std=0),
      "proc_total": dict(rows=4, min=10, max=14, mean=12, std=math.sqrt(2), mode=12, off_mode_share=.5,
                         diff_std=math.sqrt(8) / 3),
      "sock_listen": dict(rows=4, min=20, max=21, mean=20.5, std=.5, mode=20, off_mode_share=.5,
                          diff_std=math.sqrt(8) / 3)}),
    ([(99, 99, 99, 1, 0, 1), (99, 99, 99, 0, 1, 0)],
     {name: dict(rows=0, min=None, max=None, mean=None, std=None, mode=None, off_mode_share=None, diff_std=None)
      for name in ("mem_changed_ratio", "proc_total", "sock_listen")}),
], ids=["four_measured_rows", "no_measured_row"])
def test_the_audit_summary_of_a_known_matrix(matrix, summary):
    """Design B6a 1.5 and test 3: values.columns over the measured rows only, std with ddof 0, the mode the smallest
    of the most frequent values (sock_listen: 20 and 21 twice each), the std of the first differences ([2, 0, 2]
    and [1, -1, 1]: sqrt(8) / 3), null where there is no row; every other column is 0 in a measured row."""
    from features.qualification import column_summary
    full = np.zeros((len(matrix), len(MENA)))
    valid = []
    for r, (ratio, total, listen, good, predecessor, whole) in enumerate(matrix):
        full[r, :len(BEHAVIOR_NAMES)] = 0 if good and predecessor and not whole else 99
        full[r, [MENA.index(n) for n in ("mem_changed_ratio", "proc_total", "sock_listen")]] = ratio, total, listen
        full[r, MENA.index("ma_predchodcu")], full[r, MENA.index("je_plna")] = predecessor, whole
        valid.append(bool(good))
    recorded = column_summary({"matica": full.tolist(), "valid": valid})
    assert list(recorded) == list(BEHAVIOR_NAMES)
    assert all(recorded[name] == pytest.approx(summary[name], rel=1e-12, abs=1e-12) for name in summary)
    zero = dict(rows=summary["proc_total"]["rows"], **dict.fromkeys(("min", "max", "mean", "std", "mode",
                                                                     "off_mode_share", "diff_std"), 0.0))
    if zero["rows"] == 0:
        zero.update(dict.fromkeys(zero, None), rows=0)
    assert all(recorded[name] == zero for name in BEHAVIOR_NAMES if name not in summary)


def write_index(tmp_path, rows, sessions, **fields):
    """A corpus index (features/dataset.py) of these sessions on the real protocol file, with `fields` (its plan
    mode): every session in a directory of its own, as a feature archive of ROWS + 1 rows whose seq 0 is a full
    snapshot, so that its measured rows are its rows here."""
    from scripts.tests import boundary_sessions as bs
    records = []
    for k, s in enumerate(sessions):
        directory = tmp_path / s["id"].replace("#", "-")
        directory.mkdir()
        (directory / "session.json").write_text("{}")
        result, _ = bs.extraction_result(s["id"], ROWS + 1, 1000, t0=s["start"], interval_s=5, seed=k)
        for r in range(ROWS + 1):
            result["matica"][r][:len(BEHAVIOR_NAMES)] = rows[s["id"]][max(r - 1, 0)].tolist()
        path = save(directory / "features.npz", result)
        records.append(dict(s, features=str(path), features_sha256=bs.collection.digest(path),
                            session=str(directory / "session.json")))
    index = tmp_path / "index.json"
    index.write_text(json.dumps({"schema": "hyptcn3/corpus-index/1", "protocol_sha256": "0" * 64,
                                 "protocol_config": json.loads(V5.read_text()), "sessions": records, **fields}))
    return index


def test_the_command_writes_one_record_of_the_corpus_index(tmp_path):
    """python -m features.qualification --index I --stage generalka --out O on the corpus above as feature archives
    of 121 rows (seq 0 a full snapshot) in an index of plan mode rehearsal, one session with a traffic interval log of
    schema /2 whose 5 s intervals lie half an interval off the row grid: the record carries the provenance of
    data/results and the qualification of the same rows, and that session's offered load per row is the mean of the
    two intervals it overlaps."""
    from features import qualification
    from scripts import traffic_log
    rows, sessions = corpus()
    protocol = json.loads(V5.read_text())
    index, out = write_index(tmp_path, rows, sessions, plan_mode="rehearsal"), tmp_path / "qualification.json"
    first = sessions[0]
    offered = list(range(ROWS + 2))  # Interval j lies at [start + 5 j - 2.5, start + 5 j + 2.5).
    lines = [{"type": "header", "schema": traffic_log.INTERVAL_SCHEMA_2, "n": 0, "start_unix": first["start"] - 2.5}]
    lines += [{"type": "interval", "schema": traffic_log.INTERVAL_SCHEMA_2, "n": j + 1, "mono_start": 5 * j,
               "mono_end": 5 * j + 5, "offered_sessions": n} for j, n in enumerate(offered)]
    (tmp_path / first["id"].replace("#", "-") / "traffic_intervals.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines))
    assert qualification.main(["--index", str(index), "--stage", "generalka", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert all(key in doc for key in ("commit", "date", "host", "guest", "command", "n", "values"))
    assert (doc["schema"], doc["stage"], doc["n"]) == ("hyptcn3/feature-qualification-record/1", "generalka", 12)
    expected = qualification.qualify(rows, sessions, protocol)
    assert doc["values"]["proposed_columns"] == expected["proposed_columns"]
    load = {row["column"]: row["load"] for row in doc["values"]["table"]}
    assert load["mod_total"] == {"available": True, "rows": ROWS, "spearman": None, "r2": None,
                                 "why": "the column or the load is constant over these rows"}
    # Row i (seq i, time start + 5 i) covers (start + 5 i - 5, start + 5 i]: halves of intervals i - 1 and i.
    ramp = qualification.offered_load(tmp_path / first["id"].replace("#", "-") / "traffic_intervals.jsonl",
                                      [first["start"] + 5 * i for i in range(1, ROWS + 1)], 5)
    assert ramp == pytest.approx([i - .5 for i in range(1, ROWS + 1)])
    response = doc["values"]["inputs"]["response"]
    assert response == {"supplied": False, "why": "the index holds no session of role test_controls", "skipped": []}
    without = doc["values"]["inputs"]["load"]["without"]
    assert sorted(without) == sorted(s["id"] for s in sessions[1:])
    assert set(without.values()) == {"no traffic_intervals.jsonl in the session directory"}


@pytest.mark.parametrize("acknowledged", [False, True], ids=["refused", "acknowledged"])
def test_the_record_of_an_incomplete_qualification_says_so(tmp_path, capsys, acknowledged):
    """Finding F1 in the command: on the strata of the real rehearsal plan (an index of plan mode rehearsal at stage
    generalka) the command writes no record without --acknowledge-incomplete and says why; with it the record says
    complete false and names the untested kind, at its top and in its values, and its command carries the flag."""
    from features import qualification
    rows, sessions = rehearsal_corpus()
    index, out = write_index(tmp_path, rows, sessions, plan_mode="rehearsal"), tmp_path / "qualification.json"
    flag = ["--acknowledge-incomplete"] if acknowledged else []
    code = qualification.main(["--index", str(index), "--stage", "generalka", "--out", str(out), *flag])
    if not acknowledged:
        assert (code, out.exists()) == (2, False)
        assert capsys.readouterr().err == "qualification: " + INCOMPLETE.format("vm: " + VM_UNTESTED) + "\n"
        return
    doc = json.loads(out.read_text())
    assert (code, doc["plan_mode"], doc["complete"], doc["untested"]) == (0, "rehearsal", False, {"vm": VM_UNTESTED})
    assert (doc["values"]["complete"], doc["values"]["untested"], doc["values"]["acknowledge_incomplete"]) == (
        False, {"vm": VM_UNTESTED}, True)
    assert doc["command"].endswith(" --acknowledge-incomplete")


@pytest.mark.parametrize("plan_mode, stage, refusal", [
    ("campaign", "generalka", "an index of plan mode campaign is read at stage final only, not at stage generalka: "
                              "its sessions are the dataset, and at stage final role test_controls stays sealed"),
    ("rehearsal", "final", "an index of plan mode rehearsal is never read at stage final: a rehearsal is never in the "
                           "dataset (proposal 10.4)"),
    (None, "generalka", "plan mode None: the qualification reads the index of a plan of protocol schema 3, of mode "
                        "campaign or rehearsal (features/dataset.py build)"),
    ("campaign", "final", None),
], ids=["campaign_before_final", "rehearsal_at_final", "no_plan_mode", "campaign_at_final"])
def test_the_command_reads_an_index_only_at_the_stages_of_its_plan_mode(tmp_path, monkeypatch, capsys, plan_mode,
                                                                        stage, refusal):
    """Verification of B6a, finding F4. The sessions of a campaign are the dataset, so the command reads the index of
    a campaign at stage final only, where role test_controls stays sealed: no control outcome is read and the archive
    of the session of test_controls the index names is never opened. A rehearsal is never in the dataset, so its index
    is never read at stage final (a rehearsal at stage generalka: the command test above). An index without its plan
    mode is refused. A refusal comes before any feature archive is opened."""
    from features import qualification
    rows, sessions = corpus()
    index = write_index(tmp_path, rows, sessions, **({} if plan_mode is None else {"plan_mode": plan_mode}))
    doc = json.loads(index.read_text())
    doc["sessions"].append({"id": "v5-test_controls-1#0", "role": "test_controls", "group": "v5-test_controls-1",
                            "vm": "a", "scenario": "eshop_low", "position": 0, "start": 1e6,
                            "features": str(tmp_path / "sealed" / "features.npz"), "features_sha256": "0" * 64,
                            "session": str(tmp_path / "sealed" / "session.json")})
    index.write_text(json.dumps(doc))
    out, opened, original = tmp_path / "qualification.json", [], qualification._archive
    monkeypatch.setattr(qualification, "_archive", lambda record: opened.append(record["id"]) or original(record))
    code = qualification.main(["--index", str(index), "--stage", stage, "--out", str(out)])
    if refusal is not None:
        assert (code, opened, out.exists()) == (2, [], False)
        assert capsys.readouterr().err == f"qualification: {index}: {refusal}\n"
        return
    doc = json.loads(out.read_text())
    assert (code, doc["stage"], doc["plan_mode"], doc["complete"]) == (0, "final", "campaign", True)
    assert doc["values"]["inputs"]["response"] == {
        "supplied": False, "why": "role test_controls is sealed outside the final evaluation (scripts/controls.py)",
        "skipped": []}
    assert sorted(opened) == sorted(s["id"] for s in sessions)
