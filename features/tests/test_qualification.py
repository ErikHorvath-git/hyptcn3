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
The train groups run on VM a and the dev groups on VM b, after them. Names of package B6a are imported inside the
tests, so this file collects on the code before it.

The fix after the verification of B6a (dokazy/B6/ZADANIE_oprava_B6a.md) adds: a kind of comparison that the sessions
lack (finding F1); the stage of the command against the plan mode of the index (F4); a column exactly at
near_constant_share and at identity_auc, and the rank test of a differenced column by its first difference (F6).

Package B11 (the lead's answers of 2026-11-24 to questions Q7 and Q25): no strata, the effect of scenario and position
subtracted, the comparisons over all sessions (the VM, the halves of the session order, each group with all its
sessions), so in the corpus above the column that tells the group fails first on the VM, with which the halves of the
order coincide; the data of the plan mode (every role of a rehearsal, train and dev of a campaign); the lead's tests
on two designs, the real rehearsal plan (30 sessions of every role) and the campaign's train and dev (48), with seeds
0 to 4 fixed in advance; the tie of a column that depends only on scenario and position; the rows of the controls of
test_controls left out; the seal asked before an archive of a sealed role is opened. Only mechanics on synthetic rows;
no number here is a detection result.
"""
import hashlib
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
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")
    return result, {row["column"]: row for row in result["table"]}


SPECIAL = {"mod_total", "sock_listen", "proc_kernel", "mem_changed_ratio", "sock_total", "proc_wx"}
# The first comparison of score 1 in the order vm, order, groups (package B11): in this corpus the VM and the halves
# of the session order coincide, and so does the VM with the two groups of each side.
WORST = "vm a against vm b"


def test_each_column_gets_its_class_with_the_numbers_in_the_table(qualified):
    """Skeleton section 6 test 1: the constant and the near-constant column go to the rule channel, the duplicate
    and the column that tells the group are dropped, every other column is neural. The proposal is a valid value of
    analysis.columns of the protocol."""
    from scripts import protocol_v5
    result, table = qualified
    assert result["schema"] == "hyptcn3/feature-qualification/2" and list(table) == list(BEHAVIOR_NAMES)
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
    # VM a holds the two lower groups: AUC 0, score 1.
    assert (tells["identity"]["score"], tells["identity"]["auc"], tells["identity"]["rows"]) == (1.0, 0.0, [720, 720])
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
    """Question Q8 to the lead, his revised proposal (accepted by the lead 2026-11-24; package B6b): a level column that
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
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")
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
    """Every session of scenario eshop_low, by start v5-train-1 (VM a), v5-train-2 (b), v5-dev-1 (a), v5-dev-2 (b), the
    positions 0 to 2 in each. Noise in every column but three, each of which tells exactly one kind of comparison:
    mem_changed_ratio the group v5-dev-2 (0.5 more), mem_bins_active the VM (0.5 on VM b) and mem_changed_max the half
    of the session order (0.5 in the last two groups), each plus noise of width 0.1."""
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
            x[:, :3] = rng.uniform(0, .1, (ROWS, 3)) + [.5 * (g == 3), .5 * (vm == "b"), .5 * (g >= 2)]
            rows[name] = x
    return rows, sessions


@pytest.mark.parametrize("column, kind, comparison, sides, drop", [
    ("mem_changed_ratio", "group", "group v5-dev-2 against the other groups", [360, 1080], None),
    ("mem_bins_active", "vm", "vm a against vm b", [720, 720], None),
    ("mem_changed_max", "order", "first 6 against last 6 of 12 sessions by start", [720, 720], None),
    ("mem_changed_max", "order", "first 5 against last 5 of 11 sessions by start", [600, 600], "v5-dev-2#2"),
], ids=["group", "vm", "session_order", "session_order_of_an_odd_count"])
def test_the_table_names_the_worst_comparison_of_the_identity_test(column, kind, comparison, sides, drop):
    """Design B6a 1.4 point 4 under the rule of question Q7 (package B11): over all sessions VM a against b, the first
    against the second half of the session order and each group with all its sessions against the other groups; the
    column fails on the comparison that tells its sides apart (score 1), and the table names it with its kind, while
    every other column passes. The other comparisons of the column that tells one group score 0.75 at most (its VM and
    its half hold three of six sessions), so the group is named. Without the last session, 11 sessions: the middle
    one (v5-train-2#2) is in neither half."""
    from features.qualification import qualify
    rows, sessions = comparison_corpus()
    if drop is not None:
        rows.pop(drop)
        sessions = [s for s in sessions if s["id"] != drop]
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")
    table = {row["column"]: row for row in result["table"]}
    worst = table[column]["identity"]
    assert (table[column]["class"], worst["score"], worst["comparison"]) == ("dropped", 1.0, comparison)
    assert (worst["kind"], worst["rows"]) == (kind, sides)
    assert {name for name, row in table.items() if row["class"] != "neural"} == {
        "mem_changed_ratio", "mem_bins_active", "mem_changed_max"}
    assert result["inputs"]["compared"] == {"vm": 1, "order": 1, "group": 4}
    assert result["inputs"]["comparisons"] == 1 + 1 + 4


# The runner's order (package B9, protocol_v5.plan sessions_per_vm): each VM runs its sessions in the plan's order,
# SLOT_S apart, both VMs at once, VM b a minute after VM a.
SLOT_S, VM_LAG_S = 4000., 60.


def plan_sessions(mode, roles=None):
    """The sessions of the real plan of `mode` (protocol_v5.planned_rows of config/collection-v5.json) of `roles` (every
    role when None), in the plan's order, started as the runner starts them (SLOT_S, VM_LAG_S)."""
    from scripts import protocol_v5
    p = json.loads(V5.read_text())
    out, slots = [], {}
    for row in protocol_v5.planned_rows(p, mode):
        slot = slots[row["vm"]] = slots.get(row["vm"], -1) + 1
        if roles is None or row["role"] in roles:
            out.append({"id": row["label"], "role": row["role"], "group": row["group"], "vm": row["vm"],
                        "scenario": row["scenario"], "profile": p["scenarios"][row["scenario"]]["profile"],
                        "position": row["position"], "start": slot * SLOT_S + VM_LAG_S * (row["vm"] == "b")})
    return out


def rehearsal_corpus():
    """(rows, sessions) of the real rehearsal plan (G3a, where proposal 8.1 runs the qualification): the 30 sessions of
    every role of protocol_v5.planned_rows(p, "rehearsal") of config/collection-v5.json (plan_sessions), 120 rows each.
    Noise in every column but mod_total (constant 31), mem_entropy_mean (1 more in group g5-train-1: it tells the
    group) and mem_changed_ratio (0.5 more on VM b: it tells the VM)."""
    rng = np.random.default_rng(20261124)
    column = {name: k for k, name in enumerate(BEHAVIOR_NAMES)}
    rows, sessions = {}, plan_sessions("rehearsal")
    for s in sessions:
        x = np.concatenate((rng.uniform(0, 1, (ROWS, 8)), rng.integers(20, 40, (ROWS, 12))), axis=1)
        x[:, column["mod_total"]] = 31
        x[:, column["mem_entropy_mean"]] += 1. * (s["group"] == "g5-train-1")
        x[:, column["mem_changed_ratio"]] += .5 * (s["vm"] == "b")
        rows[s["id"]] = x
    return rows, sessions


def one_vm_corpus():
    """corpus() with every session on VM a: a degenerate input, which compares no VM."""
    rows, sessions = corpus()
    return rows, [dict(s, vm="a") for s in sessions]


VM_UNTESTED = "not tested, the sessions hold one VM"
INCOMPLETE = ("qualification: incomplete ({}): proposal 8.1 compares the VM, the session order and the group; "
              "acknowledge_incomplete=True (the command's --acknowledge-incomplete) records an incomplete qualification")


@pytest.mark.parametrize("case", ["complete", "one_vm_refused", "one_vm_acknowledged", "rehearsal"])
def test_a_kind_of_comparison_that_the_sessions_lack_never_reads_as_passed(qualified, case):
    """Verification of B6a, finding F1, under the rule of question Q7 (package B11): proposal 8.1 compares the VM, the
    session order and the group over all sessions. complete: the corpus above compares each kind (one comparison of the
    VM, one of the order and one of each of its four groups); inputs and every row that the identity test judged count
    them (a rule column: null), and a neural column passed every check. one_vm: that corpus on VM a alone compares no
    VM, and qualify() refuses it unless the caller acknowledges it. Acknowledged, the result says complete false and
    why, counts no comparison of the VM in inputs and in every row that the identity test judged, and the reason of
    each such row ends with why; no row says it passed every check. rehearsal: the 30 sessions of every role of the
    real rehearsal plan compare every kind, the VM too, which no stratum of train and dev compared before: the column
    that tells the VM is caught, as is the one that tells the group, and the constant one keeps its reason."""
    from features.qualification import qualify
    protocol = json.loads(V5.read_text())
    counts, untested = {"vm": 1, "order": 1, "group": 4}, {}
    if case == "complete":
        result = qualified[0]
    elif case == "rehearsal":
        rows, sessions = rehearsal_corpus()
        result, counts = qualify(rows, sessions, protocol, mode="rehearsal"), {"vm": 1, "order": 1, "group": 10}
    else:
        rows, sessions = one_vm_corpus()
        if case == "one_vm_refused":
            with pytest.raises(ValueError, match="^" + re.escape(INCOMPLETE.format("vm: " + VM_UNTESTED)) + "$"):
                qualify(rows, sessions, protocol, mode="campaign")
            return
        result = qualify(rows, sessions, protocol, mode="campaign", acknowledge_incomplete=True)
        counts, untested = dict(counts, vm=0), {"vm": VM_UNTESTED}
    table = {row["column"]: row for row in result["table"]}
    assert (result["complete"], result["untested"], result["acknowledge_incomplete"]) == (
        not untested, untested, case == "one_vm_acknowledged")
    assert result["inputs"]["compared"] == counts and result["inputs"]["comparisons"] == sum(counts.values())
    assert all(row["compared"] == (None if row["class"] == "rule" else counts) for row in table.values())
    gap = "".join(f"; {kind}: {why}" for kind, why in untested.items())
    for row in table.values():
        if row["class"] == "neural":
            assert row["reason"] == ("neural: passed the checks that ran" + gap if untested else
                                     "neural: passed every check")
        elif row["class"] == "rule":
            assert row["reason"].startswith(("constant", "near-constant")) and (not gap or gap not in row["reason"])
        else:
            assert row["reason"].endswith(gap) and "passed every check" not in row["reason"]
    if case == "rehearsal":
        assert {name: table[name]["class"] for name in ("mod_total", "mem_entropy_mean", "mem_changed_ratio")} == {
            "mod_total": "rule", "mem_entropy_mean": "dropped", "mem_changed_ratio": "dropped"}
        # The adjustment takes a little of the shift of g5-train-1 into its scenarios and positions: 0.9968, not 1.
        for name, kind, score, comparison in (
                ("mem_entropy_mean", "group", "0.9968", "group g5-train-1 against the other groups"),
                ("mem_changed_ratio", "vm", "0.8682", "vm a against vm b")):
            assert table[name]["identity"]["kind"] == kind and table[name]["reason"] == (
                f"identity: max(AUC, 1 - AUC) {score} above identity_auc 0.75 ({comparison})")
        assert result["inputs"]["roles"] == dict.fromkeys(
            ("train", "dev", "calibration", "test_benign", "test_controls"), 6)
        assert {row["class"] for row in table.values()} == {"rule", "dropped", "neural"}


@pytest.mark.parametrize("column", ["sock_listen", "mem_entropy_mean"], ids=["near_constant_share", "identity_auc"])
def test_a_column_exactly_at_a_bound_is_neural(column):
    """Verification of B6a, finding F6 (mutants Q1 and Q2), on the corpus above cut to the first 100 rows of each
    session (1200 rows). Near-constant means fewer than near_constant_share of the rows off the mode: sock_listen is
    20, and 21 in row 5 of every session, 12 of the 1200 rows, exactly 0.01. A column fails the identity test when
    max(AUC, 1 - AUC) exceeds identity_auc: mem_entropy_mean is 1 in the first 75 and -2 in the last 25 rows of each
    session of v5-train-1 and 0.25 in every other row, so every session mean is 0.25 and the adjustment of question Q7
    (package B11) subtracts the same 0.25 from every row, exactly after its rounding; the group v5-train-1 against the
    other groups then scores exactly 0.75 (AUC 0.75), the VM and the order 0.625. Both columns are neural."""
    from features.qualification import qualify
    rows, sessions = corpus()
    j = BEHAVIOR_NAMES.index(column)
    for name in rows:
        x = rows[name] = rows[name][:100]
        if column == "sock_listen":
            x[:, j] = 20
            x[5, j] = 21
        elif name.startswith("v5-train-1#"):
            x[:75, j] = 1
            x[75:, j] = -2
        else:
            x[:, j] = .25
    row = {r["column"]: r for r in qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")["table"]}[
        column]
    assert (row["class"], row["reason"]) == ("neural", "neural: passed every check")
    worst = row["identity"]
    if column == "sock_listen":
        assert (row["off_mode_share"], worst["score"]) == (.01, .5)
    else:
        assert (row["off_mode_share"], worst["score"], worst["auc"], worst["comparison"], worst["kind"]) == (
            300 / 1200, .75, .75, "group v5-train-1 against the other groups", "group")


# The lead's tests of question Q7 (his answer of 2026-11-24): their seeds, fixed in advance, and his numbers (row noise
# SD 1). A seed that fails is a finding for the lead, never a reason to change it (design B11, section 1).
LEAD_SEEDS = (0, 1, 2, 3, 4)
LEVEL_SD = .5  # "náhodný posun úrovne session o 0,5 SD"
SHIFT = 1.5  # "posun skupiny, VM alebo polovice poradia o 1,5 SD"
# The two designs (design B11, section 1): the real rehearsal plan, every role (G3a), and the campaign's train and dev.
DESIGNS = {"rehearsal": None, "campaign": ("train", "dev")}


def lead_corpus(design, seed, subjects):
    """(rows, sessions) on a design of the lead's tests: the sessions of plan_sessions in the plan's order, ROWS rows of
    uniform noise of the stream [seed, 2] in every column, but each column of `subjects` ({column: (stream, its values
    in one session)}), drawn session by session in the plan's order from np.random.default_rng(stream)."""
    sessions = plan_sessions(design, DESIGNS[design])
    noise = np.random.default_rng([seed, 2])
    rows = {s["id"]: noise.uniform(0, 1, (ROWS, len(BEHAVIOR_NAMES))) for s in sessions}
    for name, (stream, values) in subjects.items():
        rng = np.random.default_rng(stream)
        for s in sessions:
            rows[s["id"]][:, BEHAVIOR_NAMES.index(name)] = values(s, rng)
    return rows, sessions


def later_half(sessions):
    """The ids of the last floor(n/2) of the n sessions by (start, id), the second side of the comparison order."""
    ordered = sorted(sessions, key=lambda s: (s["start"], s["id"]))
    return {s["id"] for s in ordered[len(ordered) - len(ordered) // 2:]}


@pytest.mark.parametrize("seed", LEAD_SEEDS)
@pytest.mark.parametrize("design", DESIGNS)
def test_a_random_level_of_each_session_drops_no_column(design, seed):
    """The lead's first test of question Q7: a random level of each session, of SD 0.5 of the row noise and
    independent of everything, is ordinary variability, which the predictor sees in the window's context; it drops no
    column. mem_changed_ratio (no level column) is that level plus noise of SD 1 in each row, drawn from the seed
    session by session in the plan's order (level, then the rows); it passes every check."""
    from features.qualification import qualify
    rows, sessions = lead_corpus(design, seed, {
        "mem_changed_ratio": (seed, lambda s, rng: rng.normal(0, LEVEL_SD) + rng.normal(0, 1, ROWS))})
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode=design)
    row = {r["column"]: r for r in result["table"]}["mem_changed_ratio"]
    assert (result["complete"], row["class"], row["reason"]) == (True, "neural", "neural: passed every check")
    assert row["identity"]["score"] <= .75


@pytest.mark.parametrize("seed", LEAD_SEEDS)
@pytest.mark.parametrize("design", DESIGNS)
def test_a_column_that_depends_only_on_the_intensity_passes(design, seed):
    """The lead's second test of question Q7: the adjustment subtracts the effect of the scenario, whose intensity
    (low or high) the strata (profile, position) mixed before (finding F2 of the verification of B6a: a column that
    depends only on the intensity was dropped at 0.80). mem_bins_active is 1 and mem_changed_max 3 row SD higher in a
    session of intensity high, plus noise of SD 1; both pass every check."""
    from features.qualification import qualify
    rows, sessions = lead_corpus(design, seed, {
        "mem_bins_active": (seed, lambda s, rng: 1. * s["scenario"].endswith("_high") + rng.normal(0, 1, ROWS)),
        "mem_changed_max": ([seed, 1], lambda s, rng: 3. * s["scenario"].endswith("_high") + rng.normal(0, 1, ROWS))})
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode=design)
    table = {r["column"]: r for r in result["table"]}
    for name in ("mem_bins_active", "mem_changed_max"):
        assert (table[name]["class"], table[name]["reason"]) == ("neural", "neural: passed every check")
        assert table[name]["identity"]["score"] <= .75


@pytest.mark.parametrize("seed", LEAD_SEEDS)
@pytest.mark.parametrize("design", DESIGNS)
def test_a_shift_of_a_group_a_vm_or_the_later_half_drops_the_column(design, seed):
    """The lead's third test of question Q7: a systematic shift between groups, VMs or in time is what carries over
    from training to test as an error. A shift of 1.5 row SD of one group with all its sessions (the seed's group in
    the order of names), of VM b and of the later half of the session order drops a column that is no level column
    (mem_changed_p95, mem_changed_spread and mem_entropy_max), and the worst comparison names that kind (and that
    group); a level column with the same shift (sock_total, sock_estab and proc_user) is judged by its first
    difference, which no shift moves, and comes out differenced."""
    from features.qualification import qualify
    groups = sorted({s["group"] for s in plan_sessions(design, DESIGNS[design])})
    late = later_half(plan_sessions(design, DESIGNS[design]))
    shifted = {"group": lambda s: s["group"] == groups[seed], "vm": lambda s: s["vm"] == "b",
               "order": lambda s: s["id"] in late}
    columns = {"group": ("mem_changed_p95", "sock_total"), "vm": ("mem_changed_spread", "sock_estab"),
               "order": ("mem_entropy_max", "proc_user")}

    def value(kind):
        return lambda s, rng: SHIFT * shifted[kind](s) + rng.normal(0, 1, ROWS)
    subjects = {}
    for k, (kind, (plain, level)) in enumerate(columns.items()):
        subjects.update({plain: ([seed, 10 + k], value(kind)), level: ([seed, 20 + k], value(kind))})
    rows, sessions = lead_corpus(design, seed, subjects)
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode=design)
    table = {r["column"]: r for r in result["table"]}
    n = len(sessions)
    named = {"group": f"group {groups[seed]} against the other groups", "vm": "vm a against vm b",
             "order": f"first {n // 2} against last {n // 2} of {n} sessions by start"}
    for kind, (plain, level) in columns.items():
        worst = table[plain]["identity"]
        assert (table[plain]["class"], worst["kind"], worst["comparison"]) == ("dropped", kind, named[kind])
        assert worst["score"] > .75 and table[plain]["reason"] == (
            f"identity: max(AUC, 1 - AUC) {worst['score']:.4f} above identity_auc 0.75 ({named[kind]})")
        assert (table[level]["class"], table[level]["identity"]["kind"]) == ("differenced", kind)
        assert table[level]["identity_of_difference"]["score"] <= .75


@pytest.mark.parametrize("design", DESIGNS)
def test_a_column_constant_in_sessions_that_depends_only_on_scenario_and_position_scores_one_half(design):
    """Package B11, RULES rounding: mem_entropy_mean is a table of the scenario plus 0.3 x position in every row of a
    session, so the adjustment of question Q7 fits it exactly and leaves the same value in every row; rounded to its
    quantum the ties survive the float residues of the fit, and every comparison scores exactly 0.5 (the first named, of
    the VM). The column passes every check."""
    from features.qualification import QUANTUM, qualify
    table_of = {"eshop_low": .4, "eshop_high": .7, "corp_low": .3, "corp_high": .8}
    rows, sessions = lead_corpus(design, 0, {
        "mem_entropy_mean": (0, lambda s, rng: np.full(ROWS, table_of[s["scenario"]] + .3 * s["position"]))})
    result = qualify(rows, sessions, json.loads(V5.read_text()), mode=design)
    row = {r["column"]: r for r in result["table"]}["mem_entropy_mean"]
    assert (row["identity"]["score"], row["identity"]["auc"], row["identity"]["comparison"]) == (
        .5, .5, "vm a against vm b")
    assert (row["class"], row["reason"]) == ("neural", "neural: passed every check")
    assert result["inputs"]["adjustment"] == {"scenarios": sorted(table_of), "positions": [0, 1, 2],
                                              "quantum": QUANTUM}


def test_the_first_difference_is_judged_after_the_same_adjustment():
    """RULES judged_again (package B11): a level column that fails the identity test is judged again by its first
    difference after the same adjustment of scenario and position. In the corpus above with every session of VM b of
    intensity high and every one of VM a of intensity low, sock_estab is 10000 x group index (its value tells the
    group) plus the running sum of a drift 3 row SD faster in a session of intensity high and of noise of SD 1: its
    first difference depends only on the intensity, which here is the VM, so unadjusted it would tell VM a from VM b;
    adjusted it passes, and the column is differenced."""
    from features.qualification import qualify
    rows, sessions = corpus()
    sessions = [dict(s, scenario=s["profile"] + ("_high" if s["vm"] == "b" else "_low")) for s in sessions]
    rng, j = np.random.default_rng(20261124), BEHAVIOR_NAMES.index("sock_estab")
    for s in sessions:
        rows[s["id"]][:, j] = 10000 * GROUPS.index(s["group"]) + np.cumsum(3. * (s["vm"] == "b")
                                                                            + rng.normal(0, 1, ROWS))
    row = {r["column"]: r for r in qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")["table"]}[
        "sock_estab"]
    again = row["identity_of_difference"]
    assert (row["class"], row["identity"]["score"] > .75, again["score"] <= .75) == ("differenced", True, True)
    assert row["reason"].endswith(f"; its first difference scores {again['score']:.4f}, at most 0.75")


def test_the_adjustment_takes_one_unweighted_mean_per_session():
    """RULES adjustment (question Q7: the effect is fitted "z priemerov session"): every session's mean counts once,
    whatever its number of rows. Four sessions of groups g1 (VM a) and g2 (VM b), by start a#0 (eshop_low, position 0,
    10 rows), b#0 (eshop_low, position 0, 110 rows), b#1 (corp_low, position 1, 60 rows) and a#1 (corp_low, position 1,
    60 rows); mem_entropy_mean is 0, 1, 0 and 1 in every row of them. Each cell's fitted value is the mean of its two
    session means, 0.5, so the adjusted values are -0.5 and 0.5: the VM and the group (a#0 and a#1 against b#0 and b#1)
    score 0.605 and the order (a#0 and b#0 against b#1 and a#1) 17/24, at most 0.75. A fit by rows would give the cell
    eshop_low 110/120 and tell the VM at 6/7."""
    from features.qualification import qualify
    rng, j = np.random.default_rng(20261124), BEHAVIOR_NAMES.index("mem_entropy_mean")
    rows, sessions = {}, []
    for k, (name, scenario, n, value) in enumerate((("a#0", "eshop_low", 10, 0.), ("b#0", "eshop_low", 110, 1.),
                                                    ("b#1", "corp_low", 60, 0.), ("a#1", "corp_low", 60, 1.))):
        vm = name[0]
        sessions.append({"id": name, "role": "train" if vm == "a" else "dev", "group": "g1" if vm == "a" else "g2",
                         "vm": vm, "scenario": scenario, "profile": scenario.split("_")[0], "position": int(name[2]),
                         "start": 1000. * k})
        x = rng.uniform(0, 1, (n, len(BEHAVIOR_NAMES)))
        x[:, j] = value
        rows[name] = x
    row = {r["column"]: r for r in qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")["table"]}[
        "mem_entropy_mean"]
    worst = row["identity"]
    assert (row["class"], worst["comparison"], worst["rows"]) == (
        "neural", "first 2 against last 2 of 4 sessions by start", [120, 120])
    assert worst["score"] == pytest.approx(17 / 24, abs=1e-12)


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
    row = {r["column"]: r for r in qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")["table"]}[
        "sock_total"]
    kept = row["rank_test"]["kept_before"]
    assert (row["class"], row["identity"]["score"], "mem_changed_max" in kept) == ("dropped", 1.0, True)
    assert row["identity_of_difference"]["score"] <= .75 and row["rank_test"]["relative_singular_value"] < 1e-9
    assert row["reason"].startswith(f"duplicate: exact linear combination of the {len(kept)} columns kept before it")


@pytest.mark.parametrize("mode, role, reason", [
    ("campaign", "calibration", "qualification: session v5-dev-2#1 of role calibration: plan mode campaign reads the "
                                "roles train, dev only (question Q7)"),
    (None, "dev", "qualification: plan mode None: the qualification reads the roles of plan mode rehearsal or campaign "
                  "(question Q7)"),
], ids=["a_role_outside_the_mode", "no_mode"])
def test_the_plan_mode_names_the_roles_and_has_no_default(mode, role, reason):
    """Question Q7 (package B11, RULES data): the plan mode names the roles the qualification reads, every role of a
    rehearsal and train and dev of a campaign; a session of another role is refused by name, and a qualification
    without a plan mode is refused, never read as one of them (no silent default)."""
    from features.qualification import qualify
    rows, sessions = corpus()
    sessions = [dict(s, role=role) if s["id"] == "v5-dev-2#1" else s for s in sessions]
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        qualify(rows, sessions, json.loads(V5.read_text()), mode=mode)


def test_a_session_with_one_measured_row_is_refused():
    """Every session needs a first difference (the module docstring of features/qualification.py), so every
    comparison of a first difference holds the sessions of the comparison of the value, and compared holds for
    both."""
    from features.qualification import qualify
    rows, sessions = corpus()
    rows["v5-dev-2#1"] = rows["v5-dev-2#1"][:1]
    reason = ("qualification: rows of session v5-dev-2#1: needs at least two rows of 20 finite values (a first "
              "difference)")
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        qualify(rows, sessions, json.loads(V5.read_text()), mode="campaign")


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


def write_index(tmp_path, rows, sessions, *, controls=None, **fields):
    """A corpus index (features/dataset.py) of these sessions on the real protocol file, with `fields` (its plan
    mode): every session in a directory of its own, as a feature archive of ROWS + 1 rows whose seq 0 is a full
    snapshot, so that its measured rows are its rows here (row i at seq i + 1, the time start + 5 (i + 1)). A session of
    role test_controls keeps a controls.json of the occurrences `controls` names for it (none by default), named in its
    record with its sha256, as features/dataset.py build writes it."""
    from scripts import protocol_v5
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
        if s["role"] == "test_controls":
            (directory / "controls.json").write_text(json.dumps({
                "schema": protocol_v5.CONTROLS_SCHEMA, "controls": (controls or {}).get(s["id"], []),
                "note": "synthetic record of the test"}))
            records[-1].update(controls=str(directory / "controls.json"),
                               controls_sha256=bs.collection.digest(directory / "controls.json"))
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
    assert (doc["schema"], doc["stage"], doc["n"]) == ("hyptcn3/feature-qualification-record/2", "generalka", 12)
    expected = qualification.qualify(rows, sessions, protocol, mode="rehearsal")
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
    assert (doc["values"]["inputs"]["controls_left_out"], doc["values"]["inputs"]["seal"]) == ({}, {})


@pytest.mark.parametrize("acknowledged", [False, True], ids=["refused", "acknowledged"])
def test_the_record_of_an_incomplete_qualification_says_so(tmp_path, capsys, acknowledged):
    """Finding F1 in the command: on sessions of one VM (an index of plan mode rehearsal at stage generalka, every
    session of the corpus above on VM a) the command writes no record without --acknowledge-incomplete and says why;
    with it the record says complete false and names the untested kind, at its top and in its values, and its command
    carries the flag."""
    from features import qualification
    rows, sessions = one_vm_corpus()
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


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    """The ledger of the test (tcn/pecat.py zaloz), the ledger every guard reads and the ledger of record
    (tcn.pecat.KNIHA and ZAZNAM), so that the tracked data/results/kniha_pecati.json is never read or written."""
    from tcn import pecat
    path = tmp_path / "ledger" / "kniha_pecati.json"
    path.parent.mkdir()
    monkeypatch.setattr(pecat, "KNIHA", path)
    monkeypatch.setattr(pecat, "ZAZNAM", path)
    pecat.zaloz(command="features/tests/test_qualification.py", ledger=path)
    return path


def watched(monkeypatch):
    """[(event, what)] in the order the command does them: ("seal", archive path, purpose) for every call of
    tcn/pecat.py kontrola and ("open", session id) for every feature archive the command opens."""
    from features import qualification
    from tcn import pecat
    events, archive, kontrola = [], qualification._archive, pecat.kontrola
    monkeypatch.setattr(qualification, "_archive", lambda record: events.append(("open", record["id"]))
                        or archive(record))
    monkeypatch.setattr(pecat, "kontrola", lambda path=None, **kw: events.append(("seal", str(path), kw["purpose"]))
                        or kontrola(path, **kw))
    return events


@pytest.mark.parametrize("plan_mode, stage", [("rehearsal", "generalka"), ("campaign", "final")])
def test_the_command_reads_the_roles_of_its_plan_mode(tmp_path, ledger, monkeypatch, plan_mode, stage):
    """Question Q7 (the lead's answer of 2026-11-24, package B11): the data of the qualification are the roles of the
    plan mode. The 30 sessions of every role of the real rehearsal plan as feature archives in an index: of plan mode
    rehearsal at stage generalka the command reads every role (inputs.roles: all five, 6 sessions each), and before it
    opens an archive of test_benign or test_controls it asks the seal (RULES seal), whose decision the record keeps
    (the ledger of the test holds none of them: not sealed); of plan mode campaign at stage final it reads train and
    dev only, opens no other archive and asks no seal."""
    from features import qualification
    rows, sessions = rehearsal_corpus()
    index, out = write_index(tmp_path, rows, sessions, plan_mode=plan_mode), tmp_path / "qualification.json"
    events = watched(monkeypatch)
    assert qualification.main(["--index", str(index), "--stage", stage, "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    roles = ("train", "dev", "calibration", "test_benign", "test_controls") if plan_mode == "rehearsal" else (
        "train", "dev")
    read = [s for s in sessions if s["role"] in roles]
    sealed = {s["id"]: str(tmp_path / s["id"].replace("#", "-") / "features.npz") for s in read
              if s["role"] in ("test_benign", "test_controls")}
    assert (doc["n"], doc["values"]["inputs"]["roles"]) == (len(read), dict.fromkeys(roles, 6))
    assert {what for event, what, *_ in events if event == "open"} == {s["id"] for s in read}
    assert doc["values"]["proposed_columns"] == qualification.qualify(
        {s["id"]: rows[s["id"]] for s in read}, read, json.loads(V5.read_text()), mode=plan_mode)["proposed_columns"]
    seal = doc["values"]["inputs"]["seal"]
    assert set(seal) == set(sealed) and all(
        (d["purpose"], d["allowed"], d["sealed"], d["archive"]) == ("features/qualification.py", "not_sealed", False,
                                                                     sealed[name]) for name, d in seal.items())
    asked = [path for event, path, *purpose in events if event == "seal" and purpose == ["features/qualification.py"]]
    assert sorted(asked) == sorted(sealed.values())  # Once for each archive of a sealed role, and for no other.
    for name, path in sealed.items():  # The seal before the archive is opened.
        assert events.index(("seal", path, "features/qualification.py")) < events.index(("open", name))


def control(kind, polarity, start_unix, duration_s):
    """The record of one occurrence in controls.json as the runner writes it (scripts/collection.py Controls) with the
    fields scripts/controls.py _occurrence reads: a kind of class A, executed, its baseline, effect and cleanup held."""
    return {"kind": kind, "polarity": polarity, "class": "control" if polarity == "control" else "control_negative",
            "kind_class": "A", "dose": None, "executed": True, "baseline": {"ok": True}, "effect": {"ok": True},
            "cleanup": {"ok": True}, "host_start_unix": start_unix, "host_started_unix": start_unix + 1.,
            "host_stop_unix": start_unix + duration_s, "host_stopped_unix": start_unix + duration_s + 1.}


def test_the_rows_of_a_control_and_of_its_negative_are_left_out(tmp_path, ledger):
    """Question Q25 (the lead's answer of 2026-11-24, package B11): the rows of every control and of its paired
    negative are left out of the qualification, from host_start_unix to max(host_stop_unix, host_start_unix +
    controls.horizon_s), and the record states them per session. In the real rehearsal plan mod_total is 31 in every
    row; in the first session of test_controls a module control of 300 s, longer than the horizon of 180 s, holds it at
    32 in the 60 rows from seq 41 to 100, which it covers: kept, they would make the column neither constant nor
    near-constant (60 of 3600 rows off the mode), so it would leave the rule channel. In the second session of
    test_controls a negative of 100 s starts at the time of the row of seq 20 and leaves out the 36 rows of its
    horizon, from seq 21 to 56: the row at host_start_unix covers the interval before it and stays, the row at the end
    of the horizon is left out (RULES controls_left_out). Left out, mod_total is constant again; the events of a
    session would stay (none here)."""
    from features import qualification
    rows, sessions = rehearsal_corpus()
    first, second, *others = [s for s in sessions if s["role"] == "test_controls"]
    j = BEHAVIOR_NAMES.index("mod_total")
    rows[first["id"]][40:100, j] = 32  # Seq 41 to 100, at the times start + 5 x 41 to start + 5 x 100.
    module, negative = first["start"] + 5 * 40 + 2.5, second["start"] + 5 * 20  # The row of seq 20 at the latter.
    controls = {first["id"]: [control("kontrola_modul_jadra", "control", module, 300.)],
                second["id"]: [control("kontrola_modul_jadra", "negative", negative, 100.)]}
    index = write_index(tmp_path, rows, sessions, controls=controls, plan_mode="rehearsal")
    out = tmp_path / "qualification.json"
    assert qualification.main(["--index", str(index), "--stage", "generalka", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    table = {row["column"]: row for row in doc["values"]["table"]}
    assert (table["mod_total"]["class"], table["mod_total"]["reason"]) == ("rule", "constant: zero variance")
    left = doc["values"]["inputs"]["controls_left_out"]
    assert left == {first["id"]: {"rows": 60, "occurrences": [
                        {"kind": "kontrola_modul_jadra", "polarity": "control", "after_unix": module,
                         "until_unix": module + 300., "rows": 60}]},
                    second["id"]: {"rows": 36, "occurrences": [
                        {"kind": "kontrola_modul_jadra", "polarity": "negative", "after_unix": negative,
                         "until_unix": negative + 180., "rows": 36}]},
                    **{s["id"]: {"rows": 0, "occurrences": []} for s in others}}
    counted = {s["id"]: s["rows"] for s in doc["values"]["inputs"]["sessions"]}
    assert (counted[first["id"]], counted[second["id"]], doc["values"]["inputs"]["rows"]) == (60, 84, 30 * ROWS - 96)
    kept = qualification.qualify(rows, sessions, json.loads(V5.read_text()), mode="rehearsal")
    assert {row["column"]: row for row in kept["table"]}["mod_total"]["class"] == "neural"


@pytest.mark.parametrize("held_as", ["campaign", "rehearsal"])
def test_a_sealed_archive_of_a_campaign_in_a_rehearsal_is_refused_before_it_is_opened(tmp_path, ledger, monkeypatch,
                                                                                      capsys, held_as):
    """RULES seal (package B11): the rows of a rehearsal hold the sealed roles, so the command asks the seal
    (tcn/pecat.py kontrola) before it opens such an archive. An archive of test_benign that the ledger seals for a
    campaign, named in the index of a rehearsal, is refused by name: the command exits 2, writes no record and never
    opens it. An archive the ledger holds for the rehearsal passes with the rehearsal's mark, since in a rehearsal
    nothing is sealed (the lead's answer to Q7), and its decision is in the record."""
    from features import qualification
    from tcn import pecat
    rows, sessions = rehearsal_corpus()
    index, out = write_index(tmp_path, rows, sessions, plan_mode="rehearsal"), tmp_path / "qualification.json"
    record = next(r for r in json.loads(index.read_text())["sessions"] if r["role"] == "test_benign")
    pecat.zapis([record], protocol=json.loads(V5.read_text()), protocol_sha256=hashlib.sha256(
        V5.read_bytes()).hexdigest(), mode=held_as, command="features/tests/test_qualification.py", ledger=ledger)
    events = watched(monkeypatch)
    code = qualification.main(["--index", str(index), "--stage", "generalka", "--out", str(out)])
    if held_as == "campaign":
        plan = pecat.plan_name(json.loads(V5.read_text()), "campaign")
        assert (code, out.exists(), ("open", record["id"]) in events) == (2, False, False)
        assert capsys.readouterr().err == (
            f"qualification: features/qualification.py: refused, the archive {record['features']} is sealed (sha256 "
            f"{record['features_sha256']}; session {record['id']} of role test_benign, plan {plan}, ledger {ledger}): "
            "a sealed archive of a campaign is replayed or scored only by the final command (python -m tcn.finalne) "
            "in the run that consumes its seal (tcn/pecat.py GUARD_RULE)\n")
        return
    decision = json.loads(out.read_text())["values"]["inputs"]["seal"][record["id"]]
    assert (code, decision["allowed"], decision["sealed"], decision["rehearsal"], decision["mark"]) == (
        0, "rehearsal", True, True, pecat.REHEARSAL_MARK)
