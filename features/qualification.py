"""Qualification of the feature columns before training (protocol v5, package B6a).

Proposal 8.1 (docs/NAVRH_PROTOKOL_V5.sk.md), the lead's skeleton dokazy/B6/kostra/KOSTRA.md sections 2 and 3, and
design B6a sections 1.4 and 1.5. On the measured rows of the roles train and dev, from the features alone and never
from a score, every column of features.archive.BEHAVIOR_NAMES gets one class; the classes are the proposed value of
the protocol key analysis.columns. The bounds are analysis.qualification of the protocol (G0).

    qualify(rows, sessions, protocol, *, load=None, response=None, acknowledge_incomplete=False)
                                    -> {schema, complete, untested, acknowledge_incomplete, table, proposed_columns,
                                        inputs}
    column_summary(result)          values.columns of the audit of one session (scripts/collection.py audit_session)
    python -m features.qualification --index I --stage S --out O [--acknowledge-incomplete]
                                    one record of data/results from a corpus index (features/dataset.py)

Measured rows: valid under the protocol's quality policy, no full snapshot and with a predecessor (the columns
je_plna and ma_predchodcu), in the order of seq; in a full snapshot the memory part describes the whole memory and
without a predecessor proc_new, proc_gone and mod_delta are not measured (as scripts/controls.py). The first
difference of a column is taken between consecutive measured rows of one session; where an excluded row lies between
them (the full snapshot, an invalid row) it spans that row's interval too. Every session needs two measured rows at
least, so that it holds a first difference and every comparison of a first difference holds the sessions of the
comparison of the value.

The classes are decided in this order (skeleton section 3, design B6a 1.4):
  1. rule         constant (zero variance) or near-constant (fewer than near_constant_share of the rows off the mode,
                  the smallest of the most frequent values): the rule channel, never an input of the TCN (proposal
                  8.2, D3).
  2. identity     within every stratum (profile, position) the column value alone scores each group against the
                  other groups (the kind group), each VM against the other VMs (vm) and the first against the second
                  half of the stratum's sessions by start (order; the middle one of an odd count in neither half):
                  AUC = P(a > b) + P(a = b) / 2 over the rows of the two sides; of two levels only the first is
                  compared (the second gives 1 - AUC). The column fails when max(AUC, 1 - AUC) of some comparison
                  exceeds identity_auc; the table names the worst comparison. A failing column of level_columns is
                  judged again by its first difference, by the whole qualification (question Q8 to the lead, its
                  proposal, provisional until the lead answers; package B6b): rule_differenced when the first
                  difference is constant or near-constant (the rule channel, which judges the column's change since
                  the session's first measured row by the lead's revised proposal; never an input of the TCN and
                  never a duplicate), else differenced when the first difference passes the identity test and
                  dropped when it fails; any other failing column is dropped.
  3. duplicate    greedy in the order of BEHAVIOR_NAMES over the columns that passed (a differenced one by its first
                  difference): standardized over every measured row but the first of each session (where a first
                  difference exists), a column whose smallest singular value beside the columns kept before it is at
                  most duplicate_tolerance times the largest is an exact linear combination of them and is dropped.
  4. neural       every other column.
Load and response are reported only and never change a class: the Spearman correlation and the R² of the linear
regression (proposal 8.1) of the column on the offered load of the row's interval, and for every control kind that
names the column the B8 outcomes (scripts/controls.py outcomes, column_moved). Where one is missing the table says
"not available" and why.

Completeness (verification of B6a, finding F1). Proposal 8.1 names three kinds of comparison: the group, the VM and
the session order. A stratum compares a kind when it holds two of its levels (two groups, two VMs, two sessions). The
qualification is complete when every stratum compares every kind. inputs.strata_compared counts the strata that
compare each kind, inputs.strata names the kinds of each stratum, and every row that the identity test judged carries
the same counts (strata_compared; null for a column of the rule class, which the identity test does not judge).
When a kind is not compared in every stratum, the result says complete false, untested names the kind and why, and
the reason of every row that the identity test judged ends with that; no row then says "passed every check".
qualify() refuses an incomplete qualification unless the caller acknowledges it (acknowledge_incomplete=True, the
command's --acknowledge-incomplete), and the result records the acknowledgment. Refusal is chosen because the proposed
columns become analysis.columns, the mask of the frozen training, and a mask that rests on fewer comparisons than
proposal 8.1 names must never be written without someone deciding so; the acknowledgment and the untested kinds are
in the record. The real rehearsal plan (G3a, where proposal 8.1 runs the qualification) puts the two sessions of every
stratum of train and dev on one VM, so there the VM is never compared (question Q7 to the lead).

The command and the stage (verification of B6a, finding F4). The index states its plan mode (features/dataset.py
build); an index without a plan mode of protocol schema 3 is refused. The sessions of a campaign are the dataset: its
index is read at stage final only, where role test_controls stays sealed and no control outcome is read. A rehearsal
is never in the dataset (proposal 10.4): its index is never read at stage final. Both refusals come before any feature
archive is opened.

The function never writes the protocol: a human or a recorded command writes analysis.columns in G3a (skeleton
section 3); the frozen training applies them and repeats the qualification on the data of the campaign.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

import numpy as np

from .archive import BEHAVIOR_NAMES, load as load_archive
from .snapshot import MENA
from .windows import BIN_PRIZNAKY

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hyptcn3/feature-qualification/1"
RECORD_SCHEMA = "hyptcn3/feature-qualification-record/1"
# The values of analysis.columns: the four of skeleton section 2 and rule_differenced, a level column whose first
# difference is constant or near-constant, which the rule channel judges by its change since the session's first
# measured row (question Q8 to the lead, its revised proposal, provisional until the lead answers; package B6b).
CLASSES = ("neural", "rule", "differenced", "dropped", "rule_differenced")
ROLES = ("train", "dev")  # Proposal 8.1: the qualification reads the rows of these roles only.
# Proposal 8.1: one row must not tell the group, the VM or the session order (the first against the second half).
KINDS = ("group", "vm", "order")
# What a stratum holds when it compares a kind, and what it holds when it does not.
COMPARED_WITH = {"group": "two groups", "vm": "two VMs", "order": "two sessions"}
NOT_COMPARED_WITH = {"group": "one group", "vm": "one VM", "order": "one session"}
NEURAL = "neural: passed every check"  # The reason of a neural column of a complete qualification only.
SESSION_KEYS = ("id", "role", "group", "vm", "scenario", "profile", "position", "start")
SUMMARY_KEYS = ("rows", "min", "max", "mean", "std", "mode", "off_mode_share", "diff_std")
# The per-bin values the normalizer scales (analysis.scale.local_floor): has_changed is a mask, never normalized
# (safeguard/features.py).
LOCAL_SCALED = tuple(name for name in BIN_PRIZNAKY if name != "has_changed")
STAGES = ("suchy", "skuska", "generalka", "final")  # Proposal 11.1, as scripts/controls.py STAGES.
INDEX_SCHEMA = "hyptcn3/corpus-index/1"
GUEST = "none: computed from the feature archives and session logs the corpus index names; no VM is contacted"
RULES = {
    "measured_rows": "valid under the protocol's quality policy, no full snapshot (je_plna 0) and with a predecessor "
                     "(ma_predchodcu 1), in the order of seq",
    "mode": "the smallest of the most frequent values; off_mode_share is the share of the rows with another value",
    "first_difference": "between consecutive measured rows of one session; across an excluded row (a full "
                        "snapshot, an invalid row) it spans that row's interval too; every session has two measured "
                        "rows at least",
    "judged_again": "a level column that fails the identity test is qualified again by its first difference (question "
                    "Q8, its proposal, provisional): constant or near-constant by the same near_constant_share over "
                    "the pooled first differences gives rule_differenced (the rule channel, by the column's change "
                    "since the session's first measured row); otherwise the identity test of the first difference "
                    "gives differenced or dropped",
    "strata": "(profile, position): the profile of the session's scenario (protocol scenarios.<scenario>.profile) "
              "and the session's position in its group",
    "comparisons": "in every stratum each group against the other groups (kind group) and each VM against the other "
                   "VMs (kind vm; of two levels only the first, the second gives 1 - AUC), and the first against the "
                   "last floor(n/2) of its n sessions by start (kind order)",
    "coverage": "a stratum compares a kind when it holds two of its levels (two groups, two VMs, two sessions); the "
                "qualification is complete when every stratum compares every kind of proposal 8.1 (group, vm, "
                "order); otherwise untested names each kind and why, the reason of every row that the identity test "
                "judged ends with it, and qualify() refuses unless the caller acknowledges it "
                "(acknowledge_incomplete, the command's --acknowledge-incomplete)",
    "strata_compared": "per kind the number of strata that compare it, in inputs and in every row that the identity "
                       "test judged (the same for the value and the first difference of a column); null in a row of "
                       "the rule class, which the identity test does not judge",
    "auc": "P(a > b) + P(a = b) / 2 over the rows of the two sides, by midranks; a comparison fails the column when "
           "max(AUC, 1 - AUC) exceeds identity_auc",
    "rank_test": "greedy in the order of BEHAVIOR_NAMES over the columns that passed identity (the first difference "
                 "of a differenced one), each centred and divided by its standard deviation over every measured row "
                 "but the first of each session: a duplicate when the smallest singular value of it beside the "
                 "columns kept before it is at most duplicate_tolerance times the largest",
    "load": "the offered user sessions of the row's interval (t - interval_s, t] (scripts/controls.py), from the "
            "generator's summary intervals pro rata of their overlap with it; Spearman correlation and R² of the "
            "linear regression of the column on it, over the rows of the sessions that have one",
    "response": "for every control kind that names the column (controls.kinds.<kind>.columns) its occurrences by "
                "polarity from scripts/controls.py outcomes, column_moved: reached (a control) or stayed below (a "
                "negative) the expected shift, or not judged (column_moved.ok null)",
}


# ------------------------------------------------------------------ measured rows and the audit summary

def measured(result):
    """The mask of the measured rows (module docstring) of an extraction result or a loaded feature archive."""
    matrix = np.asarray(result["matica"], dtype=np.float64)
    valid = np.asarray(result["valid"], dtype=bool)
    if matrix.ndim != 2 or matrix.shape[1] != len(MENA) or valid.shape != (len(matrix),):
        raise ValueError(f"feature rows need a matrix of {len(MENA)} columns and one validity per row")
    return valid & (matrix[:, MENA.index("je_plna")] == 0) & (matrix[:, MENA.index("ma_predchodcu")] == 1)


def _mode(values):
    """(mode, rows off it): the smallest of the most frequent values (np.unique sorts, argmax takes the first)."""
    unique, counts = np.unique(values, return_counts=True)
    mode = unique[int(np.argmax(counts))]
    return float(mode), int(np.count_nonzero(values != mode))


def summary(values):
    """{rows, min, max, mean, std, mode, off_mode_share, diff_std} of one column over its rows in order: std with
    ddof 0, mode as _mode, diff_std the standard deviation of the first differences of consecutive rows; null where
    a value needs more rows than there are (no row: all of them, one row: diff_std)."""
    x = np.asarray(values, dtype=np.float64)
    if not len(x):
        return {"rows": 0, **dict.fromkeys(SUMMARY_KEYS[1:])}
    mode, off = _mode(x)
    return {"rows": len(x), "min": float(x.min()), "max": float(x.max()), "mean": float(x.mean()),
            "std": float(x.std()), "mode": mode, "off_mode_share": off / len(x),
            "diff_std": float(np.diff(x).std()) if len(x) > 1 else None}


def column_summary(result):
    """values.columns of the session audit (design B6a 1.5): summary() of every column of BEHAVIOR_NAMES over the
    session's measured rows. A record only: the audit never makes it a reason."""
    matrix = np.asarray(result["matica"], dtype=np.float64)[measured(result)]
    return {name: summary(matrix[:, j]) for j, name in enumerate(BEHAVIOR_NAMES)}


# ------------------------------------------------------------------ statistics

def _midranks(values):
    """1-based ranks of `values`; tied values share the mean of their ranks."""
    order = np.argsort(values, kind="mergesort")
    ordered = values[order]
    first = np.flatnonzero(np.concatenate(([True], ordered[1:] != ordered[:-1])))
    last = np.concatenate((first[1:], [len(ordered)]))
    ranks = np.empty(len(values))
    ranks[order] = np.repeat((first + last + 1) / 2, last - first)
    return ranks


def auc(a, b):
    """P(x > y) + P(x = y) / 2 for x drawn from `a` and y from `b` (the Mann-Whitney U over len(a) * len(b))."""
    a, b = np.asarray(a, dtype=np.float64), np.asarray(b, dtype=np.float64)
    ranks = _midranks(np.concatenate((a, b)))
    return float((ranks[:len(a)].sum() - len(a) * (len(a) + 1) / 2) / (len(a) * len(b)))


def _constant(values):
    return bool(np.all(values == values[0]))


def _pearson(x, y):
    """The Pearson correlation; None when x or y is constant."""
    if _constant(x) or _constant(y):
        return None
    x, y = x - x.mean(), y - y.mean()
    return float(x @ y) / math.sqrt(float(x @ x) * float(y @ y))


# ------------------------------------------------------------------ inputs

def _finite_matrix(value, width, what):
    """The rows as a matrix; two rows at least, so that the session holds a first difference (module docstring)."""
    matrix = np.asarray(value, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != width or len(matrix) < 2 or not np.isfinite(matrix).all():
        raise ValueError(f"{what}: needs at least two rows of {width} finite values (a first difference)")
    return matrix


def _sessions(rows, sessions, protocol):
    """The checked sessions sorted by (start, id) and {id: rows}; ValueError names what is wrong."""
    if type(sessions) is not list or not sessions:
        raise ValueError("qualification: no session")
    out, seen = [], set()
    for s in sessions:
        if type(s) is not dict or any(key not in s for key in SESSION_KEYS):
            raise ValueError("qualification: a session needs the keys " + ", ".join(SESSION_KEYS))
        name, position, start = s["id"], s["position"], s["start"]
        if not (type(name) is str and name and all(type(s[k]) is str and s[k] for k in SESSION_KEYS[1:6])
                and isinstance(position, (int, np.integer)) and not isinstance(position, bool) and position >= 0
                and isinstance(start, (int, float, np.number)) and not isinstance(start, bool)
                and math.isfinite(start)):
            raise ValueError(f"qualification: session {name!r}: id, role, group, vm, scenario and profile are names, "
                             "position an integer >= 0 and start a finite number")
        if name in seen:
            raise ValueError(f"qualification: session {name} twice")
        seen.add(name)
        if s["role"] not in ROLES:
            raise ValueError(f"qualification: session {name} of role {s['role']}: proposal 8.1 reads train and dev "
                             "only")
        scenario = protocol["scenarios"].get(s["scenario"])
        if type(scenario) is not dict or scenario.get("profile") != s["profile"]:
            raise ValueError(f"qualification: session {name}: profile {s['profile']} is not the profile of its "
                             f"scenario {s['scenario']} in the protocol")
        out.append(dict({key: s[key] for key in SESSION_KEYS}, position=int(position), start=float(start)))
    if type(rows) is not dict or set(rows) != seen:
        raise ValueError("qualification: rows must name exactly the sessions")
    values = {name: _finite_matrix(rows[name], len(BEHAVIOR_NAMES), f"qualification: rows of session {name}")
              for name in sorted(seen)}
    return sorted(out, key=lambda s: (s["start"], s["id"])), values


def _strata(sessions):
    """[((profile, position), its sessions by start)] in the order of (profile, position)."""
    found = {}
    for s in sessions:
        found.setdefault((s["profile"], s["position"]), []).append(s)
    return sorted(found.items())


def _comparisons(sessions):
    """[(stratum, kind, label, side a ids, side b ids)] of every stratum (RULES comparisons)."""
    out = []
    for stratum, members in _strata(sessions):
        for kind in ("group", "vm"):
            levels = sorted({s[kind] for s in members})
            for level in (levels[:1] if len(levels) == 2 else levels if len(levels) > 2 else []):
                label = (f"{kind} {level} against {kind} {levels[1]}" if len(levels) == 2
                         else f"{kind} {level} against the other {kind}s")
                out.append((stratum, kind, label, [s["id"] for s in members if s[kind] == level],
                            [s["id"] for s in members if s[kind] != level]))
        half = len(members) // 2
        if half:
            out.append((stratum, "order", f"first {half} against last {half} of {len(members)} sessions by start",
                        [s["id"] for s in members[:half]], [s["id"] for s in members[-half:]]))
    return out


def _coverage(sessions, comparisons):
    """({kind: the strata that compare it}, {kind: why it is not tested}) (RULES coverage); a kind compared in every
    stratum is not in the second."""
    strata = [stratum for stratum, _ in _strata(sessions)]
    compared = {kind: {c[0] for c in comparisons if c[1] == kind} for kind in KINDS}
    untested = {}
    for kind in KINDS:
        without = [f"{profile}/{position}" for profile, position in strata if (profile, position) not in compared[kind]]
        if len(without) == len(strata):
            untested[kind] = f"not tested, no stratum (profile, position) of train and dev holds {COMPARED_WITH[kind]}"
        elif without:
            untested[kind] = (f"not tested in {len(without)} of {len(strata)} strata ({', '.join(without)}), each "
                              f"holds {NOT_COMPARED_WITH[kind]}")
    return compared, untested


def _identity(columns, comparisons):
    """The worst comparison of one column, {score, auc, stratum, comparison, sessions, rows} (`columns`: {id:
    values}). Every side of a comparison holds a session, and every session two rows at least (_sessions), so every
    side holds a value and a first difference."""
    worst = None
    for (profile, position), _, label, a, b in comparisons:
        xa = np.concatenate([columns[name] for name in a])
        xb = np.concatenate([columns[name] for name in b])
        value = auc(xa, xb)
        score = max(value, 1 - value)
        if worst is None or score > worst["score"]:
            worst = {"score": score, "auc": value, "stratum": {"profile": profile, "position": position},
                     "comparison": label, "sessions": [a, b], "rows": [len(xa), len(xb)]}
    return worst


def _where(worst):
    return f"{worst['comparison']}, stratum {worst['stratum']['profile']}/{worst['stratum']['position']}"


# ------------------------------------------------------------------ load and response (reported only)

def _load(load, sessions, values):
    """(per column cell, inputs record) of the offered load (RULES load)."""
    if load is None or type(load) is str:
        why = "no offered load supplied to qualify()" if load is None else load
        return lambda j: {"available": False, "why": why}, {"supplied": False, "why": why}
    if type(load) is not dict or set(load) != {s["id"] for s in sessions}:
        raise ValueError("qualification: load must name every session, by its offered load per row or why it has none")
    with_load, without = [], {}
    for s in sessions:
        value = load[s["id"]]
        if type(value) is str:
            without[s["id"]] = value
            continue
        series = np.asarray(value, dtype=np.float64)
        if series.shape != (len(values[s["id"]]),) or not np.isfinite(series).all():
            raise ValueError(f"qualification: load of session {s['id']}: one finite value per measured row")
        with_load.append((s["id"], series))
    record = {"supplied": True, "sessions": [name for name, _ in with_load], "without": without}
    if not with_load:
        why = "no session has an offered load: " + "; ".join(f"{k}: {v}" for k, v in sorted(without.items()))
        return lambda j: {"available": False, "why": why}, dict(record, why=why)
    y = np.concatenate([series for _, series in with_load])

    def cell(j):
        x = np.concatenate([values[name][:, j] for name, _ in with_load])
        r = _pearson(x, y)
        rho = _pearson(_midranks(x), _midranks(y))
        return {"available": True, "rows": len(x), "spearman": rho, "r2": None if r is None else r * r,
                "why": None if r is not None else "the column or the load is constant over these rows"}
    return cell, record


def _response(response, protocol):
    """(per column cell, inputs record) of the control outcomes (RULES response)."""
    if response is None or type(response) is str:
        why = "no control outcomes supplied to qualify()" if response is None else response
        return lambda name: {"available": False, "why": why}, {"supplied": False, "why": why}
    kinds = protocol["controls"]["kinds"]
    if type(response) is not list or not all(
            type(o) is dict and type(o.get("kind")) is str and o["kind"] in kinds
            and o.get("polarity") in ("control", "negative")
            and type(o.get("column_moved")) is dict for o in response):
        raise ValueError("qualification: response must be a list of outcomes of scripts/controls.py for the "
                         "protocol's control kinds")

    def cell(name):
        named = [kind for kind, spec in sorted(kinds.items()) if name in spec["columns"]]
        if not named:
            return {"available": False, "why": "no control kind names this column (controls.kinds.*.columns)"}
        out = {}
        for kind in named:
            counts = {"control": {"occurrences": 0, "reached": 0, "not_judged": 0},
                      "negative": {"occurrences": 0, "stayed_below": 0, "not_judged": 0}}
            for o in response:
                if o["kind"] != kind:
                    continue
                c = counts[o["polarity"]]
                c["occurrences"] += 1
                moved = o["column_moved"]
                if moved.get("ok") is None:
                    c["not_judged"] += 1
                elif moved["columns"][name]["reached"] is (o["polarity"] == "control"):
                    c["reached" if o["polarity"] == "control" else "stayed_below"] += 1
            out[kind] = dict(counts, expect=kinds[kind]["expect"][name])
        return {"available": True, "kinds": out}
    return cell, {"supplied": True, "outcomes": len(response)}


# ------------------------------------------------------------------ the qualification

def qualify(rows, sessions, protocol, *, load=None, response=None, acknowledge_incomplete=False):
    """The classes of the 20 columns (module docstring) as {schema, complete, untested, acknowledge_incomplete, table,
    proposed_columns, inputs}.

    rows: {session id: the session's measured rows as a matrix of the columns of BEHAVIOR_NAMES, in seq order, two
    rows at least}; sessions: [{id, role, group, vm, scenario, profile, position, start}] of roles train and dev,
    position from the plan row of the session (scripts/protocol_v5.py planned_rows); protocol: a protocol of schema 3,
    whose analysis.qualification gives the bounds; load: {session id: the offered load of each measured row, or why
    the session has none}, or why no session has one, or None (not supplied, recorded); response: the outcomes of
    scripts/controls.py of the control occurrences, or why there are none, or None (not supplied, recorded);
    acknowledge_incomplete: True records a qualification in which some stratum compares not every kind of proposal
    8.1 (module docstring, Completeness), which is refused otherwise. ValueError names a malformed input or the
    refusal; the protocol is never written.
    """
    from scripts.protocol_v5 import analysis_plan  # Inside, as features/dataset.py imports scripts/ (no cycle).
    q = analysis_plan(protocol)["qualification"]
    sessions, values = _sessions(rows, sessions, protocol)
    comparisons = _comparisons(sessions)
    if not comparisons:
        raise ValueError("qualification: no stratum (profile, position) holds two groups, two VMs or two sessions")
    compared, untested = _coverage(sessions, comparisons)
    gap = "; ".join(f"{kind}: {why}" for kind, why in untested.items())
    if untested and acknowledge_incomplete is not True:
        raise ValueError(f"qualification: incomplete ({gap}): proposal 8.1 compares the group, the VM and the session "
                         "order in every stratum; acknowledge_incomplete=True (the command's --acknowledge-incomplete) "
                         "records an incomplete qualification")
    strata_compared = {kind: len(compared[kind]) for kind in KINDS}
    order = [s["id"] for s in sessions]
    pooled = np.concatenate([values[name] for name in order])
    differences = {name: np.diff(values[name], axis=0) for name in order}
    bound = q["identity_auc"]
    table, classes = {}, {}
    for j, name in enumerate(BEHAVIOR_NAMES):
        x = pooled[:, j]
        mode, off = _mode(x)
        row = {"column": name, "class": None, "reason": None, "rows": len(x),
               "variance": 0.0 if _constant(x) else float(x.var()), "mode": mode, "off_mode_share": off / len(x),
               "identity": None, "difference": None, "identity_of_difference": None, "strata_compared": None,
               "rank_test": None}
        if _constant(x):
            cls, reason = "rule", "constant: zero variance"
        elif off / len(x) < q["near_constant_share"]:
            cls, reason = "rule", (f"near-constant: {off} of {len(x)} rows off the mode {mode:g}, fewer than "
                                   f"near_constant_share {q['near_constant_share']:g}")
        else:
            row["strata_compared"] = dict(strata_compared)
            worst = row["identity"] = _identity({k: values[k][:, j] for k in order}, comparisons)
            failed = f"identity: max(AUC, 1 - AUC) {worst['score']:.4f} above identity_auc {bound:g} ({_where(worst)})"
            if worst["score"] <= bound:
                cls, reason = "neural", None  # The rank test below decides.
            elif name not in q["level_columns"]:
                cls, reason = "dropped", failed
            else:
                cls, reason = _judged_again(row, j, differences, order, comparisons, q, failed)
        classes[name] = cls
        table[name] = dict(row, **{"class": cls, "reason": reason})
    rank_rows = _rank_test(table, classes, values, differences, order, q["duplicate_tolerance"])
    for name in BEHAVIOR_NAMES:  # A kind that no stratum compared never reads as passed (module docstring).
        row = table[name]
        if row["class"] == "neural":
            row["reason"] = NEURAL if not untested else "neural: passed the checks that ran; " + gap
        elif untested and row["strata_compared"] is not None:
            row["reason"] += "; " + gap
    load_cell, load_record = _load(load, sessions, values)
    response_cell, response_record = _response(response, protocol)
    for j, name in enumerate(BEHAVIOR_NAMES):
        table[name].update(load=load_cell(j), response=response_cell(name))
    return {"schema": SCHEMA, "complete": not untested, "untested": untested,
            "acknowledge_incomplete": acknowledge_incomplete is True,
            "table": [table[name] for name in BEHAVIOR_NAMES],
            "proposed_columns": {name: classes[name] for name in BEHAVIOR_NAMES},
            "inputs": {"sessions": [dict(s, rows=len(values[s["id"]])) for s in sessions], "rows": len(pooled),
                       "roles": {role: sum(s["role"] == role for s in sessions) for role in ROLES},
                       "strata": [{"profile": profile, "position": position, "sessions": [s["id"] for s in members],
                                   "compared": [kind for kind in KINDS if (profile, position) in compared[kind]]}
                                  for (profile, position), members in _strata(sessions)],
                       "strata_compared": strata_compared, "comparisons": len(comparisons),
                       "rank_test_rows": rank_rows, "parameters": dict(q), "load": load_record,
                       "response": response_record, "rules": RULES}}


def _judged_again(row, j, differences, order, comparisons, q, failed):
    """(class, reason) of the level column `j` that failed the identity test (`failed`), qualified again by its first
    difference in the order of the classes (module docstring; question Q8, its proposal, provisional): the variance
    rule over the pooled first differences of every session first (rule_differenced, the rule channel by the change
    since the session's first measured row, which never reaches the rank test and so is never a duplicate), then the
    identity test (differenced, which the rank test still judges, or dropped). The table row gets the difference's
    numbers."""
    d = np.concatenate([differences[k][:, j] for k in order])
    mode, off = _mode(d)
    row["difference"] = {"rows": len(d), "variance": 0.0 if _constant(d) else float(d.var()), "mode": mode,
                         "off_mode_share": off / len(d)}
    if _constant(d):
        return "rule_differenced", failed + "; its first difference is constant: zero variance"
    if off / len(d) < q["near_constant_share"]:
        return "rule_differenced", (failed + f"; its first difference is near-constant: {off} of {len(d)} differences "
                                    f"off the mode {mode:g}, fewer than near_constant_share "
                                    f"{q['near_constant_share']:g}")
    again = row["identity_of_difference"] = _identity({k: differences[k][:, j] for k in order}, comparisons)
    bound = q["identity_auc"]
    if again["score"] <= bound:
        return "differenced", failed + f"; its first difference scores {again['score']:.4f}, at most {bound:g}"
    return "dropped", failed + f"; its first difference scores {again['score']:.4f} above {bound:g} ({_where(again)})"


def _rank_test(table, classes, values, differences, order, tolerance):
    """The duplicate test (RULES rank_test) over the columns that passed identity; it changes their class in place
    and returns the number of rows it ran over (qualify() writes the reason of a column that stays neural)."""
    candidates = [j for j, name in enumerate(BEHAVIOR_NAMES) if classes[name] in ("neural", "differenced")]
    n = sum(len(differences[name]) for name in order)
    if candidates and n <= len(BEHAVIOR_NAMES) + 1:
        raise ValueError(f"qualification: the rank test has {n} rows, it needs more than the "
                         f"{len(BEHAVIOR_NAMES) + 1} columns and the mean")
    kept, basis = [], np.empty((n, 0))
    for j in candidates:
        name = BEHAVIOR_NAMES[j]
        z = np.concatenate([differences[k][:, j] if classes[name] == "differenced" else values[k][1:, j]
                            for k in order])
        if _constant(z):
            relative = 0.0
            stacked = None
        else:
            stacked = np.column_stack((basis, (z - z.mean()) / z.std()))
            singular = np.linalg.svd(stacked, compute_uv=False)
            relative = float(singular[-1] / singular[0])
        table[name]["rank_test"] = {"kept_before": [BEHAVIOR_NAMES[i] for i in kept],
                                    "relative_singular_value": relative}
        if relative <= tolerance:
            classes[name] = "dropped"
            table[name].update(**{"class": "dropped", "reason": (
                "duplicate: constant over the rows of the rank test, a multiple of the mean" if stacked is None else
                f"duplicate: exact linear combination of the {len(kept)} columns kept before it (smallest relative "
                f"singular value {relative:.3g}, at most duplicate_tolerance {tolerance:g})")})
        else:
            kept.append(j)
            basis = stacked
    return n


# ------------------------------------------------------------------ the command

def _archive(record):
    """The loaded feature archive of an index record, after its hash (features/archive.py load)."""
    path = Path(record["features"])
    if hashlib.sha256(path.read_bytes()).hexdigest() != record["features_sha256"]:
        raise ValueError(f"feature archive of session {record['id']} changed since the index: {path}")
    return load_archive(path)


def offered_load(intervals_path, times, interval_s):
    """The offered user sessions in the interval (t - interval_s, t] of every row time t (RULES load), as a list,
    or the reason why there is none (str). The summary intervals of traffic_intervals.jsonl (schema /2) lie at
    header start_unix + mono_start and + mono_end; each adds its offered_sessions times the share of its length
    inside the row's interval, and the intervals must cover the row's interval."""
    from scripts import traffic_log  # Here: features/ imports scripts/ only inside functions (features/dataset.py).
    path = Path(intervals_path)
    if not path.is_file():
        return f"no {path.name} in the session directory"
    records, problems = traffic_log.read_jsonl(path)
    if problems:
        return f"{path.name}: " + ", ".join(problems)
    header = records[0]
    if header.get("schema") != traffic_log.INTERVAL_SCHEMA_2:
        return (f"{path.name} of schema {header.get('schema')}: only {traffic_log.INTERVAL_SCHEMA_2} logs the offered "
                "user sessions")
    origin = header.get("start_unix")
    rows = [r for r in records[1:] if r.get("type") == "interval"]
    if type(origin) not in (int, float) or not rows or not all(
            all(type(r.get(k)) in (int, float) for k in ("mono_start", "mono_end", "offered_sessions"))
            and r["mono_end"] > r["mono_start"] for r in rows):
        return f"{path.name}: no interval with mono_start < mono_end and offered_sessions under a header start_unix"
    start = origin + np.array([r["mono_start"] for r in rows])
    end = origin + np.array([r["mono_end"] for r in rows])
    offered = np.array([r["offered_sessions"] for r in rows], dtype=np.float64)
    high = np.asarray(times, dtype=np.float64)[:, None]
    overlap = np.clip(np.minimum(end, high) - np.maximum(start, high - interval_s), 0, None)
    if not np.allclose(overlap.sum(axis=1), interval_s, rtol=0, atol=1e-6):
        return f"{path.name} does not cover the interval of every measured row"
    return (overlap / (end - start) * offered).sum(axis=1).tolist()


def control_outcomes(records, protocol, stage):
    """(outcomes, skipped) of every control occurrence of the index's sessions of role test_controls
    (scripts/controls.py outcomes at `stage`), or the reason why there are none (str)."""
    if stage == "final":
        return "role test_controls is sealed outside the final evaluation (scripts/controls.py)"
    mine = [r for r in records if r["role"] == "test_controls"]
    if not mine:
        return "the index holds no session of role test_controls"
    from features.dataset import controls_of
    from scripts import controls
    out, skipped = [], []
    for r in mine:
        data = _archive(r)
        doc = controls_of(r)  # Its sha256 checked against the index (package B7c).
        for item in doc["controls"]:
            if item.get("kind") is None:
                continue  # A slot of the plan without a control.
            try:
                # The seal decides by the session's archive in the ledger (package B7c, tcn/pecat.py), not by the
                # stage: a rehearsal's archive carries its mark, a sealed archive of a campaign is refused.
                out.append(controls.outcomes(item, data, protocol, role="test_controls", archive=r["features"],
                                             stage=stage))
            except ValueError as error:
                skipped.append({"session": r["id"], "kind": item["kind"], "why": str(error)})
    return out, skipped


def from_index(index_path, stage):
    """(rows, sessions, protocol, load, response, skipped controls) of the corpus index at `index_path`, read at
    `stage`. The plan mode of the index decides the stages (module docstring): a refusal comes before any archive is
    opened."""
    from scripts.protocol_v5 import MODES
    doc = json.loads(Path(index_path).read_text())
    if type(doc) is not dict or doc.get("schema") != INDEX_SCHEMA or type(doc.get("protocol_config")) is not dict:
        raise ValueError(f"{index_path}: not a corpus index of schema {INDEX_SCHEMA} with its protocol_config")
    mode = doc.get("plan_mode")
    if mode not in MODES:
        raise ValueError(f"{index_path}: plan mode {mode!r}: the qualification reads the index of a plan of protocol "
                         f"schema 3, of mode {' or '.join(MODES)} (features/dataset.py build)")
    if mode == "campaign" and stage != "final":
        raise ValueError(f"{index_path}: an index of plan mode campaign is read at stage final only, not at stage "
                         f"{stage}: its sessions are the dataset, and at stage final role test_controls stays sealed")
    if mode == "rehearsal" and stage == "final":
        raise ValueError(f"{index_path}: an index of plan mode rehearsal is never read at stage final: a rehearsal is "
                         "never in the dataset (proposal 10.4)")
    protocol, records = doc["protocol_config"], doc["sessions"]
    rows, sessions, load = {}, [], {}
    for r in records:
        if r["role"] not in ROLES:
            continue
        if "position" not in r:
            raise ValueError(f"index record {r['id']} has no position: an index built before package B6a "
                             "(features/dataset.py)")
        data = _archive(r)
        mask = measured(data)
        rows[r["id"]] = np.asarray(data["matica"], dtype=np.float64)[mask][:, :len(BEHAVIOR_NAMES)]
        sessions.append({"id": r["id"], "role": r["role"], "group": r["group"], "vm": r["vm"],
                         "scenario": r["scenario"], "profile": protocol["scenarios"][r["scenario"]]["profile"],
                         "position": r["position"], "start": r["start"]})
        load[r["id"]] = offered_load(Path(r["session"]).parent / "traffic_intervals.jsonl",
                                     np.asarray(data["casy"], dtype=np.float64)[mask], protocol["interval_s"])
    if not sessions:
        raise ValueError(f"{index_path}: no session of role train or dev")
    found = control_outcomes(records, protocol, stage)
    response, skipped = (found, []) if type(found) is str else found
    return rows, sessions, protocol, load, response, skipped


def record(index_path, stage, argv, *, acknowledge_incomplete=False):
    """The record of data/results: provenance (commit, date, host, guest, command, n), the plan mode of the index,
    whether the qualification is complete (and its untested kinds) and the qualification."""
    from scripts.audit_selftest import host  # This machine as the records of data/results name it.
    rows, sessions, protocol, load, response, skipped = from_index(index_path, stage)
    values = qualify(rows, sessions, protocol, load=load, response=response,
                     acknowledge_incomplete=acknowledge_incomplete)
    values["inputs"]["response"]["skipped"] = skipped
    index = Path(index_path)
    doc = json.loads(index.read_text())
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True)
    return {"schema": RECORD_SCHEMA, "stage": stage, "plan_mode": doc["plan_mode"], "complete": values["complete"],
            "untested": values["untested"], "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "commit": commit.stdout.strip(), "host": host(), "guest": GUEST,
            "command": " ".join(["python -m features.qualification", *map(str, argv)]), "n": len(sessions),
            "index": str(index.resolve()), "index_sha256": hashlib.sha256(index.read_bytes()).hexdigest(),
            "protocol_sha256": doc.get("protocol_sha256"), "values": values,
            "note": "Proposal 8.1 on the rows of train and dev; proposed_columns is a proposal, a human or a recorded "
                    "command writes analysis.columns in G3a (skeleton B6 section 3). When complete is false, some "
                    "stratum compares not every kind of proposal 8.1 (group, vm, order), untested names them, and the "
                    "record exists only because the command was given --acknowledge-incomplete."}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--index", type=Path, required=True, help="corpus index (features/dataset.py)")
    ap.add_argument("--stage", choices=STAGES, required=True, help="the stage of the record (proposal 11.1)")
    ap.add_argument("--out", type=Path, required=True, help="the record, never overwritten")
    ap.add_argument("--acknowledge-incomplete", action="store_true",
                    help="write the record of a qualification in which some stratum compares not every kind of "
                         "proposal 8.1 (the record says complete false and names them); refused without it")
    a = ap.parse_args(argv)
    try:
        doc = record(a.index, a.stage, argv, acknowledge_incomplete=a.acknowledge_incomplete)
        with a.out.open("x") as stream:
            json.dump(doc, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    except (ValueError, OSError, KeyError) as error:
        print(f"qualification: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"record": str(a.out), "sessions": doc["n"], "complete": doc["complete"],
                      "untested": doc["untested"], "proposed_columns": doc["values"]["proposed_columns"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
