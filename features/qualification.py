"""Qualification of the feature columns before training (protocol v5, packages B6a and B11).

Proposal 8.1 (docs/NAVRH_PROTOKOL_V5.sk.md), the lead's skeleton dokazy/B6/kostra/KOSTRA.md sections 2 and 3, design
B6a sections 1.4 and 1.5, and the lead's answers of 2026-11-24 to question Q7 (the identity rule and the data), Q8 (the
class rule_differenced) and Q25 (the rows of the controls), which package B11 puts into this module. On the measured
rows of the roles of the plan mode, from the features alone and never from a score, every column of
features.archive.BEHAVIOR_NAMES gets one class; the classes are the proposed value of the protocol key analysis.columns.
The bounds are analysis.qualification of the protocol (G0).

    qualify(rows, sessions, protocol, *, mode, load=None, response=None, acknowledge_incomplete=False)
                                    -> {schema, complete, untested, acknowledge_incomplete, table, proposed_columns,
                                        inputs}
    column_summary(result)          values.columns of the audit of one session (scripts/collection.py audit_session)
    python -m features.qualification --index I --stage S --out O [--acknowledge-incomplete]
                                    one record of data/results from a corpus index (features/dataset.py)

Data (question Q7): the rows of the roles of the plan mode (ROLES_BY_MODE), in G3a every role of the rehearsal (30
sessions; in a rehearsal nothing is sealed), on the repetition on the campaign train and dev. The same rows serve every
check, the variance, the identity, the duplicates, the load and the response (the executor's reading of the answer,
which names the data under the identity rule).

Measured rows: valid under the protocol's quality policy, no full snapshot and with a predecessor (the columns
je_plna and ma_predchodcu), in the order of seq; in a full snapshot the memory part describes the whole memory and
without a predecessor proc_new, proc_gone and mod_delta are not measured (as scripts/controls.py). In a session of role
test_controls the rows of every control and of its paired negative are left out (question Q25, RULES
controls_left_out); the rows of the events stay, they are ordinary operation. The first difference of a column is
taken between consecutive measured rows of one session; where an excluded row lies between them (the full snapshot, an
invalid row, a row left out) it spans that row's interval too. Every session needs two measured rows at least, so that
it holds a first difference and every comparison of a first difference holds the sessions of the comparison of the
value.

The classes are decided in this order (skeleton section 3, design B6a 1.4):
  1. rule         constant (zero variance) or near-constant (fewer than near_constant_share of the rows off the mode,
                  the smallest of the most frequent values): the rule channel, never an input of the TCN (proposal
                  8.2, D3).
  2. identity     no strata (question Q7; finding F2 of the verification of B6a): from every row of the column the
                  additive effect of the scenario and the position is subtracted, fitted by least squares on the
                  session means, and the result is rounded to a quantum (RULES adjustment and rounding). On these rows
                  three kinds of comparison run over all sessions: VM a against VM b (vm), the first against the last
                  floor(n/2) of the n sessions by start (order; the middle one of an odd count in neither half) and
                  each group with all its sessions against the other groups (group). AUC = P(a > b) + P(a = b) / 2
                  over the rows of the two sides; of two levels only the first is compared (the second gives 1 - AUC).
                  The column fails when max(AUC, 1 - AUC) of some comparison exceeds identity_auc; the table names the
                  worst comparison, of equal scores the first in the order vm, order, then the groups by name. A
                  failing column of level_columns is judged again by its first difference, by the whole qualification
                  (question Q8, accepted by the lead 2026-11-24): rule_differenced when the first difference is
                  constant or near-constant (the rule channel, which judges the column's change since the session's
                  first measured row; never an input of the TCN and never a duplicate), else differenced when the
                  first difference passes the identity test, with the same adjustment and comparisons, and dropped
                  when it fails; any other failing column is dropped.
  3. duplicate    greedy in the order of BEHAVIOR_NAMES over the columns that passed (a differenced one by its first
                  difference): standardized over every measured row but the first of each session (where a first
                  difference exists), a column whose smallest singular value beside the columns kept before it is at
                  most duplicate_tolerance times the largest is an exact linear combination of them and is dropped.
  4. neural       every other column.
Load and response are reported only and never change a class: the Spearman correlation and the R² of the linear
regression (proposal 8.1) of the column on the offered load of the row's interval, and for every control kind that
names the column the B8 outcomes (scripts/controls.py outcomes, column_moved). Where one is missing the table says
"not available" and why.

Completeness (verification of B6a, finding F1, under the rule of Q7). Proposal 8.1 names three kinds of comparison:
the VM, the session order and the group. The sessions compare a kind when they hold two of its levels (two VMs, two
sessions, two groups). The qualification is complete when it compares every kind. inputs.compared counts the
comparisons of each kind, and every row that the identity test judged carries the same counts (compared; null for a
column of the rule class, which the identity test does not judge). When a kind is not compared, which only a
degenerate input gives (the sessions of one VM), the result says complete false, untested names the kind and why, and
the reason of every row that the identity test judged ends with that; no row then says "passed every check".
qualify() refuses an incomplete qualification unless the caller acknowledges it (acknowledge_incomplete=True, the
command's --acknowledge-incomplete), and the result records the acknowledgment. Refusal is chosen because the proposed
columns become analysis.columns, the mask of the frozen training, and a mask that rests on fewer comparisons than
proposal 8.1 names must never be written without someone deciding so; the acknowledgment and the untested kinds are
in the record.

The command and the stage (verification of B6a, finding F4). The index states its plan mode (features/dataset.py
build); an index without a plan mode of protocol schema 3 is refused. The sessions of a campaign are the dataset: its
index is read at stage final only, where role test_controls stays sealed and no control outcome is read, and only its
roles train and dev are read. A rehearsal is never in the dataset (proposal 10.4): its index is never read at stage
final, and every role of it is read. Both refusals come before any feature archive is opened. Before the command opens
the archive of a session of a sealed role (tcn/pecat.py SEALED_ROLES, which only a rehearsal's rows hold), the seal
decides, as for scripts/controls.py (RULES seal): an archive of a rehearsal passes with its mark, a sealed archive of
a campaign is refused by name; the record keeps every decision.

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
from .dataset import CONTROL_ROLE, ROLES as PLAN_ROLES
from .snapshot import MENA
from .windows import BIN_PRIZNAKY

ROOT = Path(__file__).resolve().parents[1]
# Package B11 (question Q7): no strata, the comparisons over all sessions, the data of the plan mode.
SCHEMA = "hyptcn3/feature-qualification/2"
RECORD_SCHEMA = "hyptcn3/feature-qualification-record/2"
# The values of analysis.columns: the four of skeleton section 2 and rule_differenced, a level column whose first
# difference is constant or near-constant, which the rule channel judges by its change since the session's first
# measured row (question Q8 to the lead, his revised proposal, accepted by the lead 2026-11-24; package B6b).
CLASSES = ("neural", "rule", "differenced", "dropped", "rule_differenced")
# The data of the qualification (question Q7, the lead's answer of 2026-11-24): the roles of the plan mode, every role
# of a rehearsal (features/dataset.py ROLES) and train and dev of a campaign.
ROLES_BY_MODE = {"rehearsal": PLAN_ROLES, "campaign": ("train", "dev")}
# Proposal 8.1: one row must not tell the VM, the session order (the first against the second half) or the group. The
# order of the kinds names the worst of equal scores: vm, order, then the groups by name (judgment, package B11).
KINDS = ("vm", "order", "group")
# What the sessions hold when they give no comparison of a kind.
NOT_COMPARED_WITH = {"vm": "one VM", "order": "one session", "group": "one group"}
# The adjusted values and their first differences are rounded to QUANTUM x analysis.scale.floor of the column
# (judgment, package B11; RULES rounding): far below the smallest change of the quantity (its floor) and far above the
# float residue of the least-squares fit (of order 1e-15 of the values), which would break exact ties.
QUANTUM = 1e-6
NEURAL = "neural: passed every check"  # The reason of a neural column of a complete qualification only.
# The entry point in a decision or a refusal of the seal (tcn/pecat.py kontrola; RULES seal).
PURPOSE = "features/qualification.py"
SESSION_KEYS = ("id", "role", "group", "vm", "scenario", "profile", "position", "start")
SUMMARY_KEYS = ("rows", "min", "max", "mean", "std", "mode", "off_mode_share", "diff_std")
# The per-bin values the normalizer scales (analysis.scale.local_floor): has_changed is a mask, never normalized
# (safeguard/features.py).
LOCAL_SCALED = tuple(name for name in BIN_PRIZNAKY if name != "has_changed")
STAGES = ("suchy", "skuska", "generalka", "final")  # Proposal 11.1, as scripts/controls.py STAGES.
INDEX_SCHEMA = "hyptcn3/corpus-index/1"
GUEST = "none: computed from the feature archives and session logs the corpus index names; no VM is contacted"
RULES = {
    "data": "the rows of the roles of the plan mode (ROLES_BY_MODE; question Q7, the lead's answer of 2026-11-24): every "
            "role of a rehearsal (G3a, 30 sessions; in a rehearsal nothing is sealed), train and dev of a campaign; "
            "the same rows serve every check, the variance, the identity, the duplicates, the load and the response "
            "(the executor's reading of the answer)",
    "measured_rows": "valid under the protocol's quality policy, no full snapshot (je_plna 0) and with a predecessor "
                     "(ma_predchodcu 1), in the order of seq",
    "controls_left_out": "in a session of role test_controls a measured row taken at time t is left out when "
                         "host_start_unix < t <= max(host_stop_unix, host_start_unix + controls.horizon_s) of a "
                         "control or a paired negative of its controls.json (features/dataset.py controls_of, "
                         "scripts/controls.py _occurrence; question Q25, the lead's answer of 2026-11-24); a row at t "
                         "covers (t - interval_s, t], so the start is bounded as the horizon of scripts/controls.py; "
                         "a slot of the plan without a control leaves nothing out, and an occurrence that _occurrence "
                         "refuses stops the qualification by name, since its rows are never guessed; the rows of the "
                         "events stay; the record states the rows left out per session (inputs.controls_left_out)",
    "mode": "the smallest of the most frequent values; off_mode_share is the share of the rows with another value",
    "first_difference": "between consecutive measured rows of one session; across an excluded row (a full "
                        "snapshot, an invalid row, a row left out) it spans that row's interval too; every session has "
                        "two measured rows at least",
    "judged_again": "a level column that fails the identity test is qualified again by its first difference (question "
                    "Q8, accepted by the lead 2026-11-24): constant or near-constant by the same near_constant_share "
                    "over the pooled first differences gives rule_differenced (the rule channel, by the column's "
                    "change since the session's first measured row); otherwise the identity test of the first "
                    "difference, with the same adjustment and comparisons, gives differenced or dropped",
    "adjustment": "no strata (question Q7, the lead's answer of 2026-11-24): for each column, and for its first "
                  "difference, one unweighted mean per session; X holds a one and the dummies of the scenarios and of "
                  "the positions the sessions hold, but the first of each (sorted); beta is np.linalg.lstsq(X, "
                  "means); every row less the fitted value X beta of its session (unique also when X is rank "
                  "deficient; the intercept is a common shift that no AUC sees)",
    "rounding": "the adjusted values and the adjusted first differences are rounded to the nearest multiple of "
                "QUANTUM x analysis.scale.floor of the column (judgment, package B11): the least-squares fit leaves "
                "float residues of order 1e-15 of the values, which break the exact ties of a column that is constant "
                "within sessions and depends only on scenario and position, so that on the real plans it would fail "
                "a comparison it passes at exactly 0.5; the quantum lies six orders of magnitude below the column's "
                "floor, the smallest change the quantity can show",
    "comparisons": "over all sessions sorted by (start, id), on the adjusted rows: VM a against VM b (kind vm; of two "
                   "levels only the first, the second gives 1 - AUC; of more each against the others), the first "
                   "against the last floor(n/2) of the n sessions (kind order) and each group with all its sessions "
                   "against the other groups (kind group; of two groups only the first); of equal scores the worst "
                   "is the first in the order vm, order, then the groups by name (judgment, package B11)",
    "coverage": "the sessions compare a kind when they hold two of its levels (two VMs, two sessions, two groups); "
                "the qualification is complete when it compares every kind of proposal 8.1 (vm, order, group); "
                "otherwise, which only a degenerate input gives (the sessions of one VM), untested names each kind "
                "and why, the reason of every row that the identity test judged ends with it, and qualify() refuses "
                "unless the caller acknowledges it (acknowledge_incomplete, the command's --acknowledge-incomplete)",
    "compared": "per kind the number of its comparisons, in inputs and in every row that the identity test judged "
                "(the same for the value and the first difference of a column); null in a row of the rule class, "
                "which the identity test does not judge",
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
    "seal": "before the command opens the feature archive of a session of a sealed role (tcn/pecat.py SEALED_ROLES; "
            "only the rows of a rehearsal hold them) it asks tcn/pecat.py kontrola with purpose "
            "features/qualification.py, as scripts/controls.py does (package B11): the ledger lets an archive of a "
            "rehearsal through with its mark, an archive it does not hold is not sealed, and a sealed archive of a "
            "campaign is refused by name before it is opened; the record keeps every decision (inputs.seal)",
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


def _sessions(rows, sessions, protocol, mode):
    """The checked sessions sorted by (start, id) and {id: rows}; ValueError names what is wrong."""
    if mode not in ROLES_BY_MODE:
        raise ValueError(f"qualification: plan mode {mode!r}: the qualification reads the roles of plan mode "
                         f"{' or '.join(ROLES_BY_MODE)} (question Q7)")
    roles = ROLES_BY_MODE[mode]
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
        if s["role"] not in roles:
            raise ValueError(f"qualification: session {name} of role {s['role']}: plan mode {mode} reads the roles "
                             f"{', '.join(roles)} only (question Q7)")
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


def _comparisons(sessions):
    """[(kind, label, side a ids, side b ids)] over all sessions, which come sorted by (start, id) (RULES
    comparisons), in the order that names the worst of equal scores: vm, order, then the groups by name."""
    out = []
    for kind in KINDS:
        if kind == "order":
            half = len(sessions) // 2
            if half:
                out.append((kind, f"first {half} against last {half} of {len(sessions)} sessions by start",
                            [s["id"] for s in sessions[:half]], [s["id"] for s in sessions[-half:]]))
            continue
        levels = sorted({s[kind] for s in sessions})
        for level in (levels[:1] if len(levels) == 2 else levels if len(levels) > 2 else []):
            label = (f"{kind} {level} against {kind} {levels[1]}" if len(levels) == 2
                     else f"{kind} {level} against the other {kind}s")
            out.append((kind, label, [s["id"] for s in sessions if s[kind] == level],
                        [s["id"] for s in sessions if s[kind] != level]))
    return out


def _coverage(comparisons):
    """({kind: the number of its comparisons}, {kind: why it is not tested}) (RULES coverage, compared); a kind that
    has a comparison is not in the second."""
    compared = {kind: sum(c[0] == kind for c in comparisons) for kind in KINDS}
    untested = {kind: f"not tested, the sessions hold {NOT_COMPARED_WITH[kind]}" for kind in KINDS
                if not compared[kind]}
    return compared, untested


def _design(sessions):
    """X of the adjustment (RULES adjustment), one row per session in the order of `sessions`: a one, then the dummies
    of the scenarios and of the positions the sessions hold, but the first of each in sorted order."""
    scenarios = sorted({s["scenario"] for s in sessions})
    positions = sorted({s["position"] for s in sessions})
    return np.array([[1.0, *(float(s["scenario"] == c) for c in scenarios[1:]),
                      *(float(s["position"] == q) for q in positions[1:])] for s in sessions])


def _adjusted(columns, sessions, design, quantum):
    """{id: the values of one column less the fitted value of the session's cell, rounded to the nearest multiple of
    `quantum`} (RULES adjustment and rounding; `columns`: {id: values}): the least-squares fit of the unweighted session
    means on `design`. Equal multiples of the quantum are equal floats, so the ties of the column survive the fit."""
    means = np.array([columns[s["id"]].mean() for s in sessions])
    fitted = design @ np.linalg.lstsq(design, means, rcond=None)[0]
    return {s["id"]: quantum * np.round((columns[s["id"]] - f) / quantum) for s, f in zip(sessions, fitted)}


def _identity(columns, sessions, design, comparisons, quantum):
    """The worst comparison of one column on its adjusted values, {score, auc, kind, comparison, sessions, rows}
    (`columns`: {id: values}); of equal scores the first in the order of `comparisons`. Every side of a comparison holds
    a session, and every session two rows at least (_sessions), so every side holds a value and a first difference."""
    adjusted = _adjusted(columns, sessions, design, quantum)
    worst = None
    for kind, label, a, b in comparisons:
        xa = np.concatenate([adjusted[name] for name in a])
        xb = np.concatenate([adjusted[name] for name in b])
        value = auc(xa, xb)
        score = max(value, 1 - value)
        if worst is None or score > worst["score"]:
            worst = {"score": score, "auc": value, "kind": kind, "comparison": label, "sessions": [a, b],
                     "rows": [len(xa), len(xb)]}
    return worst


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

def qualify(rows, sessions, protocol, *, mode, load=None, response=None, acknowledge_incomplete=False):
    """The classes of the 20 columns (module docstring) as {schema, complete, untested, acknowledge_incomplete, table,
    proposed_columns, inputs}.

    rows: {session id: the session's measured rows as a matrix of the columns of BEHAVIOR_NAMES, in seq order, two
    rows at least}; sessions: [{id, role, group, vm, scenario, profile, position, start}] of the roles of the plan mode,
    position from the plan row of the session (scripts/protocol_v5.py planned_rows); protocol: a protocol of schema 3,
    whose analysis.qualification gives the bounds and analysis.scale.floor the quantum of each column; mode: the plan
    mode, campaign or rehearsal, no default (RULES data: it names the roles a session may have); load: {session id: the
    offered load of each measured row, or why the session has none}, or why no session has one, or None (not supplied,
    recorded); response: the outcomes of scripts/controls.py of the control occurrences, or why there are none, or None
    (not supplied, recorded); acknowledge_incomplete: True records a qualification whose sessions compare not every
    kind of proposal 8.1 (module docstring, Completeness), which is refused otherwise. ValueError names a malformed
    input or the refusal; the protocol is never written.
    """
    from scripts.protocol_v5 import analysis_plan  # Inside, as features/dataset.py imports scripts/ (no cycle).
    plan = analysis_plan(protocol)
    q, floor = plan["qualification"], plan["scale"]["floor"]
    sessions, values = _sessions(rows, sessions, protocol, mode)
    comparisons = _comparisons(sessions)
    if not comparisons:
        raise ValueError("qualification: the sessions hold neither two VMs, nor two sessions, nor two groups: no "
                         "comparison of proposal 8.1")
    compared, untested = _coverage(comparisons)
    gap = "; ".join(f"{kind}: {why}" for kind, why in untested.items())
    if untested and acknowledge_incomplete is not True:
        raise ValueError(f"qualification: incomplete ({gap}): proposal 8.1 compares the VM, the session order and the "
                         "group; acknowledge_incomplete=True (the command's --acknowledge-incomplete) records an "
                         "incomplete qualification")
    order = [s["id"] for s in sessions]
    design = _design(sessions)
    pooled = np.concatenate([values[name] for name in order])
    differences = {name: np.diff(values[name], axis=0) for name in order}
    bound = q["identity_auc"]
    table, classes = {}, {}
    for j, name in enumerate(BEHAVIOR_NAMES):
        x = pooled[:, j]
        modal, off = _mode(x)
        row = {"column": name, "class": None, "reason": None, "rows": len(x),
               "variance": 0.0 if _constant(x) else float(x.var()), "mode": modal, "off_mode_share": off / len(x),
               "identity": None, "difference": None, "identity_of_difference": None, "compared": None,
               "rank_test": None}
        if _constant(x):
            cls, reason = "rule", "constant: zero variance"
        elif off / len(x) < q["near_constant_share"]:
            cls, reason = "rule", (f"near-constant: {off} of {len(x)} rows off the mode {modal:g}, fewer than "
                                   f"near_constant_share {q['near_constant_share']:g}")
        else:
            row["compared"] = dict(compared)
            quantum = QUANTUM * floor[name]
            worst = row["identity"] = _identity({k: values[k][:, j] for k in order}, sessions, design, comparisons,
                                                quantum)
            failed = (f"identity: max(AUC, 1 - AUC) {worst['score']:.4f} above identity_auc {bound:g} "
                      f"({worst['comparison']})")
            if worst["score"] <= bound:
                cls, reason = "neural", None  # The rank test below decides.
            elif name not in q["level_columns"]:
                cls, reason = "dropped", failed
            else:
                cls, reason = _judged_again(row, j, differences, sessions, design, comparisons, quantum, q, failed)
        classes[name] = cls
        table[name] = dict(row, **{"class": cls, "reason": reason})
    rank_rows = _rank_test(table, classes, values, differences, order, q["duplicate_tolerance"])
    for name in BEHAVIOR_NAMES:  # A kind that no comparison holds never reads as passed (module docstring).
        row = table[name]
        if row["class"] == "neural":
            row["reason"] = NEURAL if not untested else "neural: passed the checks that ran; " + gap
        elif untested and row["compared"] is not None:
            row["reason"] += "; " + gap
    load_cell, load_record = _load(load, sessions, values)
    response_cell, response_record = _response(response, protocol)
    for j, name in enumerate(BEHAVIOR_NAMES):
        table[name].update(load=load_cell(j), response=response_cell(name))
    return {"schema": SCHEMA, "complete": not untested, "untested": untested,
            "acknowledge_incomplete": acknowledge_incomplete is True,
            "table": [table[name] for name in BEHAVIOR_NAMES],
            "proposed_columns": {name: classes[name] for name in BEHAVIOR_NAMES},
            "inputs": {"mode": mode, "sessions": [dict(s, rows=len(values[s["id"]])) for s in sessions],
                       "rows": len(pooled),
                       "roles": {role: sum(s["role"] == role for s in sessions) for role in ROLES_BY_MODE[mode]},
                       "adjustment": {"scenarios": sorted({s["scenario"] for s in sessions}),
                                      "positions": sorted({s["position"] for s in sessions}), "quantum": QUANTUM},
                       "compared": compared, "comparisons": len(comparisons),
                       "rank_test_rows": rank_rows, "parameters": dict(q), "load": load_record,
                       "response": response_record, "rules": RULES}}


def _judged_again(row, j, differences, sessions, design, comparisons, quantum, q, failed):
    """(class, reason) of the level column `j` that failed the identity test (`failed`), qualified again by its first
    difference in the order of the classes (module docstring; question Q8, accepted by the lead 2026-11-24): the
    variance rule over the pooled first differences of every session first (rule_differenced, the rule channel by the
    change since the session's first measured row, which never reaches the rank test and so is never a duplicate), then
    the identity test with the same adjustment, quantum and comparisons (differenced, which the rank test still judges,
    or dropped). The table row gets the difference's numbers."""
    d = np.concatenate([differences[s["id"]][:, j] for s in sessions])
    modal, off = _mode(d)
    row["difference"] = {"rows": len(d), "variance": 0.0 if _constant(d) else float(d.var()), "mode": modal,
                         "off_mode_share": off / len(d)}
    if _constant(d):
        return "rule_differenced", failed + "; its first difference is constant: zero variance"
    if off / len(d) < q["near_constant_share"]:
        return "rule_differenced", (failed + f"; its first difference is near-constant: {off} of {len(d)} differences "
                                    f"off the mode {modal:g}, fewer than near_constant_share "
                                    f"{q['near_constant_share']:g}")
    again = row["identity_of_difference"] = _identity({s["id"]: differences[s["id"]][:, j] for s in sessions},
                                                      sessions, design, comparisons, quantum)
    bound = q["identity_auc"]
    if again["score"] <= bound:
        return "differenced", failed + f"; its first difference scores {again['score']:.4f}, at most {bound:g}"
    return "dropped", (failed + f"; its first difference scores {again['score']:.4f} above {bound:g} "
                       f"({again['comparison']})")


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
    inside the row's interval, and the intervals must cover the row's interval. The log audit binds that start_unix:
    it equals the request log's (scripts/collection_logs.py traffic_headers_disagree), to which since package B16
    scripts/traffic_log.py summarize binds the wall time of every record (WALL_CLOCK_TOLERANCE_S)."""
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


def controls_left_out(record, protocol, times, rows):
    """(mask, record) of the rows of a session of role test_controls left out of the qualification (RULES
    controls_left_out, question Q25): the mask over the session's rows at `times`, and {rows, occurrences} with the
    number of measured rows (`rows`: their mask) left out, in all and by occurrence. ValueError by name for an
    occurrence that scripts/controls.py _occurrence refuses: its rows cannot be placed."""
    from features.dataset import controls_of
    from scripts.controls import _occurrence
    horizon = protocol["controls"]["horizon_s"]
    out, occurrences = np.zeros(len(times), dtype=bool), []
    for item in controls_of(record)["controls"]:  # Its sha256 checked against the index (package B7c).
        if item.get("kind") is None:
            continue  # A slot of the plan without a control.
        try:
            kind, polarity, *_, (start, _, stop) = _occurrence(item, protocol)
        except ValueError as error:
            raise ValueError(f"session {record['id']}: {error}: the rows of a control that cannot be placed are never "
                             "guessed (question Q25)") from None
        end = max(stop, start + horizon)
        inside = (times > start) & (times <= end)
        out |= inside
        occurrences.append({"kind": kind, "polarity": polarity, "after_unix": start, "until_unix": end,
                            "rows": int(np.count_nonzero(inside & rows))})
    return out, {"rows": int(np.count_nonzero(out & rows)), "occurrences": occurrences}


def from_index(index_path, stage):
    """{rows, sessions, protocol, mode, load, response, skipped, left_out, seal} of the corpus index at `index_path`,
    read at `stage`: the rows of the roles of its plan mode (RULES data) without the rows of the controls (RULES
    controls_left_out, left_out by session), the skipped controls of the response and the decision of the seal of every
    archive of a sealed role (RULES seal, by session). The plan mode of the index decides the stages (module docstring):
    a refusal comes before any archive is opened, and so does the seal's."""
    from scripts.protocol_v5 import MODES
    from tcn import pecat  # Here, as scripts/controls.py: the seal of the test roles (package B7c).
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
    protocol, records, roles = doc["protocol_config"], doc["sessions"], ROLES_BY_MODE[mode]
    rows, sessions, load, left_out, seal = {}, [], {}, {}, {}
    for r in records:
        if r["role"] not in roles:
            continue
        if "position" not in r:
            raise ValueError(f"index record {r['id']} has no position: an index built before package B6a "
                             "(features/dataset.py)")
        if r["role"] in pecat.SEALED_ROLES:  # Before the archive is opened (RULES seal).
            seal[r["id"]] = pecat.kontrola(r["features"], purpose=PURPOSE)
        data = _archive(r)
        times = np.asarray(data["casy"], dtype=np.float64)
        mask = measured(data)
        if r["role"] == CONTROL_ROLE:
            out, left_out[r["id"]] = controls_left_out(r, protocol, times, mask)
            mask = mask & ~out
        rows[r["id"]] = np.asarray(data["matica"], dtype=np.float64)[mask][:, :len(BEHAVIOR_NAMES)]
        sessions.append({"id": r["id"], "role": r["role"], "group": r["group"], "vm": r["vm"],
                         "scenario": r["scenario"], "profile": protocol["scenarios"][r["scenario"]]["profile"],
                         "position": r["position"], "start": r["start"]})
        load[r["id"]] = offered_load(Path(r["session"]).parent / "traffic_intervals.jsonl", times[mask],
                                     protocol["interval_s"])
    if not sessions:
        raise ValueError(f"{index_path}: no session of the roles {', '.join(roles)} of plan mode {mode}")
    found = control_outcomes(records, protocol, stage)
    response, skipped = (found, []) if type(found) is str else found
    return {"rows": rows, "sessions": sessions, "protocol": protocol, "mode": mode, "load": load, "response": response,
            "skipped": skipped, "left_out": left_out, "seal": seal}


def record(index_path, stage, argv, *, acknowledge_incomplete=False):
    """The record of data/results: provenance (commit, date, host, guest, command, n), the plan mode of the index,
    whether the qualification is complete (and its untested kinds) and the qualification, whose inputs also hold the
    rows left out of every session of role test_controls (controls_left_out) and the decisions of the seal (seal)."""
    from scripts.audit_selftest import host  # This machine as the records of data/results name it.
    found = from_index(index_path, stage)
    values = qualify(found["rows"], found["sessions"], found["protocol"], mode=found["mode"], load=found["load"],
                     response=found["response"], acknowledge_incomplete=acknowledge_incomplete)
    values["inputs"]["response"]["skipped"] = found["skipped"]
    values["inputs"].update(controls_left_out=found["left_out"], seal=found["seal"])
    sessions = found["sessions"]
    index = Path(index_path)
    doc = json.loads(index.read_text())
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True)
    return {"schema": RECORD_SCHEMA, "stage": stage, "plan_mode": doc["plan_mode"], "complete": values["complete"],
            "untested": values["untested"], "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "commit": commit.stdout.strip(), "host": host(), "guest": GUEST,
            "command": " ".join(["python -m features.qualification", *map(str, argv)]), "n": len(sessions),
            "index": str(index.resolve()), "index_sha256": hashlib.sha256(index.read_bytes()).hexdigest(),
            "protocol_sha256": doc.get("protocol_sha256"), "values": values,
            "note": "Proposal 8.1 on the rows of the roles of the plan mode (question Q7: every role of a rehearsal, "
                    "train and dev of a campaign), without the rows of the controls and their paired negatives "
                    "(question Q25: values.inputs.controls_left_out); proposed_columns is a proposal, a human or a "
                    "recorded command writes analysis.columns in G3a (skeleton B6 section 3). When complete is false, "
                    "the sessions compare not every kind of proposal 8.1 (vm, order, group), untested names them, and "
                    "the record exists only because the command was given --acknowledge-incomplete."}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--index", type=Path, required=True, help="corpus index (features/dataset.py)")
    ap.add_argument("--stage", choices=STAGES, required=True, help="the stage of the record (proposal 11.1)")
    ap.add_argument("--out", type=Path, required=True, help="the record, never overwritten")
    ap.add_argument("--acknowledge-incomplete", action="store_true",
                    help="write the record of a qualification whose sessions compare not every kind of proposal 8.1 "
                         "(the record says complete false and names them); refused without it")
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
