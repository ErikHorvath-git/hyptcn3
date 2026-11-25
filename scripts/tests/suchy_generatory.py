"""The generators of synthetic sessions of the dry run of stage G1 (protocol v5, G1 preparation, package C1).

Binding texts: the skeleton dokazy/G1/kostra/KOSTRA.md (row C1 of section 1, section 2, section 6 points 4, 5 and 7)
with the lead's answers to Q32 to Q41 (2026-11-24T21:25Z): Q36, the marginal change goes into the three structured
runs only, never into a null run, and nothing goes into test_benign of a null run that the real test_benign will not
have; Q35, GENERATOR_RULE is the rule of the structured generator, written before the runs; Q38, every column states
its class by construction (TRIEDY) beside the mask of the qualification pass. Every number of the generator is the
executor's judgment, G1 preparation, unless its comment names another origin.

    riadky(riadok_planu, rezim, seed, protokol)
                                the extraction result of one row of a plan, as features/snapshot.py retazec gives it
                                (all columns of features.archive.BEHAVIOR_NAMES and the bins on the protocol's grid)
    zaznam(riadok_planu, rezim, seed, protokol)
                                the record of that session in generator.json: its seed, its inserted changes, its
                                invalid rows and the effects of its controls row by row
    generator_json(riadky_planu, rezim, seed, protokol)
                                generator.json of a run: the rule, the parameters, the classes and every session's
                                record
    controls_json(riadok_planu, measure_start_unix)
                                controls.json of a session of test_controls after a faultless run of its controls, as
                                scripts/tests/audit_cases_logs.py controls_session writes it (CONTROLS_JSON_RULE)
    ponukana_zataz(riadok_planu, protokol)
                                the planned offered load of every row (the user sessions the envelope plans in the
                                row's interval), which the counts depend on
    seed_session(meno, skupina, pozicia, pokus, seed), seed_role(meno, rola, seed)
                                the seeds of a session and of the choices of a role (the tool's own rule)

riadok_planu is a row of scripts/protocol_v5.py plan(protokol, mode) or its replacement() of an attempt; its group
prefix names the plan mode (campaign or rehearsal). rezim is "nulovy" or "strukturovany", seed the run's seed (an
integer of at least 0), protokol the loaded protocol: the working copy of the run (C3), whose scenarios have a rate.
The times of the result are seconds since the measurement start, the frame of the plan's start_s (FIRST_ROW_S): the
fake capture adds its measure_start_unix to result["casy"]. Nothing here changes the protocol, the plan or a file.

What the fake capture of the run (package C3) takes from here besides the rows: controls.json of every session of
test_controls (controls_json, with the session.json of audit_cases_logs.controls_session: its controls the plan's items
with a kind and source_sha256 lab/udalosti.py test_collection_logs.SCRIPT_SHA256), the planned offered load of every row
(ponukana_zataz, LOAD_RULE: the counts follow it, so the offered sessions of the session's traffic_intervals.jsonl that
features/qualification.py offered_load reads for Z4 should be the same numbers in the same frame), and generator.json
(generator_json). The class of every column by construction is TRIEDY (the lead's answer to Q38: written beside the
mask of the qualification pass, a difference is a finding).
"""
from collections import Counter
import copy
import hashlib
import json
import math
import random

import numpy as np

from features import quality as fq
from features.archive import BEHAVIOR_NAMES
from features.contract import validate_sidecar
from features.snapshot import MENA, SCHEMA as SNAPSHOT_SCHEMA
from scripts import protocol_v5
from scripts.protocol_v5 import CONTROL_ROLE, CONTROLS_SCHEMA
from scripts.tests import audit_cases_logs
from scripts.tests import boundary_sessions as bs

SCHEMA = "hyptcn3/suchy-generator/1"
MODES = ("nulovy", "strukturovany")
PURPOSE = "suchy_beh"  # The word of the seed rule (skeleton row C1); no purpose of streams.purposes, which is G0.
PAGES = bs.BIN_BYTES // bs.PAGE  # 4096 pages of 4 KiB in a bin of 16 MiB, the protocol's bin_bytes.
# boundary_sessions.build_session takes snapshot 0 at its base + FIRST_SNAPSHOT_S (1.5 s) and
# test_collection_logs.build starts the measurement at base + 1 s, so the first row lies 0.5 s after the measurement.
FIRST_ROW_S = bs.FIRST_SNAPSHOT_S - 1
BINS = 4  # Judgment: the bin branch of the TCN costs per bin (the executor's measurement of the G1 preparation, one
# epoch of the protocol's TCN over the 23600 windows of train, 2 threads: 14 s at 4 bins, 244 s at the guest's 128).
# The parameters of both modes (judgment, G1 preparation, unless named): LAG rows between a driver and the columns it
# drives (2, not 1: the model with shuffled context keeps the last row of its context, tcn/diagnostiky.py
# SHUFFLE_RULE); the period of the periodic component in rows (12 rows, a minute at interval_s 5); the AR(1)
# coefficient; the AR share of the drivers, the periodic share of the slow latents and of the bin latents; the noise
# shares (of the variance) of the coupled, the slow and the bin values. A slow column is half white noise: a smooth
# column makes the first difference at the edges of a block that an intervention of class C or D reorders or swaps
# fall outside the train range (tcn/zasahy.py VALIDITY_RULE), which sends it to the volume class (an earlier design
# check of this package: 16 of 27 first violations at noise 0.02, in mem_zero_ratio and mem_entropy_mean); the bins
# are not judged there.
GENERATOR = {"lag": 2, "period_rows": 12, "rho": 0.8, "w_u": 0.2, "w_p": 0.6, "w_pb": 0.9, "noise_coupled": 0.05,
             "noise_slow": 0.5, "noise_bin": 0.02, "bins": BINS}
# The columns (judgment: plausible levels, each scale above the column's analysis.scale.floor): kind, latent, mean,
# scale, physical range; a count also its load coefficient kappa (units of the count per user session the plan offers
# in the row's interval, LOAD_RULE). The scale is the standard deviation by construction of a column that is no count
# (mean + scale x a latent of variance 1).
COLUMNS = {
    "mem_changed_ratio": ("driver", ("a", 0), 0.05, 0.01, (0.0, 1.0)),
    "mem_bins_active": ("driver", ("a", 1), 0.6, 0.06, (0.0, 1.0)),
    "mem_changed_max": ("coupled", ("g", 0), 0.25, 0.04, (0.0, 1.0)),
    "mem_changed_p95": ("coupled", ("f", 1), 0.12, 0.02, (0.0, 1.0)),
    "mem_changed_spread": ("coupled", ("h",), 0.55, 0.03, (0.0, 1.0)),
    "mem_entropy_mean": ("slow", ("s", 1), 3.6, 0.25, (0.0, 8.0)),
    "mem_entropy_max": ("coupled", ("f", 0), 6.2, 0.15, (0.0, 8.0)),
    "mem_zero_ratio": ("slow", ("s", 0), 0.42, 0.02, (0.0, 1.0)),
    "proc_total": ("count", ("f", 0), 140.0, 6.0, (0.0, math.inf), 0.5),
    "proc_user": ("count", ("f", 1), 60.0, 5.0, (0.0, math.inf), 0.0),
    "proc_kernel": ("count", ("h",), 80.0, 3.0, (0.0, math.inf), 0.0),
    "proc_new": ("count", ("g", 1), 6.0, 2.5, (0.0, math.inf), 0.3),
    "proc_gone": ("count", ("g", 0), 6.0, 2.5, (0.0, math.inf), 0.3),
    "sock_total": ("count", ("f", 1), 40.0, 4.0, (0.0, math.inf), 1.0),
    "sock_estab": ("count", ("h",), 20.0, 4.0, (0.0, math.inf), 1.0),
}
# The rule channel (skeleton row C1): constant in both modes; the levels are judgment.
RULE_VALUES = {"mod_total": 48.0, "mod_delta": 0.0, "sock_listen": 8.0, "proc_wx": 0.0, "proc_memfd": 0.0}
# The difference columns: 0 in a row without a predecessor (features/snapshot.py, boundary_sessions).
DIFFERENCES = ("proc_new", "proc_gone", "mod_delta")
# Each bin channel: mean, scale, physical range and the sign of the bin's latent (judgment); changed_ratio is taken in
# whole pages of PAGES, at least 1 so that every bin changes in every row (has_changed 1, the entropy measured).
BIN_CHANNELS = {"changed_ratio": (0.12, 0.03, (1 / PAGES, 1.0), 1.0), "zero_ratio": (0.55, 0.04, (0.0, 1.0), -1.0),
                "entropy_mean": (3.5, 0.4, (0.0, 8.0), 1.0)}
# Q38: the class of every column of BEHAVIOR_NAMES by construction (features/qualification.py CLASSES): the five
# constants of the rule channel are rule, every other column is neural (no column depends on the VM, the group or the
# session order, which the identity test of the qualification reads).
TRIEDY = {name: "rule" if name in RULE_VALUES else "neural" for name in BEHAVIOR_NAMES}
# The marginal change (skeleton section 2 row marginal_change, the lead's answer to Q36): 8 standard deviations of the
# column, 12 rows of the band before a full snapshot. mem_changed_max is judgment: Z1 has a candidate of its own on it
# (tcn/metody.py Z1_RULE), so every candidate of Z1 but the difference reads the step.
OKRAJOVA_ZMENA = {"column": "mem_changed_max", "sd": 8.0}
# The process of kontrola_wx_memfd in the parser's view: the first member of the guest's effect evidence of a
# faultless control in scripts/tests/audit_cases_logs.py, which controls_json writes into every record.
WX_PID = audit_cases_logs.EFFECT["evidence"]["members"][0]
WX_KIND = "kontrola_wx_memfd"
WX_PATTERNS = ("wx", "memfd_fd")  # scripts/controls.py WX_MEMFD
# The polarity of a control; its paired negative has "negative" (scripts/protocol_v5.py CONTROL_RECORD_CLASS).
POSITIVE = "control"

GENERATOR_RULE = (
    "the sessions of the dry run of G1 (skeleton dokazy/G1/kostra/KOSTRA.md row C1 and section 2; the lead's answers "
    "to Q35, Q36 and Q38): riadky(row, mode, seed, protocol) gives the extraction result of one row of the plan of a "
    "mode of the protocol (scripts/protocol_v5.py plan, campaign or rehearsal by the row's group prefix, a "
    "replacement by its attempt) as features/snapshot.py retazec gives it (the shape of "
    "scripts/tests/boundary_sessions.extraction_result) on the protocol's grid: cycles rows of seq 0 to cycles - 1 at "
    "FIRST_ROW_S + seq x interval_s seconds after the measurement start (the frame of the plan's start_s; the capture "
    "adds its measure_start_unix), a full snapshot and a new chain at every seq divisible by full_every, BINS bins "
    "of bin_bytes of 4096 pages in one region from GPA 0 (the layout boundary_sessions writes), every bin changed in "
    "every row. SEEDS: the seed of a session is int(sha256(json.dumps([plan name, group, position, attempt, "
    "'suchy_beh', run seed])).hexdigest()[:16], 16) (the tool's own rule of the skeleton; no purpose of "
    "streams.purposes, which would reopen G0), and numpy.random.default_rng of it draws the session in the order "
    "below; the choices of a role come from numpy.random.default_rng of the same hash of [plan name, role, -1, 0, "
    "'suchy_beh', run seed], the roles in the protocol's order, every choice uniform (generator.integers): the session "
    "that carries the tolerated invalid rows (test_benign: one of its sessions with an event, then one of its events; "
    "test_controls: one of its sessions with a control of polarity control, then one of those controls, never a "
    "paired negative; another role: one of its sessions, the number of rows in 1 to invalid_rows.max, then the first "
    "row among those whose run lies inside the session and meets no full snapshot), then in test_benign of the "
    "campaign plan, group by group in the plan's order, the session that carries the marginal change (one of the "
    "positions of the group but the one with the invalid rows). MODE strukturovany draws over the rows -lag to "
    "cycles - 1: the phases phi_0 and phi_1 uniform on [0, 2 pi), the AR(1) states u_k (normal(0, 1) at row -lag, then "
    "u = rho u + sqrt(1 - rho^2) eta with eta normal(0, 1)), the innovations e_k normal(0, 1), then normal(0, 1) noise "
    "for every column of COLUMNS in the order of BEHAVIOR_NAMES and for every bin and channel. From them the drivers "
    "a_k = sqrt(w_u) u_k + sqrt(1 - w_u) e_k (normal(0, 1) at every row, a weak AR(1): w_u rho from one row to the "
    "next), the periodic components p_k = sqrt(2) sin(2 pi seq / period_rows + phi_k), the slow latents s_k = "
    "sqrt(w_p) p_k + sqrt(1 - w_p) u_k and the bin latents b_j = sqrt(w_pb) sqrt(2) sin(2 pi seq / period_rows + "
    "phi_k + pi (j // 2)) + sqrt(1 - w_pb) u_k, k = j mod 2 (the bins follow the periodic components and the AR(1) "
    "states of the drivers). The columns (COLUMNS): mem_changed_ratio and mem_bins_active are the drivers a_0 and "
    "a_1; mem_zero_ratio and mem_entropy_mean the slow latents s_0 and s_1, a periodic component and an AR(1); the "
    "eleven coupled columns (four of memory, five of processes, two of sockets) a function of the drivers lag rows "
    "before: f(a_k) with f(x) = (x^2 - 1) / sqrt(2) (tcn/k2.py GENERATOR_RULE at sigma 1 and gain 1), g(a_k) with "
    "g(x) = (|x| - sqrt(2 / pi)) / sqrt(1 - 2 / pi), or the product a_0 a_1; each has mean 0 and variance 1, is "
    "uncorrelated with every linear function of the drivers, of the slow and bin latents and of the load at any row, "
    "and correlates with the coupled values of earlier rows only through the AR(1) of the drivers, at most "
    "(w_u rho)^2 = 0.0256, so that a linear autoregression does not read the coupling and the function of the driver "
    "lag rows before does; lag is 2 and not the 1 of tcn/k2.py because the model with shuffled context "
    "(tcn/diagnostiky.py SHUFFLE_RULE) keeps the last row of the context in place and must not be better (skeleton "
    "section 2, structured_generator), and it would read a coupling to the row before. A value is mean + scale "
    "(sqrt(1 - share) latent + sqrt(share) its noise), the share noise_coupled for a coupled column or a count, "
    "noise_slow for a slow one and 0 for a driver; a count adds kappa x the planned offered load of its row "
    "(ponukana_zataz, LOAD_RULE) and is rounded to the nearest integer (numpy rint); every value is clipped to its "
    "physical range. A bin channel is mean + scale x sign x (sqrt(1 - noise_bin) b_j + sqrt(noise_bin) its noise), "
    "clipped, changed_ratio rounded to whole pages and at least one. MODE nulovy draws, for every column of COLUMNS "
    "in the order of BEHAVIOR_NAMES and then every bin and channel, the latent inputs of that column alone, for every "
    "row independently, from their law at one row of the structured mode: each driver it reads normal(0, 1), its "
    "slow or bin latent sqrt(w) sqrt(2) sin(theta) + sqrt(1 - w) u with theta uniform on [0, 2 pi) and u normal(0, 1) "
    "(w = w_p or w_pb), its noise normal(0, 1) and, for a count with kappa > 0, the offered load of a row drawn "
    "uniformly from the session's rows; the same functions give the values, so every column and every bin channel "
    "keeps the marginal of the structured mode and nothing depends on time or on another column (the negative case, "
    "which decides: skeleton section 2). BOTH MODES: proc_wx, proc_memfd, mod_total, mod_delta and sock_listen are "
    "constant (RULE_VALUES, the rule channel), chk_syscall_hooks and chk_crossview 0, ma_predchodcu 0 in row 0 and in "
    "a row after an invalid one, where proc_new, proc_gone and mod_delta are 0 (as "
    "boundary_sessions.extraction_result); the events leave no trace; in every row of an occurrence of a control "
    "(start_s < t <= start_s + duration_s, the host times of controls_json less its measure_start_unix) a control of "
    "class A adds 1 to every column of its kind (controls.kinds.<kind>.columns), kontrola_wx_memfd also the memory "
    "patterns wx and memfd_fd of process WX_PID (the first member of the effect evidence of controls_json) in the "
    "quality of those rows, and a control of class B adds kappa_c x its dose to every column of its kind, kappa_c = "
    "2 x expect.shift at the largest dose / the largest dose (the protocol's expected shift is half the effect it "
    "anticipates), in whole units for a count (rounded), both clipped to the physical range and a difference column "
    "left 0 where it has no predecessor; a paired negative adds nothing; the MARGINAL CHANGE, only in mode "
    "strukturovany and only in test_benign of the campaign plan (CHANGE_RULE): +8 standard deviations by "
    "construction of OKRAJOVA_ZMENA['column'] (the role train's, as every role has the same marginal) in the rows of "
    "the band of full_snapshot_guard.before_s before the first full snapshot after seq 0, in one session of every "
    "group (the lead's answer to Q36: never in a null run, never in train, dev or calibration); the TOLERATED INVALID "
    "ROWS: one run of contiguous rows of quality boundary_sessions.unclosed_row('processes') in one session of every "
    "role, in test_benign and test_controls invalid_rows.max rows from the first row of the first "
    "analysis.evaluable.first_s seconds of the chosen event or control, so that the run and the window_rows rows "
    "after it leave less than analysis.evaluable.scored_share of those seconds scored (UNSCORED_RULE; under "
    "config/collection-v5.json none of them), a protocol under which they would not being refused; zaznam records "
    "each session's seed, its changes, its invalid rows and the effects of its controls row by row, and generator_json "
    "all of them")
LOAD_RULE = (
    "the planned offered load of a row at t seconds after the measurement start: rate x the integral of the envelope "
    "of scripts/host_traffic.py draw_envelope (profiles.<profile>.arrivals, random.Random of the row's traffic seed, "
    "dur warmup_s + cycles x interval_s, scenario_rule.min_peak_to_mean, as scripts/collection.py _v5_traffic plans "
    "the generator) over [warmup_s + t - interval_s, warmup_s + t]: the user sessions the plan offers in the row's "
    "interval, in the frame in which the measurement starts warmup_s after the traffic (scripts/collection.py "
    "capture_session starts the collector after the warmup)")
CHANGE_RULE = (
    "OKRAJOVA_ZMENA: mode strukturovany, test_benign of the campaign plan, one session of every group; +8 x the scale "
    "of the column (its standard deviation by construction, the same in every role) in every row with T - "
    "full_snapshot_guard.before_s <= t < T, T the time of the first full snapshot after seq 0, in a session other "
    "than the one with the tolerated invalid rows; the record holds the value added to each row after the clip to the "
    "physical range and, apart, the rows of the band that end no window of the live detector "
    "(features.coverage.scorable_windows; skeleton section 2: an occurrence in an unscored stretch is reported apart)")
CONTROLS_JSON_RULE = (
    "controls.json of a session of role test_controls after a faultless run of its planned controls, as "
    "scripts/tests/audit_cases_logs.py controls_session writes it: {schema: scripts/protocol_v5.py CONTROLS_SCHEMA, "
    "controls: audit_cases_logs.control_records(items, measure_start_unix)}, items the row's controls with a kind in "
    "the plan's order (as scripts/collection.py v5_planned puts them into session.json); a record holds its item but "
    "the class A or B, which it keeps as kind_class, the class of the occurrence by its polarity, executed true, "
    "host_start_unix = measure_start_unix + start_s and host_started_unix 0.2 s later, host_stop_unix = "
    "host_start_unix + duration_s and host_stopped_unix 0.3 s later, the guest's baseline, effect (its evidence names "
    "WX_PID first) and cleanup true and the replies of lab/udalosti.py with test_collection_logs.SCRIPT_SHA256, which "
    "the session.json of the session names as source_sha256 lab/udalosti.py (as controls_session); the rows of an "
    "occurrence in riadky are those with host_start_unix < measure_start_unix + t <= host_stop_unix")


# ------------------------------------------------------------------ the seeds (skeleton row C1)

def _hash_seed(parts):
    return int(hashlib.sha256(json.dumps(parts).encode()).hexdigest()[:16], 16)


def seed_session(meno, skupina, pozicia, pokus, seed):
    """The seed of a session: sha256 of [plan name, group, position, attempt, "suchy_beh", the run's seed]."""
    return _hash_seed([meno, skupina, pozicia, pokus, PURPOSE, seed])


def seed_role(meno, rola, seed):
    """The seed of the choices of a role: sha256 of [plan name, role, -1, 0, "suchy_beh", the run's seed] (the
    role-level form of streams.rule: the role as group, session -1, attempt 0)."""
    return _hash_seed([meno, rola, -1, 0, PURPOSE, seed])


# ------------------------------------------------------------------ the protocol, the plan and the choices

def _check_protocol(p):
    if type(p) is not dict or p.get("schema") != protocol_v5.SCHEMA:
        raise ValueError("the generators of the dry run take a protocol of schema 3 (the working copy of the run)")
    if p.get("bin_bytes") != bs.BIN_BYTES:
        raise ValueError(f"bin_bytes {p.get('bin_bytes')!r} differs from the bins of boundary_sessions "
                         f"({bs.BIN_BYTES}), whose layout the result states")
    if p.get("quality_policy") != fq.BEHAVIOR_POLICY:
        raise ValueError("the generators give rows under the quality policy " + fq.BEHAVIOR_POLICY)
    rule = fq.invalid_rows_rule(p)
    if rule is None or rule["max"] < 1 or "processes" not in rule["traversals"]:
        raise ValueError("invalid_rows tolerates no row whose processes traversal did not close: the tolerated invalid "
                         "rows cannot be inserted")
    if p["cycles"] <= p["full_every"]:
        raise ValueError("a session of the protocol holds no full snapshot after seq 0: the marginal change has no "
                         "band")


def _label(row):
    """The label of a planned session (scripts/protocol_v5.py: its group and position)."""
    if type(row) is not dict or type(row.get("group")) is not str or type(row.get("position")) is not int:
        raise ValueError("a row of the plan names its group and its position")
    return protocol_v5._label(row)


def _fingerprint(p):
    return hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()


_PLANS, _CHOICES = {}, {}


def _plan(p, mode):
    key = (_fingerprint(p), mode)
    if key not in _PLANS:
        _PLANS[key] = protocol_v5.plan(copy.deepcopy(p), mode)
    return _PLANS[key]


def _plan_mode(row, p):
    """campaign or rehearsal by the row's group prefix; a group of neither or both is refused by name."""
    prefixes = {"campaign": p["group_prefix"], "rehearsal": p["rehearsal"]["group_prefix"]}
    group = row.get("group") if type(row) is dict else None
    if type(group) is not str:
        raise ValueError("a row of the plan names its group")
    found = [mode for mode, prefix in prefixes.items() if group.startswith(prefix)]
    if len(found) != 1:
        raise ValueError(f"group {group!r} starts with the prefix of {'no' if not found else 'both'} plan mode(s) "
                         f"({prefixes['campaign']!r}, {prefixes['rehearsal']!r})")
    return found[0]


def _planned(row, p):
    """(plan mode, plan, the planned session of the row): the row's role, group, position, scenario, VM and cycles are
    those of a session of the plan of its mode, and its attempt an integer of at least 1."""
    mode = _plan_mode(row, p)
    plan = _plan(p, mode)
    keys = ("role", "group", "position", "scenario", "vm", "cycles")
    match = [s for s in plan["sessions"] if all(s.get(k) == row.get(k) for k in keys)]
    if len(match) != 1:
        raise ValueError(f"the row {_label(row)} is no session of the {mode} plan (its role, group, position, "
                         "scenario, VM and cycles)")
    if type(row.get("attempt")) is not int or row["attempt"] < 1:
        raise ValueError("a row of the plan states its attempt, an integer of at least 1")
    return mode, plan, match[0]


def _occurrences(session):
    """The events of a session of an event role, or the controls of a session of test_controls that have a kind (the
    plan's slots without a control left out, as session.json and controls.json hold them)."""
    if session["role"] == CONTROL_ROLE:
        return [c for c in session["controls"] if c.get("kind") is not None]
    return list(session["events"])


def _candidates(session):
    """The indices among _occurrences(session) of the occurrences that may carry the tolerated invalid rows
    (GENERATOR_RULE): every event, and of the controls of test_controls those of polarity control, never a paired
    negative."""
    items = _occurrences(session)
    if session["role"] == CONTROL_ROLE:
        return [i for i, item in enumerate(items) if item.get("polarity") == POSITIVE]
    return list(range(len(items)))


def _invalid_starts(p, k):
    """The first rows of a run of k rows that meets no full snapshot and lies inside the session."""
    full = p["full_every"]
    return [s for s in range(1, p["cycles"] - k + 1) if all(r % full for r in range(s, s + k))]


# The roles whose tolerated invalid rows leave the first seconds of an occurrence unscored (skeleton row C1).
OCCURRING = {"test_benign": "an event", CONTROL_ROLE: "a control of polarity control"}


def _choices(p, mode, seed):
    """{"invalid": {(group, position): choice}, "change": {(group, position)}} of the plan of `mode` (GENERATOR_RULE:
    the choices of every role from its own stream, the roles in the protocol's order)."""
    key = (_fingerprint(p), mode, seed)
    if key in _CHOICES:
        return _CHOICES[key]
    plan = _plan(p, mode)
    k_max = fq.invalid_rows_rule(p)["max"]
    invalid, change = {}, set()
    for role in p["roles"]:
        rng = np.random.default_rng(seed_role(plan["name"], role, seed))
        sessions = [s for s in plan["sessions"] if s["role"] == role]
        occurring = role in OCCURRING
        eligible = [s for s in sessions if _candidates(s)] if occurring else sessions
        if not eligible:
            raise ValueError(f"role {role} of the {mode} plan holds no session" + (
                f" with {OCCURRING[role]}: the tolerated invalid rows cannot leave the first seconds of one unscored "
                "(skeleton row C1)" if occurring else ": the tolerated invalid rows cannot be inserted"))
        chosen = eligible[int(rng.integers(len(eligible)))]
        where = (chosen["group"], chosen["position"])
        if occurring:
            candidates = _candidates(chosen)
            invalid[where] = {"role": role, "occurrence": candidates[int(rng.integers(len(candidates)))],
                              "rows": k_max}
        else:
            k = int(rng.integers(1, k_max + 1))
            starts = _invalid_starts(p, k)
            invalid[where] = {"role": role, "start": starts[int(rng.integers(len(starts)))], "rows": k}
        if role == "test_benign" and mode == "campaign":
            groups = {}
            for s in sessions:
                groups.setdefault(s["group"], []).append(s["position"])
            for group, positions in groups.items():
                free = [x for x in positions if (group, x) != where]
                change.add((group, free[int(rng.integers(len(free)))]))
    _CHOICES[key] = {"invalid": invalid, "change": change}
    return _CHOICES[key]


# ------------------------------------------------------------------ the offered load (load-dependent counts)

def ponukana_zataz(riadok_planu, protokol):
    """LOAD_RULE: the planned offered user sessions of every row of the session, a list of cycles floats. A scenario
    without a rate (null until G2 in config/collection-v5.json) is refused by name: the working copy of the run fills
    it (skeleton section 0)."""
    from scripts import host_traffic  # Inside: the generator of the lab's traffic is needed for its envelope only.
    p, row = protokol, riadok_planu
    s = p["scenarios"][row["scenario"]]
    rate = s.get("rate")
    if type(rate) not in (int, float) or not math.isfinite(rate) or rate <= 0:
        raise ValueError(f"scenarios.{row['scenario']}.rate is {rate!r}: the counts of the generators depend on the "
                         "offered load, and the working copy of the run gives the rate (null until G2 in the file)")
    interval, warmup = p["interval_s"], p["warmup_s"]
    envelope, _ = host_traffic.draw_envelope(p["profiles"][s["profile"]]["arrivals"],
                                             random.Random(row["seeds"]["traffic"]),
                                             warmup + p["cycles"] * interval, warmup,
                                             p["scenario_rule"]["min_peak_to_mean"])
    return [rate * envelope.integral(warmup + t - interval, warmup + t) for t in _times(p)]


def _times(p):
    return (FIRST_ROW_S + p["interval_s"] * np.arange(p["cycles"])).tolist()


# ------------------------------------------------------------------ the two modes

def _f(x):
    return (x * x - 1) / math.sqrt(2)


def _g(x):
    return (np.abs(x) - math.sqrt(2 / math.pi)) / math.sqrt(1 - 2 / math.pi)


def _periodic(phase):
    return math.sqrt(2) * np.sin(phase)


def _coupling(latent, drivers):
    """The coupled latent of a column from its drivers (f or g of one, or the product of both), variance 1."""
    if latent[0] == "h":
        return drivers[0] * drivers[1]
    return (_f if latent[0] == "f" else _g)(drivers[latent[1]])


def _value(spec, latent, noise, load=None):
    """A column's values from its latent of variance 1 (GENERATOR_RULE): mean + scale (sqrt(1 - share) latent +
    sqrt(share) noise), a count with kappa x load and rounded, clipped to the physical range."""
    kind, _, mean, scale, (low, high) = spec[:5]
    share = {"driver": 0.0, "slow": GENERATOR["noise_slow"]}.get(kind, GENERATOR["noise_coupled"])
    x = mean + scale * (math.sqrt(1 - share) * latent + math.sqrt(share) * noise)
    if kind == "count":
        x = np.rint(x + spec[5] * np.asarray(load))
    return np.clip(x, low, high)


def _bin_values(channel, latent, noise):
    mean, scale, (low, high), sign = BIN_CHANNELS[channel]
    share = GENERATOR["noise_bin"]
    x = mean + scale * sign * (math.sqrt(1 - share) * latent + math.sqrt(share) * noise)
    if channel == "changed_ratio":
        return np.clip(np.rint(x * PAGES), 1, PAGES) / PAGES
    return np.clip(x, low, high)


def _structured(rng, p, load):
    """(global values {column: (T,)}, bins {channel: (T, BINS)}) of mode strukturovany (GENERATOR_RULE)."""
    T, lag, period = p["cycles"], GENERATOR["lag"], GENERATOR["period_rows"]
    rho, w_u, w_p, w_pb = (GENERATOR[k] for k in ("rho", "w_u", "w_p", "w_pb"))
    n = T + lag  # Rows -lag to T - 1.
    phi = rng.uniform(0, 2 * math.pi, 2)
    u = np.empty((2, n))
    u[:, 0] = rng.normal(size=2)
    eta = rng.normal(size=(2, n - 1))
    for i in range(1, n):
        u[:, i] = rho * u[:, i - 1] + math.sqrt(1 - rho * rho) * eta[:, i - 1]
    e = rng.normal(size=(2, n))
    a = math.sqrt(w_u) * u + math.sqrt(1 - w_u) * e
    seq = np.arange(-lag, T)
    p_k = _periodic(2 * math.pi * seq / period + phi[:, None])
    s = math.sqrt(w_p) * p_k + math.sqrt(1 - w_p) * u
    now, before = slice(lag, n), slice(0, T)
    noise = {name: rng.normal(size=T) for name in BEHAVIOR_NAMES if name in COLUMNS}
    out = {}
    for name, spec in COLUMNS.items():
        kind, latent = spec[0], spec[1]
        if kind == "driver":
            x = a[latent[1], now]
        elif kind == "slow":
            x = s[latent[1], now]
        else:
            x = _coupling(latent, a[:, before])
        out[name] = _value(spec, x, noise[name], load)
    bins = {}
    bin_noise = rng.normal(size=(BINS, len(BIN_CHANNELS), T))
    for j in range(BINS):
        k = j % 2
        b = (math.sqrt(w_pb) * _periodic(2 * math.pi * seq[now] / period + phi[k] + math.pi * (j // 2))
             + math.sqrt(1 - w_pb) * u[k, now])
        for c, channel in enumerate(BIN_CHANNELS):
            bins.setdefault(channel, np.empty((T, BINS)))[:, j] = _bin_values(channel, b, bin_noise[j, c])
    return out, bins


def _null(rng, p, load):
    """(global values, bins) of mode nulovy: the same functions of independent draws of every column's latent inputs
    for every row from their law at one row of the structured mode (GENERATOR_RULE)."""
    T, w_p, w_pb = p["cycles"], GENERATOR["w_p"], GENERATOR["w_pb"]

    def slow(w):
        theta = rng.uniform(0, 2 * math.pi, T)
        return math.sqrt(w) * _periodic(theta) + math.sqrt(1 - w) * rng.normal(size=T)
    out = {}
    for name in BEHAVIOR_NAMES:
        if name not in COLUMNS:
            continue
        spec = COLUMNS[name]
        kind, latent = spec[0], spec[1]
        if kind == "driver":
            x = rng.normal(size=T)
        elif kind == "slow":
            x = slow(w_p)
        else:
            x = _coupling(latent, rng.normal(size=(2, T)) if latent[0] == "h" else
                          {latent[1]: rng.normal(size=T)})
        noise = rng.normal(size=T)
        resampled = None
        if kind == "count" and spec[5] > 0:
            resampled = np.asarray(load)[rng.integers(0, T, size=T)]
        out[name] = _value(spec, x, noise, resampled if resampled is not None else np.zeros(T))
    bins = {channel: np.empty((T, BINS)) for channel in BIN_CHANNELS}
    for j in range(BINS):
        for channel in BIN_CHANNELS:
            b = slow(w_pb)
            bins[channel][:, j] = _bin_values(channel, b, rng.normal(size=T))
    return out, bins


# ------------------------------------------------------------------ one session

def _rows_of(times, start, duration):
    """The rows of an occurrence: start_s < t <= start_s + duration_s (a row at t covers (t - interval_s, t])."""
    return [i for i, t in enumerate(times) if start < t <= start + duration]


def _kappa(p, kind, column):
    """kappa_c of a column of a control kind of class B: 2 x expect.shift at the largest dose / the largest dose."""
    spec = p["controls"]["kinds"][kind]
    doses, shifts = spec["doses"], spec["expect"][column]["shift"]
    largest = max(doses)
    return 2 * shifts[doses.index(largest)] / largest


def _limits(name):
    if name in COLUMNS:
        return COLUMNS[name][4]
    return (0.0, math.inf)


UNSCORED_RULE = (
    "the unscored stretch of the tolerated invalid rows: the maximal run of consecutive rows that end no window of "
    "features.coverage.scorable_windows (the windows of the live detector, without an anchor) and hold the invalid "
    "rows, as safeguard.runtime.unscored joins the unscored rows of a replay; the run, the row after it without a "
    "predecessor and the window_rows - 1 rows that fill the window again, joined with an unscored stretch just before "
    "it; for an event or a control its scored share of the first analysis.evaluable.first_s seconds as tcn/eval.py "
    "_vyskyt takes it (the scored rows with start_s < t <= start_s + first_s times interval_s over first_s) and "
    "whether it is evaluable (at least analysis.evaluable.scored_share), which refuses the session by name")


def _scored(result, p):
    """The seq of the rows that end a window of the live detector (features.coverage.scorable_windows)."""
    from features.coverage import scorable_windows  # Inside: the scorer of the live detector, for the record only.
    windows, _ = scorable_windows(result, p, "suchy-generator", len(result["seq"]))
    return {int(m["seq_do"]) for m in windows.meta}


def _unscored(result, p, invalid, occurrence, label):
    """UNSCORED_RULE of the tolerated invalid rows `invalid` of `result`: {unscored_stretch}; the occurrence's record,
    when there is one, gets first_s_scored_share and evaluable, and an occurrence that stays evaluable is refused by
    name (the known answer of the skeleton's row C1 cannot be made under this protocol)."""
    scored = _scored(result, p)
    first, last = invalid[0], invalid[-1]
    while first > 0 and first - 1 not in scored:
        first -= 1
    while last + 1 < len(result["seq"]) and last + 1 not in scored:
        last += 1
    if occurrence is not None:
        share = sum(r in scored for r in occurrence["first_s_seq"]) * p["interval_s"] / occurrence["first_s"]
        occurrence.update(first_s_scored_share=share, evaluable=share >= p["analysis"]["evaluable"]["scored_share"])
        if occurrence["evaluable"]:
            raise ValueError(f"the tolerated invalid rows {invalid} of {label} leave {share:g} of the first "
                             f"{occurrence['first_s']:g} s of its occurrence scored, not less than "
                             "analysis.evaluable.scored_share: invalid_rows.max and window_rows of the protocol do not "
                             "make an occurrence nevyhodnotené")
    return {"unscored_stretch": {"first_seq": first, "last_seq": last, "rows": last - first + 1,
                                 "rule": UNSCORED_RULE}}


def _session(row, rezim, seed, p):
    """(result, record, base matrix) of one row of a plan: the base matrix is the drawn values with the zeros of the
    rows without a predecessor, before any control effect or change."""
    if rezim not in MODES:
        raise ValueError(f"the mode of the generator is {' or '.join(MODES)}, not {rezim!r}")
    if type(seed) is not int or seed < 0:
        raise ValueError("the seed of a run is an integer of at least 0")
    _check_protocol(p)
    plan_mode, plan, planned = _planned(row, p)
    name, T = plan["name"], p["cycles"]
    s_seed = seed_session(name, row["group"], row["position"], row["attempt"], seed)
    rng = np.random.default_rng(s_seed)
    load = ponukana_zataz(row, p)
    values, bins = (_structured if rezim == "strukturovany" else _null)(rng, p, load)
    times = _times(p)
    choices = _choices(p, plan_mode, seed)
    where = (row["group"], row["position"])

    # The tolerated invalid rows (GENERATOR_RULE).
    invalid_record, invalid = None, []
    choice = choices["invalid"].get(where)
    if choice is not None:
        k = choice["rows"]
        occurrence = None
        if "occurrence" in choice:
            # A replacement keeps the event types or the control kinds, polarities and doses in order
            # (scripts/protocol_v5.py replacement), so the planned choice names the same occurrence in it.
            items, kept = _occurrences(row), ("type", "kind", "polarity", "dose")
            if ([[x.get(key) for key in kept] for x in items]
                    != [[x.get(key) for key in kept] for x in _occurrences(planned)]):
                raise ValueError(f"the row {_label(row)} holds other occurrences than its planned session")
            item = items[choice["occurrence"]]
            first_s = p["analysis"]["evaluable"]["first_s"]
            first = _rows_of(times, item["start_s"], first_s)
            s0 = first[0]
            occurrence = {"index": choice["occurrence"], "start_s": item["start_s"], "first_s": first_s,
                          "first_s_seq": first,
                          **({"kind": item["kind"], "polarity": item["polarity"]} if row["role"] == CONTROL_ROLE
                             else {"type": item["type"]})}
        else:
            s0 = choice["start"]
        invalid = list(range(s0, s0 + k))
        if invalid[-1] >= T or any(r % p["full_every"] == 0 for r in invalid):
            raise ValueError(f"the invalid rows {invalid} of {_label(row)} meet a full snapshot or leave the "
                             "session")
        invalid_record = {"seq": invalid, "rows": k, "cause": "processes", "occurrence": occurrence,
                          "quality": "boundary_sessions.unclosed_row('processes')"}
    flagged = set(invalid)
    valid = [r not in flagged for r in range(T)]
    has_prev = np.array([r > 0 and valid[r - 1] for r in range(T)])

    matrix = np.zeros((T, len(MENA)))
    for column_name, column in values.items():
        matrix[:, MENA.index(column_name)] = column
    for column_name, level in RULE_VALUES.items():
        matrix[:, MENA.index(column_name)] = level
    matrix[:, MENA.index("ma_predchodcu")] = has_prev
    matrix[:, MENA.index("je_plna")] = [r % p["full_every"] == 0 for r in range(T)]
    for column_name in DIFFERENCES:
        matrix[~has_prev, MENA.index(column_name)] = 0.0
    base = matrix.copy()
    quality = [bs.complete_row() if valid[r] else bs.unclosed_row("processes") for r in range(T)]

    # The controls (both modes): class A +1, class B kappa_c x dose, in every row of the occurrence; negatives nothing.
    control_records = []
    if row["role"] == CONTROL_ROLE:
        kinds = p["controls"]["kinds"]
        for slot, item in enumerate(row["controls"]):
            if item.get("kind") is None:
                continue
            spec, rows = kinds[item["kind"]], _rows_of(times, item["start_s"], item["duration_s"])
            record = {"slot": slot, "kind": item["kind"], "polarity": item["polarity"], "class": spec["class"],
                      "dose": item.get("dose"), "start_s": item["start_s"], "duration_s": item["duration_s"],
                      "seq": rows, "effects": {}, "patterns": None}
            if item["polarity"] == POSITIVE:
                for column in spec["columns"]:
                    j = MENA.index(column)
                    if spec["class"] == "A":
                        step = 1.0
                    else:
                        step = _kappa(p, item["kind"], column) * item["dose"]
                        if TRIEDY.get(column) == "neural" and COLUMNS[column][0] == "count":
                            step = float(np.rint(step))
                    low, high = _limits(column)
                    keep = [r for r in rows if not (column in DIFFERENCES and not has_prev[r])]
                    before = matrix[keep, j].copy()
                    matrix[keep, j] = np.clip(before + step, low, high)
                    added = np.zeros(len(rows))
                    added[[rows.index(r) for r in keep]] = matrix[keep, j] - before
                    record["effects"][column] = {"step": step, "added": added.tolist()}
                if item["kind"] == WX_KIND:
                    for r in rows:
                        quality[r]["memory_patterns"] = [{"pid": WX_PID, "comm": "python3", "kind": kind_}
                                                         for kind_ in WX_PATTERNS]
                    record["patterns"] = {"pid": WX_PID, "comm": "python3", "kinds": list(WX_PATTERNS)}
            control_records.append(record)

    # The marginal change (the lead's answer to Q36): structured mode, test_benign of the campaign plan only.
    changes = []
    if rezim == "strukturovany" and plan_mode == "campaign" and row["role"] == "test_benign" \
            and where in choices["change"]:
        column = OKRAJOVA_ZMENA["column"]
        full = next(r for r in range(1, T) if r % p["full_every"] == 0)
        band = (times[full] - p["full_snapshot_guard"]["before_s"], times[full])
        rows = [r for r in range(T) if band[0] <= times[r] < band[1]]
        sd = COLUMNS[column][3]
        delta = OKRAJOVA_ZMENA["sd"] * sd
        j = MENA.index(column)
        before = matrix[rows, j].copy()
        matrix[rows, j] = np.clip(before + delta, *_limits(column))
        changes.append({"kind": "okrajova_zmena", "column": column, "delta": delta, "sd": sd, "sd_factor":
                        OKRAJOVA_ZMENA["sd"], "seq": rows, "times_s": [times[r] for r in rows],
                        "band_s": list(band), "full_snapshot_seq": full,
                        "added": (matrix[rows, j] - before).tolist(), "rule": CHANGE_RULE})

    # The result as features/snapshot.py retazec gives it (boundary_sessions.extraction_result).
    pages = np.rint(bins["changed_ratio"] * PAGES).astype(int)
    perbin = np.stack([pages / PAGES, bins["zero_ratio"], bins["entropy_mean"], np.ones((T, BINS))], axis=-1)
    chains = [f"{_label(row)}/{row['attempt']}-chain-{r // p['full_every']}" for r in range(T)]
    side = bs._sidecar(0, times[0], True, chains[0], quality[0], pages[0], bins["zero_ratio"][0],
                       bins["entropy_mean"][0])
    result = {"schema": SNAPSHOT_SCHEMA, "mena": list(MENA), "matica": matrix.tolist(),
              "snimky": [f"frame{r}" for r in range(T)], "poznamky": [[] for _ in range(T)], "trvanie_s": [0.0] * T,
              "seq": list(range(T)), "casy": times, "quality": quality,
              "valid": [fq.valid_for(q, fq.BEHAVIOR_POLICY) for q in quality], "quality_policy": fq.BEHAVIOR_POLICY,
              "perbin": perbin.tolist(), "biny": list(range(BINS)), "chain_ids": chains,
              "layout": validate_sidecar(side), "max_medzera_s": p["max_gap_s"]}
    if invalid_record is not None:
        invalid_record.update(_unscored(result, p, invalid, invalid_record["occurrence"], _label(row)))
    if changes:  # The skeleton (section 2, marginal_change): an occurrence in an unscored stretch is reported apart.
        scored = _scored(result, p)
        changes[0]["unscored_seq"] = [r for r in changes[0]["seq"] if r not in scored]
    loaded = np.asarray(load)
    record = {"label": _label(row), "attempt": row["attempt"], "role": row["role"],
              "group": row["group"], "position": row["position"], "scenario": row["scenario"], "vm": row.get("vm"),
              "plan_mode": plan_mode, "plan_name": name, "rezim": rezim, "run_seed": seed, "seed": s_seed,
              "load": {"rate": p["scenarios"][row["scenario"]]["rate"], "mean": float(loaded.mean()),
                       "min": float(loaded.min()), "max": float(loaded.max()), "rule": LOAD_RULE},
              "invalid_rows": invalid_record, "changes": changes, "controls": control_records}
    return result, record, base


def riadky(riadok_planu, rezim, seed, protokol):
    """The extraction result of one row of a plan (GENERATOR_RULE): a dict of the keys of features/snapshot.py retazec
    (schema, mena, matica, snimky, poznamky, trvanie_s, seq, casy, quality, valid, quality_policy, perbin, biny,
    chain_ids, layout, max_medzera_s); casy in seconds since the measurement start. ValueError names the reason of a
    refusal: another mode, a seed that is no integer of at least 0, a protocol of another schema or without a rate of
    the row's scenario, a row that is no session of the plan of its group prefix, a plan without a session for the
    tolerated invalid rows, a protocol under which they leave an occurrence evaluable."""
    return _session(riadok_planu, rezim, seed, protokol)[0]


def zaznam(riadok_planu, rezim, seed, protokol):
    """The record of the session in generator.json (GENERATOR_RULE): label, attempt, role, group, position, scenario,
    VM, plan mode and name, mode, the run's seed and the session's seed, the planned offered load (LOAD_RULE), the
    tolerated invalid rows (their seq, count, cause, the occurrence whose first seconds they leave unscored, the
    unscored stretch they make and that occurrence's scored share: UNSCORED_RULE), the inserted changes (the marginal
    change, CHANGE_RULE: column, delta, standard deviation, seq, times, band, the value added to each row and the rows
    of the band that end no window of the live detector) and the controls (slot, kind, polarity, class, dose, times,
    the rows of the occurrence, per column the step and the value added to each row, the memory patterns)."""
    return _session(riadok_planu, rezim, seed, protokol)[1]


def _json_bound(x):
    """A bound of a physical range as JSON states it: an infinite one is null (no bound)."""
    return None if math.isinf(x) else x


def generator_json(riadky_planu, rezim, seed, protokol):
    """generator.json of a run: {schema, rule, load_rule, change_rule, unscored_rule, controls_json_rule, parameters,
    columns, bin_channels, rule_values, classes, change, wx_pid, rezim, seed, sessions} with the record of every row of
    riadky_planu (zaznam), in their order; JSON-ready. A session and attempt given twice is refused by name."""
    sessions = [zaznam(row, rezim, seed, protokol) for row in riadky_planu]
    labels = Counter((s["label"], s["attempt"]) for s in sessions)
    repeated = [label for label, n in labels.items() if n > 1]
    if repeated:
        raise ValueError(f"the rows of generator.json repeat the session {repeated[0][0]} attempt {repeated[0][1]}")
    return {"schema": SCHEMA, "rule": GENERATOR_RULE, "load_rule": LOAD_RULE, "change_rule": CHANGE_RULE,
            "unscored_rule": UNSCORED_RULE, "controls_json_rule": CONTROLS_JSON_RULE,
            "parameters": dict(GENERATOR, first_row_s=FIRST_ROW_S),
            "columns": {name: [spec[0], list(spec[1]), spec[2], spec[3], [_json_bound(x) for x in spec[4]],
                               *spec[5:]] for name, spec in COLUMNS.items()},
            "bin_channels": {name: [*spec[:2], list(spec[2]), spec[3]] for name, spec in BIN_CHANNELS.items()},
            "rule_values": dict(RULE_VALUES), "classes": dict(TRIEDY), "change": dict(OKRAJOVA_ZMENA),
            "wx_pid": WX_PID, "rezim": rezim, "seed": seed, "sessions": sessions}


def controls_json(riadok_planu, measure_start_unix):
    """CONTROLS_JSON_RULE: controls.json of the session of role test_controls of `riadok_planu` (a row of the plan or of
    a replacement) whose measurement started at `measure_start_unix` (a finite number of seconds); a row of another
    role and a start that is no finite number are refused by name."""
    if type(riadok_planu) is not dict or riadok_planu.get("role") != CONTROL_ROLE:
        raise ValueError(f"controls.json belongs to a session of role {CONTROL_ROLE} only")
    if type(measure_start_unix) not in (int, float) or not math.isfinite(measure_start_unix):
        raise ValueError("measure_start_unix is a finite number of seconds")
    items = copy.deepcopy(_occurrences(riadok_planu))
    return {"schema": CONTROLS_SCHEMA, "controls": audit_cases_logs.control_records(items, measure_start_unix)}
