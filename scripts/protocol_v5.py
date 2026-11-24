"""Protocol v5: the layout of schema 3, its schedule and the self-check of a protocol file (package B4).

Schema hyptcn3/collection-protocol/3 is the v5 layout (docs/NAVRH_PROTOKOL_V5.sk.md, chapters 5.5, 6.4, 7.2-7.5,
8.3, 8.4, 10.1, 10.4, 10.9; the traffic profiles of package B5b, chapters 5.2, 5.3 and 5.7). This module holds all
v5 logic; scripts/collection.py calls it from protocol(), plan() and its subcommand selfcheck, and
scripts/host_traffic.py reads the profiles section through profiles_problems():

    check_layout(p)                the loader's part: unknown and missing keys, malformed values of the v5 sections
    profiles_problems(p)           every malformed value of the profiles section, as named reasons
    plan(p, mode)                  the schedule of a campaign or of its rehearsal (a mode of the same file)
    replacement(p, session, n)     attempt n of a planned session: the same assignment and tenths of its phases, new
                                   times and traffic seeds
    planned_rows(p, mode)          one row per planned session, the rows the corpus index and training match accepted
                                   sessions to (package B6a)
    reset_seed(p)                  the seed of lab/guest_state.py reset --seed at the start of every group of both
                                   modes (package B9a and its fix): streams.seeded_level.seed, one seeded level
    plans_events(p)                whether its sessions list events and keep events.json (log audit, corpus build)
    analysis_plan(p)               the analysis plan the training and the evaluation read (B6, B7)
    analysis_seed(p, purpose, unit, mode=...)
                                   the seed of a stream of the analysis (B7a): z0_alarms per role, bootstrap per
                                   comparison of a confirmatory claim, injections (B7b) per carrier role and class
                                   and for the insertion into dev; the plan draws none of them
    grid_problem(method, grid, window_rows)
                                   the problem of a filled grid of Z1, Z3 or Z5 (GRID_DOMAINS), or None; the value
                                   check and tcn/metody.py both use it (B7b)
    metrics_problem(metrics)       the problem of analysis.metrics, or None; the value check and tcn/eval.py both use
                                   it (B7c)
    selfcheck(path, mode, stage)   every check of the self-check on the file and on its plan, and summary(p, plan):
                                   the tables of the plan the report records

The loader does not judge balance, role sizes, the place of null values or the binding of the score coverage
gate to invalid_rows.max; the self-check does. Its check functions take (doc, plan) so that a test can pass a
mutated plan. A value a later stage determines (proposal 10.9) is null or preliminary at its one place in the
file; determined_at names the stage of each such path, and `*` stands for every key of an object at that level.
The doses of a control kind of class A are null by design (it has none), not determined later (not_applicable), and
so are the seeds of a descriptive method that draws nothing (UNSEEDED, merge of B7a).

Package B8 (the lead's skeleton dokazy/B8/kostra/KOSTRA.md, design B8 sections 1.1 and 1.2): every control kind
states its class, its doses and the occurrences per dose (class B), the feature columns it should move with the
expected shift of each, and the module kind its candidates; controls.baseline is the tolerance of the level part of
the return predicate (null until G2). The plan deals every control of class B a dose: each dose has its count among
the kind's controls and the same among its negatives, and within 1 on every VM.

Package B6a (the lead's skeleton dokazy/B6/kostra/KOSTRA.md section 2, design B6a 1.1): analysis.qualification holds
the bounds of the qualification of the feature columns (features/qualification.py, proposal 8.1), analysis.columns
the class of each of the 20 columns of features.archive.BEHAVIOR_NAMES (null until G3a; it replaces
analysis.column_mask), analysis.scale the scale rule of the normalizer and analysis.architecture the TCN of the
thesis with its optimizer; the training of package B6b reads them.

Package B7a (the lead's skeleton dokazy/B7/kostra/KOSTRA.md sections 2 to 4 and its addendum 2 point 1, design B7a
1.6): the methods Z0, Z2, Z4 and M have no free parameter (grid {} from G0 on), so only the grids of Z1, Z3 and Z5
wait for G3a; analysis.selection follows the skeleton; analysis.descriptive_methods lists the four descriptive
methods of the core (z-score, isolation forest, GRU and LSTM) apart from analysis.methods; analysis.wording holds the
conclusions of chapter 8.4 word for word for K1, K2a and K2b and each outcome; analysis.matched_rate the budget of
the matched alarm rate and the repetitions of Z0; analysis.statistics the interval and the test of the claims. The
streams gain z0_alarms and bootstrap, which the analysis draws and the plan does not (analysis_seed), so no draw of
the plan changes.

Package B7b (the lead's skeleton dokazy/B7/kostra/KOSTRA.md sections 5, 6 and 9, design B7b 1.4):
analysis.interventions states the order variants of class C, the column groups of class D, the validity predicate
(its quantiles of role train and the length of its moving average), the evaluable minimum and the rule of the volume
class; analysis.diagnostics the bounds of the descriptive diagnostics of proposal 8.5; the stream injections places
the interventions, per carrier role and class and once for the interventions inserted into dev (INJECTION_UNITS), and
the plan draws it no more than z0_alarms or bootstrap. The lead's answer to question Q13 (2026-11-24): Z4 enters K2a
by each of its variants (VARIANTS), each a comparison of its own, and "better" needs M to beat both. F3 of the
verification of B7a: the value domain of every grid parameter is one constant (GRID_DOMAINS, grid_problem) for this
check and tcn/metody.py.

Package B7c (the lead's skeleton dokazy/B7/kostra/KOSTRA.md, addendum 2 of 2026-11-22T20:55Z points 2 and 4, design
B7c 1.2): analysis.metrics holds the metrics as the thesis defines them, beside the proposal's, which tcn/eval.py
computes: the exact two-sided interval of an alarm rate (Garwood), the dispersion test of the alarm counts between
sessions, the one-sided exact test of the alarm rate during events against clean traffic, the one-sided bounds of O2
and O3 (proposal 4.2 and 9.2) and the classifier's measures, each with its numbers and its source (metrics_problem,
one check for this module and tcn/eval.py); analysis.linkage holds the table of the thesis' research questions VO1 to
VO6 and the outputs that answer them, word for word as the skeleton writes it (LINKAGE; the self-check compares it,
as it compares the methods of the claims with CONFIRMATORY). Both are G0.

Package B9a (design B9a 1.1, agent P; its fix, F4 of its verification and question Q18 to the lead): every group of
both modes starts from the one seeded level streams.seeded_level.seed (reset_seed, proposal 5.4, chapter 12), the
level lab/install.sh seeds, and no random stream draws it; the self-check names a role whose
group counts per VM differ by more than 1 (S3 of the B4 verification) and an item outside the protocol's deck (S5);
the control deal is drawn again until its cards are balanced, at a rehearsal size where a balanced deal exists (N1 of
the confirmation of B4b); where the counts allow it, every dose of class B lies in a scenario of a control and of a
negative of it (S3 of the B8 verification), which changes the doses of the campaign's plan and nothing else; and
analysis.interventions.boots must be the count of the carrier boots of the campaign plan (F3 of the verification of
B7c; the check analysis).

Package B11 (agent E; the lead's answers to questions Q17 and Q28, 2026-11-24): analysis.attachments lists in advance
the attachments of the final record, exactly ATTACHMENTS (series, losses, copies), each with the text of what it holds,
and a note (G0); attachments_problem is the one check of the loader, the self-check and tcn/finalne.py, which writes
them.
"""
from collections import Counter
import copy
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import re

SCHEMA = "hyptcn3/collection-protocol/3"
PLAN_SCHEMA = "hyptcn3/collection-plan/2"
STAGES = ("G0", "G1", "G2", "G3a", "G3b", "G4", "G5", "G6")
DETERMINED = ("G1", "G2", "G3a", "G3b")  # The stages a path of determined_at may belong to.
MODES = ("campaign", "rehearsal")
ROLES = ("train", "dev", "calibration", "test_benign", "test_controls")
CONTROL_ROLE = "test_controls"  # Its sessions hold controls on the VM and no events (proposal 7.2, 7.4).
# The record of a planned control in the session's controls.json (design B8, section 1.4): its class is that of the
# occurrence, the control or its paired negative, by the polarity of the plan's item; the item's class A or B stays in
# the record as kind_class (scripts/collection.py Controls, scripts/collection_logs.py, scripts/controls.py).
CONTROLS_SCHEMA = "hyptcn3/session-controls/1"
CONTROL_RECORD_CLASS = {"control": "control", "negative": "control_negative"}
# Proposal 7.3: train, dev and calibration in this order, then the two test roles interleaved in time.
TIME_RANK = {"train": 0, "dev": 1, "calibration": 2, "test_benign": 3, "test_controls": 3}
INTERLEAVED = ("test_benign", "test_controls")
# The random streams of the plan and the unit each one is drawn for (proposal 5.5; the streams section). Package
# B5b adds the traffic streams (skeleton B5 section 2): the arrival times, the choices in a user session and the
# sizes each have their own; traffic draws the arrival envelope and stays the session's seed. Package B4b adds
# phase_deck: the tenths of the interval in which the starts and the stops of a role lie.
# Package B7a (design B7a 1.6) adds the two streams of the analysis, which the plan never draws: z0_alarms per role
# (the random alarms of Z0 at the matched alarm rate on that role's windows) and bootstrap per comparison of a
# confirmatory claim with one method (the resamples of its interval, then the sign vectors of its test); they take no
# unit of the plan, so SESSION_PURPOSES and every draw of the plan stay as they were (analysis_seed).
# Package B7b (design B7b 1.4) adds injections, the placements of the interventions into features (skeleton B7
# sections 5 and 9) per unit of INJECTION_UNITS; the plan draws it no more than the other two.
# The fix of package B9a (F4 of its verification, question Q18 to the lead) removed the stream guest_reset of B9a,
# one seed per group: every group of both modes starts from one seeded level (proposal 5.4, chapter 12), the value
# streams.seeded_level.seed, which no random stream draws (reset_seed).
ANALYSIS_PURPOSES = {"z0_alarms": "role", "bootstrap": "comparison", "injections": "insertion"}
PURPOSES = {"scenario_order": "block", "event_free_position": "role", "event_deck": "role",
            "control_deck": "role", "phase_deck": "role", **ANALYSIS_PURPOSES, "event_times": "session",
            "traffic": "session", "traffic_arrivals": "session", "traffic_choices": "session",
            "traffic_sizes": "session"}
SESSION_PURPOSES = tuple(purpose for purpose, unit in PURPOSES.items() if unit == "session")
# lab/guest_state.py reset takes a seed of 1 to 18 digits ([0-9]{1,18}), so streams.seeded_level.seed is an integer
# of 0 to RESET_SEED_BOUND - 1.
RESET_SEED_BOUND = 10 ** 18
METHODS = ("Z0", "Z1", "Z2", "Z3", "Z4", "Z5", "M")
# Package B7a (skeleton B7 section 2, design B7a 1.4 and 1.6): the methods with free parameters, whose grid
# analysis.methods.<m>.grid is null until G3a, and the names of their parameters, which a filled grid has exactly (one
# constant for the protocol and tcn/metody.py, which reads them; merge of B7a); Z0, Z2, Z4 and M have none (grid {};
# M's epoch is analysis.stopping's).
GRID_PARAMETERS = {"Z1": ("moving_average_rows", "cusum_shift"), "Z3": ("ewma_alpha",), "Z5": ("ridge_alpha",)}
GRIDDED = tuple(GRID_PARAMETERS)
# F3 of the verification of B7a (design B7b 1.4): the value domain of each grid parameter, one constant for the value
# check of analysis.methods and for tcn/metody.py (grid_value_ok, grid_problem): integers or numbers, the lowest and
# the highest value and whether each is allowed; a highest of "window_rows" is the protocol's window_rows (a moving
# average reads the window_rows rows of a window, tcn/metody.py Z1_RULE).
GRID_DOMAINS = {
    "moving_average_rows": {"integer": True, "low": 1, "low_allowed": True, "high": "window_rows",
                            "high_allowed": True, "text": "integers of at least 1 and at most window_rows"},
    "cusum_shift": {"integer": False, "low": 0, "low_allowed": True, "high": None, "high_allowed": None,
                    "text": "numbers of at least 0 (normalized units)"},
    "ewma_alpha": {"integer": False, "low": 0, "low_allowed": False, "high": 1, "high_allowed": True,
                   "text": "numbers in (0, 1]"},
    "ridge_alpha": {"integer": False, "low": 0, "low_allowed": False, "high": None, "high_allowed": None,
                    "text": "positive numbers"},
}
# The lead's answer to question Q13 (2026-11-24; design B7b 1.4): a method with variants enters a confirmatory claim by
# each variant, "<method>:<variant>", each a comparison of its own with its own stream bootstrap, so that "better" needs
# M to beat every variant; Z4 has the variants of tcn/metody.py Z4_VARIANTS (skeleton B7 section 2: the offered load
# and the residual on it). COMPARISONS are the names a claim may compare.
VARIANTS = {"Z4": ("load", "residual")}
COMPARISONS = tuple(name for method in METHODS if method != "M"
                    for name in ([f"{method}:{v}" for v in VARIANTS[method]] if method in VARIANTS else [method]))
# Package B7b (the lead's skeleton B7 sections 5 and 9, design B7b 1.2 and 1.4): the interventions into features of
# classes C and D, carried by the sessions of the test roles (K2) and inserted into dev for the selection of Z1
# (never in K2); the units of the stream injections are "<carrier role>/<class>" and DEV_INSERTION.
INTERVENTION_CLASSES = ("C", "D")
CARRIERS = ("test_benign", "test_controls")
DEV_INSERTION = "dev"
INJECTION_UNITS = tuple(f"{role}/{name}" for role in CARRIERS for name in INTERVENTION_CLASSES) + (DEV_INSERTION,)
ORDERS = ("reversed", "random")  # The order of the rows of a block of class C (proposal 7.4).
# The shortest block of each class (tcn/zasahy.py MIN_LENGTH, merge of B7b; judgment: a block of one row has no order
# to change, so C needs two).
MIN_BLOCK_ROWS = {"C": 2, "D": 1}
# The descriptive methods of the core (skeleton B7, addendum 2 point 1; proposal 8.3), listed apart from METHODS so
# that analysis.methods stays Z0 to Z5 and M; the networks run on every seed of analysis.seeds (design B7a 1.6). A
# method of UNSEEDED draws nothing: its seeds are null and it runs once, with seed None; every other one has a
# non-empty list (an empty list would mean that it never runs; the executor's convention of the merge of B7a).
DESCRIPTIVE = ("zscore", "iforest", "gru", "lstm")
EVERY_SEED = ("gru", "lstm")
UNSEEDED = ("zscore",)
# Package B7c (design B7c 1.2; the lead's skeleton B7, addendum 2 point 2): the metrics of analysis.metrics, each with
# the one method tcn/eval.py implements for it (one constant for this check and tcn/eval.py, metrics_problem). A
# method with a level holds the level of its interval or bound (a share in (0, 1)); the test of the events holds its
# alpha; the dispersion compares the sessions; the classifier names its measures over windows and its majorities.
METRIC_METHODS = {"alarm_rate_interval": "garwood", "dispersion": "pearson_x2",
                  "event_vs_clean": "conditional_binomial", "o2_bound": "poisson_upper",
                  "o3_bound": "clopper_pearson_upper"}
LEVELLED = ("alarm_rate_interval", "o2_bound", "o3_bound")
DISPERSION_UNIT = "session"
EVENT_ALTERNATIVE = "greater"  # The thesis: more alarms during events than in clean traffic (one-sided).
CLASSIFIER_WINDOWS = ("accuracy", "macro_f1")
CLASSIFIER_MAJORITY = ("session", "occurrence")
# Package B7c (design B7c 1.2): the table of the lead's skeleton B7, addendum 2 point 4, word for word: each research
# question of the thesis (chapter 3: VO1 to VO6) with the outputs of this protocol that answer it and, in parentheses,
# the experiment of the thesis (E1 to E5; VO3 also decision D16). "bod 1" and "bod 2" are the points 1 and 2 of that
# addendum, "test z bodu 2" its one-sided exact test of the events against clean traffic.
LINKAGE = {"VO1": "O8 a O1 (E1)", "VO2": "O2, O3 a test z bodu 2 (E2)",
           "VO3": "časť vlastníka so vzorkami, mimo protokolu (E3, D16)", "VO4": "K1, K2 a bod 1 (E4)",
           "VO5": "O7 (E5)", "VO6": "O6 a bod 2 (E2)"}
# Package B11 (the lead's answers to questions Q17 and Q28, 2026-11-24): the attachments of the final record, listed
# in advance in analysis.attachments (G0), one constant for this check and tcn/finalne.py, which writes them: the
# series of score, threshold and alarms per row of the sessions of the test roles (Q17), the losses per window of the
# predictors (Q28) and the series of the copies of the interventions (Q28).
ATTACHMENTS = ("series", "losses", "copies")
# The confirmatory claims (proposal 4.1) and their three outcomes (proposal 8.4: lepší, nie lepší, nerozhodnuté), the
# keys of analysis.wording; the wording of each outcome holds as many blanks "…" (U+2026) as the table of chapter 8.4,
# the places the claim's values fill (tcn/tvrdenia.py).
CLAIMS = ("k1", "k2a", "k2b")
OUTCOMES = ("better", "not_better", "undecided")
BLANK = "\u2026"
BLANKS = {"better": 2, "not_better": 1, "undecided": 1}
# The most boots whose 2^n sign vectors the test enumerates in full (analysis.statistics.exact_up_to_boots): 2^20 is
# about a million sums (judgment: enumeration stays below a few seconds; the skeleton's 16 lies within).
MAX_EXACT_BOOTS = 20
MAX_INVALID_ROWS = 6  # Proposal 10.9 and D4: six event boundaries of a session with three events.
# Redraws of a schedule that meets a full-snapshot guard, of unbalanced scenario blocks, of event-free sessions
# whose positions are unbalanced, and of the cycle of control cells (judgment, accepted by the lead for B4); package
# B9a draws the control deal again within the same bound (N1 of the confirmation of B4b; the same judgment).
MAX_DRAWS = 1000
# The lead's must_fix 6 on B4: the phases of the starts and of the stops are stratified by construction over the
# ten tenths of the collection interval, and the start phases of the whole plan pass a Kolmogorov-Smirnov test
# against the uniform law at the 5 % level (both numbers are the lead's).
TENTHS = 10
KS_LEVEL = .05
# Names the protocol uses that a later package registers in lab/; the check lab_register stays pending while one of
# them is unknown. B5a registered the empty event naprazdno in lab/udalosti.py, B5b the traffic profiles in
# scripts/host_traffic.py (PROFILES), B8 the five control kinds in lab/udalosti.py (CONTROLS): none is left.
PENDING_IN_LAB = ()
# The control kinds (package B8; the lead's skeleton dokazy/B8/kostra/KOSTRA.md, section 1, design B8 section 1.1).
MODULE_KIND = "kontrola_modul_jadra"  # The kind that loads one of its candidate modules (it alone has candidates).
DIRECTIONS = ("up", "down")  # The direction of a column's expected shift.
ROW_FLAGS = ("ma_predchodcu", "je_plna")  # Columns of features.snapshot.MENA that say what a row is; none is expected.
# The quantities of the level part of the return predicate, each with its band [low, high] in controls.baseline once
# G2 has measured it (null until then): exactly lab/guest_state.py LEVEL_PARTS, the only non-null shape the guest
# takes (skeleton B8 section 3).
BASELINE_PARTS = ("processes", "MemAvailable_kb")
MODULE_NAME = r"[a-z0-9_]+"  # A module name as /proc/modules shows it.

# Every top-level key of a schema-3 protocol; vms or the pair domain/target as in schema 2, two optional notes.
# A section another package adds (B5b: profiles) is added here and to config/collection-v5.json together. Schema 3 has
# no field status (question Q23, F1 of the verification of B9b): the stage of a protocol file is what the readiness
# records of scripts/gates.py say (gates.py status and require), and a field of the file could not follow it, since
# stage_binding hashes it at every stage (a change in G1 would reopen the records of G0, and the file frozen at G4
# would say g0 for good); a schema-3 file with status is refused as an unknown key. Schemas 1 and 2 keep theirs.
TOP_LEVEL = ("schema", "name", "profile", "interval_s", "max_gap_s", "bin_bytes", "window_rows",
             "stride", "full_every", "cycles", "pilot_cycles", "warmup_s", "min_free_gib", "quality_policy",
             "min_score_coverage", "invalid_rows", "replacement", "group_prefix", "group_sessions", "roles",
             "interleave", "scenarios", "scenario_rule", "profiles", "events", "full_snapshot_guard", "controls",
             "streams", "audit", "exceptions", "analysis", "rehearsal", "determined_at")
OPTIONAL = ("vms_note", "note")


class Each:
    """An object with free keys, each value an object with the fixed inner set `inner`; the value of a key that
    `extra` names has the keys of extra[key] as well (required like the others, unknown under every other key)."""

    def __init__(self, inner, extra=None):
        self.inner, self.extra = inner, dict(extra or {})

    def of(self, key):
        return {**self.inner, **self.extra.get(key, {})}


class Some:
    """An object whose keys are a subset of `keys` (values not walked)."""

    def __init__(self, keys):
        self.keys = tuple(keys)


class Keys:
    """An object with the required keys `required` and the optional keys `optional` (values not walked)."""

    def __init__(self, required, optional=()):
        self.required, self.optional = tuple(required), tuple(optional)


def _fixed(*keys, **inner):
    """A fixed inner set: every key required, no other key allowed; `inner` gives the sets one level down."""
    return {**dict.fromkeys(keys), **inner}


_TEST = _fixed("statistic", "compare", "m", "rule")
_LENGTHS = ("lengths", "per_boot")
# Package B6a (design B6a 1.1): the bounds of the qualification of the feature columns (G0), the class of each of
# the 20 columns (analysis.columns, null until G3a, which replaces analysis.column_mask), the scale rule of the
# normalizer (G0) and, in architecture, the TCN of the thesis with its optimizer (G0). Package B7a (design B7a 1.6):
# the descriptive methods apart from methods, the wordings of the conclusions per claim and outcome, the matched
# alarm rate and the statistics of the claims (all G0). Package B7b (design B7b 1.4): the interventions gain the
# orders of C, the groups of D (free names, so the template does not walk them), the validity predicate as an object,
# the evaluable minimum and the volume class; the diagnostics of proposal 8.5 (all G0). Package B7c (design B7c
# 1.2): the metrics of the thesis and the bounds of O2 and O3, and the linkage table of the thesis' questions (G0).
_METRIC = {"alarm_rate_interval": _fixed("method", "level", "source"), "dispersion": _fixed("method", "unit", "source"),
           "event_vs_clean": _fixed("method", "alternative", "alpha", "source"),
           "o2_bound": _fixed("method", "level", "source"), "o3_bound": _fixed("method", "level", "source"),
           "classifier": _fixed("windows", "majority", "source")}
ANALYSIS = _fixed(
    "seeds", "deploy_seed", "fpr", "selection", "columns", "horizon_s", "reverberation_s", "min_occurrences",
    "note",
    architecture=_fixed("model", "window_rows", "kernel", "blocks", "channels", "dropout", "weight_norm",
                        "learning_rate", "gradient_clip", "classifier_gradient_clip", "batch_size", "note"),
    qualification=_fixed("near_constant_share", "identity_auc", "duplicate_tolerance", "level_columns", "note"),
    scale=_fixed("per_bin", "min_bin_pages", "floor", "local_floor", "note"),
    stopping=_fixed("rule", "patience_epochs", "max_epochs", "repeat_if_last_epoch", "note"),
    alarm_rule=_fixed("k", "n"),
    methods={name: _fixed("what", "grid") for name in METHODS},
    descriptive_methods={name: _fixed("what", "seeds", "note") for name in DESCRIPTIVE},
    matched_rate=_fixed("budget", "z0_repetitions", "note"),
    k1=_TEST, k2a=_TEST, k2b=_TEST,
    statistics=_fixed("bootstrap", "exact_up_to_boots", "level", "note"),
    wording={claim: _fixed(*OUTCOMES) for claim in CLAIMS},
    interventions=_fixed("boots", "min_evaluable", "volume_class", "note",
                         validity=_fixed("quantiles", "moving_average_rows", "note"),
                         C=_fixed(*_LENGTHS, "orders"), D=_fixed(*_LENGTHS, "groups")),
    diagnostics=_fixed("tree_depth", "min_positive_episodes", "contexts", "alarm_rules", "note"),
    evaluable=_fixed("first_s", "scored_share"),
    metrics=_fixed("note", **_METRIC), linkage=_fixed(*LINKAGE, "note"),
    # Package B11 (Q17, Q28): the attachments of the final record, each with its text, and a note (G0).
    attachments=_fixed(*ATTACHMENTS, "note"))
# The traffic profiles of the generator (package B5b, design B5b 1.1; scripts/host_traffic.py PROFILES implements
# exactly these): the keys every profile has, and those of each profile. arrivals is the envelope family of the
# open loop, think_s the think time before every request but the first, client_errors the deliberate client errors.
_PROFILE = dict(arrivals=_fixed("ramp_s", "wave_period_s", "wave_mean", "wave_amplitude", "peak_s",
                                "peak_edge_share", "peak_at", "step_s", "note"),
                client_errors=_fixed("share", "statuses", "note"), think_s=_fixed("mean", "max", "note"))
PROFILE_KEYS = {
    "eshop": _fixed("max_concurrent", "zipf_s", "note", order_share=_fixed("low", "high"),
                    funnel=_fixed("pages", "search_share", "details_per_page", "static_share", "cart_items",
                                  "page_size", "note"), **_PROFILE),
    "corp": _fixed("max_concurrent", "zipf_s", "actions", "page_size", "note",
                   shares=_fixed("doc_list", "doc_get", "doc_put", "report"),
                   document_sizes=_fixed("median_bytes", "sigma", "tail_share", "tail_from_bytes", "tail_alpha",
                                         "min_bytes", "max_bytes", "note"), **_PROFILE),
}
PEAK_AT = ("uniform", "wave_start")  # Where the envelope's peak lies: anywhere, or where a cycle of the wave starts.
CLIENT_STATUSES = (400, 401, 404)  # Proposal 5.3: the deliberate client errors the generator makes.
CLIENT_ERROR_SHARE = (.01, .03)  # Proposal 5.3: 1 to 3 % client errors.
MAX_PAGE_SIZE = 100  # lab/services.py MAX_PAGE_SIZE: the largest page the catalog and the docs service serve.
# The fixed inner sets of the v5 sections (design B4 1.1). invalid_rows, replacement, audit and exceptions keep
# their own readers (features/quality.py, collection.check_replacement, features/audit_policy.py).
INNER = {
    "roles": _fixed(*ROLES),
    "scenarios": Each(_fixed("profile", "intensity", "rate")),
    "scenario_rule": _fixed("min_peak_to_mean", "basis", "note", peak_share=_fixed("low", "high")),
    "profiles": PROFILE_KEYS,
    "events": _fixed("types", "per_session", "duration_s", "first_s", "min_gap_s", "tail_s", "grace_s",
                     "min_per_type", "note"),
    "full_snapshot_guard": _fixed("before_s", "note"),
    # Package B8 (design B8 1.1): each kind's class, doses and occurrences per dose (null for class A), the columns
    # it should move with the expected shift of each, and for the module kind its candidates; controls.baseline is
    # the tolerance of the level part of the return predicate.
    "controls": _fixed("per_kind", "negatives_per_kind", "slots_per_session", "min_duration_s", "duration_s",
                       "horizon_s", "baseline", "note",
                       kinds=Each(_fixed("class", "doses", "per_dose", "columns", "note",
                                         expect=Each(_fixed("shift", "direction"))),
                                  extra={MODULE_KIND: _fixed("candidates")})),
    # The fix of package B9a (F4 of its verification, Q18): seeded_level, the one seeded level of the guest's database
    # at the start of every group, beside the random streams. It lies in this section so that every protocol that
    # takes the streams section of the file (scripts/tests/boundary_sessions.py v5_sections) has it.
    "streams": _fixed("purposes", "rule", "note", seeded_level=_fixed("seed", "note")),
    "analysis": ANALYSIS,
    "rehearsal": _fixed("name_suffix", "group_prefix", "groups_per_role", "note"),
    "determined_at": Some(DETERMINED),
    # collection.check_replacement reads the values; schema 3 states every cause it covers (no default).
    "replacement": Keys(("max_per_campaign", "same", "covers"), ("note",)),
}


# ------------------------------------------------------------------ layout (the loader's part)

def _walk(value, template, path, out, missing_only=False):
    """Unknown and missing keys of `value` against `template`, appended to `out`: per level in sorted key order,
    then one level down in the same order. A value that is no object is left to the value checks."""
    if isinstance(template, Each):
        for key in sorted(value):
            if type(value[key]) is dict:
                _walk(value[key], template.of(key), f"{path}.{key}", out, missing_only)
        return
    if isinstance(template, Some):
        out.extend(f"unknown protocol key: {path}.{key}" for key in sorted(set(value) - set(template.keys))
                   if not missing_only)
        return
    if isinstance(template, Keys):
        for key in sorted(set(value) | set(template.required)):
            if key not in template.required + template.optional and not missing_only:
                out.append(f"unknown protocol key: {path}.{key}")
            elif key not in value:
                out.append(f"missing protocol key: {path}.{key}")
        return
    for key in sorted(set(value) | set(template)):
        if key not in template and not missing_only:
            out.append(f"unknown protocol key: {path}.{key}")
        elif key not in value and key in template:
            out.append(f"missing protocol key: {path}.{key}")
    for key in sorted(set(value) & set(template)):
        if template[key] is not None and type(value[key]) is dict:
            _walk(value[key], template[key], f"{path}.{key}", out, missing_only)


def layout_problems(p):
    """Every unknown and missing key of a schema-3 document: the top level first, then the fixed inner sets."""
    if type(p) is not dict:
        return ["protocol is not a JSON object"]
    out = []
    vm_keys = {"vms"} if "vms" in p or not {"domain", "target"} & set(p) else {"domain", "target"}
    required = set(TOP_LEVEL) | vm_keys
    allowed = required | set(OPTIONAL) | {"vms", "domain", "target"}
    for key in sorted(set(p) | required):
        if key not in allowed:
            out.append("unknown protocol key: " + key)
        elif key in required and key not in p:
            out.append("missing protocol key: " + key)
    for section in sorted(INNER):
        if type(p.get(section)) is dict:
            _walk(p[section], INNER[section], section, out)
    return out


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _count(value, low=0):
    return type(value) is int and value >= low


def _text(value):
    return type(value) is str and bool(value.strip())


def _span(value, low=0):
    """[min, max] seconds with low < min <= max."""
    return type(value) is list and len(value) == 2 and all(map(_number, value)) and low < value[0] <= value[1]


def _session_s(p):
    """Length of a session in seconds, None when the grid is malformed (the existing checks refuse it)."""
    cycles, interval = p.get("cycles"), p.get("interval_s")
    return cycles * interval if _count(cycles, 1) and _number(interval) and interval > 0 else None


def _fits(p, n, longest):
    """n items of the longest duration fit between first_s and tail_s with min_gap_s between them."""
    e, length = p["events"], _session_s(p)
    return length is None or e["first_s"] + n * longest + (n - 1) * e["min_gap_s"] + e["tail_s"] <= length


def _ok_roles(p):
    return all(_count(v) for v in p["roles"].values())


def _ok_interleave(p):
    seen = set()
    for names in p["interleave"]:
        if (type(names) is not list or len(names) < 2 or len(set(names)) != len(names)
                or not set(names) <= set(ROLES) or seen & set(names)):
            return False
        seen.update(names)
    return type(p["interleave"]) is list


def _ok_scenarios(p):
    s = p["scenarios"]
    return bool(s) and all(
        _text(name) and type(v) is dict and _text(v["profile"]) and v["intensity"] in ("low", "high")
        and (v["rate"] is None or _number(v["rate"]) and v["rate"] > 0) for name, v in s.items())


def _ok_scenario_rule(p):
    r = p["scenario_rule"]
    low, high = r["peak_share"]["low"], r["peak_share"]["high"]
    return (_number(low) and _number(high) and 0 < low < high <= 1 and _number(r["min_peak_to_mean"])
            and r["min_peak_to_mean"] >= 1 and _text(r["basis"]) and type(r["note"]) is str)


def _between(value, low, high):
    return _number(value) and low <= value <= high


def _bounds(value, low, *, integer=False, below=None):
    """[min, max] with low <= min <= max (ints when integer), and max < below when below is given."""
    kind = (lambda v: type(v) is int) if integer else _number
    return (type(value) is list and len(value) == 2 and all(map(kind, value)) and low <= value[0] <= value[1]
            and (below is None or value[1] < below))


def _arrivals_problems(a, warmup):
    """The envelope family of a profile (scripts/host_traffic.py draw_envelope)."""
    out = []
    if not _number(a["ramp_s"]) or a["ramp_s"] < 0:
        out.append(("arrivals.ramp_s", "not a number >= 0"))
    elif _number(warmup) and a["ramp_s"] > warmup:
        out.append(("arrivals.ramp_s", "longer than warmup_s: the ramp lies in the warmup"))
    for key in ("wave_period_s", "peak_s", "wave_mean"):
        if not _bounds(a[key], 0) or a[key][0] <= 0:
            out.append((f"arrivals.{key}", "not [min, max] with 0 < min <= max"))
    if not _bounds(a["wave_amplitude"], 0, below=1):  # Below 1: the wave stays above level 0.
        out.append(("arrivals.wave_amplitude", "not [min, max] with 0 <= min <= max < 1"))
    elif _bounds(a["wave_mean"], 0) and a["wave_mean"][1] * (1 + a["wave_amplitude"][1]) >= 1:
        out.append(("arrivals.wave_mean", "the slow wave reaches level 1, which only the peak has"))
    if not _number(a["peak_edge_share"]) or not 0 < a["peak_edge_share"] < .5:  # Two flanks inside the peak.
        out.append(("arrivals.peak_edge_share", "not a number in (0, 0.5)"))
    if a["peak_at"] not in PEAK_AT:
        out.append(("arrivals.peak_at", "not one of " + ", ".join(PEAK_AT)))
    if not _number(a["step_s"]) or a["step_s"] <= 0:
        out.append(("arrivals.step_s", "not a number > 0"))
    return out


def _profile_problems(name, q, warmup):
    """(path, what) of every malformed value of one profile."""
    from lab import seed  # DOCUMENT_MAX: the upload cap of lab/services.py (413 above it).
    out = _arrivals_problems(q["arrivals"], warmup)
    if type(q["max_concurrent"]) is not int or q["max_concurrent"] < 1:
        out.append(("max_concurrent", "not an integer >= 1"))
    e = q["client_errors"]
    if not _between(e["share"], *CLIENT_ERROR_SHARE):
        out.append(("client_errors.share", "outside 1 to 3 % (proposal 5.3)"))
    if (type(e["statuses"]) is not list or not e["statuses"] or len(set(map(str, e["statuses"]))) != len(e["statuses"])
            or not all(type(s) is int and s in CLIENT_STATUSES for s in e["statuses"])):
        out.append(("client_errors.statuses", "not distinct statuses of " + ", ".join(map(str, CLIENT_STATUSES))))
    t = q["think_s"]
    if not (_number(t["mean"]) and t["mean"] > 0 and _number(t["max"]) and t["max"] >= t["mean"]):
        out.append(("think_s", "not mean > 0 and max >= mean"))
    if not _number(q["zipf_s"]) or q["zipf_s"] <= 0:
        out.append(("zipf_s", "not a number > 0"))
    if name == "eshop":
        f = q["funnel"]
        if not all(_number(q["order_share"][k]) and 0 < q["order_share"][k] < 1 for k in ("low", "high")):
            out.append(("order_share", "not shares in (0, 1)"))
        for key, low in (("pages", 1), ("details_per_page", 0), ("cart_items", 1)):
            if not _bounds(f[key], low, integer=True):
                out.append((f"funnel.{key}", f"not integers [min, max] with {low} <= min <= max"))
        for key in ("search_share", "static_share"):
            if not _between(f[key], 0, 1):
                out.append((f"funnel.{key}", "not a share in [0, 1]"))
        sizes = [("funnel.page_size", f["page_size"])]
    else:
        s, d = q["shares"], q["document_sizes"]
        if not _bounds(q["actions"], 1, integer=True):
            out.append(("actions", "not integers [min, max] with 1 <= min <= max"))
        if not all(_between(v, 0, 1) for v in s.values()) or abs(sum(s.values()) - 1) > 1e-9:
            out.append(("shares", "not shares in [0, 1] that sum to 1"))
        if not (_number(d["median_bytes"]) and d["median_bytes"] > 0 and _number(d["sigma"]) and d["sigma"] >= 0
                and _between(d["tail_share"], 0, 1) and _number(d["tail_from_bytes"]) and d["tail_from_bytes"] > 0
                and _number(d["tail_alpha"]) and d["tail_alpha"] > 0):
            out.append(("document_sizes", "not a lognormal body (median_bytes, sigma) with a Pareto tail "
                                          "(tail_share, tail_from_bytes, tail_alpha)"))
        if not _bounds([d["min_bytes"], d["max_bytes"]], 1, integer=True) or d["max_bytes"] > seed.DOCUMENT_MAX:
            out.append(("document_sizes", f"not integers 1 <= min_bytes <= max_bytes <= {seed.DOCUMENT_MAX} "
                                          "(the upload cap of lab/services.py)"))
        sizes = [("page_size", q["page_size"])]
    out += [(key, f"not an integer in 1..{MAX_PAGE_SIZE}") for key, value in sizes
            if type(value) is not int or not 1 <= value <= MAX_PAGE_SIZE]
    notes = [q, q["arrivals"], e, t, *([q["funnel"]] if name == "eshop" else [q["document_sizes"]])]
    if not all(type(x["note"]) is str for x in notes):
        out.append(("note", "every note is a string"))
    return out


def profiles_problems(p):
    """The problems of the profiles section as named reasons, [] when it is well formed: its unknown and missing
    keys (the layout's reasons) or else every malformed value (the generator prints the first one; the loader says
    `invalid profiles`, after layout_problems named any key). Every scenario names one of the profiles."""
    profiles = p.get("profiles") if type(p) is dict else None
    if type(profiles) is not dict:
        return ["profiles: not an object"]
    out = []
    _walk(profiles, PROFILE_KEYS, "profiles", out)
    if out:
        return out
    scenarios = p.get("scenarios") if type(p.get("scenarios")) is dict else {}
    out += [f"scenarios.{name}.profile: {s.get('profile')!r} is not a profile of the profiles section"
            for name, s in sorted(scenarios.items()) if type(s) is dict and s.get("profile") not in profiles]
    for name in sorted(set(profiles) & set(PROFILE_KEYS)):  # An unknown profile is the layout's (unknown key).
        try:
            out += [f"profiles.{name}.{path}: {what}"
                    for path, what in _profile_problems(name, profiles[name], p.get("warmup_s"))]
        except (KeyError, TypeError, AttributeError, IndexError) as error:
            out.append(f"profiles.{name}: malformed ({type(error).__name__}: {error})")
    return out


def _ok_profiles(p):
    return not profiles_problems(p)


def _ok_events(p):
    e = p["events"]
    types, per = e["types"], e["per_session"]
    if not (type(types) is dict and types and all(_text(k) and _text(v) for k, v in types.items())):
        return False
    if not (type(per) is list and per and all(map(_count, per)) and per == sorted(set(per))):
        return False
    if not (_span(e["duration_s"]) and all(_number(e[k]) and e[k] >= 0 for k in ("first_s", "min_gap_s", "tail_s",
                                                                                   "grace_s"))):
        return False
    # The grace after an event ends before the next one can start (as schema 2).
    if not e["grace_s"] < e["min_gap_s"] or type(e["note"]) is not str:
        return False
    minimum = e["min_per_type"]  # Every role with events is named: an absent role would silently have no minimum.
    if not (type(minimum) is dict and set(minimum) == set(ROLES) - {CONTROL_ROLE} and all(map(_count,
                                                                                            minimum.values()))):
        return False
    return not max(per) or _fits(p, max(per), e["duration_s"][1])


def _ok_guard(p):
    g = p["full_snapshot_guard"]
    return _number(g["before_s"]) and g["before_s"] >= 0 and type(g["note"]) is str


def _positive(value):
    return _number(value) and value > 0


def _positive_int(value):
    return type(value) is int and value > 0


def _distinct(values, ok):
    """A non-empty list of distinct values that each pass ok()."""
    return type(values) is list and bool(values) and all(map(ok, values)) and len(set(map(str, values))) == len(values)


def _band(value):
    """[low, high] of finite numbers with low <= high."""
    return type(value) is list and len(value) == 2 and all(map(_number, value)) and value[0] <= value[1]


def _ok_kind(c, kind, k):
    """One kind of controls.kinds (design B8 1.1). Class A: no doses and no counts per dose (null), one positive
    expected shift per column. Class B: distinct positive integer doses (the guest's --dose), as many positive
    integer counts per dose summing to per_kind, which negatives_per_kind equals (each dose has its count among the
    kind's controls and the same among its negatives), and per column one positive shift or one per dose in the
    order of doses. Every kind: distinct columns of features.snapshot.MENA other than the row flags, an expectation
    {shift, direction} for exactly its columns, a note; the module kind distinct module names as its candidates."""
    from features.snapshot import MENA  # Here: the generator imports this module and needs no feature code.
    columns, doses, per, expect = k["columns"], k["doses"], k["per_dose"], k["expect"]
    if k["class"] not in ("A", "B") or type(k["note"]) is not str:
        return False
    if not _distinct(columns, lambda name: type(name) is str and name in MENA and name not in ROW_FLAGS):
        return False
    if k["class"] == "A" and (doses is not None or per is not None):
        return False
    if k["class"] == "B" and not (_distinct(doses, _positive_int) and type(per) is list and len(per) == len(doses)
                                  and all(map(_positive_int, per))
                                  and sum(per) == c["per_kind"] == c["negatives_per_kind"]):
        return False
    per_dose = len(doses) if k["class"] == "B" else None  # A shift per dose, in the order of doses (class B only).
    if not (type(expect) is dict and set(expect) == set(columns) and all(
            type(e) is dict and e["direction"] in DIRECTIONS
            and (_positive(e["shift"]) or type(e["shift"]) is list and len(e["shift"]) == per_dose
                 and all(map(_positive, e["shift"]))) for e in expect.values())):
        return False
    return kind != MODULE_KIND or _distinct(k["candidates"], lambda name: type(name) is str
                                            and re.fullmatch(MODULE_NAME, name) is not None)


def _ok_controls(p):
    c = p["controls"]
    if not (_count(c["per_kind"]) and _count(c["negatives_per_kind"]) and _count(c["slots_per_session"])
            and _number(c["min_duration_s"]) and c["min_duration_s"] > 0 and _span(c["duration_s"])
            and c["duration_s"][0] >= c["min_duration_s"] and _number(c["horizon_s"]) and c["horizon_s"] > 0
            and type(c["note"]) is str):
        return False
    if not (type(c["kinds"]) is dict and c["kinds"] and all(
            _text(kind) and type(v) is dict and _ok_kind(c, kind, v) for kind, v in c["kinds"].items())):
        return False
    # The tolerance of the level part of the return predicate: null until G2, then a band per quantity.
    baseline = c["baseline"]
    if not (baseline is None or type(baseline) is dict and set(baseline) == set(BASELINE_PARTS)
            and all(map(_band, baseline.values()))):
        return False
    slots = c["slots_per_session"]
    return not (p["roles"][CONTROL_ROLE] and slots) or _fits(p, slots, c["duration_s"][1])


def _ok_streams(p):
    s = p["streams"]
    purposes = s["purposes"]
    return (type(purposes) is list and all(map(_text, purposes)) and len(set(purposes)) == len(purposes)
            and set(purposes) == set(PURPOSES) and _text(s["rule"]) and type(s["note"]) is str)


def _ok_seeded_level(p):
    """streams.seeded_level (the fix of package B9a): the seed is an integer of 0 to RESET_SEED_BOUND - 1, which
    lab/guest_state.py reset --seed takes (1 to 18 digits), and the note is a string."""
    level = p["streams"]["seeded_level"]
    return (type(level["seed"]) is int and 0 <= level["seed"] < RESET_SEED_BOUND
            and type(level["note"]) is str)


def _receptive_field(kernel, blocks):
    """The receptive field of the TCN in rows (tcn/model.py recepcne_pole): two convolutions per block, dilations 1,
    2, ..., 2^(blocks - 1)."""
    return 1 + 2 * (kernel - 1) * (2 ** blocks - 1)


def _ok_architecture(p, arch):
    """The TCN of analysis.architecture can be built on the collection window: the bounds of
    safeguard/model.py validate_architecture (channels, kernel and blocks integers in [1, 1024], kernel at most 15,
    blocks at most 12, dropout in [0, 1), a receptive field of at least window_rows), weight normalization on or
    off, and positive learning rate, clipping norms and batch size."""
    if not all(type(arch[key]) is int and 1 <= arch[key] <= 1024 for key in ("kernel", "blocks", "channels")):
        return False
    return (_text(arch["model"]) and _count(arch["window_rows"], 1) and arch["window_rows"] == p["window_rows"]
            and arch["kernel"] <= 15 and arch["blocks"] <= 12
            and _receptive_field(arch["kernel"], arch["blocks"]) >= arch["window_rows"]
            and _number(arch["dropout"]) and 0 <= arch["dropout"] < 1 and type(arch["weight_norm"]) is bool
            and all(_positive(arch[key]) for key in ("learning_rate", "gradient_clip", "classifier_gradient_clip"))
            and _positive_int(arch["batch_size"]) and type(arch["note"]) is str)


def _floors(value, names):
    """An object with exactly `names` as keys, each a positive number."""
    return type(value) is dict and set(value) == set(names) and all(map(_positive, value.values()))


def _ok_qualification(a):
    """Design B6a 1.1: the bounds of the qualification (G0), the scale rule (G0) and the classes of the columns
    (null until G3a; a differenced column is a level column, and so is a rule_differenced one, which the rule channel
    judges by its change since the session's first measured row: question Q8, its revised proposal accepted by the
    lead 2026-11-24, package B6b)."""
    from features.archive import BEHAVIOR_NAMES  # Here: the generator imports this module and needs no feature code.
    from features.qualification import CLASSES, LOCAL_SCALED
    q, s, columns = a["qualification"], a["scale"], a["columns"]
    levels = q["level_columns"]
    if not (_number(q["near_constant_share"]) and 0 < q["near_constant_share"] < 1
            and _number(q["identity_auc"]) and .5 < q["identity_auc"] < 1
            and _number(q["duplicate_tolerance"]) and 0 < q["duplicate_tolerance"] < 1
            and type(levels) is list and all(name in BEHAVIOR_NAMES for name in levels)
            and len(set(levels)) == len(levels) and type(q["note"]) is str):
        return False
    if not (type(s["per_bin"]) is bool and _positive_int(s["min_bin_pages"]) and _floors(s["floor"], BEHAVIOR_NAMES)
            and _floors(s["local_floor"], LOCAL_SCALED) and type(s["note"]) is str):
        return False
    return columns is None or (type(columns) is dict and set(columns) == set(BEHAVIOR_NAMES) and all(
        type(cls) is str and cls in CLASSES and (cls not in ("differenced", "rule_differenced") or name in levels)
        for name, cls in columns.items()))


def grid_value_ok(name, value, window_rows):
    """Whether `value` lies in the domain of the grid parameter `name` (GRID_DOMAINS) under the protocol's
    window_rows: an integer where the domain says so, else a finite number (no bool), within its bounds. window_rows
    None leaves the bound window_rows unchecked, for the candidate of tcn/metody.py Z1 built before its window is known
    (its fit checks it against the window of train)."""
    domain = GRID_DOMAINS[name]
    if not _number(value) or (domain["integer"] and type(value) is not int):
        return False
    low, high = domain["low"], domain["high"]
    if high == "window_rows":
        high = window_rows
    return ((value >= low if domain["low_allowed"] else value > low)
            and (high is None or (value <= high if domain["high_allowed"] else value < high)))


def grid_problem(method, value, window_rows):
    """The problem of a filled grid of `method` (a method of GRID_PARAMETERS) under the protocol's window_rows, as a
    text, or None: exactly the parameters of GRID_PARAMETERS, each a non-empty list of distinct values (by value, so 1
    and 1.0 are one value) of its domain (GRID_DOMAINS). tcn/metody.py grid() raises the text; the value check of
    analysis.methods refuses a grid with a problem (F3 of the verification of B7a: one domain for both)."""
    path = f"analysis.methods.{method}.grid"
    names = GRID_PARAMETERS[method]
    if type(value) is not dict or set(value) != set(names):
        return f"{path} must be an object of exactly the keys {', '.join(names)}"
    for name in names:
        items = value[name]
        if (type(items) is not list or not items or not all(grid_value_ok(name, x, window_rows) for x in items)
                or len(set(items)) != len(items)):
            return f"{path}.{name} must be a non-empty list of distinct {GRID_DOMAINS[name]['text']}"
    return None


def _ok_methods(p):
    """Skeleton B7 section 2 (design B7a 1.4 and 1.6): every method of METHODS states what it is; a method of GRIDDED
    has a grid of its free parameters, null until G3a (determined_at), and filled it holds exactly the parameters of
    GRID_PARAMETERS, each within its domain (grid_problem, under the protocol's window_rows); every other one has
    none: {} from G0 on."""
    return all(type(m) is dict and _text(m["what"]) and (
        (m["grid"] is None or grid_problem(name, m["grid"], p["window_rows"]) is None) if name in GRIDDED
        else (type(m["grid"]) is dict and not m["grid"])) for name, m in p["analysis"]["methods"].items())


def _names_every_method(text):
    """analysis.selection states the rule of every method: a text that names each of METHODS as a word (skeleton B7
    section 2: Z1 by the interventions detected in dev, Z3 and Z5 by the loss on dev, M as B6, Z0, Z2 and Z4 without
    a free parameter)."""
    return _text(text) and all(re.search(rf"\b{name}\b", text) for name in METHODS)


def _ok_descriptive(a):
    """Design B7a 1.6 (skeleton B7, addendum 2 point 1): each descriptive method states what it is, its seeds and a
    note. A method of UNSEEDED draws nothing and has the seeds null; every other one has a non-empty list of distinct
    seeds of analysis.seeds (an empty list is refused: it would never run); GRU and LSTM run on every seed of
    analysis.seeds."""
    seeds = a["seeds"]
    for name, d in a["descriptive_methods"].items():
        if not (type(d) is dict and _text(d["what"]) and type(d["note"]) is str):
            return False
        mine = d["seeds"]
        if name in UNSEEDED:
            if mine is not None:
                return False
            continue
        if not (type(mine) is list and mine and all(type(s) is int and s in seeds for s in mine)
                and len(set(mine)) == len(mine)):
            return False
        if name in EVERY_SEED and sorted(mine) != sorted(seeds):
            return False
    return True


def _ok_claims_b7a(a):
    """Design B7a 1.6: the wording of every claim and outcome is a text with the blanks of chapter 8.4 (BLANKS); the
    matched alarm rate states its budget and the repetitions of Z0; the statistics state the bootstrap resamples, the
    most boots of the full enumeration of the test (at most MAX_EXACT_BOOTS) and the level of the interval."""
    if not all(type(w) is dict and all(_text(w[outcome]) and w[outcome].count(BLANK) == BLANKS[outcome]
                                       for outcome in OUTCOMES) for w in a["wording"].values()):
        return False
    rate, s = a["matched_rate"], a["statistics"]
    return (_text(rate["budget"]) and _count(rate["z0_repetitions"], 1) and type(rate["note"]) is str
            and _count(s["bootstrap"], 1) and _count(s["exact_up_to_boots"], 1)
            and s["exact_up_to_boots"] <= MAX_EXACT_BOOTS and _number(s["level"]) and 0 < s["level"] < 1
            and type(s["note"]) is str)


def _ok_interventions(p):
    """Design B7b 1.4 (the lead's skeleton B7 section 5, proposal 6.4 and 7.4): each class has its lengths, distinct
    and of at least MIN_BLOCK_ROWS rows (as tcn/zasahy.py refuses others, merge of B7b), and its count per boot; C names
    its orders (of ORDERS); D names its groups, which partition the inputs of the neural
    channel (the 20 columns of features.archive.BEHAVIOR_NAMES and the four channels of a bin, features/windows.py
    BIN_PRIZNAKY, which lie in one group); the validity predicate has the quantiles 0 < low < high < 1 of role train
    and a moving average of at least 2 rows and at most window_rows (tcn/zasahy.py takes the average of the last rows
    of a window of train: F2 of the verification of B7b; scripts/tests/boundary_sessions.py v5_sections scales it to
    the window of a test protocol); the evaluable minimum is analysis.min_occurrences (proposal 6.4 states one rule
    for a type or a class); the volume class is a text and the note a string."""
    # Here: the generator imports this module and needs no feature code.
    from features.archive import BEHAVIOR_NAMES
    from features.windows import BIN_PRIZNAKY
    a = p["analysis"]
    i = a["interventions"]
    for name in INTERVENTION_CLASSES:
        if not (_distinct(i[name]["lengths"], lambda n: _count(n, MIN_BLOCK_ROWS[name]))
                and _count(i[name]["per_boot"], 1)):
            return False
    inputs = set(BEHAVIOR_NAMES) | set(BIN_PRIZNAKY)
    groups = i["D"]["groups"]
    if not (_distinct(i["C"]["orders"], lambda order: order in ORDERS) and type(groups) is dict and groups
            and all(_text(name) and _distinct(columns, lambda column: column in inputs)
                    for name, columns in groups.items())):
        return False
    every = [column for columns in groups.values() for column in columns]
    if sorted(every) != sorted(inputs) or not any(set(BIN_PRIZNAKY) <= set(columns) for columns in groups.values()):
        return False
    v = i["validity"]
    q, rows = v["quantiles"], v["moving_average_rows"]
    return (type(q) is list and len(q) == 2 and all(map(_number, q)) and 0 < q[0] < q[1] < 1
            and _count(rows, 2) and rows <= p["window_rows"] and type(v["note"]) is str
            and _count(i["min_evaluable"], 1) and i["min_evaluable"] == a["min_occurrences"]
            and _count(i["boots"], 1) and _text(i["volume_class"]) and type(i["note"]) is str)


def _ok_diagnostics(p):
    """Design B7b 1.4 (proposal 8.5, the lead's skeleton B7 section 6): the depth of the tree and the fewest positive
    episodes are integers of at least 1; the contexts are increasing integers from 1 to window_rows - 1 (a window holds
    its target and at most window_rows - 1 rows of context, as tcn/diagnostiky.py truncates it: F2 of the verification
    of B7b; scripts/tests/boundary_sessions.py v5_sections scales them to the window of a test protocol); the alarm
    rules are distinct pairs [k, n] with 1 <= k <= n, the rule of analysis.alarm_rule among them (the sensitivity is
    told around it)."""
    a = p["analysis"]
    d, main = a["diagnostics"], a["alarm_rule"]
    contexts, rules = d["contexts"], d["alarm_rules"]
    return (_count(d["tree_depth"], 1) and _count(d["min_positive_episodes"], 1)
            and type(contexts) is list and bool(contexts)
            and all(_count(c, 1) and c <= p["window_rows"] - 1 for c in contexts)
            and contexts == sorted(set(contexts))
            and type(rules) is list and bool(rules) and all(
                type(r) is list and len(r) == 2 and _count(r[0], 1) and _count(r[1], 1) and r[0] <= r[1]
                for r in rules)
            and len({tuple(r) for r in rules}) == len(rules) and [main["k"], main["n"]] in rules
            and type(d["note"]) is str)


def metrics_problem(value):
    """The problem of analysis.metrics (design B7c 1.2) as a text, or None: exactly the keys of the layout; each metric
    of METRIC_METHODS names its one method and a source (a text); the levels of LEVELLED and the alpha of the test of
    the events are shares in (0, 1); the dispersion compares the sessions (DISPERSION_UNIT), the test of the events is
    one-sided towards more alarms during events (EVENT_ALTERNATIVE), the classifier names exactly the measures over
    windows CLASSIFIER_WINDOWS and the majorities CLASSIFIER_MAJORITY; the note is a string. The value check of the
    analysis section and tcn/eval.py (which reads the numbers) both use it."""
    path = "analysis.metrics"
    if type(value) is not dict or set(value) != set(_METRIC) | {"note"}:
        return f"{path} must be an object of exactly the keys {', '.join(sorted([*_METRIC, 'note']))}"
    for name, inner in _METRIC.items():
        if type(value[name]) is not dict or set(value[name]) != set(inner):
            return f"{path}.{name} must be an object of exactly the keys {', '.join(sorted(inner))}"
        if not _text(value[name]["source"]):
            return f"{path}.{name}.source must name the source of the metric (a text)"
    for name, method in METRIC_METHODS.items():
        if value[name]["method"] != method:
            return f"{path}.{name}.method must be {method}, the method tcn/eval.py implements"
    for name, key in [(name, "level") for name in LEVELLED] + [("event_vs_clean", "alpha")]:
        if not (_number(value[name][key]) and 0 < value[name][key] < 1):
            return f"{path}.{name}.{key} must be a number in (0, 1)"
    if value["dispersion"]["unit"] != DISPERSION_UNIT:
        return f"{path}.dispersion.unit must be {DISPERSION_UNIT}: the thesis compares the alarm counts of sessions"
    if value["event_vs_clean"]["alternative"] != EVENT_ALTERNATIVE:
        return (f"{path}.event_vs_clean.alternative must be {EVENT_ALTERNATIVE}: the thesis' test is one-sided, more "
                "alarms during events than in clean traffic")
    for key, names in (("windows", CLASSIFIER_WINDOWS), ("majority", CLASSIFIER_MAJORITY)):
        if value["classifier"][key] != list(names):
            return f"{path}.classifier.{key} must be {json.dumps(list(names))}"
    if type(value["note"]) is not str:
        return f"{path}.note must be a string"
    return None


def _ok_linkage(a):
    """Design B7c 1.2: every research question of LINKAGE maps to a text, and the note is a string (the self-check
    compares the texts with LINKAGE word for word, check_analysis)."""
    linkage = a["linkage"]
    return all(_text(linkage[question]) for question in LINKAGE) and type(linkage["note"]) is str


def attachments_problem(value):
    """The problem of analysis.attachments (package B11, the lead's answers to questions Q17 and Q28) as a text, or
    None: exactly the attachments of ATTACHMENTS and a note, each attachment stating what it holds (a text) and the
    note a string. The loader (through the value check of the analysis section), the self-check and tcn/finalne.py,
    which writes exactly these attachments and refuses a protocol with another list before the seal, use it."""
    path = "analysis.attachments"
    keys = [*ATTACHMENTS, "note"]
    if type(value) is not dict or set(value) != set(keys):
        found = sorted(value) if type(value) is dict else value
        return (f"{path} must be an object of exactly the keys {', '.join(sorted(keys))} (the attachments of the final "
                f"record are listed in advance: ATTACHMENTS), not {json.dumps(found, ensure_ascii=False)}")
    for name in ATTACHMENTS:
        if not _text(value[name]):
            return f"{path}.{name} must state what the attachment holds (a text)"
    if type(value["note"]) is not str:
        return f"{path}.note must be a string"
    return None


def _ok_analysis(p):
    a = p["analysis"]
    arch, stop, rule = a["architecture"], a["stopping"], a["alarm_rule"]
    seeds = a["seeds"]
    if not _ok_architecture(p, arch):
        return False
    if not (_text(stop["rule"]) and _count(stop["patience_epochs"], 1) and _count(stop["max_epochs"], 1)
            and _text(stop["repeat_if_last_epoch"]) and type(stop["note"]) is str):
        return False
    if not (type(seeds) is list and seeds and all(map(_count, seeds)) and len(set(seeds)) == len(seeds)
            and _count(a["deploy_seed"]) and a["deploy_seed"] in seeds):
        return False
    if not (_number(a["fpr"]) and 0 < a["fpr"] < 1 and _count(rule["k"], 1) and _count(rule["n"], 1)
            and rule["k"] <= rule["n"]):
        return False
    if not (_ok_methods(p) and _ok_descriptive(a) and _ok_claims_b7a(a)):
        return False
    if not (_names_every_method(a["selection"]) and _ok_qualification(a)):
        return False
    for name in ("k1", "k2a", "k2b"):
        t = a[name]
        compare = t["compare"]
        # A comparison names a method of METHODS but M, a method with variants by one of them (COMPARISONS, Q13).
        if not (_text(t["statistic"]) and type(compare) is list and compare and all(type(c) is str for c in compare)
                and len(set(compare)) == len(compare) and set(compare) <= set(COMPARISONS)
                and (t["m"] is None or _number(t["m"])) and _text(t["rule"])):
            return False
    if not (_ok_interventions(p) and _ok_diagnostics(p)):
        return False
    if metrics_problem(a["metrics"]) is not None or not _ok_linkage(a):
        return False
    if attachments_problem(a["attachments"]) is not None:  # Package B11 (Q17, Q28).
        return False
    ev = a["evaluable"]
    # The first seconds that make an occurrence evaluable lie within the horizon (merge of B7b: tcn/zasahy.py places
    # an intervention with every window of its horizon, so its first first_s seconds are scored).
    return (all(_number(a[k]) and a[k] > 0 for k in ("horizon_s", "reverberation_s")) and _number(ev["first_s"])
            and 0 < ev["first_s"] <= a["horizon_s"] and _number(ev["scored_share"]) and 0 < ev["scored_share"] <= 1
            and _count(a["min_occurrences"], 1) and type(a["note"]) is str)


def _ok_rehearsal(p):
    r = p["rehearsal"]
    return (type(r["name_suffix"]) is str and type(r["group_prefix"]) is str and _count(r["groups_per_role"], 1)
            and type(r["note"]) is str)


def expand(doc, pattern):
    """[(dotted path, value)] of every existing key the pattern names; `*` takes every key of an object."""
    found = [("", doc)]
    for part in pattern.split("."):
        step = []
        for path, value in found:
            if type(value) is not dict:
                continue
            keys = sorted(value) if part == "*" else [part] if part in value else []
            step += [(f"{path}.{key}" if path else key, value[key]) for key in keys]
        found = step
    return found


def _ok_determined(p):
    """Every path names an existing key and belongs to one stage only, and scripts/gates.py can bind the file with
    it: gates.later_paths() refuses a determined_at under which a stage record would stop binding a value of its own
    or an earlier stage, so a file that loads is never refused when a stage is recorded (lead's remarks on B4,
    part 1, section 1). Its refusal is raised as `invalid determined_at: <its reason>`."""
    from scripts import gates  # Inside the function: gates imports scripts.collection, which imports this module.
    seen = set()
    for paths in p["determined_at"].values():
        if type(paths) is not list or not all(map(_text, paths)):
            return False
        for pattern in paths:
            found = [path for path, _ in expand(p, pattern)]
            if not found or seen & set(found):
                return False  # A path names at least one existing key and belongs to one stage only.
            seen.update(found)
    try:
        gates.later_paths(p["determined_at"], "G0")
    except ValueError as error:
        raise ValueError("invalid determined_at: " + str(error)) from None
    return True


VALUE_CHECKS = (
    ("name", lambda p: _text(p["name"])), ("group_prefix", lambda p: type(p["group_prefix"]) is str),
    ("group_sessions", lambda p: _count(p["group_sessions"], 1)), ("roles", _ok_roles),
    ("interleave", _ok_interleave), ("scenarios", _ok_scenarios), ("profiles", _ok_profiles),
    ("scenario_rule", _ok_scenario_rule), ("events", _ok_events), ("full_snapshot_guard", _ok_guard),
    ("controls", _ok_controls), ("streams", _ok_streams), ("streams.seeded_level", _ok_seeded_level),
    ("analysis", _ok_analysis), ("rehearsal", _ok_rehearsal), ("determined_at", _ok_determined))


def check_layout(p):
    """The loader's v5 checks: the first unknown or missing key, then the first malformed v5 section.

    ValueError `unknown protocol key: <path>`, `missing protocol key: <path>` or `invalid <section>`; a determined_at
    that scripts/gates.py could not bind gives `invalid determined_at: <the reason of gates.later_paths>`.
    """
    problems = layout_problems(p)
    if problems:
        raise ValueError(problems[0])
    for section, ok in VALUE_CHECKS:
        try:
            good = ok(p)
        except (KeyError, TypeError, AttributeError, IndexError):
            good = False
        if not good:
            raise ValueError("invalid " + section)


def plans_events(p):
    """Whether the protocol plans events in its sessions: any events section under schema 1 and 2; under schema 3,
    where every protocol has one, only when per_session allows more than 0. The log audit and the corpus build ask
    it: a session of such a protocol lists its events in session.json and keeps events.json."""
    if type(p) is not dict:
        return False
    if p.get("schema") != SCHEMA:
        return "events" in p
    e = p.get("events")
    return type(e) is dict and type(e.get("per_session")) is list and any(_count(n, 1) for n in e["per_session"])


def analysis_plan(p):
    """The analysis plan of a schema-3 protocol (proposal 10.1 point 3), checked as the loader checks it."""
    if type(p) is not dict or p.get("schema") != SCHEMA:
        raise ValueError("the analysis plan requires protocol schema 3")
    missing = []
    _walk(p.get("analysis") if type(p.get("analysis")) is dict else {}, ANALYSIS, "analysis", missing)
    if missing:
        raise ValueError(missing[0])
    try:
        good = _ok_analysis(p)
    except (KeyError, TypeError, AttributeError, IndexError):
        good = False
    if not good:
        raise ValueError("invalid analysis")
    return p["analysis"]


def _analysis_seed(name, purpose, unit):
    """The seed of the analysis stream `purpose` for `unit` under the plan name `name` (streams.rule)."""
    return seed(name, purpose, unit, -1, 0)


def analysis_units(p):
    """{purpose: [its units]} of the streams of the analysis (design B7a 1.6, B7b 1.4): z0_alarms per role of the
    protocol, bootstrap per comparison "<claim>/<method>" of a confirmatory claim with each method it compares (CLAIMS
    and analysis.<claim>.compare of the checked analysis plan, for example "k1/Z3" or "k2a/Z4:load"), injections per
    carrier role and class and once for the insertion into dev (INJECTION_UNITS, for example "test_benign/C")."""
    a = analysis_plan(p)
    return {"z0_alarms": list(ROLES), "bootstrap": [f"{claim}/{method}" for claim in CLAIMS
                                                    for method in a[claim]["compare"]],
            "injections": list(INJECTION_UNITS)}


def analysis_seed(p, purpose, unit, *, mode):
    """The seed of a stream of the analysis (package B7a, design B7a 1.6; streams.rule): seed(name, purpose, unit, -1,
    0) with the plan's name in this mode (the rehearsal's own name in rehearsal mode, as the plan), from which the
    analysis draws with numpy.random.default_rng. z0_alarms is drawn per role (unit: a role of ROLES), the random alarms
    of Z0 at the matched alarm rate on that role's windows; bootstrap per comparison of a confirmatory claim (unit
    "<claim>/<method>", analysis_units), the resamples of its interval and then, above
    analysis.statistics.exact_up_to_boots boots, the sign vectors of its test; injections (package B7b) per carrier
    role and class "<role>/<class>" and once for the interventions inserted into dev ("dev"), the placements of the
    interventions in the order the code that inserts them states. The plan draws none of them (check_streams). The
    mode has no default. ValueError for another schema, an unknown mode, purpose or unit."""
    if purpose not in ANALYSIS_PURPOSES:
        raise ValueError(f"{purpose!r} is no stream of the analysis ({', '.join(ANALYSIS_PURPOSES)})")
    units = analysis_units(p)[purpose]
    if mode not in MODES:
        raise ValueError("unknown plan mode: " + str(mode))
    if unit not in units:
        raise ValueError(f"{unit!r} is no unit of the analysis stream {purpose} ({', '.join(units)})")
    return _analysis_seed(_shape(p, mode)[0], purpose, unit)


# ------------------------------------------------------------------ the schedule

def seed(name, purpose, group, session, attempt):
    """The seed of one random stream: sha256 of the protocol name, group, session, attempt and purpose."""
    return int(hashlib.sha256(json.dumps([name, group, session, attempt, purpose]).encode()).hexdigest()[:16], 16)


def _session_seeds(name, group, position, attempt):
    """The seeds of the session-level purposes of one attempt of a planned session (event_times and the traffic)."""
    return {purpose: seed(name, purpose, group, position, attempt) for purpose in SESSION_PURPOSES}


def _shape(p, mode):
    """(name, group prefix, groups per role) of the plan in this mode."""
    if mode == "campaign":
        return p["name"], p["group_prefix"], dict(p["roles"])
    if mode == "rehearsal":
        r = p["rehearsal"]
        return p["name"] + r["name_suffix"], r["group_prefix"], dict.fromkeys(p["roles"], r["groups_per_role"])
    raise ValueError("unknown plan mode: " + str(mode))


def _ms(seconds):
    return round(seconds * 1000)


def guards(p):
    """[(T, start, end)] in ms: no item starts in [T - before_s, T + window_rows * interval_s) of a full snapshot
    at T (proposal 5.5: up to the first scored row after it)."""
    interval, before = _ms(p["interval_s"]), _ms(p["full_snapshot_guard"]["before_s"])
    return [(r * interval, r * interval - before, (r + p["window_rows"]) * interval)
            for r in range(0, p["cycles"], p["full_every"])]


def _ceil_div(a, b):
    return -(-a // b)


def tenth(phase_ms, interval_ms):
    """The tenth of the interval (0 to TENTHS - 1) in which a phase of phase_ms (0 <= phase_ms < interval_ms) lies."""
    return phase_ms * TENTHS // interval_ms


def _phase(d, interval, rng):
    """A phase in ms, uniform on the 1 ms grid within tenth d of the interval."""
    return rng.randint(_ceil_div(d * interval, TENTHS), _ceil_div((d + 1) * interval, TENTHS) - 1)


def _times(p, spans, tenths, rng):
    """[(start, duration)] in ms for items with the given [min, max] durations, in order, whose starts and stops lie
    in the given (start tenth, stop tenth) of the collection interval (design B4b, the lead's must_fix 6 on B4).

    The phase of every start and stop is uniform within its tenth (1 ms grid). Then whole intervals: the number of
    intervals of each duration is uniform among those that keep it within its span, and the free intervals of the
    session are split over the n + 1 gaps by uniform spacings (before the first item, between items, after the
    last). first_s, min_gap_s, tail_s and the spans hold exactly at these phases, so no time is shifted after the
    draw. A draw with a start inside a guard is drawn again, at most MAX_DRAWS times.
    """
    if not spans:
        return []
    e, interval = p["events"], _ms(p["interval_s"])
    first, gap, tail = _ms(e["first_s"]), _ms(e["min_gap_s"]), _ms(e["tail_s"])
    length, bands = _ms(p["cycles"] * p["interval_s"]), guards(p)
    for _ in range(MAX_DRAWS):
        phases = [(_phase(start, interval, rng), _phase(stop, interval, rng)) for start, stop in tenths]
        counts = []  # Whole intervals of each duration: low <= count * interval + stop phase - start phase <= high.
        for (low, high), (start, stop) in zip(spans, phases):
            fewest, most = _ceil_div(_ms(low) - (stop - start), interval), (_ms(high) - (stop - start)) // interval
            if fewest > most:
                raise ValueError("an item cannot last within its duration span at the phases of its tenths")
            counts.append(rng.randint(fewest, most))
        # The earliest interval of each start: first_s before the first one, min_gap_s after the end of the one
        # before; the latest interval of the last stop leaves tail_s to the end of the session.
        earliest = [_ceil_div(first - phases[0][0], interval)]
        for i in range(1, len(spans)):
            earliest.append(earliest[-1] + counts[i - 1]
                            + _ceil_div(phases[i - 1][1] + gap - phases[i][0], interval))
        free = (length - tail - phases[-1][1]) // interval - earliest[-1] - counts[-1]
        if free < 0:
            raise ValueError("event schedule does not fit the session")
        offsets = sorted(rng.randint(0, free) for _ in spans)
        starts = [(earliest[i] + offsets[i]) * interval + phases[i][0] for i in range(len(spans))]
        durations = [counts[i] * interval + phases[i][1] - phases[i][0] for i in range(len(spans))]
        if not any(low <= start < high for start in starts for _, low, high in bands):
            return list(zip(starts, durations))
    raise ValueError(f"no schedule outside the full-snapshot guards in {MAX_DRAWS} draws")


def _timing(p, start, duration):
    interval = _ms(p["interval_s"])
    return {"start_s": start / 1000, "duration_s": duration / 1000, "start_phase_s": start % interval / 1000,
            "stop_phase_s": (start + duration) % interval / 1000}


def _items(p, role, labels, tenths, rng):
    """The timed events (labels: types) or controls (labels: (kind, polarity, dose) or None) of one session attempt;
    tenths holds the (start tenth, stop tenth) of every label that is not None, in order. A control states its kind,
    polarity, the kind's class (A or B) and its dose (null for class A; design B8 1.2)."""
    if role != CONTROL_ROLE:
        times = _times(p, [tuple(p["events"]["duration_s"])] * len(labels), tenths, rng)
        return [{"type": t, "class": p["events"]["types"][t], **_timing(p, *when)} for t, when in zip(labels, times)]
    kinds = p["controls"]["kinds"]
    times = iter(_times(p, [tuple(p["controls"]["duration_s"])] * sum(x is not None for x in labels), tenths, rng))
    return [{"kind": None, "reason": "deck exhausted"} if x is None else
            {"kind": x[0], "polarity": x[1], "class": kinds[x[0]]["class"], "dose": x[2], **_timing(p, *next(times))}
            for x in labels]


def item_tenths(p, item):
    """(start tenth, stop tenth) of a planned event or control, from its start_s and duration_s."""
    interval, start = _ms(p["interval_s"]), _ms(item["start_s"])
    return tenth(start % interval, interval), tenth((start + _ms(item["duration_s"])) % interval, interval)


def _rounds(rng, cards, rounds):
    """Shuffled full rounds of the cards: every prefix of the deck holds each card as evenly as possible."""
    deck = []
    for t in range(rounds):
        cards_t = [card for card, count in cards if t < count]
        deck += rng.sample(cards_t, len(cards_t))
    return deck


def _draw_blocks(groups, role, k, g, rngs, names, name):
    """Scenario rows of the groups of one role: blocks of k groups, the group at block position j holds the rows
    (j, ..., j + g - 1) mod k; the block's stream names the rows by scenario and orders its groups. A last,
    incomplete block takes the first groups of such a block. `rngs` keeps each block's stream across redraws."""
    for b, start in enumerate(range(0, len(groups), k)):
        if (role, b) not in rngs:
            rngs[role, b] = random.Random(seed(name, "scenario_order", f"{role}/{b + 1}", -1, 0))
        rng = rngs[role, b]
        rows, positions = rng.sample(names, k), rng.sample(range(k), k)
        for t, group in enumerate(groups[start:start + k]):
            group.update(block=b + 1, scenarios=[rows[(positions[t] + i) % k] for i in range(g)])


def _spread(counts, names):
    return max(counts[n] for n in names) - min(counts[n] for n in names)


def _representatives(members, rng, role):
    """{group: position}: one session of every group of a block, the scenarios of the chosen sessions distinct (a
    uniform system of distinct representatives, drawn by rejection at most MAX_DRAWS times)."""
    names = sorted({name for group in members for name in group["scenarios"]})
    for _ in range(MAX_DRAWS):
        picked = rng.sample(names, len(members))
        if all(name in group["scenarios"] for name, group in zip(picked, members)):
            return {group["group"]: group["scenarios"].index(name) for name, group in zip(picked, members)}
    raise ValueError(f"no event-free sessions with distinct scenarios in a block of role {role} "
                     f"after {MAX_DRAWS} draws")


def _event_free(groups, g, rng, role):
    """{group: position of its event-free session} (the lead's must_fix 5 on B4). In every block the event-free
    sessions hold distinct scenarios, so a complete block holds each scenario once and the counts per scenario in
    the role differ by at most 1 by construction; all blocks are drawn again until the counts per position in the
    role differ by at most 1 too, at most MAX_DRAWS times."""
    blocks = {}
    for group in groups:
        blocks.setdefault(group["block"], []).append(group)
    for _ in range(MAX_DRAWS):
        chosen = {}
        for b in sorted(blocks):
            chosen.update(_representatives(blocks[b], rng, role))
        if _spread(Counter(chosen.values()), range(g)) <= 1:
            return chosen
    raise ValueError(f"event-free sessions of role {role}: positions differ by more than 1 after {MAX_DRAWS} draws")


def _orient(edges, rng):
    """{edge: True when it is walked from its first end to its second}: a random orientation of the multigraph of
    `edges` ({edge: (end, end)}) under which as many edges enter every vertex as leave it, give or take 1 at a vertex
    of odd degree. The vertices of odd degree are joined to one extra vertex (None), which makes every degree even;
    then every component is walked along an Euler circuit (Hierholzer), whose start vertices and turns the stream
    draws. Every closed walk enters a vertex as often as it leaves it."""
    ends = {}
    for edge, (u, v) in edges.items():
        ends.setdefault(u, []).append((v, edge))
        ends.setdefault(v, []).append((u, edge))
    vertices = sorted(ends)
    odd = [x for x in vertices if len(ends[x]) % 2]
    for i, x in enumerate(odd):
        ends[x].append((None, ("extra", i)))
        ends.setdefault(None, []).append((x, ("extra", i)))
    vertices += [None] if odd else []
    for x in vertices:
        ends[x] = rng.sample(ends[x], len(ends[x]))
    tail, used = {}, set()
    for start in rng.sample(vertices, len(vertices)):
        stack = [start]
        while stack:
            u = stack[-1]
            while ends[u] and ends[u][-1][1] in used:
                ends[u].pop()
            if ends[u]:
                v, edge = ends[u].pop()
                used.add(edge)
                tail[edge] = u
                stack.append(v)
            else:
                stack.pop()
    return {edge: tail[edge] == u for edge, (u, v) in edges.items()}


def _deal_events(p, name, role, groups, g):
    """The event types of every session of an event role (group["labels"]), `count` = max(per_session) types per
    session, and one event-free session per group when per_session allows 0 (stream event_free_position,
    _event_free).

    Every group holds one full round of the types, split over its two sessions with events (the v5 file: 6 types,
    3 in each session), so every type lies once in every boot and as often on every VM as the role has groups
    there (as in B4; F1 of the verification of B4b; proposal 7.1, 9.1). The stream event_deck pairs the types at
    random, and a session takes one type of every pair, so it never holds a type twice. For every pair, _orient
    walks the groups of the role as the edges of the multigraph of the scenarios (a group joins the scenarios of
    its two sessions with events); the session the walk enters takes the pair's first type, the other one its
    second. A type is thus in a scenario as often as the walk of its pair enters or leaves it, which is half the
    role's sessions with events there, rounded either way at an odd count: its counts per scenario differ by at most
    1 when the counts of those sessions do (the lead's must_fix 5 on B4). In a campaign every scenario of a role
    holds two sessions with events per block (a block holds it once at every position, and its event-free sessions
    lie in different scenarios, _event_free), so every type is exactly as often in every scenario (the v5 file: 3,
    1, 2 and 3 times in train, dev, calibration and test_benign). The order of the types in a session is drawn
    last. A protocol whose groups cannot hold one full round over two sessions with events (another count of
    types or of event-free sessions) cannot be planned."""
    e = p["events"]
    types, count = sorted(e["types"]), max(e["per_session"])
    free = 0 in e["per_session"] and count > 0  # One session per group without events.
    empty = _event_free(groups, g, random.Random(seed(name, "event_free_position", role, -1, 0)), role) if free else {}
    held = {group["group"]: [i for i in range(g) if empty.get(group["group"]) != i] for group in groups}
    for group in groups:
        group["labels"] = [[] for _ in range(g)]
    if not count or not groups:
        return
    if len(types) != 2 * count or any(len(positions) != 2 for positions in held.values()):
        raise ValueError(f"events of role {role}: one full round of the types per group needs two sessions with "
                         f"events and twice as many types as a session holds ({len(types)} types, {count} per "
                         f"session, {len(held[groups[0]['group']])} sessions with events per group)")
    rng = random.Random(seed(name, "event_deck", role, -1, 0))
    shuffled = rng.sample(types, len(types))
    edges = {group["group"]: tuple(group["scenarios"][i] for i in held[group["group"]]) for group in groups}
    for first, second in zip(shuffled[::2], shuffled[1::2]):
        forward = _orient(edges, rng)
        for group in groups:
            i, j = held[group["group"]]
            into, out = (j, i) if forward[group["group"]] else (i, j)
            group["labels"][into].append(first)
            group["labels"][out].append(second)
    for group in groups:
        group["labels"] = [rng.sample(labels, len(labels)) for labels in group["labels"]]


def _cell_cycle(cells, rng):
    """The (VM, scenario) cells of the control role in a cycle that alternates the VMs and, where it can, never puts
    one scenario into two neighbouring cells (the last cell neighbours the first): the cells of each VM in random
    order, drawn again at most MAX_DRAWS times; the last draw stays when none qualifies."""
    by_vm = {}
    for cell in sorted(cells, key=str):
        by_vm.setdefault(cell[0], []).append(cell)
    for _ in range(MAX_DRAWS):
        rows = [rng.sample(by_vm[vm], len(by_vm[vm])) for vm in sorted(by_vm, key=str)]
        cycle = [cell for row in itertools.zip_longest(*rows) for cell in row if cell is not None]
        if len(cycle) < 2 or all(a[1] != b[1] for a, b in zip(cycle, cycle[1:] + cycle[:1])):
            break
    return cycle


def _deal_controls(p, name, groups, g):
    """The control slots of every session of role test_controls (group["labels"]: (kind, polarity) or None), from
    the stream control_deck (the lead's must_fix 5 on B4).

    Each card (kind, polarity) is dealt per_kind or negatives_per_kind times when the deck fits the slots (the
    slots left over stay empty), else as often as a prefix of the deck of full rounds deals it (a rehearsal). The
    slots of the role form one sequence: a slot of every (VM, scenario) cell in the order of _cell_cycle, again
    and again. The cards are laid along it kind by kind (kinds in random order, the polarity that comes first
    alternating), each card as often as it is dealt, consecutively, the empty slots last. Neighbouring slots lie
    on different VMs and in different cells, so the occurrences of a card per VM, and in a cycle whose neighbours
    hold different scenarios per scenario too, differ by at most 1. Within a cell the cards of one kind are dealt
    round robin to different sessions, so no session holds a kind twice while a cell holds no more cards of one kind
    than sessions (the v5 file: a kind lays 14 cards along a cycle of 8 cells of 3 sessions; its rehearsal at most 4
    along 6 cells of one session). The slots of a session are in random order.

    Package B9a (N1 of the confirmation of B4b): at other sizes a cell can hold more cards of a kind than sessions,
    and the cards can leave the balance per VM or per scenario (a rehearsal of 3, 4 or 5 groups per role did). So the
    whole deal is drawn again from the stream, at most MAX_DRAWS times, until its cards meet the rows of the check
    controls that a draw decides (_cards_balanced); the counts of the cards and the doses follow from the deck, not
    from a draw. The campaign of the file and its rehearsal of 2 groups per role pass at their first draw, so their
    deals stay as they were. ValueError when no draw passes, and before any further draw when the counts alone make
    the balance per VM impossible (_vm_split_problem: a rehearsal of 3 or 5 groups per role).
    """
    c, slots = p["controls"], p["controls"]["slots_per_session"]
    rng = random.Random(seed(name, "control_deck", CONTROL_ROLE, -1, 0))
    cards = [((kind, polarity), n) for kind in sorted(c["kinds"])
             for polarity, n in (("control", c["per_kind"]), ("negative", c["negatives_per_kind"]))]
    sessions = [(group, i) for group in groups for i in range(g)]
    total = len(sessions) * slots
    cells = {}
    for group, i in sessions:
        cells.setdefault((group["vm"], group["scenarios"][i]), []).append((group["group"], i))
    for draw in range(MAX_DRAWS):
        dealt = Counter(_rounds(rng, cards, max(c["per_kind"], c["negatives_per_kind"]))[:total])
        problem = None if draw else _vm_split_problem(p, groups, g, slots, dealt)
        if problem:  # Every draw deals the same counts, so no draw can help.
            raise ValueError(f"controls of role {CONTROL_ROLE}: {problem}")
        cycle, left, sequence = _cell_cycle(cells, rng), {cell: len(cells[cell]) * slots for cell in cells}, []
        while len(sequence) < total:
            for cell in cycle:
                if left[cell]:
                    sequence.append(cell)
                    left[cell] -= 1
        # The polarity that comes first alternates over the kinds of the run (the first one drawn): in a campaign the
        # first card of a kind starts at the same VM of the cycle, so its VM gets the controls of about half the
        # kinds.
        first = rng.sample(("control", "negative"), 2)
        run = [(kind, polarity) for j, kind in enumerate(rng.sample(sorted(c["kinds"]), len(c["kinds"])))
               for polarity in (first if j % 2 == 0 else first[::-1]) for _ in range(dealt[kind, polarity])]
        per_cell = {}
        for cell, card in zip(sequence, run + [None] * (total - len(run))):
            per_cell.setdefault(cell, []).append(card)
        labels = {}
        for cell in cycle:
            units = {}  # The cards of one kind together; every empty slot alone.
            for j, card in enumerate(per_cell.get(cell, [])):
                units.setdefault(card[0] if card else j, []).append(card)
            flat = [card for unit in rng.sample(list(units.values()), len(units))
                    for card in rng.sample(unit, len(unit))]
            members = rng.sample(cells[cell], len(cells[cell]))
            for j, card in enumerate(flat):
                labels.setdefault(members[j % len(members)], []).append(card)
        for group in groups:
            group["labels"] = [rng.sample(labels.get((group["group"], i), []), slots) for i in range(g)]
        if _cards_balanced(p, groups):
            break
    else:
        raise ValueError(f"controls of role {CONTROL_ROLE}: no deal holds every kind at most once in a session and "
                         f"every card within 1 per VM and per scenario after {MAX_DRAWS} draws")
    _deal_doses(c, groups, rng)  # Last: every draw above is the one of package B4b.


def _vm_split_problem(p, groups, g, slots, dealt):
    """Why no deal of the cards `dealt` ({card: its count}, the same at every draw) can hold every card within 1 per
    VM of the protocol, or None. A card dealt n times lies floor(n / VMs) or ceil(n / VMs) times on each VM, so a VM
    must hold at least the sum of the floors over the cards, and at most the sum of the ceilings (N1 of the
    confirmation of B4b: a rehearsal of 3 or 5 groups per role puts one group of test_controls more on one VM, 9
    slots, which the cards cannot follow). The bound named is the lower one: with two VMs and no slot left empty, a
    VM above the sum of the ceilings leaves the other below the sum of the floors, and a VM with empty slots may hold
    fewer cards than slots. With more VMs a VM above the ceilings is left to the draws (ValueError after MAX_DRAWS)."""
    vms = [row["name"] for row in p["vms"]] if "vms" in p else []
    if len(vms) < 2:
        return None
    n, cards = len(vms), sum(dealt.values())
    low, high = sum(k // n for k in dealt.values()), sum(_ceil_div(k, n) for k in dealt.values())
    for vm in vms:
        held = sum(group["vm"] == vm for group in groups) * g * slots
        if held < low:
            return (f"VM {vm} holds {held} control slots, but every card within 1 per VM puts {low} to {high} of the "
                    f"{cards} dealt cards on each VM")
    return None


def _cards_balanced(p, groups):
    """Whether the cards of group["labels"] meet the rows of the check controls that a draw of _deal_controls
    decides (N1 of the confirmation of B4b): no session holds a kind twice, and the occurrences of every card of the
    deck per VM of the protocol and per scenario differ by at most 1."""
    vms = [row["name"] for row in p["vms"]] if "vms" in p else []
    where = Counter()
    for group in groups:
        for i, labels in enumerate(group["labels"]):
            kinds = [card[0] for card in labels if card is not None]
            if len(set(kinds)) != len(kinds):
                return False
            for card in labels:
                if card is not None:
                    where[card, "vm", group["vm"]] += 1
                    where[card, "scenario", group["scenarios"][i]] += 1
    return not any(len(values) > 1 and _spread(Counter({v: where[(kind, polarity), axis, v] for v in values}),
                                                values) > 1
                   for kind in p["controls"]["kinds"] for polarity in ("control", "negative")
                   for axis, values in (("vm", vms), ("scenario", sorted(p["scenarios"]))))


def _deal_doses(c, groups, rng):
    """Every card of group["labels"] becomes (kind, polarity, dose) (design B8 1.2): dose null for a kind of class A;
    for a kind of class B one of its doses, from the stream control_deck after the cards are dealt (so the deal of
    package B4b stays as it is).

    A kind of class B draws one deck of full rounds of its doses, per_dose[i] times doses[i]; each of its two cards
    (control, negative) takes the doses of as many cards of that deck as it is dealt, from the top: in a campaign the
    whole deck, so each dose has its count among the kind's controls and the same among its negatives, and in a
    rehearsal a prefix, whose counts per dose differ by at most 1. The doses of a card are then split over the VMs:
    dose by dose, the larger counts first, each VM takes the even share of the dose and the VMs with the most cards
    left to fill take one more each, until the remainder is dealt. Every share of a dose then differs by at most 1
    between the VMs, since the card's occurrences per VM do (_deal_controls). On each VM the card's occurrences take
    their doses in random order. ValueError when the doses of a card do not fit its occurrences per VM.

    Package B9a (S3 of the B8 verification): split over the VMs only, a dose bound itself to scenarios (both 64 MiB
    controls of the writer lay in eshop_low and both of its negatives in corp_high), so the negative of a dose did not
    lie in its control's conditions. So, where the counts allow it, every dose that both cards of the kind hold lies in
    a scenario of a control and of a negative of it. They allow it when each such dose has, on both cards, at least
    as many occurrences as there are VMs, so that the split gives it one on every VM, and both cards lie in at least
    as many common scenarios as there are such doses. Then each dose takes a common scenario of its own and in it one
    occurrence of the control and one of the negative, all drawn from the stream (_anchor_doses); every VM's other
    occurrences take the rest of its share in random order. In a campaign of the file a card of class B has 7
    occurrences, at least one in each of the 4 scenarios, and its doses 2, 2 and 3, at least one on each of the 2 VMs,
    so all three doses of both kinds are paired. In its rehearsal a card has 1 or 2 occurrences, so no dose lies on
    both VMs, and the doses are dealt as before, the draws included, as in every kind where the counts do not allow
    it."""
    where = {}  # (kind, polarity) -> its slots [(group, session index, slot index)] in plan order
    for group in groups:
        for i, labels in enumerate(group["labels"]):
            for j, card in enumerate(labels):
                if card is not None:
                    where.setdefault(card, []).append((group, i, j))
    vms = sorted({group["vm"] for group in groups}, key=str)
    for kind in sorted(c["kinds"]):
        k = c["kinds"][kind]
        if k["class"] != "B":
            for polarity in ("control", "negative"):
                for group, i, j in where.get((kind, polarity), []):
                    group["labels"][i][j] = (kind, polarity, None)
            continue
        deck = _rounds(rng, list(zip(k["doses"], k["per_dose"])), max(k["per_dose"]))
        cards = {polarity: where.get((kind, polarity), []) for polarity in ("control", "negative")}
        counts = {polarity: Counter(deck[:len(slots)]) for polarity, slots in cards.items()}
        paired = [dose for dose in k["doses"] if all(counts[polarity][dose] >= len(vms) for polarity in cards)]
        common = sorted(set.intersection(*({group["scenarios"][i] for group, i, _ in slots}
                                           for slots in cards.values())))
        anchored = paired if len(common) >= len(paired) else []
        shares = {}
        for polarity, slots in cards.items():
            shares[polarity] = _dose_shares(kind, polarity, k["doses"], slots, counts[polarity], vms, rng)
            if not anchored:
                _lay_doses(kind, polarity, slots, shares[polarity], vms, rng)
        if anchored:
            _anchor_doses(kind, cards, shares, anchored, common, vms, rng)


def _dose_shares(kind, polarity, doses, slots, counts, vms, rng):
    """{VM: the doses of the occurrences `slots` of the card (kind, polarity) on it}, the doses `counts` split over
    the VMs as _deal_doses states it (design B8 1.2). ValueError when they do not fit the occurrences per VM."""
    mine = {vm: [slot for slot in slots if slot[0]["vm"] == vm] for vm in vms}
    left, shares = {vm: len(mine[vm]) for vm in vms}, {vm: [] for vm in vms}
    rank = {vm: r for r, vm in enumerate(rng.sample(vms, len(vms)))}
    for dose in sorted(counts, key=lambda d: (-counts[d], doses.index(d))):
        even, rest = divmod(counts[dose], len(vms))
        for r, vm in enumerate(sorted(vms, key=lambda v: (-left[v], rank[v]))):
            shares[vm] += [dose] * (even + (r < rest))
            left[vm] -= even + (r < rest)
    if any(left.values()):
        raise ValueError(f"the doses of {kind}/{polarity} do not fit its occurrences per VM")
    return shares


def _lay_doses(kind, polarity, slots, shares, vms, rng):
    """The occurrences `slots` of the card (kind, polarity) on every VM take the doses of its share in random order."""
    for vm in vms:
        mine = [slot for slot in slots if slot[0]["vm"] == vm]
        for (group, i, j), dose in zip(mine, rng.sample(shares[vm], len(shares[vm]))):
            group["labels"][i][j] = (kind, polarity, dose)


def _anchor_doses(kind, cards, shares, doses, common, vms, rng):
    """S3 of the B8 verification: each dose of `doses` takes a scenario of `common` (where both cards lie) of its
    own, and in it one occurrence of the control and one of the negative, drawn from the stream, take the dose; each
    dose has a share on every VM, so any occurrence can. Then the other occurrences of every VM take the rest of its
    share in random order (_lay_doses)."""
    fixed = {polarity: {} for polarity in cards}
    for dose, scenario in zip(doses, rng.sample(common, len(doses))):
        for polarity, slots in cards.items():
            n = rng.choice([n for n, (group, i, _) in enumerate(slots) if group["scenarios"][i] == scenario])
            fixed[polarity][n] = dose
            shares[polarity][slots[n][0]["vm"]].remove(dose)
    for polarity, slots in cards.items():
        for n, dose in fixed[polarity].items():
            group, i, j = slots[n]
            group["labels"][i][j] = (kind, polarity, dose)
        _lay_doses(kind, polarity, [slot for n, slot in enumerate(slots) if n not in fixed[polarity]],
                   shares[polarity], vms, rng)


def _deal_tenths(name, role, groups):
    """group["tenths"]: the (start tenth, stop tenth) of every item of the role's sessions in time order, from two
    decks of full rounds of the TENTHS tenths (stream phase_deck): within the role the counts of starts per tenth
    differ by at most 1, and so do those of stops (the lead's must_fix 6 on B4)."""
    rng = random.Random(seed(name, "phase_deck", role, -1, 0))
    n = sum(x is not None for group in groups for labels in group["labels"] for x in labels)
    rounds = _ceil_div(n, TENTHS)
    starts = _rounds(rng, [(d, rounds) for d in range(TENTHS)], rounds)
    stops = _rounds(rng, [(d, rounds) for d in range(TENTHS)], rounds)
    j = 0
    for group in groups:
        group["tenths"] = []
        for labels in group["labels"]:
            row = []
            for x in labels:
                if x is not None:
                    row.append((starts[j], stops[j]))
                    j += 1
            group["tenths"].append(row)


def _merge(lists):
    """One sequence of the groups of several roles: each next group from the role whose placement leaves the
    shares of groups placed so far closest to each other; ties go to the role listed first."""
    lists = [groups for groups in lists if groups]
    placed, out = [0] * len(lists), []
    while len(out) < sum(map(len, lists)):
        best = None
        for i, groups in enumerate(lists):
            if placed[i] < len(groups):
                shares = [Fraction(placed[j] + (j == i), len(lists[j])) for j in range(len(lists))]
                if best is None or max(shares) - min(shares) < best[0]:
                    best = (max(shares) - min(shares), i)
        out.append(lists[best[1]][placed[best[1]]])
        placed[best[1]] += 1
    return out


def plan(p, mode="campaign"):
    """The schedule of a schema-3 protocol: the sessions in time order (design B4 2.3).

    mode "campaign" plans the roles of the protocol; "rehearsal" the rehearsal of the same file, under the name
    name + rehearsal.name_suffix and the prefix rehearsal.group_prefix, groups_per_role groups in every role.
    Scenarios form balanced incomplete blocks; within a role the scenario counts of one VM differ by at most 1
    (a rehearsal: over the whole plan), which a redraw of the role's blocks (the rehearsal's: of every block)
    ensures, at most MAX_DRAWS times. Then the events of every event role (_deal_events: the event-free session of
    each group, one full round of the types in each group), the controls of role test_controls (_deal_controls), the
    tenths of the starts and stops of every role (_deal_tenths) and the times of every session (_times). Raises
    ValueError when the protocol cannot be planned.
    """
    name, prefix, sizes = _shape(p, mode)
    vms = [row["name"] for row in p["vms"]] if "vms" in p else [None]
    names, k, g = sorted(p["scenarios"]), len(p["scenarios"]), p["group_sessions"]
    groups = {}
    for index, role in enumerate(p["roles"]):
        # The rotation of the schema-2 plan: a b | b a | a b ..., shifted per role, so every role has groups on
        # every VM and neither odd nor even group numbers share one VM.
        groups[role] = [{"role": role, "group": f"{prefix}{role}-{n + 1}",
                         "vm": vms[(n + n // len(vms) + index) % len(vms)]} for n in range(sizes[role])]
    rngs = {}

    def balanced(selected):
        if mode == "rehearsal":
            return _spread(Counter(s for x in selected for s in x["scenarios"]), names) <= 1
        return all(_spread(Counter(s for x in selected if x["vm"] == vm for s in x["scenarios"]), names) <= 1
                   for vm in vms)

    units = [list(p["roles"])] if mode == "rehearsal" else [[role] for role in p["roles"]]
    for roles in units:
        for _ in range(MAX_DRAWS):
            for role in roles:
                _draw_blocks(groups[role], role, k, g, rngs, names, name)
            if balanced([x for role in roles for x in groups[role]]):
                break
        else:
            raise ValueError(f"scenario counts of {'the rehearsal' if mode == 'rehearsal' else 'role ' + roles[0]} "
                             f"differ by more than 1 after {MAX_DRAWS} draws")
    for role in p["roles"]:
        if role == CONTROL_ROLE:
            _deal_controls(p, name, groups[role], g)
        else:
            _deal_events(p, name, role, groups[role], g)
        _deal_tenths(name, role, groups[role])
    order, merged = [], set()
    for role in p["roles"]:
        if role not in merged:
            together = next((listed for listed in p["interleave"] if role in listed), [role])
            merged.update(together)
            order += _merge([groups[r] for r in together]) if len(together) > 1 else groups[role]
    sessions = []
    for group in order:
        role = group["role"]
        shared = {"scenario_order": seed(name, "scenario_order", f"{role}/{group['block']}", -1, 0)}
        for purpose in (("control_deck",) if role == CONTROL_ROLE else ("event_free_position", "event_deck")) + (
                "phase_deck",):
            shared[purpose] = seed(name, purpose, role, -1, 0)
        for i in range(g):
            seeds = dict(shared, **_session_seeds(name, group["group"], i, 1))
            session = {"role": role, "group": group["group"], "position": i, "scenario": group["scenarios"][i],
                       "attempt": 1, "seeds": seeds, "seed": seeds["traffic"], "cycles": p["cycles"]}
            if group["vm"] is not None:
                session["vm"] = group["vm"]
            items = _items(p, role, group["labels"][i], group["tenths"][i], random.Random(seeds["event_times"]))
            session["controls" if role == CONTROL_ROLE else "events"] = items
            sessions.append(session)
    doc = {"schema": PLAN_SCHEMA, "mode": mode, "name": name, "group_prefix": prefix, "sessions": sessions}
    if vms != [None]:
        doc["sessions_per_vm"] = {vm: sum(s["vm"] == vm for s in sessions) for vm in vms}
    doc.update(planned_hours=len(sessions) * p["cycles"] * p["interval_s"] / 3600,
               note="Design allocation, not collected data; a replacement keeps the assignment and the tenths of the "
                    "interval of its starts and stops (replacement()).")
    return doc


class OutsideDeck(ValueError):
    """A session holds an item outside the protocol's deck (S5 of the B4 verification): replacement() names it
    instead of failing on a missing key."""


def _outside_types(p, session):
    """A reason for every event of `session` whose type lies outside events.types (S5 of the B4 verification)."""
    return [f"type {x.get('type')} is outside events.types" for x in session.get("events", [])
            if x.get("type") not in p["events"]["types"]]


def _outside_deck(p, session):
    """A reason for every item of `session` outside the protocol's deck: an event type outside events.types, a
    control kind outside controls.kinds. No session of plan() has one."""
    return _outside_types(p, session) + [
        f"control kind {x['kind']} is outside controls.kinds" for x in session.get("controls", [])
        if x.get("kind") is not None and x["kind"] not in p["controls"]["kinds"]]


def replacement(p, session, attempt, *, mode="campaign"):
    """Attempt `attempt` (2 or later) of a planned session: the same VM, role, group, position, scenario and event
    types or control kinds (with their polarities and doses, package B8) in order, and the same tenths of the
    interval for every start and stop (design B4b: the phases of a role stay stratified when a session is replaced);
    new phases within those tenths, new durations and gaps, and new traffic seeds from the streams of this attempt.
    OutsideDeck (a ValueError) names an item outside the protocol's deck (S5 of the B4 verification)."""
    if type(attempt) is not int or attempt < 2:
        raise ValueError("a replacement is attempt 2 or later")
    outside = _outside_deck(p, session)
    if outside:
        raise OutsideDeck(f"no replacement of {_label(session)}: {outside[0]}")
    name = _shape(p, mode)[0]
    group, position = session["group"], session["position"]
    seeds = dict(session["seeds"], **_session_seeds(name, group, position, attempt))
    out = dict(copy.deepcopy(session), attempt=attempt, seeds=seeds, seed=seeds["traffic"])
    rng = random.Random(seeds["event_times"])
    if "controls" in session:
        labels = [None if c.get("kind") is None else (c["kind"], c["polarity"], c.get("dose"))
                  for c in session["controls"]]
        tenths = [item_tenths(p, c) for c in session["controls"] if c.get("kind") is not None]
        out["controls"] = _items(p, CONTROL_ROLE, labels, tenths, rng)
    if "events" in session:
        tenths = [item_tenths(p, x) for x in session["events"]]
        out["events"] = _items(p, session["role"], [x["type"] for x in session["events"]], tenths, rng)
    return out


def planned_rows(p, mode):
    """One row per planned session of a schema-3 protocol in this mode, in the plan's order (design B6a 1.2):
    {label, role, group, position, scenario, vm}, read from plan(p, mode); vm is None for a protocol of one unnamed
    VM. The mode has no default: "campaign" or "rehearsal" (whose groups take rehearsal.group_prefix). A replacement
    keeps role, group, position, scenario and vm (replacement()), and no group repeats a scenario, so the corpus
    index (features/dataset.py) and training (safeguard/training.py) match an accepted session to its row by
    (role, group, scenario, vm). ValueError for another schema, an unknown mode, or a plan in which that key repeats."""
    if type(p) is not dict or p.get("schema") != SCHEMA:
        raise ValueError("planned rows require protocol schema 3")
    if mode not in MODES:
        raise ValueError("unknown plan mode: " + str(mode))
    rows = [{"label": _label(s), "role": s["role"], "group": s["group"], "position": s["position"],
             "scenario": s["scenario"], "vm": s.get("vm")} for s in plan(p, mode)["sessions"]]
    seen = Counter((r["role"], r["group"], r["scenario"], r["vm"]) for r in rows)
    repeated = [f"{group} repeats scenario {scenario}" for (_, group, scenario, _), n in seen.items() if n > 1]
    if repeated:
        raise ValueError("planned rows cannot be matched: group " + repeated[0])
    return rows


def reset_seed(p):
    """The seed of lab/guest_state.py reset --seed at the start of every group of both modes: streams.seeded_level.seed,
    the one seeded level of the guest's database (proposal 5.4: every group starts with the database restored to its
    seeded level; chapter 12: a fixed seeded state; question Q18, accepted by the lead 2026-11-24: one level for every
    group of both modes, the level lab/install.sh seeds, seed 0). The fix of package B9a (F4 of its verification)
    replaced the per-group stream guest_reset of B9a by this one value. ValueError for another schema, and for a
    protocol whose seeded level the loader would refuse (`invalid streams.seeded_level`)."""
    if type(p) is not dict or p.get("schema") != SCHEMA:
        raise ValueError("the seed of the guest's reset requires protocol schema 3")
    try:
        good = _ok_seeded_level(p)
    except (KeyError, TypeError, AttributeError):
        good = False
    if not good:
        raise ValueError("invalid streams.seeded_level")
    return p["streams"]["seeded_level"]["seed"]


# ------------------------------------------------------------------ the self-check

def _label(s):
    return f"{s['group']}#{s['position']}"


def _seconds(value):
    return f"{value:.3f}".rstrip("0").rstrip(".")


def _items_of(s):
    return [x for x in [*s.get("events", []), *s.get("controls", [])] if x.get("kind", "") is not None]


def _groups(schedule):
    """{group: its sessions} in the plan's order."""
    out = {}
    for s in schedule["sessions"]:
        out.setdefault(s["group"], []).append(s)
    return out


def check_keys(doc, schedule=None):
    return layout_problems(doc)


def check_loader(path):
    from scripts import collection
    try:
        collection.protocol(path)
    except (ValueError, KeyError, TypeError) as error:
        return ["protocol(): " + (str(error) if type(error) is ValueError else f"{type(error).__name__}: {error}")]
    return []


def check_reachability(doc, schedule=None):
    """The gate admits exactly invalid_rows.max isolated rows (POKYNY 2026-11-22 section 4), max at most 6, and
    the witness of the worst case is decided as the audit decides it (features/acceptance.py). Both witnesses are
    placements without two equal spacings: one that fell back to worst_invalid_rows fails the check (lead's
    remarks on B4, part 1, section 1), so the property holds for every file that passes, not only for today's
    numbers."""
    from features.acceptance import gate_interval, max_witness_cases  # The witness of the worst case.
    reasons = []
    if doc["invalid_rows"]["max"] > MAX_INVALID_ROWS:
        reasons.append(f"invalid_rows.max above {MAX_INVALID_ROWS}")
    low, high = gate_interval(doc)
    if not low < doc["min_score_coverage"] <= high:
        reasons.append("score coverage gate outside the interval bound to invalid_rows.max")
    at_max, above = max_witness_cases(doc)
    if not at_max["accepted"]:
        reasons.append("witness with invalid_rows.max rows is refused")
    if above["accepted"] or "periodicity" in above["codes"]:
        reasons.append("witness with invalid_rows.max + 1 rows is not refused by the gate alone")
    reasons += [f"witness with {rows} rows fell back to worst_invalid_rows"
                for case, rows in ((at_max, "invalid_rows.max"), (above, "invalid_rows.max + 1"))
                if case["witness"] != "worst_witness"]
    return reasons


def check_role_sizes(doc, schedule):
    """In a campaign the groups of a role are a multiple of the scenarios; every role has a group on every VM, and
    within a role the group counts of the VMs differ by at most 1 (S3 of the B4 verification: 11 of the 12 groups of
    train on one VM passed this check and the scenario balance). A group counts on the VM of its first session."""
    k = len(doc["scenarios"])
    groups = _groups(schedule)
    vms = [row["name"] for row in doc["vms"]] if "vms" in doc else []
    reasons = []
    for role in ROLES:
        mine = [ss for ss in groups.values() if ss[0]["role"] == role]
        if schedule["mode"] == "campaign" and len(mine) % k:
            reasons.append(f"groups of role {role} are not a multiple of {k}")
        on = {s.get("vm") for ss in mine for s in ss}
        reasons += [f"role {role} has no group on VM {vm}" for vm in vms if vm not in on]
        per_vm = Counter(ss[0].get("vm") for ss in mine)
        if mine and len(vms) > 1 and _spread(per_vm, vms) > 1:
            reasons.append(f"role {role}: groups per VM differ by more than 1")
    return reasons


def check_scenario_balance(doc, schedule):
    names, k, g = sorted(doc["scenarios"]), len(doc["scenarios"]), doc["group_sessions"]
    groups = _groups(schedule)
    reasons = []
    for group, sessions in groups.items():
        positions = [s["position"] for s in sessions]
        if positions != list(range(g)):  # Groups of group_sessions sessions, one per position in order.
            reasons.append(f"group {group} has positions {json.dumps(positions)} (expected 0 to {g - 1})")
        seen = Counter(s["scenario"] for s in sessions)
        reasons += [f"group {group} repeats scenario {name}" for name in dict.fromkeys(s["scenario"] for s in sessions)
                    if seen[name] > 1]
    for role in ROLES:
        mine = [ss for ss in groups.values() if ss[0]["role"] == role]
        for b, start in enumerate(range(0, len(mine), k)):
            block = [s for ss in mine[start:start + k] for s in ss]
            for i in sorted({s["position"] for s in block}):
                seen = Counter(s["scenario"] for s in block if s["position"] == i)
                reasons += [f"scenario {name} twice at position {i} in block {role}/{b + 1}" for name in sorted(seen)
                            if seen[name] > 1]
    if schedule["mode"] == "rehearsal":
        if _spread(Counter(s["scenario"] for s in schedule["sessions"]), names) > 1:
            reasons.append("rehearsal plan: scenario counts differ by more than 1")
        return reasons
    vms = [row["name"] for row in doc["vms"]] if "vms" in doc else [None]
    for role in ROLES:
        for vm in vms:
            counts = Counter(s["scenario"] for s in schedule["sessions"] if s["role"] == role and s.get("vm") == vm)
            if _spread(counts, names) > 1:
                where = f"role {role}" if vm is None else f"role {role} on VM {vm}"
                reasons.append(where + ": scenario counts differ by more than 1")
    return reasons


def check_events(doc, schedule):
    """The events of the event roles (proposal 5.5, 7.1, 7.2, 9.1; skeleton §3; the lead's must_fix 5 on B4; F1 of
    the verification of B4b): every session has a count of per_session events and no type twice, and no group (a
    boot) holds a type twice; every group one event-free session, whose positions and scenarios differ in a role by
    at most 1; in a role the counts per type differ by at most 1, and so do the counts of each type per scenario and
    per VM; min_per_type in a campaign; no events in role test_controls. A type outside events.types is named (S5 of
    the B4 verification)."""
    e = doc["events"]
    allowed, count, names = e["per_session"], max(e["per_session"]), sorted(doc["scenarios"])
    vms = [row["name"] for row in doc["vms"]] if "vms" in doc else []
    sessions = [s for s in schedule["sessions"] if s["role"] != CONTROL_ROLE]
    reasons = [f"session {_label(s)} has {len(s.get('events', []))} events (allowed {json.dumps(allowed)})"
               for s in sessions if len(s.get("events", [])) not in allowed]
    reasons += [f"session {_label(s)}: {why}" for s in sessions for why in _outside_types(doc, s)]
    for s in sessions:
        held = Counter(x["type"] for x in s.get("events", []))
        reasons += [f"session {_label(s)} holds type {t} twice" for t in sorted(held) if held[t] > 1]
    for group, ss in _groups({"sessions": sessions}).items():
        held = Counter(x["type"] for s in ss for x in s.get("events", []))
        reasons += [f"group {group} holds type {t} twice" for t in sorted(held) if held[t] > 1]
    if 0 in allowed and count:
        for group, ss in _groups({"sessions": sessions}).items():
            empty = sum(not s.get("events") for s in ss)
            if empty != 1:
                reasons.append(f"group {group} has {empty} sessions without events")
        for role in ROLES:  # Skeleton §3, must_fix 5: positions and scenarios of the event-free sessions in a role.
            free = [s for s in sessions if s["role"] == role and not s.get("events")]
            if not any(s["role"] == role for s in sessions):
                continue
            if _spread(Counter(s["position"] for s in free), range(doc["group_sessions"])) > 1:
                reasons.append(f"role {role}: event-free sessions per position differ by more than 1")
            if _spread(Counter(s["scenario"] for s in free), names) > 1:
                reasons.append(f"role {role}: event-free sessions per scenario differ by more than 1")
    for role in ROLES:
        if role == CONTROL_ROLE:
            continue
        mine = [s for s in sessions if s["role"] == role]
        counts = Counter(x["type"] for s in mine for x in s.get("events", []))
        if mine and _spread(counts, sorted(e["types"])) > 1:
            reasons.append(f"role {role}: event type counts differ by more than 1")
        cells = Counter((x["type"], s["scenario"]) for s in mine for x in s.get("events", []))
        reasons += [f"role {role}: events of type {t} per scenario differ by more than 1" for t in sorted(e["types"])
                    if mine and max(cells[t, n] for n in names) - min(cells[t, n] for n in names) > 1]
        on = Counter((x["type"], s.get("vm")) for s in mine for x in s.get("events", []))
        reasons += [f"role {role}: events of type {t} per VM differ by more than 1" for t in sorted(e["types"])
                    if mine and len(vms) > 1 and max(on[t, vm] for vm in vms) - min(on[t, vm] for vm in vms) > 1]
        if schedule["mode"] == "campaign" and role not in e["min_per_type"]:
            reasons.append(f"role {role} has no min_per_type")
        elif schedule["mode"] == "campaign":
            reasons += [f"role {role}: type {t} has {counts[t]} events, below min_per_type {e['min_per_type'][role]}"
                        for t in sorted(e["types"]) if counts[t] < e["min_per_type"][role]]
    if any(s.get("events") for s in schedule["sessions"] if s["role"] == CONTROL_ROLE):
        reasons.append(f"role {CONTROL_ROLE} has events")
    return reasons


def check_controls(doc, schedule):
    """The controls of role test_controls (proposal 7.2, 7.4; skeleton §1, §3, §6; the lead's must_fix 5 on B4):
    every session has slots_per_session slots, each a card of the deck (a kind of the protocol with its class,
    polarity control or negative) or empty, and holds no kind twice; in a campaign each kind has per_kind controls
    and negatives_per_kind negatives and only the slots the deck cannot fill are empty; a rehearsal deals a prefix of
    the deck, so its card counts differ by at most 1 and no slot is empty while cards remain; the occurrences of
    every card per VM differ by at most 1, and so do those per scenario. No other role has controls.

    The doses (package B8, design B8 1.2): a control of a kind of class A has none (null), one of class B one of the
    kind's doses; in a campaign each dose of a kind of class B has its count per_dose among the kind's controls and
    the same among its negatives, a rehearsal deals a prefix of the kind's deck of doses, so the counts per dose of a
    card differ by at most 1; on the VMs the occurrences of every dose of a card differ by at most 1.

    Package B9a (S3 of the B8 verification, _deal_doses): where the counts allow it, every dose that both cards of a
    kind of class B hold on every VM lies in a scenario of a control and of a negative of it. They allow it when both
    cards lie in at least as many common scenarios as there are such doses."""
    c, slots = doc["controls"], doc["controls"]["slots_per_session"]
    cards = {(kind, polarity): n for kind in sorted(c["kinds"])
             for polarity, n in (("control", c["per_kind"]), ("negative", c["negatives_per_kind"]))}
    vms, names = [row["name"] for row in doc["vms"]] if "vms" in doc else [], sorted(doc["scenarios"])
    sessions = [s for s in schedule["sessions"] if s["role"] == CONTROL_ROLE]
    reasons, counts, empty, where, doses, dosed = [], Counter(), 0, Counter(), Counter(), {}
    for s in sessions:
        items = s.get("controls", [])
        if len(items) != slots:
            reasons.append(f"session {_label(s)} has {len(items)} control slots (expected {slots})")
        for x in items:
            if x.get("kind") is None:
                empty += 1
            elif (x["kind"], x.get("polarity")) not in cards or x.get("class") != c["kinds"][x["kind"]]["class"]:
                reasons.append(f"session {_label(s)}: control {x['kind']}/{x.get('polarity')} is no card of the deck")
            else:
                counts[x["kind"], x["polarity"]] += 1
                where[x["kind"], x["polarity"], "vm", s.get("vm")] += 1
                where[x["kind"], x["polarity"], "scenario", s["scenario"]] += 1
                allowed, dose = c["kinds"][x["kind"]]["doses"], x.get("dose")
                if (dose is not None) if allowed is None else (type(dose) is not int or dose not in allowed):
                    reasons.append(f"session {_label(s)}: control {x['kind']}/{x['polarity']} has dose "
                                   f"{json.dumps(dose)} (doses of the kind: {json.dumps(allowed)})")
                elif dose is not None:
                    doses[x["kind"], x["polarity"], dose] += 1
                    doses[x["kind"], x["polarity"], dose, s.get("vm")] += 1
                    dosed.setdefault((x["kind"], x["polarity"], dose), set()).add(s["scenario"])
        held = Counter(x["kind"] for x in items if x.get("kind") is not None)
        reasons += [f"session {_label(s)} holds control kind {kind} twice" for kind in sorted(held) if held[kind] > 1]
    dealt = len(sessions) * slots
    if schedule["mode"] == "campaign":
        reasons += [f"control {kind}/{polarity} has {counts[kind, polarity]} occurrences (expected {n})"
                    for (kind, polarity), n in cards.items() if counts[kind, polarity] != n]
    elif sessions and _spread(counts, cards) > 1:
        reasons.append("rehearsal plan: control counts differ by more than 1")
    for kind, polarity in cards:
        for axis, values in (("VM", vms), ("scenario", names)):
            per = Counter({v: where[kind, polarity, axis.lower(), v] for v in values})
            if sessions and len(values) > 1 and _spread(per, values) > 1:
                reasons.append(f"control {kind}/{polarity}: occurrences per {axis} differ by more than 1")
        k = c["kinds"][kind]
        if k["class"] != "B" or not sessions:
            continue
        if schedule["mode"] == "campaign":
            reasons += [f"control {kind}/{polarity}: dose {dose} has {doses[kind, polarity, dose]} occurrences "
                        f"(expected {n})" for dose, n in zip(k["doses"], k["per_dose"])
                        if doses[kind, polarity, dose] != n]
        elif _spread(Counter({d: doses[kind, polarity, d] for d in k["doses"]}), k["doses"]) > 1:
            reasons.append(f"rehearsal plan: control {kind}/{polarity}: dose counts differ by more than 1")
        reasons += [f"control {kind}/{polarity}: occurrences of dose {dose} per VM differ by more than 1"
                    for dose in k["doses"] if len(vms) > 1
                    and _spread(Counter({vm: doses[kind, polarity, dose, vm] for vm in vms}), vms) > 1]
    for kind, k in sorted(c["kinds"].items()):
        if k["class"] != "B" or not sessions:
            continue
        both = [dose for dose in k["doses"] if all(doses[kind, polarity, dose, vm] for polarity in
                                                   ("control", "negative") for vm in vms or [None])]
        lie = [{name for name in names if where[kind, polarity, "scenario", name]} for polarity in ("control",
                                                                                                    "negative")]
        if len(lie[0] & lie[1]) >= len(both):
            reasons += [f"control {kind}: dose {dose} lies in no scenario of both its controls and its negatives"
                        for dose in both if not dosed[kind, "control", dose] & dosed[kind, "negative", dose]]
    if sessions and empty != max(0, dealt - sum(cards.values())):
        reasons.append(f"{empty} empty control slots (expected {max(0, dealt - sum(cards.values()))})")
    if any(s.get("controls") for s in schedule["sessions"] if s["role"] != CONTROL_ROLE):
        reasons.append("controls outside role " + CONTROL_ROLE)
    return reasons


def _guarded(doc, sessions, prefix=""):
    """Reasons for every event or control of `sessions` that starts inside a full-snapshot guard."""
    interval, before = _ms(doc["interval_s"]), _ms(doc["full_snapshot_guard"]["before_s"])
    fulls = [r * interval for r in range(0, doc["cycles"], doc["full_every"])]
    reasons = []
    for s in sessions:
        for item in _items_of(s):
            start = _ms(item["start_s"])
            reasons += [f"{prefix}{_label(s)}: {item.get('type', item.get('kind'))} starts at "
                        f"{_seconds(start / 1000)} s inside the guard of the full snapshot at {_seconds(t / 1000)} s"
                        for t in fulls if t - before <= start < t + doc["window_rows"] * interval]
    return reasons


def _replacements(doc, schedule):
    """[(session, its replacement: attempt 2)] of the plan's sessions in order, and a reason for each session that
    has none: replacement() refuses an item outside the protocol's deck by name (S5 of the B4 verification), which
    a check of the replacements names instead of failing as a whole with `cannot check`."""
    pairs, reasons = [], []
    for s in schedule["sessions"]:
        try:
            pairs.append((s, replacement(doc, s, 2, mode=schedule["mode"])))
        except OutsideDeck as error:
            reasons.append(str(error))
    return pairs, reasons


def check_full_snapshot_guard(doc, schedule):
    """No planned item starts in a guard, and neither does an item of a replacement (attempt 2 draws new times)."""
    pairs, missing = _replacements(doc, schedule)
    return _guarded(doc, schedule["sessions"]) + missing + _guarded(doc, [r for _, r in pairs], "replacement of ")


def _timing_problems(doc, sessions, prefix=""):
    """Reasons for every event or control of `sessions` that starts before first_s, lasts outside its duration span,
    starts less than min_gap_s after the item before it in its session ends, or ends less than tail_s before the end
    of the session (S1 of the B4 verification)."""
    e = doc["events"]
    first, gap, tail = _ms(e["first_s"]), _ms(e["min_gap_s"]), _ms(e["tail_s"])
    length = _ms(doc["cycles"] * doc["interval_s"])
    spans = {"events": e["duration_s"], "controls": doc["controls"]["duration_s"]}
    reasons = []
    for s in sessions:
        before = None  # The end of the item before, in the session's order.
        for field, span in spans.items():
            for item in [x for x in s.get(field, []) if x.get("kind", "") is not None]:
                start, duration = _ms(item["start_s"]), _ms(item["duration_s"])
                what = f"{prefix}{_label(s)}: {item.get('type', item.get('kind'))}"
                if start < first:
                    reasons.append(f"{what} starts at {_seconds(start / 1000)} s, before first_s "
                                   f"{_seconds(first / 1000)} s")
                if not _ms(span[0]) <= duration <= _ms(span[1]):
                    reasons.append(f"{what} lasts {_seconds(duration / 1000)} s, outside duration_s {json.dumps(span)}")
                if before is not None and start < before + gap:
                    reasons.append(f"{what} starts less than min_gap_s {_seconds(gap / 1000)} s after the item "
                                   "before it ends")
                if start + duration + tail > length:
                    reasons.append(f"{what} ends less than tail_s {_seconds(tail / 1000)} s before the end of the "
                                   f"session ({_seconds(length / 1000)} s)")
                before = start + duration
    return reasons


def check_times(doc, schedule):
    """Every planned item keeps first_s, its duration span, min_gap_s and tail_s, and so does every item of a
    replacement (attempt 2 draws new times; S1 of the B4 verification, the lead's must_fix 6 on B4)."""
    pairs, missing = _replacements(doc, schedule)
    return (_timing_problems(doc, schedule["sessions"]) + missing
            + _timing_problems(doc, [r for _, r in pairs], "replacement of "))


def ks_distance(values):
    """The Kolmogorov-Smirnov distance of values in [0, 1) from the uniform law."""
    xs, n = sorted(values), len(values)
    return max(max((i + 1) / n - x, x - i / n) for i, x in enumerate(xs)) if xs else 0.


def ks_critical(n, level=KS_LEVEL):
    """The critical KS distance of n values at `level`: Stephens' closed form c / (sqrt(n) + 0.12 + 0.11 / sqrt(n))
    with c = sqrt(ln(2 / level) / 2). At the 5 % level it lies within 1e-4 of the exact quantile from n = 19 on
    (n = 286: 0.0797; n = 66, the rehearsal: 0.1645); for n = 2 to 18 it lies up to 0.0014 above it, so it is
    lenient there (S2 of the verification of B4b, checked against scipy.stats.kstwo for n = 2 to 3000)."""
    return math.sqrt(math.log(2 / level) / 2) / (math.sqrt(n) + .12 + .11 / math.sqrt(n))


def _phases_ms(doc, schedule):
    """{role: [(start phase, stop phase)]} in ms of the planned items of every role, in plan order."""
    interval, out = _ms(doc["interval_s"]), {}
    for s in schedule["sessions"]:
        for item in _items_of(s):
            start = _ms(item["start_s"])
            out.setdefault(s["role"], []).append((start % interval, (start + _ms(item["duration_s"])) % interval))
    return out


def check_phases(doc, schedule):
    """The phases are stratified by construction (the lead's must_fix 6 on B4; S1 of the B4 verification): in every
    role the counts of event and control starts in the TENTHS tenths of the collection interval differ by at most 1,
    and so do those of the stops; the start phases of the whole plan pass a Kolmogorov-Smirnov test against the
    uniform law at KS_LEVEL, and so do its stop phases (F2 of the verification of B4b). Every start at one phase, on
    the grid or off it, fails both."""
    interval, phases, reasons = _ms(doc["interval_s"]), _phases_ms(doc, schedule), []
    for role in ROLES:
        for i, what in enumerate(("starts", "stops")):
            counts = Counter(tenth(pair[i], interval) for pair in phases.get(role, []))
            if phases.get(role) and _spread(counts, range(TENTHS)) > 1:
                reasons.append(f"role {role}: {what} per tenth of the interval differ by more than 1")
    for i, what in enumerate(("start", "stop")):
        values = [pair[i] / interval for role in ROLES for pair in phases.get(role, [])]
        if values and ks_distance(values) > ks_critical(len(values)):
            reasons.append(f"{what} phases fail the Kolmogorov-Smirnov test against the uniform law at "
                           f"{KS_LEVEL * 100:g} %: distance {ks_distance(values):.4f} above the critical "
                           f"{ks_critical(len(values)):.4f} of {len(values)} {what}s")
    return reasons


def _stream(s, purpose, blocks):
    unit = PURPOSES.get(purpose, "session")
    if unit == "role":
        return purpose, s["role"]
    if unit == "block":
        return purpose, s["role"], blocks[s["group"]]
    return purpose, s["group"], s["position"], s.get("attempt")


def check_streams(doc, schedule):
    """No two streams share a seed, the streams of every replacement (attempt 2) included; each session's seed is
    its traffic seed (scripts/campaign.py passes `seed` to the runner); a replacement keeps its session's
    assignment (the doses of its controls included, package B8) and the tenths of the interval of its starts and
    stops (design B4b).

    Package B7a: the streams of the analysis (ANALYSIS_PURPOSES) are no streams of the plan, so no session and no
    replacement draws one, and their seeds under the plan's name (z0_alarms per role, bootstrap per comparison of
    CONFIRMATORY, which the analysis check binds to the file, and since package B7b injections per unit of
    INJECTION_UNITS) share none with each other or with the plan.

    Package B9a: a session whose replacement cannot be drawn is named (_replacements, S5 of the B4 verification). The
    seed of the guest's reset is no stream since the fix of B9a (streams.seeded_level, reset_seed)."""
    k = len(doc["scenarios"])
    groups = _groups(schedule)
    blocks = {}
    for role in ROLES:
        mine = [group for group, ss in groups.items() if ss[0]["role"] == role]
        blocks.update({group: i // k + 1 for i, group in enumerate(mine)})
    pairs, reasons = _replacements(doc, schedule)
    replacements, owners = [r for _, r in pairs], {}
    for s in schedule["sessions"] + replacements:
        for purpose, value in s["seeds"].items():
            if purpose not in ANALYSIS_PURPOSES:  # A seed of the analysis in the plan is a reason of its own (below).
                owners.setdefault(value, {})[_stream(s, purpose, blocks)] = purpose
    units = {"z0_alarms": ROLES, "bootstrap": [f"{claim}/{method}" for claim, methods in CONFIRMATORY.items()
                                               for method in methods], "injections": INJECTION_UNITS}
    for purpose, names in units.items():
        for unit in names:
            owners.setdefault(_analysis_seed(schedule["name"], purpose, unit), {})[purpose, unit] = purpose
    for value, streams in owners.items():
        if len(streams) > 1:
            a, b = sorted(streams.values())[:2]
            reasons.append(f"two {a} streams share a seed" if a == b else f"purposes {a} and {b} share a seed")
    for s, what in [(s, "session") for s in schedule["sessions"]] + [(r, "replacement of") for r in replacements]:
        reasons += [f"{what} {_label(s)} draws the analysis stream {purpose}" for purpose in s["seeds"]
                    if purpose in ANALYSIS_PURPOSES]
    reasons += [f"session {_label(s)}: seed differs from seeds.traffic" for s in schedule["sessions"]
                if s.get("seed") != s["seeds"].get("traffic")]
    for s, r in pairs:
        for field in ("vm", "role", "group", "position", "scenario"):
            if r.get(field) != s.get(field):
                reasons.append(f"replacement of {_label(s)} changes {field}")
        if [x["type"] for x in r.get("events", [])] != [x["type"] for x in s.get("events", [])]:
            reasons.append(f"replacement of {_label(s)} changes types")
        if ([(x.get("kind"), x.get("polarity")) for x in r.get("controls", [])]
                != [(x.get("kind"), x.get("polarity")) for x in s.get("controls", [])]):
            reasons.append(f"replacement of {_label(s)} changes kinds")
        elif [x.get("dose") for x in r.get("controls", [])] != [x.get("dose") for x in s.get("controls", [])]:
            reasons.append(f"replacement of {_label(s)} changes doses")
        if [item_tenths(doc, x) for x in _items_of(r)] != [item_tenths(doc, x) for x in _items_of(s)]:
            reasons.append(f"replacement of {_label(s)} changes the tenths of its phases")
    return reasons


def check_role_order(doc, schedule):
    reasons, highest = [], -1
    for s in schedule["sessions"]:
        rank = TIME_RANK[s["role"]]
        if rank < highest and f"role {s['role']} is out of time order" not in reasons:
            reasons.append(f"role {s['role']} is out of time order")
        highest = max(highest, rank)
    roles = {group: ss[0]["role"] for group, ss in _groups(schedule).items()}
    sequence = [group for group, role in roles.items() if role in INTERLEAVED]
    totals = Counter(roles[group] for group in sequence)
    if all(totals[role] for role in INTERLEAVED):
        placed, bound = Counter(), max(Fraction(1, totals[role]) for role in INTERLEAVED)
        for group in sequence:
            placed[roles[group]] += 1
            shares = [Fraction(placed[role], totals[role]) for role in INTERLEAVED]
            if max(shares) - min(shares) > bound:
                reasons.append(" and ".join(INTERLEAVED) + " are not interleaved")
                break
    return reasons


def _matches(path, pattern):
    parts, wanted = path.split("."), pattern.split(".")
    return len(parts) == len(wanted) and all(w in ("*", p) for p, w in zip(parts, wanted))


def _nulls(value, path=""):
    if value is None:
        yield path
    elif type(value) is dict:
        for key in sorted(value):
            yield from _nulls(value[key], f"{path}.{key}" if path else key)
    elif type(value) is list:
        for i, item in enumerate(value):
            yield from _nulls(item, f"{path}.{i}")


# Proposal 4.1: K1 against Z3 and Z5, K2a against the threshold methods Z1, Z2 and Z4, K2b against Z3 and Z5. A
# result "better" must beat every method of its list, so a method left out would lighten the claim (the lead's
# must_fix 4 on B4). Package B7b and the lead's answer to question Q13 (2026-11-24): Z4 enters K2a by both its
# variants (VARIANTS), each a comparison of its own, and "better" needs M to beat both.
CONFIRMATORY = {"k1": ["Z3", "Z5"], "k2a": ["Z1", "Z2", "Z4:load", "Z4:residual"], "k2b": ["Z3", "Z5"]}


def not_applicable(doc):
    """The paths whose null means "none", not a value a later stage determines: the doses and the counts per dose of
    a control kind of class A (package B8), and the seeds of a descriptive method that draws nothing (UNSEEDED, merge
    of B7a)."""
    controls = doc.get("controls") if type(doc.get("controls")) is dict else {}
    kinds = controls.get("kinds") if type(controls.get("kinds")) is dict else {}
    analysis = doc.get("analysis") if type(doc.get("analysis")) is dict else {}
    described = analysis.get("descriptive_methods") if type(analysis.get("descriptive_methods")) is dict else {}
    return ({f"controls.kinds.{kind}.{key}" for kind, k in sorted(kinds.items())
             if type(k) is dict and k.get("class") == "A" for key in ("doses", "per_dose")}
            | {f"analysis.descriptive_methods.{name}.seeds" for name in UNSEEDED if name in described})


def check_analysis(doc, schedule=None, *, stage="G0"):
    """The analysis plan is complete and compares K1, K2a and K2b with the methods of proposal 4.1; its linkage table
    is the lead's word for word (LINKAGE, package B7c); every attachment of the final record it lists states what it
    holds (ATTACHMENTS, package B11); its count of carrier boots is the campaign plan's (package B9a); null only at a
    path of determined_at or where it means none (not_applicable); with stage Gk every path of a stage up to Gk holds
    a value."""
    if stage not in STAGES:
        raise ValueError("unknown stage: " + str(stage))
    reasons = []
    analysis = doc.get("analysis")
    _walk(analysis if type(analysis) is dict else {}, ANALYSIS, "analysis", reasons, missing_only=True)
    reasons = [r.replace("missing protocol key: ", "missing analysis key: ") for r in reasons]
    for name, methods in CONFIRMATORY.items():
        compare = ((analysis if type(analysis) is dict else {}).get(name) or {}).get("compare")
        if type(compare) is list and sorted(map(str, compare)) != methods:
            reasons.append(f"analysis.{name}.compare is {json.dumps(compare)}, "
                           f"proposal 4.1 names {json.dumps(methods)}")
    # Package B7c (design B7c 1.2): the linkage table word for word as the lead's skeleton B7 writes it (addendum 2
    # point 4); the owner's text of the thesis promises it, so a reworded row is a question to the lead.
    linkage = (analysis if type(analysis) is dict else {}).get("linkage")
    for question, text in LINKAGE.items():
        if type(linkage) is dict and question in linkage and linkage[question] != text:
            reasons.append(f"analysis.linkage.{question} is {json.dumps(linkage[question], ensure_ascii=False)}, "
                           "the lead's table (skeleton B7, addendum 2 point 4) says "
                           f"{json.dumps(text, ensure_ascii=False)}")
    # Package B11 (the lead's answers to questions Q17 and Q28): every attachment of ATTACHMENTS the file names states
    # what it holds; a missing or an unknown one is the reason of the checks keys and loader (layout_problems).
    attachments = (analysis if type(analysis) is dict else {}).get("attachments")
    for name in ATTACHMENTS:
        if type(attachments) is dict and name in attachments and not _text(attachments[name]):
            reasons.append(f"analysis.attachments.{name} is {json.dumps(attachments[name], ensure_ascii=False)}: "
                           "every attachment of the final record states what it holds, a text (ATTACHMENTS)")
    # Package B9a (F3 of the verification of B7c): analysis.interventions.boots is the number of boots of the carrier
    # roles of the campaign plan, one per group of test_benign and of test_controls (plan() makes roles[role] groups
    # of every role in mode campaign); tcn/k2.py refuses another number only in the final evaluation, after the seal
    # is consumed. The self-check binds it in both of its modes, since both check the one file; a rehearsal has its
    # own carrier boots (2 + 2 in the file), which neither tcn/k2.py nor this check binds.
    interventions = (analysis if type(analysis) is dict else {}).get("interventions")
    boots = interventions.get("boots") if type(interventions) is dict else None
    roles = doc.get("roles") if type(doc.get("roles")) is dict else {}
    carriers = [roles.get(role) for role in CARRIERS]
    if type(boots) is int and all(type(n) is int for n in carriers) and boots != sum(carriers):
        reasons.append(f"analysis.interventions.boots is {boots}, the carrier roles of the campaign plan hold "
                       f"{sum(carriers)} boots (" + ", ".join(f"{role} {n}" for role, n in zip(CARRIERS, carriers))
                       + ")")
    determined = doc.get("determined_at") if type(doc.get("determined_at")) is dict else {}
    patterns = [x for paths in determined.values() if type(paths) is list for x in paths if type(x) is str]
    none = not_applicable(doc)
    reasons += [f"null outside determined_at: {path}" for path in _nulls(doc)
                if path not in none and not any(_matches(path, pattern) for pattern in patterns)]
    for name in DETERMINED:
        if STAGES.index(name) <= STAGES.index(stage) and type(determined.get(name)) is list:
            reasons += [f"null at {path} determined at {name} (stage {stage})"
                        for pattern in determined[name] for path, value in expand(doc, pattern) if value is None]
    return reasons


PLAN_CHECKS = {"role_sizes": check_role_sizes, "scenario_balance": check_scenario_balance, "events": check_events,
               "controls": check_controls, "full_snapshot_guard": check_full_snapshot_guard, "times": check_times,
               "phases": check_phases, "streams": check_streams, "role_order": check_role_order}


def _message(error):
    return str(error) if type(error) is ValueError else f"{type(error).__name__}: {error}"


def check_rehearsal(doc, schedule):
    """The rehearsal has its own name and prefix, and its plan passes the checks of a plan in rehearsal mode."""
    r = doc["rehearsal"]
    reasons = []
    if doc["name"] + r["name_suffix"] == doc["name"]:
        reasons.append("rehearsal name equals the campaign name")
    if r["group_prefix"] == doc["group_prefix"]:
        reasons.append("rehearsal group prefix equals the campaign prefix")
    if schedule is not None and schedule["mode"] == "rehearsal":
        rehearsal = schedule
    else:
        try:
            rehearsal = plan(doc, "rehearsal")
        except Exception as error:  # noqa: BLE001 - a protocol that cannot be planned fails, it never crashes
            return reasons + ["no rehearsal plan: " + _message(error)]
    for name, check in PLAN_CHECKS.items():
        reasons += [f"{name}: {reason}" for reason in check(doc, rehearsal)]
    return reasons


def lab_names():
    """What the lab registers: event types and control kinds (lab/udalosti.py), and the traffic profiles the
    generator implements (scripts/host_traffic.py PROFILES, package B5b)."""
    from lab import udalosti
    from scripts import host_traffic
    return {"event type": set(udalosti.TYPES), "profile": set(host_traffic.PROFILES),
            "control kind": set(udalosti.CONTROLS)}


def lab_controls():
    """{kind: {class, doses, candidates}} as lab/udalosti.py runs the control kinds (package B8): the class of each,
    the doses of class B (null for class A) and the module candidates of the module kind (null for the others)."""
    from lab import udalosti
    return {kind: {"class": udalosti.CLASSES[kind],
                   "doses": list(udalosti.DOSES[kind]) if kind in udalosti.DOSES else None,
                   "candidates": list(udalosti.MODULE_CANDIDATES) if kind == MODULE_KIND else None}
            for kind in udalosti.CONTROLS}


def check_lab_register(doc, schedule=None):
    """(result, reasons): failed on a name the lab does not know, pending on a name a later package will add (none
    since B8); failed too when a control kind of the protocol has another class, other doses or other module
    candidates than lab/udalosti.py runs (package B8: the guest refuses a dose it does not know)."""
    known = lab_names()
    wanted = (("event type", sorted(doc["events"]["types"])),
              ("profile", sorted({s["profile"] for s in doc["scenarios"].values()})),
              ("control kind", sorted(doc["controls"]["kinds"])))
    unknown, pending = [], []
    for kind, names in wanted:
        for name in names:
            if name not in known[kind]:
                (pending if name in PENDING_IN_LAB else unknown).append(name)
    lab = lab_controls()
    differ = [f"control kind {kind}: {field} {json.dumps(spec.get(field))} differs from lab/udalosti.py "
              f"{json.dumps(lab[kind][field])}" for kind, spec in sorted(doc["controls"]["kinds"].items())
              if kind in lab for field in ("class", "doses", "candidates") if spec.get(field) != lab[kind][field]]
    if unknown or differ:
        return "failed", [f"unknown to lab/: {name}" for name in unknown] + differ
    if pending:
        return "pending", ["registered by a later package: " + ", ".join(pending)]
    return "passed", []


CHECKS = ("keys", "loader", "reachability", "role_sizes", "scenario_balance", "events", "controls",
          "full_snapshot_guard", "times", "phases", "streams", "role_order", "analysis", "rehearsal", "lab_register")


def evaluate(path, doc, schedule, *, stage="G0", plan_error=None):
    """Every check of the self-check on the file `path` (its JSON `doc`) and the plan `schedule` (None when no plan
    could be made: plan_error says why). [{check, result, reasons}] in the order of CHECKS."""
    out = []
    for name in CHECKS:
        result = None
        try:
            if name == "keys":
                reasons = check_keys(doc)
            elif name == "loader":
                reasons = check_loader(path)
            elif name in PLAN_CHECKS:
                reasons = ["no plan: " + plan_error] if schedule is None else PLAN_CHECKS[name](doc, schedule)
            elif name == "analysis":
                reasons = check_analysis(doc, schedule, stage=stage)
            elif name == "rehearsal":
                reasons = check_rehearsal(doc, schedule)
            elif name == "reachability":
                reasons = check_reachability(doc, schedule)
            else:
                result, reasons = check_lab_register(doc, schedule)
        except Exception as error:  # noqa: BLE001 - a malformed document fails a check, it never crashes it
            result, reasons = None, ["cannot check: " + _message(error)]
        out.append({"check": name, "result": result or ("failed" if reasons else "passed"), "reasons": reasons})
    return out


def summary(doc, schedule):
    """What the self-check records of a plan (the lead's must_fix 5 and 6 on B4; F1 and F2 of the verification of
    B4b): per event role the count of every event type at each place in its session's order (first, second, ...;
    recorded, not required) and on every VM of the file (required within 1 by the check events), per role the starts
    and stops per tenth of the interval, and the Kolmogorov-Smirnov distances of the start and of the stop phases
    of the whole plan with their critical values."""
    interval, phases = _ms(doc["interval_s"]), _phases_ms(doc, schedule)
    places = max((len(s.get("events", [])) for s in schedule["sessions"]), default=0)
    vms = [row["name"] for row in doc["vms"]] if "vms" in doc else []
    order, on_vm = {}, {}
    for role in ROLES:
        mine = [s for s in schedule["sessions"] if s["role"] == role and "events" in s]
        if mine:
            seen = Counter((x["type"], i) for s in mine for i, x in enumerate(s["events"]))
            order[role] = {t: [seen[t, i] for i in range(places)] for t in sorted(doc["events"]["types"])}
            on = Counter((x["type"], s.get("vm")) for s in mine for x in s["events"])
            on_vm[role] = {t: {vm: on[t, vm] for vm in vms} for t in sorted(doc["events"]["types"])}
    tenths = {role: {what: [Counter(tenth(pair[i], interval) for pair in phases[role])[d] for d in range(TENTHS)]
                     for i, what in enumerate(("starts", "stops"))} for role in ROLES if role in phases}
    ks = {}
    for i, what in enumerate(("starts", "stops")):
        values = [pair[i] / interval for role in ROLES for pair in phases.get(role, [])]
        ks[what] = {what: len(values), "distance": round(ks_distance(values), 4),
                    "critical": round(ks_critical(len(values)), 4) if values else None, "level": KS_LEVEL}
    return {"event_types_by_place_in_session": order, "event_types_by_vm": on_vm, "phase_tenths": tenths,
            "start_phases_ks": ks["starts"], "stop_phases_ks": ks["stops"]}


def selfcheck(path, *, mode="campaign", stage="G0"):
    """The self-check report of a protocol file; it parses the file itself and does not need the loader to pass.
    Its summary records tables of the plan (summary(); null when no plan could be made)."""
    if mode not in MODES:
        raise ValueError("unknown plan mode: " + str(mode))
    if stage not in STAGES:
        raise ValueError("unknown stage: " + str(stage))
    path = Path(path)
    raw = path.read_bytes()
    doc = json.loads(raw)
    if type(doc) is not dict:
        raise ValueError("protocol file is not a JSON object")
    try:
        schedule, error = plan(doc, mode), None
    except Exception as exc:  # noqa: BLE001 - every check that needs the plan names the error
        schedule, error = None, _message(exc)
    checks = evaluate(path, doc, schedule, stage=stage, plan_error=error)
    try:
        recorded = None if schedule is None else summary(doc, schedule)
    except Exception:  # noqa: BLE001 - a malformed plan is the checks' to name; the summary is only a record
        recorded = None
    return {"protocol": str(path.resolve()), "protocol_sha256": hashlib.sha256(raw).hexdigest(), "mode": mode,
            "stage": stage, "checks": checks, "summary": recorded,
            "passed": all(c["result"] == "passed" for c in checks)}
