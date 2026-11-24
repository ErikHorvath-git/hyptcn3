"""The self-check of protocol v5 (packages B4 and B4b): the real file passes, every deliberate error fails its check.

scripts/collection.py --protocol P selfcheck (scripts/protocol_v5.py) runs on config/collection-v5.json: every
check passes, lab_register included since package B8 registered its control kinds in lab/ (B5 registered the event
types and the traffic profiles, skeleton B5 section 5 item 7; skeleton B8 section 5 item 6), so the command exits 0.
Each row of the lead's skeleton (dokazy/B4/kostra/KOSTRA.md, section 5), each property of his must_fix 5 and 6 on
B4 and each rule of the finding S1 of the B4 verification (package B4b) is one deliberate error: the file with one
change, the plan with one change or a replacement that changes the assignment.
Its check fails with exactly the reasons written here and every other check gives what it gives for the real file,
except the ones a case lists. Only what the plan draws (a group, a scenario, an event type, a card, a time) is read
from the plan. Since B4b the plan is balanced exactly (every group holds every type once, every type as often in
every scenario and on every VM of a role, the tenths of the phases within 1), so a change can break a property it is
not about: a case changes what breaks nothing else, and where that is impossible it lists the other reasons and says
why. Times are moved by whole intervals of 5 s where the phases must stay, and the rules they meet (first_s,
min_gap_s, tail_s, the duration span, the guards) are all multiples of the interval in the real file.
Names package B4 adds are imported inside the tests, so this file collects on the code before B4. Packages B6a and
B7a add one deliberate error for each key of the analysis plan they add or change (B7a: also the streams of the
analysis, which the plan never draws). Package B7b (agent F) adds one for each key of design B7b 1.4: the orders of
C, the groups of D, the validity predicate, the evaluable minimum and the volume class, the diagnostics, the stream
injections, the two variants of Z4 in K2a (question Q13, provisional) and the domains of the grids (F3 of the
verification of B7a). Package B7c (agent M) adds one for each key of design B7c 1.2: the metrics of the thesis with the
bounds of O2 and O3, and the linkage table, which the self-check compares word for word. Package B9a (agent P, design
B9a 1.1) adds one for S3 and S5 of the B4 verification; the four cases of S1 of the verification of B4b, which the
code before B9a catches already (each kills a mutant that survived there); one for S3 of the B8 verification (a dose
of class B in no scenario of a negative of it) and for F3 of the verification of B7c (the carrier boots of K2); and the
tests of the control deal at other rehearsal sizes (N1 of the confirmation of B4b) and of the bounds where the counts
allow the doses to pair. Its fix (F4 and F6 of its verification) replaces the stream guest_reset of B9a by the one
seeded level streams.seeded_level, with one deliberate error, and adds the bound of the pairing check at equality.
"""
from collections import Counter
import json
import math
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
CHECKS = ("keys", "loader", "reachability", "role_sizes", "scenario_balance", "events", "controls",
          "full_snapshot_guard", "times", "phases", "streams", "role_order", "analysis", "rehearsal", "lab_register")
TYPES = ("naprazdno", "restart_databazy", "udrzba_zaloha", "zamok_tabulky", "zataz_pamate", "zla_konfiguracia_sluzby")
ROLES = ("train", "dev", "calibration", "test_benign", "test_controls")
SCENARIOS = ("corp_high", "corp_low", "eshop_high", "eshop_low")
UNREACHABLE = "protocol(): invalid_rows.max is unreachable under the score coverage gate"
OUTSIDE = "score coverage gate outside the interval bound to invalid_rows.max"
REFUSED = "witness with invalid_rows.max rows is refused"
# B4b, the lead's must_fix 6 on B4: in every role the starts and the stops per tenth of the 5 s interval differ by at
# most 1, and the start phases of the plan pass a Kolmogorov-Smirnov test at 5 %, and so do its stop phases (F2 of the
# verification of B4b): 286 starts and stops (12 + 4 + 8 + 12 groups with two sessions of three events, 70 controls),
# critical 1.3581 / (sqrt(286) + 0.12 + 0.11 / sqrt(286)) = 0.0797.
TENTH_ROWS = [f"role {role}: {what} per tenth of the interval differ by more than 1" for role in ROLES
              for what in ("starts", "stops")]
PLAN_CHECKS = ("role_sizes", "scenario_balance", "events", "controls", "full_snapshot_guard", "times", "phases",
               "streams", "role_order")


def ks_row(distance, what="start"):
    return (f"{what} phases fail the Kolmogorov-Smirnov test against the uniform law at 5 %: distance {distance:.4f} "
            f"above the critical 0.0797 of 286 {what}s")


def ks_rows(plan):
    """The KS rows of the starts and of the stops of the plan, with the distances of its phases as counted here."""
    return [ks_row(_ks([_ends(x)[i] % 5000 / 5000 for s in plan["sessions"] for x in _items(s)]), what)
            for i, what in enumerate(("start", "stop"))]


def _label(s):
    return f"{s['group']}#{s['position']}"


def _block(group):
    return (int(group.rsplit("-", 1)[1]) - 1) // 4 + 1


def _seconds(value):
    """A time as the self-check writes it: at most three decimals, no trailing zeros."""
    return f"{value:.3f}".rstrip("0").rstrip(".")


def _ms(seconds):
    return round(seconds * 1000)


def _items(s):
    """The events or the dealt controls of a session."""
    return [x for x in s.get("events", []) + s.get("controls", []) if x.get("kind", "") is not None]


def _ends(x):
    """(start, stop) of an item in ms."""
    return _ms(x["start_s"]), _ms(x["start_s"]) + _ms(x["duration_s"])


def _move(x, start, stop):
    """The item starts at `start` and stops at `stop` (ms)."""
    x["start_s"], x["duration_s"] = start / 1000, (stop - start) / 1000


def _tenths(x):
    """(start tenth, stop tenth) of an item: the tenths of 0.5 s of the 5 s interval its start and its stop lie in."""
    start, stop = _ends(x)
    return start % 5000 // 500, stop % 5000 // 500


def _ks(values):
    """The Kolmogorov-Smirnov distance of values in [0, 1) from the uniform law."""
    xs, n = sorted(values), len(values)
    return max(max((i + 1) / n - x, x - i / n) for i, x in enumerate(xs))


def _into_guard(x):
    """An item that starts before 1740 s and ends at 1865 s or later starts later by whole intervals, in the first 5 s
    of the guard of the full snapshot at 1800 s (from 60 s before it), and ends where it ended: its phases, the gap
    before it (wider), the one after it and tail_s stay, and it lasts at least 1865 - 1745 = 120 s."""
    start, stop = _ends(x)
    _move(x, start + math.ceil((1740000 - start) / 5000) * 5000, stop)


def _spanning(item):
    return item["start_s"] < 1740 and item["start_s"] + item["duration_s"] >= 1865


def _controls(plan):
    """(session, control) of every dealt control of the plan."""
    return [(s, x) for s in plan["sessions"] for x in s.get("controls", []) if x["kind"] is not None]


def _card_counts(items):
    """(occurrences per card and VM, occurrences per card and scenario) of the (session, control) pairs."""
    return (Counter((x["kind"], x["polarity"], s["vm"]) for s, x in items),
            Counter((x["kind"], x["polarity"], s["scenario"]) for s, x in items))


def _types(s):
    """The event types of session s."""
    return {x["type"] for x in s["events"]}


def _kinds(s, but):
    """The kinds of the dealt controls of session s other than the control `but`."""
    return {x["kind"] for x in s["controls"] if x is not but and x["kind"] is not None}


def _trade(x, y, keys):
    for key in keys:
        x[key], y[key] = y[key], x[key]


# Changes of the file: doc -> the failures they cause {check: reasons}.

def unknown_key(doc):
    doc["extra"] = 1
    return {"keys": ["unknown protocol key: extra"], "loader": ["protocol(): unknown protocol key: extra"]}


def missing_key(doc):
    del doc["scenario_rule"]
    return {"keys": ["missing protocol key: scenario_rule"],
            "loader": ["protocol(): missing protocol key: scenario_rule"]}


def gate_085(doc):
    doc["min_score_coverage"] = .85  # max 3: three isolated rows leave 557 of 720
    return {"loader": [UNREACHABLE], "reachability": [OUTSIDE, REFUSED]}


def max_7(doc):
    doc["invalid_rows"]["max"] = 7
    return {"loader": [UNREACHABLE], "reachability": ["invalid_rows.max above 6", OUTSIDE, REFUSED]}


def six_groups(doc):
    doc["roles"]["dev"] = 6
    return {"role_sizes": ["groups of role dev are not a multiple of 4"]}


def below_min_per_type(doc):
    doc["events"]["min_per_type"]["train"] = 13  # 12 groups, 24 sessions with three events: 12 of each type
    return {"events": [f"role train: type {t} has 12 events, below min_per_type 13" for t in TYPES]}


def not_interleaved(doc):
    doc["interleave"] = []
    reason = "test_benign and test_controls are not interleaved"
    return {"role_order": [reason], "rehearsal": ["role_order: " + reason]}


def no_min_per_type(doc):
    """F6 of the B4 verification: an empty min_per_type would silently drop the minimum counts of every role."""
    doc["events"]["min_per_type"] = {}
    return {"loader": ["protocol(): invalid events"],
            "events": [f"role {role} has no min_per_type" for role in ("train", "dev", "calibration", "test_benign")]}


def replacement_without_covers(doc):
    """F7 of the B4 verification: without covers the loader took the schema-2 default ['audit_rejected']."""
    del doc["replacement"]["covers"]
    return {"keys": ["missing protocol key: replacement.covers"],
            "loader": ["protocol(): missing protocol key: replacement.covers"]}


def method_without_grid(doc):
    del doc["analysis"]["methods"]["Z1"]["grid"]
    return {"keys": ["missing protocol key: analysis.methods.Z1.grid"],
            "loader": ["protocol(): missing protocol key: analysis.methods.Z1.grid"],
            "analysis": ["missing analysis key: analysis.methods.Z1.grid"]}


def k2a_without_z4(doc):
    """The lead's must_fix 4 on B4: K2a is decided against Z1, Z2 and Z4 (proposal 4.1). Package B7b (question Q13,
    provisional): against both variants of Z4, so one variant left out fails."""
    doc["analysis"]["k2a"]["compare"].remove("Z4:residual")
    return {"analysis": ['analysis.k2a.compare is ["Z1", "Z2", "Z4:load"], proposal 4.1 names ["Z1", "Z2", '
                         '"Z4:load", "Z4:residual"]']}


def null_outside(doc):
    """Package B6a renamed analysis.column_mask to analysis.columns (design B6a 1.1); it stays null until G3a."""
    doc["determined_at"]["G3a"].remove("analysis.columns")
    return {"analysis": ["null outside determined_at: analysis.columns"]}


# Package B6a (design B6a 1.1): one deliberate error in each key it adds to the analysis plan; the loader refuses the
# section, every other check gives what it gives for the real file.
INVALID_ANALYSIS = {"loader": ["protocol(): invalid analysis"]}


def identity_auc_half(doc):
    """max(AUC, 1 - AUC) is at least 0.5: a bound of 0.5 fails every column (it must lie in (0.5, 1))."""
    doc["analysis"]["qualification"]["identity_auc"] = .5
    return INVALID_ANALYSIS


def differenced_outside_levels(doc):
    """The classes of G3a: only a level column may be replaced by its first difference."""
    from features.archive import BEHAVIOR_NAMES
    doc["analysis"]["columns"] = dict(dict.fromkeys(BEHAVIOR_NAMES, "neural"), mem_changed_ratio="differenced")
    return INVALID_ANALYSIS


def floor_without_a_column(doc):
    """The scale floor names each of the 20 columns."""
    del doc["analysis"]["scale"]["floor"]["proc_total"]
    return INVALID_ANALYSIS


def receptive_field_short(doc):
    """Three blocks of kernel 3 see 1 + 2 x 2 x 7 = 29 rows, fewer than the window of 32 (tcn/model.py)."""
    doc["analysis"]["architecture"]["blocks"] = 3
    return INVALID_ANALYSIS


# Package B7a (design B7a 1.6): one deliberate error in each key it adds or changes; the loader refuses the section
# (analysis, or streams for its purposes), every other check gives what it gives for the real file.

def grid_of_a_method_without_parameters(doc):
    """Z2 has no free parameter (skeleton B7 section 2): its grid is {} from G0 on, never a grid of values."""
    doc["analysis"]["methods"]["Z2"]["grid"] = {"tolerance": [0, 1]}
    return INVALID_ANALYSIS


def grid_of_z3_outside_determined_at(doc):
    """Only the grids of Z1, Z3 and Z5 wait for G3a, each by its own path: without its path the null grid of Z3 lies
    outside determined_at."""
    doc["determined_at"]["G3a"].remove("analysis.methods.Z3.grid")
    return {"analysis": ["null outside determined_at: analysis.methods.Z3.grid"]}


def selection_without_z1(doc):
    """The selection states the rule of every method: a text that leaves Z1 out (selected by the interventions
    detected in dev, skeleton B7 section 2) is refused."""
    doc["analysis"]["selection"] = ("Z3 and Z5 by their prediction loss on dev, M by the rule of analysis.stopping; "
                                    "Z0, Z2 and Z4 have no free parameter.")
    return INVALID_ANALYSIS


def gru_on_four_seeds(doc):
    """GRU and LSTM run on every seed of analysis.seeds (skeleton B7, addendum 2 point 1)."""
    doc["analysis"]["descriptive_methods"]["gru"]["seeds"] = [0, 1, 2, 3]
    return INVALID_ANALYSIS


def wording_without_a_blank(doc):
    """The wording of "better" holds the two blanks of chapter 8.4 (the methods and the difference)."""
    doc["analysis"]["wording"]["k1"]["better"] = ("neurónový kanál využíva naučenú štruktúru; rozdiel oproti … "
                                                  "je výrazný")
    return INVALID_ANALYSIS


def z0_without_repetitions(doc):
    """The random variant of Z0 takes at least one repetition (the file: 200)."""
    doc["analysis"]["matched_rate"]["z0_repetitions"] = 0
    return INVALID_ANALYSIS


def level_of_95(doc):
    """The level of the interval is a share in (0, 1): 0.95, chapter 8.4."""
    doc["analysis"]["statistics"]["level"] = 95
    return INVALID_ANALYSIS


# Package B7b (design B7b 1.4): one deliberate error in each key it adds or changes; the loader refuses the section
# (analysis, or streams for its purposes), every other check gives what it gives for the real file.

def c_without_orders(doc):
    """Class C names its orders, reversed and random (proposal 7.4): without them the layout misses a key."""
    del doc["analysis"]["interventions"]["C"]["orders"]
    reason = "missing protocol key: analysis.interventions.C.orders"
    return {"keys": [reason], "loader": ["protocol(): " + reason], "analysis": ["missing analysis key: "
                                                                              "analysis.interventions.C.orders"]}


def groups_share_a_column(doc):
    """The groups of class D partition the inputs of the neural channel: proc_wx in processes and in memory as well is
    refused."""
    doc["analysis"]["interventions"]["D"]["groups"]["memory"].append("proc_wx")
    return INVALID_ANALYSIS


def validity_quantiles_reversed(doc):
    """The validity predicate lies between a lower and a higher quantile of role train (0.001 and 0.999)."""
    doc["analysis"]["interventions"]["validity"]["quantiles"] = [.999, .001]
    return INVALID_ANALYSIS


def min_evaluable_apart_from_min_occurrences(doc):
    """Proposal 6.4 states one rule for a type or a class: the evaluable minimum of the interventions is
    analysis.min_occurrences (8), not another number."""
    doc["analysis"]["interventions"]["min_evaluable"] = 7
    return INVALID_ANALYSIS


def contexts_not_increasing(doc):
    """The contexts of the diagnostics are increasing lengths: 16 after 31 is refused."""
    doc["analysis"]["diagnostics"]["contexts"] = [1, 2, 4, 8, 31, 16]
    return INVALID_ANALYSIS


def k2a_with_z4_unsplit(doc):
    """Question Q13 (provisional): Z4 enters K2a by each variant, so a bare Z4 names no comparison; the analysis check
    names the comparisons of proposal 4.1 with the two variants."""
    doc["analysis"]["k2a"]["compare"] = ["Z1", "Z2", "Z4"]
    return {"loader": ["protocol(): invalid analysis"],
            "analysis": ['analysis.k2a.compare is ["Z1", "Z2", "Z4"], proposal 4.1 names ["Z1", "Z2", "Z4:load", '
                         '"Z4:residual"]']}


def grid_longer_than_the_window(doc):
    """F3 of the verification of B7a: a moving average of Z1 reads at most the window_rows (32) rows of a window, so a
    filled grid with 33 is refused by the protocol as tcn/metody.py refuses it."""
    doc["analysis"]["methods"]["Z1"]["grid"] = {"moving_average_rows": [33], "cusum_shift": [.5]}
    return INVALID_ANALYSIS


def validity_average_longer_than_the_window(doc):
    """F2 of the verification of B7b: the moving average of the validity predicate is taken over the last rows of a
    window of train, so 33 rows (more than the window_rows 32) are refused by the protocol as tcn/zasahy.py refuses
    them."""
    doc["analysis"]["interventions"]["validity"]["moving_average_rows"] = 33
    return INVALID_ANALYSIS


def context_of_the_whole_window(doc):
    """F2 of the verification of B7b: a window holds its target and at most window_rows - 1 (31) rows of context, so a
    context of 32 rows is refused by the protocol as tcn/diagnostiky.py refuses it."""
    doc["analysis"]["diagnostics"]["contexts"] = [1, 2, 4, 8, 16, 32]
    return INVALID_ANALYSIS


# Package B7c (design B7c 1.2): one deliberate error in each key it adds; the loader refuses the section, and the
# self-check names a reworded row of the linkage table (as it names the methods of the claims).

def garwood_level_of_95(doc):
    """The level of the thesis' interval is a share in (0, 1): 0.95."""
    doc["analysis"]["metrics"]["alarm_rate_interval"]["level"] = 95
    return INVALID_ANALYSIS


def event_test_two_sided(doc):
    """The thesis' test of the events against clean traffic is one-sided (more alarms during events)."""
    doc["analysis"]["metrics"]["event_vs_clean"]["alternative"] = "two-sided"
    return INVALID_ANALYSIS


def o2_bound_by_garwood(doc):
    """O2 needs the one-sided bound (proposal 4.2 and 9.2), not the two-sided interval of the thesis."""
    doc["analysis"]["metrics"]["o2_bound"]["method"] = "garwood"
    return INVALID_ANALYSIS


def linkage_reworded(doc):
    """The linkage table is the lead's word for word (skeleton B7, addendum 2 point 4): VO2 without the test of point 2
    is named by the self-check."""
    doc["analysis"]["linkage"]["VO2"] = "O2 a O3 (E2)"
    return {"analysis": ['analysis.linkage.VO2 is "O2 a O3 (E2)", the lead\'s table (skeleton B7, addendum 2 point 4) '
                         'says "O2, O3 a test z bodu 2 (E2)"']}


def linkage_not_a_text(doc):
    """Each row of the linkage table is a text."""
    doc["analysis"]["linkage"]["VO5"] = ["O7"]
    return {"loader": ["protocol(): invalid analysis"],
            "analysis": ['analysis.linkage.VO5 is ["O7"], the lead\'s table (skeleton B7, addendum 2 point 4) says '
                         '"O7 (E5)"']}


def streams_without_injections(doc):
    """streams.purposes names injections, the stream of the interventions (package B7b)."""
    doc["streams"]["purposes"].remove("injections")
    return {"loader": ["protocol(): invalid streams"]}


def streams_without_bootstrap(doc):
    """streams.purposes names every purpose of PURPOSES, the two streams of the analysis included."""
    doc["streams"]["purposes"].remove("bootstrap")
    return {"loader": ["protocol(): invalid streams"]}


def rehearsal_name(doc):
    doc["rehearsal"]["name_suffix"] = ""
    return {"rehearsal": ["rehearsal name equals the campaign name"]}


def rehearsal_prefix(doc):
    doc["rehearsal"]["group_prefix"] = doc["group_prefix"]
    return {"rehearsal": ["rehearsal group prefix equals the campaign prefix"]}


def unknown_to_lab(doc):
    doc["events"]["types"]["zamok_databazy"] = doc["events"]["types"].pop("zamok_tabulky")
    # Package B9b: audit.early_stop has one rate per event type, so the renamed type keeps its rate there.
    rates = doc["audit"]["early_stop"]["marked_rows_rate_per_type"]
    rates["zamok_databazy"] = rates.pop("zamok_tabulky")
    return {"lab_register": ["unknown to lab/: zamok_databazy"]}


def unknown_profile(doc):
    doc["scenarios"]["corp_low"]["profile"] = "batch"  # No profile of the profiles section, none of the generator.
    return {"loader": ["protocol(): invalid profiles"], "lab_register": ["unknown to lab/: batch"]}


def think_below_mean(doc):
    doc["profiles"]["eshop"]["think_s"]["max"] = 5  # Below the mean of 7 s.
    return {"loader": ["protocol(): invalid profiles"]}


# Package B8: the controls section (design B8 1.1) and the lab's register of its kinds (skeleton B8 section 5 item 6).
CANDIDATES = '["crc7", "crc8", "ts_kmp"]'


def module_without_candidates(doc):
    """The module kind names its candidates (design B8 1.1): without them the layout misses a key, and the protocol
    no longer names the candidates lab/udalosti.py tries."""
    del doc["controls"]["kinds"]["kontrola_modul_jadra"]["candidates"]
    reason = "missing protocol key: controls.kinds.kontrola_modul_jadra.candidates"
    return {"keys": [reason], "loader": ["protocol(): " + reason],
            "lab_register": ["control kind kontrola_modul_jadra: candidates null differs from lab/udalosti.py "
                             + CANDIDATES]}


def dose_unknown_to_lab(doc):
    """A dose the guest does not run (lab/udalosti.py DOSES; it refuses any other): the file loads and plans the dose,
    lab_register fails."""
    doc["controls"]["kinds"]["kontrola_davka_procesov"]["doses"] = [2, 10, 40]
    return {"lab_register": ["control kind kontrola_davka_procesov: doses [2, 10, 40] differs from lab/udalosti.py "
                             "[2, 10, 50]"]}


def per_dose_short(doc):
    """The counts per dose of the writer sum to 6, not to per_kind 7: the file does not load, and the plan cannot deal
    its seven controls a dose each (a rehearsal deals two of them and can)."""
    doc["controls"]["kinds"]["kontrola_zapisovac_pamate"]["per_dose"] = [2, 2, 2]
    reason = "no plan: the doses of kontrola_zapisovac_pamate/control do not fit its occurrences per VM"
    return {"loader": ["protocol(): invalid controls"], **{name: [reason] for name in PLAN_CHECKS}}


def boots_apart_from_the_carriers(doc):
    """Package B9a (F3 of the verification of B7c): analysis.interventions.boots is the count of the boots of the
    carrier roles of the campaign plan, 12 groups of test_benign and 8 of test_controls; tcn/k2.py refused another
    count only in the final evaluation, after the seal is consumed. The loader does not bind it (the test protocols
    take this section with other role sizes), the self-check does."""
    doc["analysis"]["interventions"]["boots"] = 21
    return {"analysis": ["analysis.interventions.boots is 21, the carrier roles of the campaign plan hold 20 boots "
                         "(test_benign 12, test_controls 8)"]}


def seeded_level_of_19_digits(doc):
    """The fix of package B9a (F4 of its verification, Q18): the one seeded level of every group is a seed of
    lab/guest_state.py reset --seed, which takes 1 to 18 digits, so 10^18 is refused by the loader."""
    doc["streams"]["seeded_level"]["seed"] = 10 ** 18
    return {"loader": ["protocol(): invalid streams.seeded_level"]}


def early_stop_rate_below_zero(doc):
    """Package B9b (design B9b 1.3) and its fix (F5 of its verification, Q24): the early stop holds a rate of marked
    rows per occurrence for every event type, null until G3b; a negative one is refused by the value check of the
    audit section (features/audit_policy.py audit_bounds), which the loader and the witnesses of the reachability
    check both read."""
    doc["audit"]["early_stop"]["marked_rows_rate_per_type"]["restart_databazy"] = -0.5
    reason = "invalid audit bounds: early_stop.marked_rows_rate_per_type"
    return {"loader": ["protocol(): " + reason], "reachability": ["cannot check: " + reason]}


def _unplannable(shape):
    """The failures of a file that loads but cannot be planned because a group cannot hold one full round of the six
    types over two sessions with events (F1 of the verification of B4b): every check of the plan and the rehearsal
    name the reason, which ends with the shape of the file."""
    reason = ("events of role train: one full round of the types per group needs two sessions with events and twice "
              f"as many types as a session holds ({shape})")
    return {**{name: ["no plan: " + reason] for name in PLAN_CHECKS}, "rehearsal": ["no rehearsal plan: " + reason]}


def two_events_per_session(doc):
    """Sessions of two events: a group's two sessions with events hold four of the six types."""
    doc["events"]["per_session"] = [0, 2]
    return _unplannable("6 types, 2 per session, 2 sessions with events per group")


def no_event_free_session(doc):
    """No event-free session: a group has three sessions with events, nine events of six types."""
    doc["events"]["per_session"] = [3]
    return _unplannable("6 types, 3 per session, 3 sessions with events per group")


# Changes of the plan of the real file: (doc, plan) -> the failures.

def no_group_on_vm(doc, plan):
    """Every group of dev moves to VM a. B4b: every group holds every type once, so every type of dev then has its 4
    events on VM a and none on VM b (F1 of the verification of B4b). B9a (S3 of the B4 verification): the 4 groups
    of dev per VM, 4 and 0, differ by more than 1 as well."""
    for s in plan["sessions"]:
        if s["role"] == "dev":
            s["vm"] = "a"
    return {"role_sizes": ["role dev has no group on VM b", "role dev: groups per VM differ by more than 1"],
            "events": [f"role dev: events of type {t} per VM differ by more than 1" for t in TYPES]}


def equal_scenarios(doc, plan):
    """The second session of a group of train takes the first one's scenario: in its complete block that scenario is
    then twice at position 1. The group is one where the scenario counts of its VM stay within 1. B4b: the second
    session's events (or its being event-free) now count under the first one's scenario, and train holds every type
    and its event-free sessions equally often in every scenario, so each of its types (or the event-free sessions)
    then differs by 2 between the two scenarios."""
    sessions = plan["sessions"]
    for first, second in zip(sessions, sessions[1:]):
        if (first["role"] == "train" and first["group"] == second["group"]
                and (first["position"], second["position"]) == (0, 1)):
            counts = Counter(s["scenario"] for s in sessions if (s["role"], s["vm"]) == (first["role"], first["vm"]))
            if counts[first["scenario"]] < counts[second["scenario"]]:
                break
    second["scenario"] = first["scenario"]
    events = ([f"role train: events of type {t} per scenario differ by more than 1"
               for t in sorted({x["type"] for x in second["events"]})] if second["events"]
              else ["role train: event-free sessions per scenario differ by more than 1"])
    return {"scenario_balance": [f"group {first['group']} repeats scenario {first['scenario']}",
                                 f"scenario {first['scenario']} twice at position 1 in block "
                                 f"{first['role']}/{_block(first['group'])}"], "events": events}


def twice_at_position(doc, plan):
    """The first two sessions of v5-train-1 swap their scenarios: no group repeats one and no VM count changes."""
    first, second = plan["sessions"][:2]
    assert (first["group"], first["position"], second["group"], second["position"]) == ("v5-train-1", 0,
                                                                                       "v5-train-1", 1)
    first["scenario"], second["scenario"] = second["scenario"], first["scenario"]
    # B4b: the events of the two sessions change scenario with them; a type only one of them holds (and the
    # event-free session, when it is one of them) then differs by 2 between the two scenarios.
    held = [{x["type"] for x in s["events"]} for s in (first, second)]
    free = [] if first["events"] and second["events"] else [
        "role train: event-free sessions per scenario differ by more than 1"]
    return {"scenario_balance": [f"scenario {first['scenario']} twice at position 0 in block train/1",
                                 f"scenario {second['scenario']} twice at position 1 in block train/1"],
            "events": free + [f"role train: events of type {t} per scenario differ by more than 1"
                              for t in sorted(held[0] ^ held[1])]}


def two_events(doc, plan):
    """A session of train loses an event. B4b: one whose start and stop lie in tenths of the interval that train has
    most often (8 of its 72 starts or stops), so the tenths of the role stay within 1."""
    train = [x for s in plan["sessions"] if s["role"] == "train" for x in s["events"]]
    starts, stops = [Counter(_tenths(x)[i] for x in train) for i in (0, 1)]
    s, removed = next((s, x) for s in plan["sessions"] if s["role"] == "train" for x in s["events"]
                      if starts[_tenths(x)[0]] == max(starts.values()) and stops[_tenths(x)[1]] == max(stops.values()))
    s["events"].remove(removed)
    return {"events": [f"session {_label(s)} has 2 events (allowed [0, 3])",
                       f"role train: type {removed['type']} has 11 events, below min_per_type 12"]}


def start_in_guard(doc, plan):
    """An event that spans the full snapshot of row 360 (1800 s) starts in its guard (_into_guard). B4b: by whole
    intervals and with its stop kept, so it keeps its phases and every rule but the guard."""
    s, x = next((s, x) for s in plan["sessions"] for x in s.get("events", []) if _spanning(x))
    _into_guard(x)
    return {"full_snapshot_guard": [f"{_label(s)}: {x['type']} starts at {_seconds(x['start_s'])} s inside the guard "
                                    "of the full snapshot at 1800 s"]}


def locked_to_grid(doc, plan):
    """Every start moves back to the start of its interval. B4b: so does every stop, which keeps the gaps, the
    duration spans, first_s, tail_s and the guards (multiples of 5 s); every role then has its starts and stops in
    tenth 0, and every start phase and every stop phase is 0."""
    for s in plan["sessions"]:
        for item in _items(s):
            start, stop = _ends(item)
            _move(item, start // 5000 * 5000, stop // 5000 * 5000)
    return {"phases": TENTH_ROWS + [ks_row(1), ks_row(1, "stop")]}


def same_nonzero_phase(doc, plan):
    """S1 of the B4 verification: every start and every stop moves within its interval to phase 2.5 s, which the
    phase check of B4 let pass. Whole intervals keep the gaps, the duration spans, first_s and the guards, and tail_s
    holds because no stop lies at 3240 s, the latest one tail_s allows."""
    for s in plan["sessions"]:
        for item in _items(s):
            start, stop = _ends(item)
            assert stop < 3240000
            _move(item, start // 5000 * 5000 + 2500, stop // 5000 * 5000 + 2500)
    return {"phases": TENTH_ROWS + [ks_row(.5), ks_row(.5, "stop")]}


def one_second_grid(doc, plan):
    """S1 of the B4 verification: every start and every stop moves back to a whole second (phases 0 to 4 s), which
    the phase check of B4 let pass; the rules are whole seconds and still hold. Every role then has its starts and
    stops in the even tenths only; the distances are the ones of the moved phases, computed here."""
    for s in plan["sessions"]:
        for item in _items(s):
            start, stop = _ends(item)
            _move(item, start // 1000 * 1000, stop // 1000 * 1000)
    return {"phases": TENTH_ROWS + ks_rows(plan)}


def phases_at_tenth_edges(doc, plan):
    """must_fix 6: every start and every stop moves back to the start of its tenth (a multiple of 0.5 s): the tenths
    stay as they are in every role, yet the start phases and the stop phases leave the uniform law, which only the
    two KS rows see (the one of the stops since F2 of the verification of B4b). The rules are multiples of 0.5 s and
    still hold. The distances are the ones of the moved phases, computed here."""
    for s in plan["sessions"]:
        for item in _items(s):
            start, stop = _ends(item)
            _move(item, start // 500 * 500, stop // 500 * 500)
    return {"phases": ks_rows(plan)}


def stops_at_interval_start(doc, plan):
    """must_fix 6: every event of dev that lasts 125 s or more ends at the start of its interval (shorter by its stop
    phase, never below 120 s): the stops of dev crowd into tenth 0, its starts and every other role keep theirs.
    B4b: 23 of the 286 stops of the plan then lie at phase 0, which lifts the KS distance of the stops above its
    critical value (computed here, F2 of the verification of B4b)."""
    for s in plan["sessions"]:
        for item in s["events"] if s["role"] == "dev" else []:
            if item["duration_s"] >= 125:
                start, stop = _ends(item)
                _move(item, start, stop // 5000 * 5000)
    return {"phases": ["role dev: stops per tenth of the interval differ by more than 1", ks_rows(plan)[1]]}


def stops_at_tenth_edges(doc, plan):
    """F2 of the verification of B4b: every stop moves back to the lower edge of its tenth of the interval where the
    item still lasts 120 s or more (all but one item): the tenths of the stops stay in every role, the starts stay,
    and every rule holds (a stop only moves earlier, by less than 0.5 s); only the KS row of the stops sees it. The
    distance is the one of the moved stops, computed here."""
    for s in plan["sessions"]:
        for item in _items(s):
            start, stop = _ends(item)
            if stop // 500 * 500 - start >= 120000:
                _move(item, start, stop // 500 * 500)
    return {"phases": [ks_rows(plan)[1]]}


def before_first_s(doc, plan):
    """S1: the first event of a session starts at about 200 s, before first_s 300 s (earlier by whole intervals, with
    its duration and phases): the gap after it only widens."""
    s = next(s for s in plan["sessions"] if s.get("events"))
    x = s["events"][0]
    start, stop = _ends(x)
    shift = (start - 200000) // 5000 * 5000
    _move(x, start - shift, stop - shift)
    return {"times": [f"{_label(s)}: {x['type']} starts at {_seconds(x['start_s'])} s, before first_s 300 s"]}


def overlapping_events(doc, plan):
    """S1: the second event of a session starts 5 to 10 s before the first one ends (earlier by whole intervals, with
    its duration and phases). The first one ends before 1740 s, so the moved start lies in no guard."""
    s = next(s for s in plan["sessions"] if s.get("events") and _ends(s["events"][0])[1] < 1740000)
    first, second = s["events"][:2]
    end, (start, stop) = _ends(first)[1], _ends(second)
    shift = ((start - end) // 5000 + 2) * 5000
    _move(second, start - shift, stop - shift)
    return {"times": [f"{_label(s)}: {second['type']} starts less than min_gap_s 480 s after the item before it ends"]}


def duration_2000(doc, plan):
    """S1: the first event of a session that starts before 1235 s lasts 2000 s to 2005 s (longer by whole intervals,
    with its phases): it ends before 3240 s, so tail_s holds, but the second event starts less than min_gap_s after
    it, since the second of three events never starts after 3600 - 360 - 2 * 120 - 480 = 2520 s."""
    s = next(s for s in plan["sessions"] if s.get("events") and s["events"][0]["start_s"] < 1235)
    first, second = s["events"][:2]
    start, stop = _ends(first)
    _move(first, start, stop + math.ceil((2000000 - (stop - start)) / 5000) * 5000)
    return {"times": [f"{_label(s)}: {first['type']} lasts {_seconds(first['duration_s'])} s, outside duration_s "
                      "[120, 360]",
                      f"{_label(s)}: {second['type']} starts less than min_gap_s 480 s after the item before it ends"]}


def ends_in_tail(doc, plan):
    """S1: the last event of a session moves later by whole intervals until it ends less than tail_s 360 s before the
    end of the session (by at most 5 s); it then starts after 2880 s, past every guard."""
    s = next(s for s in plan["sessions"] if s.get("events"))
    x = s["events"][-1]
    start, stop = _ends(x)
    shift = ((3240000 - stop) // 5000 + 1) * 5000
    _move(x, start + shift, stop + shift)
    return {"times": [f"{_label(s)}: {x['type']} ends less than tail_s 360 s before the end of the session (3600 s)"]}


def event_free_scenarios(doc, plan):
    """must_fix 5: two groups of train trade the positions of their event-free sessions (the counts per position
    stay), so that both event-free sessions move to one scenario, which then has two more. The events of the sessions
    that become event-free move to the scenarios the event-free sessions left; train holds every type equally often
    in every scenario, so each of their types then differs by 2 or more (fewer events in one scenario need fewer of
    some type there: the two properties cannot break apart)."""
    groups = {}
    for s in plan["sessions"]:
        if s["role"] == "train":
            groups.setdefault(s["group"], []).append(s)

    def free(ss):
        return next(s["position"] for s in ss if not s["events"])
    a, b = next((a, b) for a in groups.values() for b in groups.values()
                if free(a) != free(b) and a[free(b)]["scenario"] == b[free(a)]["scenario"])
    p, q = free(a), free(b)
    moved = {x["type"] for x in a[q]["events"] + b[p]["events"]}
    a[p]["events"], a[q]["events"] = a[q]["events"], a[p]["events"]
    b[q]["events"], b[p]["events"] = b[p]["events"], b[q]["events"]
    return {"events": ["role train: event-free sessions per scenario differ by more than 1"]
            + [f"role train: events of type {t} per scenario differ by more than 1" for t in sorted(moved)]}


def type_scenarios(doc, plan):
    """must_fix 5: two events of train in sessions of different scenarios trade their types (neither session held the
    type it gets): each of the two types is then once more in one scenario and once less in the other. B4b: the two
    sessions are the two sessions with events of one group, so the group still holds every type once (F1 of the
    verification of B4b) and no count per VM changes."""
    events = [(s, x) for s in plan["sessions"] if s["role"] == "train" for x in s["events"]]
    x, y = next((x, y) for s, x in events for t, y in events
                if s["group"] == t["group"] and s["scenario"] != t["scenario"] and x["type"] != y["type"]
                and y["type"] not in _types(s) and x["type"] not in _types(t))
    _trade(x, y, ("type", "class"))
    return {"events": [f"role train: events of type {t} per scenario differ by more than 1"
                       for t in sorted({x["type"], y["type"]})]}


def _group_rows(plan, held):
    """'group G holds type T twice' for the (group, type) pairs `held`, in the order of the groups in the plan."""
    order = list(dict.fromkeys(s["group"] for s in plan["sessions"]))
    return [f"group {group} holds type {t} twice"
            for group, t in sorted(held, key=lambda pair: (order.index(pair[0]), pair[1]))]


def type_twice(doc, plan):
    """What the lead found in B4 and B4b keeps (no type twice in a session): two sessions of train in one scenario
    and on one VM trade a type so that the first one holds a type twice; no count per scenario or VM changes. B4b:
    every group holds every type once (F1 of the verification of B4b), so the first session's group then holds that
    type twice as well, and the second session's group the type it got (its other session with events has it)."""
    sessions = [s for s in plan["sessions"] if s["role"] == "train" and s["events"]]
    s, t, x, y = next((s, t, x, y) for s in sessions for t in sessions
                      if t is not s and (t["scenario"], t["vm"]) == (s["scenario"], s["vm"])
                      for x in s["events"] for y in t["events"] if y["type"] != x["type"]
                      and y["type"] in _types(s) and x["type"] not in _types(t))
    twice, got = y["type"], x["type"]
    _trade(x, y, ("type", "class"))
    return {"events": [f"session {_label(s)} holds type {twice} twice"]
            + _group_rows(plan, [(s["group"], twice), (t["group"], got)])}


def group_twice(doc, plan):
    """F1 of the verification of B4b: two events of train in one scenario and on one VM, in two groups, trade their
    types. Neither session held the type it gets, so no session holds a type twice and no count per role, scenario
    or VM changes; but every group holds every type once, so each of the two groups then holds the type it got
    twice (its other session with events has it) and the type it gave not at all."""
    events = [(s, x) for s in plan["sessions"] if s["role"] == "train" for x in s["events"]]
    s, t, x, y = next((s, t, x, y) for s, x in events for t, y in events
                      if s["group"] != t["group"] and (s["scenario"], s["vm"]) == (t["scenario"], t["vm"])
                      and y["type"] not in _types(s) and x["type"] not in _types(t))
    _trade(x, y, ("type", "class"))
    return {"events": _group_rows(plan, [(s["group"], x["type"]), (t["group"], y["type"])])}


def type_vm(doc, plan):
    """F1 of the verification of B4b: a group of train moves to the other VM. Every group holds every type once, so
    every type then has 7 events on one VM and 5 on the other. The group misses a scenario that its new VM holds 5
    times and its old one 4 (train has 18 sessions on each VM, 5, 5, 4 and 4 per scenario), so the scenario counts of
    both VMs stay within 1. B9a (S3 of the B4 verification): the groups of train per VM, 7 and 5, differ by more than
    1 as well."""
    train, other = [s for s in plan["sessions"] if s["role"] == "train"], {"a": "b", "b": "a"}
    on_vm = Counter((s["vm"], s["scenario"]) for s in train)
    groups = {}
    for s in train:
        groups.setdefault(s["group"], []).append(s)
    ss = next(ss for ss in groups.values()
              if all(on_vm[other[ss[0]["vm"]], n] == 5 for n in set(SCENARIOS) - {s["scenario"] for s in ss}))
    for s in ss:
        s["vm"] = other[s["vm"]]
    return {"role_sizes": ["role train: groups per VM differ by more than 1"],
            "events": [f"role train: events of type {t} per VM differ by more than 1" for t in TYPES]}


def card_vm(doc, plan):
    """must_fix 5: two controls of one scenario on different VMs trade their cards. Both cards had 3 of their 7
    occurrences on the first control's VM: the first card then has 2 there and 5 on the other VM, the second one 4 and
    3. Neither session held the kind it gets. B8: both cards are of class A (no dose), so no dose moves to another
    VM (the doses of a card are within 1 on every VM, check controls)."""
    items = _controls(plan)
    per_vm, _ = _card_counts(items)
    x, y = next((x, y) for s, x in items for t, y in items
                if s["scenario"] == t["scenario"] and s["vm"] != t["vm"]
                and (x["kind"], x["polarity"]) != (y["kind"], y["polarity"]) and x["dose"] is y["dose"] is None
                and per_vm[x["kind"], x["polarity"], s["vm"]] == 3 and per_vm[y["kind"], y["polarity"], s["vm"]] == 3
                and x["kind"] not in _kinds(t, y) and y["kind"] not in _kinds(s, x))
    card = f"{x['kind']}/{x['polarity']}"
    _trade(x, y, ("kind", "polarity", "class", "dose"))
    return {"controls": [f"control {card}: occurrences per VM differ by more than 1"]}


def card_scenario(doc, plan):
    """must_fix 5: two controls on one VM in different scenarios trade their cards. The first card had 2 occurrences
    in the second scenario and has 3 then; the second card had its single occurrence of a scenario in the first one
    and stays within 1. Neither session held the kind it gets. B8: a card takes its dose along; the VM stays."""
    items = _controls(plan)
    _, per_scenario = _card_counts(items)
    x, y = next((x, y) for s, x in items for t, y in items
                if s["vm"] == t["vm"] and s["scenario"] != t["scenario"]
                and (x["kind"], x["polarity"]) != (y["kind"], y["polarity"])
                and per_scenario[x["kind"], x["polarity"], t["scenario"]] == 2
                and per_scenario[y["kind"], y["polarity"], s["scenario"]] == 1
                and x["kind"] not in _kinds(t, y) and y["kind"] not in _kinds(s, x))
    card = f"{x['kind']}/{x['polarity']}"
    _trade(x, y, ("kind", "polarity", "class", "dose"))
    return {"controls": [f"control {card}: occurrences per scenario differ by more than 1"]}


def kind_twice(doc, plan):
    """must_fix 5: a control trades its card with a control of another session of its (VM, scenario) cell whose kind
    its own session holds already: that session then holds a kind twice; no count per VM or scenario changes. B8: a
    card takes its dose along."""
    items = _controls(plan)
    s, x, y = next((s, x, y) for s, x in items for t, y in items
                   if t is not s and (t["vm"], t["scenario"]) == (s["vm"], s["scenario"]) and y["kind"] != x["kind"]
                   and y["kind"] in _kinds(s, x) and x["kind"] not in _kinds(t, y))
    twice = y["kind"]
    _trade(x, y, ("kind", "polarity", "class", "dose"))
    return {"controls": [f"session {_label(s)} holds control kind {twice} twice"]}


def common_seed(doc, plan):
    s = plan["sessions"][0]
    s["seeds"]["event_times"] = s["seeds"]["traffic"]
    return {"streams": ["purposes event_times and traffic share a seed"]}


def control_relabelled(doc, plan):
    """F1 of the B4 verification: one control card dealt twice, another once less. B4b: the control relabelled lies
    in the (VM, scenario) cell where the first card has no occurrence (3 on that VM, 1 in that scenario), its own
    card has 4 on that VM and 2 in that scenario, and its session holds no control of the first card's kind, so
    neither card leaves the balance per VM and per scenario. B8: the first card is the first one of class A (no dose)
    for which such a control of class A exists, so the counts per dose stay as they are."""
    items = _controls(plan)
    per_vm, per_scenario = _card_counts(items)
    first, other = next((first, x) for _, first in items if first["dose"] is None for s, x in items
                        if x["polarity"] == "control" and x["kind"] != first["kind"] and x["dose"] is None
                        and per_vm[first["kind"], "control", s["vm"]] == 3
                        and per_scenario[first["kind"], "control", s["scenario"]] == 1
                        and per_vm[x["kind"], "control", s["vm"]] == 4
                        and per_scenario[x["kind"], "control", s["scenario"]] == 2
                        and first["kind"] not in _kinds(s, x))
    gone = other["kind"]
    other.update(kind=first["kind"], polarity="control", **{"class": first["class"]})
    expected = sorted([(first["kind"], 8), (gone, 6)])
    return {"controls": [f"control {kind}/control has {n} occurrences (expected 7)" for kind, n in expected]}


def control_slot_emptied(doc, plan):
    """F1: a dealt card replaced by an empty slot: its count falls, and one slot more is empty than the deck leaves.
    B4b: a card with 4 of its occurrences on the session's VM and 2 in its scenario, so it stays within 1 per VM and
    per scenario. B8: a card of class A (no dose), so the counts per dose stay as they are."""
    items = _controls(plan)
    per_vm, per_scenario = _card_counts(items)
    x = next(x for s, x in items if x["dose"] is None and per_vm[x["kind"], x["polarity"], s["vm"]] == 4
             and per_scenario[x["kind"], x["polarity"], s["scenario"]] == 2)
    card = (x["kind"], x["polarity"])
    x.clear()
    x.update(kind=None, reason="deck exhausted")
    return {"controls": [f"control {card[0]}/{card[1]} has 6 occurrences (expected 7)",
                         "3 empty control slots (expected 2)"]}


def _dosed(plan):
    """(session, control) of every dealt control of class B (it has a dose)."""
    return [(s, x) for s, x in _controls(plan) if x["dose"] is not None]


def dose_of_class_a(doc, plan):
    """Package B8 (design B8 1.2): a control of class A has no dose; here the first one gets the writer's first."""
    s, x = next((s, x) for s, x in _controls(plan) if x["dose"] is None)
    x["dose"] = 16
    return {"controls": [f"session {_label(s)}: control {x['kind']}/{x['polarity']} has dose 16 (doses of the kind: "
                         "null)"]}


def dose_unknown(doc, plan):
    """B8: a control of class B dealt a dose twice (once on each VM) gets a dose its kind does not have: its own dose
    is then one short, on the VMs 1 and 0."""
    counts = Counter((x["kind"], x["polarity"], x["dose"]) for _, x in _dosed(plan))
    s, x = next((s, x) for s, x in _dosed(plan) if counts[x["kind"], x["polarity"], x["dose"]] == 2)
    dose, doses = x["dose"], doc["controls"]["kinds"][x["kind"]]["doses"]
    x["dose"] = dose + 1
    return {"controls": [f"session {_label(s)}: control {x['kind']}/{x['polarity']} has dose {dose + 1} (doses of the "
                         f"kind: {json.dumps(doses)})",
                         f"control {x['kind']}/{x['polarity']}: dose {dose} has 1 occurrences (expected 2)"]}


def dose_counts(doc, plan):
    """B8: each dose of a kind of class B has its count among the kind's controls and the same among its negatives. A
    control of a dose dealt twice takes the other dose its card has twice: the first then has 1 occurrence and the
    other 3, on the VMs 0 and 1, and 2 and 1."""
    counts = Counter((x["kind"], x["polarity"], x["dose"]) for _, x in _dosed(plan))
    s, x = next((s, x) for s, x in _dosed(plan) if counts[x["kind"], x["polarity"], x["dose"]] == 2)
    k = doc["controls"]["kinds"][x["kind"]]
    dose, other = x["dose"], next(d for d, n in zip(k["doses"], k["per_dose"]) if n == 2 and d != x["dose"])
    x["dose"] = other
    card = f"{x['kind']}/{x['polarity']}"
    return {"controls": [f"control {card}: dose {d} has {n} occurrences (expected 2)"
                         for d, n in sorted([(dose, 1), (other, 3)], key=lambda pair: k["doses"].index(pair[0]))]}


def dose_vm(doc, plan):
    """B8: the doses of a card lie within 1 on the VMs. Two controls of one card of class B on different VMs trade
    their doses: the first one's dose lies once on each VM, the second one's twice on the second control's VM and
    once on the other. The first dose then lies twice on one VM and never on the other; the counts stay."""
    items = _dosed(plan)
    on = Counter((x["kind"], x["polarity"], x["dose"], s["vm"]) for s, x in items)
    x, y = next((x, y) for s, x in items for t, y in items
                if (x["kind"], x["polarity"]) == (y["kind"], y["polarity"]) and s["vm"] != t["vm"]
                and on[x["kind"], x["polarity"], x["dose"], s["vm"]] == on[x["kind"], x["polarity"], x["dose"], t["vm"]]
                == 1 and on[y["kind"], y["polarity"], y["dose"], t["vm"]] == 2
                and on[y["kind"], y["polarity"], y["dose"], s["vm"]] == 1)
    dose = x["dose"]
    _trade(x, y, ("dose",))
    return {"controls": [f"control {x['kind']}/{x['polarity']}: occurrences of dose {dose} per VM differ by more "
                         "than 1"]}


def event_free_first(doc, plan):
    """F2: in every group of train the event-free session is moved to position 0 (the events change places). Position
    0 of a block holds every scenario once, so the event-free sessions per scenario stay equal. B4b: the events of a
    session at position 0 move to another scenario; every type whose counts per scenario then differ by more than 1
    fails too (counted here: which ones depends on the types the plan drew)."""
    for group in sorted({s["group"] for s in plan["sessions"] if s["role"] == "train"}):
        ss = [s for s in plan["sessions"] if s["group"] == group]
        free = next(s for s in ss if not s["events"])
        ss[0]["events"], free["events"] = free["events"], ss[0]["events"]
    cells = Counter((x["type"], s["scenario"]) for s in plan["sessions"] if s["role"] == "train" for x in s["events"])
    return {"events": ["role train: event-free sessions per position differ by more than 1"]
            + [f"role train: events of type {t} per scenario differ by more than 1" for t in TYPES
               if max(cells[t, n] for n in SCENARIOS) - min(cells[t, n] for n in SCENARIOS) > 1]}


def group_of_two(doc, plan):
    """F3: the event-free session of a group of train is dropped: the group has two sessions and none without events,
    and its scenario is one short on the group's VM. B4b: the group is the first one whose event-free session has a
    scenario its VM holds 4 times in train (not 5; 18 sessions over 4 scenarios), which v5-train-1 no longer is;
    train then has 2 event-free sessions in that scenario and 3 in the others, within 1."""
    train = [s for s in plan["sessions"] if s["role"] == "train"]
    on_vm = Counter((s["vm"], s["scenario"]) for s in train)
    s = next(s for s in train if not s["events"] and on_vm[s["vm"], s["scenario"]] == 4)
    plan["sessions"].remove(s)
    positions = [i for i in range(3) if i != s["position"]]
    return {"scenario_balance": [f"group {s['group']} has positions {json.dumps(positions)} (expected 0 to 2)",
                                 f"role train on VM {s['vm']}: scenario counts differ by more than 1"],
            "events": [f"group {s['group']} has 0 sessions without events"]}


def seed_field(doc, plan):
    """F5: the seed the campaign runner passes (session["seed"]) differs from the planned traffic stream."""
    s = plan["sessions"][0]
    s["seed"] = s["seeds"]["traffic"] + 1
    return {"streams": [f"session {_label(s)}: seed differs from seeds.traffic"]}


def session_draws_an_analysis_stream(doc, plan):
    """Package B7a: the streams of the analysis are no streams of the plan. A session that draws bootstrap fails, and
    so does its replacement, which keeps the session's seeds and draws its own session-level ones."""
    s = plan["sessions"][0]
    s["seeds"]["bootstrap"] = 1
    return {"streams": [f"session {_label(s)} draws the analysis stream bootstrap",
                        f"replacement of {_label(s)} draws the analysis stream bootstrap"]}


def session_draws_injections(doc, plan):
    """Package B7b: injections is no stream of the plan either; a session that draws it fails, and so does its
    replacement."""
    s = plan["sessions"][0]
    s["seeds"]["injections"] = 1
    return {"streams": [f"session {_label(s)} draws the analysis stream injections",
                        f"replacement of {_label(s)} draws the analysis stream injections"]}


# Package B9a (design B9a 1.1): the deferred checks of the plan (S3 and S5 of the B4 verification, S1 of the
# verification of B4b, S3 of the B8 verification).

def train_on_one_vm(doc, plan):
    """S3 of the B4 verification, its own example: 11 of the 12 groups of train on VM a, which passed the checks
    role_sizes and scenario_balance. Every group holds every type once, so every type of train then has 11 events on
    VM a and 1 on VM b, which the check events saw (F1 of the verification of B4b). The scenario counts of both VMs
    stay within 1: a scenario lies 9 times in train (three complete blocks) and the group left on VM b holds three
    different ones, so VM a has 8, 8, 8 and 9, VM b 1, 1, 1 and 0."""
    kept = next(s["group"] for s in plan["sessions"] if (s["role"], s["vm"]) == ("train", "b"))
    for s in plan["sessions"]:
        if s["role"] == "train" and s["group"] != kept:
            s["vm"] = "a"
    return {"role_sizes": ["role train: groups per VM differ by more than 1"],
            "events": [f"role train: events of type {t} per VM differ by more than 1" for t in TYPES]}


def type_outside_the_deck(doc, plan):
    """S5 of the B4 verification: an event of a type outside events.types was caught only by the counts and by
    'cannot check: KeyError' in the three checks that draw the replacements. The check events now names the type,
    and each of those checks names the session whose replacement cannot be drawn. The event is the first one of the
    first session of train; its own type then has 11 events in train, below min_per_type 12, and no count per
    scenario or VM leaves its bound (3 to 2 in one scenario, 6 to 5 on one VM)."""
    s = next(s for s in plan["sessions"] if s.get("events"))
    assert s["role"] == "train"
    x = s["events"][0]
    gone, x["type"] = x["type"], "neznamy_typ"
    missing = [f"no replacement of {_label(s)}: type neznamy_typ is outside events.types"]
    return {"events": [f"session {_label(s)}: type neznamy_typ is outside events.types",
                       f"role train: type {gone} has 11 events, below min_per_type 12"],
            "full_snapshot_guard": missing, "times": missing, "streams": missing}


def kind_outside_the_deck(doc, plan):
    """S5 for a control: a dealt control of class A takes a kind outside controls.kinds. The check controls names it
    as no card of the deck, as before, and the three checks of the replacements name the session whose replacement
    cannot be drawn instead of 'cannot check: KeyError'. Its own card then has 6 occurrences: it is one with 4 on the
    session's VM and 2 in its scenario, so the card stays within 1 per VM and per scenario."""
    items = _controls(plan)
    per_vm, per_scenario = _card_counts(items)
    s, x = next((s, x) for s, x in items if x["dose"] is None and per_vm[x["kind"], x["polarity"], s["vm"]] == 4
                and per_scenario[x["kind"], x["polarity"], s["scenario"]] == 2)
    card = f"{x['kind']}/{x['polarity']}"
    x["kind"] = "kontrola_neznama"
    missing = [f"no replacement of {_label(s)}: control kind kontrola_neznama is outside controls.kinds"]
    return {"controls": [f"session {_label(s)}: control kontrola_neznama/{x['polarity']} is no card of the deck",
                         f"control {card} has 6 occurrences (expected 7)"],
            "full_snapshot_guard": missing, "times": missing, "streams": missing}


def tenth_spread_of_two(doc, plan):
    """S1 of the verification of B4b (its mutant: the tolerance of the tenths raised to 2): one start of train moves
    half a second later, into the next tenth of its interval, from a tenth that holds 7 of the 72 starts of train into
    another that holds 7, so the tenths of the starts of train differ by exactly 2 (8 and 6). Its stop stays, so the
    stops and every rule hold: it lasted 120.5 s or more, it starts far from the guards, and the gap before it only
    widens."""
    train = [x for s in plan["sessions"] if s["role"] == "train" for x in s["events"]]
    starts = Counter(_tenths(x)[0] for x in train)
    assert sorted(starts.values()) == [7] * 8 + [8] * 2
    x = next(x for x in train if _tenths(x)[0] < 9 and starts[_tenths(x)[0]] == starts[_tenths(x)[0] + 1] == 7
             and x["duration_s"] >= 120.5 and not 1735 <= x["start_s"] < 1965)
    start, stop = _ends(x)
    _move(x, start + 500, stop)
    return {"phases": ["role train: starts per tenth of the interval differ by more than 1"]}


def starts_at_upper_tenth_edges(doc, plan):
    """S1 of the verification of B4b (its mutant: a one-sided KS distance, max((i + 1) / n - x), which misses phases
    that lie above the uniform law): every start moves to the last millisecond of its tenth of the interval wherever
    the item still lasts 120 s or more, and its stop stays. The tenths of the starts and of the stops stay in every
    role, and every rule holds: a start only moves later within its tenth, and no guard begins inside a tenth. Only
    the KS row of the starts sees it; the distance is the one of the moved starts, computed here."""
    for s in plan["sessions"]:
        for item in _items(s):
            start, stop = _ends(item)
            if stop - (start // 500 * 500 + 499) >= 120000:
                _move(item, start // 500 * 500 + 499, stop)
    return {"phases": [ks_rows(plan)[0]]}


def event_shortened_below_the_span(doc, plan):
    """S1 of the verification of B4b (its mutant: the lower bound of the duration span unchecked): the first event
    that lasts less than 125 s ends one interval earlier, below 120 s, with its stop phase and tenth kept; the gap
    after it only widens."""
    s, x = next((s, x) for s in plan["sessions"] for x in s.get("events", []) if x["duration_s"] < 125)
    start, stop = _ends(x)
    _move(x, start, stop - 5000)
    return {"times": [f"{_label(s)}: {x['type']} lasts {_seconds(x['duration_s'])} s, outside duration_s [120, 360]"]}


def control_before_first_s(doc, plan):
    """S1 of the verification of B4b (its mutant: the times of the controls unchecked): the first control of the
    first session of test_controls starts at about 200 s, before first_s 300 s (earlier by whole intervals, with its
    duration and phases). The gap after it only widens, and 200 s lies after the guard of the full snapshot at 0 s,
    which ends at 160 s."""
    s = next(s for s in plan["sessions"] if s["role"] == "test_controls")
    x = min(_items(s), key=lambda item: item["start_s"])
    start, stop = _ends(x)
    shift = (start - 200000) // 5000 * 5000
    _move(x, start - shift, stop - shift)
    return {"times": [f"{_label(s)}: {x['kind']} starts at {_seconds(x['start_s'])} s, before first_s 300 s"]}


def dose_unpaired(doc, plan):
    """S3 of the B8 verification: split over the VMs only, a dose of class B could lie in no scenario of a negative of
    it. Two controls of one card of class B on one VM trade their doses (no count per dose or per VM changes), so that
    one dose then lies in no scenario of both its controls and its negatives while every other dose keeps one; the
    counts allow it (every dose lies on both VMs of both cards, which lie in all four scenarios)."""
    items = _dosed(plan)

    def unpaired(kind):
        at = {}
        for s, x in items:
            if x["kind"] == kind:
                at.setdefault((x["polarity"], x["dose"]), set()).add(s["scenario"])
        return [d for d in doc["controls"]["kinds"][kind]["doses"]
                if not at.get(("control", d), set()) & at.get(("negative", d), set())]
    assert not any(unpaired(x["kind"]) for _, x in items)
    for s, x in items:
        for t, y in items:
            if (x["kind"], x["polarity"], s["vm"]) == (y["kind"], y["polarity"], t["vm"]) and x["dose"] != y["dose"]:
                dose = x["dose"]
                _trade(x, y, ("dose",))
                if unpaired(x["kind"]) == [dose]:
                    return {"controls": [f"control {x['kind']}: dose {dose} lies in no scenario of both its controls "
                                         "and its negatives"]}
                _trade(x, y, ("dose",))
    raise AssertionError("no trade of two doses on one VM leaves exactly one dose unpaired")


def replaced_type(doc, plan, monkeypatch):
    from scripts import protocol_v5
    real, target = protocol_v5.replacement, next(s for s in plan["sessions"] if s.get("events"))

    def changed(p, session, attempt, *, mode="campaign"):
        out = real(p, session, attempt, mode=mode)
        if (session["group"], session["position"]) == (target["group"], target["position"]):
            out["events"][0]["type"] = next(t for t in TYPES if t != out["events"][0]["type"])
        return out
    monkeypatch.setattr(protocol_v5, "replacement", changed)
    return {"streams": [f"replacement of {_label(target)} changes types"]}


def replaced_streams(doc, plan, monkeypatch):
    """F4: a replacement that keeps the event times and the traffic seed of attempt 1 shares both streams."""
    from scripts import protocol_v5
    real, target = protocol_v5.replacement, next(s for s in plan["sessions"] if s.get("events"))

    def same_streams(p, session, attempt, *, mode="campaign"):
        out = real(p, session, attempt, mode=mode)
        if (session["group"], session["position"]) == (target["group"], target["position"]):
            out.update(seeds=dict(session["seeds"]), seed=session["seed"],
                       events=json.loads(json.dumps(session["events"])))
        return out
    monkeypatch.setattr(protocol_v5, "replacement", same_streams)
    return {"streams": [f"two {purpose} streams share a seed" for purpose in
                        ("event_times", "traffic", "traffic_arrivals", "traffic_choices", "traffic_sizes")]}


def _replaced(protocol_v5, target, change):
    """protocol_v5.replacement, but `change` edits the replacement of the session `target`."""
    real = protocol_v5.replacement

    def changed(p, session, attempt, *, mode="campaign"):
        out = real(p, session, attempt, mode=mode)
        if (session["group"], session["position"]) == (target["group"], target["position"]):
            change(out)
        return out
    return changed


def replaced_in_guard(doc, plan, monkeypatch):
    """F4: the replacement of a session draws an event start in the guard of the full snapshot at 1800 s. B4b: as in
    start_in_guard, an event of the replacement that spans the snapshot moves into the guard (_into_guard)."""
    from scripts import protocol_v5
    target, index = next((s, i) for s in plan["sessions"]
                         for i, x in enumerate(protocol_v5.replacement(doc, s, 2).get("events", [])) if _spanning(x))
    changed = _replaced(protocol_v5, target, lambda out: _into_guard(out["events"][index]))
    x = changed(doc, target, 2)["events"][index]
    monkeypatch.setattr(protocol_v5, "replacement", changed)
    return {"full_snapshot_guard": [f"replacement of {_label(target)}: {x['type']} starts at {_seconds(x['start_s'])} "
                                    "s inside the guard of the full snapshot at 1800 s"]}


def replaced_before_first_s(doc, plan, monkeypatch):
    """S1 for a replacement (attempt 2 draws new times): its first event starts at about 200 s (earlier by whole
    intervals, with its duration and phases)."""
    from scripts import protocol_v5
    target = next(s for s in plan["sessions"] if s.get("events"))

    def early(out):
        start, stop = _ends(out["events"][0])
        shift = (start - 200000) // 5000 * 5000
        _move(out["events"][0], start - shift, stop - shift)
    changed = _replaced(protocol_v5, target, early)
    x = changed(doc, target, 2)["events"][0]
    monkeypatch.setattr(protocol_v5, "replacement", changed)
    return {"times": [f"replacement of {_label(target)}: {x['type']} starts at {_seconds(x['start_s'])} s, before "
                      "first_s 300 s"]}


def replaced_tenths(doc, plan, monkeypatch):
    """B4b: a replacement keeps the tenths of the interval of its starts and stops. Here one event of the replacement
    starts half a second later, in the next tenth of the same interval, and ends where it ended (it lasted 120.5 s or
    more): every rule still holds."""
    from scripts import protocol_v5
    target = next(s for s in plan["sessions"] if s.get("events"))
    index = next(i for i, x in enumerate(protocol_v5.replacement(doc, target, 2)["events"])
                 if _tenths(x)[0] < 9 and x["duration_s"] >= 120.5)

    def later(out):
        start, stop = _ends(out["events"][index])
        _move(out["events"][index], start + 500, stop)
    monkeypatch.setattr(protocol_v5, "replacement", _replaced(protocol_v5, target, later))
    return {"streams": [f"replacement of {_label(target)} changes the tenths of its phases"]}


def replaced_dose(doc, plan, monkeypatch):
    """B8: a replacement keeps the doses of its controls; here one control of class B of the replacement gets another
    dose of its kind."""
    from scripts import protocol_v5
    target, index = next((s, i) for s in plan["sessions"] for i, x in enumerate(s.get("controls", []))
                         if x.get("dose") is not None)

    def other(out):
        x = out["controls"][index]
        x["dose"] = next(d for d in doc["controls"]["kinds"][x["kind"]]["doses"] if d != x["dose"])
    monkeypatch.setattr(protocol_v5, "replacement", _replaced(protocol_v5, target, other))
    return {"streams": [f"replacement of {_label(target)} changes doses"]}


def analysis_seed_of_the_plan(doc, plan, monkeypatch):
    """Package B7a: the seed of the analysis stream bootstrap of the comparison k1/Z3 under the campaign's name equals
    the traffic seed of the first session of the plan (a monkeypatch, as the replacements above): the streams check
    sees two purposes on one seed; the rehearsal's plan has its own name and stays apart."""
    from scripts import protocol_v5
    real, traffic = protocol_v5._analysis_seed, plan["sessions"][0]["seeds"]["traffic"]

    def shared(name, purpose, unit):
        return traffic if (name, purpose, unit) == (doc["name"], "bootstrap", "k1/Z3") else real(name, purpose, unit)
    monkeypatch.setattr(protocol_v5, "_analysis_seed", shared)
    return {"streams": ["purposes bootstrap and traffic share a seed"]}


def injection_seed_of_the_plan(doc, plan, monkeypatch):
    """Package B7b: the seed of the stream injections of the unit test_benign/C under the campaign's name equals the
    traffic seed of the first session of the plan (a monkeypatch): the streams check sees two purposes on one seed."""
    from scripts import protocol_v5
    real, traffic = protocol_v5._analysis_seed, plan["sessions"][0]["seeds"]["traffic"]

    def shared(name, purpose, unit):
        return (traffic if (name, purpose, unit) == (doc["name"], "injections", "test_benign/C")
                else real(name, purpose, unit))
    monkeypatch.setattr(protocol_v5, "_analysis_seed", shared)
    return {"streams": ["purposes injections and traffic share a seed"]}


FILE_CASES = {f.__name__: f for f in (unknown_key, missing_key, gate_085, max_7, six_groups, below_min_per_type,
                                      no_min_per_type, not_interleaved, replacement_without_covers,
                                      method_without_grid, k2a_without_z4, null_outside, rehearsal_name,
                                      rehearsal_prefix, unknown_to_lab, unknown_profile, think_below_mean,
                                      # Package B4b, F1 of its verification.
                                      two_events_per_session, no_event_free_session,
                                      # Package B8: the controls section and the lab's register of its kinds.
                                      module_without_candidates, dose_unknown_to_lab, per_dose_short,
                                      # Package B6a: the keys of the analysis plan it adds.
                                      identity_auc_half, differenced_outside_levels, floor_without_a_column,
                                      receptive_field_short,
                                      # Package B7a: the keys of the analysis plan it adds or changes, the streams.
                                      grid_of_a_method_without_parameters, grid_of_z3_outside_determined_at,
                                      selection_without_z1, gru_on_four_seeds, wording_without_a_blank,
                                      z0_without_repetitions, level_of_95, streams_without_bootstrap,
                                      # Package B7b: the keys of design B7b 1.4 and the stream injections.
                                      c_without_orders, groups_share_a_column, validity_quantiles_reversed,
                                      min_evaluable_apart_from_min_occurrences, contexts_not_increasing,
                                      k2a_with_z4_unsplit, grid_longer_than_the_window, streams_without_injections,
                                      # F2 of the verification of B7b: the two keys bound to window_rows.
                                      validity_average_longer_than_the_window, context_of_the_whole_window,
                                      # Package B7c: the metrics of the thesis and the linkage table.
                                      garwood_level_of_95, event_test_two_sided, o2_bound_by_garwood,
                                      linkage_reworded, linkage_not_a_text,
                                      # Package B9a: F3 of the verification of B7c, the boots of K2; the fix of
                                      # B9a: the one seeded level of the guest (F4 of its verification).
                                      boots_apart_from_the_carriers, seeded_level_of_19_digits,
                                      # Package B9b: the rule of the early stop (audit.early_stop).
                                      early_stop_rate_below_zero)}
PLAN_CASES = {f.__name__: f for f in (no_group_on_vm, equal_scenarios, twice_at_position, two_events, start_in_guard,
                                      locked_to_grid, common_seed, control_relabelled, control_slot_emptied,
                                      event_free_first, group_of_two, seed_field,
                                      # Package B4b: must_fix 5, must_fix 6 and S1 of the B4 verification.
                                      event_free_scenarios, type_scenarios, type_twice, card_vm, card_scenario,
                                      kind_twice, same_nonzero_phase, one_second_grid, phases_at_tenth_edges,
                                      stops_at_interval_start, before_first_s, overlapping_events, duration_2000,
                                      ends_in_tail,
                                      # F1 and F2 of the verification of B4b.
                                      group_twice, type_vm, stops_at_tenth_edges,
                                      # Package B8: the doses of the controls (design B8 1.2).
                                      dose_of_class_a, dose_unknown, dose_counts, dose_vm,
                                      # Package B7a: the streams of the analysis are no streams of the plan.
                                      session_draws_an_analysis_stream,
                                      # Package B7b: nor is the stream injections.
                                      session_draws_injections,
                                      # Package B9a: S3 and S5 of the B4 verification, S1 of the verification of
                                      # B4b and S3 of the B8 verification.
                                      train_on_one_vm, type_outside_the_deck, kind_outside_the_deck,
                                      tenth_spread_of_two, starts_at_upper_tenth_edges,
                                      event_shortened_below_the_span, control_before_first_s, dose_unpaired)}
REPLACEMENT_CASES = {f.__name__: f for f in (replaced_type, replaced_streams, replaced_in_guard,
                                             replaced_before_first_s, replaced_tenths, replaced_dose,
                                             # Package B7a: a monkeypatched seed of the analysis.
                                             analysis_seed_of_the_plan,
                                             # Package B7b: one of the stream injections.
                                             injection_seed_of_the_plan)}
CASES = ["real_file", *FILE_CASES, *PLAN_CASES, *REPLACEMENT_CASES, "null_at_g1"]


def selfcheck(tmp_path, doc, *options):
    """scripts/collection.py --protocol <doc as a file> selfcheck: (exit code, the report it wrote)."""
    from scripts import collection
    path, out = tmp_path / "protocol.json", tmp_path / "report.json"
    path.write_text(json.dumps(doc, indent=2))
    code = collection.main(["--protocol", str(path), "selfcheck", *options, "--out", str(out)])
    return code, json.loads(out.read_text())


@pytest.mark.parametrize("case", CASES)
def test_selfcheck_passes_the_file_and_fails_each_deliberate_error(case, tmp_path, monkeypatch):
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    if case in PLAN_CASES or case in REPLACEMENT_CASES:
        plan = protocol_v5.plan(doc)
        failures = (PLAN_CASES[case](doc, plan) if case in PLAN_CASES
                    else REPLACEMENT_CASES[case](doc, plan, monkeypatch))
        checks = protocol_v5.evaluate(V5, doc, plan)
    else:
        failures = {} if case == "real_file" else FILE_CASES[case](doc) if case in FILE_CASES else {
            "analysis": [f"null at analysis.{k}.m determined at G1 (stage G1)" for k in ("k1", "k2a", "k2b")]}
        code, report = selfcheck(tmp_path, doc, *(["--stage", "G1"] if case == "null_at_g1" else []))
        assert (code, report["passed"]) == ((0, True) if case == "real_file" else (2, False))  # Since B8.
        assert (report["mode"], report["stage"]) == ("campaign", "G1" if case == "null_at_g1" else "G0")
        checks = report["checks"]
    expected = {name: ("passed", []) for name in CHECKS}
    expected.update({name: ("failed", reasons) for name, reasons in failures.items()})
    assert [c["check"] for c in checks] == list(CHECKS)
    assert {c["check"]: (c["result"], c["reasons"]) for c in checks} == expected


def test_the_rehearsal_is_a_mode_of_the_file_with_10_groups_and_30_sessions():
    from scripts import protocol_v5
    plan = protocol_v5.plan(json.loads(V5.read_text()), mode="rehearsal")
    assert (plan["mode"], plan["name"], plan["group_prefix"]) == ("rehearsal", "server-normal-v5-generalka", "g5-")
    assert (len({s["group"] for s in plan["sessions"]}), len(plan["sessions"])) == (10, 30)


def test_a_protocol_of_schema_3_has_no_field_status(tmp_path):
    """Q23 (F1 of the verification of B9b, must_fix; the B1 item 'pole protokolu status pilot_required nečíta žiadny
    kód'): the stage of a protocol file is what the readiness records of scripts/gates.py say, and a field of the
    file could not follow it, since gates.stage_binding hashes it at every stage; so schema 3 has no field status. The
    file has none and its note says where the stage is; a copy with status is refused by name as an unknown key, by
    the loader and by the layout check of the self-check. Schemas 1 and 2 keep theirs, as history."""
    from scripts import collection, protocol_v5
    doc = json.loads(V5.read_text())
    assert "status" not in doc and "status" not in protocol_v5.TOP_LEVEL
    assert all(text in doc["note"] for text in ("readiness records of scripts/gates.py", "stage_binding", "Q23"))
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(dict(doc, status="g0")))
    with pytest.raises(ValueError) as error:
        collection.protocol(path)
    assert str(error.value) == "unknown protocol key: status"
    assert protocol_v5.check_keys(dict(doc, status="g0")) == ["unknown protocol key: status"]
    old = ROOT / "config/collection-v2.json"
    assert json.loads(old.read_text())["status"] == "pilot_required"
    assert collection.protocol(old)["status"] == "pilot_required"


def test_the_interleaved_test_groups_of_the_campaign_plan_end_with_a_group_of_test_benign():
    """N1 of the confirmation of B9a (package B9b, agent Z): the barrier of scripts/campaign.py (ORDER_RULE) orders
    the starts of the test groups across the VMs, not their ends. So skeleton test 2 (no test_controls boot lies
    wholly after every test_benign boot) holds by construction only for a plan whose interleaved sequence of the test
    roles ends with a group of test_benign, which starts only after every group of test_controls has started. The
    campaign plan of the file does, with v5-test_benign-12. The rehearsal plan ends with g5-test_controls-2: that is
    the documented exposure of the rehearsal (a lag of about one group can break test 2 there), not pinned here."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    plan = protocol_v5.plan(doc, mode="campaign")
    assert doc["interleave"] == [list(protocol_v5.INTERLEAVED)]
    last = [s for s in plan["sessions"] if s["role"] in protocol_v5.INTERLEAVED][-1]
    assert (last["role"], last["group"]) == ("test_benign", "v5-test_benign-12"), (
        f"the interleaved sequence of the test roles of the campaign plan ends with {last['group']} (role "
        f"{last['role']}): skeleton test 2 holds by construction only when it ends with a group of test_benign, since "
        "the barrier of scripts/campaign.py ORDER_RULE orders the starts of the test groups and not their ends")


def test_the_report_records_the_types_by_place_in_the_session_and_the_phases(tmp_path):
    """B4b: what the lead's must_fix 5 asks to record, not to require (each event type by its place in the session's
    order), each event type per VM (F1 of the verification of B4b), and the numbers of must_fix 6 (starts and stops
    per tenth in every role, the KS distances of the 286 start phases and, since F2 of the verification, of the 286
    stop phases), as counted here from the plan of the file. Every group holds every type once, so every type is on
    each VM as often as its role has groups there: 6, 2, 4 and 6."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    plan = protocol_v5.plan(doc)
    places = {role: {t: [sum(len(s["events"]) > i and s["events"][i]["type"] == t for s in plan["sessions"]
                             if s["role"] == role) for i in range(3)] for t in TYPES} for role in ROLES[:4]}
    on_vm = {role: {t: {vm: sum(x["type"] == t for s in plan["sessions"] if (s["role"], s["vm"]) == (role, vm)
                                for x in s["events"]) for vm in ("a", "b")} for t in TYPES} for role in ROLES[:4]}
    tenths = {role: {what: [sum(_tenths(x)[i] == d for s in plan["sessions"] if s["role"] == role for x in _items(s))
                            for d in range(10)] for i, what in enumerate(("starts", "stops"))} for role in ROLES}
    distance, stops = (_ks([_ends(x)[i] % 5000 / 5000 for s in plan["sessions"] for x in _items(s)]) for i in (0, 1))
    code, report = selfcheck(tmp_path, doc)
    assert code == 0 and report["summary"] == {
        "event_types_by_place_in_session": places, "event_types_by_vm": on_vm, "phase_tenths": tenths,
        "start_phases_ks": {"starts": 286, "distance": round(distance, 4), "critical": .0797, "level": .05},
        "stop_phases_ks": {"stops": 286, "distance": round(stops, 4), "critical": .0797, "level": .05}}
    assert all(max(row) - min(row) <= 1 for role in tenths.values() for row in role.values()) and distance < .0797
    assert stops < .0797 and all(on_vm[role][t] == {"a": n, "b": n} for t in TYPES
                                 for role, n in (("train", 6), ("dev", 2), ("calibration", 4), ("test_benign", 6)))


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_every_group_holds_one_full_round_of_the_types(mode):
    """F1 of the verification of B4b, on the plans of the file and of five other protocol names: every group of an
    event role holds every type once, so every type lies once in every boot; every type is in every scenario of a
    role equally often in a campaign (its blocks are complete, so every scenario of a role holds two sessions with
    events per block) and within 1 in the rehearsal (one incomplete block per role)."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    for name in [doc["name"]] + [f"name-{k}" for k in range(5)]:
        sessions = protocol_v5.plan(dict(doc, name=name), mode)["sessions"]
        for role in ROLES[:4]:
            mine = [s for s in sessions if s["role"] == role]
            groups = {}
            for s in mine:
                groups.setdefault(s["group"], Counter()).update(x["type"] for x in s["events"])
            assert list(groups.values()) == [Counter(TYPES)] * len(groups), (name, role)
            cells = Counter((x["type"], s["scenario"]) for s in mine for x in s["events"])
            spread = max(max(cells[t, n] for n in SCENARIOS) - min(cells[t, n] for n in SCENARIOS) for t in TYPES)
            assert spread <= (0 if mode == "campaign" else 1), (name, role)


def test_a_replacement_keeps_the_tenths_of_its_phases_and_draws_new_times():
    """B4b: attempt 2 of every planned session keeps the tenth of the interval of each start and stop, so a role's
    phases stay stratified when a session is replaced; its times and phases are new."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    for s in protocol_v5.plan(doc)["sessions"]:
        again = protocol_v5.replacement(doc, s, 2)
        assert [_tenths(x) for x in _items(again)] == [_tenths(x) for x in _items(s)]
        assert not _items(s) or [_ends(x) for x in _items(again)] != [_ends(x) for x in _items(s)]


def test_the_skeletons_form_of_the_command_checks_the_same_file(tmp_path):
    """S4 of the B4 verification: `collection.py selfcheck --protocol P` (skeleton §2) works like the global form."""
    from scripts import collection
    after, before = tmp_path / "after.json", tmp_path / "before.json"
    assert collection.main(["selfcheck", "--protocol", str(V5), "--out", str(after)]) == 0
    assert collection.main(["--protocol", str(V5), "selfcheck", "--out", str(before)]) == 0
    assert json.loads(after.read_text()) == json.loads(before.read_text())


# Package B5b (lead's remarks on B4, part 1, section 1): the loader binds determined_at as scripts/gates.py does, and
# the row reachability fails when a witness had to fall back to worst_invalid_rows. Every other check gives what it
# gives for the real file.

def expected_checks(**failures):
    expected = {name: ("passed", []) for name in CHECKS}
    expected.update({name: ("failed", reasons) for name, reasons in failures.items()})
    return expected


@pytest.mark.parametrize("stage, path, reason", [
    ("G2", "analysis.k1", "determined_at path analysis.k1 (G2) would delete analysis.k1.m (G1)"),
    ("G3a", "determined_at.G1",
     "determined_at path must start with a protocol key other than determined_at: determined_at.G1"),
], ids=["deletes_an_earlier_path", "names_determined_at"])
def test_the_loader_refuses_a_determined_at_that_a_stage_record_could_not_bind(tmp_path, stage, path, reason):
    from scripts import gates
    doc = json.loads(V5.read_text())
    doc["determined_at"][stage].append(path)
    with pytest.raises(ValueError) as refused:
        gates.later_paths(doc["determined_at"], "G0")
    assert str(refused.value) == reason
    code, report = selfcheck(tmp_path, doc)
    assert code == 2
    assert {c["check"]: (c["result"], c["reasons"]) for c in report["checks"]} == expected_checks(
        loader=["protocol(): invalid determined_at: " + reason])


def test_reachability_fails_when_a_witness_falls_back_to_worst_invalid_rows(tmp_path, monkeypatch):
    """With too few placements allowed the witnesses of 3 and 4 rows are those of worst_invalid_rows: 33 rows apart,
    so the one of 4 rows is periodic as well."""
    from features import acceptance
    monkeypatch.setattr(acceptance, "WITNESS_STEPS", 10)  # The v5 grid needs 33 placements per row.
    code, report = selfcheck(tmp_path, json.loads(V5.read_text()))
    assert code == 2
    assert {c["check"]: (c["result"], c["reasons"]) for c in report["checks"]} == expected_checks(reachability=[
        "witness with invalid_rows.max + 1 rows is not refused by the gate alone",
        "witness with invalid_rows.max rows fell back to worst_invalid_rows",
        "witness with invalid_rows.max + 1 rows fell back to worst_invalid_rows"])


# Package B8: the controls section of the file (design B8 1.1) and the doses of the plan (design B8 1.2).

def _kind(name, **values):
    return lambda c: c["kinds"][name].update(values)


def _expect(name, column, **values):
    return lambda c: c["kinds"][name]["expect"][column].update(values)


@pytest.mark.parametrize("change, reason", [
    (lambda c: c.update(baseline={"processes": [-5, 5], "MemAvailable_kb": [-200000, 100000]}), None),
    (_expect("kontrola_wx_memfd", "proc_wx", tolerance=.1),
     "unknown protocol key: controls.kinds.kontrola_wx_memfd.expect.proc_wx.tolerance"),
    (lambda c: c["kinds"]["kontrola_modul_jadra"].pop("candidates"),
     "missing protocol key: controls.kinds.kontrola_modul_jadra.candidates"),
    (lambda c: c["kinds"]["kontrola_davka_procesov"]["expect"]["proc_new"].pop("direction"),
     "missing protocol key: controls.kinds.kontrola_davka_procesov.expect.proc_new.direction"),
    (lambda c: c.pop("baseline"), "missing protocol key: controls.baseline"),
    (_kind("kontrola_wx_memfd", doses=[16], per_dose=[7]), "invalid controls"),
    (_kind("kontrola_zapisovac_pamate", doses=[16, 16, 256]), "invalid controls"),
    (_kind("kontrola_zapisovac_pamate", doses=[16, 64, 256.5]), "invalid controls"),
    (_kind("kontrola_zapisovac_pamate", per_dose=[2, 2, 2]), "invalid controls"),
    (lambda c: c.update(negatives_per_kind=6), "invalid controls"),
    (_kind("kontrola_pocuvajuci_soket", columns=["sock_listening"],
           expect={"sock_listening": {"shift": .5, "direction": "up"}}), "invalid controls"),
    (_kind("kontrola_pocuvajuci_soket", columns=["je_plna"], expect={"je_plna": {"shift": .5, "direction": "up"}}),
     "invalid controls"),
    (lambda c: c["kinds"]["kontrola_wx_memfd"]["expect"].pop("proc_memfd"), "invalid controls"),
    (_expect("kontrola_wx_memfd", "proc_wx", direction="sideways"), "invalid controls"),
    (_expect("kontrola_wx_memfd", "proc_wx", shift=0), "invalid controls"),
    (_expect("kontrola_wx_memfd", "proc_wx", shift=[.5]), "invalid controls"),
    (_expect("kontrola_davka_procesov", "proc_new", shift=[2, 10]), "invalid controls"),
    (_kind("kontrola_modul_jadra", candidates=["crc-7"]), "invalid controls"),
    (lambda c: c.update(baseline={"processes": [5, -5], "MemAvailable_kb": [-1, 1]}), "invalid controls"),
    (lambda c: c.update(baseline={"processes": [-5, 5]}), "invalid controls"),
], ids=["measured_tolerance", "unknown_key", "no_candidates", "no_direction", "no_baseline",
        "dose_of_class_a", "doses_not_distinct", "dose_not_an_integer", "counts_per_dose", "fewer_negatives",
        "column_not_a_feature", "column_a_row_flag", "expectation_per_column", "direction", "shift_not_positive",
        "shift_list_of_class_a", "shift_per_dose", "candidate_name", "band_reversed", "band_missing"])
def test_the_loader_knows_every_key_and_value_of_the_controls_section(change, reason):
    """Design B8 1.1: the layout knows every key of the controls section (the module kind alone has candidates; the
    real file, whose other kinds have none, passes the self-check) and the value check every rule of a kind and of
    the tolerance controls.baseline: null in the file until G2, then a band per quantity of lab/guest_state.py
    LEVEL_PARTS, which loads."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    change(doc["controls"])
    if reason is None:
        protocol_v5.check_layout(doc)
    else:
        with pytest.raises(ValueError) as refused:
            protocol_v5.check_layout(doc)
        assert str(refused.value) == reason


def test_the_nulls_by_design_are_the_doses_of_class_a_and_the_seeds_of_a_method_that_draws_nothing():
    """A null dose means "none" only for a kind of class A, and null seeds only for a descriptive method that draws
    nothing (UNSEEDED, merge of B7a); elsewhere a null outside determined_at fails as before."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    assert protocol_v5.not_applicable(doc) == {f"controls.kinds.{kind}.{key}" for key in ("doses", "per_dose") for kind
                                               in ("kontrola_wx_memfd", "kontrola_modul_jadra",
                                                   "kontrola_pocuvajuci_soket")} | {
        "analysis.descriptive_methods.zscore.seeds"}
    assert protocol_v5.check_analysis(doc) == []
    doc["controls"]["kinds"]["kontrola_davka_procesov"]["doses"] = None
    doc["analysis"]["descriptive_methods"]["iforest"]["seeds"] = None
    assert protocol_v5.check_analysis(doc) == [
        "null outside determined_at: analysis.descriptive_methods.iforest.seeds",
        "null outside determined_at: controls.kinds.kontrola_davka_procesov.doses"]


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_every_control_of_class_b_is_dealt_a_dose_after_its_card(mode, monkeypatch):
    """Design B8 1.2 on the plans of the file and of five other protocol names: a control of class A has no dose, one
    of class B one of its kind's doses; in a campaign each dose has its count per_dose among the kind's controls and
    the same among its negatives, in a rehearsal the counts of a card differ by at most 1; on each VM a dose of a card
    differs by at most 1 from the other VM. The doses are dealt last: the plan that deals none is the same plan."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    kinds = doc["controls"]["kinds"]
    for name in [doc["name"]] + [f"name-{k}" for k in range(5)]:
        plan = protocol_v5.plan(dict(doc, name=name), mode)
        items = _controls(plan)
        assert all(x["dose"] is None if kinds[x["kind"]]["class"] == "A" else x["dose"] in kinds[x["kind"]]["doses"]
                   for _, x in items), name
        for kind in ("kontrola_zapisovac_pamate", "kontrola_davka_procesov"):
            k = kinds[kind]
            for polarity in ("control", "negative"):
                mine = [(s, x) for s, x in items if (x["kind"], x["polarity"]) == (kind, polarity)]
                counts = Counter(x["dose"] for _, x in mine)
                if mode == "campaign":
                    assert counts == dict(zip(k["doses"], k["per_dose"])), (name, kind, polarity)
                else:
                    assert max(counts[d] for d in k["doses"]) - min(counts[d] for d in k["doses"]) <= 1
                on = Counter((x["dose"], s["vm"]) for s, x in mine)
                assert all(abs(on[d, "a"] - on[d, "b"]) <= 1 for d in k["doses"]), (name, kind, polarity)
        monkeypatch.setattr(protocol_v5, "_deal_doses", lambda c, groups, rng: [
            labels.__setitem__(j, card + (None,)) for group in groups for labels in group["labels"]
            for j, card in enumerate(labels) if card is not None])
        undosed = protocol_v5.plan(dict(doc, name=name), mode)
        monkeypatch.undo()
        for _, x in items:
            x["dose"] = None
        assert json.loads(json.dumps(undosed)) == json.loads(json.dumps(plan)), name


def test_a_rehearsal_deals_a_card_a_prefix_of_its_kinds_doses():
    """B8: in the rehearsal a card of class B has two controls with two different doses (a prefix of its kind's deck,
    one on each VM). The same dose on both leaves the third and second dose at none: refused, the VMs stay within 1."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    plan = protocol_v5.plan(doc, "rehearsal")
    assert protocol_v5.check_controls(doc, plan) == []
    pairs = {}
    for s, x in _dosed(plan):
        pairs.setdefault((x["kind"], x["polarity"]), []).append(x)
    (kind, polarity), (x, y) = next((card, pair) for card, pair in sorted(pairs.items()) if len(pair) == 2)
    assert x["dose"] != y["dose"]
    y["dose"] = x["dose"]
    assert protocol_v5.check_controls(doc, plan) == [
        f"rehearsal plan: control {kind}/{polarity}: dose counts differ by more than 1"]


# Package B6a: the keys of the analysis plan of design B6a 1.1. The layout knows every key, and the value check every
# rule of each: one bad input per rule, and the good input of a filled analysis.columns (G3a).

def _at(path, value=KeyError):
    """A change of the analysis section: the value at the dotted `path` below it, or the key removed (KeyError)."""
    def change(a):
        *parents, key = path.split(".")
        for name in parents:
            a = a[name]
        if value is KeyError:
            del a[key]
        else:
            a[key] = value
    return change


def _classes(**classes):
    from features.archive import BEHAVIOR_NAMES
    return dict(dict.fromkeys(BEHAVIOR_NAMES, "neural"), **classes)


@pytest.mark.parametrize("change, reason", [
    (lambda a: a.update(columns=_classes(mod_total="rule", sock_total="differenced", proc_kernel="dropped")), None),
    (_at("architecture.kernel"), "missing protocol key: analysis.architecture.kernel"),
    (_at("architecture.channels", 1025), "invalid analysis"),
    (_at("architecture.kernel", 16), "invalid analysis"),
    (_at("architecture.blocks", 13), "invalid analysis"),
    (_at("architecture.dropout", 1), "invalid analysis"),
    (_at("architecture.weight_norm", 0), "invalid analysis"),
    (_at("architecture.learning_rate", 0), "invalid analysis"),
    (_at("architecture.gradient_clip", -5), "invalid analysis"),
    (_at("architecture.classifier_gradient_clip", 0), "invalid analysis"),
    (_at("architecture.batch_size", 32.0), "invalid analysis"),
    (_at("qualification.strata", ["profile", "position"]), "unknown protocol key: analysis.qualification.strata"),
    (_at("qualification.near_constant_share", 1), "invalid analysis"),
    (_at("qualification.duplicate_tolerance", 0), "invalid analysis"),
    (_at("qualification.level_columns", ["proc_total", "ma_predchodcu"]), "invalid analysis"),
    (_at("qualification.level_columns", ["proc_total", "proc_total"]), "invalid analysis"),
    (_at("scale.floor"), "missing protocol key: analysis.scale.floor"),
    (_at("scale.per_bin", "yes"), "invalid analysis"),
    (_at("scale.min_bin_pages", 0), "invalid analysis"),
    (_at("scale.floor.mem_changed_ratio", 0), "invalid analysis"),
    (_at("scale.local_floor.has_changed", 1), "invalid analysis"),
    (_at("column_mask", None), "unknown protocol key: analysis.column_mask"),
    (lambda a: a.update(columns={k: v for k, v in _classes().items() if k != "proc_memfd"}), "invalid analysis"),
    (lambda a: a.update(columns=_classes(mod_total="rule channel")), "invalid analysis"),
    # Package B6b: the class rule_differenced of question Q8 (its proposal, provisional), for a level column only.
    (lambda a: a.update(columns=_classes(sock_listen="rule_differenced")), None),
    (lambda a: a.update(columns=_classes(mem_changed_ratio="rule_differenced")), "invalid analysis"),
], ids=["columns_of_g3a", "no_kernel", "channels", "kernel", "blocks", "dropout", "weight_norm", "learning_rate",
        "gradient_clip", "classifier_gradient_clip", "batch_size", "unknown_key", "near_constant_share",
        "duplicate_tolerance", "level_not_a_column", "level_twice", "no_floor", "per_bin", "min_bin_pages",
        "floor_not_positive", "local_floor_of_the_mask", "old_name", "columns_missing_one", "unknown_class",
        "rule_differenced_of_a_level", "rule_differenced_outside_levels"])
def test_the_loader_knows_every_key_and_value_of_the_analysis_plan_of_b6a(change, reason):
    """Design B6a 1.1: analysis.qualification and analysis.scale (G0), analysis.columns (null until G3a, then exactly
    the 20 columns of features.archive.BEHAVIOR_NAMES, each neural, rule, differenced or dropped) and
    analysis.architecture with the TCN of the thesis and its optimizer, bounded as safeguard/model.py builds it."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    change(doc["analysis"])
    if reason is None:
        protocol_v5.check_layout(doc)
    else:
        with pytest.raises(ValueError) as refused:
            protocol_v5.check_layout(doc)
        assert str(refused.value) == reason


# Package B7a: the keys of the analysis plan of design B7a 1.6. The layout knows every key, and the value check every
# rule of each: one bad input per rule, and a good one (a descriptive method that draws on one seed of analysis.seeds).

@pytest.mark.parametrize("change, reason", [
    (_at("descriptive_methods.iforest.seeds", [0]), None),
    (_at("methods.Z0.grid", None), "invalid analysis"),
    (_at("methods.Z1.grid", {}), "invalid analysis"),
    (_at("methods.Z5.grid", {"ridge_alpha": [1, 1]}), "invalid analysis"),
    # Merge of B7a: a filled grid holds exactly the parameters of protocol_v5.GRID_PARAMETERS (read by tcn/metody.py).
    (_at("methods.Z3.grid", {"ewma_coefficient": [.1, .3]}), "invalid analysis"),
    (_at("selection", "the grid point with the best value of the method's own criterion on dev"), "invalid analysis"),
    (_at("descriptive_methods.pca", {"what": "principal components", "seeds": [], "note": ""}),
     "unknown protocol key: analysis.descriptive_methods.pca"),
    (_at("descriptive_methods.lstm.seeds"), "missing protocol key: analysis.descriptive_methods.lstm.seeds"),
    (_at("descriptive_methods.iforest.seeds", [5]), "invalid analysis"),
    # Merge of B7a: a method that draws nothing (UNSEEDED) has the seeds null, every other one a non-empty list.
    (_at("descriptive_methods.zscore.seeds", []), "invalid analysis"),
    (_at("descriptive_methods.iforest.seeds", None), "invalid analysis"),
    (_at("descriptive_methods.iforest.seeds", []), "invalid analysis"),
    (_at("descriptive_methods.iforest.seeds", [0, 0]), "invalid analysis"),
    (_at("descriptive_methods.lstm.seeds", [0, 1, 2, 3]), "invalid analysis"),
    (_at("descriptive_methods.gru.what", " "), "invalid analysis"),
    (_at("wording.k2b.undecided"), "missing protocol key: analysis.wording.k2b.undecided"),
    (_at("wording.k2a.not_better", "na týchto dátach je neurónový kanál rovnocenný"), "invalid analysis"),
    (_at("wording.k1.undecided", 1), "invalid analysis"),
    (_at("matched_rate.budget", ""), "invalid analysis"),
    (_at("matched_rate.z0_repetitions", 200.0), "invalid analysis"),
    (_at("statistics.bootstrap", 0), "invalid analysis"),
    (_at("statistics.exact_up_to_boots", 21), "invalid analysis"),
    (_at("statistics.level", 1), "invalid analysis"),
    (_at("statistics.note", None), "invalid analysis"),
], ids=["one_seed_of_the_plan", "grid_null_without_parameters", "grid_empty_with_parameters", "grid_repeats_a_value",
        "grid_unknown_parameter", "selection_names_no_method", "descriptive_unknown", "descriptive_no_seeds",
        "seed_outside_the_plan", "unseeded_empty_list", "seeded_null", "seeded_empty_list", "seed_twice",
        "lstm_on_four_seeds", "no_what", "wording_no_outcome", "wording_no_blank", "wording_no_text",
        "no_budget", "repetitions_not_an_integer", "no_resample", "enumeration_above_20", "level_one", "no_note"])
def test_the_loader_knows_every_key_and_value_of_the_analysis_plan_of_b7a(change, reason):
    """Design B7a 1.6: analysis.methods (grid {} for Z0, Z2, Z4 and M; for Z1, Z3 and Z5 null until G3a, then a
    non-empty grid of distinct values for exactly the parameters of GRID_PARAMETERS), analysis.selection (a rule for
    each method, each named), analysis.descriptive_methods (null for a method that draws nothing, else distinct seeds
    of analysis.seeds, every one for GRU and LSTM), analysis.wording (each
    claim and outcome a text with the blanks of chapter 8.4), analysis.matched_rate and analysis.statistics."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    change(doc["analysis"])
    if reason is None:
        protocol_v5.check_layout(doc)
    else:
        with pytest.raises(ValueError) as refused:
            protocol_v5.check_layout(doc)
        assert str(refused.value) == reason


def test_only_the_grids_of_z1_z3_and_z5_wait_for_g3a():
    """Design B7a 1.6: Z0, Z2, Z4 and M have no free parameter (grid {} from G0 on), so at stage G3a exactly the grids
    of Z1, Z3 and Z5 must hold a value (determined_at names their paths instead of analysis.methods.*.grid); filled
    with the parameters of GRID_PARAMETERS (merge of B7a), they load and nothing of analysis.methods is missing at
    G3a."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    assert [r for r in protocol_v5.check_analysis(doc, stage="G3a") if ".methods." in r] == [
        f"null at analysis.methods.{name}.grid determined at G3a (stage G3a)" for name in ("Z1", "Z3", "Z5")]
    grids = {"Z1": {"moving_average_rows": [6, 12], "cusum_shift": [.5, 1]}, "Z3": {"ewma_alpha": [.1, .3]},
             "Z5": {"ridge_alpha": [.1, 1, 10]}}
    assert {name: tuple(grid) for name, grid in grids.items()} == protocol_v5.GRID_PARAMETERS
    for name, grid in grids.items():
        doc["analysis"]["methods"][name]["grid"] = grid
    protocol_v5.check_layout(doc)
    assert [r for r in protocol_v5.check_analysis(doc, stage="G3a") if ".methods." in r] == []


def test_the_plan_draws_no_stream_of_the_analysis_and_their_seeds_follow_the_rule():
    """Design B7a 1.6: streams.purposes gains z0_alarms and bootstrap, which no session and no replacement of the plan
    draws (campaign and rehearsal); their seeds are seed(name, purpose, unit, -1, 0) under the plan's name of the mode,
    z0_alarms per role and bootstrap per comparison of a confirmatory claim."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    # Package B7b: bootstrap per variant of Z4 in K2a (question Q13, provisional) and the stream injections.
    units = {"z0_alarms": list(ROLES),
             "bootstrap": ["k1/Z3", "k1/Z5", "k2a/Z1", "k2a/Z2", "k2a/Z4:load", "k2a/Z4:residual", "k2b/Z3",
                           "k2b/Z5"],
             "injections": ["test_benign/C", "test_benign/D", "test_controls/C", "test_controls/D", "dev"]}
    assert protocol_v5.analysis_units(doc) == units
    assert set(doc["streams"]["purposes"]) == set(protocol_v5.PURPOSES) and {"z0_alarms", "bootstrap",
                                                                             "injections"} <= set(protocol_v5.PURPOSES)
    for mode, name in (("campaign", "server-normal-v5"), ("rehearsal", "server-normal-v5-generalka")):
        plan = protocol_v5.plan(doc, mode)
        drawn = {purpose for s in plan["sessions"] for x in (s, protocol_v5.replacement(doc, s, 2, mode=mode))
                 for purpose in x["seeds"]}
        assert drawn == set(protocol_v5.PURPOSES) - {"z0_alarms", "bootstrap", "injections"}, mode
        assert {(purpose, unit): protocol_v5.analysis_seed(doc, purpose, unit, mode=mode)
                for purpose, mine in units.items() for unit in mine} == {
            (purpose, unit): protocol_v5.seed(name, purpose, unit, -1, 0) for purpose, mine in units.items()
            for unit in mine}


@pytest.mark.parametrize("purpose, unit, mode, reason", [
    ("traffic", "test_benign", "campaign", "'traffic' is no stream of the analysis (z0_alarms, bootstrap, "
                                           "injections)"),
    ("z0_alarms", "test", "campaign", "'test' is no unit of the analysis stream z0_alarms (train, dev, calibration, "
                                      "test_benign, test_controls)"),
    ("bootstrap", "k1/Z1", "campaign", "'k1/Z1' is no unit of the analysis stream bootstrap (k1/Z3, k1/Z5, k2a/Z1, "
                                       "k2a/Z2, k2a/Z4:load, k2a/Z4:residual, k2b/Z3, k2b/Z5)"),
    ("bootstrap", "k1/Z3", "final", "unknown plan mode: final"),
    # Package B7b: injections per carrier role and class and for the insertion into dev only.
    ("injections", "calibration/C", "campaign",
     "'calibration/C' is no unit of the analysis stream injections (test_benign/C, test_benign/D, test_controls/C, "
     "test_controls/D, dev)"),
], ids=["purpose_of_the_plan", "unknown_role", "method_k1_does_not_compare", "unknown_mode",
        "injections_of_a_role_without_interventions"])
def test_a_seed_of_the_analysis_is_refused_for_an_unknown_purpose_unit_or_mode(purpose, unit, mode, reason):
    from scripts import protocol_v5
    with pytest.raises(ValueError) as refused:
        protocol_v5.analysis_seed(json.loads(V5.read_text()), purpose, unit, mode=mode)
    assert str(refused.value) == reason


# Package B7b: the keys of the analysis plan of design B7b 1.4. The layout knows every key, and the value check every
# rule of each: one bad input per rule, and good inputs (another partition of the groups, the main alarm rule alone;
# the bounds of the grids' domains are taken in tcn/tests/test_metody.py, where both checks read one constant).

def _regroup(change):
    """A change of the analysis section: the groups of class D become change(groups), read when the test runs (so that
    this file collects on the code and the file before package B7b)."""
    def apply(a):
        a["interventions"]["D"]["groups"] = change(json.loads(json.dumps(a["interventions"]["D"]["groups"])))
    return apply


@pytest.mark.parametrize("change, reason", [
    (_regroup(lambda g: {"memory": g["memory"], "processes": g["processes"], "objects": g["modules"] + g["sockets"]}),
     None),
    (_at("diagnostics.alarm_rules", [[3, 5]]), None),
    (_at("interventions.C.orders", ["reversed", "shuffled"]), "invalid analysis"),
    # The merge of B7b: the protocol refuses what tcn/zasahy.py refuses (lengths distinct, C of at least 2 rows) and
    # the first seconds of an evaluable occurrence lie within the horizon.
    (_at("interventions.D.lengths", [6, 6, 12]), "invalid analysis"),
    (_at("interventions.C.lengths", [1, 6]), "invalid analysis"),
    (_at("evaluable.first_s", 240), "invalid analysis"),
    (_at("interventions.C.orders", []), "invalid analysis"),
    (_at("interventions.D.groups", {}), "invalid analysis"),
    (_regroup(lambda g: dict(g, memory=g["memory"] + ["mem_unknown"])), "invalid analysis"),
    (_regroup(lambda g: dict(g, memory=[c for c in g["memory"] if c != "mem_zero_ratio"])), "invalid analysis"),
    (_regroup(lambda g: dict(g, memory=[c for c in g["memory"] if c != "has_changed"],
                             processes=g["processes"] + ["has_changed"])), "invalid analysis"),
    (_regroup(lambda g: {" " if name == "sockets" else name: columns for name, columns in g.items()}),
     "invalid analysis"),
    (_at("interventions.validity", "every column, its first difference and rolling mean inside train quantiles"),
     "invalid analysis"),
    (_at("interventions.validity.quantiles", [0, 1]), "invalid analysis"),
    (_at("interventions.validity.quantiles", [.001]), "invalid analysis"),
    (_at("interventions.validity.moving_average_rows", 1), "invalid analysis"),
    (_at("interventions.validity.moving_average_rows", 6.0), "invalid analysis"),
    (_at("interventions.validity.note"), "missing protocol key: analysis.interventions.validity.note"),
    (_at("interventions.volume_class", " "), "invalid analysis"),
    (_at("interventions.note"), "missing protocol key: analysis.interventions.note"),
    (_at("diagnostics.tree_depth", 0), "invalid analysis"),
    (_at("diagnostics.min_positive_episodes", 20.0), "invalid analysis"),
    (_at("diagnostics.contexts", []), "invalid analysis"),
    (_at("diagnostics.contexts", [2, 2, 31]), "invalid analysis"),
    (_at("diagnostics.contexts", [0, 31]), "invalid analysis"),
    (_at("diagnostics.alarm_rules", [[2, 3], [4, 7]]), "invalid analysis"),
    (_at("diagnostics.alarm_rules", [[3, 2], [3, 5]]), "invalid analysis"),
    (_at("diagnostics.alarm_rules", [[3, 5], [3, 5]]), "invalid analysis"),
    (_at("diagnostics.depth", 3), "unknown protocol key: analysis.diagnostics.depth"),
    # F3 of the verification of B7a: the domains of the grids (scripts/protocol_v5.py GRID_DOMAINS).
    (_at("methods.Z3.grid", {"ewma_alpha": [1.5]}), "invalid analysis"),
    (_at("methods.Z3.grid", {"ewma_alpha": ["fast"]}), "invalid analysis"),
    (_at("methods.Z5.grid", {"ridge_alpha": [-1]}), "invalid analysis"),
    (_at("methods.Z5.grid", {"ridge_alpha": [1, 1.0]}), "invalid analysis"),
    (_at("methods.Z1.grid", {"moving_average_rows": [0], "cusum_shift": [.5]}), "invalid analysis"),
    (_at("methods.Z1.grid", {"moving_average_rows": [2.5], "cusum_shift": [.5]}), "invalid analysis"),
    (_at("methods.Z1.grid", {"moving_average_rows": [4], "cusum_shift": [-2]}), "invalid analysis"),
    # F2 of the verification of B7b: the moving average and the contexts within the window of 32 rows.
    (_at("interventions.validity.moving_average_rows", 32), None),
    (_at("interventions.validity.moving_average_rows", 33), "invalid analysis"),
    (_at("diagnostics.contexts", [1, 2, 4, 8, 16, 32]), "invalid analysis"),
    # F5 of the verification of B7b (mutant P5): the open lower bounds of the grids' domains.
    (_at("methods.Z3.grid", {"ewma_alpha": [0]}), "invalid analysis"),
    (_at("methods.Z5.grid", {"ridge_alpha": [0]}), "invalid analysis"),
], ids=["groups_another_partition", "main_alarm_rule_alone", "order_unknown", "lengths_twice", "c_of_one_row",
        "first_s_beyond_the_horizon", "no_order",
        "no_group", "group_column_unknown", "group_column_missing", "bin_split_over_groups", "group_without_a_name",
        "validity_a_text", "quantiles_at_0_and_1", "one_quantile", "average_of_one_row", "average_not_an_integer",
        "validity_no_note", "volume_class_blank", "interventions_no_note", "tree_depth_0",
        "episodes_not_an_integer", "no_context", "context_twice",
        "context_0", "alarm_rules_without_the_main", "alarm_rule_k_above_n", "alarm_rule_twice",
        "diagnostics_unknown_key", "ewma_above_1", "ewma_a_name", "ridge_negative",
        "ridge_twice_by_value", "average_of_0", "average_not_an_integer", "cusum_negative",
        "average_of_the_window", "average_longer_than_the_window", "context_of_the_whole_window", "ewma_of_0",
        "ridge_of_0"])
def test_the_loader_knows_every_key_and_value_of_the_analysis_plan_of_b7b(change, reason):
    """Design B7b 1.4: analysis.interventions (the orders of C of ORDERS; the groups of D, named, partitioning the 20
    behaviour columns and the four channels of a bin, which stay in one group; the validity predicate's quantiles
    0 < low < high < 1 and its moving average of an integer of 2 to window_rows rows, with a note; min_evaluable equal
    to analysis.min_occurrences, the FILE case; the volume class a text), analysis.diagnostics (the depth and the
    episodes integers of at least 1; the contexts increasing integers of 1 to window_rows - 1, the FILE case another
    order; distinct rules k of n with the main one among them) and the domains of the grids (F3 of the verification of
    B7a, their open lower bounds F5 of the verification of B7b). F2 of the verification of B7b: the moving average and
    the contexts are bound to the window of 32 rows."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    change(doc["analysis"])
    if reason is None:
        protocol_v5.check_layout(doc)
    else:
        with pytest.raises(ValueError) as refused:
            protocol_v5.check_layout(doc)
        assert str(refused.value) == reason


def test_the_keys_of_b7b_are_those_the_skeleton_names():
    """The values of design B7b 1.4 in the real file: C reversed and random; D the four groups memory, processes,
    modules and sockets over every input of the neural channel; the predicate at the quantiles 0.001 and 0.999 of
    train with a moving average of 6 rows; the evaluable minimum 8, analysis.min_occurrences; the diagnostics of
    proposal 8.5; K2a against Z1, Z2 and both variants of Z4 (question Q13, provisional), and the variants are those of
    tcn/metody.py's Z4."""
    from features.archive import BEHAVIOR_NAMES
    from features.windows import BIN_PRIZNAKY
    from scripts import protocol_v5
    a = json.loads(V5.read_text())["analysis"]
    i = a["interventions"]
    assert (i["C"]["orders"], list(i["D"]["groups"]), i["validity"]["quantiles"], i["validity"]["moving_average_rows"],
            i["min_evaluable"], a["min_occurrences"]) == (["reversed", "random"], ["memory", "processes", "modules",
                                                                                  "sockets"], [.001, .999], 6, 8, 8)
    assert sorted(c for columns in i["D"]["groups"].values() for c in columns) == sorted(BEHAVIOR_NAMES + BIN_PRIZNAKY)
    keys = ("tree_depth", "min_positive_episodes", "contexts", "alarm_rules")
    assert {key: a["diagnostics"][key] for key in keys} == {
        "tree_depth": 3, "min_positive_episodes": 20, "contexts": [1, 2, 4, 8, 16, 31],
        "alarm_rules": [[2, 3], [3, 5], [4, 7]]}
    assert a["k2a"]["compare"] == protocol_v5.CONFIRMATORY["k2a"] == ["Z1", "Z2", "Z4:load", "Z4:residual"]
    assert protocol_v5.VARIANTS == {"Z4": ("load", "residual")} and protocol_v5.COMPARISONS == (
        "Z0", "Z1", "Z2", "Z3", "Z4:load", "Z4:residual", "Z5")


# Package B7c: the keys of the analysis plan of design B7c 1.2. The layout knows every key, and the value check every
# rule of each: one bad input per rule, and good inputs (another level of a bound, another alpha); metrics_problem
# names each rule exactly, for tcn/eval.py, which raises its text.

@pytest.mark.parametrize("change, reason", [
    (_at("metrics.o3_bound.level", .99), None),
    (_at("metrics.event_vs_clean.alpha", .01), None),
    (_at("metrics.o3_bound"), "missing protocol key: analysis.metrics.o3_bound"),
    (_at("metrics.o2_bound.sides", 1), "unknown protocol key: analysis.metrics.o2_bound.sides"),
    (_at("metrics.alarm_rate_interval.method", "exact"), "invalid analysis"),
    (_at("metrics.dispersion.source", " "), "invalid analysis"),
    (_at("metrics.o2_bound.level", 1), "invalid analysis"),
    (_at("metrics.o3_bound.level", True), "invalid analysis"),
    (_at("metrics.event_vs_clean.alpha", 0), "invalid analysis"),
    (_at("metrics.dispersion.unit", "window"), "invalid analysis"),
    (_at("metrics.event_vs_clean.alternative", "less"), "invalid analysis"),
    (_at("metrics.classifier.windows", ["accuracy"]), "invalid analysis"),
    (_at("metrics.classifier.majority", ["occurrence", "session"]), "invalid analysis"),
    (_at("metrics.note", None), "invalid analysis"),
    (_at("linkage.VO6", 1), "invalid analysis"),
    (_at("linkage.VO7", "O9 (E6)"), "unknown protocol key: analysis.linkage.VO7"),
    (_at("linkage.note"), "missing protocol key: analysis.linkage.note"),
], ids=["o3_level_0_99", "alpha_0_01", "no_o3_bound", "bound_unknown_key", "interval_not_garwood", "no_source",
        "level_one", "level_a_bool", "alpha_zero", "dispersion_over_windows", "test_towards_fewer",
        "classifier_without_macro_f1", "majorities_reordered", "metrics_no_note", "linkage_not_a_text",
        "linkage_unknown_question", "linkage_no_note"])
def test_the_loader_knows_every_key_and_value_of_the_analysis_plan_of_b7c(change, reason):
    """Design B7c 1.2: analysis.metrics (each metric its one method of METRIC_METHODS and a source; the levels of the
    interval and of the bounds and the alpha of the test shares in (0, 1); the dispersion over sessions; the test
    one-sided towards more alarms during events; the classifier's measures and majorities exactly) and
    analysis.linkage (a text for each research question, a note)."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    change(doc["analysis"])
    if reason is None:
        protocol_v5.check_layout(doc)
    else:
        with pytest.raises(ValueError) as refused:
            protocol_v5.check_layout(doc)
        assert str(refused.value) == reason


@pytest.mark.parametrize("change, reason", [
    (_at("o3_bound"), "analysis.metrics must be an object of exactly the keys alarm_rate_interval, classifier, "
                      "dispersion, event_vs_clean, note, o2_bound, o3_bound"),
    (_at("o2_bound.method", "garwood"), "analysis.metrics.o2_bound.method must be poisson_upper, the method "
                                        "tcn/eval.py implements"),
    (_at("alarm_rate_interval.level", 95), "analysis.metrics.alarm_rate_interval.level must be a number in (0, 1)"),
    (_at("event_vs_clean.alternative", "two-sided"),
     "analysis.metrics.event_vs_clean.alternative must be greater: the thesis' test is one-sided, more alarms during "
     "events than in clean traffic"),
    (_at("classifier.majority", ["session"]), 'analysis.metrics.classifier.majority must be ["session", '
                                              '"occurrence"]'),
], ids=["no_o3_bound", "o2_by_garwood", "level_95", "two_sided_test", "majority_per_session_only"])
def test_metrics_problem_names_each_rule(change, reason):
    """tcn/eval.py raises the text of metrics_problem (one check for the protocol and the evaluation)."""
    from scripts import protocol_v5
    metrics = json.loads(V5.read_text())["analysis"]["metrics"]
    assert protocol_v5.metrics_problem(metrics) is None
    change(metrics)
    assert protocol_v5.metrics_problem(metrics) == reason


def test_the_keys_of_b7c_are_those_the_skeleton_and_the_design_name():
    """The values of design B7c 1.2 in the real file: the Garwood interval at 0.95, the dispersion over sessions, the
    one-sided exact test at alpha 0.05, the one-sided bounds of O2 and O3 at 0.95 (proposal 9.2), the classifier's
    accuracy and macro-F1 over windows and its majorities per session and per occurrence, each with its source; and
    the linkage table of the lead's skeleton B7, addendum 2 point 4, word for word."""
    from scripts import protocol_v5
    a = json.loads(V5.read_text())["analysis"]
    m = a["metrics"]
    assert {name: m[name]["method"] for name in protocol_v5.METRIC_METHODS} == protocol_v5.METRIC_METHODS
    assert (m["alarm_rate_interval"]["level"], m["o2_bound"]["level"], m["o3_bound"]["level"],
            m["event_vs_clean"]["alpha"], m["event_vs_clean"]["alternative"], m["dispersion"]["unit"]) == (
        .95, .95, .95, .05, "greater", "session")
    assert (m["classifier"]["windows"], m["classifier"]["majority"]) == (["accuracy", "macro_f1"],
                                                                         ["session", "occurrence"])
    assert {key: value for key, value in a["linkage"].items() if key != "note"} == protocol_v5.LINKAGE == {
        "VO1": "O8 a O1 (E1)", "VO2": "O2, O3 a test z bodu 2 (E2)",
        "VO3": "časť vlastníka so vzorkami, mimo protokolu (E3, D16)", "VO4": "K1, K2 a bod 1 (E4)",
        "VO5": "O7 (E5)", "VO6": "O6 a bod 2 (E2)"}
    assert protocol_v5.analysis_plan(json.loads(V5.read_text()))["linkage"] == a["linkage"]


# Package B9a (design B9a 1.1, agent P): the seeded level of the guest at the start of a group (since the fix of B9a,
# F4 of its verification: one level for every group of both modes), and the control deal at other rehearsal sizes (N1
# of the confirmation of B4b).

def test_every_group_of_both_modes_starts_from_the_level_lab_install_sh_seeds(monkeypatch):
    """The fix of package B9a (F4 of its verification; question Q18 to the lead, provisional by its proposal):
    reset_seed(p) is streams.seeded_level.seed, one seeded level for every group of both modes, the level that
    lab/install.sh seeds on its line python3 guest_state.py reset --seed 0. It is no random stream: guest_reset is in
    neither PURPOSES nor streams.purposes nor the rule of the streams. The bound of its value check is the guest's:
    the parser of lab/guest_state.py takes the seed and 10^18 - 1, and refuses 10^18."""
    from lab import guest_state
    from scripts import collection, protocol_v5
    seeds = re.findall(r"guest_state\.py reset --seed ([0-9]+)", (ROOT / "lab/install.sh").read_text())
    p = collection.protocol(V5)
    assert seeds == ["0"] and protocol_v5.reset_seed(p) == int(seeds[0]) == p["streams"]["seeded_level"]["seed"]
    assert "guest_reset" not in protocol_v5.PURPOSES and "guest_reset" not in p["streams"]["purposes"]
    assert "guest_reset" not in p["streams"]["rule"]
    given = []
    monkeypatch.setattr(guest_state, "reset", given.append)
    for value in (protocol_v5.reset_seed(p), protocol_v5.RESET_SEED_BOUND - 1):
        guest_state.main(["reset", "--seed", str(value)])
    assert given == [0, 10 ** 18 - 1]
    with pytest.raises(SystemExit):
        guest_state.main(["reset", "--seed", str(protocol_v5.RESET_SEED_BOUND)])


@pytest.mark.parametrize("change, reason", [
    (lambda level: level.update(seed=10 ** 18 - 1), None),
    (lambda level: level.update(seed=10 ** 18), "invalid streams.seeded_level"),
    (lambda level: level.update(seed=-1), "invalid streams.seeded_level"),
    (lambda level: level.update(seed=True), "invalid streams.seeded_level"),
    (lambda level: level.update(seed=0.0), "invalid streams.seeded_level"),
    (lambda level: level.update(note=None), "invalid streams.seeded_level"),
    (lambda level: level.pop("note"), "missing protocol key: streams.seeded_level.note"),
    (lambda level: level.update(seeds=[0]), "unknown protocol key: streams.seeded_level.seeds"),
], ids=["largest_seed", "19_digits", "negative", "a_bool", "a_float", "note_not_a_string", "no_note", "unknown_key"])
def test_the_loader_knows_the_key_and_the_value_of_the_seeded_level(change, reason):
    """The fix of package B9a: streams.seeded_level has exactly a seed and a note; the seed is an integer (no bool,
    no float) of 0 to 10^18 - 1, as lab/guest_state.py takes it, and the note a string. reset_seed(p) returns the
    largest seed, and refuses every seed the value check refuses, with the same reason."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    change(doc["streams"]["seeded_level"])
    if reason is None:
        protocol_v5.check_layout(doc)
        assert protocol_v5.reset_seed(doc) == 10 ** 18 - 1
        return
    with pytest.raises(ValueError) as refused:
        protocol_v5.check_layout(doc)
    assert str(refused.value) == reason
    if reason == "invalid streams.seeded_level":
        with pytest.raises(ValueError) as refused:
            protocol_v5.reset_seed(doc)
        assert str(refused.value) == reason


def test_a_reset_seed_is_refused_for_another_schema_and_takes_no_group_and_no_mode():
    """reset_seed(p) refuses a protocol of another schema by name. It takes no group and no mode, since every group
    of both modes starts from the one seeded level, so the call of B9a, reset_seed(p, group, mode=...), is refused."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    with pytest.raises(ValueError) as refused:
        protocol_v5.reset_seed(dict(doc, schema="hyptcn3/collection-protocol/2"))
    assert str(refused.value) == "the seed of the guest's reset requires protocol schema 3"
    with pytest.raises(TypeError):
        protocol_v5.reset_seed(doc, "v5-train-1", mode="campaign")


# F6 of the verification of B9a (its mutant s3_check_gt, '>' for '>='): one kind of class B with the doses 1 and 2,
# whose control and negative each hold every dose once on each VM and lie twice in each of the scenarios s1 and s2.
# The cards share exactly as many scenarios as they hold doses on both VMs. Per VM, the sessions of one slot each hold
# (scenario, polarity, dose).
BOUND = {"paired": {vm: [("s1", "control", 1), ("s2", "control", 2), ("s1", "negative", 1), ("s2", "negative", 2)]
                    for vm in ("a", "b")},
         "unpaired": {vm: [("s1", "control", 1), ("s2", "control", 2), ("s2", "negative", 1), ("s1", "negative", 2)]
                      for vm in ("a", "b")}}


@pytest.mark.parametrize("layout", BOUND)
def test_the_pairing_of_the_doses_is_checked_when_the_cards_share_as_many_scenarios_as_doses(layout):
    """S3 of the B8 verification at its bound (F6 of the verification of B9a): the check controls asks every dose that
    both cards hold on every VM to lie in a scenario of a control and of a negative of it as soon as the cards share at
    least as many scenarios as there are such doses, equality included. Here they share exactly two for two doses.
    Paired, the check passes; with the doses of the negatives swapped between the scenarios, both doses lie in no
    common scenario and both are named. Every other row holds: per_kind 4 and per_dose 2 and 2, every card and dose
    within 1 per VM and per scenario, no slot empty."""
    from scripts import protocol_v5
    doc = {"controls": {"slots_per_session": 1, "per_kind": 4, "negatives_per_kind": 4,
                        "kinds": {"k": {"class": "B", "doses": [1, 2], "per_dose": [2, 2]}}},
           "vms": [{"name": "a"}, {"name": "b"}], "scenarios": {"s1": {}, "s2": {}}}
    sessions = [{"role": "test_controls", "group": f"g-{vm}", "position": i, "scenario": scenario, "vm": vm,
                 "controls": [{"kind": "k", "polarity": polarity, "class": "B", "dose": dose}]}
                for vm, mine in BOUND[layout].items() for i, (scenario, polarity, dose) in enumerate(mine)]
    named = [] if layout == "paired" else [
        f"control k: dose {dose} lies in no scenario of both its controls and its negatives" for dose in (1, 2)]
    assert protocol_v5.check_controls(doc, {"mode": "campaign", "sessions": sessions}) == named


@pytest.mark.parametrize("groups, reason", [
    (2, None),
    (4, None),
    (3, "VM a holds 9 control slots, but every card within 1 per VM puts 10 to 17 of the 27 dealt cards on each VM"),
    (5, "VM b holds 18 control slots, but every card within 1 per VM puts 20 to 25 of the 45 dealt cards on each VM"),
], ids=["two_groups_per_role", "four_groups_per_role", "three_groups_per_role", "five_groups_per_role"])
def test_the_control_deal_is_drawn_again_until_its_cards_are_balanced(groups, reason, tmp_path, monkeypatch):
    """N1 of the confirmation of B4b: _deal_controls held the rows of the check controls only at the file's
    rehearsal size of 2 groups per role. It now draws the deal again until no session holds a kind twice and every
    card lies within 1 per VM and per scenario. At 2 groups per role (the file) the first draw passes, as in the
    campaign, so neither deal changed; at 4 its first draw fails (a card off by 2 per scenario), a later one passes,
    and the self-check of the rehearsal passes in both modes. At 3 and 5 test_controls has one group more on one VM:
    its 9 slots more are more than the cards can follow when each lies within 1 per VM, so no deal can pass and the
    plan says so by name before it draws again (design B9a 1.1 asks for 3, 4 and 5; see the problems of agent P)."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    doc["rehearsal"]["groups_per_role"] = groups
    draws, real = [], protocol_v5._cards_balanced
    monkeypatch.setattr(protocol_v5, "_cards_balanced", lambda p, deal: draws.append(real(p, deal)) or draws[-1])
    if reason is not None:
        with pytest.raises(ValueError) as refused:
            protocol_v5.plan(doc, "rehearsal")
        assert (str(refused.value), draws) == ("controls of role test_controls: " + reason, [])
        return
    protocol_v5.plan(doc, "rehearsal")
    assert draws[-1] is True and not any(draws[:-1]) and (len(draws) == 1) == (groups == 2)
    del draws[:]
    protocol_v5.plan(doc, "campaign")
    assert draws == [True]
    monkeypatch.undo()
    for mode in ("campaign", "rehearsal"):
        (tmp_path / mode).mkdir()
        code, report = selfcheck(tmp_path / mode, doc, "--mode", mode)
        assert (code, report["passed"]) == (0, True), [c for c in report["checks"] if c["result"] != "passed"]


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_a_dose_of_class_b_lies_in_a_scenario_of_a_control_and_of_a_negative_where_the_counts_allow_it(mode,
                                                                                                     monkeypatch):
    """S3 of the B8 verification, on the plans of the file and of five other protocol names. In a campaign each card
    of class B has 7 occurrences, one or more in each of the 4 scenarios, and each of its doses (2, 2 and 3
    occurrences) lies on both VMs, so the counts allow it: the doses of both kinds are anchored (_anchor_doses) and
    every dose lies in a scenario of a control and of a negative of it. In the rehearsal a card has 1 or 2
    occurrences with different doses, so no dose lies on both VMs of a card: the counts do not allow it, and the doses
    are dealt as before, without an anchor."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    kinds = {kind: k for kind, k in doc["controls"]["kinds"].items() if k["class"] == "B"}
    anchored, real = [], protocol_v5._anchor_doses
    monkeypatch.setattr(protocol_v5, "_anchor_doses", lambda kind, *rest: anchored.append(kind) or real(kind, *rest))
    for name in [doc["name"]] + [f"name-{k}" for k in range(5)]:
        del anchored[:]
        at = {}
        for s, x in _dosed(protocol_v5.plan(dict(doc, name=name), mode)):
            at.setdefault((x["kind"], x["polarity"], x["dose"]), set()).add((s["vm"], s["scenario"]))
        if mode == "rehearsal":
            assert anchored == [] and all(len({vm for vm, _ in places}) == 1 for places in at.values()), name
            continue
        assert anchored == sorted(kinds), name
        for kind, k in kinds.items():
            for dose in k["doses"]:
                control, negative = at[kind, "control", dose], at[kind, "negative", dose]
                assert {vm for vm, _ in control} == {vm for vm, _ in negative} == {"a", "b"}, (name, kind, dose)
                assert {sc for _, sc in control} & {sc for _, sc in negative}, (name, kind, dose)


def test_the_carrier_boots_of_k2_are_those_of_the_campaign_in_both_modes_of_the_self_check(tmp_path):
    """F3 of the verification of B7c: the self-check in mode rehearsal checks the same file, so it names the same count
    as in mode campaign; the rehearsal's own carrier boots (2 of test_benign and 2 of test_controls) are bound neither
    here nor by tcn/k2.py, which checks the count in mode campaign only."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    doc["analysis"]["interventions"]["boots"] = 21
    code, report = selfcheck(tmp_path, doc, "--mode", "rehearsal")
    assert (code, report["mode"]) == (2, "rehearsal")
    assert {c["check"]: (c["result"], c["reasons"]) for c in report["checks"]} == expected_checks(analysis=[
        "analysis.interventions.boots is 21, the carrier roles of the campaign plan hold 20 boots (test_benign 12, "
        "test_controls 8)"])
    groups = {s["group"] for s in protocol_v5.plan(doc, "rehearsal")["sessions"] if s["role"] in ("test_benign",
                                                                                                   "test_controls")}
    assert len(groups) == 4


def _deal(plan):
    """The control deal of `plan` as _deal_controls holds it before the doses: per group of test_controls its VM, the
    scenarios of its sessions and their cards (kind, polarity), None for an empty slot."""
    groups = {}
    for s in plan["sessions"]:
        if s["role"] == "test_controls":
            group = groups.setdefault(s["group"], {"group": s["group"], "vm": s["vm"], "scenarios": [], "labels": []})
            group["scenarios"].append(s["scenario"])
            group["labels"].append([None if x["kind"] is None else (x["kind"], x["polarity"]) for x in s["controls"]])
    return list(groups.values())


@pytest.mark.parametrize("case", [None, "kind_twice", "card_vm", "card_scenario"],
                         ids=["the_deal_of_the_file", "kind_twice", "card_vm", "card_scenario"])
def test_the_redraw_of_the_control_deal_asks_for_each_row_a_draw_decides(case):
    """N1 of the confirmation of B4b: _cards_balanced, which ends the redraws of _deal_controls, holds for the deal
    of the plan of the file and fails on each row of the check controls that a draw decides, as the cases of the
    self-check change the plan: a session that holds a kind twice (kind_twice), a card off by 2 per VM (card_vm) and
    one off by 2 per scenario (card_scenario)."""
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    plan = protocol_v5.plan(doc)
    if case is not None:
        PLAN_CASES[case](doc, plan)
    assert protocol_v5._cards_balanced(doc, _deal(plan)) is (case is None)


# The deal of one kind of class B with two doses: per VM the sessions of one slot, each (scenario, polarity).
LAYOUTS = {"as_many_doses_as_common_scenarios": ([2, 2], {vm: [("s1", "control"), ("s2", "control"),
                                                                ("s1", "negative"), ("s2", "negative")]
                                                           for vm in ("a", "b")}),
           "a_dose_on_one_vm": ([1, 1], {"a": [("s1", "control"), ("s2", "negative")],
                                         "b": [("s2", "control"), ("s1", "negative")]})}


@pytest.mark.parametrize("layout", LAYOUTS)
def test_the_doses_are_paired_at_the_bounds_where_the_counts_allow_it(layout, monkeypatch):
    """S3 of the B8 verification at the bounds of 'the counts allow it', on one kind of class B with two doses whose
    control and negative lie in the two scenarios s1 and s2. With 2 occurrences of each dose on each card, every dose
    lies on both VMs, and the doses are as many as the common scenarios: both are anchored, and in each of 20 streams
    every dose lies in a scenario of a control and of a negative of it. With 1 occurrence of each dose a dose lies on
    one VM only, so the counts do not allow it: no anchor, and every card takes each dose once, as in package B8."""
    import random
    from scripts import protocol_v5
    per_dose, sessions = LAYOUTS[layout]
    c = {"kinds": {"k": {"class": "B", "doses": [1, 2], "per_dose": per_dose}}}
    calls, real = [], protocol_v5._anchor_doses
    monkeypatch.setattr(protocol_v5, "_anchor_doses", lambda kind, *rest: calls.append(kind) or real(kind, *rest))
    for stream in range(20):
        groups = [{"group": vm, "vm": vm, "scenarios": [scenario for scenario, _ in mine],
                   "labels": [[("k", polarity)] for _, polarity in mine]} for vm, mine in sessions.items()]
        del calls[:]
        protocol_v5._deal_doses(c, groups, random.Random(stream))
        at, held = {}, Counter()
        for group in groups:
            for scenario, [(kind, polarity, dose)] in zip(group["scenarios"], group["labels"]):
                at.setdefault((polarity, dose), set()).add(scenario)
                held[polarity, dose, group["vm"]] += 1
        if per_dose == [2, 2]:
            assert calls == ["k"] and all(at["control", d] & at["negative", d] for d in (1, 2)), stream
            assert set(held.values()) == {1} and len(held) == 8, stream
        else:
            assert calls == [] and sorted((p, d) for p, d, _ in held) == [("control", 1), ("control", 2),
                                                                          ("negative", 1), ("negative", 2)], stream
