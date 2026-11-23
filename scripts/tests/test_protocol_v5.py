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
analysis, which the plan never draws).
"""
from collections import Counter
import json
import math
from pathlib import Path

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
    """The lead's must_fix 4 on B4: K2a is decided against Z1, Z2 and Z4 (proposal 4.1)."""
    doc["analysis"]["k2a"]["compare"].remove("Z4")
    return {"analysis": ['analysis.k2a.compare is ["Z1", "Z2"], proposal 4.1 names ["Z1", "Z2", "Z4"]']}


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
    events on VM a and none on VM b (F1 of the verification of B4b)."""
    for s in plan["sessions"]:
        if s["role"] == "dev":
            s["vm"] = "a"
    return {"role_sizes": ["role dev has no group on VM b"],
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
    both VMs stay within 1."""
    train, other = [s for s in plan["sessions"] if s["role"] == "train"], {"a": "b", "b": "a"}
    on_vm = Counter((s["vm"], s["scenario"]) for s in train)
    groups = {}
    for s in train:
        groups.setdefault(s["group"], []).append(s)
    ss = next(ss for ss in groups.values()
              if all(on_vm[other[ss[0]["vm"]], n] == 5 for n in set(SCENARIOS) - {s["scenario"] for s in ss}))
    for s in ss:
        s["vm"] = other[s["vm"]]
    return {"events": [f"role train: events of type {t} per VM differ by more than 1" for t in TYPES]}


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
                                      z0_without_repetitions, level_of_95, streams_without_bootstrap)}
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
                                      session_draws_an_analysis_stream)}
REPLACEMENT_CASES = {f.__name__: f for f in (replaced_type, replaced_streams, replaced_in_guard,
                                             replaced_before_first_s, replaced_tenths, replaced_dose,
                                             # Package B7a: a monkeypatched seed of the analysis.
                                             analysis_seed_of_the_plan)}
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
    units = {"z0_alarms": list(ROLES),
             "bootstrap": ["k1/Z3", "k1/Z5", "k2a/Z1", "k2a/Z2", "k2a/Z4", "k2b/Z3", "k2b/Z5"]}
    assert protocol_v5.analysis_units(doc) == units
    assert set(doc["streams"]["purposes"]) == set(protocol_v5.PURPOSES) and {"z0_alarms", "bootstrap"} <= set(
        protocol_v5.PURPOSES)
    for mode, name in (("campaign", "server-normal-v5"), ("rehearsal", "server-normal-v5-generalka")):
        plan = protocol_v5.plan(doc, mode)
        drawn = {purpose for s in plan["sessions"] for x in (s, protocol_v5.replacement(doc, s, 2, mode=mode))
                 for purpose in x["seeds"]}
        assert drawn == set(protocol_v5.PURPOSES) - {"z0_alarms", "bootstrap"}, mode
        assert {(purpose, unit): protocol_v5.analysis_seed(doc, purpose, unit, mode=mode)
                for purpose, mine in units.items() for unit in mine} == {
            (purpose, unit): protocol_v5.seed(name, purpose, unit, -1, 0) for purpose, mine in units.items()
            for unit in mine}


@pytest.mark.parametrize("purpose, unit, mode, reason", [
    ("traffic", "test_benign", "campaign", "'traffic' is no stream of the analysis (z0_alarms, bootstrap)"),
    ("z0_alarms", "test", "campaign", "'test' is no unit of the analysis stream z0_alarms (train, dev, calibration, "
                                      "test_benign, test_controls)"),
    ("bootstrap", "k1/Z1", "campaign", "'k1/Z1' is no unit of the analysis stream bootstrap (k1/Z3, k1/Z5, k2a/Z1, "
                                       "k2a/Z2, k2a/Z4, k2b/Z3, k2b/Z5)"),
    ("bootstrap", "k1/Z3", "final", "unknown plan mode: final"),
], ids=["purpose_of_the_plan", "unknown_role", "method_k1_does_not_compare", "unknown_mode"])
def test_a_seed_of_the_analysis_is_refused_for_an_unknown_purpose_unit_or_mode(purpose, unit, mode, reason):
    from scripts import protocol_v5
    with pytest.raises(ValueError) as refused:
        protocol_v5.analysis_seed(json.loads(V5.read_text()), purpose, unit, mode=mode)
    assert str(refused.value) == reason
