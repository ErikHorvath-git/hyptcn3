"""Protocol v5: the layout of schema 3, its schedule and the self-check of a protocol file (package B4).

Schema hyptcn3/collection-protocol/3 is the v5 layout (docs/NAVRH_PROTOKOL_V5.sk.md, chapters 5.5, 6.4, 7.2-7.5,
8.3, 8.4, 10.1, 10.4, 10.9). This module holds all v5 logic; scripts/collection.py calls it from protocol(),
plan() and its subcommand selfcheck:

    check_layout(p)                the loader's part: unknown and missing keys, malformed values of the v5 sections
    plan(p, mode)                  the schedule of a campaign or of its rehearsal (a mode of the same file)
    replacement(p, session, n)     attempt n of a planned session: the same assignment, new times and traffic seed
    plans_events(p)                whether its sessions list events and keep events.json (log audit, corpus build)
    analysis_plan(p)               the analysis plan the training and the evaluation read (B6, B7)
    selfcheck(path, mode, stage)   every check of the self-check on the file and on its plan

The loader does not judge balance, role sizes, the place of null values or the binding of the score coverage
gate to invalid_rows.max; the self-check does. Its check functions take (doc, plan) so that a test can pass a
mutated plan. A value a later stage determines (proposal 10.9) is null or preliminary at its one place in the
file; determined_at names the stage of each such path, and `*` stands for every key of an object at that level.
"""
from collections import Counter
import copy
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random

SCHEMA = "hyptcn3/collection-protocol/3"
PLAN_SCHEMA = "hyptcn3/collection-plan/2"
STAGES = ("G0", "G1", "G2", "G3a", "G3b", "G4", "G5", "G6")
DETERMINED = ("G1", "G2", "G3a", "G3b")  # The stages a path of determined_at may belong to.
MODES = ("campaign", "rehearsal")
ROLES = ("train", "dev", "calibration", "test_benign", "test_controls")
CONTROL_ROLE = "test_controls"  # Its sessions hold controls on the VM and no events (proposal 7.2, 7.4).
# Proposal 7.3: train, dev and calibration in this order, then the two test roles interleaved in time.
TIME_RANK = {"train": 0, "dev": 1, "calibration": 2, "test_benign": 3, "test_controls": 3}
INTERLEAVED = ("test_benign", "test_controls")
# The random streams of the plan and the unit each one is drawn for (proposal 5.5; the streams section).
PURPOSES = {"scenario_order": "block", "event_free_position": "role", "event_deck": "role",
            "control_deck": "role", "event_times": "session", "traffic": "session"}
METHODS = ("Z0", "Z1", "Z2", "Z3", "Z4", "Z5", "M")
MAX_INVALID_ROWS = 6  # Proposal 10.9 and D4: six event boundaries of a session with three events.
MAX_DRAWS = 1000  # Redraws of a schedule that meets a full-snapshot guard, or of unbalanced scenario blocks.
# Names the protocol uses that are registered only from package B5b (the profiles of the generator) and B8 (the
# four new control kinds); the check lab_register stays pending while one of them is unknown. B5a registered the
# empty event naprazdno in lab/udalosti.py.
PENDING_IN_LAB = ("eshop", "corp", "kontrola_modul_jadra", "kontrola_pocuvajuci_soket",
                  "kontrola_zapisovac_pamate", "kontrola_davka_procesov")

# Every top-level key of a schema-3 protocol; vms or the pair domain/target as in schema 2, two optional notes.
# A section another package adds (B5b: profiles) is added here and to config/collection-v5.json together.
TOP_LEVEL = ("schema", "name", "status", "profile", "interval_s", "max_gap_s", "bin_bytes", "window_rows",
             "stride", "full_every", "cycles", "pilot_cycles", "warmup_s", "min_free_gib", "quality_policy",
             "min_score_coverage", "invalid_rows", "replacement", "group_prefix", "group_sessions", "roles",
             "interleave", "scenarios", "scenario_rule", "events", "full_snapshot_guard", "controls", "streams",
             "audit", "exceptions", "analysis", "rehearsal", "determined_at")
OPTIONAL = ("vms_note", "note")


class Each:
    """An object with free keys, each value an object with the fixed inner set `inner`."""

    def __init__(self, inner):
        self.inner = inner


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
_INTERVENTION = _fixed("lengths", "per_boot")
ANALYSIS = _fixed(
    "seeds", "deploy_seed", "fpr", "selection", "column_mask", "horizon_s", "reverberation_s", "min_occurrences",
    "note",
    architecture=_fixed("model", "window_rows", "note"),
    stopping=_fixed("rule", "patience_epochs", "max_epochs", "repeat_if_last_epoch", "note"),
    alarm_rule=_fixed("k", "n"),
    methods={name: _fixed("what", "grid") for name in METHODS},
    k1=_TEST, k2a=_TEST, k2b=_TEST,
    interventions=_fixed("boots", "validity", C=_INTERVENTION, D=_INTERVENTION),
    evaluable=_fixed("first_s", "scored_share"))
# The fixed inner sets of the v5 sections (design B4 1.1). invalid_rows, replacement, audit and exceptions keep
# their own readers (features/quality.py, collection.check_replacement, features/audit_policy.py).
INNER = {
    "roles": _fixed(*ROLES),
    "scenarios": Each(_fixed("profile", "intensity", "rate")),
    "scenario_rule": _fixed("min_peak_to_mean", "basis", "note", peak_share=_fixed("low", "high")),
    "events": _fixed("types", "per_session", "duration_s", "first_s", "min_gap_s", "tail_s", "grace_s",
                     "min_per_type", "note"),
    "full_snapshot_guard": _fixed("before_s", "note"),
    "controls": _fixed("per_kind", "negatives_per_kind", "slots_per_session", "min_duration_s", "duration_s",
                       "horizon_s", "note", kinds=Each(_fixed("class"))),
    "streams": _fixed("purposes", "rule", "note"),
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
                _walk(value[key], template.inner, f"{path}.{key}", out, missing_only)
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


def _ok_controls(p):
    c = p["controls"]
    if not (type(c["kinds"]) is dict and c["kinds"] and all(
            _text(kind) and type(v) is dict and v["class"] in ("A", "B") for kind, v in c["kinds"].items())):
        return False
    if not (_count(c["per_kind"]) and _count(c["negatives_per_kind"]) and _count(c["slots_per_session"])
            and _number(c["min_duration_s"]) and c["min_duration_s"] > 0 and _span(c["duration_s"])
            and c["duration_s"][0] >= c["min_duration_s"] and _number(c["horizon_s"]) and c["horizon_s"] > 0
            and type(c["note"]) is str):
        return False
    slots = c["slots_per_session"]
    return not (p["roles"][CONTROL_ROLE] and slots) or _fits(p, slots, c["duration_s"][1])


def _ok_streams(p):
    s = p["streams"]
    purposes = s["purposes"]
    return (type(purposes) is list and all(map(_text, purposes)) and len(set(purposes)) == len(purposes)
            and set(purposes) == set(PURPOSES) and _text(s["rule"]) and type(s["note"]) is str)


def _ok_analysis(p):
    a = p["analysis"]
    arch, stop, rule = a["architecture"], a["stopping"], a["alarm_rule"]
    seeds = a["seeds"]
    if not (_text(arch["model"]) and _count(arch["window_rows"], 1) and arch["window_rows"] == p["window_rows"]
            and type(arch["note"]) is str):
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
    if not all(type(m) is dict and _text(m["what"]) and (m["grid"] is None or type(m["grid"]) is dict)
               for m in a["methods"].values()):
        return False
    mask = a["column_mask"]
    if not (_text(a["selection"]) and (mask is None or type(mask) is list and all(map(_text, mask)))):
        return False
    for name in ("k1", "k2a", "k2b"):
        t = a[name]
        compare = t["compare"]
        if not (_text(t["statistic"]) and type(compare) is list and compare and len(set(compare)) == len(compare)
                and set(compare) <= set(METHODS) - {"M"} and (t["m"] is None or _number(t["m"])) and _text(t["rule"])):
            return False
    i = a["interventions"]
    for name in ("C", "D"):
        lengths = i[name]["lengths"]
        if not (type(lengths) is list and lengths and all(_count(n, 1) for n in lengths)
                and _count(i[name]["per_boot"], 1)):
            return False
    ev = a["evaluable"]
    return (_count(i["boots"], 1) and _text(i["validity"]) and all(_number(a[k]) and a[k] > 0 for k in (
        "horizon_s", "reverberation_s")) and _number(ev["first_s"]) and ev["first_s"] > 0
        and _number(ev["scored_share"]) and 0 < ev["scored_share"] <= 1 and _count(a["min_occurrences"], 1)
        and type(a["note"]) is str)


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
    seen = set()
    for paths in p["determined_at"].values():
        if type(paths) is not list or not all(map(_text, paths)):
            return False
        for pattern in paths:
            found = [path for path, _ in expand(p, pattern)]
            if not found or seen & set(found):
                return False  # A path names at least one existing key and belongs to one stage only.
            seen.update(found)
    return True


VALUE_CHECKS = (
    ("name", lambda p: _text(p["name"])), ("group_prefix", lambda p: type(p["group_prefix"]) is str),
    ("group_sessions", lambda p: _count(p["group_sessions"], 1)), ("roles", _ok_roles),
    ("interleave", _ok_interleave), ("scenarios", _ok_scenarios), ("scenario_rule", _ok_scenario_rule),
    ("events", _ok_events), ("full_snapshot_guard", _ok_guard), ("controls", _ok_controls),
    ("streams", _ok_streams), ("analysis", _ok_analysis), ("rehearsal", _ok_rehearsal),
    ("determined_at", _ok_determined))


def check_layout(p):
    """The loader's v5 checks: the first unknown or missing key, then the first malformed v5 section.

    ValueError `unknown protocol key: <path>`, `missing protocol key: <path>` or `invalid <section>`.
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


# ------------------------------------------------------------------ the schedule

def seed(name, purpose, group, session, attempt):
    """The seed of one random stream: sha256 of the protocol name, group, session, attempt and purpose."""
    return int(hashlib.sha256(json.dumps([name, group, session, attempt, purpose]).encode()).hexdigest()[:16], 16)


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


def _times(p, spans, rng):
    """[(start, duration)] in ms for items with the given [min, max] durations, in order.

    Durations are uniform in their span (1 ms grid); the free time of the session is split over the n + 1 gaps by
    uniform spacings (before the first item, between items, after the last). A draw with a start inside a guard is
    drawn again, at most MAX_DRAWS times.
    """
    if not spans:
        return []
    e = p["events"]
    first, gap, tail = _ms(e["first_s"]), _ms(e["min_gap_s"]), _ms(e["tail_s"])
    length, bands = _ms(p["cycles"] * p["interval_s"]), guards(p)
    for _ in range(MAX_DRAWS):
        durations = [rng.randint(_ms(low), _ms(high)) for low, high in spans]
        free = length - first - tail - sum(durations) - (len(spans) - 1) * gap
        if free < 0:
            raise ValueError("event schedule does not fit the session")
        offsets = sorted(rng.randint(0, free) for _ in spans)
        starts = [first + offsets[i] + sum(durations[:i]) + i * gap for i in range(len(spans))]
        if not any(low <= start < high for start in starts for _, low, high in bands):
            return list(zip(starts, durations))
    raise ValueError(f"no schedule outside the full-snapshot guards in {MAX_DRAWS} draws")


def _timing(p, start, duration):
    interval = _ms(p["interval_s"])
    return {"start_s": start / 1000, "duration_s": duration / 1000, "start_phase_s": start % interval / 1000,
            "stop_phase_s": (start + duration) % interval / 1000}


def _items(p, role, labels, rng):
    """The timed events (labels: types) or controls (labels: (kind, polarity) or None) of one session attempt."""
    if role != CONTROL_ROLE:
        times = _times(p, [tuple(p["events"]["duration_s"])] * len(labels), rng)
        return [{"type": t, "class": p["events"]["types"][t], **_timing(p, *when)} for t, when in zip(labels, times)]
    kinds = p["controls"]["kinds"]
    times = iter(_times(p, [tuple(p["controls"]["duration_s"])] * sum(x is not None for x in labels), rng))
    return [{"kind": None, "reason": "deck exhausted"} if x is None else
            {"kind": x[0], "polarity": x[1], "class": kinds[x[0]]["class"], **_timing(p, *next(times))}
            for x in labels]


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
    ensures, at most MAX_DRAWS times. Raises ValueError when the protocol cannot be planned.
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
    e, c = p["events"], p["controls"]
    count = max(e["per_session"])
    free = 0 in e["per_session"] and count > 0  # One session per group without events.
    for role in p["roles"]:
        if role == CONTROL_ROLE:
            cards = [((kind, polarity), n) for kind in sorted(c["kinds"])
                     for polarity, n in (("control", c["per_kind"]), ("negative", c["negatives_per_kind"]))]
            deck = _rounds(random.Random(seed(name, "control_deck", role, -1, 0)), cards,
                           max(c["per_kind"], c["negatives_per_kind"]))
            for group in groups[role]:
                group["labels"] = [[deck.pop(0) if deck else None for _ in range(c["slots_per_session"])]
                                   for _ in range(g)]
            continue
        position_rng = random.Random(seed(name, "event_free_position", role, -1, 0))
        type_rng = random.Random(seed(name, "event_deck", role, -1, 0))
        position_deck, type_deck = [], []  # Shuffled full rounds: counts in a role differ by at most 1.
        for group in groups[role]:
            if free and not position_deck:
                position_deck = position_rng.sample(range(g), g)
            empty = position_deck.pop(0) if free else None
            group["labels"] = []
            for i in range(g):
                labels = []
                for _ in range(0 if i == empty else count):
                    if not type_deck:
                        type_deck = type_rng.sample(sorted(e["types"]), len(e["types"]))
                    labels.append(type_deck.pop(0))
                group["labels"].append(labels)
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
        for purpose in (("control_deck",) if role == CONTROL_ROLE else ("event_free_position", "event_deck")):
            shared[purpose] = seed(name, purpose, role, -1, 0)
        for i in range(g):
            seeds = dict(shared, event_times=seed(name, "event_times", group["group"], i, 1),
                         traffic=seed(name, "traffic", group["group"], i, 1))
            session = {"role": role, "group": group["group"], "position": i, "scenario": group["scenarios"][i],
                       "attempt": 1, "seeds": seeds, "seed": seeds["traffic"], "cycles": p["cycles"]}
            if group["vm"] is not None:
                session["vm"] = group["vm"]
            items = _items(p, role, group["labels"][i], random.Random(seeds["event_times"]))
            session["controls" if role == CONTROL_ROLE else "events"] = items
            sessions.append(session)
    doc = {"schema": PLAN_SCHEMA, "mode": mode, "name": name, "group_prefix": prefix, "sessions": sessions}
    if vms != [None]:
        doc["sessions_per_vm"] = {vm: sum(s["vm"] == vm for s in sessions) for vm in vms}
    doc.update(planned_hours=len(sessions) * p["cycles"] * p["interval_s"] / 3600,
               note="Design allocation, not collected data; a replacement keeps the assignment (replacement()).")
    return doc


def replacement(p, session, attempt, *, mode="campaign"):
    """Attempt `attempt` (2 or later) of a planned session: the same VM, role, group, position, scenario and event
    types or control kinds in order; new times and a new traffic seed from the streams of this attempt."""
    if type(attempt) is not int or attempt < 2:
        raise ValueError("a replacement is attempt 2 or later")
    name = _shape(p, mode)[0]
    group, position = session["group"], session["position"]
    seeds = dict(session["seeds"], event_times=seed(name, "event_times", group, position, attempt),
                 traffic=seed(name, "traffic", group, position, attempt))
    out = dict(copy.deepcopy(session), attempt=attempt, seeds=seeds, seed=seeds["traffic"])
    rng = random.Random(seeds["event_times"])
    if "controls" in session:
        labels = [None if c.get("kind") is None else (c["kind"], c["polarity"]) for c in session["controls"]]
        out["controls"] = _items(p, CONTROL_ROLE, labels, rng)
    if "events" in session:
        out["events"] = _items(p, session["role"], [x["type"] for x in session["events"]], rng)
    return out


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
    the witness of the worst case is decided as the audit decides it (features/acceptance.py)."""
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
    return reasons


def check_role_sizes(doc, schedule):
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
    e = doc["events"]
    allowed, count = e["per_session"], max(e["per_session"])
    sessions = [s for s in schedule["sessions"] if s["role"] != CONTROL_ROLE]
    reasons = [f"session {_label(s)} has {len(s.get('events', []))} events (allowed {json.dumps(allowed)})"
               for s in sessions if len(s.get("events", [])) not in allowed]
    if 0 in allowed and count:
        for group, ss in _groups({"sessions": sessions}).items():
            empty = sum(not s.get("events") for s in ss)
            if empty != 1:
                reasons.append(f"group {group} has {empty} sessions without events")
        for role in ROLES:  # Skeleton §3: the position of the event-free session is balanced within the role.
            free = Counter(s["position"] for s in sessions if s["role"] == role and not s.get("events"))
            if any(s["role"] == role for s in sessions) and _spread(free, range(doc["group_sessions"])) > 1:
                reasons.append(f"role {role}: event-free sessions per position differ by more than 1")
    for role in ROLES:
        if role == CONTROL_ROLE:
            continue
        counts = Counter(x["type"] for s in sessions if s["role"] == role for x in s.get("events", []))
        if any(s["role"] == role for s in sessions) and _spread(counts, sorted(e["types"])) > 1:
            reasons.append(f"role {role}: event type counts differ by more than 1")
        if schedule["mode"] == "campaign" and role not in e["min_per_type"]:
            reasons.append(f"role {role} has no min_per_type")
        elif schedule["mode"] == "campaign":
            reasons += [f"role {role}: type {t} has {counts[t]} events, below min_per_type {e['min_per_type'][role]}"
                        for t in sorted(e["types"]) if counts[t] < e["min_per_type"][role]]
    if any(s.get("events") for s in schedule["sessions"] if s["role"] == CONTROL_ROLE):
        reasons.append(f"role {CONTROL_ROLE} has events")
    return reasons


def check_controls(doc, schedule):
    """The controls of role test_controls (proposal 7.2, 7.4; skeleton §1, §3, §6): every session has
    slots_per_session slots, each a card of the deck (a kind of the protocol with its class, polarity control or
    negative) or empty; in a campaign each kind has per_kind controls and negatives_per_kind negatives and only the
    slots the deck cannot fill are empty; a rehearsal deals a prefix of the deck, so its card counts differ by at
    most 1 and no slot is empty while cards remain. No other role has controls."""
    c, slots = doc["controls"], doc["controls"]["slots_per_session"]
    cards = {(kind, polarity): n for kind in sorted(c["kinds"])
             for polarity, n in (("control", c["per_kind"]), ("negative", c["negatives_per_kind"]))}
    sessions = [s for s in schedule["sessions"] if s["role"] == CONTROL_ROLE]
    reasons, counts, empty = [], Counter(), 0
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
    dealt = len(sessions) * slots
    if schedule["mode"] == "campaign":
        reasons += [f"control {kind}/{polarity} has {counts[kind, polarity]} occurrences (expected {n})"
                    for (kind, polarity), n in cards.items() if counts[kind, polarity] != n]
    elif sessions and _spread(counts, cards) > 1:
        reasons.append("rehearsal plan: control counts differ by more than 1")
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


def check_full_snapshot_guard(doc, schedule):
    """No planned item starts in a guard, and neither does an item of a replacement (attempt 2 draws new times)."""
    replacements = [replacement(doc, s, 2, mode=schedule["mode"]) for s in schedule["sessions"]]
    return _guarded(doc, schedule["sessions"]) + _guarded(doc, replacements, "replacement of ")


def check_phases(doc, schedule):
    interval = _ms(doc["interval_s"])
    starts = [_ms(item["start_s"]) for s in schedule["sessions"] for item in _items_of(s)]
    return ["event starts are locked to the sampling grid"] if starts and all(t % interval == 0 for t in starts) else []


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
    assignment."""
    k = len(doc["scenarios"])
    groups = _groups(schedule)
    blocks = {}
    for role in ROLES:
        mine = [group for group, ss in groups.items() if ss[0]["role"] == role]
        blocks.update({group: i // k + 1 for i, group in enumerate(mine)})
    replacements = [replacement(doc, s, 2, mode=schedule["mode"]) for s in schedule["sessions"]]
    owners, reasons = {}, []
    for s in schedule["sessions"] + replacements:
        for purpose, value in s["seeds"].items():
            owners.setdefault(value, {})[_stream(s, purpose, blocks)] = purpose
    for value, streams in owners.items():
        if len(streams) > 1:
            a, b = sorted(streams.values())[:2]
            reasons.append(f"two {a} streams share a seed" if a == b else f"purposes {a} and {b} share a seed")
    reasons += [f"session {_label(s)}: seed differs from seeds.traffic" for s in schedule["sessions"]
                if s.get("seed") != s["seeds"].get("traffic")]
    for s, r in zip(schedule["sessions"], replacements):
        for field in ("vm", "role", "group", "position", "scenario"):
            if r.get(field) != s.get(field):
                reasons.append(f"replacement of {_label(s)} changes {field}")
        if [x["type"] for x in r.get("events", [])] != [x["type"] for x in s.get("events", [])]:
            reasons.append(f"replacement of {_label(s)} changes types")
        if ([(x.get("kind"), x.get("polarity")) for x in r.get("controls", [])]
                != [(x.get("kind"), x.get("polarity")) for x in s.get("controls", [])]):
            reasons.append(f"replacement of {_label(s)} changes kinds")
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


def check_analysis(doc, schedule=None, *, stage="G0"):
    """The analysis plan is complete; null only at a path of determined_at; with stage Gk every path of a stage up
    to Gk holds a value."""
    if stage not in STAGES:
        raise ValueError("unknown stage: " + str(stage))
    reasons = []
    analysis = doc.get("analysis")
    _walk(analysis if type(analysis) is dict else {}, ANALYSIS, "analysis", reasons, missing_only=True)
    reasons = [r.replace("missing protocol key: ", "missing analysis key: ") for r in reasons]
    determined = doc.get("determined_at") if type(doc.get("determined_at")) is dict else {}
    patterns = [x for paths in determined.values() if type(paths) is list for x in paths if type(x) is str]
    reasons += [f"null outside determined_at: {path}" for path in _nulls(doc)
                if not any(_matches(path, pattern) for pattern in patterns)]
    for name in DETERMINED:
        if STAGES.index(name) <= STAGES.index(stage) and type(determined.get(name)) is list:
            reasons += [f"null at {path} determined at {name} (stage {stage})"
                        for pattern in determined[name] for path, value in expand(doc, pattern) if value is None]
    return reasons


PLAN_CHECKS = {"role_sizes": check_role_sizes, "scenario_balance": check_scenario_balance, "events": check_events,
               "controls": check_controls, "full_snapshot_guard": check_full_snapshot_guard, "phases": check_phases,
               "streams": check_streams, "role_order": check_role_order}


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
    """What lab/ registers: event types and control kinds (lab/udalosti.py); profiles from package B5 on."""
    from lab import udalosti
    return {"event type": set(udalosti.TYPES), "profile": set(getattr(udalosti, "PROFILES", ())),
            "control kind": set(udalosti.CONTROLS)}


def check_lab_register(doc, schedule=None):
    """(result, reasons): failed on a name lab/ does not know, pending on a name B5 or B8 will add."""
    known = lab_names()
    wanted = (("event type", sorted(doc["events"]["types"])),
              ("profile", sorted({s["profile"] for s in doc["scenarios"].values()})),
              ("control kind", sorted(doc["controls"]["kinds"])))
    unknown, pending = [], []
    for kind, names in wanted:
        for name in names:
            if name not in known[kind]:
                (pending if name in PENDING_IN_LAB else unknown).append(name)
    if unknown:
        return "failed", [f"unknown to lab/: {name}" for name in unknown]
    if pending:
        return "pending", ["registered by B5 and B8: " + ", ".join(pending)]
    return "passed", []


CHECKS = ("keys", "loader", "reachability", "role_sizes", "scenario_balance", "events", "controls",
          "full_snapshot_guard", "phases", "streams", "role_order", "analysis", "rehearsal", "lab_register")


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


def selfcheck(path, *, mode="campaign", stage="G0"):
    """The self-check report of a protocol file; it parses the file itself and does not need the loader to pass."""
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
    return {"protocol": str(path.resolve()), "protocol_sha256": hashlib.sha256(raw).hexdigest(), "mode": mode,
            "stage": stage, "checks": checks, "passed": all(c["result"] == "passed" for c in checks)}
