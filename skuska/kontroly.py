"""The controls of stage G2: their draw, the wrapper of Q46 and their block (protocol v5, package H1b2).

    python -m skuska.kontroly draw  --protocol P --out DRAW.json
    python -m skuska.kontroly block --protocol P --deck DECK.json --draw DRAW.json --vm a
                                    (--sessions N | --only k01,k03) --other-vm g2|idle [--rate SCENARIO=R ...]
                                    [--g2-dir DIR] [--dry-run]
    python skuska/kontroly.py wrap  --controls JSON --beside FILE <ROOT>/scripts/collection.py --protocol P run ...

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H3, the criterion controls_paired), the
map dokazy/G2/mapa.md (row 8, points A, B, E and F 3, its questions 1 to 3) and the lead's answers Q46 (the wrapper of
collection.v5_arguments, with his test of equality: for a plan row of role test_controls the wrapper's arguments equal
the campaign's but for the seed of the draw), Q47 (3 controls and 3 negatives of every kind, each occurrence with
parser_saw, column_moved and sensor_scored; channel_reacted not judged in G2), Q48 (controls.baseline by
controls.note), Q20 (expect is a value of G0) and Q69 (H1b). skuska/ is no directory of scripts/collection.py
MEASUREMENT_DIRS, so nothing here changes the measurement code (map point E).

The draw (DRAW_RULE, STREAMS_RULE), drawn once before the first session with controls and never changed, as the deck
of events of skuska/g2.py: 5 kinds x (3 controls + 3 negatives) = 30 occurrences in 10 sessions of 3 slots, the sessions
alternating over the VMs, the times and the guards of the full snapshots as protocol_v5 draws them for role
test_controls, the doses as the plan deals them, one per dose for class B (map row 8). A block refuses a draw that
differs from what the rule draws from the protocol. The draw does not read controls.baseline.

The wrapper (WRAP_RULE): a diagnostic session of G2 gets no controls from collection.py's command line (run --role
diagnostic does not carry them, --events refuses a kind of control), so the wrapper runs collection.py run in its own
process with collection.v5_arguments replaced for that run by a function that adds the controls, in the plan's form,
to its result; run_session, capture_session (collection.Controls) and the audit then run as the campaign runs them for
a session of role test_controls. Beside the session, outside its directory, it writes the sha256 of its own source and
the list it inserted.

The block (CONTROLS_BLOCK_RULE): skuska/g2.py Block with the draw's sessions; Block.run_command makes the wrapper's
command line for a spec with controls. The table of shifts is the mode controls of scripts/campaign_report.py.
"""
import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import random
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python skuska/kontroly.py, as the block runs the wrapper.
    sys.path.insert(0, str(ROOT))

from scripts import collection, protocol_v5  # noqa: E402
from skuska import g2  # noqa: E402

STAGE = g2.STAGE
ROLE = g2.ROLE  # Map point A: the sessions of G2 are diagnostic runs.
KIND = "controls"  # The kind of a block's spec with controls and of its record (skuska/g2.py Block.record).
WRAPPER = Path(__file__).resolve()
COLLECTION = ROOT / "scripts/collection.py"
DRAW_SCHEMA = "hyptcn3/g2-controls-draw/1"
WRAP_SCHEMA = "hyptcn3/g2-controls-wrapper/1"
OCCURRENCES = 3  # The criterion controls_paired (Q47): 3 occurrences of the control and 3 of its negative per kind.
POLARITIES = ("control", "negative")  # protocol_v5.CONTROL_RECORD_CLASS: the polarity of a plan item.
# The keys of a control as the plan states it (protocol_v5._items), the form session.json records and the audit
# compares controls.json with.
PLAN_KEYS = ("kind", "polarity", "class", "dose", "start_s", "duration_s", "start_phase_s", "stop_phase_s")
BESIDE = "kontroly"  # The wrapper's records: <G2 directory>/kontroly/<session>.json, outside the session directory.
GROUP = "G2/controls"  # The group of the draw's streams (STREAMS_RULE).
DRAW_RULE = (
    "the criterion controls_paired and the lead's answer to Q47: every kind of controls.kinds 3 times as a control "
    "and 3 times as its paired negative, so 5 x (3 + 3) = 30 occurrences in sessions of controls.slots_per_session = 3 "
    "slots, 10 sessions k01 to k10 in draw order, alternating over the VMs of the protocol (k01 on a, k02 on b, ...); "
    "on each VM the scenarios follow the cycle of the deck of events (skuska/g2.py scenario_cycle: corp_high, "
    "eshop_high, corp_low, eshop_low), the second VM one step ahead; the cards (stream control_deck): the kinds in "
    "random order, the 3 controls and the 3 negatives of a kind together, the polarity that comes first drawn once "
    "and alternating over the kinds (as protocol_v5._deal_controls lays its run), laid round after round along a "
    "cycle of the 10 sessions that alternates the VMs (the sessions of each VM in random order, as "
    "protocol_v5._cell_cycle), one slot of every session a round: the 6 cards of a kind lie in 6 different sessions, "
    "so no session holds a kind twice (as the plan), and each card lies twice on one VM and once on the other (within "
    "1 per VM, as the plan); the slots of a session in random order; the doses as the plan treats the classes "
    "(protocol_v5._deal_doses on the same stream after the cards, as the plan): class A none, class B one deck of one "
    "round of its doses, so each dose once among the kind's 3 controls and once among its 3 negatives (map row 8: "
    "class B one per dose); the tenths of the starts and of the stops (stream phase_deck): two decks of full rounds "
    "of the 10 tenths over the 30 occurrences in draw order, as protocol_v5._deal_tenths deals a role, so each tenth "
    "holds 3 starts and 3 stops; the times of each session as the plan draws them for role test_controls "
    "(protocol_v5._items with the session's stream event_times: durations in controls.duration_s, first_s, min_gap_s "
    "and tail_s of the events section, no start inside the guard of a full snapshot, full_snapshot_guard), which the "
    "wrapper admits as --controls (check_controls); controls.baseline is not read")
STREAMS_RULE = (
    "the plan's rule protocol_v5.seed(name, purpose, group, session, attempt) with the protocol's name and groups that "
    "no stream of the plan or of the deck of events has (skuska/g2.py STREAMS_RULE): control_deck and phase_deck with "
    "the group G2/controls, session -1 and attempt 0; event_times and traffic of a session with the group G2/<id> "
    "(k01 to k10), its number and attempt 1; traffic is the session's --seed, from which scripts/collection.py "
    "diagnostic_seeds draws the other traffic streams; a session run again keeps its draw item")
WRAP_RULE = (
    "the lead's answer to Q46: the wrapper runs scripts/collection.py run of a diagnostic G2 session in its own "
    "process (collection.main, the measurement code as it stands), with collection.v5_arguments replaced for that run "
    "only by a function that calls it and adds the controls of --controls to its result in the plan's form "
    "(protocol_v5._items: kind, polarity, class, dose, start_s, duration_s, start_phase_s, stop_phase_s), so that "
    "run_session writes them into session.json, capture_session starts collection.Controls for them and the audit "
    "compares controls.json with session.json (map F 3), as for a session of role test_controls; refused by name: a "
    "script other than scripts/collection.py, a protocol not of schema 3 and another command than `--protocol P run` "
    "(before collection.py runs), and inside the replaced function (before run_session touches the guest) a role "
    "other than diagnostic (a planned role takes its controls from the plan, collection.v5_planned), --events beside "
    "--controls (a session with controls holds no events, as role test_controls), no --session-id, a record beside "
    "the session that exists or lies inside the session's directory, and controls the plan would not state "
    "(check_controls, as collection.diagnostic_events checks --events: 1 to controls.slots_per_session controls of "
    "distinct kinds of controls.kinds, each with the kind's class, no dose for class A and one of its doses for class "
    "B, its times on the plan's grid of 1 ms with the phases of protocol_v5._timing, a duration in "
    "controls.duration_s, first_s, min_gap_s and tail_s of the events section, no start inside the guard of a full "
    "snapshot); once the function has the list, it writes beside the session and outside its directory (--beside, "
    "kontroly/<session>.json of the G2 directory) a new record with check E's header: the sha256 of the wrapper's own "
    "source, the list it inserted and the run's identity, before the guest checks of run_session, so the session's "
    "own record says whether it ran; the exit code and the error line are collection.py's own (`collection: "
    "<error>`, exit 2)")
CONTROLS_BLOCK_RULE = (
    "a block of G2 sessions with controls on one VM: skuska/g2.py Block (BLOCK_RULE) with the draw's sessions of the "
    "VM (DONE_RULE: --sessions N the first N of them not done, --only by id), each run through the wrapper "
    "(Block.run_command of a spec with controls, WRAP_RULE) and the wrapper's record in the session's record "
    "(Block.beside); refused before it, beside the refusals of Block: a draw that differs from its rule and "
    "controls.baseline null (the controls start against the band Zápis 2 writes after the long runs of H2); the deck "
    "of events is verified as by every block of G2 (Block.run), and the record of a session names it under deck "
    "with the draw's item")
BASELINE_NULL = ("controls.baseline is null: the sessions with controls run after Zápis 2 writes the band of "
                 "controls.note (the lead's answer to Q48; map row 18 and point C)")
NOTE = ("Stage G2 (proposal 10.3): the controls on the VMs and their paired negatives, whose data never become a "
        "dataset. Written by skuska/kontroly.py.")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ------------------------------------------------------------------ the draw

def draw_seed(p, purpose, group, session, attempt):
    """A seed of the draw's streams (STREAMS_RULE)."""
    return protocol_v5.seed(p["name"], purpose, group, session, attempt)


def _plan_doses(c):
    """The controls section as protocol_v5._deal_doses reads it for the draw: class B with one occurrence of every
    dose (map row 8)."""
    return {"kinds": {name: dict(k, per_dose=[1] * len(k["doses"])) if k["class"] == "B" else dict(k)
                      for name, k in c["kinds"].items()}}


def draw_controls(p):
    """The draw of the protocol `p` (DRAW_RULE, STREAMS_RULE): {sessions, counts, streams}; the same protocol always
    gives the same draw. ValueError when the protocol cannot hold it."""
    c = p["controls"]
    kinds, slots = sorted(c["kinds"]), c["slots_per_session"]
    vms = [row["name"] for row in p.get("vms", [])]
    if len(vms) < 2:
        raise ValueError("the draw of the controls needs the VMs of the protocol, two or more")
    cards = len(kinds) * len(POLARITIES) * OCCURRENCES
    if slots < 1 or cards % slots:
        raise ValueError(f"{cards} occurrences do not fill sessions of {slots} slots")
    count = cards // slots
    if 2 * OCCURRENCES > count:
        raise ValueError(f"{count} sessions cannot hold the {2 * OCCURRENCES} occurrences of a kind in different "
                         "sessions")
    for name in kinds:
        k = c["kinds"][name]
        if k["class"] == "B" and len(k["doses"]) != OCCURRENCES:
            raise ValueError(f"class B one per dose: {name} has {len(k['doses'])} doses for {OCCURRENCES} "
                             "occurrences of each polarity")
    cycle = g2.scenario_cycle(p)
    sessions = []
    for i in range(count):
        vm, index, number = vms[i % len(vms)], i // len(vms) + 1, i + 1
        group = f"G2/k{number:02d}"
        sessions.append({"id": f"k{number:02d}", "number": number, "vm": vm, "index_on_vm": index,
                         "scenario": cycle[(index - 1 + vms.index(vm)) % len(cycle)],
                         "seeds": {"event_times": draw_seed(p, "event_times", group, number, 1),
                                   "traffic": draw_seed(p, "traffic", group, number, 1)}, "labels": []})
    rng = random.Random(draw_seed(p, "control_deck", GROUP, -1, 0))
    first = rng.sample(POLARITIES, 2)
    run = [(kind, polarity) for j, kind in enumerate(rng.sample(kinds, len(kinds)))
           for polarity in (first if j % 2 == 0 else first[::-1]) for _ in range(OCCURRENCES)]
    rows = [rng.sample([s for s in sessions if s["vm"] == vm], sum(s["vm"] == vm for s in sessions)) for vm in vms]
    ring = [s for row in itertools.zip_longest(*rows) for s in row if s is not None]
    for position, card in enumerate(run):
        ring[position % len(ring)]["labels"].append(card)
    for session in sessions:
        session["labels"] = rng.sample(session["labels"], len(session["labels"]))
    groups = [{"group": s["id"], "vm": s["vm"], "scenarios": [s["scenario"]], "labels": [s["labels"]]}
              for s in sessions]
    protocol_v5._deal_doses(_plan_doses(c), groups, rng)  # Mutates the labels into (kind, polarity, dose).
    phase_rng = random.Random(draw_seed(p, "phase_deck", GROUP, -1, 0))
    rounds = -(-cards // protocol_v5.TENTHS)
    deck = [(d, rounds) for d in range(protocol_v5.TENTHS)]
    starts, stops = protocol_v5._rounds(phase_rng, deck, rounds), protocol_v5._rounds(phase_rng, deck, rounds)
    j = 0
    for session in sessions:
        labels = session.pop("labels")
        tenths = [(starts[j + k], stops[j + k]) for k in range(len(labels))]
        j += len(labels)
        items = protocol_v5._items(p, protocol_v5.CONTROL_ROLE, labels, tenths,
                                   random.Random(session["seeds"]["event_times"]))
        session.update(seed=session["seeds"]["traffic"], tenths=[list(t) for t in tenths], controls=items,
                       argument=json.dumps(items))
    counts = draw_counts(p, sessions)
    problems = draw_problems(p, sessions, counts)
    if problems:
        raise ValueError("the draw of the controls breaks its rule: " + "; ".join(problems))
    return {"sessions": sessions, "counts": counts,
            "streams": {"rule": STREAMS_RULE, "name": p["name"], "group": GROUP,
                        "seeds": {purpose: draw_seed(p, purpose, GROUP, -1, 0)
                                  for purpose in ("control_deck", "phase_deck")}}}


def draw_counts(p, sessions):
    """What the rule promises, counted: occurrences by kind and polarity and by kind, polarity and VM, the doses of
    each kind and polarity, sessions by VM and by scenario, starts and stops per tenth of the interval, distinct kinds
    per session."""
    vms = [row["name"] for row in p["vms"]]
    items = [(s, x) for s in sessions for x in s["controls"]]
    kinds = sorted(p["controls"]["kinds"])
    tenths = {"starts": [0] * protocol_v5.TENTHS, "stops": [0] * protocol_v5.TENTHS}
    for _, x in items:
        start, stop = protocol_v5.item_tenths(p, x)
        tenths["starts"][start] += 1
        tenths["stops"][stop] += 1
    return {"occurrences_by_kind": {k: {pol: sum(x["kind"] == k and x["polarity"] == pol for _, x in items)
                                        for pol in POLARITIES} for k in kinds},
            "occurrences_by_kind_and_vm": {k: {pol: {vm: sum(x["kind"] == k and x["polarity"] == pol and s["vm"] == vm
                                                             for s, x in items) for vm in vms}
                                               for pol in POLARITIES} for k in kinds},
            "doses": {k: {pol: sorted((x["dose"] for _, x in items if x["kind"] == k and x["polarity"] == pol),
                                      key=lambda d: (d is not None, d or 0))
                          for pol in POLARITIES} for k in kinds},
            "sessions_by_vm": {vm: sum(s["vm"] == vm for s in sessions) for vm in vms},
            "sessions_by_scenario": {name: sum(s["scenario"] == name for s in sessions)
                                     for name in sorted(p["scenarios"])},
            "per_tenth": tenths,
            "distinct_kinds_per_session": sorted({len({x["kind"] for x in s["controls"]}) for s in sessions})}


def draw_problems(p, sessions, counts):
    """Every promise of DRAW_RULE the draw breaks, named."""
    c, slots = p["controls"], p["controls"]["slots_per_session"]
    out = [f"{kind} holds {n} occurrences of polarity {pol}, not {OCCURRENCES}"
           for kind, row in counts["occurrences_by_kind"].items() for pol, n in row.items() if n != OCCURRENCES]
    out += [f"{kind}/{pol} lies on the VMs {row} times, which differ by more than 1"
            for kind, by in counts["occurrences_by_kind_and_vm"].items() for pol, row in by.items()
            if max(row.values()) - min(row.values()) > 1]
    for kind, by in counts["doses"].items():
        k = c["kinds"][kind]
        want = sorted(k["doses"]) if k["class"] == "B" else [None] * OCCURRENCES
        out += [f"{kind}/{pol} holds the doses {doses}, not {want}" for pol, doses in by.items() if doses != want]
    out += [f"the {what} per tenth differ by more than 1: {row}" for what, row in counts["per_tenth"].items()
            if max(row) - min(row) > 1]
    if counts["distinct_kinds_per_session"] != [slots] or any(len(s["controls"]) != slots for s in sessions):
        out.append(f"a session holds a kind twice or not {slots} controls")
    vms = [row["name"] for row in p["vms"]]
    if [s["vm"] for s in sessions] != [vms[i % len(vms)] for i in range(len(sessions))]:
        out.append("the sessions do not alternate over the VMs")
    for s in sessions:
        try:
            check_controls(p, s["controls"], p["cycles"])
        except ValueError as error:
            out.append(f"session {s['id']}: {error}")
    return out


def write_draw(protocol_path, out, command):
    """Draw the controls of the protocol file and write them to the new file `out` (refused when it exists)."""
    from scripts import gates  # Inside the function, as skuska/g2.py write_deck: gates imports collection.
    out = Path(out).absolute()
    if out.exists() or out.is_symlink():
        raise g2.Refused(f"the draw {out} exists: the draw of the controls is drawn once and never changed")
    p = collection.protocol(protocol_path)
    draw = draw_controls(p)
    values = {"stage": STAGE, "rule": DRAW_RULE, "protocol": str(Path(protocol_path).absolute()),
              "protocol_sha256": digest(protocol_path), "protocol_g0_binding": gates.stage_sha256(protocol_path, "G0"),
              "occurrences": OCCURRENCES, "slots_per_session": p["controls"]["slots_per_session"],
              "cycles": p["cycles"], **draw}
    doc = g2.header(DRAW_SCHEMA, command, len(draw["sessions"]), values)
    g2.write_new(out, doc)
    return doc


def load_draw(path, p):
    """(the draw file at `path`, its sha256), refused unless it is the draw its rule draws from `p`."""
    try:
        doc = g2.read_json(path)
    except (OSError, ValueError) as error:
        raise g2.Refused(f"the draw {path} cannot be read: {error}") from None
    if type(doc) is not dict or doc.get("schema") != DRAW_SCHEMA or type(doc.get("values")) is not dict:
        raise g2.Refused(f"{path} is no draw of the controls of G2 ({DRAW_SCHEMA})")
    expected = draw_controls(p)
    for key in ("sessions", "streams"):
        if doc["values"].get(key) != expected[key]:
            raise g2.Refused(f"the draw {path} differs from the draw its rule draws from this protocol ({key}): the "
                             "draw of the controls is drawn once and never changed")
    return doc, digest(path)


# ------------------------------------------------------------------ the wrapper

def check_controls(p, items, cycles):
    """The controls of --controls as the plan states them (WRAP_RULE), checked against the protocol `p` for a session
    of `cycles` rows as collection.diagnostic_events checks --events; a copy of them, or ValueError "invalid
    --controls: <the rule>"."""
    def bad(rule):
        raise ValueError("invalid --controls: " + rule)
    if type(items) is not list or not items or any(type(x) is not dict or set(x) != set(PLAN_KEYS) for x in items):
        bad("not a JSON list of controls in the plan's form {" + ", ".join(PLAN_KEYS) + "}")
    c, e, ms = p["controls"], p["events"], protocol_v5._ms
    if len(items) > c["slots_per_session"]:
        bad(f"{len(items)} controls, a session has {c['slots_per_session']} slots (controls.slots_per_session)")
    names = [x["kind"] for x in items]
    if any(type(name) is not str or name not in c["kinds"] for name in names):
        bad("unknown control kind " + ", ".join(str(name) for name in names
                                                if type(name) is not str or name not in c["kinds"]))
    if len(set(names)) != len(names):
        bad("a session holds a kind twice")
    guards = protocol_v5.guards(dict(p, cycles=cycles))
    end = None
    for x in items:
        kind, k = x["kind"], c["kinds"][x["kind"]]
        if x["polarity"] not in POLARITIES:
            bad(f"{kind}: polarity {x['polarity']!r}, not control or negative")
        if x["class"] != k["class"]:
            bad(f"{kind}: class {x['class']!r}, the kind's class is {k['class']}")
        dose = x["dose"]
        if k["class"] == "A" and dose is not None:
            bad(f"{kind}: class A has no dose, not {dose!r}")
        if k["class"] == "B" and not (type(dose) in (int, float) and dose in k["doses"]):
            bad(f"{kind}: dose {dose!r} is not one of the kind's doses {k['doses']}")
        start, duration = x["start_s"], x["duration_s"]
        if not all(type(v) in (int, float) and math.isfinite(v) for v in (start, duration, x["start_phase_s"],
                                                                           x["stop_phase_s"])):
            bad(f"{kind}: its times are not seconds")
        if not c["duration_s"][0] <= duration <= c["duration_s"][1]:
            bad(f"{kind} lasts {duration:g} s, outside controls.duration_s {json.dumps(c['duration_s'])}")
        if ms(start) / 1000 != start or ms(duration) / 1000 != duration:
            bad(f"{kind}: start_s and duration_s are not on the plan's grid of 1 ms")
        timing = protocol_v5._timing(p, ms(start), ms(duration))
        if any(x[key] != value for key, value in timing.items()):
            bad(f"{kind}: start_phase_s and stop_phase_s are not the phases of start_s and duration_s")
        if start < e["first_s"]:
            bad(f"{kind} starts at {start:g} s, before first_s {e['first_s']:g} s")
        if end is not None and ms(start) < end + ms(e["min_gap_s"]):
            bad(f"{kind} starts less than min_gap_s {e['min_gap_s']:g} s after the control before it ends")
        guard = next((t for t, low, high in guards if low <= ms(start) < high), None)
        if guard is not None:
            bad(f"{kind} starts at {start:g} s inside the guard of the full snapshot at {guard / 1000:g} s")
        end = ms(start) + ms(duration)
    if end + ms(e["tail_s"]) > ms(cycles * p["interval_s"]):
        bad(f"the last control ends less than tail_s {e['tail_s']:g} s before the end of the session "
            f"({cycles * p['interval_s']:g} s)")
    return [{key: x[key] for key in PLAN_KEYS} for x in items]


def beside_path(g2_dir, session_id):
    """Where the wrapper writes its record of a session: <G2 directory>/kontroly/<session>.json."""
    return Path(g2_dir).absolute() / BESIDE / f"{session_id}.json"


def wrapper_command(command, controls, beside):
    """The wrapper's command line around the capture's `command` ([python, <ROOT>/scripts/collection.py, ...], as
    skuska/g2.py Block.run_command makes it): collection.py and its arguments stay in it as they are, so the load
    sampler of skuska/g2.py classifies the process as the session's run (LOAD_RULE)."""
    if len(command) < 2 or Path(command[1]) != COLLECTION:
        raise ValueError(f"the controls wrapper runs {COLLECTION}, not {command[1:2]}")
    return [command[0], str(WRAPPER), "wrap", "--controls", json.dumps(controls), "--beside", str(beside),
            *map(str, command[1:])]


def _owner():
    """(uid, gid) of the VM's owner when the wrapper runs as root through sudo, else None."""
    if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
        return int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    return None


def _write_beside(path, doc):
    """The wrapper's record as a new file; its new directories and itself belong to the VM's owner, as
    scripts/collection.py run leaves a session's files."""
    path, owner = Path(path), _owner()
    missing = [d for d in [path.parent, *path.parent.parents] if not d.exists()]
    path.parent.mkdir(parents=True, exist_ok=True)
    g2.write_new(path, doc)
    for item in [*missing, path] if owner is not None else []:
        os.chown(item, *owner, follow_symlinks=False)


def wrap(controls_text, beside, script, arguments, command):
    """Run scripts/collection.py with `arguments` and the controls of `controls_text` inserted (WRAP_RULE); returns
    collection.main's exit code. ValueError for a refusal before collection.py runs; the errors inside it propagate
    as collection.py's own."""
    if Path(os.path.realpath(script)) != Path(os.path.realpath(COLLECTION)):
        raise ValueError(f"the controls wrapper runs {COLLECTION}, not {script}")
    if len(arguments) < 3 or arguments[0] != "--protocol" or arguments[2] != "run":
        raise ValueError("the controls wrapper runs `scripts/collection.py --protocol P run ...` only")
    try:
        controls = json.loads(controls_text)
    except ValueError:
        raise ValueError("invalid --controls: not JSON") from None
    if collection.protocol(arguments[1]).get("schema") != protocol_v5.SCHEMA:
        raise ValueError("the controls wrapper serves a protocol of schema 3 (collection.v5_arguments)")
    beside, state, original = Path(beside).absolute(), {"inserted": None}, collection.v5_arguments

    def v5_arguments(a, p):
        """collection.v5_arguments with the controls added to its result (WRAP_RULE)."""
        run = original(a, p)
        if a.role != ROLE or run is None:
            raise ValueError(f"the controls wrapper serves a diagnostic run only, not role {a.role} (a session of a "
                             "planned role takes its controls from the plan, collection.v5_planned)")
        if run["events"]:
            raise ValueError("a session with controls holds no events (role test_controls holds controls and no "
                             "events, proposal 7.2): --events is refused beside --controls")
        if not getattr(a, "session_id", None):
            raise ValueError("the controls wrapper needs --session-id: its record lies beside the session's directory")
        session_dir = Path(getattr(a, "collections_dir", None) or collection.COLLECTIONS).absolute() / a.session_id
        if Path(os.path.realpath(beside)).is_relative_to(os.path.realpath(session_dir)):
            raise ValueError(f"the wrapper's record {beside} lies inside the session's directory {session_dir}")
        if beside.exists() or beside.is_symlink():
            raise ValueError(f"the wrapper's record {beside} exists: a session id runs once")
        items = check_controls(p, controls, run["cycles"])
        values = {"stage": STAGE, "rule": WRAP_RULE,
                  "wrapper": {"path": str(WRAPPER.relative_to(ROOT)), "sha256": digest(WRAPPER)},
                  "session_id": a.session_id, "session_dir": str(session_dir), "vm": a.vm, "role": a.role,
                  "group": a.group, "scenario": a.scenario, "seed": a.seed, "cycles": run["cycles"],
                  "protocol": str(Path(a.protocol).absolute()), "protocol_sha256": digest(a.protocol),
                  "inserted": items}
        _write_beside(beside, g2.header(WRAP_SCHEMA, command, len(items), values))
        state["inserted"] = items
        return {**run, "controls": [dict(x) for x in items]}

    collection.v5_arguments = v5_arguments
    try:
        code = collection.main(list(arguments))
    finally:
        collection.v5_arguments = original
    if state["inserted"] is None:
        raise ValueError("the controls wrapper inserted no controls: collection.py did not ask v5_arguments")
    return code


class WrapperRecord:
    """The hook of a block with controls beside every run (skuska/g2.py Block.beside): after the run, the wrapper's
    record of the session, its sha256 and whether it inserted the spec's controls."""

    def __init__(self, path, controls):
        self.path, self.controls = Path(path), controls

    def stop(self):
        out = {"hook": "controls", "file": str(self.path), "sha256": None, "inserted": None, "wrapper_sha256": None,
               "matches_spec": None, "error": None}
        if not self.path.exists():
            return dict(out, error="no record: the wrapper refused before it inserted the controls, or did not run")
        try:
            doc = g2.read_json(self.path)
            inserted = doc["values"]["inserted"]
            out.update(sha256=digest(self.path), inserted=len(inserted),
                       wrapper_sha256=doc["values"]["wrapper"]["sha256"], matches_spec=inserted == self.controls)
        except (OSError, ValueError, KeyError, TypeError) as error:
            out["error"] = f"{type(error).__name__}: {error}"
        return out


def wrapper_record(block, spec, paths):
    """A hook of Block.beside (skuska/g2.py): the wrapper's record of the session after its run."""
    return WrapperRecord(beside_path(block.places.root, spec["session_id"]), spec.get("controls"))


# ------------------------------------------------------------------ the block

class ControlsBlock(g2.Block):
    """A block of G2 sessions with controls on one VM (CONTROLS_BLOCK_RULE)."""

    def __init__(self, protocol_path, deck_path, draw_path, vm, **options):
        super().__init__(protocol_path, deck_path, vm, **options)
        self.draw_path = Path(draw_path).absolute()
        self.draw = self.draw_sha256 = None
        self.beside = [*self.beside, wrapper_record]

    def specs(self):
        """The sessions of the block from the draw (DONE_RULE): {kind, id, deck, scenario, seed, events, controls,
        attempt, session_id} each; deck holds the draw's item with the draw's path and sha256."""
        self.draw, self.draw_sha256 = load_draw(self.draw_path, self.full)
        items = [s for s in self.draw["values"]["sessions"] if s["vm"] == self.vm]
        if self.only is not None:
            unknown = [x for x in self.only if x not in {s["id"] for s in items}]
            if unknown or not self.only or len(set(self.only)) != len(self.only):
                raise g2.Refused(f"--only names draw sessions of VM {self.vm}, each once; not of it: "
                                 + ", ".join(unknown))
            chosen = [s for s in items if s["id"] in self.only]
        else:
            done = {r["deck_session"] for r in self.records() if r.get("done") is True}
            left = [s for s in items if s["id"] not in done]
            if type(self.count) is not int or self.count < 1:
                raise g2.Refused("--sessions N: a number of sessions above 0")
            if self.count > len(left):
                raise g2.Refused(f"--sessions {self.count}: {len(left)} draw sessions of VM {self.vm} are not done")
            chosen = left[:self.count]
        specs = []
        for item in chosen:
            attempt = self.attempt(item["id"])
            specs.append({"kind": KIND, "id": item["id"],
                          "deck": {"draw": str(self.draw_path), "draw_sha256": self.draw_sha256, **item},
                          "scenario": item["scenario"], "seed": item["seed"], "events": None,
                          "controls": item["controls"], "attempt": attempt,
                          "session_id": f"g2-{self.vm}-{item['id']}-{attempt}"})
        return specs

    def checks(self, specs):
        """The refusals of Block.checks and controls.baseline null (CONTROLS_BLOCK_RULE)."""
        problems = super().checks(specs)
        if self.p["controls"]["baseline"] is None:
            problems.append(BASELINE_NULL)
        return problems


# ------------------------------------------------------------------ the command line

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m skuska.kontroly", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    draw = sub.add_parser("draw", help="draw the controls of G2 once (refused when the file exists)")
    draw.add_argument("--protocol", type=Path, required=True)
    draw.add_argument("--out", type=Path, required=True)
    block = sub.add_parser("block", help="run a block of G2 sessions with controls on one VM (as root through sudo)")
    block.add_argument("--protocol", type=Path, required=True)
    block.add_argument("--deck", type=Path, required=True, help="the deck of events of G2 (skuska/g2.py deck)")
    block.add_argument("--draw", type=Path, required=True, help="the draw of the controls (draw)")
    block.add_argument("--vm", required=True)
    which = block.add_mutually_exclusive_group(required=True)
    which.add_argument("--sessions", type=int, help="the next N draw sessions of the VM that are not done")
    which.add_argument("--only", help="these draw sessions (ids, comma-separated), each as its next attempt")
    block.add_argument("--other-vm", choices=g2.OTHER_VM, required=True,
                       help="what the block's plan lets the other VM run: nothing, or its own G2 block")
    block.add_argument("--rate", action="append", default=[], metavar="SCENARIO=R",
                       help="the rate of a scenario whose rate is null in the protocol (refused otherwise)")
    block.add_argument("--g2-dir", type=Path, default=g2.G2_DIR, help="the G2 directory: zaznamy/, zataz/, session/, "
                                                                      "kontroly/")
    block.add_argument("--dry-run", action="store_true", help="the checks and the commands; nothing is started")
    wrapped = sub.add_parser("wrap", help="run scripts/collection.py run with the controls inserted (WRAP_RULE)")
    wrapped.add_argument("--controls", required=True, help="JSON list of the controls in the plan's form")
    wrapped.add_argument("--beside", type=Path, required=True, help="the wrapper's new record, outside the session")
    wrapped.add_argument("collection", help="<ROOT>/scripts/collection.py")
    wrapped.add_argument("arguments", nargs=argparse.REMAINDER, help="its arguments: --protocol P run ...")
    a = parser.parse_args(argv)
    line = shlex.join(["python", "-m", "skuska.kontroly", *argv])
    if a.action == "wrap":
        command = shlex.join(["python", "skuska/kontroly.py", *argv])
        try:
            return wrap(a.controls, a.beside, a.collection, a.arguments, command)
        except (ValueError, OSError, KeyError, collection.FeatureError, collection.WindowError,
                subprocess.SubprocessError) as error:  # As scripts/collection.py's __main__.
            print(f"collection: {error}", file=sys.stderr)
            return 2
    try:
        if a.action == "draw":
            doc = write_draw(a.protocol, a.out, line)
            print(json.dumps({"draw": str(a.out), "sessions": doc["n"], "counts": doc["values"]["counts"]},
                             indent=2, ensure_ascii=False))
            return 0
        b = ControlsBlock(a.protocol, a.deck, a.draw, a.vm, other_vm=a.other_vm, sessions=a.sessions,
                          only=None if a.only is None else a.only.split(","), rates=g2.parse_rates(a.rate),
                          places=g2.Places(a.g2_dir), command=line)
        result = b.plan() if a.dry_run else b.run()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get("refusals") or result.get("stopped") else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"skuska.kontroly: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
