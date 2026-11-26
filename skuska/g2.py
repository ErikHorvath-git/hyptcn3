"""The deck of events of stage G2 and the driver of a block of G2 sessions on one VM (protocol v5, package H1a).

    python -m skuska.g2 deck  --protocol P --out DECK.json
    python -m skuska.g2 block --protocol P --deck DECK.json --vm a (--sessions N | --only e01,e03)
                              --other-vm g2|idle [--rate SCENARIO=R ...] [--g2-dir DIR] [--dry-run]

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (row H1, sections 0 and 3), the map
dokazy/G2/mapa.md (rows 1 to 6, points A to E) and the lead's answers Q43 (19 occurrences of each type on both VMs
together, at least 8 on each), Q51 (dealt globally), Q55 (collection under data/diagnostics/G2/<vm>, the archive on
the HDD, the reclaim with the campaign id g2), Q69 (H1a) and Q70 (what a heavy process is). skuska/ is no directory of
scripts/collection.py MEASUREMENT_DIRS: the driver runs the measurement code's own commands as children and changes
none of them.

The deck (DECK_RULE), drawn once before the first session and never changed: 6 types x 19 = 114 occurrences in 38
sessions of 3, the sessions alternating over the VMs and over the scenarios, the types dealt globally (9 or 10 of each
type on each VM), the tenths of the starts and the stops dealt as protocol_v5 deals them for the plan, the times drawn
as the plan draws them (protocol_v5._items), from its own streams of seeds (STREAMS_RULE). Every session's --events is
the deck's argument, which collection.diagnostic_events admits as it stands. A block refuses a deck that differs from
what the rule draws from the protocol.

A block (BLOCK_RULE), started by the main session with one pcc-sudo call: as root through sudo from the VM owner's
account, from /home/eh/projects/hyptcn3. Refused by name before it: gates.require of stage G1 (a valid G0, map
question 9) and the audit self-test of the protocol file, measurement code that differs from the commit, a deck that
differs from its rule, a missing or a refused --rate, a heavy process or a run outside the block's plan (LOAD_RULE),
a deployed guest that differs from lab/ of the commit, and another capture that holds the VM's collection lock, which
the block then holds as the campaign's runner does. Before every session the measurement code must still be the
block's (else it stops) and the driver waits while a heavy process runs. Then for every session:
  0. the start of a group as the campaign starts one (scripts/campaign.py start_steps: labctl stop, start, reset to
     the seeded level of the protocol, pretouch): a new group for every boot of the VM, group_sessions sessions to a
     group as in the campaign, and a new group whenever the boot or the QEMU process of the group is gone;
  1. scripts/collection.py run as map point A writes it (RUN_RULE), a child as the campaign starts its captures
     (campaign.run_child, the VM's collection lock passed to it), the load sampler beside it;
  2. labctl levels as the VM's owner;
  3. the audit as the campaign runs it (campaign.audit_capture: background_command, as the owner, its timeout and
     exit codes, its provenance checked), under the session's protocol.json, one audit or archive on the host at a
     time;
  4. the archive with collection_archive.archive_session (zstd) to <g2-dir>/session/<vm>/<session>, bound to the
     audit, then the reclaim of the working raw/ with the campaign id g2 (Q55); nothing is deleted otherwise;
  and the session's record (SESSION_SCHEMA, check E's header) in <g2-dir>/zaznamy/ and a line of the block log.
A run that exits non-zero is recorded, its audit still runs and the block goes on; a guest mismatch or a refusal of
the QEMU swap stops the block (REFUSALS), and so does a failed group start, an audit whose provenance differs from the
session (bound by the measurement code, not by the commit, which the main tree may move meanwhile), an interrupt or
any other error of the driver's own steps, each after the session's record.

Hooks for package H1b: Block.specs() makes the sessions of a block from the deck and Block.run(specs) runs any list
of them, so the controls wrapper, the fault injector, the timing driver and the ground-truth sessions give their own
specs (kind, events or None); Block.run_command(spec, group) is the one place where the capture's command line is
made (the controls wrapper of Q46 replaces it); Block.beside holds the callables started beside every run and stopped
after it (the load sampler is the first; safeguard watch, the sampler of the ground truth and the injector go there).
"""
import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shlex
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python -m skuska.g2 from another directory
    sys.path.insert(0, str(ROOT))

from scripts import campaign, collection, collection_archive, protocol_v5  # noqa: E402

STAGE = "G2"
ROLE = "diagnostic"  # Map point A: G2 runs diagnostic sessions (--role pilot stays refused under schema 3).
CAMPAIGN_ID = "g2"  # Q55: the reclaim of raw/ needs the session's campaign id; every G2 session carries this one.
G2_DIR = Path("/home/eh/hyptcn3-logs/v5/dokazy/G2")  # Stage G2's evidence outside git (skeleton section 5).
DIAGNOSTICS = ROOT / "data/diagnostics/G2"  # Map point A: the collection base of a VM is DIAGNOSTICS/<vm>.
DECK_SCHEMA = "hyptcn3/g2-deck/1"
SESSION_SCHEMA = "hyptcn3/g2-session/1"
GROUP_FAILURE_SCHEMA = "hyptcn3/g2-group-start-failure/1"
OCCURRENCES = 19  # Proposal 10.3 and Q43: occurrences of every event type, on both VMs together.
MIN_PER_VM = 8  # Q43: at least 8 occurrences of every type on each VM.
MIN_PER_SCENARIO = 8  # Skeleton section 3: every scenario in at least 8 sessions.
COMPRESSION = "zstd"  # Q55.
LOAD_INTERVAL_S = 5  # Map point B: a sample every 5 s.
LOAD_GAP_FACTOR = 3  # The executor's judgment: no gap in the samples of the measured phase above 3 intervals.
# The fixed list of dokazy/G2/zataz.sh (2026-11-24, before the first G2 run) as pgrep -f reads it, and its two
# exclusions (grep -v -e pgrep -e zataz.sh).
LOAD_PATTERN = (r"pytest|tcn\.suchy_beh|gen_prirucka\.py|check_claims\.sh|check_prirucka\.sh|audit_selftest\.py"
                r"|safeguard.* train|tcn\.train|lab_trial\.py|collection\.py.* run")
LOAD_EXCLUDED = ("pgrep", "zataz.sh")
# What a process of the list runs (invoked): its program, a script it runs (python or a shell given the file) or
# python -m; a shell's -c string runs its commands as processes of their own, and a text tool only names them.
SCRIPTS = ("gen_prirucka.py", "check_claims.sh", "check_prirucka.sh", "audit_selftest.py", "lab_trial.py",
           "collection.py")
MODULES = ("pytest", "tcn.suchy_beh", "tcn.train", "safeguard")
SHELLS = ("sh", "bash", "dash", "zsh", "ksh")
MENTIONS = ("grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "gawk", "mawk", "sed", "cat", "less", "more", "head",
            "tail", "find", "git", "echo", "printf", "vi", "vim", "nano", "man", "wc", "sort", "diff", "tee", "jq",
            "pgrep", "ps")
# The lead's answer to Q70: the heavy processes of the list; a light pytest of named test files is not one.
HEAVY = {"tcn.suchy_beh": "C4 (tcn.suchy_beh)", "gen_prirucka.py": "gen_prirucka.py, which runs the whole suite",
         "check_claims.sh": "check_claims.sh, which runs the whole suite",
         "check_prirucka.sh": "check_prirucka.sh, which runs gen_prirucka.py",
         "audit_selftest.py": "the whole self-test of the audit", "tcn.train": "a training (tcn.train)"}
HEAVY_TEST = "test_prijatie_session.py"  # Q70: heavy although it is one named file.
TEST_FILE = re.compile(r"(^|/)(test_[^/\s]*|[^/\s]*_test)\.py(::\S*)?$")
HEAVY_POLL_S = 30  # Before a session the driver waits while a heavy process runs (the executor's judgment)...
HEAVY_WAIT_S = 4 * 3600  # ...at most this long, then the block stops by name.
OTHER_VM = ("idle", "g2")  # What the block's plan lets the other VM run: nothing, or its own G2 block.
GUEST_MISMATCH = "deployed guest files differ from lab/ in this commit"  # scripts/collection.py run_session.
QEMU_SWAP = ("QEMU swap was not disabled before start", "QEMU memory was swapped before start",
             "QEMU swap is not disabled")  # run_session's two refusals and labctl's (scripts/labctl.py main).
REFUSALS = {"guest_mismatch": "the deployed guest differs from lab/ of this commit (scripts/collection.py run)",
            "qemu_swap": "the QEMU swap was refused (scripts/collection.py run or labctl start)"}
LEVELS_TIMEOUT_S = 600  # As collection.lab_json.
DECK_RULE = (
    "proposal 10.3 and Q43: every type of events.types 19 times, on both VMs together and at least 8 times on each; "
    "max(events.per_session) = 3 per session, so 38 sessions, e01 to e38 in deck order, alternating over the VMs of "
    "the protocol (e01 on a, e02 on b, ...); on each VM the scenarios follow the protocol's scenarios sorted by "
    "intensity and then profile (corp_high, eshop_high, corp_low, eshop_low), the second VM one step ahead, so the "
    "profile alternates from one session to the next and every scenario has at least 8 sessions; the types (Q51, "
    "dealt globally): the stream event_deck pairs them at random and a session holds one type of every pair, so "
    "never one type twice; on each VM the sessions of each scenario in random order, the scenarios in random order, "
    "take the two types of a pair by turns, the pair's first type first on the first VM and its second first on the "
    "second VM, so every type has 19 occurrences, 9 or 10 on each VM; the order of the types in a session is drawn "
    "last; the tenths of the starts and of the stops (stream phase_deck): two decks of full rounds of the 10 tenths "
    "over the 114 occurrences in deck order (protocol_v5._rounds, as protocol_v5._deal_tenths deals a role), so the "
    "counts per tenth differ by at most 1; the times of each session as the plan draws them (protocol_v5._items, "
    "stream event_times), which collection.diagnostic_events admits as --events")
STREAMS_RULE = (
    "the plan's rule protocol_v5.seed(name, purpose, group, session, attempt) with the protocol's name and groups "
    "that no stream of the plan has, as scripts/lab_trial.py does for the lab test: event_deck and phase_deck with the "
    "group G2/deck, session -1 and attempt 0; event_times and traffic of a session with the group G2/<deck id>, its "
    "number and attempt 1; traffic is the session's --seed, from which scripts/collection.py diagnostic_seeds draws "
    "the other traffic streams with the group diagnostic/<group>; a session run again keeps its deck item")
RUN_RULE = (
    "map point A: .venv/bin/python scripts/collection.py --protocol P run --role diagnostic --vm V --group G "
    "--scenario SC --seed N [--rate R while the scenario's rate is null] --cycles <the protocol's cycles> --events "
    "<the deck's argument> --collections-dir data/diagnostics/G2/V --session-id ID, with --campaign-id g2 (Q55: the "
    "reclaim needs it) and, as the campaign starts a capture, --expected-boot-id and --expected-qemu of the group")
LOAD_RULE = (
    "map point B and the lead's answer to Q70: every 5 s from just before the run until it ends, /proc/loadavg and the "
    "command lines of the processes that match the fixed list of dokazy/G2/zataz.sh (LOAD_PATTERN, without pgrep and "
    "zataz.sh as there) go to zataz/<session>.jsonl, outside the session's directory; the measured phase is "
    "[measure_start_unix, measure_end_unix] of the session's end.json; a process counts for what it runs (its program, "
    "a script it runs, python -m), not for what it names (a shell's -c string, whose commands are processes of their "
    "own, a text tool such as grep); the session is counted unless a sample of its measured phase holds a heavy "
    "process (C4, gen_prirucka.py, check_claims.sh, check_prirucka.sh, audit_selftest.py, a training, a pytest that "
    "names no test file or names test_prijatie_session.py) or a run outside the block's plan (lab_trial.py with --vm, "
    "collection.py run on another VM unless --other-vm g2 lets that VM's G2 sessions run, another run on this VM); a "
    "pytest of named test files is light and recorded; the loadavg is recorded and no criterion; samples with a gap "
    "above 3 intervals in the measured phase or none within 3 intervals of its ends leave the session not counted "
    "(the executor's judgment); no block starts while a heavy process or a run outside the plan is there, and before "
    "each session the driver waits for their end, at most HEAVY_WAIT_S, then stops the block by name")
BLOCK_RULE = (
    "package H1a: before the block gates.require G1, the audit self-test, collection.measurement_dirty() empty, the "
    "deck as its rule draws it, the rates, no heavy process and no run outside the plan, the deployed guest equal to "
    "lab/; before every session the measurement code of the block's start (gates.measurement_sha256) and none that "
    "differs from the commit; per session the group start of campaign.start_steps when needed (a group per boot, "
    "group_sessions sessions to a group), collection.py run (RUN_RULE) with the load sampler beside it, labctl levels, "
    "the audit as campaign.audit_capture runs it, the archive (zstd) bound to the audit and the reclaim with the "
    "campaign id g2, the record; a non-zero run is recorded and audited and the block goes on; a guest mismatch, a "
    "refusal of the QEMU swap, a failed group start, an audit whose provenance differs from the session (its paths, "
    "the session's sha256, the protocol's, the features', the measurement code it ran against the session's "
    "measurement_sha256, not the commit, which the main tree may move during a block), an interrupt and any other "
    "error of the driver's steps stop the block after the record")
DONE_RULE = ("a deck session is done when a record of it has the run's exit code 0, an audit verdict (accepted or "
             "rejected) with its provenance checked, and the archive; --sessions N takes the first N deck sessions of "
             "the VM that are not done, each as its next attempt")
NOTE = "Stage G2 (proposal 10.3): a test on the VMs, whose data never become a dataset. Written by python -m skuska.g2."


class Refused(ValueError):
    """A block or a deck the rules refuse before anything is done."""


class Stop(Exception):
    """A block stops by name (REFUSALS, an error of the driver's own steps); the sessions done stay recorded."""


# ------------------------------------------------------------------ helpers

def utc(unix=None):
    return datetime.fromtimestamp(time.time() if unix is None else unix, timezone.utc).isoformat(timespec="seconds")


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def git(*args):
    try:
        done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def header(schema, command, n, values, guest=None):
    """A record with check E's header (scripts/check_claims.sh: commit, date, host, guest, command, n, values)."""
    status = git("status", "--porcelain")
    return {"schema": schema, "commit": (git("rev-parse", "HEAD") or "").strip() or None,
            "commit_dirty": None if status is None else bool(status), "date": utc(), "host": socket.gethostname(),
            "guest": guest, "command": command, "n": n, "values": values, "note": NOTE}


def write_new(path, doc):
    """An exclusive, fsynced JSON (collection_archive.write_new: refused when the file exists)."""
    collection_archive.write_new(path, doc)


def read_json(path):
    return json.loads(Path(path).read_text())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_samples(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


# ------------------------------------------------------------------ the deck

def deck_seed(p, purpose, group, session, attempt):
    """A seed of the deck's streams (STREAMS_RULE)."""
    return protocol_v5.seed(p["name"], purpose, group, session, attempt)


def scenario_cycle(p):
    """The scenarios in the order each VM's sessions follow them (DECK_RULE): by intensity, then profile."""
    return sorted(p["scenarios"], key=lambda name: (p["scenarios"][name]["intensity"],
                                                    p["scenarios"][name]["profile"], name))


def draw_deck(p):
    """The deck of the protocol `p` (DECK_RULE, STREAMS_RULE): {sessions, counts, streams}; the same protocol always
    gives the same deck. ValueError when the protocol cannot hold it."""
    e = p["events"]
    types, count = sorted(e["types"]), max(e["per_session"])
    vms = [row["name"] for row in p.get("vms", [])]
    if len(vms) < 2:
        raise ValueError("the deck of G2 needs the VMs of the protocol, two or more")
    if count < 1 or len(types) != 2 * count:
        raise ValueError(f"the deck pairs the types into the {count} events of a session; {len(types)} types do not")
    cycle = scenario_cycle(p)
    sessions = []
    for i in range(len(types) * OCCURRENCES // count):
        vm, index, number = vms[i % len(vms)], i // len(vms) + 1, i + 1
        group = f"G2/e{number:02d}"
        sessions.append({"id": f"e{number:02d}", "number": number, "vm": vm, "index_on_vm": index,
                         "scenario": cycle[(index - 1 + vms.index(vm)) % len(cycle)],
                         "seeds": {"event_times": deck_seed(p, "event_times", group, number, 1),
                                   "traffic": deck_seed(p, "traffic", group, number, 1)}, "labels": []})
    deck_rng = random.Random(deck_seed(p, "event_deck", "G2/deck", -1, 0))
    shuffled = deck_rng.sample(types, len(types))
    for j, pair in enumerate(zip(shuffled[::2], shuffled[1::2])):
        for v, vm in enumerate(vms):
            walk = []
            for name in deck_rng.sample(cycle, len(cycle)):
                stratum = [s for s in sessions if s["vm"] == vm and s["scenario"] == name]
                walk += deck_rng.sample(stratum, len(stratum))
            for k, session in enumerate(walk):
                session["labels"].append(pair[(j + v + k) % 2])
    for session in sessions:
        session["labels"] = deck_rng.sample(session["labels"], len(session["labels"]))
    phase_rng = random.Random(deck_seed(p, "phase_deck", "G2/deck", -1, 0))
    rounds = -(-sum(len(s["labels"]) for s in sessions) // protocol_v5.TENTHS)
    cards = [(d, rounds) for d in range(protocol_v5.TENTHS)]
    starts, stops = protocol_v5._rounds(phase_rng, cards, rounds), protocol_v5._rounds(phase_rng, cards, rounds)
    j = 0
    for session in sessions:
        labels = session.pop("labels")
        tenths = [(starts[j + k], stops[j + k]) for k in range(len(labels))]
        j += len(labels)
        events = protocol_v5._items(p, ROLE, labels, tenths, random.Random(session["seeds"]["event_times"]))
        session.update(seed=session["seeds"]["traffic"], tenths=[list(t) for t in tenths], events=events,
                       argument=json.dumps([{k: x[k] for k in collection.DIAGNOSTIC_EVENT_KEYS} for x in events]))
    counts = deck_counts(p, sessions)
    problems = deck_problems(p, counts)
    if problems:
        raise ValueError("the deck breaks its rule: " + "; ".join(problems))
    return {"sessions": sessions, "counts": counts,
            "streams": {"rule": STREAMS_RULE, "name": p["name"],
                        "seeds": {purpose: deck_seed(p, purpose, "G2/deck", -1, 0)
                                  for purpose in ("event_deck", "phase_deck")}}}


def deck_counts(p, sessions):
    """What the rule promises, counted: occurrences by type and by type and VM, sessions by scenario and by scenario
    and VM, starts and stops per tenth of the collection interval, distinct types per session."""
    vms = sorted({s["vm"] for s in sessions})
    events = [(s, x) for s in sessions for x in s["events"]]
    by_type = {t: sum(x["type"] == t for _, x in events) for t in sorted(p["events"]["types"])}
    tenths = {"starts": [0] * protocol_v5.TENTHS, "stops": [0] * protocol_v5.TENTHS}
    for _, x in events:
        start, stop = protocol_v5.item_tenths(p, x)
        tenths["starts"][start] += 1
        tenths["stops"][stop] += 1
    return {"occurrences_by_type": by_type,
            "occurrences_by_type_and_vm": {t: {vm: sum(x["type"] == t and s["vm"] == vm for s, x in events)
                                               for vm in vms} for t in by_type},
            "sessions_by_scenario": {name: sum(s["scenario"] == name for s in sessions)
                                     for name in sorted(p["scenarios"])},
            "sessions_by_scenario_and_vm": {name: {vm: sum(s["scenario"] == name and s["vm"] == vm for s in sessions)
                                                   for vm in vms} for name in sorted(p["scenarios"])},
            "per_tenth": tenths,
            "distinct_types_per_session": sorted({len({x["type"] for x in s["events"]}) for s in sessions})}


def deck_problems(p, counts):
    out = [f"type {t} holds {n} occurrences, not {OCCURRENCES}" for t, n in counts["occurrences_by_type"].items()
           if n != OCCURRENCES]
    out += [f"type {t} holds {n} occurrences on VM {vm}, fewer than {MIN_PER_VM}"
            for t, row in counts["occurrences_by_type_and_vm"].items() for vm, n in row.items() if n < MIN_PER_VM]
    out += [f"scenario {name} has {n} sessions, fewer than {MIN_PER_SCENARIO}"
            for name, n in counts["sessions_by_scenario"].items() if n < MIN_PER_SCENARIO]
    out += [f"the {what} per tenth differ by more than 1: {row}" for what, row in counts["per_tenth"].items()
            if max(row) - min(row) > 1]
    if counts["distinct_types_per_session"] != [max(p["events"]["per_session"])]:
        out.append("a session holds a type twice")
    return out


def write_deck(protocol_path, out, command):
    """Draw the deck of the protocol file and write it to the new file `out` (refused when it exists)."""
    from scripts import gates  # Inside the function, as scripts/collection.py does: gates imports collection.
    out = Path(out).absolute()
    if out.exists() or out.is_symlink():
        raise Refused(f"the deck {out} exists: a deck is drawn once and never changed")
    p = collection.protocol(protocol_path)
    deck = draw_deck(p)
    values = {"stage": STAGE, "rule": DECK_RULE, "protocol": str(Path(protocol_path).absolute()),
              "protocol_sha256": digest(protocol_path), "protocol_g0_binding": gates.stage_sha256(protocol_path, "G0"),
              "occurrences": OCCURRENCES, "per_session": max(p["events"]["per_session"]), "cycles": p["cycles"],
              **deck}
    doc = header(DECK_SCHEMA, command, len(deck["sessions"]), values)
    write_new(out, doc)
    return doc


def load_deck(path, p):
    """(the deck file at `path`, its sha256), refused unless it is the deck its rule draws from `p`."""
    try:
        doc = read_json(path)
    except (OSError, ValueError) as error:
        raise Refused(f"the deck {path} cannot be read: {error}") from None
    if type(doc) is not dict or doc.get("schema") != DECK_SCHEMA or type(doc.get("values")) is not dict:
        raise Refused(f"{path} is no deck of G2 ({DECK_SCHEMA})")
    expected = draw_deck(p)
    for key in ("sessions", "streams"):
        if doc["values"].get(key) != expected[key]:
            raise Refused(f"the deck {path} differs from the deck its rule draws from this protocol ({key}): a deck "
                          "is drawn once and never changed")
    return doc, digest(path)


# ------------------------------------------------------------------ the host load

def sample(processes, loadavg, clock=time.time, exclude=()):
    """One sample of the host load (LOAD_RULE): the time, /proc/loadavg and every process the fixed list matches."""
    procs = []
    for pid, argv in processes():
        text = " ".join(argv)
        if (argv and pid not in exclude and not any(word in text for word in LOAD_EXCLUDED)
                and re.search(LOAD_PATTERN, text)):
            procs.append({"pid": pid, "argv": list(argv)})
    unix = clock()
    return {"t": utc(unix), "unix": round(unix, 3), "loadavg": loadavg(), "procs": procs}


def invoked(argv):
    """The tools of the fixed list a process runs (LOAD_RULE): its program, the script it runs, python -m; none for
    a shell given a -c string (its commands run as processes of their own) and none for a text tool that names
    them."""
    name = Path(argv[0]).name
    if name in MENTIONS:
        return set()
    if name in SHELLS:
        for arg in argv[1:]:
            if not arg.startswith("-"):
                return {Path(arg).name} & set(SCRIPTS)
            if not arg.startswith("--") and "c" in arg[1:]:
                return set()
        return set()
    out = {Path(arg).name for arg in argv if Path(arg).name in SCRIPTS}
    out |= {module for flag, module in zip(argv, argv[1:]) if flag == "-m" and module in MODULES}
    if any(Path(arg).name in ("pytest", "py.test") for arg in argv):
        out.add("pytest")
    return out


def _option(argv, name):
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(name + "="):
            return arg[len(name) + 1:]
    return None


def classify(argv, *, vm, others, other_vm, session_id=None):
    """(class, why) of a process the fixed list matched (LOAD_RULE): heavy, outside (a run outside the block's plan),
    beside (the other VM's G2 session that --other-vm g2 lets run), own (this session's run), light (a pytest of named
    test files) or listed (on the list, none of these)."""
    tools = invoked(argv)
    heavy = sorted(tools & set(HEAVY))
    if heavy:
        return "heavy", HEAVY[heavy[0]]
    if "safeguard" in tools and "train" in argv:
        return "heavy", "a training (safeguard train)"
    if "pytest" in tools:
        files = [arg for arg in argv if TEST_FILE.search(arg)]
        if not files:
            return "heavy", "a pytest that names no test file (the whole suite or a directory)"
        if any(Path(arg.split("::")[0]).name == HEAVY_TEST for arg in files):
            return "heavy", HEAVY_TEST
        return "light", "a pytest of named test files"
    if "lab_trial.py" in tools:
        target = _option(argv, "--vm")
        if target is None:
            return "listed", "lab_trial.py without --vm (no VM)"
        return "outside", f"lab_trial.py on VM {target}, outside the block's plan"
    if "collection.py" in tools and "run" in argv:
        target = _option(argv, "--vm")
        if target == vm:
            if session_id is not None and _option(argv, "--session-id") == session_id:
                return "own", "this session's run"
            return "outside", f"another collection.py run on VM {vm}"
        base = (_option(argv, "--collections-dir") or "").rstrip("/")
        if (target in others and other_vm == "g2" and _option(argv, "--role") == ROLE
                and _option(argv, "--campaign-id") == CAMPAIGN_ID and base.endswith(f"data/diagnostics/G2/{target}")):
            return "beside", f"a G2 session on VM {target} (--other-vm g2)"
        return "outside", f"collection.py run on VM {target}, outside the block's plan"
    return "listed", "on the list, but it runs no heavy tool and no run" if tools else "it only names the list"


def loud(samples, **context):
    """[(class, why, command line)] of the heavy processes and the runs outside the plan in `samples`."""
    out = set()
    for s in samples:
        for proc in s["procs"]:
            kind, why = classify(proc["argv"], **context)
            if kind in ("heavy", "outside"):
                out.add((kind, why, " ".join(proc["argv"])))
    return sorted(out)


def load_summary(samples, start, end, *, interval, **context):
    """The summary of the measured phase [start, end] (LOAD_RULE): counted or not and why, the processes seen by
    class, the 1-minute loadavg."""
    out = {"rule": LOAD_RULE, "samples": len(samples), "measured": {"start_unix": start, "end_unix": end}}
    if start is None or end is None:
        return {**out, "counted": False,
                "reasons": ["no measured phase: end.json has no measure_start_unix and measure_end_unix"]}
    gap = LOAD_GAP_FACTOR * interval
    times = sorted(s["unix"] for s in samples)
    reasons = []
    if (not times or times[0] > start + gap or times[-1] < end - gap
            or any(b - a > gap for a, b in zip(times, times[1:]) if b >= start and a <= end)):
        reasons.append(f"the samples do not cover the measured phase (a gap above {gap:g} s)")
    inside = [s for s in samples if start <= s["unix"] <= end]
    seen = {}
    for s in inside:
        for proc in s["procs"]:
            kind, why = classify(proc["argv"], **context)
            row = seen.setdefault((kind, why, " ".join(proc["argv"])), {"samples": 0, "first": s["t"]})
            row.update(samples=row["samples"] + 1, last=s["t"])
    found = [{"class": kind, "why": why, "command": command, **row}
             for (kind, why, command), row in sorted(seen.items())]
    reasons += [f"{row['class']}: {row['why']}: {row['command']}" for row in found
                if row["class"] in ("heavy", "outside")]
    loads = []
    for s in inside:
        try:
            loads.append(float(s["loadavg"].split()[0]))
        except (ValueError, IndexError, AttributeError):
            pass
    return {**out, "inside": len(inside), "counted": not reasons, "reasons": reasons, "processes": found,
            "loadavg_1min": {"max": max(loads), "mean": round(sum(loads) / len(loads), 3)} if loads else None}


class LoadSampler:
    """The sampler beside a run (LOAD_RULE): a thread that writes a sample to `path` (a new file) every interval."""

    def __init__(self, path, interval, processes, loadavg, exclude=()):
        self.path, self.interval, self.processes, self.loadavg = Path(path), interval, processes, loadavg
        self.exclude, self.count, self.error = set(exclude), 0, None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="g2-load", daemon=True)
        self._stream = None

    def start(self):
        self._stream = self.path.open("x")
        self._thread.start()
        return self

    def _loop(self):
        try:
            while True:
                self._stream.write(json.dumps(sample(self.processes, self.loadavg, exclude=self.exclude),
                                              ensure_ascii=False) + "\n")
                self._stream.flush()
                self.count += 1
                if self._stop.wait(self.interval):
                    break
        except Exception as error:  # noqa: BLE001 - the summary names a sampler that failed; the session goes on
            self.error = f"{type(error).__name__}: {error}"

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=60)
        if self._stream is not None:
            self._stream.close()
        return {"hook": "load", "file": str(self.path), "samples": self.count, "error": self.error}


# ------------------------------------------------------------------ the real steps

@contextmanager
def host_audit_lock(log):
    """One audit or archive on the host at a time, over the VMs and every campaign: the lock file of
    campaign.audit_lock (data/collections/.audit.lock), without its campaign state; a wait goes to the block log."""
    campaign.COLLECTIONS.mkdir(parents=True, exist_ok=True)
    fd = os.open(campaign.COLLECTIONS / ".audit.lock", os.O_CREAT | os.O_RDWR, 0o644)
    try:
        waiting = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waiting:
                    log("waits for the audit lock: another audit or archive runs on the host")
                waiting = True
                time.sleep(campaign.WAIT_POLL_S)
        if waiting:
            log("has the audit lock")
        yield
    finally:
        os.close(fd)


class Lab:
    """Every lab and root step of a block, done as the measurement code and the campaign do it; a test gives a fake
    with the same methods (no VM, no root)."""

    def __init__(self, protocol_path, p):
        self.protocol_path, self.p = Path(protocol_path), p

    def readiness(self):
        """Map question 9: gates.require of stage G1 (a valid G0), and the self-test every capture asks for."""
        from scripts import gates
        from scripts.audit_selftest import require_selftest
        gates.require(gates.ROOT / "data/results", self.protocol_path, "G1")
        require_selftest(self.protocol_path)

    def measurement_dirty(self):
        return collection.measurement_dirty()

    def measurement(self):
        from scripts import gates
        return gates.measurement_sha256()

    def is_root(self):
        return os.geteuid() == 0 and bool(os.environ.get("SUDO_USER"))

    def identity(self):
        return collection.guest_identity(self.p)

    def qemu(self):
        return collection.qemu_process(self.p["domain"])

    def lab_sha256(self):
        return collection.lab_sha256()

    def start_group(self, directory, name, before, environment, steps):
        return campaign.start_steps(directory, {"guest_environment": environment}, self.p,
                                    {"group": name, "role": ROLE, "vm": self.p["vm"]}, before, steps)

    def child(self, command, log, *, timeout, lock_fd=None):
        return campaign.run_child(command, log, timeout=timeout, lock_fd=lock_fd)

    def collection_lock(self):
        return collection.collection_lock(campaign.COLLECTIONS, self.p["domain"])

    def audit_lock(self, log):
        return host_audit_lock(log)

    def archive(self, source, destination, guard, **options):
        return collection_archive.archive_session(source, destination, guard, **options)

    def mount(self, root):
        return collection_archive.mount_identity(root, allow_system=True)  # The HDD holds / and the archive (Q55).

    def guard(self, root, mount):
        collection_archive.guard_mount(root, mount)

    def processes(self):
        return [(pid, [arg.decode(errors="replace") for arg in argv]) for pid, argv in collection.processes()]

    def loadavg(self):
        return Path("/proc/loadavg").read_text().strip()

    def sampler(self, path, interval):
        return LoadSampler(path, interval, self.processes, self.loadavg, exclude={os.getpid()})

    def inhibitor(self):
        process = campaign.hold_sleep_inhibitor()
        return lambda: campaign.release_sleep_inhibitor(process)

    def interrupts(self):
        return collection.Interrupts()

    def sleep(self, seconds):
        time.sleep(seconds)

    def monotonic(self):
        return time.monotonic()

    def owner(self):
        return ((int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
                if "SUDO_UID" in os.environ and "SUDO_GID" in os.environ else None)


class Places:
    """Where a block writes (skeleton section 5, Q55): the records zaznamy/, the load zataz/ and the archives
    session/<vm>/ in the G2 directory, the collection base of each VM in data/diagnostics/G2."""

    def __init__(self, g2_dir=G2_DIR, diagnostics=DIAGNOSTICS):
        self.root, self.diagnostics = Path(g2_dir).absolute(), Path(diagnostics).absolute()
        self.records, self.load, self.archive = self.root / "zaznamy", self.root / "zataz", self.root / "session"


# ------------------------------------------------------------------ the block

def parse_rates(items):
    """{scenario: rate} of --rate SCENARIO=R options."""
    out = {}
    for item in items or []:
        name, sep, text = item.partition("=")
        try:
            rate = float(text)
        except ValueError:
            rate = None
        if not sep or not name or rate is None or not math.isfinite(rate) or rate <= 0 or name in out:
            raise Refused(f"--rate {item}: SCENARIO=R, a rate above 0 (user sessions per second at envelope level 1), "
                          "once per scenario")
        out[name] = rate
    return out


def refusal_in(text):
    """The name of a refusal in a child's output that stops the block (REFUSALS), else None."""
    if GUEST_MISMATCH in text:
        return "guest_mismatch"
    if any(words in text for words in QEMU_SWAP):
        return "qemu_swap"
    return None


class Block:
    """One block of G2 sessions on one VM (BLOCK_RULE)."""

    def __init__(self, protocol_path, deck_path, vm, *, other_vm, sessions=None, only=None, rates=None,
                 places=None, lab=None, command="", interval=LOAD_INTERVAL_S):
        if other_vm not in OTHER_VM:
            raise Refused(f"--other-vm is one of {', '.join(OTHER_VM)}")
        self.protocol_path, self.deck_path = Path(protocol_path).absolute(), Path(deck_path).absolute()
        self.vm, self.other_vm, self.count, self.only = vm, other_vm, sessions, only
        self.rates, self.places, self.command, self.interval = dict(rates or {}), places or Places(), command, interval
        self.full = collection.protocol(self.protocol_path)
        self.p = collection.for_vm(self.full, vm)
        self.others = [row["name"] for row in self.full["vms"] if row["name"] != vm]
        self.lab = lab or Lab(self.protocol_path, self.p)
        self.cycles, self.group_sessions = self.p["cycles"], self.p["group_sessions"]
        self.block_id = stamp()
        self.base = self.places.diagnostics / vm
        self.block_dir = self.places.records / "bloky" / f"{vm}_{self.block_id}"
        self.log_path = self.places.records / f"blok_{vm}_{self.block_id}.log"
        self.group, self.groups, self.children, self.lock_fd, self.mount = None, 0, 0, None, None
        self.measurement = None
        self.deck = self.deck_sha256 = None
        self.beside = [self.load_sampler]  # Hooks (H1b): (block, spec, paths) -> an object with stop() -> dict.
        self.results = []

    # -------------------------------------------------- before the block

    def context(self, spec=None):
        return {"vm": self.vm, "others": self.others, "other_vm": self.other_vm,
                "session_id": None if spec is None else spec["session_id"]}

    def records(self):
        """The values of the records of this VM's G2 sessions."""
        out = []
        for path in sorted(self.places.records.glob(f"g2-{self.vm}-*.json")):
            try:
                doc = read_json(path)
            except (OSError, ValueError):
                continue
            if type(doc) is dict and doc.get("schema") == SESSION_SCHEMA and doc["values"].get("vm") == self.vm:
                out.append(doc["values"])
        return out

    def attempt(self, deck_id):
        """The next attempt of a deck session: above every recorded one and every session directory of it."""
        used = [r["attempt"] for r in self.records() if r.get("deck_session") == deck_id]
        pattern = re.compile(rf"g2-{re.escape(self.vm)}-{re.escape(deck_id)}-(\d+)")
        names = [d.name for d in self.base.iterdir()] if self.base.is_dir() else []
        used += [int(m[1]) for name in names if (m := pattern.fullmatch(name))]
        return max(used, default=0) + 1

    def specs(self):
        """The sessions of the block from the deck (DONE_RULE): {kind, id, deck, scenario, seed, events, attempt,
        session_id} each."""
        items = [s for s in self.deck["values"]["sessions"] if s["vm"] == self.vm]
        if self.only is not None:
            unknown = [x for x in self.only if x not in {s["id"] for s in items}]
            if unknown or not self.only or len(set(self.only)) != len(self.only):
                raise Refused(f"--only names deck sessions of VM {self.vm}, each once; not of it: {', '.join(unknown)}")
            chosen = [s for s in items if s["id"] in self.only]
        else:
            done = {r["deck_session"] for r in self.records() if r.get("done") is True}
            left = [s for s in items if s["id"] not in done]
            if type(self.count) is not int or self.count < 1:
                raise Refused("--sessions N: a number of sessions above 0")
            if self.count > len(left):
                raise Refused(f"--sessions {self.count}: {len(left)} deck sessions of VM {self.vm} are not done")
            chosen = left[:self.count]
        specs = []
        for item in chosen:
            attempt = self.attempt(item["id"])
            specs.append({"kind": "deck", "id": item["id"], "deck": item, "scenario": item["scenario"],
                          "seed": item["seed"], "events": item["argument"], "attempt": attempt,
                          "session_id": f"g2-{self.vm}-{item['id']}-{attempt}"})
        return specs

    def rate(self, scenario):
        """(rate, source) of a session: the protocol's, or --rate while the protocol's is null (map point A)."""
        rate = self.p["scenarios"][scenario]["rate"]
        if rate is None:
            if scenario not in self.rates:
                raise Refused(f"scenario {scenario} has no rate in the protocol (null until G2): --rate {scenario}=R")
            return self.rates[scenario], "command line"
        if scenario in self.rates:
            raise Refused(f"scenario {scenario} has the rate {rate:g} in the protocol: --rate {scenario} is refused")
        return rate, "protocol"

    def checks(self, specs):
        """The refusals before the block (BLOCK_RULE) that need no VM; [] when it may start."""
        problems = []
        try:
            self.lab.readiness()
        except ValueError as error:
            problems.append(f"readiness: {error}")
        dirty = self.lab.measurement_dirty()
        if dirty:
            problems.append("the measurement code differs from the commit: " + ", ".join(dirty))
        scenarios = {spec["scenario"] for spec in specs}
        unused = sorted(set(self.rates) - scenarios)
        if unused:
            problems.append("--rate of a scenario no session of the block runs: " + ", ".join(unused))
        for name in sorted(scenarios):
            try:
                self.rate(name)
            except Refused as error:
                problems.append(str(error))
        problems += [f"{kind}: {why}: {line}" for kind, why, line in self.loud_now()]
        return problems

    def loud_now(self):
        return loud([sample(self.lab.processes, self.lab.loadavg, exclude={os.getpid()})], **self.context())

    def prepare(self):
        self.deck, self.deck_sha256 = load_deck(self.deck_path, self.full)
        return self.specs()

    def plan(self):
        """The dry run: the checks and the commands of the block's sessions; nothing started, nothing written."""
        specs = self.prepare()
        problems = self.checks(specs)
        group = {"name": f"g2-{self.vm}-{self.block_id}-1", "identity": {"boot_id": "<at the start of the group>"},
                 "qemu": "<at the start of the group>"}
        rows = []
        for spec in specs:
            try:
                command = self.run_command(spec, group)
            except Refused as error:
                command = str(error)
            rows.append({"session_id": spec["session_id"], "deck": spec["id"], "scenario": spec["scenario"],
                         "command": command})
        return {"vm": self.vm, "block": self.block_id, "refusals": problems, "sessions": rows,
                "group_sessions": self.group_sessions, "rules": {"block": BLOCK_RULE, "run": RUN_RULE}}

    # -------------------------------------------------- the block

    def log(self, message):
        line = f"{utc()} {self.vm} {message}"
        print(line, flush=True)
        if self.log_path.exists():
            with self.log_path.open("a") as stream:
                stream.write(line + "\n")

    def mkdirs(self, directories):
        for directory in directories:
            missing = [d for d in [directory, *directory.parents] if not d.exists()]
            directory.mkdir(parents=True, exist_ok=True)
            self.chown(missing)

    def run(self, specs=None):
        """Run the block; returns its summary. Refused before anything starts; a stop by name is in "stopped"."""
        self.deck, self.deck_sha256 = load_deck(self.deck_path, self.full)
        specs = self.specs() if specs is None else specs
        problems = self.checks(specs)
        if not self.lab.is_root():
            problems.append("a block runs as root through sudo from the VM owner's account (collection.user_command "
                            "runs labctl as SUDO_USER)")
        if problems:
            raise Refused("the block does not start: " + " | ".join(problems))
        identity = self.lab.identity()
        mismatch = collection.guest_mismatch(identity, self.lab.lab_sha256())
        if mismatch:
            raise Refused("the block does not start: the deployed guest differs from lab/ of this commit: "
                          + ", ".join(mismatch))
        environment = campaign.guest_environment(identity)
        self.measurement = self.lab.measurement()
        stopped = None
        with ExitStack() as stack:
            try:  # The VM's lock first, as the campaign's runner holds it: no other capture of this VM meanwhile.
                self.lock_fd = stack.enter_context(self.lab.collection_lock())
            except BlockingIOError:
                raise Refused(f"the block does not start: another capture holds the collection lock of "
                              f"{self.p['domain']}") from None
            self.mkdirs([self.block_dir / "logs", self.block_dir / "groups", self.places.load,
                         self.places.archive / self.vm])
            self.mount = self.lab.mount(self.places.archive)
            with self.log_path.open("x") as stream:
                stream.write(f"{utc()} {self.vm} block {self.block_id}: {len(specs)} sessions "
                             f"({', '.join(s['session_id'] for s in specs)}), other VM {self.other_vm}, deck "
                             f"{self.deck_path} {self.deck_sha256}, measurement code {self.measurement}, command "
                             f"{self.command}\n")
            self.chown([self.log_path])
            interrupts = self.lab.interrupts()
            stack.callback(interrupts.restore)
            try:
                stack.callback(self.lab.inhibitor())
                for spec in specs:
                    self.frozen()
                    self.quiet()
                    result = self.session(spec, environment)
                    self.results.append(result)
                    if result["stop"]:
                        stopped = result["stop"]
                        break
            except (Stop, InterruptedError) as error:
                stopped = f"{type(error).__name__}: {error}"
            except BaseException as error:
                self.log(f"block {self.block_id} stopped: {type(error).__name__}: {error}; {len(self.results)} "
                         "sessions recorded")
                raise
            finally:
                try:
                    interrupts.disarm()
                except InterruptedError:
                    pass
        self.log(f"block {self.block_id} " + (f"stopped: {stopped}" if stopped else "done")
                 + f"; {len(self.results)} sessions recorded")
        return {"vm": self.vm, "block": self.block_id, "log": str(self.log_path), "stopped": stopped,
                "sessions": [{k: r[k] for k in ("session_id", "record", "done", "counted", "stop")}
                             for r in self.results]}

    def frozen(self):
        """The measurement code of every session is the block's: Stop when it changed or differs from the commit."""
        now, dirty = self.lab.measurement(), self.lab.measurement_dirty()
        if now != self.measurement or dirty:
            raise Stop(f"the measurement code changed during the block ({self.measurement} -> {now}; differing from "
                       f"the commit: {', '.join(dirty) or 'none'})")

    def quiet(self):
        """LOAD_RULE: before a session the driver waits while a heavy process or a run outside the plan is there, at
        most HEAVY_WAIT_S, then stops the block by name."""
        deadline, said = self.lab.monotonic() + HEAVY_WAIT_S, False
        while True:
            found = self.loud_now()
            if not found:
                if said:
                    self.log("the heavy processes ended; the block goes on")
                return
            text = "; ".join(f"{kind}: {why}: {line}" for kind, why, line in found)
            if self.lab.monotonic() >= deadline:
                raise Stop(f"heavy processes for {HEAVY_WAIT_S} s before the next session: {text}")
            if not said:
                self.log("waits before the next session: " + text)
                said = True
            self.lab.sleep(HEAVY_POLL_S)

    def ensure_group(self, environment):
        """Step 0: the current group while it has fewer than group_sessions sessions and its boot and QEMU process are
        there, else a new group started as the campaign starts one."""
        if self.group is not None and self.group["sessions"] < self.group_sessions:
            if self.lab.identity() == self.group["identity"] and self.lab.qemu() == self.group["qemu"]:
                return self.group
            self.log(f"group {self.group['name']}: its boot or QEMU process is gone; a new group")
        self.groups += 1
        name = f"g2-{self.vm}-{self.block_id}-{self.groups}"
        steps, before = [], self.lab.qemu()
        self.log(f"group {name}: start (labctl stop, start, reset, pretouch)")
        try:
            record = self.lab.start_group(self.block_dir, name, before, environment, steps)
        except campaign.GroupStartFailed as failure:
            path = self.block_dir / "groups" / f"{name}.start-failed.json"
            write_new(path, {"schema": GROUP_FAILURE_SCHEMA, "group": name, "date": utc(), "step": failure.step,
                             "error": str(failure), "steps": steps,
                             "log": None if failure.log is None else str(failure.log),
                             "rule": campaign.GROUP_START_RULE})
            self.chown([path, *(self.block_dir / "logs").glob("group-*")])
            kind = "qemu_swap" if refusal_in(str(failure)) == "qemu_swap" else "group_start"
            raise Stop(f"{kind}: the start of group {name} failed at {failure.step}: {failure}") from None
        path = self.block_dir / "groups" / f"{name}.json"
        write_new(path, record)
        self.chown([path, *(self.block_dir / "logs").glob("group-*")])
        self.group = {"name": name, "record": str(path), "sha256": digest(path), "identity": record["identity"],
                      "qemu": record["qemu"], "sessions": 0}
        return self.group

    def run_command(self, spec, group):
        """The capture's command line (RUN_RULE); the hook the controls wrapper of H1b replaces: a spec with controls
        (package H1b2) runs the same command line through the wrapper of Q46 (skuska/kontroly.py WRAP_RULE), which
        writes its record beside the session in kontroly/<session>.json of the G2 directory."""
        if spec.get("controls") is not None:
            from skuska import kontroly  # Package H1b2; imported here, since skuska/kontroly.py imports this module.
            return kontroly.wrapper_command(self.run_command(dict(spec, controls=None), group), spec["controls"],
                                            kontroly.beside_path(self.places.root, spec["session_id"]))
        rate, source = self.rate(spec["scenario"])
        qemu = group["qemu"] if type(group["qemu"]) is str else json.dumps(group["qemu"])
        return [sys.executable, str(ROOT / "scripts/collection.py"), "--protocol", str(self.protocol_path), "run",
                "--role", ROLE, "--vm", self.vm, "--group", group["name"], "--scenario", spec["scenario"],
                "--seed", str(spec["seed"]), *(["--rate", str(rate)] if source == "command line" else []),
                "--cycles", str(self.cycles), *(["--events", spec["events"]] if spec["events"] is not None else []),
                "--collections-dir", str(self.base), "--session-id", spec["session_id"], "--campaign-id", CAMPAIGN_ID,
                "--expected-boot-id", group["identity"]["boot_id"], "--expected-qemu", qemu]

    def levels_command(self):
        return collection.user_command([sys.executable, ROOT / "scripts/labctl.py", "levels",
                                        *collection.labctl_args(self.p)])

    def audit_command(self, session, report):
        """The audit as campaign.audit_capture runs it, under the session's own copy of the protocol."""
        return collection.background_command(collection.user_command(
            [sys.executable, ROOT / "scripts/collection.py", "--protocol", session / "protocol.json", "audit", session,
             "--out", report]))

    def load_sampler(self, block, spec, paths):
        """The first hook of Block.beside: the load sampler (LOAD_RULE)."""
        return self.lab.sampler(paths["load"], self.interval).start()

    def child(self, name, command, steps, *, timeout, lock_fd=None):
        """A child of the block as campaign.run_child runs it; its step {step, command, log, exit code, times} goes to
        `steps` also when it is interrupted, and (the step, its output) comes back. The exit code is None at a
        timeout."""
        self.children += 1
        log = self.block_dir / "logs" / f"{self.children:03d}_{name}_{stamp()}.log"
        step = {"step": name, "command": [str(x) for x in command], "log": str(log), "exit_code": None,
                "started": utc()}
        steps.append(step)
        try:
            step["exit_code"] = self.lab.child(command, log, timeout=timeout, lock_fd=lock_fd)
        except TimeoutError as exc:
            step["error"] = f"timeout after {timeout} s: {exc}"
        except InterruptedError as exc:
            step["error"] = f"interrupted: {exc}"
            raise
        finally:
            step["ended"] = utc()
        return step, log.read_text(errors="replace") if log.exists() else ""

    def session(self, spec, environment):
        """One session (steps 0 to 4) and its record; its result for the block."""
        session_dir = self.base / spec["session_id"]
        paths = {"session": session_dir, "load": self.places.load / f"{spec['session_id']}.jsonl"}
        steps, besides, stop, error, audit, archived, group, levels = [], [], None, None, None, None, None, None
        self.log(f"session {spec['session_id']} ({spec['kind']} {spec['id']}, {spec['scenario']}): start")
        try:
            group = self.ensure_group(environment)
            command = self.run_command(spec, group)
            group["sessions"] += 1
            started = []
            try:
                started = [hook(self, spec, paths) for hook in self.beside]
                _, text = self.child("run", command, steps, lock_fd=self.lock_fd,
                                     timeout=self.p["warmup_s"] + self.cycles * self.p["interval_s"] + 300)
            finally:
                besides = [hook.stop() for hook in started]
            stop = refusal_in(text)
            if stop is None:
                step, text = self.child("levels", self.levels_command(), steps, timeout=LEVELS_TIMEOUT_S)
                levels = next((json.loads(line) for line in reversed(text.splitlines()) if _json_object(line)), None)
                step["levels"] = levels
                if (session_dir / "session.json").exists():
                    with self.lab.audit_lock(self.log):
                        audit = self.audit(session_dir, steps)
                        archived = self.archive(session_dir, audit, steps)
        except (Stop, InterruptedError) as exc:
            stop = error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # noqa: BLE001 - the record names every error of the driver's steps; the block stops
            error = f"{type(exc).__name__}: {exc}"
            stop = "error: " + error
        finally:
            end = session_dir / "end.json"
            measured = read_json(end) if end.exists() else {}
            summary = load_summary(read_samples(paths["load"]), measured.get("measure_start_unix"),
                                   measured.get("measure_end_unix"), interval=self.interval, **self.context(spec))
            record = self.record(spec, group, steps, besides, levels, audit, archived, summary, stop, error, paths)
        v = record["values"]
        self.log(f"session {spec['session_id']}: run exit {steps[0]['exit_code'] if steps else None}, audit "
                 f"{None if audit is None else audit['accepted']}, done {v['done']}, counted {v['counted']}"
                 + (f"; stop: {stop}" if stop else ""))
        return {"session_id": spec["session_id"], "record": record["path"], "done": v["done"],
                "counted": v["counted"], "stop": stop}

    def audit(self, session_dir, steps):
        """Step 3: the audit as campaign.audit_capture runs it; Stop when it gives no verdict or its provenance
        differs from the session."""
        report = session_dir / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.json"
        step, _ = self.child("audit", self.audit_command(session_dir, report), steps,
                             timeout=max(600, self.cycles * 15))
        if step["exit_code"] not in (0, 2) or not report.exists():
            raise Stop(f"the audit of {session_dir.name} gave no verdict (exit {step['exit_code']}); see {step['log']}")
        doc = read_json(report)
        v, meta = doc["values"], read_json(session_dir / "session.json")
        features = Path(v.get("features") or "")
        code = {**(v.get("auditor_sha256") or {}), **(v.get("extractor_sha256") or {})}
        measured = meta.get("measurement_sha256") or {}
        why = [name for name, ok in (
            ("session_dir", v.get("session_dir") == str(session_dir)),
            ("session_sha256", v.get("session_sha256") == digest(session_dir / "session.json")),
            ("protocol_sha256", v.get("protocol_sha256") == digest(session_dir / "protocol.json")),
            ("features_sha256", features.is_file() and digest(features) == v.get("features_sha256")),
            ("measurement code", bool(code) and all(measured.get(name) == sha for name, sha in code.items())),
            ("measurement_dirty", doc.get("measurement_dirty") == [])) if not ok]
        if why:
            raise Stop(f"the audit of {session_dir.name} differs from the session: {', '.join(why)}")
        result = {"report": str(report), "sha256": digest(report), "accepted": v["accepted"], "reasons": v["reasons"],
                  "features": v["features"], "features_sha256": v["features_sha256"],
                  "commits": {"session": meta.get("commit"), "audit": doc.get("commit")}}
        step.update(result)
        return result

    def archive(self, session_dir, audit, steps):
        """Step 4: the archive (zstd) to session/<vm>/<session> bound to the audit, then the reclaim of the working
        raw/ with the campaign id g2 (Q55)."""
        destination = self.places.archive / self.vm / session_dir.name
        raw = session_dir / "raw"
        reclaim, started = raw.is_dir() and not raw.is_symlink(), utc()
        doc = self.lab.archive(session_dir, destination, lambda: self.lab.guard(self.places.archive, self.mount),
                               reclaim=reclaim, campaign_id=CAMPAIGN_ID, audit=Path(audit["report"]),
                               reserve_bytes=self.p["min_free_gib"] * 2 ** 30, compress=COMPRESSION)
        manifest = destination / collection_archive.MANIFEST
        result = {"step": "archive", "destination": str(destination), "started": started, "ended": utc(),
                  "manifest_sha256": digest(manifest) if manifest.exists() else None, "bytes": doc.get("bytes"),
                  "stored_bytes": doc.get("stored_bytes"), "reclaimed": reclaim, "compression": COMPRESSION,
                  "campaign_id": CAMPAIGN_ID}
        steps.append(result)
        return result

    def record(self, spec, group, steps, besides, levels, audit, archived, summary, stop, error, paths):
        """The session's record (SESSION_SCHEMA, check E's header) as zaznamy/<session>.json."""
        session_dir, load = paths["session"], paths["load"]
        meta = read_json(session_dir / "session.json") if (session_dir / "session.json").exists() else None
        identity = (meta or {}).get("guest_before") or (group or {}).get("identity") or {}
        guest = {"vm": self.vm, "domain": self.p["domain"],
                 **{k: identity.get(k) for k in ("kernel", "boot_id", "machine_id", "stack_sha256")}}
        run = steps[0] if steps and steps[0]["step"] == "run" else None
        try:
            rate = dict(zip(("value", "source"), self.rate(spec["scenario"])))
        except Refused:
            rate = None
        values = {
            "stage": STAGE, "kind": spec["kind"], "vm": self.vm, "block": self.block_id,
            "session_id": spec["session_id"], "deck_session": spec["id"], "attempt": spec["attempt"],
            "deck": {"path": str(self.deck_path), "sha256": self.deck_sha256, "item": spec.get("deck")},
            "scenario": spec["scenario"], "seed": spec["seed"], "rate": rate, "events": spec["events"],
            "group": None if group is None else {k: group[k] for k in ("name", "record", "sha256")},
            "session_dir": str(session_dir),
            "session_json_sha256": digest(session_dir / "session.json") if meta is not None else None,
            "commands": [s["command"] for s in steps if "command" in s],
            "exit_codes": {s["step"]: s["exit_code"] for s in steps if "command" in s},
            "steps": steps, "beside": besides, "levels_after": levels, "audit": audit, "archive": archived,
            "load": {"file": str(load), "sha256": digest(load) if load.exists() else None, "summary": summary},
            "counted": summary["counted"],
            "done": bool(run and run["exit_code"] == 0 and audit is not None and archived is not None),
            "stop": stop, "error": error, "other_vm": self.other_vm,
            "rules": {"block": BLOCK_RULE, "run": RUN_RULE, "load": LOAD_RULE, "done": DONE_RULE}}
        path = self.places.records / f"{spec['session_id']}.json"
        write_new(path, header(SESSION_SCHEMA, self.command, len(steps), values, guest=guest))
        self.chown([path, load, *(Path(s["log"]) for s in steps if "log" in s)])
        return {"path": str(path), "values": values}

    def chown(self, paths):
        """The driver's own files belong to the VM's owner, as scripts/collection.py run leaves a session's."""
        owner = self.lab.owner()
        for path in paths if owner is not None else []:
            try:
                os.chown(path, *owner, follow_symlinks=False)
            except FileNotFoundError:
                pass


def _json_object(line):
    try:
        return type(json.loads(line)) is dict
    except ValueError:
        return False


# ------------------------------------------------------------------ the command line

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m skuska.g2", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    deck = sub.add_parser("deck", help="draw the deck of events of G2 once (refused when the file exists)")
    deck.add_argument("--protocol", type=Path, required=True)
    deck.add_argument("--out", type=Path, required=True)
    block = sub.add_parser("block", help="run a block of G2 sessions on one VM (as root through sudo)")
    block.add_argument("--protocol", type=Path, required=True)
    block.add_argument("--deck", type=Path, required=True)
    block.add_argument("--vm", required=True)
    which = block.add_mutually_exclusive_group(required=True)
    which.add_argument("--sessions", type=int, help="the next N deck sessions of the VM that are not done")
    which.add_argument("--only", help="these deck sessions (ids, comma-separated), each as its next attempt")
    block.add_argument("--other-vm", choices=OTHER_VM, required=True,
                       help="what the block's plan lets the other VM run: nothing, or its own G2 block")
    block.add_argument("--rate", action="append", default=[], metavar="SCENARIO=R",
                       help="the rate of a scenario whose rate is null in the protocol (refused otherwise)")
    block.add_argument("--g2-dir", type=Path, default=G2_DIR, help="the G2 directory: zaznamy/, zataz/, session/")
    block.add_argument("--dry-run", action="store_true", help="the checks and the commands; nothing is started")
    a = parser.parse_args(argv)
    line = shlex.join(["python", "-m", "skuska.g2", *argv])
    try:
        if a.action == "deck":
            doc = write_deck(a.protocol, a.out, line)
            print(json.dumps({"deck": str(a.out), "sessions": doc["n"], "counts": doc["values"]["counts"]},
                             indent=2, ensure_ascii=False))
            return 0
        b = Block(a.protocol, a.deck, a.vm, other_vm=a.other_vm, sessions=a.sessions,
                  only=None if a.only is None else a.only.split(","), rates=parse_rates(a.rate),
                  places=Places(a.g2_dir), command=line)
        result = b.plan() if a.dry_run else b.run()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get("refusals") or result.get("stopped") else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"skuska.g2: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
