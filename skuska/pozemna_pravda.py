"""The ground truth of stage G2 under load: the dedicated sessions, the sampler beside them, the comparison on a
restored copy and the table of matches (protocol v5, package H1b1).

    python -m skuska.pozemna_pravda plan    --protocol P --out PLAN.json
    python -m skuska.pozemna_pravda block   --protocol P --deck DECK.json --plan PLAN.json --vm a --other-vm g2|idle
                                            [--only p01,p03] [--g2-dir DIR] [--dry-run]
    python -m skuska.pozemna_pravda compare --record <g2-dir>/zaznamy/<session>.json [--g2-dir DIR] [--keep-restored]
    python -m skuska.pozemna_pravda table   --compare <porovnanie.json> [...] --out F

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H3, criterion ground_truth_under_load),
the map dokazy/G2/mapa.md (row 7, points A, B, D and E, its question 17) and the lead's answers Q62 (question 17:
dedicated sessions, their exclusion from three tables, a discard only by a rule written before the data, connected
sockets only from two runs of ss), Q69 (H1b) and Q70 (what a heavy process is). skuska/ is no directory of
scripts/collection.py MEASUREMENT_DIRS: this module runs the measurement code's own commands as they stand (labctl
exec, guestparse validate, features crosscheck, collection_archive restore_raw) and changes none of them.

plan writes, once and before the first ground-truth session, the draw of the 4 dedicated sessions (DRAW_RULE) and the
plan of the moments of each (MOMENTS_RULE). block runs the sessions of one VM through skuska/g2.py Block (as root
through sudo, as the deck's blocks): Block.run(specs) with the specs of truth_specs(), and the sampler (SAMPLER_RULE)
in Block.beside. Each record of such a session says, in values.excluded, which tables of G2 leave it out (Q62,
EXCLUDED_RULE). compare restores a session's archive and runs guestparse validate per sample and features crosscheck
per full snapshot (COMPARE_RULE), as the VM's owner, while no collector reads a VM and no lab trial runs on one; it
reads a deck session at rate high too, for its full snapshots only. table reads the recorded files and
gives the table of matches with the criterion's minimums per VM (TABLE_RULE), and exits 1 when a VM misses one (as
features crosscheck exits 1 on a mismatch); it is a command of this module because the comparison it reads opens RAM
images, which scripts/campaign_report.py never does. The rules of discard and of
explanation (DISCARD_RULE, the *_RULE constants of the explanations) are written before the first comparison.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python -m skuska.pozemna_pravda from another directory
    sys.path.insert(0, str(ROOT))

from guestparse import validate as guest_validate  # noqa: E402
from scripts import collection, collection_archive, protocol_v5  # noqa: E402
from skuska import g2  # noqa: E402

KIND = "pozemna_pravda"  # The kind of a ground-truth session's spec and record (skuska/g2.py values.kind).
TRUTH_DIR = "pozemna_pravda"  # <g2-dir>/pozemna_pravda/<session>/: everything of a session outside its directory.
PLAN_SCHEMA = "hyptcn3/g2-truth-plan/1"
SAMPLER_SCHEMA = "hyptcn3/g2-truth-sampler/1"
COMPARE_SCHEMA = "hyptcn3/g2-truth-comparison/1"
TABLE_SCHEMA = "hyptcn3/g2-truth-table/1"
SAMPLES_FILE = "vzorky.jsonl"  # One line per moment of the plan, written by the sampler.
SUMMARY_FILE = "vzorkovac.json"  # The sampler's record of the session.
MOMENTS_FILE = "plan.json"  # The session's moments, written before its run starts.
NOTE = ("Stage G2 (proposal 10.3): a test on the VMs, whose data never become a dataset. Written by python -m "
        "skuska.pozemna_pravda.")

# ------------------------------------------------------------------ the dedicated sessions (Q62)

GROUP = "G2/pravda"  # The group of the role-level streams of the draw; a session's are G2/<id>.
SCENARIOS = ("eshop_high", "corp_high")  # Q62: eshop_high and corp_high on each VM.
EMPTY_EVENT = "naprazdno"  # Decision D8: the empty event; lab/udalosti.py PREDICATES: "none by definition".
EXCLUDED = ("event_effects", "marked_rows_per_event", "invalid_rows.max")  # Q62.
EXCLUDED_RULE = (
    "the lead's decision on Q62 (map question 17): the samples of a ground-truth session start processes in the "
    "guest, so its marked rows and its occurrences go into none of marked_rows_per_event, invalid_rows.max and "
    "event_effects; a table of G2 reads values.excluded.criteria of the session's record (skuska/g2.py, null for a "
    "deck session) and leaves the session out of every criterion or value it names; nothing else of G2 is left out "
    "by it")
DRAW_RULE = (
    "the lead's decision on Q62: 4 dedicated sessions, eshop_high and corp_high on each VM, each with 3 events "
    "(max(events.per_session)); p01 to p04 alternate over the VMs of the protocol (p01 on a, p02 on b, ...), on each "
    "VM its two sessions take the two scenarios in the order of skuska/g2.py scenario_cycle, the second VM one step "
    "ahead, so the first sessions of the two VMs differ in profile; the events come from their own streams "
    "(skuska/g2.py deck_seed with the groups G2/pravda and G2/<id>, which no stream of the plan or of the deck has), "
    "not from the deck of the 38 sessions: the types are the 5 types of events.types with an effect, naprazdno left "
    "out (the empty event of decision D8, whose predicate is none by definition, lab/udalosti.py PREDICATES: a "
    "snapshot during it is one of ordinary operation and adds no case under an event); each of the 5 once on each VM "
    "and one type a second time on each VM, the two VMs a different one (stream event_deck, group G2/pravda), once "
    "in each of the VM's two sessions; the other 4 types of the VM dealt 2 and 2 at random over its two sessions, "
    "the order of the types in a session drawn last; the tenths of the starts and the stops (stream phase_deck, "
    "group G2/pravda) from two decks of full rounds of the 10 tenths over the 12 occurrences in session order, as "
    "skuska/g2.py draw_deck deals them; the times as the plan draws them (protocol_v5._items, stream event_times of "
    "the group G2/<id>, its number and attempt 1), which collection.diagnostic_events admits as --events; the "
    "session's --seed is its stream traffic of the same group; a session run again keeps its item")

# The plan of the moments (MOMENTS_RULE).
SAMPLES = 16
IN_EVENTS = 6
FIRST_S = 60
LAST_S = 30
EVENT_START_MARGIN_S = 30
EVENT_STOP_MARGIN_S = 20
OUTSIDE_MARGIN_S = 30
MIN_SPACING_S = 20
MOMENTS_RULE = (
    "the lead's decision on Q62: about 15 samples per session, 5 of them during the events; this plan takes "
    f"SAMPLES = {SAMPLES} and IN_EVENTS = {IN_EVENTS}, 2 in each of the 3 events, one pair more than Q62 names, so "
    "that a discarded sample still leaves the criterion's minimums (30 snapshots per VM, 10 of them during an event, "
    "over the VM's two sessions) met (the executor's judgment); fixed before the session as a function of the "
    "session's planned events and the protocol: a moment is a sequence number of the session's chain, seq k "
    "nominally k x interval_s after the first snapshot; in each event its moments evenly inside [start_s + "
    f"{EVENT_START_MARGIN_S} s, start_s + duration_s - {EVENT_STOP_MARGIN_S} s] (the start call and the offset of "
    "the collector's first cycle from the start of the measured phase, a few seconds, lie in the first margin, and "
    "the stop call does not start before the second), the events taking IN_EVENTS by turns, the longest usable "
    f"span first; the other {SAMPLES - IN_EVENTS} evenly over the time of the session outside the audit's windows of "
    f"the events widened by {OUTSIDE_MARGIN_S} s on each side ([start_s - 1 s, start_s + duration_s + "
    "events.grace_s], collection_logs.event_window), outside the first "
    f"{FIRST_S} s (the sampler anchors on the collector's first sidecars) and the last {LAST_S} s; each at the "
    f"nearest sequence number; the moments at least {MIN_SPACING_S} s apart (a sample takes about 10 s)")

# The sampler (SAMPLER_RULE).
PS = "ps -eo pid,comm --no-headers"  # scripts/root_run.sh grab_gt; guestparse/validate.py read_ps.
LSMOD = "lsmod"  # read_lsmod.
SS = "ss -tuanp"  # read_ss: TCP and UDP, every state, numeric, with the holding processes.
BEFORE = (("ss_pred", SS), ("ps_pred", PS))  # ps last: the closest to the moment.
AFTER = (("ps_po", PS), ("ss_po", SS), ("lsmod", LSMOD))  # ps first: the closest to the moment.
LEAD_S = 6.0  # The commands before a moment start this long before its due time ...
LEAD_MARGIN_S = 2.0  # ... or the longest such phase so far plus this ...
LEAD_MAX_S = 30.0  # ... at most this (the executor's judgment: two labctl exec take 1 to 3 s at rate high).
POLL_S = 0.5  # The sampler reads raw/ for new sidecars this often.
SIDECAR_WAIT_S = 20.0  # It waits for the sidecar of the moment's seq at most this long after the due time.
COMMAND_TIMEOUT_S = 60.0  # One labctl exec at most this long (labctl's own agent timeout is 60 s).
SIDECAR_NAME = re.compile(r"^(?P<base>.+)_(?P<seq>\d{6,})_(?P<ts>\d{8}T\d{9}Z)\.json$")  # {domain}_{seq:06d}_{ts}
SAMPLER_RULE = (
    "started beside a ground-truth session through skuska/g2.py Block.beside; the moments come from the collector's "
    "own sidecars of the running session (raw/<domain>_<seq>_<time>.json, schema vmicollect/1): the due time of seq "
    "k is the newest sidecar's timestamp_unix - sched.lateness_s + (k - its seq) x interval_s, so every sample "
    "belongs to one sequence number of the chain; per moment, as the VM's owner (collection.user_command, as the "
    "driver runs labctl levels), scripts/labctl.py exec --guest-command: before the moment ss -tuanp and then ps -eo "
    "pid,comm --no-headers, started LEAD_S before the due time (more when the commands before a moment took longer: "
    "the longest such phase so far + LEAD_MARGIN_S, at most LEAD_MAX_S); after the sidecar of the seq appeared and "
    "the capture it describes ended (at most SIDECAR_WAIT_S after the due time) ps -eo pid,comm --no-headers, ss "
    "-tuanp and lsmod, the formats guestparse validate reads (as scripts/root_run.sh grab_gt takes them); each guest "
    "output with its host start and end times, exit code and sha256 into <g2-dir>/pozemna_pravda/<session>/, outside "
    "the session's directory, so that the session's logs manifest (collection.write_logs_manifest) does not change; "
    "a moment the sampler reaches after its start time is not sampled, a failed command ends its sample, and the "
    "sampler stops with the session's run")

# The discard and the explanations, written before the first comparison.
DISCARD_RULE = (
    "the lead's decision on Q62: a sample is discarded only by this rule, written before the data: (a) it was not "
    "sampled, or a guest command of it failed (an exit code other than 0, a timeout) or left no output; (b) the "
    "session's chain has no snapshot of its seq (no sidecar of the seq in the restored raw/, or one without "
    "timestamp_unix or capture.total_ms); (c) the sidecar of the "
    "seq as the sampler read it during the session differs from the archive's (sha256), so that the sample would "
    "not belong to the audited chain; (d) a command before the moment ended at or after the start of the capture of "
    "its seq (the sidecar's timestamp_unix): it started too late against its moment of the grid; (e) a command "
    "after the moment started before the end of that capture (timestamp_unix + capture.total_ms / 1000); every "
    "other sample is compared")
PS_STABLE_RULE = (
    "guestparse/validate.py compare_processes: only a pid in both runs of ps (the stable set) is compared; a pid in "
    "one run only is no difference")
PS_SHORT_RULE = (
    "the criterion's example (a process shorter than the interval): a pid of the snapshot in neither run of ps "
    "(validate false_positive) is explained when it lies strictly between the pid of the ps process of the run "
    "before and that of the run after, cyclically (pid_max wraps): Linux gives a new process the next free pid "
    "(alloc_pid, idr_alloc_cyclic), so it was created after the run before and, absent from the run after, it ended "
    "before that run read /proc; the rule needs exactly one line with comm ps in each run, else it does not apply")
PS_NAME_RULE = (
    "a stable pid whose snapshot name matches neither run under validate's name rules (exact, the first 15 "
    "characters, a worker's description) is explained when the two runs show different names for it: the process "
    "changed its name (exec, prctl) within the window between them")
TRUNCATED_RULE = (
    "a process or a module of the ground truth missing from the snapshot is explained when the parser reports the "
    "walk of that list as not closed (validate traversal.processes_truncated or modules_truncated): its count is a "
    "lower bound and the row is an invalid row of the audit (features/snapshot.py truncated_traversals, "
    "features/acceptance.py facts.invalid_rows)")
SS_STABLE_RULE = (
    "the lead's decision on Q62: connected sockets only from two runs of ss: a sample takes ss -tuanp before and "
    "after the moment, and the stable sockets are those in both runs (proto, local address and port, peer address "
    "and port, normalized as guestparse/validate.py read_ss normalizes them) that a process holds in both (a "
    "users:(...) field of ss -p); a socket no process holds (TIME-WAIT, an accept queue) is not compared, since the "
    "parser finds sockets through the file tables of processes (guestparse/view.py sockets); the file keeps the "
    "header of the run after and those lines verbatim, so that guestparse validate reads it as ss -tuanp")
SS_ONE_RUN_RULE = (
    "a socket of the snapshot outside the stable set that ss shows in one run only, or that a process holds in one "
    "run only, is explained: it was opened, closed or handed over between the two runs")
SS_SHORT_RULE = (
    "a connected socket of the snapshot (a peer port) in neither run is explained when its local or its peer port is "
    "a port the guest listens on in both runs (TCP LISTEN or UDP UNCONN of the stable set) of the same protocol: a "
    "connection of a server of the guest shorter than the window between the two runs; any other socket in neither "
    "run is not")
SS_UNBOUND_RULE = (
    "a socket of the snapshot with local port 0 is explained: an unbound socket, which ss does not list, since it "
    "reads the kernel's tables of bound sockets (docs/kontroly.md, 2026-09-18: UDP 0.0.0.0:0 of systemd-network)")
SS_HOLDER_RULE = (
    "a stable socket missing from the snapshot is explained when every process ss names as its holder is missing "
    "from the snapshot's processes (validate processes missing_list); the process's own explanation then covers it")
MODULES_RULE = (
    "one run of lsmod (Q62 names one): a module difference is explained only by TRUNCATED_RULE; no control runs in "
    "a ground-truth session, so its modules do not change")
EVENT_RULE = (
    "a compared sample is during an event when the capture of its seq ([timestamp_unix, timestamp_unix + "
    "capture.total_ms / 1000] of its sidecar) lies within [host_started_unix, host_stop_unix] of an occurrence of "
    "the session's events.json whose start succeeded (start.ok): after its start call returned and before its stop "
    "call began; in the window when it lies within the audit's window of an occurrence (collection_logs.event_window, "
    "host_start_unix - 1 s to host_stopped_unix + events.grace_s) and is not during one; outside otherwise; only a "
    "sample during an event counts toward the 10 of the criterion")
COMPARE_RULE = (
    "on a restored copy, after the session's archive (skuska/g2.py step 4 packs raw/ with zstd and reclaims the "
    "working copy): collection_archive.restore_raw re-extracts raw/ from the verified archive, every member checked "
    "against the archive's manifest, with the marker restored_from.json that names the session, into "
    "<g2-dir>/pozemna_pravda/<session>/porovnanie_<UTC>/obnova/raw beside a copy of the archive's session.json (so "
    "that guestparse reads the session's recorded boot as it does under S/raw), and the comparison reads that; why: "
    "the block's steps stay the campaign's (run, levels, audit, archive) with nothing between the audit and the "
    "archive, the comparison reads RAM images and runs only while no collector reads a VM of the protocol and no "
    "lab trial runs on a VM (scripts/lab_trial.py --vm), so that it neither loads the host beside a measured phase "
    "nor holds the host's audit lock, and the "
    "bytes it reads are those the audit read (the archive is bound to the audit, collection_archive.bind_audit); per "
    "sample the stable sockets (SS_STABLE_RULE) and python -m guestparse validate --snapshot <restored raw/> "
    "--profile S/profile (its files checked against session.json profile_sha256) --chain-until SEQ --ps-before "
    "--ps-after --lsmod --ss <stable sockets> --out; per full snapshot of the restored raw/ python -m features "
    "crosscheck --snapshot <full>.vmicd --c <its sidecar> --bin-bytes <the protocol's bin_bytes> --out: --c names "
    "the collector's vector, without it crosscheck takes --snapshot as --c and finds no vector in a .vmicd; each with "
    "collection.background_command (nice 19, ionice best effort 7), as the VM's owner; the restored copy is removed "
    "afterwards unless --keep-restored")
MIN_COMPARED = 30  # The criterion (the lead's G2 skeleton): at least 30 snapshots per VM ...
MIN_DURING = 10  # ... at least 10 of them during an event ...
MIN_FULL = 5  # ... the bins cross-checked on at least 5 full snapshots per VM.
TABLE_RULE = (
    "the criterion ground_truth_under_load (the lead's G2 skeleton, proposal 10.3): per VM at least MIN_COMPARED "
    "compared samples of sessions at rate high (intensity high), at least MIN_DURING of them during an event "
    "(EVENT_RULE), the bins cross-checked on at least MIN_FULL full snapshots of sessions at rate high, and every "
    "difference explained; a source (ps, lsmod, ss) of a sample agrees when it has no difference, is explained when "
    "every difference has an explanation by a rule written before the first comparison (the *_RULE constants of "
    "skuska/pozemna_pravda.py), and is unexplained otherwise, as is a comparison that gave no result; a full "
    "snapshot agrees when crosscheck's invariant against the sidecar and its comparison with the collector's vector "
    "both agree, and no rule explains a difference of bins; a session has 2 full snapshots (seq 0 and full_every), "
    "so the 5th of a VM comes from another G2 session at rate high on it, restored and cross-checked by compare")


class Refused(ValueError):
    """A plan, a block, a comparison or a table the rules refuse before anything is done."""


# ------------------------------------------------------------------ helpers

def header(schema, command, n, values, guest=None):
    """A record with check E's header (scripts/check_claims.sh: commit, date, host, guest, command, n, values)."""
    status = g2.git("status", "--porcelain")
    return {"schema": schema, "commit": (g2.git("rev-parse", "HEAD") or "").strip() or None,
            "commit_dirty": None if status is None else bool(status), "date": g2.utc(), "host": socket.gethostname(),
            "guest": guest, "command": command, "n": n, "values": values, "note": NOTE}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def truth_dir(g2_dir, session_id):
    return Path(g2_dir).absolute() / TRUTH_DIR / session_id


def high_scenarios(p):
    """The scenarios of Q62 in the order of skuska/g2.py scenario_cycle; ValueError unless both are of intensity
    high."""
    bad = [name for name in SCENARIOS if p["scenarios"].get(name, {}).get("intensity") != "high"]
    if bad:
        raise ValueError("the ground-truth sessions need the scenarios " + ", ".join(SCENARIOS) + " of intensity high")
    return [name for name in g2.scenario_cycle(p) if name in SCENARIOS]


def effect_types(p):
    return [t for t in sorted(p["events"]["types"]) if t != EMPTY_EVENT]


# ------------------------------------------------------------------ the plan of moments

def _deal(n, spans):
    """n moments over events by turns, the longest usable span first (ties: the earlier event)."""
    counts = [0] * len(spans)
    order = sorted(range(len(spans)), key=lambda i: (-spans[i], i))
    for j in range(n):
        counts[order[j % len(order)]] += 1
    return counts


def plan_moments(p, events):
    """The moments of one session (MOMENTS_RULE): [{seq, t_s, where, event, type}] in seq order; ValueError when the
    session cannot hold them."""
    interval, length, grace = p["interval_s"], p["cycles"] * p["interval_s"], p["events"]["grace_s"]
    n_in = IN_EVENTS if events else 0
    times = []
    if events:
        spans = [(x["start_s"] + EVENT_START_MARGIN_S, x["start_s"] + x["duration_s"] - EVENT_STOP_MARGIN_S)
                 for x in events]
        if any(b <= a for a, b in spans):
            raise ValueError("an event is too short for the margins of its moments")
        for i, ((a, b), n) in enumerate(zip(spans, _deal(n_in, [b - a for a, b in spans]))):
            times += [(a + (b - a) * (j + 1) / (n + 1), i) for j in range(n)]
    blocked = sorted((x["start_s"] - 1 - OUTSIDE_MARGIN_S, x["start_s"] + x["duration_s"] + grace + OUTSIDE_MARGIN_S)
                     for x in events)
    free, lo, hi = [], FIRST_S, length - LAST_S
    for a, b in blocked:
        if a > lo:
            free.append((lo, min(a, hi)))
        lo = max(lo, b)
    if lo < hi:
        free.append((lo, hi))
    free = [(a, b) for a, b in free if b > a]
    total, n_out = sum(b - a for a, b in free), SAMPLES - n_in
    if total <= 0:
        raise ValueError("the session has no time outside its events for the moments")
    for j in range(n_out):
        d = total * (j + 0.5) / n_out
        for a, b in free:
            if d <= b - a:
                times.append((a + d, None))
                break
            d -= b - a
    moments = sorted(({"seq": round(t / interval), "event": i} for t, i in times), key=lambda m: m["seq"])
    seqs = [m["seq"] for m in moments]
    if len(set(seqs)) != len(seqs) or any((b - a) * interval < MIN_SPACING_S for a, b in zip(seqs, seqs[1:])):
        raise ValueError(f"the moments of the session lie closer than {MIN_SPACING_S} s")
    if seqs and (seqs[0] < 1 or seqs[-1] >= p["cycles"]):
        raise ValueError("a moment lies outside the session's chain")
    return [{"seq": m["seq"], "t_s": m["seq"] * interval, "where": "outside" if m["event"] is None else "event",
             "event": m["event"], "type": None if m["event"] is None else events[m["event"]]["type"]}
            for m in moments]


# ------------------------------------------------------------------ the draw of the sessions

def draw_plan(p):
    """The draw of the ground-truth sessions of the protocol `p` (DRAW_RULE) with the moments of each (MOMENTS_RULE):
    {sessions, counts, streams}; the same protocol always gives the same draw."""
    vms = [row["name"] for row in p.get("vms", [])]
    if len(vms) != 2:
        raise ValueError("the ground-truth sessions of G2 need the two VMs of the protocol")
    high, types, count = high_scenarios(p), effect_types(p), max(p["events"]["per_session"])
    if (count - 1) * len(high) != len(types) - 1:
        raise ValueError(f"{len(types)} types with an effect do not fill {len(high)} sessions of {count} events per VM "
                         "with each type once and one type twice")
    sessions = []
    for i in range(len(high) * len(vms)):
        vm, index, number = vms[i % len(vms)], i // len(vms) + 1, i + 1
        sid = f"p{number:02d}"
        sessions.append({"id": sid, "number": number, "vm": vm, "index_on_vm": index,
                         "scenario": high[(index - 1 + vms.index(vm)) % len(high)],
                         "seeds": {purpose: g2.deck_seed(p, purpose, f"G2/{sid}", number, 1)
                                   for purpose in ("event_times", "traffic")}})
    rng = random.Random(g2.deck_seed(p, "event_deck", GROUP, -1, 0))
    twice = rng.sample(types, len(vms))
    for v, vm in enumerate(vms):
        rest = rng.sample([t for t in types if t != twice[v]], len(types) - 1)
        for j, session in enumerate(s for s in sessions if s["vm"] == vm):
            session["labels"] = [twice[v], *rest[j * (count - 1):(j + 1) * (count - 1)]]
    for session in sessions:
        session["labels"] = rng.sample(session["labels"], len(session["labels"]))
    phase_rng = random.Random(g2.deck_seed(p, "phase_deck", GROUP, -1, 0))
    rounds = -(-sum(len(s["labels"]) for s in sessions) // protocol_v5.TENTHS)
    cards = [(d, rounds) for d in range(protocol_v5.TENTHS)]
    starts, stops = protocol_v5._rounds(phase_rng, cards, rounds), protocol_v5._rounds(phase_rng, cards, rounds)
    j = 0
    for session in sessions:
        labels = session.pop("labels")
        tenths = [(starts[j + k], stops[j + k]) for k in range(len(labels))]
        j += len(labels)
        events = protocol_v5._items(p, g2.ROLE, labels, tenths, random.Random(session["seeds"]["event_times"]))
        argument = json.dumps([{k: x[k] for k in collection.DIAGNOSTIC_EVENT_KEYS} for x in events])
        if collection.diagnostic_events(p, argument, p["cycles"]) != events:
            raise ValueError(f"collection.diagnostic_events does not admit the events of {session['id']}")
        session.update(seed=session["seeds"]["traffic"], tenths=[list(t) for t in tenths], events=events,
                       argument=argument, moments=plan_moments(p, events))
    by_vm = {vm: {t: sum(x["type"] == t for s in sessions if s["vm"] == vm for x in s["events"]) for t in types}
             for vm in vms}
    counts = {"occurrences_by_type_and_vm": by_vm,
              "sessions_by_scenario_and_vm": {name: {vm: sum(s["scenario"] == name and s["vm"] == vm
                                                            for s in sessions) for vm in vms} for name in high},
              "moments_by_vm": {vm: {"all": sum(len(s["moments"]) for s in sessions if s["vm"] == vm),
                                     "event": sum(m["where"] == "event" for s in sessions if s["vm"] == vm
                                                  for m in s["moments"])} for vm in vms}}
    return {"sessions": sessions, "counts": counts,
            "streams": {"rule": DRAW_RULE, "name": p["name"],
                        "seeds": {purpose: g2.deck_seed(p, purpose, GROUP, -1, 0)
                                  for purpose in ("event_deck", "phase_deck")}}}


def write_plan(protocol_path, out, command):
    """Draw the ground-truth sessions of the protocol file and write them to the new file `out` (refused when it
    exists)."""
    from scripts import gates  # Inside the function, as skuska/g2.py write_deck does.
    out = Path(out).absolute()
    if out.exists() or out.is_symlink():
        raise Refused(f"the plan {out} exists: the plan of the ground truth is drawn once and never changed")
    p = collection.protocol(protocol_path)
    plan = draw_plan(p)
    values = {"stage": g2.STAGE, "rule": DRAW_RULE, "moments_rule": MOMENTS_RULE, "excluded_rule": EXCLUDED_RULE,
              "protocol": str(Path(protocol_path).absolute()), "protocol_sha256": digest(protocol_path),
              "protocol_g0_binding": gates.stage_sha256(protocol_path, "G0"), "cycles": p["cycles"], **plan}
    doc = header(PLAN_SCHEMA, command, len(plan["sessions"]), values)
    out.parent.mkdir(parents=True, exist_ok=True)
    g2.write_new(out, doc)
    return doc


def load_plan(path, p):
    """(the plan file at `path`, its sha256), refused unless it is the plan its rule draws from `p`."""
    try:
        doc = g2.read_json(path)
    except (OSError, ValueError) as error:
        raise Refused(f"the plan {path} cannot be read: {error}") from None
    if type(doc) is not dict or doc.get("schema") != PLAN_SCHEMA or type(doc.get("values")) is not dict:
        raise Refused(f"{path} is no plan of the ground truth of G2 ({PLAN_SCHEMA})")
    expected = draw_plan(p)
    for key in ("sessions", "streams"):
        if doc["values"].get(key) != expected[key]:
            raise Refused(f"the plan {path} differs from the plan its rule draws from this protocol ({key}): it is "
                          "drawn once and never changed")
    return doc, digest(path)


def truth_specs(block, plan_doc, plan_path, plan_sha256, only=None):
    """The specs of the block's VM's ground-truth sessions (the kind of spec of Q62, beside Block.specs()): those not
    done (skuska/g2.py DONE_RULE), or the ones `only` names, each as its next attempt."""
    items = [s for s in plan_doc["values"]["sessions"] if s["vm"] == block.vm]
    if only is not None:
        unknown = [x for x in only if x not in {s["id"] for s in items}]
        if unknown or not only or len(set(only)) != len(only):
            raise Refused(f"--only names ground-truth sessions of VM {block.vm}, each once; not of it: "
                          + ", ".join(unknown))
        chosen = [s for s in items if s["id"] in only]
    else:
        done = {r["deck_session"] for r in block.records() if r.get("done") is True}
        chosen = [s for s in items if s["id"] not in done]
        if not chosen:
            raise Refused(f"every ground-truth session of VM {block.vm} is done")
    specs = []
    for item in chosen:
        attempt = block.attempt(item["id"])
        specs.append({"kind": KIND, "id": item["id"], "deck": None, "scenario": item["scenario"], "seed": item["seed"],
                      "events": item["argument"], "attempt": attempt,
                      "session_id": f"g2-{block.vm}-{item['id']}-{attempt}",
                      "excluded": {"criteria": list(EXCLUDED), "rule": EXCLUDED_RULE},
                      "draw": {"path": str(Path(plan_path).absolute()), "sha256": plan_sha256, "item": item}})
    return specs


# ------------------------------------------------------------------ the sampler

def guest_argv(p, command):
    """labctl exec of one guest command as the VM's owner (collection.user_command, as the driver runs labctl
    levels)."""
    return collection.user_command([sys.executable, ROOT / "scripts/labctl.py", "exec", *collection.labctl_args(p),
                                    "--guest-command", command])


def sidecar_names(raw):
    """{seq: file name} of the collector's sidecars in raw/ by their names (a missing raw/ has none)."""
    out = {}
    try:
        entries = list(os.scandir(raw))
    except OSError:
        return out
    for entry in entries:
        m = SIDECAR_NAME.match(entry.name)
        if m and entry.is_file():
            out[int(m["seq"])] = entry.name
    return out


def sidecar_record(path):
    """What the sampler and the comparison keep of one sidecar: its name, sha256, seq and timing; None when it is no
    sidecar of the collector."""
    data = Path(path).read_bytes()
    doc = json.loads(data)
    if type(doc) is not dict or doc.get("schema") != "vmicollect/1":
        return None
    capture, sched, output = doc.get("capture") or {}, doc.get("sched") or {}, doc.get("output") or {}
    return {"name": Path(path).name, "sha256": hashlib.sha256(data).hexdigest(), "seq": doc.get("seq"),
            "timestamp_unix": doc.get("timestamp_unix"), "lateness_s": sched.get("lateness_s"),
            "total_ms": capture.get("total_ms"), "full": output.get("full")}


class Env:
    """The sampler's clock, its waits and its guest commands on the real host; a test gives a fake with the same
    methods."""

    def __init__(self, p):
        self.p, self.stopped, self._child = p, threading.Event(), None

    def now(self):
        return time.time()

    def wait(self, seconds):
        """Sleep; True when the sampler was stopped meanwhile."""
        return self.stopped.wait(max(0.0, seconds))

    def guest(self, command, out):
        """One guest command into the new file `out`: {argv, start_unix, end_unix, exit_code, stderr}."""
        argv = guest_argv(self.p, command)
        result = {"argv": [str(x) for x in argv], "start_unix": None, "end_unix": None, "exit_code": None,
                  "stderr": ""}
        if self.stopped.is_set():
            result["stderr"] = "not started: the sampler was stopped"
            return result
        with Path(out).open("xb") as stream:
            result["start_unix"] = time.time()
            process = subprocess.Popen(result["argv"], cwd=ROOT, stdout=stream, stderr=subprocess.PIPE,
                                       start_new_session=True)
            self._child = process
            try:
                _, err = process.communicate(timeout=COMMAND_TIMEOUT_S)
                result["exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                self.kill(process)
                _, err = process.communicate()
                err = (err or b"") + f"\ntimeout after {COMMAND_TIMEOUT_S:g} s".encode()
            finally:
                self._child = None
            result["end_unix"] = time.time()
        result["stderr"] = (err or b"").decode(errors="replace")[-2000:]
        return result

    @staticmethod
    def kill(process):
        """The exact process group of the sampler's own child (as campaign.run_child ends a child), never a
        pattern."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def stop(self):
        self.stopped.set()
        child = self._child
        if child is not None and child.poll() is None:
            self.kill(child)


class Sampler:
    """The sampler of the ground truth beside one session (SAMPLER_RULE); start() and stop() as the hooks of
    skuska/g2.py Block.beside. threaded False (a test in fake time): start() starts no thread and stop() runs the
    whole plan in the calling thread before it stops."""

    def __init__(self, block, spec, paths, env, threaded=True):
        self.block, self.spec, self.env, self.threaded = block, spec, env, threaded
        self.raw = Path(paths["session"]) / "raw"
        self.dir = truth_dir(block.places.root, spec["session_id"])
        self.moments = spec["draw"]["item"]["moments"]
        self.interval = block.p["interval_s"]
        self.lead, self.error, self.lines = LEAD_S, None, []
        self._stream = None
        self._thread = threading.Thread(target=self._loop, name="g2-pravda", daemon=True)

    def start(self):
        if self.dir.exists():
            raise Refused(f"the ground truth of {self.spec['session_id']} exists: {self.dir}")
        self.block.mkdirs([self.dir])
        plan = {"schema": SAMPLER_SCHEMA + "/plan", "session_id": self.spec["session_id"],
                "plan": {k: self.spec["draw"][k] for k in ("path", "sha256")}, "moments": self.moments,
                "events": self.spec["draw"]["item"]["events"], "rule": MOMENTS_RULE, "written": g2.utc()}
        g2.write_new(self.dir / MOMENTS_FILE, plan)
        self._stream = (self.dir / SAMPLES_FILE).open("x")
        if self.threaded:
            self._thread.start()
        return self

    def _loop(self):
        try:
            for moment in self.moments:
                line = self.sample(moment)
                self.lines.append(line)
                self._stream.write(json.dumps(line, ensure_ascii=False) + "\n")
                self._stream.flush()
        except Exception as error:  # noqa: BLE001 - the summary names a sampler that failed; the session goes on
            self.error = f"{type(error).__name__}: {error}"

    def anchor(self):
        """The newest sidecar of the session: its record with its due time, or None while there is none."""
        names = sidecar_names(self.raw)
        while names:
            seq = max(names)
            try:
                side = sidecar_record(self.raw / names[seq])
            except (OSError, ValueError):
                side = None
            if side is not None and side["seq"] == seq and all(
                    type(side[k]) in (int, float) for k in ("timestamp_unix", "lateness_s")):
                return {**side, "due_unix": side["timestamp_unix"] - side["lateness_s"]}
            names.pop(seq)
        return None

    def wait_anchor(self):
        while True:
            found = self.anchor()
            if found is not None:
                return found
            if self.env.wait(POLL_S):
                return None

    def wait_sidecar(self, seq, due):
        """The sidecar of `seq` once the capture it describes ended, or None after SIDECAR_WAIT_S or a stop."""
        while True:
            name = sidecar_names(self.raw).get(seq)
            if name is not None:
                try:
                    side = sidecar_record(self.raw / name)
                except (OSError, ValueError):
                    side = None
                if side is not None and side["seq"] == seq:
                    end = side["timestamp_unix"] + (side["total_ms"] or 0) / 1000
                    if self.env.now() >= end:
                        return {**side, "seen_unix": round(self.env.now(), 3)}
            if self.env.now() >= due + SIDECAR_WAIT_S or self.env.wait(POLL_S):
                return None

    def command(self, seq, name, command):
        out = self.dir / f"{seq:06d}_{name}.txt"
        result = self.env.guest(command, out)
        there = out.exists()
        record = {"name": name, "command": command, **result, "file": str(out),
                  "sha256": digest(out) if there else None, "bytes": out.stat().st_size if there else None,
                  "stderr_file": None}
        if result["stderr"]:
            err = out.with_suffix(".err")
            err.write_text(result["stderr"])
            record["stderr_file"] = str(err)
        return record

    def phase(self, seq, line, commands):
        for name, command in commands:
            record = self.command(seq, name, command)
            line["commands"].append(record)
            if record["exit_code"] != 0 or record["sha256"] is None:
                line.update(status="failed", why=f"{name} failed (exit code {record['exit_code']}): "
                                                 f"{record['stderr'][-300:]}")
                return False
        return True

    def sample(self, moment):
        """One moment: its line of vzorky.jsonl."""
        seq = moment["seq"]
        line = {"seq": seq, "where": moment["where"], "event": moment["event"], "status": "not_sampled", "why": None,
                "commands": [], "sidecar": None}
        anchor = self.wait_anchor()
        if anchor is None:
            line["why"] = "the session's run ended before the sampler saw a snapshot for this moment"
            return line
        if seq <= anchor["seq"]:
            line["why"] = f"the chain was at seq {anchor['seq']} when the sampler reached this moment"
            return line
        due = anchor["due_unix"] + (seq - anchor["seq"]) * self.interval
        line.update(due_unix=round(due, 3), lead_s=self.lead,
                    anchor={k: anchor[k] for k in ("name", "seq", "sha256", "due_unix")})
        start = due - self.lead
        if self.env.now() > start:
            line["why"] = (f"too late: the sampler reached the moment {self.env.now() - start:.3f} s after its start "
                           "time")
            return line
        if self.env.wait(start - self.env.now()):
            line["why"] = "the session's run ended before the moment"
            return line
        began = self.env.now()
        if not self.phase(seq, line, BEFORE):
            return line
        self.lead = min(LEAD_MAX_S, max(self.lead, self.env.now() - began + LEAD_MARGIN_S))
        line["sidecar"] = self.wait_sidecar(seq, due)
        if not self.phase(seq, line, AFTER):
            return line
        line.update(status="sampled", why=None if line["sidecar"] else
                    f"no sidecar of seq {seq} within {SIDECAR_WAIT_S:g} s of its due time")
        return line

    def stop(self):
        """Stop with the session's run; the sampler's record (vzorkovac.json) and its entry of the session record."""
        try:
            if not self.threaded:
                self._loop()
            self.env.stop()
            if self._thread.is_alive():
                self._thread.join(timeout=COMMAND_TIMEOUT_S + 30)
            if self._thread.is_alive():
                self.error = self.error or "the sampler's thread did not end"
            if self._stream is not None:
                self._stream.close()
            files = {path.name: digest(path) for path in sorted(self.dir.iterdir())
                     if path.is_file() and path.name != SUMMARY_FILE}
            sampled = [x["seq"] for x in self.lines if x["status"] == "sampled"]
            values = {"stage": g2.STAGE, "session_id": self.spec["session_id"], "vm": self.block.vm,
                      "dir": str(self.dir), "plan": {k: self.spec["draw"][k] for k in ("path", "sha256")},
                      "moments": len(self.moments), "sampled": len(sampled), "sampled_seq": sampled,
                      "not_sampled": [{k: x[k] for k in ("seq", "status", "why")} for x in self.lines
                                      if x["status"] != "sampled"],
                      "unreached": [m["seq"] for m in self.moments[len(self.lines):]], "lead_s": self.lead,
                      "error": self.error, "files": files, "rules": {"sampler": SAMPLER_RULE, "moments": MOMENTS_RULE}}
            guest = {"vm": self.block.vm, "domain": self.block.p["domain"]}
            summary = self.dir / SUMMARY_FILE
            g2.write_new(summary, header(SAMPLER_SCHEMA, self.block.command, len(self.lines), values, guest=guest))
            self.block.chown([self.dir, *self.dir.iterdir()])
            return {"hook": KIND, "dir": str(self.dir), "summary": str(summary), "sha256": digest(summary),
                    "planned": len(self.moments), "sampled": len(sampled), "error": self.error}
        except Exception as error:  # noqa: BLE001 - the session's record names it; the block goes on
            return {"hook": KIND, "dir": str(self.dir), "summary": None, "sha256": None, "planned": len(self.moments),
                    "sampled": None, "error": f"{type(error).__name__}: {error}"}


class _NotTruth:
    """The hook's answer for a session that is not of the ground truth: nothing beside it."""

    @staticmethod
    def stop():
        return {"hook": KIND, "skipped": "no ground-truth session"}


def make_hook(env_factory=Env, threaded=True):
    """The callable for skuska/g2.py Block.beside: (block, spec, paths) -> the started sampler of a ground-truth
    session (or nothing beside another one)."""
    def hook(block, spec, paths):
        if spec.get("kind") != KIND:
            return _NotTruth()
        return Sampler(block, spec, paths, env_factory(block.p), threaded=threaded).start()
    return hook


# ------------------------------------------------------------------ the comparison

def ss_rows(path):
    """[(key, line, holder pids)] of a file of ss -tuanp, the key normalized as guestparse/validate.py read_ss
    normalizes it; the header and lines read_ss does not parse are left out."""
    rows = []
    for line in Path(path).read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] == "Netid" or parts[0].upper() not in ("TCP", "UDP"):
            continue
        sa, _, sp = parts[4].rpartition(":")
        da, _, dp = parts[5].rpartition(":")
        key = (parts[0].upper(), guest_validate._norm_addr(sa), guest_validate._norm_port(sp),
               guest_validate._norm_addr(da), guest_validate._norm_port(dp))
        if None in key:
            continue
        users = re.search(r"users:\(\((.*)\)\)", line)
        rows.append((key, line, sorted({int(x) for x in re.findall(r"pid=(\d+)", users[1])}) if users else []))
    return rows


def stable_sockets(before, after, out):
    """The stable sockets of a sample (SS_STABLE_RULE) into the new file `out`: {sockets}, their number."""
    held_before = {key for key, _, pids in ss_rows(before) if pids}
    lines, keys = [], []
    text = Path(after).read_text(errors="replace").splitlines()
    head = [line for line in text if line.split()[:1] == ["Netid"]]
    for key, line, pids in ss_rows(after):
        if pids and key in held_before and key not in keys:
            lines.append(line)
            keys.append(key)
    with Path(out).open("x") as stream:
        stream.write("\n".join([*head[:1], *lines]) + "\n")
    return {"sockets": len(lines)}


def validate_argv(raw, profile, seq, files, stable, out):
    """python -m guestparse validate of one sample (COMPARE_RULE)."""
    return [sys.executable, "-m", "guestparse", "validate", "--snapshot", str(raw), "--profile", str(profile),
            "--chain-until", str(seq), "--ps-before", str(files["ps_pred"]), "--ps-after", str(files["ps_po"]),
            "--lsmod", str(files["lsmod"]), "--ss", str(stable), "--out", str(out)]


def crosscheck_argv(vmicd, sidecar, bin_bytes, out):
    """python -m features crosscheck of one full snapshot (COMPARE_RULE: --c its sidecar)."""
    return [sys.executable, "-m", "features", "crosscheck", "--snapshot", str(vmicd), "--c", str(sidecar),
            "--bin-bytes", str(bin_bytes), "--out", str(out)]


def run_child(argv, log, timeout=3600):
    """A comparison's child with collection.background_command, its output into the new file `log`; its exit code,
    None at a timeout."""
    with Path(log).open("x") as stream:
        try:
            return subprocess.run(collection.background_command(argv), cwd=ROOT, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return None


def busy_host(p, processes=collection.processes):
    """{what: [pids]} of what makes the host not quiet for a comparison (COMPARE_RULE): the collectors reading a VM
    of the protocol and the lab trials on a VM (scripts/lab_trial.py with --vm, skuska/g2.py classify reads them as
    runs) now."""
    out, trials = {}, []
    domains = [row["domain"] for row in collection.vms(p)]
    for pid, argv in processes():
        for domain in domains:
            if collection.is_collector(argv, domain):
                out.setdefault(f"collector of {domain}", []).append(pid)
        args = [arg.decode(errors="replace") for arg in argv]
        if args and "lab_trial.py" in g2.invoked(args) and g2._option(args, "--vm") is not None:
            trials.append(pid)
    if trials:
        out["lab_trial.py on a VM"] = trials
    return out


def discard(line, restored):
    """The reasons DISCARD_RULE discards a sample for (its sampler line, the restored sidecar of its seq or None);
    [] when it is compared."""
    reasons = []
    done = {c["name"]: c for c in line.get("commands", [])}
    if line.get("status") == "not_sampled":
        reasons.append(f"(a) not sampled: {line.get('why')}")
    elif line.get("status") != "sampled" or any(
            name not in done or done[name]["exit_code"] != 0 or done[name]["sha256"] is None
            for name, _ in BEFORE + AFTER):
        reasons.append(f"(a) a guest command failed or left no output: {line.get('why')}")
    if restored is None:
        reasons.append(f"(b) the chain has no snapshot of seq {line['seq']}")
        return reasons
    if not all(type(restored.get(k)) in (int, float) for k in ("timestamp_unix", "total_ms")):
        reasons.append(f"(b) the sidecar of seq {line['seq']} has no timestamp_unix or capture.total_ms")
        return reasons
    side = line.get("sidecar")
    if side is not None and side.get("sha256") != restored["sha256"]:
        reasons.append("(c) the sidecar the sampler read differs from the archive's")
    start = restored["timestamp_unix"]
    end = start + restored["total_ms"] / 1000
    for name, _ in BEFORE:
        if name in done and done[name]["end_unix"] is not None and done[name]["end_unix"] >= start:
            reasons.append(f"(d) {name} ended {done[name]['end_unix'] - start:.3f} s after the start of the capture")
    for name, _ in AFTER:
        if name in done and done[name]["start_unix"] is not None and done[name]["start_unix"] < end:
            reasons.append(f"(e) {name} started {end - done[name]['start_unix']:.3f} s before the end of the capture")
    return reasons


def profile_hashes(directory):
    directory = Path(directory)
    return {str(f.relative_to(directory)): digest(f) for f in directory.rglob("*") if f.is_file()}


def remove_restored(obnova, session_id):
    """Remove a restored copy that compare made (COMPARE_RULE), only when the marker of its raw/ names the session
    (collection_archive RESTORE_RULE); True when it is gone."""
    try:
        named = g2.read_json(Path(obnova) / "raw" / collection_archive.RESTORED).get("session_id")
    except (OSError, ValueError, AttributeError):
        return False
    if named != session_id:
        return False
    shutil.rmtree(obnova)
    return True


def compare(record_path, *, g2_dir=None, keep=False, run=run_child, restore=collection_archive.restore_raw,
            running=busy_host, command=""):
    """Compare one recorded G2 session with its ground truth on a restored copy of its archive (COMPARE_RULE): the
    path of its comparison record (porovnanie.json); Refused before anything when the session or the host does not
    allow it."""
    record_path = Path(record_path).absolute()
    try:
        record = g2.read_json(record_path)
    except (OSError, ValueError) as error:
        raise Refused(f"the record {record_path} cannot be read: {error}") from None
    if type(record) is not dict or record.get("schema") != g2.SESSION_SCHEMA:
        raise Refused(f"{record_path} is no record of a G2 session ({g2.SESSION_SCHEMA})")
    v = record["values"]
    archive = v.get("archive") or {}
    destination = Path(archive.get("destination") or "")
    if not archive or not (destination / collection_archive.MANIFEST).is_file():
        raise Refused(f"the session {v['session_id']} has no archive: the comparison reads a restored copy only")
    if digest(destination / collection_archive.MANIFEST) != archive.get("manifest_sha256"):
        raise Refused(f"the archive of {v['session_id']} differs from its record (manifest sha256)")
    manifest = g2.read_json(destination / collection_archive.MANIFEST)
    p = collection.protocol(destination / "protocol.json")
    busy = running(p)
    if busy:
        raise Refused("the host is not quiet (" + "; ".join(f"{what}: {pids}" for what, pids in busy.items())
                      + "): the comparison reads RAM images and runs only while no session captures and no lab "
                        "trial runs")
    truth = v.get("kind") == KIND
    beside = next((b for b in v.get("beside") or [] if b.get("hook") == KIND and b.get("summary")), None)
    if truth and beside is None:
        raise Refused(f"the ground-truth session {v['session_id']} has no record of its sampler")
    lines = []
    if truth:
        summary = Path(beside["summary"])
        if digest(summary) != beside["sha256"]:
            raise Refused(f"the sampler's record {summary} differs from the session record")
        files = g2.read_json(summary)["values"]["files"]
        samples = summary.parent / SAMPLES_FILE
        if digest(samples) != files.get(SAMPLES_FILE):
            raise Refused(f"{samples} differs from the sampler's record")
        lines = g2.read_samples(samples)
    session_dir = Path(v["session_dir"])
    item = manifest["files"].get("session.json") or {}
    if not item or digest(destination / "session.json") != item["sha256"] or item["sha256"] != v["session_json_sha256"]:
        raise Refused(f"the archive's session.json differs from its manifest or from the record of {v['session_id']}")
    meta = g2.read_json(destination / "session.json")
    profile = session_dir / "profile"
    if not profile.is_dir() or profile_hashes(profile) != meta.get("profile_sha256"):
        raise Refused(f"{profile} differs from session.json profile_sha256")
    events_item = manifest["files"].get("events.json")
    events = None
    if events_item is not None:
        if digest(destination / "events.json") != events_item["sha256"]:
            raise Refused(f"the archive's events.json differs from its manifest ({v['session_id']})")
        events = g2.read_json(destination / "events.json")["events"]
    places = g2.Places(g2_dir or Path(record_path).parents[1])
    work = truth_dir(places.root, v["session_id"]) / f"porovnanie_{g2.stamp()}"
    work.mkdir(parents=True)
    obnova = work / "obnova"
    try:
        restored = restore(destination, obnova / "raw", reserve_bytes=p["min_free_gib"] * 2 ** 30)
        shutil.copyfile(destination / "session.json", obnova / "session.json")
        raw = obnova / "raw"
        sidecars = {}
        for path in sorted(raw.glob("*.json")):
            side = sidecar_record(path) if SIDECAR_NAME.match(path.name) else None
            if side is not None:
                sidecars[side["seq"]] = side
        rows = []
        for line in lines:
            seq, files = line["seq"], {c["name"]: c["file"] for c in line.get("commands", [])}
            reasons = discard(line, sidecars.get(seq))
            row = {"seq": seq, "where": line["where"], "event": line["event"],
                   "sampler": {k: line.get(k) for k in ("status", "why", "due_unix", "lead_s")},
                   "sidecar": sidecars.get(seq), "discarded": reasons,
                   "commands": [{k: c[k] for k in ("name", "command", "start_unix", "end_unix", "exit_code", "file",
                                                   "sha256")} for c in line.get("commands", [])]}
            if not reasons:
                stable = work / f"{seq:06d}_ss_stabilne.txt"
                row["stable_ss"] = {"file": str(stable), **stable_sockets(files["ss_pred"], files["ss_po"], stable)}
                row["stable_ss"]["sha256"] = digest(stable)
                out = work / f"{seq:06d}_validate.json"
                argv = validate_argv(raw, profile, seq, files, stable, out)
                code = run(argv, work / f"{seq:06d}_validate.log")
                row["validate"] = {"argv": argv, "exit_code": code, "out": str(out),
                                   "sha256": digest(out) if out.is_file() else None}
            rows.append(row)
        full = []
        for seq, side in sorted(sidecars.items()):
            if side["full"] is True:
                vmicd = raw / (side["name"][:-len(".json")] + ".vmicd")
                out = work / f"crosscheck_{seq:06d}.json"
                argv = crosscheck_argv(vmicd, raw / side["name"], p["bin_bytes"], out)
                code = run(argv, work / f"crosscheck_{seq:06d}.log")
                full.append({"seq": seq, "sidecar": side, "argv": argv, "exit_code": code, "out": str(out),
                             "sha256": digest(out) if out.is_file() else None})
        restored["marker_sha256"] = digest(raw / collection_archive.RESTORED)
    except BaseException:
        if not keep:
            remove_restored(obnova, meta.get("session_id"))
        raise
    removed = False if keep else remove_restored(obnova, meta.get("session_id"))
    values = {"stage": g2.STAGE, "session_id": v["session_id"], "vm": v["vm"], "kind": v.get("kind"),
              "scenario": v["scenario"], "intensity": p["scenarios"][v["scenario"]]["intensity"],
              "record": {"path": str(record_path), "sha256": digest(record_path)},
              "excluded": v.get("excluded"), "archive": {"destination": str(destination),
                                                         "manifest_sha256": archive["manifest_sha256"]},
              "restored": {**restored, "removed": removed}, "profile": str(profile), "work": str(work),
              "events": events, "grace_s": p["events"]["grace_s"], "interval_s": p["interval_s"],
              "samples": rows, "full": full,
              "rules": {"compare": COMPARE_RULE, "discard": DISCARD_RULE, "ss_stable": SS_STABLE_RULE}}
    out = work / "porovnanie.json"
    g2.write_new(out, header(COMPARE_SCHEMA, command, len(rows) + len(full), values, guest=record.get("guest")))
    return out


# ------------------------------------------------------------------ the table

def _ps_anchor(path):
    pids = [pid for pid, name in guest_validate.read_ps(path).items() if name == "ps"]
    return pids[0] if len(pids) == 1 else None


def _between(pid, low, high):
    """pid strictly between low and high on the cycle of pids (PS_SHORT_RULE)."""
    return low < pid < high if low < high else (pid > low or pid < high)


def _verdict(differences):
    if not differences:
        return "agree"
    return "explained" if all(d["explanation"] for d in differences) else "unexplained"


def explain_processes(result, files):
    """The differences of ps (PS_STABLE_RULE) with their explanations."""
    out, truncated = [], result["traversal"]["processes_truncated"]
    low, high = _ps_anchor(files["ps_pred"]), _ps_anchor(files["ps_po"])
    for item in result["processes"]["missing_list"]:
        out.append({"kind": "missing", "item": item,
                    "explanation": "TRUNCATED_RULE: the walk of the task list did not close "
                                   f"({result['traversal']['processes_stop_reason']})" if truncated else None})
    for item in result["processes"]["false_positive_list"]:
        ok = low is not None and high is not None and _between(item["pid"], low, high)
        out.append({"kind": "false_positive", "item": item,
                    "explanation": f"PS_SHORT_RULE: pid {item['pid']} between the ps of the two runs ({low}, {high})"
                    if ok else None})
    for item in result["processes"]["name_mismatch_list"]:
        out.append({"kind": "name_mismatch", "item": item,
                    "explanation": "PS_NAME_RULE: the two runs name it differently"
                    if item["ps_before"] != item["ps_after"] else None})
    out += [{"kind": "duplicate_pid", "item": pid, "explanation": None}
            for pid in result["processes"]["duplicate_pids"]]
    return out


def explain_modules(result):
    out, truncated = [], result["traversal"]["modules_truncated"]
    for name in result["modules"].get("missing_list", []):
        out.append({"kind": "missing", "item": name,
                    "explanation": "TRUNCATED_RULE: the walk of the module list did not close "
                                   f"({result['traversal']['modules_stop_reason']})" if truncated else None})
    out += [{"kind": "extra", "item": name, "explanation": None} for name in result["modules"].get("extra_list", [])]
    return out


def explain_sockets(result, files, processes):
    """The differences of ss against the stable sockets (SS_STABLE_RULE) with their explanations."""
    def key(item):
        return (item["proto"], item["saddr"], item["sport"], item["daddr"], item["dport"])
    before, after, stable = (ss_rows(files[name]) for name in ("ss_pred", "ss_po", "ss_stable"))
    shown = {name: {k: pids for k, _, pids in rows} for name, rows in (("before", before), ("after", after))}
    listening = {(k[0], k[2]) for k, line, _ in stable if line.split()[1] in ("LISTEN", "UNCONN")}
    gone = {item["pid"] for d in processes if d["kind"] == "missing" for item in [d["item"]]}
    out = []
    for item in result["sockets"].get("missing_list", []):
        holders = set(shown["before"].get(key(item), [])) | set(shown["after"].get(key(item), []))
        out.append({"kind": "missing", "item": item,
                    "explanation": f"SS_HOLDER_RULE: its holders {sorted(holders)} are missing from the snapshot"
                    if holders and holders <= gone else None})
    for item in result["sockets"].get("extra_list", []):
        k = key(item)
        runs = [name for name in ("before", "after") if k in shown[name]]
        held = [name for name in runs if shown[name][k]]
        if item["sport"] == 0:
            why = "SS_UNBOUND_RULE: an unbound socket (local port 0), which ss does not list"
        elif len(runs) == 1 or (len(runs) == 2 and len(held) < 2):
            why = f"SS_ONE_RUN_RULE: ss shows it in {', '.join(runs)}, held in {', '.join(held) or 'neither'}"
        elif not runs and item["dport"] != 0 and ((k[0], item["sport"]) in listening
                                                  or (k[0], item["dport"]) in listening):
            why = "SS_SHORT_RULE: a connection of a port the guest listens on, shorter than the window"
        else:
            why = None
        out.append({"kind": "extra", "item": item, "explanation": why})
    return out


def during(capture, events, grace):
    """EVENT_RULE: {class, occurrence, type} of a capture [start, end] against the session's events."""
    start, end = capture
    for i, x in enumerate(events or []):
        on, off = x.get("host_started_unix"), x.get("host_stop_unix")
        if (x.get("start") or {}).get("ok") is True and on is not None and off is not None and on <= start \
                and end <= off:
            return {"class": "event", "occurrence": i, "type": x["type"]}
    for i, x in enumerate(events or []):
        if "host_start_unix" in x and "host_stopped_unix" in x and (
                x["host_start_unix"] - 1 <= start and end <= x["host_stopped_unix"] + grace):
            return {"class": "window", "occurrence": i, "type": x["type"]}
    return {"class": "outside", "occurrence": None, "type": None}


def _checked(path, sha256):
    """The JSON of a recorded file, refused when it differs from its recorded sha256."""
    if path is None or sha256 is None or not Path(path).is_file() or digest(path) != sha256:
        raise Refused(f"{path} is missing or differs from its recorded sha256")
    return g2.read_json(path)


def sample_row(c, s):
    """The row of one sample of the comparison record values `c`."""
    row = {"session_id": c["session_id"], "vm": c["vm"], "scenario": c["scenario"], "intensity": c["intensity"],
           "seq": s["seq"], "planned": s["where"], "during": None, "discarded": s["discarded"]}
    side = s["sidecar"]
    if side is not None and side.get("timestamp_unix") is not None:
        start = side["timestamp_unix"]
        row["during"] = during((start, start + (side["total_ms"] or 0) / 1000), c["events"], c["grace_s"])
    if s["discarded"]:
        return {**row, "status": "discarded"}
    files = {x["name"]: x["file"] for x in s["commands"]}
    for x in s["commands"]:
        if digest(x["file"]) != x["sha256"]:
            raise Refused(f"{x['file']} differs from its recorded sha256")
    files["ss_stable"] = s["stable_ss"]["file"]
    if digest(files["ss_stable"]) != s["stable_ss"]["sha256"]:
        raise Refused(f"{files['ss_stable']} differs from its recorded sha256")
    check = s["validate"]
    row.update(status="compared", validate={k: check[k] for k in ("out", "sha256", "exit_code")})
    if check["exit_code"] != 0 or check["sha256"] is None:
        failed = [{"kind": "comparison", "item": f"guestparse validate exit code {check['exit_code']}",
                   "explanation": None}]
        return {**row, **{name: {"verdict": "unexplained", "differences": failed} for name in ("ps", "lsmod", "ss")}}
    result = _checked(check["out"], check["sha256"])
    processes = explain_processes(result, files)
    for name, differences in (("ps", processes), ("lsmod", explain_modules(result)),
                              ("ss", explain_sockets(result, files, processes))):
        row[name] = {"verdict": _verdict(differences), "differences": differences}
    row["counts"] = {"ps": {k: result["processes"][k] for k in ("stable", "found", "snapshot")},
                     "lsmod": {k: result["modules"].get(k) for k in ("ground_truth", "matched")},
                     "ss": {k: result["sockets"].get(k) for k in ("ground_truth", "matched", "snapshot_tcp_udp")}}
    return row


def full_row(c, f):
    row = {"session_id": c["session_id"], "vm": c["vm"], "scenario": c["scenario"], "intensity": c["intensity"],
           "seq": f["seq"], "exit_code": f["exit_code"]}
    if f["exit_code"] not in (0, 1) or f["sha256"] is None:
        return {**row, "verdict": "unexplained", "why": f"features crosscheck exit code {f['exit_code']}"}
    snaps = _checked(f["out"], f["sha256"])["values"]["snimky"]
    if len(snaps) != 1:
        return {**row, "verdict": "unexplained", "why": f"crosscheck read {len(snaps)} snapshots, not 1"}
    snap = snaps[0]
    invariant, comparison = snap["invariant"] or {}, snap["porovnanie"] or {}
    agree = invariant.get("zhoda") is True and comparison.get("zhoda") is True
    return {**row, "verdict": "agree" if agree else "unexplained", "invariant": invariant.get("zhoda"),
            "comparison": comparison.get("zhoda"), "differences": comparison.get("rozdielov"),
            "c_vector": (snap.get("c_vystup") or {}).get("dostupny"), "why": None if agree else
            "the bins of the reference differ from the collector's, or no vector of the collector was read"}


def build_table(compare_paths, command=""):
    """The table of matches of the comparison records (TABLE_RULE) with check E's header."""
    rows, fulls, sources, sessions, guests = [], [], [], [], {}
    for path in compare_paths:
        doc = g2.read_json(path)
        if type(doc) is not dict or doc.get("schema") != COMPARE_SCHEMA:
            raise Refused(f"{path} is no comparison of the ground truth ({COMPARE_SCHEMA})")
        c = doc["values"]
        if c["session_id"] in sessions:
            raise Refused(f"two comparisons of the session {c['session_id']}")
        sessions.append(c["session_id"])
        sources.append({"path": str(Path(path).absolute()), "sha256": digest(path), "session_id": c["session_id"],
                        "vm": c["vm"], "kind": c["kind"], "scenario": c["scenario"]})
        guests[c["session_id"]] = doc.get("guest")
        rows += [sample_row(c, s) for s in c["samples"]]
        fulls += [full_row(c, f) for f in c["full"]]
    counts = {}
    for vm in sorted({x["vm"] for x in sources}):
        mine = [r for r in rows if r["vm"] == vm]
        compared = [r for r in mine if r["status"] == "compared"]
        high = [r for r in compared if r["intensity"] == "high"]
        during_event = [r for r in high if (r["during"] or {}).get("class") == "event"]
        full = [r for r in fulls if r["vm"] == vm]
        full_high = [r for r in full if r["intensity"] == "high"]
        # Every unexplained difference of the VM counts, at any intensity: the minimums count rate high only.
        unexplained = sum(r[name]["verdict"] == "unexplained" for r in compared for name in ("ps", "lsmod", "ss"))
        unexplained += sum(r["verdict"] == "unexplained" for r in full)
        minimums = {"compared": {"n": len(high), "min": MIN_COMPARED, "met": len(high) >= MIN_COMPARED},
                    "during_event": {"n": len(during_event), "min": MIN_DURING, "met": len(during_event) >= MIN_DURING},
                    "full_crosschecked": {"n": len(full_high), "min": MIN_FULL, "met": len(full_high) >= MIN_FULL},
                    "unexplained": {"n": unexplained, "max": 0, "met": unexplained == 0}}
        reasons = {}
        for r in mine:
            for reason in r["discarded"]:
                reasons[reason[:3]] = reasons.get(reason[:3], 0) + 1
        counts[vm] = {
            "samples": len(mine), "discarded": len(mine) - len(compared), "discarded_by_reason": reasons,
            "compared": len(compared), "compared_high": len(high),
            "during": {k: sum((r["during"] or {}).get("class") == k for r in high)
                       for k in ("event", "window", "outside")},
            "during_by_type": {t: sum(r["during"]["type"] == t for r in during_event)
                               for t in sorted({r["during"]["type"] for r in during_event})},
            "sources": {name: {k: sum(r[name]["verdict"] == k for r in compared)
                               for k in ("agree", "explained", "unexplained")} for name in ("ps", "lsmod", "ss")},
            "full": {k: sum(r["verdict"] == k for r in full) for k in ("agree", "unexplained")},
            "minimums": minimums, "met": all(m["met"] for m in minimums.values())}
    values = {"stage": g2.STAGE, "criterion": "ground_truth_under_load", "sources": sources, "counts": counts,
              "met": bool(counts) and all(x["met"] for x in counts.values()), "samples": rows, "full": fulls,
              "rules": {"table": TABLE_RULE, "event": EVENT_RULE, "discard": DISCARD_RULE,
                        "explanations": {name: globals()[name] for name in (
                            "PS_STABLE_RULE", "PS_SHORT_RULE", "PS_NAME_RULE", "TRUNCATED_RULE", "SS_STABLE_RULE",
                            "SS_ONE_RUN_RULE", "SS_SHORT_RULE", "SS_UNBOUND_RULE", "SS_HOLDER_RULE",
                            "MODULES_RULE")}}}
    return header(TABLE_SCHEMA, command, len(rows) + len(fulls), values, guest=guests)


# ------------------------------------------------------------------ the command line

def block_plan(b, specs):
    """The dry run of a block of ground-truth sessions: the checks, the commands and the moments; nothing started."""
    problems = b.checks(specs)
    group = {"name": f"g2-{b.vm}-{b.block_id}-1", "identity": {"boot_id": "<at the start of the group>"},
             "qemu": "<at the start of the group>"}
    return {"vm": b.vm, "block": b.block_id, "refusals": problems,
            "sessions": [{"session_id": s["session_id"], "id": s["id"], "scenario": s["scenario"],
                          "command": b.run_command(s, group), "moments": s["draw"]["item"]["moments"],
                          "excluded": s["excluded"]["criteria"]} for s in specs],
            "guest_commands": {name: guest_argv(b.p, text) for name, text in BEFORE + AFTER},
            "rules": {"sampler": SAMPLER_RULE, "moments": MOMENTS_RULE}}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m skuska.pozemna_pravda", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    plan = sub.add_parser("plan", help="draw the ground-truth sessions and their moments once")
    plan.add_argument("--protocol", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    block = sub.add_parser("block", help="run the ground-truth sessions of one VM with the sampler (root via sudo)")
    block.add_argument("--protocol", type=Path, required=True)
    block.add_argument("--deck", type=Path, required=True, help="the deck of G2 (skuska/g2.py Block needs it)")
    block.add_argument("--plan", type=Path, required=True)
    block.add_argument("--vm", required=True)
    block.add_argument("--only", help="these ground-truth sessions (ids, comma-separated), each as its next attempt")
    block.add_argument("--other-vm", choices=g2.OTHER_VM, required=True)
    block.add_argument("--g2-dir", type=Path, default=g2.G2_DIR)
    block.add_argument("--dry-run", action="store_true")
    comp = sub.add_parser("compare", help="compare one recorded session on a restored copy of its archive")
    comp.add_argument("--record", type=Path, required=True)
    comp.add_argument("--g2-dir", type=Path, default=g2.G2_DIR)
    comp.add_argument("--keep-restored", action="store_true")
    table = sub.add_parser("table", help="the table of matches of comparisons")
    table.add_argument("--compare", type=Path, action="append", required=True)
    table.add_argument("--out", type=Path, required=True)
    a = parser.parse_args(argv)
    line = shlex.join(["python", "-m", "skuska.pozemna_pravda", *argv])
    try:
        if a.action == "plan":
            doc = write_plan(a.protocol, a.out, line)
            print(json.dumps({"plan": str(a.out), "sessions": doc["n"], "counts": doc["values"]["counts"]}, indent=2))
            return 0
        if a.action == "compare":
            out = compare(a.record, g2_dir=a.g2_dir, keep=a.keep_restored, command=line)
            print(json.dumps({"comparison": str(out)}, indent=2))
            return 0
        if a.action == "table":
            if a.out.exists() or a.out.is_symlink():
                raise Refused(f"{a.out} exists")
            doc = build_table(a.compare, line)
            a.out.parent.mkdir(parents=True, exist_ok=True)
            g2.write_new(a.out, doc)
            print(json.dumps({"table": str(a.out), "met": doc["values"]["met"], "counts": {
                vm: x["minimums"] for vm, x in doc["values"]["counts"].items()}}, indent=2))
            return 0 if doc["values"]["met"] else 1
        b = g2.Block(a.protocol, a.deck, a.vm, other_vm=a.other_vm, places=g2.Places(a.g2_dir), command=line)
        plan_doc, plan_sha = load_plan(a.plan, b.full)
        specs = truth_specs(b, plan_doc, a.plan, plan_sha, None if a.only is None else a.only.split(","))
        if a.dry_run:
            b.deck, b.deck_sha256 = g2.load_deck(b.deck_path, b.full)
            result = block_plan(b, specs)
        else:
            b.beside.append(make_hook())
            result = b.run(specs)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get("refusals") or result.get("stopped") else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"skuska.pozemna_pravda: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
