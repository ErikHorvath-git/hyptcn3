"""The worst case of time of stage G2: the driver of two VMs, its four pairs and their judgment (protocol v5,
package H1b4).

    python -m skuska.cas plan  --protocol P --out PLAN.json
    python -m skuska.cas block --protocol P --deck DECK.json --plan PLAN.json [--only cas1,cas3] [--g2-dir DIR]
                               [--dry-run]

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H4, criterion worst_case_timing,
section 3: 2 modes x at least 2 sessions), the map dokazy/G2/mapa.md (row 10, points A, B, D and E, its questions 13
to 15) and the lead's answers Q58 (question 13: both definitions written before the runs and both in the report, 2
pairs per mode with zataz_pamate across seq 360, the VMs swapped in the shifted pairs), Q59 (question 14: the rule of
Q29 stays, the report shows the maximum of the other error-free runs beside it and names the case where the worst
case sets the maximum), Q60 (question 15: these sessions have no induced fault, so they are error-free runs) and Q69
(H1b). skuska/ is no directory of scripts/collection.py MEASUREMENT_DIRS: the driver runs the measurement code's own
commands as children and imports collection.background_command (through skuska/g2.py Block.audit_command),
campaign.audit_lock, collection_archive.archive_session and campaign_grids unchanged.

plan writes, once and before the first pair, the plan of the 4 pairs (PAIRS_RULE, SESSIONS_RULE). block runs, as root
through one pcc-sudo call (ROOT_RULE), the pairs that are not done (a pair record with done true) or those --only
names, each as its next attempt, on both VMs (BLOCK_RULE): every session through the steps of skuska/g2.py Block (the
group start of campaign.start_steps, the run of RUN_RULE with the load sampler beside it, labctl levels, the audit as
campaign.audit_capture runs it, the archive of collection_archive.archive_session, the session's record), timed by
TIMING_RULE, judged by MODES_RULE and WINDOWS_RULE and started again by RESTART_RULE. The record of an attempt is
<g2-dir>/cas/<pair>-<attempt>.json (check E's header), beside the session records in <g2-dir>/zaznamy/, whose
values.excluded names the tables of G2 that leave the session out (EXCLUDED_RULE). scripts/campaign_report.py timing
reads the session records and gives the report of the criterion with these definitions.
"""
import argparse
from contextlib import ExitStack
import json
import math
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python -m skuska.cas from another directory
    sys.path.insert(0, str(ROOT))

from scripts import campaign, campaign_grids, collection, collection_archive  # noqa: E402
from skuska import g2  # noqa: E402

KIND = "cas"  # The kind of a timing session's spec and record (skuska/g2.py values.kind).
CAS_DIR = "cas"  # <g2-dir>/cas/<pair>-<attempt>.json: the record of an attempt of a pair.
PLAN_SCHEMA = "hyptcn3/g2-timing-plan/1"
PAIR_SCHEMA = "hyptcn3/g2-timing-pair/1"
SIDECAR_SCHEMA = "vmicollect/1"
NOTE = ("Stage G2 (proposal 10.3): a test on the VMs, whose data never become a dataset. Written by python -m "
        "skuska.cas.")
AT_ONCE, SHIFTED = "at_once", "shifted"  # The skeleton's "plné snímky naraz aj posunuté".
NEITHER = "neither"  # MODES_RULE: full cycles overlap, but not the targets.
FIRST, SECOND, TOGETHER = "first", "second", "together"  # The roles of the sessions of a pair.
# Map row 10: zataz_pamate across seq 360 needs three events (events.per_session [0, 3] means 0 or 3).
EVENTS = ({"type": "naprazdno", "start_s": 300, "duration_s": 120},
          {"type": "zataz_pamate", "start_s": 1680, "duration_s": 300},
          {"type": "naprazdno", "start_s": 2460, "duration_s": 120})
LOAD = "zataz_pamate"
LOAD_MARGIN_S = 60  # The load holds at least this long before and after the target's nominal time.
EXCLUDED = ("event_effects", "marked_rows_per_event", "invalid_rows.max")
# TIMING_RULE.
LEAD_S = 60.0
POST_MAX_S = 300.0
LEVELS_MAX_S = 60.0
AUDIT_EST_S = 1800.0
SETTLE_S = 5.0
# RESTART_RULE.
GO_SHARE = 0.5
MAX_ATTEMPTS = {AT_ONCE: 8, SHIFTED: 3}
POLL_S = 1.0  # The driver reads raw/ and its runs this often.
JOIN_S = 600.0  # A stopped run: campaign.run_child's grace of 150 s and its group kills, with a margin.

SESSIONS_RULE = (
    "Q58 asks 2 pairs per mode, so 4 pairs; a pair is one session on each VM whose measured phases overlap, as "
    "campaign_grids.grid_pairs pairs the sessions of a campaign; so 8 sessions, 4 on each VM, and 2 more for every "
    "attempt a pair starts again (RESTART_RULE). No session serves two pairs: the two full snapshots of an at-once "
    "pair coincide only when its two sessions start together, and in a shifted pair the first session ends, and is "
    "audited and archived, while the second collects its target full snapshot; a session shared by two pairs would "
    "have to be audited and archived while its own VM collects the next pair's session, which the campaign never "
    "does (scripts/campaign.py execute: a VM's session is audited and archived before that VM's next capture), and a "
    "missed pair could not be run again alone")
PAIRS_RULE = (
    "Q58 and map row 10, written before the runs: the pairs cas1 to cas4 in this order; every session of a pair runs "
    "the events of map row 10 (naprazdno at 300 s for 120 s, zataz_pamate at 1680 s for 300 s, naprazdno at 2460 s "
    "for 120 s, given as --events, which collection.diagnostic_events admits), so zataz_pamate holds across seq "
    "full_every (360, nominally 1800 s into the measured phase), the target full snapshot of every session; cas1 and "
    "cas2 at once, cas3 and cas4 shifted, with the VMs swapped: in cas3 VM b (the second session) collects during the "
    "audit and archive of VM a's session (the first), in cas4 VM a during VM b's, so each VM collects once during the "
    "other's; cas3 plans the full snapshot into the audit and cas4 into the archive (the executor's judgment: the two "
    "loads differ, the audit's hashing and extraction against the archive's zstd and its copy to the HDD); the "
    "scenarios are the protocol's two of intensity high (rate high, the heaviest load of the plan) in the order of "
    "skuska/g2.py scenario_cycle, the first in cas1 and cas3, the second in cas2 and cas4, on both VMs of the pair, so "
    "each profile is in each mode once (the executor's judgment); a session's traffic seed is skuska/g2.py deck_seed "
    "with the group G2/<pair>, the VM's index in the protocol's vms and attempt 1, a group no stream of the plan, the "
    "deck, the controls or the ground truth has; an attempt started again keeps its seed")
MODES_RULE = (
    "Q58, both definitions written before the runs: a full cycle is [timestamp_unix, timestamp_unix + "
    "capture.total_ms / 1000] of a sidecar of the session (raw/<domain>_<seq>_<time>.json, schema vmicollect/1) "
    "with output.full true, at the seqs that are multiples of full_every; at once (naraz): the cycles of the target "
    "full snapshots of the two sessions (seq full_every of both) overlap in time, the later starting before the "
    "earlier ends; shifted (posunuté): no full cycle of one session overlaps a full cycle of the other; a pair whose "
    "full cycles overlap elsewhere but not at the targets is in neither mode (recorded as neither); the shift of "
    "the full snapshots is the start of VM b's cycle minus the start of VM a's, for the target cycle of the pair's "
    "collecting session (in an at-once pair VM a's) and the full cycle of the other session nearest to it; the shift "
    "of the grids is campaign_grids.grid_pairs' shift_s of the two sessions (the grid phase of b's audit minus a's, "
    "modulo interval_s); both shifts go into the pair's record and the report")
WINDOWS_RULE = (
    "written before the runs: the zataz_pamate window of a session is [host_started_unix, host_stop_unix] of its "
    "occurrence of zataz_pamate in events.json whose start succeeded (start.ok true, as skuska/pozemna_pravda.py "
    "EVENT_RULE reads 'during an event'); the audit window of a session is [started_unix, ended_unix] of its audit "
    "step, the archive window that of its archive step; a full snapshot fell into a window when its whole cycle lies "
    "inside it; an attempt meets its plan when it meets its mode and its target full snapshots fall into their own "
    "sessions' zataz_pamate windows (both in an at-once pair, the second's in a shifted pair), and in a shifted pair "
    "the second's also into the first session's audit and archive, from the audit's start to the archive's end "
    "(where it fell, audit or archive, is recorded); and a session that LOAD_RULE does not count (a heavy process in "
    "its measured phase) leaves its attempt not done")
TIMING_RULE = (
    "the timing of an attempt, from the sidecars as they appear: the groups of both sessions are started first (as "
    "the campaign starts one); at once: both runs start at T0, SETTLE_S after both groups are ready, VM b's run "
    "delay_s after VM a's (before it when negative; RESTART_RULE sets delay_s), their levels, audits and archives "
    "follow in the order the runs ended, one audit or archive at a time (campaign.audit_lock); shifted: the first "
    "run starts at once, the second at due0(first) + (cycles - full_every) x interval_s + POST_MAX_S + LEVELS_MAX_S "
    "+ LEAD_S (+ AUDIT_EST_S when the archive is the target) - pre(first), where due0 is the due time of seq 0 "
    "(timestamp_unix - sched.lateness_s of its sidecar) and pre the time from the run's start to its due0, so the "
    "second's target full snapshot falls about LEAD_S after the earliest moment the first's audit (or archive) can "
    "start; the first session's levels as soon as its run ended, then its audit (or, after the audit, its archive) "
    "not before due0(second) + full_every x interval_s - LEAD_S, the rest as the campaign runs it (the audit and "
    "the archive one after the other under campaign.audit_lock); the second session's levels, audit and archive as "
    "soon as its run ended. POST_MAX_S 300 (the run's end after its last cycle: the drain, capture.json, the guest's "
    "evidence), LEVELS_MAX_S 60, LEAD_S 60, SETTLE_S 5 and AUDIT_EST_S 1800 are the executor's judgment; the audits "
    "of campaign v6 took about 13 to 78 min, median about 20 min (docs/MERANIA.md, 2026-10-26), so a longer audit "
    "puts the full snapshot into the audit, which the record says")
RESTART_RULE = (
    "written before the runs: (1) at once: as soon as both seq-0 sidecars are there the driver judges their full "
    "cycles: they overlap by at least GO_SHARE (0.5) of the shorter cycle, so the target cycles, on the same grids "
    "30 min later, overlap too, and the attempt goes on; else both runs are stopped at once (SIGTERM through "
    "campaign.run_child's guard, as the campaign stops a capture), each stopped session archived without an audit "
    "under campaign.audit_lock (as campaign.archive_capture archives an incomplete capture) and recorded, and the "
    "pair starts again with delay_s minus the measured shift of the seq-0 cycles (the start of b's minus a's), which "
    "takes back the difference of the two runs' preflights; (2) an attempt that ran to its end and does not meet "
    "its plan (MODES_RULE, WINDOWS_RULE) starts again in full; (3) at most MAX_ATTEMPTS attempts per pair (8 at "
    "once, 3 shifted), then the block stops by name; (4) a run that exits non-zero, a refusal of skuska/g2.py "
    "REFUSALS, a failed group start, an audit without a verdict or with another provenance and every other error "
    "of the driver's steps stop the block by name after the records: a finding, never a restart")
ROOT_RULE = (
    "map point D: one pcc-sudo call runs python -m skuska.cas block as root from the VM owner's account, from "
    "/home/eh/projects/hyptcn3; what needs root: scripts/collection.py run (the eBPF collector; run_session refuses "
    "without root, and the generator and the monitor run under it as root), the audit's systemd scope "
    "(collection.background_command adds systemd-run --scope with MemoryHigh=3G, MemorySwapMax=0, CPUWeight=20 and "
    "IOWeight=20 only as root, so without root the audit would not run as the campaign runs it), the stop of a run "
    "by RESTART_RULE (campaign.run_child signals its child, a root process, and the child's process group), and the "
    "lock files under data/collections that root runs created; labctl (the group start, levels) and the audit itself "
    "run as the owner through collection.user_command (runuser), the archive in the driver's process as in the "
    "campaign's runner, its zstd at collection.BACKGROUND_NICE")
EXCLUDED_RULE = (
    "the lead's answers Q49 and Q51 (map questions 4 and 6): the sessions of H4 count for neither invalid_rows.max "
    "nor event_effects, and marked_rows_per_event is the code of row 14; a timing session's record names the three "
    "in values.excluded (skuska/g2.py, the key of package H1b1); Q60 counts these sessions as error-free runs, so "
    "they stay in audit.collector_majflt_max (Q59: Q29's rule stays) and audit.warnings_allowed, and no other table "
    "of G2 leaves them out")
UNAUDITED_RULE = ("RESTART_RULE (1): a run stopped by the rule is archived without an audit, as "
                  "campaign.archive_capture archives an incomplete capture")
BLOCK_RULE = (
    "package H1b4: before the block the plan as its rule draws it, the deck of skuska/g2.py, the rates of the high "
    "scenarios in the protocol, and per VM the refusals of skuska/g2.py Block.checks (gates.require G1, the audit "
    "self-test, measurement code equal to the commit, no heavy process and no run outside the plan), root, the "
    "deployed guest equal to lab/ and both VMs' collection locks, which the block holds; before every attempt the "
    "measurement code of the block's start and no heavy process (skuska/g2.py frozen and quiet); every attempt as "
    "TIMING_RULE times it, its two session records and its record, judged by MODES_RULE and WINDOWS_RULE, started "
    "again by RESTART_RULE")


class Refused(g2.Refused):
    """A plan or a block the rules refuse before anything is done."""


class Restart(InterruptedError):
    """RESTART_RULE (1): the driver stops a run of an at-once attempt whose seq-0 cycles do not overlap."""


class Clock:
    """Real time for the driver; a test gives a fake with the same two methods."""

    @staticmethod
    def now():
        return time.time()

    @staticmethod
    def sleep(seconds):
        time.sleep(seconds)


# ------------------------------------------------------------------ the plan

def argument():
    """The --events of every timing session (map row 10)."""
    return json.dumps([dict(x) for x in EVENTS])


def high_scenarios(p):
    """The protocol's scenarios of intensity high, in the order of skuska/g2.py scenario_cycle."""
    return [name for name in g2.scenario_cycle(p) if p["scenarios"][name]["intensity"] == "high"]


def draw_plan(p):
    """The plan of the protocol `p` (PAIRS_RULE): {vms, events, argument, target_seq, pairs}; ValueError by name when
    the protocol cannot hold it."""
    vms = [row["name"] for row in p.get("vms", [])]
    if len(vms) != 2:
        raise ValueError("the worst case of time needs a protocol with two VMs")
    high = high_scenarios(p)
    if len(high) != 2:
        raise ValueError(f"the plan takes the protocol's two scenarios of intensity high, not {len(high)}")
    text = argument()
    events = collection.diagnostic_events(p, text, p["cycles"])
    target = p["full_every"]
    if not 0 < target < p["cycles"]:
        raise ValueError(f"the target full snapshot, seq full_every {target}, lies outside the session")
    nominal = target * p["interval_s"]
    load = [x for x in events if x["type"] == LOAD]
    if len(load) != 1 or not (load[0]["start_s"] + LOAD_MARGIN_S <= nominal
                              <= load[0]["start_s"] + load[0]["duration_s"] - LOAD_MARGIN_S):
        raise ValueError(f"{LOAD} does not hold across seq {target} ({nominal:g} s) with {LOAD_MARGIN_S} s on each "
                         "side")
    pairs = []
    for pid, mode, k, order, aim in (("cas1", AT_ONCE, 0, vms, None), ("cas2", AT_ONCE, 1, vms, None),
                                     ("cas3", SHIFTED, 0, vms, "audit"), ("cas4", SHIFTED, 1, vms[::-1], "archive")):
        roles = [TOGETHER, TOGETHER] if mode == AT_ONCE else [FIRST, SECOND]
        pairs.append({"id": pid, "mode": mode, "scenario": high[k], "order": list(order), "target": aim,
                      "sessions": [{"vm": vm, "role": role, "seed": g2.deck_seed(p, "traffic", f"G2/{pid}",
                                                                                 vms.index(vm), 1)}
                                   for vm, role in zip(order, roles)]})
    return {"vms": vms, "events": events, "argument": text, "target_seq": target, "pairs": pairs}


def write_plan(protocol_path, out, command):
    """Draw the plan of the protocol file and write it to the new file `out` (refused when it exists)."""
    from scripts import gates  # Inside the function, as scripts/collection.py does: gates imports collection.
    out = Path(out).absolute()
    if out.exists() or out.is_symlink():
        raise Refused(f"the plan {out} exists: it is drawn once and never changed")
    p = collection.protocol(protocol_path)
    plan = draw_plan(p)
    values = {"stage": g2.STAGE, "protocol": str(Path(protocol_path).absolute()),
              "protocol_sha256": g2.digest(protocol_path),
              "protocol_g0_binding": gates.stage_sha256(protocol_path, "G0"), **plan,
              "constants": constants(),
              "rules": {"sessions": SESSIONS_RULE, "pairs": PAIRS_RULE, "modes": MODES_RULE, "windows": WINDOWS_RULE,
                        "timing": TIMING_RULE, "restart": RESTART_RULE, "root": ROOT_RULE, "excluded": EXCLUDED_RULE}}
    doc = g2.header(PLAN_SCHEMA, command, len(plan["pairs"]), values)
    out.parent.mkdir(parents=True, exist_ok=True)
    g2.write_new(out, doc)
    return doc


def constants():
    return {"lead_s": LEAD_S, "post_max_s": POST_MAX_S, "levels_max_s": LEVELS_MAX_S, "audit_est_s": AUDIT_EST_S,
            "settle_s": SETTLE_S, "go_share": GO_SHARE, "max_attempts": MAX_ATTEMPTS, "load_margin_s": LOAD_MARGIN_S}


def load_plan(path, p):
    """(the plan file at `path`, its sha256), refused unless it is the plan its rule draws from `p`."""
    try:
        doc = g2.read_json(path)
    except (OSError, ValueError) as error:
        raise Refused(f"the plan {path} cannot be read: {error}") from None
    if type(doc) is not dict or doc.get("schema") != PLAN_SCHEMA or type(doc.get("values")) is not dict:
        raise Refused(f"{path} is no plan of the worst case of time ({PLAN_SCHEMA})")
    expected = draw_plan(p)
    for key in ("pairs", "events", "argument", "target_seq"):
        if doc["values"].get(key) != expected[key]:
            raise Refused(f"the plan {path} differs from the plan its rule draws from this protocol ({key}): it is "
                          "drawn once and never changed")
    return doc, g2.digest(path)


# ------------------------------------------------------------------ the definitions (MODES_RULE, WINDOWS_RULE)

def _seconds(value):
    return type(value) in (int, float) and math.isfinite(value)


def cycle(doc):
    """{seq, full, start, end, total_ms, lateness_s, due} of a sidecar (MODES_RULE); ValueError by name for one without
    its times."""
    try:
        seq, full = doc["seq"], doc["output"]["full"]
        start, total, late = doc["timestamp_unix"], doc["capture"]["total_ms"], doc["sched"]["lateness_s"]
    except (KeyError, TypeError):
        raise ValueError("a sidecar without seq, output.full, timestamp_unix, capture.total_ms or sched.lateness_s") \
            from None
    if type(seq) is not int or type(full) is not bool or not all(map(_seconds, (start, total, late))) or total < 0:
        raise ValueError(f"a sidecar of seq {seq!r} whose seq, output.full or times are malformed")
    return {"seq": seq, "full": full, "start": float(start), "end": round(start + total / 1000, 6),
            "total_ms": float(total), "lateness_s": float(late), "due": round(start - late, 6)}


def sidecar(raw, seq):
    """The sidecar of `seq` in the directory `raw` (its name {domain}_{seq:06d}_{time}.json), or None while there is
    none (one written in part is none yet); ValueError for two."""
    docs = []
    for path in sorted(Path(raw).glob(f"*_{seq:06d}_*.json")):
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if type(doc) is dict and doc.get("schema") == SIDECAR_SCHEMA and doc.get("seq") == seq:
            docs.append(doc)
    if len(docs) > 1:
        raise ValueError(f"{raw}: {len(docs)} sidecars of seq {seq}")
    return docs[0] if docs else None


def full_cycles(raw, full_every, cycles):
    """{seq: the cycle} of the sidecars of the full snapshots in `raw` (None for a seq without one); ValueError for a
    sidecar at such a seq that is no full snapshot."""
    out = {}
    for seq in range(0, cycles, full_every):
        doc = sidecar(raw, seq)
        c = None if doc is None else cycle(doc)
        if c is not None and not c["full"]:
            raise ValueError(f"{raw}: the sidecar of seq {seq} is no full snapshot")
        out[seq] = c
    return out


def overlap_s(a, b):
    """The time the two cycles share (above 0: they overlap)."""
    return min(a["end"], b["end"]) - max(a["start"], b["start"])


def inside(c, window):
    """The whole cycle `c` lies in `window` [start, end] (WINDOWS_RULE)."""
    return (c is not None and window is not None and window[0] is not None and window[1] is not None
            and window[0] <= c["start"] and c["end"] <= window[1])


def load_window(events):
    """[host_started_unix, host_stop_unix] of the one occurrence of zataz_pamate whose start succeeded (WINDOWS_RULE),
    else None."""
    rows = [e for e in ((events or {}).get("events") or []) if type(e) is dict and e.get("type") == LOAD
            and type(e.get("start")) is dict and e["start"].get("ok") is True]
    if len(rows) != 1:
        return None
    window = [rows[0].get("host_started_unix"), rows[0].get("host_stop_unix")]
    return window if all(map(_seconds, window)) and window[0] <= window[1] else None


def step_window(steps, name):
    """[started_unix, ended_unix] of the step `name` (audit or archive) of a session record's steps, else None."""
    found = [s for s in steps or [] if type(s) is dict and s.get("step") == name]
    if not found:
        return None
    window = [found[-1].get("started_unix"), found[-1].get("ended_unix")]
    return window if all(map(_seconds, window)) else None


def judge(pair, sessions, target_seq):
    """MODES_RULE and WINDOWS_RULE for an attempt of `pair` that ran to its end. `sessions` holds, per VM, its full
    cycles ({seq: cycle or None}) and the windows load, audit and archive ([start, end] or None). Returns {mode
    (measured), met_mode, met, why, collecting, target, nearest, shift_full_s, overlaps, windows}."""
    a_vm, b_vm = sorted(pair["order"])
    full = {vm: [c for c in sessions[vm]["full"].values() if c is not None] for vm in (a_vm, b_vm)}
    overlaps = [{a_vm: x["seq"], b_vm: y["seq"], "overlap_s": round(overlap_s(x, y), 6)}
                for x in full[a_vm] for y in full[b_vm] if overlap_s(x, y) > 0]
    targets = [sessions[vm]["full"].get(target_seq) for vm in (a_vm, b_vm)]
    together = None not in targets and overlap_s(*targets) > 0
    measured = AT_ONCE if together else SHIFTED if not overlaps else NEITHER
    collecting = a_vm if pair["mode"] == AT_ONCE else pair["order"][1]
    other = b_vm if collecting == a_vm else a_vm
    target = sessions[collecting]["full"].get(target_seq)
    nearest = min(full[other], key=lambda c: abs(c["start"] - target["start"]), default=None) if target else None
    why, shift = [], None
    if target is None:
        why.append(f"VM {collecting} has no sidecar of the target full snapshot, seq {target_seq}")
    if target is not None and nearest is not None:
        starts = {collecting: target["start"], other: nearest["start"]}
        shift = round(starts[b_vm] - starts[a_vm], 6)
    windows = {"load": {vm: inside(sessions[vm]["full"].get(target_seq), sessions[vm]["load"])
                        for vm in pair["order"]}}
    met_mode = measured == pair["mode"]
    if pair["mode"] == AT_ONCE:
        if not met_mode:
            why.append(f"the target full cycles (seq {target_seq}) of VM {a_vm} and VM {b_vm} do not overlap")
        why += [f"the target full snapshot of VM {vm} lies outside its {LOAD} window"
                for vm, ok in windows["load"].items() if not ok]
        met = met_mode and all(windows["load"].values())
    else:
        first = pair["order"][0]
        if not met_mode:
            why.append("a full cycle of one session overlaps a full cycle of the other")
        audit, archive = sessions[first]["audit"], sessions[first]["archive"]
        both = [audit[0], archive[1]] if audit and archive else None
        windows.update(audit=inside(target, audit), archive=inside(target, archive),
                       audit_and_archive=inside(target, both))
        if not windows["load"][collecting]:
            why.append(f"the target full snapshot of VM {collecting} lies outside its {LOAD} window")
        if not windows["audit_and_archive"]:
            why.append(f"the target full snapshot of VM {collecting} lies outside the audit and archive of VM "
                       f"{first}'s session")
        met = met_mode and windows["load"][collecting] and windows["audit_and_archive"]
    return {"mode": measured, "planned": pair["mode"], "met_mode": met_mode, "met": met,
            "why": why, "collecting": collecting, "target": target, "nearest": nearest, "shift_full_s": shift,
            "overlaps": overlaps, "windows": windows}


def second_start(p, pair, first_due0, first_pre):
    """TIMING_RULE: the start of the second run of a shifted pair."""
    margin = POST_MAX_S + LEVELS_MAX_S + LEAD_S + (AUDIT_EST_S if pair["target"] == "archive" else 0.0)
    return first_due0 + (p["cycles"] - p["full_every"]) * p["interval_s"] + margin - first_pre


def work_start(p, second_due0):
    """TIMING_RULE: the moment the first session's audit (or archive) starts, LEAD_S before the second's target."""
    return second_due0 + p["full_every"] * p["interval_s"] - LEAD_S


# ------------------------------------------------------------------ the lab and the block of one VM

class TimingLab(g2.Lab):
    """skuska/g2.py Lab with the run's guard of RESTART_RULE passed to campaign.run_child and campaign.audit_lock
    itself (its waits recorded in the block's state directory); a test gives a fake with the same methods."""

    def __init__(self, protocol_path, p, state_dir):
        super().__init__(protocol_path, p)
        self.state_dir = Path(state_dir)
        self.stop_check = lambda: None  # Set by the driver before every child (Session.start, Driver).

    def child(self, command, log, *, timeout, lock_fd=None):
        return campaign.run_child(command, log, timeout=timeout, lock_fd=lock_fd, guard=self.stop_check)

    def audit_lock(self, log):
        return campaign.audit_lock(self.state_dir, vm=self.p["vm"])


class TimingBlock(g2.Block):
    """The steps of skuska/g2.py Block for one VM of the timing block, with the unix times of its steps."""

    def __init__(self, protocol_path, deck_path, vm, *, clock, **options):
        super().__init__(protocol_path, deck_path, vm, other_vm="g2", **options)
        self.clock = clock

    def rename(self, block_id, log_path):
        """One block id and one log for both VMs."""
        self.block_id, self.log_path = block_id, Path(log_path)
        self.block_dir = self.places.records / "bloky" / f"{self.vm}_{block_id}"

    def child(self, name, command, steps, *, timeout, lock_fd=None):
        started = self.clock.now()
        count = len(steps)
        try:
            return super().child(name, command, steps, timeout=timeout, lock_fd=lock_fd)
        finally:
            if len(steps) > count:
                steps[count].update(started_unix=round(started, 3), ended_unix=round(self.clock.now(), 3))

    def archive(self, session_dir, audit, steps):
        started = self.clock.now()
        result = super().archive(session_dir, audit, steps)
        result.update(started_unix=round(started, 3), ended_unix=round(self.clock.now(), 3))
        return result

    def archive_unaudited(self, session_dir, steps):
        """UNAUDITED_RULE: the archive of skuska/g2.py Block.archive without an audit, the reclaim with the campaign id
        g2."""
        destination = self.places.archive / self.vm / session_dir.name
        raw = session_dir / "raw"
        reclaim, started = raw.is_dir() and not raw.is_symlink(), self.clock.now()
        doc = self.lab.archive(session_dir, destination, lambda: self.lab.guard(self.places.archive, self.mount),
                               reclaim=reclaim, campaign_id=g2.CAMPAIGN_ID, audit=None,
                               reserve_bytes=self.p["min_free_gib"] * 2 ** 30, compress=g2.COMPRESSION)
        manifest = destination / collection_archive.MANIFEST
        result = {"step": "archive", "destination": str(destination), "started": g2.utc(started), "ended": g2.utc(),
                  "started_unix": round(started, 3), "ended_unix": round(self.clock.now(), 3),
                  "manifest_sha256": g2.digest(manifest) if manifest.exists() else None, "bytes": doc.get("bytes"),
                  "stored_bytes": doc.get("stored_bytes"), "reclaimed": reclaim, "compression": g2.COMPRESSION,
                  "campaign_id": g2.CAMPAIGN_ID, "audit": None, "rule": UNAUDITED_RULE}
        steps.append(result)
        return result


# ------------------------------------------------------------------ one session of an attempt

class Session:
    """One session of an attempt: skuska/g2.py Block.session's steps, split where TIMING_RULE waits."""

    def __init__(self, driver, block, spec, role):
        self.driver, self.block, self.spec, self.role, self.vm = driver, block, spec, role, block.vm
        self.dir = block.base / spec["session_id"]
        self.paths = {"session": self.dir, "load": block.places.load / f"{spec['session_id']}.jsonl"}
        self.steps, self.besides, self.text = [], [], ""
        self.group = self.command = self.levels = self.audit = self.archived = None
        self.stop = self.error = self.failure = None
        # The reason the guard stops the run (RESTART_RULE (1), or the other run of an at-once attempt that ended
        # without its seq-0 sidecar), and whether it is a restart of RESTART_RULE (1).
        self.halt, self.restart, self.finished = None, False, False
        self.thread = self.started = self.ended = None

    def prepare(self, environment):
        """Step 0 of skuska/g2.py: the group (campaign.start_steps when a new one is needed) and the run's command."""
        self.group = self.block.ensure_group(environment)
        self.command = self.block.run_command(self.spec, self.group)

    def start(self):
        """Step 1: the run (RUN_RULE) in a thread of its own, the hooks of Block.beside beside it."""
        self.group["sessions"] += 1
        self.block.lab.stop_check = self.guard
        self.started = self.driver.clock.now()
        self.block.log(f"session {self.spec['session_id']} ({KIND} {self.spec['id']}, {self.role}, "
                       f"{self.spec['scenario']}): run")
        self.thread = self.driver.spawn(self._run)

    def guard(self):
        """The guard campaign.run_child calls every 2 s: the block's interrupt, then the halt of the run."""
        if self.driver.stop.is_set():
            raise InterruptedError("the timing block was interrupted")
        if self.halt is not None:
            raise Restart(self.halt)

    def _run(self):
        started = []
        try:
            for hook in self.block.beside:
                started.append(hook(self.block, self.spec, self.paths))
            p = self.block.p
            _, self.text = self.block.child("run", self.command, self.steps, lock_fd=self.block.lock_fd,
                                            timeout=p["warmup_s"] + self.block.cycles * p["interval_s"] + 300)
        except BaseException as exc:  # noqa: BLE001 - the main thread reads it: Restart, an interrupt or an error
            self.failure = exc
        finally:
            self.besides = [hook.stop() for hook in started]
            self.ended = self.driver.clock.now()

    def ran(self):
        return self.thread is not None or self.started is not None

    def alive(self):
        return self.thread is not None and self.thread.is_alive()

    def exit_code(self):
        run = self.steps[0] if self.steps and self.steps[0]["step"] == "run" else None
        return None if run is None else run["exit_code"]

    def failed(self):
        """The run ended with an error, an interrupt or an exit code other than 0 (not a halt of the driver)."""
        if self.alive() or not self.ran() or self.halt is not None:
            return False
        return self.failure is not None or self.exit_code() != 0

    def full(self, seq):
        doc = sidecar(self.dir / "raw", seq)
        return None if doc is None else cycle(doc)

    def finish(self, before_audit=None, before_archive=None):
        """Steps 2 to 4 after the run: labctl levels, then the audit and the archive under campaign.audit_lock, with
        TIMING_RULE's waits; a run stopped by RESTART_RULE archived without an audit (UNAUDITED_RULE); a refusal of
        REFUSALS, an interrupt or an error recorded, nothing after it."""
        if not self.ran():
            return
        if self.halt is not None:
            if (self.dir / "session.json").exists():
                with self.block.lab.audit_lock(self.block.log):
                    self.archived = self.block.archive_unaudited(self.dir, self.steps)
            self.error = ("Restart: " if self.restart else "Stopped: ") + self.halt
            self.finished = True
            return
        if isinstance(self.failure, InterruptedError):
            self.stop = self.error = f"{type(self.failure).__name__}: {self.failure}"
            return
        if self.failure is not None:
            self.error = f"{type(self.failure).__name__}: {self.failure}"
            self.stop = "error: " + self.error
            return
        self.stop = g2.refusal_in(self.text)
        if self.stop is not None:
            return
        step, text = self.block.child("levels", self.block.levels_command(), self.steps, timeout=g2.LEVELS_TIMEOUT_S)
        self.levels = next((json.loads(line) for line in reversed(text.splitlines()) if g2._json_object(line)), None)
        step["levels"] = self.levels
        if not (self.dir / "session.json").exists():
            return
        if before_audit is not None:
            before_audit()
        with self.block.lab.audit_lock(self.block.log):
            self.audit = self.block.audit(self.dir, self.steps)
            if before_archive is not None:
                before_archive()
            self.archived = self.block.archive(self.dir, self.audit, self.steps)
        self.finished = True

    def record(self):
        """The session's record of skuska/g2.py (SESSION_SCHEMA) in <g2-dir>/zaznamy/."""
        end = self.dir / "end.json"
        measured = g2.read_json(end) if end.exists() else {}
        summary = g2.load_summary(g2.read_samples(self.paths["load"]), measured.get("measure_start_unix"),
                                  measured.get("measure_end_unix"), interval=self.block.interval,
                                  **self.block.context(self.spec))
        return self.block.record(self.spec, self.group, self.steps, self.besides, self.levels, self.audit,
                                 self.archived, summary, self.stop, self.error, self.paths)


# ------------------------------------------------------------------ the driver of both VMs

class Driver:
    """The timing block: the pairs of the plan on both VMs (BLOCK_RULE)."""

    def __init__(self, protocol_path, deck_path, plan_path, *, only=None, places=None, labs=None, clock=None,
                 command="", interval=g2.LOAD_INTERVAL_S, threads=True):
        self.protocol_path, self.deck_path, self.plan_path = (Path(x).absolute()
                                                              for x in (protocol_path, deck_path, plan_path))
        self.full = collection.protocol(self.protocol_path)
        self.vms = [row["name"] for row in self.full.get("vms", [])]
        self.places, self.clock = places or g2.Places(), clock or Clock()
        self.only, self.command, self.threads = only, command, threads
        self.stop = threading.Event()
        self.block_id = g2.stamp()
        self.dir = self.places.root / CAS_DIR
        self.state_dir = self.places.records / "bloky" / f"cas_{self.block_id}"
        self.log_path = self.places.records / f"blok_cas_{self.block_id}.log"
        self.blocks = {}
        for vm in self.vms:
            p = collection.for_vm(self.full, vm)
            lab = (labs or {}).get(vm) or TimingLab(self.protocol_path, p, self.state_dir)
            block = TimingBlock(self.protocol_path, self.deck_path, vm, clock=self.clock, places=self.places, lab=lab,
                                command=command, interval=interval)
            block.rename(self.block_id, self.log_path)
            self.blocks[vm] = block
        self.target_seq = self.full["full_every"]
        self.plan = self.plan_sha256 = None
        self.results = []

    # -------------------------------------------------- before the block

    def load(self):
        self.plan, self.plan_sha256 = load_plan(self.plan_path, self.full)
        for block in self.blocks.values():
            block.deck, block.deck_sha256 = g2.load_deck(self.deck_path, self.full)

    def pair_records(self, pid):
        """The values of the records of the attempts of pair `pid`, by attempt."""
        out = []
        for path in sorted(self.dir.glob(f"{pid}-*.json")):
            try:
                doc = g2.read_json(path)
            except (OSError, ValueError):
                continue
            if type(doc) is dict and doc.get("schema") == PAIR_SCHEMA and doc["values"].get("pair") == pid:
                out.append(doc["values"])
        return sorted(out, key=lambda v: v["attempt"])

    def selected(self):
        """The pairs of the block: those --only names (each once), else those without an attempt that is done."""
        pairs = self.plan["values"]["pairs"]
        if self.only is not None:
            ids = [pair["id"] for pair in pairs]
            unknown = [x for x in self.only if x not in ids]
            if unknown or not self.only or len(set(self.only)) != len(self.only):
                raise Refused("--only names pairs of the plan (" + ", ".join(ids) + "), each once; not of it: "
                              + ", ".join(unknown))
            return [pair for pair in pairs if pair["id"] in self.only]
        return [pair for pair in pairs if not any(v.get("done") is True for v in self.pair_records(pair["id"]))]

    def checks(self, pairs):
        """The refusals before the block that need no VM; [] when it may start."""
        problems = [] if pairs else ["every pair of the plan is done (a pair record with done true): --only runs "
                                     "one again"]
        for name in high_scenarios(self.full):
            if self.full["scenarios"][name]["rate"] is None:
                problems.append(f"the worst case runs at the protocol's rate high: scenario {name} has no rate "
                                "(Zápis 1 of G2 first)")
        for pair in pairs:
            used = len(self.pair_records(pair["id"]))
            if used >= MAX_ATTEMPTS[pair["mode"]]:
                problems.append(f"pair {pair['id']} used its {used} attempts (RESTART_RULE): the lead decides")
        for vm, block in self.blocks.items():
            mine = [{"scenario": pair["scenario"]} for pair in pairs if vm in pair["order"]]
            problems += [f"VM {vm}: {x}" for x in block.checks(mine) if not x.startswith("scenario ")]
        if not all(block.lab.is_root() for block in self.blocks.values()):
            problems.append("a block runs as root through sudo from the VM owner's account (ROOT_RULE)")
        return list(dict.fromkeys(problems))

    def spec(self, pair, item, attempt):
        """The spec of one session of an attempt (skuska/g2.py Block.session's keys, H1b1's excluded and draw)."""
        return {"kind": KIND, "id": pair["id"], "deck": None, "scenario": pair["scenario"], "seed": item["seed"],
                "events": self.plan["values"]["argument"], "attempt": attempt,
                "session_id": f"g2-{item['vm']}-{pair['id']}-{attempt}",
                "excluded": {"criteria": list(EXCLUDED), "rule": EXCLUDED_RULE},
                "draw": {"path": str(self.plan_path), "sha256": self.plan_sha256,
                         "item": {"pair": pair["id"], "mode": pair["mode"], "role": item["role"],
                                  "target": pair["target"], "order": pair["order"], "attempt": attempt}}}

    def next_attempt(self, pair):
        used = [block.attempt(pair["id"]) for block in self.blocks.values()]
        return max(used + [v["attempt"] + 1 for v in self.pair_records(pair["id"])])

    def next_delay(self, pair):
        """RESTART_RULE (1): the delay of VM b's run, from the pair's last attempt (0 at the first)."""
        done = self.pair_records(pair["id"])
        return float(done[-1]["timing"].get("next_delay_s", done[-1]["timing"].get("delay_s", 0.0))) if done else 0.0

    def plan_view(self):
        """The dry run: the checks and the commands of the next attempt of every pair; nothing started or written."""
        self.load()
        pairs = self.selected()
        rows = []
        for pair in pairs:
            k = self.next_attempt(pair)
            commands = {}
            for item in pair["sessions"]:
                block = self.blocks[item["vm"]]
                group = {"name": f"g2-{item['vm']}-{self.block_id}-1",
                         "identity": {"boot_id": "<at the start of the group>"}, "qemu": "<at the start of the group>"}
                try:
                    commands[item["vm"]] = block.run_command(self.spec(pair, item, k), group)
                except g2.Refused as error:
                    commands[item["vm"]] = str(error)
            rows.append({"pair": pair["id"], "mode": pair["mode"], "target": pair["target"], "attempt": k,
                         "scenario": pair["scenario"], "order": pair["order"], "commands": commands,
                         "delay_s": self.next_delay(pair) if pair["mode"] == AT_ONCE else None})
        return {"block": self.block_id, "refusals": self.checks(pairs), "pairs": rows, "constants": constants(),
                "rules": {"block": BLOCK_RULE, "timing": TIMING_RULE, "restart": RESTART_RULE, "root": ROOT_RULE}}

    # -------------------------------------------------- the block

    def log(self, message):
        self.blocks[self.vms[0]].log(message)

    def spawn(self, target):
        """A run in a thread of its own; a test without threads runs it here (its fakes end at once)."""
        if not self.threads:
            target()
            return None
        thread = threading.Thread(target=target, name="cas-run", daemon=True)
        thread.start()
        return thread

    def wait(self, ready, until=None):
        """ready()'s value as soon as it is true, polled every POLL_S; None once the time `until` passed;
        InterruptedError when the block was interrupted."""
        while True:
            if self.stop.is_set():
                raise InterruptedError("the timing block was interrupted")
            value = ready()
            if value:
                return value
            now = self.clock.now()
            if until is not None and now >= until:
                return None
            self.clock.sleep(POLL_S if until is None else min(POLL_S, until - now))

    def sleep_until(self, moment):
        self.wait(lambda: False, until=moment)

    def await_full(self, sessions, seq):
        """{vm: the cycle of seq} once every session has the sidecar of seq or its run ended (None then)."""
        def ready():
            out = {}
            for s in sessions:
                c = s.full(seq)
                if c is None and s.alive():
                    return None
                out[s.vm] = c
            return out
        return self.wait(ready)

    def join(self, sessions):
        self.wait(lambda: not any(s.alive() for s in sessions))

    def settle(self, sessions):
        """After an interrupt or an error: every run still going is stopped by its guard; wait JOIN_S for each."""
        self.stop.set()
        deadline = time.monotonic() + JOIN_S
        for s in sessions:
            if s.thread is not None:
                s.thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def run(self):
        """Run the block; its summary. Refused before anything starts; a stop by name is in "stopped"."""
        self.load()
        pairs = self.selected()
        problems = self.checks(pairs)
        if problems:
            raise Refused("the timing block does not start: " + " | ".join(problems))
        environment = {}
        for vm, block in self.blocks.items():
            identity = block.lab.identity()
            mismatch = collection.guest_mismatch(identity, block.lab.lab_sha256())
            if mismatch:
                raise Refused(f"the timing block does not start: the deployed guest of VM {vm} differs from lab/ of "
                              "this commit: " + ", ".join(mismatch))
            environment[vm] = campaign.guest_environment(identity)
            block.measurement = block.lab.measurement()
        first, stopped = self.blocks[self.vms[0]], None
        with ExitStack() as stack:
            for vm, block in self.blocks.items():  # Both VMs' locks: no other capture of either meanwhile.
                try:
                    block.lock_fd = stack.enter_context(block.lab.collection_lock())
                except BlockingIOError:
                    raise Refused("the timing block does not start: another capture holds the collection lock of "
                                  + block.p["domain"]) from None
            first.mkdirs([self.dir, self.state_dir / "events", self.places.load,
                          *(d for block in self.blocks.values()
                            for d in (block.block_dir / "logs", block.block_dir / "groups",
                                      self.places.archive / block.vm))])
            for block in self.blocks.values():
                block.mount = block.lab.mount(self.places.archive)
            with self.log_path.open("x") as stream:
                stream.write(f"{g2.utc()} block cas {self.block_id}: pairs {', '.join(x['id'] for x in pairs)}, plan "
                             f"{self.plan_path} {self.plan_sha256}, deck {self.deck_path}, measurement code "
                             f"{first.measurement}, command {self.command}\n")
            first.chown([self.log_path])
            interrupts = first.lab.interrupts()
            stack.callback(interrupts.restore)
            try:
                stack.callback(first.lab.inhibitor())
                for pair in pairs:
                    stopped = self.pair_loop(pair, environment)
                    if stopped:
                        break
            except (g2.Stop, InterruptedError) as error:
                stopped = f"{type(error).__name__}: {error}"
            except BaseException as error:
                self.log(f"block cas {self.block_id} stopped: {type(error).__name__}: {error}")
                raise
            finally:
                try:
                    interrupts.disarm()
                except InterruptedError:
                    pass
                first.chown(list(self.state_dir.rglob("*")))  # campaign.audit_lock's state, written as root.
        self.log(f"block cas {self.block_id} " + (f"stopped: {stopped}" if stopped else "done")
                 + f"; {len(self.results)} attempts recorded")
        return {"block": self.block_id, "log": str(self.log_path), "stopped": stopped, "attempts": self.results}

    def pair_loop(self, pair, environment):
        """The attempts of one pair until one is done; the stop by name, else None."""
        while True:
            for block in self.blocks.values():
                block.frozen()
                block.quiet()
            outcome = self.attempt(pair, environment)
            self.results.append(outcome)
            if outcome["done"]:
                self.log(f"pair {pair['id']}: attempt {outcome['attempt']} done")
                return None
            if outcome["stop"]:
                return outcome["stop"]
            used = len(self.pair_records(pair["id"]))
            if used >= MAX_ATTEMPTS[pair["mode"]]:
                return (f"pair {pair['id']} did not meet its plan in {used} attempts (RESTART_RULE): "
                        + "; ".join(outcome["why"]))
            self.log(f"pair {pair['id']}: attempt {outcome['attempt']} starts again: " + "; ".join(outcome["why"]))

    def attempt(self, pair, environment):
        """One attempt of a pair (TIMING_RULE) and its record; its outcome {pair, attempt, record, done, stop, why}."""
        k = self.next_attempt(pair)
        delay = self.next_delay(pair) if pair["mode"] == AT_ONCE else None
        sessions = [Session(self, self.blocks[item["vm"]], self.spec(pair, item, k), item["role"])
                    for item in pair["sessions"]]
        timing = {"rule": TIMING_RULE, **({"delay_s": delay} if delay is not None else {})}
        seq0 = error = None
        self.log(f"pair {pair['id']} ({pair['mode']}): attempt {k}")
        try:
            for s in sessions:
                s.prepare(environment[s.vm])
            if pair["mode"] == AT_ONCE:
                seq0 = self.at_once(sessions, delay, timing)
            else:
                self.shifted(pair, sessions, timing)
        except BaseException as exc:  # noqa: BLE001 - recorded below; an interrupt or an error stops the block
            error = exc
            self.settle(sessions)
        for s in sessions:  # A session the error left unfinished names it in its record.
            if error is not None and s.ran() and not s.finished and s.error is None:
                cause = s.failure or error
                s.error = f"{type(cause).__name__}: {cause}"
        records = [s.record() for s in sessions]
        restart = next((s.halt for s in sessions if s.restart), None)
        stop = None
        if error is not None:
            stop = f"{type(error).__name__}: {error}"
        else:
            for s in sessions:
                if s.stop is not None:
                    stop = stop or f"session {s.spec['session_id']}: {s.stop}"
                elif not s.ran():
                    stop = stop or f"session {s.spec['session_id']} did not start: {s.error or 'see the record'}"
                elif s.halt is None and s.exit_code() != 0:
                    stop = stop or (f"the run of {s.spec['session_id']} exited {s.exit_code()} (RESTART_RULE (4): a "
                                    "finding, never a restart)")
        judgment = None
        if stop is None and restart is None:
            judgment = self.judged(pair, sessions)
        counted = all(r["values"]["counted"] for r in records)
        done = bool(judgment and judgment["met"] and counted and all(r["values"]["done"] for r in records))
        why = ([restart] if restart else []) + (judgment["why"] if judgment else []) + (
            ["a session is not counted by LOAD_RULE (a heavy process in its measured phase)"]
            if judgment is not None and not counted else [])
        values = {"stage": g2.STAGE, "pair": pair["id"], "attempt": k, "mode": pair["mode"], "target": pair["target"],
                  "order": pair["order"], "scenario": pair["scenario"],
                  "sessions": {s.vm: {"session_id": s.spec["session_id"], "role": s.role, "record": r["path"],
                                      "done": r["values"]["done"], "counted": r["values"]["counted"],
                                      "run_started_unix": None if s.started is None else round(s.started, 3),
                                      "run_ended_unix": None if s.ended is None else round(s.ended, 3)}
                               for s, r in zip(sessions, records)},
                  "plan": {"path": str(self.plan_path), "sha256": self.plan_sha256}, "timing": timing,
                  "seq0": seq0, "restart": restart, "judgment": judgment, "done": done, "stop": stop, "why": why,
                  "rules": {"modes": MODES_RULE, "windows": WINDOWS_RULE, "restart": RESTART_RULE}}
        path = self.dir / f"{pair['id']}-{k}.json"
        g2.write_new(path, g2.header(PAIR_SCHEMA, self.command, len(sessions), values))
        self.blocks[self.vms[0]].chown([path])
        self.log(f"pair {pair['id']}: attempt {k} recorded, done {done}" + (f"; stop: {stop}" if stop else ""))
        if error is not None and not isinstance(error, (Exception, InterruptedError)):
            raise error  # KeyboardInterrupt and SystemExit go on after the records.
        return {"pair": pair["id"], "attempt": k, "record": str(path), "done": done, "stop": stop, "why": why}

    def at_once(self, sessions, delay, timing):
        """TIMING_RULE at once and RESTART_RULE (1); the record of the seq-0 cycles."""
        a, b = sessions
        t0 = self.clock.now() + SETTLE_S
        starts = {a.vm: t0 + max(0.0, -delay), b.vm: t0 + max(0.0, delay)}
        timing.update(t0_unix=round(t0, 3), starts_unix={vm: round(t, 3) for vm, t in starts.items()})
        for s in sorted(sessions, key=lambda s: starts[s.vm]):
            self.sleep_until(starts[s.vm])
            s.start()
        c0 = self.await_full(sessions, 0)
        seq0 = {"cycles": c0, "go_share": GO_SHARE}
        if all(c0.values()):
            ov = overlap_s(c0[a.vm], c0[b.vm])
            shorter = min(c["total_ms"] for c in c0.values()) / 1000
            shift = c0[b.vm]["start"] - c0[a.vm]["start"]
            go = ov >= GO_SHARE * shorter
            seq0.update(overlap_s=round(ov, 6), shift_s=round(shift, 6), go=go)
            timing["next_delay_s"] = round(delay - shift, 3)
            if not go:
                reason = (f"RESTART_RULE (1): the seq-0 full cycles of VM {a.vm} and VM {b.vm} overlap by {ov:.3f} s, "
                          f"less than {GO_SHARE:g} of the shorter ({shorter:.3f} s); shift {shift:+.3f} s")
                self.log(f"{reason}; both runs stop")
                for s in sessions:
                    s.halt, s.restart = reason, True
        else:  # A run ended without its seq-0 sidecar: the other cannot make a pair (RESTART_RULE (4)).
            gone = [s.vm for s in sessions if c0[s.vm] is None]
            for s in sessions:
                if c0[s.vm] is not None:
                    s.halt = f"the run of VM {', '.join(gone)} ended without its seq-0 sidecar"
        self.join(sessions)
        for s in sorted(sessions, key=lambda s: s.ended or 0.0):
            s.finish()
        return seq0

    def shifted(self, pair, sessions, timing):
        """TIMING_RULE shifted: the second run started after the first's seq 0, the first's audit or archive timed to
        the second's target full snapshot."""
        x, y = sessions
        x.start()
        cx = self.await_full([x], 0)[x.vm]
        if cx is None:
            y.error = "not started: the first session's run ended without its seq-0 sidecar"
            self.join([x])
            x.finish()
            return
        pre = cx["due"] - x.started
        start = second_start(self.full, pair, cx["due"], pre)
        timing.update(first_due0_unix=cx["due"], first_pre_s=round(pre, 3), second_start_unix=round(start, 3))
        if self.wait(x.failed, until=start):
            y.error = "not started: the first session's run ended before the second's planned start"
            x.finish()
            return
        y.start()
        cy = self.await_full([y], 0)[y.vm]
        work = None if cy is None else work_start(self.full, cy["due"])
        timing.update(second_due0_unix=None if cy is None else cy["due"],
                      work_unix=None if work is None else round(work, 3), work=pair["target"])
        self.join([x])
        hold = (lambda: self.sleep_until(work)) if work is not None else None
        x.finish(before_audit=hold if pair["target"] == "audit" else None,
                 before_archive=hold if pair["target"] == "archive" else None)
        self.join([y])
        y.finish()

    def judged(self, pair, sessions):
        """MODES_RULE and WINDOWS_RULE on the files of an attempt that ran to its end, with the shift of the grids
        (campaign_grids.grid_pairs over its two audited sessions)."""
        data = {}
        for s in sessions:
            events = s.dir / "events.json"
            data[s.vm] = {"full": full_cycles(s.dir / "raw", self.full["full_every"], self.full["cycles"]),
                          "load": load_window(g2.read_json(events) if events.exists() else None),
                          "audit": step_window(s.steps, "audit"), "archive": step_window(s.steps, "archive")}
        judgment = judge(pair, data, self.target_seq)
        grids = {"shift_s": None, "why": "a session of the attempt has no audit or no measured phase"}
        if all(s.audit for s in sessions):
            try:
                rows = [campaign_grids.grid_session(s.dir, s.audit["report"]) for s in sorted(sessions,
                                                                                              key=lambda s: s.vm)]
                found = campaign_grids.grid_pairs(rows) if None not in rows else []
            except (OSError, ValueError) as error:
                found, grids["why"] = [], f"{type(error).__name__}: {error}"
            grids = found[0] if found else grids
        judgment["grids"] = grids
        return judgment


# ------------------------------------------------------------------ the command line

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m skuska.cas", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    plan = sub.add_parser("plan", help="write the plan of the 4 pairs once (refused when the file exists)")
    plan.add_argument("--protocol", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    block = sub.add_parser("block", help="run the pairs on both VMs (as root through one pcc-sudo call)")
    block.add_argument("--protocol", type=Path, required=True)
    block.add_argument("--deck", type=Path, required=True, help="the deck of G2 (skuska/g2.py Block needs it)")
    block.add_argument("--plan", type=Path, required=True)
    block.add_argument("--only", help="these pairs (ids, comma-separated), each as its next attempt")
    block.add_argument("--g2-dir", type=Path, default=g2.G2_DIR, help="the G2 directory: zaznamy/, zataz/, session/, "
                                                                      "cas/")
    block.add_argument("--dry-run", action="store_true", help="the checks and the commands; nothing is started")
    a = parser.parse_args(argv)
    line = shlex.join(["python", "-m", "skuska.cas", *argv])
    try:
        if a.action == "plan":
            doc = write_plan(a.protocol, a.out, line)
            print(json.dumps({"plan": str(a.out), "pairs": [{k: x[k] for k in ("id", "mode", "scenario", "order",
                                                                                "target")}
                                                             for x in doc["values"]["pairs"]]}, indent=2))
            return 0
        d = Driver(a.protocol, a.deck, a.plan, only=None if a.only is None else a.only.split(","),
                   places=g2.Places(a.g2_dir), command=line)
        result = d.plan_view() if a.dry_run else d.run()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get("refusals") or result.get("stopped") else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"skuska.cas: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
