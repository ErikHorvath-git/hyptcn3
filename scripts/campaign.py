#!/usr/bin/env python3
"""Frozen benign collection campaign: reboot, capture, audit, archive, index.

init/status/request-stop/close need no root. launch/run need sudo for host
eBPF, and use the original user's libvirt session. A protocol with several VMs
has one runner per VM (run --vm, own systemd unit, status-<vm>.json); a boot
group belongs to one VM, audits and archiving are serialized over the VMs and
sessions live under data/collections/<campaign>/<vm>/. A failed capture or rejected
audit stops the allocation; retries never silently replace a research session.
Only an attempt that ended before its measured phase (no RAM image) is retried.

init --continue: one continuation of a campaign that stopped for good and was
closed (PLAN_multivm_dataset.md, chapter 8). Same protocol file, extractor,
collector and guest environment; groups the closed campaign completed are taken
over as they are, every other group is captured again as a whole in a new boot.

Protocol v5 (schema 3; package B9a, agent K: the lead's skeleton dokazy/B9/kostra/KOSTRA.md, the design
dokazy/B9/navrh/NAVRH_B9a.md section 1.3, proposal 5.4, 7.3, 7.5 and decision D12): one rule each, written into
campaign.json (RULES): the time order of the roles and of the test groups (ORDER_RULE), the plan mode (MODE_RULE), no
pilot (PILOT_RULE), the disk estimate (DISK_RULE), the stages at the start (STAGES_RULE), the replacement as a new
attempt (REPLACEMENT_RULE) and its limit (LIMIT_RULE), the start of a group (GROUP_START_RULE), the seal of an accepted
session (SEAL_RULE) and the changes the frozen tree admits (FROZEN_TREE_RULE).

Protocol v5, package B9b (agent R: the design dokazy/B9/navrh/NAVRH_B9b.md sections 1.1, 1.2 and 3, the skeleton rows
pozastavenie, jedno pokračovanie, záznam pri uzavretí, proposal 7.5, 10.4 to 10.7, 11.1 and 11.6): every ending of a
campaign writes one record into data/results (ENDING_RULE): complete, paused (PAUSE_RULE), stopped (an early stop,
EARLY_STOP_RULE; an error; an operator's stop request), invalid (INVALID_RULE) and closed; a paused campaign is
continued once (init --continue --cause, CONTINUATION_RULE); the record evaluates skeleton test 2 over the realized
boots (INTERLEAVE_RULE) and pairs the grids of the two VMs (GRID_RULE). Schemas 1 and 2 keep their endings and write
no record. The fix round of B9b (agent R: F2, F3, F6, F10 and F11 of its verification): the frozen measurement code and
lab file by file (INVALID_RULE), a complete or closed campaign that never runs again, the history in the deviations of
every record, the written cause before a resume after an early stop (RESUME_RULE), the state of a captured session not
yet judged and the entry of docs/MERANIA.md at a closing ending (ENDING_RULE).
"""
import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import fcntl
from fractions import Fraction
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import collection, protocol_v5
from scripts.collection_archive import (archive_session, digest, guard_mount, mount_identity,
                                        now, read_json, sync_dir, verify_archive, write_new)

BASE = ROOT / "data/campaigns"
COLLECTIONS = ROOT / "data/collections"
# ENDING_RULE (package B9b): the records of the endings of the campaigns of protocol schema 3, a tracked directory; the
# tests point it at a directory of their own.
RESULTS = ROOT / "data/results"
RESULTS_IN_GIT = "data/results"  # RESULTS as git status names it (FROZEN_TREE_RULE).
UNIT = "hyptcn-collection.service"
CAMPAIGN_NAME = r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}"
# Attempts of one assignment that may end before the measured phase (failed
# preflight, warmup or an operator stop there); the last one stops the campaign.
MAX_ATTEMPTS = 3
RETRY_PAUSE_S = 60
# Multi-VM: waiting for the audit lock or for earlier roles on the other VMs.
WAIT_POLL_S = 10
# Runners of one campaign are launched one after another; a runner that is not up yet is not a stopped one.
START_GRACE_S = 120

# ------------------------------------------------------------------ protocol v5 (package B9a, agent K)

ORDER_RULE = (
    "B6a F7 and PRE_B9, proposal 7.3, skeleton row poradie (wait_for_earlier_roles reads the order from the plan), F5 "
    "of the verification of B9a: the runners keep the time order of the plan across the VMs. By rank: "
    "protocol_v5.TIME_RANK, never the order of the protocol's roles: before a session of a role a runner waits until "
    "the other VMs finished every session of a role of a lower rank (ranked by the order of the roles, the runners of "
    "a plan with 4 or more groups per role deadlocked). Inside a rank, under protocol schema 3: a runner starts a "
    "group of an interleaved role (p['interleave']: test_benign and test_controls, whose boots alternate in time, "
    "proposal 7.3) only after every group of those roles that precedes it in the plan (the order of the frozen plan, "
    "the time order of protocol_v5.plan, on the other VMs) has started, that is, has its record groups/<group>.json, "
    "which start_group writes after the pretouch (a group a continuation took over counts as started); so the test "
    "groups start in the plan's order and a VM runs at most about one group ahead of the other. It cannot deadlock: "
    "the earliest group of the plan that has not started has no predecessor that has not started, and its VM reaches "
    "it once its current group ends. Both waits keep the operator's stop request and end with a reason when the other "
    "runner is not active after START_GRACE_S; the state names what the runner waits for. take_over judges a closed "
    "campaign by the same rank; schemas 1 and 2 keep the rank alone, and a protocol of schema 1 or 2 whose one role "
    "has no rank (test_events of the test-only protocols) ranks that role alone. Scope (N1 of the confirmation of "
    "B9a): the barrier orders the starts of the test groups, not their ends, so skeleton test 2 (no test_controls "
    "boot wholly after every test_benign boot) holds by construction only for a plan whose interleaved sequence ends "
    "with a test_benign group, as the campaign plan of config/collection-v5.json does (v5-test_benign-12); its "
    "rehearsal ends with g5-test_controls-2 and can break test 2 under a lag of about one group (three replacements "
    "on VM b suffice), which every ending record then shows in its deviations (INTERLEAVE_RULE). Cost and coupling "
    "(N2): the barrier adds idle time, in the verifier's model with sessions of equal length (a model, not a "
    "measurement) the v5 campaign ends after 72 instead of 66 session lengths, about 9 % longer; and stopping one "
    "runner also stops the other at its next test group that needs it (its reason: the other runner is not active)")
MODE_RULE = (
    "design B9a 1.3 item 2, skeleton row generálka: under protocol schema 3 a campaign has one plan mode, campaign or "
    "rehearsal (init --mode, required there and refused under schemas 1 and 2, no default); campaign.json records it "
    "and every plan of the campaign is protocol_v5.plan(p, mode=mode): init, load_campaign, finish_corpus and the "
    "--mode of every capture; the plan takes its name and its group prefix from protocol_v5._shape (a rehearsal: name "
    "+ rehearsal.name_suffix and rehearsal.group_prefix), and the campaign's default name ends in the plan's name")
PILOT_RULE = (
    "design B9a 1.3 item 3 (map 2.1): protocol v5 has no pilot; init neither needs nor accepts --pilot-report and no "
    "capture passes it; the guest environment of every VM is recorded at init; the swap ban stays the check before "
    "the start of every session (scripts/collection.py run, decision D13), and the host's vm.swappiness is frozen in "
    "the runtime that verify_frozen compares; schemas 1 and 2 keep the accepted pilot")
DISK_RULE = (
    "decision D12 and the skeleton's section 5 (Disk), design B9a 1.3 item 3: under protocol schema 3 one session is "
    "estimated by the largest accepted session so far, its working bytes (bytes of its archive manifest) and its "
    "archive bytes (stored_bytes), each the largest recorded in attempts/*.done.json; in mode campaign init "
    "--estimate-from seeds both with the largest accepted session of an ended rehearsal of the protocol (frozen in "
    "campaign.json as disk_estimate.seed), in mode rehearsal there is no seed, so before its first accepted session "
    "only min_free_gib is checked; the working disk must hold min_free_gib, this VM's next session and the part of "
    "every other VM's current session not written yet; the archive disk min_free_gib and the archive bytes of every "
    "session still to capture: the assignments not finished and, in mode campaign, the replacements its limit still "
    "allows (D12 counts the campaign with its replacements); init refuses a campaign that does not fit; schemas 1 and "
    "2 keep the estimate of the pilot")
STAGES_RULE = (
    "skeleton row stupne, design B9a 1.3 item 4: a campaign of mode campaign starts only on valid readiness records of "
    "G0 to G4 (scripts/gates.py require(..., 'G5')), a rehearsal on G0 to G2 (require(..., 'G3a')), each also on a "
    "passed self-test of the audit checks (scripts/audit_selftest.py require_selftest); init, launch and run check them")
REPLACEMENT_RULE = (
    "proposal 7.3, skeleton row náhrada, design B9a 1.3 item 5: replacement n of a planned session (ID <plan "
    "session>-r<n>) is attempt n + 1 of its row, drawn by protocol_v5.replacement in the campaign's mode: the same VM, "
    "role, group, position, scenario and event types or control kinds, new times and a new traffic stream; the capture "
    "passes --attempt and that attempt's seed, and check_session compares the attempt, the plan mode, the events and "
    "the controls; schemas 1 and 2 keep the same assignment and seed")
LIMIT_RULE = (
    "proposal 7.5, skeleton row limit náhrad, design B9a 1.3 item 5: in mode campaign replacement.max_per_campaign of "
    "the protocol is the limit and a null limit (determined at G3b) is refused by name at init; in mode rehearsal the "
    "limit is not applied, every rejection the rule covers is replaced, and the rejections of the campaign are counted "
    "by cause in its state (rejections_by_cause), from which G3b sets the limit; a rejection the exhausted limit "
    "refuses pauses the campaign (PAUSE_RULE, package B9b), inside a continuation it makes the campaign invalid "
    "(INVALID_RULE)")
GROUP_START_RULE = (
    "proposal 5.4 and B5a F4, skeleton row začiatok bootu, design B9a 1.3 item 6: a group of protocol schema 3 starts "
    "with labctl stop, then labctl start (way 1: a new QEMU process in the daemon's unit, whose pid and cgroup the "
    "start's qemu_swap record states with way unit and temporary false; way 2, the scope move, is refused, since it "
    "moves the process and not its memory, B5a F4), the new boot id with "
    "the frozen guest environment, then labctl reset --seed with the protocol's one seeded level "
    "(protocol_v5.reset_seed(p), the same for every group of both modes: proposal 5.4, the table of chapter 12, Q18; "
    "the guest must echo it) and labctl pretouch, each as the VM's owner and each output recorded in "
    "groups/<group>.json (start.steps, in this order); the guest identity and the QEMU process read again after the "
    "pretouch must be those after the start. A failed start of a group is no rejection of a session (question Q22 "
    "to the lead, decided by its proposal until he answers; before it, B9a's rejection with the cause group_start): "
    "no session was measured, so it is recorded as groups/<group>.start-failed-<UTC>.json with the step, the output "
    "of the steps done and the cause group_start, and the runner stops by name, which ends the campaign as stopped "
    "with the cause group_start (ENDING_RULE); nothing is replaced and nothing is charged to the limit, and no "
    "protocol may cover group_start, because collection.check_replacement admits in replacement.covers only "
    "REPLACEMENT_CAUSES (audit_rejected, capture_incomplete); a resumed run starts the group again from its "
    "beginning (stop, start, reset, pretouch) and captures its sessions as planned, as attempt 1; every failed start "
    "is listed in every later ending record (group_start_failures) and among its deviations. The levels at the start "
    "of each session are taken by scripts/collection.py run")
SEAL_RULE = (
    "skeleton row pečať, B7c PRE_B9, design B9a 1.3 item 7: right after the audit accepts a session of a sealed role "
    "(test_benign, test_controls: features/dataset.py ROLES without FIT_ROLES, which tcn/pecat.py SEALED_ROLES equals) "
    "and before its checkpoint, the runner writes it into the seal ledger as the campaign's owner "
    "(collection.user_command): python -m tcn.pecat zapis --audit <audit> --mode <mode>, which seals the record {id, "
    "role, group, vm, scenario, features, features_sha256}; nothing during a campaign replays or scores a session")
LEDGER = "data/results/kniha_pecati.json"  # tcn/pecat.py TRACKED: the seal ledger of record.
FROZEN_TREE_RULE = (
    "design B9a 1.3 item 8 and design B9b 1.1: the frozen tree admits the seal ledger " + LEDGER + " modified in "
    "place (tcn.pecat checks its content on every read) and, under protocol schema 3, the records of the endings this "
    "campaign wrote, data/results/kampan_<its id>_<ending>_<stamp>.json, new or modified, each with the sha256 its "
    "endings/ names (ENDING_RULE); HEAD stays the frozen commit and any other change refuses; git status runs under "
    "the lock of data/results (tcn/pecat.py _locked), under which the ledger and the records are written, so a write "
    "in progress is not a change; after the campaign the records and the ledger are committed and pushed together "
    "(stage final of tcn.finalne requires the ledger at HEAD)")
# ------------------------------------------------------------------ protocol v5: the endings (package B9b, agent R)

ENDING_SCHEMA = "hyptcn3/campaign-ending/1"
ENDING_RULE = (
    "design B9b 1.1 and 3, skeleton row záznam pri uzavretí, proposal 11.1, 11.3 and 11.6, and the fix round of B9b "
    "(F3, F6, F10 and F11 of its verification): under protocol schema 3 every "
    "ending of a campaign writes one record into data/results, kampan_<campaign id>_<ending>_<UTC stamp>.json of schema "
    + ENDING_SCHEMA + ", with the header of check E of scripts/check_claims.sh (commit, date, host, guest, command, "
    "n and values) and its stage (tcn.pecat record_stage over its accepted sessions with at_head false, question Q21 "
    "decided by its proposal until the lead answers: final or generalka when the ledger of record in the working "
    "tree holds every accepted session of the sealed roles, the basis naming that ledger's sha256, since the ledger "
    "is committed after the campaign and tcn.finalne checks it at HEAD when it reads the record; else suchy with its "
    "basis, a test's or the G1 dry run's own ledger, or a missing seal); the endings are complete (úplná: the runner "
    "that finds every planned session accepted writes it before the index, and finish_corpus refuses without it), "
    "paused (pozastavená, PAUSE_RULE), stopped (zastavená: an early stop, EARLY_STOP_RULE; an error the runner "
    "catches; a failed start of a group, with the cause group_start, GROUP_START_RULE and question Q22; an operator's "
    "stop request, with its reason), invalid (neplatná, INVALID_RULE) and closed (uzavretá operátorom: close, with "
    "its reason); a "
    "paused, stopped or invalid ending is pending in ending.json of the campaign directory from its first trigger, "
    "which asks every other active runner to stop at its next check (its stop-request file), and its record is "
    "written once the campaign is at rest, by the last runner to stop (or, after a crash of that runner, by the next "
    "run, launch or close of the campaign), with every trigger in order, the last state of every runner and every "
    "session as it then is; of the triggers of one ending the heavier kind holds (invalid, then paused, then "
    "stopped); an operator's stop request for one VM stops the whole campaign so; a stop-after boundary and a runner "
    "that stops because another VM's runner is not active are no ending; a stopped campaign runs again from where it "
    "stopped (today's resume; after an early stop only with its written cause, RESUME_RULE), and its next ending "
    "writes its own record (a complete ending whose index then fails is followed by a stopped one); a campaign whose "
    "last recorded ending is closed, or complete with its index built (the state complete at the stage complete of "
    "the runner that built it), does not run again: run and launch refuse it by name before verify_frozen and write no "
    "ending and no record (F3; a complete ending whose runner died before its index was built runs again to build it, "
    "the fix round's interpretation); endings/ of the campaign directory names every record with its sha256; values: "
    "the campaign, its mode, "
    "protocol and plan sha256, the ending and its cause, every planned session and attempt with its cause and "
    "replacement in one of four states (F10): accepted (its checkpoint), rejected (its rejection record), captured, "
    "not judged (its session directory without either: its runner stopped during its capture, its audit or while "
    "held at the audit lock) and not run (no session directory); "
    "planned_sessions, accepted_sessions and rejected_sessions as tcn.finalne reads "
    "them (with the rejections of the campaign a continuation continues), the rejections by cause, the limit and the "
    "replacements used, the nominal unscored seconds of every accepted session, the register of exceptions (the "
    "largest count in one accepted session and the sessions over the expected count, features/audit_policy.py "
    "exceptions_record; lead's answer to Q2), the grids (GRID_RULE), the interleave (INTERLEAVE_RULE), every failed "
    "start of a group (group_start_failures, Q22), the seed of the guest's reset named with the protocol's sha256, "
    "the deviations (F6: every earlier recorded ending of the campaign by its kind, cause, record and sha256; the "
    "continuation with its written cause, every operator's stop request a runner honored with "
    "its reason, the pause and the invalidation with their causes, a close with its reason, every unclean end a run "
    "found (its VM's state still running while the lock was free: SIGKILL, a crash, a power loss), which the run "
    "writes before it resumes as deviations/<UTC>_unclean-end_<vm>.json with that state, a deviation and not an "
    "ending, since the other VM's runner may have gone on; every written cause of a resume after an early stop "
    "(RESUME_RULE); every failed start of a "
    "group and whether it started again, a violation of the interleave with its cause) and the path and sha256 of "
    "docs/ODCHYLKY_V5.sk.md; the record of an ending that closes the campaign (complete, invalid, closed) carries in "
    "values.merania_entry the text of its entry of docs/MERANIA.md (F11, proposal 11.6: the campaign and the ending, "
    "the record's name, the planned, accepted, rejected and replaced sessions, the unscored time and the deviations, "
    "each of which also gets its entry in docs/ODCHYLKY_V5.sk.md), and the command that writes the record prints the "
    "entry with the record's sha256, which no file can hold of itself (endings/ names it as well); both go into the "
    "commit after that ending, beside the records and the ledger; schemas 1 and 2 write no record")
PAUSE_RULE = (
    "proposal 7.5, skeleton row pozastavenie, design B9b 1.2 and 3: in mode campaign a rejection that the exhausted "
    "limit of replacements refuses (LIMIT_RULE) pauses the whole campaign for analysis: its runner stops, every other "
    "active runner stops at its next check through its stop-request file, also one held in the barrier of ORDER_RULE "
    "(the paused record names what it was held for), the state of every runner is paused and the paused record counts "
    "the rejections by cause; run and launch refuse a paused campaign by name, and init --continue continues it once "
    "(CONTINUATION_RULE); in mode rehearsal the limit is not applied, so a rehearsal never pauses")
CONTINUATION_RULE = (
    "proposal 7.5, skeleton row jedno pokračovanie, design B9b 1.2: under protocol schema 3 init --continue <campaign "
    "directory> --cause TEXT continues a paused campaign once and in its mode: it needs the campaign's paused record "
    "(its last recorded ending paused, the record in data/results with the sha256 its endings/ names, no ending "
    "pending), a written cause (required, refused when empty) and the measurement code and the lab unchanged since "
    "that campaign was frozen, file by file (the maps init records, INVALID_RULE; F2 of the verification of B9b): a "
    "changed or missing file is refused by name, and so is a new file beside them, which the operator removes before "
    "trying again (a new file never makes a campaign invalid); the continuation has the same limit again, counted "
    "anew; a campaign that ended other than paused "
    "and a continuation are refused by name; its complete groups are taken over as under schemas 1 and 2 (take_over, "
    "a replacement as the attempt it was), and the groups of the continued campaign are released for its continuation "
    "only; schemas 1 and 2 keep the continuation of a closed campaign, whose close reason is its cause")
INVALID_RULE = (
    "proposal 7.5, skeleton row jedno pokračovanie, design B9b 1.2 and its fix (F2 of the verification of B9b): a "
    "campaign is invalid after a second exhaustion "
    "(a rejection the exhausted limit refuses inside a continuation) and when the measurement code or the lab changed "
    "during it: init freezes both file by file, measurement_files_sha256 (scripts/collection.py measurement_sources, "
    "beside their one hash measurement_sha256 of scripts/gates.py) and lab_sha256 (scripts/collection.py lab_sha256), "
    "and verify_frozen, before the tree, finds the campaign invalid only when a file of the frozen set changed its "
    "content or is gone; a new file beside them (an editor's swap file lab/.udalosti.py.swp, say) is a change of the "
    "tree and not of the measurement code or the lab: verify_frozen refuses the run by name, naming the new files, "
    "and the campaign runs again once they are removed; a campaign.json of protocol schema 3 without the per-file maps "
    "is refused by name; the run or launch that finds a change ends the campaign as invalid; an "
    "invalid campaign has no corpus (finish_corpus refuses it by name), never runs again and is never continued")
RESUME_RULE = (
    "HARNESS chapter 7 (a met stop rule is a stop and a question), skeleton section 5 and F6 of the verification of "
    "B9b: when the last recorded ending of a campaign of protocol schema 3 is a stopped ending with an early stop "
    "among its triggers (EARLY_STOP_RULE), run and launch are refused by name unless a written cause already "
    "answers that record, or the command carries --cause TEXT, the written analysis of the stop; that command then "
    "writes deviations/<UTC>_resume-after-early-stop_<vm>.json (without a VM for a launch of every VM): the record it "
    "answers by name and sha256, the cause, the VM and the command, and every later record lists it among its "
    "deviations; one answer serves both VMs; an empty --cause is refused by name, and so is --cause when the last "
    "recorded ending is no early stop; every other stopped ending (an operator's stop, a signal, a failed start of a "
    "group, an error) resumes with a plain run")
EARLY_STOP_RULE = (
    "proposal 7.5 and 10.9, skeleton row skoré zastavenie, design B9b 1.3 and its fix (F5 of the verification of B9b, "
    "question Q24 decided by its proposal): after every audit of a completed capture, in both modes, the runner writes "
    "marked/<session id>.json (its VM and session, audited_at, the audit's marked_rows_by_type and "
    "event_occurrences_by_type and the sha256 of the audit record; a re-audit replaces it), sums the files of every VM "
    "audited after the date of the campaign's latest recorded ending with an early-stop trigger (all of them before "
    "such an ending; a continuation has a directory of its own and counts only its own sessions: both restart points "
    "follow a written human analysis, the executor's judgment, Q24) and asks features/audit_policy.py early_stop (its "
    "EARLY_STOP_RULE, with the false-stop rates of the executor's Poisson model, a model and not a measurement: at "
    "most 1 % per comparison and type; checked after every occurrence, 0.12 to 0.28 per campaign at rates of 0.01 to "
    "3, against 0.23 to 0.88 for the count of one session); a session rejected for periodicity, or the campaign's "
    "count C_T of marked rows at an event type T above b, the 99th percentile of Poisson(rate_T x n_T) over its n_T "
    "occurrences, stops the campaign: the stopped ending, its cause naming T, C_T, n_T, the rate and b, after the "
    "session itself is sealed and checkpointed, or rejected and replaced, as always; an early stop that cannot be "
    "decided (early_stop refuses, a count file or the record of an earlier ending cannot be read, the rows of a "
    "counted session are not told by type while a rate is set) stops the campaign as an error by name, never as no "
    "stop; while a rate is null, C_T and n_T are printed in the runner's state and the campaign goes on")
INTERLEAVE_RULE = (
    "skeleton section 4 test 2 and design B9b section 3 (agent T's observation of the fix round of B9a): the barrier of "
    "ORDER_RULE orders the starts of the test groups, not their ends, so every ending record evaluates test 2 over the "
    "realized boots of test_benign and test_controls, each from the first measured start to the last measured end of "
    "its sessions (end.json measure_start_unix and measure_end_unix): late_controls are the test_controls boots that "
    "start at or after the end of every test_benign boot (none while no test_benign boot is realized); alternation "
    "is the share rule of scripts/protocol_v5.py check_role_order over the realized starts against the plan's group "
    "counts of the two roles; ok when neither finds anything; a violation is a deviation of the record with its "
    "cause. Scope (N1 of the confirmation of B9a, ORDER_RULE): test 2 holds by construction only for a plan whose "
    "interleaved sequence ends with a test_benign group, as the campaign plan of config/collection-v5.json does; the "
    "rehearsal ends with g5-test_controls-2 and can break test 2 under a lag of about one group, and its record then "
    "shows the violation in deviations; at an ending before the plan's last test group the check speaks of the boots "
    "realized so far")
GRID_RULE = (
    "skeleton row mriežky dvoch VM, design B9b 1.3 (a record only): for every pair of sessions of two VMs whose measured "
    "phases overlap, the grid phase of each collector (values.timing.grid_phase_s of its audit) and their mutual shift "
    "modulo interval_s, by scripts/campaign_grids.py grid_pairs over grid_session of every captured session (its "
    "GRID_RULE: the later VM's phase minus the earlier one's); a session whose records cannot be read is named in "
    "grids_unread")
RULES = {"order": ORDER_RULE, "mode": MODE_RULE, "pilot": PILOT_RULE, "disk": DISK_RULE, "stages": STAGES_RULE,
         "replacement": REPLACEMENT_RULE, "limit": LIMIT_RULE, "group_start": GROUP_START_RULE, "seal": SEAL_RULE,
         "frozen_tree": FROZEN_TREE_RULE, "ending": ENDING_RULE, "pause": PAUSE_RULE,
         "continuation": CONTINUATION_RULE, "invalid": INVALID_RULE, "early_stop": EARLY_STOP_RULE,
         "resume": RESUME_RULE, "interleave": INTERLEAVE_RULE, "grids": GRID_RULE}
# ENDING_RULE: the endings of a record's name, with the design's Slovak names.
ENDINGS = {"complete": "úplná", "paused": "pozastavená", "stopped": "zastavená", "invalid": "neplatná",
           "closed": "uzavretá operátorom"}
PENDING = {"stopped": 0, "paused": 1, "invalid": 2}  # ENDING_RULE: the kinds a trigger leaves pending, lightest first.
CLOSING = ("complete", "invalid", "closed")  # ENDING_RULE (F11): the endings that close a campaign (MERANIA.md entry).
DEVIATION_LOG = "docs/ODCHYLKY_V5.sk.md"  # ENDING_RULE: the deviation log of protocol v5 (proposal 11.3).
MEASUREMENT_LOG = "docs/MERANIA.md"  # ENDING_RULE (F11, proposal 11.6): the log of measurements, an entry per campaign.
# ENDING_RULE and RESUME_RULE (F6): deviations/<UTC>_<kind>[_<vm>].json of the campaign directory, a deviation that
# is no ending: an unclean end a run found, the written cause of a resume after an early stop.
DEVIATION_SCHEMA = "hyptcn3/campaign-deviation/1"
# INVALID_RULE (F2): the per-file maps init freezes into campaign.json, each with what it hashes and the function of
# scripts/collection.py that hashes it now.
FROZEN_MAPS = (("measurement_files_sha256", "the measurement code (scripts/gates.py measurement_sha256 over "
                "scripts/collection.py measurement_sources", "measurement_sources"),
               ("lab_sha256", "the lab (scripts/collection.py lab_sha256", "lab_sha256"))
NAMED_FILES = 12  # The files a refusal names, the rest counted (the executor's judgment: the refusal stays readable).
SEEDED_LEVEL = "streams.seeded_level.seed"  # The protocol's key of the seed of the guest's reset (protocol_v5.reset_seed).
COMPLETE_CAUSE = ("every planned session is accepted: archived here, or taken over from the campaign this one "
                  "continues")
# FROZEN_TREE_RULE: the two status columns of git status --porcelain of a record of this campaign: new (untracked or
# added) or modified.
RECORD_CODES = ("??", "A ", "AM", " M", "M ", "MM")
# STAGES_RULE: the stage gates.require checks before (every stage up to the one before it) by the campaign's mode.
START_STAGES = {"campaign": ("G5", "G0 to G4"), "rehearsal": ("G3a", "G0 to G2")}
# GROUP_START_RULE: the labctl verbs of the start of a group, in order, each with its timeout in seconds (the
# executor's judgment: an outer bound above the bounds scripts/labctl.py and lab/guest_state.py set for the step, so
# that labctl ends a stuck step with its own reason first: the wait for the domain shut off, STOP_TIMEOUT_S 180 s; the
# guest agent after a start, 120 s, with the daemon unit, 30 s; the guest helper of reset and pretouch, 600 s, the
# process of the pretouch, 300 s).
GROUP_START_STEPS = {"stop": 300, "start": 300, "reset": 900, "pretouch": 600}
SEAL_TIMEOUT_S = 120  # SEAL_RULE: one write of the ledger (the executor's judgment: the archive is hashed again).
CHILD_ERROR_CHARS = 800  # The child's error text kept in a refusal (the executor's judgment: its last lines).


def vm_names(p):
    """VM names of the protocol; [None] for a single-VM protocol (original file names and layout)."""
    return [row["name"] for row in collection.vms(p)]


def schema3(p):
    """Whether `p` is a protocol of schema 3 (protocol v5, package B9a)."""
    return p.get("schema") == protocol_v5.SCHEMA


def campaign_plan(p, mode):
    """The plan of a campaign (MODE_RULE): under protocol schema 3 protocol_v5.plan of its mode, campaign or
    rehearsal; under schemas 1 and 2 collection.plan, which has no mode. A mode that does not fit is refused by name."""
    if schema3(p):
        if mode not in protocol_v5.MODES:
            raise ValueError("a campaign of protocol schema 3 names its plan mode, " + " or ".join(protocol_v5.MODES)
                             + f", not {mode!r} (scripts/campaign.py MODE_RULE)")
        return protocol_v5.plan(p, mode=mode)
    if mode is not None:
        raise ValueError(f"plan mode {mode} applies only to protocol schema 3; a campaign of schema 1 or 2 has one plan "
                         "(scripts/campaign.py MODE_RULE)")
    return collection.plan(p)


def time_rank(p):
    """{role: rank} of the time order of the plan's roles (ORDER_RULE): protocol_v5.TIME_RANK, under which the two test
    roles share a rank. A protocol of schema 1 or 2 whose single role has no rank (test_events) ranks it alone; any
    other role without a rank is refused by name."""
    roles = list(p["roles"])
    unranked = [role for role in roles if role not in protocol_v5.TIME_RANK]
    if not unranked:
        return {role: protocol_v5.TIME_RANK[role] for role in roles}
    if not schema3(p) and len(roles) == 1:
        return {roles[0]: 0}
    raise ValueError("roles without a time rank (scripts/protocol_v5.py TIME_RANK, scripts/campaign.py ORDER_RULE): "
                     + ", ".join(unranked))


def sealed_role(role):
    """SEAL_RULE: a role whose accepted sessions are sealed, a role training never loads (features/dataset.py ROLES
    without FIT_ROLES; tcn/pecat.py SEALED_ROLES equals them)."""
    from features.dataset import FIT_ROLES, ROLES
    return role in ROLES and role not in FIT_ROLES


def vm_file(name, vm):
    """Per-VM variant of a campaign file: status.json -> status-a.json."""
    stem, suffix = name.rsplit(".", 1)
    return name if vm is None else f"{stem}-{vm}.{suffix}"


def vm_unit(vm):
    return UNIT if vm is None else UNIT.replace(".service", f"-{vm}.service")


def vm_view(manifest, p, vm):
    """Campaign and protocol as one VM's runner sees them: that VM's pilot, guest
    environment, estimates, domain and target under the single-VM keys."""
    if vm is None:
        return manifest, p
    return {**manifest, **manifest["vms"][vm], "vm": vm}, collection.for_vm(p, vm)


def session_dir(manifest, row):
    if "vm" not in row:
        return COLLECTIONS / row["session_id"]
    return COLLECTIONS / manifest["id"] / row["vm"] / row["session_id"]


def archive_dest(manifest, row):
    return Path(manifest["archive_dir"]) / "collections" / row.get("vm", "") / row["session_id"]


def frozen_files(manifest):
    """The frozen files of a campaign and of its copy next to the archive: a campaign of protocol schema 3 (its
    manifest names its plan mode) has no pilot (PILOT_RULE)."""
    pilots = [] if "mode" in manifest else [vm_file("pilot.json", vm) for vm in manifest.get("vms", [None])]
    return ["campaign.json", "protocol.json", "plan.json", *pilots]


def rejection_file(directory, session_id):
    return directory / "attempts" / (session_id + ".rejected.json")


def chain(directory, row):
    """A plan row followed by the replacements of its audit-rejected sessions, oldest first.

    The last one is the assignment's current session. A replacement is the same
    assignment under the ID <plan session>-r<n>; rejection records name it.
    """
    rows = [row]
    while rejection_file(directory, rows[-1]["session_id"]).exists():
        record = read_json(rejection_file(directory, rows[-1]["session_id"]))
        if record.get("replacement") is None:
            break
        expected = f"{row['session_id']}-r{len(rows)}"
        if record["replacement"] != expected or record.get("session") != rows[-1]["session_id"]:
            raise ValueError("rejection record does not match the frozen plan: " + rows[-1]["session_id"])
        rows.append({**row, "session_id": expected, "replaces": rows[-1]["session_id"],
                     "plan_session": row["session_id"], "replacement": len(rows)})
    return rows


def rejections(directory, vm=None):
    """Sessions the campaign could not use (rejecting audit or incomplete capture), with cause and
    reasons, in time order (all VMs unless one is named)."""
    records = [read_json(path) for path in sorted((directory / "attempts").glob("*.rejected.json"))]
    return sorted((r for r in records if vm is None or r.get("vm") == vm), key=lambda r: r["date"])


def rejections_by_cause(directory):
    """LIMIT_RULE: the rejections of the campaign over all its VMs, counted by cause (a record from before causes
    existed is an audit rejection, as execute reads it)."""
    counts = Counter(r.get("cause", "audit_rejected") for r in rejections(directory))
    return dict(sorted(counts.items()))


# The keys a campaign adds to a row of its plan (session ID, the chain of replacements); the rest is the plan's.
CAMPAIGN_KEYS = ("session_id", "replaces", "plan_session", "replacement")


def attempt_row(manifest, p, row):
    """The assignment a row of chain() captures (REPLACEMENT_RULE). Under protocol schema 3 replacement n (row
    "replacement" n) is attempt n + 1 of its planned row, protocol_v5.replacement in the campaign's mode, with the
    campaign's keys of the row; a planned row is attempt 1 as the plan states it. Schemas 1 and 2: the row itself (the
    same assignment and seed)."""
    if not schema3(p) or "replacement" not in row:
        return row
    planned = {key: value for key, value in row.items() if key not in CAMPAIGN_KEYS}
    drawn = protocol_v5.replacement(p, planned, row["replacement"] + 1, mode=manifest["mode"])
    return {**drawn, **{key: row[key] for key in CAMPAIGN_KEYS}}


def replacement_limit(manifest, p):
    """LIMIT_RULE: (applied, limit). Schemas 1 and 2: the protocol's max_per_campaign, 0 without a rule. Schema 3: in
    mode rehearsal not applied (None); in mode campaign the protocol's number, a null one refused by name."""
    rule = p.get("replacement") or {}
    if not schema3(p):
        return True, rule.get("max_per_campaign", 0)
    if manifest["mode"] == "rehearsal":
        return False, None
    limit = rule.get("max_per_campaign")
    if type(limit) is not int:
        raise ValueError(NULL_LIMIT)
    return True, limit


NULL_LIMIT = ("replacement.max_per_campaign is null (it is determined at G3b, proposal 7.5): a campaign of mode "
              "campaign needs its limit of replacements (scripts/campaign.py LIMIT_RULE)")


def is_done(directory, row):
    """The assignment is archived and accepted: the plan session itself or its replacement."""
    return (directory / "attempts" / (chain(directory, row)[-1]["session_id"] + ".done.json")).exists()


def taken_over(manifest, row):
    """Continuation campaign: the frozen record of an assignment its closed predecessor completed, else None."""
    return manifest.get("continues", {}).get("sessions", {}).get(row["session_id"])


def finished(directory, manifest, row):
    """Nothing is left to capture for the assignment: accepted and archived here, or taken over."""
    return taken_over(manifest, row) is not None or is_done(directory, row)


def taken_report(record):
    """The predecessor's selected audit of a taken-over assignment; it must still be the frozen one."""
    report = Path(record["audit"])
    if digest(report) != record["audit_sha256"]:
        raise ValueError("audit of a taken-over session changed: " + record["session_id"])
    return report


def final_report(directory, manifest, row):
    """The accepted audit that represents the assignment in the index."""
    taken = taken_over(manifest, row)
    if taken is not None:
        return taken_report(taken)
    return Path(read_json(directory / "attempts" / (chain(directory, row)[-1]["session_id"] + ".audit.json"))["path"])


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def git(*args):
    # Only the final newline goes: a line of git status --porcelain begins with its two status columns, which may be
    # a space (FROZEN_TREE_RULE reads them).
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).rstrip("\n")


def tree_hashes(directory):
    return {str(f.relative_to(directory)): digest(f) for f in sorted(directory.rglob("*")) if f.is_file()}


def extractor_hashes():
    return {str(f.relative_to(ROOT)): digest(f) for d in ("features", "guestparse")
            for f in (ROOT / d).rglob("*.py") if "tests" not in f.parts}


def runtime_identity():
    packages = subprocess.check_output(collection.user_command([
        sys.executable, "-c", "import importlib.metadata,json; "
        "print(json.dumps({p:importlib.metadata.version(p) for p in ('numpy','torch')}))"
    ]), text=True, timeout=30)
    return {"host": platform.platform(), "python": sys.version,
            "packages": json.loads(packages),
            "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect"),
            # Swapped-out guest RAM stalls full snapshots (docs/LAB.sk.md); frozen with the campaign.
            "vm_swappiness": int(Path("/proc/sys/vm/swappiness").read_text())}


def guest_environment(identity):
    return {k: v for k, v in identity.items() if k != "boot_id"}


def pilot_gate(path, protocol_path, p):
    """An accepted pilot of this protocol made by the current code: (session metadata, bytes one session needs).

    What ties the report to this protocol, this code and these files is checked first, each tie with its own
    message, and nothing in the report is trusted before that. A field the gate reads that is missing or of a
    wrong type is refused by the tie that reads it, and so is a feature file the archive reader cannot read.
    Whether the pilot is accepted is then decided again from its feature archive by the one acceptance decision
    (features/acceptance.py, role "pilot": the pilot length in an unbroken sequence, no tolerated invalid row, no
    integrity finding, the coverage gate), and the report must state that very verdict.
    """
    from features.acceptance import require_accepted
    from features.archive import load
    from features.quality import require_log_audit
    report = read_json(path)
    v = report.get("values") if type(report) is dict else None
    if type(v) is not dict or report.get("schema") != "hyptcn3/collection-audit/1" \
            or type(v.get("session_dir")) is not str or type(v.get("features")) is not str \
            or type(v.get("raw_bytes")) is not int or v["raw_bytes"] <= 0:
        raise ValueError("pilot report is not a session audit")
    if v.get("protocol_sha256") != digest(protocol_path):
        raise ValueError("pilot was audited under another protocol")
    if type(v.get("quality")) is not dict or v["quality"].get("policy") != p["quality_policy"]:
        raise ValueError("pilot was audited under another input policy")
    if v.get("extractor_sha256") != extractor_hashes():
        raise ValueError("pilot was audited by another extractor (audit the pilot again)")
    session = Path(v["session_dir"]) / "session.json"
    if digest(session) != v.get("session_sha256"):
        raise ValueError("pilot metadata changed since audit")
    if digest(v["features"]) != v.get("features_sha256"):
        raise ValueError("pilot features changed since audit")
    meta = read_json(session)
    if type(meta) is not dict:
        raise ValueError("pilot metadata is not a session record")
    require_log_audit(meta, v)
    if tree_hashes(ROOT / p["profile"]) != meta.get("profile_sha256"):
        raise ValueError("pilot profile differs from the current profile")
    if digest(ROOT / "vmicollect/build/vmicollect") != meta.get("collector_sha256"):
        raise ValueError("pilot collector differs from the current collector")
    changed = measurement_changes(meta)
    if changed:
        raise ValueError("measurement code changed since the pilot (new pilot required): " + ", ".join(changed[:12]))
    try:
        archive = load(v["features"])
    except Exception as error:  # noqa: BLE001 - whatever the reader raises, the file is not a feature archive
        reason = f"{type(error).__name__}: {error}"
        raise ValueError("pilot features are not a readable feature archive: " + reason) from None
    try:
        require_accepted(archive, p, Path(v["session_dir"]).name, "pilot", v)
    except ValueError as error:
        raise ValueError("pilot is not accepted for this protocol: " + str(error)) from None
    return meta, v["raw_bytes"] * p["cycles"] / p["pilot_cycles"] * 1.5


def measurement_changes(meta):
    """Capture/audit/archive code that differs from the pilot's; reports and docs may change."""
    recorded = meta.get("measurement_sha256")
    if type(recorded) is not dict:
        return ["<pilot predates measurement provenance>"]
    current = collection.measurement_sources()
    return sorted(name for name in set(recorded) | set(current) if recorded.get(name) != current.get(name))


def raw_bytes(session):
    """Bytes of a session's RAM images still on the working disk (0 once archived and reclaimed)."""
    raw = session / "raw"
    if raw.is_symlink() or not raw.is_dir():
        return 0
    total = 0
    for path in raw.iterdir():
        try:
            total += path.stat().st_size
        except OSError:
            pass  # Published or renamed by the collector's writer thread meanwhile.
    return total


def capacity_guard(manifest, p, remaining, directory=None):
    """Space for the next session of this VM, next to what the other VMs still write.

    Every VM has its own estimate: raw bytes of its accepted pilot scaled to the
    session length, times 1.5 (pilot_gate). The working disk must hold this VM's
    next session, plus for every other VM with sessions left the part of its
    estimate not written yet (its current session may be in capture, waiting for
    the audit lock or about to start), plus the protocol reserve min_free_gib.
    At most one unarchived session per VM exists, because a runner archives and
    reclaims its session before the next capture and audits are serialized.

    Assumed numbers (collection PC, 2026-11-14, protocol v3 values): one session
    estimate ~16.8 GB (~11.2 GB raw x 1.5), reserve 30 GiB = 32.2 GB, i.e. the
    ~49 GB one VM needed so far. Two VMs starting together need 2 x 16.8 + 32.2 =
    65.8 GB, more than the 62.9 GB free on the SSD: either space is freed first or
    protocol v4 lowers min_free_gib (27 GiB gives 62.6 GB). The real estimates come
    from the per-VM pilots of the campaign, not from these numbers.

    Protocol schema 3 has no pilot: DISK_RULE (v5_capacity_guard), whatever `remaining` says.
    """
    if schema3(p):
        return v5_capacity_guard(manifest, p, directory)
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    reserve = p["min_free_gib"] * 2**30
    needed = manifest["estimated_session_bytes_with_reserve"]
    archived = manifest.get("estimated_archive_bytes_per_session", needed) * remaining
    for vm in manifest.get("vms", {}) if directory is not None else ():
        pending = [r for r in manifest["sessions"] if r["vm"] == vm and not finished(directory, manifest, r)]
        if vm == manifest["vm"] or not pending:
            continue
        other = manifest["vms"][vm]
        current = chain(directory, pending[0])[-1]
        needed += max(0, other["estimated_session_bytes_with_reserve"] - raw_bytes(session_dir(manifest, current)))
        archived += other["estimated_archive_bytes_per_session"] * len(pending)
    if shutil.disk_usage(COLLECTIONS).free < needed + reserve:
        raise ValueError("insufficient working space for the next session")
    if shutil.disk_usage(manifest["archive_root"]).free < archived + reserve:
        raise ValueError("insufficient archive space for remaining campaign estimate")


def recorded_sizes(directory):
    """DISK_RULE: [(session, working bytes, archive bytes)] of every accepted session of a campaign directory, as
    its checkpoint attempts/<session>.done.json records them at acceptance (package B9a); a checkpoint without them is
    refused by name."""
    sizes = []
    for path in sorted((Path(directory) / "attempts").glob("*.done.json")):
        done = read_json(path)
        if not all(type(done.get(key)) is int and done[key] >= 0 for key in ("session_bytes", "archive_bytes")):
            raise ValueError(f"accepted session {done.get('session')} records no sizes (session_bytes, archive_bytes; "
                             f"scripts/campaign.py DISK_RULE): {path}")
        sizes.append((done["session"], done["session_bytes"], done["archive_bytes"]))
    return sizes


def largest_session(directory, manifest):
    """DISK_RULE: {"session_bytes", "archive_bytes"} of the largest accepted session so far, each the largest of the
    campaign's own checkpoints and of the seed its init froze (mode campaign); None before any (mode rehearsal)."""
    seed = (manifest.get("disk_estimate") or {}).get("seed")
    sizes = recorded_sizes(directory) + ([(seed["session"], seed["session_bytes"], seed["archive_bytes"])]
                                         if seed else [])
    if not sizes:
        return None
    return {"session_bytes": max(size[1] for size in sizes), "archive_bytes": max(size[2] for size in sizes)}


def v5_capacity_guard(manifest, p, directory):
    """DISK_RULE for the next session of this VM (manifest: the VM's view), and at init for the whole campaign."""
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    reserve = p["min_free_gib"] * 2**30
    largest = largest_session(directory, manifest)
    working = archived = 0
    if largest is not None:
        pending = [r for r in manifest["sessions"] if not finished(directory, manifest, r)]
        applied, limit = replacement_limit(manifest, p)
        spare = max(0, limit - sum(r.get("replacement") is not None for r in rejections(directory))) if applied else 0
        archived = largest["archive_bytes"] * (len(pending) + spare)
        working = largest["session_bytes"]
        for vm in sorted({r["vm"] for r in pending if r.get("vm") not in (None, manifest.get("vm"))}):
            current = chain(directory, next(r for r in pending if r["vm"] == vm))[-1]
            working += max(0, largest["session_bytes"] - raw_bytes(session_dir(manifest, current)))
    if shutil.disk_usage(COLLECTIONS).free < working + reserve:
        raise ValueError(f"insufficient working space for the next session: {working + reserve} bytes needed "
                         "(scripts/campaign.py DISK_RULE)")
    if shutil.disk_usage(manifest["archive_root"]).free < archived + reserve:
        raise ValueError(f"insufficient archive space for the sessions still to capture: {archived + reserve} bytes "
                         "needed (scripts/campaign.py DISK_RULE)")


def ended(directory, manifest):
    """Whether a campaign directory has ended: closed by the operator (closed.json) or complete on every VM."""
    if (directory / "closed.json").exists():
        return True
    names = list(manifest["vms"]) if "vms" in manifest else [None]
    states = [directory / vm_file("status.json", vm) for vm in names]
    return all(path.exists() and read_json(path).get("status") == "complete" for path in states)


# DISK_RULE: what a rehearsal must share with the campaign whose estimate it seeds (the length and the shape of a
# session decide its size).
ESTIMATE_KEYS = ("name", "cycles", "interval_s", "full_every", "bin_bytes")


def rehearsal_estimate(path, p, compression):
    """DISK_RULE in mode campaign (init --estimate-from): the seed of the estimate, the largest accepted session of an
    ended rehearsal of this protocol, with where it comes from; every condition is refused by name."""
    path = Path(path).resolve()
    try:
        old, old_p = read_json(path / "campaign.json"), read_json(path / "protocol.json")
    except (OSError, ValueError) as error:
        raise ValueError(f"--estimate-from {path}: no campaign directory ({type(error).__name__}: {error})") from None
    if type(old) is not dict or old.get("schema") != "hyptcn3/collection-campaign/1" or old.get("id") != path.name:
        raise ValueError(f"--estimate-from {path}: no campaign directory (campaign.json of its own name)")
    if old.get("mode") != "rehearsal":
        raise ValueError(f"--estimate-from {path}: campaign {old['id']} is no rehearsal (mode {old.get('mode')!r})")
    if not ended(path, old):
        raise ValueError(f"--estimate-from {path}: rehearsal {old['id']} has not ended (closed, or complete on every "
                         "VM)")
    differing = [key for key in ESTIMATE_KEYS if type(old_p) is not dict or old_p.get(key) != p.get(key)]
    if old.get("archive_compression") != compression:
        differing.append("archive_compression")
    if differing:
        raise ValueError(f"--estimate-from {path}: rehearsal {old['id']} differs from this campaign in "
                         + ", ".join(differing))
    sizes = recorded_sizes(path)
    if not sizes:
        raise ValueError(f"--estimate-from {path}: rehearsal {old['id']} has no accepted session")
    session = max(sizes, key=lambda size: (size[2], size[1]))[0]
    return {"campaign": old["id"], "directory": str(path), "campaign_sha256": digest(path / "campaign.json"),
            "accepted_sessions": len(sizes), "session": session,
            "session_bytes": max(size[1] for size in sizes), "archive_bytes": max(size[2] for size in sizes)}


def require_stages(protocol_path, mode):
    """STAGES_RULE: the readiness records and the self-test a campaign of this mode starts on; ValueError by name."""
    from scripts import gates  # Inside the function, as scripts/collection.py: gates imports collection.
    from scripts.audit_selftest import require_selftest
    stage, needed = START_STAGES[mode]
    try:
        gates.require(gates.ROOT / "data/results", protocol_path, stage)
    except ValueError as error:
        raise ValueError(f"a campaign of mode {mode} starts on valid readiness records of {needed}: {error}") from None
    require_selftest(protocol_path)


@contextmanager
def audit_lock(directory, **state):
    """One audit/archive on the host at a time, over all VMs and campaigns.

    Feature extraction and the compressing archiver are the heavy host work
    between captures (CPU, memory, SSD and archive disk); two at once would
    load the other VM's running capture twice. Waits; interrupts end the wait.
    """
    COLLECTIONS.mkdir(parents=True, exist_ok=True)
    fd = os.open(COLLECTIONS / ".audit.lock", os.O_CREAT | os.O_RDWR, 0o644)
    try:
        waiting = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waiting:
                    update_state(directory, status="running", stage="audit-wait", **state,
                                 message="another VM's audit or archive is running")
                waiting = True
                time.sleep(WAIT_POLL_S)
        yield
    finally:
        os.close(fd)


def pilot_reports(p, values):
    """--pilot-report PATH (single VM) or one VM=PATH per VM of the protocol."""
    names = vm_names(p)
    if names == [None]:
        if len(values) != 1:
            raise ValueError("exactly one pilot report required")
        return {None: Path(values[0])}
    given = dict(str(value).split("=", 1) if "=" in str(value) else (None, value) for value in values)
    if len(given) != len(values) or set(given) != set(names):
        raise ValueError("one accepted pilot per VM required: --pilot-report VM=PATH for " + ", ".join(names))
    return {vm: Path(given[vm]) for vm in names}


def archive_estimate(session_dir, p, compression):
    """Archive bytes per hourly session from the accepted pilot itself.

    Raw images use the archive codec on every pilot image; all other session
    files count uncompressed (upper bound). The 1.5 planning margin is kept.
    """
    raw = Path(session_dir) / "raw"
    original = stored = 0
    for path in sorted(raw.glob("*.vmicd")):
        size = path.stat().st_size
        original += size
        if compression is None:
            stored += size
            continue
        with path.open("rb") as stream:
            process = subprocess.Popen(["zstd", "-q", "-3", "-T1", "-c"], stdin=stream, stdout=subprocess.PIPE)
            for chunk in iter(lambda: process.stdout.read(1 << 20), b""):
                stored += len(chunk)
            if process.wait():
                raise ValueError("zstd failed while estimating the archive size")
    if not original:
        raise ValueError("pilot raw images are not available for the archive estimate")
    other = sum(f.stat().st_size for f in Path(session_dir).rglob("*")
                if f.is_file() and not f.is_symlink() and raw not in f.parents)
    scale = p["cycles"] / p["pilot_cycles"]
    return {"codec": compression, "pilot_raw_bytes": original, "pilot_raw_stored_bytes": stored,
            "raw_ratio": stored / original, "pilot_other_bytes": other,
            "bytes_per_session": (stored + other) * scale * 1.5,
            "note": "Measured on the accepted pilot; heavier scenarios may exceed it."}


def v5_freeze(a, p, compression):
    """What init freezes of a campaign of protocol schema 3, each condition refused by name before the lab is asked:
    the plan mode (MODE_RULE), no pilot (PILOT_RULE), the written cause of a continuation (CONTINUATION_RULE), the limit
    of mode campaign (LIMIT_RULE), the seed of the disk estimate (DISK_RULE: --estimate-from, in mode campaign only),
    the stages (STAGES_RULE), then the guest environment of every VM, the measurement code and the lab (INVALID_RULE,
    CONTINUATION_RULE: package B9b). Returns (mode, per-VM part of the manifest, the manifest's keys of schema 3)."""
    from scripts import gates  # Inside the function, as require_stages: gates imports collection.
    mode = a.mode
    if mode is None:
        raise ValueError("a campaign of protocol schema 3 needs --mode campaign or --mode rehearsal (no default; "
                         "scripts/campaign.py MODE_RULE)")
    if mode not in protocol_v5.MODES:
        raise ValueError("invalid --mode: " + " or ".join(protocol_v5.MODES))
    if a.pilot_report:
        raise ValueError("protocol v5 has no pilot: init takes no --pilot-report (scripts/campaign.py PILOT_RULE)")
    cause = getattr(a, "cause", None)
    if getattr(a, "continues", None) is not None:
        if type(cause) is not str or not cause.strip():
            raise ValueError("a continuation of a campaign of protocol schema 3 needs --cause TEXT, the written cause "
                             "of its pause (no default; scripts/campaign.py CONTINUATION_RULE)")
        if mode != "campaign":
            raise ValueError("a continuation continues a paused campaign of mode campaign (a rehearsal never pauses): "
                             "--mode campaign (scripts/campaign.py CONTINUATION_RULE)")
    elif cause is not None:
        raise ValueError("--cause belongs to --continue: the written cause of a continuation (scripts/campaign.py "
                         "CONTINUATION_RULE)")
    if mode == "campaign":
        if type((p.get("replacement") or {}).get("max_per_campaign")) is not int:
            raise ValueError(NULL_LIMIT)
        if a.estimate_from is None:
            raise ValueError("a campaign of mode campaign needs --estimate-from, the directory of an ended rehearsal "
                             "of the protocol (scripts/campaign.py DISK_RULE)")
    elif a.estimate_from is not None:
        raise ValueError("--estimate-from belongs to mode campaign: a rehearsal estimates from its own accepted "
                         "sessions (scripts/campaign.py DISK_RULE)")
    require_stages(a.protocol, mode)
    seed = None if mode == "rehearsal" else rehearsal_estimate(a.estimate_from, p, compression)
    per_vm = {}
    for vm in vm_names(p):  # PILOT_RULE: the guest environment of every VM, recorded here (no pilot to take it from).
        view = collection.for_vm(p, vm)
        per_vm[vm] = {"guest_environment": guest_environment(collection.guest_identity(view)),
                      **({} if vm is None else {"domain": view["domain"]})}
    return mode, per_vm, {"disk_estimate": {"rule": DISK_RULE, "seed": seed}, "rules": RULES,
                          # INVALID_RULE and CONTINUATION_RULE: what verify_frozen and a continuation compare, file by
                          # file (F2), beside the one hash of the measurement sources.
                          "measurement_sha256": gates.measurement_sha256(),
                          "measurement_files_sha256": collection.measurement_sources(),
                          "lab_sha256": collection.lab_sha256()}


def initialize(a):
    if git("status", "--porcelain"):
        raise ValueError("commit the source and documentation before freezing a campaign")
    p = collection.protocol(a.protocol)
    compression = None if a.archive_compression == "none" else a.archive_compression
    if schema3(p):
        mode, per_vm, v5_keys = v5_freeze(a, p, compression)
        pilots, profile = {}, tree_hashes(ROOT / p["profile"])
    else:
        pilots, per_vm, profile = pilot_freeze(a, p, compression)
        mode, v5_keys = None, {}
    if len({v["guest_environment"]["machine_id"] for v in per_vm.values()}) != len(per_vm):
        raise ValueError("VMs share a machine-id; a clone needs its own identity (labctl clone)")
    planned = campaign_plan(p, mode)
    # MODE_RULE: under schema 3 the default name ends in the plan's name (a rehearsal's own name, protocol_v5._shape).
    name = a.name or stamp() + ("_" + planned["name"] if mode else "_benign_v2")
    if not re.fullmatch(CAMPAIGN_NAME, name):
        raise ValueError("invalid campaign name")
    archive_root = Path(a.archive_root).absolute()
    mount = mount_identity(archive_root, allow_system=a.archive_on_system_disk)
    owner = pwd.getpwuid(int(os.environ.get("SUDO_UID", os.getuid())))
    directory = BASE / name
    for i, row in enumerate(planned["sessions"]):
        row["session_id"] = "_".join([name, f"{i + 1:02d}", *([row["vm"]] if "vm" in row else []),
                                      row["role"], row["scenario"]])
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": name, "date": now(),
                "commit": git("rev-parse", "HEAD"), "runtime": runtime_identity(),
                "owner": {"name": owner.pw_name, "uid": owner.pw_uid, "gid": owner.pw_gid},
                "workspace": str(ROOT), "protocol_sha256": digest(a.protocol),
                "profile_sha256": profile, "extractor_sha256": extractor_hashes(),
                # MODE_RULE (schema 3): the plan's mode, name and group prefix (protocol_v5._shape).
                **({"mode": mode, "plan_name": planned["name"], "group_prefix": planned["group_prefix"]}
                   if mode else {}),
                # Pilot, guest environment and estimates: per VM under "vms", or flat for one VM.
                **(per_vm[None] if None in per_vm else {"vms": per_vm}),
                "archive_root": str(archive_root), "archive_mount": mount,
                "archive_dir": str(archive_root / "campaigns" / name),
                "archive_compression": compression,
                "working_storage": collection.storage_identity(COLLECTIONS),
                "sessions": planned["sessions"], "planned_capture_hours": planned["planned_hours"],
                **v5_keys,
                "note": "Frozen allocation, not a measurement or a completed corpus."}
    if getattr(a, "continues", None) is not None:
        manifest["continues"] = take_over(a.continues, manifest, p, cause=getattr(a, "cause", None))
    todo = {vm: [r for r in planned["sessions"] if r.get("vm") == vm and taken_over(manifest, r) is None]
            for vm in per_vm}
    COLLECTIONS.mkdir(exist_ok=True, parents=True)
    archive_root.mkdir(exist_ok=True, parents=True)
    for vm in per_vm:
        capacity_guard(vm_view(manifest, p, vm)[0], p, len(todo[vm]), directory)
    # Group names repeat in every campaign of a protocol. Only a campaign
    # explicitly closed by the operator releases them (its data stays), and a
    # paused one of schema 3 for its continuation (CONTINUATION_RULE).
    groups, continued = {r["group"] for r in planned["sessions"]}, manifest.get("continues", {}).get("campaign")
    for old, doc in collection.session_records(COLLECTIONS):
        if (doc["group"] in groups and not closed_campaign(doc.get("campaign_id"))
                and (continued is None or doc.get("campaign_id") != continued)):
            raise ValueError("planned group already has data; resume or close its campaign: " + str(old))
    directory.mkdir(parents=True)
    for child in ("events", "groups", "attempts", "logs"):
        (directory / child).mkdir()
    copy_exclusive(Path(a.protocol), directory / "protocol.json")
    for vm, pilot in pilots.items():
        copy_exclusive(pilot, directory / vm_file("pilot.json", vm))
    write_new(directory / "plan.json", planned)
    write_new(directory / "campaign.json", manifest)
    external = Path(manifest["archive_dir"])
    guard_mount(archive_root, mount)
    external.mkdir(parents=True)
    for filename in frozen_files(manifest):
        copy_exclusive(directory / filename, external / filename)
    for vm in per_vm:
        total = sum(r.get("vm") == vm for r in planned["sessions"])
        update_state(directory, vm=vm, status="ready", stage="initialized",
                     accepted_archived=total - len(todo[vm]), total=total)
    print(json.dumps({"campaign": str(directory), "sessions": len(planned["sessions"]),
                      "capture_hours": planned["planned_hours"], **({"mode": mode} if mode else {}),
                      **({"continues": manifest["continues"]["campaign"],
                          "taken_over_sessions": len(manifest["continues"]["sessions"]),
                          "sessions_to_capture": sum(map(len, todo.values())),
                          "discarded_groups": [g["group"] for g in manifest["continues"]["discarded_groups"]]}
                         if "continues" in manifest else {}),
                      "archive": str(external)}, indent=2))
    return directory


def pilot_freeze(a, p, compression):
    """What init freezes of a campaign of protocol schema 1 or 2: one accepted pilot per VM with its guest
    environment and estimates (as before package B9a); --mode and --estimate-from are of schema 3 and refused by name.
    Returns (pilots, per-VM part of the manifest, the profile's hashes)."""
    for value, flag in ((a.mode, "--mode"), (a.estimate_from, "--estimate-from")):
        if value is not None:
            raise ValueError(flag + " applies only to protocol schema 3 (scripts/campaign.py MODE_RULE, DISK_RULE)")
    if getattr(a, "cause", None) is not None:
        raise ValueError("--cause applies only to protocol schema 3: a continuation of schema 1 or 2 takes the reason "
                         "its campaign was closed with (scripts/campaign.py CONTINUATION_RULE)")
    if not a.pilot_report:
        raise ValueError("a campaign of protocol schema 1 or 2 needs --pilot-report (an accepted pilot audit; "
                         "multi-VM protocol: one VM=PATH per VM)")
    pilots = pilot_reports(p, a.pilot_report)
    per_vm = {}
    for vm, pilot in pilots.items():  # One accepted pilot per VM: its own machine, estimate and memory.
        pv = collection.for_vm(p, vm)
        meta, needed = pilot_gate(pilot, a.protocol, pv)
        if meta.get("vm") != vm:
            raise ValueError("pilot was captured on a different VM")
        identity = collection.guest_identity(pv)
        if guest_environment(identity) != guest_environment(meta["guest_before"]):
            raise ValueError("guest environment differs from accepted pilot")
        if runtime_identity()["vm_swappiness"] != meta["host_context"].get("memory", {}).get("vm_swappiness"):
            raise ValueError("host vm.swappiness differs from accepted pilot")
        estimate = archive_estimate(read_json(pilot)["values"]["session_dir"], p, compression)
        per_vm[vm] = {"pilot_report_sha256": digest(pilot), "pilot_source": str(pilot.resolve()),
                      "guest_environment": guest_environment(identity),
                      "archive_estimate": estimate,
                      "estimated_archive_bytes_per_session": estimate["bytes_per_session"],
                      "estimated_session_bytes_with_reserve": needed}
        if vm is not None:
            per_vm[vm]["domain"] = pv["domain"]
    return pilots, per_vm, meta["profile_sha256"]


def closed_campaign(campaign_id):
    return (isinstance(campaign_id, str) and re.fullmatch(CAMPAIGN_NAME, campaign_id) is not None
            and (BASE / campaign_id / "closed.json").exists())


def copy_exclusive(source, destination):
    if destination.exists():
        if digest(source) != digest(destination):
            raise ValueError("existing campaign backup differs: " + str(destination))
        return
    temp = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    before = digest(source)
    try:
        with source.open("rb") as src, temp.open("xb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        if digest(source) != before or digest(temp) != before:
            raise ValueError("campaign backup checksum mismatch")
        os.link(temp, destination)
        temp.unlink()
        sync_dir(destination.parent)
    finally:
        temp.unlink(missing_ok=True)


def load_campaign(directory):
    directory = Path(directory).resolve()
    m = read_json(directory / "campaign.json")
    if m.get("schema") != "hyptcn3/collection-campaign/1" or m["workspace"] != str(ROOT):
        raise ValueError("campaign schema/workspace mismatch")
    p = collection.protocol(directory / "protocol.json")
    # MODE_RULE: the plan of the mode campaign.json names (schema 3), refused by name when it names none or one of a
    # schema without modes.
    if schema3(p) and m.get("mode") not in protocol_v5.MODES:
        raise ValueError("campaign of protocol schema 3 without its plan mode (campaign.json mode: campaign or "
                         "rehearsal; scripts/campaign.py MODE_RULE)")
    expected = campaign_plan(p, m.get("mode"))["sessions"]
    rows = [{k: v for k, v in row.items() if k != "session_id"} for row in m["sessions"]]
    if (m["id"] != directory.name or rows != expected
            or digest(directory / "protocol.json") != m["protocol_sha256"]
            or list(m.get("vms", [None])) != vm_names(p)
            or not set(m.get("continues", {}).get("sessions", {})) <= {row["session_id"] for row in m["sessions"]}
            or not schema3(p) and any(digest(directory / vm_file("pilot.json", vm))
                                      != vm_view(m, p, vm)[0]["pilot_report_sha256"] for vm in vm_names(p))):
        raise ValueError("campaign plan or frozen inputs changed")
    if len({r["session_id"] for r in m["sessions"]}) != len(rows):
        raise ValueError("duplicate campaign session IDs")
    for row in m["sessions"]:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}", row["session_id"]):
            raise ValueError("unsafe session ID")
    return m, p


def taken_session(previous, old, old_p, final, group):
    """One accepted, archived session of the closed campaign as the continuation takes it over.

    Its records must still agree with each other, as a resumed run of that
    campaign would require: checkpoint, selected audit, session metadata,
    features, archive manifest and the boot recorded for its group. Whether the
    selected audit accepts it is decided by the one acceptance decision on the
    record under the closed campaign's protocol (features/acceptance.py
    require_recorded; deferred point 10 of B2, package B9a), not by its flag.
    Under protocol schema 3 (a paused campaign, CONTINUATION_RULE) a replacement
    is compared as the attempt it was (attempt_row: its own seed), and the record
    names that attempt.
    """
    from features.acceptance import require_recorded
    if schema3(old_p):
        final = attempt_row(old, old_p, final)
    name = final["session_id"]
    try:
        done = read_json(previous / "attempts" / (name + ".done.json"))
        pointer = read_json(previous / "attempts" / (name + ".audit.json"))
        report, session, archive = Path(pointer["path"]), session_dir(old, final), archive_dest(old, final)
        doc, meta = read_json(report), read_json(session / "session.json")
        v = doc["values"]
        try:
            require_recorded(old_p, final["role"], v, meta.get("cycles"))
            refused = None
        except ValueError as error:
            refused = str(error)
        checks = {
            "selected audit": digest(report) == pointer["sha256"] == done["audit_sha256"],
            "audit verdict and provenance" + ("" if refused is None else f" (require_recorded: {refused})"):
                refused is None and audit_environment(doc, old)
                and v["session_dir"] == str(session) and v["role"] == final["role"],
            "session metadata": digest(session / "session.json") == v["session_sha256"]
                                and all(meta[k] == final[k] for k in ("role", "group", "scenario", "seed", "session_id"))
                                and meta.get("vm") == final.get("vm") and meta.get("campaign_id") == old["id"],
            "features": digest(v["features"]) == v["features_sha256"],
            "archive": digest(archive / "archive-manifest.json") == done["manifest_sha256"]
                       and (session / "raw").is_symlink() and os.readlink(session / "raw") == str(archive / "raw"),
            "group boot": meta["guest_before"] == group["identity"]}
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(f"session {name} cannot be taken over ({type(exc).__name__}: {exc})") from None
    if not all(checks.values()):
        raise ValueError(f"session {name} cannot be taken over, records disagree: "
                         + ", ".join(k for k, ok in checks.items() if not ok))
    return {"campaign": old["id"], "session_id": name, "group": final["group"], "audit": str(report),
            "audit_sha256": pointer["sha256"], "boot_id": meta["guest_before"]["boot_id"],
            **({"attempt": final["attempt"]} if schema3(old_p) else {})}


def continuable(previous, old):
    """CONTINUATION_RULE: the paused record ({record, sha256, date}) of the campaign of protocol schema 3 in `previous`
    (its manifest `old`) that a continuation continues; every condition refused by name before anything is frozen: a
    continuation, a closed campaign, an ending still pending, a last recorded ending other than paused or none, the
    paused record missing or changed, and the measurement code or the lab changed since that campaign was frozen, file
    by file (frozen_hashes: a file changed or gone; F2 of the verification of B9b), or a new file beside them."""
    name = old["id"]
    if "continues" in old:
        raise ValueError(f"campaign {name} is a continuation of {old['continues']['campaign']}: a continuation is "
                         "never continued (scripts/campaign.py CONTINUATION_RULE)")
    if (previous / "closed.json").exists():
        raise ValueError(f"campaign {name} was closed by the operator: only a paused campaign is continued "
                         "(scripts/campaign.py CONTINUATION_RULE)")
    pending = pending_ending(previous)
    if pending is not None:
        raise ValueError(f"campaign {name} has an ending not yet recorded ({pending['ending']}: {pending['cause']}): a "
                         "run of one of its VMs records it first (scripts/campaign.py ENDING_RULE), and only a paused "
                         "campaign is continued (CONTINUATION_RULE)")
    latest = latest_ending(previous)
    if latest is None or latest["ending"] != "paused":
        raise ValueError(f"campaign {name} ended " + ("with no recorded ending" if latest is None else latest["ending"])
                         + ", not paused: only a paused campaign is continued (scripts/campaign.py CONTINUATION_RULE)")
    path = RESULTS / latest["record"]
    if not path.is_file() or digest(path) != latest["sha256"]:
        raise ValueError(f"the paused record of campaign {name} is {'missing' if not path.is_file() else 'changed'}: "
                         f"{path} (scripts/campaign.py CONTINUATION_RULE)")
    changed, new = frozen_hashes(old)
    if changed:
        raise ValueError(f"{changed} changed since campaign {name} was frozen: a continuation needs the measurement "
                         "code and the lab unchanged (scripts/campaign.py CONTINUATION_RULE)")
    if new:
        raise ValueError(f"new files beside the measurement code and the lab that campaign {name} froze: "
                         f"{named_files(new)}; remove them and try again (a new file is no change of the frozen set "
                         "and never makes a campaign invalid; scripts/campaign.py CONTINUATION_RULE)")
    return {"record": latest["record"], "sha256": latest["sha256"], "date": latest.get("date")}


def take_over(previous, manifest, p, cause=None):
    """What a new campaign takes from the closed campaign it continues (PLAN_multivm_dataset.md, chapter 8).

    The predecessor stopped for good - a session its replacement rule could not
    replace, or a lost group boot - and the operator closed it. The continuation
    has the same protocol file, plan, extractor, profile, runtime and guest
    environments, so the sessions of both pass one index (features/dataset.py).

    A group whose every assignment is accepted and archived there is taken over:
    not captured and not audited again, indexed through its frozen audit. Every
    other group is captured again as a whole in a new boot of its VM. What the
    predecessor has of such a group stays archived, is listed under
    discarded_groups and is never indexed: a group remains one boot of one VM.

    A campaign is continued once, and a continuation is never continued. Only a
    continuation that was closed before it captured anything may be set up again.

    Protocol schema 3 (package B9b, CONTINUATION_RULE): the predecessor is a
    paused campaign, not a closed one (continuable), the continuation names its
    written cause, and its record names the predecessor's paused record and
    rejections, which the records of its endings carry on.
    """
    previous = Path(previous).resolve()
    old, old_p = load_campaign(previous)
    if schema3(p):
        paused = continuable(previous, old)
    elif not (previous / "closed.json").exists():
        raise ValueError("only a campaign closed by the operator can be continued")
    if "continues" in old:
        raise ValueError("a continuation campaign cannot be continued again")
    for other in sorted(BASE.glob("*/campaign.json")):
        if read_json(other).get("continues", {}).get("campaign") != old["id"]:
            continue
        measured = [f for kind in ("done", "rejected", "audit") for f in (other.parent / "attempts").glob(f"*.{kind}.json")]
        if measured or not (other.parent / "closed.json").exists():
            raise ValueError("campaign already has a continuation: " + other.parent.name)
    strip = lambda rows: [{k: v for k, v in row.items() if k != "session_id"} for row in rows]
    differing = [key for key in ("protocol_sha256", "profile_sha256", "extractor_sha256", "runtime")
                 if old.get(key) != manifest.get(key)]
    if list(old.get("vms", [None])) != list(manifest.get("vms", [None])) \
            or strip(old["sessions"]) != strip(manifest["sessions"]):
        differing.append("plan")
    else:
        differing += ["guest_environment" + (f" ({vm})" if vm else "") for vm in vm_names(p)
                      if vm_view(old, old_p, vm)[0]["guest_environment"]
                      != vm_view(manifest, p, vm)[0]["guest_environment"]]
    if differing:
        raise ValueError("continuation differs from the " + ("paused" if schema3(p) else "closed") + " campaign: "
                         + ", ".join(differing))
    guard_mount(old["archive_root"], old["archive_mount"])
    groups = {}
    for before, row in zip(old["sessions"], manifest["sessions"]):
        groups.setdefault(row["group"], []).append((before, row))
    sessions, discarded, complete = {}, [], {}
    for name, members in groups.items():
        first = members[0][1]
        finals = [chain(previous, before)[-1] for before, _ in members]
        accepted = [final for (before, _), final in zip(members, finals) if is_done(previous, before)]
        record = previous / "groups" / (name + ".json")
        complete[name] = len(accepted) == len(members)
        if not complete[name]:
            if record.exists():  # Started: it has a boot and possibly sessions, none of them indexed.
                discarded.append({"group": name, "role": first["role"], **({"vm": first["vm"]} if "vm" in first else {}),
                                  "boot_id": read_json(record)["identity"]["boot_id"],
                                  "accepted_sessions": [final["session_id"] for final in accepted]})
            continue
        group = read_json(record)
        for (_, row), final in zip(members, finals):
            sessions[row["session_id"]] = taken_session(previous, old, old_p, final, group)
    # The time order of the plan holds over both campaigns only if no role of a later rank was completed there
    # before one of an earlier rank (ORDER_RULE: the two test roles share a rank and interleave); the runners never
    # do that, a damaged directory could.
    rank = time_rank(p)
    role = {name: rank[members[0][1]["role"]] for name, members in groups.items()}
    if any(complete[late] and not complete[early] and role[early] < role[late] for late in groups for early in groups):
        raise ValueError(("paused" if schema3(p) else "closed") + " campaign completed a later role before an "
                         "earlier one")
    unused = rejections(previous)
    if schema3(p):  # CONTINUATION_RULE: the paused record, the written cause and the predecessor's rejections.
        ending = {"paused_record": paused, "cause": cause,
                  "rejected_sessions": [{"session": r["session"], "cause": r.get("cause", "audit_rejected"),
                                         "replacement": r.get("replacement"), "campaign": old["id"]} for r in unused],
                  "rejections_by_cause": rejections_by_cause(previous)}
    else:
        ending = {"closed_sha256": digest(previous / "closed.json"),
                  "closed_reason": read_json(previous / "closed.json")["reason"]}
    return {"campaign": old["id"], "directory": str(previous), "commit": old["commit"],
            "campaign_sha256": digest(previous / "campaign.json"), **ending,
            "replacements_used": sum(r.get("replacement") is not None for r in unused),
            "not_replaced": [r["session"] for r in unused if r.get("replacement") is None],
            "sessions": sessions, "discarded_groups": discarded,
            "note": "Taken-over sessions are indexed through the "
                    + ("paused" if schema3(p) else "closed") + " campaign's frozen audits. Discarded groups are "
                    "captured again as a whole; what the " + ("paused" if schema3(p) else "closed")
                    + " campaign has of them is never indexed."}


@contextmanager
def ledger_lock():
    """FROZEN_TREE_RULE: the lock under which tcn/pecat.py replaces the seal ledger through a temporary file (an
    exclusive flock of the ledger's directory, tcn/pecat.py _locked)."""
    descriptor = os.open(ROOT / Path(LEDGER).parent, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def own_records(directory):
    """FROZEN_TREE_RULE: {path as git status names it: sha256} of the records of the endings a campaign wrote (the
    names its endings/ holds, of its own id; ENDING_RULE)."""
    if directory is None:
        return {}
    pattern = re.escape(f"kampan_{Path(directory).name}_") + "(?:" + "|".join(ENDINGS) + r")_[0-9]{8}T[0-9]{12}Z\.json"
    return {f"{RESULTS_IN_GIT}/{pointer['record']}": pointer["sha256"] for pointer in endings(directory)
            if re.fullmatch(pattern, str(pointer.get("record")))}


def tree_changes(directory=None):
    """FROZEN_TREE_RULE: the lines of git status --porcelain other than the seal ledger modified in place (in the
    worktree, the index or both) and, of the campaign `directory`, the records of its endings it wrote, new or
    modified, each with the sha256 its endings/ names (read in RESULTS)."""
    own = own_records(directory)
    changes = []
    for line in git("status", "--porcelain").splitlines():
        if not line:
            continue
        name, code = line[3:], line[:2]
        if name == LEDGER and code in (" M", "M ", "MM"):
            continue
        if name in own and code in RECORD_CODES:
            path = RESULTS / Path(name).name
            if path.is_file() and digest(path) == own[name]:
                continue
        changes.append(line)
    return changes


class CampaignInvalid(ValueError):
    """INVALID_RULE: the measurement code or the lab changed during a campaign of protocol schema 3."""


def named_files(names):
    """The first NAMED_FILES of `names`, and how many more there are."""
    names = list(names)
    more = len(names) - NAMED_FILES
    return ", ".join(names[:NAMED_FILES]) + (f" and {more} more" if more > 0 else "")


def frozen_hashes(manifest):
    """INVALID_RULE (F2 of the verification of B9b): (what changed, new files) of the measurement code and of the lab
    against the per-file maps init froze into a campaign of protocol schema 3 (FROZEN_MAPS). What changed is None
    while every file of the frozen sets has its frozen content, else the text that names the files changed or gone;
    the new files, beside the frozen sets, change neither (a change of the tree). A campaign.json without the maps is
    refused by name."""
    missing = [key for key, _, _ in FROZEN_MAPS if type(manifest.get(key)) is not dict]
    if missing:
        raise ValueError("campaign.json of protocol schema 3 freezes no " + " and no ".join(missing) + " (init records "
                         "the measurement code and the lab file by file since the fix round of package B9b; "
                         "scripts/campaign.py INVALID_RULE)")
    changed, new = [], set()
    for key, what, function in FROZEN_MAPS:
        frozen, current = manifest[key], getattr(collection, function)()
        names = sorted(name for name in frozen if current.get(name) != frozen[name])  # Changed or gone.
        if names:
            changed.append(f"{what}: {named_files(names)})")
        new.update(set(current) - set(frozen))
    return " and ".join(changed) or None, sorted(new)


def verify_frozen(directory, manifest, p):
    new = []
    if schema3(p):  # INVALID_RULE (package B9b): the frozen hashes before the tree.
        changed, new = frozen_hashes(manifest)
        if changed:
            raise CampaignInvalid(f"{changed} changed during the campaign: a campaign whose measurement code or lab "
                                  "changed is invalid (scripts/campaign.py INVALID_RULE)")
    with ledger_lock():
        head, changes = git("rev-parse", "HEAD"), tree_changes(directory if schema3(p) else None)
    if head != manifest["commit"] or changes or new:
        raise ValueError("campaign source changed; restore frozen commit before resuming"
                         + (" (changed: " + "; ".join(changes[:5]) + ")" if changes else "")
                         # INVALID_RULE (F2): a change of the tree, not of the frozen sets; resumed without them.
                         + (f" (new files beside the frozen measurement code and lab: {named_files(new)}; remove them "
                            "and run again, scripts/campaign.py INVALID_RULE)" if new else ""))
    if (runtime_identity() != manifest["runtime"]
            or tree_hashes(ROOT / p["profile"]) != manifest["profile_sha256"]
            or extractor_hashes() != manifest["extractor_sha256"]):
        raise ValueError("campaign runtime, profile or extractor changed")
    # A missing SSD must stop the run, not redirect it to another disk.
    if "working_storage" in manifest and collection.storage_identity(COLLECTIONS) != manifest["working_storage"]:
        raise ValueError("working storage for data/collections is not the frozen disk")
    # External copy also detects accidental changes to the local immutable plan.
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    external = Path(manifest["archive_dir"])
    for name in frozen_files(manifest):
        if digest(directory / name) != digest(external / name):
            raise ValueError("frozen campaign backup mismatch: " + name)


def update_state(directory, **values):
    if values.get("vm") is None:
        values.pop("vm", None)  # Single-VM campaign: status.json without a VM key, as before.
    path = directory / vm_file("status.json", values.get("vm"))
    previous = read_json(path) if path.exists() else {}
    state = {**previous, **values, "updated_at": now()}
    write_new(path, state, replace=True)
    event = {"schema": "hyptcn3/campaign-event/1", **state}
    write_new(directory / "events" / f"{stamp()}_{uuid.uuid4().hex[:8]}.json", event)
    print(json.dumps({k: state[k] for k in ("updated_at", "vm", "status", "stage", "session", "message")
                      if k in state}), flush=True)


def process_identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return {"host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "start_ticks": text.rsplit(")", 1)[1].split()[19]}
    except OSError:
        return None


def run_child(command, log, *, timeout, guard=lambda: None, lock_fd=None, grace=150):
    env = dict(os.environ)
    env.pop("HYPTCN_COLLECTION_LOCK_FD", None)
    if lock_fd is not None:
        env["HYPTCN_COLLECTION_LOCK_FD"] = str(lock_fd)
    with log.open("x") as stream:
        process = subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   pass_fds=() if lock_fd is None else (lock_fd,))
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                guard()
                if time.monotonic() >= deadline:
                    raise TimeoutError("campaign stage timed out: " + str(log))
                time.sleep(2)
            return process.returncode
        except InterruptedError:
            # One SIGTERM to the child only; it stops its own helpers in order and
            # writes a truthful end record. Group kills below are a last resort.
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
            raise
        finally:
            # A crashed parent script may leave traffic/capture grandchildren.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def hold_sleep_inhibitor():
    """Block sleep while the runner lives; the helper exits when its stdin pipe closes."""
    process = subprocess.Popen(["systemd-inhibit", "--what=sleep:idle", "--mode=block", "--who=hyptcn3 collection",
                                "--why=Preserve the frozen RAM sampling timeline", "cat"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(.5)
    if process.poll() is not None:
        raise ValueError("cannot take the sleep inhibitor lock")
    return process


def release_sleep_inhibitor(process):
    if process is None:
        return
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def sleep_inhibited():
    listing = subprocess.run(["systemd-inhibit", "--list", "--no-pager"], capture_output=True, text=True, timeout=10)
    return "hyptcn3 collection" in listing.stdout


class GroupStartFailed(ValueError):
    """A step of the start of a group of protocol schema 3 failed (GROUP_START_RULE): no session is measured; the
    failure is recorded as the group's start failure (Q22), with `step`, the outputs of the steps before it (`steps`)
    and the log of the failed command (`log`, None where none ran)."""

    def __init__(self, step, detail, log=None):
        super().__init__(f"{step}: {detail}")
        self.step, self.log, self.steps = step, log, []


class GroupStartStop(ValueError):
    """GROUP_START_RULE (Q22): the runner stops by name after a failed start of a group, whose record is `record`
    (groups/<group>.start-failed-<UTC>.json); the campaign ends as stopped with the cause group_start."""

    def __init__(self, text, record):
        super().__init__(text)
        self.record = record


def lab_step(directory, p, verb, *args):
    """One labctl verb of the start of a group, as the VM's owner (GROUP_START_RULE): the JSON objects it printed, in
    order; its whole output stays in logs/. GroupStartFailed names the verb for an exit code other than 0, a timeout
    or a command that cannot start."""
    log = directory / "logs" / f"group-{verb}_{stamp()}.log"
    command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", verb,
                                       *collection.labctl_args(p), *args])
    try:
        rc = run_child(command, log, timeout=GROUP_START_STEPS[verb])
    except (TimeoutError, OSError) as error:
        raise GroupStartFailed(verb, f"{type(error).__name__}: {error}", log) from None
    text = log.read_text(errors="replace") if log.exists() else ""
    if rc:
        raise GroupStartFailed(verb, f"labctl {verb} exited {rc}: " + text.strip()[-CHILD_ERROR_CHARS:], log)
    printed = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if type(value) is dict:
            printed.append(value)
    return printed


def guest_record(printed, verb, schema):
    """The one record of `schema` that labctl `verb` printed (the JSON of lab/guest_state.py), else GroupStartFailed."""
    found = [value for value in printed if value.get("schema") == schema]
    if len(found) != 1:
        raise GroupStartFailed(verb, f"labctl {verb} printed {len(found)} records of {schema}, not one")
    return found[0]


def start_group(directory, manifest, p, row):
    """GROUP_START_RULE: the start of a new group of protocol schema 3, recorded in groups/<group>.json; the group's
    record (identity, qemu) is what every session of the group is checked against, as before."""
    ready = directory / "groups" / (row["group"] + ".json")
    intent = ready.with_name(row["group"] + ".start-intent.json")
    before = collection.qemu_process(p["domain"])
    if not intent.exists():
        write_new(intent, {"group": row["group"], "previous_qemu": before, "date": now()})
    update_state(directory, vm=row.get("vm"), status="running", stage="group-start", group=row["group"])
    steps = []
    try:
        group = start_steps(directory, manifest, p, row, before, steps)
    except GroupStartFailed as failure:  # GROUP_START_RULE (Q22): the outputs of the steps before the failed one.
        failure.steps = steps
        raise
    write_new(ready, group)
    return group


def start_steps(directory, manifest, p, row, before, steps):
    """GROUP_START_RULE: the steps of the start of a group (stop, start, reset, pretouch), each output appended to
    `steps` as it is done; returns the group's record. GroupStartFailed names the step that failed."""

    def identity(step):
        try:
            return collection.guest_identity(p)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            raise GroupStartFailed(step, f"guest identity unavailable ({type(error).__name__}: {error})") from None

    steps.append({"step": "stop", "date": now(), "printed": lab_step(directory, p, "stop")})
    steps.append({"step": "start", "date": now(), "printed": lab_step(directory, p, "start")})
    qemu = collection.qemu_process(p["domain"])
    if qemu is None:
        raise GroupStartFailed("start", "no QEMU process of the domain after labctl start")
    if before is not None and qemu == before:
        raise GroupStartFailed("start", "labctl start left the QEMU process of the previous group (pid "
                                        f"{qemu['pid']}): a group starts with a new one (proposal 5.4)")
    # Way 1 (B5a F4): the record labctl start prints last, qemu_swap, names the QEMU it holds, its cgroup and its way.
    swaps = [value["qemu_swap"] for value in steps[-1]["printed"] if type(value.get("qemu_swap")) is dict]
    if not swaps:
        raise GroupStartFailed("start", "labctl start printed no qemu_swap record (the pid, cgroup and way of its QEMU)")
    swap = swaps[-1]
    if swap.get("qemu_pid") != qemu["pid"]:
        raise GroupStartFailed("start", f"labctl start's qemu_swap record names QEMU pid {swap.get('qemu_pid')!r}, "
                                        f"not the domain's QEMU process {qemu['pid']}")
    if (swap.get("way"), swap.get("temporary")) != ("unit", False):
        raise GroupStartFailed("start", f"labctl start holds the QEMU by way {swap.get('way')!r} (temporary "
                                        f"{swap.get('temporary')!r}): a group starts by way 1, the session daemon in its "
                                        "unit (finding F4 of B5a: way 2 moves the process, not its memory)")
    steps[-1].update(qemu=qemu, cgroup=swap.get("cgroup"))
    current = identity("start")
    if guest_environment(current) != manifest["guest_environment"]:
        raise GroupStartFailed("start", "new group requires a new boot with the frozen guest environment")
    for _, existing in collection.session_records(COLLECTIONS):
        if existing["guest_before"]["boot_id"] == current["boot_id"]:
            raise GroupStartFailed("start", "new group boot already belongs to another session")
    seed = protocol_v5.reset_seed(p)  # GROUP_START_RULE: the protocol's one seeded level (agent P, F4 of B9a).
    reset = guest_record(lab_step(directory, p, "reset", "--seed", str(seed)), "reset", "hyptcn3/guest-reset/1")
    if reset.get("seed") != seed:
        raise GroupStartFailed("reset", f"the guest reset to seed {reset.get('seed')!r}, not {seed}")
    steps.append({"step": "reset", "date": now(), "seed": seed, "output": reset})
    pretouch = guest_record(lab_step(directory, p, "pretouch"), "pretouch", "hyptcn3/guest-pretouch/1")
    if pretouch.get("touched") is not True:
        raise GroupStartFailed("pretouch", "the pretouch did not touch the memory of the largest event")
    steps.append({"step": "pretouch", "date": now(), "output": pretouch})
    if identity("pretouch") != current:
        raise GroupStartFailed("pretouch", "the guest identity changed during the reset or the pretouch")
    if collection.qemu_process(p["domain"]) != qemu:
        raise GroupStartFailed("pretouch", "the QEMU process changed during the reset or the pretouch")
    group = {"schema": "hyptcn3/campaign-group/1", "date": now(), "group": row["group"],
             **({"vm": row["vm"], "domain": p["domain"]} if "vm" in row else {}),
             "role": row["role"], "identity": current, "qemu": qemu, "previous_qemu": before,
             "start": {"rule": GROUP_START_RULE, "reset_seed": seed, "steps": steps}}
    return group


def ensure_group(directory, manifest, p, row):
    ready = directory / "groups" / (row["group"] + ".json")
    if schema3(p) and not ready.exists():
        return start_group(directory, manifest, p, row)
    current = collection.guest_identity(p)
    if guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("guest environment changed")
    if ready.exists():
        group = read_json(ready)
        if group.get("vm") != row.get("vm"):
            raise ValueError("group belongs to another VM")
        if current != group["identity"]:
            raise ValueError("boot changed inside a group; preserve partial allocation for review")
        # A save/restore keeps the guest boot ID; the QEMU process shows it.
        qemu = collection.qemu_process(p["domain"])
        if qemu != group.get("qemu"):
            raise ValueError(("VM process not found" if qemu is None else
                              "VM process changed inside a group (restart or restore)")
                             + "; preserve partial allocation for review")
        return group
    intent = ready.with_suffix(".reboot-intent.json")
    if intent.exists():
        before = read_json(intent)["previous_boot"]
    else:
        before = current["boot_id"]
        write_new(intent, {"group": row["group"], "previous_boot": before, "date": now()})
    update_state(directory, vm=row.get("vm"), status="running", stage="reboot", group=row["group"])
    if current["boot_id"] == before:
        command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", "reboot",
                                           *collection.labctl_args(p)])
        rc = run_child(command, directory / "logs" / f"reboot_{stamp()}.log", timeout=240)
        if rc:
            raise ValueError("lab reboot failed; see campaign reboot log")
        current = collection.guest_identity(p)
    if current["boot_id"] == before or guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("new group requires a new boot with the frozen guest environment")
    for _, existing in collection.session_records(COLLECTIONS):
        if existing["guest_before"]["boot_id"] == current["boot_id"]:
            raise ValueError("new group boot already belongs to another session")
    qemu = collection.qemu_process(p["domain"])
    if qemu is None:
        raise ValueError("VM process not found after the group reboot")
    group = {"schema": "hyptcn3/campaign-group/1", "date": now(), "group": row["group"],
             **({"vm": row["vm"], "domain": p["domain"]} if "vm" in row else {}),
             "role": row["role"], "identity": current, "qemu": qemu, "previous_boot": before}
    write_new(ready, group)
    return group


ABSENT = object()  # A key a session.json does not have.


def planned_items(p, row):
    """What session.json must hold of the events and controls of an attempt (B3 S6): the row's events wherever the
    protocol plans events (scripts/collection.py run records them whenever it has an events section, [] for a row
    without), and of a row with controls those the deck filled (an empty slot is not run); ABSENT where none."""
    events = row.get("events", []) if "events" in p else ABSENT
    controls = [x for x in row["controls"] if x.get("kind") is not None] if "controls" in row else ABSENT
    return {"events": events, "controls": controls}


def check_session(path, manifest, row, directory, p):
    meta = read_json(path / "session.json")
    for k in ("role", "group", "scenario", "seed", "session_id"):
        if meta[k] != row[k]:
            raise ValueError("session differs from frozen assignment: " + k)
    if meta.get("vm") != row.get("vm"):
        raise ValueError("session differs from frozen assignment: vm")
    if meta.get("replaces") != row.get("replaces"):
        raise ValueError("session differs from frozen assignment: replaces")
    if schema3(p):  # REPLACEMENT_RULE: the attempt and the plan it was drawn from.
        for key, expected in (("attempt", row["attempt"]), ("plan_mode", manifest["mode"])):
            if meta.get(key) != expected:
                raise ValueError("session differs from frozen assignment: " + key)
    # B3 S6: the events and controls the capture ran are those of the plan's row or of its replacement's.
    for key, expected in planned_items(p, row).items():
        if meta.get(key, ABSENT) != expected:
            raise ValueError("session differs from frozen assignment: " + key)
    # Measurement sources, not the whole worktree: a note written meanwhile is not a different capture.
    if (meta.get("campaign_id") != manifest["id"] or meta["commit"] != manifest["commit"]
            or meta.get("measurement_dirty") != [] or meta["protocol_sha256"] != manifest["protocol_sha256"]
            or guest_environment(meta["guest_before"]) != manifest["guest_environment"]):
        raise ValueError("session provenance differs from frozen campaign")
    group = read_json(directory / "groups" / (row["group"] + ".json"))
    if meta["guest_before"] != group["identity"]:
        raise ValueError("session boot differs from recorded campaign group")
    if meta.get("host_context", {}).get("qemu") != group.get("qemu"):
        raise ValueError("session VM process differs from recorded campaign group")
    end = read_json(path / "end.json") if (path / "end.json").exists() else {}
    return bool(end.get("completed") and end.get("guest_after") == meta["guest_before"])


def audit_environment(doc, manifest):
    """The verdict came from the frozen code; files outside measurement sources do not matter."""
    v = doc["values"]
    return (doc["commit"] == manifest["commit"] and doc.get("measurement_dirty") == []
            and v["protocol_sha256"] == manifest["protocol_sha256"]
            and v["extractor_sha256"] == manifest["extractor_sha256"])


def audit_capture(directory, manifest, p, row, session, guard):
    pointer = directory / "attempts" / (row["session_id"] + ".audit.json")
    if pointer.exists():
        selected = read_json(pointer)
        report = Path(selected["path"])
        if digest(report) != selected["sha256"]:
            raise ValueError("selected audit changed")
    else:
        # Recover a completed verdict if interrupted before pointer publication.
        reports = sorted(session.glob("campaign_audit_*.json"))
        complete = []
        for report in reports:
            try:
                doc = read_json(report)
            except json.JSONDecodeError:
                continue  # Interrupted write retained; next attempt uses a new path.
            if doc.get("schema") != "hyptcn3/collection-audit/1":
                continue
            if audit_environment(doc, manifest):
                complete.append(report)
            else:
                # Written while HEAD or measurement code differed: kept, never selected.
                # The frozen tree was verified before this call, so a new audit is valid.
                update_state(directory, vm=row.get("vm"), status="running", stage="audit", session=session.name,
                             message="ignored audit made from a changed source tree: " + report.name)
        if len(complete) > 1:
            raise ValueError("multiple campaign audit verdicts require review")
        if complete:
            report = complete[0]
        else:
            report = session / f"campaign_audit_{stamp()}.json"
            update_state(directory, vm=row.get("vm"), status="running", stage="audit", session=session.name,
                         message=None)
            command = collection.background_command(collection.user_command(
                [sys.executable, ROOT / "scripts/collection.py", "--protocol", directory / "protocol.json",
                 "audit", session, "--out", report]))
            rc = run_child(command, directory / "logs" / f"audit_{stamp()}.log",
                           timeout=max(600, p["cycles"] * 15), guard=guard)
            if rc not in (0, 2) or not report.exists():
                raise ValueError("audit did not produce a verdict; see campaign log")
    doc = read_json(report)
    v = doc["values"]
    if (not audit_environment(doc, manifest)
            or v["session_dir"] != str(session) or v["role"] != row["role"]
            or v["session_sha256"] != digest(session / "session.json")
            or digest(v["features"]) != v["features_sha256"]):
        raise ValueError("audit provenance differs from campaign/session")
    if not pointer.exists():
        write_new(pointer, {"path": str(report), "sha256": digest(report)})
    return report, v


def ended_before_measurement(session):
    """An attempt without measured phase or RAM image (failed preflight/warmup or a stop there)."""
    raw = session / "raw"
    # An archived session keeps raw/ as a link; it may dangle once the archive was moved
    # off this machine (owner decision 2026-11-14), which is not "no RAM image".
    if not session.is_dir() or raw.exists() or raw.is_symlink():
        return False
    if not (session / "session.json").exists():
        return not (session / "end.json").exists()  # Failed while preparing its metadata.
    end = session / "end.json"
    return end.exists() and read_json(end).get("measurement_started") is False


def retire_attempt(directory, manifest, row, session):
    """Keep an attempt that never measured under a numbered name, so the assignment can run again."""
    meta = read_json(session / "session.json") if (session / "session.json").exists() else None
    if meta is not None and (meta.get("campaign_id"), meta.get("session_id")) != (manifest["id"], row["session_id"]):
        raise ValueError("unexpected metadata in assignment directory: " + str(session))
    end = read_json(session / "end.json") if (session / "end.json").exists() else {}
    reason = end.get("error") or ("no session metadata" if meta is None else "no error recorded")
    numbers = [int(n) for n in (p.name.rsplit("-", 1)[1] for p in session.parent.glob(session.name + ".attempt-*"))
               if n.isdigit()]
    number = max(numbers, default=0) + 1
    target = session.with_name(f"{session.name}.attempt-{number}")
    os.rename(session, target)
    sync_dir(session.parent)
    write_new(directory / "attempts" / f"{session.name}.attempt-{number}.json",
              {"schema": "hyptcn3/campaign-attempt/1", "session": session.name, "attempt": number,
               "directory": str(target), "reason": reason, "date": now(),
               "note": "Ended before the measured phase without a RAM image; the assignment runs again "
                       "in the same group boot. Kept for review, not part of the corpus."})
    update_state(directory, vm=row.get("vm"), status="running", stage="retry", session=session.name,
                 message=f"attempt {number} ended before measurement: {reason}")


STOP_MESSAGE = {"audit_rejected": "audit rejected session; archived without replacement",
                "capture_incomplete": "incomplete capture archived; allocation stopped, no automatic replacement",
                "group_start": "the start of the group failed before the measured phase; the campaign stopped, a run "
                               "after the cause is removed starts the group again (Q22)"}


def incomplete_reasons(session):
    """Why a capture that reached its measured phase did not complete, from its own end record."""
    if not (session / "end.json").exists():
        return ["no end.json: the capture recorded no end (crash, SIGKILL or power loss)"]
    end = read_json(session / "end.json")
    if end.get("error"):
        return [str(end["error"])]
    return ["guest identity changed during capture" if end.get("completed") else "end.json completed=false"]


def group_boot_lost(directory, p, row):
    """None while the group's boot still exists (same guest boot, same QEMU process), else why not."""
    group = read_json(directory / "groups" / (row["group"] + ".json"))
    try:
        current = collection.guest_identity(p)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return f"guest identity unavailable ({type(exc).__name__})"
    if current != group["identity"]:
        return "guest boot or environment changed since the group started"
    if collection.qemu_process(p["domain"]) != group.get("qemu"):
        return "VM process changed since the group started (restart or restore)"
    return None


def reject(directory, manifest, p, row, cause, reasons, report=None):
    """Record a session the campaign cannot use, with its cause; schedule its replacement if the
    protocol's rule allows.

    cause: "audit_rejected" (completed capture, rejecting audit; report = that audit) or
    "capture_incomplete" (the measured phase started, the capture did not complete). A failed start
    of a group is no rejection of a session (GROUP_START_RULE, question Q22 decided by its proposal):
    it is recorded as groups/<group>.start-failed-<UTC>.json, never passed here, nothing is replaced
    or charged to the limit, and no protocol may cover group_start, because
    collection.check_replacement admits in replacement.covers only REPLACEMENT_CAUSES
    (audit_rejected, capture_incomplete); the runner stops by name, the campaign ends as stopped with
    the cause group_start, and a resumed run starts the group again. The rule is part of the
    frozen protocol (collection.check_replacement): which causes it covers and one maximum per
    campaign shared by all of them. The replacement is the
    same assignment - VM, role, group, scenario, seed, event schedule - captured again in the same
    boot of its group, right after the unusable session and before the group's next one. So a group
    stays one boot of one VM and the corpus still holds each group/scenario once: the unusable
    session is archived and kept, but never indexed. Under protocol schema 3 the replacement is the
    next attempt of its planned row (REPLACEMENT_RULE: new times and traffic seed), and the maximum
    holds in mode campaign only (LIMIT_RULE: in mode rehearsal it is not applied); the rejections are
    counted by cause in the state (rejections_by_cause).

    An incomplete capture is replaced only while that boot still exists: the guest identity
    and the QEMU process equal groups/<group>.json. After a guest reboot, a VM restart or a
    host crash there is no "same group boot" to capture in; a new boot under the same group
    would break one boot per group, so the allocation stops as before, for review.

    Called under the audit lock, so the per-campaign count is exact over all VMs. Returns the
    replacement row or None (cause not covered, maximum used up, boot lost, or under schema 3 a next
    attempt protocol_v5.replacement cannot draw, its OutsideDeck named: the caller stops). Under
    protocol schema 3 a rejection the used-up maximum refuses names in its record the ending it brings
    (package B9b): paused (PAUSE_RULE), or invalid inside a continuation (INVALID_RULE).
    """
    rule = p.get("replacement") or {}
    applied, limit = replacement_limit(manifest, p)
    used = sum(r.get("replacement") is not None for r in rejections(directory))
    plan_session, number = row.get("plan_session", row["session_id"]), row.get("replacement", 0) + 1
    ending = None
    if cause not in rule.get("covers", collection.REPLACEMENT_CAUSES[:1] if rule else ()):
        refused = "the protocol has no replacement rule for this cause"
    elif applied and used >= limit:
        refused = f"the protocol's {limit} replacements per campaign are used up"
        if schema3(p):  # PAUSE_RULE; a second exhaustion inside a continuation, INVALID_RULE.
            ending = "invalid" if "continues" in manifest else "paused"
    else:
        refused = group_boot_lost(directory, p, row) if cause == "capture_incomplete" else None
    drawn = None
    if not refused:  # REPLACEMENT_RULE: the next attempt is drawn before the record names it.
        planned = next(r for r in manifest["sessions"] if r["session_id"] == plan_session)
        try:
            drawn = attempt_row(manifest, p, {**planned, "session_id": f"{plan_session}-r{number}",
                                              "replaces": row["session_id"], "plan_session": plan_session,
                                              "replacement": number})
        except protocol_v5.OutsideDeck as error:  # An item outside the protocol's deck (S5 of B4), by name.
            refused = f"its next attempt cannot be drawn: {error}"
    replacement = None if refused else f"{plan_session}-r{number}"
    write_new(rejection_file(directory, row["session_id"]), {
        "schema": "hyptcn3/campaign-rejection/1", "date": now(), "session": row["session_id"],
        **{k: row[k] for k in ("vm", "role", "group", "scenario", "seed", "replaces", "attempt") if k in row},
        "cause": cause, "reasons": reasons,
        **({} if report is None else {"audit": str(report), "audit_sha256": digest(report)}),
        "replacement": replacement, "replacements_before": used, "max_per_campaign": limit,
        **({"limit_applied": applied, "plan_mode": manifest["mode"]} if schema3(p) else {}),
        **({"not_replaced": refused} if refused else {}),
        **({"ending": ending} if ending else {}),
        "note": "Archived, never part of the corpus or event index. "
                + (("Replaced by the next attempt of the same assignment (protocol replacement rule, "
                    "scripts/campaign.py REPLACEMENT_RULE)." if schema3(p) else
                    "Replaced by the same assignment in the same group boot (protocol replacement rule).")
                   if replacement else "Not replaced; allocation stopped.")})
    counts = rejections_by_cause(directory)  # LIMIT_RULE: in the state of the runner, every VM's rejections.
    if replacement is None:
        update_state(directory, vm=row.get("vm"), status="running", stage="rejected", session=row["session_id"],
                     rejections_by_cause=counts, message=f"{cause} ({'; '.join(reasons)}); not replaced: {refused}")
        return None
    update_state(directory, vm=row.get("vm"), status="running", stage="replacement", session=row["session_id"],
                 replacements_used=used + 1, rejections_by_cause=counts,
                 message=f"{cause} ({'; '.join(reasons)}); replacement {used + 1} "
                         + (f"of {limit}" if applied else "(the limit is not applied in mode rehearsal)")
                         + ": " + replacement)
    return drawn


def take_stop_request(directory, vm=None):
    """Consume a request to stop before the next capture: the request (an operator's, or under protocol schema 3 one
    another runner's trigger of an ending wrote, ENDING_RULE), None when there is none. A request that is empty or no
    JSON object is honored as an operator's without a reason (a true value, as before package B9b)."""
    request = directory / vm_file("stop-request.json", vm)
    if not request.exists():
        return None
    try:
        doc = read_json(request)
    except (OSError, ValueError):
        doc = None
    os.replace(request, directory / "events" / f"{stamp()}_{request.name}")
    sync_dir(directory)
    return doc if type(doc) is dict and doc else {"note": "an empty or unreadable request, honored as an operator's"}


class Stop(str):
    """A reason to stop between sessions (the text, as before): `request`, the stop request the runner honored (None
    for another reason), and `waited`, what the barrier of ORDER_RULE held the runner for (None outside it)."""

    def __new__(cls, text, *, request=None, waited=None):
        self = super().__new__(cls, text)
        self.request, self.waited = request, waited
        return self


def stop_text(request):
    """The reason of a stop for a request a runner honored: an operator's ("operator stop request", as before), or
    under protocol schema 3 the ending another runner's trigger began (ENDING_RULE)."""
    if "ending" in request:
        return (f"the campaign is ending ({request['ending']}, VM {request.get('by')}: {request.get('cause')}): this "
                "runner stopped at its next check")
    return "operator stop request"


def operator_reason(request):
    """The reason an operator's stop request names (request-stop --reason), else None."""
    reason = request.get("reason")
    return reason if type(reason) is str and reason.strip() else None


def earlier_roles(directory, manifest, p, row):
    """Other VMs' sessions of roles of a lower time rank than this row's role (ORDER_RULE: protocol_v5.TIME_RANK,
    the two test roles share a rank) that are not archived yet."""
    rank = time_rank(p)
    return [r for r in manifest["sessions"] if r.get("vm") != row.get("vm")
            and rank[r["role"]] < rank[row["role"]] and not finished(directory, manifest, r)]


def interleaved_with(p, role):
    """ORDER_RULE: the list of p["interleave"] (a key protocol schema 3 requires, protocol_v5 TOP_LEVEL) that holds
    `role`, () for a role in none of them."""
    return next((tuple(together) for together in p["interleave"] if role in together), ())


def group_started(directory, manifest, group):
    """ORDER_RULE: whether a group has started: its record groups/<group>.json exists (under protocol schema 3
    start_group writes it after the pretouch), or a continuation took the group over from its closed campaign (as a
    whole)."""
    return ((Path(directory) / "groups" / (group + ".json")).exists()
            or any(r["group"] == group and taken_over(manifest, r) is not None for r in manifest["sessions"]))


def earlier_groups(directory, manifest, p, row):
    """ORDER_RULE under protocol schema 3: the groups of the roles interleaved with this row's role that precede its
    group in the plan (manifest["sessions"], the time order of protocol_v5.plan) on the other VMs and have not started,
    each as the first row of its group in the plan; [] once the row's own group has started, for a role without
    interleave and under schemas 1 and 2."""
    together = interleaved_with(p, row["role"]) if schema3(p) else ()
    if not together or group_started(directory, manifest, row["group"]):
        return []
    before, seen = [], set()
    for r in manifest["sessions"]:
        if r["group"] == row["group"]:
            break
        if r["role"] in together and r.get("vm") != row.get("vm") and r["group"] not in seen:
            seen.add(r["group"])
            if not group_started(directory, manifest, r["group"]):
                before.append(r)
    return before


def wait_message(row, pending, groups):
    """What a runner waits for (ORDER_RULE): the VMs that have not finished the roles of an earlier rank, and the groups
    before its group in the plan that have not started, by VM."""
    parts = []
    if pending:
        parts.append("earlier roles on: " + ", ".join(sorted({r["vm"] for r in pending})))
    if groups:
        parts.append(f"the start of the groups before {row['group']} in the plan: " + ", ".join(
            f"{r['group']} (VM {r['vm']})" for r in groups))
    return "waiting for " + "; ".join(parts)


def wait_for_earlier_roles(directory, manifest, p, row):
    """Keep the time order of the plan across VMs, not only inside each VM (ORDER_RULE).

    features/dataset.py accepts a corpus only if all train sessions end before
    the first dev session starts, and so on (chronology by protocol_v5.TIME_RANK).
    Each VM takes its groups in plan order; before the first group of a role of a
    later rank this runner waits until the other VMs have finished every role of
    an earlier rank, and under protocol schema 3 before a group of an interleaved
    role until the other VMs have started every group of those roles that precedes
    it in the plan (earlier_groups). Returns a reason to stop instead (operator
    request, or the other runner is not running and nobody would end the wait),
    else None. The state names what the runner waits for. The reason is a Stop:
    it carries the stop request the runner honored, the operator's or under
    protocol schema 3 another runner's trigger of an ending (package B9b: a pause
    ends this wait too, PAUSE_RULE), and what the runner was held for.
    """
    shown, grace = None, time.monotonic() + START_GRACE_S
    while True:
        pending, groups = earlier_roles(directory, manifest, p, row), earlier_groups(directory, manifest, p, row)
        if not pending and not groups:
            return None
        message = wait_message(row, pending, groups)
        request = take_stop_request(directory, row["vm"])
        if request is not None:
            return Stop(stop_text(request), request=request, waited=message)
        for vm in sorted({r["vm"] for r in pending + groups}):
            path = directory / vm_file("status.json", vm)
            if not campaign_running(read_json(path) if path.exists() else {}) and time.monotonic() >= grace:
                if any(r["vm"] == vm for r in pending):
                    return Stop(f"VM {vm} has not finished the roles before {row['role']} and its runner is not "
                                "active", waited=message)
                return Stop(f"VM {vm} has not started the groups before {row['group']} in the plan ("
                            + ", ".join(r["group"] for r in groups if r["vm"] == vm) + ") and its runner is not active",
                            waited=message)
        if message != shown:
            update_state(directory, vm=row["vm"], status="running", stage="role-wait", group=row["group"],
                         role=row["role"], message=message)
            shown = message
        time.sleep(WAIT_POLL_S)


def archive_capture(directory, manifest, session, p, audit=None):
    update_state(directory, vm=manifest.get("vm"), status="running", stage="archive", session=session.name)
    destination = Path(manifest["archive_dir"]) / "collections" / manifest.get("vm", "") / session.name
    guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
    return archive_session(session, destination, guard, reclaim=True, campaign_id=manifest["id"],
                           audit=audit, reserve_bytes=p["min_free_gib"] * 2**30,
                           compress=manifest.get("archive_compression"))


def seal_session(directory, manifest, row, report):
    """SEAL_RULE: one accepted session of a sealed role written into the seal ledger right away, as the campaign's
    owner, by the per-session form of the ledger's command line; returns its result. Its refusal keeps the child's
    error text."""
    update_state(directory, vm=row.get("vm"), status="running", stage="seal", session=row["session_id"],
                 message=None)
    log = directory / "logs" / f"seal_{stamp()}.log"
    command = collection.user_command([sys.executable, "-m", "tcn.pecat", "zapis", "--audit", report,
                                       "--mode", manifest["mode"]])
    rc = run_child(command, log, timeout=SEAL_TIMEOUT_S)
    text = log.read_text(errors="replace") if log.exists() else ""
    if rc:
        raise ValueError(f"the seal of session {row['session_id']} was refused (python -m tcn.pecat zapis exit {rc}): "
                         + text.strip()[-CHILD_ERROR_CHARS:])
    try:
        result = json.loads(text)
        sealed = {*result["written"], *result["already"]}
    except (ValueError, KeyError, TypeError):
        raise ValueError(f"the seal of session {row['session_id']}: python -m tcn.pecat zapis printed no result "
                         f"(see {log})") from None
    if read_json(report)["values"]["features_sha256"] not in sealed:
        raise ValueError(f"the seal of session {row['session_id']}: the ledger holds no record of its feature archive "
                         f"after zapis (see {log})")
    return result


# ------------------------------------------------------------------ the endings (package B9b, agent R)

NOBODY = object()  # ENDING_RULE: the trigger of an operator's command (launch), no runner of the campaign.
POINTER_SCHEMA = "hyptcn3/campaign-ending-name/1"  # endings/<stamp>_<ending>.json: a record's name and sha256.
PENDING_SCHEMA = "hyptcn3/campaign-ending-pending/1"  # ending.json: the pending ending and its triggers.


@contextmanager
def ending_lock(directory):
    """ENDING_RULE: one change of the ending of a campaign at a time over its runners and commands (an exclusive flock
    of the campaign directory, held while a last state, a trigger or a record is written; never nested)."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


@contextmanager
def results_lock():
    """ENDING_RULE and FROZEN_TREE_RULE: a record is written into RESULTS under the lock of that directory, the one
    under which tcn/pecat.py writes the ledger and verify_frozen runs git status (ledger_lock), so that no temporary
    file of a record is seen as a change."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(RESULTS, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def endings(directory):
    """ENDING_RULE: the recorded endings of a campaign, oldest first, from endings/ of its directory: {schema, ending,
    cause, record (its name in RESULTS), sha256, date, pending (the id of the pending ending it recorded)}."""
    folder = Path(directory) / "endings"
    return [read_json(path) for path in sorted(folder.glob("*.json"))] if folder.is_dir() else []


def latest_ending(directory):
    """ENDING_RULE: the last recorded ending of a campaign, None before any."""
    found = endings(directory)
    return found[-1] if found else None


def pending_ending(directory):
    """ENDING_RULE: the pending ending of a campaign (ending.json: its kind, cause and triggers), else None."""
    path = Path(directory) / "ending.json"
    return read_json(path) if path.exists() else None


def held_ending(directory):
    """PAUSE_RULE and INVALID_RULE: "invalid" or "paused" when the campaign holds that ending, pending or the last one
    recorded, else None."""
    kinds = {doc["ending"] for doc in (pending_ending(directory), latest_ending(directory)) if doc}
    return next((kind for kind in ("invalid", "paused") if kind in kinds), None)


def refuse_held(directory, verb):
    """PAUSE_RULE, INVALID_RULE and ENDING_RULE: a run or a launch of a paused or an invalid campaign is refused by
    name, and so is one while an ending is pending (another runner is still active; settle came first)."""
    name, kind, pending = Path(directory).name, held_ending(directory), pending_ending(directory)
    if kind == "paused":
        raise ValueError(f"campaign {name} is paused: it does not {verb} again; continue it once with init --continue "
                         f"{directory} --cause TEXT (scripts/campaign.py PAUSE_RULE, CONTINUATION_RULE)")
    if kind == "invalid":
        raise ValueError(f"campaign {name} is invalid: it does not {verb} again, has no corpus and is never continued "
                         "(scripts/campaign.py INVALID_RULE)")
    if pending is not None:
        raise ValueError(f"campaign {name} is ending ({pending['ending']}: {pending['cause']}): its other runner stops "
                         f"at its next check; {verb} it again once that ending is recorded (scripts/campaign.py "
                         "ENDING_RULE)")


def index_built(directory, protocol):
    """ENDING_RULE (F3): whether the index of the campaign is built, the last step of finish_corpus (the state complete
    at the stage complete of the runner that built it)."""
    for vm in vm_names(protocol):
        path = Path(directory) / vm_file("status.json", vm)
        state = read_json(path) if path.exists() else {}
        if state.get("status") == "complete" and state.get("stage") == "complete":
            return True
    return False


def refuse_ended(directory, protocol, verb):
    """ENDING_RULE (F3 of the verification of B9b): a run or a launch of a campaign whose last recorded ending is
    closed, or complete with its index built, is refused by name before verify_frozen, so that it writes no ending and
    no record (the records and the ledger are committed after that ending, which moves HEAD). A complete ending whose
    runner died before its index was built runs again and builds it (the fix round's interpretation)."""
    name, latest = Path(directory).name, latest_ending(directory)
    if latest is None:
        return
    if latest["ending"] == "closed":
        raise ValueError(f"campaign {name} was closed by the operator (record {latest['record']}): it does not {verb} "
                         "again (scripts/campaign.py ENDING_RULE)")
    if latest["ending"] == "complete" and index_built(directory, protocol):
        raise ValueError(f"campaign {name} is complete (record {latest['record']}) and its index is built: it does "
                         f"not {verb} again (scripts/campaign.py ENDING_RULE)")


def write_deviation(directory, kind, vm, doc):
    """ENDING_RULE and RESUME_RULE (F6): deviations/<UTC>_<kind>[_<vm>].json of the campaign directory, a deviation
    that is no ending; every later record lists it (deviation_events). Returns its path."""
    folder = Path(directory) / "deviations"
    folder.mkdir(exist_ok=True)
    path = folder / (f"{stamp()}_{kind}" + ("" if vm is None else f"_{vm}") + ".json")
    write_new(path, {"schema": DEVIATION_SCHEMA, "deviation": kind, "date": now(), "vm": vm, **doc})
    return path


def unclean_end(directory, vm, previous):
    """ENDING_RULE (F6 of the verification of B9b): the run that finds its VM's previous state running while the lock
    was free (SIGKILL, a crash, a power loss) writes deviations/<UTC>_unclean-end_<vm>.json before it resumes: the VM,
    that state with its stage, session and updated_at, and the time of the finding. A deviation and not an ending: the
    other VM's runner may have gone on."""
    return write_deviation(directory, "unclean-end", vm, {
        "previous": {key: previous.get(key) for key in ("status", "stage", "session", "group", "updated_at", "pid")},
        "note": "The runner of this VM ended without a final status; its session is incomplete. Recorded by the next "
                "run of the VM before it resumed (scripts/campaign.py ENDING_RULE)."})


def early_stop_triggers(pointer, what):
    """EARLY_STOP_RULE and RESUME_RULE, one reading for both (the restart point of the count, early_stop_restart, and
    the written cause of a resume, early_stop_record): the early-stop triggers of the recorded ending `pointer` (of
    endings/), a trigger whose detail holds early_stop, read from its record in RESULTS. ValueError by name for a
    record that is missing or has another sha256 than endings/ names: `what` cannot be told then."""
    path = RESULTS / pointer["record"]
    if not path.is_file() or digest(path) != pointer["sha256"]:
        raise ValueError(f"the record {path} of the ending {pointer['ending']} of {pointer['date']} is missing or "
                         f"has another sha256 than endings/ names, so {what} cannot be told")
    triggers = (read_json(path).get("values") or {}).get("triggers") or []
    return [t for t in triggers if type(t) is dict and type(t.get("detail")) is dict and t["detail"].get("early_stop")]


def early_stop_record(directory):
    """RESUME_RULE: (pointer, its early-stop triggers) of the campaign's last recorded ending when it is a stopped
    ending with an early stop among its triggers (early_stop_triggers, the reading of EARLY_STOP_RULE's restart
    point), else None. The record missing, or with another sha256 than its endings/ names, is refused by name."""
    latest = latest_ending(directory)
    if latest is None or latest["ending"] != "stopped":
        return None
    triggers = early_stop_triggers(latest, "whether its stop needs a written cause (scripts/campaign.py RESUME_RULE)")
    return (latest, triggers) if triggers else None


def answer_early_stop(directory, vm, cause, verb, command):
    """RESUME_RULE (F6 of the verification of B9b, HARNESS chapter 7): before a run or a launch of a campaign whose
    last recorded ending is an early stop, the written cause of the resume. Refused by name without --cause unless a
    deviation already answers that record; with it, deviations/<UTC>_resume-after-early-stop_<vm>.json answers it (vm
    None: a launch of every VM). An empty --cause, and --cause when the last recorded ending is no early stop, are
    refused by name. Returns the path written, else None."""
    name = Path(directory).name
    if cause is not None and (type(cause) is not str or not cause.strip()):
        raise ValueError(f"{verb} --cause is empty: the written analysis of the early stop is required (no default; "
                         "scripts/campaign.py RESUME_RULE)")
    found = early_stop_record(directory)
    if found is None:
        if cause is not None:
            raise ValueError(f"--cause answers an early stop, and the last recorded ending of campaign {name} is no "
                             f"early stop: {verb} it without --cause (scripts/campaign.py RESUME_RULE)")
        return None
    latest, _ = found
    answers = {"record": latest["record"], "sha256": latest["sha256"]}
    if cause is None:
        if any(doc.get("deviation") == "resume-after-early-stop" and {key: (doc.get("answers") or {}).get(key)
                                                                      for key in answers} == answers
               for _, doc in deviation_records(directory)):
            return None
        raise ValueError(f"campaign {name} stopped early ({latest['cause']}; record {latest['record']}): an early "
                         f"stop is a stop and a question (HARNESS chapter 7); {verb} it again with --cause TEXT, the "
                         "written analysis of its cause, which every later record lists among its deviations "
                         "(scripts/campaign.py RESUME_RULE)")
    return write_deviation(directory, "resume-after-early-stop", vm, {
        "answers": {**answers, "cause": latest["cause"]}, "cause": cause, "command": command,
        "note": "The written analysis of an early stop, before the campaign runs again (scripts/campaign.py "
                "RESUME_RULE)."})


def deviation_records(directory):
    """ENDING_RULE (F6): [(name, doc)] of deviations/ of the campaign directory, oldest first; a file that cannot be
    read is kept with its reason ({"unreadable": ...}), never left out."""
    folder = Path(directory) / "deviations"
    found = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            doc = read_json(path)
        except (OSError, ValueError) as error:
            doc = {"unreadable": f"{type(error).__name__}: {error}"}
        found.append((path.name, doc if type(doc) is dict else {"unreadable": "not a JSON object"}))
    return found


def active_runners(directory, protocol, but=NOBODY):
    """ENDING_RULE: the VMs of a campaign whose runner is active (its status running, its process alive), but the VM
    `but` (the runner that asks; NOBODY: none is left out)."""
    found = []
    for vm in vm_names(protocol):
        if but is not NOBODY and vm == but:
            continue
        path = Path(directory) / vm_file("status.json", vm)
        if path.exists() and campaign_running(read_json(path)):
            found.append(vm)
    return found


def begin_ending(directory, protocol, vm, kind, cause, detail=None):
    """ENDING_RULE: a trigger of a paused, stopped or invalid ending, met by the runner of `vm` (NOBODY: an operator's
    command). The ending is pending in ending.json with every trigger in order, the heavier kind holding (PENDING), and
    every other active runner gets its stop request, so that it stops at its next check; the record follows once the
    campaign is at rest (end_run, settle). Returns the pending ending."""
    directory = Path(directory)
    with ending_lock(directory):
        path = directory / "ending.json"
        pending = read_json(path) if path.exists() else {
            "schema": PENDING_SCHEMA, "id": uuid.uuid4().hex, "ending": kind, "cause": cause, "date": now(),
            "triggers": []}
        if PENDING[kind] > PENDING[pending["ending"]]:
            pending.update(ending=kind, cause=cause)
        pending["triggers"].append({"date": now(), "vm": None if vm is NOBODY else vm, "ending": kind,
                                    "cause": cause, "detail": detail})
        write_new(path, pending, replace=True)
        for other in active_runners(directory, protocol, but=vm):
            try:
                write_new(directory / vm_file("stop-request.json", other), {
                    "schema": "hyptcn3/campaign-stop-request/1", "date": now(), "uid": os.getuid(),
                    **({} if other is None else {"vm": other}), "ending": pending["ending"],
                    "by": None if vm is NOBODY else vm, "cause": pending["cause"],
                    "note": "Written by the trigger of an ending (scripts/campaign.py ENDING_RULE): this runner stops "
                            "at its next check, as part of that ending."})
            except FileExistsError:
                pass  # A request is there already: the runner stops at its next check all the same.
    return pending


def end_run(directory, campaign, protocol, vm, *, command, status, stage, message, **state):
    """ENDING_RULE: the last state of a run of the runner of `vm`. A run that stops while an ending is pending takes
    that ending's kind (paused, stopped or invalid; complete stays), and when its stop leaves the campaign at rest the
    pending ending is recorded. Returns the record's path, else None."""
    directory = Path(directory)
    with ending_lock(directory):
        pending = pending_ending(directory)
        if pending is not None and status != "complete":
            status = pending["ending"]
        update_state(directory, vm=vm, status=status, stage=stage, message=message, **state)
        if pending is None or active_runners(directory, protocol):
            return None
        return record_pending(directory, campaign, protocol, pending, command=command)


def settle(directory, campaign, protocol, *, command):
    """ENDING_RULE: the record of a pending ending when no runner of the campaign is active (its last runner was stopped
    by SIGKILL, a crash or a power loss before it wrote it); a run, a launch and a close settle first. Returns the
    ending that stays pending (a runner is active), else None."""
    directory = Path(directory)
    with ending_lock(directory):
        pending = pending_ending(directory)
        if pending is None:
            return None
        if active_runners(directory, protocol):
            return pending
        record_pending(directory, campaign, protocol, pending, command=command)
        return None


def record_pending(directory, campaign, protocol, pending, *, command):
    """ENDING_RULE, under ending_lock: the record of the pending ending, then the pending one goes; one recorded already
    (a crash between its record and the removal) is not recorded twice. Returns the record's path, else None."""
    latest, path = latest_ending(directory), None
    if latest is None or latest.get("pending") != pending["id"]:
        doc = ending_record(directory, campaign, protocol, pending["ending"], pending["triggers"],
                            cause=pending["cause"], command=command)
        path = publish_ending(directory, campaign, doc, pending=pending["id"])
    (Path(directory) / "ending.json").unlink()
    sync_dir(directory)
    return path


def complete_ending(directory, campaign, protocol, vm, *, command):
    """ENDING_RULE: the record of the complete ending, written before the index by the runner of `vm` that finds every
    planned session accepted (finish_corpus refuses without it), unless the last recorded ending is the complete one
    already (a complete campaign run again). Refused by name while an ending is pending (the caller stops as part of
    it instead). Returns its path, else None."""
    directory = Path(directory)
    with ending_lock(directory):
        pending = pending_ending(directory)
        if pending is not None:
            raise ValueError(f"campaign {campaign['id']} is ending ({pending['ending']}: {pending['cause']}): no record "
                             "of its complete ending while another ending is pending (scripts/campaign.py ENDING_RULE)")
        latest = latest_ending(directory)
        if latest is not None and latest["ending"] == "complete":
            return None
        trigger = {"date": now(), "vm": vm, "ending": "complete", "cause": COMPLETE_CAUSE, "detail": None}
        doc = ending_record(directory, campaign, protocol, "complete", [trigger], cause=COMPLETE_CAUSE,
                            command=command)
        return publish_ending(directory, campaign, doc)


# ENDING_RULE (F11): where the entry in a record of a closing ending names the record's own sha256, which no file can
# hold of itself; the command that writes the record prints the entry with the sha256 in its place.
MERANIA_SHA256 = "uvádza ho endings/ kampane a výpis príkazu, ktorý záznam zapísal"


def merania_entry(doc, name):
    """ENDING_RULE (F11 of the verification of B9b, proposal 11.6): the text of the entry of docs/MERANIA.md of the
    record `doc` of an ending that closes the campaign, written as data/results/<name>: the campaign and the ending,
    the record's name (its sha256 as MERANIA_SHA256), the planned, accepted, rejected and replaced sessions, the
    unscored time and the deviations, each of which also gets its entry in docs/ODCHYLKY_V5.sk.md; every number from
    the record with its marker of check C of scripts/check_claims.sh."""
    v = doc.get("values") or {}
    res = lambda key: "{{res:" + name + ":values." + key + "}}"
    kind = v.get("ending")
    by_cause = v.get("rejections_by_cause") or {}
    unscored, continues = v.get("unscored") or {}, v.get("continues")
    total = unscored.get("total_s")
    causes = "; ".join(f"`{cause}` {count} " + res("rejections_by_cause." + cause) for cause, count in by_cause.items())
    lines = ["## " + str(doc.get("date"))[:10] + f" — kampaň {v.get('campaign')}: ukončenie {ENDINGS.get(kind, kind)}",
             "",
             f"- **Záznam:** [`data/results/{name}`](../data/results/{name}), sha256 {MERANIA_SHA256}; stupeň "
             f"`{(v.get('stage') or {}).get('stage')}`, commit zmrazenia `{v.get('frozen_commit')}`, príkaz "
             f"`{doc.get('command')}`.",
             f"- **Kampaň a ukončenie:** `{v.get('campaign')}` v režime `{v.get('mode')}` (protokol sha256 "
             f"`{v.get('protocol_sha256')}`), ukončenie `{kind}` ({ENDINGS.get(kind, kind)}); "
             f"príčina: {v.get('cause')}",
             f"- **Session:** plánovaných {v.get('planned_sessions')} " + res("planned_sessions")
             + f", prijatých {v.get('accepted_sessions')} " + res("accepted_sessions")
             + f", zamietnutých {len(v.get('rejected_sessions') or [])}"
             + (f" (podľa príčiny: {causes})" if causes else "")
             + f", nahradených {v.get('replacements_used')} " + res("replacements_used")
             + ("" if not continues else f" (v kampani {continues.get('campaign')}, ktorú pokračuje, "
                f"{continues.get('replacements_used')} " + res("continues.replacements_used") + ")") + ".",
             "- **Neskórovaný čas:** "
             + ("nezaznamenaný" if type(total) not in (int, float)
                else f"{total:.1f} " + res("unscored.total_s") + " s")
             + " nominálne v prijatých session (`values.coverage.nominal_unscored_s` auditu každej); bez záznamu: "
             + (", ".join(f"`{sid}`" for sid in unscored.get("not_recorded") or []) or "žiadna") + "."]
    deviations = v.get("deviations") or []
    lines.append(f"- **Odchýlky:** {len(deviations)}" + (", každá so zápisom v `docs/ODCHYLKY_V5.sk.md`:" if deviations
                                                         else "."))
    for event in deviations:
        said = event.get("cause") or event.get("reason")
        lines.append(f"  - `{event.get('event')}`" + (f" `{event['ending']}`" if event.get("ending") else "")
                     + f" ({event.get('date')})" + (f": {said}" if said else "")
                     + (f"; záznam `{event['record']}`" if event.get("record") else ""))
    return "\n".join(lines) + "\n"


def publish_ending(directory, campaign, doc, *, pending=None):
    """ENDING_RULE: the record `doc` written into RESULTS as kampan_<campaign id>_<ending>_<UTC stamp>.json, a file of
    the campaign's owner (the runner runs as root), then named with its sha256 in endings/ of the campaign directory
    (`pending`: the id of the pending ending it records). The record of an ending that closes the campaign carries the
    entry of docs/MERANIA.md (merania_entry), which is printed with the record's sha256 (F11). Returns its path."""
    kind, when = doc["values"]["ending"], stamp()
    name = f"kampan_{campaign['id']}_{kind}_{when}.json"
    if kind in CLOSING:  # F11: the entry without the record's own sha256 (MERANIA_SHA256).
        doc = {**doc, "values": {**doc["values"], "merania_entry": merania_entry(doc, name)}}
    text = json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with results_lock():
        path = RESULTS / name
        temp = path.with_name(f".{name}.{uuid.uuid4().hex}.tmp")
        try:
            with temp.open("x", encoding="utf-8") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            if os.geteuid() == 0:  # The runner runs as root: the record stays a file of the campaign's owner.
                os.chown(temp, campaign["owner"]["uid"], campaign["owner"]["gid"])
            os.link(temp, path)  # Exclusive: a record is never replaced.
        finally:
            temp.unlink(missing_ok=True)
        sync_dir(RESULTS)
    folder = Path(directory) / "endings"
    folder.mkdir(exist_ok=True)
    write_new(folder / f"{when}_{kind}.json", {"schema": POINTER_SCHEMA, "ending": kind,
                                              "cause": doc["values"]["cause"], "record": name,
                                              "sha256": digest(path), "date": doc["date"], "pending": pending})
    if kind in CLOSING:  # F11: the command that wrote the record prints the entry, with the record's sha256.
        print(f"The entry of {MEASUREMENT_LOG} for this ending (scripts/campaign.py ENDING_RULE; one entry of "
              f"{DEVIATION_LOG} per deviation):\n" + doc["values"]["merania_entry"].replace(
                  MERANIA_SHA256, f"`{digest(path)}`"), flush=True)
    return path


def require_complete_record(directory, manifest):
    """ENDING_RULE and INVALID_RULE: the index of a campaign of protocol schema 3 is built only after the record of its
    complete ending; an invalid campaign has no corpus, and without that record (the last recorded ending complete, no
    ending pending, the record in RESULTS with the sha256 its endings/ names) finish_corpus refuses, each by name."""
    name = manifest.get("id", Path(directory).name)
    if held_ending(directory) == "invalid":
        raise ValueError(f"campaign {name} is invalid: an invalid campaign has no corpus (scripts/campaign.py "
                         "INVALID_RULE)")
    pending, latest = pending_ending(directory), latest_ending(directory)
    if pending is not None or latest is None or latest["ending"] != "complete":
        last = ("pending: " + pending["ending"] if pending is not None else
                "none" if latest is None else latest["ending"])
        raise ValueError(f"the record of the complete ending of campaign {name} is missing (its last ending: {last}): "
                         "the record comes first, then the corpus (scripts/campaign.py ENDING_RULE)")
    path = RESULTS / latest["record"]
    if not path.is_file() or digest(path) != latest["sha256"]:
        raise ValueError(f"the record of the complete ending of campaign {name} is not the one it wrote: {path} "
                         f"{'is missing' if not path.is_file() else 'has another sha256'} (scripts/campaign.py "
                         "ENDING_RULE)")
    return path


def early_stop_cause(stop):
    """EARLY_STOP_RULE: the sentence of an early stop from what early_stop_check returns (features/audit_policy.py
    early_stop: its cause a code, periodicity or marked_rows; its type, count and bound, and for marked rows the
    occurrences, the rate, the sessions counted and the restart point of the count)."""
    if stop.get("cause") == "periodicity":
        run = ("a run of equal spacings the audit did not count" if stop.get("count") is None else
               f"a run of {stop['count']} equal spacings")
        return (f"a session rejected for periodicity: {run} of its flagged rows, the bound {stop.get('bound')} of "
                "audit.periodicity.equal_spacings")
    n = stop.get("occurrences")
    return (f"{stop.get('count')} marked rows at the events of type {stop.get('type')} in its {n} "
            f"occurrence{'' if n == 1 else 's'} over {stop.get('sessions')} audited sessions since "
            f"{stop.get('since') or 'the start of the campaign'}, above the bound {stop.get('bound')}, the 99th "
            f"percentile of the Poisson distribution at the rate {stop.get('rate')} per occurrence of "
            "audit.early_stop.marked_rows_rate_per_type times its occurrences")


MARKED_SCHEMA = "hyptcn3/campaign-marked-rows/1"  # EARLY_STOP_RULE: marked/<session id>.json, the count of one audit.


def early_stop_restart(directory):
    """EARLY_STOP_RULE: the restart point of the count of the early stop, the date of the campaign's latest recorded
    ending (endings/) whose record holds an early-stop trigger, else None (the count runs from the start of the
    campaign). ValueError by name for a record of an ending that is missing or has another sha256 than its name in
    endings/: the restart point cannot be told then. The reading of an early-stop trigger is RESUME_RULE's as well
    (early_stop_triggers)."""
    for pointer in reversed(endings(directory)):
        if early_stop_triggers(pointer, "the restart point of the count"):
            return pointer["date"]
    return None


def marked_totals(directory, p, since):
    """EARLY_STOP_RULE: the campaign's count of the early stop over the files marked/<session>.json of every VM
    audited after `since` (every file when None): ({event type: {"marked": C_T, "occurrences": n_T}} for every type of
    the protocol and any other a file names, the sessions counted, the sessions whose audit did not tell their rows by
    type). ValueError by name for a file that is no such count, has no valid audited_at, or holds a malformed map."""
    start = None if since is None else datetime.fromisoformat(since)
    totals = {kind: {"marked": 0, "occurrences": 0} for kind in sorted(p["events"]["types"])}
    counted, uncounted = [], []
    for path in sorted((Path(directory) / "marked").glob("*.json")):
        doc = read_json(path)
        if type(doc) is not dict or doc.get("schema") != MARKED_SCHEMA or type(doc.get("session")) is not str:
            raise ValueError(f"{path} is no count of the early stop ({MARKED_SCHEMA})")
        if start is not None and datetime.fromisoformat(doc["audited_at"]) <= start:
            continue
        marked, occurrences = doc.get("marked_rows_by_type"), doc.get("event_occurrences_by_type")
        if marked is None or occurrences is None:
            uncounted.append(doc["session"])
            continue
        if (type(marked) is not dict or type(occurrences) is not dict or set(marked) != set(occurrences)
                or not all(type(n) is int and n >= 0 for n in (*marked.values(), *occurrences.values()))):
            raise ValueError(f"{path}: its marked rows and occurrences by event type are no counts of the same types")
        for kind in marked:
            total = totals.setdefault(kind, {"marked": 0, "occurrences": 0})
            total["marked"] += marked[kind]
            total["occurrences"] += occurrences[kind]
        counted.append(doc["session"])
    return dict(sorted(totals.items())), counted, uncounted


def early_stop_check(directory, vm, row, values, p, report):
    """EARLY_STOP_RULE after the audit (the record at `report`, its `values`) of a completed capture: writes the
    session's count marked/<session id>.json, sums the files of every VM since the restart point of the count
    (early_stop_restart, marked_totals) and asks features/audit_policy.py early_stop. Returns its stop, with the
    restart point (since) and the number of sessions counted, else None; then the campaign's count is printed in the
    runner's state, with the bound of every type whose rate is set. An early stop that cannot be decided (early_stop's
    ValueError, a count or a record of an earlier ending that cannot be read, the rows of a counted session not told
    by type while a rate is set) is an error by name, never no stop."""
    from features.audit_policy import audit_bounds, early_stop, poisson_quantile
    folder = Path(directory) / "marked"
    folder.mkdir(exist_ok=True)
    write_new(folder / f"{row['session_id']}.json", {
        "schema": MARKED_SCHEMA, "vm": vm, "session": row["session_id"], "audited_at": now(),
        "marked_rows_by_type": values.get("marked_rows_by_type"),
        "event_occurrences_by_type": values.get("event_occurrences_by_type"),
        "audit": str(report), "audit_sha256": digest(report)}, replace=True)
    try:
        since = early_stop_restart(directory)
        totals, counted, uncounted = marked_totals(directory, p, since)
        rates = audit_bounds(p)["early_stop"]["marked_rows_rate_per_type"]
        if uncounted and any(rate is not None for rate in rates.values()):
            raise ValueError(f"the audits of {', '.join(uncounted)} did not tell their marked rows by event type")
        stop = early_stop(values, p, totals)
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise ValueError(f"the early stop after the audit of {row['session_id']} cannot be decided: {error} "
                         "(scripts/campaign.py EARLY_STOP_RULE)") from None
    if stop is not None:
        return dict(stop, since=since, sessions=len(counted))
    shown = {kind: dict(total, rate=rates.get(kind), bound=None if rates.get(kind) is None else
                        poisson_quantile(rates[kind] * total["occurrences"])) for kind, total in totals.items()}
    update_state(directory, vm=vm, status="running", stage="early-stop", session=row["session_id"],
                 marked_rows_since=since, marked_rows_counts=shown, marked_rows_sessions=len(counted),
                 marked_rows_uncounted=uncounted,
                 message=f"marked rows and occurrences by event type over {len(counted)} audited sessions since "
                         f"{since or 'the start of the campaign'}: "
                         + json.dumps({kind: [t["marked"], t["occurrences"]] for kind, t in shown.items()})
                         + ": no bound of audit.early_stop is passed (a null rate, until G3b, only prints; "
                           "EARLY_STOP_RULE)")
    return None


START_FAILURE_SCHEMA = "hyptcn3/campaign-group-start-failure/1"  # GROUP_START_RULE (Q22).


def start_failure(directory, row, failure):
    """GROUP_START_RULE (question Q22, decided by its proposal): the record of a failed start of the group of `row`,
    groups/<group>.start-failed-<UTC>.json: the group, its VM and role, the session it was to start, the cause
    group_start, the step, the reason, the outputs of the steps done before it and the log of the failed command (its
    last CHILD_ERROR_CHARS). No rejection of a session: a resumed run starts the group again. Returns its path."""
    log = Path(failure.log) if failure.log is not None else None
    tail = log.read_text(errors="replace").strip()[-CHILD_ERROR_CHARS:] if log is not None and log.exists() else None
    path = Path(directory) / "groups" / f"{row['group']}.start-failed-{stamp()}.json"
    write_new(path, {"schema": START_FAILURE_SCHEMA, "date": now(), "group": row["group"],
                     **({"vm": row["vm"]} if "vm" in row else {}), "role": row["role"], "session": row["session_id"],
                     "cause": "group_start", "step": failure.step, "reason": str(failure),
                     "output": {"steps": failure.steps, "log": None if log is None else str(log), "log_tail": tail},
                     "note": "A failed start of a group, no rejection of a session (scripts/campaign.py "
                             "GROUP_START_RULE, question Q22): no session was measured; a resumed run starts the group "
                             "again from its beginning and captures its sessions as planned."})
    return path


def start_failures(directory):
    """GROUP_START_RULE (Q22): every failed start of a group of a campaign, oldest first, as every later ending record
    lists it: {record, date, group, vm, step, reason, started_again (the group has started since)}."""
    found = []
    for path in sorted((Path(directory) / "groups").glob("*.start-failed-*.json")):
        doc = read_json(path)
        found.append({"record": path.name, "date": doc.get("date"), "group": doc.get("group"), "vm": doc.get("vm"),
                      "step": doc.get("step"), "reason": doc.get("reason"),
                      "started_again": (Path(directory) / "groups" / f"{doc.get('group')}.json").exists()})
    return sorted(found, key=lambda failure: str(failure["date"]))


def audit_values_of(path):
    """The values of an audit record, None when there is none that can be read."""
    try:
        doc = read_json(path)
    except (OSError, ValueError, TypeError):
        return None
    values = doc.get("values") if type(doc) is dict else None
    return values if type(values) is dict else None


def measured_times(session):
    """INTERLEAVE_RULE and GRID_RULE: (first, last) measured unix time of a session directory from its end.json
    (measure_start_unix, measure_end_unix), None for a time it does not record."""
    try:
        end = read_json(Path(session) / "end.json")
    except (OSError, ValueError, TypeError):
        return None, None
    number = lambda x: x if type(x) in (int, float) else None
    return (number(end.get("measure_start_unix")), number(end.get("measure_end_unix"))) if type(end) is dict else (
        None, None)


def ending_sessions(directory, campaign):
    """ENDING_RULE: every planned session and each of its attempts in the plan's order, as (row of values.sessions:
    {session, vm, role, group, scenario, attempt, state, cause, replacement, captured, final, taken_over, audit (the
    path of its audit record, None without one)}, its session directory or None, the values of its audit or None).
    The state is one of four (F10 of the verification of B9b): accepted (its checkpoint), rejected (its rejection
    record), captured, not judged (its session directory without either) and not run."""
    rows = []
    for planned in campaign["sessions"]:
        taken = taken_over(campaign, planned)
        if taken is not None:  # Accepted in the campaign this one continues, indexed through its frozen audit.
            values = audit_values_of(taken["audit"])
            session = values.get("session_dir") if values else None
            rows.append(({"session": taken["session_id"], "vm": planned.get("vm"), "role": planned["role"],
                          "group": planned["group"], "scenario": planned["scenario"], "attempt": taken.get("attempt"),
                          "state": "accepted", "cause": None, "replacement": None, "captured": True, "final": True,
                          "taken_over": taken["campaign"], "audit": taken["audit"]},
                         Path(session) if type(session) is str else None, values))
            continue
        attempts = chain(directory, planned)
        for i, row in enumerate(attempts):
            sid = row["session_id"]
            done, rejected = directory / "attempts" / (sid + ".done.json"), rejection_file(directory, sid)
            session = session_dir(campaign, row)
            state, cause, replacement, audit = "not run", None, None, None
            if done.exists():
                state, audit = "accepted", read_json(done).get("audit")
            elif rejected.exists():
                record = read_json(rejected)
                state, cause, replacement, audit = ("rejected", record.get("cause", "audit_rejected"),
                                                    record.get("replacement"), record.get("audit"))
            elif session.is_dir():  # F10: its runner stopped during its capture, its audit or at the audit lock.
                state = "captured, not judged"
            rows.append(({"session": sid, "vm": row.get("vm"), "role": row["role"], "group": row["group"],
                          "scenario": row["scenario"], "attempt": row.get("replacement", 0) + 1, "state": state,
                          "cause": cause, "replacement": replacement, "captured": session.is_dir(),
                          "final": i == len(attempts) - 1, "taken_over": None, "audit": audit},
                         session, audit_values_of(audit) if audit else None))
    return rows


def unscored_summary(accepted):
    """ENDING_RULE: values.coverage.nominal_unscored_s of the audit of every accepted session and their total; an audit
    without it is not recorded, by name, never 0."""
    sessions, missing = [], []
    for row, _, values in accepted:
        seconds = ((values or {}).get("coverage") or {}).get("nominal_unscored_s")
        if type(seconds) in (int, float):
            sessions.append({"session": row["session"], "nominal_unscored_s": seconds})
        else:
            missing.append(row["session"])
    return {"sessions": sessions, "total_s": sum(x["nominal_unscored_s"] for x in sessions), "not_recorded": missing,
            "source": "values.coverage.nominal_unscored_s of the audit of each accepted session"}


def exceptions_summary(protocol, accepted):
    """ENDING_RULE, the lead's answer to Q2: per register id of features/audit_policy.py TOLERATED, the largest count in
    one accepted session and the number of accepted sessions over the expected count, from each audit's
    values.exceptions judged against the protocol's register by exceptions_record (over is false while the expected
    count is null, until G3a); an audit without a readable values.exceptions is not recorded, by name, never 0."""
    from features.audit_policy import TOLERATED, exceptions_record, register
    entries, held, missing = register(protocol) or {}, {name: [] for name in TOLERATED}, []
    for row, _, values in accepted:
        recorded, counts = (values or {}).get("exceptions"), Counter()
        try:
            if type(recorded) is not dict or not recorded:
                raise ValueError("the audit records no values.exceptions")
            for name, entry in recorded.items():
                observed = entry.get("observed") if type(entry) is dict else None
                if type(observed) is not int or observed < 0:
                    raise ValueError(f"values.exceptions.{name} records no count")
                counts[name] = observed
            judged = exceptions_record(protocol, counts)
        except ValueError as error:
            missing.append({"session": row["session"], "reason": str(error)})
            continue
        for name, entry in judged.items():
            held[name].append(entry)
    return {"by_id": {name: {"max_in_one_session": max((x["observed"] for x in found), default=None),
                             "sessions_over_expected": sum(x["over"] for x in found),
                             "expected": (entries.get(name) or {}).get("expected"),
                             "sessions_counted": len(found)} for name, found in held.items()},
            "not_recorded": missing,
            "source": "values.exceptions of the audit of each accepted session, judged by "
                      "features/audit_policy.py exceptions_record against the protocol's register"}


def interleave_check(rows, campaign):
    """INTERLEAVE_RULE: skeleton test 2 over the realized boots of test_benign and test_controls (ending_sessions):
    {ok, late_controls, alternation, order (every boot by its start: group, role, vm, start, end)}."""
    boots = {}
    for row, session, _ in rows:
        start, end = measured_times(session) if row["role"] in protocol_v5.INTERLEAVED and session else (None, None)
        if start is None:
            continue
        end = start if end is None else end
        boot = boots.setdefault((row["vm"], row["group"]), {"group": row["group"], "role": row["role"],
                                                           "vm": row["vm"], "start": start, "end": end})
        boot.update(start=min(boot["start"], start), end=max(boot["end"], end))
    order = sorted(boots.values(), key=lambda b: (b["start"], b["group"]))
    benign_ends = [b["end"] for b in order if b["role"] == "test_benign"]
    late = [b["group"] for b in order
            if b["role"] == "test_controls" and benign_ends and b["start"] >= max(benign_ends)]
    # The share rule of protocol_v5.check_role_order, against the plan's group counts of the two roles.
    totals = Counter(role for role in dict((r["group"], r["role"]) for r in campaign["sessions"]).values()
                     if role in protocol_v5.INTERLEAVED)
    alternation = []
    if all(totals[role] for role in protocol_v5.INTERLEAVED):
        placed, bound = Counter(), max(Fraction(1, totals[role]) for role in protocol_v5.INTERLEAVED)
        for b in order:
            placed[b["role"]] += 1
            shares = [Fraction(placed[role], totals[role]) for role in protocol_v5.INTERLEAVED]
            if max(shares) - min(shares) > bound:
                alternation.append(b["group"])
    return {"ok": not late and not alternation, "late_controls": late, "alternation": alternation,
            "order": order, "rule": INTERLEAVE_RULE}


def runner_states(directory, protocol):
    """ENDING_RULE: the last state of every runner of the campaign, and what the barrier of ORDER_RULE held it for
    (PAUSE_RULE: the paused record names it)."""
    states = []
    for vm in vm_names(protocol):
        path = Path(directory) / vm_file("status.json", vm)
        state = read_json(path) if path.exists() else {}
        held = state.get("waited") or (state.get("message") if state.get("stage") == "role-wait" else None)
        states.append({"vm": vm, **{key: state.get(key) for key in ("status", "stage", "message", "session", "group",
                                                                    "updated_at")},
                       "active": campaign_running(state), "waited": held})
    return states


def deviation_events(directory, campaign, triggers, interleaved, failures=()):
    """ENDING_RULE: the campaign's own events in time order: every earlier recorded ending (endings/: its kind, cause,
    record and sha256; F6), the continuation with its written cause, every operator's stop request a runner honored
    (events/, with its reason), the pause, the invalidation and the close of this ending, every deviation of
    deviations/ (an unclean end, a written cause of a resume after an early stop; F6), every failed start of a group
    (`failures`, start_failures; GROUP_START_RULE, Q22) and a violation of the interleave with its cause."""
    directory, events = Path(directory), []
    continues = campaign.get("continues") or {}
    if "cause" in continues:
        events.append({"event": "continuation", "date": campaign.get("date"), "continues": continues["campaign"],
                       "cause": continues["cause"]})
    for path in sorted((directory / "events").glob("*_stop-request*.json")):
        try:
            request = read_json(path)
        except (OSError, ValueError):
            request = None
        if path.name.endswith("-stale.json") or type(request) is not dict or "ending" in request:
            continue  # Not honored, or written by the trigger of an ending (that ending is the event).
        events.append({"event": "operator_stop", "date": request.get("date"), "vm": request.get("vm"),
                       "reason": operator_reason(request), "uid": request.get("uid"), "request": path.name})
    for pointer in endings(directory):  # F6: the history, every earlier recorded ending of the campaign.
        events.append({"event": "earlier_ending", "ending": pointer.get("ending"), "date": pointer.get("date"),
                       "cause": pointer.get("cause"), "record": pointer.get("record"), "sha256": pointer.get("sha256")})
    for name, doc in deviation_records(directory):  # F6: deviations that are no ending.
        kind, previous = doc.get("deviation"), doc.get("previous") or {}
        if kind == "unclean-end":
            events.append({"event": "unclean_end", "date": doc.get("date"), "vm": doc.get("vm"), "deviation": name,
                           "previous": previous,
                           "cause": f"the runner of VM {doc.get('vm')} ended without a final status (SIGKILL, a crash "
                                    f"or a power loss) at the stage {previous.get('stage')} of session "
                                    f"{previous.get('session')}, its last state of {previous.get('updated_at')}"})
        elif kind == "resume-after-early-stop":
            events.append({"event": "resume_after_early_stop", "date": doc.get("date"), "vm": doc.get("vm"),
                           "deviation": name, "answers": doc.get("answers"), "cause": doc.get("cause"),
                           "command": doc.get("command")})
        else:  # Not one of this rule's kinds, or unreadable: named, never left out.
            events.append({"event": "deviation", "date": doc.get("date"), "deviation": name, "kind": kind,
                           "cause": doc.get("cause") or doc.get("unreadable")})
    names = {"paused": "pause", "invalid": "invalidation", "closed": "close"}
    for trigger in triggers:
        if trigger["ending"] in names:
            events.append({"event": names[trigger["ending"]], "date": trigger["date"], "vm": trigger.get("vm"),
                           "cause": trigger["cause"]})
    for failure in failures:  # Q22: "the start of group G failed at step S, started again after the stop".
        events.append({"event": "group_start_failure", "date": failure["date"], "vm": failure["vm"],
                       "group": failure["group"], "step": failure["step"], "record": failure["record"],
                       "cause": f"the start of group {failure['group']} failed at step {failure['step']}"
                                + (", started again after the stop" if failure["started_again"] else "")
                                + f" ({failure['reason']})"})
    if not interleaved["ok"]:
        causes = []
        if interleaved["late_controls"]:
            causes.append("the test_controls boots " + ", ".join(interleaved["late_controls"]) + " start after every "
                          "test_benign boot ended: the barrier of ORDER_RULE orders the starts of the test groups, "
                          "not their ends (one VM ran on while the other had stopped)")
        if interleaved["alternation"]:
            causes.append("the starts of " + ", ".join(interleaved["alternation"]) + " break the alternation of the "
                          "two test roles (the share rule of protocol_v5.check_role_order)")
        events.append({"event": "interleave", "date": now(), "cause": "; ".join(causes)})
    return sorted(events, key=lambda event: str(event.get("date")))


def ending_record(directory, campaign, protocol, kind, triggers, *, cause, command):
    """ENDING_RULE: the record of an ending of a campaign of protocol schema 3 (`campaign` and `protocol` whole, not a
    VM's view), as it is now: the header of check E, its stage and the values the rule names."""
    from features.audit_policy import EARLY_STOP_RULE as DECISION_RULE
    from scripts.campaign_grids import GRID_RULE as PAIRS_RULE, grid_pairs, grid_session
    from tcn.pecat import RECORD_STAGE_RULE, record_stage
    directory = Path(directory)
    rows = ending_sessions(directory, campaign)
    accepted = [entry for entry in rows if entry[0]["final"] and entry[0]["state"] == "accepted"]
    applied, limit = replacement_limit(campaign, protocol)
    own = rejections(directory)
    used = sum(r.get("replacement") is not None for r in own)
    continues = campaign.get("continues")
    rejected = [*((continues or {}).get("rejected_sessions") or []),
                *({"session": r["session"], "cause": r.get("cause", "audit_rejected"),
                   "replacement": r.get("replacement"), "campaign": campaign["id"]} for r in own)]
    grid_rows, unread = [], []  # GRID_RULE: grid_session of every captured session (scripts/campaign_grids.py).
    for row, session, _ in rows:
        if session is not None and (session / "session.json").is_file():
            try:
                found = grid_session(session, row["audit"])
            except (OSError, ValueError) as error:
                unread.append({"session": row["session"], "reason": f"{type(error).__name__}: {error}"})
                continue
            if found is not None:  # None: no measured phase.
                grid_rows.append(found)
    try:
        grids = grid_pairs(grid_rows)  # Each row with the interval_s of its own session.json.
    except ValueError as error:  # A malformed row, named: no pairs rather than no record.
        grids, unread = [], [*unread, {"session": None, "reason": str(error)}]
    failures = start_failures(directory)  # GROUP_START_RULE (Q22).
    seals = [{"id": row["session"], "role": row["role"], "group": row["group"], "vm": row["vm"],
              "scenario": row["scenario"], "features": (values or {}).get("features"),
              "features_sha256": (values or {}).get("features_sha256")} for row, _, values in accepted]
    try:
        seed = {"seed": protocol_v5.reset_seed(protocol), "key": SEEDED_LEVEL}
    except ValueError as error:
        seed = {"seed": None, "key": SEEDED_LEVEL, "reason": str(error)}
    interleaved = interleave_check(rows, campaign)
    log = ROOT / DEVIATION_LOG
    stage = record_stage(campaign["mode"], seals, at_head=False)  # ENDING_RULE, question Q21: no ledger at HEAD.
    values = {
        "campaign": campaign["id"], "mode": campaign["mode"], "protocol_sha256": campaign["protocol_sha256"],
        "plan_sha256": digest(directory / "plan.json"), "frozen_commit": campaign["commit"], "ending": kind,
        "ending_name": ENDINGS[kind], "cause": cause, "triggers": triggers, "stage": stage,
        "sessions": [row for row, _, _ in rows], "planned_sessions": len(campaign["sessions"]),
        "accepted_sessions": len(accepted), "rejected_sessions": rejected,
        "rejections_by_cause": dict(sorted(Counter(r["cause"] for r in rejected).items())),
        "limit": {"applied": applied, "max_per_campaign": limit, "used": used}, "replacements_used": used,
        "unscored": unscored_summary(accepted), "exceptions": exceptions_summary(protocol, accepted),
        "grids": grids, "grids_unread": unread, "interleave": interleaved, "group_start_failures": failures,
        "reset_seed": {**seed, "protocol_sha256": campaign["protocol_sha256"]},
        "runners": runner_states(directory, protocol),
        "deviations": deviation_events(directory, campaign, triggers, interleaved, failures),
        "deviation_log": {"path": DEVIATION_LOG, "sha256": digest(log) if log.is_file() else None},
        "continues": None if continues is None else {
            **{key: continues.get(key) for key in ("campaign", "directory", "commit", "cause", "paused_record",
                                                   "replacements_used", "rejections_by_cause", "discarded_groups")},
            "taken_over_sessions": len(continues.get("sessions", {}))},
        "rules": {"ending": ENDING_RULE, "pause": PAUSE_RULE, "continuation": CONTINUATION_RULE,
                  "invalid": INVALID_RULE, "early_stop": EARLY_STOP_RULE, "early_stop_decision": DECISION_RULE,
                  "resume": RESUME_RULE,
                  "interleave": INTERLEAVE_RULE, "grids": GRID_RULE, "grid_pairs": PAIRS_RULE, "limit": LIMIT_RULE,
                  "group_start": GROUP_START_RULE, "stage": RECORD_STAGE_RULE}}
    try:
        head = git("rev-parse", "HEAD")
    except (OSError, subprocess.SubprocessError):
        head = None
    guests = ({vm: campaign["vms"][vm]["guest_environment"] for vm in campaign["vms"]} if "vms" in campaign
              else campaign.get("guest_environment"))
    return {"schema": ENDING_SCHEMA, "commit": head, "date": now(), "host": platform.platform(), "guest": guests,
            "command": command, "n": len(values["sessions"]), "stage": stage["stage"], "values": values,
            "note": "The record of an ending of a collection campaign of protocol v5 (scripts/campaign.py ENDING_RULE, "
                    "package B9b): its sessions by state and cause, replacements, unscored time and deviations; "
                    "no detection result."}


def run_command(directory, vm, stop_after, cause=None):
    """ENDING_RULE: the command line of a runner, as launch starts it (the command of its records), with the written
    cause of a resume after an early stop when it has one (RESUME_RULE)."""
    return shlex.join(["python3", "scripts/campaign.py", "run", str(directory), *(["--vm", vm] if vm else []),
                       *(["--stop-after", str(stop_after)] if stop_after else []),
                       *(["--cause", cause] if cause is not None else [])])


def execute(directory, *, stop_after=None, vm=None, cause=None):
    """Run the sessions of one VM in plan order (all sessions of a single-VM campaign).

    A multi-VM campaign has one runner process per VM; they share the frozen
    plan, the audit lock and the final index, nothing else. Under protocol
    schema 3 (package B9b, ENDING_RULE) the runner meets the endings of the
    campaign: the record of the complete ending before the index; a pause, or
    an invalidation, when the limit refuses a rejection (PAUSE_RULE,
    INVALID_RULE); an early stop after an audit (EARLY_STOP_RULE); an operator's
    stop request; every error it catches (a failed start of a group among them)
    and a changed measurement code or lab. A paused or invalid campaign does not
    run again; a stopped one runs again from where it stopped (today's resume),
    after an early stop only with the written cause `cause` (RESUME_RULE); a
    closed one and a complete one with its index never run again (F3).
    """
    directory = Path(directory).resolve()
    campaign, protocol = load_campaign(directory)
    if vm not in vm_names(protocol):
        raise ValueError("this campaign runs one VM per runner; --vm is one of: "
                         + ", ".join(map(str, vm_names(protocol))) if vm is None else "campaign has no VM " + vm)
    manifest, p = vm_view(campaign, protocol, vm)
    # Replacements of audit-rejected sessions follow their plan row; the list grows when one is scheduled. Under
    # schema 3 each is the next attempt of its planned row (REPLACEMENT_RULE).
    rows = [attempt_row(manifest, p, r) for planned in manifest["sessions"] if planned.get("vm") == vm
            for r in chain(directory, planned)]
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("run with sudo from the campaign owner's account")
    if (directory / "closed.json").exists():
        raise ValueError("campaign was closed by the operator: " + read_json(directory / "closed.json")["reason"])
    v5, run_line = schema3(p), run_command(directory, vm, stop_after, cause)
    if v5:  # ENDING_RULE: an ending a crashed last runner left pending is recorded first; PAUSE_RULE, INVALID_RULE.
        settle(directory, campaign, protocol, command=run_line)
        refuse_held(directory, "run")
        refuse_ended(directory, protocol, "run")  # F3: before verify_frozen, no ending.
        answer_early_stop(directory, vm, cause, "run", run_line)  # RESUME_RULE (F6).
    elif cause is not None:
        raise ValueError("--cause of run belongs to protocol schema 3: the written cause of a resume after an early "
                         "stop (scripts/campaign.py RESUME_RULE)")
    # ENDING_RULE (F4 of the verification of B9b): the endings recorded when this run passed refuse_held and the
    # refusals after it (refuse_ended, answer_early_stop); an ending recorded after that, of any kind, stops this
    # runner before its next capture (the capture loop).
    recorded_at_start = len(endings(directory)) if v5 else 0

    def last(status, stage, message, **state):
        """The last state of this run (under schema 3 ENDING_RULE's end_run: a pending ending recorded at rest)."""
        if v5:
            end_run(directory, campaign, protocol, vm, command=run_line, status=status, stage=stage, message=message,
                    **state)
        else:
            update_state(directory, vm=vm, status=status, stage=stage, message=message, **state)
        return 0

    def honor(request, waited=None):
        """A stop request this runner honors before its next capture. Under schema 3 an operator's request triggers the
        stopped ending, with its reason; a request of another runner's trigger makes this stop part of that ending
        (ENDING_RULE). The barrier of ORDER_RULE names what it held this runner for (PAUSE_RULE)."""
        text = stop_text(request)
        if v5 and "ending" not in request:
            reason = operator_reason(request)
            text += f": {reason}" if reason else ""
            begin_ending(directory, protocol, vm, "stopped", text, {"request": request})
        kind = request["ending"] if v5 and request.get("ending") in PENDING else "stopped"
        return last(kind, "between-sessions", text, **({"waited": waited} if v5 and waited else {}))

    def limit_ending(record):
        """PAUSE_RULE and INVALID_RULE: a rejection the exhausted limit refused ends the campaign as its record names
        (paused, or invalid inside a continuation); the runner stops with it, as for a stop request."""
        kind = record["ending"]
        cause = (f"the limit of replacements is used up ({record.get('max_per_campaign')} per campaign): session "
                 f"{record['session']} rejected ({record.get('cause', 'audit_rejected')}: "
                 + "; ".join(record.get("reasons") or []) + ")"
                 + (f"; a second exhaustion inside the continuation of {manifest['continues']['campaign']}"
                    if kind == "invalid" else ""))
        begin_ending(directory, protocol, vm, kind, cause, {"rejection": record})
        return last(kind, "limit", cause, rejections_by_cause=rejections_by_cause(directory))

    def early_ending(stop, row):
        """EARLY_STOP_RULE: the stopped ending the audit of `row` calls for; the runner stops with it."""
        cause = f"early stop after the audit of {row['session_id']}: {early_stop_cause(stop)}"
        begin_ending(directory, protocol, vm, "stopped", cause, {"early_stop": stop, "session": row["session_id"]})
        return last("stopped", "early-stop", cause, early_stop=stop)

    def ending_already():
        """ENDING_RULE: an ending another runner began while this one finished its last session: this runner stops as
        part of it (its stop request, if any, honored), instead of the complete ending."""
        pending = pending_ending(directory) if v5 else None
        if pending is None:
            return None
        request = take_stop_request(directory, vm) or {"ending": pending["ending"], "cause": pending["cause"],
                                                       "by": pending["triggers"][0]["vm"]}
        return honor(request)
    interrupts = collection.Interrupts()
    owns_lock, inhibitor = False, None
    status_file = directory / vm_file("status.json", vm)
    stop_file = directory / vm_file("stop-request.json", vm)
    try:
        with collection.collection_lock(COLLECTIONS, p["domain"] if vm else None) as lock_fd:
            owns_lock = True
            previous = read_json(status_file) if status_file.exists() else {}
            if previous.get("status") == "running":
                # The lock was free, so that process is gone: SIGKILL, crash or power loss.
                if v5:  # ENDING_RULE (F6): a deviation of every later record, written before anything can stop.
                    unclean_end(directory, vm, previous)
                update_state(directory, vm=vm, status="stopped", stage="unclean-end",
                             message="previous run ended without a final status; its session is incomplete")
            verify_frozen(directory, manifest, p)
            if schema3(p):
                require_stages(directory / "protocol.json", manifest["mode"])  # STAGES_RULE
            if stop_file.exists():
                # A request is meant for a running campaign; one left by a previous run is not.
                os.replace(stop_file, directory / "events" / f"{stamp()}_{stop_file.stem}-stale.json")
            inhibitor = hold_sleep_inhibitor()
            update_state(directory, vm=vm, status="running", stage="preflight", pid=os.getpid(),
                         process_identity=process_identity(os.getpid()), inhibitor_pid=getattr(inhibitor, "pid", None),
                         message=None, signals=[], **({"waited": None, "early_stop": None} if v5 else {}))
            reports = []
            processed = 0
            guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
            for i, row in enumerate(rows):
                taken = taken_over(manifest, row)
                if taken is not None:  # Completed by the closed campaign this one continues.
                    reports.append(taken_report(taken))
                    continue
                session = session_dir(manifest, row)
                destination = archive_dest(manifest, row)
                checkpoint = directory / "attempts" / (row["session_id"] + ".done.json")
                if rejection_file(directory, row["session_id"]).exists():
                    record = read_json(rejection_file(directory, row["session_id"]))
                    if record.get("replacement") is None:
                        if v5 and record.get("ending") in ("paused", "invalid"):
                            return limit_ending(record)  # A pause or an invalidation its runner could not record.
                        raise ValueError(STOP_MESSAGE[record.get("cause", "audit_rejected")] + ": "
                                         + "; ".join(record["reasons"]))
                    continue  # Its replacement is the next row.
                if checkpoint.exists():
                    done = read_json(checkpoint)
                    if not check_session(session, manifest, row, directory, p):
                        raise ValueError("completed session lost its provenance")
                    report, values = audit_capture(directory, manifest, p, row, session, guard)
                    if (not values["accepted"] or digest(destination / "archive-manifest.json") != done["manifest_sha256"]
                            or not (session / "raw").is_symlink()
                            or os.readlink(session / "raw") != str(destination / "raw")):
                        raise ValueError("completed archive checkpoint mismatch")
                    reports.append(report)
                    continue
                verify_frozen(directory, manifest, p)
                update_state(directory, vm=vm, status="running", stage="session-preflight", session=session.name,
                             group=row["group"], role=row["role"], scenario=row["scenario"],
                             position=i + 1, total=len(rows), accepted_archived=len(reports))
                if ended_before_measurement(session):
                    retire_attempt(directory, manifest, row, session)  # Left by a previous run.
                attempts, refused_start = 0, None
                while not session.exists():
                    request = take_stop_request(directory, vm)
                    if request is not None:
                        return honor(request)
                    # ENDING_RULE (F4 of the verification of B9b): an ending begun or recorded since this runner passed
                    # refuse_held. begin_ending asks only the runners whose state said running then, so a runner that
                    # wrote running after it reads the ending itself before every capture and stops as part of it:
                    # a pending one with its kind and cause (the last runner to stop records it); one recorded after
                    # this run started (stopped, paused or invalid: a pause or an invalidation recorded before it
                    # never gets here, refuse_held refused it) with its kind, cause and record.
                    pending = pending_ending(directory) if v5 else None
                    if pending is not None:
                        return honor({"ending": pending["ending"], "cause": pending["cause"],
                                      "by": pending["triggers"][0]["vm"]})
                    recorded = endings(directory) if v5 else []
                    if len(recorded) > recorded_at_start:
                        newest = recorded[-1]
                        return last(newest["ending"], "between-sessions", f"the campaign ended {newest['ending']} "
                                    f"({newest['cause']}; record {newest['record']}) after this run started: this "
                                    "runner stopped before its next capture (scripts/campaign.py ENDING_RULE)",
                                    ending_record=newest["record"])
                    if vm is not None:
                        reason = wait_for_earlier_roles(directory, manifest, p, row)
                        if reason:
                            if reason.request is not None:
                                return honor(reason.request, reason.waited)
                            # The other runner is not active: no ending (ENDING_RULE), it records what it held for.
                            return last("stopped", "between-sessions", reason,
                                        **({"waited": reason.waited} if v5 else {}))
                    if attempts:
                        verify_frozen(directory, manifest, p)
                    attempts += 1
                    capacity_guard(manifest, p, sum(taken_over(manifest, r) is None for r in rows[i:]), directory)
                    try:
                        group = ensure_group(directory, manifest, p, row)
                    except GroupStartFailed as failure:  # GROUP_START_RULE: rejected before the measured phase.
                        refused_start = failure
                        break
                    update_state(directory, vm=vm, status="running", stage="capture", capture_started_at=now(),
                                 message=None)
                    command = [sys.executable, ROOT / "scripts/collection.py", "--protocol", directory / "protocol.json",
                               "run", "--role", row["role"], "--group", row["group"], "--scenario", row["scenario"],
                               "--seed", str(row["seed"]),
                               # Schema 3 (PILOT_RULE, REPLACEMENT_RULE): the plan mode and the attempt, no pilot.
                               *(["--mode", manifest["mode"], "--attempt", str(row["attempt"])] if schema3(p)
                                 else ["--pilot-report", directory / vm_file("pilot.json", vm)]),
                               "--session-id", session.name, "--campaign-id", manifest["id"],
                               "--expected-boot-id", group["identity"]["boot_id"],
                               "--expected-qemu", json.dumps(group["qemu"]),
                               *(["--vm", vm] if vm else []),
                               *(["--replaces", row["replaces"]] if "replaces" in row else [])]
                    rc = run_child(command, directory / "logs" / f"capture_{stamp()}.log", lock_fd=lock_fd,
                                   timeout=p["warmup_s"] + p["cycles"] * p["interval_s"] + 300, guard=guard)
                    if rc and not session.exists():
                        raise ValueError("capture could not start; see campaign log")
                    if ended_before_measurement(session):
                        if attempts >= MAX_ATTEMPTS:
                            raise ValueError(f"{attempts} attempts of {session.name} ended before measurement; "
                                             "see its end.json and the campaign logs")
                        retire_attempt(directory, manifest, row, session)
                        time.sleep(RETRY_PAUSE_S)
                if refused_start is not None:  # GROUP_START_RULE (Q22): no session was measured, no rejection.
                    failure = start_failure(directory, row, refused_start)
                    raise GroupStartStop(STOP_MESSAGE["group_start"] + ": " + str(refused_start), failure)
                # The session stays on the working disk while it waits; its VM starts nothing new.
                values = None  # The values of its audit, None for a capture that did not complete (no audit).
                with audit_lock(directory, vm=vm, session=session.name):
                    if not check_session(session, manifest, row, directory, p):
                        archive_capture(directory, manifest, session, p)
                        cause, reasons = "capture_incomplete", incomplete_reasons(session)
                        replacement = reject(directory, manifest, p, row, cause, reasons)
                    else:
                        verify_frozen(directory, manifest, p)
                        report, values = audit_capture(directory, manifest, p, row, session, guard)
                        archived = archive_capture(directory, manifest, session, p, report)
                        cause, reasons = (None, None) if values["accepted"] else ("audit_rejected", values["reasons"])
                        replacement = cause and reject(directory, manifest, p, row, cause, reasons, report)
                        if not cause and schema3(p) and sealed_role(row["role"]):
                            seal_session(directory, manifest, row, report)  # SEAL_RULE: before the checkpoint.
                if cause:
                    # EARLY_STOP_RULE: after the session's own outcome, its rejection record (and replacement).
                    stop = (early_stop_check(directory, vm, row, values, p, report) if v5 and values is not None
                            else None)
                    if replacement is None:
                        if stop is not None:  # EARLY_STOP_RULE: a trigger of its own beside the stop that follows.
                            begin_ending(directory, protocol, vm, "stopped",
                                         f"early stop after the audit of {row['session_id']}: "
                                         + early_stop_cause(stop), {"early_stop": stop, "session": row["session_id"]})
                        record = read_json(rejection_file(directory, row["session_id"]))
                        if v5 and record.get("ending") in ("paused", "invalid"):
                            return limit_ending(record)
                        raise ValueError(STOP_MESSAGE[cause] + ": " + "; ".join(reasons))
                    rows.insert(i + 1, replacement)
                    if stop is not None:
                        return early_ending(stop, row)
                    continue
                write_new(checkpoint, {"session": session.name, "audit": str(report), "audit_sha256": digest(report),
                                       "manifest_sha256": digest(destination / "archive-manifest.json"),
                                       # DISK_RULE: the sizes of the accepted session, from its archive manifest.
                                       "session_bytes": archived["bytes"],
                                       "archive_bytes": archived.get("stored_bytes", archived["bytes"]),
                                       "date": now()})
                reports.append(report)
                processed += 1
                update_state(directory, vm=vm, status="running", stage="session-complete",
                             accepted_archived=len(reports))
                stop = early_stop_check(directory, vm, row, values, p, report) if v5 else None  # EARLY_STOP_RULE.
                if stop is not None:
                    return early_ending(stop, row)
                if stop_after and processed >= stop_after and i + 1 < len(rows):
                    return last("stopped", "between-sessions", "requested stop-after boundary")
            if vm is None:
                if ending_already() is not None:
                    return 0
                if v5:
                    complete_ending(directory, campaign, protocol, vm, command=run_line)  # ENDING_RULE: record first.
                finish_corpus(directory, manifest, p, reports)
                return 0
            # The runner that archives the campaign's last session builds the index of all VMs.
            with audit_lock(directory, vm=vm):
                if not all(finished(directory, manifest, r) for r in manifest["sessions"]):
                    return last("complete", "vm-complete", None, accepted_archived=len(reports))
                if ending_already() is not None:
                    return 0
                reports = [final_report(directory, manifest, r) for r in manifest["sessions"]]
                if v5:
                    complete_ending(directory, campaign, protocol, vm, command=run_line)  # ENDING_RULE: record first.
                finish_corpus(directory, manifest, protocol, reports)
            return 0
    except BaseException as exc:
        try:
            interrupts.disarm()
        except InterruptedError:
            pass  # First signal arrived exactly here; the handler disarmed itself.
        if owns_lock:
            stage = "interrupted" if isinstance(exc, InterruptedError) else "error"
            if v5:  # ENDING_RULE: every error the runner catches is a trigger; INVALID_RULE: a changed hash.
                kind = "invalid" if isinstance(exc, CampaignInvalid) else "stopped"
                started = isinstance(exc, GroupStartStop)  # GROUP_START_RULE (Q22): the cause group_start.
                try:
                    begin_ending(directory, protocol, vm, kind, f"group_start: {exc}" if started else f"{stage}: {exc}",
                                 {"stage": stage, "type": type(exc).__name__, "signals": interrupts.received,
                                  **({"group_start_failure": exc.record.name} if started else {})})
                    last(kind, stage, str(exc), signals=interrupts.received)
                except Exception as error:  # noqa: BLE001 - the runner's own error goes on, its ending named beside
                    exc.add_note(f"its ending was not recorded: {type(error).__name__}: {error}")
                    update_state(directory, vm=vm, status=kind, stage=stage, signals=interrupts.received,
                                 message=f"{exc} (its ending was not recorded: {type(error).__name__}: {error})")
            else:
                update_state(directory, vm=vm, status="stopped", stage=stage, message=str(exc),
                             signals=interrupts.received)
        raise
    finally:
        release_sleep_inhibitor(inhibitor)
        interrupts.restore()


EVENT_INDEX = "hyptcn3/event-index/1"


def test_only(p, mode=None):
    """Whether a campaign of `p` ends with an event index instead of a corpus index: a protocol of schema 1 or 2
    without the role train (the test-only protocol of v3, step A), and under schema 3 a plan of `mode` without a
    session of a fitting role (features/dataset.py FIT_ROLES: schema 3 names all five roles, some with no group, so the
    key alone says nothing; package B7c)."""
    if p.get("schema") != collection.protocol_v5.SCHEMA:
        return "train" not in p["roles"]
    from features.dataset import FIT_ROLES
    return not any(row["role"] in FIT_ROLES for row in collection.protocol_v5.planned_rows(p, mode))


def event_index(reports, p, protocol_sha, *, mode=None):
    """Test-only protocol (v3, step A): accepted sessions with their event intervals.

    No training roles, so no corpus index: these sessions are only scored by an
    existing bundle (python3 -m tcn.eval udalosti).

    Package B7c. Every session is admitted by features.acceptance.require_accepted from its archive, which the
    index opens anyway (deferred point 8 of B2: an archive exchanged after the audit is refused; the decision is the
    one features/dataset.py build makes). The planned sessions: under protocol schema 3 the rows of the plan of `mode`
    (scripts/protocol_v5.py planned_rows, as features/dataset.py build; the mode has no default, campaign or
    rehearsal, and the index records it as plan_mode): a session must hold a planned row, matched by role, group,
    scenario and VM, and the index is complete when every row holds exactly one session. Schemas 1 and 2 keep their
    rule (every scenario in every group of their roles: the product) and refuse a mode.
    """
    from features.acceptance import require_accepted
    from features.archive import load
    from features.dataset import named, row_key
    from features.quality import require_log_audit
    if p.get("schema") == collection.protocol_v5.SCHEMA:
        if mode is None:
            raise ValueError("an event index of protocol schema 3 needs its plan mode (campaign or rehearsal)")
        rows = collection.protocol_v5.planned_rows(p, mode)
    elif mode is not None:
        raise ValueError(f"plan mode {mode} applies only to protocol schema 3; schemas 1 and 2 keep every scenario "
                         "in every group")
    else:
        rows = None
    planned_keys = None if rows is None else {row_key(row) for row in rows}
    records, boots, groups = [], {}, {}
    for path in reports:
        v = read_json(path)["values"]
        if v.get("accepted") is not True or v["protocol_sha256"] != protocol_sha:
            raise ValueError("unaccepted audit or protocol mismatch: " + str(path))
        session = Path(v["session_dir"])
        meta = read_json(session / "session.json")
        if v.get("session_sha256") != digest(session / "session.json") or digest(v["features"]) != v["features_sha256"]:
            raise ValueError("session metadata or features changed since audit: " + str(path))
        require_log_audit(meta, v)
        boot = meta["guest_before"]["boot_id"]
        if meta["role"] not in p["roles"] or boots.setdefault(boot, meta["group"]) != meta["group"] \
                or groups.setdefault(meta["group"], boot) != boot:
            raise ValueError("role or boot/group mapping outside the plan: " + str(path))
        if planned_keys is not None and row_key(meta) not in planned_keys:
            raise ValueError(f"assignment is outside the planned allocation: session "
                             f"{named(dict(meta, id=meta['session_id']))} holds no row of plan:{mode}: {path}")
        data = load(v["features"])
        try:
            # The verdict derived from the archive must accept and equal the record (features/acceptance.py). The
            # recorded length goes in as at the audit; it decides only a session of the role "diagnostic".
            require_accepted(data, p, session.name, meta["role"], v, meta.get("cycles"))
        except ValueError as error:
            raise ValueError(f"{error}: {path}") from None
        casy = data["casy"]
        events = session / "events.json"
        records.append({"id": meta["session_id"], "role": meta["role"], "group": meta["group"], "boot_id": boot,
                        **({"vm": meta["vm"]} if meta.get("vm") else {}),
                        "scenario": meta["scenario"], "seed": meta["seed"],
                        "start": float(casy[0]), "end": float(casy[-1]),
                        "session": str(session / "session.json"), "session_sha256": v["session_sha256"],
                        "audit": str(Path(path).resolve()), "audit_sha256": digest(path),
                        "features": v["features"], "features_sha256": v["features_sha256"],
                        "events": str(events), "events_sha256": digest(events),
                        "guest": meta["guest_before"], "collector_sha256": meta["collector_sha256"],
                        "extractor_sha256": v["extractor_sha256"]})
    if rows is None:
        planned = sum(p["roles"].values()) * len(p["scenarios"])
        complete = len(records) == planned
    else:  # Every planned row holds exactly one session (a second session of a row leaves the index incomplete).
        planned = len(rows)
        complete = len(records) == planned and {row_key(r) for r in records} == planned_keys
    return {"schema": EVENT_INDEX, "complete": complete, "planned_sessions": planned,
            "protocol_sha256": protocol_sha, "protocol_config": p, "sessions": records,
            "note": "Benign operational events; test-only sessions, never training data.",
            **({} if rows is None else {"plan_mode": mode})}


def continuation_note(manifest):
    """For the index of a continuation campaign: which sessions come from the closed campaign."""
    record = manifest.get("continues")
    if record is None:
        return {}
    return {"continues": {"campaign": record["campaign"], "commit": record["commit"],
                          "taken_over_sessions": sorted(s["session_id"] for s in record["sessions"].values()),
                          "discarded_groups": record["discarded_groups"],
                          "replacements_used": record["replacements_used"],
                          "not_replaced": record["not_replaced"]}}


def finish_corpus(directory, manifest, p, reports):
    vm = manifest.get("vm")  # Multi-VM: the status file of the runner that builds the index.
    # The completeness of the plan the campaign ran (package B6a): under schema 3 the plan of the campaign's own mode
    # (MODE_RULE; load_campaign holds the manifest to it); schemas 1 and 2 keep their rule and have no mode.
    mode = manifest.get("mode") if schema3(p) else None
    if schema3(p) and mode not in protocol_v5.MODES:
        raise ValueError("a campaign of protocol schema 3 names its plan mode in campaign.json (mode: campaign or "
                         "rehearsal; scripts/campaign.py MODE_RULE)")
    if schema3(p):  # ENDING_RULE and INVALID_RULE (package B9b): the record of the complete ending comes first.
        require_complete_record(directory, manifest)
    # indexed_sessions: the sessions of the index, of every VM; accepted_archived stays the count of this runner's VM
    # (campaign_report.py compares it with the VM's done checkpoints). Since several VMs (52fd3ca) the runner that
    # builds the index wrote the count of every VM into accepted_archived, a bug the real index in the tests of the
    # fix round of B9a showed (agent T, merge point 1).
    if test_only(p, mode):  # Package B7c: under schema 3 a plan without a fitting role reaches the event index too.
        update_state(directory, vm=vm, status="running", stage="index", indexed_sessions=len(reports))
        index = directory / "events_index.json"
        doc = event_index(reports, p, manifest["protocol_sha256"], mode=mode)
        doc["protocol"] = str(directory / "protocol.json")
        doc.update(continuation_note(manifest))
        if not doc["complete"]:
            raise ValueError("campaign ended without a complete event allocation")
        if index.exists():
            if read_json(index) != doc:
                raise ValueError("existing event index differs")
        else:
            write_new(index, doc)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        copy_exclusive(index, Path(manifest["archive_dir"]) / "events_index.json")
        update_state(directory, vm=vm, status="complete", stage="complete", corpus=str(index), message=None)
        return
    from features.dataset import build
    update_state(directory, vm=vm, status="running", stage="index", indexed_sessions=len(reports))
    index = directory / "corpus.json"
    doc = build(reports, p, manifest["protocol_sha256"], mode=mode)
    doc["protocol"] = str(directory / "protocol.json")
    doc.update(continuation_note(manifest))
    if not doc["complete"]:
        mismatches = doc["allocation_mismatches"]  # Each with its reason (features/dataset.py build).
        raise ValueError("campaign ended without a complete corpus allocation: "
                         + "; ".join(json.dumps(x, sort_keys=True) for x in mismatches[:3])
                         + (f"; and {len(mismatches) - 3} more" if len(mismatches) > 3 else ""))
    if index.exists():
        if read_json(index) != doc:
            raise ValueError("existing corpus index differs")
    else:
        write_new(index, doc)
    # The production check of training, as the owner; its refusal keeps the child's error text (B2 panel, package B9a).
    checked = subprocess.run(collection.user_command([
        sys.executable, "-c", "from safeguard.training import validate_index; import sys; validate_index(sys.argv[1])",
        index]), cwd=ROOT, timeout=180, capture_output=True, text=True)
    if checked.returncode:
        said = (checked.stderr.strip() or checked.stdout.strip() or "no output")[-CHILD_ERROR_CHARS:]
        raise ValueError(f"the production check of training refused the corpus index {index} (safeguard/training.py "
                         f"validate_index, exit {checked.returncode}): {said}")
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    copy_exclusive(index, Path(manifest["archive_dir"]) / "corpus.json")
    update_state(directory, vm=vm, status="complete", stage="complete", corpus=str(index), message=None)


def launch(directory, stop_after=None, vm=None, cause=None):
    """One systemd unit per VM; without --vm every VM of the campaign is launched. Under protocol schema 3 a closed
    campaign and a complete one with its index are refused (F3), and after an early stop the launch writes the written
    cause `cause` that its runners then find (RESUME_RULE)."""
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if vm is not None and vm not in vm_names(p):
        raise ValueError("campaign has no VM " + vm)
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("launch with sudo from the campaign owner's account")
    if (directory / "closed.json").exists():
        raise ValueError("campaign was closed by the operator")
    command = shlex.join(["python3", "scripts/campaign.py", "launch", str(directory), *(["--vm", vm] if vm else []),
                          *(["--stop-after", str(stop_after)] if stop_after else []),
                          *(["--cause", cause] if cause is not None else [])])
    if schema3(p):  # ENDING_RULE: a pending ending recorded first; PAUSE_RULE and INVALID_RULE refuse by name.
        settle(directory, manifest, p, command=command)
        refuse_held(directory, "launch")
        refuse_ended(directory, p, "launch")  # F3: before verify_frozen, no ending.
        answer_early_stop(directory, vm, cause, "launch", command)  # RESUME_RULE (F6).
    elif cause is not None:
        raise ValueError("--cause of launch belongs to protocol schema 3: the written cause of a resume after an early "
                         "stop (scripts/campaign.py RESUME_RULE)")
    try:
        verify_frozen(directory, manifest, p)
    except CampaignInvalid as error:  # INVALID_RULE: the launch that finds a changed hash ends the campaign invalid.
        begin_ending(directory, p, NOBODY, "invalid", f"launch: {error}", {"command": command})
        settle(directory, manifest, p, command=command)
        raise
    if schema3(p):
        require_stages(directory / "protocol.json", manifest["mode"])  # STAGES_RULE
    # KillMode=mixed: SIGTERM reaches only the runner, which stops its child in
    # order; anything left after it exits (or after the timeout) gets SIGKILL.
    for name in vm_names(p) if vm is None else [vm]:
        unit = vm_unit(name)
        command = ["systemd-run", "--collect", f"--unit={unit}", "--description=hyptcn3 benign collection campaign",
                   "--property=Type=exec", "--property=KillMode=mixed", "--property=TimeoutStopSec=240",
                   "--property=Restart=no", f"--working-directory={ROOT}",
                   f"--setenv=SUDO_USER={manifest['owner']['name']}", f"--setenv=SUDO_UID={manifest['owner']['uid']}",
                   f"--setenv=SUDO_GID={manifest['owner']['gid']}",
                   sys.executable, ROOT / "scripts/campaign.py", "run", directory]
        if name is not None:
            command += ["--vm", name]
        if stop_after:
            command += ["--stop-after", str(stop_after)]
        subprocess.run(list(map(str, command)), check=True, timeout=30)
        print(f"Log: journalctl -fu {unit}")
    print(f"Status: python3 scripts/campaign.py status {directory}")


def campaign_running(state):
    return (state.get("status") == "running" and state.get("process_identity") is not None
            and process_identity(state.get("pid")) == state["process_identity"])


def request_stop(directory, vm=None, reason=None):
    """Ask the running campaign to stop before its next capture; the current session is kept.

    Multi-VM: every running runner gets its own request, or only the one named. Under protocol schema 3 the
    request names its reason (required, refused by name without one): the runner that honors it ends the campaign as
    stopped, every other active runner stops at its next check, and the reason is a deviation of the record
    (ENDING_RULE, package B9b).
    """
    directory = Path(directory).resolve()
    _, p = load_campaign(directory)
    if vm is not None and vm not in vm_names(p):
        raise ValueError("campaign has no VM " + vm)
    if schema3(p) and (type(reason) is not str or not reason.strip()):
        raise ValueError("a stop of a campaign of protocol schema 3 names its reason (--reason TEXT, no default): it is "
                         "a deviation of the campaign's record (scripts/campaign.py ENDING_RULE)")
    running = [name for name in (vm_names(p) if vm is None else [vm])
               if (directory / vm_file("status.json", name)).exists()
               and campaign_running(read_json(directory / vm_file("status.json", name)))]
    if not running:
        raise ValueError("campaign is not running")
    for name in running:
        try:
            write_new(directory / vm_file("stop-request.json", name), {
                "schema": "hyptcn3/campaign-stop-request/1", "date": now(), "uid": os.getuid(),
                **({} if name is None else {"vm": name}), **({} if reason is None else {"reason": reason}),
                "note": "The current session finishes, is audited and archived; no new capture starts."})
        except FileExistsError:
            raise ValueError("stop already requested") from None
    print(f"Stop requested; follow: python3 scripts/campaign.py status {directory}")


def close(directory, reason):
    """Operator decision to end a stopped campaign: its data stays, its group names become reusable. Under protocol
    schema 3 its ending pending since a crash is recorded first, then the record of the closed ending (ENDING_RULE,
    package B9b), before closed.json."""
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if not reason.strip():
        raise ValueError("closing a campaign requires a reason")
    names = vm_names(p)
    command = shlex.join(["python3", "scripts/campaign.py", "close", str(directory), "--reason", reason])
    with ExitStack() as locks:
        # No runner of any campaign may be active; multi-VM: no runner on any of its domains.
        for row in collection.vms(p):
            locks.enter_context(collection.collection_lock(COLLECTIONS, row["domain"] if row["name"] else None))
        states = {vm: read_json(directory / vm_file("status.json", vm))
                  if (directory / vm_file("status.json", vm)).exists() else {} for vm in names}
        state = states[None] if names == [None] else {"vms": states}
        # One VM's finished share (vm-complete) does not complete the campaign.
        for each in states.values():
            if each.get("status") == "closed" or (each.get("status") == "complete"
                                                  and each.get("stage") != "vm-complete"):
                raise ValueError("campaign is already " + each["status"])
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        if schema3(p):  # ENDING_RULE: no runner is active under these locks.
            settle(directory, manifest, p, command=command)
            latest = latest_ending(directory)
            if latest is None or latest["ending"] != "closed":  # A close that failed after its record writes none.
                trigger = {"date": now(), "vm": None, "ending": "closed", "cause": reason,
                           "detail": {"uid": os.getuid(), "status_before": state}}
                with ending_lock(directory):
                    publish_ending(directory, manifest, ending_record(
                        directory, manifest, p, "closed", [trigger], cause=f"closed by the operator: {reason}",
                        command=command))
        write_new(directory / "closed.json", {
            "schema": "hyptcn3/campaign-closed/1", "id": manifest["id"], "date": now(), "reason": reason,
            "uid": os.getuid(), "status_before": state,
            "note": "Operator decision. Captured, audited and archived sessions remain; no corpus index."})
        copy_exclusive(directory / "closed.json", Path(manifest["archive_dir"]) / "closed.json")
        for vm in names:
            update_state(directory, vm=vm, status="closed", stage="closed", message=reason)


def status(directory):
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if vm_names(p) == [None]:
        state = vm_status(directory, manifest, p, None)
    else:
        state = {"campaign": str(directory), "vms": {vm: vm_status(directory, manifest, p, vm) for vm in vm_names(p)}}
    if schema3(p):  # ENDING_RULE: the pending ending and the last recorded one (status records nothing).
        state["ending"] = {"pending": pending_ending(directory), "recorded": latest_ending(directory)}
    print(json.dumps(state, indent=2, ensure_ascii=False))
    return state


def vm_status(directory, manifest, p, vm):
    state = read_json(directory / vm_file("status.json", vm))
    state["running"] = campaign_running(state)
    # Every audit rejection with its cause and, if the protocol allowed one, its replacement.
    state["rejections"] = [{"cause": "audit_rejected", **{k: r[k] for k in (
        "date", "session", "cause", "reasons", "replacement", "not_replaced") if k in r}}
                           for r in rejections(directory, vm)]
    state["rejections_by_cause"] = rejections_by_cause(directory)  # LIMIT_RULE: every VM's, by cause.
    if state.get("status") == "running" and not state["running"]:
        state["stale"] = True
        state["note"] = ("recorded as running but that process is not alive (SIGKILL, crash or power loss); "
                         "the current session is incomplete and the next run records an unclean end")
    state["sleep_inhibitor_active"] = sleep_inhibited()
    state["campaign"] = str(directory)
    if "continues" in manifest:
        state["continues"] = manifest["continues"]["campaign"]
        state["taken_over"] = sum(r.get("vm") == vm and taken_over(manifest, r) is not None
                                  for r in manifest["sessions"])
    state["planned_capture_hours"] = manifest["planned_capture_hours"]
    if state.get("session"):
        raw = session_dir(manifest, {"session_id": state["session"], **({} if vm is None else {"vm": vm})}) / "raw"
        state["snapshot_images_present"] = len(list(raw.glob("*.vmicd")))
        state["snapshots_expected"] = p["cycles"]
    return state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Freeze the plan, the source, the external mount and (schemas 1 and 2) the "
                                       "accepted pilot")
    init.add_argument("--protocol", type=Path, default=collection.DEFAULT)
    init.add_argument("--pilot-report", action="append", metavar="[VM=]PATH",
                      help="Protocol schemas 1 and 2 (required there): accepted pilot audit; multi-VM protocol: one "
                           "VM=PATH per VM. Protocol v5 has no pilot and refuses it (PILOT_RULE)")
    init.add_argument("--mode", choices=protocol_v5.MODES,
                      help="Protocol schema 3 (required there, no default; refused under schemas 1 and 2): the plan "
                           "of the campaign or of its rehearsal (MODE_RULE)")
    init.add_argument("--estimate-from", type=Path, metavar="REHEARSAL_DIR",
                      help="Protocol schema 3, mode campaign (required there, refused otherwise): the campaign "
                           "directory of an ended rehearsal whose largest accepted session seeds the disk estimate "
                           "(DISK_RULE)")
    init.add_argument("--archive-root", type=Path, required=True)
    init.add_argument("--name")
    init.add_argument("--archive-on-system-disk", action="store_true",
                      help="Explicitly allow an archive on the root filesystem (no second disk)")
    init.add_argument("--archive-compression", choices=["zstd", "none"], default="zstd")
    init.add_argument("--continue", dest="continues", type=Path, metavar="CAMPAIGN_DIR",
                      help="Continue this campaign of the same protocol once: take over its complete groups, capture "
                           "every other group again; protocol schema 3: a paused campaign (with --cause, "
                           "CONTINUATION_RULE), schemas 1 and 2: a closed one")
    init.add_argument("--cause", metavar="TEXT",
                      help="Protocol schema 3, with --continue (required there, no default; refused otherwise): the "
                           "written cause of the pause, a deviation of the continuation's records (CONTINUATION_RULE)")
    for verb in ("run", "launch", "status", "verify-archives", "request-stop", "close"):
        cmd = sub.add_parser(verb)
        cmd.add_argument("directory", type=Path)
        if verb in ("run", "launch"):
            cmd.add_argument("--stop-after", type=int, help="Stop after this many newly archived sessions")
            cmd.add_argument("--cause", metavar="TEXT",
                             help="Protocol schema 3, after an early stop (required then unless a written cause "
                                  "answers it already, no default; refused otherwise): the written analysis of the "
                                  "stop, a deviation of every later record (RESUME_RULE)")
        if verb in ("run", "launch", "request-stop"):
            cmd.add_argument("--vm", help="Multi-VM campaign: this VM's runner (run requires it; "
                                          "launch and request-stop default to all VMs)")
        if verb == "close":
            cmd.add_argument("--reason", required=True, help="Recorded operator decision")
        if verb == "request-stop":
            cmd.add_argument("--reason", help="Protocol schema 3 (required there, no default): why the campaign "
                                              "stops, a deviation of its record (ENDING_RULE)")
    a = ap.parse_args(argv)
    if getattr(a, "stop_after", None) is not None and a.stop_after < 1:
        ap.error("stop-after must be positive")
    if a.command == "init":
        initialize(a)
    elif a.command == "status":
        status(a.directory)
    elif a.command == "launch":
        launch(a.directory, a.stop_after, a.vm, a.cause)
    elif a.command == "run":
        return execute(a.directory, stop_after=a.stop_after, vm=a.vm, cause=a.cause)
    elif a.command == "request-stop":
        request_stop(a.directory, a.vm, a.reason)
    elif a.command == "close":
        close(a.directory, a.reason)
    else:
        manifest, _ = load_campaign(a.directory)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        for row in (r for planned in manifest["sessions"] for r in chain(a.directory.resolve(), planned)):
            dest = archive_dest(manifest, row)
            if dest.exists():
                verify_archive(dest, session_dir(manifest, row))
                print("verified " + row["session_id"], flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"campaign: {error}", file=sys.stderr)
        sys.exit(2)
