"""The fakes of the G1 dry run (protocol v5, G1 preparation, package C3): the campaign of the command
python -m tcn.suchy_beh beh on the harness of scripts/tests/kampan_v5.py.

Binding texts: the skeleton dokazy/G1/kostra/KOSTRA.md (row C3 of section 1, section 2) with the lead's answers to Q32
to Q41 (2026-11-24T21:25Z) and point 5 of his POKYNY_TEMPO_2026-11-25. The campaign runs as on the collection PC: the
real scripts/campaign.py (init --mode rehearsal, its runners, init --mode campaign --estimate-from the rehearsal, the
replacements, the ledger through tcn.pecat, finish_corpus with features/dataset.py build and
safeguard.training.validate_index, the record of the complete ending). What this module replaces is FAKES, which the
command writes into zaznam.json, each with the attributes it patches; INFRASTRUCTURE lists what the harness patches
beside them, none of which stands in for a result (directories, waits, the children served in this process, the run's
ledger, spies); nothing else is patched:

    Kampan              kampan_v5.Harness with two changes. The capture (collection.run_session) builds the planned
                        session or its replacement with postav_session; the audit is the real
                        scripts/collection.py audit_session through scripts/tests/boundary_sessions.py audit, with only
                        collection.retazec (the feature extraction from guest RAM) returning the session's rows. The
                        ledger of the process (tcn.pecat.KNIHA) is the run's own, while the ledger of record
                        (tcn.pecat.ZAZNAM) stays the tracked file, so every stage the campaign and its records read is
                        suchy (tcn/pecat.py STAGE_RULE); a write of the tracked file is refused before it happens
    postav_session      one session as a capture leaves it, before its audit (SESSION_RULE): the row of a plan of the
                        working copy (or its replacement), the rows of scripts/tests/suchy_generatory.py riadky in its
                        mode and run seed, the evidence of boundary_sessions.build_session under the copy's rate, the
                        row's events that ran and its controls, the identity of the group's guest boot and QEMU process
    zapis_prevadzky     the traffic of that session (PREVADZKA_RULE, package C3b): the real scripts/host_traffic.py on
                        a simulated clock with the lab's answers of LAB_RULE and the arrivals of PRICHODY_RULE, whose
                        counts follow the planned offered load of suchy_generatory.ponukana_zataz, the load the
                        counts of the rows follow and Z4 reads (the lead's answer to Q72 point 2)
    ponuka_relacii      the offered user sessions of a session from one function (ZATAZ_RULE, package C4b): the
                        arrivals the full path's generator runs, counted into its summary intervals, and Ponuka.zataz,
                        the offered load of every row as features/qualification.py offered_load weighs them; the full
                        path checks its logs against it (over_zataz_logov), the shortened path reads it without logs
    bez_prevadzky       the shortened path's session without traffic (SKRATENA_RULE, package C4b): no traffic log,
                        no seal of the logs, and the session audit without its log audit (audit_logov_skratenej)
    zaznam_generatora   the readers' form of generator.json (tcn/suchy_beh.py GENERATOR_KEYS) of the sessions of a
                        corpus, from the records of suchy_generatory.zaznam (GENERATOR_MAP_RULE)

A session named in Harness.reject is built with one read error (READ_ERROR_RULE), which the real audit refuses, so the
campaign replaces it with its next attempt. The shortened path of the command (python -m tcn.suchy_beh beh --cesta
skratena) builds every session of its campaign and of its qualification pass without traffic (the lead's answer to Q73
point 2, 2026-11-25T21:20Z: only seed 0 of the null generator writes and audits the traffic logs), with the fakes of
FAKES_SKRATENA beside FAKES. Only mechanics on synthetic sessions (HONESTY P4).
"""
import bisect
import contextlib
import copy
import functools
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import threading
from types import SimpleNamespace

import numpy as np

from features.audit_policy import audit_bounds
from scripts import collection
from scripts import host_traffic as ht
from scripts import protocol_v5 as pv
from scripts.collection_archive import read_json
from scripts.tests import boundary_sessions as bs
from scripts.tests import kampan_v5 as kv
from scripts.tests import suchy_generatory as sg
from scripts.tests import test_collection_logs as evidence
from scripts.tests import test_host_traffic_v5 as htv5

# What the dry run still fakes (the skeleton, row C3: lab, the host's identity and swap, the archive, the campaign's
# requirement of the stages and of the self-test, the sleep inhibitor, root), each with what stands in for it and the
# attributes it patches. The capture and the extraction from guest RAM are the fakes the skeleton names beside them;
# git of the campaign is the harness's (the executor's reading, G1 preparation: a campaign freezes a clean tree, and a
# dry run writes its own directories beside the commit it runs on).
FAKES = (
    {"fake": "lab", "what": "labctl stop, start, reset --seed, pretouch, levels and reboot of the two VMs of the "
     "protocol, the guest identity they print (scripts/tests/kampan_v5.py Lab, with the stack manifest of "
     "boundary_sessions) and the VM's QEMU process", "why": "no VM in G1 (proposal 10.2)",
     "patches": ["scripts.collection.lab_json", "scripts.collection.guest_identity",
                 "scripts.collection.qemu_process"]},
    {"fake": "host identity and swap", "what": "the runtime identity of the host (vm.swappiness 1), the memory of a "
     "QEMU without swap, the identity of the runner's process", "why": "no root and no VM in G1",
     "patches": ["scripts.campaign.runtime_identity", "scripts.collection.host_memory",
                 "scripts.campaign.process_identity"]},
    {"fake": "archive", "what": "the archive mount on the run's working directory (no archive disk), without "
     "compression", "why": "no archive disk in G1; the copies of the archiver are real",
     "patches": ["scripts.campaign.mount_identity", "scripts.campaign.guard_mount"]},
    {"fake": "the stages and the self-test of the campaign", "what": "scripts.gates.require and "
     "scripts.audit_selftest.require_selftest inside the campaign and its children: recorded, never refused",
     "why": "a campaign session needs G0 to G4 and a self-test record of G2 rates (scripts/collection.py "
     "SESSION_GATES); the command itself calls the real gates.require of G1 on the real file and on the copy",
     "patches": ["scripts.gates.require", "scripts.audit_selftest.require_selftest"]},
    {"fake": "sleep inhibitor", "what": "campaign.hold_sleep_inhibitor and sleep_inhibited", "why": "needs logind",
     "patches": ["scripts.campaign.hold_sleep_inhibitor", "scripts.campaign.sleep_inhibited"]},
    {"fake": "root", "what": "os.geteuid 0, SUDO_USER the account that runs the command (SUDO_UID, SUDO_GID and "
     "HYPTCN_COLLECTION_LOCK_FD unset) and a child run as that account as it is (collection.user_command)",
     "why": "no sudo in G1", "patches": ["os.geteuid", "env SUDO_USER", "env SUDO_UID", "env SUDO_GID",
                                         "env HYPTCN_COLLECTION_LOCK_FD", "scripts.collection.user_command"]},
    {"fake": "git of the campaign", "what": "git status --porcelain is empty for scripts/campaign.py (init, "
     "tree_changes), git rev-parse HEAD the real commit, and the frozen-tree check of a running campaign "
     "(verify_frozen) passes", "why": "the run writes its work and its evidence beside the commit it runs on, which "
     "init refuses as a dirty tree (the executor's reading, G1 preparation); the real audit records the real commit, "
     "which the campaign compares with its frozen one (scripts/campaign.py audit_environment)",
     "patches": ["scripts.campaign.git", "scripts.campaign.verify_frozen"]},
    {"fake": "capture", "what": "collection.run_session: postav_session (suchy_kampan.SESSION_RULE)",
     "why": "no VM in G1: the skeleton's fake capture", "patches": ["scripts.collection.run_session"]},
    {"fake": "the lab's answers and the clock of the traffic generator", "what": "the real scripts/host_traffic.py "
     "of the session's command line (scripts/collection.py traffic_command) writes the traffic logs of every session "
     "on a clock that jumps from one scheduled time to the next (every request lasts 0 s) with the answers of the lab "
     "of suchy_kampan.LAB_RULE, the arrivals of suchy_kampan.PRICHODY_RULE (the counts follow the planned offered "
     "load, suchy_generatory.ponukana_zataz); nginx and the services' journal lines follow its requests "
     "(suchy_kampan.PREVADZKA_RULE)", "why": "no VM and no lab in G1 (the lead's answer to Q72 point 2: the load Z4 "
     "reads is the load the counts follow)", "patches": []},
    {"fake": "extraction from guest RAM", "what": "collection.audit_session is the real one, whose "
     "collection.retazec returns the session's rows of scripts/tests/suchy_generatory.py riadky "
     "(boundary_sessions.audit); every other check of the audit and the log audit are real",
     "why": "the RAM images of a dry run are synthetic", "patches": ["scripts.collection.audit_session"]},
)
# What the harness patches beside FAKES, none of which stands in for a result: the directories and the waits of the
# run, the children the campaign starts served in this process (the capture, the audit, labctl and tcn.pecat, each
# then the real code or a fake of FAKES; virsh, ssh, systemctl, sudo and the like refused), the run's own ledger, and
# spies that record a call and then make the real one.
INFRASTRUCTURE = (
    {"what": "the directories of the run: the collections, the campaigns and the records of the endings",
     "patches": ["scripts.campaign.COLLECTIONS", "scripts.campaign.BASE", "scripts.campaign.RESULTS"]},
    {"what": "the waits of the runners, which the harness drives in turn (kampan_v5 Harness.run)",
     "patches": ["scripts.campaign.RETRY_PAUSE_S", "scripts.campaign.WAIT_POLL_S", "scripts.campaign.START_GRACE_S"]},
    {"what": "the children of the campaign served in this process (kampan_v5 Harness.serve), a forbidden program "
     "refused", "patches": ["scripts.campaign.run_child", "subprocess.run", "subprocess.check_output",
                            "subprocess.Popen"]},
    {"what": "the run's own ledger (tcn.pecat.KNIHA; the ledger of record ZAZNAM stays the tracked file, so the stage "
     "is suchy) and the refusal of a write of the tracked file", "patches": ["tcn.pecat.KNIHA", "tcn.pecat._write"]},
    {"what": "spies that record each call and make the real one", "patches": ["scripts.campaign.finish_corpus",
                                                                              "tcn.pecat.kontrola"]},
)
# What the shortened path of the dry run fakes beside FAKES (package C4b; the lead's answer to Q73 point 2,
# 2026-11-25T21:20Z: the shortened path neither writes nor audits the traffic logs, only seed 0 of the null generator
# does), each with the attributes it patches; a run of --cesta skratena names them in zaznam.json (fakes).
FAKES_SKRATENA = (
    {"fake": "the traffic of the shortened path", "what": "postav_session with prevadzka false (SKRATENA_RULE): the "
     "capture writes no traffic, its generator does not run, and the offered load of the session's rows comes from "
     "ponuka_relacii (ZATAZ_RULE), the function whose arrivals the full path's generator runs and whose values the "
     "full path checks against the offered load of its logs", "why": "the lead's answer to Q73 point 2: the traffic "
     "logs of the 22 runs of the shortened path would cost about 35 h of C4", "patches": []},
    {"fake": "the log audit of the shortened path", "what": "scripts/collection.py audit_logs, the log audit the "
     "session audit (collection.audit_session) runs: audit_logov_skratenej, which reads no log and whose record "
     "admits the session (SKRATENA_RULE); features/quality.py require_log_audit, in the corpus build of "
     "finish_corpus, in the production check of training and in train_bundle, then reads that record and repeats "
     "nothing, since the session keeps no logs_manifest.json", "why": "the shortened path writes no traffic logs, "
     "which the log audit reads (the lead's answer to Q73 point 2)", "patches": ["scripts.collection.audit_logs"]},
)


def fakes(prevadzka):
    """The fakes a run names in zaznam.json: FAKES, and FAKES_SKRATENA beside them when its sessions are built without
    traffic (prevadzka false, the shortened path)."""
    return FAKES if prevadzka else (*FAKES, *FAKES_SKRATENA)


SESSION_RULE = (
    "a session of the dry run as a capture leaves it, before its audit (the skeleton of G1, row C3): "
    "boundary_sessions.build_session of the row (a row of the plan of the working copy in its mode, or its "
    "replacement, protocol_v5.replacement, with its attempt), its first snapshot at the time of the clock of the "
    "harness, every sidecar at the time of its row; the generator's frame (the events, the controls and the rows of "
    "suchy_generatory) starts suchy_generatory.FIRST_ROW_S before the first snapshot, and the measurement with it "
    "(end.json measure_start_unix; test_collection_logs.build starts it 1 s after its base and ends it "
    "ceil(cycles x interval_s) + 1 s after that), so that the traffic begins warmup_s before the measurement as "
    "scripts/collection.py capture_session starts it and suchy_generatory.LOAD_RULE plans it; the traffic of the whole "
    "session by the real generator (PREVADZKA_RULE, package C3b: its logs in place of those of "
    "test_collection_logs.v5_traffic, which build_session writes first), or in the shortened path no traffic and no "
    "seal of the logs (SKRATENA_RULE, package C4b), the offered load of its rows from ZATAZ_RULE in both; session.json "
    "with the row's events and controls as the plan states them, the guest identity of the group's boot (the lab's, "
    "with the stack manifest of boundary_sessions) and the QEMU process of the group (every sidecar names its pid), "
    "and the fields of the capture of kampan_v5 (campaign, attempt, plan mode, commit); events.json the row's events "
    "that ran (host_start_unix the start of the generator's frame + start_s, host_stopped_unix 0.1 s after the stop, "
    "effect ok, the replies with test_collection_logs.SCRIPT_SHA256), controls.json of a session of test_controls "
    "suchy_generatory.controls_json; the evidence sealed again (the full path); the rows of the extraction "
    "suchy_generatory.riadky in the run's mode and seed in the generator's frame")
READ_ERROR_RULE = (
    "the rejection the dry run injects (the skeleton of G1, section 2, chain_end_to_end: one replacement at least, the "
    "rejection through Harness.reject): the session of a (group, scenario, attempt) in Harness.reject has one read "
    "error in the snapshot in the middle of its first chain, in its sidecar (stats.read_errors 1) and in its row "
    "(boundary_sessions.read_error_row, no predecessor after it); the real audit refuses it, the campaign replaces it")
GENERATOR_MAP_RULE = (
    "the form of generator.json the readers of tcn/suchy_beh.py read (GENERATOR_KEYS), per session of the corpus by "
    "its session id: invalid_rows the seq of the tolerated invalid rows of its record (suchy_generatory.zaznam "
    "invalid_rows.seq), marginal_changes one {first_seq, rows, column} per change of the record (its first seq, its "
    "count of rows, its column), unevaluated the occurrence whose first seconds the invalid rows leave scored less "
    "than analysis.evaluable.scored_share (evaluable false in the record), {what: control in role test_controls else "
    "event, index: its index among the events or the controls with a kind, type: the event's type or the control's "
    "kind}")
PREVADZKA_RULE = (
    "the traffic of a session of the dry run (package C3b; the lead's answer to Q72 point 2: the load Z4 reads is the "
    "load the counts follow): the real scripts/host_traffic.py of the command line scripts/collection.py "
    "traffic_command gives the session (its copy of the protocol, the scenario, the row's traffic seeds, the "
    "protocol's rate, --dur warmup_s + cycles x interval_s, --warmup-s, summary intervals of 5 s), read as its main "
    "reads it: prepare_v5 (the envelope of draw_envelope from the row's traffic seed, as "
    "suchy_generatory.ponukana_zataz draws it, and the arrival plan of arrival_times), SessionRecorder (both logs of "
    "schema /2, the header with the rate and its source, every summary interval with offered_sessions and "
    "planned_sessions, the arrival records and the user session fields of every request), OpenLoop and UserClient "
    "with the user sessions of eshop and corp; three things differ from a run on the lab: the arrivals of "
    "PRICHODY_RULE, a clock that jumps from one scheduled time to the next (scripts/tests/test_host_traffic_v5.py "
    "FakeClock: every request lasts 0 s) on the session's times (the origin warmup_s before end.json "
    "measure_start_unix, the phase measure at measure_start_unix, post at measure_end_unix, the stop STOP_AFTER_S "
    "after it), and the answers of LAB_RULE; two things differ from the generator's process: the run id is the first "
    "12 hex digits of the sha256 of the session id (the generator draws a random one), so that a session built twice "
    "is the same, and its log writer (host_traffic Writer, its records, their numbers and both end records) writes "
    "every record when it is put, in the thread of the simulation (the generator's writer thread keeps the requests "
    "from waiting for the disk; the records are the same, and the simulation does not switch threads for each); "
    "traffic.json is the generator's status at its stop (host_traffic main_v5 save; its three fields of the real "
    "clock, elapsed_s, ok_per_s and updated_at, on the session's clock), traffic_before.json its status at the end of "
    "the warmup through scripts/collection.py check_warmup, end.json traffic_rc its exit "
    "code (main_v5), session.json traffic the block of scripts/collection.py _v5_traffic; nginx's access line and the "
    "services' journal lines of every request at its end, as test_collection_logs.v5_traffic writes them (the service "
    "of its route, the call of auth where the route asks it, the catalog call of an order; test_collection_logs "
    "_service and _asks_auth), each service under its pid in the guest's state; the lines of the requests of "
    "test_collection_logs.build and v5_traffic leave both segments")
PRICHODY_RULE = (
    "the arrivals of a session of the dry run (package C3b): the generator's plan (host_traffic arrival_times of the "
    "stream traffic_arrivals) but in the summary interval that holds most of the interval (t - interval_s, t] of a "
    "row (the row's main interval, from 0.9 of it in the dry run's frame), which gets the count that brings the "
    "row's offered load (features/qualification.py offered_load: every summary interval adds its offered_sessions "
    "times the share of its length inside the row's interval) nearest to the row's plan, rate x the integral of the "
    "envelope over the row's interval (suchy_generatory.ponukana_zataz and LOAD_RULE), from the last row to the "
    "first (the next row's main interval, which a row reads at 0.1, is decided before it), wherever that plan is at "
    "least 0.5 / audit.traffic.offered_load_tolerance user sessions, so that a count of whole user sessions reads it "
    "within the tolerance of the log audit (2.5 at the tolerance 0.2; every row at the rates of Zápis 1 of G2); the n "
    "arrivals of such an interval are placed anew, the n + 1 gaps on the envelope's integral (from the interval's "
    "start to the first arrival, between them, from the last to its end) Dirichlet with parameter (n - 1) / (n + 1) "
    "(one arrival uniform), under which every gap has the coefficient of variation 1 of a gap of a Poisson process, "
    "so that the count the plan fixes does not lower the coefficient of variation of the rescaled spacings that the "
    "log audit judges (scripts/traffic_log.py realism arrival_cv, bounds 0.8 to 1.2; the executor's judgment, G1 "
    "preparation, from design checks of envelopes of each profile at 96 and 720 rows: the uniform placement, the "
    "law of a Poisson process given its count, gave 0.83 to 1.02 at 3.2 and 4.4 user sessions a second over 40 "
    "envelopes, the Dirichlet one 0.84 to 1.16 at 1.2 to 11.7376 over 60, its mean 0.98 to 1.0), mapped to times by "
    "the generator's inverse of the integral "
    "(Envelope.inverse), rounded as it rounds them and inside the interval; every other interval keeps the "
    "generator's arrivals as drawn (the warmup but the main interval of the first row, the time after the last row, "
    "a row whose plan is lower); the draws continue the stream traffic_arrivals after arrival_times")
LAB_RULE = (
    "the lab's answers to the generator in the dry run: scripts/tests/test_host_traffic_v5.py FakeLab (the routes of "
    "lab/services.py and lab/nginx.conf, the cart of every customer, the deliberate client errors with their status), "
    "a static file and a document of the seeded level with the size lab/seed.py gives it: static_files(0) by its "
    "name, generate(0) by its id (one PBKDF2 iteration, on which no size depends; seed 0, the executor's judgment), "
    "their content not built (the generator reads only its length)")
ZATAZ_RULE = (
    "the offered load of a session of the dry run from one function (package C4b; the lead's answer to Q73 point 2, "
    "2026-11-25T21:20Z: 'Z4 dostane ponúkanú záťaž priamo z toho istého agregátora, ktorý z logov počíta "
    "host_traffic.py (jedna funkcia)'): ponuka_relacii of the session directory, its row and the times of its rows "
    "gives the arrivals of PRICHODY_RULE (prepare_v5 of the session's command line, scripts/collection.py "
    "traffic_command, with the traffic block of its session.json, and its arrival plan with the counts placed in the "
    "rows' main intervals), counted into the summary intervals of hranice_intervalov as host_traffic.py counts them "
    "(SessionRecorder arrival: an arrival at t in the interval [start, end) that holds it), and Ponuka.zataz weighs "
    "those counts into the interval (t - interval_s, t] of every row time t as features/qualification.py offered_load "
    "weighs the summary intervals of traffic_intervals.jsonl (their start and end as the log writes them, rounded to "
    "1 us, at the header's start_unix, the origin of the generator's clock; every interval adds its offered sessions "
    "times the share of its length inside the row's interval; a list, or the reason why there is none, as "
    "offered_load returns it); the full path (zapis_prevadzky) runs the generator on the arrivals of that function "
    "and checks by name that its traffic_intervals.jsonl holds the function's bounds and counts and that offered_load "
    "of it equals Ponuka.zataz at the time of every row (over_zataz_logov), so that the two paths cannot drift apart "
    "unseen; the shortened path (SKRATENA_RULE) reads Ponuka.zataz without logs, in the qualification pass of "
    "tcn/suchy_beh.py and in its final evaluation (tcn/suchy_beh.py ZATAZ_FINALNE_RULE)")
# The files of the generator in a session directory (scripts/collection.py capture_session: the two logs and the status
# of traffic_command, the child's log traffic.log, and traffic_before.json of check_warmup).
TRAFFIC_FILES = ("traffic_requests.jsonl", "traffic_intervals.jsonl", "traffic.json", "traffic_before.json",
                 "traffic.log")
SKRATENA_RULE = (
    "a session of the shortened path of the dry run (package C4b; the lead's answer to Q73 point 2, "
    "2026-11-25T21:20Z: 'Skrátená cesta logy prevádzky nepíše ani neaudituje'; only seed 0 of the null generator "
    "writes and audits them): postav_session with prevadzka false writes none of what zapis_prevadzky writes for the "
    "traffic: the generator does not run, so the session holds no file of TRAFFIC_FILES (those "
    "boundary_sessions.build_session wrote with test_collection_logs.build and v5_traffic are removed), end.json no "
    "traffic_rc, and the nginx and journal segments no line of a request (the lines of the requests of build and "
    "v5_traffic leave them); its logs are not sealed (no logs_manifest.json and no logs_manifest_sha256 in end.json: "
    "the seal is read by the log audit, and features/quality.py require_log_audit repeats the log audit only where "
    "the session keeps one); session.json keeps the traffic block of scripts/collection.py _v5_traffic, the session's "
    "plan of its traffic, which ZATAZ_RULE reads; the session audit (scripts/collection.py audit_session, in the "
    "campaign and in the qualification pass) runs without its log audit: audit_logs is audit_logov_skratenej, which "
    "reads no log and returns a record of the log audit's schema with not_run naming this rule, its metadata section "
    "(the sha256 of session.json and end.json, the measurement's times), no problem, nothing tolerated and accepted, "
    "and which refuses a session that holds a file of TRAFFIC_FILES or a logs_manifest.json; the requirements of the "
    "corpus (features/quality.py require_log_audit in the corpus build of finish_corpus, in the production check of "
    "training and in train_bundle) read that record and repeat nothing (not repeated: no logs_manifest.json); every "
    "other part of the session (session.json, end.json but traffic_rc and logs_manifest_sha256, events.json, "
    "controls.json, the rows, the snapshots and their sidecars, the guest's states, its segments but the lines of "
    "requests, the host monitor, the collector's log and the profile) is that of the full path; the faults' Session "
    "target of --chyby is built with its traffic and its log audit in both paths (tcn/suchy_beh.py FAULTS_RULE)")
STOP_AFTER_S = 0.5  # The runner stops the generator this long after the post phase begins (judgment; stop_child).
MAX_PLACEMENTS = 1000  # Draws of an interval's arrivals until all lie inside it (judgment), then refused.
MIDDLE = lambda p: p["full_every"] // 2  # noqa: E731 - the snapshot of READ_ERROR_RULE (as vlozene_chyby._middle).
EVENT_STOPPED_S, EVENT_STARTED_S = 0.1, 0.05  # The host's calls of an event (judgment: within the event's window).


def profil(p):
    """The guest profile directory of the protocol, absolute (a relative one lies in the repository)."""
    path = Path(p["profile"])
    return path if path.is_absolute() else collection.ROOT / path


def planovany_riadok(protokol, mode, role, group, scenario, vm, attempt):
    """The row of attempt `attempt` of the planned session (scripts/collection.py v5_planned): the session of
    protocol_v5.plan(protokol, mode) of this role, group, scenario and VM for attempt 1, protocol_v5.replacement of it
    for a later one; with its attempt (suchy_generatory takes it)."""
    found = [s for s in pv.plan(protokol, mode)["sessions"]
             if (s["role"], s["group"], s["scenario"], s.get("vm")) == (role, group, scenario, vm)]
    if len(found) != 1:
        raise ValueError(f"no one planned session of {role}, {group}, {scenario}, VM {vm} in the {mode} plan")
    row = found[0] if attempt == 1 else pv.replacement(protokol, found[0], attempt, mode=mode)
    return dict(copy.deepcopy(row), attempt=attempt)


def _udalosti(row, frame_start):
    """The records of events.json of the row's events that ran (SESSION_RULE)."""
    out = []
    for item in row.get("events", []):
        start = frame_start + item["start_s"]
        stop = start + item["duration_s"]
        out.append(dict(item, executed=True, effect={"ok": True, "predicate": "synthetic"}, host_start_unix=start,
                        host_started_unix=start + EVENT_STARTED_S, host_stop_unix=stop,
                        host_stopped_unix=stop + EVENT_STOPPED_S,
                        start={"ok": True, "script_sha256": evidence.SCRIPT_SHA256},
                        stop={"ok": True, "health": 200, "script_sha256": evidence.SCRIPT_SHA256}))
    return out


def _chyba_citania(result, directory, p):
    """READ_ERROR_RULE in the rows and the sidecar of a built session."""
    seq = MIDDLE(p)
    i = result["seq"].index(seq)
    result["quality"][i] = bs.read_error_row()
    result["valid"][i] = False
    if i + 1 < len(result["seq"]):
        for name in ("ma_predchodcu", "proc_new", "proc_gone", "mod_delta"):
            result["matica"][i + 1][result["mena"].index(name)] = 0.0
    found = [path for path in (Path(directory) / "raw").glob("*.json")
             if json.loads(path.read_text()).get("seq") == seq]
    side = json.loads(found[0].read_text())
    side["stats"]["read_errors"] = 1
    evidence.write(found[0], side)


# ------------------------------------------------------------------ the traffic of a session (package C3b)

class _Telo:
    """A response body of `n` bytes that is not built: the generator reads only its length (LAB_RULE)."""
    __slots__ = ("n",)

    def __init__(self, n):
        self.n = n

    def __len__(self):
        return self.n


@functools.lru_cache(maxsize=1)
def _velkosti_labu():
    """LAB_RULE: ({static file: bytes}, {document id: bytes}) of the seeded level of lab/seed.py at seed 0."""
    from lab import seed
    level = seed.generate(0, iterations=1)
    return dict(seed.static_files(0)), {item["id"]: item["bytes"] for item in level["documents"]}


class SluzbyLabu(htv5.FakeLab):
    """LAB_RULE: the lab's answers to the requests of the generator."""

    def __init__(self):
        super().__init__()
        self.static, self.documents = _velkosti_labu()

    def _answer(self, method, path, query, auth, body, rid):
        status, kind, data = super()._answer(method, path, query, auth, body, rid)
        if status == 200 and method == "GET" and path.startswith("/static/"):
            data = _Telo(self.static[path[len("/static/"):]])
        elif status == 200 and method == "GET" and path.startswith("/api/docs/"):
            data = _Telo(self.documents[int(path.rsplit("/", 1)[1])])
        return status, kind, data


class Hodiny(htv5.FakeClock):
    """The clock of PREVADZKA_RULE: test_host_traffic_v5 FakeClock (a wait jumps to the next scheduled time, an event
    runs when the time reaches it, the run stops at `limit`) whose wall clock is `origin_wall` + its time."""

    def __init__(self, origin_wall, limit, stop):
        super().__init__(limit, stop)
        self.origin_wall = origin_wall

    def wall(self):
        return self.origin_wall + self.now

    def dobeh(self):
        """After the scheduler returned: the events up to the limit, then the limit (the runner's stop)."""
        while self.events and self.events[0][0] <= self.limit:
            when, callback = self.events.pop(0)
            self.now = max(self.now, when)
            callback()
        self.now = max(self.now, self.limit)


class _Pisar(ht.Writer):
    """host_traffic Writer that writes in the thread of the simulation (PREVADZKA_RULE): never started, nothing to
    join."""

    def join(self, timeout=None):
        return None


class Zapisovac(ht.SessionRecorder):
    """host_traffic SessionRecorder of PREVADZKA_RULE: the run id given (Recorder draws a random one), its Writer
    writing every record at once in this thread (put), and the request records kept in `poziadavky`."""

    def __init__(self, args, run, stop, files, clock, run_id):
        super().__init__(args, run, stop, None, clock=clock)
        self.run_id, self.poziadavky = run_id, []
        self.writer = _Pisar(files, None, self.fail, self.SCHEMAS)
        for key in files:
            self.put(key, self.header(key))

    def put(self, key, rec):
        if key == "end":
            self.writer.finish(rec)
            return
        if rec.get("type") == "request":
            self.poziadavky.append(rec)
        self.writer.guard(self.writer._write, key, rec)


# The options of scripts/host_traffic.py main and the types its parser gives them; every other option is a string.
TYPY_PRIKAZU = {"dur": float, "seed": int, "vlakien": int, "burst": float, "catalog_share": float,
                "write_share": float, "protocol": Path, "rate": float, "warmup_s": float, "out": Path,
                "requests_log": Path, "intervals_log": Path, "summary_interval_s": float}
MOZNOSTI_PRIKAZU = ("target", "dur", "seed", "vlakien", "burst", "profile", "catalog_share", "write_share",
                    "protocol", "scenario", "seeds", "rate", "warmup_s", "out", "session_id", "requests_log",
                    "intervals_log", "summary_interval_s", "initial_phase")


def argumenty(prikaz):
    """The namespace host_traffic.py main parses from `prikaz`, the command line of scripts/collection.py
    traffic_command (the interpreter and the script first): every option of its parser of the parser's type, when
    not given its default (None, --profile legacy)."""
    if Path(str(prikaz[1])).name != "host_traffic.py" or len(prikaz[2:]) % 2:
        raise ValueError("not a command line of scripts/host_traffic.py with a value to every option")
    out = dict(dict.fromkeys(MOZNOSTI_PRIKAZU), profile="legacy")
    for flag, value in zip(prikaz[2::2], prikaz[3::2]):
        name = str(flag)[2:].replace("-", "_")
        if not str(flag).startswith("--") or name not in out:
            raise ValueError(f"host_traffic.py has no option {flag}")
        out[name] = TYPY_PRIKAZU.get(name, str)(str(value))
    return SimpleNamespace(**out)


def hranice_intervalov(switches, stop, step):
    """The bounds of the summary intervals of a run of host_traffic.py (Recorder _roll, switch and close): from 0
    every `step` seconds, a phase switch inside an interval closes it there and the next ones start from the switch,
    and the last one closes at the stop (an empty one there is left out)."""
    bounds = [0.0]
    for at in (*switches, stop):
        while bounds[-1] + step <= at:
            bounds.append(bounds[-1] + step)
        if at > bounds[-1]:
            bounds.append(at)
    return bounds


def _rozmiestni(rng, n, envelope, lo, hi):
    """PRICHODY_RULE: n arrival times inside (lo, hi), placed on the envelope's integral."""
    if n == 0:
        return []
    a, b = envelope.cumulative(lo), envelope.cumulative(hi)
    for _ in range(MAX_PLACEMENTS):
        if n == 1:
            ys = [rng.uniform(a, b)]
        else:
            gaps = [rng.gammavariate((n - 1) / (n + 1), 1.0) for _ in range(n + 1)]
            total, done, ys = sum(gaps), 0.0, []
            for gap in gaps[:-1]:
                done += gap
                ys.append(a + (b - a) * done / total)
        times = [round(envelope.inverse(y), ht.ROUND) for y in ys]
        if all(lo < t < hi for t in times):
            return times
    raise ValueError(f"no placement of {n} arrivals inside [{lo}, {hi}) in {MAX_PLACEMENTS} draws")


def prichody(run, bounds, rows, interval_s, tolerance, rng):
    """PRICHODY_RULE: (the arrival times, their record) of the V5Run `run` (prepare_v5, its arrival plan from the
    stream traffic_arrivals, which `rng` continues), the bounds of its summary intervals and the times of the rows
    (seconds of its clock); tolerance: audit.traffic.offered_load_tolerance. A row whose interval reaches into the
    main interval of an earlier row cannot be read this way (ValueError)."""
    envelope, rate = run.envelope, run.rate
    bins = [[] for _ in bounds[1:]]
    for t in run.arrivals:
        i = bisect.bisect_right(bounds, t) - 1
        if not 0 <= i < len(bins):
            raise ValueError(f"the planned arrival at {t} s lies outside the summary intervals")
        bins[i].append(t)
    shares = []
    for t in rows:
        first = max(0, bisect.bisect_right(bounds, t - interval_s) - 1)
        shares.append({i: (min(bounds[i + 1], t) - max(bounds[i], t - interval_s)) / (bounds[i + 1] - bounds[i])
                       for i in range(first, min(len(bins), bisect.bisect_right(bounds, t)))
                       if min(bounds[i + 1], t) > max(bounds[i], t - interval_s)})
        if abs(sum((bounds[i + 1] - bounds[i]) * share for i, share in shares[-1].items()) - interval_s) > 1e-6:
            raise ValueError(f"the summary intervals do not cover the interval of the row at {t} s")
    main = [max(found, key=found.get) for found in shares]
    if len(set(main)) != len(main):
        raise ValueError("two rows share the summary interval that holds most of their intervals")
    counts, placed, plans = {i: len(found) for i, found in enumerate(bins)}, {}, []
    for r in reversed(range(len(rows))):
        m, found = main[r], shares[r]
        if any(i in main[:r] for i in found if i != m):
            raise ValueError(f"the interval of row {r} reaches into the main interval of an earlier row")
        rest = sum(share * counts[i] for i, share in found.items() if i != m)
        plan = rate * envelope.integral(rows[r] - interval_s, rows[r])
        plans.append(plan)
        if plan >= 0.5 / tolerance:
            counts[m] = placed[m] = max(0, math.floor((plan - rest) / found[m] + 0.5))
    out = []
    for i, found in enumerate(bins):
        out += _rozmiestni(rng, placed[i], envelope, bounds[i], bounds[i + 1]) if i in placed else found
    return sorted(out), {"rule": PRICHODY_RULE, "rows": len(rows), "rows_placed": len(placed),
                         "lowest_plan": round(min(plans), 6) if plans else None, "planned": len(run.arrivals),
                         "arrivals": len(out)}


class Ponuka:
    """The offered user sessions of one session as ponuka_relacii aggregates them (ZATAZ_RULE): origin, the unix time
    of the generator's clock 0 (the header start_unix of its logs); bounds, the bounds of its summary intervals in
    seconds of that clock (hranice_intervalov); offered, the arrivals in every interval; arrivals, the arrival times
    of PRICHODY_RULE; record, the record of prichody."""
    __slots__ = ("origin", "bounds", "offered", "arrivals", "record")

    def __init__(self, origin, bounds, offered, arrivals, record):
        self.origin, self.bounds, self.offered, self.arrivals, self.record = origin, bounds, offered, arrivals, record

    def logged(self):
        """The bounds as the log writes them (host_traffic Interval.record: rounded to 1 us)."""
        return [round(b, 6) for b in self.bounds]

    def zataz(self, times, interval_s):
        """ZATAZ_RULE: the offered user sessions in the interval (t - interval_s, t] of every row time t (unix), as
        features/qualification.py offered_load weighs the summary intervals of traffic_intervals.jsonl: a list, or the
        reason why there is none (a text), as offered_load returns them."""
        logged = self.logged()
        start, end = self.origin + np.array(logged[:-1]), self.origin + np.array(logged[1:])
        offered = np.array(self.offered, dtype=np.float64)
        high = np.asarray(times, dtype=np.float64)[:, None]
        overlap = np.clip(np.minimum(end, high) - np.maximum(start, high - interval_s), 0, None)
        if not np.allclose(overlap.sum(axis=1), interval_s, rtol=0, atol=1e-6):
            return "the summary intervals of suchy_kampan.ponuka_relacii do not cover the interval of every row"
        return (overlap / (end - start) * offered).sum(axis=1).tolist()


def ponuka_relacii(d, p, row, times):
    """ZATAZ_RULE: (the generator's arguments, its V5Run with the arrivals of PRICHODY_RULE, the Ponuka) of the session
    directory `d` (its session.json with the traffic block of scripts/collection.py _v5_traffic, its end.json with the
    measurement's times, its protocol.json) of the planned row `row` under protocol `p` (the session's view of the
    working copy), the times of its rows `times` (unix). The one function of the offered load of both paths: the full
    path runs the generator on its arrivals, the shortened one reads Ponuka.zataz without logs."""
    meta, end = read_json(d / "session.json"), read_json(d / "end.json")
    if meta.get("scenario") != row["scenario"] or (meta.get("traffic") or {}).get("scenario") != row["scenario"]:
        raise ValueError(f"{d.name}: session.json holds no traffic block of scenario {row['scenario']} (ZATAZ_RULE)")
    args = argumenty(collection.traffic_command(p, meta, d))
    run = ht.prepare_v5(args)
    stream = random.Random(run.seeds["traffic_arrivals"])
    if ht.arrival_times(run.envelope, run.rate, stream) != run.arrivals:
        raise ValueError("the arrival plan of prepare_v5 is not arrival_times of the stream traffic_arrivals")
    origin = end["measure_start_unix"] - run.warmup_s
    measure, post = end["measure_start_unix"] - origin, end["measure_end_unix"] - origin
    if measure != run.warmup_s:
        raise ValueError("the measurement does not start warmup_s after the traffic (suchy_generatory.LOAD_RULE)")
    bounds = hranice_intervalov((measure, post), post + STOP_AFTER_S, args.summary_interval_s)
    tolerance = audit_bounds(p)["traffic"]["offered_load_tolerance"]
    arrivals, record = prichody(run, bounds, [t - origin for t in times], p["interval_s"], tolerance, stream)
    offered = [0] * (len(bounds) - 1)
    for t in arrivals:  # As host_traffic SessionRecorder arrival counts it: in the interval [start, end) that holds t.
        i = bisect.bisect_right(bounds, t) - 1
        if not 0 <= i < len(offered):
            raise ValueError(f"the arrival at {t} s lies outside the summary intervals (ZATAZ_RULE)")
        offered[i] += 1
    return args, ht.V5Run(**dict(vars(run), arrivals=arrivals)), Ponuka(origin, bounds, offered, arrivals, record)


def over_zataz_logov(d, ponuka, times, interval_s):
    """ZATAZ_RULE, the full path's check: the offered load features/qualification.py offered_load reads from the
    session's traffic_intervals.jsonl at the times of its rows `times` equals Ponuka.zataz of `ponuka`, else a
    ValueError names the first row that differs; returns the offered load."""
    from features import qualification as fq
    found, own = fq.offered_load(d / "traffic_intervals.jsonl", times, interval_s), ponuka.zataz(times, interval_s)
    if type(found) is str or type(own) is str:
        raise ValueError(f"{d.name}: no offered load to compare (offered_load: "
                         f"{found if type(found) is str else 'read'}; ponuka_relacii: "
                         f"{own if type(own) is str else 'read'}; ZATAZ_RULE)")
    wrong = [i for i, (a, b) in enumerate(zip(found, own)) if a != b]
    if len(found) != len(own) or wrong:
        i = wrong[0] if wrong else min(len(found), len(own))

        def at(values):
            return values[i] if i < len(values) else None
        raise ValueError(f"{d.name}: the offered load features/qualification.py offered_load reads from "
                         f"traffic_intervals.jsonl differs from suchy_kampan.ponuka_relacii at the row of time "
                         f"{at(times)!r} ({len(wrong)} rows differ, of {len(found)} and {len(own)}; the log "
                         f"{at(found)!r}, the function {at(own)!r}; ZATAZ_RULE)")
    return found


def _stav(metrics, recorder, run, loop, args, clock, final):
    """The status file of the generator (host_traffic main_v5 save) at the time of the clock (PREVADZKA_RULE)."""
    result = metrics.snapshot()
    elapsed = clock.mono() - recorder.origin
    result.update(elapsed_s=round(elapsed, 3), ok_per_s=round(result["ok"] / max(elapsed, .001), 3),
                  updated_at=ht.utc(clock.wall()))
    result.update(target=args.target, profile=run.profile, scenario=run.scenario, seed=run.seeds["traffic"],
                  rate=run.rate, final=final, session_id=args.session_id, run_id=recorder.run_id,
                  phase=recorder.phase, requests_logged=recorder.requests_logged(), logging_error=recorder.error,
                  log_backpressure_s=round(recorder.blocked_s, 3), worker_errors=recorder.worker_errors,
                  requests_log=str(args.requests_log), intervals_log=str(args.intervals_log), **loop.status())
    return result


def _hostovske_logy(d, requests, origin, old):
    """PREVADZKA_RULE: nginx's access lines and the services' journal lines of `requests` (the request records), in
    place of the lines of the requests `old` (their rids)."""
    units = read_json(d / "guest" / "state_before.json")["units"]
    nginx, journal = [], []

    def call(r, name, method, route, status):
        journal.append(f"{evidence.utc(r['t_end_mono'], origin)} guest "
                       f"python3[{units['hyptcn-lab@' + name]['ExecMainPID']}]: client request rid={r['rid']} "
                       f"method={method} path={route} status={status}\n")
    for r in requests:
        nginx.append(json.dumps({"schema": "hyptcn3/nginx-access/1", "rid": r["rid"], "forwarded_rid": r["rid"],
                                 "method": r["method"], "uri": r["route"], "status": r["status"],
                                 "msec": origin + r["t_end_mono"], "bytes": r["response_bytes"]}) + "\n")
        name = evidence._service(r["route"])
        if name is None:
            continue
        if evidence._asks_auth(r["method"], r["route"]):
            call(r, "auth", "GET", "/api/auth/check", 401 if r["status"] == 401 else 200)
        call(r, name, r["method"], r["route"], r["status"])
        if r["route"] == "/api/orders" and r["method"] == "POST" and r["status"] == 201:
            call(r, "catalog", "GET", "/api/catalog/prices", 200)

    def rid(line):
        found = line.split(" rid=", 1)
        return found[1].split(" ", 1)[0] if len(found) == 2 else None
    evidence._segment(d, "session", "nginx-access.jsonl",
                      lambda lines: [line for line in lines if json.loads(line)["rid"] not in old] + nginx)
    evidence._segment(d, "journal", "journal.txt", lambda lines: [line for line in lines if rid(line) not in old]
                      + journal)


def _blok_prevadzky(d, p, row):
    """The traffic block of session.json (scripts/collection.py _v5_traffic of the row, at the protocol's rate), as
    the capture records it before the generator starts; written into the session directory `d`."""
    scenario = p["scenarios"][row["scenario"]]
    if scenario.get("rate") is None:
        raise ValueError(f"scenarios.{row['scenario']}.rate is null: a session of a planned role runs at the "
                         "protocol's rate (the working copy gives it)")
    meta = read_json(d / "session.json")
    seeds = {purpose: row["seeds"][purpose] for purpose in collection.traffic_purposes()}
    meta["traffic"] = collection._v5_traffic(SimpleNamespace(scenario=row["scenario"]), p, scenario["rate"],
                                             "protocol", seeds, meta["cycles"])
    evidence.write(d / "session.json", meta)


def _poziadavky(d):
    """The rids of the requests of the session's traffic_requests.jsonl."""
    return {r["rid"] for r in map(json.loads, (d / "traffic_requests.jsonl").read_text().splitlines())
            if r.get("type") == "request"}


def zapis_prevadzky(d, p, row, times):
    """PREVADZKA_RULE: the traffic of the session directory `d` (built by boundary_sessions.build_session, its
    session.json and end.json final but the traffic) of the planned row `row` under protocol `p` (the session's view of
    the working copy), the times of its rows `times` (unix), on the arrivals of ponuka_relacii (ZATAZ_RULE), whose
    offered load its logs are checked to give (over_zataz_logov). Returns the Ponuka, its record of PRICHODY_RULE with
    the run id."""
    _blok_prevadzky(d, p, row)
    end = read_json(d / "end.json")
    old = _poziadavky(d)
    args, run, ponuka = ponuka_relacii(d, p, row, times)
    for path in (args.requests_log, args.intervals_log, args.out, d / "traffic_before.json"):
        path.unlink()
    origin = ponuka.origin
    measure, post = end["measure_start_unix"] - origin, end["measure_end_unix"] - origin
    stop, failures = threading.Event(), []
    clock = Hodiny(origin, post + STOP_AFTER_S, stop)
    files = {"requests": open(args.requests_log, "x"), "intervals": open(args.intervals_log, "x")}
    recorder = Zapisovac(args, run, stop, files, clock, hashlib.sha256(d.name.encode()).hexdigest()[:12])
    metrics = ht.SessionMetrics(recorder.origin, ht.utc(recorder.origin_wall))
    lab = SluzbyLabu()
    loop = ht.OpenLoop(run, recorder, ht.UserClient(args.target, metrics, recorder, opener=lab.opener), stop,
                       lambda function, *items: function(*items), clock=clock)

    def warmup_end():
        """The end of the warmup as capture_session reads it, then the phase measure."""
        try:
            evidence.write(args.out, _stav(metrics, recorder, run, loop, args, clock, False))
            collection.write_json(d / "traffic_before.json", collection.check_warmup(p, d))
        except Exception as error:  # noqa: BLE001 - the scheduler would take it for a failed user session
            failures.append(error)
        recorder.switch("measure")
    clock.events = [(measure, warmup_end), (post, lambda: recorder.switch("post"))]
    loop.serve()
    clock.dobeh()
    recorder.close(loop.end_fields())
    if failures:
        raise failures[0]
    status = _stav(metrics, recorder, run, loop, args, clock, True)
    evidence.write(args.out, status)
    evidence.write(d / "end.json", dict(end, traffic_rc=3 if recorder.error else int(
        status["unexpected_results"] != 0 or status["ok"] <= 0)))
    intervals = [r for r in map(json.loads, args.intervals_log.read_text().splitlines()) if r["type"] == "interval"]
    found = [iv["mono_start"] for iv in intervals] + [intervals[-1]["mono_end"]]
    if found != ponuka.logged() or [iv["offered_sessions"] for iv in intervals] != ponuka.offered:
        raise ValueError("the summary intervals of the generator are not those of suchy_kampan.ponuka_relacii, which "
                         "placed the arrivals in them (PRICHODY_RULE, ZATAZ_RULE)")
    over_zataz_logov(d, ponuka, times, p["interval_s"])
    _hostovske_logy(d, recorder.poziadavky, origin, old)
    ponuka.record = dict(ponuka.record, run_id=recorder.run_id)
    return ponuka


def bez_prevadzky(d, p, row):
    """SKRATENA_RULE: the session directory `d` (built by boundary_sessions.build_session, its session.json and end.json
    final but the traffic) of the planned row `row` under protocol `p` without traffic: the traffic block of
    session.json, no file of TRAFFIC_FILES, end.json without traffic_rc and logs_manifest_sha256, the nginx and journal
    segments without the lines of the requests, no logs_manifest.json."""
    _blok_prevadzky(d, p, row)
    old = _poziadavky(d)
    for name in TRAFFIC_FILES:
        (d / name).unlink()
    end = read_json(d / "end.json")
    evidence.write(d / "end.json", {key: value for key, value in end.items()
                                    if key not in ("traffic_rc", "logs_manifest_sha256")})
    _hostovske_logy(d, [], None, old)
    (d / "logs_manifest.json").unlink()


def audit_logov_skratenej(directory, *, snapshot_times=(), archived_raw=False):
    """SKRATENA_RULE: what the session audit of the shortened path reads in place of the log audit
    (scripts/collection_logs.py audit_logs, the same arguments), which is not run: a record of its schema whose
    not_run names the rule, with its metadata section, no problem, nothing tolerated and accepted; a session that holds
    a file of TRAFFIC_FILES or a logs_manifest.json is refused by name (it is no session of the shortened path)."""
    from scripts import collection_logs
    directory = Path(directory).resolve()
    end = read_json(directory / "end.json")
    problems = [f"shortened_path_traffic_log:{name}" for name in TRAFFIC_FILES if (directory / name).exists()]
    if (directory / "logs_manifest.json").exists():
        problems.append("shortened_path_logs_manifest")
    return {"schema": collection_logs.SCHEMA, "session_dir": str(directory),
            "sections": {"metadata": {"session_sha256": collection_logs.digest(directory / "session.json"),
                                      "end_sha256": collection_logs.digest(directory / "end.json"),
                                      "measure_start_unix": end.get("measure_start_unix"),
                                      "measure_end_unix": end.get("measure_end_unix")}},
            "problems": problems, "problem_counts": dict.fromkeys(problems, 1), "accepted": not problems,
            "tolerated": dict.fromkeys(collection_logs.LOG_EXCEPTIONS, 0), "not_run": SKRATENA_RULE,
            "note": "Not run: the shortened path of the G1 dry run writes and audits no traffic logs (suchy_kampan "
                    "SKRATENA_RULE)."}


@contextlib.contextmanager
def bez_auditu_logov():
    """SKRATENA_RULE for the length of a block: the session audit (scripts/collection.py audit_session) without its log
    audit (audit_logs is audit_logov_skratenej), restored after it."""
    real = collection.audit_logs
    collection.audit_logs = audit_logov_skratenej
    try:
        yield
    finally:
        collection.audit_logs = real


def postav_session(root, p, protocol_path, row, rezim, seed, protokol, *, session_id, prvy_riadok_unix, guest, qemu,
                   prevadzka, ponuky=None, polia=None, chyba_citania=False):
    """SESSION_RULE: the session `session_id` of `row` below `root`, as a boundary_sessions.Session (directory,
    protocol_path, result: the rows the audit's extraction returns). p: the protocol as the session's VM sees it
    (collection.for_vm of the copy), protokol: the copy itself (the generator reads its plans), guest: the identity of
    the guest's boot, qemu: the QEMU process, prevadzka: with its traffic (PREVADZKA_RULE, the full path) or without
    (SKRATENA_RULE, the shortened path), no default; ponuky: a mapping that receives the session's Ponuka (ZATAZ_RULE)
    under its resolved directory, polia: more fields of session.json, chyba_citania: READ_ERROR_RULE."""
    if type(prevadzka) is not bool:
        raise ValueError("postav_session builds a session with its traffic (prevadzka true, the full path) or without "
                         "it (false, the shortened path): no default")
    start = float(prvy_riadok_unix) - sg.FIRST_ROW_S  # The generator's frame: its events, controls and rows.
    base = start - 1  # test_collection_logs.build starts the measurement 1 s after its base (SESSION_RULE).
    items = {"events": copy.deepcopy(row.get("events", [])), "event_grace_s": protokol["events"]["grace_s"],
             "source_sha256": {"lab/udalosti.py": evidence.SCRIPT_SHA256}}
    if row["role"] == pv.CONTROL_ROLE:
        items["controls"] = [copy.deepcopy(c) for c in row["controls"] if c.get("kind") is not None]
    session = bs.build_session(Path(root), p, protocol_path, row, session_id=session_id, base=base, meta=items,
                               profile=profil(p), boot=guest["boot_id"])
    d = session.directory
    end = read_json(d / "end.json")
    meta = read_json(d / "session.json")
    meta.update(guest_before=copy.deepcopy(guest),
                host_context={"host_boot": qemu["host_boot"], "qemu": dict(qemu), "python": "python3",
                              "memory": dict(kv.MEMORY), "other_vms": []},
                **copy.deepcopy(polia or {}))
    evidence.write(d / "session.json", meta)
    evidence.write(d / "end.json", dict(end, guest_after=copy.deepcopy(guest)))
    for when in ("before", "after"):
        state = read_json(d / "guest" / f"state_{when}.json")
        evidence.write(d / "guest" / f"state_{when}.json", dict(state, boot_id=guest["boot_id"],
                                                                 kernel=guest["kernel"]))
    evidence.write(d / "events.json", {"schema": "hyptcn3/session-events/1", "events": _udalosti(row, start)})
    if row["role"] == pv.CONTROL_ROLE:
        evidence.write(d / "controls.json", sg.controls_json(row, start))
    result = sg.riadky(row, rezim, seed, protokol)
    result["casy"] = [start + t for t in result["casy"]]
    if prevadzka:
        ponuka = zapis_prevadzky(d, p, row, result["casy"])
    else:
        bez_prevadzky(d, p, row)
        _, _, ponuka = ponuka_relacii(d, p, row, result["casy"])
    if ponuky is not None:
        ponuky[str(d.resolve())] = ponuka
    times = dict(zip(result["seq"], result["casy"]))
    for path in (d / "raw").glob("*.json"):
        side = json.loads(path.read_text())
        if side.get("schema") == "vmicollect/1":
            side["vm"]["vmid"] = qemu["pid"]
            side["timestamp_unix"] = times[side["seq"]]
            evidence.write(path, side)
    if chyba_citania:
        _chyba_citania(result, d, p)
    if prevadzka:  # SKRATENA_RULE: the logs of a session of the shortened path are not sealed.
        evidence.seal(d)
    return bs.Session(d, Path(protocol_path), result)


def zaznam_generatora(records):
    """GENERATOR_MAP_RULE: {session id: {invalid_rows, marginal_changes, unevaluated}} of `records` {session id: the
    record of suchy_generatory.zaznam of its row and attempt}."""
    out = {}
    for ident, record in records.items():
        invalid = record.get("invalid_rows")
        entry = {"invalid_rows": list(invalid["seq"]) if invalid else [],
                 "marginal_changes": [{"first_seq": change["seq"][0], "rows": len(change["seq"]),
                                       "column": change["column"]} for change in record.get("changes") or []],
                 "unevaluated": []}
        occurrence = (invalid or {}).get("occurrence")
        if occurrence is not None and occurrence.get("evaluable") is False:
            control = record["role"] == pv.CONTROL_ROLE
            entry["unevaluated"].append({"what": "control" if control else "event", "index": occurrence["index"],
                                         "type": occurrence["kind"] if control else occurrence["type"]})
        out[ident] = entry
    return out


class Laboratorium(kv.Lab):
    """kampan_v5.Lab whose guest identity carries the stack manifest of boundary_sessions (the audit compares it
    with lab/ of the commit, scripts/collection.py guest_mismatch), so that a session's guest_before is the group's."""

    def identity(self, vm):
        return dict(super().identity(vm), stack_manifest=list(bs.STACK_MANIFEST))


class Kampan(kv.Harness):
    """The harness of the dry run (module docstring) under `root`, patched through `patch` (a pytest.MonkeyPatch):
    protokol the loaded working copy, rezim and seed those of the run, kniha the run's own ledger, prevadzka whether
    its sessions are built with their traffic (the full path) or without it (the shortened path, SKRATENA_RULE, with
    the fakes of FAKES_SKRATENA), no default. captures and audits are those of kampan_v5; riadky holds, per capture,
    what postav_session needs to build the session again (SESSION_RULE: the row, the plan mode, the time of the first
    row, the guest, the QEMU process, the fields and the injected read error), vysledky its rows for the real audit, and
    ponuky (the mapping given, else a new one) the Ponuka of every capture under its resolved directory (ZATAZ_RULE)."""

    def __init__(self, root, patch, *, protokol, rezim, seed, kniha, prevadzka, ponuky=None):
        from tcn import pecat
        if type(prevadzka) is not bool:
            raise ValueError("the harness of the dry run builds its sessions with their traffic (prevadzka true) or "
                             "without it (false): no default")
        self.protokol, self.rezim, self.seed, self.prevadzka = protokol, rezim, seed, prevadzka
        self.kniha, self.zaznam = Path(kniha), pecat.ZAZNAM
        self.real_audit_session = collection.audit_session
        self.riadky, self.vysledky, self.ponuky = [], {}, {} if ponuky is None else ponuky
        super().__init__(root, patch)

    def patch(self):
        from tcn import pecat
        self.lab = Laboratorium(self.protokol)
        self.lab.stops = self.allowed_stops
        self.lab.sequence = self.sequence
        self.ledger = self.kniha
        super().patch()
        self.mp.setattr(pecat, "ZAZNAM", self.zaznam)  # STAGE_RULE: the run's ledger is not the ledger of record.
        if not self.prevadzka:  # FAKES_SKRATENA: the session audit of the shortened path without its log audit.
            self.mp.setattr(collection, "audit_logs", audit_logov_skratenej)

    def git(self, *args):
        """git of the campaign (FAKES): a clean tree at the real commit."""
        if args[:1] == ("status",):
            return ""
        if args[:1] == ("rev-parse",):
            return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=collection.ROOT, text=True).strip()
        raise AssertionError("the campaign asked git " + " ".join(args))

    def capture(self, a, p):
        """collection.py run of a session of a planned role (kampan_v5 Harness.capture): what its command line and
        collection.v5_run decide, the boot and the QEMU process of the group, then postav_session."""
        if p.get("schema") != pv.SCHEMA or a.role == "diagnostic":
            raise AssertionError("a campaign of protocol v5 captures sessions of planned roles under schema 3")
        campaign = Path(a.protocol).resolve().parent
        manifest = read_json(campaign / "campaign.json")
        tries = sum(x["campaign"] == a.campaign_id for x in self.captures)
        if tries >= len(manifest["sessions"]) + kv.RUNAWAY:
            raise AssertionError(f"runaway replacements: campaign {a.campaign_id} captured {tries} sessions")
        v5 = collection.v5_run(a, p)
        vm, attempt = p["vm"], a.attempt
        key = (a.campaign_id, a.group, a.scenario, attempt)
        identity, qemu = self.lab.identity(vm), self.lab.qemu(p["domain"])
        if getattr(a, "expected_boot_id", None) and identity["boot_id"] != a.expected_boot_id:
            raise ValueError("guest boot differs from campaign group")
        if getattr(a, "expected_qemu", None) and qemu != json.loads(a.expected_qemu):
            raise ValueError("VM process differs from campaign group (restart or restore)")
        row = planovany_riadok(self.protokol, a.mode, a.role, a.group, a.scenario, vm, attempt)
        if row["seed"] != a.seed or row.get("events", []) != v5["events"] or (
                "controls" in v5 and [c for c in row["controls"] if c.get("kind") is not None] != v5["controls"]):
            raise AssertionError(f"the row of {a.session_id} is not the session collection.v5_run plans")
        t0, t1 = self.clock.take(p)
        fields = {"campaign_id": a.campaign_id, **({"replaces": a.replaces} if a.replaces else {}),
                  "group_attempt": a.group_attempt, "attempt": attempt, "plan_mode": a.mode,
                  "commit": manifest["commit"], "commit_dirty": False, "measurement_dirty": [], "host": "test-host"}
        rejected = self.injected(self.reject, *key)
        root = self.collections / a.campaign_id / vm
        root.mkdir(parents=True, exist_ok=True)
        session = postav_session(root, p, a.protocol, row, self.rezim, self.seed, self.protokol,
                                 session_id=a.session_id, prvy_riadok_unix=t0, guest=identity, qemu=qemu,
                                 prevadzka=self.prevadzka, ponuky=self.ponuky, polia=fields, chyba_citania=rejected)
        self.vysledky[str(session.directory.resolve())] = session.result
        self.riadky.append({"session": a.session_id, "campaign": a.campaign_id, "vm": vm, "row": row,
                            "plan_mode": a.mode, "first_row_unix": t0, "guest": identity, "qemu": qemu,
                            "fields": fields, "read_error": rejected, "directory": str(session.directory)})
        self.captures.append({
            "campaign": a.campaign_id, "vm": vm, "sid": a.session_id, "role": a.role, "group": a.group,
            "scenario": a.scenario, "attempt": attempt, "mode": a.mode, "seed": a.seed, "replaces": a.replaces,
            "t0": t0, "t1": t1, "boot": identity["boot_id"], "qemu": qemu, "order": next(self.sequence),
            "directory": str(session.directory),
            "ledger": {entry["session"] for entry in kv.ledger_entries(self.ledger).values()},
            "done": {path.name[:-len(".done.json")] for path in (campaign / "attempts").glob("*.done.json")}})

    def audit(self, directory, p, protocol_path, output):
        """collection.py audit: the real collection.audit_session through boundary_sessions.audit, only retazec
        returning the session's rows (FAKES)."""
        src = Path(directory).resolve()
        result = self.vysledky[str(src)]
        patched = collection.audit_session
        collection.audit_session = self.real_audit_session
        try:
            found = bs.audit(bs.Session(src, Path(protocol_path), result), p, output=output, result=result)
        finally:
            collection.audit_session = patched
        self.audits.append({"sid": src.name, "accepted": found.code == 0, "report": str(output),
                            "reasons": list(found.values["reasons"]), "order": next(self.sequence)})
        return found.code
