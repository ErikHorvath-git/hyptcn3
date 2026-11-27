#!/usr/bin/env python3
"""Traceable report over benign collection sessions or a whole campaign.

  .venv/bin/python scripts/campaign_report.py campaign data/campaigns/<id> --out NEW_DIR
  .venv/bin/python scripts/campaign_report.py sessions SESSION [SESSION ...] --out NEW_DIR
  .venv/bin/python scripts/campaign_report.py marked AUDIT [AUDIT ...] --protocol P [--g2-dir DIR] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py load SESSION [SESSION ...] [--final-protocol P] [--g2-dir DIR]
                                              --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py realism SESSION [SESSION ...] [--g2-dir DIR] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py envelope SESSION [SESSION ...] --protocol P --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py majflt AUDIT [AUDIT ...] --protocol P --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py timing RECORD [RECORD ...] [--others AUDIT ...] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py guest SESSION [SESSION ...] [--g2-dir DIR] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py events SESSION [SESSION ...] --protocol P [--g2-dir DIR] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py restarts SESSION [SESSION ...] --protocol P [--g2-dir DIR] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py controls SESSION [SESSION ...] --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py faults SESSION [SESSION ...] --records DIR --out NEW_FILE
  .venv/bin/python scripts/campaign_report.py parity WATCH_DIR REPLAY_DIR --out NEW_FILE

The report reads saved evidence only: session, end, audit and archive
metadata, the request and interval logs, the host monitor, snapshot sidecars
and campaign events. It never opens RAM images, never decompresses archived
members and never writes into its inputs. Every value is copied or computed
from a file listed with its SHA-256 (sources.csv, summary.json); absent
evidence becomes null with a stated reason (column `missing`; fields that do
not apply to a session are explained in `not_applicable`), never an estimate.
NEW_DIR must not exist. Exit 0 = report written, 2 = usage or data error.

The modes marked, load and realism (package H1b6b of stage G2, map rows 4 to 6 and 14) are tables of G2 sessions
that honour the records of the G2 driver (G2T_RECORDS_RULE: a session the record of skuska/g2.py leaves out of a
table, or one the host load does not count, is listed and never counted). The mode marked (criterion
marked_rows_per_event and the value invalid_rows.max, the lead's answer to Q49; MARKED_RULE, MARKED_MODEL_RULE)
counts, per occurrence of an event, the rows the rule marks, invalid and closed by a parser rule apart, at its
start and at its stop, with the phase of each boundary against the collector's grid, sums them by type over both
VMs, and proposes invalid_rows.max and min_score_coverage by the model written before the data; it reads the audit
records, their feature archives (numpy.load with allow_pickle=False), session files and the records, and writes
nothing into the protocol. The mode load (criterion profiles_load, the lead's answer to Q63; LOAD_RULE) gives per
scenario and VM the offered and delivered load, the load delivered in the event windows, the drop reasons and the
return to the defined state; it reads the /2 traffic logs through scripts/traffic_log.py. The mode realism
(criterion traffic_realism, the lead's answer to Q65; REALISM_RULE) gives per scenario and VM the value, bound and
result of every requirement of the audit's section realism, the maintenance timer of corp from the guest journal,
the sessions with a fault apart, and runs P1 (the mode envelope) grouped by the sha256 of each session's
protocol.json. Each writes NEW_FILE, a new JSON record with the provenance header of check E and the stage G2, which
names every file it read with its sha256. Exit 0 = the criterion's minimums are met, 1 = one is not (the record
names it), 2 = usage or data error (nothing written). They import inside their functions skuska/g2.py (the G2
directory and the numbers of Q43 and of the skeleton's section 3), scripts/gates.py (the G0 binding),
features/acceptance.py (marked: the marked rows by type and the gate interval), features/quality.py,
scripts/collection_logs.py (the event window and the required units) and scripts/lab_trial.py (realism: the lines
of the guest journal).

The mode envelope (the lead's answer to Q30, 2026-11-24; ENVELOPE_RULE) draws
the traffic envelope of each session again from the protocol P and the traffic
seed of its session.json, as scripts/host_traffic.py draws it, and compares it
with the envelope in the header of both traffic logs. It reads session.json,
the session's protocol.json (its SHA-256) and the first line of
traffic_requests.jsonl and traffic_intervals.jsonl, no score. It prints one
line per session and writes NEW_FILE, a new JSON record with the provenance
header of check E of scripts/check_claims.sh. Exit 0 = every session matches,
1 = a mismatch, 2 = usage error (nothing written) or a session with a data
error (the record names every mismatch as well).

The mode majflt (the lead's answer to Q29, 2026-11-24; MAJFLT_RULE) proposes
the bound audit.collector_majflt_max of the protocol P from the audit records
of the error-free G2 runs that the G2 record names: per VM the largest count
of the collector's major faults in one cycle (values.collector_majflt) with
its session, seq and cycle and the sessions and cycles counted, then the
largest over both VMs, the value the rule gives. It reads the audit records
and, for the VM of each, the session.json the audit read; no RAM, no archive
member, no score. It never writes the protocol. It prints one line per VM and
the proposal, and writes NEW_FILE, a new JSON record with the provenance
header of check E. Exit 0 = proposal made, 2 = usage or data error (nothing
written).

The mode timing (the criterion worst_case_timing of G2, the lead's answers
to Q58 to Q60; TIMING_RULE) is the report of the worst case of time: per
attempt of a pair of skuska/cas.py the shift of the full snapshots and of
the grids, the mode it met, whether the target full snapshot fell into the
other session's audit, its archive and the zataz_pamate window, the maxima
of the audit's values.timing against the protocol's bounds, and the major
faults per VM through the mode majflt with the largest count of the other
error-free runs (--others) beside them. It reads the G2 session records, the
session files, the sidecars of the full snapshots and the audit records, no
RAM image, with the definitions of skuska/cas.py, which only this mode
imports. It writes NEW_FILE, a new JSON record with the provenance header of
check E. Exit 0 = the criterion is met without a finding, 1 = a finding (the
record names it), 2 = usage or data error (nothing written).

The modes guest, events and restarts (package H1b6a; the criteria
guest_matches_repository, event_effects and restart_loops_bounded of G2,
map rows 1 to 3, the lead's answers Q43 and Q50 to Q53; GUEST_RULE,
EVENTS_RULE with NO_EFFECT_RULE and PHASE_RULE, RESTARTS_RULE with
ASSIGN_RULE, FITS_RULE, BOUNDED_RULE, ELSEWHERE_RULE and PERIODS_RULE) are
the tables of the G2 sessions given: guest compares the deployed files of
lab/ in each session's guest_before with git show <commit>:lab/<file> of
its commit and the dpkg lists and timers between the VMs; events lists
every occurrence (session, VM, type, the host times of its start and stop,
their real phases against the collector's grid, the predicate, for
naprazdno the rule of Q50) and counts each type on both VMs and on each
(Q43); restarts assigns the restart loops of the guests' journals to the
occurrences of zla_konfiguracia_sluzby and to the kill of the service of
skuska/poruchy.py, judges them by the rules of Q52 and names every period
the register lab/periods.json does not. Each reads the session directory,
its audit record and the records of the G2 driver in --g2-dir (zaznamy/,
and poruchy/ for restarts), honours what they say of a session (G2_SELECTION:
values.excluded, the kinds of H4, the load rule), names every file it reads
with its SHA-256 and writes NEW_FILE, a new JSON record with the provenance
header of check E and the stage G2. Exit 0 = the criterion is met, 1 = it is
not (the record names every finding and missing minimum), 2 = usage or data
error (nothing written). Only they import, inside their functions,
scripts/gates.py (the binding of the protocol), skuska/g2.py, skuska/cas.py
and skuska/poruchy.py (the records' schemas and kinds), scripts/collection.py
(deployed_paths), scripts/collection_logs.py (the event window and the lines
of the log audit) and scripts/lab_trial.py (the journal, the restart loops,
periods_of and autovacuum_property; Q53).

The mode controls (the criterion controls_paired of G2, the lead's answers
to Q46 to Q48; CONTROLS_RULE) is the table of shifts of the controls on the
VMs and their paired negatives: per occurrence of each G2 session with
controls (skuska/kontroly.py) its VM, session, kind, polarity, effect and
cleanup, the outcomes of scripts/controls.py (parser_saw, column_moved per
column against controls.kinds.<kind>.expect, sensor_scored) and
channel_reacted as not judged in G2, and the counts per kind and polarity
against the criterion's minimum of 3, every missing occurrence named by the
count. It reads controls.json, session.json, protocol.json, the audit record
and the feature archive the audit wrote, no RAM image. It writes NEW_FILE, a
new JSON record with the provenance header of check E. Exit 0 = every kind
has its minimum, 1 = a minimum is missing (the record names it), 2 = usage or
data error (nothing written).

The mode faults (the criterion live_fault_injections of G2, the lead's
answers Q56, Q57 and Q60; FAULTS_RULE) is the table of the faults injected
beside G2 sessions (skuska/poruchy.py): per fault and VM its session, the
names expected (skuska/poruchy.py FAULTS, committed before the runs), the
reasons received (end.json's error as scripts/campaign.py incomplete_reasons
gives it, and the audit's reasons), the other reasons, whether the refusal
was loud and named, and the count per fault and VM against the minimum of 1;
beside them the clean session of each VM. It reads session.json,
protocol.json, end.json, the audit record and the injector's record
(--records, <G2 directory>/poruchy). It writes NEW_FILE, a new JSON record
with the provenance header of check E. Exit 0 = every fault has its minimum
on every VM, 1 = a minimum is missing (the record names it), 2 = usage or
data error (nothing written).

The mode parity (the criterion live_archive_parity of G2, the lead's answers
Q45 and Q61; skuska/parita.py COMPARE_RULE, with the tolerance written there
before any comparison) compares, row by row by seq, the output of safeguard
watch beside a G2 session with the output of safeguard replay of that
session's feature archive: the score within the tolerance, the fields of the
alarm exactly, model_state and reason of the unscored rows, a row of one path
only named; it counts the alarms of both paths. It reads both outputs, the
audit record beside the archive and the session.json it names, no RAM image.
It writes NEW_FILE, a new JSON record with the provenance header of check E.
Exit 0 = parity holds, 1 = a finding (the record names each), 2 = usage or
data error (nothing written).

A reporting tool, not part of capture, audit or archival (collection.py lists
it in NOT_MEASUREMENT). Only the standard library and NumPy are used, but by
the mode controls, which imports scripts/controls.py (the outcomes of package
B8) and features/archive.py (the loader of a feature archive) inside its
function, by the mode faults, which imports scripts/campaign.py
(incomplete_reasons) and skuska/poruchy.py (FAULTS) inside its functions,
by the mode timing, which imports skuska/cas.py (the definitions of
the worst case of time) and scripts/campaign_grids.py inside its function,
and by the mode parity, which runs skuska/parita.py parity_table inside its
function; plots are hand-written SVG.
"""
import argparse
from array import array
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shlex
import subprocess
import sys
from xml.sax.saxutils import escape

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import host_monitor, traffic_log  # noqa: E402  (log schemas and monitor window statistics of the audit)
# The mode envelope: the generator's envelope and its schemas, and the check of the profiles section it applies.
from scripts import host_traffic, protocol_v5  # noqa: E402

SCHEMA = "hyptcn3/campaign-report/1"
SESSION_SCHEMA_1 = "hyptcn3/collection-session/1"
AUDIT_SCHEMA = "hyptcn3/collection-audit/1"
STATUSES = ("accepted", "rejected", "interrupted", "incomplete", "in_progress", "planned")
QUANTILES = (("p50", .5), ("p95", .95), ("p99", .99))
STATE_ROWS = ("scorable", "warmup", "full_snapshot", "invalid_input", "no_predecessor")
UNSCORED_CAUSES = ("full_snapshot", "invalid_input", "no_predecessor", "sequence_gap", "timestamp_gap",
                   "chain_change", "startup")
OUTCOME_CODE = {name: code for code, name in enumerate(traffic_log.OUTCOMES)}  # "ok" is code 0
CHUNK = 1 << 20
COLLECTOR_END = re.compile(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov")
SCHEMA1_SIGNAL = re.compile(r"(?:InterruptedError: )?(?:interrupted by )?signal \d+")
SAFE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
GATE_DEFAULT = .85  # What features.quality.coverage_gate() gives a schema 1 or 2 protocol without min_score_coverage.
PENDING_RAW = ".raw.pending-reclaim"  # collection_archive.PENDING: raw/ renamed, link not yet created
POST_MARKER = "generator 'post' marker"
RUNNER_END = "end.json measure_end_unix (runner; the generator wrote no 'post' marker)"
USABLE = "accepted_without_superseded_marker"
# campaign.retire_attempt: <session>.attempt-<n> directories and attempts/<session>.attempt-<n>.json records.
RETIRED_DIR = re.compile(r"(?P<sid>[a-zA-Z0-9][a-zA-Z0-9_-]{0,159})\.attempt-(?P<n>[0-9]+)")
ATTEMPT_RECORD = re.compile(r"(?P<sid>[a-zA-Z0-9][a-zA-Z0-9_-]{0,159})\.attempt-(?P<n>[0-9]+)\.json")
# campaign.take_stop_request and execute move operator stop requests into events/ under these suffixes.
STOP_REQUEST_SUFFIXES = ("_stop-request.json", "_stop-request-stale.json")
# Multi-VM campaigns: one runner per VM, <stamp>_stop-request-<vm>.json and ...-<vm>-stale.json.
STOP_REQUEST = re.compile(r".*_stop-request(?:-(?P<vm>[a-z0-9]{1,16}))??(?P<stale>-stale)?\.json")
# campaign.reject: attempts/<session>.rejected.json; a replacement is the session <plan session>-r<n>.
REJECTION_SCHEMA = "hyptcn3/campaign-rejection/1"
# Package B9b (design B9b 1.1 and 1.3): the record of every ending of a campaign, written by scripts/campaign.py into
# data/results/ as kampan_<campaign id>_<ending>_<UTC stamp>.json.
ENDING_SCHEMA = "hyptcn3/campaign-ending/1"
ENDING_NAME = "kampan_{id}_*.json"
START_FAILURE_SCHEMA = "hyptcn3/campaign-group-start-failure/1"  # scripts/campaign.py START_FAILURE_SCHEMA (Q22).
# The runner states of a campaign of protocol schema 3 that always come with an ending record (design B9b 1.2: the
# pause and the invalid campaign write theirs); stopped and complete also name the stop after a boundary and one VM's
# end before the other's, so the report shows them with the records it finds and requires none for them.
RECORDED_STATES = ("paused", "invalid")

DEFINITIONS = {
    "status": {
        "accepted": ("capture completed and the selected audit has values.accepted = true, the audit belongs to "
                     "this session (see audit_selection) and the current evidence still matches what the audit "
                     "examined (evidence_consistency); in campaign mode the session must also match its frozen "
                     "assignment and the campaign provenance (campaign_provenance). A superseded.json marker does "
                     "not change the status but is reported (superseded = true)"),
        "rejected": ("capture completed and the selected audit has values.accepted = false (reasons = audit "
                     "reasons; evidence or provenance problems are added to the reasons, a rejection is never "
                     "lifted)"),
        "interrupted": ("end.json records interrupted = true (stopped by a signal; for session schema 1, whose "
                        "end.json has no such flag, an error 'signal N'); never usable data"),
        "incomplete": ("no end.json, end.json completed = false without a signal, a session directory without "
                       "session.json, a completed capture without an audit verdict for it, or an accepting "
                       "verdict that cannot be applied (evidence changed since the audit, campaign assignment or "
                       "provenance differs); the reasons say which"),
        "in_progress": "campaign status.json says running on this session; process liveness is not checked",
        "planned": "campaign assignment without a session directory (not started)",
    },
    "missing_and_not_applicable": ("Every empty value in sessions.csv is explained: `missing` names evidence that "
                                   "is absent or unreadable (grouped as 'reason: fields'); `not_applicable` names "
                                   "fields without meaning for that session (no superseded marker, no error, not "
                                   "archived, not a campaign session, not started, a run that ended before that "
                                   "stage). Zero snapshots and zero raw bytes are reported as facts only when "
                                   "end.json shows that the run ended before the collector started. Nothing is "
                                   "estimated."),
    "audit_selection": ("Campaign mode uses the attempts/<session>.audit.json pointer when it exists (its SHA-256 "
                        "must match). Otherwise every audit_*.json / campaign_audit_*.json in the session directory "
                        "is considered; when several qualify, a rejecting verdict is never bypassed (the earliest "
                        "rejecting audit is used), else the latest accepting one. In both modes an audit gives a "
                        "verdict only when it is a complete hyptcn3/collection-audit/1 document with a boolean "
                        "values.accepted, values.session_sha256 equal to the current session.json and "
                        "values.session_dir equal to this session directory."),
    "superseded": ("superseded.json in a session directory marks a verdict that may no longer be used for the "
                   "current corpus; the status keeps the audit verdict and the flag and its reason are reported. "
                   "Every summary block that counts accepted sessions (capture time, snapshots, windows, HTTP, "
                   "data volume, per scenario) has an accepted_without_superseded_marker companion. An "
                   "unreadable superseded.json leaves superseded empty (missing), and that session is not "
                   "counted as without a marker."),
    "evidence_consistency": ("Checks of the current files against what was recorded when they were written or "
                             "audited: every input file listed in logs_manifest.json (SHA-256), the SHA-256 of "
                             "logs_manifest.json recorded in end.json, and, with an audit verdict, the sidecar "
                             "SHA-256 values (values.source_sha256), the archived image SHA-256 values "
                             "(archive-manifest.json), raw image bytes (values.raw_bytes), end.json and the "
                             "features file SHA-256, and the measure-phase request summary of the log audit. "
                             "Any difference is listed in evidence_problems; an accepting verdict is then not "
                             "applied (status incomplete), a rejection stays a rejection."),
    "campaign_provenance": ("Campaign mode only, as campaign.py check_session and audit_capture: session.json "
                            "role, group, scenario, seed and session_id equal the frozen plan row; campaign_id, "
                            "commit and protocol SHA-256 equal campaign.json and measurement_dirty is [] (no "
                            "measurement source differed from that commit; the informative whole-tree "
                            "commit_dirty is not a criterion); the guest environment equals the frozen one, and "
                            "the boot and the QEMU process equal groups/<group>.json; the audit's protocol, "
                            "commit, measurement_dirty = [], extractor hashes and role equal the campaign's. "
                            "Failures are listed in provenance_problems."),
    "retired_attempt": ("A capture attempt that ended before its measured phase (end.json measurement_started = "
                        "false, no raw/ directory, no RAM image), renamed <session>.attempt-<n> by campaign.py "
                        "and retried in the same group boot. Listed under retired_attempts with its reason; never "
                        "a session, never part of any total."),
    "multi_vm": ("A protocol with several VMs has one campaign runner per VM. Sessions are read from "
                 "<collections>/<campaign>/<vm>/<session>, runner state from status-<vm>.json, and each "
                 "session, group and event carries its vm. Campaign events are attributed per runner: an "
                 "interval lasts until the next event of the same VM, so stage seconds are runner time summed "
                 "over the VMs and can exceed the wall-clock span."),
    "replacement": ("A session the campaign cannot use may be captured again under the protocol's "
                    "pre-registered replacement rule (protocol.json replacement: max_per_campaign shared by the "
                    "causes in covers): the same assignment (VM, role, group, scenario, seed) in the same group "
                    "boot, as session <plan session>-r<n>. Causes: audit_rejected (completed capture, rejecting "
                    "audit) and capture_incomplete (the measured phase started but the capture did not complete; "
                    "replaced only while the group's boot and QEMU process were unchanged, see not_replaced). The "
                    "unusable session keeps its row (its own status, replaced_by) and is in no accepted total; "
                    "the replacement has its own row (replaces). Planned counts are plan rows, so a replacement "
                    "adds an attempted session, not a planned one. Every rejection record "
                    "(attempts/<session>.rejected.json) is listed with its reasons under campaign.rejections."),
    "tolerated": ("F1 of the verification of B9a (the B2 panel item): the conditions the audit admitted in an "
                  "accepted session instead of rejecting it, by register id of features/audit_policy.py TOLERATED, "
                  "read from the audit's values.exceptions ({id: {observed, expected, over}}, exceptions_record); an "
                  "audit without values.exceptions (one written before package B3, as those of the campaigns of "
                  "protocol schemas 1 and 2 were) gives only the invalid rows, the length of "
                  "values.quality.tolerated_invalid_seq; an audit with neither is 'not recorded', never 0. These "
                  "are apart from the coverage rows of coverage.csv: rows_invalid_input counts every row a model "
                  "input could not use, tolerated or not. Per register id the summary gives "
                  "the total over the accepted sessions that record it, the largest count in one of them and the "
                  "number of them over the expected count (the register's expected, null until G3b: then none is "
                  "over it and the number is 0)."),
    "ending": ("Package B9b: every ending of a campaign (complete, paused, stopped, invalid, closed by the operator) "
               "writes one record into data/results/ (kampan_<campaign id>_<ending>_<UTC stamp>.json, schema "
               "hyptcn3/campaign-ending/1, scripts/campaign.py). The report reads every such record of this campaign "
               "from the results directory (--results-dir, default <campaign_dir>/../../results, which is "
               "data/results beside data/campaigns) and lists them in the order of their date with their ending, "
               "cause, stage and counts, as recorded; the state of each runner is its status file's status "
               "(paused: the limit of replacements was exhausted, for review; invalid: a second exhaustion or a "
               "changed measurement or lab hash; stopped: early stop, an error or an operator's stop). A runner of a "
               "campaign of protocol schema 3 (campaign.json mode) paused or invalid without any ending record of "
               "the campaign is a consistency problem (those two states always write one)."),
    "group_start_failures": ("Package B9b, question Q22 (accepted by the lead 2026-11-24: a failed start of a group "
                             "is no session and does not charge the limit of replacements): a failed "
                             "start of a group (labctl stop, start, reset or pretouch) is no rejection of a session, "
                             "since no session was measured, so it is counted apart from the rejections by cause: "
                             "nothing is replaced and the limit is not charged, and a resumed run starts the group "
                             "again from its beginning (scripts/campaign.py GROUP_START_RULE). The report lists the "
                             "failures by group with VM, step, date, cause and reason, from values."
                             "group_start_failures of the campaign's last ending record that lists them, else, while "
                             "no ending record lists them, from groups/<group>.start-failed-<UTC>.json; a group "
                             "started again has its record groups/<group>.json now, or the ending record says so."),
    "limit": ("The limit of replacements (scripts/campaign.py LIMIT_RULE): the protocol's "
              "replacement.max_per_campaign, applied in mode campaign and under protocol schemas 1 and 2 (0 without "
              "a rule); in mode rehearsal (campaign.json mode) it is not applied, every covered rejection is "
              "replaced, and the rejections are counted by cause (rejections_by_cause), from which G3b sets the "
              "limit."),
    "stop_request": ("campaign.py request-stop asks a running campaign to stop before its next capture; the "
                     "runner moves the request into events/ when it honors it (*_stop-request.json) and sets aside "
                     "one left by an earlier run when it starts (*_stop-request-stale.json). Not campaign events."),
    "latency": ("duration_ms of each request record (client monotonic clock around the request and the reading "
                "of the response). Every latency includes failed requests (http_error, timeout, transport_error) "
                "unless the field is labeled ok-only."),
    "phase_assignment": ("Requests belong to the phase and to the 5 s interval in which they started (generator "
                         "definition in the log header)."),
    "load_model": ("Closed loop: each generator worker sends one request, waits for its response, then thinks; "
                   "it is not a fixed request rate. Request counts and rates change with server latency, not "
                   "only with the scenario setting."),
    "percentiles": ("Exact nearest-rank percentiles (the value at rank ceil(q*n) of the sorted values) over the "
                    "individual request records of one session, the same definition as scripts/traffic_log.py. "
                    "They are never averaged across intervals or sessions and never read from interval "
                    "histograms. Per-scenario blocks report the distribution of per-session values "
                    "(n, min, nearest-rank median, max), not pooled percentiles."),
    "http_window": ("Every HTTP value of a session (counts, rates, latencies, route shares) covers one window, "
                    "measure_start_utc .. measure_end_utc (source in measure_bounds_source): from the generator "
                    "'measure' marker to its 'post' marker; without a 'post' marker to the runner's end.json "
                    "measure_end_unix (generator killed or deaf to the stop signal), else to the generator end "
                    "record (interrupted run), else to the end of the last logged measure interval (log without "
                    "an end record). Only requests that the generator labeled 'measure' and that started inside "
                    "the window count; the others are counted in http_requests_outside_window and named in the "
                    "notes."),
    "requests_per_second": ("requests in the HTTP window / measure_phase_s. measure_phase_s is the sum of "
                            "duration_s of the logged measure-phase 5 s intervals when those intervals hold exactly "
                            "the counted requests, otherwise the window length (end - start, wall clock), as "
                            "labeled in measure_phase_s_source. Pooled rates use only sessions that have both "
                            "values. The ok-only rate uses ok requests."),
    "nominal_times": ("nominal_scored_s and nominal_unscored_s are sampling-slot counts x protocol period taken "
                      "from the audit (values.coverage); they are not measured availability of a live detector."),
    "capture_time": ("Measured capture interval of a session = timestamp of its last snapshot minus timestamp of "
                     "its first snapshot (sidecar timestamp_unix). Collection hours are sums of this interval "
                     "only; warmup, runner preflight, guest evidence transfer, audit, archive, reboot and stopped "
                     "periods are excluded and reported separately. A complete session of n snapshots therefore "
                     "spans (n - 1) periods (plus skipped slots), one period less than the planned allocation "
                     "(cycles x period); capture_slot_s = snapshots present x protocol period is reported for that "
                     "comparison and is nominal, not measured."),
    "warmup": ("Generator start (request log header start_utc) to its 'measure' phase marker. A run that ended "
               "before the measure phase has warmup until the generator end record (or the end of its last "
               "logged interval), labeled in warmup_end_source and counted separately."),
    "measure_phase": ("Generator 'measure' to 'post' phase markers in traffic_requests.jsonl (sent by the runner "
                      "around the collector). Without markers the runner's end.json values or the generator's "
                      "own end are used and labeled (see http_window)."),
    "cycle_ms": ("Collector cycle time = sidecar capture.total_ms; p50/p95/max are nearest-rank over the snapshots "
                 "of one session. The protocol period is the limit (cycles_at_or_over_period counts total_ms >= "
                 "period, the audit's rejection rule). Collector 1.1 (sidecar output.async true) writes files on "
                 "a writer thread after the cycle, so its total_ms excludes file writes, renames and SHA-256 "
                 "(output.data_closed_ms in collector_cycles.csv is the time to the written data, a lower bound "
                 "of publication); up to 1.0 total_ms and capture_ms "
                 "included the write of every changed page. Values of the two versions are not comparable."),
    "missed_slots": ("Sidecar sched.skipped_before is the collector's running total of skipped sampling slots "
                     "before that snapshot (vmicollect sched.c: st.cycles_skipped), so missed_slots is its value at "
                     "the last snapshot, never a sum over snapshots. Slots skipped after the last snapshot appear "
                     "only in the collect.log end line (collector_end_missed_slots). collector_cycles.csv derives "
                     "skipped_since_previous_snapshot from consecutive running totals."),
    "host_monitor": ("scripts/host_monitor.summarize over the samples whose t_utc lies in the measure window from "
                     "end.json (the audit's window). Without a recorded runner window the session's HTTP window "
                     "bounds are used (generator markers or end), as labeled in monitor_window_source; a run that "
                     "never reached the measure phase has no monitor values. Working storage = the first "
                     "monitored path other than '/' (the runner monitors the session directory)."),
    "snapshots_expected": ("Assigned cycle count from session.json (cycles), otherwise from the session protocol "
                           "(pilot_cycles for pilots, cycles otherwise) or the campaign plan; never derived from "
                           "the files present."),
    "snapshot_sources": ("Sidecars are read in raw/ (a directory or the link into the archive). When raw/ is "
                         "absent they are read in .raw.pending-reclaim (reclamation interrupted between rename "
                         "and link) or in the archive named by archive_receipt.json, as stated in the notes; "
                         "images are never opened. Per-snapshot sums (read_errors, filled_zero, "
                         "hash_deferred_snapshots) are empty with a reason when any sidecar lacks the field."),
    "ideal_windows": ("From the audit (values.coverage) when present; otherwise computed from the assigned cycle "
                      "count and the protocol (window_rows, full_every) with the formula of "
                      "features.coverage.ideal_windows and labeled 'protocol arithmetic'. A configuration ceiling, "
                      "not a measurement; summaries report the two sources separately."),
    "data_volume": ("raw_bytes = sum of the file sizes (st_size) of the uncompressed .vmicd images, the "
                    "definition of collection.py audit values.raw_bytes: stat of local images (never opened), or "
                    "the original sizes in archive-manifest.json when the images are compressed members. "
                    "raw_allocated_bytes = sum of sidecar output.bytes_on_disk, which vmicollect records as "
                    "st_blocks x 512 (allocated space on the working disk when written). Archive sizes come from "
                    "archive-manifest.json: stored_size of compressed members, size of plain members."),
    "duplicates": ("A session is reported once. Two session directories with the same directory name or the "
                   "same session.json session_id (a copy of a capture), or a campaign plan with a repeated "
                   "session_id, are a data error (exit 2)."),
    "campaign_time": ("Each campaign event opens an interval that lasts until the next event and is attributed to "
                      "that event's status/stage. An interval that ends with an unclean-end record is reported as "
                      "unaccounted because the runner stopped at an unknown time within it. Time after the last "
                      "event is not counted. These periods are never counted as collection hours."),
    "campaign_events": ("events/*.json are snapshots of the runner state (status.json) written at each stage "
                        "change; fields the runner did not update are carried over, so `session` names the most "
                        "recent session the runner was working on."),
    "session_gaps": ("Time between end.json written_unix of one attempted session and session.json created_unix "
                     "of the next one (chronological order)."),
}

SESSION_COLUMNS = (
    "index", "plot_label", "session_id", "campaign_id", "vm", "role", "group", "group_attempt", "scenario", "seed",
    "replaces", "replaced_by",
    "boot_id", "session_schema", "session_dir", "raw_dir",
    "status", "reasons", "superseded", "superseded_reason",
    "completed", "interrupted", "end_error", "collector_rc", "traffic_rc", "monitor_rc",
    "audit_accepted", "logs_accepted", "audit_path", "audit_selection", "audit_candidates",
    "archived", "campaign_done", "provenance_problems",
    "snapshots_expected", "snapshots_expected_source", "snapshots_present", "images_present",
    "snapshots_missing", "seq_contiguous",
    "missed_slots", "read_errors", "filled_zero",
    "collector_end_snapshots", "collector_end_errors", "collector_end_missed_slots",
    "cycle_ms_p50", "cycle_ms_p95", "cycle_ms_max", "cycles_at_or_over_period", "full_cycle_ms",
    "hash_async_setting", "hash_deferred_snapshots", "fsync_setting", "mlock_setting",
    "raw_bytes", "raw_bytes_source", "raw_allocated_bytes", "audit_raw_bytes", "sidecars_differing_from_audit",
    "archive_manifest", "archive_schema", "archive_bytes", "archive_stored_bytes",
    "archive_raw_image_bytes", "archive_raw_image_stored_bytes",
    "windows", "ideal_windows", "ideal_windows_source", "score_coverage", "ideal_score_coverage",
    "score_gate", "gate_passed", "nominal_scored_s", "nominal_unscored_s",
    "session_created_utc", "session_end_written_utc", "session_wall_s",
    "warmup_start_utc", "warmup_start_source", "warmup_end_utc", "warmup_end_source", "warmup_s",
    "measure_start_utc", "measure_end_utc", "measure_bounds_source", "measure_phase_s", "measure_phase_s_source",
    "capture_first_utc", "capture_last_utc", "capture_span_s", "capture_slot_s",
    "http_requests", "http_ok", "http_errors", "http_status_errors", "http_timeouts", "http_transport_errors",
    "http_rps", "http_ok_rps",
    "latency_all_n", "latency_all_p50_ms", "latency_all_p95_ms", "latency_all_p99_ms", "latency_all_max_ms",
    "latency_ok_n", "latency_ok_p50_ms", "latency_ok_p95_ms", "latency_ok_p99_ms", "latency_ok_max_ms",
    "route_shares", "http_requests_outside_window", "requests_log_complete", "requests_log_problems",
    "traffic_matches_audit",
    "monitor_window_start_utc", "monitor_window_end_utc", "monitor_window_source", "monitor_window_samples",
    "cpu_busy_p50_pct", "cpu_busy_p95_pct", "cpu_busy_max_pct",
    "swap_used_max_kib", "swap_in_pages", "swap_out_pages", "disk_bytes_written",
    "fs_free_min_working_bytes", "fs_free_min_root_bytes", "temp_max_c", "monitor_problems",
    "clock_offset_before_s", "clock_offset_after_s",
    "evidence_checked", "evidence_hash_mismatches", "evidence_checks", "evidence_consistent", "evidence_problems",
    "notes", "sources", "missing", "not_applicable",
)
CAPTURE_FIELDS = ("raw_dir", "snapshots_present", "images_present", "seq_contiguous",
                  "missed_slots", "read_errors", "filled_zero", "cycle_ms_p50", "cycle_ms_p95", "cycle_ms_max",
                  "cycles_at_or_over_period", "full_cycle_ms", "hash_deferred_snapshots", "raw_bytes",
                  "raw_bytes_source", "raw_allocated_bytes",
                  "capture_first_utc", "capture_last_utc", "capture_span_s")
COLLECTOR_LOG_FIELDS = ("collector_end_snapshots", "collector_end_errors", "collector_end_missed_slots")
HTTP_FIELDS = ("http_requests", "http_ok", "http_errors", "http_status_errors", "http_timeouts",
               "http_transport_errors", "http_rps", "http_ok_rps",
               "latency_all_n", "latency_all_p50_ms", "latency_all_p95_ms", "latency_all_p99_ms", "latency_all_max_ms",
               "latency_ok_n", "latency_ok_p50_ms", "latency_ok_p95_ms", "latency_ok_p99_ms", "latency_ok_max_ms",
               "route_shares", "http_requests_outside_window")
WINDOW_FIELDS = ("measure_start_utc", "measure_end_utc", "measure_bounds_source", "measure_phase_s",
                 "measure_phase_s_source")
TRAFFIC_FIELDS = ("warmup_start_utc", "warmup_start_source", "warmup_end_utc", "warmup_end_source", "warmup_s",
                  *WINDOW_FIELDS, *HTTP_FIELDS, "requests_log_complete", "requests_log_problems")
MONITOR_FIELDS = ("monitor_window_start_utc", "monitor_window_end_utc", "monitor_window_source",
                  "monitor_window_samples", "cpu_busy_p50_pct", "cpu_busy_p95_pct", "cpu_busy_max_pct",
                  "swap_used_max_kib", "swap_in_pages", "swap_out_pages", "disk_bytes_written",
                  "fs_free_min_working_bytes", "fs_free_min_root_bytes", "temp_max_c", "monitor_problems")
AUDIT_FIELDS = ("audit_accepted", "logs_accepted", "audit_path", "audit_selection", "windows", "ideal_windows",
                "ideal_windows_source", "score_coverage", "ideal_score_coverage", "score_gate", "gate_passed",
                "nominal_scored_s", "nominal_unscored_s", "audit_raw_bytes", "traffic_matches_audit")
ARCHIVE_FIELDS = ("archive_manifest", "archive_schema", "archive_bytes", "archive_stored_bytes",
                  "archive_raw_image_bytes", "archive_raw_image_stored_bytes")
EVIDENCE_FIELDS = ("evidence_checked", "evidence_hash_mismatches", "evidence_checks", "evidence_consistent",
                   "evidence_problems", "sidecars_differing_from_audit")
INTERVAL_COLUMNS = ("session_id", "interval", "phase", "t_start_utc", "t_end_utc", "duration_s", "requests", "ok",
                    "http_error", "timeout", "transport_error", "throughput_rps")
CYCLE_COLUMNS = ("session_id", "seq", "file", "full", "timestamp", "timestamp_unix", "capture_ms", "write_ms",
                 "total_ms", "bytes_on_disk", "pages_changed", "pages_total", "skipped_before",
                 "skipped_since_previous_snapshot", "lateness_s", "read_errors", "filled_zero", "hash_deferred",
                 "async", "backend_read_ms", "queue_wait_ms", "data_closed_ms", "queue_jobs", "queue_bytes")
COVERAGE_COLUMNS = ("session_id", "status", "audit_path", "source", "expected_snapshots", "observed_snapshots",
                    "missing_snapshots", "scorable_windows",
                    *("rows_" + name for name in STATE_ROWS), "rows_other",
                    *("unscored_" + name for name in UNSCORED_CAUSES), "unscored_other", "unscored_rows_total",
                    "first_score_seq", "longest_unscored_run_rows", "nominal_scored_s", "nominal_unscored_s",
                    "score_coverage", "ideal_windows", "ideal_score_coverage", "lost_windows_vs_ideal", "gate",
                    "gate_possible_at_assigned_length", "gate_passed", "missing")
EVENT_COLUMNS = ("time_utc", "vm", "status", "stage", "session", "group", "position", "message",
                 "duration_to_next_s", "attributed_to", "file")
ROUTE_COLUMNS = ("session_id", "route", "requests", "ok", "errors", "share_of_measure_requests")
# F1 of the verification of B9a: the tolerated conditions of every accepted session by register id (tolerated.csv). The
# register ids are those the audits record (features/audit_policy.py TOLERATED; the report never imports features/),
# invalid_rows first: it is the one id an audit without values.exceptions still records.
TOLERATED_FIRST = "invalid_rows"
TOLERATED_SOURCE = {"exceptions": "audit values.exceptions",
                    "quality": "audit values.quality.tolerated_invalid_seq (an audit without values.exceptions: only "
                               "the invalid rows)"}
NOT_RECORDED = "not recorded: the audit has neither values.exceptions nor values.quality.tolerated_invalid_seq"
SOURCE_COLUMNS = ("session_id", "session_dir", "kind", "path", "realpath", "bytes", "sha256",
                  "logs_manifest_sha256", "matches_logs_manifest")


class DataError(ValueError):
    """Unusable top-level input (exit code 2)."""


class NoVerdict(ValueError):
    """An audit exists but gives no verdict for this session (provenance mismatch)."""


# ---------------------------------------------------------------- small helpers

def number(value):
    """A finite int/float (not bool), else None."""
    return value if type(value) in (int, float) and math.isfinite(value) else None


def integer(value):
    return value if type(value) is int else None


def r6(value):
    return None if value is None else round(value, 6)


def utc(unix):
    """ISO-8601 UTC of a POSIX time; None when absent or not representable as a date."""
    if unix is None:
        return None
    try:
        return datetime.fromtimestamp(unix, timezone.utc).isoformat(timespec="microseconds")
    except (OverflowError, OSError, ValueError):
        return None


def timestamp(value):
    """A POSIX time that is a finite number representable as a date, else None (never guessed)."""
    value = number(value)
    return value if value is not None and utc(value) is not None else None


def unix_of(text):
    """Seconds since the epoch of an ISO-8601 time with a zone, else None."""
    if not isinstance(text, str):
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return moment.timestamp() if moment.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def distribution(values):
    """n/min/nearest-rank median/max of per-session values (not a pooled percentile)."""
    values = sorted(v for v in values if v is not None)
    if not values:
        return {"n": 0, "min": None, "median": None, "max": None}
    return {"n": len(values), "min": values[0], "median": traffic_log.percentile(values, .5), "max": values[-1]}


def ratio(numerator, denominator, digits=6):
    value = round(numerator / denominator, digits) if denominator else None
    return {"numerator": numerator, "denominator": denominator, "value": value}


def ideal_windows(cycles, window_rows, full_every):
    """features.coverage.ideal_windows (same formula, kept local so the report never imports the extractor;
    the equality is a regression test)."""
    chains, tail = divmod(cycles, full_every)
    return chains * max(0, full_every - window_rows) + max(0, tail - window_rows)


def total(values):
    values = [v for v in values if v is not None]
    return math.fsum(values) if values else 0


def joined(items):
    return " | ".join(str(item) for item in items)


def clean_text(text):
    return CONTROL.sub(" ", str(text))


def one_line(text):
    """Whitespace (also line breaks of multi-line errors) collapsed: for Markdown cells and histogram keys."""
    return " ".join(clean_text(text).split())


def reason_class(reason):
    """Reason with session-specific tokens (images, request IDs, numbers, paths) replaced, for histograms."""
    text = one_line(reason)
    text = re.sub(r"\S+\.vmicd\b", "<image>", text)
    text = re.sub(r"\b(?:[0-9a-f]{12}|smoke\d+)-\d{2}-\d{8}\b", "<rid>", text)
    text = re.sub(r"(unreadable:\s*[A-Za-z]+(?:Error|Exception)).*", r"\1", text)
    text = re.sub(r"(?<![\w/.-])/[^\s:'\",;)]+", "<path>", text)  # absolute paths, not "errors/fill/missed"
    text = re.sub(r"-?\d+(?:\.\d+)?!=-?\d+(?:\.\d+)?", "<n>!=<n>", text)
    text = re.sub(r"(?<=[:=])\s*-?\d+(?:\.\d+)?\b", "<n>", text)
    return text


def git_identity():
    try:
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                                timeout=20)
        status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True, text=True,
                                timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"commit": None, "dirty": None, "changed_paths": None, "missing": f"git unavailable: {exc}"}
    if commit.returncode or status.returncode:
        return {"commit": None, "dirty": None, "changed_paths": None,
                "missing": "git failed: " + (commit.stderr + status.stderr).strip()[:200]}
    changed = [line for line in status.stdout.splitlines() if line.strip()]
    return {"commit": commit.stdout.strip(), "dirty": bool(changed), "changed_paths": len(changed)}


# ---------------------------------------------------------------- input registry

class Inputs:
    """Every file the report read (path, size, SHA-256) and every input it could not use.

    `session` arguments are the Session that read the file (None for campaign-level inputs); records are
    keyed by its directory, never by its ID alone."""

    def __init__(self):
        self.files = {}
        self.unreadable = []

    def record(self, path, sha, size, kind, session):
        path = os.path.abspath(path)
        real = os.path.realpath(path)
        self.files[path] = {"session": session.sid if session is not None else None,
                            "session_dir": session.key if session is not None else None,
                            "kind": kind, "path": path,
                            "realpath": real if real != path else None, "bytes": size, "sha256": sha}
        return sha

    def sha(self, path):
        return self.files[os.path.abspath(path)]["sha256"]

    def read_bytes(self, path, kind, session):
        data = Path(path).read_bytes()
        self.record(path, hashlib.sha256(data).hexdigest(), len(data), kind, session)
        return data

    def read_json(self, path, kind, session):
        doc = json.loads(self.read_bytes(path, kind, session))
        if not isinstance(doc, dict):
            raise ValueError(f"{path}: expected a JSON object")
        return doc

    def hash_only(self, path, kind, session):
        sha, size = hashlib.sha256(), 0
        with open(path, "rb") as stream:
            while chunk := stream.read(CHUNK):
                sha.update(chunk)
                size += len(chunk)
        return self.record(path, sha.hexdigest(), size, kind, session)

    def stream(self, path, scan, kind, session):
        """Feed complete lines to scan.feed() while hashing; the unterminated tail goes to scan.finish()."""
        sha, size, tail, lineno = hashlib.sha256(), 0, b"", 0
        with open(path, "rb") as stream:
            while chunk := stream.read(CHUNK):
                sha.update(chunk)
                size += len(chunk)
                lines = (tail + chunk).split(b"\n")
                tail = lines.pop()
                for line in lines:
                    lineno += 1
                    scan.feed(lineno, line)
        self.record(path, sha.hexdigest(), size, kind, session)
        scan.finish(tail, size)
        return scan

    def problem(self, path, problem, session=None):
        self.unreadable.append({"input": str(path), "session": session.sid if session is not None else None,
                                "problem": one_line(problem)})

    def for_session(self, session):
        return sorted((r for r in self.files.values() if r["session_dir"] == session.key), key=lambda r: r["path"])


# ---------------------------------------------------------------- generator logs (streaming)

class LogScan:
    """One generator JSONL log: header, phase markers, end record and record numbering."""

    def __init__(self, schema):
        self.schema = schema
        self.header = self.end = None
        self.markers = []
        self.records = 0
        self.previous = None
        self.problems = traffic_log.Problems()

    def feed(self, lineno, line):
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("not an object")
        except ValueError:
            self.problems.add("corrupt_line", lineno)
            return
        self.records += 1
        n = record.get("n")
        if type(n) is not int or n != (0 if self.previous is None else self.previous + 1):
            self.problems.add("n_discontinuous", lineno)
        if type(n) is int:
            self.previous = n
        if record.get("schema") != self.schema:
            self.problems.add("schema_mismatch", lineno)
        if self.end is not None:
            self.problems.add("record_after_end", lineno)
        kind = record.get("type")
        if self.records == 1 and kind != "header":
            self.problems.add("missing_header")
        if kind == "header":
            if self.records == 1:
                self.header = record
            else:
                self.problems.add("unexpected_header", lineno)
        elif kind == "phase":
            self.markers.append(record)
        elif kind == "end":
            self.end = record
        else:
            self.item(record, lineno)

    def item(self, record, lineno):
        raise NotImplementedError

    def finish(self, tail, size):
        if not size:
            self.problems.add("empty_file")
        if tail:
            self.problems.add("torn_last_line")
        if self.end is None:
            self.problems.add("end_missing")
        else:
            if not self.end.get("clean") or self.end.get("write_errors"):
                self.problems.add("end_not_clean")
            if self.end.get("records") != self.records:
                self.problems.add("records_mismatch", f"{self.end.get('records')}!={self.records}")


class RequestScan(LogScan):
    """Request log: per-phase outcome counts. Each measure-phase request is kept as four compact numbers
    (start time, duration, outcome code, route index; about 21 bytes) so the HTTP window can be applied
    after the scan and percentiles stay exact."""

    def __init__(self):
        super().__init__(traffic_log.REQUEST_SCHEMA)
        self.phases = defaultdict(Counter)
        self.route_names, self.route_index = [], {}
        self.starts = array("d")     # t_start_utc as POSIX seconds; NaN when unparseable
        self.durations = array("d")  # duration_ms; NaN when invalid
        self.outcomes = array("b")   # OUTCOME_CODE, -1 for an unknown outcome
        self.routes = array("l")
        self.requests = 0

    def item(self, record, lineno):
        if record.get("type") != "request":
            self.problems.add("unknown_record_type", lineno)
            return
        self.requests += 1
        phase, outcome = record.get("phase"), record.get("outcome")
        if phase not in traffic_log.PHASES:
            self.problems.add("request_phase_unknown", lineno)
        if outcome not in traffic_log.OUTCOMES:
            self.problems.add("request_outcome_unknown", lineno)
        counts = self.phases[phase]
        counts["requests"] += 1
        counts[outcome] += 1
        if phase != "measure":
            return
        route = f"{record.get('method')} {record.get('route')}"
        if route not in self.route_index:
            self.route_index[route] = len(self.route_names)
            self.route_names.append(route)
        duration = number(record.get("duration_ms"))
        if duration is None or duration < 0:
            self.problems.add("request_duration_invalid", lineno)
            duration = math.nan
        start = unix_of(record.get("t_start_utc"))
        if start is None:
            self.problems.add("request_start_invalid", lineno)
            start = math.nan
        self.starts.append(start)
        self.durations.append(duration)
        self.outcomes.append(OUTCOME_CODE.get(outcome, -1))
        self.routes.append(self.route_index[route])

    def finish(self, tail, size):
        super().finish(tail, size)
        if self.end is not None:
            for key in ("requests_logged", "requests_started"):
                if self.end.get(key) != self.requests:
                    self.problems.add(key + "_mismatch", f"{self.end.get(key)}!={self.requests}")
            for key in ("in_flight_at_stop", "worker_errors"):
                if self.end.get(key):
                    self.problems.add(key, self.end[key])


class IntervalScan(LogScan):
    """Interval log: one row per 5 s interval for intervals.csv."""

    def __init__(self):
        super().__init__(traffic_log.INTERVAL_SCHEMA)
        self.rows = []

    def item(self, record, lineno):
        if record.get("type") != "interval":
            self.problems.add("unknown_record_type", lineno)
            return
        index = record.get("interval")
        if index != len(self.rows):
            self.problems.add("interval_index", f"{len(self.rows)}!={index}")
        self.rows.append({"interval": index, "phase": record.get("phase"),
                          "t_start_utc": record.get("t_start_utc"), "t_end_utc": record.get("t_end_utc"),
                          "duration_s": number(record.get("duration_s")),
                          **{key: integer(record.get(key)) for key in ("requests", "ok", "http_error", "timeout",
                                                                        "transport_error")},
                          "throughput_rps": number(record.get("throughput_rps"))})


def latency_stats(values):
    """Exact nearest-rank p50/p95/p99/max of one session's durations (sorted once, in memory). Python floats,
    not NumPy: traffic_log.percentile tests the list for emptiness and the CSV cells repr() the values."""
    ordered = np.sort(np.asarray(values, dtype=np.float64)).tolist()
    stats = {"n": len(ordered)}
    for name, q in QUANTILES:
        stats[name] = traffic_log.percentile(ordered, q)
    stats["max"] = traffic_log.percentile(ordered, 1.0)
    return stats


def http_stats(scan, mask):
    """Counts, exact latencies and routes of the measure-phase requests selected by `mask`."""
    durations = np.frombuffer(scan.durations, dtype=np.float64)[mask]
    outcomes = np.frombuffer(scan.outcomes, dtype=np.int8)[mask]
    routes = np.frombuffer(scan.routes, dtype=np.dtype(f"i{scan.routes.itemsize}"))[mask]
    valid = ~np.isnan(durations)
    ok = outcomes == OUTCOME_CODE["ok"]
    per_route = np.bincount(routes, minlength=len(scan.route_names))
    per_route_ok = np.bincount(routes[ok], minlength=len(scan.route_names))
    return {"requests": int(mask.sum()), "ok": int(ok.sum()),
            **{name: int((outcomes == code).sum()) for name, code in OUTCOME_CODE.items() if name != "ok"},
            "latency_all": latency_stats(durations[valid]), "latency_ok": latency_stats(durations[valid & ok]),
            "routes": {name: (int(per_route[i]), int(per_route_ok[i])) for i, name in enumerate(scan.route_names)
                       if per_route[i]}}


# ---------------------------------------------------------------- one session

class Row(dict):
    """One sessions.csv row; every value left empty carries a reason (missing or not applicable)."""

    def __init__(self):
        super().__init__({column: None for column in SESSION_COLUMNS})
        self.missing = {}
        self.not_applicable = {}

    def miss(self, fields, reason):
        """Evidence for these fields is absent or unreadable (only fields still empty are marked)."""
        for field in fields:
            if self.get(field) is None:
                self.missing.setdefault(field, reason)

    def na(self, fields, reason):
        """These fields have no meaning for this session (they are never counted as missing evidence)."""
        for field in fields:
            if self.get(field) is None:
                self.not_applicable.setdefault(field, reason)


class Session:
    def __init__(self, directory, sid=None):
        self.dir = Path(directory)
        self.key = str(self.dir)  # input records are keyed by directory, never by ID alone
        self.sid = sid or self.dir.name
        self.row = Row()
        self.row["session_id"] = self.sid
        self.row["session_dir"] = str(self.dir)
        self.status = None
        self.reasons = []
        self.notes = []
        self.attempted = False
        self.meta = {}
        self.end = None
        self.protocol = None
        self.audit = None          # values of the audit whose verdict is used
        self.audit_doc = None      # the whole audit document (campaign provenance)
        self.cycles = []
        self.sidecars_read = False
        self.request_log = False
        self.reached_measure = None
        self.intervals = []
        self.routes = []
        self.coverage = None
        self.tolerated = None      # {register id: {observed, expected, over}} (tolerated_of), None: not recorded
        self.tolerated_source = None
        self.times = {}
        self.window_sources = {}
        self.generator_measure = None  # unclipped generator measure phase, compared with the audit
        self.index = None
        self.superseded = None     # True / False, None when unknown (unreadable marker)
        self.compressed_images = 0
        self.archive_files = None
        self.evidence_problems = []
        self.archive_problems = []
        self.traffic_difference = None
        self.provenance = []


def guarded(session, name, fields, function, *args):
    """Run one evidence step; a failure marks only that step's fields as missing."""
    try:
        function(session, *args)
    except NoVerdict as exc:
        session.row.miss(fields, clean_text(f"{name}: {exc}"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError,
            ZeroDivisionError) as exc:
        problem = f"{name} evidence unreadable ({type(exc).__name__}: {exc})"
        session.notes.append(clean_text(problem))
        session.row.miss(fields, clean_text(problem))


def read_optional(session, inputs, name, kind):
    """(document, state) with state 'absent', 'read' or 'unreadable' (an unreadable file is never 'absent')."""
    path = session.dir / name
    if not path.exists():
        return None, "absent"
    try:
        return inputs.read_json(path, kind, session), "read"
    except (OSError, ValueError) as exc:
        session.notes.append(clean_text(f"{name} unreadable: {exc}"))
        inputs.problem(path, f"{name} unreadable ({type(exc).__name__}: {exc})", session)
        return None, "unreadable"


def expected_snapshots(meta, protocol, plan_row):
    cycles = integer(meta.get("cycles"))
    if cycles is not None:
        return cycles, "session.json cycles"
    if protocol:
        key = "pilot_cycles" if meta.get("role") == "pilot" else "cycles" if meta.get("role") != "diagnostic" else None
        if key and integer(protocol.get(key)) is not None:
            return protocol[key], f"session protocol.json {key} (session.json has no cycles)"
    if plan_row and integer(plan_row.get("cycles")) is not None:
        return plan_row["cycles"], "campaign plan cycles"
    return None, None


def ended_before(s, step):
    """end.json shows an unfinished run that never reached runner step `step`.

    collection.capture_session records the steps clock, functional-check, pre-segment, warmup, capture and
    guest-evidence in end.json as it reaches them. Session schema 1 recorded no steps; its runner set
    capture_started_unix immediately before starting the collector, so only 'capture' is decidable there."""
    end = s.end
    if not isinstance(end, dict) or end.get("completed"):
        return False
    if isinstance(end.get("steps"), dict):
        return step not in end["steps"]
    return s.meta.get("schema") == SESSION_SCHEMA_1 and step == "capture" and "capture_started_unix" not in end


def absent(s, fields, step, stage, reason):
    """Fields of a stage the run never reached are not applicable; otherwise their evidence is missing."""
    if ended_before(s, step):
        where = ("end.json steps has no '" + step + "'") if isinstance((s.end or {}).get("steps"), dict) \
            else "schema 1 end.json has no capture_started_unix"
        s.row.na(fields, f"the run ended before {stage} ({where})")
    else:
        s.row.miss(fields, reason)


def snapshot_directory(s, inputs):
    """Where the sidecars are: raw/, or after an interrupted or finished reclamation the pending directory or
    the archive named by the receipt. None when there is none (the row then says why)."""
    row = s.row
    raw = s.dir / "raw"
    fields = CAPTURE_FIELDS + COLLECTOR_LOG_FIELDS
    if raw.is_symlink():
        target = os.readlink(raw)
        row["raw_dir"] = target
        if not raw.exists():
            problem = f"raw/ links to {target}, which is not available"
            inputs.problem(raw, problem, s)
            row.miss(fields, problem)
            return None
        s.notes.append("raw/ is a link into the archive; sidecars were read there, images were not opened")
        return raw
    if raw.is_dir():
        row["raw_dir"] = str(raw)
        return raw
    pending = s.dir / PENDING_RAW
    if pending.is_dir() and not pending.is_symlink():
        row["raw_dir"] = str(pending)
        s.notes.append(f"raw/ is absent: its reclamation stopped between rename and link (collection_archive "
                       f"reclaim_raw); sidecars and image sizes were read in {PENDING_RAW}")
        return pending
    receipt_path = s.dir / "archive_receipt.json"
    if receipt_path.exists():
        try:
            receipt = inputs.read_json(receipt_path, "archive_receipt", s)
            target = Path(receipt["destination"]) / "raw"
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problem = f"raw/ absent and archive_receipt.json unusable ({type(exc).__name__}: {exc})"
            inputs.problem(receipt_path, problem, s)
            row.miss(fields, problem)
            return None
        if target.is_dir():
            row["raw_dir"] = str(target)
            s.notes.append("raw/ is absent after archival; sidecars were read in the archive named by "
                           "archive_receipt.json, images were not opened")
            return target
        problem = f"raw/ absent and the archived raw/ named by archive_receipt.json ({target}) is not available"
        inputs.problem(target, problem, s)
        row.miss(fields, problem)
        return None
    if ended_before(s, "capture"):
        # A fact, not missing data: end.json shows that the collector was never started.
        row["snapshots_present"] = row["images_present"] = row["raw_bytes"] = 0
        row["raw_bytes_source"] = "no raw/ directory: the run ended before the collector started"
        absent(s, fields, "capture", "the collector started", "no raw/ directory")
        return None
    if s.end is None:
        reason = ("no raw/ directory and no end.json: whether the collector started is not recorded (crash, "
                  "or a run still in progress)")
    else:
        reason = "raw/ is absent although end.json does not show that the run ended before the collector started"
        inputs.problem(raw, reason, s)
    row.miss(fields, reason)
    return None


def capture_step(s, inputs, period_ms):
    row = s.row
    source = snapshot_directory(s, inputs)
    if source is None:
        return
    cycles, images, log_seen = [], 0, False
    plain_sizes, compressed, bad_times = [], 0, 0
    for path in sorted(source.iterdir()):
        name = path.name
        if name.endswith(".vmicd"):
            images += 1
            plain_sizes.append(path.stat().st_size)  # metadata only; the image is never opened
            continue
        if name.endswith(".vmicd.zst"):
            images += 1
            compressed += 1
            continue
        if name == "collect.log":
            log_seen = True
            text = inputs.read_bytes(path, "collector_log", s).decode("utf-8", "replace")
            ends = COLLECTOR_END.findall(text)
            if len(ends) == 1:
                for field, value in zip(COLLECTOR_LOG_FIELDS, map(int, ends[0])):
                    row[field] = value
            else:
                row.miss(COLLECTOR_LOG_FIELDS, "collect.log has no end line (collector stopped before finishing)"
                         if not ends else "collect.log has several end lines")
            continue
        if not name.endswith(".json") or name == "capture.json":
            continue
        try:
            doc = inputs.read_json(path, "sidecar", s)
        except (OSError, ValueError) as exc:
            s.notes.append(clean_text(f"sidecar {name} unreadable: {exc}"))
            inputs.problem(path, f"sidecar unreadable: {exc}", s)
            continue
        if doc.get("schema") != "vmicollect/1":
            continue
        part = {key: doc.get(key) if isinstance(doc.get(key), dict) else {}
                for key in ("capture", "output", "stats", "sched")}
        stamp = timestamp(doc.get("timestamp_unix"))
        bad_times += doc.get("timestamp_unix") is not None and stamp is None
        cycles.append({"seq": integer(doc.get("seq")), "file": name, "full": part["output"].get("full"),
                       "timestamp": doc.get("timestamp"), "timestamp_unix": stamp,
                       "capture_ms": number(part["capture"].get("capture_ms")),
                       "write_ms": number(part["capture"].get("write_ms")),
                       "total_ms": number(part["capture"].get("total_ms")),
                       "bytes_on_disk": integer(part["output"].get("bytes_on_disk")),
                       "pages_changed": integer(part["output"].get("pages_changed")),
                       "pages_total": integer(part["output"].get("pages_total")),
                       "skipped_before": integer(part["sched"].get("skipped_before")),
                       "lateness_s": number(part["sched"].get("lateness_s")),
                       "read_errors": integer(part["stats"].get("read_errors")),
                       "filled_zero": integer(part["stats"].get("filled_zero")),
                       "hash_deferred": part["output"].get("hash_deferred"),
                       # collector 1.1 (output.async): writer-thread evidence, empty for older sidecars
                       "async": part["output"].get("async"),
                       "backend_read_ms": number(part["capture"].get("backend_read_ms")),
                       "queue_wait_ms": number(part["capture"].get("queue_wait_ms")),
                       "data_closed_ms": number(part["output"].get("data_closed_ms")),
                       "queue_jobs": integer(part["output"].get("queue_jobs")),
                       "queue_bytes": integer(part["output"].get("queue_bytes")),
                       "sha256": inputs.sha(path)})
    s.sidecars_read = True
    if not log_seen:
        row.miss(COLLECTOR_LOG_FIELDS, "collect.log absent next to the sidecars")
    cycles.sort(key=lambda c: (c["seq"] if c["seq"] is not None else math.inf, c["file"]))
    s.cycles = cycles
    row["images_present"] = images
    row["snapshots_present"] = len(cycles)
    if images != len(cycles):
        s.notes.append(f"{images} images but {len(cycles)} snapshot sidecars (a sidecar appears only after its "
                       "image is complete and hashed)")
    if bad_times:
        s.notes.append(f"{bad_times} sidecars have a timestamp_unix that is not a representable time; they are "
                       "left out of the capture interval")
    if compressed:  # compressed members: archive_step takes the original sizes from the archive manifest
        s.compressed_images = compressed
    else:
        row["raw_bytes"] = sum(plain_sizes)
        row["raw_bytes_source"] = "stat of the .vmicd images (st_size)" if images else "no .vmicd image present"
    if not cycles:
        row.miss(CAPTURE_FIELDS, "no snapshot sidecars")
        return
    count = len(cycles)
    row["seq_contiguous"] = [c["seq"] for c in cycles] == list(range(count))
    # skipped_before is a running total (see DEFINITIONS["missed_slots"]); per-snapshot fields are summed.
    previous = None
    for c in cycles:
        value = c["skipped_before"]
        if value is None:
            c["skipped_since_previous_snapshot"] = None
        elif previous is None:
            c["skipped_since_previous_snapshot"] = value if c["seq"] == 0 else None
        else:
            c["skipped_since_previous_snapshot"] = value - previous[1] if c["seq"] == previous[0] + 1 else None
        if value is not None:
            previous = (c["seq"], value)
    running = [c["skipped_before"] for c in cycles if c["skipped_before"] is not None]
    if running:
        row["missed_slots"] = running[-1]
        if any(b < a for a, b in zip(running, running[1:])):
            s.notes.append("sched.skipped_before decreases between snapshots (expected a running total)")
    else:
        row.miss(("missed_slots",), "sidecars lack sched.skipped_before")
    if len(running) < count:
        s.notes.append(f"missed_slots: {count - len(running)} sidecars lack sched.skipped_before")
    for field in ("read_errors", "filled_zero"):
        lacking = sum(c[field] is None for c in cycles)
        if lacking:
            row.miss((field,), f"{lacking} of {count} sidecars lack stats.{field} (no sum over a part)")
        else:
            row[field] = sum(c[field] for c in cycles)
    totals = sorted(c["total_ms"] for c in cycles if c["total_ms"] is not None)
    if totals:
        row["cycle_ms_p50"] = traffic_log.percentile(totals, .5)
        row["cycle_ms_p95"] = traffic_log.percentile(totals, .95)
        row["cycle_ms_max"] = totals[-1]
        if len(totals) < count:
            s.notes.append(f"cycle_ms: {count - len(totals)} sidecars lack capture.total_ms")
        if period_ms is not None:
            row["cycles_at_or_over_period"] = sum(t >= period_ms for t in totals)
        else:
            row.miss(("cycles_at_or_over_period",), "protocol period unknown")
    else:
        row.miss(("cycle_ms_p50", "cycle_ms_p95", "cycle_ms_max", "cycles_at_or_over_period"),
                 "sidecars lack capture.total_ms")
    flags = [c["full"] for c in cycles]
    fulls = [c for c in cycles if c["full"] is True]
    if any(type(flag) is not bool for flag in flags):
        s.notes.append(f"{sum(type(f) is not bool for f in flags)} sidecars lack output.full")
    if fulls:
        row["full_cycle_ms"] = [c["total_ms"] for c in fulls if c["total_ms"] is not None]
        if len(row["full_cycle_ms"]) < len(fulls):
            s.notes.append(f"full_cycle_ms: {len(fulls) - len(row['full_cycle_ms'])} full-snapshot sidecars lack "
                           "capture.total_ms")
    else:
        row.miss(("full_cycle_ms",), "no full-snapshot sidecar present (output.full)")
    deferred = [c["hash_deferred"] for c in cycles]
    lacking = sum(type(flag) is not bool for flag in deferred)
    if lacking:
        row.miss(("hash_deferred_snapshots",), f"{lacking} of {count} sidecars lack output.hash_deferred "
                                               "(collector predates the field)")
    else:
        row["hash_deferred_snapshots"] = sum(deferred)
    allocated = [c["bytes_on_disk"] for c in cycles]
    if None in allocated:
        row.miss(("raw_allocated_bytes",), f"{allocated.count(None)} sidecars lack output.bytes_on_disk")
    else:
        row["raw_allocated_bytes"] = sum(allocated)
    times = [c["timestamp_unix"] for c in cycles if c["timestamp_unix"] is not None]
    if times:
        s.times["first"], s.times["last"] = min(times), max(times)
        row["capture_first_utc"], row["capture_last_utc"] = utc(min(times)), utc(max(times))
        row["capture_span_s"] = r6(max(times) - min(times))
    else:
        row.miss(("capture_first_utc", "capture_last_utc", "capture_span_s"), "sidecars lack timestamp_unix")


def marker_time(markers, phase):
    for marker in markers:
        if marker.get("phase") == phase:
            return unix_of(marker.get("t_utc"))
    return None


LAST_INTERVAL = "end of the last logged measure interval (no measure end and no generator end record)"


def last_interval_end(intervals):
    ends = [unix_of(iv.get("t_end_utc")) for iv in intervals]
    ends = [t for t in ends if t is not None]
    return max(ends) if ends else None


def traffic_step(s, inputs):
    row, end = s.row, s.end or {}
    requests_path, intervals_path = s.dir / "traffic_requests.jsonl", s.dir / "traffic_intervals.jsonl"
    if not requests_path.exists():
        if s.meta.get("schema") == SESSION_SCHEMA_1:
            row.miss(TRAFFIC_FIELDS, "session schema 1 records no request log")
        else:
            absent(s, TRAFFIC_FIELDS, "warmup", "the generator started", "traffic_requests.jsonl absent")
        return
    s.request_log = True
    scan = inputs.stream(requests_path, RequestScan(), "requests_log", s)
    intervals = inputs.stream(intervals_path, IntervalScan(), "intervals_log", s) \
        if intervals_path.exists() else None
    header = scan.header or {}
    config = header.get("config") if isinstance(header.get("config"), dict) else {}
    if header.get("session_id") not in (None, s.sid):
        scan.problems.add("session_id_mismatch", header.get("session_id"))
    problems = scan.problems.result()
    if intervals is None:
        problems.append("intervals:file_missing")
    else:
        if (intervals.header or {}).get("run_id") != header.get("run_id"):
            problems.append("intervals:run_id_mismatch")
        key = lambda m: (m.get("phase"), m.get("interval"))  # noqa: E731
        if [key(m) for m in intervals.markers] != [key(m) for m in scan.markers]:
            problems.append("intervals:phase_marker_mismatch")
        problems += ["intervals:" + p for p in intervals.problems.result()]
        s.intervals = intervals.rows
    initial = config.get("initial_phase")
    gen_end = timestamp(unix_of((scan.end or {}).get("end_utc")))
    measure_marker, post_marker = marker_time(scan.markers, "measure"), marker_time(scan.markers, "post")
    measure_ivs = [iv for iv in s.intervals if iv["phase"] == "measure"]

    # Generator start (warmup start): the header first, the runner's step record only as a labeled fallback.
    start = timestamp(unix_of(header.get("start_utc")))
    if start is not None:
        row["warmup_start_utc"], row["warmup_start_source"] = utc(start), "request log header start_utc"
    elif timestamp(((end.get("steps") or {}).get("warmup") or {}).get("unix")) is not None:
        start = end["steps"]["warmup"]["unix"]
        row["warmup_start_utc"], row["warmup_start_source"] = utc(start), "end.json steps.warmup (runner)"
    else:
        row.miss(("warmup_start_utc", "warmup_start_source"), "no request log header and no warmup step")

    # HTTP window start: generator marker first; the runner's end.json value only as a labeled fallback.
    if measure_marker is not None:
        m_start, start_src = measure_marker, "generator 'measure' marker"
    elif initial == "measure" and start is not None:
        m_start, start_src = start, "generator header start_utc (initial phase measure)"
    elif timestamp(end.get("measure_start_unix")) is not None:
        m_start, start_src = end["measure_start_unix"], "end.json measure_start_unix (runner; no generator 'measure' marker)"
    else:
        m_start, start_src = None, None

    # Warmup end: the switch to measure; a run that ended during warmup has warmup until the generator stopped.
    warmup_end, warmup_src = None, None
    if initial == "warmup":
        if m_start is not None:
            warmup_end, warmup_src = m_start, start_src
        elif gen_end is not None:
            warmup_end, warmup_src = gen_end, "generator end record (the run ended before the measure phase)"
        elif last_interval_end(s.intervals) is not None:
            warmup_end = last_interval_end(s.intervals)
            warmup_src = "end of the last logged interval (the run ended before the measure phase; no generator end record)"
        else:
            row.miss(("warmup_end_utc", "warmup_end_source", "warmup_s"),
                     "no 'measure' marker, no generator end record and no logged interval")
    elif initial == "measure":
        row.na(("warmup_end_utc", "warmup_end_source", "warmup_s"), "generator initial phase is 'measure' (no warmup)")
    else:
        row.miss(("warmup_end_utc", "warmup_end_source", "warmup_s"), f"generator initial phase {initial!r} unknown")
    if warmup_end is not None:
        row["warmup_end_utc"], row["warmup_end_source"] = utc(warmup_end), warmup_src
        if start is not None:
            row["warmup_s"] = r6(warmup_end - start)
    s.times["warmup_end"] = warmup_end
    s.reached_measure = m_start is not None

    # HTTP window end (DEFINITIONS["http_window"]).
    m_end, end_src = None, None
    if m_start is not None:
        if post_marker is not None:
            m_end, end_src = post_marker, POST_MARKER
        elif timestamp(end.get("measure_end_unix")) is not None:
            m_end, end_src = end["measure_end_unix"], RUNNER_END
        elif gen_end is not None:
            m_end, end_src = gen_end, "generator end record (the run ended without a measure end)"
        elif last_interval_end(measure_ivs) is not None:
            m_end, end_src = last_interval_end(measure_ivs), LAST_INTERVAL
    s.times.update(gen_start=start, measure_start=m_start, measure_end=m_end, gen_end=gen_end)
    s.window_sources = {"start": start_src, "end": end_src}
    row["requests_log_complete"] = scan.header is not None and scan.end is not None and not scan.problems.counts
    total_measure = scan.phases["measure"]["requests"]
    logged = sum(iv["requests"] or 0 for iv in measure_ivs)
    if measure_ivs and logged != total_measure:
        problems.append(f"intervals:measure_count_mismatch:{logged}!={total_measure}")
    row["requests_log_problems"] = joined(problems) or "none"
    if m_start is None:
        absent(s, WINDOW_FIELDS + HTTP_FIELDS, "capture", "the measure phase",
               "no 'measure' phase marker and no runner measure start")
        return
    row["measure_start_utc"], row["measure_end_utc"] = utc(m_start), utc(m_end)
    row["measure_bounds_source"] = f"start: {start_src}; end: {end_src or 'unknown'}"
    if m_end is None:
        row.miss(("measure_end_utc", "measure_phase_s", "measure_phase_s_source", "http_rps", "http_ok_rps"),
                 "no measure end: no 'post' marker, no runner measure end, no generator end record and no logged "
                 "measure interval")

    if not total_measure:
        row.miss(HTTP_FIELDS, "no measure-phase request records in traffic_requests.jsonl")
    starts = np.frombuffer(scan.starts, dtype=np.float64)
    every = np.ones(len(starts), dtype=bool)
    s.generator_measure = http_stats(scan, every) if total_measure else None
    mask = every.copy()
    if start_src.startswith("end.json"):
        mask &= starts >= m_start
    if end_src in (RUNNER_END, LAST_INTERVAL):
        mask &= starts < m_end
    stats = s.generator_measure if mask.all() else http_stats(scan, mask)
    outside = total_measure - (stats["requests"] if stats else 0)
    row["http_requests_outside_window"] = outside
    if outside:
        later = starts[~mask]
        later = later[~np.isnan(later)]
        s.notes.append(f"HTTP window {utc(m_start)} .. {utc(m_end)} ({end_src}): {outside} of {total_measure} "
                       f"requests labeled 'measure' by the generator started outside it"
                       + (f" (the last at {utc(float(later.max()))})" if len(later) else "")
                       + " and are not counted in any HTTP value")
    # Rate denominator: the logged intervals when they hold exactly the counted requests, else the window length.
    durations = [iv["duration_s"] for iv in measure_ivs]
    if measure_ivs and end_src != RUNNER_END and stats and logged == stats["requests"] and None not in durations:
        row["measure_phase_s"] = r6(math.fsum(durations))
        row["measure_phase_s_source"] = "sum of the logged measure-phase 5 s intervals"
    elif m_end is not None:
        row["measure_phase_s"] = r6(m_end - m_start)
        why = ("the generator's intervals continue past the runner's end" if end_src == RUNNER_END
               else "no measure-phase interval in the interval log" if not measure_ivs
               else "interval durations missing" if None in durations
               else f"the logged measure intervals hold {logged} requests, the window {stats['requests'] if stats else 0}")
        row["measure_phase_s_source"] = f"window length end - start (wall clock): {why}"
    if not stats:
        return
    row["http_requests"], row["http_ok"] = stats["requests"], stats["ok"]
    row["http_errors"] = stats["requests"] - stats["ok"]
    row["http_status_errors"], row["http_timeouts"] = stats["http_error"], stats["timeout"]
    row["http_transport_errors"] = stats["transport_error"]
    if row["measure_phase_s"]:
        row["http_rps"] = r6(stats["requests"] / row["measure_phase_s"])
        row["http_ok_rps"] = r6(stats["ok"] / row["measure_phase_s"])
    else:
        row.miss(("http_rps", "http_ok_rps"), "measure-phase duration unknown")
    for prefix in ("latency_all", "latency_ok"):
        latency = stats[prefix]
        row[prefix + "_n"] = latency["n"]
        for name in ("p50", "p95", "p99", "max"):
            row[f"{prefix}_{name}_ms"] = latency[name]
        row.miss(tuple(f"{prefix}_{name}_ms" for name in ("p50", "p95", "p99", "max")),
                 "no request with a duration in the HTTP window" if prefix == "latency_all"
                 else "no successful request in the HTTP window")
    counted = stats["requests"]
    s.routes = [{"session_id": s.sid, "route": route, "requests": n, "ok": ok, "errors": n - ok,
                 "share_of_measure_requests": r6(n / counted)}
                for route, (n, ok) in sorted(stats["routes"].items())]
    row["route_shares"] = joined(f"{r['route']}={r['share_of_measure_requests']}" for r in s.routes) or None
    row.miss(("route_shares",), "no request in the HTTP window")


def monitor_step(s, inputs):
    row, end = s.row, s.end or {}
    path = s.dir / "host_monitor.jsonl"
    if not path.exists():
        if s.meta.get("schema") == SESSION_SCHEMA_1:
            row.na(MONITOR_FIELDS, "session schema 1 runs no host monitor")
        else:
            absent(s, MONITOR_FIELDS, "warmup", "the host monitor started", "host_monitor.jsonl absent")
        return
    start, stop = timestamp(end.get("measure_start_unix")), timestamp(end.get("measure_end_unix"))
    begin = "end.json measure_start_unix"
    if start is None and s.times.get("measure_start") is not None:
        start, begin = s.times["measure_start"], s.window_sources["start"]
    if start is None:
        absent(s, MONITOR_FIELDS, "capture", "the measure phase", "no measure window (no measure start recorded)")
        return
    finish = "end.json measure_end_unix"
    if stop is None:
        if s.times.get("measure_end") is not None:
            stop, finish = s.times["measure_end"], s.window_sources["end"]
        elif timestamp(end.get("written_unix")) is not None:
            stop, finish = end["written_unix"], "end.json written_unix (no measure end and no generator end record)"
        else:
            row.miss(MONITOR_FIELDS, "no end of the measure window recorded")
            return
    source = f"{begin} .. {finish}" + (" (the audit's window)" if begin.startswith("end.json")
                                       and finish.startswith("end.json measure") else "")
    inputs.hash_only(path, "host_monitor", s)
    doc = host_monitor.summarize(path, start, stop)
    row["monitor_window_start_utc"], row["monitor_window_end_utc"] = utc(start), utc(stop)
    row["monitor_window_source"], row["monitor_window_samples"] = source, doc["window_samples"]
    cpu = doc["cpu_busy_pct"]
    row["cpu_busy_p50_pct"], row["cpu_busy_p95_pct"], row["cpu_busy_max_pct"] = cpu["p50"], cpu["p95"], cpu["max"]
    row["swap_used_max_kib"] = doc["swap_used_kb_max"]
    row["swap_in_pages"], row["swap_out_pages"] = doc["swap_in_pages"], doc["swap_out_pages"]
    written = doc["disk_bytes_written"] or {}
    row["disk_bytes_written"] = joined(f"{disk}={written[disk]}" for disk in sorted(written))
    free = doc["fs_free_bytes_min"] or {}
    row["fs_free_min_root_bytes"] = free.get("/")
    working = [p for p in free if p != "/"]
    row["fs_free_min_working_bytes"] = free[working[0]] if working else None
    row["temp_max_c"] = doc["temp_c_max"]
    row["monitor_problems"] = joined(doc["problems"]) or "none"
    reason = "no monitor samples in the measure window" if not doc["window_samples"] else \
        "the monitor log has no such values in the window"
    row.miss(MONITOR_FIELDS, reason)


def clock_step(s, inputs):
    for when in ("before", "after"):
        field, name = f"clock_offset_{when}_s", f"guest/clock_{when}.json"
        doc, state = read_optional(s, inputs, name, "guest_clock")
        if state == "unreadable":
            s.row.miss((field,), f"{name} unreadable")
        elif doc is None and s.meta.get("schema") == SESSION_SCHEMA_1:
            s.row.na((field,), "session schema 1 records no guest clock offset")
        elif doc is None:
            absent(s, (field,), "clock" if when == "before" else "guest-evidence",
                   "the guest clock check" if when == "before" else "the guest evidence step", f"{name} absent")
        else:
            s.row[field] = number(doc.get("offset_s"))
            s.row.miss((field,), f"{name} has no offset_s")


def dig(doc, *keys):
    """doc[k1][k2]... or None when a level is absent or not an object."""
    for key in keys:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    return doc


def audit_problem(s, inputs, doc):
    """Why an audit document gives no verdict for this session, None when it does (both modes, also for the
    campaign pointer; DEFINITIONS["audit_selection"])."""
    values = doc.get("values") if isinstance(doc.get("values"), dict) else None
    if doc.get("schema") != AUDIT_SCHEMA or values is None or type(values.get("accepted")) is not bool:
        return "not a complete collection audit"
    recorded = values.get("session_sha256")
    if recorded != inputs.sha(s.dir / "session.json"):
        return "audited another session.json (sha256 differs)" if recorded else "audit has no values.session_sha256"
    directory = values.get("session_dir")
    if directory not in (str(s.dir), str(s.dir.resolve())):
        return f"audited another session directory (values.session_dir {directory})"
    return None


def audit_candidates(s, inputs):
    """(path, doc, note) for every audit JSON in the session directory; doc is None when it gives no verdict."""
    paths = sorted(s.dir.glob("campaign_audit_*.json")) + sorted(s.dir.glob("audit_*.json"))
    found = []
    for path in paths:
        try:
            doc = inputs.read_json(path, "audit", s)
        except (OSError, ValueError) as exc:
            found.append((path, None, f"unreadable ({type(exc).__name__})"))
            continue
        problem = audit_problem(s, inputs, doc)
        if problem:
            found.append((path, None, problem))
        else:
            found.append((path, doc, "accepted" if doc["values"]["accepted"] else "rejected"))
    return found


def select_audit(s, inputs, pointer):
    if pointer is not None and pointer.exists():
        selected = inputs.read_json(pointer, "campaign_audit_pointer", s)
        path = Path(selected["path"])
        data = inputs.read_bytes(path, "audit", s)
        if hashlib.sha256(data).hexdigest() != selected.get("sha256"):
            raise NoVerdict("the audit selected by the campaign pointer changed (sha256 differs)")
        doc = json.loads(data)
        if not isinstance(doc, dict):
            raise NoVerdict("the audit selected by the campaign pointer is not a JSON object")
        problem = audit_problem(s, inputs, doc)
        if problem:
            raise NoVerdict(f"the audit selected by the campaign pointer gives no verdict: {problem}")
        return path, doc, f"campaign pointer {pointer.name}", [f"{path.name}=pointer"]
    found = audit_candidates(s, inputs)
    listing = [f"{path.name}={note}" for path, _, note in found]
    complete = [(path, doc) for path, doc, _ in found if doc is not None]
    if not complete:
        return None, None, None, listing
    if len(complete) == 1:
        path, doc = complete[0]
        return path, doc, "only audit with a verdict for this session", listing
    by_date = sorted(complete, key=lambda item: (str(item[1].get("date")), item[0].name))
    rejected = [item for item in by_date if not item[1]["values"]["accepted"]]
    if rejected:
        path, doc = rejected[0]
        return path, doc, f"{len(complete)} audits with a verdict: earliest rejecting verdict (never bypassed)", listing
    path, doc = by_date[-1]
    return path, doc, f"{len(complete)} audits with a verdict, all accepting: latest", listing


def audit_step(s, inputs, pointer):
    row = s.row
    path, doc, selection, listing = select_audit(s, inputs, pointer)
    row["audit_candidates"] = joined(listing) if listing else None
    row.miss(("audit_candidates",), "no audit JSON in the session directory")
    if doc is None:
        protocol_ideal(s, "protocol arithmetic (no audit)")
        if not s.cycles and not listing:
            reason = "no snapshot sidecars, so no audit (collection.py audit requires sidecars)"
            row.na(AUDIT_FIELDS + ("audit_candidates",), reason)
        else:
            reason = "no audit verdict for this session" + (" (see audit_candidates)" if listing else "")
            row.miss(AUDIT_FIELDS, reason)
        s.coverage = empty_coverage_row(s, reason)
        return
    values = doc["values"]
    s.audit, s.audit_doc = values, doc
    s.tolerated, s.tolerated_source = tolerated_of(values)
    row["audit_accepted"] = values["accepted"]
    row["audit_path"], row["audit_selection"] = str(path), selection
    logs = values.get("logs")
    if isinstance(logs, dict):
        row["logs_accepted"] = logs.get("accepted")
    row.miss(("logs_accepted",), "audit predates the log audit (no values.logs)" if "logs" not in values
             else "audit has no log evidence (values.logs is null: session schema 1 or historical capture)")
    row["windows"], row["score_coverage"] = integer(values.get("windows")), number(values.get("score_coverage"))
    row["audit_raw_bytes"] = integer(values.get("raw_bytes"))
    coverage = values.get("coverage") if isinstance(values.get("coverage"), dict) else None
    if coverage is not None:
        row["ideal_windows"], row["ideal_windows_source"] = coverage.get("ideal_windows"), "audit values.coverage"
        row["ideal_score_coverage"] = number(coverage.get("ideal_score_coverage"))
        row["nominal_scored_s"] = number(coverage.get("nominal_scored_s"))
        row["nominal_unscored_s"] = number(coverage.get("nominal_unscored_s"))
    else:
        row.miss(("nominal_scored_s", "nominal_unscored_s"), "audit predates values.coverage")
        protocol_ideal(s, "protocol arithmetic (audit has no coverage breakdown)")
    if row["score_coverage"] is not None:
        row["gate_passed"] = row["score_coverage"] >= row["score_gate"]
    s.coverage = coverage_row(s, path, coverage, values)
    traffic = dig(logs, "sections", "traffic")
    mine = s.generator_measure  # every request the generator labeled 'measure', as traffic_log.summarize counts
    if not (isinstance(traffic, dict) and isinstance(traffic.get("measure"), dict)):
        row.na(("traffic_matches_audit",), "the audit has no request log summary to compare")
    elif mine is None:
        row.miss(("traffic_matches_audit",), "no measure-phase requests read from the request log")
    else:
        measure = traffic["measure"]
        ours = {"requests": mine["requests"], "ok": mine["ok"],
                **{f"latency_ms.{k}": mine["latency_all"][k] for k in ("p50", "p95", "p99", "max")},
                **{f"latency_ok_ms.{k}": mine["latency_ok"][k] for k in ("p50", "p95", "p99", "max")}}
        theirs = {"requests": measure.get("requests"), "ok": measure.get("ok"),
                  **{f"latency_ms.{k}": dig(measure, "latency_ms", k) for k in ("p50", "p95", "p99", "max")},
                  **{f"latency_ok_ms.{k}": dig(measure, "latency_ok_ms", k) for k in ("p50", "p95", "p99", "max")}}
        row["traffic_matches_audit"] = ours == theirs
        if ours != theirs:
            s.traffic_difference = ", ".join(k for k in ours if ours[k] != theirs[k])
    row.miss(AUDIT_FIELDS, "not provided by the selected audit")


def tolerated_of(values):
    """The tolerated conditions an audit records by register id (DEFINITIONS["tolerated"]): ({id: {"observed": n,
    "expected": e, "over": bool}}, source) from values.exceptions, an entry that is not {observed: count} left out by
    name in the source; from values.quality.tolerated_invalid_seq when the audit has no values.exceptions (the invalid
    rows only, no expected count); (None, NOT_RECORDED) when it has neither."""
    exceptions = values.get("exceptions")
    if isinstance(exceptions, dict) and exceptions:
        counts, unreadable = {}, []
        for name, entry in exceptions.items():
            observed = entry.get("observed") if isinstance(entry, dict) else None
            if type(observed) is int and observed >= 0:
                expected = entry.get("expected")
                counts[str(name)] = {"observed": observed, "expected": expected if type(expected) is int else None,
                                     "over": entry.get("over") is True}
            else:
                unreadable.append(str(name))
        source = TOLERATED_SOURCE["exceptions"]
        return counts, source + (f" (unreadable entries left out: {', '.join(unreadable)})" if unreadable else "")
    seq = dig(values, "quality", "tolerated_invalid_seq")
    if isinstance(seq, list):
        return ({TOLERATED_FIRST: {"observed": len(seq), "expected": None, "over": False}},
                TOLERATED_SOURCE["quality"])
    return None, NOT_RECORDED


def tolerated_ids(sessions):
    """The register ids of tolerated.csv and of the summary: invalid_rows, then every other id the accepted sessions
    record, in the order of their audits' records."""
    ids = [TOLERATED_FIRST]
    for s in sessions:
        if s.status == "accepted" and s.tolerated:
            ids += [name for name in s.tolerated if name not in ids]
    return ids


def tolerated_table(sessions):
    """(columns, rows) of tolerated.csv: one row per accepted session, its count per register id (empty with the
    reason in missing where it records none), the ids over their expected count and the source."""
    ids = tolerated_ids(sessions)
    columns = ("session_id", "status", "source", *ids, "over_expected", "missing")
    rows = []
    for s in sessions:
        if s.status != "accepted":
            continue
        counts = s.tolerated or {}
        absent = [name for name in ids if name not in counts]
        rows.append({"session_id": s.sid, "status": s.status, "source": s.tolerated_source,
                     **{name: counts[name]["observed"] for name in counts},
                     "over_expected": joined(name for name in ids if counts.get(name, {}).get("over")) or None,
                     "missing": (NOT_RECORDED if s.tolerated is None else
                                 f"not recorded by this audit: {', '.join(absent)}" if absent else None)})
    return columns, rows


def tolerated_block(sessions):
    """The summary of the tolerated conditions of the accepted sessions by register id (DEFINITIONS["tolerated"])."""
    accepted = [s for s in sessions if s.status == "accepted"]
    by_id = {}
    for name in tolerated_ids(sessions):
        held = [s.tolerated[name] for s in accepted if s.tolerated and name in s.tolerated]
        expected = sorted({x["expected"] for x in held if x["expected"] is not None})
        by_id[name] = {"total": sum(x["observed"] for x in held) if held else None,
                       "max_in_one_session": max((x["observed"] for x in held), default=None),
                       "sessions_over_expected": sum(x["over"] for x in held),
                       # The register's expected count as the audits recorded it: null until G3b (then no session is
                       # over it), a list when the audits differ.
                       "expected": None if not expected else expected[0] if len(expected) == 1 else expected,
                       "sessions_counted": len(held),
                       **({} if held else {"missing": "no accepted session records it"})}
    return {"definition": DEFINITIONS["tolerated"], "accepted_sessions": len(accepted),
            "sources": dict(sorted(Counter(s.tolerated_source for s in accepted).items())),
            "not_recorded": [s.sid for s in accepted if s.tolerated is None], "by_id": by_id}


def set_gate(s, protocol):
    gate = number((protocol or {}).get("min_score_coverage"))
    s.row["score_gate"] = gate if gate is not None else GATE_DEFAULT
    if gate is None:
        s.notes.append("score_gate: 0.85, the default of features.quality.coverage_gate for protocol schemas 1 "
                       "and 2 (no protocol min_score_coverage)")


def protocol_ideal(s, label):
    """Ideal ceiling from the assigned cycle count and the protocol, labeled as configuration arithmetic."""
    row, protocol = s.row, s.protocol or {}
    expected = row["snapshots_expected"]
    window, rotation = integer(protocol.get("window_rows")), integer(protocol.get("full_every"))
    if not expected or not window or not rotation:
        row.miss(("ideal_windows", "ideal_windows_source", "ideal_score_coverage"),
                 "no audit and no assigned cycle count or protocol window_rows/full_every")
        return
    ideal = ideal_windows(expected, window, rotation)
    row["ideal_windows"], row["ideal_windows_source"] = ideal, label
    row["ideal_score_coverage"] = r6(ideal / expected)


def empty_coverage_row(s, reason):
    """coverage.csv row of a session without an audit breakdown: identity, assigned count and ideal only."""
    out = {column: None for column in COVERAGE_COLUMNS}
    out.update(session_id=s.sid, source="no audit", expected_snapshots=s.row["snapshots_expected"],
               ideal_windows=s.row["ideal_windows"], ideal_score_coverage=s.row["ideal_score_coverage"],
               gate=s.row["score_gate"], missing=reason)
    if out["ideal_windows"] is not None and out["gate"] is not None:
        out["gate_possible_at_assigned_length"] = out["ideal_score_coverage"] >= out["gate"]
    return out


def coverage_row(s, path, coverage, values):
    out = {column: None for column in COVERAGE_COLUMNS}
    out.update(session_id=s.sid, audit_path=str(path), gate=s.row["score_gate"])
    missing = {}
    if coverage is None:
        out.update(source="audit values (no coverage breakdown: audit predates values.coverage)",
                   scorable_windows=integer(values.get("windows")), score_coverage=number(values.get("score_coverage")),
                   observed_snapshots=integer(values.get("snapshots")), expected_snapshots=s.row["snapshots_expected"],
                   ideal_windows=s.row["ideal_windows"], ideal_score_coverage=s.row["ideal_score_coverage"])
        for column in COVERAGE_COLUMNS:
            if out[column] is None and column not in ("status", "missing", "gate_passed"):
                missing[column] = "audit predates values.coverage"
    else:
        states = coverage.get("state_rows") or {}
        causes = coverage.get("unscored_rows_by_cause") or {}
        out.update(source="audit values.coverage", expected_snapshots=coverage.get("expected_snapshots"),
                   observed_snapshots=coverage.get("observed_snapshots"),
                   missing_snapshots=coverage.get("missing_snapshots"),
                   scorable_windows=coverage.get("scorable_windows"),
                   rows_other=joined(f"{k}={v}" for k, v in sorted(states.items()) if k not in STATE_ROWS),
                   unscored_other=joined(f"{k}={v}" for k, v in sorted(causes.items()) if k not in UNSCORED_CAUSES),
                   unscored_rows_total=sum(v for v in causes.values() if type(v) is int),
                   first_score_seq=coverage.get("first_score_seq"),
                   longest_unscored_run_rows=coverage.get("longest_observed_unscored_run_rows"),
                   nominal_scored_s=coverage.get("nominal_scored_s"),
                   nominal_unscored_s=coverage.get("nominal_unscored_s"),
                   score_coverage=coverage.get("score_coverage"), ideal_windows=coverage.get("ideal_windows"),
                   ideal_score_coverage=coverage.get("ideal_score_coverage"),
                   lost_windows_vs_ideal=coverage.get("lost_windows_vs_ideal"),
                   gate_possible_at_assigned_length=coverage.get("gate_possible_at_assigned_length"))
        for name in STATE_ROWS:
            out["rows_" + name] = states.get(name, 0)
        for name in UNSCORED_CAUSES:
            out["unscored_" + name] = causes.get(name, 0)
        if out["first_score_seq"] is None:
            missing["first_score_seq"] = "no scorable window"
    if out["score_coverage"] is not None:
        out["gate_passed"] = out["score_coverage"] >= out["gate"]
    out["missing"] = group_missing(missing)
    return out


def archive_step(s, inputs, fallback):
    row = s.row
    receipt, state = read_optional(s, inputs, "archive_receipt.json", "archive_receipt")
    destination = None
    if receipt is not None:
        if isinstance(receipt.get("destination"), str) and receipt["destination"]:
            destination = Path(receipt["destination"])
        else:
            s.notes.append("archive_receipt.json names no destination")
    if destination is None and fallback is not None and (fallback / "archive-manifest.json").exists():
        destination = fallback
        s.notes.append("archive found at the campaign archive path without a usable local archive_receipt.json")
    if state == "unreadable":
        row.miss(("archived",), "archive_receipt.json exists but is unreadable")
    else:
        row["archived"] = receipt is not None
    if destination is None:
        if state == "unreadable":
            row.miss(ARCHIVE_FIELDS, "archive_receipt.json unreadable: the archive destination is unknown")
        elif receipt is not None:
            row.miss(ARCHIVE_FIELDS, "archive_receipt.json names no destination")
        else:
            row.na(ARCHIVE_FIELDS, "not archived (no archive_receipt.json)")
        return
    manifest_path = destination / "archive-manifest.json"
    if not manifest_path.exists():
        inputs.problem(manifest_path, "archive manifest not available", s)
        row.miss(ARCHIVE_FIELDS, f"archive manifest not available at {manifest_path}")
        return
    doc = inputs.read_json(manifest_path, "archive_manifest", s)
    if receipt and receipt.get("manifest_sha256") != inputs.sha(manifest_path):
        s.archive_problems.append("archive-manifest.json differs from the SHA-256 in archive_receipt.json")
    files = doc.get("files") if isinstance(doc.get("files"), dict) else {}
    s.archive_files = files
    images = [item for name, item in files.items() if name.startswith("raw/") and name.endswith(".vmicd")]
    row["archive_manifest"], row["archive_schema"] = str(manifest_path), doc.get("schema")
    row["archive_bytes"] = integer(doc.get("bytes"))
    row["archive_stored_bytes"] = integer(doc.get("stored_bytes", doc.get("bytes")))
    sizes = [integer(item.get("size")) if isinstance(item, dict) else None for item in images]
    stored = [integer(item.get("stored_size", item.get("size"))) if isinstance(item, dict) else None
              for item in images]
    if None in sizes:
        row.miss(("archive_raw_image_bytes",), "an image entry of archive-manifest.json lacks its size")
    else:
        row["archive_raw_image_bytes"] = sum(sizes)
    if None in stored:
        row.miss(("archive_raw_image_stored_bytes",), "an image entry of archive-manifest.json lacks its stored size")
    else:
        row["archive_raw_image_stored_bytes"] = sum(stored)
    if s.compressed_images and row["raw_bytes"] is None and row["archive_raw_image_bytes"] is not None:
        row["raw_bytes"] = row["archive_raw_image_bytes"]
        row["raw_bytes_source"] = "archive-manifest.json original sizes (the images are compressed members)"
        if len(images) != row["images_present"]:
            s.notes.append(f"{row['images_present']} images present, the archive manifest lists {len(images)}")
    row.miss(ARCHIVE_FIELDS, "archive manifest lacks the value")


def superseded_step(s, inputs):
    doc, state = read_optional(s, inputs, "superseded.json", "superseded_marker")
    if state == "unreadable":
        s.superseded = None  # fail closed: never counted as 'without a superseded marker'
        s.row.miss(("superseded", "superseded_reason"), "superseded.json exists but is unreadable")
        return
    if doc is None:
        s.superseded = s.row["superseded"] = False
        s.row.na(("superseded_reason",), "no superseded.json")
        return
    values = doc.get("values") if isinstance(doc.get("values"), dict) else {}
    s.superseded = values.get("usable_for_current_corpus") is not True
    s.row["superseded"] = s.superseded
    s.row["superseded_reason"] = clean_text(values.get("reason") or "superseded.json present")


def guest_environment(identity):
    """campaign.guest_environment: the guest identity without its boot ID."""
    return {k: v for k, v in identity.items() if k != "boot_id"} if isinstance(identity, dict) else None


def campaign_step(s, ctx):
    """campaign.py check_session / audit_capture conditions (DEFINITIONS["campaign_provenance"])."""
    manifest, plan_row, meta = ctx["manifest"], ctx["plan_row"], s.meta
    problems = []
    for key in ("role", "group", "scenario", "seed", "session_id", "vm", "replaces"):
        if meta.get(key) != plan_row.get(key):
            problems.append(f"session.json {key} {meta.get(key)!r} differs from the frozen assignment "
                            f"{plan_row.get(key)!r}")
    if meta.get("campaign_id") != manifest.get("id"):
        problems.append("session.json campaign_id differs from the campaign")
    if meta.get("commit") != manifest.get("commit") or meta.get("measurement_dirty") != []:
        problems.append("session.json commit differs from the campaign commit or measurement_dirty is not [] "
                        "(measurement sources changed)")
    if meta.get("protocol_sha256") != manifest.get("protocol_sha256"):
        problems.append("session.json protocol_sha256 differs from campaign.json")
    if "guest_environment" in manifest and guest_environment(meta.get("guest_before")) != manifest["guest_environment"]:
        problems.append("guest environment differs from the frozen campaign")
    group = ctx["groups"].get(plan_row.get("group"))
    if group is None:
        problems.append(f"no readable groups/{plan_row.get('group')}.json for the session's group")
    else:
        if group.get("vm") != plan_row.get("vm"):
            problems.append("the recorded campaign group belongs to another VM (groups/<group>.json vm)")
        if meta.get("guest_before") != group.get("identity"):
            problems.append("session boot differs from the recorded campaign group (groups/<group>.json identity)")
        if dig(meta, "host_context", "qemu") != group.get("qemu"):
            problems.append("session VM process differs from the recorded campaign group (groups/<group>.json qemu)")
    doc = s.audit_doc
    if doc is not None:
        values = doc["values"]
        if values.get("protocol_sha256") != manifest.get("protocol_sha256"):
            problems.append("audit protocol_sha256 differs from campaign.json")
        if doc.get("commit") != manifest.get("commit") or doc.get("measurement_dirty") != []:
            problems.append("audit commit differs from the campaign commit or measurement_dirty is not []")
        if "extractor_sha256" in manifest and values.get("extractor_sha256") != manifest["extractor_sha256"]:
            problems.append("audit extractor hashes differ from the frozen campaign")
        if values.get("role") != plan_row.get("role"):
            problems.append("audit role differs from the assignment")
    s.provenance += problems


def evidence_step(s, inputs):
    """Current files against logs_manifest.json, end.json and the audit (DEFINITIONS["evidence_consistency"])."""
    row, problems, checks = s.row, list(s.archive_problems), []
    schema1 = s.meta.get("schema") == SESSION_SCHEMA_1
    manifest, state = read_optional(s, inputs, "logs_manifest.json", "logs_manifest")
    recorded = (s.end or {}).get("logs_manifest_sha256")
    if manifest is not None:
        files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
        checked, mismatched = 0, []
        for record in inputs.for_session(s):
            try:
                name = Path(record["path"]).relative_to(s.dir.absolute()).as_posix()
            except ValueError:
                continue
            expected = files.get(name)
            if isinstance(expected, dict):
                checked += 1
                record["logs_manifest_sha256"] = expected.get("sha256")
                record["matches_logs_manifest"] = expected.get("sha256") == record["sha256"]
                if not record["matches_logs_manifest"]:
                    mismatched.append(name)
        row["evidence_checked"], row["evidence_hash_mismatches"] = checked, len(mismatched)
        checks.append(f"{checked} input files against logs_manifest.json")
        if mismatched:
            problems.append(f"{len(mismatched)} files differ from logs_manifest.json ({', '.join(mismatched)})")
        if isinstance(recorded, str):
            checks.append("logs_manifest.json against end.json")
            if recorded != inputs.sha(s.dir / "logs_manifest.json"):
                problems.append("logs_manifest.json differs from the SHA-256 recorded in end.json")
    else:
        reason = ("logs_manifest.json unreadable" if state == "unreadable" else
                  "session schema 1 writes no logs_manifest.json" if schema1 else "no logs_manifest.json")
        row.miss(("evidence_checked", "evidence_hash_mismatches"), reason)
        if state == "unreadable" or isinstance(recorded, str):
            problems.append(reason if state == "unreadable"
                            else "logs_manifest.json is absent although end.json records its SHA-256")
    values = s.audit
    if values is None:
        reason = row.not_applicable.get("windows")
        if reason:
            row.na(("sidecars_differing_from_audit",), reason)
        else:
            row.miss(("sidecars_differing_from_audit",), row.missing.get("windows", "no audit verdict"))
    else:
        sources = values.get("source_sha256") if isinstance(values.get("source_sha256"), dict) else None
        if sources is None:
            row.miss(("sidecars_differing_from_audit",), "the audit has no values.source_sha256")
        elif not s.sidecars_read:
            row.miss(("sidecars_differing_from_audit",), row.missing.get("snapshots_present", "sidecars not read"))
        else:
            audited = {n: sha for n, sha in sources.items() if n.endswith(".json")}
            current = {c["file"]: c["sha256"] for c in s.cycles}
            differing = sorted(n for n in set(audited) | set(current) if audited.get(n) != current.get(n))
            row["sidecars_differing_from_audit"] = len(differing)
            checks.append(f"{len(audited)} sidecars against the audit")
            if differing:
                problems.append(f"{len(differing)} sidecars differ from the audited ones ("
                                + ", ".join(differing[:5]) + (", ..." if len(differing) > 5 else "") + ")")
        if sources is not None and s.archive_files is not None:
            images = {n: sha for n, sha in sources.items() if n.endswith(".vmicd")}
            archived = {n[4:]: dig(item, "sha256") for n, item in s.archive_files.items()
                        if n.startswith("raw/") and n.endswith(".vmicd")}
            differing = sorted(n for n in set(images) | set(archived) if images.get(n) != archived.get(n))
            checks.append(f"{len(archived)} archived images against the audit")
            if differing:
                problems.append(f"{len(differing)} archived images differ from the audited ones ("
                                + ", ".join(differing[:5]) + (", ..." if len(differing) > 5 else "") + ")")
        if row["audit_raw_bytes"] is not None and row["raw_bytes"] is not None and s.sidecars_read:
            checks.append("raw image bytes against the audit")
            if row["audit_raw_bytes"] != row["raw_bytes"]:
                problems.append(f"raw image bytes {row['raw_bytes']} differ from the audit's values.raw_bytes "
                                f"{row['audit_raw_bytes']}")
        if row["traffic_matches_audit"] is not None:
            checks.append("request log summary against the audit")
            if row["traffic_matches_audit"] is False:
                problems.append(f"the request log summary differs from the audit's ({s.traffic_difference})")
        end_sha = dig(values, "logs", "sections", "metadata", "end_sha256")
        if isinstance(end_sha, str) and s.end is not None:
            checks.append("end.json against the audit")
            if end_sha != inputs.sha(s.dir / "end.json"):
                problems.append("end.json differs from the audited one (SHA-256)")
        features, features_sha = values.get("features"), values.get("features_sha256")
        if isinstance(features, str) and isinstance(features_sha, str):
            if Path(features).is_file():
                checks.append("audit features file against the audit")
                if inputs.hash_only(features, "audit_features", s) != features_sha:
                    problems.append("the audit's features file differs from values.features_sha256")
            else:
                s.notes.append(f"the audit's features file {features} is absent (not checked)")
    row["evidence_checks"] = joined(checks) or None
    row["evidence_consistent"] = not problems if (checks or problems) else None
    row["evidence_problems"] = joined(problems) if problems else ("none" if checks else None)
    row.miss(("evidence_checks", "evidence_consistent", "evidence_problems"),
             "no logs_manifest.json and no audit to compare with")
    s.evidence_problems = problems


def audit_reasons(values):
    """values.reasons as a list of strings (a single string counts as one reason)."""
    reasons = values.get("reasons")
    reasons = reasons if isinstance(reasons, list) else [reasons] if reasons else []
    return [clean_text(r) for r in reasons if r]


def running_on(state, sid):
    return bool(state) and state.get("status") == "running" and state.get("session") == sid


def classify(s, state):
    end, row = s.end, s.row
    meta = s.meta
    schema1 = meta.get("schema") == SESSION_SCHEMA_1
    error = clean_text(end["error"]) if end is not None and end.get("error") else None
    signal_error = schema1 and error is not None and SCHEMA1_SIGNAL.fullmatch(error.strip()) is not None
    if end is None and (s.dir / "end.json").exists():
        status, reasons = "incomplete", ["end.json unreadable: the end of the capture cannot be established"]
    elif end is None:
        status, reasons = "incomplete", ["no end.json: the capture recorded no end (crash, SIGKILL, power loss "
                                         "or still running)"]
    elif end.get("interrupted"):
        status, reasons = "interrupted", [error or "interrupted"]
    elif schema1 and "interrupted" not in end and not end.get("completed") and signal_error:
        status, reasons = "interrupted", [error + " (session schema 1 end.json: signal error, no interrupted flag)"]
    elif not end.get("completed"):
        status, reasons = "incomplete", [error or "end.json completed=false"]
    elif s.audit is None:
        status, reasons = "incomplete", ["capture completed; no audit verdict"]
    else:
        status = "accepted" if s.audit["accepted"] else "rejected"
        reasons = audit_reasons(s.audit)
    if end is not None and end.get("completed") and end.get("guest_after") != meta.get("guest_before"):
        reasons.append("guest identity changed during capture (end.json guest_after differs)")
    if status in ("interrupted", "incomplete") and s.audit is not None and not s.audit["accepted"]:
        reasons += ["audit: " + r for r in audit_reasons(s.audit)]
    blockers = [f"campaign provenance: {p}" for p in s.provenance] + \
        [f"evidence: {p}" for p in s.evidence_problems]
    if status == "accepted" and blockers:
        status = "incomplete"
        reasons = ["accepting audit verdict not applied: " + "; ".join(blockers)]
    else:
        reasons += blockers
    undecided = end is None or (end.get("completed") and s.audit is None)
    if status == "incomplete" and undecided and running_on(state, s.sid):
        status = "in_progress"
        reasons = [f"campaign status.json: running, stage {state.get('stage')} (process liveness not checked)"]
    s.status = status
    s.reasons = reasons + s.reasons
    row["status"], row["reasons"] = status, joined(s.reasons) or "none"
    if end is None:
        row.miss(("completed", "interrupted", "end_error", "collector_rc", "traffic_rc", "monitor_rc"), "no end.json")
        return
    row["completed"] = end.get("completed")
    row["interrupted"] = end.get("interrupted")
    if row["interrupted"] is None and schema1:
        if signal_error:
            row["interrupted"] = True
            s.notes.append("interrupted: derived from the schema 1 end.json error 'signal N' (no interrupted flag)")
        elif end.get("completed") is True:
            row["interrupted"] = False
            s.notes.append("interrupted: schema 1 end.json has no flag; false because completed = true")
        elif error:
            row["interrupted"] = False
            s.notes.append("interrupted: schema 1 end.json has no flag; false because its error is not the "
                           "'signal N' error the schema 1 runner wrote for signals")
        else:
            row.miss(("interrupted",), "schema 1 end.json has no interrupted flag, no error and completed = false")
    row.miss(("completed", "interrupted"), "end.json lacks the flag")
    row["end_error"] = error
    row.na(("end_error",), "end.json records no error")
    for name in ("collector", "traffic", "monitor"):
        child = end.get(name) if isinstance(end.get(name), dict) else {}
        rc = end.get(name + "_rc", child.get("rc"))
        field = name + "_rc"
        row[field] = rc if type(rc) is int else None
        if row[field] is not None:
            continue
        if schema1 and name == "monitor":
            row.na((field,), "session schema 1 runs no host monitor")
        elif schema1:
            row.miss((field,), f"session schema 1 end.json records no {name} exit code")
        elif name in end or name + "_rc" in end:
            row.miss((field,), f"end.json {name} record has no integer exit code")
        else:
            # capture_session records every child it started (collection.py, finally block).
            row.na((field,), f"the {name} was not started (end.json has no {name} record)")


def read_session(directory, inputs, ctx=None):
    """All columns of one session directory. Each evidence step fails separately; any other error still
    yields a row (status incomplete, the error as its reason) instead of aborting the whole report."""
    s = Session(directory)
    s.attempted = True
    try:
        read_evidence(s, inputs, ctx or {})
    except Exception as exc:  # noqa: BLE001 - one malformed session must not hide all others
        problem = one_line(f"the report could not read this session ({type(exc).__name__}: {exc})")
        inputs.problem(s.dir, problem, s)
        s.status, s.audit, s.reasons = "incomplete", None, [problem]
        s.row["status"], s.row["reasons"] = s.status, problem
        if s.coverage is None:
            s.coverage = empty_coverage_row(s, problem)
        finish_missing(s, problem)
    return s


def read_evidence(s, inputs, ctx):
    row = s.row
    try:
        meta = inputs.read_json(s.dir / "session.json", "session", s)
    except (OSError, ValueError) as exc:
        problem = f"session.json unreadable or absent ({type(exc).__name__})"
        inputs.problem(s.dir / "session.json", problem, s)
        running = running_on(ctx.get("state"), s.sid)
        s.status = "in_progress" if running else "incomplete"
        s.reasons = [f"campaign status.json: running, stage {ctx['state'].get('stage')} (process liveness not "
                     f"checked); {problem}" if running else f"{problem}: capture failed before its metadata"]
        row["status"], row["reasons"] = s.status, joined(s.reasons)
        fill_plan_identity(s, ctx.get("plan_row"))
        set_gate(s, ctx.get("protocol"))
        s.protocol = ctx.get("protocol")
        protocol_ideal(s, "protocol arithmetic (no audit)")
        s.coverage = empty_coverage_row(s, problem)
        finish_missing(s, problem)
        return
    s.meta = meta
    schema1 = meta.get("schema") == SESSION_SCHEMA_1
    guest = meta.get("guest_before") if isinstance(meta.get("guest_before"), dict) else {}
    settings = meta.get("collector_settings") if isinstance(meta.get("collector_settings"), dict) else {}
    row.update(campaign_id=meta.get("campaign_id"), role=meta.get("role"), group=meta.get("group"),
               vm=meta.get("vm"), replaces=meta.get("replaces"), replaced_by=(ctx.get("plan_row") or {}).get("replaced_by"),
               group_attempt=meta.get("group_attempt"), scenario=meta.get("scenario"), seed=meta.get("seed"),
               boot_id=guest.get("boot_id"), session_schema=meta.get("schema"),
               hash_async_setting=settings.get("hash_async"), fsync_setting=settings.get("fsync"),
               mlock_setting=settings.get("mlock"))
    if settings.get("writer_thread"):
        row.na(("hash_async_setting",), "collector writer thread hashes every snapshot before publishing "
                                       "(no output.hash_async)")
    elif settings:
        row.na(("mlock_setting",), "collector predates the writer thread and output.mlock")
    row.miss(("hash_async_setting", "fsync_setting", "mlock_setting"),
             "session schema 1 records no collector_settings" if schema1 else
             "session.json collector_settings has no such flag (session predates the setting)")
    row.na(("campaign_id",), "not a campaign session (session.json campaign_id is null)")
    row.na(("vm",), "single-VM protocol (session.json names no vm)")
    row.na(("replaces",), "not a replacement of an audit-rejected session")
    row.na(("replaced_by",), "no rejection record names a replacement for this session")
    if schema1:
        row.na(("group_attempt",), "session schema 1 has no group attempts")
    else:
        row.miss(("group_attempt",), "session.json has no group_attempt")
    if meta.get("session_id") not in (None, s.sid):
        s.provenance.append(f"session.json session_id {meta.get('session_id')!r} differs from the directory name")
    plan_row = ctx.get("plan_row")
    s.protocol = read_optional(s, inputs, "protocol.json", "protocol")[0] or ctx.get("protocol")
    if not (s.dir / "protocol.json").exists() and ctx.get("protocol"):
        s.notes.append("protocol: campaign protocol.json (no session copy)")
    set_gate(s, s.protocol)
    s.end, end_state = read_optional(s, inputs, "end.json", "end")
    created, written = timestamp(meta.get("created_unix")), timestamp((s.end or {}).get("written_unix"))
    s.times.update(created=created, end=written)
    row["session_created_utc"], row["session_end_written_utc"] = utc(created), utc(written)
    if created is not None and written is not None:
        row["session_wall_s"] = r6(written - created)
    if s.end is not None and s.end.get("written_unix") is not None and written is None:
        row.miss(("session_end_written_utc", "session_wall_s"), "end.json written_unix is not a representable time")
    row.miss(("session_end_written_utc", "session_wall_s"),
             ("no end.json" if end_state == "absent" else "end.json unreadable") if s.end is None
             else "session schema 1 end.json has no written_unix" if schema1 else "end.json has no written_unix")
    row.miss(("session_created_utc", "session_wall_s"),
             "session.json created_unix is not a representable time" if meta.get("created_unix") is not None
             else "session.json has no created_unix")
    expected, source = expected_snapshots(meta, s.protocol, plan_row)
    row["snapshots_expected"], row["snapshots_expected_source"] = expected, source
    if expected is None:
        row.miss(("snapshots_expected", "snapshots_expected_source", "snapshots_missing"),
                 "no assigned cycle count in session.json, protocol or plan")
    protocol = s.protocol or {}
    period = number(protocol.get("interval_s")) or number(settings.get("interval_s"))
    period_ms = period * 1000 if period else None
    guarded(s, "snapshot sidecars", CAPTURE_FIELDS + COLLECTOR_LOG_FIELDS, capture_step, inputs, period_ms)
    present = row["snapshots_present"]
    if expected is not None and present is not None:
        row["snapshots_missing"] = expected - present
    if present is not None and period:
        row["capture_slot_s"] = r6(present * period)
    elif present is not None:
        row.miss(("capture_slot_s",), "protocol period unknown")
    for field in ("snapshots_missing", "capture_slot_s"):
        if "snapshots_present" in row.not_applicable:
            row.na((field,), row.not_applicable["snapshots_present"])
        row.miss((field,), row.missing.get("snapshots_present", "snapshot count unknown"))
    guarded(s, "request/interval logs", TRAFFIC_FIELDS, traffic_step, inputs)
    guarded(s, "host monitor", MONITOR_FIELDS, monitor_step, inputs)
    guarded(s, "guest clock", ("clock_offset_before_s", "clock_offset_after_s"), clock_step, inputs)
    guarded(s, "audit", AUDIT_FIELDS + ("audit_candidates",), audit_step, inputs, ctx.get("pointer"))
    if s.coverage is None:  # the audit step failed: no verdict is used, and the reason is part of the status
        problem = row.missing.get("windows", "audit unreadable")
        s.reasons.append(problem)
        s.audit = s.audit_doc = None
        s.tolerated, s.tolerated_source = None, NOT_RECORDED
        s.coverage = empty_coverage_row(s, problem)
    if ctx.get("manifest") is not None:
        guarded(s, "campaign provenance", ("provenance_problems",), campaign_step, ctx)
        if "provenance_problems" in row.missing:  # the checks could not run: fail closed
            s.provenance.append(row.missing["provenance_problems"])
    guarded(s, "archive", ARCHIVE_FIELDS + ("archived",), archive_step, inputs, ctx.get("archive_fallback"))
    if s.compressed_images and row["raw_bytes"] is None:
        row.miss(("raw_bytes", "raw_bytes_source"),
                 "the images are compressed members and no archive manifest gives their original sizes")
    guarded(s, "superseded marker", ("superseded", "superseded_reason"), superseded_step, inputs)
    if ctx.get("done") is not None:
        row["campaign_done"] = ctx["done"].exists()
        if row["campaign_done"]:
            try:
                inputs.read_json(ctx["done"], "campaign_checkpoint", s)
            except (OSError, ValueError) as exc:
                s.notes.append(clean_text(f"campaign checkpoint unreadable: {exc}"))
                inputs.problem(ctx["done"], f"campaign checkpoint unreadable: {exc}", s)
    else:
        row.na(("campaign_done",), "sessions mode: no campaign checkpoints")
    guarded(s, "evidence consistency", EVIDENCE_FIELDS, evidence_step, inputs)
    if row["evidence_consistent"] is None and s.audit is not None:  # the checks could not run: fail closed
        s.evidence_problems.append(row.missing.get("evidence_consistent", "evidence checks did not run"))
    if "provenance_problems" not in row.missing:
        row["provenance_problems"] = joined(s.provenance) or "none"
    classify(s, ctx.get("state"))
    if row["campaign_done"] and s.status != "accepted":
        s.notes.append("the campaign checkpoint (attempts/<session>.done.json) exists, but the report does not "
                       "find the session accepted now (see reasons)")
    finish_missing(s, None)


def fill_plan_identity(s, plan_row):
    if not plan_row:
        return
    for key in ("role", "group", "scenario", "seed", "vm", "replaces", "replaced_by"):
        if s.row.get(key) is None:
            s.row[key] = plan_row.get(key)
    if s.row["snapshots_expected"] is None and integer(plan_row.get("cycles")) is not None:
        s.row["snapshots_expected"], s.row["snapshots_expected_source"] = plan_row["cycles"], "campaign plan cycles"


NO_REASON_COLUMNS = ("missing", "not_applicable", "notes", "sources", "index", "plot_label")


def finish_missing(s, reason):
    """Every empty column gets a reason (missing or not applicable); notes become a column."""
    row = s.row
    row.missing = {f: r for f, r in row.missing.items() if row.get(f) is None}
    row.not_applicable = {f: r for f, r in row.not_applicable.items() if row.get(f) is None}
    for field in row.not_applicable:
        row.missing.pop(field, None)
    for column in SESSION_COLUMNS:
        if column in NO_REASON_COLUMNS or row[column] is not None or column in row.not_applicable:
            continue
        row.missing.setdefault(column, reason or "not recorded in the session evidence")
    row["notes"] = joined(s.notes) if s.notes else None
    row["missing"] = group_missing(row.missing)
    row["not_applicable"] = group_missing(row.not_applicable)


def group_missing(missing):
    groups = defaultdict(list)
    for field, reason in missing.items():
        groups[reason].append(field)
    return joined(f"{reason}: {', '.join(fields)}" for reason, fields in sorted(groups.items())) or None


def planned_session(sid, directory, plan_row, state, protocol=None):
    s = Session(directory, sid)
    fill_plan_identity(s, plan_row)
    running = running_on(state, sid)
    s.status = "in_progress" if running else "planned"
    s.reasons = ([f"campaign status.json: running, stage {state.get('stage')} (process liveness not checked); "
                  "no session directory yet"] if running else ["not started"])
    s.row["status"], s.row["reasons"] = s.status, joined(s.reasons)
    s.row["session_dir"] = None
    s.protocol = protocol
    set_gate(s, protocol)
    protocol_ideal(s, "protocol arithmetic (not started)")
    reason = "session directory not created yet" if running else "session not started"
    s.coverage = empty_coverage_row(s, reason)
    for column in SESSION_COLUMNS:
        if column not in NO_REASON_COLUMNS and s.row[column] is None:
            s.row.na((column,), reason)
    finish_missing(s, reason)
    return s


def session_sources(s, inputs):
    """Compact column: own files by relative name, sidecars as one digest of their sorted listing."""
    parts, sidecars = [], []
    for record in inputs.for_session(s):
        if record["kind"] == "sidecar":
            sidecars.append(f"{Path(record['path']).name} {record['sha256']}")
            continue
        try:
            name = Path(record["path"]).relative_to(s.dir.absolute()).as_posix()
        except ValueError:
            name = record["path"]
        parts.append(f"{name}={record['sha256']}")
    if sidecars:
        listing = hashlib.sha256("\n".join(sorted(sidecars)).encode()).hexdigest()
        parts.append(f"raw sidecars ({len(sidecars)} files, sha256 of 'name sha256' lines)={listing}")
    return joined(parts) or None


# ---------------------------------------------------------------- campaign

def read_events(directory, inputs):
    """Campaign events and, separately, the operator stop requests stored next to them."""
    events, requests = [], []
    for path in sorted((directory / "events").glob("*.json")):
        request = STOP_REQUEST.fullmatch(path.name)
        if request:
            stale = request["stale"] is not None
            try:
                doc = inputs.read_json(path, "campaign_stop_request", None)
            except (OSError, ValueError) as exc:
                inputs.problem(path, f"stop request unreadable: {exc}")
                doc = {}
            requests.append({"file": path.name, "requested_utc": doc.get("date") if isinstance(doc.get("date"), str)
                             else None, "honored": not stale, **({"vm": request["vm"]} if request["vm"] else {}),
                             "note": ("set aside when a later run started (meant for an earlier run)" if stale
                                      else "honored: the runner stopped before its next capture")})
            continue
        try:
            doc = inputs.read_json(path, "campaign_event", None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"campaign event unreadable: {exc}")
            continue
        events.append({"file": path.name, "time": unix_of(doc.get("updated_at")), "vm": doc.get("vm"),
                       "status": doc.get("status"),
                       "stage": doc.get("stage"), "session": doc.get("session"), "group": doc.get("group"),
                       "position": doc.get("position"),
                       "message": clean_text(doc["message"]) if doc.get("message") else None})
        if events[-1]["time"] is None:
            inputs.problem(path, "campaign event without a parseable updated_at")
    events.sort(key=lambda e: (e["time"] if e["time"] is not None else math.inf, e["file"]))
    return events, requests


def stage_category(event):
    status, stage = event.get("status"), event.get("stage")
    if status == "stopped":
        return "stopped"
    # Package B9b (scripts/campaign.py): a campaign paused for review when its limit of replacements is exhausted,
    # and one that became invalid; neither runs until its continuation or never (DEFINITIONS["ending"]).
    if status in ("paused", "invalid"):
        return status
    if status == "ready":
        return "before_first_launch"
    if status == "complete":
        return "after_complete"
    if status == "closed":
        return "after_close"
    # Package B9a (scripts/campaign.py, protocol schema 3): group-start (labctl stop, start, reset and pretouch of a
    # group), seal (the ledger write of an accepted session of a sealed role) and rejected (a rejection not replaced).
    return {"preflight": "preflight", "session-preflight": "preflight", "reboot": "reboot",
            "capture": "capture_stage", "audit": "audit", "archive": "archive",
            "session-complete": "between_sessions", "index": "index", "replacement": "between_sessions",
            "audit-wait": "audit_wait", "role-wait": "role_wait", "group-start": "group_start", "seal": "seal",
            "rejected": "between_sessions", "retry": "retry_pause"}.get(stage, f"other:{stage}")


def campaign_time(events):
    timed = [e for e in events if e["time"] is not None]
    by_category, intervals = Counter(), []
    runners = sorted({e.get("vm") for e in timed}, key=str)
    for vm in runners:  # One event stream per runner (DEFINITIONS["multi_vm"]); a single runner has vm None.
        own = [e for e in timed if e.get("vm") == vm]
        for first, second in zip(own, own[1:]):
            category = ("unaccounted" if second["status"] == "stopped" and second["stage"] == "unclean-end"
                        else stage_category(first))
            duration = second["time"] - first["time"]
            first["duration_to_next_s"], first["attributed_to"] = r6(duration), category
            by_category[category] += duration
            intervals.append((first["time"], second["time"], category))
    intervals.sort()
    if not timed:
        return None, intervals
    span = timed[-1]["time"] - timed[0]["time"]
    doc = {"events": len(events), "events_with_time": len(timed), "first_event_utc": utc(timed[0]["time"]),
           "last_event_utc": utc(timed[-1]["time"]), "last_status": timed[-1]["status"],
           "last_stage": timed[-1]["stage"], "wall_clock_span_s": r6(span), "wall_clock_span_h": r6(span / 3600),
           "by_category_s": {k: r6(v) for k, v in sorted(by_category.items())},
           "sum_of_categories_s": r6(math.fsum(by_category.values())),
           **({"runners": runners, "runners_note": DEFINITIONS["multi_vm"]} if runners != [None] else {}),
           "note": ("Runner stage time from campaign events. capture_stage covers the runner's capture child "
                    "(guest preflight, warmup, capture and guest evidence transfer); measured capture hours "
                    "are reported only under capture_time.")}
    return doc, intervals


def plan_rows(manifest):
    """campaign.json sessions, validated: a malformed or repeated session_id is a data error (campaign.py
    load_campaign refuses such a plan, so no session can have run under it)."""
    rows = manifest.get("sessions")
    if manifest.get("schema") != "hyptcn3/collection-campaign/1" or not isinstance(rows, list):
        raise DataError("campaign.json is not a hyptcn3/collection-campaign/1 document with sessions")
    for position, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise DataError(f"campaign.json plan row {position} is not an object")
        sid = row.get("session_id")
        if not isinstance(sid, str) or not SAFE_ID.fullmatch(sid):
            raise DataError(f"campaign.json plan row {position} has no usable session_id: {sid!r}")
    repeated = sorted(sid for sid, n in Counter(r["session_id"] for r in rows).items() if n > 1)
    if repeated:
        raise DataError("campaign.json repeats session IDs: " + ", ".join(repeated))
    return rows


def session_base(collections, manifest, row):
    """campaign.session_dir: <collections>/<session>, or <collections>/<campaign>/<vm>/<session> per VM."""
    return collections / str(manifest.get("id")) / row["vm"] if isinstance(row.get("vm"), str) else collections


def read_rejections(directory, inputs):
    """attempts/<session>.rejected.json records of campaign.reject, by session ID."""
    records = {}
    for path in sorted((directory / "attempts").glob("*.rejected.json")):
        try:
            doc = inputs.read_json(path, "campaign_rejection", None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"rejection record unreadable: {exc}")
            continue
        if isinstance(doc, dict) and doc.get("schema") == REJECTION_SCHEMA:
            records[path.name[:-len(".rejected.json")]] = doc
        else:
            inputs.problem(path, "not a campaign rejection record")
    return records


# campaign.CAMPAIGN_KEYS: the keys a campaign adds to a row of its plan (session ID, the chain of replacements).
CAMPAIGN_KEYS = ("session_id", "replaces", "plan_session", "replacement")


def with_replacements(rows, rejected, problems, protocol=None, mode=None):
    """Plan rows, each followed by the replacements of its audit-rejected sessions (campaign.chain), each as the
    assignment its capture ran (campaign.attempt_row, REPLACEMENT_RULE): under protocol schema 3 (`protocol`, the
    campaign's protocol.json, and `mode`, its plan mode) replacement n is attempt n + 1 of its planned row, drawn by
    protocol_v5.replacement with its own seed, phases and traffic seeds; under schemas 1 and 2 the planned row (the
    same assignment and seed)."""
    v5 = isinstance(protocol, dict) and protocol.get("schema") == protocol_v5.SCHEMA
    out = []
    for row in rows:
        current = row
        for number in range(1, 1000):
            record = rejected.get(current["session_id"])
            replacement = record.get("replacement") if record else None
            if replacement is not None and replacement != f"{row['session_id']}-r{number}":
                problems.append(f"attempts/{current['session_id']}.rejected.json names replacement {replacement!r}, "
                                f"not the plan's {row['session_id']}-r{number}; it is not followed")
                replacement = None
            out.append({**current, "replaced_by": replacement} if replacement else current)
            if replacement is None:
                break
            current = {**row, "session_id": replacement, "replaces": current["session_id"]}
            if v5:
                current = v5_attempt(protocol, mode, row, current, number, problems)
    return out


def v5_attempt(protocol, mode, planned, current, number, problems):
    """campaign.attempt_row of replacement `number` of the planned row `planned` under protocol schema 3: attempt
    number + 1, protocol_v5.replacement in the campaign's mode, with the campaign's keys. A draw protocol_v5 refuses
    is a problem (campaign.py could not have captured it), and the row stays `current`."""
    base = {key: value for key, value in planned.items() if key not in CAMPAIGN_KEYS}
    try:
        drawn = protocol_v5.replacement(protocol, base, number + 1, mode=mode)
    except ValueError as error:
        problems.append(f"replacement {current['session_id']}: protocol_v5.replacement refuses attempt {number + 1} "
                        f"of {planned['session_id']} ({error}); it is compared with its planned row")
        return current
    return {**drawn, "session_id": current["session_id"], "replaces": current["replaces"],
            "plan_session": planned["session_id"], "replacement": number}


# The values of an ending record the report lists (design B9b 1.1), beside its ending, cause and stage.
ENDING_VALUES = ("mode", "planned_sessions", "accepted_sessions", "rejections_by_cause", "limit",
                 "replacements_used", "continues")


def read_endings(results, campaign_id, inputs, failures=None):
    """The ending records of the campaign in the results directory (DEFINITIONS["ending"]), in the order of their date:
    ([{file, path, sha256, date, ending, cause, stage, rejected_sessions (their count), deviations, and the values of
    ENDING_VALUES as recorded}], problems, why none was read: null when the directory was searched). failures, a
    dict: filled with {file: values.group_start_failures as recorded} (DEFINITIONS["group_start_failures"])."""
    if not isinstance(campaign_id, str) or not SAFE_ID.fullmatch(campaign_id):
        return [], [], "campaign.json names no usable campaign id, so its ending records cannot be found"
    if not results.is_dir():
        return [], [], f"the results directory {results} is absent"
    found, problems = [], []
    for path in sorted(results.glob(ENDING_NAME.format(id=campaign_id))):
        try:
            doc = inputs.read_json(path, "campaign_ending", None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"ending record unreadable: {exc}")
            continue
        values = doc.get("values")
        if doc.get("schema") != ENDING_SCHEMA or not isinstance(values, dict):
            problems.append(f"{path.name} in {results} is not a campaign ending record ({ENDING_SCHEMA})")
            continue
        if values.get("campaign") != campaign_id:
            continue  # The record of another campaign whose ID begins with this one's and an underscore.
        rejected = values.get("rejected_sessions")
        if failures is not None:
            failures[path.name] = values.get("group_start_failures")
        # The stage beside the provenance (as tcn.eval writes it), else in values, there also as tcn.pecat
        # record_stage gives it ({stage, basis}).
        stage = doc["stage"] if "stage" in doc else values.get("stage")
        found.append({"file": path.name, "path": str(path), "sha256": inputs.sha(path),
                      "date": doc.get("date") if isinstance(doc.get("date"), str) else None,
                      "ending": values.get("ending"), "cause": values.get("cause"),
                      "stage": stage.get("stage") if isinstance(stage, dict) else stage,
                      **{key: values.get(key) for key in ENDING_VALUES},
                      "rejected_sessions": len(rejected) if isinstance(rejected, list) else None,
                      "deviations": values.get("deviations")})
    found.sort(key=lambda e: (e["date"] or "", e["file"]))
    return found, problems, None


def group_start_failures(endings, recorded, started, files):
    """DEFINITIONS["group_start_failures"]: {definition, source, total, groups, groups_started_again, by_group: {group:
    [{vm, step, date, cause, reason, started_again, record}]}}, the groups in the order of their first failure.
    endings: read_endings' records by date; recorded: their values.group_start_failures by file; started: the groups
    whose record groups/<group>.json exists; files: (name, document) of groups/*.start-failed-*.json."""
    listed = next(((e["file"], recorded.get(e["file"])) for e in reversed(endings)
                   if isinstance(recorded.get(e["file"]), list)), None)
    if listed is not None:
        source = f"values.group_start_failures of the ending record {listed[0]}"
        items = [{"record": f.get("record"), "date": f.get("date"), "group": f.get("group"), "vm": f.get("vm"),
                  "step": f.get("step"), "cause": "group_start", "reason": f.get("reason"),
                  "started_again": f.get("started_again") is True or f.get("group") in started}
                 for f in listed[1] if isinstance(f, dict)]
    else:
        source = "groups/<group>.start-failed-<UTC>.json (no ending record of the campaign lists them)"
        items = [{"record": name, "date": doc.get("date"), "group": doc.get("group"), "vm": doc.get("vm"),
                  "step": doc.get("step"), "cause": doc.get("cause"), "reason": doc.get("reason"),
                  "started_again": doc.get("group") in started} for name, doc in files]
    by_group = {}
    for item in sorted(items, key=lambda x: (str(x["date"]), str(x["record"]))):
        by_group.setdefault(str(item["group"]), []).append({key: item[key] for key in (
            "vm", "step", "date", "cause", "reason", "started_again", "record")})
    return {"definition": DEFINITIONS["group_start_failures"], "source": source, "total": len(items),
            "groups": len(by_group),
            "groups_started_again": sum(any(x["started_again"] for x in found) for found in by_group.values()),
            "by_group": by_group}


def limit_of(manifest, protocol):
    """The limit of replacements the campaign applies (DEFINITIONS["limit"], scripts/campaign.py replacement_limit):
    {applied, max_per_campaign, mode, definition}; applied null with the reason when protocol.json is unreadable."""
    mode = manifest.get("mode")
    doc = {"mode": mode, "definition": DEFINITIONS["limit"]}
    if mode == "rehearsal":
        return dict(doc, applied=False, max_per_campaign=None)
    if not isinstance(protocol, dict):
        return dict(doc, applied=None, max_per_campaign=None,
                    missing="protocol.json unreadable: the limit of replacements is not known")
    rule = protocol.get("replacement")
    return dict(doc, applied=True, max_per_campaign=rule.get("max_per_campaign", 0) if isinstance(rule, dict) else 0)


def build_campaign(directory, collections, inputs, results=None):
    directory = directory.absolute()
    try:
        manifest = inputs.read_json(directory / "campaign.json", "campaign", None)
    except (OSError, ValueError) as exc:
        raise DataError(f"cannot read campaign.json in {directory}: {exc}") from exc
    rows = plan_rows(manifest)
    collections = (collections or directory.parent.parent / "collections").absolute()
    results = (results or directory.parent.parent / "results").absolute()  # DEFINITIONS["ending"]
    if not collections.is_dir():
        raise DataError(f"collections directory {collections} does not exist; pass the session base directory "
                        "with --collections-dir (every plan row would otherwise look not started)")
    problems = []

    def optional(name, kind):
        path = directory / name
        if not path.exists():
            problems.append(f"{name} absent")
            return None
        try:
            return inputs.read_json(path, kind, None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"unreadable: {exc}")
            return None

    protocol = optional("protocol.json", "campaign_protocol")
    if protocol is not None and inputs.sha(directory / "protocol.json") != manifest.get("protocol_sha256"):
        problems.append("protocol.json sha256 differs from campaign.json protocol_sha256")
    plan = optional("plan.json", "campaign_plan")
    if plan is not None:
        # campaign.py init writes the same row objects (with session_id) to plan.json and campaign.json.
        def strip(items):
            return [{k: v for k, v in r.items() if k != "session_id"} if isinstance(r, dict) else r
                    for r in items or []]
        theirs = plan.get("sessions")
        if not isinstance(theirs, list) or strip(theirs) != strip(rows) or (
                all(isinstance(r, dict) and "session_id" in r for r in theirs) and theirs != rows):
            problems.append("plan.json sessions differ from campaign.json sessions")
    # One runner and status file per VM of a multi-VM campaign (DEFINITIONS["multi_vm"]).
    vms = manifest["vms"] if isinstance(manifest.get("vms"), dict) and manifest["vms"] else None
    for key in ("guest_environment", "extractor_sha256"):  # The guest environment is per VM there.
        if key not in manifest and not (vms and all(isinstance(v, dict) and key in v for v in vms.values())):
            problems.append(f"campaign.json has no {key}: that campaign provenance check is skipped")
    states = {vm: optional("status.json" if vm is None else f"status-{vm}.json", "campaign_status")
              for vm in (vms or [None])}
    rejected = read_rejections(directory, inputs)
    planned_rows, rows = rows, with_replacements(rows, rejected, problems, protocol=protocol,
                                                 mode=manifest.get("mode"))
    events, stop_requests = read_events(directory, inputs)
    closed = None
    if (directory / "closed.json").exists():
        try:
            doc = inputs.read_json(directory / "closed.json", "campaign_closed", None)
            closed = {"date": doc.get("date") if isinstance(doc.get("date"), str) else None,
                      "reason": one_line(doc["reason"]) if isinstance(doc.get("reason"), str) else None}
        except (OSError, ValueError) as exc:
            inputs.problem(directory / "closed.json", f"unreadable: {exc}")
            problems.append("closed.json exists but cannot be read")
    groups, group_docs, start_failed = [], {}, []
    for path in sorted((directory / "groups").glob("*.json")):
        try:
            doc = inputs.read_json(path, "campaign_group", None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"campaign group record unreadable: {exc}")
            continue
        if doc.get("schema") == START_FAILURE_SCHEMA:  # DEFINITIONS["group_start_failures"] (Q22).
            start_failed.append((path.name, doc))
        if doc.get("schema") == "hyptcn3/campaign-group/1":
            group_docs[doc.get("group")] = doc
            groups.append({"group": doc.get("group"), "role": doc.get("role"), "date": doc.get("date"),
                           **({"vm": doc["vm"]} if doc.get("vm") else {}),
                           "boot_id": dig(doc, "identity", "boot_id"),
                           "previous_boot": doc.get("previous_boot"), "file": path.name})
    archive_dir = Path(manifest["archive_dir"]) if isinstance(manifest.get("archive_dir"), str) else None
    sessions, dirs = [], {}
    for position, plan_row in enumerate(rows, 1):
        sid, vm = plan_row["session_id"], plan_row.get("vm")
        state = states.get(vm)
        path = dirs[sid] = session_base(collections, manifest, plan_row) / sid
        if path.is_dir():
            # Pilot, guest environment and estimates of a multi-VM campaign are recorded per VM.
            view = {**manifest, **vms[vm]} if vms and isinstance(vms.get(vm), dict) else manifest
            ctx = {"manifest": view, "plan_row": plan_row, "protocol": protocol, "state": state,
                   "groups": group_docs, "pointer": directory / "attempts" / f"{sid}.audit.json",
                   "done": directory / "attempts" / f"{sid}.done.json",
                   "archive_fallback": archive_dir / "collections" / (vm or "") / sid if archive_dir else None}
            s = read_session(path, inputs, ctx)
        else:
            s = planned_session(sid, path, plan_row, state, protocol)
        s.index = position
        sessions.append(s)
    problems += attempt_problems(directory, dirs, rows, states, sessions)
    bases = sorted({session_base(collections, manifest, row) for row in rows})
    retired, retired_problems = retired_attempts(directory, bases, rows, inputs)
    problems += retired_problems
    rejections = [{"session": sid, "vm": doc.get("vm"), "role": doc.get("role"), "group": doc.get("group"),
                   "scenario": doc.get("scenario"), "date": doc.get("date") if isinstance(doc.get("date"), str) else None,
                   "cause": doc.get("cause", "audit_rejected"),  # records before the cause code: audit only
                   "reasons": audit_reasons(doc), "replacement": doc.get("replacement"),
                   "not_replaced": doc.get("not_replaced"),
                   "max_per_campaign": doc.get("max_per_campaign")}
                  for sid, doc in sorted(rejected.items(), key=lambda item: (str(item[1].get("date")), item[0]))]
    problems += [f"attempts/{r['session']}.rejected.json names a session that is not in the plan"
                 for r in rejections if r["session"] not in dirs]
    state = states[None] if vms is None else {"vms": states}
    # Package B9b: the state of every runner with the records of the campaign's endings (DEFINITIONS["ending"]).
    recorded = {}
    endings, ending_problems, endings_missing = read_endings(results, manifest.get("id"), inputs, failures=recorded)
    problems += ending_problems
    starts = group_start_failures(endings, recorded, set(group_docs), start_failed)
    runners = [{"vm": vm, **{key: (doc or {}).get(key) for key in ("status", "stage", "message")}}
               for vm, doc in states.items()]
    problems += [f"{'status.json' if r['vm'] is None else 'status-' + r['vm'] + '.json'} says {r['status']}, but "
                 f"{results} holds no ending record of the campaign ({ENDING_NAME.format(id=manifest.get('id'))})"
                 for r in runners if r["status"] in RECORDED_STATES and not endings and "mode" in manifest]
    time_doc, intervals = campaign_time(events)
    campaign = {"id": manifest.get("id"), "directory": str(directory), "collections_dir": str(collections),
                "archive_dir": manifest.get("archive_dir"), "commit": manifest.get("commit"),
                "protocol_sha256": manifest.get("protocol_sha256"),
                "planned_capture_hours": manifest.get("planned_capture_hours"),
                "planned_capture_hours_source": "campaign.json planned_capture_hours (design allocation)",
                "status": state, "closed": closed, "stop_requests": stop_requests,
                "stop_request_pending": any(directory.glob("stop-request*.json")),
                "vms": list(vms) if vms else None,
                "replacement_rule": protocol.get("replacement") if isinstance(protocol, dict) else None,
                "limit": limit_of(manifest, protocol),
                "rejections": rejections, "rejections_definition": DEFINITIONS["replacement"],
                # The count by cause the runner keeps in its state (package B9a, scripts/campaign.py LIMIT_RULE).
                "rejections_by_cause": dict(sorted(Counter(r["cause"] for r in rejections).items())),
                # Package B9b, Q22: apart from the rejections, since a failed start of a group rejects no session.
                "group_start_failures": starts,
                "runners": runners, "results_dir": str(results), "endings": endings,
                "endings_missing": endings_missing, "endings_definition": DEFINITIONS["ending"],
                "groups": groups, "problems": problems}
    return {"mode": "campaign", "campaign": campaign, "sessions": sessions, "events": events,
            "campaign_time": time_doc, "stage_intervals": intervals, "protocol": protocol,
            "plan_rows": planned_rows, "retired_attempts": retired}


def attempt_problems(directory, dirs, rows, states, sessions):
    """Campaign records that name sessions whose directory is absent (a moved or lost session).

    dirs: session directory of every plan row and replacement; states: runner status per VM
    (the key None is the single runner of a single-VM campaign).
    """
    problems = []
    for path in sorted((directory / "attempts").glob("*.json")):
        if ATTEMPT_RECORD.fullmatch(path.name):
            continue  # retired_attempts()
        suffix = next((x for x in (".done.json", ".audit.json", ".rejected.json") if path.name.endswith(x)), None)
        sid = path.name[:-len(suffix)] if suffix else None
        if sid is None:
            problems.append(f"attempts/{path.name}: not a .done.json, .audit.json or .rejected.json record")
        elif sid not in dirs:
            problems.append(f"attempts/{path.name} names a session that is not in the plan")
        elif not dirs[sid].is_dir():
            problems.append(f"attempts/{path.name} exists, but the session directory {dirs[sid]} is absent")
    for vm, state in states.items():
        if not isinstance(state, dict):
            continue
        name = "status.json" if vm is None else f"status-{vm}.json"
        named = state.get("session")
        if (isinstance(named, str) and named and not (named in dirs and dirs[named].is_dir())
                and not running_on(state, named)):
            problems.append(f"{name} (status {state.get('status')}) names session {named}, whose directory "
                            "is absent")
        archived = state.get("accepted_archived")
        done = sum(1 for s, row in zip(sessions, rows) if row.get("vm") == vm and s.row["campaign_done"] is True)
        if type(archived) is int and archived != done:
            problems.append(f"{name} accepted_archived = {archived}, but {done} session directories have a "
                            "done checkpoint")
    return problems


def retired_entry(path, sid, number, inputs, record=None):
    """One attempt renamed by campaign.retire_attempt, read only to show that it holds no RAM data."""
    entry = {"session_id": sid, "attempt": number, "directory": str(path) if path is not None else None,
             "record": record["file"] if record else None,
             "reason": one_line(record["reason"]) if record and isinstance(record.get("reason"), str) else None,
             "date": record.get("date") if record and isinstance(record.get("date"), str) else None,
             "measurement_started": None, "raw_present": None, "problems": []}
    if path is None:
        return entry
    entry["raw_present"] = (path / "raw").exists() or (path / "raw").is_symlink()
    if (path / "session.json").is_file():
        try:
            meta = inputs.read_json(path / "session.json", "retired_attempt_session", None)
            if meta.get("session_id") != sid:
                entry["problems"].append(f"session.json session_id {meta.get('session_id')!r} differs from the "
                                         "directory name")
        except (OSError, ValueError) as exc:
            inputs.problem(path / "session.json", f"retired attempt session.json unreadable: {exc}")
    if (path / "end.json").is_file():
        try:
            end = inputs.read_json(path / "end.json", "retired_attempt_end", None)
            entry["measurement_started"] = end.get("measurement_started")
            if entry["reason"] is None and isinstance(end.get("error"), str):
                entry["reason"] = one_line(end["error"])
        except (OSError, ValueError) as exc:
            inputs.problem(path / "end.json", f"retired attempt end.json unreadable: {exc}")
    if entry["raw_present"] or entry["measurement_started"] is True:
        entry["problems"].append("holds raw/ or a measured phase; campaign.py retires only attempts without either")
    return entry


def retired_attempts(directory, bases, rows, inputs):
    """Campaign attempts that ended before measurement: attempts/ records and renamed directories."""
    planned = {row["session_id"] for row in rows}
    records, dirs = {}, {}
    for path in sorted((directory / "attempts").glob("*.json")):
        m = ATTEMPT_RECORD.fullmatch(path.name)
        if not m:
            continue
        try:
            records[(m["sid"], int(m["n"]))] = {**inputs.read_json(path, "campaign_attempt", None), "file": path.name}
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"attempt record unreadable: {exc}")
    for path in sorted(p for base in bases if base.is_dir() for p in base.iterdir()):
        m = RETIRED_DIR.fullmatch(path.name)
        if m and m["sid"] in planned and path.is_dir():
            dirs[(m["sid"], int(m["n"]))] = path
    entries, problems = [], []
    for key in sorted(set(records) | set(dirs)):
        record, path = records.get(key), dirs.get(key)
        entry = retired_entry(path, key[0], key[1], inputs, record)
        if key[0] not in planned:
            entry["problems"].append("names a session that is not in the plan")
        if record is None:
            entry["problems"].append("directory without an attempts/ record")
        elif path is None:
            entry["problems"].append(f"attempts/{record['file']} exists, but its directory is absent")
        elif record.get("directory") != str(path):
            entry["problems"].append(f"attempts/{record['file']} names another directory: {record.get('directory')}")
        problems += [f"retired attempt {key[0]}.attempt-{key[1]}: {p}" for p in entry["problems"]]
        entries.append(entry)
    return entries, problems


def build_sessions(directories, inputs):
    sessions, seen, retired = [], set(), []
    for directory in directories:
        directory = Path(directory).absolute()
        if not directory.is_dir():
            inputs.problem(directory, "not a directory")
            continue
        m = RETIRED_DIR.fullmatch(directory.name)
        if m:  # Not a session: an attempt retired before its measured phase (campaign.retire_attempt).
            retired.append(retired_entry(directory, m["sid"], int(m["n"]), inputs))
            continue
        if not (directory / "session.json").is_file():
            inputs.problem(directory, "no session.json (not a collection session directory)")
            continue
        real = directory.resolve()
        if real in seen:
            inputs.problem(directory, "the same session directory was given twice; counted once")
            continue
        seen.add(real)
        sessions.append(read_session(directory, inputs))
    holders = defaultdict(set)
    for s in sessions:
        holders[s.sid].add(str(s.dir))
        if isinstance(s.meta.get("session_id"), str):
            holders[s.meta["session_id"]].add(str(s.dir))
    copies = {sid: sorted(dirs) for sid, dirs in sorted(holders.items()) if len(dirs) > 1}
    if copies:
        raise DataError("a session is reported once (DEFINITIONS duplicates), but these directories hold the same "
                        "session ID: " + "; ".join(f"{sid}: {', '.join(dirs)}" for sid, dirs in copies.items()))
    sessions.sort(key=lambda s: (s.times.get("created") if s.times.get("created") is not None else math.inf,
                                 s.sid, str(s.dir)))
    for index, s in enumerate(sessions, 1):
        s.index = index
    protocol = next((s.protocol for s in sessions if s.protocol), None)
    return {"mode": "sessions", "campaign": None, "sessions": sessions, "events": [], "campaign_time": None,
            "stage_intervals": [], "protocol": protocol, "retired_attempts": retired}


# ---------------------------------------------------------------- summary

def scenario_order(report):
    protocol = report.get("protocol") or {}
    order = list(protocol.get("scenarios") or {})
    for scenario in [row.get("scenario") for row in report.get("plan_rows") or []] + \
            [s.row["scenario"] for s in report["sessions"]]:
        if isinstance(scenario, str) and scenario not in order:
            order.append(scenario)
    return order


def time_block(sessions, field):
    values = [s.row[field] for s in sessions if s.row[field] is not None]
    seconds = math.fsum(values)
    return {"sessions": len(sessions), "sessions_counted": len(values),
            "sessions_without_value": len(sessions) - len(values), "seconds": r6(seconds), "hours": r6(seconds / 3600)}


def count_block(sessions, field):
    """Sum of an integer column and its denominator; sessions without a value are counted, never added as 0."""
    values = [s.row[field] for s in sessions if s.row[field] is not None]
    return {"total": sum(values), "sessions_counted": len(values), "sessions_without_value": len(sessions) - len(values)}


def snapshot_block(sessions):
    rows = [s.row for s in sessions]
    both = [r for r in rows if r["snapshots_present"] is not None and r["snapshots_expected"] is not None]
    over = [r for r in rows if r["cycles_at_or_over_period"] is not None and r["snapshots_present"] is not None]
    return {"sessions": len(rows),
            "expected": count_block(sessions, "snapshots_expected"),
            "present": count_block(sessions, "snapshots_present"),
            "present_of_expected": {**ratio(sum(r["snapshots_present"] for r in both),
                                            sum(r["snapshots_expected"] for r in both)),
                                    "sessions_counted": len(both)},
            "sessions_without_sidecars": sum(1 for r in rows if not r["snapshots_present"]),
            "missed_slots": count_block(sessions, "missed_slots"),
            "collector_end_missed_slots": count_block(sessions, "collector_end_missed_slots"),
            "read_errors": count_block(sessions, "read_errors"),
            "filled_zero": count_block(sessions, "filled_zero"),
            "hash_deferred_snapshots": count_block(sessions, "hash_deferred_snapshots"),
            "cycles_at_or_over_period": {**count_block(sessions, "cycles_at_or_over_period"),
                                         "snapshots_of_those_sessions": sum(r["snapshots_present"] for r in over)}}


def window_block(sessions):
    rows = [s.row for s in sessions]
    audited = [r for r in rows if r["windows"] is not None]
    pooled = [r for r in audited if r["snapshots_expected"] is not None]
    breakdown = [r for r in rows if r["nominal_scored_s"] is not None and r["nominal_unscored_s"] is not None]
    ideal = {}
    for label, test in (("from_audit_coverage", lambda source: source == "audit values.coverage"),
                        ("protocol_arithmetic", lambda source: str(source).startswith("protocol arithmetic"))):
        members = [r for r in audited if r["ideal_windows"] is not None and test(r["ideal_windows_source"])]
        ideal[label] = {"sessions": len(members), "windows": sum(r["ideal_windows"] for r in members)}
    return {"sessions": len(rows), "sessions_with_audit_windows": len(audited),
            "scorable_windows": sum(r["windows"] for r in audited),
            "pooled_score_coverage": {**ratio(sum(r["windows"] for r in pooled),
                                              sum(r["snapshots_expected"] for r in pooled)),
                                      "sessions_counted": len(pooled)},
            "per_session_score_coverage": distribution(r["score_coverage"] for r in rows),
            "sessions_with_coverage_breakdown": len(breakdown),
            "nominal_scored_s": r6(total(r["nominal_scored_s"] for r in breakdown)),
            "nominal_unscored_s": r6(total(r["nominal_unscored_s"] for r in breakdown)),
            "ideal_windows_of_audited_sessions": ideal}


def http_block(sessions):
    rows = [s.row for s in sessions]
    counted = [r for r in rows if r["http_requests"] is not None]
    rated = [r for r in counted if r["measure_phase_s"] is not None]
    requests, ok = sum(r["http_requests"] for r in counted), sum(r["http_ok"] for r in counted)
    rated_requests = sum(r["http_requests"] for r in rated)
    measure_s = r6(math.fsum(r["measure_phase_s"] for r in rated))
    return {"sessions": len(rows), "sessions_with_request_log": sum(1 for s in sessions if s.request_log),
            "sessions_with_measure_requests": len(counted),
            "measure_requests": requests, "ok": ok, "errors": requests - ok, "ok_ratio": ratio(ok, requests),
            "requests_outside_http_window": count_block(sessions, "http_requests_outside_window"),
            "pooled_requests_per_s": {**ratio(rated_requests, measure_s), "sessions_counted": len(rated),
                                      "definition": "requests / measure_phase_s over sessions that have both"},
            "per_session_requests_per_s": distribution(r["http_rps"] for r in rows),
            "per_session_latency_all_p95_ms": distribution(r["latency_all_p95_ms"] for r in rows),
            "per_session_latency_all_p99_ms": distribution(r["latency_all_p99_ms"] for r in rows),
            "per_session_latency_ok_p95_ms": distribution(r["latency_ok_p95_ms"] for r in rows)}


def collector_block(sessions):
    rows = [s.row for s in sessions]
    timed = [r["cycle_ms_max"] for r in rows if r["cycle_ms_max"] is not None]
    return {"sessions": len(rows), "sessions_with_cycle_times": len(timed),
            "per_session_cycle_ms_p95": distribution(r["cycle_ms_p95"] for r in rows),
            "max_cycle_ms": max(timed, default=None),
            "cycles_at_or_over_period": count_block(sessions, "cycles_at_or_over_period")}


def volume_block(sessions):
    rows = [s.row for s in sessions]
    measured = [r for r in rows if r["raw_bytes"] is not None]
    never = [r for r in measured if str(r["raw_bytes_source"]).startswith("no raw/ directory")]
    archived = [r for r in rows if r["archive_manifest"] is not None]
    images = [r for r in archived if r["archive_raw_image_bytes"] is not None
              and r["archive_raw_image_stored_bytes"] is not None]
    return {"sessions": len(rows), "raw_bytes": sum(r["raw_bytes"] for r in measured),
            "sessions_with_raw_images_measured": len(measured) - len(never),
            "sessions_without_collector_output": len(never),
            "sessions_without_collector_output_note": ("0 bytes as a fact: end.json shows that the run ended before "
                                                       "the collector started"),
            "sessions_without_value": len(rows) - len(measured),
            "raw_allocated_bytes": count_block(sessions, "raw_allocated_bytes"),
            "archived_sessions": len(archived),
            "archive_bytes": count_block(sessions, "archive_bytes"),
            "archive_stored_bytes": count_block(sessions, "archive_stored_bytes"),
            "archive_raw_image_bytes": count_block(sessions, "archive_raw_image_bytes"),
            "archive_raw_image_stored_bytes": count_block(sessions, "archive_raw_image_stored_bytes"),
            "raw_image_stored_of_original": {**ratio(sum(r["archive_raw_image_stored_bytes"] for r in images),
                                                     sum(r["archive_raw_image_bytes"] for r in images)),
                                             "sessions_counted": len(images)}}


def host_block(sessions):
    rows = [s.row for s in sessions]
    swap = [r["swap_used_max_kib"] for r in rows if r["swap_used_max_kib"] is not None]
    return {"sessions": len(rows), "per_session_cpu_busy_p95_pct": distribution(r["cpu_busy_p95_pct"] for r in rows),
            "swap_used_max_kib": {"max": max(swap, default=None), "sessions_counted": len(swap)},
            "per_session_swap_used_max_kib": distribution(swap)}


def aggregate(sessions):
    """Every per-session aggregate of one set of sessions, each with its own denominator."""
    return {"sessions": len(sessions), "capture_time": time_block(sessions, "capture_span_s"),
            "capture_slots_nominal": time_block(sessions, "capture_slot_s"),
            "snapshots": snapshot_block(sessions), "windows": window_block(sessions), "http": http_block(sessions),
            "collector": collector_block(sessions), "data_volume": volume_block(sessions),
            "host": host_block(sessions)}


def session_gaps(sessions):
    timed = sorted((s for s in sessions if s.times.get("created") is not None),
                   key=lambda s: (s.times["created"], s.sid))
    gaps, overlaps = [], []
    for first, second in zip(timed, timed[1:]):
        if first.times.get("end") is None:
            continue
        gap = second.times["created"] - first.times["end"]
        (gaps if gap >= 0 else overlaps).append({"after": first.sid, "before": second.sid, "seconds": r6(gap)})
    return {"between_consecutive_sessions_s": r6(math.fsum(g["seconds"] for g in gaps)), "gaps": gaps,
            "overlaps": overlaps,
            "pairs_without_end_record": sum(1 for first in timed[:-1] if first.times.get("end") is None)}


def selections(sessions):
    """The three session sets every block reports: all attempted, accepted, accepted without a superseded
    marker (a marker that cannot be read counts as present)."""
    attempted = [s for s in sessions if s.attempted]
    accepted = [s for s in sessions if s.status == "accepted"]
    return {"all_attempted": attempted, "accepted": accepted, USABLE: [s for s in accepted if s.superseded is False]}


def build_summary(report, inputs, command, generated):
    sessions = report["sessions"]
    sets = selections(sessions)
    attempted, accepted, usable = sets["all_attempted"], sets["accepted"], sets[USABLE]
    by_status = {status: [s.sid for s in sessions if s.status == status] for status in STATUSES}
    campaign = report["campaign"]
    planned = len(report["plan_rows"]) if campaign else None  # replacements are attempts, not plan rows
    not_started = [s for s in sessions if not s.attempted]
    reasons = {}
    for status in ("rejected", "interrupted", "incomplete", "in_progress"):
        histogram = Counter()
        for s in sessions:
            if s.status == status:
                histogram.update(set(reason_class(r) for r in s.reasons))
        reasons[status] = dict(sorted(histogram.items()))
    inconsistent = [s for s in attempted if s.evidence_problems]
    clipped = [s for s in attempted if s.row["http_requests_outside_window"]]
    session_block = {
        "planned": planned,
        "planned_missing": None if campaign else "sessions mode: no campaign plan",
        "attempted": len(attempted),
        "attempted_definition": ("a session directory exists (campaign mode) / a session directory was given "
                                 "(sessions mode)"),
        "not_started": len(not_started) if campaign else None,
        "not_started_definition": ("plan rows without a session directory, including rows that status.json names "
                                   "as running before their directory exists (in_progress_without_directory)"),
        "not_started_sessions": [s.sid for s in not_started] if campaign else None,
        "in_progress_without_directory": sum(s.status == "in_progress" for s in not_started) if campaign else None,
        **{status: len(by_status[status]) for status in STATUSES if status != "planned"},
        "by_status": {status: {"count": len(ids), "sessions": ids} for status, ids in by_status.items()},
        "accepted_of_planned": ratio(len(accepted), planned) if campaign else None,
        "accepted_of_attempted": ratio(len(accepted), len(attempted)),
        "accepted_with_campaign_checkpoint": (sum(s.row["campaign_done"] is True for s in accepted)
                                              if campaign else None),
        "campaign_checkpoint_but_not_accepted": ([s.sid for s in attempted if s.row["campaign_done"] is True
                                                  and s.status != "accepted"] if campaign else None),
        "superseded": {"count": sum(s.superseded is True for s in attempted),
                       "sessions": [s.sid for s in attempted if s.superseded is True],
                       "marker_unreadable": [s.sid for s in attempted if s.superseded is None and s.meta],
                       USABLE: len(usable)},
        "evidence_inconsistent": {"definition": DEFINITIONS["evidence_consistency"], "count": len(inconsistent),
                                  "sessions": [{"session": s.sid, "status": s.status, "problems": s.evidence_problems}
                                               for s in inconsistent]},
        "provenance_problems": {"count": sum(1 for s in attempted if s.provenance),
                                "sessions": [{"session": s.sid, "status": s.status, "problems": s.provenance}
                                             for s in attempted if s.provenance]},
        "http_window_excludes_requests": {
            "count": len(clipped),
            "sessions": [{"session": s.sid, "requests_outside_window": s.row["http_requests_outside_window"],
                          "window": s.row["measure_bounds_source"]} for s in clipped]},
        "retired_attempts": {"definition": DEFINITIONS["retired_attempt"],
                             "count": len(report.get("retired_attempts") or []),
                             "attempts": report.get("retired_attempts") or []},
        "reason_classes_by_status": reasons,
        "reason_class_note": ("Number of sessions per reason class; session-specific tokens (image names, "
                              "request IDs, numbers, paths) are replaced. Full reasons are in sessions.csv."),
    }
    capture = {
        "definition": DEFINITIONS["capture_time"],
        **{name: time_block(members, "capture_span_s") for name, members in sets.items()},
        "by_status": {status: time_block([s for s in sessions if s.status == status], "capture_span_s")
                      for status in STATUSES if status != "planned"},
        "slots_nominal": {"definition": "snapshots present x protocol period per session (capture_slot_s)",
                          **{name: time_block(members, "capture_slot_s") for name, members in sets.items()}},
        "planned_capture_hours": campaign["planned_capture_hours"] if campaign else None,
        "planned_capture_hours_source": campaign["planned_capture_hours_source"] if campaign else
        "sessions mode: no campaign plan",
        "planned_vs_measured": ("planned hours = sessions x cycles x period; the measured interval of a complete "
                                "session is (cycles - 1) periods, so compare the plan with slots_nominal, not "
                                "with the measured hours"),
    }
    warmed = [s for s in attempted if s.row["warmup_s"] is not None]
    snapshots = {name: snapshot_block(members) for name, members in sets.items()}
    snapshots.update(expected_planned=count_block(sessions, "snapshots_expected") if campaign else None,
                     missed_slots_definition=DEFINITIONS["missed_slots"])
    per_scenario = {}
    plan = report.get("plan_rows") or []
    for scenario in scenario_order(report):
        members = [s for s in sessions if s.row["scenario"] == scenario]
        per_scenario[scenario] = {
            "planned": sum(row.get("scenario") == scenario for row in plan) if campaign else None,
            "planned_source": "campaign.json plan rows" if campaign else "sessions mode: no campaign plan",
            "membership": "sessions by their recorded scenario (session.json; the plan row when there is none)",
            "attempted": sum(s.attempted for s in members),
            "by_status": {status: sum(s.status == status for s in members) for status in STATUSES},
            **{name: aggregate([s for s in chosen if s.row["scenario"] == scenario]) for name, chosen in sets.items()},
        }
    per_vm = {vm: {"attempted": sum(s.attempted for s in members),
                   "by_status": {status: sum(s.status == status for s in members) for status in STATUSES},
                   **{name: aggregate([s for s in chosen if s.row["vm"] == vm]) for name, chosen in sets.items()}}
              for vm in sorted({s.row["vm"] for s in sessions if s.row["vm"]})
              for members in [[s for s in sessions if s.row["vm"] == vm]]}
    missing_counts = Counter(field for s in attempted for field in s.row.missing)
    return {
        "schema": SCHEMA, "generated_utc": generated, "mode": report["mode"], "command": command,
        "repository": {"root": str(ROOT), **git_identity(),
                       "report_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "campaign": campaign, "definitions": DEFINITIONS,
        "sessions": session_block, "capture_time": capture,
        "warmup_time": {"definition": DEFINITIONS["warmup"], **time_block(attempted, "warmup_s"),
                        "sessions_reaching_measure": sum(1 for s in warmed if s.reached_measure),
                        "sessions_ended_during_warmup": sum(1 for s in warmed if s.reached_measure is False)},
        "session_wall_time": {"definition": "session.json created_unix to end.json written_unix per session",
                              **time_block(attempted, "session_wall_s"), **session_gaps(attempted),
                              "gap_definition": DEFINITIONS["session_gaps"]},
        "campaign_time": report["campaign_time"],
        "campaign_time_missing": None if report["campaign_time"] else (
            "sessions mode: no campaign events" if not campaign else "no timed campaign events"),
        "snapshots": snapshots,
        "windows": {**{name: window_block(members) for name, members in sets.items()},
                    "definition": DEFINITIONS["nominal_times"], "ideal_definition": DEFINITIONS["ideal_windows"]},
        "http": {**{name: http_block(members) for name, members in sets.items()},
                 "load_model": DEFINITIONS["load_model"], "window_definition": DEFINITIONS["http_window"]},
        "collector": {name: collector_block(members) for name, members in sets.items()},
        "data_volume": {**{name: volume_block(members) for name, members in sets.items()},
                        "definition": DEFINITIONS["data_volume"]},
        "host": {name: host_block(members) for name, members in sets.items()},
        "tolerated": tolerated_block(sessions),
        "per_scenario": per_scenario,
        "per_vm": per_vm or None,
        "per_vm_note": ("sessions by their VM (session.json vm; the plan row when there is none); a control "
                        "axis next to the boot groups, not a separate test" if per_vm else
                        "single-VM protocol or sessions without a vm: no per-VM breakdown"),
        "missing_fields_attempted_sessions": dict(sorted(missing_counts.items())),
        "inputs_unreadable": sorted(inputs.unreadable, key=lambda i: (i["input"], i["problem"])),
        "sources": [{k: v for k, v in record.items()} for record in sorted(inputs.files.values(),
                                                                           key=lambda r: r["path"])],
    }


# ---------------------------------------------------------------- SVG plots

SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
SERIES = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948")
ORDINAL = ("#86b6ef", "#2a78d6", "#104281")  # one hue, light -> dark: p50, p95, p99/max
STATUS_FILL = {"accepted": "#0ca30c", "rejected": "#d03b3b", "interrupted": "#ec835a", "incomplete": "#fab219",
               "in_progress": INK2, "planned": AXIS}
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
ROW_H = 18


def fnum(value):
    return f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, float) else str(value)


def text_width(text, size=11):
    return len(text) * size * .58


def tick_label(value):
    if value == 0:
        return "0"
    if abs(value) >= 10000:
        return f"{value / 1000:g}k"
    return f"{value:g}"


def nice_ticks(lo, hi, target=6):
    if not hi > lo:
        hi = lo + 1
    raw = (hi - lo) / target
    magnitude = 10 ** math.floor(math.log10(raw))
    step = next(m * magnitude for m in (1, 2, 2.5, 5, 10) if (hi - lo) / (m * magnitude) <= target)
    ticks, value = [], math.floor(lo / step) * step
    while value <= hi + step * 1e-9:
        ticks.append(round(value, 10))
        value += step
    return ticks


def log_ticks(lo, hi):
    ticks, decade = [], 10 ** math.floor(math.log10(lo))
    while decade <= hi * 1.0001:
        for m in (1, 2, 5):
            if lo * .9999 <= m * decade <= hi * 1.0001:
                ticks.append(round(m * decade, 10))
        decade *= 10
    return ticks


class Svg:
    def __init__(self, width, height, title, desc):
        self.width, self.height, self.title, self.desc, self.items = width, height, title, desc, []

    def text(self, x, y, text, size=11, fill=INK, anchor="start", weight=None):
        bold = f' font-weight="{weight}"' if weight else ""
        self.items.append(f'<text x="{fnum(float(x))}" y="{fnum(float(y))}" font-size="{size}" fill="{fill}" '
                          f'text-anchor="{anchor}"{bold}>{escape(clean_text(text))}</text>')

    def line(self, x1, y1, x2, y2, stroke=GRID, width=1):
        self.items.append(f'<line x1="{fnum(float(x1))}" y1="{fnum(float(y1))}" x2="{fnum(float(x2))}" '
                          f'y2="{fnum(float(y2))}" stroke="{stroke}" stroke-width="{width}"/>')

    def shape(self, element, tip=None):
        if tip:
            element = element[:-2] + f"><title>{escape(clean_text(tip))}</title></{element[1:].split()[0]}>"
        self.items.append(element)

    def rect(self, x, y, w, h, fill, rx=0, tip=None):
        self.shape(f'<rect x="{fnum(float(x))}" y="{fnum(float(y))}" width="{fnum(float(max(w, 0)))}" '
                   f'height="{fnum(float(h))}" rx="{fnum(float(rx))}" fill="{fill}"/>', tip)

    def path(self, d, fill, tip=None, stroke=None, width=None):
        extra = f' stroke="{stroke}" stroke-width="{width}"' if stroke else ""
        self.shape(f'<path d="{d}" fill="{fill}"{extra}/>', tip)

    def marker(self, kind, x, y, fill, tip=None, size=4.5):
        ring = f' stroke="{SURFACE}" stroke-width="2"'
        if kind == "circle":
            self.shape(f'<circle cx="{fnum(float(x))}" cy="{fnum(float(y))}" r="{fnum(size)}" '
                       f'fill="{fill}"{ring}/>', tip)
        elif kind == "square":
            self.shape(f'<rect x="{fnum(float(x - size))}" y="{fnum(float(y - size))}" width="{fnum(2 * size)}" '
                       f'height="{fnum(2 * size)}" fill="{fill}"{ring}/>', tip)
        else:
            d = (f"M{fnum(float(x))},{fnum(float(y - size - 1))} L{fnum(float(x + size + 1))},{fnum(float(y))} "
                 f"L{fnum(float(x))},{fnum(float(y + size + 1))} L{fnum(float(x - size - 1))},{fnum(float(y))} Z")
            self.shape(f'<path d="{d}" fill="{fill}"{ring}/>', tip)

    def hbar(self, x0, x1, yc, thickness, fill, tip=None):
        """Bar from a square baseline (x0) to a 4 px rounded data end (x1)."""
        if x1 - x0 < .5:
            return
        r = min(4, (x1 - x0) / 2, thickness / 2)
        top, bottom = yc - thickness / 2, yc + thickness / 2
        d = (f"M{fnum(float(x0))},{fnum(float(top))} H{fnum(float(x1 - r))} "
             f"Q{fnum(float(x1))},{fnum(float(top))} {fnum(float(x1))},{fnum(float(top + r))} "
             f"V{fnum(float(bottom - r))} Q{fnum(float(x1))},{fnum(float(bottom))} {fnum(float(x1 - r))},"
             f"{fnum(float(bottom))} H{fnum(float(x0))} Z")
        self.path(d, fill, tip)

    def render(self):
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{fnum(float(self.width))}" '
                f'height="{fnum(float(self.height))}" viewBox="0 0 {fnum(float(self.width))} '
                f'{fnum(float(self.height))}" role="img" aria-labelledby="title desc">\n'
                f'<title id="title">{escape(clean_text(self.title))}</title>\n'
                f'<desc id="desc">{escape(clean_text(self.desc))}</desc>\n'
                f'<rect x="0" y="0" width="100%" height="100%" fill="{SURFACE}"/>\n'
                f'<g font-family="{FONT}">\n' + "\n".join(self.items) + "\n</g>\n</svg>\n")


def legend(svg, x, y, items, max_width):
    """Swatch + label pairs in rows; returns the y below the legend."""
    cursor = x
    for kind, color, label in items:
        width = 22 + text_width(label) + 16
        if cursor + width > x + max_width and cursor > x:
            cursor, y = x, y + 18
        if kind == "bar":
            svg.rect(cursor, y - 8, 14, 8, color, rx=2)
        elif kind == "line":
            svg.line(cursor, y - 4, cursor + 14, y - 4, color, 2)
        elif kind == "hairline":
            svg.line(cursor, y - 4, cursor + 14, y - 4, color, 1)
        elif kind == "tick":
            svg.line(cursor + 7, y - 10, cursor + 7, y + 2, color, 2)
        else:
            svg.marker(kind, cursor + 7, y - 4, color)
        svg.text(cursor + 20, y, label, fill=INK2)
        cursor += width
    return y + 22


def row_label(s):
    return f"{s.row['plot_label']} · {s.status.replace('_', ' ')}" + (" (superseded)" if s.superseded else "")


def row_chart(title, subtitle, sessions, panels, legend_items=(), notes=()):
    """One row per session; each panel has its own x axis (no shared or dual scales)."""
    labels = [row_label(s) for s in sessions]
    label_w = min(max([text_width(label) for label in labels] + [80]) + 12, 470)
    margin, panel_gap, value_room = 16, 28, 64
    panel_w = 560 if len(panels) == 1 else 360
    width = margin + label_w + len(panels) * (panel_w + value_room) + (len(panels) - 1) * panel_gap + margin
    svg = Svg(width, 0, title, subtitle)
    svg.text(margin, 26, title, size=15, weight="600")
    y = 44
    for line in subtitle.split("\n"):
        svg.text(margin, y, line, fill=INK2)
        y += 15
    y = legend(svg, margin, y + 8, legend_items, width - 2 * margin) if legend_items else y + 6
    top = y + (18 if len(panels) > 1 else 6)
    bottom = top + ROW_H * max(len(sessions), 1)
    for i, label in enumerate(labels):
        svg.text(margin + label_w - 8, top + ROW_H * i + ROW_H / 2 + 4, label, fill=INK2, anchor="end")
    x0 = margin + label_w
    for panel in panels:
        lo, hi, log = panel["lo"], panel["hi"], panel.get("log", False)
        if log:
            span = math.log10(hi) - math.log10(lo)

            def scale(v, x0=x0, lo=lo, span=span):
                return x0 + (math.log10(max(v, lo)) - math.log10(lo)) / span * panel_w
        else:
            def scale(v, x0=x0, lo=lo, hi=hi):
                return x0 + (min(max(v, lo), hi) - lo) / (hi - lo) * panel_w
        if len(panels) > 1:
            svg.text(x0, top - 8, panel["title"], weight="600")
        for tick in panel["ticks"]:
            svg.line(scale(tick), top, scale(tick), bottom, GRID)
            svg.text(scale(tick), bottom + 14, tick_label(tick), size=10, fill=MUTED, anchor="middle")
        svg.line(x0, bottom, x0 + panel_w, bottom, AXIS)
        svg.line(x0, top, x0, bottom, AXIS)
        svg.text(x0 + panel_w / 2, bottom + 32, panel["axis"], fill=INK2, anchor="middle")
        for value, label in panel.get("refs", ()):
            if lo <= value <= hi:
                svg.line(scale(value), top - 4, scale(value), bottom, INK, 1.5)
                svg.text(scale(value) + 4, top - 6 if len(panels) == 1 else bottom - 4, label, size=10, fill=INK)
        for i, s in enumerate(sessions):
            yc = top + ROW_H * i + ROW_H / 2
            reason = panel["draw"](svg, s, yc, scale)
            if reason:
                room = int((panel_w + value_room - 12) / text_width("x", 10))  # characters that fit this panel
                note = "no data: " + reason
                svg.text(x0 + 6, yc + 4, note if len(note) <= room else note[:room - 3] + "...", size=10, fill=MUTED)
        x0 += panel_w + value_room + panel_gap
    y = bottom + 52
    for note in notes:
        svg.text(margin, y, note, size=10, fill=MUTED)
        y += 14
    svg.height = y + 4
    return svg.render()


def missing_reason(s, field):
    if s.status == "planned":
        return "not started"
    reason = s.row.not_applicable.get(field) or s.row.missing.get(field) or "not recorded"
    return reason if len(reason) <= 90 else reason[:87] + "..."


def plot_timeline(report):
    sessions = report["sessions"]
    lanes = [("capture_stage", "runner: capture stage"), ("audit", "runner: audit"), ("archive", "runner: archive"),
             ("reboot", "runner: reboot"), ("group_start", "runner: start of a group"), ("seal", "runner: seal"),
             ("preflight", "runner: preflight"),
             ("between_sessions", "runner: between sessions"), ("audit_wait", "runner: waits for the audit lock"),
             ("role_wait", "runner: waits for earlier roles"), ("stopped", "runner: stopped"),
             ("paused", "runner: paused for review (limit of replacements)"), ("invalid", "runner: invalid campaign"),
             ("unaccounted", "runner: unaccounted (unclean end)"), ("before_first_launch", "initialized, not launched"),
             ("other", "runner: other")]
    intervals = report["stage_intervals"]
    used = {category if category in dict(lanes) else "other" for _, _, category in intervals}
    lanes = [lane for lane in lanes if lane[0] in used]
    times = [t for s in sessions for t in s.times.values() if t is not None]
    times += [t for a, b, _ in intervals for t in (a, b)]
    title = "Session timeline"
    if not times:
        svg = Svg(640, 80, title, "no timed evidence")
        svg.text(16, 40, "No timed evidence in the inputs.", fill=INK2)
        return svg.render()
    t0, t1 = min(times), max(times)
    span_h = max((t1 - t0) / 3600, 1 / 60)
    labels = [label for _, label in lanes] + [row_label(s) for s in sessions]
    label_w = min(max(text_width(label) for label in labels) + 12, 470)
    margin, plot_w, remark_room = 16, 900, 200
    width = margin + label_w + plot_w + remark_room + margin
    subtitle = ("Thin line: runner session (session.json created to end.json written). Gray: warmup "
                "(generator start to its measure marker, or to its end when the run stopped during warmup).\n"
                "Colored: measured capture (first to last snapshot) by status. Empty space between rows is time "
                "without a session." +
                ("\nTop lanes: campaign runner stages from events/*.json, one lane per stage." if lanes else ""))
    svg = Svg(width, 0, title, subtitle)
    svg.text(margin, 26, title, size=15, weight="600")
    y = 44
    for line in subtitle.split("\n"):
        svg.text(margin, y, line, fill=INK2)
        y += 15
    statuses = [st for st in STATUSES if st != "planned" and any(s.status == st for s in sessions)]
    items = [("hairline", MUTED, "runner session"), ("bar", AXIS, "warmup")]
    items += [("bar", STATUS_FILL[st], "capture: " + st.replace("_", " ")) for st in statuses]
    if lanes:
        items.append(("bar", INK2, "runner stage"))
    y = legend(svg, margin, y + 8, items, width - 2 * margin)
    top = y + 6
    bottom = top + ROW_H * len(labels)
    x0 = margin + label_w

    def scale(t):
        return x0 + (t - t0) / 3600 / span_h * plot_w

    for tick in nice_ticks(0, span_h, 8):
        if tick <= span_h + 1e-9:
            x = x0 + tick / span_h * plot_w
            svg.line(x, top, x, bottom, GRID)
            svg.text(x, bottom + 14, tick_label(tick), size=10, fill=MUTED, anchor="middle")
    svg.line(x0, bottom, x0 + plot_w, bottom, AXIS)
    svg.text(x0 + plot_w / 2, bottom + 32, f"hours since {utc(t0)[:19]}Z (UTC)", fill=INK2, anchor="middle")
    for i, label in enumerate(labels):
        svg.text(x0 - 8, top + ROW_H * i + ROW_H / 2 + 4, label, fill=INK2, anchor="end")
    lane_index = {name: i for i, (name, _) in enumerate(lanes)}
    for a, b, category in intervals:
        lane = lane_index.get(category if category in lane_index else "other")
        if lane is None:
            continue
        yc = top + ROW_H * lane + ROW_H / 2
        svg.rect(scale(a), yc - 4, max(scale(b) - scale(a), .8), 8, INK2,
                 tip=f"{category}: {utc(a)} to {utc(b)} ({b - a:.1f} s)")
    for i, s in enumerate(sessions):
        yc = top + ROW_H * (len(lanes) + i) + ROW_H / 2
        t = s.times
        known = [v for v in t.values() if v is not None]
        if s.status == "planned" or not known:
            svg.text(x0 + 6, yc + 4, "not started" if s.status == "planned" else "no timed evidence",
                     size=10, fill=MUTED)
            continue
        start = t.get("created") if t.get("created") is not None else min(known)
        stop = t.get("end") if t.get("end") is not None else max(known)
        if scale(stop) - scale(start) < 3:  # a few seconds on an hours axis: keep it visible as a tick
            svg.line(scale(start), yc - 5, scale(start), yc + 5, MUTED, 1.5)
        else:
            svg.line(scale(start), yc, scale(stop), yc, MUTED, 1)
        remarks = []
        if t.get("first") is None and s.row["snapshots_present"] == 0:
            wall = s.row["session_wall_s"]
            remarks.append("no snapshot" + (f" (runner {wall:.0f} s)" if wall is not None else ""))
        elif t.get("first") is None:
            remarks.append("snapshot times unavailable: " + missing_reason(s, "capture_first_utc")[:60])
        if s.reached_measure is False and t.get("warmup_end") is not None:
            remarks.append("warmup only")
        if s.end is None:
            remarks.append("end.json unreadable" if (s.dir / "end.json").exists() else "no end.json")
        elif t.get("end") is None:
            remarks.append("end.json without written_unix")
        if remarks:
            note = ", ".join(remarks)
            right = max(scale(stop), scale(start) + 3) + 6
            if right + text_width(note, 10) <= width - margin:
                svg.text(right, yc + 4, note, size=10, fill=MUTED)
            elif scale(start) - 6 - text_width(note, 10) >= x0:
                svg.text(scale(start) - 6, yc + 4, note, size=10, fill=MUTED, anchor="end")
            else:
                room = max(int((width - margin - right) / text_width("x", 10)), 4)
                svg.text(right, yc + 4, note if len(note) <= room else note[:room - 3] + "...", size=10, fill=MUTED)
        if t.get("gen_start") is not None and t.get("warmup_end") is not None:
            svg.rect(scale(t["gen_start"]), yc - 4, max(scale(t["warmup_end"]) - scale(t["gen_start"]), .8), 8,
                     AXIS, rx=1, tip=f"{s.sid} warmup {s.row['warmup_s']} s ({s.row['warmup_end_source']})")
        if t.get("first") is not None:
            svg.rect(scale(t["first"]), yc - 4, max(scale(t["last"]) - scale(t["first"]), .8), 8,
                     STATUS_FILL.get(s.status, INK2), rx=1,
                     tip=(f"{s.sid} {s.status}: capture {s.row['capture_first_utc']} to {s.row['capture_last_utc']} "
                          f"({s.row['capture_span_s']} s, {s.row['snapshots_present']} snapshots)"))
    svg.height = bottom + 50
    return svg.render()


def plot_throughput(report, order):
    sessions = sorted(report["sessions"], key=lambda s: (order.index(s.row["scenario"])
                                                         if s.row["scenario"] in order else len(order), s.index))
    values = [s.row["http_rps"] for s in sessions if s.row["http_rps"] is not None]
    hi = max(values + [1]) * 1.08
    present = [sc for sc in order if any(s.row["scenario"] == sc for s in sessions)]
    color = {sc: SERIES[order.index(sc) % len(SERIES)] for sc in present}

    def draw(svg, s, yc, scale):
        value = s.row["http_rps"]
        if value is None:
            return missing_reason(s, "http_rps")
        svg.hbar(scale(0), scale(value), yc, 10, color.get(s.row["scenario"], MUTED),
                 tip=(f"{s.sid}: {value} requests/s ({s.row['http_requests']} requests, {s.row['http_errors']} "
                      f"errors, {s.row['measure_phase_s']} s)"))
        svg.text(scale(value) + 4, yc + 4, f"{value:.1f}", size=10, fill=INK2)
        return None

    panel = {"lo": 0, "hi": hi, "ticks": nice_ticks(0, hi), "axis": "requests per second (measure phase)",
             "draw": draw}
    return row_chart("HTTP throughput per session",
                     "Requests in the HTTP window / measure_phase_s, all outcomes (window and denominator source in "
                     "sessions.csv). Closed-loop generator: not a fixed request rate.\nRows grouped by scenario; "
                     "the status follows each row label.",
                     sessions, [panel], [("bar", color[sc], sc) for sc in present])


def range_markers(column, last, detail):
    """Panel drawer and legend of p50 / p95 / `last` markers joined by a line (latency.svg, cycles.svg):
    column.format(q) names the sessions.csv column, detail(s) ends each marker's tooltip."""
    kinds = (("p50", "circle", ORDINAL[0]), ("p95", "square", ORDINAL[1]), (last, "diamond", ORDINAL[2]))

    def draw(svg, s, yc, scale):
        points = [(q, s.row[column.format(q)]) for q, _, _ in kinds]
        if any(v is None for _, v in points):
            return missing_reason(s, column.format("p50"))
        svg.line(scale(points[0][1]), yc, scale(points[-1][1]), yc, AXIS, 2)
        for (q, kind, fill), (_, value) in zip(kinds, points):
            svg.marker(kind, scale(value), yc, fill, tip=f"{s.sid}: {q} {value} ms {detail(s)}")
        return None

    return draw, [(kind, fill, q) for q, kind, fill in kinds]


def plot_latency(report):
    sessions = report["sessions"]
    values = [s.row[f"latency_all_{q}_ms"] for s in sessions for q in ("p50", "p95", "p99")]
    values = [v for v in values if v is not None and v > 0]
    lo = 10 ** math.floor(math.log10(min(values))) if values else 1
    hi = 10 ** math.ceil(math.log10(max(values))) if values else 10
    hi = hi if hi > lo else lo * 10
    draw, legend_items = range_markers("latency_all_{}_ms", "p99", lambda s: f"(n={s.row['latency_all_n']})")
    panel = {"lo": lo, "hi": hi, "log": True, "ticks": log_ticks(lo, hi),
             "axis": "request latency, ms (log scale)", "draw": draw}
    return row_chart("HTTP latency per session",
                     "Exact nearest-rank p50 / p95 / p99 over all measure-phase request records of each session, "
                     "failed requests included\n(ok-only values are in sessions.csv). Never averaged from "
                     "intervals.", sessions, [panel], legend_items)


def plot_cycles(report):
    sessions = report["sessions"]
    protocol = report.get("protocol") or {}
    period = number(protocol.get("interval_s"))
    values = [s.row["cycle_ms_max"] for s in sessions if s.row["cycle_ms_max"] is not None]
    hi = max(values + ([period * 1000] if period else []) + [1]) * 1.08
    draw, legend_items = range_markers("cycle_ms_{}", "max", lambda s: f"over {s.row['snapshots_present']} snapshots")
    refs = [(period * 1000, f"period {period:g} s")] if period else []
    panel = {"lo": 0, "hi": hi, "ticks": nice_ticks(0, hi), "axis": "collector cycle time, ms (capture.total_ms)",
             "draw": draw, "refs": refs}
    return row_chart("Collector cycle time per session",
                     "Nearest-rank p50 / p95 and the maximum of sidecar capture.total_ms per session; full-snapshot "
                     "cycle times are listed in sessions.csv.\nThe vertical line is the protocol sampling period.",
                     sessions, [panel], legend_items)


def plot_coverage(report):
    sessions = report["sessions"]
    gates = sorted({s.row["score_gate"] for s in sessions if s.row["score_gate"] is not None})

    def draw(svg, s, yc, scale):
        value, ideal = s.row["score_coverage"], s.row["ideal_score_coverage"]
        if value is None:
            if ideal is not None:
                svg.line(scale(ideal), yc - 6, scale(ideal), yc + 6, INK, 2)
            return missing_reason(s, "score_coverage")
        svg.hbar(scale(0), scale(value), yc, 10, SERIES[0],
                 tip=(f"{s.sid}: {s.row['windows']} scorable windows / {s.row['snapshots_expected']} assigned "
                      f"snapshots = {value:.4f}; ideal {ideal}"))
        if ideal is not None:
            svg.line(scale(ideal), yc - 6, scale(ideal), yc + 6, INK, 2)
        svg.text(scale(1) + 4, yc + 4, f"{value:.3f}", size=10, fill=INK2)
        return None

    refs = [(gate, f"gate {gate:g}") for gate in gates]
    panel = {"lo": 0, "hi": 1, "ticks": nice_ticks(0, 1, 10), "axis": "score coverage (scorable windows / "
             "assigned snapshots)", "draw": draw, "refs": refs}
    return row_chart("Score coverage per session",
                     "Bar: audit score coverage. Black tick: ideal ceiling from the protocol (window length and "
                     "full-snapshot rotation),\nnot a measurement. Vertical line: protocol gate. Sessions without an "
                     "audit show only the ideal tick.", sessions, [panel],
                     [("bar", SERIES[0], "score coverage"), ("tick", INK, "ideal ceiling")])


def plot_volume(report):
    sessions = report["sessions"]
    gib = 2 ** 30
    values = [v / gib for s in sessions for v in (s.row["raw_bytes"], s.row["archive_raw_image_stored_bytes"])
              if v is not None]
    hi = max(values + [.001]) * 1.1

    def draw(svg, s, yc, scale):
        raw, stored = s.row["raw_bytes"], s.row["archive_raw_image_stored_bytes"]
        if raw is None and stored is None:
            return missing_reason(s, "raw_bytes")
        if raw == 0 and stored is None:
            svg.text(scale(0) + 6, yc + 4, f"0 bytes: {s.row['raw_bytes_source']}", size=10, fill=MUTED)
            return None
        if raw is not None:
            svg.hbar(scale(0), scale(raw / gib), yc - 3.5, 6, SERIES[0],
                     tip=f"{s.sid}: raw images {raw} bytes ({raw / gib:.3f} GiB)")
            svg.text(scale(raw / gib) + 4, yc - 1, f"{raw / gib:.2f}", size=9, fill=INK2)
        if stored is not None:
            svg.hbar(scale(0), scale(stored / gib), yc + 3.5, 6, SERIES[1],
                     tip=f"{s.sid}: archived raw images {stored} bytes stored ({stored / gib:.3f} GiB)")
        else:
            svg.text(scale(0) + 4, yc + 8, "not archived", size=9, fill=MUTED)
        return None

    panel = {"lo": 0, "hi": hi, "ticks": nice_ticks(0, hi), "axis": "GiB (2^30 bytes)", "draw": draw}
    return row_chart("Snapshot data volume per session",
                     "Raw: sum of the .vmicd image sizes (st_size, as collection.py audit raw_bytes). Archived: "
                     "stored bytes of the raw image members in archive-manifest.json.", sessions, [panel],
                     [("bar", SERIES[0], "raw images (uncompressed)"), ("bar", SERIES[1], "raw images as archived")])


def plot_host(report):
    sessions = report["sessions"]
    cpu = [s.row["cpu_busy_p95_pct"] for s in sessions if s.row["cpu_busy_p95_pct"] is not None]
    swap = [s.row["swap_used_max_kib"] / 1024 for s in sessions if s.row["swap_used_max_kib"] is not None]
    cpu_hi = max(cpu + [1]) * 1.1
    swap_hi = max(swap + [1]) * 1.1

    def draw_cpu(svg, s, yc, scale):
        value = s.row["cpu_busy_p95_pct"]
        if value is None:
            return missing_reason(s, "cpu_busy_p95_pct")
        svg.hbar(scale(0), scale(value), yc, 10, SERIES[0],
                 tip=(f"{s.sid}: CPU busy p50 {s.row['cpu_busy_p50_pct']} %, p95 {value} %, "
                      f"max {s.row['cpu_busy_max_pct']} %"))
        svg.text(scale(value) + 4, yc + 4, f"{value:.1f}", size=10, fill=INK2)
        return None

    def draw_swap(svg, s, yc, scale):
        value = s.row["swap_used_max_kib"]
        if value is None:
            return missing_reason(s, "swap_used_max_kib")
        svg.hbar(scale(0), scale(value / 1024), yc, 10, SERIES[0],
                 tip=(f"{s.sid}: swap used max {value} KiB; swap in {s.row['swap_in_pages']} / out "
                      f"{s.row['swap_out_pages']} pages in the window"))
        svg.text(scale(value / 1024) + 4, yc + 4, f"{value / 1024:.0f}", size=10, fill=INK2)
        return None

    panels = [{"title": "CPU busy p95 (all host CPUs)", "lo": 0, "hi": cpu_hi, "ticks": nice_ticks(0, cpu_hi),
               "axis": "% busy, nearest-rank p95 of 1 s samples", "draw": draw_cpu},
              {"title": "Swap used, maximum", "lo": 0, "hi": swap_hi, "ticks": nice_ticks(0, swap_hi),
               "axis": "MiB (SwapTotal - SwapFree)", "draw": draw_swap}]
    return row_chart("Host load during the measure window",
                     "scripts/host_monitor.summarize over each session's measure window: the runner's end.json "
                     "window where recorded, otherwise the window\nnamed in sessions.csv monitor_window_source "
                     "(generator markers or end). Two separate scales, one per panel.", sessions, panels)


def plots(report):
    order = scenario_order(report)
    return {"timeline.svg": plot_timeline(report), "throughput.svg": plot_throughput(report, order),
            "latency.svg": plot_latency(report), "cycles.svg": plot_cycles(report),
            "coverage.svg": plot_coverage(report), "volume.svg": plot_volume(report),
            "host.svg": plot_host(report)}


# ---------------------------------------------------------------- output files

def cell(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(value) if math.isfinite(value) else ""
    if isinstance(value, (list, tuple)):
        return ";".join(cell(item) for item in value)
    return clean_text(value)


def csv_text(columns, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def finite(doc):
    """JSON-safe copy: non-finite floats become null."""
    if isinstance(doc, dict):
        return {str(k): finite(v) for k, v in doc.items()}
    if isinstance(doc, (list, tuple)):
        return [finite(v) for v in doc]
    if isinstance(doc, float) and not math.isfinite(doc):
        return None
    return doc


def readme(report, summary, files):
    s = summary
    lines = ["# Collection report", "",
             f"Generated: {s['generated_utc']}", "",
             f"Command: `{s['command']}`", "",
             f"Repository: `{s['repository']['root']}` at commit `{s['repository'].get('commit')}`"
             + (f" (working tree dirty: {s['repository']['changed_paths']} changed paths)"
                if s["repository"].get("dirty") else " (clean working tree)" if s["repository"].get("commit")
                else f" ({s['repository'].get('missing')})"),
             f"Report script SHA-256: `{s['repository']['report_script_sha256']}`", ""]
    if report["campaign"]:
        c = report["campaign"]
        lines += [f"Mode: campaign `{c['id']}` (`{c['directory']}`), sessions read from `{c['collections_dir']}`.",
                  ""]
        if c["closed"]:
            lines += [f"Closed by the operator on {c['closed']['date']}: {md(c['closed']['reason'] or 'no reason')}. "
                      "A closed campaign has no corpus index and cannot be launched again.", ""]
        lines += ["State of the runners: " + ", ".join(
            ("" if r["vm"] is None else f"VM {r['vm']} ") + str(r["status"] or "no status file")
            + (f" ({md(one_line(r['message']))})" if isinstance(r["message"], str) and r["message"] else "")
            for r in c["runners"]) + ".", ""]
        if c["endings"]:
            lines += [f"Ending records of the campaign (`{c['results_dir']}`, definitions: ending):", ""]
            lines += [f"- `{e['file']}` (SHA-256 `{e['sha256']}`), {e['date']}: ending {md(str(e['ending']))}, "
                      f"cause {md(one_line(str(e['cause'])))}, stage {e['stage']}; accepted {e['accepted_sessions']} "
                      f"of {e['planned_sessions']} planned sessions, {e['rejected_sessions']} rejected"
                      + (f", rejections by cause {json.dumps(e['rejections_by_cause'], sort_keys=True)}"
                         if isinstance(e["rejections_by_cause"], dict) else "") + "."
                      for e in c["endings"]] + [""]
        else:
            lines += [f"No ending record of the campaign in `{c['results_dir']}`"
                      + (f" ({md(c['endings_missing'])})" if c["endings_missing"] else "") + ".", ""]
        if c["stop_requests"] or c["stop_request_pending"]:
            honored = sum(r["honored"] for r in c["stop_requests"])
            lines += [f"Operator stop requests: {honored} honored, {len(c['stop_requests']) - honored} set aside as "
                      "stale" + ("; one is pending in stop-request.json" if c["stop_request_pending"] else "")
                      + ".", ""]
        if c["vms"]:
            lines += [f"VMs: {', '.join(c['vms'])}, one runner and status file per VM; sessions are read from "
                      "`<collections>/<campaign>/<vm>/<session>`. Runner stage seconds are summed over the VMs.", ""]
        if c["rejections"]:
            limit = c["limit"]
            replaced = sum(r["replacement"] is not None for r in c["rejections"])
            bound = (f" of at most {limit['max_per_campaign']} per campaign" if limit["applied"] else
                     "; the limit of replacements is not applied in mode rehearsal (definitions: limit)"
                     if limit["applied"] is False else f" ({limit['missing']})")
            lines += [f"Sessions the runner recorded as unusable (rejecting audit or incomplete capture): "
                      f"{len(c['rejections'])}; replaced under the "
                      f"protocol's rule: {replaced}{bound}. "
                      "Such a session is never accepted data; a replacement is the same assignment in the "
                      "same group boot. By cause: " + ", ".join(f"{cause} {n}" for cause, n in
                                                               c["rejections_by_cause"].items()) + ":", ""]
            lines += [f"- `{r['session']}`" + (f" (VM {r['vm']})" if r["vm"] else "") + f", {r['cause']}: "
                      + md(one_line("; ".join(r["reasons"]) or "no reason recorded")) + "; "
                      + (f"replaced by `{r['replacement']}`" if r["replacement"] else
                         "not replaced" + (f" ({md(one_line(r['not_replaced']))})"
                                           if isinstance(r["not_replaced"], str) else ""))
                      for r in c["rejections"]] + [""]
        starts = c["group_start_failures"]
        if starts["total"]:
            lines += [f"Failed starts of groups, no rejections of sessions (definitions: group_start_failures): "
                      f"{starts['total']} in {starts['groups']} group{'s' if starts['groups'] != 1 else ''}, "
                      f"{starts['groups_started_again']} of them started again; from {md(starts['source'])}:", ""]
            lines += [f"- `{group}`" + (f" (VM {f['vm']})" if f["vm"] else "") + f": step {f['step']} on {f['date']}, "
                      f"cause {f['cause']} ({md(one_line(str(f['reason'])))}); "
                      + ("started again" if f["started_again"] else "not started again")
                      for group, found in starts["by_group"].items() for f in found] + [""]
    else:
        lines += [f"Mode: sessions ({len(report['sessions'])} session directories read).", ""]
    lines += ["Only saved evidence was read; RAM images were not opened and archived members were not "
              "decompressed. Every input file is listed with its SHA-256 in `sources.csv` and in "
              "`summary.json` (`sources`).", "", "## Files", ""]
    descriptions = {
        "sessions.csv": "one row per session (campaign: every planned assignment), all values with sources; "
                        "`missing` and `not_applicable` give the reason for every empty value",
        "intervals.csv": "every 5 s generator interval of every session (phase by request start time)",
        "collector_cycles.csv": "every snapshot sidecar (timing, size, slots, hash flag)",
        "coverage.csv": "audit score-coverage breakdown per session (empty with a reason when there is no audit)",
        "routes.csv": "measure-phase requests per route and session",
        "tolerated.csv": ("the conditions the audit admitted in every accepted session, by register id "
                          "(values.exceptions), apart from the coverage rows invalid_input"),
        "events.csv": "campaign events with the time until the next event and its attribution",
        "sources.csv": ("every input file: session, session directory, path, real path, bytes, SHA-256, "
                        "logs_manifest.json comparison"),
        "summary.json": "totals with numerators and denominators, definitions, unreadable inputs, sources",
        "plots/timeline.svg": "session timeline: warmup, measured capture, gaps, runner stages (campaign)",
        "plots/throughput.svg": "measure-phase HTTP requests per second per session",
        "plots/latency.svg": "exact p50/p95/p99 request latency per session",
        "plots/cycles.svg": "collector cycle time p50/p95/max per session with the sampling period",
        "plots/coverage.svg": "score coverage per session with the gate and the ideal ceiling",
        "plots/volume.svg": "raw image bytes and archived (stored) bytes per session",
        "plots/host.svg": "host CPU busy p95 and maximum swap use per session",
    }
    lines += [f"- `{name}` - {descriptions.get(name, '')}" for name in files] + [""]
    sb = s["sessions"]
    sets = selections(report["sessions"])
    superseded = sb["superseded"]["sessions"]
    lines += ["## Denominators", ""]
    if report["campaign"]:
        lines.append(f"- Planned sessions: {sb['planned']}; attempted (session directory exists): "
                     f"{sb['attempted']}; not started (no session directory): {sb['not_started']}"
                     + (f", of which {sb['in_progress_without_directory']} named as running by status.json"
                        if sb["in_progress_without_directory"] else "") + ".")
    else:
        lines.append(f"- Session directories read: {sb['attempted']} (sessions mode has no plan, so no "
                     "planned or not-started counts).")
    lines.append("- By status: " + ", ".join(f"{k} {v['count']}" for k, v in sb["by_status"].items()) + ".")
    retired = sb["retired_attempts"]["attempts"]
    lines.append(f"- Retired attempts (ended before the measured phase; not sessions, in no total): {len(retired)}"
                 + (":" if retired else "."))
    lines += [f"  - `{r['session_id']}` attempt {r['attempt']}: {md(one_line(r['reason'] or 'no reason recorded'))}"
              + (f" (problems: {md('; '.join(r['problems']))})" if r["problems"] else "") for r in retired]
    acc = sb["accepted_of_planned"] if report["campaign"] else sb["accepted_of_attempted"]
    lines.append(f"- Accepted of {'planned' if report['campaign'] else 'attempted'}: {acc['numerator']} / "
                 f"{acc['denominator']}. Rejected, interrupted, incomplete and in-progress sessions are never "
                 "counted as accepted data; they are listed below with their reasons.")
    if superseded or sb["superseded"]["marker_unreadable"]:
        lines.append(f"- Superseded markers: {len(superseded)} ({', '.join(superseded) or 'none'}); unreadable "
                     f"markers: {len(sb['superseded']['marker_unreadable'])}; accepted without a marker: "
                     f"{sb['superseded'][USABLE]}. Every accepted total below is also given without them.")
    if sb["evidence_inconsistent"]["count"] or sb["provenance_problems"]["count"]:
        lines.append(f"- Sessions whose files differ from what was recorded or audited: "
                     f"{sb['evidence_inconsistent']['count']}; with campaign provenance problems: "
                     f"{sb['provenance_problems']['count']} (listed below; an accepting verdict is not applied).")

    def variants(block, render):
        parts = [f"all attempted {render(block['all_attempted'])}", f"accepted {render(block['accepted'])}"]
        if superseded or sb["superseded"]["marker_unreadable"]:
            parts.append(f"accepted without a superseded marker {render(block[USABLE])}")
        return "; ".join(parts)

    ct = s["capture_time"]
    lines.append("- Measured capture hours (first to last snapshot of each session): " + variants(
        ct, lambda b: f"{b['hours']} h over {b['sessions_counted']} of {b['sessions']} sessions") + ".")
    slots = ct["slots_nominal"]
    if ct["planned_capture_hours"] is not None:
        lines.append(f"- Planned capture hours (design allocation from campaign.json, sessions x cycles x period): "
                     f"{ct['planned_capture_hours']}. A complete session's measured interval is (cycles - 1) "
                     "periods, one period shorter than its allocation; compare the plan with the nominal slot "
                     "hours (snapshots present x period): " + variants(
                         slots, lambda b: f"{b['hours']} h over {b['sessions_counted']} sessions") + ".")
    else:
        lines.append("- Nominal slot hours (snapshots present x period, not measured; a complete session's measured "
                     "interval is one period shorter): " + variants(
                         slots, lambda b: f"{b['hours']} h over {b['sessions_counted']} sessions") + ".")
    wt = s["warmup_time"]
    lines.append(f"- Warmup (not collection time): {wt['hours']} h over {wt['sessions_counted']} sessions "
                 f"({wt['sessions_ended_during_warmup']} of them ended during warmup, without a measure phase).")
    if s["campaign_time"]:
        cti = s["campaign_time"]
        lines.append(f"- Campaign wall-clock span {cti['wall_clock_span_h']} h from {cti['first_event_utc']} to "
                     f"{cti['last_event_utc']}; runner time by stage, never counted as collection time (s): "
                     + ", ".join(f"{k} {v}" for k, v in cti["by_category_s"].items()) + ".")
    sn = s["snapshots"]["all_attempted"]
    pe = sn["present_of_expected"]
    over = sn["cycles_at_or_over_period"]
    lines.append(f"- Snapshots present / expected: {pe['numerator']} / {pe['denominator']} over "
                 f"{pe['sessions_counted']} attempted sessions with both counts; missed slots "
                 f"{sn['missed_slots']['total']} over {sn['missed_slots']['sessions_counted']} sessions (collector "
                 f"running totals at the last snapshot); read errors {sn['read_errors']['total']} over "
                 f"{sn['read_errors']['sessions_counted']} sessions; cycles at or over the period {over['total']} of "
                 f"{over['snapshots_of_those_sessions']} snapshots in {over['sessions_counted']} sessions.")
    lines.append("- Scorable windows (audit): " + variants(
        s["windows"], lambda b: (f"{b['scorable_windows']} over {b['sessions_with_audit_windows']} sessions, pooled "
                                 f"coverage {b['pooled_score_coverage']['numerator']} / "
                                 f"{b['pooled_score_coverage']['denominator']} assigned snapshots")) + ".")
    wa = s["windows"]["all_attempted"]
    lines.append(f"- Nominal unscored time {wa['nominal_unscored_s']} s over {wa['sessions_with_coverage_breakdown']} "
                 "attempted sessions with a coverage breakdown (slot counts x period, not measured availability).")
    lines.append("- HTTP requests in the measure window: " + variants(
        s["http"], lambda b: (f"{b['measure_requests']} ({b['ok']} ok, {b['errors']} errors) over "
                              f"{b['sessions_with_measure_requests']} sessions with measure-phase requests "
                              f"({b['sessions_with_request_log']} with a request log), pooled rate "
                              f"{shown(b['pooled_requests_per_s']['value'])} requests/s over "
                              f"{b['pooled_requests_per_s']['sessions_counted']} sessions")) + ".")
    clipped = sb["http_window_excludes_requests"]
    if clipped["count"]:
        lines.append(f"- HTTP windows that exclude requests the generator labeled 'measure': {clipped['count']} ("
                     + ", ".join(f"`{c['session']}` {c['requests_outside_window']}" for c in clipped["sessions"])
                     + "); see http_window in the definitions and the notes column.")
    lines.append("- Raw image bytes: " + variants(
        s["data_volume"], lambda b: (f"{b['raw_bytes']} over {b['sessions_with_raw_images_measured']} sessions with "
                                     f"measured images ({b['sessions_without_collector_output']} more with 0 bytes "
                                     f"because the run ended before the collector started, "
                                     f"{b['sessions_without_value']} without a value)")) + ".")
    va = s["data_volume"]["all_attempted"]
    lines.append(f"- Archived sessions {va['archived_sessions']}; archive stored bytes "
                 f"{va['archive_stored_bytes']['total']} over {va['archive_stored_bytes']['sessions_counted']} "
                 "sessions.")
    tb = s["tolerated"]
    lines += ["", "## Tolerated conditions of the accepted sessions", "",
              f"By register id (`tolerated.csv`, definitions: tolerated), over {tb['accepted_sessions']} accepted "
              "sessions; apart from the coverage rows invalid_input of `coverage.csv`. Sources: "
              + (", ".join(f"{k} {v}" for k, v in tb["sources"].items()) or "none") + ".", ""]
    lines += [f"- `{name}`: " + (f"total {b['total']}, largest in one session {b['max_in_one_session']}, sessions "
                                 f"over the expected count {b['sessions_over_expected']} (expected "
                                 + (f"{b['expected']}" if b["expected"] is not None else "null until G3b, so no "
                                    "session is over it") + f"; over {b['sessions_counted']} sessions that record it)"
                                 if b["sessions_counted"] else b["missing"])
              for name, b in tb["by_id"].items()]
    if tb["not_recorded"]:
        lines.append(f"- {NOT_RECORDED}: " + ", ".join(f"`{sid}`" for sid in tb["not_recorded"]) + ".")
    lines += ["", "## Definitions", ""]
    for key, value in DEFINITIONS.items():
        if isinstance(value, dict):
            lines.append(f"- **{key}**: " + "; ".join(f"`{k}` = {v}" for k, v in value.items()) + ".")
        else:
            lines.append(f"- **{key}**: {value}")
    lines += ["", "## Sessions", "", "| # | session | status | reasons |", "|---|---|---|---|"]
    for session in report["sessions"]:
        reasons = one_line(joined(session.reasons) or "none")
        reasons = reasons if len(reasons) <= 160 else reasons[:157] + "..."
        status = session.status + (" (superseded)" if session.superseded is True else "")
        lines.append(f"| {session.index} | `{session.sid}` | {status} | {md(reasons)} |")
    lines += ["", "## Missing or unreadable inputs", ""]
    sessions = report["sessions"]
    attempted = sets["all_attempted"]
    gaps = []
    if report["campaign"]:
        gaps.append(("Planned sessions without a session directory (not started)",
                     [x for x in sessions if not x.attempted], lambda x: "status.json: running" if x.status ==
                     "in_progress" else None))
    gaps += [("Session directories without session.json content", [x for x in attempted if not x.meta], None),
             ("Sessions without end.json", [x for x in attempted if x.meta and x.end is None], None),
             ("Sessions without an audit verdict", [x for x in attempted if x.audit is None], None),
             ("Sessions without a request log", [x for x in attempted if not x.request_log and x.meta], None),
             ("Sessions without snapshot sidecars", [x for x in attempted if not x.cycles],
              lambda x: x.row.missing.get("snapshots_present") or x.row["raw_bytes_source"]),
             ("Sessions whose files differ from logs_manifest.json, end.json or the audit",
              [x for x in attempted if x.evidence_problems], lambda x: "; ".join(x.evidence_problems)),
             ("Sessions with campaign provenance problems", [x for x in attempted if x.provenance],
              lambda x: "; ".join(x.provenance)),
             ("Sessions whose superseded.json could not be read",
              [x for x in attempted if x.meta and x.superseded is None], None)]
    if report["campaign"]:
        gaps.append(("Sessions with a campaign done checkpoint that the report does not find accepted",
                     [x for x in attempted if x.row["campaign_done"] is True and x.status != "accepted"],
                     lambda x: x.status))
    for label, members, detail in gaps:
        if not members:
            lines.append(f"- {label}: 0")
            continue
        lines.append(f"- {label}: {len(members)}:")
        for x in members:
            extra = detail(x) if detail else None
            lines.append(f"  - `{x.sid}`" + (f": {one_line(extra)}" if extra else ""))
    if summary["inputs_unreadable"]:
        lines += ["", "Inputs that could not be used:", ""]
        lines += [f"- `{item['input']}`: {one_line(item['problem'])}" for item in summary["inputs_unreadable"]]
    else:
        lines += ["", "No input was rejected as unreadable."]
    if report["campaign"] and report["campaign"]["problems"]:
        lines += ["", "Campaign consistency problems:", ""]
        lines += [f"- {one_line(problem)}" for problem in report["campaign"]["problems"]]
    lines += ["", "Missing values per attempted session (field groups and reasons; also in the `missing` column; "
              "fields that do not apply are in `not_applicable`):", ""]
    for session in sessions:
        if session.attempted and session.row["missing"]:
            lines.append(f"- `{session.sid}` ({session.status}): {one_line(session.row['missing'])}")
    return "\n".join(lines) + "\n"


def md(text):
    """A Markdown table cell: one line, pipes escaped."""
    return one_line(text).replace("|", "/")


def shown(value):
    return "n/a" if value is None else value


def protected_roots(report, inputs):
    """Every directory the report read from, plus the session, archive and campaign directories it names.
    The output may not be created inside any of them: a report never changes an input directory or the file
    set of a verified archive (collection_archive.verify_archive compares it with the manifest)."""
    roots = set()
    for record in inputs.files.values():
        for path in (record["path"], record["realpath"]):
            if path:
                roots.add(Path(path).parent)
    for s in report["sessions"]:
        if not s.attempted:
            continue
        roots.add(s.dir)
        if (s.dir / "raw").is_symlink():
            roots.add(s.dir / os.readlink(s.dir / "raw"))  # a relative link target is relative to the session
        if s.row["raw_dir"]:
            roots.add(s.dir / s.row["raw_dir"])
        if s.row["archive_manifest"]:
            roots.add(Path(s.row["archive_manifest"]).parent)
    campaign = report["campaign"]
    if campaign:
        roots.update(Path(campaign[key]) for key in ("directory", "collections_dir", "archive_dir") if campaign[key])
    return sorted({Path(os.path.realpath(root)) for root in roots})


def write_report(out, report, inputs, command):
    """Compute everything first, then publish into a new directory (exclusive); never overwrite."""
    target = Path(os.path.realpath(out))
    for root in protected_roots(report, inputs):
        if target == root or target.is_relative_to(root):
            raise DataError(f"refusing to write the report inside {root}, a directory the report reads from or "
                            "names (session, archive or campaign data)")
    sessions = report["sessions"]
    for s in sessions:
        s.row["index"] = s.index
        s.row["plot_label"] = f"{s.index:02d} {s.row['role'] or '?'} {s.row['scenario'] or '?'}"
        if s.attempted:
            s.row["sources"] = session_sources(s, inputs)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary = finite(build_summary(report, inputs, command, generated))
    for record in inputs.files.values():
        record.setdefault("logs_manifest_sha256", None)
        record.setdefault("matches_logs_manifest", None)
    contents = {
        "sessions.csv": csv_text(SESSION_COLUMNS, [s.row for s in sessions]),
        "intervals.csv": csv_text(INTERVAL_COLUMNS, [dict(iv, session_id=s.sid) for s in sessions
                                                     for iv in s.intervals]),
        "collector_cycles.csv": csv_text(CYCLE_COLUMNS, [dict(c, session_id=s.sid) for s in sessions
                                                         for c in s.cycles]),
        "coverage.csv": csv_text(COVERAGE_COLUMNS, [dict(s.coverage, status=s.status) for s in sessions
                                                    if s.coverage]),
        "routes.csv": csv_text(ROUTE_COLUMNS, [route for s in sessions for route in s.routes]),
        "tolerated.csv": csv_text(*tolerated_table(sessions)),
        "sources.csv": csv_text(SOURCE_COLUMNS, [dict(r, session_id=r["session"] or "") for r in
                                                 sorted(inputs.files.values(), key=lambda r: r["path"])]),
    }
    if report["mode"] == "campaign":
        contents["events.csv"] = csv_text(EVENT_COLUMNS, [dict(e, time_utc=utc(e["time"])) for e in report["events"]])
    summary["sources"] = [dict(r) for r in sorted(inputs.files.values(), key=lambda r: r["path"])]
    contents["summary.json"] = json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    figures = {f"plots/{name}": svg for name, svg in plots(report).items()}
    names = sorted(contents) + sorted(figures)
    contents.update(figures)
    contents["README.md"] = readme(report, summary, names)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.mkdir()  # FileExistsError if anything appeared meanwhile: nothing is overwritten.
    written = []
    try:
        (out / "plots").mkdir()
        for name in sorted(contents):
            with open(out / name, "x", encoding="utf-8", newline="") as stream:
                written.append(out / name)
                stream.write(contents[name])
    except BaseException:
        for path in reversed(written):
            path.unlink(missing_ok=True)
        (out / "plots").rmdir() if (out / "plots").is_dir() and not any((out / "plots").iterdir()) else None
        out.rmdir() if not any(out.iterdir()) else None
        raise
    return summary


# ---------------------------------------------------------------- envelope mode (the lead's answer to Q30)

ENVELOPE_SCHEMA = "hyptcn3/envelope-check/1"
ENVELOPE_RESULTS = ("match", "mismatch", "data_error")
# Where run_session and the generator put the files of a session (scripts/collection.py run_session copies the
# protocol to protocol.json, traffic_command names both logs), and the schema of each log's header (the generator's).
ENVELOPE_LOGS = (("traffic_requests.jsonl", host_traffic.V5_REQUEST_SCHEMA),
                 ("traffic_intervals.jsonl", host_traffic.V5_INTERVAL_SCHEMA))
ENVELOPE_GENERATOR = "scripts/host_traffic.py"  # Its key in session.json source_sha256 (collection.run_session).
# Each field of a header bound to session.json, with the field of session.json it must equal.
ENVELOPE_BINDINGS = (("session_id", "session_id"), ("profile", "traffic.profile"),
                     ("config.profile", "traffic.profile"), ("scenario", "traffic.scenario"),
                     ("config.scenario", "traffic.scenario"), ("seeds.traffic", "traffic.seeds.traffic"),
                     ("config.seed", "traffic.seeds.traffic"), ("config.dur", "traffic.dur_s"),
                     ("warmup_s", "traffic.warmup_s"), ("config.warmup_s", "traffic.warmup_s"))
ENVELOPE_GUEST = ("none: the mode envelope reads the saved session.json and protocol.json of each session in values "
                  "and the first line of its two traffic logs; no VM is contacted")
ENVELOPE_RULE = (
    "The lead's answer to question Q30 (2026-11-24) and point 3 of his comments on B10 (dokazy/B10/PRIPOMIENKY.md): "
    "the audit does not redraw the envelope of the traffic (scripts/collection_logs.py says so in its rule); this "
    "mode, outside the measurement code, redraws it over the sessions of G2, the sessions of both rehearsals and, "
    "after an ending that closes a campaign and before the records are committed, every accepted session. Of each "
    "session directory it reads session.json, the sha256 of its protocol.json and the first line of "
    "traffic_requests.jsonl and of traffic_intervals.jsonl, the header the generator writes into both "
    "(scripts/host_traffic.py SessionRecorder.header), no score; every file it reads is listed with its sha256. It "
    "draws the envelope as the generator's v5 run draws it (prepare_v5): host_traffic.draw_envelope with "
    "profiles[traffic.profile].arrivals of the protocol, random.Random(traffic.seeds.traffic of session.json), "
    "traffic.dur_s and traffic.warmup_s as floats (collection.traffic_command passes them as --dur and --warmup-s) "
    "and scenario_rule.min_peak_to_mean of the protocol, after the generator's refusals that decide whether it draws "
    "at all, in its order and with its words. Each header must carry exactly that envelope (every knot equal as a "
    "number, no tolerance; a boolean is no number) and the protocol's profiles[traffic.profile] as "
    "profile_parameters, and agree with session.json on session_id, profile, scenario, the traffic seed "
    "(seeds.traffic, config.seed), config.dur and warmup_s (also config.warmup_s). Also bound (the executor's "
    "judgment, G2 preparation): the two headers agree with each other on all of these and on run_id; session.json "
    "agrees with itself (scenario and seed equal those of its traffic block); and its span is the planned run of "
    "the protocol, traffic.dur_s = warmup_s + cycles x interval_s and traffic.warmup_s = warmup_s "
    "(collection._v5_traffic). A session is a data error, without a verdict, when a file is missing or unreadable, "
    "the first line of a log is not its v5 header, a field of session.json the redraw or a binding reads is absent "
    "or not of its type, the protocol is not the session's: its sha256 differs from that of the session's "
    "protocol.json, from session.json protocol_sha256 or from the protocol_sha256 of a header (P1 of the G2 "
    "preparation), or the generator that draws here is not the session's: the sha256 of scripts/host_traffic.py "
    "differs from the one session.json source_sha256 recorded (the executor's judgment, G2 preparation: another "
    "generator's envelope says nothing of this one's). Every other difference makes it a mismatch, each named, the "
    "generator's refusal of the planned run among them (no header of that run can exist); a session with none is a "
    "match (the executor's judgment, G2 preparation). Exit 0: every session matches; 1: at least one mismatch and "
    "no data error; 2: a usage error, nothing written, or at least one data error, whose record still names every "
    "mismatch (a mismatch in a run that ends 2 is a mismatch as in a run that ends 1; the executor's judgment, G2 "
    "preparation). A mismatch is a deviation of the campaign, written in docs/ODCHYLKY_V5.sk.md beside the ending "
    "record and naming that record, and a finding for the lead; the campaign code does not call this mode (the "
    "lead's reading of Q30, point 3).")
_ABSENT = object()  # A key a document does not have (as opposed to null).


def _number(value):
    """A finite int or float that is no boolean; an int too large for a float is none."""
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _equal(a, b):
    """Two JSON values are equal: numbers by value without tolerance (120 equals 120.0, as the audit compares them), a
    boolean only to a boolean, objects key by key, lists element by element."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) or isinstance(b, dict):
        return isinstance(a, dict) and isinstance(b, dict) and a.keys() == b.keys() and all(_equal(a[k], b[k])
                                                                                            for k in a)
    if isinstance(a, list) or isinstance(b, list):
        return isinstance(a, list) and isinstance(b, list) and len(a) == len(b) and all(map(_equal, a, b))
    return a == b


def _get(doc, dotted):
    """doc[k1][k2]... of the dotted path, _ABSENT where a level is not an object or lacks the key."""
    for key in dotted.split("."):
        if not isinstance(doc, dict) or key not in doc:
            return _ABSENT
        doc = doc[key]
    return doc


def _shown(value, limit=120):
    """A value in a reason: its JSON (a float exactly, as the logs write it), cut to `limit` characters."""
    if value is _ABSENT:
        return "absent"
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _differences(found, expected, path=""):
    """[(path, found, expected)] where two JSON values differ (_equal), down to the keys of objects and the elements
    of lists of one length; _ABSENT for a key only one of them has."""
    if isinstance(found, dict) and isinstance(expected, dict):
        return [d for key in sorted(set(found) | set(expected), key=str)
                for d in _differences(found.get(key, _ABSENT), expected.get(key, _ABSENT), f"{path}.{key}")]
    if isinstance(found, list) and isinstance(expected, list) and len(found) == len(expected):
        return [d for i, (x, y) in enumerate(zip(found, expected)) for d in _differences(x, y, f"{path}[{i}]")]
    return [] if _equal(found, expected) else [(path, found, expected)]


def _knot_differences(found, drawn):
    """How the envelope of a header differs from the drawn one (Envelope.as_dict()); [] when it is that one. Named:
    an envelope absent or no object, other keys, another number of knots, or the knots that differ (their number
    and the first of them)."""
    if not isinstance(found, dict):
        return [f"envelope is {_shown(found, 40)}, not an object"]
    out = []
    if set(found) != set(drawn):
        out.append(f"envelope has the keys {sorted(found)}, the drawn one {sorted(drawn)}")
    for key in drawn:
        if key not in found:
            continue  # Named with the keys.
        mine, theirs = found[key], drawn[key]
        if not isinstance(mine, list):
            out.append(f"envelope.{key} is {_shown(mine, 40)}, not a list")
        elif len(mine) != len(theirs):
            out.append(f"envelope.{key} has {len(mine)} knots, the drawn one {len(theirs)}")
        else:
            differ = [i for i, (x, y) in enumerate(zip(mine, theirs)) if not _equal(x, y)]
            if differ:
                i = differ[0]
                out.append(f"envelope.{key}: {len(differ)} of {len(theirs)} knots differ from the drawn ones, the "
                           f"first [{i}] is {_shown(mine[i])}, drawn {_shown(theirs[i])}")
    return out


def _first_line(path):
    """(the first line without its newline, None when the file has none; sha256; bytes) of a file read whole in
    chunks, so its hash covers all of it while only its first line is kept."""
    sha, size, parts, first = hashlib.sha256(), 0, [], None
    with open(path, "rb") as stream:
        while chunk := stream.read(CHUNK):
            sha.update(chunk)
            size += len(chunk)
            if first is None:
                cut = chunk.find(b"\n")
                if cut < 0:
                    parts.append(chunk)
                else:
                    first, parts = b"".join(parts) + chunk[:cut], None
    return first, sha.hexdigest(), size


def envelope_protocol(path):
    """(sha256, document) of the protocol of the mode envelope. A DataError, a usage error before any session is read,
    when it is not a protocol the v5 generator reads, with the generator's words (host_traffic.prepare_v5: schema 3,
    its profiles section, scenario_rule.min_peak_to_mean), or lacks a number of the planned run (warmup_s,
    interval_s)."""
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as error:
        raise DataError(f"cannot read protocol {path}: {error}") from None
    if type(doc) is not dict or doc.get("schema") != host_traffic.PROTOCOL_SCHEMA:
        raise DataError(f"protocol {path}: protocol schema is not {host_traffic.PROTOCOL_SCHEMA}: the v5 profiles are "
                        "its profiles section")
    problems = protocol_v5.profiles_problems(doc)
    if problems:
        raise DataError(f"protocol {path}: invalid profiles: {problems[0]}")
    rule = doc.get("scenario_rule")
    ratio = rule.get("min_peak_to_mean") if type(rule) is dict else None
    if not _number(ratio) or ratio < 1:
        raise DataError(f"protocol {path}: scenario_rule.min_peak_to_mean is not a number >= 1")
    for key in ("warmup_s", "interval_s"):
        if not _number(doc.get(key)) or doc[key] < 0:
            raise DataError(f"protocol {path}: {key} is not a number >= 0 (the planned run is warmup_s + cycles x "
                            "interval_s)")
    return hashlib.sha256(raw).hexdigest(), doc


def envelope_redraw(protocol, profile, scenario, seed, dur_s, warmup_s):
    """(Envelope, draws) of the run session.json plans, drawn as scripts/host_traffic.py prepare_v5 draws it: --dur and
    --warmup-s are the floats argparse makes of what collection.traffic_command passes (str of the traffic block's
    dur_s and warmup_s), then the generator's refusals of the envelope's inputs, in its order and with its words, and
    draw_envelope. A ValueError names the refusal: the generator would not have run, and wrote no header."""
    dur, warmup = float(str(dur_s)), float(str(warmup_s))
    if not math.isfinite(dur) or dur <= 0:
        raise ValueError("--dur must be a number > 0: the envelope spans [0, dur]")
    if not math.isfinite(warmup) or not 0 <= warmup < dur:
        raise ValueError("--warmup-s must lie in [0, --dur)")
    scenarios = protocol.get("scenarios")
    if type(scenarios) is not dict or type(scenarios.get(scenario)) is not dict:
        raise ValueError(f"unknown scenario: {scenario}")
    if scenarios[scenario].get("profile") != profile:
        raise ValueError(f"--profile {profile} differs from scenarios.{scenario}.profile "
                         f"{scenarios[scenario].get('profile')}")
    a = protocol["profiles"][profile]["arrivals"]
    if a["ramp_s"] > warmup:
        raise ValueError(f"the ramp of profile {profile} (arrivals.ramp_s {a['ramp_s']}) is longer than --warmup-s "
                         f"{warmup}")
    if dur - warmup < a["peak_s"][1]:
        raise ValueError(f"[--warmup-s, --dur] is shorter than the longest peak (arrivals.peak_s {a['peak_s'][1]} s)")
    return host_traffic.draw_envelope(a, random.Random(seed), dur, warmup,
                                      protocol["scenario_rule"]["min_peak_to_mean"])


def _session_fields(meta):
    """The data errors of the fields of session.json the redraw and the bindings read (ENVELOPE_RULE)."""
    integer = lambda value: type(value) is int  # noqa: E731  (no boolean)
    checks = (("session_id", lambda v: isinstance(v, str), "a string"),
              ("scenario", lambda v: isinstance(v, str), "a string"),
              ("seed", integer, "an integer"),
              ("cycles", lambda v: integer(v) and v > 0, "an integer > 0"),
              ("protocol_sha256", lambda v: isinstance(v, str), "a string"),
              ("traffic.profile", lambda v: isinstance(v, str) and v in host_traffic.PROFILES,
               "a profile of the v5 generator (" + ", ".join(host_traffic.PROFILES) + ")"),
              ("traffic.scenario", lambda v: isinstance(v, str), "a string"),
              ("traffic.seeds.traffic", lambda v: integer(v) and v >= 0, "an integer >= 0"),
              ("traffic.dur_s", _number, "a finite number"),
              ("traffic.warmup_s", _number, "a finite number"))
    out = []
    for field, ok, what in checks:
        value = _get(meta, field)
        if value is _ABSENT:
            out.append(f"session.json: {field} is absent")
        elif not ok(value):
            out.append(f"session.json: {field} is {_shown(value, 40)}, not {what}")
    return out


def envelope_session(directory, protocol_sha, protocol, generator_sha):
    """The verdict of one session directory by ENVELOPE_RULE under the protocol `protocol` (its sha256 protocol_sha),
    drawn by the generator whose scripts/host_traffic.py has the sha256 generator_sha: {session_id, path, result,
    reasons, inputs, draws, knots, files}."""
    path = Path(os.path.abspath(directory))
    entry = {"session_id": None, "path": str(path), "result": None, "reasons": [], "inputs": None, "draws": None,
             "knots": None, "files": []}
    errors, headers, meta, copy = [], {}, None, None

    def read(name, whole):
        """(content or first line, sha256) of a file of the session, listed in entry["files"]; None when unreadable."""
        try:
            if whole:
                raw = (path / name).read_bytes()
                content, sha, size = raw, hashlib.sha256(raw).hexdigest(), len(raw)
            else:
                content, sha, size = _first_line(path / name)
        except FileNotFoundError:
            errors.append(f"{name}: missing")
            return None
        except OSError as error:
            errors.append(f"{name}: unreadable ({type(error).__name__}: {error})")
            return None
        entry["files"].append({"name": name, "path": str(path / name), "bytes": size, "sha256": sha})
        return content, sha

    if not path.is_dir():
        errors.append("not a directory")
    else:
        got = read("session.json", True)
        if got is not None:
            try:
                meta = json.loads(got[0])
            except ValueError as error:
                errors.append(f"session.json: not JSON ({error})")
            else:
                if not isinstance(meta, dict):
                    errors.append("session.json: not a JSON object")
                    meta = None
        copy = read("protocol.json", True)
        for name, schema in ENVELOPE_LOGS:
            got = read(name, False)
            if got is None:
                continue
            try:
                header = json.loads(got[0]) if got[0] is not None else None
            except ValueError:
                header = None
            if got[0] is None:
                errors.append(f"{name}: no complete first line")
            elif not isinstance(header, dict) or header.get("type") != "header":
                errors.append(f"{name}: its first line is not a header record")
            elif header.get("schema") != schema:
                errors.append(f"{name}: its header has the schema {_shown(header.get('schema'), 60)}, not {schema} "
                              "(the logs of the v5 profiles)")
            else:
                headers[name] = header
    if meta is not None:
        if isinstance(meta.get("session_id"), str):
            entry["session_id"] = meta["session_id"]
        errors += _session_fields(meta)
    # P1 of the G2 preparation: the protocol must be the one the session ran with, else a redraw from it says nothing.
    if copy is not None and copy[1] != protocol_sha:
        errors.append(f"protocol: its sha256 {protocol_sha} differs from that of the session's protocol.json "
                      f"{copy[1]}")
    if meta is not None and isinstance(meta.get("protocol_sha256"), str) and meta["protocol_sha256"] != protocol_sha:
        errors.append(f"protocol: its sha256 {protocol_sha} differs from session.json protocol_sha256 "
                      f"{meta['protocol_sha256']}")
    for name, header in headers.items():
        if _get(header, "protocol_sha256") != protocol_sha:
            errors.append(f"protocol: its sha256 {protocol_sha} differs from the protocol_sha256 of the header of "
                          f"{name}, {_shown(_get(header, 'protocol_sha256'), 80)}")
    if meta is not None:  # ENVELOPE_RULE: the session's own generator draws (run_session records its sha256).
        sources = meta.get("source_sha256")
        recorded = sources.get(ENVELOPE_GENERATOR, _ABSENT) if isinstance(sources, dict) else _ABSENT
        if recorded != generator_sha:
            errors.append(f"generator: the sha256 of {ENVELOPE_GENERATOR} here is {generator_sha}, session.json "
                          f"source_sha256 records {_shown(recorded, 80)} for it (run this mode from the session's "
                          "commit)")
    if errors:
        entry.update(result="data_error", reasons=errors)
        return entry
    t = meta["traffic"]
    profile, scenario, seed = t["profile"], t["scenario"], t["seeds"]["traffic"]
    entry["inputs"] = {"profile": profile, "scenario": scenario, "seed": seed, "dur_s": t["dur_s"],
                       "warmup_s": t["warmup_s"], "cycles": meta["cycles"]}
    reasons = []
    for field, own in (("scenario", "traffic.scenario"), ("seed", "traffic.seeds.traffic")):
        if not _equal(meta[field], _get(meta, own)):
            reasons.append(f"session.json: {field} is {_shown(meta[field])}, its {own} is {_shown(_get(meta, own))}")
    planned = protocol["warmup_s"] + meta["cycles"] * protocol["interval_s"]
    if not _equal(t["dur_s"], planned):
        reasons.append(f"session.json: traffic.dur_s is {_shown(t['dur_s'])}, the planned run of the protocol "
                       f"(warmup_s + cycles x interval_s) is {_shown(planned)}")
    if not _equal(t["warmup_s"], protocol["warmup_s"]):
        reasons.append(f"session.json: traffic.warmup_s is {_shown(t['warmup_s'])}, the protocol's warmup_s is "
                       f"{_shown(protocol['warmup_s'])}")
    drawn = None
    try:
        envelope, draws = envelope_redraw(protocol, profile, scenario, seed, t["dur_s"], t["warmup_s"])
    except ValueError as error:
        reasons.append(f"redraw: the generator refuses the run session.json plans ({error}), so no header of it can "
                       "carry an envelope")
    else:
        drawn = envelope.as_dict()
        entry.update(draws=draws, knots=len(envelope.t))
    parameters = protocol["profiles"][profile]
    for name, header in headers.items():
        for field, own in ENVELOPE_BINDINGS:
            found, value = _get(header, field), _get(meta, own)
            if not _equal(found, value):
                reasons.append(f"header of {name}: {field} is {_shown(found)}, session.json {own} is {_shown(value)}")
        for where, found, expected in _differences(_get(header, "profile_parameters"), parameters):
            reasons.append(f"header of {name}: profile_parameters{where} is {_shown(found)}, the protocol's "
                           f"profiles.{profile}{where} is {_shown(expected)}")
        if drawn is not None:
            reasons += [f"header of {name}: {reason}" for reason in _knot_differences(_get(header, "envelope"), drawn)]
    first, second = (headers[name] for name, _ in ENVELOPE_LOGS)
    fields = [field for field, _ in ENVELOPE_BINDINGS] + ["profile_parameters", "envelope", "run_id"]
    differ = [field for field in fields if not _equal(_get(first, field), _get(second, field))]
    if differ:
        reasons.append(f"the headers of {ENVELOPE_LOGS[0][0]} and {ENVELOPE_LOGS[1][0]} differ in: "
                       + ", ".join(differ))
    entry.update(result="mismatch" if reasons else "match", reasons=reasons)
    return entry


def envelope_line(entry):
    """The line of one session on stdout: result, session id ("-" when session.json gives none), path, reasons."""
    line = f"{entry['result']} {entry['session_id'] or '-'} {entry['path']}"
    return line + (": " + "; ".join(one_line(r) for r in entry["reasons"]) if entry["reasons"] else "")


def envelope(args, command):
    """The mode envelope (ENVELOPE_RULE): refuses an --out that exists before it reads anything, then the protocol,
    then each session in the order given; writes the new record and returns the exit code."""
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    dirs = [Path(os.path.abspath(d)) for d in args.session_dirs]
    real = [Path(os.path.realpath(d)) for d in dirs]
    twice = sorted({str(d) for d, r in zip(dirs, real) if real.count(r) > 1})
    if twice:
        print("campaign_report: a session directory is named more than once: " + ", ".join(twice), file=sys.stderr)
        return 2
    target = Path(os.path.realpath(out.parent))
    for d, r in zip(dirs, real):
        if target == r or target.is_relative_to(r):
            print(f"campaign_report: refusing to write {out} inside the session directory {d}", file=sys.stderr)
            return 2
    try:
        protocol_sha, protocol = envelope_protocol(args.protocol)
    except DataError as error:
        print(f"campaign_report: {error}", file=sys.stderr)
        return 2
    generator = os.path.abspath(host_traffic.__file__)  # The module that draws here: ENVELOPE_GENERATOR of this tree.
    with open(generator, "rb") as stream:
        generator_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    sessions = []
    for d in dirs:
        sessions.append(envelope_session(d, protocol_sha, protocol, generator_sha))
        print(envelope_line(sessions[-1]), flush=True)
    counts = {result: sum(s["result"] == result for s in sessions) for result in ENVELOPE_RESULTS}
    code = 2 if counts["data_error"] else 1 if counts["mismatch"] else 0
    identity = git_identity()
    record = {"schema": ENVELOPE_SCHEMA, "commit": identity["commit"], "commit_dirty": identity["dirty"],
              "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
              "guest": ENVELOPE_GUEST, "command": command, "n": len(sessions),
              "values": {"protocol": {"path": os.path.abspath(args.protocol), "sha256": protocol_sha},
                         "generator": {"path": generator, "sha256": generator_sha},
                         "exit_code": code, "counts": counts,
                         "mismatch": [s["session_id"] or s["path"] for s in sessions if s["result"] == "mismatch"],
                         "data_error": [s["session_id"] or s["path"] for s in sessions
                                        if s["result"] == "data_error"],
                         "sessions": sessions, "rule": ENVELOPE_RULE},
              "note": "The traffic envelope of saved sessions drawn again from the protocol (the lead's answer to "
                      "Q30); no score is read and nothing is detected."}
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        print(f"campaign_report: --out appeared meanwhile, nothing was overwritten: {out}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"campaign_report: cannot create {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        print(f"campaign_report: cannot write {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(f"campaign_report: envelope: {len(sessions)} session(s), {counts['match']} match, {counts['mismatch']} "
          f"mismatch, {counts['data_error']} data error; record {out}", file=sys.stderr)
    return code


# ---------------------------------------------------------------- G2 tables of map rows 4 to 6 and 14 (package H1b6b)
# The modes marked, load and realism (criteria marked_rows_per_event, profiles_load and traffic_realism of stage G2 and
# the value invalid_rows.max): the readers they share, then each mode. All three honour the records of skuska/g2.py.

G2T_RECORD_SCHEMA = "hyptcn3/g2-session/1"  # skuska/g2.py SESSION_SCHEMA: the record of one G2 session.
G2T_ROLE = "diagnostic"  # skuska/g2.py ROLE: every session of G2 is a diagnostic run (map point A).
G2T_H4_KINDS = ("cas", "fault", "fault_clean")  # skuska/cas.py KIND, skuska/poruchy.py KIND_FAULT and KIND_CLEAN.
G2T_FAULT_KIND = "fault"  # skuska/poruchy.py KIND_FAULT: a session of the fault plan with its fault.
G2T_RECORDS_RULE = (
    "The records of the G2 driver decide which session a table counts (packages H1a to H1b5, the lead's answers Q49 "
    "and Q60 to Q62). Every session the mode reads is a diagnostic run whose record <--g2-dir>/zaznamy/<session "
    "id>.json (schema hyptcn3/g2-session/1, skuska/g2.py Block.record; --g2-dir defaults to skuska/g2.py G2_DIR) names "
    "it by its session_id, its directory (values.session_dir, as real paths), its VM and the sha256 of its "
    "session.json (values.session_json_sha256); a session without that record, or with the record of another "
    "session, is a data error. Of the record the mode reads values.kind, values.excluded.criteria (null, or the "
    "criteria and values of G2 whose tables leave the session out, written by the tool that planned it: the "
    "ground-truth sessions, Q62; the timing sessions of H4, Q49 and Q51; the parity sessions, Q61), values.counted "
    "with values.load.summary.reasons (map point B, skuska/g2.py LOAD_RULE: a session whose measured phase held a "
    "heavy process or a run outside its block's plan, or whose samples do not cover it, counts for no table), "
    "values.done (skuska/g2.py DONE_RULE), values.beside (the fault hook of skuska/poruchy.py, with the fault and "
    "whether it was induced, and any hook that says g2_values false: no value of G2, Q60 and Q61), values.audit, "
    "values.group and values.levels_after. A session a rule leaves out of a table is listed with the rule's words "
    "and never counted.")


def _g2t_read(path, files, name):
    """The bytes of a file a G2 table reads, listed in `files` with its path, size and sha256; a DataError by name."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise DataError(f"{path}: cannot be read ({type(error).__name__}: {error})") from None
    files.append({"name": name, "path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return raw


def _g2t_json(path, files, name, schema=None):
    """(the JSON object of a file a G2 table reads, its sha256), the file listed in `files`; a DataError by name."""
    raw = _g2t_read(path, files, name)
    try:
        doc = json.loads(raw)
    except ValueError as error:
        raise DataError(f"{path}: not JSON ({error})") from None
    if not isinstance(doc, dict):
        raise DataError(f"{path}: not a JSON object")
    if schema is not None and doc.get("schema") != schema:
        raise DataError(f"{path}: its schema is {_shown(_get(doc, 'schema'), 60)}, not {schema}")
    return doc, files[-1]["sha256"]


def _g2t_hash(path, files, name):
    """A large file a G2 table reads through another module (a traffic log), listed in `files` with its sha256."""
    try:
        with open(path, "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            size = stream.tell()
    except OSError as error:
        raise DataError(f"{path}: cannot be read ({type(error).__name__}: {error})") from None
    files.append({"name": name, "path": str(path), "bytes": size, "sha256": digest})


def g2t_record(g2_dir, directory, meta, meta_sha, files):
    """The G2 record of the session in `directory` (G2T_RECORDS_RULE) and what it says of the session: {path, sha256,
    kind, excluded, excluded_rule, counted, load_reasons, fault, induced, g2_values, done, values}."""
    sid = meta.get("session_id")
    path = Path(g2_dir) / "zaznamy" / f"{sid}.json"
    if not path.is_file():
        raise DataError(f"{directory}: no G2 record of the session ({path}): the tables of G2 count only sessions "
                        "whose records say whether they count")
    doc, sha = _g2t_json(path, files, "G2 record", G2T_RECORD_SCHEMA)
    v = doc.get("values")
    if (not isinstance(v, dict) or v.get("session_id") != sid or not isinstance(v.get("session_dir"), str)
            or os.path.realpath(v["session_dir"]) != os.path.realpath(directory) or v.get("vm") != meta.get("vm")
            or v.get("session_json_sha256") != meta_sha):
        v = v if isinstance(v, dict) else {}
        raise DataError(f"{path}: the G2 record is of the session {_shown(_get(v, 'session_id'), 80)} in "
                        f"{_shown(_get(v, 'session_dir'))} on VM {_shown(_get(v, 'vm'), 20)} with the session.json "
                        f"{_shown(_get(v, 'session_json_sha256'), 80)}, not of {sid} in {directory} on VM "
                        f"{meta.get('vm')} with {meta_sha}")
    excluded = v.get("excluded")
    criteria = excluded.get("criteria") if isinstance(excluded, dict) else None
    if excluded is not None and not (isinstance(criteria, list) and all(isinstance(c, str) for c in criteria)):
        raise DataError(f"{path}: values.excluded is neither null nor {{criteria: [names], rule}}")
    beside = [b for b in v.get("beside") or [] if isinstance(b, dict)]
    fault = next((b for b in beside if b.get("hook") == "fault"), None)
    load = v.get("load") if isinstance(v.get("load"), dict) else {}
    reasons = load.get("summary", {}).get("reasons") if isinstance(load.get("summary"), dict) else None
    return {"path": str(path), "sha256": sha, "kind": v.get("kind"), "excluded": criteria or [],
            "excluded_rule": excluded.get("rule") if isinstance(excluded, dict) else None,
            "counted": v.get("counted") is True,
            "load_reasons": ([one_line(str(r)) for r in reasons] if isinstance(reasons, list)
                             else ["the record holds no summary of the host load (values.load.summary)"]),
            "fault": None if fault is None else fault.get("fault"),
            "induced": None if fault is None else fault.get("induced"),
            "g2_values": not any(b.get("g2_values") is False for b in beside), "done": v.get("done") is True,
            "values": v}


def g2t_left_out(record, names, *, h4=False):
    """Why the record leaves its session out of a table of the criterion and values `names` (G2T_RECORDS_RULE), None
    when it does not; h4: a table of Q49, which counts no session of H4 and none that gives no value of G2."""
    named = [name for name in names if name in record["excluded"]]
    if named:
        return (f"its record leaves it out of {', '.join(named)} (values.excluded"
                + (f": {one_line(record['excluded_rule'])}" if record["excluded_rule"] else "") + ")")
    if h4 and record["kind"] in G2T_H4_KINDS:
        return f"a session of H4 (kind {record['kind']}): Q49 counts none"
    if h4 and not record["g2_values"]:
        return "a hook beside its run says that it gives no value of G2 (values.beside, g2_values false)"
    if not record["counted"]:
        return "not counted by the host load (skuska/g2.py LOAD_RULE): " + "; ".join(record["load_reasons"])
    return None


def g2t_session(path, g2_dir):
    """A session directory of a G2 table: {path, session_id, vm, scenario, meta, meta_sha, protocol, protocol_sha,
    binding, record, files}, its session.json and protocol.json read and its record bound; a DataError by name."""
    from scripts import gates
    directory = Path(os.path.abspath(path))
    if not directory.is_dir():
        raise DataError(f"{directory}: not a session directory")
    files = []
    meta, meta_sha = _g2t_json(directory / "session.json", files, "session.json")
    sid, vm = meta.get("session_id"), meta.get("vm")
    if not isinstance(sid, str) or not SAFE_ID.fullmatch(sid) or not isinstance(vm, str):
        raise DataError(f"{directory}: session.json names no session_id or no vm")
    if meta.get("role") != G2T_ROLE:
        raise DataError(f"{directory}: session.json names the role {_shown(_get(meta, 'role'), 40)}, not {G2T_ROLE} "
                        "(the sessions of G2 are diagnostic runs)")
    protocol, protocol_sha = _g2t_json(directory / "protocol.json", files, "protocol.json")
    if meta.get("protocol_sha256") != protocol_sha:
        raise DataError(f"{directory}: protocol.json has the sha256 {protocol_sha}, session.json binds "
                        f"{_shown(_get(meta, 'protocol_sha256'), 80)}")
    if protocol.get("schema") != protocol_v5.SCHEMA:
        raise DataError(f"{directory}: protocol.json is no protocol of schema {protocol_v5.SCHEMA}")
    try:
        binding = gates.stage_binding(directory / "protocol.json", "G0")[0]
    except ValueError as error:
        raise DataError(f"{directory}: protocol.json has no G0 binding ({error})") from None
    record = g2t_record(g2_dir, directory, meta, meta_sha, files)
    return {"path": str(directory), "session_id": sid, "vm": vm, "scenario": meta.get("scenario"), "meta": meta,
            "meta_sha": meta_sha, "protocol": protocol, "protocol_sha": protocol_sha, "binding": binding,
            "record": record, "files": files}


def g2t_windows(directory, meta, files):
    """The event windows of a session as its log audit takes them (scripts/collection_logs.py event_window, with the
    session's event_grace_s): (records of events.json, [(index, record, low, high)], [{index, type, why}] of the
    occurrences without a window, why there are none or None); a DataError for an unreadable events.json."""
    from scripts.collection_logs import event_window
    if not meta.get("events"):
        return [], [], [], "the session plans no events"
    path = Path(directory) / "events.json"
    if not path.is_file():
        return [], [], [], "session.json plans events and the session has no events.json"
    doc, _ = _g2t_json(path, files, "events.json", "hyptcn3/session-events/1")
    records = doc.get("events")
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise DataError(f"{path}: events is no list of records")
    windows, unwindowed = [], []
    for index, record in enumerate(records):
        try:
            window = event_window(record, meta.get("event_grace_s"))
        except (ValueError, TypeError) as error:
            raise DataError(f"{path}: occurrence {index} cannot be windowed ({error})") from None
        if window is None:
            unwindowed.append({"index": index, "type": record.get("type"),
                               "why": "no host start" if "host_start_unix" not in record else "no host stop done"})
        else:
            windows.append((index, record, *window))
    return records, windows, unwindowed, None if windows else "no occurrence was started and stopped"


def _g2t_ratio(numerator, denominator):
    """numerator / denominator rounded to 6 decimals; None when the denominator is 0 or either is no number."""
    return (round(numerator / denominator, 6) if _number(numerator) and _number(denominator) and denominator
            else None)


def g2t_distribution(values):
    """distribution() of the numbers among `values` (n, min, nearest-rank median, max, as the per-session values of
    the summary of this report)."""
    return distribution([v for v in values if _number(v)])


def g2t_write(out, record):
    """Write the new record `out` (refused when it appeared meanwhile); None, or why it was not written."""
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        return f"--out appeared meanwhile, nothing was overwritten: {out}"
    except OSError as error:
        return f"cannot create {out}: {type(error).__name__}: {error}"
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        return f"cannot write {out}: {type(error).__name__}: {error}"
    return None


def g2t_header(schema, command, n, guest, values, note):
    """A record with the provenance header of check E of scripts/check_claims.sh and the stage G2."""
    identity = git_identity()
    return {"schema": schema, "commit": identity["commit"], "commit_dirty": identity["dirty"],
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
            "guest": guest, "command": command, "n": n, "values": {"stage": "G2", **values}, "note": note}


def g2t_inputs(paths, what):
    """The absolute paths of the inputs, or why they are refused: one named twice (as real paths)."""
    paths = [os.path.abspath(path) for path in paths]
    real = [os.path.realpath(path) for path in paths]
    twice = sorted({path for path, r in zip(paths, real) if real.count(r) > 1})
    return paths, (f"{what} is named more than once: " + ", ".join(twice) if twice else None)


def g2t_inside(out, directories):
    """The refusals of an --out inside a session directory."""
    target = Path(os.path.realpath(out.parent))
    return [f"refusing to write {out} inside the session directory {d}" for d in directories
            if target == Path(os.path.realpath(d)) or target.is_relative_to(os.path.realpath(d))]


def g2t_g2_dir(args):
    """--g2-dir, or skuska/g2.py G2_DIR, the G2 directory of the stage's evidence (its zaznamy/ holds the records)."""
    if args.g2_dir is not None:
        return Path(os.path.abspath(args.g2_dir))
    from skuska import g2
    return g2.G2_DIR


# ---------------------------------------------------------------- marked mode (marked_rows_per_event, invalid_rows.max)

MARKED_TABLE_SCHEMA = "hyptcn3/g2-marked-table/1"
MARKED_CRITERION, MARKED_VALUE = "marked_rows_per_event", "invalid_rows.max"
# The model of the lead's answer to Q49 (map question 4), constants written before the data.
MARKED_ALPHA = 0.01  # P(N > k) below 1 % (proposal 10.9).
MARKED_CAP = 6  # At most 6 (proposal 10.9, decision D4; scripts/protocol_v5.py MAX_INVALID_ROWS).
MARKED_PER_OCCURRENCE = 2  # The boundaries of an occurrence: its start and its stop.
MARKED_PER_SESSION = 6  # N ~ Poisson(6 lambda): the six boundaries of a session with three events.
MARKED_ABOVE = 3  # Skeleton section 4: above 3, min_score_coverage falls below 557/720 (SULAD_S_TEXTOM_PRACE.md).
MARKED_GUEST = ("none: the mode marked reads saved audit records, their feature archives (numpy.load with "
                "allow_pickle=False), session files and the records of G2; no VM is contacted and no RAM image is "
                "opened")
MARKED_MODEL_RULE = (
    "The lead's answer to Q49 (map question 4, 2026-11-24, with his addition for lambda = 0), written before the "
    "data: lambda = the invalid rows with the traversal processes (a traversal of invalid_rows.traversals of the "
    "protocol among the row's truncated_traversals) inside the windows of the occurrences / (2 x the occurrences with "
    "a window, all six types of events.types with naprazdno), over the sessions this table counts on both VMs; N ~ "
    "Poisson(6 lambda), the invalid rows of one session with three events; invalid_rows.max = the smallest k <= 6 "
    "with P(N > k) < 0.01 (strictly, as proposal 10.9 says; features/audit_policy.py poisson_quantile tests "
    "P(X <= b) >= 0.99, which differs only at equality); no such k is a finding and gives no value. Beside it, "
    "descriptive only: the rate per type (lambda_T = the rows inside the windows of type T / (2 x its occurrences), "
    "and the k it would give) and a variant with a background term (N ~ Poisson(6 lambda + beta), beta = the invalid "
    "rows with processes outside every window of the counted sessions / the counted sessions, and its k). Invalid "
    "rows outside every window are a finding to explain before any write (harness 5.1). At lambda = 0 it is a "
    "finding (the condition under which decision D4 is reopened, proposal 12) and also a write: max 0. "
    "min_score_coverage follows from max by the inequality of invalid_rows.note, (ideal - 33 (max + 1)) / cycles < "
    "gate <= (ideal - 33 max) / cycles, its upper end (as 557/720 for today's max 3): features/acceptance.py "
    "gate_interval of --protocol with that max, the code with which the protocol's self-check judges the gate. Above "
    "3 the skeleton's section 4 asks for an entry in SULAD_S_TEXTOM_PRACE.md (a finding). The rows a parser rule "
    "closed are valid rows: the table counts them and they go only to G3b (audit.rule_closed_rows_max, "
    "audit.early_stop), never into lambda. The mode proposes the values and writes nothing into the protocol.")
MARKED_RULE = (
    "The criterion marked_rows_per_event of stage G2 (scripts/gates.py CRITERIA, the lead's G2 skeleton: the rows the "
    "rule marks per occurrence, by type, and from them the rate per event boundary for invalid_rows.max) and the "
    "value invalid_rows.max (map rows 4 and 14). The mode reads each audit record given (scripts/collection.py "
    "audit, schema hyptcn3/collection-audit/1), each once and one per session, and of it: the session's session.json "
    "(the one values.session_sha256 binds) and protocol.json (values.protocol_sha256), whose G0 binding "
    "(scripts/gates.py stage_binding: the protocol without the paths of later stages, which the writes of G2 change) "
    "must be that of --protocol, its events.json, the feature archive the audit wrote (values.features, with the "
    "sha256 values.features_sha256, read with numpy.load(allow_pickle=False): seq, casy, valid and quality_json, whose "
    "invalid rows and rows closed by a parser rule must be those of values.acceptance.facts) and the session's G2 "
    "record (G2T_RECORDS_RULE). The marked rows are those of features/acceptance.py MARKED_ROWS_RULE: the invalid "
    "rows (with the traversal processes, or invalid otherwise) and the rows a parser rule closed (quality "
    "process_walk prev, tail or meet), each at its snapshot time; the windows are those of the log audit "
    "(scripts/collection_logs.py event_window: host_start_unix - 1 s to host_stopped_unix + the session's "
    "event_grace_s), and the counts by type must equal the audit's values.marked_rows_by_type, "
    "event_occurrences_by_type and marked_rows_outside_events (when the audit counted none, the session is not "
    "counted and the audit's marked_rows_note says why). Per occurrence with a window: its session, VM, scenario, "
    "type, planned times and phases, host times, window, the phase of each boundary against the collector's grid "
    "((host_start_unix - grid_phase_s) mod interval_s for the start, host_stop_unix for the stop, grid_phase_s of the "
    "audit's values.timing), and the rows inside its window, invalid with processes, invalid otherwise and closed by "
    "a rule, each at the start or at the stop: a row belongs to the start when its time lies at or before the middle "
    "of host_start_unix and host_stop_unix, else to the stop (the executor's judgment). The sums by type are made "
    "over the sessions of both VMs that the table counts, each VM also apart. A session counts (Q49) when it is an "
    "audited session of H3 with events, accepted or refused: its record leaves it out of neither "
    "marked_rows_per_event nor invalid_rows.max (values.excluded), it is no session of H4 (kind cas, fault or "
    "fault_clean), no hook says that it gives no value of G2, the host load counts it (values.counted), and it has an "
    "occurrence with a window; every other session is listed with why. The minimum (the occurrences of Q43, which "
    "the deck of skuska/g2.py deals and which event_effects counts as well): every type of events.types with at "
    "least 19 counted occurrences with a window on both VMs together and at least 8 on each VM of --protocol; each "
    "one missing is named. Findings, none a refusal: invalid rows outside every window of a counted session, invalid "
    "rows of a cause the rule does not tolerate (a traversal outside invalid_rows.traversals, read errors, zeroed "
    "bytes), a row inside two windows, and those of MARKED_MODEL_RULE. Refused by name, each a data error: an audit "
    "record named twice, two audits of one session, a file missing, unreadable or of another schema, a feature "
    "archive or a session file other than the audit's, a protocol.json whose G0 binding is not that of --protocol, no "
    "G2 record of the session, counts that differ from the audit's, a marked row without a time, and an --out that "
    "exists (refused before anything is read) or lies inside a session directory. Exit 0: the table is written to "
    "--out, a new JSON record with the provenance header of check E, and every minimum is met; 1: the table is "
    "written and a minimum is missing, named; 2: a usage or data error, every refusal named on stderr and nothing "
    "written.")
MARKED_PARTS = ("invalid_processes", "invalid_other", "rule_closed")


def marked_protocol(path):
    """(sha256, document, G0 binding, event types, VMs, the traversals of invalid_rows) of --protocol of the mode
    marked; a DataError before any audit is read."""
    from features.acceptance import gate_interval
    from features.quality import invalid_rows_rule
    from scripts import gates
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as error:
        raise DataError(f"cannot read protocol {path}: {error}") from None
    if type(doc) is not dict or doc.get("schema") != protocol_v5.SCHEMA:
        raise DataError(f"protocol {path}: protocol schema is not {protocol_v5.SCHEMA}")
    try:
        rule = invalid_rows_rule(doc)
        types = sorted(doc["events"]["types"])
        vms = [row["name"] for row in doc["vms"]]
        if rule is None or not _number(doc["interval_s"]) or doc["interval_s"] <= 0 or len(vms) < 2:
            raise ValueError("no invalid_rows rule, no interval_s above 0 or fewer than two VMs")
        gate_interval(doc)  # The gate of the proposal is computed by it; a protocol it cannot judge is refused now.
        binding = gates.stage_binding(path, "G0")[0]
    except (ValueError, KeyError, TypeError) as error:
        raise DataError(f"protocol {path}: not a protocol the table can judge ({type(error).__name__}: "
                        f"{error})") from None
    return (hashlib.sha256(raw).hexdigest(), doc, binding, types, vms,
            [str(name) for name in rule["traversals"]])


def _marked_archive(raw, path, facts):
    """[(seq, time, valid, quality)] of the rows of a feature archive (numpy.load with allow_pickle=False), whose
    invalid rows and rows closed by a parser rule must be those of the audit's facts; a DataError by name."""
    from features.acceptance import RULE_CLOSED_WALKS
    try:
        with np.load(io.BytesIO(raw), allow_pickle=False) as data:
            seq = [int(s) for s in data["seq"]]
            times = [float(t) for t in data["casy"]]
            valid = [bool(x) for x in data["valid"]]
            quality = json.loads(str(data["quality_json"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise DataError(f"{path}: the feature archive cannot be read ({type(error).__name__}: {error})") from None
    if not isinstance(quality, list) or not len(seq) == len(times) == len(valid) == len(quality):
        raise DataError(f"{path}: seq, casy, valid and quality_json of the feature archive differ in length")
    if not all(math.isfinite(t) for t in times):
        raise DataError(f"{path}: a row of the feature archive has no finite time")
    rows = list(zip(seq, times, valid, quality))
    invalid = sorted(s for s, _, good, _ in rows if not good)
    closed = sorted(s for s, _, _, q in rows if isinstance(q, dict) and q.get("process_walk") in RULE_CLOSED_WALKS)
    try:
        listed = sorted(int(row["seq"]) for row in facts["invalid_rows"])
        listed_closed = sorted(int(s) for s in facts["rule_closed_seq"])
    except (KeyError, TypeError, ValueError):
        raise DataError(f"{path}: the audit's values.acceptance.facts hold no invalid_rows and "
                        "rule_closed_seq") from None
    if invalid != listed or closed != listed_closed:
        raise DataError(f"{path}: the invalid rows or the rows closed by a parser rule of the feature archive differ "
                        "from the audit's values.acceptance.facts")
    return rows


def _marked_class(quality, traversals):
    """(the part of an invalid row: invalid_processes or invalid_other, whether the rule would tolerate its cause)."""
    names = quality.get("truncated_traversals") if isinstance(quality, dict) else None
    names = [str(n) for n in names] if isinstance(names, list) else []
    tolerated = (bool(names) and set(names) <= set(traversals) and type(quality.get("read_errors")) is int
                 and not quality["read_errors"] and type(quality.get("filled_zero")) is int
                 and not quality["filled_zero"])
    return ("invalid_processes" if any(n in traversals for n in names) else "invalid_other"), tolerated


def marked_audit(path, binding, types, traversals, g2_dir):
    """One audit record by MARKED_RULE: (its session's entry, its occurrence rows); a DataError by name."""
    from features.acceptance import RULE_CLOSED_WALKS, marked_rows_by_type
    from scripts import gates
    files = []
    audit, audit_sha = _g2t_json(path, files, "audit record", AUDIT_SCHEMA)
    v = audit.get("values")
    if not isinstance(v, dict) or not isinstance(v.get("session_dir"), str):
        raise DataError(f"{path}: an audit record without values.session_dir")
    directory = Path(v["session_dir"])
    meta, meta_sha = _g2t_json(directory / "session.json", files, "session.json")
    if meta_sha != v.get("session_sha256"):
        raise DataError(f"{path}: {directory / 'session.json'} is not the session.json the audit read (its sha256 "
                        f"{meta_sha}, values.session_sha256 {_shown(_get(v, 'session_sha256'), 80)})")
    sid, vm = meta.get("session_id"), meta.get("vm")
    if not isinstance(sid, str) or not SAFE_ID.fullmatch(sid) or not isinstance(vm, str):
        raise DataError(f"{directory}: session.json names no session_id or no vm")
    if meta.get("role") != G2T_ROLE:
        raise DataError(f"{directory}: session.json names the role {_shown(_get(meta, 'role'), 40)}, not {G2T_ROLE} "
                        "(the sessions of G2 are diagnostic runs)")
    protocol, protocol_sha = _g2t_json(directory / "protocol.json", files, "protocol.json")
    if protocol_sha != v.get("protocol_sha256") or protocol_sha != meta.get("protocol_sha256"):
        raise DataError(f"{path}: {directory / 'protocol.json'} (sha256 {protocol_sha}) is not the protocol the audit "
                        f"read ({_shown(_get(v, 'protocol_sha256'), 80)}) or the one session.json binds")
    try:
        mine = gates.stage_binding(directory / "protocol.json", "G0")[0]
    except ValueError as error:
        raise DataError(f"{directory}: protocol.json has no G0 binding ({error})") from None
    if mine != binding:
        raise DataError(f"{directory}: protocol.json has the G0 binding {mine}, --protocol {binding}: another "
                        "protocol, not one that differs only in the values of later stages")
    record = g2t_record(g2_dir, directory, meta, meta_sha, files)
    features = v.get("features")
    if not isinstance(features, str):
        raise DataError(f"{path}: values.features names no feature archive")
    raw = _g2t_read(features, files, "feature archive")
    if files[-1]["sha256"] != v.get("features_sha256"):
        raise DataError(f"{features}: its sha256 is {files[-1]['sha256']}, the audit's values.features_sha256 "
                        f"{_shown(_get(v, 'features_sha256'), 80)}")
    rows = _marked_archive(raw, features, _get(v, "acceptance.facts"))
    _, windows, unwindowed, none = g2t_windows(directory, meta, files)
    interval = protocol.get("interval_s")
    if not _number(interval) or interval <= 0:
        raise DataError(f"{directory}: protocol.json has no interval_s above 0")
    grid = _get(v, "timing.grid_phase_s")
    grid = grid if _number(grid) else None
    marked = []  # (seq, time, part, whether the rule would tolerate its cause)
    for seq, t, good, quality in rows:
        if not good:
            marked.append((seq, t, *_marked_class(quality, traversals)))
        if isinstance(quality, dict) and quality.get("process_walk") in RULE_CLOSED_WALKS:
            marked.append((seq, t, "rule_closed", True))
    # The audit's own counts by type, made again from the same rows and windows (MARKED_ROWS_RULE).
    counts = {key: v.get(key) for key in ("marked_rows_by_type", "event_occurrences_by_type",
                                          "marked_rows_outside_events")}
    if all(value is not None for value in counts.values()):
        flagged = sorted({seq for seq, _, _, _ in marked})
        again = marked_rows_by_type(flagged, {seq: t for seq, t, _, _ in rows},
                                    [(str(r.get("type")), lo, hi) for _, r, lo, hi in windows], types)
        if list(again) != [counts["marked_rows_by_type"], counts["event_occurrences_by_type"],
                           counts["marked_rows_outside_events"]]:
            raise DataError(f"{path}: the marked rows by type counted again ({again[0]}, {again[1]}, outside "
                            f"{again[2]}) differ from the audit's values ({counts['marked_rows_by_type']}, "
                            f"{counts['event_occurrences_by_type']}, outside {counts['marked_rows_outside_events']})")

    def phase(unix):
        return None if grid is None or not _number(unix) else round((unix - grid) % interval, 6)

    occurrences, inside = [], defaultdict(list)
    for index, r, lo, hi in windows:
        start = r["host_start_unix"]
        stop = r.get("host_stop_unix") if _number(r.get("host_stop_unix")) else r["host_stopped_unix"]
        middle = (start + stop) / 2
        parts = {"start": {part: [] for part in MARKED_PARTS}, "stop": {part: [] for part in MARKED_PARTS}}
        for seq, t, part, _ in marked:
            if lo <= t <= hi:
                parts["start" if t <= middle else "stop"][part].append(seq)
                inside[(seq, part)].append(index)
        occurrences.append({
            "session_id": sid, "vm": vm, "scenario": meta.get("scenario"), "index": index, "type": r.get("type"),
            "planned": {key: r.get(key) for key in ("start_s", "duration_s", "start_phase_s", "stop_phase_s")},
            "host": {key: r.get(key) for key in ("host_start_unix", "host_started_unix", "host_stop_unix",
                                                 "host_stopped_unix")},
            "window": [lo, hi], "middle_unix": middle,
            "phase_s": {"start": phase(start), "stop": phase(stop), "interval_s": interval, "grid_phase_s": grid},
            "executed": r.get("executed"), "effect_ok": (r.get("effect") or {}).get("ok")
            if isinstance(r.get("effect"), dict) else None, **parts})
    outside = {part: [{"seq": seq, "time_unix": t} for seq, t, p, _ in marked if p == part and (seq, p) not in inside]
               for part in MARKED_PARTS}
    why = g2t_left_out(record, (MARKED_CRITERION, MARKED_VALUE), h4=True)
    if why is None and not all(value is not None for value in counts.values()):
        why = "the audit counted no marked rows by type: " + one_line(str(v.get("marked_rows_note")))
    if why is None and not windows:
        why = none
    entry = {"session_id": sid, "vm": vm, "scenario": meta.get("scenario"), "kind": record["kind"],
             "path": str(directory),
             "audit": {"path": os.path.abspath(path), "sha256": audit_sha, "accepted": v.get("accepted"),
                       "reasons": v.get("reasons")},
             "record": {"path": record["path"], "sha256": record["sha256"]},
             "protocol_sha256": protocol_sha, "grid_phase_s": grid, "occurrences": len(windows),
             "unwindowed": unwindowed, "audit_counts": counts,
             "rows": {part: sum(p == part for _, _, p, _ in marked) for part in MARKED_PARTS},
             "rows_in_windows": {part: len({seq for seq, p in inside if p == part}) for part in MARKED_PARTS},
             "outside": outside,
             "outside_rule": sorted({seq for seq, _, part, tolerated in marked
                                     if part != "rule_closed" and not tolerated}),
             "in_two_windows": sorted({seq for (seq, _), where in inside.items() if len(where) > 1}),
             "counted": why is None, "why_not_counted": why, "files": files}
    for row in occurrences:
        row["counted"] = entry["counted"]
    return entry, occurrences


def marked_sums(occurrences, types, vms):
    """The sums by type over the counted occurrences (MARKED_RULE): per type the occurrences and the rows of each part
    at the start and at the stop, both VMs together and each apart, the rows per occurrence and per boundary."""
    out = {}
    for kind in types:
        mine = [row for row in occurrences if row["counted"] and row["type"] == kind]
        n = len(mine)
        entry = {"occurrences": {"both": n, "by_vm": {vm: sum(row["vm"] == vm for row in mine) for vm in vms}}}
        for part in MARKED_PARTS:
            start, stop = (sum(len(row[end][part]) for row in mine) for end in ("start", "stop"))
            entry[part] = {"start": start, "stop": stop, "total": start + stop,
                           "by_vm": {vm: sum(len(row[end][part]) for row in mine if row["vm"] == vm
                                             for end in ("start", "stop")) for vm in vms}}
        entry["per_occurrence"] = {part: _g2t_ratio(entry[part]["total"], n) for part in MARKED_PARTS}
        entry["per_boundary"] = _g2t_ratio(entry["invalid_processes"]["total"], MARKED_PER_OCCURRENCE * n)
        out[kind] = entry
    return out


def poisson_above(mu, k):
    """P(N > k) for N ~ Poisson(mu), mu >= 0 (MARKED_MODEL_RULE)."""
    if mu == 0:
        return 0.0
    term = total = math.exp(-mu)
    for i in range(1, k + 1):
        term *= mu / i
        total += term
    return max(0.0, 1.0 - total)


def marked_k(mu):
    """The smallest k <= MARKED_CAP with P(N > k) < MARKED_ALPHA for N ~ Poisson(mu); None when there is none."""
    return next((k for k in range(MARKED_CAP + 1) if poisson_above(mu, k) < MARKED_ALPHA), None)


def marked_gate(protocol, k):
    """The coverage gates that admit exactly k isolated invalid rows, features/acceptance.py gate_interval of the
    protocol with invalid_rows.max k (the inequality of invalid_rows.note): {low, high, low_windows, high_windows,
    cycles}; min_score_coverage is the upper end."""
    from features.acceptance import gate_interval
    doc = json.loads(json.dumps(protocol))
    doc["invalid_rows"]["max"] = k
    low, high = gate_interval(doc)
    cycles = doc["cycles"]
    return {"low": low, "high": high, "low_windows": round(low * cycles, 6), "high_windows": round(high * cycles, 6),
            "cycles": cycles}


def marked_model(rows, occurrences, by_type, outside, sessions, protocol):
    """MARKED_MODEL_RULE over `rows` invalid rows with processes inside the windows of `occurrences` counted
    occurrences (by_type: {type: (rows, occurrences)}), `outside` such rows outside every window of `sessions` counted
    sessions: the rate per boundary, the proposal of invalid_rows.max and min_score_coverage, the variants beside it
    and the findings of the rule."""
    boundaries = MARKED_PER_OCCURRENCE * occurrences
    lam = rows / boundaries if boundaries else None
    mu = None if lam is None else MARKED_PER_SESSION * lam
    k = None if mu is None else marked_k(mu)
    out = {"rule": MARKED_MODEL_RULE,
           "constants": {"alpha": MARKED_ALPHA, "cap": MARKED_CAP, "boundaries_per_occurrence": MARKED_PER_OCCURRENCE,
                         "boundaries_per_session": MARKED_PER_SESSION},
           "rows_in_windows": rows, "occurrences": occurrences, "boundaries": boundaries, "lambda": lam, "mu": mu,
           "p_above": None if mu is None else [poisson_above(mu, j) for j in range(MARKED_CAP + 1)],
           "proposal": None, "per_type": {}, "background": None, "findings": []}
    for kind, (mine, n) in by_type.items():
        rate = mine / (MARKED_PER_OCCURRENCE * n) if n else None
        out["per_type"][kind] = {"rows": mine, "occurrences": n, "lambda": rate,
                                 "k": None if rate is None else marked_k(MARKED_PER_SESSION * rate)}
    beta = outside / sessions if sessions else None
    if mu is not None and beta is not None:
        out["background"] = {"rows_outside": outside, "sessions": sessions, "beta": beta, "mu": mu + beta,
                             "k": marked_k(mu + beta)}
    if mu is None:
        out["findings"].append("no counted occurrence with a window: no rate per boundary and no proposal")
        return out
    if k is None:
        out["findings"].append(f"no k <= {MARKED_CAP} has P(N > k) < {MARKED_ALPHA:g} at lambda {lam:.6g} (N ~ "
                               f"Poisson({mu:.6g}), P(N > {MARKED_CAP}) = {poisson_above(mu, MARKED_CAP):.6g}): no "
                               "value of invalid_rows.max by the rule")
        return out
    gate = marked_gate(protocol, k)
    out["proposal"] = {MARKED_VALUE: k, "min_score_coverage": gate["high"], "gate_interval": gate,
                       "p_above": poisson_above(mu, k),
                       "writes": "nothing: the mode proposes; tcn/hodnoty.py writes the values of G2 (package H5)"}
    if rows == 0:
        out["findings"].append("lambda = 0: no invalid row with processes inside a window, the condition under which "
                               "decision D4 is reopened (proposal 12), a finding and also a write: invalid_rows.max 0 "
                               f"and min_score_coverage {gate['high']:.10g} ({gate['high_windows']:g}/{gate['cycles']} "
                               "windows) by the inequality of invalid_rows.note (the lead's addition to Q49)")
    if k > MARKED_ABOVE:
        out["findings"].append(f"invalid_rows.max {k} is above {MARKED_ABOVE}: min_score_coverage falls to "
                               f"{gate['high_windows']:g}/{gate['cycles']}, below 557/720, and the sentence of the "
                               "thesis on 85 % (3.2.3) holds even less: an entry in SULAD_S_TEXTOM_PRACE.md and in the "
                               "report (skeleton section 4); the decision stays")
    return out


def marked_line(kind, row):
    """The line of one event type on stdout."""
    n = row["occurrences"]
    parts = ", ".join(f"{part.replace('_', ' ')} {row[part]['start']}/{row[part]['stop']}" for part in MARKED_PARTS)
    return (f"{kind}: {n['both']} occurrence(s) (" + ", ".join(f"VM {vm} {c}" for vm, c in n["by_vm"].items())
            + f"); rows at the start/stop: {parts}; per boundary {row['per_boundary']}")


def marked_table(args, command):
    """The mode marked (MARKED_RULE): refuses an --out that exists before it reads anything and an audit named twice,
    then reads the protocol and every audit; writes the new record, prints one line per type and the proposal, and
    returns the exit code."""
    from skuska import g2
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths, twice = g2t_inputs(args.audits, "an audit record")
    if twice:
        print(f"campaign_report: marked: {twice}", file=sys.stderr)
        return 2
    try:
        protocol_sha, protocol, binding, types, vms, traversals = marked_protocol(args.protocol)
    except DataError as error:
        print(f"campaign_report: marked: {error}", file=sys.stderr)
        return 2
    g2_dir = g2t_g2_dir(args)
    entries, occurrences, refused = [], [], []
    for path in paths:
        try:
            entry, rows = marked_audit(path, binding, types, traversals, g2_dir)
        except DataError as error:
            refused.append(str(error))
            continue
        entries.append(entry)
        occurrences += rows
    by_session = defaultdict(list)
    for entry in entries:
        by_session[os.path.realpath(entry["path"])].append(entry["audit"]["path"])
    refused += [f"{len(audits)} audit records name one session, {directory}: " + ", ".join(audits)
                + " (a session counts once)" for directory, audits in by_session.items() if len(audits) > 1]
    refused += g2t_inside(out, [entry["path"] for entry in entries])
    if refused or not entries:
        for why in refused or ["no audit record"]:
            print(f"campaign_report: marked: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: marked: {len(refused)} refusal(s): no table, nothing written", file=sys.stderr)
        return 2
    counted = [entry for entry in entries if entry["counted"]]
    sums = marked_sums(occurrences, types, vms)
    missing = []
    for kind in types:
        n = sums[kind]["occurrences"]
        if n["both"] < g2.OCCURRENCES:
            missing.append(f"{kind}: {n['both']} of {g2.OCCURRENCES} occurrences counted on both VMs together "
                           f"({g2.OCCURRENCES - n['both']} missing)")
        missing += [f"{kind}: {c} of {g2.MIN_PER_VM} occurrences counted on VM {vm} ({g2.MIN_PER_VM - c} missing)"
                    for vm, c in n["by_vm"].items() if c < g2.MIN_PER_VM]
    model = marked_model(sum(e["rows_in_windows"]["invalid_processes"] for e in counted),
                         sum(e["occurrences"] for e in counted),
                         {kind: (sums[kind]["invalid_processes"]["total"], sums[kind]["occurrences"]["both"])
                          for kind in types},
                         sum(len(e["outside"]["invalid_processes"]) for e in counted), len(counted), protocol)
    findings = [f"{e['session_id']}: {len(e['outside'][part])} invalid row(s) "
                f"({'with processes' if part == 'invalid_processes' else 'of another cause'}) outside every event "
                "window, seq " + ", ".join(str(row["seq"]) for row in e["outside"][part])
                + ": to explain before any write (Q49)" for e in counted
                for part in ("invalid_processes", "invalid_other") if e["outside"][part]]
    findings += [f"{e['session_id']}: invalid row(s) of a cause the rule does not tolerate, seq "
                 + ", ".join(map(str, e["outside_rule"])) for e in counted if e["outside_rule"]]
    findings += [f"{e['session_id']}: row(s) inside two event windows, seq " + ", ".join(map(str, e["in_two_windows"]))
                 for e in counted if e["in_two_windows"]]
    findings += model["findings"]
    record = g2t_header(
        MARKED_TABLE_SCHEMA, command, len(occurrences), MARKED_GUEST,
        {"criterion": MARKED_CRITERION, "value": MARKED_VALUE,
         "protocol": {"path": os.path.abspath(args.protocol), "sha256": protocol_sha, "g0_binding": binding,
                      "invalid_rows": protocol["invalid_rows"]},
         "g2_dir": str(g2_dir), "types": types, "vms": vms,
         "needed": {"both_vms": g2.OCCURRENCES, "per_vm": g2.MIN_PER_VM},
         "sessions": entries, "counted_sessions": [e["session_id"] for e in counted],
         "left_out": [{"session_id": e["session_id"], "why": e["why_not_counted"]} for e in entries
                      if not e["counted"]],
         "occurrences": occurrences, "by_type": sums, "model": model, "minimums_met": not missing,
         "missing": missing, "findings": findings,
         "rules": {"table": MARKED_RULE, "model": MARKED_MODEL_RULE, "records": G2T_RECORDS_RULE}},
        "The table of the rows the rule marks per occurrence and the rate per event boundary of G2, with the proposal "
        "of invalid_rows.max and min_score_coverage (Q49); the protocol is not written, no score is read and nothing "
        "is detected.")
    problem = g2t_write(out, record)
    if problem:
        print(f"campaign_report: marked: {problem}", file=sys.stderr)
        return 2
    for kind in types:
        print(marked_line(kind, sums[kind]))
    proposal = model["proposal"]
    if proposal is None:
        print("invalid_rows.max proposal: none (" + "; ".join(model["findings"][:1]) + ")")
    else:
        gate = proposal["gate_interval"]
        print(f"invalid_rows.max proposal: {proposal[MARKED_VALUE]} (lambda {model['lambda']:.6g} over "
              f"{model['boundaries']} boundaries, N ~ Poisson({model['mu']:.6g}), P(N > {proposal[MARKED_VALUE]}) = "
              f"{proposal['p_above']:.6g}); min_score_coverage {gate['high']:.10g} ({gate['high_windows']:g}/"
              f"{gate['cycles']} windows)")
    print("marked_rows_per_event minimums: " + ("met" if not missing else "missing: " + "; ".join(missing))
          + f"; {len(counted)} of {len(entries)} session(s) counted, {len(findings)} finding(s)", flush=True)
    print(f"campaign_report: marked: {len(entries)} audit(s), {len(occurrences)} occurrence(s); record {out}",
          file=sys.stderr)
    return 0 if not missing else 1


# ---------------------------------------------------------------- load mode (profiles_load)

LOAD_TABLE_SCHEMA = "hyptcn3/g2-load-table/1"
LOAD_CRITERION = "profiles_load"
LOAD_GROUP_SCHEMA = "hyptcn3/campaign-group/1"  # scripts/campaign.py start_steps: the record of a group's start.
LOAD_RESET_SCHEMA = "hyptcn3/guest-reset/1"  # lab/guest_state.py reset.
LOAD_LEVELS_SCHEMA = "hyptcn3/guest-levels/1"  # lab/guest_state.py levels.
LOAD_RESET_TIMES = ("started_unix", "finished_unix")  # The only fields in which the resets of two groups may differ.
# Q63 (a): the levels after a reset match it. The counts of the reset that no step between it and the levels of the
# group's first session writes, and those the preflight check of that session (scripts/lab_smoke.py, run by every
# capture before its levels) changes by one order of one product.
LOAD_RESET_SAME = ("products", "customers", "employees", "documents", "cart_items")
LOAD_PREFLIGHT = {"orders": 1, "order_items": 1}
LOAD_DRIFT_H = 18  # Q63: a group longer than about 18 h drifts from the seeded level by itself.
LOAD_GUEST = ("none: the mode load reads saved session files, the traffic logs through scripts/traffic_log.py, the "
              "records of G2 and of the starts of their groups; no VM is contacted")
LOAD_RULE = (
    "The criterion profiles_load of stage G2 (scripts/gates.py CRITERIA, the lead's G2 skeleton: per profile and "
    "intensity, the four scenarios, the offered and the delivered load, the user sessions dropped, and the return to "
    "the defined state after the session) and map row 5 with the lead's answer to Q63 (map question 18). Of each "
    "session directory given (G2T_RECORDS_RULE) the mode reads session.json, protocol.json, its G2 record, and of a "
    "session the table considers events.json, guest/levels_before.json, guest/state_after.json, the group "
    "record its G2 record names (values.group, bound by its sha256) and both traffic logs of schema /2 through "
    "scripts/traffic_log.py (summarize and read_jsonl: the mode sessions reads only /1). Per session over the measure "
    "phase of the logs (the generator's phase): the offered load (the arrivals of user sessions, per second, against "
    "the planned ones of the measure intervals), the delivered load (the admitted user sessions, the requests and "
    "those answered ok, per second), the load delivered in the event windows of the log audit (proposal 5.3 asks "
    "that it be shown: the requests whose start or end lies in a window, scripts/collection_logs.py event_window, "
    "and the arrivals in a window, against the window seconds within the measure phase) and outside them, the counts "
    "of the drop reasons (scripts/traffic_log.py DROP_REASONS) by phase, and the problems summarize names. The "
    "return (Q63): (a) every group of the counted sessions starts from the same reset (the hyptcn3/guest-reset/1 "
    "output of the step reset of its start, equal in every field but the times), and the levels of the group's "
    "first session (guest/levels_before.json; the first by the start of its run among the G2 records of the group in "
    "<--g2-dir>/zaznamy) match it: products, customers, employees, documents and cart_items equal to the reset's "
    "counts, orders and order_items one above them (the order of one product of scripts/lab_smoke.py, the preflight "
    "check of every capture before its levels), the document files counts.documents with documents_bytes bytes; (b) "
    "the growth of every numeric level from guest/levels_before.json to the levels after the session "
    "(values.levels_after of the record: labctl levels right after the run), per session and per scenario (minimum, "
    "median and maximum); (c) the state of the units of the guest at the end of the segment, guest/state_after.json, "
    "every unit of scripts/collection_logs.py REQUIRED_UNITS active with the result success, as the log audit judges "
    "it. With --final-protocol (the protocol file that holds the final caps, profiles.*.max_concurrent of the second "
    "write of G2, map point C, with the G0 binding of the sessions) a session ran after the final cap when its "
    "protocol.json holds that cap for its profile; a user session that a counted session dropped after the final "
    "cap, max_concurrent or all_customers_held, is a finding, while the drops of the sessions before it and of the "
    "sessions apart are shown apart; without --final-protocol no drop is judged. A session is considered when it is "
    "done (skuska/g2.py DONE_RULE) and its record does not leave it out of profiles_load (values.excluded); a "
    "session of the fault plan with its fault is shown apart and counts for no "
    "minimum; the others count when the host load counts them (values.counted). Per scenario and VM the sums of the "
    "counted sessions. The minimums: every scenario of the protocol with at least 8 counted sessions on both VMs "
    "together (the skeleton's section 3, as Q65 for realism) and at least one on each VM; (a) for every group of the "
    "counted sessions (a group whose first session is not among the inputs is not judged, which is named); (c) for "
    "every counted session. Findings, none a refusal: drops after the final cap, problems summarize names in a "
    "counted session, a group longer than 18 h (Q63's risk: it drifts from the seeded level by itself), a session "
    "that is not done (listed, its files beyond its record not read). Refused by "
    "name, each a data error: a directory named twice, a file missing or unreadable, a group record other than the "
    "one the G2 record names or without its reset, sessions of protocols with another G0 binding (or a "
    "--final-protocol), and an --out that exists (refused before anything is read) or lies inside a session "
    "directory. Exit 0: the table is written to --out, a new JSON record with the provenance header of check E, and "
    "every minimum is met; 1: the table is written and a minimum is missing, named; 2: a usage or data error, every "
    "refusal named on stderr and nothing written.")


def _load_leaves(doc, prefix=""):
    """{dotted key: number} of the numeric leaves of a levels document (its time utc_unix left out)."""
    out = {}
    for key, value in (doc.items() if isinstance(doc, dict) else ()):
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_load_leaves(value, name + "."))
        elif _number(value) and name != "utc_unix":
            out[name] = value
    return out


class _LoadScan:
    """Package B18 (Q87): what load_traffic reads of the request log, from its records as they stream by: the counts of
    the arrivals and of the requests of the measure phase, in the event windows and outside them, and the counts of the
    drop reasons by phase, never the records (the first exception is raised where load_traffic raised it)."""

    def __init__(self, windows):
        self.windows, self.error = windows, None
        self.measured = self.admitted = self.requests = self.ok = self.in_window = self.ok_in = 0
        self.windowed = {"offered": 0, "admitted": 0, "dropped": 0}
        self.by_phase = {phase: Counter() for phase in traffic_log.PHASES}
        self.dropped = Counter()

    def inside(self, *times):
        return any(t is not None and lo <= t <= hi for t in times for lo, hi in self.windows)

    def feed(self, r):
        if self.error is None:
            try:
                self._feed(r)
            except Exception as error:  # noqa: BLE001 - raised after the logs are read, as before
                self.error = error

    def _feed(self, r):
        kind = r.get("type")
        if kind == "arrival":
            phase, admitted = r.get("phase"), r.get("admitted")
            for name in traffic_log.PHASES:
                if phase == name and admitted is False:
                    self.by_phase[name][str(r.get("drop_reason"))] += 1
            if admitted is False:
                self.dropped[str(r.get("drop_reason"))] += 1
            if phase == "measure":
                self.measured += 1
                self.admitted += admitted is True
                if self.inside(unix_of(r.get("t_utc"))):
                    self.windowed["offered"] += 1
                    self.windowed["admitted"] += admitted is True
                    self.windowed["dropped"] += admitted is False
        elif kind == "request" and r.get("phase") == "measure":
            self.requests += 1
            ok = r.get("outcome") == "ok"
            self.ok += ok
            if self.inside(unix_of(r.get("t_start_utc")), unix_of(r.get("t_end_utc"))):
                self.in_window += 1
                self.ok_in += ok


def load_traffic(directory, sid, windows, files):
    """The load of a session's measure phase from its /2 traffic logs, read through scripts/traffic_log.py
    (LOAD_RULE). Package B18 (Q87): the request log read as a stream (scripts/traffic_log.py LogPair, _LoadScan), only
    counts held; the interval log whole; the table as before."""
    requests_path, intervals_path = directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl"
    _g2t_hash(requests_path, files, "traffic_requests.jsonl")
    _g2t_hash(intervals_path, files, "traffic_intervals.jsonl")
    scan = _LoadScan(windows)
    try:
        summary = traffic_log.summarize(requests_path, intervals_path, session_id=sid,
                                        schema=traffic_log.REQUEST_SCHEMA_2)
        pair = traffic_log.LogPair(requests_path, intervals_path)
        for record in pair.records():
            scan.feed(record)
        log, intervals = pair.requests, pair.intervals
    except (OSError, ValueError) as error:
        raise DataError(f"{directory}: the traffic logs cannot be read ({type(error).__name__}: {error})") from None
    header = log.header if log.records and log.header.get("type") == "header" else {}
    origin = header.get("start_unix")
    measure = [iv for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"]
    if not _number(origin) or not measure or not all(_number(iv.get(k)) for iv in measure
                                                     for k in ("mono_start", "mono_end", "planned_sessions")):
        raise DataError(f"{requests_path}: no header with start_unix or no measure intervals with their times and "
                        "planned sessions (a log of schema /2 of a v5 profile)")
    seconds = sum(iv["mono_end"] - iv["mono_start"] for iv in measure)
    span = (origin + min(iv["mono_start"] for iv in measure), origin + max(iv["mono_end"] for iv in measure))
    clipped = sorted((max(lo, span[0]), min(hi, span[1])) for lo, hi in windows if hi > span[0] and lo < span[1])
    window_s, end = 0.0, None
    for lo, hi in clipped:  # The union of the windows within the measure phase.
        lo = lo if end is None else max(lo, end)
        window_s += max(0.0, hi - lo)
        end = hi if end is None else max(end, hi)

    if scan.error is not None:
        raise scan.error
    measured, requests, in_window, ok, ok_in = scan.measured, scan.requests, scan.in_window, scan.ok, scan.ok_in
    by_phase = {phase: dict(scan.by_phase[phase]) for phase in traffic_log.PHASES}
    planned = sum(iv["planned_sessions"] for iv in measure)
    outside_s = seconds - window_s
    return {"run_id": header.get("run_id"), "rate": header.get("rate"), "rate_source": header.get("rate_source"),
            "measure_s": round(seconds, 6),
            "offered": {"user_sessions": measured, "per_s": _g2t_ratio(measured, seconds),
                        "planned": round(planned, 6), "ratio": _g2t_ratio(measured, planned)},
            "delivered": {"admitted_user_sessions": scan.admitted,
                          "requests": requests, "ok": ok, "per_s": _g2t_ratio(requests, seconds),
                          "ok_per_s": _g2t_ratio(ok, seconds), "ok_share": _g2t_ratio(ok, requests)},
            "event_windows": {"windows": len(windows), "seconds": round(window_s, 6), "requests": in_window,
                              "ok": ok_in, "per_s": _g2t_ratio(in_window, window_s),
                              "ok_per_s": _g2t_ratio(ok_in, window_s), "ok_share": _g2t_ratio(ok_in, in_window),
                              "arrivals": dict(scan.windowed)},
            "outside_windows": {"seconds": round(outside_s, 6), "requests": requests - in_window,
                                "ok": ok - ok_in, "per_s": _g2t_ratio(requests - in_window, outside_s),
                                "ok_per_s": _g2t_ratio(ok - ok_in, outside_s),
                                "ok_share": _g2t_ratio(ok - ok_in, requests - in_window)},
            "dropped": {"measure": by_phase["measure"], "by_phase": by_phase, "all": dict(scan.dropped)},
            "arrivals": summary.get("arrivals"), "log_problems": summary.get("problems") or []}


def load_session(path, g2_dir, final_caps):
    """One session directory by LOAD_RULE: its entry (status counted, left_out, fault or not_done, the load, the levels,
    the units at the end, the group); a DataError by name."""
    from scripts.collection_logs import REQUIRED_UNITS
    s = g2t_session(path, g2_dir)
    directory, record, files, meta = Path(s["path"]), s["record"], s["files"], s["meta"]
    scenario = (s["protocol"].get("scenarios") or {}).get(s["scenario"])
    if not isinstance(scenario, dict):
        raise DataError(f"{directory}: session.json names the scenario {_shown(s['scenario'], 40)}, which its protocol "
                        "does not have")
    entry = {"session_id": s["session_id"], "vm": s["vm"], "scenario": s["scenario"],
             "profile": scenario.get("profile"), "intensity": scenario.get("intensity"), "kind": record["kind"],
             "path": str(directory), "record": {"path": record["path"], "sha256": record["sha256"]},
             "protocol_sha256": s["protocol_sha"], "binding": s["binding"], "status": None, "why": None,
             "fault": record["fault"], "induced": record["induced"], "files": files}
    named = g2t_left_out(dict(record, counted=True), (LOAD_CRITERION,))
    if not record["done"]:
        v = record["values"]
        entry.update(status="not_done", why="not done (skuska/g2.py DONE_RULE): " + one_line(str(
            v.get("stop") or v.get("error") or f"exit codes {v.get('exit_codes')}, audit "
                                               f"{'present' if v.get('audit') else 'none'}")))
        return entry
    if named is not None:
        entry.update(status="left_out", why=named)
        return entry
    _, windows, _, _ = g2t_windows(directory, meta, files)
    entry["load"] = load_traffic(directory, s["session_id"], [(lo, hi) for _, _, lo, hi in windows], files)
    cap = (s["protocol"].get("profiles") or {}).get(entry["profile"], {}).get("max_concurrent")
    entry["cap"] = {"max_concurrent": cap,
                    "final": None if final_caps is None else cap == final_caps.get(entry["profile"])}
    before, _ = _g2t_json(directory / "guest" / "levels_before.json", files, "guest/levels_before.json",
                          LOAD_LEVELS_SCHEMA)
    after = record["values"].get("levels_after")
    entry["levels_before"] = before
    if isinstance(after, dict) and after.get("schema") == LOAD_LEVELS_SCHEMA:
        a, b = _load_leaves(after), _load_leaves(before)
        entry["growth"] = {key: a[key] - b[key] for key in sorted(set(a) & set(b))}
        entry["growth_seconds"] = (round(after["utc_unix"] - before["utc_unix"], 3)
                                   if _number(after.get("utc_unix")) and _number(before.get("utc_unix")) else None)
        entry["modules"] = {"added": sorted(set(after.get("modules") or []) - set(before.get("modules") or [])),
                            "removed": sorted(set(before.get("modules") or []) - set(after.get("modules") or []))}
    else:
        entry.update(growth=None, growth_why="the record holds no levels after the session (values.levels_after of "
                                             "labctl levels)")
    state, _ = _g2t_json(directory / "guest" / "state_after.json", files, "guest/state_after.json",
                         "hyptcn3/guest-state/1")
    units = state.get("units") if isinstance(state.get("units"), dict) else {}
    shown = {unit: {key: (units.get(unit) or {}).get(key) for key in ("ActiveState", "SubState", "Result",
                                                                       "NRestarts")} for unit in sorted(units)}
    bad = [f"{unit} {(units.get(unit) or {}).get('ActiveState')}/{(units.get(unit) or {}).get('Result')}"
           for unit in REQUIRED_UNITS if (units.get(unit) or {}).get("ActiveState") != "active"
           or (units.get(unit) or {}).get("Result") != "success"]
    entry["units_end"] = {"ok": not bad, "not_ok": bad, "units": shown}
    group = record["values"].get("group")
    if not isinstance(group, dict) or not all(isinstance(group.get(k), str) for k in ("name", "record", "sha256")):
        raise DataError(f"{record['path']}: names no group with its record and sha256 (values.group)")
    doc, sha = _g2t_json(group["record"], files, "group record", LOAD_GROUP_SCHEMA)
    if sha != group["sha256"] or doc.get("group") != group["name"]:
        raise DataError(f"{group['record']}: not the record of group {group['name']} that the G2 record names (its "
                        f"sha256 {sha}, the G2 record's {group['sha256']})")
    steps = (doc.get("start") or {}).get("steps") if isinstance(doc.get("start"), dict) else None
    reset = next((step.get("output") for step in steps or [] if isinstance(step, dict) and step.get("step") == "reset"),
                 None)
    if not isinstance(reset, dict) or reset.get("schema") != LOAD_RESET_SCHEMA:
        raise DataError(f"{group['record']}: its start holds no reset output of schema {LOAD_RESET_SCHEMA}")
    entry["group"] = {"name": group["name"], "record": group["record"], "sha256": sha, "reset": reset}
    if record["kind"] == G2T_FAULT_KIND:
        entry.update(status="fault", why=f"a session of the fault plan with its fault ({record['fault']}, induced "
                                         f"{record['induced']}): shown apart")
    elif not record["counted"]:
        entry.update(status="left_out", why=g2t_left_out(record, (LOAD_CRITERION,)))
    else:
        entry["status"] = "counted"
    return entry


def load_first_sessions(g2_dir, names):
    """{group: {first, records, span_h}} for the groups `names`, from the G2 records in <g2_dir>/zaznamy: the session
    id of its first session, the first by the start of its run (the step run of values.steps), the group's records
    with their sha256, and the span from the first start to the last end of a run, in hours."""
    found = defaultdict(list)
    for path in sorted((Path(g2_dir) / "zaznamy").glob("*.json")):
        try:
            raw = path.read_bytes()
            doc = json.loads(raw)
        except (OSError, ValueError):
            continue
        v = doc.get("values") if isinstance(doc, dict) and doc.get("schema") == G2T_RECORD_SCHEMA else None
        group = v.get("group") if isinstance(v, dict) else None
        if not isinstance(group, dict) or group.get("name") not in names:
            continue
        run = next((step for step in v.get("steps") or [] if isinstance(step, dict) and step.get("step") == "run"),
                   {})
        found[group["name"]].append({"session_id": v.get("session_id"), "path": str(path),
                                     "sha256": hashlib.sha256(raw).hexdigest(), "started": run.get("started"),
                                     "ended": run.get("ended")})
    out = {}
    for name in names:
        rows = sorted(found.get(name, []), key=lambda r: (str(r["started"] or "~"), str(r["session_id"])))
        starts = [t for t in (unix_of(r["started"]) for r in rows) if t is not None]
        ends = [t for t in (unix_of(r["ended"]) for r in rows) if t is not None]
        out[name] = {"first": rows[0]["session_id"] if rows else None, "records": rows,
                     "span_h": round((max(ends) - min(starts)) / 3600, 3) if starts and ends else None}
    return out


def load_reset_check(groups, first, entries):
    """Q63 (a) over the groups of the counted sessions: (rows per group, what is missing)."""
    rows, missing = [], []
    by_id = {e["session_id"]: e for e in entries}
    names = sorted(groups)
    reference = None
    for name in names:
        reset = groups[name]
        same = {k: x for k, x in reset.items() if k not in LOAD_RESET_TIMES}
        row = {"group": name, "reset": reset, "first_session": first[name]["first"], "span_h": first[name]["span_h"],
               "records": first[name]["records"], "differs_from": None, "levels": None, "levels_ok": None}
        if reference is None:
            reference = (name, same)
        elif same != reference[1]:
            keys = sorted(k for k in set(same) | set(reference[1]) if same.get(k) != reference[1].get(k))
            row["differs_from"] = {"group": reference[0], "keys": keys}
            missing.append(f"group {name}: its reset differs from that of group {reference[0]} in " + ", ".join(keys))
        session = by_id.get(first[name]["first"])
        levels = None if session is None else session.get("levels_before")
        if levels is None:
            missing.append(f"group {name}: the levels after its reset are not judged: its first session "
                           f"{first[name]['first']} " + ("is not among the sessions read" if session is None else
                                                         f"is {session['status']}, its levels not read"))
        else:
            counts, database = reset.get("counts") or {}, levels.get("database") or {}
            docs = (levels.get("files") or {}).get("documents") or {}
            expected = {**{key: counts.get(key) for key in LOAD_RESET_SAME},
                        **{key: (counts.get(key) + extra if type(counts.get(key)) is int else None)
                           for key, extra in LOAD_PREFLIGHT.items()}}
            found = {key: database.get(key) for key in expected}
            expected.update({"files.documents.files": counts.get("documents"),
                             "files.documents.bytes": reset.get("documents_bytes")})
            found.update({"files.documents.files": docs.get("files"), "files.documents.bytes": docs.get("bytes")})
            differ = [key for key in expected if expected[key] is None or found[key] != expected[key]]
            row.update(levels={"session": session["session_id"], "expected": expected, "found": found},
                       levels_ok=not differ)
            if differ:
                missing.append(f"group {name}: the levels of its first session {session['session_id']} do not match "
                               "its reset in " + ", ".join(f"{key} {found[key]} (expected {expected[key]})"
                                                           for key in differ))
        rows.append(row)
    return rows, missing


def load_aggregate(rows):
    """The sums of the counted sessions of one scenario (and VM) by LOAD_RULE."""
    def summed(path):
        return sum(_get(r["load"], path) or 0 for r in rows)
    seconds, window_s = summed("measure_s"), summed("event_windows.seconds")
    reasons = Counter()
    for r in rows:
        reasons.update(r["load"]["dropped"]["measure"])
    growth = defaultdict(list)
    for r in rows:
        for key, value in (r.get("growth") or {}).items():
            growth[key].append(value)
    return {"sessions": [r["session_id"] for r in rows], "measure_s": round(seconds, 6),
            "offered": {"user_sessions": summed("offered.user_sessions"),
                        "planned": round(summed("offered.planned"), 6),
                        "per_s": _g2t_ratio(summed("offered.user_sessions"), seconds),
                        "ratio": _g2t_ratio(summed("offered.user_sessions"), summed("offered.planned")),
                        "ratio_per_session": g2t_distribution([r["load"]["offered"]["ratio"] for r in rows])},
            "delivered": {"admitted_user_sessions": summed("delivered.admitted_user_sessions"),
                          "requests": summed("delivered.requests"), "ok": summed("delivered.ok"),
                          "per_s": _g2t_ratio(summed("delivered.requests"), seconds),
                          "ok_per_s": _g2t_ratio(summed("delivered.ok"), seconds)},
            "event_windows": {"seconds": round(window_s, 6), "requests": summed("event_windows.requests"),
                              "ok": summed("event_windows.ok"),
                              "per_s": _g2t_ratio(summed("event_windows.requests"), window_s),
                              "ok_share": _g2t_ratio(summed("event_windows.ok"), summed("event_windows.requests"))},
            "outside_windows": {"seconds": round(seconds - window_s, 6),
                                "requests": summed("outside_windows.requests"), "ok": summed("outside_windows.ok"),
                                "per_s": _g2t_ratio(summed("outside_windows.requests"), seconds - window_s)},
            "dropped_measure": dict(sorted(reasons.items())),
            "growth": {key: g2t_distribution(values) for key, values in sorted(growth.items())}}


def load_table(args, command):
    """The mode load (LOAD_RULE): refuses an --out that exists before it reads anything and a directory named twice,
    then reads every session; writes the new record, prints one line per scenario and VM, and returns the exit
    code."""
    from scripts import gates
    from skuska import g2
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths, twice = g2t_inputs(args.session_dirs, "a session directory")
    if twice:
        print(f"campaign_report: load: {twice}", file=sys.stderr)
        return 2
    g2_dir, final, final_caps, refused = g2t_g2_dir(args), None, None, []
    if args.final_protocol is not None:
        try:
            raw = Path(args.final_protocol).read_bytes()
            doc = json.loads(raw)
            final_caps = {name: row["max_concurrent"] for name, row in doc["profiles"].items()}
            final = {"path": os.path.abspath(args.final_protocol), "sha256": hashlib.sha256(raw).hexdigest(),
                     "caps": final_caps, "g0_binding": gates.stage_binding(args.final_protocol, "G0")[0]}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            print(f"campaign_report: load: --final-protocol {args.final_protocol}: no protocol with the caps of its "
                  f"profiles ({type(error).__name__}: {error})", file=sys.stderr)
            return 2
    entries = []
    for path in paths:
        try:
            entries.append(load_session(path, g2_dir, final_caps))
        except DataError as error:
            refused.append(str(error))
    bindings = sorted({e["binding"] for e in entries} | ({final["g0_binding"]} if final else set()))
    if len(bindings) > 1:
        refused.append("the sessions (and --final-protocol) are of protocols with different G0 bindings ("
                       + ", ".join(bindings) + "): one table takes one protocol up to the values of later stages")
    refused += g2t_inside(out, [e["path"] for e in entries])
    if refused or not entries:
        for why in refused or ["no session"]:
            print(f"campaign_report: load: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: load: {len(refused)} refusal(s): no table, nothing written", file=sys.stderr)
        return 2
    protocol = json.loads(Path(entries[0]["path"], "protocol.json").read_text())
    scenarios, vms = sorted(protocol.get("scenarios") or {}), [row["name"] for row in protocol.get("vms") or []]
    counted = [e for e in entries if e["status"] == "counted"]
    groups = {e["group"]["name"]: e["group"]["reset"] for e in counted}
    first = load_first_sessions(g2_dir, set(groups))
    group_rows, missing = load_reset_check(groups, first, entries)
    by_scenario, by_scenario_vm = {}, {}
    for name in scenarios:
        mine = [e for e in counted if e["scenario"] == name]
        by_scenario[name] = load_aggregate(mine)
        by_scenario_vm[name] = {vm: load_aggregate([e for e in mine if e["vm"] == vm]) for vm in vms}
        if len(mine) < g2.MIN_PER_SCENARIO:
            missing.append(f"scenario {name}: {len(mine)} of {g2.MIN_PER_SCENARIO} sessions counted on both VMs "
                           f"together ({g2.MIN_PER_SCENARIO - len(mine)} missing)")
        missing += [f"scenario {name}: no session counted on VM {vm}" for vm in vms
                    if not any(e["vm"] == vm for e in mine)]
    missing += [f"session {e['session_id']}: at the end of its segment " + ", ".join(e["units_end"]["not_ok"])
                for e in counted if not e["units_end"]["ok"]]
    findings = []
    for e in counted:
        drops = e["load"]["dropped"]["all"]
        if drops and e["cap"]["final"] is True:
            findings.append(f"session {e['session_id']} ran after the final cap {e['cap']['max_concurrent']} of "
                            f"{e['profile']} and dropped user sessions: " + ", ".join(f"{k} {n}" for k, n in
                                                                                     sorted(drops.items())))
    findings += [f"session {e['session_id']}: summarize names {len(e['load']['log_problems'])} problem(s) of its "
                 "traffic logs, the first " + one_line(str(e["load"]["log_problems"][0]))
                 for e in counted if e["load"]["log_problems"]]
    findings += [f"group {row['group']} spans {row['span_h']} h, more than {LOAD_DRIFT_H} h: it drifts from the "
                 "seeded level by itself (Q63)" for row in group_rows
                 if row["span_h"] is not None and row["span_h"] > LOAD_DRIFT_H]
    findings += [f"session {e['session_id']}: {e['why']}" for e in entries if e["status"] == "not_done"]
    before_final = [{"session_id": e["session_id"], "status": e["status"], "cap": e["cap"],
                     "dropped": e["load"]["dropped"]} for e in entries if "load" in e and e["load"]["dropped"]["all"]
                    and (e["cap"]["final"] is not True or e["status"] != "counted")]
    record = g2t_header(
        LOAD_TABLE_SCHEMA, command, len(entries), LOAD_GUEST,
        {"criterion": LOAD_CRITERION, "g2_dir": str(g2_dir), "scenarios": scenarios, "vms": vms,
         "needed": {"per_scenario": g2.MIN_PER_SCENARIO, "per_scenario_and_vm": 1}, "final_caps": final,
         "sessions": entries, "counted_sessions": [e["session_id"] for e in counted],
         "apart": [{"session_id": e["session_id"], "status": e["status"], "why": e["why"]} for e in entries
                   if e["status"] != "counted"],
         "by_scenario": by_scenario, "by_scenario_and_vm": by_scenario_vm, "groups": group_rows,
         "drops_not_judged": before_final, "minimums_met": not missing, "missing": missing,
         "findings": findings, "rules": {"table": LOAD_RULE, "records": G2T_RECORDS_RULE}},
        "The table of the offered and delivered load of the G2 sessions per scenario and VM, the drops and the return "
        "to the defined state (criterion profiles_load of G2); nothing is scored or detected.")
    problem = g2t_write(out, record)
    if problem:
        print(f"campaign_report: load: {problem}", file=sys.stderr)
        return 2
    for name in scenarios:
        for vm in vms:
            row = by_scenario_vm[name][vm]
            print(f"{name} VM {vm}: {len(row['sessions'])} session(s); offered {row['offered']['per_s']} user "
                  f"sessions/s (ratio to the plan {row['offered']['ratio']}), delivered {row['delivered']['per_s']} "
                  f"requests/s ({row['delivered']['ok_per_s']} ok), in event windows {row['event_windows']['per_s']}"
                  f" requests/s; dropped {row['dropped_measure'] or 'none'}")
    print("profiles_load minimums: " + ("met" if not missing else "missing: " + "; ".join(missing))
          + f"; {len(counted)} of {len(entries)} session(s) counted, {len(group_rows)} group(s), {len(findings)} "
          "finding(s)", flush=True)
    print(f"campaign_report: load: {len(entries)} session(s); record {out}", file=sys.stderr)
    return 0 if not missing else 1


# ---------------------------------------------------------------- realism mode (traffic_realism)

REALISM_TABLE_SCHEMA = "hyptcn3/g2-realism-table/1"
REALISM_CRITERION = "traffic_realism"
REALISM_TIMER = "hyptcn-lab-udrzba.timer"  # The entry of the maintenance timer in lab/periods.json.
REALISM_TIMER_RUNS = 2  # The executor's judgment: at least two runs in the measured phase, so a spacing is judged.
# The executor's judgment: the start of a run is the time of its journal line less the seconds it states
# (scripts/lab_trial.py periods), which leaves out the start of python3 before services.py udrzba measures them.
REALISM_TIMER_TOLERANCE_S = 2.0
REALISM_GUEST = ("none: the mode realism reads saved session files, audit records, guest journals and the records of "
                 "G2, and the first lines of the traffic logs for the envelope; no VM is contacted")
REALISM_RULE = (
    "The criterion traffic_realism of stage G2 (scripts/gates.py CRITERIA, the lead's G2 skeleton: the requirements "
    "of proposal 5.7 in every scenario, and P1, the envelope, over every G2 session without a mismatch) and map row "
    "6 with the lead's answer to Q65 (map question 20: every G2 session without a fault passes the section realism, "
    "every scenario has at least 8 such sessions, and the table shows the minimum, the median and the maximum of "
    "every requirement). Of each session directory given (G2T_RECORDS_RULE) the mode reads session.json, "
    "protocol.json and its G2 record, and of a session it considers the audit record the G2 record names "
    "(values.audit, bound by its sha256, its values.session_sha256 that of session.json and its "
    "values.protocol_sha256 that of protocol.json), end.json and, for a session of the profile corp, the guest "
    "journal of its segment (guest/journal_segment.json and the file it names). Per session: the value, the bound "
    "and the result of every requirement of the audit's section realism (values.logs.sections.realism, "
    "scripts/traffic_log.py realism as the log audit ran it: arrival_cv, think_time, order_share, "
    "object_concentration, success_rate, response_sizes, peak_to_mean, background) and of the offered-load check of "
    "proposal 5.3 beside them; a session whose audit has no such section has no values (a missing minimum when it "
    "counts). The corp background of proposal 5.7 is also the periodic task with a random delay of the guest, the "
    "maintenance timer, which the traffic log does not hold and which comes from the journal only: the requirement "
    "maintenance_timer takes the runs of hyptcn-lab-udrzba.timer whose start lies in the measured phase of end.json "
    "(the line {\"service\": \"udrzba\", ...} of lab/services.py udrzba, its time less its seconds, as "
    "scripts/lab_trial.py periods reads it) and needs at least 2 runs and every spacing of consecutive runs within "
    "period_s - (the span of random_s) and period_s + (the span of random_s) of its entry in lab/periods.json of this "
    "tree, 2 s either way (the executor's judgment). P1 (the mode envelope, ENVELOPE_RULE) runs over every session "
    "the mode considers, grouped by the sha256 of each session's protocol.json, since every write of a value of G2 "
    "changes those bytes and P1 calls another protocol a data error: each group's protocol is the protocol.json of "
    "its sessions, and the generator is this tree's scripts/host_traffic.py, which must be the sessions' own. A "
    "session is considered when it is done (skuska/g2.py DONE_RULE) and its record does not leave it out of "
    "traffic_realism (values.excluded); a session of the fault plan with its fault is shown apart (its values and "
    "its P1), and the others count when the host load counts them (values.counted); a session that is not done is "
    "listed, a finding, and neither its audit nor its logs are read. Per scenario, and per scenario "
    "and VM, of the counted sessions: for every requirement the sessions, those that pass and fail, and the minimum, "
    "median (nearest rank, as scripts/traffic_log.py percentile) and maximum of its value (of each number of a value "
    "that is an object) with the bounds. The minimums: every scenario of the protocol with at least 8 counted "
    "sessions with values; every requirement, the offered load and (corp) maintenance_timer passed in every counted "
    "session; P1 a match in every considered session. A failure is also a finding for the lead first, since a "
    "change of the lab or of scripts/traffic_log.py is a new G0 (Q65). Refused by name, each a data error: a "
    "directory named twice, a file missing or unreadable, an audit record other than the one the G2 record names or "
    "that does not bind the session, sessions of protocols with different G0 bindings, and an --out that exists "
    "(refused before anything is read) or lies inside a session directory. Exit 0: the table is written to --out, a "
    "new JSON record with the provenance header of check E, and every minimum is met; 1: the table is written and a "
    "minimum is missing, named; 2: a usage or data error, every refusal named on stderr and nothing written.")


def realism_register():
    """(the entry of REALISM_TIMER in lab/periods.json of this tree, the file with its sha256); a DataError."""
    path = ROOT / "lab/periods.json"
    files = []
    doc, _ = _g2t_json(path, files, "lab/periods.json")
    entry = next((row for row in doc.get("periods") or [] if isinstance(row, dict)
                  and row.get("name") == REALISM_TIMER), None)
    random_s = entry.get("random_s") if entry else None
    if (entry is None or not _number(entry.get("period_s")) or not isinstance(random_s, list) or len(random_s) != 2
            or not all(map(_number, random_s))):
        raise DataError(f"{path}: no entry {REALISM_TIMER} with period_s and random_s [low, high]")
    span = random_s[1] - random_s[0]
    entry = dict(entry, band_s=[entry["period_s"] - span - REALISM_TIMER_TOLERANCE_S,
                                entry["period_s"] + span + REALISM_TIMER_TOLERANCE_S])
    return entry, files[0]


def realism_timer(directory, end, files, register):
    """The requirement maintenance_timer of a corp session from its guest journal (REALISM_RULE)."""
    from scripts import lab_trial
    doc, _ = _g2t_json(directory / "guest" / "journal_segment.json", files, "guest/journal_segment.json",
                       "hyptcn3/guest-journal-segment/1")
    entry = next((f for f in doc.get("files") or [] if isinstance(f, dict) and isinstance(f.get("name"), str)
                  and f["name"].endswith("-journal.txt")), None)
    name = entry.get("file") if entry else None
    if not isinstance(name, str) or Path(name).name != name:
        raise DataError(f"{directory}: guest/journal_segment.json names no journal file of the segment")
    path = directory / "guest" / name
    _g2t_read(path, files, "guest journal")
    try:
        starts = lab_trial._udrzba(list(lab_trial.journal_lines(path)))[0]
    except (OSError, EOFError, ValueError) as error:
        raise DataError(f"{path}: the guest journal cannot be read ({type(error).__name__}: {error})") from None
    low, high = end.get("measure_start_unix"), end.get("measure_end_unix")
    if not _number(low) or not _number(high):
        raise DataError(f"{directory}: end.json has no measure_start_unix and measure_end_unix")
    runs = sorted(t for t in starts if low <= t <= high)
    spacings = [round(b - a, 6) for a, b in zip(runs, runs[1:])]
    band = register["band_s"]
    outside = [s for s in spacings if not band[0] <= s <= band[1]]
    return {"name": "maintenance_timer",
            "value": {"runs": len(runs), "spacings_s": g2t_distribution(spacings), "starts_unix": runs},
            "bound": {"runs_min": REALISM_TIMER_RUNS, "spacing_s": band, "period_s": register["period_s"],
                      "random_s": register["random_s"]},
            "ok": len(runs) >= REALISM_TIMER_RUNS and not outside,
            "note": (f"{len(runs)} run(s) of {REALISM_TIMER} in the measured phase from the guest journal; "
                     + (f"spacings outside the band: {outside}" if outside else "every spacing within the band"))}


def realism_session(path, g2_dir, register):
    """One session directory by REALISM_RULE: its entry (status counted, left_out, fault or not_done; the requirements
    and the offered load of its audit, the maintenance timer of corp); a DataError by name."""
    s = g2t_session(path, g2_dir)
    directory, record, files = Path(s["path"]), s["record"], s["files"]
    scenario = (s["protocol"].get("scenarios") or {}).get(s["scenario"])
    if not isinstance(scenario, dict):
        raise DataError(f"{directory}: session.json names the scenario {_shown(s['scenario'], 40)}, which its protocol "
                        "does not have")
    entry = {"session_id": s["session_id"], "vm": s["vm"], "scenario": s["scenario"],
             "profile": scenario.get("profile"), "intensity": scenario.get("intensity"), "kind": record["kind"],
             "path": str(directory), "record": {"path": record["path"], "sha256": record["sha256"]},
             "protocol": str(directory / "protocol.json"), "protocol_sha256": s["protocol_sha"],
             "binding": s["binding"], "status": None, "why": None, "fault": record["fault"],
             "induced": record["induced"], "audit": None, "requirements": None, "offered_load": None,
             "no_values": None, "envelope": None, "files": files}
    named = g2t_left_out(dict(record, counted=True), (REALISM_CRITERION,))
    if not record["done"]:
        v = record["values"]
        entry.update(status="not_done", why="not done (skuska/g2.py DONE_RULE): " + one_line(str(
            v.get("stop") or v.get("error") or f"exit codes {v.get('exit_codes')}, audit "
                                               f"{'present' if v.get('audit') else 'none'}")))
        return entry
    if named is not None:
        entry.update(status="left_out", why=named)
        return entry
    entry["considered"] = True  # Done and not left out by name: its values are read and P1 runs over it.
    named_audit = record["values"].get("audit")
    if not isinstance(named_audit, dict) or not isinstance(named_audit.get("report"), str):
        raise DataError(f"{record['path']}: a done session whose record names no audit (values.audit.report)")
    audit, sha = _g2t_json(named_audit["report"], files, "audit record", AUDIT_SCHEMA)
    v = audit.get("values") if isinstance(audit.get("values"), dict) else {}
    if (sha != named_audit.get("sha256") or v.get("session_sha256") != s["meta_sha"]
            or v.get("protocol_sha256") != s["protocol_sha"]):
        raise DataError(f"{named_audit['report']}: not the audit the G2 record names or not one of this session (its "
                        "sha256, values.session_sha256 or values.protocol_sha256)")
    entry["audit"] = {"path": named_audit["report"], "sha256": sha, "accepted": v.get("accepted"),
                      "reasons": v.get("reasons")}
    section = _get(v, "logs.sections.realism")
    if (isinstance(section, dict) and isinstance(section.get("requirements"), list)
            and all(isinstance(r, dict) and isinstance(r.get("name"), str) for r in section["requirements"])
            and isinstance(section.get("offered_load"), dict)):
        entry["requirements"] = [{key: r.get(key) for key in ("name", "value", "bound", "ok", "note")}
                                 for r in section["requirements"]]
        entry["offered_load"] = section["offered_load"]
    else:
        problems = [str(p) for p in _get(v, "logs.problems") or [] if str(p).startswith("realism")] \
            if isinstance(_get(v, "logs.problems"), list) else []
        entry["no_values"] = ("the audit has no section realism" + (": " + "; ".join(map(one_line, problems))
                                                                     if problems else ""))
    if entry["profile"] == "corp":
        end, _ = _g2t_json(directory / "end.json", files, "end.json")
        timer = realism_timer(directory, end, files, register)
        entry["requirements"] = None if entry["requirements"] is None else [*entry["requirements"], timer]
        entry["timer"] = timer
    if record["kind"] == G2T_FAULT_KIND:
        entry.update(status="fault", why=f"a session of the fault plan with its fault ({record['fault']}, induced "
                                         f"{record['induced']}): shown apart")
    elif not record["counted"]:
        entry.update(status="left_out", why=g2t_left_out(record, (REALISM_CRITERION,)))
    else:
        entry["status"] = "counted"
    return entry


def realism_failures(entry):
    """What a session with values fails: its requirements, the offered load, its P1."""
    out = [f"{r['name']} {_shown(r['value'], 160)} against {_shown(r['bound'], 160)}" for r in entry["requirements"]
           if r.get("ok") is not True]
    if entry["offered_load"].get("ok") is not True:
        out.append(f"offered_load {_shown(entry['offered_load'], 160)}")
    return out


def realism_aggregate(rows):
    """Per requirement of the counted sessions `rows`: the sessions, those that pass and fail, the distribution of
    each number of its value and the bounds (REALISM_RULE)."""
    out = {}
    names = list(dict.fromkeys(r["name"] for e in rows for r in e["requirements"]))
    for name in [*names, "offered_load"]:
        found = ([(e["session_id"], {"value": e["offered_load"].get("ratio"), "ok": e["offered_load"].get("ok"),
                                     "bound": "within offered_load_tolerance of 1"}) for e in rows]
                 if name == "offered_load" else
                 [(e["session_id"], r) for e in rows for r in e["requirements"] if r["name"] == name])
        values = defaultdict(list)
        for _, r in found:
            value = r.get("value")
            if isinstance(value, dict):
                for key, x in value.items():
                    x = x.get("median") if isinstance(x, dict) and "median" in x else x
                    if _number(x):
                        values[key].append(x)
            elif _number(value):
                values["value"].append(value)
        bounds = list(dict.fromkeys(json.dumps(r.get("bound"), sort_keys=True) for _, r in found))
        out[name] = {"sessions": len(found), "passed": sum(r.get("ok") is True for _, r in found),
                     "failed": [sid for sid, r in found if r.get("ok") is not True],
                     "values": {key: g2t_distribution(xs) for key, xs in values.items()},
                     "bounds": [json.loads(b) for b in bounds]}
    return out


def realism_table(args, command):
    """The mode realism (REALISM_RULE): refuses an --out that exists before it reads anything and a directory named
    twice, then reads every session and runs P1 per protocol; writes the new record, prints one line per scenario,
    and returns the exit code."""
    from skuska import g2
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths, twice = g2t_inputs(args.session_dirs, "a session directory")
    if twice:
        print(f"campaign_report: realism: {twice}", file=sys.stderr)
        return 2
    g2_dir, entries, refused = g2t_g2_dir(args), [], []
    try:
        register, register_file = realism_register()
    except DataError as error:
        print(f"campaign_report: realism: {error}", file=sys.stderr)
        return 2
    for path in paths:
        try:
            entries.append(realism_session(path, g2_dir, register))
        except DataError as error:
            refused.append(str(error))
    bindings = sorted({e["binding"] for e in entries})
    if len(bindings) > 1:
        refused.append("the sessions are of protocols with different G0 bindings (" + ", ".join(bindings)
                       + "): one table takes one protocol up to the values of later stages")
    refused += g2t_inside(out, [e["path"] for e in entries])
    if refused or not entries:
        for why in refused or ["no session"]:
            print(f"campaign_report: realism: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: realism: {len(refused)} refusal(s): no table, nothing written", file=sys.stderr)
        return 2
    # P1 per protocol.json bytes (REALISM_RULE): the generator of this tree draws, as in the mode envelope.
    generator = os.path.abspath(host_traffic.__file__)
    with open(generator, "rb") as stream:
        generator_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    considered = [e for e in entries if e.get("considered")]
    groups = defaultdict(list)
    for e in considered:
        groups[e["protocol_sha256"]].append(e)
    envelope_groups = []
    for sha, members in sorted(groups.items()):
        try:
            protocol_sha, protocol = envelope_protocol(members[0]["protocol"])
        except DataError as error:
            protocol_sha, protocol, problem = None, None, str(error)
        for e in members:
            if protocol is None:
                e["envelope"] = {"result": "data_error", "reasons": [problem]}
            else:
                found = envelope_session(e["path"], protocol_sha, protocol, generator_sha)
                e["envelope"] = {key: found[key] for key in ("result", "reasons", "draws", "knots", "files")}
        envelope_groups.append({"protocol_sha256": sha, "protocol": members[0]["protocol"],
                                "sessions": [e["session_id"] for e in members],
                                "counts": {result: sum(e["envelope"]["result"] == result for e in members)
                                           for result in ENVELOPE_RESULTS}})
    protocol = json.loads(Path(entries[0]["protocol"]).read_text())
    scenarios, vms = sorted(protocol.get("scenarios") or {}), [row["name"] for row in protocol.get("vms") or []]
    counted = [e for e in entries if e["status"] == "counted"]
    valued = [e for e in counted if e["requirements"] is not None]
    missing = [f"session {e['session_id']}: no values of the requirements ({e['no_values']})" for e in counted
               if e["requirements"] is None]
    for e in valued:
        missing += [f"session {e['session_id']} ({e['scenario']}, VM {e['vm']}): fails {text}"
                    for text in realism_failures(e)]
    missing += [f"session {e['session_id']}: P1 {e['envelope']['result']}: "
                + "; ".join(map(one_line, e["envelope"]["reasons"])) for e in considered
                if e["envelope"]["result"] != "match"]
    by_scenario, by_scenario_vm = {}, {}
    for name in scenarios:
        mine = [e for e in valued if e["scenario"] == name]
        by_scenario[name] = {"sessions": [e["session_id"] for e in mine], "requirements": realism_aggregate(mine)}
        by_scenario_vm[name] = {vm: {"sessions": [e["session_id"] for e in mine if e["vm"] == vm],
                                     "requirements": realism_aggregate([e for e in mine if e["vm"] == vm])}
                                for vm in vms}
        if len(mine) < g2.MIN_PER_SCENARIO:
            missing.insert(0, f"scenario {name}: {len(mine)} of {g2.MIN_PER_SCENARIO} sessions without a fault "
                              f"counted with values ({g2.MIN_PER_SCENARIO - len(mine)} missing)")
    faults = [{"session_id": e["session_id"], "vm": e["vm"], "scenario": e["scenario"], "fault": e["fault"],
               "induced": e["induced"],
               "failed": None if e["requirements"] is None else realism_failures(e),
               "envelope": e["envelope"]["result"]} for e in entries if e["status"] == "fault"]
    findings = [f"for the lead first (Q65): {text}" for text in missing if text.startswith("session ")]
    findings += [f"session {e['session_id']}: {e['why']}" for e in entries if e["status"] == "not_done"]
    record = g2t_header(
        REALISM_TABLE_SCHEMA, command, len(entries), REALISM_GUEST,
        {"criterion": REALISM_CRITERION, "g2_dir": str(g2_dir), "scenarios": scenarios, "vms": vms,
         "needed": {"per_scenario": g2.MIN_PER_SCENARIO},
         "register": {**register_file, "entry": register},
         "sessions": entries, "counted_sessions": [e["session_id"] for e in counted],
         "apart": [{"session_id": e["session_id"], "status": e["status"], "why": e["why"]} for e in entries
                   if e["status"] != "counted"],
         "by_scenario": by_scenario, "by_scenario_and_vm": by_scenario_vm, "faults": faults,
         "envelope": {"generator": {"path": generator, "sha256": generator_sha}, "groups": envelope_groups},
         "minimums_met": not missing, "missing": missing, "findings": findings,
         "rules": {"table": REALISM_RULE, "envelope": ENVELOPE_RULE, "records": G2T_RECORDS_RULE}},
        "The table of the realism requirements of proposal 5.7 over the G2 sessions per scenario and VM, with P1 per "
        "protocol (criterion traffic_realism of G2); nothing is scored or detected.")
    problem = g2t_write(out, record)
    if problem:
        print(f"campaign_report: realism: {problem}", file=sys.stderr)
        return 2
    for name in scenarios:
        row = by_scenario[name]["requirements"]
        print(f"{name}: {len(by_scenario[name]['sessions'])} session(s) with values; "
              + ", ".join(f"{req} {row[req]['passed']}/{row[req]['sessions']}" for req in row))
    print("P1: " + "; ".join(f"protocol {group['protocol_sha256'][:12]}: " + ", ".join(
        f"{n} {result}" for result, n in group["counts"].items() if n) for group in envelope_groups))
    print("traffic_realism minimums: " + ("met" if not missing else "missing: " + "; ".join(missing))
          + f"; {len(counted)} of {len(entries)} session(s) counted, {len(faults)} with a fault apart", flush=True)
    print(f"campaign_report: realism: {len(entries)} session(s), {len(envelope_groups)} protocol(s); record {out}",
          file=sys.stderr)
    return 0 if not missing else 1


# ---------------------------------------------------------------- majflt mode (the lead's answer to Q29)

MAJFLT_SCHEMA = "hyptcn3/collector-majflt-bound/1"
MAJFLT_KEY = "audit.collector_majflt_max"  # The value G2 sets by the rule (determined_at G2 of the protocol).
MAJFLT_FIELDS = ("max", "max_seq", "sum", "cycles")  # values.collector_majflt (scripts/collection.py majflt_record).
# The rule as audit.collector_majflt_note of the protocol states it (the lead's answer to Q29): the mode applies it
# only under a note that states it, and quotes it.
MAJFLT_RULE_TEXT = ("The rule, written before the data: the largest count per cycle observed in the error-free runs of "
                    "G2 on both VMs; at zero the bound is 0.")
MAJFLT_GUEST = ("none: the mode majflt reads saved audit records and the session.json the audit of each read; no VM is "
                "contacted")
MAJFLT_RULE = (
    "The lead's answer to question Q29 (2026-11-24) and audit.collector_majflt_note of the protocol: the bound "
    "audit.collector_majflt_max is null until G2, which sets it by the rule written before the data, the largest count "
    "per cycle observed in the error-free runs of G2 on both VMs, and 0 when every count is 0 (row P2 of "
    "dokazy/B10/odlozene_B10.md). This mode, outside the measurement code, proposes that value from saved audit "
    "records and never writes the protocol. It does not decide which runs are error-free: the G2 record states that, "
    "names the records it counts and gives them here, each once. scripts/collection.py audit (audit_session) writes "
    "the record of a session into the session's directory as audit_<UTC stamp>.json, or to the file its --out names. "
    "Of each record the mode reads schema and values.protocol_sha256, accepted, reasons, collector_majflt "
    "(majflt_record: max, the largest count of one cycle; max_seq, the seq of the first cycle with it; sum; cycles, "
    "the cycles counted), session_dir and session_sha256. The record names no VM, and the directory of a G2 session, "
    "a diagnostic run, need not name one either; so the VM is the session's: vm of the session.json in "
    "values.session_dir, read only when its sha256 is values.session_sha256 (the file the audit read) and only when "
    "the protocol's vms give that VM the domain it names (the executor's judgment, G2 preparation). Nothing else is "
    "read: no RAM, no archive member, no score. Refused by name, each a data error: a record that cannot be read or "
    "is no audit record of "
    "scripts/collection.py (schema hyptcn3/collection-audit/1 with values); one that is no audit of the protocol (its "
    "values.protocol_sha256 is not the sha256 of the protocol, which must be of schema 3); one whose verdict is not "
    "accepted (values.accepted not true), unless every one of its reasons is a collector warning outside the allowed "
    "patterns (logs: collector_warning_unlisted; audit.warnings_allowed is null until G2, so every warning refuses a "
    "session, and the lead's answer to Q60, 2026-11-24, counts such a session; the record lists it under "
    "values.warnings_only and its entry says accepted_by warnings_only); one without values.collector_majflt (absent or null) or with one not of "
    "its shape (four integers of at least 0, at least one cycle); a session.json missing, unreadable, not the one the "
    "audit read, or naming no VM of the protocol with its domain; a record named twice, and two records of one "
    "session (values.session_dir; a session counts once, the executor's judgment, G2 preparation). Per VM of the "
    "protocol: the largest max over its records, with its record, session (session_id), seq (max_seq) and cycle "
    "(full when the seq is a multiple of full_every, the cadence the audit holds an accepted session to, else delta; "
    "at a largest count of 0 every cycle has it and the seq is the first, 0), and the sessions and cycles counted; "
    "then the largest over the VMs, with all sessions and cycles. Equal counts go to the first record given, and "
    "over the VMs to the first VM of the protocol's vms (the executor's judgment, G2 preparation). The proposal for "
    "audit.collector_majflt_max is that largest count, so 0 when every count is 0. It is refused by name when a VM "
    "of the protocol has no record (the rule needs both VMs). The protocol is refused before any record is read "
    "when it is not of schema 3, lacks audit.collector_majflt_max or audit.collector_majflt_note, has a note that "
    "does not state this rule, has a bound that is not null (an audit under a bound accepts no cycle above it, so "
    "its records cannot show the largest count the rule asks for; the executor's judgment, G2 preparation), or names "
    "fewer than two VMs. Exit 0: the proposal is made, printed after one line per VM with the rule quoted from the "
    "note, and recorded in --out, a new file (refused before anything is read when it exists, and refused inside the "
    "session directory of a record); 2: a usage or data error, every refusal named on stderr and nothing written.")


def majflt_protocol(path):
    """(sha256, {VM name: domain} in the order of vms, full_every, audit.collector_majflt_note) of the protocol of the
    mode majflt; a DataError, before any record is read, for a protocol MAJFLT_RULE does not apply to."""
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as error:
        raise DataError(f"cannot read protocol {path}: {error}") from None
    if type(doc) is not dict or doc.get("schema") != protocol_v5.SCHEMA:
        raise DataError(f"protocol {path}: protocol schema is not {protocol_v5.SCHEMA}: {MAJFLT_KEY} is a key of its "
                        "audit section")
    # Only the two keys of the rule (the lead's answer to Q29); the audit read the whole section when it wrote each
    # record, and no feature or extractor code is imported here.
    audit = doc.get("audit")
    for key in ("collector_majflt_max", "collector_majflt_note"):
        if not isinstance(audit, dict) or key not in audit:
            raise DataError(f"protocol {path}: no audit.{key} (the lead's answer to Q29)")
    if audit["collector_majflt_max"] is not None:
        raise DataError(f"protocol {path}: {MAJFLT_KEY} is {_shown(audit['collector_majflt_max'])}, not null: an "
                        "audit under a bound accepts no cycle above it, so its records cannot show the largest count "
                        "the rule asks for (null until G2, determined_at G2)")
    note = audit["collector_majflt_note"]
    if not isinstance(note, str) or MAJFLT_RULE_TEXT not in note:
        raise DataError(f"protocol {path}: audit.collector_majflt_note does not state the rule this mode applies, "
                        f"\"{MAJFLT_RULE_TEXT}\"")
    rows = doc.get("vms")
    vms = {}
    for row in rows if type(rows) is list else ():
        if type(row) is dict and type(row.get("name")) is str and type(row.get("domain")) is str:
            vms.setdefault(row["name"], row["domain"])
    if type(rows) is not list or len(vms) != len(rows) or len(vms) < 2:
        raise DataError(f"protocol {path}: names fewer than two VMs, each with its own name and a domain (vms): the "
                        "rule takes the runs on both VMs")
    full = doc.get("full_every")
    if type(full) is not int or full < 1:
        raise DataError(f"protocol {path}: full_every is {_shown(full, 40)}, not an integer >= 1 (it tells a full "
                        "snapshot's cycle)")
    return hashlib.sha256(raw).hexdigest(), vms, full, note


def _majflt_shape(value):
    """values.collector_majflt as majflt_record writes it for a session with a count in every cycle."""
    return (isinstance(value, dict) and set(value) == set(MAJFLT_FIELDS)
            and all(type(value[key]) is int and value[key] >= 0 for key in MAJFLT_FIELDS) and value["cycles"] >= 1)


def majflt_audit(path, protocol_sha, vms, full_every):
    """One audit record by MAJFLT_RULE under the protocol with the sha256 protocol_sha, its vms ({name: domain}) and
    full_every: ({path, sha256, session, session_dir, session_json_sha256, vm, collector_majflt, cycle}, None), or
    (None, why it is refused)."""
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except OSError as error:
        return None, f"{path}: cannot be read ({type(error).__name__}: {error})"
    except ValueError as error:
        return None, f"{path}: not JSON ({error})"
    what = f"not an audit record of scripts/collection.py (a JSON object of schema {AUDIT_SCHEMA} with values)"
    if not isinstance(doc, dict):
        return None, f"{path}: {what}: not a JSON object"
    if doc.get("schema") != AUDIT_SCHEMA:
        return None, f"{path}: {what}: its schema is {_shown(_get(doc, 'schema'), 60)}"
    values = doc.get("values")
    if not isinstance(values, dict):
        return None, f"{path}: {what}: its values are {_shown(_get(doc, 'values'), 40)}"
    recorded = _get(values, "protocol_sha256")
    if recorded != protocol_sha:
        return None, (f"{path}: not an audit of the protocol: its values.protocol_sha256 is {_shown(recorded, 80)}, "
                      f"the protocol's sha256 is {protocol_sha}")
    verdict = _get(values, "accepted")
    warnings_only = verdict is False and _only_unlisted_warnings(values.get("reasons"))
    if verdict is not True and not warnings_only:
        reasons = values.get("reasons")
        listed = "; ".join(map(one_line, reasons)) if isinstance(reasons, list) else ""
        listed = listed if len(listed) <= 300 else listed[:297] + "..."
        return None, (f"{path}: its verdict is not accepted: values.accepted is {_shown(verdict, 40)}"
                      + (f" (reasons: {listed})" if listed else ""))
    faults = _get(values, "collector_majflt")
    if faults is _ABSENT or faults is None:
        return None, (f"{path}: records no values.collector_majflt (it is {_shown(faults)}), the largest count per "
                      "cycle the rule takes")
    if not _majflt_shape(faults):
        return None, (f"{path}: values.collector_majflt is {_shown(faults)}, not the audit's record of a session with "
                      "a count in every cycle (max, max_seq, sum and cycles: integers of at least 0, at least one "
                      "cycle)")
    # MAJFLT_RULE: the record names no VM; the session.json the audit read does.
    directory, bound = _get(values, "session_dir"), _get(values, "session_sha256")
    if not isinstance(directory, str) or not isinstance(bound, str):
        return None, (f"{path}: names no session.json the audit read: values.session_dir is {_shown(directory, 80)}, "
                      f"values.session_sha256 {_shown(bound, 80)}")
    meta_path = Path(directory) / "session.json"
    try:
        meta_raw = meta_path.read_bytes()
    except FileNotFoundError:
        return None, (f"{path}: no session.json in values.session_dir {directory}, which names the session's VM (was "
                      "the session moved after its audit?)")
    except OSError as error:
        return None, f"{path}: {meta_path} cannot be read ({type(error).__name__}: {error})"
    meta_sha = hashlib.sha256(meta_raw).hexdigest()
    if meta_sha != bound:
        return None, (f"{path}: {meta_path} is not the session.json the audit read: its sha256 is {meta_sha}, "
                      f"values.session_sha256 {bound}")
    try:
        meta = json.loads(meta_raw)
    except ValueError as error:
        return None, f"{path}: {meta_path} is not JSON ({error})"
    if not isinstance(meta, dict):
        return None, f"{path}: {meta_path} is not a JSON object"
    vm, domain, session = (_get(meta, key) for key in ("vm", "domain", "session_id"))
    if not isinstance(vm, str) or vm not in vms:
        return None, f"{path}: {meta_path} names the VM {_shown(vm, 40)}, not a VM of the protocol ({', '.join(vms)})"
    if domain != vms[vm]:
        return None, (f"{path}: {meta_path} names the domain {_shown(domain, 60)} for the VM {vm}, the protocol's vms "
                      f"give it {vms[vm]}")
    if not isinstance(session, str):
        return None, f"{path}: {meta_path} names no session_id: it is {_shown(session, 40)}"
    entry = {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "session": session, "session_dir": directory,
             "session_json_sha256": meta_sha, "vm": vm, "collector_majflt": {key: faults[key] for key in MAJFLT_FIELDS},
             "cycle": "full" if faults["max_seq"] % full_every == 0 else "delta"}
    if warnings_only:
        entry["accepted_by"] = "warnings_only"
    return entry, None


# The reason of the log audit for a collector warning outside audit.warnings_allowed (scripts/collection_logs.py, the
# section collector; the audit prefixes its problems with "logs: ").
UNLISTED_WARNING = "logs: collector_warning_unlisted:"


def _only_unlisted_warnings(reasons):
    """The lead's answer to Q60: a verdict refused for collector warnings outside the allowed patterns alone."""
    return (isinstance(reasons, list) and bool(reasons)
            and all(isinstance(r, str) and r.startswith(UNLISTED_WARNING) for r in reasons))


def majflt_together(entries, vms, out):
    """The refusals of the accepted entries taken together (MAJFLT_RULE): two records of one session and an --out
    inside the session directory of a record; when there is none, every VM of the protocol without a record."""
    refused, by_session = [], defaultdict(list)
    for entry in entries:
        by_session[entry["session_dir"]].append(entry["path"])
    for directory, paths in by_session.items():
        if len(paths) > 1:
            refused.append(f"{len(paths)} audit records name one session, values.session_dir {directory}: "
                           + ", ".join(paths) + " (a session counts once)")
    target = Path(os.path.realpath(out.parent))
    for directory in by_session:
        own = Path(os.path.realpath(directory))
        if target == own or target.is_relative_to(own):
            refused.append(f"refusing to write {out} inside the session directory {directory}")
    if refused:
        return refused
    return [f"no audit record of VM {name}: the rule needs both VMs of the protocol ({', '.join(vms)})"
            for name in vms if not any(entry["vm"] == name for entry in entries)]


def majflt_summary(entries, vms):
    """({VM: the largest count of its records with record, session, session_dir, seq and cycle, and its sessions and
    cycles}, the same over the VMs with the VM and all sessions and cycles) by MAJFLT_RULE: max() keeps the first of
    equal counts, so the first record given and the first VM of the protocol's vms."""
    by_vm = {}
    for name in vms:
        mine = [entry for entry in entries if entry["vm"] == name]
        top = max(mine, key=lambda entry: entry["collector_majflt"]["max"])
        by_vm[name] = {"max": top["collector_majflt"]["max"], "record": top["path"], "session": top["session"],
                       "session_dir": top["session_dir"], "seq": top["collector_majflt"]["max_seq"],
                       "cycle": top["cycle"], "sessions": len(mine),
                       "cycles": sum(entry["collector_majflt"]["cycles"] for entry in mine)}
    name = max(vms, key=lambda vm: by_vm[vm]["max"])
    largest = {"vm": name, **by_vm[name], "sessions": len(entries),
               "cycles": sum(entry["collector_majflt"]["cycles"] for entry in entries)}
    return by_vm, largest


def majflt_line(name, entry):
    """The line of one VM on stdout: its largest count, where it fell, and what was counted."""
    return (f"vm {name}: max {entry['max']} in session {entry['session']} seq {entry['seq']} ({entry['cycle']} cycle), "
            f"record {entry['record']}; {entry['sessions']} session(s), {entry['cycles']} cycle(s) counted")


def majflt(args, command):
    """The mode majflt (MAJFLT_RULE): refuses an --out that exists before it reads anything and a record named twice,
    then reads the protocol and each record in the order given; writes the new record, prints one line per VM and the
    proposal, and returns the exit code."""
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths = [os.path.abspath(path) for path in args.audits]
    real = [os.path.realpath(path) for path in paths]
    twice = sorted({path for path, r in zip(paths, real) if real.count(r) > 1})
    if twice:
        print("campaign_report: majflt: an audit record is named more than once: " + ", ".join(twice), file=sys.stderr)
        return 2
    try:
        protocol_sha, vms, full_every, note = majflt_protocol(args.protocol)
    except DataError as error:
        print(f"campaign_report: majflt: {error}", file=sys.stderr)
        return 2
    entries, refused = [], []
    for path in paths:
        entry, why = majflt_audit(path, protocol_sha, vms, full_every)
        if entry is None:
            refused.append(why)
        else:
            entries.append(entry)
    refused = refused or majflt_together(entries, vms, out)
    if refused:
        for why in refused:
            print(f"campaign_report: majflt: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: majflt: {len(refused)} refusal(s): no proposal, nothing written", file=sys.stderr)
        return 2
    by_vm, largest = majflt_summary(entries, vms)
    identity = git_identity()
    record = {"schema": MAJFLT_SCHEMA, "commit": identity["commit"], "commit_dirty": identity["dirty"],
              "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
              "guest": MAJFLT_GUEST, "command": command, "n": len(entries),
              "values": {"protocol": {"path": os.path.abspath(args.protocol), "sha256": protocol_sha,
                                      MAJFLT_KEY: None, "vms": vms, "full_every": full_every},
                         "records": entries, "by_vm": by_vm, "largest": largest,
                         "warnings_only": [e["path"] for e in entries if e.get("accepted_by") == "warnings_only"],
                         "proposal": {"key": MAJFLT_KEY, "value": largest["max"], "rule": MAJFLT_RULE_TEXT,
                                      "note": note},
                         "rule": MAJFLT_RULE},
              "note": "The bound of the collector's major faults per cycle proposed from saved audit records (the "
                      "lead's answer to Q29); the protocol is not written, no score is read and nothing is detected."}
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        print(f"campaign_report: --out appeared meanwhile, nothing was overwritten: {out}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"campaign_report: cannot create {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        print(f"campaign_report: cannot write {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    for name in vms:
        print(majflt_line(name, by_vm[name]))
    print(f"proposal: {MAJFLT_KEY} = {largest['max']} (vm {largest['vm']}, session {largest['session']} seq "
          f"{largest['seq']}, {largest['cycle']} cycle, record {largest['record']}; {largest['sessions']} session(s), "
          f"{largest['cycles']} cycle(s) on {len(vms)} VMs); the rule of audit.collector_majflt_note: "
          f"\"{MAJFLT_RULE_TEXT}\"", flush=True)
    print(f"campaign_report: majflt: {len(entries)} record(s), proposal {MAJFLT_KEY} = {largest['max']}; record {out}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------- timing mode (criterion worst_case_timing of G2)

TIMING_SCHEMA = "hyptcn3/g2-timing-report/1"
TIMING_RECORD_SCHEMA = "hyptcn3/g2-session/1"  # skuska/g2.py SESSION_SCHEMA: the record of one G2 session.
TIMING_KIND = "cas"  # skuska/cas.py KIND: the kind of a session of the worst case of time.
TIMING_PAIRS_NEEDED = 2  # The lead's answer to Q58: 2 pairs per mode.
TIMING_MODES = ("at_once", "shifted")  # skuska/cas.py AT_ONCE and SHIFTED.
TIMING_GUEST = ("none: the mode timing reads saved G2 session records, session files, the sidecars of the full "
                "snapshots, audit records and protocol copies; no VM is contacted")
TIMING_RULE = (
    "The criterion worst_case_timing of G2 (the lead's G2 skeleton, map row 10, the lead's answers Q58 to Q60). "
    "The mode reads the records of the timing sessions that skuska/cas.py block wrote (<g2-dir>/zaznamy/<session>.json "
    "of schema hyptcn3/g2-session/1 and kind cas), each once, and of each the session directory it names: "
    "session.json (bound by the record's session_json_sha256), protocol.json (the audit's bounds, the protocol of "
    "P2), end.json, events.json, the sidecars of the full snapshots in raw/ (through the archive's link after the "
    "reclaim; JSON only, never a RAM image) and the audit record the record names (bound by its sha256, its "
    "values.protocol_sha256 that of protocol.json and its values.session_sha256 that of session.json). It pairs the "
    "records by their pair and attempt (values.draw.item of skuska/cas.py) and judges each attempt both of whose "
    "sessions were audited with the definitions written before the runs, imported from skuska/cas.py (MODES_RULE, "
    "WINDOWS_RULE, judge): the shift of the full snapshots, the mode measured and whether it is the planned one, "
    "where the target full snapshot fell (the audit, the archive, the zataz_pamate window), and the shift of the "
    "grids from campaign_grids.grid_pairs over the two sessions; an attempt stopped by skuska/cas.py RESTART_RULE (1) "
    "is listed and not judged. Per session it sets values.timing of the audit (lateness_s_max, delta_ms_max, "
    "full_ms_max) against the bounds of its protocol (audit.lateness_max_s, audit.cycle_ms_max) and gives "
    "values.collector_majflt, and whether P2 (the mode majflt: majflt_protocol and majflt_audit) counts its audit. "
    "With --others, the audit records of the other error-free runs that the G2 record names (the lead's answer to "
    "Q59), it gives beside them per VM P2's largest count over those runs, and names the VM where the worst case sets "
    "the maximum (a count above that of every other run P2 counts) and whether it sets the value P2 proposes over "
    "both VMs; the rule of Q29 stays. The criterion is met when every mode has at least 2 pairs with an attempt that "
    "met its plan, both sessions done and counted (skuska/g2.py LOAD_RULE), each VM collected the target full "
    "snapshot of a met shifted pair during the other's audit and archive, and no session of a judged attempt has a "
    "maximum above its bound or none. Findings: a maximum above its bound or missing, a mode short of 2 met pairs, a "
    "VM that never collected during the other's audit and archive, an attempt with a session record missing, and an "
    "attempt that failed (a run that exited non-zero, a stop or an error of the driver other than RESTART_RULE's); a "
    "judged attempt that missed its plan is "
    "listed with its reasons (RESTART_RULE (2) runs it again) and is no finding by itself. "
    "Refused by name, each a data error: a record named twice, a record that is no timing record, a session file "
    "that differs from the record or cannot be read, an audit record that does not bind the session, sessions under "
    "different protocols, and an --out inside a session directory. Exit 0: the criterion is met and there is no "
    "finding; 1: a finding (the record names each); 2: a usage or data error, nothing written.")


def _timing_read(path, what):
    """(the raw bytes, the parsed JSON) of a file the mode reads; a DataError by name."""
    try:
        raw = Path(path).read_bytes()
        return raw, json.loads(raw)
    except OSError as error:
        raise DataError(f"{what} {path} cannot be read ({type(error).__name__}: {error})") from None
    except ValueError as error:
        raise DataError(f"{what} {path} is not JSON ({error})") from None


def timing_session(path, cas):
    """One record of a timing session by TIMING_RULE: its entry (vm, session, pair, attempt, files, audit, windows,
    full cycles, bounds); a DataError by name."""
    raw, doc = _timing_read(path, "the record")
    v = doc.get("values") if isinstance(doc, dict) else None
    if not isinstance(v, dict) or doc.get("schema") != TIMING_RECORD_SCHEMA or v.get("kind") != TIMING_KIND:
        raise DataError(f"{path}: no record of a timing session (schema {TIMING_RECORD_SCHEMA}, values.kind "
                        f"{TIMING_KIND})")
    item = (v.get("draw") or {}).get("item") if isinstance(v.get("draw"), dict) else None
    if (not isinstance(item, dict) or item.get("mode") not in TIMING_MODES or not isinstance(item.get("pair"), str)
            or type(v.get("attempt")) is not int or not isinstance(v.get("vm"), str)
            or not isinstance(v.get("session_dir"), str)):
        raise DataError(f"{path}: names no pair, mode, attempt, VM or session directory (values.draw.item of "
                        "skuska/cas.py)")
    directory = Path(v["session_dir"])
    entry = {"path": os.path.abspath(path), "sha256": hashlib.sha256(raw).hexdigest(), "vm": v["vm"],
             "session": v.get("session_id"), "session_dir": str(directory), "pair": item["pair"],
             "attempt": v["attempt"], "mode": item["mode"], "role": item.get("role"), "target": item.get("target"),
             "order": item.get("order"), "done": v.get("done") is True, "counted": v.get("counted") is True,
             "stop": v.get("stop"), "error": v.get("error"), "restarted": str(v.get("error") or "").startswith(
                 "Restart: "), "audit": None, "steps": v.get("steps") or [],
             "run_exit": (v.get("exit_codes") or {}).get("run") if isinstance(v.get("exit_codes"), dict) else None}
    if v.get("session_json_sha256") is None:
        return entry  # The session never wrote its session.json (it did not start): listed, nothing more to read.
    meta_raw, meta = _timing_read(directory / "session.json", "the session file")
    if hashlib.sha256(meta_raw).hexdigest() != v["session_json_sha256"]:
        raise DataError(f"{path}: {directory}/session.json is not the one the record names (session_json_sha256)")
    proto_raw, protocol = _timing_read(directory / "protocol.json", "the protocol copy")
    entry.update(protocol=str(directory / "protocol.json"), protocol_sha256=hashlib.sha256(proto_raw).hexdigest())
    try:
        entry["bounds"] = {"lateness_s_max": protocol["audit"]["lateness_max_s"],
                           "delta_ms_max": protocol["audit"]["cycle_ms_max"]["delta"],
                           "full_ms_max": protocol["audit"]["cycle_ms_max"]["full"]}
        full_every, cycles = protocol["full_every"], protocol["cycles"]
    except (KeyError, TypeError):
        raise DataError(f"{directory}/protocol.json has no audit.lateness_max_s, audit.cycle_ms_max, full_every or "
                        "cycles") from None
    events = directory / "events.json"
    try:
        entry["full"] = cas.full_cycles(directory / "raw", full_every, cycles)
    except ValueError as error:
        raise DataError(f"{path}: {error}") from None
    entry.update(load=cas.load_window(_timing_read(events, "the events file")[1] if events.exists() else None),
                 audit_window=cas.step_window(entry["steps"], "audit"),
                 archive_window=cas.step_window(entry["steps"], "archive"), full_every=full_every)
    audit = v.get("audit")
    if isinstance(audit, dict) and audit.get("report"):
        report_raw, report = _timing_read(audit["report"], "the audit record")
        values = report.get("values") if isinstance(report, dict) else None
        if (hashlib.sha256(report_raw).hexdigest() != audit.get("sha256") or not isinstance(values, dict)
                or report.get("schema") != AUDIT_SCHEMA or values.get("protocol_sha256") != entry["protocol_sha256"]
                or values.get("session_sha256") != v["session_json_sha256"]):
            raise DataError(f"{path}: the audit record {audit['report']} does not bind the session (its sha256, "
                            "schema, protocol_sha256 or session_sha256)")
        timing = values.get("timing") if isinstance(values.get("timing"), dict) else {}
        entry["audit"] = {"report": audit["report"], "accepted": values.get("accepted"),
                          "reasons": values.get("reasons"),
                          "timing": {key: timing.get(key) for key in entry["bounds"]},
                          "grid_phase_s": timing.get("grid_phase_s"),
                          "collector_majflt": values.get("collector_majflt")}
        entry["over_bounds"] = [
            f"{key} missing from values.timing" if number(entry["audit"]["timing"][key]) is None
            else f"{key} {entry['audit']['timing'][key]} above {bound}" for key, bound in entry["bounds"].items()
            if number(entry["audit"]["timing"][key]) is None
            or number(bound) is not None and entry["audit"]["timing"][key] > bound]
    return entry


def timing_attempt(entries, cas, grids):
    """The row of one attempt of a pair (TIMING_RULE): its status (judged, restarted, failed or incomplete), the
    judgment of skuska/cas.py, the shift of the grids, the maxima and the major faults per session."""
    first = entries[0]
    pair = {"id": first["pair"], "mode": first["mode"], "target": first["target"], "order": first["order"]}
    row = {"pair": pair["id"], "attempt": first["attempt"], "planned_mode": pair["mode"], "target": pair["target"],
           "order": pair["order"], "sessions": {}, "met": False, "why": []}
    for e in entries:
        row["sessions"][e["vm"]] = {
            "session": e["session"], "record": e["path"], "role": e["role"], "done": e["done"],
            "counted": e["counted"], "stop": e["stop"], "error": e["error"],
            **({"audit": e["audit"]["report"], "accepted": e["audit"]["accepted"], "reasons": e["audit"]["reasons"],
                "timing": e["audit"]["timing"], "bounds": e["bounds"], "over_bounds": e["over_bounds"],
                "collector_majflt": e["audit"]["collector_majflt"]} if e["audit"] else {})}
    vms = sorted(e["vm"] for e in entries)
    if not isinstance(pair["order"], list) or sorted(pair["order"]) != vms or len(vms) != 2:
        row.update(status="incomplete", why=[f"pair {pair['id']} attempt {row['attempt']}: the records name VM(s) "
                                             f"{', '.join(vms)}, the pair {pair['order']}"])
        return row
    if any(e["restarted"] for e in entries):
        row.update(status="restarted", why=[next(e["error"] for e in entries if e["restarted"])])
        return row
    if not all(e["audit"] for e in entries) or any(e["run_exit"] != 0 for e in entries):
        row.update(status="failed", why=[f"VM {e['vm']}: " + str(e["stop"] or e["error"] or (
            "no audit" if not e["audit"] else f"the run exited {e['run_exit']}"))
            for e in entries if not e["audit"] or e["run_exit"] != 0])
        return row
    judgment = cas.judge(pair, {e["vm"]: {"full": e["full"], "load": e["load"], "audit": e["audit_window"],
                                          "archive": e["archive_window"]} for e in entries}, first["full_every"])
    try:
        rows = [grids.grid_session(e["session_dir"], e["audit"]["report"])
                for e in sorted(entries, key=lambda e: e["vm"])]
        pairs = grids.grid_pairs([r for r in rows if r is not None]) if all(r is not None for r in rows) else []
    except (OSError, ValueError) as error:
        rows, pairs = None, []
        row["grid_error"] = f"{type(error).__name__}: {error}"
    over = [f"VM {e['vm']}: {text}" for e in entries for text in e["over_bounds"]]
    done = all(e["done"] and e["counted"] for e in entries)
    row.update(status="judged", judgment=judgment,
               full_snapshots={"shift_s": judgment["shift_full_s"], "target": judgment["target"],
                               "nearest": judgment["nearest"], "overlaps": judgment["overlaps"]},
               grids=pairs[0] if pairs else {"shift_s": None, "why": "the two sessions' measured phases do not "
                                                                    "overlap or a session has none"},
               mode={"measured": judgment["mode"], "met": judgment["met_mode"]}, windows=judgment["windows"],
               over_bounds=over, met=judgment["met"] and done,
               why=judgment["why"] + ([] if done else ["a session is not done or not counted (skuska/g2.py "
                                                       "DONE_RULE, LOAD_RULE)"]))
    return row


def timing_majflt(sessions, others, protocol_path, vms):
    """The major faults by Q59 through P2: per VM the largest count of the judged timing sessions and whether P2
    counts it, beside P2's largest count over the other error-free runs; where the worst case sets the maximum."""
    worst = {}
    for e in sessions:
        faults = e["audit"]["collector_majflt"]
        if _majflt_shape(faults) and (e["vm"] not in worst or faults["max"] > worst[e["vm"]]["max"]):
            worst[e["vm"]] = {"max": faults["max"], "seq": faults["max_seq"], "session": e["session"],
                              "audit": e["audit"]["report"]}
    out = {"timing": worst, "others": {}, "others_given": len(others), "others_refused": [], "sets_maximum": [],
           "p2": None}
    try:
        sha, p2_vms, full_every, _ = majflt_protocol(protocol_path)
    except DataError as error:
        out["p2"] = f"refused: {error}"
        return out
    out["p2"] = "applied"
    for vm, top in worst.items():
        _, why = majflt_audit(top["audit"], sha, p2_vms, full_every)
        top["counted_by_p2"] = why is None
        if why:
            top["p2_refusal"] = why
    mine = {os.path.realpath(e["session_dir"]) for e in sessions}
    for path in others:
        entry, why = majflt_audit(os.path.abspath(path), sha, p2_vms, full_every)
        if entry is not None and os.path.realpath(entry["session_dir"]) in mine:
            entry, why = None, f"{path}: the audit of a timing session, not of another run"
        if entry is None:
            out["others_refused"].append(why)
            continue
        best = out["others"].get(entry["vm"])
        if best is None or entry["collector_majflt"]["max"] > best["max"]:
            out["others"][entry["vm"]] = {"max": entry["collector_majflt"]["max"],
                                          "seq": entry["collector_majflt"]["max_seq"], "session": entry["session"],
                                          "audit": entry["path"]}
    for vm in vms:
        top, rest = worst.get(vm), out["others"].get(vm)
        if top and top.get("counted_by_p2") and (rest is None or top["max"] > rest["max"]) and others:
            out["sets_maximum"].append(f"VM {vm}: the worst case sets the maximum, {top['max']} in session "
                                       f"{top['session']} seq {top['seq']}"
                                       + (f" (the other runs: {rest['max']})" if rest else " (no other run of it)"))
    counted = [t["max"] for t in worst.values() if t.get("counted_by_p2")]
    rest = [r["max"] for r in out["others"].values()]
    if others and counted and (not rest or max(counted) > max(rest)):
        out["sets_maximum"].append(f"both VMs: the worst case sets the value P2 proposes, {max(counted)} (the other "
                                   f"runs: {max(rest) if rest else 'none'})")
    return out


def timing_line(row):
    """The line of one attempt on stdout."""
    head = f"{row['pair']} attempt {row['attempt']} ({row['planned_mode']}"
    head += f", target {row['target']})" if row["target"] else ")"
    if row["status"] != "judged":
        return f"{head}: {row['status']}: " + "; ".join(map(one_line, row["why"]))
    full = row["full_snapshots"]["shift_s"]
    grid = row["grids"].get("shift_s")
    maxima = ", ".join(f"{vm} full {s['timing']['full_ms_max']}/{s['bounds']['full_ms_max']} ms delta "
                       f"{s['timing']['delta_ms_max']}/{s['bounds']['delta_ms_max']} ms lateness "
                       f"{s['timing']['lateness_s_max']}/{s['bounds']['lateness_s_max']} s"
                       for vm, s in sorted(row["sessions"].items()))
    return (f"{head}: {'met' if row['met'] else 'missed'}, measured {row['mode']['measured']}, shift of the full "
            f"snapshots {full if full is None else f'{full:+.3f}'} s, of the grids {grid} s; {maxima}"
            + ("" if row["met"] else "; " + "; ".join(map(one_line, row["why"]))))


def timing(args, command):
    """The mode timing (TIMING_RULE): refuses an --out that exists before it reads anything and a record named twice,
    then reads every record; writes the new record, prints one line per attempt and the criterion, and returns the
    exit code."""
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths = [os.path.abspath(path) for path in args.records]
    real = [os.path.realpath(path) for path in paths]
    twice = sorted({path for path, r in zip(paths, real) if real.count(r) > 1})
    if twice:
        print("campaign_report: timing: a record is named more than once: " + ", ".join(twice), file=sys.stderr)
        return 2
    # The definitions written before the runs live in the driver (skuska/cas.py); only this mode imports it.
    from scripts import campaign_grids
    from skuska import cas
    entries, refused = [], []
    for path in paths:
        try:
            entries.append(timing_session(path, cas))
        except DataError as error:
            refused.append(str(error))
    protocols = sorted({e["protocol_sha256"] for e in entries if "protocol_sha256" in e})
    if len(protocols) > 1:
        refused.append("the timing sessions ran under different protocols (sha256 " + ", ".join(protocols) + ")")
    target = Path(os.path.realpath(out.parent))
    refused += [f"refusing to write {out} inside the session directory {e['session_dir']}" for e in entries
                if target == Path(os.path.realpath(e["session_dir"]))
                or target.is_relative_to(os.path.realpath(e["session_dir"]))]
    if refused or not entries:
        for why in refused or ["no record"]:
            print(f"campaign_report: timing: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: timing: {len(refused)} refusal(s): no report, nothing written", file=sys.stderr)
        return 2
    groups = defaultdict(list)
    for e in entries:
        groups[(e["pair"], e["attempt"])].append(e)
    rows = [timing_attempt(sorted(group, key=lambda e: e["vm"]), cas, campaign_grids)
            for _, group in sorted(groups.items())]
    vms = sorted({e["vm"] for e in entries})
    met = {mode: sorted({r["pair"] for r in rows if r["met"] and r["planned_mode"] == mode}) for mode in TIMING_MODES}
    collected = sorted({r["judgment"]["collecting"] for r in rows if r["met"] and r["planned_mode"] == "shifted"})
    over = [f"{r['pair']} attempt {r['attempt']}: {text}" for r in rows if r["status"] == "judged"
            for text in r["over_bounds"]]
    findings = list(over)
    findings += [f"mode {mode}: {len(met[mode])} pair(s) met their plan, fewer than {TIMING_PAIRS_NEEDED}"
                 for mode in TIMING_MODES if len(met[mode]) < TIMING_PAIRS_NEEDED]
    findings += [f"VM {vm} never collected the target full snapshot of a met shifted pair during the other VM's "
                 "audit and archive" for vm in vms if vm not in collected]
    findings += [f"{r['pair']} attempt {r['attempt']}: {r['status']}: " + "; ".join(map(one_line, r["why"]))
                 for r in rows if r["status"] in ("incomplete", "failed")]
    judged = [e for e in entries if e["audit"] and any(r["status"] == "judged" and r["pair"] == e["pair"]
                                                        and r["attempt"] == e["attempt"] for r in rows)]
    protocol = next((e["protocol"] for e in entries if "protocol" in e), None)
    majflt = (timing_majflt(judged, args.others or [], protocol, vms) if protocol is not None else
              {"timing": {}, "others": {}, "others_given": len(args.others or []), "others_refused": [],
               "sets_maximum": [], "p2": "not applied: no timing session wrote its session.json"})
    criterion = {"met_pairs": met, "needed_per_mode": TIMING_PAIRS_NEEDED, "collecting_vms": collected,
                 "over_bounds": over,
                 "met": all(len(met[m]) >= TIMING_PAIRS_NEEDED for m in TIMING_MODES) and not over
                 and all(vm in collected for vm in vms)}
    identity = git_identity()
    record = {"schema": TIMING_SCHEMA, "commit": identity["commit"], "commit_dirty": identity["dirty"],
              "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
              "guest": TIMING_GUEST, "command": command, "n": len(rows),
              "values": {"stage": "G2", "criterion": "worst_case_timing",
                         "definitions": {"modes": cas.MODES_RULE, "windows": cas.WINDOWS_RULE},
                         "protocol": {"path": protocol, "sha256": protocols[0] if protocols else None},
                         "records": [{k: e[k] for k in ("path", "sha256", "vm", "session", "pair", "attempt")}
                                     for e in entries],
                         "attempts": rows, "result": criterion, "majflt": majflt, "findings": findings,
                         "rule": TIMING_RULE},
              "note": "The report of the worst case of time of G2 from saved files; no RAM image or score is read and "
                      "nothing is detected."}
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        print(f"campaign_report: --out appeared meanwhile, nothing was overwritten: {out}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"campaign_report: cannot create {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        print(f"campaign_report: cannot write {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    for row in rows:
        print(timing_line(row))
    for vm in vms:
        top, rest = majflt["timing"].get(vm), majflt["others"].get(vm)
        print(f"majflt vm {vm}: worst case {top['max'] if top else None}"
              + (f" (session {top['session']} seq {top['seq']})" if top else "")
              + f", other error-free runs {rest['max'] if rest else None}")
    for text in majflt["sets_maximum"]:
        print("majflt: " + text)
    print("worst_case_timing: " + ("met" if criterion["met"] else "not met") + "; "
          + "; ".join(f"{mode} {len(met[mode])}/{TIMING_PAIRS_NEEDED} pair(s)" for mode in TIMING_MODES)
          + f"; {len(findings)} finding(s)", flush=True)
    print(f"campaign_report: timing: {len(entries)} record(s), {len(rows)} attempt(s); record {out}", file=sys.stderr)
    return 0 if criterion["met"] and not findings else 1


# ---------------------------------------------------------------- G2 tables: guest, events, restarts (package H1b6a)
# The criteria guest_matches_repository, event_effects and restart_loops_bounded of G2 (the lead's G2 skeleton, map
# rows 1 to 3, the lead's answers Q43 and Q50 to Q53). The three modes read saved files only: the G2 session
# directory (never its raw/), its audit record, the records of the G2 driver (skuska/g2.py,
# <g2-dir>/zaznamy/<session>.json) and of the fault injector (skuska/poruchy.py, <g2-dir>/poruchy/<session>.json).

GUEST_TABLE_SCHEMA = "hyptcn3/g2-guest-table/1"
EVENTS_TABLE_SCHEMA = "hyptcn3/g2-events-table/1"
RESTARTS_TABLE_SCHEMA = "hyptcn3/g2-restarts-table/1"
GUEST_REPOSITORY = ROOT  # The git repository whose commits the mode guest reads: this script's own.
G2_SESSION_EVENTS = "hyptcn3/session-events/1"  # scripts/collection.py Events.close: the schema of events.json.
G2_JOURNAL_SEGMENT = "hyptcn3/guest-journal-segment/1"  # lab/guest_state.py journal: guest/journal_segment.json.
G2_LOG_SEGMENT = "hyptcn3/guest-log-segment/1"  # lab/guest_state.py segment: guest/session_segment.json.
EMPTY_EVENT = "naprazdno"  # Decision D8: the empty event, its predicate none by definition (lab/udalosti.py).
RESTART_TYPE = "zla_konfiguracia_sluzby"  # The event type whose occurrences restart_loops_bounded names.
KILL_FAULT = "zabita_sluzba"  # skuska/poruchy.py FAULTS: the killed guest service outside an event (H4).
# lab/udalosti.py unit_states: APPS, nginx and DATABASE, the units of the reply of every start and stop of an event.
NO_EFFECT_UNITS = ("hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@docs",
                   "hyptcn-lab@worker", "nginx", "postgresql@15-main")
FITS_S = (3.0, 3.5)  # Q52: every spacing of a loop (and at the kill every delay) lies here; the lab: 3.2488-3.2517 s.
START_LIMIT_BURST = 5  # lab/hyptcn-lab@.service StartLimitBurst (Q52).
START_LIMIT_INTERVAL_S = 60  # lab/hyptcn-lab@.service StartLimitIntervalSec (Q52).
GUEST_CLOCK_S = 1.0  # The log audit's bound of the guest clock's offset (scripts/collection_logs.py guest_clock).
PERIOD_SPACINGS = 5  # Q52: a group of journal lines with at least 5 spacings ...
PERIOD_CV = 0.1  # ... and a coefficient of variation of them below 0.1 is periodic.
KILLS_NEEDED = 1  # The fault plan (skuska/poruchy.py PLAN_RULE): the killed service once on each VM.
# A line of systemd (PID 1) about a hyptcn-lab@ unit that a restart loop leaves: its unit and what it says.
G2_UNIT_LINE = re.compile(r"systemd\[1\]: (hyptcn-lab@[\w.-]+)\.service: (Scheduled restart job|Failed with result|"
                          r"Start request repeated too quickly)")
G2_SYSTEMD_LINE = re.compile(r"^\S+ \S+ systemd\[1\]: (.*)$")
G2_SYSTEMD_TROUBLE = re.compile(r"(?i)fail|Scheduled restart job|Start request repeated too quickly")
G2_JOURNAL_FORM = re.compile(r"^\S+ \S+ ([^\s\[:]+)(?:\[\d+\])?: (.*)$")  # <time> <host> <identifier>[<pid>]: ...
GUEST_FILE_LINE = re.compile(r"([0-9a-f]{64})  (/\S+)")  # A sha256sum line of collection.guest_identity.
G2_SELECTION = (
    "the sessions of a table (the executor's judgment, G2 preparation, from the records of H1a to H1b4): a session "
    "whose driver's record names the criterion in values.excluded.criteria is left out by name (skuska/g2.py "
    "Block.record: the ground truth of H1b1 and the worst case of time of H1b4 name event_effects, "
    "marked_rows_per_event and invalid_rows.max), and so is, where the criterion's rule says so, a session of H4 or "
    "one the driver's record names no audit of; where the rule reads the load, a session whose record says counted "
    "false (skuska/g2.py LOAD_RULE: a heavy process or a run outside the block's plan in its measured phase; the "
    "skeleton, section 0: nothing that goes into the values or criteria of G2 is measured beside one) counts towards "
    "no minimum, but what it shows is judged and a finding in it is a finding (Q51: an invalid predicate is never "
    "left out); every other session counts")


def _g2_digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class G2TableSession:
    """One G2 session directory as the modes guest, events and restarts read it: session.json, protocol.json (the
    file session.json binds) and the driver's record <g2-dir>/zaznamy/<session>.json (bound by its session_id, vm,
    stage, session_dir and session_json_sha256), every file read listed with its sha256; a DataError by name."""

    def __init__(self, path, g2_dir):
        from skuska import g2  # The driver's record: its schema and stage.
        self.dir = Path(os.path.abspath(path))
        self.files = []
        if not self.dir.is_dir():
            raise DataError(f"{self.dir}: not a session directory")
        self.meta, self.meta_sha = self.read("session.json")
        self.id, self.vm = self.meta.get("session_id"), self.meta.get("vm")
        if not isinstance(self.id, str) or not isinstance(self.vm, str) or self.id != self.dir.name:
            raise DataError(f"{self.dir}: session.json names the session {_shown(_get(self.meta, 'session_id'), 80)} "
                            f"on VM {_shown(_get(self.meta, 'vm'), 20)}, not the directory's session on a VM")
        if self.meta.get("role") != CONTROLS_ROLE:
            raise DataError(f"{self.dir}: session.json names the role {_shown(_get(self.meta, 'role'), 40)}, not "
                            f"{CONTROLS_ROLE} (the sessions of G2 are diagnostic runs)")
        self.protocol, self.protocol_sha = self.read("protocol.json")
        if self.meta.get("protocol_sha256") != self.protocol_sha:
            raise DataError(f"{self.dir}: protocol.json has the sha256 {self.protocol_sha}, session.json binds "
                            f"{_shown(_get(self.meta, 'protocol_sha256'), 80)}")
        self.record_path = Path(os.path.abspath(g2_dir)) / "zaznamy" / f"{self.id}.json"
        record, self.record_sha = self.read("record", self.record_path, g2.SESSION_SCHEMA)
        v = record.get("values")
        if (not isinstance(v, dict) or v.get("stage") != g2.STAGE or v.get("session_id") != self.id
                or v.get("vm") != self.vm or not isinstance(v.get("session_dir"), str)
                or os.path.realpath(v["session_dir"]) != os.path.realpath(self.dir)
                or v.get("session_json_sha256") != self.meta_sha):
            raise DataError(f"{self.record_path}: the driver's record is not of this session (its stage, session_id, "
                            "vm, session_dir or session_json_sha256)")
        self.values, self.kind = v, v.get("kind")
        excluded = v.get("excluded")
        if excluded is None:
            self.excluded, self.excluded_rule = [], None
        elif (isinstance(excluded, dict) and isinstance(excluded.get("criteria"), list)
              and all(isinstance(name, str) for name in excluded["criteria"])):
            self.excluded, self.excluded_rule = excluded["criteria"], excluded.get("rule")
        else:
            raise DataError(f"{self.record_path}: values.excluded is {_shown(excluded, 80)}, neither null nor "
                            "{criteria: [...], rule}")
        vms = [row.get("name") for row in self.protocol.get("vms") or [] if isinstance(row, dict)]
        self.vms = vms if vms and all(isinstance(name, str) for name in vms) else None

    def read(self, name, path=None, schema=None):
        """(the JSON object, its sha256) of a file of the session, listed in files."""
        path = Path(path) if path is not None else self.dir / name
        doc, sha = _controls_file(path, schema)
        self.listed(name, path, sha)
        return doc, sha

    def listed(self, name, path, sha):
        self.files.append({"name": name, "path": str(path), "sha256": sha})

    def bind(self, protocol):
        """A DataError unless the session's protocol.json agrees with --protocol outside the paths of G1 and later
        stages (gates.stage_sha256 of stage G0, the hash a record of G0 binds) and --protocol names the session's
        VM."""
        from scripts import gates
        try:
            mine = gates.stage_sha256(self.dir / "protocol.json", "G0")
        except ValueError as error:
            raise DataError(f"{self.dir}/protocol.json: {error}") from None
        if mine != protocol["binding_G0"]:
            raise DataError(f"{self.dir}: its protocol.json differs from --protocol {protocol['path']} outside the "
                            f"paths of G1 and later stages (gates.stage_sha256 G0 {mine}, not {protocol['binding_G0']})")
        if self.vm not in protocol["vms"]:
            raise DataError(f"{self.dir}: a session of VM {self.vm}, which --protocol does not name")

    def audit(self):
        """The values of the audit record the driver's record names (values.audit.report, bound by its sha256 and by
        its session_dir, session_sha256 and protocol_sha256); None when it names none."""
        named = self.values.get("audit")
        if named is None:
            return None
        if not isinstance(named, dict) or not isinstance(named.get("report"), str):
            raise DataError(f"{self.record_path}: values.audit names no audit record")
        doc, sha = self.read("audit", named["report"], AUDIT_SCHEMA)
        values = doc.get("values")
        if (sha != named.get("sha256") or not isinstance(values, dict)
                or not isinstance(values.get("session_dir"), str)
                or os.path.realpath(values["session_dir"]) != os.path.realpath(self.dir)
                or values.get("session_sha256") != self.meta_sha or values.get("protocol_sha256") != self.protocol_sha):
            raise DataError(f"{named['report']}: not the audit record of this session that the driver's record names "
                            "(its sha256, session_dir, session_sha256 or protocol_sha256)")
        return values

    def selection(self, criterion, h4=(), audited=True, load=True):
        """(status, why) of the session for the criterion by G2_SELECTION: left_out, load or counted."""
        if criterion in self.excluded:
            return "left_out", f"its record leaves it out of {criterion} (values.excluded: {self.excluded_rule})"
        if self.kind in h4:
            return "left_out", f"a session of H4 (its record's kind {self.kind})"
        if not audited:
            return "left_out", "the driver's record names no audit of it"
        if load and self.values.get("counted") is not True:
            summary = (self.values.get("load") or {}).get("summary") if isinstance(self.values.get("load"), dict) \
                else None
            reasons = summary.get("reasons") if isinstance(summary, dict) else None
            return "load", ("its record says counted false (skuska/g2.py LOAD_RULE)"
                            + (": " + "; ".join(map(str, reasons)) if reasons else ""))
        return "counted", None

    def entry(self, status=None, why=None):
        return {"session_id": self.id, "vm": self.vm, "kind": self.kind, "scenario": self.meta.get("scenario"),
                "path": str(self.dir), "status": status, "why": why,
                "record": {"path": str(self.record_path), "sha256": self.record_sha}, "files": self.files}

    def planned(self):
        """(the planned events of session.json, the records of events.json or None when it is absent); a DataError
        by name."""
        planned = self.meta.get("events")
        if not isinstance(planned, list) or not all(isinstance(item, dict) and isinstance(item.get("type"), str)
                                                    for item in planned):
            raise DataError(f"{self.dir}: session.json events is no list of planned events with a type")
        records = None
        if planned and (self.dir / "events.json").exists():
            doc, _ = self.read("events.json", schema=G2_SESSION_EVENTS)
            records = doc.get("events")
            if not isinstance(records, list):
                raise DataError(f"{self.dir}/events.json holds no list of events")
        return planned, records


def _g2_protocol(path):
    """--protocol of the modes events and restarts: {path, sha256, binding_G0, binding_rule, types, vms, interval_s};
    a DataError, a usage error before any session is read, when it is no protocol of schema 3 with events.types, vms
    and interval_s."""
    from scripts import gates
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as error:
        raise DataError(f"cannot read protocol {path}: {error}") from None
    events = doc.get("events") if isinstance(doc, dict) else None
    types = events.get("types") if isinstance(events, dict) else None
    vms = [row.get("name") for row in doc.get("vms") or [] if isinstance(row, dict)] if isinstance(doc, dict) else []
    if (not isinstance(doc, dict) or doc.get("schema") != protocol_v5.SCHEMA or not isinstance(types, dict) or not types
            or not vms or not all(isinstance(name, str) for name in vms) or not _number(doc.get("interval_s"))
            or doc["interval_s"] <= 0):
        raise DataError(f"protocol {path}: no protocol of schema {protocol_v5.SCHEMA} with events.types, vms and "
                        "interval_s")
    try:
        binding = gates.stage_sha256(path, "G0")
    except ValueError as error:
        raise DataError(f"protocol {path}: {error}") from None
    return {"path": os.path.abspath(path), "sha256": hashlib.sha256(raw).hexdigest(), "binding_G0": binding,
            "binding_rule": "gates.stage_sha256 of stage G0 (the hash a record of G0 binds): the protocol without the "
                            "paths determined_at gives G1 and later stages", "types": sorted(types), "vms": vms,
            "interval_s": doc["interval_s"]}


def _g2_start(args, mode):
    """(out, session paths) of a mode; an error line on stderr and None when --out exists or a directory is named
    twice (nothing read)."""
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return None
    paths = [os.path.abspath(path) for path in args.session_dirs]
    real = [os.path.realpath(path) for path in paths]
    twice = sorted({path for path, r in zip(paths, real) if real.count(r) > 1})
    if twice:
        print(f"campaign_report: {mode}: a session directory is named more than once: " + ", ".join(twice),
              file=sys.stderr)
        return None
    return out, paths


def _g2_dir(args):
    from skuska import g2  # The default G2 directory of the driver (the lead's G2 skeleton, section 5).
    return Path(os.path.abspath(args.g2_dir)) if args.g2_dir is not None else g2.G2_DIR


def _g2_refusals(mode, out, sessions, refused):
    """The refusals of a mode, an --out inside a session directory among them, printed; True when there are any."""
    target = Path(os.path.realpath(out.parent))
    refused = refused + [f"refusing to write {out} inside the session directory {s.dir}" for s in sessions
                         if target == Path(os.path.realpath(s.dir)) or target.is_relative_to(os.path.realpath(s.dir))]
    if refused or not sessions:
        for why in refused or ["no session"]:
            print(f"campaign_report: {mode}: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: {mode}: {len(refused)} refusal(s): no table, nothing written", file=sys.stderr)
        return True
    return False


def _g2_record(schema, guest, command, n, values, note):
    """A new record with check E's header (commit, date, host, guest, command, n) and values with the stage G2."""
    identity = git_identity()
    return {"schema": schema, "commit": identity["commit"], "commit_dirty": identity["dirty"],
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
            "guest": guest, "command": command, "n": n, "values": {"stage": "G2", **values}, "note": note}


def _g2_write(out, record):
    """Write the new record exclusively; 0, or 2 with the error on stderr."""
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        print(f"campaign_report: --out appeared meanwhile, nothing was overwritten: {out}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"campaign_report: cannot create {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        print(f"campaign_report: cannot write {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    return 0


def _g2_segment_file(s, name, schema, suffix):
    """(path, None) of the file of guest/<name> whose entry's name ends in -<suffix>, its bytes bound by the entry's
    gz_sha256, or (None, why); a segment record that is no JSON object is a DataError."""
    if not (s.dir / "guest" / name).exists():
        return None, f"guest/{name} is missing (a capture that did not complete fetches none)"
    doc, _ = s.read(f"guest/{name}")
    if doc.get("schema") != schema:
        return None, f"guest/{name} has the schema {_shown(_get(doc, 'schema'), 60)}, not {schema}"
    entries = [e for e in doc.get("files") or [] if isinstance(e, dict) and isinstance(e.get("name"), str)
               and e["name"].endswith("-" + suffix)]
    if len(entries) != 1:
        return None, f"guest/{name} lists {len(entries)} files whose name ends in -{suffix}, not one"
    file = entries[0].get("file")
    if not isinstance(file, str) or not file or "/" in file or file in (".", ".."):
        return None, f"guest/{name} names no file of guest/ for its -{suffix}"
    path = s.dir / "guest" / file
    try:
        sha = _g2_digest(path)
    except OSError as error:
        return None, f"guest/{file} cannot be read ({type(error).__name__}: {error})"
    if sha != entries[0].get("gz_sha256"):
        return None, f"guest/{file} is not the file guest/{name} binds (its gz_sha256)"
    s.listed(f"guest/{file}", path, sha)
    return path, None


def _g2_journal(s):
    """(path, [(unix time, line)]) of the session's guest journal (lab_trial.journal_lines), or (None, why)."""
    from scripts import lab_trial  # The lab test's reader of a fetched journal (Q53).
    path, why = _g2_segment_file(s, "journal_segment.json", G2_JOURNAL_SEGMENT, "journal.txt")
    if path is None:
        return None, why
    try:
        return path, list(lab_trial.journal_lines(path))
    except (OSError, EOFError, ValueError) as error:
        raise DataError(f"{path}: the journal its segment binds cannot be read ({type(error).__name__}: "
                        f"{error})") from None


def _g2_window(window):
    """A window [start, end] of host times as a table shows it, or None."""
    return None if window is None else {"start_unix": round(window[0], 6), "end_unix": round(window[1], 6),
                                        "start_utc": utc(window[0]), "end_utc": utc(window[1])}


# ------------------------------------------------ the mode guest (criterion guest_matches_repository)

GUEST_GUEST = ("none: the mode guest reads saved session files and the records of the G2 driver, and the files of "
               "lab/ of each session's commit through git; no VM is contacted")
GUEST_RULE = (
    "The criterion guest_matches_repository of G2 (the lead's G2 skeleton, map row 1, the lead's answer to Q53): the "
    "sha256 of the deployed files of lab/ on both VMs are those of the files of lab/ in the commit. Of each G2 session "
    "directory given the mode reads session.json (commit, commit_dirty, vm, guest_before: the identity "
    "collection.guest_identity took before the capture, whose stack_manifest holds a sha256sum line of every path of "
    "the deployed set, the dpkg-query lines of nginx, postgresql, python3 and python3-psycopg2 and the line of the "
    "active timers; lab_sha256, the lab/ of the tree that ran the session), protocol.json (the session's copy, the "
    "file session.json protocol_sha256 binds; its vms name the VMs) and the driver's record "
    "<g2-dir>/zaznamy/<session>.json (G2TableSession). The files of a commit come from the repository of this script "
    "and never from its working tree: git rev-parse --verify <commit>^{commit} must give the commit back, git ls-tree "
    "-z <commit> lab/ lists the top-level entries of lab/ (a blob of mode 100644 or 100755 is a deployed file; a tree "
    "such as lab/tests is not, as collection.lab_files takes files only), and the sha256 of a file is that of the "
    "bytes of git show <commit>:lab/<file>, checked against the blob's object id in the listing (git's hash of "
    "'blob <size>' and a NUL before the bytes), so no filter or text conversion passes unseen; the deployed set of the "
    "commit is collection.deployed_paths of its files (/opt/hyptcn-lab/<file> and the two copies lab/install.sh "
    "installs). Per session: its VM and the kind of its record, the commit and commit_dirty, and per guest path the "
    "guest's sha256, the commit's and whether they are equal (a path of the commit's set without a line, or a line of "
    "a path the set lacks, differs too); whether session.json lab_sha256 equals the commit's lab/ (else the session's "
    "own check, collection.guest_mismatch against the working tree, compared another lab/); the dpkg lines and the "
    "timers of the manifest. Per VM the distinct dpkg and timers values over its sessions, and whether the VMs agree. "
    "A session whose record names guest_matches_repository in values.excluded.criteria is left out by name "
    "(G2_SELECTION); every other session counts, of every kind, verdict and load (the guest is one for every table of "
    "G2). The criterion is met when every VM of the protocol has a session, the guest of every session equals its "
    "commit's lab/ and so does its lab_sha256, and each VM shows one dpkg and one timers value over its sessions, the "
    "same on every VM; every other outcome is a finding by name. Limits, no finding: the manifest holds the deployed "
    "set of the session's own tree only, so a stale file an older deployment left in /opt/hyptcn-lab is not seen; that "
    "only labctl deploy deployed is the evidence of lab_trial deploy (map row 1, P4), not of this table. Refused by "
    "name, each a data error: a directory without session.json or protocol.json, a session of another role than "
    "diagnostic, a protocol.json other than the one session.json binds, a driver's record missing or of another "
    "session, a session.json without a stack_manifest of lines or a lab_sha256, a commit that is no full object name "
    "or not in the repository, an entry of lab/ at the commit that is no regular file or whose bytes do not give its "
    "object id, sessions whose protocols name other VMs or a VM the protocol does not name, a directory named twice, "
    "and an --out that exists (refused before anything is read) or lies inside a session directory. Exit 0: the table "
    "is written to --out, a new JSON record with the provenance header of check E and the stage G2, and the criterion "
    "is met; 1: the table is written and the criterion is not met, every finding named; 2: a usage or data error, "
    "every refusal named on stderr and nothing written.")


def _git(repository, *args):
    try:
        return subprocess.run(["git", "-C", str(repository), *args], capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise DataError(f"git {args[0]} cannot run in {repository}: {type(error).__name__}: {error}") from None


def guest_commit_files(repository, commit):
    """{lab/<file>: sha256} of the top-level files of lab/ in `commit` of the git repository `repository`
    (GUEST_RULE), from git and never from a working tree; a DataError by name."""
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise DataError(f"the commit {_shown(commit, 80)} is no full object name")
    done = _git(repository, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")
    if done.returncode or done.stdout.decode(errors="replace").strip() != commit:
        raise DataError(f"the commit {commit} is not in the repository {repository}")
    done = _git(repository, "ls-tree", "-z", commit, "lab/")
    if done.returncode:
        raise DataError(f"git ls-tree {commit} lab/ failed in {repository}: "
                        + done.stderr.decode(errors="replace").strip()[:200])
    files = {}
    for item in done.stdout.split(b"\0"):
        if not item:
            continue
        head, _, raw_name = item.partition(b"\t")
        mode, kind, oid = head.decode(errors="replace").split(" ")
        name = raw_name.decode(errors="replace")
        if kind != "blob":
            continue  # A tree (lab/tests) is no deployed file: collection.lab_files takes the files of lab/ only.
        if mode not in ("100644", "100755"):
            raise DataError(f"{name} at the commit {commit} is a blob of mode {mode}, no regular file")
        shown = _git(repository, "show", f"{commit}:{name}")
        if shown.returncode:
            raise DataError(f"git show {commit}:{name} failed in {repository}: "
                            + shown.stderr.decode(errors="replace").strip()[:200])
        data = shown.stdout
        object_hash = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
        if object_hash(b"blob %d\x00" % len(data) + data).hexdigest() != oid:
            raise DataError(f"the bytes git show gives of {commit}:{name} are not its blob {oid} of git ls-tree")
        files[name] = hashlib.sha256(data).hexdigest()
    if not files:
        raise DataError(f"lab/ holds no file at the commit {commit}")
    return files


def guest_manifest(identity):
    """{files: {guest path: sha256}, packages: [dpkg line], timers: [timer] or None} of a guest identity's
    stack_manifest (collection.guest_identity: sha256sum lines, dpkg-query lines, the line 'timers: ...'), or None
    when it has no list of lines."""
    manifest = identity.get("stack_manifest") if isinstance(identity, dict) else None
    if not isinstance(manifest, list) or not all(isinstance(line, str) for line in manifest):
        return None
    files, packages, timers = {}, [], None
    for line in manifest:
        found = GUEST_FILE_LINE.fullmatch(line)
        if found:
            files[found[2]] = found[1]
        elif line.startswith("timers:"):
            timers = sorted(line[len("timers:"):].split())
        else:
            packages.append(line)
    return {"files": files, "packages": sorted(packages), "timers": timers}


def guest_row(s, commits, repository):
    """The row of one session by GUEST_RULE; `commits` caches guest_commit_files by commit."""
    from scripts import collection  # The deployed set of a list of lab/ files (deployed_paths).
    manifest = guest_manifest(s.meta.get("guest_before"))
    if manifest is None:
        raise DataError(f"{s.dir}: session.json guest_before has no stack_manifest of lines")
    session_lab = s.meta.get("lab_sha256")
    if not isinstance(session_lab, dict):
        raise DataError(f"{s.dir}: session.json has no lab_sha256")
    commit = s.meta.get("commit")
    if commit not in commits:
        commits[commit] = guest_commit_files(repository, commit)
    lab = commits[commit]
    deployed = collection.deployed_paths(lab)
    files = []
    for path in sorted(set(deployed) | set(manifest["files"])):
        source = deployed.get(path)
        mine, theirs = manifest["files"].get(path), lab.get(source) if source is not None else None
        files.append({"path": path, "source": source, "guest_sha256": mine, "commit_sha256": theirs,
                      "equal": mine is not None and mine == theirs})
    lab_differ = sorted(name for name in set(lab) | set(session_lab) if session_lab.get(name) != lab.get(name))
    identity = s.meta["guest_before"]
    return {"session": s.id, "vm": s.vm, "kind": s.kind, "commit": commit, "commit_dirty": s.meta.get("commit_dirty"),
            "kernel": identity.get("kernel"), "boot_id": identity.get("boot_id"),
            "stack_sha256": identity.get("stack_sha256"), "files": files,
            "differ": [row["path"] for row in files if not row["equal"]],
            "matches_commit": all(row["equal"] for row in files),
            "lab_sha256_matches_commit": not lab_differ, "lab_sha256_differ": lab_differ,
            "packages": manifest["packages"], "timers": manifest["timers"]}


def guest_findings(rows, vms):
    """(by_vm, agree, findings) of the rows by GUEST_RULE."""
    findings = [f"VM {vm}: no session of it" for vm in vms if not any(row["vm"] == vm for row in rows)]
    findings += [f"{row['session']} (VM {row['vm']}): the deployed guest differs from lab/ of the commit "
                 f"{row['commit']}: " + ", ".join(row["differ"]) for row in rows if not row["matches_commit"]]
    findings += [f"{row['session']} (VM {row['vm']}): session.json lab_sha256 differs from lab/ of its commit "
                 f"{row['commit']} (commit_dirty {row['commit_dirty']}): " + ", ".join(row["lab_sha256_differ"])
                 for row in rows if not row["lab_sha256_matches_commit"]]
    by_vm = {}
    for vm in vms:
        mine = [row for row in rows if row["vm"] == vm]
        packages = [list(x) for x in sorted({tuple(row["packages"]) for row in mine})]
        timers = [None if x is None else list(x) for x in sorted(
            {None if row["timers"] is None else tuple(row["timers"]) for row in mine},
            key=lambda x: (x is not None, x or ()))]
        by_vm[vm] = {"sessions": [row["session"] for row in mine], "packages": packages, "timers": timers}
        findings += [f"VM {vm}: {len(values)} different {what} over its sessions: " + _shown(values, 400)
                     for what, values in (("dpkg lists", packages), ("timers", timers)) if len(values) > 1]
    present = {vm: v for vm, v in by_vm.items() if v["sessions"]}
    agree = {}
    for what, words in (("packages", "dpkg lists"), ("timers", "timers")):
        seen = {json.dumps(v[what], sort_keys=True) for v in present.values()}
        agree[what] = len(seen) <= 1 and all(len(v[what]) == 1 for v in present.values())
        if len(seen) > 1:
            findings.append(f"the VMs differ in their {words}: "
                            + "; ".join(f"VM {vm} {_shown(v[what], 300)}" for vm, v in present.items()))
    return by_vm, agree, findings


def guest_table(args, command):
    """The mode guest (GUEST_RULE): writes the new record, prints one line per session and the criterion, and returns
    the exit code."""
    started = _g2_start(args, "guest")
    if started is None:
        return 2
    out, paths = started
    g2_dir, repository = _g2_dir(args), GUEST_REPOSITORY
    sessions, entries, rows, refused, commits, vms = [], [], [], [], {}, None
    for path in paths:
        try:
            s = G2TableSession(path, g2_dir)
            if s.vms is None:
                raise DataError(f"{s.dir}: protocol.json names no VMs")
            if vms is not None and s.vms != vms:
                raise DataError(f"{s.dir}: its protocol names the VMs {s.vms}, not {vms}")
            if s.vm not in s.vms:
                raise DataError(f"{s.dir}: a session of VM {s.vm}, which its protocol does not name")
            vms = s.vms
            status, why = s.selection("guest_matches_repository", load=False)
            row = guest_row(s, commits, repository) if status == "counted" else None
        except DataError as error:
            refused.append(str(error))
            continue
        sessions.append(s)
        entries.append(s.entry(status, why))
        if row is not None:
            rows.append(row)
    if _g2_refusals("guest", out, sessions, refused):
        return 2
    by_vm, agree, findings = guest_findings(rows, vms)
    criterion = {"met": not findings, "vms": vms, "sessions_counted": len(rows),
                 "left_out": sum(e["status"] == "left_out" for e in entries), "vms_agree": agree}
    record = _g2_record(GUEST_TABLE_SCHEMA, GUEST_GUEST, command, len(rows), {
        "criterion": "guest_matches_repository",
        "repository": {"path": str(repository), "how": "git rev-parse --verify <commit>^{commit}, git ls-tree -z "
                                                       "<commit> lab/ and git show <commit>:lab/<file>, its bytes "
                                                       "checked against the blob's object id (GUEST_RULE)"},
        "commits": {commit: {"lab": files} for commit, files in commits.items()}, "sessions": entries,
        "table": rows, "by_vm": by_vm, "result": criterion, "findings": findings, "selection": G2_SELECTION,
        "rule": GUEST_RULE},
        "The deployed files of lab/ on the VMs against the commit of each G2 session (criterion "
        "guest_matches_repository of G2); nothing is scored or detected.")
    code = _g2_write(out, record)
    if code:
        return code
    for row in rows:
        print(f"{row['session']} vm {row['vm']} commit {row['commit']}: "
              + ("matches" if row["matches_commit"] else "differs: " + ", ".join(row["differ"]))
              + ("" if row["lab_sha256_matches_commit"] else "; lab_sha256 differs from the commit"))
    print("guest_matches_repository: " + ("met" if criterion["met"] else "not met") + f"; {len(rows)} session(s), "
          f"{criterion['left_out']} left out, {len(findings)} finding(s)", flush=True)
    print(f"campaign_report: guest: {len(sessions)} session(s); record {out}", file=sys.stderr)
    return 0 if criterion["met"] else 1


# ------------------------------------------------ the mode events (criterion event_effects)

EVENTS_GUEST = ("none: the mode events reads saved session files, audit records and the records of the G2 driver; no "
                "VM is contacted and no RAM image is opened")
EVENTS_H4 = ("the kinds fault and fault_clean of skuska/poruchy.py and cas of skuska/cas.py")
NO_EFFECT_RULE = (
    "the lead's answer to Q50 (map question 5), written before the data: an occurrence of naprazdno has no effect "
    "when (1) its start and its stop reply (events.json start and stop, lab/udalosti.py) both carry health 200 and the "
    "units of lab/udalosti.py unit_states (the five applications, nginx and postgresql@15-main) with ActiveState "
    "active, and each unit's NRestarts and ExecMainPID are the same in the two replies; and in the window of the "
    "occurrence (scripts/collection_logs.py event_window: host start - 1 s to host stop done + the session's "
    "event_grace_s) (2) no request of traffic_requests.jsonl whose start or end lies in it is outside its intended "
    "state, as the log audit judges a request outside every window (a deliberate client error with another status "
    "than its intended_status, any other request not ok or without a 2xx status), (3) the guest's journal "
    "(guest/journal_segment.json, its file bound by gz_sha256) holds no restart or failure in systemd: no line of "
    "systemd[1] with a job Stopping, Stopped, Starting or Started of a unit of collection_logs.REQUIRED_UNITS "
    "(collection_logs.UNIT_LINE), and none whose message says fail (any case), 'Scheduled restart job' or 'Start "
    "request repeated too quickly' of any unit, (4) no traceback or worker error (the log audit's 'Traceback (most "
    "recent call last)' and collection_logs.WORKER_ERROR) and (5) no line of the session's nginx error log "
    "(guest/session_segment.json, its file of -nginx-error.log bound by gz_sha256) at a time in the window (its "
    "second or the next, as the log audit reads it); every violation is named and is a finding; evidence that cannot "
    "be read or placed in time (a file missing or not the one its segment binds, a line without a time) is a "
    "violation by name, never a pass")
PHASE_RULE = (
    "the real phase of a boundary against the collector's grid is (t - grid_phase_s) mod interval_s, t the host time "
    "at which the call of the start (host_start_unix) or of the stop (host_stop_unix) began and grid_phase_s the "
    "audit's values.timing.grid_phase_s (the deadline of frame 0 modulo interval_s, scripts/collection.py "
    "audit_session), with its tenth of the interval (protocol_v5.tenth) beside the planned phase and tenths; null with "
    "why when the audit has no grid phase or the occurrence no such time; the table counts the real starts and stops "
    "of the counted occurrences per tenth (proposal 10.3: phases spread over the cycle of the collection, which Q51 "
    "covers by these columns and which has no criterion of its own)")
EVENTS_RULE = (
    "The criterion event_effects of G2 (the lead's G2 skeleton, map row 2, the lead's answers Q43, Q50, Q51 and Q53): "
    "every type of events.types of --protocol, naprazdno included, at least 19 occurrences on both VMs together and "
    "at least 8 on each (Q43; skuska/g2.py OCCURRENCES and MIN_PER_VM), and the effect predicate holds at every "
    "occurrence but naprazdno's, where no effect may be (NO_EFFECT_RULE). Of each G2 session directory given the mode "
    "reads session.json (its planned events, event_grace_s), protocol.json (bound by session.json protocol_sha256; it "
    "must agree with --protocol outside the paths determined_at gives G1 and later stages, gates.stage_sha256 of "
    "stage G0, the hash the record of G0 binds, so the copies before and after a value of G1 or G2 is written are one "
    "protocol, the one G0 recorded), events.json (schema "
    "hyptcn3/session-events/1), the driver's record <g2-dir>/zaznamy/<session>.json (G2TableSession), the audit "
    "record it names and, for an occurrence of naprazdno, the evidence of NO_EFFECT_RULE; raw/ never. Which sessions "
    "count (Q51, G2_SELECTION): every audited session of H3, accepted or refused; left out by name and listed: a "
    "session whose record names event_effects in values.excluded.criteria (the ground truth, Q62, and the worst case "
    "of time), a session of H4 (" + EVENTS_H4 + ") and a session whose record names no audit; a session whose record "
    "says counted false counts towards no minimum, but its occurrences are judged and an invalid one is a finding. "
    "An occurrence is a planned event of session.json with its record of events.json at the same place (the log "
    "audit's rule, events_differ_from_plan); its row holds the session, the VM, the type, the planned times and "
    "phases, the host times of its start and stop calls, the real phases (PHASE_RULE), executed, the guest's effect "
    "predicate and for naprazdno NO_EFFECT_RULE. It is valid when its record is the plan's, it was executed "
    "(scripts/collection.py Events: both calls ok and health 200 after the stop) and the guest's effect is ok, for "
    "naprazdno when it was executed and NO_EFFECT_RULE holds. The counts per type on both VMs together and on each "
    "take every occurrence of a counted session, valid or not (Q51: an invalid predicate is never left out, it is a "
    "finding beside the count). The criterion is met when every type has its minimums and no occurrence of a counted "
    "session or of one counted false is invalid. Refused by name, each a data error: a directory without "
    "session.json or protocol.json, a session of another role than diagnostic, a protocol.json other than the one "
    "session.json binds or not --protocol outside the paths of G1 and later stages, a VM --protocol does not name, a "
    "driver's record missing or of another session, an audit record other than the one it names or not of the "
    "session, an events.json of another schema or without a list, planned events that are no list of objects with a "
    "type, a segment record that is no JSON object, a directory named twice, and an --out that exists (refused "
    "before anything is read) or lies inside a session directory. Exit 0: the table is written to --out, a new JSON "
    "record with the provenance header of check E and the stage G2, and the criterion is met; 1: the table is written "
    "and the criterion is not met (a minimum missing or an invalid occurrence, each named); 2: a usage or data error, "
    "every refusal named on stderr and nothing written.")


def _g2_unexpected(row):
    """A request outside its intended state, as the log audit judges one outside every window (collection_logs)."""
    if row.get("intended_status") is not None:
        return row.get("status") != row["intended_status"]
    return not (row.get("outcome") == "ok" and type(row.get("status")) is int and 200 <= row["status"] < 300)


def _g2_systemd_trouble(line):
    """The restart or failure in systemd a journal line shows (NO_EFFECT_RULE (3)), or None."""
    from scripts import collection_logs
    message = G2_SYSTEMD_LINE.match(line)
    if message is None:
        return None
    job = collection_logs.UNIT_LINE.match(line)
    if job and job[2] in ("Stopping", "Stopped", "Starting", "Started") and job[3] in collection_logs.REQUIRED_UNITS:
        return f"{job[2]} {job[3]}"
    trouble = G2_SYSTEMD_TROUBLE.search(message[1])
    return None if trouble is None else f"says {trouble[0]}"


def events_evidence(s, windows):
    """{index: [violation]} of the windows of the occurrences of naprazdno (NO_EFFECT_RULE (2) to (5)), each file read
    once and listed in the session's files."""
    import gzip  # The guest's segment files are gzip copies (lab/guest_state.py describe).
    from scripts import collection_logs
    found = {i: [] for i in windows}

    def inside(*times):
        return [i for i, (lo, hi) in windows.items() if any(lo <= t <= hi for t in times)]

    def every(text):
        for i in found:
            found[i].append(text)

    requests = s.dir / "traffic_requests.jsonl"
    try:
        sha = hashlib.sha256()
        with open(requests, "rb") as stream:
            for raw in stream:
                sha.update(raw)
                try:
                    row = json.loads(raw)
                except ValueError:
                    every("traffic_requests.jsonl: a line is no JSON (a request that cannot be placed)")
                    continue
                if not isinstance(row, dict) or row.get("type") != "request":
                    continue
                times = (unix_of(row.get("t_start_utc")), unix_of(row.get("t_end_utc")))
                if None in times:
                    every(f"request {_shown(row.get('rid'), 60)} has no readable time (cannot be placed)")
                    continue
                if _g2_unexpected(row):
                    for i in inside(*times):
                        found[i].append(f"request {row.get('rid')} {row.get('method')} {row.get('route')} at "
                                        f"{row.get('t_start_utc')}: outcome {row.get('outcome')}, status "
                                        f"{row.get('status')}" + (f", intended {row['intended_status']}"
                                                                  if row.get("intended_status") is not None else ""))
        s.listed("traffic_requests.jsonl", requests, sha.hexdigest())
    except OSError as error:
        every(f"traffic_requests.jsonl cannot be read ({type(error).__name__}: {error})")
    path, got = _g2_journal(s)
    if path is None:
        every(f"the journal: {got}")
    else:
        for t, line in got:
            trouble = _g2_systemd_trouble(line)
            traceback = "Traceback (most recent call last)" in line or collection_logs.WORKER_ERROR in line
            for i in inside(t) if trouble or traceback else ():
                found[i].append(("systemd " + trouble if trouble else "traceback or worker error") + ": "
                                + one_line(line)[:200])
    path, why = _g2_segment_file(s, "session_segment.json", G2_LOG_SEGMENT, "nginx-error.log")
    if path is None:
        every(f"the nginx error log: {why}")
        return found
    try:
        with gzip.open(path, "rt", errors="replace") as stream:
            lines = [line.rstrip("\n") for line in stream if line.strip()]
    except (OSError, EOFError) as error:
        every(f"the nginx error log cannot be read ({type(error).__name__}: {error})")
        return found
    for line in lines:
        stamp = collection_logs.NGINX_TIME.match(line)
        if stamp is None:
            every("an nginx error line without a time (cannot be placed): " + one_line(line)[:200])
            continue
        t = datetime.strptime(stamp[1], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        for i in inside(t, t + 1):
            found[i].append("nginx error: " + one_line(line)[:200])
    return found


def events_no_effect(record, window, evidence):
    """NO_EFFECT_RULE of one occurrence of naprazdno: {ok, violations}."""
    violations, units = [], {}
    for name in ("start", "stop"):
        reply = record.get(name) if isinstance(record, dict) else None
        if not isinstance(reply, dict):
            violations.append(f"no {name} reply in events.json")
            continue
        units[name] = reply.get("units") if isinstance(reply.get("units"), dict) else {}
        if reply.get("health") != 200:
            violations.append(f"{name}: health {_shown(reply.get('health'), 40)}, not 200")
        for unit in NO_EFFECT_UNITS:
            state = units[name].get(unit)
            if not isinstance(state, dict):
                violations.append(f"{name}: no state of {unit}")
            elif state.get("ActiveState") != "active":
                violations.append(f"{name}: {unit} ActiveState {_shown(state.get('ActiveState'), 40)}, not active")
    if len(units) == 2:
        for unit in NO_EFFECT_UNITS:
            a, b = units["start"].get(unit), units["stop"].get(unit)
            if isinstance(a, dict) and isinstance(b, dict):
                violations += [f"{unit}: {key} {_shown(a.get(key), 30)} at the start, {_shown(b.get(key), 30)} at the "
                               "stop" for key in ("NRestarts", "ExecMainPID") if a.get(key) != b.get(key)]
    if window is None:
        violations.append("no window (no host start or no host stop done)")
    else:
        violations += evidence or []
    return {"ok": not violations, "violations": violations}


def _g2_phase(t, grid, interval):
    """(phase, tenth) of the host time t against the grid (PHASE_RULE), or (None, None)."""
    if not _number(t) or not _number(grid):
        return None, None
    phase = round((t - grid) % interval, 6)
    interval_ms = int(round(interval * 1000))
    return phase, protocol_v5.tenth(min(int(phase * 1000), interval_ms - 1), interval_ms)


def events_rows(s, status, accepted, grid, interval):
    """The rows of the occurrences of one session (EVENTS_RULE)."""
    from scripts import collection_logs
    planned, records = s.planned()
    grace = s.meta.get("event_grace_s")
    rows, windows = [], {}
    for index, item in enumerate(planned):
        record = records[index] if records is not None and index < len(records) else None
        record = record if isinstance(record, dict) else None
        why, window = [], None
        if record is None:
            why.append("no record of it in events.json" if records is not None else "events.json is missing")
        else:
            if len(records) != len(planned) or not all(key in record and _equal(record[key], item[key])
                                                       for key in item):
                why.append("its record in events.json differs from the plan (the log audit's events_differ_from_plan)")
            if "host_start_unix" not in record:
                why.append("not started: no host start (the session ended before its time; Q51: a finding, never left "
                           "out)")
            elif record.get("executed") is not True:
                why.append("not executed (scripts/collection.py Events: a call failed or health was not 200 after "
                           "the stop)")
            try:
                window = collection_logs.event_window(record, grace)
            except ValueError as error:
                why.append(f"no window: {error}")
        effect = record.get("effect") if record else None
        effect = {"ok": effect.get("ok"), "predicate": effect.get("predicate")} if isinstance(effect, dict) else None
        if item["type"] != EMPTY_EVENT and record is not None and (effect or {}).get("ok") is not True:
            why.append("the guest's effect predicate did not hold"
                       + (f" ({effect['predicate']})" if effect and effect.get("predicate") else " (no effect)"))
        times = {key: (record or {}).get(key) for key in ("host_start_unix", "host_started_unix", "host_stop_unix",
                                                          "host_stopped_unix")}
        start, start_tenth = _g2_phase(times["host_start_unix"], grid, interval)
        stop, stop_tenth = _g2_phase(times["host_stop_unix"], grid, interval)
        tenths = (list(protocol_v5.item_tenths({"interval_s": interval}, item))
                  if _number(item.get("start_s")) and _number(item.get("duration_s")) else None)
        rows.append({"session": s.id, "vm": s.vm, "scenario": s.meta.get("scenario"), "kind": s.kind,
                     "status": status, "counted": status == "counted", "audit_accepted": accepted, "index": index,
                     "type": item["type"], "class": item.get("class"),
                     "planned": {**{key: item.get(key) for key in ("start_s", "duration_s", "start_phase_s",
                                                                   "stop_phase_s")}, "tenths": tenths},
                     "times": {**times, **{key.replace("_unix", "_utc"): utc(value) if _number(value) else None
                                           for key, value in times.items()}},
                     "window": _g2_window(window),
                     "phase": {"grid_phase_s": grid, "start_s": start, "start_tenth": start_tenth, "stop_s": stop,
                               "stop_tenth": stop_tenth,
                               "why": None if grid is not None else "the audit has no values.timing.grid_phase_s"},
                     "executed": None if record is None else record.get("executed"), "effect": effect,
                     "no_effect": None, "why": why})
        if item["type"] == EMPTY_EVENT and window is not None:
            windows[index] = window
    evidence = events_evidence(s, windows) if windows else {}
    for row in rows:
        if row["type"] == EMPTY_EVENT:
            record = records[row["index"]] if records is not None and row["index"] < len(records) else None
            row["no_effect"] = events_no_effect(record if isinstance(record, dict) else None,
                                                windows.get(row["index"]), evidence.get(row["index"]))
            row["why"] += [f"an effect of naprazdno (NO_EFFECT_RULE): {text}"
                           for text in row["no_effect"]["violations"]]
        row["valid"] = not row["why"]
    return rows


def events_counts(rows, protocol, needed, per_vm):
    """({type: counts}, missing) of the counted occurrences by EVENTS_RULE (Q43)."""
    counts, missing = {}, []
    for name in protocol["types"]:
        mine = [row for row in rows if row["type"] == name and row["counted"]]
        counts[name] = {"occurrences": len(mine), "valid": sum(row["valid"] for row in mine), "needed": needed,
                        "needed_per_vm": per_vm,
                        "by_vm": {vm: {"occurrences": sum(row["vm"] == vm for row in mine),
                                       "valid": sum(row["vm"] == vm and row["valid"] for row in mine)}
                                  for vm in protocol["vms"]}}
        if len(mine) < needed:
            missing.append(f"{name}: {len(mine)} occurrence(s) on both VMs together, fewer than {needed} "
                           f"({needed - len(mine)} missing)")
        missing += [f"{name} on VM {vm}: {n['occurrences']} occurrence(s), fewer than {per_vm}"
                    for vm, n in counts[name]["by_vm"].items() if n["occurrences"] < per_vm]
    return counts, missing


def events_table(args, command):
    """The mode events (EVENTS_RULE): writes the new record, prints one line per type and the criterion, and returns
    the exit code."""
    started = _g2_start(args, "events")
    if started is None:
        return 2
    out, paths = started
    try:
        protocol = _g2_protocol(args.protocol)
    except DataError as error:
        print(f"campaign_report: {error}", file=sys.stderr)
        return 2
    from skuska import cas, g2, poruchy  # The kinds of H4 and the minimums of Q43 (the deck's).
    h4 = (poruchy.KIND_FAULT, poruchy.KIND_CLEAN, cas.KIND)
    g2_dir, interval = _g2_dir(args), protocol["interval_s"]
    sessions, entries, rows, refused = [], [], [], []
    for path in paths:
        try:
            s = G2TableSession(path, g2_dir)
            s.bind(protocol)
            out_of = "event_effects" in s.excluded or s.kind in h4
            audit = None if out_of else s.audit()
            status, why = s.selection("event_effects", h4, audited=out_of or audit is not None)
            mine = []
            if status != "left_out":
                timing = audit.get("timing") if isinstance(audit.get("timing"), dict) else {}
                grid = timing.get("grid_phase_s") if _number(timing.get("grid_phase_s")) else None
                mine = events_rows(s, status, audit.get("accepted"), grid, interval)
        except DataError as error:
            refused.append(str(error))
            continue
        entry = s.entry(status, why)
        planned = s.meta.get("events")
        entry.update(audit=None if audit is None else {"report": s.values["audit"]["report"],
                                                       "sha256": s.values["audit"].get("sha256"),
                                                       "accepted": audit.get("accepted"),
                                                       "reasons": audit.get("reasons")},
                     occurrences=len(planned) if isinstance(planned, list) else None)
        sessions.append(s)
        entries.append(entry)
        rows += mine
    if _g2_refusals("events", out, sessions, refused):
        return 2
    counts, missing = events_counts(rows, protocol, g2.OCCURRENCES, g2.MIN_PER_VM)
    stray = sorted({row["type"] for row in rows} - set(protocol["types"]))
    findings = [f"{row['session']} #{row['index']} {row['type']} (VM {row['vm']}"
                + (", its session counted false" if row["status"] == "load" else "") + "): " + "; ".join(row["why"])
                for row in rows if not row["valid"]]
    findings += [f"type {name} is not one of the events.types of --protocol" for name in stray]
    tenths = {"starts": [0] * protocol_v5.TENTHS, "stops": [0] * protocol_v5.TENTHS}
    for row in rows:
        for key, field in (("starts", "start_tenth"), ("stops", "stop_tenth")):
            if row["counted"] and row["phase"][field] is not None:
                tenths[key][row["phase"][field]] += 1
    criterion = {"met": not missing and not findings, "minimums_met": not missing,
                 "invalid": sum(not row["valid"] for row in rows)}
    record = _g2_record(EVENTS_TABLE_SCHEMA, EVENTS_GUEST, command, len(rows), {
        "criterion": "event_effects", "protocol": {k: v for k, v in protocol.items() if k != "types"},
        "types": protocol["types"], "needed": g2.OCCURRENCES, "needed_per_vm": g2.MIN_PER_VM, "sessions": entries,
        "occurrences": rows, "counts": counts, "minimums_met": not missing, "missing": missing, "findings": findings,
        "phases_per_tenth": tenths, "result": criterion, "selection": G2_SELECTION,
        "rules": {"events": EVENTS_RULE, "no_effect": NO_EFFECT_RULE, "phase": PHASE_RULE}},
        "The table of the occurrences of the events of G2 and their predicates (criterion event_effects of G2); "
        "nothing is scored or detected.")
    code = _g2_write(out, record)
    if code:
        return code
    for name in protocol["types"]:
        c = counts[name]
        print(f"{name}: {c['occurrences']}/{g2.OCCURRENCES} ("
              + ", ".join(f"{vm} {c['by_vm'][vm]['occurrences']}/{g2.MIN_PER_VM}" for vm in protocol["vms"])
              + f"), {c['occurrences'] - c['valid']} invalid")
    print("event_effects: " + ("met" if criterion["met"] else "not met") + f"; {len(missing)} minimum(s) missing, "
          f"{len(findings)} finding(s)", flush=True)
    print(f"campaign_report: events: {len(sessions)} session(s), {len(rows)} occurrence(s); record {out}",
          file=sys.stderr)
    return 0 if criterion["met"] else 1


# ------------------------------------------------ the mode restarts (criterion restart_loops_bounded)

RESTARTS_GUEST = ("none: the mode restarts reads saved guest journals, session files, the records of the G2 driver and "
                  "of the fault injector, and lab/periods.json; no VM is contacted and no RAM image is opened")
ASSIGN_RULE = (
    "a loop is the times of the systemd lines 'Scheduled restart job' of one hyptcn-lab@ unit (lab_trial.RESTART_LINE) "
    "split where two lie more than RESTART_WINDOW_S = 60 s apart (lab_trial._restarts; lab/hyptcn-lab@.service "
    "StartLimitIntervalSec); it belongs to the occurrence of zla_konfiguracia_sluzby of its session whose window "
    "(collection_logs.event_window: host start - 1 s to host stop done + event_grace_s) holds its first restart, when "
    "the type restarts its unit (collection_logs.EVENT_UNITS: hyptcn-lab@catalog), or to the kill of the service in "
    "its session (skuska/poruchy.py zabita_sluzba, the injector's record with the fault induced; its unit "
    "hyptcn-lab@docs) when its unit is the killed one and its first restart lies from 1 s before the injector's "
    "labctl exec of the kill to RESTART_WINDOW_S after it returned; every other loop is a loop elsewhere")
FITS_RULE = (
    "Q52, written before the data: a loop fits lab/periods.json ('hyptcn-lab@ restart loop', period_s 3.25: "
    "RestartSec=3 and the start of python3; the lab's records 3.2488 to 3.2517 s) when every spacing of its "
    "consecutive restarts lies in [3.0, 3.5] s and, at the kill and at a loop elsewhere, every delay from the last "
    "line 'Failed with result' of the unit before a restart (since the previous restart, for the first one since the "
    "kill began or 60 s before it) to that restart lies in [3.0, 3.5] s too; a loop with nothing to measure (a single "
    "restart at an occurrence of zla_konfiguracia_sluzby, no line 'Failed with result' before a restart of the kill) "
    "does not fit")
BOUNDED_RULE = (
    "Q52, written before the data: a loop is bounded when at most StartLimitBurst = 5 of its restarts lie within any "
    "StartLimitIntervalSec = 60 s (lab/hyptcn-lab@.service) and it ends: at an occurrence of zla_konfiguracia_sluzby, "
    "whose drop-in keeps the service failing until the stop, the line 'Start request repeated too quickly.' of the "
    "unit follows the loop's last restart before the stop call began (host_stop_unix + 1 s for the guest's clock) and "
    "no restart of the unit follows that line in the occurrence's window (none in the loop and no second loop of it); "
    "at the kill no restart of the unit follows the loop in the session's journal (the unit runs again); a loop "
    "elsewhere by the burst alone")
ELSEWHERE_RULE = (
    "a loop elsewhere is listed with FITS_RULE and BOUNDED_RULE and, when it lies in the window of an occurrence of a "
    "type that restarts its unit by design (collection_logs.EVENT_UNITS, where the log audit admits a restart too), "
    "with that occurrence; it is a finding when it does not fit or is not bounded (a period the register does not "
    "name) or lies outside every such window (a restart loop no event and no fault explains: the crash loop that "
    "ended campaign v4)")
PERIODS_RULE = (
    "Q52, written before the data: a period the register does not name is a group of lines of one session's guest "
    "journal (lab_trial.journal_lines: the lines with a time) with at least 5 spacings between consecutive lines and "
    "a coefficient of variation of the spacings (their population standard deviation over their mean) below 0.1 that "
    "no entry of lab/periods.json covers; a group holds the lines of one source and one form: the syslog identifier "
    "without its [pid] and, for a message that is a JSON object, its service and its sorted keys, for any other "
    "message its text with every run of digits replaced by N; the request lines of the services "
    "(collection_logs.SERVICE_LINE: the generator's requests, traffic and no process of the guest) form no group; "
    "covered: a line of systemd that names a hyptcn-lab@ unit by 'hyptcn-lab@ restart loop' (its loops are judged by "
    "FITS_RULE and BOUNDED_RULE), the udrzba run's line (lab_trial.UDRZBA_LINE) and a line of systemd that names "
    "hyptcn-lab-udrzba by 'hyptcn-lab-udrzba.timer', a JSON line of the service worker (lab_trial.WORKER_LINE among "
    "them) and the worker's error line (collection_logs.WORKER_ERROR: a round that ends in the statement timeout "
    "during zamok_tabulky, about 4 s apart) by 'worker loop', the line of a worker start of autovacuum "
    "(lab_trial.AUTOVACUUM_LINE) by 'PostgreSQL autovacuum launcher' and a line of postgres about a checkpoint by "
    "'PostgreSQL checkpointer' (both in the journal only at debug1 logging); a loop that does not fit FITS_RULE is a "
    "period the register does not name as well. The coverage was checked on the journals of the lab test before G2 "
    "(dokazy/skuska_labu/behy 08, 15, 16, 17 and dokazy/B11/okno_VM 03), the data of no criterion of G2: every "
    "periodic group there is covered but postgres's STATEMENT lines of the worker's statements that hit the statement "
    "timeout during zamok_tabulky in the two runs with debug1 logging, which no G2 session sets (the executor's "
    "judgment: they stay a finding should they appear). Limits "
    "(no finding): a process that leaves no line in the journal is not seen (Q52); a period that holds for a part of "
    "the session only hides among the lines of its form elsewhere; the lines of one process in different forms fall "
    "into different groups")
AUTOVACUUM_RULE_G2 = (
    "Q52: PostgreSQL logs a worker start of the autovacuum launcher into the journal only at log_min_messages debug1 "
    "(lab_trial JOURNAL), which no G2 session sets, so the table takes over the window's measurement of "
    "lab/periods.json (its entry's measured.after, with the property of Q9 the lead accepted); when the journals of a "
    "VM do hold such lines, lab_trial.autovacuum_property judges them and a property that fails is a finding")
RESTARTS_RULE = (
    "The criterion restart_loops_bounded of G2 (the lead's G2 skeleton, map row 3, the lead's answers Q43, Q52 and "
    "Q53): the period of the restarts in the guest's journal at every occurrence of zla_konfiguracia_sluzby and at "
    "the killed service (H4) fits lab/periods.json and is bounded (StartLimitBurst), and no other process has a period "
    "the register does not name. Of each G2 session directory given the mode reads session.json (its planned events, "
    "event_grace_s, lab_sha256), protocol.json (bound as by the mode events, against --protocol), events.json, the "
    "driver's record <g2-dir>/zaznamy/<session>.json (G2TableSession), for a fault session the injector's record "
    "<g2-dir>/poruchy/<session>.json (schema hyptcn3/g2-fault/1, bound by its session_id, session_dir and vm) and the "
    "guest's journal (guest/journal_segment.json, its file bound by gz_sha256, read by lab_trial.journal_lines); and "
    "lab/periods.json of this tree, whose sha256 must be that of session.json lab_sha256 (the register deployed in "
    "the session's guest). It calls the functions of scripts/lab_trial.py (Q53): journal_lines, RESTART_LINE and "
    "_restarts for the loops, periods_of for the measured spacings of every entry of the register per VM, spacing, and "
    "autovacuum_property; the measured spacings go into this record and never into lab/periods.json, which is "
    "measurement code (Q27). Which sessions count (G2_SELECTION): every session given, of H3 and of H4 (the killed "
    "service is an H4 fault), accepted or refused, audited or not (the journal is the evidence); a session whose "
    "record names restart_loops_bounded in values.excluded.criteria is left out by name (no record names it today, so "
    "the ground truth and the worst case of time count here) and one counted false counts towards no minimum but is "
    "judged. The occurrences: every planned event of zla_konfiguracia_sluzby (its record of events.json at the same "
    "place) and the kill of the service of every fault session of zabita_sluzba whose injector induced it; their "
    "loops by ASSIGN_RULE, each judged by FITS_RULE and BOUNDED_RULE; an occurrence without a loop, without a window "
    "or without a journal is not judged, a finding; the loops elsewhere by ELSEWHERE_RULE; the periods by "
    "PERIODS_RULE and AUTOVACUUM_RULE_G2. The minimums: the occurrences of zla_konfiguracia_sluzby of counted sessions "
    "as Q43 asks of every type, 19 on both VMs together and 8 on each (the executor's judgment: the criterion names "
    "every occurrence, and these are the occurrences the deck deals), and the kill of the service once on each VM (the "
    "fault plan). The criterion is met when the minimums are met and there is no finding. Refused by name, each a data "
    "error: what the mode events refuses, a session.json without lab_sha256 or whose lab/periods.json is not this "
    "tree's, an injector's record of another session or schema, guest journal files other than the one the segment "
    "binds, and a journal that cannot be read. Exit 0: the table is written to --out, a new JSON record with the "
    "provenance header of check E and the stage G2, and the criterion is met; 1: the table is written and the "
    "criterion is not met, every finding and missing minimum named; 2: a usage or data error, every refusal named on "
    "stderr and nothing written.")


def restarts_units(lines):
    """{unit: {restart: [(t, line)], failed: [t], limit: [t]}} of the hyptcn-lab@ units in the journal lines
    (G2_UNIT_LINE; the restarts as lab_trial.RESTART_LINE finds them)."""
    from scripts import lab_trial
    keys = {"Scheduled restart job": "restart", "Failed with result": "failed",
            "Start request repeated too quickly": "limit"}
    out = defaultdict(lambda: {"restart": [], "failed": [], "limit": []})
    for t, line in lines:
        found = G2_UNIT_LINE.search(line)
        if found is None:
            continue
        key = keys[found[2]]
        if key != "restart":
            out[found[1]][key].append(t)
        elif lab_trial.RESTART_LINE.search(line):
            out[found[1]]["restart"].append((t, line))
    return out


def restarts_judge(times, unit_lines, kind, floor, stop=None, later=()):
    """FITS_RULE and BOUNDED_RULE of one loop (`times`, its restarts): {restarts, spacings, delays, start_limit,
    burst, fits, bounded, why_not_fits, why_not_bounded}. `kind` is event, kill or elsewhere; `floor` the time since
    which a line 'Failed with result' counts for the first delay; `stop` the host time the stop call of the event
    began; `later` the restarts of the unit after the loop that BOUNDED_RULE reads (of a second loop in the event's
    window, or the journal's after the kill)."""
    low, high = FITS_S
    spacings = [round(b - a, 6) for a, b in zip(times, times[1:])]
    delays = []
    for i, restart in enumerate(times):
        since = times[i - 1] if i else floor
        failed = [t for t in unit_lines["failed"] if since <= t <= restart]
        delays.append(round(restart - failed[-1], 6) if failed else None)
    why = []
    measured = spacings + ([d for d in delays if d is not None] if kind != "event" else [])
    if kind != "event" and None in delays:
        why.append("no line 'Failed with result' of the unit before a restart, so its delay cannot be measured")
    if not measured:
        why.append("nothing to measure (a single restart)")
    why += [f"{value:.6g} s outside [{low:g}, {high:g}] s" for value in measured if not low <= value <= high]
    bound = []
    burst = max(sum(1 for u in times if t <= u <= t + START_LIMIT_INTERVAL_S) for t in times)
    if burst > START_LIMIT_BURST:
        bound.append(f"{burst} restarts within {START_LIMIT_INTERVAL_S} s, more than StartLimitBurst "
                     f"{START_LIMIT_BURST}")
    limit = None
    if kind == "event":
        limits = ([t for t in unit_lines["limit"] if times[-1] <= t <= stop + GUEST_CLOCK_S]
                  if stop is not None else [])
        limit = limits[0] if limits else None
        if limit is None:
            bound.append("no line 'Start request repeated too quickly.' of the unit after its last restart before "
                         "the stop call")
        else:
            after = [t for t in times if t > limit] + [t for t in later if t > limit]
            if after:
                bound.append(f"{len(after)} restart(s) of the unit after 'Start request repeated too quickly.' in the "
                             "occurrence's window")
        if later and limit is None:
            bound.append(f"{len(later)} restart(s) of a second loop of the unit in the occurrence's window")
    elif kind == "kill" and later:
        bound.append(f"{len(later)} later restart(s) of the unit in the session's journal (it did not run again)")
    return {"restarts": [{"unix": round(t, 6), "utc": utc(t)} for t in times], "spacings": spacings,
            "delays": delays, "start_limit": None if limit is None else {"unix": round(limit, 6), "utc": utc(limit)},
            "burst": burst, "fits": not why, "bounded": not bound, "why_not_fits": why, "why_not_bounded": bound}


def restarts_form(line):
    """The group of a journal line by PERIODS_RULE: (source, json, service, keys, text), or None for a line of no
    group (a request line of the services, a line of another shape)."""
    from scripts import collection_logs
    found = G2_JOURNAL_FORM.match(line)
    if found is None or collection_logs.SERVICE_LINE.search(line):
        return None
    source, message = found[1], found[2]
    try:
        doc = json.loads(message)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        return (source, True, doc.get("service") if isinstance(doc.get("service"), str) else None,
                tuple(sorted(doc)), None)
    return (source, False, None, None, re.sub(r"\d+", "N", message))


def restarts_cover(form, line):
    """The entry of lab/periods.json that covers a group of lines (PERIODS_RULE), or None."""
    from scripts import collection_logs, lab_trial
    source, is_json, service, _, text = form
    if source == "systemd" and "hyptcn-lab@" in (text or ""):
        return "hyptcn-lab@ restart loop"
    if (source == "systemd" and "hyptcn-lab-udrzba" in (text or "")) or lab_trial.UDRZBA_LINE.search(line):
        return "hyptcn-lab-udrzba.timer"
    if (is_json and service == "worker") or collection_logs.WORKER_ERROR in line:
        return "worker loop"
    if lab_trial.AUTOVACUUM_LINE.search(line):
        return lab_trial.AUTOVACUUM
    if source == "postgres" and "checkpoint" in (text or ""):
        return "PostgreSQL checkpointer"
    return None


def restarts_periodic(lines):
    """The periodic groups of one journal (PERIODS_RULE): [{source, form, lines, spacings, cv, covered_by, first}]."""
    from scripts import lab_trial
    groups = defaultdict(list)
    for t, line in lines:
        form = restarts_form(line)
        if form is not None:
            groups[form].append((t, line))
    out = []
    for form, rows in groups.items():
        if len(rows) < PERIOD_SPACINGS + 1:
            continue
        times = sorted(t for t, _ in rows)
        spacings = [b - a for a, b in zip(times, times[1:])]
        mean = math.fsum(spacings) / len(spacings)
        if mean <= 0:
            continue
        cv = math.sqrt(math.fsum((x - mean) ** 2 for x in spacings) / len(spacings)) / mean
        if cv < PERIOD_CV:
            source, is_json, service, keys, text = form
            out.append({"source": source, "form": f"JSON service={service} keys={','.join(keys)}" if is_json else text,
                        "lines": len(rows), "spacings": lab_trial.spacing(spacings), "cv": round(cv, 6),
                        "covered_by": restarts_cover(form, rows[0][1]),
                        "first": {"unix": round(times[0], 6), "utc": utc(times[0])}})
    return sorted(out, key=lambda row: (row["source"], row["form"]))


def restarts_kill(s, g2_dir):
    """The kill of the service of a fault session of zabita_sluzba (skuska/poruchy.py): {unit, induced, why_not,
    call, done, record}, or None for any other session; a DataError by name."""
    from skuska import poruchy
    if s.kind != poruchy.KIND_FAULT:
        return None
    path = Path(os.path.abspath(g2_dir)) / poruchy.BESIDE / f"{s.id}.json"
    doc, _ = s.read("injector", path, poruchy.FAULT_SCHEMA)
    v = doc.get("values") if isinstance(doc.get("values"), dict) else {}
    if (v.get("session_id") != s.id or v.get("vm") != s.vm or not isinstance(v.get("session_dir"), str)
            or os.path.realpath(v["session_dir"]) != os.path.realpath(s.dir)):
        raise DataError(f"{path}: the injector's record is not of this session (its session_id, session_dir or vm)")
    if v.get("fault") != KILL_FAULT:
        return None
    unit = (v.get("parameters") or {}).get("unit") or poruchy.FAULTS[KILL_FAULT]["parameters"]["unit"]
    actions = [a for a in v.get("actions") or [] if isinstance(a, dict) and _number(a.get("unix"))]
    command = poruchy.KILL_COMMAND.format(unit=unit)
    call = next((a["unix"] for a in actions if a.get("what") == "labctl exec" and a.get("guest_command") == command),
                None)
    done = next((a["unix"] for a in actions if a.get("what") == "labctl exec done"
                 and (call is None or a["unix"] >= call)), None)
    window = v.get("window") if isinstance(v.get("window"), list) and len(v["window"]) == 2 else None
    if call is None and window and _number(window[0]):
        call = window[0]
    if done is None and window and _number(window[1]):
        done = window[1]
    return {"unit": unit, "induced": v.get("induced") is True, "why_not": v.get("why_not"), "call": call,
            "done": done, "record": str(path)}


def restarts_session(s, status, g2_dir):
    """The occurrences, the loops elsewhere and the periodic groups of one session (RESTARTS_RULE)."""
    from scripts import collection_logs, lab_trial
    planned, records = s.planned()
    grace = s.meta.get("event_grace_s")
    windows, occurrences = [], []
    for index, item in enumerate(planned):
        record = records[index] if records is not None and index < len(records) else None
        record = record if isinstance(record, dict) else None
        try:
            window = collection_logs.event_window(record, grace) if record is not None else None
        except ValueError:
            window = None
        windows.append((item["type"], window))
        if item["type"] == RESTART_TYPE:
            stop = record.get("host_stop_unix") if record is not None and _number(record.get("host_stop_unix")) \
                else None
            occurrences.append({"session": s.id, "vm": s.vm, "status": status, "counted": status == "counted",
                                "occurrence": "event", "type": RESTART_TYPE, "index": index,
                                "unit": collection_logs.EVENT_UNITS[RESTART_TYPE][0], "induced": None,
                                "window": window, "assign": window, "stop": stop, "loops": [],
                                "why": [] if window is not None else
                                ["no window (no record in events.json, no host start or no host stop done)"]})
    kill = restarts_kill(s, g2_dir)
    if kill is not None:
        timed = kill["induced"] and kill["call"] is not None and kill["done"] is not None
        occurrences.append({"session": s.id, "vm": s.vm, "status": status,
                            "counted": status == "counted" and kill["induced"], "occurrence": "kill",
                            "type": KILL_FAULT, "index": None, "unit": kill["unit"], "induced": kill["induced"],
                            "window": (kill["call"], kill["done"]) if timed else None,
                            "assign": (kill["call"] - 1, kill["done"] + START_LIMIT_INTERVAL_S) if timed else None,
                            "stop": None, "loops": [],
                            "why": [] if timed else [f"the fault was not induced ({kill['why_not']})" if not
                                                     kill["induced"] else "the injector's record has no time of the "
                                                                          "kill"]})
    path, lines = _g2_journal(s)
    elsewhere = []
    if path is None:
        for occ in occurrences:
            occ["why"].append(f"not judged: {lines}")
    else:
        units = restarts_units(lines)
        for unit, found in sorted(units.items()):
            for times in lab_trial._restarts(found["restart"]):
                owner = next((occ for occ in occurrences if occ["unit"] == unit and occ["assign"] is not None
                              and occ["assign"][0] <= times[0] <= occ["assign"][1]), None)
                if owner is not None:
                    owner["loops"].append(times)
                    continue
                design = next(((kind, i) for i, (kind, window) in enumerate(windows) if window is not None
                               and unit in collection_logs.EVENT_UNITS.get(kind, ())
                               and window[0] <= times[0] <= window[1]), None)
                row = restarts_judge(times, found, "elsewhere", times[0] - START_LIMIT_INTERVAL_S)
                row.update(session=s.id, vm=s.vm, unit=unit, status=status,
                           by_design=None if design is None else {"type": design[0], "index": design[1]})
                row["finding"] = not row["fits"] or not row["bounded"] or design is None
                elsewhere.append(row)
        for occ in occurrences:
            if occ["assign"] is None:
                continue
            found = units.get(occ["unit"], {"restart": [], "failed": [], "limit": []})
            if not occ["loops"]:
                occ["why"].append("no restart loop of the unit in the journal "
                                  + ("in the occurrence's window" if occ["occurrence"] == "event" else
                                     "after the kill"))
                continue
            first, *more = occ["loops"]
            if occ["occurrence"] == "event":
                judged = restarts_judge(first, found, "event", occ["window"][0], stop=occ["stop"],
                                        later=[t for loop in more for t in loop])
            else:
                judged = restarts_judge(first, found, "kill", occ["assign"][0],
                                        later=[t for t, _ in found["restart"] if t > first[-1]])
            occ["loop"] = judged
            occ["why"] += ([f"does not fit: {text}" for text in judged["why_not_fits"]]
                           + [f"not bounded: {text}" for text in judged["why_not_bounded"]])
    for occ in occurrences:
        occ.update(fits=(occ.get("loop") or {}).get("fits"), bounded=(occ.get("loop") or {}).get("bounded"),
                   ok=not occ["why"], window=_g2_window(occ["window"]), assign=_g2_window(occ["assign"]),
                   stop=None if occ["stop"] is None else {"unix": occ["stop"], "utc": utc(occ["stop"])},
                   loops=len(occ["loops"]))
    return {"journal": None if path is None else str(path), "journal_why": None if path is not None else lines,
            "occurrences": occurrences, "elsewhere": elsewhere,
            "periodic": [] if path is None else restarts_periodic(lines),
            "lines": 0 if path is None else len(lines)}


def restarts_by_vm(vm, sessions, results, occurrences, elsewhere, periodic, interval, taken):
    """The summary of one VM (RESTARTS_RULE): its counts, the register's entries measured over its journals
    (lab_trial.periods_of), the autovacuum (AUTOVACUUM_RULE_G2) and the periods the register does not name."""
    from scripts import lab_trial
    dirs = [s.dir for s, r in zip(sessions, results) if s.vm == vm and r and r["journal"]]
    measured = lab_trial.periods_of(dirs) if dirs else []
    autovacuum = (lab_trial.autovacuum_property(measured, interval) if dirs else
                  {"rule": lab_trial.AUTOVACUUM_RULE, "ok": None, "why": "no journal of this VM"})
    if autovacuum["ok"] is None:
        autovacuum["taken_over"] = {"rule": AUTOVACUUM_RULE_G2, "measured": (taken or {}).get("after")}
    events = [o for o in occurrences if o["vm"] == vm and o["occurrence"] == "event"]
    kills = [o for o in occurrences if o["vm"] == vm and o["occurrence"] == "kill"]
    return {"sessions": [s.id for s in sessions if s.vm == vm], "journals": len(dirs),
            "events": {"occurrences": len(events), "counted": sum(o["counted"] for o in events),
                       "ok": sum(o["ok"] for o in events)},
            "kills": {"occurrences": len(kills), "counted": sum(o["counted"] for o in kills),
                      "ok": sum(o["ok"] for o in kills)},
            "periods": measured, "autovacuum": autovacuum,
            "unregistered": [row for row in periodic if row["vm"] == vm and row["covered_by"] is None],
            "loops_elsewhere": sum(row["vm"] == vm for row in elsewhere)}


def restarts_findings(occurrences, elsewhere, periodic, by_vm):
    """The findings of RESTARTS_RULE, each named."""
    findings = [f"VM {vm}: the autovacuum launcher's spacing fails the property of Q9: its median "
                f"{v['autovacuum']['median_s']} s lies {v['autovacuum']['remainder_s']} s past a multiple of interval_s"
                for vm, v in by_vm.items() if v["autovacuum"]["ok"] is False]
    findings += [f"{o['session']} {o['type']}" + (f" #{o['index']}" if o["index"] is not None else "")
                 + f" (VM {o['vm']}" + (", its session counted false" if o["status"] == "load" else "") + "): "
                 + "; ".join(o["why"]) for o in occurrences
                 if not o["ok"] and (o["occurrence"] == "event" or o["induced"])]
    findings += [f"{row['session']} (VM {row['vm']}): a restart loop of {row['unit']} at {row['restarts'][0]['utc']} "
                 + ("outside every window of an event that restarts it by design" if row["by_design"] is None
                    else f"in the window of {row['by_design']['type']} #{row['by_design']['index']}")
                 + ("" if row["fits"] else ", does not fit: " + "; ".join(row["why_not_fits"]))
                 + ("" if row["bounded"] else ", not bounded: " + "; ".join(row["why_not_bounded"]))
                 for row in elsewhere if row["finding"]]
    findings += [f"{row['session']} (VM {row['vm']}): a period the register does not name: {row['source']}: "
                 f"{row['form'][:160]} ({row['lines']} lines, median spacing {row['spacings']['median']} s, cv "
                 f"{row['cv']})" for row in periodic if row["covered_by"] is None]
    return findings


def restarts_table(args, command):
    """The mode restarts (RESTARTS_RULE): writes the new record, prints one line per VM and the criterion, and
    returns the exit code."""
    started = _g2_start(args, "restarts")
    if started is None:
        return 2
    out, paths = started
    try:
        protocol = _g2_protocol(args.protocol)
    except DataError as error:
        print(f"campaign_report: {error}", file=sys.stderr)
        return 2
    from scripts import lab_trial
    from skuska import g2
    register = ROOT / "lab/periods.json"
    register_sha = _g2_digest(register)
    g2_dir = _g2_dir(args)
    sessions, entries, results, refused = [], [], [], []
    for path in paths:
        try:
            s = G2TableSession(path, g2_dir)
            s.bind(protocol)
            lab = s.meta.get("lab_sha256")
            if not isinstance(lab, dict) or lab.get("lab/periods.json") != register_sha:
                raise DataError(f"{s.dir}: session.json lab_sha256 names "
                                f"{_shown(lab.get('lab/periods.json') if isinstance(lab, dict) else lab, 80)} for "
                                f"lab/periods.json, not {register_sha} of {register} (run this mode from the "
                                "session's commit)")
            status, why = s.selection("restart_loops_bounded")
            result = restarts_session(s, status, g2_dir) if status != "left_out" else None
            if result is not None and result["journal"] is not None:
                found = sorted((s.dir / "guest").glob("*-journal.txt.gz"))
                if found != [Path(result["journal"])]:
                    raise DataError(f"{s.dir}/guest holds the journal files {[f.name for f in found]}, not only the "
                                    "one its segment binds (lab_trial.periods_of reads every *-journal.txt.gz)")
        except DataError as error:
            refused.append(str(error))
            continue
        entry = s.entry(status, why)
        if result is not None:
            entry.update(journal=result["journal"], journal_why=result["journal_why"], journal_lines=result["lines"])
        sessions.append(s)
        entries.append(entry)
        results.append(result)
    if _g2_refusals("restarts", out, sessions, refused):
        return 2
    occurrences = [occ for r in results if r for occ in r["occurrences"]]
    elsewhere = [row for r in results if r for row in r["elsewhere"]]
    periodic = [{"session": s.id, "vm": s.vm, **row} for s, r in zip(sessions, results) if r for row in r["periodic"]]
    taken = next((e for e in json.loads(register.read_text())["periods"] if e.get("name") == lab_trial.AUTOVACUUM),
                 {}).get("measured")
    by_vm = {vm: restarts_by_vm(vm, sessions, results, occurrences, elsewhere, periodic, protocol["interval_s"], taken)
             for vm in protocol["vms"]}
    missing = []
    total = sum(o["counted"] for o in occurrences if o["occurrence"] == "event")
    if total < g2.OCCURRENCES:
        missing.append(f"{RESTART_TYPE}: {total} occurrence(s) of counted sessions on both VMs together, fewer than "
                       f"{g2.OCCURRENCES}")
    for vm, v in by_vm.items():
        if v["events"]["counted"] < g2.MIN_PER_VM:
            missing.append(f"{RESTART_TYPE} on VM {vm}: {v['events']['counted']} occurrence(s) of counted sessions, "
                           f"fewer than {g2.MIN_PER_VM}")
        if v["kills"]["counted"] < KILLS_NEEDED:
            missing.append(f"the killed service on VM {vm}: {v['kills']['counted']} induced kill(s) in counted "
                           f"sessions, fewer than {KILLS_NEEDED}")
    findings = restarts_findings(occurrences, elsewhere, periodic, by_vm)
    criterion = {"met": not missing and not findings, "minimums_met": not missing}
    record = _g2_record(RESTARTS_TABLE_SCHEMA, RESTARTS_GUEST, command, len(occurrences), {
        "criterion": "restart_loops_bounded", "protocol": {k: v for k, v in protocol.items() if k != "types"},
        "register": {"path": str(register), "sha256": register_sha}, "needed": g2.OCCURRENCES,
        "needed_per_vm": g2.MIN_PER_VM, "kills_needed_per_vm": KILLS_NEEDED,
        "constants": {"fits_s": list(FITS_S), "start_limit_burst": START_LIMIT_BURST,
                      "start_limit_interval_s": START_LIMIT_INTERVAL_S, "restart_window_s": lab_trial.RESTART_WINDOW_S,
                      "guest_clock_s": GUEST_CLOCK_S, "period_spacings": PERIOD_SPACINGS, "period_cv": PERIOD_CV},
        "sessions": entries, "occurrences": occurrences, "loops_elsewhere": elsewhere, "periodic": periodic,
        "by_vm": by_vm, "minimums_met": not missing, "missing": missing, "findings": findings, "result": criterion,
        "selection": G2_SELECTION,
        "rules": {"restarts": RESTARTS_RULE, "assign": ASSIGN_RULE, "fits": FITS_RULE, "bounded": BOUNDED_RULE,
                  "elsewhere": ELSEWHERE_RULE, "periods": PERIODS_RULE, "autovacuum": AUTOVACUUM_RULE_G2}},
        "The restart loops and the periods of the guests' journals of G2 against lab/periods.json (criterion "
        "restart_loops_bounded of G2); the spacings measured here never go into lab/periods.json.")
    code = _g2_write(out, record)
    if code:
        return code
    for vm, v in by_vm.items():
        print(f"vm {vm}: {RESTART_TYPE} {v['events']['ok']}/{v['events']['occurrences']} fit and bounded "
              f"({v['events']['counted']}/{g2.MIN_PER_VM} counted), kills {v['kills']['ok']}/"
              f"{v['kills']['occurrences']} ({v['kills']['counted']}/{KILLS_NEEDED} counted), "
              f"{v['loops_elsewhere']} loop(s) elsewhere, {len(v['unregistered'])} period(s) the register does not "
              "name")
    print("restart_loops_bounded: " + ("met" if criterion["met"] else "not met") + f"; {len(missing)} minimum(s) "
          f"missing, {len(findings)} finding(s)", flush=True)
    print(f"campaign_report: restarts: {len(sessions)} session(s), {len(occurrences)} occurrence(s); record {out}",
          file=sys.stderr)
    return 0 if criterion["met"] else 1


def g2_table_parsers(modes):
    """The parsers of the modes guest, events and restarts (package H1b6a), in one place."""
    g2_dir = ("the G2 directory: zaznamy/ holds the driver's records (skuska/g2.py), poruchy/ the injector's "
              "(default: skuska/g2.py G2_DIR)")
    guest = modes.add_parser("guest", help="the deployed files of lab/ on the VMs against the commit of each G2 "
                                           "session (criterion guest_matches_repository; GUEST_RULE)")
    events = modes.add_parser("events", help="the occurrences of the events of G2 sessions and their predicates "
                                             "(criterion event_effects; EVENTS_RULE, NO_EFFECT_RULE)")
    restarts = modes.add_parser("restarts", help="the restart loops and periods of the guests' journals of G2 "
                                                 "against lab/periods.json (criterion restart_loops_bounded; "
                                                 "RESTARTS_RULE)")
    for mode in (guest, events, restarts):
        mode.add_argument("session_dirs", type=Path, nargs="+",
                          help="G2 session directories (data/diagnostics/G2/<vm>/<session>)")
        if mode is not guest:
            mode.add_argument("--protocol", type=Path, required=True,
                              help="the protocol file the sessions ran under (their protocol.json must agree with it "
                                   "outside the paths of G1 and later stages: gates.stage_sha256 of stage G0)")
        mode.add_argument("--g2-dir", type=Path, help=g2_dir)
        mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")


G2_TABLE_MODES = {"guest": guest_table, "events": events_table, "restarts": restarts_table}


CONTROLS_TABLE_SCHEMA = "hyptcn3/g2-controls-table/1"
# The criterion controls_paired of stage G2 (scripts/gates.py CRITERIA, the lead's answer to Q47): 3 occurrences of the
# control and 3 of its paired negative per kind of controls.kinds.
CONTROLS_NEEDED = 3
CONTROLS_POLARITIES = ("control", "negative")
CONTROLS_ROLE = "diagnostic"  # The role of every session of G2 (dokazy/G2/mapa.md point A; skuska/g2.py ROLE).
CONTROLS_STAGE = "skuska"  # scripts/controls.py STAGES: the stage of a record of G2 (proposal 11.1).
CHANNEL_NOT_JUDGED = ("not judged in G2: the lead's answer to Q47 judges channel_reacted only descriptively with the "
                      "bundle of the parity check, and protocol v5 has no bundle before G3a")
CONTROLS_GUEST = ("none: the mode controls reads saved session files, audit records and feature archives; no VM is "
                  "contacted and no RAM image is opened")
CONTROLS_RULE = (
    "The criterion controls_paired of stage G2 (scripts/gates.py CRITERIA, the lead's G2 skeleton) and the lead's "
    "answers Q46 to Q48 and Q20: every kind of controls.kinds with its paired negative, 3 occurrences of the control "
    "and 3 of the negative per kind, and the shift of the columns against controls.kinds.<kind>.expect, in a table of "
    "shifts. The mode reads, of each G2 session directory given (a diagnostic run whose session.json lists the "
    "controls the wrapper of Q46 inserted, skuska/kontroly.py WRAP_RULE): session.json, protocol.json (the session's "
    "copy, the file session.json protocol_sha256 binds), controls.json (schema hyptcn3/session-controls/1), the "
    "session's audit record (of the audit_*.json in the directory whose values.session_dir is the directory and whose "
    "values.session_sha256 is the sha256 of session.json the newest by name, its UTC stamp; it must have audited "
    "under protocol.json, values.protocol_sha256; the others are listed) and the feature archive that audit wrote "
    "(values.features, with the sha256 values.features_sha256), never a RAM image. Of every record of controls.json "
    "in its order: VM, session, kind, polarity, class, dose, times, executed, the guest's effect and cleanup, and the "
    "outcomes of scripts/controls.py outcomes (role diagnostic, stage skuska; the lead's answer to Q47): parser_saw, "
    "column_moved per column of the kind (the shift of the mean of the measured rows wholly inside against the mean of "
    "the measured rows among the 12 before the start, the expected shift and direction, reached or not) and "
    "sensor_scored; channel_reacted is not judged in G2 (Q47: only descriptively with the bundle of the parity check, "
    "and protocol v5 has no bundle before G3a). An occurrence counts towards the minimum when its outcomes were "
    "computed (it ran: executed, the return predicate held, ordered host times, its rows in the archive) and the "
    "guest's effect and cleanup predicates held (the executor's judgment, G2 preparation: a faultless occurrence by "
    "the guest, as the section controls of the log audit asks); the session's verdict does not decide it and is "
    "shown with each occurrence (as the lead accepted for the occurrences of events, Q51). The counts per kind and "
    "polarity show the criterion's minimum, 3, and name every occurrence missing by the count; an expectation missed "
    "(a control's column below its expected shift, a negative's reaching it) is a finding for the lead (Q20), and so "
    "are a parser_saw that is not ok and an occurrence without a scored row in its horizon (the sensor did not score, "
    "O4); none of them is a refusal. Refused by name, each a data error: a directory without one of these files or "
    "with a file of another schema, a session of another role than diagnostic or without controls in session.json, a "
    "protocol.json other than the one session.json binds or not of schema 3, no audit record of the session, an audit "
    "under another protocol, a feature archive missing, other than the audit's or unreadable, sessions whose protocols "
    "differ in controls.kinds, a directory named twice, and an --out that exists (refused before anything is read) or "
    "lies inside a session directory. Exit 0: the table is written to --out, a new JSON record with the provenance "
    "header of check E, and every kind has its minimum; 1: the table is written and a minimum is missing, named; 2: a "
    "usage or data error, every refusal named on stderr and nothing written.")


def _controls_file(path, schema=None):
    """(the JSON object of the file, its sha256), or a DataError that names the file and why."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise DataError(f"{path}: cannot be read ({type(error).__name__}: {error})") from None
    try:
        doc = json.loads(raw)
    except ValueError as error:
        raise DataError(f"{path}: not JSON ({error})") from None
    if not isinstance(doc, dict):
        raise DataError(f"{path}: not a JSON object")
    if schema is not None and doc.get("schema") != schema:
        raise DataError(f"{path}: its schema is {_shown(_get(doc, 'schema'), 60)}, not {schema}")
    return doc, hashlib.sha256(raw).hexdigest()


def controls_audit(directory, session_sha):
    """(path, record, the other records of the session) of the audit record CONTROLS_RULE takes: of the
    audit_*.json in `directory` that bind its session.json (values.session_dir and values.session_sha256) the newest by
    name; a DataError when there is none."""
    found = []
    for path in sorted(Path(directory).glob("audit_*.json")):
        try:
            doc, _ = _controls_file(path, AUDIT_SCHEMA)
        except DataError:
            continue
        values = doc.get("values")
        if (isinstance(values, dict) and isinstance(values.get("session_dir"), str)
                and os.path.realpath(values["session_dir"]) == os.path.realpath(directory)
                and values.get("session_sha256") == session_sha):
            found.append((path, doc))
    if not found:
        raise DataError(f"{directory}: no audit record of the session (an audit_*.json of schema {AUDIT_SCHEMA} whose "
                        "values.session_dir is the directory and whose values.session_sha256 is the sha256 of its "
                        "session.json)")
    path, doc = found[-1]
    return path, doc, [str(other) for other, _ in found[:-1]]


def _controls_ok(predicate):
    """The guest's predicate of a record (effect or cleanup) as the table shows it: its ok, None when absent."""
    return {"ok": predicate.get("ok")} if isinstance(predicate, dict) else None


def controls_row(meta, verdict, index, record, outcome, error):
    """One occurrence of the table (CONTROLS_RULE): the record's identity, the guest's predicates, the outcomes of
    scripts/controls.py (or why there are none) and whether it counts towards the minimum."""
    record = record if isinstance(record, dict) else {}
    row = {"vm": meta.get("vm"), "session": meta.get("session_id"), "scenario": meta.get("scenario"), "index": index,
           **{key: record.get(key) for key in ("kind", "polarity", "kind_class", "dose", "start_s", "duration_s",
                                                "executed")},
           "effect": _controls_ok(record.get("effect")), "cleanup": _controls_ok(record.get("cleanup")),
           "parser_saw": None, "column_moved": None, "sensor_scored": None, "channel_reacted": CHANNEL_NOT_JUDGED,
           "window": None, "outcome_error": error, "audit_accepted": verdict}
    if outcome is not None:
        saw, moved = outcome["parser_saw"], outcome["column_moved"]
        row.update(parser_saw={"ok": saw["ok"], "why": saw["why"], "rows": len(saw["rows"]),
                               "showing": len(saw["showing"]), "object": saw["object"]},
                   column_moved={"ok": moved["ok"], "why": moved["why"], "reference_rows": len(moved["reference"]),
                                 "columns": moved["columns"]},
                   sensor_scored=outcome["sensor_scored"],
                   window={name: len(outcome["window"][name]) for name in ("before", "inside", "horizon", "scored")})
    why = (f"its outcomes were not computed: {error}" if outcome is None
           else "the guest's effect predicate did not hold" if (row["effect"] or {}).get("ok") is not True
           else "the guest's cleanup did not hold" if (row["cleanup"] or {}).get("ok") is not True else None)
    row.update(counted=why is None, why_not_counted=why)
    return row


def controls_session(path, outcomes, load):
    """One session directory by CONTROLS_RULE: (its entry, its rows, its protocol), or a DataError. `outcomes` is
    scripts/controls.py outcomes and `load` features.archive.load (imported by the mode)."""
    directory = Path(os.path.abspath(path))
    if not directory.is_dir():
        raise DataError(f"{directory}: not a session directory")
    meta, meta_sha = _controls_file(directory / "session.json")
    if meta.get("role") != CONTROLS_ROLE:
        raise DataError(f"{directory}: session.json names the role {_shown(_get(meta, 'role'), 40)}, not "
                        f"{CONTROLS_ROLE} (the sessions of G2 are diagnostic runs; a session of the sealed role "
                        "test_controls is the final evaluation's)")
    if not isinstance(meta.get("controls"), list) or not meta["controls"]:
        raise DataError(f"{directory}: session.json lists no controls (no session with controls: skuska/kontroly.py "
                        "WRAP_RULE)")
    if not isinstance(meta.get("session_id"), str) or not isinstance(meta.get("vm"), str):
        raise DataError(f"{directory}: session.json names no session_id or no vm")
    protocol, protocol_sha = _controls_file(directory / "protocol.json")
    if meta.get("protocol_sha256") != protocol_sha:
        raise DataError(f"{directory}: protocol.json has the sha256 {protocol_sha}, session.json binds "
                        f"{_shown(_get(meta, 'protocol_sha256'), 80)}")
    if protocol.get("schema") != protocol_v5.SCHEMA or not isinstance((protocol.get("controls") or {}).get("kinds"),
                                                                       dict):
        raise DataError(f"{directory}: protocol.json is no protocol of schema {protocol_v5.SCHEMA} with "
                        "controls.kinds")
    doc, controls_sha = _controls_file(directory / "controls.json", protocol_v5.CONTROLS_SCHEMA)
    records = doc.get("controls")
    if not isinstance(records, list):
        raise DataError(f"{directory}: controls.json holds no list of controls")
    audit_path, audit, ignored = controls_audit(directory, meta_sha)
    values = audit["values"]
    if values.get("protocol_sha256") != protocol_sha:
        raise DataError(f"{audit_path}: audited under the protocol {_shown(_get(values, 'protocol_sha256'), 80)}, not "
                        f"the session's protocol.json {protocol_sha}")
    features = values.get("features")
    if not isinstance(features, str) or not Path(features).is_file():
        raise DataError(f"{audit_path}: values.features names no feature archive: {_shown(_get(values, 'features'))}")
    features_sha = hashlib.sha256(Path(features).read_bytes()).hexdigest()
    if features_sha != values.get("features_sha256"):
        raise DataError(f"{features}: its sha256 is {features_sha}, the audit's values.features_sha256 "
                        f"{_shown(_get(values, 'features_sha256'), 80)}")
    try:
        result = load(features)
    except (OSError, ValueError, KeyError) as error:
        raise DataError(f"{features}: the feature archive cannot be loaded ({type(error).__name__}: {error})") from None
    verdict = values.get("accepted")
    rows = []
    for index, record in enumerate(records):
        outcome = error = None
        try:
            outcome = outcomes(record, result, protocol, role=CONTROLS_ROLE, archive=features, stage=CONTROLS_STAGE)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            error = one_line(f"{type(exc).__name__}: {exc}" if not isinstance(exc, ValueError) else str(exc))
        rows.append(controls_row(meta, verdict, index, record, outcome, error))
    guest = meta.get("guest_before") if isinstance(meta.get("guest_before"), dict) else {}
    entry = {"path": str(directory), "session_id": meta["session_id"], "vm": meta["vm"],
             "scenario": meta.get("scenario"), "role": meta["role"], "session_json_sha256": meta_sha,
             "protocol_sha256": protocol_sha, "controls_json_sha256": controls_sha,
             "guest": {key: guest.get(key) for key in ("kernel", "boot_id")},
             "audit": {"path": str(audit_path), "sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
                       "accepted": verdict, "reasons": values.get("reasons"), "ignored": ignored},
             "features": {"path": features, "sha256": features_sha}, "occurrences": len(records)}
    return entry, rows, protocol


def controls_counts(rows, kinds, vms):
    """({kind: {polarity: counted, occurrences, needed, missing, by_vm}}, the occurrences missing by the count) by
    CONTROLS_RULE."""
    counts, missing = {}, []
    for kind in kinds:
        counts[kind] = {}
        for polarity in CONTROLS_POLARITIES:
            mine = [row for row in rows if row["kind"] == kind and row["polarity"] == polarity]
            counted = [row for row in mine if row["counted"]]
            counts[kind][polarity] = {"counted": len(counted), "occurrences": len(mine), "needed": CONTROLS_NEEDED,
                                      "missing": max(0, CONTROLS_NEEDED - len(counted)),
                                      "by_vm": {vm: sum(row["vm"] == vm for row in counted) for vm in vms}}
            if len(counted) < CONTROLS_NEEDED:
                missing.append(f"{kind}: {len(counted)} of {CONTROLS_NEEDED} {polarity}s counted "
                               f"({CONTROLS_NEEDED - len(counted)} missing; {len(mine)} recorded)")
    return counts, missing


def controls_shifts(rows, kinds, protocol):
    """The table of shifts per kind and column of the counted occurrences, and the findings of CONTROLS_RULE."""
    shifts, expect, parser, unscored = {}, [], [], []
    for kind in kinds:
        columns = protocol["controls"]["kinds"][kind].get("columns") or []
        shifts[kind] = {column: [] for column in columns}
    for row in rows:
        if not row["counted"]:
            continue
        name = f"{row['kind']} {row['polarity']} in {row['session']} (#{row['index']})"
        for column, moved in (row["column_moved"]["columns"] or {}).items():
            shifts.get(row["kind"], {}).setdefault(column, []).append(
                {"session": row["session"], "vm": row["vm"], "polarity": row["polarity"], "dose": row["dose"],
                 **{key: moved[key] for key in ("reference_mean", "inside_mean", "shift", "expect", "direction",
                                                "reached")}})
            if moved["reached"] is (row["polarity"] != "control"):
                expect.append(f"{name}: {column} moved {moved['shift']:.6g} against the expected {moved['expect']:g} "
                              f"{moved['direction']}" + ("" if row["polarity"] == "control" else
                                                         ", the shift its control is expected to reach"))
        if row["column_moved"]["ok"] is None:
            expect.append(f"{name}: column_moved not judged ({row['column_moved']['why']})")
        if row["parser_saw"]["ok"] is not True:
            parser.append(f"{name}: parser_saw {row['parser_saw']['ok']}"
                          + (f" ({row['parser_saw']['why']})" if row["parser_saw"]["why"] else ""))
        if row["sensor_scored"] is not True:
            unscored.append(f"{name}: no scored row within the horizon (sensor did not score, O4)")
    return shifts, expect, parser, unscored


def controls_line(kind, row):
    """The line of one kind on stdout: its counted controls and negatives against the minimum."""
    parts = [f"{polarity}s {row[polarity]['counted']}/{row[polarity]['needed']}"
             + (f" ({row[polarity]['missing']} missing)" if row[polarity]["missing"] else "")
             for polarity in CONTROLS_POLARITIES]
    return f"{kind}: " + ", ".join(parts)


def controls_table(args, command):
    """The mode controls (CONTROLS_RULE): refuses an --out that exists before it reads anything and a directory named
    twice, then reads every session; writes the new record, prints one line per kind, and returns the exit code."""
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths = [os.path.abspath(path) for path in args.session_dirs]
    real = [os.path.realpath(path) for path in paths]
    twice = sorted({path for path, r in zip(paths, real) if real.count(r) > 1})
    if twice:
        print("campaign_report: controls: a session directory is named more than once: " + ", ".join(twice),
              file=sys.stderr)
        return 2
    # The outcomes of package B8 and the loader of a feature archive: only this mode imports them (no RAM image).
    from features.archive import load
    from scripts.controls import outcomes
    entries, rows, refused, kinds = [], [], [], None
    for path in paths:
        try:
            entry, mine, protocol = controls_session(path, outcomes, load)
        except DataError as error:
            refused.append(str(error))
            continue
        spec = json.dumps(protocol["controls"]["kinds"], sort_keys=True)
        if kinds is None:
            kinds, first, kinds_spec = sorted(protocol["controls"]["kinds"]), protocol, spec
        elif spec != kinds_spec:
            refused.append(f"{path}: its protocol's controls.kinds differ from those of {entries[0]['path']}: the "
                           "table takes the expectations of one protocol")
            continue
        entries.append(entry)
        rows += mine
    target = Path(os.path.realpath(out.parent))
    refused += [f"refusing to write {out} inside the session directory {entry['path']}" for entry in entries
                if target == Path(os.path.realpath(entry["path"]))
                or target.is_relative_to(os.path.realpath(entry["path"]))]
    if refused or not entries:
        for why in refused or ["no session"]:
            print(f"campaign_report: controls: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: controls: {len(refused)} refusal(s): no table, nothing written", file=sys.stderr)
        return 2
    vms = sorted({entry["vm"] for entry in entries})
    counts, missing = controls_counts(rows, kinds, vms)
    shifts, expect, parser, unscored = controls_shifts(rows, kinds, first)
    identity = git_identity()
    record = {"schema": CONTROLS_TABLE_SCHEMA, "commit": identity["commit"], "commit_dirty": identity["dirty"],
              "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
              "guest": CONTROLS_GUEST, "command": command, "n": len(rows),
              "values": {"stage": "G2", "criterion": "controls_paired", "needed": CONTROLS_NEEDED, "kinds": kinds,
                         "sessions": entries, "occurrences": rows, "counts": counts, "minimums_met": not missing,
                         "missing": missing, "shifts": shifts, "expect_findings": expect, "parser_findings": parser,
                         "unscored": unscored, "channel_reacted": CHANNEL_NOT_JUDGED, "rule": CONTROLS_RULE},
              "note": "The table of shifts of the controls on the VMs and their paired negatives (criterion "
                      "controls_paired of G2); no score is read and nothing is detected."}
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        print(f"campaign_report: --out appeared meanwhile, nothing was overwritten: {out}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"campaign_report: cannot create {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        print(f"campaign_report: cannot write {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    for kind in kinds:
        print(controls_line(kind, counts[kind]))
    print("controls_paired minimums: " + ("met" if not missing else "missing: " + "; ".join(missing))
          + f"; {len(expect)} expectation finding(s), {len(parser)} parser finding(s), {len(unscored)} unscored",
          flush=True)
    print(f"campaign_report: controls: {len(entries)} session(s), {len(rows)} occurrence(s); record {out}",
          file=sys.stderr)
    return 0 if not missing else 1


FAULTS_TABLE_SCHEMA = "hyptcn3/g2-faults-table/1"
FAULT_RECORD_SCHEMA = "hyptcn3/g2-fault/1"  # skuska/poruchy.py FAULT_SCHEMA: the injector's record of a session.
FAULTS_NEEDED = 1  # The criterion live_fault_injections: every fault at least once on each VM.
FAULTS_GUEST = ("none: the mode faults reads saved session files, audit records and the injector's records; no VM is "
                "contacted and no RAM image is opened")
FAULTS_RULE = (
    "The criterion live_fault_injections of stage G2 (scripts/gates.py CRITERIA, the lead's G2 skeleton): the six "
    "faults of proposal 10.3, each at least once on each VM, each ending in a loud refusal with the name expected and "
    "written before the run (the lead's answer to Q56: skuska/poruchy.py FAULTS, committed before the first fault "
    "session), in a table: fault, VM, expected reason, received reason. The mode reads, of each G2 session directory "
    "given (a "
    "diagnostic run of the fault plan, skuska/poruchy.py PLAN_RULE): session.json, protocol.json (the session's copy, "
    "the file session.json protocol_sha256 binds; its vms name the VMs counted), end.json when there is one, the "
    "session's audit record when there is one (of the audit_*.json in the directory whose values.session_dir is the "
    "directory and whose values.session_sha256 is the sha256 of session.json the newest by name; it must have audited "
    "under protocol.json) and the injector's record <--records>/<session id>.json (schema hyptcn3/g2-fault/1), whose "
    "session, directory and VM must be the session's and whose fault, expected names and faults_sha256 must be those "
    "of skuska/poruchy.py FAULTS. The reasons received are, in this order, the error of a capture that did not "
    "complete (no end.json, end.json without completed true, or with an error) as scripts/campaign.py "
    "incomplete_reasons gives it, the campaign's name for an incomplete capture, and the reasons of the audit's "
    "verdict (values.reasons). A "
    "refusal is loud when the capture did not complete (with the campaign's name for why) or the audit refused the "
    "session; a session the audit "
    "accepted is not refused (for a fault that was induced a finding: the guards absorbed it, map question 11), and "
    "neither is one without an error and without an audit (no verdict). It is named when every expected name of its "
    "fault is among the reasons received, exactly; the other reasons are the rest, and those not among the reasons of "
    "the clean session of the same VM and length (a clean session of the plan given beside) are shown apart. A fault "
    "session counts towards its fault's minimum on its VM when the injector's record says the fault was induced, the "
    "refusal was loud and it was named; one that was refused with other names counts not and is shown with what it "
    "received. The counts per fault and VM show the minimum, 1, and name every one missing. Refused by name, each a "
    "data error: a directory without session.json or protocol.json, a session of another role than diagnostic, a "
    "protocol.json other than the one session.json binds, an audit under another protocol, no injector's record or "
    "one of another schema, session, directory, VM, fault or names, sessions whose protocols name other VMs, a "
    "directory named twice, and an --out that exists (refused before anything is read) or lies inside a session "
    "directory. Exit 0: the table is written to --out, a new JSON record with the provenance header of check E, and "
    "every fault has its minimum on every VM; 1: the table is written and a minimum is missing, named; 2: a usage or "
    "data error, every refusal named on stderr and nothing written.")


def faults_session(path, records_dir, faults, faults_sha):
    """One session directory by FAULTS_RULE: its row (the fault's or the clean session's), or a DataError."""
    from scripts.campaign import incomplete_reasons  # The campaign's name for a capture that did not complete.
    directory = Path(os.path.abspath(path))
    if not directory.is_dir():
        raise DataError(f"{directory}: not a session directory")
    meta, meta_sha = _controls_file(directory / "session.json")
    if meta.get("role") != CONTROLS_ROLE:
        raise DataError(f"{directory}: session.json names the role {_shown(_get(meta, 'role'), 40)}, not "
                        f"{CONTROLS_ROLE} (the sessions of G2 are diagnostic runs)")
    sid, vm = meta.get("session_id"), meta.get("vm")
    if not isinstance(sid, str) or not isinstance(vm, str):
        raise DataError(f"{directory}: session.json names no session_id or no vm")
    protocol, protocol_sha = _controls_file(directory / "protocol.json")
    if meta.get("protocol_sha256") != protocol_sha:
        raise DataError(f"{directory}: protocol.json has the sha256 {protocol_sha}, session.json binds "
                        f"{_shown(_get(meta, 'protocol_sha256'), 80)}")
    vms = [row.get("name") for row in protocol.get("vms") or [] if isinstance(row, dict)]
    record_path = Path(records_dir) / f"{sid}.json"
    record, record_sha = _controls_file(record_path, FAULT_RECORD_SCHEMA)
    v = record.get("values") if isinstance(record.get("values"), dict) else {}
    fault = v.get("fault")
    if (v.get("session_id") != sid or not isinstance(v.get("session_dir"), str)
            or os.path.realpath(v["session_dir"]) != os.path.realpath(directory) or v.get("vm") != vm):
        raise DataError(f"{record_path}: the injector's record is of the session {_shown(_get(v, 'session_id'), 80)} "
                        f"in {_shown(_get(v, 'session_dir'))} on VM {_shown(_get(v, 'vm'), 20)}, not of {sid} in "
                        f"{directory} on VM {vm}")
    if fault is not None and fault not in faults:
        raise DataError(f"{record_path}: the fault {_shown(fault, 60)} is not one of skuska/poruchy.py FAULTS")
    expected = [] if fault is None else faults[fault]["expected"]
    if v.get("expected") != expected or v.get("faults_sha256") != faults_sha:
        raise DataError(f"{record_path}: its expected names {_shown(_get(v, 'expected'))} or faults_sha256 differ from "
                        "skuska/poruchy.py FAULTS, the names committed before the runs (Q56)")
    end_path = directory / "end.json"
    end = _controls_file(end_path)[0] if end_path.exists() else None
    incomplete = end is None or end.get("completed") is not True or "error" in end
    capture = incomplete_reasons(directory) if incomplete else []
    try:
        audit_path, audit, ignored = controls_audit(directory, meta_sha)
    except DataError:
        audit_path = audit = None
        ignored = []
    audit_entry, audit_reasons = None, []
    if audit is not None:
        values = audit["values"]
        if values.get("protocol_sha256") != protocol_sha:
            raise DataError(f"{audit_path}: audited under the protocol {_shown(_get(values, 'protocol_sha256'), 80)}, "
                            f"not the session's protocol.json {protocol_sha}")
        audit_reasons = [str(x) for x in values.get("reasons") or []]
        audit_entry = {"path": str(audit_path), "sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
                       "accepted": values.get("accepted"), "reasons": audit_reasons, "ignored": ignored}
    received = list(dict.fromkeys([*capture, *audit_reasons]))
    loud = bool(capture) or (audit is not None and audit["values"].get("accepted") is False)
    named = fault is not None and all(name in received for name in expected)
    measured = v.get("measured") if isinstance(v.get("measured"), dict) else {}
    row = {"session": sid, "vm": vm, "fault": fault,
           "fault_text": None if fault is None else faults[fault]["fault"], "scenario": meta.get("scenario"),
           "cycles": meta.get("cycles"), "expected": expected, "received": received,
           "expected_received": {name: name in received for name in expected},
           "other_reasons": [x for x in received if x not in expected], "other_reasons_not_in_clean": None,
           "capture": {"completed": None if end is None else end.get("completed"),
                       "error": None if end is None else end.get("error"), "incomplete_reasons": capture},
           "audit": audit_entry, "induced": v.get("induced"), "why_not_induced": v.get("why_not"),
           "fault_window": v.get("window"), "fault_inside_measured_phase": measured.get("fault_inside"),
           "loud": loud, "named": named,
           "record": {"path": str(record_path), "sha256": record_sha}, "session_dir": str(directory),
           "session_json_sha256": meta_sha, "protocol_sha256": protocol_sha}
    why = None
    if fault is not None:
        missing = [name for name in expected if name not in received]
        why = (f"the fault was not induced: {v.get('why_not')}" if v.get("induced") is not True
               else "the session was not refused: the audit accepted it (the guards absorbed the fault, a finding)"
               if audit is not None and audit["values"].get("accepted") is True and not capture
               else "the session was not refused: no error of the capture and no audit (no verdict)" if not loud
               else "refused without the expected name(s): " + "; ".join(missing) if missing else None)
    row.update(counted=fault is not None and why is None, why_not_counted=why)
    return row, vms


def faults_counts(rows, faults, vms):
    """({fault: {vm: {counted, sessions, needed, missing}}}, the counts missing) by FAULTS_RULE."""
    counts, missing = {}, []
    for fault in faults:
        counts[fault] = {}
        for vm in vms:
            mine = [row for row in rows if row["fault"] == fault and row["vm"] == vm]
            counted = [row["session"] for row in mine if row["counted"]]
            counts[fault][vm] = {"counted": len(counted), "sessions": [row["session"] for row in mine],
                                 "counted_sessions": counted, "needed": FAULTS_NEEDED,
                                 "missing": max(0, FAULTS_NEEDED - len(counted))}
            if len(counted) < FAULTS_NEEDED:
                missing.append(f"{fault} on VM {vm}: {len(counted)} of {FAULTS_NEEDED} refused by its names "
                               f"({len(mine)} session(s): " + (", ".join(f"{row['session']}: {row['why_not_counted']}"
                                                                         for row in mine) or "none") + ")")
    return counts, missing


def faults_table(args, command):
    """The mode faults (FAULTS_RULE): refuses an --out that exists before it reads anything and a directory named
    twice, then reads every session; writes the new record, prints one line per fault, and returns the exit code."""
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        print(f"campaign_report: --out already exists, nothing was read or written: {out}", file=sys.stderr)
        return 2
    paths = [os.path.abspath(path) for path in args.session_dirs]
    real = [os.path.realpath(path) for path in paths]
    twice = sorted({path for path, r in zip(paths, real) if real.count(r) > 1})
    if twice:
        print("campaign_report: faults: a session directory is named more than once: " + ", ".join(twice),
              file=sys.stderr)
        return 2
    from skuska.poruchy import FAULTS, faults_sha256  # The forms and names committed before the runs (Q56).
    faults, faults_sha = FAULTS, faults_sha256()
    rows, refused, vms = [], [], None
    for path in paths:
        try:
            row, theirs = faults_session(path, args.records, faults, faults_sha)
        except DataError as error:
            refused.append(str(error))
            continue
        if vms is None:
            vms = theirs
        elif theirs != vms:
            refused.append(f"{path}: its protocol names the VMs {theirs}, not {vms} of {rows[0]['session_dir']}")
            continue
        rows.append(row)
    target = Path(os.path.realpath(out.parent))
    refused += [f"refusing to write {out} inside the session directory {row['session_dir']}" for row in rows
                if target == Path(os.path.realpath(row["session_dir"]))
                or target.is_relative_to(os.path.realpath(row["session_dir"]))]
    if refused or not rows:
        for why in refused or ["no session"]:
            print(f"campaign_report: faults: {one_line(why)}", file=sys.stderr)
        print(f"campaign_report: faults: {len(refused)} refusal(s): no table, nothing written", file=sys.stderr)
        return 2
    clean = {}
    for row in rows:
        if row["fault"] is None:
            clean.setdefault((row["vm"], row["cycles"]), row)
    for row in rows:
        twin = clean.get((row["vm"], row["cycles"]))
        if row["fault"] is not None and twin is not None:
            row["other_reasons_not_in_clean"] = [x for x in row["other_reasons"] if x not in twin["received"]]
            row["clean_session"] = twin["session"]
    fault_rows = [row for row in rows if row["fault"] is not None]
    counts, missing = faults_counts(fault_rows, list(faults), vms)
    absorbed = [f"{row['fault']} on VM {row['vm']} ({row['session']}): induced, and the audit accepted the session"
                for row in fault_rows if row["induced"] is True and not row["loud"]
                and (row["audit"] or {}).get("accepted") is True]
    other_names = [f"{row['fault']} on VM {row['vm']} ({row['session']}): refused with "
                   + ("; ".join(row["received"]) or "no reason") + ", not with " + "; ".join(row["expected"])
                   for row in fault_rows if row["induced"] is True and row["loud"] and not row["named"]]
    shapes = {(row["vm"], row["cycles"]) for row in fault_rows}
    without_clean = sorted(f"VM {vm}, {cycles} cycles" for vm, cycles in shapes if (vm, cycles) not in clean)
    table = [{key: row[key] for key in ("fault", "vm", "session", "expected", "received", "other_reasons", "loud",
                                        "named", "counted")} for row in fault_rows]
    identity = git_identity()
    record = {"schema": FAULTS_TABLE_SCHEMA, "commit": identity["commit"], "commit_dirty": identity["dirty"],
              "date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": platform.platform(),
              "guest": FAULTS_GUEST, "command": command, "n": len(fault_rows),
              "values": {"stage": "G2", "criterion": "live_fault_injections", "needed": FAULTS_NEEDED,
                         "faults": list(faults), "faults_sha256": faults_sha, "vms": vms, "table": table,
                         "sessions": fault_rows, "clean_sessions": [row for row in rows if row["fault"] is None],
                         "shapes_without_clean_session": without_clean, "counts": counts,
                         "minimums_met": not missing, "missing": missing, "absorbed": absorbed,
                         "other_names": other_names, "g2_values": False,
                         "g2_values_note": ("the lead's answer to Q60: a session with an induced fault never counts "
                                            "for the values of G2"), "rule": FAULTS_RULE},
              "note": "The table of the faults injected beside G2 sessions (criterion live_fault_injections of G2): "
                      "expected and received reasons; nothing is scored or detected."}
    text = json.dumps(record, indent=1, ensure_ascii=False, allow_nan=False) + "\n"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        stream = open(out, "x", encoding="utf-8")
    except FileExistsError:
        print(f"campaign_report: --out appeared meanwhile, nothing was overwritten: {out}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"campaign_report: cannot create {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    try:
        with stream:
            stream.write(text)
    except OSError as error:
        out.unlink(missing_ok=True)
        print(f"campaign_report: cannot write {out}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    for fault in faults:
        print(f"{fault}: " + ", ".join(f"VM {vm} {counts[fault][vm]['counted']}/{FAULTS_NEEDED}" for vm in vms))
    print("live_fault_injections minimums: " + ("met" if not missing else "missing: " + "; ".join(missing))
          + f"; {len(absorbed)} absorbed, {len(other_names)} refused with other names", flush=True)
    print(f"campaign_report: faults: {len(rows)} session(s), {len(fault_rows)} with a fault; record {out}",
          file=sys.stderr)
    return 0 if not missing else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = parser.add_subparsers(dest="mode", required=True)
    campaign = modes.add_parser("campaign", help="every planned session of data/campaigns/<id>")
    campaign.add_argument("campaign_dir", type=Path)
    campaign.add_argument("--out", type=Path, required=True, help="new output directory (must not exist)")
    campaign.add_argument("--collections-dir", type=Path,
                          help="session base directory (default: <campaign_dir>/../../collections)")
    campaign.add_argument("--results-dir", type=Path,
                          help="directory of the campaign's ending records kampan_<id>_*.json (package B9b; default: "
                               "<campaign_dir>/../../results, data/results beside data/campaigns)")
    sessions = modes.add_parser("sessions", help="explicit session directories")
    sessions.add_argument("session_dirs", type=Path, nargs="+")
    sessions.add_argument("--out", type=Path, required=True, help="new output directory (must not exist)")
    # Package H1b6b: the tables of map rows 4 to 6 and 14 of G2 (G2T_RECORDS_RULE), their parsers together.
    g2_dir_help = "the G2 directory whose zaznamy/ holds the records of the sessions (default: skuska/g2.py G2_DIR)"
    marked_mode = modes.add_parser("marked", help="the rows the rule marks per occurrence of G2 sessions and the "
                                                  "proposal of invalid_rows.max (criterion marked_rows_per_event, "
                                                  "Q49; MARKED_RULE)")
    marked_mode.add_argument("audits", type=Path, nargs="+",
                             help="the audit records of the G2 sessions (audit_<UTC stamp>.json), one per session")
    marked_mode.add_argument("--protocol", type=Path, required=True,
                             help="the protocol file whose invalid_rows.max the table proposes (the sessions' copies "
                                  "may differ from it only in the values of later stages: its G0 binding)")
    marked_mode.add_argument("--g2-dir", type=Path, help=g2_dir_help)
    marked_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    load_mode = modes.add_parser("load", help="the offered and delivered load of G2 sessions per scenario and VM, the "
                                              "drops and the return to the defined state (criterion profiles_load, "
                                              "Q63; LOAD_RULE)")
    load_mode.add_argument("session_dirs", type=Path, nargs="+", help="G2 session directories")
    load_mode.add_argument("--g2-dir", type=Path, help=g2_dir_help)
    load_mode.add_argument("--final-protocol", type=Path,
                           help="the protocol file with the final caps profiles.*.max_concurrent (the second write of "
                                "G2); without it no drop is judged against the final cap")
    load_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    realism_mode = modes.add_parser("realism", help="the realism requirements of proposal 5.7 over G2 sessions per "
                                                    "scenario and VM, with P1 per protocol (criterion traffic_realism, "
                                                    "Q65; REALISM_RULE)")
    realism_mode.add_argument("session_dirs", type=Path, nargs="+", help="G2 session directories")
    realism_mode.add_argument("--g2-dir", type=Path, help=g2_dir_help)
    realism_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    envelope_mode = modes.add_parser("envelope", help="the traffic envelope of session directories drawn again from "
                                                      "the protocol (the lead's answer to Q30; ENVELOPE_RULE)")
    envelope_mode.add_argument("session_dirs", type=Path, nargs="+")
    envelope_mode.add_argument("--protocol", type=Path, required=True,
                               help="the protocol file the sessions ran with (its sha256 is that of their "
                                    "protocol.json)")
    envelope_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    majflt_mode = modes.add_parser("majflt", help="the bound audit.collector_majflt_max proposed from the audit "
                                                  "records of error-free G2 runs (the lead's answer to Q29; "
                                                  "MAJFLT_RULE)")
    majflt_mode.add_argument("audits", type=Path, nargs="+",
                             help="audit records of collection.py audit (audit_<UTC stamp>.json in each session "
                                  "directory, or its --out), the ones the G2 record names")
    majflt_mode.add_argument("--protocol", type=Path, required=True,
                             help="the protocol file the sessions were audited under (its sha256 is their "
                                  "values.protocol_sha256)")
    majflt_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    timing_mode = modes.add_parser("timing", help="the report of the worst case of time of G2 from the records of "
                                                  "skuska/cas.py (criterion worst_case_timing; TIMING_RULE)")
    timing_mode.add_argument("records", type=Path, nargs="+",
                             help="the G2 session records of the timing sessions (<g2-dir>/zaznamy/<session>.json)")
    timing_mode.add_argument("--others", type=Path, nargs="+", default=[],
                             help="the audit records of the other error-free G2 runs the G2 record names (Q59)")
    timing_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    g2_table_parsers(modes)  # The modes guest, events and restarts (package H1b6a).
    controls_mode = modes.add_parser("controls", help="the table of shifts of the controls of G2 sessions and their "
                                                      "paired negatives (criterion controls_paired; CONTROLS_RULE)")
    controls_mode.add_argument("session_dirs", type=Path, nargs="+",
                               help="G2 session directories with controls (diagnostic runs of skuska/kontroly.py)")
    controls_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    faults_mode = modes.add_parser("faults", help="the table of the faults injected beside G2 sessions (criterion "
                                                  "live_fault_injections; FAULTS_RULE)")
    faults_mode.add_argument("session_dirs", type=Path, nargs="+",
                             help="G2 session directories of the fault plan (skuska/poruchy.py), clean ones included")
    faults_mode.add_argument("--records", type=Path, required=True,
                             help="the injector's records, <G2 directory>/poruchy (<session id>.json each)")
    faults_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    parity_mode = modes.add_parser("parity", help="safeguard watch beside a G2 session against the replay of its "
                                                  "archive (criterion live_archive_parity; skuska/parita.py)")
    parity_mode.add_argument("watch_dir", type=Path, help="the --out of safeguard watch beside the session")
    parity_mode.add_argument("replay_dir", type=Path, help="the --out of safeguard replay --archive of its audit")
    parity_mode.add_argument("--out", type=Path, required=True, help="new JSON record (must not exist)")
    args = parser.parse_args(argv)
    command = shlex.join([str(Path(sys.argv[0])) if argv is None else "scripts/campaign_report.py",
                          *(sys.argv[1:] if argv is None else argv)])
    if args.mode in ("marked", "load", "realism"):  # Package H1b6b: the tables of map rows 4 to 6 and 14 of G2.
        return {"marked": marked_table, "load": load_table, "realism": realism_table}[args.mode](args, command)
    if args.mode == "envelope":
        return envelope(args, command)
    if args.mode == "majflt":
        return majflt(args, command)
    if args.mode == "timing":
        return timing(args, command)
    if args.mode in G2_TABLE_MODES:  # Package H1b6a: guest, events, restarts.
        return G2_TABLE_MODES[args.mode](args, command)
    if args.mode == "controls":
        return controls_table(args, command)
    if args.mode == "faults":
        return faults_table(args, command)
    if args.mode == "parity":
        from skuska.parita import parity_table  # The comparison and the tolerance written before it (Q45).
        return parity_table(args.watch_dir, args.replay_dir, args.out, command)
    out = args.out.absolute()
    if out.exists() or out.is_symlink():
        print(f"campaign_report: output directory already exists: {out}", file=sys.stderr)
        return 2
    roots = ([args.campaign_dir] + ([args.collections_dir] if args.collections_dir else [])
             if args.mode == "campaign" else list(args.session_dirs))
    for root in roots:
        if out.resolve().is_relative_to(Path(root).resolve()):
            print(f"campaign_report: refusing to write the report inside an input directory: {root}",
                  file=sys.stderr)
            return 2
    inputs = Inputs()
    try:
        if args.mode == "campaign":
            report = build_campaign(args.campaign_dir, args.collections_dir, inputs, args.results_dir)
            collections = Path(report["campaign"]["collections_dir"])
            if out.resolve().is_relative_to(collections.resolve()):
                raise DataError(f"refusing to write the report inside the collections directory {collections}")
        else:
            report = build_sessions(args.session_dirs, inputs)
            if not report["sessions"]:
                raise DataError("no readable session directory among the inputs: "
                                + "; ".join(f"{i['input']}: {i['problem']}" for i in inputs.unreadable))
        summary = write_report(out, report, inputs, command)
    except DataError as exc:
        print(f"campaign_report: {exc}", file=sys.stderr)
        return 2
    except FileExistsError as exc:
        if exc.filename and Path(exc.filename).absolute() != out:
            print(f"campaign_report: cannot create the output directory: {exc.filename} exists and is not a "
                  "directory", file=sys.stderr)
        else:
            print(f"campaign_report: output directory already exists: {exc.filename}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"campaign_report: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    counts = {k: v["count"] for k, v in summary["sessions"]["by_status"].items() if v["count"]}
    print(json.dumps({"report": str(out), "sessions": counts,
                      "unreadable_inputs": len(summary["inputs_unreadable"])}))
    for item in summary["inputs_unreadable"]:
        print(f"campaign_report: unreadable input {item['input']}: {item['problem']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
