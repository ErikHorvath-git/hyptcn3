#!/usr/bin/env python3
"""Traceable report over benign collection sessions or a whole campaign.

  .venv/bin/python scripts/campaign_report.py campaign data/campaigns/<id> --out NEW_DIR
  .venv/bin/python scripts/campaign_report.py sessions SESSION [SESSION ...] --out NEW_DIR

The report reads saved evidence only: session, end, audit and archive
metadata, the request and interval logs, the host monitor, snapshot sidecars
and campaign events. It never opens RAM images, never decompresses archived
members and never writes into its inputs. Every value is copied or computed
from a file listed with its SHA-256 (sources.csv, summary.json); absent
evidence becomes null with a stated reason (column `missing`; fields that do
not apply to a session are explained in `not_applicable`), never an estimate.
NEW_DIR must not exist. Exit 0 = report written, 2 = usage or data error.

A reporting tool, not part of capture, audit or archival (collection.py lists
it in NOT_MEASUREMENT). Only the standard library and NumPy are used; plots
are hand-written SVG.
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
import re
import shlex
import subprocess
import sys
from xml.sax.saxutils import escape

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import host_monitor, traffic_log  # noqa: E402  (log schemas and monitor window statistics of the audit)

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
GATE_DEFAULT = .85  # collection.protocol() uses this when a protocol has no min_score_coverage.
PENDING_RAW = ".raw.pending-reclaim"  # collection_archive.PENDING: raw/ renamed, link not yet created
POST_MARKER = "generator 'post' marker"
RUNNER_END = "end.json measure_end_unix (runner; the generator wrote no 'post' marker)"
USABLE = "accepted_without_superseded_marker"
# campaign.retire_attempt: <session>.attempt-<n> directories and attempts/<session>.attempt-<n>.json records.
RETIRED_DIR = re.compile(r"(?P<sid>[a-zA-Z0-9][a-zA-Z0-9_-]{0,159})\.attempt-(?P<n>[0-9]+)")
ATTEMPT_RECORD = re.compile(r"(?P<sid>[a-zA-Z0-9][a-zA-Z0-9_-]{0,159})\.attempt-(?P<n>[0-9]+)\.json")
# campaign.take_stop_request and execute move operator stop requests into events/ under these suffixes.
STOP_REQUEST_SUFFIXES = ("_stop-request.json", "_stop-request-stale.json")

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
    "index", "plot_label", "session_id", "campaign_id", "role", "group", "group_attempt", "scenario", "seed",
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
EVENT_COLUMNS = ("time_utc", "status", "stage", "session", "group", "position", "message", "duration_to_next_s",
                 "attributed_to", "file")
ROUTE_COLUMNS = ("session_id", "route", "requests", "ok", "errors", "share_of_measure_requests")
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


def set_gate(s, protocol):
    gate = number((protocol or {}).get("min_score_coverage"))
    s.row["score_gate"] = gate if gate is not None else GATE_DEFAULT
    if gate is None:
        s.notes.append("score_gate: collection.py default 0.85 (no protocol min_score_coverage)")


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
    for key in ("role", "group", "scenario", "seed", "session_id"):
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
    for key in ("role", "group", "scenario", "seed"):
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
        if path.name.endswith(STOP_REQUEST_SUFFIXES):
            stale = path.name.endswith(STOP_REQUEST_SUFFIXES[1])
            try:
                doc = inputs.read_json(path, "campaign_stop_request", None)
            except (OSError, ValueError) as exc:
                inputs.problem(path, f"stop request unreadable: {exc}")
                doc = {}
            requests.append({"file": path.name, "requested_utc": doc.get("date") if isinstance(doc.get("date"), str)
                             else None, "honored": not stale,
                             "note": ("set aside when a later run started (meant for an earlier run)" if stale
                                      else "honored: the runner stopped before its next capture")})
            continue
        try:
            doc = inputs.read_json(path, "campaign_event", None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"campaign event unreadable: {exc}")
            continue
        events.append({"file": path.name, "time": unix_of(doc.get("updated_at")), "status": doc.get("status"),
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
    if status == "ready":
        return "before_first_launch"
    if status == "complete":
        return "after_complete"
    if status == "closed":
        return "after_close"
    return {"preflight": "preflight", "session-preflight": "preflight", "reboot": "reboot",
            "capture": "capture_stage", "audit": "audit", "archive": "archive",
            "session-complete": "between_sessions", "index": "index",
            "retry": "retry_pause"}.get(stage, f"other:{stage}")


def campaign_time(events):
    timed = [e for e in events if e["time"] is not None]
    by_category, intervals = Counter(), []
    for first, second in zip(timed, timed[1:]):
        category = ("unaccounted" if second["status"] == "stopped" and second["stage"] == "unclean-end"
                    else stage_category(first))
        duration = second["time"] - first["time"]
        first["duration_to_next_s"], first["attributed_to"] = r6(duration), category
        by_category[category] += duration
        intervals.append((first["time"], second["time"], category))
    if not timed:
        return None, intervals
    span = timed[-1]["time"] - timed[0]["time"]
    doc = {"events": len(events), "events_with_time": len(timed), "first_event_utc": utc(timed[0]["time"]),
           "last_event_utc": utc(timed[-1]["time"]), "last_status": timed[-1]["status"],
           "last_stage": timed[-1]["stage"], "wall_clock_span_s": r6(span), "wall_clock_span_h": r6(span / 3600),
           "by_category_s": {k: r6(v) for k, v in sorted(by_category.items())},
           "sum_of_categories_s": r6(math.fsum(by_category.values())),
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


def build_campaign(directory, collections, inputs):
    directory = directory.absolute()
    try:
        manifest = inputs.read_json(directory / "campaign.json", "campaign", None)
    except (OSError, ValueError) as exc:
        raise DataError(f"cannot read campaign.json in {directory}: {exc}") from exc
    rows = plan_rows(manifest)
    collections = (collections or directory.parent.parent / "collections").absolute()
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
    for key in ("guest_environment", "extractor_sha256"):
        if key not in manifest:
            problems.append(f"campaign.json has no {key}: that campaign provenance check is skipped")
    state = optional("status.json", "campaign_status")
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
    groups, group_docs = [], {}
    for path in sorted((directory / "groups").glob("*.json")):
        try:
            doc = inputs.read_json(path, "campaign_group", None)
        except (OSError, ValueError) as exc:
            inputs.problem(path, f"campaign group record unreadable: {exc}")
            continue
        if doc.get("schema") == "hyptcn3/campaign-group/1":
            group_docs[doc.get("group")] = doc
            groups.append({"group": doc.get("group"), "role": doc.get("role"), "date": doc.get("date"),
                           "boot_id": dig(doc, "identity", "boot_id"),
                           "previous_boot": doc.get("previous_boot"), "file": path.name})
    archive_dir = Path(manifest["archive_dir"]) if isinstance(manifest.get("archive_dir"), str) else None
    sessions = []
    for position, plan_row in enumerate(rows, 1):
        sid = plan_row["session_id"]
        if (collections / sid).is_dir():
            ctx = {"manifest": manifest, "plan_row": plan_row, "protocol": protocol, "state": state,
                   "groups": group_docs, "pointer": directory / "attempts" / f"{sid}.audit.json",
                   "done": directory / "attempts" / f"{sid}.done.json",
                   "archive_fallback": archive_dir / "collections" / sid if archive_dir else None}
            s = read_session(collections / sid, inputs, ctx)
        else:
            s = planned_session(sid, collections / sid, plan_row, state, protocol)
        s.index = position
        sessions.append(s)
    problems += attempt_problems(directory, collections, rows, state, sessions)
    retired, retired_problems = retired_attempts(directory, collections, rows, inputs)
    problems += retired_problems
    time_doc, intervals = campaign_time(events)
    campaign = {"id": manifest.get("id"), "directory": str(directory), "collections_dir": str(collections),
                "archive_dir": manifest.get("archive_dir"), "commit": manifest.get("commit"),
                "protocol_sha256": manifest.get("protocol_sha256"),
                "planned_capture_hours": manifest.get("planned_capture_hours"),
                "planned_capture_hours_source": "campaign.json planned_capture_hours (design allocation)",
                "status": state, "closed": closed, "stop_requests": stop_requests,
                "stop_request_pending": (directory / "stop-request.json").exists(),
                "groups": groups, "problems": problems}
    return {"mode": "campaign", "campaign": campaign, "sessions": sessions, "events": events,
            "campaign_time": time_doc, "stage_intervals": intervals, "protocol": protocol, "plan_rows": rows,
            "retired_attempts": retired}


def attempt_problems(directory, collections, rows, state, sessions):
    """Campaign records that name sessions whose directory is absent (a moved or lost session)."""
    problems, planned = [], {row["session_id"] for row in rows}
    for path in sorted((directory / "attempts").glob("*.json")):
        if ATTEMPT_RECORD.fullmatch(path.name):
            continue  # retired_attempts()
        suffix = next((x for x in (".done.json", ".audit.json") if path.name.endswith(x)), None)
        sid = path.name[:-len(suffix)] if suffix else None
        if sid is None:
            problems.append(f"attempts/{path.name}: not a .done.json or .audit.json record")
        elif sid not in planned:
            problems.append(f"attempts/{path.name} names a session that is not in the plan")
        elif not (collections / sid).is_dir():
            problems.append(f"attempts/{path.name} exists, but the session directory {collections / sid} is absent")
    if isinstance(state, dict):
        named = state.get("session")
        if isinstance(named, str) and named and not (collections / named).is_dir() and not running_on(state, named):
            problems.append(f"status.json (status {state.get('status')}) names session {named}, whose directory "
                            "is absent")
        archived = state.get("accepted_archived")
        done = sum(1 for s in sessions if s.row["campaign_done"] is True)
        if type(archived) is int and archived != done:
            problems.append(f"status.json accepted_archived = {archived}, but {done} session directories have a "
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


def retired_attempts(directory, collections, rows, inputs):
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
    for path in sorted(collections.iterdir()):
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
    planned = len(sessions) if campaign else None
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
        "per_scenario": per_scenario,
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
             ("reboot", "runner: reboot"), ("preflight", "runner: preflight"),
             ("between_sessions", "runner: between sessions"), ("stopped", "runner: stopped"),
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
        if c["stop_requests"] or c["stop_request_pending"]:
            honored = sum(r["honored"] for r in c["stop_requests"])
            lines += [f"Operator stop requests: {honored} honored, {len(c['stop_requests']) - honored} set aside as "
                      "stale" + ("; one is pending in stop-request.json" if c["stop_request_pending"] else "")
                      + ".", ""]
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = parser.add_subparsers(dest="mode", required=True)
    campaign = modes.add_parser("campaign", help="every planned session of data/campaigns/<id>")
    campaign.add_argument("campaign_dir", type=Path)
    campaign.add_argument("--out", type=Path, required=True, help="new output directory (must not exist)")
    campaign.add_argument("--collections-dir", type=Path,
                          help="session base directory (default: <campaign_dir>/../../collections)")
    sessions = modes.add_parser("sessions", help="explicit session directories")
    sessions.add_argument("session_dirs", type=Path, nargs="+")
    sessions.add_argument("--out", type=Path, required=True, help="new output directory (must not exist)")
    args = parser.parse_args(argv)
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
    command = shlex.join([str(Path(sys.argv[0])) if argv is None else "scripts/campaign_report.py",
                          *(sys.argv[1:] if argv is None else argv)])
    inputs = Inputs()
    try:
        if args.mode == "campaign":
            report = build_campaign(args.campaign_dir, args.collections_dir, inputs)
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
