#!/usr/bin/env python3
"""Offline evidence audit for managed VM sessions; no guest access or RAM parsing.

python3 scripts/collection_logs.py SESSION [--out NEW.json]
Exit 0 = evidence checks passed, 2 = rejected/incomplete evidence. This verdict
does not admit a session to training: collection.py also checks RAM and features.

The bounds come from the session's own protocol.json (features/audit_policy.py audit_bounds; the metadata
section checks its hash). Every key a check reads is mandatory: a missing one fails that check (or its section),
it never passes on a default. Each condition the audit admits instead of rejecting counts one registered
exception (features/audit_policy.py tolerate); result["tolerated"] holds the counts of LOG_EXCEPTIONS.

Under a schema-3 protocol with the profiles section (protocol v5, package B5b) the traffic logs are those of the
open-loop profiles (scripts/traffic_log.py schemas /2): their header is compared with the protocol and
session.json, a request with an intended client error passes outside the event windows only with exactly that
status (every other request still must be 2xx), the generator's exit code must be the one its request log implies,
nginx and the services are correlated for every route of lab/nginx.conf with the internal calls of
lab/services.py, and the section "realism" refuses a session that misses a realism requirement of proposal 5.7
(traffic_realism:<name>) or whose offered load differs from the plan (proposal 5.3).

A session of role test_controls (package B8, design B8 section 1.4) keeps its controls in controls.json. The
section "controls" reads only the three predicates the guest computed for each occurrence (baseline, effect,
cleanup) and whether it ran: the sealed role, no feature is read (skeleton B8 section 4). The guest's health polls
without a request id are admitted inside a control's start and stop calls, as inside an event window; nothing
else is (a control is benign and inert: the service answers as outside every window). The reason names the cause
(finding S1 of the B8 verification, package B10): a negative whose property is seen is negative_with_property, one
whose predicate fails otherwise negative_not_in_place (NEGATIVE_PROPERTY), and an occurrence whose start the return
predicate refused started nothing, so the effect and the cleanup of its stop are not its own.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.audit_policy import audit_bounds, tolerate
from scripts import host_monitor, traffic_log
from scripts.protocol_v5 import (CONTROL_RECORD_CLASS, CONTROL_ROLE, CONTROLS_SCHEMA, SCHEMA as SCHEMA_3,
                                 plans_events)

SCHEMA = "hyptcn3/collection-logs-audit/1"
REQUIRED = ("preflight_smoke.json", "host_monitor.jsonl", "host_monitor.log", "traffic.json", "traffic.log",
            "traffic_before.json", "traffic_requests.jsonl", "traffic_intervals.jsonl", "capture.log",
            "protocol.json", "domain.xml", "guest/state_before.json", "guest/state_after.json",
            "guest/clock_before.json", "guest/clock_after.json", "guest/pre_segment.json",
            "guest/session_segment.json", "guest/journal_segment.json")
SERVICE_LINE = re.compile(r"python3\[(\d+)\]: .*request rid=(\S+) method=(\S+) path=(\S+) status=(\d+)\s*$")
REQUIRED_UNITS = ("nginx", "postgresql@15-main", "hyptcn-lab@auth", "hyptcn-lab@catalog",
                  "hyptcn-lab@orders", "hyptcn-lab@docs", "hyptcn-lab@worker", "systemd-journald")
APPS = ("hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@docs", "hyptcn-lab@worker")
SERVICES = ("auth", "catalog", "orders", "docs")  # The HTTP services of lab/services.py PORTS.
# lab/nginx.conf: the service a route reaches, None where nginx answers alone (/, /static/ and every other path).
# The exact locations first, else the longest prefix, as nginx chooses.
NGINX_EXACT = {"/": None, "/healthz": "orders", "/api/orders": "orders", "/api/cart": "orders"}
NGINX_PREFIX = (("/api/catalog", "catalog"), ("/api/auth/", "auth"), ("/api/docs", "docs"), ("/api/reports", "docs"),
                ("/static/", None), ("/", None))
# Units a protocol-v3 event restarts by design (lab/udalosti.py); any other restart stays a problem.
EVENT_UNITS = {"zla_konfiguracia_sluzby": ("hyptcn-lab@catalog",), "restart_sluzby": ("hyptcn-lab@orders",),
               "restart_databazy": ("postgresql@15-main", *APPS)}
# zamok_tabulky restarts nothing: the worker reports the statement timeout and tries again
# (lab/services.py). Its journal line is admitted only inside an event window, like a traceback.
WORKER_ERROR = "worker dependency error: "
NGINX_TIME = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) ")
# vmicollect/src/log.c, text format: "<UTC time with milliseconds>Z <level padded to 5> <message>"; with log.json
# one object {"ts", "level", "msg"} per line.
COLLECTOR_TEXT = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z (DEBUG|INFO |WARN |ERROR) (.*)$")
SHA256 = re.compile(r"[0-9a-f]{64}")
# The exceptions of features/audit_policy.py TOLERATED that this audit admits, in result["tolerated"].
LOG_EXCEPTIONS = ("collector_warnings", "event_traffic_exit", "event_unit_restarts", "event_window_requests",
                  "event_window_health_checks", "event_window_journal", "event_window_nginx_errors")
# The host times of a control's record (scripts/collection.py Controls): its start call, then its stop call.
CONTROL_CALLS = (("host_start_unix", "host_started_unix"), ("host_stop_unix", "host_stopped_unix"))
# A call's window reaches this far beyond its host times: the guest clock may differ from the host's by up to 1 s
# (the bound of guest_clock below), and nginx stamps the guest's polls with the guest's time (executor's judgment,
# the margin an event window has before its start).
CALL_MARGIN_S = 1.0
# The conditions of the paired negative of each control kind that the anomalous property breaks (the negative
# predicates of lab/udalosti.py, effect.evidence.failed; lab/tests/test_kontroly.py checks that the names are the
# guest's): a failed one is the property seen, negative_with_property; any other failed condition, or none named, is a
# negative not in place as designed (its process tree, its program or its state), negative_not_in_place (finding S1 of
# the B8 verification, package B10).
NEGATIVE_PROPERTY = {
    "kontrola_wx_memfd": ("no process of it holds an rwx mapping", "no process of it holds a memfd"),
    "kontrola_modul_jadra": ("the module is not loaded",),
    "kontrola_pocuvajuci_soket": ("nothing listens on the port",),
    "kontrola_zapisovac_pamate": ("no later round rewrote it",),
    "kontrola_davka_procesov": ("it started no process besides the long child",)}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def upstream(route):
    """The service of lab/services.py that nginx passes a request of this route to; None when nginx answers it."""
    if route in NGINX_EXACT:
        return NGINX_EXACT[route]
    return max((item for item in NGINX_PREFIX if route.startswith(item[0])), key=lambda item: len(item[0]))[1]


def auth_checked(method, route):
    """Whether the service answers this request only after it asked auth about the token (lab/services.py: orders
    for /api/orders and /api/cart, docs for every document and report route it serves)."""
    if route in ("/api/orders", "/api/cart", "/api/docs"):
        return method in ("GET", "POST")
    if route.startswith("/api/docs/") or route.startswith("/api/reports/"):
        return method == "GET"
    return route == "/api/reports" and method == "POST"


def unix(value):
    time = datetime.fromisoformat(value)
    if time.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return time.timestamp()


def finite(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("non-finite or non-numeric measurement")
    return value


def event_window(record, grace_s):
    """The event window of one occurrence of a session's events.json, protocol v3: [host_start_unix - 1 s,
    host_stopped_unix + grace_s], grace_s the session's event_grace_s (events.grace_s of its protocol). The log audit
    admits the evidence of the event in it (events below), and the count of the marked rows of the early stop takes
    the same window (scripts/collection.py marked_rows_record, package B9b, F8 of its verification), so the two cannot
    drift. None for an occurrence without its host start or without its host stop done: the log audit names it
    (event_not_started, event_not_stopped) and windows nothing. A time or a grace that is no finite number is
    refused (finite)."""
    if "host_start_unix" not in record or "host_stopped_unix" not in record:
        return None
    return finite(record["host_start_unix"]) - 1, finite(record["host_stopped_unix"]) + finite(grace_s)


def local_file(directory, name, raw_target=None):
    """An evidence file of the session directory; ValueError when its path escapes the directory. raw_target: where
    the session's raw/ link points when the caller reads evidence through it (audit_logs archived_raw), the only
    place outside the directory a member under raw/ may then lie."""
    path = directory / name
    inside = isinstance(name, str) and path.resolve().is_relative_to(
        raw_target if raw_target is not None and Path(name).parts[:1] == ("raw",) else directory.resolve())
    if (not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts
            or not inside or path.is_symlink()):
        raise ValueError("evidence path escapes session: " + str(name))
    return path


def read_json(path):
    doc = json.loads(path.read_text())
    if not isinstance(doc, dict):
        raise ValueError("expected JSON object: " + str(path))
    return doc


def collector_line(line):
    """(level, message) of one collect.log line in either format of vmicollect/src/log.c; (None, line) otherwise."""
    if line.startswith("{"):
        try:
            doc = json.loads(line)
        except ValueError:
            doc = None
        if type(doc) is dict and type(doc.get("level")) is str and type(doc.get("msg")) is str:
            return doc["level"], doc["msg"]
        return None, line
    match = COLLECTOR_TEXT.match(line)
    return (match[1].strip(), match[2]) if match else (None, line)


def qemu_unswapped(sample):
    """The session VM's QEMU (label qemu in both layouts of collection.monitor_matches) is in this host monitor
    sample and none of its processes has swapped memory; a sample without it proves nothing."""
    procs = sample.get("procs")
    entries = procs.get("qemu") if type(procs) is dict else None
    return (type(entries) is list and bool(entries)
            and all(type(e) is dict and type(e.get("swap_kb")) is int and e["swap_kb"] == 0 for e in entries))


def audit_logs(directory, *, snapshot_times=(), archived_raw=False):
    """The log audit of a session directory. archived_raw: the session's raw/ is the link scripts/collection_archive.py
    reclaim_raw leaves to the verified archive copy, and the evidence under raw/ is read through it (the repeat of
    features/quality.py require_log_audit while the archive is attached, finding S9 of B3, package B9a); the audit of
    a capture never passes it, so there a raw/ that leads out of the session is refused as before."""
    directory = Path(directory).resolve()
    raw_target = (directory / "raw").resolve() if archived_raw and (directory / "raw").is_symlink() else None
    problems = traffic_log.Problems()
    result = {"schema": SCHEMA, "session_dir": str(directory), "sections": {}}
    # Protocol v3: [host start - 1 s, host stop done + grace] of each event. Failures inside a window
    # are expected evidence of the event; outside every window the checks stay as strict as in v2.
    windows, event_types, known_pids = [], [], {}
    # Package B8: [host start - 1 s, host done + 1 s] of each start and stop call of a control; only the guest's
    # health polls without a request id are admitted there (lab/udalosti.py polls them in every control call).
    calls = []
    # Requests inside an event window: one exception each, counted in traffic(); traffic() and correlation()
    # relax their checks for exactly these.
    during = set()
    counts = Counter()  # Exceptions admitted, by id of features/audit_policy.py TOLERATED.
    # The session's protocol and its audit bounds (None: schema 1 or 2). Until protocol.json has been read the
    # bounds are unknown and admit nothing. v5: a schema-3 protocol with the profiles section, whose sessions run
    # the open-loop profiles (traffic logs /2).
    protocol, limits, limits_read, v5 = {}, None, False, False

    def in_window(*times):
        return any(lo <= t <= hi for t in times for lo, hi in windows)

    def in_call(*times):
        return any(lo <= t <= hi for t in times for lo, hi in calls)

    def check(condition, key, detail=None):
        if not condition:
            problems.add(key, detail)

    def section(name, function):
        # Malformed evidence rejects that section, but still checks the others.
        try:
            value = function()
            json.dumps(value, allow_nan=False)
            result["sections"][name] = value
        except (OSError, EOFError, ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as exc:
            problems.add(name + ":unreadable", f"{type(exc).__name__}: {exc}")

    def read_bounds():
        nonlocal protocol, limits, limits_read, v5
        protocol = read_json(directory / "protocol.json")
        v5 = protocol.get("schema") == SCHEMA_3 and "profiles" in protocol
        limits, limits_read = audit_bounds(protocol), True
        return limits

    def metadata():
        meta = read_json(directory / "session.json")
        end = read_json(directory / "end.json")
        check(meta.get("schema") == "hyptcn3/collection-session/2", "session_schema")
        check(end.get("schema") == "hyptcn3/collection-end/2", "end_schema")
        check(meta.get("session_id") == directory.name, "session_identity")
        # capture_session writes "interrupted" always and "error" only when the capture failed.
        check(end.get("completed") is True and end.get("interrupted") is False and "error" not in end,
              "incomplete_capture")
        check("guest_after" in end and "guest_before" in meta and end["guest_after"] == meta["guest_before"],
              "guest_identity_changed")
        for name in ("collector", "traffic", "monitor"):
            rc = end.get(name + "_rc", end.get(name, {}).get("rc"))
            if name == "traffic" and v5:
                # Under v5 host_traffic.py exits 1 when a request did not get its expected result (a 2xx, or the
                # status a deliberate client error intends, proposal 5.3) or no request succeeded, so the code must
                # be the one its request log implies; traffic() judges every such request (inside an event window
                # it is admitted, elsewhere refused).
                logged = traffic_log.read_jsonl(directory / "traffic_requests.jsonl")[0]
                rows = [r for r in logged if r.get("type") == "request"]
                unexpected = [r for r in rows if (r.get("outcome") != "ok" if r.get("intended_status") is None
                                                  else r.get("status") != r.get("intended_status"))]
                implied = 0 if rows and not unexpected and any(r.get("outcome") == "ok" for r in rows) else 1
                check(type(rc) is int and rc == implied, "child_exit", f"{name}:{rc}")
                continue
            # host_traffic exits 1 after any failed request; outside the event windows those still fail below.
            if name == "traffic" and type(rc) is int and rc == 1 and meta.get("events"):
                tolerate(counts, "event_traffic_exit")
                continue
            check(type(rc) is int and rc == 0, "child_exit", f"{name}:{rc}")
        start, stop = finite(end["measure_start_unix"]), finite(end["measure_end_unix"])
        check(start < stop, "invalid_measure_interval")
        check(all(start <= finite(t) <= stop for t in snapshot_times), "snapshot_outside_measure")
        check(digest(directory / "protocol.json") == meta.get("protocol_sha256"), "protocol_hash")
        return {"session_sha256": digest(directory / "session.json"), "end_sha256": digest(directory / "end.json"),
                "measure_start_unix": start, "measure_end_unix": stop}

    def manifest():
        doc = read_json(directory / "logs_manifest.json")
        end = read_json(directory / "end.json")
        check(doc.get("schema") == "hyptcn3/session-logs/1", "logs_manifest_schema")
        check(digest(directory / "logs_manifest.json") == end.get("logs_manifest_sha256"), "logs_manifest_hash")
        files = doc["files"]
        for name in REQUIRED:
            check(name in files, "missing_manifest_entry", name)
            check(local_file(directory, name).is_file(), "missing_evidence", name)
        verified = 0
        for name, expected in files.items():
            try:
                path = local_file(directory, name, raw_target)
                check(path.stat().st_size == expected["size"] and digest(path) == expected["sha256"],
                      "evidence_hash", name)
                # write_logs_manifest records lines and termination of every .jsonl and .log file.
                if name.endswith((".jsonl", ".log")) or "lines" in expected or "terminated" in expected:
                    data = path.read_bytes()
                    check(data.count(b"\n") == expected.get("lines") and (not data or data.endswith(b"\n"))
                          == expected.get("terminated"), "evidence_lines", name)
                    check(not data or data.endswith(b"\n"), "torn_evidence", name)
                verified += 1
            except (OSError, ValueError, KeyError, TypeError) as exc:
                problems.add("evidence_unreadable", f"{name}:{exc}")
        return {"files_checked": verified, "sha256": digest(directory / "logs_manifest.json")}

    def guest():
        meta = read_json(directory / "session.json")
        before, after = (read_json(directory / "guest" / f"state_{when}.json") for when in ("before", "after"))
        for when, state in (("before", before), ("after", after)):
            check(state.get("schema") == "hyptcn3/guest-state/1", "guest_state_schema", when)
            check(state["boot_id"] == meta["guest_before"]["boot_id"], "guest_boot_changed", when)
            check(state["kernel"] == meta["guest_before"]["kernel"], "guest_kernel_changed", when)
            for unit in REQUIRED_UNITS:
                current = state["units"].get(unit, {})
                check(current.get("ActiveState") == "active" and current.get("Result") == "success",
                      "service_unhealthy", f"{when}:{unit}")
            clock = read_json(directory / "guest" / f"clock_{when}.json")
            check(abs(finite(clock["offset_s"])) <= 1.0 and 0 <= finite(clock["uncertainty_s"]) <= 1.0,
                  "guest_clock", when)
        restarted = {unit for kind in event_types for unit in EVENT_UNITS.get(kind, ())}
        for unit in REQUIRED_UNITS:
            if unit in restarted:
                tolerate(counts, "event_unit_restarts")
                continue
            a, b = before["units"].get(unit, {}), after["units"].get(unit, {})
            check(all(k in a and k in b and a[k] == b[k] for k in
                      ("NRestarts", "InvocationID", "ExecMainPID", "ExecMainStartTimestampMonotonic")),
                  "service_restarted", unit)
        for name in SERVICES:
            unit = "hyptcn-lab@" + name
            known_pids.setdefault(name, set()).update(str(state["units"][unit]["ExecMainPID"]) for state in (before, after))
        return {"boot_id": after["boot_id"], "database_before": before["database"],
                "database_after": after["database"], "units_checked": [u for u in REQUIRED_UNITS if u not in restarted]}

    def segments():
        files, counts = {}, {}
        for name, schema in (("pre", "hyptcn3/guest-log-segment/1"),
                             ("session", "hyptcn3/guest-log-segment/1"),
                             ("journal", "hyptcn3/guest-journal-segment/1")):
            doc = read_json(directory / "guest" / (name + "_segment.json"))
            check(doc.get("schema") == schema, "segment_schema", name)
            expected_suffixes = ("journal.txt",) if name == "journal" else ("nginx-access.jsonl", "nginx-error.log")
            for suffix in expected_suffixes:
                check(sum(entry["name"].endswith("-" + suffix) for entry in doc["files"]) == 1,
                      "segment_file_missing_or_duplicate", f"{name}:{suffix}")
            for entry in doc["files"]:
                path = local_file(directory, "guest/" + entry["file"])
                check(digest(path) == entry["gz_sha256"] == entry["file_sha256"] and
                      path.stat().st_size == entry["gz_bytes"], "segment_compressed_hash", entry["file"])
                with gzip.open(path, "rb") as stream:
                    content = stream.read()
                check(len(content) == entry["bytes"] and hashlib.sha256(content).hexdigest() == entry["sha256"],
                      "segment_content_hash", entry["file"])
                check(content.count(b"\n") == entry["lines"] and (not content or content.endswith(b"\n"))
                      and entry["terminated"] is True, "segment_lines", entry["file"])
                suffix = next((suffix for suffix in expected_suffixes if entry["name"].endswith("-" + suffix)), None)
                if suffix:
                    files[name + ":" + suffix] = content.decode("utf-8")
                counts[entry["file"]] = entry["lines"]
        return files, counts

    def traffic():
        nonlocal requests
        meta, end = read_json(directory / "session.json"), read_json(directory / "end.json")
        records, _ = traffic_log.read_jsonl(directory / "traffic_requests.jsonl")
        requests = [r for r in records if r.get("type") == "request"]
        # The protocol decides the schema (/2 for the v5 profiles, /1 otherwise); summarize refuses the other one.
        schema = traffic_log.REQUEST_SCHEMA_2 if v5 else traffic_log.REQUEST_SCHEMA
        summary = traffic_log.summarize(directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl",
                                        session_id=directory.name, schema=schema)
        for problem in summary["problems"]:
            problems.add("traffic", problem)
        header = records[0]
        intervals, _ = traffic_log.read_jsonl(directory / "traffic_intervals.jsonl")
        check("config" in header and "start_unix" in header and intervals[0].get("config") == header["config"]
              and intervals[0].get("start_unix") == header["start_unix"], "traffic_headers_disagree")
        phase_fields = lambda rows: [{k: v for k, v in r.items() if k not in ("schema", "n")}
                                     for r in rows if r.get("type") == "phase"]
        check(phase_fields(records) == phase_fields(intervals), "traffic_phase_times_disagree")
        if v5:
            # The generator's header against the protocol and session.json (design B5b 1.3 and 1.4): the scenario
            # with its profile, intensity and rate (from the protocol, or from the command line where the protocol
            # has none), the session's traffic seed, the protocol it read, the profile's parameters verbatim, the
            # warmup, and the target, summary interval and initial phase of every collection run.
            s = protocol["scenarios"].get(meta["scenario"], {})
            config, run, seeds, rate = header["config"], meta["traffic"], header.get("seeds"), s.get("rate")
            parameters = header.get("profile_parameters")
            fields = {
                "profile": header.get("profile") == s.get("profile"),
                "scenario": header.get("scenario") == meta["scenario"],
                "intensity": header.get("intensity") == s.get("intensity"),
                "rate": (header.get("rate_source") == "protocol" and header.get("rate") == rate) if rate is not None
                else (header.get("rate_source") == "command line" and type(header.get("rate")) in (int, float)
                      and header["rate"] > 0),
                "seeds": type(seeds) is dict and type(seeds.get("traffic")) is int
                and seeds["traffic"] == meta["seed"],
                "protocol_sha256": type(header.get("protocol_sha256")) is str
                and header["protocol_sha256"] == meta.get("protocol_sha256"),
                "profile_parameters": type(parameters) is dict
                and parameters == protocol["profiles"].get(s.get("profile")),
                "warmup_s": header.get("warmup_s") == protocol["warmup_s"],
                "target": config.get("target") == run["target"],
                "summary_interval_s": config.get("summary_interval_s") == run["summary_interval_s"],
                "initial_phase": config.get("initial_phase") == "warmup"}
            for key, good in fields.items():
                check(good, "traffic_config", key)
        else:
            expected = dict(meta["traffic"], seed=meta["seed"], initial_phase="warmup")
            for key in ("target", "profile", "seed", "workers", "burst", "catalog_share", "write_share",
                        "summary_interval_s", "initial_phase"):
                check(key in header["config"] and header["config"][key] == expected[key], "traffic_config", key)
        check([m["phase"] for m in summary["phase_markers"]] == ["measure", "post"], "traffic_phases")
        bounds = {m["phase"]: unix(m["t_utc"]) for m in summary["phase_markers"]}
        check(abs(bounds["measure"] - finite(end["measure_start_unix"])) <= 1 and
              abs(bounds["post"] - finite(end["measure_end_unix"])) <= 1, "traffic_measure_bounds")
        check(all(bounds["measure"] <= t <= bounds["post"] for t in snapshot_times), "traffic_snapshot_coverage")
        reqs = requests
        for row in reqs:
            check(row.get("session_id") == directory.name and row.get("run_id") == header["run_id"],
                  "request_identity", row.get("rid"))
            check(isinstance(row.get("rid"), str) and bool(row["rid"]), "request_id_missing")
            check(0 <= finite(row["t_start_mono"]) <= finite(row["t_end_mono"]) and finite(row["duration_ms"]) >= 0,
                  "request_timing", row.get("rid"))
            check(unix(row["t_start_utc"]) <= unix(row["t_end_utc"]), "request_wall_clock", row.get("rid"))
            if in_window(unix(row["t_start_utc"]), unix(row["t_end_utc"])):
                tolerate(counts, "event_window_requests")  # May fail; nginx and services are not correlated.
                during.add(row.get("rid"))
                continue
            if v5 and row.get("intended_status") is not None:
                # A deliberate client error of the v5 profiles (proposal 5.3) passes only with its own status; the
                # success rate is a realism requirement (section realism), not a rule per request.
                check(row.get("status") == row["intended_status"], "intended_status_differs", row.get("rid"))
                continue
            check(row["outcome"] == "ok" and type(row["status"]) is int and 200 <= row["status"] < 300,
                  "request_failed", row.get("rid"))
        status = read_json(directory / "traffic.json")
        before = read_json(directory / "traffic_before.json")
        # host_traffic.py writes both fields in every status: logging_error null, worker_errors 0 when clean.
        check(status.get("final") is True and "logging_error" in status and not status["logging_error"]
              and status.get("worker_errors") == 0, "traffic_status_incomplete")
        check(status.get("session_id") == directory.name and status.get("run_id") == header["run_id"] and
              before.get("run_id") == header["run_id"] and before["started_at"] == status["started_at"],
              "traffic_status_identity")
        check(status["requests"] == status["requests_logged"] == len(reqs) and
              status["ok"] == sum(r["outcome"] == "ok" for r in reqs) and
              status["errors"] == sum(r["outcome"] != "ok" for r in reqs), "traffic_status_counts")
        return summary, reqs

    def correlation(contents, requests):
        expected = {r["rid"]: r for r in requests}
        matched, tolerated = Counter(), Counter()
        for line in contents["session:nginx-access.jsonl"].splitlines():
            row = json.loads(line)
            check(row.get("schema") == "hyptcn3/nginx-access/1", "nginx_schema")
            rid = row["rid"]
            if (rid == "" and row["method"] == "GET" and row["uri"] == "/healthz"
                    and (in_window(finite(row["msec"])) or in_call(finite(row["msec"])))):
                # lab/udalosti.py polls health with no request id, in an event and in a control's call.
                tolerated["event_health_checks" if in_window(row["msec"]) else "control_health_checks"] += 1
                tolerate(counts, "event_window_health_checks")
                continue
            if rid not in expected:
                problems.add("nginx_unknown_request", rid)
                continue
            req = expected[rid]
            matched[rid] += 1
            if rid in during:
                continue  # A client timeout leaves nginx 499 and a late timestamp.
            check(row["forwarded_rid"] == rid and row["status"] == req["status"] and
                  row["method"] == req["method"] and row["uri"] == req["route"], "nginx_mismatch", rid)
            check(unix(req["t_start_utc"]) - 1 <= finite(row["msec"]) <= unix(req["t_end_utc"]) + 1,
                  "nginx_timestamp", rid)
        for rid in expected:
            check(matched[rid] == 1, "nginx_request_count", f"{rid}:{matched[rid]}")
        smoke = read_json(directory / "preflight_smoke.json")
        check(smoke.get("schema") == "hyptcn3/lab-smoke/1" and smoke["values"].get("order_completed") is True
              and bool(smoke["values"]["checks"]), "preflight_incomplete")
        pre = defaultdict(list)
        for line in contents["pre:nginx-access.jsonl"].splitlines():
            row = json.loads(line)
            pre[row["rid"]].append(row["status"])
        for row in smoke["values"]["checks"]:
            check("expected" in row and row["status"] == row["expected"], "preflight_failed", row["rid"])
            check(pre[row["rid"]] == [row["status"]], "preflight_correlation", row["rid"])
        pids = {name: known_pids[name] for name in SERVICES}
        service, catalog_calls = Counter(), Counter()
        journal = contents["journal:journal.txt"]
        for line in journal.splitlines():
            m = SERVICE_LINE.search(line)
            if m and m[2] in expected:
                service[(m[2], m[1], m[3], m[4], int(m[5]))] += 1
                if m[1] in pids["catalog"] and m[3] == "GET" and m[4].startswith("/api/catalog/") and m[5] == "200":
                    catalog_calls[m[2]] += 1
            if re.search(r"Suppressed \d+ messages|Missed \d+ journal messages", line):
                problems.add("journal_error_or_loss", line[:180])
            elif "Traceback (most recent call last)" in line or WORKER_ERROR in line:
                if windows and in_window(unix(line.split(" ", 1)[0])):
                    tolerated["worker_errors" if WORKER_ERROR in line else "journal_tracebacks"] += 1
                    tolerate(counts, "event_window_journal")
                else:
                    problems.add("journal_error_or_loss", line[:180])

        def served(rid, name, method, route, status):
            return sum(service[(rid, pid, method, route, status)] for pid in pids[name])
        for rid, req in expected.items():
            route, method, status = req["route"], req["method"], req["status"]
            if v5:  # Every route of lab/nginx.conf; nginx alone answers /, /static/ and the paths it does not pass.
                name = upstream(route)
            else:
                name = ("auth" if route.startswith("/api/auth/") else "catalog" if route.startswith("/api/catalog")
                        else None if route == "/" else "orders")
            if name is None:
                continue  # nginx serves this route without an API call.
            if rid in during:  # Counted as an exception in traffic().
                tolerated["requests_in_events"] += 1
                tolerated["failed_in_events"] += req["outcome"] != "ok" or not 200 <= req["status"] < 300
                continue
            check(served(rid, name, method, route, status) == 1, "service_request_count", rid)
            # orders and docs ask auth about the token first (lab/services.py); a token it refuses is answered 401.
            if (auth_checked(method, route) if v5 else route == "/api/orders"):
                check(served(rid, "auth", "GET", "/api/auth/check", 401 if v5 and status == 401 else 200) == 1,
                      "service_auth_call", rid)
            if route == "/api/orders" and method == "POST" and status == 201:
                check(catalog_calls[rid] == 1, "service_catalog_call", rid)
            if route == "/healthz":
                for dependency in ("auth", "catalog"):
                    check(served(rid, dependency, "GET", "/healthz", 200) == 1,
                          "service_health_call", f"{rid}:{dependency}")
        for line in contents["session:nginx-error.log"].splitlines():
            # nginx writes guest local time; the lab guest runs in UTC.
            m = NGINX_TIME.match(line)
            stamp = m and datetime.strptime(m[1], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            if stamp and windows and in_window(stamp, stamp + 1):
                tolerated["nginx_error_lines"] += 1
                tolerate(counts, "event_window_nginx_errors")
            elif line.strip():
                problems.add("nginx_error_log_nonempty", line[:180])
        return {"requests": len(expected), "nginx_matched_once": sum(matched[rid] == 1 for rid in expected),
                "service_records": sum(service.values()), "preflight_requests": len(smoke["values"]["checks"]),
                **({"tolerated_in_events": dict(tolerated)} if windows or calls else {})}

    def monitor():
        end = read_json(directory / "end.json")
        summary = host_monitor.summarize(directory / "host_monitor.jsonl", end["measure_start_unix"], end["measure_end_unix"])
        for problem in summary["problems"]:
            problems.add("monitor", problem)
        records = [json.loads(line) for line in (directory / "host_monitor.jsonl").read_text().splitlines()]
        samples = [r for r in records if r.get("type") == "sample"]
        check(records[0].get("session_id") == directory.name, "monitor_session_identity")
        check(records[-1].get("type") == "end" and records[-1].get("clean") is True and
              records[-1].get("samples") == len(samples) and bool(samples), "monitor_end_counts")
        check(all(b["i"] > a["i"] and finite(b["t_mono"]) > finite(a["t_mono"])
                  and unix(b["t_utc"]) > unix(a["t_utc"]) for a, b in zip(samples, samples[1:])), "monitor_order")
        # Proposal 6.2: swapped QEMU memory stalls a full snapshot (missed slots of campaigns v4 and v4c).
        check(all(qemu_unswapped(sample) for sample in samples), "qemu_swap")
        return summary

    def collector():
        capture = read_json(directory / "raw/capture.json")["values"]
        meta = read_json(directory / "session.json")
        log = (directory / "raw/collect.log").read_text()
        check(log.endswith("\n"), "collector_torn_log")
        ends = re.findall(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
        check(len(ends) == 1, "collector_end_missing_or_duplicate")
        if ends:
            snapshots, errors, skipped = map(int, ends[-1])
            check(snapshots == meta["cycles"] == capture["snapshots"] == capture["requested_cycles"],
                  "collector_snapshot_count")
            check(errors == skipped == 0, "collector_errors_or_missed_slots")
        check(capture["collector_exit_code"] == 0, "collector_exit_code")
        check(capture["collector_sha256"] == meta["collector_sha256"], "collector_hash")
        lines = [(line, *collector_line(line)) for line in log.splitlines()]
        errors = [line for line, level, _ in lines if level == "ERROR" or re.search(r"\sERROR\s", line)]
        check(not errors, "collector_error_log")
        warnings = [(line, message) for line, level, message in lines
                    if level == "WARN" or level is None and re.search(r"\sWARN\s", line)]
        # Proposal 6.2: a warning no pattern of warnings_allowed matches in full rejects (null: none matches).
        # Protocols of schema 1 and 2 have no bounds: their warnings are recorded only.
        if limits is not None or not limits_read:
            allowed = limits["warnings_allowed"] if limits else None
            for _, message in warnings:
                if any(re.fullmatch(pattern, message) for pattern in allowed or ()):
                    tolerate(counts, "collector_warnings")
                else:
                    problems.add("collector_warning_unlisted", message[:180])
        return {"sha256": digest(directory / "raw/collect.log"), "warnings": [line for line, _ in warnings],
                "errors": errors, "end": ends[-1] if ends else None}

    def events():
        meta = read_json(directory / "session.json")
        doc = read_json(directory / "events.json")
        check(doc.get("schema") == "hyptcn3/session-events/1", "events_schema")
        # Every key of each planned event in session.json (under schema 3 the items of the plan as they are: type,
        # class, start_s, duration_s, start_phase_s, stop_phase_s; at least the first four) has the same value in
        # its record of events.json.
        planned = meta["events"]
        check(type(planned) is list and len(planned) == len(doc["events"]) and all(
            type(item) is dict and {"type", "class", "start_s", "duration_s"} <= set(item) and type(record) is dict
            and all(key in record and record[key] == item[key] for key in item)
            for item, record in zip(planned, doc["events"])), "events_differ_from_plan")
        for record in doc["events"]:
            check(record.get("executed") is True, "event_not_executed", record["type"])
            # The predicate of the event type fills effect (package B5): {"ok": bool, "predicate": str, ...}.
            effect = record.get("effect")
            check(type(effect) is dict and effect.get("ok") is True, "event_without_effect", record["type"])
            if "host_start_unix" not in record:
                problems.add("event_not_started", record["type"])
                continue
            if "host_stopped_unix" not in record:
                problems.add("event_not_stopped", record["type"])
                continue
            windows.append(event_window(record, meta["event_grace_s"]))
            event_types.append(record["type"])
            # The deployed guest script must be the one hashed at session start: a SHA-256 on both sides.
            script = meta["source_sha256"].get("lab/udalosti.py")
            check(type(script) is str and SHA256.fullmatch(script) is not None
                  and all(type(record.get(step)) is dict and record[step].get("script_sha256") == script
                          for step in ("start", "stop")), "event_script_differs", record["type"])
            for state in (record.get("start", {}), record["stop"]):
                for name in SERVICES:
                    pid = state.get("units", {}).get("hyptcn-lab@" + name, {}).get("ExecMainPID")
                    if pid and pid != "0":
                        known_pids.setdefault(name, set()).add(str(pid))
        return {"events": len(doc["events"]), "executed": sum(r.get("executed") is True for r in doc["events"]),
                "windows": windows, "types": event_types}

    def controls():
        """Package B8 (design B8 1.4): the records of controls.json against the planned controls of session.json,
        and for each occurrence whether it ran and the guest's three predicates, nothing else (the sealed role)."""
        meta = read_json(directory / "session.json")
        if not (directory / "controls.json").is_file():
            raise ValueError("no controls.json")  # Finding S2 of B3: as an events.json missing in an event session.
        doc = read_json(directory / "controls.json")
        check(doc.get("schema") == CONTROLS_SCHEMA, "controls_schema")
        # Every key of each planned control (as the plan states it) has its value in the record, but its class A or
        # B, which the record keeps as kind_class; the record's class is the occurrence's by its polarity.
        planned, records = meta["controls"], doc["controls"]
        check(type(planned) is list and type(records) is list and len(planned) == len(records) and all(
            type(item) is dict and type(record) is dict
            and all(key in record and record[key] == item[key] for key in item if key != "class")
            and record.get("kind_class") == item.get("class")
            and record.get("class") == CONTROL_RECORD_CLASS.get(item.get("polarity"))
            for item, record in zip(planned, records)), "controls_differ_from_plan")
        # The level part of the return predicate is judged once the protocol has a tolerance (design B8 1.3).
        tolerance = protocol.get("controls", {}).get("baseline") if type(protocol.get("controls")) is dict else None
        script = meta["source_sha256"].get("lab/udalosti.py")
        for record in records:
            kind = record.get("kind")
            times = [record.get(key) for pair in CONTROL_CALLS for key in pair]
            check(record.get("executed") is True and all(type(t) in (int, float) and math.isfinite(t) for t in times),
                  "control_not_executed", kind)
            baseline = record.get("baseline")
            level = baseline.get("level") if type(baseline) is dict else None
            check(type(baseline) is dict and baseline.get("ok") is True
                  and (tolerance is None or type(level) is dict and level.get("judged") is True),
                  "control_without_baseline", kind)
            # A start the return predicate refused started nothing (lab/udalosti.py control_start), so the stop that
            # follows it stopped nothing: its effect and its cleanup are not the occurrence's (finding S1 of B8).
            start = record.get("start")
            refused = (type(start) is dict and start.get("started") is False and type(baseline) is dict
                       and baseline.get("ok") is False)
            effect = record.get("effect")
            effective = type(effect) is dict and effect.get("ok") is True
            if refused:
                pass
            elif record.get("polarity") == "negative":  # Its tree ran and the property was absent (skeleton B8 §2).
                if not effective:
                    evidence = effect.get("evidence") if type(effect) is dict else None
                    failed = evidence.get("failed") if type(evidence) is dict else None
                    named = failed if type(failed) is list and all(type(x) is str for x in failed) else []
                    seen = [x for x in named if x in NEGATIVE_PROPERTY.get(kind, ())]
                    if seen:
                        problems.add("negative_with_property", kind)
                    if len(seen) < len(named) or not named:
                        problems.add("negative_not_in_place", kind)
            else:
                check(effective, "control_without_effect", kind)
            cleanup = record.get("cleanup")
            check(refused or type(cleanup) is dict and cleanup.get("ok") is True, "control_not_cleaned", kind)
            # The deployed guest script must be the one hashed at session start, as for an event.
            check(type(script) is str and SHA256.fullmatch(script) is not None
                  and all(type(record.get(step)) is dict and record[step].get("script_sha256") == script
                          for step in ("start", "stop")), "control_script_differs", kind)
            for start, done in CONTROL_CALLS:
                if all(type(record.get(key)) in (int, float) and math.isfinite(record[key]) for key in (start, done)):
                    calls.append((record[start] - CALL_MARGIN_S, record[done] + CALL_MARGIN_S))
        return {"controls": len(records), "executed": sum(r.get("executed") is True for r in records
                                                          if type(r) is dict), "calls": calls}

    section("audit_bounds", read_bounds)
    section("metadata", metadata)
    section("manifest", manifest)
    try:
        meta = read_json(directory / "session.json")
        planned, controlled = "events" in meta, "controls" in meta or meta.get("role") == CONTROL_ROLE
    except (OSError, ValueError):
        planned = controlled = False  # The metadata section has already recorded why.
    # A protocol that plans events plans them for each of its sessions (collection.run_session): a session.json
    # without them fails the events section instead of skipping it (under schema 3: per_session above 0).
    if planned or plans_events(protocol):
        section("events", events)
    # A session of test_controls holds its planned controls (package B8): without them the section fails too.
    if controlled:
        section("controls", controls)
    section("guest", guest)
    contents, requests = {}, []

    def read_segments():
        nonlocal contents
        contents, counts = segments()
        return {"lines": counts}

    def read_traffic():
        nonlocal requests
        summary, requests = traffic()
        return summary

    def realism():
        """Protocol v5: the realism requirements of proposal 5.7 and the offered-load check of proposal 5.3
        (scripts/traffic_log.py realism) over the measure phase, outside the event windows where they judge the
        lab's answers."""
        meta = read_json(directory / "session.json")
        found = traffic_log.realism(directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl",
                                    protocol, meta["scenario"], windows=windows)
        for requirement in found["requirements"]:
            check(requirement["ok"], "traffic_realism", requirement["name"])
        check(found["offered_load"]["ok"], "offered_load_differs_from_plan")
        return found

    section("segments", read_segments)
    section("traffic", read_traffic)
    if v5:
        section("realism", realism)
    section("correlation", lambda: correlation(contents, requests))
    section("monitor", monitor)
    section("collector", collector)
    result.update(problems=problems.result(), problem_counts=dict(problems.counts), accepted=not problems.counts,
                  tolerated={name: counts[name] for name in LOG_EXCEPTIONS},
                  note="Evidence only. RAM, feature coverage and model validation require separate checks.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    result = audit_logs(args.directory)
    result["date"] = datetime.now(timezone.utc).isoformat()
    result["auditor_sha256"] = {str(p.relative_to(ROOT)): digest(p) for p in
                               (Path(__file__), ROOT / "scripts/traffic_log.py", ROOT / "scripts/host_monitor.py",
                                ROOT / "features/audit_policy.py", ROOT / "scripts/protocol_v5.py")}
    if args.out:
        with args.out.open("x") as stream:
            json.dump(result, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"report": str(args.out), "accepted": result["accepted"], "problems": result["problems"]}))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if result["accepted"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
