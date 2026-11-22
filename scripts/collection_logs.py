#!/usr/bin/env python3
"""Offline evidence audit for managed VM sessions; no guest access or RAM parsing.

python3 scripts/collection_logs.py SESSION [--out NEW.json]
Exit 0 = evidence checks passed, 2 = rejected/incomplete evidence. This verdict
does not admit a session to training: collection.py also checks RAM and features.

The bounds come from the session's own protocol.json (features/audit_policy.py audit_bounds; the metadata
section checks its hash). Every key a check reads is mandatory: a missing one fails that check (or its section),
it never passes on a default. Each condition the audit admits instead of rejecting counts one registered
exception (features/audit_policy.py tolerate); result["tolerated"] holds the counts of LOG_EXCEPTIONS.
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
from scripts.protocol_v5 import plans_events

SCHEMA = "hyptcn3/collection-logs-audit/1"
REQUIRED = ("preflight_smoke.json", "host_monitor.jsonl", "host_monitor.log", "traffic.json", "traffic.log",
            "traffic_before.json", "traffic_requests.jsonl", "traffic_intervals.jsonl", "capture.log",
            "protocol.json", "domain.xml", "guest/state_before.json", "guest/state_after.json",
            "guest/clock_before.json", "guest/clock_after.json", "guest/pre_segment.json",
            "guest/session_segment.json", "guest/journal_segment.json")
SERVICE_LINE = re.compile(r"python3\[(\d+)\]: .*request rid=(\S+) method=(\S+) path=(\S+) status=(\d+)\s*$")
REQUIRED_UNITS = ("nginx", "postgresql@15-main", "hyptcn-lab@auth", "hyptcn-lab@catalog",
                  "hyptcn-lab@orders", "hyptcn-lab@worker", "systemd-journald")
APPS = ("hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@worker")
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


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unix(value):
    time = datetime.fromisoformat(value)
    if time.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return time.timestamp()


def finite(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("non-finite or non-numeric measurement")
    return value


def local_file(directory, name):
    path = directory / name
    if (not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts
            or not path.resolve().is_relative_to(directory.resolve()) or path.is_symlink()):
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


def audit_logs(directory, *, snapshot_times=()):
    directory = Path(directory).resolve()
    problems = traffic_log.Problems()
    result = {"schema": SCHEMA, "session_dir": str(directory), "sections": {}}
    # Protocol v3: [host start - 1 s, host stop done + grace] of each event. Failures inside a window
    # are expected evidence of the event; outside every window the checks stay as strict as in v2.
    windows, event_types, known_pids = [], [], {}
    # Requests inside an event window: one exception each, counted in traffic(); traffic() and correlation()
    # relax their checks for exactly these.
    during = set()
    counts = Counter()  # Exceptions admitted, by id of features/audit_policy.py TOLERATED.
    # The session's protocol and its audit bounds (None: schema 1 or 2). Until protocol.json has been read the
    # bounds are unknown and admit nothing.
    protocol, limits, limits_read = {}, None, False

    def in_window(*times):
        return any(lo <= t <= hi for t in times for lo, hi in windows)

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
        nonlocal protocol, limits, limits_read
        protocol = read_json(directory / "protocol.json")
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
                path = local_file(directory, name)
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
        for name in ("auth", "catalog", "orders"):
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
        records, _ = traffic_log.read_jsonl(directory / "traffic_requests.jsonl", traffic_log.REQUEST_SCHEMA)
        requests = [r for r in records if r.get("type") == "request"]
        summary = traffic_log.summarize(directory / "traffic_requests.jsonl", directory / "traffic_intervals.jsonl",
                                        session_id=directory.name)
        for problem in summary["problems"]:
            problems.add("traffic", problem)
        header = records[0]
        intervals, _ = traffic_log.read_jsonl(directory / "traffic_intervals.jsonl", traffic_log.INTERVAL_SCHEMA)
        check("config" in header and "start_unix" in header and intervals[0].get("config") == header["config"]
              and intervals[0].get("start_unix") == header["start_unix"], "traffic_headers_disagree")
        phase_fields = lambda rows: [{k: v for k, v in r.items() if k not in ("schema", "n")}
                                     for r in rows if r.get("type") == "phase"]
        check(phase_fields(records) == phase_fields(intervals), "traffic_phase_times_disagree")
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
                    and in_window(finite(row["msec"]))):
                tolerated["event_health_checks"] += 1  # lab/udalosti.py polls health with no request id.
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
        pids = {name: known_pids[name] for name in ("auth", "catalog", "orders")}
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
            name = "auth" if route.startswith("/api/auth/") else "catalog" if route.startswith("/api/catalog") else "orders"
            if route == "/":
                continue  # nginx serves this route without an API call.
            if rid in during:  # Counted as an exception in traffic().
                tolerated["requests_in_events"] += 1
                tolerated["failed_in_events"] += req["outcome"] != "ok" or not 200 <= req["status"] < 300
                continue
            check(served(rid, name, method, route, status) == 1, "service_request_count", rid)
            if route == "/api/orders":
                check(served(rid, "auth", "GET", "/api/auth/check", 200) == 1, "service_auth_call", rid)
                if method == "POST" and status == 201:
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
                **({"tolerated_in_events": dict(tolerated)} if windows else {})}

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
        planned = [{k: r[k] for k in ("type", "class", "start_s", "duration_s")} for r in doc["events"]]
        check(planned == meta["events"], "events_differ_from_plan")
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
            windows.append((finite(record["host_start_unix"]) - 1,
                            finite(record["host_stopped_unix"]) + finite(meta["event_grace_s"])))
            event_types.append(record["type"])
            # The deployed guest script must be the one hashed at session start: a SHA-256 on both sides.
            script = meta["source_sha256"].get("lab/udalosti.py")
            check(type(script) is str and SHA256.fullmatch(script) is not None
                  and all(type(record.get(step)) is dict and record[step].get("script_sha256") == script
                          for step in ("start", "stop")), "event_script_differs", record["type"])
            for state in (record.get("start", {}), record["stop"]):
                for name in ("auth", "catalog", "orders"):
                    pid = state.get("units", {}).get("hyptcn-lab@" + name, {}).get("ExecMainPID")
                    if pid and pid != "0":
                        known_pids.setdefault(name, set()).add(str(pid))
        return {"events": len(doc["events"]), "executed": sum(r.get("executed") is True for r in doc["events"]),
                "windows": windows, "types": event_types}

    section("audit_bounds", read_bounds)
    section("metadata", metadata)
    section("manifest", manifest)
    try:
        planned = "events" in read_json(directory / "session.json")
    except (OSError, ValueError):
        planned = False  # The metadata section has already recorded why.
    # A protocol that plans events plans them for each of its sessions (collection.run_session): a session.json
    # without them fails the events section instead of skipping it (under schema 3: per_session above 0).
    if planned or plans_events(protocol):
        section("events", events)
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

    section("segments", read_segments)
    section("traffic", read_traffic)
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
