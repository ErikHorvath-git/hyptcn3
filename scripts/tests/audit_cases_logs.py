"""Cases of the log audit for the audit self-test (protocol v5, package B3): one bad session per problem key.

Every case starts from the clean session of the self-test: one planned session of a schema-3 protocol, built by
scripts/tests/boundary_sessions.build_session with the event of scripts/tests/test_collection_logs.build (restart of
orders inside the measurement, every field clean). mutate(d, p, result) breaks one thing of the sealed session
directory d and reseals the logs manifest where the case changes a file it lists; it keeps the extraction result.
Expected reasons are those collection.audit_session gives (code 2): "logs: " + the problem of
scripts/collection_logs.py, and a RAM reason where the RAM audit reads the same field. A detail never depends on
the session's time base or directory, so one list holds for every clean session of this shape.

LOG_CASES covers every problem key of the log audit (also "<section>:unreadable"); a key that comes only with
another reason says why in its case. A case whose id ends in ":missing" removes a key the check reads: before B3
the check passed without it (mandatory keys, proposal 6.2). UNREACHABLE names the keys no buildable session
reaches (none at present).
"""
import gzip
import json

from scripts.tests import test_collection_logs as evidence
from scripts.tests import test_traffic_log as sample
from scripts.tests.audit_case import Case
from scripts import traffic_log

UNREACHABLE = {}
# Requests of test_collection_logs.build (rid = run id, worker 00, sequence): r0 warmup token, r1 catalog and r2
# order inside the event window (r2 failed), r3 health check, r4 order list after the measurement.
R0, R2, R3, R4 = (f"{sample.RUN}-00-{seq:08d}" for seq in (0, 2, 3, 4))
EVENT = evidence.EVENT["type"]
WARNING = "synthetic warning outside every allowed pattern"
LONG_WARNING = "synthetic json warning " + "x" * 200  # The problem keeps its first 180 characters.


def logs(*problems):
    return ["logs: " + problem for problem in problems]


def _read(d, name):
    return json.loads((d / name).read_text())


def _write(d, name, doc):
    evidence.write(d / name, doc)


def _records(d, name):
    return [json.loads(line) for line in (d / name).read_text().splitlines()]


def _manifest_changed(d):
    """The logs manifest was edited on purpose: end.json names its new hash, nothing is resealed."""
    end = _read(d, "end.json")
    _write(d, "end.json", dict(end, logs_manifest_sha256=evidence.logs.digest(d / "logs_manifest.json")))


def steps(*mutates):
    """mutate: the given mutations in order; the extraction result stays."""
    def mutate(d, p, result):
        for step in mutates:
            step(d, p, result)
    return mutate


def edit(name, change, seal=True):
    """mutate: change(doc) of the JSON file `name`, then reseal (session.json and end.json are not in the manifest,
    resealing leaves them as edited)."""
    def mutate(d, p, result):
        doc = _read(d, name)
        change(doc)
        _write(d, name, doc)
        if seal:
            evidence.seal(d)
    return mutate


def edit_lines(name, change):
    """mutate: change(records) of the JSONL file `name` (a list of objects), then reseal."""
    def mutate(d, p, result):
        records = _records(d, name)
        change(records)
        evidence.jsonl(d / name, records)
        evidence.seal(d)
    return mutate


def edit_text(name, change):
    """mutate: change(text) of the text file `name`, then reseal."""
    def mutate(d, p, result):
        (d / name).write_text(change((d / name).read_text()))
        evidence.seal(d)
    return mutate


def edit_manifest(change):
    """mutate: change(doc) of logs_manifest.json; end.json names the changed manifest (no reseal)."""
    def mutate(d, p, result):
        doc = _read(d, "logs_manifest.json")
        change(doc)
        _write(d, "logs_manifest.json", doc)
        _manifest_changed(d)
    return mutate


def _set_segment(d, name, suffix, change):
    """Lines of guest/<name>-<suffix> replaced by change(lines) and packed again, as labctl writes a segment."""
    path = d / "guest" / (name + "_segment.json")
    doc = json.loads(path.read_text())
    index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith("-" + suffix))
    entry = doc["files"][index]
    lines = gzip.decompress((d / "guest" / entry["file"]).read_bytes()).decode().splitlines(keepends=True)
    doc["files"][index] = evidence.pack(d, entry["name"], "".join(change(lines)))
    evidence.write(path, doc)


def edit_segment(name, suffix, change):
    """mutate: change(lines) of a guest log segment, then reseal."""
    def mutate(d, p, result):
        _set_segment(d, name, suffix, change)
        evidence.seal(d)
    return mutate


def _nginx(change):
    """Lines of an nginx access log after change(rows), rows as objects; change edits them or returns new rows."""
    def lines(text):
        rows = [json.loads(line) for line in text]
        rows = change(rows) or rows
        return [json.dumps(row) + "\n" for row in rows]
    return lines


def _unit_pids(d, unit):
    """ExecMainPID of `unit` before and after the session (guest state)."""
    return {_read(d, f"guest/state_{when}.json")["units"][unit]["ExecMainPID"] for when in ("before", "after")}


def drop_service_line(rid, unit, path):
    """mutate: the journal loses the record of `unit` serving request `rid` on `path`."""
    def mutate(d, p, result):
        marks = [f"python3[{pid}]: " for pid in _unit_pids(d, unit)]
        _set_segment(d, "journal", "journal.txt", lambda lines: [
            line for line in lines if not (f"rid={rid} method=GET path={path} " in line
                                           and any(mark in line for mark in marks))])
        evidence.seal(d)
    return mutate


def _row(rows, rid):
    return next(row for row in rows if row["rid"] == rid)


def _change_request(d, rid, **fields):
    """Request `rid` with `fields` changed in the traffic logs and in every record that counts or serves it: its
    interval, both end records, traffic.json, its nginx access line and the journal line of its own service."""
    logs_ = {name: _records(d, name) for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl")}
    request = _row([r for r in logs_["traffic_requests.jsonl"] if r.get("type") == "request"], rid)
    old = dict(request)
    request.update(fields)
    requests = [r for r in logs_["traffic_requests.jsonl"] if r.get("type") == "request"]
    for name, records in logs_.items():
        for i, record in enumerate(records):
            if record.get("type") == "interval" and record["interval"] == request["interval"]:
                members = [r for r in requests if r["interval"] == record["interval"]]
                fresh = sample.interval(record["interval"], record["phase"], record["mono_start"],
                                        record["mono_end"], members)
                records[i] = dict(record, **{k: fresh[k] for k in ("ok", "status_codes", "routes", "route_errors",
                                                                    "ok_rps", "hist_ok", *traffic_log.OUTCOMES)})
            elif record.get("type") == "end":
                records[i] = dict(record, **{o: sum(r["outcome"] == o for r in requests)
                                             for o in traffic_log.OUTCOMES})
        evidence.jsonl(d / name, records)
    status = _read(d, "traffic.json")
    _write(d, "traffic.json", dict(status, ok=sum(r["outcome"] == "ok" for r in requests),
                                   errors=sum(r["outcome"] != "ok" for r in requests)))

    def nginx(rows):
        _row(rows, rid).update(method=request["method"], status=request["status"])
    _set_segment(d, "session", "nginx-access.jsonl", _nginx(nginx))
    before = f"rid={rid} method={old['method']} path={old['route']} status={old['status']}\n"
    after = f"rid={rid} method={request['method']} path={request['route']} status={request['status']}\n"
    _set_segment(d, "journal", "journal.txt", lambda lines: [line.replace(before, after) for line in lines])


def change_request(rid, **fields):
    def mutate(d, p, result):
        _change_request(d, rid, **fields)
        evidence.seal(d)
    return mutate


def _without_window_evidence(d):
    """Drop what only the event window admits: the event script's health polls without request id, tracebacks
    and nginx error lines (an event that never ran leaves none of them)."""
    _set_segment(d, "session", "nginx-access.jsonl", _nginx(lambda rows: [row for row in rows if row["rid"] != ""]))
    _set_segment(d, "journal", "journal.txt", lambda lines: [l for l in lines if "Traceback" not in l])
    _set_segment(d, "session", "nginx-error.log", lambda lines: [])


def event_without_window(*keys):
    """mutate: the event lacks the host times `keys`, so it opens no window; the window evidence goes too."""
    def mutate(d, p, result):
        doc = _read(d, "events.json")
        for key in keys:
            del doc["events"][0][key]
        _write(d, "events.json", doc)
        _without_window_evidence(d)
        evidence.seal(d)
    return mutate


def _event(change):
    return lambda doc: change(doc["events"][0])


def _unit(unit, **fields):
    return lambda doc: doc["units"][unit].update(fields)


def _monitor_sample(index, change):
    """change(sample) of the host monitor's sample number `index` (0 = first)."""
    def records(rows):
        change([r for r in rows if r.get("type") == "sample"][index])
    return records


def _swap_utc(rows):
    samples = [r for r in rows if r.get("type") == "sample"]
    samples[3]["t_utc"], samples[4]["t_utc"] = samples[4]["t_utc"], samples[3]["t_utc"]


def _end_count(change):
    """Replace the snapshot count of the collector's end line by change(count)."""
    def text(log):
        line = next(line for line in log.splitlines() if "koniec: " in line)
        count = int(line.split("koniec: ", 1)[1].split(" ", 1)[0])
        return log.replace(f"koniec: {count} snimok", f"koniec: {change(count)} snimok")
    return text


def _append(line):
    return lambda log: log + line + "\n"


# The next two cases start the measurement just after the first snapshot, once in end.json and once in the
# traffic logs. The clean session's first snapshot comes 0.5 s after the start of its measurement, so the other
# record of the start stays within the 1 s the audit allows between the two.
def _first_snapshot_outside_end(d, p, result):
    end = _read(d, "end.json")
    _write(d, "end.json", dict(end, measure_start_unix=result["casy"][0] + .01))


def _first_snapshot_outside_traffic(d, p, result):
    stamp = evidence.datetime.fromtimestamp(result["casy"][0] + .01, evidence.timezone.utc).isoformat()
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
        records = _records(d, name)
        next(r for r in records if r.get("type") == "phase" and r["phase"] == "measure")["t_utc"] = stamp
        evidence.jsonl(d / name, records)
    evidence.seal(d)


def _without_post_marker(d, p, result):
    """Both traffic logs without their post marker, renumbered, the end records counting one record less."""
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
        records = [r for r in _records(d, name) if not (r.get("type") == "phase" and r["phase"] == "post")]
        for n, record in enumerate(records):
            record["n"] = n
        records[-1]["records"] = len(records)
        evidence.jsonl(d / name, records)
    evidence.seal(d)


def _protocol_without_bounds(doc):
    doc["schema"] = "hyptcn3/collection-protocol/3"
    doc.pop("audit", None)


def _shift_measure_end(seconds):
    return lambda end: end.update(measure_end_unix=end["measure_end_unix"] + seconds)


def _missing_evidence(d, p, result):
    (d / "traffic.log").unlink()
    edit_manifest(lambda doc: doc["files"].pop("traffic.log"))(d, p, result)


def _torn(d, p, result):
    (d / "traffic.log").write_text("torn")
    evidence.seal(d)


def _changed_domain(d, p, result):
    (d / "domain.xml").write_text("<domain/>\n")  # Not resealed: the manifest keeps the captured hash.


def _json_line(level, message):
    return json.dumps({"ts": "2026-01-01T00:00:00.000Z", "level": level, "msg": message})


_CASES = [
    # (id, mutate, expected reasons); the check is the id up to its first ":", or the whole id of an unreadable section
    ("audit_bounds:unreadable", edit("protocol.json", _protocol_without_bounds),
     logs("audit_bounds:unreadable:ValueError: protocol schema 3 requires the audit section", "protocol_hash")),
    ("metadata:unreadable", edit("end.json", lambda end: end.update(monitor=[]), seal=False),
     logs("metadata:unreadable:AttributeError: 'list' object has no attribute 'get'")),
    ("manifest:unreadable", edit_manifest(lambda doc: doc.pop("files")), logs("manifest:unreadable:KeyError: 'files'")),
    ("events:unreadable", edit("session.json", lambda meta: meta.pop("source_sha256"), seal=False),
     logs("events:unreadable:KeyError: 'source_sha256'")),
    ("guest:unreadable", edit("guest/state_before.json", lambda doc: doc.pop("database")),
     logs("guest:unreadable:KeyError: 'database'")),
    # A broken segment leaves correlation() without the guest logs it reads.
    ("segments:unreadable", edit("guest/journal_segment.json", lambda doc: doc["files"][0].pop("lines")),
     logs("segments:unreadable:KeyError: 'lines'", "correlation:unreadable:KeyError: 'session:nginx-access.jsonl'")),
    ("traffic:unreadable", edit("traffic.json", lambda doc: doc.pop("requests")),
     logs("traffic:unreadable:KeyError: 'requests'")),
    ("correlation:unreadable", edit("preflight_smoke.json", lambda doc: doc["values"].pop("checks")),
     logs("correlation:unreadable:KeyError: 'checks'")),
    ("monitor:unreadable", edit_lines("host_monitor.jsonl", _monitor_sample(-1, lambda s: s.pop("i"))),
     logs("monitor:unreadable:KeyError: 'i'")),
    ("collector:unreadable", edit("raw/capture.json", lambda doc: doc["values"].pop("requested_cycles")),
     logs("collector:unreadable:KeyError: 'requested_cycles'")),

    ("session_schema", edit("session.json", lambda m: m.update(schema="hyptcn3/collection-session/9"), seal=False),
     logs("session_schema")),
    ("end_schema", edit("end.json", lambda e: e.update(schema="hyptcn3/collection-end/9"), seal=False),
     logs("end_schema")),
    ("session_identity", edit("session.json", lambda m: m.update(session_id="another-session"), seal=False),
     logs("session_identity")),
    ("incomplete_capture", edit("end.json", lambda e: e.update(interrupted=True), seal=False),
     logs("incomplete_capture")),
    ("incomplete_capture:missing", edit("end.json", lambda e: e.pop("interrupted"), seal=False),
     logs("incomplete_capture")),
    # The RAM audit compares the same two fields.
    ("guest_identity_changed", edit("end.json", lambda e: e.update(guest_after=dict(e["guest_after"], boot_id="x")),
                                    seal=False),
     ["incomplete capture or changed guest identity", *logs("guest_identity_changed")]),
    ("child_exit", edit("end.json", lambda e: e.update(monitor={"rc": 1}), seal=False), logs("child_exit:monitor:1")),
    # An empty measurement holds no snapshot and no longer ends at the traffic's post marker.
    ("invalid_measure_interval", edit("end.json", lambda e: e.update(measure_end_unix=e["measure_start_unix"]),
                                      seal=False),
     logs("invalid_measure_interval", "snapshot_outside_measure", "traffic_measure_bounds")),
    ("snapshot_outside_measure", _first_snapshot_outside_end, logs("snapshot_outside_measure")),
    ("protocol_hash", edit("protocol.json", lambda doc: doc.update(note="changed after the session started")),
     logs("protocol_hash")),

    ("logs_manifest_schema", edit_manifest(lambda doc: doc.update(schema="hyptcn3/session-logs/9")),
     logs("logs_manifest_schema")),
    ("logs_manifest_hash", edit("end.json", lambda e: e.update(logs_manifest_sha256="0" * 64), seal=False),
     logs("logs_manifest_hash")),
    ("missing_manifest_entry", edit_manifest(lambda doc: doc["files"].pop("traffic.log")),
     logs("missing_manifest_entry:traffic.log")),
    ("missing_evidence", _missing_evidence, logs("missing_evidence:traffic.log", "missing_manifest_entry:traffic.log")),
    ("evidence_hash", _changed_domain, logs("evidence_hash:domain.xml")),
    ("evidence_lines", edit_manifest(lambda doc: doc["files"]["traffic.log"].update(lines=5)),
     logs("evidence_lines:traffic.log")),
    ("evidence_lines:missing", edit_manifest(lambda doc: [doc["files"]["traffic.log"].pop(key)
                                                          for key in ("lines", "terminated")]),
     logs("evidence_lines:traffic.log")),
    ("torn_evidence", _torn, logs("torn_evidence:traffic.log")),
    ("evidence_unreadable", edit_manifest(lambda doc: doc["files"].update({"../outside": {"sha256": "", "size": 0}})),
     logs("evidence_unreadable:../outside:evidence path escapes session: ../outside")),

    ("guest_state_schema", edit("guest/state_after.json", lambda doc: doc.update(schema="hyptcn3/guest-state/9")),
     logs("guest_state_schema:after")),
    ("guest_boot_changed", edit("guest/state_after.json", lambda doc: doc.update(boot_id="another-boot")),
     logs("guest_boot_changed:after")),
    ("guest_kernel_changed", edit("guest/state_after.json", lambda doc: doc.update(kernel="another-kernel")),
     logs("guest_kernel_changed:after")),
    ("service_unhealthy", edit("guest/state_after.json", _unit("nginx", ActiveState="failed")),
     logs("service_unhealthy:after:nginx")),
    ("guest_clock", edit("guest/clock_after.json", lambda doc: doc.update(offset_s=8)), logs("guest_clock:after")),
    ("service_restarted", edit("guest/state_after.json", _unit("hyptcn-lab@auth", InvocationID="new")),
     logs("service_restarted:hyptcn-lab@auth")),

    ("segment_schema", edit("guest/pre_segment.json", lambda doc: doc.update(schema="hyptcn3/guest-log-segment/9")),
     logs("segment_schema:pre")),
    ("segment_file_missing_or_duplicate",
     edit("guest/pre_segment.json", lambda doc: doc["files"].append(dict(doc["files"][0]))),
     logs("segment_file_missing_or_duplicate:pre:nginx-access.jsonl")),
    ("segment_compressed_hash", edit("guest/pre_segment.json", lambda doc: doc["files"][0].update(
        gz_bytes=doc["files"][0]["gz_bytes"] + 1)), logs("segment_compressed_hash:pre-nginx-access.jsonl.gz")),
    ("segment_content_hash", edit("guest/pre_segment.json", lambda doc: doc["files"][0].update(
        bytes=doc["files"][0]["bytes"] + 1)), logs("segment_content_hash:pre-nginx-access.jsonl.gz")),
    ("segment_lines", edit("guest/pre_segment.json", lambda doc: doc["files"][0].update(
        lines=doc["files"][0]["lines"] + 1)), logs("segment_lines:pre-nginx-access.jsonl.gz")),

    ("traffic", edit_lines("traffic_intervals.jsonl", lambda rows: rows[-1].update(clean=False)),
     logs("traffic:intervals:end_not_clean")),
    # Mandatory keys of the traffic log summary (scripts/traffic_log.py): before B3 a missing one passed.
    ("traffic:missing", edit_lines("traffic_requests.jsonl", lambda rows: rows[-1].pop("worker_errors")),
     logs("traffic:requests:worker_errors")),
    ("traffic_headers_disagree", edit_lines("traffic_intervals.jsonl", lambda rows: rows[0].update(
        start_unix=rows[0]["start_unix"] + 1)), logs("traffic_headers_disagree")),
    ("traffic_headers_disagree:missing", steps(*(edit_lines(name, lambda rows: rows[0].pop("start_unix"))
                                                 for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"))),
     logs("traffic_headers_disagree")),
    ("traffic_phase_times_disagree", edit_lines("traffic_intervals.jsonl", lambda rows: next(
        r for r in rows if r.get("type") == "phase").update(t_mono=-1.0)), logs("traffic_phase_times_disagree")),
    ("traffic_config", steps(*(edit_lines(name, lambda rows: rows[0]["config"].update(workers=99))
                               for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"))),
     logs("traffic_config:workers")),
    # Without the post marker the traffic phases also lack the end of the measurement they bound.
    ("traffic_phases", _without_post_marker, logs("traffic_phases", "traffic:unreadable:KeyError: 'post'")),
    ("traffic_measure_bounds", edit("end.json", _shift_measure_end(1.5), seal=False), logs("traffic_measure_bounds")),
    ("traffic_snapshot_coverage", _first_snapshot_outside_traffic, logs("traffic_snapshot_coverage")),
    ("request_identity", edit_lines("traffic_requests.jsonl", lambda rows: _row(
        [r for r in rows if r.get("type") == "request"], R0).update(session_id="another-session")),
     logs("request_identity:" + R0)),
    # A request without id cannot be correlated: its nginx line and its service record name the old id.
    ("request_id_missing", edit_lines("traffic_requests.jsonl", lambda rows: _row(
        [r for r in rows if r.get("type") == "request"], R0).update(rid="")),
     logs("request_id_missing", "nginx_unknown_request:" + R0, "nginx_request_count::0", "service_request_count:")),
    # Both monotonic times before the generator's start: also outside the request's interval.
    ("request_timing", edit_lines("traffic_requests.jsonl", lambda rows: _row(
        [r for r in rows if r.get("type") == "request"], R0).update(t_start_mono=-.1, t_end_mono=-.097)),
     logs("request_timing:" + R0, "traffic:request_outside_interval:" + R0)),
    ("request_wall_clock", edit_lines("traffic_requests.jsonl", lambda rows: (lambda r: r.update(
        t_end_utc=evidence.datetime.fromtimestamp(evidence.logs.unix(r["t_start_utc"]) - .05,
                                                  evidence.timezone.utc).isoformat()))(
        _row([r for r in rows if r.get("type") == "request"], R0))), logs("request_wall_clock:" + R0)),
    ("request_failed", change_request(R4, status=503, outcome="http_error", error="HTTPError: HTTP Error 503"),
     logs("request_failed:" + R4)),
    ("traffic_status_incomplete", edit("traffic.json", lambda doc: doc.update(final=False)),
     logs("traffic_status_incomplete")),
    ("traffic_status_incomplete:missing", edit("traffic.json", lambda doc: doc.pop("worker_errors")),
     logs("traffic_status_incomplete")),
    ("traffic_status_identity", edit("traffic.json", lambda doc: doc.update(session_id="another-session")),
     logs("traffic_status_identity")),
    ("traffic_status_counts", edit("traffic.json", lambda doc: doc.update(requests=doc["requests"] + 1)),
     logs("traffic_status_counts")),

    ("nginx_schema", edit_segment("session", "nginx-access.jsonl", _nginx(lambda rows: _row(rows, R0).update(
        schema="hyptcn3/nginx-access/9"))), logs("nginx_schema")),
    ("nginx_unknown_request", edit_segment("session", "nginx-access.jsonl", _nginx(lambda rows: rows.append(
        dict(_row(rows, R0), rid="unknown-request", forwarded_rid="unknown-request")))),
     logs("nginx_unknown_request:unknown-request")),
    ("nginx_mismatch", edit_segment("session", "nginx-access.jsonl", _nginx(lambda rows: _row(rows, R0).update(
        status=503))), logs("nginx_mismatch:" + R0)),
    ("nginx_timestamp", edit_segment("session", "nginx-access.jsonl", _nginx(lambda rows: _row(rows, R0).update(
        msec=_row(rows, R0)["msec"] + 3))), logs("nginx_timestamp:" + R0)),
    ("nginx_request_count", edit_segment("session", "nginx-access.jsonl", _nginx(lambda rows: rows.append(
        dict(_row(rows, R0))))), logs(f"nginx_request_count:{R0}:2")),
    ("preflight_incomplete", edit("preflight_smoke.json", lambda doc: doc["values"].update(order_completed=False)),
     logs("preflight_incomplete")),
    ("preflight_failed", edit("preflight_smoke.json", lambda doc: doc["values"]["checks"][0].update(expected=500)),
     logs("preflight_failed:smoke")),
    ("preflight_correlation", edit_segment("pre", "nginx-access.jsonl", _nginx(lambda rows: rows[0].update(
        status=500))), logs("preflight_correlation:smoke")),
    ("journal_error_or_loss", edit_segment("journal", "journal.txt", lambda lines: [
        *lines, "guest systemd-journald[1]: Suppressed 5 messages from hyptcn-lab@auth\n"]),
     logs("journal_error_or_loss:guest systemd-journald[1]: Suppressed 5 messages from hyptcn-lab@auth")),
    ("service_request_count", drop_service_line(R3, "hyptcn-lab@orders", "/healthz"),
     logs("service_request_count:" + R3)),
    ("service_auth_call", drop_service_line(R4, "hyptcn-lab@auth", "/api/auth/check"),
     logs("service_auth_call:" + R4)),
    # The clean session's only order is inside the event window; r4 becomes an order outside it, without the
    # catalog call the orders service makes for every order it accepts.
    ("service_catalog_call", change_request(R4, method="POST", status=201), logs("service_catalog_call:" + R4)),
    ("service_health_call", drop_service_line(R3, "hyptcn-lab@auth", "/healthz"),
     logs(f"service_health_call:{R3}:auth")),
    ("nginx_error_log_nonempty", edit_segment("session", "nginx-error.log", lambda lines: [
        *lines, "[error] 7#7: upstream timed out while reading response header\n"]),
     logs("nginx_error_log_nonempty:[error] 7#7: upstream timed out while reading response header")),

    ("monitor", edit_lines("host_monitor.jsonl", lambda rows: rows[0].update(schema="hyptcn3/host-monitor/9")),
     logs("monitor:missing_header")),
    ("monitor_session_identity", edit_lines("host_monitor.jsonl", lambda rows: rows[0].update(
        session_id="another-session")), logs("monitor_session_identity")),
    ("monitor_end_counts", edit_lines("host_monitor.jsonl", lambda rows: rows[-1].update(
        samples=rows[-1]["samples"] + 1)), logs("monitor_end_counts")),
    ("monitor_order", edit_lines("host_monitor.jsonl", _swap_utc), logs("monitor_order")),
    ("qemu_swap", edit_lines("host_monitor.jsonl", _monitor_sample(3, lambda s: s["procs"]["qemu"][0].update(
        swap_kb=4))), logs("qemu_swap")),
    ("qemu_swap:absent", edit_lines("host_monitor.jsonl", _monitor_sample(3, lambda s: s["procs"].update(qemu=[]))),
     logs("qemu_swap")),

    # Both checks read the final newline of collect.log.
    ("collector_torn_log", edit_text("raw/collect.log", str.rstrip),
     logs("collector_torn_log", "torn_evidence:raw/collect.log")),
    ("collector_end_missing_or_duplicate", edit_text("raw/collect.log", lambda log: log + log),
     logs("collector_end_missing_or_duplicate")),
    ("collector_snapshot_count", edit_text("raw/collect.log", _end_count(lambda n: n + 1)),
     logs("collector_snapshot_count")),
    ("collector_errors_or_missed_slots", edit_text("raw/collect.log", lambda log: log.replace(
        " 0 zmeskanych", " 1 zmeskanych")), logs("collector_errors_or_missed_slots")),
    ("collector_exit_code", edit("raw/capture.json", lambda doc: doc["values"].update(collector_exit_code=3)),
     logs("collector_exit_code")),
    # The RAM audit compares the collector hash of capture.json with session.json as well.
    ("collector_hash", edit("raw/capture.json", lambda doc: doc["values"].update(collector_sha256="0" * 64)),
     ["collector binary or temporal settings mismatch", *logs("collector_hash")]),
    ("collector_error_log", edit_text("raw/collect.log", _append(
        "2026-01-01T00:00:00.000Z ERROR zapis: 1 snimok sa nezverejnilo cele")), logs("collector_error_log")),
    ("collector_error_log:json", edit_text("raw/collect.log", _append(_json_line("ERROR", "zapis zlyhal"))),
     logs("collector_error_log")),
    ("collector_warning_unlisted", edit_text("raw/collect.log", _append("2026-01-01T00:00:00.000Z WARN  " + WARNING)),
     logs("collector_warning_unlisted:" + WARNING)),
    ("collector_warning_unlisted:json", edit_text("raw/collect.log", _append(_json_line("WARN", LONG_WARNING))),
     logs("collector_warning_unlisted:" + LONG_WARNING[:180])),

    ("events_schema", edit("events.json", lambda doc: doc.update(schema="hyptcn3/session-events/9")),
     logs("events_schema")),
    ("events_differ_from_plan", edit("events.json", _event(lambda e: e.update(start_s=30))),
     logs("events_differ_from_plan")),
    # Without a window the failed order and the restart of orders are no longer admitted.
    ("event_not_started", event_without_window("host_start_unix", "host_started_unix", "host_stop_unix",
                                               "host_stopped_unix"),
     logs("event_not_started:" + EVENT, "request_failed:" + R2, "service_restarted:hyptcn-lab@orders")),
    ("event_not_stopped", event_without_window("host_stopped_unix"),
     logs("event_not_stopped:" + EVENT, "request_failed:" + R2, "service_restarted:hyptcn-lab@orders")),
    ("event_script_differs", edit("events.json", _event(lambda e: e["stop"].update(script_sha256="0" * 64))),
     logs("event_script_differs:" + EVENT)),
    # Before B3 a hash missing on both sides passed.
    ("event_script_differs:missing", steps(
        edit("session.json", lambda m: m["source_sha256"].pop("lab/udalosti.py"), seal=False),
        edit("events.json", _event(lambda e: [e[step].pop("script_sha256") for step in ("start", "stop")]))),
     logs("event_script_differs:" + EVENT)),
    ("event_not_executed", edit("events.json", _event(lambda e: e.update(executed=False))),
     logs("event_not_executed:" + EVENT)),
    ("event_without_effect", edit("events.json", _event(lambda e: e.pop("effect"))),
     logs("event_without_effect:" + EVENT)),
    ("event_without_effect:not_ok", edit("events.json", _event(lambda e: e["effect"].update(ok=False))),
     logs("event_without_effect:" + EVENT)),
]

LOG_CASES = [Case("logs:" + name, name.split(":")[0] if not name.endswith(":unreadable") else name,
                  sorted(expected), mutate) for name, mutate, expected in _CASES]
