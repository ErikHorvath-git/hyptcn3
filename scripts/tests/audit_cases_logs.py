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
reaches.

Protocol v5 (package B5b): under a schema-3 protocol with the profiles section the clean session carries the
traffic of its scenario's open-loop profile (logs of schema /2, test_collection_logs.v5_traffic). V5_CASES break
one realism requirement, the offered load, an intended client error, a field of the generator's header, its exit
code or the correlation of a new route at a time; a case that needs one profile moves the session to a scenario
of it. They apply once the schema-3 layout has the profiles section (agent T of B5b, scripts/protocol_v5.py
TOP_LEVEL): from then on every schema-3 protocol has it. Until then UNREACHABLE names their keys with that reason.
A case of the base list whose reasons differ under v5 takes them from the protocol (expected is a callable).

Package B8 (design B8 1.4, skeleton B8 section 5 item 4): CONTROL_CASES start from the clean session of role
test_controls (controls_session: a control of class A and a negative of class B that ran faultlessly, the guest's
health polls without request id inside their start and stop calls) and break one predicate or record at a time:
a control not executed, without the return predicate, without its effect, not cleaned, a negative with its
property, a record that differs from the plan or is missing, controls.json missing (the four cases of finding S2
of B3, whose pilot protocol v5 does not have).
"""
import copy
import gzip
import json
from pathlib import Path

from scripts import collection
from scripts.protocol_v5 import CONTROL_RECORD_CLASS, CONTROL_ROLE, CONTROLS_SCHEMA
from scripts.tests import boundary_sessions as bs
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


def _v5(p):
    """Whether the sessions of protocol p carry the traffic of the v5 profiles (logs /2; package B5b)."""
    return p.get("schema") == "hyptcn3/collection-protocol/3" and "profiles" in p


def under_v5(base, extra):
    """expected: the reasons `base`, and under a protocol with the profiles section (package B5b) also `extra`,
    which v5 adds because the case breaks what the v5 traffic checks read too."""
    return lambda p: sorted([*base, *(extra if _v5(p) else [])])


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
    if logs_["traffic_requests.jsonl"][0].get("schema") == traffic_log.REQUEST_SCHEMA_2:
        # Under v5 the generator's exit code counts the request too: 1 when a result is not the expected one (a 2xx,
        # or the status a deliberate error intends) or none succeeded.
        unexpected = [r for r in requests if (r["outcome"] != "ok" if r.get("intended_status") is None
                                              else r["status"] != r["intended_status"])]
        end = _read(d, "end.json")
        ok = any(r["outcome"] == "ok" for r in requests)
        _write(d, "end.json", dict(end, traffic_rc=int(bool(unexpected) or not ok)))

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
    # Under v5 the realism section needs the same bounds.
    ("audit_bounds:unreadable", edit("protocol.json", _protocol_without_bounds),
     under_v5(logs("audit_bounds:unreadable:ValueError: protocol schema 3 requires the audit section", "protocol_hash"),
              logs("realism:unreadable:ValueError: protocol schema 3 requires the audit section"))),
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
    # Under v5 the realism section needs the generator's start to place the intervals.
    ("traffic_headers_disagree:missing", steps(*(edit_lines(name, lambda rows: rows[0].pop("start_unix"))
                                                 for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"))),
     under_v5(logs("traffic_headers_disagree"), logs("realism:unreadable:KeyError: 'start_unix'"))),
    ("traffic_phase_times_disagree", edit_lines("traffic_intervals.jsonl", lambda rows: next(
        r for r in rows if r.get("type") == "phase").update(t_mono=-1.0)), logs("traffic_phase_times_disagree")),
    # The target: both kinds of traffic compare it with session.json (package B5b: v5 has no workers).
    ("traffic_config", steps(*(edit_lines(name, lambda rows: rows[0]["config"].update(target="http://another-lab"))
                               for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"))),
     logs("traffic_config:target")),
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
    # Both monotonic times before the generator's start: also outside the request's interval (under v5 also
    # before its user session arrived).
    ("request_timing", edit_lines("traffic_requests.jsonl", lambda rows: _row(
        [r for r in rows if r.get("type") == "request"], R0).update(t_start_mono=-.1, t_end_mono=-.097)),
     under_v5(logs("request_timing:" + R0, "traffic:request_outside_interval:" + R0),
              logs("traffic:request_before_arrival:" + R0))),
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

_CASES.append(  # lab/services.py since B5a: the docs service is a unit of the lab like the others.
    ("service_restarted:docs", edit("guest/state_after.json", _unit("hyptcn-lab@docs", InvocationID="new")),
     logs("service_restarted:hyptcn-lab@docs")))


# Protocol v5 (package B5b): the cases of the traffic of the open-loop profiles.

def _scenario_of(p, d, profile):
    """The session's scenario when it is one of `profile`, else the first scenario of p that is."""
    own = _read(d, "session.json")["scenario"]
    if p["scenarios"][own]["profile"] == profile:
        return own
    return next(name for name in sorted(p["scenarios"]) if p["scenarios"][name]["profile"] == profile)


def traffic(profile, **variant):
    """mutate: the traffic of the v5 profile `profile` again (test_collection_logs.v5_traffic with `variant`), the
    session moved to a scenario of that profile where its own is of the other one; then reseal."""
    def mutate(d, p, result):
        evidence.v5_traffic(d, p, scenario=_scenario_of(p, d, profile), **variant)
        evidence.seal(d)
    return mutate


def headers(change):
    """mutate: change(header) of the headers of both traffic logs, then reseal."""
    return steps(*(edit_lines(name, lambda rows: change(rows[0]))
                   for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl")))


def _rid(sessions, step):
    """The request id v5_traffic gives the first request `step` of the user sessions `sessions`."""
    k, j = next((k, row.index(step)) for k, row in enumerate(sessions) if step in row)
    return f"{sample.RUN}-{k + 1:02d}-{j:08d}"


def _distinct(sessions):
    """The user sessions with another object in every request that names one, but the deliberate error."""
    out, n = [], 0
    for steps_ in sessions:
        row = []
        for s in steps_:
            if s.object is not None and s.intended is None:
                n += 1
                if s.route.startswith("/static/"):
                    s = s._replace(route=f"/static/f{n}.png", object=f"f{n}.png")
                elif s.route.startswith("/api/catalog/"):
                    s = s._replace(route=f"/api/catalog/{100 + n}", object=100 + n)
                else:
                    s = s._replace(object=100 + n)
            row.append(s)
        out.append(row)
    return tuple(out)


def traffic_rows(change):
    """mutate: change(request records, interval records) of both traffic logs, renumbered, then reseal."""
    def mutate(d, p, result):
        rows = {name: _records(d, name) for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl")}
        change(*rows.values())
        for name, records in rows.items():
            evidence.jsonl(d / name, [dict(r, n=n) for n, r in enumerate(records)])
        evidence.seal(d)
    return mutate


def both_headers(change):
    return traffic_rows(lambda r, i: [change(rows[0]) for rows in (r, i)])


def _arrivals(rows):
    return [r for r in rows if r.get("type") == "arrival"]


def _request(rows, rid):
    return _row([r for r in rows if r.get("type") == "request"], rid)


def _first_iv(rows):
    """The interval of the first user session of the measure phase (u4): interval 2 in every layout of v5_traffic,
    which places it 2.01 s after the start, alone in its interval."""
    return next(r for r in rows if r.get("type") == "interval" and r["interval"] == 2)


def _duplicate_last(r, i):
    last = _arrivals(r)[-1]
    r.insert(r.index(last) + 1, dict(last))
    r[-1]["records"] += 1  # Written by the generator: the end record counts it.


E = evidence
RID_UNKNOWN, RID_CART = _rid(E.ESHOP, E.UNKNOWN), _rid(E.ESHOP, E.CART)  # The deliberate 404, a cart of eshop.
RID_DOC = _rid(E.CORP, E.DOC)  # A document download of corp.
RID_LAST = f"{sample.RUN}-01-{len(E.ESHOP[0]) - 1:08d}"  # The last request of eshop's first user session.
ARRIVALS = len(E.LEGACY) + len(E.ESHOP)  # Admitted user sessions of the clean session (as many in corp).
U4, U_LAST = f"{sample.RUN}-u{len(E.LEGACY)}", f"{sample.RUN}-u{ARRIVALS - 1}"  # The first and last of the measure
FIRST, EXTRA = f"{sample.RUN}-01-00000000", f"{sample.RUN}-01-00000001"  # phase; the first two requests of u4.
_V5_CASES = [
    # One realism requirement of proposal 5.7 broken at a time (scripts/traffic_log.py realism).
    ("traffic_realism:arrival_cv", traffic("eshop", spacings=(1.,) * (len(E.ESHOP) - 1)),
     logs("traffic_realism:arrival_cv")),  # Evenly spaced arrivals: CV 0.
    ("traffic_realism:think_time", traffic("eshop", thinks=(75.,)), logs("traffic_realism:think_time")),
    ("traffic_realism:order_share", traffic("eshop", sessions=tuple(
        s if E.ORDER in s else [*s, E.CART_ADD, E.ORDER] for s in E.ESHOP)), logs("traffic_realism:order_share")),
    ("traffic_realism:object_concentration", traffic("eshop", sessions=_distinct(E.ESHOP)),
     logs("traffic_realism:object_concentration")),
    ("traffic_realism:success_rate", traffic("eshop", sessions=tuple(  # No deliberate error: 100 %.
        [E.DETAIL if s == E.UNKNOWN else s for s in steps_] for steps_ in E.ESHOP)),
     logs("traffic_realism:success_rate")),
    ("traffic_realism:response_sizes", traffic("eshop", sessions=tuple(
        [s._replace(bytes=200) for s in steps_] for steps_ in E.ESHOP)), logs("traffic_realism:response_sizes")),
    ("traffic_realism:peak_to_mean", traffic("eshop", flat=True), logs("traffic_realism:peak_to_mean")),
    ("traffic_realism:background", traffic("corp", sessions=tuple(  # No report requested.
        [s for s in steps_ if s != E.REPORT] for steps_ in E.CORP)), logs("traffic_realism:background")),
    # Proposal 5.3: the plan names twice the user sessions that were offered.
    ("offered_load_differs_from_plan", traffic("eshop", rate_factor=2), logs("offered_load_differs_from_plan")),
    ("intended_status_differs", steps(traffic("eshop"), change_request(RID_UNKNOWN, status=400)),
     logs("intended_status_differs:" + RID_UNKNOWN)),
    # A planned envelope without the level 1: summarize says so, realism cannot judge.
    ("realism:unreadable", headers(lambda h: h["envelope"].update(level=[.5] * len(h["envelope"]["level"]))),
     logs("realism:unreadable:ValueError: invalid envelope: levels", "traffic:envelope_invalid:levels")),
    # The generator's header against the protocol and session.json (design B5b 1.3, 1.4).
    ("traffic_config:profile", headers(lambda h: h.update(profile="corp" if h["profile"] == "eshop" else "eshop")),
     logs("traffic_config:profile")),
    ("traffic_config:scenario", headers(lambda h: h.update(scenario="another-scenario")),
     logs("traffic_config:scenario")),
    ("traffic_config:intensity", headers(lambda h: h.update(intensity="high" if h["intensity"] == "low" else "low")),
     logs("traffic_config:intensity")),
    ("traffic_config:rate", headers(lambda h: h.update(
        rate_source="protocol" if h["rate_source"] == "command line" else "command line")),
     logs("traffic_config:rate")),
    ("traffic_config:seeds", headers(lambda h: h["seeds"].update(traffic=h["seeds"]["traffic"] + 1)),
     logs("traffic_config:seeds")),
    ("traffic_config:protocol_sha256", headers(lambda h: h.update(protocol_sha256="0" * 64)),
     logs("traffic_config:protocol_sha256")),
    ("traffic_config:profile_parameters", headers(lambda h: h["profile_parameters"].update(
        max_concurrent=h["profile_parameters"]["max_concurrent"] + 1)), logs("traffic_config:profile_parameters")),
    ("traffic_config:warmup_s", headers(lambda h: h.update(warmup_s=h["warmup_s"] - 1)),
     logs("traffic_config:warmup_s")),
    # The exit code must be the one the request log implies (0 or 1 by host_traffic.py's rule); 2 never is.
    ("child_exit:traffic", edit("end.json", lambda e: e.update(traffic_rc=2), seal=False),
     logs("child_exit:traffic:2")),
    # The routes of B5a: the docs service, and the token check of the orders service for the cart.
    ("service_request_count:docs", steps(traffic("corp"), drop_service_line(RID_DOC, "hyptcn-lab@docs", "/api/docs/5")),
     logs("service_request_count:" + RID_DOC)),
    ("service_auth_call:cart", steps(traffic("eshop"), drop_service_line(RID_CART, "hyptcn-lab@auth",
                                                                         "/api/auth/check")),
     logs("service_auth_call:" + RID_CART)),
    # The cross-checks of the /2 logs (scripts/traffic_log.py summarize), two of them.
    ("traffic:arrivals", edit_lines("traffic_requests.jsonl", lambda rows: rows[-1].update(
        arrivals=rows[-1]["arrivals"] + 1)), logs(f"traffic:requests:end_arrivals_mismatch:arrivals:{ARRIVALS + 1}!="
                                                f"{ARRIVALS}")),
    ("traffic:user_session", steps(traffic("eshop"), edit_lines("traffic_requests.jsonl", lambda rows: _row(
        [r for r in rows if r.get("type") == "request"], RID_LAST).update(user_session="unknown-user-session"))),
     logs("traffic:request_user_session_unknown:" + RID_LAST)),
    # The other cross-checks of summarize whose problem does not depend on the session's timeline (the rest:
    # scripts/tests/test_traffic_realism.py); where the header field is also compared, its traffic_config too.
    ("traffic:v5_header_missing", traffic_rows(lambda r, i: r[0].pop("load_model")),
     logs("traffic:v5_header_missing:load_model")),
    ("traffic:v5_header_mismatch", traffic_rows(lambda r, i: i[0].update(warmup_s=i[0]["warmup_s"] + 1)),
     logs("traffic:v5_header_mismatch:warmup_s")),
    ("traffic:rate_invalid", both_headers(lambda h: h.update(rate=0)),
     logs("traffic:rate_invalid", "traffic_config:rate")),
    ("traffic:rate_source_invalid", both_headers(lambda h: h.update(rate_source="guess")),
     logs("traffic:rate_source_invalid", "traffic_config:rate")),
    ("traffic:seeds_invalid", both_headers(lambda h: h["seeds"].pop("traffic_sizes")), logs("traffic:seeds_invalid")),
    ("traffic:warmup_invalid", both_headers(lambda h: h.update(warmup_s=h["envelope"]["t_s"][-1])),  # Not before D.
     logs("traffic:warmup_invalid", "traffic_config:warmup_s")),
    ("traffic:profile_unknown", both_headers(lambda h: h.update(profile="lab")),
     logs("traffic:profile_unknown:lab", "traffic_config:profile")),
    ("traffic:profile_parameters_invalid", both_headers(lambda h: h["profile_parameters"].pop("max_concurrent")),
     logs("traffic:profile_parameters_invalid:max_concurrent", "traffic_config:profile_parameters")),
    ("traffic:arrival_cap", traffic_rows(lambda r, i: _arrivals(r)[4].update(  # Admitted at the cap.
        active=r[0]["profile_parameters"]["max_concurrent"])), logs("traffic:arrival_cap:" + U4)),
    ("traffic:user_session_id", traffic_rows(lambda r, i: [x.update(user_session="u4") for x in r
                                                           if x.get("user_session") == U4]),
     logs("traffic:user_session_id:u4")),
    ("traffic:duplicate_user_session", traffic_rows(_duplicate_last),
     logs("traffic:duplicate_user_session:" + U_LAST, "traffic:arrivals_outside_intervals:1",
          f"traffic:requests:end_arrivals_mismatch:arrivals:{ARRIVALS}!={ARRIVALS + 1}",
          f"traffic:requests:end_arrivals_mismatch:admitted:{ARRIVALS}!={ARRIVALS + 1}")),
    ("traffic:request_v5_malformed", traffic_rows(lambda r, i: _request(r, EXTRA).pop("step")),
     logs("traffic:request_v5_malformed:" + EXTRA)),
    ("traffic:request_before_arrival", traffic_rows(lambda r, i: _arrivals(r)[4].update(  # After its first request.
        t_mono=_arrivals(r)[4]["t_mono"] + .0015)), logs("traffic:request_before_arrival:" + FIRST)),
    ("traffic:think_s_first", traffic_rows(lambda r, i: _request(r, FIRST).update(think_s=1.)),
     logs("traffic:think_s_first:" + FIRST)),
    ("traffic:think_s_missing", traffic_rows(lambda r, i: _request(r, EXTRA).update(think_s=None)),
     logs("traffic:think_s_missing:" + EXTRA)),
    # An intended status outside the profile's client errors; answered 200, it also differs from its own.
    ("traffic:intended_status_unknown", traffic_rows(lambda r, i: _request(r, EXTRA).update(intended_status=500)),
     logs("traffic:intended_status_unknown:" + EXTRA, "intended_status_differs:" + EXTRA)),
    ("traffic:end_v5_invalid", traffic_rows(lambda r, i: r[-1].pop("dropped")),
     logs("traffic:requests:end_v5_invalid:dropped")),
    ("traffic:end_user_sessions_mismatch", traffic_rows(lambda r, i: r[-1].update(
        user_sessions_completed=r[-1]["user_sessions_completed"] - 1)),
     logs("traffic:requests:end_user_sessions_mismatch")),
    ("traffic:interval_sessions", traffic_rows(lambda r, i: _first_iv(i).update(admitted_sessions=0,
                                                                                 dropped_sessions=1)),
     logs("traffic:interval_sessions:2:admitted_sessions:0!=1", "traffic:interval_sessions:2:dropped_sessions:1!=0")),
    ("traffic:planned_sessions", traffic_rows(lambda r, i: _first_iv(i).update(
        planned_sessions=_first_iv(i)["planned_sessions"] + .01)), logs("traffic:planned_sessions:2")),
    ("traffic:active_max", traffic_rows(lambda r, i: _first_iv(i).update(
        active_max=r[0]["profile_parameters"]["max_concurrent"] + 1)), logs("traffic:active_max:2")),
    # Without the planned count the offered load cannot be judged either.
    ("traffic:interval_v5_malformed", traffic_rows(lambda r, i: _first_iv(i).pop("planned_sessions")),
     logs("traffic:interval_v5_malformed:2", "realism:unreadable:KeyError: 'planned_sessions'")),
]


# Package B8: the clean session of role test_controls and the cases of the section controls of the log audit.

CONTROLS = (("kontrola_wx_memfd", "control"), ("kontrola_zapisovac_pamate", "negative"))
CONTROL_KIND, NEGATIVE_KIND = (kind for kind, _ in CONTROLS)
# The guest's predicates of a faultless occurrence (lab/udalosti.py, design B8 1.3); the level part is not judged
# while controls.baseline is null.
BASELINE = {"ok": True, "exact": {"ok": True, "residues": []},
            "level": {"judged": False, "why": "controls.baseline null until G2"}, "evidence": []}
EFFECT = {"ok": True, "predicate": "synthetic", "evidence": {"members": [4321, 4322]}}
CLEANUP = {"ok": True, "residues": [], "evidence": []}


def control_items(p):
    """The planned controls of the clean session of role test_controls as the plan states them: a control of
    kontrola_wx_memfd (class A, no dose) 2 s after the measurement starts and a negative of kontrola_zapisovac_pamate
    (class B, its first dose) 8 s after it, 3 s each, so that both fit the short sessions of the test protocols."""
    kinds, interval, items = p["controls"]["kinds"], p["interval_s"], []
    for (kind, polarity), start in zip(CONTROLS, (2., 8.)):
        k = kinds[kind]
        items.append({"kind": kind, "polarity": polarity, "class": k["class"],
                      "dose": None if k["doses"] is None else k["doses"][0], "start_s": start, "duration_s": 3.,
                      "start_phase_s": start % interval, "stop_phase_s": (start + 3.) % interval})
    return items


def control_records(items, measure_start):
    """The records of controls.json as scripts/collection.py Controls leaves them after a faultless run of `items`
    (design B8 1.4): the item with its class under kind_class, the occurrence's class, executed, the host times
    of both calls, the replies of labctl and at the top the guest's baseline, effect and cleanup."""
    records = []
    for item in items:
        start = measure_start + item["start_s"]
        stop = start + item["duration_s"]
        reply = {"schema": "hyptcn3/lab-event/1", "type": item["kind"], "ok": True, "error": None, "health": 200,
                 "script_sha256": evidence.SCRIPT_SHA256, "kind": item["kind"], "polarity": item["polarity"],
                 "dose": item["dose"], "class": CONTROL_RECORD_CLASS[item["polarity"]]}
        record = {key: value for key, value in item.items() if key != "class"}
        record.update(kind_class=item["class"], executed=True, host_start_unix=start, host_started_unix=start + .2,
                      host_stop_unix=stop, host_stopped_unix=stop + .3,
                      start=dict(reply, action="start", started=True, baseline=copy.deepcopy(BASELINE)),
                      stop=dict(reply, action="stop", effect=copy.deepcopy(EFFECT), cleanup=copy.deepcopy(CLEANUP)),
                      baseline=copy.deepcopy(BASELINE), effect=copy.deepcopy(EFFECT), cleanup=copy.deepcopy(CLEANUP),
                      **{"class": CONTROL_RECORD_CLASS[item["polarity"]]})
        records.append(record)
    return records


def health_polls(records):
    """The nginx lines of the guest's health polls without request id in the calls of the records (lab/udalosti.py
    polls once at the end of a start and twice in a stop: its wait for health 200 and its reply)."""
    times = [t for r in records for t in (r["host_started_unix"] - .1, r["host_stopped_unix"] - .2,
                                          r["host_stopped_unix"] - .1)]
    return [json.dumps({"schema": "hyptcn3/nginx-access/1", "rid": "", "forwarded_rid": "x", "method": "GET",
                        "uri": "/healthz", "status": 200, "msec": t}) + "\n" for t in times]


def controls_session(root, p, protocol_path, name):
    """The clean session of role test_controls below `root` (package B8): a boundary_sessions.Session.

    The first planned session of plan(p) as a session of test_controls (as its VM sees the protocol), of full
    length, built as the clean session of the self-test is but without an event: session.json plans no event
    (events.json holds none) and the controls of control_items(p), controls.json holds their records after a
    faultless run (control_records), and the session's nginx log the guest's health polls inside their calls."""
    root = Path(root)
    place = dict(collection.plan(p)["sessions"][0], role=CONTROL_ROLE, group=f"{p['group_prefix']}{CONTROL_ROLE}-1")
    pv = collection.for_vm(p, place.get("vm"))
    items = control_items(p)
    session = bs.build_session(root, pv, protocol_path, place, session_id=name, base=bs.time_base(p, CONTROL_ROLE, 0),
                               profile=bs.profile_dir(root / (name + "-profile")),
                               meta={"events": [], "event_grace_s": p["events"]["grace_s"],
                                     "source_sha256": {"lab/udalosti.py": evidence.SCRIPT_SHA256}, "controls": items})
    d = session.directory
    records = control_records(items, _read(d, "end.json")["measure_start_unix"])
    _write(d, "events.json", {"schema": "hyptcn3/session-events/1", "events": []})
    _write(d, "controls.json", {"schema": CONTROLS_SCHEMA, "controls": records})
    _set_segment(d, "session", "nginx-access.jsonl", lambda lines: [*lines, *health_polls(records)])
    evidence.seal(d)
    return session


def _control(index, change):
    """mutate: change(record) of record `index` of controls.json (0: the control, 1: the negative), then reseal."""
    return edit("controls.json", lambda doc: change(doc["controls"][index]))


def _failed(name):
    return lambda record: record[name].update(ok=False)


def _without_controls_json(d, p, result):
    (d / "controls.json").unlink()
    evidence.seal(d)


_CONTROL_CASES = [
    # Finding S2 of B3: without the records no call of a control admits its health polls either.
    ("controls:unreadable", _without_controls_json,
     logs("controls:unreadable:ValueError: no controls.json", "nginx_unknown_request:")),
    ("controls_schema", edit("controls.json", lambda doc: doc.update(schema="hyptcn3/session-controls/9")),
     logs("controls_schema")),
    ("controls_differ_from_plan", _control(0, lambda r: r.update(start_s=r["start_s"] + 1)),
     logs("controls_differ_from_plan")),
    ("controls_differ_from_plan:class", _control(1, lambda r: r.update({"class": r["kind_class"]})),
     logs("controls_differ_from_plan")),
    # S2: a planned control missing from controls.json (the negative): its calls admit no health poll.
    ("controls_differ_from_plan:missing", edit("controls.json", lambda doc: doc["controls"].pop()),
     logs("controls_differ_from_plan", "nginx_unknown_request:")),
    ("control_not_executed", _control(0, lambda r: r.update(executed=False)),
     logs("control_not_executed:" + CONTROL_KIND)),
    # Package B10, S8 of the B8 verification (mutant A1): executed, but a host time of its calls is missing; without it
    # the stop call admits none of its health polls either.
    ("control_not_executed:host_times", _control(0, lambda r: r.pop("host_stopped_unix")),
     logs("control_not_executed:" + CONTROL_KIND, "nginx_unknown_request:")),
    # Mutant A2 of the same verification: the record keeps the plan's class A or B as kind_class.
    ("controls_differ_from_plan:kind_class", _control(0, lambda r: r.update(kind_class="B")),
     logs("controls_differ_from_plan")),
    ("control_without_baseline", _control(0, _failed("baseline")), logs("control_without_baseline:" + CONTROL_KIND)),
    # S2: the counterpart of a positive control not detected, from the guest's effect predicate (no feature is read).
    ("control_without_effect", _control(0, _failed("effect")), logs("control_without_effect:" + CONTROL_KIND)),
    ("negative_with_property", _control(1, _failed("effect")), logs("negative_with_property:" + NEGATIVE_KIND)),
    ("control_not_cleaned", _control(0, _failed("cleanup")), logs("control_not_cleaned:" + CONTROL_KIND)),
    ("control_script_differs", _control(0, lambda r: r["stop"].update(script_sha256="0" * 64)),
     logs("control_script_differs:" + CONTROL_KIND)),
]


def _cases(rows, session=None):
    return [Case("logs:" + name, name.split(":")[0] if not name.endswith(":unreadable") else name,
                 expected if callable(expected) else sorted(expected), mutate, session)
            for name, mutate, expected in rows]


V5_CASES = _cases(_V5_CASES)
CONTROL_CASES = _cases(_CONTROL_CASES, controls_session)
LOG_CASES = _cases(_CASES) + V5_CASES + CONTROL_CASES
