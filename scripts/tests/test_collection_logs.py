from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import collection_logs as logs, host_monitor, traffic_log as tl
from scripts.collection import write_logs_manifest
from scripts.tests import test_traffic_log as sample


def write(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc) + "\n")


def jsonl(path, records):
    path.write_text("".join(json.dumps(row) + "\n" for row in records))


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()


def utc(offset, base=BASE):
    return datetime.fromtimestamp(base + offset, timezone.utc).isoformat()


def pack(directory, name, text):
    content = text.encode()
    path = directory / "guest" / (name + ".gz")
    path.write_bytes(gzip.compress(content))
    return {"name": name, "file": path.name, "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "lines": content.count(b"\n"), "terminated": content.endswith(b"\n") or not content,
            "gz_bytes": path.stat().st_size, "gz_sha256": logs.digest(path), "file_sha256": logs.digest(path)}


# Protocol v3 variant: restart_sluzby of orders, host bounds 1.45-1.6 s, grace .1 s -> window .45-1.7 s.
EVENT = {"type": "restart_sluzby", "class": "restart_sluzby", "start_s": 0, "duration_s": 1}


@pytest.fixture
def session(tmp_path):
    return build(tmp_path)


def build(tmp_path, event=False, *, session_name="synthetic-session", base=BASE, snapshots=10, measure_s=2):
    # Offsets from base: warmup [0, 1), measurement [1, 1 + measure_s], post until 1.5 + measure_s.
    # The caller's snapshot times must lie inside the measurement; the logs claim `snapshots` of them.
    if type(snapshots) is not int or snapshots < 1 or type(measure_s) is not int or measure_s < 1:
        raise ValueError("snapshots and measure_s must be positive integers")
    base, stop = float(base), 1 + measure_s
    # Interval and end records carry one stamp, the start of the session (the default equals sample.UTC).
    start = datetime.fromtimestamp(base, timezone.utc).isoformat(timespec="microseconds")

    def at(offset):
        return utc(offset, base)
    d = tmp_path / session_name
    (d / "guest").mkdir(parents=True)
    (d / "raw").mkdir()
    config = {"target": "http://lab", "profile": "lab", "seed": 1, "workers": 1, "burst": 0,
              "catalog_share": .5, "write_share": .2, "summary_interval_s": 1, "initial_phase": "warmup"}
    identity = {"kernel": "synthetic-kernel", "boot_id": "synthetic-boot"}
    write(d / "protocol.json", {"synthetic": True})
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": d.name, "cycles": snapshots,
                               "guest_before": identity, "seed": 1, "traffic": config,
                               "protocol_sha256": logs.digest(d / "protocol.json"), "collector_sha256": "test",
                               **({"events": [EVENT], "event_grace_s": .1, "source_sha256": {"lab/udalosti.py": "u"}}
                                  if event else {})})
    write(d / "end.json", {"schema": "hyptcn3/collection-end/2", "completed": True,
                           "guest_after": identity, "collector_rc": 0, "traffic_rc": int(event),
                           "monitor": {"rc": 0}, "measure_start_unix": base + 1, "measure_end_unix": base + stop})
    reqs = [sample.request(0, 0, "warmup", .1, 3, method="POST", route="/api/auth/token"),
            sample.request(1, 1, "measure", 1.1, 2),
            sample.request(2, 1, "measure", 1.5, 2, method="POST", route="/api/orders", status=201),
            sample.request(3, measure_s, "measure", measure_s + .2, 2, route="/healthz"),
            sample.request(4, stop, "post", stop + .1, 2, route="/api/orders")]
    for r in reqs:
        r.update(session_id=d.name, t_start_utc=at(r["t_start_mono"]), t_end_utc=at(r["t_end_mono"]))
    if event:  # The order placed while orders restarts gets 502 from nginx.
        reqs[2].update(status=502, outcome="http_error", error="HTTPError: HTTP Error 502")
    marks = [dict(sample.marker("measure", "warmup", 1., 1), t_utc=at(1)),
             dict(sample.marker("post", "measure", float(stop), stop), t_utc=at(stop))]
    heads = [dict(sample.header(schema, d.name), config=config, start_utc=at(0), start_unix=base)
             for schema in (tl.REQUEST_SCHEMA, tl.INTERVAL_SCHEMA)]
    rs = [heads[0], reqs[0], marks[0], *reqs[1:4], marks[1], reqs[4]]
    ivs = [dict(sample.interval(i, phase, float(i), float(i + 1) if i < stop else stop + .5,
                                [r for r in reqs if r["interval"] == i]), t_start_utc=start, t_end_utc=start)
           for i, phase in enumerate(("warmup", *["measure"] * measure_s, "post"))]
    iv = [heads[1], ivs[0], marks[0], *ivs[1:stop], marks[1], ivs[stop]]
    rs.append(dict(sample.end(reqs, len(rs), end_mono=stop + .5), end_utc=start))
    iv.append(dict(sample.end(reqs, len(iv), end_mono=stop + .5), end_utc=start))
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA, rs)
    sample.write(d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA, iv)
    write(d / "traffic_before.json", {"run_id": sample.RUN, "started_at": at(0)})
    write(d / "traffic.json", {"run_id": sample.RUN, "session_id": d.name, "started_at": at(0),
                              "final": True, "requests": len(reqs), "requests_logged": len(reqs),
                              "ok": sum(r["outcome"] == "ok" for r in reqs),
                              "errors": sum(r["outcome"] != "ok" for r in reqs)})
    units = {name: {"ActiveState": "active", "Result": "success", "NRestarts": "0", "InvocationID": name,
                    "ExecMainPID": str(100 + i), "ExecMainStartTimestampMonotonic": "1"}
             for i, name in enumerate(logs.REQUIRED_UNITS)}
    restarted = {**units, "hyptcn-lab@orders": dict(units["hyptcn-lab@orders"], InvocationID="new", ExecMainPID="999")}
    for when in ("before", "after"):
        write(d / "guest" / f"state_{when}.json", {"schema": "hyptcn3/guest-state/1", **identity,
                                                   "units": restarted if event and when == "after" else units,
                                                   "database": {}})
        write(d / "guest" / f"clock_{when}.json", {"offset_s": .01, "uncertainty_s": .01})
    nginx = [dict(schema="hyptcn3/nginx-access/1", rid=r["rid"], forwarded_rid=r["rid"],
                  method=r["method"], uri=r["route"], status=r["status"], msec=base + r["t_end_mono"]) for r in reqs]
    if event:  # lab/udalosti.py checks health without a request id while the event runs.
        nginx.append(dict(schema="hyptcn3/nginx-access/1", rid="", forwarded_rid="x", method="GET",
                          uri="/healthz", status=502, msec=base + 1.55))
    write(d / "preflight_smoke.json", {"schema": "hyptcn3/lab-smoke/1", "values": {
        "order_completed": True, "checks": [{"rid": "smoke", "status": 401, "expected": 401}]}})
    journal = []

    def call(r, service, method, route, status):
        pid = units["hyptcn-lab@" + service]["ExecMainPID"]
        if event and service == "orders" and r["t_start_mono"] > 1.7:
            pid = "999"
        journal.append(f"{at(2)} guest python3[{pid}]: client request rid={r['rid']} method={method} path={route} status={status}\n")

    for r in reqs:
        service = "auth" if "auth" in r["route"] else "catalog" if "catalog" in r["route"] else "orders"
        call(r, service, r["method"], r["route"], r["status"])
        if r["route"] == "/api/orders":
            call(r, "auth", "GET", "/api/auth/check", 200)
            if r["method"] == "POST":
                call(r, "catalog", "GET", "/api/catalog/1", 200)
        if r["route"] == "/healthz":
            for name in ("auth", "catalog"):
                call(r, name, "GET", "/healthz", 200)
    errors = ""
    if event:
        journal.append(f"{at(1.5)} guest python3[999]: Traceback (most recent call last):\n")
        errors = (f"{datetime.fromtimestamp(base + 1, timezone.utc):%Y/%m/%d %H:%M:%S} [error] 7#7: *1 connect() "
                  "failed (111: Connection refused) while connecting to upstream\n")
        write(d / "events.json", {"schema": "hyptcn3/session-events/1", "events": [dict(
            EVENT, executed=True, host_start_unix=base + 1.45, host_started_unix=base + 1.5,
            host_stop_unix=base + 1.55, host_stopped_unix=base + 1.6, start={"ok": True, "script_sha256": "u"},
            stop={"ok": True, "health": 200, "script_sha256": "u",
                  "units": {"hyptcn-lab@orders": {"ExecMainPID": "999"}}})]})
    for name, suffix, text in (("pre", "nginx-access.jsonl", json.dumps({"rid": "smoke", "status": 401}) + "\n"),
                               ("session", "nginx-access.jsonl", "".join(json.dumps(r) + "\n" for r in nginx)),
                               ("journal", "journal.txt", "".join(journal))):
        entries = [pack(d, name + "-" + suffix, text)]
        if name != "journal":
            entries.append(pack(d, name + "-nginx-error.log", errors if name == "session" else ""))
        write(d / "guest" / (name + "_segment.json"), {
            "schema": "hyptcn3/guest-journal-segment/1" if name == "journal" else "hyptcn3/guest-log-segment/1",
            "files": entries})
    jsonl(d / "host_monitor.jsonl", [
        {"schema": host_monitor.SCHEMA, "type": "header", "session_id": d.name, "interval_s": 1},
        *[{"type": "sample", "i": i, "t_mono": float(i), "t_utc": at(i), "cpu": {}} for i in range(stop + 2)],
        {"type": "end", "samples": stop + 2, "clean": True, "missed_ticks": 0}])
    write(d / "raw/capture.json", {"values": {"snapshots": snapshots, "requested_cycles": snapshots,
                                               "collector_exit_code": 0, "collector_sha256": "test"}})
    (d / "raw/collect.log").write_text(f"{datetime.fromtimestamp(base + stop, timezone.utc):%Y-%m-%dT%H:%M:%SZ} "
                                       f"INFO koniec: {snapshots} snimok, 0 chyb, 0 zmeskanych slotov\n")
    for name in ("traffic.log", "capture.log", "host_monitor.log", "domain.xml"):
        (d / name).touch()
    seal(d)
    return d


def seal(directory):
    (directory / "logs_manifest.json").unlink(missing_ok=True)
    sha = write_logs_manifest(directory)
    end = logs.read_json(directory / "end.json")
    write(directory / "end.json", dict(end, logs_manifest_sha256=sha))


def test_consistent_managed_session_checks_all_evidence(session):
    result = logs.audit_logs(session, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert result["accepted"], result["problems"]
    assert result["sections"]["correlation"]["nginx_matched_once"] == 5
    assert result["sections"]["collector"]["end"] == ("10", "0", "0")


@pytest.mark.parametrize("case,problem", [
    ("modified", "evidence_hash"), ("missing", "missing_evidence"), ("killed", "child_exit"),
    ("restart", "service_restarted"), ("clock", "guest_clock"), ("torn", "traffic"),
    ("missing_nginx", "nginx_request_count"), ("missing_service", "service_catalog_call"),
    ("duplicate_nginx", "nginx_request_count"), ("status_mismatch", "nginx_mismatch"),
    ("missing_monitor", "monitor"), ("skipped_slot", "collector_errors_or_missed_slots"),
    ("malformed", "traffic:unreadable"), ("gzip_corrupt", "segments:unreadable"),
])
def test_rejects_independent_evidence_failures(session, case, problem):
    if case == "modified":
        (session / "traffic.log").write_text("changed\n")
    elif case == "missing":
        (session / "traffic.log").unlink()
    elif case == "killed":
        end = logs.read_json(session / "end.json")
        write(session / "end.json", dict(end, traffic_rc=-9))
    elif case in ("restart", "clock"):
        path = session / "guest" / ("state_after.json" if case == "restart" else "clock_after.json")
        doc = logs.read_json(path)
        if case == "restart":
            doc["units"]["hyptcn-lab@orders"]["InvocationID"] = "new"
        else:
            doc["offset_s"] = 8
        write(path, doc)
    elif case in ("torn", "malformed"):
        with (session / "traffic_requests.jsonl").open("a") as stream:
            stream.write('{"type":' if case == "torn" else '{"type":"request","rid":[],"interval":{}}\n')
    elif case in ("missing_nginx", "duplicate_nginx", "status_mismatch", "missing_service", "gzip_corrupt"):
        name = "journal" if case == "missing_service" else "session"
        suffix = "journal.txt" if case == "missing_service" else "nginx-access.jsonl"
        path = session / "guest" / (name + "-" + suffix + ".gz")
        if case == "gzip_corrupt":
            path.write_bytes(b"broken gzip")
        else:
            lines = gzip.decompress(path.read_bytes()).decode().splitlines(keepends=True)
            if case == "missing_service":
                lines = [line for line in lines if "path=/api/catalog/1 " not in line]
            elif case == "missing_nginx":
                lines.pop()
            elif case == "duplicate_nginx":
                lines.append(lines[-1])
            else:
                lines[-1] = json.dumps(dict(json.loads(lines[-1]), status=503)) + "\n"
            path.write_bytes(gzip.compress("".join(lines).encode()))
            doc_path = session / "guest" / (name + "_segment.json")
            doc = logs.read_json(doc_path)
            doc["files"][0] = pack(session, name + "-" + suffix, "".join(lines))
            write(doc_path, doc)
    elif case == "missing_monitor":
        path = session / "host_monitor.jsonl"
        path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    else:
        path = session / "raw/collect.log"
        path.write_text(path.read_text().replace("0 zmeskanych", "1 zmeskanych"))
    result = logs.audit_logs(session)
    assert not result["accepted"]
    assert problem in result["problem_counts"], result["problems"]


def test_event_window_tolerates_expected_failures_only(tmp_path):
    d = build(tmp_path, event=True)
    result = logs.audit_logs(d, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert result["accepted"], result["problems"]
    assert result["sections"]["events"]["executed"] == 1
    assert result["sections"]["correlation"]["tolerated_in_events"] == {
        "event_health_checks": 1, "journal_tracebacks": 1, "nginx_error_lines": 1,
        "requests_in_events": 2, "failed_in_events": 1}
    assert "hyptcn-lab@orders" not in result["sections"]["guest"]["units_checked"]


@pytest.mark.parametrize("event", [False, True])
@pytest.mark.parametrize("session_name,base,snapshots,measure_s", [
    ("v5-train-1-steady", BASE + 5000, 96, 100), ("s2", BASE + 100000, 720, 725)])
def test_renamed_shifted_longer_session_passes_the_log_audit_like_the_default(
        tmp_path, event, session_name, base, snapshots, measure_s):
    default = logs.audit_logs(build(tmp_path / "default", event), snapshot_times=[BASE + 1.1, BASE + 2.5])
    d = build(tmp_path / "custom", event, session_name=session_name, base=base, snapshots=snapshots,
              measure_s=measure_s)
    result = logs.audit_logs(d, snapshot_times=[base + 1.5 + i for i in range(snapshots)])  # 1 s apart
    assert result["accepted"], result["problems"]
    assert result["sections"]["correlation"]["nginx_matched_once"] == 5
    assert result["sections"]["collector"]["end"] == (str(snapshots), "0", "0")
    assert default["accepted"] and result["sections"].keys() == default["sections"].keys()
    assert result["sections"]["correlation"] == default["sections"]["correlation"]
    assert result["sections"]["guest"]["units_checked"] == default["sections"]["guest"]["units_checked"]


def test_builder_parameters_reach_the_audited_evidence(tmp_path):
    base, snapshots, measure_s = BASE + 5000, 96, 100
    d = build(tmp_path, True, session_name="v5-train-1-steady", base=base, snapshots=snapshots, measure_s=measure_s)
    result = logs.audit_logs(d, snapshot_times=[base + 1, base + 1 + measure_s])
    assert result["accepted"], result["problems"]
    sections = result["sections"]
    assert Path(result["session_dir"]).name == sections["traffic"]["session_id"] == "v5-train-1-steady"
    assert logs.read_json(d / "session.json")["session_id"] == "v5-train-1-steady"
    assert sections["collector"]["end"] == ("96", "0", "0")
    assert logs.read_json(d / "raw/capture.json")["values"]["snapshots"] == 96
    assert (sections["metadata"]["measure_start_unix"], sections["metadata"]["measure_end_unix"]) == (
        base + 1, base + 101)
    assert [m["t_utc"] for m in sections["traffic"]["phase_markers"]] == [utc(1, base), utc(101, base)]
    assert sections["traffic"]["measure"]["intervals"] == measure_s
    assert sections["monitor"]["window_samples"] == measure_s + 1
    (lo, hi), = sections["events"]["windows"]
    assert (lo, hi) == (pytest.approx(base + .45), pytest.approx(base + 1.7))
    # Times the audit does not bound must follow base and the length of the measurement as well.
    traffic = [[json.loads(line) for line in (d / name).read_text().splitlines()]
               for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl")]
    stamps = [r[k] for log in traffic for r in log
              for k in ("t_start_utc", "t_end_utc", "t_utc", "start_utc", "end_utc") if k in r]
    journal = gzip.decompress((d / "guest/journal-journal.txt.gz").read_bytes()).decode().splitlines()
    stamps += [line.split(" ", 1)[0] for line in journal]
    assert len(stamps) > 2 * measure_s and all(base <= logs.unix(s) <= base + 101.5 for s in stamps)
    for log in traffic:
        assert (log[0]["start_unix"], log[0]["start_utc"]) == (base, utc(0, base))
        assert (log[-1]["type"], log[-1]["end_mono"]) == ("end", measure_s + 1.5)
    happened, = logs.read_json(d / "events.json")["events"]
    assert [happened[k] - base for k in ("host_start_unix", "host_started_unix", "host_stop_unix",
                                         "host_stopped_unix")] == pytest.approx([1.45, 1.5, 1.55, 1.6])
    assert (d / "raw/collect.log").read_text().startswith(utc(101, base)[:19] + "Z ")
    # Snapshots in the default window, or after the default end, show which window the evidence claims.
    for times in ([BASE + 1.1], [base + 1 + measure_s + 1]):
        problems = logs.audit_logs(d, snapshot_times=times)["problem_counts"]
        assert {"snapshot_outside_measure", "traffic_snapshot_coverage"} <= set(problems), problems
    assert logs.audit_logs(d, snapshot_times=[base + 3.5])["accepted"]
    for bad in ({"snapshots": 0}, {"measure_s": 0}, {"measure_s": 1.5}):
        with pytest.raises(ValueError):
            build(tmp_path / "bad", **bad)


@pytest.mark.parametrize("case,problem", [
    ("other_unit", "service_restarted"), ("late_traceback", "journal_error_or_loss"),
    ("late_nginx_error", "nginx_error_log_nonempty"), ("not_stopped", "event_not_stopped"),
    ("plan", "events_differ_from_plan"), ("no_events_file", "events:unreadable"),
    ("script", "event_script_differs"), ("late_health_check", "nginx_unknown_request"),
])
def test_event_session_stays_strict_outside_windows(tmp_path, case, problem):
    d = build(tmp_path, event=True)
    if case == "other_unit":
        path = d / "guest/state_after.json"
        doc = logs.read_json(path)
        doc["units"]["hyptcn-lab@auth"]["InvocationID"] = "new"
        write(path, doc)
    elif case in ("late_traceback", "late_nginx_error"):
        name, suffix = ("journal", "journal.txt") if case == "late_traceback" else ("session", "nginx-error.log")
        path = d / "guest" / (name + "-" + suffix + ".gz")
        text = gzip.decompress(path.read_bytes()).decode() + (
            f"{utc(2.5)} guest python3[999]: Traceback (most recent call last):\n" if name == "journal"
            else "2026/01/01 00:00:03 [error] 7#7: upstream timed out\n")
        doc_path = d / "guest" / (name + "_segment.json")
        doc = logs.read_json(doc_path)
        index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith(suffix))
        doc["files"][index] = pack(d, name + "-" + suffix, text)
        write(doc_path, doc)
    elif case == "late_health_check":
        doc_path = d / "guest/session_segment.json"
        path = d / "guest/session-nginx-access.jsonl.gz"
        row = dict(schema="hyptcn3/nginx-access/1", rid="", forwarded_rid="y", method="GET", uri="/healthz",
                   status=200, msec=BASE + 2.5)
        text = gzip.decompress(path.read_bytes()).decode() + json.dumps(row) + "\n"
        doc = logs.read_json(doc_path)
        index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith("nginx-access.jsonl"))
        doc["files"][index] = pack(d, "session-nginx-access.jsonl", text)
        write(doc_path, doc)
    elif case in ("not_stopped", "plan", "script"):
        doc = logs.read_json(d / "events.json")
        if case == "plan":
            doc["events"][0]["start_s"] = 30
        elif case == "script":
            doc["events"][0]["stop"]["script_sha256"] = "other"
        else:
            del doc["events"][0]["host_stopped_unix"]
        write(d / "events.json", doc)
    else:
        (d / "events.json").unlink()
    seal(d)
    result = logs.audit_logs(d)
    assert not result["accepted"]
    assert problem in result["problem_counts"], result["problems"]


def add_journal_line(d, line):
    path, doc_path = d / "guest/journal-journal.txt.gz", d / "guest/journal_segment.json"
    doc = logs.read_json(doc_path)
    index = next(i for i, f in enumerate(doc["files"]) if f["name"].endswith("journal.txt"))
    doc["files"][index] = pack(d, "journal-journal.txt", gzip.decompress(path.read_bytes()).decode() + line)
    write(doc_path, doc)
    seal(d)


def test_worker_statement_timeout_is_admitted_only_inside_an_event_window(tmp_path):
    """lab/services.py reports a round that hit the statement timeout instead of exiting (protocol v5)."""
    line = "guest python3[5]: " + logs.WORKER_ERROR + "canceling statement due to statement timeout\n"
    d = build(tmp_path / "inside", event=True)
    add_journal_line(d, f"{utc(1.5)} {line}")
    result = logs.audit_logs(d, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert result["accepted"], result["problems"]
    assert result["sections"]["correlation"]["tolerated_in_events"]["worker_errors"] == 1
    d = build(tmp_path / "outside", event=True)
    add_journal_line(d, f"{utc(2.5)} {line}")
    result = logs.audit_logs(d, snapshot_times=[BASE + 1.1, BASE + 2.5])
    assert not result["accepted"] and "journal_error_or_loss" in result["problem_counts"], result["problems"]
    d = build(tmp_path / "no-events")
    add_journal_line(d, f"{utc(1.5)} {line}")
    assert "journal_error_or_loss" in logs.audit_logs(d)["problem_counts"]


def test_failed_request_outside_event_window_is_rejected(tmp_path):
    d = build(tmp_path, event=True)
    events = logs.read_json(d / "events.json")
    events["events"][0].update(host_start_unix=BASE + 3.5, host_started_unix=BASE + 3.5,
                               host_stop_unix=BASE + 3.6, host_stopped_unix=BASE + 3.6)
    write(d / "events.json", events)
    seal(d)
    result = logs.audit_logs(d)
    assert {"request_failed", "journal_error_or_loss", "nginx_error_log_nonempty"} <= set(result["problem_counts"])


def test_snapshot_must_be_inside_traffic_phase(session):
    result = logs.audit_logs(session, snapshot_times=[BASE + 3.1])
    assert not result["accepted"] and "traffic_snapshot_coverage" in result["problem_counts"]


def test_manifest_cannot_reference_external_file(session):
    path = session / "logs_manifest.json"
    doc = logs.read_json(path)
    doc["files"]["../outside"] = {"sha256": "", "size": 0}
    write(path, doc)
    result = logs.audit_logs(session)
    assert not result["accepted"] and "evidence_unreadable" in result["problem_counts"]


def test_cli_works_without_numpy_and_refuses_overwrite(session, tmp_path):
    script = Path(logs.__file__)
    out = tmp_path / "report.json"
    result = subprocess.run([sys.executable, "-S", script, session, "--out", out], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    before = out.read_bytes()
    assert subprocess.run([sys.executable, "-S", script, session, "--out", out], capture_output=True).returncode != 0
    assert out.read_bytes() == before


def test_missing_session_still_returns_reviewable_rejection(tmp_path):
    result = logs.audit_logs(tmp_path)
    assert result["accepted"] is False
    assert "metadata:unreadable" in result["problem_counts"]


def test_full_collection_audit_cannot_accept_good_features_with_failed_logs(session, monkeypatch):
    from scripts import collection
    from features.tests.test_collection_contract import sample_sidecar
    from features.tests.test_coverage import data
    from safeguard.tests.test_features import sample as frame

    # Fake only expensive RAM parsing. Real sidecar, window and log validators
    # plus the immutable JSON/NPZ writer are exercised together.
    p = dict(collection.protocol(collection.DEFAULT), interval_s=.1, max_gap_s=.15,
             window_rows=3, min_score_coverage=.5)
    write(session / "protocol.json", p)
    meta = logs.read_json(session / "session.json")
    meta.update(role="diagnostic", profile_sha256={}, protocol_sha256=logs.digest(session / "protocol.json"))
    write(session / "session.json", meta)
    (session / "profile").mkdir()
    capture = logs.read_json(session / "raw/capture.json")
    capture["values"].update(interval_s=p["interval_s"], full_every=p["full_every"])
    write(session / "raw/capture.json", capture)
    frames = [frame(i, full=i == 0, predecessor=i != 0, timestamp=BASE + 1.1 + i * .1) for i in range(10)]
    result = data(frames)
    result.update(snimky=[str(i) for i in range(10)], poznamky=[[]] * 10, trvanie_s=[0.] * 10,
                  max_medzera_s=.15)
    for f in frames:
        image = session / "raw" / f"frame{f.seq}.vmicd"
        image.write_bytes(b"synthetic RAM")
        side = sample_sidecar()
        side.update(seq=f.seq, timestamp_unix=f.timestamp, sched={"skipped_before": 0}, capture={"total_ms": .1})
        side["output"].update(full=f.full, sha256=logs.digest(image))
        write(image.with_suffix(".json"), side)
    monkeypatch.setattr(collection, "retazec", lambda *a, **kw: result)
    seal(session)
    good = session / "audit_good.json"
    assert collection.audit_session(session, p, session / "protocol.json", good) == 0
    end = logs.read_json(session / "end.json")
    write(session / "end.json", dict(end, traffic_rc=-9))
    rejected = session / "audit_rejected.json"
    assert collection.audit_session(session, p, session / "protocol.json", rejected) == 2
    values = logs.read_json(rejected)["values"]
    assert values["quality"]["behavior_valid_rows"] == 10
    assert values["coverage"]["scorable_windows"] == 7
    assert "logs: child_exit:traffic:-9" in values["reasons"]
    assert logs.read_json(good)["values"]["accepted"] is True
