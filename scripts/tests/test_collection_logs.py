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


def utc(offset):
    return datetime.fromtimestamp(BASE + offset, timezone.utc).isoformat()


def pack(directory, name, text):
    content = text.encode()
    path = directory / "guest" / (name + ".gz")
    path.write_bytes(gzip.compress(content))
    return {"name": name, "file": path.name, "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "lines": content.count(b"\n"), "terminated": content.endswith(b"\n") or not content,
            "gz_bytes": path.stat().st_size, "gz_sha256": logs.digest(path), "file_sha256": logs.digest(path)}


@pytest.fixture
def session(tmp_path):
    d = tmp_path / "synthetic-session"
    (d / "guest").mkdir(parents=True)
    (d / "raw").mkdir()
    config = {"target": "http://lab", "profile": "lab", "seed": 1, "workers": 1, "burst": 0,
              "catalog_share": .5, "write_share": .2, "summary_interval_s": 1, "initial_phase": "warmup"}
    identity = {"kernel": "synthetic-kernel", "boot_id": "synthetic-boot"}
    write(d / "protocol.json", {"synthetic": True})
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": d.name, "cycles": 10,
                               "guest_before": identity, "seed": 1, "traffic": config,
                               "protocol_sha256": logs.digest(d / "protocol.json"), "collector_sha256": "test"})
    write(d / "end.json", {"schema": "hyptcn3/collection-end/2", "completed": True,
                           "guest_after": identity, "collector_rc": 0, "traffic_rc": 0,
                           "monitor": {"rc": 0}, "measure_start_unix": BASE + 1, "measure_end_unix": BASE + 3})
    reqs = [sample.request(0, 0, "warmup", .1, 3, method="POST", route="/api/auth/token"),
            sample.request(1, 1, "measure", 1.1, 2),
            sample.request(2, 1, "measure", 1.5, 2, method="POST", route="/api/orders", status=201),
            sample.request(3, 2, "measure", 2.2, 2, route="/healthz"),
            sample.request(4, 3, "post", 3.1, 2, route="/api/orders")]
    for r in reqs:
        r.update(session_id=d.name, t_start_utc=utc(r["t_start_mono"]), t_end_utc=utc(r["t_end_mono"]))
    marks = [dict(sample.marker("measure", "warmup", 1., 1), t_utc=utc(1)),
             dict(sample.marker("post", "measure", 3., 3), t_utc=utc(3))]
    heads = [dict(sample.header(schema, d.name), config=config, start_utc=utc(0), start_unix=BASE)
             for schema in (tl.REQUEST_SCHEMA, tl.INTERVAL_SCHEMA)]
    rs = [heads[0], reqs[0], marks[0], *reqs[1:4], marks[1], reqs[4]]
    ivs = [sample.interval(i, phase, float(i), float(i + 1) if i < 3 else 3.5,
                           [r for r in reqs if r["interval"] == i])
           for i, phase in enumerate(("warmup", "measure", "measure", "post"))]
    iv = [heads[1], ivs[0], marks[0], *ivs[1:3], marks[1], ivs[3]]
    rs.append(sample.end(reqs, len(rs)))
    iv.append(sample.end(reqs, len(iv)))
    sample.write(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA, rs)
    sample.write(d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA, iv)
    write(d / "traffic_before.json", {"run_id": sample.RUN, "started_at": utc(0)})
    write(d / "traffic.json", {"run_id": sample.RUN, "session_id": d.name, "started_at": utc(0),
                              "final": True, "requests": len(reqs), "requests_logged": len(reqs),
                              "ok": len(reqs), "errors": 0})
    units = {name: {"ActiveState": "active", "Result": "success", "NRestarts": "0", "InvocationID": name,
                    "ExecMainPID": str(100 + i), "ExecMainStartTimestampMonotonic": "1"}
             for i, name in enumerate(logs.REQUIRED_UNITS)}
    for when in ("before", "after"):
        write(d / "guest" / f"state_{when}.json", {"schema": "hyptcn3/guest-state/1", **identity,
                                                   "units": units, "database": {}})
        write(d / "guest" / f"clock_{when}.json", {"offset_s": .01, "uncertainty_s": .01})
    nginx = [dict(schema="hyptcn3/nginx-access/1", rid=r["rid"], forwarded_rid=r["rid"],
                  method=r["method"], uri=r["route"], status=r["status"], msec=BASE + r["t_end_mono"]) for r in reqs]
    write(d / "preflight_smoke.json", {"schema": "hyptcn3/lab-smoke/1", "values": {
        "order_completed": True, "checks": [{"rid": "smoke", "status": 401, "expected": 401}]}})
    journal = []

    def call(r, service, method, route, status):
        pid = units["hyptcn-lab@" + service]["ExecMainPID"]
        journal.append(f"{utc(2)} guest python3[{pid}]: client request rid={r['rid']} method={method} path={route} status={status}\n")

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
    for name, suffix, text in (("pre", "nginx-access.jsonl", json.dumps({"rid": "smoke", "status": 401}) + "\n"),
                               ("session", "nginx-access.jsonl", "".join(json.dumps(r) + "\n" for r in nginx)),
                               ("journal", "journal.txt", "".join(journal))):
        entries = [pack(d, name + "-" + suffix, text)]
        if name != "journal":
            entries.append(pack(d, name + "-nginx-error.log", ""))
        write(d / "guest" / (name + "_segment.json"), {
            "schema": "hyptcn3/guest-journal-segment/1" if name == "journal" else "hyptcn3/guest-log-segment/1",
            "files": entries})
    jsonl(d / "host_monitor.jsonl", [
        {"schema": host_monitor.SCHEMA, "type": "header", "session_id": d.name, "interval_s": 1},
        *[{"type": "sample", "i": i, "t_mono": float(i), "t_utc": utc(i), "cpu": {}} for i in range(5)],
        {"type": "end", "samples": 5, "clean": True, "missed_ticks": 0}])
    write(d / "raw/capture.json", {"values": {"snapshots": 10, "requested_cycles": 10,
                                               "collector_exit_code": 0, "collector_sha256": "test"}})
    (d / "raw/collect.log").write_text("2026-01-01T00:00:03Z INFO koniec: 10 snimok, 0 chyb, 0 zmeskanych slotov\n")
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
