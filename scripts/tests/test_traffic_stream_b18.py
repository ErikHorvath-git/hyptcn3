"""Package B18 (Q87, decision 2 of B18): the readers that read the traffic logs and the guest segments as streams give
exactly the results of the code before B18 (scripts/tests/traffic_log_pred_b18.py, frozen at df3cee5).

Each test runs the new function and the frozen one on the same logs and compares their results with their types (the
same keys of the same types in the same order, a tuple apart from a list, the same problems with their details, the
same numbers of the same types and reprs) or, where the frozen one raises, the type and the text of the exception: on
the fixtures of scripts/tests/test_traffic_log.py, test_traffic_realism.py and test_collection_logs.py, on the session
of every case of the audit self-test (scripts/tests/audit_cases.py, under the small protocol of test_audit_selftest.py),
and on random breaks of the logs of synthetic sessions (types, missing keys, repeated, moved and removed records, lines
that are no JSON, a cut end, segment lines that are no UTF-8 or carry other line ends). And the request log is read as
a stream: no reader reads it through read_jsonl, Path.read_bytes or Path.read_text, or through read() without a size or
readlines() of a file of it that open, io.open or Path.open opened; and the compact index of the session audit holds
no record. Synthetic sessions only; no measurement.

Q88 (should_fix 2 of the sixth G0 verification; the executor's decision, for the lead's review): the comparison was the
JSON text of the results, which cannot tell a tuple from a list or an int key from its string, and the refusal covered
read_jsonl, Path.read_bytes and Path.read_text only.
"""
import builtins
import copy
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import random
import shutil

import pytest

from scripts import campaign_report, collection, collection_logs as logs, lab_trial, traffic_log as tl
from scripts.tests import boundary_sessions as bs, protokol_g0
from scripts.tests import test_collection_logs as evidence
from scripts.tests import test_traffic_log as sample
from scripts.tests import test_traffic_realism as ttr
from scripts.tests import traffic_log_pred_b18 as before

TIMES = [evidence.BASE + 1.1, evidence.BASE + 2.5]


def typed(value):
    """value as nested tuples that keep what JSON text loses (Q88): the type of every value and key, the order of the
    keys, a tuple apart from a list, an int key apart from its string, and the repr of each float (-0.0 apart from 0.0,
    NaN equal to NaN). Any other object is its type and repr."""
    if isinstance(value, dict):
        return type(value).__name__, tuple((typed(key), typed(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return type(value).__name__, tuple(typed(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return type(value).__name__, tuple(sorted(repr(typed(item)) for item in value))
    if isinstance(value, float):
        return "float", repr(value)
    if value is None or isinstance(value, (bool, int, str, bytes)):
        return type(value).__name__, value
    return type(value).__name__, repr(value)


def outcome(function, *args, **kwargs):
    """("ok", the result in its typed form) or ("raise", "<type>: <text>") of a call."""
    try:
        return "ok", typed(function(*args, **kwargs))
    except Exception as error:  # noqa: BLE001 - an exception is a result to compare
        return "raise", f"{type(error).__name__}: {error}"


def assert_same(old, new, *args, **kwargs):
    found, expected = outcome(new, *args, **kwargs), outcome(old, *args, **kwargs)
    assert found == expected


@pytest.fixture(scope="module")
def p(tmp_path_factory):
    """The protocol of scripts/tests/test_traffic_realism.py (its fixture p, the G0 file's profiles)."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(bs, "V5", protokol_g0.g0_file())
        bs._v5_file.cache_clear()
        try:
            doc = bs.protocol_doc(bs.profile_dir(tmp_path_factory.mktemp("b18") / "profile"),
                                  schema="hyptcn3/collection-protocol/3", cycles=96, pilot_cycles=80, window_rows=8,
                                  full_every=64, gate=bs.worst_gate(96, 8, 64, bs.RULE["max"]), name="realism",
                                  scenarios={name: {} for name in ttr.SCENARIOS})
            doc.update(bs.audit_sections(1))
            doc.setdefault("profiles", copy.deepcopy(json.loads(bs.V5.read_text()).get("profiles", ttr.STAND_IN)))
        finally:
            bs._v5_file.cache_clear()
    return doc


def windows(d):
    return ttr.windows_of(d) if (d / "events.json").exists() else []


def assert_readers_same(d, p, scenario, audit=True):
    """Every reader of package B18 on the session directory d: the new one gives the frozen one's result."""
    req, ivl = d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl"
    found = windows(d)
    assert_same(before.read_jsonl, tl.read_jsonl, req)
    assert_same(before.read_jsonl, tl.read_jsonl, req, tl.REQUEST_SCHEMA_2)
    assert_same(before.summarize, tl.summarize, req, ivl, session_id=d.name)
    assert_same(before.summarize, tl.summarize, req, ivl, schema=tl.REQUEST_SCHEMA_2)
    assert_same(before.summarize, tl.summarize, req, ivl, schema=tl.REQUEST_SCHEMA)
    assert_same(before.realism, tl.realism, req, ivl, p, scenario, windows=found)
    assert_same(before.measure_phase, lab_trial.measure_phase, d)
    assert_same(before.peak_of, lab_trial.peak_of, d)
    assert_same(before.analysis, lab_trial.analysis, d, p, scenario, found)
    assert_same(lambda: before.load_traffic(d, d.name, found, []),
                lambda: campaign_report.load_traffic(d, d.name, found, []))
    if audit:
        assert_same(before.audit_logs, logs.audit_logs, d, snapshot_times=TIMES)


# The fixtures of scripts/tests/test_traffic_log.py (schema /1).

@pytest.mark.parametrize("name", sorted(sample.EXPECTED))
def test_summarize_and_read_jsonl_of_every_case_of_test_traffic_log(tmp_path, name):
    req_log, ivl_log, session = sample.mutate(name, *sample.build())
    req, ivl = sample.write_pair(tmp_path, req_log, ivl_log)
    for sid in (session, None):
        assert_same(before.summarize, tl.summarize, req, ivl, session_id=sid)
    assert_same(before.read_jsonl, tl.read_jsonl, req)
    assert_same(before.read_jsonl, tl.read_jsonl, ivl, tl.INTERVAL_SCHEMA)


def test_read_jsonl_of_cut_corrupt_and_odd_logs(tmp_path):
    req, ivl = sample.write_pair(tmp_path, *sample.build())
    data = req.read_bytes()
    variants = [data[:-10], data[:-1], data + b"\n", data + b"x", b"", b"\n", b"\n\n", b"{}", b"{}\n", b"[]\n",
                b"\xef\xbb\xbf" + data, data.replace(b"\n", b"\r\n"), data.replace(b"\n", b"\n\n", 3),
                data[:-len(data.splitlines()[-1]) - 1] + b'{"broken": \n', b"\x00\x01\n" + data, b" 1 \n{\"n\": 0}\n",
                data.replace(b'"n": 3,', b'"n": true,'), data.replace(b'"n": 4,', b'"n": 4.0,')]
    rng = random.Random(18)
    lines = data.splitlines(keepends=True)
    for _ in range(40):  # Random lines broken, repeated or swapped.
        broken = list(lines)
        i, j = rng.randrange(len(broken)), rng.randrange(len(broken))
        choice = rng.random()
        if choice < .4:
            broken[i] = broken[i][:rng.randrange(len(broken[i]))] + b"\n"
        elif choice < .7:
            broken.insert(j, broken[i])
        else:
            broken[i], broken[j] = broken[j], broken[i]
        variants.append(b"".join(broken))
    for k, variant in enumerate(variants):
        path = tmp_path / f"v{k}.jsonl"
        path.write_bytes(variant)
        for schema in (None, tl.REQUEST_SCHEMA, tl.REQUEST_SCHEMA_2):
            assert_same(before.read_jsonl, tl.read_jsonl, path, schema)
        assert_same(before.summarize, tl.summarize, path, ivl)
    assert_same(before.read_jsonl, tl.read_jsonl, tmp_path / "missing.jsonl")
    assert_same(before.summarize, tl.summarize, req, tmp_path / "missing.jsonl")
    assert_same(before.summarize, tl.summarize, tmp_path / "missing.jsonl", ivl)


def test_problem_details_stay_capped_in_the_same_order(tmp_path):
    req_log, ivl_log = sample.build()
    for r in req_log[1:-1]:
        if r["type"] == "request":
            r["duration_ms"] = 123.0
    requests = [r for r in req_log if r.get("type") == "request"]
    req_log[1:1] = [dict(requests[0], rid=f"{sample.RUN}-dup-{k % 3}", phase=["x"] if k % 4 else "nowhere")
                    for k in range(30)]
    req, ivl = sample.write_pair(tmp_path, req_log, ivl_log)
    assert_same(before.summarize, tl.summarize, req, ivl)


# The fixtures of scripts/tests/test_traffic_realism.py (schema /2 under the profiles section).

@pytest.mark.parametrize("scenario, event", [("steady", True), ("bursty", False), ("office", True),
                                             ("office_busy", False)])
def test_every_reader_of_a_clean_v5_session(tmp_path, p, scenario, event):
    assert_readers_same(ttr.session(tmp_path, p, scenario, event=event), p, scenario)


@pytest.mark.parametrize("name", list(ttr.MUTATIONS))
def test_every_reader_of_each_cross_check_of_v5_logs(tmp_path, p, name):
    d = ttr.session(tmp_path, p, "steady")
    r, i = ttr._pair(d)
    ttr.MUTATIONS[name](r, i, p)
    ttr._write_pair(d, r, i)
    assert_readers_same(d, p, "steady")


@pytest.mark.parametrize("name", [*ttr.BROKEN, *ttr.OTHER_SIDE])
def test_every_reader_of_each_broken_realism_requirement(tmp_path, p, name):
    scenario, variant = ttr.broken(name) if name in ttr.BROKEN else ttr.OTHER_SIDE[name]
    assert_readers_same(ttr.session(tmp_path, p, scenario, **variant), p, scenario)


@pytest.mark.parametrize("kind, field, log", ttr.WALL_FIELDS, ids=["-".join(x) for x in ttr.WALL_FIELDS])
def test_every_reader_of_each_moved_or_unreadable_wall_time(tmp_path, p, kind, field, log):
    for k, value in enumerate([1.001, -1.001, .999, "missing", None, "garbage", "2026-01-01T00:00:01.100000", 7.5]):
        d = ttr.session(tmp_path / str(k), p, "steady")
        r, i = ttr._pair(d)
        record, _ = ttr._record(r, i, kind, log)
        if value == "missing":
            del record[field]
        elif type(value) is float and abs(value) > .5 and abs(value) < 2:
            record[field] = ttr._later(record[field], value)
        else:
            record[field] = value
        ttr._write_pair(d, r, i, seal=False)
        assert_readers_same(d, p, "steady")


@pytest.mark.parametrize("value", [None, "1767225600.0", True, math.nan, math.inf, 10 ** 400, "missing"])
def test_every_reader_of_a_header_or_an_end_without_a_finite_time(tmp_path, p, value):
    for k, (log, key) in enumerate([("requests", "start_unix"), ("intervals", "start_unix"),
                                    ("requests", "end_mono"), ("intervals", "end_mono")]):
        d = ttr.session(tmp_path / str(k), p, "steady")
        r, i = ttr._pair(d)
        record = (r if log == "requests" else i)[0 if key == "start_unix" else -1]
        if value == "missing":
            del record[key]
        else:
            record[key] = value
        ttr._write_pair(d, r, i)
        assert_readers_same(d, p, "steady")


@pytest.mark.parametrize("after", [.5, 30.001, 1000])
def test_the_log_audit_of_a_stop_moved_after_the_post_marker(tmp_path, p, after):
    d = ttr.session(tmp_path, p, "steady", event=True, measure_s=600, snapshots=600)
    ttr._stop_at(d, ttr._post(d) + after)
    assert_readers_same(d, p, "steady")


# The fixtures of scripts/tests/test_collection_logs.py.

def _evidence_case(session, case):
    """The session of test_collection_logs test_rejects_independent_evidence_failures for `case`."""
    if case == "modified":
        (session / "traffic.log").write_text("changed\n")
    elif case == "missing":
        (session / "traffic.log").unlink()
    elif case == "killed":
        evidence.write(session / "end.json", dict(logs.read_json(session / "end.json"), traffic_rc=-9))
    elif case in ("torn", "malformed"):
        with (session / "traffic_requests.jsonl").open("a") as stream:
            stream.write('{"type":' if case == "torn" else '{"type":"request","rid":[],"interval":{}}\n')
    elif case in ("missing_nginx", "duplicate_nginx", "status_mismatch", "missing_service", "gzip_corrupt"):
        name = "journal" if case == "missing_service" else "session"
        suffix = "journal.txt" if case == "missing_service" else "nginx-access.jsonl"
        path = session / "guest" / (name + "-" + suffix + ".gz")
        if case == "gzip_corrupt":
            path.write_bytes(b"broken gzip")
            return
        lines = gzip.decompress(path.read_bytes()).decode().splitlines(keepends=True)
        if case == "missing_service":
            lines = [line for line in lines if "path=/api/catalog/1 " not in line]
        elif case == "missing_nginx":
            lines.pop()
        elif case == "duplicate_nginx":
            lines.append(lines[-1])
        else:
            lines[-1] = json.dumps(dict(json.loads(lines[-1]), status=503)) + "\n"
        doc_path = session / "guest" / (name + "_segment.json")
        doc = logs.read_json(doc_path)
        doc["files"][0] = evidence.pack(session, name + "-" + suffix, "".join(lines))
        evidence.write(doc_path, doc)
    elif case == "missing_monitor":
        path = session / "host_monitor.jsonl"
        path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")


@pytest.mark.parametrize("case", ["clean", "modified", "missing", "killed", "torn", "malformed", "missing_nginx",
                                  "missing_service", "duplicate_nginx", "status_mismatch", "gzip_corrupt",
                                  "missing_monitor", "no_request_log", "empty_request_log"])
@pytest.mark.parametrize("event", [False, True])
def test_the_log_audit_of_each_case_of_test_collection_logs(tmp_path, case, event):
    d = evidence.build(tmp_path, event=event)
    _evidence_case(d, case)
    if case == "no_request_log":
        (d / "traffic_requests.jsonl").unlink()
    elif case == "empty_request_log":
        (d / "traffic_requests.jsonl").write_bytes(b"")
    for times in (TIMES, ()):
        assert_same(before.audit_logs, logs.audit_logs, d, snapshot_times=times)


def test_the_log_audit_of_a_missing_session(tmp_path):
    assert_same(before.audit_logs, logs.audit_logs, tmp_path)


# The sessions of the audit self-test.

def pytest_generate_tests(metafunc):
    if "selftest_case" in metafunc.fixturenames:
        from scripts.tests.audit_cases import CASES
        metafunc.parametrize("selftest_case", [case.id for case in CASES])


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    """(protocol, its path) of the small schema-3 protocol of test_audit_selftest.py, every case of its CASES."""
    from scripts.tests.test_audit_selftest import small_doc
    root = tmp_path_factory.mktemp("selftest")
    path = bs.write_protocol(root / "protocol.json", small_doc(bs.profile_dir(root / "profile")))
    return collection.protocol(path), path


def test_the_log_audit_of_the_session_of_every_case_of_the_self_test(tmp_path, small, selftest_case):
    from scripts.tests import audit_cases
    p, path = small
    case = {case.id: case for case in audit_cases.CASES}[selftest_case]
    build = audit_cases.clean_session if case.session is None else case.session
    session = build(tmp_path / "case", p, path, audit_cases.SESSION)
    result = case.mutate(session.directory, p, copy.deepcopy(session.result))
    times = (session.result if result is None else result)["casy"]
    for archived in (False, True):
        assert_same(before.audit_logs, logs.audit_logs, session.directory, snapshot_times=times,
                    archived_raw=archived)


def test_the_session_audit_of_the_clean_session_of_the_self_test(tmp_path, small, monkeypatch):
    """collection.audit_session with the log audit of df3cee5 and with the new one: the same record but the hashes of
    the code."""
    from scripts.tests import audit_cases
    p, path = small
    session = audit_cases.clean_session(tmp_path / "clean", p, path, audit_cases.SESSION)
    found = []
    for audit_logs in (before.audit_logs, logs.audit_logs):
        monkeypatch.setattr(collection, "audit_logs", audit_logs)
        audit = bs.audit(session, p, output=tmp_path / f"audit{len(found)}.json")
        values = {k: v for k, v in audit.values.items()
                  if k not in ("auditor_sha256", "features", "features_sha256", "extractor_sha256")}
        found.append((audit.code, typed(values)))
    assert found[0] == found[1] and found[0][0] == 0


# Random breaks of the logs and segments of synthetic v5 sessions.

WEIRD = [None, "x", "", True, False, 0, 1, -1, 2.5, -0.0, math.nan, math.inf, 10 ** 30, 10 ** 400, [], {}, [1],
         {"a": 1}, "2026-01-01T00:00:00", "2026-01-01T00:00:00+00:00", "200", 200, 404, "measure", "ok", "request",
         "arrival", "/api/orders", "POST", 3, 7, "zakaznik0001"]
KEYS = ["type", "rid", "interval", "phase", "outcome", "status", "method", "route", "duration_ms", "t_start_mono",
        "t_end_mono", "t_start_utc", "t_end_utc", "user_session", "step", "object", "intended_status", "think_s",
        "response_bytes", "admitted", "active", "customer", "drop_reason", "t_mono", "t_utc", "offered_sessions",
        "admitted_sessions", "dropped_sessions", "planned_sessions", "active_max", "mono_start", "mono_end",
        "duration_s", "hist", "hist_ok", "status_codes", "requests", "ok", "end_mono", "end_utc", "records",
        "requests_logged", "clean", "write_errors", "arrivals", "user_sessions_completed", "start_unix", "envelope",
        "rate", "profile", "run_id", "session_id", "config", "schema", "n", "seeds"]
SEGMENT_LINES = [b"\xff\xfe no utf-8\n", b"caf\xc3\xa9\n", b"a\rb\n", b"x\xe2\x80\xa8y\n", b"\x85z\n", b"\n",
                 b"\xe2\x82\n", b"2026-01-01T00:00:02.000000+00:00 guest python3[101]: Traceback (most recent call "
                 b"last):\n", b"yesterday guest systemd[1]: Started hyptcn-lab@orders.service - x.\n", b"\xc3"]


def _break_records(rng, records):
    for _ in range(rng.randint(1, 3)):
        if not records:
            return
        i, choice = rng.randrange(len(records)), rng.random()
        if choice < .4:
            records[i][rng.choice(KEYS)] = copy.deepcopy(rng.choice(WEIRD))
        elif choice < .6 and records[i]:
            del records[i][rng.choice(list(records[i]))]
        elif choice < .7:
            records.insert(rng.randrange(len(records) + 1), copy.deepcopy(records[i]))
        elif choice < .8:
            j = rng.randrange(len(records))
            records[i], records[j] = records[j], records[i]
        elif choice < .87:
            del records[i]
        else:
            others = [x for x in records if x.get("type") == records[i].get("type") and x is not records[i]]
            key = rng.choice(["rid", "user_session", "interval", "t_start_mono", "t_mono", "phase"])
            if others and key in records[i]:
                records[i][key] = copy.deepcopy(rng.choice(others).get(key))


def _write_broken(rng, path, schema, records):
    lines = [json.dumps({"schema": schema, "n": n, **r}) + "\n" for n, r in enumerate(records)]
    if rng.random() < .15:
        lines.insert(rng.randrange(len(lines) + 1), rng.choice(["not json\n", "\n", "[1, 2]\n", '{"a": [\n']))
    data = "".join(lines).encode()
    path.write_bytes(data[:rng.randrange(len(data))] if rng.random() < .07 and data else data)


def _break_segment(rng, d):
    name, suffix = rng.choice([("session", "nginx-access.jsonl"), ("journal", "journal.txt"),
                               ("pre", "nginx-access.jsonl"), ("session", "nginx-error.log")])
    doc_path = d / "guest" / (name + "_segment.json")
    doc = logs.read_json(doc_path)
    entry = next(f for f in doc["files"] if f["name"].endswith("-" + suffix))
    lines = gzip.decompress((d / "guest" / entry["file"]).read_bytes()).splitlines(keepends=True)
    choice = rng.random()
    if choice < .3 and lines and suffix.endswith(".jsonl"):
        i = rng.randrange(len(lines))
        row = json.loads(lines[i])
        row[rng.choice(["rid", "status", "method", "uri", "msec", "forwarded_rid", "schema"])] = rng.choice(WEIRD)
        lines[i] = (json.dumps(row) + "\n").encode()
    elif choice < .45 and lines:
        del lines[rng.randrange(len(lines))]
    elif choice < .55 and lines:
        lines.append(lines[rng.randrange(len(lines))])
    else:
        lines.insert(rng.randrange(len(lines) + 1), rng.choice(SEGMENT_LINES))
    text = b"".join(lines)
    gz = d / "guest" / entry["file"]
    gz.write_bytes(gzip.compress(text))
    if rng.random() < .9:  # Mostly with its record, so that the checks after the hashes run.
        entry.update(sha256=hashlib.sha256(text).hexdigest(), bytes=len(text), lines=text.count(b"\n"),
                     terminated=text.endswith(b"\n") or not text, gz_bytes=gz.stat().st_size,
                     gz_sha256=logs.digest(gz), file_sha256=logs.digest(gz))
        evidence.write(doc_path, doc)


@pytest.mark.parametrize("seed", range(6))
def test_every_reader_of_randomly_broken_logs(tmp_path, p, seed):
    rng = random.Random(seed)
    bases = {(scenario, event): ttr.session(tmp_path / f"{scenario}-{event}", p, scenario, event=event)
             for scenario, event in (("steady", True), ("office", True), ("steady", False))}
    for case in range(25):
        scenario, event = rng.choice(list(bases))
        d = tmp_path / str(case) / "synthetic-session"
        shutil.copytree(bases[(scenario, event)], d)
        r, i = ttr._pair(d)
        which = rng.random()
        if which < .8:
            _break_records(rng, r if which < .45 else i)
            if which >= .65:
                _break_records(rng, r)
        _write_broken(rng, d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA_2, r)
        _write_broken(rng, d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA_2, i)
        if which >= .8 or rng.random() < .2:
            _break_segment(rng, d)
        if rng.random() < .5:
            evidence.seal(d)
        assert_readers_same(d, p, scenario)
        shutil.rmtree(tmp_path / str(case))


# Package B18's own parts: the decoding of a segment in pieces, its lines, the counts of the manifest.

def test_a_segment_decoded_in_pieces_raises_the_error_of_decoding_it_whole(tmp_path, monkeypatch):
    rng = random.Random(1887)
    monkeypatch.setattr(logs, "CHUNK_BYTES", 7)  # Pieces that split the sequences of UTF-8 bytes.
    pieces = [b"a", b"\n", b"\r", b"\xc3\xa9", b"\xe2\x82\xac", b"\xf0\x9f\x98\x80", b"\xff", b"\x80", b"\xc3",
              b"\xe2\x82", b"\xf0\x9f", b"\xed\xa0\x80", b"\xc0\xaf"]
    for k in range(400):
        content = b"".join(rng.choice(pieces[:6] if rng.random() < .3 else pieces)
                           for _ in range(rng.randint(0, 40)))
        path = tmp_path / f"s{k}.gz"
        path.write_bytes(gzip.compress(content))
        size, sha256, lines, ends, error = logs.scan_segment(path, True)
        assert (size, sha256, lines, ends) == (len(content), hashlib.sha256(content).hexdigest(),
                                               content.count(b"\n"), content.endswith(b"\n"))
        try:
            content.decode("utf-8")
            expected = None
        except UnicodeDecodeError as whole:
            expected = f"{type(whole).__name__}: {whole}"
        assert (None if error is None else f"{type(error).__name__}: {error}") == expected
        assert error is None or isinstance(error, UnicodeDecodeError)
        if expected is None:
            assert list(logs.segment_lines(path)) == content.decode("utf-8").splitlines()


def test_the_manifest_counts_lines_as_before(tmp_path, monkeypatch):
    monkeypatch.setattr(logs, "CHUNK_BYTES", 3)
    for k, data in enumerate([b"", b"\n", b"a", b"a\n", b"a\nb", b"\r\n\r\n", b"x" * 10 + b"\n" * 7, b"\n" * 9 + b"y"]):
        path = tmp_path / f"f{k}.jsonl"
        path.write_bytes(data)
        assert collection.file_record(path) == before.file_record(path)
        assert logs.line_count(path) == (data.count(b"\n"), len(data), data.endswith(b"\n"))


# The request log is read as a stream.

def test_no_reader_reads_the_request_log_whole(tmp_path, p, monkeypatch):
    """read_jsonl, Path.read_bytes and Path.read_text of the request log refused, and so are read() without a size and
    readlines() of a file of it that open, io.open or Path.open opened (Q88; reading it by lines or in pieces is
    allowed): summarize, realism, the log audit, the readers of scripts/lab_trial.py and scripts/campaign_report.py
    still give their results, and each of them opened the request log through the guard; and the compact index of the
    log audit holds no record."""
    d = ttr.session(tmp_path, p, "steady", event=True)
    found = windows(d)
    expected = {"summarize": tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl"),
                "realism": tl.realism(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", p, "steady",
                                      windows=found),
                "audit": logs.audit_logs(d, snapshot_times=TIMES), "analysis": lab_trial.analysis(d, p, "steady", found),
                "peak": lab_trial.peak_of(d), "load": campaign_report.load_traffic(d, d.name, found, [])}
    request_log = (d / "traffic_requests.jsonl").resolve()

    def refuse(original):
        def read(self, *args, **kwargs):
            assert Path(self).resolve() != request_log, "the request log read whole"
            return original(self, *args, **kwargs)
        return read
    real = tl.read_jsonl
    monkeypatch.setattr(Path, "read_bytes", refuse(Path.read_bytes))
    monkeypatch.setattr(Path, "read_text", refuse(Path.read_text))
    monkeypatch.setattr(tl, "read_jsonl", lambda path, schema=None: (
        pytest.fail("read_jsonl of the request log") if Path(path).resolve() == request_log else real(path, schema)))

    class Stream:
        """A file of the request log that may be read by lines or in pieces only."""

        def __init__(self, stream):
            self._stream = stream

        def read(self, size=-1, /):
            if size is None or size < 0:
                pytest.fail("the request log read whole (read)")
            return self._stream.read(size)

        def readlines(self, hint=-1, /):
            pytest.fail("the request log read whole (readlines)")

        def __iter__(self):
            return iter(self._stream)

        def __next__(self):
            return next(self._stream)

        def __enter__(self):
            self._stream.__enter__()
            return self

        def __exit__(self, *exc):
            return self._stream.__exit__(*exc)

        def __getattr__(self, name):
            return getattr(self._stream, name)
    real_open, opened = io.open, []

    def guarded_open(file, *args, **kwargs):
        stream = real_open(file, *args, **kwargs)
        if isinstance(file, (str, bytes, os.PathLike)) and Path(os.fsdecode(file)).resolve() == request_log:
            opened.append(file)
            return Stream(stream)
        return stream
    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    readers = {"summarize": lambda: tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl"),
               "realism": lambda: tl.realism(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl", p, "steady",
                                             windows=found),
               "audit": lambda: logs.audit_logs(d, snapshot_times=TIMES),
               "analysis": lambda: lab_trial.analysis(d, p, "steady", found), "peak": lambda: lab_trial.peak_of(d),
               "load": lambda: campaign_report.load_traffic(d, d.name, found, [])}
    for name, read in readers.items():
        count = len(opened)
        assert read() == expected[name], name
        assert len(opened) > count, f"{name} did not open the request log through the guard"
    index = logs.RequestIndex(d / "traffic_requests.jsonl")
    assert len(index) == expected["summarize"]["records"]["request_records"]
    assert set(index.columns) == set(logs.RequestIndex.OBJECT_FIELDS + logs.RequestIndex.NUMBER_FIELDS
                                     + logs.RequestIndex.TIME_FIELDS)
    assert not any(isinstance(value, dict) for column in index.columns.values() for value in column)
    assert all(type(index.columns[name]) is tl.Values for name in logs.RequestIndex.NUMBER_FIELDS)
