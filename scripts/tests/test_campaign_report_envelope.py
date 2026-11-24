"""The mode envelope of scripts/campaign_report.py (item P1 of the G2 preparation): the traffic envelope of saved
sessions drawn again from the protocol, the lead's answer to question Q30 (2026-11-24) and point 3 of his comments on
B10 (dokazy/B10/PRIPOMIENKY.md).

The audit does not redraw the envelope (scripts/collection_logs.py says so in its rule). The mode does it, outside the
measurement code, over the sessions of G2, of both rehearsals and over every accepted session of a closed campaign;
a mismatch is a deviation of the campaign and a finding for the lead.

The sessions here lie on the protocol's timeline and come through the producers' own code, as a collection run makes
them: protocol.json is a copy of the protocol (run_session), session.json carries the traffic block of
collection._v5_traffic (written by collection.write_json), host_traffic.main parses the command line of
collection.traffic_command and its prepare_v5 draws the envelope (main_v5, which would start the run, is replaced),
and the first line of both traffic logs is SessionRecorder.header of that run, as the log writer writes it. The
synthetic logs of test_collection_logs.v5_traffic cannot serve: their span between warmup_s and dur is 10 s, while
the longest peak takes 240 s. Expected reasons are written out here, never made by the mode's code. No VM, no network,
nothing written outside tmp_path.
"""
import hashlib
import json
from pathlib import Path
import random
import shutil
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from scripts import campaign_report as cr
from scripts import collection
from scripts import host_traffic as ht

REPO = Path(__file__).resolve().parents[2]
V5 = REPO / "config/collection-v5.json"
GENERATOR = REPO / "scripts/host_traffic.py"
SEEDS = {"traffic": 11, "traffic_arrivals": 12, "traffic_choices": 13, "traffic_sizes": 14}
REQUESTS, INTERVALS = "traffic_requests.jsonl", "traffic_intervals.jsonl"
LOGS = {REQUESTS: ("requests", "hyptcn3/traffic-request/2"), INTERVALS: ("intervals", "hyptcn3/traffic-interval/2")}
# --rate of a diagnostic run while the protocol's rate is null (until G2); the envelope does not depend on it.
RATE = 0.5
PROVENANCE = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.


@pytest.fixture(autouse=True)
def one_git_state(monkeypatch):
    """The record's commit without asking git (the provenance keys are checked, not the commit)."""
    monkeypatch.setattr(cr, "git_identity", lambda: {"commit": "synthetic", "dirty": False, "changed_paths": 0})


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protocol_copy(tmp_path, change, name="protocol-copy.json"):
    """A copy of the real protocol whose document `change` changed."""
    doc = json.loads(V5.read_text())
    change(doc)
    path = tmp_path / name
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return path


def command_line(d, protocol=None):
    """The generator's command line that run_session makes for the session in d (collection.traffic_command), with
    --protocol `protocol` instead of the session's protocol.json when given."""
    meta = json.loads((d / "session.json").read_text())
    p = collection.for_vm(json.loads((d / "protocol.json").read_text()), "a")
    argv = [str(x) for x in collection.traffic_command(p, meta, d)[2:]]
    if protocol is not None:
        argv[argv.index("--protocol") + 1] = str(protocol)
    return argv


def start(argv):
    """(args, run) of the generator's main() on argv, its real argparse and prepare_v5; main_v5, which would start the
    run, only takes them."""
    started = {}
    with mock.patch.object(ht, "main_v5", lambda parser, args, run: started.update(args=args, run=run) or 0):
        assert ht.main(argv) == 0
    return started["args"], started["run"]


def generator_refusal(argv, capsys):
    """The message with which the generator's main() refuses argv, by its real argparse and prepare_v5; main_v5,
    which would start the run, is never reached."""
    def reached(parser, args, run):
        raise AssertionError("the generator accepted the command line")
    with mock.patch.object(ht, "main_v5", reached), pytest.raises(SystemExit):
        ht.main(argv)
    return capsys.readouterr().err.splitlines()[-1].split("error: ", 1)[1]


def make_session(base, name, scenario="eshop_low", seeds=SEEDS, protocol=V5):
    """A session directory of `protocol` (VM a, the protocol's cycles) with the files the mode reads, made by the
    producers' code (module docstring). Returns the directory."""
    d = base / name
    d.mkdir(parents=True)
    raw = Path(protocol).read_bytes()
    (d / "protocol.json").write_bytes(raw)
    p = collection.for_vm(json.loads(raw), "a")
    s = p["scenarios"][scenario]
    rate, source = (RATE, "command line") if s["rate"] is None else (s["rate"], "protocol")
    collection.write_json(d / "session.json", {
        "schema": collection.SESSION_SCHEMA, "session_id": name, "scenario": scenario, "seed": seeds["traffic"],
        "cycles": p["cycles"], "protocol_sha256": hashlib.sha256(raw).hexdigest(),
        "source_sha256": {"scripts/host_traffic.py": sha(GENERATOR)},  # run_session records every source file.
        "traffic": collection._v5_traffic(SimpleNamespace(scenario=scenario), p, rate, source, dict(seeds),
                                          p["cycles"])})
    args, run = start(command_line(d))
    recorder = ht.SessionRecorder(args, run, threading.Event())
    for log, (key, schema) in LOGS.items():
        (d / log).write_text(json.dumps({"schema": schema, "n": 0, **recorder.header(key)}) + "\n")
    return d


def header(d, log):
    return json.loads((d / log).read_text().splitlines()[0])


def edit_header(d, log, change):
    """Let `change` change the header (the first line) of a log of d."""
    path = d / log
    lines = path.read_text().splitlines(keepends=True)
    doc = json.loads(lines[0])
    change(doc)
    lines[0] = json.dumps(doc) + "\n"
    path.write_text("".join(lines))


def edit_session(d, change):
    meta = json.loads((d / "session.json").read_text())
    change(meta)
    (d / "session.json").write_text(json.dumps(meta, indent=2) + "\n")


def move_knot(key, by=1e-6):
    """A change of a header: the middle knot of envelope[key] moved by `by` (1e-6: the logs' last decimal)."""
    def change(doc):
        values = doc["envelope"][key]
        values[len(values) // 2] += by
    return change


def envelope(tmp_path, *dirs, protocol=V5, out=None):
    """(exit code, record or None) of the mode over `dirs`; the record is a new file under tmp_path."""
    out = tmp_path / "envelope.json" if out is None else out
    code = cr.main(["envelope", *map(str, dirs), "--protocol", str(protocol), "--out", str(out)])
    return code, json.loads(out.read_text()) if out.exists() else None


def only(record):
    """The one session of a record."""
    (entry,) = record["values"]["sessions"]
    return entry


# ---------------------------------------------------------------- a match

def test_sessions_of_the_real_protocol_match_for_every_profile(tmp_path, capsys):
    """Item 2 of P1: config/collection-v5.json as the protocol, each of its scenarios and so each of its profiles,
    three traffic seeds each. One line per session; the record has the provenance of check E and lists, per session,
    the four files read with their sha256; the mode changed none of them and wrote nothing beside them."""
    doc = json.loads(V5.read_text())
    assert {s["profile"] for s in doc["scenarios"].values()} == set(doc["profiles"]) == {"eshop", "corp"}
    dirs = [make_session(tmp_path / "sessions", f"{scenario}-{seed}", scenario, dict(SEEDS, traffic=seed))
            for scenario in sorted(doc["scenarios"]) for seed in (0, 11, 2026)]
    before = {path: sha(path) for d in dirs for path in sorted(d.iterdir())}
    code, record = envelope(tmp_path, *dirs)
    assert code == 0
    assert [line.split() for line in capsys.readouterr().out.splitlines()] == [["match", d.name, str(d)] for d in dirs]
    assert all(key in record for key in PROVENANCE) and "values" in record
    assert (record["schema"], record["commit"], record["n"]) == ("hyptcn3/envelope-check/1", "synthetic", len(dirs))
    v = record["values"]
    assert (v["protocol"], v["generator"], v["exit_code"], v["mismatch"], v["data_error"]) == (
        {"path": str(V5), "sha256": sha(V5)}, {"path": str(GENERATOR), "sha256": sha(GENERATOR)}, 0, [], [])
    assert v["counts"] == {"match": len(dirs), "mismatch": 0, "data_error": 0}
    for d, entry in zip(dirs, v["sessions"]):
        assert (entry["session_id"], entry["path"], entry["result"], entry["reasons"]) == (d.name, str(d), "match", [])
        assert {f["name"]: (f["path"], f["sha256"]) for f in entry["files"]} == {
            path.name: (str(path), digest) for path, digest in before.items() if path.parent == d}
        assert entry["knots"] == len(header(d, REQUESTS)["envelope"]["t_s"]) and entry["draws"] >= 1
    assert {path: sha(path) for d in dirs for path in sorted(d.iterdir())} == before


def test_an_envelope_the_generator_drew_again_matches(tmp_path):
    """The redraw loop of draw_envelope: under a copy of the protocol whose scenario_rule.min_peak_to_mean is 3 (under
    the real 2 every draw passes), seed 0 takes several draws for both profiles, and the mode follows the protocol's
    bound to the same envelope (a bound of 1 would take the first draw, which differs)."""
    other = protocol_copy(tmp_path, lambda doc: doc["scenario_rule"].update(min_peak_to_mean=3))
    dirs = [make_session(tmp_path, scenario, scenario, dict(SEEDS, traffic=0), protocol=other)
            for scenario in ("eshop_low", "corp_high")]
    code, record = envelope(tmp_path, *dirs, protocol=other)
    assert code == 0 and [s["result"] for s in record["values"]["sessions"]] == ["match", "match"]
    assert all(s["draws"] > 1 for s in record["values"]["sessions"])
    for d, profile in zip(dirs, ("eshop", "corp")):
        first, _ = ht.draw_envelope(json.loads(other.read_text())["profiles"][profile]["arrivals"], random.Random(0),
                                    3720.0, 120.0, 1)
        assert first.as_dict() != header(d, REQUESTS)["envelope"]


# ---------------------------------------------------------------- mismatches

@pytest.mark.parametrize("key", ["t_s", "level"])
def test_one_knot_moved_is_a_mismatch(tmp_path, capsys, key):
    """Item 1 of P1: one knot moved by 1e-6 in both headers; exact, no tolerance."""
    d = make_session(tmp_path, "s1")
    knots = len(header(d, REQUESTS)["envelope"]["t_s"])
    drawn = header(d, REQUESTS)["envelope"][key][knots // 2]
    for log in LOGS:
        edit_header(d, log, move_knot(key))
    code, record = envelope(tmp_path, d)
    entry = only(record)
    assert (code, entry["result"], record["values"]["mismatch"]) == (1, "mismatch", ["s1"])
    assert entry["reasons"] == [
        f"header of {log}: envelope.{key}: 1 of {knots} knots differ from the drawn ones, the first [{knots // 2}] is "
        f"{json.dumps(drawn + 1e-6)}, drawn {json.dumps(drawn)}" for log in LOGS]
    assert capsys.readouterr().out.startswith(f"mismatch s1 {d}: header of {REQUESTS}: envelope.{key}: 1 of ")


def test_a_knot_left_out_is_a_mismatch(tmp_path):
    d = make_session(tmp_path, "s1")
    knots = len(header(d, REQUESTS)["envelope"]["t_s"])

    def leave_out(doc):
        for key in ("t_s", "level"):
            del doc["envelope"][key][knots // 2]
    for log in LOGS:
        edit_header(d, log, leave_out)
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [
        f"header of {log}: envelope.{key} has {knots - 1} knots, the drawn one {knots}"
        for log in LOGS for key in ("t_s", "level")]


def test_another_seed_in_session_json_is_a_mismatch(tmp_path):
    """Item 1 of P1: session.json names another traffic seed than the one the logs were drawn from; the mode draws
    from session.json's seed (not the header's), so the envelope differs as well as the seeds."""
    d = make_session(tmp_path, "s1")

    def another(meta):
        meta["seed"] = meta["traffic"]["seeds"]["traffic"] = 12
    edit_session(d, another)
    code, record = envelope(tmp_path, d)
    entry = only(record)
    assert (code, entry["result"], entry["inputs"]["seed"]) == (1, "mismatch", 12)
    for log in LOGS:
        assert f"header of {log}: seeds.traffic is 11, session.json traffic.seeds.traffic is 12" in entry["reasons"]
        assert f"header of {log}: config.seed is 11, session.json traffic.seeds.traffic is 12" in entry["reasons"]
        assert any(reason.startswith(f"header of {log}: envelope.") for reason in entry["reasons"])


@pytest.mark.parametrize("change, where, found, expected", [
    (lambda q: q["arrivals"].update(step_s=31), ".arrivals.step_s", "31", "30"),
    (lambda q: q.update(max_concurrent=499), ".max_concurrent", "499", "500"),
    (lambda q: q["think_s"].pop("max"), ".think_s.max", "absent", None),
    (lambda q: q.update(extra=1), ".extra", "1", "absent"),
], ids=["arrivals", "value", "key_absent", "key_added"])
def test_profile_parameters_that_differ_from_the_protocol_are_a_mismatch(tmp_path, change, where, found, expected):
    """Item 1 of P1: the headers' profile_parameters against the protocol's profile. The envelope is drawn from the
    protocol's arrivals, not the header's copy, so a changed step_s is named once per header and nothing else."""
    d = make_session(tmp_path, "s1")
    expected = expected or json.dumps(json.loads(V5.read_text())["profiles"]["eshop"]["think_s"]["max"])
    for log in LOGS:
        edit_header(d, log, lambda doc: change(doc["profile_parameters"]))
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [
        f"header of {log}: profile_parameters{where} is {found}, the protocol's profiles.eshop{where} is {expected}"
        for log in LOGS]


def test_headers_that_disagree_on_the_envelope_are_a_mismatch(tmp_path):
    """Item 1 of P1: the two headers disagree; each header is compared with the drawn envelope, and the two with each
    other (the executor's judgment: a mismatch, since the logs of one run carry one envelope)."""
    d = make_session(tmp_path, "s1")
    knots = len(header(d, INTERVALS)["envelope"]["level"])
    drawn = header(d, INTERVALS)["envelope"]["level"][knots // 2]
    edit_header(d, INTERVALS, move_knot("level"))
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [
        f"header of {INTERVALS}: envelope.level: 1 of {knots} knots differ from the drawn ones, the first "
        f"[{knots // 2}] is {json.dumps(drawn + 1e-6)}, drawn {json.dumps(drawn)}",
        f"the headers of {REQUESTS} and {INTERVALS} differ in: envelope"]


def test_headers_of_two_runs_are_a_mismatch(tmp_path):
    d = make_session(tmp_path, "s1")
    edit_header(d, INTERVALS, lambda doc: doc.update(run_id="0123456789ab"))
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [f"the headers of {REQUESTS} and {INTERVALS} differ in: run_id"]


def test_a_boolean_in_a_header_is_no_number(tmp_path):
    """ENVELOPE_RULE: numbers compare by value without tolerance (the headers' config.dur 3720.0 equals session.json's
    dur_s 3720, as the audit compares them), but true is no 1."""
    d = make_session(tmp_path, "s1", seeds=dict(SEEDS, traffic=1))
    for log in LOGS:
        edit_header(d, log, lambda doc: doc["seeds"].update(traffic=True))
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [
        f"header of {log}: seeds.traffic is true, session.json traffic.seeds.traffic is 1" for log in LOGS]


@pytest.mark.parametrize("field, value, own, theirs", [
    ("seed", 99, "traffic.seeds.traffic", "11"),
    ("scenario", "eshop_high", "traffic.scenario", '"eshop_low"'),
], ids=["seed", "scenario"])
def test_session_json_that_disagrees_with_itself_is_a_mismatch(tmp_path, field, value, own, theirs):
    d = make_session(tmp_path, "s1")
    edit_session(d, lambda meta: meta.update({field: value}))
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [f"session.json: {field} is {json.dumps(value)}, its {own} is "
                                                     f"{theirs}"]


def test_a_span_that_is_not_the_planned_run_of_the_protocol_is_a_mismatch(tmp_path):
    """The span of the envelope is the planned run of the protocol, warmup_s + cycles x interval_s
    (collection._v5_traffic): 120 + 700 x 5 = 3620 s for 700 cycles, while the logs span 3720 s."""
    d = make_session(tmp_path, "s1")
    edit_session(d, lambda meta: meta.update(cycles=700))
    code, record = envelope(tmp_path, d)
    assert code == 1 and only(record)["reasons"] == [
        "session.json: traffic.dur_s is 3720, the planned run of the protocol (warmup_s + cycles x interval_s) is 3620"]


def test_a_planned_run_the_generator_refuses_is_a_mismatch(tmp_path, capsys):
    """The timeline of the synthetic logs of test_collection_logs.v5_traffic (warmup_s 120 s, dur 130 s: two cycles):
    the generator refuses that run, so no header of it can exist; the reason quotes the generator's words."""
    d = make_session(tmp_path, "s1")

    def two_cycles(meta):
        meta["cycles"], meta["traffic"]["dur_s"] = 2, 130
    edit_session(d, two_cycles)
    for log in LOGS:
        edit_header(d, log, lambda doc: doc["config"].update(dur=130.0))
    words = "[--warmup-s, --dur] is shorter than the longest peak (arrivals.peak_s 240 s)"
    assert generator_refusal(command_line(d), capsys) == words
    code, record = envelope(tmp_path, d)
    entry = only(record)
    assert (code, entry["draws"], entry["knots"]) == (1, None, None)
    assert entry["reasons"] == [f"redraw: the generator refuses the run session.json plans ({words}), so no header of "
                                "it can carry an envelope"]


# ---------------------------------------------------------------- data errors

def test_a_protocol_that_is_not_the_sessions_is_a_data_error(tmp_path):
    """Item 1 of P1: the protocol's sha256 differs from that of the session's protocol.json, from session.json and
    from both headers; the session has no verdict."""
    d = make_session(tmp_path, "s1")
    other = protocol_copy(tmp_path, lambda doc: doc.update(note=doc["note"] + " (a copy)"))
    mine, theirs = sha(other), sha(V5)
    code, record = envelope(tmp_path, d, protocol=other)
    entry = only(record)
    assert (code, entry["result"], record["values"]["data_error"], entry["draws"]) == (2, "data_error", ["s1"], None)
    assert entry["reasons"] == [
        f"protocol: its sha256 {mine} differs from that of the session's protocol.json {theirs}",
        f"protocol: its sha256 {mine} differs from session.json protocol_sha256 {theirs}",
        *(f'protocol: its sha256 {mine} differs from the protocol_sha256 of the header of {log}, "{theirs}"'
          for log in LOGS)]


@pytest.mark.parametrize("where", ["protocol.json", "session.json", REQUESTS, INTERVALS])
def test_each_binding_of_the_protocol_is_a_data_error_of_its_own(tmp_path, where):
    d = make_session(tmp_path, "s1")
    wrong = "0" * 64
    if where == "protocol.json":
        (d / where).write_bytes(V5.read_bytes() + b"\n")
        reason = f"that of the session's protocol.json {sha(d / where)}"
    elif where == "session.json":
        edit_session(d, lambda meta: meta.update(protocol_sha256=wrong))
        reason = f"session.json protocol_sha256 {wrong}"
    else:
        edit_header(d, where, lambda doc: doc.update(protocol_sha256=wrong))
        reason = f'the protocol_sha256 of the header of {where}, "{wrong}"'
    code, record = envelope(tmp_path, d)
    assert code == 2 and only(record)["reasons"] == [f"protocol: its sha256 {sha(V5)} differs from {reason}"]


@pytest.mark.parametrize("recorded", ["0" * 64, None], ids=["another", "absent"])
def test_a_session_of_another_generator_is_a_data_error(tmp_path, recorded):
    """The envelope is drawn by the session's own generator: the sha256 of scripts/host_traffic.py that session.json
    source_sha256 recorded (the executor's judgment, G2 preparation); another generator's envelope says nothing."""
    d = make_session(tmp_path, "s1")
    edit_session(d, lambda meta: meta["source_sha256"].update({"scripts/host_traffic.py": recorded})
                 if recorded else meta["source_sha256"].pop("scripts/host_traffic.py"))
    code, record = envelope(tmp_path, d)
    shown = f'"{recorded}"' if recorded else "absent"
    assert code == 2 and only(record)["reasons"] == [
        f"generator: the sha256 of scripts/host_traffic.py here is {sha(GENERATOR)}, session.json source_sha256 "
        f"records {shown} for it (run this mode from the session's commit)"]


@pytest.mark.parametrize("name", ["session.json", "protocol.json", REQUESTS, INTERVALS, "directory"])
def test_a_missing_file_is_a_data_error(tmp_path, capsys, name):
    """Item 1 of P1: a missing log or session.json (or the session's protocol.json, or the directory)."""
    d = make_session(tmp_path, "s1")
    if name == "directory":
        shutil.rmtree(d)
    else:
        (d / name).unlink()
    code, record = envelope(tmp_path, d)
    entry = only(record)
    assert (code, entry["result"]) == (2, "data_error")
    assert entry["reasons"] == ["not a directory" if name == "directory" else f"{name}: missing"]
    sid = "-" if name in ("session.json", "directory") else "s1"
    assert capsys.readouterr().out.startswith(f"data_error {sid} {d}: ")


@pytest.mark.parametrize("content, reason", [
    (b"", "no complete first line"),
    (b'{"schema": "hyptcn3/traffic-request/2", "n": 0, "type": "header"', "no complete first line"),
    (b"not json\n", "its first line is not a header record"),
    (b'{"schema": "hyptcn3/traffic-request/2", "n": 0, "type": "request"}\n', "its first line is not a header record"),
], ids=["empty", "torn", "not_json", "not_a_header"])
def test_a_log_without_its_header_as_first_line_is_a_data_error(tmp_path, content, reason):
    d = make_session(tmp_path, "s1")
    (d / REQUESTS).write_bytes(content)
    code, record = envelope(tmp_path, d)
    assert code == 2 and only(record)["reasons"] == [f"{REQUESTS}: {reason}"]


def test_a_log_of_another_schema_is_a_data_error(tmp_path):
    d = make_session(tmp_path, "s1")
    edit_header(d, INTERVALS, lambda doc: doc.update(schema="hyptcn3/traffic-interval/1"))
    code, record = envelope(tmp_path, d)
    assert code == 2 and only(record)["reasons"] == [
        f'{INTERVALS}: its header has the schema "hyptcn3/traffic-interval/1", not hyptcn3/traffic-interval/2 (the '
        "logs of the v5 profiles)"]


@pytest.mark.parametrize("change, reason", [
    (lambda meta: meta["traffic"]["seeds"].update(traffic=True), "traffic.seeds.traffic is true, not an integer >= 0"),
    (lambda meta: meta["traffic"].update(dur_s="3720"), 'traffic.dur_s is "3720", not a finite number'),
    (lambda meta: meta["traffic"].update(profile="lab"),
     'traffic.profile is "lab", not a profile of the v5 generator (eshop, corp)'),
    (lambda meta: meta.pop("cycles"), "cycles is absent"),
], ids=["boolean_seed", "text_dur", "legacy_profile", "no_cycles"])
def test_a_field_of_session_json_absent_or_of_another_type_is_a_data_error(tmp_path, change, reason):
    d = make_session(tmp_path, "s1")
    edit_session(d, change)
    code, record = envelope(tmp_path, d)
    assert code == 2 and only(record)["reasons"] == [f"session.json: {reason}"]


def test_session_json_that_is_no_object_is_a_data_error(tmp_path):
    d = make_session(tmp_path, "s1")
    (d / "session.json").write_text("[]\n")
    code, record = envelope(tmp_path, d)
    assert code == 2 and only(record)["reasons"] == ["session.json: not a JSON object"]


# ---------------------------------------------------------------- several sessions and the exit code

def test_several_sessions_with_one_mismatch_exit_1_and_name_it(tmp_path, capsys):
    """Item 1 of P1: three sessions, the second with a moved knot."""
    dirs = [make_session(tmp_path, "s1", "eshop_low", dict(SEEDS, traffic=1)),
            make_session(tmp_path, "s2", "corp_low", dict(SEEDS, traffic=2)),
            make_session(tmp_path, "s3", "eshop_high", dict(SEEDS, traffic=3))]
    for log in LOGS:
        edit_header(dirs[1], log, move_knot("t_s"))
    code, record = envelope(tmp_path, *dirs)
    v = record["values"]
    assert (code, v["exit_code"], v["mismatch"], v["data_error"]) == (1, 1, ["s2"], [])
    assert v["counts"] == {"match": 2, "mismatch": 1, "data_error": 0}
    assert [(s["session_id"], s["result"]) for s in v["sessions"]] == [("s1", "match"), ("s2", "mismatch"),
                                                                     ("s3", "match")]
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[:2] for line in lines] == [["match", "s1"], ["mismatch", "s2"], ["match", "s3"]]
    assert f"header of {REQUESTS}: envelope.t_s: 1 of " in lines[1]


def test_a_mismatch_beside_a_data_error_exits_2_and_stays_a_mismatch(tmp_path):
    """How a mix is reported (the executor's judgment): exit 2, since one session has no verdict, while the record
    still names the mismatch as a mismatch."""
    dirs = [make_session(tmp_path, "s1"), make_session(tmp_path, "s2", "corp_high", dict(SEEDS, traffic=5))]
    for log in LOGS:
        edit_header(dirs[0], log, move_knot("level"))
    (dirs[1] / INTERVALS).unlink()
    code, record = envelope(tmp_path, *dirs)
    v = record["values"]
    assert (code, v["exit_code"], v["mismatch"], v["data_error"]) == (2, 2, ["s1"], ["s2"])
    assert v["counts"] == {"match": 0, "mismatch": 1, "data_error": 1}


# ---------------------------------------------------------------- usage errors: nothing is written

@pytest.mark.parametrize("kind", ["file", "dangling_link"])
def test_an_existing_out_is_refused_before_anything_is_read(tmp_path, monkeypatch, capsys, kind):
    """Item 1 of P1: neither the protocol nor a session is read (both are absent here, and their readers fail)."""
    out = tmp_path / "envelope.json"
    if kind == "file":
        out.write_text("kept\n")
    else:
        out.symlink_to(tmp_path / "nowhere.json")

    def unread(*args):
        raise AssertionError("read before --out was refused")
    monkeypatch.setattr(cr, "envelope_protocol", unread)
    monkeypatch.setattr(cr, "envelope_session", unread)
    code = cr.main(["envelope", str(tmp_path / "no-session"), "--protocol", str(tmp_path / "no-protocol.json"),
                    "--out", str(out)])
    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert f"campaign_report: --out already exists, nothing was read or written: {out}" in captured.err
    assert out.read_text() == "kept\n" if kind == "file" else out.is_symlink() and not out.exists()


@pytest.mark.parametrize("change, words", [
    (lambda doc: doc.update(schema="hyptcn3/collection-protocol/2"),
     "protocol schema is not hyptcn3/collection-protocol/3: the v5 profiles are its profiles section"),
    (lambda doc: doc["profiles"]["eshop"]["arrivals"].pop("step_s"), "invalid profiles: "),
    (lambda doc: doc["scenario_rule"].update(min_peak_to_mean=0.5),
     "scenario_rule.min_peak_to_mean is not a number >= 1"),
], ids=["schema", "profiles", "min_peak_to_mean"])
def test_a_protocol_the_generator_would_not_read_is_a_usage_error(tmp_path, capsys, change, words):
    """The protocol is checked once, before any session, as the generator checks it and with its words."""
    d = make_session(tmp_path, "s1")
    other = protocol_copy(tmp_path, change)
    said = generator_refusal(command_line(d, other), capsys)
    assert said.startswith(words)
    code, record = envelope(tmp_path, d, protocol=other)
    captured = capsys.readouterr()
    assert (code, record, captured.out) == (2, None, "")
    assert f"campaign_report: protocol {other}: {said}" in captured.err


def test_an_out_inside_a_session_or_a_session_named_twice_is_refused(tmp_path, capsys):
    d = make_session(tmp_path, "s1")
    files = sorted(d.iterdir())
    code, record = envelope(tmp_path, d, out=d / "envelope.json")
    assert (code, record, sorted(d.iterdir())) == (2, None, files)
    assert f"refusing to write {d / 'envelope.json'} inside the session directory {d}" in capsys.readouterr().err
    code, record = envelope(tmp_path, d, tmp_path / "s1" / ".." / "s1")
    assert (code, record) == (2, None)
    assert f"a session directory is named more than once: {d}" in capsys.readouterr().err


# ---------------------------------------------------------------- the rule and the campaign procedure

def test_the_paragraph_of_q30_names_the_command_and_what_to_do_on_exit_1():
    """Item 3 of P1: docs/AUTOMATICKY_ZBER.sk.md names the command, how to read its result and what exit 1 asks for
    (the deviation entry and the lead), in the lead's words; the audit's rule still says the envelope is not redrawn
    there, which is why this mode exists."""
    text = (REPO / "docs/AUTOMATICKY_ZBER.sk.md").read_text(encoding="utf-8")
    start = text.index("Po ukončení, ktoré kampaň uzavrie, a pred commitom záznamov")
    paragraph = " ".join(text[start:text.index("Rovnaký príkaz pokračuje", start)].split())
    for words in ("audit ju neprepočítava (odpoveď vedúceho na otázku Q30, 2026-11-24; návrh, kap. 5.3)",
                  "číta iba logy prevádzky, žiadne skóre", "Kód kampane nástroj nevolá",
                  "scripts/campaign_report.py envelope <session> [<session> ...]",
                  "--protocol config/collection-v5.json", "--out data/results/",
                  "Kód 0", "Kód 1", "Kód 2", "`match`", "`mismatch`", "`data_error`",
                  "Nezhoda obálky ide do denníka odchýlok pri zázname ukončenia a zápis ten záznam menuje",
                  "[ODCHYLKY_V5.sk.md](ODCHYLKY_V5.sk.md)", "nález pre vedúceho"):
        assert words in paragraph, words
    audit = " ".join(line.strip().lstrip("#").strip()
                     for line in (REPO / "scripts/collection_logs.py").read_text().splitlines())
    assert "The envelope is not redrawn from the protocol here" in audit
    assert "the audit does not redraw the envelope of the traffic" in cr.ENVELOPE_RULE
