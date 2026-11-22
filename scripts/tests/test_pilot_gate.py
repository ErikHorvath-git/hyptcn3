"""The real campaign.pilot_gate and the role table as the real audit applies it (protocol v5, package B2, K2).

Every pilot is built by scripts/tests/boundary_sessions.py and audited by the real collection.audit_session. Only
campaign.digest is wrapped, for the collector binary that clones do not have; the two L10 tests also replace
features.acceptance._verdict. Window counts come from the helper's oracle and are written here as literals.
Runs unchanged on the code before and after package B2 (no name B2 adds is imported at module level).
"""
from collections import namedtuple
import copy
import hashlib
import itertools
import json
from pathlib import Path
import re

import numpy as np
import pytest

from scripts import campaign, collection
from scripts.tests import boundary_sessions as bs

COLLECTOR = campaign.ROOT / "vmicollect/build/vmicollect"
PREFIX = "pilot is not accepted for this protocol: "
UNCLEAN = "unaccepted audit: the record does not state a clean acceptance"
OTHER_ROLE = "unaccepted audit: recorded for another role"
NOT_LISTED = "incomplete features in accepted audit"
OVER = "more invalid rows than the protocol tolerates"
REJECTS = "accepted audit of a session the protocol rejects: "
DIFFERS = "audit record differs from the acceptance decision"
COUNT = "snapshot count differs from assigned protocol"
SEQUENCE = "sequence must start at zero and be contiguous"
INTEGRITY = "integrity findings require review before benign admission"
ROLE = "session role is not assigned by the protocol"
INCOMPLETE = "incomplete model inputs under " + bs.fq.BEHAVIOR_POLICY
SLOT = itertools.count()

World = namedtuple("World", "p path root")


def coverage(p):
    return f"score coverage below design gate {p['min_score_coverage']:g}"


def exactly(message):
    return pytest.raises(ValueError, match="^" + re.escape(message) + "$")


def world(root, name="S3"):
    """A protocol of the family with its own profile directory, loaded by collection.protocol."""
    profile = bs.profile_dir(root / "profile")
    path = bs.write_protocol(root / f"{name}.json", bs.family(name, profile))
    return World(collection.protocol(path), path, root)


def session(w, session_id, *, role="pilot", place=None, rows=None, quality=None, measurement=None):
    """A sealed session (default: a pilot) whose session.json carries the measurement sources, audited for real."""
    place = place if place is not None else {"role": role, "group": f"{role}-1", "scenario": "steady", "seed": 11}
    meta = {"measurement_sha256": collection.measurement_sources() if measurement is None else measurement}
    s = bs.build_session(w.root / "sessions", w.p, w.path, place, session_id=session_id,
                         base=bs.time_base(w.p, place.get("role"), next(SLOT) % bs.SLOTS), rows=rows,
                         quality=quality, meta=meta)
    return s, bs.audit(s, w.p)


def record_file(audit, path, *changes):
    """A new record file: the audit's record with each change applied to it."""
    record = copy.deepcopy(audit.record)
    for change in changes:
        change(record)
    path.write_text(json.dumps(record))
    return path


def f1(record):
    """Forgery F1 (plan section 8): the flag flipped."""
    record["values"].update(accepted=True, reasons=[])


def f1b(record):
    """F1b: F1 and the stored verdict flipped too (on the code before B2 the record has none: F1b is F1)."""
    f1(record)
    if type(record["values"].get("acceptance")) is dict:
        record["values"]["acceptance"].update(accepted=True, reasons=[], codes=[])


def f1c(invalid):
    """F1c: F1b and the record lists every invalid row of the archive as tolerated."""
    def change(record):
        f1b(record)
        record["values"]["quality"]["tolerated_invalid_seq"] = sorted(invalid)
        if type(record["values"].get("acceptance")) is dict:
            record["values"]["acceptance"]["tolerated_invalid_seq"] = sorted(invalid)
    return change


def image_bytes(s):
    return sum(f.stat().st_size for f in (s.directory / "raw").glob("*.vmicd"))


@pytest.fixture
def gate(monkeypatch):
    """campaign.pilot_gate with campaign.digest wrapped: the collector binary has the session's recorded
    collector_sha256 (or `collector`, a collector built since the pilot); every other file its real digest."""
    real = campaign.digest

    def offer(report, protocol_path, p, s, collector=None):
        if collector is None:
            collector = json.loads((s.directory / "session.json").read_text())["collector_sha256"]
        monkeypatch.setattr(campaign, "digest", lambda f: collector if Path(f) == COLLECTOR else real(f))
        return campaign.pilot_gate(report, protocol_path, p)
    return offer


# T03: pilot cells of plan section 4. One tolerable row: mid-chain in S3, the last row of the pilot in V4 (it costs
# one window, so coverage still passes and only the pilot's lack of tolerance can refuse it).
def one_row(p):
    return {"S3": bs.isolated_seqs(1, p["window_rows"], p["full_every"])[0], "V4": p["pilot_cycles"] - 1}


def two_findings():
    finding = bs.finding_row()["findings"][0]
    return dict(bs.finding_row(), findings=[finding, dict(finding, index=1)])


PILOT_CELLS = {("S3", "clean"): 64, ("S3", "one_row"): 55, ("V4", "clean"): 536, ("V4", "one_row"): 535,
               ("S3", "findings"): 64}


def pilot_cell(w, name, cell):
    seq = one_row(w.p)[name]
    quality = {"clean": {}, "one_row": {seq: bs.unclosed_row()}, "findings": {seq: two_findings()}}[cell]
    s, a = session(w, f"pilot-{cell}", quality=quality)
    return s, a, quality


@pytest.mark.parametrize("name,cell", list(PILOT_CELLS), ids=[f"{n}-{c}" for n, c in PILOT_CELLS])
def test_pilot_cell_audit_decision(tmp_path, name, cell):
    w = world(tmp_path, name)
    s, a, quality = pilot_cell(w, name, cell)
    rows = w.p["pilot_cycles"]
    windows = PILOT_CELLS[name, cell]
    invalid = [seq for seq, q in quality.items() if not q["behavior_valid"]]
    assert bs.window_count(rows, w.p["window_rows"], w.p["full_every"], invalid) == windows
    assert windows / rows >= w.p["min_score_coverage"]  # Coverage passes in every pilot cell.
    v = a.values
    assert (v["role"], v["snapshots"], v["windows"], v["score_coverage"]) == ("pilot", rows, windows, windows / rows)
    expected = {"clean": [], "one_row": [INCOMPLETE], "findings": [INTEGRITY]}[cell]
    assert (a.code, v["accepted"], v["reasons"]) == (2 if expected else 0, not expected, expected)
    assert v["quality"]["tolerated_invalid_seq"] == []  # A pilot tolerates no invalid row.
    if cell == "findings":  # Two findings on one row: the count is of findings, not of rows.
        assert (v["quality"]["integrity_findings"], v["quality"]["integrity_finding_rows"]) == (2, 1)


GATE_CASES = [(name, "clean", record) for name in ("S3", "V4") for record in ("identity", "F1", "F1b", "F1c")]
GATE_CASES += [(name, "one_row", record) for name in ("S3", "V4") for record in ("honest", "F1", "F1b", "F1c")]
GATE_CASES += [("S3", "findings", record) for record in ("honest", "F1", "F1b")]
GATE_REFUSALS = {("one_row", "honest"): UNCLEAN, ("one_row", "F1"): NOT_LISTED, ("one_row", "F1b"): NOT_LISTED,
                 ("one_row", "F1c"): OVER, ("findings", "honest"): UNCLEAN, ("findings", "F1"): REJECTS + INTEGRITY,
                 ("findings", "F1b"): REJECTS + INTEGRITY}


@pytest.mark.parametrize("name,cell,record", GATE_CASES, ids=["-".join(case) for case in GATE_CASES])
def test_pilot_gate_follows_the_audit(tmp_path, gate, name, cell, record):
    w = world(tmp_path, name)
    s, a, quality = pilot_cell(w, name, cell)
    invalid = [seq for seq, q in quality.items() if not q["behavior_valid"]]
    change = {"identity": None, "honest": None, "F1": f1, "F1b": f1b, "F1c": f1c(invalid)}[record]
    report = a.path if change is None else record_file(a, tmp_path / f"{record}.json", change)
    refusal = GATE_REFUSALS.get((cell, record))
    if refusal is not None:
        with exactly(PREFIX + refusal):
            gate(report, w.path, w.p, s)
    else:
        meta, needed = gate(report, w.path, w.p, s)
        assert meta == json.loads((s.directory / "session.json").read_text())
        raw = a.values["raw_bytes"]
        assert raw == image_bytes(s) > 0
        assert needed == raw * w.p["cycles"] / w.p["pilot_cycles"] * 3 / 2
    # pilot_gate accepts exactly what the audit accepts.
    assert (a.code == 0) is (refusal is None)


# T12: the bindings of pilot_gate in the order of its code. Every case is built by offer(); each step that can break
# a binding runs in every case and is a no-op unless the case names the binding.
BINDINGS = ("schema", "protocol", "policy", "extractor", "metadata", "features", "log_audit", "profile", "collector",
            "measurement", "acceptance")
BINDING_MESSAGES = {
    "schema": "pilot report is not a session audit",
    "protocol": "pilot was audited under another protocol",
    "policy": "pilot was audited under another input policy",
    "extractor": "pilot was audited by another extractor (audit the pilot again)",
    "metadata": "pilot metadata changed since audit",
    "features": "pilot features changed since audit",
    "log_audit": "managed session requires an accepted log audit; re-audit the session",
    "profile": "pilot profile differs from the current profile",
    "collector": "pilot collector differs from the current collector",
    "measurement": "measurement code changed since the pilot (new pilot required): {name}",
    "acceptance": PREFIX + UNCLEAN,
}
Offer = namedtuple("Offer", "report protocol_path p session collector stale")


def offer(root, broken=()):
    """An S3 pilot audited for real and offered to pilot_gate, with the named bindings broken."""
    w = world(root)
    current = collection.measurement_sources()
    stale = min(current)
    # measurement: the pilot was captured and audited by measurement code of which one file has changed since.
    measured = dict(current, **{stale: "0" * 64}) if "measurement" in broken else current
    # acceptance: the pilot has one row whose process list did not close; its honest record refuses it.
    quality = {one_row(w.p)["S3"]: bs.unclosed_row()} if "acceptance" in broken else {}
    s, a = session(w, "pilot-offer", quality=quality, measurement=measured)
    # metadata: session.json edited after the audit (else rewritten with its own bytes).
    meta = s.directory / "session.json"
    text = meta.read_text()
    meta.write_text(json.dumps(dict(json.loads(text), note="edited after the audit")) if "metadata" in broken
                    else text)
    # features: the archive overwritten after the audit by another archive of the same rows (another seed).
    archive = Path(a.values["features"])
    if "features" in broken:
        other, _ = bs.extraction_result(s.directory.name, w.p["pilot_cycles"], w.p["full_every"],
                                        t0=s.result["casy"][0], interval_s=w.p["interval_s"], quality=quality,
                                        seed=99, max_gap_s=w.p["max_gap_s"])
        archive.write_bytes(bs.save_archive(root / "other.npz", other)[0].read_bytes())
    else:
        archive.write_bytes(archive.read_bytes())
    # profile: a file installed into the current profile after the pilot.
    profile = Path(w.p["profile"])
    (profile / "symbols.txt").write_bytes((profile / "symbols.txt").read_bytes())
    if "profile" in broken:
        (profile / "extra.txt").write_text("installed after the pilot\n")

    def edit(record):
        v = record["values"]
        if "schema" in broken:  # Another document of the project.
            record["schema"] = "hyptcn3/score-coverage/1"
        if "policy" in broken:
            v["quality"]["policy"] = bs.fq.LEGACY_POLICY
        if "extractor" in broken:  # One extractor file had another hash at the audit.
            v["extractor_sha256"][min(v["extractor_sha256"])] = "0" * 64
        if "log_audit" in broken:
            v["logs"]["accepted"] = False
    report = record_file(a, root / "offered.json", edit)
    # protocol: another protocol file (the same document under another name); else a byte copy of the file.
    protocol_path = root / "offered-protocol.json"
    if "protocol" in broken:
        doc = json.loads(w.path.read_text())
        bs.write_protocol(protocol_path, dict(doc, name=doc["name"] + "-other"))
    else:
        protocol_path.write_bytes(w.path.read_bytes())
    # collector: the collector binary was rebuilt since the pilot.
    collector = "0" * 64 if "collector" in broken else None
    return Offer(report, protocol_path, collection.protocol(protocol_path), s, collector, stale)


def offered(gate, o):
    return gate(o.report, o.protocol_path, o.p, o.session, o.collector)


def message(binding, o):
    return BINDING_MESSAGES[binding].format(name=o.stale)


@pytest.mark.parametrize("binding", BINDINGS, ids=[f"{i:02}-{b}" for i, b in enumerate(BINDINGS, 1)])
def test_binding_has_its_own_message(tmp_path, gate, binding):
    o = offer(tmp_path, {binding})
    with exactly(message(binding, o)):
        offered(gate, o)


def test_offer_without_a_break_is_accepted(tmp_path, gate):
    o = offer(tmp_path)
    meta, needed = offered(gate, o)
    raw = json.loads(o.report.read_text())["values"]["raw_bytes"]
    assert meta == json.loads((o.session.directory / "session.json").read_text())
    assert needed == raw * o.p["cycles"] / o.p["pilot_cycles"] * 3 / 2


PAIRS = [*zip(BINDINGS, BINDINGS[1:]), *((b, "acceptance") for b in BINDINGS[:-2])]


@pytest.mark.parametrize("first,second", PAIRS, ids=[f"{a}+{b}" for a, b in PAIRS])
def test_earlier_binding_wins(tmp_path, gate, first, second):
    o = offer(tmp_path, {first, second})
    with exactly(message(first, o)):
        offered(gate, o)


def without(doc, key):
    return {k: value for k, value in doc.items() if k != key}


# Parts of the report pilot_gate reads itself, of a wrong type or missing: (the document written, binding refusing).
MALFORMED = {
    "report_list": (lambda r: [r], "schema"),
    "values_list": (lambda r: dict(r, values=[r["values"]]), "schema"),
    "values_missing": (lambda r: without(r, "values"), "schema"),
    "protocol_sha_missing": (lambda r: dict(r, values=without(r["values"], "protocol_sha256")), "protocol"),
    "quality_null": (lambda r: dict(r, values=dict(r["values"], quality=None)), "policy"),
    "extractor_null": (lambda r: dict(r, values=dict(r["values"], extractor_sha256=None)), "extractor"),
}


@pytest.mark.parametrize("case", MALFORMED)
def test_malformed_report_parts(tmp_path, gate, case):
    w = world(tmp_path)
    s, a = session(w, "pilot-malformed")
    document, binding = MALFORMED[case]
    report = tmp_path / "malformed.json"
    report.write_text(json.dumps(document(copy.deepcopy(a.record))))
    with exactly(BINDING_MESSAGES[binding]):
        gate(report, w.path, w.p, s)


# Forgery F2 (plan section 8) at pilot_gate: the clean pilot's honest record pointing at another archive with the
# clean pilot's id, first timestamp and layout. "numbers": the record's windows and score coverage (and those of the
# stored verdict) are made to match the forged archive, so that only the decision can refuse it.
TRANSPLANTS = {
    ("S3", "a"): ({"quality": "one_row"}, PREFIX + NOT_LISTED),
    ("S3", "b"): ({"full_every": 19, "windows": 44}, "coverage"),
    ("S3", "b_numbers"): ({"full_every": 19, "windows": 44, "numbers": True}, "coverage"),
    ("S3", "b_above"): ({"full_every": 20, "windows": 48}, PREFIX + DIFFERS),
    ("S3", "b_above_numbers"): ({"full_every": 20, "windows": 48, "numbers": True}, None),
    ("S3", "c"): ({"quality": "findings"}, PREFIX + REJECTS + INTEGRITY),
    ("S3", "d"): ({"missing": (40,)}, PREFIX + REJECTS + COUNT),
    ("S3", "e"): ({"missing": (79,)}, PREFIX + REJECTS + COUNT),
    ("S3", "f"): ({"rows": 81, "missing": (40,)}, PREFIX + REJECTS + SEQUENCE),
    ("S3", "twin"): ({}, None),
    ("V4", "b"): ({"full_every": 200, "windows": 504}, "coverage"),
    ("V4", "b_numbers"): ({"full_every": 200, "windows": 504, "numbers": True}, "coverage"),
    ("V4", "twin"): ({}, None),
}


def transplant(w, root, s, a, name, *, full_every=None, quality=None, missing=(), rows=None, windows=None,
               numbers=False):
    """F2 record file: `a`'s record over a new archive of session `s` (another seed)."""
    rows = w.p["pilot_cycles"] if rows is None else rows
    seq = one_row(w.p)["S3"]
    quality = {None: None, "one_row": {seq: bs.unclosed_row()}, "findings": {seq: two_findings()}}[quality]
    result, _ = bs.extraction_result(s.directory.name, rows, full_every or w.p["full_every"], t0=s.result["casy"][0],
                                     interval_s=w.p["interval_s"], quality=quality, missing=missing, seed=77,
                                     max_gap_s=w.p["max_gap_s"])
    assert result["casy"][0] == s.result["casy"][0] and result["layout"] == s.result["layout"]
    path, sha = bs.save_archive(root / f"{name}.npz", result)

    def change(record):
        v = record["values"]
        v.update(features=str(path), features_sha256=sha)
        if numbers:
            share = windows / w.p["pilot_cycles"]
            v.update(windows=windows, score_coverage=share)
            if type(v.get("acceptance")) is dict:
                v["acceptance"].update(windows=windows, score_coverage=share,
                                       facts=dict(v["acceptance"]["facts"], windows=windows))
    return record_file(a, root / f"{name}.json", change)


@pytest.mark.parametrize("name,variant", list(TRANSPLANTS), ids=[f"{n}-{v}" for n, v in TRANSPLANTS])
def test_pilot_transplant(tmp_path, gate, name, variant):
    w = world(tmp_path, name)
    s, a = session(w, "pilot-clean")
    assert a.code == 0
    spec, refusal = TRANSPLANTS[name, variant]
    if "windows" in spec:  # Every row valid, full snapshots at another cadence: the oracle's windows.
        rows = w.p["pilot_cycles"]
        assert bs.window_count(rows, w.p["window_rows"], spec["full_every"]) == spec["windows"]
        assert (spec["windows"] / rows < w.p["min_score_coverage"]) is (refusal == "coverage")
    report = transplant(w, tmp_path, s, a, "forged", **spec)
    if refusal is None:
        meta, _ = gate(report, w.path, w.p, s)
        assert meta == json.loads((s.directory / "session.json").read_text())
    else:
        with exactly(PREFIX + REJECTS + coverage(w.p) if refusal == "coverage" else refusal):
            gate(report, w.path, w.p, s)


# C1: another role. The train session has the corpus length and is accepted by its audit.
@pytest.mark.parametrize("case", ["train", "train_as_pilot", "pilot_as_pilot"])
def test_another_role_is_refused(tmp_path, gate, case):
    w = world(tmp_path)
    place = bs.places(w.p, "train")[0] if case.startswith("train") else None
    s, a = session(w, "offered-" + case, place=place)
    assert (a.code, a.values["role"]) == (0, "train" if place else "pilot")
    report = a.path if case == "train" else record_file(
        a, tmp_path / "role.json", lambda record: record["values"].update(role="pilot"))
    if case == "pilot_as_pilot":
        gate(report, w.path, w.p, s)
        return
    with exactly(PREFIX + (OTHER_ROLE if case == "train" else REJECTS + COUNT)):
        gate(report, w.path, w.p, s)


# C2: a session of role pilot that does not have the pilot length (96 = the corpus length; 79 and 81 are the
# neighbours of the pilot length). The audit must decide, not raise.
LENGTHS = {80: 64, 79: 63, 81: 65, 96: 80}


def audited_pilot_of(w, rows):
    try:
        return session(w, f"pilot-{rows}-rows", rows=rows)
    except ValueError as error:
        pytest.fail(f"the audit raised instead of deciding on a pilot of {rows} rows: {error}")


@pytest.mark.parametrize("rows", LENGTHS)
def test_pilot_of_another_length_audit(tmp_path, rows):
    w = world(tmp_path)
    s, a = audited_pilot_of(w, rows)
    windows = LENGTHS[rows]
    assert bs.window_count(rows, w.p["window_rows"], w.p["full_every"]) == windows
    expected = [] if rows == w.p["pilot_cycles"] else [COUNT]
    v = a.values
    assert (a.code, v["accepted"], v["reasons"]) == (2 if expected else 0, not expected, expected)
    # Coverage is the share of the assigned (pilot) length.
    assert (v["snapshots"], v["windows"], v["score_coverage"]) == (rows, windows, windows / w.p["pilot_cycles"])


@pytest.mark.parametrize("rows", LENGTHS)
def test_pilot_of_another_length_gate(tmp_path, gate, rows):
    w = world(tmp_path)
    s, a = audited_pilot_of(w, rows)
    report = record_file(a, tmp_path / "forged.json", f1b)
    if rows == w.p["pilot_cycles"]:
        gate(report, w.path, w.p, s)
        return
    with exactly(PREFIX + REJECTS + COUNT):
        gate(report, w.path, w.p, s)


# Role cells: a diagnostic session is as long as it records (shorter than the corpus) and falls under the
# protocol's rule; S3 places the row mid-chain, V4 as the last row (one window).
DIAGNOSTIC = {("S3", "clean"): (88, 72), ("S3", "one_row"): (88, 63), ("V4", "clean"): (480, 416),
              ("V4", "one_row"): (480, 415)}


@pytest.mark.parametrize("name,cell", list(DIAGNOSTIC), ids=[f"{n}-{c}" for n, c in DIAGNOSTIC])
def test_diagnostic_session_of_its_recorded_length(tmp_path, name, cell):
    w = world(tmp_path, name)
    rows, windows = DIAGNOSTIC[name, cell]
    assert rows < w.p["cycles"]
    seq = {"S3": bs.isolated_seqs(1, w.p["window_rows"], w.p["full_every"])[0], "V4": rows - 1}[name]
    invalid = [seq] if cell == "one_row" else []
    assert bs.window_count(rows, w.p["window_rows"], w.p["full_every"], invalid) == windows
    s, a = session(w, "diagnostic-" + cell, role="diagnostic", rows=rows,
                   quality={q: bs.unclosed_row() for q in invalid})
    v = a.values
    assert (a.code, v["accepted"], v["reasons"], v["role"]) == (0, True, [], "diagnostic")
    assert (v["snapshots"], v["windows"], v["score_coverage"]) == (rows, windows, windows / rows)
    assert v["quality"]["tolerated_invalid_seq"] == invalid


ROLES = {"holdout": {"role": "holdout"}, "missing": {}, "null": {"role": None}, "train": None}


@pytest.mark.parametrize("case", ROLES)
def test_role_the_protocol_does_not_assign(tmp_path, case):
    w = world(tmp_path)
    place = bs.places(w.p, "train")[0] if ROLES[case] is None else dict(
        ROLES[case], group="other-1", scenario="steady", seed=11)
    s, a = session(w, "role-" + case, place=place)
    v = a.values
    assert v["snapshots"] == w.p["cycles"] and v["windows"] == bs.window_count(*(w.p[k] for k in (
        "cycles", "window_rows", "full_every"))) == 80
    if case == "train":
        assert (a.code, v["accepted"], v["reasons"], v["score_coverage"]) == (0, True, [], 80 / w.p["cycles"])
    else:  # No assigned length, hence no coverage either.
        assert (a.code, v["accepted"], v["reasons"], v["score_coverage"]) == (2, False, [ROLE], None)


# L10 (NEW only): pilot_gate reaches the one acceptance function and keeps no coverage rule of its own.
def test_sentinel_pilot_gate_asks_the_one_function(tmp_path, gate, monkeypatch):
    acceptance = pytest.importorskip("features.acceptance")
    w = world(tmp_path)
    s, a = session(w, "pilot-sentinel")
    calls, real = [], acceptance._verdict

    def recorder(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)
    monkeypatch.setattr(acceptance, "_verdict", recorder)
    gate(a.path, w.path, w.p, s)
    assert calls and all(args[1:3] == ("pilot", w.p["pilot_cycles"]) for args, _ in calls)


def test_negative_control_pilot_gate_has_no_rule_of_its_own(tmp_path, gate, monkeypatch):
    acceptance = pytest.importorskip("features.acceptance")
    w = world(tmp_path)
    s, a = session(w, "pilot-clean")
    numbers = transplant(w, tmp_path, s, a, "numbers", full_every=19, windows=44, numbers=True)
    plain = transplant(w, tmp_path, s, a, "plain", full_every=19, windows=44)
    with exactly(PREFIX + REJECTS + coverage(w.p)):
        gate(numbers, w.path, w.p, s)
    real = acceptance._verdict
    monkeypatch.setattr(acceptance, "_verdict",
                        lambda *args, **kwargs: dict(real(*args, **kwargs), accepted=True, reasons=[], codes=[]))
    meta, _ = gate(numbers, w.path, w.p, s)
    assert meta["session_id"] == s.directory.name
    # The plan's F2 b keeps the clean pilot's numbers: the function's own record comparison still refuses it.
    with exactly(PREFIX + DIFFERS):
        gate(plain, w.path, w.p, s)


# Addendum 3 (after the review): the reads pilot_gate makes itself, field by field. Every case is the offer() pilot
# with one thing changed after the audit; the twins are test_offer_without_a_break_is_accepted (offer() as it is),
# test_rewritten_metadata_with_matching_digests_is_accepted (a rewritten session.json) and
# test_smallest_raw_bytes_is_accepted (a rewritten raw_bytes).
NOT_A_RECORD = "pilot metadata is not a session record"
MEASUREMENT = "measurement code changed since the pilot (new pilot required): "
PREDATES = "<pilot predates measurement provenance>"
EVERY_SOURCE = ", ".join(sorted(collection.measurement_sources())[:12])  # The gate names the first twelve.
OTHER_DIGEST = hashlib.sha256(b"another file").hexdigest()
KEEP, DROP = object(), object()


def meta_of(o):
    return json.loads((o.session.directory / "session.json").read_text())


def field(key, make):
    """A change of the record's values: `key` dropped (DROP) or replaced by make(old value)."""
    def change(v):
        if make is DROP:
            del v[key]
        else:
            v[key] = make(v[key])
    return change


def reoffered(o, root, *, meta=KEEP, values=None):
    """A new report for the offered pilot. With `meta`, session.json is rewritten as that JSON value and its new
    SHA-256 goes into the record's session_sha256 and into its log audit, so only the named thing is wrong; then
    `values` changes the record's values. The gate gets the collector digest session.json held before."""
    path = o.session.directory / "session.json"
    collector = json.loads(path.read_text())["collector_sha256"] if o.collector is None else o.collector
    record = json.loads(o.report.read_text())
    v = record["values"]
    if meta is not KEEP:
        path.write_text(json.dumps(meta))
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        v["session_sha256"] = sha
        v["logs"]["sections"]["metadata"]["session_sha256"] = sha
    if values is not None:
        values(v)
    report = root / "reoffered.json"
    report.write_text(json.dumps(record))
    return o._replace(report=report, collector=collector)


# K2-1: a name only the current measurement sources have, and a name only the pilot recorded.
@pytest.mark.parametrize("case", ["only_current", "only_recorded"])
def test_measurement_names_bind_both_ways(tmp_path, gate, case):
    o = offer(tmp_path)
    meta = meta_of(o)
    recorded = dict(meta["measurement_sha256"])
    if case == "only_current":  # A source file added since the pilot (absent from its record).
        name = min(recorded)
        del recorded[name]
    else:  # A source file the pilot was measured with and that is gone now.
        name = "scripts/collection_retired.py"
        assert name not in recorded
        recorded[name] = OTHER_DIGEST
    o = reoffered(o, tmp_path, meta=dict(meta, measurement_sha256=recorded))
    with exactly(MEASUREMENT + name):
        offered(gate, o)


# K2-2: a pilot recorded before measurement provenance existed.
@pytest.mark.parametrize("case", ["absent", "null"])
def test_pilot_without_measurement_provenance(tmp_path, gate, case):
    o = offer(tmp_path)
    meta = meta_of(o)
    o = reoffered(o, tmp_path, meta=without(meta, "measurement_sha256") if case == "absent"
                  else dict(meta, measurement_sha256=None))
    with exactly(MEASUREMENT + PREDATES):
        offered(gate, o)


# K2-3: the content of a profile file changes after the pilot; no file is added or removed.
def test_profile_file_content_binds(tmp_path, gate):
    o = offer(tmp_path)
    profile = Path(o.p["profile"])
    names = sorted(str(f.relative_to(profile)) for f in profile.rglob("*") if f.is_file())
    before = (profile / "symbols.txt").read_bytes()
    (profile / "symbols.txt").write_text("synthetic profile, rebuilt after the pilot\n")
    assert names == sorted(meta_of(o)["profile_sha256"]) == ["symbols.txt"]
    assert sorted(str(f.relative_to(profile)) for f in profile.rglob("*") if f.is_file()) == names
    assert (profile / "symbols.txt").read_bytes() != before
    with exactly(BINDING_MESSAGES["profile"]):
        offered(gate, o)


# K2-4 (NEW only): with _verdict accepting everything, pilot_gate adds no rule of its own after the one function:
# neither on the rows (one unclosed row) nor on integrity findings.
@pytest.mark.parametrize("cell", ["one_row", "integrity"])
def test_gate_adds_no_rule_to_the_one_function(tmp_path, gate, monkeypatch, cell):
    acceptance = pytest.importorskip("features.acceptance")
    w = world(tmp_path)
    seq = one_row(w.p)["S3"]
    s, a = session(w, "pilot-" + cell, quality={seq: bs.unclosed_row() if cell == "one_row" else two_findings()})
    reason = INCOMPLETE if cell == "one_row" else INTEGRITY
    assert (a.code, a.values["accepted"], a.values["reasons"]) == (2, False, [reason])
    with exactly(PREFIX + UNCLEAN):
        gate(a.path, w.path, w.p, s)
    real = acceptance._verdict

    def accepting(*args, **kwargs):
        # A well-formed accepting verdict (addendum 3a): it names every invalid row of the session as tolerated.
        verdict = real(*args, **kwargs)
        return dict(verdict, accepted=True, reasons=[], codes=[],
                    tolerated_invalid_seq=[row["seq"] for row in verdict["facts"]["invalid_rows"]])
    monkeypatch.setattr(acceptance, "_verdict", accepting)
    b = bs.audit(s, w.p, s.directory / "audit-patched.json")
    assert (b.code, b.values["accepted"], b.values["reasons"]) == (0, True, [])
    # The admitted report still shows what an own rule of the gate would refuse.
    q = b.values["quality"]
    if cell == "one_row":
        assert (q["tolerated_invalid_seq"], q["behavior_valid_rows"]) == ([seq], w.p["pilot_cycles"] - 1)
    else:
        assert q["integrity_findings"] != 0 and q["behavior_valid_rows"] == w.p["pilot_cycles"]
    meta, needed = gate(b.path, w.path, w.p, s)
    assert meta == json.loads((s.directory / "session.json").read_text())
    assert needed == b.values["raw_bytes"] * w.p["cycles"] / w.p["pilot_cycles"] * 3 / 2


# K2-5: raw_bytes must be a positive int (bool excluded); the float is the honest count as a float.
RAW_BYTES = {"true": lambda raw: True, "zero": lambda raw: 0, "negative": lambda raw: -raw, "float": float}


@pytest.mark.parametrize("case", RAW_BYTES)
def test_raw_bytes_must_be_a_positive_count(tmp_path, gate, case):
    o = reoffered(offer(tmp_path), tmp_path, values=field("raw_bytes", RAW_BYTES[case]))
    with exactly(BINDING_MESSAGES["schema"]):
        offered(gate, o)


def test_smallest_raw_bytes_is_accepted(tmp_path, gate):
    # This pins the range check only: raw_bytes is bound to nothing (not to the images), so 1 passes the gate.
    o = reoffered(offer(tmp_path), tmp_path, values=field("raw_bytes", lambda raw: 1))
    meta, needed = offered(gate, o)
    assert meta == meta_of(o)
    assert needed == 1 * o.p["cycles"] / o.p["pilot_cycles"] * 3 / 2


# K2-6: only the record's digest changes; session.json and the archive stay as audited.
DIGESTS = {f"{key}_{kind}": (key, value, binding)
           for key, binding in (("session_sha256", "metadata"), ("features_sha256", "features"))
           for kind, value in (("null", None), ("other", OTHER_DIGEST))}


@pytest.mark.parametrize("case", DIGESTS)
def test_recorded_digest_must_match(tmp_path, gate, case):
    key, value, binding = DIGESTS[case]
    o = reoffered(offer(tmp_path), tmp_path, values=field(key, lambda old: value))
    with exactly(BINDING_MESSAGES[binding]):
        offered(gate, o)


# K2-7: a field a step reads, missing or of a wrong type: (record change, session.json change, message).
SHAPES = {
    **{f"{key}_{kind}": (field(key, make), None, BINDING_MESSAGES["schema"])
       for key in ("session_dir", "features") for kind, make in (("missing", DROP), ("null", lambda old: None),
                                                                 ("list", lambda old: [old]))},
    "raw_bytes_missing": (field("raw_bytes", DROP), None, BINDING_MESSAGES["schema"]),
    "raw_bytes_null": (field("raw_bytes", lambda old: None), None, BINDING_MESSAGES["schema"]),
    "raw_bytes_text": (field("raw_bytes", str), None, BINDING_MESSAGES["schema"]),
    "session_sha256_missing": (field("session_sha256", DROP), None, BINDING_MESSAGES["metadata"]),
    "features_sha256_missing": (field("features_sha256", DROP), None, BINDING_MESSAGES["features"]),
    "metadata_list": (None, lambda meta: [meta], NOT_A_RECORD),
    "metadata_null": (None, lambda meta: None, NOT_A_RECORD),
    "profile_sha_missing": (None, lambda meta: without(meta, "profile_sha256"), BINDING_MESSAGES["profile"]),
    "collector_sha_missing": (None, lambda meta: without(meta, "collector_sha256"), BINDING_MESSAGES["collector"]),
    "measurement_list": (None, lambda meta: dict(meta, measurement_sha256=sorted(meta["measurement_sha256"])),
                         MEASUREMENT + PREDATES),
    # An empty object is a record that names no source (not an absent one): every current source has changed.
    "measurement_empty": (None, lambda meta: dict(meta, measurement_sha256={}), MEASUREMENT + EVERY_SOURCE),
}


@pytest.mark.parametrize("case", SHAPES)
def test_missing_or_mistyped_field_is_refused(tmp_path, gate, case):
    values, rewrite, expected = SHAPES[case]
    o = offer(tmp_path)
    o = reoffered(o, tmp_path, values=values, **({} if rewrite is None else {"meta": rewrite(meta_of(o))}))
    with exactly(expected):
        offered(gate, o)


# K2-8: the twin of every rewritten session.json: a change no step reads, both digests following it.
def test_rewritten_metadata_with_matching_digests_is_accepted(tmp_path, gate):
    o = offer(tmp_path)
    rewritten = dict(meta_of(o), note_read_by_no_step="rewritten after the audit")
    o = reoffered(o, tmp_path, meta=rewritten)
    meta, needed = offered(gate, o)
    raw = json.loads(o.report.read_text())["values"]["raw_bytes"]
    assert meta == rewritten == meta_of(o)
    assert needed == raw * o.p["cycles"] / o.p["pilot_cycles"] * 3 / 2


# K2-9 (addendum D3 for the hardened steps): two breaks at once, the earlier step's message wins.
ORDER = {
    "raw_bytes_missing+protocol": ({"protocol"}, None, field("raw_bytes", DROP), BINDING_MESSAGES["schema"]),
    "features_digest+metadata_list": (set(), lambda meta: [meta], field("features_sha256", lambda old: OTHER_DIGEST),
                                      BINDING_MESSAGES["features"]),
    "metadata_list+profile": ({"profile"}, lambda meta: [meta], None, NOT_A_RECORD),
}


@pytest.mark.parametrize("case", ORDER)
def test_field_shape_keeps_the_binding_order(tmp_path, gate, case):
    broken, rewrite, values, expected = ORDER[case]
    o = offer(tmp_path, broken)
    o = reoffered(o, tmp_path, values=values, **({} if rewrite is None else {"meta": rewrite(meta_of(o))}))
    with exactly(expected):
        offered(gate, o)


# Addendum 4 (part B): pilot_gate reads the feature archive itself, after the measurement step and before the
# decision (step 12 of 13). Every case is the offer() pilot with its archive rewritten into a new file and the record
# re-sealed for it, so that only the content of the archive can be at fault.
ARCHIVE = "pilot features are not a readable feature archive: "


def quality_row_as_pairs(arrays):
    quality = json.loads(str(arrays["quality_json"]))
    quality[3] = list(quality[3].items())
    arrays["quality_json"] = np.array(json.dumps(quality))


# The change of each rewrite and the type name of the exception the archive reader raises for it.
REWRITES = {
    "no_seq": (lambda arrays: arrays.pop("seq"), "KeyError"),
    "valid_short": (lambda arrays: arrays.update(valid=arrays["valid"][:-1]), "WindowError"),
    "row_not_dict": (quality_row_as_pairs, "TypeError"),
    "legacy_schema": (lambda arrays: arrays.update(schema=np.array("hyptcn3/features/0")), "ValueError"),
    "unchanged": (lambda arrays: None, None),
}


def rewritten(o, root, rewrite, **flags):
    """A new report for the offered pilot over a rewrite of its archive: the arrays read with np.load, the change of
    `rewrite` applied, written with np.savez_compressed to a new file under `root`; values.features names that file,
    values.features_sha256 is its SHA-256, and `flags` are set in the values as well."""
    root.mkdir()
    with np.load(json.loads(o.report.read_text())["values"]["features"], allow_pickle=False) as data:
        arrays = {key: data[key].copy() for key in data.files}
    REWRITES[rewrite][0](arrays)
    path = root / f"{rewrite}.npz"
    np.savez_compressed(path, **arrays)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    return reoffered(o, root, values=lambda v: v.update(features=str(path), features_sha256=sha, **flags))


def unreadable(rewrite):
    """The archive step's refusal: its prefix and the type name of the reader's exception (the rest is the reader's)."""
    return pytest.raises(ValueError, match="^" + re.escape(ARCHIVE + REWRITES[rewrite][1] + ": "))


@pytest.mark.parametrize("rewrite", ["no_seq", "valid_short", "row_not_dict", "legacy_schema"])
def test_unreadable_archive_is_refused_by_the_gate(tmp_path, gate, rewrite):
    o = rewritten(offer(tmp_path), tmp_path / rewrite, rewrite)
    # A ValueError of the reader is reported by the archive step, not under the prefix of the decision.
    refusal = exactly(ARCHIVE + "ValueError: legacy feature archive: re-extract from raw snapshots") \
        if rewrite == "legacy_schema" else unreadable(rewrite)
    with refusal:
        offered(gate, o)


# The measurement step stands before the archive step, the archive step before the decision. First the unchanged
# rewrite (what the earlier step says on its own), then the unreadable one.
@pytest.mark.parametrize("case", ["measurement", "unclean_record"])
def test_unreadable_archive_keeps_the_binding_order(tmp_path, gate, case):
    o = offer(tmp_path, {"measurement"} if case == "measurement" else set())
    flags = {"accepted": False} if case == "unclean_record" else {}
    with exactly(message("measurement", o) if case == "measurement" else PREFIX + UNCLEAN):
        offered(gate, rewritten(o, tmp_path / "unchanged", "unchanged", **flags))
    refusal = exactly(message("measurement", o)) if case == "measurement" else unreadable("no_seq")
    with refusal:
        offered(gate, rewritten(o, tmp_path / "no_seq", "no_seq", **flags))


# The positive twin of the rewrites above (rule F3): the same construction without a change is accepted.
def test_readable_archive_twin_is_accepted(tmp_path, gate):
    o = rewritten(offer(tmp_path), tmp_path / "unchanged", "unchanged")
    v = json.loads(o.report.read_text())["values"]
    assert v["features"] == str(tmp_path / "unchanged" / "unchanged.npz")
    meta, needed = offered(gate, o)
    assert meta == meta_of(o)
    assert needed == v["raw_bytes"] * o.p["cycles"] / o.p["pilot_cycles"] * 3 / 2


# Addendum 4a (K2-A): the archive step stands before every part of the decision, not only before the flag `accepted`:
# before the record's reasons and its role as well. First the unchanged rewrite (the flag alone is enough for the
# decision to refuse), then the unreadable one (the archive step answers first).
DECISION_PARTS = {"unclean_reasons": ({"reasons": ["forged"]}, UNCLEAN), "other_role": ({"role": "train"}, OTHER_ROLE)}


@pytest.mark.parametrize("case", DECISION_PARTS)
def test_archive_step_precedes_every_part_of_the_decision(tmp_path, gate, case):
    flags, decision = DECISION_PARTS[case]
    o = offer(tmp_path)
    with exactly(PREFIX + decision):
        offered(gate, rewritten(o, tmp_path / "unchanged", "unchanged", **flags))
    with unreadable("no_seq"):
        offered(gate, rewritten(o, tmp_path / "no_seq", "no_seq", **flags))
