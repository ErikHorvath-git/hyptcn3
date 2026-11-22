"""The index of a test-only protocol admits a session only with the verdict the protocol gives (protocol v5, B2).

campaign.event_index reads the audit record and never decides from the archive: the recorded verdict must be the
one the protocol gives for the recorded facts of the session's role, and the record's summary must repeat it.
Every session here is built by scripts/tests/boundary_sessions.py and audited by the real audit; forged records
are new files whose digests are all right, so a refusal can only come from the decision. Expected values come
from the oracle bs.window_count, the table of section 4 of the plan and literals, never from product helpers.
Runs unchanged on the code before and after package B2 (no name B2 adds is imported).
"""
from collections import namedtuple
import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts import campaign, collection
from scripts.tests import boundary_sessions as bs

# One test-only role per family, as the place is used in production. V4 has another role name, so a decision
# that ignores the session's role cannot pass every family. Since package B4 schema 3 is the v5 layout with its
# five roles, so S3 plans test_benign and gives the other four roles no group.
# places: accepted sessions on the planned places, in plan order (label "<cell>-spare": the same cell again);
# rejected: sessions built for place 0 (the forgery place); record: the accepted record the field cases edit.
FAMILIES = {
    "S2G": {"role": "test_events", "count": 3, "places": ("k0", "k1", "k2i", "k2c", "k3c", "k0-spare"),
            "rejected": ("k3i", "k4i", "k4c"), "record": "k1"},
    "V4": {"role": "test_operations", "count": 1, "places": ("k0", "k1"), "rejected": ("k2i", "k3i"),
           "record": "k1"},
    "S3": {"role": "test_benign", "count": 1, "places": ("k0", "k3i"), "rejected": ("k4i", "k4c"),
           "record": "k3i"},
}
OTHER_BOOT = ("S2G", "k3i-boot")  # A rejected cell at place 0 under another boot id (order case "mapping").
# Plan section 4: scorable windows of each cell and why the audit rejects it (None: accepted).
WINDOWS = {"S2G": {"k0": 80, "k1": 71, "k2i": 62, "k2c": 70, "k3i": 53, "k3c": 69, "k4i": 44, "k4c": 68},
           "S3": {"k0": 80, "k3i": 53, "k4i": 44, "k4c": 68},
           "V4": {"k0": 656, "k1": 623, "k2i": 590, "k3i": 557}}
WHY = {"S2G": {"k0": None, "k1": None, "k2i": None, "k2c": None, "k3i": "coverage", "k3c": None, "k4i": "both",
               "k4c": "count"},
       "S3": {"k0": None, "k3i": None, "k4i": "both", "k4c": "count"},
       "V4": {"k0": None, "k1": None, "k2i": "coverage", "k3i": "coverage"}}
PLANNED = {"S2G": 6, "V4": 2, "S3": 2}  # Role count times the two scenarios.
F2B = {"S2G": (16, 48), "S3": (16, 48), "V4": (64, 352)}  # Full-snapshot cadence of the F2 b archive, its windows.

UNACCEPTED = "unaccepted audit or protocol mismatch: "
CHANGED = "session metadata or features changed since audit: "
LOGS = "managed session requires an accepted log audit; re-audit the session"
MAPPING = "role or boot/group mapping outside the plan: "
NOT_CLEAN = "unaccepted audit: the record does not state a clean acceptance"
OTHER_ROLE = "unaccepted audit: recorded for another role"
NO_VERDICT = "audit record carries no acceptance verdict"
DIFFERS = "audit record differs from the acceptance decision"
REJECTS = "accepted audit of a session the protocol rejects: "
OVER = "more invalid rows than the protocol tolerates"
CAUSE = "invalid rows have a cause the protocol does not tolerate"
FACTS = "invalid session facts"
INTEGRITY = "integrity findings require review before benign admission"
ROWS = "snapshot count differs from assigned protocol"
SEQUENCE = "sequence must start at zero and be contiguous"
INCOMPLETE = "incomplete model inputs under behavioral-inputs-v1"
ZERO = "0" * 64

World = namedtuple("World", "name p path doc sha places sessions")
Built = namedtuple("Built", "label cell index session audit invalid base")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cell_of(label):
    return label.split("-")[0]


def invalid_seqs(cell, p):
    """Seq of the cell's invalid rows (plan section 4 positions)."""
    if cell == "k0":
        return []
    count, kind = int(cell[1]), cell[2:] or "i"  # k1: one isolated row.
    place = bs.isolated_seqs if kind == "i" else bs.clustered_seqs
    return place(count, p["window_rows"], p["full_every"])


def sessions_of(name):
    """(label, place index) of every session of a family: the places, the rejected cells, the other boot."""
    spec = FAMILIES[name]
    rows = [*enumerate(spec["places"]), *((0, label) for label in spec["rejected"])]
    rows += [(0, OTHER_BOOT[1])] if name == OTHER_BOOT[0] else []
    return [(label, index) for index, label in rows]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """Per family: the loaded protocol and every session built at its place, audited for real."""
    out = {}
    for name, spec in FAMILIES.items():
        root = tmp_path_factory.mktemp(name.lower())
        doc = bs.family(name, bs.profile_dir(root / "profile"))
        roles = {spec["role"]: spec["count"]}
        doc["roles"] = {**dict.fromkeys(doc["roles"], 0), **roles} if doc["schema"].endswith("/3") else roles
        path = bs.write_protocol(root / "protocol.json", doc)
        p = collection.protocol(path)
        places = bs.places(p)
        assert len(places) == PLANNED[name]
        sessions = {}
        for slot, (label, index) in enumerate(sessions_of(name)):
            invalid = invalid_seqs(cell_of(label), p)
            base = bs.time_base(p, spec["role"], slot)
            session = bs.build_session(root, p, path, places[index], session_id=f"{name.lower()}-{label}",
                                       base=base, quality={seq: bs.unclosed_row() for seq in invalid},
                                       boot="boot-other" if label.endswith("-boot") else None)
            audit = bs.audit(session, p)
            (session.directory / "events.json").write_text('{"events": []}\n')  # Only its digest is read.
            sessions[label] = Built(label, cell_of(label), index, session, audit, invalid, base)
        out[name] = World(name, p, path, json.loads(path.read_text()), sha(path), places, sessions)
    return out


def honest(w):
    """Report paths of the accepted sessions, in plan order."""
    return [w.sessions[label].audit.path for label in FAMILIES[w.name]["places"]]


def replaced(w, index, path):
    reports = honest(w)
    reports[index] = path
    return reports


def forge(tmp_path, report, *edits, name="forged"):
    """A new report file: the record of `report` with the edits applied to its values (in order)."""
    doc = json.loads(Path(report).read_text())
    for edit in edits:
        edit(doc["values"])
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(doc))
    return path


def stored(edit):
    """Edit of the stored verdict, applied only where the record has one (the code before B2 has none)."""
    def apply(v):
        if type(v.get("acceptance")) is dict:
            edit(v["acceptance"])
    return apply


def f1(v):
    v.update(accepted=True, reasons=[])


def f1b(v):
    f1(v)
    stored(lambda a: a.update(accepted=True, reasons=[], codes=[]))(v)


def f1c(invalid):
    def edit(v):
        f1b(v)
        v["quality"]["tolerated_invalid_seq"] = sorted(invalid)
        stored(lambda a: a.update(tolerated_invalid_seq=sorted(invalid)))(v)
    return edit


def numbers(windows, cycles):
    """F3 and its twin: the summary's windows and score coverage set to `windows` of `cycles` rows."""
    return lambda v: v.update(windows=windows, score_coverage=windows / cycles)


def coverage(p):
    return f"score coverage below design gate {p['min_score_coverage']:g}"


def refused(w, reports, expected, protocol_sha=None):
    with pytest.raises(ValueError) as caught:
        campaign.event_index(reports, w.p, w.sha if protocol_sha is None else protocol_sha)
    assert str(caught.value) == expected


def entry(w, b, report):
    """The index entry of session `b` under `report`, from what the test built."""
    d = Path(b.session.directory).resolve()
    place = w.places[b.index]
    first = b.base + bs.FIRST_SNAPSHOT_S
    boot = "boot-other" if b.label.endswith("-boot") else bs.boot_id(place["group"])
    return {"id": f"{w.name.lower()}-{b.label}", "role": FAMILIES[w.name]["role"], "group": place["group"],
            "boot_id": boot, "scenario": place["scenario"], "seed": place["seed"],
            "start": float(first), "end": float(first + (w.p["cycles"] - 1) * w.p["interval_s"]),
            "session": str(d / "session.json"), "session_sha256": sha(d / "session.json"),
            "audit": str(Path(report).resolve()), "audit_sha256": sha(report),
            "features": str(Path(b.audit.archive).resolve()), "features_sha256": sha(b.audit.archive),
            "events": str(d / "events.json"), "events_sha256": sha(d / "events.json"),
            "guest": {"kernel": bs.KERNEL, "boot_id": boot, "stack_sha256": bs.STACK,
                      "stack_manifest": bs.STACK_MANIFEST},
            "collector_sha256": json.loads((d / "session.json").read_text())["collector_sha256"],
            "extractor_sha256": b.audit.values["extractor_sha256"]}


def admitted(w, reports):
    """event_index of `reports`, checked against the entries the inputs give."""
    doc = campaign.event_index(reports, w.p, w.sha)
    assert set(doc) == {"schema", "complete", "planned_sessions", "protocol_sha256", "protocol_config", "sessions",
                        "note"}
    assert (doc["schema"], doc["planned_sessions"], doc["protocol_sha256"]) == ("hyptcn3/event-index/1",
                                                                               PLANNED[w.name], w.sha)
    assert doc["protocol_config"] == w.doc and doc["complete"] == (len(reports) == PLANNED[w.name])
    by_place = FAMILIES[w.name]["places"]
    assert doc["sessions"] == [entry(w, w.sessions[by_place[i]], r) for i, r in enumerate(reports)]
    return doc


# E1: the honest records.

@pytest.mark.parametrize("family,label", [(f, label) for f in FAMILIES for label, _ in sessions_of(f)])
def test_audit_decides_as_the_table_says(world, family, label):
    """Precondition of every other leg: the audit decides each cell as section 4 says, windows from the oracle."""
    w = world[family]
    b, p = w.sessions[label], w.p
    windows, why, cycles = WINDOWS[family][b.cell], WHY[family][b.cell], p["cycles"]
    assert windows == bs.window_count(cycles, p["window_rows"], p["full_every"], b.invalid)
    reasons = {None: [], "coverage": [coverage(p)], "count": [INCOMPLETE], "both": [INCOMPLETE, coverage(p)]}[why]
    v = b.audit.values
    assert (b.audit.code, v["accepted"], v["reasons"]) == (2 if why else 0, why is None, reasons)
    assert (v["role"], v["snapshots"], v["windows"], v["score_coverage"], v["protocol_sha256"]) == (
        FAMILIES[family]["role"], cycles, windows, windows / cycles, w.sha)
    assert v["quality"]["tolerated_invalid_seq"] == ([] if why in ("count", "both") else b.invalid)
    assert (windows / cycles < p["min_score_coverage"]) == (why in ("coverage", "both"))
    if (family, b.cell) == ("S3", "k3i"):
        assert windows / cycles == p["min_score_coverage"]  # Accepted on equality.


@pytest.mark.parametrize("family", FAMILIES)
def test_index_of_the_honest_accepted_set(world, family):
    """Exactly the accepted sessions, field by field; complete only when every planned session is there."""
    w = world[family]
    reports = honest(w)
    assert len(reports) == PLANNED[family] == FAMILIES[family]["count"] * len(w.doc["scenarios"])
    assert admitted(w, reports)["complete"]
    partial = admitted(w, reports[:-1])
    assert not partial["complete"] and len(partial["sessions"]) == PLANNED[family] - 1


REJECTED = [(f, label) for f in FAMILIES for label in FAMILIES[f]["rejected"]]


@pytest.mark.parametrize("family,label", REJECTED)
def test_honest_rejecting_record_is_refused(world, family, label):
    w = world[family]
    report = w.sessions[label].audit.path
    refused(w, [*honest(w), report], UNACCEPTED + str(report))


def decision_message(w, label):
    """Section 14, column validate_index: what a record of this rejected cell that claims acceptance gets."""
    return REJECTS + coverage(w.p) if WHY[w.name][cell_of(label)] == "coverage" else OVER


# E2, E3: a rejected session whose record claims acceptance.

@pytest.mark.parametrize("family,label", REJECTED)
def test_f1_is_refused(world, family, label, tmp_path):
    w = world[family]
    forged = forge(tmp_path, w.sessions[label].audit.path, f1)
    refused(w, replaced(w, 0, forged), f"{decision_message(w, label)}: {forged}")


@pytest.mark.parametrize("kind", ("F1b", "F1c"))
@pytest.mark.parametrize("family,label", REJECTED)
def test_f1b_f1c_are_refused(world, family, label, kind, tmp_path):
    w = world[family]
    b = w.sessions[label]
    forged = forge(tmp_path, b.audit.path, f1b if kind == "F1b" else f1c(b.invalid))
    refused(w, replaced(w, 0, forged), f"{decision_message(w, label)}: {forged}")


# E4: numbers that differ from the verdict.

def record(w):
    return w.sessions[FAMILIES[w.name]["record"]]


@pytest.mark.parametrize("family", ("S2G", "V4"))
def test_f3_is_refused(world, family, tmp_path):
    """k1 with the windows and the score coverage of the clean cell (oracle)."""
    w = world[family]
    clean = bs.window_count(w.p["cycles"], w.p["window_rows"], w.p["full_every"])
    assert clean == WINDOWS[family]["k0"]
    forged = forge(tmp_path, w.sessions["k1"].audit.path, numbers(clean, w.p["cycles"]))
    refused(w, replaced(w, 1, forged), f"{DIFFERS}: {forged}")


Ctx = namedtuple("Ctx", "p cycles max below")


def context(w):
    cycles, gate = w.p["cycles"], w.p["min_score_coverage"]
    return Ctx(w.p, cycles, w.p["invalid_rows"]["max"], max(n for n in range(cycles + 1) if n / cycles < gate))


def fill_up(c):
    """Stored facts with tolerable invalid rows up to max + 1."""
    def edit(a):
        rows = a["facts"]["invalid_rows"]
        taken = {row["seq"] for row in rows}
        free = [seq for seq in range(c.cycles) if seq not in taken][:c.max + 1 - len(rows)]
        rows += [{"seq": seq, "truncated_traversals": ["processes"], "read_errors": 0, "filled_zero": 0}
                 for seq in free]
        assert len(rows) == c.max + 1
    return edit


def facts(**changes):
    return lambda c: stored(lambda a: a["facts"].update(changes))


# One case per field of the record summary and of the stored verdict, changing only that field: (edit, message).
FIELDS = {
    "role": (lambda c: lambda v: v.update(role="pilot"), OTHER_ROLE),
    "snapshots": (lambda c: lambda v: v.update(snapshots=v["snapshots"] + 1), DIFFERS),
    "windows": (lambda c: lambda v: v.update(windows=v["windows"] - 1), DIFFERS),
    "score_coverage": (lambda c: lambda v: v.update(score_coverage=(v["windows"] - 1) / c.cycles), DIFFERS),
    "tolerated_invalid_seq": (lambda c: lambda v: v["quality"].update(
        tolerated_invalid_seq=v["quality"]["tolerated_invalid_seq"][:-1]), DIFFERS),
    "acceptance.schema": (lambda c: stored(lambda a: a.update(schema=a["schema"] + "-forged")), DIFFERS),
    "acceptance.accepted": (lambda c: stored(lambda a: a.update(accepted=False)), DIFFERS),
    "acceptance.reasons": (lambda c: stored(lambda a: a.update(reasons=["forged"])), DIFFERS),
    "acceptance.codes": (lambda c: stored(lambda a: a.update(codes=["coverage"])), DIFFERS),
    "acceptance.role": (lambda c: stored(lambda a: a.update(role="pilot")), DIFFERS),
    "acceptance.assigned_rows": (lambda c: stored(lambda a: a.update(assigned_rows=a["assigned_rows"] + 1)),
                                 DIFFERS),
    "acceptance.gate": (lambda c: stored(lambda a: a.update(gate=a["gate"] - 1 / c.cycles)), DIFFERS),
    "acceptance.snapshots": (lambda c: stored(lambda a: a.update(snapshots=a["snapshots"] + 1)), DIFFERS),
    "acceptance.windows": (lambda c: stored(lambda a: a.update(windows=a["windows"] - 1)), DIFFERS),
    "acceptance.score_coverage": (lambda c: stored(lambda a: a.update(
        score_coverage=(a["windows"] - 1) / c.cycles)), DIFFERS),
    "acceptance.tolerated_invalid_seq": (lambda c: stored(lambda a: a.update(tolerated_invalid_seq=[])), DIFFERS),
    # The stored facts are decided again: still accepting but another verdict, or rejecting.
    "facts.windows_up": (lambda c: stored(lambda a: a["facts"].update(windows=a["facts"]["windows"] + 1)),
                         DIFFERS),
    "facts.below_gate": (lambda c: stored(lambda a: a["facts"].update(windows=c.below)), REJECTS + "{coverage}"),
    "facts.integrity": (facts(integrity_findings=1), REJECTS + INTEGRITY),
    "facts.snapshots_short": (lambda c: stored(lambda a: a["facts"].update(snapshots=c.cycles - 1)),
                              REJECTS + ROWS),
    "facts.snapshots_long": (lambda c: stored(lambda a: a["facts"].update(snapshots=c.cycles + 1)), REJECTS + ROWS),
    "facts.sequence": (facts(sequence_contiguous=False), REJECTS + SEQUENCE),
    "facts.over_max": (lambda c: stored(fill_up(c)), OVER),
    "facts.cause": (lambda c: stored(lambda a: a["facts"]["invalid_rows"][0].update(read_errors=1)), CAUSE),
    "facts.null": (lambda c: stored(lambda a: a.update(facts=None)), FACTS),
}


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("family", FAMILIES)
def test_one_recorded_field_differs(world, family, field, tmp_path):
    """The accepted record of the family (S2G, V4: k1; S3: k3i, on the gate) with one field changed."""
    w = world[family]
    c = context(w)
    edit, message = FIELDS[field]
    b = record(w)
    forged = forge(tmp_path, b.audit.path, edit(c))
    refused(w, replaced(w, b.index, forged), f"{message.format(coverage=coverage(w.p))}: {forged}")


# E5: no stored verdict.

@pytest.mark.parametrize("family,label", [*((f, "k0") for f in FAMILIES),
                                          *((f, label) for f, label in REJECTED if WHY[f][label] == "coverage")])
def test_record_without_verdict_is_refused(world, family, label, tmp_path):
    """An honest accepting record, and F1 of a coverage-only cell (the missing verdict is noticed first)."""
    w = world[family]
    b = w.sessions[label]
    edits = (f1,) if WHY[family][label] else ()
    forged = forge(tmp_path, b.audit.path, *edits, lambda v: v.pop("acceptance", None))
    refused(w, replaced(w, b.index, forged), f"{NO_VERDICT}: {forged}")


# Order: a case that breaks two checks expects the message of the earlier one.

def order_case(w, case, tmp_path):
    s = w.sessions
    if case == "features_digest":
        forged = forge(tmp_path, s["k3i"].audit.path, f1, lambda v: v.update(features_sha256=ZERO))
        return replaced(w, 0, forged), CHANGED + str(forged)
    if case == "log_audit":
        forged = forge(tmp_path, s["k3i"].audit.path, f1, lambda v: v["logs"].update(accepted=False))
        return replaced(w, 0, forged), LOGS
    if case == "mapping":
        forged = forge(tmp_path, s[OTHER_BOOT[1]].audit.path, f1)
        return [*honest(w), forged], MAPPING + str(forged)
    if case == "flag_type":
        forged = forge(tmp_path, s["k3i"].audit.path, f1, lambda v: v.update(accepted=1))
        return replaced(w, 0, forged), UNACCEPTED + str(forged)
    if case == "role_and_f3":
        forged = forge(tmp_path, s["k1"].audit.path, numbers(WINDOWS["S2G"]["k0"], w.p["cycles"]),
                       lambda v: v.update(role="pilot"))
        return replaced(w, 1, forged), f"{OTHER_ROLE}: {forged}"
    if case == "strict_and_no_verdict":
        forged = forge(tmp_path, s["k0"].audit.path, lambda v: v.update(reasons=["forged"]),
                       lambda v: v.pop("acceptance", None))
        return replaced(w, 0, forged), f"{NOT_CLEAN}: {forged}"
    if case == "decision_and_summary":
        forged = forge(tmp_path, s["k1"].audit.path, stored(lambda a: a["facts"].update(integrity_findings=1)),
                       lambda v: v.update(windows=v["windows"] - 1))
        return replaced(w, 1, forged), f"{REJECTS}{INTEGRITY}: {forged}"
    if case == "count_and_summary":
        forged = forge(tmp_path, s["k4c"].audit.path, f1b, lambda v: v.update(windows=v["windows"] + 1))
        return replaced(w, 0, forged), f"{OVER}: {forged}"
    raise AssertionError(case)


@pytest.mark.parametrize("case", ("features_digest", "log_audit", "mapping", "flag_type", "role_and_f3",
                                  "strict_and_no_verdict", "decision_and_summary", "count_and_summary"))
def test_earlier_check_wins(world, case, tmp_path):
    w = world["S2G"]
    reports, expected = order_case(w, case, tmp_path)
    refused(w, reports, expected)


# Wrong types of what the place and the strict record read (S2G; k0, or k1 where the list is not empty).
TYPES = {
    "accepted_int": ("k0", lambda v: v.update(accepted=1), UNACCEPTED),
    "accepted_string": ("k0", lambda v: v.update(accepted="yes"), UNACCEPTED),
    "accepted_null": ("k0", lambda v: v.update(accepted=None), UNACCEPTED),
    "reasons_nonempty": ("k0", lambda v: v.update(reasons=["forged"]), NOT_CLEAN),
    "reasons_null": ("k0", lambda v: v.update(reasons=None), NOT_CLEAN),
    "reasons_missing": ("k0", lambda v: v.pop("reasons"), NOT_CLEAN),
    "role_null": ("k0", lambda v: v.update(role=None), OTHER_ROLE),
    "verdict_list": ("k0", lambda v: v.update(acceptance=[]), NO_VERDICT),
    "verdict_string": ("k0", lambda v: v.update(acceptance="verdict"), NO_VERDICT),
    "verdict_null": ("k0", lambda v: v.update(acceptance=None), NO_VERDICT),
    "quality_null": ("k1", lambda v: v.update(quality=None), DIFFERS),
    "tolerated_null": ("k1", lambda v: v["quality"].update(tolerated_invalid_seq=None), DIFFERS),
}


@pytest.mark.parametrize("case", TYPES)
def test_wrong_type_is_refused(world, case, tmp_path):
    w = world["S2G"]
    label, edit, message = TYPES[case]
    b = w.sessions[label]
    forged = forge(tmp_path, b.audit.path, edit)
    # The first check of event_index ends its message with the path itself; the others get ": <path>" appended.
    refused(w, replaced(w, b.index, forged), message + str(forged) if message == UNACCEPTED else f"{message}: {forged}")


# Every digest the place checks binds the record (checks before the decision; the same on both trees).
DIGESTS = {
    "session_sha256": (lambda v: v.update(session_sha256=ZERO), CHANGED),
    "features_sha256": (lambda v: v.update(features_sha256=ZERO), CHANGED),
    "logs_session_sha256": (lambda v: v["logs"]["sections"]["metadata"].update(session_sha256=ZERO), LOGS),
    "protocol_sha256": (lambda v: v.update(protocol_sha256=ZERO), UNACCEPTED),
}


@pytest.mark.parametrize("case", [*DIGESTS, "protocol_argument"])
def test_digest_binds_the_record(world, case, tmp_path):
    w = world["S2G"]
    if case == "protocol_argument":
        reports = honest(w)
        refused(w, reports, UNACCEPTED + str(reports[0]), protocol_sha=ZERO)
        return
    edit, message = DIGESTS[case]
    forged = forge(tmp_path, w.sessions["k0"].audit.path, edit)
    refused(w, replaced(w, 0, forged), message if message == LOGS else message + str(forged))


# Positive twins: the same constructions without the break are admitted.

@pytest.mark.parametrize("construction", ("copy", "F1", "F1b", "F1c", "F3"))
@pytest.mark.parametrize("family", FAMILIES)
def test_twin_is_admitted(world, family, construction, tmp_path):
    w = world[family]
    if construction == "copy":
        reports = [forge(tmp_path, r, name=f"copy{i}") for i, r in enumerate(honest(w))]
    elif construction in ("F1", "F1b"):
        reports = replaced(w, 0, forge(tmp_path, w.sessions["k0"].audit.path, f1 if construction == "F1" else f1b))
    else:
        b = record(w)
        windows = bs.window_count(w.p["cycles"], w.p["window_rows"], w.p["full_every"], b.invalid)
        assert windows == WINDOWS[family][b.cell]
        edit = f1c(b.invalid) if construction == "F1c" else numbers(windows, w.p["cycles"])
        reports = replaced(w, b.index, forge(tmp_path, b.audit.path, edit))
    assert admitted(w, reports)["complete"]


# E6: the depth of this place. A clean record over an archive below the gate is not seen (the archive stays closed).

@pytest.mark.parametrize("family", FAMILIES)
def test_f2b_is_not_seen(world, family, tmp_path):
    w = world[family]
    p, b = w.p, w.sessions["k0"]
    cadence, windows = F2B[family]
    assert bs.window_count(p["cycles"], p["window_rows"], cadence) == windows
    assert windows / p["cycles"] < p["min_score_coverage"]
    result, _ = bs.extraction_result(b.session.directory.name, p["cycles"], cadence, t0=b.session.result["casy"][0],
                                     interval_s=p["interval_s"], seed=w.places[0]["seed"], max_gap_s=p["max_gap_s"])
    archive, digest = bs.save_archive(tmp_path / "forged.npz", result)
    assert digest == sha(archive) != sha(b.audit.archive)
    forged = forge(tmp_path, b.audit.path, lambda v: v.update(features=str(archive), features_sha256=digest))
    doc = campaign.event_index(replaced(w, 0, forged), p, w.sha)
    assert doc["complete"]
    assert doc["sessions"][0] == dict(entry(w, b, forged), features=str(archive), features_sha256=sha(archive))


# Fixes after the review (addendum 3, part K5). New sessions come from their own fixture; nothing above changes.

EXTRA_SLOT = 40  # First time slot of the extras in the role's lane (world uses 0 to 9).


@pytest.fixture(scope="module")
def extras(world, tmp_path_factory):
    """Per family: accepted sessions built for place 0 the way world builds its rejected cells, audited for real.

    "extra-<cell>": the cell of the family's field cases (S2G, V4: k1; S3: k3i, on the gate), own id and slot.
    "extra-k0-otherboot" (S2G only): a clean session at place 0 under a boot id that is not its group's.
    """
    out = {}
    for name, spec in FAMILIES.items():
        w = world[name]
        root = tmp_path_factory.mktemp(name.lower() + "-extra")
        labels = [(f"extra-{spec['record']}", spec["record"], None)]
        labels += [("extra-k0-otherboot", "k0", "boot-extra")] if name == "S2G" else []
        built = {}
        for slot, (label, cell, boot) in enumerate(labels, EXTRA_SLOT):
            invalid = invalid_seqs(cell, w.p)
            base = bs.time_base(w.p, spec["role"], slot)
            session = bs.build_session(root, w.p, w.path, w.places[0], session_id=f"{name.lower()}-{label}",
                                       base=base, quality={seq: bs.unclosed_row() for seq in invalid}, boot=boot)
            audit = bs.audit(session, w.p)
            (session.directory / "events.json").write_text('{"events": []}\n')  # Only its digest is read.
            windows = WINDOWS[name][cell]
            assert windows == bs.window_count(w.p["cycles"], w.p["window_rows"], w.p["full_every"], invalid)
            assert (audit.code, audit.values["accepted"], audit.values["reasons"], audit.values["windows"]) == (
                0, True, [], windows)
            built[label] = Built(label, cell, 0, session, audit, invalid, base)
        out[name] = built
    return out


def extra(extras, family):
    return extras[family][f"extra-{FAMILIES[family]['record']}"]


def honest_pairs(w):
    """(Built, report) of the accepted sessions, in plan order."""
    return [(w.sessions[label], w.sessions[label].audit.path) for label in FAMILIES[w.name]["places"]]


def index_of(w, pairs, complete):
    """event_index of the reports of `pairs`, checked as a whole against the sessions the test names for them."""
    doc = campaign.event_index([report for _, report in pairs], w.p, w.sha)
    assert set(doc) == {"schema", "complete", "planned_sessions", "protocol_sha256", "protocol_config", "sessions",
                        "note"}
    assert (doc["schema"], doc["planned_sessions"], doc["protocol_sha256"], doc["protocol_config"]) == (
        "hyptcn3/event-index/1", PLANNED[w.name], w.sha, w.doc)
    assert doc["complete"] is complete
    assert doc["sessions"] == [entry(w, b, report) for b, report in pairs]
    return doc


@pytest.mark.parametrize("family,count", [(f, count) for f in FAMILIES for count in ("one_fewer", "one_more")])
def test_complete_only_at_the_planned_count(world, extras, family, count):
    """Both sides of the planned count (PLANNED: 6, 2, 2): one report fewer, and one more from a new accepted
    session with its own id (never a report offered twice), are admitted, and neither index is complete."""
    w = world[family]
    pairs = honest_pairs(w)
    if count == "one_fewer":
        pairs = pairs[1:]
    else:
        pairs = [*pairs, (extra(extras, family), extra(extras, family).audit.path)]
    assert len(pairs) == PLANNED[family] + (1 if count == "one_more" else -1)
    doc = index_of(w, pairs, False)
    assert len({s["id"] for s in doc["sessions"]}) == len({str(r) for _, r in pairs}) == len(pairs)


@pytest.mark.parametrize("family", FAMILIES)
def test_unclean_record_of_another_role_is_called_unclean(world, family, tmp_path):
    """An accepted record whose flag stays true, with reasons ["forged"] and role "pilot": two breaks of the strict
    record check at once, and the earlier one (the clean acceptance) names the refusal."""
    w = world[family]
    b = w.sessions["k0"]
    assert b.index == 0 and b.audit.values["accepted"] is True
    # Twin: the same copy without the two edits is admitted (the whole list: test_twin_is_admitted[<family>-copy]).
    assert admitted(w, replaced(w, 0, forge(tmp_path, b.audit.path, name="twin")))["complete"]
    forged = forge(tmp_path, b.audit.path, lambda v: v.update(reasons=["forged"], role="pilot"))
    assert json.loads(forged.read_text())["values"]["accepted"] is True
    refused(w, replaced(w, 0, forged), f"{NOT_CLEAN}: {forged}")


@pytest.mark.parametrize("family,construction", [(f, kind) for f in FAMILIES for kind in ("F1", "F1b", "F1c")])
def test_twin_from_an_accepted_extra_session(world, extras, family, construction, tmp_path):
    """The forgeries of rejected cells (test_f1_is_refused, test_f1b_f1c_are_refused) put an extra session built
    for place 0 there; the same construction on an accepted extra session built the same way is admitted."""
    w = world[family]
    b = extra(extras, family)
    forged = forge(tmp_path, b.audit.path, {"F1": f1, "F1b": f1b, "F1c": f1c(b.invalid)}[construction])
    pairs = honest_pairs(w)
    pairs[0] = (b, forged)
    index_of(w, pairs, True)


def other_session_digest(v):
    """Another session.json digest in the record and in its log audit, so that only the digest check breaks."""
    v.update(session_sha256=ZERO)
    v["logs"]["sections"]["metadata"].update(session_sha256=ZERO)


# The checks before the decision, each broken on its own: (edit of the record, message). "mapping" is no edit:
# the record is that of a session whose boot id is not its group's, appended to the honest list.
BREAKS = {
    "protocol": (lambda v: v.update(protocol_sha256=ZERO), UNACCEPTED),
    "flag": (lambda v: v.update(accepted=False), UNACCEPTED),
    "digest": (lambda v: v.update(features_sha256=ZERO), CHANGED),
    "session_digest": (other_session_digest, CHANGED),
    "features_digest": (lambda v: v.update(features_sha256=ZERO), CHANGED),
    "log_audit": (lambda v: v["logs"].update(accepted=False), LOGS),
    "mapping": (None, MAPPING),
}


def broken(w, extras, names, tmp_path):
    """Reports with the named breaks in one record, and the message of the first of them."""
    base = extras["S2G"]["extra-k0-otherboot"] if "mapping" in names else w.sessions["k0"]
    edits = [BREAKS[n][0] for n in names if BREAKS[n][0] is not None]
    forged = forge(tmp_path, base.audit.path, *edits, name="+".join(names))
    reports = [*honest(w), forged] if "mapping" in names else replaced(w, 0, forged)
    message = BREAKS[names[0]][1]
    # The log audit names no path; the other checks end their message with it.
    return reports, message if message == LOGS else message + str(forged)


@pytest.mark.parametrize("case", ("protocol+digest", "flag+digest", "digest+log_audit", "log_audit+mapping",
                                  "session_digest+features_digest"))
def test_earlier_of_two_checks_before_the_decision_wins(world, extras, case, tmp_path):
    """Two checks before the decision broken in one record (S2G): the earlier check's message, as the product
    writes it. Each break alone gives its own message first, so both breaks are real."""
    w = world["S2G"]
    first, second = case.split("+")
    for names in ((first,), (second,)):
        refused(w, *broken(w, extras, names, tmp_path))
    refused(w, *broken(w, extras, (first, second), tmp_path))


# A planned role named "diagnostic" (addendum 4, part D): the index hands the session's recorded length to the
# decision, as the audit does. Since package B4 schema 3 names the five v5 roles only, so the family is S2G (the
# same shape under schema 2). Each test builds its own world under tmp_path; nothing above is used or changed
# except the helpers forge, stored, refused and the message constants.

Planned = namedtuple("Planned", "p sha path root places")
DIAGNOSTIC_WINDOWS = {"pilot_cycles": 64, "cycles": 80}  # Clean S2G sessions of 80 and 96 rows (W 8, F 64).


def planned_diagnostic(tmp_path):
    """Family S2G whose only planned role is named diagnostic: two places, one group, one boot."""
    root = tmp_path / "planned"
    doc = dict(bs.family("S2G", bs.profile_dir(root / "profile")), roles={"diagnostic": 1})
    path = bs.write_protocol(root / "protocol.json", doc)
    p = collection.protocol(path)
    places = bs.places(p)
    assert [(s["role"], s["group"]) for s in places] == [("diagnostic", "s2g-diagnostic-1")] * 2
    assert (p["pilot_cycles"], p["cycles"]) == (80, 96)
    return Planned(p, sha(path), path, root, places)


def diagnostic_session(w, index, slot, rows, recorded):
    """A clean session at planned place `index` with `rows` snapshots whose session.json records `recorded`."""
    session = bs.build_session(w.root, w.p, w.path, w.places[index], session_id=f"diag-{slot}",
                               base=bs.time_base(w.p, "diagnostic", slot), rows=rows, meta={"cycles": recorded})
    assert json.loads((session.directory / "session.json").read_text())["cycles"] == recorded
    audit = bs.audit(session, w.p)
    (session.directory / "events.json").write_text('{"events": []}\n')  # Only its digest is read.
    return session, audit


def accepted_diagnostic(w, slot, index, rows):
    """The honest audit of a clean session of `rows` rows recorded as `rows`, checked against the oracle."""
    session, audit = diagnostic_session(w, index, slot, rows, rows)
    windows = bs.window_count(rows, w.p["window_rows"], w.p["full_every"])
    v = audit.values
    assert (audit.code, v["accepted"], v["reasons"]) == (0, True, [])
    assert (v["role"], v["snapshots"], v["windows"], v["score_coverage"]) == ("diagnostic", rows, windows,
                                                                              windows / rows)
    return session, audit


def diagnostic_index(w, reports):
    try:
        return campaign.event_index(reports, w.p, w.sha)
    except ValueError as error:
        pytest.fail("the index refused a planned diagnostic session: " + str(error))


@pytest.mark.parametrize("key", ("pilot_cycles", "cycles"))
def test_planned_role_named_diagnostic_is_indexed(key, tmp_path):
    """Both planned places hold clean sessions of p[key] rows recorded as cycles: accepted and indexed."""
    w = planned_diagnostic(tmp_path)
    length = w.p[key]
    assert bs.window_count(length, w.p["window_rows"], w.p["full_every"]) == DIAGNOSTIC_WINDOWS[key]
    built = [accepted_diagnostic(w, slot, slot, length) for slot in range(2)]
    doc = diagnostic_index(w, [audit.path for _, audit in built])
    assert (doc["complete"], doc["planned_sessions"]) == (True, 2)
    assert [(s["id"], s["role"]) for s in doc["sessions"]] == [("diag-0", "diagnostic"), ("diag-1", "diagnostic")]
    for slot, s in enumerate(doc["sessions"]):
        assert s["start"] == bs.time_base(w.p, "diagnostic", slot) + bs.FIRST_SNAPSHOT_S
        assert s["end"] - s["start"] == (length - 1) * w.p["interval_s"]


@pytest.mark.parametrize("case", ("short", "long", "cycles"))
def test_planned_diagnostic_with_other_stored_rows_is_refused(case, tmp_path):
    """The accepted 80/80 record with only its stored facts.snapshots changed is refused by the decision. The
    cycles case pins that the assigned length of a planned diagnostic session is the recorded one."""
    w = planned_diagnostic(tmp_path)
    n = w.p["pilot_cycles"]
    reports = [accepted_diagnostic(w, slot, slot, n)[1].path for slot in range(2)]
    snapshots = {"short": n - 1, "long": n + 1, "cycles": w.p["cycles"]}[case]
    assert snapshots == {"short": 79, "long": 81, "cycles": 96}[case] != n
    # Twin: the same copy without the edit is admitted.
    assert diagnostic_index(w, [forge(tmp_path, reports[0], name="twin"), reports[1]])["complete"]
    forged = forge(tmp_path, reports[0], stored(lambda a: a["facts"].update(snapshots=snapshots)))
    refused(w, [forged, reports[1]], f"{REJECTS}{ROWS}: {forged}")


def test_planned_diagnostic_of_another_length_is_rejected_by_the_audit(tmp_path):
    """A session of 79 rows recorded as 80: the audit rejects it on the row count (the log audit's own reason is
    an audit check outside the function and is not pinned), and the index refuses its honest record."""
    w = planned_diagnostic(tmp_path)
    n = w.p["pilot_cycles"]
    honest_reports = [accepted_diagnostic(w, slot, slot, n)[1].path for slot in range(2)]
    assert diagnostic_index(w, honest_reports)["complete"]  # Twin: the recorded length met.
    _, audit = diagnostic_session(w, 0, 2, n - 1, n)
    assert (audit.code, audit.values["accepted"], audit.values["snapshots"]) == (2, False, n - 1)
    assert ROWS in audit.values["reasons"]
    refused(w, [audit.path, honest_reports[1]], UNACCEPTED + str(audit.path))


# Addendum 4a (K5-A): the record of a short session forged together with its log audit section. require_log_audit
# reads only the record and the digest of session.json, so such a forgery reaches the decision.
@pytest.mark.parametrize("case", ("partial", "consistent"))
def test_short_session_forged_with_its_log_audit_is_refused(case, tmp_path):
    """A session of 79 rows recorded as 80 whose record states a clean acceptance and a clean log audit is refused by
    the decision on the recorded length. partial keeps the stored verdict's assigned_rows at 80; consistent states
    everything an honest audit of the 79 rows with the assigned length 79 would state."""
    w = planned_diagnostic(tmp_path)
    n, W, F = w.p["pilot_cycles"], w.p["window_rows"], w.p["full_every"]
    honest_reports = [accepted_diagnostic(w, slot, slot, n)[1].path for slot in range(2)]
    assert diagnostic_index(w, honest_reports)["complete"]  # Twin: the recorded length met.
    _, audit = diagnostic_session(w, 0, 2, n - 1, n)
    assert audit.code == 2

    def edit(v):
        f1b(v)
        v["logs"].update(accepted=True, problems=[])
        if case == "consistent":
            windows = v["windows"]
            v.update(score_coverage=windows / (n - 1))
            stored(lambda a: a.update(assigned_rows=n - 1, score_coverage=windows / (n - 1)))(v)

    forged = forge(tmp_path, audit.path, edit)
    refused(w, [forged, honest_reports[1]], f"{REJECTS}{ROWS}: {forged}")
    assert audit.values["windows"] == bs.window_count(n - 1, W, F)
