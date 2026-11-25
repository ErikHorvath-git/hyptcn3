"""The mode majflt of scripts/campaign_report.py (item P2 of the G2 preparation, package G2p2): the bound of the
collector's major faults per cycle, audit.collector_majflt_max, proposed from the audit records of the error-free G2
runs by the lead's rule (his answer to question Q29, 2026-11-24; audit.collector_majflt_note of
config/collection-v5.json): the largest count per cycle observed in the error-free runs of G2 on both VMs, 0 when
every count is 0. Row P2 of dokazy/B10/odlozene_B10.md; [13] to [15] of agent Q's result of B10.

The audit records are written by the real audit, scripts/collection.py audit_session, through the helpers of
scripts/tests/test_collector_majflt.py, unchanged: audited() builds the clean session of the audit self-test with the
given counts of major faults in its sidecars and audits it (the record lies in the session's directory, audit.json).
That session is the first session of plan(p) (scripts/tests/audit_cases.py clean_session), so a session of a VM is
built with plan(p) narrowed to the sessions of that VM while it is built (audit_on); the audit reads no plan. Every
session is of the real protocol file, with its two VMs a and b, except the sessions of another protocol (the small
protocol of the self-test, the fixture small, and a protocol of schema 2). The counts are numbers of these tests, not
measurements; a cycle whose seq is a multiple of 360 (full_every of the file) is a full snapshot. Expected values and
texts are written out here, never made by the mode's code. The names this item adds are used inside the tests only, so
this file collects on the code before it and fails there test by test. No VM, no network, nothing written outside the
test's directories.
"""
import hashlib
import json
from pathlib import Path
from unittest import mock

import pytest

from scripts import campaign_report as cr
from scripts import collection
from scripts.tests.test_collector_majflt import NOT_A_COUNT, V5, audited, small  # noqa: F401 (small: a fixture)

PROVENANCE = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.
RULE = ("The rule, written before the data: the largest count per cycle observed in the error-free runs of G2 on both "
        "VMs; at zero the bound is 0.")  # The sentence of audit.collector_majflt_note the mode quotes.
CYCLES = 720  # The cycles of a session of the real protocol file, each with a count.
VMS = {"a": "hyptcn-lab-a", "b": "hyptcn-lab-b"}  # The vms of the real protocol file.
SESSION = "audit-selftest"  # The session id of every built session (scripts/tests/audit_cases.py SESSION).
REFUSED = "campaign_report: majflt: {} refusal(s): no proposal, nothing written"


@pytest.fixture(autouse=True)
def one_git_state(monkeypatch):
    """The record's commit without asking git (the provenance keys are checked, not the commit)."""
    monkeypatch.setattr(cr, "git_identity", lambda: {"commit": "synthetic", "dirty": False, "changed_paths": 0})


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit_on(vm, root, counts=(), change=None):
    """audited() of scripts/tests/test_collector_majflt.py under the real protocol file, on VM `vm`: plan(p) lists only
    the sessions of `vm` while the clean session is built (and audited, which reads no plan). A
    boundary_sessions.Audit."""
    p, plan = collection.protocol(V5), collection.plan

    def of_vm(q):
        doc = plan(q)
        return dict(doc, sessions=[s for s in doc["sessions"] if s.get("vm") == vm])
    with mock.patch.object(collection, "plan", of_vm):
        return audited(root, p, V5, counts, change)


@pytest.fixture(scope="module")
def audits(tmp_path_factory, small):
    """The audit records of these tests by name: {name: boundary_sessions.Audit}. Under the real protocol file: a1
    and a2 on VM a, b1 and b2 on VM b, a0 and b0 without any fault, `refused` on VM b with a count that is no count in
    the sidecar of frame 3 (FRAME of scripts/tests/test_collector_majflt.py; refused by the audit, with 900 faults in
    one cycle); `other`, the clean session of the small protocol of the self-test."""
    root = tmp_path_factory.mktemp("audits")
    built = {name: audit_on(vm, root / name, counts, change) for name, (vm, counts, change) in {
        "a1": ("a", {3: 4, 200: 6}, None),
        "a2": ("a", {360: 12, 400: 12, 401: 1}, None),
        "b1": ("b", {100: 30}, None),
        "b2": ("b", {seq: 30 for seq in range(5, 10)}, None),
        "a0": ("a", {}, None),
        "b0": ("b", {}, None),
        "refused": ("b", {50: 900}, lambda side: side["capture"]["rusage"].update(majflt=-1)),
    }.items()}
    built["other"] = audited(root / "other", *small)
    return built


def majflt(capsys, out, *records, protocol=V5):
    """(exit code, stdout lines, stderr lines, the record at `out` or None) of the mode over `records` (an Audit or a
    path each)."""
    paths = [str(r.path) if hasattr(r, "values") else str(r) for r in records]
    code = cr.main(["majflt", *paths, "--protocol", str(protocol), "--out", str(out)])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err.splitlines(), (
        json.loads(Path(out).read_text()) if Path(out).is_file() else None)


def vm_line(vm, count, audit, seq, cycle, sessions):
    """The line of one VM on stdout, written out."""
    return (f"vm {vm}: max {count} in session {SESSION} seq {seq} ({cycle} cycle), record {audit.path}; "
            f"{sessions} session(s), {sessions * CYCLES} cycle(s) counted")


def entry(audit, vm, faults, cycle):
    """The entry of one record in values.records, written out: the record's sha256 and that of its session.json are
    computed here from the files."""
    directory = audit.values["session_dir"]
    return {"path": str(audit.path), "sha256": sha(audit.path), "session": SESSION, "session_dir": directory,
            "session_json_sha256": sha(Path(directory) / "session.json"), "vm": vm, "collector_majflt": faults,
            "cycle": cycle}


def copy_of(audit, path, change):
    """A copy at `path` of the record of `audit` whose values `change` changed; the original stays."""
    doc = json.loads(audit.path.read_text())
    change(doc["values"])
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return path


def protocol_copy(tmp_path, change):
    doc = json.loads(V5.read_text())
    change(doc)
    path = tmp_path / "protocol-copy.json"
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return path


# ---------------------------------------------------------------- the proposal


FAULTS = {"a1": {"max": 6, "max_seq": 200, "sum": 10, "cycles": CYCLES},
          "a2": {"max": 12, "max_seq": 360, "sum": 25, "cycles": CYCLES},
          "b1": {"max": 30, "max_seq": 100, "sum": 30, "cycles": CYCLES},
          "b2": {"max": 30, "max_seq": 5, "sum": 150, "cycles": CYCLES},
          "b0": {"max": 0, "max_seq": 0, "sum": 0, "cycles": CYCLES}}
CYCLE = {"a1": "delta", "a2": "full", "b1": "delta", "b2": "delta", "b0": "full"}


@pytest.mark.parametrize("names, by_vm, largest", [
    # VM b: two records with 30 in one cycle, b1 first (seq 100); b2 sums 150. The largest over both VMs is on b.
    (("a1", "a2", "b1", "b2"), {"a": ("a2", 2), "b": ("b1", 2)}, "b"),
    # VM b: one record without any fault (seq 0, the first cycle, a full snapshot). The largest is on a.
    (("a1", "a2", "b0"), {"a": ("a2", 2), "b": ("b0", 1)}, "a"),
], ids=["largest_on_b", "largest_on_a"])
def test_both_vms_give_the_largest_count_per_vm_and_over_both_with_session_seq_and_cycle(audits, tmp_path, capsys,
                                                                                          names, by_vm, largest):
    """Items 2 to 4 of P2 under the real protocol file: per VM the largest values.collector_majflt.max of its records,
    not their sum, with its record, session, seq and cycle (full at seq 360, a multiple of full_every; equal counts go
    to the first record given), the sessions and cycles counted; then the largest over both VMs, not over one of
    them, which is the proposal for audit.collector_majflt_max with the rule quoted from the note of the real file.
    One line per VM and the proposal on stdout; the new record has the provenance of check E and lists every record
    with its path, sha256, session, VM and collector_majflt. The protocol, the records and their session.json stay as
    they were, and nothing else is written."""
    for name in names:
        assert (audits[name].code, audits[name].values["collector_majflt"]) == (0, FAULTS[name])
    files = [V5] + [p for name in names for p in (audits[name].path,
                                                  Path(audits[name].values["session_dir"]) / "session.json")]
    before = {path: sha(path) for path in files}
    out = tmp_path / "majflt.json"
    code, lines, err, record = majflt(capsys, out, *(audits[name] for name in names))
    top = {vm: (audits[name], FAULTS[name], CYCLE[name], sessions) for vm, (name, sessions) in by_vm.items()}
    audit, faults, cycle, _ = top[largest]
    sessions = len(names)
    assert code == 0
    assert lines == [vm_line(vm, f["max"], a, f["max_seq"], c, n) for vm, (a, f, c, n) in top.items()] + [
        f"proposal: audit.collector_majflt_max = {faults['max']} (vm {largest}, session {SESSION} seq "
        f"{faults['max_seq']}, {cycle} cycle, record {audit.path}; {sessions} session(s), {sessions * CYCLES} "
        f"cycle(s) on 2 VMs); the rule of audit.collector_majflt_note: \"{RULE}\""]
    assert err == [f"campaign_report: majflt: {sessions} record(s), proposal audit.collector_majflt_max = "
                   f"{faults['max']}; record {out}"]
    assert all(key in record for key in PROVENANCE) and "values" in record
    assert (record["schema"], record["commit"], record["n"]) == ("hyptcn3/collector-majflt-bound/1", "synthetic",
                                                                sessions)
    v = record["values"]
    vm_of = {name: name[0] for name in names}
    assert v["protocol"] == {"path": str(V5), "sha256": sha(V5), "audit.collector_majflt_max": None, "vms": VMS,
                             "full_every": 360}
    assert v["records"] == [entry(audits[name], vm_of[name], FAULTS[name], CYCLE[name]) for name in names]
    expected = {vm: {"max": f["max"], "record": str(a.path), "session": SESSION, "session_dir": a.values["session_dir"],
                     "seq": f["max_seq"], "cycle": c, "sessions": n, "cycles": n * CYCLES}
                for vm, (a, f, c, n) in top.items()}
    assert v["by_vm"] == expected
    assert v["largest"] == {"vm": largest, **expected[largest], "sessions": sessions, "cycles": sessions * CYCLES}
    note = json.loads(V5.read_text())["audit"]["collector_majflt_note"]
    assert RULE in note
    assert v["proposal"] == {"key": "audit.collector_majflt_max", "value": faults["max"], "rule": RULE, "note": note}
    assert {path: sha(path) for path in files} == before
    assert sorted(tmp_path.iterdir()) == [out]


def test_every_count_0_gives_the_bound_0(audits, tmp_path, capsys):
    """The rule at zero: sessions on both VMs whose every cycle counts 0 major faults give the bound 0 (the first cycle
    of each, a full snapshot, holds the largest count 0; over the VMs the first VM of the protocol)."""
    zero = {"max": 0, "max_seq": 0, "sum": 0, "cycles": CYCLES}
    assert [(audits[name].code, audits[name].values["collector_majflt"]) for name in ("a0", "b0")] == [(0, zero)] * 2
    out = tmp_path / "majflt.json"
    code, lines, _, record = majflt(capsys, out, audits["a0"], audits["b0"])
    assert code == 0
    assert lines == [vm_line("a", 0, audits["a0"], 0, "full", 1), vm_line("b", 0, audits["b0"], 0, "full", 1),
                     f"proposal: audit.collector_majflt_max = 0 (vm a, session {SESSION} seq 0, full cycle, record "
                     f"{audits['a0'].path}; 2 session(s), {2 * CYCLES} cycle(s) on 2 VMs); the rule of "
                     f"audit.collector_majflt_note: \"{RULE}\""]
    assert (record["values"]["proposal"]["value"], record["values"]["largest"]["vm"]) == (0, "a")


# ---------------------------------------------------------------- refused by name: nothing proposed, nothing written


def test_a_vm_without_a_record_refuses_the_proposal_by_name(audits, tmp_path, capsys):
    """The rule needs both VMs: records of one VM alone, whichever, make no proposal."""
    for given, missing in ((("a1", "a2"), "b"), (("b1",), "a")):
        out = tmp_path / f"majflt-{missing}.json"
        code, lines, err, record = majflt(capsys, out, *(audits[name] for name in given))
        assert (code, lines, record) == (2, [], None)
        assert err == [f"campaign_report: majflt: no audit record of VM {missing}: the rule needs both VMs of the "
                       "protocol (a, b)", REFUSED.format(1)]


def test_a_refused_verdict_is_refused_by_name_and_never_counted(audits, tmp_path, capsys):
    """A session the audit refused (a count that is no count, under the null bound of the file) is no error-free run:
    its record is refused by name, although its 900 faults in one cycle would have been the largest count."""
    refused = audits["refused"]
    assert (refused.code, refused.values["accepted"], refused.values["reasons"]) == (2, False, [NOT_A_COUNT])
    assert refused.values["collector_majflt"] == {"max": 900, "max_seq": 50, "sum": 900, "cycles": CYCLES - 1}
    code, lines, err, record = majflt(capsys, tmp_path / "majflt.json", audits["a1"], refused, audits["b1"])
    assert (code, lines, record) == (2, [], None)
    assert err == [f"campaign_report: majflt: {refused.path}: its verdict is not accepted: values.accepted is false "
                   f"(reasons: {NOT_A_COUNT})", REFUSED.format(1)]


def test_a_session_refused_only_for_unlisted_collector_warnings_counts(audits, tmp_path, capsys):
    """The lead's answer to Q60: audit.warnings_allowed is null until G2, so the audit refuses every session with a
    collector warning; such a session, refused for nothing else, still counts for the bound and is listed apart. One
    more reason of any other kind refuses it by name, as any refused verdict."""
    warning = "logs: collector_warning_unlisted:writer queue waited 120 ms"
    only = copy_of(audits["b1"], tmp_path / "only.json", lambda v: v.update(accepted=False, reasons=[warning]))
    code, lines, err, record = majflt(capsys, tmp_path / "majflt.json", audits["a1"], only)
    assert code == 0, err
    assert record["values"]["warnings_only"] == [str(only)]
    assert [e.get("accepted_by") for e in record["values"]["records"]] == [None, "warnings_only"]
    assert record["values"]["proposal"]["value"] == 30
    more = copy_of(audits["b1"], tmp_path / "more.json",
                   lambda v: v.update(accepted=False, reasons=[warning, "logs: service_restarted:hyptcn-lab@auth"]))
    code, lines, err, record = majflt(capsys, tmp_path / "majflt-more.json", audits["a1"], more)
    assert (code, record) == (2, None)
    assert err[0].startswith(f"campaign_report: majflt: {more}: its verdict is not accepted"), err


def schema_2_audit(root):
    """The audit of a train session of the schema-2 family S2G of scripts/tests/boundary_sessions.py (its sidecars
    are those of scripts/tests/test_collector_majflt.py test_schemas_1_and_2_do_not_read_the_count, without a change):
    (Audit, protocol path)."""
    from scripts.tests import boundary_sessions as bs
    path = bs.write_protocol(root / "S2G.json", bs.family("S2G", bs.profile_dir(root / "profile")))
    p = collection.protocol(path)
    session = bs.build_session(root / "sessions", p, path, bs.places(p, "train")[0], session_id="majflt-schema2",
                               base=bs.time_base(p, "train", 0))
    return bs.audit(session, p), path


@pytest.mark.parametrize("kind", ["other_protocol", "schema_2", "protocol_file", "not_json"])
def test_a_record_that_is_no_schema_3_audit_of_the_protocol_is_refused_by_name(audits, tmp_path, capsys, small, kind):
    """By sha256: the audit of a session of another schema-3 protocol (the small protocol of the self-test) and of a
    schema-2 protocol (whose values.collector_majflt is null) are no audits of the protocol; the protocol file and a
    text file are no audit records at all."""
    if kind == "other_protocol":
        record, other = audits["other"], small[1]
        assert record.values["accepted"] is True
        why = (f"{record.path}: not an audit of the protocol: its values.protocol_sha256 is \"{sha(other)}\", the "
               f"protocol's sha256 is {sha(V5)}")
    elif kind == "schema_2":
        record, other = schema_2_audit(tmp_path / "s2g")
        assert (record.values["accepted"], record.values["collector_majflt"]) == (True, None)
        why = (f"{record.path}: not an audit of the protocol: its values.protocol_sha256 is \"{sha(other)}\", the "
               f"protocol's sha256 is {sha(V5)}")
    elif kind == "protocol_file":
        record = V5
        why = (f"{V5}: not an audit record of scripts/collection.py (a JSON object of schema "
               "hyptcn3/collection-audit/1 with values): its schema is \"hyptcn3/collection-protocol/3\"")
    else:
        record = tmp_path / "audit.txt"
        record.write_text("accepted\n")
        why = f"{record}: not JSON (Expecting value: line 1 column 1 (char 0))"
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", audits["a1"], record, audits["b1"])
    assert (code, lines, out) == (2, [], None)
    assert err == [f"campaign_report: majflt: {why}", REFUSED.format(1)]


@pytest.mark.parametrize("change, why", [
    (lambda values: values.pop("collector_majflt"), "records no values.collector_majflt (it is absent), the largest "
                                                    "count per cycle the rule takes"),
    (lambda values: values.update(collector_majflt=None), "records no values.collector_majflt (it is null), the "
                                                          "largest count per cycle the rule takes"),
    (lambda values: values["collector_majflt"].pop("cycles"),
     "values.collector_majflt is {\"max\": 30, \"max_seq\": 100, \"sum\": 30}, not the audit's record of a session "
     "with a count in every cycle (max, max_seq, sum and cycles: integers of at least 0, at least one cycle)"),
    (lambda values: values.update(collector_majflt={"max": None, "max_seq": None, "sum": None, "cycles": 0}),
     "values.collector_majflt is {\"cycles\": 0, \"max\": null, \"max_seq\": null, \"sum\": null}, not the audit's "
     "record of a session with a count in every cycle (max, max_seq, sum and cycles: integers of at least 0, at least "
     "one cycle)"),
], ids=["absent", "null", "no_cycles", "no_count"])
def test_a_record_without_values_collector_majflt_is_refused_by_name(audits, tmp_path, capsys, change, why):
    """A copy of the record b1 without the audit's values.collector_majflt (absent, null), or with one that is not the
    record of a session with a count in every cycle (no cycles; no usable count, as the audit records it then), is
    refused by name, never taken as 0."""
    record = copy_of(audits["b1"], tmp_path / "audit-copy.json", change)
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", audits["a1"], audits["b2"], record)
    assert (code, lines, out) == (2, [], None)
    assert err == [f"campaign_report: majflt: {record}: {why}", REFUSED.format(1)]


def test_a_record_named_twice_or_two_records_of_one_session_are_refused(audits, tmp_path, capsys):
    """The same record twice, also through a link to it, is refused before anything is read; a copy of a record names
    its session once more, and a session counts once."""
    a1, b1 = audits["a1"], audits["b1"]
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", a1, b1, a1)
    assert (code, lines, err, out) == (2, [], [f"campaign_report: majflt: an audit record is named more than once: "
                                               f"{a1.path}"], None)
    link = tmp_path / "audit-link.json"
    link.symlink_to(a1.path)
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", a1, b1, link)
    assert (code, lines, err, out) == (2, [], ["campaign_report: majflt: an audit record is named more than once: "
                                               + ", ".join(sorted([str(a1.path), str(link)]))], None)
    copy = copy_of(a1, tmp_path / "audit-copy.json", lambda values: None)
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", a1, copy, b1)
    assert (code, lines, out) == (2, [], None)
    assert err == [f"campaign_report: majflt: 2 audit records name one session, values.session_dir "
                   f"{a1.values['session_dir']}: {a1.path}, {copy} (a session counts once)", REFUSED.format(1)]


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_an_existing_out_is_refused_before_anything_is_read(tmp_path, capsys, monkeypatch, kind):
    """An --out that exists, a file or a dangling link, is refused before the protocol or any record is read, and it
    stays as it was."""
    out = tmp_path / "majflt.json"
    if kind == "file":
        out.write_text("kept\n")
    else:
        out.symlink_to(tmp_path / "nowhere.json")

    def unread(*args):
        raise AssertionError("read before --out was refused")
    monkeypatch.setattr(cr, "majflt_protocol", unread)
    monkeypatch.setattr(cr, "majflt_audit", unread)
    code = cr.main(["majflt", str(tmp_path / "no-audit.json"), "--protocol", str(tmp_path / "no-protocol.json"),
                    "--out", str(out)])
    captured = capsys.readouterr()
    assert (code, captured.out) == (2, "")
    assert captured.err.splitlines() == [f"campaign_report: --out already exists, nothing was read or written: {out}"]
    assert out.read_text() == "kept\n" if kind == "file" else out.is_symlink() and not out.exists()


def test_an_out_inside_the_session_directory_of_a_record_is_refused(audits, tmp_path, capsys):
    """The mode writes nothing into its inputs: not into the directory of a session it reads."""
    directory = Path(audits["a1"].values["session_dir"])
    listed = sorted(directory.iterdir())
    out = directory / "majflt.json"
    code, lines, err, record = majflt(capsys, out, audits["a1"], audits["b1"])
    assert (code, lines, record, sorted(directory.iterdir())) == (2, [], None, listed)
    assert err == [f"campaign_report: majflt: refusing to write {out} inside the session directory {directory}",
                   REFUSED.format(1)]


# ---------------------------------------------------------------- the VM of a record


def forged(audit, root, change=None, *, bind=True, directory=None):
    """A copy of the record of `audit` under root whose values.session_dir is a new directory holding a copy of the
    session's session.json, changed by `change`; values.session_sha256 is the sha256 of that copy when `bind`.
    `directory` instead names a session directory without session.json. Returns (record path, session.json path)."""
    session = root / "session" / SESSION
    meta = json.loads((Path(audit.values["session_dir"]) / "session.json").read_text())
    if change is not None:
        change(meta)
    session.mkdir(parents=True)
    (session / "session.json").write_text(json.dumps(meta, indent=2) + "\n")
    digest = sha(session / "session.json")
    target = str(directory if directory is not None else session)

    def point(values):
        values.update(session_dir=target, **({"session_sha256": digest} if bind else {}))
    return copy_of(audit, root / "audit-forged.json", point), Path(target) / "session.json"


def test_the_vm_is_that_of_the_session_json_the_audit_read(audits, tmp_path, capsys):
    """The record names no VM: the mode takes the vm of the session.json in values.session_dir whose sha256 is
    values.session_sha256. A copy of the record b1 bound to a session.json of VM a counts on VM a."""
    as_a = lambda meta: meta.update(vm="a", domain=VMS["a"])  # noqa: E731
    record, _ = forged(audits["b1"], tmp_path / "forged", as_a)
    code, lines, _, out = majflt(capsys, tmp_path / "majflt.json", record, audits["b2"])
    assert code == 0
    assert lines[0] == (f"vm a: max 30 in session {SESSION} seq 100 (delta cycle), record {record}; 1 session(s), "
                        f"{CYCLES} cycle(s) counted")
    assert [(e["path"], e["vm"]) for e in out["values"]["records"]] == [(str(record), "a"),
                                                                        (str(audits["b2"].path), "b")]


@pytest.mark.parametrize("kind", ["changed", "moved", "foreign_vm", "foreign_domain"])
def test_a_session_json_that_is_not_the_audited_one_or_names_no_vm_of_the_protocol_is_refused(audits, tmp_path,
                                                                                             capsys, kind):
    """A session.json changed since the audit, a session moved after its audit (no session.json where the record says),
    and a session.json bound to the record that names a VM the protocol does not have, or another VM's domain."""
    root = tmp_path / "forged"
    if kind == "changed":
        record, meta = forged(audits["b1"], root, lambda m: m.update(edited=True), bind=False)
        why = (f"{meta} is not the session.json the audit read: its sha256 is {sha(meta)}, values.session_sha256 "
               f"{audits['b1'].values['session_sha256']}")
    elif kind == "moved":
        record, meta = forged(audits["b1"], root, directory=tmp_path / "moved" / SESSION)
        why = (f"no session.json in values.session_dir {meta.parent}, which names the session's VM (was the session "
               "moved after its audit?)")
    elif kind == "foreign_vm":
        record, meta = forged(audits["b1"], root, lambda m: m.update(vm="c"))
        why = f"{meta} names the VM \"c\", not a VM of the protocol (a, b)"
    else:
        record, meta = forged(audits["b1"], root, lambda m: m.update(domain=VMS["a"]))
        why = f"{meta} names the domain \"{VMS['a']}\" for the VM b, the protocol's vms give it {VMS['b']}"
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", audits["a1"], record)
    assert (code, lines, out) == (2, [], None)
    assert err == [f"campaign_report: majflt: {record}: {why}", REFUSED.format(1)]


# ---------------------------------------------------------------- the protocol and the rule


@pytest.mark.parametrize("change, why", [
    (lambda doc: doc["audit"].update(collector_majflt_max=0),
     "audit.collector_majflt_max is 0, not null: an audit under a bound accepts no cycle above it, so its records "
     "cannot show the largest count the rule asks for (null until G2, determined_at G2)"),
    (lambda doc: doc["audit"].update(collector_majflt_note=doc["audit"]["collector_majflt_note"].replace(
        RULE, "The rule: the sum of the counts.")),
     f"audit.collector_majflt_note does not state the rule this mode applies, \"{RULE}\""),
    (lambda doc: doc.update(schema="hyptcn3/collection-protocol/2"),
     "protocol schema is not hyptcn3/collection-protocol/3: audit.collector_majflt_max is a key of its audit section"),
    (lambda doc: doc.update(vms=doc["vms"][:1]),
     "names fewer than two VMs, each with its own name and a domain (vms): the rule takes the runs on both VMs"),
    (lambda doc: doc["audit"].pop("collector_majflt_note"),
     "no audit.collector_majflt_note (the lead's answer to Q29)"),
    (lambda doc: doc["audit"].pop("collector_majflt_max"), "no audit.collector_majflt_max (the lead's answer to Q29)"),
    (lambda doc: doc["audit"].update(collector_majflt_note=[RULE]),
     f"audit.collector_majflt_note does not state the rule this mode applies, \"{RULE}\""),
    (lambda doc: doc.update(full_every=0), "full_every is 0, not an integer >= 1 (it tells a full snapshot's cycle)"),
], ids=["bound_set", "rule_not_stated", "schema_2", "one_vm", "no_note", "no_bound", "note_no_text", "full_every"])
def test_a_protocol_the_rule_does_not_apply_to_is_refused_before_any_record(audits, tmp_path, capsys, monkeypatch,
                                                                            change, why):
    """The protocol is read once, before any record: of schema 3, with both keys of the rule, a null bound (G2 sets it
    from records the audit did not judge by a bound), a note that states the rule the mode applies, both VMs and the
    cadence of full snapshots."""
    path = protocol_copy(tmp_path, change)

    def unread(*args):
        raise AssertionError("a record was read under a refused protocol")
    monkeypatch.setattr(cr, "majflt_audit", unread)
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", audits["a1"], audits["b1"], protocol=path)
    assert (code, lines, err, out) == (2, [], [f"campaign_report: majflt: protocol {path}: {why}"], None)


def test_a_protocol_that_cannot_be_read_is_refused_before_any_record(audits, tmp_path, capsys, monkeypatch):
    def unread(*args):
        raise AssertionError("a record was read without a protocol")
    monkeypatch.setattr(cr, "majflt_audit", unread)
    missing = tmp_path / "no-protocol.json"
    code, lines, err, out = majflt(capsys, tmp_path / "majflt.json", audits["a1"], audits["b1"], protocol=missing)
    assert (code, lines, err, out) == (2, [], [f"campaign_report: majflt: cannot read protocol {missing}: [Errno 2] "
                                               f"No such file or directory: '{missing}'"], None)


def test_the_rule_names_its_origin_what_it_reads_where_the_records_lie_and_who_chooses_the_runs():
    """MAJFLT_RULE, written beside the result: the lead's answer to Q29 and the note of the protocol; the mode never
    writes the protocol; the G2 record, not the mode, decides which runs are error-free; where scripts/collection.py
    audit writes a record; what is read (the VM from the session.json the audit read) and what is not; the rule's two
    VMs and its 0. The sentence the mode quotes is the one of the real file, and the module's usage names the mode."""
    for words in ("question Q29 (2026-11-24)", "audit.collector_majflt_note", "row P2 of dokazy/B10/odlozene_B10.md",
                  "never writes the protocol",
                  "It does not decide which runs are error-free: the G2 record states that",
                  "scripts/collection.py audit (audit_session) writes the record of a session into the session's "
                  "directory as audit_<UTC stamp>.json, or to the file its --out names",
                  "vm of the session.json in values.session_dir, read only when its sha256 is values.session_sha256",
                  "no RAM, no archive member, no score", "the rule needs both VMs", "so 0 when every count is 0"):
        assert words in cr.MAJFLT_RULE, words
    assert cr.MAJFLT_RULE_TEXT == RULE
    assert RULE in json.loads(V5.read_text())["audit"]["collector_majflt_note"]
    assert "scripts/campaign_report.py majflt AUDIT [AUDIT ...] --protocol P --out NEW_FILE" in cr.__doc__
