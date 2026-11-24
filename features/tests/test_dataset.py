import json
from pathlib import Path

import numpy as np
import pytest

from features import archive, dataset
from features.acceptance import judge
from features.snapshot import MENA

LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 4096]],
          "regions": [{"gpa": 0, "bytes": 16777216}], "memsize": 16777216, "vcpus": 1}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "truncated_traversals": [],
        "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0, "process_walk": "next"}
ROW = dict.fromkeys(MENA, 0.) | {
    "mem_changed_ratio": .1, "mem_bins_active": 1, "mem_changed_max": .1, "mem_changed_p95": .1,
    "mem_entropy_mean": 4, "mem_entropy_max": 4, "mem_zero_ratio": .2, "proc_total": 20, "proc_user": 15,
    "proc_kernel": 5, "mod_total": 10, "sock_total": 4, "sock_listen": 1, "sock_estab": 3, "ma_predchodcu": 1}
INVALID = 1  # seq of the row the tampering tests make invalid
# The roles of the schema-2 protocol below; since package B6a dataset.ROLES also holds test_controls, a role of
# schema 3 only.
ROLES = ("train", "dev", "calibration", "test_benign")


def extraction(number, invalid=None):
    """Extraction result of one session: a full snapshot at seq 0, then one chain of deltas every interval_s.

    invalid: {seq: cause} of rows with incomplete behavioral inputs; like features.snapshot, the row after
    such a row has no predecessor and no differences.
    """
    invalid, p = invalid or {}, protocol()
    rows = p["cycles"]
    matrix = np.tile([ROW[name] for name in MENA], (rows, 1))
    matrix[0, MENA.index("je_plna")] = 1
    for seq in {0} | {s + 1 for s in invalid}:
        matrix[seq, [MENA.index(n) for n in ("proc_new", "proc_gone", "mod_delta", "ma_predchodcu")]] = 0
    quality = [dict(GOOD, model_valid=False, behavior_valid=False, traversals_complete=False, **invalid[i])
               if i in invalid else dict(GOOD) for i in range(rows)]
    perbin = np.zeros((rows, len(LAYOUT["bins"]), 4))
    perbin[:] = [ROW["mem_changed_ratio"], ROW["mem_zero_ratio"], ROW["mem_entropy_mean"], 1]
    t0 = 1700000000. + number * 1000
    return {"matica": matrix, "seq": list(range(rows)), "casy": [t0 + p["interval_s"] * i for i in range(rows)],
            "valid": [q["behavior_valid"] for q in quality], "perbin": perbin, "biny": [b for b, _ in LAYOUT["bins"]],
            "chain_ids": [f"chain-{number}"] * rows, "snimky": [f"{i}.vmicd" for i in range(rows)],
            "trvanie_s": [0.] * rows, "poznamky": [[] for _ in range(rows)], "quality": quality,
            "quality_policy": "behavioral-inputs-v1", "layout": LAYOUT, "max_medzera_s": p["max_gap_s"]}


def audited(feature_path, session, p, role):
    """Values the collection audit writes from its verdict on the archive (scripts/collection.py audit_session)."""
    verdict, _, _ = judge(archive.load(feature_path), p, session, role)
    return {"features_sha256": dataset.sha(feature_path), "snapshots": verdict["snapshots"],
            "windows": verdict["windows"], "score_coverage": verdict["score_coverage"],
            "quality": {"tolerated_invalid_seq": verdict["tolerated_invalid_seq"]}, "acceptance": verdict}


def record(tmp_path, role, number, boot=None):
    directory = tmp_path / f"{role}-{number}"
    directory.mkdir()
    feature_path = archive.save(directory / "features.npz", extraction(number))
    meta = {"session_id": directory.name, "role": role, "group": f"{role}-1",
            "scenario": "steady", "seed": number, "typ": "benign",
            "collector_sha256": "test-collector",
            "guest_before": {"boot_id": boot or directory.name, "kernel": "test-kernel", "stack_sha256": "test-stack"}}
    path = directory / "session.json"
    path.write_text(json.dumps(meta))
    audit = directory / "audit.json"
    audit.write_text(json.dumps({"values": {
        "accepted": True, "reasons": [], "role": role, "protocol_sha256": "protocol-test",
        "session_dir": str(directory), "session_sha256": dataset.sha(path), "features": str(feature_path),
        "layout": LAYOUT, "extractor_sha256": {"test": "test"},
        **audited(feature_path, directory.name, protocol(), role)}}))
    return audit


def protocol():
    return {"schema": "hyptcn3/collection-protocol/2", "quality_policy": "behavioral-inputs-v1",
            "roles": dict.fromkeys(ROLES, 1), "scenarios": {"steady": {}},
            "cycles": 30, "full_every": 30, "window_rows": 3, "stride": 1, "interval_s": 5, "max_gap_s": 7.5,
            "min_score_coverage": .8}


def invalidate(audit, cause):
    """Swap the audited archive for one whose row INVALID is invalid for cause; the record stays as it was.

    Only the archive hash in the record follows the swap: verdict, facts and the list of tolerated rows are
    still those of the archive the audit saw.
    """
    report = json.loads(audit.read_text())
    values = report["values"]
    meta = json.loads((audit.parent / "session.json").read_text())
    Path(values["features"]).unlink()
    archive.save(values["features"], extraction(meta["seed"], {INVALID: cause}))
    values["features_sha256"] = dataset.sha(values["features"])
    audit.write_text(json.dumps(report))
    return report


def audit_again(audit, p):
    """Rewrite the record as the honest audit of the archive now in place, under protocol p."""
    report = json.loads(audit.read_text())
    meta = json.loads((audit.parent / "session.json").read_text())
    report["values"].update(audited(report["values"]["features"], meta["session_id"], p, meta["role"]))
    audit.write_text(json.dumps(report))
    return report


def list_invalid(audit, report):
    """The forger also names row INVALID, in the record's list and in its stored verdict."""
    report["values"]["quality"] = {"tolerated_invalid_seq": [INVALID]}
    report["values"]["acceptance"]["tolerated_invalid_seq"] = [INVALID]
    audit.write_text(json.dumps(report))


def test_complete_corpus_keeps_prescribed_roles(tmp_path):
    audits = [record(tmp_path, role, i) for i, role in enumerate(ROLES)]
    result = dataset.build(audits, protocol(), "protocol-test")
    assert result["complete"]
    assert [r["role"] for r in result["sessions"]] == list(ROLES)


def test_boot_leak_between_train_and_calibration_is_rejected(tmp_path):
    a = record(tmp_path, "train", 0, boot="same")
    b = record(tmp_path, "calibration", 1, boot="same")
    with pytest.raises(ValueError, match="shared"):
        dataset.build([a, b], protocol(), "protocol-test")


def test_relabelling_after_audit_is_rejected(tmp_path):
    audit = record(tmp_path, "train", 0)
    meta = audit.parent / "session.json"
    m = json.loads(meta.read_text())
    m["role"] = "test_benign"
    meta.write_text(json.dumps(m))
    with pytest.raises(ValueError, match="metadata changed"):
        dataset.build([audit], protocol(), "protocol-test")


def test_duplicate_and_partial_corpus(tmp_path):
    audit = record(tmp_path, "train", 0)
    with pytest.raises(ValueError, match="duplicate"):
        dataset.build([audit, audit], protocol(), "protocol-test")
    assert not dataset.build([audit], protocol(), "protocol-test")["complete"]


@pytest.mark.parametrize("verdict", [None, False, True])
def test_managed_sessions_cannot_bypass_log_audit(tmp_path, verdict):
    path = record(tmp_path, "train", 0)
    meta_path = path.parent / "session.json"
    meta = json.loads(meta_path.read_text())
    meta["schema"] = "hyptcn3/collection-session/2"
    meta_path.write_text(json.dumps(meta))
    report = json.loads(path.read_text())
    values = report["values"]
    values["session_sha256"] = dataset.sha(meta_path)
    if verdict is not None:
        values["logs"] = {"schema": "hyptcn3/collection-logs-audit/1", "accepted": verdict,
                          "problems": [] if verdict else ["missing request"],
                          "sections": {"metadata": {"session_sha256": values["session_sha256"]}}}
    path.write_text(json.dumps(report))
    if verdict:
        assert len(dataset.build([path], protocol(), "protocol-test")["sessions"]) == 1
    else:
        with pytest.raises(ValueError, match="log audit"):
            dataset.build([path], protocol(), "protocol-test")


def test_index_builder_and_trainer_accept_same_collection_provenance(tmp_path):
    """Exercise the CLI-produced index shape against training's strict reader."""
    from safeguard.training import validate_index

    config = {**protocol(),
              "window_rows": 3, "max_gap_s": 7.5, "interval_s": 5}
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(config))
    protocol_sha = dataset.sha(protocol_path)
    audits = [record(tmp_path, role, i) for i, role in enumerate(ROLES)]
    for role, audit in zip(ROLES, audits):
        metadata_path = audit.parent / "session.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.update(schema="hyptcn3/collection-session/1", protocol_sha256=protocol_sha)
        metadata_path.write_text(json.dumps(metadata))
        report = json.loads(audit.read_text())
        report["schema"] = "hyptcn3/collection-audit/1"
        report["values"].update(role=role, reasons=[], protocol_sha256=protocol_sha,
                                  session_sha256=dataset.sha(metadata_path))
        audit.write_text(json.dumps(report))
    index = dataset.build(audits, config, protocol_sha)
    index["protocol"] = str(protocol_path.resolve())
    index_path = tmp_path / "corpus.json"
    index_path.write_text(json.dumps(index))
    # Synthetic metadata has no real guest profile or current extractor provenance.
    loaded, frozen_protocol, records = validate_index(index_path, diagnostic=True)
    assert loaded["complete"]
    assert frozen_protocol == config
    assert [row["role"] for row in records] == list(ROLES)
    assert all(row["protocol_sha256"] == protocol_sha for row in records)


def test_protocol_with_events_carries_each_sessions_events(tmp_path):
    """Protokol v4 (krok B): udalosti vo vsetkych rolach, zaznam ide do korpusu pre E2'."""
    audits = [record(tmp_path, role, i) for i, role in enumerate(ROLES)]
    config = dict(protocol(), events={"classes": {"zamok_tabulky": "chyba_aplikacie"}})
    with pytest.raises(ValueError, match="no events.json"):
        dataset.build(audits, config, "protocol-test")
    for role in ROLES:
        (tmp_path / f"{role}-{ROLES.index(role)}" / "events.json").write_text('{"events": []}')
    result = dataset.build(audits, config, "protocol-test")
    assert all(r["events_sha256"] == dataset.sha(r["events"]) for r in result["sessions"])
    assert "events" not in dataset.build(audits, protocol(), "protocol-test")["sessions"][0]


def test_group_names_follow_protocol_prefix(tmp_path):
    audit = record(tmp_path, "train", 0)
    with pytest.raises(ValueError, match="outside the planned allocation"):
        dataset.build([audit], dict(protocol(), group_prefix="v4-"), "protocol-test")
    meta = tmp_path / "train-0" / "session.json"
    doc = json.loads(meta.read_text())
    meta.write_text(json.dumps(dict(doc, group="v4-train-1")))
    report = json.loads(audit.read_text())
    report["values"]["session_sha256"] = dataset.sha(meta)
    audit.write_text(json.dumps(report))
    assert dataset.build([audit], dict(protocol(), group_prefix="v4-"), "protocol-test")["sessions"]


def test_tolerated_invalid_rows_enter_the_corpus_only_within_the_rule(tmp_path):
    audits = [record(tmp_path, role, i) for i, role in enumerate(ROLES)]
    path = audits[0]
    report = invalidate(path, {"truncated_traversals": ["processes"]})
    with pytest.raises(ValueError, match="incomplete features in accepted audit"):
        dataset.build(audits, protocol(), "protocol-test")
    list_invalid(path, report)
    with pytest.raises(ValueError, match="more invalid rows than the protocol tolerates"):
        dataset.build(audits, protocol(), "protocol-test")
    # The record carries the verdict of the protocol the corpus is built under: audited again under that one.
    tolerant = dict(protocol(), invalid_rows={"max": 3, "traversals": ["processes"]})
    assert audit_again(path, tolerant)["values"]["quality"] == {"tolerated_invalid_seq": [INVALID]}
    assert dataset.build(audits, tolerant, "protocol-test")["complete"]


@pytest.mark.parametrize("cause", [
    {"truncated_traversals": ["modules"]},
    {"truncated_traversals": ["processes", "modules"]},
    {"truncated_traversals": ["processes"], "read_errors": 1},
    {"truncated_traversals": ["processes"], "filled_zero": 4096},
    {"truncated_traversals": []},
], ids=["other_traversal", "two_traversals", "read_error", "filled_zero", "no_traversal"])
def test_listed_invalid_row_with_a_cause_outside_the_rule_stays_out_of_the_corpus(tmp_path, cause):
    """The audit's list alone admits nothing: corpus building checks the cause of each invalid row itself."""
    audits = [record(tmp_path, role, i) for i, role in enumerate(ROLES)]
    path = audits[0]
    tolerant = dict(protocol(), invalid_rows={"max": 3, "traversals": ["processes"]})
    # The honest record of a tolerated row; then the archive is swapped for one whose row has another cause.
    invalidate(path, {"truncated_traversals": ["processes"]})
    audit_again(path, tolerant)
    assert dataset.build(audits, tolerant, "protocol-test")["complete"]
    invalidate(path, cause)
    with pytest.raises(ValueError, match="cause the protocol does not tolerate"):
        dataset.build(audits, tolerant, "protocol-test")


@pytest.mark.parametrize("case", ["repeated", "rewritten", "reclaimed", "reclaimed_rewritten", "detached"])
def test_log_audit_is_repeated_where_the_session_keeps_its_logs(tmp_path, case):
    """B2 deferred point 6: on a session that keeps its logs the corpus build runs the log audit again, so a record
    whose logs section was rewritten is refused. Finding S9 of B3 (package B9a): a session whose raw/ went to the
    archive is audited again through the link while the archive is attached (a rewritten record is refused there
    too); with the archive not attached the record is trusted, and the index row says so by name."""
    from scripts import collection
    from scripts.tests import boundary_sessions as bs
    path = bs.write_protocol(tmp_path / "protocol.json", bs.family("S2G", bs.profile_dir(tmp_path / "profile")))
    p = collection.protocol(path)
    place = bs.places(p, "train")[0]
    session = bs.build_session(tmp_path / "sessions", p, path, place, session_id="train-0",
                               base=bs.time_base(p, "train", 0))
    audit = bs.audit(session, p)
    assert audit.code == 0, audit.values["reasons"]
    if case.startswith("reclaimed") or case == "detached":
        # scripts/collection_archive.py: raw/ becomes a link to the verified archive copy.
        (session.directory / "raw").rename(tmp_path / "archive-raw")
        (session.directory / "raw").symlink_to(tmp_path / "archive-raw", target_is_directory=True)
    if case == "detached":  # The archive disk is not mounted: the link dangles.
        (tmp_path / "archive-raw").rename(tmp_path / "archive-raw-elsewhere")
    if case.endswith("rewritten"):
        report = json.loads(audit.path.read_text())
        report["values"]["logs"]["sections"]["monitor"]["samples"] += 1
        audit.path.write_text(json.dumps(report))
        with pytest.raises(ValueError, match="^log audit differs from the record$"):
            dataset.build([audit.path], p, dataset.sha(path))
        return
    row, = dataset.build([audit.path], p, dataset.sha(path))["sessions"]
    if case == "detached":
        from features.quality import NOT_REPEATED  # A name of package B9a: imported here, the file collects before it.
        assert row["log_audit"] == f"{NOT_REPEATED['detached']} ({tmp_path / 'archive-raw'})"
        return
    assert row["log_audit"] == "repeated"
