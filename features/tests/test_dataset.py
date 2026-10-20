import json

import pytest

from features import archive, dataset
from features.tests.test_collection_contract import archive_result


def record(tmp_path, role, number, boot=None):
    directory = tmp_path / f"{role}-{number}"
    directory.mkdir()
    result = archive_result()
    result["quality_policy"] = "behavioral-inputs-v1"
    result["casy"] = [t + number * 100 for t in result["casy"]]
    feature_path = archive.save(directory / "features.npz", result)
    meta = {"session_id": directory.name, "role": role, "group": f"{role}-1",
            "scenario": "steady", "seed": number, "typ": "benign",
            "collector_sha256": "test-collector",
            "guest_before": {"boot_id": boot or directory.name, "kernel": "test-kernel", "stack_sha256": "test-stack"}}
    path = directory / "session.json"
    path.write_text(json.dumps(meta))
    audit = directory / "audit.json"
    audit.write_text(json.dumps({"values": {
        "accepted": True, "protocol_sha256": "protocol-test", "session_dir": str(directory),
        "session_sha256": dataset.sha(path), "features": str(feature_path),
        "features_sha256": dataset.sha(feature_path), "layout": {"size": 1},
        "extractor_sha256": {"test": "test"}}}))
    return audit


def protocol():
    return {"schema": "hyptcn3/collection-protocol/2", "quality_policy": "behavioral-inputs-v1",
            "roles": dict.fromkeys(dataset.ROLES, 1), "scenarios": {"steady": {}}}


def test_complete_corpus_keeps_prescribed_roles(tmp_path):
    audits = [record(tmp_path, role, i) for i, role in enumerate(dataset.ROLES)]
    result = dataset.build(audits, protocol(), "protocol-test")
    assert result["complete"]
    assert [r["role"] for r in result["sessions"]] == list(dataset.ROLES)


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
    audits = [record(tmp_path, role, i) for i, role in enumerate(dataset.ROLES)]
    for role, audit in zip(dataset.ROLES, audits):
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
    assert [row["role"] for row in records] == list(dataset.ROLES)
    assert all(row["protocol_sha256"] == protocol_sha for row in records)
