import json
from pathlib import Path

import pytest

from scripts import collection_archive as arc


@pytest.fixture
def session(tmp_path):
    src = tmp_path / "working/session"
    src.mkdir(parents=True)
    (src / "raw").mkdir()
    (src / "raw/a.vmicd").write_bytes(b"synthetic RAM a")
    (src / "raw/b.vmicd").write_bytes(b"synthetic RAM b")
    (src / "features.npz").write_bytes(b"synthetic features")
    (src / "session.json").write_text(json.dumps({
        "schema": "hyptcn3/collection-session/1", "campaign_id": "test",
        "guest_before": {"boot_id": "1602ed36-8187-4f33-bbaa-a36ebff348b4"}}))
    return src, tmp_path / "archive/session"


def move(src, dst, guard=lambda: None):
    return arc.archive_session(src, dst, guard, reclaim=True, campaign_id="test")


def test_verified_move_keeps_feature_paths_and_native_boot_context(session):
    from guestparse.context import capture_boot_id
    src, dst = session
    before = arc.inventory(src)
    move(src, dst)
    assert (src / "raw").is_symlink()
    assert (src / "raw/a.vmicd").read_bytes() == b"synthetic RAM a"
    assert arc.digest(src / "features.npz") == before["features.npz"]["sha256"]
    assert capture_boot_id(str(src / "raw/a.vmicd")) == "1602ed36-8187-4f33-bbaa-a36ebff348b4"
    assert arc.verify_archive(dst, src)["files"] == before
    assert not (src / arc.PENDING).exists()
    assert move(src, dst)["files"] == before  # Idempotent after all raw deletions.


def test_interrupted_copy_keeps_original_and_resumes(session, monkeypatch):
    src, dst = session
    copy = arc.shutil.copyfileobj
    def interrupt(source, target, *args):
        target.write(source.read(3))
        raise OSError("USB disconnected")
    monkeypatch.setattr(arc.shutil, "copyfileobj", interrupt)
    with pytest.raises(OSError, match="disconnected"):
        move(src, dst)
    assert (src / "raw").is_dir() and not (src / "raw").is_symlink()
    assert not dst.exists() and not (src / arc.RECEIPT).exists()
    monkeypatch.setattr(arc.shutil, "copyfileobj", copy)
    move(src, dst)
    arc.verify_archive(dst, src)


def test_corrupt_published_archive_never_authorizes_deletion(session):
    src, dst = session
    arc.archive_session(src, dst, lambda: None)
    (dst / "raw/a.vmicd").write_bytes(b"corruption")
    with pytest.raises(ValueError, match="checksum"):
        move(src, dst)
    assert (src / "raw/a.vmicd").read_bytes() == b"synthetic RAM a"
    assert not (src / arc.RECEIPT).exists()


@pytest.mark.parametrize("phase", ["rename", "unlink"])
def test_crash_during_reclamation_is_resumable(session, monkeypatch, phase):
    src, dst = session
    original_link, original_unlink = Path.symlink_to, Path.unlink
    def broken_link(path, *args, **kwargs):
        if path == src / "raw":
            raise InterruptedError("after raw rename")
        return original_link(path, *args, **kwargs)
    def broken_unlink(path, *args, **kwargs):
        original_unlink(path, *args, **kwargs)
        if path == src / arc.PENDING / "a.vmicd":
            raise InterruptedError("after first raw deletion")
    monkeypatch.setattr(Path, "symlink_to" if phase == "rename" else "unlink",
                        broken_link if phase == "rename" else broken_unlink)
    with pytest.raises(InterruptedError):
        move(src, dst)
    assert (src / arc.RECEIPT).exists()
    assert (src / arc.PENDING).is_dir()
    monkeypatch.setattr(Path, "symlink_to", original_link)
    monkeypatch.setattr(Path, "unlink", original_unlink)
    move(src, dst)
    assert (src / "raw/a.vmicd").read_bytes() == b"synthetic RAM a"
    assert not (src / arc.PENDING).exists()


def test_source_change_during_copy_preserves_raw(session, monkeypatch):
    src, dst = session
    copy = arc.shutil.copyfileobj
    def mutate(source, target, *args):
        copy(source, target, *args)
        if str(source.name).endswith("b.vmicd"):
            (src / "raw/a.vmicd").write_bytes(b"changed during copy")
    monkeypatch.setattr(arc.shutil, "copyfileobj", mutate)
    with pytest.raises(ValueError, match="source changed"):
        move(src, dst)
    assert not dst.exists() and (src / "raw").is_dir()


def test_mount_loss_blocks_reclamation_even_with_a_complete_copy(session):
    src, dst = session
    arc.archive_session(src, dst, lambda: None)
    def missing():
        raise ValueError("wrong disk")
    with pytest.raises(ValueError, match="wrong disk"):
        move(src, dst, missing)
    assert not (src / "raw").is_symlink()
    assert not (src / arc.RECEIPT).exists()


def test_low_disk_space_preserves_working_copy(session, monkeypatch):
    from types import SimpleNamespace
    src, dst = session
    monkeypatch.setattr(arc.shutil, "disk_usage", lambda _: SimpleNamespace(free=1))
    with pytest.raises(ValueError, match="insufficient archive"):
        move(src, dst)
    assert not dst.exists() and not (src / arc.RECEIPT).exists()
    assert (src / "raw/a.vmicd").read_bytes() == b"synthetic RAM a"


def test_extra_archive_file_and_wrong_campaign_are_rejected(session):
    src, dst = session
    with pytest.raises(ValueError, match="only this campaign"):
        arc.archive_session(src, dst, lambda: None, reclaim=True, campaign_id="other")
    arc.archive_session(src, dst, lambda: None)
    (dst / "unexpected").write_text("extra")
    with pytest.raises(ValueError, match="file set"):
        move(src, dst)
    assert not (src / "raw").is_symlink()


def test_source_symlink_is_not_followed(session):
    src, dst = session
    (src / "escape").symlink_to(src.parent)
    with pytest.raises(ValueError, match="non-regular"):
        move(src, dst)
    assert not dst.exists()


def test_disk_mount_fallback_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(arc.subprocess, "check_output", lambda *a, **k: json.dumps({
        "filesystems": [{"target": "/home", "fstype": "btrfs", "uuid": "internal"}]}))
    with pytest.raises(ValueError, match="explicitly mounted"):
        arc.mount_identity(tmp_path / "not-mounted/archive")


def test_atomic_json_cannot_replace_measurement(session):
    src, _ = session
    path = src / "new.json"
    arc.write_new(path, {"accepted": False})
    with pytest.raises(FileExistsError):
        arc.write_new(path, {"accepted": True})
    assert arc.read_json(path) == {"accepted": False}


def test_modified_ram_after_audit_cannot_be_reclaimed(session):
    src, dst = session
    audit = src / "audit.json"
    arc.write_new(audit, {"values": {"session_dir": str(src),
                  "session_sha256": arc.digest(src / "session.json"),
                  "features": str(src / "features.npz"), "features_sha256": arc.digest(src / "features.npz"),
                  "source_sha256": {f.name: arc.digest(f) for f in (src / "raw").iterdir()}}})
    (src / "raw/a.vmicd").write_bytes(b"changed after audit")
    with pytest.raises(ValueError, match="audited inputs"):
        arc.archive_session(src, dst, lambda: None, reclaim=True, campaign_id="test", audit=audit)
    assert not (src / "raw").is_symlink()
    assert not (src / arc.RECEIPT).exists()


def test_archive_preserves_dataset_and_training_paths(tmp_path):
    from features import dataset
    from features.tests.test_dataset import record, protocol
    from safeguard.training import validate_index
    config = {**protocol(), "window_rows": 3, "max_gap_s": 7.5, "interval_s": 5}
    protocol_path = tmp_path / "protocol.json"
    arc.write_new(protocol_path, config)
    protocol_sha = arc.digest(protocol_path)
    audits = [record(tmp_path, role, i) for i, role in enumerate(dataset.ROLES)]
    for role, audit in zip(dataset.ROLES, audits):
        src = audit.parent
        meta = arc.read_json(src / "session.json")
        meta.update(schema="hyptcn3/collection-session/1", campaign_id="test", protocol_sha256=protocol_sha)
        (src / "session.json").write_text(json.dumps(meta))
        doc = arc.read_json(audit)
        doc["schema"] = "hyptcn3/collection-audit/1"
        doc["values"].update(role=role, reasons=[], protocol_sha256=protocol_sha,
                              session_sha256=arc.digest(src / "session.json"))
        audit.write_text(json.dumps(doc))
        (src / "raw").mkdir()
        (src / "raw/frame.vmicd").write_bytes(b"synthetic fixture")
        move(src, tmp_path / "external" / src.name)
    index = dataset.build(audits, config, protocol_sha)
    index["protocol"] = str(protocol_path)
    path = tmp_path / "corpus.json"
    arc.write_new(path, index)
    assert validate_index(path, diagnostic=True)[0]["complete"]
