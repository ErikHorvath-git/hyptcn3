import json
import os
from pathlib import Path
import re
import shutil

import pytest

from scripts import collection_archive as arc


needs_zstd = pytest.mark.skipif(shutil.which(arc.ZSTD) is None, reason="zstd CLI required")


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


@pytest.fixture
def bulky(session):
    """Members above the compression threshold beside small ones stored plainly."""
    src, dst = session
    (src / "raw/c.vmicd").write_bytes(b"synthetic RAM page " * 5000)
    (src / "events.jsonl").write_bytes(b'{"event": "tick"}\n' * 5000)
    return src, dst


def move(src, dst, guard=lambda: None, **kw):
    return arc.archive_session(src, dst, guard, reclaim=True, campaign_id="test", **kw)


def stage_until(monkeypatch, src, dst, name):
    """Compress members up to `name`, whose complete temp file is left unverified."""
    real = arc.stage_zstd
    def interrupt(source, temp, args):
        real(source, temp, args)
        if Path(source).name == name:
            raise OSError("power loss")
    monkeypatch.setattr(arc, "stage_zstd", interrupt)
    with pytest.raises(OSError, match="power loss"):
        move(src, dst, compress="zstd")
    monkeypatch.setattr(arc, "stage_zstd", real)


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


@pytest.mark.parametrize("manifest_published", [False, True])
def test_interrupted_atomic_manifest_publication_resumes(session, manifest_published):
    src, dst = session
    partial = dst.with_name(".partial-" + dst.name)
    if manifest_published:
        arc.archive_session(src, dst, lambda: None)
        dst.rename(partial)
    else:
        partial.mkdir(parents=True)
    temp = partial / ("." + arc.MANIFEST + "." + "a" * 32 + ".tmp")
    temp.write_text('{"partial":')
    move(src, dst)
    assert not (dst / temp.name).exists()
    arc.verify_archive(dst, src)
    assert (src / "raw").is_symlink()


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


@needs_zstd
def test_compressed_archive_round_trip_reclaims_and_verifies(bulky):
    src, dst = bulky
    before = arc.inventory(src)
    doc = move(src, dst, compress="zstd")
    assert doc["schema"] == arc.SCHEMA_COMPRESSED
    assert {n: arc.original(v) for n, v in doc["files"].items()} == before
    assert {n for n, v in doc["files"].items() if "codec" in v} == {"raw/c.vmicd", "events.jsonl"}
    assert doc["files"]["raw/c.vmicd"]["stored"] == "raw/c.vmicd.zst"
    assert set(arc.files_in(dst)) == {arc.MANIFEST, "events.jsonl.zst", "features.npz", "raw/a.vmicd",
                                      "raw/b.vmicd", "raw/c.vmicd.zst", "session.json"}
    assert doc["bytes"] == sum(v["size"] for v in before.values()) > doc["stored_bytes"]
    assert doc["codec_info"]["zstd"]["level"] == 3
    assert re.fullmatch(r"\d+\.\d+\.\d+", doc["codec_info"]["zstd"]["version"])
    assert (src / "raw").is_symlink() and os.readlink(src / "raw") == str(dst / "raw")
    assert (src / "raw/c.vmicd.zst").is_file() and not (src / arc.PENDING).exists()
    assert arc.verify_archive(dst, src) == doc
    assert move(src, dst, compress="zstd") == doc  # Idempotent after reclamation.


@needs_zstd
@pytest.mark.parametrize("tamper", ["flip", "forged", "truncate", "delete", "extra"])
def test_compressed_archive_tampering_is_rejected(bulky, tamper):
    src, dst = bulky
    arc.archive_session(src, dst, lambda: None, compress="zstd")
    member = dst / "raw/c.vmicd.zst"
    data = bytearray(member.read_bytes())
    if tamper in ("flip", "forged"):
        data[len(data) // 2] ^= 0xFF
        member.write_bytes(data)
    if tamper == "forged":  # Manifest agrees with the damaged bytes; only decompression can tell.
        doc = arc.read_json(dst / arc.MANIFEST)
        doc["files"]["raw/c.vmicd"].update(stored_size=len(data), stored_sha256=arc.digest(member))
        (dst / arc.MANIFEST).write_text(json.dumps(doc))
    elif tamper == "truncate":
        member.write_bytes(data[:-1])
    elif tamper == "delete":
        member.unlink()
    elif tamper == "extra":
        (dst / "raw/c.vmicd").write_bytes(b"plain twin")
    with pytest.raises(ValueError, match="mismatch|file set|zstd failed"):
        arc.verify_archive(dst, src)
    with pytest.raises(ValueError):
        move(src, dst, compress="zstd")
    assert (src / "raw/c.vmicd").is_file() and not (src / "raw").is_symlink()
    assert not (src / arc.RECEIPT).exists()


@needs_zstd
def test_decompression_mismatch_never_reclaims(bulky, monkeypatch):
    src, dst = bulky
    partial = dst.with_name(".partial-" + dst.name)
    real = arc.decompressed_identity
    monkeypatch.setattr(arc, "decompressed_identity", lambda path: (0, "0" * 64))
    with pytest.raises(ValueError, match="decompression mismatch"):
        move(src, dst, compress="zstd")
    assert not dst.exists() and not (src / arc.RECEIPT).exists()
    assert (src / "raw/c.vmicd").is_file() and not (src / "raw").is_symlink()
    assert not list(partial.rglob("*.zst"))  # Nothing unproven became a staged member.
    monkeypatch.setattr(arc, "decompressed_identity", real)
    move(src, dst, compress="zstd")
    arc.verify_archive(dst, src)


@needs_zstd
@pytest.mark.parametrize("failure", ["missing", "failing"])
def test_broken_zstd_never_reclaims_and_resume_recovers(bulky, tmp_path, monkeypatch, failure):
    src, dst = bulky
    partial = dst.with_name(".partial-" + dst.name)
    stand_in = tmp_path / "zstd"
    if failure == "failing":  # Reports a version, then fails every compression.
        stand_in.write_text(f'#!/bin/sh\n[ "$1" = --version ] && exec {shutil.which(arc.ZSTD)} --version\nexit 3\n')
        stand_in.chmod(0o755)
    monkeypatch.setattr(arc, "ZSTD", str(stand_in))
    with pytest.raises(ValueError, match="zstd (unavailable|failed)"):
        move(src, dst, compress="zstd")
    assert partial.exists() == (failure == "failing")  # A missing binary fails before any staging.
    assert not dst.exists() and not (src / arc.RECEIPT).exists()
    assert (src / "raw/c.vmicd").is_file() and not (src / "raw").is_symlink()
    monkeypatch.undo()
    assert move(src, dst, compress="zstd")["schema"] == arc.SCHEMA_COMPRESSED
    assert arc.verify_archive(dst, src)["files"]["raw/c.vmicd"]["codec"] == "zstd"


@needs_zstd
def test_interrupted_compressed_staging_resumes_without_recompressing(bulky, monkeypatch):
    src, dst = bulky
    partial = dst.with_name(".partial-" + dst.name)
    stage_until(monkeypatch, src, dst, "c.vmicd")
    assert (partial / "raw/c.vmicd.zst.copying").is_file() and not (partial / "raw/c.vmicd.zst").exists()
    staged = (partial / "events.jsonl.zst").stat()
    assert not dst.exists() and (src / "raw").is_dir() and not (src / arc.RECEIPT).exists()
    move(src, dst, compress="zstd")
    kept = (dst / "events.jsonl.zst").stat()
    assert (kept.st_ino, kept.st_mtime_ns) == (staged.st_ino, staged.st_mtime_ns)  # Re-verified, not redone.
    assert not list(dst.rglob("*.copying"))
    arc.verify_archive(dst, src)
    assert (src / "raw").is_symlink()


@needs_zstd
def test_corrupt_staged_compressed_member_blocks_resume(bulky, monkeypatch):
    src, dst = bulky
    partial = dst.with_name(".partial-" + dst.name)
    stage_until(monkeypatch, src, dst, "c.vmicd")
    (partial / "events.jsonl.zst").write_bytes(b"not a zstd frame")
    with pytest.raises(ValueError, match="zstd failed"):
        move(src, dst, compress="zstd")
    assert not dst.exists() and not (src / "raw").is_symlink() and not (src / arc.RECEIPT).exists()


@needs_zstd
def test_colliding_stored_names_are_rejected(bulky):
    src, dst = bulky
    (src / "raw/c.vmicd.zst").write_bytes(b"pre-compressed twin")
    with pytest.raises(ValueError, match="collide"):
        move(src, dst, compress="zstd")
    assert not dst.exists() and not dst.with_name(".partial-" + dst.name).exists()


def test_plain_archive_manifest_unchanged_and_restorable(session, tmp_path):
    src, dst = session
    originals = {p.name: p.read_bytes() for p in (src / "raw").iterdir()}
    doc = move(src, dst)
    assert doc["schema"] == arc.SCHEMA_PLAIN
    assert set(doc) == {"schema", "date", "source", "destination", "files", "bytes", "note"}
    assert all(set(v) == {"size", "sha256"} for v in doc["files"].values())
    assert arc.verify_archive(dst, src) == doc
    summary = arc.restore_raw(dst, tmp_path / "restored")
    assert {p.name: p.read_bytes() for p in (tmp_path / "restored").iterdir()} == originals
    assert summary["files"] == 2
    assert summary["bytes"] == summary["stored_bytes"] == sum(map(len, originals.values()))


@needs_zstd
def test_restore_raw_reproduces_compressed_members(bulky, tmp_path, capsys):
    src, dst = bulky
    originals = {p.name: p.read_bytes() for p in (src / "raw").iterdir()}
    move(src, dst, compress="zstd")
    target = tmp_path / "restored"
    summary = arc.restore_raw(dst, target)
    assert {p.name: p.read_bytes() for p in target.iterdir()} == originals
    assert summary["files"] == 3 and summary["bytes"] == sum(map(len, originals.values())) > summary["stored_bytes"]
    with pytest.raises(ValueError, match="already exists"):
        arc.restore_raw(dst, target)
    assert arc.main(["verify", str(dst)]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == arc.SCHEMA_COMPRESSED
    assert arc.main(["restore", str(dst), str(tmp_path / "again")]) == 0
    assert json.loads(capsys.readouterr().out)["files"] == 3
    assert (tmp_path / "again/c.vmicd").read_bytes() == originals["c.vmicd"]


@pytest.mark.parametrize("target", ["/", "/home"])
def test_system_disk_identity_requires_explicit_opt_in(tmp_path, monkeypatch, target):
    archive = tmp_path / "archive" if target == "/" else Path("/home/.hyptcn3-absent/archive")
    findmnt = {"filesystems": [{"target": target, "fstype": "ext4", "uuid": "internal"}]}
    monkeypatch.setattr(arc.subprocess, "check_output", lambda *a, **k: json.dumps(findmnt))
    monkeypatch.setattr(Path, "is_mount", lambda self: str(self) in ("/", "/home"))
    with pytest.raises(ValueError, match="explicitly mounted"):
        arc.mount_identity(archive)
    identity = arc.mount_identity(archive, allow_system=True)
    assert identity == {"target": target, "fstype": "ext4", "uuid": "internal", "system_disk": True}
    # A frozen external-disk identity never accepts the system disk, whatever the uuid.
    with pytest.raises(ValueError, match="explicitly mounted"):
        arc.guard_mount(archive, {k: v for k, v in identity.items() if k != "system_disk"})


def test_system_disk_guard_requires_existing_real_directory(tmp_path, monkeypatch):
    archive = tmp_path / "archive"
    archive.mkdir()
    findmnt = {"filesystems": [{"target": "/", "fstype": "ext4", "uuid": "internal"}]}
    monkeypatch.setattr(arc.subprocess, "check_output", lambda *a, **k: json.dumps(findmnt))
    identity = arc.mount_identity(archive, allow_system=True)
    arc.guard_mount(archive, identity)
    archive.rmdir()
    with pytest.raises(ValueError, match="directory missing"):
        arc.guard_mount(archive, identity)
    assert not archive.exists()
    (tmp_path / "elsewhere").mkdir()
    archive.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="directory missing"):
        arc.guard_mount(archive, identity)
    archive.unlink()
    archive.mkdir()
    findmnt["filesystems"][0]["uuid"] = "reinstalled"
    with pytest.raises(ValueError, match="identity changed"):
        arc.guard_mount(archive, identity)
