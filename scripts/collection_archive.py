"""Verified, resumable archival of closed collection sessions.

Only raw working copies are reclaimed. Small local provenance and feature
files keep their original paths; raw becomes a link to the verified archive.
An interrupted copy never authorizes deletion of its source.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import uuid

from scripts.collection import digest


MANIFEST = "archive-manifest.json"
RECEIPT = "archive_receipt.json"
PENDING = ".raw.pending-reclaim"


def now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    return json.loads(Path(path).read_text())


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def mkdir_durable(path):
    """Persist each new directory's entry before relying on its descendants."""
    path = Path(path)
    if path.is_dir():
        return
    mkdir_durable(path.parent)
    path.mkdir()
    sync_dir(path.parent)


def write_new(path, doc, *, replace=False):
    """Publish a complete, fsynced JSON; immutable unless explicitly state."""
    path = Path(path)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x") as stream:
            json.dump(doc, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path)  # Atomic exclusive publication, including on NTFS.
            temp.unlink()
        sync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def mount_identity(path):
    path = Path(path).absolute()
    # findmnt requires an existing path; never mkdir on an unmounted target.
    existing = path
    while not existing.exists():
        existing = existing.parent
    doc = json.loads(subprocess.check_output(
        ["findmnt", "-J", "-T", str(existing), "-o", "TARGET,FSTYPE,UUID"], text=True, timeout=10))
    mount = doc["filesystems"][0]
    target = Path(mount["target"])
    if (not mount.get("uuid") or target in (Path("/"), Path("/home"))
            or not target.is_mount() or not path.is_relative_to(target)
            or path.resolve() != path):
        raise ValueError("archive must be on an explicitly mounted disk, without symlink components")
    return mount


def guard_mount(path, expected):
    if mount_identity(path) != expected:
        raise ValueError("archive disk missing or mount identity changed; preserving local data")


def files_in(directory):
    """Reject links and device nodes, including links to otherwise valid files."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("expected a real directory: " + str(directory))
    files = {}
    for path in sorted(directory.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("non-regular archive input: " + str(path))
        files[path.relative_to(directory).as_posix()] = path
    return files


def inventory(directory):
    return {name: {"size": path.stat().st_size, "sha256": digest(path)}
            for name, path in files_in(directory).items()}


def check_file(path, item):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"]
            or digest(path) != item["sha256"]):
        raise ValueError("archive checksum mismatch: " + str(path))


def verify_archive(destination, source=None):
    destination = Path(destination)
    doc = read_json(destination / MANIFEST)
    if (doc["schema"] != "hyptcn3/collection-archive/1"
            or doc["destination"] != str(destination)
            or (source is not None and doc["source"] != str(source))):
        raise ValueError("archive manifest identity mismatch")
    actual = files_in(destination)
    if set(actual) != set(doc["files"]) | {MANIFEST}:
        raise ValueError("archive file set differs from manifest")
    for name, item in doc["files"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("unsafe archive member")
        check_file(actual[name], item)
    return doc


def publish_archive(source, destination, guard, reserve_bytes):
    """Resume copying only identical files; publish only after two-sided checks."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    guard()
    if destination.exists():
        return verify_archive(destination, source)
    if (source / RECEIPT).exists() or (source / PENDING).exists():
        raise ValueError("archive missing after local reclamation was started")
    expected = inventory(source)
    if (MANIFEST in expected or RECEIPT in expected
            or any(n.endswith(".copying") or n.startswith("." + MANIFEST + ".") for n in expected)):
        raise ValueError("reserved archive metadata in source")
    needed = sum(v["size"] for v in expected.values())
    mkdir_durable(destination.parent)
    partial = destination.with_name(".partial-" + destination.name)
    if partial.is_symlink():
        raise ValueError("archive staging directory is a symlink")
    mkdir_durable(partial)
    # Remaining work, not already verified staged files, determines free space.
    staged = files_in(partial)
    for name in list(staged):
        # A kill between fsync(temp) and publication may leave this scratch file.
        if re.fullmatch(r"\.archive-manifest\.json\.[0-9a-f]{32}\.tmp", name):
            staged.pop(name).unlink()
    allowed = set(expected) | {MANIFEST} | {n + ".copying" for n in expected}
    if set(staged) - allowed:
        raise ValueError("unexpected file in archive staging directory")
    copied = sum(v["size"] for n, v in expected.items() if (partial / n).is_file())
    if shutil.disk_usage(partial).free < max(0, needed - copied) + reserve_bytes:
        raise ValueError("insufficient archive disk space")
    for name, item in expected.items():
        guard()
        target = partial / name
        mkdir_durable(target.parent)
        if target.exists():
            check_file(target, item)
            target.with_name(target.name + ".copying").unlink(missing_ok=True)
            continue
        temp = target.with_name(target.name + ".copying")
        if temp.is_symlink():
            raise ValueError("archive temporary file is a symlink")
        temp.unlink(missing_ok=True)
        with (source / name).open("rb") as src, temp.open("xb") as dst:
            shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        check_file(temp, item)
        os.rename(temp, target)
        sync_dir(target.parent)
    if inventory(source) != expected:
        raise ValueError("source changed during archival; keeping working copy")
    doc = {"schema": "hyptcn3/collection-archive/1", "date": now(),
           "source": str(source), "destination": str(destination), "files": expected,
           "bytes": needed, "note": "SHA-256 verified copy, not an additional independent capture."}
    if (partial / MANIFEST).exists():
        old = read_json(partial / MANIFEST)
        if any(old[k] != doc[k] for k in ("schema", "source", "destination", "files", "bytes")):
            raise ValueError("staged archive manifest differs")
        doc = old
    else:
        write_new(partial / MANIFEST, doc)
    # Verify the destination bytes again before publishing its directory.
    for name, item in expected.items():
        check_file(partial / name, item)
    if set(files_in(partial)) != set(expected) | {MANIFEST}:
        raise ValueError("unexpected files after archive copy")
    guard()
    os.rename(partial, destination)
    sync_dir(destination.parent)
    return doc


def reclaim_raw(source, destination, doc, guard):
    """An immutable receipt precedes rename/link/unlink, making each step resumable."""
    receipt = {"schema": "hyptcn3/collection-archive-receipt/1", "source": str(source),
               "destination": str(destination), "manifest_sha256": digest(destination / MANIFEST)}
    guard()
    if (source / RECEIPT).exists():
        if read_json(source / RECEIPT) != receipt:
            raise ValueError("local receipt does not match verified archive")
    else:
        write_new(source / RECEIPT, receipt)
    # Provenance/features must stay available under their original local paths.
    for name, item in doc["files"].items():
        if not name.startswith("raw/"):
            check_file(source / name, item)
    raw, pending = source / "raw", source / PENDING
    if raw.is_symlink():
        if os.readlink(raw) != str(destination / "raw"):
            raise ValueError("raw link points to a different archive")
    elif raw.exists():
        if pending.exists():
            raise ValueError("both raw and pending reclamation exist")
        if inventory(raw) != {n[4:]: v for n, v in doc["files"].items() if n.startswith("raw/")}:
            raise ValueError("raw working copy differs from verified archive")
        raw.rename(pending)
        sync_dir(source)
    if not raw.is_symlink():
        raw.symlink_to(destination / "raw", target_is_directory=True)
        sync_dir(source)
    if pending.exists():
        remaining = files_in(pending)
        for name, path in remaining.items():
            item = doc["files"].get("raw/" + name)
            if item is None:
                raise ValueError("unexpected file in pending reclamation")
            check_file(path, item)
        guard()
        for path in remaining.values():
            path.unlink()
        for directory in sorted(pending.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            directory.rmdir()
        pending.rmdir()
        sync_dir(source)
    return receipt


def bind_audit(doc, source, audit):
    """The bytes being reclaimed must be the exact inputs the audit examined."""
    v = read_json(audit)["values"]
    expected = {"raw/" + n: sha for n, sha in v["source_sha256"].items()}
    feature = Path(v["features"])
    if not feature.is_relative_to(source) or v["session_dir"] != str(source):
        raise ValueError("audit paths do not belong to archived session")
    expected[feature.relative_to(source).as_posix()] = v["features_sha256"]
    expected["session.json"] = v["session_sha256"]
    if any(doc["files"].get(n, {}).get("sha256") != sha for n, sha in expected.items()):
        raise ValueError("archive differs from audited inputs; preserving working copy")
    if ({n for n in doc["files"] if n.startswith("raw/") and n.endswith(".vmicd")}
            != {n for n in expected if n.endswith(".vmicd")}):
        raise ValueError("archive image set differs from audited inputs")


def archive_session(source, destination, guard, *, reclaim=False, campaign_id=None,
                    audit=None, reserve_bytes=2**30):
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if source.resolve() != source or destination.resolve() != destination:
        raise ValueError("archive directory paths must not contain symlinks")
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError("archive source and destination overlap")
    if reclaim:
        meta = read_json(source / "session.json")
        if not campaign_id or meta.get("campaign_id") != campaign_id:
            raise ValueError("only this campaign's raw working copies can be reclaimed")
    doc = publish_archive(source, destination, guard, reserve_bytes)
    if audit is not None:
        bind_audit(doc, source, audit)
    if reclaim:
        reclaim_raw(source, destination, doc, guard)
    return doc
