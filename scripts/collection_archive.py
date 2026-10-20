"""Verified, resumable archival of closed collection sessions.

Only raw working copies are reclaimed. Small local provenance and feature
files keep their original paths; raw becomes a link to the verified archive.
An interrupted copy never authorizes deletion of its source.

Large raw/log members may be stored zstd-compressed (manifest schema 2). A
compressed member is published only after its decompressed stream reproduced
the original size and SHA-256; `restore_raw` re-extracts raw/ later.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

from scripts.collection import digest


MANIFEST = "archive-manifest.json"
RECEIPT = "archive_receipt.json"
PENDING = ".raw.pending-reclaim"
SCHEMA_PLAIN = "hyptcn3/collection-archive/1"
SCHEMA_COMPRESSED = "hyptcn3/collection-archive/2"
ZSTD = "zstd"  # Resolved through PATH; tests point it at a stand-in.
ZSTD_LEVEL = 3
ZSTD_COMPRESS = ["-q", f"-{ZSTD_LEVEL}", "-T1", "--check", "-c"]
ZSTD_DECOMPRESS = ["-q", "-d", "-c"]
COMPRESS_SUFFIXES = (".vmicd", ".jsonl")
COMPRESS_MIN_BYTES = 64 * 1024
PLAIN_KEYS = {"size", "sha256"}
COMPRESSED_KEYS = PLAIN_KEYS | {"stored", "stored_size", "stored_sha256", "codec"}
CHUNK = 4 * 1024 * 1024


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


def mount_identity(path, *, allow_system=False):
    """Filesystem identity under path; the system disk only by explicit opt-in."""
    path = Path(path).absolute()
    # findmnt requires an existing path; never mkdir on an unmounted target.
    existing = path
    while not existing.exists():
        existing = existing.parent
    doc = json.loads(subprocess.check_output(
        ["findmnt", "-J", "-T", str(existing), "-o", "TARGET,FSTYPE,UUID"], text=True, timeout=10))
    mount = doc["filesystems"][0]
    target = Path(mount["target"])
    system = target in (Path("/"), Path("/home"))
    if (not mount.get("uuid") or (system and not allow_system)
            or not target.is_mount() or not path.is_relative_to(target)
            or path.resolve() != path):
        raise ValueError("archive must be on an explicitly mounted disk, without symlink components")
    if system:
        mount["system_disk"] = True  # Frozen with the campaign; absent from external-disk identities.
    return mount


def guard_mount(path, expected):
    system = bool(expected.get("system_disk"))
    path = Path(path)
    # On the system disk a missing directory must never be recreated silently.
    if system and (path.is_symlink() or not path.is_dir()):
        raise ValueError("system-disk archive directory missing; preserving local data")
    if mount_identity(path, allow_system=system) != expected:
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


def original(item):
    """Identity of the original bytes, whatever the stored form."""
    return {"size": item["size"], "sha256": item["sha256"]}


def check_file(path, item):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"]
            or digest(path) != item["sha256"]):
        raise ValueError("archive checksum mismatch: " + str(path))


def run_zstd(args, **kw):
    """A missing or failing zstd is a verification failure, never an authorization."""
    try:
        done = subprocess.run([ZSTD, *args], stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)
    except OSError as error:
        raise ValueError(f"zstd unavailable: {error}") from error
    if done.returncode:
        raise ValueError(f"zstd failed ({done.returncode}): " + done.stderr.decode(errors="replace").strip())
    return done


def codec_info(codec):
    """Describe the codec before any staging; fails fast without the binary."""
    if codec != "zstd":
        raise ValueError("unsupported archive compression: " + str(codec))
    banner = run_zstd(["--version"], stdout=subprocess.PIPE, timeout=10).stdout.decode(errors="replace")
    match = re.search(r"\bv(\d+\.\d+\.\d+)", banner)
    if match is None:
        raise ValueError("unrecognized zstd version output: " + banner.strip())
    return {"zstd": {"version": match.group(1), "level": ZSTD_LEVEL, "command": [ZSTD, *ZSTD_COMPRESS],
                     "min_size": COMPRESS_MIN_BYTES, "suffixes": list(COMPRESS_SUFFIXES)}}


def stage_copy(source, temp):
    with Path(source).open("rb") as src, Path(temp).open("xb") as dst:
        shutil.copyfileobj(src, dst, CHUNK)
        dst.flush()
        os.fsync(dst.fileno())


def stage_zstd(source, temp, args):
    """Stream zstd output (compress or decompress) into an exclusive, fsynced temp file."""
    with Path(temp).open("xb") as dst:
        run_zstd([*args, str(source)], stdout=dst)
        dst.flush()
        os.fsync(dst.fileno())


def decompressed_identity(path):
    """Size and SHA-256 of the decompressed stream, without materializing it."""
    try:
        proc = subprocess.Popen([ZSTD, *ZSTD_DECOMPRESS, str(path)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise ValueError(f"zstd unavailable: {error}") from error
    sha, size = hashlib.sha256(), 0
    with proc:
        while chunk := proc.stdout.read(CHUNK):
            sha.update(chunk)
            size += len(chunk)
        error = proc.stderr.read()
    if proc.returncode:
        raise ValueError(f"zstd failed ({proc.returncode}): " + error.decode(errors="replace").strip())
    return size, sha.hexdigest()


def record_stored(path, item):
    """Record a compressed member's stored identity; its content is proven by decompression."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("archive checksum mismatch: " + str(path))
    item.update(stored_size=path.stat().st_size, stored_sha256=digest(path))


def check_stored(path, item):
    """The bytes on the archive disk: a plain copy or the recorded compressed form."""
    if "codec" not in item:
        return check_file(path, item)
    check_file(path, {"size": item["stored_size"], "sha256": item["stored_sha256"]})


def check_readable(path, item):
    """Complete and readable: stored hashes, then the decompressed content."""
    check_stored(path, item)
    if "codec" not in item:
        return
    if item["codec"] != "zstd":
        raise ValueError("unsupported archive codec: " + str(item["codec"]))
    if decompressed_identity(path) != (item["size"], item["sha256"]):
        raise ValueError("archive decompression mismatch: " + str(path))


def plan_storage(expected, compress):
    """Original identities plus stored name and codec for members worth compressing."""
    files = {}
    for name, item in expected.items():
        files[name] = dict(item)
        if compress and name.endswith(COMPRESS_SUFFIXES) and item["size"] >= COMPRESS_MIN_BYTES:
            files[name].update(stored=name + ".zst", codec=compress)
    if len({v.get("stored", n) for n, v in files.items()}) != len(files):
        raise ValueError("stored archive names collide")
    return files


def archive_members(doc):
    """Stored name -> (original name, item), rejecting malformed or unsafe entries."""
    compressed = doc["schema"] == SCHEMA_COMPRESSED
    members = {}
    for name, item in doc["files"].items():
        stored = item.get("stored", name)
        if any(Path(n).is_absolute() or ".." in Path(n).parts for n in (name, stored)):
            raise ValueError("unsafe archive member")
        keys = set(item)
        if (keys != PLAIN_KEYS and not (compressed and keys == COMPRESSED_KEYS)) or stored in members:
            raise ValueError("malformed archive member entry: " + name)
        members[stored] = (name, item)
    return members


def verify_archive(destination, source=None):
    destination = Path(destination)
    doc = read_json(destination / MANIFEST)
    if (doc["schema"] not in (SCHEMA_PLAIN, SCHEMA_COMPRESSED)
            or doc["destination"] != str(destination)
            or (source is not None and doc["source"] != str(source))):
        raise ValueError("archive manifest identity mismatch")
    members = archive_members(doc)
    actual = files_in(destination)
    if set(actual) != set(members) | {MANIFEST}:
        raise ValueError("archive file set differs from manifest")
    for stored, (_, item) in members.items():
        check_readable(actual[stored], item)
    return doc


def publish_archive(source, destination, guard, reserve_bytes, compress=None):
    """Resume only proven staged members; publish only after two-sided checks."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    guard()
    if destination.exists():
        return verify_archive(destination, source)
    if (source / RECEIPT).exists() or (source / PENDING).exists():
        raise ValueError("archive missing after local reclamation was started")
    info = codec_info(compress) if compress is not None else None
    expected = inventory(source)
    if (MANIFEST in expected or RECEIPT in expected
            or any(n.endswith(".copying") or n.startswith("." + MANIFEST + ".") for n in expected)):
        raise ValueError("reserved archive metadata in source")
    files = plan_storage(expected, compress)
    stored = {v.get("stored", n): n for n, v in files.items()}
    needed = sum(v["size"] for v in expected.values())
    mkdir_durable(destination.parent)
    partial = destination.with_name(".partial-" + destination.name)
    if partial.is_symlink():
        raise ValueError("archive staging directory is a symlink")
    mkdir_durable(partial)
    staged = files_in(partial)
    for name in list(staged):
        # A kill between fsync(temp) and publication may leave this scratch file.
        if re.fullmatch(r"\.archive-manifest\.json\.[0-9a-f]{32}\.tmp", name):
            staged.pop(name).unlink()
    allowed = set(stored) | {MANIFEST} | {n + ".copying" for n in stored}
    if set(staged) - allowed:
        raise ValueError("unexpected file in archive staging directory")
    # Remaining original bytes bound the work; compressed sizes are unknown in advance.
    copied = sum(v["size"] for n, v in files.items() if (partial / v.get("stored", n)).is_file())
    if shutil.disk_usage(partial).free < max(0, needed - copied) + reserve_bytes:
        raise ValueError("insufficient archive disk space")
    for name, item in files.items():
        guard()
        target = partial / item.get("stored", name)
        temp = target.with_name(target.name + ".copying")
        mkdir_durable(target.parent)
        if target.exists():
            # A staged member counts only once proven complete and readable again.
            if "codec" in item:
                record_stored(target, item)
            check_readable(target, item)
            temp.unlink(missing_ok=True)
            continue
        if temp.is_symlink():
            raise ValueError("archive temporary file is a symlink")
        temp.unlink(missing_ok=True)
        if "codec" in item:
            stage_zstd(source / name, temp, ZSTD_COMPRESS)
            record_stored(temp, item)
            check_readable(temp, item)
            check_file(source / name, item)  # The source itself must still be what was hashed.
        else:
            stage_copy(source / name, temp)
            check_file(temp, item)
        os.rename(temp, target)
        sync_dir(target.parent)
    if inventory(source) != expected:
        raise ValueError("source changed during archival; keeping working copy")
    doc = {"schema": SCHEMA_PLAIN, "date": now(),
           "source": str(source), "destination": str(destination), "files": files,
           "bytes": needed, "note": "SHA-256 verified copy, not an additional independent capture."}
    compared = ["schema", "source", "destination", "files", "bytes"]
    if compress is not None:
        doc.update(schema=SCHEMA_COMPRESSED, codec_info=info,
                   stored_bytes=sum(v.get("stored_size", v["size"]) for v in files.values()),
                   note="SHA-256 verified copy; zstd members verified by decompression. "
                        "Not an additional independent capture.")
        compared.append("stored_bytes")
    if (partial / MANIFEST).exists():
        old = read_json(partial / MANIFEST)
        if any(old.get(k) != doc[k] for k in compared):
            raise ValueError("staged archive manifest differs")
        doc = old
    else:
        write_new(partial / MANIFEST, doc)
    # Verify the destination bytes again before publishing its directory.
    for name, item in files.items():
        check_stored(partial / item.get("stored", name), item)
    if set(files_in(partial)) != set(stored) | {MANIFEST}:
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
        if inventory(raw) != {n[4:]: original(v) for n, v in doc["files"].items() if n.startswith("raw/")}:
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
                    audit=None, reserve_bytes=2**30, compress=None):
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if source.resolve() != source or destination.resolve() != destination:
        raise ValueError("archive directory paths must not contain symlinks")
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError("archive source and destination overlap")
    if reclaim:
        meta = read_json(source / "session.json")
        if not campaign_id or meta.get("campaign_id") != campaign_id:
            raise ValueError("only this campaign's raw working copies can be reclaimed")
    doc = publish_archive(source, destination, guard, reserve_bytes, compress=compress)
    if audit is not None:
        bind_audit(doc, source, audit)
    if reclaim:
        reclaim_raw(source, destination, doc, guard)
    return doc


def restore_raw(destination, target, *, reserve_bytes=2**30):
    """Re-extract the raw/ members of a verified archive into a new directory."""
    destination, target = Path(destination).absolute(), Path(target).absolute()
    if target.exists() or target.is_symlink():
        raise ValueError("restore target already exists: " + str(target))
    doc = verify_archive(destination)
    members = {n[4:]: v for n, v in doc["files"].items() if n.startswith("raw/")}
    needed = sum(v["size"] for v in members.values())
    existing = target
    while not existing.exists():
        existing = existing.parent
    if shutil.disk_usage(existing).free < needed + reserve_bytes:
        raise ValueError("insufficient disk space for restore")
    mkdir_durable(target)
    for name, item in members.items():
        out = target / name
        mkdir_durable(out.parent)
        temp = out.with_name(out.name + ".copying")
        stored = destination / item.get("stored", "raw/" + name)
        if "codec" in item:
            stage_zstd(stored, temp, ZSTD_DECOMPRESS)
        else:
            stage_copy(stored, temp)
        check_file(temp, item)
        os.rename(temp, out)
        sync_dir(out.parent)
    return {"archive": str(destination), "target": str(target), "schema": doc["schema"],
            "files": len(members), "bytes": needed,
            "stored_bytes": sum(v.get("stored_size", v["size"]) for v in members.values())}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a collection archive or restore its raw/ members.")
    sub = ap.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="Check every member, decompressing compressed ones")
    verify.add_argument("archive", type=Path)
    restore = sub.add_parser("restore", help="Re-extract raw/ into a new directory")
    restore.add_argument("archive", type=Path)
    restore.add_argument("target", type=Path)
    a = ap.parse_args(argv)
    if a.command == "verify":
        archive = a.archive.absolute()
        doc = verify_archive(archive)
        result = {"archive": str(archive), "schema": doc["schema"], "files": len(doc["files"]),
                  "bytes": doc["bytes"], "stored_bytes": doc.get("stored_bytes", doc["bytes"]), "verified": True}
    else:
        result = restore_raw(a.archive, a.target)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"collection_archive: {error}", file=sys.stderr)
        sys.exit(2)
