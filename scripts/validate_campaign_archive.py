#!/usr/bin/env python3
"""Exercise archival on the mounted disk, without deleting any existing capture.

A real session is copied and bound to its audit. A separate synthetic fixture
exercises reclamation and repeat/resume. This is not a new RAM measurement.
"""
import argparse
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guestparse.context import capture_boot_id
from scripts.collection_archive import (archive_session, digest, guard_mount, inventory,
                                        mount_identity, now, read_json, verify_archive, write_new)
from scripts.campaign import stamp


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--session", type=Path, required=True)
    ap.add_argument("--audit", type=Path, required=True)
    ap.add_argument("--archive-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    if a.out.exists():
        raise ValueError("validation output already exists")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("commit validation implementation before running")
    source, external = a.session.resolve(), a.archive_root.resolve()
    mount = mount_identity(external)
    guard = lambda: guard_mount(external, mount)
    name = "archive_validation_" + stamp()
    destination = external / "validation" / name
    before = inventory(source)
    print("Copying unchanged session to " + str(destination / "pilot-copy"), flush=True)
    real = archive_session(source, destination / "pilot-copy", guard, audit=a.audit.resolve())
    verify_archive(destination / "pilot-copy", source)
    if inventory(source) != before:
        raise ValueError("original session changed")
    fixture = ROOT / "data/lab" / name
    fixture.mkdir()
    (fixture / "raw").mkdir()
    boot = "00000000-0000-4000-8000-000000000001"
    write_new(fixture / "session.json", {"schema": "hyptcn3/collection-session/1",
              "campaign_id": name, "diagnostic": True, "guest_before": {"boot_id": boot}})
    # Deliberately synthetic bytes; never passed to the RAM parser or a corpus.
    for number in range(2):
        (fixture / "raw" / f"fixture-{number}.vmicd").write_bytes(bytes([number]) * (2 * 1024**2))
    (fixture / "features.fixture").write_bytes(b"synthetic feature path placeholder")
    fixture_hashes = inventory(fixture)
    target = destination / "synthetic-reclamation"
    arc = archive_session(fixture, target, guard, reclaim=True, campaign_id=name)
    archive_session(fixture, target, guard, reclaim=True, campaign_id=name)
    if not (fixture / "raw").is_symlink() or (fixture / ".raw.pending-reclaim").exists():
        raise ValueError("reclamation incomplete")
    if capture_boot_id(fixture / "raw/fixture-0.vmicd") != boot:
        raise ValueError("relocated native boot context unavailable")
    if digest(fixture / "features.fixture") != fixture_hashes["features.fixture"]["sha256"]:
        raise ValueError("local feature path changed")
    result = {"schema": "hyptcn3/campaign-archive-validation/1", "date": now(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "commit_dirty": False, "host": platform.platform(),
              "guest": read_json(source / "session.json")["guest_before"],
              "command": shlex.join(sys.argv), "n": 2,
              "values": {"mounted_disk": mount, "original_session": str(source),
                         "original_session_unchanged": True, "real_session_copied_files": len(real["files"]),
                         "real_session_copied_bytes": real["bytes"], "audit_bound": str(a.audit.resolve()),
                         "audit_sha256": digest(a.audit), "original_raw_retained": not (source / "raw").is_symlink(),
                         "real_archive": str(destination / "pilot-copy"),
                         "real_manifest_sha256": digest(destination / "pilot-copy/archive-manifest.json"),
                         "synthetic_reclamation_files": len(arc["files"]),
                         "synthetic_reclamation_bytes": arc["bytes"], "synthetic_raw_is_archive_link": True,
                         "repeat_reclamation_ok": True, "native_boot_context_ok": True,
                         "local_feature_path_unchanged": True, "fixture_dir": str(fixture),
                         "note": "Filesystem/archive validation only. Real pilot was copied, not recollected or reclaimed. "
                                 "Reclamation used a synthetic fixture. Full live campaign and reboot sequence are not certified here."}}
    write_new(a.out, result)
    print(json.dumps({"output": str(a.out), "real_files_verified": len(real["files"]),
                      "synthetic_reclamation_ok": True}, indent=2))


if __name__ == "__main__":
    main()
