"""One-off: archive the raw data of two old pilots to the HDD archive and reclaim their SSD working copies.

Approved by the user on 2026-10-25 ("Archivovať 2 staré piloty"): campaign v5 needs ~11 GiB more free space on
the working SSD, and the campaign tool reclaims only its own sessions. This runs the same verified steps of
scripts/collection_archive.py for the two pilots: publish_archive (SHA-256, zstd members verified by
decompression), bind_audit (archived bytes equal the audited inputs) and reclaim_raw (receipt, raw/ becomes a
link to the archive, the local copy is removed only after the checks).
usage: archive_pilots.py
"""
import json
import sys
from pathlib import Path

ROOT = Path("/home/eh/projects/hyptcn3")
sys.path.insert(0, str(ROOT))
from scripts.collection_archive import (bind_audit, guard_mount, mount_identity,  # noqa: E402
                                        publish_archive, reclaim_raw)

ARCHIVE_ROOT = Path("/home/eh/hyptcn3-archive")
PILOTS = (("20261021T230727556324Z_pilot_bursty", "audit_20261022T000456589579Z.json"),
          ("20261022T003017919708Z_pilot_bursty", "audit_20261022T012236704934Z.json"))

expected = mount_identity(ARCHIVE_ROOT, allow_system=True)
print("archive mount", json.dumps(expected), flush=True)


def guard():
    guard_mount(ARCHIVE_ROOT, expected)


for name, audit in PILOTS:
    source = ROOT / "data/collections" / name
    destination = ARCHIVE_ROOT / "pilots" / name
    if json.loads((source / "session.json").read_text()).get("role") != "pilot":
        raise SystemExit(f"{name}: not a pilot session")
    doc = publish_archive(source, destination, guard, 30 * 2**30, compress="zstd")
    bind_audit(doc, source, source / audit)
    receipt = reclaim_raw(source, destination, doc, guard)
    print(name, "files", len(doc["files"]), "bytes", doc.get("bytes"), "stored", doc.get("stored_bytes"),
          "receipt", receipt["manifest_sha256"], flush=True)
