"""Working-space preparation before campaign benign-v6: pilot 4 archived to the HDD (user-approved).

usage: record.py ARCHIVE_START VERIFY_LOG OUT_JSON
ARCHIVE_START holds the UTC start time and the free bytes of the working SSD (df) right before the archival.
VERIFY_LOG holds one "<session> rc=<n> seconds=<s>" line per independent `collection_archive verify` run.
Reads the archive manifest and local receipt of the pilot, the campaign space rule (protocol min_free_gib,
the init estimate raw_bytes * cycles / pilot_cycles * 1.5 from the accepted pilot 7) and the current free space.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path("/home/eh/projects/hyptcn3")
ARCHIVE = Path("/home/eh/hyptcn3-archive")
PILOTS = ("20261022T073059077133Z_pilot_bursty",)
start, verify_log, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
COMMIT_NOTE = ("HEAD when this record was generated. The record script data/results/collection_storage_20261026/"
               "record.py and the archival script archive_pilots.py are not part of this commit; they are committed "
               "together with this file. Free space is read live from the host.")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def space(path):
    u = shutil.disk_usage(path)
    return {"total": u.total, "used": u.used, "free": u.free}


started_utc, free_before = start.read_text().split()
verified = {m[1]: {"rc": int(m[2]), "seconds": float(m[3])}
            for m in re.finditer(r"^(\S+) rc=(\d+) seconds=([\d.]+)$", verify_log.read_text(), re.M)}
protocol = json.loads((ROOT / "config/collection-v2.json").read_text())
pilot = json.loads((ROOT / "data/results/collection_pilot_7_20261026_audit.json").read_text())["values"]
needed = pilot["raw_bytes"] * protocol["cycles"] / protocol["pilot_cycles"] * 1.5
reserve = protocol["min_free_gib"] * 2**30
sessions = []
for name in PILOTS:
    source = ROOT / "data/collections" / name
    destination = ARCHIVE / "pilots" / name
    manifest = json.loads((destination / "archive-manifest.json").read_text())
    receipt = json.loads((source / "archive_receipt.json").read_text())
    raw = {n: f for n, f in manifest["files"].items() if n.startswith("raw/")}
    sessions.append({
        "session": name, "group": json.loads((source / "session.json").read_text()).get("group"),
        "source": str(source), "destination": str(destination),
        "archive_manifest_sha256": sha(destination / "archive-manifest.json"),
        "receipt_matches_manifest": receipt["manifest_sha256"] == sha(destination / "archive-manifest.json"),
        "raw_is_link_to_archive": (source / "raw").is_symlink()
                                  and str((source / "raw").readlink()) == str(destination / "raw"),
        "files": len(manifest["files"]), "source_bytes": manifest["bytes"], "stored_bytes": manifest.get("stored_bytes"),
        "raw_files": len(raw), "raw_bytes": sum(f["size"] for f in raw.values()),
        "raw_stored_bytes": sum(f.get("stored_size", f["size"]) for f in raw.values()),
        "manifest_note": manifest.get("note"), "receipt": receipt, "independent_verify": verified.get(name),
    })
after = space(ROOT / "data/collections")
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": {"domain": "hyptcn-lab", "new_capture": False}, "command": " ".join(sys.argv), "n": len(sessions),
    "values": {
        "archive_root": str(ARCHIVE), "archival_started_utc": started_utc,
        "working_free_before": int(free_before), "space_after": {"working": after, "archive": space(ARCHIVE)},
        "campaign_rule": {"min_free_gib": protocol["min_free_gib"], "pilot_raw_bytes": pilot["raw_bytes"],
                          "estimated_session_bytes_with_reserve": needed,
                          "required_free_before_each_session": needed + reserve,
                          "short_before_archival": needed + reserve - int(free_before),
                          "margin_after_archival": after["free"] - needed - reserve},
        "gib": {"working_free_before": round(int(free_before) / 2**30, 2),
                "working_free_after": round(after["free"] / 2**30, 2),
                "required_free_before_each_session": round((needed + reserve) / 2**30, 2),
                "short_before_archival": round((needed + reserve - int(free_before)) / 2**30, 2),
                "margin_after_archival": round((after["free"] - needed - reserve) / 2**30, 2),
                "reclaimed": round(sum(s["raw_bytes"] for s in sessions) / 2**30, 2)},
        "reclaimed_bytes": sum(s["raw_bytes"] for s in sessions),
        "sessions": sessions,
        "note": ("Approved by the user on 2026-10-26 ('Archivovat pilot 4'). From pilot 7 the free working space "
                 "was 3.3 GiB above the rule of the capacity check that campaign init and the runner apply before "
                 "every session (estimated session bytes + min_free_gib), and each session leaves about 70 MB of "
                 "metadata on the working SSD, so 48 sessions would have reached the limit. The raw data of pilot "
                 "4, the oldest pilot still on the SSD, were archived with the verified steps of "
                 "scripts/collection_archive.py (publish_archive with zstd members checked by decompression, "
                 "bind_audit against the pilot's audit, reclaim_raw). Metadata, audit and logs stay at their "
                 "original paths; raw/ links to the archive, and collection_archive.py restore re-extracts it. The "
                 "archive is now the only copy of these RAM images, not a second backup. campaign_rule."
                 "short_before_archival is negative here: the rule was met, only with a small margin."),
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k != "sessions"}, indent=1))
for s in sessions:
    print({k: s[k] for k in ("session", "raw_files", "raw_bytes", "raw_stored_bytes", "receipt_matches_manifest",
                             "raw_is_link_to_archive")})
