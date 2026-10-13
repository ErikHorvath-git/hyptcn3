#!/usr/bin/env python3
"""Replay saved RAM after fixing stale kernel selection; preserve old outputs."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guestparse.view import build_view
from safeguard.bundle import digest
from safeguard.features import frame_from_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--seq", required=True, type=int, action="append")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output exists; choose a new immutable path")
    audit = json.loads(args.audit.read_text())
    session = Path(audit["values"]["session_dir"])
    metadata = json.loads((session / "session.json").read_text())
    if digest(session / "session.json") != audit["values"]["session_sha256"]:
        raise ValueError("original session metadata changed")
    raw, profile = session / "raw", session / "profile"
    for name, expected in audit["values"]["source_sha256"].items():
        if digest(raw / name) != expected:
            raise ValueError("original source changed: " + name)
    archive = Path(audit["values"]["features"])
    if digest(archive) != audit["values"]["features_sha256"]:
        raise ValueError("original feature archive changed")
    with np.load(archive, allow_pickle=False) as data:
        old_seq = data["seq"].tolist()
        old_matrix, old_local = data["matica"].copy(), data["perbin"].copy()
        old_quality = json.loads(str(data["quality_json"]))
    records = []
    for seq in sorted(set(args.seq)):
        view, image = build_view(str(raw), str(profile), until_seq=seq)
        try:
            if view.ktext_shift is None:
                raise ValueError(view.resolve_problem())
            assert view.expected_boot_id == view.snapshot_boot_id == metadata["guest_before"]["boot_id"]
            if view.profile_boot_mismatch():
                ok, detail = view.reanchor()
                if not ok:
                    raise ValueError(detail)
            assert all(row["match"] for row in view.translation_check())
            anchoring = {"expected_boot_id": view.expected_boot_id,
                         "snapshot_boot_id": view.snapshot_boot_id,
                         "selected_banner_pa": view.banner_pa,
                         "candidates": view.kernel_candidates,
                         "reanchored": view.reanchored,
                         "translation_check": view.translation_check()}
        finally:
            image.close()
        frame, _ = frame_from_snapshot(raw, profile, seq)
        index = old_seq.index(seq)
        np.testing.assert_array_equal(frame.vector[:8], old_matrix[index, :8])
        np.testing.assert_array_equal(frame.perbin, old_local[index])
        record = {"seq": seq, "anchoring": anchoring,
                  "old_behavior_valid": old_quality[index]["behavior_valid"],
                  "behavior_valid": frame.valid, "quality": frame.quality,
                  "objects": frame.vector[8:18].tolist(),
                  "memory_values_and_bins_unchanged": True}
        records.append(record)
        print(json.dumps({"seq": seq, "valid": frame.valid,
                          "candidates": len(anchoring["candidates"])}), flush=True)
    report = {
        "schema": "hyptcn3/boot-anchor-validation/1",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
        "guest": audit["guest"], "command": shlex.join([sys.executable, *sys.argv]), "n": len(records),
        "values": {"diagnostic": True, "session": str(session), "replays": records,
                   "original_audit_sha256": digest(args.audit),
                   "original_features_sha256": digest(archive),
                   "source_sha256": {str(path.relative_to(ROOT)): digest(path)
                                     for directory in ("features", "guestparse", "safeguard")
                                     for path in (ROOT / directory).rglob("*.py") if "tests" not in path.parts},
                   "script_sha256": digest(Path(__file__)),
                   "note": "Selected raw frames only; no new capture, full-session admission or detection measurement. Original audit remains unchanged. If commit_dirty is true, source hashes identify the exact replay implementation."},
    }
    with args.out.open("x") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    return 0 if all(record["behavior_valid"] for record in records) else 2


if __name__ == "__main__":
    raise SystemExit(main())
