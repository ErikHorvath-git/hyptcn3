#!/usr/bin/env python3
"""Diagnostic replay of selected frames from an immutable, already audited session.

Checks behavioral continuity around integrity gaps. It cannot accept an old
pilot under a new protocol, train a deployed model or measure detection.
"""
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
from features.snapshot import MENA
from safeguard.bundle import digest
from safeguard.features import WindowBuffer, frame_from_snapshot


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
    raw = session / "raw"
    # Read the old schema explicitly as diagnostic evidence, never as a new
    # training archive. Production import deliberately rejects old schemas.
    archive = Path(audit["values"]["features"])
    if digest(archive) != audit["values"]["features_sha256"]:
        raise ValueError("original feature archive changed")
    for name, expected in audit["values"]["source_sha256"].items():
        if digest(raw / name) != expected:
            raise ValueError("original source changed: " + name)
    with np.load(archive, allow_pickle=False) as data:
        old_seq = data["seq"].tolist()
        old_matrix = data["matica"].copy()
        old_local = data["perbin"].copy()
        old_quality = json.loads(str(data["quality_json"]))
    previous = None
    # A short diagnostic window exercises continuity; it is not the research
    # window or an estimate of the new pilot's score coverage.
    buffer = WindowBuffer(2)
    records = []
    stable = [i for i in range(18) if MENA[i] not in ("proc_new", "proc_gone", "mod_delta")]
    for seq in sorted(set(args.seq)):
        frame, previous = frame_from_snapshot(raw, session / "profile", seq, previous)
        i = old_seq.index(seq)
        np.testing.assert_array_equal(frame.vector[stable], old_matrix[i, stable])
        np.testing.assert_array_equal(frame.perbin, old_local[i])
        ready = buffer.push(frame) is not None
        record = {"seq": seq, "behavior_valid": frame.valid,
                  "legacy_valid": frame.quality["model_valid"],
                  "has_predecessor": frame.has_predecessor,
                  "inconclusive": frame.quality["inconclusive"],
                  "integrity_findings": len(frame.quality["findings"]),
                  "diagnostic_window_ready": ready,
                  "original_model_valid": old_quality[i]["model_valid"],
                  "changed_behavior_columns": [MENA[j] for j in range(18)
                                               if frame.vector[j] != old_matrix[i, j]],
                  "independent_behavior_values_and_bins_unchanged": True}
        records.append(record)
        print(json.dumps(record, ensure_ascii=False), flush=True)
    values = {"diagnostic": True, "session": str(session),
              "original_audit_sha256": digest(args.audit),
              "original_features_sha256": digest(archive), "replays": records,
              "source_sha256": {str(p.relative_to(ROOT)): digest(p)
                                for name in ("features", "guestparse", "safeguard")
                                for p in (ROOT / name).rglob("*.py") if "tests" not in p.parts},
              "script_sha256": digest(Path(__file__)),
              "note": "Selected saved-frame replay only. Original pilot verdict is unchanged; admission requires a new pilot under the new protocol. No detection or live latency claim."}
    report = {"schema": "hyptcn3/quality-policy-validation/1",
              "date": datetime.now(timezone.utc).isoformat(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "host": platform.platform(), "guest": audit["guest"],
              "command": shlex.join([sys.executable, *sys.argv]), "n": len(records), "values": values}
    with args.out.open("x") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
