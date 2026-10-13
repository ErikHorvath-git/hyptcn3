#!/usr/bin/env python3
"""Reproducible mechanical integration check, without live capture or attacks.

Uses real saved RAM as replay input and a freshly trained SYNTHETIC diagnostic
bundle matching its geometry. This cannot measure detection performance.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys

import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.archive import save
from features.snapshot import retazec
from safeguard.bundle import digest, load_bundle
from safeguard.demo import smoke, write_json
from safeguard.runtime import replay_archive, run_directory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw", required=True, type=Path)
    p.add_argument("--profile", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--result", required=True, type=Path)
    a = p.parse_args()
    if a.result.exists():
        p.error("result already exists; choose a new immutable filename")
    a.out.mkdir(parents=True, exist_ok=False)
    torch.set_num_threads(4)
    print("Extracting saved real RAM; no live collector is started.", flush=True)
    extracted = retazec(str(a.raw.resolve()), str(a.profile.resolve()),
                       quality_policy="behavioral-inputs-v1")
    archive = save(a.out / "real-features.npz", extracted)
    print("Training synthetic diagnostic models with matching memory geometry.", flush=True)
    demo = smoke(a.out / "synthetic", layout=extracted["layout"])
    bundle_path = a.out / "synthetic/bundle"
    bundle = load_bundle(bundle_path, allow_diagnostic=True)
    archived = replay_archive(bundle, archive, a.raw.name)
    print("Replaying raw RAM through the directory detector and comparing scores.", flush=True)
    runtime = run_directory(bundle, a.raw, a.profile, a.out / "raw-replay", preserve=False)
    live = [json.loads(line) for line in (a.out / "raw-replay/events.jsonl").read_text().splitlines()]
    archived_scores = [(r["seq"], r["score"], r.get("activity_probabilities"), r.get("bin_errors"))
                       for r in archived if r["score"] is not None]
    raw_scores = [(r["seq"], r["score"], r.get("activity_probabilities"), r.get("bin_errors"))
                  for r in live if r["score"] is not None]
    parity = bool(archived_scores) and archived_scores == raw_scores
    values = {"diagnostic": True, "synthetic_training": demo,
              "real_replay_rows": len(live), "real_replay_scored": len(raw_scores),
              "scored_sequences": [row[0] for row in raw_scores],
              "global_local_scores_and_class_probabilities_exactly_equal": parity,
              "raw_replay": runtime, "raw": str(a.raw.resolve()), "archive_sha256": digest(archive),
              "bundle_manifest_sha256": digest(bundle_path / "manifest.json"),
              "raw_source_sha256": {f.name: digest(f) for f in sorted(a.raw.glob("*"))
                                    if f.is_file() and f.suffix in (".json", ".vmicd")},
              "source_sha256": {str(f.relative_to(ROOT)): digest(f)
                                for directory in ("safeguard", "features", "guestparse", "tcn")
                                for f in (ROOT / directory).rglob("*.py") if "tests" not in f.parts},
              "ok": bool(demo["ok"] and runtime["ok"] and parity),
              "limitation": "Synthetic model; saved real RAM replay only. No live eBPF integration, malware efficacy, calibrated lab accuracy or live latency claim."}
    report = {"schema": "hyptcn3/safeguard-validation/1", "date": datetime.now(timezone.utc).isoformat(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "host": platform.platform(), "guest": {"mode": "saved raw replay", "profile": str(a.profile.resolve())},
              "command": " ".join([sys.executable, *sys.argv]), "n": len(live), "values": values}
    a.result.parent.mkdir(parents=True, exist_ok=True)
    write_json(a.result, report)
    print(json.dumps({"ok": values["ok"], "rows": len(live), "scored": len(raw_scores),
                      "exact_parity": parity, "result": str(a.result)}, indent=2))
    return 0 if values["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
