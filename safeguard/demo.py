"""Synthetic integration fixtures. Never a measurement of malware detection.

Original project code. Artifacts carry diagnostic markers through every layer.
"""
import json
from pathlib import Path

import numpy as np

from features.archive import save
from .bundle import digest, load_bundle
from .runtime import replay_archive
from .training import train_bundle


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def create_corpus(output, *, layout=None, rows=96, window_rows=8):
    """Create four isolated, chronological roles and two artificial workloads."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    if layout is None:
        layout = {"bin_bytes": 16777216, "page_size": 4096,
                  "bins": [[i, 4096] for i in range(3)],
                  "regions": [{"gpa": 0, "bytes": 50331648}],
                  "memsize": 50331648, "vcpus": 2}
    roles = ("train", "dev", "calibration", "test_benign")
    protocol = {"schema": "hyptcn3/collection-protocol/2", "name": "synthetic-mechanics-only",
                "quality_policy": "behavioral-inputs-v1",
                "diagnostic": True, "interval_s": 5, "max_gap_s": 7.5,
                "window_rows": window_rows, "bin_bytes": layout["bin_bytes"],
                "roles": dict.fromkeys(roles, 1), "scenarios": {"quiet": {}, "steady": {}}}
    protocol_path = output / "protocol.json"
    write_json(protocol_path, protocol)
    protocol_sha = digest(protocol_path)
    records = []
    rng = np.random.default_rng(42)
    for role_i, role in enumerate(roles):
        for scenario_i, scenario in enumerate(protocol["scenarios"]):
            name = f"synthetic-{role}-{scenario}"
            directory = output / name
            directory.mkdir()
            t = np.arange(rows)
            level = 0.02 + scenario_i * 0.08
            matrix = np.zeros((rows, 22))
            matrix[:, :8] = np.clip(level + rng.normal(0, 0.005, (rows, 8)), 0, 1)
            matrix[:, 8:18] = 20 + scenario_i * 10 + rng.integers(0, 5, (rows, 10))
            matrix[:, 20] = 1
            full = (t % 64 == 0)
            matrix[full, 20] = 0
            matrix[full, 21] = 1
            local = np.zeros((rows, len(layout["bins"]), 4))
            local[:, :, 0] = np.clip(level + rng.normal(0, 0.01, local.shape[:2]), 0, 1)
            local[:, :, 1] = rng.uniform(0.1, 0.3, local.shape[:2])
            local[:, :, 3] = local[:, :, 0] > 0
            local[:, :, 2] = np.clip(4 + scenario_i + rng.normal(0, 0.1, local.shape[:2]), 0, 8) * local[:, :, 3]
            times = (1700000000 + (2 * role_i + scenario_i) * (rows + 20) * 5 + t * 5).astype(float)
            quality = [{"model_valid": True, "behavior_valid": True, "traversals_complete": True,
                        "inconclusive": ["text_integrity"], "findings": [],
                        "read_errors": 0, "filled_zero": 0} for _ in t]
            archive = save(directory / "features.npz", {
                "matica": matrix, "perbin": local, "seq": t, "casy": times,
                "valid": np.ones(rows, dtype=bool), "biny": [b[0] for b in layout["bins"]],
                "chain_ids": [f"{name}-chain-{i // 64}" for i in t],
                "snimky": [f"synthetic-{i}" for i in t], "trvanie_s": np.zeros(rows),
                "poznamky": [["synthetic diagnostic input"] for _ in t],
                "quality": quality, "quality_policy": "behavioral-inputs-v1",
                "layout": layout, "max_medzera_s": 7.5})
            guest = {"boot_id": f"synthetic-{role}-boot", "kernel": "synthetic",
                     "stack_sha256": "synthetic-no-guest"}
            meta = {"schema": "hyptcn3/collection-session/1", "session_id": name,
                    "role": role, "group": f"{role}-1", "scenario": scenario,
                    "typ": "benign", "protocol_sha256": protocol_sha, "guest_before": guest,
                    "collector_sha256": "synthetic-no-collector", "diagnostic": True}
            session = directory / "session.json"
            write_json(session, meta)
            audit = directory / "audit.json"
            write_json(audit, {"schema": "hyptcn3/collection-audit/1", "values": {
                "accepted": True, "diagnostic": True, "reasons": [], "role": role,
                "protocol_sha256": protocol_sha, "session_sha256": digest(session),
                "features": str(archive), "features_sha256": digest(archive),
                "layout": layout, "extractor_sha256": {"synthetic": "no-real-extraction"}}})
            records.append({"id": name, "role": role, "group": meta["group"],
                            "scenario": scenario, "typ": "benign", "boot_id": guest["boot_id"],
                            "protocol_sha256": protocol_sha, "session": str(session),
                            "session_sha256": digest(session), "audit": str(audit),
                            "audit_sha256": digest(audit), "features": str(archive),
                            "features_sha256": digest(archive), "start": float(times[0]),
                            "end": float(times[-1])})
    index = output / "index.json"
    write_json(index, {"schema": "hyptcn3/corpus-index/1", "complete": False,
                       "diagnostic": True, "protocol": str(protocol_path),
                       "protocol_sha256": protocol_sha, "protocol_config": protocol,
                       "sessions": records})
    return index


def smoke(output, *, layout=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    corpus = create_corpus(output / "corpus", layout=layout)
    training = train_bundle(corpus, output / "bundle", window_rows=8, epochs=2,
                            batch_size=32, fpr=0.05, diagnostic=True)
    try:
        load_bundle(output / "bundle")
    except ValueError as exc:
        guarded = "diagnostic" in str(exc)
    else:
        guarded = False
    bundle = load_bundle(output / "bundle", allow_diagnostic=True)
    index = json.loads(corpus.read_text())
    test = next(r for r in index["sessions"] if r["role"] == "test_benign")
    rows = replay_archive(bundle, test["features"], test["id"])
    with (output / "events.jsonl").open("x") as stream:
        for row in rows:
            stream.write(json.dumps(row, allow_nan=False) + "\n")
    result = {"schema": "hyptcn3/safeguard-smoke/1", "diagnostic": True,
              "purpose": "synthetic train/save/load/replay mechanics only",
              "training": training, "rows": len(rows),
              "scored": sum(r["score"] is not None for r in rows),
              "input_errors": sum(r["model_state"] == "input_error" for r in rows),
              "normal_load_rejected_diagnostic": guarded,
              "test_arrays_loaded_during_training": training["training"]["test_feature_arrays_loaded"],
              "states": sorted({r["state"] for r in rows}),
              "limitation": "Not an attack detection, classification accuracy or live performance measurement."}
    result["ok"] = bool(guarded and result["scored"] and not result["input_errors"])
    write_json(output / "report.json", result)
    return result
