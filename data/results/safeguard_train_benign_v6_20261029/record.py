"""Vyrobil safeguard_train_benign_v6_20261029.json na zberovom PC (2026-10-29, commit 51d512d).

Spustene ako `.venv/bin/python /tmp/mk_train_record.py` z ~/projects/hyptcn3; vystup
/tmp/safeguard_train_benign_v6_20261029.json sa skopiroval do data/results bez zmeny.
values.manifest_sha256 je SHA-256 BAJTOV suboru manifest.json balika; tcn.eval far
uvadza balik.manifest_sha256 ako SHA-256 kanonickeho JSON (json.dumps, sort_keys).
"""
import hashlib, json, platform, subprocess, collections
from pathlib import Path
root = Path.home() / "projects/hyptcn3"
bundle = root / "data/models/server-v2-benign-v6"
log = root / "data/models/server-v2-benign-v6.train.log"
manifest_file = bundle / "manifest.json"
manifest = json.loads(manifest_file.read_text())
result = json.loads(log.read_text())
commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
dirty = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True).strip()
roles = collections.Counter(s["role"] for s in manifest["provenance"]["sessions"])
env = manifest["environment"]
digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
doc = {
    "commit": commit, "commit_dirty": bool(dirty),
    "date": manifest["created_utc"],
    "host": platform.platform(),
    "guest": "hyptcn-lab, jadro %s, stack_sha256 %s" % (env["kernel"], env["stack_sha256"]),
    "command": ".venv/bin/python -m safeguard train --corpus data/campaigns/benign-v6-20261026/corpus.json "
               "--out data/models/server-v2-benign-v6 --epochs 10 --seed 0",
    "n": sum(v for k, v in roles.items() if k != "test_benign"),
    "values": {
        "schema": "hyptcn3/safeguard-train-record/1",
        "bundle": str(bundle), "manifest_sha256": digest(manifest_file),
        "weights_sha256": {p.name: digest(p) for p in sorted(bundle.glob("*.pt"))},
        "sessions_by_role": dict(sorted(roles.items())),
        "test_benign_loaded_in_training": result["training"]["test_feature_arrays_loaded"],
        "train_result": result,
        "manifest": manifest,
        "note": ("Zaznam treningu: kalibracna frekvencia udalosti je na role calibration (nie drzane bokom FAR). "
                 "Strata klasifikatora na dev rastie od 1. epochy, preto checkpoint klasifikatora je z epochy 1. "
                 "Ziadna detekcia utokov ani FAR na test_benign z tohto zaznamu nevyplyva."),
    },
}
out = Path("/tmp/safeguard_train_benign_v6_20261029.json")
out.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
print(commit, bool(dirty), doc["n"], dict(roles), out.stat().st_size)
