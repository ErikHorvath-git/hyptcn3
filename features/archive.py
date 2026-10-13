"""Versioned, non-pickle session archive including timing, quality and bins."""
import json
from pathlib import Path

import numpy as np

from .snapshot import MENA, SCHEMA
from .windows import snimky_z_matice
from .quality import valid_for

# Integrity verdicts and acquisition flags are kept as metadata, not behavioral
# prediction targets. This selection is independent of process/VM identities.
BEHAVIOR_NAMES = MENA[:18]


def model_arrays(data):
    """Unnormalized inputs for the planned global/per-bin experiments.

    Return time x 18 global behavior columns and time x bins x 4 local columns.
    Keep the entropy measurement mask (has_changed) with its value. Identity,
    quality flags and integrity findings never become input numbers here.
    """
    return data["matica"][:, :len(BEHAVIOR_NAMES)], data["perbin"]


def save(path, result):
    path = Path(path)
    if path.suffix != ".npz":
        path = Path(str(path) + ".npz")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        np.savez_compressed(
            stream, schema=SCHEMA, mena=np.array(MENA),
            matica=np.asarray(result["matica"], dtype=np.float64),
            seq=np.array(result["seq"], dtype=np.int64),
            casy=np.array(result["casy"], dtype=np.float64),
            valid=np.array(result["valid"], dtype=bool),
            perbin=np.asarray(result["perbin"], dtype=np.float64),
            biny=np.array(result["biny"], dtype=np.int64),
            chain_ids=np.array(result["chain_ids"]),
            snimky=np.array(result["snimky"]),
            trvanie_s=np.array(result["trvanie_s"], dtype=np.float64),
            poznamky=np.array(["; ".join(p) for p in result["poznamky"]]),
            quality_json=json.dumps(result["quality"]),
            quality_policy=result["quality_policy"],
            layout_json=json.dumps(result["layout"], sort_keys=True),
            max_medzera_s=result["max_medzera_s"],
        )
    return path


def load(path):
    with np.load(path, allow_pickle=False) as data:
        if str(data["schema"]) != SCHEMA:
            raise ValueError("legacy feature archive: re-extract from raw snapshots")
        if tuple(data["mena"]) != MENA:
            raise ValueError("feature order mismatch")
        result = {k: data[k].copy() for k in data.files}
    rows = snimky_z_matice("validation", result["matica"], MENA,
                           result["casy"], result["seq"], result["valid"])
    if result["valid"].dtype != np.dtype(bool) or result["seq"].dtype.kind not in "iu":
        raise ValueError("invalid quality/sequence types")
    if any(len(result[k]) != len(rows) for k in ("chain_ids", "snimky", "poznamky", "trvanie_s")):
        raise ValueError("metadata row count mismatch")
    quality = json.loads(str(result["quality_json"]))
    policy = str(result["quality_policy"])
    if len(quality) != len(rows) or [valid_for(q, policy) for q in quality] != result["valid"].tolist():
        raise ValueError("quality metadata mismatch")
    from .windows import segmenty
    segmenty(rows, max_medzera_s=float(result["max_medzera_s"]))
    if result["perbin"].shape != (len(rows), len(result["biny"]), 4):
        raise ValueError("invalid per-bin tensor shape")
    if not np.isfinite(result["perbin"]).all():
        raise ValueError("non-finite per-bin data")
    return result


def snapshots(session):
    """Synthetic unit inputs may omit metadata; file imports never do."""
    return snimky_z_matice(session["meno"], session["matica"], MENA,
                          session.get("casy"), session.get("seq"), session.get("valid"))
