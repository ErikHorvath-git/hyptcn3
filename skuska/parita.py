"""The live/archive parity of stage G2 (protocol v5, package H1b5): the tolerance of the criterion live_archive_parity,
written from the precision the code computes in before any comparison (the lead's answer to Q45).

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H3, the criterion live_archive_parity,
section 6 point 4), the map dokazy/G2/mapa.md (row 11, points A, B, D and E, its questions 15 and 16) and the lead's
answers Q45 (the tolerance follows the precision of the network and the batch of both paths, written with its reason
before the first comparison; the sequence of the alarms must match exactly, every differing alarm is a finding), Q61
(map question 16, accepted as proposed: math.isclose with abs_tol 0 on the score, the fields of the alarm exactly) and
Q60 (map question 15: a run beside watch is no error-free run). skuska/ is no directory of scripts/collection.py
MEASUREMENT_DIRS, so nothing here changes the measurement code (map point E).
"""
import math

# ------------------------------------------------------------------ the tolerance (Q45), before any comparison

# What the code at commit 2a89b6c computes in (TOLERANCE_RULE), read from the files of PRECISION_SOURCES.
NETWORK_DTYPE = "float32"
BATCH = {"watch": 1, "replay": 1}  # Windows per call of the network on each path.
THREADS = 1  # Map row 11: --threads 1 for safeguard watch and safeguard replay alike.
# The sha256 of the files the precision and the batch were read from (TOLERANCE_RULE); the comparison refuses other
# files by name, since the precision must then be found out again before a comparison (Q45).
PRECISION_SOURCES = {
    "safeguard/bundle.py": "438f761d83960629c34281ec9d1ebbfbdb3301c0ef64b894bbf05234257cd976",
    "safeguard/runtime.py": "8e22a89fd9ee987460a19c98bda01effbb874345efd8f2afc0198cfe3a5f0480",
    "safeguard/model.py": "2afbb91abe0cf268632763f80a680235b74d5ce8780466f5ca8630e064b62bde",
    "safeguard/cli.py": "813ebe8e5800c9f3c086952e25e69e7829ce50b512f454f71f99764d2f9c36ce",
    "safeguard/features.py": "05e45f1147a31ea321d65adc679a191a911c341586e6f3749c3d9a4099a12019",
    "tcn/model.py": "7da3a3f38398bb3536cb6a3a5e12605b3594ede1eefd907be7d0ca3e79470f97",
}
# Q45: float64 and the same batch on both paths give 1e-9 relative, float32 or another batch 1e-5 relative.
TOLERANCES = {("float64", True): 1e-9, ("float64", False): 1e-5, ("float32", True): 1e-5, ("float32", False): 1e-5}
SCORE_REL_TOL = 1e-5  # TOLERANCES[(NETWORK_DTYPE, BATCH["watch"] == BATCH["replay"])]
SCORE_ABS_TOL = 0.0  # Map question 16 (Q61, accepted as proposed): abs_tol 0, so a score of 0 must be 0 on both paths.
TOLERANCE_RULE = (
    "the lead's answer to Q45 (2026-11-24T22:12Z), written before the first comparison: the network computes in "
    "float32 and both paths score one window per call, so the score of a row agrees when math.isclose(live, replay, "
    "rel_tol=1e-5, abs_tol=0) holds, |live - replay| <= 1e-5 x max(|live|, |replay|) (Q45: float32 or another batch "
    "1e-5 relative, float64 and the same batch 1e-9; abs_tol 0 by map question 16, which Q61 accepted). The precision, "
    "read from the code at commit 2a89b6c (the files of PRECISION_SOURCES): safeguard/bundle.py Bundle.score casts "
    "the normalized inputs of its window with torch.as_tensor(..., dtype=torch.float32) and runs the predictor and the "
    "classifier on them, torch modules of the default dtype float32 (safeguard/model.py Predictor and Classifier, the "
    "TCN blocks of tcn/model.py, no set_default_dtype and no double() anywhere in them), whose weights load_bundle "
    "loads with load_state_dict from the bundle's predictor.pt and classifier.pt; the features before the network are "
    "float64 on both paths (safeguard/features.py Frame and FeatureNormalizer.transform; the audit's feature archive "
    "stores matica and perbin as float64, features/archive.py save), so the network, not the features, sets the "
    "precision. The batch: safeguard watch (safeguard/cli.py execute -> safeguard/runtime.py run_directory) and "
    "safeguard replay --archive (safeguard/cli.py replay_directory -> safeguard/runtime.py replay_archive) both give "
    "each frame to Detector.process, which scores at most one window per frame through Bundle.score, whose "
    "unsqueeze(0) makes a batch of one; so one window per call on both paths, the same batch. Both run with --threads "
    "1 (map row 11; torch.set_num_threads in safeguard/cli.py execute). Beside the score: a row scored on one path and "
    "not on the other is a finding; the fields of the alarm (alarm, alarm_event, alarm_sources, model_alarm, "
    "rule_alarm, integrity_alarm, channel) must be equal exactly on every row, and every differing alarm is a finding "
    "even when the score is within the tolerance (Q45), so the sequence of the alarms of both paths must be the same")


def tolerance(dtype, same_batch):
    """The relative tolerance of the score by the lead's rule of Q45: 1e-9 for float64 and the same batch on both
    paths, 1e-5 for float32 or another batch. ValueError for another dtype."""
    try:
        return TOLERANCES[(dtype, bool(same_batch))]
    except KeyError:
        raise ValueError(f"Q45 names float32 and float64, not {dtype!r}") from None


def score_agrees(live, replay):
    """Whether two scores of a row agree within the tolerance written before the data (TOLERANCE_RULE)."""
    return math.isclose(live, replay, rel_tol=SCORE_REL_TOL, abs_tol=SCORE_ABS_TOL)
