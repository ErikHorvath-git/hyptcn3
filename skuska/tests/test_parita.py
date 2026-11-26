"""The live/archive parity of G2 (skuska/parita.py, package H1b5), with fakes of every lab, root and training step.

No test touches a VM, runs as root, trains a model, runs safeguard watch or replay for real, or writes outside
tmp_path (checked after every test for data/results, data/diagnostics, data/collections and docs/MERANIA.md).
"""
import hashlib
import inspect
from pathlib import Path

import pytest

from skuska import parita

ROOT = Path(__file__).resolve().parents[2]
WATCHED = [ROOT / "data/results", ROOT / "data/diagnostics", ROOT / "data/collections"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def listing(path):
    return sorted(str(p.relative_to(path)) for p in path.rglob("*")) if path.exists() else None


@pytest.fixture(autouse=True)
def _repository_unchanged():
    """No test leaves a file in data/results, data/diagnostics or data/collections, or changes docs/MERANIA.md."""
    before = {path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")
    yield
    assert ({path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")) == before


# ------------------------------------------------------------------ the tolerance (Q45)

def test_the_tolerance_follows_q45_from_the_precision_of_the_code():
    """Q45: float64 and the same batch 1e-9, float32 or another batch 1e-5. The code the rule was read from is the
    code here (PRECISION_SOURCES); Bundle.score casts its window to float32 and makes a batch of one, the models are
    float32, and both paths give every frame to Detector.process, which scores at most one window per frame."""
    import torch
    from safeguard import bundle, model, runtime, cli
    assert {name: sha(ROOT / name) for name in parita.PRECISION_SOURCES} == parita.PRECISION_SOURCES
    score = inspect.getsource(bundle.Bundle.score)
    assert score.count("dtype=torch.float32") == 2 and ".unsqueeze(0)" in score and "float64" not in score
    for module in (bundle, model, runtime):
        assert "set_default_dtype" not in inspect.getsource(module) and ".double()" not in inspect.getsource(module)
    config = model.architecture(32, global_features=4)
    assert {p.dtype for net in (model.Predictor(config), model.Classifier(config, 2)) for p in net.parameters()} == {
        torch.float32}
    process = inspect.getsource(runtime.Detector.process)
    assert process.count("self.bundle.score(window)") == 1
    assert "detector.process(frame)" in inspect.getsource(runtime.replay_archive)
    assert "detector.process(frame)" in inspect.getsource(runtime.run_directory)
    assert "replay_archive(bundle, archive)" in inspect.getsource(cli.replay_directory)
    assert "torch.set_num_threads(a.threads)" in inspect.getsource(cli.execute)
    assert (parita.NETWORK_DTYPE, parita.BATCH, parita.THREADS) == ("float32", {"watch": 1, "replay": 1}, 1)
    assert parita.tolerance("float32", True) == parita.tolerance("float64", False) == 1e-5
    assert parita.tolerance("float64", True) == 1e-9
    assert parita.SCORE_REL_TOL == parita.tolerance(parita.NETWORK_DTYPE, len(set(parita.BATCH.values())) == 1)
    assert parita.SCORE_ABS_TOL == 0.0
    with pytest.raises(ValueError, match="Q45 names float32 and float64"):
        parita.tolerance("bfloat16", True)


@pytest.mark.parametrize("live, replay, agrees", [
    (2.0, 2.0, True), (2.0, 2.0 * (1 + 9e-6), True), (2.0, 2.0 * (1 + 1.1e-5), False), (0.0, 0.0, True),
    (0.0, 1e-300, False), (-3.0, -3.0 * (1 - 9e-6), True)])
def test_a_score_agrees_within_the_relative_tolerance_and_abs_tol_0(live, replay, agrees):
    assert parita.score_agrees(live, replay) is agrees
