"""TCN GUI (analyza.py, tcn_gui.py) on the synthetic diagnostic bundle from safeguard.demo (mechanics only, HONESTY P4)."""
import json
from pathlib import Path
import sys

import numpy as np
import pytest

GUI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI))

import analyza  # noqa: E402
import tcn_gui  # noqa: E402
from safeguard.bundle import load_bundle  # noqa: E402
from safeguard.demo import create_corpus  # noqa: E402
from safeguard.runtime import replay_archive  # noqa: E402
from safeguard.training import train_bundle  # noqa: E402


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    root = tmp_path_factory.mktemp("gui")
    index = create_corpus(root / "corpus")
    train_bundle(index, root / "models" / "synthetic", window_rows=8, epochs=2,
                 batch_size=32, fpr=0.05, diagnostic=True)
    test = next(s for s in json.loads(index.read_text())["sessions"] if s["role"] == "test_benign")
    data = dict(np.load(test["features"], allow_pickle=False))
    data["perbin"][50:62, 1, 0] = 0.95  # One bin suddenly rewritten: an artificial deviation.
    data["perbin"][50:62, 1, 3] = 1
    odd = root / "collections" / "odchylka"
    odd.mkdir(parents=True)
    np.savez(odd / "features.npz", **data)
    return root, test, odd


def test_scores_match_detector_replay_and_decompose_exactly(setup):
    root, test, _ = setup
    bundle = root / "models" / "synthetic"
    report = analyza.analyze(bundle, test["features"], allow_diagnostic=True)
    reference = replay_archive(load_bundle(bundle, allow_diagnostic=True), test["features"], test["id"])
    assert report["series"]["score"] == [r["score"] for r in reference]
    s = report["series"]
    for i, score in enumerate(s["score"]):
        if score is None:
            assert report["features"]["errors"][i] is None
            continue
        assert s["global_part"][i] + s["bin_part"][i] == pytest.approx(score, rel=1e-5)
        features = report["features"]["errors"][i]
        assert 0.5 * sum(features) / len(features) == pytest.approx(s["global_part"][i], rel=1e-4)
    json.dumps(report, allow_nan=False)
    assert report["model"]["history"] and report["model"]["name"] == "synthetic"


def test_deviation_raises_model_alarm_in_the_changed_bin(setup):
    root, _, odd = setup
    report = analyza.analyze(root / "models" / "synthetic", odd, allow_diagnostic=True)
    assert report["verdict"]["level"] == "alarm" and report["summary"]["model_alarm_events"] >= 1
    assert report["bins"]["top_by_mean"][0] == 1


def test_diagnostic_bundle_needs_explicit_permission(setup):
    root, test, _ = setup
    with pytest.raises(ValueError, match="diagnostic"):
        analyza.analyze(root / "models" / "synthetic", test["features"])


def test_rejects_directory_without_snapshots(tmp_path):
    with pytest.raises(ValueError, match="vmicd"):
        analyza.resolve_input(tmp_path)


def test_one_figure_renders_without_a_window(setup, tmp_path):
    root, _, odd = setup
    out = tmp_path / "session.png"
    assert tcn_gui.main(["--bundle", str(root / "models" / "synthetic"), "--input", str(odd),
                         "--diagnostic", "--png", str(out)]) == 0
    assert out.read_bytes().startswith(b"\x89PNG") and out.stat().st_size > 50_000


def test_app_checks_a_folder_of_sessions(setup, tmp_path, monkeypatch):
    import os
    import time
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        pytest.skip("bez grafického displeja")
    root, test, odd = setup
    folder = tmp_path / "sessions"
    folder.mkdir()
    (folder / "benign").symlink_to(Path(test["features"]).parent)
    (folder / "odchylka").symlink_to(odd)
    monkeypatch.setattr(tcn_gui, "SETTINGS", tmp_path / "settings.json")
    monkeypatch.setattr(analyza, "busy_collecting", lambda: False)
    app = tcn_gui.App(diagnostic=True)
    try:
        app.load_model(root / "models" / "synthetic")
        app.add_inputs(tcn_gui.find_sessions(folder))
        app.analyze_all()
        deadline = time.monotonic() + 60
        while (app.busy or len(app.reports) < 2) and time.monotonic() < deadline:
            app.root.update()
            time.sleep(0.02)
        values = {app.tree.item(k)["text"]: app.tree.item(k)["values"][0] for k in app.tree.get_children()}
        assert values["odchylka"].startswith("✗") and values["benign"].startswith("✓")
    finally:
        app.root.destroy()


def test_cka_ignores_channel_order_and_scale():
    import porovnanie
    rng = np.random.default_rng(0)
    x = rng.normal(size=(200, 16))
    assert porovnanie.linear_cka(x, x[:, rng.permutation(16)] * 3.0) == pytest.approx(1.0)
    assert porovnanie.linear_cka(x, rng.normal(size=(200, 16))) < 0.3


def test_compare_two_trainings_on_one_session(setup, tmp_path):
    import porovnanie
    root, test, odd = setup
    second = tmp_path / "tyzden-2"
    corpus = Path(test["features"]).parents[1] / "index.json"
    train_bundle(corpus, second, window_rows=8, epochs=2, batch_size=32, fpr=0.05, diagnostic=True, seed=1)
    result = porovnanie.compare([second, root / "models" / "synthetic"], odd, allow_diagnostic=True)
    assert [m["name"] for m in result["models"]] == ["synthetic", "tyzden-2"]  # Ordered by training date.
    assert result["layers"]["cka"][0] == pytest.approx([1.0] * len(result["layers"]["names"]))
    assert all(0 <= v <= 1 + 1e-6 for v in result["layers"]["cka"][1])
    assert result["models"][1]["baseline_shift"] == pytest.approx([0.0] * 21, abs=1e-9)  # Same training data.
    out = tmp_path / "porovnanie.png"
    assert tcn_gui.main(["--compare", str(root / "models" / "synthetic"), str(second), "--input", str(odd),
                         "--diagnostic", "--png", str(out)]) == 0
    assert out.stat().st_size > 50_000
