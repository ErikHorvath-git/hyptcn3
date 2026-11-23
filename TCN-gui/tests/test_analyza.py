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
    pytest.importorskip("matplotlib", reason="matplotlib je volitelny (iba TCN-gui), v requirements.txt nie je")
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
    pytest.importorskip("matplotlib", reason="matplotlib je volitelny (iba TCN-gui), v requirements.txt nie je")
    import porovnanie
    root, test, odd = setup
    second = tmp_path / "tyzden-2"
    corpus = Path(test["features"]).parents[1] / "index.json"
    train_bundle(corpus, second, window_rows=8, epochs=2, batch_size=32, fpr=0.05, diagnostic=True, seed=1)
    result = porovnanie.compare([second, root / "models" / "synthetic"], odd, allow_diagnostic=True)
    assert [m["name"] for m in result["models"]] == ["synthetic", "tyzden-2"]  # Ordered by training date.
    assert result["layers"]["cka"][0] == pytest.approx([1.0] * len(result["layers"]["names"]))
    assert all(0 <= v <= 1 + 1e-6 for v in result["layers"]["cka"][1])
    assert result["models"][1]["baseline_shift"] == pytest.approx([0.0] * len(result["baseline_names"]), abs=1e-9)  # Same training data.
    out = tmp_path / "porovnanie.png"
    assert tcn_gui.main(["--compare", str(root / "models" / "synthetic"), str(second), "--input", str(odd),
                         "--diagnostic", "--png", str(out)]) == 0
    assert out.stat().st_size > 50_000


# ------------------------------------------------------------------ the seal (package B7c, verification of B7c F1)
# tcn/pecat.py GUARD_RULE: the GUI checks an input before it opens it (analyza.resolve_input): a feature archive by its
# bytes, a snapshot directory by the session its session.json names. The ledger is one of the test's own, which
# tcn.pecat.KNIHA points at; the expected messages are literals.

ROOT = GUI.parent
V5 = ROOT / "config" / "collection-v5.json"
GUARD = ("a sealed archive of a campaign is replayed or scored only by the final command (python -m tcn.finalne) in "
         "the run that consumes its seal (tcn/pecat.py GUARD_RULE)")


def sha(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    """A ledger of the test's own, the one every guard reads (tcn.pecat.KNIHA)."""
    from tcn import pecat
    path = tmp_path / "ledger" / "kniha_pecati.json"
    path.parent.mkdir()
    monkeypatch.setattr(pecat, "KNIHA", path)
    pecat.zaloz(command="test_analyza", ledger=path)
    return path


def seal_session(tmp_path, ledger, mode, archive=None):
    """The session gui-1 of role test_benign as a capture leaves it, whose archive the ledger seals in plan mode `mode`
    (as the campaign writes it): session.json, raw/ with one snapshot file, and features.npz (a synthetic one, or a
    copy of `archive`); (session directory, archive, its sha256)."""
    import shutil
    from scripts.tests import boundary_sessions as bs
    from tcn import pecat
    directory = tmp_path / "sessions" / "gui-1"
    (directory / "raw").mkdir(parents=True)
    (directory / "raw" / "frame0.vmicd").write_bytes(b"synthetic RAM 0")
    (directory / "session.json").write_text(json.dumps({"session_id": "gui-1", "role": "test_benign"}))
    target = directory / "features.npz"
    if archive is None:
        result, _ = bs.extraction_result("gui-1", 24, 12, t0=10000., interval_s=5)
        bs.save_archive(target, result)
    else:
        shutil.copyfile(archive, target)
    record = {"id": "gui-1", "role": "test_benign", "group": "g", "vm": "a", "scenario": "eshop_low",
              "features": str(target), "features_sha256": sha(target)}
    pecat.zapis([record], protocol=json.loads(V5.read_text()), protocol_sha256=sha(V5), mode=mode,
                command="the campaign", ledger=ledger)
    return directory, target, record["features_sha256"]


@pytest.mark.parametrize("entry", ["analyze", "analyze_snapshots", "png", "button", "compare"])
def test_a_sealed_session_is_refused_by_the_gui(tmp_path, ledger, entry):
    """Every way the GUI scores a session refuses a sealed one of a campaign by name before it loads a model or opens
    the input: analyze on its archive and on its session directory (the snapshots of raw/, by the session that
    session.json names), the figure without a window (--png, before matplotlib is imported), the button
    Skontrolovať všetky (App.work: the refusal is the session's error in the list) and the comparison of models."""
    from tcn import pecat
    directory, archive, digest = seal_session(tmp_path, ledger, "campaign")
    what = (f"the snapshot directory {(directory / 'raw').resolve()} of session gui-1" if entry == "analyze_snapshots"
            else f"the archive {archive.resolve()}")
    purpose = "TCN-gui porovnanie.compare" if entry == "compare" else "TCN-gui analyze"
    expected = (f"{purpose}: refused, {what} is sealed (sha256 {digest}; session gui-1 of role test_benign, plan "
                f"{json.loads(V5.read_text())['name']}, ledger {ledger}): {GUARD}")
    out = tmp_path / "figure.png"
    if entry == "button":
        import queue
        from types import SimpleNamespace
        app = SimpleNamespace(queue=queue.Queue(), bundle_path=tmp_path / "no-bundle", bundle=object())
        tcn_gui.App.work(app, [str(archive)])
        messages = [app.queue.get() for _ in range(app.queue.qsize())]
        assert ("error", str(archive), "Zapecatene: " + expected) in messages
        return
    import porovnanie
    calls = {"analyze": lambda: analyza.analyze(tmp_path / "no-bundle", archive),
             "analyze_snapshots": lambda: analyza.analyze(tmp_path / "no-bundle", directory),
             "png": lambda: tcn_gui.main(["--bundle", str(tmp_path / "no-bundle"), "--input", str(archive), "--png",
                                          str(out)]),
             "compare": lambda: porovnanie.compare([tmp_path / "a", tmp_path / "b"], archive)}
    with pytest.raises(pecat.Zapecatene) as error:
        calls[entry]()
    assert str(error.value) == expected and not out.exists()


def test_a_rehearsal_session_is_scored_with_its_mark(setup, tmp_path, ledger, monkeypatch):
    """The twin: the archive of a rehearsal's session (the ledger of record, so stage generalka) is scored as the
    detector's replay scores it, and the report carries the seal's decision with the rehearsal mark."""
    from tcn import pecat
    monkeypatch.setattr(pecat, "ZAZNAM", ledger)
    root, test, _ = setup
    _, archive, digest = seal_session(tmp_path, ledger, "rehearsal", archive=test["features"])
    report = analyza.analyze(root / "models" / "synthetic", archive, allow_diagnostic=True)
    assert (report["seal"]["allowed"], report["seal"]["sha256"], report["seal"]["stage"], report["seal"]["mark"]) == (
        "rehearsal", digest, "generalka", pecat.REHEARSAL_MARK)
    reference = replay_archive(load_bundle(root / "models" / "synthetic", allow_diagnostic=True), archive, "gui-1")
    assert report["series"]["score"] == [r["score"] for r in reference]
