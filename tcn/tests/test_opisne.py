"""The descriptive methods of the core in the method interface (protocol v5, package B7a, agent D; design
dokazy/B7/navrh/NAVRH_B7a.md sections 1.1, 1.3, 1.6 and 4, the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 2
and addendum 2 point 1).

Each method on data whose answer is known by construction: the z-score of a window mean against a train set of mean 0
and deviation 1, the isolation forest on a window far from all train windows, GRU and LSTM on windows of a constant
level (the last value predicts the last row) and with the weights at zero (the loss and the score by hand), and the
GRU/LSTM parameter count against the TCN's. With them the plan of analysis.descriptive_methods (design 1.6), the
windows of M (safeguard.training.Windows) and the refusals by name.

Synthetic data, mechanics only: no number here is a detection result (HONESTY P4). The names of package B7a are
imported inside the tests, so this file collects on the code before it.
"""
import json
from pathlib import Path
import re

import numpy as np
import pytest
import torch

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
G, B, L = 2, 2, 6  # The synthetic windows: global inputs, scored bins, rows.
DELETE = object()
# Two bins of 4096 pages and one of 64 (as safeguard/tests/test_channels.py): under analysis.scale.min_bin_pages 1024
# the third is neither fitted nor scored, so M's windows have two bins.
LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 4096], [1, 4096], [2, 64]],
          "regions": [{"gpa": 0, "bytes": 33554432}, {"gpa": 33554432, "bytes": 262144}],
          "memsize": 33816576, "vcpus": 2}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "inconclusive": ["text_integrity"],
        "findings": [], "read_errors": 0, "filled_zero": 0}


@pytest.fixture(scope="module", autouse=True)
def _threads():
    """Two torch threads for this file (as safeguard/tests/test_training.py)."""
    before = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(before)


def protocol(changes=()):
    """config/collection-v5.json, its analysis.descriptive_methods as the file has it (agent K's key; merge of B7a),
    with a shorter stop for the speed of the tests only (max_epochs 10, patience 3; judgment); `changes` set keys
    under analysis by dotted path (DELETE removes one)."""
    doc = json.loads(V5.read_text())
    doc["analysis"]["stopping"].update(max_epochs=10, patience_epochs=3)
    for path, value in dict(changes).items():
        *parents, key = path.split(".")
        node = doc["analysis"]
        for parent in parents:
            node = node[parent]
        if value is DELETE:
            del node[key]
        else:
            node[key] = value
    return doc


def refused(reason):
    return pytest.raises(ValueError, match="^" + re.escape(reason) + "$")


def constant_windows(levels, rows=L):
    """Windows whose every value is the window's level: the G global inputs and the four channels of the B bins in
    each of `rows` rows."""
    levels = np.asarray(levels, dtype=np.float64)
    return (np.broadcast_to(levels[:, None, None], (len(levels), rows, G)).copy(),
            np.broadcast_to(levels[:, None, None, None], (len(levels), rows, B, 4)).copy())


def level_windows(levels, jump=0.):
    """constant_windows with has_changed 1 in every bin (its entropy is scored) and `jump` added to the last row's
    global inputs and bin values."""
    g, local = constant_windows(levels)
    local[..., 3] = 1.
    g[:, -1] += jump
    local[:, -1, :, :3] += jump
    return g, local


def session(name, seed, rows=24):
    """The frames of one synthetic session: a full snapshot at seq 0, then measured rows of noise (as
    safeguard/tests/test_channels.py)."""
    from features.snapshot import MENA
    from safeguard.features import Frame
    rng = np.random.default_rng(seed)
    frames = []
    for seq in range(rows):
        vector = np.zeros(len(MENA))
        vector[:8] = rng.uniform(.1, .3, 8)
        vector[8:20] = rng.integers(20, 40, 12)
        vector[MENA.index("ma_predchodcu")], vector[MENA.index("je_plna")] = seq != 0, seq == 0
        local = np.ones((3, 4))
        local[:, 0], local[:, 1], local[:, 2] = rng.uniform(.1, .3, 3), rng.uniform(.1, .3, 3), rng.uniform(2, 5, 3)
        frames.append(Frame(name, seq, 1000. + 5 * seq, vector, local, (0, 1, 2), dict(GOOD), name + "-chain",
                            LAYOUT))
    return frames


def test_the_plan_lists_every_run():
    """Design 1.6: the four methods of analysis.descriptive_methods of the real file, GRU and LSTM (and the forest) at
    each seed, the z-score with seeds null once with seed None."""
    from tcn import opisne
    p = protocol()
    assert opisne.descriptive_methods(p) == json.loads(V5.read_text())["analysis"]["descriptive_methods"]
    assert opisne.runs(p) == [("zscore", None)] + [(name, seed) for name in ("iforest", "gru", "lstm")
                                                    for seed in range(5)]
    assert [(opisne.method(name).name, opisne.method(name).kind) for name in opisne.NAMES] == [
        ("zscore", "detector"), ("iforest", "detector"), ("gru", "predictor"), ("lstm", "predictor")]


@pytest.mark.parametrize("name, seed, changes, reason", [
    ("gru", 0, {"descriptive_methods": DELETE}, "the protocol has no analysis.descriptive_methods"),
    ("gru", 0, {"descriptive_methods.pca": {"what": "PCA", "seeds": None, "note": ""}},
     "analysis.descriptive_methods names exactly zscore, iforest, gru and lstm (design B7a 1.6)"),
    ("gru", 0, {"descriptive_methods.gru.grid": {}},
     "analysis.descriptive_methods.gru has exactly the keys what, seeds and note"),
    ("gru", 0, {"descriptive_methods.lstm.seeds": [0, 0]},
     "analysis.descriptive_methods.lstm.seeds is null or a list of distinct integers >= 0"),
    ("gru", 0, {"descriptive_methods.iforest.seeds": None},
     "analysis.descriptive_methods.iforest.seeds is null, but iforest draws from a seed"),
    ("gru", 7, {}, "gru: seed 7 is not one of analysis.descriptive_methods.gru.seeds [0, 1, 2, 3, 4]"),
    ("zscore", 0, {}, "zscore: analysis.descriptive_methods.zscore.seeds is null (zscore draws nothing): its fit "
     "takes seed None, not 0"),
    ("gru", 0, {"stopping.rule": "last epoch"}, "analysis.stopping gives the rule 'last epoch' and the repeat 'once "
     "with twice the cap'; GRU and LSTM are trained as M by safeguard.training._fit, which implements 'best dev loss, "
     "patience' and 'once with twice the cap'"),
    ("gru", 0, {"architecture.learning_rate": 0}, "analysis.architecture.learning_rate is a positive number, not 0"),
    ("lstm", 0, {"stopping.max_epochs": 0}, "analysis.stopping.max_epochs is an integer >= 1, not 0"),
    ("lstm", 0, {"architecture.kernel": 1}, "analysis.architecture builds no predictor of safeguard/model.py with 2 "
     "global inputs: recepcne pole 1 < dlzka okna 32 (k=1, blokov=4); pridaj blok alebo zvacsi jadro"),
], ids=["no_key", "names", "entry_keys", "seeds", "seeds_null", "seed_outside", "seed_of_zscore", "stopping_rule",
        "learning_rate", "max_epochs", "architecture"])
def test_the_protocol_is_refused_by_name(name, seed, changes, reason):
    """Design 1.6 and no silent default: a plan without the key, with other methods or entry keys, with bad seeds or a
    seed outside them, and M's training values GRU and LSTM cannot be trained by are refused by name at the fit."""
    from tcn import opisne
    with refused(reason):
        opisne.method(name).fit(level_windows([0., 1.]), level_windows([0., 1.]), protocol=protocol(changes), seed=seed)


class Empty:
    """A window set without a window."""
    indices = []

    def batches(self, batch_size, order=None):
        return iter(())


class Flat:
    """A window set whose global inputs have no axis of rows."""
    indices = [0]

    def batches(self, batch_size, order=None):
        yield torch.zeros(1, G), torch.zeros(1, L, B, 4), torch.zeros(1, dtype=torch.long)


@pytest.mark.parametrize("case, reason", [
    ("form", "a window set is a safeguard.training.Windows (batches and indices) or the pair (global inputs (N, L, "
     "G), bin inputs (N, L, B, 4)) (design B7a 1.1)"),
    ("pair", "a window set pair is the global inputs (N, L, G) and the bin inputs (N, L, B, 4) of one N and one L, "
     "with N, L, G and B at least 1, all finite"),
    ("batch", "a batch of a window set is the global inputs (n, L, G) and the bin inputs (n, L, B, 4)"),
    ("empty", "a window set has at least one window"),
    ("shape", "zscore: its windows have 6 rows, 2 global inputs and 2 bins; these have 5, 2 and 2"),
    ("one_row", "gru: a window of 1 row has no row before its last; a predictor needs 2 rows at least"),
    ("detector_unfitted", "iforest: fit has not run"),
    ("predictor_unfitted", "lstm: fit has not run"),
    ("name", "unknown descriptive method 'pca'; the methods are zscore, iforest, gru and lstm"),
])
def test_window_sets_are_refused_by_name(case, reason):
    """Design 1.1: a window set of another form, of bad shapes, without windows or of another shape than the method's,
    a predictor's window of one row, scores and losses before the fit and an unknown method are refused by name."""
    from tcn import opisne
    p, windows = protocol(), level_windows([0., 1.])

    def zscore(sets):
        return opisne.method("zscore").fit(sets, None, protocol=p, seed=None)

    def shape():
        fitted = opisne.method("zscore")
        fitted.fit(windows, None, protocol=p, seed=None)
        return fitted.scores(constant_windows([0.], rows=5))

    calls = {"form": lambda: zscore(42),
             "pair": lambda: zscore((np.zeros((2, L, G)), np.zeros((2, L, B, 3)))),
             "batch": lambda: zscore(Flat()),
             "empty": lambda: zscore(Empty()),
             "shape": shape,
             "one_row": lambda: opisne.method("gru").fit(constant_windows([0.], rows=1), constant_windows([0.], rows=1),
                                                         protocol=p, seed=0),
             "detector_unfitted": lambda: opisne.method("iforest").scores(windows),
             "predictor_unfitted": lambda: opisne.method("lstm").losses(windows),
             "name": lambda: opisne.method("pca")}
    with refused(reason):
        calls[case]()


def test_zscore_scores_the_squared_z_value_of_the_window_mean():
    """Known answer: over train windows of the levels -1, -1, 1, 1 every one of the G + 8 summary columns has the mean
    0 and the deviation 1, so a train window scores 1, a window at the mean 0, and a window with global input 0 at 3
    and the rest at the mean 9 / (G + 8)."""
    from tcn import opisne
    train = constant_windows([-1., -1., 1., 1.])
    shifted = constant_windows([0.])
    shifted[0][0, :, 0] = 3.
    method = opisne.method("zscore")
    record = method.fit(train, None, protocol=protocol(), seed=None)
    np.testing.assert_allclose(method.scores(train), [1., 1., 1., 1.])
    np.testing.assert_allclose(method.scores(constant_windows([0.])), [0.])
    np.testing.assert_allclose(method.scores(shifted), [9. / (G + 8)])
    assert method.losses(train) is None
    assert (record["chosen"], record["seed"], record["windows"]) == (None, None, {"train": 4})


def test_iforest_isolates_the_far_window():
    """Known answer: a window six deviations off every train window is the most isolated, at either seed; the scores
    are -score_samples in (0, 1], the forest of one seed is reproducible and another seed draws other trees."""
    from tcn import opisne
    rng = np.random.default_rng(3)
    train = (rng.normal(size=(256, L, G)), rng.normal(size=(256, L, B, 4)))
    test = (rng.normal(size=(33, L, G)), rng.normal(size=(33, L, B, 4)))
    test[0][32] += 6.
    test[1][32] += 6.
    scores = {}
    for seed in (0, 1):
        method = opisne.method("iforest")
        record = method.fit(train, None, protocol=protocol(), seed=seed)
        scores[seed] = method.scores(test)
        assert np.argmax(scores[seed]) == 32
        assert ((scores[seed] > 0) & (scores[seed] <= 1)).all()
        assert (record["random_state"], record["trees"], record["chosen"]) == (seed, 200, None)
    again = opisne.method("iforest")
    again.fit(train, None, protocol=protocol(), seed=0)
    np.testing.assert_array_equal(again.scores(test), scores[0])
    assert not np.array_equal(scores[0], scores[1])


@pytest.mark.parametrize("name", ["gru", "lstm"])
def test_predictor_learns_the_last_value(name):
    """Known answer: in windows of a constant level the last value predicts the last row, so the trained predictor's
    dev loss falls far below the loss of the prediction 0 (the mean squared level) and a window whose last row jumps
    by 3 has the highest score. The record names the epoch of the best dev loss, which is the loss of the model it
    leaves; one seed reproduces its model, another does not."""
    from tcn import opisne
    from tcn.model import pocet_parametrov
    rng = np.random.default_rng(1)
    train, dev = level_windows(rng.uniform(-1, 1, 256)), level_windows(rng.uniform(-1, 1, 64))
    test = tuple(np.concatenate(parts) for parts in zip(level_windows(rng.uniform(-1, 1, 32)),
                                                        level_windows([0.], jump=3.)))
    method = opisne.method(name)
    state = torch.random.get_rng_state()
    record = method.fit(train, dev, protocol=protocol(), seed=0)
    assert torch.equal(torch.random.get_rng_state(), state)  # Its draws come from its own streams.
    losses = method.losses(dev)
    assert losses.mean() < 0.1 * np.mean(dev[0][:, -1, 0] ** 2)  # judgment: the margin of the test
    assert np.argmax(method.scores(test)) == 32
    assert record["chosen"] == {"epoch": record["stop"]["selected_epoch"]}
    np.testing.assert_allclose(record["stop"]["best_dev_loss"], losses.mean(), rtol=1e-5)
    assert record["parameters"] == pocet_parametrov(method.net)
    assert record["windows"] == {"train": 256, "dev": 64}
    again, other = opisne.method(name), opisne.method(name)
    again.fit(train, dev, protocol=protocol(), seed=0)
    other.fit(train, dev, protocol=protocol(), seed=1)
    np.testing.assert_array_equal(again.scores(test), method.scores(test))
    assert not np.array_equal(other.scores(test), method.scores(test))


@pytest.mark.parametrize("name", ["gru", "lstm"])
def test_predictor_loss_is_the_training_loss_of_m(name):
    """Design 1.3: the mean loss of a batch is M's training loss of it (safeguard.training._prediction_loss); with every
    weight at 0 the prediction is 0, so the loss of a window is 0.5 x the mean squared last row of the global inputs +
    0.5 x the mean over the bins of their masked mean squared values (the entropy only where the bin changed), and the
    score takes the worst bin."""
    from safeguard.training import _prediction_loss
    from tcn import opisne
    rng = np.random.default_rng(2)
    g, local = rng.normal(size=(16, L, G)), rng.uniform(0, 1, (16, L, B, 4))
    local[..., 3] = rng.integers(0, 2, (16, L, B))
    local[..., 2] *= local[..., 3]
    method = opisne.method(name)
    method.fit((g, local), (g, local), protocol=protocol({"stopping.max_epochs": 1}), seed=0)
    with torch.inference_mode():
        batch = (torch.as_tensor(g, dtype=torch.float32), torch.as_tensor(local, dtype=torch.float32))
        np.testing.assert_allclose(method.losses((g, local)).mean(), float(_prediction_loss(method.net, *batch)),
                                   rtol=1e-5)
    with torch.no_grad():
        for parameter in method.net.parameters():
            parameter.zero_()
    changed, zero, entropy, mask = (local[:, -1, :, channel] for channel in range(4))
    global_error = (g[:, -1] ** 2).mean(axis=1)
    bin_error = (changed ** 2 + zero ** 2 + mask * entropy ** 2) / (2 + mask)
    np.testing.assert_allclose(method.losses((g, local)), 0.5 * global_error + 0.5 * bin_error.mean(axis=1), rtol=1e-5)
    np.testing.assert_allclose(method.scores((g, local)), 0.5 * global_error + 0.5 * bin_error.max(axis=1), rtol=1e-5)


@pytest.mark.parametrize("name", ["gru", "lstm"])
def test_parameter_count_is_closest_to_the_tcn(name):
    """Addendum 2 point 1: at the shape of v5 under every column neural (20 global inputs, the 128 scored bins of the
    hyptcn-lab layout) the hidden size gives the parameter count closest to M's predictor, within 5 % of it; M's
    predictor is the one of analysis.architecture, which in v5 is architecture() at 32 rows."""
    from safeguard.model import Predictor, architecture
    from tcn import opisne
    from tcn.baselines import GRUPrediktor, LSTMPrediktor
    from tcn.model import pocet_parametrov
    hidden, count, tcn = opisne.recurrent_size(name, 20, 128, opisne.training_settings(protocol()))
    assert tcn == pocet_parametrov(Predictor(architecture(32, global_features=20)))
    cell = {"gru": GRUPrediktor, "lstm": LSTMPrediktor}[name]

    def count_at(size):
        return pocet_parametrov(cell(20 + 8, size, 20 + 3 * 128))

    assert count == count_at(hidden)
    assert all(abs(count - tcn) <= abs(count_at(size) - tcn) for size in (hidden - 1, hidden + 1))
    assert abs(count - tcn) / tcn < 0.05  # judgment: "close", the bound of tcn/tests/test_porovnanie.py


def test_methods_take_the_windows_of_m():
    """Design 1.1: a method fits and scores the windows of M as safeguard.training.Windows gives them (the normalizer
    of the protocol's rule, here every column neural while analysis.columns is null), and scores them as it scores
    the same windows given as the pair of arrays."""
    from safeguard.features import FeatureNormalizer, NormalizationRule, feature_contract
    from safeguard.training import Windows
    from tcn import opisne
    train, dev = [session("train-1", 1), session("train-2", 2)], [session("dev-1", 3)]
    rule = NormalizationRule.from_protocol(json.loads(V5.read_text()), diagnostic=True)
    normalizer = FeatureNormalizer.fit([frame for frames in train for frame in frames if frame.measured], rule)
    contract = feature_contract(train[0][0], 8, 7.5)

    def windows(sessions):
        return Windows([({"scenario": "quiet"}, frames) for frames in sessions], normalizer, contract, ["quiet"])

    train, dev = windows(train), windows(dev)
    pair = tuple(values.numpy() for values in dev.batch(range(len(dev.indices)))[:2])
    for name, seed in (("zscore", None), ("gru", 0)):
        method = opisne.method(name)
        record = method.fit(train, dev, protocol=protocol({"stopping.max_epochs": 1}), seed=seed)
        assert record["shape"] == {"window_rows": 8, "inputs": len(normalizer.input_names), "bins": 2}
        assert len(method.scores(dev)) == len(dev.indices)
        np.testing.assert_allclose(method.scores(dev), method.scores(pair), rtol=1e-6)
