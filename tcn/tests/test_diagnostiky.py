"""The descriptive diagnostics of the model (protocol v5, package B7b, agent G; design dokazy/B7/navrh/NAVRH_B7b.md
sections 1.3 and 3, the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 6, the B7b row of section 8 and point 3 of
its addendum of 2026-11-22T20:55Z, proposal 8.5 and 8.7).

The design's tests (section 3): the tree and the share of one member mark Z1 to Z3 as threshold-like on data where
they are (the skeleton's B7b row), and a diagnostic is used only then; fewer than 20 positive episodes give
nevyhodnotené; the model with shuffled context loses the advantage on data whose structure is temporal; the context
truncation of Z3 is flat (it uses one row); the variants of k of n; the threshold with one boot of calibration left
out; the partial models (mem_* only, global only, bins only) each see only their inputs. With them the threshold from
clean traffic only (1.3 point 5), the network with random weights and the retrained model of the full context against
M's training, and the refusals of analysis.diagnostics, the key agent F writes (synthetic protocol dicts here).

Synthetic normalized inputs and small fast trainings (the stop is shortened for the speed of the tests only:
judgment): mechanics, no number here is a detection result (HONESTY P4). The names of package B7b are imported inside
the tests, so this file collects on the code before it. The merge of B7b: the rates of alarm_rules and clean_threshold
are per observed hour of clean traffic, so they take the Traffic of each window set (tcn.metody.traffic); the accessor
reads analysis.diagnostics of config/collection-v5.json too. The fixes of the verification of B7b: M's seeds also
walked to the budget as in K2 (F4, SEED_WALK_RULE), and the level of the tree and of the share of one member taken
inclusive at exactly 0.8 (F5, mutants G1 and G2).
"""
import copy
import json
from pathlib import Path

import numpy as np
import pytest
import torch

from features.qualification import LOCAL_SCALED
from safeguard.features import GLOBAL_NAMES

ROOT = Path(__file__).resolve().parents[2]
WINDOW, INTERVAL, GAP, K, N = 8, 5.0, 7.5, 3, 5
COUNTS = GLOBAL_NAMES[GLOBAL_NAMES.index("proc_total"):]  # The columns of floor 1 (config analysis.scale).
DELETE = object()
UNEVALUATED = "nevyhodnotené"


@pytest.fixture(scope="module", autouse=True)
def _threads():
    """Two torch threads for this file (as tcn/tests/test_metody.py)."""
    before = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(before)


def protocol(*changes, window=WINDOW):
    """The keys this module reads: analysis.diagnostics of design 1.4 (agent F writes the key into
    config/collection-v5.json) with the lead's numbers (skeleton section 6) but the contexts 1, 2, 4 and 7 (judgment:
    the lead's 1, 2, 4, 8, 16 and 31 within a window of 8 rows), M's training of config/collection-v5.json with a stop
    shortened for speed (max_epochs 8, patience 3; judgment), the grids of Z1, Z3 and Z5, two seeds (judgment: speed)
    and fpr 0.1 (judgment: a quantile of these small sets); the reverberation 0 and the band of 60 s that
    tcn.metody.traffic reads (the merge of B7b). changes: (dotted path, value or DELETE)."""
    doc = {"name": "v5-test", "interval_s": INTERVAL, "window_rows": window, "full_snapshot_guard": {"before_s": 60},
           "analysis": {"alarm_rule": {"k": K, "n": N}, "fpr": 0.1, "seeds": [0, 1], "reverberation_s": 0,
                        "architecture": {"model": "safeguard/model.py TCN", "window_rows": window, "kernel": 3,
                                         "blocks": 4, "channels": 16, "dropout": 0.1, "weight_norm": False,
                                         "learning_rate": 0.001, "gradient_clip": 5, "classifier_gradient_clip": 5,
                                         "batch_size": 32, "note": ""},
                        "stopping": {"rule": "best dev loss, patience", "patience_epochs": 3, "max_epochs": 8,
                                     "repeat_if_last_epoch": "once with twice the cap", "note": ""},
                        "methods": {"Z1": {"grid": {"moving_average_rows": [4], "cusum_shift": [0.5]}},
                                    "Z3": {"grid": {"ewma_alpha": [0.3, 0.7]}},
                                    "Z5": {"grid": {"ridge_alpha": [0.0001, 100.0]}}},
                        "diagnostics": {"tree_depth": 3, "min_positive_episodes": 20, "contexts": [1, 2, 4, 7],
                                        "alarm_rules": [[2, 3], [3, 5], [4, 7]], "note": ""}}}
    for path, value in changes:
        *parents, last = path.split(".")
        node = doc
        for part in parents:
            node = node[part]
        if value is DELETE:
            del node[last]
        else:
            node[last] = copy.deepcopy(value)
    return doc


def normalizer(inputs, differenced=()):
    """A normalizer whose TCN inputs are `inputs` (in the order of GLOBAL_NAMES; those of `differenced` by their first
    difference, so the windows are anchored), mean 0 and scale 1, so the synthetic values are the normalized inputs;
    one bin of 4096 pages; floor 1 for the counts, 1e-3 for the other columns (as tcn/tests/test_metody.py)."""
    from safeguard.features import FeatureNormalizer, NormalizationRule
    classes = {name: "differenced" if name in differenced else "neural" if name in inputs else "rule"
               for name in GLOBAL_NAMES}
    floor = {name: 1.0 if name in COUNTS else 1e-3 for name in GLOBAL_NAMES}
    rule = NormalizationRule("analysis.columns", classes, floor, True, 1, dict.fromkeys(LOCAL_SCALED, 1e-6))
    width = len(rule.tcn_names)
    return FeatureNormalizer(rule, np.zeros(width), np.ones(width), [(0, 4096)], [], np.zeros((1, 4)),
                             np.ones((1, 4)), 1, 0)


def window_set(sessions, norm, *, role="train", bins=None, window=WINDOW):
    """A window set (tcn.metody.Okna) over synthetic sessions, each an array (T, G) of normalized inputs, rows 5 s apart
    from 1000 s, a window ending at every row from the `window`-th on (anchored by the row before its first when the
    rule has a differenced input, from the next row on); bins: per session the (T, 1, 4) inputs of the one bin, else 0
    with no change. The ids are <role>-<position>."""
    from tcn.metody import Okna
    rows, windows = [], []
    for s, values in enumerate(sessions):
        count = len(values)
        rows.append({"id": f"{role}-{s}", "global": values,
                     "local": np.zeros((count, 1, 4)) if bins is None else bins[s], "seq": np.arange(count),
                     "timestamp": 1000. + INTERVAL * np.arange(count), "full_times": [], "load": None})
        windows += [(s, end, end - window if norm.rule.anchored else None)
                    for end in range(window - 1 + int(norm.rule.anchored), count)]
    return Okna(rows, windows, role=role, normalizer=norm, window_rows=window, max_gap_s=GAP, interval_s=INTERVAL)


def boots(windows):
    """Every session its own boot."""
    return {ident: f"boot-{s}" for s, ident in enumerate(windows.session_ids)}


def everywhere(windows):
    return np.ones(len(windows), dtype=bool)


def traffic_of(windows, events=None):
    """The Traffic of a window set (tcn.metody.traffic under protocol(): the merge of B7b, the rates are per observed
    hour of clean traffic): no event, or `events` {session id: [event records]} for some sessions; no control."""
    from tcn.metody import traffic
    found = {ident: [] for ident in windows.session_ids}
    found.update(events or {})
    return traffic(windows, found, protocol())


def rng(seed):
    return np.random.default_rng(seed)


def places(seed, rows, count, spacing=4):
    """`count` rows of a session of `rows` rows, at least `spacing` apart and after the first window."""
    return rng(seed).choice(np.arange(WINDOW + 2, rows - 2, spacing), size=count, replace=False)


def spikes(seed, rows=200, count=8, width=2, length=1):
    """Noise in `width` columns with `count` spikes of +12 in column 0, each `length` rows long."""
    values = rng(seed).normal(size=(rows, width))
    for start in places(seed + 100, rows, count, spacing=4 + length):
        values[start:start + length, 0] += 12.0
    return values


def counts(seed, rows=200, count=8):
    """Two counts at their mode 5, a fifth of the rows one off it; `count` jumps of the second to 9."""
    values = np.full((rows, 2), 5.0)
    off = rng(seed).random((rows, 2)) < 0.2
    values[off] += rng(seed + 1).choice([-1.0, 1.0], off.sum())
    values[places(seed + 100, rows, count), 1] = 9.0
    return values


def walk(seed, rows=200, count=8, width=1, size=8.0):
    """A random walk of steps 0.3 in `width` columns with `count` jumps of `size` in every column."""
    steps = 0.3 * rng(seed).normal(size=(rows, width))
    if count:
        steps[places(seed + 100, rows, count)] += size
    return np.cumsum(steps, axis=0)


def periodic(seed, rows=100):
    """0, 1, 0, -1 repeated from a random phase, with noise of 0.05: the next row is minus the one two rows back."""
    pattern = np.array([0., 1., 0., -1.])
    return (pattern[(np.arange(rows) + rng(seed).integers(4)) % 4] + 0.05 * rng(seed + 1).normal(size=rows))[:, None]


def iid(seed, rows=100):
    return rng(seed).normal(size=(rows, 1))


class Fixed:
    """A fitted method, or M of one seed, of the interface of tcn.metody (name, kind, label, scores; M also seed and
    threshold) whose scores on a set are given by the set's role."""
    kind = "detector"

    def __init__(self, name, scores, *, seed=None, threshold=None):
        self.name, self.seed, self.threshold, self._scores = name, seed, threshold, scores
        self.label = name if seed is None else f"{name}:seed {seed}"

    def scores(self, windows):
        return np.asarray(self._scores[windows.role], dtype=np.float64)


def fitted(method, data, columns, *, seed=0):
    """`method` fitted on train (sessions 1, 2) and dev (session 3) of the generator `data` without its anomalies."""
    norm = normalizer(columns)
    train = window_set([data(s, count=0) for s in (1, 2)], norm)
    method.fit(train, window_set([data(3, count=0)], norm, role="dev"), protocol=protocol(), seed=seed)
    return method, norm


# ------------------------------------------------------------------ what the exceedances have in common


CASES = {  # its data, its TCN inputs, its threshold, the column its exceedances are in
    "Z1": (spikes, ("mem_changed_ratio", "mem_changed_max"), 5.0, "mem_changed_ratio"),
    "Z2": (counts, ("proc_total", "proc_user"), 2.0, "proc_user"),
    "Z3": (walk, ("mem_changed_ratio",), 8.0, "mem_changed_ratio"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_tree_and_the_share_mark_z1_to_z3_threshold_like(name):
    """Skeleton section 8, row B7b: on data where they are threshold-like by construction (Z1 at spikes of one column,
    Z2 at a count off its mode, Z3 at jumps of a random walk, where it predicts by the last value), 24 single-window
    exceedances in three boots, the tree cross-validated by boots reproduces every exceedance from the column it is in
    (F1 1) and in every exceeding window that column alone exceeds (share 1): both threshold-like."""
    from tcn import metody
    from tcn.diagnostiky import THRESHOLD_LIKE, one_member, tree
    data, columns, threshold, column = CASES[name]
    method, norm = fitted(metody.Z1(statistic="value") if name == "Z1" else getattr(metody, name)(), data, columns)
    test = window_set([data(s) for s in (4, 5, 6)], norm, role="test_benign")
    found = tree(method, test, threshold, boots(test), protocol=protocol())
    share = one_member(method, test, threshold, protocol=protocol())
    assert (found["positive_windows"], found["positive_episodes"], found["outcome"], found["f1"]) == (
        24, 24, THRESHOLD_LIKE, 1.0)
    assert [fold["boot"] for fold in found["boots"]] == ["boot-0", "boot-1", "boot-2"]
    assert any(split.startswith(column) for split in found["splits"])
    assert (share["outcome"], share["share"], share["alone"]) == (THRESHOLD_LIKE, 1.0, {column: 24})
    json.dumps([found, share], allow_nan=False)
    if name == "Z3":
        assert method.variant == "last"


class Random:
    """A detector whose scores do not follow its inputs."""
    name, kind, label = "R", "detector", "R"

    def scores(self, windows):
        return rng(len(windows)).random(len(windows))


@pytest.mark.parametrize("diagnostic", ["tree", "one_member"])
def test_what_is_not_threshold_like_is_marked(diagnostic):
    """The bad input of each: the exceedances of random scores are no function of the last row, so the tree reproduces
    few of them (F1 under 0.8); Z3 at jumps of 3 in each of four columns at once exceeds 3 (0.5 x the mean squared
    error 9) where no column alone does (0.5 x 9 / 4), so the share of one member is 0."""
    from tcn.diagnostiky import NOT_THRESHOLD_LIKE, one_member, tree
    from tcn.metody import Z3
    if diagnostic == "tree":
        norm = normalizer(("mem_changed_ratio", "mem_changed_max"))
        test = window_set([spikes(s) for s in (4, 5, 6)], norm, role="test_benign")
        found = tree(Random(), test, 0.9, boots(test), protocol=protocol())
        assert found["outcome"] == NOT_THRESHOLD_LIKE and found["f1"] < 0.8 and found["positive_episodes"] >= 20
        return
    columns = ("mem_changed_ratio", "mem_bins_active", "mem_changed_max", "mem_changed_p95")
    method, norm = fitted(Z3(), lambda s, count: walk(s, count=count, width=4, size=3.0), columns)
    test = window_set([walk(s, width=4, size=3.0) for s in (4, 5, 6)], norm, role="test_benign")
    share = one_member(method, test, 3.0, protocol=protocol())
    assert (share["outcome"], share["share"], share["alone"], share["positive_episodes"]) == (
        NOT_THRESHOLD_LIKE, 0.0, {}, 24)


def test_a_tree_of_f1_exactly_at_the_level_is_threshold_like():
    """TREE_RULE: threshold-like when the F1 is at least THRESHOLD_LEVEL, 0.8 inclusive (mutant G1 of the verification
    of B7b). Twelve spikes of 12 in one column of each of three boots, at eight of which the method exceeds its
    threshold: the tree cannot tell the other four from them (the same last row), so each boot's twelve are predicted
    exceeding by the tree of the other two boots: 24 true and 12 false positives, F1 = 48 / 60 = 0.8."""
    from tcn.diagnostiky import THRESHOLD_LEVEL, THRESHOLD_LIKE, tree
    norm = normalizer(("mem_changed_ratio",))
    sessions, scores = [], []
    for s in range(3):
        values = np.zeros((200, 1))
        where = places(s, 200, 12, spacing=6)
        values[where, 0] = 12.0
        score = np.zeros(200 - (WINDOW - 1))  # A window ends at every row from the window's last on.
        score[where[:8] - (WINDOW - 1)] = 1.0
        sessions.append(values)
        scores.append(score)
    test = window_set(sessions, norm, role="test_benign")
    found = tree(Fixed("Z1", {"test_benign": np.concatenate(scores)}), test, 0.5, boots(test), protocol=protocol())
    assert (found["positive_episodes"], found["pooled"]["true_positive"], found["pooled"]["false_positive"],
            found["pooled"]["false_negative"]) == (24, 24, 12, 0)
    assert found["f1"] == THRESHOLD_LEVEL == 0.8 and found["outcome"] == THRESHOLD_LIKE


def test_a_share_of_one_member_exactly_at_the_level_is_threshold_like():
    """ONE_MEMBER_RULE: threshold-like when the share is at least THRESHOLD_LEVEL, 0.8 inclusive (mutant G2 of the
    verification of B7b). Z3 (by the last value) on random walks of four columns at threshold 3: 20 jumps of 8 in one
    column, where that column alone exceeds (0.5 x 64 / 4), and 5 jumps of 3.5 in all four at once, where none does
    (0.5 x 12.25 / 4) though together they do: a share of 20 / 25 = 0.8."""
    from tcn.diagnostiky import THRESHOLD_LEVEL, THRESHOLD_LIKE, one_member
    from tcn.metody import Z3
    columns = ("mem_changed_ratio", "mem_bins_active", "mem_changed_max", "mem_changed_p95")
    method, norm = fitted(Z3(), lambda s, count: walk(s, count=count, width=4, size=3.0), columns)

    def jumps(seed, single, every):
        steps = 0.3 * rng(seed).normal(size=(200, 4))
        where = places(seed + 100, 200, single + every)
        steps[where[:single], 0] += 8.0
        steps[where[single:]] += 3.5
        return np.cumsum(steps, axis=0)
    test = window_set([jumps(4, 7, 2), jumps(5, 7, 2), jumps(6, 6, 1)], norm, role="test_benign")
    share = one_member(method, test, 3.0, protocol=protocol())
    assert (method.variant, share["positive_episodes"], share["alone"]) == ("last", 25, {"mem_changed_ratio": 20})
    assert share["share"] == THRESHOLD_LEVEL == 0.8 and share["outcome"] == THRESHOLD_LIKE


@pytest.mark.parametrize("episodes, minimum, evaluated", [(19, 20, False), (20, 20, True), (19, 19, True)])
def test_fewer_than_20_positive_episodes_give_nevyhodnotene(episodes, minimum, evaluated):
    """analysis.diagnostics.min_positive_episodes 20 (proposal 8.5): spikes two rows long give two exceeding windows
    each, one episode (EPISODE_RULE), so 19 spikes in two boots are 38 exceeding windows and still nevyhodnotené for
    both diagnostics; 20 are evaluated, and so are 19 when the protocol's minimum is 19."""
    from tcn.diagnostiky import THRESHOLD_LIKE, one_member, tree
    from tcn.metody import Z1
    method, norm = fitted(Z1(statistic="value"), spikes, ("mem_changed_ratio", "mem_changed_max"))
    test = window_set([spikes(4, count=10, length=2), spikes(5, count=episodes - 10, length=2)], norm,
                      role="test_benign")
    p = protocol(("analysis.diagnostics.min_positive_episodes", minimum))
    for found in (tree(method, test, 5.0, boots(test), protocol=p), one_member(method, test, 5.0, protocol=p)):
        assert (found["positive_windows"], found["positive_episodes"]) == (2 * episodes, episodes)
        if evaluated:
            assert found["outcome"] == THRESHOLD_LIKE
        else:
            assert (found["outcome"], found["why"]) == (UNEVALUATED, "19 positive episodes, fewer than 20")


@pytest.mark.parametrize("depth", [1, 3])
def test_the_tree_is_measured_on_the_boots_it_was_not_fitted_on(depth):
    """TREE_RULE: Z1 at spikes of a column of its own in each of three boots; the tree of
    analysis.diagnostics.tree_depth 3 fitted on every boot splits on the three columns, but a boot's exceedances are
    predicted by the tree of the other two boots, which never saw its column, so the F1 is 0 (not threshold-like); a
    tree of depth 1 splits once."""
    from tcn.diagnostiky import NOT_THRESHOLD_LIKE, tree
    from tcn.metody import Z1
    columns = ("mem_changed_ratio", "mem_bins_active", "mem_changed_max")
    method, norm = fitted(Z1(statistic="value"), lambda s, count: spikes(s, count=count, width=3), columns)
    sessions = [spikes(s, width=3) for s in (4, 5, 6)]
    for b, values in enumerate(sessions):  # The spikes of boot b in column b.
        values[:, [0, b]] = values[:, [b, 0]]
    test = window_set(sessions, norm, role="test_benign")
    found = tree(method, test, 5.0, boots(test), protocol=protocol(("analysis.diagnostics.tree_depth", depth)))
    assert (found["positive_episodes"], found["f1"], found["outcome"], found["depth"]) == (24, 0.0, NOT_THRESHOLD_LIKE,
                                                                                          depth)
    if depth == 1:
        assert len(found["splits"]) == 1
    else:  # A split names its column first (TREE_INPUTS).
        assert {split.split()[0] for split in found["splits"]} == set(columns)


def model(norm, *, seed=0, threshold=0.0):
    """M of one seed (tcn.metody.MetodaM) over a bundle in memory: an untrained TCN of the seed on `norm`."""
    from safeguard.bundle import Bundle
    from safeguard.model import Predictor, architecture
    from tcn.metody import MetodaM
    torch.manual_seed(seed)
    predictor = Predictor(architecture(WINDOW, global_features=len(norm.input_names))).eval()
    manifest = {"feature_contract": {"window_rows": WINDOW, "max_gap_s": GAP},
                "calibration": {"threshold": threshold, "k": K, "n": N}, "training": {"seed": seed}}
    return MetodaM(Bundle(manifest, predictor, None, norm))


def mixed(seed, count=12):
    """Noise in mem_changed_ratio with `count` spikes of +8, and the count proc_total at its mode 5 (a fifth of the
    rows one off it) with `count` jumps to 9."""
    values = np.column_stack((rng(seed).normal(size=200), np.full(200, 5.0)))
    off = rng(seed + 1).random(200) < 0.2
    values[off, 1] += rng(seed + 2).choice([-1.0, 1.0], off.sum())
    where = places(seed + 100, 200, 2 * count)
    values[where[:count], 0] += 8.0
    values[where[count:], 1] = 9.0
    return values


@pytest.mark.parametrize("z2_threshold, used", [(2.0, True), (100.0, False)])
def test_a_diagnostic_is_used_only_when_z1_to_z3_are_threshold_like(z2_threshold, used):
    """USE_RULE (proposal 8.5): Z1, Z2, Z3 and M of one seed on one set of spikes and count jumps; at thresholds where
    Z1 to Z3 are threshold-like both diagnostics are used for M; when Z2 never exceeds (threshold 100) it is
    nevyhodnotené, and neither diagnostic is used, naming Z2."""
    from tcn.diagnostiky import THRESHOLD_LIKE, threshold_likeness
    from tcn.metody import Z1, Z2, Z3
    norm = normalizer(("mem_changed_ratio", "proc_total"))
    train = window_set([mixed(s, count=0) for s in (1, 2)], norm)
    dev = window_set([mixed(3, count=0)], norm, role="dev")
    test = window_set([mixed(s) for s in (4, 5, 6)], norm, role="test_benign")
    methods = [Z1(statistic="value"), Z2(), Z3()]
    for method in methods:
        method.fit(train, dev, protocol=protocol(), seed=0)
    m = model(norm)
    entries = list(zip(methods, (5.0, z2_threshold, 3.0))) + [(m, float(np.quantile(m.scores(test), 0.88)))]
    found = threshold_likeness(entries, test, boots(test), protocol=protocol())
    json.dumps(found, allow_nan=False)
    assert [row["label"] for row in found["methods"]] == ["Z1:value", "Z2", "Z3:mean", "M:seed 0"]
    reference = {row["name"]: (row["tree"]["outcome"], row["one_member"]["outcome"]) for row in found["methods"]}
    assert reference["Z1"] == reference["Z3"] == (THRESHOLD_LIKE, THRESHOLD_LIKE)
    if used:
        assert reference["Z2"] == (THRESHOLD_LIKE, THRESHOLD_LIKE)
        assert found["use"] == {"tree": {"used": True, "failed": {}}, "one_member": {"used": True, "failed": {}}}
    else:
        assert found["use"] == {d: {"used": False, "failed": {"Z2": UNEVALUATED}} for d in ("tree", "one_member")}
    with pytest.raises(ValueError, match=r"^the diagnostics take Z1, Z2 and Z3 once each and M of one seed or more "
                                         r"\(proposal 8\.5\)$"):
        threshold_likeness(entries[1:], test, boots(test), protocol=protocol())


# ------------------------------------------------------------------ the networks of M's architecture


def test_the_shuffled_context_model_loses_the_advantage_on_temporal_data():
    """On a sequence whose next row is minus the row two back (period 4), the retrained TCN beats Z3 (I = 1 - loss /
    loss of Z3 near 1), and the model with shuffled context (the 8 rows before the last row of the context of a window
    of 10, two whole periods, in a random order) cannot tell the two cases after a 0 apart and has no advantage left
    (I near 0); on noise without structure the shuffle changes nothing. On both, Z3 predicts by the window mean, which
    the same shuffle for Z3 (proposal 8.5) leaves as it was, and so its loss. The shuffle keeps the multiset of the
    rows, the last row of the context and the target (SHUFFLE_RULE)."""
    import zlib
    from tcn.diagnostiky import SHUFFLE_ENTROPY, Shuffled, Siet, shuffle_order, shuffled
    from tcn.metody import Z3
    window, norm = 10, normalizer(("mem_changed_ratio",))
    p = protocol(window=window)
    improvement = {}
    for name, data in (("temporal", periodic), ("noise", iid)):
        train = window_set([data(s) for s in range(3)], norm, window=window)
        dev = window_set([data(10)], norm, role="dev", window=window)
        test = window_set([data(20)], norm, role="test_benign", window=window)
        z3 = Z3()
        z3.fit(train, dev, protocol=p, seed=0)
        for variant, m in (("retrained", Siet("retrained")), ("shuffled", Shuffled(Siet("retrained")))):
            record = m.fit(train, dev, protocol=p, seed=0)
            assert record["label"] == {"retrained": "M:retrained, seed 0",
                                       "shuffled": "M:shuffled context, retrained, seed 0"}[variant]
            improvement[name, variant] = 1 - m.losses(test).mean() / z3.losses(test).mean()
        z3_shuffled = Shuffled(Z3())
        record = z3_shuffled.fit(train, dev, protocol=p, seed=0)
        assert (record["chosen"]["predictor"], z3.variant) == ("mean", "mean")
        assert np.allclose(z3_shuffled.losses(test), z3.losses(test), rtol=1e-12)
    assert improvement["temporal", "retrained"] > 0.9 and improvement["temporal", "shuffled"] < 0.05
    assert abs(improvement["noise", "retrained"] - improvement["noise", "shuffled"]) < 0.05
    every = np.arange(len(test))
    g, plain = shuffled(test, 0).batch(every)[0], test.batch(every)[0]
    assert np.array_equal(g[:, -2:], plain[:, -2:]) and not np.array_equal(g, plain)
    assert np.array_equal(np.sort(g[:, :-2], axis=1), np.sort(plain[:, :-2], axis=1))
    drawn = rng([3, SHUFFLE_ENTROPY, zlib.crc32(b"test_benign")]).random((len(test), window - 2)).argsort(axis=1)
    assert np.array_equal(shuffle_order(test, 3), np.column_stack((drawn, np.full(len(test), window - 2))))


PARTS = {"mem": (["mem_changed_ratio", "mem_changed_max"], False, ("mem",), ("count", "bins")),
         "global": (["mem_changed_ratio", "mem_changed_max", "proc_total"], False, ("mem", "count"), ("bins",)),
         "bins": ([], True, ("bins",), ("mem", "count"))}


def partial_session(seed, change=None, rows=80):
    """Two memory columns, one count and one bin with changes; `change` adds 1 to the first memory column (mem), to
    the count (count) or to the bin's zero_ratio (bins)."""
    r = rng(seed)
    g = np.column_stack((r.normal(size=rows), r.normal(size=rows), r.integers(3, 7, rows).astype(float)))
    local = np.zeros((rows, 1, 4))
    local[:, 0, 3] = r.integers(0, 2, rows)
    local[:, 0, 0] = local[:, 0, 3] * r.uniform(.1, .5, rows)
    local[:, 0, 1] = r.normal(size=rows)
    local[:, 0, 2] = local[:, 0, 3] * r.normal(size=rows)
    if change is not None:
        (g[:, 0] if change == "mem" else g[:, 2] if change == "count" else local[:, 0, 1])[:] += 1.0
    return g, local


def partial_set(seeds, norm, role, change=None):
    made = [partial_session(s, change) for s in seeds]
    return window_set([g for g, _ in made], norm, role=role, bins=[local for _, local in made])


@pytest.mark.parametrize("part", sorted(PARTS))
def test_the_partial_models_see_only_their_inputs(part):
    """Addendum 2 point 3 (PARTIAL_RULE): each partial model, trained by M's training on the loss it reports, names the
    inputs it sees, and its scores and losses do not move when an input outside them moves (mem_* only: the count and
    the bins; global only: the bins; bins only: every global input), while they move with its own. The bad input: a
    model over mem_* when no mem_* column is an input of the TCN."""
    from tcn.diagnostiky import Siet
    inputs, has_bins, inside, outside = PARTS[part]
    norm = normalizer(("mem_changed_ratio", "mem_changed_max", "proc_total"))
    p = protocol(("analysis.stopping.max_epochs", 2), ("analysis.stopping.patience_epochs", 1))
    m, dev = Siet(part), partial_set((3,), norm, "dev")
    record = m.fit(partial_set((1, 2), norm, "train"), dev, protocol=p, seed=0)
    assert (record["inputs"], record["bins"], record["chosen"]["epoch"] >= 1) == (inputs, has_bins, True)
    # The loss it was trained and selected by is the loss it reports (LOSS_FORMULA of its part).
    assert record["stop"]["best_dev_loss"] == pytest.approx(float(m.losses(dev).mean()), rel=1e-5)
    json.dumps(record, allow_nan=False)
    base = partial_set((4,), norm, "test_benign")
    for change in outside:
        moved = partial_set((4,), norm, "test_benign", change)
        assert np.array_equal(m.scores(moved), m.scores(base)) and np.array_equal(m.losses(moved), m.losses(base))
    for change in inside:
        assert not np.allclose(m.scores(partial_set((4,), norm, "test_benign", change)), m.scores(base))
    if part == "mem":
        counts_only = normalizer(("proc_total",))
        with pytest.raises(ValueError, match=r"^Siet mem: no mem_\* column is an input of the TCN under rule "
                                             r"analysis\.columns$"):
            Siet("mem").fit(window_set([np.ones((20, 1))], counts_only),
                            window_set([np.ones((20, 1))], counts_only, role="dev"), protocol=p, seed=0)


@pytest.mark.parametrize("variant", ["random", "retrained", "shuffled"])
def test_the_networks_are_built_and_trained_as_m(variant):
    """The network with random weights is M's predictor at the seed before its first epoch (RANDOM_RULE: the stream
    predictor_init), with M's loss; the retrained model of the full context (CONTEXT_RULE: c = window_rows - 1 is the
    full set) is bit for bit what safeguard.training._train_predictor gives on the same window sets, and the model
    with shuffled context what it gives on the shuffled windows of train and dev (TRAINING_RULE, SHUFFLE_RULE)."""
    from safeguard.model import Predictor
    from safeguard.training import _train_predictor, model_config, stream_seed
    from tcn.diagnostiky import Shuffled, Siet, Truncated, shuffled
    from tcn.metody import errors
    from tcn.opisne import training_settings
    norm = normalizer(("mem_changed_ratio", "mem_changed_max", "proc_total"))
    p = protocol(("analysis.stopping.max_epochs", 2), ("analysis.stopping.patience_epochs", 1))
    train, dev = partial_set((1, 2), norm, "train"), partial_set((3,), norm, "dev")
    settings = training_settings(p)
    config = model_config({"model": settings["architecture"]}, WINDOW, 3)
    if variant == "random":
        m = Siet("random")
        record = m.fit(train, dev, protocol=p, seed=1)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(stream_seed(1, "predictor_init"))
            expected = Predictor(config).eval()
        g, local = (torch.as_tensor(train.rows(v), dtype=torch.float32) for v in train.batch(np.arange(len(train))))
        with torch.inference_mode():
            loss, score = errors(*expected(g[:, :-1], local[:, :-1]), g[:, -1], local[:, -1])
        assert (record["label"], record["chosen"], record["parameters"]) == ("M:random weights, seed 1", None, 11590)
        assert np.allclose(m.losses(train), loss, rtol=1e-6) and np.allclose(m.scores(train), score, rtol=1e-6)
        net = m.net
    else:
        m = Truncated(Siet("retrained"), WINDOW - 1) if variant == "retrained" else Shuffled(Siet("retrained"))
        seed = 0 if variant == "retrained" else 1  # The shuffle draws from the seed of the fit.
        record = m.fit(train, dev, protocol=p, seed=seed)
        parameters = dict(learning_rate=0.001, gradient_clip=5, batch_size=32, stopping=settings["stopping"],
                          seed=seed)
        sets = {"train": train, "dev": dev}
        if variant == "shuffled":
            sets = {role: shuffled(windows, seed) for role, windows in sets.items()}
        expected, stop, _ = _train_predictor(config, sets, parameters)
        assert record["label"] == {"retrained": "M:context 7, retrained, seed 0",
                                   "shuffled": "M:shuffled context, retrained, seed 1"}[variant]
        assert record["inner"]["stop"] == stop
        net = m.inner.net
    assert list(net.state_dict()) == list(expected.state_dict())
    assert all(torch.equal(a, b) for a, b in zip(net.state_dict().values(), expected.state_dict().values()))


# ------------------------------------------------------------------ the context


@pytest.mark.parametrize("make, data, flat", [("Z3", walk, True), ("Z5", periodic, False)])
def test_the_context_truncation_of_z3_is_flat(make, data, flat):
    """Proposal 8.5 over analysis.diagnostics.contexts (1, 2, 4, 7 here): on a random walk Z3 predicts by the last
    value at every context, which reads one row, so its loss is the same at each (flat); the truncation does move a
    method that reads more rows: Z5 on the sequence 0, 1, 0, -1 needs two rows (minus the row two back), so its loss
    at a context of one row is more than ten times its loss at two. The truncated windows are the full windows' last
    rows, in an anchored set too. The bad input: a context of window_rows rows."""
    from tcn import metody
    from tcn.diagnostiky import Truncated, context_truncation, truncated
    norm = normalizer(("mem_changed_ratio",))
    sessions = (lambda s: walk(s, count=0)) if data is walk else data
    train = window_set([sessions(s) for s in (1, 2)], norm)
    dev, test = window_set([sessions(3)], norm, role="dev"), window_set([sessions(4)], norm, role="test_benign")
    methods, record = context_truncation(getattr(metody, make), train, dev, {"test_benign": (test, everywhere(test))},
                                         protocol=protocol(), seed=0)
    json.dumps(record, allow_nan=False)
    losses = [row["loss"]["test_benign"] for row in record["contexts"]]
    assert [row["rows"] for row in record["contexts"]] == list(methods) == [1, 2, 4, 7]
    if flat:
        assert len(set(losses)) == 1 and [row["chosen"]["predictor"] for row in record["contexts"]] == ["last"] * 4
    else:
        assert losses[0] > 10 * losses[1]
    for full in (test, window_set([sessions(5)], normalizer(("mem_changed_ratio",), ("mem_changed_ratio",)))):
        short, every = truncated(full, 2), np.arange(len(full))
        assert (short.window_rows, short.seq.tolist(), short.anchored) == (3, full.seq.tolist(), full.anchored)
        assert np.array_equal(short.rows(short.batch(every)[0]), full.rows(full.batch(every)[0])[:, -3:])
        if full.anchored:  # The anchor is the row before the first row of the truncated window.
            assert short.index[:, 2].tolist() == (full.index[:, 1] - 3).tolist()
    with pytest.raises(ValueError, match=r"^a context of 8 rows: the windows of 8 rows have contexts of 1 to 7 rows$"):
        Truncated(metody.Z3(), WINDOW).fit(train, dev, protocol=protocol(), seed=0)


# ------------------------------------------------------------------ the alarm rule and the threshold


def runs(lengths, count=63):
    """Scores 0 with runs of 1 of the given lengths starting at windows 10, 25 and 40 (one session, no reset)."""
    values = np.zeros(count)
    for start, length in zip((10, 25, 40), lengths):
        values[start:start + length] = 1.0
    return values


def test_the_k_of_n_variants():
    """ALARM_RULES_RULE: runs of 2, 3 and 4 exceeding windows give seed 0 three alarms under 2 of 3, two under 3 of 5
    and one under 4 of 7; runs of 2, 2 and 5 give seed 1 three, one and one; the budget of each rule is their median
    rounded up (3, 2, 1), and each method's threshold is the matched threshold at it under that rule. The bad input:
    M of a subset of analysis.seeds."""
    from tcn.diagnostiky import alarm_rules
    from tcn.metody import matched_threshold, rate
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([np.zeros((70, 1))], norm, role="calibration")
    test = window_set([np.zeros((70, 1))], norm, role="test_benign")
    noise = {"calibration": rng(1).random(63), "test_benign": rng(2).random(63)}
    models = [Fixed("M", {"calibration": runs((2, 3, 4)), "test_benign": runs((3, 3, 3))}, seed=0, threshold=0.5),
              Fixed("M", {"calibration": runs((2, 2, 5)), "test_benign": runs((1, 1, 1))}, seed=1, threshold=0.5)]
    z1 = Fixed("Z1", noise)
    roles = {"test_benign": (test, traffic_of(test))}
    calls = []
    found = alarm_rules(models, [z1], calibration, traffic_of(calibration), protocol=protocol(), roles=roles,
                        detection=lambda method, threshold, k, n: calls.append((method.label, k, n)) or k)
    assert [(r["k"], r["n"], r["budget"]) for r in found["rules"]] == [(2, 3, 3), (3, 5, 2), (4, 7, 1)]
    assert [[s["alarms"] for s in r["seeds"]] for r in found["rules"]] == [[3, 3], [2, 1], [1, 1]]
    for row in found["rules"]:
        k, n = row["k"], row["n"]
        expected = matched_threshold(noise["calibration"], calibration, row["budget"], k=k, n=n,
                                     clean=everywhere(calibration))
        method = row["methods"][0]
        assert (method["label"], method["threshold"], method["alarms"], method["detection"]) == (
            "Z1", expected["threshold"], expected["alarms"], k)
        assert method["rates"]["test_benign"] == rate(noise["test_benign"], test, expected["threshold"], k=k, n=n,
                                                      traffic=roles["test_benign"][1])
        assert row["seeds"][0]["rates"]["test_benign"]["alarms"] == (3 if k <= 3 else 0)
    # The detection at every threshold: each seed at its bundle threshold and walked to the budget (SEED_WALK_RULE,
    # F4 of the verification of B7b) and the method, under each of the three rules.
    assert found["main"] == {"k": K, "n": N} and len(calls) == 15
    json.dumps(found, allow_nan=False)
    with pytest.raises(ValueError, match=r"^the models are M of exactly the seeds of analysis\.seeds \[0, 1\], each "
                                         r"once$"):
        alarm_rules(models[:1], [z1], calibration, traffic_of(calibration), protocol=protocol(), roles=roles,
                    detection=None)


def test_the_threshold_with_one_boot_left_out():
    """LEAVE_ONE_OUT_RULE: three boots of calibration whose scores rise to 1, 1.2 and 5; leaving out each boot, M's
    threshold of each seed is the quantile 1 - fpr (higher) of its scores on the windows left, the budget the median
    of its alarms there, and each method's threshold the matched threshold on the calibration of the two boots left;
    the range is their minimum and maximum. The bad input: boots that miss a session."""
    from tcn.diagnostiky import leave_one_boot_out
    from tcn.metody import alarm_count, budget, matched_threshold
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([np.zeros((30, 1))] * 3, norm, role="calibration")
    tops = (1.0, 1.2, 5.0)
    scores = [np.concatenate([np.linspace(0, top, 23) for top in tops]),
              np.concatenate([np.linspace(0, top, 23)[::-1] for top in tops])]
    models = [Fixed("M", {"calibration": s}, seed=seed, threshold=0.9) for seed, s in enumerate(scores)]
    noise = rng(3).random(69)
    clean = everywhere(calibration)
    found = leave_one_boot_out(models, [Fixed("Z1", {"calibration": noise})], calibration, clean, boots(calibration),
                               protocol=protocol())
    assert [row["left_out"] for row in found["boots"]] == ["boot-0", "boot-1", "boot-2"]
    for b, row in enumerate(found["boots"]):
        keep = [s for s in range(3) if s != b]
        left = window_set([np.zeros((30, 1))] * 2, norm, role="calibration")
        kept = np.concatenate([np.arange(23 * s, 23 * s + 23) for s in keep])
        thresholds = [float(np.quantile(s[kept], 0.9, method="higher")) for s in scores]
        alarms = [alarm_count(s[kept], left, t, k=K, n=N, clean=everywhere(left)) for s, t in zip(scores, thresholds)]
        assert [(s["threshold"], s["alarms"]) for s in row["seeds"]] == list(zip(thresholds, alarms))
        assert row["budget"] == budget(alarms) and row["windows"] == 46
        expected = matched_threshold(noise[kept], left, row["budget"], k=K, n=N, clean=everywhere(left))
        assert row["methods"][0]["threshold"] == expected["threshold"]
    assert found["boots"][2]["seeds"][0]["threshold"] < 1.2 < found["boots"][0]["seeds"][0]["threshold"]
    json.dumps(found, allow_nan=False)
    assert found["range"]["seeds"][0] == {"min": min(r["seeds"][0]["threshold"] for r in found["boots"]),
                                          "max": max(r["seeds"][0]["threshold"] for r in found["boots"]), "main": 0.9}
    with pytest.raises(ValueError, match=r"^boots maps the id of every session of the window set, and no other, to "
                                         r"the name of its boot \(a non-empty text\)$"):
        leave_one_boot_out(models, [], calibration, clean, {"calibration-0": "boot-0"}, protocol=protocol())


def test_the_threshold_from_clean_traffic_next_to_the_main_one():
    """CLEAN_THRESHOLD_RULE (proposal 8.7): the first 20 windows of calibration are an event with scores near 5; M's
    main threshold is its bundle's, the clean one the quantile 1 - fpr of the clean windows only, lower; at each the
    budget is the median of M's clean alarms and each method's threshold the matched one; the detection is called at
    every threshold. The bad input: a calibration without a clean window."""
    from tcn.diagnostiky import clean_threshold
    from tcn.metody import alarm_count, budget, matched_threshold
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([np.zeros((70, 1))] * 2, norm, role="calibration")
    test = window_set([np.zeros((40, 1))], norm, role="test_benign")
    # The event from row 0 to row 19 of the first session (reverberation 0): its first 20 windows are no clean traffic.
    traffic = traffic_of(calibration, {"calibration-0": [{"host_start_unix": 1000., "host_stopped_unix": 1095.}]})
    clean = traffic.clean
    assert np.array_equal(clean, np.arange(len(calibration)) >= 20)
    scores = []
    for seed in (0, 1):
        values = rng(seed).random(len(calibration))
        values[~clean] += 4.5
        scores.append(values)
    main = [float(np.quantile(s, 0.9, method="higher")) for s in scores]
    models = [Fixed("M", {"calibration": s, "test_benign": rng(9).random(33)}, seed=seed, threshold=t)
              for seed, (s, t) in enumerate(zip(scores, main))]
    noise = rng(5).random(len(calibration))
    z1 = Fixed("Z1", {"calibration": noise, "test_benign": rng(6).random(33)})
    found = clean_threshold(models, [z1], calibration, traffic, protocol=protocol(),
                            roles={"test_benign": (test, traffic_of(test))},
                            detection=lambda method, threshold, k, n: threshold)
    assert [v["threshold"] for v in found["variants"]] == ["main", "clean"]
    expected = {"main": main, "clean": [float(np.quantile(s[clean], 0.9, method="higher")) for s in scores]}
    for variant in found["variants"]:
        thresholds = expected[variant["threshold"]]
        alarms = [alarm_count(s, calibration, t, k=K, n=N, clean=clean) for s, t in zip(scores, thresholds)]
        assert [(s["threshold"], s["alarms"], s["detection"]) for s in variant["seeds"]] == [
            (t, a, t) for t, a in zip(thresholds, alarms)]
        assert variant["budget"] == budget(alarms)
        z1_threshold = matched_threshold(noise, calibration, variant["budget"], k=K, n=N, clean=clean)["threshold"]
        assert (variant["methods"][0]["threshold"], variant["methods"][0]["detection"]) == (z1_threshold, z1_threshold)
    assert all(c < m for c, m in zip(expected["clean"], main))
    assert [s["main_recomputed"] for s in found["variants"][0]["seeds"]] == main
    json.dumps(found, allow_nan=False)
    with pytest.raises(ValueError, match=r"^calibration has no clean window: the threshold from clean traffic only has "
                                         r"no score$"):
        everything = {ident: [{"host_start_unix": 1000., "host_stopped_unix": 1345.}]
                      for ident in calibration.session_ids}
        clean_threshold(models, [z1], calibration, traffic_of(calibration, everything), protocol=protocol(),
                        roles={}, detection=None)


def bursts(count, levels):
    """Scores 0 of `count` windows with three windows at each level of `levels`, from window 10 on, 25 apart."""
    values = np.zeros(count)
    for i, level in enumerate(levels):
        values[10 + 25 * i: 13 + 25 * i] = level
    return values


def test_the_seeds_of_m_also_walk_to_the_budget_as_in_k2():
    """SEED_WALK_RULE (F4 of the verification of B7b, the verifier's probe_rules_threshold): in K2 every seed of M walks
    to the budget like every method (tcn/k2.py DETECTION_RULE), so alarm_rules and the main variant of clean_threshold
    report each seed at its matched threshold beside its bundle threshold. Seed 0 alarms once at its bundle threshold
    4 and seed 1 three times, so the budget at 3 of 5 is 2; walked to it, seed 0 alarms twice at 2 and seed 1 never at
    5, as tcn.k2.matched_thresholds gives them; the clean variant keeps each seed at its clean threshold."""
    from tcn import k2
    from tcn.diagnostiky import alarm_rules, clean_threshold
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([np.zeros((120, 1))], norm, role="calibration")
    count = len(calibration)
    seeds = [Fixed("M", {"calibration": bursts(count, [5, 3, 2])}, seed=0, threshold=4.0),
             Fixed("M", {"calibration": bursts(count, [5, 5, 5])}, seed=1, threshold=4.0)]
    z1 = Fixed("Z1", {"calibration": bursts(count, [1, 2, 3, 4])})
    traffic = traffic_of(calibration)
    found = alarm_rules(seeds, [z1], calibration, traffic, protocol=protocol(), roles={},
                        detection=lambda method, threshold, k, n: (method.label, threshold, k, n))
    for row in found["rules"]:
        k, n = row["k"], row["n"]
        walked = k2.matched_thresholds([*seeds, z1], calibration, traffic.clean, row["budget"], k=k, n=n)
        for seed in row["seeds"]:
            mine = walked[seed["label"]]
            assert (seed["threshold"], seed["detection"]) == (4.0, (seed["label"], 4.0, k, n))
            assert (seed["matched"]["threshold"], seed["matched"]["alarms"], seed["matched"]["detection"]) == (
                mine["threshold"], mine["alarms"], (seed["label"], mine["threshold"], k, n))
        assert row["methods"][0]["threshold"] == walked["Z1"]["threshold"]
    main = next(row for row in found["rules"] if (row["k"], row["n"]) == (K, N))
    assert main["budget"] == 2 and [(s["alarms"], s["matched"]["threshold"], s["matched"]["alarms"])
                                    for s in main["seeds"]] == [(1, 2.0, 2), (3, 5.0, 0)]
    assert found["seed_walk_rule"].startswith("each seed of M also at its matched threshold at the budget")
    variants = clean_threshold(seeds, [z1], calibration, traffic, protocol=protocol(), roles={}, detection=None)
    first, clean = variants["variants"]
    walked = k2.matched_thresholds(seeds, calibration, traffic.clean, first["budget"], k=K, n=N)
    assert (first["threshold"], first["budget"]) == ("main", 2)
    assert [(s["matched"]["threshold"], s["matched"]["detection"]) for s in first["seeds"]] == [
        (walked[s["label"]]["threshold"], None) for s in first["seeds"]]
    assert clean["threshold"] == "clean" and not any("matched" in s for s in clean["seeds"])
    json.dumps([found, variants], allow_nan=False)


# ------------------------------------------------------------------ the protocol key


@pytest.mark.parametrize("changes, reason", [
    ([("analysis.diagnostics", DELETE)], r"^protocol key analysis\.diagnostics is missing \(design B7b 1\.4\)$"),
    ([("analysis.diagnostics.note", DELETE)],
     r"^analysis\.diagnostics must be an object of exactly the keys tree_depth, min_positive_episodes, contexts, "
     r"alarm_rules, note$"),
    ([("analysis.diagnostics.tree_depth", 0)], r"^analysis\.diagnostics\.tree_depth must be an integer of at least 1$"),
    ([("analysis.diagnostics.min_positive_episodes", 2.5)],
     r"^analysis\.diagnostics\.min_positive_episodes must be an integer of at least 1$"),
    ([("analysis.diagnostics.contexts", [1, 2, 8])],
     r"^analysis\.diagnostics\.contexts must be an increasing list of integers from 1 to window_rows - 1 \(7\)$"),
    ([("analysis.diagnostics.alarm_rules", [[2, 3], [4, 3]])],
     r"^analysis\.diagnostics\.alarm_rules must be a non-empty list of distinct pairs \[k, n\] of integers with "
     r"1 <= k <= n$"),
])
def test_analysis_diagnostics_is_read_and_refused_by_name(changes, reason):
    """The one accessor of analysis.diagnostics (design 1.4, agent F's key): the good input gives the lead's numbers
    (skeleton section 6); each bad one is refused with its reason."""
    from tcn.diagnostiky import diagnostics
    assert diagnostics(protocol()) == {"tree_depth": 3, "min_positive_episodes": 20, "contexts": [1, 2, 4, 7],
                                       "alarm_rules": [(2, 3), (3, 5), (4, 7)]}
    with pytest.raises(ValueError, match=reason):
        diagnostics(protocol(*changes))


def test_analysis_diagnostics_of_the_real_file():
    """The merge of B7b: the accessor reads analysis.diagnostics of config/collection-v5.json (agent F's key, G0) as
    the lead's numbers of skeleton section 6, the contexts within the file's window of 32 rows."""
    from tcn.diagnostiky import diagnostics
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    assert diagnostics(doc) == {"tree_depth": 3, "min_positive_episodes": 20, "contexts": [1, 2, 4, 8, 16, 31],
                                "alarm_rules": [(2, 3), (3, 5), (4, 7)]}
    assert doc["analysis"]["diagnostics"]["alarm_rules"] == [[2, 3], [3, 5], [4, 7]]


@pytest.mark.parametrize("call", ["alarm_rules", "clean_threshold"])
def test_the_rates_take_the_traffic_of_their_window_sets(call):
    """The merge of B7b: alarm_rules and clean_threshold report rates per observed hour of clean traffic, so they take
    the Traffic of calibration and of each role; a boolean mask in its place is refused by name."""
    from tcn import diagnostiky
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([np.zeros((70, 1))], norm, role="calibration")
    models = [Fixed("M", {"calibration": rng(seed).random(63)}, seed=seed, threshold=0.9) for seed in (0, 1)]
    function = getattr(diagnostiky, call)
    with pytest.raises(ValueError, match=r"^the traffic of calibration of role calibration is the Traffic of its "
                                         r"window set \(tcn\.metody\.traffic\): a rate is per observed hour of clean "
                                         r"traffic \(tcn\.metody RATE_RULE\)$"):
        function(models, [], calibration, everywhere(calibration), protocol=protocol(), roles={}, detection=None)
