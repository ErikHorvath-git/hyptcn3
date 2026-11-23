"""The wrapper of the methods Z0 to Z5 and M, and the matched alarm rate (protocol v5, package B7a, agent W; design
dokazy/B7/navrh/NAVRH_B7a.md sections 1.1 to 1.4 and 2, the lead's skeleton dokazy/B7/kostra/KOSTRA.md sections 2
and 3 and the B7a row of section 8).

Skeleton section 8, row B7a, and design section 2: every method on data whose answer is known by construction (a
level shift for Z1, a count off its mode for Z2, a random walk for Z3 where the last value wins, AR(1) for Z5, a load
jump for Z4; Z0 never alarms and its random variant meets the rate), and the matched rate: the budget on clean traffic
only (an event window excluded), the walk from the top, the non-monotonic case and the budget-0 case. With them the
alarm rule against safeguard.runtime and safeguard.training.calibrate, the windows and the score of M against its
bundle, the clean traffic, the interface every method keeps, and the refusals of the protocol keys of design 1.6 that
agent K writes (synthetic protocol dicts here).

The data are synthetic normalized inputs, and for M and the alarm rule synthetic frames with an untrained, seeded TCN:
mechanics only, no number is a detection result (HONESTY P4). The names of package B7a are imported inside the tests,
so this file collects on the code before it.

Package B7b (agent F, design dokazy/B7/navrh/NAVRH_B7b.md 1.1 and 4): the deferred findings of the verification of
B7a. F1 and F2 (question Q12, provisional): the clean traffic without the full-snapshot band, the placeable traffic
with it and the controls, the rate per observed hour of clean traffic; F3: the grids refused as the protocol refuses
them; F6: fit on the roles train and dev only, the budget at exactly analysis.seeds; F5: one test for each mutant
that survived (M01 in the budget's cases, M02, M03, M05, M14, M16; M04 is tcn/tests/test_tvrdenia.py's).
"""
import copy
import json
from pathlib import Path

import numpy as np
import pytest
import torch

from features.qualification import LOCAL_SCALED
from features.snapshot import MENA
from safeguard.features import GLOBAL_NAMES, Frame

ROOT = Path(__file__).resolve().parents[2]
WINDOW, INTERVAL, GAP, K, N = 8, 5.0, 7.5, 3, 5
COUNTS = GLOBAL_NAMES[GLOBAL_NAMES.index("proc_total"):]  # The columns of floor 1 (config analysis.scale).
DELETE = object()


@pytest.fixture(scope="module", autouse=True)
def _threads():
    """Two torch threads for this file (as safeguard/tests/test_channels.py)."""
    before = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(before)


def protocol(*changes):
    """The keys the wrapper reads, of the layout of design 1.6 (agent K writes them into config/collection-v5.json):
    the grids of Z1, Z3 and Z5 (null there until G3a), analysis.matched_rate and the stream z0_alarms. changes: (dotted
    path, value or DELETE)."""
    doc = {"name": "v5-test", "interval_s": INTERVAL, "window_rows": WINDOW,
           "roles": {"train": 12, "dev": 4, "calibration": 8, "test_benign": 12, "test_controls": 8},
           "rehearsal": {"name_suffix": "-generalka"}, "full_snapshot_guard": {"before_s": 60},
           "streams": {"purposes": ["traffic", "z0_alarms", "bootstrap"]},
           "analysis": {"alarm_rule": {"k": K, "n": N}, "reverberation_s": 300,
                        "matched_rate": {"budget": "the median over the seeds of M's alarms on the clean traffic of "
                                                   "calibration, rounded up", "z0_repetitions": 200, "note": ""},
                        "methods": {"Z0": {"grid": {}}, "Z2": {"grid": {}}, "Z4": {"grid": {}}, "M": {"grid": {}},
                                    "Z1": {"grid": {"moving_average_rows": [4], "cusum_shift": [0.5, 1.0]}},
                                    "Z3": {"grid": {"ewma_alpha": [0.3, 0.7]}},
                                    "Z5": {"grid": {"ridge_alpha": [0.0001, 100.0]}}}}}
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
    """A normalizer (safeguard/features.py) whose TCN inputs are `inputs` (in the order of GLOBAL_NAMES; those of
    `differenced` by their first difference), mean 0 and scale 1, so the synthetic values below are the normalized
    inputs; one bin of 4096 pages; floor 1 for the counts, 1e-3 for the other columns."""
    from safeguard.features import FeatureNormalizer, NormalizationRule
    classes = {name: "differenced" if name in differenced else "neural" if name in inputs else "rule"
               for name in GLOBAL_NAMES}
    floor = {name: 1.0 if name in COUNTS else 1e-3 for name in GLOBAL_NAMES}
    rule = NormalizationRule("analysis.columns", classes, floor, True, 1, dict.fromkeys(LOCAL_SCALED, 1e-6))
    width = len(rule.tcn_names)
    return FeatureNormalizer(rule, np.zeros(width), np.ones(width), [(0, 4096)], [], np.zeros((1, 4)),
                             np.ones((1, 4)), 1, 0)


def window_set(sessions, norm, *, role="train", loads=None, barriers=(), full=None, bins=None):
    """A window set (tcn.metody.Okna) over synthetic sessions, each an array (T, G) of normalized inputs, rows 5 s
    apart from 1000 s: a window ends at every row whose window_rows rows hold no barrier (`barriers`: positions of
    every session that are full or invalid rows), anchored by the last row before them that is no barrier when the
    rule has a differenced input. loads: per session the offered load of each row; bins: per session the (T, 1, 4)
    inputs of the one bin, else 0 with no change; role: the role of the set."""
    from tcn.metody import Okna
    rows, windows = [], []
    for s, values in enumerate(sessions):
        count = len(values)
        rows.append({"id": f"session-{s}", "global": values,
                     "local": np.zeros((count, 1, 4)) if bins is None else bins[s],
                     "seq": np.arange(count), "timestamp": 1000. + INTERVAL * np.arange(count),
                     "full_times": [] if full is None else [1000. + INTERVAL * p for p in full],
                     "load": None if loads is None else loads[s]})
        for end in range(WINDOW - 1, count):
            first = end - WINDOW + 1
            if any(first <= b <= end for b in barriers):
                continue
            anchor = None
            if norm.rule.anchored:
                anchor = next((p for p in range(first - 1, -1, -1) if p not in barriers), None)
                if anchor is None:
                    continue
            windows.append((s, end, anchor))
    return Okna(rows, windows, role=role, normalizer=norm, window_rows=WINDOW, max_gap_s=GAP, interval_s=INTERVAL)


def everywhere(windows):
    return np.ones(len(windows), dtype=bool)


def quiet(windows):
    """The Traffic of a window set whose sessions hold no event and no control (package B7b: every window and every
    row clean); the rate takes it (RATE_RULE)."""
    from tcn.metody import traffic
    return traffic(windows, {ident: [] for ident in windows.session_ids}, protocol())


def as_role(windows, role):
    """The same windows as a window set of another role. Package B7b: fit takes window sets of roles train and dev
    only (F6 of the verification of B7a); a test whose train and dev are one synthetic set passes it as both roles."""
    out = copy.copy(windows)
    out.role = role
    return out


def edges(method, windows, threshold):
    """The seq of the windows where an alarm of `method` begins at `threshold`."""
    from tcn.metody import alarm_edges
    return windows.seq[alarm_edges(method.scores(windows), windows, threshold, k=K, n=N)].tolist()


def matched(method, calibration, budget):
    from tcn.metody import matched_threshold
    return matched_threshold(method.scores(calibration), calibration, budget, k=K, n=N,
                             clean=everywhere(calibration))["threshold"]


def noise(seed, *shape):
    return np.random.default_rng(seed).normal(size=shape)


# ------------------------------------------------------------------ the methods on data with a known answer


Z1_INPUTS = ("mem_changed_ratio", "mem_changed_max")


def test_z1_alarms_at_a_level_shift():
    """A level shift of 6 standard deviations in one column from row 150 to 169 of a quiet test role (a tenth of the
    noise of train, so that no alarm of the noise can fall in it): at the threshold matched to a budget of 0 on noise,
    Z1 (the value statistic) raises one alarm, at the third shifted window (3 of 5), and the matched rate reports it."""
    from tcn.metody import Z1, matched_rate
    norm = normalizer(Z1_INPUTS)
    train = window_set([noise(s, 300, 2) for s in (1, 2, 3)], norm)
    dev = window_set([noise(4, 300, 2)], norm, role="dev")
    calibration = window_set([noise(s, 300, 2) for s in (5, 6)], norm, role="calibration")
    shifted = 0.1 * noise(7, 300, 2)
    shifted[150:170, 0] += 6
    test = window_set([shifted], norm, role="test_benign")
    z1 = Z1(statistic="value")
    record = z1.fit(train, dev, protocol=protocol(), seed=0)
    assert record["columns"] == list(Z1_INPUTS) and record["chosen"] == {"statistic": "value", "parameter": None}
    assert edges(z1, test, matched(z1, calibration, 0)) == [152]
    result = matched_rate(z1, calibration, quiet(calibration), 0, k=K, n=N,
                          roles={"test_benign": (test, quiet(test))})
    assert (result["label"], result["alarms"], result["rates"]["calibration"]["alarms"]) == ("Z1:value", 0, 0)
    assert result["rates"]["test_benign"]["alarms"] == 1
    # Package B7b (F2 of the verification of B7a): per observed hour of clean traffic, the 300 rows of the session.
    assert result["rates"]["test_benign"]["per_hour"] == pytest.approx(1 / (300 * INTERVAL / 3600))


@pytest.mark.parametrize("prefer, chosen", [
    ("cusum(1.0)", {"statistic": "cusum", "parameter": 1.0}),
    (None, {"statistic": "value", "parameter": None}),  # Every candidate ties: the first one.
])
def test_z1_selection_takes_the_given_criterion(prefer, chosen):
    """The hook of the selection on dev (B7b gives the share of the interventions detected): the candidate the
    criterion prefers, ties to the first, every candidate of the grid in order."""
    from tcn.metody import Z1
    norm = normalizer(Z1_INPUTS)
    train, dev = window_set([noise(1, 200, 2)], norm), window_set([noise(2, 200, 2)], norm, role="dev")
    seen = []

    def criterion(candidate, windows):
        seen.append(windows)
        return 1.0 if candidate.variant == prefer else 0.0
    z1 = Z1(criterion)
    record = z1.fit(train, dev, protocol=protocol(), seed=0)
    assert record["chosen"] == chosen and z1.variant == (prefer or "value")
    assert [(c["statistic"], c["parameter"]) for c in record["candidates"]] == [
        ("value", None), ("difference", None), ("moving_average", 4), ("cusum", 0.5), ("cusum", 1.0),
        ("mem_changed_max", None)]
    assert all(windows is dev for windows in seen)
    fixed = Z1(statistic=chosen["statistic"], parameter=chosen["parameter"])
    fixed.fit(train, dev, protocol=protocol(), seed=0)
    assert np.array_equal(z1.scores(dev), fixed.scores(dev))


UP, DOWN = [0, 0, 0, 0, 1, 1, 1, 3], [0, 0, 0, 0, -1, -1, -1, -3]


@pytest.mark.parametrize("statistic, parameter, rows, center, spread, score", [
    ("value", None, UP, 0.0, 1.0, 3.0),                # |3 - 0| / 1
    ("value", None, DOWN, 0.0, 1.0, 3.0),              # two-sided: |-3 - 0| / 1
    ("difference", None, UP, 0.0, 2.0, 1.0),           # the steps of train are +-2: |2 - 0| / 2
    ("moving_average", 4, UP, 0.0, 1e-3, 1500.0),      # every mean of train is 0, so the floor: |1.5 - 0| / 0.001
    ("cusum", 0.5, UP, 0.5, 1e-3, 3500.0),             # every CUSUM of train is 0.5: (4 - 0.5) / 0.001
    ("cusum", 0.5, DOWN, 0.5, 1e-3, 3500.0),           # the lower sum S- is the same 4
    ("mem_changed_max", None, UP, 0.0, 1.0, 3.0),      # (3 - 0) / 1
    ("mem_changed_max", None, DOWN, 0.0, 1.0, -3.0),   # one-sided: (-3 - 0) / 1, a low value is no anomaly
])
def test_z1_statistics_by_hand(statistic, parameter, rows, center, spread, score):
    """Each statistic of Z1_RULE, by hand: train is +1, -1, +1, ... in its one input mem_changed_max (floor 1e-3), 207
    rows and so 200 windows, half of them ending in +1; the window UP is 0, 0, 0, 0, 1, 1, 1, 3, whose value is 3,
    difference 2, mean of the last four 1.5 and CUSUM with shift 0.5 0.5 + 0.5 + 0.5 + 2.5 = 4; DOWN is its negative."""
    from tcn.metody import Z1
    norm = normalizer(("mem_changed_max",))
    train = window_set([np.where(np.arange(207) % 2, -1.0, 1.0)[:, None]], norm)
    z1 = Z1(statistic=statistic, parameter=parameter)
    record = z1.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)
    assert (record["center"][0], record["spread"][0]) == pytest.approx((center, spread))
    window = window_set([np.array(rows, dtype=float)[:, None]], norm)
    assert z1.scores(window)[0] == pytest.approx(score)


def test_z1_needs_the_criterion_of_its_selection():
    from tcn.metody import Z1
    norm = normalizer(Z1_INPUTS)
    train = window_set([noise(1, 100, 2)], norm)
    with pytest.raises(ValueError, match=r"^Z1 is selected by the share of the interventions inserted into dev that "
                                         r"it detects \(skeleton section 2, package B7b\): its fit needs that "
                                         r"criterion$"):
        Z1().fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)


def test_z2_alarms_where_a_count_leaves_its_mode():
    """proc_total is 5 in train with an isolated 6 in every 25th row (mode 5); 8 in rows 100 to 119 of the test role:
    Z2 scores 0 at the mode, 1 at the isolated rows and 3 in the block, and at the threshold of a budget of 0 alarms
    once, at the third window of the block; the other input (no count) does not enter."""
    from tcn.metody import Z2
    norm = normalizer(("mem_changed_ratio", "proc_total"))

    def session(seed, rows, block=False):
        count = np.where(np.arange(rows) % 25 == 3, 6.0, 5.0)
        if block:
            count[100:120] = 8.0
        return np.stack((noise(seed, rows), count), axis=1)
    train = window_set([session(1, 300), session(2, 300)], norm)
    calibration = window_set([session(3, 300)], norm, role="calibration")
    test = window_set([session(4, 300, block=True)], norm, role="test_benign")
    z2 = Z2()
    record = z2.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)
    assert record["counts"] == ["proc_total"] and record["modes"] == [5.0]
    scores = z2.scores(test)
    assert set(scores[(test.seq >= 100) & (test.seq < 120)]) == {3.0}
    assert set(scores[test.seq % 25 == 3]) - {3.0} == {1.0} and set(scores) == {0.0, 1.0, 3.0}
    assert edges(z2, test, matched(z2, calibration, 0)) == [102]


def test_z2_needs_a_count_among_the_inputs():
    from tcn.metody import Z2
    norm = normalizer(("mem_changed_ratio",))
    train = window_set([noise(1, 100, 1)], norm)
    with pytest.raises(ValueError, match=r"^Z2 has no count \(a column of analysis\.scale\.floor 1\) among the TCN "
                                         r"inputs$"):
        Z2().fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)


def walk(seed, rows, step):
    return np.cumsum(np.random.default_rng(seed).normal(scale=step, size=rows))[:, None]


def test_z3_last_value_wins_on_a_random_walk():
    """On a random walk the last value is the best prediction: Z3 selects it on dev over the window mean and the EWMA,
    and its dev loss is half the variance of a step (the bins are constant)."""
    from tcn.metody import Z3
    norm = normalizer(("mem_changed_ratio",))
    train = window_set([walk(1, 300, .1), walk(2, 300, .1)], norm)
    dev = window_set([walk(3, 400, .1)], norm, role="dev")
    z3 = Z3()
    record = z3.fit(train, dev, protocol=protocol(), seed=0)
    assert record["chosen"] == {"predictor": "last", "ewma_alpha": None} and z3.variant == "last"
    losses = {(c["predictor"], c["ewma_alpha"]): c["dev_loss"] for c in record["candidates"]}
    assert list(losses) == [("last", None), ("mean", None), ("ewma", 0.3), ("ewma", 0.7)]
    assert losses[("last", None)] < min(v for key, v in losses.items() if key[0] != "last")
    assert losses[("last", None)] == pytest.approx(0.5 * 0.1 ** 2, rel=0.2)  # judgment: 20 % for 393 windows
    assert np.mean(z3.losses(dev)) == pytest.approx(losses[("last", None)])


def test_z3_predictors_by_hand():
    """One dev window: the rows before the last are 0, 0, 0, 0, 0, 0, 1 and the last is 2 (the bins do not change, so
    only the global part of the loss, 0.5 times the squared error, is left): the last value predicts 1, the mean 1/7,
    the EWMA 0.3 and 0.7 (s = 0 until the row 1, then a)."""
    from tcn.metody import Z3
    norm = normalizer(("mem_changed_ratio",))
    dev = window_set([np.array([0, 0, 0, 0, 0, 0, 1, 2], dtype=float)[:, None]], norm, role="dev")
    record = Z3().fit(as_role(dev, "train"), dev, protocol=protocol(), seed=0)
    assert [c["dev_loss"] for c in record["candidates"]] == pytest.approx(
        [0.5 * (2 - p) ** 2 for p in (1, 1 / 7, 0.3, 0.7)])


def test_z3_is_not_fitted_before_its_grid():
    from tcn.metody import Z3
    norm = normalizer(("mem_changed_ratio",))
    train = window_set([walk(1, 100, .1)], norm)
    with pytest.raises(ValueError, match=r"^analysis\.methods\.Z3\.grid is null: the grid of Z3 is determined in G3a "
                                         r"\(determined_at\), so Z3 is not fitted before it$"):
        Z3().fit(train, as_role(train, "dev"), protocol=protocol(("analysis.methods.Z3.grid", None)), seed=0)


def ar1(seed, rows, phi):
    rng = np.random.default_rng(seed)
    x = np.zeros(rows)
    for t in range(1, rows):
        x[t] = phi * x[t - 1] + rng.normal()
    return x[:, None]


def ar1_session(seed, rows):
    """A session of AR(1) series: the global input with coefficient 0.5, the changed ratio of the one bin with -0.4 and
    its entropy with 0.6, every noise of variance 1; the bin changes in every row (the entropy is measured)."""
    local = np.zeros((rows, 1, 4))
    local[:, 0, 0], local[:, 0, 2], local[:, 0, 3] = ar1(seed + 50, rows, -.4)[:, 0], ar1(seed + 90, rows, .6)[:, 0], 1
    return ar1(seed, rows, .5), local


def test_z5_recovers_an_ar1():
    """Z5 selects the weak strength on dev and recovers each coefficient on the row before the last (0.5 in the global
    branch, -0.4 and 0.6 in the shared bin branch, the others 0); its dev loss is that of the noise alone, 0.5 * 1 +
    0.5 * (1 + 0 + 1) / 3 (LOSS_FORMULA with the three values of the bin), below that of Z3's best."""
    from tcn.metody import Z3, Z5
    norm = normalizer(("mem_changed_ratio",))

    def windows(seeds, rows, role):
        sessions = [ar1_session(seed, rows) for seed in seeds]
        return window_set([g for g, _ in sessions], norm, role=role, bins=[local for _, local in sessions])
    train, dev = windows((1, 2, 3), 400, "train"), windows((4,), 600, "dev")
    z5, z3 = Z5(), Z3()
    record = z5.fit(train, dev, protocol=protocol(), seed=0)
    assert record["chosen"] == {"ridge_alpha": 0.0001} and record["unobserved"] == []
    global_coefficients = z5.coefficients[0][:, 0]  # The intercept, then the rows before the last in order.
    assert global_coefficients[-1] == pytest.approx(0.5, abs=0.1)  # judgment: 0.1 for 1176 train windows
    assert np.abs(global_coefficients[:-1]).max() < 0.1
    bins = z5.coefficients[1]  # The intercept, then the four channels of each row before the last in order.
    last = 1 + 4 * (WINDOW - 2)
    assert (bins[last, 0], bins[last + 2, 2]) == pytest.approx((-0.4, 0.6), abs=0.1)
    others = np.ones(bins.shape, dtype=bool)
    others[0], others[last, 0], others[last + 2, 2] = False, False, False
    assert np.abs(bins[others]).max() < 0.1
    loss = {c["ridge_alpha"]: c["dev_loss"] for c in record["candidates"]}
    assert loss[0.0001] == pytest.approx(0.5 + 0.5 * 2 / 3, rel=0.15)  # judgment: 15 % for 593 windows
    assert loss[0.0001] < loss[100.0] and np.mean(z5.losses(dev)) == pytest.approx(loss[0.0001])
    z3.fit(train, dev, protocol=protocol(), seed=0)
    assert loss[0.0001] < np.mean(z3.losses(dev))


def test_z5_fits_a_bin_by_the_loss_of_training():
    """The bin changes in a random half of the rows, its entropy is 1 where it changed and 0 (the normalizer's value
    of an unmeasured entropy) where it did not, so nothing before a row tells whether it changes: the entropy enters
    the loss only where the bin changed, so Z5 predicts 1 there (an unweighted fit would predict the mean, 0.5)."""
    from tcn.metody import Z5
    norm = normalizer(("mem_changed_ratio",))
    rng = np.random.default_rng(5)
    sessions = []
    for seed in (1, 2):
        local = np.zeros((300, 1, 4))
        local[:, 0, 3] = rng.integers(0, 2, 300)
        local[:, 0, 2] = local[:, 0, 3]
        sessions.append((noise(seed, 300, 1), local))
    train = window_set([g for g, _ in sessions], norm, bins=[local for _, local in sessions])
    z5 = Z5()
    z5.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)
    bins = z5.coefficients[1]
    assert bins[0, 2] == pytest.approx(1.0, abs=1e-3) and np.abs(bins[1:, 2]).max() < 1e-3


@pytest.mark.parametrize("variant, alarms", [("load", [152]), ("residual", [252])])
def test_z4_on_a_load_jump(variant, alarms):
    """The features follow the offered load (x = 0.1 load + noise of 0.01 in train and calibration). In the test role
    (no noise, so that no alarm of the noise can fall in it) the load jumps from 10 to 30 at row 150 and x departs from
    the load by 1 in rows 250 to 269. At the threshold of a budget of 0 the variant load alarms at the jump, the
    variant residual only at the departure."""
    from tcn.metody import Z4
    norm = normalizer(("mem_changed_ratio",))

    def session(seed, load, departure=False):
        x = 0.1 * load + (0 if departure else 0.01) * noise(seed, len(load))
        if departure:
            x[250:270] += 1
        return x[:, None], load

    def uniform(seed):
        return np.random.default_rng(seed).uniform(5, 15, 300)
    parts = [session(s, uniform(s)) for s in (1, 2, 3)]
    train = window_set([x for x, _ in parts], norm, loads=[load for _, load in parts])
    calibration_x, calibration_load = session(4, uniform(4))
    calibration = window_set([calibration_x], norm, role="calibration", loads=[calibration_load])
    test_x, test_load = session(5, np.where(np.arange(300) < 150, 10.0, 30.0), departure=True)
    test = window_set([test_x], norm, role="test_benign", loads=[test_load])
    z4 = Z4(variant)
    z4.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)
    assert z4.label == "Z4:" + variant
    assert edges(z4, test, matched(z4, calibration, 0)) == alarms


def test_z4_needs_the_offered_load():
    from tcn.metody import Z4
    norm = normalizer(("mem_changed_ratio",))
    train = window_set([noise(1, 100, 1)], norm)
    with pytest.raises(ValueError, match=r"^Z4 needs the offered load of every row; the window set of train has "
                                         r"none$"):
        Z4("load").fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)


def test_z0_never_alarms_and_its_random_variant_meets_the_rate():
    """Z0 has no alarm at its matched threshold on any role. Its random variant (200 repetitions of the stream
    z0_alarms): every repetition has at most the budget of 4 alarms on the clean windows of calibration (the matched
    rate), 4 in most; on a role five times as long its mean rate per hour lies between the budget's rate and 6/4 of it
    (judgment: the walk stops just before a fifth alarm, so for scores without structure the expected rate of the
    threshold is about 5/4 of the budget's; skeleton section 3 lets the bound of G1 absorb that)."""
    from tcn.metody import Z0, rate, z0_random
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([noise(s, 600, 1) for s in (1, 2)], norm, role="calibration")
    role = window_set([noise(s, 3000, 1) for s in (3, 4)], norm, role="test_benign")
    z0 = Z0()
    z0.fit(as_role(calibration, "train"), as_role(calibration, "dev"), protocol=protocol(), seed=0)
    assert rate(z0.scores(role), role, matched(z0, calibration, 4), k=K, n=N, traffic=quiet(role))["alarms"] == 0
    result = z0_random(calibration, 4, protocol=protocol(), mode="campaign", k=K, n=N, traffic=quiet(calibration),
                       roles={"test_benign": (role, quiet(role))})
    assert result["repetitions"] == 200 and len(result["roles"]["calibration"]["alarms"]) == 200
    on_calibration, on_role = result["roles"]["calibration"], result["roles"]["test_benign"]
    # judgment: the count at a threshold is the budget unless the step after it adds two alarms at once, so the mean
    # is at most half an alarm short.
    assert max(on_calibration["alarms"]) == 4 and on_calibration["mean_alarms"] >= 3.5
    budget_rate = 4 / on_calibration["hours"]
    assert budget_rate <= on_role["mean_per_hour"] <= 1.5 * budget_rate


# ------------------------------------------------------------------ the matched rate (design 1.2)


def scored(values):
    """A window set of one session whose windows are as many as `values`, in one run (no reset)."""
    norm = normalizer(("mem_changed_ratio",))
    return (window_set([np.zeros((len(values) + WINDOW - 1, 1))], norm, role="calibration"),
            np.asarray(values, dtype=float))


@pytest.mark.parametrize("values, budget, expected", [
    # The walk from the top passes two isolated scores (9 and 8 alone raise no 3 of 5) and stops at 0, where windows
    # 0, 4, 8, 9 and 10 exceed and raise one alarm: budget 0 gives 2, the most sensitive threshold without an alarm.
    ([9, 0, 0, 0, 8, 0, 0, 0, 2, 2, 2, 0, 0], 0,
     {"threshold": 2.0, "alarms": 0, "walked": 4, "first_excess": {"threshold": 0.0, "alarms": 1}, "exhausted": False}),
    ([9, 0, 0, 0, 8, 0, 0, 0, 2, 2, 2, 0, 0], 1,
     {"threshold": 0.0, "alarms": 1, "walked": 4, "first_excess": None, "exhausted": True}),
    # Not monotonic: 0, 2 and 1 alarms at the thresholds 5, 2 and 0 (two alarms merge into one). The walk stops at the
    # first excess, though the lower threshold 0 has 1 alarm.
    ([5, 5, 5, 2, 2, 2, 5, 5, 5, 0, 0, 0, 0, 0], 1,
     {"threshold": 5.0, "alarms": 0, "walked": 2, "first_excess": {"threshold": 2.0, "alarms": 2}, "exhausted": False}),
])
def test_the_threshold_walks_from_the_top(values, budget, expected):
    from tcn.metody import THRESHOLD_RULE, alarm_count, matched_threshold
    windows, scores = scored(values)
    result = matched_threshold(scores, windows, budget, k=K, n=N, clean=everywhere(windows))
    assert result == dict(expected, budget=budget, rule=THRESHOLD_RULE)
    assert alarm_count(scores, windows, result["threshold"], k=K, n=N, clean=everywhere(windows)) == result["alarms"]


def test_the_count_is_not_monotonic_in_the_threshold():
    from tcn.metody import alarm_count
    windows, scores = scored([5, 5, 5, 2, 2, 2, 5, 5, 5, 0, 0, 0, 0, 0])
    assert [alarm_count(scores, windows, t, k=K, n=N, clean=everywhere(windows)) for t in (5, 2, 0)] == [0, 2, 1]


def test_the_budget_counts_clean_traffic_only():
    """Two alarms at the threshold 1, the second in an event (rows 195 to 205): on the clean windows one is left, and
    so the budget of a seed with these scores is 1, not 2."""
    from tcn.metody import alarm_count, budget, clean_windows
    windows, scores = scored(np.zeros(300))
    scores[(windows.seq >= 60) & (windows.seq < 65)] = 5
    scores[(windows.seq >= 200) & (windows.seq < 205)] = 5
    event = {"host_start_unix": 1000 + 5 * 195., "host_stopped_unix": 1000 + 5 * 205.}
    clean = clean_windows(windows, {"session-0": [event]}, protocol(("analysis.reverberation_s", 0)))
    assert alarm_count(scores, windows, 1, k=K, n=N, clean=everywhere(windows)) == 2
    assert alarm_count(scores, windows, 1, k=K, n=N, clean=clean) == 1
    assert budget([alarm_count(scores, windows, 1, k=K, n=N, clean=clean)]) == 1


@pytest.mark.parametrize("counts, expected", [
    ([2, 0, 5, 1, 2], 2), ([1, 2, 3, 4], 3),
    # Package B7b (F5 of the verification of B7a, mutant M01): the median 0, where the mean (4) would give 4.
    ([0, 0, 0, 10, 10], 0),
])
def test_the_budget_is_the_median_over_the_seeds_rounded_up(counts, expected):
    from tcn.metody import budget
    assert budget(counts) == expected


@pytest.mark.parametrize("end, anchored, clean, placeable", [
    # Package B7b (F1 of the verification of B7a, question Q12, provisional): the band of the full snapshot at row 50,
    # 60 s before it to 8 rows after, [t(38), t(58)), is no part of clean traffic; it bounds only the placeable windows.
    (37, False, True, True), (38, False, True, False), (49, False, True, False),
    (58, False, True, False), (64, False, True, False), (65, False, True, True),
    # The event 100-110 with 20 s of reverberation: neither clean nor placeable.
    (99, False, True, True), (100, False, False, False), (121, False, False, False), (122, False, True, True),
    (122, True, False, False), (123, True, True, True),  # Anchored: the anchor of the window ending at 122 is row 114.
])
def test_clean_windows(end, anchored, clean, placeable):
    """CLEAN_RULE and PLACEABLE_RULE on one session of 200 rows (window 8, 5 s apart) with a full snapshot at row 50
    (no window holds it) and an event from row 100 to row 110 with a reverberation of 20 s (rows up to 114)."""
    from tcn.metody import clean_windows, placeable_windows
    norm = normalizer(("mem_changed_ratio", "proc_total"), differenced=("proc_total",) if anchored else ())
    windows = window_set([np.zeros((200, 2))], norm, barriers=(50,), full=[50])
    event = {"host_start_unix": 1000 + 5 * 100., "host_stopped_unix": 1000 + 5 * 110.}
    p = protocol(("analysis.reverberation_s", 20))
    mask = clean_windows(windows, {"session-0": [event]}, p)
    assert mask[list(windows.seq).index(end)] == clean
    assert placeable_windows(windows, {"session-0": [event]}, p)[list(windows.seq).index(end)] == placeable


def test_clean_windows_need_the_events_of_every_session():
    from tcn.metody import clean_windows
    windows, _ = scored(np.zeros(20))
    with pytest.raises(ValueError, match=r"^events maps the id of every session of the window set, and no other, to "
                                         r"its event records \(\[\] for a session without events\)$"):
        clean_windows(windows, {}, protocol())


# ------------------------------------------------------------------ the alarm rule, M and its windows (frames)


LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 4096], [1, 4096], [2, 64]],
          "regions": [{"gpa": 0, "bytes": 33554432}, {"gpa": 33554432, "bytes": 262144}],
          "memsize": 33816576, "vcpus": 2}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "inconclusive": ["text_integrity"],
        "findings": [], "read_errors": 0, "filled_zero": 0}
BAD = dict(GOOD, model_valid=False, behavior_valid=False)


def frames(name, *, seed, rows=60, full=(0, 30), invalid=(45,)):
    """The frames of one synthetic session (as safeguard/tests/test_channels.py session()): a full snapshot and a new
    chain at each row of `full`, an invalid row at each of `invalid`; memory columns and counts as noise."""
    rng = np.random.default_rng(seed)
    out = []
    for seq in range(rows):
        vector = np.zeros(len(MENA))
        vector[:8] = rng.uniform(.1, .3, 8)
        vector[8:20] = rng.integers(20, 40, 12)
        vector[MENA.index("ma_predchodcu")], vector[MENA.index("je_plna")] = seq != 0, seq in full
        local = np.ones((3, 4))
        local[:, 0] = rng.uniform(.1, .6, 3)
        local[:, 1] = rng.uniform(.1, .3, 3)
        local[:, 2] = rng.uniform(2, 5, 3)
        chain = f"{name}-chain-{max(f for f in full if f <= seq)}"
        out.append(Frame(name, seq, 1000. + 5 * seq, vector, local, (0, 1, 2), dict(BAD if seq in invalid else GOOD),
                         chain, LAYOUT))
    return out


SESSIONS = {"train": [frames("train-1", seed=1), frames("train-2", seed=2)],
            "calibration": [frames("calibration-1", seed=3), frames("calibration-2", seed=4, rows=40, invalid=())]}


def rule():
    """The rule of the v5 file with proc_total differenced (anchored windows) and mod_total in the rule channel."""
    from safeguard.features import NormalizationRule
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    doc["analysis"]["columns"] = dict(dict.fromkeys(GLOBAL_NAMES, "neural"), proc_total="differenced",
                                      mod_total="rule")
    return NormalizationRule.from_protocol(doc, diagnostic=False)


def fitted():
    from safeguard.features import FeatureNormalizer, feature_contract
    normalization = rule()
    norm = FeatureNormalizer.fit([f for session in SESSIONS["train"] for f in session if f.measured], normalization)
    return norm, feature_contract(SESSIONS["train"][0][0], WINDOW, GAP)


def records(role):
    return [({"id": session[0].session, "scenario": "steady"}, session) for session in SESSIONS[role]]


class Oracle:
    """A score oracle for safeguard.runtime.Detector (as safeguard/tests/test_runtime.py FakeBundle): the score of a
    window is given by its last row."""
    manifest = {"calibration": {"diagnostic": True}}

    def __init__(self, contract, threshold, scores):
        self.contract, self.threshold, self.k, self.n, self.anchored = contract, threshold, K, N, True
        self.scores = scores

    @property
    def rule_channel(self):
        return {"columns": [], "quantity": {}, "ranges": {}, "k": self.k, "n": self.n}

    def score(self, window):
        return {"score": self.scores[(window[-1].session, window[-1].seq)]}


def test_the_alarm_rule_is_that_of_the_runtime_and_of_calibrate():
    """Random scores on the anchored windows of two sessions with full snapshots, an invalid row and a session change:
    the alarms of alarm_count over every window equal the alarm_events of safeguard.training.calibrate and the rising
    edges of model_anomaly of safeguard.runtime.Detector, at calibrate's threshold; the windows are the Detector's."""
    from safeguard.runtime import Detector
    from safeguard.training import Windows, calibrate
    from tcn.metody import Okna, alarm_count, alarm_edges
    norm, contract = fitted()
    windows = Okna.from_sessions(records("calibration"), norm, contract, role="calibration", interval_s=INTERVAL)
    scores = np.random.default_rng(0).uniform(size=len(windows))
    result = calibrate(scores, Windows(records("calibration"), norm, contract, ["steady"]), fpr=0.3, k=K, n=N,
                       interval_s=INTERVAL, diagnostic=True)
    oracle = Oracle(contract, result["threshold"], dict(zip(zip(windows.session, windows.seq), scores)))
    detector = Detector(oracle, preserve=False)
    rows = [detector.process(frame) for session in SESSIONS["calibration"] for frame in session]
    assert [(r["session"], r["seq"]) for r in rows if r["score"] is not None] == list(zip(windows.session,
                                                                                          windows.seq))
    count = alarm_count(scores, windows, result["threshold"], k=K, n=N, clean=everywhere(windows))
    assert count == result["alarm_events"] > 1
    edges = alarm_edges(scores, windows, result["threshold"], k=K, n=N)
    assert list(zip(windows.session[edges], windows.seq[edges])) == [
        (r["session"], r["seq"]) for r in rows if "model_anomaly" in r["alarm_sources"]]


def test_an_alarm_needs_n_windows_after_a_reset():
    """Every window exceeds: the run of three windows before a barrier (row 10) raises no alarm, since 3 of 5 needs
    five windows after the reset (calibrate's len(history) == n, the runtime's), and the run after it raises one at its
    fifth window."""
    from tcn.metody import alarm_edges
    windows = window_set([np.zeros((31, 1))], normalizer(("mem_changed_ratio",)), barriers=(10,))
    assert windows.seq.tolist() == [7, 8, 9, *range(18, 31)]
    assert windows.seq[alarm_edges(np.ones(len(windows)), windows, 0, k=K, n=N)].tolist() == [22]


def bundle(seed):
    """A bundle in memory (as safeguard/tests/test_channels.py bundle()): the normalizer of train, an untrained TCN of
    `seed`, the threshold calibrated on calibration at fpr 0.2 (diagnostic) and alarm rule 3 of 5."""
    from safeguard.bundle import Bundle
    from safeguard.features import rule_channel
    from safeguard.model import Classifier, Predictor, architecture
    from safeguard.training import Windows, _scores, calibrate
    norm, contract = fitted()
    torch.manual_seed(seed)
    config = architecture(WINDOW, global_features=len(norm.input_names))
    sessions = {role: [(None, s) for s in SESSIONS[role]] for role in ("train", "calibration")}
    predictor = Predictor(config).eval()
    dataset = Windows(records("calibration"), norm, contract, ["steady"])
    calibration = calibrate(_scores(predictor, dataset, 64), dataset, fpr=0.2, k=K, n=N, interval_s=INTERVAL,
                            diagnostic=True)
    manifest = {"feature_contract": contract, "classes": ["steady", "busy"], "calibration": calibration,
                "rule_channel": rule_channel(sessions, norm.rule.classes, k=K, n=N), "training": {"seed": seed}}
    return Bundle(manifest, predictor, Classifier(config, 2).eval(), norm)


def test_m_scores_and_losses_are_those_of_its_bundle():
    """MetodaM on the window set of its bundle: the windows are those of the bundle's WindowBuffer (anchored: the last
    row and the anchor), the score of every window is Bundle.score's and the loss 0.5 global_error + 0.5 the mean of
    bin_errors (LOSS_FORMULA; the tolerance of tcn/porovnanie.py's and safeguard/training.py's same check, float32);
    the budget takes each seed at its own threshold on the clean windows given."""
    from tcn.metody import MetodaM, Okna, alarm_count, model_budget
    models = [bundle(0), bundle(1)]
    windows = Okna.from_sessions(records("calibration"), models[0].normalizer, models[0].contract,
                                 role="calibration", interval_s=INTERVAL)
    expected = []
    for session in SESSIONS["calibration"]:
        buffer = models[0].window_buffer()
        expected += [window for window in map(buffer.push, session) if window is not None]
    assert len(expected[0]) == WINDOW + 1  # The anchor and the rows.
    assert [(w[-1].session, w[-1].seq, w[0].timestamp) for w in expected] == list(zip(
        windows.session, windows.seq, windows.start))
    m = MetodaM(models[0])
    scores, losses = m.scores(windows), m.losses(windows)
    for i, window in enumerate(expected):
        reference = models[0].score(window)
        assert scores[i] == pytest.approx(reference["score"], rel=1e-5, abs=1e-6)
        assert losses[i] == pytest.approx(0.5 * reference["global_error"] + 0.5 * np.mean(reference["bin_errors"]),
                                          rel=1e-5, abs=1e-6)
    clean = np.arange(len(windows)) >= len(windows) // 3
    result = model_budget([MetodaM(b) for b in models], windows, clean, protocol=protocol(("analysis.seeds", [0, 1])))
    counts = [alarm_count(MetodaM(b).scores(windows), windows, b.threshold, k=K, n=N, clean=clean) for b in models]
    assert [(r["seed"], r["threshold"], r["alarms"]) for r in result["seeds"]] == [
        (0, models[0].threshold, counts[0]), (1, models[1].threshold, counts[1])]
    assert models[0].threshold != models[1].threshold and result["budget"] == int(np.ceil(np.median(counts)))


def test_the_window_set_reads_as_safeguard_windows():
    """Code written against safeguard.training.Windows (tcn/opisne.py, safeguard.training _scores and _fit) reads a
    window set as it reads Windows: the same indices, and in any order the same float32 batches of the rows after the
    anchor; so the scores of _scores over it are M's."""
    from safeguard.training import Windows, _scores
    from tcn.metody import MetodaM, Okna
    model = bundle(0)
    windows = Okna.from_sessions(records("calibration"), model.normalizer, model.contract, role="calibration",
                                 interval_s=INTERVAL)
    reference = Windows(records("calibration"), model.normalizer, model.contract, ["steady"])
    assert windows.indices == reference.indices
    order = np.random.default_rng(0).permutation(len(windows))
    for mine, theirs in zip(windows.batches(7, order), reference.batches(7, order)):
        assert all(torch.equal(a, b) for a, b in zip(mine[:2], theirs[:2])) and len(mine[2]) == len(theirs[2])
    assert _scores(model.predictor, windows, 16) == pytest.approx(list(MetodaM(model).scores(windows)), rel=1e-5,
                                                                  abs=1e-6)


class Stub:
    """A method of the interface that does not subclass Metoda (as tcn/opisne.py's): its score is the input."""
    name, kind = "zscore", "detector"

    def scores(self, windows):
        return np.concatenate([windows.rows(g)[:, -1, 0] for _, g, _ in windows.arrays(bins=False)])


@pytest.mark.parametrize("method, reason", [
    (Stub(), None),
    (object(), r"^the matched rate takes a fitted method of the interface of tcn\.metody\.Metoda \(name, kind, "
               r"scores\)$"),
])
def test_the_matched_rate_takes_any_method_of_the_interface(method, reason):
    from tcn.metody import matched_rate
    norm = normalizer(("mem_changed_ratio",))
    calibration = window_set([noise(1, 60, 1)], norm, role="calibration")
    if reason is not None:
        with pytest.raises(ValueError, match=reason):
            matched_rate(method, calibration, quiet(calibration), 0, k=K, n=N, roles={})
        return
    result = matched_rate(method, calibration, quiet(calibration), 0, k=K, n=N, roles={})
    assert (result["label"], result["kind"], result["alarms"], list(result["rates"])) == (
        "zscore", "detector", 0, ["calibration"])


def test_the_threshold_comes_from_calibration():
    from tcn.metody import matched_threshold
    norm = normalizer(("mem_changed_ratio",))
    dev = window_set([noise(1, 40, 1)], norm, role="dev")
    with pytest.raises(ValueError, match=r"^the budget and the matched threshold come from role calibration, not "
                                         r"dev$"):
        matched_threshold(np.zeros(len(dev)), dev, 0, k=K, n=N, clean=everywhere(dev))


def test_k1_takes_the_losses_of_the_wrapper():
    """Agent K's tcn/tvrdenia.hodnoty_k1 takes, aligned on one window set of the wrapper, the losses of M at every
    seed of analysis.seeds (MetodaM), those of Z3 and Z5, the group of each window's session as its boot and the clean
    mask (every window here), and gives I = 1 - (the median over the seeds of M's mean loss) / (Z's mean loss) of
    each boot (merge of B7a). Z3 and Z5 are selected on train itself here (synthetic, test only)."""
    from tcn import tvrdenia
    from tcn.metody import MetodaM, Okna, Z3, Z5
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    seeds = doc["analysis"]["seeds"]
    models = {seed: MetodaM(bundle(seed)) for seed in seeds}
    norm, contract = models[0].bundle.normalizer, models[0].bundle.contract
    train = Okna.from_sessions(records("train"), norm, contract, role="train", interval_s=INTERVAL)
    windows = Okna.from_sessions(records("calibration"), norm, contract, role="calibration", interval_s=INTERVAL)
    methods = {"Z3": Z3(), "Z5": Z5()}
    for method in methods.values():
        method.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)
    boots = {"calibration-1": "group-1", "calibration-2": "group-2"}
    losses = {seed: m.losses(windows) for seed, m in models.items()}
    result = tvrdenia.hodnoty_k1(doc, losses, {name: m.losses(windows) for name, m in methods.items()},
                                 [boots[s] for s in windows.session], everywhere(windows))
    assert result["boots"] == ["group-1", "group-2"] and set(result["methods"]) == {"Z3", "Z5"}
    for name, method in methods.items():
        for boot, session in (("group-1", "calibration-1"), ("group-2", "calibration-2")):
            mine = windows.session == session
            median = np.median([losses[seed][mine].mean() for seed in seeds])
            assert result["methods"][name]["values"][boot] == pytest.approx(
                1 - median / method.losses(windows)[mine].mean())


def test_a_method_refuses_the_windows_of_another_normalizer():
    from tcn.metody import MetodaM, Okna
    m = MetodaM(bundle(0))
    other = window_set([noise(1, 40, 1)], normalizer(("mem_changed_ratio",)))
    assert isinstance(other, Okna)
    with pytest.raises(ValueError, match=r"^the window set is not of the bundle M's normalizer and window$"):
        m.scores(other)


# ------------------------------------------------------------------ the interface and the protocol keys


def methods():
    from tcn.metody import Z0, Z0Random, Z1, Z2, Z3, Z4, Z5
    return [Z0(), Z0Random(3, mode="rehearsal"), Z1(lambda candidate, dev: 0.0), Z2(), Z3(), Z4("load"),
            Z4("residual"), Z5()]


@pytest.mark.parametrize("index", range(8))
def test_every_method_keeps_the_interface(index):
    """name, kind and label; fit returns a JSON record of its choice; one finite score per window; a predictor gives
    a loss per window and a detector None; an unfitted method refuses to score."""
    from tcn.metody import KINDS
    method = methods()[index]
    norm = normalizer(("mem_changed_ratio", "mem_changed_max", "proc_total"))
    rng = np.random.default_rng(index)
    values = [np.stack((noise(s, 120), noise(s + 9, 120), rng.integers(3, 6, 120)), axis=1) for s in (1, 2)]
    loads = [rng.uniform(5, 15, 120) for _ in values]
    train, dev = window_set(values, norm, loads=loads), window_set(values[:1], norm, role="dev", loads=loads[:1])
    with pytest.raises(ValueError, match=r" is not fitted$"):
        method.scores(dev)
    record = method.fit(train, dev, protocol=protocol(), seed=0)
    json.dumps(record, allow_nan=False)
    assert method.name in ("Z0", "Z1", "Z2", "Z3", "Z4", "Z5") and method.kind in KINDS
    assert (record["name"], record["kind"], type(record["why"]), "chosen" in record) == (
        method.name, method.kind, str, True)
    scores = method.scores(dev)
    assert scores.shape == (len(dev),) and np.isfinite(scores).all()
    losses = method.losses(dev)
    assert (losses is None) == (method.kind == "detector")
    if losses is not None:
        assert losses.shape == (len(dev),) and np.isfinite(losses).all()


@pytest.mark.parametrize("call, changes, reason", [
    ("grid", [("analysis.methods.Z1.grid.moving_average_rows", [0])],
     r"^analysis\.methods\.Z1\.grid\.moving_average_rows must be a non-empty list of distinct integers of at least 1 "
     r"and at most window_rows$"),
    ("grid", [("analysis.methods.Z5.grid", {"alpha": [1.0]})],
     r"^analysis\.methods\.Z5\.grid must be an object of exactly the keys ridge_alpha$"),
    ("grid", [("analysis.methods.Z3.grid", {"ewma_coefficient": [0.3]})],
     r"^analysis\.methods\.Z3\.grid must be an object of exactly the keys ewma_alpha$"),
    ("z0_repetitions", [("analysis.matched_rate", DELETE)],
     r"^protocol key analysis\.matched_rate\.z0_repetitions is missing \(design B7a 1\.6\)$"),
    ("stream_seed", [("streams.purposes", ["traffic"])],
     r"^streams\.purposes has no z0_alarms: the stream of design B7a 1\.6 \(agent K adds it\)$"),
    ("stream_seed", [("roles", {"train": 12})],
     r"^the unit of the stream z0_alarms is a role of the protocol, not 'calibration'$"),
])
def test_the_protocol_keys_are_refused_by_name(call, changes, reason):
    from tcn import metody
    function = {"grid": lambda p: (metody.grid(p, "Z1"), metody.grid(p, "Z3"), metody.grid(p, "Z5")),
                "z0_repetitions": metody.z0_repetitions,
                "stream_seed": lambda p: metody.stream_seed(p, "z0_alarms", "calibration", mode="campaign")}[call]
    function(protocol())  # The good input.
    with pytest.raises(ValueError, match=reason):
        function(protocol(*changes))


@pytest.mark.parametrize("mode, name", [("campaign", "v5-test"), ("rehearsal", "v5-test-generalka")])
def test_the_stream_of_z0_is_drawn_per_role(mode, name):
    """The seed of z0_alarms (STREAM_RULE, streams.rule of package B7a) is scripts/protocol_v5.py seed with the name
    of the plan mode and the role as its unit; repetition 7 of the random variant of Z0 scores the windows of each role
    by the eighth row of numpy.random.default_rng(that seed).random((repetitions, windows)) (Z0_RANDOM_RULE)."""
    from scripts.protocol_v5 import seed
    from tcn.metody import Z0Random, stream_seed
    p = protocol()
    assert stream_seed(p, "z0_alarms", "calibration", mode=mode) == seed(name, "z0_alarms", "calibration", -1, 0)
    norm = normalizer(("mem_changed_ratio",))
    train, dev = window_set([noise(1, 40, 1)], norm), window_set([noise(1, 40, 1)], norm, role="dev")
    z0 = Z0Random(7, mode=mode)
    z0.fit(train, dev, protocol=p, seed=0)
    for windows in (train, dev):
        assert np.array_equal(z0.scores(windows), np.random.default_rng(
            seed(name, "z0_alarms", windows.role, -1, 0)).random((8, len(windows)))[7])
    assert not np.array_equal(z0.scores(train), z0.scores(dev))


# ------------------------------------------------------------------ the merge of B7a (agents K and D)


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_the_stream_seed_is_the_analysis_seed_of_the_protocol(mode):
    """On the real file, stream_seed (which reads the keys alone, so the tests above take synthetic protocols) gives
    the seed of scripts/protocol_v5.py analysis_seed (agent K) for z0_alarms on each of the five roles."""
    from scripts import protocol_v5
    from tcn.metody import stream_seed
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    assert [stream_seed(doc, "z0_alarms", role, mode=mode) for role in protocol_v5.ROLES] == [
        protocol_v5.analysis_seed(doc, "z0_alarms", role, mode=mode) for role in protocol_v5.ROLES]


def test_the_grid_parameters_are_those_of_the_protocol():
    """One constant names the parameters of the grids, scripts/protocol_v5.py GRID_PARAMETERS; this module says what
    each holds (GRID_VALUES) and reads no other."""
    from scripts.protocol_v5 import GRID_PARAMETERS
    from tcn.metody import GRID_VALUES
    assert set(GRID_VALUES) == {name for names in GRID_PARAMETERS.values() for name in names}


@pytest.mark.parametrize("name", ["zscore", "iforest", "gru", "lstm"])
def test_the_descriptive_methods_run_in_the_matched_rate(name):
    """Each descriptive method of tcn/opisne.py (agent D), at its first run of analysis.descriptive_methods of the
    real file, fits on the window sets of this module, gives one score per window and, for a predictor, one loss, and
    gets its threshold and its rates from matched_rate like every method. The stop is shortened for the speed of the
    test only (max_epochs 2, patience 1; judgment)."""
    from tcn import opisne
    from tcn.metody import matched_rate
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    doc["analysis"]["stopping"].update(max_epochs=2, patience_epochs=1)
    norm = normalizer(("mem_changed_ratio", "mem_changed_max"))
    rng = np.random.default_rng(5)

    def role(seeds, role):
        bins = []
        for _ in seeds:
            local = np.zeros((80, 1, 4))
            local[:, 0, 3] = rng.integers(0, 2, 80)
            local[:, 0, 0] = local[:, 0, 3] * rng.uniform(.1, .5, 80)
            bins.append(local)
        return window_set([noise(s, 80, 2) for s in seeds], norm, role=role, bins=bins)
    train, dev, calibration, test = role((1, 2), "train"), role((3,), "dev"), role((4,), "calibration"), role(
        (5,), "test_benign")
    seed = next(s for n, s in opisne.runs(doc) if n == name)
    method = opisne.method(name)
    method.fit(train, dev, protocol=doc, seed=seed)
    result = matched_rate(method, calibration, quiet(calibration), 2, k=K, n=N,
                          roles={"test_benign": (test, quiet(test))})
    # Package B7b (F4 of the verification of B7a): the label of a method that draws from a seed carries it.
    label = name if seed is None else f"{name}:seed {seed}"
    assert (result["label"], result["kind"], result["alarms"] <= 2) == (label, method.kind, True)
    assert set(result["rates"]) == {"calibration", "test_benign"}
    losses = method.losses(test)
    assert (losses is None) == (method.kind == "detector")
    assert losses is None or (losses.shape == (len(test),) and np.isfinite(losses).all())


# ------------------------------------------------------------------ package B7b (agent F): the deferred findings of B7a


def test_a_v5_session_without_events_is_clean_traffic_in_every_scored_window():
    """F1 and F2 of the verification of B7a (question Q12, provisional): a session of the v5 shape of the real file
    (720 rows of 5 s, full snapshots at rows 0 and 360, window 32, full_snapshot_guard.before_s 60) without any event.
    Each of its 656 scored windows is clean traffic (proposal 4.2); the band of the full snapshots leaves 582 of them
    placeable (74 fewer: the 31 windows after each snapshot and the 12 before the second). The observed clean time is
    its 720 rows, one hour; the scored clean time its 656 windows."""
    from tcn.metody import Okna, rate, traffic
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    rows, window, interval = doc["cycles"], doc["window_rows"], doc["interval_s"]
    full = [p for p in range(rows) if p % doc["full_every"] == 0]
    session = {"id": "s", "global": np.zeros((rows, 1)), "local": np.zeros((rows, 1, 4)), "seq": np.arange(rows),
               "timestamp": 1000. + interval * np.arange(rows), "full_times": [1000. + interval * p for p in full],
               "load": None}
    windows = Okna([session], [(0, end, None) for end in range(window - 1, rows)
                               if not any(end - window + 1 <= f <= end for f in full)],
                   role="calibration", normalizer=normalizer(("mem_changed_ratio",)), window_rows=window,
                   max_gap_s=doc["max_gap_s"], interval_s=interval)
    t = traffic(windows, {"s": []}, doc)
    assert (full, len(windows), int(t.clean.sum()), int(t.placeable.sum())) == ([0, 360], 656, 656, 582)
    result = rate(np.zeros(len(windows)), windows, 0.0, k=3, n=5, traffic=t)
    assert (result["rows"], result["windows"], result["hours"]) == (720, 656, 1.0)
    assert (result["scored_hours"], result["scored_share"]) == (pytest.approx(656 * 5 / 3600), pytest.approx(656 / 720))


def test_the_rate_is_per_observed_hour_of_clean_traffic():
    """F2 (and the mutant M02) of the verification of B7a: one session of 300 rows (window 8, 5 s apart) with an event
    from row 100 to row 110 and 20 s of reverberation (to row 114). A row is clean when the 8 rows ending at it miss the
    event and its reverberation: rows 0 to 99 and 122 to 299, 278 rows; the clean windows end at rows 7 to 99 and 122 to
    299, 271 of 293. Alarms begin at rows 62 and 202, clean, and 106, in the event: the rate is 2 per 278 rows of 5 s,
    beside it 2 per 271 scored clean windows and the scored share 271 / 278."""
    from tcn.metody import NO_CONTROLS, rate, traffic
    windows, scores = scored(np.zeros(293))
    for first in (60, 104, 200):
        scores[(windows.seq >= first) & (windows.seq < first + 5)] = 5
    event = {"host_start_unix": 1000 + 5 * 100., "host_stopped_unix": 1000 + 5 * 110.}
    t = traffic(windows, {"session-0": [event]}, protocol(("analysis.reverberation_s", 20)))
    assert {key: t.record()[key] for key in ("rows", "clean_rows", "windows", "clean_windows", "placeable_windows",
                                              "events", "controls")} == {
        "rows": 300, "clean_rows": 278, "windows": 293, "clean_windows": 271, "placeable_windows": 271, "events": 1,
        "controls": NO_CONTROLS}
    result = rate(scores, windows, 1.0, k=K, n=N, traffic=t)
    assert (result["alarms"], result["rows"], result["windows"]) == (2, 278, 271)
    assert result["hours"] == pytest.approx(278 * 5 / 3600)
    assert result["per_hour"] == pytest.approx(2 / (278 * 5 / 3600))
    assert result["scored_hours"] == pytest.approx(271 * 5 / 3600)
    assert result["per_scored_hour"] == pytest.approx(2 / (271 * 5 / 3600))
    assert result["scored_share"] == pytest.approx(271 / 278)


CONTROL = {"host_start_unix": 1000 + 5 * 100., "host_stopped_unix": 1000 + 5 * 110.}


@pytest.mark.parametrize("role, controls, reason", [
    ("test_controls", {"session-0": [CONTROL]}, None),
    ("calibration", None, None),
    ("test_controls", None, r"^the sessions of role test_controls hold controls on the VM: give the records of their "
                            r"controls \(controls\.json; \[\] for a session without one\)$"),
    ("test_controls", {}, r"^controls maps the id of every session of the window set, and no other, to its control "
                          r"records \(\[\] for a session without controls\)$"),
    ("test_controls", {"session-0": [{"host_start_unix": 1500.}]},
     r"^a control of session session-0 needs host_start_unix <= host_stopped_unix$"),
], ids=["control", "no_controls_by_rule", "controls_missing", "session_missing", "control_without_stop"])
def test_a_control_is_no_clean_traffic(role, controls, reason):
    """CLEAN_RULE (judgment): a control placed on the VM, from row 100 to row 110 with 20 s of reverberation, leaves the
    clean and the placeable windows as an event does (the windows ending at rows 100 to 121). Only role test_controls
    holds controls, so its traffic needs their records; another role's takes none by the named rule NO_CONTROLS, which
    the record states."""
    from tcn.metody import NO_CONTROLS, traffic
    windows = window_set([np.zeros((200, 1))], normalizer(("mem_changed_ratio",)), role=role)
    p = protocol(("analysis.reverberation_s", 20))
    if reason is not None:
        with pytest.raises(ValueError, match=reason):
            traffic(windows, {"session-0": []}, p, controls=controls)
        return
    t = traffic(windows, {"session-0": []}, p, controls=controls)
    expected = ~((windows.seq >= 100) & (windows.seq <= 121)) if controls else everywhere(windows)
    assert np.array_equal(t.clean, expected) and np.array_equal(t.placeable, expected)
    assert t.record()["controls"] == (1 if controls else NO_CONTROLS)


@pytest.mark.parametrize("which, reason", [
    ("mask", r"^the rate is per observed hour of clean traffic \(RATE_RULE\): it takes the Traffic of the window set "
             r"\(tcn\.metody\.traffic\), not a mask$"),
    ("other", r"^the Traffic is of another window set$"),
], ids=["a_mask", "the_traffic_of_another_set"])
def test_the_rate_takes_the_traffic_of_its_window_set(which, reason):
    """RATE_RULE: the observed time comes with the Traffic of the window set (the good input: the tests above)."""
    from tcn.metody import rate
    windows, scores = scored(np.zeros(20))
    other, _ = scored(np.zeros(20))
    with pytest.raises(ValueError, match=reason):
        rate(scores, windows, 1.0, k=K, n=N, traffic=everywhere(windows) if which == "mask" else quiet(other))


@pytest.mark.parametrize("method, value, reason", [
    ("Z1", {"moving_average_rows": [WINDOW], "cusum_shift": [0, 0.5]}, None),
    ("Z3", {"ewma_alpha": [1.5]}, "analysis.methods.Z3.grid.ewma_alpha must be a non-empty list of distinct numbers in "
                                  "(0, 1]"),
    ("Z3", {"ewma_alpha": ["fast"]}, "analysis.methods.Z3.grid.ewma_alpha must be a non-empty list of distinct numbers "
                                     "in (0, 1]"),
    ("Z5", {"ridge_alpha": [-1.0]}, "analysis.methods.Z5.grid.ridge_alpha must be a non-empty list of distinct "
                                    "positive numbers"),
    ("Z5", {"ridge_alpha": [1, 1.0]}, "analysis.methods.Z5.grid.ridge_alpha must be a non-empty list of distinct "
                                      "positive numbers"),
    ("Z1", {"moving_average_rows": [0], "cusum_shift": [0.5]},
     "analysis.methods.Z1.grid.moving_average_rows must be a non-empty list of distinct integers of at least 1 and at "
     "most window_rows"),
    ("Z1", {"moving_average_rows": [2.5], "cusum_shift": [0.5]},
     "analysis.methods.Z1.grid.moving_average_rows must be a non-empty list of distinct integers of at least 1 and at "
     "most window_rows"),
    ("Z1", {"moving_average_rows": [WINDOW + 1], "cusum_shift": [0.5]},
     "analysis.methods.Z1.grid.moving_average_rows must be a non-empty list of distinct integers of at least 1 and at "
     "most window_rows"),
    ("Z1", {"moving_average_rows": [4], "cusum_shift": [-2]},
     "analysis.methods.Z1.grid.cusum_shift must be a non-empty list of distinct numbers of at least 0 (normalized "
     "units)"),
    # Mutant P5 of the verification of B7b: the lower bounds 0 of ewma_alpha and ridge_alpha are not taken.
    ("Z3", {"ewma_alpha": [1]}, None),
    ("Z3", {"ewma_alpha": [0]}, "analysis.methods.Z3.grid.ewma_alpha must be a non-empty list of distinct numbers in "
                                "(0, 1]"),
    ("Z5", {"ridge_alpha": [0]}, "analysis.methods.Z5.grid.ridge_alpha must be a non-empty list of distinct positive "
                                 "numbers"),
], ids=["bounds_taken", "ewma_above_1", "ewma_a_name", "ridge_negative", "ridge_twice_by_value", "average_of_0",
        "average_not_an_integer", "average_longer_than_the_window", "cusum_negative", "ewma_of_1", "ewma_of_0",
        "ridge_of_0"])
def test_a_grid_is_refused_as_the_protocol_refuses_it(method, value, reason):
    """F3 of the verification of B7a: tcn.metody.grid refuses exactly the grids that scripts/protocol_v5.py
    grid_problem names under the protocol's window_rows (8 here), with its text (GRID_DOMAINS, one constant for both):
    the verifier's probes, a value repeated as 1 and 1.0 and a moving average longer than the window; the bounds of
    the domains (a moving average of the window's 8 rows, a CUSUM shift of 0, an ewma_alpha of 1) are taken, the open
    lower bounds (an ewma_alpha and a ridge_alpha of 0) are not (F5 of the verification of B7b)."""
    from scripts import protocol_v5
    from tcn.metody import grid
    p = protocol((f"analysis.methods.{method}.grid", value))
    assert protocol_v5.grid_problem(method, value, WINDOW) == reason
    if reason is None:
        assert grid(p, method) == value
        return
    with pytest.raises(ValueError) as refused:
        grid(p, method)
    assert str(refused.value) == reason


@pytest.mark.parametrize("roles, reason", [
    (("train", "dev"), None),
    (("train", "test_benign"), "fit takes the window sets of roles train and dev (analysis.selection: never on a test "
                               "role), not train and test_benign"),
    (("test_benign", "test_benign"), "fit takes the window sets of roles train and dev (analysis.selection: never on "
                                     "a test role), not test_benign and test_benign"),
], ids=["roles_of_the_fit", "selected_on_a_test_role", "fitted_on_a_test_role"])
def test_fit_takes_train_and_dev_of_their_roles(roles, reason):
    """F6 of the verification of B7a: Z3 and Z5 were selected on a window set of role test_benign, and Z3 fitted with
    train = dev = test_benign; every fit (Metoda._bind) now refuses window sets of other roles than train and dev and
    writes the roles into its record."""
    from tcn.metody import Z3, Z5
    norm = normalizer(("mem_changed_ratio",))
    train = window_set([walk(1, 200, .1)], norm, role=roles[0])
    dev = window_set([walk(2, 200, .1)], norm, role=roles[1])
    for method in (Z3(), Z5()):
        if reason is None:
            assert method.fit(train, dev, protocol=protocol(), seed=0)["roles"] == {"train": "train", "dev": "dev"}
            continue
        with pytest.raises(ValueError) as refused:
            method.fit(train, dev, protocol=protocol(), seed=0)
        assert str(refused.value) == reason


@pytest.mark.parametrize("seeds, reason", [
    ((1, 0), None),
    ((0, 0), "the budget takes M at every seed of analysis.seeds [0, 1], each once, not at the seeds [0, 0]"),
    ((0,), "the budget takes M at every seed of analysis.seeds [0, 1], each once, not at the seeds [0]"),
], ids=["every_seed", "one_seed_twice", "a_seed_missing"])
def test_the_budget_takes_m_at_exactly_the_seeds_of_the_analysis(seeds, reason):
    """F6 of the verification of B7a: model_budget took one seed twice and a part of analysis.seeds (here [0, 1]); it
    takes M at exactly its seeds, each once, in any order."""
    from tcn.metody import MetodaM, Okna, model_budget
    bundles = {seed: bundle(seed) for seed in set(seeds)}
    windows = Okna.from_sessions(records("calibration"), bundles[0].normalizer, bundles[0].contract,
                                 role="calibration", interval_s=INTERVAL)
    models = [MetodaM(bundles[seed]) for seed in seeds]
    p = protocol(("analysis.seeds", [0, 1]))
    if reason is None:
        result = model_budget(models, windows, quiet(windows), protocol=p)
        assert [row["seed"] for row in result["seeds"]] == [1, 0]
        return
    with pytest.raises(ValueError) as refused:
        model_budget(models, windows, everywhere(windows), protocol=p)
    assert str(refused.value) == reason


def test_z5_keeps_its_intercept_out_of_the_penalty():
    """F5 of the verification of B7a, mutant M03: the global input is 3 plus noise of 0.01; at the strength 1e6 every
    coefficient of the rows before the last is about 0 and the intercept, which is not penalized, is the mean 3 (a
    penalized one would shrink to about 0 too and predict 0)."""
    from tcn.metody import Z5
    norm = normalizer(("mem_changed_ratio",))
    train = window_set([3 + 0.01 * noise(1, 300, 1)], norm)
    z5 = Z5()
    z5.fit(train, as_role(train, "dev"), protocol=protocol(("analysis.methods.Z5.grid", {"ridge_alpha": [1e6]})),
           seed=0)
    intercept, rest = z5.coefficients[0][0, 0], z5.coefficients[0][1:, 0]
    assert intercept == pytest.approx(3, abs=0.01) and np.abs(rest).max() < 1e-4


def test_the_walk_takes_the_scores_of_every_calibration_window():
    """F5, mutant M05: the threshold walks the distinct scores of every calibration window, the windows outside clean
    traffic included (the rule k of n runs over every window). Window 3, outside clean traffic, scores 1 and windows 4
    and 5 score 2: at the threshold 2 nothing exceeds, at 1 two windows do (no 3 of 5), at 0 three, and the alarm begins
    at window 5, a clean one. At a budget of 0 the threshold is therefore 1, the score of no clean window; a walk over
    the scores of the clean windows alone would stop at 2."""
    from tcn.metody import matched_threshold
    windows, scores = scored([0, 0, 0, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0])
    result = matched_threshold(scores, windows, 0, k=K, n=N, clean=np.arange(len(windows)) != 3)
    assert (result["threshold"], result["alarms"], result["walked"], result["first_excess"]) == (
        1.0, 0, 3, {"threshold": 0.0, "alarms": 1})


def test_z4_residual_has_the_floor_of_its_spread():
    """F5, mutant M14: an input that is exactly 0.1 times the load in train leaves residuals of 0, so its spread is the
    floor of the column in normalized units (1e-3 here); a departure of 0.01 from the load then scores 10, where a
    spread of 0 would give a score without bound."""
    from tcn.metody import Z4
    norm = normalizer(("mem_changed_ratio",))
    load = np.random.default_rng(1).uniform(5, 15, 300)
    train = window_set([0.1 * load[:, None]], norm, loads=[load])
    z4 = Z4("residual")
    assert z4.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)["spread"] == pytest.approx([1e-3])
    flat = np.full(20, 10.0)
    x = 0.1 * flat[:, None]
    x[-1, 0] += 0.01
    test = window_set([x], norm, role="test_benign", loads=[flat])
    assert z4.scores(test)[-1] == pytest.approx(10.0, rel=1e-6)


def test_z2_takes_the_mode_not_the_median():
    """F5, mutant M16: proc_total is 5, 7 or 8 (four, three and three rows of ten), so over the last rows of the train
    windows its mode is 5 and its median 7: Z2 takes the mode, and a window ending at 5, 7 or 8 scores 0, 2 or 3."""
    from tcn.metody import Z2
    norm = normalizer(("mem_changed_ratio", "proc_total"))
    count = np.tile([5., 5., 5., 5., 7., 7., 7., 8., 8., 8.], 30)
    train = window_set([np.stack((noise(1, 300), count), axis=1)], norm)
    z2 = Z2()
    assert z2.fit(train, as_role(train, "dev"), protocol=protocol(), seed=0)["modes"] == [5.0]
    assert np.median(count[WINDOW - 1:]) == 7.0
    assert sorted(set(z2.scores(train))) == [0.0, 2.0, 3.0]


@pytest.mark.parametrize("index, reason", [
    (1, None),
    (2, r"^the set holds the sessions 0 to 1, not 2$"),
], ids=["a_session", "no_such_session"])
def test_the_session_arrays_are_read_only_views(index, reason):
    """The merge of B7b: Okna.session_arrays (and sessions) is the public accessor of a session's arrays for
    tcn/zasahy.py and tcn/diagnostiky.py: the constructor's layout (SESSION_KEYS), the values of the set, read-only
    views of its own arrays; a window set built from them holds the same windows. UNEVALUATED is one constant."""
    from tcn import diagnostiky, k2
    from tcn.metody import SESSION_KEYS, UNEVALUATED, Okna
    loads = [np.arange(40.), np.arange(40.) + 1]
    windows = window_set([noise(1, 40, 1), noise(2, 40, 1)], normalizer(("mem_changed_ratio",)), loads=loads,
                         full=[0])
    if reason is not None:
        with pytest.raises(ValueError, match=reason):
            windows.session_arrays(index)
        return
    found = windows.session_arrays(index)
    assert list(found) == list(SESSION_KEYS) and found["id"] == "session-1" and found["full_times"] == [1000.]
    assert np.array_equal(found["global"], noise(2, 40, 1)) and np.array_equal(found["load"], loads[1])
    assert np.array_equal(found["timestamp"], 1000. + INTERVAL * np.arange(40))
    for key in ("global", "local", "seq", "timestamp", "load"):
        assert not found[key].flags.writeable
        with pytest.raises(ValueError, match="read-only"):
            found[key][0] = 0
    again = Okna(windows.sessions(), [tuple(int(x) for x in row[:2]) + (None,) for row in windows.index],
                 role=windows.role, normalizer=windows.normalizer, window_rows=WINDOW, max_gap_s=GAP,
                 interval_s=INTERVAL)
    assert np.array_equal(again.seq, windows.seq) and np.array_equal(again.last_load(range(len(again))),
                                                                      windows.last_load(range(len(windows))))
    assert UNEVALUATED == k2.UNEVALUATED == diagnostiky.UNEVALUATED == "nevyhodnotené"
