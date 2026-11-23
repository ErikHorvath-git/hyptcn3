"""The normalization rule, the inputs of the TCN, the rule channel and the attribution of the score (protocol v5,
package B6b, agent N; design dokazy/B6/navrh/NAVRH_B6b.md sections 1.1 to 1.3, 2 and 5, the lead's skeleton
dokazy/B6/kostra/KOSTRA.md sections 2, 4 and 6).

Skeleton section 6: test 1 (the columns of the rule channel are no input of the TCN), test 2 (a one-unit change of a
rule column gives an alarm of the channel rule and none of the channel neural), test 4 (the errors of the columns sum
to the global error, the worst bin is the maximum) and test 5 (a bin under 1024 pages does not change the score, two
bins of different variance get different scales); with them the rule of the protocol (1.1), the first difference
across a barrier and the rows a window needs (section 5), and the refusals of the saved normalizer and bundle.

The bundles here are built in memory from synthetic sessions and an untrained, seeded TCN: mechanics only, no number
is a detection result (HONESTY P4). Names of package B6b are imported inside the tests, so this file collects on the
code before it.
"""
from dataclasses import replace
import json
from pathlib import Path
import re

import numpy as np
import pytest
import torch

from features.snapshot import MENA
from safeguard.features import GLOBAL_NAMES, Frame

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
WINDOW, ROWS, FULL, GAP = 8, 40, (0, 20), 7.5
# Two bins of 4096 pages and one of 64 (the hyptcn-lab layout ends in bins of 1 and 64 pages): under
# analysis.scale.min_bin_pages 1024 the third is neither fitted nor scored.
LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 4096], [1, 4096], [2, 64]],
          "regions": [{"gpa": 0, "bytes": 33554432}, {"gpa": 33554432, "bytes": 262144}],
          "memsize": 33816576, "vcpus": 2}
SMALL = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 64]], "regions": [{"gpa": 0, "bytes": 262144}],
         "memsize": 262144, "vcpus": 2}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "inconclusive": ["text_integrity"],
        "findings": [], "read_errors": 0, "filled_zero": 0}
# The classes of the rule of most tests: one column of each class but neural (sock_listen and proc_total are level
# columns of analysis.qualification).
CLASSES = {"mod_total": "rule", "sock_listen": "rule_differenced", "proc_total": "differenced",
           "proc_kernel": "dropped"}


def column(name):
    return MENA.index(name)


def session(name, *, seed, changes=(), layout=LAYOUT):
    """The frames of one synthetic session of ROWS rows, a full snapshot (and a new chain) at each row of FULL: memory
    columns and counts as noise, mod_total 31 and sock_listen 5 in every row, proc_memfd 5 and 6 in every 25th row;
    the changed ratio of bin 1 has ten times the spread of bin 0. changes: (seq, column, delta) added to a raw
    value, after the same random draws as the session without them."""
    rng = np.random.default_rng(seed)
    bins = len(layout["bins"])
    frames = []
    for seq in range(ROWS):
        vector = np.zeros(len(MENA))
        vector[:8] = rng.uniform(.1, .3, 8)
        vector[8:20] = rng.integers(20, 40, 12)
        vector[column("mod_total")], vector[column("sock_listen")] = 31, 5
        vector[column("proc_memfd")] = 6 if seq % 25 == 3 else 5
        vector[column("ma_predchodcu")], vector[column("je_plna")] = seq != 0, seq in FULL
        for at, name_, delta in changes:
            if at == seq:
                vector[column(name_)] += delta
        local = np.ones((bins, 4))
        local[:, 0] = np.concatenate(([rng.uniform(.19, .21), rng.uniform(.1, .3)], rng.uniform(.4, .6, 3)))[:bins]
        local[:, 1] = rng.uniform(.1, .3, bins)
        local[:, 2] = rng.uniform(2, 5, bins)
        chain = f"{name}-chain-{max(f for f in FULL if f <= seq)}"
        frames.append(Frame(name, seq, 1000. + 5 * seq, vector, local, tuple(b for b, _ in layout["bins"]),
                            dict(GOOD), chain, layout))
    return frames


@pytest.fixture(scope="module", autouse=True)
def _threads():
    """Two torch threads for the scores of this file (as safeguard/tests/test_training.py)."""
    before = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(before)


TRAIN = [session("train-1", seed=1), session("train-2", seed=2)]
CALIBRATION = [session("calibration-1", seed=3)]
TEST = session("test-1", seed=4)


def protocol(columns):
    """config/collection-v5.json with analysis.columns: None (as in the file before G3a) or these classes, every
    other column neural."""
    doc = json.loads(V5.read_text())
    doc["analysis"]["columns"] = None if columns is None else dict(dict.fromkeys(GLOBAL_NAMES, "neural"), **columns)
    return doc


def rule(columns=CLASSES):
    from safeguard.features import NormalizationRule
    return NormalizationRule.from_protocol(protocol(columns), diagnostic=False)


def fit_rows(sessions):
    return [frame for frames in sessions for frame in frames if frame.measured]


def bundle(normalization):
    """A bundle in memory (safeguard/bundle.py Bundle) over TRAIN and CALIBRATION by the rule `normalization`: the
    normalizer fitted on the measured rows of TRAIN, an untrained TCN of seed 0, the rule channel's ranges over TRAIN
    and CALIBRATION and the alarm rule 3 of 5; the threshold 1e9 until a test sets it."""
    from safeguard.bundle import Bundle
    from safeguard.features import FeatureNormalizer, feature_contract, rule_channel
    from safeguard.model import Classifier, Predictor, architecture
    normalizer = FeatureNormalizer.fit(fit_rows(TRAIN), normalization)
    torch.manual_seed(0)
    config = architecture(WINDOW, global_features=len(normalizer.input_names))
    sessions = {"train": [(None, frames) for frames in TRAIN], "calibration": [(None, frames) for frames in CALIBRATION]}
    manifest = {"feature_contract": feature_contract(TRAIN[0][0], WINDOW, GAP), "classes": ["quiet", "busy"],
                "calibration": {"threshold": 1e9, "k": 3, "n": 5, "diagnostic": True},
                "rule_channel": rule_channel(sessions, normalization.classes, k=3, n=5)}
    return Bundle(manifest, Predictor(config).eval(), Classifier(config, 2).eval(), normalizer)


def replay(model, frames):
    from safeguard.runtime import Detector
    detector = Detector(model, preserve=False)
    return [detector.process(frame) for frame in frames]


def windows(model, frames):
    buffer = model.window_buffer()
    return [window for window in map(buffer.push, frames) if window is not None]


@pytest.mark.parametrize("doc, diagnostic, expected", [
    ({"schema": "hyptcn3/collection-protocol/2"}, False,
     ("legacy_schema_2", (), 20, "machine_epsilon_to_one", False, None)),
    (protocol(None), True, ("all_neural_diagnostic", (), 20, "at_least_floor", True, 1024)),
    (protocol(CLASSES), False, ("analysis.columns", ("mod_total", "sock_listen"), 17, "at_least_floor", True, 1024)),
    (protocol(None), False, "normalization rule: analysis.columns is null until G3a; production training needs the "
                            "classes of the columns (diagnostic training takes the rule all_neural_diagnostic, every "
                            "column neural)"),
    ({"schema": "hyptcn3/collection-protocol/4"}, True, "normalization rule: protocol schema "
     "'hyptcn3/collection-protocol/4' has none (schemas 1 and 2: legacy_schema_2; schema 3: analysis.columns and "
     "analysis.scale)"),
], ids=["schema_2", "schema_3_before_g3a_diagnostic", "schema_3_columns", "schema_3_before_g3a_production",
        "unknown_schema"])
def test_the_rule_comes_from_the_protocol_and_has_a_name(doc, diagnostic, expected):
    """Design B6b 1.1: schemas 1 and 2 take the named rule legacy_schema_2 (every column neural, one pooled bin scale,
    the machine-epsilon floor, no bin minimum); schema 3 the classes of analysis.columns and the scale rule of
    analysis.scale; while analysis.columns is null a production call is refused by name and a diagnostic one takes
    the named rule all_neural_diagnostic; another schema is refused. Never a silent default."""
    from safeguard.features import NormalizationRule
    if type(expected) is str:
        with pytest.raises(ValueError, match="^" + re.escape(expected) + "$"):
            NormalizationRule.from_protocol(doc, diagnostic=diagnostic)
        return
    found = NormalizationRule.from_protocol(doc, diagnostic=diagnostic)
    assert (found.name, found.rule_names, len(found.tcn_names), found.floor_policy, found.per_bin,
            found.min_bin_pages) == expected
    assert found.to_dict()["name"] == expected[0]


def test_the_columns_of_the_rule_channel_are_no_input_of_the_tcn():
    """Skeleton section 6 test 1, its part of B6b: the classes features/qualification.py proposes for the synthetic
    corpus of features/tests/test_qualification.py (the constant mod_total and the near-constant sock_listen to the
    rule channel; proc_kernel, mem_changed_ratio and proc_wx dropped; sock_total differenced) as analysis.columns.
    The TCN then takes the 15 other columns, sock_total by its first difference; changing a column of the rule
    channel or a dropped one in every row leaves the TCN's inputs exactly as they were, changing an input does not."""
    from features.qualification import qualify
    from features.tests.test_qualification import corpus
    from safeguard.features import FeatureNormalizer
    from safeguard.model import Predictor, architecture
    rows, sessions = corpus()
    proposed = qualify(rows, sessions, json.loads(V5.read_text()))["proposed_columns"]
    found = rule({name: cls for name, cls in proposed.items() if cls != "neural"})
    out = ("mem_changed_ratio", "proc_kernel", "mod_total", "sock_listen", "proc_wx")
    assert (found.rule_names, found.tcn_names, found.anchored) == (
        ("mod_total", "sock_listen"), tuple(name for name in GLOBAL_NAMES if name not in out), True)
    normalizer = FeatureNormalizer.fit(fit_rows(TRAIN), found)
    assert normalizer.input_names == found.tcn_names and len(found.tcn_names) == 15
    before = normalizer.inputs(TEST)
    for name in out:
        after = normalizer.inputs([replace(f, vector=f.vector + 7 * np.eye(len(MENA))[column(name)]) for f in TEST])
        np.testing.assert_array_equal(after[0], before[0])
        np.testing.assert_array_equal(after[1], before[1])
    changed = normalizer.inputs(session("test-1", seed=4, changes=[(10, "sock_total", 7)]))[0]
    j = found.tcn_names.index("sock_total")
    assert [i for i in range(ROWS) if changed[i, j] != before[0][i, j]] == [10, 11]  # Its first difference.
    predictor = Predictor(architecture(WINDOW, global_features=len(normalizer.input_names)))
    assert predictor.global_tcn.bloky[0].c1.in_channels == 15


@pytest.mark.parametrize("name, changes, exceeded, alarmed", [
    ("mod_total", [(seq, "mod_total", 1) for seq in range(30, 36)], list(range(30, 36)), list(range(32, 38))),
    ("sock_listen", [(seq, "sock_listen", 1) for seq in range(30, ROWS)], list(range(30, ROWS)),
     list(range(32, ROWS))),
    ("sock_listen", [(seq, "sock_listen", 1) for seq in range(ROWS)], [], []),
], ids=["rule_value", "rule_differenced_persistent_step", "rule_differenced_another_constant_level"])
def test_a_one_unit_change_of_a_rule_column_alarms_the_rule_channel_and_never_the_neural_one(name, changes,
                                                                                              exceeded, alarmed):
    """Skeleton section 6 test 2. mod_total (class rule, its range over train and calibration [31, 31]) one unit
    higher in rows 30 to 35: each of them exceeds, the alarm of the channel rule rises at the third (3 of 5, the
    history of the rule channel filled since the full snapshot at row 20) and stays while 3 of the last 5 rows
    exceed, rows 32 to 37. sock_listen is of class rule_differenced, which the rule channel judges by its change since
    the session's first measured row (question Q8 to the lead, its revised proposal; the range of that change over
    train and calibration [0, 0]): one more listening socket from row 30 on stays +1 to the end, so the alarm rises
    at row 32 and stays; a boot whose sock_listen is one higher in every row changes nothing and raises none. In each
    case the neural score of every row is exactly that of the session without the change (the rule columns are no
    input of the TCN): with the threshold at the highest score of that session the neural channel never alarms, and
    no alarm is a model_anomaly."""
    model = bundle(rule())
    clean = [row["score"] for row in replay(model, TEST)]
    model.manifest["calibration"]["threshold"] = max(score for score in clean if score is not None)
    rows = replay(model, session("test-1", seed=4, changes=changes))
    assert [row["score"] for row in rows] == clean
    assert not any(row["model_alarm"] or "model_anomaly" in row["alarm_sources"] for row in rows)
    assert [row["seq"] for row in rows if row["rule"]["exceeded"]] == exceeded
    quantity, value, low = ("value", 32., 31.) if name == "mod_total" else ("since_session_start", 1., 0.)
    assert [row["rule"]["exceeded"] for row in rows if row["rule"]["exceeded"]][:1] == (
        [[{"column": name, "quantity": quantity, "value": value, "range": [low, low]}]] if exceeded else [])
    assert [row["seq"] for row in rows if row["rule_alarm"]] == alarmed
    assert [(row["seq"], row["alarm_sources"]) for row in rows if row["alarm_event"]] == (
        [(alarmed[0], ["rule_anomaly"])] if alarmed else [])
    assert [row["channel"] for row in rows] == [["rule"] if row["seq"] in alarmed else [] for row in rows]


@pytest.mark.parametrize("anchored", [False, True], ids=["legacy_schema_2", "analysis"])
def test_the_errors_of_the_columns_sum_to_the_global_error_and_the_worst_bin_is_the_maximum(anchored):
    """Skeleton section 6 test 4 and design B6b 1.2: Bundle.score keeps its keys and adds attribution. The error of
    each input column is its squared error divided by the number of inputs, so they sum to global_error; the bins are
    the scored bins with their pages, in the order of bin_errors; the worst of them has the largest error, which is
    the bin part of the score; beside it the mean of the three worst. Under legacy_schema_2 every column and every
    bin; under the rule of CLASSES 17 columns, bins 0 and 1, and a window with the measured row before it."""
    from safeguard.features import NormalizationRule
    model = bundle(rule() if anchored else NormalizationRule.legacy())
    window = windows(model, TEST)[-1]
    result = model.score(window)
    attribution = result["attribution"]
    assert len(window) == WINDOW + anchored
    assert set(result) == {"score", "global_error", "bin_errors", "activity", "activity_probabilities",
                           "attribution"}
    assert list(attribution["columns"]) == list(model.normalizer.input_names)
    assert len(attribution["columns"]) == (17 if anchored else 20)
    assert sum(attribution["columns"].values()) == pytest.approx(result["global_error"], rel=1e-6)
    assert [(b["bin"], b["pages"]) for b in attribution["bins"]] == [(0, 4096), (1, 4096)] + (
        [] if anchored else [(2, 64)])
    assert [b["error"] for b in attribution["bins"]] == result["bin_errors"]
    assert attribution["worst_bin"] == max(attribution["bins"], key=lambda b: b["error"])
    assert result["score"] == pytest.approx(.5 * result["global_error"] + .5 * attribution["worst_bin"]["error"],
                                            rel=1e-6)
    assert attribution["top3_bin_mean"] == pytest.approx(np.mean(sorted(result["bin_errors"])[-3:]), rel=1e-6)


def test_a_bin_under_1024_pages_never_changes_the_score_and_each_scored_bin_has_its_scale():
    """Skeleton section 6 test 5 and design B6b 1.1: under analysis.scale (per_bin, min_bin_pages 1024) the bin of 64
    pages is neither fitted nor scored, so any value of it leaves the score and its attribution exactly as they were;
    the changed ratio of bin 1 spreads ten times as much as that of bin 0 and gets its own, larger scale, while the
    pooled scale of legacy_schema_2 is one for every bin. A layout without a bin of 1024 pages is refused."""
    from safeguard.features import FeatureNormalizer, NormalizationRule
    model = bundle(rule())
    normalizer = model.normalizer
    assert (normalizer.bins, normalizer.unscored) == (((0, 4096), (1, 4096)), ((2, 64),))
    window = windows(model, TEST)[0]
    other = [replace(f, perbin=np.vstack((f.perbin[:2], [[.9, 0., 7.5, 1.]]))) for f in window]
    assert model.score(other) == model.score(window)
    assert normalizer.local_scale[1, 0] > 5 * normalizer.local_scale[0, 0]
    pooled = FeatureNormalizer.fit(fit_rows(TRAIN), NormalizationRule.legacy()).local_scale
    assert pooled.shape == (3, 4) and (pooled == pooled[0]).all()
    reason = "no bin of the layout has at least min_bin_pages 1024 pages: rule analysis.columns scores no bin"
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        FeatureNormalizer.fit(fit_rows([session("small", seed=5, layout=SMALL)]), rule())


@pytest.mark.parametrize("anchored, scale", [(False, "deviation"), (True, 1.)], ids=["legacy_schema_2", "analysis"])
def test_the_scale_of_a_count_is_at_least_one_unit(anchored, scale):
    """Design B6b 1.1 (analysis.scale.floor, one unit for counts): proc_memfd is 5, and 6 in every 25th row, so its
    standard deviation over the fit rows is about 0.2; under analysis.scale its scale is the floor 1, under
    legacy_schema_2 the deviation itself (only a scale at or below the machine epsilon is replaced by 1)."""
    from safeguard.features import FeatureNormalizer, NormalizationRule
    normalizer = FeatureNormalizer.fit(fit_rows(TRAIN), rule() if anchored else NormalizationRule.legacy())
    values = np.array([f.vector[column("proc_memfd")] for f in fit_rows(TRAIN)])
    expected = values.std() if scale == "deviation" else scale
    assert values.std() < .3
    assert normalizer.global_scale[normalizer.input_names.index("proc_memfd")] == pytest.approx(expected)


def test_a_differenced_input_needs_the_measured_row_before_the_window_also_across_a_barrier():
    """Design B6b 1.1 and section 5 (the first difference between consecutive measured rows, across an excluded row,
    as features/qualification.py takes it). Full snapshots at rows 0 and 20, window 8: without a differenced input
    the windows end at rows 8 to 19 and 28 to 39. With proc_total differenced a window also needs the measured row
    before its first row: at the session's start window_rows + 1 = 9 measured rows (the windows end at rows 9 to 19),
    after the full snapshot only 8 again, the window ending at row 28 being [row 19, rows 21 to 28]. The input of
    row 21 is proc_total of row 21 minus that of row 19 (two intervals), the first difference of the measured rows.
    The detector scores those rows and says required_rows 9."""
    from safeguard.features import WindowBuffer
    ends = {}
    for anchored in (False, True):
        buffer = WindowBuffer(WINDOW, GAP, anchored=anchored)
        ends[anchored] = [(w[-1].seq, w[0].seq) for w in map(buffer.push, TEST) if w is not None]
    assert [end for end, _ in ends[False]] == [*range(8, 20), *range(28, 40)]
    assert [end for end, _ in ends[True]] == [*range(9, 20), *range(28, 40)]
    assert dict(ends[True])[28] == 19
    model = bundle(rule())
    normalizer, j, c = model.normalizer, model.normalizer.input_names.index("proc_total"), column("proc_total")
    measured = np.array([f.vector[c] for f in TEST if f.measured])  # Rows 1 to 19 and 21 to 39.
    assert TEST[21].vector[c] - TEST[19].vector[c] == np.diff(measured)[18]
    assert normalizer.inputs(TEST)[0][21, j] == pytest.approx(
        (np.diff(measured)[18] - normalizer.global_mean[j]) / normalizer.global_scale[j])
    from safeguard.bundle import window_inputs  # The window Bundle.score takes has the inputs of the session's rows.
    window = next(w for w in windows(model, TEST) if w[-1].seq == 28)
    for a, b in zip(window_inputs(window, model.contract, normalizer), normalizer.inputs(TEST)):
        np.testing.assert_array_equal(a, b[21:29])
    rows = replay(model, TEST)
    assert {row["required_rows"] for row in rows} == {WINDOW + 1}
    assert [row["seq"] for row in rows if row["score"] is not None] == [*range(9, 20), *range(28, 40)]


@pytest.mark.parametrize("change, reason", [
    (lambda w: w[1:], "window length differs from bundle: 8 frames, the bundle takes 9 (the measured row before the "
                      "window and window_rows 8, rule analysis.columns)"),
    (lambda w: [TEST[20], *w[1:]], "the first frame of the window must be a measured row of its session before the "
                                   "window (the anchor of its first differences)"),
], ids=["no_anchor", "anchor_not_measured"])
def test_a_window_without_the_measured_row_before_it_is_refused(change, reason):
    """Design B6b 1.1: under a differenced input Bundle.score takes [anchor, *rows], the anchor the measured row of the
    session before the window (the good input: every window above). The window ending at row 28 without its anchor
    (row 19), or with the full snapshot of row 20 in its place, is refused."""
    model = bundle(rule())
    window = next(w for w in windows(model, TEST) if w[-1].seq == 28)
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        model.score(change(window))


def _scale_of(column_name, value):
    def change(saved):
        saved["global_scale"][saved["input_names"].index(column_name)] = value
    return change


@pytest.mark.parametrize("change, reason", [
    (lambda saved: None, None),
    (lambda saved: saved.update(schema="hyptcn3/safeguard-normalizer/1"),
     "normalizer of schema hyptcn3/safeguard-normalizer/1 (before package B6b: every column and one pooled bin "
     "scale, no normalization rule) is refused; retrain under the rule of the protocol"),
    (lambda saved: saved["input_names"].reverse(),
     "normalizer inputs differ from the columns of class neural or differenced of rule analysis.columns"),
    (_scale_of("proc_user", .5), "normalizer scale below the floor of rule analysis.columns"),
    (lambda saved: saved["bins"].append(saved["unscored_bins"].pop()),
     "normalizer bins differ from rule analysis.columns: at least one scored bin, every bin once, a bin of fewer than "
     "min_bin_pages pages never scored and every other bin scored"),
    (lambda saved: saved["rule"].update(per_bin=False),
     "rule analysis.columns has one pooled scale of the bins; the normalizer's bins differ"),
], ids=["roundtrip", "schema_before_b6b", "inputs", "below_floor", "unscored_bin_scored", "pooled_rule"])
def test_the_saved_normalizer_carries_its_rule_and_refuses_a_mismatch(change, reason):
    """Design B6b 1.1: to_dict and from_dict carry the rule (name, classes, floors, scored bins); the round trip gives
    the same inputs, and a saved normalizer that disagrees with its rule or with this code is refused by name."""
    from safeguard.features import FeatureNormalizer
    normalizer = FeatureNormalizer.fit(fit_rows(TRAIN), rule())
    saved = json.loads(json.dumps(normalizer.to_dict()))
    change(saved)
    if reason is None:
        restored = FeatureNormalizer.from_dict(saved)
        assert restored.rule == normalizer.rule and restored.to_dict() == normalizer.to_dict()
        for a, b in zip(restored.inputs(TEST), normalizer.inputs(TEST)):
            np.testing.assert_array_equal(a, b)
        return
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        FeatureNormalizer.from_dict(saved)


@pytest.mark.parametrize("change, reason", [
    (lambda manifest: None, None),
    (lambda manifest: manifest.pop("rule_channel"),
     "bundle has no rule_channel (package B6b): the ranges of the rule channel over train and calibration"),
    (lambda manifest: manifest["rule_channel"]["columns"].reverse(),
     "rule_channel columns differ from the columns of class rule or rule_differenced of rule analysis.columns"),
    (lambda manifest: manifest["rule_channel"].update(k=2),
     "rule_channel alarm rule differs from the neural channel's k of n (calibration)"),
], ids=["good", "missing", "columns", "k_of_n"])
def test_the_rule_channel_of_a_bundle_follows_its_rule_and_the_neural_alarm_rule(change, reason):
    """Design B6b 1.3 (load_bundle checks it): the rule channel's columns are the columns of class rule and
    rule_differenced, each with the range of its quantity (the value; the change since the session's first measured
    row) over the measured rows of train and calibration, and its alarm is the neural channel's k of n."""
    from safeguard.bundle import check_rule_channel
    model = bundle(rule())
    manifest = json.loads(json.dumps(model.manifest))
    change(manifest)
    if reason is None:
        check_rule_channel(manifest, model.normalizer)
        assert manifest["rule_channel"]["ranges"] == {
            "mod_total": {"quantity": "value", "min": 31., "max": 31., "rows": 3 * 38},
            "sock_listen": {"quantity": "since_session_start", "min": 0., "max": 0., "rows": 3 * 38}}
        return
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        check_rule_channel(manifest, model.normalizer)


def test_a_bundle_of_the_score_formula_before_b6b_is_refused_by_name(tmp_path):
    """Design B6b 1.2: new score and loss formulas (the mean over the inputs of the rule, the scored bins); a bundle
    of the strings before is refused by name before anything else of it is read."""
    from safeguard.bundle import SCHEMA, load_bundle
    from safeguard.model import OLD_LOSS_FORMULA, OLD_SCORE_FORMULA, SCORE_FORMULA
    assert SCORE_FORMULA != OLD_SCORE_FORMULA
    (tmp_path / "manifest.json").write_text(json.dumps({"schema": SCHEMA, "diagnostic": False,
                                                        "score_formula": OLD_SCORE_FORMULA,
                                                        "loss_formula": OLD_LOSS_FORMULA}))
    reason = (f"bundle of the score formula before package B6b ({OLD_SCORE_FORMULA!r}: every column and every bin, "
              "no normalization rule) is refused; retrain it")
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        load_bundle(tmp_path)


def test_a_bundle_trained_under_a_rule_with_every_class_scores_the_anchored_windows(tmp_path, monkeypatch):
    """The merge of agents N and T (design B6b section 1): production training under protocol schema 3, its
    parameters from the analysis plan, on the v5-shaped corpus of features/tests/test_dataset_plan.py with
    analysis.columns holding every class. The manifest names the rule analysis.columns and the scale rule of
    analysis.scale with its scored bins; the TCN takes the 15 columns of the mask, proc_total by its first difference,
    so a window holds the measured row before it. The sensitivity table and the dev verification ran on the windows
    Bundle.score takes (training refuses a table whose window scores otherwise than its batch): the table's window
    is the anchored window of the bundle's own buffer. The rule channel has its four columns with their quantities,
    and the loaded bundle replays a clean session of 96 rows with required_rows 9 and 79 scored rows, one fewer than
    without a differenced input."""
    import features.tests.test_dataset_plan as plan
    from features.archive import load
    from safeguard.bundle import load_bundle
    from safeguard.features import frames_from_archive
    from safeguard.runtime import replay_archive
    from safeguard.training import train_bundle
    every = {"mod_total": "rule", "proc_wx": "rule", "proc_memfd": "rule", "sock_listen": "rule_differenced",
             "proc_total": "differenced", "proc_kernel": "dropped"}
    original = plan.protocol_doc

    def protocol_doc(profile, scenarios=plan.SCENARIOS):
        doc = original(profile, scenarios)  # Its analysis has the parameters of the test (fit_analysis).
        doc["analysis"]["columns"].update(every)
        return doc
    monkeypatch.setattr(plan, "protocol_doc", protocol_doc)
    corpus = plan.make_corpus(tmp_path / "corpus", "campaign")
    index = plan.write_index(corpus, plan.build(corpus), tmp_path / "corpus.json")
    train_bundle(index, tmp_path / "bundle", window_rows=plan.WINDOW, max_gap_s=plan.GAP)
    bundle = load_bundle(tmp_path / "bundle")
    manifest, sessions = bundle.manifest, json.loads(index.read_text())["sessions"]
    tcn = [name for name in GLOBAL_NAMES if name not in ("mod_total", "proc_wx", "proc_memfd", "sock_listen",
                                                         "proc_kernel")]
    assert (manifest["parameters"]["rule"], manifest["normalization"]["rule"], manifest["normalizer"]["rule"]["name"],
            manifest["normalization"]["tcn_columns"], list(bundle.normalizer.input_names)) == (
        "analysis", "analysis.columns", "analysis.columns", tcn, tcn)
    scale = manifest["normalization"]["scale"]
    assert (scale["rule"], scale["per_bin"], scale["min_bin_pages"], scale["bins"], scale["unscored_bins"]) == (
        "analysis.scale", True, 1024, [[0, 4096], [1, 4096], [2, 4096]], [])
    assert (bundle.anchored, bundle.required_rows, manifest["training"]["windows"]) == (
        True, plan.WINDOW + 1, {role: 6 * (plan.WINDOWS - 1) for role in plan.FIT})
    assert {name: spec["quantity"] for name, spec in manifest["rule_channel"]["ranges"].items()} == {
        "mod_total": "value", "sock_listen": "since_session_start", "proc_wx": "value", "proc_memfd": "value"}
    table = manifest["sensitivity"]
    assert [row["name"] for row in table["columns"]] == tcn
    where = table["window"]
    record = next(r for r in sessions if r["id"] == where["session"])
    buffer = bundle.window_buffer()
    window = next(w for w in map(buffer.push, frames_from_archive(load(record["features"]), record["id"]))
                  if w is not None and w[-1].seq == where["last_seq"])
    assert (len(window), window[0].seq, window[1].seq) == (plan.WINDOW + 1, where["anchor_seq"], where["first_seq"])
    assert bundle.score(window)["score"] == table["base_score"]
    test = next(r for r in sessions if r["role"] == "test_benign")
    rows = replay_archive(bundle, test["features"], test["id"])
    assert ({row["required_rows"] for row in rows}, sum(row["score"] is not None for row in rows)) == (
        {plan.WINDOW + 1}, plan.WINDOWS - 1)
