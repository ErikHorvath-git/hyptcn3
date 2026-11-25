"""The pure part of the G1 dry run (tcn/suchy_beh.py) and the claims at a null m of the final command (tcn/finalne.py
M_NULL_RULE, CONTROL_CLAIMS_RULE): package C2 of the G1 preparation.

Synthetic records of the shape tcn.finalne writes, their claims built by the code under test (finalne.undecided_claim)
or by tcn.tvrdenia rozhodni on config/collection-v5.json (read, never written; its bounds m are null, a copy fills
them), so that every interval is the bootstrap of the file's analysis.statistics. The answers are counted by hand in
each test from the numbers it chooses: the per-run values are multiples of 1/64 and 1/128 so that every mean is exact,
and the linear percentile is computed by its formula, h = (n - 1) q (numpy, method linear). The end-to-end run on the
corpus of tcn/tests/test_finalne.py is in that file. Only mechanics on synthetic numbers: no number here is a result
(HONESTY P4).
"""
import copy
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pytest

from scripts import protocol_v5

REPO = Path(__file__).resolve().parents[2]
PROTOCOL = json.loads((REPO / "config" / "collection-v5.json").read_text())
MODE = "campaign"
CLAIMS = protocol_v5.CLAIMS
COMPARE = {claim: protocol_v5.analysis_plan(PROTOCOL)[claim]["compare"] for claim in CLAIMS}
K1_BOOTS = [f"g-test_benign-{i:02d}" for i in range(12)]  # Twelve boots of test_benign, as the plan of the campaign.
K2_BOOTS = [f"g-carrier-{i:02d}" for i in range(16)]  # Sixteen carrier boots (a power of two: exact means of 0.05).
GRIDS = {"Z1": {"moving_average_rows": [2, 4], "cusum_shift": [0.5]}, "Z3": {"ewma_alpha": [0.5]},
         "Z5": {"ridge_alpha": [1.0]}}
COLUMNS = {"mem_changed_ratio": "neural", "proc_wx": "rule"}
VALUES = {"analysis.columns": COLUMNS, **{f"analysis.methods.{z}.grid": grid for z, grid in GRIDS.items()},
          "analysis.horizon_s": 20}
FITS = {"Z1:value": {"name": "Z1", "grid": GRIDS["Z1"], "chosen": {"statistic": "value", "parameter": None}},
        "Z2": {"name": "Z2"}, "Z3:last": {"name": "Z3", "grid": GRIDS["Z3"]},
        "Z4:load": {"name": "Z4"}, "Z4:residual": {"name": "Z4"}, "Z5:ridge(1.0)": {"name": "Z5", "grid": GRIDS["Z5"]}}


def _filled(m):
    """A copy of the protocol with the bounds m filled."""
    out = copy.deepcopy(PROTOCOL)
    for claim, value in m.items():
        out["analysis"][claim]["m"] = value
    return out


def _hand_percentile(values, q=0.95):
    """The linear percentile by its formula: h = (n - 1) q, v[floor h] + (h - floor h) (v[floor h + 1] - v[floor
    h])."""
    v = sorted(values)
    h = (len(v) - 1) * q
    low = math.floor(h)
    return v[low] if low + 1 == len(v) else v[low] + (h - low) * (v[low + 1] - v[low])


def _constant(claim, value):
    """Every method of the claim at `value` on every boot."""
    boots = K1_BOOTS if claim == "k1" else K2_BOOTS
    return {z: dict.fromkeys(boots, value) for z in COMPARE[claim]}


def _record(per_claim, *, m=None, stage="suchy", status="complete", values=VALUES, fits=FITS, extra=None):
    """A record of tcn.finalne of the shape the readers read: per_claim {claim: {method: {boot: value}}, or None for a
    claim nevyhodnotené}; its claims undecided by finalne.undecided_claim at m None, else decided by tcn.tvrdenia
    rozhodni at the bounds m (a copy of the protocol filled)."""
    from tcn import finalne, tvrdenia
    claims, conclusions = {}, {}
    for claim in CLAIMS:
        given = per_claim[claim]
        if given is None:
            claims[claim] = {"claim": claim, "mode": MODE, "outcome": None, "status": finalne.UNEVALUATED,
                             "why": "no class has analysis.interventions.min_evaluable evaluable interventions"}
            conclusions[claim] = {"outcome": None, "status": finalne.UNEVALUATED, "wording": None, "conclusion": None}
            continue
        found = (finalne.undecided_claim(PROTOCOL, claim, given, mode=MODE) if m is None
                 else tvrdenia.rozhodni(_filled(m), claim, given, rezim=MODE))
        claims[claim] = found
        conclusions[claim] = {"outcome": found["outcome"], "status": finalne.EVALUATED, "wording": found["wording"],
                              "conclusion": found["conclusion"]}
    v = {"schema": finalne.SCHEMA, "stage": stage, "status": status, "plan_mode": MODE, "claims": claims,
         "conclusions": conclusions, "corpus": {"protocol_values": values}, "methods": fits,
         "models": [{"seed": 0}, {"seed": 1}], **(extra or {})}
    return {"schema": finalne.SCHEMA, "stage": stage, "values": v}


def _spread(center, d, boots):
    """Half the boots at center - d and half at center + d (mean center, exactly for these multiples)."""
    half = len(boots) // 2
    return {boot: center - d if i < half else center + d for i, boot in enumerate(boots)}


_NULL_RUNS = []


def _null_runs():
    """Twenty null runs counted by hand in test_the_bounds_are_the_95th_percentile_of_the_point_estimates_per_run:
    run r = 1..20; K1 Z3 at r/64 and Z5 at (r + 2)/64, each half its boots 1/256 below and half above; K2a every
    method at r/128 on every boot; K2b Z3 at 0 and Z5 at 0.05 on every boot. Built once, a copy each call."""
    if not _NULL_RUNS:
        runs = {}
        for r in range(1, 21):
            per = {"k1": {"Z3": _spread(r / 64, 1 / 256, K1_BOOTS), "Z5": _spread((r + 2) / 64, 1 / 256, K1_BOOTS)},
                   "k2a": _constant("k2a", r / 128),
                   "k2b": {"Z3": dict.fromkeys(K2_BOOTS, 0.0), "Z5": dict.fromkeys(K2_BOOTS, 0.05)}}
            runs[f"nulovy_{r}"] = _record(per)
        _NULL_RUNS.append(runs)
    return copy.deepcopy(_NULL_RUNS[0])


# ------------------------------------------------------------------ the claims at a null m (tcn/finalne.py)


@pytest.mark.parametrize("claim", CLAIMS)
def test_an_undecided_claim_has_the_values_and_intervals_of_rozhodni_at_any_m(claim):
    """M_NULL_RULE: finalne.undecided_claim writes the values per boot, the mean and the interval of every method that
    tcn.tvrdenia rozhodni writes at any m (the same sorted boots, the same stream bootstrap <claim>/<method>, the
    interval its first draw), with p, the test and the outcome null and the conclusion M_NULL; at each of three m the
    decision of rozhodni is tcn.tvrdenia vysledok of those intervals. The values are given in an order that is not the
    sorted one, and every method has its own (kills: boots unsorted, another stream)."""
    from tcn import finalne, tvrdenia
    boots = K1_BOOTS if claim == "k1" else K2_BOOTS
    rng = np.random.default_rng(7)
    given = {z: {boot: float(x) for boot, x in zip(reversed(boots), rng.normal(0.1 * i, 0.05, len(boots)))}
             for i, z in enumerate(COMPARE[claim])}
    found = finalne.undecided_claim(PROTOCOL, claim, given, mode=MODE)
    assert (found["m"], found["outcome"], found["conclusion"], found["wording"], found["boots"]) == (
        None, None, finalne.M_NULL, None, sorted(boots))
    lows = [item["interval"][0] for item in found["methods"].values()]
    highs = [item["interval"][1] for item in found["methods"].values()]
    for m in (min(lows) - 1.0, min(lows), max(highs) + 1.0):
        decided = tvrdenia.rozhodni(_filled({claim: m}), claim, given, rezim=MODE)
        for z in COMPARE[claim]:
            mine, theirs = found["methods"][z], decided["methods"][z]
            assert (mine["values"], mine["mean"], mine["interval"], mine["stream"]) == (
                theirs["values"], theirs["mean"], theirs["interval"], theirs["stream"])
            assert (mine["p_value"], mine["test"]) == (None, None) and theirs["p_value"] is not None
        assert decided["outcome"] == tvrdenia.vysledok({z: found["methods"][z]["interval"] for z in COMPARE[claim]}, m)
    assert {tvrdenia.vysledok({z: i["interval"] for z, i in found["methods"].items()}, m)
            for m in (min(lows) - 1.0, min(lows), max(highs) + 1.0)} == set(protocol_v5.OUTCOMES)


def test_an_undecided_claim_refuses_a_filled_m_by_name():
    """M_NULL_RULE: a filled bound is rozhodni's."""
    from tcn import finalne
    with pytest.raises(ValueError, match=r"^analysis\.k1\.m is 0\.25: a filled bound is decided by tcn\.tvrdenia "
                                         r"rozhodni \(M_NULL_RULE\)$"):
        finalne.undecided_claim(_filled({"k1": 0.25}), "k1", _constant("k1", 0.0), mode=MODE)


@pytest.mark.parametrize("stage, mode, null, reason", [
    ("final", "campaign", ("k1", "k2a", "k2b"), "of stage final decides no claim without it"),
    ("generalka", "rehearsal", ("k1", "k2a", "k2b"), "of stage generalka decides no claim without it"),
    ("suchy", "rehearsal", ("k1", "k2a", "k2b"), "of stage suchy in plan mode rehearsal writes no claim without it"),
    ("suchy", "campaign", ("k2a",), "of stage suchy takes the three bounds of G1 null together, but analysis.k1.m is "
                                    "0.0"),
    ("suchy", "campaign", ("k1", "k2a", "k2b"), None),
    ("final", "campaign", (), None)])
def test_null_bounds_allow_a_null_m_in_a_dry_run_of_a_campaign_only(stage, mode, null, reason):
    """M_NULL_RULE in step 0: a null m is refused by name at stages final and generalka, in a dry run of a rehearsal,
    and with some of the three null and some filled; a dry run of a campaign takes all three null, and filled bounds
    pass at any stage."""
    from tcn import finalne
    plan = {claim: {"m": None if claim in null else 0.0} for claim in CLAIMS}
    if reason is None:
        assert finalne.null_bounds(plan, stage, mode) == list(null)
        return
    with pytest.raises(ValueError) as error:
        finalne.null_bounds(plan, stage, mode)
    assert str(error.value).startswith(f"analysis.{null[0]}.m is null: the bound m is determined in G1 "
                                       f"(determined_at), and the final evaluation {reason}")
    assert str(error.value).endswith("refused before the seal is consumed")


def test_k2_without_a_class_evaluated_stays_nevyhodnotene_at_a_null_m():
    """k2_claims: no class of the interventions evaluated, tcn.k2 k2 decides nothing and reads no m, so the claims are
    nevyhodnotené at a null m as at a filled one."""
    from tcn import finalne, k2
    plan = protocol_v5.analysis_plan(PROTOCOL)
    values = {"schema": k2.SCHEMA, "mode": MODE, "status": finalne.UNEVALUATED, "classes": {"C": {}, "D": {}}}
    found = finalne.k2_claims(PROTOCOL, plan, values, mode=MODE)
    assert found == k2.k2(PROTOCOL, values, mode=MODE) and {c["status"] for c in found.values()} == {
        finalne.UNEVALUATED}


def test_the_controls_of_the_structured_generator_are_judged_by_the_formulas_of_k1_and_k2():
    """CONTROL_CLAIMS_RULE: the networks shuffled context and random weights, K1 on their I per boot against Z3 and Z5
    (diagnostic_values improvement) and K2a, K2b on D = share(network) - share(Z) per boot (their detection against
    the shares of Z of k2_values), undecided at a null m with the intervals of rozhodni, decided at a filled one with
    the outcome of rozhodni and no wording; a boot without value is nevyhodnotené. Hand-made rows: the shuffled
    network detects 3/4 per boot, the random one 0; Z1 1/4, Z2 1/2, Z4 and Z3, Z5 0 (kills: D of Z minus the
    network, the shares of M in place of the network's)."""
    from tcn import finalne, tvrdenia
    labels = {"k2a": {"Z1": "Z1:value", "Z2": "Z2", "Z4:load": "Z4:load", "Z4:residual": "Z4:residual"},
              "k2b": {"Z3": "Z3:last", "Z5": "Z5:ridge(1.0)"}}
    z_shares = {"Z1:value": 0.25, "Z2": 0.5, "Z4:load": 0.0, "Z4:residual": 0.0, "Z3:last": 0.0,
                "Z5:ridge(1.0)": 0.0}
    values = {"status": finalne.EVALUATED, "boots": K2_BOOTS, "compare": labels,
              "shares": {label: dict.fromkeys(K2_BOOTS, share) for label, share in z_shares.items()}}
    rng = np.random.default_rng(3)
    networks = {}
    for name, detected, level in (("shuffled context", 0.75, 0.2), ("random weights", 0.0, -1.0)):
        networks[name] = {"label": name, "improvement": {
            z: {"boots": {b: float(x) for b, x in zip(K1_BOOTS, rng.normal(level, 0.01, len(K1_BOOTS)))}}
            for z in COMPARE["k1"]},
            "detection": {"status": finalne.EVALUATED, "shares": dict.fromkeys(K2_BOOTS, detected)}}
    plan = protocol_v5.analysis_plan(PROTOCOL)
    undecided = finalne.control_claims(networks, values, PROTOCOL, plan, MODE)
    assert list(undecided) == [*finalne.STRUCTURE_CONTROLS, "rule"]
    for name, detected in (("shuffled context", 0.75), ("random weights", 0.0)):
        claims = undecided[name]["claims"]
        assert claims["k1"]["methods"]["Z3"]["values"] == {b: networks[name]["improvement"]["Z3"]["boots"][b]
                                                           for b in sorted(K1_BOOTS)}
        for claim in ("k2a", "k2b"):
            for z, label in labels[claim].items():
                assert set(claims[claim]["methods"][z]["values"].values()) == {detected - z_shares[label]}, (name, z)
        for claim in CLAIMS:
            assert (claims[claim]["status"], claims[claim]["outcome"], claims[claim]["conclusion"]) == (
                finalne.EVALUATED, None, finalne.M_NULL)
    m = {claim: 0.0 for claim in CLAIMS}
    filled = _filled(m)
    decided = finalne.control_claims(networks, values, filled, protocol_v5.analysis_plan(filled), MODE)
    assert {claim: decided["shuffled context"]["claims"][claim]["outcome"] for claim in CLAIMS} == {
        "k1": "better", "k2a": "better", "k2b": "better"}
    assert {claim: decided["random weights"]["claims"][claim]["outcome"] for claim in CLAIMS} == {
        "k1": "not_better", "k2a": "not_better", "k2b": "undecided"}
    for name in finalne.STRUCTURE_CONTROLS:
        for claim in CLAIMS:
            mine = decided[name]["claims"][claim]
            assert "wording" not in mine and mine["conclusion"] is None and mine["m"] == 0.0
            per = {z: item["values"] for z, item in mine["methods"].items()}
            assert mine["outcome"] == tvrdenia.rozhodni(filled, claim, per, rezim=MODE)["outcome"]
            assert {z: i["interval"] for z, i in mine["methods"].items()} == {
                z: i["interval"] for z, i in undecided[name]["claims"][claim]["methods"].items()}
    networks["random weights"]["improvement"]["Z5"]["boots"][K1_BOOTS[3]] = None
    missing = finalne.control_claims(networks, values, PROTOCOL, plan, MODE)["random weights"]["claims"]["k1"]
    assert (missing["status"], missing["outcome"]) == (finalne.UNEVALUATED, None)
    assert missing["why"].startswith(f"boot {K1_BOOTS[3]} has no value")


# ------------------------------------------------------------------ the bounds m


def test_the_bounds_are_the_95th_percentile_of_the_point_estimates_per_run():
    """BOUND_RULE, BESIDE_RULE and SPREAD_RULE on the twenty runs of _null_runs, counted by hand: the point estimate
    of a method in a run is the mean of its values per boot (K1 Z3 r/64, Z5 (r + 2)/64; K2a r/128; K2b Z3 0, Z5
    0.05), the percentile of twenty of them h = 19 x 0.95 = 18.05, so K1 Z3 19/64 + 0.05 (20/64 - 19/64) = 0.2977, Z5
    21/64 + 0.05/64 = 0.3289 sets m of K1 (the maximum); K2a 19.05/128 by all four; K2b 0.05 by Z5. Beside it the
    pooled values per boot of K1 Z3 (240, half 1/256 off their run's mean) have their own percentile, above the
    bound; the mean + 1.645 SD of Z3 is (10.5 + 1.645 sqrt(35))/64; the flag is raised for K1 (spread 2/64 above
    0.02) and not for K2b, whose spread is exactly its bound 0.05 (kills: percentile 0.5, minimum instead of
    maximum, the pooled values per boot in place of the point estimates per run, the spread at or above)."""
    from tcn import suchy_beh
    found = suchy_beh.hranice_m(_null_runs())
    k1 = found["claims"]["k1"]
    z3, z5 = ([r / 64 for r in range(1, 21)], [(r + 2) / 64 for r in range(1, 21)])
    assert k1["methods"]["Z3"]["percentile"] == pytest.approx(19 / 64 + 0.05 * (1 / 64), rel=1e-12)
    assert k1["methods"]["Z3"]["percentile"] == pytest.approx(_hand_percentile(z3), rel=1e-12)
    assert k1["methods"]["Z5"]["percentile"] == pytest.approx(21 / 64 + 0.05 * (1 / 64), rel=1e-12)
    assert found["m"]["k1"] == k1["m"] == k1["methods"]["Z5"]["percentile"] and k1["set_by"] == ["Z5"]
    assert found["m"]["k2a"] == pytest.approx(19 / 128 + 0.05 * (1 / 128), rel=1e-12)
    assert found["claims"]["k2a"]["set_by"] == COMPARE["k2a"] and found["claims"]["k2a"]["spread"] == 0
    assert (found["m"]["k2b"], found["claims"]["k2b"]["set_by"]) == (0.05, ["Z5"])
    assert k1["methods"]["Z3"]["point_estimates"] == {f"nulovy_{r}": r / 64 for r in range(1, 21)}
    assert [found["claims"][c]["methods"][z]["count"] for c in CLAIMS for z in COMPARE[c]] == [20] * 8
    pooled = [x for r in range(1, 21) for x in _spread(r / 64, 1 / 256, K1_BOOTS).values()]
    assert k1["methods"]["Z3"]["pooled_boot_values"] == {"count": 240, "percentile": pytest.approx(
        _hand_percentile(pooled), rel=1e-12)}
    assert k1["methods"]["Z3"]["pooled_boot_values"]["percentile"] > k1["methods"]["Z3"]["percentile"] + 1e-3
    assert found["claims"]["k2a"]["methods"]["Z1"]["pooled_boot_values"]["count"] == 320
    assert k1["methods"]["Z3"]["mean_plus_1645_sd"] == pytest.approx((10.5 + 1.645 * math.sqrt(35)) / 64, rel=1e-12)
    assert k1["methods"]["Z3"]["sd"] == pytest.approx(math.sqrt(35) / 64, rel=1e-12)
    assert k1["mean_plus_1645_sd"] == k1["methods"]["Z5"]["mean_plus_1645_sd"]
    assert k1["pooled_boot_percentile"] == k1["methods"]["Z5"]["pooled_boot_values"]["percentile"]
    assert (k1["spread"], k1["spread_bound"], k1["spread_flag"]) == (pytest.approx(2 / 64, rel=1e-12), 0.02, True)
    assert (found["claims"]["k2b"]["spread"], found["claims"]["k2b"]["spread_flag"]) == (0.05, False)
    assert found["flag"] == {"raised": True, "claims": ["k1"], "rule": suchy_beh.SPREAD_RULE}
    assert (found["grids"], found["columns"], found["runs"]) == (GRIDS, COLUMNS, list(_null_runs()))
    assert found["schema"] == suchy_beh.SCHEMA_BOUNDS and found["rules"]["bound"] == suchy_beh.BOUND_RULE


def test_the_bounds_read_the_records_by_their_path(tmp_path):
    """A record given by the path of its file is read as its JSON."""
    from tcn import suchy_beh
    runs = _null_runs()
    paths = {}
    for name, record in runs.items():
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(record))
    assert suchy_beh.hranice_m(paths) == suchy_beh.hranice_m(runs)


def _changed(runs, name, change):
    out = dict(runs)
    out[name] = copy.deepcopy(runs[name])
    change(out[name])
    return out


@pytest.mark.parametrize("case", ["nineteen_runs", "stage_final", "failed", "nevyhodnotene", "other_grids",
                                  "fit_grid", "no_protocol_values", "mean", "compare"])
def test_the_bounds_refuse_what_is_no_family_of_null_runs(case):
    """BOUND_RULE: refused by name are fewer than 20 runs, a record of stage final, a failed record, a claim
    nevyhodnotené in a run, a run with other grids than the others, a fit whose grid is not the record's, a record
    without its protocol values, a mean that is not the mean of its values per boot, and other methods compared."""
    from tcn import suchy_beh
    runs = _null_runs()
    last = "nulovy_20"

    def grids(record):
        record["values"]["corpus"]["protocol_values"] = dict(VALUES, **{"analysis.methods.Z3.grid": {
            "ewma_alpha": [0.25, 0.5]}})
        record["values"]["methods"] = dict(FITS, **{"Z3:last": {"name": "Z3", "grid": {"ewma_alpha": [0.25, 0.5]}}})
    changes = {
        "stage_final": lambda r: r.update(stage="final"),
        "failed": lambda r: r["values"].update(status="failed"),
        "nevyhodnotene": lambda r: r["values"]["conclusions"]["k2a"].update(status="nevyhodnotené"),
        "other_grids": grids,
        "fit_grid": lambda r: r["values"]["methods"]["Z1:value"].update(grid={"moving_average_rows": [2]}),
        "no_protocol_values": lambda r: r["values"]["corpus"].pop("protocol_values"),
        "mean": lambda r: r["values"]["claims"]["k1"]["methods"]["Z3"].update(mean=0.5),
        "compare": lambda r: r["values"]["claims"]["k2b"].update(compare=["Z5", "Z3"]),
    }
    if case == "nineteen_runs":
        runs.pop(last)
        expected = "^19 null runs: the bound m is the 95th percentile on at least 20 runs"
    else:
        runs = _changed(runs, last, changes[case])
        expected = {
            "stage_final": f"^run {last}: a record of stage 'final'; the tools of G1 read the dry runs only",
            "failed": f"^run {last}: a record of status 'failed'",
            "nevyhodnotene": f"^run {last}: the claim k2a is nevyhodnotené there",
            "other_grids": f"^run {last} used other grids of Z1, Z3 and Z5 or another column mask than run nulovy_1",
            "fit_grid": f"^run {last}: the fit of Z1 used the grid",
            "no_protocol_values": f"^run {last}: the record names no grids and column mask of its run",
            "mean": rf"^run {last}: the mean 0\.5 of k1/Z3 in the record is not the mean of its values per boot",
            "compare": f"^run {last}: the claim k2b has no values of every method of its compare",
        }[case]
    with pytest.raises(ValueError, match=expected):
        suchy_beh.hranice_m(runs)


# ------------------------------------------------------------------ the decisions and the table without one run


def _decided_runs():
    """Five runs of K1 whose values per boot are drawn about 0, 0.1, ..., 0.4, K2a and K2b likewise, and one run whose
    K2a and K2b are nevyhodnotené."""
    rng = np.random.default_rng(11)
    runs = {}
    for r in range(5):
        per = {claim: {z: {b: float(x) for b, x in zip(K1_BOOTS if claim == "k1" else K2_BOOTS,
                                                         rng.normal(0.1 * r, 0.05, 16))}
                       for z in COMPARE[claim]} for claim in CLAIMS}
        runs[f"run_{r}"] = per
    runs["no_k2"] = dict(runs["run_2"], k2a=None, k2b=None)
    return runs


@pytest.mark.parametrize("m", [{"k1": 0.0, "k2a": 0.0, "k2b": 0.0}, {"k1": 0.2, "k2a": 0.15, "k2b": 0.3},
                               {"k1": 0.5, "k2a": 0.05, "k2b": -0.1}])
def test_the_decisions_at_m_are_those_of_a_run_decided_at_m(m):
    """DECISION_RULE: the outcome of every claim of a record written at a null m, at the bounds m, is the outcome
    tcn.tvrdenia rozhodni gives the same values at that m (the run decided at m), and the record of a run decided at
    m is read the same with its own m and outcome beside; a claim nevyhodnotené stays so; the counts and the
    exceptions (the runs neither not_better nor undecided)."""
    from tcn import suchy_beh, tvrdenia
    per_run = _decided_runs()
    undecided = {name: _record(per) for name, per in per_run.items()}
    decided = {name: _record(per, m=m) for name, per in per_run.items()}
    found = suchy_beh.rozhodnutia(undecided, m)
    again = suchy_beh.rozhodnutia(decided, m)
    assert found["m"] == m and found["schema"] == suchy_beh.SCHEMA_DECISIONS
    for name, per in per_run.items():
        for claim in CLAIMS:
            mine, theirs = found["runs"][name][claim], again["runs"][name][claim]
            if per[claim] is None:
                assert mine == theirs and (mine["outcome"], mine["status"]) == (None, "nevyhodnotené")
                continue
            expected = tvrdenia.rozhodni(_filled(m), claim, per[claim], rezim=MODE)
            assert mine["outcome"] == theirs["outcome"] == theirs["record_outcome"] == expected["outcome"]
            assert (mine["record_m"], theirs["record_m"]) == (None, m[claim])
            assert mine["intervals"] == theirs["intervals"] == {z: expected["methods"][z]["interval"]
                                                                for z in COMPARE[claim]}
    for claim in CLAIMS:
        outcomes = [found["runs"][name][claim]["outcome"] for name in per_run]
        counts = found["claims"][claim]["counts"]
        assert counts == {key: outcomes.count(None if key == "nevyhodnotené" else key)
                          for key in ("better", "not_better", "undecided", "nevyhodnotené")}
        assert found["claims"][claim]["exceptions"] == [name for name in per_run if found["runs"][name][claim][
            "outcome"] not in ("not_better", "undecided")]


def test_one_extra_run_is_decided_at_given_bounds_and_a_wrong_outcome_is_refused():
    """DECISION_RULE: the verifier's null run of seed 20 is a mapping of one run decided at the bounds given; a record
    decided at the same m whose outcome is not vysledok of its intervals is refused by name, and so are bounds without
    a claim or not a number."""
    from tcn import suchy_beh
    per = _decided_runs()["run_1"]
    m = {"k1": 0.0, "k2a": 0.0, "k2b": 0.0}
    one = suchy_beh.rozhodnutia({"nulovy_20": _record(per)}, m)
    assert list(one["runs"]) == ["nulovy_20"] and one["runs"]["nulovy_20"]["k1"]["outcome"] == "better"
    wrong = _record(per, m=m)
    wrong["values"]["claims"]["k1"]["outcome"] = "not_better"
    with pytest.raises(ValueError, match=r"^run nulovy_20: the claim k1 was decided 'not_better' at m 0\.0, but "
                                         r"tcn\.tvrdenia vysledok of its intervals at that m is 'better'"):
        suchy_beh.rozhodnutia({"nulovy_20": wrong}, m)
    for bad in ({"k1": 0.0, "k2a": 0.0}, {"k1": 0.0, "k2a": 0.0, "k2b": True}, {"k1": math.nan, "k2a": 0, "k2b": 0}):
        with pytest.raises(ValueError, match="^the bounds m are"):
            suchy_beh.rozhodnutia({"nulovy_20": _record(per)}, bad)


def test_the_table_without_one_run_decides_each_run_at_the_bound_of_the_others():
    """LEAVE_ONE_OUT_RULE, counted by hand on twenty runs whose every value per boot of K1 is r/64 (r = 1..20), so
    that every interval is [r/64, r/64]; K2a and K2b at 0. At the bound of all twenty, 19/64 + 0.05/64, run 20 is
    better and run 19 not better; without run 19 the other nineteen give h = 18 x 0.95 = 17.1, 18/64 + 0.1 (20/64 -
    18/64) = 18.2/64, below 19/64, so run 19 is better there; run 20 is better at 18.1/64, run 18 not better at
    19.1/64; K2a and K2b undecided everywhere ([0, 0] at m 0). Kills: the table using all twenty."""
    from tcn import suchy_beh
    runs = {f"nulovy_{r}": _record({"k1": _constant("k1", r / 64), "k2a": _constant("k2a", 0.0),
                                    "k2b": _constant("k2b", 0.0)}) for r in range(1, 21)}
    table = suchy_beh.bez_jedneho(runs)
    full = suchy_beh.rozhodnutia(runs, suchy_beh.hranice_m(runs)["m"])
    assert table["runs"]["nulovy_19"]["m"]["k1"] == pytest.approx(18 / 64 + 0.1 * (2 / 64), rel=1e-12)
    assert table["runs"]["nulovy_20"]["m"]["k1"] == pytest.approx(18 / 64 + 0.1 * (1 / 64), rel=1e-12)
    assert table["runs"]["nulovy_18"]["m"]["k1"] == pytest.approx(19 / 64 + 0.1 * (1 / 64), rel=1e-12)
    assert (full["runs"]["nulovy_19"]["k1"]["outcome"], table["runs"]["nulovy_19"]["claims"]["k1"]["outcome"]) == (
        "not_better", "better")
    assert table["claims"]["k1"]["exceptions"] == ["nulovy_19", "nulovy_20"]
    assert full["claims"]["k1"]["exceptions"] == ["nulovy_20"]
    assert table["claims"]["k1"]["counts"] == {"better": 2, "not_better": 18, "undecided": 0, "nevyhodnotené": 0}
    for claim in ("k2a", "k2b"):
        assert table["claims"][claim]["counts"]["undecided"] == full["claims"][claim]["counts"]["undecided"] == 20
    assert table["schema"] == suchy_beh.SCHEMA_LEAVE_ONE_OUT and table["rule"] == suchy_beh.LEAVE_ONE_OUT_RULE
    runs.pop("nulovy_1")
    with pytest.raises(ValueError, match="^19 null runs: the table leaves one out"):
        suchy_beh.bez_jedneho(runs)


# ------------------------------------------------------------------ the readers of the known answers


def _series(path, *, z1_edges, replay_edges, unscored=()):
    """An attachment series (tcn/finalne.py CONTENTS) of two sessions of 40 rows, one row every 5 s: tb-1 from 1000,
    tc-1 from 3000; the labels M:seed 0, Z1:value and Z3:last, every window scored; z1_edges [(session, seq)] the
    alarm edges of Z1; replay_edges {seed: [(session, seq, source)]} the alarm events of the replays of seeds 0 and
    1; unscored [(seed, session, seq)] the replay rows without score. Returns the record's attachment entry."""
    sessions = ["tb-1", "tc-1"]
    rows = 40
    seq = np.tile(np.arange(rows), 2)
    time = np.concatenate([1000.0 + 5 * np.arange(rows), 3000.0 + 5 * np.arange(rows)])
    at = {(name, int(s)): i * rows + int(s) for i, name in enumerate(sessions) for s in range(rows)}
    labels, names = ["M:seed 0", "Z1:value", "Z3:last"], ["M", "Z1", "Z3"]
    edge = np.zeros((3, 2 * rows), dtype=bool)
    for key in z1_edges:
        edge[1, at[key]] = True
    sources = ["model_anomaly", "rule_anomaly", "kernel_integrity"]
    event = np.zeros((2, 2 * rows), dtype=bool)
    rising = np.zeros((2, 2 * rows, 3), dtype=bool)
    for seed, found in replay_edges.items():
        for name, s, source in found:
            event[seed, at[(name, s)]] = True
            rising[seed, at[(name, s)], sources.index(source)] = True
    replay_score = np.ones((2, 2 * rows))
    for seed, name, s in unscored:
        replay_score[seed, at[(name, s)]] = np.nan
    np.savez_compressed(path, session_id=np.array(sessions), session_first_row=np.array([0, rows]),
                        session_rows=np.array([rows, rows]), row_seq=seq, row_time=time, label=np.array(labels),
                        label_name=np.array(names), threshold=np.ones(3), score=np.ones((3, 2 * rows)),
                        exceed=edge.copy(), up=edge.copy(), edge=edge, replay_seed=np.array([0, 1]),
                        replay_score=replay_score, replay_alarm_event=event, sources=np.array(sources),
                        replay_sources=rising)
    return {"path": str(path), "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def _generator(**sessions):
    return {"sessions": {name: {"invalid_rows": [], "marginal_changes": [], "unevaluated": [], **entry}
                         for name, entry in sessions.items()}}


def test_the_marginal_changes_are_caught_by_z1_and_every_replay_within_the_horizon(tmp_path):
    """MARGINAL_RULE on a synthetic series with the known answer (horizon 20 s, one row every 5 s: the horizon of a
    change at t0 is its first row and the four after it, t0 + 20 s included): change A at seq 10 of tb-1, Z1 rises at
    seq 9 (before t0, no catch) and 12, seed 0 at 11 (neural), seed 1 at 14 (t0 + 20 s, the closed end); change B at
    seq 25, Z1 at 27, seed 0 at 26, seed 1 only at 30 (t0 + 25 s, beyond the horizon: not caught); change C at seq 5
    of tc-1 lies where the replay of seed 1 has no score (listed apart, judged by neither). So Z1 catches 2 of the 2
    judged, seed 0 2 and seed 1 1: it does not hold; without B it holds (kills: the horizon ignored)."""
    from tcn import suchy_beh
    series = _series(tmp_path / "final.series.npz", z1_edges=[("tb-1", 9), ("tb-1", 12), ("tb-1", 27), ("tc-1", 7)],
                     replay_edges={0: [("tb-1", 11, "model_anomaly"), ("tb-1", 26, "rule_anomaly")],
                                   1: [("tb-1", 14, "model_anomaly"), ("tb-1", 30, "model_anomaly")]},
                     unscored=[(1, "tc-1", 6)])
    record = _record({claim: _constant(claim, 0.0) for claim in CLAIMS}, extra={"attachments": {"series": series}})
    changes = {"tb-1": {"marginal_changes": [{"first_seq": 10, "rows": 3, "column": "mem_changed_ratio"},
                                             {"first_seq": 25, "rows": 3, "column": "mem_changed_ratio"}]},
               "tc-1": {"marginal_changes": [{"first_seq": 5, "rows": 2, "column": "proc_user"}]}}
    found = suchy_beh.okrajova_zmena(record, _generator(**changes))
    a, b, c = found["changes"]
    assert (a["start_unix"], a["horizon_rows"], a["z1"], a["replays"]) == (1050.0, 5, {
        "caught": True, "first_edge_s": 10.0, "scored": True}, {
        "0": {"caught": True, "first_edge_s": 5.0, "sources": ["model_anomaly"], "neural": True, "scored": True},
        "1": {"caught": True, "first_edge_s": 20.0, "sources": ["model_anomaly"], "neural": True, "scored": True}})
    assert (b["z1"]["caught"], b["replays"]["0"]["caught"], b["replays"]["0"]["neural"]) == (True, True, False)
    assert b["replays"]["1"] == {"caught": False, "first_edge_s": None, "sources": [], "neural": False,
                                 "scored": True}
    assert (a["in_unscored_stretch"], b["in_unscored_stretch"], c["in_unscored_stretch"]) == (False, False, True)
    assert (found["judged"], found["listed_apart"], found["caught"], found["holds"]) == (
        2, [c], {"Z1": 2, "seed 0": 2, "seed 1": 1}, False)
    assert found["z1"] == {"label": "Z1:value", "chosen": FITS["Z1:value"]["chosen"]} and found["horizon_s"] == 20
    del changes["tb-1"]["marginal_changes"][1]
    assert suchy_beh.okrajova_zmena(record, _generator(**changes))["holds"] is True
    assert suchy_beh.okrajova_zmena(record, _generator())["holds"] is None  # A null run: no change (Q36).
    Path(series["path"]).write_bytes(Path(series["path"]).read_bytes() + b"\0")
    with pytest.raises(ValueError, match="is not the one its record names"):
        suchy_beh.okrajova_zmena(record, _generator(**changes))


def _unscored_record(*, invalid=2, event_evaluable=False, seed1_stretch=True, control_status="nevyhodnotené"):
    """A record whose replays and O1 hold the stretch of two invalid rows at seq 30 and 31 of tb-1 (then the warmup to
    seq 39) and of one at seq 50 of tc-1, whose O3 holds the second event of tb-1 nevyhodnotené (a quarter of its
    first 60 s scored) and whose O4 holds the control of tc-1 nevyhodnotené with 40 s unscored; the arguments break
    one of them."""
    def stretches(session):
        if session == "tb-1":
            return [{"first_seq": 0, "last_seq": 7, "rows": 8, "reasons": {"full_snapshot": 1, "warmup": 7},
                     "status": "nevyhodnotené"},
                    {"first_seq": 30, "last_seq": 39, "rows": 10, "reasons": {"invalid_input": invalid, "warmup": 8},
                     "status": "nevyhodnotené"}]
        return [{"first_seq": 50, "last_seq": 57, "rows": 8, "reasons": {"invalid_input": 1, "warmup": 7},
                 "status": "nevyhodnotené"}]
    events = [{"session": "tb-1", "type": "udrzba_zaloha", "start_unix": 1100.0, "executed": True, "evaluable": True,
               "status": "evaluated", "first_s_scored_share": 1.0},
              {"session": "tb-1", "type": "zamok_tabulky", "start_unix": 1150.0, "executed": True,
               "evaluable": event_evaluable, "status": "evaluated" if event_evaluable else "nevyhodnotené",
               "first_s_scored_share": 0.25}]
    o3 = {"occurrences": events, "total": {"evaluable": sum(e["evaluable"] for e in events)},
          "not_evaluable": [{key: e[key] for key in ("session", "type", "start_unix", "first_s_scored_share",
                                                     "status")} for e in events if not e["evaluable"]]}
    o4 = {"computed": True, "occurrences": [{"session": "tc-1", "kind": "memfd", "evaluable": False,
                                             "status": control_status, "first_s_scored_share": 0.0,
                                             "unscored_horizon_s": 40.0,
                                             "outputs": {"rule": {"result": "nezachytené"}}}]}
    metrics = {"o2": {}, "o3": {}, "o4": {}}
    for seed in ("0", "1"):
        benign = {"tb-1": {"stretches": stretches("tb-1") if seed == "0" or seed1_stretch else []}}
        metrics["o2"][seed] = {"v5": {"unscored": {"sessions": benign}}}
        metrics["o3"][seed] = {"v5": {"o3": o3}}
        metrics["o4"][seed] = {"v5": {"o4": o4, "unscored": {"sessions": {"tc-1": {"stretches": stretches("tc-1")}}}}}
    unscored = {"tb-1": {"role": "test_benign", "stretches": stretches("tb-1")},
                "tc-1": {"role": "test_controls", "stretches": stretches("tc-1")}}
    return _record({claim: _constant(claim, 0.0) for claim in CLAIMS},
                   extra={"opisné": {"unscored": {"sessions": unscored}, "metrics": metrics}})


UNSCORED_GENERATOR = _generator(**{
    "tb-1": {"invalid_rows": [31, 30], "unevaluated": [{"what": "event", "index": 1, "type": "zamok_tabulky"}]},
    "tc-1": {"invalid_rows": [50], "unevaluated": [{"what": "control", "index": 0, "type": "memfd"}]},
    "tr-1": {"invalid_rows": [12]}})


@pytest.mark.parametrize("case", [None, "one_invalid_row_too_few", "event_evaluable", "o1_of_seed_1",
                                  "control_evaluated"])
def test_the_unscored_stretches_and_the_unevaluated_occurrences_are_read_with_their_known_answer(case):
    """UNSCORED_RULE on a synthetic record with the known answer (_unscored_record): the two invalid rows of tb-1 lie
    in one stretch of its replays and of O1 of both seeds with two rows of reason invalid_input, the one of tc-1 in
    its stretch; tr-1 (a role without replay) is listed apart; the event is nevyhodnotené and out of the denominator
    of O3, the control nevyhodnotené in O4 with its unscored time, in the planned denominator: it holds. One row of
    invalid_input too few, the event evaluable, O1 of seed 1 without the stretch, or the control evaluated: it does
    not."""
    from tcn import suchy_beh
    record = _unscored_record(**{None: {}, "one_invalid_row_too_few": {"invalid": 1},
                                 "event_evaluable": {"event_evaluable": True}, "o1_of_seed_1": {"seed1_stretch": False},
                                 "control_evaluated": {"control_status": "evaluated"}}[case])
    found = suchy_beh.neskorovane(record, UNSCORED_GENERATOR)
    assert found["holds"] is (case is None)
    benign, controls = found["invalid_rows"]
    assert (benign["session"], benign["role"], benign["inserted"]) == ("tb-1", "test_benign", [[30, 31]])
    assert benign["holds"] is (case not in ("one_invalid_row_too_few", "o1_of_seed_1"))
    assert benign["o1"]["1"]["holds"] is (case not in ("one_invalid_row_too_few", "o1_of_seed_1"))
    assert controls["holds"] is True and found["not_replayed"][0]["session"] == "tr-1"
    event, = found["events"]
    assert event["holds"] is (case != "event_evaluable")
    assert event["seeds"]["0"]["in_denominator"] is (case == "event_evaluable")
    control, = found["controls"]
    assert control["holds"] is (case != "control_evaluated")
    assert (control["seeds"]["1"]["denominator"], control["seeds"]["1"]["unscored_horizon_s"]) == (
        "planned (proposal 6.4)", 40.0)
    if case is None:
        assert benign["replays"]["runs"] == [{"rows": [30, 31], "stretch": {
            "first_seq": 30, "last_seq": 39, "rows": 10, "status": "nevyhodnotené"}, "invalid_input_rows": 2,
            "inserted_in_it": 2}]


def _likeness(outcomes, used=None):
    """opisné.diagnostics.threshold_likeness of Z1, Z2 and Z3 with the outcomes {name: (tree, one member)} and M of
    two seeds; the use of USE_RULE from them unless `used` is given."""
    from tcn.diagnostiky import THRESHOLD_LIKE
    rows = [{"label": f"{name}:x", "name": name, "tree": {"outcome": tree, "positive_episodes": 25},
             "one_member": {"outcome": member, "positive_episodes": 25}}
            for name, (tree, member) in outcomes.items()]
    rows += [{"label": f"M:seed {s}", "name": "M", "tree": {"outcome": "not threshold-like"},
              "one_member": {"outcome": "not threshold-like"}} for s in (0, 1)]
    use = {d: {"used": all(o[i] == THRESHOLD_LIKE for o in outcomes.values())} for i, d in
           enumerate(("tree", "one_member"))}
    return {"methods": rows, "use": used or use}


@pytest.mark.parametrize("case", ["threshold_like", "z2_tree_not", "z3_member_unevaluated", "inconsistent"])
def test_the_diagnostics_mark_z1_to_z3_threshold_like_where_they_are_evaluated(case):
    """DIAGNOSTICS_RULE (the lead's answer to Q41): all three threshold-like by both diagnostics holds; Z2 not
    threshold-like by the tree does not; Z3 nevyhodnotené by the share of one member leaves the run not evaluated
    (holds null, not counted); a record whose use is not USE_RULE of its outcomes is refused."""
    from tcn import suchy_beh
    like, unlike, unevaluated = "threshold-like", "not threshold-like", "nevyhodnotené"
    outcomes = {"Z1": (like, like), "Z2": (like, like), "Z3": (like, like)}
    if case == "z2_tree_not":
        outcomes["Z2"] = (unlike, like)
    if case == "z3_member_unevaluated":
        outcomes["Z3"] = (like, unevaluated)
    used = {"tree": {"used": True}, "one_member": {"used": False}} if case == "inconsistent" else None
    record = _record({claim: _constant(claim, 0.0) for claim in CLAIMS},
                     extra={"opisné": {"diagnostics": {"threshold_likeness": _likeness(outcomes, used)}}})
    if case == "inconsistent":
        with pytest.raises(ValueError, match="^the record says the one_member is used"):
            suchy_beh.diagnostiky(record)
        return
    found = suchy_beh.diagnostiky(record)
    assert (found["evaluated"], found["holds"]) == {"threshold_like": (True, True), "z2_tree_not": (True, False),
                                                    "z3_member_unevaluated": (False, None)}[case]
    assert found["diagnostics"]["tree"]["outcomes"] == {name: o[0] for name, o in outcomes.items()}
    assert set(found["models"]) == {"M:seed 0", "M:seed 1"}


def _structured(m, *, control_better=False):
    """A structured run decided at m: M better by every claim (values about 0.5), the two networks with their claims
    by rozhodni without wording (values about -0.5; the shuffled one about 0.5 when control_better)."""
    from tcn import finalne, tvrdenia
    rng = np.random.default_rng(5)

    def per(level):
        return {claim: {z: {b: float(x) for b, x in zip(K1_BOOTS if claim == "k1" else K2_BOOTS,
                                                         rng.normal(level, 0.02, 16))}
                        for z in COMPARE[claim]} for claim in CLAIMS}
    controls = {}
    for name in finalne.STRUCTURE_CONTROLS:
        mine = per(0.5 if control_better and name == "shuffled context" else -0.5)
        controls[name] = {"label": name, "claims": {}}
        for claim in CLAIMS:
            found = (finalne.undecided_claim(PROTOCOL, claim, mine[claim], mode=MODE) if m is None
                     else tvrdenia.rozhodni(_filled(m), claim, mine[claim], rezim=MODE))
            controls[name]["claims"][claim] = dict({k: v for k, v in found.items() if k not in ("wording", "fill")},
                                                   conclusion=finalne.M_NULL if m is None else None,
                                                   status=finalne.EVALUATED)
    return _record(per(0.5), m=m, extra={"opisné": {"diagnostics": {"claims": dict(controls, rule="")}}})


def test_the_structured_run_holds_when_m_is_better_and_no_control_is():
    """STRUCTURED_RULE: decided at m 0 (the record's own, or given), M better by every claim and both networks not
    better: it holds; the shuffled network better by K1: it does not; a record at a null m is decided at the bounds
    given and refused without them; a record without the claims of the networks is refused by name."""
    from tcn import suchy_beh
    m = {claim: 0.0 for claim in CLAIMS}
    found = suchy_beh.strukturovane(_structured(m))
    assert (found["m_origin"], found["m"], found["holds"]) == ("record", m, True)
    assert {claim: found["claims"][claim]["outcome"] for claim in CLAIMS} == dict.fromkeys(CLAIMS, "better")
    assert {found["controls"][name][claim]["outcome"] for name in found["controls"] for claim in CLAIMS} == {
        "not_better"}
    assert suchy_beh.strukturovane(_structured(m), m)["m_origin"] == "given"
    assert suchy_beh.strukturovane(_structured(m, control_better=True))["holds"] is False
    null = _structured(None)
    assert suchy_beh.strukturovane(null, m)["holds"] is True
    with pytest.raises(ValueError, match="^the record's bound of k1 is null"):
        suchy_beh.strukturovane(null)
    null["values"]["opisné"]["diagnostics"].pop("claims")
    with pytest.raises(ValueError, match="^the record carries no claims of the model with shuffled context"):
        suchy_beh.strukturovane(null, m)


@pytest.mark.parametrize("bad, reason", [
    ({}, "has no object sessions"),
    ({"sessions": {"tb-1": {"invalid_rows": []}}}, "the session tb-1 has no lists"),
    ({"sessions": {"tb-1": {"invalid_rows": [3, 3], "marginal_changes": [], "unevaluated": []}}},
     "the invalid rows of session tb-1 are distinct integers"),
    ({"sessions": {"tb-1": {"invalid_rows": [], "marginal_changes": [{"first_seq": 3}], "unevaluated": []}}},
     "a marginal change of session tb-1 is"),
    ({"sessions": {"tb-1": {"invalid_rows": [], "marginal_changes": [], "unevaluated": [{"what": "event"}]}}},
     "an unevaluated occurrence of session tb-1 is")])
def test_a_generator_json_without_the_keys_of_the_readers_is_refused(bad, reason):
    """GENERATOR_KEYS: the readers refuse by name a generator.json without the lists they read."""
    from tcn import suchy_beh
    with pytest.raises(ValueError, match=reason):
        suchy_beh.neskorovane(_unscored_record(), bad)


def test_the_command_entry_prints_the_pure_part_and_refuses_an_incomplete_call(capsys):
    """The command entry (package C3 since the G1 preparation's C3: python -m tcn.suchy_beh beh, tested in
    scripts/tests/test_suchy_beh.py; hranice and tabulka since C4a, tested in tcn/tests/test_suchy_beh_tabulka.py):
    --help prints the module's docstring with the pure part; no command, and a call of beh or of hranice without its
    required options are refused with exit 2 by the parser, before anything runs."""
    from tcn import suchy_beh
    assert suchy_beh.main(["--help"]) == 0 and "hranice_m(zaznamy)" in capsys.readouterr().out
    for argv in ([], ["beh", "--generator", "nulovy", "--seed", "0", "--out", "x"], ["hranice"]):
        assert suchy_beh.main(argv) == 2
        assert "usage: python -m tcn.suchy_beh" in capsys.readouterr().err
