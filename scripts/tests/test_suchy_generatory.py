"""The generators of the dry run of G1 (protocol v5, G1 preparation, package C1): scripts/tests/suchy_generatory.py.

The column "Hotové, keď" of row C1 of the skeleton dokazy/G1/kostra/KOSTRA.md with the lead's answer to Q36: the null
mode has no correlation of column pairs, no lag-1 autocorrelation and no lagged dependence above chance, and both
modes have the same marginals (KS over 10 sessions); the structured mode has its coupling and its periodicity, a linear
autoregression does not read the coupling and the function of the driver LAG rows before does, while the last row of
the context alone (what the model with shuffled context keeps) does not; the controls, the marginal change and the
invalid rows match generator.json exactly, and the null mode puts nothing into test_benign that the real test_benign
will not have; every row of the plans of the campaign and of the rehearsal passes collection.analyze_windows under the
real file. Beside them: controls.json of every session of test_controls passes the controls section of the real log
audit and bounds the rows of the effects, and a wrong input is refused by name. Every bound below states its origin;
the generator's own numbers are its GENERATOR and COLUMNS. No case file of scripts/audit_selftest.py changes: they
are imported only (audit_cases_logs through the generator, test_collection_logs here).

The protocol of the runs is the working copy of package C3: config/collection-v5.json with the rates of the skeleton
(section 1, row C3: the lab test skuska_labu, eshop and corp low 1.2 and high 3.2 user sessions a second); the plans and
analyze_windows read the real file itself. Nothing is written outside pytest's tmp_path.
"""
import copy
import functools
import hashlib
import json
import math

import numpy as np
import pytest
from scipy import stats

from features import quality as fq
from features.archive import BEHAVIOR_NAMES
from features.contract import validate_sidecar
from features.coverage import scorable_windows
from features.snapshot import MENA
from scripts import collection, protocol_v5
from scripts.tests import boundary_sessions as bs
from scripts.tests import suchy_generatory as sg
from scripts.tests import test_collection_logs as evidence

RATES = {"low": 1.2, "high": 3.2}  # Skeleton section 1, row C3 (the copy's rate from the lab test skuska_labu).
SEED = 0
NEURAL = [name for name in BEHAVIOR_NAMES if sg.TRIEDY[name] == "neural"]
CHANNELS = list(sg.BIN_CHANNELS)
# The family-wise level of every test of chance below (judgment: one false refusal in a thousand runs of the file),
# split over its tests by Bonferroni.
ALPHA = 0.001
# A row of the KS comparison every THIN rows: the AR(1) correlation left at that lag is rho^17 (0.023 at rho 0.8),
# and 17 is prime to period_rows 12, so the rows cycle through every phase of the periodic component (judgment).
THIN = 17


@functools.lru_cache(maxsize=None)
def real():
    return collection.protocol(collection.ROOT / "config/collection-v5.json")


@functools.lru_cache(maxsize=None)
def working_copy():
    p = copy.deepcopy(real())
    for s in p["scenarios"].values():
        s["rate"] = RATES[s["intensity"]]
    return p


@functools.lru_cache(maxsize=None)
def plan(mode):
    return protocol_v5.plan(working_copy(), mode)


@functools.lru_cache(maxsize=None)
def session(mode, index, rezim, seed=SEED):
    """(result, record, base matrix) of row `index` of the plan of `mode`."""
    return sg._session(plan(mode)["sessions"][index], rezim, seed, working_copy())


def rows_of(mode, role):
    return [i for i, s in enumerate(plan(mode)["sessions"]) if s["role"] == role]


def measured(result):
    """The measured rows (valid, no full snapshot, with a predecessor), as features/qualification.py takes them."""
    m = np.asarray(result["matica"])
    return (np.asarray(result["valid"]) & (m[:, MENA.index("je_plna")] == 0)
            & (m[:, MENA.index("ma_predchodcu")] == 1))


def series(result):
    """{name: values over all rows} of the neural columns and of every bin channel (bin.channel)."""
    m, b = np.asarray(result["matica"]), np.asarray(result["perbin"])
    out = {name: m[:, MENA.index(name)] for name in NEURAL}
    for j in range(sg.BINS):
        for c, channel in enumerate(CHANNELS):
            out[f"{j}.{channel}"] = b[:, j, c]
    return out


def z_bound(tests, n):
    """The bound of |r| of a sample correlation over n rows when there is no relation, at ALPHA over `tests` tests:
    sqrt(n) r is about normal(0, 1) when one side is i.i.d. and independent of the other (the null mode), so the
    two-sided Bonferroni quantile over sqrt(n)."""
    return stats.norm.isf(ALPHA / (2 * tests)) / math.sqrt(n)


def corr(x, y):
    x, y = x - x.mean(), y - y.mean()
    return float(x @ y / math.sqrt((x @ x) * (y @ y)))


def ranked(x):
    """The rank correlation's view of the columns of x: their ranks (ties averaged), centred and scaled."""
    r = stats.rankdata(x, axis=0)
    return (r - r.mean(axis=0)) / r.std(axis=0)


def rank_correlations(left, right):
    """Spearman's rank correlation of every column of `left` with every column of `right` (rows aligned)."""
    return ranked(left).T @ ranked(right) / len(left)


# ------------------------------------------------------------------ the null mode (Hotové, keď 1)

def test_null_mode_has_no_dependence_above_chance():
    """Ten sessions of test_benign of the campaign, null mode: within each session, over its consecutive measured rows,
    no correlation of two columns or bin channels at the same row, no lag-1 autocorrelation, and no lagged dependence of
    one on another 1 or 2 rows before (linear, of the square, of the absolute value, of a product of two), above the
    chance bound at ALPHA over every test of the ten sessions. The statistic is Spearman's rank correlation: when the
    two sides are independent and one is i.i.d., sqrt(n - 1) r has mean 0, variance at most 1 (ties lower it) and,
    its terms bounded, a normal tail; the lagged forms are those of the couplings of the structured mode
    (GENERATOR_RULE), so that a coupling left in the null mode would lie above chance."""
    scaled = []  # sqrt(n - 1) |r| of every test
    for index in rows_of("campaign", "test_benign")[:10]:
        result = session("campaign", index, "nulovy")[0]
        keep = measured(result)
        values = series(result)
        assert len(values) == len(NEURAL) + sg.BINS * len(CHANNELS) == 27
        x = np.stack(list(values.values()), axis=1)
        rows = np.flatnonzero(keep)
        same = rank_correlations(x[rows], x[rows])
        scaled += (np.abs(same[np.triu_indices(x.shape[1], 1)]) * math.sqrt(len(rows) - 1)).tolist()
        for lag in (1, 2):
            pairs = np.array([r for r in rows if r >= lag and keep[r - lag:r + 1].all()])
            now, before = x[pairs], x[pairs - lag]
            before = (before - before.mean(axis=0)) / before.std(axis=0)
            products = [before[:, [i]] * before[:, i + 1:] for i in range(x.shape[1] - 1)]
            lagged = np.concatenate([before, before ** 2, np.abs(before), *products], axis=1)
            scaled += (np.abs(rank_correlations(now, lagged)).ravel() * math.sqrt(len(pairs) - 1)).tolist()
    bound = stats.norm.isf(ALPHA / (2 * len(scaled)))
    assert max(scaled) <= bound, f"a dependence of the null mode above chance: {max(scaled):.2f} > {bound:.2f}"


def test_both_modes_have_the_same_marginals():
    """KS over 10 sessions (skeleton row C1): ten sessions of train of the campaign in both modes, the measured rows of
    every THIN-th seq pooled per mode; for every neural column and every bin channel the two-sample KS test
    (scipy.stats.ks_2samp, two-sided) does not refuse at ALPHA over the 27 series (Bonferroni). The rule channel is the
    same constant in both modes. The thinning keeps the rows of the structured mode about independent (THIN), which
    the test assumes."""
    pooled = {rezim: {} for rezim in sg.MODES}
    for index in rows_of("campaign", "train")[:10]:
        for rezim in sg.MODES:
            result = session("campaign", index, rezim)[0]
            keep = measured(result) & (np.arange(len(result["seq"])) % THIN == 0)
            for name, values in series(result).items():
                pooled[rezim].setdefault(name, []).extend(values[keep].tolist())
            m = np.asarray(result["matica"])
            for name, level in sg.RULE_VALUES.items():
                assert set(m[:, MENA.index(name)].tolist()) == {level}
    level = ALPHA / len(pooled["nulovy"])
    for name in pooled["nulovy"]:
        p = stats.ks_2samp(pooled["nulovy"][name], pooled["strukturovany"][name]).pvalue
        assert p >= level, f"{name}: the marginals of the two modes differ (KS p = {p:.2g} < {level:.2g})"


@pytest.mark.parametrize("rezim", sg.MODES)
def test_the_scale_of_the_marginal_change_column_is_its_standard_deviation(rezim):
    """OKRAJOVA_ZMENA takes 8 x the scale of mem_changed_max as 8 standard deviations of role train: the scale is the
    standard deviation by construction (a latent of variance 1, no clip at these levels), so the measured rows of
    twelve sessions of train, pooled, give it within 5 standard errors of a standard deviation (sd / sqrt(2 n), normal
    approximation; the bound is judgment), in the structured mode, whose test_benign carries the change, and in the
    null mode alike; every role has the same marginal by construction."""
    column = sg.OKRAJOVA_ZMENA["column"]
    values = []
    for index in rows_of("campaign", "train")[:12]:
        result = session("campaign", index, rezim)[0]
        values += np.asarray(result["matica"])[measured(result), MENA.index(column)].tolist()
    sd = sg.COLUMNS[column][3]
    assert abs(np.std(values) - sd) <= 5 * sd / math.sqrt(2 * len(values))


# ------------------------------------------------------------------ the structured mode (Hotové, keď 2)

def _drivers(m):
    """The drivers a_0 and a_1 of every row, recovered exactly from mem_changed_ratio and mem_bins_active (a driver
    column is mean + scale x a, no noise)."""
    out = []
    for name in ("mem_changed_ratio", "mem_bins_active"):
        _, _, mean, scale, _ = sg.COLUMNS[name]
        out.append((m[:, MENA.index(name)] - mean) / scale)
    return np.stack(out)


def _term(latent, a, lag, rows):
    if latent[0] == "h":
        return a[0, rows - lag] * a[1, rows - lag]
    x = a[latent[1], rows - lag]
    return (x * x - 1) / math.sqrt(2) if latent[0] == "f" else np.abs(x)


def _r2(y, x):
    """R^2 of the least squares of y on the columns of x with an intercept."""
    design = np.column_stack([np.ones(len(y)), x])
    fit = np.linalg.lstsq(design, y, rcond=None)[0]
    residual = y - design @ fit
    return 1 - float(residual @ residual) / float(((y - y.mean()) ** 2).sum())


# The couplings without the offered load: R^2 on the coupling term is its share by construction, 1 - noise_coupled.
# (A count with kappa > 0 also follows the smooth envelope of the load, which a linear autoregression reads by design.)
COUPLED = [name for name, spec in sg.COLUMNS.items() if spec[0] == "coupled" or spec[0] == "count" and spec[5] == 0]
# The chance bound of n R^2 of k regressors uncorrelated with the response: INFLATION x the chi-square quantile of k
# degrees of freedom. A coupling term is uncorrelated with every linear function of the drivers but not independent of
# its driver, which inflates the variance of its sample correlation with the driver by E[f(a)^2 a^2] / (var f var a),
# 5 for f, 3 for g and the product (normal moments), so 5 bounds them all. The coupled values of earlier rows
# correlate with it through the AR(1) of the drivers by at most (w_u rho)^2 = 0.0256 (GENERATOR_RULE), which adds about
# n x 0.0256^2, under 5 at the rows of the test, to n R^2: far below the bound, which stays the origin of "R^2 = 0".
INFLATION = 5


def _pooled(rezim):
    """Over 10 sessions of train of the campaign: per coupled column, (y, the coupling term at LAG, the coupling term at
    lag 1, the linear lags 1..LAG of every neural column) pooled over the rows whose LAG rows before are measured."""
    lag = sg.GENERATOR["lag"]
    out = {name: [[], [], [], []] for name in COUPLED}
    for index in rows_of("campaign", "train")[:10]:
        result = session("campaign", index, rezim)[0]
        m, keep = np.asarray(result["matica"]), measured(result)
        a = _drivers(m)
        rows = np.array([r for r in range(lag, len(keep)) if keep[r - lag:r + 1].all()])
        linear = np.column_stack([m[rows - k, MENA.index(c)] for k in range(1, lag + 1) for c in NEURAL])
        for name in COUPLED:
            latent = sg.COLUMNS[name][1]
            y = m[rows, MENA.index(name)]
            for part, value in zip(out[name], (y, _term(latent, a, lag, rows), _term(latent, a, 1, rows), linear)):
                part.append(value)
    return {name: [np.concatenate(part) for part in parts] for name, parts in out.items()}


def test_the_structured_coupling_is_read_by_its_function_and_not_by_a_linear_autoregression():
    """GENERATOR_RULE over 10 sessions of train (pooled): every coupled column without load has R^2 of at least
    1 - noise_coupled - 0.05 on its coupling term of the drivers LAG rows before (the share by construction less 0.05,
    more than ten standard errors of R^2 at these rows; the rounding of a count takes under 0.01 of it); its R^2 on a
    linear autoregression over every neural column at lags 1 to LAG, and on its coupling term one row before (the last
    row of the context, which the model with shuffled context keeps: tcn/diagnostiky.py SHUFFLE_RULE), stays below the
    chance bound INFLATION x chi2.isf(ALPHA / tests, k) / n. In the null mode the coupling term reads nothing either.
    The skeleton's f(a_(t-1)) is f of the driver LAG = 2 rows before (GENERATOR_RULE: the shuffled context keeps row
    t - 1, so a coupling to it would make that model better, which section 2 of the skeleton forbids)."""
    data = _pooled("strukturovany")
    share = 1 - sg.GENERATOR["noise_coupled"]
    tests = 2 * len(COUPLED)
    for name, (y, term, last_row, linear) in data.items():
        n = len(y)
        assert _r2(y, term) >= share - 0.05, name
        k = linear.shape[1]
        assert _r2(y, linear) <= INFLATION * stats.chi2.isf(ALPHA / tests, k) / n, name
        assert _r2(y, last_row) <= INFLATION * stats.chi2.isf(ALPHA / tests, 1) / n, name
    for name, (y, term, _, _) in _pooled("nulovy").items():
        assert _r2(y, term) <= INFLATION * stats.chi2.isf(ALPHA / len(COUPLED), 1) / len(y), name


def _ordinate(x, period):
    """The periodogram ordinate of x at the frequency 1 / period, over the variance: about exponential(1) for white
    noise (a Fourier frequency, not 0 or the Nyquist one)."""
    x = np.asarray(x, dtype=float) - np.mean(x)
    j = len(x) // period
    return float(np.abs(np.fft.rfft(x)[j]) ** 2 / (len(x) * x.var()))


def test_the_structured_mode_has_its_periodicity_and_its_ar1():
    """The slow columns mem_zero_ratio and mem_entropy_mean and every bin channel have a periodic component of
    period_rows: their periodogram ordinate at that frequency (all rows of the session, whose values exist in every row)
    is above the white-noise bound -ln(ALPHA / tests) in the structured mode and below it in the null mode (an
    exponential(1) ordinate under white noise, Bonferroni over every test of the ten sessions and both modes); the
    drivers mem_changed_ratio and mem_bins_active have the lag-1 autocorrelation w_u x rho of their AR(1) state: pooled
    over the ten sessions (each centred on its own mean) above the chance bound in the structured mode, within 5
    standard errors of w_u x rho, and below the bound in the null mode."""
    period = sg.GENERATOR["period_rows"]
    slow = ["mem_zero_ratio", "mem_entropy_mean"] + [f"{j}.{c}" for j in range(sg.BINS) for c in CHANNELS]
    sessions = rows_of("campaign", "train")[:10]
    bound = -math.log(ALPHA / (len(sg.MODES) * len(slow) * len(sessions)))
    drivers = ("mem_changed_ratio", "mem_bins_active")
    for rezim in sg.MODES:
        pairs = {name: ([], []) for name in drivers}
        for index in sessions:
            result = session("campaign", index, rezim)[0]
            values = series(result)
            for name in slow:
                above = _ordinate(values[name], period) > bound
                assert above == (rezim == "strukturovany"), (name, rezim)
            m = np.asarray(result["matica"])
            for name in drivers:
                x = m[:, MENA.index(name)] - m[:, MENA.index(name)].mean()
                pairs[name][0].append(x[1:])
                pairs[name][1].append(x[:-1])
        for name in drivers:
            now, before = (np.concatenate(v) for v in pairs[name])
            r = float(now @ before / math.sqrt((now @ now) * (before @ before)))
            limit = z_bound(len(sg.MODES) * len(drivers), len(now))
            assert (r > limit) == (rezim == "strukturovany"), (name, rezim, r, limit)
            if rezim == "strukturovany":
                assert abs(r - sg.GENERATOR["w_u"] * sg.GENERATOR["rho"]) <= 5 / math.sqrt(len(now)), (name, r)


def test_the_counts_depend_on_the_offered_load_in_the_structured_mode():
    """ponukana_zataz is LOAD_RULE (rate x the envelope of scripts/host_traffic.py draw_envelope over each row's
    interval); in the structured mode a count with kappa follows the load of its row: the slope of its least squares on
    the load over ten sessions of train (each centred on its own means) lies within 5 standard errors of kappa (the
    standard error of that slope from its residuals; 5 is judgment); in the null mode it does not follow the load of its
    own row: the within-session correlation is below the chance bound."""
    from scripts import host_traffic
    import random
    p = working_copy()
    row = plan("campaign")["sessions"][0]
    s = p["scenarios"][row["scenario"]]
    warmup, interval = p["warmup_s"], p["interval_s"]
    envelope, _ = host_traffic.draw_envelope(p["profiles"][s["profile"]]["arrivals"],
                                             random.Random(row["seeds"]["traffic"]), warmup + p["cycles"] * interval,
                                             warmup, p["scenario_rule"]["min_peak_to_mean"])
    load = sg.ponukana_zataz(row, p)
    t = sg.FIRST_ROW_S + 10 * interval  # Row 10, its interval (t - interval_s, t] on the axis of the traffic.
    assert load[10] == pytest.approx(s["rate"] * envelope.integral(warmup + t - interval, warmup + t), rel=1e-12)
    counts = [name for name, spec in sg.COLUMNS.items() if spec[0] == "count" and spec[5] > 0]
    sessions = rows_of("campaign", "train")[:10]
    for rezim in sg.MODES:
        pooled = {name: ([], []) for name in counts}
        for index in sessions:
            result = session("campaign", index, rezim)[0]
            m, keep = np.asarray(result["matica"]), measured(result)
            load = np.asarray(sg.ponukana_zataz(plan("campaign")["sessions"][index], p))
            for name in counts:
                y = m[keep, MENA.index(name)]
                pooled[name][0].append(y - y.mean())
                pooled[name][1].append(load[keep] - load[keep].mean())
                if rezim == "nulovy":
                    assert abs(corr(y, load[keep])) <= z_bound(len(counts) * len(sessions), int(keep.sum())), name
        if rezim == "strukturovany":
            for name in counts:
                y, x = (np.concatenate(v) for v in pooled[name])
                kappa, slope = sg.COLUMNS[name][5], float(x @ y / (x @ x))
                residual = y - slope * x
                se = math.sqrt(float(residual @ residual) / (len(y) - 1) / float(x @ x))
                assert abs(slope - kappa) <= 5 * se, (name, slope, kappa, se)


# ------------------------------------------------------------------ controls, the marginal change, invalid rows (3)

def _differences(result, base):
    return np.asarray(result["matica"]) - base


@pytest.mark.parametrize("rezim", sg.MODES)
def test_the_controls_match_generator_json_exactly(rezim):
    """Every session of test_controls of the campaign: every planned control has its record (slot, kind, polarity,
    class, dose, the rows start_s < t <= start_s + duration_s); the result differs from the drawn values only by the
    recorded values added, row by row, in the columns of the control's kind: class A 1, class B kappa_c x dose
    (2 x expect.shift at the largest dose / the largest dose; a count in whole units), a negative nothing; the memory
    patterns of kontrola_wx_memfd are in exactly the rows of its controls; the null and the structured mode alike."""
    p = working_copy()
    kinds = p["controls"]["kinds"]
    seen = set()
    for index in rows_of("campaign", "test_controls"):
        row = plan("campaign")["sessions"][index]
        result, record, base = session("campaign", index, rezim)
        expected = np.zeros_like(base)
        patterns = set()
        items = [(slot, c) for slot, c in enumerate(row["controls"]) if c.get("kind") is not None]
        assert [r["slot"] for r in record["controls"]] == [slot for slot, _ in items]
        for (slot, item), rec in zip(items, record["controls"]):
            rows = [i for i, t in enumerate(result["casy"]) if item["start_s"] < t <= item["start_s"] +
                    item["duration_s"]]
            spec = kinds[item["kind"]]
            assert (rec["kind"], rec["polarity"], rec["class"], rec["dose"], rec["seq"]) == (
                item["kind"], item["polarity"], spec["class"], item["dose"], rows)
            if item["polarity"] == "negative":
                assert rec["effects"] == {} and rec["patterns"] is None
                continue
            assert sorted(rec["effects"]) == sorted(spec["columns"])
            for column, effect in rec["effects"].items():
                if spec["class"] == "A":
                    step = 1.0
                else:
                    doses = spec["doses"]
                    step = 2 * spec["expect"][column]["shift"][doses.index(max(doses))] / max(doses) * item["dose"]
                    if sg.COLUMNS[column][0] == "count":
                        step = float(np.rint(step))
                assert effect["step"] == step
                expected[rows, MENA.index(column)] += effect["added"]
                seen.add((item["kind"], item["dose"]))
            if item["kind"] == sg.WX_KIND:
                patterns.update(rows)
                assert rec["patterns"] == {"pid": sg.WX_PID, "comm": "python3", "kinds": list(sg.WX_PATTERNS)}
        assert np.array_equal(_differences(result, base), expected)
        for r, q in enumerate(result["quality"]):
            assert q["memory_patterns"] == ([{"pid": sg.WX_PID, "comm": "python3", "kind": k} for k in sg.WX_PATTERNS]
                                            if r in patterns else [])
        # Class A in the rule channel: the constant + 1 in every row of a control, the constant elsewhere.
        m = np.asarray(result["matica"])
        for rec in record["controls"]:
            if rec["class"] == "A" and rec["polarity"] == "control":
                for column in rec["effects"]:
                    assert set(m[rec["seq"], MENA.index(column)].tolist()) == {sg.RULE_VALUES[column] + 1}
    assert {kind for kind, _ in seen} == set(kinds)
    # Every dose of every kind of class B occurs among the controls of the campaign, so each step above was compared.
    for kind, spec in kinds.items():
        if spec["class"] == "B":
            assert {dose for k, dose in seen if k == kind} == set(spec["doses"])


# The problems of the controls section of the log audit (scripts/collection_logs.py audit_logs, controls()): its own
# keys; the section unreadable is controls:unreadable.
CONTROL_PROBLEMS = ("controls_schema", "controls_differ_from_plan", "control_not_executed", "control_without_baseline",
                    "control_without_effect", "negative_with_property", "negative_not_in_place", "control_not_cleaned",
                    "control_script_differs")


@pytest.mark.parametrize("mode", protocol_v5.MODES)
def test_controls_json_passes_the_log_audit_and_bounds_the_rows_of_the_effects(tmp_path, mode):
    """controls_json of every session of test_controls (CONTROLS_JSON_RULE): the real log audit
    (scripts/collection_logs.py audit_logs) of a directory with that controls.json, the session.json of
    audit_cases_logs.controls_session (role, the plan's controls with a kind, source_sha256 lab/udalosti.py) and the
    real file as protocol.json finds no problem in its controls section and every control executed (the sections whose
    files the directory lacks fail on their own); the records are audit_cases_logs.control_records of those items; and
    the rows of every control's effects and memory patterns in generator.json (both modes) are exactly the rows of the
    session whose time lies in (host_start_unix, host_stop_unix] of its record, the pid of the patterns the first
    member of its effect evidence."""
    from scripts import collection_logs
    from scripts.tests import audit_cases_logs as acl
    from scripts.tests.test_collection_logs import SCRIPT_SHA256
    start = 1e9  # Judgment: any measurement start; the audit reads differences of times only.
    for n, index in enumerate(rows_of(mode, "test_controls")):
        row = plan(mode)["sessions"][index]
        items = [c for c in row["controls"] if c.get("kind") is not None]
        doc = sg.controls_json(row, start)
        assert doc == {"schema": protocol_v5.CONTROLS_SCHEMA, "controls": acl.control_records(items, start)}
        d = tmp_path / f"s{n}"
        d.mkdir()
        evidence.write(d / "session.json", {"role": "test_controls", "controls": items,
                                            "source_sha256": {"lab/udalosti.py": SCRIPT_SHA256}})
        evidence.write(d / "controls.json", doc)
        evidence.write(d / "protocol.json", real())
        audit = collection_logs.audit_logs(d)
        assert [x for x in audit["problems"] if x.split(":")[0] in CONTROL_PROBLEMS
                or x.startswith("controls:")] == []
        assert (audit["sections"]["controls"]["controls"], audit["sections"]["controls"]["executed"]) == (
            len(items), len(items))
        for rezim in sg.MODES:
            result, record, _ = session(mode, index, rezim)
            assert len(record["controls"]) == len(doc["controls"])
            for rec, written in zip(record["controls"], doc["controls"]):
                rows = [r for r, t in enumerate(result["casy"])
                        if written["host_start_unix"] < start + t <= written["host_stop_unix"]]
                assert rec["seq"] == rows and (rec["kind"], rec["polarity"]) == (written["kind"], written["polarity"])
                if rec["patterns"] is not None:
                    assert rec["patterns"]["pid"] == written["effect"]["evidence"]["members"][0] == sg.WX_PID
                    assert all(q["memory_patterns"] for q in (result["quality"][r] for r in rows))


def test_class_b_scales_with_the_dose():
    """GENERATOR_RULE: over every control of class B of test_controls of the campaign, the step of a continuous column
    over the dose is one number per kind and column (in proportion to the dose: kappa_c), and a count's step is that
    number times the dose rounded to the nearest integer; kappa_c is 2 x expect.shift at the largest dose / the largest
    dose, so the largest dose moves a column by twice its expected shift, the effect the protocol anticipates."""
    p = working_copy()
    kinds = p["controls"]["kinds"]
    steps = {}
    for index in rows_of("campaign", "test_controls"):
        for rec in session("campaign", index, "strukturovany")[1]["controls"]:
            if rec["class"] == "B" and rec["polarity"] == "control":
                for column, effect in rec["effects"].items():
                    steps.setdefault((rec["kind"], column), {})[rec["dose"]] = effect["step"]
    assert {kind for kind, _ in steps} == {k for k, spec in kinds.items() if spec["class"] == "B"}
    for (kind, column), by_dose in steps.items():
        doses = kinds[kind]["doses"]
        assert sorted(by_dose) == sorted(doses)
        kappa = 2 * kinds[kind]["expect"][column]["shift"][doses.index(max(doses))] / max(doses)
        for dose, step in by_dose.items():
            assert step == (float(np.rint(kappa * dose)) if sg.COLUMNS[column][0] == "count" else kappa * dose)
        if sg.COLUMNS[column][0] != "count":
            assert len({round(step / dose, 15) for dose, step in by_dose.items()}) == 1


@pytest.mark.parametrize("rezim", sg.MODES)
def test_the_marginal_change_lies_in_its_band_of_test_benign_of_the_structured_runs_only(rezim):
    """The lead's answer to Q36: in the structured mode one session of every group of test_benign of the campaign
    carries +8 standard deviations of OKRAJOVA_ZMENA['column'] in the 12 rows of the 60 s band before the full snapshot
    (T - full_snapshot_guard.before_s <= t < T), and the result differs from the drawn values only there, by the
    recorded values; no other role, no session of the rehearsal and no null run has a change, and the null mode's
    test_benign is the drawn values exactly (nothing that the real test_benign will not have: the tolerated invalid
    rows are in its quality only)."""
    p = working_copy()
    column = MENA.index(sg.OKRAJOVA_ZMENA["column"])
    for mode in protocol_v5.MODES:
        groups = {}
        for index, row in enumerate(plan(mode)["sessions"]):
            result, record, base = session(mode, index, rezim)
            changed = record["changes"]
            if rezim == "nulovy" or mode == "rehearsal" or row["role"] != "test_benign":
                assert changed == []
                if row["role"] != "test_controls":
                    assert np.array_equal(np.asarray(result["matica"]), base)
                if row["role"] == "test_benign":  # Its quality: complete rows and the tolerated invalid ones only.
                    invalid = set(record["invalid_rows"]["seq"]) if record["invalid_rows"] else set()
                    assert all(q == (bs.unclosed_row("processes") if r in invalid else bs.complete_row())
                               for r, q in enumerate(result["quality"]))
                continue
            groups.setdefault(row["group"], 0)
            if not changed:
                assert np.array_equal(np.asarray(result["matica"]), base)
                continue
            groups[row["group"]] += 1
            (change,) = changed
            full = p["full_every"]
            band = [r for r, t in enumerate(result["casy"])
                    if result["casy"][full] - p["full_snapshot_guard"]["before_s"] <= t < result["casy"][full]]
            assert change["seq"] == band == list(range(full - 12, full))
            assert change["delta"] == 8 * sg.COLUMNS[sg.OKRAJOVA_ZMENA["column"]][3]
            assert np.abs(np.asarray(change["added"]) - change["delta"]).max() <= 1e-12  # no clip: float rounding
            expected = np.zeros_like(base)
            expected[band, column] = change["added"]
            assert np.array_equal(np.asarray(result["matica"]) - base, expected)
            # Never in the session with the tolerated invalid rows, and every row of the band ends a window of the
            # live detector (scored; the record names the rows that do not, none here).
            assert record["invalid_rows"] is None and change["unscored_seq"] == []
            windows, _ = scorable_windows(result, real(), "x", len(result["seq"]))
            assert set(band) <= {int(m["seq_do"]) for m in windows.meta}
        if rezim == "strukturovany" and mode == "campaign":
            assert len(groups) == 12 and set(groups.values()) == {1}


def _first_s_share(result, start, p):
    """The scored share of the first analysis.evaluable.first_s seconds of an occurrence at start (tcn/eval.py: the
    rows with start < t <= start + first_s, scored x interval_s / first_s), by the windows of the live detector
    (features.coverage.scorable_windows)."""
    windows, _ = scorable_windows(result, p, "x", len(result["seq"]))
    scored = {int(m["seq_do"]) for m in windows.meta}
    first_s = p["analysis"]["evaluable"]["first_s"]
    first = [i for i, t in enumerate(result["casy"]) if start < t <= start + first_s]
    return sum(i in scored for i in first) * p["interval_s"] / first_s


@pytest.mark.parametrize("mode", protocol_v5.MODES)
def test_the_tolerated_invalid_rows_match_generator_json_and_leave_one_event_and_one_control_unevaluable(mode):
    """One session of every role carries one run of contiguous invalid rows, at most invalid_rows.max, of quality
    boundary_sessions.unclosed_row('processes'), exactly the rows generator.json names (both modes alike); in
    test_benign and test_controls the run begins at the first row of the first analysis.evaluable.first_s seconds of
    the recorded event or control, whose scored share is then below analysis.evaluable.scored_share (tcn/eval.py:
    nevyhodnotené)."""
    p = working_copy()
    k_max = fq.invalid_rows_rule(p)["max"]
    found = {}
    for index, row in enumerate(plan(mode)["sessions"]):
        records = [session(mode, index, rezim)[1] for rezim in sg.MODES]
        assert records[0]["invalid_rows"] == records[1]["invalid_rows"]
        result, record, _ = session(mode, index, "nulovy")
        invalid = [r for r, good in enumerate(result["valid"]) if not good]
        if record["invalid_rows"] is None:
            assert invalid == []
            continue
        found.setdefault(row["role"], []).append(index)
        rec = record["invalid_rows"]
        assert invalid == rec["seq"] == list(range(invalid[0], invalid[0] + len(invalid))) and len(invalid) <= k_max
        # The memory patterns of a control of kontrola_wx_memfd are in every row of it, an invalid one too (the test of
        # the controls pins them); the rest of the quality is that of an unclosed process list.
        assert all(dict(result["quality"][r], memory_patterns=[]) == bs.unclosed_row("processes") for r in invalid)
        assert all(r % p["full_every"] for r in invalid)
        # The stretch: the run, the row without a predecessor and window_rows - 1 rows more (boundary_sessions
        # clustered_seqs: count + window_rows windows), joined with an unscored stretch just before it.
        stretch = rec["unscored_stretch"]
        windows, _ = scorable_windows(result, real(), "x", len(result["seq"]))
        scored = {int(m["seq_do"]) for m in windows.meta}
        assert stretch["last_seq"] == invalid[-1] + p["window_rows"] and stretch["last_seq"] + 1 in scored
        assert stretch["first_seq"] == (invalid[0] if invalid[0] - 1 in scored else stretch["first_seq"])
        assert all(r not in scored for r in range(stretch["first_seq"], stretch["last_seq"] + 1))
        assert stretch["first_seq"] == 0 or stretch["first_seq"] - 1 in scored
        assert stretch["rows"] == stretch["last_seq"] - stretch["first_seq"] + 1
        if row["role"] in ("test_benign", "test_controls"):
            occurrence = rec["occurrence"]
            if row["role"] == "test_benign":
                items = row["events"]
                assert occurrence["type"] == items[occurrence["index"]]["type"]
            else:  # A control of polarity control, never a paired negative (GENERATOR_RULE).
                items = [c for c in row["controls"] if c.get("kind") is not None]
                assert (occurrence["kind"], occurrence["polarity"]) == (items[occurrence["index"]]["kind"], "control")
            item = items[occurrence["index"]]
            assert occurrence["start_s"] == item["start_s"] and len(invalid) == k_max
            first_s = p["analysis"]["evaluable"]["first_s"]
            first = [i for i, t in enumerate(result["casy"]) if item["start_s"] < t <= item["start_s"] + first_s]
            assert invalid[0] == first[0] == occurrence["first_s_seq"][0]
            share = _first_s_share(result, item["start_s"], real())
            assert share == occurrence["first_s_scored_share"] < p["analysis"]["evaluable"]["scored_share"]
            assert occurrence["evaluable"] is False
    assert {role: len(v) for role, v in found.items()} == dict.fromkeys(p["roles"], 1)


# ------------------------------------------------------------------ the plans (Hotové, keď 4)

@pytest.mark.parametrize("rezim", sg.MODES)
def test_every_row_of_both_plans_passes_analyze_windows_under_the_real_file(rezim):
    """collection.analyze_windows of every row of the plan of the campaign (132) and of the rehearsal (30) under
    config/collection-v5.json itself: accepted with no reason, the assigned rows, its windows and the tolerated
    invalid rows those of generator.json. The rows are those of the real file's plans: the working copy's rates change
    no row of them."""
    p = real()
    for mode in protocol_v5.MODES:
        assert protocol_v5.plan(p, mode) == plan(mode)
        assert len(plan(mode)["sessions"]) == {"campaign": 132, "rehearsal": 30}[mode]
        for index, row in enumerate(plan(mode)["sessions"]):
            result, record, _ = session(mode, index, rezim)
            _, windows, verdict, quality = collection.analyze_windows(copy.deepcopy(result), p,
                                                                      protocol_v5._label(row), row["role"])
            invalid = [] if record["invalid_rows"] is None else record["invalid_rows"]["seq"]
            assert (verdict["accepted"], verdict["reasons"], verdict["snapshots"]) == (True, [], p["cycles"])
            assert quality["tolerated_invalid_seq"] == invalid
            assert verdict["windows"] == bs.window_count(p["cycles"], p["window_rows"], p["full_every"], invalid)


# ------------------------------------------------------------------ the seed, the frame, the refusals

def test_the_seed_of_a_session_is_the_skeletons_rule_and_a_replacement_draws_anew():
    """The seed of a session is sha256 of [plan name, group, position, attempt, "suchy_beh", run seed] (skeleton row
    C1); the record names it; attempt 2 of the same session (protocol_v5.replacement) has another seed and other rows;
    another run seed gives other rows."""
    p = working_copy()
    row = plan("campaign")["sessions"][0]
    expected = int(hashlib.sha256(json.dumps(["server-normal-v5", row["group"], row["position"], 1, "suchy_beh",
                                              SEED]).encode()).hexdigest()[:16], 16)
    record = session("campaign", 0, "strukturovany")[1]
    assert record["seed"] == expected == sg.seed_session("server-normal-v5", row["group"], row["position"], 1, SEED)
    again = protocol_v5.replacement(p, row, 2, mode="campaign")
    second = sg.zaznam(again, "strukturovany", SEED, p)
    assert second["seed"] != expected and second["attempt"] == 2
    assert sg.riadky(again, "strukturovany", SEED, p)["matica"] != session("campaign", 0, "strukturovany")[0]["matica"]
    assert sg.riadky(row, "strukturovany", 1, p)["matica"] != session("campaign", 0, "strukturovany")[0]["matica"]
    assert sg.riadky(row, "strukturovany", SEED, p) == session("campaign", 0, "strukturovany")[0]


@pytest.mark.parametrize("role", ["test_benign", "test_controls"])
def test_a_replacement_carries_the_invalid_rows_at_its_own_occurrence(role):
    """A replacement (protocol_v5.replacement, attempt 2) of the session with the tolerated invalid rows of the role
    keeps the chosen occurrence (the same index: a replacement keeps the types, kinds and polarities in order) and
    moves the invalid rows to the first row of the first analysis.evaluable.first_s seconds of its own, newly drawn
    start, which stays nevyhodnotené."""
    p = working_copy()
    where = next(w for w, c in sg._choices(p, "campaign", SEED)["invalid"].items() if c["role"] == role)
    row = next(s for s in plan("campaign")["sessions"] if (s["group"], s["position"]) == where)
    again = protocol_v5.replacement(p, row, 2, mode="campaign")
    first, second = sg.zaznam(row, "nulovy", SEED, p), sg.zaznam(again, "nulovy", SEED, p)
    occurrence = second["invalid_rows"]["occurrence"]
    item = sg._occurrences(again)[occurrence["index"]]
    assert occurrence["index"] == first["invalid_rows"]["occurrence"]["index"]
    assert occurrence["start_s"] == item["start_s"] != sg._occurrences(row)[occurrence["index"]]["start_s"]
    assert second["invalid_rows"]["seq"][0] == next(r for r, t in enumerate(sg._times(p)) if t > item["start_s"])
    assert occurrence["evaluable"] is False
    assert occurrence["first_s_scored_share"] < p["analysis"]["evaluable"]["scored_share"]


def test_the_rows_lie_on_the_grid_of_the_measurement_start_of_boundary_sessions(tmp_path):
    """FIRST_ROW_S: test_collection_logs.build starts the measurement at its base + 1 s and
    boundary_sessions.build_session takes snapshot 0 at base + FIRST_SNAPSHOT_S, so a result shifted by the session's
    measure_start_unix has the times build_session gives; the grid is interval_s; the layout is the one
    boundary_sessions writes for the result's bins (validate_sidecar of its sidecar)."""
    d = evidence.build(tmp_path, base=bs.BASE, snapshots=3, measure_s=20)
    start = json.loads((d / "end.json").read_text())["measure_start_unix"]
    assert start + sg.FIRST_ROW_S == bs.BASE + bs.FIRST_SNAPSHOT_S
    result = session("campaign", 0, "nulovy")[0]
    assert result["casy"] == [sg.FIRST_ROW_S + 5 * r for r in range(720)]
    b = np.asarray(result["perbin"])
    pages = np.rint(b[0, :, 0] * sg.PAGES).astype(int)
    assert np.array_equal(pages / sg.PAGES, b[0, :, 0]) and (b[..., 3] == 1).all()
    side = bs._sidecar(0, result["casy"][0], True, result["chain_ids"][0], result["quality"][0], pages, b[0, :, 1],
                       b[0, :, 2])
    assert result["layout"] == validate_sidecar(side)
    assert [b["pages_changed"] for b in side["features"]["bins"]] == pages.tolist()


def test_the_events_leave_no_trace_in_the_features():
    """A session of test_benign with events and no tolerated invalid rows gives the same result without its events."""
    p = working_copy()
    choices = sg._choices(p, "campaign", SEED)
    for index in rows_of("campaign", "test_benign"):
        row = plan("campaign")["sessions"][index]
        if row["events"] and (row["group"], row["position"]) not in choices["invalid"]:
            for rezim in sg.MODES:
                assert sg.riadky(dict(row, events=[]), rezim, SEED, p) == session("campaign", index, rezim)[0]
            return
    raise AssertionError("no session of test_benign with events and without invalid rows")


def test_the_classes_by_construction_and_generator_json():
    """Q38: TRIEDY states the class of every column (rule for the five constants of the rule channel, neural for the
    others); generator_json holds the rule, the parameters, the classes and the record of every row in their order,
    and JSON states it without a non-finite number."""
    assert sg.TRIEDY == {name: "rule" if name in ("proc_wx", "proc_memfd", "mod_total", "mod_delta", "sock_listen")
                         else "neural" for name in BEHAVIOR_NAMES}
    rows = plan("rehearsal")["sessions"]
    doc = sg.generator_json(rows, "strukturovany", SEED, working_copy())
    text = json.dumps(doc, allow_nan=False)
    assert json.loads(text)["sessions"] == [json.loads(json.dumps(sg.zaznam(r, "strukturovany", SEED,
                                                                            working_copy()))) for r in rows]
    assert (doc["schema"], doc["rule"], doc["classes"], doc["rezim"], doc["seed"]) == (
        sg.SCHEMA, sg.GENERATOR_RULE, sg.TRIEDY, "strukturovany", SEED)
    assert (doc["load_rule"], doc["change_rule"], doc["unscored_rule"], doc["controls_json_rule"]) == (
        sg.LOAD_RULE, sg.CHANGE_RULE, sg.UNSCORED_RULE, sg.CONTROLS_JSON_RULE)
    with pytest.raises(ValueError, match=r"^the rows of generator\.json repeat the session g5-train-1#0 attempt 1$"):
        sg.generator_json([rows[0], rows[0]], "nulovy", SEED, working_copy())


@pytest.mark.parametrize("change, reason", [
    (lambda a: a.update(rezim="iny"), r"^the mode of the generator is nulovy or strukturovany, not 'iny'$"),
    (lambda a: a.update(seed=-1), r"^the seed of a run is an integer of at least 0$"),
    (lambda a: a.update(seed=True), r"^the seed of a run is an integer of at least 0$"),
    (lambda a: a.update(protokol=real()), r"^scenarios\.eshop_high\.rate is None: the counts of the generators depend "
                                          r"on the offered load"),
    (lambda a: a["row"].update(group="x5-train-1"), r"^group 'x5-train-1' starts with the prefix of no plan mode"),
    (lambda a: a["row"].update(position=7), r"^the row v5-train-1#7 is no session of the campaign plan"),
    (lambda a: a["row"].update(attempt=0), r"^a row of the plan states its attempt, an integer of at least 1$"),
    (lambda a: a.update(protokol=dict(working_copy(), schema="hyptcn3/collection-protocol/2")),
     r"^the generators of the dry run take a protocol of schema 3"),
])
def test_a_wrong_input_is_refused_by_name(change, reason):
    args = {"row": copy.deepcopy(plan("campaign")["sessions"][0]), "rezim": "nulovy", "seed": SEED,
            "protokol": working_copy()}
    change(args)
    with pytest.raises(ValueError, match=reason):
        sg.riadky(args["row"], args["rezim"], args["seed"], args["protokol"])


@pytest.mark.parametrize("row, start, reason", [
    (lambda: plan("campaign")["sessions"][rows_of("campaign", "test_benign")[0]], 1e9,
     r"^controls\.json belongs to a session of role test_controls only$"),
    (lambda: plan("campaign")["sessions"][rows_of("campaign", "test_controls")[0]], math.nan,
     r"^measure_start_unix is a finite number of seconds$"),
    (lambda: plan("campaign")["sessions"][rows_of("campaign", "test_controls")[0]], True,
     r"^measure_start_unix is a finite number of seconds$"),
])
def test_controls_json_refuses_by_name(row, start, reason):
    with pytest.raises(ValueError, match=reason):
        sg.controls_json(row(), start)


def test_invalid_rows_that_would_leave_an_occurrence_evaluable_are_refused_by_name():
    """GENERATOR_RULE: under a protocol whose invalid_rows.max and window_rows leave at least
    analysis.evaluable.scored_share of the first seconds of the chosen event scored (here max 1 and a window of 4 rows:
    1 + 4 of the 12 rows of the first 60 s unscored, 7 x 5 s / 60 s = 0.583 scored), the session is refused by name
    instead of carrying an evaluable occurrence that generator.json would call the known answer."""
    p = copy.deepcopy(working_copy())
    p.update(window_rows=4, invalid_rows=dict(p["invalid_rows"], max=1))
    where = next(w for w, c in sg._choices(p, "campaign", SEED)["invalid"].items() if c["role"] == "test_benign")
    row = next(s for s in protocol_v5.plan(p, "campaign")["sessions"] if (s["group"], s["position"]) == where)
    with pytest.raises(ValueError, match=r"^the tolerated invalid rows \[\d+\] of v5-test_benign-\d+#\d leave "
                                         r"0\.583333 of the first 60 s of its occurrence scored, not less than "
                                         r"analysis\.evaluable\.scored_share"):
        sg.riadky(row, "nulovy", SEED, p)
