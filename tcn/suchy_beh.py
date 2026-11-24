"""The pure part of the G1 dry run (protocol v5, G1 preparation, package C2): the bounds m from the null runs, the
decisions at an m, and the readers of the known answers of proposal 10.2.

Binding texts: the skeleton dokazy/G1/kostra/KOSTRA.md (row C2 of section 1, the known answers of section 2), the
lead's answer to questions Q32 to Q41 (2026-11-24T21:25Z: Q33 the unit of the percentile is the run, Q32 the grids and
the column mask, Q34 m null at stage suchy, Q36 the marginal change in the structured runs only, Q41 the diagnostics
where they are evaluated), proposal 6.4, 8.4, 8.5, 10.2 and 10.9. Nothing here runs the chain: the command that does,
python -m tcn.suchy_beh beh ..., is package C3's, and main() refuses every call but --help.

    hranice_m(zaznamy)          the bounds m of K1, K2a and K2b from the records of the null runs (BOUND_RULE), with
                                their derivation, the numbers beside them (BESIDE_RULE), the flag of the spread
                                between the methods of a claim (SPREAD_RULE), and the grids and the column mask the
                                runs used
    rozhodnutia(zaznamy, m)     the outcome of every claim of every run at the bounds m (DECISION_RULE)
    bez_jedneho(zaznamy)        every null run decided at the bounds of the other runs (LEAVE_ONE_OUT_RULE)
    okrajova_zmena(zaznam, generator)
                                the marginal changes of a run: the alarm edge of Z1 as fitted and of the replay of M of
                                every seed within analysis.horizon_s (MARGINAL_RULE)
    neskorovane(zaznam, generator)
                                the inserted invalid rows and the occurrences whose first seconds are scored less than
                                half (UNSCORED_RULE)
    diagnostiky(zaznam)         the threshold-likeness of Z1, Z2 and Z3 by the tree and the share of one member
                                (DIAGNOSTICS_RULE)
    strukturovane(zaznam, m=None)
                                the three claims of M and the same claims of the model with shuffled context and of the
                                network with random weights (STRUCTURED_RULE)

A record (zaznam) is the record of tcn.finalne of one dry run, complete and of stage suchy: its JSON object, or the
path of its file. zaznamy maps the name of every run (a text; package C3: <generator>_<seed>) to its record. The
values per boot and the intervals are the record's (tcn/finalne.py M_NULL_RULE: undecided at a null m, and
CONTROL_CLAIMS_RULE). generator is the run's generator.json (package C1), of which the readers read GENERATOR_KEYS
only. Every refusal is a ValueError that names its reason.
"""
import json
import math
from pathlib import Path
import sys

import numpy as np

from scripts.protocol_v5 import CLAIMS, GRIDDED

SCHEMA_BOUNDS = "hyptcn3/g1-bounds/1"
SCHEMA_DECISIONS = "hyptcn3/g1-decisions/1"
SCHEMA_LEAVE_ONE_OUT = "hyptcn3/g1-leave-one-out/1"
SCHEMA_MARGINAL = "hyptcn3/g1-marginal-change/1"
SCHEMA_UNSCORED = "hyptcn3/g1-unscored/1"
SCHEMA_DIAGNOSTICS = "hyptcn3/g1-diagnostics/1"
SCHEMA_STRUCTURED = "hyptcn3/g1-structured/1"
PERCENTILE = 0.95  # Proposal 8.4 and 10.9: "95. percentil" (numpy quantile, method linear: the skeleton's).
MIN_RUNS = 20  # Proposal 8.4 and 10.2: "aspoň 20 seedov" (analysis.<claim>.rule: "on >= 20 structure-free seeds").
# The lead's numbers (his answer to Q33, 2026-11-24T21:25Z): the spread between the methods of a claim he wants to
# see before m is written, and the normal quantile of the mean + 1.645 SD written beside the bound.
SPREAD_BOUND = {"k1": 0.02, "k2a": 0.05, "k2b": 0.05}
NORMAL_QUANTILE = 1.645
SD_DDOF = 1  # The executor's judgment, G1 preparation: the sample standard deviation of the 20 point estimates.
OK_OUTCOMES = ("not_better", "undecided")  # Proposal 10.2, the null generator: "nie lepší" or "nerozhodnuté".
# The values of the protocol a record of tcn.finalne carries (values.corpus.protocol_values, tcn/finalne.py
# RECORDED_VALUES): the grids and the column mask of the lead's answer to Q32, and the horizon of the marginal change.
COLUMNS, HORIZON = "analysis.columns", "analysis.horizon_s"
GRIDS = {method: f"analysis.methods.{method}.grid" for method in GRIDDED}
INVALID_REASON = "invalid_input"  # safeguard/features.py WindowBuffer: the reason of a replay row of an invalid frame.
NEURAL_SOURCE = "model_anomaly"  # safeguard/runtime.py SOURCES: the source of the neural channel.

# ------------------------------------------------------------------ the rules (written into every output)

BOUND_RULE = (
    "the bound m of a claim (proposal 8.4 and 10.9: the 95th percentile on at least 20 runs of the generator without "
    "structure; the lead's answer to Q33, 2026-11-24T21:25Z: the unit of the percentile is the run, not the boot): for "
    "every method of analysis.<claim>.compare the 95th percentile (numpy quantile 0.95, method linear) of its point "
    "estimates, one per null run, each the mean over the run's boots of its values per boot, the statistic around "
    "which tcn/tvrdenia.py builds the interval (K1: I, M by the median of its seeds; K2a and K2b: D); m of the claim "
    "the maximum over its methods, and set_by the methods that reach it; at least MIN_RUNS complete dry runs of stage "
    "suchy whose records name the same methods, the same grids of Z1, Z3 and Z5 and the same column mask (the lead's "
    "answer to Q32: m depends on what M is compared with), which the bounds write beside them; a claim that is "
    "nevyhodnotené in a run has no point estimate there, and the bound is refused by name")
BESIDE_RULE = (
    "beside every bound, with no effect on it (the lead's answer to Q33): the percentile of every method on its own, "
    "the 95th percentile of the values per boot pooled over the runs and its maximum over the methods (the skeleton's "
    "earlier reading), the mean + 1.645 standard deviations of the point estimates and its maximum over the methods "
    "(1.645 the lead's number; the standard deviation with ddof 1, the executor's judgment, G1 preparation), and the "
    "point estimates themselves, by run")
SPREAD_RULE = (
    "the flag of the spread between the methods of a claim (the lead's answer to Q33): raised when the percentiles of "
    "the methods of one claim differ by more than SPREAD_BOUND (K1 0.02, K2a and K2b 0.05; the lead's numbers), that "
    "is when the largest minus the smallest of them is above it; the coordinator reads it before m is written into the "
    "protocol, since the maximum over the methods then judges the comparison with the weaker bound")
DECISION_RULE = (
    "the outcome of a claim of a run at a bound m (proposal 8.4; tcn/finalne.py M_NULL_RULE): tcn.tvrdenia vysledok of "
    "the intervals its record writes for the methods of analysis.<claim>.compare, which is the decision a run at that "
    "m writes; a claim nevyhodnotené in the record (no class of the interventions evaluated) stays nevyhodnotené with "
    "outcome null; a record decided at the same m whose outcome is not that vysledok is refused by name; per claim the "
    "count of every outcome and the exceptions, the runs whose outcome is neither not_better nor undecided (proposal "
    "10.2: the null generator gives 'nie lepší' or 'nerozhodnuté' with at most one exception of 20)")
LEAVE_ONE_OUT_RULE = (
    "the check out of sample of the lead's answer to Q33: for every null run the bound of every claim from the other "
    "runs alone (BOUND_RULE on every run but that one, 19 of 20) and that run's outcome at it (DECISION_RULE), with "
    "the exceptions per claim; the criterion null_generator is read from this table and from the decisions at the "
    "bounds of all the runs, each with at most one exception")
GENERATOR_KEYS = (
    "the keys of a run's generator.json (package C1) that these readers read, every other key ignored: sessions, an "
    "object {session id: entry} with an entry for every session the generator changed, and in every entry three lists: "
    "invalid_rows, the seq of every inserted invalid row (integers); marginal_changes, every inserted marginal change "
    "{first_seq, rows, column}: the seq of its first row, its number of rows and the TCN input it steps; and "
    "unevaluated, every occurrence whose first analysis.evaluable.first_s seconds the inserted rows leave scored less "
    "than analysis.evaluable.scored_share, {what: event or control, index: its position among the events of the "
    "session's events.json, or among the controls of its controls.json that have a kind, and type: the event's type or "
    "the control's kind}")
MARGINAL_RULE = (
    "the known answer of the marginal change (proposal 10.2: 'vložená okrajová zmena: zachytí ju Z1 aj M'; the "
    "skeleton of G1, section 2; the lead's answer to Q36: only in the structured runs): for every change of the run's "
    "generator.json, t0 the time of its first row in the attachment series and its horizon the rows of its session "
    "with t0 <= t <= t0 + analysis.horizon_s (closed, as tcn/k2.py DETECTION_RULE); Z1 as fitted (the one label of "
    "name Z1 in the series, at its matched threshold) catches it when an alarm begins (edge) at a row of the horizon, "
    "and the replay of M of a seed when its alarm_event is true at such a row (some channel rises; the sources that "
    "rise there are reported, the neural one apart); a change some row of which Z1 or a replay leaves unscored (score "
    "NaN) lies in an unscored stretch and is listed apart, judged by neither; it holds when every change outside the "
    "unscored stretches is caught by Z1 and by the replay of every seed, and is null without such a change; the "
    "candidate Z1 chose on dev is reported (the skeleton's risk: a candidate difference sees a step only at its edge)")
UNSCORED_RULE = (
    "the known answer of the unscored stretches (proposal 6.4 and 10.2; the skeleton of G1, section 2): every run of "
    "consecutive inserted invalid rows of a replayed session lies in an unscored stretch of its replays "
    "(opisné.unscored, safeguard.runtime UNSCORED_RULE) and of O1, the unscored time of the block v5 of every seed (o2 "
    "for test_benign, o4 for test_controls), nevyhodnotené, and the rows of reason invalid_input of the session's "
    "stretches are exactly the inserted ones; a session that is not replayed (a role without a seal: train, dev, "
    "calibration) is listed apart; an event whose first seconds are scored less than half is nevyhodnotené in O3 of "
    "every seed, listed under not_evaluable and out of its denominator, the evaluable occurrences; such a control is "
    "nevyhodnotené in O4 of every seed with its unscored time, and stays in O4's denominator, the planned occurrences "
    "(proposal 6.4: 'Pri citlivosti (O4, K2) je menovateľom počet plánovaných výskytov'; the nearest reading of the "
    "skeleton's 'v žiadnom menovateli alarmov' is the denominators of the false alarms); it holds when every one of "
    "these holds")
DIAGNOSTICS_RULE = (
    "the known answer of the diagnostics (proposal 8.5 and 10.2: the tree and the share of one member mark Z1 to Z3 "
    "threshold-like; the lead's answer to Q41): opisné.diagnostics.threshold_likeness (tcn/diagnostiky.py TREE_RULE, "
    "ONE_MEMBER_RULE, USE_RULE) for Z1, Z2 and Z3; a diagnostic is evaluated in the run when none of the three is "
    "nevyhodnotené there (fewer than analysis.diagnostics.min_positive_episodes positive episodes), and then it must "
    "mark all three threshold-like, which is its used; the run counts only when both diagnostics are evaluated, and "
    "holds is null otherwise")
STRUCTURED_RULE = (
    "the known answer of the structured generator (proposal 10.2: K1 and K2 come out better, the model with shuffled "
    "context and the network with random weights do not): the outcomes of K1, K2a and K2b (DECISION_RULE) and of the "
    "same claims of the two networks (tcn/finalne.py CONTROL_CLAIMS_RULE, opisné.diagnostics.claims), all by "
    "tcn.tvrdenia vysledok of the record's intervals at the bounds m given, or at those the record was decided at; it "
    "holds when the three claims of M are better and no claim of either network is")


# ------------------------------------------------------------------ reading the records


def _finalne():
    from tcn import finalne  # Inside: it imports torch, which --help needs not.
    return finalne


def _cislo(x):
    return isinstance(x, (int, float, np.integer, np.floating)) and not isinstance(x, (bool, np.bool_)) \
        and math.isfinite(x)


def _hodnoty(zaznam, kto):
    """The values of a record of tcn.finalne (its JSON object or the path of its file): a complete record of stage
    suchy, else refused by name."""
    from tcn.pecat import DRY_STAGE
    finalne = _finalne()
    if isinstance(zaznam, (str, Path)):
        try:
            zaznam = json.loads(Path(zaznam).read_text())
        except (OSError, ValueError) as error:
            raise ValueError(f"{kto}: the record cannot be read ({type(error).__name__}: {error})") from None
    if type(zaznam) is not dict or zaznam.get("schema") != finalne.SCHEMA or type(zaznam.get("values")) is not dict:
        raise ValueError(f"{kto}: no record of tcn.finalne (schema {finalne.SCHEMA})")
    values = zaznam["values"]
    if zaznam.get("stage") != DRY_STAGE or values.get("stage") != DRY_STAGE:
        raise ValueError(f"{kto}: a record of stage {zaznam.get('stage')!r}; the tools of G1 read the dry runs only, "
                         f"stage {DRY_STAGE} (tcn/pecat.py STAGE_RULE)")
    if values.get("status") != "complete":
        raise ValueError(f"{kto}: a record of status {values.get('status')!r}; a failed run gives no number "
                         "(tcn/finalne.py FAILURE_RULE)")
    return values


def _behy(zaznamy):
    """{run: values} of `zaznamy` {run: record}, in its order."""
    if type(zaznamy) is not dict or not zaznamy:
        raise ValueError("zaznamy maps the name of every run to its record, one run or more")
    out = {}
    for name, zaznam in zaznamy.items():
        if type(name) is not str or not name:
            raise ValueError(f"the name of a run is a non-empty text, not {name!r}")
        out[name] = _hodnoty(zaznam, f"run {name}")
    return out


def _tvrdenie(values, claim, kto):
    """(status, compare, the claim's record) of the claim in the values of a record; compare None when the claim is
    nevyhodnotené there. Every method of compare has values per boot (finite numbers) and an interval [low, high]."""
    finalne = _finalne()
    record = (values.get("claims") or {}).get(claim)
    conclusion = (values.get("conclusions") or {}).get(claim)
    if type(record) is not dict or type(conclusion) is not dict:
        raise ValueError(f"{kto}: the record has no claim {claim} with its conclusion")
    status = conclusion.get("status")
    if status == finalne.UNEVALUATED:
        return status, None, record
    if status != finalne.EVALUATED:
        raise ValueError(f"{kto}: the claim {claim} has the status {status!r}")
    compare, methods = record.get("compare"), record.get("methods")
    if type(compare) is not list or not compare or type(methods) is not dict or list(methods) != compare:
        raise ValueError(f"{kto}: the claim {claim} has no values of every method of its compare")
    for z in compare:
        item = methods[z]
        interval = item.get("interval") if type(item) is dict else None
        if not (type(item) is dict and type(item.get("values")) is dict and len(item["values"]) >= 1
                and all(_cislo(x) for x in item["values"].values()) and type(interval) in (list, tuple)
                and len(interval) == 2 and all(_cislo(x) for x in interval) and interval[0] <= interval[1]):
            raise ValueError(f"{kto}: the method {z} of the claim {claim} has no values per boot and interval")
    return status, compare, record


def _odhad(item, kto, claim, z):
    """(the point estimate, the values per boot) of one method of a claim: the mean of its values in the order of the
    boots (sorted, as tcn.tvrdenia rozhodni computes it), which must be the mean its record writes."""
    x = [float(item["values"][boot]) for boot in sorted(item["values"])]
    mean = float(np.mean(x))
    if item.get("mean") != mean:
        raise ValueError(f"{kto}: the mean {item.get('mean')!r} of {claim}/{z} in the record is not the mean of its "
                         f"values per boot ({mean!r})")
    return mean, x


def _kopia(values, kto):
    """The grids of Z1, Z3 and Z5 and the column mask the run used (the lead's answer to Q32): the protocol values its
    record carries (values.corpus.protocol_values, tcn/finalne.py RECORDED_VALUES), the grids checked against those
    of its fits (values.methods)."""
    recorded = (values.get("corpus") or {}).get("protocol_values")
    if type(recorded) is not dict or not all(path in recorded for path in (COLUMNS, *GRIDS.values())):
        raise ValueError(f"{kto}: the record names no grids and column mask of its run (values.corpus.protocol_values, "
                         "tcn/finalne.py RECORDED_VALUES)")
    fits = values.get("methods") if type(values.get("methods")) is dict else {}
    for method, path in GRIDS.items():
        found = [fit.get("grid") for fit in fits.values() if type(fit) is dict and fit.get("name") == method]
        if found != [recorded[path]]:
            raise ValueError(f"{kto}: the fit of {method} used the grid {found!r}, the record names {path} "
                             f"{recorded[path]!r}")
    return {"grids": {method: recorded[path] for method, path in GRIDS.items()}, "columns": recorded[COLUMNS]}


def _odhady(behy):
    """{claim: {compare, statistic, estimates {method: {run: point estimate}}, pooled {method: [values per boot of
    every run]}}} of the runs; every run names the same methods, and no claim is nevyhodnotené in a run."""
    out = {}
    for claim in CLAIMS:
        found = {"compare": None, "statistic": None, "estimates": {}, "pooled": {}}
        for name, values in behy.items():
            kto = f"run {name}"
            status, compare, record = _tvrdenie(values, claim, kto)
            if compare is None:
                raise ValueError(f"{kto}: the claim {claim} is nevyhodnotené there ({record.get('why')}), so the run "
                                 f"has no point estimate of it (BOUND_RULE)")
            if found["compare"] is None:
                found.update(compare=compare, statistic=record.get("statistic"),
                             estimates={z: {} for z in compare}, pooled={z: [] for z in compare})
            elif compare != found["compare"]:
                raise ValueError(f"{kto}: the claim {claim} compares {compare}, the runs before it {found['compare']}")
            for z in compare:
                mean, x = _odhad(record["methods"][z], kto, claim, z)
                found["estimates"][z][name] = mean
                found["pooled"][z].extend(x)
        out[claim] = found
    return out


def _percentil(values):
    return float(np.quantile(np.asarray(values, dtype=float), PERCENTILE, method="linear"))


def _m(odhady, runs):
    """{claim: m} from the point estimates of the runs `runs` (BOUND_RULE)."""
    return {claim: max(_percentil([found["estimates"][z][run] for run in runs]) for z in found["compare"])
            for claim, found in odhady.items()}


def _hranice_dane(m):
    """The bounds m given: exactly one finite number per claim."""
    if type(m) is not dict or set(m) != set(CLAIMS) or not all(_cislo(m[claim]) for claim in CLAIMS):
        raise ValueError(f"the bounds m are {{{', '.join(CLAIMS)}}} with a finite number each, not {m!r}")
    return {claim: float(m[claim]) for claim in CLAIMS}


# ------------------------------------------------------------------ the bounds m and the decisions


def hranice_m(zaznamy):
    """BOUND_RULE, BESIDE_RULE and SPREAD_RULE over the records of the null runs `zaznamy` {run: record}: {schema, m
    {claim: number}, runs, claims {claim: {m, set_by, compare, statistic, methods {method: {count, point_estimates
    {run: value}, percentile, mean, sd, mean_plus_1645_sd, pooled_boot_values {count, percentile}}},
    pooled_boot_percentile, mean_plus_1645_sd, spread, spread_bound, spread_flag}}, flag {raised, claims, rule}, grids,
    columns, rules}. The flag is the field the coordinator reads before m is written into the protocol."""
    behy = _behy(zaznamy)
    if len(behy) < MIN_RUNS:
        raise ValueError(f"{len(behy)} null runs: the bound m is the 95th percentile on at least {MIN_RUNS} runs of "
                         "the generator without structure (proposal 8.4 and 10.2; BOUND_RULE)")
    kopie = {name: _kopia(values, f"run {name}") for name, values in behy.items()}
    first = next(iter(kopie))
    other = [name for name, kopia in kopie.items() if kopia != kopie[first]]
    if other:
        raise ValueError(f"run {other[0]} used other grids of Z1, Z3 and Z5 or another column mask than run {first}: "
                         "the bound m is one family of comparisons (the lead's answer to Q32; BOUND_RULE)")
    odhady = _odhady(behy)
    names = list(behy)
    claims = {}
    for claim, found in odhady.items():
        methods = {}
        for z in found["compare"]:
            x = [found["estimates"][z][name] for name in names]
            mean, sd = float(np.mean(x)), float(np.std(x, ddof=SD_DDOF))
            methods[z] = {"count": len(x), "point_estimates": dict(found["estimates"][z]), "percentile": _percentil(x),
                          "mean": mean, "sd": sd, "mean_plus_1645_sd": mean + NORMAL_QUANTILE * sd,
                          "pooled_boot_values": {"count": len(found["pooled"][z]),
                                                 "percentile": _percentil(found["pooled"][z])}}
        percentiles = [methods[z]["percentile"] for z in found["compare"]]
        m = max(percentiles)
        spread = max(percentiles) - min(percentiles)
        claims[claim] = {
            "m": m, "set_by": [z for z in found["compare"] if methods[z]["percentile"] == m],
            "compare": found["compare"], "statistic": found["statistic"], "methods": methods,
            "pooled_boot_percentile": max(methods[z]["pooled_boot_values"]["percentile"] for z in found["compare"]),
            "mean_plus_1645_sd": max(methods[z]["mean_plus_1645_sd"] for z in found["compare"]),
            "spread": spread, "spread_bound": SPREAD_BOUND[claim], "spread_flag": spread > SPREAD_BOUND[claim]}
    raised = [claim for claim in CLAIMS if claims[claim]["spread_flag"]]
    return {"schema": SCHEMA_BOUNDS, "m": {claim: claims[claim]["m"] for claim in CLAIMS}, "runs": names,
            "claims": claims, "flag": {"raised": bool(raised), "claims": raised, "rule": SPREAD_RULE},
            "grids": kopie[first]["grids"], "columns": kopie[first]["columns"],
            "rules": {"bound": BOUND_RULE, "beside": BESIDE_RULE, "spread": SPREAD_RULE}, "numpy": np.__version__}


def _rozhodni(values, m, kto):
    """DECISION_RULE for the claims of one run at the bounds m {claim: number} (a claim nevyhodnotené there needs
    none)."""
    from tcn.tvrdenia import vysledok
    finalne = _finalne()
    out = {}
    for claim in CLAIMS:
        status, compare, record = _tvrdenie(values, claim, kto)
        if compare is None:
            out[claim] = {"outcome": None, "status": status, "why": record.get("why"), "intervals": None,
                          "record_m": None, "record_outcome": None}
            continue
        intervals = {z: list(record["methods"][z]["interval"]) for z in compare}
        outcome = vysledok(intervals, m[claim])
        record_m, record_outcome = record.get("m"), record.get("outcome")
        if record_m is not None and record_m == m[claim] and record_outcome != outcome:
            raise ValueError(f"{kto}: the claim {claim} was decided {record_outcome!r} at m {record_m!r}, but "
                             f"tcn.tvrdenia vysledok of its intervals at that m is {outcome!r} (DECISION_RULE)")
        out[claim] = {"outcome": outcome, "status": finalne.EVALUATED, "intervals": intervals, "record_m": record_m,
                      "record_outcome": record_outcome}
    return out


def _pocty(decided):
    """{claim: {counts {outcome: n}, exceptions [runs]}} of {run: {claim: decision}}."""
    finalne = _finalne()
    out = {}
    for claim in CLAIMS:
        keys = [d[claim]["outcome"] or d[claim]["status"] for d in decided.values()]
        counts = {key: keys.count(key) for key in ("better", "not_better", "undecided", finalne.UNEVALUATED)}
        out[claim] = {"counts": counts, "exceptions": [run for run, d in decided.items()
                                                       if d[claim]["outcome"] not in OK_OUTCOMES]}
    return out


def rozhodnutia(zaznamy, m):
    """DECISION_RULE: the outcome of every claim of every run of `zaznamy` {run: record} at the bounds m {k1, k2a,
    k2b: number}: {schema, m, runs {run: {claim: {outcome, status, why?, intervals, record_m, record_outcome}}}, claims
    {claim: {counts, exceptions}}, rule}. One run is a mapping of one name (the verifier's null run of seed 20)."""
    m = _hranice_dane(m)
    behy = _behy(zaznamy)
    decided = {name: _rozhodni(values, m, f"run {name}") for name, values in behy.items()}
    return {"schema": SCHEMA_DECISIONS, "m": m, "runs": decided, "claims": _pocty(decided), "rule": DECISION_RULE}


def bez_jedneho(zaznamy):
    """LEAVE_ONE_OUT_RULE over the records of the null runs `zaznamy` {run: record}: {schema, runs {run: {m {claim: the
    bound of the other runs}, claims {claim: decision}}}, claims {claim: {counts, exceptions}}, rule}."""
    behy = _behy(zaznamy)
    if len(behy) < MIN_RUNS:
        raise ValueError(f"{len(behy)} null runs: the table leaves one out of the at least {MIN_RUNS} runs of the "
                         "bound (LEAVE_ONE_OUT_RULE, BOUND_RULE)")
    odhady = _odhady(behy)
    names = list(behy)
    runs = {}
    for name in names:
        m = _m(odhady, [other for other in names if other != name])
        runs[name] = {"m": m, "claims": _rozhodni(behy[name], m, f"run {name}")}
    return {"schema": SCHEMA_LEAVE_ONE_OUT, "runs": runs,
            "claims": _pocty({name: run["claims"] for name, run in runs.items()}), "rule": LEAVE_ONE_OUT_RULE}


# ------------------------------------------------------------------ the readers of the known answers


def _generator(generator):
    """{session: {invalid_rows, marginal_changes, unevaluated}} of a generator.json (GENERATOR_KEYS), checked."""
    if isinstance(generator, (str, Path)):
        try:
            generator = json.loads(Path(generator).read_text())
        except (OSError, ValueError) as error:
            raise ValueError(f"generator.json cannot be read ({type(error).__name__}: {error})") from None
    sessions = generator.get("sessions") if type(generator) is dict else None
    if type(sessions) is not dict:
        raise ValueError("generator.json has no object sessions (GENERATOR_KEYS)")
    out = {}
    for ident, entry in sessions.items():
        if type(entry) is not dict or not all(type(entry.get(key)) is list
                                              for key in ("invalid_rows", "marginal_changes", "unevaluated")):
            raise ValueError(f"generator.json: the session {ident} has no lists invalid_rows, marginal_changes and "
                             "unevaluated (GENERATOR_KEYS)")
        if not all(type(seq) is int for seq in entry["invalid_rows"]) or len(set(entry["invalid_rows"])) != len(
                entry["invalid_rows"]):
            raise ValueError(f"generator.json: the invalid rows of session {ident} are distinct integers (seq)")
        for change in entry["marginal_changes"]:
            if not (type(change) is dict and type(change.get("first_seq")) is int and type(change.get("rows")) is int
                    and change["rows"] >= 1 and type(change.get("column")) is str):
                raise ValueError(f"generator.json: a marginal change of session {ident} is {{first_seq, rows, column}}")
        for item in entry["unevaluated"]:
            if not (type(item) is dict and item.get("what") in ("event", "control") and type(item.get("index")) is int
                    and item["index"] >= 0 and type(item.get("type")) is str):
                raise ValueError(f"generator.json: an unevaluated occurrence of session {ident} is {{what: event or "
                                 "control, index, type}}")
        out[ident] = entry
    return out


def _priloha(values, name):
    """The arrays of the attachment `name` of a record (tcn/finalne.py ATTACHMENT_RULE): the file at its path, of the
    sha256 the record names, read with allow_pickle=False."""
    import hashlib
    item = (values.get("attachments") or {}).get(name)
    if type(item) is not dict or type(item.get("path")) is not str:
        raise ValueError(f"the record names no attachment {name} (tcn/finalne.py ATTACHMENT_RULE)")
    path = Path(item["path"])
    try:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ValueError(f"the attachment {name} {path} cannot be read ({type(error).__name__}: {error})") from None
    if digest != item.get("sha256"):
        raise ValueError(f"the attachment {name} {path} is not the one its record names (sha256)")
    with np.load(path, allow_pickle=False) as data:
        return {key: data[key] for key in data.files}


def _rad(series, ident, kto):
    """(the first row, the rows) of session `ident` in the attachment series."""
    found = np.flatnonzero(series["session_id"] == ident)
    if len(found) != 1:
        raise ValueError(f"{kto}: the session {ident} is no session of the attachment series (test_benign, "
                         "test_controls)")
    i = int(found[0])
    return int(series["session_first_row"][i]), int(series["session_rows"][i])


def _hrana(edges, times, t0):
    """(whether an edge lies in the horizon, the seconds from t0 to the first one or None)."""
    at = np.flatnonzero(edges)
    return (bool(len(at)), float(times[at[0]] - t0) if len(at) else None)


def okrajova_zmena(zaznam, generator):
    """MARGINAL_RULE over the record of one run and its generator.json: {schema, horizon_s, z1 {label, chosen},
    changes [{session, first_seq, rows, column, start_unix, horizon_rows, in_unscored_stretch, z1 {caught,
    first_edge_s, scored}, replays {seed: {caught, first_edge_s, sources, neural, scored}}}], judged, listed_apart,
    caught {Z1, seed <s>: number}, holds, rule}."""
    values = _hodnoty(zaznam, "the record")
    sessions = _generator(generator)
    recorded = (values.get("corpus") or {}).get("protocol_values") or {}
    horizon = recorded.get(HORIZON)
    if not _cislo(horizon) or horizon <= 0:
        raise ValueError(f"the record names no {HORIZON} of its run (values.corpus.protocol_values)")
    series = _priloha(values, "series")
    z1 = np.flatnonzero(series["label_name"] == "Z1")
    if len(z1) != 1:
        raise ValueError("the attachment series holds no one label of Z1 (SERIES_RULE)")
    z1 = int(z1[0])
    z1_fit = next((fit for fit in (values.get("methods") or {}).values()
                   if type(fit) is dict and fit.get("name") == "Z1"), {})
    sources = [str(x) for x in series["sources"]]
    neural = sources.index(NEURAL_SOURCE)
    seeds = [int(x) for x in series["replay_seed"]]
    changes = []
    for ident, entry in sessions.items():
        for change in entry["marginal_changes"]:
            kto = f"the marginal change at seq {change['first_seq']} of session {ident}"
            first, count = _rad(series, ident, kto)
            seq, times = series["row_seq"][first:first + count], series["row_time"][first:first + count]
            changed = np.flatnonzero((seq >= change["first_seq"]) & (seq < change["first_seq"] + change["rows"]))
            if len(changed) != change["rows"] or np.any(np.diff(changed) != 1):
                raise ValueError(f"{kto}: its {change['rows']} rows are not consecutive rows of the session")
            t0 = float(times[changed[0]])
            horizon_rows = np.flatnonzero((times >= t0) & (times <= t0 + horizon))
            rows, inside = first + changed, first + horizon_rows
            caught, edge_s = _hrana(series["edge"][z1, inside], series["row_time"][inside], t0)
            item = {"session": ident, "first_seq": change["first_seq"], "rows": change["rows"],
                    "column": change["column"], "start_unix": t0, "horizon_rows": int(len(horizon_rows)),
                    "z1": {"caught": caught, "first_edge_s": edge_s,
                           "scored": bool(np.isfinite(series["score"][z1, rows]).all())}, "replays": {}}
            for j, seed in enumerate(seeds):
                caught, edge_s = _hrana(series["replay_alarm_event"][j, inside], series["row_time"][inside], t0)
                at = np.flatnonzero(series["replay_alarm_event"][j, inside])
                item["replays"][str(seed)] = {
                    "caught": caught, "first_edge_s": edge_s,
                    "sources": [sources[k] for k in np.flatnonzero(series["replay_sources"][j, inside[at[0]]])]
                    if len(at) else [],
                    "neural": bool(series["replay_sources"][j, inside, neural].any()),
                    "scored": bool(np.isfinite(series["replay_score"][j, rows]).all())}
            item["in_unscored_stretch"] = not (item["z1"]["scored"]
                                               and all(r["scored"] for r in item["replays"].values()))
            changes.append(item)
    judged = [item for item in changes if not item["in_unscored_stretch"]]
    caught = {"Z1": sum(item["z1"]["caught"] for item in judged),
              **{f"seed {seed}": sum(item["replays"][str(seed)]["caught"] for item in judged) for seed in seeds}}
    return {"schema": SCHEMA_MARGINAL, "horizon_s": horizon,
            "z1": {"label": str(series["label"][z1]), "chosen": z1_fit.get("chosen")}, "changes": changes,
            "judged": len(judged), "listed_apart": [item for item in changes if item["in_unscored_stretch"]],
            "caught": caught, "holds": None if not judged else all(n == len(judged) for n in caught.values()),
            "rule": MARGINAL_RULE, "generator_keys": GENERATOR_KEYS}


def _runy(seqs):
    """The runs of consecutive seq of `seqs`, [[first, last]]."""
    out = []
    for seq in sorted(seqs):
        if out and seq == out[-1][1] + 1:
            out[-1][1] = seq
        else:
            out.append([seq, seq])
    return out


def _v_useku(stretches, inserted):
    """Whether the inserted invalid rows `inserted` lie in the unscored stretches `stretches` (safeguard.runtime
    unscored): every run of them inside one stretch, whose rows of reason invalid_input are the inserted rows inside
    it, and no other row of that reason in the session."""
    finalne = _finalne()
    found, ok = [], True
    for low, high in _runy(inserted):
        mine = [s for s in stretches if s["first_seq"] <= low and s["last_seq"] >= high]
        if len(mine) != 1:
            ok = False
            found.append({"rows": [low, high], "stretch": None})
            continue
        s = mine[0]
        expected = sum(s["first_seq"] <= seq <= s["last_seq"] for seq in inserted)
        invalid = int((s.get("reasons") or {}).get(INVALID_REASON, 0))
        ok = ok and invalid == expected and s.get("status") == finalne.UNEVALUATED
        found.append({"rows": [low, high], "stretch": {key: s.get(key) for key in (
            "first_seq", "last_seq", "rows", "status")}, "invalid_input_rows": invalid, "inserted_in_it": expected})
    total = sum(int((s.get("reasons") or {}).get(INVALID_REASON, 0)) for s in stretches)
    return {"holds": ok and total == len(inserted), "runs": found, "invalid_input_rows": total}


def _v5(metrics, block, seed, kto):
    """The block v5 of the metric `block` (o2, o3, o4) of one seed in opisné.metrics."""
    found = ((metrics.get(block) or {}).get(seed) or {}).get("v5")
    if type(found) is not dict:
        raise ValueError(f"{kto}: the record has no block v5 of opisné.metrics.{block} of seed {seed}")
    return found


def _vyskyt(occurrences, ident, index, kto):
    mine = [item for item in occurrences if item.get("session") == ident]
    if not 0 <= index < len(mine):
        raise ValueError(f"{kto}: the session {ident} has {len(mine)} occurrences there, not one at index {index}")
    return mine[index]


def _udalost(metrics, seed, ident, item, kto):
    """UNSCORED_RULE for an event of `item` in O3 of one seed: nevyhodnotené, not evaluable, listed under not_evaluable
    and out of the denominator (the evaluable occurrences that ran)."""
    finalne = _finalne()
    o3 = _v5(metrics, "o3", seed, kto).get("o3") or {}
    found = _vyskyt(o3.get("occurrences") or [], ident, item["index"], kto)
    listed = any(other.get("session") == ident and other.get("start_unix") == found.get("start_unix")
                 and other.get("type") == found.get("type") for other in o3.get("not_evaluable") or [])
    ran = [other for other in o3.get("occurrences") or [] if other.get("executed")]
    denominator = (o3.get("total") or {}).get("evaluable")
    holds = (found.get("type") == item["type"] and found.get("status") == finalne.UNEVALUATED
             and found.get("evaluable") is False and listed
             and denominator == sum(other.get("evaluable") is True for other in ran))
    return {"type": found.get("type"), "status": found.get("status"), "evaluable": found.get("evaluable"),
            "first_s_scored_share": found.get("first_s_scored_share"), "listed_not_evaluable": listed,
            "denominator": denominator, "in_denominator": found.get("evaluable") is not False, "holds": holds}


def _kontrola(metrics, seed, ident, item, kto):
    """UNSCORED_RULE for a control of `item` in O4 of one seed: nevyhodnotené and not evaluable, with its unscored time
    (it stays in the denominator of O4, the planned occurrences: proposal 6.4)."""
    finalne = _finalne()
    o4 = _v5(metrics, "o4", seed, kto).get("o4") or {}
    found = _vyskyt(o4.get("occurrences") or [], ident, item["index"], kto)
    unscored = found.get("unscored_horizon_s")
    holds = (found.get("kind") == item["type"] and found.get("status") == finalne.UNEVALUATED
             and found.get("evaluable") is False and _cislo(unscored) and unscored > 0)
    return {"type": found.get("kind"), "status": found.get("status"), "evaluable": found.get("evaluable"),
            "first_s_scored_share": found.get("first_s_scored_share"), "unscored_horizon_s": unscored,
            "results": {output: (found.get("outputs") or {})[output].get("result")
                        for output in found.get("outputs") or {}},
            "denominator": "planned (proposal 6.4)", "in_denominator": True, "holds": holds}


def neskorovane(zaznam, generator):
    """UNSCORED_RULE over the record of one run and its generator.json: {schema, invalid_rows [{session, role, runs,
    replays, o1 {seed: ...}, holds}], not_replayed [...], events [...], controls [...], holds, rule}."""
    finalne = _finalne()
    values = _hodnoty(zaznam, "the record")
    sessions = _generator(generator)
    opisne = values.get(finalne.OPISNE) or {}
    unscored = (opisne.get("unscored") or {}).get("sessions") or {}
    metrics = opisne.get("metrics") or {}
    seeds = [str(model["seed"]) for model in values.get("models") or []]
    if not seeds:
        raise ValueError("the record names no bundle of M (values.models)")
    invalid, apart = [], []
    for ident, entry in sessions.items():
        if not entry["invalid_rows"]:
            continue
        if ident not in unscored:
            apart.append({"session": ident, "rows": len(entry["invalid_rows"]),
                          "why": "no replay of the session: a role without a seal (train, dev, calibration)"})
            continue
        role = unscored[ident].get("role")
        block = {"test_benign": "o2", "test_controls": "o4"}.get(role)
        if block is None:
            raise ValueError(f"the session {ident} of the record's unscored time has the role {role!r}")
        kto = f"the invalid rows of session {ident}"
        o1 = {}
        for seed in seeds:
            mine = (_v5(metrics, block, seed, kto).get("unscored") or {}).get("sessions", {}).get(ident)
            if type(mine) is not dict:
                raise ValueError(f"{kto}: O1 of seed {seed} has no unscored time of the session")
            o1[seed] = _v_useku(mine.get("stretches") or [], entry["invalid_rows"])
        replays = _v_useku(unscored[ident].get("stretches") or [], entry["invalid_rows"])
        invalid.append({"session": ident, "role": role, "inserted": _runy(entry["invalid_rows"]), "replays": replays,
                        "o1": o1, "holds": replays["holds"] and all(found["holds"] for found in o1.values())})
    events, controls = [], []
    for ident, entry in sessions.items():
        for item in entry["unevaluated"]:
            kto = f"the {item['what']} {item['index']} of session {ident}"
            judge = _udalost if item["what"] == "event" else _kontrola
            per = {seed: judge(metrics, seed, ident, item, kto) for seed in seeds}
            (events if item["what"] == "event" else controls).append(
                {"session": ident, "index": item["index"], "type": item["type"], "seeds": per,
                 "holds": all(found["holds"] for found in per.values())})
    every = [*invalid, *events, *controls]
    return {"schema": SCHEMA_UNSCORED, "invalid_rows": invalid, "not_replayed": apart, "events": events,
            "controls": controls, "holds": None if not every else all(item["holds"] for item in every),
            "rule": UNSCORED_RULE, "generator_keys": GENERATOR_KEYS}


def diagnostiky(zaznam):
    """DIAGNOSTICS_RULE over the record of one run: {schema, diagnostics {tree, one_member: {outcomes {Z1, Z2, Z3},
    positive_episodes, evaluated, used}}, models {label: {tree, one_member}}, evaluated, holds, rule}."""
    from tcn.diagnostiky import REFERENCE, THRESHOLD_LIKE
    finalne = _finalne()
    values = _hodnoty(zaznam, "the record")
    found = ((values.get(finalne.OPISNE) or {}).get("diagnostics") or {}).get("threshold_likeness")
    if type(found) is not dict or type(found.get("methods")) is not list or type(found.get("use")) is not dict:
        raise ValueError("the record has no opisné.diagnostics.threshold_likeness (tcn/diagnostiky.py USE_RULE)")
    rows = {}
    for row in found["methods"]:
        if row.get("name") in REFERENCE:
            if row["name"] in rows:
                raise ValueError(f"the diagnostics hold {row['name']} twice")
            rows[row["name"]] = row
    if sorted(rows) != sorted(REFERENCE):
        raise ValueError(f"the diagnostics hold {sorted(rows)}, not {', '.join(REFERENCE)}")
    out = {}
    for diagnostic in ("tree", "one_member"):
        outcomes = {name: rows[name][diagnostic]["outcome"] for name in REFERENCE}
        used = all(outcome == THRESHOLD_LIKE for outcome in outcomes.values())
        if used != (found["use"].get(diagnostic) or {}).get("used"):
            raise ValueError(f"the record says the {diagnostic} is used {found['use'].get(diagnostic)!r}, its outcomes "
                             f"for {', '.join(REFERENCE)} are {outcomes} (tcn/diagnostiky.py USE_RULE)")
        out[diagnostic] = {"outcomes": outcomes,
                           "positive_episodes": {name: rows[name][diagnostic].get("positive_episodes")
                                                 for name in REFERENCE},
                           "evaluated": all(outcome != finalne.UNEVALUATED for outcome in outcomes.values()),
                           "used": used}
    evaluated = all(item["evaluated"] for item in out.values())
    models = {row.get("label"): {d: row[d].get("outcome") for d in ("tree", "one_member")}
              for row in found["methods"] if row.get("name") == "M"}
    return {"schema": SCHEMA_DIAGNOSTICS, "diagnostics": out, "models": models, "evaluated": evaluated,
            "holds": all(item["used"] for item in out.values()) if evaluated else None, "rule": DIAGNOSTICS_RULE}


def strukturovane(zaznam, m=None):
    """STRUCTURED_RULE over the record of one structured run at the bounds m {k1, k2a, k2b: number}, or at those the
    record was decided at when m is None (refused when the record's bounds are null): {schema, m, m_origin, claims
    {claim: decision}, controls {network: {claim: decision}}, holds, rule}."""
    finalne = _finalne()
    values = _hodnoty(zaznam, "the record")
    if m is None:
        found = {}
        for claim in CLAIMS:
            status, compare, record = _tvrdenie(values, claim, "the record")
            found[claim] = record.get("m") if compare is not None else None
            if compare is not None and found[claim] is None:
                raise ValueError(f"the record's bound of {claim} is null (a dry run at m null, tcn/finalne.py "
                                 "M_NULL_RULE): strukturovane decides it at the bounds m given")
        m, origin = found, "record"
    else:
        m, origin = _hranice_dane(m), "given"
    claims = _rozhodni(values, m, "the record")
    controls = ((values.get(finalne.OPISNE) or {}).get("diagnostics") or {}).get("claims")
    if type(controls) is not dict or not all(type(controls.get(name)) is dict for name in finalne.STRUCTURE_CONTROLS):
        raise ValueError("the record carries no claims of the model with shuffled context and the network with random "
                         "weights (opisné.diagnostics.claims, tcn/finalne.py CONTROL_CLAIMS_RULE)")
    judged = {}
    for name in finalne.STRUCTURE_CONTROLS:
        mine = controls[name].get("claims") or {}
        per = {"claims": mine, "conclusions": {claim: {"status": (mine.get(claim) or {}).get("status")}
                                               for claim in CLAIMS}}
        judged[name] = _rozhodni(per, m, f"the network {name}")
    holds = (all(claims[claim]["outcome"] == "better" for claim in CLAIMS)
             and not any(found[claim]["outcome"] == "better" for found in judged.values() for claim in CLAIMS))
    return {"schema": SCHEMA_STRUCTURED, "m": m, "m_origin": origin, "claims": claims, "controls": judged,
            "holds": holds, "rule": STRUCTURED_RULE}


# ------------------------------------------------------------------ the command (package C3)


def main(argv=None):
    """The command entry of the G1 dry run belongs to package C3: every call but --help is refused."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--help"], ["-h"]):
        print(__doc__.rstrip())
        return 0
    print("tcn.suchy_beh: the command of the G1 dry run (beh, hranice, tabulka) is package C3's; this module holds the "
          "pure part of package C2 only (hranice_m, rozhodnutia, bez_jedneho, okrajova_zmena, neskorovane, "
          "diagnostiky, strukturovane)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
