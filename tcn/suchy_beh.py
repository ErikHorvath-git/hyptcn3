"""The G1 dry run (protocol v5, G1 preparation): its pure part (package C2), the bounds m from the null runs, the
decisions at an m and the readers of the known answers of proposal 10.2, and its command (package C3).

Binding texts: the skeleton dokazy/G1/kostra/KOSTRA.md (rows C2 and C3 of section 1, the known answers of section 2),
the lead's answer to questions Q32 to Q41 (2026-11-24T21:25Z: Q33 the unit of the percentile is the run, Q32 the grids
and the column mask, Q34 m null at stage suchy, Q36 the marginal change in the structured runs only, Q37 the threads,
Q38 the mask of one qualification pass per generator, Q41 the diagnostics where they are evaluated), point 5 of his
POKYNY_TEMPO_2026-11-25 (the shortened path), proposal 6.4, 7.5, 8.3, 8.4, 8.5, 10.2 and 10.9.

THE COMMAND (package C3):

    python -m tcn.suchy_beh beh --generator G --seed S --out DIR --praca WORK --cesta plna|skratena
                                [--protocol P] [--vysledky R] [--chyby]

One run from the plan to the report (Beh.run): scripts/gates.py require of G1 on the protocol file P (default
config/collection-v5.json; R, default data/results, holds its gate records) and on the working copy (COPY_RULE: the
rates, the grids of Z1, Z3 and Z5, analysis.columns of the qualification pass, MASK_RULE, and the limit of the
replacements; its hashes of G0 and G1 are the file's); the rehearsal and the campaign of the real scripts/campaign.py
on the harness of scripts/tests/suchy_kampan.py, whose fakes zaznam.json names (FAKES), the sessions of generator G
(scripts/tests/suchy_generatory.py) at the run's seed S and one rejection injected (READ_ERROR_RULE), so that the
campaign replaces once; the real corpus index of finish_corpus; safeguard.training.train_bundle at every seed of
analysis.seeds; tcn.finalne evaluate on the run's own ledger (stage suchy), by the full path or the shortened one
(SHORT_RULE, --cesta, no default); the readers of the known answers; scripts/campaign_report.py campaign; with --chyby
the nine injected errors on the run's own targets (FAULTS_RULE); the cleanup (CLEANUP_RULE); check E of
scripts/check_claims.sh over DIR. DIR receives the records, each with the header of check E (zaznam.json,
generator.json, kvalifikacia.json, final.json with its attachments, vlozene_chyby.json), and the logs, each with the
full header of S2 (suchy_beh.log, sprava.log, kontrola_E.log); WORK the campaign, its archive and index, the bundles,
the replays, the ledgers and the report. The threads are fixed (VLAKNA, the lead's answer to Q37), no internet socket
connects (bez_siete), the ledger of record is never written (strazena_kniha). Exit codes: EXIT_RULE.

THE PURE PART (package C2):

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

REPO = Path(__file__).resolve().parents[1]
PROTOKOL = REPO / "config" / "collection-v5.json"  # The real file of proposal 10.2 (the default of --protocol).
VYSLEDKY = REPO / "data" / "results"  # The gate records (scripts/gates.py), the default of --vysledky.
TRACKED_LEDGER = VYSLEDKY / "kniha_pecati.json"  # The ledger of record, which a dry run never writes.
SCHEMA_RUN = "hyptcn3/g1-dry-run/1"
SCHEMA_GENERATOR = "hyptcn3/g1-generator/1"
SCHEMA_QUALIFICATION = "hyptcn3/g1-qualification-pass/1"
SCHEMA_FAULTS = "hyptcn3/g1-injected-errors/1"
REZIMY = ("nulovy", "strukturovany")  # scripts/tests/suchy_generatory.py MODES
CESTY = ("plna", "skratena")
# The lead's answer to Q37 (2026-11-24T21:25Z): two runs at once only with a number of compute threads the code fixes,
# the same in every run. 2 threads of PyTorch and of the native thread pools (threadpoolctl): the executor's judgment,
# G1 preparation (two runs at once take four of the six cores; the tests of tcn/ train with 2 threads too).
VLAKNA = 2
GUEST_NOTE = "bez VM: suchý beh G1 (návrh 10.2), syntetické session"  # The skeleton, section 4: guest null, a reason.
# The working copy (the skeleton, section 0 and row C3; the lead's answer to Q32): the values of later stages that the
# chain needs, each with its origin; the copy's hashes of G0 and G1 are the real file's (COPY_RULE).
RATES = {"low": 1.2, "high": 3.2}
RATE_ORIGIN = (
    "the rates the lab trial proposes "
    "(~/hyptcn3-logs/v5/dokazy/skuska_labu/behy/skuska_labu_20261123T092454Z_cast1.json values.proposed_rate eshop_low "
    "1.2, eshop_high 3.2, and _cast2.json corp_low 1.2, corp_high 3.2; the skeleton of G1, row C3: eshop and corp low "
    "1.2, high 3.2), user sessions a second at envelope level 1; G2 determines rate")
CUSUM_SHIFTS = (0.0, 0.25, 0.5, 1.0, 2.0)  # normalized units (train standard deviations of M's normalizer)
EWMA_ALPHAS = (0.02, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0)
RIDGE_ALPHAS = (1e-4, 1e-3, 1e-2, 0.1, 1.0, 10.0, 100.0, 1e3, 1e4)
GRID_ORIGIN = (
    "the executor's judgment, G1 preparation: the full family of candidates G3a will propose (the lead's answer to "
    "Q32: never shrunk for time, with the edge members), under the rules of proposal 8.3 (Z1 a threshold per column on "
    "its value, first difference, moving average and CUSUM, and on mem_changed_max; Z3 prediction by the last value, "
    "the window mean and the EWMA; Z5 linear autoregression, ridge) and the skeleton of B7, section 2 (the free "
    "parameters: Z1 the length of the moving average and the shift of the CUSUM, selected by the share of the "
    "interventions inserted into dev it detects; Z3 the coefficient of the EWMA and Z5 the strength of the "
    "regularization, each selected by the loss on dev): Z1 moving_average_rows every power of two from 2 up to "
    "window_rows and window_rows itself (the longest the window holds), cusum_shift 0 (a plain cumulative sum, the "
    "edge) to 2 standard deviations; Z3 ewma_alpha over the whole range (0, 1] from 0.02 (close to the window mean) to "
    "1 (the last value); Z5 ridge_alpha from 1e-4 (close to least squares) to 1e4 (the strongest, close to the "
    "intercept alone) by factors of 10")
MAX_PER_CAMPAIGN = 9
LIMIT_ORIGIN = (
    "proposal 7.5: the limit is the smallest number at which the predicted probability of completing the plan is at "
    "least 0.95, and its indicative table for 132 sessions and a rehearsal of 30 attempts gives 9 when the rehearsal "
    "rejected none (the skeleton of G1, row C3: 9, no rejection); G3b determines it")
COLUMNS_ORIGIN = (
    "the qualification pass of the run's generator (MASK_RULE; the lead's answer to Q38), kvalifikacia.json "
    "values.proposed_columns; G3a determines analysis.columns")
COPY_RULE = (
    "the working copy of the protocol (the skeleton of G1, sections 0 and 6 point 1; the lead's answer to Q32, "
    "2026-11-24T21:25Z): the real file with the values of later stages the chain needs, scenarios.*.rate (G2), the "
    "grids of Z1, Z3 and Z5 and analysis.columns (G3a) and replacement.max_per_campaign (G3b), each with its origin in "
    "zaznam.json; every path in which the copy differs from the file is one that determined_at assigns to a stage "
    "after G1 (scripts/gates.py later_paths), else the copy is refused naming the path, and its hashes of stages G0 "
    "and G1 (scripts/gates.py stage_binding) are those of the file, else it is refused naming the stage; the command "
    "calls scripts/gates.py require of G1 (a valid record of G0) on the file and on the copy")
MASK_RULE = (
    "the column mask of the copy (the skeleton of G1, row C3 and section 6 point 7; the lead's answer to Q38): one "
    "qualification pass per generator, always at seed 0 of the generator whatever the run's seed, so that every run of "
    "a generator has the same mask (tcn.suchy_beh hranice_m refuses runs whose masks differ): the sessions of roles "
    "train and dev of the campaign plan of the copy without the mask, built by suchy_kampan.postav_session (one boot "
    "per group, each session in the plan's order one slot of a session's length and kampan_v5.SLOT_GAP_S after the one "
    "before), each audited by the real audit (boundary_sessions.audit) and refused by name when the audit refuses it; "
    "of every accepted audit the measured rows of its feature archive (features/qualification.py measured) and the "
    "offered load of its traffic_intervals.jsonl (offered_load), then features/qualification.py qualify in plan mode "
    "campaign (its roles train and dev; never from_index, which reads the index of a campaign only at stage final); "
    "its proposed_columns are the copy's analysis.columns; the classes by construction of the generator "
    "(suchy_generatory.TRIEDY) are written beside them, and a difference is a finding, not a failure")
SHORT_RULE = (
    "the shortened path of the dry run (the lead's POKYNY_TEMPO_2026-11-25, point 5): the real tcn.finalne evaluate, "
    "so that I and D are computed by the same functions as in the full path (tcn/finalne.py k1_claim and k2_claims, "
    "tcn/k2.py k2_values, tcn.tvrdenia), with only what the criteria of G1 do not read left out, inside "
    "tcn/suchy_beh.py alone (the final command of a campaign has no option to leave anything out): the descriptive "
    "methods of analysis.descriptive_methods (tcn.opisne runs nothing in fit_methods), the context truncation of the "
    "diagnostics (diagnostic_fits fits none, so opisné.diagnostics.context is empty) and the networks of the "
    "diagnostics but those structured_generator reads, the model with shuffled context and the network with random "
    "weights, which a run of the structured generator keeps (tcn/finalne.py STRUCTURE_CONTROLS) and a null run leaves "
    "out with their claims (opisné.diagnostics.claims names the rule); M at every seed of analysis.seeds, Z0 to Z5, "
    "the interventions, K1, K2a, K2b, the threshold-likeness of Z1 to Z3, the other diagnostics (the boot left out of "
    "calibration, the alarm rules, the threshold from clean traffic), the replays, the metrics and the attachments are "
    "those of the full path")
KEPT_NETWORKS = {"nulovy": (), "strukturovany": ("shuffled context", "random weights")}  # tcn/finalne.py
# STRUCTURE_CONTROLS, the networks structured_generator reads (the lead's list names M, Z1 to Z5 and the diagnostics
# of Z1 to Z3; that the structured runs keep these two networks is the executor's reading, G1 preparation).
FAULTS_RULE = (
    "the nine injected errors of proposal 10.2 (scripts/tests/vlozene_chyby.py vsetky, in its order) on the run's own "
    "targets (deferred item G [12] of B10: each injection on a copy of its own): Session, the session of the campaign "
    "the run captured first with an event and without a tolerated invalid row, attempt 1, built again from "
    "generator.json (values.captures, suchy_kampan.postav_session) before its audit, under the campaign's protocol; "
    "Korpus, the accepted audits of the run's corpus in the order of its index, every session directory copied with "
    "its audit record and its feature archive (every path of the session directory in the record, its session_dir, its "
    "features and the paths of the log audit's sections, naming the copy, so that the log audit repeated in the copy "
    "is the record's, features/quality.py require_log_audit); Pecat, a copy of the run's index and of its ledger after "
    "its own final run (the branch 'consumed'), and a new directory; for each error expected = vloz(target) and got = "
    "krok(target), equal or not; a clean target of each kind is admitted: a Session copy accepted by krok_audit and a "
    "Korpus copy indexed by krok_korpus with no refusal, and of a Pecat the run's own final evaluation on its ledger "
    "before it consumed the seal (complete) and the seal letting the replay of an archive of role train through "
    "(tcn.pecat kontrola, allowed not_sealed)")
CLEANUP_RULE = (
    "after the run and its injected errors (the skeleton of G1, row C3: the session directories are deleted only after "
    "--chyby): the session directories of the campaign and of the qualification pass and the copies of the injected "
    "errors are deleted; the archive of the campaign (a copy of every session directory), the corpus index (it names "
    "the deleted directories), the bundles, the replays, the ledgers, the ending records and the report stay in the "
    "working directory, and the run's records in its out")
EXIT_RULE = (
    "exit 0 when the run ended with the record of stage suchy, the report, check E with no finding and, with --chyby, "
    "nine of nine errors refused by their expected reasons and every clean target admitted; 1 when the run ended but "
    "one of these did not hold (zaznam.json and the log name it); 2 for a refusal or a failure (zaznam.json says which "
    "step, with the error)")


def _cas():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _git(*args):
    import subprocess
    found = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    return found.stdout.rstrip("\n") if found.returncode == 0 else None


def _sha(path):
    import hashlib
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _hostitel():
    import platform
    import socket
    return f"{socket.gethostname()} ({platform.platform()})"


def hlavicka_s2(command):
    """The full header of S2 (deferred item S2 of G0) of a log: commit, date, host, git status --porcelain and the
    command as run, each line beginning with '# '."""
    status = _git("status", "--porcelain")
    lines = [f"# commit {_git('rev-parse', 'HEAD')}", f"# date {_cas()}", f"# host {_hostitel()}",
             "# git status --porcelain:" + (" (none)" if not status else ""),
             *(f"#   {line}" for line in (status or "").splitlines()), f"# command {command}"]
    return "".join(line + "\n" for line in lines)


def hlavicka_e(schema, command, n, values, **extra):
    """A record with the header of check E (scripts/check_claims.sh: commit, date, host, guest, command, n and
    values): guest null with its reason (GUEST_NOTE), the commit with whether the tree differed from it."""
    status = _git("status", "--porcelain")
    return {"schema": schema, "commit": _git("rev-parse", "HEAD"), "commit_dirty": None if status is None else
            bool(status), "date": _cas(), "host": _hostitel(), "guest": None, "guest_note": GUEST_NOTE,
            "command": command, "n": n, **extra, "values": values}


def _json(value):
    from tcn.finalne import _json_default
    return json.dumps(value, indent=1, ensure_ascii=False, allow_nan=False, default=_json_default) + "\n"


def _zapis(path, doc):
    """A new JSON file (never overwritten)."""
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(_json(doc))
    return Path(path)


def _cesta(doc, path):
    node = doc
    for key in path.split("."):
        node = node[key]
    return node


def _nastav(doc, path, value):
    keys = path.split(".")
    node = doc
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = _copy_value(value)


def _copy_value(value):
    return json.loads(json.dumps(value))


def _z1_ma(window_rows):
    """Z1's moving averages (GRID_ORIGIN): every power of two from 2 up to window_rows, and window_rows itself."""
    out, n = [], 2
    while n < window_rows:
        out.append(n)
        n *= 2
    return [*out, window_rows]


def hodnoty_kopie(doc):
    """{path: {value, origin}} that the working copy fills but analysis.columns (COPY_RULE): the rate of every
    scenario, the grids of Z1, Z3 and Z5 and the limit of the replacements."""
    out = {f"scenarios.{name}.rate": {"value": RATES[s["intensity"]], "origin": RATE_ORIGIN}
           for name, s in doc["scenarios"].items()}
    grids = {"Z1": {"moving_average_rows": _z1_ma(doc["window_rows"]), "cusum_shift": list(CUSUM_SHIFTS)},
             "Z3": {"ewma_alpha": list(EWMA_ALPHAS)}, "Z5": {"ridge_alpha": list(RIDGE_ALPHAS)}}
    for method, grid in grids.items():
        out[f"analysis.methods.{method}.grid"] = {"value": grid, "origin": GRID_ORIGIN}
    out["replacement.max_per_campaign"] = {"value": MAX_PER_CAMPAIGN, "origin": LIMIT_ORIGIN}
    return out


def _rozdiely(a, b, path=()):
    """The dotted paths at which two JSON values differ: the keys of an object one by one, any other value whole."""
    if type(a) is dict and type(b) is dict:
        out = []
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                out.append((*path, key))
            else:
                out.extend(_rozdiely(a[key], b[key], (*path, key)))
        return out
    return [] if a == b and type(a) is type(b) else [path]


def over_kopiu(skutocny, kopia):
    """COPY_RULE: the working copy `kopia` of the protocol file `skutocny` (paths), checked: {paths, stages {G0, G1}},
    the paths in which it differs; a path of no later stage than G1 is refused by name, so is a stage hash that
    differs."""
    from scripts import gates
    real, mine = (json.loads(Path(path).read_text()) for path in (skutocny, kopia))
    later = gates.later_paths(real.get("determined_at"), "G1")
    paths = _rozdiely(real, mine)
    for path in paths:
        if not any(len(keys) <= len(path) and all(k in ("*", p) for k, p in zip(keys, path)) for keys in later):
            where = ".".join(path) or "(the whole document)"
            raise ValueError(f"the working copy {kopia} differs from the protocol file {skutocny} at {where}, which "
                             "determined_at assigns to no stage after G1: refused (COPY_RULE; the lead's answer to "
                             "Q32)")
    stages = {}
    for stage in ("G0", "G1"):
        stages[stage] = {"file": gates.stage_sha256(skutocny, stage), "copy": gates.stage_sha256(kopia, stage)}
        if stages[stage]["file"] != stages[stage]["copy"]:
            raise ValueError(f"the working copy {kopia} has another hash of stage {stage} than the protocol file "
                             f"{skutocny}: refused (COPY_RULE)")
    return {"paths": [".".join(path) for path in paths], "stages": stages, "rule": COPY_RULE}


def _gate(vysledky, protocol):
    """scripts/gates.py require of G1 (a valid record of G0) on a protocol file, real (COPY_RULE)."""
    from scripts import gates
    gates.require(vysledky, protocol, "G1")
    return {"results": str(vysledky), "protocol": str(protocol), "protocol_sha256": _sha(protocol), "stage": "G1",
            "requires": "G0", "g0_stage_sha256": gates.stage_sha256(protocol, "G0"), "passed": True}


class _Patch:
    """Attributes set for the length of a block and restored after it, in reverse order."""

    def __init__(self):
        self.saved = []

    def set(self, target, name, value):
        self.saved.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def undo(self):
        while self.saved:
            target, name, value = self.saved.pop()
            setattr(target, name, value)


class _Context:
    def __init__(self, enter):
        self.enter, self.patch = enter, _Patch()

    def __enter__(self):
        self.enter(self.patch)
        return self.patch

    def __exit__(self, *exc):
        self.patch.undo()
        return False


def vlakna():
    """VLAKNA for the length of a block: the threads of PyTorch and the limit of the native thread pools
    (threadpoolctl), the same in the command and in a check that evaluates its corpus again; PyTorch's are restored
    after it."""
    import threadpoolctl
    import torch

    def enter(patch):
        before = torch.get_num_threads()
        limits = threadpoolctl.threadpool_limits(VLAKNA)  # First: its restore resets the OpenMP pool of PyTorch.
        torch.set_num_threads(VLAKNA)
        patch.threads = (before, limits)

    class Vlakna(_Context):
        def __exit__(self, *exc):
            before, limits = self.patch.threads
            limits.restore_original_limits()
            torch.set_num_threads(before)
            return super().__exit__(*exc)
    return Vlakna(enter)


COMMAND_PATCHES = (
    {"what": "VLAKNA threads of PyTorch and of the native thread pools (threadpoolctl) for the whole run",
     "patches": ["torch.set_num_threads", "threadpoolctl.threadpool_limits"]},
    {"what": "bez_siete: a connection of an internet socket of the process is refused",
     "patches": ["socket.socket.connect", "socket.socket.connect_ex"]},
    {"what": "strazena_kniha: a write of the ledger of record is refused", "patches": ["tcn.pecat._write"]},
    {"what": "tcn.pecat vlastna_kniha: the run's ledger is the ledger of the process for the training, the final "
     "evaluation and the injected errors (stage suchy)", "patches": ["tcn.pecat.KNIHA"]},
    {"what": "vysledky_finalneho: tcn.finalne reads the gate records of --vysledky (GATE_RULE), only when it is not "
     "data/results", "patches": ["tcn.finalne.RESULTS"]},
    {"what": "skratena_cesta, only with --cesta skratena (SHORT_RULE)",
     "patches": ["tcn.finalne.fit_methods", "tcn.finalne.diagnostic_fits", "tcn.finalne._variants",
                 "tcn.finalne.control_claims"]},
)


def bez_siete():
    """The dry run uses no network (proposal 10.2): a connection of an internet socket of this process is refused by
    name (an AF_INET or AF_INET6 connect); its attempts are kept in .attempts of the patch."""
    import socket

    def enter(patch):
        patch.attempts = []
        connect, connect_ex = socket.socket.connect, socket.socket.connect_ex

        def refuse(real):
            def call(self, address):
                if self.family in (socket.AF_INET, socket.AF_INET6):
                    patch.attempts.append(repr(address))
                    raise OSError(f"the G1 dry run uses no network: a connection to {address!r} is refused")
                return real(self, address)
            return call
        patch.set(socket.socket, "connect", refuse(connect))
        patch.set(socket.socket, "connect_ex", refuse(connect_ex))
    return _Context(enter)


def strazena_kniha():
    """A write of the ledger of record (data/results/kniha_pecati.json) is refused before it happens."""
    from tcn import pecat

    def enter(patch):
        original = pecat._write

        def write(path, doc, command):
            if Path(path).resolve() == TRACKED_LEDGER.resolve():
                raise AssertionError("the G1 dry run never writes the ledger of record " + str(TRACKED_LEDGER))
            return original(path, doc, command)
        patch.set(pecat, "_write", write)
    return _Context(enter)


def vysledky_finalneho(vysledky):
    """tcn/finalne.py reads the gate records of its stage in RESULTS (GATE_RULE): here those of --vysledky."""
    from tcn import finalne

    def enter(patch):
        if Path(vysledky).resolve() != Path(finalne.RESULTS).resolve():
            patch.set(finalne, "RESULTS", Path(vysledky))
    return _Context(enter)


def skratena_cesta(rezim):
    """SHORT_RULE for a run of generator `rezim`, for the length of a block."""
    from tcn import diagnostiky, finalne, opisne
    keep = KEPT_NETWORKS[rezim]

    def enter(patch):
        fit_methods, diagnostic_fits = finalne.fit_methods, finalne.diagnostic_fits
        variants, control_claims = finalne._variants, finalne.control_claims

        def fit_short(*args, **kwargs):
            inner = _Patch()
            inner.set(opisne, "runs", lambda protocol: [])
            try:
                return fit_methods(*args, **kwargs)
            finally:
                inner.undo()

        def diagnostics_short(*args, **kwargs):
            inner = _Patch()
            inner.set(diagnostiky, "context_truncation", lambda *a, **k: None)
            try:
                return dict(diagnostic_fits(*args, **kwargs), context={})
            finally:
                inner.undo()

        def controls_short(networks, values, protocol, plan, mode):
            if not keep:
                return {"rule": finalne.CONTROL_CLAIMS_RULE, "not_computed": SHORT_RULE}
            return control_claims(networks, values, protocol, plan, mode)
        patch.set(finalne, "fit_methods", fit_short)
        patch.set(finalne, "diagnostic_fits", diagnostics_short)
        patch.set(finalne, "_variants", lambda: {name: net for name, net in variants().items() if name in keep})
        patch.set(finalne, "control_claims", controls_short)
    return _Context(enter)


def vyhodnot(index, bundles, *, campaign, replays, out, ledger, cesta, rezim, vysledky=VYSLEDKY):
    """The final evaluation of the dry run: tcn.finalne evaluate on the run's own ledger (stage suchy), the gate
    records of `vysledky`, by the full path or by the shortened one (SHORT_RULE). Returns the record."""
    from tcn import finalne
    if cesta not in CESTY:
        raise ValueError(f"the path of the dry run is {' or '.join(CESTY)}, not {cesta!r}")
    with vysledky_finalneho(vysledky):
        if cesta == "plna":
            return finalne.evaluate(index, bundles, campaign=campaign, replays=replays, out=out, ledger=ledger)
        with skratena_cesta(rezim):
            return finalne.evaluate(index, bundles, campaign=campaign, replays=replays, out=out, ledger=ledger)


def kvalifikacny_prechod(praca, kopia, protokol, rezim):
    """MASK_RULE: (the values of kvalifikacia.json, the proposed columns) of the copy without the mask `kopia` (its
    file) and `protokol` (the copy, loaded), the run's generator `rezim`, below the directory `praca`."""
    from features import archive as feature_archive
    from features import qualification as fq
    from scripts import collection
    from scripts import protocol_v5 as pv
    from scripts.tests import boundary_sessions as bs
    from scripts.tests import kampan_v5 as kv
    from scripts.tests import suchy_generatory as sg
    from scripts.tests import suchy_kampan as sk
    roles = fq.ROLES_BY_MODE["campaign"]
    rows = [dict(s, attempt=1) for s in pv.plan(protokol, "campaign")["sessions"] if s["role"] in roles]
    span = protokol["cycles"] * protokol["interval_s"] + kv.SLOT_GAP_S
    vms = [vm["name"] for vm in protokol["vms"]]
    found, sessions, load, audits = {}, [], {}, []
    for i, row in enumerate(rows):
        p = collection.for_vm(protokol, row["vm"])
        guest = {"kernel": kv.KERNEL, "boot_id": f"kvalifikacia-{row['group']}", "machine_id": f"machine-{row['vm']}",
                 "stack_sha256": kv.STACK, "stack_manifest": list(bs.STACK_MANIFEST)}
        qemu = {"pid": kv.FIRST_PID + vms.index(row["vm"]), "start_ticks": 1, "host_boot": kv.HOST_BOOT}
        ident = f"kvalifikacia_{i + 1:02d}_{row['vm']}_{row['role']}_{row['scenario']}"
        root = Path(praca) / "sessions" / row["vm"]
        root.mkdir(parents=True, exist_ok=True)
        session = sk.postav_session(root, p, kopia, row, rezim, 0, protokol, session_id=ident,
                                    prvy_riadok_unix=kv.Clock().now + i * span, guest=guest, qemu=qemu)
        (Path(praca) / "audits").mkdir(exist_ok=True)
        audit = bs.audit(session, p, output=Path(praca) / "audits" / f"{ident}.json")
        if audit.code != 0:
            raise ValueError(f"the qualification pass: the audit refused session {ident}: {audit.values['reasons']}")
        data = feature_archive.load(audit.archive)
        mask = fq.measured(data)
        times = np.asarray(data["casy"], dtype=float)
        found[ident] = np.asarray(data["matica"], dtype=float)[mask][:, :len(feature_archive.BEHAVIOR_NAMES)]
        sessions.append({"id": ident, "role": row["role"], "group": row["group"], "vm": row["vm"],
                         "scenario": row["scenario"], "profile": protokol["scenarios"][row["scenario"]]["profile"],
                         "position": row["position"], "start": float(times[0])})
        load[ident] = fq.offered_load(session.directory / "traffic_intervals.jsonl", times[mask],
                                      protokol["interval_s"])
        audits.append({"session": ident, "role": row["role"], "group": row["group"], "vm": row["vm"],
                       "audit": str(audit.path), "audit_sha256": _sha(audit.path),
                       "features_sha256": audit.values["features_sha256"]})
    result = fq.qualify(found, sessions, protokol, mode="campaign", load=load,
                        response="plan mode campaign: its roles train and dev hold no control (features/"
                                 "qualification.py ROLES_BY_MODE)")
    proposed = result["proposed_columns"]
    differ = {name: {"pass": proposed[name], "construction": sg.TRIEDY[name]} for name in proposed
              if proposed[name] != sg.TRIEDY[name]}
    values = {"generator": rezim, "seed": 0, "rule": MASK_RULE, "copy_without_mask": str(kopia),
              "copy_without_mask_sha256": _sha(kopia), "sessions": audits, "qualification": result,
              "proposed_columns": proposed, "classes_by_construction": dict(sg.TRIEDY),
              "differences": differ, "finding": bool(differ)}
    return values, proposed


def _riadky_tvrdeni(values):
    """The claims of a final record as zaznam.json carries them: per claim its status, outcome, m, statistic, compare
    and per method the point estimate (the mean of its values per boot) and the interval."""
    out = {}
    for claim, record in (values.get("claims") or {}).items():
        methods = record.get("methods") or {}
        out[claim] = {"status": (values.get("conclusions") or {}).get(claim, {}).get("status"),
                      "outcome": record.get("outcome"), "m": record.get("m"), "statistic": record.get("statistic"),
                      "compare": record.get("compare"), "conclusion": record.get("conclusion"),
                      "methods": {z: {"mean": item.get("mean"), "interval": item.get("interval"),
                                      "boots": len(item.get("values") or {})}
                                  for z, item in methods.items() if type(item) is dict}}
    return out


class Beh:
    """One run of the dry run (beh): the arguments of the command line, the log, the steps and their times."""

    def __init__(self, generator, seed, out, praca, cesta, *, protocol=PROTOKOL, vysledky=VYSLEDKY, chyby=False,
                 command):
        if generator not in REZIMY:
            raise ValueError(f"the generator is {' or '.join(REZIMY)}, not {generator!r}")
        if type(seed) is not int or seed < 0:
            raise ValueError("the seed of a run is an integer of at least 0")
        if cesta not in CESTY:
            raise ValueError(f"the path is {' or '.join(CESTY)}, not {cesta!r}")
        self.generator, self.seed, self.cesta, self.chyby = generator, seed, cesta, bool(chyby)
        self.out, self.praca = Path(out).absolute(), Path(praca).absolute()
        self.protocol, self.vysledky = Path(protocol).absolute(), Path(vysledky).absolute()
        self.command = command
        for path, option in ((self.out, "--out"), (self.praca, "--praca")):
            if path.exists() or path.is_symlink():
                raise FileExistsError(f"{option} {path} exists; a run writes a new directory")
        if self.praca == self.out or self.out in self.praca.parents or self.praca in self.out.parents:
            raise ValueError("--out and --praca are two separate directories, neither inside the other")
        results = VYSLEDKY.resolve()
        if self.praca.resolve() == results or results in self.praca.resolve().parents:
            raise ValueError(f"--praca {self.praca} lies in {results}: the run's own ledger and its replays lie "
                             "outside data/results (tcn/pecat.py vlastna_kniha, tcn/finalne.py REPLAY_RULE)")
        self.out.mkdir(parents=True)
        self.praca.mkdir(parents=True)
        self.log = self.out / "suchy_beh.log"
        self.log.write_text(hlavicka_s2(command))
        self.kroky, self.facts, self.checks = [], {}, []

    def zapis_log(self, text):
        with self.log.open("a") as stream:
            stream.write(f"{_cas()} {text}\n")

    def krok(self, name):
        """A step of the run: its start, end and seconds in self.kroky and in the log."""
        import time
        beh = self

        class Krok:
            def __enter__(self):
                self.t0, self.start = time.monotonic(), _cas()
                beh.zapis_log(f"krok {name}: začiatok")
                return self

            def __exit__(self, kind, error, trace):
                item = {"step": name, "start": self.start, "end": _cas(), "s": round(time.monotonic() - self.t0, 3)}
                if kind is not None:
                    item["error"] = f"{kind.__name__}: {error}"
                beh.kroky.append(item)
                beh.zapis_log(f"krok {name}: {'koniec' if kind is None else 'chyba ' + item['error']} "
                              f"({item['s']} s)")
                return False
        return Krok()

    def kontrola(self, name, holds, detail):
        """A check of EXIT_RULE: kept in self.checks and in the log."""
        self.checks.append({"check": name, "holds": bool(holds), "detail": detail})
        self.zapis_log(f"kontrola {name}: {'platí' if holds else 'NEPLATÍ'} ({detail})")

    # ---------------------------------------------------------------- the chain

    def run(self):
        """The run, from the plan to the report and check E: its exit code (EXIT_RULE); zaznam.json either way."""
        import torch
        self.failure = None
        try:
            with vlakna(), bez_siete() as self.siet, strazena_kniha():
                self.threads = {"torch_threads": torch.get_num_threads(),
                                "torch_interop_threads": torch.get_num_interop_threads(), "threadpool_limit": VLAKNA,
                                "rule": "VLAKNA (the lead's answer to Q37): fixed by the code, the same in every run"}
                self._chain()
        except Exception as error:  # noqa: BLE001 - every failure is written into zaznam.json (EXIT_RULE)
            self.failure = {"step": self.kroky[-1]["step"] if self.kroky else None,
                            "error": f"{type(error).__name__}: {error}"}
            self.zapis_log(f"zlyhanie: {self.failure['error']}")
            print(f"tcn.suchy_beh: {self.failure['error']}", file=sys.stderr)
            if not (self.out / "zaznam.json").exists():
                try:
                    self._zaznam()
                except Exception as late:  # noqa: BLE001 - the log keeps it
                    self.zapis_log(f"zaznam.json sa nedal zapísať: {type(late).__name__}: {late}")
            return 2
        failed = [c["check"] for c in self.checks if not c["holds"]]
        if failed:
            print("tcn.suchy_beh: these checks of the run did not hold: " + ", ".join(failed), file=sys.stderr)
        return 1 if failed else 0

    def _chain(self):
        import shutil
        from scripts import collection
        from scripts.collection_archive import read_json
        from tcn import pecat
        with self.krok("1 protokol a stupne"):
            self.real_doc = json.loads(self.protocol.read_text())
            collection.protocol(self.protocol)  # The loader's checks, before anything else.
            self.gates = [_gate(self.vysledky, self.protocol)]
        with self.krok("2 pracovna kopia bez masky"):
            doc0 = _copy_value(self.real_doc)
            self.values = hodnoty_kopie(doc0)
            for path, item in self.values.items():
                _nastav(doc0, path, item["value"])
            self.kopia0 = _zapis(self.praca / "protokol_kopia_bez_masky.json", doc0)
            over_kopiu(self.protocol, self.kopia0)
            p0 = collection.protocol(self.kopia0)
        with self.krok("3 kvalifikacny prechod"):
            values, proposed = kvalifikacny_prechod(self.praca / "kvalifikacia", self.kopia0, p0, self.generator)
            self.kvalifikacia = _zapis(self.out / "kvalifikacia.json", hlavicka_e(
                SCHEMA_QUALIFICATION, self.command, len(values["sessions"]), values))
            self.mask_finding = values["differences"]
        with self.krok("4 pracovna kopia"):
            doc = _copy_value(doc0)
            doc["analysis"]["columns"] = proposed
            self.values["analysis.columns"] = {"value": proposed, "origin": COLUMNS_ORIGIN}
            self.kopia = _zapis(self.praca / "protokol_kopia.json", doc)
            self.copy_check = over_kopiu(self.protocol, self.kopia)
            self.gates.append(_gate(self.vysledky, self.kopia))
            self.P = collection.protocol(self.kopia)
        with self.krok("5 generalka a kampan"):
            self._kampan()
        with self.krok("6 generator.json"):
            self._generator_json()
        with self.krok("7 trening M"):
            from safeguard.training import train_bundle
            from scripts.protocol_v5 import analysis_plan
            (self.praca / "baliky").mkdir()
            with pecat.vlastna_kniha(self.kniha):
                self.bundles = [Path(train_bundle(self.index, self.praca / "baliky" / f"seed-{seed}",
                                                  window_rows=self.P["window_rows"], max_gap_s=self.P["max_gap_s"],
                                                  seed=seed)["bundle"]) for seed in analysis_plan(self.P)["seeds"]]
        with self.krok("8 finalne vyhodnotenie"):
            self.kniha_pred = self.praca / "kniha_pred_finalnym_behom.json"
            shutil.copyfile(self.kniha, self.kniha_pred)
            self.final = self.out / "final.json"
            with pecat.vlastna_kniha(self.kniha):
                self.record = vyhodnot(self.index, self.bundles, campaign=self.ending, replays=self.praca / "prehratia",
                                       out=self.final, ledger=self.kniha, cesta=self.cesta, rezim=self.generator,
                                       vysledky=self.vysledky)
            values = self.record["values"]
            self.kontrola("final_record", self.record.get("stage") == "suchy" and values.get("status") == "complete",
                          f"stage {self.record.get('stage')}, status {values.get('status')}")
        with self.krok("9 citace znamych odpovedi"):
            self._citace()
        with self.krok("10 sprava kampane"):
            self._sprava()
        if self.chyby:
            with self.krok("11 vlozene chyby"):
                self._chyby()
        with self.krok("12 upratanie"):
            removed = [self.h.collections, self.praca / "kvalifikacia" / "sessions", self.praca / "chyby"]
            self.removed = [str(path) for path in removed if path.exists()]
            for path in removed:
                if path.exists():
                    shutil.rmtree(path)
        with self.krok("13 kontrola E pred zaznamom"):
            self.check_e = self._kontrola_e("pred zápisom zaznam.json")
        with self.krok("14 zaznam"):
            self._zaznam()
        with self.krok("15 kontrola E"):
            last = self._kontrola_e("po zápise zaznam.json, nad každým JSON v --out")
            self.kontrola("check_E", self.check_e["exit"] == 0 and last["exit"] == 0,
                          f"exit {self.check_e['exit']} before and {last['exit']} after zaznam.json (kontrola_E.log)")
        read_json(self.out / "zaznam.json")  # Readable once written.

    def _kampan(self):
        """The rehearsal and the campaign on the harness (suchy_kampan.Kampan), one rejection injected."""
        import pytest
        from scripts import protocol_v5 as pv
        from scripts.collection_archive import read_json
        from scripts.tests import suchy_kampan as sk
        P = self.P
        self.kniha = self.praca / "kniha" / "kniha_pecati.json"
        self.kniha.parent.mkdir()
        with pytest.MonkeyPatch.context() as mp:
            h = sk.Kampan(self.praca / "kampan", mp, protokol=P, rezim=self.generator, seed=self.seed, kniha=self.kniha)
            h.label = "rehearsal"
            self.rehearsal = h.init(self.kopia, "rehearsal", P["name"] + P["rehearsal"]["name_suffix"])
            h.run(self.rehearsal)
            h.label = "campaign"
            first = next(s for s in pv.plan(P, "campaign")["sessions"] if s["role"] == REJECTED_ROLE)
            self.injected = {"campaign": P["name"], "group": first["group"], "scenario": first["scenario"],
                             "attempt": 1, "rule": sk.READ_ERROR_RULE}
            h.reject.add((P["name"], first["group"], first["scenario"], 1))
            self.campaign = h.init(self.kopia, "campaign", P["name"], estimate_from=self.rehearsal)
            h.run(self.campaign)
        self.h = h
        self.index = self.campaign / "corpus.json"
        self.endings = {}
        for directory in (self.rehearsal, self.campaign):
            found = [path for path, doc in h.records(directory)
                     if (doc.get("values") or {}).get("ending") == "complete"]
            if len(found) != 1:
                raise ValueError(f"the campaign {directory.name} has {len(found)} records of its complete ending, not "
                                 "one")
            self.endings[directory.name] = found[0]
        self.ending = self.endings[self.campaign.name]
        self.ending_doc = read_json(self.ending)

    def _generator_json(self):
        """generator.json of the run (check E's header): suchy_generatory.generator_json of every captured row and
        attempt, the readers' form of the sessions of the corpus (suchy_kampan.GENERATOR_MAP_RULE) and what rebuilds
        every capture (suchy_kampan.SESSION_RULE)."""
        from scripts.collection_archive import read_json
        from scripts.tests import suchy_generatory as sg
        from scripts.tests import suchy_kampan as sk
        h = self.h
        gen = sg.generator_json([entry["row"] for entry in h.riadky], self.generator, self.seed, self.P)
        by_session = {entry["session"]: record for entry, record in zip(h.riadky, gen["sessions"])}
        verdicts = {}
        for audit in h.audits:  # The last audit of a session decides (a session is audited once).
            verdicts[audit["sid"]] = audit
        self.corpus_ids = [r["id"] for r in read_json(self.index)["sessions"]]
        captures = [{"session": entry["session"], "campaign": entry["campaign"], "vm": entry["vm"],
                     "plan_mode": entry["plan_mode"], "row": entry["row"], "first_row_unix": entry["first_row_unix"],
                     "guest": entry["guest"], "qemu": entry["qemu"], "fields": entry["fields"],
                     "read_error": entry["read_error"], "accepted": verdicts[entry["session"]]["accepted"],
                     "reasons": verdicts[entry["session"]]["reasons"]} for entry in h.riadky]
        values = {"generator": gen, "sessions": sk.zaznam_generatora({sid: by_session[sid] for sid in self.corpus_ids}),
                  "corpus_sessions": self.corpus_ids, "captures": captures,
                  "rules": {"session": sk.SESSION_RULE, "read_error": sk.READ_ERROR_RULE,
                            "map": sk.GENERATOR_MAP_RULE, "keys": GENERATOR_KEYS}}
        self.generator_values = values
        self.generator_file = _zapis(self.out / "generator.json", hlavicka_e(
            SCHEMA_GENERATOR, self.command, len(captures), values))

    def _citace(self):
        """The readers of the known answers over the run's record (C2): what zaznam.json carries of section 2."""
        readers = {"diagnostics_controls": lambda: diagnostiky(self.final),
                   "marginal_change": lambda: okrajova_zmena(self.final, self.generator_values),
                   "unscored_spans": lambda: neskorovane(self.final, self.generator_values)}
        self.answers = {}
        for name, read in readers.items():
            try:
                self.answers[name] = read()
            except ValueError as error:
                self.answers[name] = {"error": str(error)}
                self.kontrola(f"reader {name}", False, str(error))

    def _sprava(self):
        """scripts/campaign_report.py campaign of the campaign, its output in sprava.log (S2 header)."""
        import contextlib
        import io
        import shlex
        from scripts import campaign_report
        self.sprava = self.praca / "sprava"
        argv = ["campaign", str(self.campaign), "--out", str(self.sprava), "--collections-dir",
                str(self.h.collections), "--results-dir", str(self.h.results)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = campaign_report.main(argv)
        with (self.out / "sprava.log").open("x") as stream:
            command = shlex.join(["scripts/campaign_report.py", *argv]) + " (in the process of the run)"
            stream.write(hlavicka_s2(command))
            stream.write(out.getvalue() + err.getvalue() + f"exit {code}\n")
        self.sprava_code = code
        self.kontrola("report", code == 0 and (self.sprava / "summary.json").is_file(), f"exit {code}")

    def _kontrola_e(self, kedy):
        """Check E (scripts/check_claims.sh --json-hlavicky with VMIC_RESULTS_DIR the run's out), into kontrola_E.log
        with the S2 header: {exit, output, when}."""
        import os
        import shlex
        import subprocess
        command = ["bash", str(REPO / "scripts" / "check_claims.sh"), "--json-hlavicky"]
        env = dict(os.environ, VMIC_RESULTS_DIR=str(self.out))
        found = subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
        with (self.out / "kontrola_E.log").open("a") as stream:
            stream.write(hlavicka_s2(f"VMIC_RESULTS_DIR={shlex.quote(str(self.out))} {shlex.join(command)}")
                         + f"# when {kedy}\n" + found.stdout + found.stderr + f"exit {found.returncode}\n")
        return {"exit": found.returncode, "output": (found.stdout + found.stderr).strip()[-2000:], "when": kedy,
                "log": str(self.out / "kontrola_E.log")}

    def _chyby(self):
        """FAULTS_RULE: vlozene_chyby.json."""
        import shutil
        from scripts import collection
        from scripts.tests import suchy_kampan as sk
        from scripts.tests import vlozene_chyby as vc
        from tcn import pecat
        root = self.praca / "chyby"
        root.mkdir()
        gen = json.loads(self.generator_file.read_text())["values"]
        protocol_path = self.campaign / "protocol.json"
        records = {capture["session"]: record for capture, record in zip(gen["captures"], gen["generator"]["sessions"])}
        chosen = next((c for c in gen["captures"] if c["campaign"] == self.P["name"] and c["row"]["attempt"] == 1
                       and c["accepted"] and c["row"].get("events") and not records[c["session"]]["invalid_rows"]),
                      None)
        if chosen is None:
            raise ValueError("the campaign captured no session with an event and without a tolerated invalid row: no "
                             "target Session (FAULTS_RULE)")
        index_doc = json.loads(self.index.read_text())

        def session(d):
            p = collection.for_vm(self.P, chosen["vm"])
            built = sk.postav_session(d, p, protocol_path, chosen["row"], self.generator, self.seed, self.P,
                                      session_id=chosen["session"], prvy_riadok_unix=chosen["first_row_unix"],
                                      guest=chosen["guest"], qemu=chosen["qemu"], polia=chosen["fields"])
            return vc.Session(built.directory, protocol_path, p, built.result)

        def korpus(d):
            audits = []
            for r in index_doc["sessions"]:
                source = Path(r["audit"]).parent
                target = d / source.name
                shutil.copytree(source, target, symlinks=True)
                audit = target / Path(r["audit"]).name
                # The audit record names the session directory (session_dir, features, the paths of the log audit's
                # sections), which features/quality.py require_log_audit compares with the log audit repeated there:
                # the copy's record names the copy (FAULTS_RULE).
                text = audit.read_text()
                for old, new in ((f'"{source}/', f'"{target}/'), (f'"{source}"', f'"{target}"')):
                    text = text.replace(old, new)
                audit.write_text(text)
                audits.append(audit)
            return vc.Korpus(audits, self.P, _sha(protocol_path), "campaign")

        def pecat_target(d):
            shutil.copyfile(self.index, d / "corpus.json")
            shutil.copyfile(self.kniha, d / "kniha_pecati.json")
            (d / "work").mkdir()
            return vc.Pecat(d / "corpus.json", d / "kniha_pecati.json", d / "work")
        builders = {"Session": session, "Korpus": korpus, "Pecat": pecat_target}
        rows = []
        for chyba in vc.vsetky():
            d = root / chyba.id
            d.mkdir()
            target = builders[chyba.ciel.__name__](d)
            expected = chyba.vloz(target)
            got = chyba.krok(target)
            rows.append({"id": chyba.id, "chyba": chyba.chyba, "ciel": chyba.ciel.__name__, "krok": chyba.krok.__name__,
                         "expected": expected, "got": got, "equal": expected == got, "reasons": list(chyba.dovody)})
            self.zapis_log(f"vložená chyba {chyba.id}: {'rovnaký dôvod' if expected == got else 'INÝ DÔVOD'}")
        clean = {}
        d = root / "cisty_session"
        d.mkdir()
        got = vc.krok_audit(session(d))
        clean["Session"] = {"krok": "krok_audit", "target": chosen["session"], "got": got, "admitted": got == []}
        d = root / "cisty_korpus"
        d.mkdir()
        got = vc.krok_korpus(korpus(d))
        clean["Korpus"] = {"krok": "krok_korpus", "audits": len(index_doc["sessions"]), "got": got,
                           "admitted": got == []}
        d = root / "cisty_pecat"
        d.mkdir()
        target = pecat_target(d)
        train = next(r for r in index_doc["sessions"] if r["role"] == "train")
        allowed = pecat.kontrola(train["features"], purpose="tcn.porovnanie replay", ledger=target.ledger)["allowed"]
        values = self.record["values"]
        clean["Pecat"] = {"krok_finalne": {"what": "the run's own final evaluation on its ledger before it consumed "
                                           "the seal", "out": str(self.final), "stage": self.record.get("stage"),
                                           "status": values.get("status"), "ledger_before": str(self.kniha_pred),
                                           "ledger_before_sha256": _sha(self.kniha_pred)},
                          "krok_prehratie": {"what": "tcn.pecat kontrola of the archive of the first session of role "
                                             "train, the purpose of a replay", "session": train["id"],
                                             "allowed": allowed},
                          "admitted": values.get("status") == "complete" and allowed == "not_sealed"}
        refused = sum(row["equal"] for row in rows)
        admitted = all(item["admitted"] for item in clean.values())
        out = {"errors": rows, "refused_as_expected": refused, "of": len(rows), "clean_targets": clean,
               "clean_admitted": admitted, "session_target": chosen["session"], "rule": FAULTS_RULE}
        self.faults = _zapis(self.out / "vlozene_chyby.json", hlavicka_e(SCHEMA_FAULTS, self.command, len(rows), out))
        self.faults_summary = {"file": str(self.faults), "sha256": _sha(self.faults), "refused_as_expected": refused,
                               "of": len(rows), "clean_admitted": admitted}
        self.kontrola("fault_injections", refused == len(rows) == 9 and admitted,
                      f"{refused} of {len(rows)} refused by their expected reasons, clean targets admitted {admitted}")

    # ---------------------------------------------------------------- zaznam.json

    def _subory(self):
        """The paths and sha256 of what the run made (the skeleton, row C3)."""
        files = {}

        def item(path):
            path = Path(path)
            return {"path": str(path), "sha256": _sha(path)} if path.is_file() else {"path": str(path), "sha256": None}
        files["protocol"] = item(self.protocol)
        for key, attr in (("copy", "kopia"), ("copy_without_mask", "kopia0"), ("qualification", "kvalifikacia"),
                          ("generator", "generator_file"), ("index", "index"), ("ending", "ending"),
                          ("final", "final"), ("ledger", "kniha"), ("ledger_before_final", "kniha_pred"),
                          ("faults", "faults")):
            if getattr(self, attr, None) is not None:
                files[key] = item(getattr(self, attr))
        if getattr(self, "endings", None):
            files["endings"] = {name: item(path) for name, path in self.endings.items()}
        if getattr(self, "bundles", None):
            files["bundles"] = [dict(item(Path(b) / "manifest.json"), bundle=str(b)) for b in self.bundles]
        if getattr(self, "record", None) is not None:
            files["attachments"] = self.record["values"].get("attachments")
            files["replays"] = str(self.praca / "prehratia")
        if getattr(self, "sprava", None) is not None:
            files["report"] = {"directory": str(self.sprava), "summary": item(self.sprava / "summary.json"),
                               "readme": item(self.sprava / "README.md"), "exit": self.sprava_code,
                               "log": item(self.out / "sprava.log")}
        return files

    def _retaz(self):
        """chain_end_to_end (the skeleton, section 2): what the run did, from the plan to the report."""
        from scripts.tests import suchy_kampan as sk
        h, P = self.h, self.P
        captures = self.generator_values["captures"]
        corpus = set(self.corpus_ids)
        mine = [c for c in captures if c["session"] in corpus]
        events = [e for c in mine for e in c["row"].get("events", [])]
        controls = [x for c in mine for x in c["row"].get("controls", []) if x.get("kind") is not None]
        invalid = {sid: entry["invalid_rows"] for sid, entry in self.generator_values["sessions"].items()
                   if entry["invalid_rows"]}
        ending = self.ending_doc["values"]
        rejected = [{"session": c["session"], "reasons": c["reasons"], "read_error": c["read_error"]}
                    for c in captures if not c["accepted"]]
        return {
            "record": {"stage": self.record.get("stage"), "status": self.record["values"].get("status"),
                       "mark": (self.record["values"].get("mark") or {}).get("mark")},
            "group_prefixes": {"campaign": P["group_prefix"], "rehearsal": P["rehearsal"]["group_prefix"],
                               "groups": sorted({c["row"]["group"] for c in captures})},
            "vms": sorted({c["vm"] for c in captures}),
            "events": {"sessions": sum(bool(c["row"].get("events")) for c in mine), "occurrences": len(events),
                       "types": sorted({e["type"] for e in events})},
            "controls": {"sessions": sum(bool(c["row"].get("controls")) for c in mine), "occurrences": len(controls),
                         "kinds": sorted({x["kind"] for x in controls})},
            "tolerated_invalid_rows": {"sessions": invalid, "rows": sum(len(v) for v in invalid.values())},
            "rehearsal": {"campaign": self.rehearsal.name, "ending": str(self.endings[self.rehearsal.name]),
                          "sessions": sum(c["campaign"] == self.rehearsal.name for c in captures)},
            "campaign": {"campaign": self.campaign.name, "ending": str(self.ending), "corpus_sessions": len(corpus),
                         "planned_sessions": ending.get("planned_sessions"),
                         "accepted_sessions": ending.get("accepted_sessions"),
                         "rejected_sessions": ending.get("rejected_sessions"),
                         "replacements_used": ending.get("replacements_used")},
            "replacement": {"injected": self.injected, "rejected": rejected,
                            "replaced": [r for r in ending.get("rejected_sessions") or [] if r.get("replacement")]},
            "fakes": [f["fake"] for f in sk.FAKES], "check_E": self.check_e, "report_exit": self.sprava_code,
            "network": {"attempts": list(self.siet.attempts), "rule": "bez_siete: no connection of an internet socket"},
            "stages_asked_by_the_campaign": len(h.gates), "selftests_asked_by_the_campaign": len(h.selftests)}

    def _zaznam(self):
        """zaznam.json (check E's header): the copy and both hashes, the fakes, the steps, the paths and sha256, the
        claims, and one entry per criterion of G1 (the skeleton, section 2) with what the run shows of it."""
        from scripts import gates
        from scripts.tests import suchy_kampan as sk
        ok = self.failure is None and getattr(self, "record", None) is not None
        values = {
            "status": "complete" if self.failure is None else "failed", "failure": self.failure,
            "generator": self.generator, "seed": self.seed, "cesta": self.cesta, "chyby": self.chyby,
            "protocol": {"path": str(self.protocol), "sha256": _sha(self.protocol),
                         "g0_stage_sha256": gates.stage_sha256(self.protocol, "G0"),
                         "g1_stage_sha256": gates.stage_sha256(self.protocol, "G1")},
            "copy": {"values": {path: dict(item, file=_cesta_alebo_nic(self.real_doc, path)) for path, item in
                                getattr(self, "values", {}).items()},
                     "check": getattr(self, "copy_check", None), "rule": COPY_RULE,
                     "mask_rule": MASK_RULE, "mask_finding": getattr(self, "mask_finding", None)},
            "gates": getattr(self, "gates", []), "results": str(self.vysledky),
            "fakes": list(sk.FAKES), "infrastructure": list(sk.INFRASTRUCTURE),
            "command_patches": list(COMMAND_PATCHES), "threads": getattr(self, "threads", None),
            "steps": list(self.kroky),
            "files": self._subory(), "checks": list(self.checks),
            "shortening": None if self.cesta == "plna" else {"rule": SHORT_RULE, "kept_networks":
                                                             list(KEPT_NETWORKS[self.generator])},
            "cleanup": {"removed": getattr(self, "removed", []), "rule": CLEANUP_RULE},
            "rules": {"exit": EXIT_RULE, "faults": FAULTS_RULE, "short": SHORT_RULE, "copy": COPY_RULE,
                      "mask": MASK_RULE, "session": sk.SESSION_RULE, "read_error": sk.READ_ERROR_RULE}}
        if ok:
            record = self.record["values"]
            claims = _riadky_tvrdeni(record)
            controls = ((record.get(OPISNE) or {}).get("diagnostics") or {}).get("claims")
            values["claims"] = claims
            values["known_answers"] = {
                "chain_end_to_end": self._retaz(),
                "null_generator": {"applies": self.generator == "nulovy", "claims": claims,
                                   "reader": "tcn.suchy_beh hranice_m, rozhodnutia and bez_jedneho over the records of "
                                             "at least MIN_RUNS null runs (package C4)"},
                "structured_generator": {"applies": self.generator == "strukturovany", "claims": claims,
                                         "controls": controls,
                                         "reader": "tcn.suchy_beh strukturovane(final.json, m) at the bounds m of G1 "
                                                   "(package C4)"},
                **self.answers,
                "fault_injections": getattr(self, "faults_summary", None) or {"not_run": "the run had no --chyby"}}
        n = len(getattr(self, "corpus_ids", []) or [])
        _zapis(self.out / "zaznam.json", hlavicka_e(SCHEMA_RUN, self.command, n, values))


OPISNE = "opisné"  # tcn/finalne.py OPISNE
REJECTED_ROLE = "train"  # The role whose first planned session the campaign rejects once (judgment, G1 preparation).


def _cesta_alebo_nic(doc, path):
    """The value at `path` of the real file, or None where it has none."""
    try:
        return _cesta(doc, path)
    except (KeyError, TypeError):
        return None


def main(argv=None):
    """python -m tcn.suchy_beh beh ...: one run of the G1 dry run (Beh); --help prints the module docstring."""
    import argparse
    import shlex
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--help"], ["-h"]):
        print(__doc__.rstrip())
        return 0
    parser = argparse.ArgumentParser(prog="python -m tcn.suchy_beh", description="the G1 dry run (package C3)")
    sub = parser.add_subparsers(dest="command", required=True)
    beh = sub.add_parser("beh", help="one run from the plan to the report and check E")
    beh.add_argument("--generator", required=True, choices=REZIMY, help="the generator of the sessions (C1)")
    beh.add_argument("--seed", required=True, type=int, help="the run's seed, an integer of at least 0")
    beh.add_argument("--out", required=True, type=Path, help="a new directory for the run's records and logs")
    beh.add_argument("--praca", required=True, type=Path,
                     help="a new working directory (the campaign, the bundles, the replays), outside --out")
    beh.add_argument("--cesta", required=True, choices=CESTY,
                     help="plna: the whole final evaluation; skratena: SHORT_RULE (POKYNY_TEMPO point 5)")
    beh.add_argument("--protocol", type=Path, default=PROTOKOL,
                     help=f"the protocol file of the run (default {PROTOKOL.relative_to(REPO)}, the real file)")
    beh.add_argument("--vysledky", type=Path, default=VYSLEDKY,
                     help=f"the gate records scripts/gates.py require reads (default {VYSLEDKY.relative_to(REPO)})")
    beh.add_argument("--chyby", action="store_true", help="the nine injected errors on the run's targets")
    try:
        a = parser.parse_args(argv)
    except SystemExit as exit_:
        return exit_.code if type(exit_.code) is int else 2
    command = shlex.join(["python", "-m", "tcn.suchy_beh", *argv])
    try:
        run = Beh(a.generator, a.seed, a.out, a.praca, a.cesta, protocol=a.protocol, vysledky=a.vysledky,
                  chyby=a.chyby, command=command)
    except (OSError, ValueError) as error:
        print(f"tcn.suchy_beh: {error}", file=sys.stderr)
        return 2
    code = run.run()
    print(json.dumps({"zaznam": str(run.out / "zaznam.json"), "exit": code,
                      "checks": {c["check"]: c["holds"] for c in run.checks}}, ensure_ascii=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
