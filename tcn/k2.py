"""K2: the interventions of classes C and D detected at the matched alarm rate, and the confirmatory claims K2a and K2b
(protocol v5, package B7b, agent I).

Binding texts: the lead's skeleton dokazy/B7/kostra/KOSTRA.md sections 4, 5 and 9 with the B7b row of section 8, the
design dokazy/B7/navrh/NAVRH_B7b.md sections 1.2 and 2, and proposal 4.1, 6.4, 8.4 and 9.1. The interventions are
tcn/zasahy.py's; the methods, the window sets, the alarm rule and the matched threshold tcn/metody.py's; the interval,
the test and the three outcomes tcn/tvrdenia.py's rozhodni, unchanged.

    matched_thresholds(methods, calibration, clean, budget, *, k, n)
                                the threshold of every method at the budget (tcn.metody THRESHOLD_RULE)
    detect(method, threshold, plan, *, k, n)
                                which interventions of a plan the method detects (DETECTION_RULE)
    detection(plans, *, protocol)
                                the function (method, threshold, k, n) -> its record that the diagnostics of
                                tcn/diagnostiky.py (alarm_rules, clean_threshold) call at every threshold: detect over
                                the plans given and the share detected (DIAGNOSTIC_DETECTION_RULE; merge of B7b)
    class_status(interventions, min_evaluable)
                                planned, evaluable, volume and not placed per class, and whether the class is
                                evaluated or nevyhodnotené (SHARE_RULE)
    pooled(status)              the classes whose interventions enter a share: both whenever one is evaluated
                                (POOL_RULE, skeleton section 9)
    k2_values(protocol, plans, *, models, methods, calibration, clean, budget, mode)
                                the shares per boot of every method, M as the median of its seeds, and D per boot
                                against every method of analysis.k2a.compare and analysis.k2b.compare (K2_RULE), with
                                the table by class and length, the volume class and the finding of the volume class
                                (descriptive; volume_finding, VOLUME_FINDING_RULE: the lead's answer to Q14)
    k2(protocol, values, *, mode)
                                K2a and K2b by tcn.tvrdenia.rozhodni
    z1_criterion(plan, calibration, clean, budget, *, protocol)
                                the criterion of Z1's selection on dev (CRITERION_RULE; tcn.metody.Z1(criterion))
    known_answer(structured, ...)
                                sessions with a known answer, with and without structure (GENERATOR_RULE; skeleton
                                section 9: the tests of B7b and the dry run of G1)

k2_values reads the keys of design 1.4 (tcn.zasahy.protocol_keys) and k2 the analysis plan through rozhodni; under the
final protocol both read one document.
"""
from collections import Counter
import math

import numpy as np

from tcn.metody import UNEVALUATED, alarm_edges, alarm_rule, matched_threshold, protocol_value
from tcn.zasahy import CARRIER_ROLES, CLASSES, DEV_ROLE, Carriers, Plan, protocol_keys

SCHEMA = "hyptcn3/k2-values/1"
CLAIMS = ("k2a", "k2b")
# UNEVALUATED (tcn.metody, one constant with tcn/diagnostiky.py): proposal 6.4, a class with fewer than min_evaluable
# evaluable interventions.
EVALUATED = "evaluated"

DETECTION_RULE = (
    "an intervention is detected by a method when an alarm (tcn.metody ALARM_RULE) of the method at its matched "
    "threshold (tcn.metody THRESHOLD_RULE at the budget, every method and every seed of M alike: design 1.2, "
    "metody.matched_rate) begins at a window of the intervention's copy whose last row lies in [t, t + "
    "analysis.horizon_s], t the time of the block's first row (judgment: closed, as the horizon of scripts/controls.py "
    "is closed at its end; the window that ends at the block's first row already reads it); the copy holds "
    "window_rows windows before the block, so the alarm state at the block is that of the session for every rule with "
    "n up to window_rows; an intervention not placed is detected by no method")
POOL_RULE = (
    "the classes C and D are pooled (skeleton section 9: D is computed from every intervention of both classes; "
    "the table by class and length is descriptive): whenever at least one class is evaluated, a share is taken over "
    "every planned intervention of both classes, so a class below analysis.interventions.min_evaluable stays in the "
    "denominator with all of its planned interventions and in the numerator with its evaluable ones detected; its "
    "status nevyhodnotené is kept in the record (classes) and in the table by class and length; only when no class "
    "is evaluated is the share nevyhodnotené (sections 5 and 9 of the skeleton read together: section 5 makes a "
    "class nevyhodnotené, section 9 computes D from every intervention of both classes; verification of B7b, F1)")
SHARE_RULE = (
    "the share of a boot is the number of its interventions that are evaluable (placed and valid, tcn/zasahy.py) and "
    "detected over the number planned (proposal 6.4: the denominator is the planned count; an intervention not placed "
    "or of the volume class is no success), both classes pooled (POOL_RULE); a class is evaluated when at least "
    "analysis.interventions.min_evaluable of its planned interventions over the carrier roles are evaluable, else "
    "nevyhodnotené (proposal 6.4); M's share of a boot is the median of the shares of its seeds analysis.seeds "
    "(proposal 8.4, D14), every seed reported")
K2_RULE = (
    "D = M's share - Z's share per boot (skeleton section 4) over the boots of test_benign and test_controls, for each"
    " method of analysis.k2a.compare (K2a) and analysis.k2b.compare (K2b): a name with a variant (Z4:load) is the "
    "method of that label, a name without one the one method of that name (two methods of the name are refused: "
    "question Q13); decided by tcn.tvrdenia.rozhodni unchanged on the shares of both classes pooled (POOL_RULE), a "
    "class below the minimum reported nevyhodnotené by class; when no class is evaluated both claims are "
    "nevyhodnotené; the table by class and length and the volume class are descriptive")
DIAGNOSTIC_DETECTION_RULE = (
    "the detection of the diagnostics (tcn/diagnostiky.py alarm_rules and clean_threshold: the sensitivity of the "
    "share of interventions detected to the alarm rule and to the threshold, descriptive): at a threshold and a rule "
    "k of n given, detect() (DETECTION_RULE) of every plan given, and the share of the interventions detected and "
    "evaluable over the planned ones (SHARE_RULE) pooled over the plans and per boot, over both classes whenever one "
    "is evaluated (POOL_RULE); with no class evaluated the share is nevyhodnotené; the random variant of Z0 detects no "
    "intervention (its numbers are drawn per window set) and is recorded as not computed")
CRITERION_RULE = (
    "the criterion of Z1's selection on dev (skeleton sections 2 and 9): the share of the interventions inserted into "
    "dev (tcn/zasahy.py, role dev, its own unit of the stream injections) that the candidate detects at its matched "
    "threshold (DETECTION_RULE), detected and evaluable over planned, pooled over the whole role and over both classes "
    "whenever one class of dev is evaluated (SHARE_RULE, POOL_RULE); with no class of dev evaluated Z1 has no "
    "criterion; these interventions never enter K2")
# The lead's answer to question Q14 (2026-11-24): G3a reports the share of the volume class by class and length, and
# a share above one half at some length is a finding for the lead (the lead's number, VOLUME_FINDING_RULE).
VOLUME_FINDING_SHARE = 0.5
VOLUME_FINDING_RULE = (
    "the report of the volume class (the lead's answer to question Q14, 2026-11-24): every row of the table by class "
    "and length of the carrier roles holds volume_share, its interventions of the volume class (tcn/zasahy.py "
    "VALIDITY_RULE) over its planned ones (None when it has none); a row whose share lies above "
    f"{VOLUME_FINDING_SHARE} (the lead's number: above one half at some length) is a cell of volume_finding, a finding "
    "for the lead that G3a reports (the final command in mode rehearsal); it is descriptive, decides nothing and never "
    "changes the predicate, which is valid from G1 on and never tuned")


# ------------------------------------------------------------------ thresholds and detections


def _label(method):
    return getattr(method, "label", None) or method.name


def _method(method):
    if not (type(getattr(method, "name", None)) is str and callable(getattr(method, "scores", None))):
        raise ValueError("a method of K2 has the interface of tcn.metody.Metoda (name, scores)")
    if method.name == "Z0" and getattr(method, "variant", None) == "random":
        raise ValueError("the random variant of Z0 draws the numbers of a whole window set, so a copy would get other "
                         "numbers than its session: it detects no intervention (Z0 is in no comparison of K2)")
    return method


def matched_thresholds(methods, calibration, clean, budget, *, k, n):
    """{label: tcn.metody.matched_threshold record} of every method at `budget` on the clean windows of calibration."""
    out = {}
    for method in methods:
        label = _label(_method(method))
        if label in out:
            raise ValueError(f"two methods have the label {label}; every method of K2 has its own")
        out[label] = matched_threshold(method.scores(calibration), calibration, budget, k=k, n=n, clean=clean)
    return out


def detect(method, threshold, plan, *, k, n):
    """{intervention id: whether `method` detects it at `threshold` (DETECTION_RULE)}, None for one not placed."""
    _method(method)
    if not isinstance(plan, Plan):
        raise ValueError("detect takes the plan of the interventions of one role (tcn.zasahy.plan)")
    if type(n) is int and n > plan.carriers.windows.window_rows:
        raise ValueError(f"the copies hold {plan.carriers.windows.window_rows} windows before the block; an alarm rule "
                         f"of n {n} needs n")
    out = {item["id"]: None for item in plan.interventions}
    if plan.copies is None:
        return out
    edges = alarm_edges(method.scores(plan.copies), plan.copies, threshold, k=k, n=n)
    for ident, horizon in plan.horizons.items():
        out[ident] = bool(edges[horizon].any())
    return out


def detection(plans, *, protocol):
    """DIAGNOSTIC_DETECTION_RULE: the function detection(method, threshold, k, n) -> its record that tcn/diagnostiky.py
    alarm_rules and clean_threshold take, over `plans` {role: tcn.zasahy.plan of that role} (the carrier roles for K2's
    interventions, or dev); the evaluable minimum is the protocol's (analysis.interventions.min_evaluable)."""
    keys = protocol_keys(protocol)
    if type(plans) is not dict or not plans or not all(isinstance(plan, Plan) and plan.role == role
                                                       for role, plan in plans.items()):
        raise ValueError("detection takes {role: tcn.zasahy.plan of that role}, one plan or more")
    windows = [plan.carriers.windows for plan in plans.values()]
    if not all(w.same(windows[0]) for w in windows):
        raise ValueError("the plans of a detection are of one normalizer and window")
    interventions = [item for plan in plans.values() for item in plan.interventions]
    status = class_status(interventions, keys["min_evaluable"])
    evaluated = [cls for cls in CLASSES if status[cls]["status"] == EVALUATED]
    classes = pooled(status)
    boots = [boot for plan in plans.values() for boot in plan.boots]
    head = {"rule": DIAGNOSTIC_DETECTION_RULE, "detection_rule": DETECTION_RULE, "share_rule": SHARE_RULE,
            "pool_rule": POOL_RULE, "roles": list(plans), "classes": status, "evaluated": evaluated,
            "pooled": classes}

    def detected_interventions(method, threshold, k, n):
        record = dict(head, label=_label(method), threshold=float(threshold), k=k, n=n)
        if getattr(method, "name", None) == "Z0" and getattr(method, "variant", None) == "random":
            return dict(record, status="not computed", why="the random variant of Z0 draws its numbers per window set: "
                                                           "it detects no intervention (DETECTION_RULE)")
        found = {}
        for plan in plans.values():
            found.update(detect(method, threshold, plan, k=k, n=n))
        record["detected"] = found
        if not classes:
            return dict(record, status=UNEVALUATED, share=None, shares=None)
        return dict(record, status=EVALUATED, share=_share(interventions, found, classes),
                    shares=_share(interventions, found, classes, boots))
    detected_interventions.rule = DIAGNOSTIC_DETECTION_RULE
    return detected_interventions


def class_status(interventions, min_evaluable):
    """{class: {planned, evaluable, volume, not_placed, status}}: status evaluated with at least `min_evaluable`
    evaluable interventions, else nevyhodnotené (SHARE_RULE)."""
    if type(min_evaluable) is not int or min_evaluable < 1:
        raise ValueError("the evaluable minimum is an integer of at least 1")
    out = {}
    for cls in CLASSES:
        found = Counter(item["status"] for item in interventions if item["class"] == cls)
        planned = sum(found.values())
        out[cls] = {"planned": planned, "evaluable": found["evaluable"], "volume": found["volume"],
                    "not_placed": found["not_placed"],
                    "status": EVALUATED if found["evaluable"] >= min_evaluable else UNEVALUATED}
    return out


def pooled(status):
    """POOL_RULE: the classes whose planned interventions enter a share, from class_status(): both classes whenever at
    least one of them is evaluated, none when no class is (the share is then nevyhodnotené)."""
    return list(CLASSES) if any(status[cls]["status"] == EVALUATED for cls in CLASSES) else []


def _share(interventions, detected, classes, boots=None):
    """SHARE_RULE: {boot: share} over `boots`, or the share over all of them when boots is None."""
    planned, hits = Counter(), Counter()
    for item in interventions:
        if item["class"] not in classes:
            continue
        key = item["boot"] if boots is not None else None
        planned[key] += 1
        hits[key] += item["status"] == "evaluable" and bool(detected[item["id"]])
    if boots is None:
        return hits[None] / planned[None]
    return {boot: hits[boot] / planned[boot] for boot in boots}


# ------------------------------------------------------------------ K2


def _compared(entry, methods, claim):
    """The label of the method that `entry` of analysis.<claim>.compare names (K2_RULE)."""
    if type(entry) is not str or not entry:
        raise ValueError(f"analysis.{claim}.compare names methods, not {entry!r}")
    found = [label for label, method in methods.items() if (label if ":" in entry else method.name) == entry]
    if not found:
        raise ValueError(f"analysis.{claim}.compare names {entry}, which is not among the methods given "
                         f"({', '.join(methods)})")
    if len(found) > 1:
        raise ValueError(f"analysis.{claim}.compare names {entry}, of which {len(found)} methods are given "
                         f"({', '.join(found)}): name the variant (question Q13: Z4:load and Z4:residual)")
    return found[0]


def k2_values(protocol, plans, *, models, methods, calibration, clean, budget, mode):
    """The values of K2 (K2_RULE, SHARE_RULE, DETECTION_RULE): plans {role: tcn.zasahy.plan} of exactly test_benign and
    test_controls; models {seed: M of that seed} for exactly analysis.seeds; methods every other method (Z1 to Z5 and
    the descriptive ones), each fitted on the same normalizer; calibration, its clean mask and the budget give every
    threshold (tcn.metody.model_budget gives the budget); mode the plan mode, no default. The interventions of dev are
    refused here: they select Z1 and never enter K2."""
    keys = protocol_keys(protocol)
    k, n = alarm_rule(protocol)
    seeds = protocol_value(protocol, "analysis.seeds")
    if (type(seeds) is not list or not seeds or not all(type(x) is int and x >= 0 for x in seeds)
            or len(set(seeds)) != len(seeds)):
        raise ValueError("analysis.seeds must be a non-empty list of distinct integers of at least 0")
    if type(plans) is not dict or set(plans) != set(CARRIER_ROLES):
        raise ValueError("K2 takes the plans of exactly " + " and ".join(CARRIER_ROLES) + f"; the interventions of "
                         f"{DEV_ROLE} select Z1 and never enter K2")
    boots = []
    for role in CARRIER_ROLES:
        plan = plans[role]
        if not isinstance(plan, Plan) or plan.role != role:
            raise ValueError(f"the plan of {role} is tcn.zasahy.plan of the carriers of {role}")
        if plan.mode != mode:
            raise ValueError(f"the plan of {role} was drawn in mode {plan.mode}, K2 is in mode {mode}")
        if not plan.carriers.windows.same(calibration):
            raise ValueError(f"the plan of {role} is not of calibration's normalizer and window")
        if set(boots) & set(plan.boots):
            raise ValueError(f"a boot of {role} is a boot of the other carrier role")
        boots += plan.boots
    if mode == "campaign" and len(boots) != keys["boots"]:
        raise ValueError(f"the carrier roles hold {len(boots)} boots, analysis.interventions.boots is {keys['boots']}")
    if type(models) is not dict or sorted(models) != sorted(seeds):
        raise ValueError(f"models gives M of exactly the seeds analysis.seeds {seeds} (M enters by their median, D14)")
    for seed, model in models.items():
        if getattr(_method(model), "name", None) != "M" or getattr(model, "seed", seed) != seed:
            raise ValueError(f"the model of seed {seed} is M of that seed")
    if type(methods) not in (list, tuple) or any(getattr(_method(m), "name", None) == "M" for m in methods):
        raise ValueError("methods are the methods other than M (the seeds of M are models)")
    order = [*(models[seed] for seed in seeds), *methods]
    labels = [_label(method) for method in order]
    if len(set(labels)) != len(labels):
        raise ValueError(f"two methods have the label {next(x for x in labels if labels.count(x) > 1)}; every method "
                         "of K2 has its own")
    by_label = dict(zip(labels, order))
    model_labels = {seed: _label(models[seed]) for seed in seeds}
    others = {label: method for label, method in by_label.items() if label not in model_labels.values()}
    compare = {claim: {entry: _compared(entry, others, claim)
                       for entry in protocol_value(protocol, f"analysis.{claim}.compare")} for claim in CLAIMS}
    thresholds = matched_thresholds(order, calibration, clean, budget, k=k, n=n)
    detected = {}
    for label, method in by_label.items():
        detected[label] = {}
        for role in CARRIER_ROLES:
            detected[label].update(detect(method, thresholds[label]["threshold"], plans[role], k=k, n=n))
    interventions = [item for role in CARRIER_ROLES for item in plans[role].interventions]
    status = class_status(interventions, keys["min_evaluable"])
    evaluated = [cls for cls in CLASSES if status[cls]["status"] == EVALUATED]
    classes = pooled(status)
    record = {"schema": SCHEMA, "mode": mode, "k": k, "n": n, "budget": budget, "seeds": list(seeds), "boots": boots,
              "roles": {role: {"boots": plans[role].boots, "counts": plans[role].record()["counts"]}
                        for role in CARRIER_ROLES},
              "thresholds": thresholds, "classes": status, "evaluated": evaluated, "pooled": classes,
              "status": EVALUATED if classes else UNEVALUATED, "detected": detected, "compare": compare,
              "rules": {"detection": DETECTION_RULE, "share": SHARE_RULE, "pool": POOL_RULE, "k2": K2_RULE}}
    if classes:
        shares = {label: _share(interventions, detected[label], classes, boots) for label in labels}
        per_seed = {seed: shares[model_labels[seed]] for seed in seeds}
        median = {boot: float(np.median([per_seed[seed][boot] for seed in seeds])) for boot in boots}
        record.update(shares=shares, model={"labels": [model_labels[seed] for seed in seeds], "median": median},
                      values={claim: {entry: {boot: median[boot] - shares[label][boot] for boot in boots}
                                      for entry, label in compare[claim].items()} for claim in CLAIMS})
    table = _table(interventions, detected, labels, model_labels, seeds, keys, status)
    record.update(table=table, volume=_volume(interventions, detected, labels, keys),
                  volume_finding=volume_finding(table))
    return record


def volume_finding(table):
    """VOLUME_FINDING_RULE over the rows of _table: {bound, cells [{class, length, volume, planned, share}] of every
    row whose volume_share lies above the bound, in the order of the table, finding (whether there is a cell),
    rule}."""
    cells = [{"class": row["class"], "length": row["length"], "volume": row["volume"], "planned": row["planned"],
              "share": row["volume_share"]} for row in table
             if row["volume_share"] is not None and row["volume_share"] > VOLUME_FINDING_SHARE]
    return {"bound": VOLUME_FINDING_SHARE, "cells": cells, "finding": bool(cells), "rule": VOLUME_FINDING_RULE}


def _table(interventions, detected, labels, model_labels, seeds, keys, status):
    """The descriptive table by class and length: the counts, the share of the volume class (VOLUME_FINDING_RULE),
    the share of every method (detected and evaluable over planned) and M's median over its seeds; a cell with fewer
    than min_evaluable evaluable is nevyhodnotené, and every cell carries the status of its class (class_status: a
    class below the minimum stays pooled in K2, POOL_RULE)."""
    rows = []
    for cls in CLASSES:
        for length in keys["classes"][cls]["lengths"]:
            mine = [item for item in interventions if item["class"] == cls and item["length"] == length]
            count = Counter(item["status"] for item in mine)
            row = {"class": cls, "length": length, "planned": len(mine), "evaluable": count["evaluable"],
                   "volume": count["volume"], "not_placed": count["not_placed"],
                   "volume_share": count["volume"] / len(mine) if mine else None,
                   "status": EVALUATED if count["evaluable"] >= keys["min_evaluable"] else UNEVALUATED,
                   "class_status": status[cls]["status"]}
            if mine:
                row["shares"] = {label: sum(item["status"] == "evaluable" and bool(detected[label][item["id"]])
                                            for item in mine) / len(mine) for label in labels}
                row["model_median"] = float(np.median([row["shares"][model_labels[seed]] for seed in seeds]))
            rows.append(row)
    return rows


def _volume(interventions, detected, labels, keys):
    """The volume class, reported apart (skeleton section 5) by planned class and by its lengths: the count and, for
    every method, the number detected and their share of those volume interventions (None where there is none)."""
    def cell(mine):
        hits = {label: sum(bool(detected[label][item["id"]]) for item in mine) for label in labels}
        return {"count": len(mine), "detected": hits,
                "shares": {label: hits[label] / len(mine) for label in labels} if mine else None,
                "ids": [item["id"] for item in mine]}
    out = {}
    for cls in CLASSES:
        mine = [item for item in interventions if item["class"] == cls and item["status"] == "volume"]
        out[cls] = dict(cell(mine), lengths={str(length): cell([item for item in mine if item["length"] == length])
                                             for length in keys["classes"][cls]["lengths"]})
    return out


def k2(protocol, values, *, mode):
    """K2a and K2b (K2_RULE) from k2_values(): tcn.tvrdenia.rozhodni of each claim on its values D per boot (both
    classes pooled, POOL_RULE, the status of each class beside them); both are nevyhodnotené when no class is
    evaluated. The protocol is the one k2_values read (rozhodni reads its analysis plan, analysis.<claim>.m null
    refused by name)."""
    from tcn.tvrdenia import rozhodni
    if type(values) is not dict or values.get("schema") != SCHEMA:
        raise ValueError("K2 decides on the values of k2_values()")
    if values["mode"] != mode:
        raise ValueError(f"the values of K2 are of mode {values['mode']}, not {mode}")
    out = {}
    for claim in CLAIMS:
        if values["status"] == UNEVALUATED:
            out[claim] = {"claim": claim, "mode": mode, "outcome": None, "status": UNEVALUATED,
                          "why": "no class has analysis.interventions.min_evaluable evaluable interventions",
                          "classes": values["classes"]}
            continue
        decided = rozhodni(protocol, claim, values["values"][claim], rezim=mode)
        out[claim] = dict(decided, status=EVALUATED, classes_pooled=list(values["pooled"]),
                          classes=values["classes"], compared_labels=dict(values["compare"][claim]))
    return out


# ------------------------------------------------------------------ the criterion of Z1 on dev


def z1_criterion(plan, calibration, clean, budget, *, protocol):
    """The criterion of tcn.metody.Z1(criterion) (CRITERION_RULE): criterion(candidate, dev) -> the share of the
    interventions of `plan` (role dev) that the fitted candidate detects at its matched threshold on calibration (its
    clean mask `clean`, the budget `budget`); dev must be the window set of the plan."""
    keys = protocol_keys(protocol)
    k, n = alarm_rule(protocol)
    if not isinstance(plan, Plan) or plan.role != DEV_ROLE:
        raise ValueError(f"Z1 is selected by the interventions inserted into {DEV_ROLE} (a plan of role {DEV_ROLE})")
    if not plan.carriers.windows.same(calibration):
        raise ValueError(f"the plan of {DEV_ROLE} is not of calibration's normalizer and window")
    status = class_status(plan.interventions, keys["min_evaluable"])
    classes = pooled(status)
    if not classes:
        raise ValueError(f"no class of the interventions of {DEV_ROLE} has analysis.interventions.min_evaluable "
                         "evaluable ones: Z1 has no criterion")

    def share_of_dev_interventions_detected(candidate, windows):
        if windows is not plan.carriers.windows:
            raise ValueError("Z1's criterion takes the window set of dev its interventions were placed in")
        found = matched_threshold(candidate.scores(calibration), calibration, budget, k=k, n=n, clean=clean)
        return _share(plan.interventions, detect(candidate, found["threshold"], plan, k=k, n=n), classes)
    share_of_dev_interventions_detected.rule = CRITERION_RULE
    share_of_dev_interventions_detected.classes = classes  # The classes pooled (POOL_RULE).
    share_of_dev_interventions_detected.status = status  # The status of each class of dev (class_status).
    return share_of_dev_interventions_detected


# ------------------------------------------------------------------ generators with a known answer (skeleton section 9)

# The TCN inputs of the generator (GENERATOR_RULE): two memory aggregates drive two process counts, so that D breaks
# the relation whichever of the groups memory and processes of analysis.interventions.D.groups it swaps.
GENERATOR_INPUTS = ("mem_changed_ratio", "mem_bins_active", "proc_user", "proc_kernel", "proc_new")
# Judgment (the generator's author, skeleton section 9): the spread of a, the gain and the noise of b, and the mean of
# the count; chosen so that a trained TCN reads b from a in a few epochs while the noise of a's own error stays small.
GENERATOR = {"sigma_a": 0.3, "gain": 2.0, "noise": 0.1, "count_mean": 0.2}
GENERATOR_RULE = (
    "sessions of the synthetic normalizer's inputs (mean 0, scale 1: the values are the normalized inputs) on the "
    "interval grid with no event, no control and no full snapshot (every window placeable), boots of three sessions of"
    " one scenario at positions 0, 1 and 2; five TCN inputs: the drivers a1 = mem_changed_ratio and a2 = "
    "mem_bins_active, each i.i.d. normal(0, sigma_a), the driven b1 = proc_user and b2 = proc_kernel, and the count c "
    "= proc_new i.i.d. Poisson(count_mean); with structure b1_t = f(a1_{t-1}) and b2_t = f(a2_{t-1}), f(x) = gain ((x "
    "/ sigma_a)^2 - 1) / sqrt(2), each plus noise e_t: a relation in time between the group memory (the drivers) and "
    "the group processes (the driven) that neither a threshold on one column, nor a prediction without learning, nor a"
    " linear autoregression reads (E[b1_t | past] is a square of a1_{t-1}, uncorrelated with every linear term); "
    "without structure b1 and b2 are the same f of drivers drawn apart from a1 and a2, independent of each other, so "
    "that every column keeps its marginal and no relation is left (the negative case, which decides: skeleton section "
    "9); one bin that never changes; the offered load i.i.d. uniform on [0, 1)")


def synthetic_normalizer(inputs, differenced=()):
    """A normalizer (safeguard/features.py) whose TCN inputs are `inputs` (those of `differenced` by their first
    difference, so the windows are anchored; every other column in the rule channel), mean 0 and scale 1, one scored
    bin of 4096 pages; floor 1 for the counts (proc_total and after) and 1e-3 otherwise."""
    from features.qualification import LOCAL_SCALED
    from safeguard.features import GLOBAL_NAMES, FeatureNormalizer, NormalizationRule
    counts = GLOBAL_NAMES[GLOBAL_NAMES.index("proc_total"):]
    classes = {name: "differenced" if name in differenced else "neural" if name in inputs else "rule"
               for name in GLOBAL_NAMES}
    floor = {name: 1.0 if name in counts else 1e-3 for name in GLOBAL_NAMES}
    rule = NormalizationRule("analysis.columns", classes, floor, True, 1, dict.fromkeys(LOCAL_SCALED, 1e-6))
    width = len(rule.tcn_names)
    return FeatureNormalizer(rule, np.zeros(width), np.ones(width), [(0, 4096)], [], np.zeros((1, 4)),
                             np.ones((1, 4)), 1, 0)


def known_answer(structured, *, seed, boots, rows, window_rows, interval_s, max_gap_s):
    """GENERATOR_RULE: ({role: Carriers}, normalizer) with `boots` {role: number of boots} of three sessions of `rows`
    rows each, every window placeable, the window, the interval and the gap of the protocol given; no default;
    numpy.random.default_rng(seed) draws the roles in the order given."""
    from tcn.metody import Okna
    if type(structured) is not bool:
        raise ValueError("structured is True or False")
    if type(rows) is not int or rows <= window_rows:
        raise ValueError("a session holds more rows than a window")
    normalizer = synthetic_normalizer(GENERATOR_INPUTS)
    rng = np.random.default_rng(seed)
    p = GENERATOR
    out = {}
    for role, count in boots.items():
        sessions, windows, meta = [], [], {}
        for b in range(count):
            for position in range(3):
                drivers = rng.normal(0, p["sigma_a"], (2, rows))
                hidden = drivers if structured else rng.normal(0, p["sigma_a"], (2, rows))
                driven = np.zeros((2, rows))
                driven[:, 1:] = p["gain"] * ((hidden[:, :-1] / p["sigma_a"]) ** 2 - 1) / math.sqrt(2)
                driven += p["noise"] * rng.normal(size=(2, rows))
                c = rng.poisson(p["count_mean"], rows).astype(np.float64)
                ident = f"{role}-{b + 1}-{position}"
                start = 1000. + 10 * rows * interval_s * len(sessions)
                sessions.append({"id": ident, "global": np.stack([*drivers, *driven, c], axis=1),
                                 "local": np.zeros((rows, 1, 4)), "seq": np.arange(rows),
                                 "timestamp": start + interval_s * np.arange(rows), "full_times": [],
                                 "load": rng.uniform(size=rows)})
                windows += [(len(sessions) - 1, end, None) for end in range(window_rows - 1, rows)]
                meta[ident] = {"boot": f"{role}-{b + 1}", "scenario": "synthetic", "position": position}
        okna = Okna(sessions, windows, role=role, normalizer=normalizer, window_rows=window_rows,
                    max_gap_s=max_gap_s, interval_s=interval_s)
        out[role] = Carriers(okna, np.ones(len(okna), dtype=bool), meta)
    return out, normalizer
