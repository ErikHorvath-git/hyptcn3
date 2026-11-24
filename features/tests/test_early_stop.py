"""The early stop of a campaign (protocol v5, package B9b, agent Z, and its fix round: F5 and F8 of the verification of
B9b, question Q24; design dokazy/B9/navrh/NAVRH_B9b.md 1.3, the lead's skeleton dokazy/B9/kostra/KOSTRA.md, row skoré
zastavenie and test 4 of its section 4).

The protocol key audit.early_stop of config/collection-v5.json with its rate of marked rows per occurrence and its
value check (features/audit_policy.py audit_bounds), the bound (poisson_quantile, the 99th percentile of proposal
10.9), the rule on the campaign's count (early_stop), and the count of one session in the event windows of its log
audit (features/acceptance.py marked_rows_by_type, scripts/collection_logs.py event_window). The campaign's sum over the
files of both VMs is tested in scripts/tests/test_early_stop_count.py. The names of package B9b are imported inside
the tests, so this file collects on the code before it. Mechanics only; no number here is a measurement (HONESTY P4).
"""
import json
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
TYPE = "restart_databazy"


def v5(**rates):
    """config/collection-v5.json, with the rates of early stop given set (event type: rate per occurrence)."""
    doc = json.loads(V5.read_text())
    doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(rates)
    return doc


def values(codes=(), run=None):
    """The values of an audit record as far as early_stop reads them: the codes of its verdict and the longest periodic
    run (scripts/collection.py audit_session)."""
    out = {"acceptance": {"codes": list(codes)}}
    if run is not None:
        out["timing"] = {"periodic_run": {"equal_spacings": run, "spacing": 5, "min_spacing_rows": 2,
                                          "flagged_rows": 4}}
    return out


def totals(**counts):
    """The campaign's count (scripts/campaign.py marked_totals): every event type of the file at 0 marked rows in 0
    occurrences, but the types given, each (marked rows, occurrences)."""
    types = json.loads(V5.read_text())["events"]["types"]
    out = {kind: {"marked": 0, "occurrences": 0} for kind in sorted(types)}
    out.update({kind: {"marked": marked, "occurrences": n} for kind, (marked, n) in counts.items()})
    return out


def cdf(k, mean):
    """P(X <= k) for X ~ Poisson(mean), by the series of its terms (an independent computation of the test)."""
    return math.fsum(mean ** j * math.exp(-mean) / math.factorial(j) for j in range(k + 1))


# ------------------------------------------------------------------ the protocol key


def test_the_v5_file_states_one_null_rate_per_event_type_until_g3b():
    """Design B9b 1.3 and F5 of its verification (Q24): audit.early_stop holds one rate of marked rows per occurrence
    for every event type of events.types, each null until G3b (determined_at), the stop for periodicity and a note
    with the rule of proposal 10.9 and Q24; the self-check of stage G0 finds no null outside determined_at, the one of
    stage G3b names every null rate."""
    from features.audit_policy import audit_bounds
    from scripts import protocol_v5
    doc = v5()
    rule = audit_bounds(doc)["early_stop"]
    types = sorted(doc["events"]["types"])
    assert set(rule) == {"marked_rows_rate_per_type", "periodicity_stops", "note"}
    assert (rule["marked_rows_rate_per_type"], rule["periodicity_stops"]) == (dict.fromkeys(types), True)
    assert all(text in rule["note"] for text in ("7.5", "10.9", "Q24", "99th percentile of the Poisson distribution",
                                                 "rate_T x n_T", "G2 and G3b together", "judgment", "null until then"))
    assert "audit.early_stop.marked_rows_rate_per_type.*" in doc["determined_at"]["G3b"]
    assert protocol_v5.check_analysis(doc) == []
    assert [r for r in protocol_v5.check_analysis(doc, stage="G3b") if "early_stop" in r] == [
        f"null at audit.early_stop.marked_rows_rate_per_type.{t} determined at G3b (stage G3b)" for t in types]


@pytest.mark.parametrize("change, key", [
    (lambda doc: doc["audit"]["early_stop"].update(extra=1), ""),
    (lambda doc: doc["audit"]["early_stop"].update(marked_rows_per_type={}), ""),
    (lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].pop("naprazdno"),
     ".marked_rows_rate_per_type"),
    (lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(neznamy_typ=None),
     ".marked_rows_rate_per_type"),
    (lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(naprazdno=-0.1),
     ".marked_rows_rate_per_type"),
    (lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(naprazdno="0.5"),
     ".marked_rows_rate_per_type"),
    (lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(naprazdno=True),
     ".marked_rows_rate_per_type"),
    (lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(naprazdno=math.inf),
     ".marked_rows_rate_per_type"),
    (lambda doc: doc["events"].pop("types"), ".marked_rows_rate_per_type"),
    (lambda doc: doc["audit"]["early_stop"].update(periodicity_stops="yes"), ".periodicity_stops"),
    (lambda doc: doc["audit"]["early_stop"].update(note=" "), ".note"),
], ids=["extra_key", "old_key", "type_without_rate", "rate_of_no_type", "negative", "text", "boolean", "infinite",
        "events_without_types", "periodicity_stops_text", "empty_note"])
def test_a_malformed_early_stop_is_refused_with_its_name(change, key):
    """The value check of audit.early_stop (features/audit_policy.py audit_bounds, the only reader of the audit
    section): each malformed part refused by its name; the key of the bound per session that the fix replaced is an
    unknown key."""
    from features.audit_policy import audit_bounds
    doc = v5()
    change(doc)
    with pytest.raises(ValueError) as error:
        audit_bounds(doc)
    assert str(error.value) == "invalid audit bounds: early_stop" + key


def test_a_schema_3_protocol_needs_the_early_stop_and_takes_rates_of_g3b():
    """Without the key the audit section is refused as a whole (no silent default); a rate is any finite number of at
    least 0, a fraction or a whole number (G3b), and a protocol without an events section has no event type to rate."""
    from features.audit_policy import audit_bounds
    doc = v5()
    del doc["audit"]["early_stop"]
    with pytest.raises(ValueError) as error:
        audit_bounds(doc)
    assert str(error.value) == "invalid audit bounds"
    rates = audit_bounds(v5(naprazdno=0, restart_databazy=0.25, zamok_tabulky=3))["early_stop"][
        "marked_rows_rate_per_type"]
    assert (rates["naprazdno"], rates["restart_databazy"], rates["zamok_tabulky"], rates["zataz_pamate"]) == (
        0, 0.25, 3, None)
    doc = v5()
    del doc["events"]
    doc["audit"]["early_stop"]["marked_rows_rate_per_type"] = {}
    assert audit_bounds(doc)["early_stop"]["marked_rows_rate_per_type"] == {}


# ------------------------------------------------------------------ the bound


@pytest.mark.parametrize("mean, bound", [(0, 0), (0.01, 0), (0.05, 1), (0.1, 1), (0.3, 2), (1.0, 4), (3.0, 8),
                                         (10.0, 18), (36.0, 51)])
def test_the_bound_is_the_99th_percentile_of_the_poisson_distribution(mean, bound):
    """Proposal 10.9: the smallest b with P(X <= b) >= 0.99 for X ~ Poisson(mean); Poisson(0) gives 0. The rates 0.01
    to 3 at one occurrence give the bounds of the executor's model of Q24 (dokazy/B9/navrh/skore_zastavenie_model.txt),
    and each value is checked against the series of the Poisson terms."""
    from features.audit_policy import poisson_quantile
    assert poisson_quantile(mean) == bound
    assert cdf(bound, mean) >= 0.99 and (bound == 0 or cdf(bound - 1, mean) < 0.99)


def test_the_bound_is_the_count_whose_cumulative_probability_is_exactly_0_99():
    """N2 of the confirmation of B9b (the surviving mutant cdf >= EARLY_STOP_LEVEL -> cdf > EARLY_STOP_LEVEL): the
    bound is the smallest b with P(X <= b) >= 0.99, so at a mean of -ln 0.99, where P(X <= 0) = exp(ln 0.99) is 0.99
    to the last bit, the bound is 0, not 1."""
    from features.audit_policy import poisson_quantile
    mean = -math.log(0.99)
    assert math.exp(-mean) == 0.99  # The premise of the case: the probability of no marked row is 0.99 exactly.
    assert poisson_quantile(mean) == 0


def test_the_bound_takes_a_large_mean_and_refuses_what_is_no_mean():
    """A mean of thousands (a high rate over many occurrences) does not underflow: the bound lies above the mean,
    within 3 standard deviations; a mean below 0 or one that is no finite number is refused by name."""
    from features.audit_policy import poisson_quantile
    bound = poisson_quantile(3000.0)
    assert 3000 + 2 * math.sqrt(3000) < bound < 3000 + 3 * math.sqrt(3000)
    for mean in (-1, math.nan, math.inf, True, "1"):
        with pytest.raises(ValueError) as error:
            poisson_quantile(mean)
        assert str(error.value) == f"the mean of a Poisson distribution is a finite number of at least 0, not {mean!r}"


# ------------------------------------------------------------------ the rule (skeleton test 4)


def test_a_session_rejected_for_periodicity_stops_the_campaign():
    """Skeleton test 4, first part: the code periodicity of the verdict stops the campaign, with the periodic run the
    audit recorded against the bound of the periodicity rule; periodicity_stops false would not stop it."""
    from features.audit_policy import EARLY_STOP_RULE, early_stop
    assert early_stop(values(["timing:gap", "periodicity"], run=3), v5(), totals()) == {
        "rule": EARLY_STOP_RULE, "cause": "periodicity", "type": None, "count": 3, "bound": 3, "occurrences": None,
        "rate": None}
    assert early_stop(values(["periodicity"]), v5(), totals())["count"] is None  # A record without its periodic run.
    doc = v5()
    doc["audit"]["early_stop"]["periodicity_stops"] = False
    assert early_stop(values(["periodicity"], run=3), doc, totals()) is None
    assert early_stop(values(["timing:gap"]), v5(), totals()) is None


@pytest.mark.parametrize("rate, occurrences, bound", [(0.3, 1, 2), (0.3, 10, 8), (0.01, 36, 2), (0, 5, 0)])
def test_the_campaigns_count_stops_above_the_bound_at_its_rate(rate, occurrences, bound):
    """Skeleton test 4, second part, by Q24: the campaign's count C_T of marked rows at a type stops the campaign when
    it is above b, the 99th percentile of Poisson(rate_T x n_T) over its n_T occurrences; C_T = b does not stop, b + 1
    does, with the type, the count, the bound, the occurrences and the rate."""
    from features.audit_policy import EARLY_STOP_RULE, early_stop
    doc = v5(**{TYPE: rate})
    assert early_stop(values(), doc, totals(**{TYPE: (bound, occurrences)})) is None
    assert early_stop(values(), doc, totals(**{TYPE: (bound + 1, occurrences)})) == {
        "rule": EARLY_STOP_RULE, "cause": "marked_rows", "type": TYPE, "count": bound + 1, "bound": bound,
        "occurrences": occurrences, "rate": rate}


def test_of_several_types_above_their_bounds_the_first_in_sorted_order_is_named():
    from features.audit_policy import early_stop
    doc = v5(restart_databazy=0.3, zamok_tabulky=0.3)
    assert early_stop(values(), doc, totals(restart_databazy=(3, 1), zamok_tabulky=(3, 1)))["type"] == TYPE
    assert early_stop(values(), doc, totals(restart_databazy=(2, 1), zamok_tabulky=(3, 1)))["type"] == "zamok_tabulky"


def test_a_null_rate_does_not_stop_and_a_set_rate_needs_its_count():
    """Skeleton row skoré zastavenie: while a rate is null its count stops nothing (the runner prints it), also with
    no count at all; a set rate whose count or occurrences the campaign's count does not hold as counts is refused by
    name, never taken as 0; so is an audit record without the codes of its verdict. A protocol of schema 2 has no
    early stop."""
    from features.audit_policy import early_stop
    assert early_stop(values(), v5(), totals(**{TYPE: (10 ** 6, 1)})) is None
    assert early_stop(values(), v5(), {}) is None
    broken = (totals(**{TYPE: (None, 1)}), totals(**{TYPE: (1, -1)}), {"zamok_tabulky": {"marked": 0,
                                                                                        "occurrences": 0}}, None)
    for count in broken:
        with pytest.raises(ValueError) as error:
            early_stop(values(), v5(**{TYPE: 0.5}), count)
        assert str(error.value) == ("early stop: the campaign's count holds no marked rows and occurrences of event "
                                    f"type {TYPE} (scripts/campaign.py early_stop_check), whose rate is 0.5")
    with pytest.raises(ValueError) as error:
        early_stop({"accepted": False}, v5(), totals())
    assert str(error.value) == "early stop: the audit record holds no acceptance codes (values.acceptance.codes)"
    assert early_stop(values(["periodicity"]), {"schema": "hyptcn3/collection-protocol/2"}, None) is None


def test_the_rule_texts_state_the_reading_of_q24_and_the_model_as_a_model():
    """F5 of the verification of B9b: EARLY_STOP_RULE and MARKED_ROWS_RULE state the campaign's count (Q24), its
    restart point, and the false-stop rates of the executor's model as a model. Package B11: Q24 is accepted by the
    lead 2026-11-24, whose text counts on across the continuation (no longer the executor's judgment that a
    continuation counts only its own sessions), and the rule names EARLY_STOP_MODEL, which the G3b record carries."""
    from features.acceptance import MARKED_ROWS_RULE
    from features.audit_policy import EARLY_STOP_RULE
    for text in ("Q24", "campaign's count", "both VMs", "restart point", "latest recorded ending with an early-stop "
                 "trigger", "a continuation counts on", "the paused campaign it continues",
                 "accepted by the lead 2026-11-24", "s náhradami aj s pokračovaním", "RESUME_RULE",
                 "not a measurement", "at most 1 % per type", "0.12 to 0.28", "0.01 to 3", "0.23 to 0.88",
                 "36 occurrences per type and six types", "Poisson(rate_T x n_T)", "EARLY_STOP_MODEL",
                 "stage G3b"):
        assert text in EARLY_STOP_RULE, text
    for text in ("a continuation counts only its own sessions", "the executor's judgment", "decided by its proposal"):
        assert text not in EARLY_STOP_RULE, text
    for text in ("Q24", "event_window", "host_start_unix - 1 s", "host_stopped_unix", "event_grace_s",
                 "restores the lab", "no occurrence", "event_occurrences_by_type", "the campaign sums",
                 "accepted by the lead 2026-11-24", "the paused campaign it continues"):
        assert text in MARKED_ROWS_RULE, text
    assert "decided by its proposal" not in MARKED_ROWS_RULE


MODEL_RATES = (0.01, 0.05, 0.1, 0.3, 1.0, 3.0)  # The rates of the executor's model (skore_zastavenie_model.py).


def exact_model(rate, occurrences, types):
    """The executor's exact model of Q24 at one rate per occurrence (dokazy/B9/navrh/skore_zastavenie_model.py,
    recomputed here): (false stop of one type and of the campaign when the campaign's count of a type is compared
    with poisson_quantile(rate x n) after each of its n = 1 .. occurrences occurrences, false stop of the campaign when
    the count of one session is compared with poisson_quantile(rate) at each occurrence). The counts per occurrence are
    Poisson(rate) and independent; a path that crossed the bound once is a false stop."""
    import numpy as np
    from features.audit_policy import poisson_quantile
    pmf = lambda k, mean: math.exp(-mean + k * math.log(mean) - math.lgamma(k + 1))
    top = poisson_quantile(rate * occurrences) + 1  # Above it every count is a stop at every n, so it is cut.
    step = np.array([pmf(k, rate) for k in range(top + 1)])
    alive = np.zeros(top + 1)
    alive[0] = 1.0
    for n in range(1, occurrences + 1):
        alive = np.convolve(alive, step)[:top + 1]
        alive[poisson_quantile(rate * n) + 1:] = 0.0
    per_type = 1 - alive.sum()
    one = 1 - math.fsum(pmf(k, rate) for k in range(poisson_quantile(rate) + 1))
    return per_type, 1 - (1 - per_type) ** types, 1 - (1 - one) ** (occurrences * types)


def test_the_numbers_of_the_model_follow_from_the_exact_model_at_the_plans_premise():
    """The lead's answer to Q24 (package B11): EARLY_STOP_MODEL states the numbers of the executor's model, which the
    record of stage G3b carries for the owner. Its premise is the campaign plan of config/collection-v5.json (36
    occurrences of each of its 6 event types, the level 0.99); recomputed at the model's rates, the false stops are
    0.021 to 0.054 per type and 0.121 to 0.283 per campaign, against 0.230 to 0.885 for the count of one session, and
    the constant states each range rounded to two decimals, the same numbers EARLY_STOP_RULE names in its text. It is
    a model and says so."""
    from collections import Counter
    from features.audit_policy import EARLY_STOP_LEVEL, EARLY_STOP_MODEL, EARLY_STOP_RULE
    from scripts import protocol_v5
    plan = protocol_v5.plan(json.loads(V5.read_text()), "campaign")
    counts = Counter(event["type"] for row in plan["sessions"] for event in row.get("events", []))
    premise = EARLY_STOP_MODEL["premise"]
    assert set(counts) == set(json.loads(V5.read_text())["events"]["types"])
    assert set(counts.values()) == {premise["occurrences_per_type"]} and len(counts) == premise["types"]
    assert (premise["rates_per_occurrence"], premise["level"], EARLY_STOP_LEVEL) == ([0.01, 3], 0.99, 0.99)
    found = [exact_model(rate, premise["occurrences_per_type"], premise["types"]) for rate in MODEL_RATES]
    per_type, per_campaign, per_session = zip(*found)
    assert [round(x, 3) for x in per_campaign] == [0.121, 0.142, 0.187, 0.21, 0.254, 0.283]
    assert [round(x, 3) for x in per_session] == [0.885, 0.23, 0.637, 0.541, 0.547, 0.561]
    span = lambda values: [round(min(values), 2), round(max(values), 2)]
    assert EARLY_STOP_MODEL["false_stops_per_type"] == span(per_type) == [0.02, 0.05]
    assert EARLY_STOP_MODEL["false_stops_per_campaign"] == span(per_campaign) == [0.12, 0.28]
    assert EARLY_STOP_MODEL["per_session_reading"] == span(per_session) == [0.23, 0.88]
    assert EARLY_STOP_MODEL["per_comparison_max"] == round(1 - EARLY_STOP_LEVEL, 2) == 0.01
    for low, high in (EARLY_STOP_MODEL["false_stops_per_campaign"], EARLY_STOP_MODEL["per_session_reading"]):
        assert f"{low} to {high}" in EARLY_STOP_RULE
    assert "not a measurement" in EARLY_STOP_MODEL["kind"] and EARLY_STOP_MODEL["source"].strip()
    assert "judgment" in premise["rates_note"]


# ------------------------------------------------------------------ the count of one session


def test_a_marked_row_inside_the_stop_call_counts_under_its_event():
    """F8 of the verification of B9b (the verifier's probe p5_marked.py): the window of an occurrence is the event
    window of the log audit, host_start_unix - 1 s to host_stopped_unix + the session's event_grace_s, so marked rows
    while the stop call restores the lab (between host_stop_unix and host_stopped_unix) and in the grace after it count
    under the event; the window's ends are included."""
    from features.acceptance import marked_rows_by_type
    from scripts.collection_logs import event_window
    record = {"type": "zla_konfiguracia_sluzby", "host_start_unix": 1000.0, "host_started_unix": 1002.0,
              "host_stop_unix": 1200.0, "host_stopped_unix": 1215.0}
    assert event_window(record, 60) == (999.0, 1275.0)
    windows = [("zla_konfiguracia_sluzby", *event_window(record, 60))]
    times = {1: 998.0, 2: 999.0, 3: 1100.0, 4: 1205.0, 5: 1210.0, 6: 1275.0, 7: 1276.0}
    types = ["restart_databazy", "zla_konfiguracia_sluzby"]
    assert marked_rows_by_type([1, 2, 3, 4, 5, 6, 7], times, windows, types) == (
        {"restart_databazy": 0, "zla_konfiguracia_sluzby": 5}, {"restart_databazy": 0, "zla_konfiguracia_sluzby": 1}, 2)


def test_an_occurrence_the_log_audit_does_not_window_holds_no_row_and_is_no_occurrence():
    """An occurrence without its host start or its host stop done has no event window (event_window None, as the log
    audit names it and windows nothing): its rows count outside, and it is no occurrence; a type the protocol does not
    name keeps its own name; a session without events counts every marked row outside; a marked row without a time is
    refused by name."""
    from features.acceptance import marked_rows_by_type
    from scripts.collection_logs import event_window
    assert event_window({"type": "naprazdno", "host_start_unix": 10.0}, 60) is None
    assert event_window({"type": "naprazdno", "host_stopped_unix": 20.0}, 60) is None
    with pytest.raises(ValueError):
        event_window({"type": "naprazdno", "host_start_unix": 10.0, "host_stopped_unix": "20"}, 60)
    times = {seq: 1000.0 + 5 * seq for seq in range(20)}
    windows = [("restart_databazy", 1009.0, 1031.0), ("mimo_protokolu", 1079.0, 1086.0)]
    types = ["naprazdno", "restart_databazy"]
    assert marked_rows_by_type([1, 2, 6, 7, 16], times, windows, types) == (
        {"mimo_protokolu": 1, "naprazdno": 0, "restart_databazy": 2},
        {"mimo_protokolu": 1, "naprazdno": 0, "restart_databazy": 1}, 2)
    assert marked_rows_by_type([1, 2], times, [], types) == (dict.fromkeys(types, 0), dict.fromkeys(types, 0), 2)
    with pytest.raises(ValueError) as error:
        marked_rows_by_type([25], times, windows, types)
    assert str(error.value) == "marked row 25 has no snapshot time"


def test_the_log_audit_windows_its_events_by_the_same_function(tmp_path):
    """F8: one function for both (scripts/collection_logs.py event_window), so the log audit's event windows of a
    session are exactly the windows its count of marked rows takes."""
    from scripts import collection_logs as logs
    from scripts.collection_logs import event_window
    from scripts.tests.test_collection_logs import build
    session = build(tmp_path, event=True)
    events = json.loads((session / "events.json").read_text())["events"]
    grace = json.loads((session / "session.json").read_text())["event_grace_s"]
    assert logs.audit_logs(session)["sections"]["events"]["windows"] == [event_window(r, grace) for r in events]
