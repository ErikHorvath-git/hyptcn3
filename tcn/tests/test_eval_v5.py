"""The metrics of protocol v5 in tcn/eval.py (package B7c, agent M; design dokazy/B7/navrh/NAVRH_B7c.md 1.2, 1.3 and
section 3, the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 7 and addendum 2 points 2 and 4).

Design section 3: each metric on data whose answer is known (the Garwood interval against its table values, the
one-sided bounds against proposal 9.2, the dispersion test, the one-sided exact test), the edges per channel and for
the union on hand-made rows, channel_reacted with and without a scored row, the reverberation from the protocol, and
the roles calibration and test_controls accepted. With them: the seal of a sealed role (only the final command or a
rehearsal, marked), O2, O3, O4 and the classifier on a small corpus of schema 3, the unscored stretch reported as
nevyhodnotené, a baseline without classes evaluable in far, the clean traffic of the replay rows equal to
tcn/metody.py's, and the summary of one training (question Q11).

The rows, the indexes and the replays are hand-made in the shape safeguard.runtime, features/dataset.py and
safeguard/cli.py write them: mechanics only, no number is a measurement (HONESTY P4). The names of package B7c are
imported inside the tests, so this file collects on the code before it.
"""
import copy
import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
T0, STEP = 10000.0, 5.0
CHANNELS = ("rule", "neural", "kernel_integrity")
SOURCE = {"rule": "rule_anomaly", "neural": "model_anomaly", "kernel_integrity": "kernel_integrity"}
ORDER = ("model_anomaly", "rule_anomaly", "kernel_integrity")  # safeguard.runtime SOURCES
CLASSES = ["corp_high", "corp_low", "eshop_high", "eshop_low"]


def protocol(window_rows=4, **analysis):
    """config/collection-v5.json with a short window (the replays below are short); analysis: keys replaced."""
    doc = json.loads(V5.read_text())
    doc["window_rows"] = window_rows
    doc["analysis"].update(copy.deepcopy(analysis))
    return doc


def rows(n, *, up=lambda i: (), scored=lambda i: True, required=4, activity=lambda i: "eshop_low", t0=T0):
    """n replay rows of safeguard.runtime at t0 + STEP * i: up(i) the channels up at row i; a source rises where its
    channel comes up (Detector._finish), alarm is the union, channel the channels up in their order."""
    out, before = [], set()
    for i in range(n):
        now = set(up(i))
        sources = [s for s in ORDER if any(SOURCE[c] == s and c not in before for c in now)]
        score = 0.1 if scored(i) else None
        r = {"schema": "hyptcn3/safeguard-events/1", "session": "s", "seq": i, "timestamp": t0 + STEP * i,
             "score": score, "model_state": "monitoring" if score is not None else "warming_up",
             "alarm": bool(now), "alarm_event": bool(sources), "alarm_sources": sources,
             "channel": [c for c in CHANNELS if c in now], "model_alarm": "neural" in now,
             "rule_alarm": "rule" in now, "integrity_alarm": "kernel_integrity" in now,
             "rule": {"state": "judged"}, "integrity": {"conclusive": True, "inconclusive": [], "findings": []},
             "required_rows": required}
        if score is not None:
            r["activity"] = activity(i)
        out.append(r)
        before = now
    return out


def event(start, stop, kind="zamok_tabulky", executed=True):
    return {"type": kind, "class": "chyba_aplikacie", "executed": executed, "host_start_unix": start,
            "host_started_unix": start + 1, "host_stop_unix": stop - 1, "host_stopped_unix": stop}


def control(start, stop, kind="kontrola_modul_jadra", polarity="control"):
    return {"kind": kind, "polarity": polarity, "class": {"control": "control", "negative": "control_negative"}[
        polarity], "kind_class": "A", "executed": True, "host_start_unix": start, "host_started_unix": start + 1,
        "host_stop_unix": stop - 1, "host_stopped_unix": stop}


def outcome(start, horizon, scored, kind="kontrola_modul_jadra", polarity="control", klass="A"):
    """An outcome of scripts/controls.py outcomes() (schema hyptcn3/control-outcomes/1) with its window."""
    return {"schema": "hyptcn3/control-outcomes/1", "kind": kind, "class": klass, "polarity": polarity,
            "dose": None, "window": {"start_unix": start, "started_unix": start + 1, "stop_unix": start + 60,
                                     "horizon_end_unix": start + 180, "before": [], "inside": [],
                                     "horizon": list(horizon), "scored": list(scored)},
            "parser_saw": {}, "column_moved": {}, "sensor_scored": bool(scored)}


def session(ident, role="test_benign", *, group="g5-test_benign-1", vm="a", scenario="eshop_low", n=720, up=None,
            scored=None, events=(), controls=(), activity=None):
    return {"id": ident, "role": role, "group": group, "vm": vm, "scenario": scenario,
            "rows": rows(n, up=up or (lambda i: ()), scored=scored or (lambda i: True),
                         activity=activity or (lambda i: scenario)), "events": list(events),
            "controls": list(controls)}


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def corpus(tmp_path, sessions, *, mode="rehearsal", doc=None, classes=CLASSES, hash_controls=True):
    """A complete corpus index of schema 3 (features/dataset.py) over the sessions, with fake archives and the
    replays of one bundle (safeguard replay --archive, with the archive_sha256 the seal checks them by): (corpus path,
    replay directories)."""
    doc = protocol() if doc is None else doc
    records = []
    for s in sessions:
        d = tmp_path / s["id"]
        d.mkdir()
        (d / "features.npz").write_bytes(("archive " + s["id"]).encode())
        (d / "events.json").write_text(json.dumps({"schema": "hyptcn3/session-events/1", "events": s["events"]}))
        (d / "audit.json").write_text(json.dumps({"values": {"extractor_sha256": {"features/a.py": "e"}}}))
        record = {"id": s["id"], "role": s["role"], "group": s["group"], "vm": s["vm"], "scenario": s["scenario"],
                  "start": s["rows"][0]["timestamp"], "end": s["rows"][-1]["timestamp"],
                  "session": str(d / "session.json"), "features": str(d / "features.npz"),
                  "features_sha256": _sha(d / "features.npz"), "events": str(d / "events.json"),
                  "events_sha256": _sha(d / "events.json"), "audit": str(d / "audit.json"),
                  "audit_sha256": _sha(d / "audit.json"), "collector_sha256": "c",
                  "guest": {"kernel": "6.1.0-42-cloud-amd64", "stack_sha256": "x"}}
        if s["role"] == "test_controls":
            (d / "controls.json").write_text(json.dumps({"schema": "hyptcn3/session-controls/1",
                                                         "controls": s["controls"] + [{"kind": None}]}))
            if hash_controls:
                record.update(controls=str(d / "controls.json"), controls_sha256=_sha(d / "controls.json"))
        records.append(record)
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"schema": "hyptcn3/corpus-index/1", "complete": True, "plan_mode": mode,
                                "protocol_sha256": "p", "protocol_config": doc, "sessions": records}))
    manifest = {"diagnostic": False, "classes": classes, "weights": {"predictor": "w"},
                "calibration": {"threshold": 1.0, "k": 3, "n": 5}, "created_utc": "2026-11-23T00:00:00+00:00",
                "feature_contract": {"max_gap_s": doc["max_gap_s"], "window_rows": doc["window_rows"]},
                "training": {"seed": 0, "epochs": 1, "batch_size": 32},
                "environment": {"kernel": "6.1.0-42-cloud-amd64", "stack_sha256": "x", "collector_sha256": "c",
                                "extractor_sha256": {"features/a.py": "e"}},
                "provenance": {"corpus_index_sha256": _sha(path), "source_sha256": {}}}
    replays = []
    for s, record in zip(sessions, records):
        out = tmp_path / ("replay_" + s["id"])
        out.mkdir()
        # archive_sha256 as safeguard replay --archive writes it: the seal checks every replay by it (design B7c 5.5).
        (out / "configuration.json").write_text(json.dumps({"schema": "hyptcn3/safeguard-configuration/1",
                                                            "bundle_manifest": manifest,
                                                            "archive": record["features"],
                                                            "archive_sha256": record["features_sha256"]}))
        (out / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in s["rows"]))
        (out / "status.json").write_text(json.dumps({
            "schema": "hyptcn3/safeguard-run/1", "processed": len(s["rows"]),
            "scored": sum(r["score"] is not None for r in s["rows"]), "input_errors": 0,
            "alarm_events": sum(r["alarm_event"] for r in s["rows"]), "fatal": False,
            "stop_reason": "replay_complete"}))
        replays.append(out)
    return path, replays


def normalizer(inputs):
    """A normalizer of safeguard/features.py whose TCN inputs are `inputs`, mean 0 and scale 1, one bin (as
    tcn/tests/test_metody.py builds it)."""
    from features.qualification import LOCAL_SCALED
    from safeguard.features import GLOBAL_NAMES, FeatureNormalizer, NormalizationRule
    classes = {name: "neural" if name in inputs else "rule" for name in GLOBAL_NAMES}
    rule = NormalizationRule("analysis.columns", classes, dict.fromkeys(GLOBAL_NAMES, 1.0), True, 1,
                             dict.fromkeys(LOCAL_SCALED, 1e-6))
    width = len(rule.tcn_names)
    return FeatureNormalizer(rule, np.zeros(width), np.ones(width), [(0, 4096)], [], np.zeros((1, 4)),
                             np.ones((1, 4)), 1, 0)


def state(s, doc=None):
    """The input of metriky_v5 for one hand-made session."""
    return {"zaznam": {k: s[k] for k in ("id", "role", "group", "vm", "scenario")}, "riadky": s["rows"],
            "udalosti": s["events"], "kontroly": s["controls"]}


# ------------------------------------------------------------------ each metric on data with a known answer


@pytest.mark.parametrize("k, lower, upper", [(0, 0.0, 3.6889), (1, 0.0253, 5.5716), (2, 0.2422, 7.2247),
                                             (5, 1.6235, 11.6683), (10, 4.7954, 18.3904)])
def test_the_garwood_interval_has_its_table_values(k, lower, upper):
    """The exact two-sided interval of a Poisson mean at 0.95 (Garwood 1936; the table values at 4 decimals)."""
    from tcn.eval import garwood
    assert garwood(k, .95) == (pytest.approx(lower, abs=1e-4), pytest.approx(upper, abs=1e-4))


@pytest.mark.parametrize("hours, bounds", [(16.8, (.18, .28, .37)), (25.2, (.12, .19, .25)), (33.6, (.09, .14, .19))])
def test_the_one_sided_poisson_bound_of_o2_gives_the_table_of_proposal_9_2(hours, bounds):
    """Proposal 9.2: the one-sided 95 % upper bound of the false alarms per observed clean hour at 0, 1 and 2."""
    from tcn.eval import poissonov_horna
    assert tuple(round(poissonov_horna(k, .95) / hours, 2) for k in range(3)) == bounds


@pytest.mark.parametrize("k, n, upper", [(0, 12, .22), (12, 12, 1.0), (1, 12, .339)])
def test_the_one_sided_clopper_pearson_bound_of_o3(k, n, upper):
    """Proposal 9.2: 12 evaluable occurrences of a type without an alarm give 0.22; every one with an alarm 1."""
    from tcn.eval import clopper_pearson_horna
    assert round(clopper_pearson_horna(k, n, .95), 3 if k == 1 else 2) == upper


def _exposures(counts, rows=(720, 720)):
    return [{"rows": n, "alarms": {o: c for o in ("rule", "neural", "kernel_integrity", "union")}}
            for c, n in zip(counts, rows)]


@pytest.mark.parametrize("counts, rows, x2, p", [([0, 10], (720, 720), 10.0, 0.0015654),
                                                 ([5, 5], (720, 720), 0.0, 1.0),
                                                 ([2, 2], (720, 1440), 0.5, 0.4795001),
                                                 ([0, 0], (720, 720), None, None)])
def test_the_dispersion_test_of_the_alarm_counts_between_sessions(counts, rows, x2, p):
    """Pearson's X2 against the expectation by observed time: 0 and 10 alarms in two equal sessions give 10 on one
    degree of freedom; equal counts give 0; 2 and 2 alarms in one and two hours expect 4/3 and 8/3 and give 1/2;
    without an alarm it is not computed, with the reason."""
    from tcn.eval import _disperzia
    out = _disperzia(_exposures(counts, rows))["union"]
    if x2 is None:
        assert out == {"x2": None, "df": None, "p": None, "sessions": 2, "why": "no alarm"}
    else:
        assert (out["x2"], out["df"], out["p"]) == (pytest.approx(x2), 1, pytest.approx(p, abs=1e-6))


@pytest.mark.parametrize("k1, e1, k0, e0, p, higher, why", [
    (3, 3600., 0, 3600., .125, False, None), (5, 3600., 0, 3600., .03125, True, None),
    (0, 3600., 0, 3600., 1.0, False, "no alarm"), (2, 0., 1, 3600., None, None, "no exposure of the events or of "
                                                                                 "clean traffic")])
def test_the_one_sided_exact_test_of_the_events_against_clean_traffic(k1, e1, k0, e0, p, higher, why):
    """P(X >= k1) for X binomial(k1 + k0, e1 / (e1 + e0)): 3 of 3 alarms in half of the time give 1/8 (not below 0.05),
    5 of 5 give 1/32 (below); without an alarm p is 1, without exposure none."""
    from tcn.eval import porovnanie_v5
    out = porovnanie_v5(k1, e1, k0, e0, .05)
    assert (out["p"], out["higher"], out["why"]) == (p if p is None else pytest.approx(p), higher, why)


# ------------------------------------------------------------------ the edges per channel and for the union


def test_the_edges_of_each_channel_and_of_the_union_on_hand_made_rows():
    """The rule channel up at rows 3 to 6, the neural at 5 to 8 and the integrity at row 10: each channel rises once,
    the union twice (the overlap of rule and neural is one alarm of the union)."""
    from tcn.eval import channel_edges
    up = {**{i: {"rule"} for i in (3, 4)}, 5: {"rule", "neural"}, 6: {"rule", "neural"}, 7: {"neural"},
          8: {"neural"}, 10: {"kernel_integrity"}}
    edges = channel_edges(rows(12, up=lambda i: up.get(i, ())))
    assert edges == {"rule": [3], "neural": [5], "kernel_integrity": [10], "union": [3, 10]}
    again = channel_edges(rows(4, up=lambda i: {"neural"} if i in (0, 2) else ()))
    assert again["union"] == again["neural"] == [0, 2]  # Up at the first row: an edge (the detector starts down).


@pytest.mark.parametrize("change, reason", [
    (lambda r: r.update(channel=[]), "alarm, alarm_event, alarm_sources and channel disagree"),
    (lambda r: r.update(alarm_sources=["kernel_integrity"]), "alarm, alarm_event, alarm_sources and channel "
                                                             "disagree"),
    (lambda r: r.update(channel=["neural", "rule"]), "channel lists channels of rule, neural, kernel_integrity in "
                                                     "that order"),
    (lambda r: r.pop("alarm"), "alarm and alarm_event are true or false"),
], ids=["alarm_without_channel", "source_of_a_channel_down", "channels_out_of_order", "no_alarm"])
def test_a_row_whose_fields_disagree_is_refused_by_name(change, reason):
    from tcn.eval import channel_edges
    r = rows(3, up=lambda i: {"neural", "rule"} if i == 1 else ())
    change(r[1])
    with pytest.raises(ValueError, match=reason):
        channel_edges(r)


# ------------------------------------------------------------------ the contexts and the reverberation


@pytest.mark.parametrize("reverberation, context", [(300, "clean"), (600, "reverberation")])
def test_the_reverberation_comes_from_the_protocol(reverberation, context):
    """A row 400 s after the stop of an event (its span 3 rows back stays after the stop) is clean under
    analysis.reverberation_s 300 and in the reverberation under 600; the stop itself is the event."""
    from tcn.eval import dozvuk_s, row_contexts
    doc = protocol(reverberation_s=reverberation)
    stop = T0 + 100 * STEP
    r = rows(200)
    contexts = row_contexts(r, [event(T0 + 50 * STEP, stop)], [], doc)
    assert contexts[100] == ("event", "zamok_tabulky")
    assert contexts[100 + 80 + 3] == (context, None)  # 415 s after the stop, its span from 400 s.
    assert dozvuk_s(doc) == reverberation and dozvuk_s({"interval_s": 5}) == 300.0  # Schemas 1, 2: v3 and v4.


def test_the_contexts_of_a_control_and_of_an_event_that_did_not_run():
    """A control and its reverberation are no clean traffic (tcn/metody.py CLEAN_RULE); a row that meets an event
    that did not run is excluded."""
    from tcn.eval import row_contexts
    r = rows(400)
    contexts = row_contexts(r, [event(T0 + 300 * STEP, T0 + 320 * STEP, executed=False)],
                            [control(T0 + 50 * STEP, T0 + 70 * STEP)], protocol())
    assert (contexts[10], contexts[60], contexts[100], contexts[200], contexts[310]) == (
        ("clean", None), ("control", None), ("control", None), ("clean", None), (None, None))


def test_the_clean_rows_of_a_replay_are_those_of_tcn_metody_traffic():
    """Question Q12 (accepted by the lead 2026-11-24): the clean rows of eval's CONTEXT_RULE are tcn/metody.py
    OBSERVED_RULE's clean rows on the same session with two events and a control (a window set of the wrapper and
    the replay of the same frames)."""
    from tcn.eval import row_contexts
    from tcn.metody import Okna, traffic
    norm = normalizer(("mem_changed_ratio", "proc_user"))
    count, width = 300, 4
    sessions = [{"id": "s", "global": np.zeros((count, 2)), "local": np.zeros((count, 1, 4)),
                 "seq": np.arange(count), "timestamp": T0 + STEP * np.arange(count), "full_times": [], "load": None}]
    windows = Okna(sessions, [(0, end, None) for end in range(width - 1, count)], role="test_benign",
                   normalizer=norm, window_rows=width, max_gap_s=7.5, interval_s=STEP)
    events = [event(T0 + 40 * STEP, T0 + 60 * STEP), event(T0 + 200 * STEP, T0 + 210 * STEP, "udrzba_zaloha")]
    controls = [control(T0 + 120 * STEP, T0 + 130 * STEP)]
    doc = protocol(window_rows=width, reverberation_s=300)
    expected = traffic(windows, {"s": events}, doc, controls={"s": controls}).row_clean[0]
    found = [c[0] == "clean" for c in row_contexts(rows(count, required=width), events, controls, doc)]
    assert found == expected.tolist() and 0 < sum(found) < count


# ------------------------------------------------------------------ channel_reacted (O4)


def test_channel_reacted_with_a_scored_row_detects_by_channel():
    """The neural channel rises at a row of the horizon: zachytené for it and the union, nezachytené for the others;
    an alarm up before the start is no reaction (the rule channel here) and is recorded."""
    from tcn.eval import channel_reacted
    start = T0 + 50 * STEP
    r = rows(120, up=lambda i: ({"rule"} if 40 <= i <= 70 else set()) | ({"neural"} if 60 <= i <= 65 else set()))
    horizon = [i for i in range(120) if start < T0 + STEP * i <= start + 180]
    out = channel_reacted(outcome(start, horizon, horizon), r, protocol())
    assert {o: v["result"] for o, v in out["outputs"].items()} == {
        "rule": "nezachytené", "neural": "zachytené", "kernel_integrity": "nezachytené", "union": "nezachytené"}
    assert out["outputs"]["rule"]["up_at_start"] is True and out["outputs"]["neural"]["first_edge_s"] == 50.0
    assert out["sensor_scored"] is True and out["evaluable"] is True


def test_channel_reacted_without_a_scored_row_is_its_own_result():
    """No scored row in the horizon: every channel and the union are nezachytené, senzor neskóroval (proposal 6.4),
    even where a channel rose, and the occurrence is not evaluable."""
    from tcn.eval import channel_reacted
    start = T0 + 50 * STEP
    horizon = [i for i in range(120) if start < T0 + STEP * i <= start + 180]
    r = rows(120, up=lambda i: {"kernel_integrity"} if i == 60 else (), scored=lambda i: i not in horizon)
    out = channel_reacted(outcome(start, horizon, []), r, protocol())
    assert {v["result"] for v in out["outputs"].values()} == {"nezachytené, senzor neskóroval"}
    assert out["outputs"]["kernel_integrity"]["edges"] == 1
    assert (out["sensor_scored"], out["evaluable"], out["status"]) == (False, False, "nevyhodnotené")


def test_a_channel_that_judged_no_row_of_the_horizon_is_nevyhodnotene_not_a_miss():
    """A rule channel without columns (rule.state no_columns, a baseline of tcn/porovnanie.py or a bundle without a
    column of class rule) judged no row of the horizon: its result is nevyhodnotené, never nezachytené."""
    from tcn.eval import channel_reacted
    start = T0 + 50 * STEP
    r = rows(120)
    for row in r:
        row["rule"] = {"state": "no_columns"}
    horizon = [i for i in range(120) if start < T0 + STEP * i <= start + 180]
    out = channel_reacted(outcome(start, horizon, horizon), r, protocol())
    assert (out["outputs"]["rule"]["result"], out["outputs"]["neural"]["result"]) == ("nevyhodnotené", "nezachytené")


def test_channel_reacted_refuses_a_replay_that_scores_beyond_the_outcomes_coverage():
    """A row the replay scored but the outcome's coverage does not: the two describe different data."""
    from tcn.eval import channel_reacted
    start = T0 + 50 * STEP
    horizon = [i for i in range(120) if start < T0 + STEP * i <= start + 180]
    with pytest.raises(ValueError, match="which the outcome's coverage does not score"):
        channel_reacted(outcome(start, horizon, horizon[1:]), rows(120), protocol())


# ------------------------------------------------------------------ the roles and the seal


@pytest.mark.parametrize("role", ["calibration", "test_controls"])
def test_the_roles_calibration_and_test_controls_are_accepted(role, tmp_path):
    """Under schema 3 far takes calibration and test_controls (design B7c 1.3); test_controls inside the final command
    (final_evaluation=True), whose outcomes of the controls give O4. Schemas 1 and 2 keep their two roles."""
    from tcn.eval import vyhodnot_far
    start = T0 + 100 * STEP
    controls = [control(start, start + 60)] if role == "test_controls" else []
    s = session("s1", role, group=f"g-{role}-1", controls=controls,
                up=lambda i: {"neural"} if i == 130 and role == "test_controls" else ())
    path, replays = corpus(tmp_path, [s], mode="campaign")
    horizon = [i for i in range(720) if start < T0 + STEP * i <= start + 180]
    given = {"s1": [outcome(start, horizon, horizon)]} if role == "test_controls" else None
    values, _ = vyhodnot_far(path, role, replays, final_evaluation=role == "test_controls", vysledky_kontrol=given)
    v5 = values["v5"]
    assert (values["rola"], v5["role"], values["plan_mode"], values["rehearsal"]) == (role, role, "campaign", False)
    if role == "test_controls":
        assert v5["o4"]["control"]["total"]["neural"]["zachytené"] == 1
        assert v5["o4"]["control"]["total"]["status"] == "nevyhodnotené"  # 1 of analysis.min_occurrences 8.
        # Not clean: the rows whose span of 4 rows meets [start, stop + reverberation_s 300].
        assert v5["o2"]["total"]["rows"] == 720 - sum(T0 + STEP * i >= start and T0 + STEP * (i - 3) <= start + 360
                                                      for i in range(720)) == 720 - 76
    else:
        assert v5["o4"] is None and v5["o2"]["total"]["rows"] == 720
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    path, replays = corpus(legacy, [s], doc={"interval_s": 5.0, "max_gap_s": 7.5, "window_rows": 4})
    with pytest.raises(ValueError, match="FAR sa pocita iba pre role dev, test_benign"):
        vyhodnot_far(path, role, replays)


@pytest.mark.parametrize("mode, final_evaluation, final, reason", [
    ("campaign", False, False, "sealed role test_benign"),
    ("campaign", True, True, "--final and its mark next to the index serve protocol schemas 1 and 2"),
    ("campaign", True, False, None), ("rehearsal", False, False, None)])
def test_a_sealed_role_is_evaluated_by_the_final_command_or_in_a_rehearsal(mode, final_evaluation, final, reason,
                                                                           tmp_path):
    """Design B7c 1.1: test_benign of a campaign index only with final_evaluation=True (the final command); --final
    and its mark serve schemas 1 and 2; an index of plan mode rehearsal is evaluated freely and marked."""
    from tcn.eval import REHEARSAL_MARK, vyhodnot_far
    path, replays = corpus(tmp_path, [session("s1")], mode=mode)
    if reason is not None:
        with pytest.raises(ValueError, match=reason):
            vyhodnot_far(path, "test_benign", replays, final=final, final_evaluation=final_evaluation)
        return
    values, _ = vyhodnot_far(path, "test_benign", replays, final_evaluation=final_evaluation)
    assert (values["rehearsal"], values["rehearsal_mark"], values["final_evaluation"]) == (
        mode == "rehearsal", REHEARSAL_MARK if mode == "rehearsal" else None, final_evaluation)


def test_the_commands_under_schema_3_write_their_record_and_refuse_final(tmp_path):
    """python -m tcn.eval far on a rehearsal index writes its record with the block v5 and the rehearsal mark and no
    mark next to the index; --final is refused under schema 3 by far and by udalosti (design B7c 1.1)."""
    from tcn.eval import _hlavny
    path, replays = corpus(tmp_path, [session("s1")])
    argv = ["far", "--corpus", str(path), "--role", "test_benign", "--replay", *map(str, replays)]
    assert _hlavny(argv + ["--out", str(tmp_path / "far.json")]) == 0
    values = json.loads((tmp_path / "far.json").read_text())["values"]
    assert values["rehearsal"] is True and values["v5"]["schema"] == "hyptcn3/v5-metrics/1"
    assert not list(tmp_path.glob("corpus.json.*"))
    with pytest.raises(ValueError, match="--final and its mark next to the index serve protocol schemas 1 and 2"):
        _hlavny(argv + ["--final", "--out", str(tmp_path / "b.json")])
    with pytest.raises(SystemExit, match="--final and its mark next to the index serve protocol schemas 1 and 2"):
        _hlavny(["udalosti", "--index", str(path), "--role", "test_benign", "--final", "--replay",
                 *map(str, replays), "--out", str(tmp_path / "c.json")])
    assert not (tmp_path / "b.json").exists() and not (tmp_path / "c.json").exists()


def test_a_session_of_test_controls_needs_its_controls_hashed_by_the_index(tmp_path):
    from tcn.eval import vyhodnot_far
    path, replays = corpus(tmp_path, [session("s1", "test_controls", group="g5-test_controls-1")],
                           hash_controls=False)
    with pytest.raises(ValueError, match="the index does not hash its controls.json"):
        vyhodnot_far(path, "test_controls", replays)


# ------------------------------------------------------------------ O2, the thesis' metrics, O3 and the classifier


def test_o2_counts_per_channel_and_union_in_clean_traffic_with_the_one_sided_bound():
    """One session of 720 clean rows (one observed hour): the neural channel rises twice, the rule channel once with
    it; O2 gives 2 alarms per hour for the neural channel and the union (an overlap is one alarm) and the one-sided
    bound chi2.ppf(0.95, 6) / 2 per hour; the boots, the VMs and the profiles have their tables."""
    from scipy.stats import chi2
    from tcn.eval import metriky_v5
    s = session("s1", up=lambda i: ({"neural"} if i in (100, 101, 400) else set())
                | ({"rule"} if i == 101 else set()))
    out = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")["o2"]
    total = out["total"]
    assert (total["observed_hours"], total["union"]["alarms"], total["neural"]["alarms"], total["rule"]["alarms"],
            total["kernel_integrity"]["alarms"]) == (1.0, 2, 2, 1, 0)
    assert total["union"]["bounds_per_hour"] == [0.0, pytest.approx(chi2.ppf(.95, 6) / 2)]
    assert set(out["by_boot"]) == {"g5-test_benign-1"} and set(out["by_vm"]) == {"a"}
    assert set(out["by_profile"]) == {"eshop"} and out["by_scenario"]["eshop_low"]["union"]["alarms"] == 2


def test_a_channel_that_judged_no_row_is_nevyhodnotene_not_zero():
    """A baseline of tcn/porovnanie.py has no rule column (rule.state no_columns): its rule channel judged no row, so
    its rate is nevyhodnotené, never 0 alarms per hour."""
    from tcn.eval import metriky_v5
    s = session("s1")
    for r in s["rows"]:
        r["rule"] = {"state": "no_columns"}
    out = metriky_v5(protocol(), [state(s)], triedy=[], rola="test_benign")
    assert (out["o2"]["total"]["rule"]["status"], out["o2"]["total"]["rule"]["per_hour"]) == ("nevyhodnotené", None)
    assert out["o2"]["total"]["neural"]["per_hour"] == 0.0 and "skipped" in out["classifier"]


def test_the_thesis_rate_the_boots_the_dispersion_and_the_events_against_clean_traffic():
    """Two sessions of two boots: one with an event and an alarm in it, one with an alarm in clean traffic. The rate of
    the thesis counts both over every evaluated row with the Garwood interval; two boot groups; the dispersion over
    the two sessions; the test of the events against clean traffic in total and for the event's type."""
    from tcn.eval import garwood, metriky_v5
    a = session("a", group="g5-test_benign-1", events=[event(T0 + 300 * STEP, T0 + 330 * STEP)],
                up=lambda i: {"neural"} if i == 310 else ())
    b = session("b", group="g5-test_benign-2", vm="b", scenario="corp_high", up=lambda i: {"neural"} if i == 50 else ())
    out = metriky_v5(protocol(), [state(a), state(b)], triedy=CLASSES, rola="test_benign")["thesis"]
    assert out["rate"]["total"]["neural"]["alarms"] == 2 and out["rate"]["total"]["observed_hours"] == 2.0
    assert out["rate"]["total"]["neural"]["bounds_per_hour"] == [pytest.approx(x / 2) for x in garwood(2, .95)]
    assert out["boot_groups"] == 2 and out["dispersion"]["neural"]["df"] == 1
    # Every output keeps its entry beside the definition (the channel of the rule is named rule).
    assert set(out["dispersion"]) == {"rule", "neural", "kernel_integrity", "union", "definition"}
    assert out["dispersion"]["rule"]["why"] == "no alarm"
    test = out["event_vs_clean"]
    neural = test["total"]["neural"]
    # 34 event rows (span of 4 rows) against 1440 - 34 - 60 (reverberation) clean rows: 1 alarm in each.
    assert (neural["event_alarms"], neural["event_seconds"], neural["clean_alarms"], neural["clean_seconds"]) == (
        1, 34 * STEP, 1, 1346 * STEP)
    assert neural["p"] == pytest.approx(1 - (1346 / 1380) ** 2) and neural["higher"] is True
    assert set(test["by_type"]) == {"zamok_tabulky"} and test["by_type"]["zamok_tabulky"]["neural"] == neural


def test_o3_takes_the_evaluable_occurrences_of_each_type_and_marks_a_small_type():
    """An occurrence whose first 60 s are unscored is nevyhodnotené and leaves the denominator; one with an edge in the
    horizon reacts; a type with fewer than analysis.min_occurrences (8) evaluable occurrences is nevyhodnotené."""
    from tcn.eval import metriky_v5
    first, second = T0 + 200 * STEP, T0 + 400 * STEP
    s = session("s1", events=[event(first, first + 100), event(second, second + 100)],
                up=lambda i: {"neural"} if i == 210 else (),
                scored=lambda i: not 400 < i <= 410)  # 10 of the 12 rows of the first 60 s of the second unscored.
    out = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")["o3"]
    t = out["by_type"]["zamok_tabulky"]
    assert (t["occurrences"], t["evaluable"], t["not_evaluable"], t["status"]) == (2, 1, 1, "nevyhodnotené")
    assert t["neural"] == {"reacted": 1, "share": None, "upper": None, "status": "nevyhodnotené", "during_event": 1,
                           "in_reverberation": 0}
    assert [v["start_unix"] for v in out["not_evaluable"]] == [second]
    many = metriky_v5(protocol(min_occurrences=1), [state(s)], triedy=CLASSES, rola="test_benign")["o3"]
    assert many["by_type"]["zamok_tabulky"]["neural"] == {"reacted": 1, "share": 1.0, "upper": 1.0,
                                                          "status": "evaluated", "during_event": 1,
                                                          "in_reverberation": 0}


def test_an_edge_at_the_start_of_an_occurrence_is_no_reaction():
    """The horizon is host_start_unix < t <= host_start_unix + horizon_s (a row at t covers (t - interval_s, t], as
    scripts/controls.py): an alarm that rises at the row of the start time began before the event."""
    from tcn.eval import metriky_v5
    start = T0 + 200 * STEP
    s = session("s1", events=[event(start, start + 100)], up=lambda i: {"neural"} if 200 <= i <= 210 else ())
    occurrence, = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")["o3"]["occurrences"]
    assert (occurrence["outputs"]["neural"]["reacted"], occurrence["outputs"]["neural"]["up_at_start"]) == (False,
                                                                                                           True)


@pytest.mark.parametrize("unscored, evaluable", [(6, True), (7, False)])
def test_an_occurrence_is_evaluable_at_half_of_its_first_60_s_scored(unscored, evaluable):
    """Proposal 6.4 (analysis.evaluable: first_s 60, scored_share 0.5): of the 12 rows of the first 60 s after the
    start, 6 unscored leave exactly half scored (evaluable), 7 too few."""
    from tcn.eval import metriky_v5
    start = T0 + 200 * STEP
    s = session("s1", events=[event(start, start + 100)], scored=lambda i: not 200 < i <= 200 + unscored)
    occurrence, = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")["o3"]["occurrences"]
    assert (occurrence["first_s_scored_share"], occurrence["evaluable"]) == ((12 - unscored) / 12, evaluable)


def test_o4_counts_every_planned_control():
    """The denominator of O4 is the planned occurrences: a control of the role without its outcome is refused."""
    from tcn.eval import metriky_v5
    start = T0 + 100 * STEP
    s = session("s1", "test_controls", group="g5-test_controls-1",
                controls=[control(start, start + 60), control(start + 1000, start + 1060)])
    horizon = [i for i in range(720) if start < T0 + STEP * i <= start + 180]
    with pytest.raises(ValueError, match="1 outcomes of controls given for the 2 planned controls"):
        metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_controls",
                   vysledky_kontrol={"s1": [outcome(start, horizon, horizon)]})


@pytest.mark.parametrize("row, reacted, during, after", [(250, False, True, False), (330, False, False, True)],
                         ids=["late_in_the_event", "in_the_reverberation"])
def test_o3_reports_an_alarm_beyond_the_horizon_beside_it(row, reacted, during, after):
    """An event of 400 s: an alarm 250 s after its start lies beyond analysis.horizon_s (180 s) but during the event,
    one 250 s after its stop in its reverberation (300 s); neither is a reaction within the horizon, both are
    reported beside it."""
    from tcn.eval import metriky_v5
    start = T0 + 1000
    s = session("s1", events=[event(start, start + 400)], up=lambda i: {"neural"} if i == row else ())
    out = metriky_v5(protocol(min_occurrences=1), [state(s)], triedy=CLASSES, rola="test_benign")["o3"]
    neural = out["by_type"]["zamok_tabulky"]["neural"]
    assert (neural["reacted"], neural["during_event"], neural["in_reverberation"]) == (reacted, during, after)


def test_an_unscored_stretch_is_nevyhodnotene_in_the_output():
    """G1 (proposal 10.2): an inserted unscored stretch is reported as nevyhodnotené, never as time without alarms."""
    from tcn.eval import metriky_v5
    s = session("s1", scored=lambda i: not (i < 3 or 300 <= i < 340))
    out = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")
    stretches = out["unscored"]["sessions"]["s1"]["stretches"]
    assert [(x["rows"], x["seconds"], x["status"]) for x in stretches] == [(3, 15.0, "nevyhodnotené"),
                                                                          (40, 200.0, "nevyhodnotené")]
    assert (out["o2"]["total"]["unscored_seconds"], out["o2"]["total"]["unscored_status"]) == (215.0, "nevyhodnotené")


def test_the_classifier_over_windows_per_session_and_per_occurrence():
    """Clean windows labelled with the session's scenario: accuracy, macro-F1, the most frequent class and chance;
    the majority class of each session and of each occurrence (an event: is the session's activity kept?)."""
    from tcn.eval import metriky_v5
    a = session("a", scenario="eshop_low", activity=lambda i: "eshop_low" if i < 540 else "corp_low")
    b = session("b", group="g5-test_benign-2", scenario="corp_low", activity=lambda i: "eshop_low" if 300 <= i < 340
                else "corp_low", events=[event(T0 + 300 * STEP, T0 + 330 * STEP)])
    out = metriky_v5(protocol(), [state(a), state(b)], triedy=CLASSES, rola="test_benign")["classifier"]
    assert out["sessions"]["right"] == 2 and out["occurrences"]["by_type"] == {"zamok_tabulky": {"occurrences": 1,
                                                                                                  "right": 0}}
    # a: 720 clean windows, 540 right; b: 626 clean windows (34 of the event and 60 of its reverberation left out),
    # all right; the event's 34 scored windows all say eshop_low, so its majority is not b's corp_low.
    windows = out["windows"]
    f1_eshop, f1_corp = 2 * .75 / 1.75, 2 * (626 / 806) / (1 + 626 / 806)
    assert (windows["n"], windows["accuracy"], windows["macro_f1"], windows["chance"]) == (
        1346, pytest.approx(1166 / 1346), pytest.approx((f1_eshop + f1_corp) / 2), .25)
    assert windows["most_frequent_class"] == {"class": "eshop_low", "accuracy": pytest.approx(720 / 1346)}
    assert out["occurrences"]["per_occurrence"][0]["windows"] == 34


def test_a_baseline_without_classes_is_evaluable_in_far(tmp_path):
    """Design B7c 1.3: a method without classes (tcn/porovnanie.py, classes []) skips the classifier tables."""
    from tcn.eval import BEZ_TRIED, vyhodnot_far
    path, replays = corpus(tmp_path, [session("s1")], classes=[])
    values, _ = vyhodnot_far(path, "test_benign", replays)
    assert (values["klasifikacia_aktivit"], values["klasifikacia_aktivit_dovod"]) == (None, BEZ_TRIED)
    assert values["v5"]["classifier"]["skipped"].startswith("the bundle has no classes")


@pytest.mark.parametrize("role", ["test_benign", "calibration"])
def test_udalosti_under_schema_3_reads_the_reverberation_and_gives_the_block_v5(role, tmp_path):
    """udalosti of a corpus of schema 3, also for role calibration: the reverberation of analysis.reverberation_s,
    the same block v5."""
    from tcn.eval import vyhodnot_udalosti
    s = session("s1", role, group=f"g5-{role}-1", events=[event(T0 + 200 * STEP, T0 + 230 * STEP)],
                up=lambda i: {"neural"} if i == 210 else ())
    path, replays = corpus(tmp_path, [s], doc=protocol(reverberation_s=120))
    values, _ = vyhodnot_udalosti(path, replays, rola=role)
    assert values["dozvuk_s"] == 120.0 and values["v5"]["reverberation_s"] == 120.0 and values["rehearsal"] is True
    assert values["v5"]["o3"]["total"]["neural"]["reacted"] == 1 and values["v5"]["role"] == role


# ------------------------------------------------------------------ per training (question Q11)


def test_the_summary_of_a_training_gives_the_loss_against_z3_and_z5_and_the_score_by_context():
    """On a window set of dev: the mean loss of M, Z3 and Z5 per context and I = 1 - loss(M) / loss(Z); the score of
    M by context and scenario; a sealed role is refused."""
    from tcn.eval import training_record, training_summary
    from tcn.metody import Okna
    norm = normalizer(("mem_changed_ratio", "proc_user"))
    count, width = 200, 4
    sessions = [{"id": ident, "global": np.zeros((count, 2)), "local": np.zeros((count, 1, 4)),
                 "seq": np.arange(count), "timestamp": T0 + STEP * np.arange(count), "full_times": [], "load": None}
                for ident in ("a", "b")]
    windows = Okna(sessions, [(s, end, None) for s in range(2) for end in range(width - 1, count)], role="dev",
                   normalizer=norm, window_rows=width, max_gap_s=7.5, interval_s=STEP)
    n = len(windows)

    class Fake:
        def __init__(self, loss, label=None):
            self.loss, self.label, self.threshold = loss, label, .5

        def losses(self, w):
            return np.full(n, self.loss)

        def scores(self, w):
            return np.where(np.arange(n) % 2 == 0, 1.0, 0.0)
    events = {"a": [event(T0 + 50 * STEP, T0 + 60 * STEP)], "b": []}
    doc = protocol(window_rows=width)
    out = training_summary(windows, events, doc, model=Fake(1.0, "M:seed 0"), methods={"Z3": Fake(2.0),
                                                                                       "Z5": Fake(4.0)},
                           scenarios={"a": "eshop_low", "b": "corp_low"})
    assert out["loss"]["all"]["improvement"] == {"Z3": .5, "Z5": .75} and out["loss"]["all"]["windows"] == n
    assert set(out["loss"]) == {"all", "clean", "event", "reverberation"}
    assert out["score"]["by_scenario"]["corp_low"]["above_threshold"] == pytest.approx(.5, abs=.01)
    manifest = {"training": {"seed": 0}, "created_utc": "c", "provenance": {"corpus_index_sha256": "x"},
                "environment": {"kernel": "k", "stack_sha256": "s"}}
    record = training_record(out, manifest, ["python3", "-m", "tcn.seedy", "train"])
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(record) and record["n"] == n
    assert record["command"] == "python3 -m tcn.seedy train" and set(out["score"]["by_context"]) == set(out["loss"]) - {
        "all"}
    assert record["values"]["bundle"]["seed"] == 0
    with pytest.raises(ValueError, match="analysis.k1.compare"):
        training_summary(windows, events, doc, model=Fake(1.0), methods={"Z3": Fake(2.0)},
                         scenarios={"a": "eshop_low", "b": "corp_low"})
    windows.role = "test_benign"
    with pytest.raises(ValueError, match="a sealed role is the final command's"):
        training_summary(windows, events, doc, model=Fake(1.0), methods={"Z3": Fake(2.0), "Z5": Fake(4.0)},
                         scenarios={"a": "eshop_low", "b": "corp_low"})


def test_the_unevaluated_mark_is_the_one_of_tcn_metody():
    from tcn.eval import UNEVALUATED
    from tcn.metody import UNEVALUATED as WRAPPER
    assert UNEVALUATED == WRAPPER == "nevyhodnotené"


# ------------------------------------------------------------------ the seal of a replay, the one rule of the unscored
# stretches (design B7c 5.5 and 5.6, the merge of package B7c)


@pytest.mark.parametrize("command", ["far", "udalosti"])
def test_the_replays_of_a_final_run_are_refused_after_it(command, tmp_path, monkeypatch):
    """Design B7c 5.5 (question Q17, tcn.eval SEAL_RULE): the replays of the sealed archives of a campaign are read
    inside the final run that consumed their seal and refused by name after it, by far and by udalosti, as their
    archives are (tcn/pecat.py GUARD_RULE)."""
    from tcn import eval as ev
    from tcn import pecat
    ledger = tmp_path / "ledger" / "kniha_pecati.json"
    ledger.parent.mkdir()
    monkeypatch.setattr(pecat, "KNIHA", ledger)
    path, replays = corpus(tmp_path, [session("s1", events=[event(T0 + 200 * STEP, T0 + 230 * STEP)])],
                           mode="campaign")
    index = json.loads(path.read_text())
    pecat.zapis(index["sessions"], protocol=index["protocol_config"], protocol_sha256="0" * 64, mode="campaign",
                command="the test's campaign", ledger=ledger)

    def read():
        if command == "far":
            return ev.vyhodnot_far(path, "test_benign", replays, final_evaluation=True)[0]
        return ev.vyhodnot_udalosti(path, replays, rola="test_benign", final_evaluation=True)[0]
    with pecat.spotrebuj(path, out=tmp_path / "final.json", command="final", ledger=ledger):
        assert read()["pecat"] == {"decisions": {"s1": "final_run"}, "definition": ev.SEAL_RULE}
    with pytest.raises(pecat.Zapecatene) as error:
        read()
    record, = index["sessions"]
    entry, = json.loads(ledger.read_text())["values"]["runs"]
    assert str(error.value) == (
        f"tcn.eval {command}: refused, the archive of the replay {replays[0]} is sealed (sha256 "
        f"{record['features_sha256']}; session s1 of role test_benign, plan "
        f"{pecat.plan_name(index['protocol_config'], 'campaign')}, ledger {ledger.resolve()}): a sealed archive of a "
        "campaign is replayed or scored only by the final command (python -m tcn.finalne) in the run that consumes "
        f"its seal (tcn/pecat.py GUARD_RULE); its seal was consumed by the final run opened {entry['opened']['date']} "
        f"(out {(tmp_path / 'final.json').resolve()})")


@pytest.mark.parametrize("change", ["no_archive_sha256", "another_archive"])
def test_a_replay_of_schema_3_names_the_archive_it_replayed(change, tmp_path):
    """SEAL_RULE: a replay of a corpus of schema 3 without archive_sha256 is refused by name, here one of the sealed
    role test_benign, and so is one whose archive_sha256 is not the sha256 of the archive it names."""
    from tcn.eval import vyhodnot_far
    path, replays = corpus(tmp_path, [session("s1")])
    configuration = json.loads((replays[0] / "configuration.json").read_text())
    found = configuration["archive_sha256"]
    if change == "no_archive_sha256":
        del configuration["archive_sha256"]
        reason = (f"{replays[0]}: the replay of a session of role test_benign names no archive_sha256 in its "
                  "configuration.json (safeguard replay --archive and tcn.porovnanie replay write it since package "
                  "B7c): under protocol schema 3 the seal decides by it whether the replay may be read (tcn.eval "
                  "SEAL_RULE)")
    else:
        configuration["archive_sha256"] = "0" * 64
        reason = (f"{replays[0]}: the archive {configuration['archive']} has sha256 {found}, the replay names "
                  f"archive_sha256 {'0' * 64}: the replay is not of this archive (tcn.eval SEAL_RULE)")
    (replays[0] / "configuration.json").write_text(json.dumps(configuration))
    with pytest.raises(ValueError) as error:
        vyhodnot_far(path, "test_benign", replays)
    assert str(error.value) == reason


def test_the_unscored_stretches_are_those_of_safeguard_runtime():
    """Design B7c 5.6, one rule of the unscored stretches: those of the block v5 are safeguard.runtime.unscored's on
    the same rows, here a full snapshot and its warmup at the start and two unscored rows with a seq gap between them
    (two stretches, not one), each nevyhodnotené with the reasons of its rows."""
    from safeguard.runtime import unscored
    from tcn.eval import metriky_v5
    s = session("s1", scored=lambda i: not (i < 3 or i in (300, 301)))
    s["rows"][0]["reason"] = "full_snapshot"
    for r in s["rows"][301:]:
        r["seq"] += 1  # A frame missing from the archive after row 300.
    found = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")["unscored"]["sessions"]["s1"]
    assert found["stretches"] == unscored(s["rows"], STEP)["stretches"]
    assert [(x["first_seq"], x["last_seq"], x["rows"], x["seconds"], x["reasons"], x["status"])
            for x in found["stretches"]] == [
        (0, 2, 3, 15.0, {"full_snapshot": 1, "warming_up": 2}, "nevyhodnotené"),
        (300, 300, 1, 5.0, {"warming_up": 1}, "nevyhodnotené"),
        (302, 302, 1, 5.0, {"warming_up": 1}, "nevyhodnotené")]


# ------------------------------------------------------------------ the fix round of B7c (findings F4, F6, F9, mutant S9)


def test_o4_takes_the_planned_controls_and_gives_the_increment_of_the_neural_channel():
    """O4 over the planned occurrences (proposal 6.4: one that is not evaluable stays in the denominator) and, in every
    group, the increment of the neural channel over the rule channel (INCREMENT_RULE, proposal 8.2, finding F6): of
    three planned controls the neural channel detects the first, both channels the second, and the third is not
    evaluable (10 of the 12 rows of its first 60 s unscored); the neural share is 2 of 3 (not of the 2 evaluable),
    the rule's 1 of 3, and the increment 1 of 3 with its counts."""
    from tcn.eval import metriky_v5
    starts = [T0 + 100 * STEP, T0 + 300 * STEP, T0 + 500 * STEP]
    unscored = set(range(501, 511))
    s = session("s1", "test_controls", group="g5-test_controls-1", controls=[control(a, a + 60) for a in starts],
                up=lambda i: {"neural"} if i == 110 else ({"neural", "rule"} if i == 310 else ()),
                scored=lambda i: i not in unscored)
    outcomes = []
    for a in starts:
        horizon = [i for i in range(720) if a < T0 + STEP * i <= a + 180]
        outcomes.append(outcome(a, horizon, [i for i in horizon if i not in unscored]))
    o4 = metriky_v5(protocol(min_occurrences=1), [state(s)], triedy=CLASSES, rola="test_controls",
                    vysledky_kontrol={"s1": outcomes})["o4"]
    total = o4["control"]["total"]
    assert (total["planned"], total["evaluable"], total["status"]) == (3, 2, "evaluated")
    assert (total["neural"]["share"], total["rule"]["share"], total["union"]["share"]) == (2 / 3, 1 / 3, 2 / 3)
    assert total["neural_over_rule"] == {"planned": 3, "rule": 1, "rule_or_neural": 2, "neural_not_rule": 1,
                                         "share": 1 / 3, "status": "evaluated"}
    assert o4["control"]["by_kind"]["kontrola_modul_jadra"]["neural_over_rule"] == total["neural_over_rule"]


def test_the_thesis_rate_gives_the_garwood_interval_per_scored_hour():
    """Finding F9: beside the rate per observed hour, the rate of the thesis gives the Garwood interval per scored
    hour. Two alarms of the neural channel in one session of 720 rows (one observed hour), every second row scored
    (half a scored hour): the table values of Garwood at 0.95 for k = 2 (0.2422, 7.2247) over each."""
    from tcn.eval import metriky_v5
    s = session("s1", up=lambda i: {"neural"} if i in (100, 500) else (), scored=lambda i: i % 2 == 0)
    rate = metriky_v5(protocol(), [state(s)], triedy=CLASSES, rola="test_benign")["thesis"]["rate"]["total"]
    neural = rate["neural"]
    assert (rate["observed_hours"], rate["scored_hours"], neural["alarms"], neural["per_scored_hour"]) == (
        1.0, 0.5, 2, 4.0)
    assert neural["bounds_per_hour"] == [pytest.approx(0.2422, abs=1e-4), pytest.approx(7.2247, abs=1e-4)]
    assert neural["bounds_per_scored_hour"] == [pytest.approx(0.2422 / 0.5, abs=2e-4),
                                                pytest.approx(7.2247 / 0.5, abs=2e-4)]


@pytest.mark.parametrize("mode, of_record, stage", [("campaign", True, "final"), ("rehearsal", True, "generalka"),
                                                    ("campaign", False, "suchy")],
                         ids=["campaign_of_record", "rehearsal_of_record", "another_ledger"])
def test_a_record_of_schema_3_carries_the_stage_of_its_ledger(mode, of_record, stage, tmp_path, monkeypatch):
    """Finding F4 (proposal 11.1): the values and the record of far and of udalosti under schema 3 carry the stage
    that tcn.pecat's STAGE_RULE gives the plan mode and the ledger of the process: final or generalka on the ledger
    of record, suchy on another."""
    from tcn import eval as ev
    from tcn import pecat
    ledger = tmp_path / "ledger" / "kniha_pecati.json"
    ledger.parent.mkdir()
    pecat.zaloz(command="test_eval_v5", ledger=ledger)
    monkeypatch.setattr(pecat, "KNIHA", ledger)
    if of_record:
        monkeypatch.setattr(pecat, "ZAZNAM", ledger)
    s = session("s1", "dev", group="g5-dev-1", events=[event(T0 + 200 * STEP, T0 + 230 * STEP)])
    # Package B9b (finding N2 of the confirmation of B7c, tcn.pecat record_stage): the stage of a record is that of
    # the seal of its corpus, so the corpus holds a session of a sealed role whose archive the ledger holds in the
    # corpus's mode (as a campaign writes it) and the ledger at HEAD holds it too; the role dev is evaluated.
    path, replays = corpus(tmp_path, [s, sealed_session()], mode=mode)
    seal_corpus(path, mode, ledger)
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: True)
    replays = replays[:1]
    far, _ = ev.vyhodnot_far(path, "dev", replays)
    udalosti, _ = ev.vyhodnot_udalosti(path, replays, rola="dev")
    assert (far["stage"], udalosti["stage"], far["stage_rule"]) == (stage, stage, pecat.STAGE_RULE)
    replay = [str(r) for r in replays]
    assert ev._hlavny(["far", "--corpus", str(path), "--role", "dev", "--replay", *replay, "--out",
                       str(tmp_path / "far.json")]) == 0
    assert ev._hlavny(["udalosti", "--index", str(path), "--role", "dev", "--replay", *replay, "--out",
                       str(tmp_path / "udalosti.json")]) == 0
    for name in ("far.json", "udalosti.json"):
        record = json.loads((tmp_path / name).read_text())
        assert (record["stage"], record["values"]["stage"]) == (stage, stage)


def sealed_session():
    """A session of the sealed role test_benign beside the evaluated session of role dev (package B9b)."""
    return session("t1", "test_benign", group="g5-test_benign-1")


def seal_corpus(path, mode, ledger):
    """Write the sessions of the sealed roles of the corpus index at `path` into `ledger` in plan mode `mode`, as the
    campaign writes them at acceptance (tcn.pecat zapis)."""
    from tcn import pecat
    index = json.loads(Path(path).read_text())
    pecat.zapis(index["sessions"], protocol=index["protocol_config"], protocol_sha256="0" * 64, mode=mode,
                command="test_eval_v5", ledger=ledger)


@pytest.mark.parametrize("case", ["not_in_the_ledger", "not_at_head", "outside_the_repository",
                                  "no_sealed_session"])
def test_a_synthetic_campaign_corpus_is_recorded_suchy_with_the_basis_of_its_stage(case, tmp_path, monkeypatch):
    """Finding N2 of the confirmation of B7c (package B9b): from the command line a corpus of plan mode campaign on
    the ledger of record is recorded final only when that ledger holds the archives of the sessions of its sealed
    roles and the ledger at HEAD holds them (the case final is the test above); a synthetic corpus whose archives the
    ledger does not hold is suchy, and so is one whose seal the ledger at HEAD does not hold or cannot show (here the
    ledger lies outside the repository) and one without a session of a sealed role; the far and udalosti records name
    why (values.stage_basis)."""
    from tcn import eval as ev
    from tcn import pecat
    ledger = tmp_path / "ledger" / "kniha_pecati.json"
    ledger.parent.mkdir()
    pecat.zaloz(command="test_eval_v5", ledger=ledger)
    monkeypatch.setattr(pecat, "KNIHA", ledger)
    monkeypatch.setattr(pecat, "ZAZNAM", ledger)
    s = session("s1", "dev", group="v5-dev-1", events=[event(T0 + 200 * STEP, T0 + 230 * STEP)])
    path, replays = corpus(tmp_path, [s] if case == "no_sealed_session" else [s, sealed_session()], mode="campaign")
    if case in ("not_at_head", "outside_the_repository"):
        seal_corpus(path, "campaign", ledger)
    if case != "outside_the_repository":
        monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: case != "not_at_head")
    why = {"not_in_the_ledger": "the ledger of record holds no archive of 1 of the 1 sessions of the sealed roles for "
                                "their session, role and plan mode campaign (first t1): their seal is not the "
                                "campaign's",
           "not_at_head": f"the ledger {ledger.resolve()} as committed at HEAD does not hold every archive of the "
                          "sessions of the sealed roles",
           "outside_the_repository": f"whether the ledger at HEAD holds them cannot be shown (the ledger "
                                     f"{ledger.resolve()} lies outside the repository {ROOT}, or git is unavailable)",
           "no_sealed_session": "the record covers no session of the sealed roles test_benign, test_controls: the "
                                "ledger of record cannot tie it to the seal of a plan"}[case]
    replay = [str(replays[0])]
    assert ev._hlavny(["far", "--corpus", str(path), "--role", "dev", "--replay", *replay, "--out",
                       str(tmp_path / "far.json")]) == 0
    assert ev._hlavny(["udalosti", "--index", str(path), "--role", "dev", "--replay", *replay, "--out",
                       str(tmp_path / "udalosti.json")]) == 0
    for name in ("far.json", "udalosti.json"):
        record = json.loads((tmp_path / name).read_text())
        basis = record["values"]["stage_basis"]
        assert (record["stage"], record["values"]["stage"], basis["rule"], basis["of_record"], basis["why"]) == (
            "suchy", "suchy", pecat.RECORD_STAGE_RULE, True, why)
        assert basis["missing"] == (["t1"] if case == "not_in_the_ledger" else None if case == "no_sealed_session"
                                    else [])
