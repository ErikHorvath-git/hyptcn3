"""The one final evaluation (tcn/finalne.py, package B7c, agent E; design dokazy/B7/navrh/NAVRH_B7c.md section 4 and
its addendum 5, the merge with agents S and M).

A small synthetic corpus of the v5 shape in rehearsal mode: the five roles of protocol schema 3 in two groups each (the
rehearsal's groups_per_role) on two VMs, events in every role but test_controls, controls and their paired negatives
in test_controls (controls.json), the offered load of every session (traffic_intervals.jsonl), audited by the code of
the audit (collection.analyze_windows) and indexed by features/dataset.py build in mode rehearsal; the five bundles of
M are trained on it by safeguard.training.train_bundle at the seeds of analysis.seeds. Its twin in mode campaign (the
same builder) serves the tests that end before anything is computed, so it has no bundles. The analysis of the
protocol is the one of config/collection-v5.json on the test's window (scripts/tests/boundary_sessions.py
v5_sections, fit_analysis, with the file's analysis.metrics and analysis.linkage) with the numbers a corpus this small
can carry: they are the test's, no judgment of the protocol.

The seal is agent S's tcn/pecat.py on a ledger of the test (tcn.pecat.KNIHA, the ledger the guards read, points at
it): a run on it has stage suchy; the end-to-end test makes it the ledger of record as well (tcn.pecat.ZAZNAM), stage
generalka, and the test of the gates stage final, whose seal the ledger at HEAD is taken to hold (tcn.pecat._in_git;
its refusal is tcn/tests/test_pecat.py's). The gate records are taken as valid (scripts.gates.require, its calls
recorded) except in the test of their refusal. The metrics are agent M's tcn/eval.py as it is. The names of package
B7c are imported inside the tests, so this file collects on the code before it. Only mechanics on synthetic rows: no
number here is a result of detection (HONESTY P4). Package B11 (agent E; the lead's answers to questions Q17 and Q28):
both end-to-end runs check the attachments of their record against its numbers, an existing attachment is refused
before the seal, and a failed run leaves none.
"""
import copy
import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from features import archive as feature_archive
from features import dataset
from features.snapshot import MENA, SCHEMA
from scripts import campaign, collection, protocol_v5
from scripts.tests.boundary_sessions import _v5_file, audit_sections, fit_analysis, v5_sections

CYCLES, FULL_EVERY, WINDOW = 96, 64, 8
LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[i, 4096] for i in range(3)],
          "regions": [{"gpa": 0, "bytes": 50331648}], "memsize": 50331648, "vcpus": 2}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "truncated_traversals": [],
        "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0, "process_walk": "next",
        "memory_patterns": []}
SCENARIOS = ("eshop_low", "corp_low")  # Two profiles of config/collection-v5.json, so the profile table has two rows.
ROLES = {"train": 2, "dev": 2, "calibration": 2, "test_benign": 2, "test_controls": 2}
SEALED = ("test_benign", "test_controls")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _protocol(profile):
    """The protocol of the test corpus (module docstring)."""
    v5file = _v5_file()
    v5 = v5_sections(SCENARIOS, ROLES, group_sessions=2, window_rows=WINDOW)
    v5.update(roles=dict(ROLES), interleave=[["test_benign", "test_controls"]],
              scenarios={name: copy.deepcopy(v5file["scenarios"][name]) for name in SCENARIOS})
    a = fit_analysis(v5["analysis"], fpr=0.05, max_epochs=1, batch_size=64)
    for claim in protocol_v5.CLAIMS:
        a[claim]["m"] = 0.0
    a["methods"]["Z1"]["grid"] = {"moving_average_rows": [2, 4], "cusum_shift": [0.5]}
    a["methods"]["Z3"]["grid"] = {"ewma_alpha": [0.5]}
    a["methods"]["Z5"]["grid"] = {"ridge_alpha": [1.0]}
    # Sessions of 96 rows: a short reverberation and horizon, short blocks, few interventions, one evaluable one
    # suffices, few repetitions and resamples.
    a.update(reverberation_s=20, horizon_s=20, evaluable={"first_s": 10, "scored_share": 0.5}, min_occurrences=1)
    a["interventions"]["min_evaluable"] = 1
    # The boots of K2 are the carrier boots of the index (two groups of each carrier role, tcn/k2.py k2_values;
    # finding F3 of the verification of B7c: the file's 20 boots made a campaign of this corpus fail after its seal).
    a["interventions"]["boots"] = ROLES["test_benign"] + ROLES["test_controls"]
    for cls in ("C", "D"):
        a["interventions"][cls].update(lengths=[2, 4], per_boot=2)
    a["matched_rate"]["z0_repetitions"] = 3
    a["statistics"]["bootstrap"] = 200
    a["diagnostics"]["min_positive_episodes"] = 2
    v5["analysis"] = a
    v5["controls"].update(slots_per_session=2, min_duration_s=20, duration_s=[20, 30], horizon_s=30)
    from scripts.tests.boundary_sessions import early_stop_bounds  # Package B9b: imported here, as its name is new.
    sections = audit_sections(5)
    # Package B9b: audit.early_stop holds one bound per event type, here the two types of the test's schedule.
    sections["audit"]["early_stop"] = early_stop_bounds(["udrzba_zaloha", "zamok_tabulky"])
    return {
        **v5, **sections,
        "schema": protocol_v5.SCHEMA, "name": "finalne-test", "quality_policy": "behavioral-inputs-v1",
        "profile": str(profile), "interval_s": 5, "max_gap_s": 7.5, "bin_bytes": 16777216, "window_rows": WINDOW,
        "stride": 1, "full_every": FULL_EVERY, "cycles": CYCLES, "pilot_cycles": CYCLES, "min_score_coverage": 0.7,
        "vms": [{"name": "a", "domain": "hyptcn-test-a", "port": 28080},
                {"name": "b", "domain": "hyptcn-test-b", "port": 28081}],
        "group_prefix": "v5-", "full_snapshot_guard": dict(v5["full_snapshot_guard"], before_s=10),
        "events": dict(v5["events"], note="the test's schedule", per_session=[1], duration_s=[20, 30], first_s=60,
                       min_gap_s=60, tail_s=60, grace_s=10,
                       types={"zamok_tabulky": "chyba_aplikacie", "udrzba_zaloha": "udrzba"},
                       min_per_type=dict.fromkeys(("train", "dev", "calibration", "test_benign"), 0)),
        "invalid_rows": {"max": 1, "traversals": ["processes"]},
    }


def _result(session, t0, scenario, seed):
    """The extraction result of one session (features.snapshot.retazec), values as safeguard.demo."""
    rng = np.random.default_rng(seed)
    t = np.arange(CYCLES)
    level = 0.02 + scenario * 0.08
    matrix = np.zeros((CYCLES, len(MENA)))
    matrix[:, :8] = np.clip(level + rng.normal(0, 0.005, (CYCLES, 8)), 0, 1)
    matrix[:, 8:18] = 20 + scenario * 10 + rng.integers(0, 5, (CYCLES, 10))
    predecessor, full = MENA.index("ma_predchodcu"), MENA.index("je_plna")
    matrix[:, predecessor] = 1
    matrix[t % FULL_EVERY == 0, full] = 1
    matrix[t % FULL_EVERY == 0, predecessor] = 0
    for name in ("proc_new", "proc_gone", "mod_delta"):
        matrix[matrix[:, predecessor] == 0, MENA.index(name)] = 0
    local = np.zeros((CYCLES, len(LAYOUT["bins"]), 4))
    local[:, :, 0] = np.clip(level + rng.normal(0, 0.01, local.shape[:2]), 0, 1)
    local[:, :, 1] = rng.uniform(0.1, 0.3, local.shape[:2])
    local[:, :, 3] = local[:, :, 0] > 0
    local[:, :, 2] = np.clip(4 + scenario + rng.normal(0, 0.1, local.shape[:2]), 0, 8) * local[:, :, 3]
    quality = [copy.deepcopy(GOOD) for _ in t]
    return {"schema": SCHEMA, "mena": MENA, "matica": matrix.tolist(), "perbin": local.tolist(),
            "seq": [int(i) for i in t], "casy": [t0 + 5.0 * int(i) for i in t], "valid": [True] * CYCLES,
            "quality": quality, "quality_policy": "behavioral-inputs-v1", "biny": [b[0] for b in LAYOUT["bins"]],
            "chain_ids": [f"{session}-chain-{int(i) // FULL_EVERY}" for i in t],
            "snimky": [f"synthetic-{int(i)}" for i in t], "trvanie_s": [0.0] * CYCLES, "poznamky": [[] for _ in t],
            "layout": LAYOUT, "max_medzera_s": 7.5}


def _ran(item, t0):
    """The host times of an occurrence that ran as planned (scripts/collection.py Events, Controls)."""
    start = t0 + item["start_s"]
    return {"executed": True, "host_start_unix": start, "start": {"ok": True, "started": True},
            "host_started_unix": start + 1.0, "host_stop_unix": start + item["duration_s"],
            "stop": {"ok": True, "health": 200}, "host_stopped_unix": start + item["duration_s"] + 1.0}


def _corpus(root, mode):
    """The corpus of the module docstring in plan mode `mode` under `root`: {index, protocol, protocol_path,
    records}."""
    root.mkdir(parents=True)
    profile = root / "profile"
    profile.mkdir()
    (profile / "symbols.txt").write_text("synthetic profile of the test\n")
    path = root / "protocol.json"
    collection.write_json(path, _protocol(profile))
    p = collection.protocol(path)
    protocol_sha = _sha(path)
    order, audits = {}, []
    for i, s in enumerate(protocol_v5.plan(p, mode)["sessions"]):
        sid = "_".join(["finalne", f"{i + 1:02d}", s["vm"], s["role"], s["scenario"]])
        place = order.setdefault((s["role"], s["vm"]), [])
        t0 = 1700000000.0 + list(p["roles"]).index(s["role"]) * 4000 + len(place) * 600
        place.append(sid)
        result = _result(sid, t0, list(p["scenarios"]).index(s["scenario"]), s["seed"])
        rows, _, verdict, quality = collection.analyze_windows(result, p, sid, s["role"])
        assert verdict["reasons"] == [], (sid, verdict["reasons"])
        directory = root / "sessions" / sid
        directory.mkdir(parents=True)
        events = s.get("events", [])
        collection.write_json(directory / "session.json", {
            "schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": "finalne", "vm": s["vm"],
            "role": s["role"], "group": s["group"], "group_attempt": 1, "scenario": s["scenario"], "typ": "benign",
            "seed": s["seed"], "cycles": s["cycles"],
            "guest_before": {"boot_id": "boot-" + s["group"], "kernel": "6.1.0-test", "stack_sha256": "5" * 64},
            "events": events, "event_grace_s": p["events"]["grace_s"], "protocol_sha256": protocol_sha,
            "collector_sha256": "c" * 64, "profile_sha256": {"symbols.txt": _sha(profile / "symbols.txt")}})
        collection.write_json(directory / "events.json", {"schema": "hyptcn3/session-events/1", "events": [
            dict(item, **_ran(item, t0)) for item in events], "note": "the test's record"})
        if s["role"] == "test_controls":
            records = [dict(collection.control_record(item), **({} if item.get("kind") is None else dict(
                _ran(item, t0), baseline={"ok": True}, effect={"ok": True, "evidence": {"members": [4242]}},
                cleanup={"ok": True}))) for item in s["controls"]]
            collection.write_json(directory / "controls.json", {"schema": protocol_v5.CONTROLS_SCHEMA,
                                                                "controls": records})
        with (directory / "traffic_intervals.jsonl").open("w") as stream:
            schema, rng = "hyptcn3/traffic-interval/2", np.random.default_rng(i)
            stream.write(json.dumps({"type": "header", "schema": schema, "n": 0, "start_unix": t0 - 10}) + "\n")
            for k in range(CYCLES + 3):
                stream.write(json.dumps({"type": "interval", "schema": schema, "n": k + 1, "mono_start": 5.0 * k,
                                         "mono_end": 5.0 * (k + 1),
                                         "offered_sessions": float(rng.integers(0, 6))}) + "\n")
        archive = feature_archive.save(directory / "audit_test.npz", result)
        session_sha = _sha(directory / "session.json")
        collection.write_json(directory / "audit_test.json", {"schema": "hyptcn3/collection-audit/1", "n": len(rows),
                                                              "values": {
            "accepted": True, "reasons": [], "role": s["role"], "protocol_sha256": protocol_sha,
            "snapshots": verdict["snapshots"], "windows": verdict["windows"],
            "score_coverage": verdict["score_coverage"], "acceptance": verdict,
            "coverage": quality.pop("coverage", None),
            "logs": {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True, "problems": [],
                     "sections": {"metadata": {"session_sha256": session_sha}}},
            "quality": quality, "session_sha256": session_sha, "extractor_sha256": campaign.extractor_hashes(),
            "features": str(archive), "features_sha256": _sha(archive), "layout": result["layout"],
            "session_dir": str(directory)}})
        audits.append(directory / "audit_test.json")
    doc = dataset.build(audits, p, protocol_sha, mode=mode)
    doc["protocol"] = str(path)
    assert doc["complete"], doc["allocation_mismatches"]
    index = root / "corpus.json"
    collection.write_json(index, doc)
    return {"index": index, "protocol": p, "protocol_path": path, "records": doc["sessions"]}


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    return _corpus(tmp_path_factory.mktemp("finalne") / "corpus", "rehearsal")


@pytest.fixture(scope="module")
def campaign_corpus(tmp_path_factory):
    return _corpus(tmp_path_factory.mktemp("finalne-campaign") / "corpus", "campaign")


def _train(corpus, root):
    """The bundles of M at every seed of analysis.seeds (safeguard.training.train_bundle) of a corpus."""
    import torch
    from safeguard.training import train_bundle
    threads = torch.get_num_threads()
    torch.set_num_threads(2)
    try:
        return [Path(train_bundle(corpus["index"], root / f"seed-{seed}", window_rows=WINDOW, max_gap_s=7.5,
                                  seed=seed)["bundle"]) for seed in corpus["protocol"]["analysis"]["seeds"]]
    finally:
        torch.set_num_threads(threads)


@pytest.fixture(scope="module")
def models(corpus, tmp_path_factory):
    return _train(corpus, tmp_path_factory.mktemp("models"))


@pytest.fixture(scope="module")
def campaign_models(campaign_corpus, tmp_path_factory):
    return _train(campaign_corpus, tmp_path_factory.mktemp("models-campaign"))


def _campaign_record(corpus, path):
    """The record of the complete ending of the campaign of `corpus` of package B9 (design B7c 1.4; package B9b,
    scripts/campaign.py ENDING_RULE), of its documented shape: its schema, the ending complete, the campaign of the
    index (the campaign_id of its session.json files, "finalne"), a row in state accepted per session of the index, one
    rejected session replaced and one not. tcn.finalne reads only the record of its own corpus (CAMPAIGN_RULE, F7 of
    the verification of B9b), so each corpus has its record."""
    doc = json.loads(Path(corpus["index"]).read_text())
    planned = len(corpus["records"])
    rows = [{"session": r["id"], "vm": r.get("vm"), "role": r["role"], "group": r["group"], "scenario": r["scenario"],
             "attempt": 1, "state": "accepted", "cause": None, "replacement": None} for r in doc["sessions"]]
    path.write_text(json.dumps({"schema": "hyptcn3/campaign-ending/1", "commit": "0" * 40, "date": "2026-11-23",
                                "host": "test", "guest": None, "command": "the test's record", "n": planned,
                                "values": {
                                    "campaign": "finalne", "ending": "complete", "sessions": rows,
                                    "planned_sessions": planned, "accepted_sessions": planned,
                                    "rejected_sessions": [
                                        {"session": "finalne_03-r", "cause": "audit_rejected",
                                         "replacement": "finalne_03-r-r1"},
                                        {"session": "finalne_07-c", "cause": "capture_incomplete",
                                         "replacement": None}]}}))
    return path


@pytest.fixture(scope="module")
def campaign_record(corpus, tmp_path_factory):
    """The record of the complete ending of the corpus in plan mode rehearsal (_campaign_record)."""
    return _campaign_record(corpus, tmp_path_factory.mktemp("campaign") / "campaign.json")


@pytest.fixture(scope="module")
def campaign_record_campaign(campaign_corpus, tmp_path_factory):
    """The record of the complete ending of the corpus in plan mode campaign (_campaign_record)."""
    return _campaign_record(campaign_corpus, tmp_path_factory.mktemp("campaign-campaign") / "campaign.json")


@pytest.fixture
def ledger(tmp_path_factory, monkeypatch):
    """The test's ledger (tcn.pecat zaloz), the ledger of this process that the guards read (tcn.pecat.KNIHA); no
    final run stays open after a test."""
    from tcn import pecat
    path = tmp_path_factory.mktemp("ledger") / "kniha_pecati.json"
    monkeypatch.setattr(pecat, "KNIHA", path)
    pecat.zaloz(command="test_finalne", ledger=path)
    yield path
    run = pecat.otvoreny()
    if run is not None:
        run.close("failed", "left open by a test")
        pytest.fail("a final run stayed open")


@pytest.fixture
def of_record(ledger, monkeypatch):
    """The test's ledger as the ledger of record (tcn.pecat.ZAZNAM, design B7c 5.1): a run on it has stage final or
    generalka, and at stage final the ledger at HEAD is taken to hold its seal (tcn.pecat._in_git)."""
    from tcn import pecat
    monkeypatch.setattr(pecat, "ZAZNAM", ledger)
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: True)
    return ledger


@pytest.fixture
def gates_passed(monkeypatch):
    """Every gate record taken as valid (scripts.gates.require, design B7c 5.3); the calls in order."""
    from scripts import gates
    calls = []
    monkeypatch.setattr(gates, "require", lambda results, protocol, stage: calls.append((results, protocol, stage)))
    return calls


@pytest.fixture
def results(tmp_path_factory, monkeypatch):
    """The tracked results of the final command (tcn.finalne.RESULTS) in a directory of the test: the gate records
    (none) and the record of a run of stage final or generalka (OUT_RULE); data/results is never written."""
    from tcn import finalne
    path = tmp_path_factory.mktemp("results")
    monkeypatch.setattr(finalne, "RESULTS", path)
    return path


# Proposal 9.1 (tcn/finalne.py CONFIRMATORY_RULE): the top level of the values of a complete record and of a failed one,
# and the descriptive part (opisné). Package B11 (ATTACHMENT_RULE): a complete record names its attachments, a failed
# one none.
TOP = {"schema", "stage", "mark", "plan_mode", "corpus_index", "corpus_index_sha256", "rehearsal", "order_rule",
       "campaign", "corpus", "seal", "seal_note", "gate", "tree", "models", "status", "replays", "attachments", "rules",
       "budget", "methods", "matched", "claims", "conclusions", "k2_values", "interventions", "opisné"}
FAILED = {"schema", "stage", "mark", "plan_mode", "corpus_index", "corpus_index_sha256", "rehearsal", "order_rule",
          "campaign", "corpus", "seal", "seal_note", "gate", "tree", "models", "status", "failed_step", "error", "rule",
          "replays", "opisné"}
OPISNE = {"metrics", "diagnostics", "descriptive_methods", "losses", "tables", "training", "unscored", "z0_random",
          "linkage", "rule_channel_only"}
CONFIRMATORY, DESCRIPTIVE = ("M", "Z0", "Z1", "Z2", "Z3", "Z4", "Z5"), ("zscore", "iforest", "gru", "lstm")


def _names(labels):
    return {label.split(":")[0] for label in labels}


def _parts(v, seeds):
    """Proposal 9.1: the exact key sets of the values and of opisné; the matched thresholds, the fits and the values
    of K2 of M and Z0 to Z5 at the top level, those of the descriptive methods under opisné; the wording of the rule
    channel filled with a number (finding F6)."""
    from safeguard.training import RULE_CHANNEL_ONLY
    o = v["opisné"]
    assert set(v) == TOP and set(o) == OPISNE
    descriptive = o["descriptive_methods"]
    assert set(descriptive) == {"methods", "matched", "k2_values"}
    assert _names(v["matched"]) == set(CONFIRMATORY) and _names(v["methods"]) == set(CONFIRMATORY) - {"M"}
    assert _names(descriptive["matched"]) == _names(descriptive["methods"]) == set(DESCRIPTIVE)
    for key in ("thresholds", "detected"):
        assert _names(v["k2_values"][key]) == set(CONFIRMATORY) and _names(descriptive["k2_values"][key]) == set(
            DESCRIPTIVE)
    assert all(_names(row.get("shares", {})) <= set(CONFIRMATORY) for row in v["k2_values"]["table"])
    assert all(_names(row.get("shares", {})) <= set(DESCRIPTIVE) for row in descriptive["k2_values"]["table"])
    wording = o["rule_channel_only"]
    assert wording["wording"] == RULE_CHANNEL_ONLY and "…" not in wording["text"]
    assert wording["text"].startswith(RULE_CHANNEL_ONLY["text"][:-1]) and set(wording["increment"]["per_seed"]) == {
        str(seed) for seed in seeds}


def _attachments(v, out, corpus):
    """Package B11 (the lead's answers to questions Q17 and Q28, tcn/finalne.py ATTACHMENT_RULE): values.attachments
    names exactly the attachments of the protocol, each the file <record stem>.<name>.npz beside the record whose
    sha256 and bytes the record holds, read with allow_pickle=False and holding exactly the arrays of its contents; and
    their contents are the record's numbers: the series holds every sealed session, one row per frame, every method
    and seed at its matched threshold, whose alarms in the clean windows of each role are those of its matched rate,
    M's replay rows as its events.jsonl holds them, and the host times of every event and control; the losses give
    the mean loss over the clean windows of test_benign of every predictor (opisné.losses); the copies give the
    detection of every intervention by every label of K2 (k2_values.detected)."""
    from tcn import finalne
    p, o = corpus["protocol"], v["opisné"]
    listed = [name for name in p["analysis"]["attachments"] if name != "note"]
    assert list(v["attachments"]) == listed == list(protocol_v5.ATTACHMENTS) == ["series", "losses", "copies"]
    found = {}
    for name, item in v["attachments"].items():
        path = Path(item["path"])
        assert path == Path(out).resolve().with_name(f"{Path(out).stem}.{name}.npz")
        assert (item["sha256"], item["bytes"]) == (_sha(path), path.stat().st_size)
        assert (item["format"], item["contents"], item["rule"]) == (
            finalne.ATTACHMENT_FORMAT, finalne.CONTENTS[name], finalne.ATTACHMENT_RULES[name])
        with np.load(path, allow_pickle=False) as data:
            found[name] = {key: data[key] for key in data.files}
        assert set(found[name]) == set(item["contents"])
    series, losses, copies = (found[name] for name in ("series", "losses", "copies"))
    by_id = {r["id"]: r for r in corpus["records"]}
    sealed = [r["id"] for r in corpus["records"] if r["role"] in SEALED]
    ids = series["session_id"].tolist()
    assert sorted(ids) == sorted(sealed) and losses["session_id"].tolist() == ids
    assert series["session_role"].tolist() == [by_id[ident]["role"] for ident in ids] == sorted(
        series["session_role"].tolist(), key=SEALED.index)
    assert series["session_boot"].tolist() == [by_id[ident]["group"] for ident in ids]
    assert series["session_rows"].tolist() == [CYCLES] * len(ids) and len(series["row_seq"]) == CYCLES * len(ids)
    assert series["row_seq"].tolist() == [seq for _ in ids for seq in range(CYCLES)]
    # Every method and seed at its matched threshold; its alarms in the clean windows of a role are its matched rate's.
    matched = {**v["matched"], **o["descriptive_methods"]["matched"]}
    labels = series["label"].tolist()
    assert labels == list(matched) and series["threshold"].tolist() == [matched[x]["threshold"] for x in labels]
    roles = {role: np.isin(series["row_session"], [i for i, ident in enumerate(ids) if by_id[ident]["role"] == role])
             for role in SEALED}
    for i, label in enumerate(labels):
        assert np.array_equal(np.isnan(series["score"][i]), ~series["row_window"])
        assert np.array_equal(series["exceed"][i], series["score"][i] > series["threshold"][i])
        assert not (series["edge"][i] & ~series["up"][i]).any()
        for role, mine in roles.items():
            rate = matched[label]["rates"][role]
            assert (int((series["edge"][i] & series["row_clean"] & mine).sum()),
                    int((series["row_clean"] & mine).sum())) == (rate["alarms"], rate["windows"]), (label, role)
    # M's replay rows, as the events.jsonl of its replay holds them.
    assert series["replay_seed"].tolist() == [m["seed"] for m in v["models"]]
    assert series["replay_threshold"].tolist() == [m["threshold"] for m in v["models"]]
    first = ids.index(next(ident for ident in ids if by_id[ident]["role"] == "test_benign"))
    rows = slice(int(series["session_first_row"][first]), int(series["session_first_row"][first]) + CYCLES)
    directory = Path(v["replays"]["sessions"][ids[first]]["0"]["directory"])
    replay = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
    assert [None if np.isnan(x) else x for x in series["replay_score"][0, rows].tolist()] == [r["score"]
                                                                                              for r in replay]
    sources = series["sources"].tolist()
    assert [[sources[j] for j in np.flatnonzero(x)] for x in series["replay_sources"][0, rows]] == [
        r["alarm_sources"] for r in replay]
    assert series["replay_alarm"][0, rows].tolist() == [r["alarm"] for r in replay]
    # The events and the controls with their host times.
    expected = []
    for i, ident in enumerate(ids):
        record = by_id[ident]
        expected += [(i, "event", e["type"], "", e["host_start_unix"], e["host_stopped_unix"])
                     for e in json.loads(Path(record["events"]).read_text())["events"]]
        if record["role"] == "test_controls":
            expected += [(i, "control", c["kind"], c["polarity"], c["host_start_unix"], c["host_stopped_unix"])
                         for c in json.loads(Path(record["controls"]).read_text())["controls"] if c.get("kind")]
    assert list(zip(series["occurrence_session"].tolist(), series["occurrence_what"].tolist(),
                    series["occurrence_type"].tolist(), series["occurrence_polarity"].tolist(),
                    series["occurrence_host_start_unix"].tolist(),
                    series["occurrence_host_stopped_unix"].tolist())) == expected
    assert any(what == "control" for _, what, *_ in expected) and any(what == "event" for _, what, *_ in expected)
    # The losses of every predictor: opisné.losses over the clean windows of test_benign.
    assert losses["label"].tolist() == list(o["losses"])
    clean = losses["row_clean"] & roles["test_benign"]
    for i, label in enumerate(losses["label"].tolist()):
        assert float(np.mean(losses["loss"][i][clean])) == o["losses"][label]["mean"]
    # The copies: every placed intervention of K2, and its detection by every label of K2.
    placed = [item for role in SEALED for item in v["interventions"][role]["interventions"] if item["placed"]]
    assert copies["intervention_id"].tolist() == [item["id"] for item in placed]
    k2 = {**v["k2_values"]["thresholds"], **o["descriptive_methods"]["k2_values"]["thresholds"]}
    detected = {**v["k2_values"]["detected"], **o["descriptive_methods"]["k2_values"]["detected"]}
    assert copies["label"].tolist() == list(k2) and copies["threshold"].tolist() == [k2[x]["threshold"] for x in k2]
    for c, item in enumerate(placed):
        mine = copies["row_intervention"] == c
        assert int((copies["row_block"] & mine).sum()) == item["length"]
        for i, label in enumerate(copies["label"].tolist()):
            hit = bool((copies["edge"][i] & copies["row_horizon"] & mine).any())
            assert hit == detected[label][item["id"]], (label, item["id"])
    return found


def _argv(corpus, models, campaign, tmp, **change):
    options = {"--corpus": corpus["index"], "--campaign": campaign, "--replays": tmp / "replays",
               "--out": tmp / "record.json", **change}
    argv = ["--models", *map(str, change.pop("--models", models))]
    for key, value in options.items():
        if key != "--models":
            argv += [key, str(value)]
    return argv + ["--threads", "2"]


def test_a_rehearsal_runs_the_final_command_end_to_end_into_one_record(corpus, models, campaign_record, of_record,
                                                                      gates_passed, results, tmp_path, monkeypatch):
    """Design B7c 4, test 1, with the merge (5.1 to 5.6) and its fixes: one record under data/results (OUT_RULE)
    with every section of design 1.4, its confirmatory part at the top level and everything else under opisné
    (proposal 9.1), of the stage and the mark of its run on the ledger of record (generalka, the rehearsal mark) on it
    and on every replay; the gate of its stage asked first; the fit roles read before the seal is consumed and every
    sealed archive only inside the run (5.4); the replays those of safeguard replay --archive, read by agent M's
    metrics inside the run."""
    from safeguard.bundle import load_bundle
    from safeguard.runtime import replay_archive
    from tcn import finalne, pecat
    events, load, check = [], finalne._load_archive, pecat.kontrola

    def recorded(*args, **kwargs):
        decision = check(*args, **kwargs)
        found = decision["sha256"]
        events.append(("check", frozenset([found] if isinstance(found, str) else found or ()),
                       pecat.otvoreny() is not None, kwargs["purpose"]))
        return decision
    monkeypatch.setattr(finalne, "_load_archive",
                        lambda path: events.append(("load", str(path), pecat.otvoreny() is not None)) or load(path))
    monkeypatch.setattr(pecat, "kontrola", recorded)
    assert finalne._hlavny(_argv(corpus, models, campaign_record, tmp_path, **{"--out": results / "record.json"})) == 0
    record = json.loads((results / "record.json").read_text())
    v, p = record["values"], corpus["protocol"]
    o = v["opisné"]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["replays"]
    # Package B11 (ATTACHMENT_RULE): the record and its attachments, nothing else.
    assert sorted(path.name for path in results.iterdir()) == sorted(
        ["record.json", *(f"record.{name}.npz" for name in protocol_v5.ATTACHMENTS)])
    _parts(v, p["analysis"]["seeds"])
    _attachments(v, results / "record.json", corpus)
    # The provenance fields of scripts/check_claims.sh (check E), the stage and the mark of the run (proposal 11.1).
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(record)
    mark = {"stage": "generalka", "rehearsal": True, "mark": pecat.REHEARSAL_MARK}
    assert (record["stage"], v["stage"], record["mark"], v["mark"], v["plan_mode"]) == (
        "generalka", "generalka", mark, mark, "rehearsal")
    assert record["rehearsal"]["mark"] == v["rehearsal"]["mark"] == pecat.REHEARSAL_MARK
    assert gates_passed == [(results, corpus["protocol_path"], "G3a")]
    assert (v["gate"]["stage"], v["gate"]["required"]) == ("generalka", "G3a")
    # One run of the ledger, closed completed after the record; the record's seal is that run.
    entry, = json.loads(of_record.read_text())["values"]["runs"]
    assert (entry["number"], entry["stage"], entry["closed"]["outcome"]) == (1, "generalka", "completed")
    assert (v["seal"]["identity"], v["seal"]["opened"], v["seal"]["closed"], v["seal"]["mark"]) == (
        entry["identity"], entry["opened"], None, mark)
    sealed = {r["features"] for r in corpus["records"] if r["role"] in SEALED}
    sealed_sha = {r["features_sha256"] for r in corpus["records"] if r["role"] in SEALED}
    assert record["n"] == len(sealed) == 8
    # The fit roles before the seal, every sealed archive checked and opened only inside the run (design 5.4), each
    # sealed session loaded right after its check by tcn.pecat kontrola.
    loads = [(i, path, inside) for i, (kind, path, inside, *_) in enumerate(events) if kind == "load"]
    checks = [(shas, inside) for kind, shas, inside, *_ in events if kind == "check"]
    assert {path for _, path, _ in loads} == {r["features"] for r in corpus["records"]}
    assert all(inside == (path in sealed) for _, path, inside in loads)
    sha_of = {r["features"]: r["features_sha256"] for r in corpus["records"]}
    for i, path, _ in loads:
        assert (events[i - 1] == ("check", frozenset([sha_of[path]]), True, "tcn.finalne loads a sealed session")) == (
            path in sealed)
    assert [inside for shas, inside in checks if shas & sealed_sha] and all(
        inside for shas, inside in checks if shas & sealed_sha)
    assert any(not inside for _, inside in checks)  # The fits scored their window sets before the seal.
    # Every replay is safeguard replay --archive's, of the run's seal and mark, and the rows of replay_archive.
    replays = v["replays"]["sessions"]
    assert set(replays) == {r["id"] for r in corpus["records"] if r["role"] in SEALED}
    by_id = {r["id"]: r for r in corpus["records"]}
    for ident, seeds in replays.items():
        assert set(seeds) == {str(seed) for seed in p["analysis"]["seeds"]}
        for item in seeds.values():
            configuration = json.loads((Path(item["directory"]) / "configuration.json").read_text())
            assert configuration["archive_sha256"] == by_id[ident]["features_sha256"]
            seal = configuration["seal"]
            assert (seal["allowed"], seal["stage"], seal["mark"]) == ("final_run", "generalka", pecat.REHEARSAL_MARK)
    first = next(r for r in corpus["records"] if r["role"] == "test_benign")
    directory = Path(replays[first["id"]]["0"]["directory"])
    rows = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
    again = replay_archive(load_bundle(models[0]), first["features"], session_id=first["id"])
    assert [(r["seq"], r["score"], r["alarm_sources"]) for r in rows] == [
        (r["seq"], r["score"], r["alarm_sources"]) for r in again]
    # K1, K2a and K2b decided, each with its wording of analysis.wording.
    for claim in protocol_v5.CLAIMS:
        found = v["conclusions"][claim]
        assert found["outcome"] in protocol_v5.OUTCOMES, (claim, found)
        assert found["wording"] == p["analysis"]["wording"][claim][found["outcome"]]
    # The tables by boot, VM and profile; K1's table by boot holds K1's values.
    k1 = v["claims"]["k1"]
    assert set(o["tables"]["k1"]["boot"]) == set(k1["boots"]) == {"g5-test_benign-1", "g5-test_benign-2"}
    for entry in p["analysis"]["k1"]["compare"]:
        for boot, value in k1["methods"][entry]["values"].items():
            assert o["tables"]["k1"]["boot"][boot]["methods"][entry]["improvement"] == pytest.approx(value)
    assert set(o["tables"]["k1"]["vm"]) == {"a", "b"} and set(o["tables"]["k1"]["profile"]) == {"eshop", "corp"}
    assert set(o["tables"]["k2"]["boot"]["groups"]) == {r["group"] for r in corpus["records"] if r["role"] in SEALED}
    assert set(o["tables"]["k2"]["vm"]["groups"]) == {"a", "b"}
    # O2 to O4 per channel: agent M's metrics on the replays of every seed, read inside the run.
    for name in ("o2", "o3", "o4"):
        assert set(o["metrics"][name]) == {str(seed) for seed in p["analysis"]["seeds"]}
        for found in o["metrics"][name].values():
            assert (found["final_evaluation"], found["rehearsal_mark"], set(found["pecat"]["decisions"].values()),
                    len(found["pecat"]["decisions"]), found["stage"]) == (
                True, pecat.REHEARSAL_MARK, {"final_run"}, 4, "generalka")
    outputs = {"rule", "neural", "kernel_integrity", "union"}  # Every channel of safeguard.runtime and their union.
    assert outputs <= set(o["metrics"]["o2"]["0"]["v5"]["o2"]["total"]) and outputs <= set(
        o["metrics"]["o3"]["0"]["v5"]["o3"]["total"])
    assert o["metrics"]["levels"] == p["analysis"]["metrics"]
    assert o["metrics"]["alpha"] == pytest.approx(1 - p["analysis"]["metrics"]["alarm_rate_interval"]["level"])
    o4 = o["metrics"]["o4"]["0"]["v5"]["o4"]
    planned = [c for r in corpus["records"] if r["role"] == "test_controls"
               for c in json.loads(Path(r["controls"]).read_text())["controls"] if c.get("kind")]
    assert o4["computed"] is True and o4["control"]["total"]["planned"] + o4["negative"]["total"]["planned"] == len(
        planned) == 8
    assert all(outputs <= set(o4[polarity]["total"]) for polarity in ("control", "negative"))
    assert all(o4[polarity]["total"]["neural_over_rule"]["planned"] == o4[polarity]["total"]["planned"]
               for polarity in ("control", "negative"))
    assert sum(len(items) for items in o["metrics"]["controls"]["outcomes"].values()) == 8
    # The summary of every training (question Q11) on dev and calibration, for every bundle the record names.
    assert set(o["training"]) == {str(seed) for seed in p["analysis"]["seeds"]} | {"rule"}
    for model in v["models"]:
        assert {role: (item["schema"], item["role"], item["model"]) for role, item in o["training"][
            str(model["seed"])].items()} == {role: ("hyptcn3/training-summary/1", role, model["label"])
                                             for role in ("dev", "calibration")}
    # The unscored time of safeguard.runtime unscored: every sealed session, a stretch of it nevyhodnotené (the full
    # snapshot at seq 0 and the warmup after it), never left out as silence.
    unscored = o["unscored"]["sessions"]
    assert set(unscored) == set(replays)
    for item in unscored.values():
        stretch = item["stretches"][0]
        assert (stretch["first_seq"], stretch["last_seq"], stretch["status"]) == (0, WINDOW - 1, "nevyhodnotené")
        assert item["seconds"] == sum(s["seconds"] for s in item["stretches"]) > 0
    # The rejected and replaced sessions by cause, the linkage table.
    assert v["campaign"]["by_cause"] == {
        "audit_rejected": {"rejected": 1, "replaced": 1, "not_replaced": 0,
                           "sessions": [{"session": "finalne_03-r", "replacement": "finalne_03-r-r1"}]},
        "capture_incomplete": {"rejected": 1, "replaced": 0, "not_replaced": 1,
                               "sessions": [{"session": "finalne_07-c", "replacement": None}]}}
    assert o["linkage"] == p["analysis"]["linkage"]
    # Every pre-registered model and method: M at every seed, Z0 to Z5, the descriptive methods at their seeds.
    assert [m["seed"] for m in v["models"]] == p["analysis"]["seeds"]
    matched = {**v["matched"], **o["descriptive_methods"]["matched"]}
    assert _names(matched) == {"M", "Z0", "Z1", "Z2", "Z3", "Z4", "Z5", "zscore", "iforest", "gru", "lstm"}
    assert all(set(found["rates"]) == {"calibration", *SEALED} for found in matched.values())
    for section in ("budget", "k2_values", "interventions"):
        assert v[section], section
    for section in ("z0_random", "losses", "diagnostics"):
        assert o[section], section


def test_a_null_m_is_refused_before_the_seal_is_consumed(corpus, models, campaign_record, ledger, tmp_path, capsys):
    """Design B7c 4, test 2: an index whose protocol has analysis.k2b.m null (the bound of G1) is refused by name,
    and nothing is consumed, read, replayed or written."""
    from tcn import finalne
    doc = json.loads(corpus["index"].read_text())
    doc["protocol_config"]["analysis"]["k2b"]["m"] = None
    index = tmp_path / "corpus.json"
    index.write_text(json.dumps(doc))
    before = ledger.read_bytes()
    argv = _argv(corpus, models, campaign_record, tmp_path, **{"--corpus": index})
    assert finalne._hlavny(argv) == 2
    assert capsys.readouterr().err == ("tcn.finalne: analysis.k2b.m is null: the bound m is determined in G1 "
                                       "(determined_at), and the final evaluation decides no claim without it; "
                                       "refused before the seal is consumed\n")
    assert ledger.read_bytes() == before and sorted(p.name for p in tmp_path.iterdir()) == ["corpus.json"]


def test_a_diagnostic_bundle_is_refused(corpus, models, campaign_record, ledger, gates_passed, tmp_path, capsys):
    """Design B7c 4, test 3: a bundle whose manifest says diagnostic true is refused by name before it is loaded and
    before the seal is consumed."""
    import shutil
    from tcn import finalne
    diagnostic = tmp_path / "seed-4-diagnostic"
    shutil.copytree(models[4], diagnostic)
    manifest = json.loads((diagnostic / "manifest.json").read_text())
    (diagnostic / "manifest.json").write_text(json.dumps(dict(manifest, diagnostic=True)))
    before = ledger.read_bytes()
    argv = _argv(corpus, models, campaign_record, tmp_path, **{"--models": [*models[:4], diagnostic]})
    assert finalne._hlavny(argv) == 2
    assert capsys.readouterr().err == (f"tcn.finalne: bundle {diagnostic} is diagnostic (manifest diagnostic True): "
                                       "the final evaluation takes the production bundles of M at analysis.seeds "
                                       "only (design B7c 1.4)\n")
    assert ledger.read_bytes() == before and not (tmp_path / "record.json").exists()


@pytest.mark.parametrize("where", ["same_index", "copy_elsewhere", "re_extracted"])
def test_a_second_run_is_refused(where, campaign_corpus, ledger, tmp_path, capsys):
    """Design B7c 4, test 4, and the skeleton's B7c row: after the seal of a campaign was consumed (tcn.pecat
    spotrebuj, the run of the first final command), the final command refuses a second run by name before anything is
    computed or read (tcn.pecat stav, design 5.4), also through a byte-identical copy of the index under another path
    (the seal is the identity of the sealed archives, not a path) and through an index whose sealed session has an
    archive of other bytes, a re-extraction (agent S's fix of finding F8: the seal binds the sessions; that archive is
    also not in the ledger); the ledger keeps the one run (here a dry run, stage suchy: the error of proposal 10.2 is
    refused there as well)."""
    from tcn import finalne, pecat
    pecat.zapis_korpus(campaign_corpus["index"], command="the test's campaign (package B9)", ledger=ledger)
    pecat.spotrebuj(campaign_corpus["index"], out=tmp_path / "first.json", command="the first final run",
                    ledger=ledger).close()
    first, = json.loads(ledger.read_text())["values"]["runs"]
    index = campaign_corpus["index"]
    if where == "copy_elsewhere":
        index = tmp_path / "elsewhere" / "corpus.json"
        index.parent.mkdir()
        index.write_bytes(campaign_corpus["index"].read_bytes())
    seal = f"its seal was consumed by the final run 1 of seal {first['identity']}"
    tail = ""
    if where == "re_extracted":
        doc = json.loads(campaign_corpus["index"].read_text())
        record = next(r for r in doc["sessions"] if r["role"] == "test_benign")
        archive = tmp_path / "re-extracted" / "audit_test.npz"
        archive.parent.mkdir()
        archive.write_bytes(Path(record["features"]).read_bytes() + b"\0")
        record.update(features=str(archive), features_sha256=_sha(archive))
        index = archive.parent / "corpus.json"
        index.write_text(json.dumps(doc))
        seal = f"its sessions were in the final run 1 of seal {first['identity']}"
        tail = (" (the seal binds the sessions, tcn/pecat.py RUN_RULE); the ledger does not hold the archives of the "
                f"sessions {record['id']} (the campaign writes them, tcn/pecat.py zapis)")
    out = tmp_path / "out"
    out.mkdir()
    before = ledger.read_bytes()
    argv = ["--corpus", str(index), "--models", str(tmp_path / "not-read"), "--campaign",
            str(tmp_path / "not-read.json"), "--replays", str(out / "replays"), "--out", str(out / "record.json")]
    assert finalne._hlavny(argv) == 2
    assert capsys.readouterr().err == (
        f"tcn.finalne: {index.resolve()}: the seal of the corpus cannot be consumed on the ledger {ledger.resolve()} "
        f"({seal} opened {first['opened']['date']} (out {first['out']}): a second final run is refused{tail}); refused "
        "before anything is computed (tcn.pecat stav, RUN_RULE)\n")
    assert ledger.read_bytes() == before and sorted(path.name for path in out.iterdir()) == []


def test_the_gate_records_are_required_before_the_seal_is_consumed(campaign_corpus, of_record, results, tmp_path,
                                                                    capsys):
    """Design B7c 5.3 (question Q16, GATE_RULE): a final run of stage final (a campaign on the ledger of record) asks
    scripts/gates.py require for G6 with the protocol file of the index, and without valid gate records of G0 to G5
    (the test's results hold none) it is refused by name before the seal is consumed: the ledger holds no run and
    nothing is written."""
    from scripts import gates
    from tcn import finalne, pecat
    pecat.zapis_korpus(campaign_corpus["index"], command="the test's campaign (package B9)", ledger=of_record)
    row = next(r for r in gates.status(results, campaign_corpus["protocol_path"])
               if r["stage"] in gates.STAGES[:gates.STAGES.index("G6")] and not r["passed"])
    before = of_record.read_bytes()
    argv = ["--corpus", str(campaign_corpus["index"]), "--models", str(tmp_path / "not-read"), "--campaign",
            str(tmp_path / "not-read.json"), "--replays", str(tmp_path / "replays"), "--out",
            str(results / "record.json")]
    assert finalne._hlavny(argv) == 2
    assert capsys.readouterr().err == (
        f"tcn.finalne: the gate records do not admit a final run of stage final (G6 needs every stage before it "
        f"valid; scripts/gates.py require, {results}): stage {row['stage']} is not valid: "
        + "; ".join(row["problems"]) + "; refused before the seal is consumed (GATE_RULE)\n")
    assert of_record.read_bytes() == before and sorted(path.name for path in tmp_path.iterdir()) == []
    assert sorted(path.name for path in results.iterdir()) == []


def test_a_failure_before_the_seal_consumes_nothing_and_writes_nothing(corpus, models, campaign_record, ledger,
                                                                       gates_passed, tmp_path, monkeypatch, capsys):
    """Design B7c 5.4: the fits run before the seal is consumed, so a step that fails there (here the fits of the
    methods) leaves the ledger without a run and as it was, and writes no record and no replay."""
    from tcn import finalne

    def fails(*args, **kwargs):
        raise ValueError("the test's failure of a fit")
    monkeypatch.setattr(finalne, "fit_methods", fails)
    before = ledger.read_bytes()
    assert finalne._hlavny(_argv(corpus, models, campaign_record, tmp_path)) == 2
    assert capsys.readouterr().err == "tcn.finalne: the test's failure of a fit\n"
    assert ledger.read_bytes() == before and json.loads(before)["values"]["runs"] == []
    assert sorted(path.name for path in tmp_path.iterdir()) == []


def test_a_failure_after_the_consumption_leaves_its_record(corpus, models, campaign_record, ledger, gates_passed,
                                                           tmp_path, tmp_path_factory, monkeypatch):
    """tcn/finalne.py FAILURE_RULE, through the Python entry with a ledger of its own (design 5.1: the guards read it
    for the whole run, tcn.pecat vlastna_kniha): a step that fails after the seal is consumed (here the outcomes of
    the controls of the first session of test_controls) leaves the record of the one final run in `out`, of status
    failed, with the step, the error and the seal, of stage suchy and the mark of a dry run; the run closes failed in
    that ledger, and the ledger of the process is as it was."""
    from tcn import finalne, pecat

    def fails(session, protocol, stage):
        raise ValueError("the test's failure of the outcomes of a control")
    monkeypatch.setattr(finalne, "control_outcomes", fails)
    own = tmp_path_factory.mktemp("own") / "kniha_pecati.json"
    pecat.zaloz(command="a dry run's own ledger", ledger=own)
    before = ledger.read_bytes()
    with pytest.raises(ValueError) as error:
        finalne.evaluate(corpus["index"], models, campaign=campaign_record, replays=tmp_path / "replays",
                         out=tmp_path / "record.json", ledger=own)
    assert str(error.value) == "the test's failure of the outcomes of a control"
    record = json.loads((tmp_path / "record.json").read_text())
    v = record["values"]
    assert {"commit", "date", "host", "guest", "command", "n"} <= set(record)
    mark = {"stage": "suchy", "rehearsal": True, "mark": pecat.DRY_MARK}
    assert (v["status"], v["failed_step"], v["error"], record["stage"], v["stage"], record["mark"], v["mark"]) == (
        "failed", "3: the outcomes of the controls", "ValueError: the test's failure of the outcomes of a control",
        "suchy", "suchy", mark, mark)
    entry, = json.loads(own.read_text())["values"]["runs"]
    assert (v["seal"]["identity"], v["seal"]["ledger"]) == (entry["identity"], str(own.resolve()))
    assert set(v) == FAILED and v["opisné"] == {}  # Proposal 9.1: the failed record has the descriptive key, empty.
    assert gates_passed == [(finalne.RESULTS, corpus["protocol_path"], "G1")]  # GATE_RULE: a dry run asks for G1.
    assert v["rehearsal"]["mark"] == pecat.REHEARSAL_MARK  # The corpus is a rehearsal; its run is a dry run.
    assert (entry["stage"], entry["closed"]["outcome"], entry["closed"]["error"]) == (
        "suchy", "failed", "ValueError: the test's failure of the outcomes of a control")
    assert pecat.KNIHA == ledger and ledger.read_bytes() == before and pecat.otvoreny() is None
    # Package B11 (ATTACHMENT_RULE): a failed record names no attachment, and none lies beside it.
    assert not any(path.exists() for path in finalne.attachment_paths(tmp_path / "record.json").values())


def test_a_failure_while_the_attachments_are_written_leaves_none(corpus, models, campaign_record, ledger,
                                                                gates_passed, tmp_path, tmp_path_factory,
                                                                monkeypatch):
    """Package B11 (tcn/finalne.py ATTACHMENT_RULE and FAILURE_RULE): a dry run on a ledger of its own (stage suchy)
    writes its attachments beside its own record, outside data/results, as <record stem>.<name>.npz in the order of
    the protocol's list; when the second fails (the test's error in numpy.savez_compressed), the run removes the
    attachments it wrote, writes its failed record at step 4, which names none, and closes failed; only the record
    lies in its directory."""
    from tcn import finalne, pecat
    real, seen = np.savez_compressed, []

    def fails_second(stream, **arrays):
        seen.append(Path(stream.name))
        if len(seen) == 2:
            raise OSError("the test's failure of the attachment losses")
        return real(stream, **arrays)
    monkeypatch.setattr(np, "savez_compressed", fails_second)
    own = tmp_path_factory.mktemp("own-attachments") / "kniha_pecati.json"
    pecat.zaloz(command="a dry run's own ledger", ledger=own)
    out = tmp_path / "dry" / "record.json"
    out.parent.mkdir()
    with pytest.raises(OSError, match="^the test's failure of the attachment losses$"):
        finalne.evaluate(corpus["index"], models, campaign=campaign_record, replays=tmp_path / "replays", out=out,
                         ledger=own)
    assert seen == [out.with_name(f"record.{name}.npz") for name in ("series", "losses")]
    v = json.loads(out.read_text())["values"]
    assert (v["status"], v["failed_step"], v["error"], v["stage"]) == (
        "failed", "4: the attachments", "OSError: the test's failure of the attachment losses", "suchy")
    assert set(v) == FAILED and sorted(path.name for path in out.parent.iterdir()) == ["record.json"]
    entry, = json.loads(own.read_text())["values"]["runs"]
    assert (entry["stage"], entry["closed"]["outcome"]) == ("suchy", "failed") and pecat.otvoreny() is None


@pytest.mark.parametrize("option", ["--stage", "--ledger"])
def test_the_command_line_takes_no_stage_and_no_ledger(option, corpus, campaign_record, tmp_path, capsys):
    """Design B7c 5.1 (question Q15): the stage of the record is the stage of its run on its ledger, and the command
    line runs on the ledger of record: it has no option of either, refused before anything is read."""
    from tcn import finalne
    with pytest.raises(SystemExit) as error:
        finalne._hlavny(_argv(corpus, [tmp_path / "not-read"], campaign_record, tmp_path) + [option, "final"])
    assert error.value.code == 2 and f"unrecognized arguments: {option} final" in capsys.readouterr().err


# ------------------------------------------------------------------ the fix round of B7c (findings F2, F3, F6, F7 and
# the mutants F5 to F8 of its verification)


def test_a_campaign_runs_the_final_command_end_to_end_at_stage_final(campaign_corpus, campaign_models,
                                                                    campaign_record_campaign, of_record, gates_passed,
                                                                    results, tmp_path, monkeypatch, capsys):
    """Finding F3: the final command end to end in plan mode campaign at stage final, on a protocol whose
    analysis.interventions.boots are the carrier boots of the index, as the verifier's probe: the ledger of record
    (patched), its seal at HEAD (_in_git true), the gate records (scripts.gates.require patched: G6 asked) and a
    committed tree of code (tcn.eval._git_stav: the working tree of the test is not the subject; the refusal of a
    changed tree is test_a_refusal_before_the_seal_consumes_nothing[dirty_tree]). One complete record under
    data/results (OUT_RULE) of the parts of proposal 9.1 and FINAL_MARK, the run closed completed; after it a second
    run, a read of its replays by tcn.eval and a replay of a sealed archive are refused by name."""
    from safeguard.bundle import load_bundle
    from safeguard.runtime import replay_archive
    from tcn import eval as ev
    from tcn import finalne, pecat
    monkeypatch.setattr(ev, "_git_stav", lambda: ("0" * 40, []))
    pecat.zapis_korpus(campaign_corpus["index"], command="the test's campaign (package B9)", ledger=of_record)
    out = results / "record.json"
    argv = _argv(campaign_corpus, campaign_models, campaign_record_campaign, tmp_path, **{"--out": out})
    assert finalne._hlavny(argv) == 0
    record, p = json.loads(out.read_text()), campaign_corpus["protocol"]
    v = record["values"]
    mark = {"stage": "final", "rehearsal": False, "mark": pecat.FINAL_MARK}
    assert (record["stage"], v["stage"], record["mark"], v["mark"], v["status"], v["plan_mode"], v["rehearsal"]) == (
        "final", "final", mark, mark, "complete", "campaign", None)
    assert gates_passed == [(results, campaign_corpus["protocol_path"], "G6")]
    entry, = json.loads(of_record.read_text())["values"]["runs"]
    assert (entry["stage"], entry["mode"], entry["seal_in_git"], entry["closed"]["outcome"]) == (
        "final", "campaign", True, "completed")
    sessions = [{"plan": p["name"], "role": r["role"], "session": r["id"]}
                for r in sorted(campaign_corpus["records"], key=lambda r: r["id"]) if r["role"] in SEALED]
    assert v["seal"]["sessions"] == entry["sessions"] == sessions  # Agent S's F8: the run records its sessions.
    _parts(v, p["analysis"]["seeds"])
    _attachments(v, out, campaign_corpus)  # Package B11 (ATTACHMENT_RULE).
    for claim in protocol_v5.CLAIMS:
        found = v["conclusions"][claim]
        assert found["outcome"] in protocol_v5.OUTCOMES, (claim, found)
        assert found["wording"] == p["analysis"]["wording"][claim][found["outcome"]]
    assert len(v["k2_values"]["boots"]) == p["analysis"]["interventions"]["boots"] == 4  # K2 took every boot.
    capsys.readouterr()
    second = tmp_path / "second"
    second.mkdir()
    assert finalne._hlavny(_argv(campaign_corpus, campaign_models, campaign_record_campaign, second,
                                 **{"--out": results / "second.json"})) == 2
    assert capsys.readouterr().err == (
        f"tcn.finalne: {campaign_corpus['index'].resolve()}: the seal of the corpus cannot be consumed on the ledger "
        f"{of_record.resolve()} (its seal was consumed by the final run 1 of seal {entry['identity']} opened "
        f"{entry['opened']['date']} (out {entry['out']}): a second final run is refused); refused before anything is "
        "computed (tcn.pecat stav, RUN_RULE)\n")
    benign = [r for r in campaign_corpus["records"] if r["role"] == "test_benign"]
    replays = [v["replays"]["sessions"][r["id"]]["0"]["directory"] for r in benign]
    with pytest.raises(pecat.Zapecatene) as error:
        ev.vyhodnot_far(str(campaign_corpus["index"]), "test_benign", replays, final_evaluation=True)
    assert str(error.value).startswith(f"tcn.eval far: refused, the archive of the replay {replays[0]} is sealed")
    with pytest.raises(pecat.Zapecatene) as error:
        replay_archive(load_bundle(campaign_models[0]), benign[0]["features"])
    assert str(error.value).startswith("safeguard.runtime.replay_archive: refused, the archive "
                                       f"{benign[0]['features']} is sealed")


REFUSALS = ["carrier_boots", "out_outside_results_final", "out_outside_results_generalka", "replays_in_results",
            "dirty_tree", "campaign_record_of_another_corpus", "attachment_exists", "replays_at_an_attachment"]


@pytest.mark.parametrize("case", REFUSALS)
def test_a_refusal_before_the_seal_consumes_nothing(case, corpus, campaign_corpus, campaign_record, ledger,
                                                    gates_passed, results, request, tmp_path, monkeypatch, capsys):
    """Refusals of step 0 (ORDER_RULE), before the seal is consumed and without a session read: BOOTS_RULE (finding F3:
    in plan mode campaign the carrier boots of the index against analysis.interventions.boots), OUT_RULE (finding F7:
    the record of a run of stage final or generalka under data/results), REPLAY_RULE (the replays outside it),
    CLEAN_TREE_RULE at stage final and CAMPAIGN_RULE (a campaign record of another corpus); the three before the last
    pin rules the merge already had (the mutants F6, F5 and F7 of the verification); package B11 (ATTACHMENT_RULE): an
    attachment of the record that exists already, and replays at the path of an attachment. The ledger keeps its bytes
    and nothing is written."""
    from tcn import finalne, pecat
    target = corpus if case == "out_outside_results_generalka" else campaign_corpus
    index, out, replays, campaign = target["index"], results / "record.json", tmp_path / "replays", campaign_record
    if target is campaign_corpus:  # Package B9b (F7): the record of the complete ending of that corpus.
        campaign = request.getfixturevalue("campaign_record_campaign")
    if target is campaign_corpus:
        pecat.zapis_korpus(index, command="the test's campaign (package B9)", ledger=ledger)
    if case not in ("replays_in_results", "campaign_record_of_another_corpus"):  # Stage final or generalka.
        request.getfixturevalue("of_record")
    stage = "generalka" if target is corpus else "final"
    if case == "carrier_boots":
        doc = json.loads(index.read_text())
        doc["protocol_config"]["analysis"]["interventions"]["boots"] = 20
        index = tmp_path / "corpus.json"
        index.write_text(json.dumps(doc))
        reason = (f"{index.resolve()}: the carrier roles of the index hold 4 boots (test_benign 2, test_controls 2), "
                  "analysis.interventions.boots is 20: K2 takes every boot of the plan (tcn/k2.py k2_values), so the "
                  "protocol and the index disagree; refused before the seal is consumed (BOOTS_RULE)")
    elif case.startswith("out_outside_results"):
        out = tmp_path / "record.json"
        reason = (f"--out {out}: the record of a run of stage {stage} lies in {results.resolve()} (OUT_RULE); refused "
                  "before the seal is consumed")
    elif case == "replays_in_results":
        replays = results / "replays"
        reason = f"--replays {replays} lies in {results.resolve()}: the replays stay outside the tracked results"
    elif case == "dirty_tree":
        from tcn import eval as ev
        monkeypatch.setattr(ev, "_git_stav", lambda: ("0" * 40, ["tcn/finalne.py"]))
        reason = "the final evaluation of stage final needs git and a committed tree of code: changed tcn/finalne.py"
    elif case == "attachment_exists":
        existing = results / "record.series.npz"
        existing.write_bytes(b"an earlier attachment")
        reason = (f"--out {out}: its attachment series {existing} exists; the final evaluation writes a new one "
                  "(ATTACHMENT_RULE)")
    elif case == "replays_at_an_attachment":
        replays = results / "record.losses.npz"
        reason = f"--replays {replays} is the attachment losses of --out {out} (ATTACHMENT_RULE)"
    else:
        doc = json.loads(campaign.read_text())
        doc["values"]["accepted_sessions"] -= 1
        campaign = tmp_path / "campaign.json"
        campaign.write_text(json.dumps(doc))
        reason = (f"{campaign.resolve()}: the campaign record names {len(target['records']) - 1} accepted sessions, "
                  f"the corpus index holds {len(target['records'])}: it is not the record of this corpus")
    before = ledger.read_bytes()
    argv = ["--corpus", str(index), "--models", str(tmp_path / "not-read"), "--campaign", str(campaign),
            "--replays", str(replays), "--out", str(out)]
    assert finalne._hlavny(argv) == 2
    assert capsys.readouterr().err == f"tcn.finalne: {reason}\n"
    assert ledger.read_bytes() == before and pecat.otvoreny() is None
    assert not out.exists() and not replays.exists()
    if case == "attachment_exists":  # Package B11: the earlier file is never overwritten.
        assert existing.read_bytes() == b"an earlier attachment"


@pytest.mark.parametrize("case", ["neural_adds", "rule_carries_all"])
def test_the_wording_of_the_rule_channel_is_filled_with_the_increment(case):
    """Finding F6 (proposal 8.2, question Q6): the wording the bundles carry (safeguard/training.py RULE_CHANNEL_ONLY)
    with its ellipsis filled by the median over the seeds of the increment of the neural channel over the rule
    channel in the total of the planned controls, and the flag of all detection carried by the rule channel: false
    when the neural channel adds detections (median 0.25), true when the increment is 0 while the rule channel
    detects."""
    from safeguard.training import RULE_CHANNEL_ONLY
    from tcn import finalne
    increments = {"neural_adds": [0.125, 0.25, 0.25, 0.375, 0.5], "rule_carries_all": [0.0] * 5}[case]
    o4 = {seed: {"computed": True, "control": {"total": {"neural_over_rule": {
        "planned": 8, "rule": 2, "rule_or_neural": 2 + round(8 * x), "neural_not_rule": round(8 * x), "share": x,
        "status": "evaluated"}}}} for seed, x in enumerate(increments)}
    manifests = [{"analysis_wording": {"rule_channel_only": dict(RULE_CHANNEL_ONLY)}} for _ in increments]
    found = finalne.rule_channel_only(manifests, o4)
    value = {"neural_adds": 0.25, "rule_carries_all": 0.0}[case]
    assert found["text"] == RULE_CHANNEL_ONLY["text"].replace("…", {"neural_adds": "0.25", "rule_carries_all": "0"}[
        case])
    assert (found["increment"]["median"], found["all_detection_by_rule_channel"]) == (
        value, case == "rule_carries_all")
    assert found["wording"] == RULE_CHANNEL_ONLY and found["increment"]["per_seed"]["1"]["neural_not_rule"] == round(
        8 * increments[1])
