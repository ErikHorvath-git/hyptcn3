"""Completeness of the corpus read from the plan (protocol v5, package B6a; design NAVRH_B6a sections 1.2, 1.3, 3).

The skeleton's addendum (dokazy/B6/kostra/KOSTRA.md): a corpus of the v5 shape passes the index build and the
production check of training, and a group with a planned session missing is refused by both. The corpus here has
the v5 shape: groups of 3 sessions holding 3 of the 4 scenarios, the five roles of v5 with test_controls, two VMs and
the two test roles interleaved in time. Its sessions are planned by scripts/protocol_v5.py plan, accepted by the
audit's own code (collection.analyze_windows) and recorded as tcn/tests/test_odovzdanie_korpusu.py records them, so
the index passes safeguard.training.validate_index without diagnostic. The expected side comes from the plan and
from this file's own record of the session times, never from the code under test.

Names that package B6a adds are imported inside the tests, so this file collects on the code before it. Only
mechanics on synthetic rows; no number here is a detection result (HONESTY P4).
"""
from collections import Counter
import json
from pathlib import Path
import re
from types import SimpleNamespace

import numpy as np
import pytest

from features.archive import save
from features.snapshot import MENA, SCHEMA
from scripts import campaign, collection, protocol_v5

NAME = "plan-b6a-test"
CYCLES, FULL_EVERY, WINDOW, INTERVAL, GAP = 96, 64, 8, 5, 7.5
WINDOWS = (FULL_EVERY - WINDOW) + (CYCLES - FULL_EVERY - WINDOW)  # 80 windows of a clean session, two chains
FPR = .05  # Production training needs max(100, ceil(10 / FPR)) = 200 calibration windows; the corpus has 6 * 80.
SCENARIOS = ("eshop_low", "eshop_high", "corp_low", "corp_high")  # In the order of config/collection-v5.json.
GROUPS = {"train": 2, "dev": 2, "calibration": 2, "test_benign": 2, "test_controls": 2}  # Every role on both VMs.
FIT = ("train", "dev", "calibration")  # The roles training loads.
# The time order of the plan (proposal 7.3): a lane per rank, the two test roles share one. The sessions of a VM
# follow each other in its lane; VM b starts a minute after VM a, so no two sessions start at once.
RANK = {"train": 0, "dev": 1, "calibration": 2, "test_benign": 3, "test_controls": 3}
BASE, LANE_S, SLOT_S, VM_S = 1700000000., 4000, 600, {"a": 0, "b": 60}
LAYOUT = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[i, 4096] for i in range(3)],
          "regions": [{"gpa": 0, "bytes": 50331648}], "memsize": 50331648, "vcpus": 2}
GOOD = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "truncated_traversals": [],
        "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0, "process_walk": "next"}


def protocol_doc(profile, scenarios=SCENARIOS):
    """A schema-3 protocol of the v5 shape (the v5 sections of scripts/tests/boundary_sessions.py v5_sections): groups
    of 3 sessions, two groups in every role, two VMs, the test roles interleaved. A session lasts 8 minutes: no event
    is planned and a session of test_controls holds one control of 30 to 60 s; the rehearsal has one group per role."""
    from scripts.tests.boundary_sessions import audit_sections, fit_analysis, v5_sections
    v5 = v5_sections(scenarios, GROUPS, group_sessions=3, window_rows=WINDOW)
    # The one production training of this file takes its parameters from the analysis plan (package B6b).
    v5["analysis"] = fit_analysis(v5["analysis"], fpr=FPR, max_epochs=1, batch_size=64)
    return {**v5, **audit_sections(INTERVAL), "schema": "hyptcn3/collection-protocol/3", "name": NAME,
            "quality_policy": "behavioral-inputs-v1", "profile": str(profile), "interval_s": INTERVAL,
            "max_gap_s": GAP, "bin_bytes": 16777216, "window_rows": WINDOW, "stride": 1, "full_every": FULL_EVERY,
            "cycles": CYCLES, "pilot_cycles": CYCLES, "min_score_coverage": .7,
            "invalid_rows": {"max": 1, "traversals": ["processes"]},
            "vms": [{"name": "a", "domain": "hyptcn-test-a", "port": 28080},
                    {"name": "b", "domain": "hyptcn-test-b", "port": 28081}],
            "group_prefix": "v5-", "roles": dict(GROUPS), "interleave": [["test_benign", "test_controls"]],
            "events": dict(v5["events"], first_s=60, min_gap_s=60, tail_s=60, grace_s=10, duration_s=[30, 60]),
            "controls": dict(v5["controls"], slots_per_session=1, min_duration_s=30, duration_s=[30, 60]),
            "rehearsal": dict(v5["rehearsal"], groups_per_role=1)}


def label(place):
    return f"{place['group']}#{place['position']}"


def extraction(sid, t0, level, seed):
    """Extraction result of one clean session (features.snapshot.retazec shape), values as safeguard.demo: the
    scenario sets their level."""
    rng = np.random.default_rng(seed)
    t = np.arange(CYCLES)
    full = t % FULL_EVERY == 0
    matrix = np.zeros((CYCLES, len(MENA)))
    matrix[:, :8] = np.clip(.02 + .08 * level + rng.normal(0, .005, (CYCLES, 8)), 0, 1)
    matrix[:, 8:18] = 20 + 10 * level + rng.integers(0, 5, (CYCLES, 10))
    matrix[:, MENA.index("ma_predchodcu")] = ~full
    matrix[full, MENA.index("je_plna")] = 1
    for name in ("proc_new", "proc_gone", "mod_delta"):  # No difference without a predecessor.
        matrix[full, MENA.index(name)] = 0
    local = np.zeros((CYCLES, len(LAYOUT["bins"]), 4))
    local[:, :, 0] = np.clip(.02 + .08 * level + rng.normal(0, .01, local.shape[:2]), 0, 1)
    local[:, :, 1] = rng.uniform(.1, .3, local.shape[:2])
    local[:, :, 3] = local[:, :, 0] > 0
    local[:, :, 2] = np.clip(4 + level + rng.normal(0, .1, local.shape[:2]), 0, 8) * local[:, :, 3]
    return {"schema": SCHEMA, "mena": MENA, "matica": matrix.tolist(), "perbin": local.tolist(),
            "seq": t.tolist(), "casy": [t0 + INTERVAL * i for i in t.tolist()], "valid": [True] * CYCLES,
            "quality": [dict(GOOD) for _ in t], "quality_policy": "behavioral-inputs-v1",
            "biny": [b for b, _ in LAYOUT["bins"]], "chain_ids": [f"{sid}-chain-{i // FULL_EVERY}" for i in t.tolist()],
            "snimky": [f"synthetic-{i}" for i in t.tolist()], "trvanie_s": [0.] * CYCLES,
            "poznamky": [[] for _ in t], "layout": LAYOUT, "max_medzera_s": GAP}


def session(root, c, place, sid, t0):
    """One accepted session at `place` (a plan row or a dict like it) as a closed campaign leaves it: session.json,
    events.json, the feature archive and the audit record collection.audit_session writes from analyze_windows.
    Returns the audit."""
    directory = Path(root) / sid
    directory.mkdir(parents=True)
    collection.write_json(directory / "session.json", {
        "schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": NAME, "vm": place["vm"],
        "role": place["role"], "group": place["group"], "group_attempt": 1, "scenario": place["scenario"],
        "typ": "benign", "seed": place["seed"], "cycles": CYCLES,
        "guest_before": {"boot_id": "boot-" + place["group"], "kernel": "6.1.0-test", "stack_sha256": "5" * 64},
        "events": place.get("events", []), "event_grace_s": c.p["events"]["grace_s"],
        **({"controls": place["controls"]} if "controls" in place else {}),
        "protocol_sha256": c.sha, "collector_sha256": "c" * 64,
        "profile_sha256": {"symbols.txt": collection.digest(c.profile / "symbols.txt")}})
    # A schema-3 session lists its events (none are planned here) and keeps events.json, which build indexes.
    collection.write_json(directory / "events.json", {"schema": "hyptcn3/session-events/1", "events": [],
                                                      "note": "synthetic record of the test"})
    if place["role"] == "test_controls":  # Package B7c: build hashes it (its log audit refuses a session without it).
        collection.write_json(directory / "controls.json", {"schema": protocol_v5.CONTROLS_SCHEMA, "controls": [],
                                                            "note": "synthetic record of the test"})
    result = extraction(sid, t0, SCENARIOS.index(place["scenario"]), place["seed"])
    rows, _, verdict, quality = collection.analyze_windows(result, c.p, sid, place["role"])
    assert verdict["reasons"] == [] and verdict["windows"] == WINDOWS, (sid, verdict["reasons"])
    archive = save(directory / "features.npz", result)
    meta_sha = collection.digest(directory / "session.json")
    audit = directory / "audit.json"
    collection.write_json(audit, {"schema": "hyptcn3/collection-audit/1", "n": len(rows), "values": {
        "accepted": True, "reasons": [], "role": place["role"], "protocol_sha256": c.sha,
        "snapshots": verdict["snapshots"], "windows": verdict["windows"], "score_coverage": verdict["score_coverage"],
        "acceptance": verdict, "coverage": quality.pop("coverage", None),
        "logs": {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True, "problems": [],
                 "sections": {"metadata": {"session_sha256": meta_sha}}},
        "quality": quality, "session_sha256": meta_sha, "extractor_sha256": c.extractor,
        "features": str(archive), "features_sha256": collection.digest(archive), "layout": LAYOUT,
        "session_dir": str(directory)}})
    c.times[sid] = (t0, t0 + INTERVAL * (CYCLES - 1))
    return audit


def make_corpus(root, mode):
    """Accepted sessions of the plan of `mode`: c.plan (the plan's sessions), c.sids and c.audits by label, c.times."""
    root.mkdir(parents=True)
    profile = root / "profile"
    profile.mkdir()
    (profile / "symbols.txt").write_text("synthetic profile\n")
    path = root / "protocol.json"
    collection.write_json(path, protocol_doc(profile))
    c = SimpleNamespace(root=root, path=path, p=collection.protocol(path), sha=collection.digest(path), mode=mode,
                        profile=profile, extractor=campaign.extractor_hashes(), times={}, sids={}, audits={})
    c.plan = protocol_v5.plan(c.p, mode)["sessions"]
    slots = Counter()
    for i, place in enumerate(c.plan):
        lane = RANK[place["role"]], place["vm"]
        t0 = BASE + lane[0] * LANE_S + VM_S[place["vm"]] + slots[lane] * SLOT_S
        slots[lane] += 1
        c.sids[label(place)] = sid = f"{mode}-{i + 1:02d}-{place['vm']}-{place['role']}-{place['scenario']}"
        c.audits[label(place)] = session(root / "sessions", c, place, sid, t0)
    return c


@pytest.fixture(scope="module", autouse=True)
def _threads():
    """Two torch threads for the one training of this file (as tcn/tests/test_odovzdanie_korpusu.py)."""
    import torch
    before = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(before)


@pytest.fixture(scope="module")
def campaign_corpus(tmp_path_factory):
    return make_corpus(tmp_path_factory.mktemp("plan") / "campaign", "campaign")


@pytest.fixture(scope="module")
def rehearsal_corpus(tmp_path_factory):
    return make_corpus(tmp_path_factory.mktemp("plan") / "rehearsal", "rehearsal")


def build(c, audits=None, mode=None):
    """features/dataset.py build as finish_corpus calls it, by default with the corpus's audits and mode."""
    from features import dataset
    return dataset.build(list(c.audits.values()) if audits is None else audits, c.p, c.sha, mode=mode or c.mode)


def write_index(c, doc, path):
    path.write_text(json.dumps(dict(doc, protocol=str(c.path))))
    return path


def refused(reason):
    return pytest.raises(ValueError, match="^" + re.escape(reason) + "$")


def named(place, sid=None):
    """A session (its id) or a planned row (its label) as the refusals name it, with role, group, scenario and VM."""
    return f"{sid or label(place)} ({place['role']}, {place['group']}, {place['scenario']}, VM {place['vm']})"


def record_of(c, audit, position):
    """The index record of an accepted audit with the fields build writes (features/dataset.py), for an index build
    would not write."""
    v = json.loads(Path(audit).read_text())["values"]
    meta_path = Path(v["session_dir"]) / "session.json"
    m = json.loads(meta_path.read_text())
    start, end = c.times[m["session_id"]]
    return {"id": m["session_id"], "role": m["role"], "group": m["group"], "vm": m["vm"],
            "boot_id": m["guest_before"]["boot_id"], "kernel": m["guest_before"]["kernel"], "typ": m["typ"],
            "guest": m["guest_before"], "collector_sha256": m["collector_sha256"], "protocol_sha256": c.sha,
            "session": str(meta_path.resolve()), "session_sha256": collection.digest(meta_path),
            "scenario": m["scenario"], "position": position, "seed": m["seed"], "start": start, "end": end,
            "audit": str(Path(audit).resolve()), "audit_sha256": collection.digest(audit),
            "features": str(Path(v["features"]).resolve()), "features_sha256": v["features_sha256"],
            "log_audit": "not repeated"}


def finish_setup(c, root, monkeypatch):
    """A campaign directory for scripts/campaign.py finish_corpus: its protocol and a manifest; the archive mount and
    the copy to the archive are replaced (the copies are recorded). The production check runs as the campaign runs
    it."""
    directory = root / "campaign"
    (directory / "events").mkdir(parents=True)
    (directory / "protocol.json").write_bytes(c.path.read_bytes())
    manifest = {"protocol_sha256": c.sha, "archive_root": str(root / "archive"), "archive_mount": None,
                "archive_dir": str(root / "archive" / "campaigns" / NAME)}
    copied = []
    monkeypatch.setattr(campaign, "guard_mount", lambda archive_root, mount: None)
    monkeypatch.setattr(campaign, "copy_exclusive", lambda source, destination: copied.append((source, destination)))
    return directory, manifest, copied


def test_corpus_of_the_v5_shape_passes_the_build_and_the_production_check(campaign_corpus, tmp_path):
    """The addendum's test: groups of 3 with 3 of the 4 scenarios; the index is complete under the plan of the
    campaign, every session carries the position of its planned row and production training accepts the index."""
    from safeguard.training import validate_index
    c = campaign_corpus
    groups = {}
    for place in c.plan:
        groups.setdefault(place["group"], set()).add(place["scenario"])
    assert len(c.plan) == 30 and len(groups) == 10 and {len(held) for held in groups.values()} == {3}
    doc = build(c)
    assert (doc["complete"], doc["allocation_mismatches"], doc["allocation_rule"], doc["plan_mode"]) == (
        True, [], "plan:campaign", "campaign")
    assert sorted((r["group"], r["position"], r["scenario"], r["vm"]) for r in doc["sessions"]) == sorted(
        (s["group"], s["position"], s["scenario"], s["vm"]) for s in c.plan)
    _, _, records = validate_index(write_index(c, doc, tmp_path / "corpus.json"))
    assert Counter(r["role"] for r in records) == {role: 3 * n for role, n in GROUPS.items()}


MISSING = "v5-dev-1#2"  # A planned session of a group that keeps its other two.


@pytest.mark.parametrize("at", ["build", "validate_index", "finish_corpus"])
def test_group_missing_a_planned_session_is_refused(campaign_corpus, tmp_path, monkeypatch, at):
    """build names the missing row and the index is not complete; production training refuses an index without it
    even when the index calls itself complete; a campaign does not end with it (scripts/campaign.py finish_corpus)."""
    c = campaign_corpus
    row = next(s for s in c.plan if label(s) == MISSING)
    mismatch = {"reason": "missing planned session", "label": MISSING, "role": "dev", "group": "v5-dev-1",
                "position": 2, "scenario": row["scenario"], "vm": row["vm"]}
    audits = [audit for key, audit in c.audits.items() if key != MISSING]
    if at == "build":
        doc = build(c, audits)
        assert (doc["complete"], doc["allocation_mismatches"]) == (False, [mismatch])
    elif at == "validate_index":
        from safeguard.training import validate_index
        doc = build(c)
        doc["sessions"] = [r for r in doc["sessions"] if r["id"] != c.sids[MISSING]]
        assert doc["complete"] is True
        with refused(f"incomplete planned allocation: planned session {named(row)} of plan:campaign has no session"):
            validate_index(write_index(c, doc, tmp_path / "corpus.json"))
    else:
        directory, manifest, copied = finish_setup(c, tmp_path, monkeypatch)
        with refused("campaign ended without a complete corpus allocation: " + json.dumps(mismatch, sort_keys=True)):
            campaign.finish_corpus(directory, manifest, c.p, audits)
        assert not (directory / "corpus.json").exists() and copied == []


def test_finish_corpus_indexes_the_plan_of_the_campaign(campaign_corpus, tmp_path, monkeypatch):
    """Good input of finish_corpus: the whole plan; the index names its rule and passes the production check, which
    the campaign runs in a subprocess, and goes to the archive."""
    c = campaign_corpus
    directory, manifest, copied = finish_setup(c, tmp_path, monkeypatch)
    campaign.finish_corpus(directory, manifest, c.p, list(c.audits.values()))
    doc = json.loads((directory / "corpus.json").read_text())
    assert (doc["complete"], doc["allocation_rule"], doc["plan_mode"], len(doc["sessions"])) == (
        True, "plan:campaign", "campaign", 30)
    assert copied == [(directory / "corpus.json", Path(manifest["archive_dir"]) / "corpus.json")]


@pytest.mark.parametrize("at", ["build", "validate_index"])
@pytest.mark.parametrize("case", ["extra_session", "other_vm"])
def test_session_holding_no_planned_row_is_refused(campaign_corpus, tmp_path, case, at):
    """extra_session: an extra accepted session in group v5-train-1 with the scenario the plan leaves out of that
    group, after the group's sessions in the lane of train. other_vm (verification of B6a, finding F5): the planned
    session v5-dev-1#2 (MISSING) captured on the other VM than its row, in its place and at its time; a replacement
    keeps the VM of its row (B4), so the VM is part of the key (role, group, scenario, vm). Build and the production
    check refuse either by name."""
    c = campaign_corpus
    if case == "extra_session":
        held = [s for s in c.plan if s["group"] == "v5-train-1"]
        scenario, = set(SCENARIOS) - {s["scenario"] for s in held}
        place, sid, instead = dict(held[0], scenario=scenario), "extra-v5-train-1-" + scenario, None
        start = BASE + VM_S[place["vm"]] + len(held) * SLOT_S
    else:
        row = next(s for s in c.plan if label(s) == MISSING)
        place, sid, instead = dict(row, vm={"a": "b", "b": "a"}[row["vm"]]), "other-vm-" + c.sids[MISSING], MISSING
        start = c.times[c.sids[MISSING]][0]
    extra = session(tmp_path / "sessions", c, place, sid, start)
    if at == "build":
        with refused(f"assignment is outside the planned allocation: session {named(place, sid)} holds no row "
                     "of plan:campaign"):
            build(c, [*(audit for key, audit in c.audits.items() if key != instead), extra])
    else:
        from safeguard.training import validate_index
        doc = build(c)
        doc["sessions"] = [r for r in doc["sessions"] if instead is None or r["id"] != c.sids[instead]]
        doc["sessions"].append(record_of(c, extra, position=place["position"]))
        with refused(f"incomplete planned allocation: session {named(place, sid)} holds no row of plan:campaign"):
            validate_index(write_index(c, doc, tmp_path / "corpus.json"))


@pytest.mark.parametrize("at", ["build", "validate_index"])
def test_rehearsal_corpus_passes_in_its_own_mode_only(rehearsal_corpus, tmp_path, at):
    """A rehearsal (prefix g5-, one group per role) is complete under plan:rehearsal and production training accepts
    it; under the plan of the campaign its first session holds no row."""
    c = rehearsal_corpus
    doc = build(c)
    assert (doc["complete"], doc["allocation_rule"], doc["plan_mode"]) == (True, "plan:rehearsal", "rehearsal")
    assert {r["group"][:3] for r in doc["sessions"]} == {"g5-"} and len(doc["sessions"]) == 15
    first = c.plan[0]  # The first audit of the build and the earliest session of the index.
    assert c.times[c.sids[label(first)]][0] == min(start for start, _ in c.times.values())
    if at == "build":
        with refused(f"assignment is outside the planned allocation: session {named(first, c.sids[label(first)])} "
                     "holds no row of plan:campaign"):
            build(c, mode="campaign")
    else:
        from safeguard.training import validate_index
        validate_index(write_index(c, doc, tmp_path / "rehearsal.json"))
        forged = dict(doc, plan_mode="campaign", allocation_rule="plan:campaign")
        with refused(f"incomplete planned allocation: session {named(first, c.sids[label(first)])} holds no row "
                     "of plan:campaign"):
            validate_index(write_index(c, forged, tmp_path / "as-campaign.json"))


@pytest.mark.parametrize("loader", ["train_bundle", "nacitaj_role"])
def test_test_controls_are_indexed_and_never_loaded(campaign_corpus, tmp_path, monkeypatch, loader):
    """The sessions of test_controls are in the index with their hashes; training (and tcn.porovnanie, which loads as
    training does) opens the archives of train, dev and calibration only."""
    import safeguard.training as training
    from tcn import porovnanie
    c = campaign_corpus
    doc = build(c)
    controls = [r for r in doc["sessions"] if r["role"] == "test_controls"]
    assert len(controls) == 6 and all(r["features_sha256"] == collection.digest(r["features"]) for r in controls)
    module = training if loader == "train_bundle" else porovnanie
    opened, original = [], module.load_archive
    monkeypatch.setattr(module, "load_archive", lambda path: opened.append(str(path)) or original(path))
    index = write_index(c, doc, tmp_path / "corpus.json")
    if loader == "train_bundle":
        result = training.train_bundle(index, tmp_path / "bundle", window_rows=WINDOW, max_gap_s=GAP)
        assert result["training"]["windows"] == {role: 6 * WINDOWS for role in FIT}
    else:
        assert {role: len(data.indices) for role, data in porovnanie.nacitaj_role(index)["data"].items()} == {
            role: 6 * WINDOWS for role in FIT}
    assert sorted(opened) == sorted(r["features"] for r in doc["sessions"] if r["role"] in FIT)


@pytest.mark.parametrize("at", ["build", "validate_index"])
def test_train_session_after_a_test_session_is_refused(campaign_corpus, tmp_path, at):
    """The two test roles run at once on the two VMs and pass (they share a rank of the time order); a train session
    after them is refused by build (a replacement of its row captured late) and by the production check (its times
    in the index)."""
    c = campaign_corpus
    times = {role: [c.times[c.sids[label(s)]] for s in c.plan if s["role"] == role] for role in RANK}
    benign, controls = times["test_benign"], times["test_controls"]
    assert min(s for s, _ in controls) < max(e for _, e in benign) and min(s for s, _ in benign) < max(
        e for _, e in controls)
    moved = c.plan[0]
    first_dev = min((s for s in c.plan if s["role"] == "dev"), key=lambda s: c.times[c.sids[label(s)]][0])
    late = BASE + 4 * LANE_S  # After the lane of the test roles.
    if at == "build":
        sid = "late-" + c.sids[label(moved)]
        audit = session(tmp_path / "sessions", c, moved, sid, late)
        with refused(f"dataset roles are not chronologically separated: train session {sid} ends after dev session "
                     f"{c.sids[label(first_dev)]} starts"):
            build(c, [audit if key == label(moved) else a for key, a in c.audits.items()])
    else:
        from safeguard.training import validate_index
        doc = build(c)
        validate_index(write_index(c, doc, tmp_path / "corpus.json"))
        record, = [r for r in doc["sessions"] if r["id"] == c.sids[label(moved)]]
        record.update(start=late, end=late + INTERVAL * (CYCLES - 1))
        with refused(f"corpus roles must be chronologically separated: train session {record['id']} ends after dev "
                     f"session {c.sids[label(first_dev)]} starts"):
            validate_index(write_index(c, doc, tmp_path / "late.json"))


def test_protocol_of_schema_2_keeps_its_rule_and_the_index_names_it(tmp_path):
    """Every scenario in every group of the four roles of schema 2, as before: the index names the rule, has no plan
    mode and no positions, and a missing role is the mismatch it was; a plan mode is refused there."""
    from features import dataset
    from features.tests.test_dataset import protocol, record
    audits = [record(tmp_path, role, i) for i, role in enumerate(("train", "dev", "calibration"))]
    doc = dataset.build(audits, protocol(), "protocol-test")
    assert (doc["allocation_rule"], doc["plan_mode"], doc["complete"]) == ("every_scenario_every_group", None, False)
    assert doc["allocation_mismatches"] == [{"role": "test_benign", "scenario": "steady", "expected": 1, "actual": 0}]
    assert [r["position"] for r in doc["sessions"]] == [None] * 3
    with refused("plan mode campaign applies only to protocol schema 3; schemas 1 and 2 keep "
                 "every_scenario_every_group"):
        dataset.build(audits, protocol(), "protocol-test", mode="campaign")


@pytest.mark.parametrize("mode", [None, "generalka"], ids=["no_mode", "unknown_mode"])
def test_build_of_schema_3_needs_a_known_plan_mode(campaign_corpus, mode):
    """No default mode: build without one is refused, and so is a mode the plan does not know."""
    from features import dataset
    c = campaign_corpus
    if mode is None:
        with refused("a corpus of protocol schema 3 needs its plan mode (campaign or rehearsal)"):
            dataset.build(list(c.audits.values()), c.p, c.sha)
    else:
        with refused("no planned rows of mode generalka: unknown plan mode: generalka"):
            dataset.build(list(c.audits.values()), c.p, c.sha, mode=mode)


def _no_rule(c, doc):
    del doc["allocation_rule"]
    return "corpus index states allocation rule None; its protocol and plan mode give plan:campaign"


def _no_mode(c, doc):
    del doc["plan_mode"]
    return "corpus index allocation: a corpus of protocol schema 3 needs its plan mode (campaign or rehearsal)"


def _position(c, doc):
    record = doc["sessions"][0]
    row = next(s for s in c.plan if c.sids[label(s)] == record["id"])
    record["position"] = (row["position"] + 1) % 3
    return (f"index/plan mismatch: position of session {record['id']} is {record['position']}, its row {label(row)} "
            f"has {row['position']}")


def _vm(c, doc):
    record = doc["sessions"][0]
    record["vm"] = {"a": "b", "b": "a"}[record["vm"]]
    return "index/session mismatch: vm"


def _no_controls(c, doc):
    doc["sessions"] = [r for r in doc["sessions"] if r["role"] != "test_controls"]
    return "missing corpus role: test_controls"


@pytest.mark.parametrize("change", [_no_rule, _no_mode, _position, _vm, _no_controls],
                         ids=["no_rule", "no_mode", "position", "vm", "no_test_controls"])
def test_production_check_refuses_an_index_that_differs_from_its_plan(campaign_corpus, tmp_path, change):
    """The index states its rule and plan mode, every record the position of its row and the VM of its session.json,
    and every role of the plan is present (also test_controls); each change alone is refused by name."""
    from safeguard.training import validate_index
    c = campaign_corpus
    doc = build(c)
    with refused(change(c, doc)):
        validate_index(write_index(c, doc, tmp_path / "corpus.json"))


def test_planned_rows_are_the_sessions_of_the_plan(campaign_corpus, rehearsal_corpus):
    """One row per planned session in the plan's order, in either mode; the rehearsal's groups take its prefix."""
    from scripts.protocol_v5 import planned_rows
    for c in (campaign_corpus, rehearsal_corpus):
        assert planned_rows(c.p, c.mode) == [{"label": label(s), "role": s["role"], "group": s["group"],
                                             "position": s["position"], "scenario": s["scenario"], "vm": s["vm"]}
                                            for s in c.plan]
    assert {r["group"][:3] for r in planned_rows(rehearsal_corpus.p, "rehearsal")} == {"g5-"}


@pytest.mark.parametrize("case", ["no_mode", "schema_2", "repeated_scenario"])
def test_planned_rows_refuse(campaign_corpus, case):
    """No default mode; schema 3 only; a plan whose group repeats a scenario cannot be matched by (role, group,
    scenario, vm), so it is refused by name."""
    from scripts.protocol_v5 import planned_rows
    c = campaign_corpus
    if case == "no_mode":
        with pytest.raises(TypeError, match=re.escape("planned_rows() missing 1 required positional argument: 'mode'")):
            planned_rows(c.p)
    elif case == "schema_2":
        with refused("planned rows require protocol schema 3"):
            planned_rows(dict(c.p, schema="hyptcn3/collection-protocol/2"), "campaign")
    else:
        p = protocol_doc(c.profile, scenarios=SCENARIOS[:2])  # Groups of 3 sessions over 2 scenarios.
        sessions = protocol_v5.plan(p, "campaign")["sessions"]
        held = [s["scenario"] for s in sessions if s["group"] == sessions[0]["group"]]
        scenario = next(s for s in held if held.count(s) > 1)
        with refused(f"planned rows cannot be matched: group {sessions[0]['group']} repeats scenario {scenario}"):
            planned_rows(p, "campaign")


@pytest.mark.parametrize("case", ["indexed", "missing", "changed"])
def test_the_index_hashes_the_controls_of_test_controls(campaign_corpus, tmp_path, case):
    """Package B7c (the executor's points for B7): every session of role test_controls is indexed with its
    controls.json and the file's sha256, no session of another role has one; build refuses a session of the role
    without the file, and the production check of training (validate_index) and the reader controls_of refuse a file
    whose sha256 differs from the index."""
    from features import dataset
    from safeguard.training import validate_index
    c = campaign_corpus
    if case == "missing":
        place = next(s for s in c.plan if s["role"] == "test_controls")
        audit = session(tmp_path / "sessions", c, place, "no-controls", c.times[c.sids[label(place)]][0])
        (tmp_path / "sessions" / "no-controls" / "controls.json").unlink()
        with refused(f"session of role test_controls has no controls.json: {tmp_path / 'sessions' / 'no-controls'}"):
            build(c, [audit if key == label(place) else a for key, a in c.audits.items()])
        return
    doc = build(c)
    controls = [r for r in doc["sessions"] if r["role"] == "test_controls"]
    assert len(controls) == 6 and not any("controls" in r for r in doc["sessions"] if r["role"] != "test_controls")
    for r in controls:
        assert r["controls"] == str(Path(r["session"]).parent / "controls.json")
        assert r["controls_sha256"] == collection.digest(r["controls"])
        assert dataset.controls_of(r) == json.loads(Path(r["controls"]).read_text())
    if case == "indexed":
        validate_index(write_index(c, doc, tmp_path / "corpus.json"))
        return
    first = controls[0]
    first["controls_sha256"] = "0" * 64
    with refused("controls checksum mismatch"):
        validate_index(write_index(c, doc, tmp_path / "corpus.json"))
    with refused(f"controls.json of session {first['id']} changed since the index: {first['controls']}"):
        dataset.controls_of(first)

