"""A campaign of the v5 shape on the fakes of collection, end to end (protocol v5, package B9a, agent T).

Binding texts: the lead's skeleton dokazy/B9/kostra/KOSTRA.md section 4 (tests 1, 2, 3 in part, 6 and 7; the others
are B9b's), the design dokazy/B9/navrh/NAVRH_B9a.md section 1.4, written against the contract of its sections 1.1
to 1.3 (agents P, L and K), and the fix round dokazy/B9/navrh/OPRAVA_B9a.md section 4 (findings F2, F4, F5 and F6 of
the verification of B9a). The harness is scripts/tests/kampan_v5.py: the real scripts/campaign.py, the real archiver,
ledger, corpus build and production check of training, fakes of the lab, the capture and the audit (its docstring
lists them). No test here replaces the final index (F2).

The scenario of this file (one module fixture; real feature archives and audit records, kampan_v5.audit_values, of
the smallest v5-shaped protocol that features/tests/test_dataset_plan.py builds: five roles, two groups each on two
VMs, the test roles interleaved, 8-minute sessions):

1. a rehearsal (init --mode rehearsal) under a protocol whose replacement.max_per_campaign is null, as until G3b;
   its audit rejects the first session of g5-test_benign-1 twice, so attempts 2 and 3 of that row run;
2. init --mode campaign of the same protocol (the null limit), refused;
3. the campaign (init --mode campaign --estimate-from <the rehearsal>) under the protocol as G3b leaves it: the same
   file with the limit 1, nothing else changed; its audit rejects the first session of v5-test_controls-1 once.

Both runners run in turn (Harness.run), each to finish_corpus with the real features/dataset.py build and the real
safeguard.training.validate_index. The deadlock at 4 groups per role, test 2 under a drift (one VM runs ahead of the
other, F5) and the failing steps of the start of a group run campaigns of their own on the same harness, with real
archives and the real index; the first two start from the scenario's rehearsal (--estimate-from).

Names of package B9a are reached only inside the fixtures and the tests, so this file collects on the code before it
(where every test fails: init knows no --mode). Only mechanics on synthetic sessions; no number here is a detection
result (HONESTY P4).

Package B9b (agent T; the design dokazy/B9/navrh/NAVRH_B9b.md section 1.4 and its addendum, section 3): tests 3, 4
and 5 of the skeleton, the corpus of a continuation through validate_index, tcn.finalne reading the record of the
complete ending, and the interleave of the realized boots in that record, in the last part of this file with the
campaigns of their own fixtures (listed there). Every ending writes its record into the directory of its harness
(scripts/campaign.py RESULTS); no test leaves a file in data/results or changes docs/ (checked after every test). The
names of package B9b are reached only inside the fixtures and the tests too, so this file still collects on the code
before it, where every test of package B9b fails.
"""
from collections import Counter
import contextlib
import copy
import io
import json
import math
import os
from pathlib import Path
import re
import threading
import time
from types import SimpleNamespace

import pytest

from scripts import campaign as c
from scripts import collection
from scripts import protocol_v5 as pv
from scripts.collection_archive import digest, read_json
from scripts.tests.kampan_v5 import (GROUP_START, LAB_STEPS, PERIODICITY, TRACKED_LEDGER, VMS, Harness, NoSignals,
                                     holds, ledger_entries, printed)
from scripts.tests.test_multivm import no_inherited_lock  # noqa: F401 (autouse fixture: no inherited lock)

SEALED = ("test_benign", "test_controls")  # tcn/pecat.py SEALED_ROLES
TRACKED = digest(TRACKED_LEDGER) if TRACKED_LEDGER.exists() else None
# Package B9b: what a test may never change in the repository (the records of the endings belong to data/results,
# proposal 11.6 names docs/MERANIA.md, design 1.1 the deviation log).
DEVIATION_LOG = c.ROOT / "docs/ODCHYLKY_V5.sk.md"
RESULTS_LISTING = sorted(path.name for path in (c.ROOT / "data/results").iterdir())
DOCS = {path: digest(path) for path in (c.ROOT / "docs/MERANIA.md", DEVIATION_LOG)}


@pytest.fixture(autouse=True)
def _tracked_ledger_unchanged():
    """No test writes data/results/kniha_pecati.json (the harness points tcn.pecat.KNIHA and ZAZNAM elsewhere and
    refuses a write of it; this checks the file itself after every test, the module's scenario included)."""
    yield
    assert (digest(TRACKED_LEDGER) if TRACKED_LEDGER.exists() else None) == TRACKED


@pytest.fixture(autouse=True)
def _results_and_docs_unchanged():
    """Package B9b: no test leaves a file in data/results (the harness points scripts/campaign.py RESULTS, where every
    ending writes its record, to its own directory) or changes docs/MERANIA.md or the deviation log; checked after
    every test, the fixtures' campaigns included."""
    yield
    assert sorted(path.name for path in (c.ROOT / "data/results").iterdir()) == RESULTS_LISTING
    assert {path: digest(path) for path in DOCS} == DOCS


def first_of(plan, group):
    return next(x for x in plan if x["group"] == group)


@pytest.fixture(scope="module")
def scenario(tmp_path_factory):
    """The scenario of the module docstring; the patches of the harness are undone before the tests read it."""
    with pytest.MonkeyPatch.context() as mp:
        h = Harness(tmp_path_factory.mktemp("kampan"), mp)
        protocol_r = h.protocol("protocol-generalka", limit=None)
        protocol_c = h.protocol("protocol-kampan", limit=1)
        p_r, p_c = collection.protocol(protocol_r), collection.protocol(protocol_c)
        plan_r, plan_c = pv.plan(p_r, "rehearsal")["sessions"], pv.plan(p_c, "campaign")["sessions"]
        twice = first_of(plan_r, p_r["rehearsal"]["group_prefix"] + "test_benign-1")
        once = first_of(plan_c, p_c["group_prefix"] + "test_controls-1")
        h.reject |= {(twice["group"], twice["scenario"], 1), (twice["group"], twice["scenario"], 2),
                     (once["group"], once["scenario"], 1)}
        h.label = "rehearsal"
        rehearsal = h.init(protocol_r, "rehearsal", p_r["name"] + p_r["rehearsal"]["name_suffix"])
        h.run(rehearsal)
        h.label = "null"
        null = h.base / (p_r["name"] + "-null")
        try:
            h.init(protocol_r, "campaign", null.name, estimate_from=rehearsal)
            refusal = None
        except ValueError as error:
            refusal = str(error)
        h.label = "campaign"
        campaign = h.init(protocol_c, "campaign", p_c["name"], estimate_from=rehearsal)
        h.run(campaign)
    return SimpleNamespace(h=h, rehearsal=rehearsal, campaign=campaign, null=null, refusal=refusal,
                           protocol_r=protocol_r, protocol_c=protocol_c, p_r=p_r, p_c=p_c, plan_r=plan_r,
                           plan_c=plan_c, twice=twice, once=once)


def assert_test_boots_interleave(h, directory):
    """Skeleton section 4, test 2, as one check of the boots of a campaign: no boot of test_controls lies wholly after
    every boot of test_benign (it starts before the last of them ends), and ordered by their start the boots of the
    two test roles alternate: the numbers of the two roles' boots started so far never differ by more than one."""
    boots = sorted((b for b in h.boots(directory).values() if b["role"] in pv.INTERLEAVED),
                   key=lambda b: b["start"])
    assert {b["role"] for b in boots} == set(pv.INTERLEAVED)
    last_benign_end = max(b["end"] for b in boots if b["role"] == "test_benign")
    late = [b["first"]["group"] for b in boots if b["role"] == "test_controls" and b["start"] >= last_benign_end]
    assert late == []
    started, spread = Counter(), []
    for b in boots:
        started[b["role"]] += 1
        spread.append(abs(started["test_benign"] - started["test_controls"]))
    assert max(spread) <= 1, [(b["first"]["group"], b["first"]["vm"]) for b in boots]


def accepted_order(h, directory, vm):
    return [(x["group"], x["scenario"]) for x in h.of(directory) if x["vm"] == vm and h.accepted(x["sid"])]


def test_a_small_campaign_runs_from_initialize_to_finish_corpus(scenario):
    """Skeleton section 4, test 1: a full small campaign on the fakes of collection (all five roles, both VMs) goes
    from initialize to finish_corpus with the real features.dataset.build over synthetic sessions, and the index passes
    the production check of training: the subprocess finish_corpus runs, and validate_index again here. The index
    holds exactly one accepted session of the campaign per planned row and goes to the archive. The start asks the
    stages of its mode (design 1.3 item 4): G5 and the self-test for the campaign, G3a and the self-test for the
    rehearsal; every capture asked the stage of its mode as well (design 1.2)."""
    from safeguard.training import validate_index
    s, h = scenario, scenario.h
    states = {vm: read_json(s.campaign / c.vm_file("status.json", vm)) for vm in VMS}
    assert {vm: state["status"] for vm, state in states.items()} == dict.fromkeys(VMS, "complete")
    assert sorted(state["stage"] for state in states.values()) == ["complete", "vm-complete"]
    corpus = s.campaign / "corpus.json"
    doc = read_json(corpus)
    assert (doc["complete"], doc["allocation_rule"], doc["plan_mode"], doc["allocation_mismatches"]) == (
        True, "plan:campaign", "campaign", [])
    assert sorted((r["group"], r["position"], r["scenario"], r["vm"]) for r in doc["sessions"]) == sorted(
        (x["group"], x["position"], x["scenario"], x["vm"]) for x in s.plan_c)
    accepted = {x["sid"] for x in h.of(s.campaign) if h.accepted(x["sid"])}
    assert len(accepted) == len(s.plan_c) == 30 and {r["id"] for r in doc["sessions"]} == accepted
    _, _, records = validate_index(corpus)
    assert Counter(r["role"] for r in records) == dict.fromkeys(pv.ROLES, 6)
    assert read_json(Path(read_json(s.campaign / "campaign.json")["archive_dir"]) / "corpus.json") == doc
    for label, protocol, stage in (("rehearsal", s.protocol_r, "G3a"), ("campaign", s.protocol_c, "G5")):
        asked = {g["stage"] for g in h.gates if g["label"] == label and g["phase"] == "campaign"}
        assert asked == {stage}, label
        assert {g["stage"] for g in h.gates if g["label"] == label and g["phase"] == "session"} == {stage}, label
        tested = {t["protocol_sha256"] for t in h.selftests if t["label"] == label and t["phase"] == "campaign"}
        assert tested == {digest(protocol)}, label


def test_the_boots_of_the_test_roles_interleave_in_time(scenario):
    """Skeleton section 4, test 2 (design 1.3 item 1, B6a F7, PRE_B9: the runners rank by protocol_v5.TIME_RANK, where
    both test roles have one rank): no boot of test_controls lies wholly after every boot of test_benign, and the
    boots of the two test roles alternate in time (assert_test_boots_interleave), in the rehearsal and in the
    campaign; each VM takes the rows of its plan in the plan's order. Ranked by the order of p["roles"] instead, VM
    b's v5-test_controls-2 would wait until VM a's v5-test_benign-2 ended."""
    s, h = scenario, scenario.h
    for directory, plan in ((s.rehearsal, s.plan_r), (s.campaign, s.plan_c)):
        assert_test_boots_interleave(h, directory)
        for vm in VMS:
            assert accepted_order(h, directory, vm) == [(x["group"], x["scenario"]) for x in plan if x["vm"] == vm]


def test_no_deadlock_at_four_groups_per_role(scenario, tmp_path, monkeypatch):
    """Skeleton section 4, test 2, and design 1.3 item 1 (map section 3.1: ranked by the order of p["roles"], the
    runners of a campaign of 4 groups per role stick, VM a at v5-test_controls-1 and VM b at v5-test_controls-2): with
    4 groups in every role both runners end, every planned session is captured once, the last runner builds the index
    once from all 60 sessions, and the test boots interleave as in test 2. Driven through execute of both runners with
    real archives and the real index (F2 of the verification of B9a): it holds all 60 sessions, in the time order of
    the roles, and passes the production check of training. The campaign starts from the scenario's rehearsal, whose
    sessions have the same shape (--estimate-from)."""
    from safeguard.training import validate_index
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-4", limit=0, groups=4)
    p = collection.protocol(protocol)
    campaign = h.init(protocol, "campaign", p["name"], estimate_from=scenario.rehearsal)
    h.run(campaign)
    plan = pv.plan(p, "campaign")["sessions"]
    assert len(plan) == 60 and Counter(x["role"] for x in plan) == dict.fromkeys(pv.ROLES, 12)
    assert sorted((x["group"], x["scenario"], x["attempt"]) for x in h.of(campaign)) == sorted(
        (x["group"], x["scenario"], 1) for x in plan)
    built = [f for f in h.finished if f["campaign"] == campaign.name]
    assert len(built) == 1 and len(set(built[0]["reports"])) == 60
    doc = read_json(campaign / "corpus.json")
    assert (doc["complete"], doc["allocation_rule"], len(doc["sessions"])) == (True, "plan:campaign", 60)
    assert Counter(r["role"] for r in validate_index(campaign / "corpus.json")[2]) == dict.fromkeys(pv.ROLES, 12)
    assert_test_boots_interleave(h, campaign)
    for vm in VMS:
        assert accepted_order(h, campaign, vm) == [(x["group"], x["scenario"]) for x in plan if x["vm"] == vm]


def test_the_boots_of_the_test_roles_interleave_when_one_vm_runs_ahead(scenario, tmp_path, monkeypatch):
    """Skeleton section 4, test 2, under a drift (finding F5 of the verification of B9a; the fix round's sections 1 and
    4): both runners in turn until each VM's next session is of a test role, then VM a alone until it waits, then VM b
    alone until it waits, then both in turn to the end (Harness.drift; the verifier's sondy/s/drift_harness.py). The
    barrier of the shared rank holds VM a: a runner starts a group of an interleaved role only after every group of
    the interleaved roles before it in the plan has started on the other VMs (its group record exists). So VM a, ahead,
    records that it waits for the test groups of VM b before its own first one, and the boots of the test roles still
    interleave (assert_test_boots_interleave). Without the barrier VM a runs all its test groups alone, and VM b's last
    group of test_controls starts after every boot of test_benign has ended. Real archives and the real index; the
    campaign starts from the scenario's rehearsal (--estimate-from)."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-drift", limit=0)
    p = collection.protocol(protocol)
    campaign = h.init(protocol, "campaign", p["name"], estimate_from=scenario.rehearsal)
    alone = h.drift(campaign, ahead="a")
    rows = h.plan_rows(campaign)
    interleaved = list(dict.fromkeys((x["group"], x["vm"]) for x in rows if x["role"] in pv.INTERLEAVED))
    first = next(i for i, (_, vm) in enumerate(interleaved) if vm == "a")
    awaited = [group for group, vm in interleaved[:first] if vm != "a"]
    assert awaited and alone["a"]["status"] == "stopped", alone["a"]
    assert all(group in alone["a"]["message"] for group in awaited), alone["a"]["message"]
    boots = h.boots(campaign)
    first_test_of_a = min(x["order"] for x in h.of(campaign) if x["vm"] == "a" and x["role"] in pv.INTERLEAVED)
    assert all(boots[vm, group]["first"]["order"] < first_test_of_a for group, vm in interleaved[:first] if vm != "a")
    assert_test_boots_interleave(h, campaign)
    doc = read_json(campaign / "corpus.json")
    assert (doc["complete"], doc["allocation_rule"], len(doc["sessions"])) == (True, "plan:campaign", len(rows))


def test_a_null_limit_is_refused_at_the_start_of_a_campaign(scenario):
    """Skeleton section 4, test 3 (part; design 1.3 item 5): in mode campaign init refuses, by its name, a protocol
    whose replacement.max_per_campaign is null (determined at G3b), before it writes the campaign; the same start
    with the limit 1 (the campaign of the scenario, which differs in that value only) is accepted."""
    s = scenario
    assert s.refusal is not None and "max_per_campaign" in s.refusal
    assert not s.null.exists() and not (s.h.archive / "campaigns" / s.null.name).exists()
    assert (s.campaign / "campaign.json").exists()
    assert {k: v for k, v in read_json(s.protocol_r).items() if k != "replacement"} == {
        k: v for k, v in read_json(s.protocol_c).items() if k != "replacement"}


def filled(controls):
    """The controls a session records: the slots the deck filled (collection.v5_planned)."""
    return [x for x in controls if x.get("kind") is not None]


def test_a_replacement_keeps_the_assignment_and_gets_new_times(scenario):
    """Skeleton section 4, test 3 (part; design 1.3 item 5): the session of the campaign its audit rejected is
    replaced by attempt 2 of its planned row (protocol_v5.replacement): the same VM, role, group, scenario and controls
    (kind, polarity, class, dose and the tenths of the interval of their starts and stops), in the same boot, as the
    VM's next capture; new control times and a new traffic seed. The capture passed --attempt 2, the seed of attempt
    2 and --replaces; session.json records the attempt and the mode; the rejection names the replacement; the index
    holds the replacement at the row's position and never the rejected session."""
    s, h = scenario, scenario.h
    row = s.once
    tries = [x for x in h.of(s.campaign) if (x["group"], x["scenario"]) == (row["group"], row["scenario"])]
    assert [(x["attempt"], h.accepted(x["sid"])) for x in tries] == [(1, False), (2, True)]
    first, second = tries
    again = pv.replacement(s.p_c, row, 2, mode="campaign")
    assert (first["seed"], second["seed"]) == (row["seed"], again["seed"]) and again["seed"] != row["seed"]
    assert (second["vm"], second["role"], second["boot"], second["qemu"]) == (
        first["vm"], first["role"], first["boot"], first["qemu"])
    assert second["replaces"] == first["sid"]
    after = [x for x in h.captures if x["vm"] == first["vm"] and x["order"] > first["order"]]
    assert after[0] is second
    old, new = (read_json(Path(x["directory"]) / "session.json") for x in tries)
    assert (old["attempt"], old["plan_mode"], new["attempt"], new["plan_mode"]) == (1, "campaign", 2, "campaign")
    assert old["controls"] == filled(row["controls"]) and new["controls"] == filled(again["controls"])
    kinds = lambda controls: [(x["kind"], x["polarity"], x["class"], x["dose"], pv.item_tenths(s.p_c, x))
                              for x in controls]
    assert new["controls"] and kinds(new["controls"]) == kinds(old["controls"])
    assert all((x["start_s"], x["duration_s"]) != (y["start_s"], y["duration_s"])
               for x, y in zip(old["controls"], new["controls"]))
    record = read_json(s.campaign / "attempts" / (first["sid"] + ".rejected.json"))
    assert (record["session"], record["cause"], record["replacement"]) == (first["sid"], "audit_rejected",
                                                                           second["sid"])
    held = {r["id"]: r for r in read_json(s.campaign / "corpus.json")["sessions"]}
    assert first["sid"] not in held and held[second["sid"]]["position"] == row["position"]


def test_a_rehearsal_has_its_own_name_and_prefix(scenario):
    """Skeleton section 4, test 6 (design 1.3 item 2): the rehearsal's frozen plan is protocol_v5.plan in mode
    rehearsal, under the name of the protocol with rehearsal.name_suffix and the prefix rehearsal.group_prefix
    (protocol_v5._shape); every capture ran with --mode rehearsal and every session.json records it; the campaign's
    plan keeps the protocol's own name and prefix and mode campaign."""
    s, h = scenario, scenario.h
    for directory, p, mode, name, prefix in (
            (s.rehearsal, s.p_r, "rehearsal", s.p_r["name"] + s.p_r["rehearsal"]["name_suffix"],
             s.p_r["rehearsal"]["group_prefix"]),
            (s.campaign, s.p_c, "campaign", s.p_c["name"], s.p_c["group_prefix"])):
        plan = read_json(directory / "plan.json")
        assert (plan["mode"], plan["name"], plan["group_prefix"]) == (mode, name, prefix)
        strip = lambda rows: [{k: v for k, v in row.items() if k != "session_id"} for row in rows]
        assert strip(plan["sessions"]) == strip(h.plan_rows(directory)) == pv.plan(p, mode)["sessions"]
        assert all(row["group"].startswith(prefix) for row in plan["sessions"])
        assert {x["mode"] for x in h.of(directory)} == {mode}
        assert {read_json(Path(x["directory"]) / "session.json")["plan_mode"] for x in h.of(directory)} == {mode}
    assert (s.p_r["rehearsal"]["group_prefix"], s.p_c["group_prefix"]) == ("g5-", "v5-")


def test_the_sessions_of_a_rehearsal_never_enter_the_corpus_of_the_campaign(scenario):
    """Skeleton section 4, test 6 (design 1.3 item 2): the rehearsal ends with its own index (plan:rehearsal, its 15
    sessions) and the campaign's index holds none of the rehearsal's sessions; features/dataset.py build refuses the
    rehearsal's sessions under the plan of the campaign by name (a group of prefix g5- holds no row of plan:campaign)
    and builds them under their own plan."""
    from features import dataset
    s, h = scenario, scenario.h
    own = read_json(s.rehearsal / "corpus.json")
    assert (own["complete"], own["allocation_rule"], own["plan_mode"], len(own["sessions"])) == (
        True, "plan:rehearsal", "rehearsal", 15)
    ids = {x["sid"] for x in h.of(s.rehearsal)}
    campaign = read_json(s.campaign / "corpus.json")
    assert {r["id"] for r in own["sessions"]} <= ids and not ids & {r["id"] for r in campaign["sessions"]}
    assert not any(r["group"].startswith(s.p_r["rehearsal"]["group_prefix"]) for r in campaign["sessions"])
    audits = [r["audit"] for r in own["sessions"]]
    first = read_json(Path(audits[0]))["values"]
    meta = read_json(Path(first["session_dir"]) / "session.json")
    named = f"{meta['session_id']} ({meta['role']}, {meta['group']}, {meta['scenario']}, VM {meta['vm']})"
    with pytest.raises(ValueError, match="^" + re.escape(f"assignment is outside the planned allocation: session "
                                                         f"{named} holds no row of plan:campaign") + "$"):
        dataset.build(audits, s.p_r, digest(s.protocol_r), mode="campaign")
    assert dataset.build(audits, s.p_r, digest(s.protocol_r), mode="rehearsal")["complete"] is True


def counts_by_cause(directory):
    """Every mapping of a cause of rejection to an integer in the state files of a campaign (status*.json)."""
    found = []

    def walk(tree):
        if isinstance(tree, dict):
            if tree and all(type(v) is int for v in tree.values()) and "audit_rejected" in tree:
                found.append(tree)
            for value in tree.values():
                walk(value)
        elif isinstance(tree, list):
            for value in tree:
                walk(value)
    for path in sorted(Path(directory).glob("status*.json")):
        walk(read_json(path))
    return found


def test_a_rehearsal_does_not_apply_the_limit_and_counts_its_rejections_by_cause(scenario):
    """Skeleton section 4, test 6 (design 1.3 item 5): under a protocol whose replacement.max_per_campaign is null, as
    until G3b, the rehearsal replaces a session its audit rejected twice by attempts 2 and 3 of its planned row
    (protocol_v5.replacement in mode rehearsal) and ends complete; each rejection names its replacement, and the
    campaign's state counts the rejections by cause (2 audit_rejected), from which G3b sets the limit."""
    s, h = scenario, scenario.h
    row = s.twice
    assert s.p_r["replacement"]["max_per_campaign"] is None
    tries = [x for x in h.of(s.rehearsal) if (x["group"], x["scenario"]) == (row["group"], row["scenario"])]
    assert [(x["attempt"], h.accepted(x["sid"])) for x in tries] == [(1, False), (2, False), (3, True)]
    assert [x["seed"] for x in tries] == [row["seed"], *(pv.replacement(s.p_r, row, n, mode="rehearsal")["seed"]
                                                         for n in (2, 3))]
    assert [x["replaces"] for x in tries] == [None, tries[0]["sid"], tries[1]["sid"]]
    records = c.rejections(s.rehearsal)
    assert [(r["session"], r["cause"], r["replacement"]) for r in records] == [
        (tries[0]["sid"], "audit_rejected", tries[1]["sid"]), (tries[1]["sid"], "audit_rejected", tries[2]["sid"])]
    assert {read_json(s.rehearsal / c.vm_file("status.json", vm))["status"] for vm in VMS} == {"complete"}
    assert any(counts.get("audit_rejected") == 2 for counts in counts_by_cause(s.rehearsal))


def test_an_accepted_session_of_a_sealed_role_is_in_the_ledger_and_its_replay_is_refused(scenario, tmp_path,
                                                                                         monkeypatch):
    """Skeleton section 4, test 7 (design 1.3 item 7, B7c PRE_B9): after its audit accepts a session of test_benign or
    test_controls the campaign writes it into the ledger (tcn.pecat.KNIHA and ZAZNAM, a file of the test) at once,
    before any later capture: id, role, group, vm, scenario, features and features_sha256 under the plan and mode it
    ran in (the rehearsal's archives are kept, mode rehearsal); a session its audit rejected and every session of
    train, dev and calibration are not in it, and nothing during the campaign replays or scores anything (no call of
    tcn.pecat.kontrola). After the campaign tcn.porovnanie replay of a sealed archive is refused by name before
    anything is written; the archive of a train session is not sealed and an archive of the rehearsal is let
    through."""
    from tcn import pecat, porovnanie
    s, h = scenario, scenario.h
    entries = ledger_entries(h.ledger)
    plans = {"campaign": s.p_c["name"], "rehearsal": s.p_r["name"] + s.p_r["rehearsal"]["name_suffix"]}
    sealed = {}
    for directory, mode in ((s.rehearsal, "rehearsal"), (s.campaign, "campaign")):
        for x in h.of(directory):
            if x["role"] in SEALED and h.accepted(x["sid"]):
                meta = read_json(Path(x["directory"]) / "session.json")
                audit = next(a for a in h.audits if a["sid"] == x["sid"])
                values = read_json(Path(audit["report"]))["values"]
                sealed[values["features_sha256"]] = {
                    "session": x["sid"], "role": x["role"], "group": meta["group"], "vm": meta["vm"],
                    "scenario": meta["scenario"], "features": str(Path(values["features"]).resolve()),
                    "plan": plans[mode], "mode": mode}
    assert len(sealed) == 6 + 12 and set(entries) == set(sealed)
    assert {sha: {k: entries[sha].get(k) for k in expected} for sha, expected in sealed.items()} == sealed
    rejected = {x["sid"] for x in h.captures if h.accepted(x["sid"]) is False}
    assert len(rejected) == 3 and not rejected & {entry["session"] for entry in entries.values()}
    for x in h.captures:  # At once: every sealed session done before a capture is in the ledger at that capture.
        done = {sid for sid in x["done"] if any(entry["session"] == sid for entry in sealed.values())}
        assert done <= x["ledger"], x["sid"]
    assert h.kontrola == []
    monkeypatch.setattr(pecat, "KNIHA", h.ledger)
    monkeypatch.setattr(pecat, "ZAZNAM", h.ledger)
    sha, entry = next((sha, e) for sha, e in sealed.items() if e["mode"] == "campaign")
    out = tmp_path / "out"
    with pytest.raises(pecat.Zapecatene) as refused:
        porovnanie.replay(tmp_path / "no-model", entry["features"], out)
    assert str(refused.value) == (
        f"tcn.porovnanie replay: refused, the archive {entry['features']} is sealed (sha256 {sha}; session "
        f"{entry['session']} of role {entry['role']}, plan {s.p_c['name']}, ledger {h.ledger.resolve()}): a sealed "
        "archive of a campaign is replayed or scored only by the final command (python -m tcn.finalne) in the run "
        "that consumes its seal (tcn/pecat.py GUARD_RULE)")
    assert not out.exists()
    train = next(r for r in read_json(s.campaign / "corpus.json")["sessions"] if r["role"] == "train")
    assert pecat.kontrola(train["features"], purpose="test")["allowed"] == "not_sealed"
    kept = next(e for e in sealed.values() if e["mode"] == "rehearsal")
    assert pecat.kontrola(kept["features"], purpose="test")["allowed"] == "rehearsal"


def test_every_group_starts_with_stop_start_reset_and_pretouch(scenario):
    """Design 1.4, the start of a group (1.3 item 6, proposal 5.4, B5a F4): before the first session of every group of
    the rehearsal and of the campaign its VM ran labctl stop, start, reset --seed and pretouch, in this order, each
    once, all of them passing, and no reboot; the seed is protocol_v5.reset_seed(p), the protocol's one seeded level
    of the database, the same for every group of both modes (finding F4 of the verification of B9a: proposal 5.4,
    the table of chapter 12 and Q18); the start is a new QEMU process (way 1) with a new guest boot, which every
    session of the group names, and groups/<group>.json records that QEMU's pid and cgroup and the outputs of reset
    and pretouch."""
    s, h = scenario, scenario.h
    assert not any(call["verb"] == "reboot" for call in h.lab.calls)
    seed = pv.reset_seed(s.p_c)
    assert pv.reset_seed(s.p_r) == seed  # The two files differ in replacement.max_per_campaign only.
    seeds = set()
    for directory, plan in ((s.rehearsal, s.plan_r), (s.campaign, s.plan_c)):
        starts = h.starts(directory)
        assert sorted(group for _, group in starts) == sorted({x["group"] for x in plan})
        pids = []
        for (vm, group), steps in starts.items():
            assert [(x["verb"], x["code"]) for x in steps] == [(verb, 0) for verb in GROUP_START], group
            stop, start, reset, pretouch = steps
            seeds.add(int(reset["seed"]))
            qemu = printed(start["out"], "qemu_swap")
            assert printed(stop["out"], "stop")["qemu_pid_before"] != qemu["qemu_pid"]
            boot = h.boots(directory)[vm, group]
            assert {(x["qemu"]["pid"], x["boot"]) for x in boot["sessions"]} == {
                (qemu["qemu_pid"], boot["first"]["boot"])}
            record = read_json(directory / "groups" / f"{group}.json")
            assert holds(record, qemu["qemu_pid"]) and holds(record, qemu["cgroup"]), group
            for step in (reset, pretouch):
                assert holds(record, json.loads(step["out"])) or holds(record, step["out"]), (group, step["verb"])
            pids.append(qemu["qemu_pid"])
        assert len(set(pids)) == len(pids)
    assert seeds == {seed}  # One seeded level: every group of the rehearsal and of the campaign.


@pytest.mark.parametrize("step", GROUP_START)
def test_a_failing_step_of_the_start_of_a_group_rejects_before_the_measured_phase(tmp_path, monkeypatch, step):
    """Design 1.4, the start of a group (1.3 item 6): when one step of the start of the first group of VM a fails
    (labctl exits 1 with its reason), no session is measured and no later step of that start runs: attempt 1 is never
    captured or audited, and the group's start failure (question Q22, package B9b: no rejection of a session, so
    nothing is replaced and the limit is not charged) names its cause group_start, a cause of its own (neither an
    audit rejection nor an incomplete capture, outside the v5 file's replacement.covers), and the step. The runner
    stops by name, before any further capture. Run again, it starts the group again from its beginning, here into the
    same failure, each recorded. A rehearsal: the start of a group is the same in both modes."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol", limit=None)
    p = collection.protocol(protocol)
    first = next(x for x in pv.plan(p, "rehearsal")["sessions"] if x["vm"] == "a")
    h.lab.fail["a", step] = 2  # Both runs below fail at the step (Q22: a run again starts the group again).
    rehearsal = h.init(protocol, "rehearsal", p["name"] + p["rehearsal"]["name_suffix"])
    failed = GROUP_START.index(step)
    for i in range(2):  # Each run starts the group from its beginning and stops at the step: it captures nothing.
        with pytest.raises(ValueError) as stopped, contextlib.redirect_stdout(io.StringIO()):
            c.execute(rehearsal, vm="a", stop_after=1)
        assert [(x["verb"], x["code"]) for x in h.lab.calls if x["verb"] in LAB_STEPS] == [
            *((verb, 0) for verb in GROUP_START[:failed]), (step, 1)] * (i + 1)
        assert h.captures == h.audits == []
        paths = sorted((rehearsal / "groups").glob(first["group"] + ".start-failed-*.json"))
        assert len(paths) == i + 1, paths
        record = read_json(paths[-1])
        assert (record["session"], record["group"], record["step"]) == (
            h.plan_rows(rehearsal)[0]["session_id"], first["group"], step)
        assert record["cause"] == "group_start", record
        assert record["cause"] not in (*collection.REPLACEMENT_CAUSES, *p["replacement"]["covers"]), record
        said = record["reason"]
        named = {verb for verb in GROUP_START if re.search(rf"\b{verb}\b", said)}
        assert step in named and not named & set(GROUP_START[failed + 1:]), record  # Later steps never ran.
        assert c.rejections(rehearsal) == []  # No rejection of a session: nothing is replaced.
        assert said in str(stopped.value)  # The runner stops with the record's reason.
        assert not (h.collections / rehearsal.name / "a" / record["session"]).exists()
    state = read_json(rehearsal / c.vm_file("status.json", "a"))
    assert state["status"] == "stopped" and said in state["message"]


# ====================================================================================================================
# Package B9b (agent T): pause, continuation, early stop and the records of the endings. The design
# dokazy/B9/navrh/NAVRH_B9b.md section 1.4 and its addendum (section 3), written against the contract of its sections
# 1.1 to 1.3: agent R (scripts/campaign.py: the endings and their records, the pause, the one continuation, the
# stopped ending of an early stop, the interleave of the realized boots) and agent Z (features/audit_policy.py
# early_stop with the protocol key audit.early_stop, the audit's count values.marked_rows_by_type, grid_pairs and
# tcn/pecat.py record_stage). Each test names its row of the skeleton's section 4. The campaigns, each on a harness of
# its own, with real archives and the real index, start from the rehearsal of the module's scenario (--estimate-from):
#
#   pause    limit 1. The audit rejects the first session of v5-train-1 (replaced) and of v5-dev-2 (over the limit):
#            the campaign pauses. The continuations init refuses, each by name; the continuation with its written
#            cause, in which the first session of v5-dev-2 is rejected and replaced again (the same limit) and the
#            first session of v5-calibration-1 exhausts the limit a second time: invalid, and finish_corpus refuses
#            it. Beside them a campaign of the group prefix w5- whose first group fails to start (stopped), refused
#            as the predecessor of a continuation.
#   resumed  the same pause; its continuation (one rejection, replaced) runs to the end, and its corpus holds the
#            groups it took over.
#   stops    the operator's stop request during the first capture (stopped), the campaign run again and closed by the
#            operator (closed); an error of the runner (stopped); a failed start of a group (stopped).
#   counted  a complete campaign whose audits count marked rows of an event type under the null bound of the file,
#            rows the register tolerates, and two sessions of the two VMs that run at the same time.
#
# The tests of early stop, of the pause that ends the wait of the other runner, of the mirrored drift and of
# finish_corpus without its record run campaigns of their own.

# Design 1.1: the endings by their kind, with the Slovak names the skeleton gives them. A record names its ending
# (values.ending and its file name) by the kind or by that name; the name stands in the record either way.
ENDINGS = {"complete": "úplná", "paused": "pozastavená", "stopped": "zastavená", "invalid": "neplatná",
           "closed": "uzavretá operátorom"}
ENDING_SCHEMA = "hyptcn3/campaign-ending/1"
HEADER = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.
VALUES = ("campaign", "mode", "protocol_sha256", "plan_sha256", "ending", "cause", "sessions", "planned_sessions",
          "accepted_sessions", "rejected_sessions", "rejections_by_cause", "limit", "replacements_used", "unscored",
          "exceptions", "grids", "deviations", "continues", "interleave")
ROW = ("session", "vm", "role", "group", "scenario", "attempt", "state", "cause", "replacement")
STATES = ("accepted", "rejected", "captured, not judged", "not run")  # F10 of the verification of B9b: four states.
CAUSE = "the archive disk of the collection PC was full (synthetic cause of the test)"  # The cause of a continuation.
CLOSED = "the operator closed the campaign after its stop (synthetic reason of the test)"
STOPPED = "the operator stops the campaign for a look at the host (synthetic reason of the test)"
TYPE = "restart_databazy"  # An event type of the test protocol (config/collection-v5.json events.types).
# Judgment of the test: the bound of early stop it sets for TYPE, and a count of marked rows above it. Since the fix of
# B9b (Q24) the protocol sets a rate per occurrence: RATE, whose 99th percentile of Poisson at one occurrence is BOUND.
BOUND, OVER_BOUND = 2, 3
RATE = 0.3
# Judgment of the test: how long a runner in a thread may take to end once the other runner paused or stopped the
# campaign (it polls every POLL_S s), and the grace of its wait (longer than any test: only a stop request ends it).
JOIN_S, GRACE_S, POLL_S = 30, 600, .05


def attempt(call):
    """(result, None) of call(), or (None, the text of its refusal): a ValueError, or what a command line prints when
    it refuses its arguments (SystemExit)."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            return call(), None
    except ValueError as error:
        return None, str(error)
    except SystemExit as error:
        return None, err.getvalue().strip() or f"exit {error.code}"


def ending_of(record):
    """The kind of the ending a record names (values.ending: the kind, or its Slovak name), else None."""
    named = record["values"].get("ending")
    return next((kind for kind, name in ENDINGS.items() if named in (kind, name)), None)


def records_of(h, directory, kind):
    """[(path, record)] of the records of the ending `kind` of a campaign (Harness.records), oldest first."""
    found = [(path, record) for path, record in h.records(directory) if ending_of(record) == kind]
    return sorted(found, key=lambda item: (str(item[1].get("date")), item[0].name))


def the_record(h, directory, kind):
    """(path, record) of the one record of the ending `kind` of a campaign."""
    found = records_of(h, directory, kind)
    assert len(found) == 1, (kind, [path.name for path, _ in h.records(directory)])
    return found[0]


def strings(tree):
    """Every key and string of a JSON tree."""
    if isinstance(tree, str):
        yield tree
    elif isinstance(tree, dict):
        for key, value in tree.items():
            yield key
            yield from strings(value)
    elif isinstance(tree, list):
        for value in tree:
            yield from strings(value)


def numbers(tree):
    """Every number of a JSON tree (a boolean is none)."""
    if isinstance(tree, (int, float)) and not isinstance(tree, bool):
        yield tree
    elif isinstance(tree, dict):
        for value in tree.values():
            yield from numbers(value)
    elif isinstance(tree, list):
        for value in tree:
            yield from numbers(value)


def text(tree):
    return json.dumps(tree, ensure_ascii=False)


def stage_of(record):
    """(stage, basis) of a record (proposal 11.1, finding N2 of B7c): {stage, basis} (tcn.pecat record_stage) beside
    its provenance or in its values, or a name there with its basis (stage_basis or basis) beside it. A stage beside
    the provenance must be the stage of the values."""
    holders = (record, record.get("values") or {})
    found = [holder["stage"] for holder in holders if isinstance(holder.get("stage"), dict)]
    names = {holder["stage"] for holder in holders if isinstance(holder.get("stage"), str)}
    if found:
        assert names <= {found[0].get("stage")}, (names, found[0])
        return found[0].get("stage"), found[0].get("basis")
    if names:
        assert len(names) == 1, names
        return names.pop(), next((h[key] for h in holders for key in ("stage_basis", "basis") if h.get(key)), None)
    raise AssertionError("the record states no stage (proposal 11.1)")


def per_session(tree, sessions):
    """{session: number} that a JSON tree states for the sessions named: as {session: number}, as {session: {...}}
    with one number (or one under a key of unscored time), or as {"session": session, ...} likewise."""
    found = {}

    def one(node):
        values = list(numbers(node))
        if len(values) != 1 and isinstance(node, dict):
            values = list(numbers({key: value for key, value in node.items() if "unscored" in key}))
        return values[0] if len(values) == 1 else None

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in sessions and one(value) is not None:
                    found[key] = one(value)
            if node.get("session") in sessions:
                value = one({key: value for key, value in node.items() if key != "session"})
                if value is not None:
                    found[node["session"]] = value
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(tree)
    return found


def group_sequences(tree, groups):
    """Every list of a JSON tree read as the groups it names in its order (an item a group's name, or an object with
    its group), for the lists whose every item names one of `groups`."""
    out = []

    def name(item):
        return item if isinstance(item, str) else item.get("group") if isinstance(item, dict) else None

    def walk(node):
        if isinstance(node, list):
            named = [name(item) for item in node]
            if node and all(group in groups for group in named):
                out.append(named)
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
    walk(tree)
    return out


def together(tree, *needles):
    """Whether one text of a JSON tree holds every needle (a text as a part of it, a number as a whole word), or one
    object of it does by its own values (a text needle in one of its texts, a number equal to one of its numbers; the
    values of the objects and lists below it do not count)."""
    def in_text(t, needle):
        return needle in t if isinstance(needle, str) else re.search(rf"(?<![0-9.]){needle}(?![0-9.])", t) is not None

    def in_values(own, needle):
        if isinstance(needle, str):
            return any(isinstance(value, str) and needle in value for value in own)
        return any(not isinstance(value, str) and value == needle for value in own)

    def walk(node):
        if isinstance(node, str):
            return all(in_text(node, needle) for needle in needles)
        if isinstance(node, dict):
            own = [value for value in node.values()
                   if isinstance(value, (str, int, float)) and not isinstance(value, bool)]
            return all(in_values(own, needle) for needle in needles) or any(map(walk, node.values()))
        return isinstance(node, list) and any(map(walk, node))
    return walk(tree)


def says_waited(record, awaited):
    """Whether a record says that a runner waited (the addendum of NAVRH_B9b): a text of it names a wait and the group
    it waited for."""
    return any("wait" in s and awaited in s for s in strings(record))


def exception_counts(block, key):
    """(largest count in one accepted session, accepted sessions over the expected count) of register id `key` in the
    exceptions of a record (Q2): its entry under the id, at the top of the block or under by_id; the number over as
    over or sessions_over_expected, the largest as max_in_one_session, max or largest, else the one number left."""
    entry = (block.get("by_id") or block)[key]
    over = next(entry[name] for name in ("over", "sessions_over_expected") if name in entry)
    named = [entry[name] for name in ("max_in_one_session", "max", "largest") if name in entry]
    if named:
        return named[0], over
    rest = [x for name, x in entry.items() if name not in ("over", "sessions_over_expected", "expected")
            and isinstance(x, (int, float)) and not isinstance(x, bool)]
    return (rest[0] if len(rest) == 1 else None), over


def accepted_audits(directory, manifest):
    """{session: audit values} of every accepted session of a campaign: its own by its checkpoint, and those a
    continuation took over by their frozen audit."""
    out = {}
    for planned in manifest["sessions"]:
        taken = c.taken_over(manifest, planned)
        if taken is not None:
            out[taken["session_id"]] = read_json(Path(taken["audit"]))["values"]
            continue
        done = directory / "attempts" / (c.chain(directory, planned)[-1]["session_id"] + ".done.json")
        if done.exists():
            out[read_json(done)["session"]] = read_json(Path(read_json(done)["audit"]))["values"]
    return out


def expected_rows(directory, manifest):
    """What design 1.1 asks of values.sessions, read from the campaign's own files: ({session: row} of every planned
    session and every attempt of its chain, accepted with its checkpoint, rejected with its rejection record, captured,
    not judged with its session directory and neither (F10 of the verification of B9b), else not run, with the cause
    and the replacement of that record; {planned session: its session in the predecessor} of the sessions a
    continuation took over, accepted)."""
    own, taken = {}, {}
    for planned in manifest["sessions"]:
        was = c.taken_over(manifest, planned)
        if was is not None:
            taken[planned["session_id"]] = was["session_id"]
            continue
        for number, row in enumerate(c.chain(directory, planned), 1):
            sid = row["session_id"]
            rejection = c.rejection_file(directory, sid)
            record = read_json(rejection) if rejection.exists() else {}
            state = ("accepted" if (directory / "attempts" / f"{sid}.done.json").exists() else
                     "rejected" if rejection.exists() else
                     "captured, not judged" if c.session_dir(manifest, row).is_dir() else "not run")
            own[sid] = {"session": sid, **{key: planned.get(key) for key in ("vm", "role", "group", "scenario")},
                        "attempt": number, "state": state, "cause": record.get("cause"),
                        "replacement": record.get("replacement")}
    return own, taken


def expectations(directory):
    """What the record of an ending of the campaign in `directory` states, read from the campaign's own files as they
    are now (assert_ending; a fixture keeps them at an ending after which the campaign goes on)."""
    manifest = read_json(directory / "campaign.json")
    own, taken = expected_rows(directory, manifest)
    return SimpleNamespace(manifest=manifest, own=own, taken=taken, audits=accepted_audits(directory, manifest),
                           rejections=c.rejections(directory), counts=c.rejections_by_cause(directory),
                           limit=read_json(directory / "protocol.json")["replacement"]["max_per_campaign"])


def assert_ending(h, directory, kind, *, expected=None, which=-1):
    """Design 1.1 (agent R's contract): the record `which` (by time) of the ending `kind` of the campaign in
    `directory`, read against what the campaign's files stated at that ending (`expected`, by default expectations
    now); returns (path, record).

    Its identity: kampan_<campaign id>_<ending>_<UTC stamp>.json (the ending by its kind or by its Slovak name, a space
    of which may be an underscore), schema hyptcn3/campaign-ending/1, the provenance header of check E, the Slovak name
    of its ending (the skeleton's) in it. Its stage (finding N2 of B7c, tcn.pecat record_stage; question Q21, accepted
    by the lead 2026-11-24: the ending record asks no ledger at HEAD): with accepted sessions of the sealed roles,
    which the ledger of record holds (the harness's KNIHA and ZAZNAM are one file), generalka for a rehearsal and
    final for a campaign; else suchy with its basis.
    Its values: the keys of 1.1; one row per planned session and attempt with its state, cause and replacement (a
    continuation: its own attempts, the sessions it took over accepted); the planned and accepted sessions; the
    rejected sessions {session, cause, replacement}, the counts by cause and the replacements used (a continuation: at
    least its own); the limit, applied in mode campaign only; the unscored time of every accepted session
    (values.coverage.nominal_unscored_s of its audit) and their total; per register id the largest count in one
    accepted session and the number of accepted sessions over the expected count (Q2); the deviations, and beside
    them or in them the deviation log by path and sha256; the predecessor (null, its id, or an object that names it);
    the interleave's verdict."""
    from features.audit_policy import TOLERATED
    e = expected or expectations(directory)
    manifest = e.manifest
    name, mode = manifest["id"], manifest["mode"]
    predecessor = (manifest.get("continues") or {}).get("campaign")
    found = records_of(h, directory, kind)
    assert found, (kind, [path.name for path, _ in h.records(directory)])
    path, record = found[which]
    identity = re.fullmatch(rf"kampan_{re.escape(name)}_(.+)_([0-9]{{8}}T[0-9]{{6,12}}Z)\.json", path.name)
    assert identity and identity[1] in (kind, ENDINGS[kind], ENDINGS[kind].replace(" ", "_")), path.name
    assert record.get("schema") == ENDING_SCHEMA and set(HEADER) <= set(record), sorted(record)
    assert record["commit"] == manifest["commit"] and type(record["n"]) is int and record["command"], record["commit"]
    assert ENDINGS[kind] in set(strings(record["values"])), (kind, record["values"].get("ending"))
    stage, basis = stage_of(record)
    if any(c.sealed_role(values["role"]) for values in e.audits.values()):  # Q21: the ledger at HEAD is not asked.
        assert stage == ("generalka" if mode == "rehearsal" else "final"), (stage, basis)
    else:
        assert stage == "suchy" and basis, (stage, basis)
    v = record["values"]
    assert set(VALUES) <= set(v), sorted(set(VALUES) - set(v))
    assert (v["campaign"], v["mode"], v["protocol_sha256"]) == (name, mode, manifest["protocol_sha256"])
    named_predecessor = v["continues"].get("campaign") if isinstance(v["continues"], dict) else v["continues"]
    assert named_predecessor == predecessor, v["continues"]
    assert re.fullmatch("[0-9a-f]{64}", str(v["plan_sha256"])), v["plan_sha256"]
    own, taken = e.own, e.taken
    assert all(set(ROW) <= set(row) and row["state"] in STATES for row in v["sessions"]), v["sessions"][:3]
    listed = {}
    for row in v["sessions"]:
        listed.setdefault(row["session"], []).append({key: row[key] for key in ROW})
    assert {sid: listed.get(sid) for sid in own} == {sid: [row] for sid, row in own.items()}
    for planned, held in taken.items():
        assert "accepted" in [row["state"] for sid in {planned, held} for row in listed.get(sid, [])], planned
    others = set(listed) - set(own) - set(taken) - set(taken.values())
    assert all(predecessor and sid.startswith(predecessor + "_") for sid in others), sorted(others)
    accepted = sum(row["state"] == "accepted" for row in own.values()) + len(taken)
    assert (v["planned_sessions"], v["accepted_sessions"]) == (len(manifest["sessions"]), accepted)
    by_session = lambda items: sorted(items, key=lambda item: item["session"])
    mine = by_session({key: r.get(key) for key in ("session", "cause", "replacement")} for r in e.rejections)
    named = by_session({key: item.get(key) for key in ("session", "cause", "replacement")}
                       for item in v["rejected_sessions"])
    counts, used = e.counts, sum(item["replacement"] is not None for item in mine)
    if predecessor is None:
        assert (named, v["rejections_by_cause"], v["replacements_used"]) == (mine, counts, used)
    else:
        assert all(item in named for item in mine), (mine, named)
        assert all(v["rejections_by_cause"].get(cause, 0) >= n for cause, n in counts.items()), v["rejections_by_cause"]
        assert type(v["replacements_used"]) is int and v["replacements_used"] >= used, v["replacements_used"]
    assert type(v["limit"]) is dict and v["limit"].get("applied") is (mode == "campaign"), v["limit"]
    if mode == "campaign":
        assert holds(v["limit"], e.limit), v["limit"]
    audits = e.audits
    unscored = {sid: values["coverage"]["nominal_unscored_s"] for sid, values in audits.items()}
    assert per_session(v["unscored"], unscored) == unscored, v["unscored"]
    if audits:
        assert any(math.isclose(x, sum(unscored.values())) for x in numbers(v["unscored"])), v["unscored"]
    for key in TOLERATED:
        largest, over = exception_counts(v["exceptions"], key)
        assert over == sum(values["exceptions"][key]["over"] for values in audits.values()), (key, largest, over)
        assert largest == max((values["exceptions"][key]["observed"] for values in audits.values()), default=None) \
            or not audits and largest in (None, 0), (key, largest, over)
    assert isinstance(v["grids"], (list, dict)), v["grids"]
    beside = text({key: value for key, value in v.items() if key != "sessions"})
    assert "docs/ODCHYLKY_V5.sk.md" in beside and digest(DEVIATION_LOG) in beside, "the deviation log is not named"
    assert isinstance(v["deviations"], (list, dict)), v["deviations"]
    assert type(v["interleave"]) is dict and type(v["interleave"].get("ok")) is bool, v["interleave"]
    return path, record


def paused_campaign(h, scenario, name):
    """Skeleton test 3 (design 1.2): campaign `name` of limit 1 whose audit rejects the first session of v5-train-1
    (attempt 2 replaces it) and of v5-dev-2 (the second rejection, over the limit); both runners in turn until neither
    moves. Returns (directory, protocol, plan, refusals of the runners)."""
    protocol = h.protocol(f"protocol-{name}", limit=1)
    plan = pv.plan(collection.protocol(protocol), "campaign")["sessions"]
    for group in ("v5-train-1", "v5-dev-2"):
        row = first_of(plan, group)
        h.reject.add((name, group, row["scenario"], 1))
    directory = h.init(protocol, "campaign", name, estimate_from=scenario.rehearsal)
    _, refused = h.run_to_end(directory)
    return directory, protocol, plan, refused


@pytest.fixture(scope="module")
def pause(scenario, tmp_path_factory):
    """The campaign pause of the comment above, the continuations init refuses, the continuation to its second
    exhaustion and the stopped campaign of the prefix w5-; the patches of the harness are undone before the tests read
    them."""
    with pytest.MonkeyPatch.context() as mp:
        h = Harness(tmp_path_factory.mktemp("pauza"), mp)
        campaign, protocol, plan, refused = paused_campaign(h, scenario, "pauza")
        after = len(h.captures)
        for _ in range(2):  # Each runner once more: a paused campaign captures nothing.
            for vm in VMS:
                attempt(lambda: h.step(campaign, vm))
        rerun = h.captures[after:]
        # A campaign that ended other than paused: a group of prefix w5- fails to start (stopped).
        other = h.protocol("protocol-w5", limit=1, edit=lambda doc: doc.update(group_prefix="w5-"))
        h.lab.fail["a", "start"] = 1
        stopped = h.init(other, "campaign", "w5-zastavena", estimate_from=scenario.rehearsal)
        attempt(lambda: h.step(stopped, "a"))
        h.lab.start_again("a")
        # The fix round of B9b (F2): a continuation compares the measurement code file by file, so a file of it changes.
        sources = collection.measurement_sources()
        refusals = {}
        for case, name, cause, source, changes in (
                ("no_cause", "bez-priciny", None, campaign, {}),
                ("blank_cause", "prazdna-pricina", "   ", campaign, {}),
                ("measurement_changed", "iny-merac", CAUSE, campaign,
                 {(collection, "measurement_sources"): lambda: {**sources, "scripts/collection.py": "0" * 64}}),
                ("lab_changed", "iny-lab", CAUSE, campaign,
                 {(collection, "lab_sha256"): lambda: {"lab/zmeneny.py": "0" * 64}}),
                ("not_paused", "po-zastaveni", CAUSE, stopped, {})):
            with pytest.MonkeyPatch.context() as changed:
                for (module, attribute), value in changes.items():
                    changed.setattr(module, attribute, value)
                _, refusals[case] = attempt(lambda: h.init(other if source == stopped else protocol, "campaign", name,
                                                           estimate_from=scenario.rehearsal, continues=source,
                                                           cause=cause))
            refusals[case] = (refusals[case], name)
        # The good input: the continuation with its written cause; its own rejections (the same limit 1 again).
        continued = "pauza-2"
        h.reject.add((continued, "v5-dev-2", first_of(plan, "v5-dev-2")["scenario"], 1))
        h.reject.add((continued, "v5-calibration-1", first_of(plan, "v5-calibration-1")["scenario"], 1))
        continuation, accepted = attempt(lambda: h.init(protocol, "campaign", continued,
                                                        estimate_from=scenario.rehearsal, continues=campaign,
                                                        cause=CAUSE))
        states = finish = None
        if continuation is not None:
            states, _ = h.run_to_end(continuation)
            manifest, p = c.load_campaign(continuation)
            view, _ = c.vm_view(manifest, p, "a")
            reports = [c.final_report(continuation, manifest, row) for row in manifest["sessions"]
                       if c.finished(continuation, manifest, row)]
            _, finish = attempt(lambda: c.finish_corpus(continuation, view, p, reports))
            for case, again, source in (("continued", "pauza-3", continuation),
                                        ("second_continuation", "pauza-4", campaign)):
                _, refused_again = attempt(lambda: h.init(protocol, "campaign", again, estimate_from=scenario.rehearsal,
                                                          continues=source, cause=CAUSE))
                refusals[case] = (refused_again, again)
    return SimpleNamespace(h=h, campaign=campaign, protocol=protocol, plan=plan, refused=refused, rerun=rerun,
                           stopped=stopped, refusals=refusals, continuation=continuation, accepted=accepted,
                           states=states, finish=finish)


@pytest.fixture(scope="module")
def resumed(scenario, tmp_path_factory):
    """The campaign resumed of the comment above: the pause of pause, its continuation (the first session of v5-dev-2
    rejected and replaced) to the end of the plan."""
    with pytest.MonkeyPatch.context() as mp:
        h = Harness(tmp_path_factory.mktemp("obnova"), mp)
        campaign, protocol, plan, _ = paused_campaign(h, scenario, "obnova")
        continued = "obnova-2"
        h.reject.add((continued, "v5-dev-2", first_of(plan, "v5-dev-2")["scenario"], 1))
        continuation, accepted = attempt(lambda: h.init(protocol, "campaign", continued,
                                                        estimate_from=scenario.rehearsal, continues=campaign,
                                                        cause=CAUSE))
        if continuation is not None:
            h.run(continuation)
    return SimpleNamespace(h=h, campaign=campaign, protocol=protocol, plan=plan, continuation=continuation,
                           accepted=accepted)


@pytest.fixture(scope="module")
def stops(scenario, tmp_path_factory):
    """The campaigns of stops of the comment above (VM a only), with what their files state at each ending
    (expectations): zastavena, whose operator requests a stop while its first session is captured, then closed;
    chyba, whose first capture fails (an error of the runner), then run again once the cause is gone (today's resume:
    it captures that session) and closed; start, whose first group fails to start (labctl start)."""
    with pytest.MonkeyPatch.context() as mp:
        h = Harness(tmp_path_factory.mktemp("zastavenia"), mp)
        protocol = h.protocol("protocol-zastavenia", limit=1)
        first = pv.plan(collection.protocol(protocol), "campaign")["sessions"][0]
        key = (first["group"], first["scenario"], 1)
        stopped = h.base / "zastavena"
        # The operator, while the first session is captured: python3 scripts/campaign.py request-stop with a reason.
        h.during[("zastavena", *key)] = lambda: c.main(["request-stop", str(stopped), "--vm", "a",
                                                        "--reason", STOPPED])
        h.init(protocol, "campaign", stopped.name, estimate_from=scenario.rehearsal)
        _, operator = attempt(lambda: c.execute(stopped, vm="a"))
        state, at_stop = h.status(stopped, "a"), expectations(stopped)
        captured = [x["sid"] for x in h.of(stopped)]
        _, closing = attempt(lambda: c.close(stopped, CLOSED))
        at_close = expectations(stopped)
        error = h.base / "chyba"
        h.fail_capture.add(("chyba", *key))
        h.init(protocol, "campaign", error.name, estimate_from=scenario.rehearsal)
        _, failed = attempt(lambda: c.execute(error, vm="a"))
        at_error = expectations(error)
        h.fail_capture.clear()  # The operator removed the cause; run again, the runner resumes.
        _, resumed = attempt(lambda: h.step(error, "a"))
        resumed_captures = [x["sid"] for x in h.of(error)]
        _, closing_error = attempt(lambda: c.close(error, CLOSED))
        at_close_error = expectations(error)
        start = h.base / "start"
        h.lab.fail["a", "start"] = 1
        h.init(protocol, "campaign", start.name, estimate_from=scenario.rehearsal)
        _, refused_start = attempt(lambda: c.execute(start, vm="a"))
        at_start = expectations(start)
        h.lab.start_again("a")
    return SimpleNamespace(h=h, stopped=stopped, operator=operator, state=state, captured=captured, closing=closing,
                           error=error, failed=failed, resumed=resumed, resumed_captures=resumed_captures,
                           closing_error=closing_error, group_start=start, refused_start=refused_start,
                           expected={"stopped_by_the_operator": at_stop, "closed_by_the_operator": at_close,
                                     "stopped_by_an_error": at_error, "closed_after_a_resume": at_close_error,
                                     "stopped_at_the_start_of_a_group": at_start})


@pytest.fixture(scope="module")
def counted(scenario, tmp_path_factory):
    """The campaign counted of the comment above (limit 1, the bounds of early stop null as in the file): marked rows
    of TYPE in the first session of v5-dev-1, over the bound a test sets elsewhere; tolerated invalid rows 1 in the
    first session of v5-train-1 and 3 in the first session of v5-train-2 against the expected count 1 of the register;
    tolerated requests inside an event window 2 in the first session of v5-calibration-1 against the null expected
    count; the second session of v5-train-2 (VM b) starts 2.5 s after the second session of v5-train-1 (VM a), so the
    two run at once with grid phases 0 and 2.5 s."""
    def edit(doc):
        doc["exceptions"]["invalid_rows"]["expected"] = 1
    with pytest.MonkeyPatch.context() as mp:
        h = Harness(tmp_path_factory.mktemp("pocty"), mp)
        protocol = h.protocol("protocol-pocty", limit=1, edit=edit)
        p = collection.protocol(protocol)
        plan = pv.plan(p, "campaign")["sessions"]
        key = lambda row: (row["group"], row["scenario"], 1)
        first = {group: first_of(plan, group) for group in ("v5-train-1", "v5-train-2", "v5-dev-1", "v5-calibration-1")}
        h.marked[key(first["v5-dev-1"])] = {TYPE: OVER_BOUND}
        h.tolerated[key(first["v5-train-1"])] = {"invalid_rows": 1}
        h.tolerated[key(first["v5-train-2"])] = {"invalid_rows": 3}
        h.tolerated[key(first["v5-calibration-1"])] = {"event_window_requests": 2}
        second = [x for x in plan if x["group"] == "v5-train-1"][1], [x for x in plan if x["group"] == "v5-train-2"][1]
        h.overlap[key(second[1])] = (key(second[0]), 2.5)
        campaign = h.init(protocol, "campaign", "pocty", estimate_from=scenario.rehearsal)
        states = h.run(campaign)
    together = [next(x["sid"] for x in h.of(campaign) if (x["group"], x["scenario"]) == key(row)[:2])
                for row in second]
    return SimpleNamespace(h=h, campaign=campaign, protocol=protocol, p=p, plan=plan, first=first, states=states,
                           together=together)


def test_a_rejection_over_the_limit_pauses_the_campaign_with_its_record(pause):
    """Skeleton section 4, test 3 (design 1.2, proposal 7.5, skeleton row pozastavenie): in mode campaign the second
    rejection of a campaign of limit 1 is over the limit and pauses the campaign: its runner's state is paused and the
    one record of the ending pozastavená is written (the shape of design 1.1: the rejected sessions by cause, the
    one replacement used, the limit applied, the pause and its cause among the deviations); the other runner stops at
    its next check, and run again neither runner captures anything."""
    s, h = pause, pause.h
    plan_rows = h.plan_rows(s.campaign)
    replaced, over = (first_of(plan_rows, group)["session_id"] for group in ("v5-train-1", "v5-dev-2"))
    assert h.status(s.campaign, "a")["status"] == "paused", h.status(s.campaign, "a")
    assert h.status(s.campaign, "b").get("status") not in ("running", "complete"), h.status(s.campaign, "b")
    paused_at = next(x["order"] for x in h.of(s.campaign) if x["sid"] == over)
    assert [x["sid"] for x in h.of(s.campaign) if x["order"] > paused_at] == [] and s.rerun == []
    assert [(r["session"], r["cause"], r["replacement"]) for r in c.rejections(s.campaign)] == [
        (replaced, "audit_rejected", replaced + "-r1"), (over, "audit_rejected", None)]
    path, record = assert_ending(h, s.campaign, "paused")
    later = [other.name for other, doc in h.records(s.campaign) if str(doc.get("date")) > str(record.get("date"))]
    assert later == [] and len(records_of(h, s.campaign, "paused")) == 1, later
    v = record["values"]
    assert (v["rejections_by_cause"], v["replacements_used"], v["accepted_sessions"]) == ({"audit_rejected": 2}, 1, 6)
    assert v["cause"] and v["cause"] in text(v["deviations"]), (v["cause"], v["deviations"])
    assert v["continues"] is None and v["limit"]["applied"] is True


def test_a_pause_ends_the_wait_of_the_other_runner(scenario, tmp_path, monkeypatch):
    """Skeleton section 4, test 3, and the addendum of NAVRH_B9b (F5 of B9a: inside the shared rank of the test roles
    a runner waits until the other VMs have started every test group that precedes its next one in the plan): VM b
    runs its first test group and waits, in a thread, as on the collection PC, for VM a's v5-test_benign-2; VM a's
    first session of v5-test_controls-1 is rejected over the limit 0 and pauses the campaign. The waiting runner stops
    at its next check through the stop request, without a capture; the one new record is that of the pause, and it
    says that VM b waited (for v5-test_benign-2)."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-cakanie", limit=0)
    plan = pv.plan(collection.protocol(protocol), "campaign")["sessions"]
    h.reject.add(("cakanie", "v5-test_controls-1", first_of(plan, "v5-test_controls-1")["scenario"], 1))
    campaign = h.init(protocol, "campaign", "cakanie", estimate_from=scenario.rehearsal)
    met = meet_a_waiting_runner(h, monkeypatch, campaign)
    assert h.status(campaign, "a")["status"] == "paused", (met.ran, h.status(campaign, "a"))
    assert [x["vm"] for x in h.captures[met.captured:]] == ["a"]  # VM a's rejected session only.
    assert h.status(campaign, "b").get("status") != "running", h.status(campaign, "b")
    new = [(path, record) for path, record in h.records(campaign) if path not in met.before]
    assert [ending_of(record) for _, record in new] == ["paused"], [p.name for p, _ in new]
    assert says_waited(new[0][1], "v5-test_benign-2"), new[0][1]
    assert_ending(h, campaign, "paused")


def meet_a_waiting_runner(h, monkeypatch, campaign):
    """The addendum of NAVRH_B9b: both runners in turn to the test roles, VM b alone through its first test group
    until it waits inside the shared rank; then VM b's runner in a thread (Harness.background: collection.Interrupts
    patched, the grace of its wait GRACE_S, its poll POLL_S), waiting there (stage role-wait), and VM a's runner here
    (execute, no stop_after). VM b's runner must end within JOIN_S s once VM a's runner returned; if it does not, a
    stop request ends it and the test fails. Returns what the test reads: before (the records then), ran (VM a's
    result or refusal), outcome (VM b's), captured (the captures before)."""
    h.until_interleaved(campaign)
    assert h.alone(campaign, "b")["status"] == "stopped"
    assert h.pending(campaign, "b")[0]["group"] == "v5-test_controls-2"
    monkeypatch.setattr(collection, "Interrupts", NoSignals)
    monkeypatch.setattr(c, "START_GRACE_S", GRACE_S)
    monkeypatch.setattr(c, "WAIT_POLL_S", POLL_S)
    before, captured = [path for path, _ in h.records(campaign)], len(h.captures)
    waiting = h.background(campaign, "b")
    ran = (None, "VM a's runner did not run")
    try:
        h.wait_for(campaign, "b", "role-wait", runner=waiting)
        ran = attempt(lambda: c.execute(campaign, vm="a"))
    finally:
        try:
            outcome = waiting.join(JOIN_S)
        except AssertionError as late:
            (campaign / c.vm_file("stop-request.json", "b")).write_text("{}")
            waiting.join(JOIN_S)
            raise AssertionError(f"the waiting runner of VM b did not stop when VM a's ended ({ran})") from late
    return SimpleNamespace(before=before, ran=ran, outcome=outcome, captured=captured)


# The reason each refusal of a continuation names (a pattern of its text, and one it must not hold): the written
# cause; the measurement code and the lab by the functions that hash them (the contract's names), each apart.
REFUSED = {"no_cause": (r"--cause", None), "blank_cause": (r"--cause", None),
           "measurement_changed": (r"measurement_sha256", r"lab_sha256"),
           "lab_changed": (r"lab_sha256", r"measurement_sha256"), "not_paused": (r"not paused|paus", None),
           "continued": (r"continu", None), "second_continuation": (r"already has a continuation|continued once", None)}


@pytest.mark.parametrize("case", REFUSED)
def test_a_continuation_is_refused_by_name(pause, case):
    """Skeleton section 4, test 3 (design 1.2, skeleton row jedno pokračovanie): init --continue of the paused campaign
    is refused without a written cause (no --cause, and a blank one: no default fills it in) and when the hash of the
    measurement code (scripts/gates.py measurement_sha256) or of the lab (scripts/collection.py lab_sha256) differs
    from the one the paused campaign froze at its init; a campaign that ended other than paused (stopped: its first
    group failed to start) is refused as a predecessor, and so is the continuation itself (a continuation is never
    continued; it ended invalid), and a second continuation of the paused campaign (one continuation). Each refusal
    names its reason and leaves no campaign. The good input is the continuation of
    test_a_continuation_has_the_same_limit_and_a_second_exhaustion_makes_it_invalid."""
    s = pause
    assert case in s.refusals, (case, s.accepted)  # The last two cases need the accepted continuation.
    refusal, name = s.refusals[case]
    named, other = REFUSED[case]
    assert refusal is not None and re.search(named, refusal, re.IGNORECASE), refusal
    assert other is None or not re.search(other, refusal), refusal
    assert "unrecognized arguments" not in refusal, refusal  # init knows --cause: the refusal is its own.
    assert not (s.h.base / name).exists() and not (s.h.archive / "campaigns" / name).exists()


def test_a_continuation_has_the_same_limit_and_a_second_exhaustion_makes_it_invalid(pause):
    """Skeleton section 4, test 3 (design 1.2, proposal 7.5: one continuation with the same limit when the cause lies
    outside the measurement code and the lab; else the campaign is invalid): the continuation with its written cause
    is accepted and names the paused campaign; it takes over the groups the paused campaign completed and captures the
    others; its limit is the same 1 again, so its first rejection is replaced, and its second exhausts the limit a
    second time: the state invalid and the record of the ending neplatná, with the continuation and its cause and the
    invalidation among the deviations; finish_corpus refuses the invalid campaign by name; neither runner captures
    after it."""
    s, h = pause, pause.h
    assert s.accepted is None and s.continuation is not None, s.accepted
    manifest = read_json(s.continuation / "campaign.json")
    assert manifest["continues"]["campaign"] == s.campaign.name
    assert {r["group"] for r in manifest["sessions"] if c.taken_over(manifest, r)} == {"v5-train-1", "v5-train-2"}
    rejections = c.rejections(s.continuation)
    assert [(r["group"], r["replacement"] is not None) for r in rejections] == [("v5-dev-2", True),
                                                                               ("v5-calibration-1", False)]
    assert s.states["a"]["status"] == "invalid" and s.states["b"].get("status") not in ("running", "complete")
    last = next(x["order"] for x in h.of(s.continuation) if x["group"] == "v5-calibration-1")
    assert [x["sid"] for x in h.of(s.continuation) if x["order"] > last] == []
    path, record = assert_ending(h, s.continuation, "invalid")
    assert len(records_of(h, s.continuation, "invalid")) == 1
    v = record["values"]
    assert CAUSE in text(v["deviations"]) and v["cause"] and v["cause"] in text(v["deviations"]), v["deviations"]
    assert s.finish is not None and re.search(r"invalid|neplatn", s.finish, re.IGNORECASE), s.finish
    assert not (s.continuation / "corpus.json").exists()


def test_the_corpus_of_a_continuation_passes_the_production_check(resumed):
    """Design 1.4 and the B2 panel item (dokazy/B2/panel: a corpus of a continuation was never run through
    validate_index): the continuation of the paused campaign runs to the end; its index holds every planned row once,
    the sessions of the groups it took over (v5-train-1 with the replacement attempt 2 of the paused campaign, and
    v5-train-2) by their own IDs and its own sessions for every other group, names the campaign it continues, and
    passes the production check of training (in finish_corpus's subprocess and here again)."""
    from safeguard.training import validate_index
    s = resumed
    assert s.accepted is None and s.continuation is not None, s.accepted
    manifest = read_json(s.continuation / "campaign.json")
    taken = {r["session_id"]: c.taken_over(manifest, r) for r in manifest["sessions"] if c.taken_over(manifest, r)}
    assert {r["group"] for r in manifest["sessions"] if r["session_id"] in taken} == {"v5-train-1", "v5-train-2"}
    doc = read_json(s.continuation / "corpus.json")
    assert (doc["complete"], doc["allocation_rule"], doc["plan_mode"], doc["allocation_mismatches"]) == (
        True, "plan:campaign", "campaign", [])
    assert sorted((r["group"], r["position"], r["scenario"], r["vm"]) for r in doc["sessions"]) == sorted(
        (x["group"], x["position"], x["scenario"], x["vm"]) for x in s.plan)
    held = {r["id"]: r for r in doc["sessions"]}
    old = {t["session_id"] for t in taken.values()}
    assert old <= set(held) and all(sid.startswith(s.campaign.name + "_") for sid in old)
    replaced = first_of(s.h.plan_rows(s.campaign), "v5-train-1")["session_id"] + "-r1"
    assert replaced in old and held[replaced]["position"] == first_of(s.plan, "v5-train-1")["position"]
    own = set(held) - old
    assert all(sid.startswith(s.continuation.name + "_") for sid in own) and len(own) == len(s.plan) - len(old)
    assert doc["continues"]["campaign"] == s.campaign.name and doc["continues"]["taken_over_sessions"] == sorted(old)
    _, _, records = validate_index(s.continuation / "corpus.json")
    assert Counter(r["role"] for r in records) == dict.fromkeys(pv.ROLES, 6)
    path, record = assert_ending(s.h, s.continuation, "complete")
    assert CAUSE in text(record["values"]["deviations"])


@pytest.mark.parametrize("rule", ["periodicity", "bound"])
def test_early_stop_stops_the_campaign(scenario, tmp_path, monkeypatch, rule):
    """Skeleton section 4, test 4 (design 1.3, proposal 7.5 and 10.9, skeleton row skoré zastavenie): after the audit
    of VM a's first session of v5-test_controls-1 the rule of early stop stops the campaign, though its limit 1 would
    replace a rejection: periodicity, the session rejected with the code periodicity (features/acceptance.py); bound,
    the session accepted with a count of marked rows of an event type in its one occurrence that brings the campaign's
    count over the bound of the protocol's rate for that type (audit.early_stop.marked_rows_rate_per_type: RATE gives
    the bound BOUND at one occurrence, the fix of B9b by Q24). VM a's state is stopped; VM b, waiting in a thread for
    VM a's v5-test_benign-2 (as in the pause), stops at its next check; nothing is captured after that session; the
    one new record is that of the ending zastavená, which names the rule and the session (and the type, its count and
    its bound)."""
    def edit(doc):
        if rule == "bound":
            doc["audit"]["early_stop"]["marked_rows_rate_per_type"][TYPE] = RATE
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-skore", limit=1, edit=edit)
    row = first_of(pv.plan(collection.protocol(protocol), "campaign")["sessions"], "v5-test_controls-1")
    key = ("skore", row["group"], row["scenario"], 1)
    if rule == "periodicity":
        h.reject.add(key)
        h.codes[key] = PERIODICITY
    else:
        h.marked[key] = {TYPE: OVER_BOUND}
    campaign = h.init(protocol, "campaign", "skore", estimate_from=scenario.rehearsal)
    met = meet_a_waiting_runner(h, monkeypatch, campaign)
    sid = first_of(h.plan_rows(campaign), "v5-test_controls-1")["session_id"]
    assert [x["sid"] for x in h.captures[met.captured:]] == [sid]
    assert h.accepted(sid) is (rule == "bound")
    assert h.status(campaign, "a")["status"] == "stopped" and h.status(campaign, "b").get("status") != "running"
    new = [(path, record) for path, record in h.records(campaign) if path not in met.before]
    assert [ending_of(record) for _, record in new] == ["stopped"], [p.name for p, _ in new]
    path, record = assert_ending(h, campaign, "stopped")
    # Beside the rows of the sessions and the texts of the rules: the session named with the early stop, and its rule
    # (periodicity; or the type, its count and its bound) in one text or one object.
    rest = {key: value for key, value in record["values"].items() if key not in ("sessions", "rules")}
    decision = together(rest, sid, "periodicity") if rule == "periodicity" else together(rest, TYPE, OVER_BOUND, BOUND)
    assert record["values"]["cause"] and together(rest, sid, "early") and decision, record["values"]["cause"]


def test_a_null_bound_prints_the_count_and_does_not_stop(counted):
    """Skeleton section 4, test 4 (design 1.3, skeleton row skoré zastavenie: null until G3b, printed, no stop): the
    audit of the first session of v5-dev-1 counts marked rows of an event type over any small bound, but the
    protocol's bound is null as in the file; the count is printed (the runner's output or its state) and the campaign
    runs to its end with the one record of the ending úplná and no stopped ending."""
    s, h = counted, counted.h
    assert s.p["audit"]["early_stop"]["marked_rows_rate_per_type"][TYPE] is None
    assert {vm: state["status"] for vm, state in s.states.items()} == dict.fromkeys(VMS, "complete")
    sid = next(x["sid"] for x in h.of(s.campaign) if (x["group"], x["scenario"]) == (
        s.first["v5-dev-1"]["group"], s.first["v5-dev-1"]["scenario"]))
    audit = next(a for a in h.audits if a["sid"] == sid)
    assert read_json(Path(audit["report"]))["values"]["marked_rows_by_type"][TYPE] == OVER_BOUND
    shown = [line for x in h.printed if x["campaign"] == s.campaign.name for line in x["out"].splitlines()]
    shown += [text(read_json(path)) for path in sorted((s.campaign / "events").glob("*.json"))]
    assert any(re.search(rf"{TYPE}[^0-9]{{0,40}}\b{OVER_BOUND}\b", line) for line in shown), shown[-5:]
    the_record(h, s.campaign, "complete")
    assert records_of(h, s.campaign, "stopped") == []


CASES = {  # Skeleton test 5: the case, its fixture, the campaign of the fixture, its ending and which record of it.
    "complete": ("scenario", "campaign", "complete", -1),
    "complete_rehearsal": ("scenario", "rehearsal", "complete", -1),
    "complete_continuation": ("resumed", "continuation", "complete", -1),
    "complete_with_counts": ("counted", "campaign", "complete", -1),
    "paused": ("pause", "campaign", "paused", -1),
    "stopped_by_the_operator": ("stops", "stopped", "stopped", 0),
    "stopped_by_an_error": ("stops", "error", "stopped", 0),
    "stopped_at_the_start_of_a_group": ("stops", "group_start", "stopped", 0),
    "invalid": ("pause", "continuation", "invalid", -1),
    "closed_by_the_operator": ("stops", "stopped", "closed", -1),
    "closed_after_a_resume": ("stops", "error", "closed", -1),
}


@pytest.mark.parametrize("case", CASES)
def test_every_ending_leaves_its_record(request, case):
    """Skeleton section 4, test 5 (design 1.1, skeleton row záznam pri uzavretí): each of the five endings leaves its
    record of the shape of design 1.1 (assert_ending, against the campaign's files at that ending): complete (a
    campaign, a rehearsal, a continuation, a campaign with counts), paused, stopped (by the operator's stop request,
    by an error of the runner, at a failed start of a group), invalid and closed by the operator. A complete campaign
    has one record of the ending úplná and its interleave holds; the operator's stop and the closure's reason are among
    the deviations; the error and the failed start are the causes of their stopped endings; a stopped campaign runs
    again once its cause is gone (today's resume) and its next ending writes a record of its own."""
    fixture, attribute, ending, which = CASES[case]
    s = request.getfixturevalue(fixture)
    directory = getattr(s, attribute)
    expected = getattr(s, "expected", {}).get(case)
    path, record = assert_ending(s.h, directory, ending, expected=expected, which=which)
    v = record["values"]
    if ending == "complete":
        assert len(records_of(s.h, directory, "complete")) == 1
        assert v["interleave"]["ok"] is True and v["accepted_sessions"] == v["planned_sessions"]
    if case == "stopped_by_the_operator":
        assert s.operator is None and s.state["status"] == "stopped" and len(s.captured) == 1, (s.operator, s.state)
        assert re.search(r"stop", v["cause"], re.IGNORECASE) and STOPPED in text(v["deviations"]), v["cause"]
    if case == "closed_by_the_operator":
        assert s.closing is None and CLOSED in text(v["deviations"]), v["deviations"]
    if case == "stopped_by_an_error":
        assert s.failed is not None and "capture could not start" in v["cause"], (s.failed, v["cause"])
    if case == "closed_after_a_resume":
        assert (s.resumed, s.closing_error, len(s.resumed_captures)) == (None, None, 1)
        stopped, = (r for _, r in records_of(s.h, directory, "stopped")[:1])
        assert (stopped["values"]["accepted_sessions"], v["accepted_sessions"]) == (0, 1)
    if case == "stopped_at_the_start_of_a_group":
        assert s.refused_start is not None and re.search(r"group_start|start of the group", v["cause"]), v["cause"]
    if case == "paused":
        assert v["cause"] in text(v["deviations"])


def test_the_record_counts_the_tolerated_rows_by_register_id(counted):
    """The skeleton's addendum on Q2 (design 1.1, features.audit_policy.exceptions_record): per register id the record
    of the ending has the largest count in one accepted session and the number of accepted sessions over the expected
    count (over): invalid rows 1 and 3 in two sessions against the expected count 1 give the largest 3 and over 1;
    requests inside an event window 2 in one session against the null expected count give the largest 2 and over 0
    (null in the register gives 0), and so do the other ids, whose expected count is null as well."""
    from features.audit_policy import TOLERATED
    s = counted
    _, record = the_record(s.h, s.campaign, "complete")
    exceptions = record["values"]["exceptions"]
    found = {key: exception_counts(exceptions, key) for key in TOLERATED}
    assert (found["invalid_rows"], found["event_window_requests"]) == ((3, 1), (2, 0)), exceptions
    assert all(found[key][1] == 0 for key in TOLERATED if key != "invalid_rows"), exceptions  # Null: none over.


def test_the_record_pairs_the_grids_of_two_sessions_that_run_at_once(counted):
    """Skeleton row mriežky dvoch VM (design 1.3 grid_pairs, which agent R puts into the record): of the campaign's
    sessions only the two that ran at the same time on the two VMs (the second sessions of v5-train-1 on VM a and of
    v5-train-2 on VM b, 2.5 s apart) are paired in the record's grids, with both grid phases (0 and 2.5 s) and their
    mutual shift modulo interval_s (2.5 s)."""
    s = counted
    _, record = the_record(s.h, s.campaign, "complete")
    grids = record["values"]["grids"]
    named = {x["sid"] for x in s.h.of(s.campaign) if x["sid"] in text(grids)}
    assert named == set(s.together), grids
    assert holds(grids, 2.5) and holds(grids, 0.0), grids


def test_finish_corpus_without_the_record_of_the_complete_ending_fails(scenario, tmp_path, monkeypatch):
    """Skeleton section 4, test 5 (design 1.1: the record comes first, and then the corpus): a complete campaign
    leaves its record of the ending úplná and its index; without that record the real finish_corpus refuses by name and
    writes no index; with it back the same call builds the same index again."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-zaznam", limit=0)
    campaign = h.init(protocol, "campaign", "zaznam", estimate_from=scenario.rehearsal)
    h.run(campaign)
    (path, _), = records_of(h, campaign, "complete")
    index = read_json(campaign / "corpus.json")
    manifest, p = c.load_campaign(campaign)
    view, _ = c.vm_view(manifest, p, "b")
    reports = [c.final_report(campaign, manifest, row) for row in manifest["sessions"]]
    for built in (campaign / "corpus.json", Path(manifest["archive_dir"]) / "corpus.json"):
        built.unlink()
    aside = tmp_path / path.name
    path.rename(aside)
    _, refusal = attempt(lambda: c.finish_corpus(campaign, view, p, reports))
    assert refusal is not None and re.search(r"record|záznam", refusal), refusal
    assert not (campaign / "corpus.json").exists()
    aside.rename(path)
    _, refusal = attempt(lambda: c.finish_corpus(campaign, view, p, reports))
    assert refusal is None and read_json(campaign / "corpus.json") == index, refusal


def test_tcn_finalne_reads_the_record_of_the_complete_ending(scenario, resumed):
    """Design 1.4 (PRE_B9: the record tcn.finalne reads; tcn/finalne.py campaign_record, CAMPAIGN_RULE): the record of
    the ending úplná of the campaign, of its rehearsal and of a continuation, with the corpus index of each, gives
    tcn.finalne the planned sessions, the accepted ones (the sessions of the index) and the rejected ones by cause and
    replacement, as the record lists them and the campaign's own rejections are among them; the record of the pause
    that the continuation continued is not the record of its corpus and is refused."""
    from tcn import finalne
    for h, directory in ((scenario.h, scenario.campaign), (scenario.h, scenario.rehearsal),
                         (resumed.h, resumed.continuation)):
        path, record = the_record(h, directory, "complete")
        index = read_json(directory / "corpus.json")
        read = finalne.campaign_record(path, index)
        listed = record["values"]["rejected_sessions"]
        assert (read["record"], read["sha256"], read["planned_sessions"], read["accepted_sessions"]) == (
            str(path.resolve()), digest(path), len(read_json(directory / "campaign.json")["sessions"]),
            len(index["sessions"]))
        assert (read["rejected_sessions"], read["replaced_sessions"]) == (
            len(listed), sum(item["replacement"] is not None for item in listed))
        by_cause = {}
        for item in listed:
            row = by_cause.setdefault(item["cause"], {"rejected": 0, "replaced": 0, "not_replaced": 0, "sessions": []})
            row["rejected"] += 1
            row["replaced" if item["replacement"] else "not_replaced"] += 1
            row["sessions"].append({"session": item["session"], "replacement": item["replacement"]})
        assert read["by_cause"] == dict(sorted(by_cause.items()))
        held = {(x["session"], x["replacement"]) for row in read["by_cause"].values() for x in row["sessions"]}
        assert {(r["session"], r["replacement"]) for r in c.rejections(directory)} <= held
    paused, _ = the_record(resumed.h, resumed.campaign, "paused")
    with pytest.raises(ValueError, match="^" + re.escape(
            f"{paused.resolve()}: the record of the ending 'paused' of campaign '{resumed.campaign.name}' is not the "
            "record of a corpus: only the record of the complete ending is (CAMPAIGN_RULE)") + "$"):
        finalne.campaign_record(paused, read_json(resumed.continuation / "corpus.json"))


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_the_record_reports_a_test_controls_boot_after_every_test_benign_boot(scenario, tmp_path, monkeypatch, mode):
    """The addendum of NAVRH_B9b and finding N1 of the confirmation of B9a (the interleave of the realized boots;
    skeleton test 2 over the realized boots of the test roles in the record of every ending): the barrier of the
    shared rank orders the starts of the test groups, not their ends. In the mirrored drift VM b runs ahead (its
    test_benign-1, then it waits), then VM a runs alone to its end (test_controls-1, test_benign-2), and only then VM
    b's test_controls-2 starts: after every boot of test_benign has ended, so test 2 (assert_test_boots_interleave)
    fails on these boots, in the realized order (b, test_benign-1), (a, test_controls-1), (a, test_benign-2), (b,
    test_controls-2). The campaign and a rehearsal of two groups per role, whose plans have that shape (v5- and g5-),
    still end complete, and the record of the ending úplná says so: interleave.ok false, the boot of test_controls-2
    of its plan after every boot of test_benign, the realized order of the group starts (by each group's first
    measured start), and the violation with that group among the deviations."""
    h = Harness(tmp_path, monkeypatch)
    if mode == "campaign":
        protocol = h.protocol("protocol-zrkadlo", limit=0)
        directory = h.init(protocol, "campaign", "zrkadlo", estimate_from=scenario.rehearsal)
    else:
        protocol = h.protocol("protocol-zrkadlo", limit=None, rehearsal_groups=2)
        directory = h.init(protocol, "rehearsal", "zrkadlo-generalka")
    prefix = h.manifest(directory)["group_prefix"]
    alone = h.drift(directory, ahead="b")
    assert alone["b"]["status"] == "stopped" and alone["a"]["status"] == "complete", alone
    with pytest.raises(AssertionError):
        assert_test_boots_interleave(h, directory)
    boots = sorted((b for b in h.boots(directory).values() if b["role"] in pv.INTERLEAVED), key=lambda b: b["start"])
    last_benign = max(b["end"] for b in boots if b["role"] == "test_benign")
    late = [b["first"]["group"] for b in boots if b["role"] == "test_controls" and b["start"] >= last_benign]
    order = [(b["first"]["vm"], b["first"]["group"]) for b in boots]
    assert late == [prefix + "test_controls-2"] and order == [
        ("b", prefix + "test_benign-1"), ("a", prefix + "test_controls-1"), ("a", prefix + "test_benign-2"),
        ("b", prefix + "test_controls-2")]
    assert read_json(directory / "corpus.json")["complete"] is True
    _, record = assert_ending(h, directory, "complete")
    v = record["values"]
    sequences = group_sequences(v["interleave"], {group for _, group in order})
    assert v["interleave"]["ok"] is False and late in sequences, v["interleave"]
    assert [group for _, group in order] in sequences, v["interleave"]
    assert all(group in text(v["deviations"]) for group in late), v["deviations"]


# ====================================================================================================================
# The fix round of package B9b (agent T; dokazy/B9/navrh/OPRAVA_B9b.md section 3, the findings F4, F7 and F9 of the
# verification of B9b, overenie_B9b/vysledok.json, with its probes and mutants in sondy/). F12 is a case of
# scripts/tests/test_campaign.py. The cases of F9 pin code that is already right, so they may pass on the base; their
# proof is the verifier's mutant killed (sondy/mutanty.py).


def started_beside(h, campaign, monkeypatch, *, release):
    """F4 (the verifier's sondy/test_p1_race.py): VM b's runner in a thread (Harness.background), held at
    hold_sleep_inhibitor, after refuse_held, verify_frozen and require_stages and before its state says running.
    `release`: "after_the_record", the test releases it (go) once VM a's run is over; "after_the_trigger", VM a's
    begin_ending releases it right after VM a's trigger and waits until VM b has written its state. Returns (runner,
    go)."""
    at_hook, go = threading.Event(), threading.Event()
    monkeypatch.setattr(collection, "Interrupts", NoSignals)

    def inhibitor():
        if threading.current_thread() is not threading.main_thread() and not at_hook.is_set():
            at_hook.set()
            assert go.wait(JOIN_S), "VM b's runner was never released"
        return None
    monkeypatch.setattr(c, "hold_sleep_inhibitor", inhibitor)
    if release == "after_the_trigger":
        real = c.begin_ending

        def begin(directory, protocol, vm, kind, cause, detail=None):
            pending = real(directory, protocol, vm, kind, cause, detail)
            if vm == "a" and not go.is_set():
                go.set()
                deadline = time.monotonic() + JOIN_S
                while h.status(campaign, "b").get("status") in (None, "ready"):  # Not yet past its hook.
                    assert time.monotonic() < deadline, h.status(campaign, "b")
                    time.sleep(.01)  # Judgment of the test: a poll far below the steps of a runner.
            return pending
        monkeypatch.setattr(c, "begin_ending", begin)
    runner = h.background(campaign, "b")
    assert at_hook.wait(JOIN_S), (runner.outcome, h.status(campaign, "b"))
    return runner, go


@pytest.mark.parametrize("release", ["after_the_record", "after_the_trigger"])
def test_a_runner_that_writes_running_after_a_pause_stops_as_part_of_it(scenario, tmp_path, monkeypatch, release):
    """Finding F4 of the verification of B9b (PAUSE_RULE, design 1.2: both runners stop; ENDING_RULE): VM b's runner
    passes refuse_held before VM a's pause and writes its state running only after it, so begin_ending, which asks
    only the runners whose state says running, writes it no stop request. VM a's pause is the real one: its first
    session is rejected over the limit 0. VM b is released after_the_record (the verifier's interleaving: VM a's run is
    over, its paused record written) or after_the_trigger (right after VM a's trigger, before VM a's record). Before
    its first capture VM b reads the ending and stops as part of it: it captures nothing (nor tries to), its state is
    paused and names the ending's cause, and the campaign has one record, the paused one. after_the_record: VM b's
    state also names that record. after_the_trigger: VM b was active when VM a stopped, so the record is written once
    both runners stopped, and it holds VM b's state as stopped by the ending."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-zavod", limit=0)
    first = next(x for x in pv.plan(collection.protocol(protocol), "campaign")["sessions"] if x["vm"] == "a")
    h.reject.add(("zavod", first["group"], first["scenario"], 1))
    campaign = h.init(protocol, "campaign", "zavod", estimate_from=scenario.rehearsal)
    runner, go = started_beside(h, campaign, monkeypatch, release=release)
    try:
        h.step(campaign, "a")  # VM a's first session is rejected over the limit 0: the pause.
    finally:
        go.set()
        outcome = runner.join(JOIN_S)
    assert outcome == {"value": 0}, outcome
    assert [x["vm"] for x in h.captures] == ["a"] and not any("never captures" in r for r in h.refusals), (
        [x["sid"] for x in h.captures], h.refusals[-2:])
    (path, record), = h.records(campaign)
    v = record["values"]
    assert ending_of(record) == "paused" and h.status(campaign, "a")["status"] == "paused", v["cause"]
    state = h.status(campaign, "b")
    assert state["status"] == "paused" and v["cause"] in state["message"], state
    if release == "after_the_record":
        assert path.name in text(state), state
    else:
        held, = (r for r in v["runners"] if r["vm"] == "b")
        assert held["status"] == "paused" and v["cause"] in held["message"], held


@pytest.mark.parametrize("ending", ["operator_stop", "early_stop"])
def test_a_runner_that_writes_running_after_a_stopped_ending_stops_as_part_of_it(scenario, tmp_path, monkeypatch,
                                                                               ending):
    """Finding F4 of the verification of B9b, for a stopped ending (the coordinator's review of ca69259): the
    verifier's interleaving (VM b's runner past refuse_held, held at hold_sleep_inhibitor until VM a's run is over)
    with VM a's ending a stopped one: operator_stop, the operator's request-stop --reason during VM a's first capture;
    early_stop, VM a's first session rejected for periodicity (a campaign stopped so runs again only with a written
    cause, R's F6). VM a's runner records the stopped ending at once: VM b's state does not yet say running, so no stop
    request reaches it, and once the ending is recorded nothing is pending and it is no pause or invalidation. VM b's
    runner, once it writes running, finds before its first capture the ending recorded after its start and stops as
    part of it: it captures nothing (nor tries to), its state is stopped and names the ending's cause and its record,
    and the campaign keeps its one stopped record."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-zastavenie", limit=1)
    first = next(x for x in pv.plan(collection.protocol(protocol), "campaign")["sessions"] if x["vm"] == "a")
    key = ("zastavenie", first["group"], first["scenario"], 1)
    if ending == "operator_stop":
        h.during[key] = lambda: c.main(["request-stop", str(campaign), "--vm", "a", "--reason", STOPPED])
    else:
        h.reject.add(key)
        h.codes[key] = PERIODICITY
    campaign = h.init(protocol, "campaign", "zastavenie", estimate_from=scenario.rehearsal)
    runner, go = started_beside(h, campaign, monkeypatch, release="after_the_record")
    try:
        _, refused = attempt(lambda: c.execute(campaign, vm="a"))
    finally:
        go.set()
        outcome = runner.join(JOIN_S)
    assert refused is None and outcome == {"value": 0}, (refused, outcome)
    assert [x["vm"] for x in h.captures] == ["a"] and not any("never captures" in r for r in h.refusals), (
        [x["sid"] for x in h.captures], h.refusals[-2:])
    (path, record), = h.records(campaign)
    v = record["values"]
    assert ending_of(record) == "stopped" and h.status(campaign, "a")["status"] == "stopped", v["cause"]
    assert (STOPPED if ending == "operator_stop" else "periodicity") in v["cause"], v["cause"]
    state = h.status(campaign, "b")
    assert state["status"] == "stopped" and v["cause"] in state["message"] and path.name in text(state), state


def test_a_run_while_an_ending_is_pending_is_refused(scenario, tmp_path, monkeypatch):
    """F9 of the verification of B9b (the mutant refuse_pending_skip; ENDING_RULE, refuse_held): while VM a's runner,
    active, holds a stopped ending pending (its trigger written, its record not yet), a run of VM b is refused by name
    before it starts anything; the ending stays pending, no record is written and nothing is captured."""
    h = Harness(tmp_path, monkeypatch)
    campaign = h.init(h.protocol("protocol-cekanie", limit=1), "campaign", "cekanie", estimate_from=scenario.rehearsal)
    manifest, p = c.load_campaign(campaign)
    state = {**h.status(campaign, "a"), "status": "running", "pid": os.getpid(),
             "process_identity": c.process_identity(os.getpid())}  # Active: its state running, its process alive.
    (campaign / c.vm_file("status.json", "a")).write_text(json.dumps(state))
    c.begin_ending(campaign, p, "a", "stopped", "operator stop request: the test's reason")
    with pytest.raises(ValueError, match="^" + re.escape(
            "campaign cekanie is ending (stopped: operator stop request: the test's reason): its other runner stops at "
            "its next check; run it again once that ending is recorded (scripts/campaign.py ENDING_RULE)") + "$"):
        h.step(campaign, "b")
    assert c.pending_ending(campaign)["ending"] == "stopped" and h.records(campaign) == [] and h.captures == []


@pytest.mark.parametrize("order", [("paused", "invalid"), ("invalid", "paused")], ids=["paused_first", "invalid_first"])
def test_the_heavier_trigger_of_one_ending_holds(scenario, tmp_path, monkeypatch, order):
    """F9 of the verification of B9b (the mutant pending_order; ENDING_RULE: of the triggers of one ending the heavier
    kind holds, invalid, then paused, then stopped): a paused and an invalid trigger of the two VMs in one pending
    ending, in either order, leave it invalid with the cause of the invalid trigger and both triggers in order; its
    record, once no runner is active, is that of the ending invalid."""
    h = Harness(tmp_path, monkeypatch)
    campaign = h.init(h.protocol("protocol-tazsi", limit=1), "campaign", "tazsi", estimate_from=scenario.rehearsal)
    manifest, p = c.load_campaign(campaign)
    for vm, kind in zip(VMS, order):
        c.begin_ending(campaign, p, vm, kind, f"the {kind} trigger of the test")
    pending = c.pending_ending(campaign)
    assert (pending["ending"], pending["cause"], [t["ending"] for t in pending["triggers"]]) == (
        "invalid", "the invalid trigger of the test", list(order))
    assert c.settle(campaign, manifest, p, command="test") is None
    (_, record), = h.records(campaign)
    assert (ending_of(record), record["values"]["cause"], c.held_ending(campaign)) == (
        "invalid", "the invalid trigger of the test", "invalid")


class Died(BaseException):
    """The death of a runner inside its trigger (SIGKILL, power loss): no handler of execute runs to its end."""


def test_a_pause_whose_runner_died_before_its_trigger_is_recovered_by_the_next_run(scenario, tmp_path, monkeypatch):
    """F9 of the verification of B9b (the mutant crash_recovery_limit_ending_skip; PAUSE_RULE): VM a's first session is
    rejected over the limit 0, so its rejection record names the ending paused, and its runner dies inside the trigger
    of the pause (begin_ending), before anything of the ending is written. The next run of VM a finds the rejection
    record without its trigger and pauses the campaign as the record names: its state paused and the one record, of the
    ending paused, whose cause names the session; never the stopped ending of an error."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol-pad", limit=0)
    first = next(x for x in pv.plan(collection.protocol(protocol), "campaign")["sessions"] if x["vm"] == "a")
    h.reject.add(("pad", first["group"], first["scenario"], 1))
    campaign = h.init(protocol, "campaign", "pad", estimate_from=scenario.rehearsal)
    real = c.begin_ending

    def dies(*args, **kwargs):
        raise Died("the runner died inside the trigger of its pause (test)")
    monkeypatch.setattr(c, "begin_ending", dies)
    with pytest.raises(Died):
        h.step(campaign, "a")
    sid = h.plan_rows(campaign)[0]["session_id"]
    rejection = read_json(c.rejection_file(campaign, sid))
    assert (rejection["replacement"], rejection["ending"]) == (None, "paused")
    assert c.pending_ending(campaign) is None and h.records(campaign) == []
    monkeypatch.setattr(c, "begin_ending", real)
    h.step(campaign, "a")
    (_, record), = h.records(campaign)
    assert ending_of(record) == "paused" and sid in record["values"]["cause"], record["values"]["cause"]
    assert h.status(campaign, "a")["status"] == "paused" and len(h.captures) == 1


def test_an_audit_without_its_unscored_time_is_not_recorded_as_0():
    """F9 of the verification of B9b (the mutant rec_unscored_zero; ENDING_RULE, design 1.1 unscored): the summary of
    the unscored time of the accepted sessions takes values.coverage.nominal_unscored_s of each audit; an audit
    without it (no coverage block, or no audit values) is not recorded, by name, never 0, and the total is of the
    recorded ones."""
    accepted = [({"session": "s1"}, None, {"coverage": {"nominal_unscored_s": 80.0}}),
                ({"session": "s2"}, None, {"coverage": {"nominal_scored_s": 400.0}}),
                ({"session": "s3"}, None, None)]
    summary = c.unscored_summary(accepted)
    assert (summary["sessions"], summary["total_s"], summary["not_recorded"]) == (
        [{"session": "s1", "nominal_unscored_s": 80.0}], 80.0, ["s2", "s3"])


def test_a_vm_that_completes_while_a_pause_is_pending_stays_complete(scenario, tmp_path, monkeypatch):
    """F9 of the verification of B9b (the mutant end_run_complete_overridden; ENDING_RULE end_run: a run that stops
    while an ending is pending takes that ending's kind, complete stays): VM b's last state of a run that completed its
    share of the plan, while VM a's pause is pending and VM a's runner still active, stays complete; no record is
    written while VM a is active, and the pause stays pending for VM a's stop."""
    h = Harness(tmp_path, monkeypatch)
    campaign = h.init(h.protocol("protocol-hotovo", limit=0), "campaign", "hotovo", estimate_from=scenario.rehearsal)
    manifest, p = c.load_campaign(campaign)
    state = {**h.status(campaign, "a"), "status": "running", "pid": os.getpid(),
             "process_identity": c.process_identity(os.getpid())}
    (campaign / c.vm_file("status.json", "a")).write_text(json.dumps(state))
    c.begin_ending(campaign, p, "a", "paused", "the limit of the test")
    with contextlib.redirect_stdout(io.StringIO()):
        recorded = c.end_run(campaign, manifest, p, "b", command="test", status="complete", stage="vm-complete",
                             message=None)
    assert recorded is None and h.status(campaign, "b")["status"] == "complete", h.status(campaign, "b")
    assert c.pending_ending(campaign)["ending"] == "paused" and h.records(campaign) == []


def test_a_test_controls_boot_that_starts_at_the_end_of_the_last_test_benign_boot_is_late(tmp_path):
    """F9 of the verification of B9b (the mutant interleave_gt; INTERLEAVE_RULE: late_controls are the test_controls
    boots that start at or after the end of every test_benign boot, skeleton test 2): a boot of test_controls whose
    first measured start equals the last measured end of the boot of test_benign is late, and the interleave fails."""
    plan, rows = [], []
    for group, role, vm, start, end in (("v5-test_benign-1", "test_benign", "b", 1000.0, 1475.0),
                                        ("v5-test_controls-1", "test_controls", "a", 1475.0, 1950.0)):
        session = tmp_path / group
        session.mkdir()
        (session / "end.json").write_text(json.dumps({"measure_start_unix": start, "measure_end_unix": end}))
        plan.append({"group": group, "role": role, "vm": vm})
        rows.append(({"session": group + "_01", "role": role, "group": group, "vm": vm}, session, None))
    check = c.interleave_check(rows, {"sessions": plan})
    assert (check["ok"], check["late_controls"], check["alternation"]) == (False, ["v5-test_controls-1"], [])


FINALNE_REFUSED = ("schema", "ending", "campaign", "sessions", "another_campaign")


@pytest.mark.parametrize("case", FINALNE_REFUSED)
def test_tcn_finalne_reads_only_the_record_of_its_own_corpus(scenario, counted, tmp_path, case):
    """Finding F7 of the verification of B9b (tcn/finalne.py CAMPAIGN_RULE; the verifier's sondy/test_p4_finalne.py):
    campaign_record reads only the record of the complete ending of the campaign of the corpus index; every other
    record is refused by name, each check alone: a record of another schema; the record of another ending (closed),
    its campaign and sessions its own; a record that names another campaign; one whose accepted sessions are not those
    of the index (one accepted row renamed, the counts unchanged); and the complete record of another campaign of as
    many sessions (the scenario's campaign against the corpus of the campaign pocty, 30 each), which the count alone
    let through. The good inputs are those of test_tcn_finalne_reads_the_record_of_the_complete_ending."""
    from tcn import finalne
    path, record = the_record(scenario.h, scenario.campaign, "complete")
    index, doc, name = read_json(scenario.campaign / "corpus.json"), copy.deepcopy(record), scenario.campaign.name
    target = tmp_path / path.name
    if case == "schema":
        doc["schema"] = "hyptcn3/collection-campaign/1"
        said = ("a record of schema 'hyptcn3/collection-campaign/1' is no record of the ending of a campaign "
                "(hyptcn3/campaign-ending/1, scripts/campaign.py ENDING_RULE): it is not the record of a corpus "
                "(CAMPAIGN_RULE)")
    elif case == "ending":
        doc["values"]["ending"] = "closed"
        said = (f"the record of the ending 'closed' of campaign '{name}' is not the record of a corpus: only the "
                "record of the complete ending is (CAMPAIGN_RULE)")
    elif case == "campaign":
        doc["values"]["campaign"] = "kampan-x"
        said = (f"the record of campaign 'kampan-x' is not the record of the corpus index of campaign '{name}' "
                "(CAMPAIGN_RULE)")
    elif case == "sessions":
        row = next(r for r in doc["values"]["sessions"] if r["state"] == "accepted")
        old, row["session"] = row["session"], row["session"] + "-x"
        said = (f"the accepted sessions of the record are not the sessions of the corpus index (only in the record: "
                f"{old}-x; only in the index: {old}): it is not the record of this corpus (CAMPAIGN_RULE)")
    else:
        index = read_json(counted.campaign / "corpus.json")
        assert len(index["sessions"]) == record["values"]["accepted_sessions"] == 30
        said = (f"the record of campaign '{name}' is not the record of the corpus index of campaign "
                f"'{counted.campaign.name}' (CAMPAIGN_RULE)")
    target.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="^" + re.escape(f"{target.resolve()}: {said}") + "$"):
        finalne.campaign_record(target, index)
