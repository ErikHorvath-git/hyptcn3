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
"""
from collections import Counter
import contextlib
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from scripts import campaign as c
from scripts import collection
from scripts import protocol_v5 as pv
from scripts.collection_archive import digest, read_json
from scripts.tests.kampan_v5 import GROUP_START, LAB_STEPS, TRACKED_LEDGER, VMS, Harness, holds, ledger_entries, printed
from scripts.tests.test_multivm import no_inherited_lock  # noqa: F401 (autouse fixture: no inherited lock)

SEALED = ("test_benign", "test_controls")  # tcn/pecat.py SEALED_ROLES
TRACKED = digest(TRACKED_LEDGER) if TRACKED_LEDGER.exists() else None


@pytest.fixture(autouse=True)
def _tracked_ledger_unchanged():
    """No test writes data/results/kniha_pecati.json (the harness points tcn.pecat.KNIHA and ZAZNAM elsewhere and
    refuses a write of it; this checks the file itself after every test, the module's scenario included)."""
    yield
    assert (digest(TRACKED_LEDGER) if TRACKED_LEDGER.exists() else None) == TRACKED


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
    (labctl exits 1 with its reason), the session is rejected before its measured phase and no later step of that
    start runs: attempt 1 is never captured or audited and the rejection record names its cause, a cause of its own
    (neither an audit rejection nor an incomplete capture), and the step. Then the replacement rule decides: the v5
    file's replacement.covers names audit_rejected and capture_incomplete only, so the rule does not replace it and
    the runner stops by name, before any further capture, also when it runs again (a stop for review, as an exhausted
    limit until the pause of package B9b). A rehearsal: the start of a group is the same in both modes, and in mode
    rehearsal no limit stands between the session and the rule."""
    h = Harness(tmp_path, monkeypatch)
    protocol = h.protocol("protocol", limit=None)
    p = collection.protocol(protocol)
    first = next(x for x in pv.plan(p, "rehearsal")["sessions"] if x["vm"] == "a")
    h.lab.fail["a", step] = 1
    rehearsal = h.init(protocol, "rehearsal", p["name"] + p["rehearsal"]["name_suffix"])
    failed = GROUP_START.index(step)
    for _ in range(2):  # The stop is permanent: running again starts nothing, captures nothing.
        with pytest.raises(ValueError) as stopped, contextlib.redirect_stdout(io.StringIO()):
            c.execute(rehearsal, vm="a", stop_after=1)
        assert [(x["verb"], x["code"]) for x in h.lab.calls if x["verb"] in LAB_STEPS] == [
            *((verb, 0) for verb in GROUP_START[:failed]), (step, 1)]
        assert h.captures == h.audits == []
        record, = c.rejections(rehearsal)
        assert (record["session"], record["group"], record["scenario"]) == (
            h.plan_rows(rehearsal)[0]["session_id"], first["group"], first["scenario"])
        assert record["cause"] not in (*collection.REPLACEMENT_CAUSES, *p["replacement"]["covers"]), record
        said = "; ".join(record["reasons"])
        named = {verb for verb in GROUP_START if re.search(rf"\b{verb}\b", said)}
        assert step in named and not named & set(GROUP_START[failed + 1:]), record  # Later steps never ran.
        assert record["replacement"] is None, record
        assert record["not_replaced"] == "the protocol has no replacement rule for this cause"
        assert said in str(stopped.value)  # The runner stops with the record's reason.
        assert not (h.collections / rehearsal.name / "a" / record["session"]).exists()
    state = read_json(rehearsal / c.vm_file("status.json", "a"))
    assert state["status"] == "stopped" and said in state["message"]
