"""The self-check of protocol v5 (package B4): the real file passes, every deliberate error fails its check.

scripts/collection.py --protocol P selfcheck (scripts/protocol_v5.py) runs on config/collection-v5.json: every
check passes except lab_register, which stays pending until package B8 registers its four control kinds in lab/ (B5
registered the event types and the traffic profiles, skeleton B5 section 5 item 7), so the command exits 2 until B8.
Each row of the lead's skeleton (dokazy/B4/kostra/KOSTRA.md, section 5) is one deliberate error: the file with one
change, the plan with one change or a replacement that changes the assignment.
Its check fails with exactly the reasons written here and every other check gives what it gives for the real file,
except the ones a case lists. Only what the plan draws (a group, a scenario, an event type) is read from the plan.
Names package B4 adds are imported inside the tests, so this file collects on the code before B4.
"""
from collections import Counter
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
CHECKS = ("keys", "loader", "reachability", "role_sizes", "scenario_balance", "events", "controls",
          "full_snapshot_guard", "phases", "streams", "role_order", "analysis", "rehearsal", "lab_register")
PENDING = ("registered by B8: kontrola_davka_procesov, kontrola_modul_jadra, kontrola_pocuvajuci_soket, "
           "kontrola_zapisovac_pamate")
TYPES = ("naprazdno", "restart_databazy", "udrzba_zaloha", "zamok_tabulky", "zataz_pamate", "zla_konfiguracia_sluzby")
UNREACHABLE = "protocol(): invalid_rows.max is unreachable under the score coverage gate"
OUTSIDE = "score coverage gate outside the interval bound to invalid_rows.max"
REFUSED = "witness with invalid_rows.max rows is refused"


def _label(s):
    return f"{s['group']}#{s['position']}"


def _block(group):
    return (int(group.rsplit("-", 1)[1]) - 1) // 4 + 1


# Changes of the file: doc -> the failures they cause {check: reasons}.

def unknown_key(doc):
    doc["extra"] = 1
    return {"keys": ["unknown protocol key: extra"], "loader": ["protocol(): unknown protocol key: extra"]}


def missing_key(doc):
    del doc["scenario_rule"]
    return {"keys": ["missing protocol key: scenario_rule"],
            "loader": ["protocol(): missing protocol key: scenario_rule"]}


def gate_085(doc):
    doc["min_score_coverage"] = .85  # max 3: three isolated rows leave 557 of 720
    return {"loader": [UNREACHABLE], "reachability": [OUTSIDE, REFUSED]}


def max_7(doc):
    doc["invalid_rows"]["max"] = 7
    return {"loader": [UNREACHABLE], "reachability": ["invalid_rows.max above 6", OUTSIDE, REFUSED]}


def six_groups(doc):
    doc["roles"]["dev"] = 6
    return {"role_sizes": ["groups of role dev are not a multiple of 4"]}


def below_min_per_type(doc):
    doc["events"]["min_per_type"]["train"] = 13  # 12 groups, 24 sessions with three events: 12 of each type
    return {"events": [f"role train: type {t} has 12 events, below min_per_type 13" for t in TYPES]}


def not_interleaved(doc):
    doc["interleave"] = []
    reason = "test_benign and test_controls are not interleaved"
    return {"role_order": [reason], "rehearsal": ["role_order: " + reason]}


def no_min_per_type(doc):
    """F6 of the B4 verification: an empty min_per_type would silently drop the minimum counts of every role."""
    doc["events"]["min_per_type"] = {}
    return {"loader": ["protocol(): invalid events"],
            "events": [f"role {role} has no min_per_type" for role in ("train", "dev", "calibration", "test_benign")]}


def replacement_without_covers(doc):
    """F7 of the B4 verification: without covers the loader took the schema-2 default ['audit_rejected']."""
    del doc["replacement"]["covers"]
    return {"keys": ["missing protocol key: replacement.covers"],
            "loader": ["protocol(): missing protocol key: replacement.covers"]}


def method_without_grid(doc):
    del doc["analysis"]["methods"]["Z1"]["grid"]
    return {"keys": ["missing protocol key: analysis.methods.Z1.grid"],
            "loader": ["protocol(): missing protocol key: analysis.methods.Z1.grid"],
            "analysis": ["missing analysis key: analysis.methods.Z1.grid"]}


def k2a_without_z4(doc):
    """The lead's must_fix 4 on B4: K2a is decided against Z1, Z2 and Z4 (proposal 4.1)."""
    doc["analysis"]["k2a"]["compare"].remove("Z4")
    return {"analysis": ['analysis.k2a.compare is ["Z1", "Z2"], proposal 4.1 names ["Z1", "Z2", "Z4"]']}


def null_outside(doc):
    doc["determined_at"]["G3a"].remove("analysis.column_mask")
    return {"analysis": ["null outside determined_at: analysis.column_mask"]}


def rehearsal_name(doc):
    doc["rehearsal"]["name_suffix"] = ""
    return {"rehearsal": ["rehearsal name equals the campaign name"]}


def rehearsal_prefix(doc):
    doc["rehearsal"]["group_prefix"] = doc["group_prefix"]
    return {"rehearsal": ["rehearsal group prefix equals the campaign prefix"]}


def unknown_to_lab(doc):
    doc["events"]["types"]["zamok_databazy"] = doc["events"]["types"].pop("zamok_tabulky")
    return {"lab_register": ["unknown to lab/: zamok_databazy"]}


def unknown_profile(doc):
    doc["scenarios"]["corp_low"]["profile"] = "batch"  # No profile of the profiles section, none of the generator.
    return {"loader": ["protocol(): invalid profiles"], "lab_register": ["unknown to lab/: batch"]}


def think_below_mean(doc):
    doc["profiles"]["eshop"]["think_s"]["max"] = 5  # Below the mean of 7 s.
    return {"loader": ["protocol(): invalid profiles"]}


# Changes of the plan of the real file: (doc, plan) -> the failures.

def no_group_on_vm(doc, plan):
    for s in plan["sessions"]:
        if s["role"] == "dev":
            s["vm"] = "a"
    return {"role_sizes": ["role dev has no group on VM b"]}


def equal_scenarios(doc, plan):
    """The second session of a group takes the first one's scenario: in its complete block that scenario is then
    twice at position 1. The group is one where the scenario counts of its VM stay within 1."""
    sessions = plan["sessions"]
    for first, second in zip(sessions, sessions[1:]):
        if first["group"] == second["group"] and (first["position"], second["position"]) == (0, 1):
            counts = Counter(s["scenario"] for s in sessions if (s["role"], s["vm"]) == (first["role"], first["vm"]))
            if counts[first["scenario"]] < counts[second["scenario"]]:
                break
    second["scenario"] = first["scenario"]
    return {"scenario_balance": [f"group {first['group']} repeats scenario {first['scenario']}",
                                 f"scenario {first['scenario']} twice at position 1 in block "
                                 f"{first['role']}/{_block(first['group'])}"]}


def twice_at_position(doc, plan):
    """The first two sessions of v5-train-1 swap their scenarios: no group repeats one and no VM count changes."""
    first, second = plan["sessions"][:2]
    assert (first["group"], first["position"], second["group"], second["position"]) == ("v5-train-1", 0,
                                                                                       "v5-train-1", 1)
    first["scenario"], second["scenario"] = second["scenario"], first["scenario"]
    return {"scenario_balance": [f"scenario {first['scenario']} twice at position 0 in block train/1",
                                 f"scenario {second['scenario']} twice at position 1 in block train/1"]}


def two_events(doc, plan):
    s = next(s for s in plan["sessions"] if s["role"] == "train" and s["events"])
    removed = s["events"].pop()["type"]
    return {"events": [f"session {_label(s)} has 2 events (allowed [0, 3])",
                       f"role train: type {removed} has 11 events, below min_per_type 12"]}


def start_in_guard(doc, plan):
    s = next(s for s in plan["sessions"] if s.get("events"))
    s["events"][0]["start_s"] = 1770.  # 30 s before the full snapshot of row 360
    return {"full_snapshot_guard": [f"{_label(s)}: {s['events'][0]['type']} starts at 1770 s inside the guard of "
                                    "the full snapshot at 1800 s"]}


def locked_to_grid(doc, plan):
    for s in plan["sessions"]:
        for item in s.get("events", []) + [c for c in s.get("controls", []) if c["kind"] is not None]:
            item["start_s"] = item["start_s"] // 5 * 5  # Guards start and end on a multiple of 5 s: none is met.
    return {"phases": ["event starts are locked to the sampling grid"]}


def common_seed(doc, plan):
    s = plan["sessions"][0]
    s["seeds"]["event_times"] = s["seeds"]["traffic"]
    return {"streams": ["purposes event_times and traffic share a seed"]}


def control_relabelled(doc, plan):
    """F1 of the B4 verification: one control card dealt twice, another once less."""
    items = [x for s in plan["sessions"] for x in s.get("controls", []) if x["kind"] is not None]
    first, other = items[0], next(x for x in items if (x["kind"], x["polarity"]) != (items[0]["kind"], "control")
                                  and x["polarity"] == "control")
    gone = other["kind"]
    other.update(kind=first["kind"], polarity="control", **{"class": first["class"]})
    expected = sorted([(first["kind"], 8), (gone, 6)])
    return {"controls": [f"control {kind}/control has {n} occurrences (expected 7)" for kind, n in expected]}


def control_slot_emptied(doc, plan):
    """F1: a dealt card replaced by an empty slot: its count falls, and one slot more is empty than the deck leaves."""
    x = next(x for s in plan["sessions"] for x in s.get("controls", []) if x["kind"] is not None)
    card = (x["kind"], x["polarity"])
    x.clear()
    x.update(kind=None, reason="deck exhausted")
    return {"controls": [f"control {card[0]}/{card[1]} has 6 occurrences (expected 7)",
                         "3 empty control slots (expected 2)"]}


def event_free_first(doc, plan):
    """F2: in every group of train the event-free session is moved to position 0 (the events change places)."""
    for group in sorted({s["group"] for s in plan["sessions"] if s["role"] == "train"}):
        ss = [s for s in plan["sessions"] if s["group"] == group]
        free = next(s for s in ss if not s["events"])
        ss[0]["events"], free["events"] = free["events"], ss[0]["events"]
    return {"events": ["role train: event-free sessions per position differ by more than 1"]}


def group_of_two(doc, plan):
    """F3: the event-free session of v5-train-1 is dropped: the group has two sessions and none without events, and
    its scenario is one short on the group's VM."""
    s = next(s for s in plan["sessions"] if s["group"] == "v5-train-1" and not s["events"])
    plan["sessions"].remove(s)
    positions = [i for i in range(3) if i != s["position"]]
    return {"scenario_balance": [f"group v5-train-1 has positions {json.dumps(positions)} (expected 0 to 2)",
                                 f"role train on VM {s['vm']}: scenario counts differ by more than 1"],
            "events": ["group v5-train-1 has 0 sessions without events"]}


def seed_field(doc, plan):
    """F5: the seed the campaign runner passes (session["seed"]) differs from the planned traffic stream."""
    s = plan["sessions"][0]
    s["seed"] = s["seeds"]["traffic"] + 1
    return {"streams": [f"session {_label(s)}: seed differs from seeds.traffic"]}


def replaced_type(doc, plan, monkeypatch):
    from scripts import protocol_v5
    real, target = protocol_v5.replacement, next(s for s in plan["sessions"] if s.get("events"))

    def changed(p, session, attempt, *, mode="campaign"):
        out = real(p, session, attempt, mode=mode)
        if (session["group"], session["position"]) == (target["group"], target["position"]):
            out["events"][0]["type"] = next(t for t in TYPES if t != out["events"][0]["type"])
        return out
    monkeypatch.setattr(protocol_v5, "replacement", changed)
    return {"streams": [f"replacement of {_label(target)} changes types"]}


def replaced_streams(doc, plan, monkeypatch):
    """F4: a replacement that keeps the event times and the traffic seed of attempt 1 shares both streams."""
    from scripts import protocol_v5
    real, target = protocol_v5.replacement, next(s for s in plan["sessions"] if s.get("events"))

    def same_streams(p, session, attempt, *, mode="campaign"):
        out = real(p, session, attempt, mode=mode)
        if (session["group"], session["position"]) == (target["group"], target["position"]):
            out.update(seeds=dict(session["seeds"]), seed=session["seed"],
                       events=json.loads(json.dumps(session["events"])))
        return out
    monkeypatch.setattr(protocol_v5, "replacement", same_streams)
    return {"streams": [f"two {purpose} streams share a seed" for purpose in
                        ("event_times", "traffic", "traffic_arrivals", "traffic_choices", "traffic_sizes")]}


def replaced_in_guard(doc, plan, monkeypatch):
    """F4: the replacement of a session draws an event start 30 s before the full snapshot at 1800 s."""
    from scripts import protocol_v5
    real, target = protocol_v5.replacement, next(s for s in plan["sessions"] if s.get("events"))

    def in_guard(p, session, attempt, *, mode="campaign"):
        out = real(p, session, attempt, mode=mode)
        if (session["group"], session["position"]) == (target["group"], target["position"]):
            out["events"][0]["start_s"] = 1770.
        return out
    monkeypatch.setattr(protocol_v5, "replacement", in_guard)
    return {"full_snapshot_guard": [f"replacement of {_label(target)}: {target['events'][0]['type']} starts at 1770 s "
                                    "inside the guard of the full snapshot at 1800 s"]}


FILE_CASES = {f.__name__: f for f in (unknown_key, missing_key, gate_085, max_7, six_groups, below_min_per_type,
                                      no_min_per_type, not_interleaved, replacement_without_covers,
                                      method_without_grid, k2a_without_z4, null_outside, rehearsal_name,
                                      rehearsal_prefix, unknown_to_lab, unknown_profile, think_below_mean)}
PLAN_CASES = {f.__name__: f for f in (no_group_on_vm, equal_scenarios, twice_at_position, two_events, start_in_guard,
                                      locked_to_grid, common_seed, control_relabelled, control_slot_emptied,
                                      event_free_first, group_of_two, seed_field)}
REPLACEMENT_CASES = {f.__name__: f for f in (replaced_type, replaced_streams, replaced_in_guard)}
CASES = ["real_file", *FILE_CASES, *PLAN_CASES, *REPLACEMENT_CASES, "null_at_g1"]


def selfcheck(tmp_path, doc, *options):
    """scripts/collection.py --protocol <doc as a file> selfcheck: (exit code, the report it wrote)."""
    from scripts import collection
    path, out = tmp_path / "protocol.json", tmp_path / "report.json"
    path.write_text(json.dumps(doc, indent=2))
    code = collection.main(["--protocol", str(path), "selfcheck", *options, "--out", str(out)])
    return code, json.loads(out.read_text())


@pytest.mark.parametrize("case", CASES)
def test_selfcheck_passes_the_file_and_fails_each_deliberate_error(case, tmp_path, monkeypatch):
    from scripts import protocol_v5
    doc = json.loads(V5.read_text())
    if case in PLAN_CASES or case in REPLACEMENT_CASES:
        plan = protocol_v5.plan(doc)
        failures = (PLAN_CASES[case](doc, plan) if case in PLAN_CASES
                    else REPLACEMENT_CASES[case](doc, plan, monkeypatch))
        checks = protocol_v5.evaluate(V5, doc, plan)
    else:
        failures = {} if case == "real_file" else FILE_CASES[case](doc) if case in FILE_CASES else {
            "analysis": [f"null at analysis.{k}.m determined at G1 (stage G1)" for k in ("k1", "k2a", "k2b")]}
        code, report = selfcheck(tmp_path, doc, *(["--stage", "G1"] if case == "null_at_g1" else []))
        assert code == 2 and report["passed"] is False  # lab_register is pending until B8 at the least
        assert (report["mode"], report["stage"]) == ("campaign", "G1" if case == "null_at_g1" else "G0")
        checks = report["checks"]
    expected = {name: ("passed", []) for name in CHECKS}
    expected["lab_register"] = ("pending", [PENDING])
    expected.update({name: ("failed", reasons) for name, reasons in failures.items()})
    assert [c["check"] for c in checks] == list(CHECKS)
    assert {c["check"]: (c["result"], c["reasons"]) for c in checks} == expected


def test_the_rehearsal_is_a_mode_of_the_file_with_10_groups_and_30_sessions():
    from scripts import protocol_v5
    plan = protocol_v5.plan(json.loads(V5.read_text()), mode="rehearsal")
    assert (plan["mode"], plan["name"], plan["group_prefix"]) == ("rehearsal", "server-normal-v5-generalka", "g5-")
    assert (len({s["group"] for s in plan["sessions"]}), len(plan["sessions"])) == (10, 30)


def test_the_skeletons_form_of_the_command_checks_the_same_file(tmp_path):
    """S4 of the B4 verification: `collection.py selfcheck --protocol P` (skeleton §2) works like the global form."""
    from scripts import collection
    after, before = tmp_path / "after.json", tmp_path / "before.json"
    assert collection.main(["selfcheck", "--protocol", str(V5), "--out", str(after)]) == 2
    assert collection.main(["--protocol", str(V5), "selfcheck", "--out", str(before)]) == 2
    assert json.loads(after.read_text()) == json.loads(before.read_text())


# Package B5b (lead's remarks on B4, part 1, section 1): the loader binds determined_at as scripts/gates.py does, and
# the row reachability fails when a witness had to fall back to worst_invalid_rows. Every other check gives what it
# gives for the real file.

def expected_checks(**failures):
    expected = {name: ("passed", []) for name in CHECKS}
    expected["lab_register"] = ("pending", [PENDING])
    expected.update({name: ("failed", reasons) for name, reasons in failures.items()})
    return expected


@pytest.mark.parametrize("stage, path, reason", [
    ("G2", "analysis.k1", "determined_at path analysis.k1 (G2) would delete analysis.k1.m (G1)"),
    ("G3a", "determined_at.G1",
     "determined_at path must start with a protocol key other than determined_at: determined_at.G1"),
], ids=["deletes_an_earlier_path", "names_determined_at"])
def test_the_loader_refuses_a_determined_at_that_a_stage_record_could_not_bind(tmp_path, stage, path, reason):
    from scripts import gates
    doc = json.loads(V5.read_text())
    doc["determined_at"][stage].append(path)
    with pytest.raises(ValueError) as refused:
        gates.later_paths(doc["determined_at"], "G0")
    assert str(refused.value) == reason
    code, report = selfcheck(tmp_path, doc)
    assert code == 2
    assert {c["check"]: (c["result"], c["reasons"]) for c in report["checks"]} == expected_checks(
        loader=["protocol(): invalid determined_at: " + reason])


def test_reachability_fails_when_a_witness_falls_back_to_worst_invalid_rows(tmp_path, monkeypatch):
    """With too few placements allowed the witnesses of 3 and 4 rows are those of worst_invalid_rows: 33 rows apart,
    so the one of 4 rows is periodic as well."""
    from features import acceptance
    monkeypatch.setattr(acceptance, "WITNESS_STEPS", 10)  # The v5 grid needs 33 placements per row.
    code, report = selfcheck(tmp_path, json.loads(V5.read_text()))
    assert code == 2
    assert {c["check"]: (c["result"], c["reasons"]) for c in report["checks"]} == expected_checks(reachability=[
        "witness with invalid_rows.max + 1 rows is not refused by the gate alone",
        "witness with invalid_rows.max rows fell back to worst_invalid_rows",
        "witness with invalid_rows.max + 1 rows fell back to worst_invalid_rows"])
