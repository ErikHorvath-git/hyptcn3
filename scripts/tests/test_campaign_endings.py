"""The endings of a campaign of protocol v5, their records, the pause and the one continuation (package B9b, agent R).

Binding texts: the design dokazy/B9/navrh/NAVRH_B9b.md sections 1.1 and 1.2 and its addendum (section 3), the lead's
skeleton dokazy/B9/kostra/KOSTRA.md (the rows pozastavenie, jedno pokračovanie, záznam pri uzavretí, the addendum on
Q2), finding N2 of B7c and N1 of the confirmation of B9a. Skeleton tests 3, 4 and 5 are agent T's
(scripts/tests/test_campaign_v5.py); this file pins what those tests do not reach:

    the register of exceptions in the record     the lead's answer to Q2 (two sessions, the maximum, the count over the
                                                 expected one, a null register)
    the interleave of the realized boots         INTERLEAVE_RULE, from the measured times of the sessions
    the frozen tree and the frozen hashes        FROZEN_TREE_RULE (the records this campaign wrote) and INVALID_RULE
    a changed hash during a run                  the invalid ending, its record, and the refusals of an invalid campaign
    a pause beside a held runner                 the addendum's order bullet: the other runner, held in the barrier,
                                                 stops at its next check and the paused record says that it waited
    an operator's stop and its resume            the reason as a deviation, the resume to the complete ending, one
                                                 record per ending
    a pending ending after a crash               settle: recorded once by the next run
    the one continuation                         every refusal by name, and the records of a continuation

The fix round of B9b (dokazy/B9/navrh/OPRAVA_B9b.md section 1, the verifier's probes of dokazy/B9/overenie_B9b/sondy):

    F2  a new file beside the frozen lab        a change of the tree that stops the run until it is removed; a changed
                                                tracked file makes the campaign invalid (the hashes before the tree);
                                                the continuation names a new file and stays possible
    F3  a complete or a closed campaign         run and launch refused by name before verify_frozen, no record
    F6  the history in the deviations           the earlier endings, an unclean end, the written cause of a resume
                                                after an early stop
    F10 a captured session not yet judged       its own state in the record
    F11 the entry of docs/MERANIA.md            in the record of a closing ending, printed with the record's sha256

The campaigns run on the harness scripts/tests/kampan_v5.py: the real init and runners, real archives, the real
ledger in the test's directory, fakes of the lab, the capture and the audit. RESULTS, the directory of the records,
is the test's own. Names of package B9b are reached only inside the tests, so this file collects on the code before
it. Only mechanics on synthetic sessions; no number here is a measurement (HONESTY P4).
"""
from collections import Counter
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import threading
import time

import pytest

from scripts import campaign as c
from scripts import collection
from scripts import protocol_v5 as pv
from scripts.collection_archive import digest, read_json, write_new
from scripts.tests.kampan_v5 import GROUP_START, PERIODICITY, TRACKED_LEDGER, VMS, Harness
from scripts.tests.test_multivm import no_inherited_lock  # noqa: F401 (autouse fixture: no inherited lock)

REAL_VERIFY = c.verify_frozen  # The real frozen-tree check, which the harness replaces (its git is the harness's).
TRACKED = digest(TRACKED_LEDGER) if TRACKED_LEDGER.exists() else None
REAL_RESULTS = c.ROOT / "data/results"
RECORDS_BEFORE = sorted(path.name for path in REAL_RESULTS.glob("kampan_*.json"))
# How long a test lets a runner in a thread take before it fails instead of hanging (judgment of the test: a held
# runner polls every POLL_S and the other runner's step takes a few seconds on this harness).
THREAD_S, POLL_S, GRACE_S = 60, 0.01, 30


@pytest.fixture(autouse=True)
def _the_repository_is_untouched():
    """No test writes the tracked ledger or a record into the repository's data/results."""
    yield
    assert (digest(TRACKED_LEDGER) if TRACKED_LEDGER.exists() else None) == TRACKED
    assert sorted(path.name for path in REAL_RESULTS.glob("kampan_*.json")) == RECORDS_BEFORE


class NoSignals:
    """collection.Interrupts without signal handlers (a runner in a thread cannot install them); nothing signals."""

    def __init__(self):
        self.received, self.armed = [], True

    def disarm(self):
        self.armed = False

    def restore(self):
        pass


def harness(tmp_path, monkeypatch):
    """The harness of kampan_v5 with RESULTS in the test's directory (set also on the code before package B9b, which
    has none, so that a test there fails on the behavior it pins, not on its setup)."""
    h = Harness(tmp_path, monkeypatch)
    monkeypatch.setattr(c, "RESULTS", tmp_path / "results", raising=False)
    return h


def ended_rehearsal(h, protocol, name="skuska-generalka"):
    """An ended rehearsal of `protocol` as init --estimate-from reads it (DISK_RULE): campaign.json of mode rehearsal,
    protocol.json, the sizes of one accepted session and closed.json (scripts/tests/test_campaign.py ended_rehearsal)."""
    directory = h.root / "rehearsals" / name
    (directory / "attempts").mkdir(parents=True)
    shutil.copyfile(protocol, directory / "protocol.json")
    write_new(directory / "campaign.json", {"schema": "hyptcn3/collection-campaign/1", "id": name, "mode": "rehearsal",
                                            "archive_compression": None, "vms": {"a": {}, "b": {}}})
    write_new(directory / "attempts" / "s0.done.json", {"session": "s0", "session_bytes": 1000, "archive_bytes": 1000})
    write_new(directory / "closed.json", {"reason": "the rehearsal ended"})
    return directory


def campaign_of(h, limit, name="kampan"):
    """A campaign of mode campaign of the harness's protocol (limit `limit`), seeded by an ended rehearsal."""
    protocol = h.protocol(name + "-protocol", limit=limit)
    return h.init(protocol, "campaign", name, estimate_from=ended_rehearsal(h, protocol, name + "-generalka"))


def records(directory):
    """[(ending, record)] of the endings a campaign recorded, oldest first; each record is the file endings/ names,
    with the sha256 it names."""
    out = []
    for pointer in c.endings(directory):
        path = c.RESULTS / pointer["record"]
        assert digest(path) == pointer["sha256"], pointer
        out.append((pointer["ending"], read_json(path)))
    return out


def first_row(h, directory, group):
    return next(r for r in h.plan_rows(directory) if r["group"] == group)


def stop_during_the_first_capture(h, monkeypatch, directory, vm, reason):
    """The operator's request-stop of the VM's runner while its first capture runs (the runner is active then)."""
    asked = []

    def capture(a, p):
        h.capture(a, p)
        if p["vm"] == vm and not asked:
            asked.append(c.request_stop(directory, vm, reason))
    monkeypatch.setattr(collection, "run_session", capture)
    return asked


def entry(session, exceptions):
    """(row, session directory, audit values) of an accepted session as ending_sessions gives it."""
    values = {} if exceptions is None else {"exceptions": exceptions}
    return {"session": session, "final": True, "state": "accepted"}, None, values


def observed(**counts):
    """values.exceptions of an audit: every registered id, the given ones with their counts."""
    from features.audit_policy import TOLERATED
    return {name: {"observed": counts.get(name, 0), "expected": None, "over": False} for name in TOLERATED}


@pytest.mark.parametrize("expected, over", [(None, 0), (2, 1)], ids=["null_register", "expected_2"])
def test_the_record_gives_the_largest_count_and_the_sessions_over_the_expected_count(expected, over):
    """The skeleton's addendum on Q2 (design 1.1, values.exceptions): per register id the largest count in one accepted
    session and the number of accepted sessions over the expected count, judged by features/audit_policy.py
    exceptions_record against the protocol's register; a null expected count (until G3a) gives 0 over. An audit
    without values.exceptions is not recorded, by name, never 0, and so is one with an id the register lacks."""
    p = collection.protocol(c.ROOT / "config/collection-v5.json")
    p["exceptions"]["invalid_rows"] = dict(p["exceptions"]["invalid_rows"], expected=expected)
    summary = c.exceptions_summary(p, [entry("s1", observed(invalid_rows=1)), entry("s2", observed(invalid_rows=3)),
                                       entry("s3", None), entry("s4", {**observed(), "unregistered": {"observed": 1}})])
    rows = summary["by_id"]["invalid_rows"]
    assert (rows["max_in_one_session"], rows["sessions_over_expected"], rows["expected"], rows["sessions_counted"]) \
        == (3, over, expected, 2)
    assert summary["by_id"]["rule_closed_rows"] == {"max_in_one_session": 0, "sessions_over_expected": 0,
                                                    "expected": None, "sessions_counted": 2}
    assert summary["not_recorded"] == [{"session": "s3", "reason": "the audit records no values.exceptions"},
                                       {"session": "s4", "reason": "unregistered exception: unregistered"}]


def boots(tmp_path, times):
    """Sessions of the four test groups of the harness's plan (tb-1@b, tc-1@a, tb-2@a, tc-2@b, in this order) with the
    measured times `times` {group: (start, end)}, as ending_sessions gives them, and the campaign's plan."""
    groups = {"v5-test_benign-1": ("test_benign", "b"), "v5-test_controls-1": ("test_controls", "a"),
              "v5-test_benign-2": ("test_benign", "a"), "v5-test_controls-2": ("test_controls", "b")}
    rows, plan = [], []
    for group, (role, vm) in groups.items():
        plan.append({"group": group, "role": role, "vm": vm})
        if group not in times:
            continue
        session = tmp_path / group
        session.mkdir()
        start, end = times[group]
        write_new(session / "end.json", {"measure_start_unix": start, "measure_end_unix": end})
        rows.append(({"session": group + "_01", "role": role, "group": group, "vm": vm}, session, None))
    return rows, {"sessions": plan}


@pytest.mark.parametrize("times, late, alternation", [
    ({"v5-test_benign-1": (0, 100), "v5-test_controls-1": (50, 150), "v5-test_benign-2": (160, 260),
      "v5-test_controls-2": (170, 270)}, [], []),
    ({"v5-test_benign-1": (0, 100), "v5-test_controls-1": (50, 150), "v5-test_benign-2": (160, 260),
      "v5-test_controls-2": (300, 400)}, ["v5-test_controls-2"], []),
    ({"v5-test_controls-1": (0, 100), "v5-test_controls-2": (10, 110), "v5-test_benign-1": (20, 120),
      "v5-test_benign-2": (30, 130)}, [], ["v5-test_controls-2"]),
    ({"v5-test_benign-1": (0, 100)}, [], []),
], ids=["interleaved", "late_controls", "alternation", "one_boot"])
def test_the_interleave_of_the_realized_boots_names_its_violation(tmp_path, times, late, alternation):
    """INTERLEAVE_RULE (the addendum of design B9b, skeleton test 2 over the realized boots): a test_controls boot that
    starts at or after the end of every test_benign boot is late; the starts break the alternation when the share rule
    of protocol_v5.check_role_order against the plan's group counts fails; the order is that of the first measured
    starts; a violation is a deviation of the record with its cause. One realized boot is no violation."""
    rows, campaign = boots(tmp_path, times)
    check = c.interleave_check(rows, campaign)
    assert (check["ok"], check["late_controls"], check["alternation"]) == (not late and not alternation, late,
                                                                           alternation)
    assert [b["group"] for b in check["order"]] == sorted(times, key=lambda g: times[g][0])
    assert check["order"][0]["start"] == min(start for start, _ in times.values())
    events = c.deviation_events(tmp_path, campaign, [], check)
    if check["ok"]:
        assert events == []
        return
    event, = events
    assert event["event"] == "interleave" and all(group in event["cause"] for group in late + alternation)
    assert ("not their ends" in event["cause"]) == bool(late)


def frozen(tmp_path, monkeypatch, status, *, name="kampan-x"):
    """A campaign directory of protocol schema 3 for verify_frozen, its frozen files beside an external copy; git
    status gives `status`; the campaign wrote one record (endings/ and RESULTS)."""
    from scripts import gates
    directory = tmp_path / name
    directory.mkdir()
    monkeypatch.setattr(c, "RESULTS", tmp_path / "results", raising=False)  # As harness().
    monkeypatch.setattr(c, "git", lambda *args: "frozen" if args[0] == "rev-parse" else status)
    monkeypatch.setattr(c, "runtime_identity", lambda: {"version": "old"})
    monkeypatch.setattr(c, "tree_hashes", lambda _: {"hash": "old"})
    monkeypatch.setattr(c, "extractor_hashes", lambda: {"hash": "old"})
    monkeypatch.setattr(c, "guard_mount", lambda *a: None)
    external = tmp_path / "external"
    external.mkdir()
    manifest = {"id": name, "commit": "frozen", "runtime": {"version": "old"}, "profile_sha256": {"hash": "old"},
                "extractor_sha256": {"hash": "old"}, "mode": "campaign", "archive_root": str(external),
                "archive_mount": {}, "archive_dir": str(external), "owner": {"name": "test"},
                "measurement_sha256": gates.measurement_sha256(),
                "measurement_files_sha256": collection.measurement_sources(), "lab_sha256": collection.lab_sha256()}
    for filename in c.frozen_files(manifest):
        for place in (directory, external):
            (place / filename).write_text(filename)
    record = c.publish_ending(directory, manifest, {"date": "2026-11-24T00:00:00+00:00",
                                                    "values": {"ending": "stopped", "cause": "a test"}})
    return directory, manifest, record


@pytest.mark.parametrize("case", ["own", "own_staged", "own_changed", "other_campaign", "no_pointer"])
def test_the_frozen_tree_admits_only_the_records_this_campaign_wrote(tmp_path, monkeypatch, case):
    """FROZEN_TREE_RULE (design 1.1): beside the ledger, verify_frozen of a campaign of protocol schema 3 admits the
    new or modified records data/results/kampan_<its id>_*.json it wrote, each with the sha256 its endings/ names;
    a record changed since, another campaign's record and one of its name that endings/ does not name are changes."""
    p = {"schema": pv.SCHEMA, "profile": "unused"}
    directory, manifest, record = frozen(tmp_path, monkeypatch, "")
    name = record.name
    status = {"own": f"?? data/results/{name}", "own_staged": f"A  data/results/{name}",
              "own_changed": f"?? data/results/{name}",
              "other_campaign": "?? data/results/" + name.replace("kampan_kampan-x_", "kampan_kampan-y_"),
              "no_pointer": "?? data/results/" + re.sub(r"_[0-9]{8}T[0-9]{12}Z", "_20261124T000000000000Z", name)}[case]
    monkeypatch.setattr(c, "git", lambda *args: "frozen" if args[0] == "rev-parse" else status)
    if case == "own_changed":
        record.write_text(record.read_text() + " ")
    if case in ("own", "own_staged"):
        c.verify_frozen(directory, manifest, p)
        return
    with pytest.raises(ValueError, match="^" + re.escape("campaign source changed; restore frozen commit before "
                                                         f"resuming (changed: {status})") + "$"):
        c.verify_frozen(directory, manifest, p)


MEASUREMENT_CODE = ("the measurement code (scripts/gates.py measurement_sha256 over scripts/collection.py "
                    "measurement_sources")
NEW_FILES = (" (new files beside the frozen measurement code and lab: {}; remove them and run again, "
             "scripts/campaign.py INVALID_RULE)")


@pytest.mark.parametrize("case, said", [
    ("measurement", MEASUREMENT_CODE + ": scripts/collection.py) changed during the campaign"),
    ("lab", "the lab (scripts/collection.py lab_sha256: lab/udalosti.py) changed during the campaign"),
    ("gone", MEASUREMENT_CODE + ": scripts/labctl.py) changed during the campaign"),
    ("missing", "campaign.json of protocol schema 3 freezes no measurement_files_sha256 (init records the measurement "
                "code and the lab file by file since the fix round of package B9b"),
    ("new", "campaign source changed; restore frozen commit before resuming" + NEW_FILES.format("lab/stary.pyc")),
], ids=["measurement", "lab", "gone", "missing", "new"])
def test_the_frozen_hashes_name_what_changed(tmp_path, monkeypatch, case, said):
    """INVALID_RULE (design 1.2 and F2 of the verification of B9b): verify_frozen of a campaign of protocol schema 3
    compares the measurement code and the lab with the maps init froze file by file, before the tree; a file of the
    frozen set changed or gone is CampaignInvalid, the file named; a new file beside them (here one git ignores, so that
    only the hashes see it) is a change of the tree, refused by name and not invalid; a campaign.json without the
    per-file map is refused by name."""
    directory, manifest, _ = frozen(tmp_path, monkeypatch, "")
    p = {"schema": pv.SCHEMA, "profile": "unused"}
    sources, lab = collection.measurement_sources(), collection.lab_sha256()
    if case == "measurement":
        monkeypatch.setattr(collection, "measurement_sources", lambda: {**sources, "scripts/collection.py": "0" * 64})
    elif case == "lab":
        monkeypatch.setattr(collection, "lab_sha256", lambda: {**lab, "lab/udalosti.py": "0" * 64})
    elif case == "gone":
        monkeypatch.setattr(collection, "measurement_sources",
                            lambda: {k: v for k, v in sources.items() if k != "scripts/labctl.py"})
    elif case == "new":
        monkeypatch.setattr(collection, "lab_sha256", lambda: {**lab, "lab/stary.pyc": "0" * 64})
        monkeypatch.setattr(collection, "measurement_sources", lambda: {**sources, "lab/stary.pyc": "0" * 64})
    else:
        del manifest["measurement_files_sha256"]
    with pytest.raises(ValueError, match="^" + re.escape(said) + ("$" if case == "new" else "")) as refused:
        c.verify_frozen(directory, manifest, p)
    assert isinstance(refused.value, c.CampaignInvalid) == (case not in ("missing", "new"))


@pytest.mark.parametrize("change", ["measurement", "lab"])
def test_a_hash_that_changes_during_a_run_makes_the_campaign_invalid(tmp_path, monkeypatch, change):
    """INVALID_RULE (design 1.2): the run that finds the measurement code or the lab changed since init ends the
    campaign as invalid, with its record; an invalid campaign never runs again, has no corpus (finish_corpus refuses
    it by name) and is never continued. The real verify_frozen on the harness's git (a clean tree at the commit)."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    monkeypatch.setattr(c, "verify_frozen", REAL_VERIFY)
    h.step(directory, "a")  # One accepted session under the frozen code.
    if change == "measurement":
        sources = collection.measurement_sources()
        monkeypatch.setattr(collection, "measurement_sources", lambda: {**sources, "scripts/collection.py": "0" * 64})
    else:
        lab = collection.lab_sha256()
        monkeypatch.setattr(collection, "lab_sha256", lambda: {**lab, "lab/udalosti.py": "0" * 64})
    with pytest.raises(c.CampaignInvalid, match="changed during the campaign"):
        h.step(directory, "a")
    (ending, record), = records(directory)
    v = record["values"]
    assert (ending, v["ending"], v["ending_name"], record["schema"]) == ("invalid", "invalid", "neplatná",
                                                                         c.ENDING_SCHEMA)
    assert v["cause"].startswith("error: ") and "changed during the campaign" in v["cause"]
    assert [x["event"] for x in v["deviations"]] == ["invalidation"]
    assert h.status(directory, "a")["status"] == "invalid" and c.held_ending(directory) == "invalid"
    assert v["accepted_sessions"] == 1 and v["planned_sessions"] == len(h.plan_rows(directory))
    with pytest.raises(ValueError, match="is invalid: it does not run again, has no corpus and is never continued"):
        c.execute(directory, vm="b")
    manifest, p = c.load_campaign(directory)
    with pytest.raises(ValueError, match="is invalid: an invalid campaign has no corpus"):
        c.finish_corpus(directory, manifest, p, [])
    with pytest.raises(ValueError, match="ended invalid, not paused: only a paused campaign is continued"):
        c.continuable(directory, manifest)


def test_a_pause_ends_the_wait_of_the_other_runner_and_its_record_says_that_it_waited(tmp_path, monkeypatch):
    """PAUSE_RULE and the addendum of design B9b (order): VM b's runner is held in the barrier of ORDER_RULE before
    v5-test_controls-2, active, while VM a's first session of v5-test_controls-1 is rejected over the limit (0): the
    campaign pauses; VM a's runner stops and writes VM b's stop request; VM b's runner stops at its next check
    through it, as part of the pause, and as the last runner to stop writes the one paused record, which names what
    it was held for. Both runners end paused, and the paused campaign does not run again."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=0)
    first = first_row(h, directory, "v5-test_controls-1")
    h.reject.add((first["group"], first["scenario"], 1))
    targets = {"a": "v5-test_controls-1", "b": "v5-test_controls-2"}
    for _ in range(100):  # Both runners in turn until each VM's next session is the first of its target group.
        due = [vm for vm, group in targets.items() if h.pending(directory, vm)[0]["group"] != group]
        if not due:
            break
        assert any([h.step(directory, vm) for vm in due]), "the runners deadlock"
    monkeypatch.setattr(c, "START_GRACE_S", GRACE_S)
    monkeypatch.setattr(c, "WAIT_POLL_S", POLL_S)
    monkeypatch.setattr(collection, "Interrupts", NoSignals)
    outcome = []

    def run_b():
        try:
            outcome.append(c.execute(directory, vm="b"))
        except BaseException as error:  # noqa: BLE001 - reported by the test
            outcome.append(error)
    held = threading.Thread(target=run_b, daemon=True)
    held.start()
    try:
        deadline = time.monotonic() + THREAD_S
        while h.status(directory, "b").get("stage") != "role-wait":
            assert held.is_alive() and time.monotonic() < deadline, (outcome, h.status(directory, "b"))
            time.sleep(POLL_S)
        assert h.status(directory, "b")["status"] == "running"
        h.step(directory, "a")  # Its first session of v5-test_controls-1 is rejected over the limit: the pause.
        held.join(THREAD_S)
    finally:
        if held.is_alive():  # A failure: the held runner ends by a stop request before the patches are undone.
            write_new(directory / "stop-request-b.json", {"reason": "the end of a failed test"})
            held.join(THREAD_S)
    assert not held.is_alive() and outcome == [0], outcome
    (ending, record), = records(directory)
    v = record["values"]
    assert (ending, v["ending"], v["ending_name"]) == ("paused", "paused", "pozastavená")
    assert v["cause"].startswith("the limit of replacements is used up (0 per campaign): session "
                                 + first["session_id"])
    runners = {r["vm"]: r for r in v["runners"]}
    assert (runners["a"]["status"], runners["a"]["stage"]) == ("paused", "limit")
    assert (runners["b"]["status"], runners["b"]["active"]) == ("paused", False)
    assert runners["b"]["message"].startswith("the campaign is ending (paused, VM a: the limit of replacements")
    assert "the start of the groups before v5-test_controls-2 in the plan: v5-test_benign-2 (VM a)" \
        in runners["b"]["waited"]
    request, = (read_json(path) for path in (directory / "events").glob("*_stop-request-b.json"))
    assert (request["ending"], request["by"]) == ("paused", "a")
    assert v["rejected_sessions"] == [{"session": first["session_id"], "cause": "audit_rejected", "replacement": None,
                                       "campaign": directory.name}]
    assert v["rejections_by_cause"] == {"audit_rejected": 1} and v["limit"] == {"applied": True,
                                                                               "max_per_campaign": 0, "used": 0}
    # INTERLEAVE_RULE over the boots realized so far: in this schedule VM b ran its v5-test_benign-1 to its end before
    # VM a started v5-test_controls-1, so that boot lies wholly after every realized test_benign boot.
    assert [x["event"] for x in v["deviations"]] == ["pause", "interleave"]
    assert v["interleave"]["late_controls"] == ["v5-test_controls-1"] and not v["interleave"]["ok"]
    assert not (directory / "ending.json").exists()
    for vm in ("a", "b"):
        assert h.status(directory, vm)["status"] == "paused"
        with pytest.raises(ValueError, match="is paused: it does not run again; continue it once with init "):
            c.execute(directory, vm=vm)


def test_an_operator_stop_names_its_reason_and_the_resume_ends_complete(tmp_path, monkeypatch):
    """ENDING_RULE (design 1.1 and 1.2): under protocol schema 3 request-stop names its reason (refused without one);
    the runner that honors it ends the campaign as stopped with one record whose deviations hold the reason; the
    stopped campaign runs again (today's resume) to its complete ending, whose record comes before the index, holds
    the earlier stop among its deviations, counts what tcn.finalne reads and names the seed of the guest's reset with
    the protocol's sha256. The fix round of B9b: the complete record names the earlier stopped ending by its kind,
    cause, record and sha256 (F6); the stopped campaign takes no --cause, which answers an early stop only
    (RESUME_RULE); and the complete campaign is refused by name when it is run again (F3), with no record and no
    index again."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    with pytest.raises(ValueError, match=r"^a stop of a campaign of protocol schema 3 names its reason \(--reason"):
        c.request_stop(directory, "a")
    asked = stop_during_the_first_capture(h, monkeypatch, directory, "a", "the owner needs the host for an hour")
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(directory, vm="a") == 0
    assert asked == [None] and len(h.of(directory)) == 1
    state = h.status(directory, "a")
    assert (state["status"], state["stage"], state["message"]) == (
        "stopped", "between-sessions", "operator stop request: the owner needs the host for an hour")
    (ending, stopped), = records(directory)
    v = stopped["values"]
    assert (ending, v["cause"]) == ("stopped", "operator stop request: the owner needs the host for an hour")
    stop, = v["deviations"]
    assert (stop["event"], stop["vm"], stop["reason"]) == ("operator_stop", "a", "the owner needs the host for an hour")
    assert all(key in stopped for key in ("commit", "date", "host", "guest", "command", "n", "values"))
    assert stopped["command"] == f"python3 scripts/campaign.py run {Path(directory).resolve()} --vm a"
    manifest = h.manifest(directory)
    assert v["reset_seed"] == {"seed": 0, "key": "streams.seeded_level.seed",
                               "protocol_sha256": manifest["protocol_sha256"]}
    assert v["deviation_log"] == {"path": "docs/ODCHYLKY_V5.sk.md", "sha256": digest(c.ROOT / "docs/ODCHYLKY_V5.sk.md")}
    assert stopped["stage"] == v["stage"]["stage"] == "suchy" and v["stage"]["basis"]  # The test's ledger, no HEAD.
    assert Counter(r["state"] for r in v["sessions"]) == {"accepted": 1, "not run": len(h.plan_rows(directory)) - 1}
    with pytest.raises(ValueError, match="^" + re.escape("--cause answers an early stop, and the last recorded "
                                                         "ending of campaign kampan is no early stop: run it without "
                                                         "--cause")):
        c.execute(directory, vm="a", cause="no early stop to answer")
    h.run(directory)
    (first, _), (last, complete) = records(directory)
    w = complete["values"]
    assert (first, last, w["ending"], w["ending_name"]) == ("stopped", "complete", "complete", "úplná")
    index = read_json(directory / "corpus.json")
    assert w["accepted_sessions"] == w["planned_sessions"] == len(index["sessions"]) == len(h.plan_rows(directory))
    assert (w["rejected_sessions"], w["rejections_by_cause"]) == ([], {})
    assert [x["event"] for x in w["deviations"]] == ["operator_stop", "earlier_ending"]
    pointer = c.endings(directory)[0]
    assert {key: w["deviations"][1][key] for key in ("ending", "cause", "record", "sha256")} == {
        "ending": "stopped", "cause": v["cause"], "record": pointer["record"], "sha256": pointer["sha256"]}
    assert digest(c.RESULTS / c.latest_ending(directory)["record"]) == c.latest_ending(directory)["sha256"]
    assert {r["state"] for r in w["sessions"]} == {"accepted"} and len(w["unscored"]["sessions"]) == len(index["sessions"])
    # Question Q21 (accepted by the lead 2026-11-24): the ledger of record in the working tree holds every accepted
    # session of the sealed roles (the harness's KNIHA and ZAZNAM are one file), so the complete record is final; the
    # ledger at HEAD is not asked, tcn.finalne checks it when it reads the record.
    basis = w["stage"]["basis"]
    assert complete["stage"] == w["stage"]["stage"] == "final" and basis["sealed"] == 12, basis
    assert (basis["of_record"], basis["at_head"], basis["seal_in_git"], basis["missing"]) == (True, False, None, [])
    assert basis["ledger_sha256"] == digest(h.ledger) and "tcn.finalne" in basis["head"]
    record = c.latest_ending(directory)["record"]
    finished, said = len(h.finished), (f"campaign kampan is complete (record {record}) and its index is built: it "
                                       "does not run again (scripts/campaign.py ENDING_RULE)")
    for vm in ("a", "b"):
        with pytest.raises(ValueError, match="^" + re.escape(said) + "$"), contextlib.redirect_stdout(io.StringIO()):
            c.execute(directory, vm=vm)
    assert len(records(directory)) == 2 and len(h.finished) == finished  # F3: no record again, no index again.


def test_a_pending_ending_whose_last_runner_died_is_recorded_once_by_the_next_run(tmp_path, monkeypatch):
    """ENDING_RULE (settle): an ending left pending by a runner that died before its record (SIGKILL, a crash: its
    status still running, its process gone) is recorded by the next run of the campaign, once; a stopped campaign
    then runs on (today's resume), and a pending ending already recorded is only removed."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    h.step(directory, "a")
    manifest, p = c.load_campaign(directory)
    c.begin_ending(directory, p, "a", "stopped", "error: a test's crash", {"stage": "error"})
    state = h.status(directory, "a")
    write_new(directory / "status-a.json", {**state, "status": "running", "process_identity": {"alive": -1}},
              replace=True)  # Its process is gone.
    pending = read_json(directory / "ending.json")
    assert h.step(directory, "b")
    (ending, record), = records(directory)
    assert (ending, record["values"]["cause"]) == ("stopped", "error: a test's crash")
    assert [t["vm"] for t in record["values"]["triggers"]] == ["a"] and not (directory / "ending.json").exists()
    write_new(directory / "ending.json", pending)  # Recorded, but not removed (a crash between the two).
    assert c.settle(directory, manifest, p, command="test") is None
    assert len(records(directory)) == 1 and not (directory / "ending.json").exists()


@pytest.mark.parametrize("case, said", [
    ("stopped", "ended stopped, not paused: only a paused campaign is continued"),
    ("closed", "was closed by the operator: only a paused campaign is continued"),
    ("pending", "has an ending not yet recorded (stopped: a test): a run of one of its VMs records it first"),
    ("record_changed", "the paused record of campaign kampan is changed"),
    ("lab_changed", "the lab (scripts/collection.py lab_sha256: lab/udalosti.py) changed since campaign kampan was "
                    "frozen: a continuation needs the measurement code and the lab unchanged"),
    ("mode", "a continuation continues a paused campaign of mode campaign (a rehearsal never pauses)"),
    ("cause_alone", "--cause belongs to --continue"),
    ("continued", None),
], ids=["stopped", "closed", "pending", "record_changed", "lab_changed", "mode", "cause_alone", "continued"])
def test_the_one_continuation_needs_a_paused_campaign_and_names_every_refusal(tmp_path, monkeypatch, case, said):
    """CONTINUATION_RULE (design 1.2): init --continue of protocol schema 3 needs the paused record of the campaign it
    continues, a written cause, the mode campaign and an unchanged lab; a stopped or closed campaign, one with an
    ending still pending and a changed paused record are refused by name, before anything is frozen (skeleton test 3
    has the missing cause and the changed measurement code, agent T). The continuation names the paused record, its
    cause and the paused campaign's rejections, its records carry them on (the continuation as a deviation, the
    rejections in rejected_sessions), and a continuation is never continued. Package B11 (the lead's answer to Q24):
    the records of the continuation carry the deviations of the paused record as well, each tagged with the paused
    campaign and that record."""
    h = harness(tmp_path, monkeypatch)
    protocol = h.protocol("kampan-protocol", limit=0)
    rehearsal = ended_rehearsal(h, protocol)
    directory = h.init(protocol, "campaign", "kampan", estimate_from=rehearsal)
    first = h.plan_rows(directory)[0]
    if case == "stopped":
        stop_during_the_first_capture(h, monkeypatch, directory, first["vm"], "a test")
        with contextlib.redirect_stdout(io.StringIO()):
            c.execute(directory, vm=first["vm"])
    else:
        h.reject.add((first["group"], first["scenario"], 1))
        h.step(directory, first["vm"])  # Rejected over the limit 0: the pause.
        assert c.latest_ending(directory)["ending"] == "paused"
    if case == "closed":
        c.close(directory, "the owner ends it")
    elif case == "pending":
        manifest, p = c.load_campaign(directory)
        c.begin_ending(directory, p, "a", "stopped", "a test")
    elif case == "record_changed":
        path = c.RESULTS / c.latest_ending(directory)["record"]
        os.chmod(path, 0o644)
        path.write_text(path.read_text() + " ")
    elif case == "lab_changed":
        lab = collection.lab_sha256()
        monkeypatch.setattr(collection, "lab_sha256", lambda: {**lab, "lab/udalosti.py": "0" * 64})
    argv = ["init", "--protocol", str(protocol), "--mode", "rehearsal" if case == "mode" else "campaign",
            "--archive-root", str(h.archive), "--name", "pokracovanie", "--archive-on-system-disk",
            "--archive-compression", "none", *([] if case == "mode" else ["--estimate-from", str(rehearsal)]),
            *([] if case == "cause_alone" else ["--continue", str(directory)]),
            "--cause", "the gap came from the host's backup job, now disabled"]
    if said is not None:
        with pytest.raises(ValueError, match=re.escape(said)), contextlib.redirect_stdout(io.StringIO()):
            c.main(argv)
        assert not (h.base / "pokracovanie").exists()
        return
    with contextlib.redirect_stdout(io.StringIO()):
        c.main(argv)
    h.campaigns.append(h.base / "pokracovanie")
    continuation = h.base / "pokracovanie"
    record = h.manifest(continuation)["continues"]
    pointer = c.latest_ending(directory)
    assert (record["campaign"], record["cause"]) == ("kampan", "the gap came from the host's backup job, now disabled")
    assert record["paused_record"] == {"record": pointer["record"], "sha256": pointer["sha256"],
                                       "date": pointer["date"]}
    assert record["rejected_sessions"] == [{"session": first["session_id"], "cause": "audit_rejected",
                                            "replacement": None, "campaign": "kampan"}]
    with pytest.raises(ValueError, match="is a continuation of kampan: a continuation is never continued"):
        c.continuable(continuation, h.manifest(continuation))
    h.reject.clear()  # The cause of the pause is gone (a second rejection over the limit would make it invalid).
    stop_during_the_first_capture(h, monkeypatch, continuation, first["vm"], "a test")
    with contextlib.redirect_stdout(io.StringIO()):
        c.execute(continuation, vm=first["vm"])
    (ending, stopped), = records(continuation)
    v = stopped["values"]
    assert ending == "stopped" and [(x["event"], x.get("campaign")) for x in v["deviations"]] == [
        ("pause", "kampan"), ("continuation", None), ("operator_stop", None)]
    paused = read_json(c.RESULTS / pointer["record"])["values"]["deviations"]
    assert v["deviations"][0] == {**paused[0], "campaign": "kampan", "carried_from": pointer["record"]}
    assert v["deviations"][1]["cause"] == "the gap came from the host's backup job, now disabled"
    assert v["rejected_sessions"] == record["rejected_sessions"]
    assert (v["continues"]["campaign"], v["continues"]["paused_record"]) == ("kampan", record["paused_record"])


def test_a_campaign_on_a_ledger_of_its_own_is_recorded_suchy(tmp_path, monkeypatch):
    """Question Q21 (accepted by the lead 2026-11-24; finding N2 of B7c): the ending record asks no ledger at HEAD,
    so a test or the G1 dry run that keeps a ledger of its own (tcn.pecat vlastna_kniha) must still be suchy:
    a campaign run to its end there seals its accepted sessions of the sealed roles into that ledger, and its complete
    record is suchy, its basis naming the ledger that is not the ledger of record."""
    from tcn import pecat
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    own = tmp_path / "own" / "kniha_pecati.json"
    own.parent.mkdir()
    with pecat.vlastna_kniha(own):
        h.run(directory)
    (ending, record), = records(directory)
    stage = record["values"]["stage"]
    assert (ending, record["stage"], stage["stage"]) == ("complete", "suchy", "suchy")
    assert (stage["basis"]["ledger"], stage["basis"]["of_record"]) == (str(own.resolve()), False)
    assert "is not the ledger of record" in stage["basis"]["why"]
    assert len(read_json(own)["values"]["archives"]) == 12 and not h.ledger.exists()


def test_a_resumed_run_starts_the_failed_group_again_and_the_campaign_completes(tmp_path, monkeypatch):
    """GROUP_START_RULE and question Q22 (accepted by the lead 2026-11-24: a failed start of a group is no session and
    does not charge the limit of replacements): a failed start of a group (labctl reset of VM a's first group fails
    once) is no rejection of a session: its record names the step and the
    cause group_start, the runner stops by name and the stopped record lists the failure. A resumed run starts the
    group again from its beginning (stop, start, reset, pretouch) and captures its sessions as planned, as attempt 1:
    nothing is replaced and the limit (0) is not charged; the campaign completes, and its complete record lists the
    failure, started again, in group_start_failures and among its deviations."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=0)
    first = h.plan_rows(directory)[0]
    h.lab.fail["a", "reset"] = 1
    with pytest.raises(ValueError, match="^" + re.escape(c.STOP_MESSAGE["group_start"] + ": reset: labctl reset ")), \
            contextlib.redirect_stdout(io.StringIO()):
        c.execute(directory, vm="a")
    failure, = (directory / "groups").glob(first["group"] + ".start-failed-*.json")
    doc = read_json(failure)
    assert (doc["group"], doc["session"], doc["cause"], doc["step"]) == (first["group"], first["session_id"],
                                                                         "group_start", "reset")
    assert [s["step"] for s in doc["output"]["steps"]] == ["stop", "start"] and doc["output"]["log_tail"]
    (ending, stopped), = records(directory)
    assert ending == "stopped" and stopped["values"]["cause"].startswith("group_start: ")
    listed, = stopped["values"]["group_start_failures"]
    assert (listed["record"], listed["step"], listed["started_again"]) == (failure.name, "reset", False)
    assert h.captures == [] and c.rejections(directory) == []
    h.run(directory)
    (_, _), (last, complete) = records(directory)
    v = complete["values"]
    assert last == "complete" and v["accepted_sessions"] == v["planned_sessions"] == len(h.plan_rows(directory))
    assert (v["rejected_sessions"], v["limit"]["used"], v["replacements_used"]) == ([], 0, 0)
    listed, = v["group_start_failures"]
    assert (listed["record"], listed["group"], listed["step"], listed["started_again"]) == (
        failure.name, first["group"], "reset", True)
    event, = (x for x in v["deviations"] if x["event"] == "group_start_failure")
    assert event["group"] == first["group"] and "failed at step reset, started again after the stop" in event["cause"]
    starts = [x["verb"] for x in h.lab.calls if x["vm"] == "a" and x["verb"] in GROUP_START]
    assert starts[:7] == ["stop", "start", "reset", "stop", "start", "reset", "pretouch"]
    capture, = (x for x in h.captures if x["sid"] == first["session_id"])
    assert (capture["attempt"], capture["replaces"]) == (1, None)


# ---------------------------------------------------------------- the fix round of B9b (agent R)

def tree_overlay(monkeypatch, h):
    """Files of the worktree that a test adds or changes without touching the repository (F2 of the verification of
    B9b): {path relative to the repository: a file of the same name under the test's directory}. The real hashing of
    scripts/collection.py reads them beside, or in place of, the files of the tree (measurement_sources through its
    own filter is_measurement, lab_files for a top-level file of lab/), and the harness's git status names each as git
    does: "??" for a new file, " M" for a tracked one changed, nothing for a name in `ignored` (a pattern of
    .gitignore). Returns (files, ignored)."""
    files, ignored = {}, set()
    real_sources, real_lab = collection.measurement_sources, collection.lab_files
    tracked = set(real_sources())

    def sources():
        found = real_sources()
        found.update({name: digest(path) for name, path in files.items() if collection.is_measurement(name)})
        return dict(sorted(found.items()))

    def lab_files():
        found = {path.name: path for path in real_lab()}
        found.update({Path(name).name: path for name, path in files.items()
                      if len(Path(name).parts) == 2 and Path(name).parts[0] == "lab"})
        return [found[name] for name in sorted(found)]

    def git(*args):
        if args[:1] == ("status",):
            return "\n".join((" M " if name in tracked else "?? ") + name for name in sorted(files)
                             if name not in ignored)
        return h.git(*args)
    monkeypatch.setattr(collection, "measurement_sources", sources)
    monkeypatch.setattr(collection, "lab_files", lab_files)
    monkeypatch.setattr(c, "git", git)
    return files, ignored


@pytest.mark.parametrize("case", ["untracked", "ignored", "changed"])
def test_a_new_file_beside_the_frozen_lab_stops_the_run_and_a_changed_one_makes_the_campaign_invalid(
        tmp_path, monkeypatch, case):
    """INVALID_RULE (F2 of the verification of B9b, its probes p10_swap.py and test_p10_swap_run.py): the real
    verify_frozen meets the tree between two sessions of VM a, with a git status as git gives it. A new file beside the
    frozen lab, an editor's swap file lab/.x.swp that git shows untracked or a compiled lab/stary.pyc that git ignores
    (labctl deploy copies either into the guest), changes neither the measurement code nor the lab: the run is refused
    by name as a change of the tree, the file named, and the campaign ends stopped, not invalid; once the file is
    removed the run goes on to the complete ending, whose record names that stop. A tracked measurement file changed,
    which git shows modified, makes the campaign invalid: the frozen hashes come before the tree (the verifier's mutant
    frozen_tree_before_hashes, F9, ends it stopped instead), and the invalid record carries its entry of
    docs/MERANIA.md (F11)."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    monkeypatch.setattr(c, "verify_frozen", REAL_VERIFY)
    files, ignored = tree_overlay(monkeypatch, h)
    assert h.step(directory, "a")  # One accepted session under the frozen tree.
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    if case == "changed":
        changed = overlay / "collection.py"
        changed.write_text((c.ROOT / "scripts/collection.py").read_text() + "\nCHANGED = True\n")
        files["scripts/collection.py"] = changed
        with pytest.raises(c.CampaignInvalid, match="^" + re.escape(MEASUREMENT_CODE + ": scripts/collection.py) "
                                                                    "changed during the campaign")):
            h.step(directory, "a")
        (ending, record), = records(directory)
        assert (ending, c.held_ending(directory), h.status(directory, "a")["status"]) == ("invalid",) * 3
        assert record["values"]["cause"].startswith("error: " + MEASUREMENT_CODE + ": scripts/collection.py)")
        assert record["values"]["merania_entry"].startswith("## ")
        return
    name = "lab/.x.swp" if case == "untracked" else "lab/stary.pyc"
    new = overlay / Path(name).name
    new.write_bytes(b"synthetic file of the test")
    files[name] = new
    if case == "ignored":
        ignored.add(name)
    said = ("campaign source changed; restore frozen commit before resuming"
            + ("" if case == "ignored" else f" (changed: ?? {name})") + NEW_FILES.format(name))
    with pytest.raises(ValueError, match="^" + re.escape(said) + "$") as refused:
        h.step(directory, "a")
    assert not isinstance(refused.value, c.CampaignInvalid)
    (ending, stopped), = records(directory)
    assert (ending, stopped["values"]["cause"]) == ("stopped", "error: " + said)
    assert c.held_ending(directory) is None and h.status(directory, "a")["status"] == "stopped"
    del files[name]  # The operator removes it, and the campaign runs on.
    new.unlink()
    assert h.step(directory, "a")
    h.run(directory)
    (_, _), (last, complete) = records(directory)
    earlier, = (x for x in complete["values"]["deviations"] if x["event"] == "earlier_ending")
    assert (last, earlier["ending"], earlier["record"]) == ("complete", "stopped", c.endings(directory)[0]["record"])


def test_a_new_file_refuses_the_continuation_by_name_and_leaves_the_campaign_paused(tmp_path, monkeypatch):
    """CONTINUATION_RULE (F2 of the verification of B9b): init --continue of a paused campaign compares the measurement
    code and the lab file by file. A new file beside them that git ignores (a compiled lab/stary.pyc, which labctl
    deploy would copy into the guest; git status stays clean, so init's own check of the tree passes) is refused by
    name, no campaign is left and the paused campaign stays paused, never invalid; once the file is removed, the
    continuation is set up."""
    h = harness(tmp_path, monkeypatch)
    protocol = h.protocol("kampan-protocol", limit=0)
    rehearsal = ended_rehearsal(h, protocol)
    directory = h.init(protocol, "campaign", "kampan", estimate_from=rehearsal)
    first = h.plan_rows(directory)[0]
    h.reject.add((first["group"], first["scenario"], 1))
    h.step(directory, first["vm"])  # Rejected over the limit 0: the pause.
    files, ignored = tree_overlay(monkeypatch, h)
    new = tmp_path / "overlay" / "stary.pyc"
    new.parent.mkdir()
    new.write_bytes(b"synthetic compiled file of the test")
    files["lab/stary.pyc"], _ = new, ignored.add("lab/stary.pyc")
    argv = ["init", "--protocol", str(protocol), "--mode", "campaign", "--archive-root", str(h.archive), "--name",
            "pokracovanie", "--archive-on-system-disk", "--archive-compression", "none", "--estimate-from",
            str(rehearsal), "--continue", str(directory), "--cause", "the gap came from the host's backup job"]
    with pytest.raises(ValueError, match="^" + re.escape(
            "new files beside the measurement code and the lab that campaign kampan froze: lab/stary.pyc; remove them "
            "and try again (a new file is no change of the frozen set and never makes a campaign invalid")), \
            contextlib.redirect_stdout(io.StringIO()):
        c.main(argv)
    assert not (h.base / "pokracovanie").exists()
    assert (c.latest_ending(directory)["ending"], c.held_ending(directory)) == ("paused", "paused")
    del files["lab/stary.pyc"]
    new.unlink()
    with contextlib.redirect_stdout(io.StringIO()):
        c.main(argv)
    h.campaigns.append(h.base / "pokracovanie")
    assert h.manifest(h.base / "pokracovanie")["continues"]["campaign"] == "kampan"


@pytest.mark.parametrize("ending", ["complete", "closed"])
def test_a_complete_or_closed_campaign_does_not_run_again(tmp_path, monkeypatch, ending):
    """ENDING_RULE (F3 of the verification of B9b, its probe test_p7_after_complete.py): HEAD has moved, as after the
    commit of the records and the ledger that FROZEN_TREE_RULE asks for after the campaign. A complete campaign (its
    record and its index) and a closed one (its record, here without closed.json: the close stopped between the two)
    are refused by name by the run of either VM, and by launch after a change of the measurement code, before
    verify_frozen (which fails the test if it is called): no record is added, no index is built again, and the
    complete record is still the one finish_corpus requires. The close printed the entry of docs/MERANIA.md of its
    record (F11)."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    if ending == "complete":
        h.run(directory)
    else:
        assert h.step(directory, "a")
        real = c.write_new

        def write_new(path, doc, **kwargs):
            if Path(path).name == "closed.json":
                raise OSError("the power failed before closed.json (the test)")
            return real(path, doc, **kwargs)
        monkeypatch.setattr(c, "write_new", write_new)
        out = io.StringIO()
        with pytest.raises(OSError, match="before closed.json"), contextlib.redirect_stdout(out):
            c.close(directory, "the owner ends the campaign")
        monkeypatch.setattr(c, "write_new", real)
        (_, record), = records(directory)
        assert not (directory / "closed.json").exists()
        sha256 = c.latest_ending(directory)["sha256"]
        printed = record["values"]["merania_entry"].replace(c.MERANIA_SHA256, f"`{sha256}`")
        assert printed in out.getvalue()
    latest, finished = c.latest_ending(directory), len(h.finished)
    before = [pointer["record"] for pointer in c.endings(directory)]
    assert latest["ending"] == ending
    monkeypatch.setattr(c, "git", lambda *args: "" if args[:1] == ("status",) else "commit-of-the-records")

    def never(*args, **kwargs):
        raise AssertionError("verify_frozen was called")
    monkeypatch.setattr(c, "verify_frozen", never)
    said = {"complete": f"campaign kampan is complete (record {latest['record']}) and its index is built: it does not "
                        "{} again (scripts/campaign.py ENDING_RULE)",
            "closed": f"campaign kampan was closed by the operator (record {latest['record']}): it does not {{}} again "
                      "(scripts/campaign.py ENDING_RULE)"}[ending]
    for vm in VMS:
        with pytest.raises(ValueError, match="^" + re.escape(said.format("run")) + "$"), \
                contextlib.redirect_stdout(io.StringIO()):
            c.execute(directory, vm=vm)
    sources = collection.measurement_sources()
    monkeypatch.setattr(collection, "measurement_sources", lambda: {**sources, "scripts/collection.py": "0" * 64})
    with pytest.raises(ValueError, match="^" + re.escape(said.format("launch")) + "$"), \
            contextlib.redirect_stdout(io.StringIO()):
        c.launch(directory)
    assert [pointer["record"] for pointer in c.endings(directory)] == before and len(h.finished) == finished
    assert not (directory / "ending.json").exists()
    if ending == "complete":
        manifest, _ = c.load_campaign(directory)
        assert c.require_complete_record(directory, manifest) == c.RESULTS / latest["record"]


@pytest.mark.parametrize("by", ["run", "launch"])
def test_an_early_stop_asks_for_a_written_cause_before_the_campaign_runs_again(tmp_path, monkeypatch, by):
    """RESUME_RULE (F6 of the verification of B9b, its probe test_p3_early_resume.py; HARNESS chapter 7): the first
    session of the plan is rejected for periodicity and replaced (limit 1), and the early stop stops the campaign. A
    plain run of either VM and a plain launch are refused by name, and so is an empty --cause. The run of that VM with
    --cause TEXT, or a launch with it (its systemd-run faked; no VM named), writes
    deviations/<UTC>_resume-after-early-stop[_<vm>].json, which answers the stopped record by name and sha256, so that
    the plain runs of both VMs go on; the campaign completes, and its complete record names the early stop (its kind,
    cause, record and sha256) and the written cause among its deviations. Package B11 (the lead's answer to Q24: every
    stop and every resume is a deviation): the stopped record's deviations are exactly its own early stop, with the
    session and the decision; the written cause states its condition, the frozen maps found unchanged and that it
    uses no continuation."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    first = h.plan_rows(directory)[0]
    key = (first["group"], first["scenario"], 1)
    h.reject.add(key)
    h.codes[key] = PERIODICITY
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(directory, vm=first["vm"]) == 0
    (ending, stopped), = records(directory)
    pointer = c.latest_ending(directory)
    assert ending == "stopped" and pointer["cause"].startswith(
        f"early stop after the audit of {first['session_id']}: a session rejected for periodicity")
    own, = stopped["values"]["deviations"]
    assert {k: own[k] for k in ("event", "vm", "session", "cause")} == {
        "event": "early_stop", "vm": first["vm"], "session": first["session_id"], "cause": pointer["cause"]}
    assert own["decision"] == {"cause": "periodicity", "type": None, "count": 3, "bound": 3, "occurrences": None,
                               "rate": None, "since": None, "sessions": 1}
    said = (f"campaign kampan stopped early ({pointer['cause']}; record {pointer['record']}): an early stop is a stop "
            "and a question (HARNESS chapter 7); {} it again with --cause TEXT, the written analysis of its cause")
    for vm in VMS:
        with pytest.raises(ValueError, match="^" + re.escape(said.format("run"))):
            c.execute(directory, vm=vm)
    with pytest.raises(ValueError, match="^" + re.escape(said.format("launch"))):
        c.launch(directory)
    with pytest.raises(ValueError, match="^" + re.escape(f"{by} --cause is empty: the written analysis of the early "
                                                         "stop is required")):
        c.execute(directory, vm=first["vm"], cause="  ") if by == "run" else c.launch(directory, cause="  ")
    assert not (directory / "deviations").exists() and len(h.of(directory)) == 1
    cause = "the periodic rows came from the backup timer of the host, now disabled (synthetic cause of the test)"
    if by == "run":
        with contextlib.redirect_stdout(io.StringIO()):
            c.execute(directory, vm=first["vm"], cause=cause)
    else:
        started = []

        def systemd_run(args, *more, **kwargs):  # The units launch would start; their runners run below.
            started.append([str(a) for a in args])
            return subprocess.CompletedProcess(args, 0)
        with pytest.MonkeyPatch.context() as mp, contextlib.redirect_stdout(io.StringIO()):
            mp.setattr(subprocess, "run", systemd_run)
            c.launch(directory, cause=cause)
        assert [(a[0], a[a.index("--vm") + 1]) for a in started] == [("systemd-run", vm) for vm in VMS]
    vm = first["vm"] if by == "run" else None
    answer, = (directory / "deviations").glob("*_resume-after-early-stop" + (f"_{vm}" if vm else "") + ".json")
    doc = read_json(answer)
    assert (doc["schema"], doc["deviation"], doc["vm"], doc["cause"]) == (
        c.DEVIATION_SCHEMA, "resume-after-early-stop", vm, cause)
    assert (doc["answers"]["record"], doc["answers"]["sha256"]) == (pointer["record"], pointer["sha256"])
    assert shlex.split(doc["command"])[1:3] == ["scripts/campaign.py", by]
    assert shlex.split(doc["command"])[-2:] == ["--cause", cause]
    assert doc["condition"] == c.RESUME_CONDITION and "no cause in the measurement code or the lab" in doc["condition"]
    assert doc["frozen"] == {"unchanged": True, "maps": ["measurement_files_sha256", "lab_sha256"],
                             "measurement_sha256": h.manifest(directory)["measurement_sha256"]}
    assert doc["continuation"].startswith("none")
    h.run(directory)  # Plain runs of both VMs: one answer serves both.
    (_, _), (last, complete) = records(directory)
    events = {x["event"]: x for x in complete["values"]["deviations"]}
    assert last == "complete"
    assert {k: events["earlier_ending"][k] for k in ("ending", "cause", "record", "sha256")} == {
        "ending": "stopped", "cause": pointer["cause"], "record": pointer["record"], "sha256": pointer["sha256"]}
    resumed = events["resume_after_early_stop"]
    assert (resumed["cause"], resumed["vm"], resumed["deviation"], resumed["answers"]["record"]) == (
        cause, vm, answer.name, pointer["record"])
    assert resumed["condition"] == c.RESUME_CONDITION and "early_stop" not in events  # Its own record holds it.


def test_an_unclean_end_is_a_deviation_of_every_later_record(tmp_path, monkeypatch):
    """ENDING_RULE (F6 of the verification of B9b, its probe test_p9_unclean.py): the runner of VM a dies during a
    capture without a trigger (SIGKILL, a power loss: its state still running, its process gone), which leaves no
    ending; its next run finds that state while the lock is free and, before it resumes, writes
    deviations/<UTC>_unclean-end_a.json with the VM, that state (its stage, session and updated_at) and the time of the
    finding. It is no ending and writes no record, and the complete record lists it among its deviations."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    assert h.step(directory, "a")
    dead = {**h.status(directory, "a"), "status": "running", "stage": "capture", "process_identity": {"alive": -1}}
    write_new(directory / "status-a.json", dead, replace=True)
    assert h.step(directory, "a")
    found, = (directory / "deviations").glob("*_unclean-end_a.json")
    doc = read_json(found)
    assert (doc["schema"], doc["deviation"], doc["vm"]) == (c.DEVIATION_SCHEMA, "unclean-end", "a")
    keys = ("status", "stage", "session", "updated_at")
    assert {k: doc["previous"][k] for k in keys} == {k: dead.get(k) for k in keys} and doc["date"] > dead["updated_at"]
    assert records(directory) == [] and c.pending_ending(directory) is None
    h.run(directory)
    (ending, complete), = records(directory)
    event, = (x for x in complete["values"]["deviations"] if x["event"] == "unclean_end")
    assert ending == "complete" and (event["vm"], event["deviation"], event["previous"]) == ("a", found.name,
                                                                                         doc["previous"])
    assert f"at the stage capture of session {dead['session']}" in event["cause"]


def test_a_captured_session_not_yet_judged_has_its_own_state(tmp_path, monkeypatch):
    """ENDING_RULE (F10 of the verification of B9b, its probe test_p11_not_run.py): SIGTERM (InterruptedError, as
    collection.Interrupts raises it) reaches the runner while its first captured session is in its audit; the stopped
    record states that session captured, not judged (its session directory without a checkpoint or a rejection
    record), with no cause and no audit, never not run; the resumed campaign judges it, and its complete record states
    it accepted."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    first = h.plan_rows(directory)[0]
    real, calls = c.audit_capture, []

    def audit(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise InterruptedError("SIGTERM during the audit of the session (the test)")
        return real(*args, **kwargs)
    monkeypatch.setattr(c, "audit_capture", audit)
    with pytest.raises(InterruptedError), contextlib.redirect_stdout(io.StringIO()):
        c.execute(directory, vm=first["vm"])
    (ending, stopped), = records(directory)
    sessions = stopped["values"]["sessions"]
    row = next(r for r in sessions if r["session"] == first["session_id"])
    assert (ending, stopped["values"]["cause"]) == ("stopped", "interrupted: SIGTERM during the audit of the session "
                                                                "(the test)")
    assert {k: row[k] for k in ("state", "cause", "captured", "audit", "replacement")} == {
        "state": "captured, not judged", "cause": None, "captured": True, "audit": None, "replacement": None}
    assert Counter(r["state"] for r in sessions) == {"captured, not judged": 1, "not run": len(sessions) - 1}
    h.run(directory)
    (_, _), (last, complete) = records(directory)
    row = next(r for r in complete["values"]["sessions"] if r["session"] == first["session_id"])
    assert (last, row["state"], row["captured"]) == ("complete", "accepted", True)


MARKER = re.compile(r"([0-9]+(?:\.[0-9]+)?) \{\{res:([^:}]+):values\.([^}]+)\}\}")


def test_the_record_of_a_closing_ending_carries_the_entry_of_the_measurement_log(tmp_path, monkeypatch):
    """ENDING_RULE (F11 of the verification of B9b, proposal 11.6): a campaign with one rejection and its replacement
    and an operator's stop runs to its complete ending. The stopped record carries no entry; the complete record, of
    an ending that closes the campaign, carries in values.merania_entry the entry of docs/MERANIA.md: the campaign and
    the ending, the record's name with its sha256 left to endings/ and the printout, the planned, accepted, rejected
    and replaced sessions, the unscored time and every deviation. Every number in it is the record's, with its marker
    of check C of scripts/check_claims.sh, which passes on the printed entry against the test's records; the run that
    wrote the record printed the entry with the record's sha256."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    first = h.plan_rows(directory)[0]
    h.reject.add((first["group"], first["scenario"], 1))
    stop_during_the_first_capture(h, monkeypatch, directory, first["vm"], "the owner needs the host for an hour")
    with contextlib.redirect_stdout(io.StringIO()):
        c.execute(directory, vm=first["vm"])
    (ending, stopped), = records(directory)
    assert ending == "stopped" and "merania_entry" not in stopped["values"]
    h.run(directory)
    (_, _), (last, complete) = records(directory)
    pointer, v = c.latest_ending(directory), complete["values"]
    name, entry = pointer["record"], v["merania_entry"]
    assert last == "complete" and v["rejections_by_cause"] == {"audit_rejected": 1} and v["replacements_used"] == 1
    assert entry.startswith(f"## {complete['date'][:10]} — kampaň kampan: ukončenie úplná\n")
    assert f"[`data/results/{name}`](../data/results/{name}), sha256 {c.MERANIA_SHA256}" in entry
    assert pointer["sha256"] not in entry
    found = {key: number for number, file, key in MARKER.findall(entry) if file == name}
    assert set(found) == {"planned_sessions", "accepted_sessions", "replacements_used", "unscored.total_s",
                          "rejections_by_cause.audit_rejected"} and len(MARKER.findall(entry)) == len(found)
    for key, number in found.items():
        value = v
        for part in key.split("."):
            value = value[part]
        decimals = len(number.split(".")[1]) if "." in number else 0
        assert round(float(value), decimals) == float(number), (key, number, value)
    assert f"zamietnutých 1 (podľa príčiny: `audit_rejected` 1 " in entry
    assert all(f"`{event['event']}`" in entry for event in v["deviations"]) and len(v["deviations"]) == 2
    printed = entry.replace(c.MERANIA_SHA256, f"`{pointer['sha256']}`")
    assert any(printed in x["out"] for x in h.printed)
    page = tmp_path / "MERANIA.md"
    page.write_text(printed)
    checked = subprocess.run(["bash", str(c.ROOT / "scripts/check_claims.sh"), str(page)], capture_output=True,
                             text=True, timeout=120, env={**os.environ, "VMIC_RESULTS_DIR": str(c.RESULTS)})
    assert checked.returncode == 0 and "ciste" in checked.stdout, checked.stdout + checked.stderr


def test_a_complete_record_whose_index_was_never_built_runs_again_to_build_it(tmp_path, monkeypatch):
    """ENDING_RULE (F3 of the verification of B9b, the fix round's interpretation): the runner that wrote the record
    of the complete ending died while it built the index (SIGKILL, a power loss: its state running at the stage index,
    no index and no copy in the archive). The campaign is not refused then: the next run of that VM records the
    unclean end, writes no second record (the complete one is there) and builds the index; once the index is built,
    the campaign is refused by name like every complete one."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    h.run(directory)
    builder, = (vm for vm in VMS if (h.status(directory, vm)["status"], h.status(directory, vm)["stage"])
                == ("complete", "complete"))
    manifest = h.manifest(directory)
    for index in (directory / "corpus.json", Path(manifest["archive_dir"]) / "corpus.json"):
        index.unlink()
    write_new(directory / c.vm_file("status.json", builder), {**h.status(directory, builder), "status": "running",
                                                               "stage": "index", "process_identity": {"alive": -1}},
              replace=True)
    before, finished = c.endings(directory), len(h.finished)
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(directory, vm=builder) == 0
    assert c.endings(directory) == before and len(h.finished) == finished + 1
    assert (directory / "corpus.json").exists() and (h.status(directory, builder)["status"],
                                                     h.status(directory, builder)["stage"]) == ("complete", "complete")
    unclean, = (directory / "deviations").glob(f"*_unclean-end_{builder}.json")
    assert read_json(unclean)["previous"]["stage"] == "index"
    with pytest.raises(ValueError, match="^campaign kampan is complete .* and its index is built: it does not run "
                                         "again"), contextlib.redirect_stdout(io.StringIO()):
        c.execute(directory, vm=builder)


def test_a_written_cause_answers_only_its_own_early_stop(tmp_path, monkeypatch):
    """RESUME_RULE (F6 of the verification of B9b): a written cause answers the record it names. The first session of
    the plan is rejected for periodicity (the early stop), answered with --cause, and its replacement is rejected for
    periodicity again (a second early stop, limit 2): the first answer does not answer the second record, so a plain
    run is refused by name again, and the second written cause lets the campaign complete; its complete record lists
    both stopped endings and both answers, each with the record it answers."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=2)
    first = h.plan_rows(directory)[0]
    for attempt in (1, 2):
        key = (first["group"], first["scenario"], attempt)
        h.reject.add(key)
        h.codes[key] = PERIODICITY
    causes = ("the first periodic rows: the backup timer of the host (synthetic cause of the test)",
              "the second periodic rows: a cron job of the guest (synthetic cause of the test)")
    with contextlib.redirect_stdout(io.StringIO()):
        c.execute(directory, vm=first["vm"])
        one = c.latest_ending(directory)
        c.execute(directory, vm=first["vm"], cause=causes[0])
    two = c.latest_ending(directory)
    assert (one["ending"], two["ending"]) == ("stopped", "stopped") and one["record"] != two["record"]
    assert two["cause"].startswith(f"early stop after the audit of {first['session_id']}-r1: a session rejected for "
                                   "periodicity")
    with pytest.raises(ValueError, match="^" + re.escape(f"campaign kampan stopped early ({two['cause']}; record "
                                                         f"{two['record']}): an early stop is a stop and a question")):
        c.execute(directory, vm=first["vm"])
    with contextlib.redirect_stdout(io.StringIO()):
        c.execute(directory, vm=first["vm"], cause=causes[1])
    h.run(directory)
    complete = records(directory)[-1][1]["values"]
    earlier = [x["record"] for x in complete["deviations"] if x["event"] == "earlier_ending"]
    answered = [(x["answers"]["record"], x["cause"]) for x in complete["deviations"]
                if x["event"] == "resume_after_early_stop"]
    assert complete["ending"] == "complete" and earlier == [one["record"], two["record"]]
    assert answered == [(one["record"], causes[0]), (two["record"], causes[1])]


# ---------------------------------------------------------------- package B11 (agent G): the lead's answer to Q24, N1

CONTINUE = ["init", "--mode", "campaign", "--name", "pokracovanie", "--archive-on-system-disk", "--archive-compression",
            "none"]  # init --continue of a paused campaign, beside its protocol, archive, rehearsal and cause.


def continue_campaign(h, protocol, directory, cause):
    """init --continue of the paused campaign `directory` (CONTINUATION_RULE), as the operator runs it; the
    continuation's directory."""
    argv = [*CONTINUE, "--protocol", str(protocol), "--archive-root", str(h.archive), "--estimate-from",
            str(h.root / "rehearsals" / "kampan-generalka"), "--continue", str(directory), "--cause", cause]
    with contextlib.redirect_stdout(io.StringIO()):
        c.main(argv)
    h.campaigns.append(h.base / "pokracovanie")
    return h.base / "pokracovanie"


def test_a_resume_after_an_early_stop_uses_no_continuation(tmp_path, monkeypatch):
    """RESUME_RULE and CONTINUATION_RULE (the lead's answer to Q24, 2026-11-24): a resume after an early stop does not
    use up the one continuation after an exhausted limit (proposal 7.5). Limit 1: the first session of the plan is
    rejected for periodicity and replaced, and the early stop stops the campaign; run --cause resumes it; the
    replacement is rejected again, which the exhausted limit refuses (the count of replacements ran on across the
    resume), so the campaign pauses. The paused record lists the early stop (an earlier ending), the resume and the
    pause; init --continue is admitted, and the continuation's records carry those deviations, each tagged with the
    paused campaign and its record."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    first = h.plan_rows(directory)[0]
    for attempt, code in ((1, PERIODICITY), (2, None)):
        key = ("kampan", first["group"], first["scenario"], attempt)
        h.reject.add(key)
        if code:
            h.codes[key] = code
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(directory, vm=first["vm"]) == 0
        stopped = c.latest_ending(directory)
        assert stopped["ending"] == "stopped" and "early stop after the audit of" in stopped["cause"]
        assert c.execute(directory, vm=first["vm"], cause="the periodic rows came from a host timer, now off "
                                                          "(synthetic cause of the test)") == 0
    (_, early), (ending, paused) = records(directory)
    assert ending == "paused" and [x["event"] for x in early["values"]["deviations"]] == ["early_stop"]
    v = paused["values"]
    assert v["limit"] == {"applied": True, "max_per_campaign": 1, "used": 1}
    assert [(r["session"], r["replacement"]) for r in v["rejected_sessions"]] == [
        (first["session_id"], first["session_id"] + "-r1"), (first["session_id"] + "-r1", None)]
    assert [x["event"] for x in v["deviations"]] == ["earlier_ending", "resume_after_early_stop", "pause"]
    assert v["deviations"][0]["record"] == stopped["record"] and v["deviations"][1]["answers"]["record"] == (
        stopped["record"])
    continuation = continue_campaign(h, h.root / "kampan-protocol.json", directory, "the second rejection came from a "
                                     "full archive disk, now emptied (synthetic cause of the test)")
    assert h.manifest(continuation)["continues"]["paused_record"]["record"] == c.latest_ending(directory)["record"]
    stop_during_the_first_capture(h, monkeypatch, continuation, first["vm"], "a test")
    with contextlib.redirect_stdout(io.StringIO()):
        c.execute(continuation, vm=first["vm"])
    (_, record), = records(continuation)
    carried = [x for x in record["values"]["deviations"] if x.get("campaign") == "kampan"]
    pointer = c.latest_ending(directory)
    assert carried == [{**x, "campaign": "kampan", "carried_from": pointer["record"]} for x in v["deviations"]]
    assert [x["event"] for x in record["values"]["deviations"] if x.get("campaign") is None] == [
        "continuation", "operator_stop"]


@pytest.mark.parametrize("by", ["run_with_cause", "plain_run", "launch"])
def test_an_early_stop_is_never_resumed_after_a_change_of_the_frozen_code(tmp_path, monkeypatch, by):
    """RESUME_RULE and INVALID_RULE (the lead's answer to Q24: a resume needs the frozen hashes unchanged): after an
    early stop the lab changes (a frozen file of lab/ with another sha256). run --cause, a plain run and a launch each
    end the campaign as invalid through the real verify_frozen: answer_early_stop compares the frozen maps first and,
    with a change, writes no resume and refuses nothing. The invalid record names the changed file, the campaign holds
    the ending invalid, and no resume-after-early-stop deviation exists."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    first = h.plan_rows(directory)[0]
    key = (first["group"], first["scenario"], 1)
    h.reject.add(key)
    h.codes[key] = PERIODICITY
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(directory, vm=first["vm"]) == 0
    assert c.early_stop_record(directory) is not None
    monkeypatch.setattr(c, "verify_frozen", REAL_VERIFY)
    lab = collection.lab_sha256()
    monkeypatch.setattr(collection, "lab_sha256", lambda: {**lab, "lab/udalosti.py": "0" * 64})
    cause = "the periodic rows came from the lab itself (synthetic cause of the test)"
    with pytest.raises(c.CampaignInvalid, match="lab/udalosti.py\\) changed during the campaign"), \
            contextlib.redirect_stdout(io.StringIO()):
        if by == "launch":
            c.launch(directory, cause=cause)
        else:
            c.execute(directory, vm=first["vm"], cause=cause if by == "run_with_cause" else None)
    assert list((directory / "deviations").glob("*resume-after-early-stop*")) == []
    (_, _), (ending, invalid) = records(directory)
    assert (ending, c.held_ending(directory)) == ("invalid", "invalid")
    said = invalid["values"]["cause"]
    assert said.startswith("launch: " if by == "launch" else "error: ") and "lab/udalosti.py" in said
    assert [x["event"] for x in invalid["values"]["deviations"]] == ["earlier_ending", "invalidation"]


def test_a_runner_held_inside_refuse_ended_captures_nothing_after_a_stopped_ending(tmp_path, monkeypatch):
    """V3 of the B11 verification (package B10, its mutant G1; the verifier's probe test_probe_n1_stopped.py): the
    test below with an ending of another kind, since a runner that read held_ending alone would stop on a pause but
    not on this. VM b's runner is held inside refuse_ended while VM a's runner is stopped by the operator's request
    during its first capture, so the campaign's stopped record is written while VM b is held. An ending of any kind
    recorded after the run's count stops the runner before its next capture (ENDING_RULE): VM b captures nothing
    after the stopped record, its state says stopped, and no second record is written. With the count taken after the
    refusals (as at 540a098) VM b captured three sessions."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=1)
    monkeypatch.setattr(collection, "Interrupts", NoSignals)
    main = threading.main_thread()
    monkeypatch.setattr(threading, "main_thread", lambda: threading.current_thread())
    at_hook, go, outcome = threading.Event(), threading.Event(), []
    real_refuse_ended = c.refuse_ended

    def refuse_ended(*args, **kwargs):
        if threading.current_thread() is not main and not at_hook.is_set():
            at_hook.set()
            assert go.wait(THREAD_S)
        return real_refuse_ended(*args, **kwargs)
    monkeypatch.setattr(c, "refuse_ended", refuse_ended)

    def run_b():
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                outcome.append(c.execute(directory, vm="b"))
        except BaseException as error:  # noqa: BLE001 - reported by the test
            outcome.append(error)
    held = threading.Thread(target=run_b, daemon=True)
    held.start()
    try:
        assert at_hook.wait(THREAD_S)
        assert h.status(directory, "b").get("status") != "running"  # Held before its state says running.
        stop_during_the_first_capture(h, monkeypatch, directory, "a", "the operator's stop of the test")
        with contextlib.redirect_stdout(io.StringIO()):
            assert c.execute(directory, vm="a") == 0
        (ending, _), = records(directory)
        assert ending == "stopped"
        captured = len(h.of(directory))
    finally:
        go.set()
        held.join(THREAD_S)
    assert not held.is_alive() and outcome == [0], outcome
    assert h.of(directory)[captured:] == [] and [ending for ending, _ in records(directory)] == ["stopped"]
    state = h.status(directory, "b")
    assert (state["status"], state["stage"]) == ("stopped", "between-sessions")


def test_a_runner_held_inside_refuse_ended_captures_nothing_after_a_pause(tmp_path, monkeypatch):
    """N1 of the confirmation of B9b (the verifier's probe sondy/potvrdenie/test_p1b_window.py): VM b's runner is held
    inside refuse_ended, after refuse_held and before its first capture, while VM a's first session is rejected over
    the limit 0 and the campaign's paused record is written. The run counts the recorded endings right after settle,
    before refuse_held, and reads held_ending before every capture, so VM b's runner stops before its first capture as
    part of the pause: nothing is captured after the paused record, VM b's state is paused with the record named, and
    no second record is written. VM b's runner may capture in this test (the harness's main thread is its thread), so
    a capture would show."""
    h = harness(tmp_path, monkeypatch)
    directory = campaign_of(h, limit=0)
    first_a = next(r for r in h.plan_rows(directory) if r["vm"] == "a")
    h.reject.add((first_a["group"], first_a["scenario"], 1))
    monkeypatch.setattr(collection, "Interrupts", NoSignals)
    main = threading.main_thread()
    monkeypatch.setattr(threading, "main_thread", lambda: threading.current_thread())
    at_hook, go, outcome = threading.Event(), threading.Event(), []
    real_refuse_ended = c.refuse_ended

    def refuse_ended(*args, **kwargs):
        if threading.current_thread() is not main and not at_hook.is_set():
            at_hook.set()
            assert go.wait(THREAD_S)
        return real_refuse_ended(*args, **kwargs)
    monkeypatch.setattr(c, "refuse_ended", refuse_ended)

    def run_b():
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                outcome.append(c.execute(directory, vm="b"))
        except BaseException as error:  # noqa: BLE001 - reported by the test
            outcome.append(error)
    held = threading.Thread(target=run_b, daemon=True)
    held.start()
    try:
        assert at_hook.wait(THREAD_S)
        assert h.status(directory, "b").get("status") != "running"  # Held before its state says running.
        h.step(directory, "a")  # VM a's first session is rejected over the limit 0: the pause, recorded at once.
        (ending, _), = records(directory)
        assert ending == "paused"
        captured = len(h.of(directory))
    finally:
        go.set()
        held.join(THREAD_S)
    assert not held.is_alive() and outcome == [0], outcome
    assert h.of(directory)[captured:] == [] and [ending for ending, _ in records(directory)] == ["paused"]
    state = h.status(directory, "b")
    assert (state["status"], state["stage"], state.get("ending_record")) == (
        "paused", "between-sessions", c.latest_ending(directory)["record"])
    assert "after this run started: this runner stopped before its next capture" in state["message"]


def test_the_count_of_the_early_stop_runs_on_across_the_continuation(tmp_path, monkeypatch):
    """EARLY_STOP_RULE (the accepted text of Q24, 's náhradami aj s pokračovaním'; package B11): the rate 0.05 per
    occurrence at an event type gives the bound 1 at one occurrence and at two. The paused campaign's first session
    holds one marked row at that type in its one occurrence (1 of 1, no stop) and is rejected over the limit 0: the
    pause. The continuation's first session holds one more (1 of 1 alone, no stop), but its count runs on from the
    paused campaign: 2 marked rows in 2 occurrences over 2 audited sessions, above the bound 1, so the continuation
    stops early, and its stopped record names the paused campaign in the cause and in the early stop's decision."""
    edit = lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update({"restart_databazy": 0.05})
    h = harness(tmp_path, monkeypatch)
    protocol = h.protocol("kampan-protocol", limit=0, edit=edit)
    directory = h.init(protocol, "campaign", "kampan", estimate_from=ended_rehearsal(h, protocol, "kampan-generalka"))
    first = h.plan_rows(directory)[0]
    h.reject.add(("kampan", first["group"], first["scenario"], 1))
    for name in ("kampan", "pokracovanie"):
        h.marked[name, first["group"], first["scenario"], 1] = {"restart_databazy": 1}
    assert h.step(directory, first["vm"])
    assert c.latest_ending(directory)["ending"] == "paused"
    continuation = continue_campaign(h, protocol, directory, "the rejection came from the host's backup job, now "
                                                             "disabled (synthetic cause of the test)")
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(continuation, vm=first["vm"]) == 0
    (ending, stopped), = records(continuation)
    sid = next(r for r in h.plan_rows(continuation) if r["vm"] == first["vm"])["session_id"]
    assert ending == "stopped" and stopped["values"]["cause"] == (
        f"early stop after the audit of {sid}: 2 marked rows at the events of type restart_databazy in its 2 "
        "occurrences over 2 audited sessions since the start of the campaign (with those of the paused campaign "
        "kampan, which this continuation continues), above the bound 1, the 99th percentile of the Poisson "
        "distribution at the rate 0.05 per occurrence of audit.early_stop.marked_rows_rate_per_type times its "
        "occurrences")
    early, = (x for x in stopped["values"]["deviations"] if x["event"] == "early_stop")
    assert {k: early["decision"][k] for k in ("count", "occurrences", "bound", "sessions", "since", "continued")} == {
        "count": 2, "occurrences": 2, "bound": 1, "sessions": 2, "since": None, "continued": "kampan"}
    assert len(h.of(continuation)) == 1  # Nothing is captured after the session that stopped it.


def test_the_count_runs_on_across_the_continuation_also_after_a_rejected_session(tmp_path, monkeypatch):
    """V4 of the B11 verification (package B10, mutant F6): EARLY_STOP_RULE asks the early stop after the audit of a
    rejected session as well, with the count of the continuation. As the test above, but the continuation's first
    session is rejected too: its one marked row is 1 of 1 alone, and with the paused campaign's 2 in 2 occurrences
    over 2 audited sessions, above the bound 1, so the early stop is decided on the path of the rejection, and its
    decision names the paused campaign. The rejection also uses up the continuation's limit 0, and a continuation is
    never continued, so its record is that of an invalid campaign, which lists the early stop among its deviations."""
    edit = lambda doc: doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update({"restart_databazy": 0.05})
    h = harness(tmp_path, monkeypatch)
    protocol = h.protocol("kampan-protocol", limit=0, edit=edit)
    directory = h.init(protocol, "campaign", "kampan", estimate_from=ended_rehearsal(h, protocol, "kampan-generalka"))
    first = h.plan_rows(directory)[0]
    for name in ("kampan", "pokracovanie"):
        h.reject.add((name, first["group"], first["scenario"], 1))
        h.marked[name, first["group"], first["scenario"], 1] = {"restart_databazy": 1}
    assert h.step(directory, first["vm"])
    assert c.latest_ending(directory)["ending"] == "paused"
    continuation = continue_campaign(h, protocol, directory, "the rejection came from the host's backup job, now "
                                                             "disabled (synthetic cause of the test)")
    with contextlib.redirect_stdout(io.StringIO()):
        assert c.execute(continuation, vm=first["vm"]) == 0
    (ending, record), = records(continuation)
    sid = next(r for r in h.plan_rows(continuation) if r["vm"] == first["vm"])["session_id"]
    assert ending == "invalid" and [x["event"] for x in record["values"]["deviations"]] == [
        "pause", "continuation", "early_stop", "invalidation"]
    early, = (x for x in record["values"]["deviations"] if x["event"] == "early_stop")
    assert early["session"] == sid and early["cause"].startswith(f"early stop after the audit of {sid}: 2 marked rows")
    assert {k: early["decision"][k] for k in ("count", "occurrences", "bound", "sessions", "since", "continued")} == {
        "count": 2, "occurrences": 2, "bound": 1, "sessions": 2, "since": None, "continued": "kampan"}


def test_a_continuation_carries_the_deviations_of_the_paused_record_or_names_it(tmp_path, monkeypatch):
    """ENDING_RULE and CONTINUATION_RULE (package B11): the deviations of the paused record a continuation continues
    are carried into its records, read after the sha256 check of the record's name and each tagged with the paused
    campaign and that record, in the time order of all deviations; a paused record that is missing, changed or holds
    no list of deviations is named as one deviation instead, and the record of the ending is written all the same."""
    monkeypatch.setattr(c, "RESULTS", tmp_path / "results")
    c.RESULTS.mkdir()
    paused = c.RESULTS / "kampan_kampan_paused_20261124T000000000000Z.json"
    deviations = [{"event": "earlier_ending", "ending": "stopped", "date": "2026-11-24T00:00:01+00:00",
                   "record": "kampan_kampan_stopped_20261124T000001000000Z.json"},
                  {"event": "pause", "date": "2026-11-24T00:00:03+00:00", "vm": "a", "cause": "a test's pause"}]
    write_new(paused, {"values": {"ending": "paused", "deviations": deviations}})
    continues = {"campaign": "kampan", "cause": "a test's cause", "paused_record": {
        "record": paused.name, "sha256": digest(paused), "date": "2026-11-24T00:00:03+00:00"}}
    campaign = {"date": "2026-11-24T00:00:05+00:00", "continues": continues, "sessions": []}
    found = c.deviation_events(tmp_path, campaign, [], {"ok": True})
    assert [(x["event"], x.get("campaign"), x.get("carried_from")) for x in found] == [
        ("earlier_ending", "kampan", paused.name), ("pause", "kampan", paused.name), ("continuation", None, None)]
    assert found[0]["record"] == deviations[0]["record"]  # The tag never hides a key of the carried deviation.
    for broken in ("changed", "no_list", "missing"):
        if broken == "changed":
            paused.write_text(paused.read_text() + " ")
        elif broken == "no_list":
            write_new(paused, {"values": {"deviations": "none"}}, replace=True)
            continues["paused_record"]["sha256"] = digest(paused)
        else:
            paused.unlink()
        unread, continuation = c.deviation_events(tmp_path, campaign, [], {"ok": True})
        assert (unread["event"], unread["campaign"], unread["record"], continuation["event"]) == (
            "paused_record_unread", "kampan", paused.name, "continuation"), broken
        assert unread["cause"].startswith("the deviations of the paused record of campaign kampan cannot be carried: ")
