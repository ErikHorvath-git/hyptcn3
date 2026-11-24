"""The campaign's count of the early stop (protocol v5, package B9b, the fix round of agent Z: F5 of the verification of
B9b, question Q24, accepted by the lead 2026-11-24; scripts/campaign.py EARLY_STOP_RULE). Package B11 (agent G): the
count of a continuation runs on from the paused campaign it continues (the accepted text of Q24).

After every audit of a completed capture the runner writes marked/<session id>.json, sums the files of every VM since
the count's restart point and asks features/audit_policy.py early_stop (early_stop_check, marked_totals,
early_stop_restart, early_stop_cause). The tests run these functions on a campaign directory of their own: the audits'
values are given, the records of earlier endings are written in the shape scripts/campaign.py publish_ending writes,
and campaign.RESULTS is a directory of the test. The names of the fix are imported inside the tests, so this file
collects on the code before it. Mechanics only; no number here is a measurement (HONESTY P4).
"""
from datetime import datetime, timedelta
import json
from pathlib import Path

import pytest

from scripts import campaign as camp
from scripts.collection_archive import digest, write_new

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
TYPE = "restart_databazy"
TYPES = sorted(json.loads(V5.read_text())["events"]["types"])
# Judgment of the test: a rate of marked rows per occurrence whose bound is 1 at one occurrence and 2 at two and at
# three (the 99th percentiles of Poisson(0.1), Poisson(0.2) and Poisson(0.3)).
RATE = 0.1


def protocol(**rates):
    doc = json.loads(V5.read_text())
    doc["audit"]["early_stop"]["marked_rows_rate_per_type"].update(rates)
    return doc


@pytest.fixture
def directory(tmp_path, monkeypatch):
    """A campaign directory (with events/ for its states) and RESULTS, the directory of the records of its endings."""
    folder = tmp_path / "campaigns" / "kampan"
    (folder / "events").mkdir(parents=True)
    monkeypatch.setattr(camp, "RESULTS", tmp_path / "results")
    camp.RESULTS.mkdir()
    return folder


def audit(directory, session, marked=None, occurrences=None, codes=()):
    """(the values of an audit of `session`, the path of its record): marked rows and occurrences of TYPE as given, 0
    of every other type; both maps null when marked is None (an audit that could not tell the rows by type)."""
    report = directory.parent / f"audit_{session}.json"
    report.write_text(json.dumps({"session": session}))
    counts = None if marked is None else {kind: marked if kind == TYPE else 0 for kind in TYPES}
    seen = None if marked is None else {kind: occurrences if kind == TYPE else 0 for kind in TYPES}
    return {"acceptance": {"codes": list(codes)}, "marked_rows_by_type": counts, "event_occurrences_by_type": seen}, report


def check(directory, vm, session, p, marked=None, occurrences=None, codes=(), continues=None):
    """early_stop_check after an audit of `session` (audit); continues: the record of the paused campaign a
    continuation continues (campaign.json continues), None for a campaign that continues none (package B11)."""
    values, report = audit(directory, session, marked, occurrences, codes)
    return camp.early_stop_check(directory, vm, {"session_id": session}, values, p, report, continues=continues)


def ending(directory, kind, date, *, early):
    """The record of an ending (RESULTS) and its name in endings/, as publish_ending writes them; with an early-stop
    trigger when early. Returns the record's path."""
    trigger = {"date": date, "vm": "a", "ending": kind, "cause": "a test's cause",
               "detail": {"early_stop": {"cause": "marked_rows", "type": TYPE}, "session": "s"} if early else None}
    stamp = datetime.fromisoformat(date).strftime("%Y%m%dT%H%M%S%fZ")
    record = camp.RESULTS / f"kampan_kampan_{kind}_{stamp}.json"
    record.write_text(json.dumps({"schema": "hyptcn3/campaign-ending/1", "date": date,
                                  "values": {"ending": kind, "cause": "a test's cause", "triggers": [trigger]}}))
    (directory / "endings").mkdir(exist_ok=True)
    write_new(directory / "endings" / f"{stamp}_{kind}.json", {
        "schema": camp.POINTER_SCHEMA, "ending": kind, "cause": "a test's cause", "record": record.name,
        "sha256": digest(record), "date": date, "pending": None})
    return record


def state(directory, vm):
    return json.loads((directory / f"status-{vm}.json").read_text())


def test_the_count_sums_the_files_of_both_vms_and_stops_above_its_bound(directory):
    """Q24: after every audit the count C_T and the occurrences n_T are the sums over the files of both VMs, this
    session included; at the rate 0.1 the bound is 1 at one occurrence and 2 at two and three, so C_T = b does not
    stop (1 of 1, then 2 of 2) and C_T = b + 1 does (3 of 3), with the type, the count, the bound, the occurrences, the
    rate, the sessions counted and the restart point (none: the start of the campaign)."""
    p = protocol(**{TYPE: RATE})
    assert check(directory, "a", "kampan_01_a", p, 1, 1) is None
    assert check(directory, "b", "kampan_02_b", p, 1, 1) is None
    stop = check(directory, "a", "kampan_03_a", p, 1, 1)
    assert {k: v for k, v in stop.items() if k != "rule"} == {
        "cause": "marked_rows", "type": TYPE, "count": 3, "bound": 2, "occurrences": 3, "rate": RATE, "since": None,
        "sessions": 3}
    files = {path.name: json.loads(path.read_text()) for path in sorted((directory / "marked").glob("*.json"))}
    assert {name: (doc["vm"], doc["session"]) for name, doc in files.items()} == {
        "kampan_01_a.json": ("a", "kampan_01_a"), "kampan_02_b.json": ("b", "kampan_02_b"),
        "kampan_03_a.json": ("a", "kampan_03_a")}
    doc = files["kampan_03_a.json"]
    assert (doc["schema"], doc["marked_rows_by_type"][TYPE], doc["event_occurrences_by_type"][TYPE],
            doc["audit_sha256"]) == (camp.MARKED_SCHEMA, 1, 1, digest(directory.parent / "audit_kampan_03_a.json"))
    datetime.fromisoformat(doc["audited_at"])  # A time of the check, the restart point compares with it.


def test_a_re_audit_replaces_its_own_file(directory):
    """A session audited again counts once, by its newest audit."""
    p = protocol(**{TYPE: RATE})
    assert check(directory, "a", "kampan_01_a", p, 1, 1) is None
    assert check(directory, "a", "kampan_01_a", p, 1, 1) is None  # 2 of 2 would be C = b; one file, 1 of 1.
    assert len(list((directory / "marked").glob("*.json"))) == 1
    assert check(directory, "b", "kampan_02_b", p, 2, 1)["count"] == 3  # 1 + 2 in 2 occurrences, above 2.


def test_the_count_starts_again_after_the_latest_ending_with_an_early_stop_trigger(directory):
    """Q24, accepted by the lead 2026-11-24: the count starts again after the campaign's latest recorded ending whose
    record holds an early-stop trigger (its date in endings/); an ending without one does not restart it, and the
    files of the sessions audited before the restart point no longer count."""
    p = protocol(**{TYPE: RATE})
    assert check(directory, "a", "kampan_01_a", p, 1, 1) is None
    assert check(directory, "b", "kampan_02_b", p, 1, 1) is None
    moment = datetime.fromisoformat(camp.now())
    ending(directory, "stopped", (moment + timedelta(seconds=1)).isoformat(), early=True)
    later = ending(directory, "stopped", (moment + timedelta(seconds=2)).isoformat(), early=False)
    assert camp.early_stop_restart(directory) == (moment + timedelta(seconds=1)).isoformat()
    for vm, session in (("a", "kampan_03_a"), ("b", "kampan_04_b")):  # Their files lie after it: audited_at now.
        values, report = audit(directory, session, 1, 1)
        write_new(directory / "marked" / f"{session}.json", {
            "schema": camp.MARKED_SCHEMA, "vm": vm, "session": session,
            "audited_at": (moment + timedelta(seconds=3)).isoformat(), "marked_rows_by_type": values[
                "marked_rows_by_type"], "event_occurrences_by_type": values["event_occurrences_by_type"],
            "audit": str(report), "audit_sha256": digest(report)})
    totals, counted, uncounted = camp.marked_totals(directory, p, camp.early_stop_restart(directory))
    assert (totals[TYPE], counted, uncounted) == ({"marked": 2, "occurrences": 2}, ["kampan_03_a", "kampan_04_b"], [])
    later.write_text("{}")  # A record that is not the one its name in endings/ names: no restart point to tell.
    with pytest.raises(ValueError) as error:
        check(directory, "a", "kampan_05_a", p, 0, 0)
    assert str(error.value).startswith("the early stop after the audit of kampan_05_a cannot be decided: the record "
                                       f"{later} of the ending stopped of ")


def continuation_of(directory, tmp_path):
    """A continuation's directory (with events/ for its states) and its record of the paused campaign `directory`
    (campaign.json continues: the campaign, its directory and the sha256 of its campaign.json), as take_over writes
    it."""
    write_new(directory / "campaign.json", {"schema": "hyptcn3/collection-campaign/1", "id": directory.name})
    continuation = tmp_path / "campaigns" / "pokracovanie"
    (continuation / "events").mkdir(parents=True)
    return continuation, {"campaign": directory.name, "directory": str(directory),
                          "campaign_sha256": digest(directory / "campaign.json")}


def test_a_continuation_counts_on_from_the_paused_campaign_until_its_own_early_stop(directory, tmp_path):
    """Q24, accepted by the lead 2026-11-24, whose text counts every audited session "s náhradami aj s pokračovaním"
    (package B11; before it the coordinator's word that a continuation counts only its own sessions): until its own
    first ending with an early-stop trigger, a continuation's count also holds the files of the paused campaign it
    continues, audited after that campaign's restart point. At the rate 0.1 one marked row in the paused campaign and
    one in the continuation are 2 in 2 occurrences at the bound 2, no stop, and are printed with the paused campaign
    named; a third stops (3 of 3, above 2), and the stop names the paused campaign. After the continuation's own
    early-stop ending only its files audited after it count, and the paused campaign's no longer do."""
    p = protocol(**{TYPE: RATE})
    assert check(directory, "a", "kampan_01_a", p, 1, 1) is None  # The paused campaign's audit: 1 of 1, bound 1.
    continuation, continues = continuation_of(directory, tmp_path)
    assert check(continuation, "a", "pokracovanie_01_a", p, 1, 1, continues=continues) is None  # 2 of 2, bound 2.
    shown = state(continuation, "a")
    assert shown["marked_rows_counts"][TYPE] == {"marked": 2, "occurrences": 2, "rate": RATE, "bound": 2}
    assert (shown["marked_rows_since"], shown["marked_rows_sessions"], shown["marked_rows_continued"]) == (
        None, 2, "kampan")
    assert "(with those of the paused campaign kampan)" in shown["message"]
    stop = check(continuation, "b", "pokracovanie_02_b", p, 1, 1, continues=continues)  # 3 of 3, above 2.
    assert {k: v for k, v in stop.items() if k != "rule"} == {
        "cause": "marked_rows", "type": TYPE, "count": 3, "bound": 2, "occurrences": 3, "rate": RATE, "since": None,
        "sessions": 3, "continued": "kampan"}
    assert ("over 3 audited sessions since the start of the campaign (with those of the paused campaign kampan, which "
            "this continuation continues), above the bound 2") in camp.early_stop_cause(stop)
    moment = datetime.fromisoformat(camp.now())
    ending(continuation, "stopped", (moment + timedelta(seconds=1)).isoformat(), early=True)
    values, report = audit(continuation, "pokracovanie_03_a", 1, 1)
    write_new(continuation / "marked" / "pokracovanie_03_a.json", {
        "schema": camp.MARKED_SCHEMA, "vm": "a", "session": "pokracovanie_03_a",
        "audited_at": (moment + timedelta(seconds=3)).isoformat(), "marked_rows_by_type": values[
            "marked_rows_by_type"], "event_occurrences_by_type": values["event_occurrences_by_type"],
        "audit": str(report), "audit_sha256": digest(report)})
    assert check(continuation, "a", "pokracovanie_04_a", p, 0, 0, continues=continues) is None
    shown = state(continuation, "a")
    assert shown["marked_rows_counts"][TYPE]["marked"] == shown["marked_rows_counts"][TYPE]["occurrences"] == 1
    assert (shown["marked_rows_since"], shown["marked_rows_sessions"], shown["marked_rows_continued"]) == (
        (moment + timedelta(seconds=1)).isoformat(), 1, None)


def test_a_continuation_counts_the_paused_campaign_from_its_own_restart_point(directory, tmp_path):
    """V4 of the B11 verification (package B10, mutant F3): the paused campaign's files count in a continuation only
    when audited after that campaign's own restart point (continued_count with early_stop_restart). The paused
    campaign: a session with one marked row, then an early stop (its ending with an early-stop trigger: the restart
    point; a resume after it uses no continuation, RESUME_RULE), then a session with one more audited after it. The
    continuation's first session with one more is 2 of 2 occurrences at the bound 2: no stop, and the count names the
    paused campaign's restart point; counted from that campaign's start it would be 3 of 3, above 2."""
    p = protocol(**{TYPE: RATE})
    assert check(directory, "a", "kampan_01_a", p, 1, 1) is None
    moment = datetime.fromisoformat(camp.now())
    restart = (moment + timedelta(seconds=1)).isoformat()
    ending(directory, "stopped", restart, early=True)
    values, report = audit(directory, "kampan_02_a", 1, 1)
    write_new(directory / "marked" / "kampan_02_a.json", {
        "schema": camp.MARKED_SCHEMA, "vm": "a", "session": "kampan_02_a",
        "audited_at": (moment + timedelta(seconds=2)).isoformat(), "marked_rows_by_type": values["marked_rows_by_type"],
        "event_occurrences_by_type": values["event_occurrences_by_type"], "audit": str(report),
        "audit_sha256": digest(report)})
    continuation, continues = continuation_of(directory, tmp_path)
    assert check(continuation, "a", "pokracovanie_01_a", p, 1, 1, continues=continues) is None
    shown = state(continuation, "a")
    assert shown["marked_rows_counts"][TYPE] == {"marked": 2, "occurrences": 2, "rate": RATE, "bound": 2}
    assert (shown["marked_rows_since"], shown["marked_rows_sessions"], shown["marked_rows_continued"]) == (
        restart, 2, "kampan")


@pytest.mark.parametrize("case", ["gone", "changed"])
def test_a_paused_campaign_that_cannot_be_counted_is_an_error_by_name(directory, tmp_path, case):
    """EARLY_STOP_RULE (package B11): a continuation counts on from the paused campaign only where and as the
    continuation froze it; a directory without that campaign.json, or with another sha256 of it, cannot be counted, so
    the early stop cannot be decided: an error by name, never a count of 0."""
    p = protocol(**{TYPE: RATE})
    continuation, continues = continuation_of(directory, tmp_path)
    if case == "gone":
        (directory / "campaign.json").unlink()
    else:
        (directory / "campaign.json").write_text("{}")
    with pytest.raises(ValueError) as error:
        check(continuation, "a", "pokracovanie_01_a", p, 0, 0, continues=continues)
    assert str(error.value) == (
        "the early stop after the audit of pokracovanie_01_a cannot be decided: the paused campaign kampan that this "
        f"campaign continues is not at {directory} as the continuation froze it (its campaign.json missing or with "
        "another sha256), so its count of the early stop cannot be told (scripts/campaign.py EARLY_STOP_RULE)")


def test_a_null_rate_prints_the_count_and_does_not_stop(directory):
    """Skeleton row skoré zastavenie: a null rate (the file until G3b) stops nothing, and the campaign's count C_T and
    n_T stay printed in the runner's state and message, with the bound of every type whose rate is set; the restart
    point and the sessions counted beside them."""
    p = protocol(zamok_tabulky=0.5)
    assert check(directory, "a", "kampan_01_a", p, 5, 1) is None
    shown = state(directory, "a")
    assert shown["marked_rows_counts"][TYPE] == {"marked": 5, "occurrences": 1, "rate": None, "bound": None}
    assert shown["marked_rows_counts"]["zamok_tabulky"] == {"marked": 0, "occurrences": 0, "rate": 0.5, "bound": 0}
    assert (shown["marked_rows_since"], shown["marked_rows_sessions"], shown["marked_rows_uncounted"]) == (None, 1, [])
    assert shown["stage"] == "early-stop" and f'"{TYPE}": [5, 1]' in shown["message"]
    assert "a null rate, until G3b, only prints" in shown["message"]


def test_the_cause_names_the_type_the_count_the_occurrences_the_rate_and_the_bound(directory):
    """F5: the stopped ending's cause names T, C_T, n_T, the rate and b, with the sessions counted and the restart
    point; the periodicity part is as before."""
    p = protocol(**{TYPE: RATE})
    check(directory, "a", "kampan_01_a", p, 1, 1)
    stop = check(directory, "b", "kampan_02_b", p, 2, 1)
    assert camp.early_stop_cause(stop) == (
        f"3 marked rows at the events of type {TYPE} in its 2 occurrences over 2 audited sessions since the start of "
        "the campaign, above the bound 2, the 99th percentile of the Poisson distribution at the rate 0.1 per "
        "occurrence of audit.early_stop.marked_rows_rate_per_type times its occurrences")
    one = dict(stop, occurrences=1, since="2026-11-24T05:00:00+00:00")
    assert "in its 1 occurrence over 2 audited sessions since 2026-11-24T05:00:00+00:00," in camp.early_stop_cause(one)
    assert camp.early_stop_cause({"cause": "periodicity", "count": 3, "bound": 3}) == (
        "a session rejected for periodicity: a run of 3 equal spacings of its flagged rows, the bound 3 of "
        "audit.periodicity.equal_spacings")


def test_an_early_stop_that_cannot_be_decided_is_an_error_by_name(directory):
    """EARLY_STOP_RULE: a session whose audit did not tell its marked rows by type cannot be counted; while every rate
    is null it is printed as uncounted, and once a rate is set the early stop cannot be decided, an error by name,
    never no stop; a count file that is no such count is refused by name."""
    assert check(directory, "a", "kampan_01_a", protocol(), None) is None
    assert state(directory, "a")["marked_rows_uncounted"] == ["kampan_01_a"]
    with pytest.raises(ValueError) as error:
        check(directory, "b", "kampan_02_b", protocol(**{TYPE: RATE}), 0, 0)
    assert str(error.value) == ("the early stop after the audit of kampan_02_b cannot be decided: the audits of "
                                "kampan_01_a did not tell their marked rows by event type (scripts/campaign.py "
                                "EARLY_STOP_RULE)")
    (directory / "marked" / "kampan_01_a.json").write_text(json.dumps({"schema": "another/1"}))
    with pytest.raises(ValueError) as error:
        check(directory, "b", "kampan_03_b", protocol(), 0, 0)
    assert str(error.value) == (f"the early stop after the audit of kampan_03_b cannot be decided: "
                                f"{directory / 'marked' / 'kampan_01_a.json'} is no count of the early stop "
                                f"({camp.MARKED_SCHEMA}) (scripts/campaign.py EARLY_STOP_RULE)")
