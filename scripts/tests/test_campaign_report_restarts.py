"""The table of the restart loops and the periods of the guests' journals of G2 (scripts/campaign_report.py restarts,
package H1b6a) on recorded files: the 38 sessions of the deck and the two sessions of the killed service as
scripts/tests/g2_tabulky.py records them (the driver's records by skuska/g2.py Block.record, the injector's by
skuska/poruchy.py Injector.values), with the journal lines systemd writes at an occurrence of zla_konfiguracia_sluzby
and at a killed service. Nothing outside tmp_path is written.
"""
import importlib.util
import json
import re

import pytest

from scripts import campaign_report, collection, lab_trial
from scripts.tests import g2_tabulky as tab
from skuska import g2

RESTART = campaign_report.RESTART_TYPE
DECK = g2.draw_deck(tab.P)["sessions"]
OCCURRING = [s for s in DECK if any(x["type"] == RESTART for x in s["events"])]


def table(tmp_path, recorder, dirs, *extra):
    return tab.run("restarts", dirs, recorder, tmp_path / "out" / "restarty.json", "--protocol", str(tab.REAL),
                   *extra)


def start_of(deck_id):
    """The measure start of a deck session recorded by Recorder.deck() without a session before it."""
    return tab.T0 + (next(n for n, s in enumerate(DECK, 1) if s["id"] == deck_id)) * tab.SPAN


def ordinary(start):
    return tab.background(start, 600)


def recorded(tmp_path, change=None, kills=("a", "b")):
    """The deck with the lab's ordinary lines in every journal and a session of the killed service on each VM of
    `kills`."""
    rec = tab.Recorder(tmp_path)
    dirs = rec.deck(change=lambda item: {"journal": ordinary, **((change(item) if change else None) or {})})
    for vm in kills:
        d, _ = rec.kill_session(vm, f"f1{1 + 'ab'.index(vm)}")
        dirs.append(d)
    return rec, dirs


def test_every_loop_fits_and_is_bounded_and_every_period_is_named(tmp_path, capsys):
    """Every occurrence of zla_konfiguracia_sluzby (19, 9 or 10 on each VM) has its loop of 5 restarts 3.25 s apart
    that ends with the start limit, and the killed service on each VM restarts once 3.19 s after it failed: all fit
    and are bounded; the worker's rounds are periodic and covered by the register; the requests form no group: exit 0;
    the header of check E with the stage G2; the measured spacings and the register entries per VM."""
    rec, dirs = recorded(tmp_path)
    code, doc = table(tmp_path, rec, dirs)
    assert code == 0, doc["values"]["findings"] + doc["values"]["missing"]
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"]) == ("hyptcn3/g2-restarts-table/1", 21)
    v = doc["values"]
    assert (v["stage"], v["criterion"], v["result"], v["missing"], v["findings"]) == (
        "G2", "restart_loops_bounded", {"met": True, "minimums_met": True}, [], [])
    assert v["register"]["sha256"] == tab.sha(campaign_report.ROOT / "lab/periods.json")
    events = [o for o in v["occurrences"] if o["occurrence"] == "event"]
    kills = [o for o in v["occurrences"] if o["occurrence"] == "kill"]
    assert len(events) == 19 and sorted(sum(o["vm"] == vm for o in events) for vm in "ab") == [9, 10]
    for o in events:
        assert (o["ok"], o["fits"], o["bounded"], o["loops"], o["unit"]) == (True, True, True, 1, "hyptcn-lab@catalog")
        assert o["loop"]["spacings"] == [pytest.approx(tab.LOOP_SPACING, abs=1e-5)] * 4
        assert o["loop"]["delays"] == [pytest.approx(tab.LOOP_DELAY, abs=1e-5)] * 5
        assert o["loop"]["burst"] == 5 and o["loop"]["start_limit"] is not None
    assert [(o["vm"], o["unit"], o["ok"], o["loop"]["delays"], o["loop"]["spacings"]) for o in kills] == [
        ("a", "hyptcn-lab@docs", True, [pytest.approx(tab.KILL_DELAY, abs=1e-5)], []),
        ("b", "hyptcn-lab@docs", True, [pytest.approx(tab.KILL_DELAY, abs=1e-5)], [])]
    assert v["loops_elsewhere"] == []
    worker = [row for row in v["periodic"] if row["covered_by"] == "worker loop"]
    assert len(worker) == 38 and all(row["spacings"]["median"] == pytest.approx(1.0, abs=1e-5) for row in worker)
    assert all(row["covered_by"] for row in v["periodic"])
    assert {row["covered_by"] for row in v["periodic"]} == {"worker loop", "hyptcn-lab@ restart loop"}
    for vm in "ab":
        by = v["by_vm"][vm]
        assert by["unregistered"] == [] and by["kills"] == {"occurrences": 1, "counted": 1, "ok": 1}
        assert by["periods"] == lab_trial.periods_of([d for d in dirs if d.name.startswith(f"g2-{vm}-")])
        loop = next(e for e in by["periods"] if e["name"] == "hyptcn-lab@ restart loop")
        assert loop["spacings"]["median"] == pytest.approx(tab.LOOP_SPACING, abs=1e-5)
        assert by["autovacuum"]["ok"] is None and by["autovacuum"]["taken_over"]["measured"]["spacings"]["median"] \
            == 22.337974
    session = next(s for s in v["sessions"] if s["session_id"] == "g2-a-f11-1")
    assert {"session.json", "protocol.json", "record", "injector", "guest/journal_segment.json"} <= {
        f["name"] for f in session["files"]}
    assert "restart_loops_bounded: met" in capsys.readouterr().out


def custom_loops(deck_id, **options):
    """The journal of a deck session: its ordinary lines and the loops of its occurrences of zla_konfiguracia_sluzby,
    the first one with `options` of g2_tabulky.loop_lines."""
    item = next(s for s in DECK if s["id"] == deck_id)

    def journal(start):
        rows, first = ordinary(start), True
        for x in item["events"]:
            if x["type"] == RESTART:
                record = tab.record_of(x, start)
                rows += tab.loop_lines(record["host_start_unix"], record["host_stop_unix"], **(options if first else {}))
                first = False
        return rows
    return {"journal": journal, "loops": False}


@pytest.mark.parametrize("options, why", [
    ({"restarts": 6}, "not bounded: 6 restarts within 60 s, more than StartLimitBurst 5"),
    ({"limit": False}, "not bounded: no line 'Start request repeated too quickly.' of the unit after its last restart "
                       "before the stop call"),
    ({"spacing": 6.25}, "does not fit: 6.25 s outside [3, 3.5] s"),
    ({"restarts": 1}, "does not fit: nothing to measure (a single restart)"),
])
def test_a_loop_that_does_not_fit_or_is_not_bounded_is_a_finding(tmp_path, options, why):
    """Q52: a loop of 6 restarts within 60 s, one without the start limit, one 6.25 s apart, one of a single restart:
    each a finding of its occurrence by name, exit 1. Six starts of the failing service also leave 6 lines of its own
    output 3.25 s apart, a period the register does not name (PERIODS_RULE covers the lines of systemd only)."""
    target = OCCURRING[0]["id"]
    rec, dirs = recorded(tmp_path, change=lambda item: custom_loops(target, **options) if item["id"] == target else None)
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    bad = [o for o in v["occurrences"] if not o["ok"]]
    sid = f"g2-{OCCURRING[0]['vm']}-{target}-1"
    assert len(bad) == 1 and bad[0]["session"] == sid
    assert why in bad[0]["why"] and v["minimums_met"] is True
    assert v["findings"][0].startswith(f"{sid} {RESTART} #") and why in v["findings"][0]
    extra = [f"{sid} (VM {OCCURRING[0]['vm']}): a period the register does not name: python3: usage: services.py [-h] "
             "{catalog,auth,orders,docs,worker,udrzba} (6 lines, median spacing 3.25 s, cv 0.0)"]
    assert v["findings"][1:] == (extra if options.get("restarts") == 6 else [])


def test_a_crash_loop_outside_every_event_is_a_finding(tmp_path):
    """The crash loop that ended campaign v4: hyptcn-lab@worker restarting every 6.25 s outside every window of an
    event that restarts it is a loop elsewhere that neither fits nor is bounded, a finding; a loop of the database's
    lab units inside a window of restart_databazy that fits is listed only."""
    worker = next(s for s in DECK if all(x["type"] != "restart_databazy" for x in s["events"]))
    database = next(s for s in DECK if any(x["type"] == "restart_databazy" for x in s["events"]))

    def change(item):
        if item["id"] == worker["id"]:
            def crash(start):
                rows = ordinary(start)
                for k in range(8):
                    t = start + 3200 + 6.25 * k
                    rows += [(t - 3.0, "systemd[1]: hyptcn-lab@worker.service: Failed with result 'exit-code'."),
                             (t, "systemd[1]: hyptcn-lab@worker.service: Scheduled restart job, restart counter is "
                                 f"at {k + 1}.")]
                return rows
            return {"journal": crash}
        if item["id"] == database["id"]:
            x = next(x for x in database["events"] if x["type"] == "restart_databazy")

            def restart(start):
                return ordinary(start) + tab.kill_lines(tab.record_of(x, start)["host_start_unix"] + 2,
                                                        unit="hyptcn-lab@orders")
            return {"journal": restart}
        return None

    rec, dirs = recorded(tmp_path, change=change)
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    rows = {row["unit"]: row for row in v["loops_elsewhere"]}
    assert set(rows) == {"hyptcn-lab@worker", "hyptcn-lab@orders"}
    crash, by_design = rows["hyptcn-lab@worker"], rows["hyptcn-lab@orders"]
    assert (crash["finding"], crash["fits"], crash["bounded"], crash["by_design"]) == (True, False, False, None)
    assert crash["spacings"] == [pytest.approx(6.25, abs=1e-5)] * 7 and crash["burst"] == 8
    assert (by_design["finding"], by_design["fits"], by_design["bounded"], by_design["by_design"]["type"]) == (
        False, True, True, "restart_databazy")
    assert len(v["findings"]) == 1 and v["findings"][0].startswith(
        f"g2-{worker['vm']}-{worker['id']}-1 (VM {worker['vm']}): a restart loop of hyptcn-lab@worker at ")
    assert "outside every window of an event that restarts it by design" in v["findings"][0]


def test_a_period_the_register_does_not_name_is_a_finding(tmp_path):
    """Q52: a group of 12 journal lines of one form 30 s apart (cv 0) that no entry of lab/periods.json covers is a
    finding; a group of 5 spacings with a cv above 0.1 and one of 4 spacings are not periodic; the worker's error lines
    of a round in the statement timeout 4 s apart and postgres's checkpoints 300 s apart are periodic and covered."""
    target = DECK[0]["id"]

    def change(item):
        if item["id"] != target:
            return None
        return {"journal": lambda start: ordinary(start)
                + [(start + 100 + 30 * k, "cron[77]: (root) CMD (/usr/local/sbin/zaloha 1)") for k in range(12)]
                + [(start + 100 + t, "kernel: audit: type=1400 apparmor=\"DENIED\"")
                   for t in (0, 10, 30, 31, 70, 75)]
                + [(start + 500 + 20 * k, "systemd-timesyncd[60]: Timed out waiting for reply") for k in range(5)]
                + [(start + 800 + 4 * k, "python3[801]: worker dependency error: canceling statement due to statement "
                                         "timeout") for k in range(30)]
                + [(start + 50 + 300 * k, f"postgres[1234]: [{k}-1] 2027-01-15 11:00:00.000 UTC [1234] LOG:  "
                                          "checkpoint starting: time") for k in range(8)]}

    rec, dirs = recorded(tmp_path, change=change)
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    sid = f"g2-{DECK[0]['vm']}-{target}-1"
    mine = {row["form"]: row for row in v["periodic"] if row["session"] == sid}
    assert mine["worker dependency error: canceling statement due to statement timeout"]["covered_by"] == "worker loop"
    assert mine["[N-N] N-N-N N:N:N.N UTC [N] LOG:  checkpoint starting: time"]["covered_by"] == (
        "PostgreSQL checkpointer")
    assert not {row["source"] for row in mine.values()} & {"kernel", "systemd-timesyncd"}
    unnamed = [row for row in v["periodic"] if row["covered_by"] is None]
    assert [(row["source"], row["form"], row["lines"], row["spacings"]["median"], row["cv"]) for row in unnamed] == [
        ("cron", "(root) CMD (/usr/local/sbin/zaloha N)", 12, 30.0, 0.0)]
    assert v["by_vm"][DECK[0]["vm"]]["unregistered"][0]["form"] == "(root) CMD (/usr/local/sbin/zaloha N)"
    assert v["findings"] == [f"{sid} (VM {DECK[0]['vm']}): a period the register does not name: cron: (root) CMD "
                             "(/usr/local/sbin/zaloha N) (12 lines, median spacing 30.0 s, cv 0.0)"]


def test_a_missing_loop_a_missing_kill_and_a_kill_not_induced(tmp_path):
    """An occurrence of zla_konfiguracia_sluzby whose loop is not in the journal is a finding; VM b without a kill
    (its fault was not induced) misses the minimum, and the kill not induced is no finding; a killed service that
    restarts 4.0 s after it failed does not fit."""
    target = OCCURRING[0]["id"]
    rec, dirs = recorded(tmp_path, change=lambda item: {"loops": False} if item["id"] == target else None,
                         kills=("a",))
    d, _ = rec.kill_session("b", "f12", induced=False, journal=lambda kill: [])
    late, _ = rec.kill_session("a", "f21", journal=lambda kill: tab.kill_lines(kill, delay=4.0))
    code, doc = table(tmp_path, rec, [*dirs, d, late])
    assert code == 1
    v = doc["values"]
    assert v["missing"] == ["the killed service on VM b: 0 induced kill(s) in counted sessions, fewer than 1"]
    kills = {o["session"]: o for o in v["occurrences"] if o["occurrence"] == "kill"}
    assert kills["g2-b-f12-1"]["counted"] is False and kills["g2-b-f12-1"]["why"][0].startswith(
        "the fault was not induced")
    assert "does not fit: 4 s outside [3, 3.5] s" in kills["g2-a-f21-1"]["why"]
    assert len(v["findings"]) == 2
    assert v["findings"][0].startswith(f"g2-{OCCURRING[0]['vm']}-{target}-1 {RESTART} #")
    assert v["findings"][0].endswith("no restart loop of the unit in the journal in the occurrence's window")
    assert v["findings"][1].startswith("g2-a-f21-1 zabita_sluzba (VM a): does not fit: 4 s outside")


def test_a_session_the_records_leave_out_and_one_counted_false(tmp_path):
    """A session whose record names restart_loops_bounded in values.excluded is left out by name; one the load rule
    leaves uncounted is judged and counts towards no minimum: 18 occurrences counted, exit 1 by the minimum alone."""
    first, second = OCCURRING[0]["id"], OCCURRING[1]["id"]

    def change(item):
        if item["id"] == first:
            return {"excluded": {"criteria": ["restart_loops_bounded"], "rule": "a test"}}
        if item["id"] == second:
            return {"counted": False}
        return None

    rec, dirs = recorded(tmp_path, change=change)
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    status = {s["session_id"]: s["status"] for s in v["sessions"]}
    assert status[f"g2-{OCCURRING[0]['vm']}-{first}-1"] == "left_out"
    assert status[f"g2-{OCCURRING[1]['vm']}-{second}-1"] == "load"
    events = [o for o in v["occurrences"] if o["occurrence"] == "event"]
    assert len(events) == 18 and sum(o["counted"] for o in events) == 17 and all(o["ok"] for o in events)
    assert v["findings"] == [] and v["missing"][0] == (f"{RESTART}: 17 occurrence(s) of counted sessions on both VMs "
                                                       "together, fewer than 19")


def test_another_register_or_journal_is_a_data_error(tmp_path, capsys):
    """A session whose lab_sha256 names another lab/periods.json than this tree's, and one with a second journal file
    beside the one its segment binds: exit 2, nothing written."""
    rec = tab.Recorder(tmp_path)
    lab = {**collection.lab_sha256(), "lab/periods.json": "0" * 64}
    d1, _ = rec.session("a", "e01", items=DECK[0]["events"], lab=lab)
    d2, _ = rec.session("b", "e02", items=DECK[1]["events"])
    (d2 / "guest" / "stray-journal.txt.gz").write_bytes(b"")
    assert table(tmp_path, rec, [d1, d2]) == (2, None)
    err = capsys.readouterr().err
    assert "for lab/periods.json, not" in err and "not only the one its segment binds" in err


def test_the_rules_constants_are_the_labs(tmp_path):
    """FITS_S holds the register's period, START_LIMIT_* and RestartSec are lab/hyptcn-lab@.service's, the units of
    NO_EFFECT_RULE are lab/udalosti.py unit_states', and lab_trial's split of loops is StartLimitIntervalSec."""
    unit = (campaign_report.ROOT / "lab/hyptcn-lab@.service").read_text()
    setting = {k: v for k, v in re.findall(r"^(\w+)=(.*)$", unit, re.M)}
    assert (int(setting["StartLimitBurst"]), int(setting["StartLimitIntervalSec"])) == (
        campaign_report.START_LIMIT_BURST, campaign_report.START_LIMIT_INTERVAL_S) == (5, lab_trial.RESTART_WINDOW_S)
    low, high = campaign_report.FITS_S
    entry = next(e for e in json.loads((campaign_report.ROOT / "lab/periods.json").read_text())["periods"]
                 if e["name"] == "hyptcn-lab@ restart loop")
    assert low <= int(setting["RestartSec"]) <= entry["period_s"] <= high
    spec = importlib.util.spec_from_file_location("udalosti_h1b6a", campaign_report.ROOT / "lab/udalosti.py")
    udalosti = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(udalosti)
    assert campaign_report.NO_EFFECT_UNITS == (*udalosti.APPS, "nginx", udalosti.DATABASE)
    assert set(lab_trial.JOURNAL) == {"hyptcn-lab@ restart loop", "hyptcn-lab-udrzba.timer", "worker loop",
                                      lab_trial.AUTOVACUUM}
