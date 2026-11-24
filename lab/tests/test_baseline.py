"""The return predicate of the controls (lab/guest_state.py baseline; skeleton dokazy/B8/kostra/KOSTRA.md sections 3
and 5 item 2; design NAVRH_B8.md section 1.3).

On the fake guest of lab/tests/conftest.py: a clean guest meets it; every residue (a process of a control, its memfd,
the negative's file, a candidate module, the listening port, a failed unit) and a level outside its band fail it with
the residue named; a null tolerance leaves the level part unjudged; what cannot be read is a residue, never a pass.
"""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_state  # noqa: E402
import udalosti  # noqa: E402

# The session's start as guest_state.py levels printed it: the fake guest has three processes and 1.5 GB available,
# and (package B9) the modules of the fake guest's boot (conftest LOADED).
LEVELS = {"schema": "hyptcn3/guest-levels/1", "processes": 3, "threads": 3, "meminfo_kb": {"MemAvailable": 1500000},
          "modules": ["fuse", "virtio_net"]}
TOLERANCE = {"processes": [-2, 5], "MemAvailable_kb": [-100000, 50000]}
UNJUDGED = {"judged": False, "why": "controls.baseline null until G2"}


def test_a_clean_guest_meets_it_and_the_null_tolerance_leaves_the_level_part_unjudged(control_guest):
    assert guest_state.baseline(LEVELS, None) == {"ok": True, "exact": {"ok": True, "residues": []},
                                                  "level": UNJUDGED, "evidence": []}


def test_within_its_band_the_level_part_is_judged_and_holds(control_guest):
    control_guest.process(310, 310, ["/usr/sbin/sshd"])
    control_guest.memory(1480000)
    found = guest_state.baseline(LEVELS, TOLERANCE)
    assert found["ok"] is True and found["evidence"] == []
    assert found["level"] == {"judged": True, "ok": True,
                              "processes": {"start": 3, "now": 4, "change": 1, "tolerance": [-2, 5], "ok": True},
                              "MemAvailable_kb": {"start": 1500000, "now": 1480000, "change": -20000,
                                                  "tolerance": [-100000, 50000], "ok": True}}


def leftover_file(guest):
    udalosti.NEGATIVE_FILE.write_text("")


def processes(guest):
    for pid in range(400, 410):
        guest.process(pid, pid, ["/usr/bin/sleep", "60"])


RESIDUES = [  # (what is left, set up, the evidence that names it)
    ("process", lambda g: g.process(500, 500, ["python3", "-c", "# hyptcn-kontrola kontrola_wx_memfd", "control"]),
     lambda: "process 500 of a control lives: python3 -c # hyptcn-kontrola kontrola_wx_memfd control"),
    ("memfd", lambda g: g.process(510, 510, ["/usr/bin/python3"], fds=["/memfd:hyptcn-kontrola (deleted)"]),
     lambda: "process 510 holds the memfd of a control: /memfd:hyptcn-kontrola (deleted)"),
    ("file", leftover_file, lambda: f"the file of a negative control exists: {udalosti.NEGATIVE_FILE}"),
    ("module", lambda g: g.load("ts_kmp"), lambda: "candidate module ts_kmp is loaded"),
    ("port", lambda g: g.listen(udalosti.CONTROL_PORT, 777, "tcp6"),
     lambda: f"TCP port {udalosti.CONTROL_PORT} of a control listens: 00000000000000000000000001000000:24AF"),
    ("unit", lambda g: g.failed.append("hyptcn-lab@catalog.service"),
     lambda: "unit hyptcn-lab@catalog.service is failed"),
    ("processes", processes, lambda: "level processes changed by 10 since the start, outside [-2, 5]"),
    ("MemAvailable_kb", lambda g: g.memory(1300000),
     lambda: "level MemAvailable_kb changed by -200000 since the start, outside [-100000, 50000]"),
]


@pytest.mark.parametrize("left,setup,named", RESIDUES, ids=[r[0] for r in RESIDUES])
def test_every_residue_and_a_level_outside_its_band_fail_it_naming_what_is_left(control_guest, left, setup, named):
    setup(control_guest)
    found = guest_state.baseline(LEVELS, TOLERANCE)
    assert (found["ok"], found["evidence"]) == (False, [named()])
    level = left in guest_state.LEVEL_PARTS
    assert found["exact"]["ok"] is level and found["level"]["ok"] is not level
    assert [r["residue"] for r in found["exact"]["residues"]] == ([] if level else [left])
    if level:
        assert found["level"][left]["ok"] is False


def test_a_residue_fails_it_also_while_the_tolerance_is_null(control_guest):
    control_guest.load("crc7")
    found = guest_state.baseline(LEVELS, None)
    assert (found["ok"], found["level"], found["evidence"]) == (False, UNJUDGED, ["candidate module crc7 is loaded"])


def test_what_cannot_be_read_is_a_residue(control_guest, monkeypatch):
    def missing(*args, **kw):
        raise FileNotFoundError("systemctl")
    monkeypatch.setattr(guest_state, "run", missing)
    found = guest_state.baseline(LEVELS, None)
    assert (found["ok"], found["evidence"]) == (False, ["the failed units could not be read: "
                                                        "FileNotFoundError: systemctl"])


def test_the_baseline_command_prints_it(control_guest, capsys):
    guest_state.main(["baseline", "--levels", json.dumps(LEVELS), "--tolerance", json.dumps(TOLERANCE)])
    record = json.loads(capsys.readouterr().out)
    assert record["schema"] == "hyptcn3/guest-baseline/1" and type(record["utc_unix"]) is float
    assert (record["ok"], record["exact"], record["level"]["judged"]) == (True, {"ok": True, "residues": []}, True)


@pytest.mark.parametrize("levels,tolerance,message", [
    ("{", "null", "invalid --levels or --tolerance: not JSON"),
    ("[]", "null", "invalid --levels: not the JSON object guest_state.py levels printed"),
    ("{}", '{"processes": [5, -2], "MemAvailable_kb": [0, 1]}',
     'invalid --tolerance: null or {"processes": [low, high], "MemAvailable_kb": [low, high]}'),
    ('{"processes": 3}', json.dumps(TOLERANCE),
     "invalid --levels: no processes and meminfo_kb.MemAvailable to judge the level part"),
])
def test_malformed_levels_or_tolerance_are_refused(control_guest, levels, tolerance, message):
    with pytest.raises(SystemExit) as refused:
        guest_state.main(["baseline", "--levels", levels, "--tolerance", tolerance])
    assert str(refused.value) == message
