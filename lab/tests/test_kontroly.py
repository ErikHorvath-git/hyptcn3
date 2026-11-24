"""The controls of package B8 in the guest (lab/udalosti.py; skeleton dokazy/B8/kostra/KOSTRA.md sections 1, 2 and
5 item 1; design NAVRH_B8.md sections 1.3 and 2).

Every kind on fakes of /proc, modprobe and the socket list (lab/tests/conftest.py): the control with its property and
without it, the negative without it and with it, effect.ok always by the truth and `failed` naming the condition that
does not hold. Then the further conditions once each, the start (nothing starts without the return predicate), the
stop (the effect in place, then the stop, then the cleanup), the command line, the module candidate, the lab register,
and once the real program of each kind on this host with a small dose: its own polarity's effect holds, the other's
does not. Nothing here is a measurement (HONESTY P4).
"""
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import udalosti  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RWX = "7f0000000000-7f0000001000 rwxp 00000000 00:00 0\n"
RW = "7f0000000000-7f0000001000 rw-p 00000000 00:00 0\n"
MEMFD = "/memfd:hyptcn-kontrola (deleted)"
KINDS = ("kontrola_wx_memfd", "kontrola_modul_jadra", "kontrola_pocuvajuci_soket", "kontrola_zapisovac_pamate",
         "kontrola_davka_procesov")
PROGRAM_KINDS = ("kontrola_wx_memfd", "kontrola_pocuvajuci_soket", "kontrola_zapisovac_pamate",
                 "kontrola_davka_procesov")
DOSE = {"kontrola_zapisovac_pamate": 64, "kontrola_davka_procesov": 10}
# Package B9: the levels name the modules loaded at the session's start, here the fake guest's (conftest LOADED).
LEVELS = json.dumps({"schema": "hyptcn3/guest-levels/1", "processes": 3, "meminfo_kb": {"MemAvailable": 1500000},
                     "modules": ["fuse", "virtio_net"]})
# The condition of the control's property, and the negative's conditions the property breaks.
PROPERTY = {
    "kontrola_wx_memfd": (["one process of the occurrence holds an rwx mapping and the memfd"],
                          ["no process of it holds an rwx mapping", "no process of it holds a memfd"]),
    "kontrola_modul_jadra": (["the module is loaded"], ["the module is not loaded"]),
    "kontrola_pocuvajuci_soket": (["a process of the occurrence listens on the port"], ["nothing listens on the port"]),
    "kontrola_zapisovac_pamate": (["every later round rewrote the dose"], ["no later round rewrote it"]),
    "kontrola_davka_procesov": (["it starts the dose of processes a second"],
                                ["it started no process besides the long child"]),
}


def in_place(guest, kind, polarity, present):
    """An occurrence of `kind` started as `polarity`, as its program leaves it, with the property of the control
    present or absent (the state of a control, or of its negative)."""
    now, dose = time.monotonic(), DOSE.get(kind)
    if kind == "kontrola_modul_jadra":
        guest.occurrence(kind, None, polarity, module="crc7", modules_before=2, interfaces=["enp1s0", "lo"],
                         devices=["1:3", "253:0"], dry_run={"returncode": 0, "stdout": "insmod .../crc7.ko"})
        if present:
            guest.load("crc7")
        return
    sid = {"kontrola_wx_memfd": 600, "kontrola_pocuvajuci_soket": 700, "kontrola_zapisovac_pamate": 800,
           "kontrola_davka_procesov": 900}[kind]
    guest.occurrence(kind, sid, polarity, dose)
    if kind == "kontrola_wx_memfd":
        guest.program(kind, sid, maps=RWX if present else RW, fds=[MEMFD if present else str(udalosti.NEGATIVE_FILE)])
        guest.report(kind, {"ready": True, "t": now - 30})
    elif kind == "kontrola_pocuvajuci_soket":
        guest.program(kind, sid, fds=["socket:[4242]"])
        guest.report(kind, {"ready": True, "t": now - 30})
        if present:
            guest.listen(udalosti.CONTROL_PORT, 4242)
    elif kind == "kontrola_zapisovac_pamate":
        guest.program(kind, sid, rss_kib=(64 << 10) + 9000)
        guest.report(kind, *({"round": n, "bytes": 64 << 20 if n == 1 or present else 0, "t": now - 10.5 + 5 * n}
                             for n in (1, 2, 3)))
    else:
        guest.program(kind, sid)
        for n, pid in enumerate((902, 903, 904) if present else (902,)):
            guest.process(pid, sid, [udalosti.BATCH_CHILD, "1" if present else "3600"])
        guest.report(kind, *({"started": 10 * n if present else 1, "alive": 10 if present else 1, "t": now - 3.5 + n}
                             for n in (1, 2, 3)))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("polarity,present", [("control", True), ("control", False), ("negative", False),
                                              ("negative", True)])
def test_effect_of_each_kind_holds_exactly_for_the_control_with_its_property_and_the_negative_without(
        control_guest, kind, polarity, present):
    in_place(control_guest, kind, polarity, present)
    measured = udalosti.effect(kind, polarity, DOSE.get(kind))
    holds = present is (polarity == "control")
    assert measured["ok"] is holds, measured
    control_fails, negative_fails = PROPERTY[kind]
    assert measured["evidence"]["failed"] == ([] if holds else control_fails if polarity == "control"
                                              else negative_fails)
    assert measured["predicate"] == (udalosti.PREDICATES if polarity == "control"
                                     else udalosti.NEGATIVE_PREDICATES)[kind]
    if kind == "kontrola_wx_memfd":  # The outcomes function matches the parser's rows by these PIDs (agent O).
        assert measured["evidence"]["members"] == [600, 601]


def remembered_as(**values):
    def change(guest, kind):
        path = guest.state / f"{kind}.before.json"
        path.write_text(json.dumps({**json.loads(path.read_text()), **values}))
    return change


def shift_reports(seconds):
    def change(guest, kind):
        reports = [json.loads(line) for line in (guest.state / f"{kind}.out").read_text().splitlines()]
        guest.report(kind, *({**r, "t": r["t"] - seconds} for r in reports))
    return change


def first_round_short(guest, kind):
    reports = [json.loads(line) for line in (guest.state / f"{kind}.out").read_text().splitlines()]
    guest.report(kind, {**reports[0], "bytes": 1 << 20}, *reports[1:])


def small(guest, kind):
    (guest.proc / "801" / "status").write_text("Name:\tpython3\nThreads:\t1\nVmRSS:\t    9000 kB\n")


def sysfs(path):
    return lambda guest, kind: (guest.sys / path).mkdir(parents=True)


def not_started(guest, kind):
    (guest.state / f"{kind}.before.json").unlink()


# Package B10, S8 of the B8 verification: a property that holds in part (its mutants P1, P2, P3, P5 and P6).

def _reports_of(guest, kind):
    return [json.loads(line) for line in (guest.state / f"{kind}.out").read_text().splitlines()]


def one_rewrite(guest, kind):
    """The writer's last round the other way: the control rewrites the dose in one later round only, the negative
    rewrites it in one."""
    *rounds, last = _reports_of(guest, kind)
    guest.report(kind, *rounds, {**last, "bytes": 0 if last["bytes"] else 64 << 20})


def slow_batch(guest, kind):
    """The batch starts 5 processes a second for the dose of 10, below BATCH_RATE_FLOOR 0.8 times the dose."""
    guest.report(kind, *({**r, "started": r["started"] // 2} for r in _reports_of(guest, kind)))


def another_listener(guest, kind):
    """A process outside the occurrence listens on the port, not the program's socket (inode 4242)."""
    table = guest.proc / "net" / "tcp"
    table.write_text("".join(line for line in table.read_text().splitlines(keepends=True) if " 4242 " not in line))
    guest.listen(udalosti.CONTROL_PORT, 5555)


def wx_without_memfd(guest, kind):
    """The program holds the W+X page and no memfd."""
    for fd in (guest.proc / "601" / "fd").iterdir():
        fd.unlink()


FURTHER = [  # (kind, polarity, the good state changed by, the one condition that fails)
    ("kontrola_pocuvajuci_soket", "control", remembered_as(polarity="negative"),
     ["the occurrence in place is this polarity and dose"]),
    ("kontrola_davka_procesov", "control", remembered_as(dose=50),
     ["the occurrence in place is this polarity and dose"]),
    ("kontrola_wx_memfd", "negative", lambda g, k: [g.remove(600), g.remove(601)], ["the process tree runs"]),
    ("kontrola_pocuvajuci_soket", "negative", lambda g, k: (g.state / f"{k}.out").unlink(),
     ["the program reported ready"]),
    ("kontrola_zapisovac_pamate", "control", shift_reports(60), ["its last report is fresh"]),
    ("kontrola_zapisovac_pamate", "control", first_round_short, ["its first round wrote the dose"]),
    ("kontrola_zapisovac_pamate", "negative", small, ["it holds the dose"]),
    ("kontrola_davka_procesov", "negative", lambda g, k: g.remove(902), ["a child of it runs"]),
    ("kontrola_davka_procesov", "control", lambda g, k: [g.remove(pid) for pid in (902, 903, 904)],
     ["a child of it runs"]),
    ("kontrola_davka_procesov", "negative", shift_reports(10), ["its last report is fresh"]),
    ("kontrola_modul_jadra", "negative", remembered_as(dry_run={"returncode": 1, "stdout": ""}),
     ["modprobe -n of it succeeded"]),
    ("kontrola_modul_jadra", "control", sysfs("class/net/dummy0"), ["loading it created no network interface"]),
    ("kontrola_modul_jadra", "control", sysfs("dev/char/10:200"), ["loading it created no device"]),
    ("kontrola_modul_jadra", "control", not_started, ["a candidate was chosen at the start", "the module is loaded"]),
    ("kontrola_zapisovac_pamate", "control", one_rewrite, ["every later round rewrote the dose"]),  # P1
    ("kontrola_zapisovac_pamate", "negative", one_rewrite, ["no later round rewrote it"]),  # P2
    ("kontrola_davka_procesov", "control", slow_batch, ["it starts the dose of processes a second"]),  # P3
    ("kontrola_pocuvajuci_soket", "control", another_listener, ["a process of the occurrence listens on the port"]),
    ("kontrola_wx_memfd", "control", wx_without_memfd,
     ["one process of the occurrence holds an rwx mapping and the memfd"]),  # P6; the line above P5.
]


@pytest.mark.parametrize("kind,polarity,change,failed", FURTHER,
                         ids=[f"{k}-{p}-{f[0][:28]}" for k, p, _, f in FURTHER])
def test_each_further_condition_fails_alone_and_is_named(control_guest, kind, polarity, change, failed):
    in_place(control_guest, kind, polarity, polarity == "control")
    change(control_guest, kind)
    measured = udalosti.effect(kind, polarity, DOSE.get(kind))
    assert (measured["ok"], measured["evidence"]["failed"]) == (False, failed), measured


def test_a_module_that_created_an_interface_names_it(control_guest):
    in_place(control_guest, "kontrola_modul_jadra", "control", True)
    (control_guest.sys / "class/net/dummy0").mkdir()
    assert udalosti.effect("kontrola_modul_jadra")["evidence"]["created"] == {"interfaces": ["dummy0"], "devices": []}


def printed(capsys):
    return json.loads(capsys.readouterr().out)


def start(kind, polarity, *more):
    return ["start", kind, "--polarity", polarity, *more, "--levels", LEVELS, "--tolerance", "null"]


@pytest.mark.parametrize("kind,more", [("kontrola_modul_jadra", []), ("kontrola_zapisovac_pamate", ["--dose", "16"])])
def test_nothing_starts_while_the_return_predicate_does_not_hold(control_guest, capsys, kind, more):
    control_guest.process(500, 500, ["python3", "-c", "# hyptcn-kontrola leftover"])
    udalosti.main(start(kind, "control", *more))
    record = printed(capsys)
    assert (record["ok"], record["started"], record["error"]) == (False, False, "the return predicate does not hold")
    assert record["baseline"]["ok"] is False
    assert record["baseline"]["evidence"] == ["process 500 of a control lives: python3 -c # hyptcn-kontrola leftover"]
    assert control_guest.started == [] and not [c for c in control_guest.calls if c[0] == "modprobe"]
    assert not list(control_guest.state.iterdir())  # Nothing remembered: no occurrence.


def test_start_runs_the_kinds_program_as_nobody_once_the_return_predicate_holds(control_guest, capsys):
    udalosti.main(start("kontrola_zapisovac_pamate", "negative", "--dose", "64"))
    record = printed(capsys)
    assert udalosti.missing("kontrola_zapisovac_pamate", "negative", 64) == []  # In place when start returned.
    assert (record["ok"], record["started"], record["error"], record["polarity"], record["dose"]) == (
        True, True, None, "negative", 64)
    assert record["baseline"] == {"ok": True, "exact": {"ok": True, "residues": []},
                                  "level": {"judged": False, "why": "controls.baseline null until G2"}, "evidence": []}
    assert control_guest.started == [("kontrola_zapisovac_pamate", [
        "runuser", "-u", "nobody", "--", "python3", "-c", udalosti.WRITER_PROGRAM, "negative", "64", "5", "3600"])]
    assert record["background_pid"] == udalosti._session_of("kontrola_zapisovac_pamate")
    assert (udalosti.remembered("kontrola_zapisovac_pamate", "polarity"),
            udalosti.remembered("kontrola_zapisovac_pamate", "dose")) == ("negative", 64)


@pytest.mark.parametrize("polarity,command,loaded", [("control", ("modprobe", "crc7"), True),
                                                     ("negative", ("modprobe", "-n", "-v", "crc7"), False)])
def test_the_module_kind_loads_the_first_candidate_or_only_tries_it_and_stop_removes_it(
        control_guest, capsys, polarity, command, loaded):
    udalosti.main(start("kontrola_modul_jadra", polarity))
    assert printed(capsys)["started"] is True
    assert [c for c in control_guest.calls if c[0] == "modprobe"] == [command]
    assert ("crc7" in udalosti.loaded_modules()) is loaded
    udalosti.main(["stop", "kontrola_modul_jadra", "--polarity", polarity])
    record = printed(capsys)
    assert (record["ok"], record["effect"]["ok"], record["cleanup"]) == (True, True, {"ok": True, "residues": [],
                                                                                      "evidence": []})
    assert record["effect"]["evidence"]["module"] == "crc7" and "crc7" not in udalosti.loaded_modules()
    assert (("modprobe", "-r", "crc7") in control_guest.calls) is loaded


def test_stop_measures_the_effect_in_place_then_ends_the_session_and_shows_nothing_remains(control_guest, capsys):
    udalosti.main(start("kontrola_wx_memfd", "negative"))
    sid = printed(capsys)["background_pid"]
    assert udalosti.NEGATIVE_FILE.exists()  # The negative's program holds it open.
    udalosti.main(["stop", "kontrola_wx_memfd", "--polarity", "negative"])
    record = printed(capsys)
    assert (record["ok"], record["background_pid"], record["health"]) == (True, sid, 200)
    assert record["effect"]["ok"] is True and record["effect"]["evidence"]["members"] == [sid, sid + 1]
    assert record["cleanup"] == {"ok": True, "residues": [], "evidence": []}
    assert control_guest.signals == [(sid, signal.SIGTERM)]
    assert not udalosti.NEGATIVE_FILE.exists() and not list(control_guest.state.iterdir())


def test_a_session_that_outlives_sigterm_gets_sigkill(control_guest, capsys, monkeypatch):
    monkeypatch.setattr(udalosti, "STOP_WAIT_S", .2)
    udalosti.main(start("kontrola_pocuvajuci_soket", "negative"))
    sid = printed(capsys)["background_pid"]
    control_guest.stubborn.add((sid, signal.SIGTERM))
    udalosti.main(["stop", "kontrola_pocuvajuci_soket", "--polarity", "negative"])
    assert printed(capsys)["cleanup"]["ok"] is True
    assert control_guest.signals == [(sid, signal.SIGTERM), (sid, signal.SIGKILL)]


def test_a_stop_that_cannot_remove_the_module_fails_and_its_cleanup_names_the_module(control_guest, capsys):
    udalosti.main(start("kontrola_modul_jadra", "control"))
    capsys.readouterr()
    control_guest.modprobe_fails.add("crc7")
    udalosti.main(["stop", "kontrola_modul_jadra", "--polarity", "control"])
    record = printed(capsys)
    assert record["ok"] is False and record["error"].startswith("CalledProcessError")
    assert record["effect"]["ok"] is True  # Measured before the stop.
    assert record["cleanup"] == {"ok": False, "residues": [{"residue": "module", "name": "crc7"}],
                                 "evidence": ["candidate module crc7 is loaded"]}


@pytest.mark.parametrize("kind,polarity,more,error", [
    ("kontrola_wx_memfd", "control", [], "missing: the W+X page and the memfd in one process"),
    ("kontrola_wx_memfd", "negative", [], "missing: the ready report, the open file in /tmp"),
    ("kontrola_pocuvajuci_soket", "control", [], "missing: the listening socket"),
    ("kontrola_pocuvajuci_soket", "negative", [], "missing: the ready report, the created socket"),
    ("kontrola_zapisovac_pamate", "control", ["--dose", "256"], "missing: the first write of the dose, the dose "
                                                               "resident"),
    ("kontrola_davka_procesov", "negative", ["--dose", "2"], "missing: a report of the batch, a running child"),
    ("kontrola_modul_jadra", "control", [], None),
])
def test_start_returns_only_once_the_occurrence_is_in_place(control_guest, capsys, monkeypatch, kind, polarity, more,
                                                            error):
    """The rows of an occurrence begin one collection interval after its start: a half-started one fails its start
    (the executor's precision of design B8 section 1.3). The fake program here sets up nothing, the fake modprobe
    loads nothing."""
    monkeypatch.setattr(udalosti, "START_WAIT_S", .2)
    control_guest.sets_up = control_guest.modprobe_loads = False
    udalosti.main(start(kind, polarity, *more))
    record = printed(capsys)
    assert (record["ok"], record["started"]) == (False, False)
    assert record["error"] == ("SystemExit: modprobe crc7 returned, but the module is not in /proc/modules"
                               if error is None else
                               f"SystemExit: the {polarity} of {kind} is not in place within 0.2 s, {error}")


@pytest.mark.parametrize("argv,message", [
    (["start", "kontrola_wx_memfd"], None),  # Protocol v4's pilot call: a control has a polarity now.
    (["stop", "kontrola_wx_memfd", "--polarity", "positive"], "invalid --polarity: control or negative"),
    (["stop", "kontrola_wx_memfd", "--polarity", "control", "--dose", "16"], None),
    (["stop", "kontrola_zapisovac_pamate", "--polarity", "control"], None),
    (["stop", "kontrola_zapisovac_pamate", "--polarity", "control", "--dose", "32"],
     "invalid --dose for kontrola_zapisovac_pamate: one of 16, 64, 256"),
    (["stop", "kontrola_davka_procesov", "--polarity", "control", "--dose", "2", "--levels", "{}"], None),
    (["start", "kontrola_davka_procesov", "--polarity", "control", "--dose", "2", "--levels", "{}", "--tolerance",
      "[1, 2]"], 'invalid --tolerance: null or {"processes": [low, high], "MemAvailable_kb": [low, high]}'),
])
def test_a_malformed_command_line_runs_nothing(control_guest, argv, message):
    with pytest.raises(SystemExit) as refused:
        udalosti.main(argv)
    assert str(refused.value) == (udalosti.CONTROL_USAGE if message is None else message)
    assert control_guest.calls == [] and control_guest.started == []


def test_the_module_candidate_is_the_first_present_not_loaded_and_needing_nothing(control_guest, monkeypatch):
    assert udalosti.module_candidate() == "crc7"
    monkeypatch.setattr(udalosti, "MODULE_CANDIDATES", ("vendor", "udf", "crc_itu_t", "crc8"))
    control_guest.load("crc_itu_t")
    assert udalosti.module_candidate() == "crc8"
    control_guest.load("crc8")
    with pytest.raises(SystemExit) as refused:
        udalosti.module_candidate()
    assert str(refused.value) == ("no module candidate: vendor not in the kernel's package; udf needs crc_itu_t, "
                                  "cdrom; crc_itu_t is loaded; crc8 is loaded")


def test_the_lab_registers_the_five_kinds_of_the_protocol_with_their_class():
    """Skeleton B8 section 5 item 6 and the addendum: the kinds are where protocol_v5.lab_names() reads them, and the
    protocol's lab_register check passes; the protocol's classes, doses and candidates are the lab's (the doses and
    candidates once package B8's host side has written them into the protocol)."""
    from scripts import protocol_v5
    doc = json.loads((ROOT / "config/collection-v5.json").read_text())
    kinds = doc["controls"]["kinds"]
    assert udalosti.CONTROLS == KINDS and udalosti.CLASSES == {k: v["class"] for k, v in kinds.items()}
    assert set(udalosti.DOSES) == {k for k, c in udalosti.CLASSES.items() if c == "B"}
    assert set(udalosti.PROGRAMS) == set(PROGRAM_KINDS) == set(udalosti.CONTROLS) - {"kontrola_modul_jadra"}
    assert set(udalosti.EVALUATE) == set(udalosti.PREDICATES) == set(udalosti.TYPES + udalosti.CONTROLS)
    assert set(udalosti.NEGATIVE_PREDICATES) == set(udalosti.CONTROLS)
    assert protocol_v5.lab_names()["control kind"] == set(KINDS)
    assert protocol_v5.check_lab_register(doc) == ("passed", [])
    for kind, entry in kinds.items():
        if "doses" in entry:
            assert entry["doses"] == (list(udalosti.DOSES[kind]) if kind in udalosti.DOSES else None), kind
    if "candidates" in kinds["kontrola_modul_jadra"]:
        assert kinds["kontrola_modul_jadra"]["candidates"] == list(udalosti.MODULE_CANDIDATES)


# The condition the running program breaks when its occurrence is asked about as the other polarity.
OTHER = {("kontrola_wx_memfd", "control"): "no process of it holds an rwx mapping",
         ("kontrola_wx_memfd", "negative"): "one process of the occurrence holds an rwx mapping and the memfd",
         ("kontrola_pocuvajuci_soket", "control"): "nothing listens on the port",
         ("kontrola_pocuvajuci_soket", "negative"): "a process of the occurrence listens on the port",
         ("kontrola_zapisovac_pamate", "control"): "no later round rewrote it",
         ("kontrola_zapisovac_pamate", "negative"): "every later round rewrote the dose",
         ("kontrola_davka_procesov", "control"): "it started no process besides the long child",
         ("kontrola_davka_procesov", "negative"): "it starts the dose of processes a second"}


@pytest.mark.parametrize("kind", PROGRAM_KINDS)
@pytest.mark.parametrize("polarity", ["control", "negative"])
def test_the_real_program_of_each_kind_shows_its_polarity_and_ends_with_the_stop(tmp_path, monkeypatch, kind,
                                                                                    polarity):
    """The program itself on this host's /proc, small: 16 MiB rewritten every 0.2 s, 10 processes a second living
    0.5 s, a free loopback port. Once its effect holds, start's check finds it in place. Nothing is remembered from a
    start, so the other polarity is judged by its conditions alone. halt() ends the program's own process group (its
    leader is this test's child)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    for name, value in (("STATE", tmp_path), ("NEGATIVE_FILE", tmp_path / "negativna"), ("CONTROL_PORT", port),
                        ("WRITER_PERIOD_S", .2), ("BATCH_CHILD_S", .5), ("PROC", Path("/proc"))):
        monkeypatch.setattr(udalosti, name, value)
    dose = {"kontrola_zapisovac_pamate": 16, "kontrola_davka_procesov": 10}.get(kind)
    with open(tmp_path / f"{kind}.out", "w") as out:
        program = subprocess.Popen([sys.executable, "-c", udalosti.PROGRAMS[kind],
                                    *udalosti.program_arguments(kind, polarity, dose)],
                                   start_new_session=True, stdin=subprocess.DEVNULL, stdout=out,
                                   stderr=subprocess.STDOUT)
    (tmp_path / f"{kind}.pid").write_text(str(program.pid))
    threading.Thread(target=program.wait, daemon=True).start()  # Reaps it as soon as it ends.
    other = "negative" if polarity == "control" else "control"
    try:
        deadline = time.monotonic() + 15
        while not (measured := udalosti.effect(kind, polarity, dose))["ok"] and time.monotonic() < deadline:
            if program.returncode is not None and kind == "kontrola_wx_memfd" and polarity == "control":
                pytest.skip("the host does not allow an rwx mapping: "
                            + (tmp_path / f"{kind}.out").read_text()[-200:])
            time.sleep(.1)
        assert measured["ok"], measured
        assert udalosti.missing(kind, polarity, dose) == []
        assert OTHER[kind, polarity] in udalosti.effect(kind, other, dose)["evidence"]["failed"]
    finally:
        sid = udalosti.halt(kind)
    assert sid == program.pid and udalosti.session_members(sid) == [] and program.returncode is not None
    assert not list(tmp_path.glob(f"{kind}.*")) and not udalosti.NEGATIVE_FILE.exists()
    assert udalosti.listeners(port) == []
