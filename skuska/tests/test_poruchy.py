"""The faults of G2, the injector, the plan of the fault sessions and their block (skuska/poruchy.py, package H1b3).

Fakes of every lab, signal and root step: FakeHost has a fake clock, a fake process table, the sidecars of a fake
collector on its grid (late after a stop, none after a kill), labctl replies, a cgroup and a pressure child that are
all dictionaries; no test signals a process, touches a VM, runs labctl, writes a cgroup, uses the network or writes
outside tmp_path (checked after every test for data/results, data/diagnostics, data/collections and docs/MERANIA.md).
The only process a test starts is the pressure child for three rounds of 1 MiB, which ends by itself.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

import pytest

from scripts import campaign, collection, labctl, protocol_v5
from scripts.tests import audit_cases
from skuska import g2, kontroly, poruchy
from skuska.tests.test_g2 import COMMIT, CODE, FakeLab

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
P = collection.protocol(REAL)
PA = collection.for_vm(P, "a")
WATCHED = [ROOT / "data/results", ROOT / "data/diagnostics", ROOT / "data/collections"]
GRID0 = 1_800_000_000.0  # The deadline of the fake collector's first cycle.
UNIT_CGROUP = f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/app.slice/hyptcn-libvirtd.service"
QEMU = {"pid": 4242, "start_ticks": 7, "host_boot": "h"}
BLOCK_PID, RUN_PID, CAPTURE_PID, COLLECTOR_PID, TRAFFIC_PID, MONITOR_PID = 100, 200, 300, 400, 500, 600


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def listing(path):
    return sorted(str(p.relative_to(path)) for p in path.rglob("*")) if path.exists() else None


@pytest.fixture(autouse=True)
def _repository_unchanged():
    """No test leaves a file in data/results, data/diagnostics or data/collections, or changes docs/MERANIA.md."""
    before = {path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")
    yield
    assert ({path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")) == before


# ------------------------------------------------------------------ the forms and the names

def test_the_six_faults_of_proposal_10_3_with_their_forms_and_names():
    """FAULTS holds the six faults in the order of 10.3, each with its form, parameters, proof, scenario, expected
    names and origin; one scenario of rate high for all of them."""
    assert list(poruchy.FAULTS) == ["zabity_zberac", "zdrzany_procesor", "tlak_na_pamat", "restart_vm",
                                    "zastaveny_generator", "zabita_sluzba"]
    for name, fault in poruchy.FAULTS.items():
        assert set(fault) == {"fault", "form", "parameters", "proof", "scenario", "expected", "origin"}, name
        assert fault["expected"] and all(type(x) is str and x for x in fault["expected"])
        assert fault["parameters"]["at_s"] == 60 and fault["parameters"]["longest_s"] > 0
        assert fault["scenario"] == poruchy.SCENARIO == "corp_high"
    assert P["scenarios"]["corp_high"]["intensity"] == "high"
    assert poruchy.FAULTS["zabita_sluzba"]["parameters"]["unit"] == "hyptcn-lab@docs"
    assert poruchy.faults_sha256() == hashlib.sha256(json.dumps(poruchy.FAULTS, sort_keys=True,
                                                                ensure_ascii=False).encode()).hexdigest()


def test_the_audits_names_are_reasons_the_audit_self_test_proves():
    """Every expected name of the audit is a reason the real audit gives for a case of the audit self-test
    (scripts/tests/audit_cases.py, the self-test whose record the G0 record binds), exactly as written."""
    reasons = set()
    for case in audit_cases.cases(P):
        reasons |= set(audit_cases.expected(case, P))
    audit_names = [x for fault in poruchy.FAULTS.values() for x in fault["expected"] if not x.startswith("ValueError")]
    assert audit_names == ["logs: collector_exit_code", "cycle start later than the audit bound", "logs: qemu_swap",
                           "logs: traffic_realism:arrival_cv", "logs: service_restarted:hyptcn-lab@docs"]
    assert [x for x in audit_names if x not in reasons] == []


@pytest.mark.parametrize("fault, message", [("zabity_zberac", "collector failed; see capture.log"),
                                            ("restart_vm", "guest rebooted or changed during capture")])
def test_the_names_of_end_json_are_capture_sessions_errors_as_the_campaign_gives_them(tmp_path, fault, message):
    """capture_session raises the error inside its try and records it as '<type>: <message>';
    campaign.incomplete_reasons gives the error of end.json as it stands, which is the expected name."""
    source = inspect.getsource(collection.capture_session)
    assert f'raise ValueError("{message}")' in source
    assert 'status["error"] = f"{type(exc).__name__}: {exc}"' in source
    assert source.index(f'raise ValueError("{message}")') < source.index('status["error"] = ')
    (tmp_path / "end.json").write_text(json.dumps({"completed": False, "error": "ValueError: " + message}))
    assert campaign.incomplete_reasons(tmp_path) == poruchy.FAULTS[fault]["expected"][:1] == ["ValueError: " + message]


def test_the_collector_is_refused_after_the_reboot_only_when_no_cycle_failed():
    """capture_session checks the collector's exit code before it compares the guest: the order the name of the VM
    restart depends on (CHECK FOR G2: a failed cycle during the guest's reset gives the collector's name first)."""
    source = inspect.getsource(collection.capture_session)
    assert source.index('raise ValueError("collector failed; see capture.log")') < source.index(
        'raise ValueError("guest rebooted or changed during capture")')


# ------------------------------------------------------------------ the plan

def test_the_plan_every_fault_once_on_each_vm_and_a_clean_session_per_vm():
    """12 fault sessions, every fault once on each VM, and a clean session of the same shape on each VM; every session
    corp_high; the seeds are the plan's rule and no stream of the campaign's plan, the deck or the draw has them."""
    sessions = poruchy.plan(P)
    assert [s["id"] for s in sessions] == ["c01", "c02"] + [f"f{n:02d}" for n in range(1, 13)]
    assert [(s["vm"], s["fault"]) for s in sessions[:2]] == [("a", None), ("b", None)]
    faults = sessions[2:]
    assert [s["vm"] for s in faults] == ["a", "b"] * 6
    assert [s["fault"] for s in faults] == [name for name in poruchy.FAULTS for _ in "ab"]
    for vm in "ab":
        assert sorted(s["fault"] for s in faults if s["vm"] == vm) == sorted(poruchy.FAULTS)
    assert {s["scenario"] for s in sessions} == {"corp_high"}
    for s in sessions:
        assert s["seed"] == protocol_v5.seed(P["name"], "traffic", f"G2/{s['id']}", s["number"], 1)
    ours = {s["seed"] for s in sessions}
    assert len(ours) == 14
    others = ({s["seed"] for s in g2.draw_deck(P)["sessions"]}
              | {s["seed"] for s in kontroly.draw_controls(P)["sessions"]})
    for mode in protocol_v5.MODES:
        others |= {seed for s in protocol_v5.plan(P, mode)["sessions"] for seed in s["seeds"].values()}
    assert not ours & others
    assert poruchy.plan(P) == sessions


def test_the_plan_refuses_a_generator_fault_that_is_not_at_rate_high():
    doc = json.loads(REAL.read_text())
    doc["scenarios"]["corp_high"]["intensity"] = "low"
    with pytest.raises(ValueError, match="the stopped generator runs at rate high"):
        poruchy.plan(doc)


def test_the_shortest_session_each_fault_needs():
    assert {name: poruchy.minimum_cycles(P, name) for name in poruchy.FAULTS} == {
        "zabity_zberac": 84, "zdrzany_procesor": 84, "tlak_na_pamat": 204, "restart_vm": 132,
        "zastaveny_generator": 102, "zabita_sluzba": 132}
    assert max(poruchy.minimum_cycles(P, name) for name in poruchy.FAULTS) < P["pilot_cycles"] == 600


# ------------------------------------------------------------------ the fake host

COMMAND = [sys.executable, str(ROOT / "scripts/collection.py"), "--protocol", str(REAL), "run", "--role", "diagnostic",
           "--vm", "a", "--group", "g2-a-x-1", "--session-id", "g2-a-f01-1"]


def argv(*words):
    return [w.encode() for w in words]


def tree(command=COMMAND):
    """The process table of a session of VM a: the block, its run, lab_capture.sh with vmicollect, the generator and
    the monitor; another VM's collector and generator; nothing else of VM a."""
    return {
        BLOCK_PID: {"ppid": 1, "state": "S", "argv": argv(sys.executable, "-m", "skuska.poruchy", "block")},
        RUN_PID: {"ppid": BLOCK_PID, "state": "S", "argv": argv(*command)},
        CAPTURE_PID: {"ppid": RUN_PID, "state": "S", "argv": argv("bash", "scripts/lab_capture.sh", "600")},
        COLLECTOR_PID: {"ppid": CAPTURE_PID, "state": "S", "argv": argv(
            "vmicollect/build/vmicollect", "run", "-o", "vm.domain=hyptcn-lab-a", "-o", "vm.backend=ebpf")},
        TRAFFIC_PID: {"ppid": RUN_PID, "state": "S", "argv": argv(
            sys.executable, str(ROOT / "scripts/host_traffic.py"), "--profile", "corp", "--target",
            "http://127.0.0.1:18080")},
        MONITOR_PID: {"ppid": RUN_PID, "state": "S", "argv": argv(sys.executable, "scripts/host_monitor.py", "run")},
        900: {"ppid": 901, "state": "S", "argv": argv("vmicollect/build/vmicollect", "run", "-o",
                                                      "vm.domain=hyptcn-lab-b")},
        910: {"ppid": 901, "state": "S", "argv": argv(sys.executable, "scripts/host_traffic.py", "--target",
                                                      "http://127.0.0.1:18081")}}


class FakeChild:
    def __init__(self, pid):
        self.pid, self.running = pid, True


class FakeHost:
    """The injector's host without a process, a signal, a VM or a cgroup (the methods of poruchy.Host)."""

    def __init__(self, table=None, *, cycles=600, start=GRID0 - 10, swap_rate_kb=600):
        self.t, self.table_rows, self.cycles = start, table if table is not None else tree(), cycles
        self.stops, self.killed, self.signals, self.calls = [], None, [], []
        self.unit = {"NRestarts": 0, "ExecMainPID": 512}
        self.reboot = {"rc": 0, "stdout": '{"libvirtd": {}}\n{"previous_boot": "boot-1", "boot_id": "boot-2"}\n'}
        self.qemu_now, self.cgroups = dict(QEMU), {QEMU["pid"]: UNIT_CGROUP}
        self.swap_max_of, self.swap, self.swap_rate_kb = {UNIT_CGROUP: "0"}, {QEMU["pid"]: 0, 5151: 0}, swap_rate_kb
        self.others = [{"vm": "b", "domain": "hyptcn-lab-b", "qemu": {"pid": 5151}, "collectors": [], "generators": []}]
        self.children, self.restore_fails, self.gate = [], False, None

    def now(self):
        return self.t

    def wait(self, event, seconds):
        if self.gate is not None:
            self.gate.wait(20)  # A block test opens it once its fake run has started.
        if event.is_set():
            return True
        self.t += seconds
        if any(child.running for child in self.children) and self.swap_max_of[UNIT_CGROUP] == "max":
            self.swap[QEMU["pid"]] += self.swap_rate_kb
        return event.is_set()

    def table(self):
        return {pid: dict(row) for pid, row in self.table_rows.items()}

    def argv(self, pid):
        row = self.table_rows.get(pid)
        return None if row is None else list(row["argv"])

    def state(self, pid):
        row = self.table_rows.get(pid)
        return None if row is None else row["state"]

    def collectors(self, domain):
        return [pid for pid, row in self.table_rows.items() if collection.is_collector(row["argv"], domain)]

    def generators(self, target):
        return [pid for pid, row in self.table_rows.items() if collection.is_generator(row["argv"])
                and collection.option(row["argv"], b"--target") == target.encode()]

    def signal(self, pid, number):
        self.signals.append((round(self.t, 3), pid, signal.Signals(number).name))
        if pid not in self.table_rows:
            raise ProcessLookupError(pid)
        if number == signal.SIGKILL:
            del self.table_rows[pid]
            if pid == COLLECTOR_PID:
                self.killed = self.t
        elif number == signal.SIGSTOP:
            self.table_rows[pid]["state"] = "T"
            if pid == COLLECTOR_PID:
                self.stops.append([self.t, None])
        elif number == signal.SIGCONT:
            self.table_rows[pid]["state"] = "S"
            if pid == COLLECTOR_PID and self.stops and self.stops[-1][1] is None:
                self.stops[-1][1] = self.t

    def start_of(self, k):
        start = GRID0 + 5 * k
        for a, b in self.stops:
            if a <= start and (b is None or start < b):
                start = b if b is not None else float("inf")
        return start

    def sidecars(self, raw, seen):
        out = {}
        for k in range(self.cycles):
            start = self.start_of(k)
            if start + 0.3 > self.t:
                break
            if self.killed is not None and start >= self.killed:
                break
            name = f"hyptcn-lab-a_{k:06d}.json"
            if name not in seen:
                seen.add(name)
                out[k] = {"file": name, "seq": k, "timestamp_unix": start,
                          "lateness_s": round(start - GRID0 - 5 * k, 6), "full": k % 360 == 0}
        return out

    def labctl(self, p, arguments, timeout):
        command = [sys.executable, ROOT / "scripts/labctl.py", *collection.labctl_args(p), *arguments]
        self.calls.append(([str(x) for x in arguments], timeout, round(self.t, 3)))
        if arguments[0] == "reboot":
            self.t += 40
            return {"command": command, "stderr": "", **self.reboot}
        guest = arguments[arguments.index("--guest-command") + 1]
        if guest.startswith("systemctl kill"):
            self.unit = {"NRestarts": self.unit["NRestarts"] + 1, "ExecMainPID": self.unit["ExecMainPID"] + 100}
            return {"command": command, "rc": 0, "stdout": "", "stderr": ""}
        text = (f"NRestarts={self.unit['NRestarts']}\nExecMainPID={self.unit['ExecMainPID']}\nActiveState=active\n"
                "SubState=running\n")
        return {"command": command, "rc": 0, "stdout": text, "stderr": ""}

    def qemu(self, domain):
        return dict(self.qemu_now) if self.qemu_now else None

    def swap_kb(self, pid):
        return self.swap.get(pid)

    def cgroup(self, pid):
        return self.cgroups.get(pid)

    def swap_max(self, cgroup):
        return self.swap_max_of[cgroup]

    def set_swap_max(self, cgroup, value):
        self.calls.append((["memory.swap.max", cgroup, value], None, round(self.t, 3)))
        if value == "0" and self.restore_fails:
            raise PermissionError("memory.swap.max: Permission denied")
        self.swap_max_of[cgroup] = value

    def other_vms(self, p):
        return [dict(o) for o in self.others]

    def meminfo(self):
        return {"MemTotal": 32 << 20, "MemAvailable": 20 << 20}

    def pressure(self, step_mib, step_s, mib_max):
        self.children.append(FakeChild(7777))
        self.calls.append((["pressure", step_mib, step_s, mib_max], None, round(self.t, 3)))
        return self.children[-1]

    def alive(self, child):
        return child.running

    def stop_pressure(self, child):
        child.running = False
        return -9


def session_dir(tmp_path):
    """A session directory as collection.py run leaves it while its capture runs: session.json and raw/."""
    d = tmp_path / "diag" / "a" / "g2-a-f01-1"
    (d / "raw").mkdir(parents=True)
    (d / "session.json").write_text(json.dumps({"session_id": d.name, "guest_before": {"boot_id": "boot-1"},
                                                "host_context": {"qemu": QEMU}}))
    return d


def injector(tmp_path, fault, host=None, *, cycles=600, owner=(os.getuid(), os.getgid())):
    host = host or FakeHost(cycles=cycles)
    return poruchy.Injector(fault, PA, session_dir(tmp_path), COMMAND, BLOCK_PID, cycles, host, owner=owner), host


def spec(fault="zabity_zberac", ident="f01"):
    return {"kind": poruchy.KIND_FAULT if fault else poruchy.KIND_CLEAN, "id": ident, "deck": {"id": ident},
            "session_id": f"g2-a-{ident}-1", "fault": fault}


# ------------------------------------------------------------------ the exact PID

def test_the_pid_is_the_one_collector_and_generator_of_the_sessions_own_tree(tmp_path):
    """The session's run is the one child of the block with the run's command line; the collector and the generator are
    the ones collection.collectors and generators name below it, never another VM's."""
    inj, _ = injector(tmp_path, "zabity_zberac")
    assert (inj.pick("collector"), inj.pick("generator")) == (COLLECTOR_PID, TRAFFIC_PID)
    assert inj.candidates["collector"] == {"run": RUN_PID, "named": [COLLECTOR_PID], "in_session": [COLLECTOR_PID]}
    assert poruchy.descendants(tree(), RUN_PID) == {CAPTURE_PID, COLLECTOR_PID, TRAFFIC_PID, MONITOR_PID}


@pytest.mark.parametrize("change, kind, words", [
    (lambda t: t.update({401: {"ppid": CAPTURE_PID, "state": "S", "argv": t[COLLECTOR_PID]["argv"]}}), "collector",
     r"2 collectors of the session descend from its run 200, not one: \[400, 401\]"),
    (lambda t: t.pop(COLLECTOR_PID), "collector",
     "0 collectors of the session descend from its run 200, not one: none"),
    (lambda t: t.update({950: {"ppid": 1, "state": "S", "argv": t.pop(COLLECTOR_PID)["argv"]}}), "collector",
     r"0 collectors .* not one: none \(outside the session: \[950\]\)"),
    (lambda t: t.update({501: {"ppid": RUN_PID, "state": "S", "argv": t[TRAFFIC_PID]["argv"]}}), "generator",
     r"2 generators of the session descend from its run 200, not one: \[500, 501\]"),
    (lambda t: t[RUN_PID].update(argv=argv(*COMMAND[:-1], "g2-a-f03-1")), "collector",
     "0 processes of the session's run"),
    (lambda t: t.update({201: {"ppid": BLOCK_PID, "state": "S", "argv": argv(*COMMAND)}}), "generator",
     "2 processes of the session's run"),
], ids=["two-collectors", "no-collector", "collector-outside", "two-generators", "no-run", "two-runs"])
def test_no_pid_or_two_refuse_the_fault_by_name_and_nothing_is_signalled(tmp_path, change, kind, words):
    table = tree()
    change(table)
    inj, host = injector(tmp_path, "zabity_zberac" if kind == "collector" else "zastaveny_generator",
                         FakeHost(table))
    with pytest.raises(poruchy.NotInduced, match=words):
        inj.pick(kind)
    inj.run()
    assert host.signals == [] and inj.induced is False and inj.why_not.endswith("no signal")


# ------------------------------------------------------------------ the timing

def side(seq, lateness=0.002):
    return {"seq": seq, "file": f"{seq}.json", "timestamp_unix": GRID0 + 5 * seq + lateness, "lateness_s": lateness,
            "full": seq % 360 == 0}


def test_the_deadline_from_the_newest_sidecar_no_full_snapshot_and_not_its_next_cycle():
    """The deadline of cycle k is the newest sidecar's start minus its lateness plus whole intervals; from its cycle + 2
    on, past `after`, never a full snapshot (seq % 360 = 0) or the cycle after one, never the last two cycles."""
    assert poruchy.next_deadline({0: side(0)}, GRID0 + 60, PA, 600) == (12, GRID0 + 60)
    assert poruchy.next_deadline({0: side(0), 30: side(30, 0.4)}, GRID0 + 60, PA, 600) == (32, GRID0 + 160)
    assert poruchy.next_deadline({355: side(355)}, GRID0 + 5 * 359, PA, 720) == (359, GRID0 + 5 * 359)
    assert poruchy.next_deadline({355: side(355)}, GRID0 + 5 * 360, PA, 720) == (362, GRID0 + 5 * 362)
    assert poruchy.next_deadline({590: side(590)}, GRID0 + 5 * 597, PA, 600) == (597, GRID0 + 5 * 597)
    assert poruchy.next_deadline({590: side(590)}, GRID0 + 5 * 598, PA, 600) is None
    assert poruchy.next_deadline({596: side(596)}, GRID0 + 5 * 597, PA, 600) is None


def test_the_killed_collector_at_an_idle_moment_after_the_first_sidecar(tmp_path):
    """SIGKILL of the exact PID 0.5 s before the deadline of cycle 12 (60 s after the first sidecar), the sidecar of
    cycle 11 published; the PID is gone; no sidecar after it."""
    inj, host = injector(tmp_path, "zabity_zberac")
    inj.run()
    assert host.signals == [(round(GRID0 + 59.5, 3), COLLECTOR_PID, "SIGKILL")]
    assert inj.induced is True and inj.why_not is None and inj.error is None
    assert inj.proof == {"pid": COLLECTOR_PID, "seq": 12, "deadline_unix": GRID0 + 60, "state_after": None,
                         "gone": True}
    assert [a["what"] for a in inj.actions] == ["first sidecar", "SIGKILL"]
    assert inj.first["seq"] == 0 and max(inj.sidecars) == 11 and inj.window == [GRID0 + 59.5] * 2


def test_the_delayed_processor_is_late_by_about_one_and_a_half_seconds(tmp_path):
    """SIGSTOP 0.5 s before the deadline, SIGCONT 2 s later: the cycle starts 1.5 s late, above lateness_max_s 0.5,
    and the next cycle keeps its deadline (no missed slot)."""
    inj, host = injector(tmp_path, "zdrzany_procesor")
    inj.run()
    assert host.signals == [(round(GRID0 + 59.5, 3), COLLECTOR_PID, "SIGSTOP"),
                            (round(GRID0 + 61.5, 3), COLLECTOR_PID, "SIGCONT")]
    assert inj.induced is True and inj.proof["lateness_s"] == pytest.approx(1.5)
    assert (inj.proof["state_after_stop"], inj.proof["stopped_s"], inj.proof["lateness_max_s"]) == ("T", 2.0, 0.5)
    assert host.start_of(13) == GRID0 + 65 and host.state(COLLECTOR_PID) == "S" and inj.stopped is None


def test_a_deadline_whose_previous_sidecar_is_not_published_waits_for_the_next(tmp_path):
    """The writer is behind: the sidecar of cycle 11 is not there 0.5 s before deadline 12, so the injector skips it."""
    host = FakeHost()
    real = host.sidecars

    def behind(raw, seen):
        found = real(raw, seen)
        if host.t < GRID0 + 60:
            for k in [k for k in found if k == 11]:
                seen.discard(found.pop(k)["file"])
        return found
    host.sidecars = behind
    inj, _ = injector(tmp_path, "zabity_zberac", host)
    inj.run()
    skipped = [a for a in inj.actions if a["what"] == "deadline skipped"]
    assert [(a["seq"], a["why"]) for a in skipped] == [(12, "the sidecar of cycle 11 is not published")]
    assert host.signals == [(round(GRID0 + 64.5, 3), COLLECTOR_PID, "SIGKILL")] and inj.proof["seq"] == 13


def test_no_fault_starts_that_would_end_near_the_end_of_the_measured_phase(tmp_path):
    """A session of 150 cycles (750 s): the memory fault (60 + 660 s) would end less than 300 s before its end."""
    inj, host = injector(tmp_path, "tlak_na_pamat", cycles=150)
    inj.run()
    assert inj.induced is False and "less than 300 s before the planned end" in inj.why_not
    assert host.swap_max_of[UNIT_CGROUP] == "0" and host.children == []


def test_a_session_that_ends_before_its_first_sidecar(tmp_path):
    host = FakeHost(cycles=600, start=GRID0 - 100)
    inj, _ = injector(tmp_path, "zastaveny_generator", host)
    inj.ended.set()
    inj.run()
    assert (inj.induced, inj.why_not, host.signals) == (False, "the session ended before its first sidecar", [])


# ------------------------------------------------------------------ every fault and its record

def test_the_stopped_generator_for_120_s(tmp_path):
    inj, host = injector(tmp_path, "zastaveny_generator")
    inj.run()
    assert [(round(t - GRID0, 1), pid, name) for t, pid, name in host.signals] == [
        (60.0, TRAFFIC_PID, "SIGSTOP"), (180.0, TRAFFIC_PID, "SIGCONT")]
    assert inj.induced is True
    assert inj.proof == {"pid": TRAFFIC_PID, "state_after_stop": "T", "state_after_cont": "S", "stopped_s": 120.0,
                         "stop_s": 120}


def test_the_vm_restart_by_labctl_reboot(tmp_path):
    inj, host = injector(tmp_path, "restart_vm")
    inj.run()
    assert host.calls == [(["reboot"], 300, round(GRID0 + 60, 3))] and host.signals == []
    assert inj.induced is True
    assert {k: inj.proof[k] for k in ("rc", "session_boot", "previous_boot", "boot_id")} == {
        "rc": 0, "session_boot": "boot-1", "previous_boot": "boot-1", "boot_id": "boot-2"}
    assert inj.proof["command"][1:] == [str(ROOT / "scripts/labctl.py"), "--domain", "hyptcn-lab-a", "--vm", "a",
                                        "--port", "18080", "reboot"]


def test_a_reboot_that_kept_the_boot_is_not_induced(tmp_path):
    host = FakeHost()
    host.reboot = {"rc": 1, "stdout": ""}
    inj, _ = injector(tmp_path, "restart_vm", host)
    inj.run()
    assert inj.induced is False and inj.why_not == "its proof does not hold (proof)"


def test_the_killed_guest_service(tmp_path):
    """systemctl show before, the kill of the brief's form, systemctl show wait_s after: NRestarts higher, another
    ExecMainPID."""
    inj, host = injector(tmp_path, "zabita_sluzba")
    inj.run()
    guest = [call[0][-1] for call in host.calls]
    assert guest == ["systemctl show -p NRestarts -p ExecMainPID -p ActiveState -p SubState hyptcn-lab@docs",
                     "systemctl kill -s KILL hyptcn-lab@docs",
                     "systemctl show -p NRestarts -p ExecMainPID -p ActiveState -p SubState hyptcn-lab@docs"]
    assert host.calls[2][2] - host.calls[1][2] == pytest.approx(20)
    assert inj.induced is True
    assert (inj.proof["before"]["NRestarts"], inj.proof["after"]["NRestarts"]) == ("0", "1")
    assert inj.proof["after"]["ExecMainPID"] != inj.proof["before"]["ExecMainPID"]


def test_the_memory_pressure_lifts_the_ban_until_the_swap_is_seen_and_restores_it(tmp_path):
    """The other VM idle, the session's QEMU in the owner's unit with memory.swap.max 0: max, the pressure child until
    VmSwap reaches swap_kb and hold_s longer, the child killed, 0 again; the proof names the swap seen."""
    inj, host = injector(tmp_path, "tlak_na_pamat")
    inj.run()
    assert [c[0] for c in host.calls] == [["memory.swap.max", UNIT_CGROUP, "max"], ["pressure", 256, 0.5, 32768],
                                          ["memory.swap.max", UNIT_CGROUP, "0"]]
    assert host.swap_max_of[UNIT_CGROUP] == "0" and not host.children[0].running and inj.lifted is None
    assert inj.induced is True
    assert {k: inj.proof[k] for k in ("swap_max_before", "swap_max_during", "swap_max_after", "swap_kb_needed")} == {
        "swap_max_before": "0", "swap_max_during": "max", "swap_max_after": "0", "swap_kb_needed": 1024}
    assert inj.proof["swap_kb_peak"] >= 1024 and inj.proof["pressure"]["rc"] == -9
    seen = next(a for a in inj.actions if a["what"] == "swap seen")
    stopped = next(a for a in inj.actions if a["what"] == "pressure stopped")
    assert stopped["unix"] - seen["unix"] >= 10 and inj.proof["other_vms_swap_kb"]["before"] == {"b": 0}


@pytest.mark.parametrize("change, words", [
    (lambda h: h.others[0].update(collectors=[900]), "the other VM is not idle"),
    (lambda h: h.cgroups.update({QEMU["pid"]: "/user.slice/user-1000.slice/session-3.scope"}),
     "is not in the unit hyptcn-libvirtd.service"),
    (lambda h: h.swap_max_of.update({UNIT_CGROUP: "max"}), "is 'max', not 0: the ban is not in place"),
    (lambda h: h.qemu_now.update(pid=999), "no longer runs the VM"),
], ids=["other-vm-busy", "not-the-unit", "no-ban", "other-qemu"])
def test_the_memory_fault_refuses_by_name_before_it_lifts_anything(tmp_path, change, words):
    host = FakeHost()
    change(host)
    inj, _ = injector(tmp_path, "tlak_na_pamat", host)
    inj.run()
    assert inj.induced is False and words in inj.why_not and host.children == []
    assert ["memory.swap.max", UNIT_CGROUP, "max"] not in [c[0] for c in host.calls]


def test_the_memory_fault_without_swap_is_not_induced_and_restores_the_ban(tmp_path):
    """The guards absorb the pressure (no swap within max_s): not induced, the ban back, the child killed."""
    inj, host = injector(tmp_path, "tlak_na_pamat", FakeHost(swap_rate_kb=0))
    inj.run()
    assert inj.induced is False and inj.proof["seen_unix"] is None and host.swap_max_of[UNIT_CGROUP] == "0"
    assert "pressure at its limit" in [a["what"] for a in inj.actions] and not host.children[0].running


def test_the_cleanup_continues_a_stopped_process_when_the_run_ends(tmp_path):
    """The run ends during the generator's stop: the stop ends early, SIGCONT is sent, the fault is not induced."""
    inj, host = injector(tmp_path, "zastaveny_generator")
    real = host.wait

    def end_during_stop(event, seconds):
        if host.table_rows[TRAFFIC_PID]["state"] == "T" and host.t > GRID0 + 90:
            inj.ended.set()
        return real(event, seconds)
    host.wait = end_during_stop
    inj.run()
    assert [name for _, _, name in host.signals] == ["SIGSTOP", "SIGCONT"] and host.state(TRAFFIC_PID) == "S"
    assert inj.induced is False and inj.proof["stopped_s"] < 120


UNCLEAN = (f"memory.swap.max of {UNIT_CGROUP} is 'max', not '0' again (PermissionError: memory.swap.max: Permission "
           "denied)")


def test_a_ban_that_cannot_be_restored_is_named_and_left_for_the_block(tmp_path):
    host = FakeHost()
    host.restore_fails = True
    inj, _ = injector(tmp_path, "tlak_na_pamat", host)
    inj.run()
    assert inj.error.startswith("PermissionError") and inj.lifted == (UNIT_CGROUP, "0")
    assert inj.unclean == [UNCLEAN]
    host.restore_fails = False
    inj.clean()
    assert inj.lifted is None and host.swap_max_of[UNIT_CGROUP] == "0"


# ------------------------------------------------------------------ the command lines

def test_the_capture_of_a_fault_session_is_map_point_a_with_600_cycles_and_no_events(tmp_path, monkeypatch):
    """collection.py's own parser and v5_arguments take the run's command: diagnostic, corp_high, 600 cycles
    (pilot_cycles, Q57), no events, campaign id g2, the plan's seed."""
    b, _ = block(tmp_path)
    b.deck, b.deck_sha256 = g2.load_deck(b.deck_path, b.full)
    [s] = b.specs()
    group = {"name": "g2-a-x-1", "identity": {"boot_id": "boot-1"}, "qemu": QEMU}
    command = b.run_command(s, group)
    assert "--events" not in command and command[command.index("--cycles") + 1] == "600"
    seen = {}
    monkeypatch.setattr(collection, "run_session", lambda a, p: seen.update(a=a, p=p))
    assert collection.main(command[2:]) == 0
    a, p = seen["a"], seen["p"]
    assert (a.role, a.scenario, a.cycles, a.events, a.campaign_id, a.seed) == (
        "diagnostic", "corp_high", 600, None, "g2", s["seed"])
    run = collection.v5_arguments(a, p)
    assert (run["cycles"], run["events"], run["traffic"]["rate_source"]) == (600, [], "protocol")


class FakeLabctlLab:
    """scripts/labctl.py Lab for its own main(): records what main asks of it (no VM)."""
    done = []

    def __init__(self, uri, domain, vm, port):
        self.unit, self.swap_error = f"hyptcn-lab-traffic-{vm}", None
        FakeLabctlLab.done.append(("lab", domain, vm, port))

    def reboot(self):
        FakeLabctlLab.done.append(("reboot",))

    def owned(self):
        FakeLabctlLab.done.append(("owned",))

    def guest(self, command):
        FakeLabctlLab.done.append(("guest", command))
        return ""


@pytest.mark.parametrize("arguments, done", [
    (["reboot"], [("reboot",)]),
    (["exec", "--guest-command", "systemctl kill -s KILL hyptcn-lab@docs"],
     [("owned",), ("guest", "systemctl kill -s KILL hyptcn-lab@docs")]),
    (["exec", "--guest-command", poruchy.SHOW_COMMAND.format(unit="hyptcn-lab@docs")],
     [("owned",), ("guest", poruchy.SHOW_COMMAND.format(unit="hyptcn-lab@docs"))])])
def test_the_labctl_command_lines_against_labctls_own_parser(monkeypatch, arguments, done):
    """The injector's labctl calls as Host.labctl makes them (the VM's labctl options, as collection.lab_json), parsed
    and dispatched by scripts/labctl.py main with its Lab replaced."""
    calls = []

    def run(command, **kw):
        calls.append([str(x) for x in command])
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(poruchy.subprocess, "run", run)
    monkeypatch.delenv("SUDO_USER", raising=False)
    reply = poruchy.Host().labctl(PA, arguments, 60)
    [command] = calls
    assert command == [sys.executable, str(ROOT / "scripts/labctl.py"), "--domain", "hyptcn-lab-a", "--vm", "a",
                       "--port", "18080", *arguments] and reply["rc"] == 0
    FakeLabctlLab.done = []
    monkeypatch.setattr(labctl, "Lab", FakeLabctlLab)
    assert labctl.main(command[2:]) == 0
    assert FakeLabctlLab.done == [("lab", "hyptcn-lab-a", "a", 18080), *done]


def test_the_pressure_child_raises_its_oom_score_and_holds_its_memory():
    """The child for three rounds of 1 MiB up to 2 MiB (it ends by itself): its oom_score_adj is 1000; with another
    parent than its own it ends at once, before it takes anything."""
    base = [sys.executable, str(poruchy.SCRIPT), "pressure", "--step-mib", "1", "--step-s", "0.01", "--mib-max", "2",
            "--rounds", "3"]
    done = subprocess.run([*base, "--parent", str(os.getpid())], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and json.loads(done.stdout) == {"mib": 2, "oom_score_adj": "1000"}
    done = subprocess.run([*base, "--parent", "1"], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and json.loads(done.stdout)["mib"] == 0


# ------------------------------------------------------------------ the block

class FaultLab(FakeLab):
    """FakeLab whose run lasts until the injector beside it is done (its thread joined), with the session.json and
    end.json of a capture whose measured phase holds the fake collector's grid."""

    block = None

    def child(self, command, log, *, timeout, lock_fd=None):
        command = [str(x) for x in command]
        if "--session-id" not in command:
            return super().child(command, log, timeout=timeout, lock_fd=lock_fd)
        sid = command[command.index("--session-id") + 1]
        self.events.append(("run", sid, lock_fd))
        assert timeout == 120 + 600 * 5 + 300
        log.write_text("session: ...\n")
        out = Path(command[command.index("--collections-dir") + 1]) / sid
        (out / "raw").mkdir(parents=True)
        (out / "protocol.json").write_bytes(Path(command[command.index("--protocol") + 1]).read_bytes())
        (out / "session.json").write_text(json.dumps({
            "session_id": sid, "campaign_id": "g2", "commit": COMMIT, "guest_before": self.identity(),
            "host_context": {"qemu": QEMU}, "measurement_sha256": {**CODE, "lab/x.py": "3" * 64}}))
        hook = self.block.hook
        host = hook.injector.host
        host.table_rows = tree(hook.injector.command)
        host.table_rows[os.getpid()] = host.table_rows.pop(BLOCK_PID)
        for row in host.table_rows.values():
            if row["ppid"] == BLOCK_PID:
                row["ppid"] = os.getpid()
        host.gate.set()
        hook.thread.join(20)
        assert not hook.thread.is_alive()
        self.window = (GRID0 - 1, GRID0 + 3000)
        (out / "end.json").write_text(json.dumps({"measure_start_unix": GRID0 - 1, "measure_end_unix": GRID0 + 3000,
                                                  "completed": True}))
        self.sessions += 1
        return self.rc.get(sid, 0)


class GatedBlock(poruchy.FaultBlock):
    """FaultBlock with a fresh FakeHost for every session, its gate closed until the fake run starts."""

    def fault_hook(self, block, spec, paths):
        self.host = self.host_factory()
        self.host.gate = threading.Event()
        return super().fault_hook(block, spec, paths)


def block(tmp_path, *, only=("f01",), lab=None, host_factory=FakeHost, **options):
    deck = tmp_path / "balicek.json"
    if not deck.exists():
        g2.write_deck(REAL, deck, "python -m skuska.g2 deck --protocol config/collection-v5.json --out balicek.json")
    lab = lab or FaultLab(REAL)
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    b = GatedBlock(REAL, deck, "a", other_vm=options.pop("other_vm", "g2"), only=None if only is None else list(only),
                  places=places, lab=lab, host=host_factory(), command="python -m skuska.poruchy block --vm a",
                  **options)
    b.host_factory = host_factory
    lab.block = b
    return b, lab


def records(b):
    return {p.stem: json.loads(p.read_text()) for p in sorted(b.places.records.glob("g2-a-*.json"))}


def test_a_fault_block_injects_records_outside_the_session_and_starts_a_group_per_session(tmp_path):
    """Two sessions (the killed collector, then the stopped generator): a new group for each, the injector beside each
    run, its record poruchy/<session>.json with check E's header outside the session's directory, its summary in the
    session's record, the session record of kind fault."""
    b, lab = block(tmp_path, only=("f01", "f09"))
    result = b.run()
    assert result["stopped"] is None
    assert [e[1] for e in lab.events if e[0] == "start_group"] == [f"g2-a-{b.block_id}-1", f"g2-a-{b.block_id}-2"]
    for sid, fault in (("g2-a-f01-1", "zabity_zberac"), ("g2-a-f09-1", "zastaveny_generator")):
        path = tmp_path / "G2" / "poruchy" / f"{sid}.json"
        doc = json.loads(path.read_text())
        assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
        assert (doc["schema"], doc["command"]) == (poruchy.FAULT_SCHEMA, "python -m skuska.poruchy block --vm a")
        v = doc["values"]
        assert (v["fault"], v["induced"], v["g2_values"], v["expected"]) == (
            fault, True, False, poruchy.FAULTS[fault]["expected"])
        assert v["measured"]["fault_inside"] is True and v["faults_sha256"] == poruchy.faults_sha256()
        assert not path.resolve().is_relative_to((tmp_path / "diag").resolve())
        rec = records(b)[sid]["values"]
        assert rec["kind"] == poruchy.KIND_FAULT and rec["deck"]["item"]["cycles"] == 600
        [summary] = [x for x in rec["beside"] if x["hook"] == "fault"]
        assert (summary["induced"], summary["sha256"], summary["unclean"]) == (True, sha(path), [])


def test_the_done_rule_and_the_next_attempt(tmp_path):
    """A fault session is done once its fault was induced, whatever its verdict; --sessions takes the plan's sessions
    of the VM that are not done; --only of another VM's session is refused."""
    b, lab = block(tmp_path, only=("f01",))
    b.run()
    b2, _ = block(tmp_path, only=None, sessions=2)
    b2.deck, b2.deck_sha256 = g2.load_deck(b2.deck_path, b2.full)
    assert [s["session_id"] for s in b2.specs()] == ["g2-a-c01-1", "g2-a-f03-1"]
    assert [(s["kind"], s["fault"], s["events"]) for s in b2.specs()] == [("fault_clean", None, None),
                                                                          ("fault", "zdrzany_procesor", None)]
    b2.only = ["f01"]
    assert [s["session_id"] for s in b2.specs()] == ["g2-a-f01-2"]
    b2.only = ["f02"]
    with pytest.raises(g2.Refused, match="--only names plan sessions of VM a, each once; not of it: f02"):
        b2.specs()


def test_the_block_refusals_of_the_fault_plan(tmp_path):
    """The memory fault needs --other-vm idle; --cycles above pilot_cycles is refused; a session shorter than its fault
    needs is refused; fewer cycles than pilot_cycles need a clean session of that length accepted on each VM (Q57)."""
    b, lab = block(tmp_path, only=("f05",))
    with pytest.raises(g2.Refused, match=r"the memory fault lifts the swap ban .* --other-vm idle"):
        b.run()
    b, _ = block(tmp_path, only=("f01",), cycles=700)
    with pytest.raises(g2.Refused, match="at most pilot_cycles = 600 cycles"):
        b.run()
    b, _ = block(tmp_path, only=("f05",), cycles=150, other_vm="idle")
    with pytest.raises(g2.Refused, match="shorter than the faults need: tlak_na_pamat needs 204") as refused:
        b.run()
    assert "none on a, b" in str(refused.value)
    b, _ = block(tmp_path, only=("c01",), cycles=150)
    b.deck, b.deck_sha256 = g2.load_deck(b.deck_path, b.full)
    assert b.checks(b.specs()) == []  # A clean session of fewer cycles runs first.


def test_fewer_cycles_once_a_clean_session_of_that_length_passed_on_each_vm(tmp_path):
    b, _ = block(tmp_path, only=("f01",), cycles=200)
    b.deck, b.deck_sha256 = g2.load_deck(b.deck_path, b.full)
    for vm, ident in (("a", "c01"), ("b", "c02")):
        b.places.records.mkdir(parents=True, exist_ok=True)
        (b.places.records / f"g2-{vm}-{ident}-1.json").write_text(json.dumps({"values": {
            "vm": vm, "kind": poruchy.KIND_CLEAN, "done": True, "deck": {"item": {"cycles": 200}},
            "audit": {"accepted": vm == "a"}}}))
    assert any("none on b" in x for x in b.checks(b.specs()))
    (b.places.records / "g2-b-c02-2.json").write_text(json.dumps({"values": {
        "vm": "b", "kind": poruchy.KIND_CLEAN, "done": True, "deck": {"item": {"cycles": 200}},
        "audit": {"accepted": True}}}))
    assert b.checks(b.specs()) == []


def test_a_cleanup_that_fails_stops_the_block_by_name(tmp_path):
    """The memory fault whose ban cannot be restored: the session's record names it and the block stops."""
    class Restoring(FakeHost):
        def __init__(self):
            super().__init__()
            self.restore_fails = True

    class Owned(FaultLab):
        def owner(self):
            return os.getuid(), os.getgid()
    b, lab = block(tmp_path, only=("f05", "f11"), lab=Owned(REAL), host_factory=Restoring, other_vm="idle")
    result = b.run()
    assert result["stopped"] == "fault cleanup: " + UNCLEAN
    assert [s["session_id"] for s in result["sessions"]] == ["g2-a-f05-1"]
    summary = [x for x in records(b)["g2-a-f05-1"]["values"]["beside"] if x["hook"] == "fault"][0]
    assert summary["unclean"] == [UNCLEAN]


def test_the_clean_session_gets_a_record_without_a_fault(tmp_path):
    b, lab = block(tmp_path, only=("c01",))
    assert b.run()["stopped"] is None
    v = json.loads((tmp_path / "G2" / "poruchy" / "g2-a-c01-1.json").read_text())["values"]
    assert (v["fault"], v["induced"], v["actions"], v["g2_values"], v["kind"]) == (None, None, [], None, "fault_clean")
    assert records(b)["g2-a-c01-1"]["values"]["done"] is True


def test_the_dry_run_and_the_plan_command(tmp_path, capsys):
    b, lab = block(tmp_path, only=("f01", "f03"))
    plan = b.plan()
    assert plan["refusals"] == [] and [r["session_id"] for r in plan["sessions"]] == ["g2-a-f01-1", "g2-a-f03-1"]
    assert not (tmp_path / "G2").exists() and [e for e in lab.events if e[0] == "run"] == []
    assert poruchy.main(["plan", "--protocol", str(REAL)]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert len(shown["sessions"]) == 14 and shown["faults_sha256"] == poruchy.faults_sha256()
