"""scripts/labctl.py in package B9 (design B9a section 1.2), on the fakes of lab/tests/test_labctl.py only.

The start of a group (proposal 5.4; skeleton B9 row "začiatok bootu"): `stop` waits until the VM is shut off and its
QEMU process has exited; `start` of the shut-off VM is way 1 (the session daemon in its unit), and the record it
prints last names the new QEMU's pid, its cgroup and the way that holds it; way 2, the scope move, is reported as
temporary (finding F4 of B5a). `reset --seed S` and `pretouch` run lab/guest_state.py through Lab.helper and print
what it prints. Nothing real is reached (test_labctl.nothing_real: no command, no signal, no socket of this host).
Names package B9 adds are read inside the tests, so this file collects on the code before B9.
"""
import json
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace

import pytest

from scripts import labctl
from lab.tests.test_labctl import (DAEMON_UNIT, MANAGER, SESSION, daemon, host, nothing_real,  # noqa: F401
                                   qemu)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_state  # noqa: E402

LARGEST = 10 ** 18 - 1  # The largest seed of guest_state.py reset --seed (18 digits).


class Domain:
    """virsh of one domain on the fake host of test_labctl: domstate answers the state; shutdown takes the guest
    down `down_after` pauses later (the state shut off first, the QEMU process gone one pause after), never when
    `down_after` is None; start runs QEMU `next_pid` in the cgroup of the session daemon that runs. The guest agent
    and the guest commands of a start answer at once."""

    def __init__(self, host, monkeypatch, state="running", pid=4242, down_after=2, next_pid=4343):
        self.host, self.state, self.pid, self.down_after, self.next_pid = host, state, pid, down_after, next_pid
        self.calls = []
        monkeypatch.setattr(labctl.Lab, "virsh", lambda lab, *args, timeout=30: self.virsh(*args))
        monkeypatch.setattr(labctl.Lab, "owned", lambda lab: None)
        monkeypatch.setattr(labctl.Lab, "wait", lambda lab: None)
        monkeypatch.setattr(labctl.Lab, "guest", lambda lab, command, timeout=120: "")
        # main() asks for the old traffic unit before a stop; it is not loaded under schema 3.
        monkeypatch.setattr(labctl.subprocess, "check_output", lambda argv, **kw: "not-found\n")

    def virsh(self, *args):
        self.calls.append(args[0])
        if args[0] == "domstate":
            return self.state
        if args[0] == "shutdown":
            self.state = "in shutdown"
            if self.down_after is not None:
                due = len(self.host.sleeps) + self.down_after
                self.host.pending += [(due, self.shut_off), (due + 1, self.exited)]
            return f"Domain '{args[1]}' is being shutdown"
        if args[0] == "start":
            pid, cgroup, swap = labctl.session_daemon()
            qemu(self.host, self.next_pid, cgroup, swap)
            self.state = "running"
            return f"Domain '{args[1]}' started"
        raise AssertionError(f"unexpected virsh {args}")

    def shut_off(self):
        self.state = "shut off"

    def exited(self):
        shutil.rmtree(self.host.proc / str(self.pid))


def test_reset_and_pretouch_print_what_guest_state_prints(monkeypatch, capsys):
    """Through Lab.helper, after the domain's ownership check; the largest seed of 18 digits is guest_state.py's."""
    replies = {"reset": {"schema": "hyptcn3/guest-reset/1", "seed": LARGEST, "data_sha256": "5" * 64},
               "pretouch": {"schema": "hyptcn3/guest-pretouch/1", "mib": 400, "touched": True}}
    calls, helper = [], labctl.Lab.helper
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: calls.append("owned"))
    monkeypatch.setattr(labctl.Lab, "helper", lambda self, *a, timeout=600: calls.append(a) or replies[a[0]])
    for command in (["reset", "--seed", str(LARGEST)], ["pretouch"]):
        labctl.main(command)
        assert json.loads(capsys.readouterr().out) == replies[command[0]]
    assert calls == ["owned", ("reset", "--seed", LARGEST), "owned", ("pretouch",)]
    commands = []  # The guest's command line of the real helper.
    monkeypatch.setattr(labctl.Lab, "guest", lambda self, command, timeout=120: commands.append(command) or "{}")
    helper(labctl.Lab(), "reset", "--seed", LARGEST)
    assert commands == [f"python3 /opt/hyptcn-lab/guest_state.py reset --seed {LARGEST}"]
    reset = []
    monkeypatch.setattr(guest_state, "reset", reset.append)
    guest_state.main(["reset", "--seed", str(LARGEST)])
    assert reset == [LARGEST]


@pytest.mark.parametrize("argv, message", [
    (["reset"], "reset requires --seed (the seed of the protocol's seeded level, protocol_v5.reset_seed)"),
    (["reset", "--seed", str(LARGEST + 1)], "--seed is an integer from 0 to 10**18 - 1 (18 digits, "
                                            "lab/guest_state.py reset --seed)"),
    (["reset", "--seed", "-1"], "--seed is an integer from 0 to 10**18 - 1 (18 digits, lab/guest_state.py reset "
                                "--seed)"),
    (["pretouch", "--seed", "1"], "--seed belongs to reset"),
], ids=["reset_without_seed", "seed_of_19_digits", "negative_seed", "seed_of_another_command"])
def test_a_reset_without_its_seed_or_a_seed_elsewhere_is_a_usage_error(monkeypatch, capsys, argv, message):
    """No default: refused by name before the VM is touched."""
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: pytest.fail("the VM was touched"))
    with pytest.raises(SystemExit) as stopped:
        labctl.main(argv)
    assert stopped.value.code == 2 and capsys.readouterr().err.rstrip().endswith("error: " + message)


def test_stop_waits_until_the_vm_is_shut_off_and_its_qemu_has_exited(host, monkeypatch, capsys):
    """The state shut off is not enough while the QEMU process still runs: the next start must start a new one."""
    qemu(host, 4242, DAEMON_UNIT, "0")
    domain = Domain(host, monkeypatch, down_after=2)
    record = labctl.Lab().stop()
    assert domain.calls == ["domstate", "shutdown"] + ["domstate"] * 4
    assert host.sleeps == [labctl.STOP_PAUSE_S] * 3 and labctl.qemu_pid("hyptcn-lab") is None
    assert record == {"domain": "hyptcn-lab", "state_before": "running", "qemu_pid_before": 4242, "state": "shut off",
                      "seconds": record["seconds"]} and record["seconds"] >= 0
    assert json.loads(capsys.readouterr().out) == {"stop": record}


def test_a_vm_shut_off_already_stays_so(host, monkeypatch):
    domain = Domain(host, monkeypatch, state="shut off")
    record = labctl.Lab().stop()
    assert domain.calls == ["domstate"] and host.sleeps == []
    assert (record["state_before"], record["qemu_pid_before"], record["state"]) == ("shut off", None, "shut off")


def test_a_vm_that_does_not_shut_off_fails_after_the_bound(host, monkeypatch):
    """STOP_TIMEOUT_S of waiting, one read every STOP_PAUSE_S; the campaign then rejects before the measured phase."""
    qemu(host, 4242, DAEMON_UNIT, "0")
    Domain(host, monkeypatch, down_after=None)
    monkeypatch.setattr(labctl, "time", SimpleNamespace(monotonic=lambda: sum(host.sleeps), sleep=time.sleep))
    with pytest.raises(RuntimeError) as failed:
        labctl.Lab().stop()
    assert str(failed.value) == "domain hyptcn-lab is 'in shutdown' and its QEMU 4242 runs 180 s after virsh shutdown"
    assert host.sleeps == [labctl.STOP_PAUSE_S] * (labctl.STOP_TIMEOUT_S // labctl.STOP_PAUSE_S)


@pytest.mark.parametrize("daemon_cgroup", [DAEMON_UNIT, SESSION], ids=["way_1", "way_2"])
def test_stop_and_start_give_a_new_qemu_whose_pid_cgroup_and_way_are_reported(host, monkeypatch, capsys,
                                                                               daemon_cgroup):
    """Way 1: the daemon runs in its unit, the new QEMU inherits the unit's cgroup without swap and stays there. Way 2:
    the daemon runs outside its unit while the other VM runs (it is not replaced then), so the new QEMU starts in the
    login session's scope and is moved into a scope of its own: temporary, its pages stay charged where it started
    (finding F4 of B5a). The group's old QEMU ran in a scope of an earlier move."""
    host.allowed = {"busctl", "virsh", "systemctl", "systemd-run"}
    daemon(host, 711993, daemon_cgroup)
    host.running = ["hyptcn-lab-b"]
    qemu(host, 4242, f"{MANAGER}/app.slice/hyptcn-qemu-hyptcn-lab-4242.scope", "0")
    Domain(host, monkeypatch)
    labctl.main(["stop"])
    stop = json.loads(capsys.readouterr().out)["stop"]
    assert (stop["qemu_pid_before"], stop["state"]) == (4242, "shut off")
    labctl.main(["start"])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [list(line) for line in lines] == [["libvirtd"], ["qemu_swap"]]
    record = lines[-1]["qemu_swap"]
    assert (record["qemu_pid"], record["memory_swap_max"], record["vm_swap_kb"]) == (4343, "0", 0)
    if daemon_cgroup == DAEMON_UNIT:
        assert (record["cgroup"], record["way"], record["temporary"], record["scope"]) == (DAEMON_UNIT, "unit", False,
                                                                                           None)
        assert "note" not in record and lines[0]["libvirtd"]["qemu_way"] == "unit"
    else:
        assert (record["cgroup_before"], record["cgroup"], record["way"], record["temporary"], record["note"]) == (
            SESSION, f"{MANAGER}/app.slice/hyptcn-qemu-hyptcn-lab-4343.scope", "scope", True, labctl.TEMPORARY)
        assert lines[0]["libvirtd"]["qemu_way"] == "scope"
