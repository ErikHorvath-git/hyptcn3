"""scripts/labctl.py for protocol v5 (package B5a), with fakes only.

The event command keeps the effect the guest returns in the stop record. The QEMU swap ban works without root
(KOSTRA B5, addendum 20:50Z; dokazy/B5/skuska_swapu.md): before every virsh start the session daemon of libvirt runs
in the transient user unit hyptcn-libvirtd.service without swap, whose cgroup the new QEMU inherits (way 1); after
the start a QEMU outside a cgroup labctl made is moved into a transient scope of the user's systemd manager (way 2);
then memory.swap.max must be 0 and VmSwap 0 kB, and labctl fails loudly otherwise, naming the owner's command when
both ways failed. The fakes replace /proc, the cgroup tree, $XDG_RUNTIME_DIR, the commands (busctl, systemctl,
systemd-run, virsh), the signal and the daemon's socket; two lab VMs may run on this host, so nothing real is
reached (nothing_real). The real check is the lab test on the VM.
"""
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket

import pytest

from scripts import labctl

UID = os.getuid()
MANAGER = f"/user.slice/user-{UID}.slice/user@{UID}.service"
USER_UNIT = f"/user.slice/user-{UID}.slice/user@{UID}.service/app.slice/virtqemud.service"
DAEMON_UNIT = f"{MANAGER}/app.slice/hyptcn-libvirtd.service"
SESSION = f"/user.slice/user-{UID}.slice/session-2730.scope"
SCOPE = "hyptcn-qemu-hyptcn-lab-4242.scope"
# The owner's command for QEMU 4242 of hyptcn-lab, as the lead wrote it (KOSTRA B5, addendum 20:50Z; assignment B5a).
OWNER = ('sudo busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager '
         'StartTransientUnit "ssa(sv)a(sa(sv))" hyptcn-qemu-hyptcn-lab-4242.scope fail 2 PIDs au 1 4242 '
         'MemorySwapMax t 0 0')
LIST = ["virsh", "-c", "qemu:///session", "list", "--state-running", "--name"]
SHOW = ["systemctl", "--user", "show", "hyptcn-libvirtd.service", "-p", "LoadState", "--value"]
START = ["systemctl", "--user", "start", "hyptcn-libvirtd.service"]
CREATE = ["systemd-run", "--user", "--unit", "hyptcn-libvirtd", "-p", "MemorySwapMax=0", "-p", "KillMode=process",
          "/usr/sbin/libvirtd", "--timeout=120"]
DAEMON_COMMANDS = {"virsh", "systemctl", "systemd-run"}  # What way 1 may run; never busctl.
REAL_LISTENING = getattr(labctl, "listening", None)  # Kept before nothing_real replaces it in every test.
# Package B8 (finding F5 of the B5b verification): labctl up requires the protocol the lab serves, of schema 1 or 2.
SCHEMA_2 = ["--protocol", str(Path(labctl.REPO) / "config/collection-v2.json")]


@pytest.fixture(autouse=True)
def nothing_real(tmp_path, monkeypatch):
    """No test of this file runs a command, sends a signal or reaches the session daemon's files and socket of this
    host; a test that needs one of them gets the fake of the host fixture."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"a test reached the real host: {args}")
    for name in ("run", "check_output", "check_call", "call", "Popen"):
        monkeypatch.setattr(labctl.subprocess, name, refuse)
    monkeypatch.setattr(labctl.os, "kill", refuse)
    monkeypatch.setattr(labctl, "listening", refuse, raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "no-runtime-dir"))


@pytest.fixture
def host(tmp_path, monkeypatch):
    """Fake /proc, /sys/fs/cgroup and $XDG_RUNTIME_DIR. Only commands named in host.allowed run (busctl, unless a test
    allows way 1's): busctl answers with host.reply and moves the process when host.moves; virsh lists the domains
    host.running; systemctl show answers host.load_state; systemctl start and systemd-run start a fake daemon (pid
    5151) in the unit, or fail when host.refuses names them. SIGTERM ends a fake daemon host.exit_after sleeps later,
    never when host.lingers; the started daemon's socket accepts after host.socket_after refused probes, never
    without host.opens_socket. Commands and signals are logged in host.calls, sleeps in host.sleeps."""
    host = type("Host", (), {})()
    host.proc, host.cgroups, host.calls = tmp_path / "proc", tmp_path / "cgroup", []
    host.reply, host.moves, host.scope_swap = (0, "o \"/org/freedesktop/systemd1/job/7\"\n", ""), True, "0"
    host.runtime, host.allowed, host.running, host.load_state = tmp_path / "run", {"busctl"}, [], "not-found"
    host.refuses, host.exit_after, host.lingers, host.socket_after, host.opens_socket = None, 0, False, 0, True
    host.sleeps, host.pending, host.probes, host.spawned = [], [], 0, False
    (host.runtime / "libvirt").mkdir(parents=True)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(host.runtime))
    monkeypatch.setattr(labctl, "PROC", host.proc)
    monkeypatch.setattr(labctl, "CGROUPS", host.cgroups)

    def sleep(seconds):
        host.sleeps.append(seconds)
        for due, event in [entry for entry in host.pending if entry[0] <= len(host.sleeps)]:
            host.pending.remove((due, event))
            event()
    monkeypatch.setattr(labctl.time, "sleep", sleep)

    def run(argv, **kw):
        host.calls.append(argv)
        assert argv[0] in host.allowed, argv  # Nothing else may run.
        code, out, err = 0, "", ""
        if argv[0] == "busctl":
            code, out, err = host.reply
            if host.moves and code == 0:
                pid = int(argv[argv.index("PIDs") + 3])
                cgroup(host, pid, f"/user.slice/user-{UID}.slice/user@{UID}.service/app.slice/{argv[8]}",
                       host.scope_swap)
        elif argv == LIST:
            out = "".join(name + "\n" for name in host.running) + "\n"
        elif argv == SHOW:
            out = host.load_state + "\n"
        elif argv in (START, CREATE):
            # A daemon labctl signalled has exited before the unit starts another one.
            assert not any((host.proc / str(call[1]) / "exe").is_symlink() for call in host.calls if call[0] == "kill")
            if host.refuses == argv[0]:
                code, err = 1, "Failed to start transient service unit: Unit hyptcn-libvirtd.service was already loaded"
            else:
                daemon(host, 5151, DAEMON_UNIT)
                host.spawned = True
        else:
            raise AssertionError(f"unexpected command {argv}")
        if kw.get("check") and code:
            raise labctl.subprocess.CalledProcessError(code, argv, out, err)
        return labctl.subprocess.CompletedProcess(argv, code, out, err)
    monkeypatch.setattr(labctl.subprocess, "run", run)

    def kill(pid, sig):
        host.calls.append(("kill", pid, sig))

        def exit_():
            (host.proc / str(pid) / "exe").unlink()  # A zombie until it is reaped has no exe.
            (host.runtime / "libvirt/libvirtd.pid").unlink()
        if host.lingers:
            return
        if host.exit_after:
            host.pending.append((len(host.sleeps) + host.exit_after, exit_))
        else:
            exit_()
    monkeypatch.setattr(labctl.os, "kill", kill)

    def listening(path):
        assert path == host.runtime / "libvirt/libvirt-sock", path
        host.probes += 1
        return host.spawned and host.opens_socket and host.probes > host.socket_after
    monkeypatch.setattr(labctl, "listening", listening, raising=False)
    return host


def cgroup(host, pid, path, swap):
    (host.proc / str(pid) / "cgroup").write_text(f"0::{path}\n")
    directory = host.cgroups / path.lstrip("/")
    directory.mkdir(parents=True, exist_ok=True)
    if swap is not None:
        (directory / "memory.swap.max").write_text(swap + "\n")


def qemu(host, pid, path, swap, domain="hyptcn-lab", swap_kb=0):
    """A fake QEMU of `domain` in the cgroup `path` with VmSwap `swap_kb` (None: no status file)."""
    (host.proc / str(pid)).mkdir(parents=True)
    (host.proc / str(pid) / "cmdline").write_bytes(
        b"/usr/bin/qemu-system-x86_64\0-name\0guest=" + domain.encode() + b",debug-threads=on\0")
    if swap_kb is not None:
        (host.proc / str(pid) / "status").write_text(f"Name:\tqemu-system-x86\nVmSwap:\t{swap_kb:8d} kB\n")
    cgroup(host, pid, path, swap)


def daemon(host, pid, path, swap="0", exe="/usr/sbin/libvirtd", uid=UID):
    """A fake libvirtd (its exe and uid) in the cgroup `path`, and the pid file that names it."""
    (host.proc / str(pid)).mkdir(parents=True, exist_ok=True)
    (host.proc / str(pid) / "exe").symlink_to(exe)
    (host.proc / str(pid) / "status").write_text(f"Name:\tlibvirtd\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    cgroup(host, pid, path, swap)
    (host.runtime / "libvirt/libvirtd.pid").write_text(str(pid))


@pytest.mark.parametrize("place", [DAEMON_UNIT, f"{MANAGER}/app.slice/{SCOPE}"], ids=["daemon_unit", "qemu_scope"])
def test_qemu_with_swap_already_off_is_left_where_it_is(host, place):
    """Only in a cgroup labctl made: the daemon unit (way 1) or a hyptcn-qemu scope of an earlier move (way 2)."""
    qemu(host, 4242, place, "0")
    qemu(host, 4343, USER_UNIT.replace("virtqemud.service", "b.scope"), "max", domain="hyptcn-lab-b")  # Not this VM.
    record = labctl.Lab().qemu_swap_off()
    assert record == {"domain": "hyptcn-lab", "qemu_pid": 4242, "cgroup_before": place, "swap_max_before": "0",
                      "scope": None, "cgroup": place, "memory_swap_max": "0", "vm_swap_kb": 0}
    assert host.calls == []


@pytest.mark.parametrize("before, swap", [(SESSION, "0"), (USER_UNIT, "0"), (DAEMON_UNIT, "max")],
                         ids=["login_session_scope", "another_unit_of_the_manager", "daemon_unit_with_swap"])
def test_qemu_is_moved_unless_a_cgroup_labctl_made_forbids_swap(host, before, swap):
    """A login session scope with memory.swap.max 0 is no place to stay: it ends with the login (KOSTRA B5, addendum
    20:50Z), and another unit's 0 is not labctl's to keep."""
    qemu(host, 4242, before, swap)
    record = labctl.Lab().qemu_swap_off()
    assert [call[:3] + call[8:9] for call in host.calls] == [["busctl", "--user", "call", SCOPE]]
    assert record == {"domain": "hyptcn-lab", "qemu_pid": 4242, "cgroup_before": before, "swap_max_before": swap,
                      "scope": SCOPE, "cgroup": f"{MANAGER}/app.slice/{SCOPE}", "memory_swap_max": "0", "vm_swap_kb": 0}


@pytest.mark.parametrize("before, swap, swap_kb, text", [
    (DAEMON_UNIT, "0", 8592, "8592 kB"), (SESSION, "max", 8592, "8592 kB"), (DAEMON_UNIT, "0", None, "unreadable"),
], ids=["kept", "moved", "unreadable"])
def test_qemu_with_memory_in_swap_fails_with_both_values(host, before, swap, swap_kb, text):
    """memory.swap.max 0 forbids new swap only: pages swapped out before stay there (KOSTRA B5, addendum 20:50Z)."""
    qemu(host, 4242, before, swap, swap_kb=swap_kb)
    place = before if swap == "0" else f"{MANAGER}/app.slice/{SCOPE}"
    with pytest.raises(RuntimeError, match=f"^QEMU 4242 \\(hyptcn-lab\\) has VmSwap {text} with memory.swap.max '0' "
                                           f"in {re.escape(place)}: pages swapped out ") as caught:
        labctl.Lab().qemu_swap_off()
    assert "sudo" not in str(caught.value)  # The owner's command would not bring the pages back.


def test_qemu_is_moved_into_a_user_scope_without_swap_and_read_back(host):
    qemu(host, 4242, USER_UNIT, "max")
    record = labctl.Lab().qemu_swap_off()
    scope = "hyptcn-qemu-hyptcn-lab-4242.scope"
    assert host.calls == [["busctl", "--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                           "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))", scope,
                           "fail", "3", "PIDs", "au", "1", "4242", "MemorySwapMax", "t", "0", "Description", "s",
                           "hyptcn3 QEMU of hyptcn-lab without swap", "0"]]
    assert record["scope"] == scope and record["memory_swap_max"] == "0" and record["cgroup"].endswith("/" + scope)
    assert record["swap_max_before"] == "max"


@pytest.mark.parametrize("before,reply,moves,scope_swap,message", [
    (SESSION, (1, "", "Call failed: Access denied"), False, "0",
     "Access denied; the owner can run: " + re.escape(OWNER) + "$"),
    (USER_UNIT, (0, "", ""), False, "0",
     "is 'max' in .*virtqemud.service after the move into " + SCOPE + ", VmSwap 0 kB; the owner can run: "
     + re.escape(OWNER) + "$"),
    (USER_UNIT, (0, "", ""), True, None, "is None in .*memory controller is not enabled"),
])
def test_labctl_fails_loudly_unless_it_reads_back_0(host, before, reply, moves, scope_swap, message):
    qemu(host, 4242, before, "max")
    host.reply, host.moves, host.scope_swap = reply, moves, scope_swap
    with pytest.raises(RuntimeError, match=message):
        labctl.Lab().qemu_swap_off()


def test_a_move_is_read_back_in_the_scope_itself(host):
    """busctl answered but nothing moved: the QEMU still in a login session scope with 0 is no success."""
    qemu(host, 4242, SESSION, "0")
    host.moves = False
    with pytest.raises(RuntimeError, match=re.escape(f"is '0' in {SESSION} after the move into {SCOPE}, VmSwap 0 kB; "
                                                     f"the owner can run: {OWNER}") + "$"):
        labctl.Lab().qemu_swap_off()
    assert len(host.calls) == 1 and len(host.sleeps) == labctl.SWAP_TRIES  # One move, then only reading back.


def test_the_owner_command_moves_this_qemu_into_a_system_scope_of_its_own():
    """Only when both ways failed, and never a property of a login session scope (KOSTRA B5, addendum 20:50Z)."""
    command = labctl.owner_command("hyptcn-lab", 4242)
    assert command == OWNER
    assert shlex.split(command) == ["sudo", "busctl", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
                                    SCOPE, "fail", "2", "PIDs", "au", "1", "4242", "MemorySwapMax", "t", "0", "0"]


def test_labctl_fails_without_a_qemu_process(host):
    host.proc.mkdir()
    with pytest.raises(RuntimeError, match="QEMU process of domain hyptcn-lab not found"):
        labctl.Lab().qemu_swap_off()


@pytest.mark.parametrize("command", ["start", "up", "deploy"])
def test_every_start_of_the_vm_disables_qemu_swap_before_anything_else(monkeypatch, command, capsys):
    steps = []

    class Stop(Exception):
        pass

    def guest(self, *a, **k):
        steps.append("guest")
        raise Stop
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: None)
    monkeypatch.setattr(labctl.Lab, "clone", lambda self, source: steps.append("clone"))
    monkeypatch.setattr(labctl.Lab, "start", lambda self: steps.append("start"))
    monkeypatch.setattr(labctl.Lab, "qemu_swap_off", lambda self: steps.append("swap off") or {"memory_swap_max": "0"})
    monkeypatch.setattr(labctl.Lab, "guest", guest)
    try:
        # start ends after the swap step; up and deploy go on into the guest.
        labctl.main([command, *(SCHEMA_2 if command == "up" else [])])
    except Stop:
        pass
    starts = [i for i, step in enumerate(steps) if step == "start"]
    assert starts and all(steps[i + 1] == "swap off" for i in starts)
    assert steps[-1] == ("swap off" if command == "start" else "guest")
    lines = capsys.readouterr().out.splitlines()
    assert lines and all(json.loads(line) == {"qemu_swap": {"memory_swap_max": "0"}} for line in lines)


@pytest.mark.parametrize("effect,stored", [
    ({"ok": True, "predicate": "p", "evidence": {"MainPID": "2"}}, {"ok": True, "predicate": "p",
                                                                    "evidence": {"MainPID": "2"}}),
    ({"ok": False, "predicate": "p", "evidence": {"MainPID": "1"}}, {"ok": False, "predicate": "p",
                                                                     "evidence": {"MainPID": "1"}}),
    (None, None),
    ({"predicate": "p", "evidence": "x"}, None),  # Without ok (mutant m12 of the B3 verification).
    ({"ok": "true", "evidence": "x"}, None),
])
def test_stop_record_keeps_the_guest_effect_or_a_false_one(monkeypatch, effect, stored):
    reply = {"schema": "hyptcn3/lab-event/1", "type": "restart_databazy", "action": "stop", "ok": True}
    if effect is not None:
        reply["effect"] = effect
    monkeypatch.setattr(labctl.Lab, "guest", lambda self, command, timeout=120: json.dumps(reply))
    record = labctl.Lab().event("stop", "restart_databazy")
    if stored is None:
        assert record["effect"]["ok"] is False and record["effect"]["evidence"]["guest_effect"] == effect
    else:
        assert record["effect"] == stored
    assert {k: v for k, v in record.items() if k != "effect"} == {k: v for k, v in reply.items() if k != "effect"}


def test_start_record_has_no_effect_and_the_event_command_prints_the_stop_effect(monkeypatch, capsys):
    replies = {"start": {"action": "start", "ok": True},
               "stop": {"action": "stop", "ok": True, "effect": {"ok": True, "predicate": "p", "evidence": "iba spúšťač"}}}
    monkeypatch.setattr(labctl.Lab, "guest", lambda self, command, timeout=120: json.dumps(replies[command.split()[2]]))
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: None)
    assert "effect" not in labctl.Lab().event("start", "naprazdno")
    labctl.main(["event", "--event", "stop", "naprazdno"])
    assert json.loads(capsys.readouterr().out)["effect"] == replies["stop"]["effect"]


@pytest.mark.parametrize("command, rest", [("start", []), ("up", ["deploy", "health", "traffic"]),
                                           ("deploy", ["guest"])])
def test_a_failed_swap_step_ends_the_command_with_the_owner_command_after_its_other_steps(monkeypatch, command,
                                                                                         rest, capsys):
    """The executor's merge of B5a: when both ways fail (the unit for the daemon and the scope for the running QEMU)
    the command still deploys (the lab test needs no collection; run_session refuses a QEMU with swap) and then fails
    with the owner's command."""
    steps = []
    owner = OWNER.replace("4242", "42")

    def refused(self):
        steps.append("swap off")
        raise RuntimeError("cannot move QEMU 42 of hyptcn-lab; the owner can run: " + owner)
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: None)
    monkeypatch.setattr(labctl.Lab, "clone", lambda self, source: steps.append("clone"))
    monkeypatch.setattr(labctl.Lab, "start", lambda self: steps.append("start"))
    monkeypatch.setattr(labctl.Lab, "qemu_swap_off", refused)
    if command == "up":
        monkeypatch.setattr(labctl.Lab, "deploy", lambda self: steps.append("deploy"))
        monkeypatch.setattr(labctl.Lab, "health", lambda self: steps.append("health"))
        monkeypatch.setattr(labctl.Lab, "traffic", lambda self: steps.append("traffic"))
    else:
        monkeypatch.setattr(labctl.Lab, "guest", lambda self, *a, **k: steps.append("guest") or "yes")
        monkeypatch.setattr(labctl.Lab, "health", lambda self: steps.append("health"))
    if command == "deploy":
        monkeypatch.setattr(labctl.Lab, "deploy", lambda self: (self.start(), self.swap_step(),
                                                                self.guest("true")) and None)
    with pytest.raises(RuntimeError, match="^QEMU swap is not disabled: cannot move QEMU 42 .*" + re.escape(owner)
                       + "$"):
        labctl.main([command, *(SCHEMA_2 if command == "up" else [])])
    up_to_rest = ["clone", "start", "swap off"] if command == "up" else ["start", "swap off"]
    assert steps == up_to_rest + rest + (["health"] if command == "deploy" else [])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert lines[0]["qemu_swap"]["memory_swap_max"] is None and owner in lines[0]["qemu_swap"]["error"]


# Way 1: the session daemon of libvirt in hyptcn-libvirtd.service before every virsh start.

def test_the_daemon_step_comes_right_before_every_virsh_start_and_only_then(monkeypatch):
    """Lab.start(): only a shut-off domain is started, and the daemon is made sure of right before."""
    for state, before_wait in (("shut off", ["domstate", "libvirtd", "start"]), ("running", ["domstate"])):
        steps = []
        monkeypatch.setattr(labctl.Lab, "owned", lambda self: steps.append("owned"))
        monkeypatch.setattr(labctl.Lab, "virsh", lambda self, *a, **k: steps.append(a[0]) or (
            state if a[0] == "domstate" else ""))
        monkeypatch.setattr(labctl.Lab, "daemon_step", lambda self: steps.append("libvirtd"), raising=False)
        monkeypatch.setattr(labctl.Lab, "wait", lambda self: steps.append("wait"))
        monkeypatch.setattr(labctl.Lab, "guest", lambda self, *a, **k: steps.append("guest") or "")
        labctl.Lab().start()
        assert steps == ["owned", *before_wait, "wait", "guest"], state


def test_a_daemon_in_its_unit_is_left_as_it_is(host, capsys):
    daemon(host, 711993, DAEMON_UNIT)
    record = labctl.Lab().daemon_step()
    assert host.calls == []
    assert record == {"unit": "hyptcn-libvirtd.service", "found": "unit", "daemon_pid_before": 711993,
                      "cgroup_before": DAEMON_UNIT, "done": [], "daemon_pid": 711993, "cgroup": DAEMON_UNIT,
                      "memory_swap_max": "0", "qemu_way": "unit"}
    assert json.loads(capsys.readouterr().out) == {"libvirtd": record}  # Printed like the qemu_swap record.


@pytest.mark.parametrize("load_state, command, socket_after", [("not-found", CREATE, 0), ("loaded", START, 0),
                                                               ("not-found", CREATE, 5)],
                         ids=["created", "loaded_unit_started_again", "socket_awaited"])
def test_without_a_daemon_the_unit_is_started_and_its_socket_awaited(host, load_state, command, socket_after):
    """A unit stays loaded while processes of a stopped run remain in it (skuska_swapu.md): systemctl start then,
    systemd-run only for a unit that is not loaded."""
    host.allowed, host.load_state, host.socket_after = DAEMON_COMMANDS, load_state, socket_after
    record = labctl.Lab().daemon_step()
    assert host.calls == [SHOW, command]
    assert record == {"unit": "hyptcn-libvirtd.service", "found": "none", "daemon_pid_before": None,
                      "cgroup_before": None, "done": [" ".join(command)], "daemon_pid": 5151, "cgroup": DAEMON_UNIT,
                      "memory_swap_max": "0", "qemu_way": "unit"}
    assert host.sleeps == [labctl.DAEMON_PAUSE_S] * socket_after  # One pause per refused probe of the socket.


@pytest.mark.parametrize("exe, uid", [("/usr/bin/python3", UID), ("/usr/sbin/libvirtd", UID + 1)],
                         ids=["another_program", "another_user"])
def test_a_stale_pid_file_names_no_daemon_and_its_process_is_never_signalled(host, exe, uid):
    host.allowed = DAEMON_COMMANDS
    daemon(host, 711993, SESSION, exe=exe, uid=uid)
    record = labctl.Lab().daemon_step()
    assert host.calls == [SHOW, CREATE]  # No signal, and no question whether domains run.
    assert (record["found"], record["daemon_pid_before"], record["daemon_pid"], record["qemu_way"]) == (
        "none", None, 5151, "unit")


def test_a_daemon_outside_the_unit_is_replaced_while_no_domain_runs(host):
    """The daemon of 2026-11-22 ran in the login session scope (memory.swap.max 0 there): at the start of a group it
    gets SIGTERM, exactly it, and the unit starts only after it has exited."""
    host.allowed, host.exit_after = DAEMON_COMMANDS, 3
    daemon(host, 711993, SESSION)
    record = labctl.Lab().daemon_step()
    assert host.calls == [LIST, ("kill", 711993, signal.SIGTERM), SHOW, CREATE]
    assert record == {"unit": "hyptcn-libvirtd.service", "found": "outside", "daemon_pid_before": 711993,
                      "cgroup_before": SESSION, "running_domains": [], "done": ["SIGTERM 711993", " ".join(CREATE)],
                      "daemon_pid": 5151, "cgroup": DAEMON_UNIT, "memory_swap_max": "0", "qemu_way": "unit"}
    assert host.sleeps == [labctl.DAEMON_PAUSE_S] * 3  # Its exit was awaited.


def test_a_daemon_outside_the_unit_stays_while_a_domain_runs_and_the_new_qemu_goes_through_the_scope(host):
    host.allowed, host.running = DAEMON_COMMANDS, ["hyptcn-lab-b"]
    daemon(host, 711993, SESSION)
    record = labctl.Lab().daemon_step()
    assert host.calls == [LIST]
    assert record == {"unit": "hyptcn-libvirtd.service", "found": "outside", "daemon_pid_before": 711993,
                      "cgroup_before": SESSION, "running_domains": ["hyptcn-lab-b"], "done": [], "daemon_pid": 711993,
                      "cgroup": SESSION, "memory_swap_max": "0", "qemu_way": "scope"}


@pytest.mark.parametrize("failure, calls, error", [
    ("refused", [SHOW, CREATE], r"returned non-zero exit status 1\.: Failed to start transient service unit: "),
    ("no_socket", [SHOW, CREATE], "^no daemon of hyptcn-libvirtd.service accepts connections on its socket "
                                  "after 30 s$"),
    ("no_exit", [LIST, ("kill", 711993, signal.SIGTERM)], "^libvirtd 711993 has not exited after 30 s$"),
    ("no_runtime_dir", [], "^XDG_RUNTIME_DIR is not set"),
])
def test_a_failed_daemon_unit_is_recorded_and_the_qemu_goes_through_the_scope(host, monkeypatch, failure, calls,
                                                                             error):
    """Way 1 failing alone is no error (way 2 and the check follow the start); it is recorded."""
    host.allowed = DAEMON_COMMANDS
    if failure == "refused":
        host.refuses = "systemd-run"
    elif failure == "no_socket":
        host.opens_socket = False
    elif failure == "no_exit":
        daemon(host, 711993, SESSION)
        host.lingers = True
    else:
        monkeypatch.delenv("XDG_RUNTIME_DIR")
    record = labctl.Lab().daemon_step()
    assert host.calls == calls  # A daemon that has not exited is not followed by the unit.
    assert re.search(error, record["error"]) and record["qemu_way"] == "scope"
    assert set(record) - {"running_domains"} == {"unit", "found", "daemon_pid_before", "cgroup_before", "done", "error",
                                                 "daemon_pid", "cgroup", "memory_swap_max", "qemu_way"}


def test_listening_needs_a_process_that_accepts_on_the_socket(tmp_path, monkeypatch):
    """A socket file left behind by a daemon that is gone refuses connections (virsh would start its own daemon)."""
    monkeypatch.chdir(tmp_path)  # A unix socket path has at most 107 bytes; this test's directory may be longer.
    path = Path("libvirt-sock")
    assert REAL_LISTENING(path) is False  # No file.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen()
        assert REAL_LISTENING(path) is True
    assert path.is_socket() and REAL_LISTENING(path) is False
