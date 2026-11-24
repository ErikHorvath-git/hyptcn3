"""scripts/labctl.py in package B11: QEMU born in the session daemon's unit and the unit charged with its memory (the
lead's instruction on finding F4 of B5a, 2026-11-24, and his answer to Q26), on the fakes of lab/tests/test_labctl.py
only.

charge(cgroup) judges anon of the cgroup's memory.stat against 0.9 (judgment of the lab test, accepted by the lead) x
the RssAnon of the QEMU processes in its cgroup.procs, and records memory.current and VmRSS beside it. labctl start
ends with exit code 1 naming F4 when the QEMU is in the unit but its memory is not, or when the command started it
outside the unit; a running QEMU labctl did not start keeps the temporary way 2. start and stop make sure of the daemon
before their first virsh call, every virsh call of labctl starts no daemon of its own (LIBVIRT_AUTOSTART=0), and labctl
daemon reports and ensures the unit and refuses to replace a daemon outside it while a domain runs. Nothing real is
reached (test_labctl.nothing_real: no command, no signal, no socket of this host). Names of the package are read inside
the tests, so this file collects on the code before it.
"""
import json
import re
import signal
import subprocess

import pytest

from scripts import labctl
from lab.tests import test_labctl as fakes
from lab.tests.test_labctl import (CREATE, DAEMON_COMMANDS, DAEMON_UNIT, LIST, SESSION, SHOW, cgroup, daemon,  # noqa
                                   host, nothing_real, qemu)

PAGE = fakes.PAGE_CACHE
OWNED = ("<domain><description>hyptcn3 benign persistent lab</description><devices><interface><portForward>"
         "<range start='18080' to='8080'/></portForward></interface></devices></domain>")


def process(host, pid, exe, path, anon_kb):
    """Another process of the daemon's unit (virtlogd, passt): its cmdline and anon_kb of anonymous memory there."""
    (host.proc / str(pid)).mkdir(parents=True)
    (host.proc / str(pid) / "cmdline").write_bytes(exe.encode() + b"\0")
    (host.proc / str(pid) / "status").write_text(f"Name:\t{exe.rsplit('/', 1)[-1]}\nVmRSS:\t{anon_kb} kB\n"
                                                 f"RssAnon:\t{anon_kb} kB\n")
    cgroup(host, pid, path, "0", anon_kb)


def test_charge_sums_the_qemu_processes_of_the_unit_and_leaves_the_others_out(host):
    """One daemon starts both VMs: both QEMUs are in the unit, with libvirtd, virtlogd and passt, whose memory only
    adds to anon; a process listed in cgroup.procs that has exited since is no longer charged there."""
    daemon(host, 711993, DAEMON_UNIT)
    qemu(host, 4242, DAEMON_UNIT, "0", rss_anon_kb=800000)
    qemu(host, 4343, DAEMON_UNIT, "0", domain="hyptcn-lab-b", rss_anon_kb=600000)
    process(host, 712054, "/usr/sbin/virtlogd", DAEMON_UNIT, 1800)
    process(host, 712060, "/usr/bin/passt", DAEMON_UNIT, 1200)
    procs = host.cgroups / DAEMON_UNIT.lstrip("/") / "cgroup.procs"
    procs.write_text(procs.read_text() + "4999\n")  # Exited: no /proc entry.
    anon = fakes.DAEMON_ANON_KB + 800000 + 600000 + 1800 + 1200
    assert labctl.charge(DAEMON_UNIT) == fakes.memory(DAEMON_UNIT, [(4242, 800000), (4343, 600000)], anon)
    assert labctl.charge(DAEMON_UNIT)["share"] == 1.016 and labctl.CHARGED_SHARE == .9  # 1423000 / 1400000


@pytest.mark.parametrize("case, error", [
    ("below_share", None),
    ("at_share", None),
    ("no_cgroup", "no cgroup v2 path"),
    ("no_memory_stat", "No such file or directory"),
    ("no_anon_line", "memory.stat of .* has no anon line"),
    ("no_cgroup_procs", "No such file or directory"),
    ("no_qemu", "no QEMU process in the cgroup.procs of "),
    ("no_rss_anon", "^/proc/4242/status has no VmRSS or RssAnon$"),
    ("unreadable_qemu", "No such file or directory: .*/proc/4242/status"),
    ("rss_anon_zero", "the QEMU processes of .* have RssAnon 0 kB$"),
])
def test_charge_is_never_true_for_memory_charged_elsewhere_or_unread(host, case, error):
    """Below the share (the QEMU was moved into the unit: its pages stayed where they were faulted) charged is false,
    at the share exactly true (at least 0.9); every file it cannot read gives the error, never charged."""
    daemon(host, 711993, DAEMON_UNIT)
    base = host.cgroups / DAEMON_UNIT.lstrip("/")
    if case == "below_share":
        qemu(host, 4242, SESSION, "0")
        cgroup(host, 4242, DAEMON_UNIT, "0")
    elif case != "no_qemu":
        qemu(host, 4242, DAEMON_UNIT, "0", rss_anon_kb=0 if case == "rss_anon_zero" else fakes.RSS_ANON_KB)
    status = host.proc / "4242/status"
    if case == "at_share":
        (base / "memory.stat").write_text(f"anon {int(.9 * fakes.RSS_ANON_KB) << 10}\nfile 0\n")
    elif case == "no_memory_stat":
        (base / "memory.stat").unlink()
    elif case == "no_anon_line":
        (base / "memory.stat").write_text("file 0\n")
    elif case == "no_cgroup_procs":
        (base / "cgroup.procs").unlink()
    elif case == "no_rss_anon":
        status.write_text("Name:\tqemu-system-x86\nVmSwap:\t       0 kB\n")
    elif case == "unreadable_qemu":
        status.unlink()
    record = labctl.charge(None if case == "no_cgroup" else DAEMON_UNIT)
    assert record["charged"] is (case == "at_share") and record["charged_share"] == .9
    if case == "at_share":
        assert "error" not in record and record["share"] == .9
    elif error is None:
        assert "error" not in record and record["share"] == round(fakes.DAEMON_ANON_KB / fakes.RSS_ANON_KB, 3)
    else:
        assert re.search(error, record["error"]) and record["share"] is None


class Virsh:
    """virsh of one domain through labctl.run, as the session daemon answers it: refused (rc 1) while no daemon runs
    (LIBVIRT_AUTOSTART=0: virsh starts none); dumpxml of a domain labctl made, domstate, start (QEMU 4343 born in the
    cgroup of the daemon that runs) and shutdown (shut off at once, its QEMU gone). Every command and its environment
    is recorded in host.calls and self.env; the other commands go to the host fixture."""

    def __init__(self, host, monkeypatch, state):
        self.host, self.state, self.env, self.base = host, state, [], labctl.subprocess.run
        monkeypatch.setattr(labctl.subprocess, "run", self.run)
        monkeypatch.setattr(labctl.subprocess, "check_output", lambda argv, **kw: "not-found\n")  # The traffic unit.
        monkeypatch.setattr(labctl.Lab, "wait", lambda lab: None)
        monkeypatch.setattr(labctl.Lab, "guest", lambda lab, command, timeout=120: "")

    def run(self, argv, **kw):
        if argv[0] != "virsh" or argv == LIST:
            return self.base(argv, **kw)
        self.host.calls.append(argv)
        self.env.append((kw.get("env") or {}).get("LIBVIRT_AUTOSTART"))
        pid, cgroup_path, swap = labctl.session_daemon()
        verb, out = argv[3], ""
        if pid is None:
            raise subprocess.CalledProcessError(1, argv, "", "error: failed to connect to the hypervisor")
        if verb == "dumpxml":
            out = OWNED
        elif verb == "domstate":
            out = self.state
        elif verb == "start":
            qemu(self.host, 4343, cgroup_path, swap)
            self.state = "running"
        elif verb == "shutdown":
            self.state = "shut off"
            (self.host.proc / "4242/cmdline").unlink()  # Its QEMU has exited.
        return subprocess.CompletedProcess(argv, 0, out + "\n", "")


@pytest.mark.parametrize("command", ["start", "stop"])
def test_with_no_daemon_start_and_stop_start_the_unit_before_any_virsh_call_and_virsh_starts_none(
        host, monkeypatch, capsys, command):
    """After a reboot of the host no daemon runs: the unit starts before the first virsh call, so the daemon, and every
    QEMU it starts or restores from a managed save, lives in it; no virsh call of labctl may start a daemon itself."""
    host.allowed = DAEMON_COMMANDS
    if command == "stop":
        qemu(host, 4242, DAEMON_UNIT, "0")
    virsh = Virsh(host, monkeypatch, "shut off" if command == "start" else "running")
    labctl.main([command])
    assert host.calls[:2] == [SHOW, CREATE] and all(call[0] == "virsh" for call in host.calls[2:])
    verbs = [call[3] for call in host.calls[2:]]
    assert verbs == (["dumpxml", "domstate", "start"] if command == "start" else
                     ["dumpxml", "domstate", "shutdown", "domstate"])
    assert virsh.env == ["0"] * len(verbs)
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert '"found": "none"' in lines[0] and '"qemu_way": "unit"' in lines[0]  # The daemon step, once.
    if command == "start":
        assert len(lines) == 2 and '"way": "unit"' in lines[1] and '"charged": true' in lines[1]


def test_clone_makes_sure_of_the_daemon_before_its_first_virsh_call(monkeypatch):
    """labctl up and create clone before they start: with no daemon running, the unit is started before virsh list."""
    steps = []
    monkeypatch.setattr(labctl, "session_daemon", lambda: (None, None, None))
    monkeypatch.setattr(labctl.Lab, "daemon_step", lambda self: steps.append("libvirtd"))
    monkeypatch.setattr(labctl.Lab, "virsh", lambda self, *a, **k: steps.append(a[0]) or "hyptcn-lab")
    monkeypatch.setattr(labctl.Lab, "owned", lambda self: steps.append("owned"))
    labctl.Lab().clone("hyptcn-guest")  # The domain exists: clone only checks it is labctl's.
    assert steps == ["libvirtd", "list", "owned"]


def test_a_qemu_in_the_unit_whose_memory_is_charged_elsewhere_ends_labctl_start_naming_f4(host, monkeypatch, capsys):
    """Way 1 by its cgroup but not by its memory: the QEMU was moved into the unit and its pages stayed where they were
    faulted. labctl start exits 1 with the numbers, and the record of the swap step is printed whole."""
    daemon(host, 711993, DAEMON_UNIT)
    qemu(host, 4242, SESSION, "0")
    cgroup(host, 4242, DAEMON_UNIT, "0")
    Virsh(host, monkeypatch, "running")
    unit_anon = fakes.DAEMON_ANON_KB << 10
    message = ("QEMU swap is not disabled: QEMU 4242 (hyptcn-lab) runs in hyptcn-libvirtd.service, but the unit is "
               "not charged with the memory of its QEMU processes (finding F4 of B5a): memory.stat anon "
               f"{unit_anon} B is 0.025 of their RssAnon {fakes.RSS_ANON_KB} kB, at least 0.9 required (judgment, the "
               "lead's answer to "
               f"Q26); memory.current {unit_anon + PAGE} B, VmRSS 4242 {fakes.RSS_ANON_KB + fakes.RSS_FILE_KB} kB")
    with pytest.raises(RuntimeError) as failed:
        labctl.main(["start"])
    assert str(failed.value) == message
    record = json.loads(capsys.readouterr().out.splitlines()[-1])["qemu_swap"]
    assert (record["way"], record["temporary"], record["memory"]["charged"], record["error"]) == (
        "unit", False, False, message.removeprefix("QEMU swap is not disabled: "))


def test_a_running_qemu_labctl_did_not_start_keeps_the_temporary_way_2(host, monkeypatch, capsys):
    """Way 2 as before for a QEMU that runs already (labctl deploy of a running VM): moved, temporary, exit 0."""
    host.allowed = DAEMON_COMMANDS | {"busctl"}
    daemon(host, 711993, SESSION)
    qemu(host, 4242, SESSION, "0")
    Virsh(host, monkeypatch, "running")
    labctl.main(["start"])
    record = json.loads(capsys.readouterr().out.splitlines()[-1])["qemu_swap"]
    assert (record["way"], record["temporary"], record["memory"]["charged"]) == ("scope", True, False)
    assert "error" not in record and [call[0] for call in host.calls] == ["virsh", "virsh", "busctl"]


@pytest.mark.parametrize("case, calls, error", [
    ("in_unit", [], None),
    ("none", [SHOW, CREATE], None),
    ("outside_idle", [LIST, ("kill", 711993, signal.SIGTERM), SHOW, CREATE], None),
    ("outside_busy", [LIST], "^the session daemon 711993 runs outside hyptcn-libvirtd.service \\(in "
                             + re.escape(SESSION) + "\\) while hyptcn-lab-b run: it is not replaced while a domain "
                             "runs \\(finding F4 of B5a\\); stop every lab VM \\(labctl stop\\), then start them with "
                             "labctl start: "),
    ("unit_refused", [SHOW, CREATE], "^no session daemon runs in hyptcn-libvirtd.service with memory.swap.max 0 "
                                     "\\(found none, memory.swap.max None\\): .*Failed to start transient service"),
])
def test_labctl_daemon_reports_ensures_the_unit_and_refuses_to_replace_a_daemon_while_a_domain_runs(
        host, monkeypatch, capsys, case, calls, error):
    """The check before a launch (dokazy/B9/odlozene_B9a.md) and the first step of the migration of F4: a daemon in
    the unit is left, none is started there, one outside is replaced while no domain runs; otherwise exit 1 with the
    migration (both VMs shut off, then labctl start each), or with the failure of the unit."""
    host.allowed = DAEMON_COMMANDS
    if case == "in_unit":
        daemon(host, 711993, DAEMON_UNIT)
    elif case.startswith("outside"):
        daemon(host, 711993, SESSION)
        host.running = ["hyptcn-lab-b"] if case == "outside_busy" else []
    elif case == "unit_refused":
        host.refuses = "systemd-run"
    envs, base = [], labctl.subprocess.run  # The environment of each command: virsh starts no daemon.
    monkeypatch.setattr(labctl.subprocess, "run", lambda argv, **kw: envs.append(
        (argv[0], (kw.get("env") or {}).get("LIBVIRT_AUTOSTART"))) or base(argv, **kw))
    if error is None:
        labctl.main(["daemon"])
    else:
        with pytest.raises(RuntimeError, match=error):
            labctl.main(["daemon"])
    assert host.calls == calls and [env for name, env in envs if name == "virsh"] == ["0"] * calls.count(LIST)
    record = json.loads(capsys.readouterr().out)["libvirtd"]
    assert record["qemu_way"] == ("unit" if error is None else "scope")
    assert record["cgroup"] == (DAEMON_UNIT if error is None else SESSION if case == "outside_busy" else None)
