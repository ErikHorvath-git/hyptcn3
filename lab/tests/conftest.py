"""A fake guest for the controls of package B8 (lab/tests/test_kontroly.py, lab/tests/test_baseline.py).

Fakes of /proc (stat, cmdline, maps, fd, status, modules, meminfo, net/tcp), sysfs, modules.dep and the state
directory, of the commands lab/udalosti.py and lab/guest_state.py run (modprobe, systemctl), of the sessions
background starts and of the signals sent to them: nothing runs, loads a module or sends a signal for real.
Names package B8 adds are used inside the fixture only, so the files collect on the base code.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_state  # noqa: E402
import udalosti  # noqa: E402

RWX = "7f0000000000-7f0000001000 rwxp 00000000 00:00 0\n"
RW = "7f0000000000-7f0000001000 rw-p 00000000 00:00 0\n"
MEMFD = "/memfd:hyptcn-kontrola (deleted)"
TCP_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
LOADED = "virtio_net 61440 0 - Live 0x0000000000000000\nfuse 176128 1 - Live 0x0000000000000000\n"
# The guest kernel's package: the three candidates as Debian 12 ships them, a module that needs another one.
MODULES_DEP = ("kernel/lib/crc7.ko:\nkernel/lib/crc8.ko:\nkernel/lib/ts_kmp.ko:\n"
               "kernel/fs/udf/udf.ko: kernel/lib/crc-itu-t.ko kernel/drivers/cdrom/cdrom.ko\n"
               "kernel/lib/crc-itu-t.ko:\nupdates/dkms/vendor.ko:\n")


class FakeGuest:
    def __init__(self, root, monkeypatch):
        self.root, self.proc, self.state, self.sys = root, root / "proc", root / "state", root / "sys"
        self.calls, self.started, self.signals, self.failed, self.stubborn = [], [], [], [], set()
        self.next_pid, self.modprobe_fails, self.modprobe_loads, self.sets_up = 4000, set(), True, True
        for path in ("proc/net", "state", "sys/class/net/lo", "sys/class/net/enp1s0", "sys/dev/char/1:3",
                     "sys/dev/block/253:0"):
            (root / path).mkdir(parents=True)
        (self.proc / "net" / "tcp").write_text(TCP_HEADER)
        (self.proc / "net" / "tcp6").write_text(TCP_HEADER)
        (self.proc / "modules").write_text(LOADED)
        (root / "modules.dep").write_text(MODULES_DEP)
        self.memory(1_500_000)
        for pid in (1, 300, 301):  # init and two lab services: processes of no control.
            self.process(pid, pid, ["/usr/bin/python3", "/opt/hyptcn-lab/services.py", "catalog"])
        for name, value in (("PROC", self.proc), ("STATE", self.state), ("SYS", self.sys),
                            ("MODULES_DEP", root / "modules.dep"), ("NEGATIVE_FILE", root / "tmp-negativna"),
                            ("run", self.run), ("health", lambda: 200), ("signal_session", self.signal),
                            ("background", self.background)):
            monkeypatch.setattr(udalosti, name, value)
        monkeypatch.setattr(guest_state, "PROC", self.proc)
        monkeypatch.setattr(guest_state, "run", self.list_units)

    # ---------------------------------------------------------------------------------------- /proc
    def process(self, pid, sid, argv, maps="", fds=(), rss_kib=9000):
        entry = self.proc / str(pid)
        (entry / "fd").mkdir(parents=True)
        (entry / "stat").write_text(f"{pid} ({Path(argv[0]).name[:15]}) S 1 {sid} {sid} 0 -1 4194560 0 0 0 0 0 0 0 0 "
                                    f"20 0 1 0 100\n")
        (entry / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in argv))
        (entry / "status").write_text(f"Name:\t{Path(argv[0]).name}\nThreads:\t1\nVmRSS:\t{rss_kib:>8} kB\n")
        (entry / "maps").write_text(maps)
        for number, target in enumerate(fds, 3):
            (entry / "fd" / str(number)).symlink_to(target)

    def remove(self, pid):
        shutil.rmtree(self.proc / str(pid))

    def memory(self, available_kb):
        (self.proc / "meminfo").write_text(f"MemTotal:        2000000 kB\nMemAvailable:    {available_kb} kB\n")

    def listen(self, port, inode, table="tcp"):
        """A socket in state LISTEN (0A) on 127.0.0.1 (tcp) or ::1 (tcp6)."""
        local = "0100007F" if table == "tcp" else "00000000000000000000000001000000"
        with (self.proc / "net" / table).open("a") as stream:
            stream.write(f"   0: {local}:{port:04X} {'0' * len(local)}:0000 0A 00000000:00000000 00:00000000 "
                         f"00000000 65534        0 {inode} 1 0000000000000000 100 0 0 10 0\n")

    def load(self, name):
        with (self.proc / "modules").open("a") as stream:
            stream.write(f"{name} 16384 0 - Live 0x0000000000000000\n")

    def unload(self, name):
        modules = self.proc / "modules"
        modules.write_text("".join(line + "\n" for line in modules.read_text().splitlines()
                                   if line.split()[0] != name))

    # ---------------------------------------------------------------------------------------- an occurrence
    def occurrence(self, kind, sid, polarity, dose=None, **values):
        """The state udalosti.py start leaves: the session's pid file (none for the module kind) and what start
        remembered."""
        if sid is not None:
            (self.state / f"{kind}.pid").write_text(str(sid))
        (self.state / f"{kind}.before.json").write_text(json.dumps({"polarity": polarity, "dose": dose, **values}))

    def report(self, kind, *lines):
        (self.state / f"{kind}.out").write_text("".join(json.dumps(line) + "\n" for line in lines))

    def program(self, kind, sid, **process):
        """The runuser leader `sid` and the python3 of a control's program in its session."""
        command = ["runuser", "-u", "nobody", "--", "python3", "-c", udalosti.PROGRAMS[kind], "control"]
        self.process(sid, sid, command)
        self.process(sid + 1, sid, command[4:], **process)

    # ---------------------------------------------------------------------------------------- commands
    def run(self, *args, check=True, timeout=90):
        self.calls.append(args)
        if args[:2] == ("systemctl", "show"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "modprobe":
            name = args[-1]
            if name in self.modprobe_fails:
                raise subprocess.CalledProcessError(1, args, "", f"modprobe: FATAL: Module {name} is in use.")
            if args[1:-1] == ("-n", "-v"):
                return subprocess.CompletedProcess(args, 0, f"insmod /lib/modules/6.1.0-42-cloud-amd64/kernel/lib/"
                                                            f"{name}.ko \n", "")
            if args[1:-1] == ("-r",):
                self.unload(name)
            elif len(args) == 2 and self.modprobe_loads:
                self.load(name)
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected guest command {args}")

    def list_units(self, *args, check=True, input=None, timeout=120):
        assert args == ("systemctl", "list-units", "--state=failed", "--all", "--plain", "--no-legend",
                        "--no-pager"), args
        return "".join(f"{unit} loaded failed failed A lab unit\n" for unit in self.failed)

    def background(self, name, command, output=None):
        """A session as udalosti.background starts it: the runuser leader and the program's python3, which at once
        sets up what the real program would and reports (nothing of it while sets_up is false). command is runuser
        -u nobody -- python3 -c PROGRAM polarity ARGUMENTS (udalosti.program_arguments)."""
        self.started.append((name, command))
        sid, self.next_pid = self.next_pid, self.next_pid + 10
        program, polarity, arguments, now = sid + 1, command[7], command[8:], time.monotonic()
        self.process(sid, sid, command)
        setup, report = {}, {"ready": True, "pid": program, "t": now}
        if name == "kontrola_wx_memfd" and self.sets_up:
            negative = polarity == "negative"
            setup = {"maps": RW if negative else RWX, "fds": [arguments[0] if negative else MEMFD]}
            if negative:
                Path(arguments[0]).write_text("")
        elif name == "kontrola_pocuvajuci_soket" and self.sets_up:
            setup = {"fds": [f"socket:[{program}]"]}
            if polarity == "control":
                self.listen(int(arguments[0]), program)
        elif name == "kontrola_zapisovac_pamate":
            setup = {"rss_kib": (int(arguments[0]) << 10) + 9000} if self.sets_up else {}
            report = {"round": 1, "bytes": int(arguments[0]) << 20, "t": now}
        elif name == "kontrola_davka_procesov":
            report = {"started": 1 if polarity == "negative" else int(arguments[0]), "alive": 1, "t": now}
            if self.sets_up:
                self.process(sid + 2, sid, [udalosti.BATCH_CHILD, arguments[2] if polarity == "negative"
                                            else arguments[1]])
        self.process(program, sid, command[4:], **setup)
        (self.state / f"{name}.pid").write_text(str(sid))
        if output and self.sets_up:
            Path(output).write_text(json.dumps(report) + "\n")
        return sid

    def signal(self, sid, number):
        """The processes of the session end, unless the test keeps them (stubborn) for this signal."""
        self.signals.append((sid, number))
        if (sid, number) in self.stubborn:
            return
        for stat in self.proc.glob("[0-9]*/stat"):
            if int(stat.read_text().rsplit(")", 1)[1].split()[3]) == sid:
                self.remove(int(stat.parent.name))


@pytest.fixture
def control_guest(tmp_path, monkeypatch):
    return FakeGuest(tmp_path, monkeypatch)
