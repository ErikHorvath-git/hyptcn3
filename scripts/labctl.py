#!/usr/bin/env python3
"""Host-side lifecycle for the benign server VM; no host root required."""
import argparse
import base64
import fnmatch
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import uuid
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[1]
STATE = REPO / "vms/lab-state.json"
UNIT = "hyptcn-lab-traffic"
PORT = 18080  # Host port of the single (legacy) lab VM; every further VM names its own.
# Guest disk of every named VM (protocol v4): all clones of hyptcn-guest are grown to
# the same size the legacy lab got by hand on 2026-10-20 (docs/LAB.sk.md), so VMs of
# one campaign differ only in machine-id and hostname.
DISK_GIB = 20
AGENT_TIMEOUT_S = 60
AGENT_RETRIES = 2
AGENT_IDEMPOTENT = {"guest-exec-status", "guest-ping", "guest-info", "guest-get-time"}
# Grow the root partition and file system to the disk, idempotently (growpart says
# NOCHANGE once done). Runs in the guest through the agent on every start of a named VM.
GROW_ROOT = ('src=$(findmnt -no SOURCE /); disk=/dev/$(lsblk -no PKNAME "$src"); '
             'part=$(cat /sys/class/block/$(basename "$src")/partition); '
             'growpart "$disk" "$part" >/dev/null 2>&1; resize2fs "$src" >/dev/null 2>&1; '
             'df -B1 --output=size / | tail -1')
VM_NAME = r"[a-z0-9]{1,16}"
PROC = Path("/proc")
CGROUPS = Path("/sys/fs/cgroup")
# The old closed-loop generator's user unit (traffic-start) restarts after RestartSec=5, the collection period: at
# most 5 starts in 60 s, then it stays failed, the start limit of the guest units (lab/hyptcn-lab@.service, KOSTRA
# B5 section 1; registered in scripts/host_periods.json). It never starts under a protocol of schema 3.
TRAFFIC_UNIT_PROPERTIES = ("Restart=on-failure", "RestartSec=5", "StartLimitBurst=5", "StartLimitIntervalSec=60")
SCHEMA_3 = "hyptcn3/collection-protocol/3"
OLD_GENERATOR_UNDER_V5 = ("the old traffic generator unit (closed loop, restarted every 5 s) does not run under a "
                          "protocol of schema 3: the session runs the v5 generator (scripts/collection.py run)")
# Read-back of memory.swap.max after the scope job: 20 tries 0.25 s apart (executor's judgment, B5a).
SWAP_TRIES, SWAP_PAUSE_S = 20, .25
# Way 1 of the QEMU swap ban (KOSTRA B5, addendum 20:50Z; dokazy/B5/skuska_swapu.md): the session daemon of libvirt
# runs in this transient unit of the user's systemd manager, so every QEMU it starts inherits the unit's cgroup
# without swap (libvirt manages no cgroup under qemu:///session). KillMode=process: stopping the daemon leaves the
# QEMU of running domains alive in the unit (the default control-group kills them, reported only as "Stopped").
DAEMON_UNIT = "hyptcn-libvirtd"
DAEMON_SERVICE = DAEMON_UNIT + ".service"
SESSION_URI = "qemu:///session"
# The command line libvirt itself gives a session daemon it starts on demand: it quits 120 s after its last
# running domain and client.
LIBVIRTD = ("/usr/sbin/libvirtd", "--timeout=120")
# Way 2 moves QEMU into a scope of this name; way 1's unit and these scopes are the cgroups labctl makes for QEMU.
QEMU_SCOPES = "hyptcn-qemu-*.scope"
# The old daemon's exit after SIGTERM, and the new daemon's socket: 120 tries 0.25 s apart, 30 s each (judgment, B5a).
DAEMON_TRIES, DAEMON_PAUSE_S = 120, .25
# systemctl --user and systemd-run --user of the daemon unit, and virsh list: 60 s each (judgment, B5a).
UNIT_TIMEOUT_S = 60
# labctl stop (package B9: a group starts with a new QEMU process, proposal 5.4): after virsh shutdown the domain's
# state is read every STOP_PAUSE_S until it is shut off and its QEMU process has exited, at most STOP_TIMEOUT_S
# (judgment: the bound and the pause of the reboot wait, Lab.reboot).
STOP_TIMEOUT_S, STOP_PAUSE_S = 180, 2
# Finding F4 of B5a (dokazy/B5/odlozene_B5a.md): way 2 is temporary, the record of every start says so.
TEMPORARY = ("way 2 moved the QEMU process, not its memory: the pages it touched before the move stay charged to the "
             "cgroup it ran in before, whose swap policy still applies to them (finding F4 of B5a); a group starts "
             "through way 1: the VM shut off and the session daemon in its unit")


def run(args, **kw):
    return subprocess.run([str(a) for a in args], check=True, text=True, **kw)


def qemu_pid(domain):
    """PID of the domain's QEMU process, found as scripts/collection.py qemu_process finds it; None if none runs."""
    marker = f"guest={domain},".encode()
    found = []
    for entry in PROC.glob("[0-9]*"):
        try:
            argv = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if argv.startswith(b"/usr/bin/qemu-system") and marker in argv:
            found.append(int(entry.name))
    if len(found) > 1:
        raise RuntimeError(f"several QEMU processes run domain {domain}: {sorted(found)}")
    return found[0] if found else None


def swap_max(pid):
    """(cgroup v2 path, text of its memory.swap.max) of the process; the text is None when the file is missing."""
    for line in (PROC / str(pid) / "cgroup").read_text().splitlines():
        hierarchy, _, path = line.split(":", 2)
        if hierarchy == "0":
            try:
                return path, (CGROUPS / path.lstrip("/") / "memory.swap.max").read_text().strip()
            except OSError:
                return path, None
    return None, None


def vm_swap_kb(pid):
    """VmSwap of the process in kB (/proc/<pid>/status, as scripts/collection.py qemu_swap_kb reads it); None when
    unreadable."""
    try:
        return int(re.search(r"^VmSwap:\s+(\d+) kB$", (PROC / str(pid) / "status").read_text(), re.M)[1])
    except (OSError, TypeError):
        return None


def kb_text(kb):
    return "unreadable" if kb is None else f"{kb} kB"


def in_user_unit(cgroup, unit):
    """True when the cgroup v2 path is a unit of this user's systemd manager whose name matches the glob `unit`."""
    return (f"/user@{os.getuid()}.service/" in (cgroup or "")
            and fnmatch.fnmatchcase(PurePosixPath(cgroup).name, unit))


def labctl_cgroup(cgroup):
    """True for the cgroups labctl makes for QEMU without swap: the daemon unit (way 1) and a hyptcn-qemu scope
    (way 2). A login session scope is none of them, whatever its memory.swap.max: it ends with the login."""
    return in_user_unit(cgroup, DAEMON_SERVICE) or in_user_unit(cgroup, QEMU_SCOPES)


def owner_command(domain, pid):
    """The owner's command when both ways failed: the system manager moves this QEMU into a scope of its own without
    swap. Never a property of a login session scope, which would bind everything that runs in the login (KOSTRA B5,
    addendum 20:50Z)."""
    return ("sudo busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "
            f'StartTransientUnit "ssa(sv)a(sa(sv))" hyptcn-qemu-{domain}-{pid}.scope fail 2 PIDs au 1 {pid} '
            "MemorySwapMax t 0 0")


def runtime_dir():
    """$XDG_RUNTIME_DIR/libvirt: the pid file and the socket of the session daemon."""
    if not os.environ.get("XDG_RUNTIME_DIR"):
        raise RuntimeError("XDG_RUNTIME_DIR is not set (libvirt's session daemon and systemd --user live there)")
    return Path(os.environ["XDG_RUNTIME_DIR"]) / "libvirt"


def is_daemon(pid):
    """True while process `pid` is a libvirtd of this user (its exe, its real and effective uid): the pid of a stale
    pid file may belong to another process by now, and labctl signals no process it has not identified."""
    try:
        exe = os.readlink(PROC / str(pid) / "exe")
        uid = re.search(r"^Uid:\s+(\d+)\s+(\d+)", (PROC / str(pid) / "status").read_text(), re.M)
    except OSError:
        return False  # Gone, or a zombie (it has no exe).
    return (PurePosixPath(exe.removesuffix(" (deleted)")).name == "libvirtd" and uid is not None
            and int(uid[1]) == int(uid[2]) == os.getuid())


def session_daemon():
    """(pid, cgroup v2 path, memory.swap.max there) of this user's libvirt session daemon, found by its pid file;
    (None, None, None) when the file is missing or names no libvirtd of this user."""
    try:
        pid = int((runtime_dir() / "libvirtd.pid").read_text().strip())
        if is_daemon(pid):
            return (pid, *swap_max(pid))
    except (OSError, ValueError):
        pass
    return None, None, None


def listening(path):
    """True when a process accepts connections on the unix socket `path`. A socket file left behind by a daemon
    that is gone refuses them, and virsh would then start a daemon of its own, outside the unit."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        try:
            probe.connect(str(path))
        except OSError:
            return False
    return True


def poll(ready, what):
    """Wait until ready() is true: DAEMON_TRIES tries DAEMON_PAUSE_S apart, else RuntimeError naming `what`."""
    for _ in range(DAEMON_TRIES):
        if ready():
            return
        time.sleep(DAEMON_PAUSE_S)
    raise RuntimeError(f"{what} after {DAEMON_TRIES * DAEMON_PAUSE_S:g} s")


def start_daemon_unit(done):
    """Run the session daemon in its unit; then wait until the daemon of the pid file runs there and accepts
    connections on its socket. The commands run are appended to `done`.

    The unit stays loaded, inactive, while processes of a stopped run remain in it (the QEMU of running domains,
    KillMode=process): then systemctl start runs the daemon again, and a second systemd-run of the name would fail
    ("already loaded"). Otherwise systemd-run creates it (skuska_swapu.md)."""
    state = run(["systemctl", "--user", "show", DAEMON_SERVICE, "-p", "LoadState", "--value"],
                capture_output=True, timeout=UNIT_TIMEOUT_S).stdout.strip()
    command = (["systemctl", "--user", "start", DAEMON_SERVICE] if state == "loaded" else
               ["systemd-run", "--user", "--unit", DAEMON_UNIT, "-p", "MemorySwapMax=0", "-p", "KillMode=process",
                *LIBVIRTD])
    run(command, capture_output=True, timeout=UNIT_TIMEOUT_S)
    done.append(" ".join(command))
    poll(lambda: in_user_unit(session_daemon()[1], DAEMON_SERVICE) and listening(runtime_dir() / "libvirt-sock"),
         f"no daemon of {DAEMON_SERVICE} accepts connections on its socket")


def stored_effect(effect):
    """The effect of an event's stop reply as the event record keeps it (KOSTRA B5, section 3): the guest's own
    when it is a dict with a boolean ok and evidence, otherwise a false one naming what came back, so the record
    never claims an effect the guest did not report."""
    if type(effect) is dict and type(effect.get("ok")) is bool and "evidence" in effect:
        return effect
    return {"ok": False, "predicate": None,
            "evidence": {"error": "stop reply without a well-formed effect (lab/udalosti.py older than B5?)",
                         "guest_effect": effect}}


# The class of a control's record (design B8, section 1.4): the control or its paired negative, by the polarity; the
# same mapping as scripts/protocol_v5.py CONTROL_RECORD_CLASS (labctl runs without the repository's modules).
CONTROL_CLASS = {"control": "control", "negative": "control_negative"}


def stored_baseline(baseline):
    """The return predicate of a control's start reply as the record keeps it (design B8, section 1.3): the guest's
    own when it is a dict with a boolean ok, an exact part with a boolean ok, a level part that says whether it was
    judged (and then with a boolean ok) and evidence, and ok is the exact part's and the judged level part's;
    otherwise a false one naming what came back, so the record never claims a return the guest did not report."""
    if type(baseline) is dict and type(baseline.get("ok")) is bool and "evidence" in baseline:
        exact, level = baseline.get("exact"), baseline.get("level")
        if (type(exact) is dict and type(exact.get("ok")) is bool and type(level) is dict
                and type(level.get("judged")) is bool and (not level["judged"] or type(level.get("ok")) is bool)
                and baseline["ok"] is (exact["ok"] and (not level["judged"] or level["ok"]))):
            return baseline
    return {"ok": False, "exact": None, "level": None,
            "evidence": {"error": "start reply without a well-formed baseline (lab/udalosti.py older than B8?)",
                         "guest_baseline": baseline}}


def stored_cleanup(cleanup):
    """The cleanup of a control's stop reply as the record keeps it (design B8, section 1.3): the guest's own when it
    is a dict with a boolean ok and evidence, otherwise a false one naming what came back."""
    if type(cleanup) is dict and type(cleanup.get("ok")) is bool and "evidence" in cleanup:
        return cleanup
    return {"ok": False,
            "evidence": {"error": "stop reply without a well-formed cleanup (lab/udalosti.py older than B8?)",
                         "guest_cleanup": cleanup}}


class Lab:
    def __init__(self, uri="qemu:///session", domain="hyptcn-lab", vm=None, port=PORT):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,50}", domain):
            raise ValueError("Invalid lab domain name")
        if vm is not None and not re.fullmatch(VM_NAME, vm):
            raise ValueError("Invalid lab VM name")
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("Invalid host forward port")
        self.uri, self.domain, self.vm, self.port = uri, domain, vm, port
        self.swap_error = None  # Why qemu_swap_off() failed in this command (swap_step); main() ends with it.

    # Without a VM name (one lab VM) the original names stay; a named VM of a
    # multi-VM protocol has its own state file, traffic unit and status file.
    @property
    def state_file(self):
        return STATE if self.vm is None else STATE.with_name(f"lab-state-{self.vm}.json")

    @property
    def unit(self):
        return UNIT if self.vm is None else f"{UNIT}-{self.vm}"

    @property
    def traffic_status(self):
        return REPO / "data/lab" / ("traffic.json" if self.vm is None else f"traffic-{self.vm}.json")

    def virsh(self, *args, timeout=30):
        return run(["virsh", "-c", self.uri, *args], capture_output=True, timeout=timeout).stdout.strip()

    def agent(self, command, arguments=None):
        """One guest-agent command with AGENT_TIMEOUT_S (virsh defaults to 5 s).

        Campaign normal-v4-20261115 lost session 10_b: guest-file-read missed the
        5 s default while the host was reading swap for the other VM. Commands
        without side effects (AGENT_IDEMPOTENT) are retried; a read or write on
        a file handle is not, because the guest may have advanced the handle.
        """
        req = {"execute": command}
        if arguments is not None:
            req["arguments"] = arguments
        attempts = AGENT_RETRIES + 1 if command in AGENT_IDEMPOTENT else 1
        for attempt in range(attempts):
            try:
                reply = json.loads(self.virsh("qemu-agent-command", "--timeout", str(AGENT_TIMEOUT_S),
                                              self.domain, json.dumps(req), timeout=AGENT_TIMEOUT_S + 30))
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if attempt + 1 == attempts:
                    raise
                time.sleep(2)
        if "error" in reply:
            raise RuntimeError(str(reply["error"]))
        return reply["return"]

    def guest(self, command, timeout=120):
        pid = self.agent("guest-exec", {"path": "/bin/bash", "arg": ["-lc", command],
                                       "capture-output": True})["pid"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            reply = self.agent("guest-exec-status", {"pid": pid})
            if reply.get("exited"):
                out = base64.b64decode(reply.get("out-data", "")).decode(errors="replace")
                err = base64.b64decode(reply.get("err-data", "")).decode(errors="replace")
                if reply.get("exitcode", 1) != 0:
                    raise RuntimeError(f"Guest command failed: {command}\n{out}\n{err}")
                return out
            time.sleep(0.3)
        raise TimeoutError(f"Guest command did not complete: {command}")

    def upload(self, data, path):
        fd = self.agent("guest-file-open", {"path": path, "mode": "wb"})
        try:
            for start in range(0, len(data), 32768):
                chunk = data[start:start + 32768]
                result = self.agent("guest-file-write", {
                    "handle": fd, "buf-b64": base64.b64encode(chunk).decode()})
                if result["count"] != len(chunk):
                    raise RuntimeError("Incomplete guest upload")
        finally:
            self.agent("guest-file-close", {"handle": fd})

    def download(self, path, target):
        """Copy one guest file over the agent channel; the caller verifies hashes."""
        handle = self.agent("guest-file-open", {"path": path, "mode": "r"})
        digest = hashlib.sha256()
        try:
            with open(target, "xb") as out:
                while True:
                    reply = self.agent("guest-file-read", {"handle": handle, "count": 1 << 20})
                    data = base64.b64decode(reply.get("buf-b64", ""))
                    out.write(data)
                    digest.update(data)
                    if reply.get("eof") or not data:
                        break
                out.flush()
                os.fsync(out.fileno())
        finally:
            self.agent("guest-file-close", {"handle": handle})
        return digest.hexdigest()

    def helper(self, *args, timeout=600):
        """Run the deployed guest evidence helper and parse its JSON reply."""
        return json.loads(self.guest("python3 /opt/hyptcn-lab/guest_state.py "
                                     + " ".join(shlex.quote(str(a)) for a in args), timeout=timeout))

    def event(self, action, kind, timeout=180, *, polarity=None, dose=None, levels=None, tolerance=None):
        """Start or stop one benign operational event or control (lab/udalosti.py) and parse its JSON reply.

        The guest evaluates the effect predicate in stop, before it restores the lab; the stop record keeps
        that effect (stored_effect), the log audit refuses an event whose effect is not ok.

        A control (package B8; a polarity is given) runs with the guest's command line of design B8 1.3: its polarity,
        its dose for a kind of class B, and at the start the session's starting levels (`levels`, the object
        guest_state.py levels printed) and the protocol's tolerance (controls.baseline, null until G2). The reply
        keeps the guest's return predicate of the start (stored_baseline), the effect and the cleanup of the stop
        (stored_effect, stored_cleanup), and names the occurrence at its top: kind, polarity, dose and class, control
        or control_negative (design B8 1.4)."""
        command = ["python3", "/opt/hyptcn-lab/udalosti.py", action, kind]
        if polarity is not None:
            command += ["--polarity", polarity, *(["--dose", dose] if dose is not None else [])]
            if action == "start":
                command += ["--levels", json.dumps(levels, sort_keys=True), "--tolerance", json.dumps(tolerance)]
        reply = json.loads(self.guest(" ".join(shlex.quote(str(part)) for part in command), timeout=timeout))
        if polarity is None:
            if action == "stop":
                reply["effect"] = stored_effect(reply.get("effect"))
            return reply
        if action == "start":
            reply["baseline"] = stored_baseline(reply.get("baseline"))
        elif action == "stop":
            reply["effect"] = stored_effect(reply.get("effect"))
            reply["cleanup"] = stored_cleanup(reply.get("cleanup"))
        reply.update(kind=kind, polarity=polarity, dose=dose, **{"class": CONTROL_CLASS[polarity]})
        return reply

    def fetch_segment(self, doc, dest):
        """Fetch gzip copies, verify transfer and content hashes, then delete them in the guest."""
        dest = Path(dest)
        files = []
        for item in doc["files"]:
            target = dest / (item["name"] + ".gz")
            if self.download(item["gz_path"], target) != item["gz_sha256"] or target.stat().st_size != item["gz_bytes"]:
                raise RuntimeError("guest segment transfer checksum mismatch: " + item["name"])
            digest, size, lines = hashlib.sha256(), 0, 0
            with gzip.open(target, "rb") as stream:
                for line in stream:
                    digest.update(line)
                    size += len(line)
                    lines += 1
            if (digest.hexdigest(), size, lines) != (item["sha256"], item["bytes"], item["lines"]):
                raise RuntimeError("guest segment content mismatch: " + item["name"])
            files.append({**{k: v for k, v in item.items() if k != "gz_path"}, "file": target.name,
                          "file_sha256": item["gz_sha256"]})
        self.helper("cleanup", doc["label"])
        return {**{k: v for k, v in doc.items() if k != "files"}, "files": files}

    def clock(self):
        """Host/guest wall-clock offset from one agent round trip."""
        before = time.time()
        guest_ns = self.agent("guest-get-time")
        after = time.time()
        return {"host_before_unix": before, "host_after_unix": after, "guest_unix": guest_ns / 1e9,
                "offset_s": guest_ns / 1e9 - (before + after) / 2, "uncertainty_s": (after - before) / 2}

    def wait(self):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                self.agent("guest-ping")
                return
            except (subprocess.CalledProcessError, RuntimeError):
                time.sleep(2)
        raise TimeoutError("Guest agent is unavailable after boot")

    def clone(self, source):
        if self.domain in self.virsh("list", "--all", "--name").splitlines():
            self.owned()
            return
        if source == self.domain:
            raise ValueError("Source and lab must be different domains")
        if self.virsh("domstate", source) != "shut off":
            raise RuntimeError(f"Source {source} must be shut off before cloning")
        xml = ET.fromstring(self.virsh("dumpxml", source))
        disk = xml.find("./devices/disk[@device='disk']/source").attrib["file"]
        target = REPO / "vms" / f"{self.domain}.qcow2"
        target.parent.mkdir(exist_ok=True)
        if target.exists():
            raise RuntimeError(f"Unmanaged disk already exists: {target}")
        staging = target.with_suffix(".partial.qcow2")
        if staging.exists():
            raise RuntimeError(f"Incomplete clone exists; inspect first: {staging}")
        if self.vm is not None and shutil.which("guestfish") is None:
            raise RuntimeError("guestfish (libguestfs) is required to give a further VM its own identity")
        print(f"Cloning stopped {source} into {target}", flush=True)
        run(["qemu-img", "convert", "-O", "qcow2", disk, staging])
        if self.vm is not None:
            size = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", str(staging)],
                                                      text=True))["virtual-size"]
            if size > DISK_GIB << 30:
                raise RuntimeError(f"Source disk is larger than {DISK_GIB} GiB; refusing to shrink")
            run(["qemu-img", "resize", staging, f"{DISK_GIB}G"])
            print(json.dumps({"domain": self.domain, "machine_id": self.fresh_identity(staging)}), flush=True)
        staging.rename(target)
        domain = ET.Element("domain", type="kvm")
        ET.SubElement(domain, "name").text = self.domain
        ET.SubElement(domain, "description").text = "hyptcn3 benign persistent lab"
        ET.SubElement(domain, "uuid").text = str(uuid.uuid4())
        ET.SubElement(domain, "memory", unit="MiB").text = "2048"
        ET.SubElement(domain, "vcpu").text = "2"
        guest_os = ET.SubElement(domain, "os")
        ET.SubElement(guest_os, "type", arch="x86_64", machine="q35").text = "hvm"
        ET.SubElement(guest_os, "boot", dev="hd")
        ET.SubElement(ET.SubElement(domain, "features"), "acpi")
        ET.SubElement(domain, "cpu", mode="host-passthrough")
        devices = ET.SubElement(domain, "devices")
        drive = ET.SubElement(devices, "disk", type="file", device="disk")
        ET.SubElement(drive, "driver", name="qemu", type="qcow2")
        ET.SubElement(drive, "source", file=str(target))
        ET.SubElement(drive, "target", dev="vda", bus="virtio")
        nic = ET.SubElement(devices, "interface", type="user")
        ET.SubElement(nic, "backend", type="passt")
        ET.SubElement(nic, "model", type="virtio")
        forward = ET.SubElement(nic, "portForward", proto="tcp", address="127.0.0.1")
        ET.SubElement(forward, "range", start=str(self.port), to="8080")
        channel = ET.SubElement(devices, "channel", type="unix")
        ET.SubElement(channel, "target", type="virtio", name="org.qemu.guest_agent.0")
        serial = ET.SubElement(devices, "serial", type="pty")
        ET.SubElement(serial, "target", port="0")
        definition = target.with_suffix(".xml")
        ET.indent(domain)
        definition.write_text(ET.tostring(domain, encoding="unicode") + "\n")
        self.virsh("define", str(definition))

    def fresh_identity(self, image):
        """Offline, before the first boot: clones of one image must differ in machine-id and hostname.

        No root: guestfish runs its own appliance as the calling user. The image
        is still the staging file, so a failure leaves no usable half-made disk.
        """
        machine_id = uuid.uuid4().hex
        run(["guestfish", "--rw", "--format=qcow2", "-a", image, "-i",
             "write", "/etc/machine-id", machine_id + "\n", ":",
             "write", "/etc/hostname", self.domain + "\n"],
            env={**os.environ, "LIBGUESTFS_BACKEND": "direct"})
        return machine_id

    def owned(self):
        xml = ET.fromstring(self.virsh("dumpxml", self.domain))
        if xml.findtext("description") != "hyptcn3 benign persistent lab":
            raise RuntimeError("Refusing to modify a domain not created by labctl")
        # A wrong --port would reach another VM's stack and report it as this one.
        forward = xml.find("./devices/interface/portForward/range")
        if forward is None or forward.get("start") != str(self.port):
            raise RuntimeError(f"Domain {self.domain} does not forward host port {self.port}")

    def reboot(self, timeout=180):
        self.owned()
        before = self.guest("cat /proc/sys/kernel/random/boot_id").strip()
        self.virsh("reboot", self.domain, "--mode", "agent")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                after = self.guest("cat /proc/sys/kernel/random/boot_id", timeout=10).strip()
                if after and after != before:
                    self.health()
                    print(json.dumps({"previous_boot": before, "boot_id": after}))
                    return
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
            time.sleep(2)
        raise TimeoutError("Guest did not become healthy on a new boot")

    def stop(self):
        """Shut the VM down and wait until it is shut off and its QEMU process has exited (package B9: each group
        starts with a new QEMU process, proposal 5.4; the start that follows is way 1). A VM already shut off stays
        so. Prints and returns {domain, state_before, qemu_pid_before, state, seconds}; RuntimeError when the domain
        is not shut off, or its QEMU still runs, STOP_TIMEOUT_S after virsh shutdown."""
        self.owned()
        before, pid, started = self.virsh("domstate", self.domain), qemu_pid(self.domain), time.monotonic()
        if before != "shut off":
            self.virsh("shutdown", self.domain)
            while True:
                state, running = self.virsh("domstate", self.domain), qemu_pid(self.domain)
                if state == "shut off" and running is None:
                    break
                if time.monotonic() - started >= STOP_TIMEOUT_S:
                    raise RuntimeError(f"domain {self.domain} is {state!r}" + (f" and its QEMU {running} runs"
                                                                             if running else "")
                                       + f" {STOP_TIMEOUT_S} s after virsh shutdown")
                time.sleep(STOP_PAUSE_S)
        record = {"domain": self.domain, "state_before": before, "qemu_pid_before": pid, "state": "shut off",
                  "seconds": round(time.monotonic() - started, 3)}
        print(json.dumps({"stop": record}, sort_keys=True), flush=True)
        return record

    def start(self):
        """Start the VM when it is shut off, through way 1 (daemon_step right before virsh start): the new QEMU process
        inherits the daemon unit's cgroup (package B9: a group starts with stop, then start). A running VM keeps its
        QEMU. main() runs the swap step after every start; its record, printed last, names the QEMU's pid, cgroup and
        way (qemu_swap_off), which the campaign records."""
        self.owned()
        if self.virsh("domstate", self.domain) == "shut off":
            self.daemon_step()  # Way 1 of the swap ban: the daemon that starts this QEMU runs in a unit without swap.
            self.virsh("start", self.domain)
        self.wait()
        # passt provides DHCP and forwards only the local development port.
        self.guest("if [ ! -f /var/lib/hyptcn-lab-network-v3 ]; then "
                   "hostnamectl set-hostname " + shlex.quote(self.domain) + "; "
                   "printf '[Match]\\nName=en* eth*\\n[Network]\\nDHCP=ipv4\\n[DHCPv4]\\nClientIdentifier=mac\\n' "
                   "> /etc/systemd/network/00-hyptcn-lab.network; "
                   "networkctl reload && networkctl reconfigure enp1s0 && "
                   "touch /var/lib/hyptcn-lab-network-v3; fi")
        if self.vm is not None:
            root = int(self.guest(GROW_ROOT).split()[-1])
            # ext4 metadata and the boot partitions take a few percent of the disk.
            if root < 0.9 * (DISK_GIB << 30):
                raise RuntimeError(f"Guest root file system has {root} B, expected about {DISK_GIB} GiB")

    def daemon_step(self):
        """Way 1 of the swap ban, before every virsh start of a lab VM (KOSTRA B5, addendum 20:50Z): the session
        daemon of libvirt runs in DAEMON_SERVICE (MemorySwapMax=0, KillMode=process), so the QEMU it starts
        inherits a cgroup without swap.

        A daemon in the unit is left as it is. Without a daemon the unit is started. A daemon outside the unit is
        replaced (SIGTERM to its exact pid, its exit awaited, then the unit) only while no domain runs, at the start
        of a group; while one runs it stays, and the new QEMU goes through way 2 (qemu_swap_off). The record of what
        was found and done is printed (qemu_way: "unit" when the daemon now runs in the unit without swap, else
        "scope"). A failure is recorded, not raised: way 2 and the check follow after the start, and only both ways
        failing ends the command with the owner's command."""
        record = {"unit": DAEMON_SERVICE, "found": None, "daemon_pid_before": None, "cgroup_before": None, "done": []}
        try:
            pid, cgroup, _ = session_daemon()
            record.update(daemon_pid_before=pid, cgroup_before=cgroup)
            if pid is None:
                record["found"] = "none"
                start_daemon_unit(record["done"])
            elif in_user_unit(cgroup, DAEMON_SERVICE):
                record["found"] = "unit"
            else:
                record["found"] = "outside"
                record["running_domains"] = run(["virsh", "-c", SESSION_URI, "list", "--state-running", "--name"],
                                                capture_output=True, timeout=UNIT_TIMEOUT_S).stdout.split()
                if not record["running_domains"]:
                    os.kill(pid, signal.SIGTERM)
                    record["done"].append(f"SIGTERM {pid}")
                    poll(lambda: not is_daemon(pid), f"libvirtd {pid} has not exited")
                    start_daemon_unit(record["done"])
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            stderr = (getattr(error, "stderr", None) or "").strip()
            record["error"] = (f"{error}: {stderr}" if stderr else str(error))[:500]
        try:
            pid, cgroup, value = session_daemon()
        except RuntimeError:  # No XDG_RUNTIME_DIR: the error above says so.
            pid = cgroup = value = None
        way = "unit" if "error" not in record and in_user_unit(cgroup, DAEMON_SERVICE) and value == "0" else "scope"
        record.update(daemon_pid=pid, cgroup=cgroup, memory_swap_max=value, qemu_way=way)
        print(json.dumps({"libvirtd": record}, sort_keys=True), flush=True)
        return record

    def qemu_swap_off(self):
        """Way 2 of the swap ban and the check, right after every start of the VM (KOSTRA B5, addendum 20:50Z;
        proposal 6.2: run_session refuses a start unless memory.swap.max is 0 and VmSwap 0 kB). Campaigns v4 and
        v4c lost slots to a swapped QEMU.

        QEMU stays where it is only in a cgroup labctl made (labctl_cgroup: the daemon unit of way 1 or a
        hyptcn-qemu scope) whose memory.swap.max is 0. Anywhere else, a login session scope with 0 included, it is
        moved into a transient scope of the user's systemd manager with MemorySwapMax=0 (StartTransientUnit with
        PIDs, no root needed: skuska_swapu.md) and read back there. Then memory.swap.max must be 0 and VmSwap 0 kB,
        else RuntimeError with both values: a process moved late may keep pages swapped out before the move. A
        failed move (both ways failed) names the owner's command.

        The record names the QEMU's pid and cgroup and the way that holds it (package B9): "unit" in the daemon's
        unit (way 1), "scope" in a hyptcn-qemu scope, moved now or by an earlier start (way 2). Way 2 is temporary
        (finding F4 of B5a): temporary is true and the note says why."""
        pid = qemu_pid(self.domain)
        if pid is None:
            raise RuntimeError(f"QEMU process of domain {self.domain} not found")
        cgroup, value = swap_max(pid)
        record = {"domain": self.domain, "qemu_pid": pid, "cgroup_before": cgroup, "swap_max_before": value}
        scope = None
        if not (value == "0" and labctl_cgroup(cgroup)):
            scope = f"hyptcn-qemu-{self.domain}-{pid}.scope"
            reply = subprocess.run(
                ["busctl", "--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                 "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))", scope, "fail", "3",
                 "PIDs", "au", "1", str(pid), "MemorySwapMax", "t", "0",
                 "Description", "s", f"hyptcn3 QEMU of {self.domain} without swap", "0"],
                capture_output=True, text=True, timeout=30)
            if reply.returncode != 0:
                raise RuntimeError(f"cannot move QEMU {pid} of {self.domain} (memory.swap.max {value!r} in {cgroup}, "
                                   f"VmSwap {kb_text(vm_swap_kb(pid))}) into {scope} with MemorySwapMax=0: "
                                   f"{reply.stderr.strip()[:300]}; the owner can run: "
                                   + owner_command(self.domain, pid))
            for _ in range(SWAP_TRIES):
                cgroup, value = swap_max(pid)
                if value == "0" and in_user_unit(cgroup, scope):
                    break
                time.sleep(SWAP_PAUSE_S)
            else:
                missing = " (no memory.swap.max: the memory controller is not enabled there)" if value is None else ""
                raise RuntimeError(f"memory.swap.max of QEMU {pid} ({self.domain}) is {value!r} in {cgroup}{missing} "
                                   f"after the move into {scope}, VmSwap {kb_text(vm_swap_kb(pid))}; the owner can "
                                   f"run: {owner_command(self.domain, pid)}")
        kb = vm_swap_kb(pid)
        if kb != 0:
            raise RuntimeError(f"QEMU {pid} ({self.domain}) has VmSwap {kb_text(kb)} with memory.swap.max {value!r} in "
                               f"{cgroup}: pages swapped out before its cgroup forbade swap stay in swap until QEMU "
                               "touches them; a VM started again begins without them")
        way = "unit" if in_user_unit(cgroup, DAEMON_SERVICE) else "scope"
        return {**record, "scope": scope, "cgroup": cgroup, "memory_swap_max": value, "vm_swap_kb": kb, "way": way,
                "temporary": way == "scope", **({"note": TEMPORARY} if way == "scope" else {})}

    def swap_step(self):
        """qemu_swap_off() as a step right after every start of the VM: its record is printed. A failure ends the
        command with an error (main), but only after the command's other steps: a lab deployed with swap is still
        usable outside a collection (the lab test on the VM), and run_session refuses to collect from a QEMU whose
        memory.swap.max is not 0 or whose VmSwap is not 0 kB, so the failure stays loud without blocking what needs
        no collection."""
        try:
            record = self.qemu_swap_off()
        except RuntimeError as error:
            self.swap_error = str(error)
            record = {"domain": self.domain, "memory_swap_max": None, "error": self.swap_error}
        print(json.dumps({"qemu_swap": record}, sort_keys=True), flush=True)
        return record

    def target(self):
        return f"http://127.0.0.1:{self.port}"

    def deploy(self):
        self.owned()
        self.start()
        self.swap_step()
        # Guest NAT may be unavailable on the development host. Transfer the
        # one extra Debian driver over the serial guest-agent channel instead.
        present = self.guest("python3 -c 'import psycopg2' >/dev/null 2>&1 && echo yes || echo no").strip()
        if present == "no":
            metadata = json.loads((REPO / "lab/dependencies.json").read_text())
            package = metadata["python3-psycopg2"]
            path = REPO / "vms" / package["filename"]
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != package["sha256"]:
                with urllib.request.urlopen(package["url"], timeout=60) as reply:
                    data = reply.read()
                if hashlib.sha256(data).hexdigest() != package["sha256"]:
                    raise RuntimeError("Debian driver checksum mismatch")
                path.write_bytes(data)
            self.upload(path.read_bytes(), "/tmp/hyptcn-psycopg2.deb")
            print(self.guest("dpkg -i /tmp/hyptcn-psycopg2.deb"), end="")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for path in sorted((REPO / "lab").iterdir()):
                if path.is_file():
                    archive.add(path, arcname=path.name)
        self.upload(buffer.getvalue(), "/tmp/hyptcn-lab.tar.gz")
        print(self.guest("install -d /opt/hyptcn-lab && "
                         "tar xzf /tmp/hyptcn-lab.tar.gz -C /opt/hyptcn-lab && "
                         "bash /opt/hyptcn-lab/install.sh", timeout=600), end="")

    def health(self):
        target = self.target()
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(target + "/healthz", timeout=5) as reply:
                    health = json.load(reply)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        state = {"uri": self.uri, "domain": self.domain, "target": target, "health": health,
                 **({} if self.vm is None else {"vm": self.vm})}
        self.state_file.parent.mkdir(exist_ok=True)
        self.state_file.write_text(json.dumps(state, indent=2) + "\n")
        print(json.dumps(state, indent=2))
        return target

    def traffic(self):
        """The old closed-loop generator as a user unit (protocols of schemas 1 and 2, `make lab-up`), with the start
        limit of TRAFFIC_UNIT_PROPERTIES; main() refuses it under a protocol of schema 3, and scripts/collection.py
        stops it before every session."""
        target = self.health()
        running = subprocess.run(["systemctl", "--user", "is-active", "--quiet", self.unit]).returncode == 0
        if running:
            print(f"{self.unit} is already running")
            return
        out = self.traffic_status
        out.parent.mkdir(parents=True, exist_ok=True)
        run(["systemd-run", "--user", f"--unit={self.unit}", "--collect",
             *(f"--property={value}" for value in TRAFFIC_UNIT_PROPERTIES),
             f"--working-directory={REPO}", sys.executable, REPO / "scripts/host_traffic.py",
             "--profile", "lab", "--target", target, "--dur", "0", "--vlakien", "4",
             "--out", out])


def control_options(parser, args):
    """The options of `event` for a control (package B8, design B8 1.3) as keyword arguments of Lab.event, {} for an
    event; a usage error (parser.error) for options that do not belong together: --dose, --levels and --tolerance
    only with --polarity, --levels and --tolerance only and always at the start of a control, --levels a JSON object
    and --tolerance JSON null or an object, --dose a positive number."""
    given = [name for name in ("dose", "levels", "tolerance") if getattr(args, name) is not None]
    if args.polarity is None:
        if given:
            parser.error("--dose, --levels and --tolerance belong to the event of a control (--polarity)")
        return {}
    start = args.event[0] == "start"
    if start != (args.levels is not None) or start != (args.tolerance is not None):
        parser.error("--levels and --tolerance belong to the start of a control, and it needs both")
    if args.dose is not None and args.dose < 1:
        parser.error("--dose is a positive number")
    options = {"polarity": args.polarity, "dose": args.dose}
    if start:
        try:
            levels, tolerance = json.loads(args.levels), json.loads(args.tolerance)
        except ValueError as error:
            parser.error(f"--levels and --tolerance are JSON: {error}")
        if type(levels) is not dict or not (tolerance is None or type(tolerance) is dict):
            parser.error("--levels is a JSON object (guest_state.py levels) and --tolerance null or an object")
        options.update(levels=levels, tolerance=tolerance)
    return options


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["up", "create", "clone", "start", "deploy", "status", "stop", "reboot",
                                            "traffic-start", "traffic-stop", "exec", "logs", "state", "levels",
                                            "reset", "pretouch", "clock", "sync-clock", "segment", "journal",
                                            "event"])
    parser.add_argument("--domain", default="hyptcn-lab")
    parser.add_argument("--vm", help="VM name of a multi-VM protocol (own state file, traffic unit and port); "
                                     "clone: the new disk gets a fresh machine-id and hostname before its first boot")
    parser.add_argument("--port", type=int, help="Host port forwarded to the guest's 8080 (required with --vm)")
    parser.add_argument("--uri", default="qemu:///session")
    parser.add_argument("--source", default="hyptcn-guest")
    parser.add_argument("--guest-command", help="Command for exec, executed inside the lab VM")
    parser.add_argument("--label", help="segment/journal: exclusive guest segment label")
    parser.add_argument("--dest", type=Path, help="segment/journal: existing host directory for verified copies")
    parser.add_argument("--event", nargs=2, metavar=("ACTION", "TYPE"),
                        help="event: start|stop and event type or control kind")
    parser.add_argument("--polarity", choices=("control", "negative"),
                        help="event of a control kind (lab/udalosti.py CONTROLS, package B8): the control or its "
                             "paired negative")
    parser.add_argument("--dose", type=int, help="event of a control of class B: its dose")
    parser.add_argument("--levels", help="start of a control: the session's starting levels, the JSON object "
                                         "guest_state.py levels printed")
    parser.add_argument("--tolerance", help="start of a control: controls.baseline of the protocol as JSON (null "
                                            "until G2)")
    parser.add_argument("--seed", type=int, help="reset (required there, refused elsewhere): the seed of the "
                                                 "protocol's seeded level (protocol_v5.reset_seed), 0 to 10**18 - 1, "
                                                 "the 18 digits lab/guest_state.py reset --seed takes")
    parser.add_argument("--since", type=float, help="journal: start, Unix seconds")
    parser.add_argument("--until", type=float, help="journal: end, Unix seconds")
    parser.add_argument("--protocol", type=Path,
                        help="up/traffic-start (required): the protocol the lab serves, of schema 1 or 2; under schema "
                             "3 the old traffic unit is refused before any step")
    args = parser.parse_args(argv)
    if args.domain == args.source:
        parser.error("Lab domain must be different from the experiment source")
    if (args.vm is None) != (args.port is None):
        parser.error("--vm and --port belong together")
    if args.command == "clone" and args.vm is None:
        parser.error("clone creates a further VM and requires --vm and --port")
    if (args.command == "reset") != (args.seed is not None):
        parser.error("reset requires --seed (the seed of the protocol's seeded level, protocol_v5.reset_seed)"
                     if args.command == "reset" else "--seed belongs to reset")
    if args.seed is not None and not 0 <= args.seed < 10 ** 18:
        parser.error("--seed is an integer from 0 to 10**18 - 1 (18 digits, lab/guest_state.py reset --seed)")
    if args.command in ("up", "traffic-start"):
        # Finding F5 of the B5b verification: without the protocol the old generator unit would start under v5 too.
        if args.protocol is None:
            parser.error(args.command + " requires --protocol (the protocol the lab serves)")
        try:
            protocol = json.loads(args.protocol.read_text())
        except (OSError, ValueError) as error:
            parser.error(f"cannot read --protocol: {error}")
        if type(protocol) is dict and protocol.get("schema") == SCHEMA_3:
            raise RuntimeError(OLD_GENERATOR_UNDER_V5)
    control = control_options(parser, args) if args.command == "event" and args.event else {}
    try:
        lab = Lab(args.uri, args.domain, args.vm, PORT if args.port is None else args.port)
    except ValueError as error:
        parser.error(str(error))
    unit = lab.unit
    if args.command in ("up", "create", "clone"):
        lab.clone(args.source)
    if args.command == "clone":
        # Not started here: the first boot must already see the new identity.
        print(f"Defined {lab.domain}; next: labctl.py up --domain {lab.domain} --vm {lab.vm} --port {lab.port}")
    if args.command in ("up", "start", "create"):
        lab.start()
        lab.swap_step()
    if args.command in ("up", "deploy"):
        lab.deploy()
        lab.health()
    if args.command in ("up", "traffic-start"):
        lab.traffic()
    if args.command == "status":
        state = lab.virsh("domstate", lab.domain)
        print(state)
        if state == "running":
            lab.health()
        loaded = subprocess.check_output(["systemctl", "--user", "show", unit, "-p", "LoadState", "--value"], text=True).strip()
        if loaded != "not-found":
            subprocess.run(["systemctl", "--user", "status", unit, "--no-pager"])
    if args.command in ("stop", "traffic-stop"):
        loaded = subprocess.check_output(["systemctl", "--user", "show", unit, "-p", "LoadState", "--value"], text=True).strip()
        if loaded != "not-found":
            subprocess.run(["systemctl", "--user", "stop", unit], check=True)
    if args.command == "reboot":
        lab.reboot()
    if args.command == "stop":  # Waits until the VM is shut off (package B9; Lab.stop).
        lab.stop()
    if args.command == "exec":
        lab.owned()
        if not args.guest_command:
            parser.error("exec requires --guest-command")
        print(lab.guest(args.guest_command), end="")
    if args.command == "logs":
        print(lab.guest("journalctl -u 'hyptcn-*' -n 60 --no-pager"), end="")
    if args.command == "state":
        lab.owned()
        print(json.dumps(lab.helper("state"), sort_keys=True))
    if args.command == "levels":  # The level values at the start of a session (proposal 5.4; package B8).
        lab.owned()
        print(json.dumps(lab.helper("levels"), sort_keys=True))
    # The start of a group (proposal 5.4, package B9): the database and the documents at the protocol's seeded level,
    # then one process touches the memory of the largest event; each prints the JSON guest_state.py prints.
    if args.command == "reset":
        lab.owned()
        print(json.dumps(lab.helper("reset", "--seed", args.seed), sort_keys=True))
    if args.command == "pretouch":
        lab.owned()
        print(json.dumps(lab.helper("pretouch"), sort_keys=True))
    if args.command == "clock":
        print(json.dumps(lab.clock()))
    if args.command == "sync-clock":
        lab.owned()
        before = lab.clock()
        lab.virsh("domtime", lab.domain, "--sync")
        print(json.dumps({"before": before, "after": lab.clock()}))
    if args.command == "event":
        lab.owned()
        if not args.event:
            parser.error("event requires --event ACTION TYPE")
        print(json.dumps(lab.event(*args.event, **control), sort_keys=True))
    if args.command in ("segment", "journal"):
        lab.owned()
        if not args.label or not args.dest or not args.dest.is_dir():
            parser.error(args.command + " requires --label and an existing --dest directory")
        if args.command == "segment":
            doc = lab.helper("segment", args.label)
        else:
            if args.since is None or args.until is None:
                parser.error("journal requires --since and --until")
            doc = lab.helper("journal", args.label, args.since, args.until)
        print(json.dumps(lab.fetch_segment(doc, args.dest), sort_keys=True))
    if lab.swap_error:
        raise RuntimeError("QEMU swap is not disabled: " + lab.swap_error)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"labctl: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
