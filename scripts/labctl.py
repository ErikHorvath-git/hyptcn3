#!/usr/bin/env python3
"""Host-side lifecycle for the benign server VM; no host root required."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import shlex
import re
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


def run(args, **kw):
    return subprocess.run([str(a) for a in args], check=True, text=True, **kw)


class Lab:
    def __init__(self, uri="qemu:///session", domain="hyptcn-lab"):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,50}", domain):
            raise ValueError("Invalid lab domain name")
        self.uri, self.domain = uri, domain

    def virsh(self, *args):
        return run(["virsh", "-c", self.uri, *args], capture_output=True).stdout.strip()

    def agent(self, command, arguments=None):
        req = {"execute": command}
        if arguments is not None:
            req["arguments"] = arguments
        reply = json.loads(self.virsh("qemu-agent-command", self.domain, json.dumps(req)))
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
        print(f"Cloning stopped {source} into {target}", flush=True)
        run(["qemu-img", "convert", "-O", "qcow2", disk, staging])
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
        ET.SubElement(forward, "range", start="18080", to="8080")
        channel = ET.SubElement(devices, "channel", type="unix")
        ET.SubElement(channel, "target", type="virtio", name="org.qemu.guest_agent.0")
        serial = ET.SubElement(devices, "serial", type="pty")
        ET.SubElement(serial, "target", port="0")
        definition = target.with_suffix(".xml")
        ET.indent(domain)
        definition.write_text(ET.tostring(domain, encoding="unicode") + "\n")
        self.virsh("define", str(definition))

    def owned(self):
        xml = ET.fromstring(self.virsh("dumpxml", self.domain))
        if xml.findtext("description") != "hyptcn3 benign persistent lab":
            raise RuntimeError("Refusing to modify a domain not created by labctl")

    def start(self):
        self.owned()
        if self.virsh("domstate", self.domain) == "shut off":
            self.virsh("start", self.domain)
        self.wait()
        # passt provides DHCP and forwards only the local development port.
        self.guest("if [ ! -f /var/lib/hyptcn-lab-network-v3 ]; then "
                   "hostnamectl set-hostname " + shlex.quote(self.domain) + "; "
                   "printf '[Match]\\nName=en* eth*\\n[Network]\\nDHCP=ipv4\\n[DHCPv4]\\nClientIdentifier=mac\\n' "
                   "> /etc/systemd/network/00-hyptcn-lab.network; "
                   "networkctl reload && networkctl reconfigure enp1s0 && "
                   "touch /var/lib/hyptcn-lab-network-v3; fi")

    def target(self):
        return "http://127.0.0.1:18080"

    def deploy(self):
        self.owned()
        self.start()
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
        state = {"uri": self.uri, "domain": self.domain, "target": target, "health": health}
        STATE.parent.mkdir(exist_ok=True)
        STATE.write_text(json.dumps(state, indent=2) + "\n")
        print(json.dumps(state, indent=2))
        return target

    def traffic(self):
        target = self.health()
        running = subprocess.run(["systemctl", "--user", "is-active", "--quiet", UNIT]).returncode == 0
        if running:
            print(f"{UNIT} is already running")
            return
        out = REPO / "data/lab"
        out.mkdir(parents=True, exist_ok=True)
        run(["systemd-run", "--user", f"--unit={UNIT}", "--collect",
             "--property=Restart=on-failure", "--property=RestartSec=5",
             f"--working-directory={REPO}", sys.executable, REPO / "scripts/host_traffic.py",
             "--profile", "lab", "--target", target, "--dur", "0", "--vlakien", "4",
             "--out", out / "traffic.json"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["up", "create", "start", "deploy", "status", "stop",
                                            "traffic-start", "traffic-stop", "exec", "logs"])
    parser.add_argument("--domain", default="hyptcn-lab")
    parser.add_argument("--uri", default="qemu:///session")
    parser.add_argument("--source", default="hyptcn-guest")
    parser.add_argument("--guest-command", help="Command for exec, executed inside the lab VM")
    args = parser.parse_args(argv)
    if args.domain == args.source:
        parser.error("Lab domain must be different from the experiment source")
    lab = Lab(args.uri, args.domain)
    if args.command in ("up", "create"):
        lab.clone(args.source)
    if args.command in ("up", "start", "create"):
        lab.start()
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
        subprocess.run(["systemctl", "--user", "status", UNIT, "--no-pager"])
    if args.command in ("stop", "traffic-stop"):
        subprocess.run(["systemctl", "--user", "stop", UNIT], check=False)
    if args.command == "stop":
        lab.owned()
        print(lab.virsh("shutdown", lab.domain))
    if args.command == "exec":
        lab.owned()
        if not args.guest_command:
            parser.error("exec requires --guest-command")
        print(lab.guest(args.guest_command), end="")
    if args.command == "logs":
        print(lab.guest("journalctl -u 'hyptcn-*' -n 60 --no-pager"), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"labctl: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
