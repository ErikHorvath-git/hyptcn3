#!/usr/bin/env python3
"""Benign operational events in the lab VM, run as root through qemu-guest-agent.

Protocol v3 (docs/NAVRH_PROTOKOL_V3.sk.md) measures false alarms during ordinary
server operations, never malware. Every event has `start` and `stop`; `stop`
always returns the lab to its deployed state, also after a failed `start`. Both
print one JSON object with guest times and evidence (unit states, health).

  udalosti.py start TYPE
  udalosti.py stop TYPE
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request

STATE = Path("/run/hyptcn-udalosti")
APPS = ["hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@worker"]
DROPIN = Path("/etc/systemd/system/hyptcn-lab@catalog.service.d/zla-konfiguracia.conf")
NGINX = Path("/etc/nginx/conf.d/hyptcn-lab.conf")
BACKUPS = Path("/var/tmp/hyptcn-udrzba")
TYPES = ("zla_konfiguracia_sluzby", "zla_konfiguracia_nginx", "restart_databazy", "restart_sluzby",
         "zamok_tabulky", "udrzba_zaloha", "zataz_pamate")
# Pilot-only positive control of the features proc_wx and proc_memfd (protocol v4,
# events.pilot_controls): one process with one touched W+X anonymous page and an
# open memfd. Benign and inert: the page holds a single RET byte that is never run.
CONTROLS = ("kontrola_wx_memfd",)
CONTROL_PROGRAM = ("import mmap, os, time\n"
                   "m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n"
                   "m[0:1] = b'\\xc3'\n"
                   "fd = os.memfd_create('hyptcn-kontrola')\n"
                   "time.sleep(3600)\n")


def run(*args, check=True, timeout=90):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def background(name, command):
    """Detached child that survives the guest-agent call; its PID is kept for stop."""
    STATE.mkdir(mode=0o700, exist_ok=True)
    process = subprocess.Popen(command, start_new_session=True, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (STATE / (name + ".pid")).write_text(str(process.pid))
    return process.pid


def kill_background(name):
    path = STATE / (name + ".pid")
    if not path.exists():
        return None
    pid = int(path.read_text())
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    path.unlink()
    return pid


def health():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=3) as reply:
            return reply.status
    except OSError as exc:
        return str(exc)[:120]


def unit_states():
    out = {}
    for unit in [*APPS, "nginx", "postgresql@15-main"]:
        show = run("systemctl", "show", unit, "-p", "ActiveState,NRestarts,ExecMainPID", check=False).stdout
        out[unit] = dict(line.split("=", 1) for line in show.splitlines() if "=" in line)
    return out


def nginx_reload():
    run("nginx", "-t")
    run("systemctl", "reload", "nginx")


def start(kind):
    if kind == "zla_konfiguracia_sluzby":
        # A typo in the deployed unit: the service exits at once, systemd restarts it every RestartSec.
        DROPIN.parent.mkdir(exist_ok=True)
        DROPIN.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/python3 -u /opt/hyptcn-lab/services.py catalgo\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "hyptcn-lab@catalog", check=False)
    elif kind == "zla_konfiguracia_nginx":
        # A wrong upstream port in the proxy configuration: catalog requests get 502.
        original = NGINX.read_text()
        if "127.0.0.1:8081" not in original:
            raise SystemExit("unexpected nginx configuration")
        STATE.mkdir(mode=0o700, exist_ok=True)
        (STATE / "nginx.conf").write_text(original)
        NGINX.write_text(original.replace("127.0.0.1:8081", "127.0.0.1:8091"))
        nginx_reload()
    elif kind == "restart_databazy":
        # The lab units have Requires=postgresql.service, so systemd restarts them with the database.
        run("systemctl", "restart", "postgresql")
    elif kind == "restart_sluzby":
        run("systemctl", "restart", "hyptcn-lab@orders")
    elif kind == "zamok_tabulky":
        # A long migration holds the orders table; requests hit the 3 s statement timeout.
        background(kind, ["runuser", "-u", "postgres", "--", "psql", "-X", "hyptcn_lab", "-c",
                          "BEGIN; LOCK TABLE orders IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(3600);"])
    elif kind == "udrzba_zaloha":
        BACKUPS.mkdir(mode=0o700, exist_ok=True)
        background(kind, ["bash", "-c",
                          f"runuser -u postgres -- pg_dump hyptcn_lab | gzip > {BACKUPS}/db.sql.gz && "
                          f"tar -C / -czf {BACKUPS}/etc.tar.gz etc 2>/dev/null; sync"])
    elif kind == "zataz_pamate":
        # A legitimate report job that holds about 400 MiB of touched memory.
        background(kind, ["runuser", "-u", "nobody", "--", "python3", "-c",
                          "import time; b = bytearray(400 << 20); b[::4096] = b'x' * len(b[::4096]); time.sleep(3600)"])
    elif kind == "kontrola_wx_memfd":
        leader = background(kind, ["runuser", "-u", "nobody", "--", "python3", "-c", CONTROL_PROGRAM])
        time.sleep(2)
        if not control_evidence(leader):
            raise SystemExit("positive control process has no rwx mapping or memfd")
    else:
        raise SystemExit("unknown event type")


def session_members(sid, proc=Path("/proc")):
    """PIDs whose session is `sid` (the runuser leader and its python3 child)."""
    out = []
    for stat in proc.glob("[0-9]*/stat"):
        try:
            fields = stat.read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[3]) == sid:
            out.append(int(stat.parent.name))
    return out


def control_evidence(sid, proc=Path("/proc")):
    """Guest-side evidence that the control holds an rwx mapping and an open memfd."""
    for pid in session_members(sid, proc):
        try:
            maps = (proc / str(pid) / "maps").read_text()
            fds = [os.readlink(f) for f in (proc / str(pid) / "fd").iterdir()]
        except OSError:
            continue
        if any(line.split()[1].startswith("rwx") for line in maps.splitlines() if line.strip()) \
                and any(f.startswith("/memfd:hyptcn-kontrola") for f in fds):
            return True
    return False


def stop(kind):
    pid = kill_background(kind)
    if kind == "zla_konfiguracia_sluzby":
        if DROPIN.exists():
            DROPIN.unlink()
        if DROPIN.parent.exists() and not any(DROPIN.parent.iterdir()):
            DROPIN.parent.rmdir()
        run("systemctl", "daemon-reload")
        run("systemctl", "reset-failed", "hyptcn-lab@catalog", check=False)
        run("systemctl", "restart", "hyptcn-lab@catalog")
    elif kind == "zla_konfiguracia_nginx":
        saved = STATE / "nginx.conf"
        if saved.exists():
            NGINX.write_text(saved.read_text())
            saved.unlink()
        nginx_reload()
    elif kind == "zamok_tabulky":
        run("runuser", "-u", "postgres", "--", "psql", "-X", "hyptcn_lab", "-tAc",
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE query LIKE 'BEGIN; LOCK TABLE orders%' AND pid <> pg_backend_pid()", check=False)
    elif kind == "udrzba_zaloha":
        run("rm", "-rf", str(BACKUPS), check=False)
    return pid


def main(argv):
    if len(argv) != 2 or argv[0] not in ("start", "stop") or argv[1] not in TYPES + CONTROLS:
        raise SystemExit("usage: udalosti.py start|stop " + "|".join(TYPES + CONTROLS))
    action, kind = argv
    began = time.time()
    error = None
    pid = None
    try:
        if action == "start":
            start(kind)
        else:
            pid = stop(kind)
    except (OSError, subprocess.SubprocessError, SystemExit) as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
    if action == "stop":
        for _ in range(30):
            if health() == 200:
                break
            time.sleep(1)
    print(json.dumps({"schema": "hyptcn3/lab-event/1", "type": kind, "action": action, "ok": error is None,
                      "error": error, "guest_started_unix": began, "guest_finished_unix": time.time(),
                      "background_pid": pid, "health": health(), "units": unit_states(),
                      "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}))


if __name__ == "__main__":
    os.umask(0o027)
    main(sys.argv[1:])
