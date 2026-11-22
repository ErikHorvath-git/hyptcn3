#!/usr/bin/env python3
"""Benign operational events in the lab VM, run as root through qemu-guest-agent.

Protocol v3 (docs/NAVRH_PROTOKOL_V3.sk.md) measures false alarms during ordinary
server operations, never malware. Every event has `start` and `stop`; `stop`
always returns the lab to its deployed state, also after a failed `start`. Both
print one JSON object with guest times and evidence (unit states, health).

Protocol v5 (package B5): `stop` first evaluates the effect predicate of the type
while the event is still in place and prints it as `effect` = {ok, predicate,
evidence}; the log audit refuses an event whose effect is not ok
(scripts/collection_logs.py, event_without_effect). `effect` evaluates the
predicate alone and changes nothing. `naprazdno` runs the trigger only: the
negative control of the trigger's own trace (proposal 5.5, decision D8).

  udalosti.py start TYPE
  udalosti.py stop TYPE
  udalosti.py effect TYPE
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

STATE = Path("/run/hyptcn-udalosti")
PROC = Path("/proc")
APPS = ["hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@docs", "hyptcn-lab@worker"]
DATABASE = "postgresql@15-main"
DROPIN = Path("/etc/systemd/system/hyptcn-lab@catalog.service.d/zla-konfiguracia.conf")
NGINX = Path("/etc/nginx/conf.d/hyptcn-lab.conf")
BACKUPS = Path("/var/tmp/hyptcn-udrzba")
TYPES = ("zla_konfiguracia_sluzby", "zla_konfiguracia_nginx", "restart_databazy", "restart_sluzby",
         "zamok_tabulky", "udrzba_zaloha", "zataz_pamate", "naprazdno")
# Pilot-only positive control of the features proc_wx and proc_memfd (protocol v4,
# events.pilot_controls): one process with one touched W+X anonymous page and an
# open memfd. Benign and inert: the page holds a single RET byte that is never run.
CONTROLS = ("kontrola_wx_memfd",)
CONTROL_PROGRAM = ("import mmap, os, time\n"
                   "m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n"
                   "m[0:1] = b'\\xc3'\n"
                   "fd = os.memfd_create('hyptcn-kontrola')\n"
                   "time.sleep(3600)\n")
# Memory of the largest event (zataz_pamate); lab/guest_state.py pretouch touches the same amount (proposal 5.4).
LOAD_MIB = 400
# The effect of zataz_pamate (KOSTRA B5, section 3): the load holds at least 390 MiB resident.
LOAD_MIN_KIB = 390 << 10
TRIGGER_ONLY = "iba spúšťač"
# The predicates ask the services on their own ports, never through nginx: the log audit refuses every nginx line
# that is neither a generator request nor a health check without request id inside an event window
# (scripts/collection_logs.py, nginx_unknown_request).
CATALOG_URL = "http://127.0.0.1:8081/api/catalog?page=1&size=1"
TOKEN_URL = "http://127.0.0.1:8082/api/auth/token"
ORDERS_URL = "http://127.0.0.1:8083/api/orders"
BROKEN_UPSTREAM = "127.0.0.1:8091"
LOCKS = ("SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
         "WHERE l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
         "AND c.relname = 'orders' AND l.mode = 'AccessExclusiveLock' AND l.granted")
PREDICATES = {
    "zla_konfiguracia_sluzby": "NRestarts of hyptcn-lab@catalog rose since start and /api/catalog of the catalog "
                               "service fails (no reply, which nginx answers with 502, or 5xx)",
    "zla_konfiguracia_nginx": "the nginx configuration proxies to 127.0.0.1:8091 and nothing answers there",
    "restart_databazy": "the main PID of postgresql@15-main differs from the one before start",
    "restart_sluzby": "the main PID of hyptcn-lab@orders differs from the one before start",
    "zamok_tabulky": "pg_locks shows a granted AccessExclusiveLock on orders and an order write gets 503",
    "udrzba_zaloha": "the backup db.sql.gz exists, is not empty and holds a non-empty dump",
    "zataz_pamate": "a process of the load holds at least 390 MiB resident",
    "naprazdno": "none by definition: only the trigger ran",
    "kontrola_wx_memfd": "a process of the control holds an rwx mapping and an open memfd",
}


def load_program(hold_s):
    """A legitimate report job that touches LOAD_MIB of memory and holds it for hold_s seconds."""
    return (f"import time; b = bytearray({LOAD_MIB} << 20); b[::4096] = b'x' * len(b[::4096]); "
            f"time.sleep({hold_s})")


def run(*args, check=True, timeout=90):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def http(method, url, body=None, token=None, timeout=10):
    """(status, JSON reply, error) of one request to a lab service; status None when nothing answered.
    Timeouts (10 s, 15 s for the locked order write): executor's judgment (B5a)."""
    headers = {"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})}
    request = urllib.request.Request(url, method=method, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            return reply.status, json.loads(reply.read() or b"null"), None
    except urllib.error.HTTPError as error:
        return error.code, None, None
    except (OSError, ValueError) as error:
        return None, None, f"{type(error).__name__}: {error}"[:200]


def unit_value(unit, name):
    return run("systemctl", "show", unit, "-p", name, "--value", check=False).stdout.strip()


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


def remember(kind, values):
    """Values the effect predicate compares with, taken in start before the change."""
    STATE.mkdir(mode=0o700, exist_ok=True)
    (STATE / (kind + ".before.json")).write_text(json.dumps(values))


def remembered(kind, name):
    try:
        return json.loads((STATE / (kind + ".before.json")).read_text()).get(name)
    except (OSError, ValueError, AttributeError):
        return None


def health():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=3) as reply:
            return reply.status
    except OSError as exc:
        return str(exc)[:120]


def unit_states():
    out = {}
    for unit in [*APPS, "nginx", DATABASE]:
        show = run("systemctl", "show", unit, "-p", "ActiveState,NRestarts,ExecMainPID", check=False).stdout
        out[unit] = dict(line.split("=", 1) for line in show.splitlines() if "=" in line)
    return out


def nginx_reload():
    run("nginx", "-t")
    run("systemctl", "reload", "nginx")


def start(kind):
    if kind == "zla_konfiguracia_sluzby":
        # A typo in the deployed unit: the service exits at once, systemd restarts it every RestartSec
        # until StartLimitBurst ends the loop in state failed (lab/hyptcn-lab@.service).
        DROPIN.parent.mkdir(exist_ok=True)
        DROPIN.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/python3 -u /opt/hyptcn-lab/services.py catalgo\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "hyptcn-lab@catalog", check=False)
        # Read before the first automatic restart (RestartSec=3 s): the predicate counts the loop's restarts.
        remember(kind, {"NRestarts": unit_value("hyptcn-lab@catalog", "NRestarts")})
    elif kind == "zla_konfiguracia_nginx":
        # A wrong upstream port in the proxy configuration: catalog requests get 502.
        original = NGINX.read_text()
        if "127.0.0.1:8081" not in original:
            raise SystemExit("unexpected nginx configuration")
        STATE.mkdir(mode=0o700, exist_ok=True)
        (STATE / "nginx.conf").write_text(original)
        NGINX.write_text(original.replace("127.0.0.1:8081", BROKEN_UPSTREAM))
        nginx_reload()
    elif kind == "restart_databazy":
        remember(kind, {"MainPID": unit_value(DATABASE, "MainPID")})
        # The lab units have Requires=postgresql.service, so systemd restarts them with the database.
        run("systemctl", "restart", "postgresql")
    elif kind == "restart_sluzby":
        remember(kind, {"MainPID": unit_value("hyptcn-lab@orders", "MainPID")})
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
        background(kind, ["runuser", "-u", "nobody", "--", "python3", "-c", load_program(3600)])
    elif kind == "kontrola_wx_memfd":
        leader = background(kind, ["runuser", "-u", "nobody", "--", "python3", "-c", CONTROL_PROGRAM])
        time.sleep(2)
        if not control_evidence(leader):
            raise SystemExit("positive control process has no rwx mapping or memfd")
    elif kind == "naprazdno":
        pass  # The trigger only: the guest agent ran this script, nothing else happens.
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


def _number(value):
    return type(value) is str and value.isdigit()


def _catalog_restarting():
    before, now = remembered("zla_konfiguracia_sluzby", "NRestarts"), unit_value("hyptcn-lab@catalog", "NRestarts")
    status, _, error = http("GET", CATALOG_URL)
    rose = _number(before) and _number(now) and int(now) > int(before)
    return rose and (status is None or status >= 500), {
        "NRestarts_before": before, "NRestarts": now, "ActiveState": unit_value("hyptcn-lab@catalog", "ActiveState"),
        "catalog_status": status, "catalog_error": error}


def _nginx_upstream_broken():
    configured = BROKEN_UPSTREAM in NGINX.read_text()
    status, _, error = http("GET", f"http://{BROKEN_UPSTREAM}/api/catalog")
    return configured and status is None, {"proxies_to_8091": configured, "upstream_status": status,
                                           "upstream_error": error}


def _new_main_pid(kind, unit):
    before, now = remembered(kind, "MainPID"), unit_value(unit, "MainPID")
    valid = [_number(pid) and pid != "0" for pid in (before, now)]
    return all(valid) and now != before, {"MainPID_before": before, "MainPID": now}


def _orders_locked():
    locks = int(run("runuser", "-u", "postgres", "--", "psql", "-X", "-tA", "hyptcn_lab", "-c", LOCKS).stdout.strip())
    evidence = {"access_exclusive_locks": locks}
    if not locks:
        return False, evidence  # No write without the lock: it would place a real order.
    status, reply, error = http("POST", TOKEN_URL, {"user": "udalosti"})
    token = reply.get("token") if status == 200 and isinstance(reply, dict) else None
    evidence.update(token_status=status, token_error=error)
    if not token:
        return False, evidence
    # The orders service waits for the lock until its 3 s statement timeout and answers 503.
    status, _, error = http("POST", ORDERS_URL, {"product_id": 1, "quantity": 1}, token, timeout=15)
    evidence.update(order_write_status=status, order_write_error=error)
    return status == 503, evidence


def _backup_written():
    path = BACKUPS / "db.sql.gz"
    if not path.is_file():
        return False, {"backup": str(path), "exists": False}
    dumped = 0
    with gzip.open(path, "rb") as stream:  # A truncated (unfinished) gzip raises EOFError: no effect.
        while chunk := stream.read(1 << 20):
            dumped += len(chunk)
    size = path.stat().st_size
    return size > 0 and dumped > 0, {"backup": str(path), "exists": True, "bytes": size, "dump_bytes": dumped}


def _session_of(kind):
    path = STATE / (kind + ".pid")
    return int(path.read_text()) if path.exists() else None


def _load_resident():
    sid = _session_of("zataz_pamate")
    rss = {}
    for pid in session_members(sid, PROC) if sid else ():
        try:
            status = (PROC / str(pid) / "status").read_text()
        except OSError:
            continue
        rss.update({str(pid): int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")})
    peak = max(rss.values(), default=0)
    return peak >= LOAD_MIN_KIB, {"session": sid, "rss_kib": rss, "peak_rss_kib": peak}


def _control_present():
    sid = _session_of("kontrola_wx_memfd")
    return bool(sid) and control_evidence(sid, PROC), {"session": sid,
                                                       "members": session_members(sid, PROC) if sid else []}


EVALUATE = {
    "zla_konfiguracia_sluzby": _catalog_restarting,
    "zla_konfiguracia_nginx": _nginx_upstream_broken,
    "restart_databazy": lambda: _new_main_pid("restart_databazy", DATABASE),
    "restart_sluzby": lambda: _new_main_pid("restart_sluzby", "hyptcn-lab@orders"),
    "zamok_tabulky": _orders_locked,
    "udrzba_zaloha": _backup_written,
    "zataz_pamate": _load_resident,
    "naprazdno": lambda: (True, TRIGGER_ONLY),
    "kontrola_wx_memfd": _control_present,
}


def effect(kind):
    """The effect predicate of the type (KOSTRA B5, section 3): {"ok", "predicate", "evidence"}.

    Never raises: a predicate that cannot be evaluated is false with the error as evidence,
    so that stop still restores the lab."""
    try:
        ok, evidence = EVALUATE[kind]()
    except Exception as exc:  # noqa: BLE001  Any failure means: no effect shown.
        ok, evidence = False, {"error": f"{type(exc).__name__}: {exc}"[:300]}
    return {"ok": ok is True, "predicate": PREDICATES[kind], "evidence": evidence}


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
    (STATE / (kind + ".before.json")).unlink(missing_ok=True)
    return pid


def main(argv):
    if len(argv) != 2 or argv[0] not in ("start", "stop", "effect") or argv[1] not in TYPES + CONTROLS:
        raise SystemExit("usage: udalosti.py start|stop|effect " + "|".join(TYPES + CONTROLS))
    action, kind = argv
    began = time.time()
    error = None
    pid = None
    measured = None
    try:
        if action == "start":
            start(kind)
        elif action == "stop":
            measured = effect(kind)  # While the event is still in place; effect() never raises.
            pid = stop(kind)
        else:
            measured = effect(kind)
    except (OSError, subprocess.SubprocessError, SystemExit) as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
    if action == "stop":
        for _ in range(30):
            if health() == 200:
                break
            time.sleep(1)
    record = {"schema": "hyptcn3/lab-event/1", "type": kind, "action": action, "ok": error is None,
              "error": error, "guest_started_unix": began, "guest_finished_unix": time.time(),
              "background_pid": pid, "health": health(), "units": unit_states(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    if measured is not None:
        record["effect"] = measured
    print(json.dumps(record))


if __name__ == "__main__":
    os.umask(0o027)
    main(sys.argv[1:])
