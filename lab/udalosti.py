#!/usr/bin/env python3
"""Benign operational events and controls in the lab VM, run as root through qemu-guest-agent.

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

Protocol v5 (package B8, skeleton dokazy/B8/kostra/KOSTRA.md, proposal 7.4): the controls of classes A and B, each
with its paired negative (the same program and process tree, the same memory, without the anomalous property).
Every control is a benign, inert program of the lab: no foreign code and no module of its own. `start` first
evaluates the return predicate (lab/guest_state.py baseline) and starts nothing when it does not hold; `stop`
evaluates the effect while the occurrence is in place, stops it and evaluates the cleanup (nothing of the
occurrence remains). The reply carries `baseline` and `started` (start), `effect` and `cleanup` (stop).

  udalosti.py start TYPE
  udalosti.py stop TYPE
  udalosti.py effect TYPE
  udalosti.py start KIND --polarity control|negative [--dose D] --levels JSON --tolerance JSON|null
  udalosti.py stop KIND --polarity control|negative [--dose D]
  udalosti.py effect KIND --polarity control|negative [--dose D]
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
SYS = Path("/sys")
APPS = ["hyptcn-lab@auth", "hyptcn-lab@catalog", "hyptcn-lab@orders", "hyptcn-lab@docs", "hyptcn-lab@worker"]
DATABASE = "postgresql@15-main"
DROPIN = Path("/etc/systemd/system/hyptcn-lab@catalog.service.d/zla-konfiguracia.conf")
NGINX = Path("/etc/nginx/conf.d/hyptcn-lab.conf")
BACKUPS = Path("/var/tmp/hyptcn-udrzba")
TYPES = ("zla_konfiguracia_sluzby", "zla_konfiguracia_nginx", "restart_databazy", "restart_sluzby",
         "zamok_tabulky", "udrzba_zaloha", "zataz_pamate", "naprazdno")
ACTIONS = ("start", "stop", "effect")
# The control kinds of protocol v5 and their classes (skeleton B8 section 1, proposal 7.4): A edge, B volume.
# kontrola_wx_memfd was the pilot's positive control of protocol v4 (events.pilot_controls).
CLASSES = {"kontrola_wx_memfd": "A", "kontrola_modul_jadra": "A", "kontrola_pocuvajuci_soket": "A",
           "kontrola_zapisovac_pamate": "B", "kontrola_davka_procesov": "B"}
CONTROLS = tuple(CLASSES)
POLARITIES = ("control", "negative")
# The doses of class B, the lead's judgment (skeleton B8 section 1; config/collection-v5.json controls.kinds.*.doses
# holds the same): MiB the writer holds, short processes a second the batch starts.
DOSES = {"kontrola_zapisovac_pamate": (16, 64, 256), "kontrola_davka_procesov": (2, 10, 50)}
# Every process of a control has this in its command line (the programs below, the batch's children in argv[0]);
# the return predicate finds a process of a control by it.
MARKER = "hyptcn-kontrola"
MEMFD_PREFIX = "/memfd:hyptcn-kontrola"  # How /proc/PID/fd shows the memfd of kontrola_wx_memfd.
NEGATIVE_FILE = Path("/tmp/hyptcn-kontrola-negativna")  # The negative of kontrola_wx_memfd holds this instead.
# Modules of the guest kernel's package (Debian 12 cloud kernel) that need no other module and create no device and
# no network interface: library code without an init of its own (crc7, crc8) or one that registers a text search
# algorithm (ts_kmp). The lead's judgment until the lab test on the VM confirms them (skeleton B8 section 6); the
# control takes the first one present, not loaded and without dependencies.
MODULE_CANDIDATES = ("crc7", "crc8", "ts_kmp")
MODULES_DEP = Path("/lib/modules") / os.uname().release / "modules.dep"
# The port of the listening control, judgment: outside the lab's ports (nginx 8080, the services 8081 to 8084,
# PostgreSQL 5432, the broken upstream 8091) and below the ephemeral range 32768-60999; loopback only.
CONTROL_PORT = 9391
WRITER_PERIOD_S = 5  # Judgment (skeleton B8 section 1): the writer rewrites its memory once per collection interval.
BATCH_CHILD = "hyptcn-kontrola-potomok"  # argv[0] of the batch's children (the executable is sleep).
# Judgment: a short process lives 2 s. K x 2 >= 4 of them are alive at any instant also at the lowest dose (K = 2), so
# every snapshot sees about 2K of them; 2 s is below the 5 s collection interval, so no snapshot sees one twice.
BATCH_CHILD_S = 2
PROGRAM_MAX_S = 3600  # Every control program ends itself after this; the stop of its occurrence ends it before.
START_WAIT_S = 10  # Judgment: an occurrence is in place (missing) this long after its program started.
STOP_WAIT_S = 10  # Judgment: the processes of an occurrence are gone this long after SIGTERM, else SIGKILL ...
KILL_WAIT_S = 5  # ... and this long after SIGKILL.
WRITER_FRESH_PERIODS = 3  # Judgment: the writer's last report is at most three periods old while it runs.
BATCH_FRESH_S = 3  # Judgment: the batch reports every second; its last report is at most 3 s old while it runs.
BATCH_RATE_FLOOR = .8  # Judgment: the batch starts at least 0.8 K processes a second over its reports.
# One program per kind (skeleton B8 section 1): the control and its negative run the same text, the polarity and the
# parameters are its arguments, and each prints one JSON line per report into its output file (STATE/KIND.out).
# Every program is benign and inert: the W+X page holds a single RET byte that is never run.
WX_MEMFD_PROGRAM = (
    "# hyptcn-kontrola kontrola_wx_memfd: a touched page and an open file; the control's page W+X and its file a\n"
    "# memfd, the negative's page RW and its file in /tmp (arguments: polarity, the negative's file, seconds)\n"
    "import json, mmap, os, sys, time\n"
    "negative = sys.argv[1:2] == ['negative']\n"
    "page = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | (0 if negative else mmap.PROT_EXEC))\n"
    "page[0:1] = b'\\xc3'\n"
    "held = (os.open(sys.argv[2], os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600) if negative\n"
    "        else os.memfd_create('hyptcn-kontrola'))\n"
    "print(json.dumps({'ready': True, 'pid': os.getpid(), 't': time.monotonic()}), flush=True)\n"
    "time.sleep(float(sys.argv[3]) if len(sys.argv) > 3 else 3600)\n")
CONTROL_PROGRAM = WX_MEMFD_PROGRAM  # The name of protocol v4's pilot.
SOCKET_PROGRAM = (
    "# hyptcn-kontrola kontrola_pocuvajuci_soket: a TCP socket bound to 127.0.0.1; only the control listens\n"
    "# (arguments: polarity, port, seconds)\n"
    "import json, os, socket, sys, time\n"
    "negative = sys.argv[1] == 'negative'\n"
    "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "sock.bind(('127.0.0.1', int(sys.argv[2])))\n"
    "if not negative:\n"
    "    sock.listen(1)\n"
    "print(json.dumps({'ready': True, 'pid': os.getpid(), 't': time.monotonic()}), flush=True)\n"
    "time.sleep(float(sys.argv[3]))\n")
WRITER_PROGRAM = (
    "# hyptcn-kontrola kontrola_zapisovac_pamate: holds N MiB; the control overwrites them with random bytes once a\n"
    "# period, the negative writes them once (arguments: polarity, MiB, period s, seconds)\n"
    "import json, os, sys, time\n"
    "negative, size, period = sys.argv[1] == 'negative', int(sys.argv[2]) << 20, float(sys.argv[3])\n"
    "memory, end = memoryview(bytearray(size)), time.monotonic() + float(sys.argv[4])\n"
    "rounds, due = 0, time.monotonic()\n"
    "while time.monotonic() < end:\n"
    "    written = 0\n"
    "    if rounds == 0 or not negative:\n"
    "        for offset in range(0, size, 1 << 20):\n"
    "            memory[offset:offset + (1 << 20)] = os.urandom(1 << 20)\n"
    "        written = size\n"
    "    rounds += 1\n"
    "    print(json.dumps({'round': rounds, 'bytes': written, 't': time.monotonic()}), flush=True)\n"
    "    due += period\n"
    "    time.sleep(max(0.0, due - time.monotonic()))\n")
BATCH_PROGRAM = (
    "# hyptcn-kontrola kontrola_davka_procesov: the control starts K short processes a second, the negative one long\n"
    "# process (arguments: polarity, K, seconds a short process lives, seconds)\n"
    "import json, os, shutil, sys, time\n"
    "negative, rate, life, seconds = sys.argv[1] == 'negative', int(sys.argv[2]), sys.argv[3], sys.argv[4]\n"
    "executable, end = shutil.which('sleep'), time.monotonic() + float(seconds)\n"
    "started = reaped = 0\n"
    "def child(lives):\n"
    "    global started\n"
    "    os.posix_spawn(executable, ['hyptcn-kontrola-potomok', lives], os.environ)\n"
    "    started += 1\n"
    "if negative:\n"
    "    child(seconds)\n"
    "due = time.monotonic()\n"
    "while time.monotonic() < end:\n"
    "    for _ in range(rate):\n"
    "        if not negative:\n"
    "            child(life)\n"
    "        try:\n"
    "            while os.waitpid(-1, os.WNOHANG)[0]:\n"
    "                reaped += 1\n"
    "        except ChildProcessError:\n"
    "            pass\n"
    "        due += 1 / rate\n"
    "        time.sleep(max(0.0, due - time.monotonic()))\n"
    "    print(json.dumps({'started': started, 'alive': started - reaped, 't': time.monotonic()}), flush=True)\n")
PROGRAMS = {"kontrola_wx_memfd": WX_MEMFD_PROGRAM, "kontrola_pocuvajuci_soket": SOCKET_PROGRAM,
            "kontrola_zapisovac_pamate": WRITER_PROGRAM, "kontrola_davka_procesov": BATCH_PROGRAM}
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
# The predicate of each type, and of each control kind for the control (skeleton B8 section 2).
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
    "kontrola_modul_jadra": "the candidate module chosen at the start is in /proc/modules and loading it created no "
                            "network interface and no device",
    "kontrola_pocuvajuci_soket": f"a process of the control listens on TCP port {CONTROL_PORT}",
    "kontrola_zapisovac_pamate": "the writer holds the dose and its reports show every round rewriting the dose, the "
                                 "last one fresh",
    "kontrola_davka_procesov": "the batch's reports show it starting the dose of short processes a second, the last "
                               "one fresh",
}
# The predicate of each kind for its paired negative: the process tree runs and the property is absent.
NEGATIVE_PREDICATES = {
    "kontrola_wx_memfd": "the process of the negative runs and reported ready, no process of it holds an rwx "
                         "mapping or a memfd",
    "kontrola_modul_jadra": "modprobe -n of the candidate chosen at the start succeeded and the module is not in "
                            "/proc/modules",
    "kontrola_pocuvajuci_soket": f"the process of the negative runs and reported ready, nothing listens on TCP port "
                                 f"{CONTROL_PORT}",
    "kontrola_zapisovac_pamate": "the writer holds the dose, its first round wrote the dose and no later round "
                                 "rewrote it, the last report fresh",
    "kontrola_davka_procesov": "the batch and its one long child run, it started no other process, the last report "
                               "fresh",
}
# Each residue of a control in words (the evidence of the return predicate and of the cleanup).
SAYS = {"process": "process {pid} of a control lives: {cmdline}",
        "memfd": "process {pid} holds the memfd of a control: {target}",
        "file": "the file of a negative control exists: {path}",
        "module": "candidate module {name} is loaded",
        "port": "TCP port {port} of a control listens: {local}",
        "unit": "unit {unit} is failed",
        "state": "a state file of the occurrence remains: {path}",
        "error": "{what} could not be read: {error}"}


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


def background(name, command, output=None):
    """Detached child that survives the guest-agent call; its PID is kept for stop. With `output` its stdout and
    stderr go to that file (a control's reports)."""
    STATE.mkdir(mode=0o700, exist_ok=True)
    stream = open(output, "w") if output else subprocess.DEVNULL
    try:
        process = subprocess.Popen(command, start_new_session=True, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT if output else subprocess.DEVNULL)
    finally:
        if output:
            stream.close()
    (STATE / (name + ".pid")).write_text(str(process.pid))
    return process.pid


def signal_session(sid, number):
    """Send `number` to the process group of a session this script started (its leader's group)."""
    try:
        os.killpg(sid, number)
    except ProcessLookupError:
        pass


def kill_background(name):
    path = STATE / (name + ".pid")
    if not path.exists():
        return None
    pid = int(path.read_text())
    signal_session(pid, signal.SIGTERM)
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
                and any(f.startswith(MEMFD_PREFIX) for f in fds):
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


# ------------------------------------------------------------------------------------------- controls (B8)

def _argv(pid, proc=None):
    """The command line of a process as a list (empty for a kernel thread, a zombie or a vanished process)."""
    try:
        data = ((proc or PROC) / str(pid) / "cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode(errors="replace") for part in data.split(b"\0")[:-1]] if data else []


def _fd_targets(pid, proc=None):
    try:
        return [os.readlink(fd) for fd in ((proc or PROC) / str(pid) / "fd").iterdir()]
    except OSError:
        return []


def _rwx_mappings(pid):
    try:
        maps = (PROC / str(pid) / "maps").read_text()
    except OSError:
        return 0
    return sum(1 for line in maps.splitlines() if line.strip() and line.split()[1].startswith("rwx"))


def _peak_rss_kib(pids):
    peak = 0
    for pid in pids:
        try:
            status = (PROC / str(pid) / "status").read_text()
        except OSError:
            continue
        peak = max([peak] + [int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")])
    return peak


def _members(kind):
    sid = _session_of(kind)
    return sid, sorted(session_members(sid, PROC)) if sid else []


def _reports(kind):
    """The JSON lines the program of a control printed into its output file (other lines are its errors)."""
    try:
        lines = (STATE / (kind + ".out")).read_text().splitlines()
    except OSError:
        return []
    reports = []
    for line in lines:
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if type(value) is dict and type(value.get("t")) in (int, float):
            reports.append(value)
    return reports


def _age(reports):
    return round(time.monotonic() - reports[-1]["t"], 3) if reports else None


def loaded_modules(proc=None):
    """Names of the modules in /proc/modules."""
    return {line.split()[0] for line in ((proc or PROC) / "modules").read_text().splitlines() if line.strip()}


def _module_name(path):
    """kernel/lib/crc-itu-t.ko.xz -> crc_itu_t, the name /proc/modules shows."""
    return Path(path).name.split(".ko")[0].replace("-", "_")


def module_dependencies():
    """{module: [modules it needs]} of the modules the guest kernel's package installs (kernel/ in modules.dep)."""
    out = {}
    for line in MODULES_DEP.read_text().splitlines():
        path, _, needs = line.partition(":")
        if path.startswith("kernel/"):
            out[_module_name(path)] = [_module_name(p) for p in needs.split()]
    return out


def module_candidate(proc=None):
    """The first of MODULE_CANDIDATES in the kernel's package, not loaded and needing no other module (skeleton B8
    section 1); SystemExit naming why each one was passed over."""
    needs, loaded, why = module_dependencies(), loaded_modules(proc), []
    for name in MODULE_CANDIDATES:
        if name not in needs:
            why.append(f"{name} not in the kernel's package")
        elif needs[name]:
            why.append(f"{name} needs {', '.join(needs[name])}")
        elif name in loaded:
            why.append(f"{name} is loaded")
        else:
            return name
    raise SystemExit("no module candidate: " + "; ".join(why))


def devices():
    """Network interfaces and devices of the guest (sysfs), to show that a module created none."""
    def names(*paths):
        return sorted(p.name for path in paths if (SYS / path).is_dir() for p in (SYS / path).iterdir())
    return {"interfaces": names("class/net"), "devices": names("dev/char", "dev/block")}


def listeners(port, proc=None):
    """Sockets in state LISTEN on TCP `port` (/proc/net/tcp and tcp6)."""
    out = []
    for table in ("tcp", "tcp6"):
        try:
            lines = ((proc or PROC) / "net" / table).read_text().splitlines()[1:]
        except FileNotFoundError:
            continue  # A guest without IPv6.
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                out.append({"table": table, "local": fields[1], "inode": int(fields[9])})
    return out


def _socket_inodes(pid):
    return [int(f[8:-1]) for f in _fd_targets(pid) if f.startswith("socket:[")]


def control_processes(proc=None):
    """(pid, command line) of every process with MARKER in its command line, this script's own excepted."""
    proc, own, out = proc or PROC, os.getpid(), []
    for path in proc.glob("[0-9]*/cmdline"):
        pid = int(path.parent.name)
        argv = _argv(pid, proc)
        if pid != own and any(MARKER in part for part in argv):
            out.append((pid, " ".join(argv)[:200]))
    return sorted(out)


def memfd_holders(proc=None):
    proc, out = proc or PROC, []
    for fd in proc.glob("[0-9]*/fd/*"):
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith(MEMFD_PREFIX):
            out.append((int(fd.parent.parent.name), target))
    return sorted(out)


# The candidates a control of this boot chose and could not unload (finding F3 of the B9a verification): halt() names
# each one in this file of STATE while it stays loaded after the stop, and the file is no state file of a kind
# (_state_files), so it is no state residue. chosen_modules() reads it, so every later return predicate and cleanup of
# the boot counts the module as a residue; the file goes once none of its modules is loaded. STATE is under /run: the
# reboot of a group's start empties it.
LEFT_LOADED = "left-loaded-modules.json"
# Why a loaded candidate is a residue when the modules of the session's start are not known (residues with None).
UNKNOWN_START = "the modules loaded at the session's start are not known, so it cannot be ruled out"


def _left_names():
    """The names STATE / LEFT_LOADED holds; every candidate when the file exists but cannot be read (none ruled out)."""
    try:
        names = json.loads((STATE / LEFT_LOADED).read_text())
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return list(MODULE_CANDIDATES)
    return names if type(names) is list and all(type(name) is str for name in names) else list(MODULE_CANDIDATES)


def left_loaded():
    """The candidates a control of this boot chose and could not unload, while they are loaded (STATE / LEFT_LOADED,
    finding F3 of the B9a verification). The names no longer in /proc/modules leave the file, and the file goes with
    the last of them; while /proc/modules cannot be read none leaves. Never raises."""
    names = _left_names()
    try:
        still = [name for name in names if name in loaded_modules(PROC)]
    except OSError:
        return names
    try:
        if still and still != names:
            (STATE / LEFT_LOADED).write_text(json.dumps(still))
        elif not still:
            (STATE / LEFT_LOADED).unlink(missing_ok=True)
    except OSError:
        pass  # The names returned are right; the file is tidied at the next read.
    return still


def keep_left_loaded(name):
    """Name the candidate `name` a control chose in STATE / LEFT_LOADED while it is loaded after its stop (halt;
    finding F3 of the B9a verification); also when /proc/modules cannot be read, since it cannot be ruled out."""
    try:
        if name not in loaded_modules(PROC):
            return
    except OSError:
        pass
    STATE.mkdir(mode=0o700, exist_ok=True)
    (STATE / LEFT_LOADED).write_text(json.dumps(sorted(set(_left_names()) | {name})))


def chosen_modules():
    """The candidates a control chose, as a sorted list: the one the module kind's occurrence in place remembers (its
    state names it), and those a control of this boot chose and could not unload while they stay loaded
    (left_loaded, finding F3 of the B9a verification)."""
    name = remembered("kontrola_modul_jadra", "module")
    return sorted(set(left_loaded()) | ({name} if type(name) is str else set()))


def residues(proc, modules_at_start, chosen):
    """Whatever of any control is in the guest (the exact part of the return predicate, skeleton B8 section 3): a
    process, the memfd or the negative's file, a candidate module, the listening port.

    A loaded candidate module is a residue only when it was loaded after the session's start (not among
    `modules_at_start`, the names guest_state.py levels listed then) or a control chose it (`chosen`, chosen_modules:
    in place, or of this boot and never unloaded): finding S2 of B8, a candidate the kernel loaded at boot is no
    residue. Without the start's names (None: the stop of an occurrence that never started) no loaded candidate is
    ruled out, and every one is a residue, as before B9; the residue then says why (UNKNOWN_START)."""
    proc = proc or PROC
    found = [{"residue": "process", "pid": pid, "cmdline": text} for pid, text in control_processes(proc)]
    found += [{"residue": "memfd", "pid": pid, "target": target} for pid, target in memfd_holders(proc)]
    if NEGATIVE_FILE.exists():
        found.append({"residue": "file", "path": str(NEGATIVE_FILE)})
    loaded = loaded_modules(proc)
    why = {"why": UNKNOWN_START} if modules_at_start is None else {}  # The rule the residue was named by.
    found += [{"residue": "module", "name": name, **why} for name in MODULE_CANDIDATES if name in loaded
              and (modules_at_start is None or name not in modules_at_start or name in chosen)]
    found += [{"residue": "port", "port": CONTROL_PORT, "local": entry["local"]}
              for entry in listeners(CONTROL_PORT, proc)]
    return found


def says(residue):
    text = SAYS[residue["residue"]].format(**residue)
    return f"{text} ({residue['why']})" if "why" in residue else text


def _wx_memfd(polarity, dose):
    sid, members = _members("kontrola_wx_memfd")
    rwx, memfd, files = {}, {}, {}
    for pid in members:
        fds = _fd_targets(pid)
        for found, items in ((rwx, _rwx_mappings(pid)), (memfd, [f for f in fds if f.startswith(MEMFD_PREFIX)]),
                             (files, [f for f in fds if f.startswith(str(NEGATIVE_FILE))])):
            if items:
                found[str(pid)] = items
    evidence = {"session": sid, "members": members, "rwx_mappings": rwx, "memfd_fds": memfd, "file_fds": files}
    if polarity == "control":
        return [("one process of the occurrence holds an rwx mapping and the memfd",
                 bool(sid) and control_evidence(sid, PROC))], evidence
    return [("the process tree runs", bool(members)),
            ("the program reported ready", bool(_reports("kontrola_wx_memfd"))),
            ("no process of it holds an rwx mapping", not rwx), ("no process of it holds a memfd", not memfd)], evidence


def _module(polarity, dose):
    kind = "kontrola_modul_jadra"
    chosen, loaded, dry = remembered(kind, "module"), loaded_modules(PROC), remembered(kind, "dry_run")
    now = devices()
    before = {key: remembered(kind, key) for key in now}  # None: the occurrence never started.
    created = {key: [] if before[key] is None else sorted(set(now[key]) - set(before[key])) for key in now}
    evidence = {"module": chosen, "candidates": list(MODULE_CANDIDATES), "loaded": chosen in loaded,
                "modules": len(loaded), "modules_before": remembered(kind, "modules_before"), "created": created,
                "dry_run": dry}
    conditions = [("a candidate was chosen at the start", chosen is not None)]
    if polarity == "control":
        return conditions + [("the module is loaded", chosen in loaded),
                             ("loading it created no network interface", not created["interfaces"]),
                             ("loading it created no device", not created["devices"])], evidence
    return conditions + [("modprobe -n of it succeeded", type(dry) is dict and dry.get("returncode") == 0),
                         ("the module is not loaded", chosen not in loaded)], evidence


def _socket(polarity, dose):
    sid, members = _members("kontrola_pocuvajuci_soket")
    sockets = {str(pid): inodes for pid in members if (inodes := _socket_inodes(pid))}
    held = {inode for inodes in sockets.values() for inode in inodes}
    listening = listeners(CONTROL_PORT, PROC)
    evidence = {"session": sid, "members": members, "port": CONTROL_PORT, "listening": listening,
                "socket_inodes": sockets}
    if polarity == "control":
        return [("a process of the occurrence listens on the port",
                 any(entry["inode"] in held for entry in listening))], evidence
    return [("the process tree runs", bool(members)),
            ("the program reported ready", bool(_reports("kontrola_pocuvajuci_soket"))),
            ("nothing listens on the port", not listening)], evidence


def _writer(polarity, dose):
    kind = "kontrola_zapisovac_pamate"
    sid, members = _members(kind)
    reports, size = [r for r in _reports(kind) if "round" in r], (dose or 0) << 20
    later, age, rss = reports[1:], _age(reports), _peak_rss_kib(members)
    evidence = {"session": sid, "members": members, "dose_mib": dose, "peak_rss_kib": rss, "rounds": len(reports),
                "first_round_bytes": reports[0].get("bytes") if reports else None,
                "later_rounds_rewriting": sum(1 for r in later if r.get("bytes")), "last_report_age_s": age}
    conditions = [("the process tree runs", bool(members)), ("it holds the dose", rss >= (dose or 0) << 10),
                  ("its first round wrote the dose", bool(reports) and reports[0].get("bytes") == size),
                  ("its last report is fresh", age is not None and age <= WRITER_FRESH_PERIODS * WRITER_PERIOD_S)]
    if polarity == "control":
        return conditions + [("every later round rewrote the dose",
                              bool(later) and all(r.get("bytes") == size for r in later))], evidence
    return conditions + [("no later round rewrote it", all(r.get("bytes") == 0 for r in later))], evidence


def _batch(polarity, dose):
    kind = "kontrola_davka_procesov"
    sid, members = _members(kind)
    reports = [r for r in _reports(kind) if type(r.get("started")) is int]
    age, rate = _age(reports), None
    if len(reports) >= 2 and reports[-1]["t"] > reports[0]["t"]:
        rate = round((reports[-1]["started"] - reports[0]["started"]) / (reports[-1]["t"] - reports[0]["t"]), 3)
    children = _children(members)
    evidence = {"session": sid, "members": members, "dose_per_s": dose, "reports": len(reports),
                "started": reports[-1]["started"] if reports else None, "rate_per_s": rate,
                "children_alive": len(children), "last_report_age_s": age}
    conditions = [("the process tree runs", bool(members)), ("a child of it runs", bool(children)),
                  ("its last report is fresh", age is not None and age <= BATCH_FRESH_S)]
    if polarity == "control":
        return conditions + [("it starts the dose of processes a second",
                              rate is not None and rate >= BATCH_RATE_FLOOR * dose)], evidence
    return conditions + [("it started no process besides the long child",
                          bool(reports) and all(r["started"] == 1 for r in reports))], evidence


def _children(members):
    """The running children of the batch (a zombie has no command line)."""
    return [pid for pid in members if _argv(pid)[:1] == [BATCH_CHILD]]


def _control(kind, conditions_of):
    """The effect predicate of a control kind as (ok, evidence): every condition holds; `failed` names the ones that
    do not. The occurrence in place must be the one asked about (polarity and dose of its start)."""
    def predicate(polarity, dose):
        started_as = {"polarity": remembered(kind, "polarity"), "dose": remembered(kind, "dose")}
        conditions, evidence = conditions_of(polarity, dose)
        conditions = [("the occurrence in place is this polarity and dose",
                       started_as["polarity"] in (None, polarity) and started_as["dose"] in (None, dose)),
                      *conditions]
        failed = [name for name, holds in conditions if not holds]
        return not failed, {"started_as": started_as, **evidence, "failed": failed}
    return predicate


EVALUATE = {
    "zla_konfiguracia_sluzby": _catalog_restarting,
    "zla_konfiguracia_nginx": _nginx_upstream_broken,
    "restart_databazy": lambda: _new_main_pid("restart_databazy", DATABASE),
    "restart_sluzby": lambda: _new_main_pid("restart_sluzby", "hyptcn-lab@orders"),
    "zamok_tabulky": _orders_locked,
    "udrzba_zaloha": _backup_written,
    "zataz_pamate": _load_resident,
    "naprazdno": lambda: (True, TRIGGER_ONLY),
    "kontrola_wx_memfd": _control("kontrola_wx_memfd", _wx_memfd),
    "kontrola_modul_jadra": _control("kontrola_modul_jadra", _module),
    "kontrola_pocuvajuci_soket": _control("kontrola_pocuvajuci_soket", _socket),
    "kontrola_zapisovac_pamate": _control("kontrola_zapisovac_pamate", _writer),
    "kontrola_davka_procesov": _control("kontrola_davka_procesov", _batch),
}


def effect(kind, polarity="control", dose=None):
    """The effect predicate of the type (KOSTRA B5, section 3), of a control kind for the polarity (KOSTRA B8,
    section 2): {"ok", "predicate", "evidence"}.

    Never raises: a predicate that cannot be evaluated is false with the error as evidence,
    so that stop still restores the lab."""
    try:
        ok, evidence = EVALUATE[kind](polarity, dose) if kind in CONTROLS else EVALUATE[kind]()
    except Exception as exc:  # noqa: BLE001  Any failure means: no effect shown.
        ok, evidence = False, {"error": f"{type(exc).__name__}: {exc}"[:300]}
    predicates = NEGATIVE_PREDICATES if kind in CONTROLS and polarity == "negative" else PREDICATES
    return {"ok": ok is True, "predicate": predicates[kind], "evidence": evidence}


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


def wait_for(condition, seconds):
    """True as soon as condition() holds, False after `seconds`: the bounded waits of a control's start and stop."""
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(.1)
    return True


def program_arguments(kind, polarity, dose):
    """The arguments of a control's program after its text (the program's first comment names them)."""
    if kind == "kontrola_wx_memfd":
        return [polarity, str(NEGATIVE_FILE), str(PROGRAM_MAX_S)]
    if kind == "kontrola_pocuvajuci_soket":
        return [polarity, str(CONTROL_PORT), str(PROGRAM_MAX_S)]
    if kind == "kontrola_zapisovac_pamate":
        return [polarity, str(dose), str(WRITER_PERIOD_S), str(PROGRAM_MAX_S)]
    return [polarity, str(dose), str(BATCH_CHILD_S), str(PROGRAM_MAX_S)]


def _state_files(kind):
    return [STATE / (kind + suffix) for suffix in (".pid", ".before.json", ".out")]


def missing(kind, polarity, dose):
    """What of the occurrence is not in place yet, from /proc and the program's reports; empty once it is all there.
    Start returns only then: the rows of an occurrence begin one collection interval after its start (the executor's
    precision of design B8 section 1.3)."""
    sid, members = _members(kind)
    reports = _reports(kind)
    reporter = [pid for pid in members if any(r.get("pid") == pid for r in reports)]  # The program's own process.
    if kind == "kontrola_wx_memfd":
        parts = ([("the W+X page and the memfd in one process", bool(sid) and control_evidence(sid, PROC))]
                 if polarity == "control" else
                 [("the ready report", bool(reporter)),
                  ("the open file in /tmp", any(f.startswith(str(NEGATIVE_FILE)) for pid in reporter
                                                for f in _fd_targets(pid)))])
    elif kind == "kontrola_pocuvajuci_soket":
        held = {inode for pid in members for inode in _socket_inodes(pid)}
        parts = ([("the listening socket", any(e["inode"] in held for e in listeners(CONTROL_PORT, PROC)))]
                 if polarity == "control" else
                 [("the ready report", bool(reporter)),
                  ("the created socket", any(_socket_inodes(pid) for pid in reporter))])
    elif kind == "kontrola_zapisovac_pamate":
        parts = [("the first write of the dose", bool(reports) and reports[0].get("bytes") == dose << 20),
                 ("the dose resident", _peak_rss_kib(members) >= dose << 10)]
    else:
        parts = [("a report of the batch", bool(reports)), ("a running child", bool(_children(members)))]
    return [name for name, there in parts if not there]


def launch(kind, polarity, dose, modules_at_start):
    """Start the control or its paired negative (skeleton B8 section 1) and return once it is in place (missing);
    the leader's PID or None. The occurrence remembers the modules loaded at the session's start (`modules_at_start`,
    package B9) for its cleanup."""
    if kind == "kontrola_modul_jadra":
        name = module_candidate(PROC)
        values = {"polarity": polarity, "dose": dose, "module": name, "modules_before": len(loaded_modules(PROC)),
                  **devices(), "modules_at_start": modules_at_start}
        remember(kind, values)
        if polarity == "control":
            run("modprobe", name)
            if name not in loaded_modules(PROC):
                raise SystemExit(f"modprobe {name} returned, but the module is not in /proc/modules")
        else:
            dry = run("modprobe", "-n", "-v", name)
            remember(kind, {**values, "dry_run": {"returncode": dry.returncode, "stdout": dry.stdout.strip()[:300]}})
        return None
    remember(kind, {"polarity": polarity, "dose": dose, "modules_at_start": modules_at_start})
    leader = background(kind, ["runuser", "-u", "nobody", "--", "python3", "-c", PROGRAMS[kind],
                               *program_arguments(kind, polarity, dose)], output=STATE / (kind + ".out"))
    absent = []

    def in_place():
        absent[:] = missing(kind, polarity, dose)
        return not absent
    if not wait_for(in_place, START_WAIT_S):
        try:
            said = (STATE / (kind + ".out")).read_text()[-200:].strip()  # The program's error, if it printed one.
        except OSError:
            said = ""
        raise SystemExit(f"the {polarity} of {kind} is not in place within {START_WAIT_S} s, missing: "
                         + ", ".join(absent) + ("; the program printed: " + said if said else ""))
    return leader


def halt(kind):
    """Stop the occurrence: SIGTERM to its session and SIGKILL STOP_WAIT_S later if a process is left; the module of
    the module kind removed (modprobe -r), and named in STATE / LEFT_LOADED when it is still loaded after that, also
    after a failed modprobe -r (keep_left_loaded, finding F3 of the B9a verification); the negative's file and the
    state files deleted."""
    sid = kill_background(kind)
    name = remembered(kind, "module") if kind == "kontrola_modul_jadra" else None
    try:
        if sid and not wait_for(lambda: not session_members(sid, PROC), STOP_WAIT_S):
            signal_session(sid, signal.SIGKILL)
            wait_for(lambda: not session_members(sid, PROC), KILL_WAIT_S)
        if name and name in loaded_modules(PROC):
            run("modprobe", "-r", name)
        if kind == "kontrola_wx_memfd":
            NEGATIVE_FILE.unlink(missing_ok=True)
    finally:
        if type(name) is str:  # Before the state goes, which names it until then.
            keep_left_loaded(name)
        for path in _state_files(kind):
            path.unlink(missing_ok=True)
    return sid


def cleanup(kind, sid, modules_at_start, chosen):
    """Nothing of the occurrence remains after its stop (skeleton B8 section 2): no process of its session, no residue
    of any control (residues: a candidate module counts against the session's start `modules_at_start` and the
    modules a control chose, `chosen`), no state file of the kind. Never raises."""
    try:
        found = residues(PROC, modules_at_start, chosen)
        seen = {r["pid"] for r in found if r["residue"] == "process"}
        found += [{"residue": "process", "pid": pid, "cmdline": " ".join(_argv(pid))[:200]}
                  for pid in (session_members(sid, PROC) if sid else ()) if pid not in seen]
        found += [{"residue": "state", "path": str(path)} for path in _state_files(kind) if path.exists()]
    except Exception as exc:  # noqa: BLE001  A cleanup that cannot be shown is not ok.
        found = [{"residue": "error", "what": "the residues of the occurrence",
                  "error": f"{type(exc).__name__}: {exc}"[:300]}]
    return {"ok": not found, "residues": found, "evidence": [says(r) for r in found]}


def _message(exc):
    return f"{type(exc).__name__}: {exc}"[:300]


def control_start(kind, polarity, dose, levels, tolerance):
    """({baseline, started}, leader PID, error): nothing starts unless the return predicate holds (skeleton B8
    section 3: no waiting and no retry)."""
    import guest_state
    found = guest_state.baseline(levels, tolerance, sys.modules[__name__])
    if not found["ok"]:
        return {"baseline": found, "started": False}, None, "the return predicate does not hold"
    try:
        leader = launch(kind, polarity, dose, guest_state.start_modules(levels))
    except (Exception, SystemExit) as exc:  # noqa: BLE001  Whatever stops the start leaves a record; stop cleans.
        return {"baseline": found, "started": False}, None, _message(exc)
    return {"baseline": found, "started": True}, leader, None


def control_stop(kind, polarity, dose):
    """({effect, cleanup}, session, error): the effect while the occurrence is in place, then the stop, then the
    cleanup, also after a failed stop."""
    measured = effect(kind, polarity, dose)  # effect() never raises.
    sid = error = None
    # Read before halt deletes the occurrence's state (package B9, finding S2 of B8): the modules loaded at the
    # session's start, which its start remembered, and the candidate the module kind chose.
    at_start, chosen = remembered(kind, "modules_at_start"), chosen_modules()
    try:
        sid = _session_of(kind)
        halt(kind)
    except (Exception, SystemExit) as exc:  # noqa: BLE001  The cleanup below shows what a failed stop left.
        error = _message(exc)
    return {"effect": measured, "cleanup": cleanup(kind, sid, at_start, chosen)}, sid, error


CONTROL_USAGE = ("usage: udalosti.py start KIND --polarity control|negative [--dose D] --levels JSON "
                 "--tolerance JSON|null, or stop|effect KIND --polarity control|negative [--dose D]; --dose for "
                 + ", ".join(DOSES) + " only")


def control_command(argv):
    """(polarity, dose, levels, tolerance) of a control's command line (design B8, section 1.3), or SystemExit."""
    action, kind, rest = argv[0], argv[1], argv[2:]
    options = dict(zip(rest[::2], rest[1::2]))
    wanted = ({"--polarity"} | ({"--dose"} if kind in DOSES else set())
              | ({"--levels", "--tolerance"} if action == "start" else set()))
    if len(rest) != 2 * len(options) or set(options) != wanted:
        raise SystemExit(CONTROL_USAGE)
    if options["--polarity"] not in POLARITIES:
        raise SystemExit("invalid --polarity: control or negative")
    dose = None
    if kind in DOSES:
        if not options["--dose"].isdigit() or int(options["--dose"]) not in DOSES[kind]:
            raise SystemExit(f"invalid --dose for {kind}: one of " + ", ".join(map(str, DOSES[kind])))
        dose = int(options["--dose"])
    levels = tolerance = None
    if action == "start":
        import guest_state
        levels, tolerance = guest_state.levels_and_tolerance(options["--levels"], options["--tolerance"])
    return options["--polarity"], dose, levels, tolerance


def main(argv):
    control = len(argv) >= 2 and argv[0] in ACTIONS and argv[1] in CONTROLS
    if control:
        polarity, dose, levels, tolerance = control_command(argv)
    elif len(argv) != 2 or argv[0] not in ACTIONS or argv[1] not in TYPES:
        raise SystemExit("usage: udalosti.py start|stop|effect " + "|".join(TYPES) + "; for a control: "
                         + CONTROL_USAGE)
    action, kind = argv[:2]
    began = time.time()
    error = None
    pid = None
    measured = None
    fields = {}
    try:
        if control and action == "start":
            fields, pid, error = control_start(kind, polarity, dose, levels, tolerance)
        elif control and action == "stop":
            fields, pid, error = control_stop(kind, polarity, dose)
        elif control:
            fields = {"effect": effect(kind, polarity, dose)}
        elif action == "start":
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
    if control:
        record.update({"polarity": polarity, "dose": dose, **fields})
    if measured is not None:
        record["effect"] = measured
    print(json.dumps(record))


if __name__ == "__main__":
    os.umask(0o027)
    main(sys.argv[1:])
