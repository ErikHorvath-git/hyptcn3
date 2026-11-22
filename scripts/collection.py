#!/usr/bin/env python3
"""Plan, capture and audit benign research sessions. Never runs attack samples.

Original protocol tooling for hyptcn3. Data and verdicts are written exclusively;
failed sessions remain on disk. Run audit again with a new output name.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import fcntl
import functools
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.contract import validate_sidecar
from features.archive import load, save
from features.snapshot import retazec, MENA
from features.windows import snimky_z_matice
from features.perbin import FeatureError
from features.windows import WindowError
from features.quality import protocol_policy, coverage_gate, invalid_rows_rule, tolerated_invalid_rows
# ideal_windows is kept for a tracked record script under data/results, which reads it from this module.
from features.coverage import ideal_windows, scorable_windows
from features.acceptance import assignment, flagged_seq, judge, periodic_run, protocol_reachability, spacing_mode
from features.audit_policy import audit_bounds, exceptions_record, register, tolerate
from scripts.collection_logs import audit_logs
from scripts import protocol_v5
from lab.udalosti import CONTROLS as CONTROL_TYPES, TYPES as EVENT_TYPES

DEFAULT = ROOT / "config/collection-v2.json"
COLLECTIONS = ROOT / "data/collections"  # Global lock; diagnostics only change the session base.
DIAGNOSTICS = ROOT / "data/diagnostics"
SESSION_SCHEMA = "hyptcn3/collection-session/2"
END_SCHEMA = "hyptcn3/collection-end/2"
MEASUREMENT_DIRS = ("features", "guestparse", "safeguard", "scripts", "lab", "vmicollect")
SOURCE_SUFFIXES = (".py", ".c", ".h", ".sh", ".sql", ".conf", ".service")
# Reporting/documentation tools do not take part in capture, audit or archival.
NOT_MEASUREMENT = {"scripts/campaign_report.py", "scripts/gen_prirucka.py", "scripts/check_claims.sh",
                   "scripts/check_prirucka.sh",
                   # Keeps the chain of readiness records; each record stores this file's own hash.
                   "scripts/gates.py"}
# Measured 2026-10-20 on the working SSD with fsync: full snapshots took
# 4.7-10.7 s (period 5 s) after sustained delta writes. Without fsync a
# snapshot is published from the page cache; its SHA-256 (sidecar) is re-checked
# by the audit and by the fsynced, decompression-verified archive. A crash can
# lose an unarchived session, which then is incomplete - never silently accepted.
COLLECTOR_FSYNC = False
# The collector's sampling cycle does no file I/O: its writer thread creates,
# writes, hashes and renames snapshots and sidecars, and its log thread writes
# collect.log (campaign benign-v4-20261022 lost a slot when a cycle waited on SSD
# writeback). mlockall keeps the collector's own memory (queue, buffers, code)
# resident, so a cycle takes no page fault or swap-in on it; reading guest RAM can
# still fault in swapped-out QEMU pages (vm.swappiness 1 and the prefault step).
COLLECTOR_MLOCK = True
# The log audit rejects a guest clock offset above 1 s at either end. Measured
# drift was below 0.04 s/h (2026-10-20), so a session synchronized to 0.25 s
# keeps that margin for its whole hour.
CLOCK_SYNC_S = .25
VM_NAME = r"[a-z0-9]{1,16}"
# Session base of a multi-VM capture outside a campaign (pilot); not a valid campaign name.
STANDALONE = "_bez-kampane"
# Why a campaign session is not used; the first one is what a rule without "covers" replaces.
REPLACEMENT_CAUSES = ("audit_rejected", "capture_incomplete")


def digest(path):
    with Path(path).open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256").hexdigest()
        drop_cache(stream.fileno())
        return value


DROP_CACHE_MIN = 16 << 20


def drop_cache(fd):
    """Release the page cache of a large file just read or written (best effort).

    Campaign normal-v4-20261115: hashing, auditing and archiving a 17 GB session
    filled the page cache, the kernel swapped the idle QEMU of the other VM to
    the HDD, and that VM's guest agent and collector then missed their deadlines.
    """
    try:
        if os.fstat(fd).st_size >= DROP_CACHE_MIN:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except (OSError, AttributeError):
        pass


# Background work beside another VM's capture (audit, archive compression): lowest
# CPU and best-effort IO priority. As root the audit also gets its own transient
# scope whose memory (including its page cache) is capped and never swapped, so the
# kernel reclaims inside the scope instead of pushing other VMs' QEMU to swap.
BACKGROUND_NICE = ["nice", "-n", "19", "ionice", "-c", "2", "-n", "7"]
BACKGROUND_SCOPE = ["systemd-run", "--scope", "--quiet", "--collect",
                    "-p", "MemoryHigh=3G", "-p", "MemorySwapMax=0",
                    "-p", "CPUWeight=20", "-p", "IOWeight=20", "--"]


def background_command(command):
    prefix = BACKGROUND_NICE if all(shutil.which(c) for c in ("nice", "ionice")) else []
    if os.geteuid() == 0 and shutil.which("systemd-run"):
        prefix = BACKGROUND_SCOPE + prefix
    return [*prefix, *map(str, command)]


def write_json(path, doc):
    with Path(path).open("x") as stream:
        json.dump(doc, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def protocol(path):
    p = json.loads(Path(path).read_text())
    schema3 = type(p) is dict and p.get("schema") == protocol_v5.SCHEMA
    if schema3:
        # Schema 3 is the v5 layout: no unknown and no missing key, and well-formed v5 sections. Balance, role sizes,
        # the place of null values and the gate's binding to invalid_rows.max are the self-check's (selfcheck).
        protocol_v5.check_layout(p)
    protocol_policy(p)
    coverage_gate(p)
    for key in ("interval_s", "window_rows", "full_every", "cycles", "pilot_cycles", "bin_bytes"):
        if type(p[key]) is not int or p[key] < 1:
            raise ValueError("invalid " + key)
    if p.get("stride") != 1:
        raise ValueError("collection and live scoring require stride 1")
    if not p["interval_s"] < p["max_gap_s"] < 2 * p["interval_s"]:
        raise ValueError("gap must distinguish a missed sampling slot")
    if p["full_every"] <= p["window_rows"] or p["pilot_cycles"] <= p["full_every"] + p["window_rows"]:
        raise ValueError("pilot must cover two full snapshots and score after both")
    # Schema 3 states the bounds of the audit checks and the register of what the audit admits; both readers
    # refuse a missing or malformed section, and older schemas carry neither (features/audit_policy.py).
    audit_bounds(p)
    register(p)
    # A faultless session of each assigned length must be acceptable, decided as the audit decides it.
    for case in protocol_reachability(p):
        if case["case"] == "clean" and not case["accepted"]:
            raise ValueError("score coverage gate is unreachable for " + case["key"])
    if p["bin_bytes"] != 16777216:
        raise ValueError("capture runner currently supports 16 MiB bins")
    if "events" in p and not schema3:  # Schema 3 events are checked by protocol_v5.check_layout.
        check_events(p)
    if "vms" in p:
        check_vms(p)
    if "replacement" in p:
        check_replacement(p)
    if "invalid_rows" in p:
        check_invalid_rows(p)
    return p


def check_invalid_rows(p):
    """Pre-registered tolerance of a few rows whose traversal did not close (owner, 2026-11-17).

    Without the key every invalid row rejects the session. With it a session of a role
    the protocol plans, or a diagnostic session, is admitted when at most `max` rows are
    invalid, each only because one of the named traversals did not close (no RAM read
    error or zero fill), and the score coverage gate still holds; a pilot, and a session
    whose role the protocol does not assign, gets no tolerance (features/acceptance.py,
    assignment). Invalid rows are never scored (their windows are not scorable) and the
    audit lists them.

    One invalid row away from the others costs window_rows + 1 windows: the row itself
    and the window_rows rows that refill the buffer. Protocol version 3 therefore
    requires that a full session with `max` such rows, placed where they cost the most,
    is still accepted (features/acceptance.py decides it as it decides a real session);
    under version 2 the two rules could contradict each other (v4: 3 rows allowed,
    1 passed the gate).
    """
    invalid_rows_rule(p)  # The shape check is shared with every reader of the rule (features/quality.py).
    if p["schema"] == "hyptcn3/collection-protocol/3":
        if any(case["case"] == "worst" and not case["accepted"] for case in protocol_reachability(p)):
            raise ValueError("invalid_rows.max is unreachable under the score coverage gate")


def check_replacement(p):
    """Pre-registered rule for sessions the campaign cannot use (scripts/campaign.py reject).

    Without the key nothing is ever replaced. The only rule: at most max_per_campaign
    such sessions of a campaign are captured again, each as the same assignment
    (VM, role, group, scenario, seed) in the same group boot. "covers" names the
    causes the rule applies to; without it only audit rejections, as before:
      audit_rejected      the capture completed and its audit rejected it
      capture_incomplete  the measured phase started but the capture did not complete
                          (collector failure, interruption, guest change); replaced only
                          while the group's boot and QEMU process are still the recorded
                          ones - after a reboot or restart the group's boot is gone and
                          the campaign stops
    All causes share the one per-campaign maximum. Under schema 3 the maximum may be null until stage G3b
    determines it (proposal 7.5).
    """
    r = p["replacement"]
    limit = r.get("max_per_campaign") if type(r) is dict else None
    if p.get("schema") == protocol_v5.SCHEMA and type(r) is dict and "covers" not in r:
        raise ValueError("missing protocol key: replacement.covers")  # Schema 3 states every cause (no default).
    if (type(r) is not dict
            or not {"max_per_campaign", "same"} <= set(r) <= {"max_per_campaign", "same", "covers", "note"}
            or not (type(limit) is int and limit >= 0 or limit is None and p.get("schema") == protocol_v5.SCHEMA)
            or type(r["same"]) is not list or sorted(map(str, r["same"])) != ["role", "scenario", "vm"]):
        raise ValueError("invalid replacement rule")
    covers = r.get("covers", list(REPLACEMENT_CAUSES[:1]))
    if (type(covers) is not list or not covers or len(set(map(str, covers))) != len(covers)
            or not set(map(str, covers)) <= set(REPLACEMENT_CAUSES)):
        raise ValueError("invalid replacement rule")


def check_vms(p):
    """Several lab VMs measured concurrently on one host, each with its own domain and host port."""
    rows = p["vms"]
    if "domain" in p or "target" in p or type(rows) is not list or not rows:
        raise ValueError("a protocol names either vms or one domain/target")
    for row in rows:
        if (type(row) is not dict or set(row) != {"name", "domain", "port"}
                or type(row["name"]) is not str or not re.fullmatch(VM_NAME, row["name"])
                or type(row["domain"]) is not str or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,50}", row["domain"])
                or type(row["port"]) is not int or not 1024 <= row["port"] <= 65535):
            raise ValueError("invalid VM in protocol")
    if any(len({row[key] for row in rows}) != len(rows) for key in ("name", "domain", "port")):
        raise ValueError("VM names, domains and ports must be unique")
    # A schema-3 role may plan no group at all (a test protocol's test_controls); the self-check judges sizes.
    planned = [n for n in p["roles"].values() if n or p.get("schema") != protocol_v5.SCHEMA]
    if any(count < len(rows) for count in planned):
        raise ValueError("every role needs a boot group on every VM")


def vms(p):
    """VMs of a protocol; a protocol with one domain/target is one unnamed VM (original layout)."""
    if "vms" not in p:
        return [{"name": None, "domain": p["domain"], "target": p["target"]}]
    return [{**row, "target": f"http://127.0.0.1:{row['port']}"} for row in p["vms"]]


def for_vm(p, name):
    """The protocol as seen by one VM's capture: its domain and target under the single-VM keys."""
    rows = {row["name"]: row for row in vms(p)}
    if name not in rows:
        raise ValueError("protocol has no VM " + str(name) if name is not None else
                         "protocol names several VMs; choose one of: " + ", ".join(rows))
    if name is None:
        return p
    return {**p, "vm": name, "domain": rows[name]["domain"], "target": rows[name]["target"], "port": rows[name]["port"]}


def labctl_args(p):
    """labctl options selecting this VM (the unnamed VM keeps labctl's original defaults)."""
    return ["--domain", p["domain"], *(["--vm", p["vm"], "--port", str(p["port"])] if p.get("vm") else [])]


EVENT_KEYS = {"note", "classes", "per_session", "duration_s", "first_s", "min_gap_s", "tail_s", "grace_s", "pilot"}


def check_events(p):
    """Protocol v3: benign operational events scheduled inside the measured interval."""
    e = p["events"]
    if set(e) - {"pilot_controls"} != EVENT_KEYS or not e["classes"] or not set(e["classes"]) <= set(EVENT_TYPES):
        raise ValueError("invalid event configuration")
    controls = e.get("pilot_controls", [])
    if not isinstance(controls, list) or any(
            not isinstance(c, dict) or set(c) != {"type", "start_s", "duration_s"} or c["type"] not in CONTROL_TYPES
            or any(type(c[k]) is not int or c[k] < 1 for k in ("start_s", "duration_s")) for c in controls):
        raise ValueError("invalid pilot control configuration")
    numbers = [*e["per_session"], *e["duration_s"], e["first_s"], e["min_gap_s"], e["tail_s"], e["grace_s"]]
    if any(type(v) is not int or v < 1 for v in numbers) or e["per_session"][0] > e["per_session"][1] \
            or e["duration_s"][0] > e["duration_s"][1] or e["grace_s"] >= e["min_gap_s"]:
        raise ValueError("invalid event configuration")
    longest = e["first_s"] + e["per_session"][1] * e["duration_s"][1] + (e["per_session"][1] - 1) * e["min_gap_s"]
    if longest + e["tail_s"] > p["cycles"] * p["interval_s"]:
        raise ValueError("event schedule does not fit the session")
    check_schedule(p, pilot_events(p), p["pilot_cycles"])


CONTROL_CLASS = "pozitivna_kontrola"


def pilot_events(p):
    """Pilot schedule: the protocol's pilot events and its positive controls, by start time.

    A positive control (lab/udalosti.py CONTROLS) runs only in the pilot, never in a
    corpus or event session, and carries the class 'pozitivna_kontrola'.
    """
    e = p["events"]
    merged = [dict(x, **{"class": e["classes"][x["type"]]}) for x in e["pilot"]]
    merged += [dict(x, **{"class": CONTROL_CLASS}) for x in e.get("pilot_controls", [])]
    return sorted(merged, key=lambda x: x["start_s"])


def check_schedule(p, events, cycles):
    e, end = p["events"], 0
    allowed = set(e["classes"]) | {c["type"] for c in e.get("pilot_controls", [])}
    for event in sorted(events, key=lambda x: x["start_s"]):
        if event["type"] not in allowed or event["start_s"] < max(e["first_s"], end + e["min_gap_s"] * bool(end)):
            raise ValueError("event schedule violates the protocol")
        end = event["start_s"] + event["duration_s"]
    if events and end + e["tail_s"] > cycles * p["interval_s"]:
        raise ValueError("event schedule does not fit the session")


def event_schedule(p, seed, deck):
    """Seeded offsets from the measurement start; types are drawn from the group's deck."""
    e, rng = p["events"], random.Random(seed)
    events, start = [], e["first_s"]
    for _ in range(rng.randint(*e["per_session"])):
        kind = deck.pop(0)
        duration = rng.randrange(e["duration_s"][0], e["duration_s"][1] + 1, 30)
        events.append({"type": kind, "class": e["classes"][kind], "start_s": start, "duration_s": duration})
        start += duration + e["min_gap_s"]
    # Slack (the longest schedule fits) moves the whole block by a seeded offset.
    slack = p["cycles"] * p["interval_s"] - e["tail_s"] - (start - e["min_gap_s"])
    shift = rng.randrange(0, slack // 30 + 1) * 30
    return [dict(event, start_s=event["start_s"] + shift) for event in events]


def plan(p):
    if p.get("schema") == protocol_v5.SCHEMA:
        return protocol_v5.plan(p, mode="campaign")  # The v5 schedule (balanced blocks, streams, events, controls).
    result = []
    names = [row["name"] for row in vms(p)]
    # Each role/repetition is a separate boot group. Adjacent chunks of a
    # running VM cannot become independent train/calibration/test sessions.
    for index, (role, count) in enumerate(p["roles"].items()):
        for repetition in range(count):
            # A group is one boot of one VM. Groups of a role rotate over the VMs and the
            # rotation shifts with every round and role (a b | b a | a b ...), so each role
            # has groups on every VM and neither odd nor even group numbers share one VM.
            # Each VM takes its own groups in this (role) order.
            vm = names[(repetition + repetition // len(names) + index) % len(names)]
            scenarios = list(p["scenarios"])
            seed = int.from_bytes(hashlib.sha256(f"{role}/{repetition}".encode()).digest()[:4], "big")
            random.Random(seed).shuffle(scenarios)
            deck = []  # Every event type before any repeats, within each group.
            for scenario in scenarios:
                session = {"role": role, "group": f"{p.get('group_prefix', '')}{role}-{repetition + 1}",
                           "scenario": scenario, "seed": seed + len(result), "cycles": p["cycles"]}
                if vm is not None:
                    session["vm"] = vm
                if "events" in p:
                    rng = random.Random(session["seed"])
                    while len(deck) < p["events"]["per_session"][1]:
                        deck.extend(rng.sample(sorted(p["events"]["classes"]), len(p["events"]["classes"])))
                    session["events"] = event_schedule(p, session["seed"], deck)
                result.append(session)
    return {"schema": "hyptcn3/collection-plan/1", "sessions": result,
            **({} if names == [None] else
               {"sessions_per_vm": {name: sum(s["vm"] == name for s in result) for name in names}}),
            "planned_hours": len(result) * p["cycles"] * p["interval_s"] / 3600,
            "note": "Design allocation, not collected data; pilot and overhead runs are separate."}


def user_command(command):
    user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and user:
        import pwd
        uid = pwd.getpwnam(user).pw_uid
        # LIBVIRT_AUTOSTART=0: a missing session daemon is an error here. An
        # auto-spawned daemon would live (and die) inside the runner's cgroup.
        return ["runuser", "-u", user, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}", "LIBVIRT_AUTOSTART=0",
                *map(str, command)]
    return list(map(str, command))


def is_measurement(name):
    """Code that captures, checks or archives data (tests and reports excluded), and every file `labctl deploy`
    puts into the guest (lab_files(): the top-level files of lab/, whatever their suffix; finding S7 of B3)."""
    path = Path(name)
    deployed = len(path.parts) == 2 and path.parts[0] == "lab"
    return (path.parts[0] in MEASUREMENT_DIRS and (path.suffix in SOURCE_SUFFIXES or deployed)
            and "tests" not in path.parts and name not in NOT_MEASUREMENT)


def measurement_sources():
    files = [f for d in MEASUREMENT_DIRS for f in (ROOT / d).rglob("*")
             if f.is_file() and is_measurement(str(f.relative_to(ROOT)))]
    return {str(f.relative_to(ROOT)): digest(f) for f in sorted(files)}


def measurement_dirty():
    """Measurement sources that differ from the commit, including new untracked files.

    Unlike commit_dirty (whole worktree), notes or reports written during a
    capture or audit do not make its provenance unusable.
    """
    entries = subprocess.check_output(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all",
                                       "--", *MEASUREMENT_DIRS], cwd=ROOT).split(b"\0")
    names, i = [], 0
    while i < len(entries) and entries[i]:
        names.append(entries[i][3:].decode())
        if set(entries[i][:2]) & set(b"RC"):  # A rename/copy is followed by its source path.
            i += 1
            names.append(entries[i].decode())
        i += 1
    return sorted({name for name in names if is_measurement(name)})


def storage_identity(path):
    """Filesystem holding a working directory; device names (sdX) may change at boot."""
    doc = json.loads(subprocess.check_output(["findmnt", "-J", "-T", str(path), "-o", "TARGET,FSROOT,FSTYPE,UUID"],
                                             text=True, timeout=10))
    return doc["filesystems"][0]


def lab_json(p, *args, timeout=600):
    """labctl as the VM owner (qemu:///session); its reply is one JSON document."""
    command = [sys.executable, ROOT / "scripts/labctl.py", *labctl_args(p), *args]
    return json.loads(subprocess.check_output(user_command(command), cwd=ROOT, text=True, timeout=timeout))


@contextmanager
def collection_lock(base, domain=None):
    """A campaign passes the same open lock to its capture child only.

    Without a domain (single-VM protocol) the lock is exclusive for the whole
    host, as before. A VM of a multi-VM protocol holds .lock shared - a single-VM
    run or the detector (both exclusive) still excludes it and is excluded by it -
    and its own .lock-<domain> exclusively, so only the same domain is refused.
    """
    base.mkdir(parents=True, exist_ok=True)
    path = base / (".lock" if domain is None else ".lock-" + domain)
    shared = None
    if domain is not None:
        shared = os.open(base / ".lock", os.O_CREAT | os.O_RDWR, 0o644)
    inherited = os.environ.get("HYPTCN_COLLECTION_LOCK_FD")
    try:
        if shared is not None:
            fcntl.flock(shared, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fd = os.dup(int(inherited)) if inherited else os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            stat, expected = os.fstat(fd), path.stat() if path.exists() else None
            if expected is None or (stat.st_dev, stat.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValueError("inherited collection lock refers to another file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)
    finally:
        if shared is not None:
            os.close(shared)


def session_records(root):
    """(path, start record) of every session under a collections directory.

    Covers the flat layout (<session>) and the multi-VM one (<campaign>/<vm>/<session>).
    Another VM's runner may be writing or retiring a session at this moment.
    """
    for pattern in ("*/session.json", "*/*/*/session.json"):
        for path in sorted(Path(root).glob(pattern)):
            for attempt in range(5):
                try:
                    yield path, json.loads(path.read_text())
                    break
                except FileNotFoundError:
                    break  # Renamed to a numbered attempt meanwhile; that name is not in this listing.
                except json.JSONDecodeError:
                    if attempt == 4:
                        raise
                    time.sleep(.2)


LAB_DEPLOYED = "/opt/hyptcn-lab/"  # labctl deploy unpacks every top-level file of lab/ here.
# lab/install.sh installs two of them once more outside the deployment directory.
LAB_INSTALLED = {"/etc/nginx/conf.d/hyptcn-lab.conf": "lab/nginx.conf",
                 "/etc/systemd/system/hyptcn-lab@.service": "lab/hyptcn-lab@.service"}


def lab_files():
    """Every top-level file of lab/: the set `labctl deploy` puts into the guest."""
    return [f for f in sorted((ROOT / "lab").iterdir()) if f.is_file()]


def lab_sha256():
    """{lab/<name>: SHA-256} of the deployed set (session.json lab_sha256)."""
    return {f"lab/{f.name}": digest(f) for f in lab_files()}


def deployed_paths(names):
    """Guest path -> lab/ source of every file a deployment of the lab/ files `names` leaves in the guest."""
    paths = {LAB_DEPLOYED + Path(name).name: name for name in sorted(names)}
    paths.update(LAB_INSTALLED)
    return paths


def guest_mismatch(identity, lab):
    """Deployed guest paths whose hash in identity["stack_manifest"] differs from lab/ (`lab` as lab_sha256 gives
    it) or is missing there; [] when the guest runs exactly the lab/ files of this commit."""
    seen = {}
    manifest = identity.get("stack_manifest") if type(identity) is dict else None
    for line in manifest if type(manifest) is list else []:
        match = re.fullmatch(r"([0-9a-f]{64})  (/\S+)", line) if type(line) is str else None
        if match:  # A sha256sum line; the package and timer lines of the manifest are not files.
            seen[match[2]] = match[1]
    lab = lab if type(lab) is dict else {}
    return sorted(path for path, source in deployed_paths(lab).items() if seen.get(path) != lab.get(source))


def guest_identity(p):
    paths = list(deployed_paths(f"lab/{f.name}" for f in lab_files()))
    identity_command = (
        "uname -r; cat /proc/sys/kernel/random/boot_id; cat /etc/machine-id; "
        # Every deployed file of lab/ and the two installed copies (guest_mismatch compares them with lab/).
        f"sha256sum {' '.join(map(shlex.quote, paths))} && "
        "dpkg-query -W nginx postgresql python3 python3-psycopg2 && "
        # Active (waiting) timers can start unplanned work; lab/install.sh leaves none.
        "echo \"timers: $(systemctl list-units --type=timer --state=active --no-legend --plain"
        " | awk '{print $1}' | sort | tr '\\n' ' ')\"")
    command = [sys.executable, ROOT / "scripts/labctl.py", "exec", *labctl_args(p),
               "--guest-command", identity_command]
    lines = subprocess.check_output(user_command(command), cwd=ROOT, text=True, timeout=150).strip().splitlines()
    # Three identity lines, one line per hashed file, four packages and the timers.
    if len(lines) < 3 + len(paths) + 5 or not lines[-1].startswith("timers:"):
        raise ValueError("cannot establish guest identity")
    return {**dict(zip(("kernel", "boot_id", "machine_id"), lines[:3])),
            "stack_sha256": hashlib.sha256("\n".join(lines[3:]).encode()).hexdigest(),
            "stack_manifest": lines[3:]}


class Interrupts:
    """The first SIGINT/SIGTERM/SIGHUP interrupts the run once; later ones are only recorded.

    Repeated signals (systemd plus a forwarding parent, or an impatient
    operator) must not cut the cleanup that writes the truthful end record.
    """

    def __init__(self):
        self.received, self.armed = [], True
        # SIGHUP (closed SSH terminal) also ends in an orderly, recorded stop.
        self.previous = {s: signal.signal(s, self.handle) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

    def handle(self, signum, _frame):
        self.received.append({"signal": signum, "unix": time.time()})
        if self.armed:
            self.armed = False
            raise InterruptedError(f"interrupted by signal {signum}")

    def disarm(self):
        self.armed = False

    def restore(self):
        for sig, handler in self.previous.items():
            signal.signal(sig, handler)


def _child_setup():
    """New session plus SIGTERM if the runner itself dies (even by SIGKILL)."""
    os.setsid()
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG


def start_child(command, log, env=None):
    with open(log, "x") as stream:
        return subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, preexec_fn=_child_setup)


def stop_child(process, grace, *, first=signal.SIGTERM):
    """Signal the child's own process group, wait, escalate; report what happened."""
    if process is None:
        return None
    if process.poll() is not None:
        return {"pid": process.pid, "rc": process.returncode, "stopped_by": "exited"}
    result = {"pid": process.pid, "stopped_by": signal.Signals(first).name}
    try:
        os.killpg(process.pid, first)
        process.wait(timeout=grace)
    except ProcessLookupError:
        process.wait()
    except subprocess.TimeoutExpired:
        result["stopped_by"] = "SIGKILL after %ss" % grace
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    result["rc"] = process.returncode
    return result


def is_generator(argv):
    """A process executing host_traffic.py, not one that merely mentions it in an argument."""
    if not argv:
        return False
    target = argv[0]
    if Path(argv[0].decode(errors="replace")).name.startswith("python"):
        target = next((arg for arg in argv[1:] if not arg.startswith(b"-")), b"")
    return Path(target.decode(errors="replace")).name == "host_traffic.py"


def option(argv, name):
    """Value of '--name value' or '--name=value' in a command line, else None."""
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(name + b"="):
            return arg[len(name) + 1:]
    return None


def is_collector(argv, domain):
    """A vmicollect process reading the RAM of this domain."""
    return (bool(argv) and Path(argv[0].decode(errors="replace")).name == "vmicollect"
            and f"vm.domain={domain}".encode() in argv)


def processes():
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            yield int(proc.name), [arg for arg in (proc / "cmdline").read_bytes().split(b"\0") if arg]
        except OSError:
            continue


def generators(exclude=(), target=None):
    """Host generator processes not started by this session.

    With a target (VM of a multi-VM protocol) only generators aimed at that
    VM count; another VM's session runs its own generator at the same time.
    """
    return [pid for pid, argv in processes() if is_generator(argv) and pid not in exclude
            and (target is None or option(argv, b"--target") == target.encode())]


def collectors(domain):
    return [pid for pid, argv in processes() if is_collector(argv, domain)]


def foreign_traffic(p, exclude=()):
    return generators(exclude, p["target"] if p.get("vm") else None)


def other_vms(p):
    """Cheap /proc view of the protocol's other VMs: is each running, collected or loaded right now."""
    return [{"vm": row["name"], "domain": row["domain"], "qemu": qemu_process(row["domain"]),
             "collectors": collectors(row["domain"]), "generators": generators(target=row["target"])}
            for row in vms(p) if row["name"] != p.get("vm")]


def monitor_matches(p):
    """host_monitor process labels. The session's own VM keeps the original labels; the other
    VMs of the protocol are recorded as label@vm. Host-wide CPU, memory, swap and disk
    counters are part of every monitor record."""
    if not p.get("vm"):
        return [f"qemu=guest={p['domain']},", "vmicollect=vmicollect/build/vmicollect",
                "traffic=host_traffic.py", "passt=^passt ", "monitor=host_monitor.py"]
    matches = ["monitor=host_monitor.py"]
    for row in vms(p):
        suffix = "" if row["name"] == p["vm"] else "@" + row["name"]
        domain, target = re.escape(row["domain"]), re.escape(row["target"])
        matches += [f"qemu{suffix}=guest={domain},",
                    f"vmicollect{suffix}=vmicollect/build/vmicollect .*vm\\.domain={domain}( |$)",
                    f"traffic{suffix}=host_traffic\\.py .*--target[ =]{target}( |$)",
                    # libvirt names the passt socket after the domain; the forwarded port is the fallback.
                    f"passt{suffix}=^passt .*(-{domain}-net[0-9]+\\.socket|/{row['port']}:)"]
    return matches


def qemu_process(domain):
    """Identity of the running QEMU process; changes when the VM is restarted or restored."""
    marker = f"guest={domain},".encode()
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            argv = (proc / "cmdline").read_bytes()
            stat = (proc / "stat").read_text()
        except OSError:
            continue
        if argv.startswith(b"/usr/bin/qemu-system") and marker in argv:
            return {"pid": int(proc.name), "start_ticks": int(stat.rsplit(")", 1)[1].split()[19]),
                    "host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    return None


def qemu_swap_kb(pid):
    try:
        return int(re.search(r"^VmSwap:\s+(\d+) kB$", Path(f"/proc/{pid}/status").read_text(), re.M)[1])
    except (OSError, TypeError):
        return None


def qemu_swap_max(pid, proc=Path("/proc"), cgroups=Path("/sys/fs/cgroup")):
    """Text of memory.swap.max of the process's cgroup v2 ("0" forbids swap), None when unreadable.

    Reading only: the VM start sets it (package B5); campaigns v4 and v4c lost slots to a swapped QEMU.
    """
    try:
        for line in (Path(proc) / str(pid) / "cgroup").read_text().splitlines():
            hierarchy, _, path = line.split(":", 2)
            if hierarchy == "0":  # The unified (v2) hierarchy.
                return (Path(cgroups) / path.lstrip("/") / "memory.swap.max").read_text().strip()
    except (OSError, ValueError):
        pass
    return None


def host_memory(qemu):
    """Swap policy and swapped-out QEMU memory. A full snapshot reads all guest RAM.

    2026-10-21: with vm.swappiness=60 and swap on the system HDD, 322 MiB of QEMU
    memory were swapped out before a pilot; its first full snapshot then read
    925 MiB in 7.3 s (period 5 s) and dropped a sampling slot.
    """
    return {"vm_swappiness": int(Path("/proc/sys/vm/swappiness").read_text()),
            "qemu_swap_kb": qemu_swap_kb(qemu["pid"]) if qemu else None,
            "qemu_swap_max": qemu_swap_max(qemu["pid"]) if qemu else None}


def swapped_ranges(smaps):
    """Address ranges of mappings that have swapped-out pages, from /proc/PID/smaps."""
    ranges, current = [], None
    for line in smaps.splitlines():
        head = re.match(r"([0-9a-f]+)-([0-9a-f]+) ", line)
        if head:
            current = (int(head[1], 16), int(head[2], 16))
        elif line.startswith("Swap:") and current and int(line.split()[1]) > 0:
            ranges.append(current)
    return ranges


def prefault_swapped(pid, chunk=8 << 20):
    """Read swapped-out QEMU memory back in before the measured phase (root; read-only)."""
    before, started = qemu_swap_kb(pid), time.monotonic()
    if before:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            for start, end in swapped_ranges(Path(f"/proc/{pid}/smaps").read_text()):
                for offset in range(start, end, chunk):
                    try:
                        mem.seek(offset)
                        mem.read(min(chunk, end - offset))
                    except OSError:
                        pass  # An unreadable range stays as it is; the audit sees any stall.
    return {"swap_kb_before": before, "swap_kb_after": qemu_swap_kb(pid),
            "seconds": round(time.monotonic() - started, 3)}


def qemu_guest_bytes(pid):
    """Guest RAM size from the QEMU command line ('-m size=2097152k' as libvirt writes it, or MiB)."""
    argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    value = argv[argv.index(b"-m") + 1].decode() if b"-m" in argv else ""
    m = re.fullmatch(r"(?:size=)?(\d+)([kKmMgG]?)(?:,.*)?", value)
    if not m:
        raise ValueError(f"cannot read the guest RAM size of QEMU {pid}")
    return int(m[1]) << {"k": 10, "": 20, "m": 20, "g": 30}[m[2].lower()]


def collector_memory(pid):
    """The collector locks its queue memory (output.mlock): pool for a full snapshot of every guest
    page plus 512 MiB, descriptors, the guest RAM QEMU may still take and a 2 GiB reserve
    (vmicollect collector.c check_memory). Checked here before the measured phase as well, so a
    shortfall ends the attempt before measurement (the campaign retries it) and not at collector start."""
    guest = qemu_guest_bytes(pid)
    resident = int(re.search(r"^RssAnon:\s+(\d+) kB$", Path(f"/proc/{pid}/status").read_text(), re.M)[1]) << 10
    chunk = (1 << 20) - 8
    pool = -(-(guest // 4096) * 4104 // chunk) * (1 << 20) + (512 << 20)
    need = pool + (64 << 20) + max(0, guest - resident) + (2 << 30)
    meminfo = Path("/proc/meminfo").read_text()
    available = int(re.search(r"^MemAvailable:\s+(\d+) kB$", meminfo, re.M)[1]) << 10
    return {"guest_bytes": guest, "qemu_rss_anon_bytes": resident, "pool_bytes": pool,
            "need_bytes": need, "available_bytes": available, "ok": available >= need}


def file_record(path):
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    record = {"size": path.stat().st_size, "sha256": sha}
    if path.suffix in (".jsonl", ".log"):
        with path.open("rb") as stream:
            data = stream.read()
        record["lines"] = data.count(b"\n")
        record["terminated"] = not data or data.endswith(b"\n")
    return record


def write_logs_manifest(out):
    """Hash evidence plus collector log/status; RAM hashes live in sidecars."""
    files = {}
    for path in sorted(out.rglob("*")):
        name = path.relative_to(out).as_posix()
        if (path.is_file() and not path.is_symlink()
                and (not name.startswith("raw/") or name in ("raw/collect.log", "raw/capture.json"))
                and name not in ("session.json", "end.json", "logs_manifest.json")
                and not re.fullmatch(r"(campaign_)?audit_.*", name)):
            files[name] = file_record(path)
    doc = {"schema": "hyptcn3/session-logs/1", "date": datetime.now(timezone.utc).isoformat(), "files": files}
    write_json(out / "logs_manifest.json", doc)
    return digest(out / "logs_manifest.json")


def wait_healthy(target, timeout=30):
    """Poll /healthz until 200: a forward clock step briefly makes the worker heartbeat stale."""
    deadline = time.monotonic() + timeout
    run_id = "health" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    attempt = 0
    while True:
        attempt += 1
        request = urllib.request.Request(target + "/healthz", headers={"X-Request-ID": f"{run_id}-{attempt:04d}"})
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:
                if reply.status == 200:
                    return attempt
        except OSError:  # Includes HTTP errors such as 503 "worker stale".
            pass
        if time.monotonic() >= deadline:
            raise ValueError("lab stack not healthy before the preflight check")
        time.sleep(1)


def smoke_rids(path):
    return {c["rid"]: c["status"] for c in json.loads(Path(path).read_text())["values"]["checks"]}


def nginx_lines(path):
    with gzip.open(path, "rt") as stream:
        for line in stream:
            yield json.loads(line)


def run_session(a, p):
    # No capture without a passed self-test of the audit checks for this code and this protocol file.
    from scripts.audit_selftest import require_selftest
    require_selftest(a.protocol)
    if os.geteuid() != 0:
        raise ValueError("host eBPF capture needs sudo; plan and audit do not")
    if a.scenario not in p["scenarios"]:
        raise ValueError("unknown benign scenario")
    vm = p.get("vm")
    campaign = getattr(a, "campaign_id", None)
    if vm and campaign is not None and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", campaign):
        raise ValueError("invalid campaign ID")
    base = Path(getattr(a, "collections_dir", None) or COLLECTIONS).absolute()
    diagnostic = a.role == "diagnostic"
    if vm and not diagnostic:
        # One directory per VM: <campaign>/<vm>/<session>; a single-VM protocol keeps <session>.
        base = base / (campaign or STANDALONE) / vm
    if diagnostic != base.is_relative_to(DIAGNOSTICS):
        raise ValueError("diagnostic runs (and only they) must use a directory under data/diagnostics")
    if getattr(a, "cycles", None) and not diagnostic:
        raise ValueError("--cycles is only allowed for diagnostic runs")
    created = [d for d in (base.parent.parent, base.parent, base) if vm and not diagnostic and not d.exists()]
    base.mkdir(parents=True, exist_ok=True)
    if "SUDO_UID" in os.environ:
        for directory in created:  # Like the sessions below them, owned by the operator.
            os.chown(directory, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    with collection_lock(COLLECTIONS, p["domain"] if vm else None):
        before = guest_identity(p)
        lab = lab_sha256()
        mismatch = guest_mismatch(before, lab)
        if mismatch:
            raise ValueError("deployed guest files differ from lab/ in this commit: " + ", ".join(mismatch))
        if getattr(a, "expected_boot_id", None) and before["boot_id"] != a.expected_boot_id:
            raise ValueError("guest boot differs from campaign group")
        qemu = qemu_process(p["domain"])
        if qemu is None:
            raise ValueError("VM process not found")
        # A restore keeps the guest boot ID but starts a new QEMU process.
        if getattr(a, "expected_qemu", None) and qemu != json.loads(a.expected_qemu):
            raise ValueError("VM process differs from campaign group (restart or restore)")
        # Before the session directory exists: swapped QEMU pages stall the reads of a cycle (v4, v4c).
        memory = host_memory(qemu)
        if memory["qemu_swap_max"] != "0":
            raise ValueError("QEMU swap was not disabled before start: memory.swap.max is "
                             + repr(memory["qemu_swap_max"]))
        # memory.swap.max 0 forbids new swap only: a QEMU moved into its cgroup late keeps what was swapped before.
        if type(memory["qemu_swap_kb"]) is not int or memory["qemu_swap_kb"] != 0:
            raise ValueError("QEMU memory was swapped before start: qemu_swap_kb is " + repr(memory["qemu_swap_kb"]))
        attempt = getattr(a, "group_attempt", 1) or 1
        events = pilot_events(p) if a.role == "pilot" and "events" in p else []
        if a.role not in ("pilot", "diagnostic"):
            assignment = {"role": a.role, "group": a.group, "scenario": a.scenario,
                          "seed": a.seed, "cycles": p["cycles"], **({"vm": vm} if vm else {})}
            planned = [s for s in plan(p)["sessions"] if {k: s[k] for k in assignment} == assignment]
            if not planned:
                raise ValueError("assignment/seed not present in frozen collection plan")
            events = planned[0].get("events", [])
            if not a.pilot_report:
                raise ValueError("corpus capture requires --pilot-report from an accepted pilot audit")
            # The gate alone decides whether the report is an accepted pilot of this protocol.
            from scripts.campaign import pilot_gate
            _, needed = pilot_gate(a.pilot_report, a.protocol, p)
        else:
            needed = 0
        if shutil.disk_usage(base).free < needed + p["min_free_gib"] * 2**30:
            raise ValueError("insufficient disk budget; archive existing captures first")
        # Immutable start records, including unfinished/failed runs: a boot belongs to
        # one group attempt only, and a group (across its attempts) to one role.
        mine = (campaign, a.group, attempt)
        # A VM's base holds only its own sessions of one campaign; the checks need all of them.
        for path, old in session_records(COLLECTIONS if vm and not diagnostic else base):
            theirs = (old.get("campaign_id"), old["group"], old.get("group_attempt", 1))
            if old["group"] == a.group and old["role"] != a.role:
                raise ValueError("group already belongs to a different split")
            if old["guest_before"]["boot_id"] == before["boot_id"] and theirs != mine:
                raise ValueError("same guest boot already belongs to another group or group attempt")
            if theirs == mine and old["guest_before"]["boot_id"] != before["boot_id"]:
                raise ValueError("one boot must correspond to exactly one collection group attempt")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        session_id = getattr(a, "session_id", None) or f"{stamp}_{a.role}_{a.scenario}"
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}", session_id):
            raise ValueError("invalid session ID")
        cycles = a.cycles if diagnostic and a.cycles else p["pilot_cycles"] if a.role in ("pilot", "diagnostic") else p["cycles"]
        out = base / session_id
        out.mkdir()
        shutil.copyfile(a.protocol, out / "protocol.json")
        prof = ROOT / p["profile"]
        shutil.copytree(prof, out / "profile")
        source_files = [f for directory in MEASUREMENT_DIRS for f in (ROOT / directory).rglob("*")
                        if f.is_file() and (f.suffix in SOURCE_SUFFIXES or f.parent == ROOT / "lab")]
        source_hashes = {str(f.relative_to(ROOT)): digest(f) for f in source_files}
        subprocess.run(user_command(["make", "-C", ROOT / "vmicollect"]), check=True)
        s = p["scenarios"][a.scenario]
        metadata = {"schema": SESSION_SCHEMA, "session_id": out.name,
                    "campaign_id": getattr(a, "campaign_id", None),
                    "vm": vm, "domain": p["domain"],
                    **({"replaces": a.replaces} if getattr(a, "replaces", None) else {}),
                    "role": a.role, "group": a.group, "group_attempt": attempt, "scenario": a.scenario,
                    "typ": "benign", "seed": a.seed, "cycles": cycles, "guest_before": before,
                    **({"events": events, "event_grace_s": p["events"]["grace_s"]} if "events" in p else {}),
                    "protocol_sha256": digest(a.protocol), "source_sha256": source_hashes,
                    "lab_sha256": lab, "measurement_sha256": measurement_sources(),
                    "profile_sha256": {str(f.relative_to(prof)): digest(f) for f in prof.rglob("*") if f.is_file()},
                    "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect"),
                    "collector_settings": {"writer": "delta", "fsync": COLLECTOR_FSYNC, "hash": "sha256",
                                           "writer_thread": True, "mlock": COLLECTOR_MLOCK,
                                           "interval_s": p["interval_s"], "full_every": p["full_every"],
                                           "bin_bytes": p["bin_bytes"]},
                    "traffic": {"generator": "scripts/host_traffic.py", "profile": "lab", "target": p["target"],
                                "seed": a.seed, "workers": s["workers"], "burst": s["burst"],
                                "catalog_share": s["catalog_share"], "write_share": s["write_share"],
                                "summary_interval_s": 5, "load_model": "closed loop, not a fixed request rate"},
                    "metadata_not_model_inputs": ["scenario", "seed", "traffic", "boot_id", "group", "session_id", "events",
                                                  "vm", "domain"],
                    "working_storage": storage_identity(base),
                    "host_context": {"host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                                     "qemu": qemu, "memory": memory, "python": sys.executable,
                                     **({"other_vms": other_vms(p)} if vm else {})},
                    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                    "measurement_dirty": measurement_dirty(),
                    "host": platform.platform(), "created_unix": time.time()}
        write_json(out / "session.json", metadata)
        subprocess.run(user_command(["virsh", "-c", "qemu:///session", "dumpxml", p["domain"]]),
                       stdout=(out / "domain.xml").open("x"), check=True)
        print(f"session: {out}", flush=True)
        capture_session(p, out, metadata, cycles)
        print(f"Audit: python3 scripts/collection.py audit {out}")


class Events:
    """Planned benign events (lab/udalosti.py), offsets from the measurement start.

    One event at a time. Stop always runs, also after a failed start or an
    interruption, and returns the lab to its deployed state. An event counts
    only with guest evidence of both steps and a healthy stack afterwards.
    """

    def __init__(self, p, planned, step):
        self.p, self.step, self.active = p, step, None
        self.records = [dict(event, executed=False) for event in planned]

    def call(self, record, action):
        try:
            return lab_json(self.p, "event", "--event", action, record["type"], timeout=240)
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}

    def tick(self, origin):
        now = time.time()
        if self.active is not None:
            record = self.records[self.active]
            if now >= origin + record["start_s"] + record["duration_s"]:
                if not self.stop():
                    raise ValueError("lab not restored after event " + record["type"])
            return
        for index, record in enumerate(self.records):
            if "host_start_unix" not in record and now >= origin + record["start_s"]:
                self.active = index  # Before the call: an interruption must still stop it.
                record["host_start_unix"] = time.time()
                record["start"] = self.call(record, "start")
                record["host_started_unix"] = time.time()
                self.step("event-start", type=record["type"], ok=record["start"].get("ok"))
                if not record["start"].get("ok") and not self.stop():
                    raise ValueError("lab not restored after event " + record["type"])
                return

    def stop(self):
        record, self.active = self.records[self.active], None
        record["host_stop_unix"] = time.time()
        record["stop"] = self.call(record, "stop")
        record["host_stopped_unix"] = time.time()
        # The guest computes the effect in stop, before it restores the lab (lab/udalosti.py; labctl keeps it in
        # the reply); the log audit reads it at the top of the record, so a failed stop call leaves none.
        record["effect"] = record["stop"].get("effect")
        restored = record["stop"].get("ok") is True and record["stop"].get("health") == 200
        record["executed"] = record.get("start", {}).get("ok") is True and restored
        self.step("event-stop", type=record["type"], executed=record["executed"])
        return restored

    def close(self, path):
        if self.active is not None:
            self.stop()
        write_json(path, {"schema": "hyptcn3/session-events/1", "events": self.records,
                          "note": "Benign operational events; host times bound each event, guest replies are evidence."})


def capture_session(p, out, metadata, cycles):
    owner = (int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])) if "SUDO_UID" in os.environ else None
    guest = out / "guest"
    guest.mkdir()
    if owner:
        os.chown(guest, *owner)  # labctl runs as the VM owner and writes verified copies here.
    status = {"schema": END_SCHEMA, "completed": False, "interrupted": False, "steps": {}}
    children = {}
    interrupts = Interrupts()
    events = Events(p, metadata["events"], lambda name, **values: step(name, **values)) if "events" in metadata else None

    def step(name, **values):
        status["steps"][name] = {"unix": time.time(), **values}
        print(json.dumps({"step": name, **values}, default=str)[:400], flush=True)

    def write_guest(name, doc):
        write_json(guest / name, doc)

    try:
        # Preflight, all outside the measured interval: no other generator, a
        # functional stack, guest clock, guest state and a closed log segment.
        subprocess.run(user_command([sys.executable, ROOT / "scripts/labctl.py", "traffic-stop",
                                     *(labctl_args(p) if p.get("vm") else [])]), check=True)
        if foreign_traffic(p):
            raise ValueError("another host_traffic.py is running; refusing to mix traffic")
        if collectors(p["domain"]):
            raise ValueError("another collector is reading this VM; refusing a second one")
        clock = lab_json(p, "clock", timeout=60)
        if abs(clock["offset_s"]) > CLOCK_SYNC_S:
            synced = lab_json(p, "sync-clock", timeout=60)
            clock = {**synced["after"], "synced_from": synced["before"]}
            if abs(clock["offset_s"]) > CLOCK_SYNC_S:
                raise ValueError(f"guest clock offset above {CLOCK_SYNC_S} s after synchronization")
        write_guest("clock_before.json", clock)
        step("clock", offset_s=clock["offset_s"], synced="synced_from" in clock)
        step("health", attempts=wait_healthy(p["target"]))
        smoke = subprocess.run([sys.executable, ROOT / "scripts/lab_smoke.py", "--target", p["target"],
                                "--domain", p["domain"], "--out", out / "preflight_smoke.json"], cwd=ROOT, capture_output=True,
                               text=True, timeout=120)
        if smoke.returncode:
            raise ValueError("preflight functional check failed: " + (smoke.stdout + smoke.stderr)[-500:])
        step("functional-check", result=smoke.stdout.strip()[-200:])
        write_guest("state_before.json", lab_json(p, "state"))
        pre = lab_json(p, "segment", "--label", out.name + "-pre", "--dest", guest)
        write_guest("pre_segment.json", pre)
        expected = smoke_rids(out / "preflight_smoke.json")
        seen = {line["rid"]: line["status"] for line in nginx_lines(guest / (out.name + "-pre-nginx-access.jsonl.gz"))
                if line["rid"] in expected}
        if seen != expected:
            raise ValueError("request ID correlation failed for the preflight checks")
        step("pre-segment", lines=pre["files"][0]["lines"], correlated=len(seen))
        # Before any measured load: swapped guest RAM would stall the first full snapshot.
        status["prefault"] = prefault_swapped(metadata["host_context"]["qemu"]["pid"])
        step("prefault", **status["prefault"])
        if COLLECTOR_MLOCK:
            status["collector_memory"] = collector_memory(metadata["host_context"]["qemu"]["pid"])
            if not status["collector_memory"]["ok"]:
                raise ValueError("not enough free memory for the collector's locked queue; see end.json")
        s = p["scenarios"][metadata["scenario"]]
        children["monitor"] = start_child(
            [sys.executable, ROOT / "scripts/host_monitor.py", "run", "--out", out / "host_monitor.jsonl",
             "--interval-s", "1", "--session-id", out.name, "--path", str(out), "--path", "/",
             *(arg for match in monitor_matches(p) for arg in ("--match", match))],
            out / "host_monitor.log")
        children["traffic"] = start_child(
            [sys.executable, ROOT / "scripts/host_traffic.py", "--profile", "lab", "--target", p["target"],
             "--dur", "0", "--seed", str(metadata["seed"]), "--vlakien", str(s["workers"]),
             "--burst", str(s["burst"]), "--catalog-share", str(s["catalog_share"]),
             "--write-share", str(s["write_share"]), "--session-id", out.name,
             "--requests-log", out / "traffic_requests.jsonl", "--intervals-log", out / "traffic_intervals.jsonl",
             "--summary-interval-s", "5", "--initial-phase", "warmup", "--out", out / "traffic.json"],
            out / "traffic.log")
        step("warmup", seconds=p["warmup_s"])
        deadline = time.monotonic() + p["warmup_s"]
        while time.monotonic() < deadline:
            for name in ("traffic", "monitor"):
                if children[name].poll() is not None:
                    raise ValueError(f"{name} exited during warmup")
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        metrics = json.loads((out / "traffic.json").read_text())
        if not metrics["ok"] or metrics["errors"] or metrics.get("logging_error"):
            raise ValueError("warmup traffic failed")
        write_json(out / "traffic_before.json", metrics)
        if foreign_traffic(p, {children["traffic"].pid}):
            raise ValueError("another host_traffic.py appeared during warmup")
        os.kill(children["traffic"].pid, signal.SIGUSR1)
        status["measure_start_unix"] = time.time()
        env = dict(os.environ, VMIC_DOMAIN=p["domain"], VMIC_INTERVAL=str(p["interval_s"]),
                   VMIC_FULL_EVERY=str(p["full_every"]), VMIC_OUT=str(out / "raw"), VMIC_FSYNC=str(COLLECTOR_FSYNC).lower(),
                   VMIC_MLOCK=str(COLLECTOR_MLOCK).lower(),
                   VMIC_MANAGED_SESSION="1")
        status["capture_started_unix"] = time.time()
        children["collector"] = start_child(["bash", "scripts/lab_capture.sh", str(cycles)], out / "capture.log", env)
        step("capture", cycles=cycles)
        checked = 0
        while children["collector"].poll() is None:
            for name in ("traffic", "monitor"):
                if children[name].poll() is not None:
                    raise ValueError(f"{name} exited during capture")
            if shutil.disk_usage(out).free < p["min_free_gib"] * 2**30:
                raise ValueError("disk reserve reached; preserving partial session")
            if time.monotonic() - checked > 15:
                checked = time.monotonic()
                if foreign_traffic(p, {children["traffic"].pid}):
                    raise ValueError("another host_traffic.py appeared during capture")
            if events:
                events.tick(status["measure_start_unix"])
            time.sleep(1)
        status["capture_finished_unix"] = time.time()
        status["collector_rc"] = children["collector"].returncode
        if children["collector"].returncode:
            raise ValueError("collector failed; see capture.log")
        os.kill(children["traffic"].pid, signal.SIGUSR2)
        status["measure_end_unix"] = time.time()
        status["traffic"] = stop_child(children["traffic"], 30)
        children.pop("traffic")
        # Request errors or a logging failure (rc 1/3) are audit reasons, not a broken capture.
        status["traffic_rc"] = status["traffic"]["rc"]
        status["guest_after"] = guest_identity(p)
        if status["guest_after"] != metadata["guest_before"]:
            raise ValueError("guest rebooted or changed during capture")
        if qemu_process(p["domain"]) != metadata["host_context"]["qemu"]:
            raise ValueError("VM process restarted during capture")
        status["host_memory_after"] = host_memory(metadata["host_context"]["qemu"])
        if p.get("vm"):
            status["other_vms_after"] = other_vms(p)
        # Larger guest logs only now, between measurements.
        segment = lab_json(p, "segment", "--label", out.name, "--dest", guest)
        write_guest("session_segment.json", segment)
        journal = lab_json(p, "journal", "--label", out.name + "-journal", "--since",
                           str(metadata["created_unix"]), "--until", str(time.time()), "--dest", guest)
        write_guest("journal_segment.json", journal)
        write_guest("state_after.json", lab_json(p, "state"))
        write_guest("clock_after.json", lab_json(p, "clock", timeout=60))
        step("guest-evidence", nginx_lines=segment["files"][0]["lines"])
        status["monitor"] = stop_child(children["monitor"], 15)
        children.pop("monitor")
        status["completed"] = True
    except BaseException as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        status["interrupted"] = isinstance(exc, InterruptedError)
        raise
    finally:
        try:
            interrupts.disarm()
        except InterruptedError:
            pass  # The first signal landed exactly here; the handler disarmed itself.
        # Collector first, so no snapshot is taken without its generator.
        for name, grace in (("collector", 60), ("traffic", 30), ("monitor", 15)):
            if name in children:
                status[name] = stop_child(children.pop(name), grace)
        status["signals"] = interrupts.received
        if events:
            try:
                events.close(out / "events.json")
            except OSError as exc:
                status["events_error"] = str(exc)
        # No snapshot without the measured phase: the campaign may retry such an attempt.
        status["measurement_started"] = "measure_start_unix" in status
        if status["interrupted"]:
            status["note"] = ("Interrupted run: the guest log segment was not closed here; the next "
                              "session's pre-segment keeps those nginx lines. Not a usable capture.")
        try:
            status["logs_manifest_sha256"] = write_logs_manifest(out)
        except OSError as exc:
            status["logs_manifest_error"] = str(exc)
        status["written_unix"] = time.time()
        write_json(out / "end.json", status)
        interrupts.restore()
        if owner:
            for path in [out, *out.rglob("*")]:
                os.chown(path, *owner, follow_symlinks=False)


CONTROL_KINDS = {"kontrola_wx_memfd": {"wx", "memfd_fd"}}


def positive_controls(result, events_path, p):
    """Pilot gate: every row fully inside an executed positive control shows its patterns.

    A row counts as inside when its snapshot time lies in [host_started + one
    period, host_stop]. Inside, one python3 process must show every expected
    kind (W+X and memfd). Rows with patterns outside the controls are counted
    and reported, not judged: benign software may legitimately map W+X.
    """
    try:
        events = json.loads(events_path.read_text())["events"]
    except (OSError, ValueError, KeyError):
        return {"problems": ["positive control: events.json missing or unreadable"], "controls": []}
    planned = {c["type"] for c in p["events"]["pilot_controls"]}
    out, problems, inside_any = [], [], set()
    for record in events:
        if record["type"] not in planned:
            continue
        expected = CONTROL_KINDS[record["type"]]
        start, stop = record.get("host_started_unix"), record.get("host_stop_unix")
        rows = [] if start is None or stop is None else [
            i for i, t in enumerate(result["casy"]) if start + p["interval_s"] <= t <= stop]
        inside_any.update(rows)
        hits = 0
        for i in rows:
            kinds = {}
            for pattern in result["quality"][i].get("memory_patterns", []):
                if pattern["comm"] == "python3":
                    kinds.setdefault(pattern["pid"], set()).add(pattern["kind"])
            hits += any(expected <= k for k in kinds.values())
        out.append({"type": record["type"], "executed": record.get("executed") is True,
                    "rows": len(rows), "rows_with_patterns": hits})
        if record.get("executed") is not True:
            problems.append("positive control not executed: " + record["type"])
        elif not rows or hits != len(rows):
            problems.append(f"positive control not detected: {record['type']} {hits}/{len(rows)} rows")
    if {c["type"] for c in out} != planned:
        problems.append("positive control missing from events.json")
    outside = sum(1 for i, q in enumerate(result["quality"])
                  if i not in inside_any and q.get("memory_patterns"))
    return {"problems": problems, "controls": out, "rows_with_patterns_outside": outside}


SKIPPED_TASKS = ("sockets", "memory_patterns")  # The traversals whose skipped tasks the row quality counts.


def analyze_windows(result, p, session, role, recorded_rows=None, counts=None):
    """Audit the frozen input policy while retaining independent integrity gaps.

    Returns rows, windows, the acceptance verdict and the quality summary. The verdict is the one decision
    of features/acceptance.py: `role` selects the assigned length and the tolerance of invalid rows, a
    diagnostic session also passes the length it recorded for itself (`recorded_rows`). What the audit admits
    instead of rejecting is counted into `counts` (a Counter) under its id of the register of exceptions.
    """
    counts = Counter() if counts is None else counts
    verdict, windows, detail = judge(result, p, session, role, recorded_rows)
    # Admitted, so counted (features/audit_policy.py TOLERATED): rows the invalid_rows rule covered, process
    # lists a parser rule closed (below the cap, which is null until G3b), cross-view differences seen in one
    # snapshot only, and integrity checks that could not conclude, by row.
    tolerate(counts, "invalid_rows", len(verdict["tolerated_invalid_seq"] or []))
    tolerate(counts, "rule_closed_rows", len(verdict["facts"]["rule_closed_seq"]))
    tolerate(counts, "unconfirmed_findings", sum(bool(q.get("unconfirmed_findings")) for q in result["quality"]))
    tolerate(counts, "inconclusive_integrity", sum(bool(q["inconclusive"]) for q in result["quality"]))
    policy = protocol_policy(p)
    rows = snimky_z_matice(session, result["matica"], MENA, result["casy"],
                          result["seq"], result["valid"])
    checks = {"syscall_table", "process_cross_view", "modules", "text_integrity"}
    checks.update(name for q in result["quality"] for name in q["inconclusive"])
    quality = {
        "policy": policy,
        "behavior_valid_rows": sum(q["behavior_valid"] for q in result["quality"]),
        "legacy_valid_rows": sum(q["model_valid"] for q in result["quality"]),
        "invalid_input_seq": [seq for seq, good in zip(result["seq"], result["valid"]) if not good],
        # Invalid rows admitted under the rule the session's role gets: the protocol's pre-registered
        # invalid_rows rule, none for a pilot or a role the protocol does not assign.
        "tolerated_invalid_seq": verdict["tolerated_invalid_seq"] or [],
        "integrity_inconclusive_rows": {
            name: sum(name in q["inconclusive"] for q in result["quality"]) for name in sorted(checks)},
        "integrity_finding_rows": sum(bool(q["findings"]) for q in result["quality"]),
        "integrity_findings": sum(len(q["findings"]) for q in result["quality"]),
        # Single-snapshot cross-view differences of the live read; not findings.
        "integrity_unconfirmed_seq": [seq for seq, q in zip(result["seq"], result["quality"])
                                      if q.get("unconfirmed_findings")],
        "integrity_unconfirmed": sum(len(q.get("unconfirmed_findings", [])) for q in result["quality"]),
        # Process lists closed only by the backward walk after a torn forward link.
        "process_walk_prev_seq": [seq for seq, q in zip(result["seq"], result["quality"])
                                  if q.get("process_walk") == "prev"],
        # Process lists cut before a tail node that init_task.prev already named but whose
        # own links were read before it was linked in.
        "process_walk_tail_seq": [seq for seq, q in zip(result["seq"], result["quality"])
                                  if q.get("process_walk") == "tail"],
        # Process lists closed where the consistent forward and backward parts meet on one
        # node read at another moment (guestparse.view _stretnutie, rule 'meet').
        "process_walk_meet_seq": [seq for seq, q in zip(result["seq"], result["quality"])
                                  if q.get("process_walk") == "meet"],
        # Process lists the forward walk closed whose backward walk did not close over the same tasks in reverse:
        # a prev link the forward walk alone does not read (proposal 6.2, recorded only).
        "process_walk_backward_disagrees_seq": [
            seq for seq, q in zip(result["seq"], result["quality"])
            if q.get("process_walk") == "next" and (q.get("process_walk_backward") or {}).get("agrees") is not True],
        # Tasks the socket and memory-pattern traversals skipped (their sockets and pages are not counted), and
        # the rows that record no such count (the traversal returned early, recorded only).
        "skipped_tasks": {name: sum((q.get("skipped_tasks") or {}).get(name) or 0 for q in result["quality"])
                          for name in SKIPPED_TASKS},
        "skipped_tasks_unrecorded_seq": [
            seq for seq, q in zip(result["seq"], result["quality"])
            if any(type((q.get("skipped_tasks") or {}).get(name)) is not int for name in SKIPPED_TASKS)],
    }
    if detail is not None:
        quality["coverage"] = detail
    return rows, windows, verdict, quality


MISSING = object()  # A key the audit reads is absent; required() records the reason instead of using a default.


def required(reasons, doc, name, path):
    """The value at the dotted `path` of the JSON object `doc` read from the file `name`.

    When a key on the path is absent it returns MISSING and adds `missing key: <name>:<path>` to `reasons`; the
    check that reads the value is then not evaluated (the missing key is its reason), never passed by a default.
    """
    value = doc
    for key in path.split("."):
        if type(value) is not dict or key not in value:
            reasons.append(f"missing key: {name}:{path}")
            return MISSING
        value = value[key]
    return value


def present(*values):
    return all(value is not MISSING for value in values)


def audit_session(directory, p, protocol_path, output=None):
    """Audit one session directory under protocol `p` (read from `protocol_path`); 0 accepted, 2 refused.

    A managed session (session.json present) must state every key the audit reads from session.json, end.json,
    raw/capture.json and the sidecars: a missing one is the reason `missing key: <file>:<dotted.path>`
    (validate_sidecar still refuses a structurally broken sidecar). The checks with a bound apply only when the
    protocol has an audit section (schema 3, features/audit_policy.py); the record states the section or null
    (values.audit_bounds), what the audit admitted next to the register of exceptions (values.exceptions) and
    the timing of the collector (values.timing).
    """
    directory = Path(directory).resolve()
    native = (directory / "session.json").exists()
    raw = directory / "raw" if native else directory
    metadata = json.loads((directory / "session.json").read_text()) if native else {}
    bounds = audit_bounds(p)
    reasons = []
    need = functools.partial(required, reasons)
    session = "session.json"
    role = cycles = None
    mlock = domain = vmid = MISSING
    if not native:
        reasons.append("historical capture without protocol/session provenance; exploratory only")
    else:
        recorded = need(metadata, session, "protocol_sha256")
        if present(recorded) and recorded != digest(protocol_path):
            reasons.append("protocol hash mismatch")
        end = json.loads((directory / "end.json").read_text()) if (directory / "end.json").exists() else {}
        completed, after = need(end, "end.json", "completed"), need(end, "end.json", "guest_after")
        before = need(metadata, session, "guest_before")
        if present(completed) and not completed or present(after, before) and after != before:
            reasons.append("incomplete capture or changed guest identity")
        hashes = {str(f.relative_to(directory / "profile")): digest(f)
                  for f in (directory / "profile").rglob("*") if f.is_file()}
        profile = need(metadata, session, "profile_sha256")
        if present(profile) and hashes != profile:
            reasons.append("kernel profile changed since capture")
        capture = json.loads((raw / "capture.json").read_text())
        captured = {key: need(capture, "raw/capture.json", "values." + key)
                    for key in ("collector_sha256", "full_every", "interval_s", "mlock")}
        collector = need(metadata, session, "collector_sha256")
        if (present(collector, captured["collector_sha256"]) and captured["collector_sha256"] != collector
                or present(captured["full_every"]) and captured["full_every"] != p["full_every"]
                or present(captured["interval_s"]) and captured["interval_s"] != p["interval_s"]):
            reasons.append("collector binary or temporal settings mismatch")
        # The flag passed to the collector (capture.json) and the one in every sidecar match the session settings.
        mlock = need(metadata, session, "collector_settings.mlock")
        if present(mlock, captured["mlock"]) and captured["mlock"] != mlock:
            reasons.append("collector memory locking differs from session settings")
        # Every sidecar names the session's VM: its domain and the QEMU pid (the eBPF backend writes it as vmid).
        domain, vmid = need(metadata, session, "domain"), need(metadata, session, "host_context.qemu.pid")
        # The VM start forbids swap for the QEMU cgroup (package B5); the session records what it found.
        swap = need(metadata, session, "host_context.memory.qemu_swap_max")
        if present(swap) and swap != "0":
            reasons.append("QEMU swap was not disabled before start")
        # And no QEMU memory in swap at the start (VmSwap 0 kB): swap.max 0 set late keeps the pages swapped before.
        swapped = need(metadata, session, "host_context.memory.qemu_swap_kb")
        if present(swapped) and (type(swapped) is not int or swapped != 0):
            reasons.append("QEMU memory was swapped before start")
        lab = need(metadata, session, "lab_sha256")
        if present(lab, need(metadata, session, "guest_before.stack_manifest")) and guest_mismatch(
                metadata["guest_before"], lab):
            reasons.append("deployed guest files differ from lab/")
        role, cycles = (None if value is MISSING else value
                        for value in (need(metadata, session, "role"), need(metadata, session, "cycles")))
    sidecars = []
    for path in raw.glob("*.json"):
        doc = json.loads(path.read_text())
        if doc.get("schema") == "vmicollect/1":
            validate_sidecar(doc)
            if doc["features"]["bin_bytes"] != p["bin_bytes"]:
                reasons.append("bin width differs from protocol")
            sidecars.append((path, doc))
    sidecars.sort(key=lambda item: item[1]["seq"])
    if not sidecars:
        raise ValueError("no collector sidecars")
    if len(list(raw.glob("*.vmicd"))) != len(sidecars):
        reasons.append("image/sidecar count mismatch")
    # The role decides the assigned length (features/acceptance.py); diagnostic runs are shorter by design and
    # their recorded length is the target. A role the protocol does not assign is rejected by the verdict below.
    assigned, _, assigned_role = assignment(p, role, cycles)
    if assigned_role and len(sidecars) != assigned:
        reasons.append("snapshot count differs from assigned protocol")
    if [d["seq"] for _, d in sidecars] != list(range(len(sidecars))):
        reasons.append("sequence must start at zero and be contiguous")
    source_hashes = {}
    total_bytes = 0
    timing = {"lateness_s": [], "delta_ms": [], "full_ms": []}
    published = {"data_closed_ms": [], "queue_bytes": [], "queue_jobs": [], "queue_wait_ms": []}
    first_lateness = MISSING
    for index, (path, side) in enumerate(sidecars):
        name, image = path.name, path.with_suffix(".vmicd")
        sha = digest(image)
        source_hashes[image.name] = sha
        source_hashes[name] = digest(path)
        total_bytes += image.stat().st_size
        full = need(side, name, "output.full")
        if native and present(full) and full != (side["seq"] % p["full_every"] == 0):
            reasons.append("full snapshot cadence differs from protocol")
        if native:
            recorded = need(side, name, "output.sha256")
            if present(recorded) and recorded != sha:
                reasons.append("image checksum mismatch: " + image.name)
        skipped = need(side, name, "sched.skipped_before")
        if side["stats"]["read_errors"] or side["stats"]["filled_zero"] or present(skipped) and skipped:
            reasons.append("read errors/fill/missed slots: " + image.name)
        total = need(side, name, "capture.total_ms")
        if present(total) and total >= p["interval_s"] * 1000:
            reasons.append("collector cycle exceeded period")
        if present(total, full):
            timing["full_ms" if full else "delta_ms"].append(total)
            # A full snapshot reads every guest page, a delta the changed ones only (proposal 6.2).
            if bounds is not None and total > bounds["cycle_ms_max"]["full" if full else "delta"]:
                reasons.append("collector cycle time above the audit bound")
        lateness = need(side, name, "sched.lateness_s")
        first_lateness = lateness if index == 0 else first_lateness
        if present(lateness):
            timing["lateness_s"].append(lateness)
            if bounds is not None and lateness > bounds["lateness_max_s"]:
                reasons.append("cycle start later than the audit bound")
        if native:
            recorded = need(side, name, "output.mlock")
            if present(recorded, mlock) and recorded != mlock:
                reasons.append("collector memory locking differs from session settings")
            side_domain, side_vmid = need(side, name, "vm.domain"), need(side, name, "vm.vmid")
            if present(side_domain, domain) and side_domain != domain or present(side_vmid, vmid) and side_vmid != vmid:
                reasons.append("sidecar VM identity differs from session")
        # A wait for queue memory happens inside the live read and stretches it; it means the writer
        # thread fell far behind. Strict: never accepted, even when the cycle stayed below the period.
        wait = need(side, name, "capture.queue_wait_ms")
        if present(wait) and wait > 0:
            reasons.append("collector waited for queue memory: " + image.name)
        for key, value in (("queue_wait_ms", wait), *((key, need(side, name, "output." + key))
                                                       for key in ("data_closed_ms", "queue_bytes", "queue_jobs"))):
            if present(value):
                published[key].append(value)
    result = retazec(str(raw), str(directory / "profile" if native else ROOT / p["profile"]),
                    p["max_gap_s"], quality_policy=protocol_policy(p))
    counts = Counter()
    rows, windows, verdict, quality = analyze_windows(result, p, directory.name, role, cycles, counts)
    reasons.extend(verdict["reasons"])
    controls = None
    if native and role == "pilot" and p.get("events", {}).get("pilot_controls"):
        controls = positive_controls(result, directory / "events.json", p)
        reasons.extend(controls["problems"])
    # The timestamp gap and the sampling period are reasons of the verdict (features/acceptance.py).
    if any(b - a != 1 for a, b in zip(result["seq"], result["seq"][1:])):
        reasons.append("sequence gap")
    logs = audit_logs(directory, snapshot_times=result["casy"]) if native else None
    # Publication runs on the collector's writer thread after the cycle: reported, not a gate (the
    # offline corpus depends on the sampling instants only; live latency is a separate experiment).
    # The p95 is nearest rank, as in soft_rt_check and campaign_report.
    closed = sorted(published["data_closed_ms"])
    publication = None if not closed else {
        # data_closed_ms: cycle start to the snapshot data written and closed; the sidecar and both
        # renames follow, so this is a lower bound of the publication time.
        "snapshots": len(closed), "data_closed_ms_max": closed[-1],
        "data_closed_ms_p95": closed[-(-95 * len(closed) // 100) - 1],
        "queue_bytes_max": max(published["queue_bytes"], default=None),
        "queue_jobs_max": max(published["queue_jobs"], default=None),
        "queue_wait_ms_max": max(published["queue_wait_ms"], default=None)}
    if logs is not None:
        reasons.extend("logs: " + problem for problem in logs["problems"])
        counts.update(logs["tolerated"])
    # Recorded for every session, a bound only under schema 3: G2 and G3a judge the bound by this run. The most
    # frequent spacing between burst starts (spacing_mode) is recorded only and never a reason.
    flagged = flagged_seq(verdict["facts"])
    spacing_min = bounds["periodicity"]["min_spacing_rows"] if bounds is not None else 2
    run, spacing = periodic_run(flagged, spacing_min)
    # Phase of the collector's grid: frame 0 was due at its timestamp minus its lateness. Recorded only;
    # pairing the grids of two VMs is package B9.
    phase = (round((sidecars[0][1]["timestamp_unix"] - first_lateness) % p["interval_s"], 6)
             if present(first_lateness) else None)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = Path(output).resolve() if output else directory / f"audit_{stamp}.json"
    feature_path = output.with_suffix(".npz")
    save(feature_path, result)
    values = {"accepted": not reasons, "reasons": sorted(set(reasons)),
              "role": role, "protocol_sha256": digest(protocol_path),
              # The verdict of the one acceptance decision; the three fields before it repeat it for older readers.
              "snapshots": verdict["snapshots"], "windows": verdict["windows"],
              "score_coverage": verdict["score_coverage"], "acceptance": verdict,
              "coverage": quality.pop("coverage", None), "logs": logs, "publication": publication,
              **({"positive_controls": controls} if controls is not None else {}),
              "audit_bounds": bounds, "exceptions": exceptions_record(p, counts),
              "timing": {"lateness_s_max": max(timing["lateness_s"], default=None),
                         "delta_ms_max": max(timing["delta_ms"], default=None),
                         "full_ms_max": max(timing["full_ms"], default=None),
                         "periodic_run": {"equal_spacings": run, "spacing": spacing, "min_spacing_rows": spacing_min,
                                          "flagged_rows": len(flagged)},
                         "spacing_mode": spacing_mode(flagged),
                         "grid_phase_s": phase},
              "auditor_sha256": {str(f.relative_to(ROOT)): digest(f) for f in
                                  (Path(__file__), ROOT / "scripts/collection_logs.py",
                                   ROOT / "scripts/traffic_log.py", ROOT / "scripts/host_monitor.py",
                                   ROOT / "safeguard/features.py", ROOT / "features/audit_policy.py",
                                   ROOT / "scripts/protocol_v5.py")},
              "quality": quality,
              "raw_bytes": total_bytes, "source_sha256": source_hashes,
              "session_sha256": digest(directory / "session.json") if native else None,
              "extractor_sha256": {str(f.relative_to(ROOT)): digest(f)
                                    for d in ("features", "guestparse") for f in (ROOT / d).rglob("*.py")
                                    if "tests" not in f.parts},
              "features": str(feature_path), "features_sha256": digest(feature_path),
              "layout": result["layout"], "session_dir": str(directory),
              "text_integrity_inconclusive_rows": sum("text_integrity" in q["inconclusive"] for q in result["quality"]),
              "feature_extraction_s": result["trvanie_s"],
              "note": "Offline feature audit. Does not certify live scoring latency, integrity baseline or detection."}
    report = {"schema": "hyptcn3/collection-audit/1", "date": datetime.now(timezone.utc).isoformat(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "measurement_dirty": measurement_dirty(),
              "host": platform.platform(), "guest": metadata.get("guest_before"),
              "command": " ".join(sys.argv), "n": len(rows), "values": values}
    write_json(output, report)
    print(json.dumps({"report": str(output), **{k: values[k] for k in
                     ("accepted", "reasons", "snapshots", "windows", "score_coverage", "raw_bytes")}}, indent=2))
    return 0 if values["accepted"] else 2


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--protocol", type=Path, default=DEFAULT)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    run = sub.add_parser("run")
    run.add_argument("--role", choices=["pilot", "diagnostic", "train", "dev", "calibration", "test_benign",
                                        "test_events"],
                     required=True)
    run.add_argument("--scenario", default="steady")
    run.add_argument("--group", required=True)
    run.add_argument("--vm", help="VM name; required for (and only for) a protocol that lists vms")
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--pilot-report", type=Path)
    run.add_argument("--session-id", help="Exclusive output name for a frozen campaign assignment")
    run.add_argument("--campaign-id")
    run.add_argument("--replaces", help="Campaign: session ID of the audit-rejected session this one replaces")
    run.add_argument("--expected-boot-id", help="Refuse a boot change since campaign preflight")
    run.add_argument("--expected-qemu", help="JSON identity of the group's QEMU process (refuse restart/restore)")
    run.add_argument("--group-attempt", type=int, default=1, help="Campaign group generation after a recorded restart")
    run.add_argument("--collections-dir", type=Path, help="Diagnostic session base under data/diagnostics")
    run.add_argument("--cycles", type=int, help="Diagnostic runs only: number of snapshots")
    audit = sub.add_parser("audit")
    audit.add_argument("directory", type=Path)
    audit.add_argument("--out", type=Path)
    coverage = sub.add_parser("coverage", help="explain score eligibility from an existing NPZ without re-reading RAM")
    coverage.add_argument("archive", type=Path)
    coverage.add_argument("--expected-snapshots", type=int, required=True,
                          help="assigned cycle count, including missing snapshots")
    coverage.add_argument("--out", type=Path)
    check = sub.add_parser(
        "selfcheck", help="self-check of a schema-3 protocol file and its plan (scripts/protocol_v5.py); exit 0 only "
                          "when every check passed: lab_register stays pending until packages B5 and B8 register "
                          "their names in lab/, so the command exits 2 until B8")
    # The skeleton's form `collection.py selfcheck --protocol P` works too: given here, it replaces the global one.
    check.add_argument("--protocol", type=Path, default=argparse.SUPPRESS, help="the protocol file to check")
    check.add_argument("--mode", choices=protocol_v5.MODES, default="campaign")
    check.add_argument("--stage", choices=protocol_v5.STAGES, default="G0",
                       help="every path determined_at assigns to this stage or an earlier one must hold a value")
    check.add_argument("--out", type=Path, help="also write the report to this new file")
    a = ap.parse_args(argv)
    if a.command == "selfcheck":  # It reads the file itself and does not need the loader to pass.
        report = protocol_v5.selfcheck(a.protocol, mode=a.mode, stage=a.stage)
        if a.out:
            write_json(a.out, report)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["passed"] else 2
    p = protocol(a.protocol)
    if a.command == "plan":
        print(json.dumps(plan(p), indent=2))
        return 0
    if a.command == "run":
        run_session(a, for_vm(p, a.vm))
        return 0
    if a.command == "coverage":
        data = load(a.archive)
        _, report = scorable_windows(data, p, a.archive.stem, a.expected_snapshots)
        report.update(archive=str(a.archive.resolve()), archive_sha256=digest(a.archive),
                      protocol_sha256=digest(a.protocol), minimum=coverage_gate(p),
                      gate_passed=not report["score_coverage"] < coverage_gate(p),
                      date=datetime.now(timezone.utc).isoformat(),
                      source_sha256={str(f.relative_to(ROOT)): digest(f) for f in
                                     (ROOT / "features/coverage.py", ROOT / "safeguard/features.py")})
        if a.out:
            write_json(a.out, report)
            shown = {"report": str(a.out), **{key: report[key] for key in
                     ("scorable_windows", "expected_snapshots", "score_coverage", "ideal_score_coverage",
                      "gate_possible_at_assigned_length", "gate_passed")}}
        else:
            shown = report
        print(json.dumps(shown, indent=2, ensure_ascii=False, allow_nan=False))
        return 0 if report["gate_passed"] else 2
    return audit_session(a.directory, p, a.protocol, a.out)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, FeatureError, WindowError, subprocess.SubprocessError) as error:
        print(f"collection: {error}", file=sys.stderr)
        sys.exit(2)
