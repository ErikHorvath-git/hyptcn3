"""Collection fakes for a campaign of the v5 shape (protocol v5, package B9a, agent T; design NAVRH_B9a 1.4 and the fix
round OPRAVA_B9a section 4).

A campaign of scripts/campaign.py runs as it runs on the collection PC: the real init (main, the command line of
design 1.3), the real runners (execute, one per VM), the real audit lock, rejections, replacements and archiver, the
real ledger of tcn/pecat.py and the real finish_corpus with features/dataset.py build and the production check of
training (safeguard.training.validate_index, in the subprocess finish_corpus starts). No test replaces the final index
(harness row B9 "Hotové, keď"; the B2 panel item finish_corpus): Harness.finished is a spy that records each call and
then calls the real function. Only what touches the lab VMs, the host or the extraction from guest RAM is replaced:

    the lab (Lab)        labctl stop, start, reset --seed, pretouch, levels and reboot of the two VMs of the protocol,
                         as package B9a's labctl prints them (agent L: stop {"stop": ...}; start {"libvirtd": ...} and
                         {"qemu_swap": ...} with the QEMU's pid and cgroup; reset and pretouch the JSON guest_state.py
                         prints); collection.guest_identity, collection.qemu_process and collection.host_memory read it:
                         every start of a VM that is shut off is a new QEMU process with a new guest boot (way 1)
    the capture          collection.py run, parsed by collection.py's own command line (collection.main) and planned by
                         its own collection.v5_run (the attempt of the planned session in the plan of --mode, its seed,
                         the stage of its mode); instead of the lab work it writes what a capture leaves: session.json
                         (with attempt and plan_mode, design 1.2), events.json, controls.json of a session of
                         test_controls, raw/ and end.json with the session's time from one clock (Clock)
    the audit            collection.py audit, parsed by collection.main; audit_values writes the real feature archive of
                         a clean session at the capture's time (scripts/tests/boundary_sessions.py extraction_result on
                         the protocol's own grid) and the values of the audit record in the shape
                         features/tests/test_dataset_plan.py session writes, from collection.analyze_windows; a
                         session named in Harness.reject is refused with a reason the real decision gives
    the records          scripts/campaign.py RESULTS, where every ending of a campaign writes its record (package
                         B9b), is a directory under the test's directory
    the ledger           tcn.pecat.KNIHA and tcn.pecat.ZAZNAM are a file under the test's directory; a ledger command
                         of the campaign (python -m tcn.pecat or tcn/pecat.py, through run_child, subprocess.run or
                         subprocess.check_output) runs in this process with pecat.main, so it writes that file; a write
                         of data/results/kniha_pecati.json is refused before it happens (Harness.patch)
    the host             git (HEAD test-commit, a clean tree), the runtime identity (vm.swappiness 1), the archive
                         mount, the frozen-tree check, the sleep inhibitor, root and the owner (SUDO_USER), the stages
                         (scripts.gates.require) and the self-test (scripts.audit_selftest.require_selftest), recorded
    the guard            subprocess.Popen refuses virsh, ssh, systemctl, systemd-run, busctl, kill, pkill,
                         systemd-inhibit, runuser, sudo, and a labctl, capture or ledger child the harness did not
                         serve: no lab or host command runs for real, and the lab VMs on this host are never touched

The runners are driven in turn, one accepted session each (Harness.run: execute(..., stop_after=1) for VM a, then for
VM b, and again): the two VMs of the collection PC run at the same time, and a session of one VM takes the time of a
session of the other. A runner that waits for the other VM stops (START_GRACE_S 0, the other runner is not running
between its steps) and runs again in the next round; a round in which no VM captured, rejected or started anything is a
deadlock (Deadlock). Harness.drift drives a schedule in which one VM runs ahead of the other (finding F5 of the
verification of B9a). Every capture takes the next slot of one clock, so the times of the archives follow the order of
the captures and the corpus build checks the time order of the roles the campaign kept. A runaway loop of
replacements or of starts of a group fails the test by name (RUNAWAY, finding F6) instead of running on.

Package B9b (agent T; design NAVRH_B9b 1.4): the endings of a campaign and their records. The records of the endings
go to a directory of the test (scripts/campaign.py RESULTS, Harness.results), never to data/results; Harness.records
reads them. The fake audit writes the rest of the shape of a real audit record that the record of an ending reads:
values.exceptions (features.audit_policy.exceptions_record over the counts of the audit's own decision, the counts a
test adds, Harness.tolerated), values.timing with the phase of the collector's grid (grid_phase_s) and, under protocol
schema 3, values.marked_rows_by_type (marked_rows: the counts a test gives, Harness.marked, 0 for every other event
type). A test chooses the code of a rejection (Harness.codes: PERIODICITY), a capture that fails (Harness.fail_capture),
a step during a capture (Harness.during: the operator's stop request), a session that runs at the same time as a
session of the other VM (Harness.overlap), and a continuation (Harness.init continues and cause). Harness.run_to_end
drives both runners in turn until no runner moves (a pause, a stop, an invalid campaign or the end), and
Harness.background runs one runner in a thread of this process, as the two runners of the collection PC run at once,
so that a pause or a stop meets the other runner while it waits (addendum of NAVRH_B9b, F5 of B9a).

Names that package B9a and its fix round add (protocol_v5.reset_seed, the --mode and --attempt of collection.py run,
init --mode and --estimate-from) and those of package B9b (init --continue with --cause under schema 3, the records of
the endings, campaign.RESULTS) are reached only when a harness runs, so this module imports on the code before them.
Only mechanics on synthetic sessions; no number here is a measurement (HONESTY P4).
"""
import argparse
from collections import Counter
import contextlib
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess
import threading
import time

from features.acceptance import flagged_seq, periodic_run, spacing_mode
from features.archive import save
from features.audit_policy import exceptions_record
from features.tests import test_dataset_plan as dp
from scripts import campaign as c
from scripts import collection
from scripts import protocol_v5 as pv
from scripts.collection_archive import digest, read_json, write_new
from scripts.labctl import DAEMON_SERVICE
from scripts.tests import boundary_sessions as bs

VMS = ("a", "b")  # The VMs of features/tests/test_dataset_plan.py protocol_doc, in its order.
OWNER = pwd.getpwuid(os.getuid()).pw_name  # init records the account that runs it; the runner must be its sudo user.
COMMIT = "test-commit"  # HEAD as the fake git gives it; the fake capture and audit record it, as the real ones do.
KERNEL, STACK = "6.1.0-test", "5" * 64  # One guest kernel and service stack (test_dataset_plan session writes these).
COLLECTOR = "c" * 64  # The collector binary of every session (test_dataset_plan session writes this).
HOST_BOOT = "synthetic-host-boot"
# The pids of the fake QEMU processes lie above the largest pid_max of Linux (2^22), so no /proc/<pid> of this host
# is ever one of them.
FIRST_PID = 2 ** 22 + 1000
CGROUP = f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/app.slice/{DAEMON_SERVICE}"  # Way 1.
MEMORY = {"vm_swappiness": 1, "qemu_swap_kb": 0, "qemu_swap_max": "0"}  # collection.host_memory of a QEMU without swap.
RUNTIME = {"host": "test-host", "python": "test-python", "packages": {"numpy": "test", "torch": "test"},
           "collector_sha256": COLLECTOR, "vm_swappiness": 1}
# The rate of every scenario of the test protocol: collection.v5_planned refuses a null rate (null until G2); any
# positive number serves the fake capture, which runs no traffic (judgment of the test, no measurement).
RATE = .5
REJECTION = ("timing:gap", "timestamp gap")  # (code, reason) of an injected rejection: one the real decision gives.
# The code and reason features/acceptance.py gives a session whose flagged rows are periodic (the early stop of package
# B9b, proposal 7.5: such a rejection stops the campaign).
PERIODICITY = ("periodicity", "periodic flagged rows")
# Finding F6 of the verification of B9a: a runaway loop (a rehearsal replaces without a limit, a start of a group could
# fail again and again) ends in an assertion of the harness instead of a hang. A campaign may capture at most RUNAWAY
# sessions beyond the sessions of its plan, and a VM may be stopped at most RUNAWAY times beyond the groups planned on
# it (judgment of the test: its scenarios capture at most 2 sessions beyond a plan and start every group once).
RUNAWAY = 6
FORBIDDEN = frozenset({"virsh", "ssh", "systemctl", "systemd-run", "busctl", "kill", "pkill", "systemd-inhibit",
                       "runuser", "sudo", "guestfish", "qemu-img"})
TRACKED_LEDGER = c.ROOT / "data/results/kniha_pecati.json"
GROUP_START = ("stop", "start", "reset", "pretouch")  # Design 1.3 item 6, in this order.
LAB_STEPS = (*GROUP_START, "reboot")  # The verbs that change a VM's state (reboot: a group's start before B9).
SLOT_GAP_S = 100  # The clock leaves this much between two sessions (no measurement; sessions never overlap).
# The grid of features/tests/test_dataset_plan.py protocol_doc (96 rows of 5 s, a full snapshot every 64, windows of 8,
# the gate .7 its clean sessions meet), for the protocols of schema 2 of the old fixtures (scripts/tests/
# test_campaign.py lab, test_multivm.py multi, test_continuation.py lab): their audits write real archives since the
# fix round (finding F2), and the archive and audit of a session of the 720 rows of config/collection-v2.json took
# 0.17 s against 0.02 s here, its build likewise (judgment of the test: speed; no protocol of the thesis).
SMALL_GRID = {"cycles": dp.CYCLES, "pilot_cycles": 80, "full_every": dp.FULL_EVERY, "window_rows": dp.WINDOW,
              "min_score_coverage": .7}


class Deadlock(AssertionError):
    """A round of the runners of both VMs in which none of them captured, rejected or started anything."""


class Clock:
    """One clock for the captures of a test: every capture takes the next slot, as long as one session of its protocol
    (cycles * interval_s) and SLOT_GAP_S, so the times of the archives follow the order of the captures. A capture
    that runs at the same time as an earlier one (Harness.overlap) names its start; the clock then goes on after both.
    The two runners of Harness.background take it from two threads, hence the lock."""

    def __init__(self, start=dp.BASE):
        self.now = float(start)
        self.lock = threading.Lock()

    def take(self, p, start=None):
        """(start, end) of the next session of protocol `p`: the time of its first and of its last row; `start` given,
        the session starts then (it overlaps the session before it)."""
        with self.lock:
            start = self.now if start is None else float(start)
            self.now = max(self.now, start + p["cycles"] * p["interval_s"] + SLOT_GAP_S)
            return start, start + (p["cycles"] - 1) * p["interval_s"]


def marked_rows(p, counts=None):
    """values.marked_rows_by_type, event_occurrences_by_type, marked_rows_outside_events and marked_rows_note of an
    audit (package B9b, agent Z, and its fix: Q24; design NAVRH_B9b 1.3, scripts/collection.py marked_rows_record):
    under protocol schema 3 the marked rows (invalid rows and rows closed by a parser rule) inside the event windows of
    every event type of the protocol, here 0 (the fake's sessions are clean and plan no event) unless a test gives the
    count (Harness.marked), and none outside them; the windowed occurrences of every type, 0 but one of each type a
    test gives a count for (a session holds a type at most once); under schemas 1 and 2 none of them is counted (null,
    with the reason)."""
    if p.get("schema") != pv.SCHEMA:
        return {"marked_rows_by_type": None, "event_occurrences_by_type": None, "marked_rows_outside_events": None,
                "marked_rows_note": "the protocol names no event types (protocol schema 1 or 2; fake of the test)"}
    unknown = set(counts or {}) - set(p["events"]["types"])
    if unknown:
        raise AssertionError("marked rows of event types the protocol does not name: " + ", ".join(sorted(unknown)))
    return {"marked_rows_by_type": {name: (counts or {}).get(name, 0) for name in sorted(p["events"]["types"])},
            "event_occurrences_by_type": {name: int(name in (counts or {})) for name in sorted(p["events"]["types"])},
            "marked_rows_outside_events": 0, "marked_rows_note": "synthetic counts of the fake audit of the test"}


def audit_values(directory, p, protocol_path, output, *, extractor, accepted=True, rejection=REJECTION,
                 tolerated=None, marked=None):
    """The values of the audit record of a session a fake capture left in `directory` (session.json, raw/ and end.json
    with measure_start_unix, the time of its first row), as collection.py audit records them: the real feature
    archive of a clean session of the protocol's own grid (scripts/tests/boundary_sessions.py extraction_result, its
    seed from the session ID), written at output.with_suffix(".npz"), and collection.analyze_windows' verdict and
    quality of it, in the shape of features/tests/test_dataset_plan.py session; source_sha256 and raw_bytes of the
    images in raw/. accepted False: the verdict refused with rejection (code, reason). features/dataset.py build and
    safeguard.training.validate_index accept a session of these values, as the session of test_dataset_plan.

    Package B9b (the record of an ending and the early stop read them): values.exceptions as collection.py audit
    records it (features.audit_policy.exceptions_record of the counts analyze_windows gives, with `tolerated`, {id: n},
    added); values.timing with the phase of the collector's grid (grid_phase_s: the first row's time modulo
    interval_s, the fake's cycles start on time) and the periodic run of the flagged rows (a refusal with the code
    periodicity has the run that refuses, audit.periodicity.equal_spacings); the marked rows by event type
    (marked_rows of `marked`)."""
    directory, output = Path(directory), Path(output)
    meta, end = read_json(directory / "session.json"), read_json(directory / "end.json")
    sid, role = meta["session_id"], meta["role"]
    seed = int(hashlib.sha256(sid.encode()).hexdigest()[:8], 16)
    t0 = float(end["measure_start_unix"])
    result, _ = bs.extraction_result(sid, p["cycles"], p["full_every"], t0=t0,
                                     interval_s=p["interval_s"], max_gap_s=p["max_gap_s"], seed=seed)
    counts = Counter()
    _, _, verdict, quality = collection.analyze_windows(result, p, sid, role, counts=counts)
    if verdict["reasons"]:  # A clean session of the protocol's own grid; anything else is a broken fake.
        raise AssertionError(f"the clean session {sid} is not accepted: {verdict['reasons']}")
    counts.update(tolerated or {})
    archive = save(output.with_suffix(".npz"), result)
    session_sha = digest(directory / "session.json")
    raw = sorted((directory / "raw").glob("*.vmicd"))
    flagged = flagged_seq(verdict["facts"])
    spacing_min = (p.get("audit") or {}).get("periodicity", {}).get("min_spacing_rows", 2)
    run, spacing = periodic_run(flagged, spacing_min)
    values = {"accepted": True, "reasons": [], "role": role, "protocol_sha256": digest(protocol_path),
              "snapshots": verdict["snapshots"], "windows": verdict["windows"],
              "score_coverage": verdict["score_coverage"], "acceptance": verdict,
              "coverage": quality.pop("coverage", None),
              "logs": {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True, "problems": [],
                       "sections": {"metadata": {"session_sha256": session_sha}}},
              "exceptions": exceptions_record(p, counts),
              "timing": {"lateness_s_max": 0.0, "delta_ms_max": None, "full_ms_max": None,
                         "periodic_run": {"equal_spacings": run, "spacing": spacing, "min_spacing_rows": spacing_min,
                                          "flagged_rows": len(flagged)},
                         "spacing_mode": spacing_mode(flagged), "grid_phase_s": round(t0 % p["interval_s"], 6)},
              "quality": quality, "session_sha256": session_sha, "extractor_sha256": extractor,
              "features": str(archive), "features_sha256": digest(archive), "layout": result["layout"],
              "session_dir": str(directory), "source_sha256": {path.name: digest(path) for path in raw},
              "raw_bytes": sum(path.stat().st_size for path in raw)}
    values.update(marked_rows(p, marked))
    if not accepted:
        code, reason = rejection
        values.update(accepted=False, reasons=[reason],
                      acceptance=dict(verdict, accepted=False, reasons=[reason], codes=[code]))
        if code == "periodicity" and p.get("audit"):  # The run of equal spacings that refuses (acceptance.py).
            values["timing"]["periodic_run"]["equal_spacings"] = p["audit"]["periodicity"]["equal_spacings"]
    return values


def argv_of(args):
    """The argument vector of a subprocess call, as strings."""
    if isinstance(args, (str, bytes, os.PathLike)):
        return shlex.split(os.fsdecode(args))
    return [os.fsdecode(a) if isinstance(a, (bytes, os.PathLike)) else str(a) for a in args]


def forbidden(argv):
    """The first program of the argument vector that never runs for real in these tests, or None."""
    return next((token for token in argv if os.path.basename(token) in FORBIDDEN), None)


def child_kind(argv):
    """(kind, arguments) of a child the harness serves: labctl, collection (capture or audit) or pecat; else None."""
    for i, token in enumerate(argv):
        name = token.replace("\\", "/")
        if name.endswith("scripts/labctl.py"):
            return "labctl", argv[i + 1:]
        if name.endswith("scripts/collection.py"):
            return "collection", argv[i + 1:]
        if name.endswith("tcn/pecat.py"):
            return "pecat", argv[i + 1:]
        if token == "-m" and i + 1 < len(argv) and argv[i + 1] == "tcn.pecat":
            return "pecat", argv[i + 2:]
    return None


def text_mode(kw):
    return bool(kw.get("text") or kw.get("universal_newlines") or kw.get("encoding") or kw.get("errors"))


def stdout_of(text, kw):
    return text if text_mode(kw) else text.encode()


def ledger_entries(path):
    """{features_sha256: entry} of a seal ledger, {} while it does not exist."""
    return read_json(path)["values"]["archives"] if Path(path).exists() else {}


def lab_parser():
    """The options of scripts/labctl.py main (one positional command, the rest anywhere), --seed of package B9a."""
    parser = argparse.ArgumentParser(prog="labctl.py", add_help=False, exit_on_error=False)
    parser.add_argument("command")
    for option in ("--domain", "--vm", "--uri", "--source", "--guest-command", "--label", "--dest", "--polarity",
                   "--dose", "--levels", "--tolerance", "--since", "--until", "--protocol", "--seed"):
        parser.add_argument(option)
    parser.add_argument("--port", type=int)
    parser.add_argument("--event", nargs=2)
    return parser


class Lab:
    """The two lab VMs of the protocol: their state, every labctl command and its output, injected failures.

    A VM is running or shut off. stop shuts it off (a VM already shut off stays so); start of a VM that is shut off is
    way 1: a new QEMU process (pid, start ticks) in the daemon's unit, a new guest boot; reset and pretouch need a
    running VM. fail[(vm, verb)] = n makes the next n such commands fail as labctl fails (exit 1, the reason on
    stderr; a failed start leaves the VM shut off, a failed pretouch prints its record first, as guest_state.py).
    stops(vm): how many stops of the VM the tests allow before RUNAWAY ends a loop of starts."""

    def __init__(self, doc):
        self.domains = {row["domain"]: row["name"] for row in doc["vms"]}
        self.ports = {row["name"]: row["port"] for row in doc["vms"]}
        self.pids, self.boots, self.ticks = itertools.count(FIRST_PID, 7), itertools.count(1), itertools.count(1)
        self.calls, self.fail = [], {}
        self.sequence = None  # Harness.sequence: one order of lab commands and captures.
        self.stops = lambda vm: float("inf")
        self.vms = {vm: {"running": False, "boot": None, "qemu": None} for vm in self.ports}
        for vm in self.vms:
            self._boot(vm)

    def _boot(self, vm):
        state = self.vms[vm]
        state.update(running=True, boot=f"boot-{vm}-{next(self.boots)}",
                     qemu={"pid": next(self.pids), "start_ticks": next(self.ticks), "host_boot": HOST_BOOT})
        return state

    def start_again(self, vm):
        """The operator starts a VM that a failed start of a group left shut off (package B9b: the campaigns of a test
        that follow need its guest)."""
        if not self.vms[vm]["running"]:
            self._boot(vm)

    def domain(self, vm):
        return next(d for d, name in self.domains.items() if name == vm)

    def identity(self, vm):
        """collection.guest_identity of the VM: refused while it is shut off (labctl exec fails then)."""
        state = self.vms[vm]
        if not state["running"]:
            raise subprocess.CalledProcessError(1, ["labctl.py", "exec", "--vm", vm], "",
                                                f"labctl: domain {self.domain(vm)} is not running")
        return {"kernel": KERNEL, "boot_id": state["boot"], "machine_id": f"machine-{vm}", "stack_sha256": STACK}

    def qemu(self, domain):
        """collection.qemu_process of a domain: its QEMU process, None while the VM is shut off."""
        state = self.vms.get(self.domains.get(domain))
        return None if state is None or not state["running"] else dict(state["qemu"])

    def command(self, argv):
        """(exit code, stdout, stderr) of labctl.py with these arguments."""
        try:
            args, unknown = lab_parser().parse_known_args(argv)
        except argparse.ArgumentError as error:
            return 2, "", f"labctl.py: error: {error}\n"
        vm = args.vm
        if unknown or vm not in self.vms or args.domain != self.domain(vm) or args.port != self.ports[vm]:
            return 2, "", f"labctl.py: error: arguments {shlex.join(argv)}\n"
        state, verb = self.vms[vm], args.command
        if verb == "stop":
            stopped = sum(x["vm"] == vm and x["verb"] == "stop" for x in self.calls)
            if stopped >= self.stops(vm):
                raise AssertionError(f"runaway starts of VM {vm}: {stopped} stops, the groups planned on it and "
                                     f"RUNAWAY {RUNAWAY} allow {self.stops(vm)}")
        call = {"vm": vm, "verb": verb, "argv": list(argv), "seed": args.seed,
                "order": None if self.sequence is None else next(self.sequence)}
        self.calls.append(call)
        code, out, err = self._serve(vm, state, verb, args)
        call.update(code=code, out=out, err=err)
        return code, out, err

    def _failing(self, vm, verb):
        left = self.fail.get((vm, verb), 0)
        if left:
            self.fail[vm, verb] = left - 1
        return bool(left)

    def _serve(self, vm, state, verb, args):
        """What labctl prints and exits with. The counts, sizes and times in these records are synthetic values of
        the fake in the shape of the real ones; nothing reads them as data."""
        domain = self.domain(vm)
        line = lambda doc: json.dumps(doc, sort_keys=True) + "\n"
        if verb == "stop":
            if self._failing(vm, verb):
                return 1, "", f"labctl: domain {domain} is 'running' 180 s after virsh shutdown (synthetic)\n"
            before = {"domain": domain, "state_before": "running" if state["running"] else "shut off",
                      "qemu_pid_before": state["qemu"]["pid"] if state["running"] else None, "state": "shut off",
                      "seconds": 0.0}
            state.update(running=False, qemu=None)
            return 0, line({"stop": before}), ""
        if verb == "start":
            if self._failing(vm, verb):
                return 1, "", f"labctl: Guest of {domain} did not become healthy (synthetic)\n"
            daemon = ""
            if not state["running"]:
                self._boot(vm)
                daemon = line({"libvirtd": {"unit": DAEMON_SERVICE, "found": "unit", "daemon_pid": 90,
                                            "cgroup": CGROUP, "memory_swap_max": "0", "qemu_way": "unit",
                                            "done": []}})
            swap = {"domain": domain, "qemu_pid": state["qemu"]["pid"], "cgroup_before": CGROUP,
                    "swap_max_before": "0", "scope": None, "cgroup": CGROUP, "memory_swap_max": "0", "vm_swap_kb": 0,
                    "way": "unit", "temporary": False}
            return 0, daemon + line({"qemu_swap": swap}), ""
        if not state["running"]:
            return 1, "", f"labctl: domain {domain} is not running\n"
        if verb == "reboot":
            state["boot"] = f"boot-{vm}-{next(self.boots)}"
            return 0, "", ""
        if verb == "reset":
            if args.seed is None or not re.fullmatch(r"[0-9]{1,18}", args.seed):
                return 2, "", "labctl.py: error: reset requires --seed, 0 to 10**18 - 1\n"
            if self._failing(vm, verb):
                return 1, "", "labctl: guest_state.py reset: psql: connection refused (synthetic)\n"
            return 0, line({"schema": "hyptcn3/guest-reset/1", "seed": int(args.seed),
                            "data_sha256": digest_text(f"{vm}/{args.seed}"),
                            "counts": {"products": 40, "customers": 30, "employees": 8, "orders": 60,
                                       "order_items": 120, "cart_items": 10, "documents": 12},
                            "documents_bytes": 65536, "started_unix": 1.0, "finished_unix": 2.0}), ""
        if verb == "pretouch":
            failed = self._failing(vm, verb)
            record = {"schema": "hyptcn3/guest-pretouch/1", "mib": 256, "exit_code": 1 if failed else 0,
                      "peak_rss_kib": 1024 if failed else 262144, "touched": not failed, "seconds": 1.0,
                      "meminfo_kb_before": {"MemAvailable": 1000000}, "meminfo_kb_after": {"MemAvailable": 999000},
                      "stderr": "MemoryError (synthetic)" if failed else ""}
            if failed:
                return 1, line(record), "labctl: pretouch did not touch the memory of the largest event\n"
            return 0, line(record), ""
        if verb == "levels":
            return 0, line({"schema": "hyptcn3/guest-levels/1", "processes": 120, "threads": 200,
                            "meminfo_kb": {"MemAvailable": 1000000}, "modules": []}), ""
        if verb == "state":
            return 0, line({"schema": "hyptcn3/guest-state/1", "boot_id": state["boot"], "kernel": KERNEL}), ""
        raise AssertionError(f"a campaign does not run labctl {verb} (VM {vm})")


def digest_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def holds(tree, wanted):
    """Whether `wanted` is a value anywhere in the JSON tree (a record keeps it under a key of its own)."""
    if tree == wanted:
        return True
    if isinstance(tree, dict):
        return any(holds(value, wanted) for value in tree.values())
    if isinstance(tree, list):
        return any(holds(value, wanted) for value in tree)
    return False


def printed(out, key):
    """The record under `key` of the JSON lines a labctl command printed (start: libvirtd, qemu_swap; stop: stop)."""
    docs = [json.loads(line) for line in out.splitlines() if line.strip()]
    return next(doc[key] for doc in docs if key in doc)


class NoSignals:
    """collection.Interrupts for a runner in a thread (Harness.background): signal handlers are the main thread's
    alone, and no test sends a signal."""

    def __init__(self):
        self.received = []

    def disarm(self):
        pass

    def restore(self):
        pass


class Runner:
    """One runner of Harness.background: execute(directory, vm=vm) in a thread; `outcome` holds its return value
    (value) or its exception (error) once it has ended."""

    def __init__(self, directory, vm):
        self.directory, self.vm, self.outcome = Path(directory), vm, {}
        self.thread = threading.Thread(target=self._run, name=f"runner-{vm}", daemon=True)

    def _run(self):
        try:
            self.outcome["value"] = c.execute(self.directory, vm=self.vm)
        except BaseException as error:  # noqa: BLE001 - the test reads what ended the runner
            self.outcome["error"] = error

    def join(self, timeout):
        """The outcome once the runner has ended; AssertionError when it is still running after `timeout` s."""
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise AssertionError(f"the runner of VM {self.vm} still runs {timeout} s later")
        return self.outcome


class Harness:
    """A campaign directory tree under `root` with the fakes of this module patched in through `patch` (a
    pytest.MonkeyPatch). The audit writes real feature archives and records (audit_values) and finish_corpus is the
    real one, behind the spy finish (Harness.finished).

    Records, in one order (`order`): lab.calls (every labctl command) and captures (every capture child:
    vm, sid, role, group, scenario, attempt, mode, seed, replaces, t0, t1, boot, qemu, ledger and done before it);
    audits; children (every child served); gates and selftests (the stages and self-tests asked, with "phase"
    campaign or session); kontrola (calls of tcn.pecat.kontrola: none during a campaign); finished (every call of
    finish_corpus: campaign, vm, reports); printed (what each run of a runner printed, Harness.step).

    What a test injects, each keyed by (group, scenario, attempt) of a session of any campaign of the harness or by
    (campaign, group, scenario, attempt) of one campaign (Harness.injected): reject (the audit refuses it), codes
    ((code, reason) of that refusal, else REJECTION), tolerated ({register id: count} the audit adds to its
    exceptions), marked ({event type: marked rows}), fail_capture (the capture child fails before it writes anything:
    an error of the runner), during (a function the capture calls once it has written the session, while its runner
    runs) and overlap ((key of an earlier session, seconds): the session starts that long after the start of that
    session, so the two run at the same time on the two VMs)."""

    def __init__(self, root, patch):
        self.root, self.mp = Path(root), patch
        self.collections, self.base = self.root / "collections", self.root / "campaigns"
        self.archive = self.root / "archive"
        self.ledger = self.root / "ledger" / "kniha_pecati.json"
        # Package B9b: the records of the endings (scripts/campaign.py RESULTS), never data/results in a test.
        self.results = self.root / "results"
        for directory in (self.collections, self.base, self.archive, self.ledger.parent, self.results):
            directory.mkdir(parents=True)
        self.profile = self.root / "profile"
        self.profile.mkdir()
        (self.profile / "symbols.txt").write_text("synthetic profile\n")
        self.extractor = c.extractor_hashes()
        self.lab = Lab(dp.protocol_doc(self.profile))
        self.lab.stops = self.allowed_stops
        self.sequence = itertools.count(1)
        self.lab.sequence = self.sequence
        self.clock = Clock()
        self.captures, self.audits, self.children, self.gates, self.selftests = [], [], [], [], []
        self.kontrola, self.finished, self.refusals, self.campaigns, self.printed = [], [], [], [], []
        self.reject = set()  # (group, scenario, attempt) of the sessions the audit refuses.
        # Package B9b: what a test injects (the class docstring), keyed as reject.
        self.codes, self.tolerated, self.marked, self.during, self.overlap = {}, {}, {}, {}, {}
        self.fail_capture = set()
        self.phase = "campaign"  # "session" while a capture or an audit child runs (the stages it asks).
        self.label = None  # The step of a test's scenario, kept in the records of the stages and the self-tests.
        self.patch()

    # ---------------------------------------------------------------- the protocol and the campaign

    def protocol(self, name, *, limit, groups=None, rehearsal_groups=None, edit=None):
        """A protocol file of features/tests/test_dataset_plan.py protocol_doc (five roles, two VMs, the test roles
        interleaved, 8-minute sessions) with replacement.max_per_campaign `limit`, min_free_gib 0 (tiny synthetic
        sessions on pytest's tmpfs, as scripts/tests/test_campaign.py) and a rate in every scenario (RATE);
        groups: groups of every role of the campaign; rehearsal_groups: rehearsal.groups_per_role; edit: a function
        that changes the document before it is written (package B9b: a bound of early stop, an expected count of the
        register, another group prefix)."""
        doc = dp.protocol_doc(self.profile)
        doc["min_free_gib"] = 0
        doc["scenarios"] = {name_: dict(entry, rate=RATE) for name_, entry in doc["scenarios"].items()}
        doc["replacement"] = dict(doc["replacement"], max_per_campaign=limit)
        if groups is not None:
            doc["roles"] = dict.fromkeys(doc["roles"], groups)
        if rehearsal_groups is not None:
            doc["rehearsal"] = dict(doc["rehearsal"], groups_per_role=rehearsal_groups)
        if edit is not None:
            edit(doc)
        path = self.root / f"{name}.json"
        collection.write_json(path, doc)
        collection.protocol(path)  # The loader's checks, before any campaign reads it.
        return path

    def init(self, protocol, mode, name, estimate_from=None, *, continues=None, cause=None, extra=()):
        """scripts/campaign.py init with the command line of design 1.3: --mode, and --estimate-from in mode
        campaign; the archive on this test's disk, without compression (the sessions are small). Package B9b
        (design NAVRH_B9b 1.2): continues, the directory of the paused campaign it continues (--continue), with its
        written cause (--cause); extra, more arguments as they are. Returns the campaign directory."""
        argv = ["init", "--protocol", str(protocol), "--mode", mode, "--archive-root", str(self.archive),
                "--name", name, "--archive-on-system-disk", "--archive-compression", "none"]
        if estimate_from is not None:
            argv += ["--estimate-from", str(estimate_from)]
        if continues is not None:
            argv += ["--continue", str(continues)]
        if cause is not None:
            argv += ["--cause", cause]
        argv += list(extra)
        with contextlib.redirect_stdout(io.StringIO()):
            c.main(argv)
        self.campaigns.append(self.base / name)
        return self.base / name

    def step(self, directory, vm):
        """One run of the VM's runner up to its next accepted session (execute(..., stop_after=1)); whether it moved
        anything (a capture, a labctl command or a record of attempts/). What it printed is kept (printed)."""
        before = self.progress(directory)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                c.execute(directory, vm=vm, stop_after=1)
        except BaseException as error:
            for refusal in self.refusals[-3:]:
                error.add_note("refused child: " + refusal)
            raise
        finally:
            self.printed.append({"campaign": Path(directory).name, "vm": vm, "out": out.getvalue()})
        return self.progress(directory) != before

    def status(self, directory, vm):
        path = Path(directory) / c.vm_file("status.json", vm)
        return read_json(path) if path.exists() else {}

    def run(self, directory, *, vms=VMS, rounds=400):
        """Both runners in turn, one accepted session each, until every VM is complete; Deadlock when a round of
        both moved nothing. Returns the status of every VM."""
        directory = Path(directory)
        for _ in range(rounds):
            moved = False
            for vm in vms:
                if self.status(directory, vm).get("status") != "complete":
                    moved = self.step(directory, vm) or moved
            states = {vm: self.status(directory, vm) for vm in vms}
            if all(state.get("status") == "complete" for state in states.values()):
                return states
            if not moved:
                raise Deadlock("no runner moved in a round: " + "; ".join(
                    f"VM {vm} {state.get('status')}/{state.get('stage')}: {state.get('message')}"
                    for vm, state in states.items()))
        raise AssertionError(f"the campaign did not end in {rounds} rounds")

    def pending(self, directory, vm):
        """The planned rows of the VM nothing is captured for yet (scripts/campaign.py finished)."""
        manifest = read_json(Path(directory) / "campaign.json")
        return [row for row in manifest["sessions"] if row.get("vm") == vm and not c.finished(directory, manifest, row)]

    def run_to_end(self, directory, *, vms=VMS, rounds=400):
        """Both runners in turn, one accepted session each, until a round in which no runner moved (package B9b: a
        pause, an early stop, a stop or an invalid campaign ends the runs as the end of the plan does). A refusal of a
        runner (ValueError) is kept, not raised. Returns ({vm: status}, [(vm, refusal text)])."""
        directory, refused = Path(directory), []
        for _ in range(rounds):
            moved = False
            for vm in vms:
                if self.status(directory, vm).get("status") == "complete":
                    continue
                try:
                    moved = self.step(directory, vm) or moved
                except ValueError as error:
                    refused.append((vm, str(error)))
            if not moved:
                return {vm: self.status(directory, vm) for vm in vms}, refused
        raise AssertionError(f"the campaign did not end in {rounds} rounds")

    def until_interleaved(self, directory, *, rounds=400):
        """Both runners in turn until each VM's next session is of an interleaved role (protocol_v5.INTERLEAVED)."""
        directory = Path(directory)
        for _ in range(rounds):
            due = [vm for vm in VMS if self.pending(directory, vm)
                   and self.pending(directory, vm)[0]["role"] not in pv.INTERLEAVED]
            if not due:
                return
            for vm in due:
                self.step(directory, vm)
        raise AssertionError(f"the runners did not reach the test roles in {rounds} rounds")

    def alone(self, directory, vm, *, rounds=400):
        """VM `vm` alone until a run of it moves nothing (it waits, or it stopped) or it is complete; its status."""
        for _ in range(rounds):
            if self.status(directory, vm).get("status") == "complete" or not self.step(directory, vm):
                break
        return self.status(directory, vm)

    def drift(self, directory, ahead="a", *, rounds=400):
        """A schedule in which VM `ahead` runs ahead of the other (finding F5 of the verification of B9a, the
        verifier's sondy/s/drift_harness.py): both runners in turn until each VM's next session is of an interleaved
        role (protocol_v5.INTERLEAVED); then VM `ahead` alone until a run of it moves nothing (it waits) or it is
        complete; then the other VM alone in the same way; then both in turn to the end (run). Returns the status of
        each VM after its run alone."""
        directory = Path(directory)
        behind = next(vm for vm in VMS if vm != ahead)
        self.until_interleaved(directory, rounds=rounds)
        alone = {vm: self.alone(directory, vm, rounds=rounds) for vm in (ahead, behind)}
        self.run(directory, rounds=rounds)
        return alone

    def background(self, directory, vm):
        """The runner of VM `vm` (execute without stop_after) started in a thread of this process, as the two runners
        of the collection PC run at the same time; the test patches collection.Interrupts (NoSignals) first. Such a
        runner may wait and start a group; a capture, an audit or a seal it asks for fails (Harness.serve), so that
        only the runner of the main thread captures. Returns the Runner."""
        if c.collection.Interrupts is not NoSignals:
            raise AssertionError("a runner in a thread needs collection.Interrupts patched to NoSignals")
        runner = Runner(directory, vm)
        runner.thread.start()
        return runner

    def wait_for(self, directory, vm, stage, *, runner=None, timeout=60):
        """Until the status of VM `vm` names `stage` (a runner in a thread reached it); AssertionError after
        `timeout` s or when its runner ended first."""
        deadline = time.monotonic() + timeout
        while self.status(directory, vm).get("stage") != stage:
            if runner is not None and not runner.thread.is_alive():
                raise AssertionError(f"the runner of VM {vm} ended before {stage}: {runner.outcome} "
                                     f"{self.status(directory, vm)}")
            if time.monotonic() > deadline:
                raise AssertionError(f"VM {vm} did not reach {stage} in {timeout} s: {self.status(directory, vm)}")
            time.sleep(.02)

    def records(self, directory):
        """[(path, record)] of the records of the endings of one campaign (package B9b, design NAVRH_B9b 1.1: files
        kampan_<campaign id>_<ending>_<UTC stamp>.json in scripts/campaign.py RESULTS, here Harness.results), by
        name, which orders them by time within one ending; a record of another campaign whose name begins alike is
        left out by its values.campaign."""
        name = Path(directory).name
        found = []
        for path in sorted(self.results.glob(f"kampan_{name}_*.json")):
            doc = read_json(path)
            if (doc.get("values") or {}).get("campaign") == name:
                found.append((path, doc))
        return found

    def injected(self, mapping, campaign, group, scenario, attempt, default=None):
        """What a test injected for a session (the class docstring): under (campaign, group, scenario, attempt), else
        under (group, scenario, attempt); a set gives True or False."""
        keys = ((campaign, group, scenario, attempt), (group, scenario, attempt))
        if isinstance(mapping, (set, frozenset)):
            return any(key in mapping for key in keys)
        return next((mapping[key] for key in keys if key in mapping), default)

    def progress(self, directory):
        return (len(self.captures), len(self.lab.calls),
                len(list((Path(directory) / "attempts").glob("*.json"))))

    def allowed_stops(self, vm):
        """Lab.stops: the groups planned on the VM in every campaign this harness initialized, and RUNAWAY."""
        return RUNAWAY + sum(len({row["group"] for row in read_json(directory / "campaign.json")["sessions"]
                                  if row.get("vm") == vm}) for directory in self.campaigns)

    # ---------------------------------------------------------------- what the tests read

    def manifest(self, directory):
        return read_json(Path(directory) / "campaign.json")

    def plan_rows(self, directory):
        """The sessions of the plan the campaign froze, with the campaign's session IDs."""
        return self.manifest(directory)["sessions"]

    def of(self, directory):
        """The captures of one campaign, in the order they ran."""
        name = Path(directory).name
        return [x for x in self.captures if x["campaign"] == name]

    def boots(self, directory):
        """{(vm, group): {role, start, end, first, sessions}} of one campaign: the time of a group's boot is that of
        its sessions (start of the first, end of the last)."""
        out = {}
        for x in self.of(directory):
            boot = out.setdefault((x["vm"], x["group"]), {"role": x["role"], "start": x["t0"], "end": x["t1"],
                                                          "first": x, "sessions": []})
            boot["end"] = max(boot["end"], x["t1"])
            boot["sessions"].append(x)
        return out

    def starts(self, directory):
        """{(vm, group): [lab steps]} of one campaign: the commands of LAB_STEPS on the group's VM after the VM's last
        capture before the group's first one, each {vm, verb, argv, seed, code, out, err, order}."""
        out = {}
        for (vm, group), boot in self.boots(directory).items():
            first = boot["first"]["order"]
            after = max((x["order"] for x in self.captures if x["vm"] == vm and x["order"] < first), default=0)
            out[vm, group] = [call for call in self.lab.calls if call["vm"] == vm and call["verb"] in LAB_STEPS
                              and after < call["order"] < first]
        return out

    def accepted(self, sid):
        """Whether the audit of the session accepted it (None: not audited)."""
        return next((x["accepted"] for x in self.audits if x["sid"] == sid), None)

    # ---------------------------------------------------------------- the fakes

    def patch(self):
        mp = self.mp
        mp.setattr(c, "COLLECTIONS", self.collections)
        mp.setattr(c, "BASE", self.base)
        # Package B9b (design NAVRH_B9b 1.1): every ending writes its record into data/results; in a test into
        # Harness.results. The name is set also where the code before B9b has none (raising False).
        mp.setattr(c, "RESULTS", self.results, raising=False)
        for name in ("RETRY_PAUSE_S", "WAIT_POLL_S", "START_GRACE_S"):
            mp.setattr(c, name, 0)
        mp.setattr(c, "git", self.git)
        mp.setattr(c, "runtime_identity", lambda: json.loads(json.dumps(RUNTIME)))
        mp.setattr(c, "mount_identity", lambda path, allow_system=False: {
            "target": str(self.archive), "fstype": "test", "uuid": "test-archive", "system_disk": True})
        mp.setattr(c, "guard_mount", lambda *a, **k: None)
        mp.setattr(c, "verify_frozen", lambda *a, **k: None)  # As scripts/tests/test_campaign.py lab.
        mp.setattr(c, "hold_sleep_inhibitor", lambda: None)  # The real one needs logind (test_campaign.py lab).
        mp.setattr(c, "sleep_inhibited", lambda: False)
        mp.setattr(c, "process_identity", lambda pid: {"alive": pid} if pid == os.getpid() else None)
        mp.setattr(c, "run_child", self.run_child)
        mp.setattr(os, "geteuid", lambda: 0)
        mp.setenv("SUDO_USER", OWNER)
        for name in ("SUDO_UID", "SUDO_GID", "HYPTCN_COLLECTION_LOCK_FD"):
            mp.delenv(name, raising=False)
        mp.setattr(collection, "user_command", lambda command: list(map(str, command)))
        mp.setattr(collection, "guest_identity", lambda p: self.lab.identity(p["vm"]))
        mp.setattr(collection, "qemu_process", self.lab.qemu)
        mp.setattr(collection, "host_memory", lambda qemu: dict(MEMORY))
        mp.setattr(collection, "lab_json", self.lab_json)
        mp.setattr(collection, "run_session", self.capture)
        mp.setattr(collection, "audit_session", self.audit)
        from scripts import audit_selftest, gates
        mp.setattr(gates, "require", self.require)
        mp.setattr(audit_selftest, "require_selftest", self.require_selftest)
        from tcn import pecat
        mp.setattr(pecat, "KNIHA", self.ledger)
        mp.setattr(pecat, "ZAZNAM", self.ledger)
        original_write, original_kontrola = pecat._write, pecat.kontrola

        def write(path, doc, command):
            if Path(path).resolve() == TRACKED_LEDGER.resolve():
                raise AssertionError("a test wrote the tracked ledger " + str(TRACKED_LEDGER))
            return original_write(path, doc, command)

        def kontrola(*args, **kwargs):
            self.kontrola.append({"args": [str(a) for a in args], "purpose": kwargs.get("purpose")})
            return original_kontrola(*args, **kwargs)
        mp.setattr(pecat, "_write", write)
        mp.setattr(pecat, "kontrola", kontrola)
        real_run, real_check_output, real_popen = subprocess.run, subprocess.check_output, subprocess.Popen

        def run(args, *more, **kw):
            served = self.serve(argv_of(args))
            if served is None:
                return real_run(args, *more, **kw)
            code, out, err = served
            streams = {"stdout": out, "stderr": err}
            kept = {}
            for name, text in streams.items():
                target = kw.get(name)
                if kw.get("capture_output") or target == subprocess.PIPE:
                    kept[name] = stdout_of(text, kw)
                elif name == "stderr" and target == subprocess.STDOUT:
                    kept["stdout"] = (kept.get("stdout") or stdout_of("", kw)) + stdout_of(text, kw)
                elif hasattr(target, "write"):  # A file of the caller, as a child's output would go there.
                    target.write(text.encode() if "b" in getattr(target, "mode", "") else text)
            result = subprocess.CompletedProcess(args, code, kept.get("stdout"), kept.get("stderr"))
            if kw.get("check") and code:
                raise subprocess.CalledProcessError(code, args, result.stdout, result.stderr)
            return result

        def check_output(args, *more, **kw):
            served = self.serve(argv_of(args))
            if served is None:
                return real_check_output(args, *more, **kw)
            code, out, err = served
            if code:
                raise subprocess.CalledProcessError(code, args, stdout_of(out, kw), stdout_of(err, kw))
            return stdout_of(out, kw)

        def popen(args, *more, **kw):
            argv = argv_of(args)
            if child_kind(argv) is not None or forbidden(argv) is not None:
                raise AssertionError("the tests never start this for real (serve it through run_child, "
                                     "subprocess.run, subprocess.check_output or collection.lab_json): "
                                     + shlex.join(argv))
            return real_popen(args, *more, **kw)
        mp.setattr(subprocess, "run", run)
        mp.setattr(subprocess, "check_output", check_output)
        mp.setattr(subprocess, "Popen", popen)
        real_finish = c.finish_corpus

        def finish(directory, manifest, p, reports, *more, **kw):
            """The spy of finish_corpus: the call is recorded, then the real function builds and checks the index."""
            self.finished.append({"campaign": Path(directory).name, "vm": manifest.get("vm"),
                                  "reports": [str(r) for r in reports]})
            return real_finish(directory, manifest, p, reports, *more, **kw)
        mp.setattr(c, "finish_corpus", finish)

    def git(self, *args):
        """git of the frozen tree: a clean worktree at COMMIT."""
        if args[:1] == ("status",):
            return ""
        if args[:1] == ("rev-parse",):
            return COMMIT
        raise AssertionError("the campaign asked git " + shlex.join(args))

    def require(self, results, protocol, stage):
        """scripts/gates.py require: every stage before `stage` valid; recorded, never refused."""
        self.gates.append({"stage": stage, "protocol_sha256": digest(protocol), "phase": self.phase,
                           "label": self.label})

    def require_selftest(self, protocol_path, directory=None):
        """scripts/audit_selftest.py require_selftest: a passed self-test of these files; recorded, never refused."""
        self.selftests.append({"protocol_sha256": digest(protocol_path), "phase": self.phase, "label": self.label})
        return {"passed": True}

    def lab_json(self, p, *args, timeout=600):
        argv = [*collection.labctl_args(p), *map(str, args)]
        code, out, err = self.lab.command(argv)
        if code:
            self.refusals.append(f"labctl {shlex.join(argv)}: {err.strip()}")
            raise subprocess.CalledProcessError(code, ["labctl.py", *argv], out, err)
        return json.loads(out)

    def serve(self, argv):
        """(exit code, stdout, stderr) of a child this harness serves, else None."""
        kind = child_kind(argv)
        if kind is None:
            return None
        name, args = kind
        if name != "labctl" and threading.current_thread() is not threading.main_thread():
            # Harness.background: a runner in a thread only waits; its capture, audit or seal would run beside the
            # other runner's in fakes that redirect the process's output, so it fails here, by name, as a child.
            code, out, err = 2, "", f"{name}: a runner in a thread of the test never captures, audits or seals\n"
        elif name == "labctl":
            code, out, err = self.lab.command(args)
        elif name == "collection":
            code, out, err = self.collection_child(args)
        else:
            code, out, err = self.pecat_child(args)
        self.children.append({"kind": name, "argv": argv, "code": code, "err": err})
        if code and err.strip():  # A refusal (a rejecting audit exits 2 with its verdict, nothing on stderr).
            self.refusals.append(f"{name} {shlex.join(args)}: {err.strip()[-500:]}")
        return code, out, err

    def run_child(self, command, log, *, timeout, guard=lambda: None, lock_fd=None, grace=150):
        """scripts/campaign.py run_child: the served child's output goes to its log, its exit code is returned."""
        argv = list(map(str, command))
        served = self.serve(argv)
        if served is None:
            raise AssertionError("a campaign child the harness does not know: " + shlex.join(argv))
        code, out, err = served
        guard()
        with Path(log).open("x") as stream:
            stream.write(out + err)
        return code

    def collection_child(self, args):
        """collection.py with its own command line (collection.main); run and audit are the fakes below."""
        out, err = io.StringIO(), io.StringIO()
        errors = (ValueError, OSError, KeyError, subprocess.SubprocessError,
                  getattr(collection, "FeatureError", ValueError), getattr(collection, "WindowError", ValueError))
        self.phase = "session"
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = collection.main(list(args))
        except SystemExit as exit_:  # Its parser refused the command line.
            code = exit_.code if type(exit_.code) is int else 2
        except errors as error:  # As collection.py's __main__: the reason on stderr, exit 2.
            code = 2
            err.write(f"collection: {error}\n")
        finally:
            self.phase = "campaign"
        return code, out.getvalue(), err.getvalue()

    def pecat_child(self, args):
        """python -m tcn.pecat in this process, so that it reads and writes tcn.pecat.KNIHA of the test."""
        from tcn import pecat
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = pecat.main(list(args))
        except SystemExit as exit_:
            code = exit_.code if type(exit_.code) is int else 2
        return code, out.getvalue(), err.getvalue()

    def capture(self, a, p):
        """collection.py run (collection.run_session) of a session of a planned role under schema 3: what its command
        line and collection.v5_run decide (design 1.2: --mode and --attempt, the attempt of the planned session, its
        seed, the stage of the mode), the boot and QEMU the campaign expects, then the files a capture leaves."""
        if p.get("schema") != pv.SCHEMA or a.role == "diagnostic":
            raise AssertionError("a campaign of protocol v5 captures sessions of planned roles under schema 3")
        campaign = Path(a.protocol).resolve().parent
        manifest = read_json(campaign / "campaign.json")
        tries = sum(x["campaign"] == a.campaign_id for x in self.captures)
        if tries >= len(manifest["sessions"]) + RUNAWAY:
            raise AssertionError(f"runaway replacements: campaign {a.campaign_id} captured {tries} sessions for a "
                                 f"plan of {len(manifest['sessions'])} and RUNAWAY {RUNAWAY}")
        v5 = collection.v5_run(a, p)
        vm = p["vm"]
        key = (a.campaign_id, a.group, a.scenario, getattr(a, "attempt", None))
        if self.injected(self.fail_capture, *key):  # Package B9b: an error of the runner (the child fails at once).
            raise ValueError(f"synthetic failure of the capture of {a.session_id}")
        identity, qemu = self.lab.identity(vm), self.lab.qemu(p["domain"])
        if getattr(a, "expected_boot_id", None) and identity["boot_id"] != a.expected_boot_id:
            raise ValueError("guest boot differs from campaign group")
        if getattr(a, "expected_qemu", None) and qemu != json.loads(a.expected_qemu):
            raise ValueError("VM process differs from campaign group (restart or restore)")
        out = self.collections / a.campaign_id / vm / a.session_id
        out.parent.mkdir(parents=True, exist_ok=True)
        out.mkdir()
        shutil.copyfile(a.protocol, out / "protocol.json")
        shutil.copytree(self.profile, out / "profile")
        overlap = self.injected(self.overlap, *key)  # Package B9b: at the same time as an earlier session.
        if overlap is not None:
            other, shift = overlap
            earlier = next(x for x in self.captures if self.injected({other}, x["campaign"], x["group"],
                                                                     x["scenario"], x["attempt"]))
            t0, t1 = self.clock.take(p, start=earlier["t0"] + shift)
        else:
            t0, t1 = self.clock.take(p)
        meta = {"schema": "hyptcn3/collection-session/2", "session_id": out.name, "campaign_id": a.campaign_id,
                "vm": vm, "domain": p["domain"], **({"replaces": a.replaces} if a.replaces else {}),
                "role": a.role, "group": a.group, "group_attempt": a.group_attempt,
                "attempt": getattr(a, "attempt", None), "plan_mode": getattr(a, "mode", None),
                "scenario": a.scenario, "typ": "benign", "seed": a.seed, "cycles": v5["cycles"],
                "guest_before": identity, "events": v5["events"], "event_grace_s": p["events"]["grace_s"],
                **({"controls": v5["controls"]} if "controls" in v5 else {}),
                "protocol_sha256": digest(a.protocol), "profile_sha256": c.tree_hashes(self.profile),
                "collector_sha256": COLLECTOR, "traffic": v5["traffic"],
                # As scripts/collection.py run records them (package B9b: scripts/campaign_grids.py reads interval_s).
                "collector_settings": {"writer": "delta", "fsync": collection.COLLECTOR_FSYNC, "hash": "sha256",
                                       "writer_thread": True, "mlock": collection.COLLECTOR_MLOCK,
                                       "interval_s": p["interval_s"], "full_every": p["full_every"],
                                       "bin_bytes": p["bin_bytes"]},
                "host_context": {"host_boot": HOST_BOOT, "qemu": qemu, "memory": dict(MEMORY), "other_vms": []},
                "commit": manifest["commit"], "commit_dirty": False, "measurement_dirty": [], "host": "test-host"}
        collection.write_json(out / "session.json", meta)
        collection.write_json(out / "events.json", {"schema": "hyptcn3/session-events/1", "events": [],
                                                     "note": "synthetic record of the test"})
        if a.role == pv.CONTROL_ROLE:  # As test_dataset_plan session: build hashes it.
            collection.write_json(out / "controls.json", {"schema": pv.CONTROLS_SCHEMA, "controls": [],
                                                          "note": "synthetic record of the test"})
        (out / "raw").mkdir()
        (out / "raw/frame000000.vmicd").write_bytes(b"synthetic RAM " + out.name.encode())
        collection.write_json(out / "end.json", {"completed": True, "measurement_started": True,
                                                 "guest_after": identity, "measure_start_unix": t0,
                                                 "measure_end_unix": t1})
        self.captures.append({
            "campaign": a.campaign_id, "vm": vm, "sid": out.name, "role": a.role, "group": a.group,
            "scenario": a.scenario, "attempt": getattr(a, "attempt", None), "mode": getattr(a, "mode", None),
            "seed": a.seed, "replaces": a.replaces, "t0": t0, "t1": t1, "boot": identity["boot_id"], "qemu": qemu,
            "order": next(self.sequence), "directory": str(out),
            "ledger": {entry["session"] for entry in ledger_entries(self.ledger).values()},
            "done": {path.name[:-len(".done.json")] for path in (campaign / "attempts").glob("*.done.json")}})
        during = self.injected(self.during, *key)
        if during is not None:  # Package B9b: while the session's runner runs (the operator's stop request).
            during()

    def audit(self, directory, p, protocol_path, output):
        """collection.py audit (collection.audit_session): the record of the session with its real archive
        (audit_values); a session named in reject is refused with REJECTION, or with the (code, reason) a test gives
        it in codes; tolerated and marked add the counts a test gives it (package B9b)."""
        src = Path(directory)
        meta = read_json(src / "session.json")
        key = (meta["campaign_id"], meta["group"], meta["scenario"], meta.get("attempt"))
        accepted = not self.injected(self.reject, *key)
        output = Path(output)
        values = audit_values(src, p, protocol_path, output, extractor=self.extractor, accepted=accepted,
                              rejection=self.injected(self.codes, *key, default=REJECTION),
                              tolerated=self.injected(self.tolerated, *key), marked=self.injected(self.marked, *key))
        campaign = read_json(Path(protocol_path).resolve().parent / "campaign.json")
        write_new(output, {"schema": "hyptcn3/collection-audit/1", "date": "2026-11-23T00:00:00+00:00",
                           "commit": campaign["commit"], "commit_dirty": False, "measurement_dirty": [],
                           "host": "test-host", "guest": meta["guest_before"], "command": "collection.py audit (fake)",
                           "n": values["windows"], "values": values})
        self.audits.append({"sid": src.name, "accepted": accepted, "report": str(output),
                            "order": next(self.sequence)})
        return 0 if accepted else 2
