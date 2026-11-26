"""The faults of stage G2: their forms and expected names, the injector beside a G2 session, the plan of the fault
sessions and their block (protocol v5, package H1b3).

    python -m skuska.poruchy plan  --protocol P
    python -m skuska.poruchy block --protocol P --deck DECK.json --vm a (--sessions N | --only c01,f01)
                                   --other-vm g2|idle [--cycles N] [--rate SCENARIO=R ...] [--g2-dir DIR] [--dry-run]
    python skuska/poruchy.py pressure --step-mib N --step-s S --mib-max M --parent PID   (the memory fault's child)

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H4, the criterion
live_fault_injections, section 3), the map dokazy/G2/mapa.md (row 9, its questions 11 and 12) and the lead's answers
Q56 (the forms and the expected names are committed before the first run; the memory pressure with the QEMU swap ban
of that VM lifted, expecting `logs: qemu_swap`), Q57 (600 cycles), Q60 (an error-free run has no induced fault, also
on the other VM) and Q26 (both VMs' QEMU share one unit). skuska/ is no directory of scripts/collection.py
MEASUREMENT_DIRS, so nothing here changes the measurement code (map point E).

FAULTS is written and committed before any fault runs (Q56) and never changed afterwards: a fault's form, its
parameters, what proves it happened, the scenario of its sessions and the exact reasons it must be refused with,
each with its origin in the code at commit f5f43d8 (17546fe and package H1b2). An expected name is one exact string of
the refusal: the error end.json records for a capture that did not complete, as scripts/campaign.py
incomplete_reasons gives it, or a reason of the audit's verdict (values.reasons of scripts/collection.py audit). A
fault is refused by its names when every one of them is among those the session received.

The injector (INJECT_RULE) is a hook of skuska/g2.py Block.beside: a thread of the block, started before the run and
stopped after it. The block runs as root through one pcc-sudo call, so the signals need no sudo of their own
(ROOT_NOTE says what else needs root). It finds the exact PID in the session's own process tree, times the fault
from the session's sidecars, writes its record outside the session's directory and undoes what it left. The plan
(PLAN_RULE) and the block (FAULT_BLOCK_RULE, FAULT_DONE_RULE): 12 sessions, every fault once on each VM, and a clean
session of the same shape on each VM. The table of the faults is the mode faults of scripts/campaign_report.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python skuska/poruchy.py pressure, as the injector starts the pressure child.
    sys.path.insert(0, str(ROOT))

from scripts import collection, protocol_v5  # noqa: E402
from scripts.labctl import DAEMON_SERVICE  # noqa: E402
from skuska import g2  # noqa: E402

# The scenario of every fault session and of the clean session of each VM: one shape for all of them (Q57: a clean
# session per VM of the same shape). The stopped generator runs at rate high (map row 9: the variation its stop leaves
# grows with the rate); corp_high rather than eshop_high, since the burst of the arrivals the stop held back is then
# at most about 16.6/s x 120 s = 2000 user sessions against the cap of 3984, not about 3650 against 7307, and the docs
# service that the killed service fault kills serves corp's documents and reports.
SCENARIO = "corp_high"

FAULTS = {
    "zabity_zberac": {
        "fault": "killed collector",
        "form": ("SIGKILL of the exact PID of the session's collector, vmicollect (scripts/collection.py collectors of "
                 "the VM's domain that descend from the session's own collection.py run), never of "
                 "scripts/lab_capture.sh, whose EXIT trap would end before raw/capture.json; after the first sidecar, "
                 "at an idle moment of the collector: lead_s before the deadline of a cycle whose previous sidecar "
                 "is published, the first such deadline at least at_s after the first sidecar that is neither a full "
                 "snapshot nor the cycle after one"),
        "parameters": {"at_s": 60, "lead_s": 0.5, "longest_s": 60},
        "proof": "the PID is gone or a zombie within 10 s of the signal",
        "scenario": SCENARIO,
        "expected": ["ValueError: collector failed; see capture.log", "logs: collector_exit_code"],
        "origin": ("map row 9 and question 11 (Q56): scripts/collection.py capture_session raises 'collector failed; "
                   "see capture.log' when scripts/lab_capture.sh exits non-zero (line 1532) and records it in "
                   "end.json as '<type>: <message>' (line 1560), which scripts/campaign.py incomplete_reasons gives as "
                   "it stands (line 1830); lab_capture.sh writes raw/capture.json with the collector's exit code "
                   "(137 after SIGKILL) after its wait and exits 1, and the log audit refuses an exit code other than "
                   "0 (scripts/collection_logs.py collector, line 660), which scripts/collection.py audit_session "
                   "names 'logs: collector_exit_code'")},
    "zdrzany_procesor": {
        "fault": "delayed processor",
        "form": ("SIGSTOP of the exact PID of the session's vmicollect (as for the killed collector) lead_s before "
                 "the deadline of a cycle chosen as for the killed collector, SIGCONT stop_s later: that cycle starts "
                 "about stop_s - lead_s = 1.5 s late, less than the interval, so no slot is missed"),
        "parameters": {"at_s": 60, "lead_s": 0.5, "stop_s": 2.0, "longest_s": 60},
        "proof": ("the PID's state is T after SIGSTOP; the sidecar of the delayed cycle records a sched.lateness_s "
                  "above audit.lateness_max_s"),
        "scenario": SCENARIO,
        "expected": ["cycle start later than the audit bound"],
        "origin": ("map row 9 and question 11: vmicollect/src/sched.c keeps absolute deadlines on CLOCK_MONOTONIC and "
                   "records the start of a cycle minus its deadline as sched.lateness_s of its sidecar, so the cycle "
                   "after SIGCONT starts about 1.5 s late and the next deadline stays on the grid; scripts/collection.py "
                   "audit_session refuses a lateness above audit.lateness_max_s, 0.5 s, by this reason (line 1923)")},
    "tlak_na_pamat": {
        "fault": "memory pressure",
        "form": ("at_s after the first sidecar, with the other VM idle (no collector and no generator aimed at it: "
                 "both VMs' QEMU share the unit whose ban is lifted, Q26): memory.swap.max of the cgroup of the "
                 "session's QEMU, the user unit hyptcn-libvirtd.service of way 1, from 0 to max; a child of the "
                 "injector with oom_score_adj 1000 takes step_mib of anonymous memory every step_s and touches all "
                 "of it again and again, until VmSwap of the session's QEMU is at least swap_kb, and holds hold_s "
                 "longer, at most max_s in all; then the child is killed (its exact PID) and memory.swap.max is 0 "
                 "again; the VM restarts before its next session (a run refuses a QEMU with swapped memory)"),
        "parameters": {"at_s": 60, "step_mib": 256, "step_s": 0.5, "swap_kb": 1024, "hold_s": 10, "max_s": 600,
                       "longest_s": 660},
        "proof": ("VmSwap of the session's QEMU at least swap_kb while the ban is lifted; memory.swap.max max during "
                  "the pressure and 0 after it"),
        "scenario": SCENARIO,
        "expected": ["logs: qemu_swap"],
        "origin": ("the lead's answer to Q56 (map question 11): the log audit refuses a session in which a sample of "
                   "the host monitor (one a second) shows swapped memory of the session VM's QEMU "
                   "(scripts/collection_logs.py monitor and qemu_unswapped, line 645), named 'logs: qemu_swap'; with "
                   "the ban in place no page of that QEMU can be swapped (the start refuses a QEMU without it, "
                   "scripts/collection.py run_session lines 1175-1181), so the fault lifts the ban of the unit")},
    "restart_vm": {
        "fault": "VM restart during the session",
        "form": ("at_s after the first sidecar, scripts/labctl.py reboot of the session's VM as its owner (virsh "
                 "reboot --mode agent: the same QEMU, a new boot of the guest); the next session in a new group"),
        "parameters": {"at_s": 60, "timeout_s": 300, "longest_s": 300},
        "proof": "labctl reboot exits 0 and prints the session's boot as previous_boot and another boot_id",
        "scenario": SCENARIO,
        "expected": ["ValueError: guest rebooted or changed during capture"],
        "origin": ("map row 9 and question 11: scripts/collection.py capture_session compares the guest's identity "
                   "after the capture with the one before it and raises 'guest rebooted or changed during capture' "
                   "(line 1541), recorded in end.json as '<type>: <message>' and given by campaign.incomplete_reasons "
                   "as it stands")},
    "zastaveny_generator": {
        "fault": "stopped generator",
        "form": ("at_s after the first sidecar, SIGSTOP of the exact PID of the session's scripts/host_traffic.py "
                 "(scripts/collection.py generators aimed at the VM's target that descend from the session's run), "
                 "SIGCONT stop_s later, at rate high"),
        "parameters": {"at_s": 60, "stop_s": 120, "longest_s": 150},
        "proof": "the PID's state is T after SIGSTOP and no longer T after SIGCONT, stop_s apart",
        "scenario": SCENARIO,
        "expected": ["logs: traffic_realism:arrival_cv"],
        "origin": ("map row 9 and question 11: the scheduler of scripts/host_traffic.py offers every arrival at its "
                   "time and records it when it offers it (OpenLoop._due, the recorder's clock at that moment), so "
                   "after SIGCONT the arrivals the stop held back come in one burst; scripts/traffic_log.py realism "
                   "measures the coefficient of variation of the spacings of the measure phase's arrivals rescaled by "
                   "the planned envelope against audit.traffic.arrival_cv [0.8, 1.2] (lines 822-825), and the log "
                   "audit names a requirement missed 'traffic_realism:<name>' (scripts/collection_logs.py realism)")},
    "zabita_sluzba": {
        "fault": "killed guest service outside an event",
        "form": ("at_s after the first sidecar, in a session without events, scripts/labctl.py exec --guest-command "
                 "'systemctl kill -s KILL hyptcn-lab@docs' as the VM's owner; systemctl show of the unit in the "
                 "guest before the kill and wait_s after it"),
        "parameters": {"at_s": 60, "unit": "hyptcn-lab@docs", "wait_s": 20, "longest_s": 300},
        "proof": "NRestarts of the unit higher wait_s after the kill than before it, and another ExecMainPID",
        "scenario": SCENARIO,
        "expected": ["logs: service_restarted:hyptcn-lab@docs"],
        "origin": ("map row 9 and question 11: hyptcn-lab@docs has Restart=on-failure and RestartSec=3 "
                   "(lab/hyptcn-lab@.service), so systemd restarts it after the SIGKILL and its NRestarts, "
                   "InvocationID, ExecMainPID and ExecMainStartTimestampMonotonic differ between "
                   "guest/state_before.json and guest/state_after.json; in a session without events no event type "
                   "restarts a unit (scripts/collection_logs.py timed_units is empty) and the section guest refuses "
                   "the change by its name (line 371), 'logs: service_restarted:hyptcn-lab@docs'; beside an event of "
                   "restart_databazy it would be service_restarted_outside_event (package B12), so its session has "
                   "no events (map row 9)")},
}

STAGE = g2.STAGE
KIND_FAULT, KIND_CLEAN = "fault", "fault_clean"  # The kinds of a spec and of its session record (g2 Block.record).
FAULT_SCHEMA = "hyptcn3/g2-fault/1"
SIDECAR_SCHEMA = "vmicollect/1"
BESIDE = "poruchy"  # The injector's records: <G2 directory>/poruchy/<session>.json, outside the session directory.
SCRIPT = Path(__file__).resolve()
POLL_S = 0.5  # How often the injector reads the session's sidecars and the QEMU's swap (the executor's judgment).
LATE_S = 0.25  # A fault timed by a deadline waits for the next one when it would act later than this (judgment).
TRIES = 5  # Deadlines a fault timed by a deadline tries before it is not induced (judgment).
GONE_S = 10  # The killed collector's PID is gone or a zombie within this (FAULTS zabity_zberac proof).
END_MARGIN_S = 300  # No fault may end later than this before the planned end of the measured phase (judgment).
LABCTL_EXEC_S = 60  # The timeout of one labctl exec in the guest (the executor's judgment; the agent answers in < 1 s).
JOIN_S = 360  # How long the hook waits for the injector's thread after the run (the longest labctl call is 300 s).
KILL_COMMAND = "systemctl kill -s KILL {unit}"  # FAULTS zabita_sluzba, the guest command of its form.
SHOW_COMMAND = "systemctl show -p NRestarts -p ExecMainPID -p ActiveState -p SubState {unit}"
SHOW_KEYS = ("NRestarts", "ExecMainPID", "ActiveState", "SubState")

INJECT_RULE = (
    "package H1b3 (map row 9, Q56): beside every session of the fault plan a thread of the block, started before the "
    "run (skuska/g2.py Block.beside) and stopped after it, waits for the session's first sidecar (raw/*.json of "
    "schema vmicollect/1, read once published) and injects the session's fault in the form FAULTS states, timed from "
    "the sidecars: at_s after the first sidecar's timestamp_unix, or lead_s before the deadline of a cycle (the newest "
    "sidecar's timestamp_unix minus its sched.lateness_s, plus whole intervals), the first deadline at least at_s "
    "after the first sidecar that is no full snapshot, not the cycle after one and not one of the last two cycles, "
    "whose previous cycle's sidecar is published when the injector wakes and which it reaches no later than LATE_S, "
    "else the next one, at most TRIES; no fault starts when its longest_s would end less than END_MARGIN_S before the "
    "planned end of the measured phase (the first sidecar's deadline plus cycles intervals); the exact PID of the "
    "collector or of the generator is the one process that scripts/collection.py collectors (of the VM's domain) or "
    "generators (aimed at the VM's target) names and that descends from the session's own run (the one child of the "
    "block whose command line is the run's), never a pattern over all processes, and its command line is read again "
    "right before the signal; none, or two such processes, refuse the fault by name and nothing is signalled; every "
    "signal, labctl call, change of memory.swap.max and the pressure child are recorded with their times; at its end, "
    "and again after the run, the injector undoes what it left (SIGCONT of a process it stopped, the pressure child "
    "killed by its PID, memory.swap.max back to its value before), and the block stops by name when it could not; "
    "its record <G2 directory>/poruchy/<session>.json, a new file with check E's header outside the session's "
    "directory, holds the fault, its form and expected names (FAULTS and their sha256), the actions, the proof, "
    "whether the fault was induced and why not, the fault's window, the measured phase of end.json and G2_VALUES_NOTE; "
    "the clean session of the plan gets one too, without a fault")
PLAN_RULE = (
    "package H1b3 and the lead's answer to Q57: a clean session on each VM of the protocol (c01 on the first VM, c02 "
    "on the second, ...) and every fault of FAULTS once on each VM (f01, f02, ... the faults in the order of FAULTS, "
    "each on the VMs in their order); every session diagnostic, of the scenario of its fault (FAULTS scenario, one for "
    "all: corp_high, rate high as the stopped generator needs, so the clean session of a VM has the same shape), "
    "without events (the killed service needs a session without them, and the shape is one), of pilot_cycles cycles "
    "(600, Q57), fewer only once a clean session of that length was accepted on each VM and never fewer than its "
    "fault needs (at_s + longest_s + END_MARGIN_S); the traffic seed of a session is protocol_v5.seed(the protocol's "
    "name, traffic, G2/<id>, its number, 1), a group no stream of the plan, the deck of events or the draw of the "
    "controls has (skuska/g2.py STREAMS_RULE); a session run again keeps its plan item")
FAULT_BLOCK_RULE = (
    "a block of the fault plan on one VM: skuska/g2.py Block (BLOCK_RULE) with the plan's sessions of the VM, of the "
    "block's cycles, and the injector beside each run (INJECT_RULE); every session starts a new group "
    "(campaign.start_steps: labctl stop, start, reset, pretouch), so no fault reaches the next session (a QEMU that "
    "swapped, a guest that rebooted, the lab after the burst of the stopped generator) and every fault and the clean "
    "session start from the same state; refused before it, beside the refusals of Block: the memory fault with "
    "--other-vm g2 (both VMs' QEMU share the unit whose ban it lifts, Q26), --cycles above pilot_cycles, a session "
    "shorter than its fault needs, and fault sessions shorter than pilot_cycles before a clean session of that length "
    "was accepted on each VM (Q57); a session whose injector could not undo what it left stops the block by name")
FAULT_DONE_RULE = (
    "a fault session of the plan is done when a record of it with the block's cycles holds the injector's summary "
    "with the fault induced, whatever its verdict (the table of the faults judges the refusal); a clean session when "
    "a record of it with the block's cycles is done by DONE_RULE of skuska/g2.py; --sessions N takes the first N plan "
    "sessions of the VM that are not done, each as its next attempt")
G2_VALUES_NOTE = (
    "the lead's answer to Q60: a session with an induced fault is no error-free run and never counts for the values of "
    "G2 (audit.collector_majflt_max, audit.warnings_allowed), and neither does a session of the other VM whose "
    "measured phase overlaps the fault's window; the clean session of the plan is an error-free run unless that holds "
    "for it")
ROOT_NOTE = (
    "the block runs as root through one pcc-sudo call (skuska/g2.py BLOCK_RULE), and so does its injector: the signals "
    "to vmicollect and host_traffic.py need root, since both run as root under collection.py run; labctl reboot and "
    "exec run as the VM's owner (collection.user_command, as every labctl call of a capture); memory.swap.max of the "
    "unit hyptcn-libvirtd.service lies in the subtree of the owner's systemd manager, where the ban of way 1 is set "
    "without root (labctl daemon_step), while the ban of a QEMU in a cgroup outside that subtree (a system slice, a "
    "machine scope) needs root, and the injector lifts the ban only for a QEMU in that unit, the only way the group "
    "start of G2 admits (campaign.start_steps); the pressure child raises its own oom_score_adj, which needs no root")
NOTE = ("Stage G2 (proposal 10.3): a fault injected beside a G2 session on a VM, whose data never become a dataset. "
        "Written by skuska/poruchy.py.")


class NotInduced(ValueError):
    """The fault was not injected, by name (a refusal before any signal, or a session that ended first)."""


def faults_sha256():
    """The sha256 of FAULTS as canonical JSON: the records name the forms and names they ran with."""
    return hashlib.sha256(json.dumps(FAULTS, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def beside_path(g2_dir, session_id):
    """Where the injector writes its record of a session: <G2 directory>/poruchy/<session>.json."""
    return Path(g2_dir).absolute() / BESIDE / f"{session_id}.json"


# ------------------------------------------------------------------ the plan

def plan(p):
    """The sessions of the fault test of the protocol `p` (PLAN_RULE): [{id, number, vm, fault, scenario, seed}];
    ValueError when the protocol cannot hold it."""
    vms = [row["name"] for row in p.get("vms", [])]
    if not vms:
        raise ValueError("the fault plan needs the VMs of the protocol")
    for name, fault in FAULTS.items():
        scenario = p["scenarios"].get(fault["scenario"])
        if scenario is None:
            raise ValueError(f"the scenario {fault['scenario']} of the fault {name} is not in the protocol")
        if name == "zastaveny_generator" and scenario["intensity"] != "high":
            raise ValueError(f"the stopped generator runs at rate high; {fault['scenario']} is not high")
    if len({fault["scenario"] for fault in FAULTS.values()}) != 1:
        raise ValueError("the faults take one scenario, so that one clean session per VM has their shape (Q57)")

    def item(ident, number, vm, fault):
        return {"id": ident, "number": number, "vm": vm, "fault": fault, "scenario": SCENARIO,
                "seed": protocol_v5.seed(p["name"], "traffic", f"G2/{ident}", number, 1)}
    sessions = [item(f"c{i:02d}", i, vm, None) for i, vm in enumerate(vms, 1)]
    number = 0
    for name in FAULTS:
        for vm in vms:
            number += 1
            sessions.append(item(f"f{number:02d}", number, vm, name))
    return sessions


def minimum_cycles(p, fault):
    """The fewest cycles a session of `fault` holds it in (PLAN_RULE): at_s + longest_s + END_MARGIN_S, rounded up to
    whole intervals."""
    parameters = FAULTS[fault]["parameters"]
    return -(-(parameters["at_s"] + parameters["longest_s"] + END_MARGIN_S) // p["interval_s"])


# ------------------------------------------------------------------ the process tree and the sidecars

def descendants(table, root):
    """The PIDs below `root` in the process table {pid: {"ppid", ...}} (not root itself)."""
    children = {}
    for pid, row in table.items():
        children.setdefault(row["ppid"], []).append(pid)
    out, todo = set(), list(children.get(root, ()))
    while todo:
        pid = todo.pop()
        if pid not in out:
            out.add(pid)
            todo += children.get(pid, ())
    return out


def decoded(argv):
    return [arg.decode(errors="replace") if isinstance(arg, bytes) else str(arg) for arg in argv]


def deadline_of(side):
    """The deadline of a sidecar's cycle, Unix time: its start (timestamp_unix) minus its lateness."""
    return side["timestamp_unix"] - side["lateness_s"]


def next_deadline(sidecars, after, p, cycles):
    """(seq, Unix time) of the first deadline at least `after` (INJECT_RULE): counted from the newest sidecar, from
    its cycle + 2 on, no full snapshot, not the cycle after one, not one of the last two cycles; None past them."""
    newest = sidecars[max(sidecars)]
    k = newest["seq"] + 2
    while k < cycles - 2:
        unix = deadline_of(newest) + (k - newest["seq"]) * p["interval_s"]
        if unix >= after and k % p["full_every"] not in (0, 1):
            return k, unix
        k += 1
    return None


def unit_state(text):
    """{key: value} of `systemctl show -p ...` output (SHOW_KEYS)."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in SHOW_KEYS:
            out[key] = value.strip()
    return out


def last_json(text):
    """The last line of `text` that is a JSON object, else None (what labctl prints last)."""
    for line in reversed((text or "").splitlines()):
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if type(doc) is dict:
            return doc
    return None


# ------------------------------------------------------------------ the host

class Host:
    """Every host step of the injector, done for real (as root in the block); a test gives a fake with the same
    methods (no process is signalled, no labctl runs, no cgroup is written)."""

    def now(self):
        return time.time()

    def wait(self, event, seconds):
        """Sleep `seconds` or until `event` is set; True when it is set."""
        return event.wait(seconds)

    def table(self):
        """{pid: {"ppid", "state", "argv" (bytes)}} of every process now, from /proc."""
        out = {}
        for proc in Path("/proc").glob("[0-9]*"):
            try:
                stat = (proc / "stat").read_text()
                argv = [arg for arg in (proc / "cmdline").read_bytes().split(b"\0") if arg]
                fields = stat.rsplit(")", 1)[1].split()
                out[int(proc.name)] = {"ppid": int(fields[1]), "state": fields[0], "argv": argv}
            except (OSError, IndexError, ValueError):
                continue
        return out

    def argv(self, pid):
        try:
            return [arg for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if arg]
        except OSError:
            return None

    def state(self, pid):
        """The state letter of /proc/<pid>/stat (T stopped, Z zombie, ...), None when the process is gone."""
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            return None

    def collectors(self, domain):
        return collection.collectors(domain)

    def generators(self, target):
        return collection.generators(target=target)

    def signal(self, pid, number):
        os.kill(pid, number)

    def sidecars(self, raw, seen):
        """{seq: {file, seq, timestamp_unix, lateness_s, full}} of the sidecars in `raw` not in `seen` (names); a file
        that is not whole JSON yet is read again later."""
        out, raw = {}, Path(raw)
        for path in sorted(raw.glob("*.json")) if raw.is_dir() else []:
            if path.name in seen:
                continue
            try:
                doc = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            seen.add(path.name)
            if type(doc) is dict and doc.get("schema") == SIDECAR_SCHEMA and type(doc.get("seq")) is int:
                out[doc["seq"]] = {"file": path.name, "seq": doc["seq"], "timestamp_unix": doc.get("timestamp_unix"),
                                   "lateness_s": (doc.get("sched") or {}).get("lateness_s"),
                                   "full": (doc.get("output") or {}).get("full")}
        return out

    def labctl(self, p, arguments, timeout):
        """scripts/labctl.py with `arguments` for the VM of `p` as its owner (as collection.lab_json runs it):
        {command, rc, stdout, stderr}; rc None at a timeout."""
        command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", *collection.labctl_args(p),
                                           *arguments])
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
            return {"command": command, "rc": done.returncode, "stdout": done.stdout, "stderr": done.stderr[-500:]}
        except subprocess.TimeoutExpired as error:
            out = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout or ""
            return {"command": command, "rc": None, "stdout": out, "stderr": f"timeout after {timeout} s"}

    def qemu(self, domain):
        return collection.qemu_process(domain)

    def swap_kb(self, pid):
        return collection.qemu_swap_kb(pid)

    def cgroup(self, pid):
        """The cgroup v2 path of the process, None when unreadable."""
        try:
            for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
                hierarchy, _, path = line.split(":", 2)
                if hierarchy == "0":
                    return path
        except (OSError, ValueError):
            pass
        return None

    def swap_max(self, cgroup):
        return (Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "memory.swap.max").read_text().strip()

    def set_swap_max(self, cgroup, value):
        (Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "memory.swap.max").write_text(value + "\n")

    def other_vms(self, p):
        return collection.other_vms(p)

    def meminfo(self):
        return {line.split(":")[0]: int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                if line.split()[1:2] and line.split()[1].isdigit()}

    def pressure(self, step_mib, step_s, mib_max):
        """The pressure child (pressure() below), which dies with the thread that started it."""
        return subprocess.Popen([sys.executable, str(SCRIPT), "pressure", "--step-mib", str(step_mib), "--step-s",
                                 str(step_s), "--mib-max", str(mib_max), "--parent", str(os.getpid())], cwd=ROOT,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def alive(self, child):
        return child.poll() is None

    def stop_pressure(self, child):
        """SIGKILL to the child's exact PID (its Popen) and its exit code."""
        if child.poll() is None:
            child.kill()
        return child.wait(timeout=30)


# ------------------------------------------------------------------ the injector

class Injector:
    """The fault of one G2 session beside its run (INJECT_RULE). `command` is the run's command line, `parent` the
    PID of the block that runs it, `owner` (uid, gid) of the VM's owner or None."""

    def __init__(self, fault, p, session_dir, command, parent, cycles, host, *, owner=None, log=lambda text: None):
        self.fault, self.p, self.session_dir, self.parent = fault, p, Path(session_dir), parent
        self.command, self.cycles, self.host, self.owner, self.log = decoded(command), cycles, host, owner, log
        self.parameters = FAULTS[fault]["parameters"] if fault is not None else {}
        self.ended, self.lock = threading.Event(), threading.Lock()
        self.seen, self.sidecars, self.first = set(), {}, None
        self.actions, self.proof, self.candidates, self.window = [], {}, {}, None
        self.induced = None if fault is None else False
        self.why_not = self.error = None
        self.stopped = self.lifted = self.child = None  # What the injector must undo (clean).
        self.cleanup, self.unclean = [], []
        self.never = threading.Event()  # A wait the end of the run does not cut short.

    # -------------------------------------------------- helpers

    def act(self, what, **values):
        now = self.host.now()
        self.actions.append({"t": g2.utc(now), "unix": round(now, 3), "what": what, **values})
        self.log(f"fault {self.fault}: {what}" + "".join(f", {k} {v}" for k, v in values.items()
                                                        if k in ("pid", "seq", "cgroup", "rc", "swap_kb")))
        return now

    def read_sidecars(self):
        self.sidecars.update(self.host.sidecars(self.session_dir / "raw", self.seen))

    def session_json(self):
        return json.loads((self.session_dir / "session.json").read_text())

    def sleep_until(self, unix):
        """Wait until the Unix time `unix`; False when the run ended first."""
        while True:
            left = unix - self.host.now()
            if left <= 0:
                return not self.ended.is_set()
            if self.host.wait(self.ended, min(left, POLL_S)):
                return False

    def planned_end(self):
        return deadline_of(self.first) + self.cycles * self.p["interval_s"]

    def guard(self, start):
        """NotInduced when the fault starting at `start` would end less than END_MARGIN_S before the planned end."""
        end = start + self.parameters["longest_s"]
        if end > self.planned_end() - END_MARGIN_S:
            raise NotInduced(f"the fault would end at {g2.utc(end)}, less than {END_MARGIN_S} s before the planned end "
                             f"of the measured phase {g2.utc(self.planned_end())}")

    def at(self):
        """Sleep until at_s after the first sidecar (guarded); its time."""
        start = self.first["timestamp_unix"] + self.parameters["at_s"]
        self.guard(start)
        if not self.sleep_until(start):
            raise NotInduced("the session ended before the fault's time")
        return start

    def pick(self, kind):
        """The exact PID of the session's collector or generator (INJECT_RULE); NotInduced unless exactly one."""
        table = self.host.table()
        runs = sorted(pid for pid, row in table.items()
                      if row["ppid"] == self.parent and decoded(row["argv"]) == self.command)
        if len(runs) != 1:
            raise NotInduced(f"{len(runs)} processes of the session's run (children of the block {self.parent} with "
                             "the run's command line), not one: no signal")
        tree = descendants(table, runs[0])
        named = (self.host.collectors(self.p["domain"]) if kind == "collector"
                 else self.host.generators(self.p["target"]))
        inside = sorted(pid for pid in named if pid in tree)
        self.candidates[kind] = {"run": runs[0], "named": sorted(named), "in_session": inside}
        if len(inside) != 1:
            outside = sorted(set(named) - set(inside))
            raise NotInduced(f"{len(inside)} {kind}s of the session descend from its run {runs[0]}, not one: "
                             f"{inside or 'none'}" + (f" (outside the session: {outside})" if outside else "")
                             + "; no signal")
        return inside[0]

    def same(self, pid, kind):
        """NotInduced unless `pid` still runs the session's collector or generator (its command line read again)."""
        argv = self.host.argv(pid)
        good = argv is not None and (collection.is_collector(argv, self.p["domain"]) if kind == "collector" else
                                     collection.is_generator(argv)
                                     and collection.option(argv, b"--target") == self.p["target"].encode())
        if not good:
            raise NotInduced(f"the {kind} {pid} is gone or runs another program before the signal: no signal")

    def signal(self, pid, number, **values):
        with self.lock:
            self.host.signal(pid, number)
            if number == signal.SIGSTOP:
                self.stopped = pid
            elif number == signal.SIGCONT and self.stopped == pid:
                self.stopped = None
        return self.act(signal.Signals(number).name, pid=pid, **values)

    def at_deadline(self):
        """Sleep until lead_s before an idle deadline (INJECT_RULE); (seq, its deadline)."""
        after, lead = self.first["timestamp_unix"] + self.parameters["at_s"], self.parameters["lead_s"]
        for _ in range(TRIES):
            self.read_sidecars()
            found = next_deadline(self.sidecars, after, self.p, self.cycles)
            if found is None:
                raise NotInduced("no deadline of the session is left for the fault")
            seq, unix = found
            self.guard(unix)
            if not self.sleep_until(unix - lead):
                raise NotInduced("the session ended before the fault's deadline")
            self.read_sidecars()
            late = self.host.now() - (unix - lead)
            if seq - 1 in self.sidecars and late <= LATE_S:
                return seq, unix
            self.act("deadline skipped", seq=seq, deadline_unix=round(unix, 3),
                     why=(f"the sidecar of cycle {seq - 1} is not published" if seq - 1 not in self.sidecars
                          else f"{late:.3f} s late"))
            after = unix + self.p["interval_s"] / 2
        raise NotInduced(f"no idle deadline in {TRIES} tries")

    def wait_sidecar(self, seq, seconds):
        deadline = self.host.now() + seconds
        while seq not in self.sidecars and self.host.now() < deadline:
            self.read_sidecars()
            if seq not in self.sidecars:
                self.host.wait(self.never, POLL_S)  # The run cannot end while the cycle is being written.
        return self.sidecars.get(seq)

    # -------------------------------------------------- the run

    def run(self):
        """The thread's work: the fault of FAULTS, then the cleanup. Never raises."""
        if self.fault is None:
            return
        try:
            while not self.ended.is_set():
                self.read_sidecars()
                if self.sidecars:
                    self.first = self.sidecars[min(self.sidecars)]
                    self.act("first sidecar", seq=self.first["seq"], file=self.first["file"],
                             timestamp_unix=self.first["timestamp_unix"])
                    break
                self.host.wait(self.ended, POLL_S)
            if self.first is None:
                raise NotInduced("the session ended before its first sidecar")
            getattr(self, "_" + self.fault)()
        except NotInduced as refusal:
            self.why_not = str(refusal)
            self.act("not induced", why=self.why_not)
        except Exception as error:  # noqa: BLE001 - the record names it; the cleanup runs
            self.error = f"{type(error).__name__}: {error}"
            self.why_not = self.why_not or f"an error of the injector: {self.error}"
            self.act("error", error=self.error)
        finally:
            self.clean()
        if self.induced is not True and self.why_not is None:
            self.why_not = "its proof does not hold (proof)"

    def _zabity_zberac(self):
        pid = self.pick("collector")
        seq, unix = self.at_deadline()
        self.same(pid, "collector")
        start = self.signal(pid, signal.SIGKILL, seq=seq, deadline_unix=round(unix, 3))
        self.window = [round(start, 3), round(start, 3)]
        state, waited = self.host.state(pid), 0.0
        while state not in (None, "Z") and waited < GONE_S:
            self.host.wait(self.never, POLL_S)
            waited += POLL_S
            state = self.host.state(pid)
        self.proof = {"pid": pid, "seq": seq, "deadline_unix": round(unix, 3), "state_after": state,
                      "gone": state in (None, "Z")}
        self.induced = self.proof["gone"]

    def _zdrzany_procesor(self):
        pid = self.pick("collector")
        seq, unix = self.at_deadline()
        self.same(pid, "collector")
        stop = self.signal(pid, signal.SIGSTOP, seq=seq, deadline_unix=round(unix, 3))
        state = self.host.state(pid)
        self.sleep_until(stop + self.parameters["stop_s"])
        cont = self.signal(pid, signal.SIGCONT, seq=seq)
        self.window = [round(stop, 3), round(cont, 3)]
        side = self.wait_sidecar(seq, 3 * self.p["interval_s"] + GONE_S)
        bound = self.p["audit"]["lateness_max_s"]
        lateness = None if side is None else side["lateness_s"]
        self.proof = {"pid": pid, "seq": seq, "deadline_unix": round(unix, 3), "state_after_stop": state,
                      "stopped_s": round(cont - stop, 3), "sidecar": None if side is None else side["file"],
                      "lateness_s": lateness, "lateness_max_s": bound}
        self.induced = state == "T" and type(lateness) in (int, float) and lateness > bound

    def _zastaveny_generator(self):
        self.at()
        pid = self.pick("generator")
        self.same(pid, "generator")
        stop = self.signal(pid, signal.SIGSTOP)
        state = self.host.state(pid)
        self.sleep_until(stop + self.parameters["stop_s"])
        cont = self.signal(pid, signal.SIGCONT)
        after = self.host.state(pid)
        self.window = [round(stop, 3), round(cont, 3)]
        self.proof = {"pid": pid, "state_after_stop": state, "state_after_cont": after,
                      "stopped_s": round(cont - stop, 3), "stop_s": self.parameters["stop_s"]}
        self.induced = (state == "T" and after not in (None, "T")
                        and cont - stop >= self.parameters["stop_s"] - POLL_S)

    def _restart_vm(self):
        start = self.at()
        boot = self.session_json()["guest_before"]["boot_id"]
        self.act("labctl reboot", previous_boot=boot)
        done = self.host.labctl(self.p, ["reboot"], self.parameters["timeout_s"])
        end = self.act("labctl reboot done", rc=done["rc"])
        printed = last_json(done["stdout"]) or {}
        self.window = [round(start, 3), round(end, 3)]
        self.proof = {"command": [str(x) for x in done["command"]], "rc": done["rc"], "session_boot": boot,
                      "previous_boot": printed.get("previous_boot"), "boot_id": printed.get("boot_id"),
                      "stderr": done["stderr"][-300:]}
        self.induced = (done["rc"] == 0 and printed.get("previous_boot") == boot
                        and printed.get("boot_id") not in (None, "", boot))

    def show(self, unit):
        done = self.host.labctl(self.p, ["exec", "--guest-command", SHOW_COMMAND.format(unit=unit)], LABCTL_EXEC_S)
        return {"rc": done["rc"], **unit_state(done["stdout"])}

    def _zabita_sluzba(self):
        start = self.at()
        unit = self.parameters["unit"]
        before = self.show(unit)
        if before["rc"] != 0 or not before.get("NRestarts", "").isdigit():
            raise NotInduced(f"the state of {unit} before the kill cannot be read (labctl exec exit {before['rc']}): "
                             "no kill")
        command = KILL_COMMAND.format(unit=unit)
        self.act("labctl exec", guest_command=command)
        done = self.host.labctl(self.p, ["exec", "--guest-command", command], LABCTL_EXEC_S)
        kill = self.act("labctl exec done", rc=done["rc"])
        self.host.wait(self.never, self.parameters["wait_s"])
        after = self.show(unit)
        self.window = [round(start, 3), round(kill, 3)]
        self.proof = {"unit": unit, "command": [str(x) for x in done["command"]], "rc": done["rc"],
                      "before": before, "after": after, "stderr": done["stderr"][-300:]}
        try:
            higher = int(after["NRestarts"]) > int(before["NRestarts"])
        except (KeyError, ValueError):
            higher = False
        self.induced = (done["rc"] == 0 and higher
                        and after.get("ExecMainPID") not in (None, before.get("ExecMainPID")))

    def _tlak_na_pamat(self):
        start = self.at()
        q = self.parameters
        others = self.host.other_vms(self.p)
        busy = [f"{o['vm']} (collectors {o['collectors']}, generators {o['generators']})" for o in others
                if o.get("collectors") or o.get("generators")]
        if busy:
            raise NotInduced("the other VM is not idle (both VMs' QEMU share the unit of the ban, Q26): "
                             + "; ".join(busy))
        qemu, now = self.session_json()["host_context"]["qemu"], self.host.qemu(self.p["domain"])
        if now is None or (now["pid"], now["start_ticks"]) != (qemu["pid"], qemu["start_ticks"]):
            raise NotInduced(f"the session's QEMU {qemu['pid']} no longer runs the VM (now {now})")
        pid, cgroup = qemu["pid"], self.host.cgroup(qemu["pid"])
        uid = None if self.owner is None else self.owner[0]
        if (uid is None or cgroup is None or PurePosixPath(cgroup).name != DAEMON_SERVICE
                or f"/user@{uid}.service/" not in cgroup):
            raise NotInduced(f"the QEMU {pid} is not in the unit {DAEMON_SERVICE} of the VM's owner (uid {uid}): its "
                             f"cgroup is {cgroup} (ROOT_NOTE)")
        before = self.host.swap_max(cgroup)
        if before != "0":
            raise NotInduced(f"memory.swap.max of {cgroup} is {before!r}, not 0: the ban is not in place")
        swap0 = self.host.swap_kb(pid)
        others_before = {o["vm"]: self.host.swap_kb(o["qemu"]["pid"]) if o.get("qemu") else None for o in others}
        with self.lock:
            self.host.set_swap_max(cgroup, "max")
            self.lifted = (cgroup, before)
        self.act("swap ban lifted", cgroup=cgroup, before=before, now=self.host.swap_max(cgroup))
        mib_max = self.host.meminfo()["MemTotal"] // 1024
        with self.lock:
            self.child = self.host.pressure(q["step_mib"], q["step_s"], mib_max)
        began = self.act("pressure started", pid=self.child.pid, mib_max=mib_max)
        seen = None
        peak = swap0 if type(swap0) is int else 0
        while True:
            kb, now_unix = self.host.swap_kb(pid), self.host.now()
            peak = max(peak, kb) if type(kb) is int else peak
            if seen is None and type(kb) is int and kb >= q["swap_kb"]:
                seen = self.act("swap seen", swap_kb=kb)
            if seen is not None and now_unix >= seen + q["hold_s"]:
                break
            if now_unix >= began + q["max_s"]:
                self.act("pressure at its limit", max_s=q["max_s"])
                break
            if not self.host.alive(self.child):
                self.act("pressure child ended by itself")
                break
            if self.host.wait(self.ended, POLL_S):
                self.act("the run ended during the pressure")
                break
        child, rc = self.child.pid, None
        with self.lock:
            if self.child is not None:
                rc = self.host.stop_pressure(self.child)
                self.child = None
        self.act("pressure stopped", pid=child, rc=rc)
        with self.lock:
            self.host.set_swap_max(cgroup, before)
            after = self.host.swap_max(cgroup)
            if after == before:
                self.lifted = None
        end = self.act("swap ban restored", cgroup=cgroup, now=after)
        self.window = [round(start, 3), round(end, 3)]
        self.proof = {"qemu_pid": pid, "cgroup": cgroup, "swap_max_before": before, "swap_max_during": "max",
                      "swap_max_after": after, "swap_kb_before": swap0, "swap_kb_peak": peak, "swap_kb_needed":
                      q["swap_kb"], "seen_unix": None if seen is None else round(seen, 3),
                      "pressure": {"pid": child, "rc": rc, "mib_max": mib_max},
                      "other_vms_swap_kb": {"before": others_before,
                                            "after": {o["vm"]: self.host.swap_kb(o["qemu"]["pid"]) if o.get("qemu")
                                                      else None for o in others}}}
        self.induced = seen is not None

    # -------------------------------------------------- the cleanup

    def clean(self):
        """Undo what the injector left (INJECT_RULE); idempotent, thread-safe. What it cannot undo is in unclean."""
        with self.lock:
            if self.stopped is not None:
                pid, self.stopped = self.stopped, None
                try:
                    self.host.signal(pid, signal.SIGCONT)
                    self.cleanup.append(f"SIGCONT {pid}")
                except ProcessLookupError:
                    self.cleanup.append(f"SIGCONT {pid}: the process is gone")
                except OSError as error:
                    self.failed(f"SIGCONT {pid} failed: {error}")
            if self.child is not None:
                child, self.child = self.child, None
                try:
                    self.cleanup.append(f"pressure child {child.pid} killed, exit {self.host.stop_pressure(child)}")
                except Exception as error:  # noqa: BLE001 - named; the block stops
                    self.failed(f"the pressure child {child.pid} was not stopped: {error}")
            if self.lifted is not None:
                cgroup, before = self.lifted
                problem = None
                try:
                    self.host.set_swap_max(cgroup, before)
                except OSError as error:
                    problem = f"{type(error).__name__}: {error}"
                try:
                    now = self.host.swap_max(cgroup)
                except OSError as error:
                    now = f"unreadable ({error})"
                if now == before:
                    self.lifted = None
                    self.cleanup.append(f"memory.swap.max of {cgroup} back to {before}")
                else:
                    self.failed(f"memory.swap.max of {cgroup} is {now!r}, not {before!r} again"
                                + (f" ({problem})" if problem else ""))

    def failed(self, problem):
        """A cleanup that failed, named once however often clean() tries again."""
        if problem not in self.unclean:
            self.unclean.append(problem)

    # -------------------------------------------------- the record

    def values(self, spec, block_command, other_vm):
        """The record's values (INJECT_RULE)."""
        end = self.session_dir / "end.json"
        try:
            measured = json.loads(end.read_text()) if end.exists() else {}
        except (OSError, ValueError):
            measured = {}
        start, stop = measured.get("measure_start_unix"), measured.get("measure_end_unix")
        inside = (None if self.window is None or start is None else
                  start <= self.window[0] and (stop is None or self.window[1] <= stop))
        f = FAULTS.get(self.fault, {})
        return {"stage": STAGE, "kind": spec["kind"], "fault": self.fault, "fault_text": f.get("fault"),
                "form": f.get("form"), "parameters": f.get("parameters"), "proof_rule": f.get("proof"),
                "expected": f.get("expected", []), "faults_sha256": faults_sha256(),
                "session_id": spec["session_id"], "session_dir": str(self.session_dir), "vm": self.p.get("vm"),
                "domain": self.p["domain"], "plan": spec.get("deck"), "cycles": self.cycles, "other_vm": other_vm,
                "first_sidecar": self.first, "actions": self.actions, "candidates": self.candidates,
                "proof": self.proof, "induced": self.induced, "why_not": self.why_not, "error": self.error,
                "window": self.window, "measured": {"start_unix": start, "end_unix": stop, "fault_inside": inside},
                "cleanup": {"done": self.cleanup, "failed": self.unclean},
                "g2_values": False if self.fault is not None else None, "g2_values_note": G2_VALUES_NOTE,
                "block_command": block_command, "rules": {"inject": INJECT_RULE, "root": ROOT_NOTE}}


class FaultHook:
    """The injector beside one run of a fault block (skuska/g2.py Block.beside): its thread from before the run to
    after it, then its record. start() and stop() never raise; a refusal is in the record."""

    def __init__(self, block, spec, paths, host):
        self.block, self.spec, self.path = block, spec, beside_path(block.places.root, spec["session_id"])
        self.injector = Injector(spec.get("fault"), block.p, paths["session"], block.run_command(spec, block.group),
                                 os.getpid(), block.cycles, host, owner=block.lab.owner(), log=block.log)
        self.thread = threading.Thread(target=self.injector.run, name="g2-fault", daemon=True)

    def start(self):
        if self.path.exists() or self.path.is_symlink():
            self.injector.why_not = f"the injector's record {self.path} exists: a session id runs once"
        else:
            self.thread.start()
        return self

    def stop(self):
        inj = self.injector
        inj.ended.set()
        if self.thread.is_alive() or self.thread.ident is not None:
            self.thread.join(JOIN_S)
        alive = self.thread.is_alive()
        inj.clean()
        if alive:
            inj.failed(f"the injector's thread had not ended {JOIN_S} s after the run")
        out = {"hook": "fault", "file": str(self.path), "sha256": None, "fault": inj.fault, "induced": inj.induced,
               "why_not": inj.why_not, "error": inj.error, "unclean": list(inj.unclean)}
        if self.thread.ident is None and self.path.exists():
            return dict(out, error=inj.why_not)
        try:
            values = inj.values(self.spec, self.block.command, self.block.other_vm)
            doc = g2.header(FAULT_SCHEMA, self.block.command, len(inj.actions), values,
                            guest={"vm": self.block.vm, "domain": self.block.p["domain"]})
            doc["note"] = NOTE
            missing = [d for d in [self.path.parent, *self.path.parent.parents] if not d.exists()]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            g2.write_new(self.path, doc)
            self.block.chown([*missing, self.path])
            out["sha256"] = g2.digest(self.path)
        except Exception as error:  # noqa: BLE001 - the session's record names it
            out["error"] = f"the injector's record was not written: {type(error).__name__}: {error}"
        return out


# ------------------------------------------------------------------ the block

class FaultBlock(g2.Block):
    """A block of the fault plan on one VM (FAULT_BLOCK_RULE)."""

    def __init__(self, protocol_path, deck_path, vm, *, cycles=None, host=None, **options):
        super().__init__(protocol_path, deck_path, vm, **options)
        self.cycles = self.p["pilot_cycles"] if cycles is None else cycles  # Q57; Block.run_command reads it.
        self.host = host or Host()
        self.faults = plan(self.full)
        self.hook = None
        self.beside = [*self.beside, self.fault_hook]

    def fault_hook(self, block, spec, paths):
        """The hook of Block.beside: the injector of the session (FaultHook)."""
        self.hook = FaultHook(self, spec, paths, self.host)
        return self.hook.start()

    def done(self, record):
        """FAULT_DONE_RULE for the values of a session record."""
        if ((record.get("deck") or {}).get("item") or {}).get("cycles") != self.cycles:
            return False
        if record.get("kind") == KIND_CLEAN:
            return record.get("done") is True
        return any(type(b) is dict and b.get("hook") == "fault" and b.get("induced") is True
                   for b in record.get("beside") or [])

    def specs(self):
        """The sessions of the block from the plan (FAULT_DONE_RULE): {kind, id, deck, scenario, seed, events, fault,
        attempt, session_id} each; deck holds the plan's item with the block's cycles."""
        items = [s for s in self.faults if s["vm"] == self.vm]
        if self.only is not None:
            unknown = [x for x in self.only if x not in {s["id"] for s in items}]
            if unknown or not self.only or len(set(self.only)) != len(self.only):
                raise g2.Refused(f"--only names plan sessions of VM {self.vm}, each once; not of it: "
                                 + ", ".join(unknown))
            chosen = [s for s in items if s["id"] in self.only]
        else:
            done = {r["deck_session"] for r in self.records() if self.done(r)}
            left = [s for s in items if s["id"] not in done]
            if type(self.count) is not int or self.count < 1:
                raise g2.Refused("--sessions N: a number of sessions above 0")
            if self.count > len(left):
                raise g2.Refused(f"--sessions {self.count}: {len(left)} plan sessions of VM {self.vm} are not done")
            chosen = left[:self.count]
        specs = []
        for item in chosen:
            attempt = self.attempt(item["id"])
            specs.append({"kind": KIND_CLEAN if item["fault"] is None else KIND_FAULT, "id": item["id"],
                          "deck": {**item, "cycles": self.cycles, "rule": PLAN_RULE}, "scenario": item["scenario"],
                          "seed": item["seed"], "events": None, "fault": item["fault"], "attempt": attempt,
                          "session_id": f"g2-{self.vm}-{item['id']}-{attempt}"})
        return specs

    def clean_passed(self, vm):
        """Whether a clean session of the plan with the block's cycles was accepted on `vm` (Q57)."""
        for path in sorted(self.places.records.glob(f"g2-{vm}-c*-*.json")):
            try:
                v = g2.read_json(path)["values"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if (v.get("vm") == vm and v.get("kind") == KIND_CLEAN and v.get("done") is True
                    and ((v.get("deck") or {}).get("item") or {}).get("cycles") == self.cycles
                    and (v.get("audit") or {}).get("accepted") is True):
                return True
        return False

    def checks(self, specs):
        """The refusals of Block.checks and of FAULT_BLOCK_RULE."""
        problems = super().checks(specs)
        faults = sorted({s["fault"] for s in specs if s.get("fault")})
        if "tlak_na_pamat" in faults and self.other_vm != "idle":
            problems.append("the memory fault lifts the swap ban of the unit both VMs' QEMU share (Q26): it runs with "
                            "--other-vm idle")
        pilot = self.p["pilot_cycles"]
        if type(self.cycles) is not int or self.cycles < 1 or self.cycles > pilot:
            problems.append(f"--cycles {self.cycles}: the fault sessions have at most pilot_cycles = {pilot} cycles "
                            "(Q57)")
            return problems
        short = [f"{name} needs {minimum_cycles(self.p, name)}" for name in faults
                 if self.cycles < minimum_cycles(self.p, name)]
        if short:
            problems.append(f"--cycles {self.cycles} is shorter than the faults need: " + ", ".join(short))
        if faults and self.cycles != pilot:
            missing = [row["name"] for row in self.full["vms"] if not self.clean_passed(row["name"])]
            if missing:
                problems.append(f"fault sessions of {self.cycles} cycles, fewer than pilot_cycles = {pilot}, run only "
                                f"after a clean session of that length was accepted on each VM (Q57); none on "
                                + ", ".join(missing))
        return problems

    def ensure_group(self, environment):
        """Every session of the plan in a new group (FAULT_BLOCK_RULE)."""
        self.group = None
        return super().ensure_group(environment)

    def session(self, spec, environment):
        """Block.session; a session whose injector could not undo what it left stops the block by name."""
        self.hook = None
        result = super().session(spec, environment)
        unclean = [] if self.hook is None else self.hook.injector.unclean
        if unclean and not result["stop"]:
            result["stop"] = "fault cleanup: " + "; ".join(unclean)
        return result


# ------------------------------------------------------------------ the pressure child

def pressure(step_mib, step_s, mib_max, *, parent=None, sleep=time.sleep, rounds=None):
    """The child of the memory fault (FAULTS tlak_na_pamat): it dies with the thread that started it (PR_SET_PDEATHSIG
    SIGKILL, then its parent checked, the race-free order) and its oom_score_adj is 1000 (the OOM killer takes it
    before any other process); then step_mib of anonymous memory every step_s, up to mib_max, every page touched again
    in every round; it runs until it is killed (`rounds` ends it in a test). Returns the MiB it holds."""
    if parent is not None:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
        if os.getppid() != parent:
            return 0  # The injector ended before the prctl.
    try:
        Path("/proc/self/oom_score_adj").write_text("1000\n")
    except OSError:
        pass
    step = step_mib << 20
    ones, chunks, done = b"\x01" * (step // 4096), [], 0
    while rounds is None or done < rounds:
        if (len(chunks) + 1) * step_mib <= mib_max:
            chunks.append(bytearray(step))
        for chunk in chunks:
            chunk[::4096] = ones
        done += 1
        sleep(step_s)
    return len(chunks) * step_mib


# ------------------------------------------------------------------ the command line

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m skuska.poruchy", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    shown = sub.add_parser("plan", help="print the plan of the fault sessions (PLAN_RULE)")
    shown.add_argument("--protocol", type=Path, required=True)
    block = sub.add_parser("block", help="run a block of the fault plan on one VM (as root through sudo)")
    block.add_argument("--protocol", type=Path, required=True)
    block.add_argument("--deck", type=Path, required=True, help="the deck of events of G2 (skuska/g2.py deck)")
    block.add_argument("--vm", required=True)
    which = block.add_mutually_exclusive_group(required=True)
    which.add_argument("--sessions", type=int, help="the next N plan sessions of the VM that are not done")
    which.add_argument("--only", help="these plan sessions (ids, comma-separated), each as its next attempt")
    block.add_argument("--other-vm", choices=g2.OTHER_VM, required=True,
                       help="what the block's plan lets the other VM run: nothing, or its own G2 block")
    block.add_argument("--cycles", type=int, help="the sessions' cycles: pilot_cycles (600) unless a clean session of "
                                                  "fewer was accepted on each VM (Q57)")
    block.add_argument("--rate", action="append", default=[], metavar="SCENARIO=R",
                       help="the rate of a scenario whose rate is null in the protocol (refused otherwise)")
    block.add_argument("--g2-dir", type=Path, default=g2.G2_DIR, help="the G2 directory: zaznamy/, zataz/, session/, "
                                                                      "poruchy/")
    block.add_argument("--dry-run", action="store_true", help="the checks and the commands; nothing is started")
    child = sub.add_parser("pressure", help="the memory pressure child of the memory fault (started by the injector)")
    child.add_argument("--step-mib", type=int, required=True)
    child.add_argument("--step-s", type=float, required=True)
    child.add_argument("--mib-max", type=int, required=True)
    child.add_argument("--parent", type=int, help="the PID of the block whose injector started the child")
    child.add_argument("--rounds", type=int, help=argparse.SUPPRESS)  # A test's child ends by itself and reports.
    a = parser.parse_args(argv)
    if a.action == "pressure":
        mib = pressure(a.step_mib, a.step_s, a.mib_max, parent=a.parent, rounds=a.rounds)
        if a.rounds is not None:
            print(json.dumps({"mib": mib, "oom_score_adj": Path("/proc/self/oom_score_adj").read_text().strip()}))
        return 0
    line = shlex.join(["python", "-m", "skuska.poruchy", *argv])
    try:
        if a.action == "plan":
            print(json.dumps({"rule": PLAN_RULE, "faults_sha256": faults_sha256(),
                              "sessions": plan(collection.protocol(a.protocol))}, indent=2, ensure_ascii=False))
            return 0
        b = FaultBlock(a.protocol, a.deck, a.vm, other_vm=a.other_vm, sessions=a.sessions,
                       only=None if a.only is None else a.only.split(","), rates=g2.parse_rates(a.rate),
                       cycles=a.cycles, places=g2.Places(a.g2_dir), command=line)
        result = b.plan() if a.dry_run else b.run()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get("refusals") or result.get("stopped") else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"skuska.poruchy: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
