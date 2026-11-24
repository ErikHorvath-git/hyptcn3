#!/usr/bin/env python3
"""Frozen benign collection campaign: reboot, capture, audit, archive, index.

init/status/request-stop/close need no root. launch/run need sudo for host
eBPF, and use the original user's libvirt session. A protocol with several VMs
has one runner per VM (run --vm, own systemd unit, status-<vm>.json); a boot
group belongs to one VM, audits and archiving are serialized over the VMs and
sessions live under data/collections/<campaign>/<vm>/. A failed capture or rejected
audit stops the allocation; retries never silently replace a research session.
Only an attempt that ended before its measured phase (no RAM image) is retried.

init --continue: one continuation of a campaign that stopped for good and was
closed (PLAN_multivm_dataset.md, chapter 8). Same protocol file, extractor,
collector and guest environment; groups the closed campaign completed are taken
over as they are, every other group is captured again as a whole in a new boot.

Protocol v5 (schema 3; package B9a, agent K: the lead's skeleton dokazy/B9/kostra/KOSTRA.md, the design
dokazy/B9/navrh/NAVRH_B9a.md section 1.3, proposal 5.4, 7.3, 7.5 and decision D12): one rule each, written into
campaign.json (RULES): the time order of the roles and of the test groups (ORDER_RULE), the plan mode (MODE_RULE), no
pilot (PILOT_RULE), the disk estimate (DISK_RULE), the stages at the start (STAGES_RULE), the replacement as a new
attempt (REPLACEMENT_RULE) and its limit (LIMIT_RULE), the start of a group (GROUP_START_RULE), the seal of an accepted
session (SEAL_RULE) and the one change the frozen tree admits (FROZEN_TREE_RULE). Pause, continuation under v5,
early stop and the record at closure are package B9b; until then an exhausted limit stops as before.
"""
import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import collection, protocol_v5
from scripts.collection_archive import (archive_session, digest, guard_mount, mount_identity,
                                        now, read_json, sync_dir, verify_archive, write_new)

BASE = ROOT / "data/campaigns"
COLLECTIONS = ROOT / "data/collections"
UNIT = "hyptcn-collection.service"
CAMPAIGN_NAME = r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}"
# Attempts of one assignment that may end before the measured phase (failed
# preflight, warmup or an operator stop there); the last one stops the campaign.
MAX_ATTEMPTS = 3
RETRY_PAUSE_S = 60
# Multi-VM: waiting for the audit lock or for earlier roles on the other VMs.
WAIT_POLL_S = 10
# Runners of one campaign are launched one after another; a runner that is not up yet is not a stopped one.
START_GRACE_S = 120

# ------------------------------------------------------------------ protocol v5 (package B9a, agent K)

ORDER_RULE = (
    "B6a F7 and PRE_B9, proposal 7.3, skeleton row poradie (wait_for_earlier_roles reads the order from the plan), F5 "
    "of the verification of B9a: the runners keep the time order of the plan across the VMs. By rank: "
    "protocol_v5.TIME_RANK, never the order of the protocol's roles: before a session of a role a runner waits until "
    "the other VMs finished every session of a role of a lower rank (ranked by the order of the roles, the runners of "
    "a plan with 4 or more groups per role deadlocked). Inside a rank, under protocol schema 3: a runner starts a "
    "group of an interleaved role (p['interleave']: test_benign and test_controls, whose boots alternate in time, "
    "proposal 7.3) only after every group of those roles that precedes it in the plan (the order of the frozen plan, "
    "the time order of protocol_v5.plan, on the other VMs) has started, that is, has its record groups/<group>.json, "
    "which start_group writes after the pretouch (a group a continuation took over counts as started); so the test "
    "groups start in the plan's order and a VM runs at most about one group ahead of the other. It cannot deadlock: "
    "the earliest group of the plan that has not started has no predecessor that has not started, and its VM reaches "
    "it once its current group ends. Both waits keep the operator's stop request and end with a reason when the other "
    "runner is not active after START_GRACE_S; the state names what the runner waits for. take_over judges a closed "
    "campaign by the same rank; schemas 1 and 2 keep the rank alone, and a protocol of schema 1 or 2 whose one role "
    "has no rank (test_events of the test-only protocols) ranks that role alone")
MODE_RULE = (
    "design B9a 1.3 item 2, skeleton row generálka: under protocol schema 3 a campaign has one plan mode, campaign or "
    "rehearsal (init --mode, required there and refused under schemas 1 and 2, no default); campaign.json records it "
    "and every plan of the campaign is protocol_v5.plan(p, mode=mode): init, load_campaign, finish_corpus and the "
    "--mode of every capture; the plan takes its name and its group prefix from protocol_v5._shape (a rehearsal: name "
    "+ rehearsal.name_suffix and rehearsal.group_prefix), and the campaign's default name ends in the plan's name")
PILOT_RULE = (
    "design B9a 1.3 item 3 (map 2.1): protocol v5 has no pilot; init neither needs nor accepts --pilot-report and no "
    "capture passes it; the guest environment of every VM is recorded at init; the swap ban stays the check before "
    "the start of every session (scripts/collection.py run, decision D13), and the host's vm.swappiness is frozen in "
    "the runtime that verify_frozen compares; schemas 1 and 2 keep the accepted pilot")
DISK_RULE = (
    "decision D12 and the skeleton's section 5 (Disk), design B9a 1.3 item 3: under protocol schema 3 one session is "
    "estimated by the largest accepted session so far, its working bytes (bytes of its archive manifest) and its "
    "archive bytes (stored_bytes), each the largest recorded in attempts/*.done.json; in mode campaign init "
    "--estimate-from seeds both with the largest accepted session of an ended rehearsal of the protocol (frozen in "
    "campaign.json as disk_estimate.seed), in mode rehearsal there is no seed, so before its first accepted session "
    "only min_free_gib is checked; the working disk must hold min_free_gib, this VM's next session and the part of "
    "every other VM's current session not written yet; the archive disk min_free_gib and the archive bytes of every "
    "session still to capture: the assignments not finished and, in mode campaign, the replacements its limit still "
    "allows (D12 counts the campaign with its replacements); init refuses a campaign that does not fit; schemas 1 and "
    "2 keep the estimate of the pilot")
STAGES_RULE = (
    "skeleton row stupne, design B9a 1.3 item 4: a campaign of mode campaign starts only on valid readiness records of "
    "G0 to G4 (scripts/gates.py require(..., 'G5')), a rehearsal on G0 to G2 (require(..., 'G3a')), each also on a "
    "passed self-test of the audit checks (scripts/audit_selftest.py require_selftest); init, launch and run check them")
REPLACEMENT_RULE = (
    "proposal 7.3, skeleton row náhrada, design B9a 1.3 item 5: replacement n of a planned session (ID <plan "
    "session>-r<n>) is attempt n + 1 of its row, drawn by protocol_v5.replacement in the campaign's mode: the same VM, "
    "role, group, position, scenario and event types or control kinds, new times and a new traffic stream; the capture "
    "passes --attempt and that attempt's seed, and check_session compares the attempt, the plan mode, the events and "
    "the controls; schemas 1 and 2 keep the same assignment and seed")
LIMIT_RULE = (
    "proposal 7.5, skeleton row limit náhrad, design B9a 1.3 item 5: in mode campaign replacement.max_per_campaign of "
    "the protocol is the limit and a null limit (determined at G3b) is refused by name at init; in mode rehearsal the "
    "limit is not applied, every rejection the rule covers is replaced, and the rejections of the campaign are counted "
    "by cause in its state (rejections_by_cause), from which G3b sets the limit; an exhausted limit stops the runner "
    "as before (pause and continuation are package B9b)")
GROUP_START_RULE = (
    "proposal 5.4 and B5a F4, skeleton row začiatok bootu, design B9a 1.3 item 6: a group of protocol schema 3 starts "
    "with labctl stop, then labctl start (way 1: a new QEMU process in the daemon's unit, whose pid and cgroup the "
    "start's qemu_swap record states with way unit and temporary false; way 2, the scope move, is refused, since it "
    "moves the process and not its memory, B5a F4), the new boot id with "
    "the frozen guest environment, then labctl reset --seed with the protocol's one seeded level "
    "(protocol_v5.reset_seed(p), the same for every group of both modes: proposal 5.4, the table of chapter 12, Q18; "
    "the guest must echo it) and labctl pretouch, each as the VM's owner and each output recorded in "
    "groups/<group>.json (start.steps, in this order); the guest identity and the QEMU process read again after the "
    "pretouch must be those after the start; a failure of any step rejects the session before its measured phase "
    "with the cause group_start and the step named. A rejection with the cause group_start is never replaced: no "
    "protocol may cover group_start, because collection.check_replacement admits in replacement.covers only "
    "REPLACEMENT_CAUSES (audit_rejected, capture_incomplete); the runner stops by name, and package B9b ends the "
    "campaign with a record (F7 of the verification of B9a). The levels at the start of each session are taken by "
    "scripts/collection.py run")
SEAL_RULE = (
    "skeleton row pečať, B7c PRE_B9, design B9a 1.3 item 7: right after the audit accepts a session of a sealed role "
    "(test_benign, test_controls: features/dataset.py ROLES without FIT_ROLES, which tcn/pecat.py SEALED_ROLES equals) "
    "and before its checkpoint, the runner writes it into the seal ledger as the campaign's owner "
    "(collection.user_command): python -m tcn.pecat zapis --audit <audit> --mode <mode>, which seals the record {id, "
    "role, group, vm, scenario, features, features_sha256}; nothing during a campaign replays or scores a session")
LEDGER = "data/results/kniha_pecati.json"  # tcn/pecat.py TRACKED: the seal ledger of record.
FROZEN_TREE_RULE = (
    "design B9a 1.3 item 8: the frozen tree admits exactly one change, the seal ledger " + LEDGER + " modified in "
    "place (tcn.pecat checks its content on every read); HEAD stays the frozen commit and any other change refuses; "
    "git status runs under the ledger's lock (tcn/pecat.py _locked), so another runner's seal write in progress is not "
    "a change; the ledger is committed and pushed after the campaign closes (stage final of tcn.finalne requires it at "
    "HEAD)")
RULES = {"order": ORDER_RULE, "mode": MODE_RULE, "pilot": PILOT_RULE, "disk": DISK_RULE, "stages": STAGES_RULE,
         "replacement": REPLACEMENT_RULE, "limit": LIMIT_RULE, "group_start": GROUP_START_RULE, "seal": SEAL_RULE,
         "frozen_tree": FROZEN_TREE_RULE}
# STAGES_RULE: the stage gates.require checks before (every stage up to the one before it) by the campaign's mode.
START_STAGES = {"campaign": ("G5", "G0 to G4"), "rehearsal": ("G3a", "G0 to G2")}
# GROUP_START_RULE: the labctl verbs of the start of a group, in order, each with its timeout in seconds (the
# executor's judgment: an outer bound above the bounds scripts/labctl.py and lab/guest_state.py set for the step, so
# that labctl ends a stuck step with its own reason first: the wait for the domain shut off, STOP_TIMEOUT_S 180 s; the
# guest agent after a start, 120 s, with the daemon unit, 30 s; the guest helper of reset and pretouch, 600 s, the
# process of the pretouch, 300 s).
GROUP_START_STEPS = {"stop": 300, "start": 300, "reset": 900, "pretouch": 600}
SEAL_TIMEOUT_S = 120  # SEAL_RULE: one write of the ledger (the executor's judgment: the archive is hashed again).
CHILD_ERROR_CHARS = 800  # The child's error text kept in a refusal (the executor's judgment: its last lines).


def vm_names(p):
    """VM names of the protocol; [None] for a single-VM protocol (original file names and layout)."""
    return [row["name"] for row in collection.vms(p)]


def schema3(p):
    """Whether `p` is a protocol of schema 3 (protocol v5, package B9a)."""
    return p.get("schema") == protocol_v5.SCHEMA


def campaign_plan(p, mode):
    """The plan of a campaign (MODE_RULE): under protocol schema 3 protocol_v5.plan of its mode, campaign or
    rehearsal; under schemas 1 and 2 collection.plan, which has no mode. A mode that does not fit is refused by name."""
    if schema3(p):
        if mode not in protocol_v5.MODES:
            raise ValueError("a campaign of protocol schema 3 names its plan mode, " + " or ".join(protocol_v5.MODES)
                             + f", not {mode!r} (scripts/campaign.py MODE_RULE)")
        return protocol_v5.plan(p, mode=mode)
    if mode is not None:
        raise ValueError(f"plan mode {mode} applies only to protocol schema 3; a campaign of schema 1 or 2 has one plan "
                         "(scripts/campaign.py MODE_RULE)")
    return collection.plan(p)


def time_rank(p):
    """{role: rank} of the time order of the plan's roles (ORDER_RULE): protocol_v5.TIME_RANK, under which the two test
    roles share a rank. A protocol of schema 1 or 2 whose single role has no rank (test_events) ranks it alone; any
    other role without a rank is refused by name."""
    roles = list(p["roles"])
    unranked = [role for role in roles if role not in protocol_v5.TIME_RANK]
    if not unranked:
        return {role: protocol_v5.TIME_RANK[role] for role in roles}
    if not schema3(p) and len(roles) == 1:
        return {roles[0]: 0}
    raise ValueError("roles without a time rank (scripts/protocol_v5.py TIME_RANK, scripts/campaign.py ORDER_RULE): "
                     + ", ".join(unranked))


def sealed_role(role):
    """SEAL_RULE: a role whose accepted sessions are sealed, a role training never loads (features/dataset.py ROLES
    without FIT_ROLES; tcn/pecat.py SEALED_ROLES equals them)."""
    from features.dataset import FIT_ROLES, ROLES
    return role in ROLES and role not in FIT_ROLES


def vm_file(name, vm):
    """Per-VM variant of a campaign file: status.json -> status-a.json."""
    stem, suffix = name.rsplit(".", 1)
    return name if vm is None else f"{stem}-{vm}.{suffix}"


def vm_unit(vm):
    return UNIT if vm is None else UNIT.replace(".service", f"-{vm}.service")


def vm_view(manifest, p, vm):
    """Campaign and protocol as one VM's runner sees them: that VM's pilot, guest
    environment, estimates, domain and target under the single-VM keys."""
    if vm is None:
        return manifest, p
    return {**manifest, **manifest["vms"][vm], "vm": vm}, collection.for_vm(p, vm)


def session_dir(manifest, row):
    if "vm" not in row:
        return COLLECTIONS / row["session_id"]
    return COLLECTIONS / manifest["id"] / row["vm"] / row["session_id"]


def archive_dest(manifest, row):
    return Path(manifest["archive_dir"]) / "collections" / row.get("vm", "") / row["session_id"]


def frozen_files(manifest):
    """The frozen files of a campaign and of its copy next to the archive: a campaign of protocol schema 3 (its
    manifest names its plan mode) has no pilot (PILOT_RULE)."""
    pilots = [] if "mode" in manifest else [vm_file("pilot.json", vm) for vm in manifest.get("vms", [None])]
    return ["campaign.json", "protocol.json", "plan.json", *pilots]


def rejection_file(directory, session_id):
    return directory / "attempts" / (session_id + ".rejected.json")


def chain(directory, row):
    """A plan row followed by the replacements of its audit-rejected sessions, oldest first.

    The last one is the assignment's current session. A replacement is the same
    assignment under the ID <plan session>-r<n>; rejection records name it.
    """
    rows = [row]
    while rejection_file(directory, rows[-1]["session_id"]).exists():
        record = read_json(rejection_file(directory, rows[-1]["session_id"]))
        if record.get("replacement") is None:
            break
        expected = f"{row['session_id']}-r{len(rows)}"
        if record["replacement"] != expected or record.get("session") != rows[-1]["session_id"]:
            raise ValueError("rejection record does not match the frozen plan: " + rows[-1]["session_id"])
        rows.append({**row, "session_id": expected, "replaces": rows[-1]["session_id"],
                     "plan_session": row["session_id"], "replacement": len(rows)})
    return rows


def rejections(directory, vm=None):
    """Sessions the campaign could not use (rejecting audit or incomplete capture), with cause and
    reasons, in time order (all VMs unless one is named)."""
    records = [read_json(path) for path in sorted((directory / "attempts").glob("*.rejected.json"))]
    return sorted((r for r in records if vm is None or r.get("vm") == vm), key=lambda r: r["date"])


def rejections_by_cause(directory):
    """LIMIT_RULE: the rejections of the campaign over all its VMs, counted by cause (a record from before causes
    existed is an audit rejection, as execute reads it)."""
    counts = Counter(r.get("cause", "audit_rejected") for r in rejections(directory))
    return dict(sorted(counts.items()))


# The keys a campaign adds to a row of its plan (session ID, the chain of replacements); the rest is the plan's.
CAMPAIGN_KEYS = ("session_id", "replaces", "plan_session", "replacement")


def attempt_row(manifest, p, row):
    """The assignment a row of chain() captures (REPLACEMENT_RULE). Under protocol schema 3 replacement n (row
    "replacement" n) is attempt n + 1 of its planned row, protocol_v5.replacement in the campaign's mode, with the
    campaign's keys of the row; a planned row is attempt 1 as the plan states it. Schemas 1 and 2: the row itself (the
    same assignment and seed)."""
    if not schema3(p) or "replacement" not in row:
        return row
    planned = {key: value for key, value in row.items() if key not in CAMPAIGN_KEYS}
    drawn = protocol_v5.replacement(p, planned, row["replacement"] + 1, mode=manifest["mode"])
    return {**drawn, **{key: row[key] for key in CAMPAIGN_KEYS}}


def replacement_limit(manifest, p):
    """LIMIT_RULE: (applied, limit). Schemas 1 and 2: the protocol's max_per_campaign, 0 without a rule. Schema 3: in
    mode rehearsal not applied (None); in mode campaign the protocol's number, a null one refused by name."""
    rule = p.get("replacement") or {}
    if not schema3(p):
        return True, rule.get("max_per_campaign", 0)
    if manifest["mode"] == "rehearsal":
        return False, None
    limit = rule.get("max_per_campaign")
    if type(limit) is not int:
        raise ValueError(NULL_LIMIT)
    return True, limit


NULL_LIMIT = ("replacement.max_per_campaign is null (it is determined at G3b, proposal 7.5): a campaign of mode "
              "campaign needs its limit of replacements (scripts/campaign.py LIMIT_RULE)")


def is_done(directory, row):
    """The assignment is archived and accepted: the plan session itself or its replacement."""
    return (directory / "attempts" / (chain(directory, row)[-1]["session_id"] + ".done.json")).exists()


def taken_over(manifest, row):
    """Continuation campaign: the frozen record of an assignment its closed predecessor completed, else None."""
    return manifest.get("continues", {}).get("sessions", {}).get(row["session_id"])


def finished(directory, manifest, row):
    """Nothing is left to capture for the assignment: accepted and archived here, or taken over."""
    return taken_over(manifest, row) is not None or is_done(directory, row)


def taken_report(record):
    """The predecessor's selected audit of a taken-over assignment; it must still be the frozen one."""
    report = Path(record["audit"])
    if digest(report) != record["audit_sha256"]:
        raise ValueError("audit of a taken-over session changed: " + record["session_id"])
    return report


def final_report(directory, manifest, row):
    """The accepted audit that represents the assignment in the index."""
    taken = taken_over(manifest, row)
    if taken is not None:
        return taken_report(taken)
    return Path(read_json(directory / "attempts" / (chain(directory, row)[-1]["session_id"] + ".audit.json"))["path"])


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def git(*args):
    # Only the final newline goes: a line of git status --porcelain begins with its two status columns, which may be
    # a space (FROZEN_TREE_RULE reads them).
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).rstrip("\n")


def tree_hashes(directory):
    return {str(f.relative_to(directory)): digest(f) for f in sorted(directory.rglob("*")) if f.is_file()}


def extractor_hashes():
    return {str(f.relative_to(ROOT)): digest(f) for d in ("features", "guestparse")
            for f in (ROOT / d).rglob("*.py") if "tests" not in f.parts}


def runtime_identity():
    packages = subprocess.check_output(collection.user_command([
        sys.executable, "-c", "import importlib.metadata,json; "
        "print(json.dumps({p:importlib.metadata.version(p) for p in ('numpy','torch')}))"
    ]), text=True, timeout=30)
    return {"host": platform.platform(), "python": sys.version,
            "packages": json.loads(packages),
            "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect"),
            # Swapped-out guest RAM stalls full snapshots (docs/LAB.sk.md); frozen with the campaign.
            "vm_swappiness": int(Path("/proc/sys/vm/swappiness").read_text())}


def guest_environment(identity):
    return {k: v for k, v in identity.items() if k != "boot_id"}


def pilot_gate(path, protocol_path, p):
    """An accepted pilot of this protocol made by the current code: (session metadata, bytes one session needs).

    What ties the report to this protocol, this code and these files is checked first, each tie with its own
    message, and nothing in the report is trusted before that. A field the gate reads that is missing or of a
    wrong type is refused by the tie that reads it, and so is a feature file the archive reader cannot read.
    Whether the pilot is accepted is then decided again from its feature archive by the one acceptance decision
    (features/acceptance.py, role "pilot": the pilot length in an unbroken sequence, no tolerated invalid row, no
    integrity finding, the coverage gate), and the report must state that very verdict.
    """
    from features.acceptance import require_accepted
    from features.archive import load
    from features.quality import require_log_audit
    report = read_json(path)
    v = report.get("values") if type(report) is dict else None
    if type(v) is not dict or report.get("schema") != "hyptcn3/collection-audit/1" \
            or type(v.get("session_dir")) is not str or type(v.get("features")) is not str \
            or type(v.get("raw_bytes")) is not int or v["raw_bytes"] <= 0:
        raise ValueError("pilot report is not a session audit")
    if v.get("protocol_sha256") != digest(protocol_path):
        raise ValueError("pilot was audited under another protocol")
    if type(v.get("quality")) is not dict or v["quality"].get("policy") != p["quality_policy"]:
        raise ValueError("pilot was audited under another input policy")
    if v.get("extractor_sha256") != extractor_hashes():
        raise ValueError("pilot was audited by another extractor (audit the pilot again)")
    session = Path(v["session_dir"]) / "session.json"
    if digest(session) != v.get("session_sha256"):
        raise ValueError("pilot metadata changed since audit")
    if digest(v["features"]) != v.get("features_sha256"):
        raise ValueError("pilot features changed since audit")
    meta = read_json(session)
    if type(meta) is not dict:
        raise ValueError("pilot metadata is not a session record")
    require_log_audit(meta, v)
    if tree_hashes(ROOT / p["profile"]) != meta.get("profile_sha256"):
        raise ValueError("pilot profile differs from the current profile")
    if digest(ROOT / "vmicollect/build/vmicollect") != meta.get("collector_sha256"):
        raise ValueError("pilot collector differs from the current collector")
    changed = measurement_changes(meta)
    if changed:
        raise ValueError("measurement code changed since the pilot (new pilot required): " + ", ".join(changed[:12]))
    try:
        archive = load(v["features"])
    except Exception as error:  # noqa: BLE001 - whatever the reader raises, the file is not a feature archive
        reason = f"{type(error).__name__}: {error}"
        raise ValueError("pilot features are not a readable feature archive: " + reason) from None
    try:
        require_accepted(archive, p, Path(v["session_dir"]).name, "pilot", v)
    except ValueError as error:
        raise ValueError("pilot is not accepted for this protocol: " + str(error)) from None
    return meta, v["raw_bytes"] * p["cycles"] / p["pilot_cycles"] * 1.5


def measurement_changes(meta):
    """Capture/audit/archive code that differs from the pilot's; reports and docs may change."""
    recorded = meta.get("measurement_sha256")
    if type(recorded) is not dict:
        return ["<pilot predates measurement provenance>"]
    current = collection.measurement_sources()
    return sorted(name for name in set(recorded) | set(current) if recorded.get(name) != current.get(name))


def raw_bytes(session):
    """Bytes of a session's RAM images still on the working disk (0 once archived and reclaimed)."""
    raw = session / "raw"
    if raw.is_symlink() or not raw.is_dir():
        return 0
    total = 0
    for path in raw.iterdir():
        try:
            total += path.stat().st_size
        except OSError:
            pass  # Published or renamed by the collector's writer thread meanwhile.
    return total


def capacity_guard(manifest, p, remaining, directory=None):
    """Space for the next session of this VM, next to what the other VMs still write.

    Every VM has its own estimate: raw bytes of its accepted pilot scaled to the
    session length, times 1.5 (pilot_gate). The working disk must hold this VM's
    next session, plus for every other VM with sessions left the part of its
    estimate not written yet (its current session may be in capture, waiting for
    the audit lock or about to start), plus the protocol reserve min_free_gib.
    At most one unarchived session per VM exists, because a runner archives and
    reclaims its session before the next capture and audits are serialized.

    Assumed numbers (collection PC, 2026-11-14, protocol v3 values): one session
    estimate ~16.8 GB (~11.2 GB raw x 1.5), reserve 30 GiB = 32.2 GB, i.e. the
    ~49 GB one VM needed so far. Two VMs starting together need 2 x 16.8 + 32.2 =
    65.8 GB, more than the 62.9 GB free on the SSD: either space is freed first or
    protocol v4 lowers min_free_gib (27 GiB gives 62.6 GB). The real estimates come
    from the per-VM pilots of the campaign, not from these numbers.

    Protocol schema 3 has no pilot: DISK_RULE (v5_capacity_guard), whatever `remaining` says.
    """
    if schema3(p):
        return v5_capacity_guard(manifest, p, directory)
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    reserve = p["min_free_gib"] * 2**30
    needed = manifest["estimated_session_bytes_with_reserve"]
    archived = manifest.get("estimated_archive_bytes_per_session", needed) * remaining
    for vm in manifest.get("vms", {}) if directory is not None else ():
        pending = [r for r in manifest["sessions"] if r["vm"] == vm and not finished(directory, manifest, r)]
        if vm == manifest["vm"] or not pending:
            continue
        other = manifest["vms"][vm]
        current = chain(directory, pending[0])[-1]
        needed += max(0, other["estimated_session_bytes_with_reserve"] - raw_bytes(session_dir(manifest, current)))
        archived += other["estimated_archive_bytes_per_session"] * len(pending)
    if shutil.disk_usage(COLLECTIONS).free < needed + reserve:
        raise ValueError("insufficient working space for the next session")
    if shutil.disk_usage(manifest["archive_root"]).free < archived + reserve:
        raise ValueError("insufficient archive space for remaining campaign estimate")


def recorded_sizes(directory):
    """DISK_RULE: [(session, working bytes, archive bytes)] of every accepted session of a campaign directory, as
    its checkpoint attempts/<session>.done.json records them at acceptance (package B9a); a checkpoint without them is
    refused by name."""
    sizes = []
    for path in sorted((Path(directory) / "attempts").glob("*.done.json")):
        done = read_json(path)
        if not all(type(done.get(key)) is int and done[key] >= 0 for key in ("session_bytes", "archive_bytes")):
            raise ValueError(f"accepted session {done.get('session')} records no sizes (session_bytes, archive_bytes; "
                             f"scripts/campaign.py DISK_RULE): {path}")
        sizes.append((done["session"], done["session_bytes"], done["archive_bytes"]))
    return sizes


def largest_session(directory, manifest):
    """DISK_RULE: {"session_bytes", "archive_bytes"} of the largest accepted session so far, each the largest of the
    campaign's own checkpoints and of the seed its init froze (mode campaign); None before any (mode rehearsal)."""
    seed = (manifest.get("disk_estimate") or {}).get("seed")
    sizes = recorded_sizes(directory) + ([(seed["session"], seed["session_bytes"], seed["archive_bytes"])]
                                         if seed else [])
    if not sizes:
        return None
    return {"session_bytes": max(size[1] for size in sizes), "archive_bytes": max(size[2] for size in sizes)}


def v5_capacity_guard(manifest, p, directory):
    """DISK_RULE for the next session of this VM (manifest: the VM's view), and at init for the whole campaign."""
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    reserve = p["min_free_gib"] * 2**30
    largest = largest_session(directory, manifest)
    working = archived = 0
    if largest is not None:
        pending = [r for r in manifest["sessions"] if not finished(directory, manifest, r)]
        applied, limit = replacement_limit(manifest, p)
        spare = max(0, limit - sum(r.get("replacement") is not None for r in rejections(directory))) if applied else 0
        archived = largest["archive_bytes"] * (len(pending) + spare)
        working = largest["session_bytes"]
        for vm in sorted({r["vm"] for r in pending if r.get("vm") not in (None, manifest.get("vm"))}):
            current = chain(directory, next(r for r in pending if r["vm"] == vm))[-1]
            working += max(0, largest["session_bytes"] - raw_bytes(session_dir(manifest, current)))
    if shutil.disk_usage(COLLECTIONS).free < working + reserve:
        raise ValueError(f"insufficient working space for the next session: {working + reserve} bytes needed "
                         "(scripts/campaign.py DISK_RULE)")
    if shutil.disk_usage(manifest["archive_root"]).free < archived + reserve:
        raise ValueError(f"insufficient archive space for the sessions still to capture: {archived + reserve} bytes "
                         "needed (scripts/campaign.py DISK_RULE)")


def ended(directory, manifest):
    """Whether a campaign directory has ended: closed by the operator (closed.json) or complete on every VM."""
    if (directory / "closed.json").exists():
        return True
    names = list(manifest["vms"]) if "vms" in manifest else [None]
    states = [directory / vm_file("status.json", vm) for vm in names]
    return all(path.exists() and read_json(path).get("status") == "complete" for path in states)


# DISK_RULE: what a rehearsal must share with the campaign whose estimate it seeds (the length and the shape of a
# session decide its size).
ESTIMATE_KEYS = ("name", "cycles", "interval_s", "full_every", "bin_bytes")


def rehearsal_estimate(path, p, compression):
    """DISK_RULE in mode campaign (init --estimate-from): the seed of the estimate, the largest accepted session of an
    ended rehearsal of this protocol, with where it comes from; every condition is refused by name."""
    path = Path(path).resolve()
    try:
        old, old_p = read_json(path / "campaign.json"), read_json(path / "protocol.json")
    except (OSError, ValueError) as error:
        raise ValueError(f"--estimate-from {path}: no campaign directory ({type(error).__name__}: {error})") from None
    if type(old) is not dict or old.get("schema") != "hyptcn3/collection-campaign/1" or old.get("id") != path.name:
        raise ValueError(f"--estimate-from {path}: no campaign directory (campaign.json of its own name)")
    if old.get("mode") != "rehearsal":
        raise ValueError(f"--estimate-from {path}: campaign {old['id']} is no rehearsal (mode {old.get('mode')!r})")
    if not ended(path, old):
        raise ValueError(f"--estimate-from {path}: rehearsal {old['id']} has not ended (closed, or complete on every "
                         "VM)")
    differing = [key for key in ESTIMATE_KEYS if type(old_p) is not dict or old_p.get(key) != p.get(key)]
    if old.get("archive_compression") != compression:
        differing.append("archive_compression")
    if differing:
        raise ValueError(f"--estimate-from {path}: rehearsal {old['id']} differs from this campaign in "
                         + ", ".join(differing))
    sizes = recorded_sizes(path)
    if not sizes:
        raise ValueError(f"--estimate-from {path}: rehearsal {old['id']} has no accepted session")
    session = max(sizes, key=lambda size: (size[2], size[1]))[0]
    return {"campaign": old["id"], "directory": str(path), "campaign_sha256": digest(path / "campaign.json"),
            "accepted_sessions": len(sizes), "session": session,
            "session_bytes": max(size[1] for size in sizes), "archive_bytes": max(size[2] for size in sizes)}


def require_stages(protocol_path, mode):
    """STAGES_RULE: the readiness records and the self-test a campaign of this mode starts on; ValueError by name."""
    from scripts import gates  # Inside the function, as scripts/collection.py: gates imports collection.
    from scripts.audit_selftest import require_selftest
    stage, needed = START_STAGES[mode]
    try:
        gates.require(gates.ROOT / "data/results", protocol_path, stage)
    except ValueError as error:
        raise ValueError(f"a campaign of mode {mode} starts on valid readiness records of {needed}: {error}") from None
    require_selftest(protocol_path)


@contextmanager
def audit_lock(directory, **state):
    """One audit/archive on the host at a time, over all VMs and campaigns.

    Feature extraction and the compressing archiver are the heavy host work
    between captures (CPU, memory, SSD and archive disk); two at once would
    load the other VM's running capture twice. Waits; interrupts end the wait.
    """
    COLLECTIONS.mkdir(parents=True, exist_ok=True)
    fd = os.open(COLLECTIONS / ".audit.lock", os.O_CREAT | os.O_RDWR, 0o644)
    try:
        waiting = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waiting:
                    update_state(directory, status="running", stage="audit-wait", **state,
                                 message="another VM's audit or archive is running")
                waiting = True
                time.sleep(WAIT_POLL_S)
        yield
    finally:
        os.close(fd)


def pilot_reports(p, values):
    """--pilot-report PATH (single VM) or one VM=PATH per VM of the protocol."""
    names = vm_names(p)
    if names == [None]:
        if len(values) != 1:
            raise ValueError("exactly one pilot report required")
        return {None: Path(values[0])}
    given = dict(str(value).split("=", 1) if "=" in str(value) else (None, value) for value in values)
    if len(given) != len(values) or set(given) != set(names):
        raise ValueError("one accepted pilot per VM required: --pilot-report VM=PATH for " + ", ".join(names))
    return {vm: Path(given[vm]) for vm in names}


def archive_estimate(session_dir, p, compression):
    """Archive bytes per hourly session from the accepted pilot itself.

    Raw images use the archive codec on every pilot image; all other session
    files count uncompressed (upper bound). The 1.5 planning margin is kept.
    """
    raw = Path(session_dir) / "raw"
    original = stored = 0
    for path in sorted(raw.glob("*.vmicd")):
        size = path.stat().st_size
        original += size
        if compression is None:
            stored += size
            continue
        with path.open("rb") as stream:
            process = subprocess.Popen(["zstd", "-q", "-3", "-T1", "-c"], stdin=stream, stdout=subprocess.PIPE)
            for chunk in iter(lambda: process.stdout.read(1 << 20), b""):
                stored += len(chunk)
            if process.wait():
                raise ValueError("zstd failed while estimating the archive size")
    if not original:
        raise ValueError("pilot raw images are not available for the archive estimate")
    other = sum(f.stat().st_size for f in Path(session_dir).rglob("*")
                if f.is_file() and not f.is_symlink() and raw not in f.parents)
    scale = p["cycles"] / p["pilot_cycles"]
    return {"codec": compression, "pilot_raw_bytes": original, "pilot_raw_stored_bytes": stored,
            "raw_ratio": stored / original, "pilot_other_bytes": other,
            "bytes_per_session": (stored + other) * scale * 1.5,
            "note": "Measured on the accepted pilot; heavier scenarios may exceed it."}


def v5_freeze(a, p, compression):
    """What init freezes of a campaign of protocol schema 3, each condition refused by name before the lab is asked:
    the plan mode (MODE_RULE), no pilot (PILOT_RULE), the limit of mode campaign (LIMIT_RULE), the seed of the disk
    estimate (DISK_RULE: --estimate-from, in mode campaign only), the stages (STAGES_RULE), then the guest environment
    of every VM. Returns (mode, per-VM part of the manifest, the manifest's keys of schema 3)."""
    mode = a.mode
    if mode is None:
        raise ValueError("a campaign of protocol schema 3 needs --mode campaign or --mode rehearsal (no default; "
                         "scripts/campaign.py MODE_RULE)")
    if mode not in protocol_v5.MODES:
        raise ValueError("invalid --mode: " + " or ".join(protocol_v5.MODES))
    if a.pilot_report:
        raise ValueError("protocol v5 has no pilot: init takes no --pilot-report (scripts/campaign.py PILOT_RULE)")
    if mode == "campaign":
        if type((p.get("replacement") or {}).get("max_per_campaign")) is not int:
            raise ValueError(NULL_LIMIT)
        if a.estimate_from is None:
            raise ValueError("a campaign of mode campaign needs --estimate-from, the directory of an ended rehearsal "
                             "of the protocol (scripts/campaign.py DISK_RULE)")
    elif a.estimate_from is not None:
        raise ValueError("--estimate-from belongs to mode campaign: a rehearsal estimates from its own accepted "
                         "sessions (scripts/campaign.py DISK_RULE)")
    require_stages(a.protocol, mode)
    seed = None if mode == "rehearsal" else rehearsal_estimate(a.estimate_from, p, compression)
    per_vm = {}
    for vm in vm_names(p):  # PILOT_RULE: the guest environment of every VM, recorded here (no pilot to take it from).
        view = collection.for_vm(p, vm)
        per_vm[vm] = {"guest_environment": guest_environment(collection.guest_identity(view)),
                      **({} if vm is None else {"domain": view["domain"]})}
    return mode, per_vm, {"disk_estimate": {"rule": DISK_RULE, "seed": seed}, "rules": RULES}


def initialize(a):
    if git("status", "--porcelain"):
        raise ValueError("commit the source and documentation before freezing a campaign")
    p = collection.protocol(a.protocol)
    compression = None if a.archive_compression == "none" else a.archive_compression
    if schema3(p):
        mode, per_vm, v5_keys = v5_freeze(a, p, compression)
        pilots, profile = {}, tree_hashes(ROOT / p["profile"])
    else:
        pilots, per_vm, profile = pilot_freeze(a, p, compression)
        mode, v5_keys = None, {}
    if len({v["guest_environment"]["machine_id"] for v in per_vm.values()}) != len(per_vm):
        raise ValueError("VMs share a machine-id; a clone needs its own identity (labctl clone)")
    planned = campaign_plan(p, mode)
    # MODE_RULE: under schema 3 the default name ends in the plan's name (a rehearsal's own name, protocol_v5._shape).
    name = a.name or stamp() + ("_" + planned["name"] if mode else "_benign_v2")
    if not re.fullmatch(CAMPAIGN_NAME, name):
        raise ValueError("invalid campaign name")
    archive_root = Path(a.archive_root).absolute()
    mount = mount_identity(archive_root, allow_system=a.archive_on_system_disk)
    owner = pwd.getpwuid(int(os.environ.get("SUDO_UID", os.getuid())))
    directory = BASE / name
    for i, row in enumerate(planned["sessions"]):
        row["session_id"] = "_".join([name, f"{i + 1:02d}", *([row["vm"]] if "vm" in row else []),
                                      row["role"], row["scenario"]])
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": name, "date": now(),
                "commit": git("rev-parse", "HEAD"), "runtime": runtime_identity(),
                "owner": {"name": owner.pw_name, "uid": owner.pw_uid, "gid": owner.pw_gid},
                "workspace": str(ROOT), "protocol_sha256": digest(a.protocol),
                "profile_sha256": profile, "extractor_sha256": extractor_hashes(),
                # MODE_RULE (schema 3): the plan's mode, name and group prefix (protocol_v5._shape).
                **({"mode": mode, "plan_name": planned["name"], "group_prefix": planned["group_prefix"]}
                   if mode else {}),
                # Pilot, guest environment and estimates: per VM under "vms", or flat for one VM.
                **(per_vm[None] if None in per_vm else {"vms": per_vm}),
                "archive_root": str(archive_root), "archive_mount": mount,
                "archive_dir": str(archive_root / "campaigns" / name),
                "archive_compression": compression,
                "working_storage": collection.storage_identity(COLLECTIONS),
                "sessions": planned["sessions"], "planned_capture_hours": planned["planned_hours"],
                **v5_keys,
                "note": "Frozen allocation, not a measurement or a completed corpus."}
    if getattr(a, "continues", None) is not None:
        manifest["continues"] = take_over(a.continues, manifest, p)
    todo = {vm: [r for r in planned["sessions"] if r.get("vm") == vm and taken_over(manifest, r) is None]
            for vm in per_vm}
    COLLECTIONS.mkdir(exist_ok=True, parents=True)
    archive_root.mkdir(exist_ok=True, parents=True)
    for vm in per_vm:
        capacity_guard(vm_view(manifest, p, vm)[0], p, len(todo[vm]), directory)
    # Group names repeat in every campaign of a protocol. Only a campaign
    # explicitly closed by the operator releases them (its data stays).
    groups = {r["group"] for r in planned["sessions"]}
    for old, doc in collection.session_records(COLLECTIONS):
        if doc["group"] in groups and not closed_campaign(doc.get("campaign_id")):
            raise ValueError("planned group already has data; resume or close its campaign: " + str(old))
    directory.mkdir(parents=True)
    for child in ("events", "groups", "attempts", "logs"):
        (directory / child).mkdir()
    copy_exclusive(Path(a.protocol), directory / "protocol.json")
    for vm, pilot in pilots.items():
        copy_exclusive(pilot, directory / vm_file("pilot.json", vm))
    write_new(directory / "plan.json", planned)
    write_new(directory / "campaign.json", manifest)
    external = Path(manifest["archive_dir"])
    guard_mount(archive_root, mount)
    external.mkdir(parents=True)
    for filename in frozen_files(manifest):
        copy_exclusive(directory / filename, external / filename)
    for vm in per_vm:
        total = sum(r.get("vm") == vm for r in planned["sessions"])
        update_state(directory, vm=vm, status="ready", stage="initialized",
                     accepted_archived=total - len(todo[vm]), total=total)
    print(json.dumps({"campaign": str(directory), "sessions": len(planned["sessions"]),
                      "capture_hours": planned["planned_hours"], **({"mode": mode} if mode else {}),
                      **({"continues": manifest["continues"]["campaign"],
                          "taken_over_sessions": len(manifest["continues"]["sessions"]),
                          "sessions_to_capture": sum(map(len, todo.values())),
                          "discarded_groups": [g["group"] for g in manifest["continues"]["discarded_groups"]]}
                         if "continues" in manifest else {}),
                      "archive": str(external)}, indent=2))
    return directory


def pilot_freeze(a, p, compression):
    """What init freezes of a campaign of protocol schema 1 or 2: one accepted pilot per VM with its guest
    environment and estimates (as before package B9a); --mode and --estimate-from are of schema 3 and refused by name.
    Returns (pilots, per-VM part of the manifest, the profile's hashes)."""
    for value, flag in ((a.mode, "--mode"), (a.estimate_from, "--estimate-from")):
        if value is not None:
            raise ValueError(flag + " applies only to protocol schema 3 (scripts/campaign.py MODE_RULE, DISK_RULE)")
    if not a.pilot_report:
        raise ValueError("a campaign of protocol schema 1 or 2 needs --pilot-report (an accepted pilot audit; "
                         "multi-VM protocol: one VM=PATH per VM)")
    pilots = pilot_reports(p, a.pilot_report)
    per_vm = {}
    for vm, pilot in pilots.items():  # One accepted pilot per VM: its own machine, estimate and memory.
        pv = collection.for_vm(p, vm)
        meta, needed = pilot_gate(pilot, a.protocol, pv)
        if meta.get("vm") != vm:
            raise ValueError("pilot was captured on a different VM")
        identity = collection.guest_identity(pv)
        if guest_environment(identity) != guest_environment(meta["guest_before"]):
            raise ValueError("guest environment differs from accepted pilot")
        if runtime_identity()["vm_swappiness"] != meta["host_context"].get("memory", {}).get("vm_swappiness"):
            raise ValueError("host vm.swappiness differs from accepted pilot")
        estimate = archive_estimate(read_json(pilot)["values"]["session_dir"], p, compression)
        per_vm[vm] = {"pilot_report_sha256": digest(pilot), "pilot_source": str(pilot.resolve()),
                      "guest_environment": guest_environment(identity),
                      "archive_estimate": estimate,
                      "estimated_archive_bytes_per_session": estimate["bytes_per_session"],
                      "estimated_session_bytes_with_reserve": needed}
        if vm is not None:
            per_vm[vm]["domain"] = pv["domain"]
    return pilots, per_vm, meta["profile_sha256"]


def closed_campaign(campaign_id):
    return (isinstance(campaign_id, str) and re.fullmatch(CAMPAIGN_NAME, campaign_id) is not None
            and (BASE / campaign_id / "closed.json").exists())


def copy_exclusive(source, destination):
    if destination.exists():
        if digest(source) != digest(destination):
            raise ValueError("existing campaign backup differs: " + str(destination))
        return
    temp = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    before = digest(source)
    try:
        with source.open("rb") as src, temp.open("xb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        if digest(source) != before or digest(temp) != before:
            raise ValueError("campaign backup checksum mismatch")
        os.link(temp, destination)
        temp.unlink()
        sync_dir(destination.parent)
    finally:
        temp.unlink(missing_ok=True)


def load_campaign(directory):
    directory = Path(directory).resolve()
    m = read_json(directory / "campaign.json")
    if m.get("schema") != "hyptcn3/collection-campaign/1" or m["workspace"] != str(ROOT):
        raise ValueError("campaign schema/workspace mismatch")
    p = collection.protocol(directory / "protocol.json")
    # MODE_RULE: the plan of the mode campaign.json names (schema 3), refused by name when it names none or one of a
    # schema without modes.
    if schema3(p) and m.get("mode") not in protocol_v5.MODES:
        raise ValueError("campaign of protocol schema 3 without its plan mode (campaign.json mode: campaign or "
                         "rehearsal; scripts/campaign.py MODE_RULE)")
    expected = campaign_plan(p, m.get("mode"))["sessions"]
    rows = [{k: v for k, v in row.items() if k != "session_id"} for row in m["sessions"]]
    if (m["id"] != directory.name or rows != expected
            or digest(directory / "protocol.json") != m["protocol_sha256"]
            or list(m.get("vms", [None])) != vm_names(p)
            or not set(m.get("continues", {}).get("sessions", {})) <= {row["session_id"] for row in m["sessions"]}
            or not schema3(p) and any(digest(directory / vm_file("pilot.json", vm))
                                      != vm_view(m, p, vm)[0]["pilot_report_sha256"] for vm in vm_names(p))):
        raise ValueError("campaign plan or frozen inputs changed")
    if len({r["session_id"] for r in m["sessions"]}) != len(rows):
        raise ValueError("duplicate campaign session IDs")
    for row in m["sessions"]:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}", row["session_id"]):
            raise ValueError("unsafe session ID")
    return m, p


def taken_session(previous, old, old_p, final, group):
    """One accepted, archived session of the closed campaign as the continuation takes it over.

    Its records must still agree with each other, as a resumed run of that
    campaign would require: checkpoint, selected audit, session metadata,
    features, archive manifest and the boot recorded for its group. Whether the
    selected audit accepts it is decided by the one acceptance decision on the
    record under the closed campaign's protocol (features/acceptance.py
    require_recorded; deferred point 10 of B2, package B9a), not by its flag.
    """
    from features.acceptance import require_recorded
    name = final["session_id"]
    try:
        done = read_json(previous / "attempts" / (name + ".done.json"))
        pointer = read_json(previous / "attempts" / (name + ".audit.json"))
        report, session, archive = Path(pointer["path"]), session_dir(old, final), archive_dest(old, final)
        doc, meta = read_json(report), read_json(session / "session.json")
        v = doc["values"]
        try:
            require_recorded(old_p, final["role"], v, meta.get("cycles"))
            refused = None
        except ValueError as error:
            refused = str(error)
        checks = {
            "selected audit": digest(report) == pointer["sha256"] == done["audit_sha256"],
            "audit verdict and provenance" + ("" if refused is None else f" (require_recorded: {refused})"):
                refused is None and audit_environment(doc, old)
                and v["session_dir"] == str(session) and v["role"] == final["role"],
            "session metadata": digest(session / "session.json") == v["session_sha256"]
                                and all(meta[k] == final[k] for k in ("role", "group", "scenario", "seed", "session_id"))
                                and meta.get("vm") == final.get("vm") and meta.get("campaign_id") == old["id"],
            "features": digest(v["features"]) == v["features_sha256"],
            "archive": digest(archive / "archive-manifest.json") == done["manifest_sha256"]
                       and (session / "raw").is_symlink() and os.readlink(session / "raw") == str(archive / "raw"),
            "group boot": meta["guest_before"] == group["identity"]}
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(f"session {name} cannot be taken over ({type(exc).__name__}: {exc})") from None
    if not all(checks.values()):
        raise ValueError(f"session {name} cannot be taken over, records disagree: "
                         + ", ".join(k for k, ok in checks.items() if not ok))
    return {"campaign": old["id"], "session_id": name, "group": final["group"], "audit": str(report),
            "audit_sha256": pointer["sha256"], "boot_id": meta["guest_before"]["boot_id"]}


def take_over(previous, manifest, p):
    """What a new campaign takes from the closed campaign it continues (PLAN_multivm_dataset.md, chapter 8).

    The predecessor stopped for good - a session its replacement rule could not
    replace, or a lost group boot - and the operator closed it. The continuation
    has the same protocol file, plan, extractor, profile, runtime and guest
    environments, so the sessions of both pass one index (features/dataset.py).

    A group whose every assignment is accepted and archived there is taken over:
    not captured and not audited again, indexed through its frozen audit. Every
    other group is captured again as a whole in a new boot of its VM. What the
    predecessor has of such a group stays archived, is listed under
    discarded_groups and is never indexed: a group remains one boot of one VM.

    A campaign is continued once, and a continuation is never continued. Only a
    continuation that was closed before it captured anything may be set up again.
    """
    previous = Path(previous).resolve()
    old, old_p = load_campaign(previous)
    if not (previous / "closed.json").exists():
        raise ValueError("only a campaign closed by the operator can be continued")
    if "continues" in old:
        raise ValueError("a continuation campaign cannot be continued again")
    for other in sorted(BASE.glob("*/campaign.json")):
        if read_json(other).get("continues", {}).get("campaign") != old["id"]:
            continue
        measured = [f for kind in ("done", "rejected", "audit") for f in (other.parent / "attempts").glob(f"*.{kind}.json")]
        if measured or not (other.parent / "closed.json").exists():
            raise ValueError("campaign already has a continuation: " + other.parent.name)
    strip = lambda rows: [{k: v for k, v in row.items() if k != "session_id"} for row in rows]
    differing = [key for key in ("protocol_sha256", "profile_sha256", "extractor_sha256", "runtime")
                 if old.get(key) != manifest.get(key)]
    if list(old.get("vms", [None])) != list(manifest.get("vms", [None])) \
            or strip(old["sessions"]) != strip(manifest["sessions"]):
        differing.append("plan")
    else:
        differing += ["guest_environment" + (f" ({vm})" if vm else "") for vm in vm_names(p)
                      if vm_view(old, old_p, vm)[0]["guest_environment"]
                      != vm_view(manifest, p, vm)[0]["guest_environment"]]
    if differing:
        raise ValueError("continuation differs from the closed campaign: " + ", ".join(differing))
    guard_mount(old["archive_root"], old["archive_mount"])
    groups = {}
    for before, row in zip(old["sessions"], manifest["sessions"]):
        groups.setdefault(row["group"], []).append((before, row))
    sessions, discarded, complete = {}, [], {}
    for name, members in groups.items():
        first = members[0][1]
        finals = [chain(previous, before)[-1] for before, _ in members]
        accepted = [final for (before, _), final in zip(members, finals) if is_done(previous, before)]
        record = previous / "groups" / (name + ".json")
        complete[name] = len(accepted) == len(members)
        if not complete[name]:
            if record.exists():  # Started: it has a boot and possibly sessions, none of them indexed.
                discarded.append({"group": name, "role": first["role"], **({"vm": first["vm"]} if "vm" in first else {}),
                                  "boot_id": read_json(record)["identity"]["boot_id"],
                                  "accepted_sessions": [final["session_id"] for final in accepted]})
            continue
        group = read_json(record)
        for (_, row), final in zip(members, finals):
            sessions[row["session_id"]] = taken_session(previous, old, old_p, final, group)
    # The time order of the plan holds over both campaigns only if no role of a later rank was completed there
    # before one of an earlier rank (ORDER_RULE: the two test roles share a rank and interleave); the runners never
    # do that, a damaged directory could.
    rank = time_rank(p)
    role = {name: rank[members[0][1]["role"]] for name, members in groups.items()}
    if any(complete[late] and not complete[early] and role[early] < role[late] for late in groups for early in groups):
        raise ValueError("closed campaign completed a later role before an earlier one")
    unused = rejections(previous)
    return {"campaign": old["id"], "directory": str(previous), "commit": old["commit"],
            "campaign_sha256": digest(previous / "campaign.json"),
            "closed_sha256": digest(previous / "closed.json"),
            "closed_reason": read_json(previous / "closed.json")["reason"],
            "replacements_used": sum(r.get("replacement") is not None for r in unused),
            "not_replaced": [r["session"] for r in unused if r.get("replacement") is None],
            "sessions": sessions, "discarded_groups": discarded,
            "note": "Taken-over sessions are indexed through the closed campaign's frozen audits. Discarded groups "
                    "are captured again as a whole; what the closed campaign has of them is never indexed."}


@contextmanager
def ledger_lock():
    """FROZEN_TREE_RULE: the lock under which tcn/pecat.py replaces the seal ledger through a temporary file (an
    exclusive flock of the ledger's directory, tcn/pecat.py _locked)."""
    descriptor = os.open(ROOT / Path(LEDGER).parent, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def tree_changes():
    """FROZEN_TREE_RULE: the lines of git status --porcelain other than the seal ledger modified in place (in the
    worktree, the index or both)."""
    return [line for line in git("status", "--porcelain").splitlines()
            if line and not (line[3:] == LEDGER and line[:2] in (" M", "M ", "MM"))]


def verify_frozen(directory, manifest, p):
    with ledger_lock():
        head, changes = git("rev-parse", "HEAD"), tree_changes()
    if head != manifest["commit"] or changes:
        raise ValueError("campaign source changed; restore frozen commit before resuming"
                         + (" (changed: " + "; ".join(changes[:5]) + ")" if changes else ""))
    if (runtime_identity() != manifest["runtime"]
            or tree_hashes(ROOT / p["profile"]) != manifest["profile_sha256"]
            or extractor_hashes() != manifest["extractor_sha256"]):
        raise ValueError("campaign runtime, profile or extractor changed")
    # A missing SSD must stop the run, not redirect it to another disk.
    if "working_storage" in manifest and collection.storage_identity(COLLECTIONS) != manifest["working_storage"]:
        raise ValueError("working storage for data/collections is not the frozen disk")
    # External copy also detects accidental changes to the local immutable plan.
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    external = Path(manifest["archive_dir"])
    for name in frozen_files(manifest):
        if digest(directory / name) != digest(external / name):
            raise ValueError("frozen campaign backup mismatch: " + name)


def update_state(directory, **values):
    if values.get("vm") is None:
        values.pop("vm", None)  # Single-VM campaign: status.json without a VM key, as before.
    path = directory / vm_file("status.json", values.get("vm"))
    previous = read_json(path) if path.exists() else {}
    state = {**previous, **values, "updated_at": now()}
    write_new(path, state, replace=True)
    event = {"schema": "hyptcn3/campaign-event/1", **state}
    write_new(directory / "events" / f"{stamp()}_{uuid.uuid4().hex[:8]}.json", event)
    print(json.dumps({k: state[k] for k in ("updated_at", "vm", "status", "stage", "session", "message")
                      if k in state}), flush=True)


def process_identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return {"host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "start_ticks": text.rsplit(")", 1)[1].split()[19]}
    except OSError:
        return None


def run_child(command, log, *, timeout, guard=lambda: None, lock_fd=None, grace=150):
    env = dict(os.environ)
    env.pop("HYPTCN_COLLECTION_LOCK_FD", None)
    if lock_fd is not None:
        env["HYPTCN_COLLECTION_LOCK_FD"] = str(lock_fd)
    with log.open("x") as stream:
        process = subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   pass_fds=() if lock_fd is None else (lock_fd,))
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                guard()
                if time.monotonic() >= deadline:
                    raise TimeoutError("campaign stage timed out: " + str(log))
                time.sleep(2)
            return process.returncode
        except InterruptedError:
            # One SIGTERM to the child only; it stops its own helpers in order and
            # writes a truthful end record. Group kills below are a last resort.
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
            raise
        finally:
            # A crashed parent script may leave traffic/capture grandchildren.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def hold_sleep_inhibitor():
    """Block sleep while the runner lives; the helper exits when its stdin pipe closes."""
    process = subprocess.Popen(["systemd-inhibit", "--what=sleep:idle", "--mode=block", "--who=hyptcn3 collection",
                                "--why=Preserve the frozen RAM sampling timeline", "cat"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(.5)
    if process.poll() is not None:
        raise ValueError("cannot take the sleep inhibitor lock")
    return process


def release_sleep_inhibitor(process):
    if process is None:
        return
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def sleep_inhibited():
    listing = subprocess.run(["systemd-inhibit", "--list", "--no-pager"], capture_output=True, text=True, timeout=10)
    return "hyptcn3 collection" in listing.stdout


class GroupStartFailed(ValueError):
    """A step of the start of a group of protocol schema 3 failed (GROUP_START_RULE): the session is rejected before
    its measured phase with the cause group_start."""

    def __init__(self, step, detail):
        super().__init__(f"{step}: {detail}")
        self.step = step


def lab_step(directory, p, verb, *args):
    """One labctl verb of the start of a group, as the VM's owner (GROUP_START_RULE): the JSON objects it printed, in
    order; its whole output stays in logs/. GroupStartFailed names the verb for an exit code other than 0, a timeout
    or a command that cannot start."""
    log = directory / "logs" / f"group-{verb}_{stamp()}.log"
    command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", verb,
                                       *collection.labctl_args(p), *args])
    try:
        rc = run_child(command, log, timeout=GROUP_START_STEPS[verb])
    except (TimeoutError, OSError) as error:
        raise GroupStartFailed(verb, f"{type(error).__name__}: {error}") from None
    text = log.read_text(errors="replace") if log.exists() else ""
    if rc:
        raise GroupStartFailed(verb, f"labctl {verb} exited {rc}: " + text.strip()[-CHILD_ERROR_CHARS:])
    printed = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if type(value) is dict:
            printed.append(value)
    return printed


def guest_record(printed, verb, schema):
    """The one record of `schema` that labctl `verb` printed (the JSON of lab/guest_state.py), else GroupStartFailed."""
    found = [value for value in printed if value.get("schema") == schema]
    if len(found) != 1:
        raise GroupStartFailed(verb, f"labctl {verb} printed {len(found)} records of {schema}, not one")
    return found[0]


def start_group(directory, manifest, p, row):
    """GROUP_START_RULE: the start of a new group of protocol schema 3, recorded in groups/<group>.json; the group's
    record (identity, qemu) is what every session of the group is checked against, as before."""
    ready = directory / "groups" / (row["group"] + ".json")
    intent = ready.with_name(row["group"] + ".start-intent.json")
    before = collection.qemu_process(p["domain"])
    if not intent.exists():
        write_new(intent, {"group": row["group"], "previous_qemu": before, "date": now()})
    update_state(directory, vm=row.get("vm"), status="running", stage="group-start", group=row["group"])
    steps = []

    def identity(step):
        try:
            return collection.guest_identity(p)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            raise GroupStartFailed(step, f"guest identity unavailable ({type(error).__name__}: {error})") from None

    steps.append({"step": "stop", "date": now(), "printed": lab_step(directory, p, "stop")})
    steps.append({"step": "start", "date": now(), "printed": lab_step(directory, p, "start")})
    qemu = collection.qemu_process(p["domain"])
    if qemu is None:
        raise GroupStartFailed("start", "no QEMU process of the domain after labctl start")
    if before is not None and qemu == before:
        raise GroupStartFailed("start", "labctl start left the QEMU process of the previous group (pid "
                                        f"{qemu['pid']}): a group starts with a new one (proposal 5.4)")
    # Way 1 (B5a F4): the record labctl start prints last, qemu_swap, names the QEMU it holds, its cgroup and its way.
    swaps = [value["qemu_swap"] for value in steps[-1]["printed"] if type(value.get("qemu_swap")) is dict]
    if not swaps:
        raise GroupStartFailed("start", "labctl start printed no qemu_swap record (the pid, cgroup and way of its QEMU)")
    swap = swaps[-1]
    if swap.get("qemu_pid") != qemu["pid"]:
        raise GroupStartFailed("start", f"labctl start's qemu_swap record names QEMU pid {swap.get('qemu_pid')!r}, "
                                        f"not the domain's QEMU process {qemu['pid']}")
    if (swap.get("way"), swap.get("temporary")) != ("unit", False):
        raise GroupStartFailed("start", f"labctl start holds the QEMU by way {swap.get('way')!r} (temporary "
                                        f"{swap.get('temporary')!r}): a group starts by way 1, the session daemon in its "
                                        "unit (finding F4 of B5a: way 2 moves the process, not its memory)")
    steps[-1].update(qemu=qemu, cgroup=swap.get("cgroup"))
    current = identity("start")
    if guest_environment(current) != manifest["guest_environment"]:
        raise GroupStartFailed("start", "new group requires a new boot with the frozen guest environment")
    for _, existing in collection.session_records(COLLECTIONS):
        if existing["guest_before"]["boot_id"] == current["boot_id"]:
            raise GroupStartFailed("start", "new group boot already belongs to another session")
    seed = protocol_v5.reset_seed(p)  # GROUP_START_RULE: the protocol's one seeded level (agent P, F4 of B9a).
    reset = guest_record(lab_step(directory, p, "reset", "--seed", str(seed)), "reset", "hyptcn3/guest-reset/1")
    if reset.get("seed") != seed:
        raise GroupStartFailed("reset", f"the guest reset to seed {reset.get('seed')!r}, not {seed}")
    steps.append({"step": "reset", "date": now(), "seed": seed, "output": reset})
    pretouch = guest_record(lab_step(directory, p, "pretouch"), "pretouch", "hyptcn3/guest-pretouch/1")
    if pretouch.get("touched") is not True:
        raise GroupStartFailed("pretouch", "the pretouch did not touch the memory of the largest event")
    steps.append({"step": "pretouch", "date": now(), "output": pretouch})
    if identity("pretouch") != current:
        raise GroupStartFailed("pretouch", "the guest identity changed during the reset or the pretouch")
    if collection.qemu_process(p["domain"]) != qemu:
        raise GroupStartFailed("pretouch", "the QEMU process changed during the reset or the pretouch")
    group = {"schema": "hyptcn3/campaign-group/1", "date": now(), "group": row["group"],
             **({"vm": row["vm"], "domain": p["domain"]} if "vm" in row else {}),
             "role": row["role"], "identity": current, "qemu": qemu, "previous_qemu": before,
             "start": {"rule": GROUP_START_RULE, "reset_seed": seed, "steps": steps}}
    write_new(ready, group)
    return group


def ensure_group(directory, manifest, p, row):
    ready = directory / "groups" / (row["group"] + ".json")
    if schema3(p) and not ready.exists():
        return start_group(directory, manifest, p, row)
    current = collection.guest_identity(p)
    if guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("guest environment changed")
    if ready.exists():
        group = read_json(ready)
        if group.get("vm") != row.get("vm"):
            raise ValueError("group belongs to another VM")
        if current != group["identity"]:
            raise ValueError("boot changed inside a group; preserve partial allocation for review")
        # A save/restore keeps the guest boot ID; the QEMU process shows it.
        qemu = collection.qemu_process(p["domain"])
        if qemu != group.get("qemu"):
            raise ValueError(("VM process not found" if qemu is None else
                              "VM process changed inside a group (restart or restore)")
                             + "; preserve partial allocation for review")
        return group
    intent = ready.with_suffix(".reboot-intent.json")
    if intent.exists():
        before = read_json(intent)["previous_boot"]
    else:
        before = current["boot_id"]
        write_new(intent, {"group": row["group"], "previous_boot": before, "date": now()})
    update_state(directory, vm=row.get("vm"), status="running", stage="reboot", group=row["group"])
    if current["boot_id"] == before:
        command = collection.user_command([sys.executable, ROOT / "scripts/labctl.py", "reboot",
                                           *collection.labctl_args(p)])
        rc = run_child(command, directory / "logs" / f"reboot_{stamp()}.log", timeout=240)
        if rc:
            raise ValueError("lab reboot failed; see campaign reboot log")
        current = collection.guest_identity(p)
    if current["boot_id"] == before or guest_environment(current) != manifest["guest_environment"]:
        raise ValueError("new group requires a new boot with the frozen guest environment")
    for _, existing in collection.session_records(COLLECTIONS):
        if existing["guest_before"]["boot_id"] == current["boot_id"]:
            raise ValueError("new group boot already belongs to another session")
    qemu = collection.qemu_process(p["domain"])
    if qemu is None:
        raise ValueError("VM process not found after the group reboot")
    group = {"schema": "hyptcn3/campaign-group/1", "date": now(), "group": row["group"],
             **({"vm": row["vm"], "domain": p["domain"]} if "vm" in row else {}),
             "role": row["role"], "identity": current, "qemu": qemu, "previous_boot": before}
    write_new(ready, group)
    return group


ABSENT = object()  # A key a session.json does not have.


def planned_items(p, row):
    """What session.json must hold of the events and controls of an attempt (B3 S6): the row's events wherever the
    protocol plans events (scripts/collection.py run records them whenever it has an events section, [] for a row
    without), and of a row with controls those the deck filled (an empty slot is not run); ABSENT where none."""
    events = row.get("events", []) if "events" in p else ABSENT
    controls = [x for x in row["controls"] if x.get("kind") is not None] if "controls" in row else ABSENT
    return {"events": events, "controls": controls}


def check_session(path, manifest, row, directory, p):
    meta = read_json(path / "session.json")
    for k in ("role", "group", "scenario", "seed", "session_id"):
        if meta[k] != row[k]:
            raise ValueError("session differs from frozen assignment: " + k)
    if meta.get("vm") != row.get("vm"):
        raise ValueError("session differs from frozen assignment: vm")
    if meta.get("replaces") != row.get("replaces"):
        raise ValueError("session differs from frozen assignment: replaces")
    if schema3(p):  # REPLACEMENT_RULE: the attempt and the plan it was drawn from.
        for key, expected in (("attempt", row["attempt"]), ("plan_mode", manifest["mode"])):
            if meta.get(key) != expected:
                raise ValueError("session differs from frozen assignment: " + key)
    # B3 S6: the events and controls the capture ran are those of the plan's row or of its replacement's.
    for key, expected in planned_items(p, row).items():
        if meta.get(key, ABSENT) != expected:
            raise ValueError("session differs from frozen assignment: " + key)
    # Measurement sources, not the whole worktree: a note written meanwhile is not a different capture.
    if (meta.get("campaign_id") != manifest["id"] or meta["commit"] != manifest["commit"]
            or meta.get("measurement_dirty") != [] or meta["protocol_sha256"] != manifest["protocol_sha256"]
            or guest_environment(meta["guest_before"]) != manifest["guest_environment"]):
        raise ValueError("session provenance differs from frozen campaign")
    group = read_json(directory / "groups" / (row["group"] + ".json"))
    if meta["guest_before"] != group["identity"]:
        raise ValueError("session boot differs from recorded campaign group")
    if meta.get("host_context", {}).get("qemu") != group.get("qemu"):
        raise ValueError("session VM process differs from recorded campaign group")
    end = read_json(path / "end.json") if (path / "end.json").exists() else {}
    return bool(end.get("completed") and end.get("guest_after") == meta["guest_before"])


def audit_environment(doc, manifest):
    """The verdict came from the frozen code; files outside measurement sources do not matter."""
    v = doc["values"]
    return (doc["commit"] == manifest["commit"] and doc.get("measurement_dirty") == []
            and v["protocol_sha256"] == manifest["protocol_sha256"]
            and v["extractor_sha256"] == manifest["extractor_sha256"])


def audit_capture(directory, manifest, p, row, session, guard):
    pointer = directory / "attempts" / (row["session_id"] + ".audit.json")
    if pointer.exists():
        selected = read_json(pointer)
        report = Path(selected["path"])
        if digest(report) != selected["sha256"]:
            raise ValueError("selected audit changed")
    else:
        # Recover a completed verdict if interrupted before pointer publication.
        reports = sorted(session.glob("campaign_audit_*.json"))
        complete = []
        for report in reports:
            try:
                doc = read_json(report)
            except json.JSONDecodeError:
                continue  # Interrupted write retained; next attempt uses a new path.
            if doc.get("schema") != "hyptcn3/collection-audit/1":
                continue
            if audit_environment(doc, manifest):
                complete.append(report)
            else:
                # Written while HEAD or measurement code differed: kept, never selected.
                # The frozen tree was verified before this call, so a new audit is valid.
                update_state(directory, vm=row.get("vm"), status="running", stage="audit", session=session.name,
                             message="ignored audit made from a changed source tree: " + report.name)
        if len(complete) > 1:
            raise ValueError("multiple campaign audit verdicts require review")
        if complete:
            report = complete[0]
        else:
            report = session / f"campaign_audit_{stamp()}.json"
            update_state(directory, vm=row.get("vm"), status="running", stage="audit", session=session.name,
                         message=None)
            command = collection.background_command(collection.user_command(
                [sys.executable, ROOT / "scripts/collection.py", "--protocol", directory / "protocol.json",
                 "audit", session, "--out", report]))
            rc = run_child(command, directory / "logs" / f"audit_{stamp()}.log",
                           timeout=max(600, p["cycles"] * 15), guard=guard)
            if rc not in (0, 2) or not report.exists():
                raise ValueError("audit did not produce a verdict; see campaign log")
    doc = read_json(report)
    v = doc["values"]
    if (not audit_environment(doc, manifest)
            or v["session_dir"] != str(session) or v["role"] != row["role"]
            or v["session_sha256"] != digest(session / "session.json")
            or digest(v["features"]) != v["features_sha256"]):
        raise ValueError("audit provenance differs from campaign/session")
    if not pointer.exists():
        write_new(pointer, {"path": str(report), "sha256": digest(report)})
    return report, v


def ended_before_measurement(session):
    """An attempt without measured phase or RAM image (failed preflight/warmup or a stop there)."""
    raw = session / "raw"
    # An archived session keeps raw/ as a link; it may dangle once the archive was moved
    # off this machine (owner decision 2026-11-14), which is not "no RAM image".
    if not session.is_dir() or raw.exists() or raw.is_symlink():
        return False
    if not (session / "session.json").exists():
        return not (session / "end.json").exists()  # Failed while preparing its metadata.
    end = session / "end.json"
    return end.exists() and read_json(end).get("measurement_started") is False


def retire_attempt(directory, manifest, row, session):
    """Keep an attempt that never measured under a numbered name, so the assignment can run again."""
    meta = read_json(session / "session.json") if (session / "session.json").exists() else None
    if meta is not None and (meta.get("campaign_id"), meta.get("session_id")) != (manifest["id"], row["session_id"]):
        raise ValueError("unexpected metadata in assignment directory: " + str(session))
    end = read_json(session / "end.json") if (session / "end.json").exists() else {}
    reason = end.get("error") or ("no session metadata" if meta is None else "no error recorded")
    numbers = [int(n) for n in (p.name.rsplit("-", 1)[1] for p in session.parent.glob(session.name + ".attempt-*"))
               if n.isdigit()]
    number = max(numbers, default=0) + 1
    target = session.with_name(f"{session.name}.attempt-{number}")
    os.rename(session, target)
    sync_dir(session.parent)
    write_new(directory / "attempts" / f"{session.name}.attempt-{number}.json",
              {"schema": "hyptcn3/campaign-attempt/1", "session": session.name, "attempt": number,
               "directory": str(target), "reason": reason, "date": now(),
               "note": "Ended before the measured phase without a RAM image; the assignment runs again "
                       "in the same group boot. Kept for review, not part of the corpus."})
    update_state(directory, vm=row.get("vm"), status="running", stage="retry", session=session.name,
                 message=f"attempt {number} ended before measurement: {reason}")


STOP_MESSAGE = {"audit_rejected": "audit rejected session; archived without replacement",
                "capture_incomplete": "incomplete capture archived; allocation stopped, no automatic replacement",
                "group_start": "the start of the group failed before the measured phase; allocation stopped, no "
                               "automatic replacement"}


def incomplete_reasons(session):
    """Why a capture that reached its measured phase did not complete, from its own end record."""
    if not (session / "end.json").exists():
        return ["no end.json: the capture recorded no end (crash, SIGKILL or power loss)"]
    end = read_json(session / "end.json")
    if end.get("error"):
        return [str(end["error"])]
    return ["guest identity changed during capture" if end.get("completed") else "end.json completed=false"]


def group_boot_lost(directory, p, row):
    """None while the group's boot still exists (same guest boot, same QEMU process), else why not."""
    group = read_json(directory / "groups" / (row["group"] + ".json"))
    try:
        current = collection.guest_identity(p)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return f"guest identity unavailable ({type(exc).__name__})"
    if current != group["identity"]:
        return "guest boot or environment changed since the group started"
    if collection.qemu_process(p["domain"]) != group.get("qemu"):
        return "VM process changed since the group started (restart or restore)"
    return None


def reject(directory, manifest, p, row, cause, reasons, report=None):
    """Record a session the campaign cannot use, with its cause; schedule its replacement if the
    protocol's rule allows.

    cause: "audit_rejected" (completed capture, rejecting audit; report = that audit) or
    "capture_incomplete" (the measured phase started, the capture did not complete), and under
    protocol schema 3 "group_start" (a step of the start of its group failed before the measured
    phase, GROUP_START_RULE). A rejection with the cause group_start is never replaced: no protocol
    may cover group_start, because collection.check_replacement admits in replacement.covers only
    REPLACEMENT_CAUSES (audit_rejected, capture_incomplete); the runner stops by name, and package
    B9b ends the campaign with a record (F7 of the verification of B9a). The rule is part of the
    frozen protocol (collection.check_replacement): which causes it covers and one maximum per
    campaign shared by all of them. The replacement is the
    same assignment - VM, role, group, scenario, seed, event schedule - captured again in the same
    boot of its group, right after the unusable session and before the group's next one. So a group
    stays one boot of one VM and the corpus still holds each group/scenario once: the unusable
    session is archived and kept, but never indexed. Under protocol schema 3 the replacement is the
    next attempt of its planned row (REPLACEMENT_RULE: new times and traffic seed), and the maximum
    holds in mode campaign only (LIMIT_RULE: in mode rehearsal it is not applied); the rejections are
    counted by cause in the state (rejections_by_cause).

    An incomplete capture is replaced only while that boot still exists: the guest identity
    and the QEMU process equal groups/<group>.json. After a guest reboot, a VM restart or a
    host crash there is no "same group boot" to capture in; a new boot under the same group
    would break one boot per group, so the allocation stops as before, for review.

    Called under the audit lock, so the per-campaign count is exact over all VMs. Returns the
    replacement row or None (cause not covered, maximum used up, boot lost, or under schema 3 a next
    attempt protocol_v5.replacement cannot draw, its OutsideDeck named: the caller stops).
    """
    rule = p.get("replacement") or {}
    applied, limit = replacement_limit(manifest, p)
    used = sum(r.get("replacement") is not None for r in rejections(directory))
    plan_session, number = row.get("plan_session", row["session_id"]), row.get("replacement", 0) + 1
    if cause not in rule.get("covers", collection.REPLACEMENT_CAUSES[:1] if rule else ()):
        refused = "the protocol has no replacement rule for this cause"
    elif applied and used >= limit:
        refused = f"the protocol's {limit} replacements per campaign are used up"
    else:
        refused = group_boot_lost(directory, p, row) if cause == "capture_incomplete" else None
    drawn = None
    if not refused:  # REPLACEMENT_RULE: the next attempt is drawn before the record names it.
        planned = next(r for r in manifest["sessions"] if r["session_id"] == plan_session)
        try:
            drawn = attempt_row(manifest, p, {**planned, "session_id": f"{plan_session}-r{number}",
                                              "replaces": row["session_id"], "plan_session": plan_session,
                                              "replacement": number})
        except protocol_v5.OutsideDeck as error:  # An item outside the protocol's deck (S5 of B4), by name.
            refused = f"its next attempt cannot be drawn: {error}"
    replacement = None if refused else f"{plan_session}-r{number}"
    write_new(rejection_file(directory, row["session_id"]), {
        "schema": "hyptcn3/campaign-rejection/1", "date": now(), "session": row["session_id"],
        **{k: row[k] for k in ("vm", "role", "group", "scenario", "seed", "replaces", "attempt") if k in row},
        "cause": cause, "reasons": reasons,
        **({} if report is None else {"audit": str(report), "audit_sha256": digest(report)}),
        "replacement": replacement, "replacements_before": used, "max_per_campaign": limit,
        **({"limit_applied": applied, "plan_mode": manifest["mode"]} if schema3(p) else {}),
        **({"not_replaced": refused} if refused else {}),
        "note": "Archived, never part of the corpus or event index. "
                + (("Replaced by the next attempt of the same assignment (protocol replacement rule, "
                    "scripts/campaign.py REPLACEMENT_RULE)." if schema3(p) else
                    "Replaced by the same assignment in the same group boot (protocol replacement rule).")
                   if replacement else "Not replaced; allocation stopped.")})
    counts = rejections_by_cause(directory)  # LIMIT_RULE: in the state of the runner, every VM's rejections.
    if replacement is None:
        update_state(directory, vm=row.get("vm"), status="running", stage="rejected", session=row["session_id"],
                     rejections_by_cause=counts, message=f"{cause} ({'; '.join(reasons)}); not replaced: {refused}")
        return None
    update_state(directory, vm=row.get("vm"), status="running", stage="replacement", session=row["session_id"],
                 replacements_used=used + 1, rejections_by_cause=counts,
                 message=f"{cause} ({'; '.join(reasons)}); replacement {used + 1} "
                         + (f"of {limit}" if applied else "(the limit is not applied in mode rehearsal)")
                         + ": " + replacement)
    return drawn


def take_stop_request(directory, vm=None):
    """Consume an operator request to stop before the next capture."""
    request = directory / vm_file("stop-request.json", vm)
    if not request.exists():
        return False
    os.replace(request, directory / "events" / f"{stamp()}_{request.name}")
    sync_dir(directory)
    return True


def earlier_roles(directory, manifest, p, row):
    """Other VMs' sessions of roles of a lower time rank than this row's role (ORDER_RULE: protocol_v5.TIME_RANK,
    the two test roles share a rank) that are not archived yet."""
    rank = time_rank(p)
    return [r for r in manifest["sessions"] if r.get("vm") != row.get("vm")
            and rank[r["role"]] < rank[row["role"]] and not finished(directory, manifest, r)]


def interleaved_with(p, role):
    """ORDER_RULE: the list of p["interleave"] (a key protocol schema 3 requires, protocol_v5 TOP_LEVEL) that holds
    `role`, () for a role in none of them."""
    return next((tuple(together) for together in p["interleave"] if role in together), ())


def group_started(directory, manifest, group):
    """ORDER_RULE: whether a group has started: its record groups/<group>.json exists (under protocol schema 3
    start_group writes it after the pretouch), or a continuation took the group over from its closed campaign (as a
    whole)."""
    return ((Path(directory) / "groups" / (group + ".json")).exists()
            or any(r["group"] == group and taken_over(manifest, r) is not None for r in manifest["sessions"]))


def earlier_groups(directory, manifest, p, row):
    """ORDER_RULE under protocol schema 3: the groups of the roles interleaved with this row's role that precede its
    group in the plan (manifest["sessions"], the time order of protocol_v5.plan) on the other VMs and have not started,
    each as the first row of its group in the plan; [] once the row's own group has started, for a role without
    interleave and under schemas 1 and 2."""
    together = interleaved_with(p, row["role"]) if schema3(p) else ()
    if not together or group_started(directory, manifest, row["group"]):
        return []
    before, seen = [], set()
    for r in manifest["sessions"]:
        if r["group"] == row["group"]:
            break
        if r["role"] in together and r.get("vm") != row.get("vm") and r["group"] not in seen:
            seen.add(r["group"])
            if not group_started(directory, manifest, r["group"]):
                before.append(r)
    return before


def wait_message(row, pending, groups):
    """What a runner waits for (ORDER_RULE): the VMs that have not finished the roles of an earlier rank, and the groups
    before its group in the plan that have not started, by VM."""
    parts = []
    if pending:
        parts.append("earlier roles on: " + ", ".join(sorted({r["vm"] for r in pending})))
    if groups:
        parts.append(f"the start of the groups before {row['group']} in the plan: " + ", ".join(
            f"{r['group']} (VM {r['vm']})" for r in groups))
    return "waiting for " + "; ".join(parts)


def wait_for_earlier_roles(directory, manifest, p, row):
    """Keep the time order of the plan across VMs, not only inside each VM (ORDER_RULE).

    features/dataset.py accepts a corpus only if all train sessions end before
    the first dev session starts, and so on (chronology by protocol_v5.TIME_RANK).
    Each VM takes its groups in plan order; before the first group of a role of a
    later rank this runner waits until the other VMs have finished every role of
    an earlier rank, and under protocol schema 3 before a group of an interleaved
    role until the other VMs have started every group of those roles that precedes
    it in the plan (earlier_groups). Returns a reason to stop instead (operator
    request, or the other runner is not running and nobody would end the wait),
    else None. The state names what the runner waits for.
    """
    shown, grace = None, time.monotonic() + START_GRACE_S
    while True:
        pending, groups = earlier_roles(directory, manifest, p, row), earlier_groups(directory, manifest, p, row)
        if not pending and not groups:
            return None
        if take_stop_request(directory, row["vm"]):
            return "operator stop request"
        for vm in sorted({r["vm"] for r in pending + groups}):
            path = directory / vm_file("status.json", vm)
            if not campaign_running(read_json(path) if path.exists() else {}) and time.monotonic() >= grace:
                if any(r["vm"] == vm for r in pending):
                    return f"VM {vm} has not finished the roles before {row['role']} and its runner is not active"
                return (f"VM {vm} has not started the groups before {row['group']} in the plan ("
                        + ", ".join(r["group"] for r in groups if r["vm"] == vm) + ") and its runner is not active")
        message = wait_message(row, pending, groups)
        if message != shown:
            update_state(directory, vm=row["vm"], status="running", stage="role-wait", group=row["group"],
                         role=row["role"], message=message)
            shown = message
        time.sleep(WAIT_POLL_S)


def archive_capture(directory, manifest, session, p, audit=None):
    update_state(directory, vm=manifest.get("vm"), status="running", stage="archive", session=session.name)
    destination = Path(manifest["archive_dir"]) / "collections" / manifest.get("vm", "") / session.name
    guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
    return archive_session(session, destination, guard, reclaim=True, campaign_id=manifest["id"],
                           audit=audit, reserve_bytes=p["min_free_gib"] * 2**30,
                           compress=manifest.get("archive_compression"))


def seal_session(directory, manifest, row, report):
    """SEAL_RULE: one accepted session of a sealed role written into the seal ledger right away, as the campaign's
    owner, by the per-session form of the ledger's command line; returns its result. Its refusal keeps the child's
    error text."""
    update_state(directory, vm=row.get("vm"), status="running", stage="seal", session=row["session_id"],
                 message=None)
    log = directory / "logs" / f"seal_{stamp()}.log"
    command = collection.user_command([sys.executable, "-m", "tcn.pecat", "zapis", "--audit", report,
                                       "--mode", manifest["mode"]])
    rc = run_child(command, log, timeout=SEAL_TIMEOUT_S)
    text = log.read_text(errors="replace") if log.exists() else ""
    if rc:
        raise ValueError(f"the seal of session {row['session_id']} was refused (python -m tcn.pecat zapis exit {rc}): "
                         + text.strip()[-CHILD_ERROR_CHARS:])
    try:
        result = json.loads(text)
        sealed = {*result["written"], *result["already"]}
    except (ValueError, KeyError, TypeError):
        raise ValueError(f"the seal of session {row['session_id']}: python -m tcn.pecat zapis printed no result "
                         f"(see {log})") from None
    if read_json(report)["values"]["features_sha256"] not in sealed:
        raise ValueError(f"the seal of session {row['session_id']}: the ledger holds no record of its feature archive "
                         f"after zapis (see {log})")
    return result


def execute(directory, *, stop_after=None, vm=None):
    """Run the sessions of one VM in plan order (all sessions of a single-VM campaign).

    A multi-VM campaign has one runner process per VM; they share the frozen
    plan, the audit lock and the final index, nothing else.
    """
    directory = Path(directory).resolve()
    campaign, protocol = load_campaign(directory)
    if vm not in vm_names(protocol):
        raise ValueError("this campaign runs one VM per runner; --vm is one of: "
                         + ", ".join(map(str, vm_names(protocol))) if vm is None else "campaign has no VM " + vm)
    manifest, p = vm_view(campaign, protocol, vm)
    # Replacements of audit-rejected sessions follow their plan row; the list grows when one is scheduled. Under
    # schema 3 each is the next attempt of its planned row (REPLACEMENT_RULE).
    rows = [attempt_row(manifest, p, r) for planned in manifest["sessions"] if planned.get("vm") == vm
            for r in chain(directory, planned)]
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("run with sudo from the campaign owner's account")
    if (directory / "closed.json").exists():
        raise ValueError("campaign was closed by the operator: " + read_json(directory / "closed.json")["reason"])
    interrupts = collection.Interrupts()
    owns_lock, inhibitor = False, None
    status_file = directory / vm_file("status.json", vm)
    stop_file = directory / vm_file("stop-request.json", vm)
    try:
        with collection.collection_lock(COLLECTIONS, p["domain"] if vm else None) as lock_fd:
            owns_lock = True
            verify_frozen(directory, manifest, p)
            if schema3(p):
                require_stages(directory / "protocol.json", manifest["mode"])  # STAGES_RULE
            last = read_json(status_file) if status_file.exists() else {}
            if last.get("status") == "running":
                # The lock was free, so that process is gone: SIGKILL, crash or power loss.
                update_state(directory, vm=vm, status="stopped", stage="unclean-end",
                             message="previous run ended without a final status; its session is incomplete")
            if stop_file.exists():
                # A request is meant for a running campaign; one left by a previous run is not.
                os.replace(stop_file, directory / "events" / f"{stamp()}_{stop_file.stem}-stale.json")
            inhibitor = hold_sleep_inhibitor()
            update_state(directory, vm=vm, status="running", stage="preflight", pid=os.getpid(),
                         process_identity=process_identity(os.getpid()), inhibitor_pid=getattr(inhibitor, "pid", None),
                         message=None, signals=[])
            reports = []
            processed = 0
            guard = lambda: guard_mount(manifest["archive_root"], manifest["archive_mount"])
            for i, row in enumerate(rows):
                taken = taken_over(manifest, row)
                if taken is not None:  # Completed by the closed campaign this one continues.
                    reports.append(taken_report(taken))
                    continue
                session = session_dir(manifest, row)
                destination = archive_dest(manifest, row)
                checkpoint = directory / "attempts" / (row["session_id"] + ".done.json")
                if rejection_file(directory, row["session_id"]).exists():
                    record = read_json(rejection_file(directory, row["session_id"]))
                    if record.get("replacement") is None:
                        raise ValueError(STOP_MESSAGE[record.get("cause", "audit_rejected")] + ": "
                                         + "; ".join(record["reasons"]))
                    continue  # Its replacement is the next row.
                if checkpoint.exists():
                    done = read_json(checkpoint)
                    if not check_session(session, manifest, row, directory, p):
                        raise ValueError("completed session lost its provenance")
                    report, values = audit_capture(directory, manifest, p, row, session, guard)
                    if (not values["accepted"] or digest(destination / "archive-manifest.json") != done["manifest_sha256"]
                            or not (session / "raw").is_symlink()
                            or os.readlink(session / "raw") != str(destination / "raw")):
                        raise ValueError("completed archive checkpoint mismatch")
                    reports.append(report)
                    continue
                verify_frozen(directory, manifest, p)
                update_state(directory, vm=vm, status="running", stage="session-preflight", session=session.name,
                             group=row["group"], role=row["role"], scenario=row["scenario"],
                             position=i + 1, total=len(rows), accepted_archived=len(reports))
                if ended_before_measurement(session):
                    retire_attempt(directory, manifest, row, session)  # Left by a previous run.
                attempts, refused_start = 0, None
                while not session.exists():
                    if take_stop_request(directory, vm):
                        update_state(directory, vm=vm, status="stopped", stage="between-sessions",
                                     message="operator stop request")
                        return 0
                    if vm is not None:
                        reason = wait_for_earlier_roles(directory, manifest, p, row)
                        if reason:
                            update_state(directory, vm=vm, status="stopped", stage="between-sessions", message=reason)
                            return 0
                    if attempts:
                        verify_frozen(directory, manifest, p)
                    attempts += 1
                    capacity_guard(manifest, p, sum(taken_over(manifest, r) is None for r in rows[i:]), directory)
                    try:
                        group = ensure_group(directory, manifest, p, row)
                    except GroupStartFailed as failure:  # GROUP_START_RULE: rejected before the measured phase.
                        refused_start = failure
                        break
                    update_state(directory, vm=vm, status="running", stage="capture", capture_started_at=now(),
                                 message=None)
                    command = [sys.executable, ROOT / "scripts/collection.py", "--protocol", directory / "protocol.json",
                               "run", "--role", row["role"], "--group", row["group"], "--scenario", row["scenario"],
                               "--seed", str(row["seed"]),
                               # Schema 3 (PILOT_RULE, REPLACEMENT_RULE): the plan mode and the attempt, no pilot.
                               *(["--mode", manifest["mode"], "--attempt", str(row["attempt"])] if schema3(p)
                                 else ["--pilot-report", directory / vm_file("pilot.json", vm)]),
                               "--session-id", session.name, "--campaign-id", manifest["id"],
                               "--expected-boot-id", group["identity"]["boot_id"],
                               "--expected-qemu", json.dumps(group["qemu"]),
                               *(["--vm", vm] if vm else []),
                               *(["--replaces", row["replaces"]] if "replaces" in row else [])]
                    rc = run_child(command, directory / "logs" / f"capture_{stamp()}.log", lock_fd=lock_fd,
                                   timeout=p["warmup_s"] + p["cycles"] * p["interval_s"] + 300, guard=guard)
                    if rc and not session.exists():
                        raise ValueError("capture could not start; see campaign log")
                    if ended_before_measurement(session):
                        if attempts >= MAX_ATTEMPTS:
                            raise ValueError(f"{attempts} attempts of {session.name} ended before measurement; "
                                             "see its end.json and the campaign logs")
                        retire_attempt(directory, manifest, row, session)
                        time.sleep(RETRY_PAUSE_S)
                if refused_start is not None:  # GROUP_START_RULE: no session directory, nothing to archive.
                    reasons = [str(refused_start)]
                    with audit_lock(directory, vm=vm, session=session.name):
                        replacement = reject(directory, manifest, p, row, "group_start", reasons)
                    if replacement is None:
                        raise ValueError(STOP_MESSAGE["group_start"] + ": " + "; ".join(reasons))
                    rows.insert(i + 1, replacement)
                    continue
                # The session stays on the working disk while it waits; its VM starts nothing new.
                with audit_lock(directory, vm=vm, session=session.name):
                    if not check_session(session, manifest, row, directory, p):
                        archive_capture(directory, manifest, session, p)
                        cause, reasons = "capture_incomplete", incomplete_reasons(session)
                        replacement = reject(directory, manifest, p, row, cause, reasons)
                    else:
                        verify_frozen(directory, manifest, p)
                        report, values = audit_capture(directory, manifest, p, row, session, guard)
                        archived = archive_capture(directory, manifest, session, p, report)
                        cause, reasons = (None, None) if values["accepted"] else ("audit_rejected", values["reasons"])
                        replacement = cause and reject(directory, manifest, p, row, cause, reasons, report)
                        if not cause and schema3(p) and sealed_role(row["role"]):
                            seal_session(directory, manifest, row, report)  # SEAL_RULE: before the checkpoint.
                if cause:
                    if replacement is None:
                        raise ValueError(STOP_MESSAGE[cause] + ": " + "; ".join(reasons))
                    rows.insert(i + 1, replacement)
                    continue
                write_new(checkpoint, {"session": session.name, "audit": str(report), "audit_sha256": digest(report),
                                       "manifest_sha256": digest(destination / "archive-manifest.json"),
                                       # DISK_RULE: the sizes of the accepted session, from its archive manifest.
                                       "session_bytes": archived["bytes"],
                                       "archive_bytes": archived.get("stored_bytes", archived["bytes"]),
                                       "date": now()})
                reports.append(report)
                processed += 1
                update_state(directory, vm=vm, status="running", stage="session-complete",
                             accepted_archived=len(reports))
                if stop_after and processed >= stop_after and i + 1 < len(rows):
                    update_state(directory, vm=vm, status="stopped", stage="between-sessions",
                                 message="requested stop-after boundary")
                    return 0
            if vm is None:
                finish_corpus(directory, manifest, p, reports)
                return 0
            # The runner that archives the campaign's last session builds the index of all VMs.
            with audit_lock(directory, vm=vm):
                if not all(finished(directory, manifest, r) for r in manifest["sessions"]):
                    update_state(directory, vm=vm, status="complete", stage="vm-complete", message=None,
                                 accepted_archived=len(reports))
                    return 0
                reports = [final_report(directory, manifest, r) for r in manifest["sessions"]]
                finish_corpus(directory, manifest, protocol, reports)
            return 0
    except BaseException as exc:
        try:
            interrupts.disarm()
        except InterruptedError:
            pass  # First signal arrived exactly here; the handler disarmed itself.
        if owns_lock:
            update_state(directory, vm=vm, status="stopped",
                         stage="interrupted" if isinstance(exc, InterruptedError) else "error",
                         message=str(exc), signals=interrupts.received)
        raise
    finally:
        release_sleep_inhibitor(inhibitor)
        interrupts.restore()


EVENT_INDEX = "hyptcn3/event-index/1"


def test_only(p, mode=None):
    """Whether a campaign of `p` ends with an event index instead of a corpus index: a protocol of schema 1 or 2
    without the role train (the test-only protocol of v3, step A), and under schema 3 a plan of `mode` without a
    session of a fitting role (features/dataset.py FIT_ROLES: schema 3 names all five roles, some with no group, so the
    key alone says nothing; package B7c)."""
    if p.get("schema") != collection.protocol_v5.SCHEMA:
        return "train" not in p["roles"]
    from features.dataset import FIT_ROLES
    return not any(row["role"] in FIT_ROLES for row in collection.protocol_v5.planned_rows(p, mode))


def event_index(reports, p, protocol_sha, *, mode=None):
    """Test-only protocol (v3, step A): accepted sessions with their event intervals.

    No training roles, so no corpus index: these sessions are only scored by an
    existing bundle (python3 -m tcn.eval udalosti).

    Package B7c. Every session is admitted by features.acceptance.require_accepted from its archive, which the
    index opens anyway (deferred point 8 of B2: an archive exchanged after the audit is refused; the decision is the
    one features/dataset.py build makes). The planned sessions: under protocol schema 3 the rows of the plan of `mode`
    (scripts/protocol_v5.py planned_rows, as features/dataset.py build; the mode has no default, campaign or
    rehearsal, and the index records it as plan_mode): a session must hold a planned row, matched by role, group,
    scenario and VM, and the index is complete when every row holds exactly one session. Schemas 1 and 2 keep their
    rule (every scenario in every group of their roles: the product) and refuse a mode.
    """
    from features.acceptance import require_accepted
    from features.archive import load
    from features.dataset import named, row_key
    from features.quality import require_log_audit
    if p.get("schema") == collection.protocol_v5.SCHEMA:
        if mode is None:
            raise ValueError("an event index of protocol schema 3 needs its plan mode (campaign or rehearsal)")
        rows = collection.protocol_v5.planned_rows(p, mode)
    elif mode is not None:
        raise ValueError(f"plan mode {mode} applies only to protocol schema 3; schemas 1 and 2 keep every scenario "
                         "in every group")
    else:
        rows = None
    planned_keys = None if rows is None else {row_key(row) for row in rows}
    records, boots, groups = [], {}, {}
    for path in reports:
        v = read_json(path)["values"]
        if v.get("accepted") is not True or v["protocol_sha256"] != protocol_sha:
            raise ValueError("unaccepted audit or protocol mismatch: " + str(path))
        session = Path(v["session_dir"])
        meta = read_json(session / "session.json")
        if v.get("session_sha256") != digest(session / "session.json") or digest(v["features"]) != v["features_sha256"]:
            raise ValueError("session metadata or features changed since audit: " + str(path))
        require_log_audit(meta, v)
        boot = meta["guest_before"]["boot_id"]
        if meta["role"] not in p["roles"] or boots.setdefault(boot, meta["group"]) != meta["group"] \
                or groups.setdefault(meta["group"], boot) != boot:
            raise ValueError("role or boot/group mapping outside the plan: " + str(path))
        if planned_keys is not None and row_key(meta) not in planned_keys:
            raise ValueError(f"assignment is outside the planned allocation: session "
                             f"{named(dict(meta, id=meta['session_id']))} holds no row of plan:{mode}: {path}")
        data = load(v["features"])
        try:
            # The verdict derived from the archive must accept and equal the record (features/acceptance.py). The
            # recorded length goes in as at the audit; it decides only a session of the role "diagnostic".
            require_accepted(data, p, session.name, meta["role"], v, meta.get("cycles"))
        except ValueError as error:
            raise ValueError(f"{error}: {path}") from None
        casy = data["casy"]
        events = session / "events.json"
        records.append({"id": meta["session_id"], "role": meta["role"], "group": meta["group"], "boot_id": boot,
                        **({"vm": meta["vm"]} if meta.get("vm") else {}),
                        "scenario": meta["scenario"], "seed": meta["seed"],
                        "start": float(casy[0]), "end": float(casy[-1]),
                        "session": str(session / "session.json"), "session_sha256": v["session_sha256"],
                        "audit": str(Path(path).resolve()), "audit_sha256": digest(path),
                        "features": v["features"], "features_sha256": v["features_sha256"],
                        "events": str(events), "events_sha256": digest(events),
                        "guest": meta["guest_before"], "collector_sha256": meta["collector_sha256"],
                        "extractor_sha256": v["extractor_sha256"]})
    if rows is None:
        planned = sum(p["roles"].values()) * len(p["scenarios"])
        complete = len(records) == planned
    else:  # Every planned row holds exactly one session (a second session of a row leaves the index incomplete).
        planned = len(rows)
        complete = len(records) == planned and {row_key(r) for r in records} == planned_keys
    return {"schema": EVENT_INDEX, "complete": complete, "planned_sessions": planned,
            "protocol_sha256": protocol_sha, "protocol_config": p, "sessions": records,
            "note": "Benign operational events; test-only sessions, never training data.",
            **({} if rows is None else {"plan_mode": mode})}


def continuation_note(manifest):
    """For the index of a continuation campaign: which sessions come from the closed campaign."""
    record = manifest.get("continues")
    if record is None:
        return {}
    return {"continues": {"campaign": record["campaign"], "commit": record["commit"],
                          "taken_over_sessions": sorted(s["session_id"] for s in record["sessions"].values()),
                          "discarded_groups": record["discarded_groups"],
                          "replacements_used": record["replacements_used"],
                          "not_replaced": record["not_replaced"]}}


def finish_corpus(directory, manifest, p, reports):
    vm = manifest.get("vm")  # Multi-VM: the status file of the runner that builds the index.
    # The completeness of the plan the campaign ran (package B6a): under schema 3 the plan of the campaign's own mode
    # (MODE_RULE; load_campaign holds the manifest to it); schemas 1 and 2 keep their rule and have no mode.
    mode = manifest.get("mode") if schema3(p) else None
    if schema3(p) and mode not in protocol_v5.MODES:
        raise ValueError("a campaign of protocol schema 3 names its plan mode in campaign.json (mode: campaign or "
                         "rehearsal; scripts/campaign.py MODE_RULE)")
    # indexed_sessions: the sessions of the index, of every VM; accepted_archived stays the count of this runner's VM
    # (campaign_report.py compares it with the VM's done checkpoints). Since several VMs (52fd3ca) the runner that
    # builds the index wrote the count of every VM into accepted_archived, a bug the real index in the tests of the
    # fix round of B9a showed (agent T, merge point 1).
    if test_only(p, mode):  # Package B7c: under schema 3 a plan without a fitting role reaches the event index too.
        update_state(directory, vm=vm, status="running", stage="index", indexed_sessions=len(reports))
        index = directory / "events_index.json"
        doc = event_index(reports, p, manifest["protocol_sha256"], mode=mode)
        doc["protocol"] = str(directory / "protocol.json")
        doc.update(continuation_note(manifest))
        if not doc["complete"]:
            raise ValueError("campaign ended without a complete event allocation")
        if index.exists():
            if read_json(index) != doc:
                raise ValueError("existing event index differs")
        else:
            write_new(index, doc)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        copy_exclusive(index, Path(manifest["archive_dir"]) / "events_index.json")
        update_state(directory, vm=vm, status="complete", stage="complete", corpus=str(index), message=None)
        return
    from features.dataset import build
    update_state(directory, vm=vm, status="running", stage="index", indexed_sessions=len(reports))
    index = directory / "corpus.json"
    doc = build(reports, p, manifest["protocol_sha256"], mode=mode)
    doc["protocol"] = str(directory / "protocol.json")
    doc.update(continuation_note(manifest))
    if not doc["complete"]:
        mismatches = doc["allocation_mismatches"]  # Each with its reason (features/dataset.py build).
        raise ValueError("campaign ended without a complete corpus allocation: "
                         + "; ".join(json.dumps(x, sort_keys=True) for x in mismatches[:3])
                         + (f"; and {len(mismatches) - 3} more" if len(mismatches) > 3 else ""))
    if index.exists():
        if read_json(index) != doc:
            raise ValueError("existing corpus index differs")
    else:
        write_new(index, doc)
    # The production check of training, as the owner; its refusal keeps the child's error text (B2 panel, package B9a).
    checked = subprocess.run(collection.user_command([
        sys.executable, "-c", "from safeguard.training import validate_index; import sys; validate_index(sys.argv[1])",
        index]), cwd=ROOT, timeout=180, capture_output=True, text=True)
    if checked.returncode:
        said = (checked.stderr.strip() or checked.stdout.strip() or "no output")[-CHILD_ERROR_CHARS:]
        raise ValueError(f"the production check of training refused the corpus index {index} (safeguard/training.py "
                         f"validate_index, exit {checked.returncode}): {said}")
    guard_mount(manifest["archive_root"], manifest["archive_mount"])
    copy_exclusive(index, Path(manifest["archive_dir"]) / "corpus.json")
    update_state(directory, vm=vm, status="complete", stage="complete", corpus=str(index), message=None)


def launch(directory, stop_after=None, vm=None):
    """One systemd unit per VM; without --vm every VM of the campaign is launched."""
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if vm is not None and vm not in vm_names(p):
        raise ValueError("campaign has no VM " + vm)
    if os.geteuid() != 0 or os.environ.get("SUDO_USER") != manifest["owner"]["name"]:
        raise ValueError("launch with sudo from the campaign owner's account")
    if (directory / "closed.json").exists():
        raise ValueError("campaign was closed by the operator")
    verify_frozen(directory, manifest, p)
    if schema3(p):
        require_stages(directory / "protocol.json", manifest["mode"])  # STAGES_RULE
    # KillMode=mixed: SIGTERM reaches only the runner, which stops its child in
    # order; anything left after it exits (or after the timeout) gets SIGKILL.
    for name in vm_names(p) if vm is None else [vm]:
        unit = vm_unit(name)
        command = ["systemd-run", "--collect", f"--unit={unit}", "--description=hyptcn3 benign collection campaign",
                   "--property=Type=exec", "--property=KillMode=mixed", "--property=TimeoutStopSec=240",
                   "--property=Restart=no", f"--working-directory={ROOT}",
                   f"--setenv=SUDO_USER={manifest['owner']['name']}", f"--setenv=SUDO_UID={manifest['owner']['uid']}",
                   f"--setenv=SUDO_GID={manifest['owner']['gid']}",
                   sys.executable, ROOT / "scripts/campaign.py", "run", directory]
        if name is not None:
            command += ["--vm", name]
        if stop_after:
            command += ["--stop-after", str(stop_after)]
        subprocess.run(list(map(str, command)), check=True, timeout=30)
        print(f"Log: journalctl -fu {unit}")
    print(f"Status: python3 scripts/campaign.py status {directory}")


def campaign_running(state):
    return (state.get("status") == "running" and state.get("process_identity") is not None
            and process_identity(state.get("pid")) == state["process_identity"])


def request_stop(directory, vm=None):
    """Ask the running campaign to stop before its next capture; the current session is kept.

    Multi-VM: every running runner gets its own request, or only the one named.
    """
    directory = Path(directory).resolve()
    _, p = load_campaign(directory)
    if vm is not None and vm not in vm_names(p):
        raise ValueError("campaign has no VM " + vm)
    running = [name for name in (vm_names(p) if vm is None else [vm])
               if (directory / vm_file("status.json", name)).exists()
               and campaign_running(read_json(directory / vm_file("status.json", name)))]
    if not running:
        raise ValueError("campaign is not running")
    for name in running:
        try:
            write_new(directory / vm_file("stop-request.json", name), {
                "schema": "hyptcn3/campaign-stop-request/1", "date": now(), "uid": os.getuid(),
                **({} if name is None else {"vm": name}),
                "note": "The current session finishes, is audited and archived; no new capture starts."})
        except FileExistsError:
            raise ValueError("stop already requested") from None
    print(f"Stop requested; follow: python3 scripts/campaign.py status {directory}")


def close(directory, reason):
    """Operator decision to end a stopped campaign: its data stays, its group names become reusable."""
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if not reason.strip():
        raise ValueError("closing a campaign requires a reason")
    names = vm_names(p)
    with ExitStack() as locks:
        # No runner of any campaign may be active; multi-VM: no runner on any of its domains.
        for row in collection.vms(p):
            locks.enter_context(collection.collection_lock(COLLECTIONS, row["domain"] if row["name"] else None))
        states = {vm: read_json(directory / vm_file("status.json", vm))
                  if (directory / vm_file("status.json", vm)).exists() else {} for vm in names}
        state = states[None] if names == [None] else {"vms": states}
        # One VM's finished share (vm-complete) does not complete the campaign.
        for each in states.values():
            if each.get("status") == "closed" or (each.get("status") == "complete"
                                                  and each.get("stage") != "vm-complete"):
                raise ValueError("campaign is already " + each["status"])
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        write_new(directory / "closed.json", {
            "schema": "hyptcn3/campaign-closed/1", "id": manifest["id"], "date": now(), "reason": reason,
            "uid": os.getuid(), "status_before": state,
            "note": "Operator decision. Captured, audited and archived sessions remain; no corpus index."})
        copy_exclusive(directory / "closed.json", Path(manifest["archive_dir"]) / "closed.json")
        for vm in names:
            update_state(directory, vm=vm, status="closed", stage="closed", message=reason)


def status(directory):
    directory = Path(directory).resolve()
    manifest, p = load_campaign(directory)
    if vm_names(p) == [None]:
        state = vm_status(directory, manifest, p, None)
    else:
        state = {"campaign": str(directory), "vms": {vm: vm_status(directory, manifest, p, vm) for vm in vm_names(p)}}
    print(json.dumps(state, indent=2, ensure_ascii=False))
    return state


def vm_status(directory, manifest, p, vm):
    state = read_json(directory / vm_file("status.json", vm))
    state["running"] = campaign_running(state)
    # Every audit rejection with its cause and, if the protocol allowed one, its replacement.
    state["rejections"] = [{"cause": "audit_rejected", **{k: r[k] for k in (
        "date", "session", "cause", "reasons", "replacement", "not_replaced") if k in r}}
                           for r in rejections(directory, vm)]
    state["rejections_by_cause"] = rejections_by_cause(directory)  # LIMIT_RULE: every VM's, by cause.
    if state.get("status") == "running" and not state["running"]:
        state["stale"] = True
        state["note"] = ("recorded as running but that process is not alive (SIGKILL, crash or power loss); "
                         "the current session is incomplete and the next run records an unclean end")
    state["sleep_inhibitor_active"] = sleep_inhibited()
    state["campaign"] = str(directory)
    if "continues" in manifest:
        state["continues"] = manifest["continues"]["campaign"]
        state["taken_over"] = sum(r.get("vm") == vm and taken_over(manifest, r) is not None
                                  for r in manifest["sessions"])
    state["planned_capture_hours"] = manifest["planned_capture_hours"]
    if state.get("session"):
        raw = session_dir(manifest, {"session_id": state["session"], **({} if vm is None else {"vm": vm})}) / "raw"
        state["snapshot_images_present"] = len(list(raw.glob("*.vmicd")))
        state["snapshots_expected"] = p["cycles"]
    return state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Freeze the plan, the source, the external mount and (schemas 1 and 2) the "
                                       "accepted pilot")
    init.add_argument("--protocol", type=Path, default=collection.DEFAULT)
    init.add_argument("--pilot-report", action="append", metavar="[VM=]PATH",
                      help="Protocol schemas 1 and 2 (required there): accepted pilot audit; multi-VM protocol: one "
                           "VM=PATH per VM. Protocol v5 has no pilot and refuses it (PILOT_RULE)")
    init.add_argument("--mode", choices=protocol_v5.MODES,
                      help="Protocol schema 3 (required there, no default; refused under schemas 1 and 2): the plan "
                           "of the campaign or of its rehearsal (MODE_RULE)")
    init.add_argument("--estimate-from", type=Path, metavar="REHEARSAL_DIR",
                      help="Protocol schema 3, mode campaign (required there, refused otherwise): the campaign "
                           "directory of an ended rehearsal whose largest accepted session seeds the disk estimate "
                           "(DISK_RULE)")
    init.add_argument("--archive-root", type=Path, required=True)
    init.add_argument("--name")
    init.add_argument("--archive-on-system-disk", action="store_true",
                      help="Explicitly allow an archive on the root filesystem (no second disk)")
    init.add_argument("--archive-compression", choices=["zstd", "none"], default="zstd")
    init.add_argument("--continue", dest="continues", type=Path, metavar="CAMPAIGN_DIR",
                      help="Continue this closed campaign of the same protocol: take over its complete "
                           "groups, capture every other group again (once per campaign)")
    for verb in ("run", "launch", "status", "verify-archives", "request-stop", "close"):
        cmd = sub.add_parser(verb)
        cmd.add_argument("directory", type=Path)
        if verb in ("run", "launch"):
            cmd.add_argument("--stop-after", type=int, help="Stop after this many newly archived sessions")
        if verb in ("run", "launch", "request-stop"):
            cmd.add_argument("--vm", help="Multi-VM campaign: this VM's runner (run requires it; "
                                          "launch and request-stop default to all VMs)")
        if verb == "close":
            cmd.add_argument("--reason", required=True, help="Recorded operator decision")
    a = ap.parse_args(argv)
    if getattr(a, "stop_after", None) is not None and a.stop_after < 1:
        ap.error("stop-after must be positive")
    if a.command == "init":
        initialize(a)
    elif a.command == "status":
        status(a.directory)
    elif a.command == "launch":
        launch(a.directory, a.stop_after, a.vm)
    elif a.command == "run":
        return execute(a.directory, stop_after=a.stop_after, vm=a.vm)
    elif a.command == "request-stop":
        request_stop(a.directory, a.vm)
    elif a.command == "close":
        close(a.directory, a.reason)
    else:
        manifest, _ = load_campaign(a.directory)
        guard_mount(manifest["archive_root"], manifest["archive_mount"])
        for row in (r for planned in manifest["sessions"] for r in chain(a.directory.resolve(), planned)):
            dest = archive_dest(manifest, row)
            if dest.exists():
                verify_archive(dest, session_dir(manifest, row))
                print("verified " + row["session_id"], flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"campaign: {error}", file=sys.stderr)
        sys.exit(2)
