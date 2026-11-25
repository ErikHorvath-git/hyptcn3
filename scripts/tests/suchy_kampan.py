"""The fakes of the G1 dry run (protocol v5, G1 preparation, package C3): the campaign of the command
python -m tcn.suchy_beh beh on the harness of scripts/tests/kampan_v5.py.

Binding texts: the skeleton dokazy/G1/kostra/KOSTRA.md (row C3 of section 1, section 2) with the lead's answers to Q32
to Q41 (2026-11-24T21:25Z) and point 5 of his POKYNY_TEMPO_2026-11-25. The campaign runs as on the collection PC: the
real scripts/campaign.py (init --mode rehearsal, its runners, init --mode campaign --estimate-from the rehearsal, the
replacements, the ledger through tcn.pecat, finish_corpus with features/dataset.py build and
safeguard.training.validate_index, the record of the complete ending). What this module replaces is FAKES, which the
command writes into zaznam.json, each with the attributes it patches; INFRASTRUCTURE lists what the harness patches
beside them, none of which stands in for a result (directories, waits, the children served in this process, the run's
ledger, spies); nothing else is patched:

    Kampan              kampan_v5.Harness with two changes. The capture (collection.run_session) builds the planned
                        session or its replacement with postav_session; the audit is the real
                        scripts/collection.py audit_session through scripts/tests/boundary_sessions.py audit, with only
                        collection.retazec (the feature extraction from guest RAM) returning the session's rows. The
                        ledger of the process (tcn.pecat.KNIHA) is the run's own, while the ledger of record
                        (tcn.pecat.ZAZNAM) stays the tracked file, so every stage the campaign and its records read is
                        suchy (tcn/pecat.py STAGE_RULE); a write of the tracked file is refused before it happens
    postav_session      one session as a capture leaves it, before its audit (SESSION_RULE): the row of a plan of the
                        working copy (or its replacement), the rows of scripts/tests/suchy_generatory.py riadky in its
                        mode and run seed, the evidence of boundary_sessions.build_session under the copy's rate, the
                        row's events that ran and its controls, the identity of the group's guest boot and QEMU process
    zaznam_generatora   the readers' form of generator.json (tcn/suchy_beh.py GENERATOR_KEYS) of the sessions of a
                        corpus, from the records of suchy_generatory.zaznam (GENERATOR_MAP_RULE)

A session named in Harness.reject is built with one read error (READ_ERROR_RULE), which the real audit refuses, so the
campaign replaces it with its next attempt. Only mechanics on synthetic sessions (HONESTY P4).
"""
import copy
import json
from pathlib import Path
import subprocess

from scripts import collection
from scripts import protocol_v5 as pv
from scripts.collection_archive import read_json
from scripts.tests import boundary_sessions as bs
from scripts.tests import kampan_v5 as kv
from scripts.tests import suchy_generatory as sg
from scripts.tests import test_collection_logs as evidence

# What the dry run still fakes (the skeleton, row C3: lab, the host's identity and swap, the archive, the campaign's
# requirement of the stages and of the self-test, the sleep inhibitor, root), each with what stands in for it and the
# attributes it patches. The capture and the extraction from guest RAM are the fakes the skeleton names beside them;
# git of the campaign is the harness's (the executor's reading, G1 preparation: a campaign freezes a clean tree, and a
# dry run writes its own directories beside the commit it runs on).
FAKES = (
    {"fake": "lab", "what": "labctl stop, start, reset --seed, pretouch, levels and reboot of the two VMs of the "
     "protocol, the guest identity they print (scripts/tests/kampan_v5.py Lab, with the stack manifest of "
     "boundary_sessions) and the VM's QEMU process", "why": "no VM in G1 (proposal 10.2)",
     "patches": ["scripts.collection.lab_json", "scripts.collection.guest_identity",
                 "scripts.collection.qemu_process"]},
    {"fake": "host identity and swap", "what": "the runtime identity of the host (vm.swappiness 1), the memory of a "
     "QEMU without swap, the identity of the runner's process", "why": "no root and no VM in G1",
     "patches": ["scripts.campaign.runtime_identity", "scripts.collection.host_memory",
                 "scripts.campaign.process_identity"]},
    {"fake": "archive", "what": "the archive mount on the run's working directory (no archive disk), without "
     "compression", "why": "no archive disk in G1; the copies of the archiver are real",
     "patches": ["scripts.campaign.mount_identity", "scripts.campaign.guard_mount"]},
    {"fake": "the stages and the self-test of the campaign", "what": "scripts.gates.require and "
     "scripts.audit_selftest.require_selftest inside the campaign and its children: recorded, never refused",
     "why": "a campaign session needs G0 to G4 and a self-test record of G2 rates (scripts/collection.py "
     "SESSION_GATES); the command itself calls the real gates.require of G1 on the real file and on the copy",
     "patches": ["scripts.gates.require", "scripts.audit_selftest.require_selftest"]},
    {"fake": "sleep inhibitor", "what": "campaign.hold_sleep_inhibitor and sleep_inhibited", "why": "needs logind",
     "patches": ["scripts.campaign.hold_sleep_inhibitor", "scripts.campaign.sleep_inhibited"]},
    {"fake": "root", "what": "os.geteuid 0, SUDO_USER the account that runs the command (SUDO_UID, SUDO_GID and "
     "HYPTCN_COLLECTION_LOCK_FD unset) and a child run as that account as it is (collection.user_command)",
     "why": "no sudo in G1", "patches": ["os.geteuid", "env SUDO_USER", "env SUDO_UID", "env SUDO_GID",
                                         "env HYPTCN_COLLECTION_LOCK_FD", "scripts.collection.user_command"]},
    {"fake": "git of the campaign", "what": "git status --porcelain is empty for scripts/campaign.py (init, "
     "tree_changes), git rev-parse HEAD the real commit, and the frozen-tree check of a running campaign "
     "(verify_frozen) passes", "why": "the run writes its work and its evidence beside the commit it runs on, which "
     "init refuses as a dirty tree (the executor's reading, G1 preparation); the real audit records the real commit, "
     "which the campaign compares with its frozen one (scripts/campaign.py audit_environment)",
     "patches": ["scripts.campaign.git", "scripts.campaign.verify_frozen"]},
    {"fake": "capture", "what": "collection.run_session: postav_session (suchy_kampan.SESSION_RULE)",
     "why": "no VM in G1: the skeleton's fake capture", "patches": ["scripts.collection.run_session"]},
    {"fake": "extraction from guest RAM", "what": "collection.audit_session is the real one, whose "
     "collection.retazec returns the session's rows of scripts/tests/suchy_generatory.py riadky "
     "(boundary_sessions.audit); every other check of the audit and the log audit are real",
     "why": "the RAM images of a dry run are synthetic", "patches": ["scripts.collection.audit_session"]},
)
# What the harness patches beside FAKES, none of which stands in for a result: the directories and the waits of the
# run, the children the campaign starts served in this process (the capture, the audit, labctl and tcn.pecat, each
# then the real code or a fake of FAKES; virsh, ssh, systemctl, sudo and the like refused), the run's own ledger, and
# spies that record a call and then make the real one.
INFRASTRUCTURE = (
    {"what": "the directories of the run: the collections, the campaigns and the records of the endings",
     "patches": ["scripts.campaign.COLLECTIONS", "scripts.campaign.BASE", "scripts.campaign.RESULTS"]},
    {"what": "the waits of the runners, which the harness drives in turn (kampan_v5 Harness.run)",
     "patches": ["scripts.campaign.RETRY_PAUSE_S", "scripts.campaign.WAIT_POLL_S", "scripts.campaign.START_GRACE_S"]},
    {"what": "the children of the campaign served in this process (kampan_v5 Harness.serve), a forbidden program "
     "refused", "patches": ["scripts.campaign.run_child", "subprocess.run", "subprocess.check_output",
                            "subprocess.Popen"]},
    {"what": "the run's own ledger (tcn.pecat.KNIHA; the ledger of record ZAZNAM stays the tracked file, so the stage "
     "is suchy) and the refusal of a write of the tracked file", "patches": ["tcn.pecat.KNIHA", "tcn.pecat._write"]},
    {"what": "spies that record each call and make the real one", "patches": ["scripts.campaign.finish_corpus",
                                                                              "tcn.pecat.kontrola"]},
)

SESSION_RULE = (
    "a session of the dry run as a capture leaves it, before its audit (the skeleton of G1, row C3): "
    "boundary_sessions.build_session of the row (a row of the plan of the working copy in its mode, or its "
    "replacement, protocol_v5.replacement, with its attempt), its first snapshot at the time of the clock of the "
    "harness and one interval_s after the logs of the traffic begin (test_collection_logs.build starts the measurement "
    "1 s after them; so the offered load of the interval of every frame is logged, tcn/finalne.py LOAD_RULE), every "
    "sidecar at the time of its row; the generator's frame (the events, the controls and the rows of suchy_generatory) "
    "starts suchy_generatory.FIRST_ROW_S before the first snapshot; the logs of the traffic under the copy's rate on "
    "the whole session (test_collection_logs.v5_traffic, the construction of item P3 of G2p, run again after "
    "events.json so that its user sessions lie after every event window, its journal lines of the orders service "
    "naming the service's pid in the guest's state, since no event of the plan restarts a unit here); session.json "
    "with the row's events and controls as the plan states them, the guest identity of the group's boot (the lab's, "
    "with the stack manifest of boundary_sessions) and the QEMU process of the group (every sidecar names its pid), "
    "and the fields of the capture of kampan_v5 (campaign, attempt, plan mode, commit); events.json the row's events "
    "that ran (host_start_unix the start of the generator's frame + start_s, host_stopped_unix 0.1 s after the stop, "
    "effect ok, the replies with test_collection_logs.SCRIPT_SHA256), controls.json of a session of test_controls "
    "suchy_generatory.controls_json; the evidence sealed again; the rows of the extraction suchy_generatory.riadky in "
    "the run's mode and seed in the generator's frame")
READ_ERROR_RULE = (
    "the rejection the dry run injects (the skeleton of G1, section 2, chain_end_to_end: one replacement at least, the "
    "rejection through Harness.reject): the session of a (group, scenario, attempt) in Harness.reject has one read "
    "error in the snapshot in the middle of its first chain, in its sidecar (stats.read_errors 1) and in its row "
    "(boundary_sessions.read_error_row, no predecessor after it); the real audit refuses it, the campaign replaces it")
GENERATOR_MAP_RULE = (
    "the form of generator.json the readers of tcn/suchy_beh.py read (GENERATOR_KEYS), per session of the corpus by "
    "its session id: invalid_rows the seq of the tolerated invalid rows of its record (suchy_generatory.zaznam "
    "invalid_rows.seq), marginal_changes one {first_seq, rows, column} per change of the record (its first seq, its "
    "count of rows, its column), unevaluated the occurrence whose first seconds the invalid rows leave scored less "
    "than analysis.evaluable.scored_share (evaluable false in the record), {what: control in role test_controls else "
    "event, index: its index among the events or the controls with a kind, type: the event's type or the control's "
    "kind}")
MIDDLE = lambda p: p["full_every"] // 2  # noqa: E731 - the snapshot of READ_ERROR_RULE (as vlozene_chyby._middle).
EVENT_STOPPED_S, EVENT_STARTED_S = 0.1, 0.05  # The host's calls of an event (judgment: within the event's window).
RESTARTED_PID = "999"  # test_collection_logs.build(event=True): the orders service after its restart_sluzby.


def profil(p):
    """The guest profile directory of the protocol, absolute (a relative one lies in the repository)."""
    path = Path(p["profile"])
    return path if path.is_absolute() else collection.ROOT / path


def planovany_riadok(protokol, mode, role, group, scenario, vm, attempt):
    """The row of attempt `attempt` of the planned session (scripts/collection.py v5_planned): the session of
    protocol_v5.plan(protokol, mode) of this role, group, scenario and VM for attempt 1, protocol_v5.replacement of it
    for a later one; with its attempt (suchy_generatory takes it)."""
    found = [s for s in pv.plan(protokol, mode)["sessions"]
             if (s["role"], s["group"], s["scenario"], s.get("vm")) == (role, group, scenario, vm)]
    if len(found) != 1:
        raise ValueError(f"no one planned session of {role}, {group}, {scenario}, VM {vm} in the {mode} plan")
    row = found[0] if attempt == 1 else pv.replacement(protokol, found[0], attempt, mode=mode)
    return dict(copy.deepcopy(row), attempt=attempt)


def _udalosti(row, frame_start):
    """The records of events.json of the row's events that ran (SESSION_RULE)."""
    out = []
    for item in row.get("events", []):
        start = frame_start + item["start_s"]
        stop = start + item["duration_s"]
        out.append(dict(item, executed=True, effect={"ok": True, "predicate": "synthetic"}, host_start_unix=start,
                        host_started_unix=start + EVENT_STARTED_S, host_stop_unix=stop,
                        host_stopped_unix=stop + EVENT_STOPPED_S,
                        start={"ok": True, "script_sha256": evidence.SCRIPT_SHA256},
                        stop={"ok": True, "health": 200, "script_sha256": evidence.SCRIPT_SHA256}))
    return out


def _chyba_citania(result, directory, p):
    """READ_ERROR_RULE in the rows and the sidecar of a built session."""
    seq = MIDDLE(p)
    i = result["seq"].index(seq)
    result["quality"][i] = bs.read_error_row()
    result["valid"][i] = False
    if i + 1 < len(result["seq"]):
        for name in ("ma_predchodcu", "proc_new", "proc_gone", "mod_delta"):
            result["matica"][i + 1][result["mena"].index(name)] = 0.0
    found = [path for path in (Path(directory) / "raw").glob("*.json")
             if json.loads(path.read_text()).get("seq") == seq]
    side = json.loads(found[0].read_text())
    side["stats"]["read_errors"] = 1
    evidence.write(found[0], side)


def postav_session(root, p, protocol_path, row, rezim, seed, protokol, *, session_id, prvy_riadok_unix, guest, qemu,
                   polia=None, chyba_citania=False):
    """SESSION_RULE: the session `session_id` of `row` below `root`, as a boundary_sessions.Session (directory,
    protocol_path, result: the rows the audit's extraction returns). p: the protocol as the session's VM sees it
    (collection.for_vm of the copy), protokol: the copy itself (the generator reads its plans), guest: the identity of
    the guest's boot, qemu: the QEMU process, polia: more fields of session.json, chyba_citania: READ_ERROR_RULE."""
    base = float(prvy_riadok_unix) - p["interval_s"]  # The logs begin one interval before the first snapshot.
    start = float(prvy_riadok_unix) - sg.FIRST_ROW_S  # The generator's frame: its events, controls and rows.
    items = {"events": copy.deepcopy(row.get("events", [])), "event_grace_s": protokol["events"]["grace_s"],
             "source_sha256": {"lab/udalosti.py": evidence.SCRIPT_SHA256}}
    if row["role"] == pv.CONTROL_ROLE:
        items["controls"] = [copy.deepcopy(c) for c in row["controls"] if c.get("kind") is not None]
    session = bs.build_session(Path(root), p, protocol_path, row, session_id=session_id, base=base, meta=items,
                               profile=profil(p), boot=guest["boot_id"])
    d = session.directory
    end = read_json(d / "end.json")
    meta = read_json(d / "session.json")
    meta.update(guest_before=copy.deepcopy(guest),
                host_context={"host_boot": qemu["host_boot"], "qemu": dict(qemu), "python": "python3",
                              "memory": dict(kv.MEMORY), "other_vms": []},
                **copy.deepcopy(polia or {}))
    evidence.write(d / "session.json", meta)
    evidence.write(d / "end.json", dict(end, guest_after=copy.deepcopy(guest)))
    for when in ("before", "after"):
        state = read_json(d / "guest" / f"state_{when}.json")
        evidence.write(d / "guest" / f"state_{when}.json", dict(state, boot_id=guest["boot_id"],
                                                                 kernel=guest["kernel"]))
    events = _udalosti(row, start)
    evidence.write(d / "events.json", {"schema": "hyptcn3/session-events/1", "events": events})
    if events:
        evidence.v5_traffic(d, p)  # Again: its user sessions after every event window (SESSION_RULE).
        # v5_traffic names the orders service of build()'s own event (restart_sluzby, orders as pid RESTARTED_PID) in
        # the journal lines of its requests after that event; no event of the plan restarts a unit here, so they name
        # the service's pid in the guest's state (SESSION_RULE).
        orders = read_json(d / "guest" / "state_before.json")["units"]["hyptcn-lab@orders"]["ExecMainPID"]
        evidence._segment(d, "journal", "journal.txt", lambda lines: [
            line.replace(f"python3[{RESTARTED_PID}]:", f"python3[{orders}]:") for line in lines])
    if row["role"] == pv.CONTROL_ROLE:
        evidence.write(d / "controls.json", sg.controls_json(row, start))
    result = sg.riadky(row, rezim, seed, protokol)
    result["casy"] = [start + t for t in result["casy"]]
    times = dict(zip(result["seq"], result["casy"]))
    for path in (d / "raw").glob("*.json"):
        side = json.loads(path.read_text())
        if side.get("schema") == "vmicollect/1":
            side["vm"]["vmid"] = qemu["pid"]
            side["timestamp_unix"] = times[side["seq"]]
            evidence.write(path, side)
    if chyba_citania:
        _chyba_citania(result, d, p)
    evidence.seal(d)
    return bs.Session(d, Path(protocol_path), result)


def zaznam_generatora(records):
    """GENERATOR_MAP_RULE: {session id: {invalid_rows, marginal_changes, unevaluated}} of `records` {session id: the
    record of suchy_generatory.zaznam of its row and attempt}."""
    out = {}
    for ident, record in records.items():
        invalid = record.get("invalid_rows")
        entry = {"invalid_rows": list(invalid["seq"]) if invalid else [],
                 "marginal_changes": [{"first_seq": change["seq"][0], "rows": len(change["seq"]),
                                       "column": change["column"]} for change in record.get("changes") or []],
                 "unevaluated": []}
        occurrence = (invalid or {}).get("occurrence")
        if occurrence is not None and occurrence.get("evaluable") is False:
            control = record["role"] == pv.CONTROL_ROLE
            entry["unevaluated"].append({"what": "control" if control else "event", "index": occurrence["index"],
                                         "type": occurrence["kind"] if control else occurrence["type"]})
        out[ident] = entry
    return out


class Laboratorium(kv.Lab):
    """kampan_v5.Lab whose guest identity carries the stack manifest of boundary_sessions (the audit compares it
    with lab/ of the commit, scripts/collection.py guest_mismatch), so that a session's guest_before is the group's."""

    def identity(self, vm):
        return dict(super().identity(vm), stack_manifest=list(bs.STACK_MANIFEST))


class Kampan(kv.Harness):
    """The harness of the dry run (module docstring) under `root`, patched through `patch` (a pytest.MonkeyPatch):
    protokol the loaded working copy, rezim and seed those of the run, kniha the run's own ledger. captures and audits
    are those of kampan_v5; riadky holds, per capture, what postav_session needs to build the session again
    (SESSION_RULE: the row, the plan mode, the time of the first row, the guest, the QEMU process, the fields and the
    injected read error), and vysledky its rows for the real audit."""

    def __init__(self, root, patch, *, protokol, rezim, seed, kniha):
        from tcn import pecat
        self.protokol, self.rezim, self.seed = protokol, rezim, seed
        self.kniha, self.zaznam = Path(kniha), pecat.ZAZNAM
        self.real_audit_session = collection.audit_session
        self.riadky, self.vysledky = [], {}
        super().__init__(root, patch)

    def patch(self):
        from tcn import pecat
        self.lab = Laboratorium(self.protokol)
        self.lab.stops = self.allowed_stops
        self.lab.sequence = self.sequence
        self.ledger = self.kniha
        super().patch()
        self.mp.setattr(pecat, "ZAZNAM", self.zaznam)  # STAGE_RULE: the run's ledger is not the ledger of record.

    def git(self, *args):
        """git of the campaign (FAKES): a clean tree at the real commit."""
        if args[:1] == ("status",):
            return ""
        if args[:1] == ("rev-parse",):
            return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=collection.ROOT, text=True).strip()
        raise AssertionError("the campaign asked git " + " ".join(args))

    def capture(self, a, p):
        """collection.py run of a session of a planned role (kampan_v5 Harness.capture): what its command line and
        collection.v5_run decide, the boot and the QEMU process of the group, then postav_session."""
        if p.get("schema") != pv.SCHEMA or a.role == "diagnostic":
            raise AssertionError("a campaign of protocol v5 captures sessions of planned roles under schema 3")
        campaign = Path(a.protocol).resolve().parent
        manifest = read_json(campaign / "campaign.json")
        tries = sum(x["campaign"] == a.campaign_id for x in self.captures)
        if tries >= len(manifest["sessions"]) + kv.RUNAWAY:
            raise AssertionError(f"runaway replacements: campaign {a.campaign_id} captured {tries} sessions")
        v5 = collection.v5_run(a, p)
        vm, attempt = p["vm"], a.attempt
        key = (a.campaign_id, a.group, a.scenario, attempt)
        identity, qemu = self.lab.identity(vm), self.lab.qemu(p["domain"])
        if getattr(a, "expected_boot_id", None) and identity["boot_id"] != a.expected_boot_id:
            raise ValueError("guest boot differs from campaign group")
        if getattr(a, "expected_qemu", None) and qemu != json.loads(a.expected_qemu):
            raise ValueError("VM process differs from campaign group (restart or restore)")
        row = planovany_riadok(self.protokol, a.mode, a.role, a.group, a.scenario, vm, attempt)
        if row["seed"] != a.seed or row.get("events", []) != v5["events"] or (
                "controls" in v5 and [c for c in row["controls"] if c.get("kind") is not None] != v5["controls"]):
            raise AssertionError(f"the row of {a.session_id} is not the session collection.v5_run plans")
        t0, t1 = self.clock.take(p)
        fields = {"campaign_id": a.campaign_id, **({"replaces": a.replaces} if a.replaces else {}),
                  "group_attempt": a.group_attempt, "attempt": attempt, "plan_mode": a.mode,
                  "commit": manifest["commit"], "commit_dirty": False, "measurement_dirty": [], "host": "test-host"}
        rejected = self.injected(self.reject, *key)
        root = self.collections / a.campaign_id / vm
        root.mkdir(parents=True, exist_ok=True)
        session = postav_session(root, p, a.protocol, row, self.rezim, self.seed, self.protokol,
                                 session_id=a.session_id, prvy_riadok_unix=t0, guest=identity, qemu=qemu,
                                 polia=fields, chyba_citania=rejected)
        self.vysledky[str(session.directory.resolve())] = session.result
        self.riadky.append({"session": a.session_id, "campaign": a.campaign_id, "vm": vm, "row": row,
                            "plan_mode": a.mode, "first_row_unix": t0, "guest": identity, "qemu": qemu,
                            "fields": fields, "read_error": rejected, "directory": str(session.directory)})
        self.captures.append({
            "campaign": a.campaign_id, "vm": vm, "sid": a.session_id, "role": a.role, "group": a.group,
            "scenario": a.scenario, "attempt": attempt, "mode": a.mode, "seed": a.seed, "replaces": a.replaces,
            "t0": t0, "t1": t1, "boot": identity["boot_id"], "qemu": qemu, "order": next(self.sequence),
            "directory": str(session.directory),
            "ledger": {entry["session"] for entry in kv.ledger_entries(self.ledger).values()},
            "done": {path.name[:-len(".done.json")] for path in (campaign / "attempts").glob("*.done.json")}})

    def audit(self, directory, p, protocol_path, output):
        """collection.py audit: the real collection.audit_session through boundary_sessions.audit, only retazec
        returning the session's rows (FAKES)."""
        src = Path(directory).resolve()
        result = self.vysledky[str(src)]
        patched = collection.audit_session
        collection.audit_session = self.real_audit_session
        try:
            found = bs.audit(bs.Session(src, Path(protocol_path), result), p, output=output, result=result)
        finally:
            collection.audit_session = patched
        self.audits.append({"sid": src.name, "accepted": found.code == 0, "report": str(output),
                            "reasons": list(found.values["reasons"]), "order": next(self.sequence)})
        return found.code
