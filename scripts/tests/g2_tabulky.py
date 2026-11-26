"""Recorded G2 sessions for the tables guest, events and restarts of scripts/campaign_report.py (package H1b6a).

A session directory is written as scripts/collection.py run and audit leave one after skuska/g2.py archived it:
session.json, protocol.json, end.json, events.json, the audit record, traffic_requests.jsonl and in guest/ the
journal and the nginx error log of the session with their segment records (lab/guest_state.py journal and segment,
the files as labctl fetch_segment leaves them). The driver's record is written by skuska/g2.py Block.record itself
and the injector's by skuska/poruchy.py Injector.values, so the tables read the records exactly as the driver and
the injector write them. The guest journal holds what systemd writes at an occurrence of zla_konfiguracia_sluzby
and at a killed service, in the form of the lab's journals (dokazy/skuska_labu/behy, 2026-11-23). Nothing outside
the root directory given is written.
"""
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

from scripts import campaign_report, collection
from skuska import g2, poruchy

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
P = collection.protocol(REAL)
T0 = 1_800_000_000.0  # The measure start of the first session (a multiple of interval_s).
SPAN = 10_000.0  # The measure starts of two sessions lie this far apart.
GRID = 0.25  # values.timing.grid_phase_s of every audit.
LOOP_SPACING = 3.25  # The lab's restart loop (lab/periods.json); LOOP_DELAY from 'Failed with result' to the restart.
LOOP_DELAY = 3.15
KILL_AT_S = 400.0  # The kill of the service after the measure start of its session.
KILL_DELAY = 3.19
PREDICATE = {name: f"the effect of {name}" for name in P["events"]["types"]}
PREDICATE[campaign_report.EMPTY_EVENT] = "none by definition: only the trigger ran"
PACKAGES = ["nginx\t1.22.1-9+deb12u3", "postgresql\t15+248", "python3\t3.11.2-1+b1", "python3-psycopg2\t2.9.5-1+b1"]
TIMERS = "timers: hyptcn-lab-udrzba.timer "


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stamp(t):
    """A time as journalctl -o short-iso-precise --utc writes it."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="microseconds")


def units(changed=None):
    """The units of a reply of lab/udalosti.py (unit_states), each active; changed: {unit: {key: value}}."""
    out = {unit: {"ActiveState": "active", "NRestarts": "0", "ExecMainPID": str(100 + i)}
           for i, unit in enumerate(campaign_report.NO_EFFECT_UNITS)}
    for unit, values in (changed or {}).items():
        out[unit] = {**out[unit], **values}
    return out


def record_of(item, start, *, ok=True, executed=True, start_units=None, stop_units=None, health=200):
    """The record of events.json of a planned item whose measure phase started at `start` (scripts/collection.py
    Events: the plan's keys, the host times, the replies of labctl event, the effect, executed)."""
    host_start = start + item["start_s"]
    host_stop = host_start + item["duration_s"]
    reply = {"schema": "hyptcn3/lab-event/1", "type": item["type"], "ok": True, "error": None, "health": health,
             "script_sha256": "5" * 64}
    effect = {"ok": ok, "predicate": PREDICATE[item["type"]],
              "evidence": "iba spúšťač" if item["type"] == campaign_report.EMPTY_EVENT else {}}
    return {**item, "executed": executed, "host_start_unix": host_start,
            "start": {**reply, "action": "start", "units": start_units or units()},
            "host_started_unix": host_start + 0.4, "host_stop_unix": host_stop,
            "stop": {**reply, "action": "stop", "units": stop_units or units(), "effect": effect},
            "host_stopped_unix": host_stop + 0.6, "effect": effect}


def loop_lines(start, stop, unit="hyptcn-lab@catalog", restarts=5, spacing=LOOP_SPACING, limit=True):
    """(t, text) of the journal at an occurrence of zla_konfiguracia_sluzby started at `start` and stopped at `stop`:
    the restart, `restarts` restarts `spacing` apart, each LOOP_DELAY after its line 'Failed with result', the line of
    the start limit after the last one, and the start of the stop."""
    name = unit + ".service"
    rows = [(start + 0.10, f"systemd[1]: Stopping {name} - hyptcn benign lab catalog..."),
            (start + 0.11, f"systemd[1]: Stopped {name} - hyptcn benign lab catalog."),
            (start + 0.12, f"systemd[1]: Started {name} - hyptcn benign lab catalog.")]
    for k in range(restarts):
        restart = start + 0.25 + LOOP_DELAY + k * spacing
        failed = restart - LOOP_DELAY
        rows += [(failed - 0.01, "python3[9]: usage: services.py [-h] {catalog,auth,orders,docs,worker,udrzba}"),
                 (failed - 0.001, f"systemd[1]: {name}: Main process exited, code=exited, status=2/INVALIDARGUMENT"),
                 (failed, f"systemd[1]: {name}: Failed with result 'exit-code'."),
                 (restart, f"systemd[1]: {name}: Scheduled restart job, restart counter is at {k + 1}."),
                 (restart + 0.001, f"systemd[1]: Stopped {name} - hyptcn benign lab catalog.")]
        if k < restarts - 1 or not limit:
            rows.append((restart + 0.03, f"systemd[1]: Started {name} - hyptcn benign lab catalog."))
        else:
            rows += [(restart + 0.002, f"systemd[1]: {name}: Start request repeated too quickly."),
                     (restart + 0.003, f"systemd[1]: {name}: Failed with result 'exit-code'."),
                     (restart + 0.004, f"systemd[1]: Failed to start {name} - hyptcn benign lab catalog.")]
    rows.append((stop + 0.3, f"systemd[1]: Started {name} - hyptcn benign lab catalog."))
    return rows


def kill_lines(kill, unit="hyptcn-lab@docs", delay=KILL_DELAY):
    """(t, text) of the journal after the SIGKILL of a service at `kill`: one restart `delay` after its failure."""
    name = unit + ".service"
    return [(kill + 0.05, f"systemd[1]: {name}: Main process exited, code=killed, status=9/KILL"),
            (kill + 0.06, f"systemd[1]: {name}: Failed with result 'signal'."),
            (kill + 0.06 + delay, f"systemd[1]: {name}: Scheduled restart job, restart counter is at 1."),
            (kill + 0.07 + delay, f"systemd[1]: Stopped {name} - hyptcn benign lab docs."),
            (kill + 0.10 + delay, f"systemd[1]: Started {name} - hyptcn benign lab docs.")]


def background(start, seconds=3700.0):
    """(t, text) of the lab's ordinary lines over a session: the worker's rounds (1 s apart, the register's worker
    loop), the maintenance runs (lab/periods.json hyptcn-lab-udrzba.timer) and the requests of the services every 2 s
    (traffic, which forms no group)."""
    rows = [(start - 100 + k, f'python3[801]: {{"service": "worker", "completed": {1 + k % 3}}}')
            for k in range(0, int(seconds), 1)]
    rows += [(start + t, 'python3[900]: {"service": "udrzba", "vacuum_rc": 0, "vacuum_error": null, '
                         '"log_compressed": null, "seconds": 0.2}') for t in (300.0, 1013.0, 1544.0, 2496.0, 3170.0)]
    rows += [(start + t, "systemd[1]: Starting hyptcn-lab-udrzba.service - hyptcn benign lab maintenance...")
             for t in (299.8, 1012.8, 1543.8, 2495.8, 3169.8)]
    rows += [(start + 2 * k, f"python3[700]: 127.0.0.1 - - request rid=r{k}-01-{k:08d} method=GET path=/api/catalog "
                             "status=200") for k in range(0, 200)]
    return rows


def gz_entry(dest, name, text):
    """The file a labctl fetch leaves in guest/ and its entry in the segment record (lab/guest_state.py describe)."""
    data = text.encode()
    target = dest / (name + ".gz")
    target.write_bytes(gzip.compress(data))
    return {"name": name, "file": target.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "lines": data.count(b"\n"), "terminated": True, "gz_bytes": target.stat().st_size,
            "gz_sha256": sha(target), "file_sha256": sha(target)}


class Lab:
    """What skuska/g2.py Block.record asks of its lab: the VM's owner (none: no chown)."""

    def owner(self):
        return None


class Recorder:
    """Writes recorded G2 sessions under root/diag/<vm>/<session>, the driver's records under root/G2/zaznamy and
    the injector's under root/G2/poruchy."""

    def __init__(self, root, protocol=REAL):
        self.root, self.protocol = Path(root), Path(protocol)
        self.g2_dir = self.root / "G2"
        self.places = g2.Places(self.g2_dir, diagnostics=self.root / "diag")
        self.places.records.mkdir(parents=True, exist_ok=True)
        self.blocks, self.number = {}, 0

    def block(self, vm):
        if vm not in self.blocks:
            self.blocks[vm] = g2.Block(REAL, self.root / "balicek.json", vm, other_vm="g2", places=self.places,
                                       lab=Lab(), command=f"python -m skuska.g2 block --vm {vm}")
        return self.blocks[vm]

    def session(self, vm, deck_id, *, kind="deck", items=(), item=None, scenario="corp_high", records=None,
                journal=(), nginx_errors=(), requests=None, audit=True, accepted=True, counted=True, excluded=None,
                protocol_bytes=None, commit="c" * 40, manifest=None, lab=None, commit_dirty=False, grid=GRID,
                loops=True, start=None):
        """One recorded session; `items` its planned events, `records` (index -> record) its records of events.json
        instead of the faithful ones, `journal` more (t, text) lines or a function of the measure start that gives
        them, `loops` whether its occurrences of zla_konfiguracia_sluzby leave their restart loop in the journal."""
        self.number += 1
        start = T0 + self.number * SPAN if start is None else start
        sid = f"g2-{vm}-{deck_id}-1"
        d = self.places.diagnostics / vm / sid
        (d / "guest").mkdir(parents=True)
        (d / "protocol.json").write_bytes(protocol_bytes if protocol_bytes is not None else self.protocol.read_bytes())
        items = [dict(x) for x in items]
        identity = {"kernel": "6.1.0-42-cloud-amd64", "boot_id": f"boot-{vm}-{self.number}", "machine_id": "m" * 32,
                    "stack_sha256": "s" * 64, "stack_manifest": manifest if manifest is not None
                    else [*PACKAGES, TIMERS]}
        meta = {"schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": g2.CAMPAIGN_ID,
                "vm": vm, "domain": f"hyptcn-lab-{vm}", "role": "diagnostic", "group": f"g2-{vm}-b-1",
                "scenario": scenario, "typ": "benign", "seed": 7, "cycles": 720, "guest_before": identity,
                "events": items, "event_grace_s": P["events"]["grace_s"], "protocol_sha256": sha(d / "protocol.json"),
                "lab_sha256": collection.lab_sha256() if lab is None else lab, "commit": commit,
                "commit_dirty": commit_dirty, "created_unix": start - 200}
        (d / "session.json").write_text(json.dumps(meta, indent=1))
        (d / "end.json").write_text(json.dumps({"schema": "hyptcn3/collection-end/2", "completed": True,
                                                "interrupted": False, "measure_start_unix": start,
                                                "measure_end_unix": start + 3600}))
        made = [record_of(x, start) for x in items]
        for index, record in (records or {}).items():
            made[index] = record
        if items:
            (d / "events.json").write_text(json.dumps({"schema": campaign_report.G2_SESSION_EVENTS, "events": made}))
        rows = list(journal(start) if callable(journal) else journal)
        for x in made:
            if (isinstance(x, dict) and x.get("type") == campaign_report.RESTART_TYPE and loops
                    and "host_start_unix" in x):
                rows += loop_lines(x["host_start_unix"], x["host_stop_unix"])
        text = "".join(f"{stamp(t)} hyptcn-lab-{vm} {line}\n" for t, line in sorted(rows, key=lambda r: r[0]))
        entry = gz_entry(d / "guest", f"{sid}-journal-journal.txt", text)
        (d / "guest" / "journal_segment.json").write_text(json.dumps({
            "schema": campaign_report.G2_JOURNAL_SEGMENT, "label": f"{sid}-journal", "files": [entry]}))
        errors = "".join(f"{datetime.fromtimestamp(t, timezone.utc).strftime('%Y/%m/%d %H:%M:%S')} [error] 7#7: "
                         f"{line}\n" for t, line in nginx_errors)
        (d / "guest" / "session_segment.json").write_text(json.dumps({
            "schema": campaign_report.G2_LOG_SEGMENT, "label": sid,
            "files": [gz_entry(d / "guest", f"{sid}-nginx-access.jsonl", ""),
                      gz_entry(d / "guest", f"{sid}-nginx-error.log", errors)]}))
        lines = [{"type": "header", "schema": "hyptcn3/traffic-requests/2", "session_id": sid}]
        lines += requests if requests is not None else [
            {"type": "request", "rid": f"r{k}", "method": "GET", "route": "/api/catalog", "outcome": "ok",
             "status": 200, "intended_status": None, "t_start_utc": iso(start + 30 * k),
             "t_end_utc": iso(start + 30 * k + 0.05)} for k in range(120)]
        (d / "traffic_requests.jsonl").write_text("".join(json.dumps(row) + "\n" for row in lines))
        audit_entry = None
        if audit:
            report = d / "audit_20261126T200000000000Z.json"
            report.write_text(json.dumps({"schema": campaign_report.AUDIT_SCHEMA, "values": {
                "accepted": accepted, "reasons": [] if accepted else ["logs: synthetic"], "session_dir": str(d),
                "session_sha256": sha(d / "session.json"), "protocol_sha256": sha(d / "protocol.json"),
                "timing": {"grid_phase_s": grid}}}))
            audit_entry = {"report": str(report), "sha256": sha(report), "accepted": accepted,
                           "reasons": [] if accepted else ["logs: synthetic"]}
        spec = {"kind": kind, "id": deck_id, "deck": item, "scenario": scenario, "seed": 7,
                "events": json.dumps(items) if items else None, "attempt": 1, "session_id": sid,
                "excluded": excluded, "draw": None}
        summary = {"counted": counted, "reasons": [] if counted else ["heavy: C4 (tcn.suchy_beh): python -m "
                                                                      "tcn.suchy_beh"]}
        steps = [{"step": "run", "command": ["collection.py"], "exit_code": 0}]
        archived = {"step": "archive", "destination": str(self.g2_dir / "session" / vm / sid)} if audit else None
        self.block(vm).record(spec, {"name": f"g2-{vm}-b-1", "record": "group.json", "sha256": "0" * 64}, steps, [],
                              None, audit_entry, archived, summary, None, None,
                              {"session": d, "load": self.g2_dir / "zataz" / f"{sid}.jsonl"})
        return d, start

    def kill_session(self, vm, plan_id, *, induced=True, journal=None, counted=True):
        """A session of the fault plan with the killed service (skuska/poruchy.py zabita_sluzba) and the injector's
        record of it: the kill KILL_AT_S after the measure start, its restart in the journal unless `journal`."""
        start = T0 + (self.number + 1) * SPAN
        kill = start + KILL_AT_S
        rows = kill_lines(kill) if journal is None else journal(kill)
        d, _ = self.session(vm, plan_id, kind=poruchy.KIND_FAULT, item={"id": plan_id, "fault": "zabita_sluzba"},
                            journal=rows, start=start, counted=counted)
        injector = poruchy.Injector("zabita_sluzba", {"vm": vm, "domain": f"hyptcn-lab-{vm}"}, d, [], 1, 600, None)
        injector.induced, injector.window = induced, [kill - 2.0, kill]
        injector.why_not = None if induced else "the state of hyptcn-lab@docs before the kill cannot be read"
        injector.actions = [{"t": iso(kill - 0.5), "unix": kill - 0.5, "what": "labctl exec",
                             "guest_command": poruchy.KILL_COMMAND.format(unit="hyptcn-lab@docs")},
                            {"t": iso(kill), "unix": kill, "what": "labctl exec done", "rc": 0}] if induced else []
        spec = {"kind": poruchy.KIND_FAULT, "session_id": d.name, "deck": {"id": plan_id, "cycles": 600}}
        values = injector.values(spec, f"python -m skuska.poruchy block --vm {vm}", "idle")
        records = self.g2_dir / poruchy.BESIDE
        records.mkdir(parents=True, exist_ok=True)
        (records / f"{d.name}.json").write_text(json.dumps(g2.header(poruchy.FAULT_SCHEMA, "python -m skuska.poruchy "
                                                                                           "block", 2, values)))
        return d, kill

    def deck(self, change=None, skip=()):
        """The 38 sessions of the deck of the protocol (skuska/g2.py draw_deck), every event faithful; `change(item)`
        gives other options of session for a deck item, `skip` the deck ids left out."""
        dirs = []
        for item in g2.draw_deck(P)["sessions"]:
            if item["id"] in skip:
                continue
            options = (change(item) if change else None) or {}
            d, _ = self.session(item["vm"], item["id"], items=item["events"], item=item, scenario=item["scenario"],
                                **options)
            dirs.append(d)
        return dirs


def run(mode, dirs, recorder, out, *extra):
    """campaign_report.main of a mode over the directories; (exit code, the record or None)."""
    argv = [mode, *map(str, dirs), "--g2-dir", str(recorder.g2_dir), "--out", str(out), *extra]
    code = campaign_report.main(argv)
    return code, (json.loads(Path(out).read_text()) if Path(out).exists() else None)
