"""Fakes of the timing block (skuska/cas.py, package H1b4): a fake clock and a fake lab per VM whose runs write the
files of a session on that clock. No VM, no root, no process: every lab and root step is a fake, every file lies
under the test's tmp_path. Shared by skuska/tests/test_cas.py and scripts/tests/test_campaign_report_timing.py.
"""
import json
from pathlib import Path

from scripts import collection
from scripts.tests import protokol_g0
from skuska import cas, g2
from skuska.tests import test_g2

START = 1_790_000_000.0  # The fake clock's start (2026-09-21), far from every real time.
RATES = {"eshop_low": 11.4165, "eshop_high": 30.444, "corp_low": 6.2247, "corp_high": 16.5992}  # Zápis 1 of G2.
CODE = test_g2.CODE
COMMIT = test_g2.COMMIT


class FakeClock:
    """The driver's clock in a test: sleep moves the time on at once."""

    def __init__(self, t=START):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)

    def at_least(self, t):
        self.t = max(self.t, t)


def protocol_with_rates(directory):
    """config/collection-v5.json as the G0 record bound it, with the four rates of Zápis 1 (the timing block refuses
    a null rate high)."""
    doc = json.loads(protokol_g0.g0_bytes())
    for name, rate in RATES.items():
        doc["scenarios"][name]["rate"] = rate
    path = Path(directory) / "collection-v5.json"
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return path


class CasLab(test_g2.FakeLab):
    """The fake lab of one VM: a run writes session.json, protocol.json, end.json, events.json and raw/ with the
    sidecars of the full snapshots, its seq 0 `pre` seconds after the run's start on the fake clock (plus `offsets`,
    {session: seconds}), the target `late` seconds later than due (late, {session: seconds}); levels moves the clock to
    the end of the run (its last cycle and `post`); the audit writes values.timing and values.collector_majflt and
    takes `audit_s`, the archive `archive_s`. Its clock is `timer` (H1a's FakeLab keeps its own `clock`)."""

    def __init__(self, protocol_path, clock, vm, *, pre=150.0, offsets=None, late=None, full_ms=(2000.0, 2200.0),
                 timing=None, majflt=None, post=60.0, audit_s=900.0, archive_s=300.0, **options):
        super().__init__(protocol_path, **options)
        self.timer, self.vm, self.pre = clock, vm, pre
        self.offsets, self.late = dict(offsets or {}), dict(late or {})
        self.full_ms, self.post, self.audit_s, self.archive_s = full_ms, post, audit_s, archive_s
        self.timing, self.majflt = dict(timing or {}), dict(majflt or {})
        self.p = collection.for_vm(collection.protocol(protocol_path), vm)
        self.runs, self.commands, self.halts, self.unaudited = {}, [], [], []
        self.stop_check = lambda: None
        self.end = None

    def child(self, command, log, *, timeout, lock_fd=None):
        command = [str(x) for x in command]
        self.commands.append((command, timeout))
        if "levels" in command:
            if self.end is not None:
                self.timer.at_least(self.end)
            return super().child(command, log, timeout=timeout, lock_fd=lock_fd)
        if "audit" in command:
            rc = self.audit(command, log)
            self.timer.sleep(self.audit_s)
            return rc
        return self.run(command, log, timeout)

    def run(self, command, log, timeout):
        sid = command[command.index("--session-id") + 1]
        p, out = self.p, Path(command[command.index("--collections-dir") + 1]) / sid
        assert command[1].endswith("scripts/collection.py") and timeout == p["warmup_s"] + p["cycles"] * 5 + 300
        self.events.append(("run", sid, None))
        log.write_text(self.output.get(sid, f"session: {out}\n"))
        start = self.timer.now()
        due0 = start + self.pre + self.offsets.get(sid, 0.0)
        measure_start, measure_end = due0 - 1.0, due0 + p["cycles"] * p["interval_s"]
        (out / "raw").mkdir(parents=True)
        (out / "protocol.json").write_bytes(Path(command[command.index("--protocol") + 1]).read_bytes())
        (out / "session.json").write_text(json.dumps({
            "session_id": sid, "vm": self.vm, "domain": p["domain"], "campaign_id": g2.CAMPAIGN_ID, "commit": COMMIT,
            "guest_before": self.identity(), "measurement_sha256": {**CODE, "lab/x.py": "3" * 64},
            "collector_settings": {"interval_s": p["interval_s"], "full_every": p["full_every"]}}))
        for i, seq in enumerate(range(0, p["cycles"], p["full_every"])):
            late = 0.002 + (self.late.get(sid, 0.0) if seq else 0.0)
            (out / "raw" / f"{p['domain']}_{seq:06d}_20260921T000000000Z.json").write_text(json.dumps({
                "schema": cas.SIDECAR_SCHEMA, "seq": seq,
                "timestamp_unix": round(due0 + seq * p["interval_s"] + late, 3),
                "sched": {"lateness_s": late, "skipped_before": 0},
                "capture": {"total_ms": self.full_ms[min(i, len(self.full_ms) - 1)], "rusage": {"majflt": 0}},
                "output": {"full": True}}))
        events = []
        for x in cas.EVENTS:
            begin, stop = measure_start + x["start_s"], measure_start + x["start_s"] + x["duration_s"]
            events.append({**x, "host_start_unix": begin, "host_started_unix": begin + 2.0, "host_stop_unix": stop,
                           "host_stopped_unix": stop + 3.0, "start": {"ok": True}, "stop": {"ok": True,
                                                                                          "health": 200},
                           "executed": True})
        (out / "events.json").write_text(json.dumps({"schema": "hyptcn3/session-events/1", "events": events}))
        rc = self.rc.get(sid, 0)
        (out / "end.json").write_text(json.dumps({"measure_start_unix": measure_start, "measure_end_unix": measure_end,
                                                  "completed": rc == 0}))
        self.window = (measure_start, measure_end)
        self.runs[sid] = {"start": start, "due0": due0}
        self.end = measure_end + self.post
        try:
            self.stop_check()  # The run's guard (campaign.run_child calls it every 2 s).
        except InterruptedError:
            self.halts.append(sid)
            raise
        return rc

    def audit(self, command, log):
        out = Path(command[command.index("audit") + 1])
        report = Path(command[command.index("--out") + 1])
        self.events.append(("audit", out.name))
        assert command[command.index("--protocol") + 1] == str(out / "protocol.json")
        sid = out.name
        features = report.with_suffix(".npz")
        features.write_bytes(b"npz")
        timing = {"lateness_s_max": 0.004, "delta_ms_max": 900.0, "full_ms_max": max(self.full_ms),
                  **self.timing.get(sid, {}),
                  "grid_phase_s": round((self.runs[sid]["due0"] % 5), 6)}
        faults = self.majflt.get(sid, 0)
        report.write_text(json.dumps({"schema": "hyptcn3/collection-audit/1", "commit": COMMIT,
                                      "measurement_dirty": [], "values": {
                                          "accepted": self.accepted, "reasons": [] if self.accepted else ["x"],
                                          "session_dir": str(out), "session_sha256": test_g2.sha(out / "session.json"),
                                          "protocol_sha256": test_g2.sha(out / "protocol.json"),
                                          "features": str(features), "features_sha256": test_g2.sha(features),
                                          "auditor_sha256": {"scripts/collection.py": CODE["scripts/collection.py"]},
                                          "extractor_sha256": {"features/archive.py": CODE["features/archive.py"]},
                                          "timing": timing, "collector_majflt": {
                                              "max": faults, "max_seq": 360 if faults else 0, "sum": faults,
                                              "cycles": 720}}}))
        log.write_text("audit\n")
        return 0 if self.accepted else 2

    def archive(self, source, destination, guard, **options):
        result = super().archive(source, destination, guard, **options)
        if options.get("audit") is None:
            self.unaudited.append(Path(source).name)
        self.timer.sleep(self.archive_s)
        return result


def setup(tmp_path, *, only=None, labs=None, clock=None, **lab_options):
    """(the driver, its labs, its clock) of a timing block under tmp_path with fakes of both VMs; lab_options
    {vm: {...}} go to each VM's CasLab."""
    clock = clock or FakeClock()
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    protocol = protocol_with_rates(tmp_path)
    deck, plan = tmp_path / "balicek.json", tmp_path / "cas_plan.json"
    g2.write_deck(protocol, deck, "python -m skuska.g2 deck")
    cas.write_plan(protocol, plan, "python -m skuska.cas plan")
    labs = labs or {vm: CasLab(protocol, clock, vm, **lab_options.get(vm, {})) for vm in ("a", "b")}
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    driver = cas.Driver(protocol, deck, plan, only=only, places=places, labs=labs, clock=clock,
                        command="python -m skuska.cas block (test)", threads=False)
    return driver, labs, clock


def session_records(driver):
    return {p.stem: json.loads(p.read_text()) for p in sorted(driver.places.records.glob("g2-*-cas*.json"))}


def pair_records(driver):
    return {p.stem: json.loads(p.read_text()) for p in sorted(driver.dir.glob("cas*.json"))}
