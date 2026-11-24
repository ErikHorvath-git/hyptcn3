import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import campaign as c
from scripts import collection
from scripts.collection_archive import digest, read_json, write_new


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Fake capture/audit subprocesses; real orchestration, files, archiver and final index. The audit writes a real
    feature archive and the values of a real audit record (scripts/tests/kampan_v5.py audit_values) at the time of
    its capture (one clock, kampan_v5.Clock), and finish_corpus is the real one behind a spy that keeps this fixture's
    checks of its reports (harness row B9 "Hotové, keď": the final index is no longer faked; finding F2 of the
    verification of B9a)."""
    from scripts.tests.kampan_v5 import SMALL_GRID, Clock, audit_values
    directory = tmp_path / "test-campaign"
    directory.mkdir()
    for name in ("events", "groups", "attempts", "logs"):
        (directory / name).mkdir()
    captures = tmp_path / "collections"
    captures.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    p = collection.protocol(collection.DEFAULT)
    p["min_free_gib"] = 0  # Tiny synthetic files on pytest's possibly small tmpfs.
    p.update(SMALL_GRID)  # Real archives of 96 rows, not 720 (kampan_v5.SMALL_GRID).
    p["roles"] = dict.fromkeys(("train", "dev", "calibration", "test_benign"), 1)
    p["scenarios"] = {k: p["scenarios"][k] for k in ("quiet", "steady")}
    write_new(directory / "protocol.json", p)
    write_new(directory / "pilot.json", {"synthetic": True})
    rows = collection.plan(p)["sessions"]
    for i, row in enumerate(rows):
        row["session_id"] = f"test-campaign_{i:02d}"
    env = {"kernel": "test-kernel", "machine_id": "test-machine", "stack_sha256": "test-stack"}
    # The current extractor and profile: the production check of the real index compares both with the tree.
    profile, clock = c.tree_hashes(c.ROOT / p["profile"]), Clock()
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": directory.name,
                "workspace": str(c.ROOT), "commit": "test-commit", "sessions": rows,
                "owner": {"name": "test-owner"}, "extractor_sha256": c.extractor_hashes(),
                "guest_environment": env, "protocol_sha256": digest(directory / "protocol.json"),
                "pilot_report_sha256": digest(directory / "pilot.json"),
                "archive_dir": str(external), "archive_root": str(external), "archive_mount": {},
                "planned_capture_hours": len(rows)}
    write_new(directory / "campaign.json", manifest)
    state = {"directory": directory, "manifest": manifest, "p": p, "rows": rows,
             "captures": captures, "calls": [], "boot": "pilot-boot", "reboots": 0,
             "qemu": {"pid": 4242, "start_ticks": 1, "host_boot": "host-boot"},
             "capture_complete": True, "audit_accepted": True, "interrupt_audit": False,
             "truncate_audit": False, "preflight_failures": 0, "stop_during_capture": False,
             "audit_measurement_dirty": []}
    monkeypatch.setattr(c, "COLLECTIONS", captures)
    monkeypatch.setattr(c, "BASE", tmp_path)
    monkeypatch.setattr(c, "RETRY_PAUSE_S", 0)
    monkeypatch.setattr(collection, "qemu_process", lambda domain: state["qemu"])
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "test-owner")
    monkeypatch.setattr(collection, "user_command", lambda args: list(map(str, args)))
    monkeypatch.setattr(collection, "guest_identity", lambda p: {**env, "boot_id": state["boot"]})
    monkeypatch.setattr(c, "verify_frozen", lambda *a: None)
    monkeypatch.setattr(c, "capacity_guard", lambda *a: None)
    monkeypatch.setattr(c, "hold_sleep_inhibitor", lambda: None)  # Real one needs logind/polkit.
    monkeypatch.setattr(c, "sleep_inhibited", lambda: False)
    monkeypatch.setattr(c, "guard_mount", lambda *a: None)
    def child(command, log, **kw):
        command = list(map(str, command))
        log.write_text("Synthetic test subprocess\n")
        if "reboot" in command:
            state["reboots"] += 1
            state["boot"] = "boot-" + str(state["reboots"])
            state["calls"].append("reboot")
            return 0
        if "run" in command:
            state["calls"].append("capture")
            assert "--mode" not in command and "--attempt" not in command  # Schemas 1 and 2: collection.py run refuses both (package B9a); they are of schema 3.
            sid = command[command.index("--session-id") + 1]
            row = next(r for r in rows if r["session_id"] == sid.split("-r")[0])  # -r<n>: a replacement
            replaces = {"replaces": command[command.index("--replaces") + 1]} if "--replaces" in command else {}
            assert command[command.index("--expected-boot-id") + 1] == state["boot"]
            assert json.loads(command[command.index("--expected-qemu") + 1]) == state["qemu"]
            assert kw["lock_fd"] >= 0
            src = captures / sid
            src.mkdir()
            identity = {**env, "boot_id": state["boot"]}
            write_new(src / "session.json", {**row, "session_id": sid, **replaces,
                       "schema": "hyptcn3/collection-session/1",
                       "campaign_id": manifest["id"], "commit": manifest["commit"], "commit_dirty": True,
                       "measurement_dirty": [], "host_context": {"qemu": state["qemu"]},
                       "protocol_sha256": manifest["protocol_sha256"], "guest_before": identity,
                       "typ": "benign", "collector_sha256": "test-collector", "profile_sha256": profile})
            if state["stop_during_capture"]:
                c.request_stop(directory)
            if state["preflight_failures"]:
                state["preflight_failures"] -= 1
                write_new(src / "end.json", {"completed": False, "measurement_started": False,
                                             "error": "ValueError: preflight functional check failed"})
                return 2
            (src / "raw").mkdir()
            (src / "raw/frame.vmicd").write_bytes(b"synthetic RAM " + sid.encode())
            start, end = clock.take(p)
            write_new(src / "end.json", {"completed": state["capture_complete"], "guest_after": identity,
                                         "measurement_started": True, "measure_start_unix": start,
                                         "measure_end_unix": end})
            return 0 if state["capture_complete"] else 2
        assert "audit" in command
        state["calls"].append("audit")
        src = Path(command[command.index("audit") + 1])
        report = Path(command[command.index("--out") + 1])
        # The feature archive comes first, so an interrupted or truncated audit leaves it, as the extractor does.
        values = audit_values(src, read_json(directory / "protocol.json"), directory / "protocol.json", report,
                              extractor=manifest["extractor_sha256"], accepted=state["audit_accepted"],
                              rejection=("timing:gap", "synthetic rejection"))
        if state["interrupt_audit"]:
            raise InterruptedError("interrupted extractor")
        if state["truncate_audit"]:
            report.write_text('{"schema":')
            return 2
        row = next(r for r in rows if r["session_id"] == src.name.split("-r")[0])
        assert values["role"] == row["role"]
        write_new(report, {"schema": "hyptcn3/collection-audit/1", "commit": manifest["commit"],
                  "commit_dirty": True, "measurement_dirty": state["audit_measurement_dirty"], "values": values})
        return 0 if state["audit_accepted"] else 2
    monkeypatch.setattr(c, "run_child", child)
    real_finish = c.finish_corpus
    def finish(directory, manifest, p, reports):  # The spy: its checks, then the real index.
        assert len(reports) == len(rows)
        assert len(set(reports)) == len(rows)
        return real_finish(directory, manifest, p, reports)
    monkeypatch.setattr(c, "finish_corpus", finish)
    monkeypatch.setattr(c, "process_identity", lambda pid: {"alive": pid} if pid == os.getpid() else None)
    return state


def test_whole_campaign_and_repeat_do_not_recapture(lab):
    assert c.execute(lab["directory"]) == 0
    assert lab["reboots"] == 4
    assert lab["calls"].count("capture") == lab["calls"].count("audit") == 8
    assert read_json(lab["directory"] / "status.json")["status"] == "complete"
    for row in lab["rows"]:
        assert (lab["captures"] / row["session_id"] / "raw").is_symlink()
    calls = list(lab["calls"])
    c.execute(lab["directory"])
    assert lab["calls"] == calls


def test_boundary_resume_keeps_group_boot(lab):
    c.execute(lab["directory"], stop_after=1)
    assert lab["reboots"] == 1
    first_boot = lab["boot"]
    c.execute(lab["directory"], stop_after=1)
    assert lab["reboots"] == 1 and lab["boot"] == first_boot
    assert lab["calls"].count("capture") == 2


def test_reboot_inside_group_stops_before_next_capture(lab):
    c.execute(lab["directory"], stop_after=1)
    lab["boot"] = "unexpected-reboot"
    with pytest.raises(ValueError, match="boot changed inside"):
        c.execute(lab["directory"])
    assert lab["calls"].count("capture") == 1 and lab["reboots"] == 1


@pytest.mark.parametrize("failure", ["capture_complete", "audit_accepted"])
def test_failed_assignment_is_archived_but_never_replaced(lab, failure):
    lab[failure] = False
    for _ in range(2):
        with pytest.raises(ValueError, match="incomplete capture|audit rejected"):
            c.execute(lab["directory"])
    assert lab["calls"].count("capture") == 1
    assert lab["calls"].count("audit") == int(failure == "audit_accepted")
    first = lab["captures"] / lab["rows"][0]["session_id"]
    assert (first / "raw").is_symlink()
    assert not list((lab["directory"] / "attempts").glob("*.done.json"))


@pytest.mark.parametrize("failure", ["interrupt_audit", "truncate_audit"])
def test_interrupted_extraction_retries_without_recapturing(lab, failure):
    lab[failure] = True
    with pytest.raises((InterruptedError, json.JSONDecodeError)):
        c.execute(lab["directory"])
    assert not list((lab["directory"] / "attempts").glob("*.audit.json"))
    lab[failure] = False
    c.execute(lab["directory"], stop_after=1)
    assert lab["calls"].count("capture") == 1
    assert lab["calls"].count("audit") == 2
    first = lab["captures"] / lab["rows"][0]["session_id"]
    assert len(list(first.glob("campaign_audit_*.npz"))) == 2


def test_second_runner_cannot_overwrite_active_status(lab):
    c.update_state(lab["directory"], status="running", stage="capture", message="first runner")
    before = (lab["directory"] / "status.json").read_bytes()
    with collection.collection_lock(lab["captures"]):
        with pytest.raises(BlockingIOError):
            c.execute(lab["directory"])
    assert (lab["directory"] / "status.json").read_bytes() == before
    assert not lab["calls"]


def test_frozen_plan_tampering_is_rejected(lab):
    path = lab["directory"] / "campaign.json"
    doc = read_json(path)
    doc["sessions"][0]["seed"] += 1
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="plan or frozen"):
        c.load_campaign(lab["directory"])


@pytest.mark.parametrize("changed", ["commit", "dirty", "runtime", "profile", "extractor"])
def test_frozen_environment_drift_stops_before_next_capture(tmp_path, monkeypatch, changed):
    monkeypatch.setattr(c, "git", lambda *args: (
        "other-commit" if changed == "commit" else "frozen") if args[0] == "rev-parse"
        else (" M scripts/collection.py" if changed == "dirty" else ""))
    monkeypatch.setattr(c, "runtime_identity", lambda: {"version": "new" if changed == "runtime" else "old"})
    monkeypatch.setattr(c, "tree_hashes", lambda _: {"hash": "new" if changed == "profile" else "old"})
    monkeypatch.setattr(c, "extractor_hashes", lambda: {"hash": "new" if changed == "extractor" else "old"})
    manifest = {"commit": "frozen", "runtime": {"version": "old"},
                "profile_sha256": {"hash": "old"}, "extractor_sha256": {"hash": "old"}}
    with pytest.raises(ValueError, match="source changed|runtime, profile or extractor changed"):
        c.verify_frozen(tmp_path, manifest, {"profile": "unused"})


def test_collection_lock_is_inherited_only_by_authorized_child(tmp_path):
    code = ("import pathlib,sys; from scripts.collection import collection_lock; "
            "lock=collection_lock(pathlib.Path(sys.argv[1])); lock.__enter__(); print('acquired')")
    with collection.collection_lock(tmp_path) as fd:
        env = dict(os.environ, HYPTCN_COLLECTION_LOCK_FD=str(fd))
        inherited = subprocess.run([sys.executable, "-c", code, str(tmp_path)], env=env, pass_fds=(fd,),
                                   capture_output=True, text=True)
        assert inherited.returncode == 0 and "acquired" in inherited.stdout
        independent = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
                                     capture_output=True, text=True)
        assert independent.returncode != 0 and "BlockingIOError" in independent.stderr


def test_lab_reboot_waits_for_changed_boot_before_health(monkeypatch):
    from scripts.labctl import Lab
    lab = Lab()
    ids = iter(["old", "old", "new"])
    calls = []
    monkeypatch.setattr(lab, "owned", lambda: calls.append("owned"))
    monkeypatch.setattr(lab, "guest", lambda *a, **k: next(ids))
    monkeypatch.setattr(lab, "virsh", lambda *args: calls.append(args))
    monkeypatch.setattr(lab, "health", lambda: calls.append("healthy"))
    monkeypatch.setattr("scripts.labctl.time.sleep", lambda _: None)
    lab.reboot()
    assert calls == ["owned", ("reboot", "hyptcn-lab", "--mode", "agent"), "healthy"]


def test_lab_reboot_cannot_accept_unchanged_boot(monkeypatch):
    from scripts.labctl import Lab
    lab = Lab()
    monkeypatch.setattr(lab, "owned", lambda: None)
    monkeypatch.setattr(lab, "guest", lambda *a, **k: "old")
    monkeypatch.setattr(lab, "virsh", lambda *args: None)
    monkeypatch.setattr(lab, "health", lambda: pytest.fail("old boot must not be accepted"))
    with pytest.raises(TimeoutError, match="new boot"):
        lab.reboot(timeout=0)


def test_interrupted_run_records_stopped_state_and_signals(lab):
    def interrupt(command, log, **kw):
        raise InterruptedError("interrupted by signal 15")
    c.run_child = interrupt
    with pytest.raises(InterruptedError):
        c.execute(lab["directory"])
    state = read_json(lab["directory"] / "status.json")
    assert state["status"] == "stopped" and state["stage"] == "interrupted"
    assert "signal 15" in state["message"]


def test_stale_running_status_is_recorded_as_unclean_end(lab):
    write_new(lab["directory"] / "status.json", {"status": "running", "stage": "capture",
                                                 "pid": 999999, "process_identity": {"x": 1}}, replace=True)
    shown = c.status(lab["directory"])
    assert shown["running"] is False and shown["stale"] is True
    c.execute(lab["directory"], stop_after=1)
    events = [read_json(e) for e in sorted((lab["directory"] / "events").glob("*.json"))]
    assert any(e.get("stage") == "unclean-end" for e in events)


def test_run_child_lets_the_child_finish_cleanup_on_interrupt(tmp_path):
    marker = tmp_path / "end.json"
    child = tmp_path / "child.py"
    child.write_text(
        "import signal, sys, time, pathlib\n"
        "count = []\n"
        "def stop(signum, frame):\n"
        "    count.append(signum)\n"
        "    if len(count) == 1:\n"
        "        time.sleep(1)  # cleanup that must not be cut short\n"
        "        pathlib.Path(sys.argv[1]).write_text(str(len(count)))\n"
        "        sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "while True:\n"
        "    time.sleep(.1)\n")
    started = []
    def guard():
        started.append(1)
        if len(started) > 1:
            raise InterruptedError("operator stop")
    with pytest.raises(InterruptedError):
        c.run_child([sys.executable, child, marker], tmp_path / "child.log", timeout=60, guard=guard, grace=20)
    assert marker.read_text() == "1"  # exactly one SIGTERM, cleanup completed


@pytest.mark.skipif(not shutil.which("zstd"), reason="zstd CLI unavailable")
def test_archive_estimate_measures_codec_on_pilot_images(tmp_path):
    session = tmp_path / "pilot"
    (session / "raw").mkdir(parents=True)
    (session / "raw/a.vmicd").write_bytes(bytes(1 << 20))  # highly compressible
    (session / "raw/b.vmicd").write_bytes(os.urandom(1 << 20))  # incompressible
    (session / "features.npz").write_bytes(b"x" * 1000)
    p = {"cycles": 720, "pilot_cycles": 480}
    plain = c.archive_estimate(session, p, None)
    packed = c.archive_estimate(session, p, "zstd")
    assert plain["raw_ratio"] == 1 and plain["pilot_other_bytes"] == 1000
    assert .45 < packed["raw_ratio"] < .55
    assert packed["bytes_per_session"] == pytest.approx(
        (packed["pilot_raw_stored_bytes"] + 1000) * 720 / 480 * 1.5)


def test_pilot_measurement_provenance_must_match_current_code(monkeypatch):
    current = {"scripts/collection.py": "a", "lab/services.py": "b"}
    monkeypatch.setattr(collection, "measurement_sources", lambda: dict(current))
    assert c.measurement_changes({"measurement_sha256": dict(current)}) == []
    assert c.measurement_changes({"measurement_sha256": {**current, "lab/services.py": "old"}}) == ["lab/services.py"]
    assert c.measurement_changes({"measurement_sha256": {"scripts/collection.py": "a"}}) == ["lab/services.py"]
    assert c.measurement_changes({}) == ["<pilot predates measurement provenance>"]


def test_attempt_that_never_measured_is_kept_and_retried_in_the_same_boot(lab):
    lab["preflight_failures"] = 1
    assert c.execute(lab["directory"], stop_after=1) == 0
    sid = lab["rows"][0]["session_id"]
    retired = lab["captures"] / (sid + ".attempt-1")
    assert read_json(retired / "end.json")["measurement_started"] is False
    record = read_json(lab["directory"] / "attempts" / (sid + ".attempt-1.json"))
    assert record["directory"] == str(retired) and "preflight" in record["reason"]
    assert lab["calls"] == ["reboot", "capture", "capture", "audit"]
    assert (lab["captures"] / sid / "raw").is_symlink()  # The retry was captured and archived.


def test_retries_are_bounded_per_run_and_resume_after_review(lab):
    lab["preflight_failures"] = c.MAX_ATTEMPTS
    with pytest.raises(ValueError, match="ended before measurement"):
        c.execute(lab["directory"])
    sid = lab["rows"][0]["session_id"]
    assert lab["calls"].count("capture") == c.MAX_ATTEMPTS
    assert sorted(p.name for p in lab["captures"].glob(sid + "*")) == [
        sid, *(f"{sid}.attempt-{n}" for n in range(1, c.MAX_ATTEMPTS))]
    assert read_json(lab["directory"] / "status.json")["stage"] == "error"
    # After the operator has removed the cause, a new run retires the last attempt first.
    assert c.execute(lab["directory"], stop_after=1) == 0
    assert (lab["captures"] / f"{sid}.attempt-{c.MAX_ATTEMPTS}").is_dir()
    assert lab["reboots"] == 1


def test_measured_attempt_is_never_retried(lab):
    lab["capture_complete"] = False
    with pytest.raises(ValueError, match="incomplete capture"):
        c.execute(lab["directory"])
    assert not list(lab["captures"].glob("*.attempt-*"))
    assert not list((lab["directory"] / "attempts").glob("*.attempt-*.json"))


def test_stop_request_ends_the_run_at_the_next_session_boundary(lab):
    lab["stop_during_capture"] = True
    assert c.execute(lab["directory"]) == 0
    state = read_json(lab["directory"] / "status.json")
    assert (state["status"], state["stage"], state["message"]) == ("stopped", "between-sessions", "operator stop request")
    assert lab["calls"] == ["reboot", "capture", "audit"]  # The current session finished and was archived.
    assert not (lab["directory"] / "stop-request.json").exists()
    assert len(list((lab["directory"] / "events").glob("*_stop-request.json"))) == 1
    lab["stop_during_capture"] = False
    c.execute(lab["directory"], stop_after=1)
    assert lab["calls"].count("capture") == 2 and lab["reboots"] == 1


def test_stale_stop_request_does_not_stop_a_new_run(lab):
    write_new(lab["directory"] / "stop-request.json", {"left": "by a crashed run"})
    c.execute(lab["directory"], stop_after=1)
    assert lab["calls"].count("capture") == 1
    assert len(list((lab["directory"] / "events").glob("*_stop-request-stale.json"))) == 1


def test_stop_request_needs_a_running_campaign(lab):
    c.update_state(lab["directory"], status="stopped", stage="error")
    with pytest.raises(ValueError, match="not running"):
        c.request_stop(lab["directory"])
    assert not (lab["directory"] / "stop-request.json").exists()


def test_closed_campaign_cannot_run_and_releases_its_groups(lab):
    c.execute(lab["directory"], stop_after=1)
    group = lab["rows"][0]["group"]
    assert not c.closed_campaign(lab["manifest"]["id"])
    c.close(lab["directory"], "first session showed a lab defect; superseded by a new campaign")
    record = read_json(lab["directory"] / "closed.json")
    assert record["status_before"]["stage"] == "between-sessions"
    assert read_json(Path(lab["manifest"]["archive_dir"]) / "closed.json") == record
    assert read_json(lab["directory"] / "status.json")["status"] == "closed"
    assert c.closed_campaign(lab["manifest"]["id"]) and not c.closed_campaign("../" + lab["manifest"]["id"])
    assert read_json(lab["captures"] / lab["rows"][0]["session_id"] / "session.json")["group"] == group
    with pytest.raises(ValueError, match="closed"):
        c.execute(lab["directory"])
    with pytest.raises(ValueError, match="already closed"):
        c.close(lab["directory"], "again")
    assert lab["calls"].count("capture") == 1


def test_vm_restore_inside_a_group_stops_before_next_capture(lab):
    c.execute(lab["directory"], stop_after=1)
    lab["qemu"] = {**lab["qemu"], "pid": 4343, "start_ticks": 2}  # Same guest boot, new QEMU process.
    with pytest.raises(ValueError, match="VM process changed inside a group"):
        c.execute(lab["directory"])
    assert lab["calls"].count("capture") == 1


def test_audit_from_changed_measurement_code_is_ignored_and_redone(lab):
    lab["audit_measurement_dirty"] = ["scripts/collection.py"]
    with pytest.raises(ValueError, match="audit provenance"):
        c.execute(lab["directory"])
    sid = lab["rows"][0]["session_id"]
    assert not (lab["directory"] / "attempts" / (sid + ".audit.json")).exists()
    lab["audit_measurement_dirty"] = []
    c.execute(lab["directory"], stop_after=1)
    reports = sorted((lab["captures"] / sid).glob("campaign_audit_*.json"))
    assert len(reports) == 2 and lab["calls"].count("audit") == 2
    selected = read_json(lab["directory"] / "attempts" / (sid + ".audit.json"))
    assert selected["path"] == str(reports[1])
    events = [read_json(e).get("message") or "" for e in (lab["directory"] / "events").glob("*.json")]
    assert any(m.startswith("ignored audit made from a changed source tree") for m in events)


def test_ended_before_measurement_needs_proof_of_no_ram(tmp_path):
    session = tmp_path / "s"
    assert not c.ended_before_measurement(session)  # Missing directory.
    session.mkdir()
    assert c.ended_before_measurement(session)  # Failed before its metadata existed.
    write_new(session / "session.json", {})
    assert not c.ended_before_measurement(session)  # No truthful end record (e.g. SIGKILL).
    write_new(session / "end.json", {"measurement_started": False})
    assert c.ended_before_measurement(session)
    (session / "raw").mkdir()
    assert not c.ended_before_measurement(session)  # Contradiction: keep it for review.


def event_audit(tmp_path, name, p, role="test_events", group="v3-test_events-1", boot="b1", accepted=True):
    from features.acceptance import decide
    session = tmp_path / name
    session.mkdir()
    (session / "events.json").write_text('{"events": []}\n')
    (session / "f.npz").write_bytes(name.encode())
    meta = {"schema": "hyptcn3/collection-session/2", "session_id": name, "role": role, "group": group,
            "scenario": "quiet", "seed": 1, "guest_before": {"boot_id": boot}, "collector_sha256": "c"}
    write_new(session / "session.json", meta)
    logs = {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True, "problems": [],
            "sections": {"metadata": {"session_sha256": digest(session / "session.json")}}}
    values = {"accepted": accepted, "protocol_sha256": "p", "session_dir": str(session),
              "session_sha256": digest(session / "session.json"), "features": str(session / "f.npz"),
              "features_sha256": digest(session / "f.npz"), "logs": logs, "extractor_sha256": {}}
    facts = {"snapshots": 2, "sequence_contiguous": True, "invalid_rows": [], "integrity_findings": 0, "windows": 1,
             # Two rows one interval apart (features.acceptance reads the grid since package B3).
             "rule_closed_seq": [], "smallest_gap_s": p["interval_s"], "largest_gap_s": p["interval_s"],
             "span_s": p["interval_s"]}
    verdict = decide(p, role, facts)
    values.update(reasons=[], role=role, snapshots=verdict["snapshots"], windows=verdict["windows"],
                  score_coverage=verdict["score_coverage"],
                  quality={"tolerated_invalid_seq": verdict["tolerated_invalid_seq"]}, acceptance=verdict)
    write_new(session / "audit.json", {"values": values})
    return session / "audit.json"


def test_test_only_protocol_gets_an_event_index_not_a_corpus(tmp_path, monkeypatch):
    import features.acceptance
    import features.archive
    # Imported before the stand-in below: event_index imports features.dataset, whose `from .archive import load`
    # would otherwise keep the stand-in for every later test of the process (scripts/tests/test_multivm.py builds a
    # corpus with it).
    import features.dataset  # noqa: F401
    monkeypatch.setattr(features.archive, "load", lambda path: {"casy": [10.0, 15.0]})
    # Package B7c: event_index decides from the archive (require_accepted); the archive here is a stand-in, so the
    # decision stays the one from the record this test builds (require_recorded, which require_accepted also ends
    # with). scripts/tests/test_event_index.py decides real archives.
    monkeypatch.setattr(features.acceptance, "require_accepted",
                        lambda data, p, session, role, values, recorded_rows=None:
                        features.acceptance.require_recorded(p, role, values, recorded_rows))
    p = {"schema": "hyptcn3/collection-protocol/2", "quality_policy": "behavioral-inputs-v1", "cycles": 2,
         "min_score_coverage": 0.5, "roles": {"test_events": 1}, "scenarios": {"quiet": {}, "steady": {}},
         "interval_s": 5, "max_gap_s": 7.5}
    reports = [event_audit(tmp_path, "s1", p), event_audit(tmp_path, "s2", p)]
    doc = c.event_index(reports, p, "p")
    assert doc["complete"] and [r["id"] for r in doc["sessions"]] == ["s1", "s2"]
    assert doc["sessions"][0]["start"] == 10.0 and doc["sessions"][0]["events_sha256"]
    assert not c.event_index(reports[:1], p, "p")["complete"]
    with pytest.raises(ValueError, match="boot/group"):
        c.event_index([*reports, event_audit(tmp_path, "s3", p, boot="b2")], p, "p")
    with pytest.raises(ValueError, match="unaccepted"):
        c.event_index([event_audit(tmp_path, "s4", p, accepted=False)], p, "p")


def test_single_vm_campaign_replaces_a_rejected_session_only_under_a_protocol_rule(lab):
    """Without the rule (every older protocol) a rejection stops the campaign: test above. With it:"""
    directory = lab["directory"]
    protocol = read_json(directory / "protocol.json")
    protocol["replacement"] = {"max_per_campaign": 1, "same": ["vm", "role", "scenario"]}
    (directory / "protocol.json").write_text(json.dumps(protocol))
    manifest = read_json(directory / "campaign.json")
    manifest["protocol_sha256"] = lab["manifest"]["protocol_sha256"] = digest(directory / "protocol.json")
    (directory / "campaign.json").write_text(json.dumps(manifest))
    lab["audit_accepted"] = False  # The first session and then its replacement are rejected.
    first = lab["rows"][0]["session_id"]
    for _ in range(2):
        with pytest.raises(ValueError, match="audit rejected session; archived without replacement"):
            c.execute(directory)
    assert lab["calls"] == ["reboot", "capture", "audit", "capture", "audit"]  # One boot, one replacement.
    records = c.rejections(directory)
    assert [(r["session"], r["replacement"]) for r in records] == [(first, first + "-r1"), (first + "-r1", None)]
    assert all(r["reasons"] == ["synthetic rejection"] for r in records)
    replacement = read_json(lab["captures"] / (first + "-r1") / "session.json")
    assert replacement["replaces"] == first and replacement["group"] == lab["rows"][0]["group"]
    assert (lab["captures"] / first / "raw").is_symlink() and (lab["captures"] / (first + "-r1") / "raw").is_symlink()
    assert not list((directory / "attempts").glob("*.done.json"))
    assert [r["session"] for r in c.status(directory)["rejections"]] == [first, first + "-r1"]


def test_dangling_raw_link_is_not_an_attempt_without_measurement(tmp_path):
    from scripts import campaign
    session = tmp_path / "s"
    session.mkdir()
    (session / "raw").symlink_to(tmp_path / "archive-gone" / "raw", target_is_directory=True)
    (session / "end.json").write_text('{"measurement_started": false}')
    (session / "session.json").write_text("{}")
    assert not campaign.ended_before_measurement(session)


# ------------------------------------------------------------------ protocol v5 (package B9a, agent K)
# A campaign of protocol schema 3 on fakes of collection (design B9a 1.3): the real init, run, start of a group,
# rejection, archiver and the seal through the command line of tcn.pecat (run in this process, on the test's ledger:
# tcn.pecat.KNIHA and ZAZNAM under tmp_path); fake children for labctl, the capture (collection.py run as package B9a's
# command line has it, agent L) and the audit, which writes a real feature archive and the values of a real audit
# record (scripts/tests/kampan_v5.py audit_values); finish_corpus is the real one behind a spy, with the production
# check of training as the owner (finding F2 of the verification of B9a). A runaway loop of captures or of starts of a
# group fails by name (V5_RUNAWAY, finding F6). The names of package B9a are read inside the tests, so this file
# collects before it.

V5_ENV = {"kernel": "test-kernel", "stack_sha256": "test-stack"}
V5_RUNTIME = {"vm_swappiness": 1, "collector_sha256": "test-collector"}


def v5_protocol(path, *, limit=0, **changes):
    """A protocol of schema 3 and of the v5 shape (features/tests/test_dataset_plan.py protocol_doc: two VMs, the five
    roles with two groups each, the test roles interleaved, 96 rows a session; a rehearsal of one group per role);
    nothing reserved on the test's disk; replacement.max_per_campaign `limit`."""
    from features.tests.test_dataset_plan import protocol_doc
    profile = path.parent / "profile"
    profile.mkdir(exist_ok=True)
    (profile / "symbols.txt").write_text("synthetic profile\n")
    doc = protocol_doc(profile)
    doc.update({"min_free_gib": 0, "replacement": dict(doc["replacement"], max_per_campaign=limit), **changes})
    path.write_text(json.dumps(doc))
    return path


# The cgroup of the QEMU the fake labctl start reports, in the shape of scripts/labctl.py's qemu_swap record (agent L).
V5_CGROUP = "/user.slice/user-1000.slice/user@1000.service/app.slice/hyptcn-libvirtd.service"
# Finding F6 of the verification of B9a: a campaign captures at most V5_RUNAWAY sessions beyond its plan's, and a VM is
# stopped at most V5_RUNAWAY times beyond the groups planned on it, else the fixture fails by name instead of looping
# (judgment of the test: a test here captures at most 2 sessions beyond a plan and starts every group once).
V5_RUNAWAY = 6


@pytest.fixture
def v5(tmp_path, monkeypatch):
    from scripts import audit_selftest, gates, protocol_v5
    from scripts.tests.kampan_v5 import Clock, audit_values
    from tcn import pecat
    import pwd
    captures, results, source = tmp_path / "collections", tmp_path / "results", tmp_path / "source"
    for directory in (captures, results, source):
        directory.mkdir()
    protocol = v5_protocol(source / "protocol.json")
    domains = {"hyptcn-test-a": "a", "hyptcn-test-b": "b"}
    state = {"tmp": tmp_path, "protocol": protocol, "captures": captures, "calls": [], "stages": [], "selftests": [],
             "qemu": {vm: {"pid": 100 + i, "start_ticks": 1, "host_boot": "host-boot"} for i, vm in enumerate("ab")},
             "boot": {"a": "boot-a-0", "b": "boot-b-0"}, "pid": 200, "fail": None, "same_qemu": False,
             "way": ("unit", False),
             "reject": set(), "corrupt": {}, "finished": [], "ledger": results / "kniha_pecati.json",
             "free": {"working": 10**15, "archive": 10**15}, "clock": Clock(), "captured": {}}
    owner = pwd.getpwuid(os.getuid()).pw_name
    for name in ("RETRY_PAUSE_S", "WAIT_POLL_S", "START_GRACE_S"):
        monkeypatch.setattr(c, name, 0)
    monkeypatch.setattr(c, "COLLECTIONS", captures)
    monkeypatch.setattr(c, "BASE", tmp_path / "campaigns")
    monkeypatch.setattr(pecat, "KNIHA", state["ledger"])
    monkeypatch.setattr(pecat, "ZAZNAM", state["ledger"])
    monkeypatch.setattr(gates, "require", lambda results, path, stage: state["stages"].append((Path(path).name, stage)))
    monkeypatch.setattr(audit_selftest, "require_selftest",
                        lambda path, directory=None: state["selftests"].append(Path(path).name))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", owner)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("HYPTCN_COLLECTION_LOCK_FD", raising=False)
    monkeypatch.setattr(collection, "user_command", lambda args: ["as-owner", *map(str, args)])
    monkeypatch.setattr(collection, "guest_identity",
                        lambda p: {**V5_ENV, "machine_id": "machine-" + p["vm"], "boot_id": state["boot"][p["vm"]]})
    monkeypatch.setattr(collection, "qemu_process", lambda domain: state["qemu"][domains[domain]])
    monkeypatch.setattr(collection, "storage_identity", lambda path: {"target": "/test", "fstype": "test"})
    monkeypatch.setattr(c, "git", lambda *args: "" if args[0] == "status" else "test-commit")
    monkeypatch.setattr(c, "runtime_identity", lambda: dict(V5_RUNTIME))
    monkeypatch.setattr(c, "mount_identity", lambda *a, **kw: {})
    monkeypatch.setattr(c, "guard_mount", lambda *a: None)
    monkeypatch.setattr(c, "verify_frozen", lambda *a: None)
    monkeypatch.setattr(c, "hold_sleep_inhibitor", lambda: None)
    monkeypatch.setattr(c, "sleep_inhibited", lambda: False)
    monkeypatch.setattr(c, "process_identity", lambda pid: {"alive": pid} if pid == os.getpid() else None)
    monkeypatch.setattr(c.shutil, "disk_usage", lambda path: SimpleNamespace(
        free=state["free"]["working" if Path(path) == captures else "archive"]))

    def lab(command, log, vm):
        verb = command[command.index(str(c.ROOT / "scripts/labctl.py")) + 1]
        if verb == "stop":  # V5_RUNAWAY: every group of every campaign of the test starts once, and a few more.
            groups = sum(len({r["group"] for r in read_json(path)["sessions"] if r.get("vm") == vm})
                         for path in c.BASE.glob("*/campaign.json"))
            stopped = sum(call == ("lab", vm, "stop") for call in state["calls"])
            if stopped >= groups + V5_RUNAWAY:
                pytest.fail(f"runaway starts of VM {vm}: {stopped} stops for {groups} planned groups and "
                            f"V5_RUNAWAY {V5_RUNAWAY}")
        state["calls"].append(("lab", vm, verb))
        if state["fail"] == verb:
            log.write_text(f"labctl: synthetic failure of {verb}\n")
            return 1
        printed, domain = [], "hyptcn-test-" + vm  # The shapes of scripts/labctl.py's records (agent L).
        if verb == "stop":
            running = state["qemu"][vm] is not None
            printed.append({"stop": {"domain": domain, "state_before": "running" if running else "shut off",
                                     "qemu_pid_before": state["qemu"][vm]["pid"] if running else None,
                                     "state": "shut off", "seconds": 0.0}})
            if not state["same_qemu"]:
                state["qemu"][vm] = None
        elif verb == "start":
            if not state["same_qemu"]:
                state["pid"] += 1
                state["qemu"][vm] = {"pid": state["pid"], "start_ticks": 1, "host_boot": "host-boot"}
                state["boot"][vm] = f"boot-{vm}-{state['pid']}"
                printed.append({"libvirtd": {"unit": "hyptcn-libvirtd.service", "found": "unit", "qemu_way": "unit"}})
            way, temporary = state["way"]
            printed.append({"qemu_swap": {"domain": domain, "qemu_pid": state["qemu"][vm]["pid"], "cgroup": V5_CGROUP,
                                          "memory_swap_max": "0", "vm_swap_kb": 0, "way": way, "temporary": temporary}})
        elif verb == "reset":
            printed.append({"schema": "hyptcn3/guest-reset/1", "seed": int(command[command.index("--seed") + 1])})
        elif verb == "pretouch":
            printed.append({"schema": "hyptcn3/guest-pretouch/1", "touched": True})
        else:
            pytest.fail("a group of protocol schema 3 starts without " + verb)
        log.write_text("".join(json.dumps(value) + "\n" for value in printed))
        return 0

    def capture(command, log):
        arg = lambda name: command[command.index(name) + 1] if name in command else None
        assert "--pilot-report" not in command  # PILOT_RULE
        role, group, scenario, vm, mode = (arg("--" + k) for k in ("role", "group", "scenario", "vm", "mode"))
        attempt, sid = int(arg("--attempt")), arg("--session-id")
        p = collection.protocol(Path(arg("--protocol")))
        # The row of the attempt as scripts/collection.py run finds it (agent L's contract): the plan of --mode, then
        # protocol_v5.replacement of the planned row for an attempt 2 or later.
        planned = next(s for s in protocol_v5.plan(p, mode=mode)["sessions"]
                       if (s["role"], s["group"], s["scenario"], s.get("vm")) == (role, group, scenario, vm))
        row = planned if attempt == 1 else protocol_v5.replacement(p, planned, attempt, mode=mode)
        assert int(arg("--seed")) == row["seed"]
        state["calls"].append(("capture", vm, sid, attempt, mode))
        manifest = read_json(Path(arg("--protocol")).parent / "campaign.json")
        state["captured"][manifest["id"]] = tries = state["captured"].get(manifest["id"], 0) + 1
        if tries > len(manifest["sessions"]) + V5_RUNAWAY:
            pytest.fail(f"runaway replacements: campaign {manifest['id']} captured {tries} sessions for a plan of "
                        f"{len(manifest['sessions'])} and V5_RUNAWAY {V5_RUNAWAY}")
        src = captures / manifest["id"] / vm / sid
        src.mkdir(parents=True)
        identity = {**V5_ENV, "machine_id": "machine-" + vm, "boot_id": state["boot"][vm]}
        assert arg("--expected-boot-id") == identity["boot_id"]
        meta = {"schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": manifest["id"], "vm": vm,
                **({"replaces": arg("--replaces")} if arg("--replaces") else {}), "role": role, "group": group,
                "attempt": attempt, "plan_mode": mode, "scenario": scenario, "seed": row["seed"],
                "cycles": p["cycles"], "guest_before": identity, "events": row.get("events", []),
                **({"controls": [x for x in row["controls"] if x.get("kind") is not None]} if "controls" in row
                   else {}),
                "protocol_sha256": manifest["protocol_sha256"], "commit": manifest["commit"],
                "measurement_dirty": [], "host_context": {"qemu": state["qemu"][vm]},
                # What the real index reads besides (features/dataset.py build, safeguard/training.py validate_index).
                "typ": "benign", "collector_sha256": V5_RUNTIME["collector_sha256"],
                "profile_sha256": c.tree_hashes(Path(p["profile"]))}
        for key, value in state["corrupt"].get(sid, {}).items():
            meta[key] = value
        write_new(src / "session.json", meta)
        shutil.copyfile(arg("--protocol"), src / "protocol.json")
        # The records of the session's events and controls, as the capture leaves them (build hashes both).
        write_new(src / "events.json", {"schema": "hyptcn3/session-events/1", "events": [], "note": "synthetic"})
        if role == protocol_v5.CONTROL_ROLE:
            write_new(src / "controls.json", {"schema": protocol_v5.CONTROLS_SCHEMA, "controls": [],
                                              "note": "synthetic"})
        (src / "raw").mkdir()
        (src / "raw/frame.vmicd").write_bytes(b"synthetic RAM " + sid.encode())
        start, end = state["clock"].take(p)
        write_new(src / "end.json", {"completed": True, "guest_after": identity, "measurement_started": True,
                                     "measure_start_unix": start, "measure_end_unix": end})
        log.write_text("synthetic capture\n")
        return 0

    def audit(command, log):
        src, report = Path(command[command.index("audit") + 1]), Path(command[command.index("--out") + 1])
        meta = read_json(src / "session.json")
        campaign = read_json(c.BASE / meta["campaign_id"] / "campaign.json")
        state["calls"].append(("audit", meta["vm"], src.name))
        accepted = src.name not in state["reject"]
        protocol_path = c.BASE / meta["campaign_id"] / "protocol.json"
        values = audit_values(src, read_json(protocol_path), protocol_path, report,
                              extractor=campaign["extractor_sha256"], accepted=accepted,
                              rejection=("timing:gap", "missed sampling slot"))
        write_new(report, {"schema": "hyptcn3/collection-audit/1", "commit": campaign["commit"],
                           "measurement_dirty": [], "values": values})
        log.write_text("synthetic audit\n")
        return 0 if accepted else 2

    def seal(command, log):
        import contextlib
        state["calls"].append(("seal", command[command.index("--audit") + 1]))
        with log.open("w") as stream, contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            return pecat.main(command[command.index("tcn.pecat") + 1:])

    def child(command, log, **kw):
        command = list(map(str, command))
        owned = "as-owner" in command
        if str(c.ROOT / "scripts/labctl.py") in command:
            assert owned  # GROUP_START_RULE: as the VM's owner.
            return lab(command, log, command[command.index("--vm") + 1])
        if "tcn.pecat" in command:
            assert owned  # SEAL_RULE: the ledger stays a file of its owner.
            return seal(command, log)
        if "run" in command:
            assert not owned and kw["lock_fd"] >= 0
            return capture(command, log)
        assert "audit" in command and owned
        return audit(command, log)
    monkeypatch.setattr(c, "run_child", child)
    real_run, real_finish = subprocess.run, c.finish_corpus

    def run(args, *more, **kw):
        """finish_corpus runs the production check of training as the owner (collection.user_command): here the
        command itself, in this test's environment."""
        argv = list(map(str, args)) if isinstance(args, (list, tuple)) else None
        if argv and argv[0] == "as-owner":
            state["calls"].append(("owner", argv[1:3]))
            return real_run(argv[1:], *more, **kw)
        return real_run(args, *more, **kw)
    monkeypatch.setattr(subprocess, "run", run)

    def finish(directory, manifest, protocol, reports):  # The spy: the call is recorded, then the real index.
        state["finished"].append((manifest.get("vm"), list(reports)))
        return real_finish(directory, manifest, protocol, reports)
    monkeypatch.setattr(c, "finish_corpus", finish)
    return state


def v5_init(v5, mode="rehearsal", **changes):
    """init of the test's campaign as its command line gives it (no pilot report, no name: the plan's)."""
    arguments = SimpleNamespace(protocol=v5["protocol"], name=None, archive_compression="none", pilot_report=None,
                                archive_root=v5["tmp"] / "archive", archive_on_system_disk=True, continues=None,
                                mode=mode, estimate_from=None)
    vars(arguments).update(changes)
    return c.initialize(arguments)


def ended_rehearsal(v5, sizes=((1000, 400), (1500, 300)), mode="rehearsal", ended=True, **changes):
    """The directory of an ended rehearsal of the test's protocol, with what --estimate-from reads (campaign.json,
    protocol.json, the checkpoints of its accepted sessions with their sizes, closed.json); `changes` to its protocol."""
    directory = v5["tmp"] / "rehearsals" / "skuska-generalka"
    (directory / "attempts").mkdir(parents=True)
    (directory / "protocol.json").write_text(json.dumps({**json.loads(v5["protocol"].read_text()), **changes}))
    write_new(directory / "campaign.json", {"schema": "hyptcn3/collection-campaign/1", "id": directory.name,
                                            "mode": mode, "archive_compression": None, "vms": {"a": {}, "b": {}}})
    for i, (working, stored) in enumerate(sizes):
        write_new(directory / "attempts" / f"s{i}.done.json",
                  {"session": f"s{i}", "session_bytes": working, "archive_bytes": stored})
    if ended:
        write_new(directory / "closed.json", {"reason": "the rehearsal ended"})
    return directory


def run_v5(directory):
    for _ in range(20):
        for vm in ("a", "b"):
            c.execute(directory, vm=vm)
        if all(read_json(directory / f"status-{vm}.json")["status"] == "complete" for vm in ("a", "b")):
            return
    pytest.fail("campaign did not complete")


def first_of(directory, vm="a", role=None):
    return next(r for r in read_json(directory / "campaign.json")["sessions"]
                if r["vm"] == vm and role in (None, r["role"]))


def test_v5_init_of_a_rehearsal_freezes_its_mode_plan_and_guests(v5):
    """MODE_RULE, PILOT_RULE and STAGES_RULE (design B9a 1.3 items 2 to 4): init takes the mode and no pilot; the plan,
    its name and its group prefix are the rehearsal's (protocol_v5._shape), the guest environment of every VM is
    recorded, and the stages G0 to G2 and the self-test are asked for."""
    from scripts import protocol_v5
    directory = v5_init(v5)
    manifest = read_json(directory / "campaign.json")
    p = collection.protocol(v5["protocol"])
    name, prefix, _ = protocol_v5._shape(p, "rehearsal")
    assert (manifest["mode"], manifest["plan_name"], manifest["group_prefix"]) == ("rehearsal", name, prefix)
    assert directory.name.endswith("_" + name) and prefix == "g5-"
    assert [{k: v for k, v in r.items() if k != "session_id"} for r in manifest["sessions"]] \
        == protocol_v5.plan(p, mode="rehearsal")["sessions"]
    assert manifest["vms"] == {vm: {"guest_environment": {**V5_ENV, "machine_id": "machine-" + vm},
                                    "domain": "hyptcn-test-" + vm} for vm in "ab"}
    assert c.frozen_files(manifest) == ["campaign.json", "protocol.json", "plan.json"]
    assert not list(directory.glob("pilot*.json")) and not any("pilot" in key for key in manifest)
    assert manifest["disk_estimate"] == {"rule": c.DISK_RULE, "seed": None} and manifest["rules"] == c.RULES
    assert v5["stages"] == [("protocol.json", "G3a")] and v5["selftests"] == ["protocol.json"]
    assert c.load_campaign(directory)[0] == manifest


@pytest.mark.parametrize("case, reason", [
    ("no_mode", "a campaign of protocol schema 3 needs --mode campaign or --mode rehearsal (no default"),
    ("pilot", "protocol v5 has no pilot: init takes no --pilot-report"),
    ("null_limit", "replacement.max_per_campaign is null (it is determined at G3b"),
    ("no_estimate", "a campaign of mode campaign needs --estimate-from"),
    ("estimate_in_rehearsal", "--estimate-from belongs to mode campaign"),
    ("stages", "a campaign of mode rehearsal starts on valid readiness records of G0 to G2: stage G0 is not valid"),
    ("mode_under_schema_2", "--mode applies only to protocol schema 3"),
], ids=["no_mode", "pilot", "null_limit", "no_estimate", "estimate_in_rehearsal", "stages", "mode_under_schema_2"])
def test_v5_init_refuses_by_name(v5, monkeypatch, case, reason):
    """One bad input per check of init under schema 3 (design B9a 1.3 items 2 to 5), each before anything is frozen."""
    from scripts import gates
    changes = {"no_mode": {"mode": None}, "pilot": {"pilot_report": ["a=pa.json", "b=pb.json"]},
               "null_limit": {"mode": "campaign"}, "no_estimate": {"mode": "campaign"},
               "estimate_in_rehearsal": {"estimate_from": v5["tmp"]}, "stages": {},
               "mode_under_schema_2": {"protocol": collection.DEFAULT}}[case]
    if case in ("null_limit", "no_estimate"):
        v5_protocol(v5["protocol"], limit=None if case == "null_limit" else 1)
    if case == "stages":
        def refuse(results, path, stage):
            raise ValueError("stage G0 is not valid: no record")
        monkeypatch.setattr(gates, "require", refuse)
    with pytest.raises(ValueError, match="^" + re.escape(reason)):
        v5_init(v5, **changes)
    assert not c.BASE.exists()


@pytest.mark.parametrize("archive_free, refused", [
    (31 * 400, None),
    (31 * 400 - 1, "insufficient archive space for the sessions still to capture: 12400 bytes needed"),
], ids=["fits", "does_not_fit"])
def test_v5_campaign_estimate_is_seeded_by_an_ended_rehearsal(v5, archive_free, refused):
    """DISK_RULE in mode campaign: --estimate-from seeds the estimate with the largest accepted session of the
    rehearsal (1500 working bytes, 400 archive bytes); init refuses a campaign whose 30 sessions and the 1
    replacement its limit allows do not fit on the archive disk; the working disk holds both VMs' next sessions."""
    v5_protocol(v5["protocol"], limit=1)
    rehearsal = ended_rehearsal(v5)
    v5["free"] = {"working": 2 * 1500, "archive": archive_free}
    if refused:
        with pytest.raises(ValueError, match="^" + re.escape(refused)):
            v5_init(v5, "campaign", estimate_from=rehearsal)
        return
    directory = v5_init(v5, "campaign", estimate_from=rehearsal)
    seed = read_json(directory / "campaign.json")["disk_estimate"]["seed"]
    assert (seed["campaign"], seed["session_bytes"], seed["archive_bytes"], seed["accepted_sessions"],
            seed["session"]) == (rehearsal.name, 1500, 400, 2, "s0")
    assert v5["stages"] == [("protocol.json", "G5")]


@pytest.mark.parametrize("case, reason", [
    ("campaign", "is no rehearsal (mode 'campaign')"),
    ("open", "has not ended (closed, or complete on every VM)"),
    ("cycles", "differs from this campaign in cycles"),
    ("empty", "has no accepted session"),
], ids=["campaign", "open", "cycles", "empty"])
def test_v5_estimate_source_is_refused_by_name(v5, case, reason):
    """DISK_RULE: the seed comes only from an ended rehearsal of sessions of the same shape that accepted one."""
    v5_protocol(v5["protocol"], limit=1)
    rehearsal = ended_rehearsal(v5, **{"campaign": {"mode": "campaign"}, "open": {"ended": False},
                                       "cycles": {"cycles": 97}, "empty": {"sizes": ()}}[case])
    with pytest.raises(ValueError, match=re.escape(reason)):
        v5_init(v5, "campaign", estimate_from=rehearsal)


def test_v5_rehearsal_estimate_follows_its_largest_accepted_session(v5):
    """DISK_RULE in mode rehearsal: before its first accepted session only min_free_gib is needed; after it the largest
    accepted session times the sessions still to capture (14 of 15; no replacement counted, the limit is not applied),
    and on the working disk this VM's next session and the other VM's; the sizes come from the archive manifest."""
    v5_protocol(v5["protocol"], min_free_gib=1)
    directory = v5_init(v5)
    view, p = c.vm_view(*c.load_campaign(directory), "a")
    reserve = 2**30
    v5["free"] = {"working": reserve, "archive": reserve}
    c.capacity_guard(view, p, 0, directory)
    v5["free"] = {"working": 10**15, "archive": 10**15}
    c.execute(directory, vm="a", stop_after=1)
    done, = (read_json(path) for path in (directory / "attempts").glob("*.done.json"))
    archived = read_json(next((v5["tmp"] / "archive").rglob("archive-manifest.json")))
    assert (done["session_bytes"], done["archive_bytes"]) == (archived["bytes"], archived["bytes"])  # uncompressed
    need = {"working": 2 * done["session_bytes"] + reserve, "archive": 14 * done["archive_bytes"] + reserve}
    v5["free"] = dict(need)
    c.capacity_guard(view, p, 0, directory)
    for disk, message in (("working", "insufficient working space"), ("archive", "insufficient archive space")):
        v5["free"] = {**need, disk: need[disk] - 1}
        with pytest.raises(ValueError, match="^" + message):
            c.capacity_guard(view, p, 0, directory)


def test_v5_capture_names_the_mode_and_the_attempt_and_no_pilot(v5):
    """PILOT_RULE and REPLACEMENT_RULE: the capture of a planned session passes --mode and --attempt 1 with the
    plan's seed and no --pilot-report (the fake child checks the seed against the plan of the mode)."""
    directory = v5_init(v5)
    c.execute(directory, vm="a", stop_after=1)
    first = first_of(directory)
    assert [call for call in v5["calls"] if call[0] == "capture"] == [("capture", "a", first["session_id"], 1,
                                                                       "rehearsal")]
    meta = read_json(c.session_dir(read_json(directory / "campaign.json"), first) / "session.json")
    assert (meta["attempt"], meta["plan_mode"], meta["seed"]) == (1, "rehearsal", first["seed"])


def test_v5_rehearsal_replaces_every_covered_rejection_by_the_next_attempt(v5):
    """REPLACEMENT_RULE and LIMIT_RULE in mode rehearsal: the protocol's limit (0) is not applied, so a session of
    test_controls and its first replacement, both rejected, are replaced; replacement n is attempt n + 1 of the
    planned row: the same VM, role, group, scenario and kinds of the controls, new times and a new traffic seed; the
    rejections are counted by cause in the state."""
    from scripts import protocol_v5
    directory = v5_init(v5)
    planned = next(r for r in read_json(directory / "campaign.json")["sessions"]
                   if r["role"] == "test_controls" and any(x.get("kind") for x in r["controls"]))
    sid = planned["session_id"]
    v5["reject"].update({sid, sid + "-r1"})
    run_v5(directory)
    assert [(r["session"], r["replacement"], r["attempt"], r["limit_applied"], r["max_per_campaign"])
            for r in c.rejections(directory)] == [(sid, sid + "-r1", 1, False, None),
                                                  (sid + "-r1", sid + "-r2", 2, False, None)]
    assert [call[2:4] for call in v5["calls"] if call[0] == "capture" and call[2].startswith(sid)] \
        == [(sid, 1), (sid + "-r1", 2), (sid + "-r2", 3)]
    p = collection.protocol(directory / "protocol.json")
    third = protocol_v5.replacement(p, {k: v for k, v in planned.items() if k != "session_id"}, 3, mode="rehearsal")
    meta = read_json(c.session_dir(read_json(directory / "campaign.json"), {**planned, "session_id": sid + "-r2"})
                     / "session.json")
    filled = [x for x in third["controls"] if x.get("kind") is not None]
    assert (meta["attempt"], meta["seed"], meta["controls"]) == (3, third["seed"], filled) and filled
    assert meta["seed"] != planned["seed"] and all(meta[k] == planned[k] for k in ("vm", "role", "group", "scenario"))
    kinds = lambda items: [(x["kind"], x["polarity"], x["dose"]) for x in items if x.get("kind") is not None]
    assert kinds(meta["controls"]) == kinds(planned["controls"])
    assert [x["start_s"] for x in meta["controls"]] != [x["start_s"] for x in planned["controls"] if x["kind"]]
    assert c.status(directory)["vms"]["b"]["rejections_by_cause"] == {"audit_rejected": 2}


def test_v5_campaign_stops_when_its_limit_is_used_up(v5):
    """LIMIT_RULE in mode campaign: the protocol's limit 1 holds; the second rejection is not replaced and the runner
    stops as before package B9a (pause is B9b); the state counts the rejections by cause."""
    v5_protocol(v5["protocol"], limit=1)
    directory = v5_init(v5, "campaign", estimate_from=ended_rehearsal(v5))
    sid = first_of(directory)["session_id"]
    v5["reject"].update({sid, sid + "-r1"})
    with pytest.raises(ValueError, match="^audit rejected session; archived without replacement: missed sampling slot$"):
        c.execute(directory, vm="a")
    first, second = c.rejections(directory)
    assert [(r["replacement"], r["limit_applied"], r["max_per_campaign"]) for r in (first, second)] \
        == [(sid + "-r1", True, 1), (None, True, 1)]
    assert second["not_replaced"] == "the protocol's 1 replacements per campaign are used up"
    assert [call[3:] for call in v5["calls"] if call[0] == "capture"] == [(1, "campaign"), (2, "campaign")]
    assert read_json(directory / "status-a.json")["rejections_by_cause"] == {"audit_rejected": 2}


@pytest.mark.parametrize("key", [None, "attempt", "plan_mode", "events", "controls"])
def test_check_session_compares_the_attempt_and_its_planned_items(v5, key):
    """B3 S6 and REPLACEMENT_RULE: the session.json of a replacement holds its attempt, the campaign's plan mode and
    the events and controls of that attempt, the replacement's and not the plan's; a difference is named."""
    directory = v5_init(v5)
    campaign, protocol = c.load_campaign(directory)
    planned = next(r for r in campaign["sessions"]
                   if r["role"] == "test_controls" and any(x.get("kind") for x in r["controls"]))
    manifest, p = c.vm_view(campaign, protocol, planned["vm"])
    sid = planned["session_id"]
    row = c.attempt_row(manifest, p, {**planned, "session_id": sid + "-r1", "replaces": sid, "plan_session": sid,
                                      "replacement": 1})
    identity = {**V5_ENV, "machine_id": "machine-" + planned["vm"], "boot_id": "boot-group"}
    qemu = {"pid": 7, "start_ticks": 1, "host_boot": "host-boot"}
    write_new(directory / "groups" / (planned["group"] + ".json"), {"identity": identity, "qemu": qemu})
    session = v5["tmp"] / "session"
    session.mkdir()
    filled = [x for x in row["controls"] if x.get("kind") is not None]
    meta = {"session_id": sid + "-r1", "replaces": sid, "vm": planned["vm"], "attempt": 2, "plan_mode": "rehearsal",
            "events": [], "controls": filled, "campaign_id": campaign["id"], "commit": campaign["commit"],
            "measurement_dirty": [], "protocol_sha256": campaign["protocol_sha256"], "guest_before": identity,
            "host_context": {"qemu": qemu}, **{k: row[k] for k in ("role", "group", "scenario", "seed")}}
    changed = {"attempt": 1, "plan_mode": "campaign", "events": [{"type": "unplanned"}],
               "controls": [x for x in planned["controls"] if x.get("kind") is not None]}
    write_new(session / "session.json", {**meta, **({key: changed[key]} if key else {})})
    write_new(session / "end.json", {"completed": True, "guest_after": identity})
    if key is None:
        assert c.check_session(session, manifest, row, directory, p) is True
        return
    assert changed[key] != meta[key]
    with pytest.raises(ValueError, match="^session differs from frozen assignment: " + key + "$"):
        c.check_session(session, manifest, row, directory, p)


def test_v5_group_starts_with_stop_start_reset_and_pretouch_recorded(v5):
    """GROUP_START_RULE (proposal 5.4, B5a F4): labctl stop, start (a new QEMU process by way 1, its pid and cgroup
    from the start's qemu_swap record), the reset to the protocol's one seeded level (protocol_v5.reset_seed(p), the
    same for every group and both modes: finding F4 of the verification of B9a) and the pretouch, in this order and as
    the VM's owner, each output in the group's record; no guest reboot."""
    from scripts import protocol_v5
    directory = v5_init(v5)
    before = dict(v5["qemu"]["a"])
    c.execute(directory, vm="a", stop_after=1)
    first = first_of(directory)
    group = read_json(directory / "groups" / (first["group"] + ".json"))
    steps = group["start"]["steps"]
    assert [s["step"] for s in steps] == ["stop", "start", "reset", "pretouch"]
    assert [call for call in v5["calls"] if call[1] == "a"][:5] == [
        ("lab", "a", "stop"), ("lab", "a", "start"), ("lab", "a", "reset"), ("lab", "a", "pretouch"),
        ("capture", "a", first["session_id"], 1, "rehearsal")]
    seed = protocol_v5.reset_seed(collection.protocol(directory / "protocol.json"))  # F4: one seed for every group.
    assert (group["start"]["reset_seed"], steps[2]["seed"], steps[2]["output"]["seed"]) == (seed, seed, seed)
    assert steps[3]["output"] == {"schema": "hyptcn3/guest-pretouch/1", "touched": True}
    assert group["qemu"] == v5["qemu"]["a"] != before and group["previous_qemu"] == before
    assert (steps[1]["qemu"], steps[1]["cgroup"]) == (group["qemu"], V5_CGROUP)
    assert steps[1]["printed"][-1] == {"qemu_swap": {"domain": "hyptcn-test-a", "qemu_pid": group["qemu"]["pid"],
                                                     "cgroup": V5_CGROUP, "memory_swap_max": "0", "vm_swap_kb": 0,
                                                     "way": "unit", "temporary": False}}
    assert group["identity"]["boot_id"] == v5["boot"]["a"] and group["start"]["rule"] == c.GROUP_START_RULE


@pytest.mark.parametrize("step", ["stop", "start", "reset", "pretouch", "same_qemu", "way_2"])
def test_v5_failed_group_start_rejects_before_the_measured_phase(v5, step):
    """GROUP_START_RULE: a failing step (or a start that leaves the old QEMU process, or one that holds the QEMU by way
    2, the scope move, which labctl reports as temporary) rejects the group's first session before its measured phase
    with the cause group_start and the step named; the protocol's rule covers no such cause, so nothing is replaced,
    nothing captured and no group recorded."""
    directory = v5_init(v5)
    if step == "same_qemu":
        v5["same_qemu"] = True
    elif step == "way_2":
        v5["way"] = ("scope", True)
    else:
        v5["fail"] = step
    named = step if step in ("stop", "start", "reset", "pretouch") else "start"
    with pytest.raises(ValueError, match="^" + re.escape(c.STOP_MESSAGE["group_start"] + ": " + named + ": ")):
        c.execute(directory, vm="a")
    first = first_of(directory)
    record, = c.rejections(directory)
    assert (record["session"], record["cause"], record["replacement"]) == (first["session_id"], "group_start", None)
    assert record["reasons"][0].startswith(named + ": ") and len(record["reasons"]) == 1
    assert {"same_qemu": "labctl start left the QEMU process of the previous group",
            "way_2": "labctl start holds the QEMU by way 'scope' (temporary True)"}.get(
        step, f"labctl {step} exited 1: labctl: synthetic failure of {step}") in record["reasons"][0]
    assert record["not_replaced"] == "the protocol has no replacement rule for this cause"
    assert not any(call[0] == "capture" for call in v5["calls"])
    assert not (directory / "groups" / (first["group"] + ".json")).exists()
    assert read_json(directory / "status-a.json")["rejections_by_cause"] == {"group_start": 1}


def test_v5_accepted_sessions_of_the_sealed_roles_are_sealed_at_once(v5):
    """SEAL_RULE (skeleton row pečať): every accepted session of test_benign and test_controls is written into the
    ledger (the test's: tcn.pecat.KNIHA and ZAZNAM) right after its audit, as the owner, with its id, role, group, vm,
    scenario and plan; no other role is; afterwards a replay of a sealed archive of the campaign is refused."""
    from tcn import pecat
    v5_protocol(v5["protocol"], limit=1)
    directory = v5_init(v5, "campaign", estimate_from=ended_rehearsal(v5))
    run_v5(directory)
    planned = {r["session_id"]: r for r in read_json(directory / "campaign.json")["sessions"]}
    archives = read_json(v5["ledger"])["values"]["archives"]
    sealed = {entry["session"]: entry for entry in archives.values()}
    assert set(sealed) == {sid for sid, r in planned.items() if r["role"] in ("test_benign", "test_controls")}
    assert len(sealed) == 12
    for sid, entry in sealed.items():
        row = planned[sid]
        assert (entry["role"], entry["group"], entry["vm"], entry["scenario"], entry["mode"]) \
            == (row["role"], row["group"], row["vm"], row["scenario"], "campaign")
    calls = [call for call in v5["calls"] if call[0] in ("audit", "seal")]
    seals = [i for i, call in enumerate(calls) if call[0] == "seal"]
    assert len(seals) == 12 and all(calls[i - 1][0] == "audit" and calls[i - 1][2] in sealed for i in seals)
    sha, entry = next(iter(archives.items()))
    with pytest.raises(pecat.Zapecatene, match="refused"):
        pecat.kontrola(entry["features"], purpose="a replay of the test")


def test_v5_launch_and_run_start_on_the_stages_of_the_mode(v5, monkeypatch):
    """STAGES_RULE: launch and run check the readiness records of the campaign's mode before anything starts."""
    from scripts import gates
    directory = v5_init(v5)

    def refuse(results, path, stage):
        raise ValueError(f"stage before {stage} is not valid")
    monkeypatch.setattr(gates, "require", refuse)
    monkeypatch.setattr(c.subprocess, "run", lambda *a, **k: pytest.fail("no unit may start"))
    for start in (lambda: c.launch(directory), lambda: c.execute(directory, vm="a")):
        with pytest.raises(ValueError, match="^a campaign of mode rehearsal starts on valid readiness records of G0 "
                                             "to G2: stage before G3a is not valid$"):
            start()
    assert not any(call[0] in ("lab", "capture") for call in v5["calls"])


@pytest.mark.parametrize("status, changed", [
    (" M data/results/kniha_pecati.json", None),
    ("M  data/results/kniha_pecati.json", None),
    (" M data/results/kniha_pecati.json\n?? data/results/novy.json", "?? data/results/novy.json"),
    (" D data/results/kniha_pecati.json", " D data/results/kniha_pecati.json"),
    (" M scripts/campaign.py", " M scripts/campaign.py"),
], ids=["ledger", "ledger_staged", "ledger_and_new_file", "ledger_deleted", "source"])
def test_verify_frozen_admits_only_the_seal_ledger(tmp_path, monkeypatch, status, changed):
    """FROZEN_TREE_RULE: the frozen tree admits the seal ledger modified in place and nothing else, named."""
    monkeypatch.setattr(c, "git", lambda *args: "frozen" if args[0] == "rev-parse" else status)
    monkeypatch.setattr(c, "runtime_identity", lambda: {"version": "old"})
    monkeypatch.setattr(c, "tree_hashes", lambda _: {"hash": "old"})
    monkeypatch.setattr(c, "extractor_hashes", lambda: {"hash": "old"})
    monkeypatch.setattr(c, "guard_mount", lambda *a: None)
    external = tmp_path / "external"
    external.mkdir()
    manifest = {"commit": "frozen", "runtime": {"version": "old"}, "profile_sha256": {"hash": "old"},
                "extractor_sha256": {"hash": "old"}, "mode": "campaign", "archive_root": str(external),
                "archive_mount": {}, "archive_dir": str(external)}
    for name in c.frozen_files(manifest):
        for place in (tmp_path, external):
            (place / name).write_text(name)
    if changed is None:
        c.verify_frozen(tmp_path, manifest, {"profile": "unused"})
        return
    with pytest.raises(ValueError, match="^" + re.escape("campaign source changed; restore frozen commit before "
                                                         f"resuming (changed: {changed})") + "$"):
        c.verify_frozen(tmp_path, manifest, {"profile": "unused"})


def test_finish_corpus_keeps_the_error_text_of_the_production_check(tmp_path, monkeypatch):
    """B2 panel (deferred to B9): the refusal of validate_index, run as the owner, keeps the child's own error text
    in the error that becomes the runner's status message."""
    import features.dataset
    (tmp_path / "events").mkdir()
    p = collection.protocol(collection.DEFAULT)
    monkeypatch.setattr(features.dataset, "build", lambda *a, **k: {"complete": True, "sessions": []})
    monkeypatch.setattr(collection, "user_command", lambda args: [
        sys.executable, "-c", "import sys; sys.exit('ValueError: the index holds the session s1 twice')"])
    with pytest.raises(ValueError, match="refused the corpus index .* the index holds the session s1 twice$"):
        c.finish_corpus(tmp_path, {"protocol_sha256": "p", "archive_root": "/", "archive_mount": {},
                                   "archive_dir": str(tmp_path)}, p, [])


@pytest.mark.parametrize("case, reason", [
    (None, None),
    ("unaccepted", "the audit does not accept its session; only an accepted session is sealed"),
    ("session", "changed since its audit"),
    ("protocol", "the session's protocol.json is not the protocol of its audit"),
    ("mode", "the session belongs to the plan of mode rehearsal, not campaign"),
], ids=["good", "unaccepted", "session", "protocol", "mode"])
def test_seal_of_one_audit_refuses_by_name(tmp_path, monkeypatch, capsys, case, reason):
    """SEAL_RULE, the per-session form of the ledger's command line (python -m tcn.pecat zapis --audit A --mode M):
    one good input, and one bad input per check, each refused with exit 2 and its reason, the ledger unchanged."""
    from tcn import pecat
    ledger = tmp_path / "results" / "kniha_pecati.json"
    ledger.parent.mkdir()
    monkeypatch.setattr(pecat, "KNIHA", ledger)
    monkeypatch.setattr(pecat, "ZAZNAM", ledger)
    session = tmp_path / "sessions" / "s1"
    session.mkdir(parents=True)
    v5_protocol(session / "protocol.json")
    meta = {"schema": "hyptcn3/collection-session/2", "session_id": "s1", "role": "test_benign", "group": "v5-tb-1",
            "vm": "a", "scenario": "eshop_low", "plan_mode": "rehearsal" if case == "mode" else "campaign"}
    write_new(session / "session.json", meta)
    (session / "features.npz").write_bytes(b"synthetic feature archive")
    values = {"accepted": case != "unaccepted", "reasons": [] if case != "unaccepted" else ["rejected"],
              "role": "test_benign", "session_dir": str(session), "session_sha256": digest(session / "session.json"),
              "protocol_sha256": digest(session / "protocol.json"), "features": str(session / "features.npz"),
              "features_sha256": digest(session / "features.npz")}
    if case == "session":
        write_new(session / "session.json", {**meta, "scenario": "corp_high"}, replace=True)
    if case == "protocol":
        values["protocol_sha256"] = "0" * 64
    audit = session / "audit.json"
    write_new(audit, {"schema": "hyptcn3/collection-audit/1", "values": values})
    code = pecat.main(["zapis", "--audit", str(audit), "--mode", "campaign"])
    if case is None:
        assert code == 0
        entry, = read_json(ledger)["values"]["archives"].values()
        assert (entry["session"], entry["role"], entry["group"], entry["vm"], entry["scenario"], entry["mode"]) \
            == ("s1", "test_benign", "v5-tb-1", "a", "eshop_low", "campaign")
        return
    assert code == 2 and reason in capsys.readouterr().err
    assert not ledger.exists()


def test_v5_replacement_that_cannot_be_drawn_is_refused_by_name(v5, monkeypatch):
    """REPLACEMENT_RULE with OutsideDeck of protocol_v5.replacement (agent P; S5 of B4): a rejected session whose next
    attempt cannot be drawn, for an item outside the protocol's deck, is not replaced; the rejection names why, no
    record names a replacement that cannot exist, and the runner stops by name instead of failing."""
    from scripts import protocol_v5
    directory = v5_init(v5)
    first = first_of(directory)
    v5["reject"].add(first["session_id"])
    said = f"no replacement of {first['group']}#{first['position']}: type naprazdno is outside events.types"

    def outside(p, session, attempt, *, mode="campaign"):
        raise protocol_v5.OutsideDeck(said)
    monkeypatch.setattr(protocol_v5, "replacement", outside)
    for _ in range(2):  # The stop is permanent: a rerun captures nothing and draws nothing.
        with pytest.raises(ValueError, match="^audit rejected session; archived without replacement: missed sampling "
                                             "slot$"):
            c.execute(directory, vm="a")
    record, = c.rejections(directory)
    assert (record["session"], record["replacement"]) == (first["session_id"], None)
    assert record["not_replaced"] == "its next attempt cannot be drawn: " + said
    assert [call[2] for call in v5["calls"] if call[0] == "capture"] == [first["session_id"]]


@pytest.mark.parametrize("attempt", [1, 3])
def test_check_session_agrees_with_what_the_capture_runs_for_an_attempt(tmp_path, monkeypatch, attempt):
    """REPLACEMENT_RULE and B3 S6 against scripts/collection.py v5_planned (agent L), on the plan of the v5 file: for
    attempt N of a session of test_controls with an empty slot (the deck exhausted), the seed, the events and the
    controls without the empty slot that collection.py run takes are exactly what check_session asks of that attempt's
    session.json (attempt 1 the plan's row, attempt 3 its second replacement)."""
    from scripts import gates, protocol_v5
    doc = json.loads((c.ROOT / "config/collection-v5.json").read_text())
    for scenario in doc["scenarios"].values():  # collection.py run needs the protocol's rate (null until G2).
        scenario["rate"] = 1.0
    (tmp_path / "protocol.json").write_text(json.dumps(doc))
    protocol = collection.protocol(tmp_path / "protocol.json")
    monkeypatch.setattr(gates, "require", lambda results, path, stage: None)  # v5_planned's readiness records.
    planned = next(dict(r, session_id="kampan_01") for r in protocol_v5.plan(protocol, mode="campaign")["sessions"]
                   if r["role"] == "test_controls" and {x.get("kind") is None for x in r["controls"]} == {True, False})
    p = collection.for_vm(protocol, planned["vm"])
    manifest = {"id": "kampan", "commit": "c", "protocol_sha256": "p", "mode": "campaign",
                "guest_environment": {**V5_ENV, "machine_id": "machine-" + planned["vm"]}}
    sid = planned["session_id"]
    row = planned if attempt == 1 else c.attempt_row(manifest, p, {
        **planned, "session_id": f"{sid}-r{attempt - 1}", "replaces": f"{sid}-r{attempt - 2}" if attempt > 2 else sid,
        "plan_session": sid, "replacement": attempt - 1})
    run = collection.v5_planned(SimpleNamespace(
        role=row["role"], group=row["group"], scenario=row["scenario"], seed=row["seed"], mode="campaign",
        attempt=attempt, protocol=tmp_path / "protocol.json"), p)
    assert (run["attempt"], run["plan_mode"], run["events"]) == (attempt, "campaign", [])
    assert run["controls"] and len(run["controls"]) == len(row["controls"]) - 1
    identity = {**V5_ENV, "machine_id": "machine-" + planned["vm"], "boot_id": "boot-group"}
    qemu = {"pid": 7, "start_ticks": 1, "host_boot": "host-boot"}
    directory, session = tmp_path / "campaign", tmp_path / "session"
    (directory / "groups").mkdir(parents=True)
    session.mkdir()
    write_new(directory / "groups" / (planned["group"] + ".json"), {"identity": identity, "qemu": qemu})
    write_new(session / "session.json", {  # As scripts/collection.py run_session records a planned session.
        "session_id": row["session_id"], **({"replaces": row["replaces"]} if "replaces" in row else {}),
        "vm": planned["vm"], "role": row["role"], "group": row["group"], "scenario": row["scenario"],
        "seed": row["seed"], "attempt": run["attempt"], "plan_mode": run["plan_mode"], "events": run["events"],
        "controls": run["controls"], "campaign_id": "kampan", "commit": "c", "measurement_dirty": [],
        "protocol_sha256": "p", "guest_before": identity, "host_context": {"qemu": qemu}})
    write_new(session / "end.json", {"completed": True, "guest_after": identity})
    assert c.check_session(session, manifest, row, directory, p) is True


# ------------------------------------------------------------------ the fix round of B9a (agent K)
# F5 of the verification of B9a: ORDER_RULE inside the shared rank of the two test roles; F4 and F7: the start of a
# group; F6: tests that kill the verifier's surviving mutants (dokazy/B9/overenie_B9a/sondy/mut/mutants.py).

def v5_file_plan():
    """The campaign plan of config/collection-v5.json as init freezes it (session IDs added), its protocol, and the
    groups of the interleaved roles in the plan's order as (vm, group)."""
    from scripts import protocol_v5
    p = collection.protocol(c.ROOT / "config/collection-v5.json")
    manifest = {"id": "kampan", "mode": "campaign", "sessions": protocol_v5.plan(p, mode="campaign")["sessions"]}
    for i, row in enumerate(manifest["sessions"]):
        row["session_id"] = f"kampan_{i + 1:03d}_{row['vm']}"
    tests = list(dict.fromkeys((r["vm"], r["group"]) for r in manifest["sessions"]
                               if r["role"] in p["interleave"][0]))
    return p, manifest, tests


def first_row(manifest, group):
    return next(r for r in manifest["sessions"] if r["group"] == group)


def start(directory, group):
    """What start_group leaves when a group has started: its record groups/<group>.json (written after the pretouch)."""
    write_new(directory / "groups" / (group + ".json"), {"schema": "hyptcn3/campaign-group/1", "group": group})


def lower_ranks_done(directory, manifest, p):
    """Every session of a role of a lower rank than the test roles accepted and archived (its done checkpoint)."""
    rank = c.time_rank(p)
    for row in manifest["sessions"]:
        if rank[row["role"]] < rank["test_benign"]:
            write_new(directory / "attempts" / (row["session_id"] + ".done.json"), {})


@pytest.mark.parametrize("started, at, waits", [
    ((), 0, ()),                    # the first test group of the plan waits for nothing
    ((), 1, (0,)),                  # VM a's first test group waits for VM b's, which precedes it
    ((), 3, (1, 2)),                # VM b's second test group waits for VM a's two before it
    ((0, 1, 2), 4, (3,)),           # VM a ran ahead: its next group waits for VM b's
    ((0, 1, 2), 3, ()),             # ... and VM b's group starts at once
    ((0, 1, 2, 3, 4), 8, (5, 6, 7)),  # drift: VM a at its next group waits for the three of VM b before it
    ((0, 1, 2, 3, 4), 5, ()),
    ((0, 1, 2, 3, 4, 5, 6, 7), 12, (8, 9, 10, 11)),  # drift the other way: VM b waits for four groups of VM a
    ((0, 1, 2, 3, 4, 8), 8, ()),    # a group that has started never waits (a rerun or a replacement in its boot)
])
def test_order_rule_waits_for_the_test_groups_before_it_in_the_plan(tmp_path, started, at, waits):
    """ORDER_RULE under protocol schema 3 (F5 of the verification of B9a; skeleton row poradie, proposal 7.3): before a
    group of an interleaved role a runner waits for every group of the interleaved roles that precedes it in the plan
    (the order of the frozen plan, on the other VM) and has not started, at several positions of the two-VM plan of
    config/collection-v5.json with one VM ahead of the other."""
    p, manifest, tests = v5_file_plan()
    assert [vm for vm, _ in tests[:13]] == list("baababbbaaaab") and len(tests) == 20
    (tmp_path / "groups").mkdir()
    for index in started:
        start(tmp_path, tests[index][1])
    row = first_row(manifest, tests[at][1])
    found = c.earlier_groups(tmp_path, manifest, p, row)
    assert [(r["vm"], r["group"]) for r in found] == [tests[index] for index in waits]
    assert found == [first_row(manifest, tests[index][1]) for index in waits]  # each named by its group's first row
    later = [r for r in manifest["sessions"] if r["group"] == row["group"]][1:]
    assert later and c.earlier_groups(tmp_path, manifest, p, later[0]) == found  # the same for each of its sessions


def test_order_rule_reads_the_start_of_a_group_from_its_record(tmp_path):
    """ORDER_RULE (F5): a group has started when its record groups/<group>.json exists, which start_group writes after
    the pretouch; the intent of a start (groups/<group>.start-intent.json, written before labctl stop) and a session
    directory are no start; a group a continuation took over from its closed campaign counts as started. A role
    without interleave never waits for a group."""
    p, manifest, tests = v5_file_plan()
    (tmp_path / "groups").mkdir()
    (b_vm, first), (_, second) = tests[0], tests[1]
    row = first_row(manifest, second)
    write_new(tmp_path / "groups" / (first + ".start-intent.json"), {"group": first})
    (tmp_path / "collections" / b_vm / first_row(manifest, first)["session_id"]).mkdir(parents=True)
    assert [r["group"] for r in c.earlier_groups(tmp_path, manifest, p, row)] == [first]
    start(tmp_path, first)
    assert c.earlier_groups(tmp_path, manifest, p, row) == []
    other = tmp_path / "continuation"
    (other / "groups").mkdir(parents=True)
    taken = {"continues": {"sessions": {r["session_id"]: {"session_id": r["session_id"]}
                                        for r in manifest["sessions"] if r["group"] == first}}}
    assert c.earlier_groups(other, {**manifest, **taken}, p, row) == []
    assert [r["group"] for r in c.earlier_groups(other, manifest, p, row)] == [first]
    calibration = next(r for r in reversed(manifest["sessions"]) if r["role"] == "calibration")
    assert c.earlier_groups(other, manifest, p, calibration) == []


@pytest.mark.parametrize("policy", ["vm a as far as it can", "vm b as far as it can", "one session each in turn"])
def test_order_rule_starts_the_test_groups_in_the_plan_order_without_deadlock(tmp_path, policy):
    """ORDER_RULE (F5): two runners, each taking its VM's sessions in plan order and waiting while
    campaign.earlier_roles or campaign.earlier_groups names something, finish every session of the plan of
    config/collection-v5.json under each schedule, one VM as far ahead as the rule lets it; the groups of the test
    roles start in the plan's order (proposal 7.3: their boots alternate in time), which the time rank alone did not
    keep."""
    p, manifest, tests = v5_file_plan()
    for name in ("groups", "attempts"):
        (tmp_path / name).mkdir()
    queues = {vm: [r for r in manifest["sessions"] if r["vm"] == vm] for vm in ("a", "b")}
    starts, waited = [], set()
    while queues["a"] or queues["b"]:
        moved = False
        for vm in {"vm b as far as it can": ("b", "a")}.get(policy, ("a", "b")):
            while queues[vm]:
                row = queues[vm][0]
                if c.earlier_roles(tmp_path, manifest, p, row) or c.earlier_groups(tmp_path, manifest, p, row):
                    waited.add(vm)
                    break
                if not (tmp_path / "groups" / (row["group"] + ".json")).exists():
                    start(tmp_path, row["group"])
                    starts.append((vm, row["group"]))
                write_new(tmp_path / "attempts" / (row["session_id"] + ".done.json"), {})
                queues[vm].pop(0)
                moved = True
                if policy == "one session each in turn":
                    break
        assert moved, f"the runners deadlock: VM a at {queues['a'][:1]}, VM b at {queues['b'][:1]}"
    assert [s for s in starts if s in tests] == tests
    assert waited == {"a", "b"}


def test_order_rule_wait_names_the_groups_and_keeps_its_exits(tmp_path, monkeypatch):
    """ORDER_RULE (F5): wait_for_earlier_roles under protocol schema 3 waits for the start of the groups before its
    group, names them in the state, and ends once their record exists; it keeps the exits of the rank wait: the
    operator's stop request, and a reason when the other runner is not active after START_GRACE_S."""
    p, manifest, tests = v5_file_plan()
    for name in ("groups", "attempts", "events"):
        (tmp_path / name).mkdir()
    lower_ranks_done(tmp_path, manifest, p)
    row = first_row(manifest, tests[1][1])
    monkeypatch.setattr(c, "START_GRACE_S", 0)
    # The other runner is not active: a reason to stop that names the groups.
    assert c.wait_for_earlier_roles(tmp_path, manifest, p, row) == (
        f"VM b has not started the groups before {tests[1][1]} in the plan ({tests[0][1]}) and its runner is not "
        "active")
    # It is active: the state names what the runner waits for, and the wait ends when the group has started.
    write_new(tmp_path / "status-b.json", {"status": "running", "pid": os.getpid(),
                                           "process_identity": c.process_identity(os.getpid())})
    rounds = []

    def sleep(seconds):
        assert seconds == c.WAIT_POLL_S
        rounds.append(read_json(tmp_path / "status-a.json"))
        start(tmp_path, tests[0][1])
    monkeypatch.setattr(c.time, "sleep", sleep)
    assert c.wait_for_earlier_roles(tmp_path, manifest, p, row) is None
    state, = rounds
    assert (state["stage"], state["group"], state["message"]) == (
        "role-wait", tests[1][1], f"waiting for the start of the groups before {tests[1][1]} in the plan: "
                                  f"{tests[0][1]} (VM b)")
    # The operator's stop request ends the wait.
    later = first_row(manifest, tests[3][1])
    write_new(tmp_path / "stop-request-b.json", {"reason": "test"})
    assert c.wait_for_earlier_roles(tmp_path, manifest, p, later) == "operator stop request"


def test_order_rule_barrier_holds_under_schema_3_only(tmp_path, monkeypatch):
    """ORDER_RULE (F5): under protocol schemas 1 and 2 nothing changes: a test_benign session of a two-VM plan waits
    only for the roles of the lower ranks (none waits for a group of the other VM), while under schema 3 the same wait
    holds a test group back until the groups before it in the plan have started."""
    doc = json.loads(collection.DEFAULT.read_text())
    del doc["domain"], doc["target"]
    doc.update(roles={"train": 2, "dev": 2, "calibration": 2, "test_benign": 4}, min_free_gib=0,
               vms=[{"name": "a", "domain": "hyptcn-lab", "port": 18080},
                    {"name": "b", "domain": "hyptcn-lab-b", "port": 18081}])
    (tmp_path / "protocol.json").write_text(json.dumps(doc))
    old = collection.protocol(tmp_path / "protocol.json")
    assert old["schema"] == "hyptcn3/collection-protocol/2"
    rows = collection.plan(old)["sessions"]
    for i, row in enumerate(rows):
        row["session_id"] = f"stary_{i:02d}_{row['vm']}"
    for name in ("START_GRACE_S", "WAIT_POLL_S"):  # No runner is active: a wait ends with its reason at once.
        monkeypatch.setattr(c, name, 0)
    for name, (p, manifest) in {"v5": v5_file_plan()[:2], "old": (old, {"sessions": rows})}.items():
        directory = tmp_path / name
        for child in ("groups", "attempts", "events"):
            (directory / child).mkdir(parents=True)
        lower_ranks_done(directory, manifest, p)
        tested = [r for r in manifest["sessions"] if r["role"] == "test_benign"]
        firsts = [first_row(manifest, g) for g in dict.fromkeys(r["group"] for r in tested)]
        waits = {r["group"]: c.wait_for_earlier_roles(directory, manifest, p, r) for r in firsts}
        if name == "old":
            assert set(waits.values()) == {None} and len(waits) == 4
            assert all(c.earlier_groups(directory, manifest, p, r) == [] for r in firsts)
            assert not (directory / "status-a.json").exists() and not (directory / "status-b.json").exists()
        else:
            assert [w is None for w in waits.values()] == [True] + [False] * (len(waits) - 1)


def test_order_rule_states_the_order_inside_the_shared_rank():
    """F5: ORDER_RULE, the text init writes into campaign.json (RULES), states the order inside the shared rank of the
    two test roles and no longer that neither of them waits for the other."""
    order = " ".join(c.ORDER_RULE.split())
    assert "neither waits" not in order and c.RULES["order"] == c.ORDER_RULE
    for phrase in ("p['interleave']", "precedes it in the plan", "groups/<group>.json", "after the pretouch",
                   "START_GRACE_S", "operator's stop request", "cannot deadlock", "schemas 1 and 2"):
        assert phrase in order, phrase


def test_a_group_start_rejection_is_never_replaced_as_the_rule_says(tmp_path):
    """F7 of the verification of B9a: GROUP_START_RULE (written into campaign.json) and reject() state that a rejection
    with the cause group_start is never replaced, why no protocol may cover it, that the runner stops by name and that
    package B9b ends the campaign with a record; and so it is: REPLACEMENT_CAUSES lacks group_start, and the loader
    refuses a replacement rule whose covers name it (the verifier's probe sondy/s/covers.py)."""
    for text in (" ".join(c.GROUP_START_RULE.split()), " ".join(c.reject.__doc__.split())):
        assert "its covers decide whether group_start is replaced" not in text
        for phrase in ("A rejection with the cause group_start is never replaced", "no protocol may cover group_start",
                       "collection.check_replacement admits in replacement.covers only REPLACEMENT_CAUSES "
                       "(audit_rejected, capture_incomplete)", "the runner stops by name",
                       "package B9b ends the campaign with a record"):
            assert phrase in text, phrase
    assert c.RULES["group_start"] == c.GROUP_START_RULE
    assert set(collection.REPLACEMENT_CAUSES) == {"audit_rejected", "capture_incomplete"}
    (tmp_path / "source").mkdir()
    doc = json.loads(v5_protocol(tmp_path / "source" / "protocol.json", limit=1).read_text())
    doc["replacement"]["covers"] = [*doc["replacement"]["covers"], "group_start"]
    (tmp_path / "covers.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="invalid replacement rule"):
        collection.protocol(tmp_path / "covers.json")


def test_v5_every_group_of_both_modes_resets_to_the_one_seeded_level(v5):
    """F4 of the verification of B9a (GROUP_START_RULE; proposal 5.4, chapter 12, Q18): every group of a rehearsal and
    of a campaign starts with labctl reset --seed protocol_v5.reset_seed(p), the protocol's one seeded level, and its
    record keeps the seed and the guest's echo of it."""
    from scripts import protocol_v5
    rule = " ".join(c.GROUP_START_RULE.split())
    assert "the protocol's one seeded level (protocol_v5.reset_seed(p)" in rule and "reset_seed(p, group" not in rule
    v5_protocol(v5["protocol"], limit=1)
    seed = protocol_v5.reset_seed(collection.protocol(v5["protocol"]))
    seen = {}
    for mode, changes in (("rehearsal", {}), ("campaign", {"estimate_from": ended_rehearsal(v5)})):
        directory = v5_init(v5, mode, **changes)
        run_v5(directory)
        groups = list(dict.fromkeys(r["group"] for r in read_json(directory / "campaign.json")["sessions"]))
        for group in groups:
            record = read_json(directory / "groups" / (group + ".json"))["start"]
            reset = next(s for s in record["steps"] if s["step"] == "reset")
            seen[mode, group] = (record["reset_seed"], reset["seed"], reset["output"]["seed"])
    assert len({group for mode, group in seen if mode == "rehearsal"}) == 5
    assert len({group for mode, group in seen if mode == "campaign"}) == 10
    assert set(seen.values()) == {(seed, seed, seed)}
    resets = [call for call in v5["calls"] if call[0] == "lab" and call[2] == "reset"]
    assert len(resets) == 15


def after_lab_verb(monkeypatch, verb, change):
    """The child of the v5 fixture, and then change(log, vm) once labctl `verb` has returned (what labctl or the
    guest did instead of the step's result; F6 of the verification of B9a)."""
    inner = c.run_child

    def child(command, log, **kw):
        rc = inner(command, log, **kw)
        command = list(map(str, command))
        labctl = str(c.ROOT / "scripts/labctl.py")
        if labctl in command and command[command.index(labctl) + 1] == verb:
            change(log, command[command.index("--vm") + 1])
        return rc
    monkeypatch.setattr(c, "run_child", child)


@pytest.mark.parametrize("case, verb, step, said", [
    # mutant start_seed_echo_unchecked: labctl reset exits 0, the guest echoes another seed
    ("another_seed", "reset", "reset", "the guest reset to seed 1, not 0"),
    # mutant start_touch_unchecked: labctl pretouch exits 0 but prints touched: false
    ("untouched", "pretouch", "pretouch", "the pretouch did not touch the memory of the largest event"),
    # mutant start_identity_unchecked: the guest identity changes between the start and the pretouch
    ("identity", "reset", "pretouch", "the guest identity changed during the reset or the pretouch"),
    # mutant start_qemu_after_unchecked: the QEMU process changes between the start and the pretouch
    ("qemu", "pretouch", "pretouch", "the QEMU process changed during the reset or the pretouch"),
])
def test_v5_group_start_refuses_a_step_whose_result_is_not_what_it_asked(v5, monkeypatch, case, verb, step, said):
    """GROUP_START_RULE (F6 of the verification of B9a): a step that exits 0 without the result the start asked for is
    refused by name: the guest must echo the protocol's seed after labctl reset, labctl pretouch must have touched the
    memory, and the guest identity and the QEMU process after the pretouch must be those after the start. The group's
    first session is rejected with the cause group_start before its measured phase, nothing is replaced, captured or
    recorded as the group."""
    directory = v5_init(v5)
    first = first_of(directory)

    def change(log, vm):
        if case == "another_seed":
            record, = [json.loads(line) for line in log.read_text().splitlines()]
            log.write_text(json.dumps(dict(record, seed=record["seed"] + 1)) + "\n")
        elif case == "untouched":
            log.write_text(json.dumps({"schema": "hyptcn3/guest-pretouch/1", "touched": False}) + "\n")
        elif case == "identity":
            v5["boot"][vm] += "-rebooted"
        else:
            v5["qemu"][vm] = dict(v5["qemu"][vm], pid=v5["qemu"][vm]["pid"] + 1000)
    after_lab_verb(monkeypatch, verb, change)
    with pytest.raises(ValueError, match="^" + re.escape(f"{c.STOP_MESSAGE['group_start']}: {step}: {said}") + "$"):
        c.execute(directory, vm="a")
    record, = c.rejections(directory)
    assert (record["session"], record["cause"], record["reasons"], record["replacement"]) \
        == (first["session_id"], "group_start", [f"{step}: {said}"], None)
    assert [call[2] for call in v5["calls"] if call[0] == "lab"] \
        == ["stop", "start", "reset", *(["pretouch"] if step == "pretouch" else [])]  # refused at its step
    assert not any(call[0] == "capture" for call in v5["calls"])
    assert not (directory / "groups" / (first["group"] + ".json")).exists()


def test_v5_seal_whose_result_lacks_the_session_is_refused_by_name(v5, monkeypatch):
    """SEAL_RULE (F6 of the verification of B9a, mutant seal_result_unchecked): python -m tcn.pecat zapis exits 0 with a
    result whose written and already lists lack the feature archive of the session: the seal is refused by name, and
    the session gets no checkpoint, so it is no accepted session of the campaign."""
    directory = v5_init(v5)
    inner, results = c.run_child, []

    def child(command, log, **kw):
        command = list(map(str, command))
        if "tcn.pecat" not in command:
            return inner(command, log, **kw)
        audit = Path(command[command.index("--audit") + 1])
        result = {"ledger": str(v5["ledger"]), "mode": "rehearsal", "written": [], "already": ["0" * 64],
                  "audit": str(audit), "session": read_json(audit.parent / "session.json")["session_id"]}
        results.append(result)
        log.write_text(json.dumps(result) + "\n")
        return 0
    monkeypatch.setattr(c, "run_child", child)
    with pytest.raises(ValueError, match=r"^the seal of session (\S+): the ledger holds no record of its feature "
                                         r"archive after zapis \(see .*seal_\S+\.log\)$") as refused:
        for _ in range(6):
            for vm in ("a", "b"):
                c.execute(directory, vm=vm)
    result, = results
    sid = result["session"]
    assert str(refused.value).startswith(f"the seal of session {sid}: ")
    row = next(r for r in read_json(directory / "campaign.json")["sessions"] if r["session_id"] == sid)
    assert row["role"] in ("test_benign", "test_controls")
    assert not (directory / "attempts" / (sid + ".done.json")).exists()
    assert not v5["ledger"].exists()


def test_v5_null_limit_is_refused_by_name_at_run_time(tmp_path):
    """LIMIT_RULE (F6 of the verification of B9a, mutant null_limit_is_0): at run time replacement_limit refuses a
    null replacement.max_per_campaign in mode campaign by name, and so does reject before it writes a record; mode
    rehearsal applies no limit. Init refuses a null limit first (test_v5_init_refuses_by_name), so both are called
    directly."""
    from scripts import protocol_v5
    (tmp_path / "source").mkdir()
    p = collection.protocol(v5_protocol(tmp_path / "source" / "protocol.json", limit=None))
    assert p["replacement"]["max_per_campaign"] is None
    with pytest.raises(ValueError, match="^" + re.escape(c.NULL_LIMIT) + "$"):
        c.replacement_limit({"mode": "campaign"}, p)
    assert c.replacement_limit({"mode": "rehearsal"}, p) == (False, None)
    row = dict(protocol_v5.plan(p, mode="campaign")["sessions"][0], session_id="kampan_01")
    directory = tmp_path / "campaign"
    (directory / "attempts").mkdir(parents=True)
    with pytest.raises(ValueError, match="^" + re.escape(c.NULL_LIMIT) + "$"):
        c.reject(directory, {"mode": "campaign", "sessions": [row]}, p, row, "audit_rejected", ["missed sampling slot"])
    assert list((directory / "attempts").iterdir()) == []


def test_v5_status_counts_its_own_vm_and_the_index_has_a_key_of_its_own(v5):
    """The connection of the fix round of B9a (agent T's merge point 1, a bug the real index showed): each runner's
    accepted_archived is the count of its own VM, the done checkpoints of that VM, which campaign_report.py compares it
    with; a runner that builds the index of every VM (or, run again after it, checks the index against the one there)
    writes the count of the index under indexed_sessions."""
    directory = v5_init(v5)
    run_v5(directory)
    manifest = read_json(directory / "campaign.json")
    done = {vm: sum((directory / "attempts" / (r["session_id"] + ".done.json")).exists()
                    for r in manifest["sessions"] if r["vm"] == vm) for vm in ("a", "b")}
    states = {vm: read_json(directory / f"status-{vm}.json") for vm in ("a", "b")}
    assert {vm: state["accepted_archived"] for vm, state in states.items()} == done
    assert sum(done.values()) == len(manifest["sessions"]) and min(done.values()) > 0
    built = {vm: state["indexed_sessions"] for vm, state in states.items() if "indexed_sessions" in state}
    index = read_json(directory / "corpus.json")
    assert built and set(built.values()) == {len(index["sessions"])} == {len(manifest["sessions"])}
