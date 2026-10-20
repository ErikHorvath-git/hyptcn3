import json
import os
import shutil
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import campaign as c
from scripts import collection
from scripts.collection_archive import digest, read_json, write_new


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Fake capture/audit subprocesses; real orchestration, files and archiver."""
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
    p["roles"] = dict.fromkeys(("train", "dev", "calibration", "test_benign"), 1)
    p["scenarios"] = {k: p["scenarios"][k] for k in ("quiet", "steady")}
    write_new(directory / "protocol.json", p)
    write_new(directory / "pilot.json", {"synthetic": True})
    rows = collection.plan(p)["sessions"]
    for i, row in enumerate(rows):
        row["session_id"] = f"test-campaign_{i:02d}"
    env = {"kernel": "test-kernel", "machine_id": "test-machine", "stack_sha256": "test-stack"}
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": directory.name,
                "workspace": str(c.ROOT), "commit": "test-commit", "sessions": rows,
                "owner": {"name": "test-owner"}, "extractor_sha256": {"test": "test"},
                "guest_environment": env, "protocol_sha256": digest(directory / "protocol.json"),
                "pilot_report_sha256": digest(directory / "pilot.json"),
                "archive_dir": str(external), "archive_root": str(external), "archive_mount": {},
                "planned_capture_hours": len(rows)}
    write_new(directory / "campaign.json", manifest)
    state = {"directory": directory, "manifest": manifest, "p": p, "rows": rows,
             "captures": captures, "calls": [], "boot": "pilot-boot", "reboots": 0,
             "capture_complete": True, "audit_accepted": True, "interrupt_audit": False,
             "truncate_audit": False}
    monkeypatch.setattr(c, "COLLECTIONS", captures)
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
            sid = command[command.index("--session-id") + 1]
            row = next(r for r in rows if r["session_id"] == sid)
            assert command[command.index("--expected-boot-id") + 1] == state["boot"]
            assert kw["lock_fd"] >= 0
            src = captures / sid
            src.mkdir()
            (src / "raw").mkdir()
            (src / "raw/frame.vmicd").write_bytes(b"synthetic RAM " + sid.encode())
            identity = {**env, "boot_id": state["boot"]}
            write_new(src / "session.json", {**row, "schema": "hyptcn3/collection-session/1",
                       "campaign_id": manifest["id"], "commit": manifest["commit"], "commit_dirty": False,
                       "protocol_sha256": manifest["protocol_sha256"], "guest_before": identity})
            write_new(src / "end.json", {"completed": state["capture_complete"], "guest_after": identity})
            return 0 if state["capture_complete"] else 2
        assert "audit" in command
        state["calls"].append("audit")
        src = Path(command[command.index("audit") + 1])
        report = Path(command[command.index("--out") + 1])
        feature = report.with_suffix(".npz")
        feature.write_bytes(b"synthetic feature archive")
        if state["interrupt_audit"]:
            raise InterruptedError("interrupted extractor")
        if state["truncate_audit"]:
            report.write_text('{"schema":')
            return 2
        row = next(r for r in rows if r["session_id"] == src.name)
        write_new(report, {"schema": "hyptcn3/collection-audit/1", "commit": manifest["commit"],
                  "commit_dirty": False, "values": {"accepted": state["audit_accepted"],
                  "reasons": [] if state["audit_accepted"] else ["synthetic rejection"],
                  "protocol_sha256": manifest["protocol_sha256"], "extractor_sha256": manifest["extractor_sha256"],
                  "session_dir": str(src), "role": row["role"], "session_sha256": digest(src / "session.json"),
                  "source_sha256": {"frame.vmicd": digest(src / "raw/frame.vmicd")},
                  "features": str(feature), "features_sha256": digest(feature)}})
        return 0 if state["audit_accepted"] else 2
    monkeypatch.setattr(c, "run_child", child)
    def finish(directory, manifest, p, reports):
        assert len(reports) == len(rows)
        assert len(set(reports)) == len(rows)
        c.update_state(directory, status="complete", stage="complete")
    monkeypatch.setattr(c, "finish_corpus", finish)
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
