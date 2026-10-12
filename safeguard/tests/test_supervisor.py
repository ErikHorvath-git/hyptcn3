"""Collector lifecycle tests use process doubles; no VM, sudo or eBPF execution."""
import json
from pathlib import Path
import signal
import subprocess
import threading
from types import SimpleNamespace

import pytest

from safeguard import supervisor
from scripts import collection


class Process:
    def __init__(self, code=None, ignore_term=False):
        self.returncode = code
        self.ignore_term = ignore_term
        self.terminated = self.killed = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated += 1
        if not self.ignore_term:
            self.returncode = -15

    def kill(self):
        self.killed += 1
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fixture collector", timeout)
        return self.returncode


@pytest.fixture
def setup(tmp_path, monkeypatch):
    actual_root = Path(__file__).resolve().parents[2]
    root = tmp_path / "repo"
    root.mkdir()
    for dirname in ("features", "guestparse"):
        directory = root / dirname
        directory.mkdir()
        (directory / "__init__.py").write_text("# lifecycle fixture\n")
    for name in supervisor.INFERENCE_SOURCES:
        source = root / name
        source.parent.mkdir(exist_ok=True)
        source.write_text("# inference implementation fixture\n")
    protocol = json.loads((actual_root / "config/collection-v1.json").read_text())
    protocol["min_free_gib"] = 1
    protocol_path = root / "protocol.json"
    protocol_path.write_text(json.dumps(protocol))
    profile = root / "profile"
    profile.mkdir()
    for name in ("kallsyms.txt", "btf.txt"):
        (profile / name).write_text("fixture guest profile")
    (profile / "nested").mkdir()
    (profile / "nested/meta.json").write_text('{"fixture": true}')
    binary = root / "collector"
    binary.write_text("fixture collector, never executed")
    binary.chmod(0o755)
    monkeypatch.setattr(supervisor, "ROOT", root)
    monkeypatch.setattr(supervisor, "_WATCH_INTERVAL", 0.005)
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(supervisor.shutil, "disk_usage", lambda _: SimpleNamespace(free=2 * 2**30))
    guest = {"kernel": "fixture-kernel", "stack_sha256": "fixture-stack", "boot_id": "fixture-boot"}
    monkeypatch.setattr(collection, "guest_identity", lambda _: dict(guest))
    environment = {"kernel": guest["kernel"], "stack_sha256": guest["stack_sha256"],
                   "profile_sha256": supervisor._profile_hashes(profile),
                   "extractor_sha256": supervisor._extractor_hashes(),
                   "collector_sha256": supervisor.digest(binary)}
    bundle = SimpleNamespace(
        contract={"window_rows": protocol["window_rows"], "max_gap_s": protocol["max_gap_s"],
                  "layout": {"bin_bytes": protocol["bin_bytes"]}},
        manifest={"diagnostic": False, "environment": environment,
                  "provenance": {"protocol_sha256": supervisor.digest(protocol_path),
                                 "source_sha256": {name: supervisor.digest(root / name)
                                                   for name in supervisor.INFERENCE_SOURCES}}})
    process = Process()
    commands = []
    def launch(command, **kwargs):
        commands.append((command, kwargs))
        return process
    monkeypatch.setattr(supervisor.subprocess, "Popen", launch)
    def detector(*args, stop_event, **kwargs):
        assert stop_event.wait(2), "collector watcher did not finish"
        return {"ok": True, "processed": 3, "scored": 1}
    monkeypatch.setattr(supervisor, "run_directory", detector)
    return SimpleNamespace(root=root, protocol=protocol, protocol_path=protocol_path, profile=profile,
                           binary=binary, bundle=bundle, process=process, commands=commands,
                           output=root / "run", guest=guest)


def run(setup):
    return supervisor.supervise(setup.bundle, setup.protocol_path, setup.profile, "fixture-guest",
                                 setup.output, cycles=2, binary=setup.binary)


def no_watcher_left():
    assert not any(t.name == "safeguard-collector" for t in threading.enumerate())


def test_command_is_explicit_bounded_and_retention_preserves_evidence(setup):
    command = supervisor.collector_command(setup.binary, setup.output / "raw", "a guest",
                                            setup.protocol, 2)
    assert command[:2] == [str(setup.binary), "run"]
    assert command[2::2] == ["-o"] * len(command[3::2])
    options = dict(item.split("=", 1) for item in command[3::2])
    assert options["vm.domain"] == "a guest" and options["vm.backend"] == "ebpf"
    assert options["schedule.max_cycles"] == "2"
    assert options["schedule.interval_s"] == "5"
    assert options["features.bin_bytes"] == str(setup.protocol["bin_bytes"])
    assert options["features.entropy"] == "true"
    assert options["output.hash"] == "sha256"
    assert all(options[name] == "0" for name in (
        "retention.max_snapshots", "retention.max_bytes", "retention.max_age_s"))
    with pytest.raises(ValueError):
        supervisor.collector_command(setup.binary, setup.output, "", setup.protocol, 2)
    with pytest.raises(ValueError):
        supervisor.collector_command(setup.binary, setup.output, "vm", setup.protocol, True)


def test_live_requires_root_before_creating_output(setup, monkeypatch):
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="requires sudo"):
        run(setup)
    assert not setup.output.exists() and not setup.commands


def test_live_refuses_diagnostic_even_if_loaded_explicitly(setup):
    setup.bundle.manifest["diagnostic"] = True
    with pytest.raises(ValueError, match="non-diagnostic"):
        run(setup)
    assert not setup.commands


@pytest.mark.parametrize("mismatch", ["protocol", "profile", "extractor", "inference", "kernel", "stack", "collector", "window"])
def test_environment_mismatch_stops_before_launch(setup, mismatch):
    if mismatch == "protocol":
        setup.protocol_path.write_text(setup.protocol_path.read_text() + "\n")
    elif mismatch == "profile":
        (setup.profile / "nested/meta.json").write_text("changed")
    elif mismatch == "extractor":
        (setup.root / "features/new_parser.py").write_text("# unexpected source addition\n")
    elif mismatch == "inference":
        (setup.root / "safeguard/features.py").write_text("# incompatible inference changes\n")
    elif mismatch == "kernel":
        setup.guest["kernel"] = "another-kernel"
    elif mismatch == "stack":
        setup.guest["stack_sha256"] = "another-stack"
    elif mismatch == "collector":
        setup.binary.write_text("different executable")
    elif mismatch == "window":
        setup.bundle.contract["window_rows"] -= 1
    with pytest.raises(ValueError, match="differs|differ"):
        run(setup)
    assert not setup.commands and not setup.output.exists()


def test_normal_exit_signals_final_drain_and_preserves_manifest(setup):
    setup.process.returncode = 0
    result = run(setup)
    assert result["ok"] and result["collector_returncode"] == 0
    assert result["detector"]["processed"] == 3
    assert setup.process.terminated == 0
    metadata = json.loads((setup.output / "run.json").read_text())
    assert "nested/meta.json" in metadata["profile_sha256"]
    assert metadata["extractor_sha256"] == setup.bundle.manifest["environment"]["extractor_sha256"]
    assert json.loads((setup.output / "result.json").read_text()) == result
    no_watcher_left()


def test_fatal_detector_stops_only_its_child(setup, monkeypatch):
    monkeypatch.setattr(supervisor, "run_directory", lambda *args, **kwargs: {"ok": False, "fatal": True})
    result = run(setup)
    assert not result["ok"] and setup.process.terminated == 1
    assert setup.process.poll() is not None
    no_watcher_left()


@pytest.mark.parametrize("exception", [KeyboardInterrupt, ValueError])
def test_detector_exception_stops_child_and_records_failure(setup, monkeypatch, exception):
    def fail(*args, **kwargs):
        raise exception("intentional detector fixture failure")
    monkeypatch.setattr(supervisor, "run_directory", fail)
    with pytest.raises(exception):
        run(setup)
    result = json.loads((setup.output / "result.json").read_text())
    assert not result["ok"] and exception.__name__ in result["error"]
    assert setup.process.terminated == 1
    no_watcher_left()


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_signal_runs_cleanup_and_restores_handlers(setup, monkeypatch, sig):
    original = signal.getsignal(sig)
    def signal_arrived(*args, **kwargs):
        handler = signal.getsignal(sig)
        assert callable(handler)
        handler(sig, None)
    monkeypatch.setattr(supervisor, "run_directory", signal_arrived)
    with pytest.raises(InterruptedError, match="received signal"):
        run(setup)
    assert setup.process.terminated == 1
    assert signal.getsignal(sig) == original
    assert not json.loads((setup.output / "result.json").read_text())["ok"]
    no_watcher_left()


def test_deadline_stops_collector_then_drains_detector(setup, monkeypatch):
    monkeypatch.setattr(supervisor, "_DEADLINE_GRACE", -100)
    result = run(setup)
    assert not result["ok"] and result["stop_reason"] == "collector_deadline_exceeded"
    assert setup.process.terminated == 1
    no_watcher_left()


def test_disk_reserve_stops_collector_then_drains_detector(setup, monkeypatch):
    monkeypatch.setattr(supervisor.shutil, "disk_usage", lambda path:
                        SimpleNamespace(free=0 if Path(path) == setup.output else 2 * 2**30))
    result = run(setup)
    assert not result["ok"] and result["stop_reason"] == "disk_reserve_reached"
    assert setup.process.terminated == 1
    no_watcher_left()


def test_initial_disk_failure_never_launches(setup, monkeypatch):
    monkeypatch.setattr(supervisor.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    with pytest.raises(ValueError, match="reserve"):
        run(setup)
    assert not setup.commands and not setup.output.exists()


def test_launch_failure_writes_result_and_leaves_no_watcher(setup, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("fixture launch failed")
    monkeypatch.setattr(supervisor.subprocess, "Popen", fail)
    with pytest.raises(OSError, match="launch failed"):
        run(setup)
    result = json.loads((setup.output / "result.json").read_text())
    assert not result["ok"] and result["collector_returncode"] is None
    no_watcher_left()


def test_collection_lock_prevents_concurrent_launch(setup):
    lockpath = setup.root / "data/collections/.lock"
    lockpath.parent.mkdir(parents=True)
    with lockpath.open("a") as lock:
        supervisor.fcntl.flock(lock, supervisor.fcntl.LOCK_EX | supervisor.fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            run(setup)
    assert not setup.commands


def test_terminate_timeout_escalates_only_own_child():
    child = Process(ignore_term=True)
    supervisor.stop_child(child)
    assert child.terminated == 1 and child.killed == 1 and child.returncode == -9
