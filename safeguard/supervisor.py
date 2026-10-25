"""Bounded host collector lifecycle for the integrated detector.

Original integration. Only the child collector started here is stopped; VM and
traffic lifecycle remain explicit operations of the existing lab controller.
"""
from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import threading
import time

from .bundle import digest
from .runtime import _atomic_json, run_directory

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COLLECTOR = ROOT / "vmicollect/build/vmicollect"
_WATCH_INTERVAL = 0.5
_DEADLINE_GRACE = 120
INFERENCE_SOURCES = ("safeguard/features.py", "safeguard/model.py",
                     "safeguard/bundle.py", "tcn/model.py")


def collector_command(binary, raw, domain, protocol, cycles):
    if type(cycles) is not int or cycles < 1:
        raise ValueError("cycles must be a positive integer")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("an explicit guest domain is required")
    options = {"vm.domain": domain, "vm.backend": "ebpf", "output.dir": str(raw),
               "output.writer": "delta", "output.hash": "sha256",
               "output.delta_full_every": protocol["full_every"],
               "features.enable": "true", "features.entropy": "true",
               "features.bin_bytes": protocol["bin_bytes"],
               "retention.max_snapshots": 0, "retention.max_bytes": 0,
               "retention.max_age_s": 0, "schedule.interval_s": protocol["interval_s"],
               "schedule.max_cycles": cycles,
               # The collector runs as root here: lock its queue memory like the campaign does,
               # and keep its final drain below the run deadline grace.
               "output.mlock": "true", "output.drain_s": 90}
    return [str(binary), "run", *[argument for k, v in options.items()
                                  for argument in ("-o", f"{k}={v}")]]


def stop_child(process):
    if process.poll() is None:
        process.terminate()
        try:
            # After SIGTERM the collector still publishes its queued snapshots (at most 40 s) and
            # stops its log thread (at most 5 s); a shorter grace would kill it mid-publication.
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@contextmanager
def _termination_handlers():
    """SIGTERM/SIGHUP must run the same cleanup as an interrupted terminal."""
    state = {"cleaning": False}
    old = {}
    def interrupted(signum, _frame):
        if not state["cleaning"]:
            raise InterruptedError("supervisor received signal " + str(signum))
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGHUP):
            old[sig] = signal.signal(sig, interrupted)
    try:
        yield state
    finally:
        for sig, previous in old.items():
            signal.signal(sig, previous)


def _profile_hashes(profile):
    return {str(path.relative_to(profile)): digest(path)
            for path in sorted(profile.rglob("*")) if path.is_file()}


def _extractor_hashes():
    return {str(path.relative_to(ROOT)): digest(path)
            for directory in ("features", "guestparse")
            for path in sorted((ROOT / directory).rglob("*.py")) if "tests" not in path.parts}


def supervise(bundle, protocol_path, profile, domain, output_dir, *, cycles=None,
              binary=DEFAULT_COLLECTOR):
    from scripts.collection import guest_identity, protocol as read_protocol
    if os.geteuid() != 0:
        raise PermissionError("host eBPF capture requires sudo; replay and training do not")
    if bundle.manifest.get("diagnostic") is not False:
        raise ValueError("live capture requires a non-diagnostic trained and calibrated bundle")
    protocol_path, profile, binary = map(lambda p: Path(p).resolve(), (protocol_path, profile, binary))
    protocol = read_protocol(protocol_path)
    provenance = bundle.manifest["provenance"]
    environment = bundle.manifest["environment"]
    if digest(protocol_path) != provenance["protocol_sha256"]:
        raise ValueError("live protocol differs from trained bundle")
    if (bundle.contract["window_rows"] != protocol["window_rows"]
            or bundle.contract["max_gap_s"] != protocol["max_gap_s"]
            or bundle.contract["layout"]["bin_bytes"] != protocol["bin_bytes"]):
        raise ValueError("live feature settings differ from trained bundle")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("collector binary unavailable; run make build")
    for name in ("kallsyms.txt", "btf.txt"):
        if not (profile / name).is_file():
            raise ValueError("missing guest profile file: " + name)
    profile_hashes = _profile_hashes(profile)
    extractor_hashes = _extractor_hashes()
    if not environment.get("profile_sha256") or profile_hashes != environment["profile_sha256"]:
        raise ValueError("guest profile differs from trained environment")
    if not environment.get("extractor_sha256") or extractor_hashes != environment["extractor_sha256"]:
        raise ValueError("feature extractor differs from trained environment")
    inference_hashes = {name: digest(ROOT / name) for name in INFERENCE_SOURCES}
    saved_sources = provenance.get("source_sha256", {})
    if any(saved_sources.get(name) != value for name, value in inference_hashes.items()):
        raise ValueError("model inference implementation differs from trained bundle")
    reserve_gib = protocol["min_free_gib"]
    if (isinstance(reserve_gib, bool) or not isinstance(reserve_gib, (int, float))
            or not math.isfinite(reserve_gib) or reserve_gib <= 0):
        raise ValueError("min_free_gib must be finite and positive")
    cycles = protocol["cycles"] if cycles is None else cycles
    command = collector_command(binary, Path(output_dir).resolve() / "raw", domain, protocol, cycles)
    # Share the capture lock with the corpus runner: simultaneous collectors
    # change the experiment and compete for the same host kernel resources.
    lock_path = ROOT / "data/collections/.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guest = guest_identity({**protocol, "domain": domain})
        if any(guest[key] != environment[key] for key in ("kernel", "stack_sha256")):
            raise ValueError("guest kernel/software differs from trained environment")
        if digest(binary) != environment["collector_sha256"]:
            raise ValueError("collector differs from trained environment")
        output = Path(output_dir).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        reserve = reserve_gib * 2**30
        if shutil.disk_usage(output.parent).free < reserve:
            raise ValueError("free disk is below the collection protocol reserve")
        output.mkdir(exist_ok=False)
        raw = output / "raw"
        raw.mkdir()
        metadata = {"schema": "hyptcn3/safeguard-supervisor/1", "started_utc": datetime.now(timezone.utc).isoformat(),
                    "domain": domain, "guest": guest, "command": command,
                    "protocol_sha256": digest(protocol_path), "collector_sha256": digest(binary),
                    "bundle_manifest": bundle.manifest, "profile": str(profile),
                    "profile_sha256": profile_hashes, "extractor_sha256": extractor_hashes,
                    "inference_sha256": inference_hashes,
                    "diagnostic": bundle.manifest["diagnostic"]}
        with (output / "run.json").open("x") as stream:
            json.dump(metadata, stream, indent=2, allow_nan=False)
        stopped, watcher_done = threading.Event(), threading.Event()
        issue = {}
        deadline = time.monotonic() + cycles * protocol["interval_s"] + _DEADLINE_GRACE
        with _termination_handlers() as handlers, (output / "collector.log").open("x") as log:
            process, watcher = None, None
            child_lock = threading.Lock()

            def stop_owned_child():
                with child_lock:
                    stop_child(process)

            def watch():
                try:
                    while not watcher_done.wait(_WATCH_INTERVAL):
                        if process.poll() is not None:
                            break
                        if shutil.disk_usage(output).free < reserve:
                            issue["reason"] = "disk_reserve_reached"
                            stop_owned_child()
                            break
                        if time.monotonic() > deadline:
                            issue["reason"] = "collector_deadline_exceeded"
                            stop_owned_child()
                            break
                except Exception as exc:
                    issue["reason"] = "collector_watch_error: " + str(exc)
                finally:
                    stopped.set()

            summary, failure = None, None
            try:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT)
                watcher = threading.Thread(target=watch, name="safeguard-collector")
                watcher.start()
                summary = run_directory(bundle, raw, profile, output / "detector", follow=True,
                                        stop_event=stopped, preserve=True, hold_binary=str(binary))
            except BaseException as exc:
                failure = type(exc).__name__ + ": " + str(exc)
                raise
            finally:
                handlers["cleaning"] = True
                watcher_done.set()
                if process is not None:
                    try:
                        stop_owned_child()
                    except Exception as exc:
                        issue["cleanup"] = type(exc).__name__ + ": " + str(exc)
                if watcher is not None and watcher.ident is not None:
                    watcher.join()
                result = {"schema": "hyptcn3/safeguard-supervisor-result/1",
                          "finished_utc": datetime.now(timezone.utc).isoformat(),
                          "collector_returncode": process.returncode if process is not None else None,
                          "error": failure, "cleanup_error": issue.get("cleanup"),
                          "stop_reason": issue.get("reason"), "detector": summary,
                          "ok": bool(summary and summary["ok"] and process is not None and process.returncode == 0
                                     and not failure and not issue)}
                _atomic_json(output / "result.json", result)
        return result
