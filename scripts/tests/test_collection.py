import json
from types import SimpleNamespace

import pytest

from scripts.collection import DEFAULT, plan, protocol, run_session, analyze_windows


def test_plan_balances_scenarios_and_assigns_whole_groups():
    p = protocol(DEFAULT)
    result = plan(p)
    assert result["planned_hours"] == 48
    assert len(result["sessions"]) == 48
    groups = {}
    for s in result["sessions"]:
        assert groups.setdefault(s["group"], s["role"]) == s["role"]
    assert len({s["seed"] for s in result["sessions"]}) == 48
    for role, count in p["roles"].items():
        for scenario in p["scenarios"]:
            assert sum(s["role"] == role and s["scenario"] == scenario for s in result["sessions"]) == count
    assert plan(p) == result


def test_protocol_rejects_pilot_without_rotation(tmp_path):
    p = protocol(DEFAULT)
    p["pilot_cycles"] = 24
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError, match="two full"):
        protocol(path)


def test_protocol_rejects_unreachable_score_coverage(tmp_path):
    p = protocol(DEFAULT)
    p["pilot_cycles"] = 400
    path = tmp_path / "impossible.json"
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError, match="unreachable"):
        protocol(path)


def test_unprivileged_run_fails_before_mutating(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="sudo"):
        run_session(SimpleNamespace(), protocol(DEFAULT))


def test_v1_cannot_silently_change_input_policy(tmp_path):
    p = protocol(DEFAULT)
    p["schema"] = "hyptcn3/collection-protocol/1"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError, match="version 2"):
        protocol(path)


@pytest.mark.parametrize("primary_complete", [True, False])
@pytest.mark.parametrize("integrity_finding", [False, True])
def test_pilot_gate_distinguishes_input_loss_from_integrity_gap(primary_complete, integrity_finding):
    from features.snapshot import MENA, SCHEMA
    p = protocol(DEFAULT)
    matrix = [[0.] * len(MENA) for _ in range(p["pilot_cycles"])]
    quality = [{"model_valid": True, "behavior_valid": True, "inconclusive": [], "findings": [],
                "traversals_complete": True, "read_errors": 0, "filled_zero": 0}
               for _ in matrix]
    for i, row in enumerate(matrix):
        row[-2:] = [i != 0, i % p["full_every"] == 0]
    for i in (81, 331):
        quality[i].update(model_valid=False, behavior_valid=primary_complete,
                          inconclusive=["process_cross_view"])
        if not primary_complete:
            matrix[i + 1][-2] = 0
    # A single-snapshot cross-view difference is reported but never rejects.
    quality[81]["unconfirmed_findings"] = [{"check": "process_cross_view", "pid": 7}]
    # A process list closed by the backward walk is complete and only reported.
    quality[200]["process_walk"] = "prev"
    # So is a list cut before a tail node that init_task.prev names.
    quality[300]["process_walk"] = "tail"
    if integrity_finding:
        quality[7]["findings"] = [{"check": "synthetic-hook"}]
    result = {"schema": SCHEMA, "mena": MENA, "matica": matrix, "seq": list(range(len(matrix))),
              "casy": [float(i * p["interval_s"]) for i in range(len(matrix))],
              "quality": quality, "valid": [q["behavior_valid"] for q in quality],
              "quality_policy": p["quality_policy"], "biny": [0],
              "perbin": [[[0., 1., 0., 0.]]] * len(matrix),
              "chain_ids": [str(i // p["full_every"]) for i in range(len(matrix))],
              "layout": {"bin_bytes": 16777216, "page_size": 4096, "bins": [[0, 1]],
                         "regions": [{"gpa": 0, "bytes": 4096}], "memsize": 4096, "vcpus": 2}}
    _, windows, coverage, reasons, report = analyze_windows(result, p, "synthetic-pilot")
    assert not reasons if primary_complete and not integrity_finding else reasons
    assert (coverage >= p["min_score_coverage"]) is primary_complete
    assert report["integrity_inconclusive_rows"]["process_cross_view"] == 2
    assert report["legacy_valid_rows"] == len(matrix) - 2
    assert report["integrity_finding_rows"] == int(integrity_finding)
    assert report["integrity_unconfirmed_seq"] == [81] and report["integrity_unconfirmed"] == 1
    assert report["process_walk_prev_seq"] == [200]
    assert report["process_walk_tail_seq"] == [300]
    assert len(windows) == (416 if primary_complete else 354)


def test_interrupts_raise_once_and_record_every_signal():
    import os
    import signal
    from scripts.collection import Interrupts
    interrupts = Interrupts()
    try:
        with pytest.raises(InterruptedError):
            os.kill(os.getpid(), signal.SIGTERM)
            for _ in range(100):
                pass  # The handler runs between bytecodes.
        os.kill(os.getpid(), signal.SIGTERM)  # Second signal during cleanup must not raise.
        os.kill(os.getpid(), signal.SIGHUP)
        for _ in range(100):
            pass
        assert [r["signal"] for r in interrupts.received] == [signal.SIGTERM, signal.SIGTERM, signal.SIGHUP]
    finally:
        interrupts.restore()


def test_hangup_interrupts_like_sigterm():
    import os
    import signal
    from scripts.collection import Interrupts
    interrupts = Interrupts()
    try:
        with pytest.raises(InterruptedError, match="signal 1"):
            os.kill(os.getpid(), signal.SIGHUP)
            for _ in range(100):
                pass
    finally:
        interrupts.restore()


@pytest.mark.parametrize("argv, expected", [
    ([b"/usr/bin/python3", b"/repo/scripts/host_traffic.py", b"--profile", b"lab"], True),
    ([b"python3", b"-u", b"scripts/host_traffic.py"], True),
    ([b"/repo/scripts/host_traffic.py", b"--dur", b"0"], True),
    ([b"/venv/bin/python", b"/repo/scripts/host_monitor.py", b"run", b"--match", b"traffic=host_traffic.py"], False),
    ([b"grep", b"host_traffic.py"], False),
    ([], False),
])
def test_only_running_generator_scripts_count_as_foreign_traffic(argv, expected):
    from scripts.collection import is_generator
    assert is_generator(argv) is expected


def test_measurement_dirty_ignores_notes_reports_and_tests(monkeypatch):
    from scripts import collection
    status = (b" M scripts/collection.py\0?? scripts/campaign_report.py\0?? scripts/tests/test_new.py\0"
              b"R  features/renamed.py\0features/original.py\0 M lab/README.md\0?? vmicollect/new.c\0")
    calls = []
    monkeypatch.setattr(collection.subprocess, "check_output", lambda args, **kw: calls.append(args) or status)
    assert collection.measurement_dirty() == ["features/original.py", "features/renamed.py",
                                              "scripts/collection.py", "vmicollect/new.c"]
    assert calls[0][-len(collection.MEASUREMENT_DIRS):] == list(collection.MEASUREMENT_DIRS)
    monkeypatch.setattr(collection.subprocess, "check_output", lambda args, **kw: b"")
    assert collection.measurement_dirty() == []


def test_working_storage_identity_ignores_device_names(monkeypatch):
    from scripts import collection
    seen = []
    def findmnt(args, **kw):
        seen.append(args)
        return json.dumps({"filesystems": [{"target": "/w", "fsroot": "/work", "fstype": "ext4", "uuid": "u"}]})
    monkeypatch.setattr(collection.subprocess, "check_output", findmnt)
    assert collection.storage_identity("/w") == {"target": "/w", "fsroot": "/work", "fstype": "ext4", "uuid": "u"}
    assert "SOURCE" not in seen[0][seen[0].index("-o") + 1]


def test_preflight_waits_for_a_healthy_stack_after_a_clock_step(monkeypatch):
    import io
    import urllib.error
    from scripts import collection

    class Reply:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    replies, rids = [503, 503, 200], []

    def urlopen(request, timeout):
        rids.append(request.get_header("X-request-id"))
        code = replies.pop(0)
        if code != 200:
            raise urllib.error.HTTPError(request.full_url, code, "worker stale", {}, io.BytesIO())
        return Reply()

    monkeypatch.setattr(collection.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(collection.time, "sleep", lambda s: None)
    assert collection.wait_healthy("http://lab") == 3
    assert len(set(rids)) == 3 and all(rid.replace("-", "").isalnum() and len(rid) <= 64 for rid in rids)

    def refused(request, timeout):
        raise ConnectionRefusedError()

    monkeypatch.setattr(collection.urllib.request, "urlopen", refused)
    with pytest.raises(ValueError, match="not healthy"):
        collection.wait_healthy("http://lab", timeout=0)


def test_host_memory_records_swap_policy_and_qemu_swap():
    import os
    from scripts import collection
    doc = collection.host_memory({"pid": os.getpid()})
    assert type(doc["vm_swappiness"]) is int and type(doc["qemu_swap_kb"]) is int
    assert collection.host_memory(None)["qemu_swap_kb"] is None
    assert collection.qemu_swap_kb(2 ** 22 + 7) is None  # no such process


def test_prefault_reads_only_mappings_with_swapped_pages(monkeypatch):
    import mmap
    import os
    from scripts import collection
    smaps = ("7f0000000000-7f0000400000 rw-p 00000000 00:00 0 \nSize: 4096 kB\nSwap: 0 kB\nSwapPss: 0 kB\n"
             "7f0000400000-7f0000800000 rw-p 00000000 00:00 0 \nSize: 4096 kB\nSwap: 12 kB\n"
             "VmFlags: rd wr mr mw me ac\n"
             "55d000000000-55d000001000 r--p 00000000 08:02 123 /usr/bin/qemu-system-x86_64\nSwap: 4 kB\n")
    assert collection.swapped_ranges(smaps) == [(0x7f0000400000, 0x7f0000800000), (0x55d000000000, 0x55d000001000)]
    assert collection.prefault_swapped(os.getpid())["swap_kb_before"] is not None
    # The reader on a process it may read (this one): a real mapping and an unmapped range.
    buffer = mmap.mmap(-1, 3 << 20)
    buffer[:4] = b"page"
    import ctypes
    start = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
    swaps = iter([64, 0])
    monkeypatch.setattr(collection, "qemu_swap_kb", lambda pid: next(swaps))
    monkeypatch.setattr(collection, "swapped_ranges", lambda text: [(start, start + (3 << 20)), (8 << 40, (8 << 40) + 4096)])
    result = collection.prefault_swapped(os.getpid(), chunk=1 << 20)
    assert (result["swap_kb_before"], result["swap_kb_after"]) == (64, 0) and result["seconds"] >= 0


def test_clock_sync_margin_covers_a_session_of_measured_drift():
    from scripts import collection
    p = protocol(DEFAULT)
    hours = (p["warmup_s"] + p["cycles"] * p["interval_s"]) / 3600
    assert collection.CLOCK_SYNC_S + 0.04 * hours * 5 < 1.0  # Five times the drift seen on 2026-10-20.
