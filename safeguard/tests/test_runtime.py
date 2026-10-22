"""Runtime state/evidence tests with deterministic model outputs, not detection claims."""
import json
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import numpy as np
import pytest

from features.snapshot import MENA, SCHEMA
from safeguard.features import Frame, feature_contract
from safeguard import runtime


def frame(seq, *, timestamp=None, full=False, valid=True, predecessor=True,
          findings=None, inconclusive=None, chain="1791292684568", vcpus=2):
    vector = np.ones(len(MENA))
    vector[-2:] = [predecessor, full]
    quality = dict(model_valid=valid, behavior_valid=valid, traversals_complete=valid,
                   findings=findings or [], inconclusive=inconclusive or [],
                   read_errors=0, filled_zero=0)
    return Frame("test-session", seq, 1000 + seq * 5 if timestamp is None else timestamp,
                 vector, np.array([[0.25, 0.0, 4.0, 1.0]]), (0,), quality, chain,
                 dict(bin_bytes=16384, page_size=4096, bins=[[0, 4]],
                      regions=[{"gpa": 0, "bytes": 16384}], memsize=16384, vcpus=vcpus))


class FakeBundle:
    """A score oracle isolates state transitions from optimization randomness."""
    threshold, k, n = 1.0, 1, 1
    manifest = {"calibration": {"diagnostic": True}}

    def __init__(self, *, window=3, k=1, n=1, scores=None):
        self.contract = feature_contract(frame(0), window, 7.5)
        self.k, self.n = k, n
        self.scores = scores or {}
        self.windows = []

    def score(self, window):
        self.windows.append([row.seq for row in window])
        value = self.scores.get(window[-1].seq, 2.0)
        return {"score": value, "global_error": value,
                "bin_errors": [{"bin": 0, "error": value}],
                "activity": "steady", "activity_probabilities": {"steady": 1.0}}


def test_warmup_integrity_and_missing_baseline_are_independent():
    model = FakeBundle()
    detector = runtime.Detector(model, preserve=False)
    first = detector.process(frame(0, full=True, predecessor=False,
                                    findings=[{"check": "syscall_hook", "index": 7}],
                                    inconclusive=["text_integrity"]))
    assert first["state"] == "alarm"
    assert first["model_state"] == "warming_up"
    assert first["score"] is None and first["alarm_event"]
    assert first["integrity"]["conclusive"] is False
    assert first["evidence"]["status"] == "disabled"
    second = detector.process(frame(1, inconclusive=["text_integrity"]))
    assert second["integrity"]["status"] == "inconclusive"
    assert not second["alarm"] and second["state"] == "warming_up"
    assert not model.windows


def test_integrity_finding_on_invalid_input_is_not_suppressed():
    row = runtime.Detector(FakeBundle(), preserve=False).process(
        frame(0, valid=False, findings=[{"check": "text_integrity", "va": 4096}]))
    assert row["state"] == "alarm" and row["model_state"] == "input_error"
    assert row["integrity_alarm"] and row["score"] is None


def test_inconclusive_cross_view_is_input_error_without_integrity_alarm():
    row = runtime.Detector(FakeBundle(), preserve=False).process(
        frame(0, valid=False, inconclusive=["process_cross_view"]))
    assert row["state"] == "input_error"
    assert row["integrity"]["status"] == "inconclusive"
    assert not row["alarm"] and not row["integrity_alarm"]
    assert row["score"] is None


def test_unconfirmed_cross_view_difference_is_reported_without_alarm():
    hidden = {"check": "process_cross_view", "pid": 450961, "seen_in": "tasks",
              "missing_in": "children/sibling"}
    detector = runtime.Detector(FakeBundle(scores={0: 0.0, 1: 0.0}), preserve=False)
    row = frame(0)
    first = detector.process(replace(row, quality={
        **row.quality, "model_valid": False, "inconclusive": ["process_cross_view"],
        "unconfirmed_findings": [hidden]}))
    assert first["integrity"]["status"] == "inconclusive"
    assert first["integrity"]["unconfirmed"] == [hidden]
    assert not first["integrity_alarm"] and not first["alarm"]
    # The extractor moves the difference to findings once the next snapshot repeats it.
    second = detector.process(frame(1, findings=[hidden]))
    assert second["integrity_alarm"] and second["alarm_sources"] == ["kernel_integrity"]


@pytest.mark.parametrize("independent_finding", [False, True])
def test_integrity_gap_preserves_behavior_windows_and_independent_alarm(independent_finding):
    detector = runtime.Detector(FakeBundle(window=2, scores={2: 0.0}), preserve=False)
    detector.process(frame(1))
    row = frame(2)
    quality = {**row.quality, "model_valid": False, "inconclusive": ["process_cross_view"],
               "findings": [{"check": "syscall_hook"}] if independent_finding else []}
    result = detector.process(replace(row, quality=quality))
    assert result["score"] == 0.0
    assert result["integrity"]["conclusive"] is False
    assert result["integrity_alarm"] is independent_finding
    assert result["alarm"] is independent_finding


def test_event_counts_are_rising_edges_and_threshold_is_strict():
    detector = runtime.Detector(FakeBundle(window=1, k=2, n=2,
        scores={1: 1.0, 2: 2.0, 3: 2.0, 4: 2.0, 5: 0.0, 6: 2.0, 7: 2.0}), preserve=False)
    rows = [detector.process(frame(i)) for i in range(1, 8)]
    assert [row["alarm"] for row in rows] == [False, False, True, True, False, False, True]
    assert [row["seq"] for row in rows if row["alarm_event"]] == [3, 7]
    assert detector.event_count == 2


@pytest.mark.parametrize("barrier", ["full", "invalid", "gap", "no_predecessor"])
def test_barriers_reset_voting_history(barrier):
    detector = runtime.Detector(FakeBundle(window=1, k=2, n=2), preserve=False)
    assert not detector.process(frame(1))["alarm"]
    seq = 4 if barrier == "gap" else 2
    middle = detector.process(frame(seq, full=barrier == "full", valid=barrier != "invalid",
                                      predecessor=barrier != "no_predecessor"))
    assert not middle["alarm"]
    following = detector.process(frame(seq + 1))
    assert following["alarm"] == (barrier == "gap")


def test_timestamp_error_resets_then_can_recover():
    detector = runtime.Detector(FakeBundle(window=2), preserve=False)
    detector.process(frame(1))
    invalid = detector.process(frame(2, timestamp=1000))
    assert invalid["state"] == "input_error" and invalid["recoverable"]
    assert detector.process(frame(3))["state"] == "warming_up"
    assert detector.process(frame(4))["score"] == 2.0


def test_contract_change_stops_instead_of_adapting():
    detector = runtime.Detector(FakeBundle(window=1), preserve=False)
    detector.process(frame(1))
    invalid = detector.process(frame(2, vcpus=4))
    assert invalid["fatal"] and not invalid["recoverable"]
    assert "feature_contract_mismatch" in invalid["reason"]
    with pytest.raises(RuntimeError, match="stopped"):
        detector.process(frame(3))


def test_nonfinite_model_output_stops():
    detector = runtime.Detector(FakeBundle(window=1, scores={1: float("nan")}), preserve=False)
    row = detector.process(frame(1))
    assert row["fatal"] and row["score"] is None
    assert row["state"] == "input_error"


def test_hold_uses_actual_chain_id_and_does_not_repeat(monkeypatch, tmp_path):
    calls = []
    def hold(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stderr="", stdout="")
    monkeypatch.setattr(runtime.subprocess, "run", hold)
    detector = runtime.Detector(FakeBundle(window=2, k=2, n=2), tmp_path, "/local/vmicollect")
    rows = [detector.process(frame(i)) for i in range(1, 6)]
    assert calls == [["/local/vmicollect", "hold", str(tmp_path), "1791292684568"]]
    assert sum(row["alarm_event"] for row in rows) == 1
    assert rows[-1]["evidence"]["held_chain_ids"] == ["1791292684568"]
    assert [item.seq for item in detector.context] == [3, 4, 5]


def test_hold_error_is_visible_and_retried(monkeypatch, tmp_path):
    outcomes = iter([SimpleNamespace(returncode=2, stderr="permission denied", stdout=""),
                     SimpleNamespace(returncode=0, stderr="", stdout="")])
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: next(outcomes))
    detector = runtime.Detector(FakeBundle(window=1), tmp_path)
    first = detector.process(frame(1))
    assert first["evidence"]["status"] == "error"
    assert "permission denied" in first["evidence"]["error"]
    second = detector.process(frame(2))
    assert second["evidence"]["status"] == "held" and not second["alarm_event"]


def test_missing_hold_program_is_visible(monkeypatch, tmp_path):
    def missing(*args, **kwargs):
        raise FileNotFoundError("collector binary missing")
    monkeypatch.setattr(runtime.subprocess, "run", missing)
    row = runtime.Detector(FakeBundle(window=1), tmp_path).process(frame(1))
    assert row["evidence"]["status"] == "error"


def test_integrity_alarm_on_full_holds_previous_chain_context(monkeypatch, tmp_path):
    calls = []
    def hold(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stderr="", stdout="")
    monkeypatch.setattr(runtime.subprocess, "run", hold)
    detector = runtime.Detector(FakeBundle(window=3), tmp_path)
    detector.process(frame(0, chain="100"))
    detector.process(frame(1, chain="100"))
    finding = [{"check": "syscall_hook", "index": 7}]
    row = detector.process(frame(2, full=True, chain="200", findings=finding))
    assert row["model_state"] == "warming_up" and row["alarm_event"]
    assert calls[0][-2:] == ["100", "200"]
    still_active = detector.process(frame(3, chain="200", findings=finding))
    assert still_active["alarm"] and not still_active["alarm_event"]


def sidecar(directory, seq, *, suffix="test", document=None):
    path = directory / f"guest_{seq:06d}_{suffix}.json"
    path.with_suffix(".vmicd").write_bytes(b"unit fixture, no memory content")
    value = {"schema": "vmicollect/1", "seq": seq, "timestamp_unix": 1000 + seq * 5}
    path.write_text(json.dumps(value if document is None else document))
    return path


def stub_extractor(monkeypatch, results=None):
    calls = []
    def extract(directory, profile, seq, previous=None, session_id=None, **kwargs):
        calls.append((seq, previous))
        return (results or {}).get(seq, frame(seq)), {"previous_seq": seq}
    monkeypatch.setattr(runtime, "frame_from_snapshot", extract)
    return calls


def test_finite_directory_exclusive_output_status_and_evidence(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    for seq in range(4):
        sidecar(raw, seq)
    (raw / "capture.json").write_text('{"metadata": true}')
    calls = stub_extractor(monkeypatch)
    output = tmp_path / "run"
    summary = runtime.run_directory(FakeBundle(window=2), raw, "profile", output, preserve=False)
    assert summary["ok"] and summary["processed"] == 4 and summary["scored"] == 3
    assert summary["alarm_events"] == 1 and summary["backlog"] == 0
    assert summary["diagnostic"] is True and summary["running"] is False
    assert len(calls) == 4
    rows = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert [row["seq"] for row in rows] == [0, 1, 2, 3]
    assert len(list((output / "evidence").glob("*.json"))) == 1
    assert json.loads((output / "status.json").read_text()) == summary
    with pytest.raises(FileExistsError):
        runtime.run_directory(FakeBundle(), raw, "profile", output, preserve=False)


def test_duplicate_sequences_are_errors_and_not_scored_twice(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    sidecar(raw, 1, suffix="a")
    sidecar(raw, 1, suffix="b")
    sidecar(raw, 2)
    calls = stub_extractor(monkeypatch)
    summary = runtime.run_directory(FakeBundle(window=1), raw, "profile", tmp_path / "out", preserve=False)
    assert not summary["ok"] and summary["input_errors"] == 1
    assert [seq for seq, _ in calls] == [2]
    assert summary["backlog"] == 0


@pytest.mark.parametrize("damage", ["partial", "missing_sidecar", "missing_snapshot", "bad_timestamp"])
def test_finite_replay_reports_unfinished_or_bad_input(monkeypatch, tmp_path, damage):
    raw = tmp_path / "raw"
    raw.mkdir()
    path = sidecar(raw, 0)
    if damage == "partial":
        path.write_text('{"schema":')
    elif damage == "missing_sidecar":
        path.unlink()
    elif damage == "missing_snapshot":
        path.with_suffix(".vmicd").unlink()
    else:
        doc = json.loads(path.read_text())
        doc["timestamp_unix"] = "not a timestamp"
        path.write_text(json.dumps(doc))
    calls = stub_extractor(monkeypatch)
    summary = runtime.run_directory(FakeBundle(window=1), raw, "profile", tmp_path / "out", preserve=False)
    assert not summary["ok"] and summary["input_errors"] == 1 and not calls


def test_follow_retries_partial_sidecar_and_drains_on_stop(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    path = sidecar(raw, 0)
    complete = path.read_text()
    path.write_text('{"schema":')
    sidecar(raw, 1)
    calls = stub_extractor(monkeypatch)
    monkeypatch.setattr(runtime, "_POLL_SECONDS", 0.005)
    stop = threading.Event()
    def writer():
        time.sleep(0.04)
        path.write_text(complete)
        stop.set()
    worker = threading.Thread(target=writer)
    worker.start()
    try:
        summary = runtime.run_directory(FakeBundle(window=1), raw, "profile", tmp_path / "out",
                                        follow=True, stop_event=stop, preserve=False)
    finally:
        worker.join(timeout=2)
    assert summary["ok"] and summary["stop_reason"] == "stop_requested"
    assert [seq for seq, _ in calls] == [0, 1]


def test_follow_idle_timeout_records_incomplete(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    path = sidecar(raw, 0)
    path.write_text("{")
    monkeypatch.setattr(runtime, "_POLL_SECONDS", 0.005)
    summary = runtime.run_directory(FakeBundle(), raw, "profile", tmp_path / "out",
                                    follow=True, idle_timeout=0.025, preserve=False)
    assert summary["stop_reason"] == "idle_timeout"
    assert summary["input_errors"] == 1 and not summary["ok"]


def test_empty_replay_is_explicit_error(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    summary = runtime.run_directory(FakeBundle(), raw, "profile", tmp_path / "out", preserve=False)
    assert not summary["ok"] and summary["stop_reason"] == "empty_input"


@pytest.mark.parametrize("exception", [KeyboardInterrupt, AssertionError])
def test_interrupted_or_unexpected_error_leaves_stopped_status(monkeypatch, tmp_path, exception):
    raw = tmp_path / "raw"
    raw.mkdir()
    sidecar(raw, 0)
    def broken(*args, **kwargs):
        raise exception("intentional fixture interruption")
    monkeypatch.setattr(runtime, "frame_from_snapshot", broken)
    output = tmp_path / "run"
    with pytest.raises(exception):
        runtime.run_directory(FakeBundle(), raw, "profile", output, preserve=False)
    status = json.loads((output / "status.json").read_text())
    assert status["running"] is False and status["ok"] is False
    assert status["stop_reason"] == ("interrupted" if exception is KeyboardInterrupt else "runtime_error")


@pytest.mark.parametrize("exception", [ValueError, KeyError, TypeError])
def test_extraction_failure_resets_predecessor_then_recovers(monkeypatch, tmp_path, exception):
    raw = tmp_path / "raw"
    raw.mkdir()
    for seq in range(4):
        sidecar(raw, seq)
    previous_seen = []
    def extract(directory, profile, seq, previous=None, **kwargs):
        previous_seen.append(previous)
        if seq == 1:
            raise exception("unreadable snapshot fixture")
        return frame(seq), {"seq": seq}
    monkeypatch.setattr(runtime, "frame_from_snapshot", extract)
    summary = runtime.run_directory(FakeBundle(window=2), raw, "profile", tmp_path / "out", preserve=False)
    assert summary["input_errors"] == 1 and summary["scored"] == 1
    assert previous_seen[2] is None


def test_archive_uses_same_detector_path_without_hold(monkeypatch, tmp_path):
    frames = [frame(seq, full=seq == 0, predecessor=seq != 0,
                    inconclusive=["text_integrity"]) for seq in range(8)]
    path = tmp_path / "features.npz"
    np.savez(path, schema=SCHEMA, mena=np.array(MENA), quality_policy="behavioral-inputs-v1",
             matica=np.stack([item.vector for item in frames]),
             seq=np.array([item.seq for item in frames]),
             casy=np.array([item.timestamp for item in frames]),
             valid=np.array([item.valid for item in frames]),
             perbin=np.stack([item.perbin for item in frames]), biny=np.array([0]),
             chain_ids=np.array([item.chain_id for item in frames]),
             quality_json=json.dumps([item.quality for item in frames]),
             layout_json=json.dumps(frames[0].layout))
    def forbidden(*args, **kwargs):
        pytest.fail("replay must not issue HOLD")
    monkeypatch.setattr(runtime.subprocess, "run", forbidden)
    replayed = runtime.replay_archive(FakeBundle(window=2), path, "test-session")
    detector = runtime.Detector(FakeBundle(window=2), preserve=False)
    live = [detector.process(item) for item in frames]
    for a, b in zip(replayed, live, strict=True):
        for key in ("state", "model_state", "score", "alarm", "alarm_event", "integrity", "bin_errors"):
            assert a.get(key) == b.get(key)
