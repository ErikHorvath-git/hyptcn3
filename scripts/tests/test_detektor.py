import json
from pathlib import Path

import pytest

from scripts import detektor
from features import snapshot


def run_detector(monkeypatch, tmp_path, sequences):
    binary = Path(__file__).resolve().parents[2] / "vmicollect/build/vmicollect"
    if not binary.exists():
        pytest.skip("build vmicollect first to test the real HOLD CLI")
    for seq in sequences:
        (tmp_path / f"snap{seq}.json").write_text(json.dumps({
            "seq": seq, "id": f"snap{seq}", "timestamp_unix": 10 + seq,
            "output": {"chain_id": 700 if seq < 2 else 900}}))
    monkeypatch.setattr(detektor, "nacitaj_prediktor", lambda _: (None, None, {"dlzka_okna": 3}))
    monkeypatch.setattr(detektor, "chyba_predikcie_okna", lambda *_: (2., [], []))
    monkeypatch.setattr(snapshot, "vektor_snimky", lambda *_: ([1.] * 22, {}, []))
    out = tmp_path / "output.jsonl"
    rc = detektor.main(["--snapshots", str(tmp_path), "--profile", "unused", "--model", "unused",
                       "--prah", "1", "--k", "1", "--n", "1", "--hold-bin", str(binary), "--out", str(out)])
    return rc, [json.loads(row) for row in out.read_text().splitlines()]


def test_alarm_preserves_real_chain_ids_across_full_snapshot_boundary(monkeypatch, tmp_path):
    rc, events = run_detector(monkeypatch, tmp_path, [0, 1, 2, 3])
    assert rc == 0
    assert events[1]["stav"] == "zahrievanie"
    assert events[2]["alarm"] and events[2]["hold_rc"] == 0
    assert (tmp_path / "HOLD").read_text().splitlines() == ["700", "900"]
    assert json.loads((tmp_path / "alarm.json").read_text())["seq"] == 3


def test_missing_snapshot_resets_model_window(monkeypatch, tmp_path):
    rc, events = run_detector(monkeypatch, tmp_path, [0, 1, 5, 6])
    assert rc == 0
    assert all(e["stav"] == "zahrievanie" for e in events)
    assert not (tmp_path / "HOLD").exists()
