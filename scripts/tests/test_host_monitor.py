import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from scripts.host_monitor import summarize

REPO = Path(__file__).resolve().parents[2]


def start(out, *extra):
    return subprocess.Popen([sys.executable, REPO / "scripts/host_monitor.py", "run", "--out", out,
                             "--interval-s", "0.2", "--path", str(out.parent), *extra],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_monitor_records_fixed_ticks_and_finishes_on_repeated_sigterm(tmp_path):
    out = tmp_path / "monitor.jsonl"
    process = start(out, "--pid", f"{os.getpid()}:pytest", "--match", "pytest=pytest")
    try:
        time.sleep(1.3)
        process.send_signal(signal.SIGTERM)
        process.send_signal(signal.SIGTERM)  # A second signal must not cut the final record.
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert records[0]["type"] == "header" and records[-1]["type"] == "end" and records[-1]["clean"]
    samples = [r for r in records if r["type"] == "sample"]
    assert len(samples) >= 4
    assert [s["i"] for s in samples] == sorted({s["i"] for s in samples})
    assert all(s["mem_kb"]["MemTotal"] > 0 for s in samples)
    assert any(p["pid"] == os.getpid() for p in samples[-1]["procs"]["pytest"])
    assert str(tmp_path) in samples[-1]["fs"]
    doc = summarize(out, datetime_unix(samples[0]), datetime_unix(samples[-1]))
    assert doc["problems"] == [] and doc["window_samples"] == len(samples)


def datetime_unix(sample):
    from datetime import datetime
    return datetime.fromisoformat(sample["t_utc"]).timestamp()


def test_summary_reports_torn_tail_missing_end_and_uncovered_window(tmp_path):
    out = tmp_path / "monitor.jsonl"
    assert subprocess.run([sys.executable, REPO / "scripts/host_monitor.py", "run", "--out", out,
                           "--interval-s", "0.2", "--duration-s", "0.5"], timeout=10).returncode == 0
    lines = out.read_text().splitlines()
    out.write_text("\n".join(lines[:-1]) + "\n" + '{"type": "samp')
    doc = summarize(out, start_unix=time.time() - 3600, end_unix=time.time() + 3600)
    assert "torn_last_line" in doc["problems"] and "missing_end_record" in doc["problems"]
    assert "does_not_cover_window_start" in doc["problems"]
    assert "does_not_cover_window_end" in doc["problems"]


def test_monitor_refuses_to_overwrite_existing_log(tmp_path):
    out = tmp_path / "monitor.jsonl"
    out.write_text("previous measurement\n")
    result = subprocess.run([sys.executable, REPO / "scripts/host_monitor.py", "run", "--out", out,
                             "--duration-s", "0.2"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 3
    assert out.read_text() == "previous measurement\n"
