"""State of the guest for a group (proposal 5.4; lab/guest_state.py reset, pretouch, levels; lab/seed.py).

The same seed gives the same seeded level; reset loads it and replaces the documents; pretouch lets one process
touch the memory of the largest event; levels reports what a session starts from. psql, runuser and /proc are
fakes; the memory program itself runs, with a small size.
"""
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_state  # noqa: E402
import udalosti  # noqa: E402

SMALL = {"products": 20, "customers": 4, "employees": 2, "documents": 3, "orders": 5, "carts": 2}


@pytest.fixture
def seed(monkeypatch):
    """lab/seed.py with small counts; imported here because the module is new in B5."""
    import seed as module
    monkeypatch.setattr(module, "SIZES", SMALL)
    monkeypatch.setattr(module, "PBKDF2_ITERATIONS", 1000)
    return module


def test_same_seed_gives_the_same_level_and_another_seed_another(seed):
    first, again, other = seed.generate(11), seed.generate(11), seed.generate(12)
    assert seed.digest(first) == seed.digest(again) != seed.digest(other)
    assert [len(first[t]) for t in ("products", "customers", "employees", "orders", "documents")] == [20, 4, 2, 5, 3]
    script = seed.sql_script(first, 1_800_000_000)
    assert script.startswith("BEGIN;\nTRUNCATE ") and script.endswith("COMMIT;\n")
    assert script.count("\\.\n") == 7 and "COPY products (id, name, category, description, price_cents)" in script
    assert all(seed.STATIC_MIN <= size <= seed.STATIC_MAX for _, size in seed.static_files(0))
    sizes = sorted(size for _, size in seed.static_files(0))
    assert len(sizes) == 200 and (sizes[0], sizes[-1]) == (300, 2 << 20)


def test_reset_loads_the_seeded_level_and_replaces_everything_written_since(seed, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(guest_state, "DATA", tmp_path)
    for directory in ("docs", "reports", "logs", "spool/queued", "spool/running", "spool/failed", "static"):
        (tmp_path / directory).mkdir(parents=True)
    for leftover in ("docs/99.bin", "reports/r.csv.gz", "logs/docs.log", "spool/queued/r.json", "static/000.css"):
        (tmp_path / leftover).write_bytes(b"from the last group")
    scripts = []

    def run(*args, check=True, input=None, timeout=120):
        assert args[:4] == ("runuser", "-u", "hyptcnlab", "--") and "psql" in args, args
        scripts.append(input)
        return ""
    monkeypatch.setattr(guest_state, "run", run)
    monkeypatch.setattr(guest_state.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    guest_state.main(["reset", "--seed", "11"])
    record = json.loads(capsys.readouterr().out)
    data = seed.generate(11)
    assert record["data_sha256"] == seed.digest(data) and record["seed"] == 11
    assert len(scripts) == 1 and scripts[0] == seed.sql_script(data, record["started_unix"])
    docs = {p.name: p.read_bytes() for p in (tmp_path / "docs").iterdir()}
    assert docs == {f"{d['id']}.bin": seed.document_content(11, d["id"], d["bytes"]) for d in data["documents"]}
    assert [p.name for p in tmp_path.rglob("*") if p.is_file() and "docs" not in p.parts] == ["000.css"]
    with pytest.raises(SystemExit):
        guest_state.main(["reset", "--seed", "x"])


def test_the_memory_program_touches_its_memory(monkeypatch):
    monkeypatch.setattr(udalosti, "LOAD_MIB", 16)  # The size of the program, not of the event.
    subprocess.run([sys.executable, "-c", udalosti.load_program(0)], check=True)
    assert resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss >= 16 << 10


@pytest.mark.parametrize("peak_kib,touched", [(410_000, True), (200_000, False)])
def test_pretouch_runs_the_program_of_the_largest_event_once(monkeypatch, capsys, tmp_path, peak_kib, touched):
    (tmp_path / "meminfo").write_text("MemTotal: 2000000 kB\nMemAvailable: 1500000 kB\n")
    monkeypatch.setattr(guest_state, "PROC", tmp_path)
    runs = []
    monkeypatch.setattr(guest_state.subprocess, "run",
                        lambda argv, **kw: runs.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    monkeypatch.setattr(guest_state.resource, "getrusage", lambda who: SimpleNamespace(ru_maxrss=peak_kib))
    if touched:
        guest_state.main(["pretouch"])
    else:
        with pytest.raises(SystemExit, match="did not touch"):
            guest_state.main(["pretouch"])
    assert runs == [["runuser", "-u", "nobody", "--", "python3", "-c", udalosti.load_program(0)]]
    record = json.loads(capsys.readouterr().out)
    assert record["mib"] == udalosti.LOAD_MIB == 400 and record["touched"] is touched


def test_levels_reports_processes_memory_database_and_files(tmp_path, monkeypatch, capsys):
    proc, data = tmp_path / "proc", tmp_path / "data"
    for pid, threads in ((1, 1), (200, 12)):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "status").write_text(f"Name:\tx\nThreads:\t{threads}\n")
    (proc / "meminfo").write_text("MemTotal: 2000000 kB\nMemAvailable: 1500000 kB\nSwapTotal: 0 kB\n")
    (proc / "loadavg").write_text("0.10 0.20 0.30 1/100 4242\n")
    (proc / "modules").write_text("virtio_net 61440 0 - Live 0x0\n")  # Package B9: levels reads it as well.
    (data / "docs").mkdir(parents=True)
    (data / "docs" / "1.bin").write_bytes(b"x" * 10)
    monkeypatch.setattr(guest_state, "PROC", proc)
    monkeypatch.setattr(guest_state, "DATA", data)
    monkeypatch.setattr(guest_state, "run", lambda *args, **kw: "5000|2000|200|3000|1|7500|300|500|9000000|25\n")
    guest_state.main(["levels"])
    record = json.loads(capsys.readouterr().out)
    assert (record["processes"], record["threads"]) == (2, 13)
    assert record["meminfo_kb"]["MemAvailable"] == 1500000 and record["loadavg"] == ["0.10", "0.20", "0.30"]
    assert record["database"] == dict(zip(guest_state.LEVEL_NAMES, (5000, 2000, 200, 3000, 1, 7500, 300, 500,
                                                                     9000000, 25)))
    assert record["files"]["documents"] == {"files": 1, "bytes": 10} and record["files"]["reports"]["files"] == 0
