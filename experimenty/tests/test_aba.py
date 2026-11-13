import json
import os
from pathlib import Path
import subprocess

import pytest

from experimenty import aba
from experimenty.tests import synth
from scripts import traffic_log as tl


# --- schedule -------------------------------------------------------------------------------

@pytest.mark.parametrize("repetitions", [2, 4, 6, 8])
def test_schedule_is_counterbalanced(repetitions):
    blocks = aba.schedule(repetitions)
    assert len(blocks) == 5 * repetitions
    assert [b["index"] for b in blocks] == list(range(len(blocks)))
    for b in blocks:
        if b["condition"] in aba.MONITORED:
            before, after = blocks[b["index"] - 1], blocks[b["index"] + 1]
            assert b["flanks"] == [before["block_id"], after["block_id"]]
            assert before["condition"] == after["condition"] == "A"
            assert before["repetition"] == after["repetition"] == b["repetition"]
    patterns = [blocks[5 * r]["pattern"] for r in range(repetitions)]
    assert patterns[:4] == ["A-B-A-C-A", "A-C-A-B-A", "A-C-A-B-A", "A-B-A-C-A"][:repetitions]
    bal = aba.balance(blocks)
    assert bal["balanced"]
    assert bal["B"]["positions"] == bal["C"]["positions"] == {1: repetitions // 2, 3: repetitions // 2}
    assert bal["B"]["mean_index"] == bal["C"]["mean_index"]


def test_odd_repetitions_are_refused_unless_allowed():
    with pytest.raises(ValueError, match="odd"):
        aba.schedule(3)
    assert not aba.balance(aba.schedule(3, allow_unbalanced=True))["balanced"]
    with pytest.raises(ValueError):
        aba.schedule(0)


def test_plan_cli_prints_schedule(capsys):
    assert aba.main(["plan", "--repetitions", "2"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == aba.PLAN_SCHEMA and doc["balance"]["balanced"]
    assert [b["condition"] for b in doc["blocks"]] == list("ABACAACABA")


# --- summary --------------------------------------------------------------------------------

def summarize(run, out, **kw):
    kw.setdefault("bootstrap", 200)
    return aba.summarize(run, out, **kw)


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    root = tmp_path_factory.mktemp("e5")
    run = synth.build_run(root)
    out = root / "result.json"
    assert summarize(run, out) == 0
    return run, json.loads(out.read_text())


def test_summary_recovers_injected_effects_despite_drift(recorded):
    _, result = recorded
    d = result["values"]["differences"]
    for name, ms, cpu in (("B_minus_A", 2.0, 5.0), ("C_minus_A", 4.0, 10.0), ("C_minus_B", 2.0, 5.0)):
        for metric, expected in (("latency_p50_ms", ms), ("latency_p95_ms", ms), ("cpu_busy_pct", cpu),
                                 ("throughput_rps", 0.0)):
            entry = d[name][metric]
            assert entry["estimate"] == pytest.approx(expected, abs=1e-6), (name, metric)
            lo, hi = entry["ci95"]
            assert lo <= entry["estimate"] + 1e-9 and entry["estimate"] <= hi + 1e-9
    assert d["B_minus_A"]["proc_cpu_vmicollect_pct"]["estimate"] == pytest.approx(8.0)
    assert d["C_minus_A"]["proc_cpu_safeguard_pct"]["estimate"] == pytest.approx(30.0)
    assert d["B_minus_A"]["proc_cpu_safeguard_pct"]["estimate"] == pytest.approx(0.0)
    assert len(d["B_minus_A"]["per_triplet"]) == 2
    # A drifts by DRIFT_MS per block; the drift record shows it, the triplet estimate cancels it.
    drift = result["values"]["drift_A"][0]
    assert drift["latency_p50_ms"] == pytest.approx(4 * synth.DRIFT_MS)


def test_block_percentiles_equal_the_traffic_log_audit(recorded):
    run, result = recorded
    for block in result["values"]["blocks"]:
        bdir = run / "blocks" / block["block_id"]
        audit = tl.summarize(bdir / "traffic_requests.jsonl", bdir / "traffic_intervals.jsonl")
        assert block["latency_p95_ms"] == pytest.approx(audit["measure"]["latency_ms"]["p95"])
        assert block["latency_p50_ms"] == pytest.approx(audit["measure"]["latency_ms"]["p50"])
        assert block["throughput_rps"] == pytest.approx(audit["measure"]["phase_request_rate_rps"])
        assert block["requests"] == audit["measure"]["requests"]


def test_result_has_provenance(recorded):
    run, result = recorded
    v = result["values"]
    for key in ("command", "commit", "commit_dirty", "date", "host", "guest", "n"):
        assert key in result
    assert len(result["commit"]) == 40
    assert v["config"]["protocol_sha256"] and v["run"]["started_utc"]
    assert set(v["inputs_sha256"]) == {"run.json", "run_end.json"} | {
        f"blocks/{b['block_id']}/{n}" for b in v["blocks"]
        for n in ("block.json", "traffic_requests.jsonl", "traffic_intervals.jsonl", "host_monitor.jsonl")}
    assert v["bootstrap"] == {**v["bootstrap"], "resamples": 200, "seed": 0, "cluster_intervals": 6}
    assert set(v["conditions"]) == {"A", "B", "C"}
    for c in v["conditions"].values():
        assert {"latency_p50_ms", "latency_p95_ms", "throughput_rps", "cpu_busy_pct"} <= set(c)


def test_bootstrap_is_deterministic_for_a_fixed_seed(recorded, tmp_path):
    run, first = recorded
    assert summarize(run, tmp_path / "again.json") == 0
    assert summarize(run, tmp_path / "other.json", seed=7) == 0
    again = json.loads((tmp_path / "again.json").read_text())
    other = json.loads((tmp_path / "other.json").read_text())
    assert again["values"]["differences"] == first["values"]["differences"]
    assert other["values"]["differences"] != first["values"]["differences"]
    assert other["values"]["differences"]["B_minus_A"]["latency_p50_ms"]["estimate"] == \
        first["values"]["differences"]["B_minus_A"]["latency_p50_ms"]["estimate"]


def test_summarize_cli_refuses_existing_output(recorded, tmp_path):
    run, _ = recorded
    out = tmp_path / "r.json"
    out.write_text("{}")
    with pytest.raises(SystemExit):
        aba.main(["summarize", str(run), "--out", str(out)])
    assert out.read_text() == "{}"


# --- refusal of incomplete or mismatched logs --------------------------------------------------

def first(run, condition):
    return next(p for p in sorted((run / "blocks").iterdir()) if p.name.endswith("-" + condition))


def rewrite_json(path, change):
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc))


def torn_traffic(run):
    path = first(run, "B") / "traffic_requests.jsonl"
    path.write_bytes(path.read_bytes()[:-40])


def missing_monitor(run):
    (first(run, "C") / "host_monitor.jsonl").unlink()


def missing_run_end(run):
    (run / "run_end.json").unlink()


def other_load_profile(run):
    for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
        path = first(run, "A") / name
        lines = path.read_text().splitlines()
        header = json.loads(lines[0])
        header["config"]["workers"] += 1
        path.write_text("\n".join([json.dumps(header), *lines[1:]]) + "\n")


def collector_in_a_block(run):
    bdir = first(run, "A")
    synth.monitor_log(bdir, bdir.name, json.loads((bdir / "block.json").read_text())["measure_start_unix"]
                      - synth.WARMUP_IV * synth.INTERVAL, "A", 0, presence={"vmicollect": True, "safeguard": False})


def detector_missing_in_c(run):
    bdir = first(run, "C")
    origin = json.loads((bdir / "block.json").read_text())["measure_start_unix"] - synth.WARMUP_IV * synth.INTERVAL
    (bdir / "host_monitor.jsonl").unlink()
    synth.monitor_log(bdir, bdir.name, origin, "C", 0, presence={"vmicollect": True, "safeguard": False})


def swapped_condition(run):
    rewrite_json(first(run, "B") / "block.json", lambda d: d.update(condition="C"))


def qemu_restarted(run):
    rewrite_json(first(run, "C") / "block.json", lambda d: d["qemu_after"].update(pid=99))


def component_killed(run):
    rewrite_json(first(run, "B") / "block.json", lambda d: d.update(component={"pid": 1, "rc": -9,
                                                                              "stopped_by": "SIGKILL after 120s"}))


def run_incomplete(run):
    rewrite_json(run / "run_end.json", lambda d: d.update(completed=False, blocks_done=d["blocks_done"][:-1]))


def guest_rebooted(run):
    rewrite_json(run / "run_end.json", lambda d: d["guest_after"].update(boot_id="other"))


def extra_block(run):
    (run / "blocks" / "99-r9-B").mkdir()


def session_mismatch(run):
    a, b = first(run, "A"), first(run, "B")
    (a / "host_monitor.jsonl").write_text((b / "host_monitor.jsonl").read_text())


def short_measurement(run):
    rewrite_json(run / "run.json", lambda d: d["config"].update(measure_s=600))


@pytest.mark.parametrize("damage", [torn_traffic, missing_monitor, missing_run_end, other_load_profile,
                                    collector_in_a_block, detector_missing_in_c, swapped_condition,
                                    qemu_restarted, component_killed, run_incomplete, guest_rebooted,
                                    extra_block, session_mismatch, short_measurement])
def test_incomplete_or_mismatched_logs_are_refused(tmp_path, capsys, damage):
    run = synth.build_run(tmp_path)
    damage(run)
    out = tmp_path / "result.json"
    assert summarize(run, out, bootstrap=10) == 2
    assert not out.exists()
    report = json.loads(capsys.readouterr().err)
    assert report["refused"] and report["problems"]


# --- dry run --------------------------------------------------------------------------------

def test_dry_run_has_no_side_effects(tmp_path, monkeypatch, capsys):
    import safeguard.supervisor  # noqa: F401  (imported before the traps; it is read-only)

    def trap(*args, **kwargs):
        raise AssertionError(f"side effect during dry run: {args!r}")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, trap)
    for name in ("kill", "killpg", "mkdir", "makedirs", "chown", "remove", "unlink", "rename", "replace"):
        monkeypatch.setattr(os, name, trap)
    monkeypatch.setattr(Path, "mkdir", trap)
    monkeypatch.setattr(Path, "write_text", trap)
    monkeypatch.setattr(Path, "touch", trap)
    out = tmp_path / "e5-run"
    before = sorted(p.name for p in tmp_path.iterdir())
    assert aba.main(["run", "--dry-run", "--out", str(out), "--repetitions", "2"]) == 0
    text = capsys.readouterr().out
    assert not out.exists() and sorted(p.name for p in tmp_path.iterdir()) == before
    assert "nothing is created or started" in text
    assert text.count("== block ") == 10
    assert "vmicollect/build/vmicollect run" in text and "-m safeguard --threads 4 run" in text
    assert "scripts/host_traffic.py" in text and "scripts/host_monitor.py" in text
    assert "sudo env PYTHONPATH=" in text and "run --execute" in text


def test_execute_without_root_is_refused_before_any_change(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    out = tmp_path / "e5-run"
    assert aba.main(["run", "--execute", "--out", str(out), "--repetitions", "2"]) == 2
    assert not out.exists()
    assert "sudo" in capsys.readouterr().err


def test_run_requires_a_mode(tmp_path):
    with pytest.raises(SystemExit):
        aba.main(["run", "--out", str(tmp_path / "x")])
