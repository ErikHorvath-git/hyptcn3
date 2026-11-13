"""Synthetic run directories in the exact formats of host_traffic.py, host_monitor.py and aba.py."""
from argparse import Namespace
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

from experimenty import aba
from scripts import host_monitor as hm
from scripts import traffic_log as tl

INTERVAL = 5.0
WARMUP_IV, MEASURE_IV, POST_IV = 2, 24, 1
BASE_MS = [10.0, 12.0, 15.0, 11.0, 30.0, 13.0, 9.0, 18.0, 14.0, 50.0]  # per-request pattern within an interval
EFFECT_MS = {"A": 0.0, "B": 2.0, "C": 4.0}
EFFECT_CPU = {"A": 0.0, "B": 5.0, "C": 10.0}
DRIFT_MS, DRIFT_CPU = 0.25, 0.5  # linear drift per block index; cancels in X - mean(flanks)
BLOCK_GAP_S = 400


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="microseconds")


def config(repetitions=2):
    a = Namespace(protocol=aba.DEFAULTS["protocol"], scenario="steady", traffic_seed=1, repetitions=repetitions,
                  allow_unbalanced=False, warmup_s=240, measure_s=MEASURE_IV * INTERVAL, rest_s=0,
                  bundle=aba.DEFAULTS["bundle"], profile=None, domain=None, target=None, threads=4,
                  collector=aba.DEFAULTS["collector"])
    return aba.make_config(a)


def write_log(path, schema, records):
    path.write_text("".join(json.dumps({"schema": schema, "n": n, **r}) + "\n" for n, r in enumerate(records)))


def traffic_logs(bdir, block_id, origin, condition, index, traffic_config):
    run_id = f"run{index:04d}"
    seq, requests_by_iv, intervals = 0, {}, []
    phases = ["warmup"] * WARMUP_IV + ["measure"] * MEASURE_IV + ["post"] * POST_IV
    for i, phase in enumerate(phases):
        start, end = i * INTERVAL, (i + 1) * INTERVAL
        members = []
        for j, base in enumerate(BASE_MS):
            # Same multiset of interval factors in every block, rotated per block: whole-phase
            # percentiles are exact shifts of each other, bootstrap resamples are not.
            factor = 1 + ((i - WARMUP_IV + 5 * index) % MEASURE_IV % 7) * .07
            ms = round(base * factor + EFFECT_MS[condition] + DRIFT_MS * index, 3)
            t0 = round(start + .1 + j * .4, 6)
            members.append({"type": "request", "session_id": block_id, "run_id": run_id,
                            "rid": f"{run_id}-00-{seq:08d}", "worker": 0, "worker_seq": seq, "interval": i,
                            "phase": phase, "method": "GET", "route": "/api/catalog", "status": 200,
                            "outcome": "ok", "error": None, "t_start_utc": utc(origin + t0),
                            "t_end_utc": utc(origin + t0 + ms / 1000), "t_start_mono": t0,
                            "t_end_mono": round(t0 + ms / 1000, 6), "duration_ms": ms, "response_bytes": 10})
            seq += 1
        requests_by_iv[i] = members
        intervals.append({"type": "interval", "interval": i, "phase": phase, "t_start_utc": utc(origin + start),
                          "t_end_utc": utc(origin + end), "mono_start": start, "mono_end": end,
                          "duration_s": end - start, "requests": len(members),
                          **{o: sum(r["outcome"] == o for r in members) for o in tl.OUTCOMES},
                          "status_codes": {"200": len(members)}, "routes": {"GET /api/catalog": len(members)},
                          "route_errors": {}, "throughput_rps": len(members) / INTERVAL,
                          "ok_rps": len(members) / INTERVAL, "sum_ms": sum(r["duration_ms"] for r in members),
                          "min_ms": min(r["duration_ms"] for r in members),
                          "max_ms": max(r["duration_ms"] for r in members),
                          "hist": dict(Counter(str(tl.bucket_index(r["duration_ms"])) for r in members)),
                          "hist_ok": dict(Counter(str(tl.bucket_index(r["duration_ms"])) for r in members))})
    t_measure, t_post = WARMUP_IV * INTERVAL, (WARMUP_IV + MEASURE_IV) * INTERVAL
    marks = [{"type": "phase", "phase": "measure", "previous": "warmup", "t_utc": utc(origin + t_measure),
              "t_mono": t_measure, "interval": WARMUP_IV},
             {"type": "phase", "phase": "post", "previous": "measure", "t_utc": utc(origin + t_post),
              "t_mono": t_post, "interval": WARMUP_IV + MEASURE_IV}]
    header = {"type": "header", "session_id": block_id, "run_id": run_id, "generator": "synthetic",
              "config": dict(traffic_config), "start_utc": utc(origin), "start_unix": origin}
    req_log, ivl_log = [header], [dict(header, hist_edges_ms=tl.EDGES, hist_precision=tl.HIST_PRECISION)]
    for i, iv in enumerate(intervals):
        for mark in marks:
            if mark["interval"] == i:
                req_log.append(mark)
                ivl_log.append(mark)
        req_log.extend(requests_by_iv[i])
        ivl_log.append(iv)
    all_requests = [r for i in requests_by_iv for r in requests_by_iv[i]]
    end_mono = len(phases) * INTERVAL
    for log in (req_log, ivl_log):
        log.append({"type": "end", "requests_started": len(all_requests), "requests_completed": len(all_requests),
                    **{o: sum(r["outcome"] == o for r in all_requests) for o in tl.OUTCOMES},
                    "in_flight_at_stop": 0, "worker_errors": 0, "log_backpressure_s": 0, "phase": "post",
                    "end_utc": utc(origin + end_mono), "end_mono": end_mono, "records": len(log) + 1,
                    "requests_logged": len(all_requests), "write_errors": 0, "clean": True})
    write_log(bdir / "traffic_requests.jsonl", tl.REQUEST_SCHEMA, req_log)
    write_log(bdir / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA, ivl_log)
    return origin + t_measure, origin + t_post


def monitor_log(bdir, block_id, origin, condition, index, presence=None):
    presence = presence or aba.PRESENCE[condition]
    lines = [{"schema": hm.SCHEMA, "type": "header", "session_id": block_id, "start_utc": utc(origin - 1),
              "interval_s": 1.0, "disks": ["sda"], "paths": [], "process_labels": {}}]
    total = int((WARMUP_IV + MEASURE_IV + POST_IV) * INTERVAL) + 3
    for i in range(total):
        t = origin - 1 + i + .5
        procs = {"qemu": [{"pid": 10, "rss_kb": 1, "swap_kb": 0, "cpu_pct": 50.0}],
                 "vmicollect": [{"pid": 20, "rss_kb": 1, "swap_kb": 0, "cpu_pct": 8.0}] if presence["vmicollect"] else [],
                 "safeguard": [{"pid": 30, "rss_kb": 1, "swap_kb": 0, "cpu_pct": 30.0}] if presence["safeguard"] else []}
        lines.append({"type": "sample", "i": i, "t_utc": utc(t), "t_mono": i,
                      "cpu": {"jiffies": None, "busy_pct": 20 + (i % 4) + EFFECT_CPU[condition] + DRIFT_CPU * index,
                              "iowait_pct": 1.0},
                      "mem_kb": {"MemTotal": 32 * 2**20, "MemAvailable": 16 * 2**20, "SwapTotal": 0, "SwapFree": 0},
                      "vmstat": {"pswpin": 0, "pswpout": 0}, "disks": {"sda": {"sectors_written": i * 100}},
                      "disks_rate": {"sda": {"read_MBps": 0.0, "write_MBps": 1.0 + EFFECT_CPU[condition] / 5,
                                             "util_pct": 1.0}},
                      "fs": {}, "temps_c": {}, "psi_avg10": {"io": 0.0}, "procs": procs})
    lines.append({"type": "end", "end_utc": utc(origin + total), "samples": total, "missed_ticks": 0, "clean": True})
    (bdir / "host_monitor.jsonl").write_text("".join(json.dumps(r) + "\n" for r in lines))


def build_run(root, repetitions=2, start=1_800_000_000.0):
    """A complete, consistent run directory; returns its path."""
    cfg = config(repetitions)
    plan = aba.plan_doc(cfg)
    qemu = {"pid": 10, "start_ticks": 1, "host_boot": "hb"}
    guest = {"kernel": "6.1.0-42-cloud-amd64", "boot_id": "b", "machine_id": "m", "stack_sha256": "s"}
    run = Path(root) / "run"
    (run / "blocks").mkdir(parents=True)
    aba.write_json(run / "run.json", {"schema": aba.RUN_SCHEMA, "run_id": "run", "started_utc": utc(start),
                                      "commit": "0" * 40, "commit_dirty": False, "host": "synthetic",
                                      "config": cfg, "plan": plan, "guest_before": guest, "qemu": qemu})
    for block in plan["blocks"]:
        bid, condition, index = block["block_id"], block["condition"], block["index"]
        bdir = run / "blocks" / bid
        bdir.mkdir()
        origin = start + index * BLOCK_GAP_S
        m0, m1 = traffic_logs(bdir, bid, origin, condition, index, cfg["traffic"])
        monitor_log(bdir, bid, origin, condition, index)
        status = {"schema": aba.BLOCK_SCHEMA, **{k: block[k] for k in ("block_id", "condition", "repetition",
                                                                         "position", "pattern")},
                  "completed": True, "qemu_before": qemu, "qemu_after": qemu,
                  "measure_start_unix": m0, "measure_end_unix": m1}
        if condition in aba.MONITORED:
            status["component"] = {"pid": 20, "rc": 0, "stopped_by": "exited"}
        aba.write_json(bdir / "block.json", status)
    aba.write_json(run / "run_end.json", {"schema": aba.RUN_END_SCHEMA, "completed": True,
                                          "blocks_done": [b["block_id"] for b in plan["blocks"]],
                                          "guest_after": guest, "ended_utc": utc(start + len(plan["blocks"]) * BLOCK_GAP_S)})
    return run
