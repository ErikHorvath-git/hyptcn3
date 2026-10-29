"""scripts/campaign_report.py over synthetic sessions and campaigns (no VM, no root, no RAM).

Fixtures use the formats of their producers: session.json/end.json as written by
collection.capture_session (logs_manifest.json by the real collection.write_logs_manifest),
request/interval logs with the host_traffic record layout, host_monitor samples, vmicollect/1
sidecars, collection.py audits, archives made by the real collection_archive (zstd members,
receipt, raw/ link into the archive) and campaign state written by campaign.update_state on a
fake clock. Every time derives from T0, so expected values are exact.
"""
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from scripts import campaign as camp
from scripts import campaign_report as cr
from scripts import collection
from scripts import collection_archive as arc
from scripts import host_monitor
from scripts import traffic_log as tl

REPO = Path(__file__).resolve().parents[2]
T0 = 1_800_000_000.0
RUN = "feedc0ffee00"
GUEST = {"kernel": "synthetic-kernel", "boot_id": "11111111-2222-3333-4444-555555555555",
         "machine_id": "synthetic-machine", "stack_sha256": "synthetic-stack", "stack_manifest": []}
QEMU = {"pid": 4242, "start_ticks": 1, "host_boot": "synthetic-host-boot"}
SCENARIO = {"workers": 4, "burst": 0.2, "catalog_share": 0.5, "write_share": 0.2}
PROTOCOL = {"schema": "hyptcn3/collection-protocol/2", "name": "synthetic", "status": "pilot_required",
            "domain": "synthetic-vm", "target": "http://127.0.0.1:18080", "profile": "profiles/none",
            "interval_s": 5, "max_gap_s": 7.5, "bin_bytes": 16777216, "window_rows": 2, "stride": 1,
            "full_every": 6, "cycles": 12, "pilot_cycles": 10, "warmup_s": 20, "min_free_gib": 0,
            "roles": {"train": 2, "dev": 1}, "scenarios": {"quiet": SCENARIO, "steady": SCENARIO},
            "quality_policy": "behavioral-inputs-v1", "min_score_coverage": 0.6}
HAVE_ZSTD = shutil.which(arc.ZSTD) is not None


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def iso_z(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_json(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")


def write_log(path, schema, records, torn=None):
    text = "".join(json.dumps({"schema": schema, "n": n, **r}) + "\n" for n, r in enumerate(records))
    path.write_text(text + (torn or ""))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def nearest_rank_brute(values, q):
    """Nearest rank by definition: the smallest value with at least ceil(q*n) values <= it."""
    need = max(1, math.ceil(q * len(values)))
    for candidate in sorted(values):
        if sum(1 for v in values if v <= candidate) >= need:
            return candidate


# ---------------------------------------------------------------- one synthetic session

def traffic(d, sid, g0, measure, post, gen_end, *, rate, errors, rng, end_record=True, unlogged_intervals=0):
    """Request and interval logs of one generator run (phase and interval by request start).

    unlogged_intervals: the last N intervals never reach the interval log (generator killed before it
    emitted them); their requests stay in the request log."""
    config = {"target": PROTOCOL["target"], "profile": "lab", "seed": 1, **SCENARIO, "dur": 0.0,
              "summary_interval_s": 5.0, "initial_phase": "warmup", "timeout_s": 4}
    head = {"type": "header", "session_id": sid, "run_id": RUN, "generator": "synthetic", "config": config,
            "start_utc": iso(g0), "start_unix": g0, "mono_origin": 100.0}
    changes = [(round(t - g0, 6), name) for t, name in ((measure, "measure"), (post, "post")) if t is not None]
    end_mono = round(gen_end - g0, 6)

    def phase_at(mono):
        current = "warmup"
        for at, name in changes:
            if mono >= at:
                current = name
        return current

    cuts = sorted({5.0 * k for k in range(int(end_mono // 5) + 1)} | {at for at, _ in changes} | {end_mono})
    bounds = list(zip(cuts, cuts[1:]))
    starts = [(k + 0.1) / rate for k in range(int((end_mono - 1.5) * rate))]
    if post is not None:  # started in measure, logged after the 'post' marker: still a measure request
        starts.append(round(post - g0 - 0.05, 6))
    routes = (("GET", "/api/catalog"), ("GET", "/api/orders"), ("POST", "/api/orders"), ("GET", "/healthz"))
    requests = []
    for k, start in enumerate(sorted(starts)):
        method, route = routes[k % len(routes)]
        outcome, status = "ok", 201 if method == "POST" else 200
        if errors and k % 17 == 5:
            outcome, status = "http_error", 503
        elif errors and k % 29 == 7:
            outcome, status = "timeout", None
        elif errors and k % 31 == 11:
            outcome, status = "transport_error", None
        duration = 900.0 if post is not None and abs(start - (post - g0 - 0.05)) < 1e-6 else \
            round(rng.lognormvariate(1.9, 0.7), 3)
        index = next(i for i, (a, b) in enumerate(bounds) if a <= start < b)
        requests.append({"type": "request", "session_id": sid, "run_id": RUN, "rid": f"{RUN}-{k % 4:02d}-{k:08d}",
                         "worker": k % 4, "worker_seq": k // 4, "interval": index, "phase": phase_at(start),
                         "method": method, "route": route, "status": status, "outcome": outcome,
                         "error": None if outcome == "ok" else outcome, "t_start_utc": iso(g0 + start),
                         "t_end_utc": iso(g0 + start + duration / 1000), "t_start_mono": round(start, 6),
                         "t_end_mono": round(start + duration / 1000, 6), "duration_ms": duration,
                         "response_bytes": 100})
    intervals = []
    for i, (a, b) in enumerate(bounds):
        members = [r for r in requests if r["interval"] == i]
        ok = [r for r in members if r["outcome"] == "ok"]
        key = lambda r: f"{r['method']} {r['route']}"  # noqa: E731
        intervals.append({
            "type": "interval", "interval": i, "phase": phase_at(a), "t_start_utc": iso(g0 + a),
            "t_end_utc": iso(g0 + b), "mono_start": a, "mono_end": b, "duration_s": round(b - a, 6),
            "requests": len(members), "ok": len(ok),
            **{o: sum(r["outcome"] == o for r in members) for o in tl.OUTCOMES if o != "ok"},
            "status_codes": dict(Counter("none" if r["status"] is None else str(r["status"]) for r in members)),
            "routes": dict(Counter(key(r) for r in members)),
            "route_errors": dict(Counter(key(r) for r in members if r["outcome"] != "ok")),
            "throughput_rps": round(len(members) / (b - a), 3), "ok_rps": round(len(ok) / (b - a), 3),
            "sum_ms": round(sum(r["duration_ms"] for r in members), 3),
            "min_ms": min((r["duration_ms"] for r in members), default=None),
            "max_ms": max((r["duration_ms"] for r in members), default=None),
            "hist": dict(Counter(str(tl.bucket_index(r["duration_ms"])) for r in members)),
            "hist_ok": dict(Counter(str(tl.bucket_index(r["duration_ms"])) for r in ok))})
    marks = [{"type": "phase", "phase": name, "previous": "warmup" if name == "measure" else "measure",
              "t_utc": iso(g0 + at), "t_mono": at, "interval": next(i for i, (a, _) in enumerate(bounds) if a >= at)}
             for at, name in changes]
    outcomes = Counter(r["outcome"] for r in requests)

    def end(records):
        return {"type": "end", "requests_started": len(requests), "requests_completed": len(requests),
                **{o: outcomes[o] for o in tl.OUTCOMES}, "in_flight_at_stop": 0, "worker_errors": 0,
                "log_backpressure_s": 0.0, "phase": phase_at(end_mono), "end_utc": iso(gen_end),
                "end_mono": end_mono, "records": records + 1, "requests_logged": len(requests),
                "write_errors": 0, "clean": True}

    timeline = sorted([(r["t_end_mono"], 1, r["rid"], r) for r in requests] +
                      [(m["t_mono"], 0, m["phase"], m) for m in marks], key=lambda item: item[:3])
    request_log = [head] + [item[3] for item in timeline]
    interval_log = [dict(head)]
    for iv in intervals[:len(intervals) - unlogged_intervals]:
        interval_log += [m for m in marks if m["interval"] == iv["interval"]] + [iv]
    if end_record:
        request_log.append(end(len(request_log)))
        interval_log.append(end(len(interval_log)))
    write_log(d / "traffic_requests.jsonl", tl.REQUEST_SCHEMA, request_log,
              torn=None if end_record else '{"schema": "hyptcn3/traffic-request/1", "n": ')
    write_log(d / "traffic_intervals.jsonl", tl.INTERVAL_SCHEMA, interval_log)
    return requests, intervals


def monitor(d, sid, t_from, t_to):
    records = [{"schema": host_monitor.SCHEMA, "type": "header", "session_id": sid, "start_utc": iso(t_from),
                "interval_s": 1.0, "disks": ["sda", "sdb"], "paths": [str(d), "/"], "cpus": 6}]
    t, i = t_from, 0
    while t <= t_to:
        records.append({
            "type": "sample", "i": i, "t_utc": iso(t), "t_mono": round(t - t_from, 6),
            "mem_kb": {"MemAvailable": 8_000_000 - 10 * i, "SwapTotal": 2_000_000, "SwapFree": 2_000_000 - 4 * (i % 50)},
            "vmstat": {"pswpin": 100 + i // 10, "pswpout": 7 + i // 40, "pgmajfault": 0, "pgpgin": 0, "pgpgout": 0},
            "disks": {"sda": {"reads": 0, "sectors_read": 0, "writes": i, "sectors_written": 1000 + 16 * i, "io_ms": i},
                      "sdb": {"reads": 0, "sectors_read": 0, "writes": i, "sectors_written": 500 + 2 * i, "io_ms": i}},
            "cpu": {"jiffies": [i] * 8, **({"busy_pct": round(10 + (i * 7) % 23 + 0.125, 3)} if i else {})},
            "fs": {str(d): {"free_bytes": 100_000_000_000 - 1_000_000 * i, "total_bytes": 200_000_000_000},
                   "/": {"free_bytes": 400_000_000_000 - 1000 * i, "total_bytes": 900_000_000_000}},
            "temps_c": {"coretemp/Package id 0/hwmon2": 40.0 + (i % 6), "nvme/Composite/hwmon1": None}})
        t, i = t + 1.0, i + 1
    records.append({"type": "end", "end_utc": iso(t_to), "samples": i, "missed_ticks": 0, "signal": 15,
                    "clean": True})
    (d / "host_monitor.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))


def capture(d, times, *, skips, completed, cycles):
    """raw/ with one vmicollect/1 sidecar and image per snapshot; skipped_before is a running total."""
    raw = d / "raw"
    raw.mkdir()
    running, lines = 0, [f"{iso_z(times[0] - 3)} INFO  zacinam zber: perioda 5.000 s"]
    for seq, t in enumerate(times):
        full = seq % PROTOCOL["full_every"] == 0
        size = (100_000 if full else 70_000) + seq
        name = f"lab_{seq:06d}_{datetime.fromtimestamp(t, timezone.utc).strftime('%Y%m%dT%H%M%S%f')[:-3]}Z"
        pattern = b"synthetic RAM %06d " % seq
        image = raw / (name + ".vmicd")
        image.write_bytes((pattern * (size // len(pattern) + 1))[:size])
        total = 5000.0 + 600 * skips[seq] if skips.get(seq) else (2400.0 + seq if full else 950.0 + 10 * (seq % 5))
        write_json(raw / (name + ".json"), {
            "schema": "vmicollect/1", "version": "1.0.0", "seq": seq, "id": name, "path": str(image),
            "timestamp": iso_z(t), "timestamp_unix": round(t, 3),
            "vm": {"domain": "synthetic-vm", "backend": "ebpf/kvm", "memsize": 2 ** 31},
            "capture": {"regions": [], "paused": False, "pause_ms": 0.0, "capture_ms": round(total - 40.0, 3),
                        "write_ms": 40.0, "total_ms": total},
            "stats": {"bytes_requested": 2 ** 31, "bytes_read": 2 ** 31, "chunks": 2048, "read_errors": 0,
                      "filled_zero": 0, "read_mib_s": 900.0},
            "sched": {"lateness_s": 0.0, "skipped_before": running},
            "output": {"writer": "delta", "full": full, "fsync": False, "chain_id": int(times[0] * 1000),
                       "bytes_logical": 2 ** 32, "bytes_on_disk": -(-size // 4096) * 4096, "pages_total": 524353,
                       "pages_changed": 200_000 if full else 5000 + seq, "page_size": 4096,
                       "sha256_covers_file": True, "hash_deferred": full, "sha256": sha(image)}})
        lines.append(f"{iso_z(t + total / 1000)} INFO  #{seq} {'full ' if full else 'delta'} spolu {total:.1f} ms")
        running += skips.get(seq, 0)
    lines.append(f"{iso_z(times[-1] + 1.5)} INFO  koniec: {len(times)} snimok, 0 chyb, {running} zmeskanych "
                 "slotov, najvacsie meskanie 0.000 s, spolu 1.00 GiB")
    (raw / "collect.log").write_text("\n".join(lines) + "\n")
    if completed:
        write_json(raw / "capture.json", {"schema": "hyptcn3/lab-capture/1", "values": {
            "requested_cycles": cycles, "interval_s": 5, "collector_exit_code": 0, "snapshots": len(times),
            "full_every": PROTOCOL["full_every"], "fsync": False, "hash_async": True}})
    return running


def write_audit(d, sid, *, role, cycles, accepted, windows, reasons=(), prefix="audit_", stamp="20270115T090000000000Z",
                coverage=True, logs=True, extra=None):
    npz = d / f"{prefix}{stamp}.npz"
    npz.write_bytes(b"synthetic features " + sid.encode())
    source, raw_bytes, observed = {}, 0, 0
    for side in sorted((d / "raw").glob("*.json")):
        if json.loads(side.read_text()).get("schema") != "vmicollect/1":
            continue
        image = side.with_suffix(".vmicd")
        source[image.name], source[side.name] = sha(image), sha(side)
        raw_bytes += image.stat().st_size
        observed += 1
    ideal = cr.ideal_windows(cycles, PROTOCOL["window_rows"], PROTOCOL["full_every"])
    fulls = len(range(0, observed, PROTOCOL["full_every"]))
    values = {"accepted": accepted, "reasons": sorted(reasons), "role": role, "protocol_sha256": sha(d / "protocol.json"),
              "snapshots": observed, "windows": windows, "score_coverage": windows / cycles,
              "coverage": {"schema": "hyptcn3/score-coverage/1", "session": sid, "window_rows": PROTOCOL["window_rows"],
                           "observed_snapshots": observed, "expected_snapshots": cycles,
                           "missing_snapshots": cycles - observed, "scorable_windows": windows,
                           "score_coverage": windows / cycles, "ideal_windows": ideal,
                           "ideal_score_coverage": ideal / cycles, "lost_windows_vs_ideal": max(0, ideal - windows),
                           "gate_possible_at_assigned_length": ideal / cycles >= PROTOCOL["min_score_coverage"],
                           "state_rows": {"scorable": windows, "full_snapshot": fulls, "warmup": fulls,
                                          "invalid_input": observed - windows - 2 * fulls},
                           "unscored_rows_by_cause": {"full_snapshot": 2 * fulls,
                                                      "invalid_input": observed - windows - 2 * fulls},
                           "first_score_seq": 2 if windows else None, "longest_observed_unscored_run_rows": 2,
                           "nominal_scored_s": windows * 5, "nominal_unscored_s": (cycles - windows) * 5}
              if coverage else None,
              "logs": {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True, "problems": [],
                       "sections": {"traffic": tl.summarize(d / "traffic_requests.jsonl", d / "traffic_intervals.jsonl",
                                                             session_id=sid)}} if logs else None,
              "raw_bytes": raw_bytes, "source_sha256": source, "session_sha256": sha(d / "session.json"),
              "extractor_sha256": {}, "features": str(npz), "features_sha256": sha(npz), "session_dir": str(d)}
    if not logs:
        values.pop("logs")
    path = d / f"{prefix}{stamp}.json"
    write_json(path, {"schema": "hyptcn3/collection-audit/1", "date": iso(T0), "commit": "synthetic",
                      "commit_dirty": False, "measurement_dirty": [], "guest": GUEST, "command": "synthetic",
                      "n": observed, "values": values, **(extra or {})})
    return path


def make_session(base, sid, *, start, kind="accepted", role="train", group="train-1", scenario="steady", seed=1,
                 cycles=12, present=None, skips=None, rate=4.0, errors=False, campaign_id=None, windows=8,
                 reasons=(), audit_prefix="audit_", meta_extra=None, audit_extra=None):
    """One session directory in the layout of collection.capture_session; returns its expected times."""
    d = base / sid
    (d / "guest").mkdir(parents=True)
    write_json(d / "protocol.json", PROTOCOL)
    skips = skips or {}
    if kind == "schema1":
        write_json(d / "session.json", {"schema": "hyptcn3/collection-session/1", "session_id": sid,
                                        "campaign_id": campaign_id, "role": role, "group": group,
                                        "scenario": scenario, "typ": "benign", "seed": seed, "guest_before": GUEST,
                                        "protocol_sha256": sha(d / "protocol.json"), "created_unix": start})
        times = [start + 130 + 5 * i for i in range(present or 3)]
        capture(d, times, skips={}, completed=False, cycles=cycles)
        write_json(d / "end.json", {"completed": False, "capture_started_unix": start + 129, "error": "signal 15"})
        return {"dir": d, "times": times}
    write_json(d / "session.json", {
        "schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": campaign_id, "role": role,
        "group": group, "group_attempt": 1, "scenario": scenario, "typ": "benign", "seed": seed, "cycles": cycles,
        "guest_before": GUEST, "protocol_sha256": sha(d / "protocol.json"),
        "collector_settings": {"writer": "delta", "fsync": False, "hash": "sha256", "hash_async": True,
                               "interval_s": 5, "full_every": PROTOCOL["full_every"], "bin_bytes": 16777216},
        "traffic": {"generator": "scripts/host_traffic.py", "profile": "lab", "target": PROTOCOL["target"],
                    "seed": seed, **SCENARIO, "summary_interval_s": 5},
        "commit": "synthetic", "commit_dirty": False, "measurement_dirty": [], "host_context": {"qemu": QEMU},
        "created_unix": start, **(meta_extra or {})})
    for name in ("domain.xml", "capture.log", "traffic.log", "host_monitor.log"):
        (d / name).write_text("synthetic\n")
    write_json(d / "preflight_smoke.json", {"schema": "hyptcn3/lab-smoke/1", "values": {"checks": []}})
    write_json(d / "guest" / "clock_before.json", {"offset_s": 0.0125, "uncertainty_s": 0.002})
    steps = {"clock": {"unix": start + 1, "offset_s": 0.0125}, "functional-check": {"unix": start + 2}}
    end = {"schema": "hyptcn3/collection-end/2", "completed": False, "interrupted": False, "steps": steps}
    truth = {"dir": d, "times": [], "g0": None, "measure": None, "post": None}
    if kind == "preflight_failed":
        end.update(error="ValueError: request ID correlation failed for the preflight checks", signals=[],
                   written_unix=start + 5.5)
    else:
        rng = random.Random(f"{sid}/{seed}")
        steps["pre-segment"] = {"unix": start + 3}
        g0 = start + 4.0
        steps["warmup"] = {"unix": g0, "seconds": PROTOCOL["warmup_s"]}
        measure = g0 + PROTOCOL["warmup_s"] if kind != "warmup_failed" else None
        truth.update(g0=g0, measure=measure)
        times = []
        if measure is not None:
            steps["capture"] = {"unix": measure + 0.01, "cycles": cycles}
            end.update(measure_start_unix=measure, capture_started_unix=measure + 0.001)
            t = measure + 1.5
            for seq in range(cycles if present is None else present):
                times.append(t)
                t += 5 * (1 + skips.get(seq, 0))
        truth["times"] = times
        completed = kind in ("accepted", "rejected", "unaudited", "killed_generator")
        post = times[-1] + 1.2 if completed else None
        stop = (times[-1] + 2.0) if times else g0 + 8
        gen_end = post + 1.0 if completed else stop + 0.3
        if kind == "killed_generator":  # SIGUSR2 had no effect; SIGKILL 30 s later: no 'post' marker, no end records
            gen_end = post + 30.0
        truth.update(post=post, gen_end=gen_end)
        requests, _ = traffic(d, sid, g0, measure, None if kind == "killed_generator" else post, gen_end, rate=rate,
                              errors=errors, rng=rng, end_record=kind not in ("crash", "killed_generator"),
                              unlogged_intervals=1 if kind == "killed_generator" else 0)
        truth["requests"] = requests
        monitor(d, sid, start + 3.5, gen_end + 0.5)
        if times:
            capture(d, times, skips=skips, completed=completed, cycles=cycles)
        children = {"traffic": {"pid": 2, "stopped_by": "SIGTERM", "rc": 0},
                    "monitor": {"pid": 3, "stopped_by": "SIGTERM", "rc": 0}}
        if completed:
            steps["guest-evidence"] = {"unix": post + 2, "nginx_lines": len(requests)}
            write_json(d / "guest" / "clock_after.json", {"offset_s": -0.004, "uncertainty_s": 0.002})
            end.update(completed=True, capture_finished_unix=times[-1] + 1.0, collector_rc=0, measure_end_unix=post,
                       traffic_rc=0, guest_after=GUEST, signals=[], written_unix=post + 3, **children)
            if kind == "killed_generator":
                end.update(traffic={"pid": 2, "stopped_by": "SIGKILL after 30s", "rc": -9}, traffic_rc=-9,
                           written_unix=gen_end + 3)
        elif kind in ("interrupted", "crash"):
            end.update(interrupted=True, error="InterruptedError: interrupted by signal 15",
                       collector={"pid": 1, "stopped_by": "SIGTERM", "rc": 143}, signals=[{"signal": 15, "unix": stop}],
                       note="Interrupted run.", written_unix=stop + 0.8, **children)
        else:  # warmup_failed
            end.update(error="ValueError: another host_traffic.py appeared during warmup", signals=[],
                       written_unix=stop + 0.8, **children)
    end["measurement_started"] = "measure_start_unix" in end  # collection.capture_session, finally block
    if kind != "crash":  # a crashed runner writes neither the manifest nor end.json (finally block not reached)
        end["logs_manifest_sha256"] = collection.write_logs_manifest(d)
        write_json(d / "end.json", end)
    if kind in ("accepted", "rejected"):
        truth["audit"] = write_audit(d, sid, role=role, cycles=cycles, accepted=kind == "accepted",
                                     windows=windows, reasons=reasons, prefix=audit_prefix, extra=audit_extra)
    return truth


def archive(d, destination):
    """Verified archive with zstd members and raw/ reclaimed into a link (collection_archive itself)."""
    doc = arc.publish_archive(d, destination, lambda: None, 0, compress="zstd" if HAVE_ZSTD else None)
    arc.reclaim_raw(d, destination, doc, lambda: None)
    return doc


def run_report(argv, monkeypatch=None):
    if monkeypatch is not None:  # one git state for both runs of a determinism check
        monkeypatch.setattr(cr, "git_identity", lambda: {"commit": "synthetic", "dirty": False, "changed_paths": 0})
    return cr.main(list(map(str, argv)))


def read_csv(path):
    return list(csv.DictReader(io.StringIO(Path(path).read_text())))


def by_id(rows):
    return {r["session_id"]: r for r in rows}


# ---------------------------------------------------------------- sessions mode

@pytest.fixture(scope="module")
def sessions(tmp_path_factory):
    base = tmp_path_factory.mktemp("sessions")
    work, store = base / "collections", base / "archive"
    work.mkdir()
    truth = {
        "acc": make_session(work, "acc", start=T0, kind="accepted", skips={3: 1}, errors=True, rate=6.0),
        "rej": make_session(work, "rej", start=T0 + 1000, kind="rejected", windows=5,
                            reasons=("score coverage below design gate 0.6",
                                     "incomplete model inputs under behavioral-inputs-v1")),
        "int": make_session(work, "int", start=T0 + 2000, kind="interrupted", present=4),
        "pre": make_session(work, "pre", start=T0 + 3000, kind="preflight_failed"),
        "warm": make_session(work, "warm", start=T0 + 3100, kind="warmup_failed"),
        "una": make_session(work, "una", start=T0 + 4000, kind="unaudited"),
        "crash": make_session(work, "crash", start=T0 + 5000, kind="crash", present=3),
        "old": make_session(work, "old", start=T0 + 6000, kind="schema1", role="pilot", present=3),
    }
    manifest = archive(work / "acc", store / "acc")
    (work / "not-a-session").mkdir()
    out = base / "report"
    dirs = [work / name for name in truth] + [work / "not-a-session"]
    assert run_report(["sessions", *dirs, "--out", out]) == 0
    return {"base": base, "work": work, "out": out, "truth": truth, "manifest": manifest, "dirs": dirs}


def test_statuses_reasons_and_denominators(sessions):
    rows = by_id(read_csv(sessions["out"] / "sessions.csv"))
    assert {k: rows[k]["status"] for k in rows} == {
        "acc": "accepted", "rej": "rejected", "int": "interrupted", "pre": "incomplete", "warm": "incomplete",
        "una": "incomplete", "crash": "incomplete", "old": "interrupted"}
    assert "score coverage below design gate 0.6" in rows["rej"]["reasons"]
    assert rows["int"]["reasons"].startswith("InterruptedError: interrupted by signal 15")
    assert rows["pre"]["reasons"] == "ValueError: request ID correlation failed for the preflight checks"
    assert rows["una"]["reasons"] == "capture completed; no audit verdict"
    assert rows["crash"]["reasons"].startswith("no end.json")
    assert "schema 1" in rows["old"]["reasons"]
    summary = json.loads((sessions["out"] / "summary.json").read_text())
    block = summary["sessions"]
    assert block["planned"] is None and block["planned_missing"] == "sessions mode: no campaign plan"
    assert block["attempted"] == 8 and block["accepted"] == 1 and block["rejected"] == 1
    assert block["interrupted"] == 2 and block["incomplete"] == 4
    assert block["accepted_of_attempted"] == {"numerator": 1, "denominator": 8, "value": 0.125}
    assert block["reason_classes_by_status"]["rejected"] == {
        "incomplete model inputs under behavioral-inputs-v1": 1, "score coverage below design gate 0.6": 1}
    # The non-session directory is reported, never silently dropped.
    assert [i["problem"] for i in summary["inputs_unreadable"]] == [
        "no session.json (not a collection session directory)"]
    readme = (sessions["out"] / "README.md").read_text()
    assert "not-a-session" in readme and "- Sessions without end.json: 1:\n  - `crash`" in readme


def test_capture_hours_count_only_first_to_last_snapshot(sessions):
    truth, out = sessions["truth"], sessions["out"]
    rows = by_id(read_csv(out / "sessions.csv"))
    spans = {k: t["times"][-1] - t["times"][0] for k, t in truth.items() if len(t["times"]) > 1}
    for name, span in spans.items():
        assert float(rows[name]["capture_span_s"]) == pytest.approx(span, abs=1e-6)
    # The accepted session skipped one slot: the span includes it, warmup and runner time do not.
    assert spans["acc"] == pytest.approx(5 * 12)
    summary = json.loads((out / "summary.json").read_text())
    capture_time = summary["capture_time"]
    assert capture_time["accepted"]["seconds"] == pytest.approx(spans["acc"])
    assert capture_time["accepted"]["sessions_counted"] == 1
    assert capture_time["all_attempted"]["seconds"] == pytest.approx(sum(spans.values()))
    assert capture_time["all_attempted"]["hours"] == pytest.approx(sum(spans.values()) / 3600, abs=1e-6)
    # Warmup is reported separately (generator start to its measure marker) and never added to capture time;
    # the run stopped during warmup counts its warmup until the generator end record (g0 + 8 s + 0.3 s).
    assert float(rows["acc"]["warmup_s"]) == pytest.approx(PROTOCOL["warmup_s"])
    assert float(rows["warm"]["warmup_s"]) == pytest.approx(8.3)
    assert rows["warm"]["warmup_end_source"] == "generator end record (the run ended before the measure phase)"
    assert summary["warmup_time"]["seconds"] == pytest.approx(PROTOCOL["warmup_s"] * 5 + 8.3)
    assert (summary["warmup_time"]["sessions_reaching_measure"], summary["warmup_time"]["sessions_ended_during_warmup"]) \
        == (5, 1)
    wall = float(rows["acc"]["session_wall_s"])
    assert wall > float(rows["acc"]["capture_span_s"]) + PROTOCOL["warmup_s"]


def test_latency_percentiles_are_exact_over_request_records(sessions):
    truth, out = sessions["truth"]["acc"], sessions["out"]
    row = by_id(read_csv(out / "sessions.csv"))["acc"]
    measure = [r for r in truth["requests"] if r["phase"] == "measure"]
    durations = [r["duration_ms"] for r in measure]
    ok = [r["duration_ms"] for r in measure if r["outcome"] == "ok"]
    assert len(ok) < len(durations)  # failures exist and are included in the all-request latencies
    for name, q in (("p50", .5), ("p95", .95), ("p99", .99), ("max", 1.0)):
        assert float(row[f"latency_all_{name}_ms"]) == nearest_rank_brute(durations, q)
        assert float(row[f"latency_ok_{name}_ms"]) == nearest_rank_brute(ok, q)
    summary = tl.summarize(sessions["work"] / "acc" / "traffic_requests.jsonl",
                           sessions["work"] / "acc" / "traffic_intervals.jsonl", session_id="acc")
    assert float(row["latency_all_p95_ms"]) == summary["measure"]["latency_ms"]["p95"]
    assert int(row["http_requests"]) == summary["measure"]["requests"] == len(measure)
    assert int(row["http_errors"]) == len(measure) - len(ok)
    assert int(row["http_status_errors"]) + int(row["http_timeouts"]) + int(row["http_transport_errors"]) == \
        int(row["http_errors"])
    assert row["traffic_matches_audit"] == "true"
    # The request started before the 'post' marker but logged after it counts in measure.
    late = [r for r in measure if r["duration_ms"] == 900.0]
    assert len(late) == 1 and float(row["latency_all_max_ms"]) == 900.0
    measure_s = sum(iv["duration_s"] for iv in (json.loads(line) for line in
                    (sessions["work"] / "acc" / "traffic_intervals.jsonl").read_text().splitlines())
                    if iv.get("type") == "interval" and iv["phase"] == "measure")
    assert float(row["http_rps"]) == pytest.approx(len(measure) / measure_s, abs=1e-6)
    routes = read_csv(out / "routes.csv")
    assert sum(int(r["requests"]) for r in routes if r["session_id"] == "acc") == len(measure)


def test_latency_stats_matches_brute_force_on_random_values():
    from array import array
    rng = random.Random(7)
    for n in (1, 2, 3, 19, 20, 21, 100, 1001):
        values = [round(rng.lognormvariate(1, 1.3), 2) for _ in range(n)]  # rounding creates ties
        stats = cr.latency_stats(array("d", values))
        assert stats["n"] == n and stats["max"] == max(values)
        for name, q in cr.QUANTILES:
            assert stats[name] == nearest_rank_brute(values, q) == tl.percentile(sorted(values), q)
    assert cr.latency_stats(array("d"))["p50"] is None


def test_intervals_cycles_and_missed_slots(sessions):
    out, truth = sessions["out"], sessions["truth"]
    intervals = read_csv(out / "intervals.csv")
    acc = [r for r in intervals if r["session_id"] == "acc"]
    logged = [json.loads(line) for line in (sessions["work"] / "acc" / "traffic_intervals.jsonl").read_text().splitlines()]
    logged = [r for r in logged if r.get("type") == "interval"]
    assert [int(r["interval"]) for r in acc] == [r["interval"] for r in logged]
    assert {r["phase"] for r in acc} == {"warmup", "measure", "post"}
    assert sum(int(r["requests"]) for r in acc) == len(truth["acc"]["requests"])
    cycles = [r for r in read_csv(out / "collector_cycles.csv") if r["session_id"] == "acc"]
    assert [int(r["seq"]) for r in cycles] == list(range(12))
    assert [int(r["skipped_before"]) for r in cycles] == [0] * 4 + [1] * 8  # running total from the collector
    assert [int(r["skipped_since_previous_snapshot"]) for r in cycles] == [0] * 4 + [1] + [0] * 7
    assert [r["full"] for r in cycles].count("true") == 2
    row = by_id(read_csv(out / "sessions.csv"))["acc"]
    assert row["missed_slots"] == "1" == row["collector_end_missed_slots"]  # never a sum of running totals
    assert row["cycles_at_or_over_period"] == "1" and float(row["cycle_ms_max"]) == 5600.0
    assert row["full_cycle_ms"] == "2400.0;2406.0" and row["hash_deferred_snapshots"] == "2"
    assert row["snapshots_expected"] == "12" and row["snapshots_present"] == "12" and row["snapshots_missing"] == "0"


def test_expected_snapshots_come_from_the_assignment_not_the_files(sessions):
    rows = by_id(read_csv(sessions["out"] / "sessions.csv"))
    assert (rows["int"]["snapshots_expected"], rows["int"]["snapshots_present"], rows["int"]["snapshots_missing"]) == \
        ("12", "4", "8")
    assert rows["int"]["snapshots_expected_source"] == "session.json cycles"
    assert (rows["pre"]["snapshots_present"], rows["pre"]["snapshots_missing"]) == ("0", "12")
    # Schema 1 has no cycles in session.json: the pilot length comes from the session protocol.
    assert rows["old"]["snapshots_expected"] == str(PROTOCOL["pilot_cycles"])
    assert "pilot_cycles" in rows["old"]["snapshots_expected_source"]
    summary = json.loads((sessions["out"] / "summary.json").read_text())
    expected = 12 * 7 + PROTOCOL["pilot_cycles"]
    present = sum(len(t["times"]) for t in sessions["truth"].values())
    block = summary["snapshots"]["all_attempted"]
    assert block["expected"]["total"] == expected and block["present"]["total"] == present
    assert block["present_of_expected"] == {"numerator": present, "denominator": expected,
                                            "value": round(present / expected, 6), "sessions_counted": 8}


def test_missing_data_is_null_with_a_reason_never_invented(sessions):
    rows = by_id(read_csv(sessions["out"] / "sessions.csv"))
    pre, warm, una, old, crash = (rows[k] for k in ("pre", "warm", "una", "old", "crash"))
    # Preflight failure: nothing after the preflight exists, and it is not called missing evidence.
    for field in ("http_requests", "latency_all_p95_ms", "cycle_ms_p95", "cpu_busy_p95_pct", "capture_span_s"):
        assert pre[field] == ""
        assert field in pre["not_applicable"] and field not in pre["missing"]
    assert "the run ended before the collector started" in pre["not_applicable"]
    # The warmup failure has warmup traffic but no measure phase: no HTTP values are computed from warmup.
    assert warm["http_requests"] == warm["http_rps"] == warm["measure_start_utc"] == "" and warm["warmup_start_utc"]
    assert "the run ended before the measure phase" in warm["not_applicable"]
    # A completed capture without an audit: windows are missing, the ideal ceiling is labeled arithmetic.
    assert una["windows"] == una["score_coverage"] == "" and "no audit verdict for this session" in una["missing"]
    assert una["ideal_windows"] == "8" and una["ideal_windows_source"] == "protocol arithmetic (no audit)"
    # Schema 1: no request log or monitor; reasons say why.
    assert old["http_requests"] == "" and "session schema 1 records no request log" in old["missing"]
    assert old["cpu_busy_p95_pct"] == "" and "session schema 1 runs no host monitor" in old["not_applicable"]
    # A crash leaves no end record: completion flags stay empty, and the torn request log is reported.
    assert crash["completed"] == crash["interrupted"] == "" and "no end.json" in crash["missing"]
    assert crash["requests_log_complete"] == "false" and "torn_last_line" in crash["requests_log_problems"]
    for row in rows.values():
        missing, not_applicable = listed(row["missing"]), listed(row["not_applicable"])
        columns = [c for c in cr.SESSION_COLUMNS if c not in cr.NO_REASON_COLUMNS]
        assert {c for c in columns if row[c] == ""} == missing | not_applicable, row["session_id"]
        assert not missing & not_applicable


def listed(text):
    """Field names of a `missing`/`not_applicable` cell ('reason: f1, f2 | reason: f3')."""
    return {field for group in text.split(" | ") if group for field in group.rpartition(": ")[2].split(", ")}


def test_reclaimed_raw_link_is_read_without_opening_images(sessions):
    out, manifest = sessions["out"], sessions["manifest"]
    assert (sessions["work"] / "acc" / "raw").is_symlink()
    row = by_id(read_csv(out / "sessions.csv"))["acc"]
    assert row["archived"] == "true" and row["snapshots_present"] == row["images_present"] == "12"
    assert int(row["archive_stored_bytes"]) == manifest.get("stored_bytes", manifest["bytes"])
    images = [v for k, v in manifest["files"].items() if k.startswith("raw/") and k.endswith(".vmicd")]
    assert int(row["archive_raw_image_bytes"]) == sum(v["size"] for v in images) == int(row["raw_bytes"])
    assert int(row["raw_bytes"]) == int(row["audit_raw_bytes"])  # the audit's definition: image st_size
    if HAVE_ZSTD:
        assert row["raw_bytes_source"] == "archive-manifest.json original sizes (the images are compressed members)"
    # Sidecar bytes_on_disk is allocated space (st_blocks x 512): reported apart, never as image bytes.
    assert int(row["raw_allocated_bytes"]) == sum(-(-v["size"] // 4096) * 4096 for v in images)
    local = by_id(read_csv(out / "sessions.csv"))["rej"]
    sizes = [p.stat().st_size for p in (sessions["work"] / "rej" / "raw").glob("*.vmicd")]
    assert int(local["raw_bytes"]) == sum(sizes) == int(local["audit_raw_bytes"])
    assert local["raw_bytes_source"] == "stat of the .vmicd images (st_size)"
    assert int(row["archive_raw_image_stored_bytes"]) == sum(v.get("stored_size", v["size"]) for v in images)
    if HAVE_ZSTD:
        assert all(v["codec"] == "zstd" for v in images)
        assert int(row["archive_raw_image_stored_bytes"]) < int(row["archive_raw_image_bytes"])
    sources = read_csv(out / "sources.csv")
    assert not any(r["path"].endswith((".vmicd", ".zst")) for r in sources)  # images never opened
    sidecars = [r for r in sources if r["session_id"] == "acc" and "/raw/" in r["path"] and r["path"].endswith(".json")]
    archive_root = os.path.realpath(sessions["base"] / "archive")
    assert len(sidecars) == 12 and all(r["realpath"].startswith(archive_root) for r in sidecars)
    assert row["sidecars_differing_from_audit"] == "0" and row["evidence_hash_mismatches"] == "0"


def test_monitor_values_come_from_host_monitor_summarize(sessions):
    row = by_id(read_csv(sessions["out"] / "sessions.csv"))["acc"]
    truth = sessions["truth"]["acc"]
    doc = host_monitor.summarize(sessions["work"] / "acc" / "host_monitor.jsonl", truth["measure"], truth["post"])
    assert float(row["cpu_busy_p50_pct"]) == doc["cpu_busy_pct"]["p50"]
    assert float(row["cpu_busy_p95_pct"]) == doc["cpu_busy_pct"]["p95"]
    assert int(row["swap_used_max_kib"]) == doc["swap_used_kb_max"]
    assert int(row["swap_in_pages"]) == doc["swap_in_pages"] and int(row["swap_out_pages"]) == doc["swap_out_pages"]
    assert row["disk_bytes_written"] == f"sda={doc['disk_bytes_written']['sda']} | sdb={doc['disk_bytes_written']['sdb']}"
    assert int(row["fs_free_min_working_bytes"]) == doc["fs_free_bytes_min"][str(sessions["work"] / "acc")]
    assert float(row["temp_max_c"]) == doc["temp_c_max"]
    assert row["monitor_window_source"].endswith("(the audit's window)")
    interrupted = by_id(read_csv(sessions["out"] / "sessions.csv"))["int"]
    assert "generator end record" in interrupted["monitor_window_source"]


def test_coverage_rows_for_every_session(sessions):
    coverage = by_id(read_csv(sessions["out"] / "coverage.csv"))
    assert set(coverage) == set(sessions["truth"])
    acc, rej, una = coverage["acc"], coverage["rej"], coverage["una"]
    assert (acc["scorable_windows"], acc["ideal_windows"], acc["nominal_scored_s"], acc["nominal_unscored_s"]) == \
        ("8", "8", "40", "20")
    assert rej["scorable_windows"] == "5" and rej["gate_passed"] == "false" and acc["gate_passed"] == "true"
    assert int(rej["unscored_rows_total"]) == 12 - 5
    assert una["source"] == "no audit" and una["scorable_windows"] == "" and una["ideal_windows"] == "8"
    summary = json.loads((sessions["out"] / "summary.json").read_text())
    windows = summary["windows"]["all_attempted"]
    assert windows["scorable_windows"] == 13 and windows["pooled_score_coverage"] == {
        "numerator": 13, "denominator": 24, "value": round(13 / 24, 6), "sessions_counted": 2}
    assert windows["nominal_unscored_s"] == (12 - 8) * 5 + (12 - 5) * 5
    assert windows["sessions_with_coverage_breakdown"] == 2
    assert windows["ideal_windows_of_audited_sessions"] == {"from_audit_coverage": {"sessions": 2, "windows": 16},
                                                            "protocol_arithmetic": {"sessions": 0, "windows": 0}}
    accepted = summary["windows"]["accepted"]
    assert (accepted["sessions"], accepted["scorable_windows"], accepted["nominal_unscored_s"]) == (1, 8, 20)


def test_plots_are_labeled_svg(sessions):
    plots = sorted((sessions["out"] / "plots").glob("*.svg"))
    assert [p.name for p in plots] == ["coverage.svg", "cycles.svg", "host.svg", "latency.svg", "throughput.svg",
                                       "timeline.svg", "volume.svg"]
    axis = {"coverage.svg": "score coverage", "cycles.svg": "ms", "host.svg": "MiB", "latency.svg": "ms (log scale)",
            "throughput.svg": "requests per second", "timeline.svg": "hours since", "volume.svg": "GiB"}
    geometry = ("x", "y", "x1", "x2", "y1", "y2", "cx", "cy", "r", "width", "height")
    for path in plots:
        text = path.read_text()
        root = ET.fromstring(text)
        assert root.tag.endswith("svg") and root.find("{http://www.w3.org/2000/svg}title").text
        assert axis[path.name] in text
        for element in root.iter():
            for name in geometry:
                if name in element.attrib and not element.attrib[name].endswith("%"):
                    assert math.isfinite(float(element.attrib[name])), (path.name, element.tag, name)
    assert "gate 0.6" in (sessions["out"] / "plots" / "coverage.svg").read_text()
    assert "period 5 s" in (sessions["out"] / "plots" / "cycles.svg").read_text()


def test_definitions_and_sources(sessions):
    summary = json.loads((sessions["out"] / "summary.json").read_text())
    definitions = json.dumps(summary["definitions"])
    for phrase in ("includes failed requests", "in which they started", "Closed loop", "not measured availability",
                   "Exact nearest-rank", "running total"):
        assert phrase in definitions
    paths = {s["path"]: s["sha256"] for s in summary["sources"]}
    for name in ("session.json", "end.json", "traffic_requests.jsonl", "host_monitor.jsonl"):
        path = sessions["work"] / "acc" / name
        assert paths[str(path)] == sha(path)
    readme = (sessions["out"] / "README.md").read_text()
    for needle in ("Command: `scripts/campaign_report.py sessions", "commit", "## Files", "## Definitions",
                   "## Denominators", "## Missing or unreadable inputs"):
        assert needle in readme


# ---------------------------------------------------------------- output directory and determinism

def test_output_directory_must_be_new(sessions, tmp_path, capsys):
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "keep.txt").write_text("keep\n")
    assert run_report(["sessions", sessions["work"] / "acc", "--out", taken]) == 2
    assert [p.name for p in taken.iterdir()] == ["keep.txt"] and (taken / "keep.txt").read_text() == "keep\n"
    afile = tmp_path / "afile"
    afile.write_text("x")
    assert run_report(["sessions", sessions["work"] / "acc", "--out", afile]) == 2 and afile.read_text() == "x"
    inside = sessions["work"] / "acc" / "report"
    assert run_report(["sessions", sessions["work"] / "acc", "--out", inside]) == 2 and not inside.exists()
    assert "already exists" in capsys.readouterr().err


def test_no_readable_session_is_a_data_error(tmp_path):
    (tmp_path / "empty").mkdir()
    assert run_report(["sessions", tmp_path / "empty", "--out", tmp_path / "out"]) == 2
    assert not (tmp_path / "out").exists()
    assert run_report(["campaign", tmp_path / "empty", "--out", tmp_path / "out2"]) == 2
    with pytest.raises(SystemExit) as usage:
        cr.main(["sessions", str(tmp_path / "empty")])  # --out is required
    assert usage.value.code == 2


def test_output_is_deterministic(sessions, tmp_path, monkeypatch):
    out = tmp_path / "again"
    first = {}
    for attempt in range(2):
        assert run_report(["sessions", *sessions["dirs"], "--out", out], monkeypatch) == 0
        files = {p.relative_to(out).as_posix(): p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}
        if attempt == 0:
            first = files
            shutil.rmtree(out)
    assert sorted(first) == sorted(files)
    for name in files:
        if name == "summary.json":
            a, b = json.loads(first[name]), json.loads(files[name])
            a.pop("generated_utc"), b.pop("generated_utc")
            assert a == b
        elif name == "README.md":
            strip = lambda data: [line for line in data.decode().splitlines() if not line.startswith("Generated:")]  # noqa: E731
            assert strip(first[name]) == strip(files[name])
        else:
            assert first[name] == files[name], name
    # Rows are ordered by session start, independent of the argument order.
    rows = read_csv(out / "sessions.csv")
    assert [r["session_id"] for r in rows] == ["acc", "rej", "int", "pre", "warm", "una", "crash", "old"]


def test_cli_entry_point(sessions, tmp_path):
    out = tmp_path / "cli"
    done = subprocess.run([sys.executable, str(REPO / "scripts/campaign_report.py"), "sessions",
                           str(sessions["work"] / "rej"), "--out", str(out)], cwd=REPO, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["sessions"] == {"rejected": 1}
    again = subprocess.run([sys.executable, str(REPO / "scripts/campaign_report.py"), "sessions",
                            str(sessions["work"] / "rej"), "--out", str(out)], cwd=REPO, capture_output=True, text=True)
    assert again.returncode == 2 and "already exists" in again.stderr


def test_audit_selection_never_bypasses_a_rejection(tmp_path):
    d = make_session(tmp_path, "twice", start=T0, kind="rejected", windows=5,
                     reasons=("score coverage below design gate 0.6",))["dir"]
    later = write_audit(d, "twice", role="train", cycles=12, accepted=True, windows=8, stamp="20270116T000000000000Z")
    doc = json.loads(later.read_text())
    write_json(later, dict(doc, date=iso(T0 + 86400)))  # a later accepting re-audit
    assert run_report(["sessions", d, "--out", tmp_path / "out"]) == 0
    row = read_csv(tmp_path / "out" / "sessions.csv")[0]
    assert row["status"] == "rejected" and "earliest rejecting verdict" in row["audit_selection"]
    assert row["audit_candidates"].count("=") == 2


def test_unusable_evidence_never_yields_a_verdict(tmp_path):
    d = make_session(tmp_path, "broken", start=T0, kind="accepted")["dir"]
    (d / "end.json").write_text('{"completed": true, ')  # torn
    assert run_report(["sessions", d, "--out", tmp_path / "out"]) == 0
    row = read_csv(tmp_path / "out" / "sessions.csv")[0]
    assert row["status"] == "incomplete" and row["reasons"].startswith("end.json unreadable")
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert any(i["input"].endswith("broken/end.json") for i in summary["inputs_unreadable"])
    assert summary["sessions"]["accepted"] == 0 and summary["capture_time"]["accepted"]["seconds"] == 0


def test_unavailable_archive_is_missing_not_zero(tmp_path):
    d = make_session(tmp_path / "work", "gone", start=T0, kind="accepted")["dir"]
    archive(d, tmp_path / "disk" / "gone")
    (tmp_path / "disk").rename(tmp_path / "unmounted")  # archive disk not mounted: raw/ dangles
    assert run_report(["sessions", d, "--out", tmp_path / "out"]) == 0
    row = read_csv(tmp_path / "out" / "sessions.csv")[0]
    assert row["status"] == "accepted" and row["archived"] == "true"
    for field in ("snapshots_present", "raw_bytes", "capture_span_s", "cycle_ms_max", "archive_stored_bytes"):
        assert row[field] == "" and field in listed(row["missing"])
    assert "which is not available" in row["missing"] and "archive manifest not available" in row["missing"]
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["capture_time"]["accepted"]["sessions_without_value"] == 1
    assert sorted(i["problem"] for i in summary["inputs_unreadable"]) == [
        "archive manifest not available", f"raw/ links to {tmp_path / 'disk' / 'gone' / 'raw'}, which is not available"]


def test_ideal_windows_matches_features_coverage():
    from features.coverage import ideal_windows
    for cycles in (1, 31, 32, 33, 359, 360, 400, 480, 720, 721):
        for window, rotation in ((32, 360), (2, 6), (4, 3)):
            assert cr.ideal_windows(cycles, window, rotation) == ideal_windows(cycles, window, rotation)


def test_reason_classes_strip_session_tokens():
    assert cr.reason_class("read errors/fill/missed slots: hyptcn-lab_000361_20261020T234908593Z.vmicd") == \
        "read errors/fill/missed slots: <image>"
    assert cr.reason_class("logs: traffic:records_mismatch:12!=13") == "logs: traffic:records_mismatch:<n>!=<n>"
    assert cr.reason_class("raw/ links to /home/eh/archive/raw, which is not available") == \
        "raw/ links to <path>, which is not available"


# ---------------------------------------------------------------- campaign mode

class Clock:
    def __init__(self, t):
        self.t = t

    def now(self):
        return iso(self.t)

    def stamp(self):
        return datetime.fromtimestamp(self.t, timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def make_campaign(root, monkeypatch, *, stop_kind, first_meta=None, first_audit=None):
    """A frozen plan of 6 sessions run by the update_state sequence of campaign.execute.

    stop_kind: 'rejected' (row 3 rejected by its audit, runner stopped with an error),
    'running' (row 3 capturing now, status.json running) or 'interrupted' (row 3 stopped by a signal).
    """
    clock = Clock(T0)
    monkeypatch.setattr(camp, "now", clock.now)
    monkeypatch.setattr(camp, "stamp", clock.stamp)
    cid = "synthetic-campaign"
    data = root / "data"
    directory, collections, store = data / "campaigns" / cid, data / "collections", root / "archive"
    for child in ("events", "groups", "attempts", "logs"):
        (directory / child).mkdir(parents=True)
    collections.mkdir(parents=True)
    planned = collection.plan(PROTOCOL)
    for i, row in enumerate(planned["sessions"]):  # as campaign.initialize: plan.json keeps the session IDs
        row["session_id"] = f"{cid}_{i + 1:02d}_{row['role']}_{row['scenario']}"
    arc.write_new(directory / "protocol.json", PROTOCOL)
    arc.write_new(directory / "pilot.json", {"synthetic": True})
    arc.write_new(directory / "plan.json", planned)
    manifest = {"schema": "hyptcn3/collection-campaign/1", "id": cid, "date": iso(T0), "commit": "synthetic",
                "workspace": str(REPO), "protocol_sha256": arc.digest(directory / "protocol.json"),
                "pilot_report_sha256": arc.digest(directory / "pilot.json"), "archive_root": str(store),
                "archive_mount": {}, "archive_dir": str(store / "campaigns" / cid), "archive_compression": "zstd",
                "sessions": planned["sessions"], "planned_capture_hours": planned["planned_hours"],
                "guest_environment": {k: v for k, v in GUEST.items() if k != "boot_id"}, "extractor_sha256": {},
                "note": "Frozen allocation, not a measurement or a completed corpus."}
    arc.write_new(directory / "campaign.json", manifest)
    rows, expect = manifest["sessions"], Counter()
    camp.update_state(directory, status="ready", stage="initialized", accepted_archived=0, total=len(rows))
    clock.t += 100
    expect["before_first_launch"] += 100
    camp.update_state(directory, status="running", stage="preflight", pid=4242, message=None, signals=[])
    accepted, groups, spans = 0, set(), []
    for i, row in enumerate(rows[:3]):
        sid = row["session_id"]
        clock.t += 1
        camp.update_state(directory, status="running", stage="session-preflight", session=sid, group=row["group"],
                          role=row["role"], scenario=row["scenario"], position=i + 1, total=len(rows),
                          accepted_archived=accepted)
        clock.t += 1
        if row["group"] not in groups:  # campaign.ensure_group: a new group starts with a recorded reboot
            groups.add(row["group"])
            camp.update_state(directory, status="running", stage="reboot", group=row["group"])
            clock.t += 60
            expect["reboot"] += 60
            arc.write_new(directory / "groups" / f"{row['group']}.json", {
                "schema": "hyptcn3/campaign-group/1", "date": clock.now(), "group": row["group"], "role": row["role"],
                "identity": GUEST, "qemu": QEMU, "previous_boot": "previous"})
        camp.update_state(directory, status="running", stage="capture", capture_started_at=clock.now())
        start = clock.t + 2
        kind = "accepted" if i < 2 else {"rejected": "rejected", "running": "crash", "interrupted": "interrupted"}[stop_kind]
        truth = make_session(collections, sid, start=start, kind=kind, role=row["role"], group=row["group"],
                             scenario=row["scenario"], seed=row["seed"], cycles=row["cycles"], campaign_id=cid,
                             windows=8 if kind == "accepted" else 4,
                             present=5 if kind in ("interrupted", "crash") else None,
                             reasons=("score coverage below design gate 0.6",), audit_prefix="campaign_audit_",
                             meta_extra=first_meta if i == 0 else None, audit_extra=first_audit if i == 0 else None)
        spans.append(truth["times"][-1] - truth["times"][0])
        if kind == "crash":  # still capturing: no end.json, status.json says running on it
            return directory, rows, expect, spans
        end = json.loads((collections / sid / "end.json").read_text())
        clock.t = end["written_unix"] + 2
        if kind == "interrupted":
            camp.update_state(directory, status="stopped", stage="interrupted", message="interrupted by signal 15",
                              signals=[{"signal": 15, "unix": clock.t}])
            return directory, rows, expect, spans
        camp.update_state(directory, status="running", stage="audit", session=sid)
        clock.t += 40
        expect["audit"] += 40
        report = truth["audit"]
        arc.write_new(directory / "attempts" / f"{sid}.audit.json", {"path": str(report), "sha256": arc.digest(report)})
        camp.update_state(directory, status="running", stage="archive", session=sid)
        destination = store / "campaigns" / cid / "collections" / sid
        archive(collections / sid, destination)
        clock.t += 20
        expect["archive"] += 20
        if kind == "rejected":
            camp.update_state(directory, status="stopped", stage="error",
                              message="audit rejected session; archived without replacement: score coverage below "
                                      "design gate 0.6", signals=[])
            return directory, rows, expect, spans
        arc.write_new(directory / "attempts" / f"{sid}.done.json", {
            "session": sid, "audit": str(report), "audit_sha256": arc.digest(report),
            "manifest_sha256": arc.digest(destination / "archive-manifest.json"), "date": clock.now()})
        accepted += 1
        camp.update_state(directory, status="running", stage="session-complete", accepted_archived=accepted)
        clock.t += 1
        if i == 1:  # planned stop at a session boundary, relaunched 1000 s later
            camp.update_state(directory, status="stopped", stage="between-sessions",
                              message="requested stop-after boundary")
            clock.t += 1000
            expect["stopped"] += 1000
            camp.update_state(directory, status="running", stage="preflight", pid=4343, message=None, signals=[])
    raise AssertionError("unreachable")


@pytest.mark.parametrize("stop_kind", ["rejected", "running", "interrupted"])
def test_campaign_report(tmp_path, monkeypatch, stop_kind):
    directory, rows, expect, spans = make_campaign(tmp_path, monkeypatch, stop_kind=stop_kind)
    out = tmp_path / "report"
    assert run_report(["campaign", directory, "--out", out]) == 0
    sessions = read_csv(out / "sessions.csv")
    assert [r["session_id"] for r in sessions] == [r["session_id"] for r in rows]  # every planned row, plan order
    third = {"rejected": "rejected", "running": "in_progress", "interrupted": "interrupted"}[stop_kind]
    assert [r["status"] for r in sessions] == ["accepted", "accepted", third, "planned", "planned", "planned"]
    assert all(r["campaign_done"] == "true" for r in sessions[:2]) and sessions[2]["campaign_done"] == "false"
    assert all(r["reasons"] == "not started" and r["session_dir"] == "" for r in sessions[3:])
    assert all(r["snapshots_expected"] == "12" and r["snapshots_expected_source"] == "campaign plan cycles"
               for r in sessions[3:])
    summary = json.loads((out / "summary.json").read_text())
    block = summary["sessions"]
    assert (block["planned"], block["attempted"], block["not_started"], block["accepted"]) == (6, 3, 3, 2)
    assert block[third] == 1 and block["accepted_of_planned"] == {"numerator": 2, "denominator": 6,
                                                                  "value": round(2 / 6, 6)}
    assert block["accepted_with_campaign_checkpoint"] == 2
    assert summary["campaign"]["problems"] == []  # plan.json carries session IDs, as campaign.initialize writes it
    capture_time = summary["capture_time"]
    assert capture_time["accepted"]["seconds"] == pytest.approx(sum(spans[:2]))
    assert capture_time["all_attempted"]["seconds"] == pytest.approx(sum(spans))
    assert capture_time["planned_capture_hours"] == 6 * 12 * 5 / 3600
    assert summary["snapshots"]["expected_planned"]["total"] == 72
    # The plan counts cycles x period; a complete session's measured interval is one period shorter.
    assert capture_time["slots_nominal"]["accepted"]["seconds"] == 2 * 12 * 5
    assert capture_time["accepted"]["seconds"] == pytest.approx(2 * 11 * 5)
    timing = summary["campaign_time"]
    events = sorted((directory / "events").glob("*.json"))
    assert timing["events"] == len(events) == len(read_csv(out / "events.csv"))
    for category in ("before_first_launch", "reboot", "audit", "archive", "stopped"):
        if expect[category]:
            assert timing["by_category_s"][category] == pytest.approx(expect[category]), category
    assert timing["sum_of_categories_s"] == pytest.approx(timing["wall_clock_span_s"])
    # Downtime and runner stages are reported, but never become collection hours.
    assert capture_time["accepted"]["seconds"] < timing["by_category_s"]["capture_stage"]
    assert timing["by_category_s"]["stopped"] >= 1000
    coverage = read_csv(out / "coverage.csv")
    assert len(coverage) == 6 and [r["source"] for r in coverage[3:]] == ["no audit"] * 3
    readme = (out / "README.md").read_text()
    assert "- Planned sessions without a session directory (not started): 3:" in readme
    assert "Planned sessions: 6" in readme and "not started (no session directory): 3" in readme
    assert "one period shorter than its allocation" in readme
    if stop_kind == "running":
        assert "campaign status.json: running, stage capture" in sessions[2]["reasons"]
    if stop_kind == "rejected":
        assert sessions[2]["archived"] == "true" and block["reason_classes_by_status"]["rejected"] == {
            "score coverage below design gate 0.6": 1}


def test_campaign_time_attributes_unclean_end_as_unaccounted():
    events = [{"time": T0, "status": "running", "stage": "capture"},
              {"time": T0 + 50, "status": "stopped", "stage": "unclean-end"},
              {"time": T0 + 80, "status": "running", "stage": "preflight"},
              {"time": T0 + 81, "status": "running", "stage": "session-preflight"}]
    doc, intervals = cr.campaign_time(events)
    assert doc["by_category_s"] == {"preflight": 1.0, "stopped": 30.0, "unaccounted": 50.0}
    assert doc["wall_clock_span_s"] == 81.0 and len(intervals) == 3


def test_changed_campaign_audit_is_not_used(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    pointer = json.loads((directory / "attempts" / f"{rows[0]['session_id']}.audit.json").read_text())
    audit = Path(pointer["path"])
    audit.write_text(audit.read_text().replace('"accepted": true', '"accepted": false', 1))
    out = tmp_path / "report"
    assert run_report(["campaign", directory, "--out", out]) == 0
    row = read_csv(out / "sessions.csv")[0]
    assert row["status"] == "incomplete" and "sha256 differs" in row["reasons"]
    assert row["audit_accepted"] == "" and "sha256 differs" in row["missing"]


def test_planned_row_with_running_status_is_in_progress(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    state = json.loads((directory / "status.json").read_text())
    arc.write_new(directory / "status.json", dict(state, status="running", stage="reboot",
                                                  session=rows[3]["session_id"]), replace=True)
    out = tmp_path / "report"
    assert run_report(["campaign", directory, "--out", out]) == 0
    row = read_csv(out / "sessions.csv")[3]
    assert row["status"] == "in_progress" and "no session directory yet" in row["reasons"]


# ---------------------------------------------------------------- regressions of the verified review findings

def report_of(argv, out):
    assert run_report([*argv, "--out", out]) == 0
    return (by_id(read_csv(out / "sessions.csv")), json.loads((out / "summary.json").read_text()),
            (out / "README.md").read_text())


def test_killed_generator_http_values_cover_one_window(tmp_path):
    """No 'post' marker (SIGUSR2 without effect, SIGKILL 30 s later): every HTTP value uses the runner's window."""
    truth = make_session(tmp_path, "kill9", start=T0, kind="killed_generator", errors=True, rate=6.0)
    d = truth["dir"]
    end = json.loads((d / "end.json").read_text())
    rows, summary, readme = report_of(["sessions", d], tmp_path / "out")
    row = rows["kill9"]
    measure = [r for r in truth["requests"] if r["phase"] == "measure"]
    inside = [r for r in measure if cr.unix_of(r["t_start_utc"]) < end["measure_end_unix"]]
    assert 0 < len(inside) < len(measure)
    assert row["measure_end_utc"] == cr.utc(end["measure_end_unix"]) and row["measure_bounds_source"] == \
        "start: generator 'measure' marker; end: " + cr.RUNNER_END
    assert int(row["http_requests"]) == len(inside)
    assert int(row["http_requests_outside_window"]) == len(measure) - len(inside)
    assert int(row["http_ok"]) == sum(r["outcome"] == "ok" for r in inside)
    window = end["measure_end_unix"] - truth["measure"]
    assert float(row["measure_phase_s"]) == pytest.approx(window, abs=1e-6)
    assert row["measure_phase_s_source"].startswith("window length end - start (wall clock)")
    assert float(row["http_rps"]) == round(len(inside) / round(window, 6), 6)
    durations = [r["duration_ms"] for r in inside]
    ok = [r["duration_ms"] for r in inside if r["outcome"] == "ok"]
    for name, q in (("p50", .5), ("p95", .95), ("p99", .99), ("max", 1.0)):
        assert float(row[f"latency_all_{name}_ms"]) == nearest_rank_brute(durations, q)
        assert float(row[f"latency_ok_{name}_ms"]) == nearest_rank_brute(ok, q)
    routes = [r for r in read_csv(tmp_path / "out" / "routes.csv") if r["session_id"] == "kill9"]
    assert sum(int(r["requests"]) for r in routes) == len(inside)
    # The unlogged last interval holds requests: the interval log does not cover the generator's measure phase.
    assert "intervals:measure_count_mismatch" in row["requests_log_problems"]
    assert "started outside it" in row["notes"]
    # The host monitor uses the same runner window.
    assert row["monitor_window_end_utc"] == row["measure_end_utc"]
    clipped = summary["sessions"]["http_window_excludes_requests"]
    assert clipped["count"] == 1 and clipped["sessions"][0]["requests_outside_window"] == len(measure) - len(inside)
    assert summary["http"]["all_attempted"]["measure_requests"] == len(inside)
    assert "HTTP windows that exclude requests the generator labeled 'measure': 1" in readme


def test_superseded_sessions_have_accepted_companion_totals(tmp_path):
    work = tmp_path / "work"
    a = make_session(work, "keep", start=T0, kind="accepted", scenario="steady")
    b = make_session(work, "old_parser", start=T0 + 1000, kind="accepted", scenario="quiet", windows=7)
    write_json(b["dir"] / "superseded.json", {"values": {"usable_for_current_corpus": False, "reason": "parser bug"}})
    rows, summary, readme = report_of(["sessions", a["dir"], b["dir"]], tmp_path / "out")
    assert rows["old_parser"]["status"] == "accepted" and rows["old_parser"]["superseded"] == "true"
    keep = rows["keep"]
    assert summary["sessions"]["superseded"] == {"count": 1, "sessions": ["old_parser"], "marker_unreadable": [],
                                                 cr.USABLE: 1}
    assert summary["http"]["accepted"]["measure_requests"] == int(keep["http_requests"]) + int(
        rows["old_parser"]["http_requests"])
    assert summary["http"][cr.USABLE]["measure_requests"] == int(keep["http_requests"])
    assert summary["windows"]["accepted"]["scorable_windows"] == 15
    assert summary["windows"][cr.USABLE]["scorable_windows"] == 8
    assert summary["data_volume"][cr.USABLE]["raw_bytes"] == int(keep["raw_bytes"])
    assert summary["snapshots"][cr.USABLE]["present"]["total"] == 12
    assert summary["capture_time"][cr.USABLE]["seconds"] == pytest.approx(float(keep["capture_span_s"]))
    quiet = summary["per_scenario"]["quiet"]
    assert quiet["accepted"]["sessions"] == 1 and quiet[cr.USABLE]["sessions"] == 0
    assert quiet[cr.USABLE]["windows"]["scorable_windows"] == 0
    assert "accepted without a superseded marker" in readme and "Superseded markers: 1 (old_parser)" in readme


def test_unreadable_markers_fail_closed(tmp_path):
    work = tmp_path / "work"
    a = make_session(work, "torn", start=T0, kind="accepted")
    (a["dir"] / "superseded.json").write_text('{"values": {"usable_for_current_corpus": false, "reason": "x"')
    (a["dir"] / "archive_receipt.json").write_text('{"schema": "hyptcn3/collection-archive-receipt/1", ')
    rows, summary, readme = report_of(["sessions", a["dir"]], tmp_path / "out")
    row = rows["torn"]
    assert row["superseded"] == "" and "superseded.json exists but is unreadable" in row["missing"]
    assert row["archived"] == "" and "archive_receipt.json exists but is unreadable" in row["missing"]
    assert "archive_receipt.json unreadable: the archive destination is unknown" in row["missing"]
    assert summary["sessions"]["superseded"]["marker_unreadable"] == ["torn"]
    assert summary["capture_time"][cr.USABLE]["sessions"] == 0  # never counted as 'without a marker'
    assert "Sessions whose superseded.json could not be read: 1:" in readme


def test_evidence_changed_after_the_audit_is_not_accepted(tmp_path):
    work = tmp_path / "work"
    acc = make_session(work, "acc", start=T0, kind="accepted")["dir"]
    rej = make_session(work, "rej", start=T0 + 1000, kind="rejected", windows=4,
                       reasons=("score coverage below design gate 0.6",))["dir"]
    for d in (acc, rej):  # one measure-phase request and one sidecar timestamp changed after the audit
        lines = (d / "traffic_requests.jsonl").read_text().splitlines(True)
        for i, line in enumerate(lines):
            record = json.loads(line)
            if record.get("type") == "request" and record.get("phase") == "measure":
                lines[i] = json.dumps(dict(record, duration_ms=99999.0)) + "\n"
                break
        (d / "traffic_requests.jsonl").write_text("".join(lines))
        side = max(p for p in (d / "raw").glob("*.json") if json.loads(p.read_text()).get("schema") == "vmicollect/1")
        write_json(side, dict(json.loads(side.read_text()), timestamp_unix=T0 + 99999))
    rows, summary, readme = report_of(["sessions", acc, rej], tmp_path / "out")
    row = rows["acc"]
    assert row["status"] == "incomplete" and row["audit_accepted"] == "true"
    assert row["reasons"].startswith("accepting audit verdict not applied: evidence:")
    assert row["evidence_consistent"] == "false" and row["sidecars_differing_from_audit"] == "1"
    assert row["evidence_hash_mismatches"] == "1" and row["traffic_matches_audit"] == "false"
    assert "sidecars differ from the audited ones" in row["evidence_problems"]
    assert rows["rej"]["status"] == "rejected" and "evidence:" in rows["rej"]["reasons"]  # never lifted
    assert summary["sessions"]["accepted"] == 0 and summary["capture_time"]["accepted"]["sessions"] == 0
    listed_sessions = {item["session"] for item in summary["sessions"]["evidence_inconsistent"]["sessions"]}
    assert summary["sessions"]["evidence_inconsistent"]["count"] == 2 and listed_sessions == {"acc", "rej"}
    assert "Sessions whose files differ from logs_manifest.json, end.json or the audit: 2:" in readme
    # Unchanged evidence: every check is listed and passes.
    clean = make_session(tmp_path / "other", "clean", start=T0, kind="accepted")["dir"]
    rows, _, _ = report_of(["sessions", clean], tmp_path / "out2")
    assert rows["clean"]["status"] == "accepted" and rows["clean"]["evidence_consistent"] == "true"
    assert "12 sidecars against the audit" in rows["clean"]["evidence_checks"]
    assert "request log summary against the audit" in rows["clean"]["evidence_checks"]


def test_audit_must_belong_to_this_session_in_both_modes(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    first = rows[0]["session_id"]
    session = directory.parent.parent / "collections" / first
    meta = json.loads((session / "session.json").read_text())
    other = "quiet" if meta["scenario"] != "quiet" else "steady"
    write_json(session / "session.json", dict(meta, scenario=other))  # edited after its audit
    out = tmp_path / "campaign-report"
    report, summary, _ = report_of(["campaign", directory], out)
    row = report[first]
    assert row["status"] == "incomplete" and row["audit_accepted"] == ""
    assert "the audit selected by the campaign pointer gives no verdict: audited another session.json" in row["reasons"]
    assert f"session.json scenario '{other}' differs from the frozen assignment" in row["provenance_problems"]
    sessions_mode, _, _ = report_of(["sessions", session], tmp_path / "sessions-report")
    assert sessions_mode[first]["status"] == "incomplete"
    assert "audited another session.json" in sessions_mode[first]["audit_candidates"]
    # Per-scenario 'planned' follows the frozen plan, not session.json.
    for scenario in ("quiet", "steady"):
        assert summary["per_scenario"][scenario]["planned"] == sum(r["scenario"] == scenario for r in rows)
    # A copy of an audited session elsewhere: the audit names another directory, so it gives no verdict.
    copy = tmp_path / "elsewhere" / rows[1]["session_id"]
    shutil.copytree(session.parent / rows[1]["session_id"], copy, symlinks=True)
    copied, _, _ = report_of(["sessions", copy], tmp_path / "copy-report")
    assert copied[copy.name]["status"] == "incomplete"
    assert "audited another session directory" in copied[copy.name]["audit_candidates"]


def test_campaign_assignment_mismatch_is_not_accepted(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    first = rows[0]["session_id"]
    manifest = json.loads((directory / "campaign.json").read_text())
    manifest["commit"] = "another-commit"  # the session was not captured at the campaign's frozen commit
    arc.write_new(directory / "campaign.json", manifest, replace=True)
    report, summary, readme = report_of(["campaign", directory], tmp_path / "out")
    row = report[first]
    assert row["status"] == "incomplete" and row["audit_accepted"] == "true"
    assert "campaign provenance: session.json commit differs from the campaign commit" in row["reasons"]
    assert "audit commit differs from the campaign commit" in row["provenance_problems"]
    assert summary["sessions"]["accepted"] == 0 and summary["sessions"]["provenance_problems"]["count"] == 3
    assert summary["sessions"]["campaign_checkpoint_but_not_accepted"] == [rows[0]["session_id"],
                                                                           rows[1]["session_id"]]
    assert "Sessions with campaign provenance problems: 3:" in readme


def test_interrupted_reclamation_still_reads_the_snapshots(tmp_path):
    work, store = tmp_path / "work", tmp_path / "archive"
    d = make_session(work, "midway", start=T0, kind="accepted")["dir"]
    doc = arc.publish_archive(d, store / "midway", lambda: None, 0, compress="zstd" if HAVE_ZSTD else None)
    arc.write_new(d / arc.RECEIPT, {"schema": "hyptcn3/collection-archive-receipt/1", "source": str(d),
                                    "destination": str(store / "midway"),
                                    "manifest_sha256": arc.digest(store / "midway" / arc.MANIFEST)})
    (d / "raw").rename(d / arc.PENDING)  # reclaim_raw stopped between rename and link
    assert cr.PENDING_RAW == arc.PENDING
    rows, summary, _ = report_of(["sessions", d], tmp_path / "out")
    row = rows["midway"]
    assert row["status"] == "accepted" and row["snapshots_present"] == row["images_present"] == "12"
    assert row["raw_bytes"] == row["audit_raw_bytes"] == row["archive_raw_image_bytes"]
    assert float(row["capture_span_s"]) == 55.0 and arc.PENDING in row["notes"]
    assert summary["capture_time"]["accepted"]["seconds"] == 55.0
    # Finished reclamation, then raw/ lost: the receipt still names the archive, whose sidecars are read.
    arc.reclaim_raw(d, store / "midway", doc, lambda: None)
    (d / "raw").unlink()
    rows, _, _ = report_of(["sessions", d], tmp_path / "out2")
    row = rows["midway"]
    assert row["status"] == "accepted" and row["snapshots_present"] == "12"
    assert row["raw_dir"] == str(store / "midway" / "raw") and "archive_receipt.json" in row["notes"]
    assert row["raw_bytes"] == row["audit_raw_bytes"]


def test_absent_raw_after_capture_is_missing_not_zero(tmp_path):
    d = make_session(tmp_path / "work", "lost", start=T0, kind="unaudited")["dir"]
    shutil.rmtree(d / "raw")
    rows, summary, _ = report_of(["sessions", d], tmp_path / "out")
    row = rows["lost"]
    for field in ("snapshots_present", "images_present", "raw_bytes", "capture_span_s", "snapshots_missing",
                  "capture_slot_s"):
        assert row[field] == "" and field in listed(row["missing"]), field
    assert "raw/ is absent although end.json does not show that the run ended before the collector started" \
        in row["missing"]
    volume = summary["data_volume"]["all_attempted"]
    assert (volume["sessions_without_value"], volume["sessions_without_collector_output"]) == (1, 0)


def test_sidecar_fields_that_are_absent_are_not_zero(tmp_path):
    d = make_session(tmp_path / "work", "older", start=T0, kind="unaudited")["dir"]
    for side in sorted((d / "raw").glob("*.json")):
        doc = json.loads(side.read_text())
        if doc.get("schema") != "vmicollect/1":
            continue
        if doc["output"]["full"]:  # the full snapshots' sidecars are missing (hash not finished)
            side.unlink()
            continue
        doc["output"].pop("hash_deferred")
        if doc["seq"] % 2:
            doc["stats"].pop("read_errors")
        write_json(side, doc)
    rows, summary, _ = report_of(["sessions", d], tmp_path / "out")
    row = rows["older"]
    assert row["hash_deferred_snapshots"] == "" and "10 of 10 sidecars lack output.hash_deferred" in row["missing"]
    assert row["read_errors"] == "" and "6 of 10 sidecars lack stats.read_errors" in row["missing"]  # odd seq 1..11
    assert row["filled_zero"] == "0"
    assert row["full_cycle_ms"] == "" and "no full-snapshot sidecar present" in row["missing"]
    assert "12 images but 10 snapshot sidecars" in row["notes"]
    block = summary["snapshots"]["all_attempted"]["read_errors"]
    assert block == {"total": 0, "sessions_counted": 0, "sessions_without_value": 1}


def test_pooled_rate_uses_only_sessions_with_a_duration(tmp_path):
    work = tmp_path / "work"
    acc = make_session(work, "acc", start=T0, kind="accepted")["dir"]
    crash = make_session(work, "crash", start=T0 + 1000, kind="crash", present=3)["dir"]
    (crash / "traffic_intervals.jsonl").unlink()  # no interval log and no end record: no window end
    rows, summary, _ = report_of(["sessions", acc, crash], tmp_path / "out")
    assert rows["crash"]["http_requests"] and rows["crash"]["measure_phase_s"] == "" and rows["crash"]["http_rps"] == ""
    http = summary["http"]["all_attempted"]
    assert http["measure_requests"] == int(rows["acc"]["http_requests"]) + int(rows["crash"]["http_requests"])
    assert http["pooled_requests_per_s"]["numerator"] == int(rows["acc"]["http_requests"])
    assert http["pooled_requests_per_s"]["denominator"] == float(rows["acc"]["measure_phase_s"])
    assert http["pooled_requests_per_s"]["sessions_counted"] == 1
    assert (http["sessions_with_measure_requests"], http["sessions_with_request_log"]) == (2, 2)


def test_denominator_labels_count_what_they_name(sessions):
    summary = json.loads((sessions["out"] / "summary.json").read_text())
    http = summary["http"]["all_attempted"]
    # Request logs: every session that started the generator (also the warmup-only one); measure requests: 5.
    assert (http["sessions_with_request_log"], http["sessions_with_measure_requests"]) == (6, 5)
    volume = summary["data_volume"]["all_attempted"]
    assert (volume["sessions_with_raw_images_measured"], volume["sessions_without_collector_output"],
            volume["sessions_without_value"]) == (6, 2, 0)
    readme = (sessions["out"] / "README.md").read_text()
    assert "over 5 sessions with measure-phase requests (6 with a request log)" in readme
    assert "2 more with 0 bytes because the run ended before the collector started" in readme


def test_duplicate_session_ids_are_a_data_error(tmp_path, capsys):
    d = make_session(tmp_path / "a", "same", start=T0, kind="accepted")["dir"]
    copy = tmp_path / "b" / "same"
    shutil.copytree(d, copy)
    assert run_report(["sessions", d, copy, "--out", tmp_path / "out"]) == 2
    assert not (tmp_path / "out").exists() and "hold the same session ID" in capsys.readouterr().err
    renamed = tmp_path / "c" / "renamed"
    shutil.copytree(d, renamed)  # another directory name, the same session.json session_id
    assert run_report(["sessions", d, renamed, "--out", tmp_path / "out"]) == 2
    assert not (tmp_path / "out").exists()


def test_campaign_inputs_that_cannot_be_found(tmp_path, monkeypatch, capsys):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    assert run_report(["campaign", directory, "--collections-dir", tmp_path / "data" / "colections",
                       "--out", tmp_path / "out"]) == 2
    assert not (tmp_path / "out").exists() and "does not exist" in capsys.readouterr().err
    moved = directory.parent.parent / "collections" / rows[0]["session_id"]
    moved.rename(tmp_path / "moved-away")
    _, summary, readme = report_of(["campaign", directory], tmp_path / "out2")
    problems = summary["campaign"]["problems"]
    assert f"attempts/{rows[0]['session_id']}.done.json exists, but the session directory {moved} is absent" \
        in problems
    assert "status.json accepted_archived = 2, but 1 session directories have a done checkpoint" in problems
    assert "Campaign consistency problems:" in readme
    manifest = json.loads((directory / "campaign.json").read_text())
    manifest["sessions"][1]["session_id"] = ["not", "a", "string"]
    arc.write_new(directory / "campaign.json", manifest, replace=True)
    assert run_report(["campaign", directory, "--out", tmp_path / "out3"]) == 2
    assert "no usable session_id" in capsys.readouterr().err


def test_malformed_values_do_not_abort_the_report(tmp_path, monkeypatch):
    work = tmp_path / "work"
    good = make_session(work, "good", start=T0, kind="accepted")["dir"]
    huge = make_session(work, "huge", start=T0 + 1000, kind="unaudited")["dir"]
    write_json(huge / "session.json", dict(json.loads((huge / "session.json").read_text()), created_unix=1e20))
    past = make_session(work, "past", start=T0 + 2000, kind="unaudited")["dir"]
    write_json(past / "end.json", dict(json.loads((past / "end.json").read_text()), written_unix=-1e15))
    rows, _, _ = report_of(["sessions", good, huge, past], tmp_path / "out")
    assert rows["huge"]["session_created_utc"] == "" and "created_unix is not a representable time" in \
        rows["huge"]["missing"]
    assert rows["past"]["session_end_written_utc"] == "" and "written_unix is not a representable time" in \
        rows["past"]["missing"]
    assert rows["good"]["status"] == "accepted"

    def broken(*_args):
        raise RuntimeError("unexpected layout")
    monkeypatch.setattr(cr, "clock_step", broken)
    rows, summary, _ = report_of(["sessions", good, huge], tmp_path / "out2")
    for row in rows.values():
        assert row["status"] == "incomplete"
        assert row["reasons"] == "the report could not read this session (RuntimeError: unexpected layout)"
    assert len(summary["inputs_unreadable"]) == 2


def test_multiline_error_stays_one_table_row(tmp_path):
    d = make_session(tmp_path / "work", "smokefail", start=T0, kind="preflight_failed")["dir"]
    end = json.loads((d / "end.json").read_text())
    end["error"] = ("ValueError: preflight functional check failed: FAIL: 2 of 13 HTTP checks\n"
                    "  GET /api/catalog -> 503\n  POST /api/orders -> timeout\n")
    write_json(d / "end.json", end)
    rows, summary, readme = report_of(["sessions", d], tmp_path / "out")
    assert "\n" in rows["smokefail"]["reasons"]  # the CSV keeps the full text (quoted)
    table = [line for line in readme.splitlines() if line.startswith("| 1 |")]
    assert len(table) == 1 and table[0].endswith("POST /api/orders -> timeout |")
    assert all("\n" not in key for key in summary["sessions"]["reason_classes_by_status"]["incomplete"])


def test_timeline_end_annotations(sessions, tmp_path):
    d = make_session(tmp_path, "s1done", start=T0, kind="schema1", role="train", present=12)["dir"]
    (d / "end.json").unlink()
    write_json(d / "end.json", {"completed": True, "capture_started_unix": T0 + 129, "capture_finished_unix": T0 + 200,
                                "collector_rc": 0, "guest_after": GUEST})
    rows, _, _ = report_of(["sessions", d, sessions["work"] / "crash"], tmp_path / "out")
    assert rows["s1done"]["interrupted"] == "false"
    assert rows["s1done"]["notes"] == "interrupted: schema 1 end.json has no flag; false because completed = true"
    root = ET.fromstring((tmp_path / "out" / "plots" / "timeline.svg").read_text())
    texts = [(element.text, element.attrib) for element in root.iter("{http://www.w3.org/2000/svg}text")]
    remarks = [text for text, _ in texts if text and ("end.json" in text or "end record" in text)]
    assert "end.json without written_unix" in " ".join(remarks) and "no end.json" in " ".join(remarks)
    assert not any("no end record" in text for text in remarks)
    width = float(root.attrib["width"])
    for text, attrib in texts:  # remarks stay inside the drawing
        if attrib.get("text-anchor") == "start":
            assert float(attrib["x"]) + cr.text_width(text, float(attrib["font-size"])) <= width + 1, text


def test_output_inside_an_archive_is_refused(tmp_path):
    work, store = tmp_path / "work", tmp_path / "archive"
    d = make_session(work, "arch", start=T0, kind="accepted")["dir"]
    archive(d, store / "arch")
    for out in (d / "raw" / "report", store / "arch" / "report", store / "arch" / "raw" / "deep" / "report"):
        assert run_report(["sessions", d, "--out", out]) == 2
        assert not out.exists()
    arc.verify_archive(store / "arch", d)  # the archive's file set is unchanged


def test_host_plot_names_each_session_window(sessions):
    text = (sessions["out"] / "plots" / "host.svg").read_text()
    assert "monitor_window_source" in text and "over the audit's measure window (end.json)" not in text


def test_in_progress_planned_row_counts_as_not_started_everywhere(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    state = json.loads((directory / "status.json").read_text())
    arc.write_new(directory / "status.json", dict(state, status="running", stage="reboot",
                                                  session=rows[3]["session_id"]), replace=True)
    _, summary, readme = report_of(["campaign", directory], tmp_path / "out")
    block = summary["sessions"]
    assert (block["not_started"], block["in_progress_without_directory"], block["in_progress"]) == (3, 1, 1)
    assert block["not_started_sessions"] == [r["session_id"] for r in rows[3:]]
    assert "not started (no session directory): 3, of which 1 named as running by status.json" in readme
    assert "- Planned sessions without a session directory (not started): 3:" in readme


# ---------------------------------------------------------------- campaign runner semantics of 2026-10-21

@pytest.mark.parametrize("first_meta, first_audit, problem", [
    ({"commit_dirty": True}, {"commit_dirty": True}, None),  # a note in the tree is not a different capture
    ({"measurement_dirty": ["scripts/collection.py"]}, None, "measurement_dirty is not []"),
    (None, {"measurement_dirty": ["features/snapshot.py"]}, "audit commit differs"),
    ({"host_context": {"qemu": dict(QEMU, pid=4343)}}, None, "VM process differs"),
])
def test_campaign_provenance_follows_measurement_sources_and_vm_process(tmp_path, monkeypatch, first_meta,
                                                                        first_audit, problem):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected", first_meta=first_meta,
                                          first_audit=first_audit)
    out = tmp_path / "report"
    assert run_report(["campaign", directory, "--out", out]) == 0
    row = read_csv(out / "sessions.csv")[0]
    if problem is None:
        assert row["status"] == "accepted" and row["provenance_problems"] == "none"
    else:
        assert row["status"] == "incomplete" and problem in row["reasons"]


def test_retired_attempts_are_listed_and_never_counted(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    collections = directory.parent.parent / "collections"
    manifest = json.loads((directory / "campaign.json").read_text())
    row = rows[3]
    make_session(collections, row["session_id"], start=T0 + 50_000, kind="preflight_failed", role=row["role"],
                 group=row["group"], scenario=row["scenario"], seed=row["seed"], campaign_id=manifest["id"])
    camp.retire_attempt(directory, manifest, row, collections / row["session_id"])  # the runner's own code
    out = tmp_path / "report"
    assert run_report(["campaign", directory, "--out", out]) == 0
    summary = json.loads((out / "summary.json").read_text())
    retired = summary["sessions"]["retired_attempts"]
    assert retired["count"] == 1 and summary["campaign"]["problems"] == []
    entry = retired["attempts"][0]
    assert (entry["session_id"], entry["attempt"], entry["measurement_started"], entry["raw_present"]) == (
        row["session_id"], 1, False, False)
    assert "request ID correlation failed" in entry["reason"] and entry["problems"] == []
    row3 = read_csv(out / "sessions.csv")[3]  # status.json: running, stage retry; no directory until the retry
    assert row3["status"] == "in_progress" and "no session directory yet" in row3["reasons"]
    assert summary["sessions"]["attempted"] == 3
    readme = (out / "README.md").read_text()
    assert "Retired attempts (ended before the measured phase; not sessions, in no total): 1:" in readme
    # Sessions mode over the same directories: the renamed attempt is not a duplicate of its session ID.
    out2 = tmp_path / "report-sessions"
    dirs = sorted(p for p in collections.iterdir() if p.is_dir())
    assert run_report(["sessions", *dirs, "--out", out2]) == 0
    summary2 = json.loads((out2 / "summary.json").read_text())
    assert summary2["sessions"]["retired_attempts"]["count"] == 1 and summary2["sessions"]["attempted"] == 3


def test_closed_campaign_and_stop_requests_are_reported(tmp_path, monkeypatch):
    directory, rows, _, _ = make_campaign(tmp_path, monkeypatch, stop_kind="rejected")
    collections = directory.parent.parent / "collections"
    arc.write_new(directory / "stop-request.json", {"schema": "hyptcn3/campaign-stop-request/1",
                                                    "date": iso(T0 + 60_000), "uid": 1000})
    assert camp.take_stop_request(directory)  # honored by a runner
    arc.write_new(directory / "stop-request.json", {"schema": "hyptcn3/campaign-stop-request/1",
                                                    "date": iso(T0 + 61_000), "uid": 1000})
    os.replace(directory / "stop-request.json", directory / "events" / f"{camp.stamp()}_stop-request-stale.json")
    monkeypatch.setattr(camp, "COLLECTIONS", collections)
    monkeypatch.setattr(camp, "guard_mount", lambda *a: None)
    camp.close(directory, "row 3 rejected: lab defect; superseded by a new campaign")
    out = tmp_path / "report"
    assert run_report(["campaign", directory, "--out", out]) == 0
    summary = json.loads((out / "summary.json").read_text())
    campaign = summary["campaign"]
    assert campaign["closed"]["reason"] == "row 3 rejected: lab defect; superseded by a new campaign"
    assert sorted(r["honored"] for r in campaign["stop_requests"]) == [False, True]
    assert not any("stop-request" in item["input"] for item in summary["inputs_unreadable"])
    assert campaign["status"]["status"] == "closed"  # status.json; events may share the fake clock's timestamp
    assert "closed" in {e["status"] for e in read_csv(out / "events.csv")}
    readme = (out / "README.md").read_text()
    assert "Closed by the operator on" in readme and "Operator stop requests: 1 honored, 1 set aside" in readme
