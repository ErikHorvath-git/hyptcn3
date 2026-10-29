"""Campaign benign-v6-20261026 (collector 1.1): sessions, groups, writer thread, audit stages, operator steps and
archive checks.

usage: record.py CAMPAIGN_DIR VERIFY_LOG OUT_JSON
VERIFY_LOG is the saved output of `campaign.py verify-archives` with its wall time; the operator's diagnostic samplers
(sampler.sh, sampler2.sh and their xz-compressed logs) lie in the same directory.
Audit stage times come from the campaign status events; feature_extraction_s is the audit's own per-snapshot timer
(values.feature_extraction_s of each campaign audit), split into the two chains of a session (full snapshots 0 and
full_every). Rows on the prev/tail process walks and rows with an unconfirmed cross-view difference are described from
the audit's NPZ (quality_json, poznamky, the proc_total column).
Request latencies are read from each session's traffic_requests.jsonl (measure phase). Collector cycles
come from raw/collect.log; every per-cycle ' INFO  #' line must parse. Collector 1.1 writes files on its vmic-writer
thread after the cycle, so the logged 'citanie' value is capture_ms (read + compare + features + copy into the
queue), not a pure read time; backend_read_ms (read_pa only), queue_wait_ms, rusage and data_closed_ms come from the
snapshot sidecars (raw/*.json, read through the raw/ link into the archive). data_closed_ms runs from the cycle start
to complete data, before the sidecar and both renames, so it is a lower bound of the publication time.
QEMU swap during a session comes from host_monitor.jsonl (1 s samples). Snapshot sizes (bytes, mib) are the exact file
sizes from the session's archive-manifest.json; logged_size is the collector's own rounded figure.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import lzma
from pathlib import Path
import platform
import re
import subprocess
import sys

import numpy as np

ROOT = Path("/home/eh/projects/hyptcn3")
campaign, verify_log, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
DIAG = verify_log.parent
LINE = re.compile(r"^(\S+) INFO  #(\d+) (PLNA|delta)\s+([\d.]+) (MiB|GiB|KiB|B)/[\d.]+ GiB\s+stranky (\d+)/(\d+).*"
                  r"citanie ([\d.]+) ms\s+spolu ([\d.]+) ms$")
SKIP = re.compile(r"^(\S+) WARN  planovac: cyklus (\d+) trval ([\d.]+) s \(perioda ([\d.]+) s\) - zahadzujem (\d+) slotov")
WRITER = re.compile(r"INFO  zapisovac: (\d+) zverejnenych.*")
OPS = re.compile(r"INFO  zapisovac: najdlhsie operacie: (.*)")
LOCK = re.compile(r"INFO  pamat procesu uzamknuta za ([\d.]+) s: VmRSS (\d+) MiB")
SNAPSHOT = re.compile(r"^raw/[^/]+_(\d{6})_[^/]+\.vmicd$")
COMMIT_NOTE = ("HEAD when this record was generated. The record script "
               "data/results/collection_campaign_benign_v6_20261026/record.py is not part of this commit; it is "
               "committed together with this file. This HEAD is also the campaign commit 01c2088 "
               "(values.campaign_commit, collector 1.1): the campaign was captured with its code, and no commit was "
               "made between the campaign's init and this record.")
SLOW_AUDIT_S = 1800
# Every recursive walk of the repository (which holds the live working directories data/collections,
# data/diagnostics and data/campaigns) or of the archive during the campaign, found in the session logs of the
# operator and of the workflow agents. Start, end (when the command returned) and commands are operator statements;
# incident_effect() computes the collector, request and disk timing around each walk that overlapped a measurement.
REPO = "the repository tree on the system HDD (with .venv) and the directory trees under data/"
INCIDENTS = [
    {"utc": "2026-10-26T23:04:57.618Z", "end_utc": "2026-10-26T23:04:58.024Z",
     "session": "benign-v6-20261026_05_train_read_heavy", "actor": "operator",
     "command": "grep -rn -i queue --include=*.c --include=*.h . (repository root)",
     "touched": REPO + "; it opened every *.c and *.h file, none of them under data/"},
    {"utc": "2026-10-27T12:24:34.423Z", "end_utc": "2026-10-27T12:24:34.521Z",
     "session": "benign-v6-20261026_14_train_bursty", "actor": "agent of workflow wf_45270756-001",
     "command": "grep -rn --include=*.py . (repository root)",
     "touched": REPO + "; it opened every *.py file, three small ones under data/diagnostics"},
    {"utc": "2026-10-27T12:26:33.982Z", "end_utc": "2026-10-27T12:26:34.048Z",
     "session": "benign-v6-20261026_14_train_bursty", "actor": "agent of workflow wf_45270756-001",
     "command": "grep -rn --include=*.py --include=*.sh . (repository root)",
     "touched": REPO + "; it opened every *.py and *.sh file, three small ones under data/diagnostics"},
    {"utc": "2026-10-27T12:41:12.330Z", "end_utc": "2026-10-27T12:41:12.488Z",
     "session": "benign-v6-20261026_14_train_bursty", "actor": "agent of workflow wf_45270756-001",
     "command": "grep -rn -i --include=*.md --include=*.py --include=*.sh --include=*.json --include=*.sql . "
                "(repository root)",
     "touched": REPO + "; it opened every *.md, *.py, *.sh, *.json and *.sql file, including those under "
                       "data/collections (with the raw/ sidecars of the running session 14), data/diagnostics and "
                       "data/campaigns; read-only, symbolic links not followed"},
    {"utc": "2026-10-27T15:21:41.631Z", "end_utc": "2026-10-27T15:21:48.400Z",
     "session": "benign-v6-20261026_16_train_steady", "actor": "operator",
     "command": "read the archive manifests of sessions 1-15, then du -sh --apparent-size /home/eh/hyptcn3-archive",
     "touched": "the archive manifests and the metadata of the archive on the system HDD, which also holds the VM "
                "disk"},
]
WINDOW = (60, 120)
NOTE = (
    "Operator statements from the session log, not machine records: before init the operator power-cycled the VM "
    "(`labctl stop` at 2026-10-26T17:19:55Z, guest shutdown, domain shut off; `labctl start` at 17:20:02Z; service "
    "health ok at 17:20:21Z; the new QEMU process is the one in values.groups). The operator launched the campaign "
    "with --stop-after 1 at 17:21:38Z, checked session 1 (audit result, collector timing and an independent "
    "`collection_archive verify` of its archive from 18:45:53Z to 18:46:54Z, rc 0) and relaunched it without a limit "
    "at 18:47:16Z. There were no operator stop requests, no QEMU or VM restarts (the runner rebooted the guest at "
    "the start of each group) and no fstrim during the campaign; the host timers apt-daily, apt-daily-upgrade, "
    "fstrim and man-db stayed disabled and vm.swappiness stayed 1. After each archived session the operator read "
    "its audit result, collector log, request and monitor logs (read-only), which overlapped the preflight and "
    "warm-up of the next session. values.operator_incidents lists every recursive walk of the repository or of the "
    "archive during the campaign that the session logs show (read-only; three of them by a workflow agent during "
    "the measurement of session 14, against the operator's rule for agents); for walks that overlapped a measurement "
    "the collector, request and disk timing around them is computed from the session's own records. From "
    "2026-10-29T06:05:17Z (during the measurement of session 41) to 18:50:16Z the operator ran a passive /proc "
    "sampler every 30 s, and from 15:52:14Z (during session 47) to 18:50:19Z a /proc/diskstats sampler; both "
    "diagnose the slow audits, ran through the following sessions and are no input of any audit "
    "(values.operator_diagnostics; scripts and logs beside this record). The audit of session 40 ran before the "
    "samplers started. Operator inference: the slow audits of sessions 40 and 46 waited on reads of the raw "
    "snapshots in their second chain. The samplers show the audit process of session 46 often in state D under IO "
    "pressure while the kernel reclaimed page cache, and, during the audit of session 48, whole-device SSD reads "
    "larger than that session's raw size while its audit process stayed busy on the CPU; they record device "
    "counters and process states, not the audit's file reads. Why sessions 40 and 46 and not other sessions of "
    "similar raw size were slow is not determined.")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unix(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def rank(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))] if values else None


def measure_latency(path):
    durations = []
    with open(path) as requests:
        for line in requests:
            rec = json.loads(line)
            if rec.get("type") == "request" and rec["phase"] == "measure":
                durations.append(rec["duration_ms"])
    durations.sort()
    return {"n": len(durations), "max_ms": durations[-1], "p99_ms": rank(durations, .99),
            "over_1s": sum(d > 1000 for d in durations), "over_2s": sum(d > 2000 for d in durations),
            "over_4s": sum(d > 4000 for d in durations)}


def cycles_of(log, sizes):
    rows, last_full = [], None
    for line in log.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        seq = int(m[2])
        if m[3] == "PLNA":
            last_full = seq
        size = sizes.get(seq)
        rows.append({"seq": seq, "kind": m[3], "bytes": size, "mib": None if size is None else round(size / 2**20, 2),
                     "logged_size": f"{m[4]} {m[5]}", "pages_changed": int(m[6]),
                     "pages_total": int(m[7]), "capture_ms": float(m[8]), "total_ms": float(m[9]),
                     "since_full": None if last_full is None else seq - last_full, "end_utc": m[1]})
    if len(rows) != sum(" INFO  #" in line for line in log.splitlines()):
        raise SystemExit("unparsed collector cycle line")
    return rows


def host_monitor(path):
    """QEMU swap, host swap-outs and SSD saturation over the session, from the 1 s host monitor samples."""
    samples = [r for r in map(json.loads, path.open()) if r.get("type") == "sample"]
    swap = [max((q.get("swap_kb") or 0 for q in r["procs"].get("qemu", [])), default=0) for r in samples]
    return {"qemu_swap_kb_max": max(swap), "qemu_swap_samples_over_0": sum(v > 0 for v in swap),
            "pswpout_delta": samples[-1]["vmstat"]["pswpout"] - samples[0]["vmstat"]["pswpout"],
            "sda_util_ge_99_samples": sum(r.get("disks_rate", {}).get("sda", {}).get("util_pct", 0) >= 99
                                          for r in samples),
            "mem_available_mib_min": min(round(r["mem_kb"]["MemAvailable"] / 1024) for r in samples),
            "samples": len(samples)}


def extraction(times, full_every):
    """The audit's per-snapshot extraction timer per chain: snapshots before and from the second full snapshot."""
    return {name: {"n": len(part), "p50_s": round(rank(part, .5), 3), "max_s": round(max(part), 3),
                   "sum_s": round(sum(part), 1)}
            for name, part in (("chain_0", times[:full_every]), ("chain_1", times[full_every:]))}


def row_details(npz, seqs):
    """Audit rows on the prev/tail walks or with an unconfirmed cross-view difference, from the audit's own NPZ;
    proc_total of the row before, the row and the row after."""
    z = np.load(npz, allow_pickle=False)
    quality, order = json.loads(str(z["quality_json"])), [int(s) for s in z["seq"]]
    if order != list(range(len(order))):
        raise SystemExit(f"{npz}: rows are not in snapshot order")
    column = list(z["mena"]).index("proc_total")
    total = [None if np.isnan(v) else int(v) for v in z["matica"][:, column]]
    return [{"seq": s, "process_walk": quality[s]["process_walk"], "behavior_valid": quality[s]["behavior_valid"],
             "inconclusive": quality[s]["inconclusive"], "unconfirmed_findings": quality[s]["unconfirmed_findings"],
             "proc_total_before_row_after": [total[j] if 0 <= j < len(total) else None for j in (s - 1, s, s + 1)],
             "note": str(z["poznamky"][s])} for s in sorted(seqs)]


def neighbours(row):
    """proc_total of the snapshots before and after a marked row (one of them is missing at a session edge)."""
    return [v for v in row["proc_total_before_row_after"][::2] if v is not None]


def one_above(row):
    """The row counts exactly one process more than each neighbouring snapshot."""
    before, value, after = row["proc_total_before_row_after"]
    return None not in (before, after) and value == before + 1 == after + 1


def equal_to_both(row):
    """The row counts as many processes as each neighbouring snapshot."""
    before, value, after = row["proc_total_before_row_after"]
    return None not in (before, after) and value == before == after


def stats(values):
    values = sorted(values)
    return {"n": len(values), "p50": rank(values, .5), "p99": rank(values, .99), "max": values[-1]}


def incident_effect(incident, measure, cycles, sides, directory):
    """Timing around a walk that overlapped the measurement, from WINDOW[0] s before its start to WINDOW[1] s after
    its end, against the rest of the measurement: collector cycles (by their end), measure-phase requests (by their
    start) and the host disks (1 s monitor samples). Outside the measurement only the distance to it."""
    t0, t1 = unix(incident["utc"]), unix(incident["end_utc"])
    if t1 < measure[0] or t0 > measure[1]:
        return {"during_measurement": False, "measure_utc": [iso(measure[0]), iso(measure[1])],
                "seconds_before_measure_start": round(measure[0] - t1, 1)}
    low, high = t0 - WINDOW[0], t1 + WINDOW[1]
    near = {c["seq"] for c in cycles if low <= unix(c["end_utc"]) <= high}
    deltas = [c for c in cycles if c["kind"] == "delta"]
    with (directory / "traffic_requests.jsonl").open() as log:
        requests = [(unix(r["t_start_utc"]), r["duration_ms"]) for r in map(json.loads, log)
                    if r.get("type") == "request" and r["phase"] == "measure"]
    with (directory / "host_monitor.jsonl").open() as log:
        samples = [(unix(r["t_utc"]), r["disks_rate"]) for r in map(json.loads, log)
                   if r.get("type") == "sample" and measure[0] <= unix(r["t_utc"]) <= measure[1]]

    def util(rows, disk):
        values = [d[disk]["util_pct"] for _, d in rows if disk in d]
        return {"mean": round(sum(values) / len(values), 1), "max": max(values)}
    inside = [s for s in samples if low <= s[0] <= high]
    rest = [s for s in samples if not low <= s[0] <= high]
    return {"during_measurement": True, "window_s": list(WINDOW),
            "delta_ms_near": stats([c["total_ms"] for c in deltas if c["seq"] in near]),
            "delta_ms_rest": stats([c["total_ms"] for c in deltas if c["seq"] not in near]),
            "full_snapshots_near": [c["seq"] for c in cycles if c["kind"] == "PLNA" and c["seq"] in near],
            "data_closed_ms_max_near": max(d["output"]["data_closed_ms"] for d in sides if d["seq"] in near),
            "queue_wait_ms_max_near": max(d["capture"].get("queue_wait_ms", 0) for d in sides if d["seq"] in near),
            "scheduler_skips_near": sum(d["sched"]["skipped_before"] for d in sides if d["seq"] in near),
            "requests_ms_near": stats([d for t, d in requests if low <= t <= high]),
            "requests_ms_rest": stats([d for t, d in requests if not low <= t <= high]),
            "disk_util_pct_near": {disk: util(inside, disk) for disk in ("sda", "sdb")},
            "disk_util_pct_rest": {disk: util(rest, disk) for disk in ("sda", "sdb")}}


def proc_samples(path):
    """sampler.sh lines: time, the system counters and the [pid subcommand state,majflt,ticks] process blocks."""
    rows = []
    with lzma.open(path, "rt") as log:
        for line in log:
            if " stage=" not in line:
                continue
            ts, rest = line.split(" ", 1)
            values = dict(re.findall(r"(\w+):?=([^\s\[]+)", rest.split("[", 1)[0]))
            procs = re.findall(r"\[(\d+) (\w+) st/majflt/ticks=(\w),(\d+),(\d+) ", rest)
            rows.append((unix(ts), values, procs))
    return rows


def disk_samples(path):
    """sampler2.sh lines: time and the /proc/diskstats counters of sda and sdb."""
    rows = []
    with lzma.open(path, "rt") as log:
        for line in log:
            if " stage=" not in line:
                continue
            ts, *tokens = line.split()
            disks, disk = {}, None
            for token in tokens:
                if token in ("sda", "sdb"):
                    disk = disks.setdefault(token, {})
                elif disk is not None and "=" in token:
                    key, value = token.split("=", 1)
                    disk[key] = int(value)
            rows.append((unix(ts), disks))
    return rows


def bracket(rows, start, end):
    """Samples inside [start, end] and the nearest sample on each side of it (at most 60 s away, else None)."""
    inside = [r for r in rows if start <= r[0] <= end]
    before = [r for r in rows if start - 60 <= r[0] < start]
    after = [r for r in rows if end < r[0] <= end + 60]
    return inside, before[-1] if before else None, after[0] if after else None


def proc_window(rows, start, end):
    """Passive /proc samples (every 30 s) for one stage. Shares, rates and counters run from the first to the last
    sample inside the stage, so a counter is a lower bound of the stage value; pswpout_pages_outer and
    pgsteal_kswapd_gb_outer run between the samples just outside it, upper bounds. qemu_swap_mib_before is the last
    sample before the stage."""
    inside, prior, after = bracket(rows, start, end)
    if len(inside) < 2:
        return None
    (t0, first, _), (t1, last, _) = inside[0], inside[-1]
    span = t1 - t0

    def delta(key, a=first, b=last):
        return float(b[key].split("/")[-1]) - float(a[key].split("/")[-1])
    audit = [(t, p) for t, _, procs in inside for p in procs if p[1] == "audit"]
    swap = [int(v["qemu_VmSwap"]) for _, v, _ in inside if "qemu_VmSwap" in v]
    doc = {"samples": len(inside), "first_sample_offset_s": round(t0 - start, 1),
           "last_sample_offset_s": round(end - t1, 1), "span_s": round(span, 1),
           "io_some_share": round(delta("io_some") / span, 3),
           "memory_some_share": round(delta("memory_some") / span, 3),
           "pgsteal_kswapd_mb_s": round(delta("pgsteal_kswapd") * 4096 / span / 1e6, 1),
           "pgsteal_kswapd_gb": round(delta("pgsteal_kswapd") * 4096 / 1e9, 1),
           "pgsteal_kswapd_gb_outer": round(delta("pgsteal_kswapd", prior[1], after[1]) * 4096 / 1e9, 1)
           if prior and after else None,
           "pswpin_pages": int(delta("pswpin")), "pswpout_pages": int(delta("pswpout")),
           "pswpout_pages_outer": int(delta("pswpout", prior[1], after[1])) if prior and after else None,
           "mem_available_mib_min": min(int(v["MemAvailable"]) for _, v, _ in inside),
           "cached_mib_min": min(int(v["Cached"]) for _, v, _ in inside),
           "cached_mib_max": max(int(v["Cached"]) for _, v, _ in inside),
           "qemu_swap_mib_before": int(prior[1]["qemu_VmSwap"]) if prior and "qemu_VmSwap" in prior[1] else None,
           "qemu_swap_mib_before_offset_s": round(start - prior[0], 1) if prior else None,
           "qemu_swap_mib_first": swap[0] if swap else None, "qemu_swap_mib_last": swap[-1] if swap else None,
           "qemu_swap_mib_max": max(swap) if swap else None}
    if len(audit) >= 2:
        (a0, p0), (a1, p1) = audit[0], audit[-1]
        doc["audit_states"] = dict(Counter(p[2] for _, p in audit))
        # CPU seconds per wall second of the audit process (utime + stime in 1/100 s).
        doc["audit_cpu_share"] = round((int(p1[4]) - int(p0[4])) / 100 / (a1 - a0), 3) if p0[0] == p1[0] else None
    return doc


def disk_window(rows, start, end):
    """/proc/diskstats (whole devices, every process) for one stage: MB read and written from the first to the last
    sample inside it (a lower bound) and between the samples just outside it (*_outer, an upper bound), the share of
    time busy, and the reads from 120 s after the stage start on."""
    inside, prior, after = bracket(rows, start, end)
    if len(inside) < 2:
        return None
    (t0, a), (t1, b) = inside[0], inside[-1]
    late = next((d for t, d in inside if t >= start + 120), None)

    def mb(x, y, disk, key):
        return round((y[disk][key] - x[disk][key]) * 512 / 1e6, 1)
    return {"samples": len(inside), "first_sample_offset_s": round(t0 - start, 1),
            "last_sample_offset_s": round(end - t1, 1)} | {
        disk: {"read_mb": mb(a, b, disk, "rs"),
               "read_mb_outer": mb(prior[1], after[1], disk, "rs") if prior and after else None,
               "read_mb_from_120_s": mb(late, b, disk, "rs") if late else None,
               "written_mb": mb(a, b, disk, "ws"),
               "written_mb_outer": mb(prior[1], after[1], disk, "ws") if prior and after else None,
               "busy_share": round((b[disk]["ticks"] - a[disk]["ticks"]) / 1000 / (t1 - t0), 3)}
        for disk in ("sda", "sdb")}


def stage_diagnostics(session, stage, span, proc_rows, disk_rows):
    """One stage seen by the samplers. An audit is also split where its second chain starts: the audit's own
    extraction timer puts that point chain_1.sum_s before the stage end (an estimate; the work after the extraction
    is short and is counted in the second part)."""
    start, end = unix(span[0]), unix(span[1])
    doc = {"session": session["session"], "stage": stage, "utc": span,
           "proc": proc_window(proc_rows, start, end), "disks": disk_window(disk_rows, start, end)}
    if stage == "audit":
        split = end - session["feature_extraction"]["chain_1"]["sum_s"]
        doc |= {"chain_1_start_estimate_utc": iso(split),
                "proc_before_chain_1": proc_window(proc_rows, start, split),
                "proc_chain_1": proc_window(proc_rows, split, end),
                "disks_before_chain_1": disk_window(disk_rows, start, split),
                "disks_chain_1": disk_window(disk_rows, split, end)}
        chain = doc["proc_chain_1"]
        if chain:
            # Reclaimed memory per second-chain snapshot, lower and upper bound (GB).
            n = session["feature_extraction"]["chain_1"]["n"]
            doc["pgsteal_kswapd_gb_per_chain_1_snapshot"] = round(chain["pgsteal_kswapd_gb"] / n, 2)
            outer = chain["pgsteal_kswapd_gb_outer"]
            doc["pgsteal_kswapd_gb_per_chain_1_snapshot_outer"] = round(outer / n, 2) if outer is not None else None
    return doc


manifest = json.loads((campaign / "campaign.json").read_text())
full_every = json.loads((campaign / "protocol.json").read_text())["full_every"]
# Stop requests moved into events/ have no updated_at; only status events time the stages.
records = [(p.name, json.loads(p.read_text())) for p in sorted((campaign / "events").glob("*.json"))]
events = sorted((e for _, e in records if e.get("schema") == "hyptcn3/campaign-event/1"),
                key=lambda e: e["updated_at"])
stops = [{"event_file": name, "date": e["date"], "uid": e["uid"]}
         for name, e in records if e.get("schema") == "hyptcn3/campaign-stop-request/1"]
stages, windows = {}, {}
for a, b in zip(events, events[1:]):
    if a.get("session") and a["status"] == "running":
        stage = stages.setdefault(a["session"], {})
        stage[a["stage"]] = round(stage.get(a["stage"], 0) + unix(b["updated_at"]) - unix(a["updated_at"]), 1)
        windows.setdefault(a["session"], {}).setdefault(a["stage"], []).append([a["updated_at"], b["updated_at"]])
stopped = [{"updated_at": e["updated_at"], "stage": e["stage"], "position": e.get("position"),
            "session": e.get("session"), "message": e.get("message")}
           for e in events if e["status"] == "stopped"]
groups = {}
for path in sorted((campaign / "groups").glob("*.json")):
    if path.name.endswith(".reboot-intent.json"):
        continue
    g = json.loads(path.read_text())
    groups[g["group"]] = {"qemu": g["qemu"], "previous_boot": g["previous_boot"],
                          "boot_id": g["identity"]["boot_id"], "date": g["date"]}
sessions, effects = [], {}
for row in manifest["sessions"]:
    sid = row["session_id"]
    directory = ROOT / "data/collections" / sid
    attempt = campaign / "attempts" / (sid + ".audit.json")
    if not attempt.exists():
        continue
    audit_path = Path(json.loads(attempt.read_text())["path"])
    report = json.loads(audit_path.read_text())["values"]
    meta = json.loads((directory / "session.json").read_text())
    end_doc = json.loads((directory / "end.json").read_text())
    measure = (end_doc["measure_start_unix"], end_doc["measure_end_unix"])
    log = (directory / "raw/collect.log").read_text()
    archive = Path(manifest["archive_dir"]) / "collections" / sid / "archive-manifest.json"
    stored = json.loads(archive.read_text())
    sizes = {int(m[1]): f["size"] for name, f in stored["files"].items() if (m := SNAPSHOT.match(name))}
    cycles = cycles_of(log, sizes)
    if any(c["bytes"] is None for c in cycles if c["kind"] == "PLNA" or c["total_ms"] > 1500):
        raise SystemExit(f"{sid}: snapshot file missing from the archive manifest")
    sides = sorted((d for d in (json.loads(p.read_text()) for p in (directory / "raw").glob("*.json"))
                    if d.get("schema") == "vmicollect/1"), key=lambda d: d["seq"])
    if [d["seq"] for d in sides] != [c["seq"] for c in cycles]:
        raise SystemExit(f"{sid}: sidecars do not match the logged cycles")
    if ([c["seq"] for c in cycles if c["kind"] == "PLNA"] != [0, full_every]
            or len(report["feature_extraction_s"]) != len(cycles)):
        raise SystemExit(f"{sid}: unexpected full snapshots or extraction timer length")
    for incident in INCIDENTS:
        if incident["session"] == sid:
            effects[incident["utc"]] = incident_effect(incident, measure, cycles, sides, directory)
    quality = report["quality"]
    marked = (set(quality.get("process_walk_prev_seq") or []) | set(quality.get("process_walk_tail_seq") or [])
              | set(quality["integrity_unconfirmed_seq"] or []))
    backend = {d["seq"]: d["capture"].get("backend_read_ms") for d in sides}
    closed_ms = [d["output"]["data_closed_ms"] for d in sides]
    deltas = sorted(c["total_ms"] for c in cycles if c["kind"] == "delta")
    end = re.search(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
    writer, ops, lock = WRITER.search(log), OPS.search(log), LOCK.search(log)
    traffic = json.loads((directory / "traffic.json").read_text())
    monitor = report["logs"]["sections"]["monitor"]
    sessions.append({
        "session": sid, "group": row.get("group"), "role": row.get("role"), "scenario": row.get("scenario"),
        "group_attempt": meta["group_attempt"], "guest_boot": meta["guest_before"]["boot_id"],
        "qemu": meta["host_context"]["qemu"], "measurement_dirty": meta.get("measurement_dirty"),
        "measure_utc": [iso(measure[0]), iso(measure[1])],
        "qemu_swap_kb_at_start": meta["host_context"]["memory"].get("qemu_swap_kb"),
        "host_monitor": host_monitor(directory / "host_monitor.jsonl"),
        "accepted": report["accepted"], "reasons": report["reasons"], "snapshots": report["snapshots"],
        "windows": report["windows"], "score_coverage": report["score_coverage"],
        "logs_accepted": report["logs"]["accepted"],
        "integrity_findings": quality["integrity_findings"],
        "invalid_input_seq": quality["invalid_input_seq"],
        "integrity_unconfirmed_seq": quality["integrity_unconfirmed_seq"],
        "process_walk_prev_seq": quality.get("process_walk_prev_seq"),
        "process_walk_tail_seq": quality.get("process_walk_tail_seq"),
        "integrity_inconclusive_rows": quality.get("integrity_inconclusive_rows"),
        "behavior_valid_rows": quality.get("behavior_valid_rows"),
        "marked_rows": row_details(audit_path.with_suffix(".npz"), marked) if marked else [],
        "collector_end": {"snapshots": int(end[1]), "errors": int(end[2]), "missed_slots": int(end[3])},
        "collector_mlock": {"seconds": float(lock[1]), "vmrss_mib": int(lock[2])} if lock else None,
        "log_error_lines": sum(" ERROR " in line for line in log.splitlines()),
        "scheduler_skips": [{"seq": int(m[2]), "cycle_s": float(m[3]), "period_s": float(m[4]),
                             "slots": int(m[5]), "utc": m[1]} for m in map(SKIP.match, log.splitlines()) if m],
        "full_snapshots": [{"seq": c["seq"], "pages": c["pages_changed"], "bytes": c["bytes"], "mib": c["mib"],
                            "logged_size": c["logged_size"], "capture_ms": c["capture_ms"],
                            "backend_read_ms": backend[c["seq"]], "total_ms": c["total_ms"]}
                           for c in cycles if c["kind"] == "PLNA"],
        "cycle_total_ms_max": max(c["total_ms"] for c in cycles),
        "delta_ms": {"n": len(deltas), "p50": rank(deltas, .5), "p99": rank(deltas, .99), "max": deltas[-1]},
        "long_cycles": [{k: c[k] for k in ("seq", "kind", "bytes", "mib", "logged_size", "capture_ms", "total_ms",
                                           "since_full", "end_utc")}
                        for c in cycles if c["total_ms"] > 1500],
        "writer": {"summary": writer[0].split("INFO  ", 1)[1] if writer else None,
                   "longest_operations": ops[1] if ops else None,
                   "queue_jobs_max": max(d["output"].get("queue_jobs", 0) for d in sides),
                   "queue_bytes_max": max(d["output"].get("queue_bytes", 0) for d in sides),
                   "queue_wait_ms_max": max(d["capture"].get("queue_wait_ms", 0) for d in sides),
                   "data_closed_ms": {"p50": rank(closed_ms, .5), "max": max(closed_ms),
                                      "max_seq": max(sides, key=lambda d: d["output"]["data_closed_ms"])["seq"]},
                   "sha_ms_max": max(d["output"].get("sha_ms", 0) for d in sides),
                   "write_ms_max": max(d["capture"].get("write_ms", 0) for d in sides)},
        "rusage_majflt_max": max(d["capture"].get("rusage", {}).get("majflt", 0) for d in sides),
        "skipped_before_max": max(d["sched"]["skipped_before"] for d in sides),
        "monitor_max_gap_s": monitor["max_gap_s"], "monitor_missed_ticks": monitor["missed_ticks"],
        "requests": traffic["requests"], "request_errors": traffic["errors"],
        "measure_latency": measure_latency(directory / "traffic_requests.jsonl"),
        "raw_bytes": report["raw_bytes"], "archive_stored_bytes": stored.get("stored_bytes"),
        "stage_s": stages.get(sid, {}),
        "stage_utc": windows.get(sid, {}),
        "feature_extraction": extraction(report["feature_extraction_s"], full_every),
        "inputs_sha256": {"audit": sha(audit_path), "audit_npz": sha(audit_path.with_suffix(".npz")),
                          "session.json": sha(directory / "session.json"),
                          "end.json": sha(directory / "end.json"),
                          "collect.log": sha(directory / "raw/collect.log"),
                          "traffic.json": sha(directory / "traffic.json"),
                          "traffic_requests.jsonl": sha(directory / "traffic_requests.jsonl"),
                          "host_monitor.jsonl": sha(directory / "host_monitor.jsonl"),
                          "archive-manifest.json": sha(archive)},
    })
if set(effects) != {i["utc"] for i in INCIDENTS}:
    raise SystemExit("an operator incident names no recorded session")
proc_rows, disk_rows = proc_samples(DIAG / "sampler.log.xz"), disk_samples(DIAG / "sampler2.log.xz")
diagnostics = {
    "files": {p.name: {"sha256": sha(p)} | ({"sha256_uncompressed": hashlib.sha256(lzma.decompress(p.read_bytes()))
                                                                     .hexdigest()} if p.suffix == ".xz" else {})
              for p in sorted(DIAG.glob("sampler*"))},
    "proc_sampler_utc": [iso(proc_rows[0][0]), iso(proc_rows[-1][0])],
    "disk_sampler_utc": [iso(disk_rows[0][0]), iso(disk_rows[-1][0])],
    "stages": [stage_diagnostics(s, stage, span, proc_rows, disk_rows)
               for s in sessions for stage in ("audit", "archive") for span in s["stage_utc"].get(stage, [])
               if unix(span[1]) > proc_rows[0][0]],
}
closed = campaign / "closed.json"
corpus = campaign / "corpus.json"
verify = verify_log.read_text()
accepted = [s for s in sessions if s["accepted"]]
all_long = [c for s in sessions for c in s["long_cycles"] if c["kind"] == "delta"]
worst_closed = max(sessions, key=lambda s: s["writer"]["data_closed_ms"]["max"])
marked = [(s["session"], r) for s in sessions for r in s["marked_rows"]]
walk_rows = [r for _, r in marked if r["process_walk"] in ("prev", "tail")]
unconfirmed_rows = [r for _, r in marked if r["unconfirmed_findings"]]
gaps = [b - a for s in sessions for a, b in zip(s["integrity_unconfirmed_seq"], s["integrity_unconfirmed_seq"][1:])]
tasks_only = [r for r in unconfirmed_rows if all(f["seen_in"] == "tasks" and f["missing_in"] == "children/sibling"
                                                 for f in r["unconfirmed_findings"])]
children_only = [r for r in unconfirmed_rows if all(f["seen_in"] == "children/sibling" and f["missing_in"] == "tasks"
                                                     for f in r["unconfirmed_findings"])]
by_group = {}
for s in sessions:
    g = by_group.setdefault(s["group"], {"guest_boots": [], "qemu_pids": [], "sessions": 0,
                                        "first_full_pages": s["full_snapshots"][0]["pages"]})
    g["sessions"] += 1
    if s["guest_boot"] not in g["guest_boots"]:
        g["guest_boots"].append(s["guest_boot"])
    if s["qemu"]["pid"] not in g["qemu_pids"]:
        g["qemu_pids"].append(s["qemu"]["pid"])
    g["last_full_pages"] = s["full_snapshots"][-1]["pages"]
    g["max_full_pages"] = max(g.get("max_full_pages", 0), *(f["pages"] for f in s["full_snapshots"]))
summary = {
    "accepted_sessions": len(accepted),
    "sessions_by_role": dict(Counter(s["role"] for s in accepted)),
    "windows_min": min(s["windows"] for s in accepted), "windows_max": max(s["windows"] for s in accepted),
    "integrity_findings": sum(s["integrity_findings"] for s in sessions),
    "accepted_missed_slots": sum(s["collector_end"]["missed_slots"] for s in accepted),
    "accepted_collector_errors": sum(s["collector_end"]["errors"] for s in accepted),
    "log_error_lines": sum(s["log_error_lines"] for s in sessions),
    "scheduler_skips": sum(len(s["scheduler_skips"]) for s in sessions),
    "measurement_dirty_sessions": [s["session"] for s in sessions if s["measurement_dirty"]],
    "behavior_valid_rows_min": min(s["behavior_valid_rows"] for s in sessions),
    "full_pages_min": min(f["pages"] for s in sessions for f in s["full_snapshots"]),
    "full_pages_max": max(f["pages"] for s in sessions for f in s["full_snapshots"]),
    "full_ms_min": min(f["total_ms"] for s in sessions for f in s["full_snapshots"]),
    "full_ms_max": max(f["total_ms"] for s in sessions for f in s["full_snapshots"]),
    "cycle_total_ms_max": max(s["cycle_total_ms_max"] for s in sessions),
    "cycle_total_ms_max_session": max(sessions, key=lambda s: s["cycle_total_ms_max"])["session"],
    "delta_ms_max_accepted": max(s["delta_ms"]["max"] for s in accepted),
    "delta_ms_max_accepted_session": max(accepted, key=lambda s: s["delta_ms"]["max"])["session"],
    "delta_ms_max_all": max(s["delta_ms"]["max"] for s in sessions),
    "long_delta_cycles": {f"over_{t}_ms": sum(c["total_ms"] > t for c in all_long) for t in (1500, 2000, 3000, 4000, 5000)},
    "writer_queue_jobs_max": max(s["writer"]["queue_jobs_max"] for s in sessions),
    "writer_queue_jobs_max_session": max(sessions, key=lambda s: s["writer"]["queue_jobs_max"])["session"],
    "writer_queue_wait_ms_max": max(s["writer"]["queue_wait_ms_max"] for s in sessions),
    "data_closed_ms_max": worst_closed["writer"]["data_closed_ms"]["max"],
    "data_closed_ms_max_session": worst_closed["session"],
    "data_closed_ms_max_seq": worst_closed["writer"]["data_closed_ms"]["max_seq"],
    "rusage_majflt_max": max(s["rusage_majflt_max"] for s in sessions),
    "rusage_majflt_sessions": [s["session"] for s in sessions if s["rusage_majflt_max"] > 0],
    "monitor_max_gap_s": max(s["monitor_max_gap_s"] for s in sessions),
    "monitor_missed_ticks": sum(s["monitor_missed_ticks"] for s in sessions),
    "qemu_swap_kb_max": max(s["host_monitor"]["qemu_swap_kb_max"] for s in sessions),
    "qemu_swap_sessions": [s["session"] for s in sessions if s["host_monitor"]["qemu_swap_kb_max"] > 0],
    # The longest cycles of the sessions in which QEMU had memory in swap while the monitor ran.
    "qemu_swap_sessions_cycle_total_ms_max": max((s["cycle_total_ms_max"] for s in sessions
                                                  if s["host_monitor"]["qemu_swap_kb_max"] > 0), default=None),
    "qemu_swap_sessions_delta_ms_max": max((s["delta_ms"]["max"] for s in sessions
                                            if s["host_monitor"]["qemu_swap_kb_max"] > 0), default=None),
    # VmSwap of QEMU when the session started, before the prefault step reads swapped guest memory back in.
    "qemu_swap_at_start_count": sum((s["qemu_swap_kb_at_start"] or 0) > 0 for s in sessions),
    "qemu_swap_kb_at_start_max": max(s["qemu_swap_kb_at_start"] or 0 for s in sessions),
    "sda_util_ge_99_samples": sum(s["host_monitor"]["sda_util_ge_99_samples"] for s in sessions),
    "requests": sum(s["requests"] for s in sessions),
    "request_errors": sum(s["request_errors"] for s in sessions),
    "measure_latency_max_ms": max(s["measure_latency"]["max_ms"] for s in sessions),
    "measure_latency_over_2s": sum(s["measure_latency"]["over_2s"] for s in sessions),
    "measure_latency_over_4s": sum(s["measure_latency"]["over_4s"] for s in sessions),
    "process_walk_prev_rows": sum(len(s["process_walk_prev_seq"] or []) for s in sessions),
    "process_walk_tail_rows": sum(len(s["process_walk_tail_seq"] or []) for s in sessions),
    "process_walk_sessions": sum(bool(s["process_walk_prev_seq"] or s["process_walk_tail_seq"]) for s in sessions),
    # A cut process list should count within the range (inclusive) of its neighbouring snapshots' counts.
    "walk_rows_proc_total_within_neighbours": sum(min(neighbours(r)) <= r["proc_total_before_row_after"][1]
                                                  <= max(neighbours(r)) for r in walk_rows),
    "integrity_unconfirmed_rows": sum(len(s["integrity_unconfirmed_seq"] or []) for s in sessions),
    "integrity_unconfirmed_sessions": sum(bool(s["integrity_unconfirmed_seq"]) for s in sessions),
    "unconfirmed_comm": dict(Counter(f["comm"] for r in unconfirmed_rows for f in r["unconfirmed_findings"])),
    # Which process list held the process that the other list lacked.
    "unconfirmed_only_in_tasks": sum(f["seen_in"] == "tasks" and f["missing_in"] == "children/sibling"
                                     for r in unconfirmed_rows for f in r["unconfirmed_findings"]),
    "unconfirmed_only_in_children": sum(f["seen_in"] == "children/sibling" and f["missing_in"] == "tasks"
                                        for r in unconfirmed_rows for f in r["unconfirmed_findings"]),
    "unconfirmed_findings": sum(len(r["unconfirmed_findings"]) for r in unconfirmed_rows),
    # Snapshots between consecutive unconfirmed rows of one session (12 snapshots are 60 s).
    "unconfirmed_gaps": gaps,
    "unconfirmed_gaps_multiple_of_12": sum(g % 12 == 0 for g in gaps),
    # Rows whose differences all lie on one side, and how their process count compares with both neighbours: one
    # more for a process present only in this snapshot's tasks list, equal when the process is missing from it.
    "unconfirmed_tasks_only_rows": len(tasks_only),
    "unconfirmed_tasks_only_rows_one_above_both_neighbours": sum(map(one_above, tasks_only)),
    "unconfirmed_children_only_rows": len(children_only),
    "unconfirmed_children_only_rows_equal_to_both_neighbours": sum(map(equal_to_both, children_only)),
    "audit_s_min": min(s["stage_s"]["audit"] for s in sessions),
    "audit_s_p50": rank([s["stage_s"]["audit"] for s in sessions], .5),
    "audit_s_max": max(s["stage_s"]["audit"] for s in sessions),
    "audit_s_max_session": max(sessions, key=lambda s: s["stage_s"]["audit"])["session"],
    # Audits longer than SLOW_AUDIT_S with the per-chain extraction timer: the slow part is the second chain.
    "slow_audits": [{"session": s["session"], "audit_s": s["stage_s"]["audit"], "raw_bytes": s["raw_bytes"],
                     "chain_0_sum_s": s["feature_extraction"]["chain_0"]["sum_s"],
                     "chain_1_sum_s": s["feature_extraction"]["chain_1"]["sum_s"],
                     "chain_0_p50_s": s["feature_extraction"]["chain_0"]["p50_s"],
                     "chain_1_p50_s": s["feature_extraction"]["chain_1"]["p50_s"]}
                    for s in sessions if s["stage_s"]["audit"] > SLOW_AUDIT_S],
    "slow_audit_threshold_s": SLOW_AUDIT_S,
    "extraction_chain_0_p50_s_max": max(s["feature_extraction"]["chain_0"]["p50_s"] for s in sessions),
    "extraction_chain_0_sum_s_max": max(s["feature_extraction"]["chain_0"]["sum_s"] for s in sessions),
    # Second-chain median of the sessions below the slow-audit threshold, the reference for the slow ones.
    "extraction_chain_1_p50_s_max_not_slow": max(s["feature_extraction"]["chain_1"]["p50_s"] for s in sessions
                                                 if s["stage_s"]["audit"] <= SLOW_AUDIT_S),
    "extraction_chain_1_p50_s_max_not_slow_session": max(
        (s for s in sessions if s["stage_s"]["audit"] <= SLOW_AUDIT_S),
        key=lambda s: s["feature_extraction"]["chain_1"]["p50_s"])["session"],
    # Sessions with the largest ratio of second-chain to first-chain extraction time (sum of the per-snapshot timer).
    "extraction_chain_ratio_top": sorted(({"session": s["session"], "audit_s": s["stage_s"]["audit"],
                                          "ratio": round(s["feature_extraction"]["chain_1"]["sum_s"]
                                                         / s["feature_extraction"]["chain_0"]["sum_s"], 3)}
                                         for s in sessions), key=lambda r: -r["ratio"])[:6],
    "archive_s_max": max(s["stage_s"]["archive"] for s in sessions),
    "raw_bytes_total": sum(s["raw_bytes"] for s in sessions),
    "archive_stored_bytes_total": sum(s["archive_stored_bytes"] for s in sessions),
    "by_group": by_group,
}
if NOTE.startswith("TODO"):
    raise SystemExit("write the v6 operator note first")
doc = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
    "commit_note": COMMIT_NOTE,
    "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
    "guest": manifest["guest_environment"], "command": " ".join(sys.argv), "n": len(sessions),
    "values": {
        "campaign": manifest["id"], "campaign_commit": manifest["commit"],
        "planned_sessions": len(manifest["sessions"]),
        "accepted_sessions": sum(s["accepted"] for s in sessions),
        "rejected_sessions": [s["session"] for s in sessions if not s["accepted"]],
        "final_status": {k: json.loads((campaign / "status.json").read_text()).get(k)
                         for k in ("status", "stage", "message", "accepted_archived", "session", "corpus")},
        "closed": json.loads(closed.read_text()) if closed.exists() else None,
        "corpus": {k: v for k, v in json.loads(corpus.read_text()).items() if not isinstance(v, (list, dict))}
                  | {"sessions": len(json.loads(corpus.read_text())["sessions"]),
                     "allocation_mismatches": json.loads(corpus.read_text())["allocation_mismatches"]}
                  if corpus.exists() else None,
        "summary": summary,
        "groups": groups,
        "qemu_processes": sorted({(g["qemu"]["pid"], g["qemu"]["start_ticks"]) for g in groups.values()}),
        "operator_stop_requests": stops,
        "stopped_states": stopped,
        "operator_incidents": [i | effects[i["utc"]] for i in INCIDENTS],
        "operator_diagnostics": diagnostics,
        "sessions": sessions,
        "verify_archives": {"verified": re.findall(r"^verified (\S+)$", verify, re.M),
                            "n_verified": len(re.findall(r"^verified (\S+)$", verify, re.M)),
                            "wall_s": float(re.search(r"seconds=([\d.]+)", verify)[1]),
                            "rc": int(re.search(r"rc=(\d+)", verify)[1])},
        "inputs_sha256": {"campaign.json": sha(campaign / "campaign.json"), "verify_log": sha(verify_log),
                          "status.json": sha(campaign / "status.json")}
                         | ({"closed.json": sha(closed)} if closed.exists() else {})
                         | ({"corpus.json": sha(corpus)} if corpus.exists() else {})
                         | {"events": {name: sha(campaign / "events" / name) for name, _ in records},
                            "groups": {p.name: sha(p) for p in sorted((campaign / "groups").glob("*.json"))
                                       if not p.name.endswith(".reboot-intent.json")}},
        "note": NOTE,
    },
}
out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({k: v for k, v in doc["values"].items() if k not in ("sessions", "operator_diagnostics")},
                 indent=1, ensure_ascii=False)[:8000])
