#!/usr/bin/env python3
"""Lightweight host resource timeline for a collection session (JSONL, fixed tick).

Reads only /proc and /sys. Missing sensors are reported as null, never guessed.
Counters are cumulative; derived rates use the actual time between samples.
SIGTERM/SIGINT end the run with a final record. `summarize` checks a log offline.
"""
import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import queue
import re
import signal
import socket
import sys
import threading
import time

SCHEMA = "hyptcn3/host-monitor/1"
METRICS = {
    "cpu.jiffies": "cumulative /proc/stat 'cpu' line (user nice system idle iowait irq softirq steal), USER_HZ ticks",
    "cpu.busy_pct": "100 * (1 - (idle+iowait) delta / total delta) since the previous sample, all CPUs",
    "cpu.iowait_pct": "100 * iowait delta / total delta since the previous sample",
    "load": "/proc/loadavg 1, 5 and 15 minute averages",
    "mem_kb": "selected /proc/meminfo fields in kB",
    "vmstat": "cumulative /proc/vmstat counters (pswpin/pswpout pages, pgmajfault, pgpgin/pgpgout KiB)",
    "disks": "cumulative /proc/diskstats per whole disk: reads, sectors_read, writes, sectors_written (512 B), io_ms",
    "disks_rate": "derived per disk since previous sample: read_MBps, write_MBps, util_pct (io_ms delta / elapsed)",
    "fs": "statvfs per monitored path: free_bytes (available to unprivileged users), total_bytes",
    "procs": "per label: pid, cpu_pct (utime+stime delta / elapsed, 100 = one CPU), rss_kb, swap_kb",
    "temps_c": "hwmon temperature inputs in degrees Celsius, keyed name/label",
    "cpufreq_mhz": "scaling_cur_freq per CPU in MHz",
    "psi_avg10": "/proc/pressure some avg10 for cpu, memory, io (percent)",
}
# Mlocked/Unevictable: the collector locks its queue memory (output.mlock); locked memory cannot be
# reclaimed, so its size belongs next to the swap and dirty-memory figures.
MEM_KEYS = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "Dirty", "Writeback",
            "AnonPages", "Shmem", "SwapTotal", "SwapFree", "SwapCached", "Mlocked", "Unevictable")
VM_KEYS = ("pswpin", "pswpout", "pgmajfault", "pgpgin", "pgpgout")


def utc(ts=None):
    return datetime.fromtimestamp(time.time() if ts is None else ts, timezone.utc).isoformat()


def read(path):
    return Path(path).read_text()


def whole_disks():
    return sorted(d.name for d in Path("/sys/block").iterdir()
                  if not d.name.startswith(("loop", "ram", "zram", "dm-", "sr")))


def sensors():
    found = {}
    for hw in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        try:
            name = read(hw / "name").strip()
        except OSError:
            continue
        for temp in sorted(hw.glob("temp*_input")):
            label_file = temp.with_name(temp.name.replace("_input", "_label"))
            label = read(label_file).strip() if label_file.exists() else temp.name.split("_")[0]
            found[f"{name}/{label}/{hw.name}"] = temp
    return found


class Monitor:
    def __init__(self, args):
        self.args, self.prev, self.errors = args, None, {}
        self.disks = args.disk or whole_disks()
        self.sensors = sensors()
        self.cpus = sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"))
        self.pids, self.discovered = {}, -math.inf
        for item in args.pid or []:
            pid, _, label = item.partition(":")
            self.pids.setdefault(label or "pid", set()).add(int(pid))
        self.matches = [(label, re.compile(rx)) for label, _, rx in (m.partition("=") for m in args.match or [])]

    def note(self, key, exc):
        self.errors[key] = f"{type(exc).__name__}: {exc}"[:200]

    def discover(self, now):
        if now - self.discovered < 10 or not self.matches:
            return
        self.discovered = now
        for label, rx in self.matches:
            self.pids[label] = set()
        for proc in Path("/proc").glob("[0-9]*"):
            try:
                cmd = read(proc / "cmdline").replace("\0", " ").strip()
            except OSError:
                continue
            if proc.name == str(os.getpid()):
                continue
            for label, rx in self.matches:
                if cmd and rx.search(cmd):
                    self.pids[label].add(int(proc.name))

    def counters(self):
        c = {}
        try:
            line = read("/proc/stat").splitlines()[0].split()
            c["cpu"] = [int(x) for x in line[1:9]]
        except (OSError, ValueError, IndexError) as exc:
            self.note("cpu", exc)
        try:
            mem = dict(l.split(":", 1) for l in read("/proc/meminfo").splitlines())
            c["mem_kb"] = {k: int(mem[k].split()[0]) if k in mem else None for k in MEM_KEYS}
        except (OSError, ValueError) as exc:
            self.note("mem", exc)
        try:
            vm = dict(l.split() for l in read("/proc/vmstat").splitlines())
            c["vmstat"] = {k: int(vm[k]) if k in vm else None for k in VM_KEYS}
        except (OSError, ValueError) as exc:
            self.note("vmstat", exc)
        try:
            disks = {}
            for line in read("/proc/diskstats").splitlines():
                f = line.split()
                if f[2] in self.disks:
                    disks[f[2]] = {"reads": int(f[3]), "sectors_read": int(f[5]), "writes": int(f[7]),
                                   "sectors_written": int(f[9]), "io_ms": int(f[12])}
            c["disks"] = disks
        except (OSError, ValueError, IndexError) as exc:
            self.note("disks", exc)
        procs = {}
        for label, pids in self.pids.items():
            procs[label] = []
            for pid in sorted(pids):
                try:
                    stat = read(f"/proc/{pid}/stat").rsplit(")", 1)[1].split()
                    status = dict(l.split(":", 1) for l in read(f"/proc/{pid}/status").splitlines() if ":" in l)
                    procs[label].append({"pid": pid, "ticks": int(stat[11]) + int(stat[12]),
                                         "rss_kb": int(status.get("VmRSS", "0 kB").split()[0]),
                                         "swap_kb": int(status.get("VmSwap", "0 kB").split()[0])})
                except (OSError, ValueError, IndexError):
                    continue  # Process ended between discovery and sampling.
        c["procs"] = procs
        return c

    def sample(self, tick, now_mono):
        self.discover(now_mono)
        c = self.counters()
        doc = {"type": "sample", "i": tick, "t_utc": utc(), "t_mono": round(now_mono - self.args.origin, 6)}
        doc.update({k: c[k] for k in ("mem_kb", "vmstat", "disks") if k in c})
        doc["cpu"] = {"jiffies": c.get("cpu")}
        try:
            doc["load"] = [float(x) for x in read("/proc/loadavg").split()[:3]]
        except (OSError, ValueError) as exc:
            self.note("load", exc)
        doc["fs"] = {}
        for path in self.args.path or []:
            try:
                st = os.statvfs(path)
                doc["fs"][path] = {"free_bytes": st.f_bavail * st.f_frsize, "total_bytes": st.f_blocks * st.f_frsize}
            except OSError as exc:
                doc["fs"][path] = None
                self.note("fs:" + path, exc)
        doc["temps_c"] = {}
        for key, path in self.sensors.items():
            try:
                doc["temps_c"][key] = int(read(path)) / 1000
            except (OSError, ValueError):
                doc["temps_c"][key] = None
        try:
            doc["cpufreq_mhz"] = [int(read(p)) / 1000 for p in self.cpus] if self.cpus else None
        except (OSError, ValueError) as exc:
            doc["cpufreq_mhz"] = None
            self.note("cpufreq", exc)
        doc["psi_avg10"] = {}
        for kind in ("cpu", "memory", "io"):
            try:
                doc["psi_avg10"][kind] = float(read(f"/proc/pressure/{kind}").split()[1].split("=")[1])
            except (OSError, ValueError, IndexError):
                doc["psi_avg10"][kind] = None
        prev = self.prev
        dt = now_mono - prev[0] if prev else None
        if prev and dt and dt > 0 and c.get("cpu") and prev[1].get("cpu"):
            delta = [a - b for a, b in zip(c["cpu"], prev[1]["cpu"])]
            total = sum(delta)
            if total > 0:
                doc["cpu"]["busy_pct"] = round(100 * (1 - (delta[3] + delta[4]) / total), 3)
                doc["cpu"]["iowait_pct"] = round(100 * delta[4] / total, 3)
        if prev and dt and dt > 0:
            rates = {}
            for name, now_d in c.get("disks", {}).items():
                old = prev[1].get("disks", {}).get(name)
                if old:
                    rates[name] = {"read_MBps": round((now_d["sectors_read"] - old["sectors_read"]) * 512 / dt / 1e6, 4),
                                   "write_MBps": round((now_d["sectors_written"] - old["sectors_written"]) * 512 / dt / 1e6, 4),
                                   "util_pct": round(min(100.0, (now_d["io_ms"] - old["io_ms"]) / (dt * 10)), 3)}
            doc["disks_rate"] = rates
        hz = os.sysconf("SC_CLK_TCK")
        doc["procs"] = {}
        for label, items in c.get("procs", {}).items():
            old = {p["pid"]: p for p in (prev[1].get("procs", {}).get(label, []) if prev else [])}
            doc["procs"][label] = [{"pid": p["pid"], "rss_kb": p["rss_kb"], "swap_kb": p["swap_kb"],
                                    "cpu_pct": round(100 * (p["ticks"] - old[p["pid"]]["ticks"]) / hz / dt, 3)
                                    if dt and p["pid"] in old else None} for p in items]
        if self.errors:
            doc["errors"] = dict(self.errors)
            self.errors.clear()
        self.prev = (now_mono, c)
        return doc


def run(args):
    stop = {"signal": None}

    def handle(signum, _frame):
        if stop["signal"] is None:
            stop["signal"] = signum  # Later signals are ignored; cleanup is short.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, handle)
    args.origin = time.monotonic()
    monitor = Monitor(args)
    header = {"schema": SCHEMA, "type": "header", "session_id": args.session_id, "start_utc": utc(),
              "mono_origin": "seconds since monitor start (time.monotonic)", "interval_s": args.interval_s,
              "hostname": socket.gethostname(), "kernel": platform.release(), "cpus": os.cpu_count(),
              "user_hz": os.sysconf("SC_CLK_TCK"), "page_size": os.sysconf("SC_PAGE_SIZE"),
              "disks": monitor.disks, "paths": args.path or [], "process_labels":
              {**{k: sorted(v) for k, v in monitor.pids.items() if k not in dict(monitor.matches)},
               **{label: rx.pattern for label, rx in monitor.matches}},
              "sensors": sorted(monitor.sensors), "cpufreq_available": bool(monitor.cpus), "metrics": METRICS,
              "note": "Observational host timeline; it does not by itself measure collector overhead."}
    samples = missed = 0
    # No fsync while sampling: on the working SSD an fsync waited for unrelated
    # writeback of a full snapshot in the same ext4 journal and the monitor lost
    # ticks (2026-10-21 pilot: a 3 s sample gap). Line-buffered samples reach the
    # page cache at once and the kernel writes them back within ~30 s; the end
    # record is fsynced. A plain write can still block in that writeback
    # (2026-10-22: single 2 s gaps in campaign sessions), so a writer thread
    # takes the lines from a queue and the sampling loop never waits for it.
    lines, failed = queue.SimpleQueue(), []

    def write_lines(out):
        while (line := lines.get()) is not None:
            try:
                out.write(line)
            except OSError as exc:
                failed.append(exc)
                return

    with open(args.out, "x", buffering=1) as out:
        out.write(json.dumps(header) + "\n")
        writer = threading.Thread(target=write_lines, args=(out,), name="monitor-writer", daemon=True)
        writer.start()
        tick = 0
        while stop["signal"] is None and not failed:
            lines.put(json.dumps(monitor.sample(tick, time.monotonic())) + "\n")
            samples += 1
            nxt = tick + 1
            due = args.origin + nxt * args.interval_s
            now = time.monotonic()
            if now > due:  # Fixed schedule: late ticks are skipped and counted, not shifted.
                skipped = int((now - due) // args.interval_s) + 1
                missed += skipped
                nxt += skipped
                due = args.origin + nxt * args.interval_s
            while stop["signal"] is None and time.monotonic() < due:
                time.sleep(min(.2, max(0, due - time.monotonic())))
            if args.duration_s and time.monotonic() - args.origin >= args.duration_s:
                break
            tick = nxt
        lines.put(None)
        writer.join()
        if failed:
            raise failed[0]
        out.write(json.dumps({"type": "end", "end_utc": utc(), "samples": samples, "missed_ticks": missed,
                              "signal": stop["signal"], "clean": True}) + "\n")
        out.flush()
        os.fsync(out.fileno())
    return 0


def percentile(values, q):
    values = sorted(v for v in values if v is not None)
    return values[max(0, math.ceil(q * len(values)) - 1)] if values else None


def summarize(path, start_unix=None, end_unix=None):
    """Offline check: completeness, tick gaps and resource extremes in an optional window."""
    problems, records = [], []
    lines = Path(path).read_bytes().split(b"\n")
    tail = lines.pop()
    if tail:
        problems.append("torn_last_line")
    for number, line in enumerate(lines, 1):
        try:
            records.append(json.loads(line))
        except ValueError:
            problems.append(f"corrupt_line:{number}")
    header = records[0] if records and records[0].get("type") == "header" else None
    end = records[-1] if records and records[-1].get("type") == "end" else None
    if header is None or header.get("schema") != SCHEMA:
        problems.append("missing_header")
    if end is None:
        problems.append("missing_end_record")
    samples = [r for r in records if r.get("type") == "sample"]
    times = [datetime.fromisoformat(r["t_utc"]).timestamp() for r in samples]
    interval = header["interval_s"] if header else None
    window = [(t, r) for t, r in zip(times, samples)
              if (start_unix is None or t >= start_unix) and (end_unix is None or t <= end_unix)]
    gaps = [b - a for a, b in zip(times, times[1:])]
    max_gap = max(gaps) if gaps else None
    if interval and max_gap is not None and max_gap > 2.5 * interval:
        problems.append(f"sample_gap_s:{max_gap:.3f}")
    if start_unix is not None and (not times or times[0] > start_unix + 2 * (interval or 1)):
        problems.append("does_not_cover_window_start")
    if end_unix is not None and (not times or times[-1] < end_unix - 2 * (interval or 1)):
        problems.append("does_not_cover_window_end")
    ws = [r for _, r in window]
    swap_used = [(r["mem_kb"]["SwapTotal"] - r["mem_kb"]["SwapFree"]) for r in ws
                 if r.get("mem_kb") and r["mem_kb"].get("SwapTotal") is not None]
    pswp = [(r["vmstat"]["pswpin"], r["vmstat"]["pswpout"]) for r in ws if r.get("vmstat")]
    disk_written = {}
    for name in (header or {}).get("disks", []):
        values = [r["disks"][name]["sectors_written"] for r in ws if name in r.get("disks", {})]
        disk_written[name] = (values[-1] - values[0]) * 512 if len(values) > 1 else None
    free = {p: min((r["fs"][p]["free_bytes"] for r in ws if r.get("fs", {}).get(p)), default=None)
            for p in (header or {}).get("paths", [])}
    temps = [v for r in ws for v in (r.get("temps_c") or {}).values() if v is not None]
    return {"path": str(path), "problems": problems, "samples": len(samples), "window_samples": len(ws),
            "first_utc": samples[0]["t_utc"] if samples else None, "last_utc": samples[-1]["t_utc"] if samples else None,
            "max_gap_s": max_gap, "missed_ticks": end.get("missed_ticks") if end else None,
            "cpu_busy_pct": {"p50": percentile([r["cpu"].get("busy_pct") for r in ws], .5),
                             "p95": percentile([r["cpu"].get("busy_pct") for r in ws], .95),
                             "max": percentile([r["cpu"].get("busy_pct") for r in ws], 1)},
            "iowait_pct_p95": percentile([r["cpu"].get("iowait_pct") for r in ws], .95),
            "mem_available_kb_min": min((r["mem_kb"]["MemAvailable"] for r in ws if r.get("mem_kb")), default=None),
            "swap_used_kb_max": max(swap_used, default=None),
            "swap_in_pages": pswp[-1][0] - pswp[0][0] if len(pswp) > 1 else None,
            "swap_out_pages": pswp[-1][1] - pswp[0][1] if len(pswp) > 1 else None,
            "disk_bytes_written": disk_written, "fs_free_bytes_min": free,
            "temp_c_max": max(temps) if temps else None,
            "window": {"start_unix": start_unix, "end_unix": end_unix},
            "note": "Percentiles are nearest-rank over the samples inside the window."}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--interval-s", type=float, default=1.0)
    r.add_argument("--duration-s", type=float, default=0, help="0 = until SIGTERM")
    r.add_argument("--session-id", default="")
    r.add_argument("--path", action="append", help="statvfs path (repeatable)")
    r.add_argument("--disk", action="append", help="whole disk name, default all")
    r.add_argument("--pid", action="append", help="PID[:label] (repeatable)")
    r.add_argument("--match", action="append", help="LABEL=REGEX over /proc/*/cmdline (repeatable)")
    s = sub.add_parser("summarize")
    s.add_argument("path", type=Path)
    s.add_argument("--start-unix", type=float)
    s.add_argument("--end-unix", type=float)
    a = ap.parse_args(argv)
    if a.command == "run":
        if not 0.1 <= a.interval_s <= 60 or a.duration_s < 0:
            ap.error("interval must be 0.1..60 s and duration >= 0")
        try:
            return run(a)
        except OSError as exc:
            print(f"host_monitor: {exc}", file=sys.stderr)
            return 3
    doc = summarize(a.path, a.start_unix, a.end_unix)
    print(json.dumps(doc, indent=2))
    return 0 if not doc["problems"] else 2


if __name__ == "__main__":
    sys.exit(main())
