#!/usr/bin/env python3
"""E5 (VO5): overhead of the monitoring module on the lab VM and the host, A/B/A design.

Conditions (same HTTP load profile in all of them):
  A  lab workload only, no collection
  B  the collector (vmicollect) with exactly the options `safeguard run` gives it, no detector
  C  the full detector: `python3 -m safeguard run`

Every repetition is a five-block sequence in which each monitored block is flanked by A
blocks: A-B-A-C-A or A-C-A-B-A. The two patterns alternate in ABBA order across
repetitions (P0 P1 P1 P0 ...), so B and C occupy both positions equally often and, for
any even number of repetitions, have the same mean position in the run (a linear drift
does not separate them). The effect of X in one triplet is X - mean(A before, A after).

Subcommands:
  plan                      print the counterbalanced schedule (no side effects)
  run --dry-run             print every step and command of a run (no side effects)
  run --execute             orchestrate the run; needs sudo like scripts/collection.py run
  summarize LOGDIR --out F  offline result from the recorded logs only; refuses incomplete
                            or mismatched logs and writes nothing then (exit 2)

The runner only calls existing tools: scripts/host_traffic.py (load + request logs),
scripts/host_monitor.py (host CPU/IO/memory), scripts/labctl.py (as the VM owner),
the collector command of safeguard/supervisor.py and `python3 -m safeguard run`.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import host_monitor, traffic_log  # noqa: E402  (stdlib-only readers)

PLAN_SCHEMA = "hyptcn3/e5-aba-plan/1"
RUN_SCHEMA = "hyptcn3/e5-aba-run/1"
RUN_END_SCHEMA = "hyptcn3/e5-aba-run-end/1"
BLOCK_SCHEMA = "hyptcn3/e5-aba-block/1"
RESULT_SCHEMA = "hyptcn3/e5-aba-result/1"
CONDITIONS = {"A": "lab workload, no collection",
              "B": "collector (vmicollect) with the options of safeguard run, no detector",
              "C": "full detector: python3 -m safeguard run"}
MONITORED = ("B", "C")
PATTERNS = (("A", "B", "A", "C", "A"), ("A", "C", "A", "B", "A"))
SUMMARY_INTERVAL_S = 5
# Process labels of the host monitor. Anchored at argv[0] so that an argument that merely
# mentions a path (e.g. this runner's --collector) never counts as a running component.
MONITOR_MATCH = {"qemu": "guest={domain},", "vmicollect": r"^\S*vmicollect/build/vmicollect ",
                 "safeguard": r"^\S*python\S* -m safeguard ", "traffic": "host_traffic.py",
                 "passt": "^passt ", "monitor": "host_monitor.py"}
PRESENCE = {"A": {"vmicollect": False, "safeguard": False},
            "B": {"vmicollect": True, "safeguard": False},
            "C": {"vmicollect": True, "safeguard": True}}
DEFAULTS = {"protocol": "config/collection-v2.json", "scenario": "steady", "traffic_seed": 1,
            "repetitions": 4, "warmup_s": 240, "measure_s": 600, "rest_s": 60,
            "bundle": "data/models/server-v2-benign-v6", "threads": 4,
            "collector": "vmicollect/build/vmicollect"}
# Extra collector cycles after warmup + measurement: the component must outlive the measured
# window although it starts a few seconds after the warmup began (safeguard preflight).
EXTRA_CYCLES = 4
COMPONENT_DRAIN_S = 90  # output.drain_s that safeguard/supervisor.py sets
MEASURE_TOLERANCE = .05


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def unix(iso):
    return datetime.fromisoformat(iso).timestamp()


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rel(path):
    path = Path(path).absolute()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def write_json(path, doc):
    with Path(path).open("x") as stream:
        json.dump(doc, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


# --- schedule -------------------------------------------------------------------------------

def schedule(repetitions, allow_unbalanced=False):
    """Blocks in run order; each B/C block names its two flanking A blocks."""
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if repetitions % 2 and not allow_unbalanced:
        raise ValueError("an odd number of repetitions does not counterbalance B and C "
                         "(use an even number or --allow-unbalanced)")
    blocks = []
    for rep in range(repetitions):
        pattern = PATTERNS[0 if rep % 4 in (0, 3) else 1]
        first = len(blocks)
        for position, condition in enumerate(pattern):
            index = len(blocks)
            blocks.append({"index": index, "block_id": f"{index + 1:02d}-r{rep + 1}-{condition}",
                           "repetition": rep + 1, "position": position, "condition": condition,
                           "pattern": "-".join(pattern)})
        for block in blocks[first:]:
            if block["condition"] in MONITORED:
                block["flanks"] = [blocks[block["index"] - 1]["block_id"], blocks[block["index"] + 1]["block_id"]]
    return blocks


def balance(blocks):
    """Position counts and mean run index of B and C; balanced when they coincide."""
    doc = {}
    for condition in MONITORED:
        mine = [b for b in blocks if b["condition"] == condition]
        doc[condition] = {"blocks": len(mine),
                          "positions": dict(sorted(Counter(b["position"] for b in mine).items())),
                          "mean_index": sum(b["index"] for b in mine) / len(mine) if mine else None}
    b, c = doc["B"], doc["C"]
    doc["balanced"] = (b["blocks"] == c["blocks"] and b["positions"] == c["positions"]
                       and len(set(b["positions"].values())) <= 1 and b["mean_index"] == c["mean_index"])
    return doc


def plan_doc(cfg):
    blocks = schedule(cfg["repetitions"], cfg.get("allow_unbalanced", False))
    block_s = cfg["warmup_s"] + cfg["measure_s"] + cfg["rest_s"]
    return {"schema": PLAN_SCHEMA, "experiment": "E5", "objective": "VO5", "conditions": CONDITIONS,
            "patterns": ["-".join(p) for p in PATTERNS],
            "pattern_order": "ABBA across repetitions: P0 P1 P1 P0, repeated",
            "effect": "per triplet: X - (A_before + A_after) / 2; condition effect = mean over its triplets",
            "blocks": blocks, "balance": balance(blocks),
            "estimated_hours": round(len(blocks) * block_s / 3600, 2)}


# --- configuration --------------------------------------------------------------------------

LABCTL_PORT = 18080  # scripts/labctl.py default: the host port of the VM that needs no --vm/--port


def lab_vm(p, name):
    """Domain and target of the VM under test (scripts/collection.py vms/for_vm, stdlib only here).

    A protocol with one domain/target is that VM; a multi-VM protocol names its VMs and E5 runs
    on one of them (--vm), with no campaign on any other: the run holds data/collections/.lock.
    """
    if "vms" not in p:
        if name is not None:
            raise ValueError("--vm is only for a protocol that lists vms")
        return {"domain": p["domain"], "target": p["target"]}
    rows = {row["name"]: row for row in p["vms"]}
    if name not in rows:
        raise ValueError("the protocol lists several VMs; choose one with --vm: " + ", ".join(rows))
    return {"vm": name, "port": rows[name]["port"], "domain": rows[name]["domain"],
            "target": f"http://127.0.0.1:{rows[name]['port']}"}


def make_config(a):
    protocol_path = (ROOT / a.protocol) if not Path(a.protocol).is_absolute() else Path(a.protocol)
    p = json.loads(protocol_path.read_text())
    vm = lab_vm(p, getattr(a, "vm", None))
    p = {**p, "domain": vm["domain"], "target": vm["target"]}
    if a.scenario not in p["scenarios"]:
        raise ValueError(f"unknown scenario {a.scenario!r}; protocol has {sorted(p['scenarios'])}")
    for key in ("warmup_s", "measure_s"):
        if not getattr(a, key) > 0:
            raise ValueError(key + " must be positive")
    if a.rest_s < 0:
        raise ValueError("rest_s must be >= 0")
    if a.warmup_s < p["window_rows"] * p["interval_s"]:
        raise ValueError(f"warmup must cover one detector window ({p['window_rows'] * p['interval_s']} s) "
                         "so that condition C is already scoring when the measurement starts")
    s = p["scenarios"][a.scenario]
    cycles = math.ceil((a.warmup_s + a.measure_s) / p["interval_s"]) + EXTRA_CYCLES
    return {"protocol": rel(protocol_path), "protocol_sha256": sha256(protocol_path),
            "protocol_values": {k: p[k] for k in ("domain", "target", "interval_s", "full_every", "bin_bytes",
                                                  "window_rows", "max_gap_s", "min_free_gib", "profile")},
            "domain": a.domain or p["domain"], "target": a.target or p["target"],
            **({"vm": vm["vm"], "port": vm["port"]} if "vm" in vm else {}),
            "profile": a.profile or p["profile"], "bundle": a.bundle, "collector": a.collector,
            "threads": a.threads, "repetitions": a.repetitions, "allow_unbalanced": a.allow_unbalanced,
            "warmup_s": a.warmup_s, "measure_s": a.measure_s, "rest_s": a.rest_s,
            "component_cycles": cycles, "scenario": a.scenario,
            "traffic": {"target": a.target or p["target"], "profile": "lab", "seed": a.traffic_seed,
                        "workers": s["workers"], "burst": s["burst"], "catalog_share": s["catalog_share"],
                        "write_share": s["write_share"], "dur": 0, "summary_interval_s": SUMMARY_INTERVAL_S,
                        "initial_phase": "warmup"},
            "load_model": "closed loop, identical generator arguments and seed in every block"}


def traffic_argv(cfg, bdir, block_id):
    t = cfg["traffic"]
    return [sys.executable, ROOT / "scripts/host_traffic.py", "--profile", "lab", "--target", t["target"],
            "--dur", "0", "--seed", t["seed"], "--vlakien", t["workers"], "--burst", t["burst"],
            "--catalog-share", t["catalog_share"], "--write-share", t["write_share"], "--session-id", block_id,
            "--requests-log", bdir / "traffic_requests.jsonl", "--intervals-log", bdir / "traffic_intervals.jsonl",
            "--summary-interval-s", t["summary_interval_s"], "--initial-phase", "warmup",
            "--out", bdir / "traffic.json"]


def monitor_argv(cfg, bdir, block_id):
    argv = [sys.executable, ROOT / "scripts/host_monitor.py", "run", "--out", bdir / "host_monitor.jsonl",
            "--interval-s", "1", "--session-id", block_id, "--path", bdir, "--path", "/"]
    for label, regex in MONITOR_MATCH.items():
        argv += ["--match", f"{label}={regex.format(domain=cfg['domain'])}"]
    return argv


def component_argv(cfg, condition, bdir):
    """B: the collector exactly as safeguard/supervisor.py starts it. C: safeguard run itself."""
    if condition == "B":
        from safeguard.supervisor import collector_command
        protocol = {k: cfg["protocol_values"][k] for k in ("interval_s", "full_every", "bin_bytes")}
        return collector_command(ROOT / cfg["collector"], (bdir / "raw").absolute(), cfg["domain"], protocol,
                                 cfg["component_cycles"])
    if condition == "C":
        return [sys.executable, "-m", "safeguard", "--threads", cfg["threads"], "run", "--bundle", ROOT / cfg["bundle"],
                "--protocol", ROOT / cfg["protocol"], "--domain", cfg["domain"], "--profile", ROOT / cfg["profile"],
                "--out", (bdir / "safeguard").absolute(), "--cycles", cfg["component_cycles"]]
    return None


def labctl_argv(cfg, *args):
    return [sys.executable, ROOT / "scripts/labctl.py", "--domain", cfg["domain"],
            *(["--vm", cfg["vm"], "--port", cfg["port"]] if cfg.get("vm") else []), *args]


def guest_protocol(cfg):
    """What scripts/collection.py guest_identity needs to reach this VM through labctl."""
    return {"domain": cfg["domain"], **({"vm": cfg["vm"], "port": cfg["port"]} if cfg.get("vm") else {})}


def detector_reaches_vm(cfg):
    """Condition C: `safeguard run` calls labctl with --domain only, i.e. labctl's default host port."""
    return cfg.get("port", LABCTL_PORT) == LABCTL_PORT


def block_steps(cfg, block, bdir):
    """Ordered steps of one block; `as` = root (needs sudo), user (VM owner) or runner (in-process)."""
    c, component = block["condition"], component_argv(cfg, block["condition"], bdir)
    steps = [{"step": "check", "as": "runner", "note": "no foreign host_traffic.py; same QEMU process as the run; "
                                                       + ("hold data/collections/.lock" if c != "C" else
                                                          "lock left to safeguard run")},
             {"step": "health", "as": "runner", "note": f"GET {cfg['target']}/healthz until 200"},
             {"step": "prefault", "as": "root", "note": "read swapped-out QEMU pages back (scripts/collection.py)"}]
    if c in MONITORED:
        steps.append({"step": "collector-memory", "as": "runner",
                      "note": "MemAvailable covers the collector's locked queue; disk reserve min_free_gib"})
    steps += [{"step": "monitor-start", "as": "root", "argv": monitor_argv(cfg, bdir, block["block_id"])},
              {"step": "traffic-start", "as": "root", "argv": traffic_argv(cfg, bdir, block["block_id"]),
               "note": "phase warmup"}]
    if component:
        steps.append({"step": "component-start", "as": "root", "argv": component,
                      "note": "eBPF RAM capture needs root"})
    steps += [{"step": "warmup", "as": "runner", "seconds": cfg["warmup_s"]},
              {"step": "measure", "as": "runner", "seconds": cfg["measure_s"], "note": "SIGUSR1 to traffic"},
              {"step": "post", "as": "runner", "note": "SIGUSR2 to traffic"}]
    if component:
        steps.append({"step": "component-wait", "as": "runner",
                      "note": f"component ends by itself after {cfg['component_cycles']} cycles; SIGTERM on timeout"})
    steps += [{"step": "traffic-stop", "as": "runner", "note": "SIGTERM, final log records"},
              {"step": "monitor-stop", "as": "runner", "note": "SIGTERM, end record"},
              {"step": "block-record", "as": "runner", "note": "block.json"},
              {"step": "rest", "as": "runner", "seconds": cfg["rest_s"], "note": "no load, no collection"}]
    return steps


def preflight_steps(cfg):
    return [{"step": "root-check", "as": "runner", "note": "euid 0 and SUDO_USER (VM owner) set"},
            {"step": "traffic-stop", "as": "user", "argv": labctl_argv(cfg, "traffic-stop"),
             "note": "stop the persistent generator; it is not restarted afterwards"},
            {"step": "guest-identity", "as": "user", "note": "scripts/collection.py guest_identity (labctl exec)"},
            {"step": "run-record", "as": "runner", "note": "run.json with config, plan, commit, hashes"}]


def shown(step):
    line = f"[{step['as']:6}] {step['step']}"
    if "seconds" in step:
        line += f" {step['seconds']} s"
    if step.get("argv"):
        line += "\n           " + shlex.join(map(str, step["argv"]))
    if step.get("note"):
        line += f"\n           # {step['note']}"
    return line


def dry_run(cfg, out):
    """Print the full plan of a run. Reads configuration only; writes and starts nothing."""
    doc, out = plan_doc(cfg), Path(out).absolute()
    lines = [f"E5 A/B/A dry run -> {out} (nothing is created or started)",
             f"blocks: {len(doc['blocks'])}, estimated {doc['estimated_hours']} h, balanced: {doc['balance']['balanced']}",
             f"order: {' '.join(b['condition'] for b in doc['blocks'])}", "", "== preflight"]
    lines += [shown(s) for s in preflight_steps(cfg)]
    for block in doc["blocks"]:
        lines += ["", f"== block {block['block_id']} ({CONDITIONS[block['condition']]})"]
        lines += [shown(s) for s in block_steps(cfg, block, out / "blocks" / block["block_id"])]
    warnings = []
    if not (ROOT / cfg["collector"]).is_file():
        warnings.append(f"collector binary missing: {cfg['collector']} (make build)")
    if any(b["condition"] == "C" for b in doc["blocks"]) and not (ROOT / cfg["bundle"]).is_dir():
        warnings.append(f"bundle missing: {cfg['bundle']}")
    if Path(out).exists():
        warnings.append(f"output exists and would be refused: {out}")
    if not detector_reaches_vm(cfg):
        warnings.append(f"condition C cannot run on VM {cfg['vm']}: safeguard run reaches labctl without "
                        f"--vm/--port (host port {LABCTL_PORT}); --execute refuses")
    lines += ["", "== execute with (from the repository root):",
              "sudo env PYTHONPATH=\"$(python3 -m site --user-site)\" " + shlex.join(
                  [os.path.basename(sys.executable), "-m", "experimenty.aba", "run", "--execute", "--out", str(out),
                   *cli_options(cfg)])]
    lines += ["", *("WARNING: " + w for w in warnings)]
    print("\n".join(lines).rstrip())
    return 0


def cli_options(cfg):
    opts = ["--protocol", cfg["protocol"], *(["--vm", cfg["vm"]] if cfg.get("vm") else []),
            "--scenario", cfg["scenario"], "--traffic-seed", cfg["traffic"]["seed"],
            "--repetitions", cfg["repetitions"], "--warmup-s", cfg["warmup_s"], "--measure-s", cfg["measure_s"],
            "--rest-s", cfg["rest_s"], "--bundle", cfg["bundle"]]
    if cfg["allow_unbalanced"]:
        opts.append("--allow-unbalanced")
    return [str(o) for o in opts]


# --- execution (root) -----------------------------------------------------------------------

def git_state():
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    return commit, dirty


class Lock:
    """The capture lock of scripts/collection.py and safeguard run (no concurrent campaign)."""
    def __init__(self):
        self.stream = None

    def take(self):
        path = ROOT / "data/collections/.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("a")
        try:
            fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.release()
            # Runners of a multi-VM campaign hold this lock shared, one per VM: any of them refuses E5.
            raise ValueError("data/collections/.lock is held: a campaign or detector is running")

    def release(self):
        if self.stream:
            self.stream.close()
            self.stream = None


def wait_alive(seconds, children):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for name, process in children.items():
            if process.poll() is not None:
                raise ValueError(f"{name} exited (rc {process.returncode}) during the block")
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def run_block(cfg, block, bdir, col, run_qemu):
    status = {"schema": BLOCK_SCHEMA, **{k: block[k] for k in ("block_id", "condition", "repetition", "position",
                                                               "pattern")},
              "completed": False, "steps": {}}
    children, lock = {}, Lock()
    component = component_argv(cfg, block["condition"], bdir)

    def step(name, **values):
        status["steps"][name] = {"unix": time.time(), **values}
        print(json.dumps({"block": block["block_id"], "step": name, **values}, default=str)[:300], flush=True)

    bdir.mkdir()
    try:
        if block["condition"] != "C":
            lock.take()
        if col.generators():
            raise ValueError("another host_traffic.py is running; refusing to mix traffic")
        status["qemu_before"] = col.qemu_process(cfg["domain"])
        if status["qemu_before"] != run_qemu:
            raise ValueError("VM process differs from the start of the run (restart or restore)")
        step("health", attempts=col.wait_healthy(cfg["target"]))
        status["prefault"] = col.prefault_swapped(run_qemu["pid"])
        step("prefault", **status["prefault"])
        status["host_memory_before"] = col.host_memory(run_qemu)
        if block["condition"] in MONITORED:
            status["collector_memory"] = col.collector_memory(run_qemu["pid"])
            if not status["collector_memory"]["ok"]:
                raise ValueError("not enough free memory for the collector's locked queue")
            if shutil.disk_usage(bdir).free < cfg["protocol_values"]["min_free_gib"] * 2**30:
                raise ValueError("free disk below the protocol reserve")
        children["monitor"] = col.start_child(monitor_argv(cfg, bdir, block["block_id"]), bdir / "host_monitor.log")
        children["traffic"] = col.start_child(traffic_argv(cfg, bdir, block["block_id"]), bdir / "traffic.log")
        status["warmup_start_unix"] = time.time()
        if component:
            status["component_argv"] = list(map(str, component))
            children["component"] = col.start_child(component, bdir / "component.log")
            status["component_start_unix"] = time.time()
        step("warmup", seconds=cfg["warmup_s"])
        wait_alive(cfg["warmup_s"], children)
        os.kill(children["traffic"].pid, signal.SIGUSR1)
        status["measure_start_unix"] = time.time()
        step("measure", seconds=cfg["measure_s"])
        wait_alive(cfg["measure_s"], children)
        os.kill(children["traffic"].pid, signal.SIGUSR2)
        status["measure_end_unix"] = time.time()
        step("post")
        if component:
            process = children["component"]
            limit = (status["component_start_unix"] + cfg["component_cycles"] * cfg["protocol_values"]["interval_s"]
                     + COMPONENT_DRAIN_S + 120)
            while process.poll() is None and time.time() < limit:
                time.sleep(1)
            status["component"] = col.stop_child(children.pop("component"), 120)
            status["component_end_unix"] = time.time()
            step("component-end", **status["component"])
        status["traffic"] = col.stop_child(children.pop("traffic"), 30)
        status["qemu_after"] = col.qemu_process(cfg["domain"])
        status["host_memory_after"] = col.host_memory(run_qemu)
        status["monitor"] = col.stop_child(children.pop("monitor"), 15)
        status["completed"] = status["qemu_after"] == run_qemu
        if not status["completed"]:
            raise ValueError("VM process restarted during the block")
    except BaseException as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        for name, grace in (("component", 120), ("traffic", 30), ("monitor", 15)):
            if name in children:
                status[name] = col.stop_child(children.pop(name), grace)
        lock.release()
        status["written_unix"] = time.time()
        write_json(bdir / "block.json", status)


def chown_tree(out):
    if "SUDO_UID" in os.environ:
        owner = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        for path in [out, *out.rglob("*")]:
            os.chown(path, *owner, follow_symlinks=False)


def execute(cfg, out):
    if os.geteuid() != 0 or not os.environ.get("SUDO_USER"):
        raise ValueError("run --execute needs sudo from the VM owner's account (eBPF capture); "
                         "see `run --dry-run` for the command")
    from scripts import collection as col
    doc = plan_doc(cfg)
    if any(b["condition"] == "C" for b in doc["blocks"]) and not (ROOT / cfg["bundle"]).is_dir():
        raise ValueError("bundle not found: " + cfg["bundle"])
    if not detector_reaches_vm(cfg):
        raise ValueError(f"condition C cannot run on VM {cfg['vm']}: safeguard run reaches labctl without "
                         f"--vm/--port; run E5 on the VM with host port {LABCTL_PORT}")
    collector = ROOT / cfg["collector"]
    if not collector.is_file() or not os.access(collector, os.X_OK):
        raise ValueError("collector binary unavailable; run make build as the user")
    out = Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    (out / "blocks").mkdir()
    subprocess.run(col.user_command(labctl_argv(cfg, "traffic-stop")), cwd=ROOT, check=True)
    if col.generators():
        raise ValueError("another host_traffic.py is running; refusing to mix traffic")
    qemu = col.qemu_process(cfg["domain"])
    if qemu is None:
        raise ValueError("VM process not found")
    commit, dirty = git_state()
    run_doc = {"schema": RUN_SCHEMA, "run_id": out.name, "started_utc": utc_now(), "started_unix": time.time(),
               "command": shlex.join(map(str, [sys.executable, "-m", "experimenty.aba", *sys.argv[1:]])),
               "commit": commit, "commit_dirty": dirty, "measurement_dirty": col.measurement_dirty(),
               "host": platform.platform(), "config": cfg, "plan": doc,
               "guest_before": col.guest_identity(guest_protocol(cfg)), "qemu": qemu,
               "host_memory": col.host_memory(qemu), "collector_sha256": sha256(collector),
               "aba_sha256": sha256(Path(__file__)),
               "source_sha256": {name: sha256(ROOT / name) for name in
                                 ("scripts/host_traffic.py", "scripts/host_monitor.py", "scripts/traffic_log.py",
                                  "scripts/labctl.py", "scripts/collection.py", "safeguard/supervisor.py",
                                  "safeguard/cli.py", "safeguard/runtime.py")}}
    write_json(out / "run.json", run_doc)
    end = {"schema": RUN_END_SCHEMA, "completed": False, "blocks_done": []}
    interrupts = col.Interrupts()
    try:
        for number, block in enumerate(doc["blocks"]):
            run_block(cfg, block, out / "blocks" / block["block_id"], col, qemu)
            end["blocks_done"].append(block["block_id"])
            if number + 1 < len(doc["blocks"]):
                time.sleep(cfg["rest_s"])
        end["guest_after"] = col.guest_identity(guest_protocol(cfg))
        end["completed"] = True
    except BaseException as exc:
        end["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        try:
            interrupts.disarm()
        except InterruptedError:
            pass
        end.update(signals=interrupts.received, ended_utc=utc_now(), ended_unix=time.time())
        write_json(out / "run_end.json", end)
        interrupts.restore()
        chown_tree(out)
    print(f"E5 run complete: {out}\nSummarize: python3 -m experimenty.aba summarize {out} --out RESULT.json")
    return 0


# --- offline summary ------------------------------------------------------------------------

METRICS = ("latency_p50_ms", "latency_p95_ms", "throughput_rps", "ok_rps", "cpu_busy_pct", "cpu_iowait_pct",
           "disk_read_MBps", "disk_write_MBps", "mem_used_mib", "psi_io_avg10",
           "proc_cpu_qemu_pct", "proc_cpu_vmicollect_pct", "proc_cpu_safeguard_pct")
SAMPLE_METRICS = METRICS[4:]
PROC_LABELS = ("qemu", "vmicollect", "safeguard")


def sample_values(sample):
    """Host-monitor sample -> metric values (None when the sensor/counter is unavailable)."""
    cpu, mem, rates = sample.get("cpu") or {}, sample.get("mem_kb") or {}, sample.get("disks_rate")
    values = {"cpu_busy_pct": cpu.get("busy_pct"), "cpu_iowait_pct": cpu.get("iowait_pct"),
              "disk_read_MBps": sum(r["read_MBps"] for r in rates.values()) if rates is not None else None,
              "disk_write_MBps": sum(r["write_MBps"] for r in rates.values()) if rates is not None else None,
              "mem_used_mib": ((mem["MemTotal"] - mem["MemAvailable"]) / 1024
                               if mem.get("MemTotal") is not None and mem.get("MemAvailable") is not None else None),
              "psi_io_avg10": (sample.get("psi_avg10") or {}).get("io")}
    procs = sample.get("procs") or {}
    for label in PROC_LABELS:
        items = procs.get(label)
        known = [p["cpu_pct"] for p in items or [] if p.get("cpu_pct") is not None]
        values[f"proc_cpu_{label}_pct"] = None if items is None or (items and not known) else float(sum(known))
    return values


class BlockData:
    """Measured phase of one block split into clusters of consecutive traffic intervals."""

    def __init__(self, block_id, clusters):
        import numpy as np
        self.block_id, self.k = block_id, len(clusters)
        self.lat = [np.asarray(c["latency"], dtype=float) for c in clusters]
        self.n = np.array([c["requests"] for c in clusters], dtype=float)
        self.ok = np.array([c["ok"] for c in clusters], dtype=float)
        self.dur = np.array([c["duration_s"] for c in clusters], dtype=float)
        self.sums = {m: np.array([c["sums"][m] for c in clusters], dtype=float) for m in SAMPLE_METRICS}
        self.counts = {m: np.array([c["counts"][m] for c in clusters], dtype=float) for m in SAMPLE_METRICS}

    def metrics(self, idx):
        import numpy as np
        lat = np.concatenate([self.lat[i] for i in idx])
        q = np.quantile(lat, [.5, .95], method="inverted_cdf") if lat.size else [math.nan, math.nan]
        dur = self.dur[idx].sum()
        out = [q[0], q[1], self.n[idx].sum() / dur, self.ok[idx].sum() / dur]
        for m in SAMPLE_METRICS:
            count = self.counts[m][idx].sum()
            out.append(self.sums[m][idx].sum() / count if count else math.nan)
        return np.array(out, dtype=float)


def clusters_of(requests, intervals, samples, size):
    """Group measured intervals by `size`; requests by their interval, monitor samples by UTC time."""
    measured = [iv for iv in intervals if iv.get("type") == "interval" and iv.get("phase") == "measure"]
    groups = [measured[i:i + size] for i in range(0, len(measured), size)]
    if len(groups) > 1 and len(groups[-1]) < size:
        groups[-2].extend(groups.pop())  # a short tail joins the previous cluster
    by_interval = {}
    for r in requests:
        if r.get("type") == "request" and r.get("phase") == "measure":
            by_interval.setdefault(r["interval"], []).append(r)
    times = [(unix(s["t_utc"]), sample_values(s)) for s in samples]
    clusters = []
    for group in groups:
        members = [r for iv in group for r in by_interval.get(iv["interval"], [])]
        start, end = unix(group[0]["t_start_utc"]), unix(group[-1]["t_end_utc"])
        inside = [v for t, v in times if start <= t < end]
        clusters.append({"latency": [r["duration_ms"] for r in members], "requests": len(members),
                         "ok": sum(r.get("outcome") == "ok" for r in members),
                         "duration_s": sum(iv["duration_s"] for iv in group),
                         "samples": len(inside),
                         "sums": {m: sum(v[m] for v in inside if v[m] is not None) for m in SAMPLE_METRICS},
                         "counts": {m: sum(v[m] is not None for v in inside) for m in SAMPLE_METRICS}})
    return clusters


def read_records(path):
    records, _ = traffic_log.read_jsonl(path)
    return records


def load_block(logdir, block, run, problems, inputs):
    """Audit one block with the existing log checkers; returns (BlockData, report) or None."""
    bid, cfg = block["block_id"], run["config"]
    bdir = logdir / "blocks" / bid
    names = ("block.json", "traffic_requests.jsonl", "traffic_intervals.jsonl", "host_monitor.jsonl")
    missing = [n for n in names if not (bdir / n).is_file()]
    if missing:
        problems.append(f"{bid}: missing {', '.join(missing)}")
        return None
    for n in names:
        inputs[f"blocks/{bid}/{n}"] = sha256(bdir / n)
    status = json.loads((bdir / "block.json").read_text())
    if status.get("schema") != BLOCK_SCHEMA or status.get("block_id") != bid \
            or status.get("condition") != block["condition"]:
        problems.append(f"{bid}: block.json does not match the planned block")
    if not status.get("completed"):
        problems.append(f"{bid}: block not completed ({status.get('error')})")
    if status.get("qemu_before") != run["qemu"] or status.get("qemu_after") != run["qemu"]:
        problems.append(f"{bid}: QEMU process differs from the run (restart/restore)")
    if block["condition"] in MONITORED:
        comp = status.get("component") or {}
        if comp.get("rc") != 0 or comp.get("stopped_by") != "exited":
            problems.append(f"{bid}: monitored component did not finish cleanly ({comp})")

    audit = traffic_log.summarize(bdir / "traffic_requests.jsonl", bdir / "traffic_intervals.jsonl", session_id=bid)
    for item in audit["problems"]:
        problems.append(f"{bid}: traffic log: {item}")
    if not audit["clean"]:
        problems.append(f"{bid}: traffic log not clean")
    requests = read_records(bdir / "traffic_requests.jsonl")
    intervals = read_records(bdir / "traffic_intervals.jsonl")
    header = requests[0] if requests and requests[0].get("type") == "header" else {}
    config = {k: (header.get("config") or {}).get(k) for k in cfg["traffic"]}
    if config != cfg["traffic"]:
        diff = {k: [config[k], cfg["traffic"][k]] for k in config if config[k] != cfg["traffic"][k]}
        problems.append(f"{bid}: traffic configuration differs from the run: {diff}")
    marks = {m["phase"]: m for m in audit["phase_markers"]}
    if "measure" not in marks or "post" not in marks:
        problems.append(f"{bid}: measured phase not delimited by phase markers")
        return None
    start, end = unix(marks["measure"]["t_utc"]), unix(marks["post"]["t_utc"])
    measured = audit["measure"]["phase_duration_s"]
    if abs(measured - cfg["measure_s"]) > MEASURE_TOLERANCE * cfg["measure_s"] + 2:
        problems.append(f"{bid}: measured phase {measured} s, planned {cfg['measure_s']} s")
    for key, recorded in (("measure_start_unix", start), ("measure_end_unix", end)):
        if key in status and abs(status[key] - recorded) > 2:
            problems.append(f"{bid}: {key} of block.json differs from the traffic phase marker")

    mon = host_monitor.summarize(bdir / "host_monitor.jsonl", start, end)
    for item in mon["problems"]:
        problems.append(f"{bid}: host monitor: {item}")
    if not mon["window_samples"]:
        problems.append(f"{bid}: no host-monitor samples in the measured phase")
    records = read_records(bdir / "host_monitor.jsonl")
    mheader = records[0] if records and records[0].get("type") == "header" else {}
    if mheader.get("session_id") != bid:
        problems.append(f"{bid}: host monitor session_id {mheader.get('session_id')!r}")
    samples = [r for r in records if r.get("type") == "sample" and start <= unix(r["t_utc"]) <= end]
    for label, expected in PRESENCE[block["condition"]].items():
        present = [bool((s.get("procs") or {}).get(label)) for s in samples]
        if expected and not all(present):
            problems.append(f"{bid}: {label} not running in {present.count(False)} of {len(present)} measured samples")
        if not expected and any(present):
            problems.append(f"{bid}: {label} running in {sum(present)} measured samples of an "
                            f"{block['condition']} block")
    clusters = clusters_of(requests, intervals, samples, run["cluster_intervals"])
    if len(clusters) < 2:
        problems.append(f"{bid}: fewer than two bootstrap clusters in the measured phase")
        return None
    data = BlockData(bid, clusters)
    report = {"block_id": bid, "condition": block["condition"], "repetition": block["repetition"],
              "position": block["position"], "measure_start_utc": marks["measure"]["t_utc"],
              "measure_end_utc": marks["post"]["t_utc"], "measure_duration_s": measured,
              "requests": audit["measure"]["requests"], "ok": audit["measure"]["ok"],
              "errors": audit["measure"]["errors"], "timeouts": audit["measure"]["timeout"],
              "latency_ok_ms": audit["measure"]["latency_ok_ms"], "clusters": len(clusters),
              "monitor_window_samples": mon["window_samples"], "host_monitor_max_gap_s": mon["max_gap_s"],
              "run_id": audit["run_id"]}
    if "prefault" in status:
        report["prefault"] = status["prefault"]
    return data, report


def as_float(x):
    return None if x is None or not math.isfinite(x) else round(float(x), 6)


def effects(values, blocks):
    """values[block_id] -> metric vector; returns {name: (estimate vector, base vector)}."""
    import numpy as np
    out = {}
    for condition in MONITORED:
        mine = [b for b in blocks if b["condition"] == condition]
        diffs = [values[b["block_id"]] - (values[b["flanks"][0]] + values[b["flanks"][1]]) / 2 for b in mine]
        bases = [(values[b["flanks"][0]] + values[b["flanks"][1]]) / 2 for b in mine]
        out[f"{condition}_minus_A"] = (np.mean(diffs, axis=0), np.mean(bases, axis=0))
    out["C_minus_B"] = (out["C_minus_A"][0] - out["B_minus_A"][0], out["B_minus_A"][1] + out["B_minus_A"][0])
    return out


def summarize(logdir, out, *, bootstrap=2000, seed=0, cluster_intervals=6, argv=None):
    import numpy as np
    logdir = Path(logdir)
    problems, inputs = [], {}
    for name in ("run.json", "run_end.json"):
        if not (logdir / name).is_file():
            problems.append(f"missing {name}")
    if problems:
        return refuse(problems)
    run = json.loads((logdir / "run.json").read_text())
    end = json.loads((logdir / "run_end.json").read_text())
    inputs["run.json"], inputs["run_end.json"] = sha256(logdir / "run.json"), sha256(logdir / "run_end.json")
    if run.get("schema") != RUN_SCHEMA or end.get("schema") != RUN_END_SCHEMA:
        return refuse(["run.json/run_end.json schema mismatch"])
    cfg = run["config"]
    planned = schedule(cfg["repetitions"], cfg.get("allow_unbalanced", False))
    if [(b["block_id"], b["condition"]) for b in planned] != \
            [(b["block_id"], b["condition"]) for b in run["plan"]["blocks"]]:
        problems.append("recorded plan differs from the schedule of its configuration")
    if not end.get("completed"):
        problems.append(f"run not completed: {end.get('error')}")
    if end.get("blocks_done") != [b["block_id"] for b in planned]:
        problems.append("completed blocks differ from the plan")
    if end.get("guest_after") != run.get("guest_before"):
        problems.append("guest identity changed during the run (reboot or software change)")
    present = sorted(p.name for p in (logdir / "blocks").iterdir()) if (logdir / "blocks").is_dir() else []
    extra = sorted(set(present) - {b["block_id"] for b in planned})
    if extra:
        problems.append(f"unplanned block directories: {extra}")
    run = dict(run, cluster_intervals=cluster_intervals)
    data, reports = {}, []
    for block in planned:
        loaded = load_block(logdir, block, run, problems, inputs)
        if loaded:
            data[block["block_id"]], report = loaded
            reports.append(report)
    if problems:
        return refuse(problems)

    original = {bid: d.metrics(np.arange(d.k)) for bid, d in data.items()}
    point = effects(original, planned)
    rng = np.random.default_rng(seed)
    draws = {name: [] for name in point}
    for _ in range(bootstrap):
        values = {bid: d.metrics(rng.integers(0, d.k, d.k)) for bid, d in data.items()}
        for name, (estimate, _base) in effects(values, planned).items():
            draws[name].append(estimate)

    differences = {}
    for name, (estimate, base) in point.items():
        matrix = np.array(draws[name])
        lo, hi = np.percentile(matrix, [2.5, 97.5], axis=0) if bootstrap else (estimate * math.nan,) * 2
        entry = {}
        for i, metric in enumerate(METRICS):
            entry[metric] = {"estimate": as_float(estimate[i]),
                             "relative_pct": as_float(100 * estimate[i] / base[i]) if base[i] else None,
                             "ci95": [as_float(lo[i]), as_float(hi[i])],
                             "ci_excludes_zero": bool(lo[i] > 0 or hi[i] < 0) if math.isfinite(lo[i]) else None}
        if name != "C_minus_B":
            condition = name[0]
            entry["per_triplet"] = [
                {"block_id": b["block_id"], "flanks": b["flanks"],
                 **{m: as_float(original[b["block_id"]][i] - (original[b["flanks"][0]][i]
                                                             + original[b["flanks"][1]][i]) / 2)
                    for i, m in enumerate(METRICS)}}
                for b in planned if b["condition"] == condition]
        differences[name] = entry

    conditions = {}
    for condition in CONDITIONS:
        mine = [data[b["block_id"]] for b in planned if b["condition"] == condition]
        pooled = BlockData(condition, [])
        for attr in ("lat",):
            setattr(pooled, attr, [x for d in mine for x in getattr(d, attr)])
        pooled.n, pooled.ok, pooled.dur = (np.concatenate([getattr(d, a) for d in mine]) for a in ("n", "ok", "dur"))
        pooled.sums = {m: np.concatenate([d.sums[m] for d in mine]) for m in SAMPLE_METRICS}
        pooled.counts = {m: np.concatenate([d.counts[m] for d in mine]) for m in SAMPLE_METRICS}
        values = pooled.metrics(np.arange(len(pooled.n)))
        conditions[condition] = {"description": CONDITIONS[condition], "blocks": len(mine),
                                 "requests": int(pooled.n.sum()), "measured_s": as_float(pooled.dur.sum()),
                                 **{m: as_float(values[i]) for i, m in enumerate(METRICS)},
                                 "note": "pooled over the condition's measured phases (descriptive)"}
    for report in reports:
        report.update({m: as_float(v) for m, v in zip(METRICS, original[report["block_id"]])})
    drift = []
    for rep in sorted({b["repetition"] for b in planned}):
        a_blocks = [b["block_id"] for b in planned if b["repetition"] == rep and b["condition"] == "A"]
        drift.append({"repetition": rep, "first_A": a_blocks[0], "last_A": a_blocks[-1],
                      **{m: as_float(original[a_blocks[-1]][i] - original[a_blocks[0]][i])
                         for i, m in enumerate(METRICS)}})

    commit, dirty = git_state()
    result = {"command": shlex.join(argv or ["python3", "-m", "experimenty.aba", "summarize", str(logdir),
                                             "--out", str(out)]),
              "commit": commit, "commit_dirty": dirty, "date": utc_now(), "host": run.get("host"),
              "guest": {"domain": cfg["domain"], "qemu": run.get("qemu"),
                        **{k: run.get("guest_before", {}).get(k) for k in ("kernel", "boot_id", "stack_sha256")}},
              "n": len(planned),
              "values": {
                  "schema": RESULT_SCHEMA, "experiment": "E5", "objective": "VO5",
                  "run": {"run_id": run.get("run_id"), "logdir": rel(logdir), "commit": run.get("commit"),
                          "commit_dirty": run.get("commit_dirty"), "measurement_dirty": run.get("measurement_dirty"),
                          "started_utc": run.get("started_utc"), "ended_utc": end.get("ended_utc"),
                          "command": run.get("command"), "collector_sha256": run.get("collector_sha256"),
                          "source_sha256": run.get("source_sha256"), "aba_sha256": run.get("aba_sha256")},
                  "config": cfg, "design": {k: run["plan"][k] for k in ("patterns", "pattern_order", "effect",
                                                                        "balance")},
                  "inputs_sha256": inputs,
                  "summarizer_sha256": sha256(Path(__file__)),
                  "definitions": {
                      "latency": "client-side duration_ms of every request started in the measured phase "
                                 "(host_traffic.py; failed requests included); exact nearest-rank percentiles",
                      "throughput_rps": "measured-phase requests / summed measured interval duration",
                      "host": "means of 1 s host_monitor.py samples inside the measured phase; disk MB/s summed "
                              "over the monitored whole disks; proc_cpu_*: 100 = one CPU, summed over the label's PIDs",
                      "difference": "X - (A_before + A_after) / 2 per triplet, averaged over the triplets of X; "
                                    "C_minus_B = (C - A) - (B - A); relative_pct against the mean flanking A",
                      "bootstrap": f"nonparametric cluster bootstrap, stratified by block: each block's measured "
                                   f"phase is cut into clusters of {cluster_intervals} consecutive "
                                   f"{SUMMARY_INTERVAL_S} s traffic intervals (requests and monitor samples "
                                   "together), clusters are resampled with replacement within every block, the "
                                   "whole statistic is recomputed; percentile 95 % CI",
                      "not_covered": "variation between repetitions is only in the per-triplet values; with few "
                                     "repetitions the CI reflects within-block variability"},
                  "bootstrap": {"resamples": bootstrap, "seed": seed, "cluster_intervals": cluster_intervals,
                                "rng": "numpy.random.default_rng(seed), resamples drawn block by block in run order"},
                  "blocks": reports, "conditions": conditions, "differences": differences, "drift_A": drift}}
    write_json(out, result)
    print(json.dumps({"out": str(out), "B_minus_A": {m: differences["B_minus_A"][m] for m in
                                                     ("latency_p95_ms", "throughput_rps", "cpu_busy_pct")},
                      "C_minus_A": {m: differences["C_minus_A"][m] for m in
                                    ("latency_p95_ms", "throughput_rps", "cpu_busy_pct")}}, indent=2))
    return 0


def refuse(problems):
    print(json.dumps({"refused": True, "problems": problems}, indent=2), file=sys.stderr)
    return 2


# --- CLI ------------------------------------------------------------------------------------

def add_design(p):
    p.add_argument("--repetitions", type=int, default=DEFAULTS["repetitions"])
    p.add_argument("--allow-unbalanced", action="store_true", help="permit an odd number of repetitions")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    add_design(sub.add_parser("plan", help="print the counterbalanced schedule"))
    r = sub.add_parser("run", help="orchestrate the A/B/A run")
    mode = r.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    r.add_argument("--out", type=Path, required=True, help="new run directory (refused if it exists)")
    add_design(r)
    r.add_argument("--protocol", default=DEFAULTS["protocol"], help="must be the bundle's protocol for condition C")
    r.add_argument("--scenario", default=DEFAULTS["scenario"], help="traffic scenario of the protocol")
    r.add_argument("--traffic-seed", type=int, default=DEFAULTS["traffic_seed"])
    r.add_argument("--warmup-s", type=float, default=DEFAULTS["warmup_s"])
    r.add_argument("--measure-s", type=float, default=DEFAULTS["measure_s"])
    r.add_argument("--rest-s", type=float, default=DEFAULTS["rest_s"])
    r.add_argument("--bundle", default=DEFAULTS["bundle"])
    r.add_argument("--profile", help="guest profile (default: the protocol's)")
    r.add_argument("--vm", help="VM under test; required for (and only for) a protocol that lists vms")
    r.add_argument("--domain", help="default: the protocol's")
    r.add_argument("--target", help="default: the protocol's")
    r.add_argument("--threads", type=int, default=DEFAULTS["threads"], help="safeguard --threads")
    r.add_argument("--collector", default=DEFAULTS["collector"])
    s = sub.add_parser("summarize", help="offline result from a recorded run directory")
    s.add_argument("logdir", type=Path)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--bootstrap", type=int, default=2000)
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--cluster-intervals", type=int, default=6, help="traffic intervals per bootstrap cluster")
    a = ap.parse_args(argv)
    try:
        if a.command == "plan":
            print(json.dumps(plan_doc({"repetitions": a.repetitions, "allow_unbalanced": a.allow_unbalanced,
                                       "warmup_s": DEFAULTS["warmup_s"], "measure_s": DEFAULTS["measure_s"],
                                       "rest_s": DEFAULTS["rest_s"]}), indent=2))
            return 0
        if a.command == "run":
            cfg = make_config(a)
            schedule(cfg["repetitions"], cfg["allow_unbalanced"])
            return dry_run(cfg, a.out) if a.dry_run else execute(cfg, a.out)
        if a.bootstrap < 0 or a.cluster_intervals < 1:
            ap.error("--bootstrap must be >= 0 and --cluster-intervals >= 1")
        if a.out.exists():
            ap.error(f"{a.out} exists; results are written exclusively")
        return summarize(a.logdir, a.out, bootstrap=a.bootstrap, seed=a.seed, cluster_intervals=a.cluster_intervals,
                         argv=["python3", "-m", "experimenty.aba", *(argv if argv is not None else sys.argv[1:])])
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print(f"aba: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
