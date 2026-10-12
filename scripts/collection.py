#!/usr/bin/env python3
"""Plan, capture and audit benign research sessions. Never runs attack samples.

Original protocol tooling for hyptcn3. Data and verdicts are written exclusively;
failed sessions remain on disk. Run audit again with a new output name.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.contract import validate_sidecar
from features.archive import load, save
from features.snapshot import retazec, MENA
from features.windows import okna, snimky_z_matice
from features.perbin import FeatureError
from features.windows import WindowError

DEFAULT = ROOT / "config/collection-v1.json"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, doc):
    with Path(path).open("x") as stream:
        json.dump(doc, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def protocol(path):
    p = json.loads(Path(path).read_text())
    if p["schema"] != "hyptcn3/collection-protocol/1":
        raise ValueError("unsupported protocol")
    for key in ("interval_s", "window_rows", "full_every", "cycles", "pilot_cycles", "bin_bytes"):
        if type(p[key]) is not int or p[key] < 1:
            raise ValueError("invalid " + key)
    if not p["interval_s"] < p["max_gap_s"] < 2 * p["interval_s"]:
        raise ValueError("gap must distinguish a missed sampling slot")
    if p["full_every"] <= p["window_rows"] or p["pilot_cycles"] <= p["full_every"] + p["window_rows"]:
        raise ValueError("pilot must cover two full snapshots and score after both")
    if p["bin_bytes"] != 16777216:
        raise ValueError("capture runner currently supports 16 MiB bins")
    return p


def plan(p):
    result = []
    # Each role/repetition is a separate boot group. Adjacent chunks of a
    # running VM cannot become independent train/calibration/test sessions.
    for role, count in p["roles"].items():
        for repetition in range(count):
            scenarios = list(p["scenarios"])
            seed = int.from_bytes(hashlib.sha256(f"{role}/{repetition}".encode()).digest()[:4], "big")
            random.Random(seed).shuffle(scenarios)
            for scenario in scenarios:
                result.append({"role": role, "group": f"{role}-{repetition + 1}",
                               "scenario": scenario, "seed": seed + len(result),
                               "cycles": p["cycles"]})
    return {"schema": "hyptcn3/collection-plan/1", "sessions": result,
            "planned_hours": len(result) * p["cycles"] * p["interval_s"] / 3600,
            "note": "Design allocation, not collected data; pilot and overhead runs are separate."}


def user_command(command):
    user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and user:
        import pwd
        uid = pwd.getpwnam(user).pw_uid
        return ["runuser", "-u", user, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}", *map(str, command)]
    return list(map(str, command))


def guest_identity(p):
    identity_command = (
        "uname -r; cat /proc/sys/kernel/random/boot_id; cat /etc/machine-id; "
        "sha256sum /opt/hyptcn-lab/services.py /opt/hyptcn-lab/schema.sql "
        "/etc/nginx/conf.d/hyptcn-lab.conf /etc/systemd/system/hyptcn-lab@.service && "
        "dpkg-query -W nginx postgresql python3 python3-psycopg2")
    command = [sys.executable, ROOT / "scripts/labctl.py", "exec", "--domain", p["domain"],
               "--guest-command", identity_command]
    lines = subprocess.check_output(user_command(command), cwd=ROOT, text=True).strip().splitlines()
    if len(lines) < 11:
        raise ValueError("cannot establish guest identity")
    return {**dict(zip(("kernel", "boot_id", "machine_id"), lines[:3])),
            "stack_sha256": hashlib.sha256("\n".join(lines[3:]).encode()).hexdigest(),
            "stack_manifest": lines[3:]}


def run_session(a, p):
    if os.geteuid() != 0:
        raise ValueError("host eBPF capture needs sudo; plan and audit do not")
    if a.scenario not in p["scenarios"]:
        raise ValueError("unknown benign scenario")
    base = ROOT / "data/collections"
    base.mkdir(parents=True, exist_ok=True)
    with (base / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = guest_identity(p)
        if a.role != "pilot":
            assignment = {"role": a.role, "group": a.group, "scenario": a.scenario,
                          "seed": a.seed, "cycles": p["cycles"]}
            if assignment not in plan(p)["sessions"]:
                raise ValueError("assignment/seed not present in frozen collection plan")
            if not a.pilot_report:
                raise ValueError("corpus capture requires --pilot-report from an accepted pilot audit")
            report = json.loads(Path(a.pilot_report).read_text())
            if (not report["values"]["accepted"] or report["values"].get("role") != "pilot"
                    or report["values"]["protocol_sha256"] != digest(a.protocol)):
                raise ValueError("pilot report is not accepted for this protocol")
            needed = report["values"]["raw_bytes"] * p["cycles"] / p["pilot_cycles"] * 1.5
        else:
            needed = 0
        if shutil.disk_usage(base).free < needed + p["min_free_gib"] * 2**30:
            raise ValueError("insufficient disk budget; archive existing captures first")
        # Scan immutable start records, including unfinished/failed runs.
        for path in base.glob("*/session.json"):
            old = json.loads(path.read_text())
            if old["guest_before"]["boot_id"] == before["boot_id"] and old["role"] != a.role:
                raise ValueError("same guest boot already belongs to role " + old["role"])
            if old["group"] == a.group and old["role"] != a.role:
                raise ValueError("group already belongs to a different split")
            if ((old["guest_before"]["boot_id"] == before["boot_id"]) != (old["group"] == a.group)):
                if old["group"] == a.group or old["guest_before"]["boot_id"] == before["boot_id"]:
                    raise ValueError("one boot must correspond to exactly one collection group")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        out = base / f"{stamp}_{a.role}_{a.scenario}"
        out.mkdir()
        shutil.copyfile(a.protocol, out / "protocol.json")
        prof = ROOT / p["profile"]
        shutil.copytree(prof, out / "profile")
        source_files = [f for directory in ("features", "guestparse", "scripts", "lab", "vmicollect")
                        for f in (ROOT / directory).rglob("*")
                        if f.is_file() and f.suffix in (".py", ".c", ".h", ".sh", ".sql", ".conf", ".service")]
        source_hashes = {str(f.relative_to(ROOT)): digest(f) for f in source_files}
        subprocess.run(user_command(["make", "-C", ROOT / "vmicollect"]), check=True)
        metadata = {"schema": "hyptcn3/collection-session/1", "session_id": out.name,
                    "role": a.role, "group": a.group, "scenario": a.scenario,
                    "typ": "benign", "seed": a.seed, "guest_before": before,
                    "protocol_sha256": digest(a.protocol), "source_sha256": source_hashes,
                    "profile_sha256": {str(f.relative_to(prof)): digest(f) for f in prof.rglob("*") if f.is_file()},
                    "collector_sha256": digest(ROOT / "vmicollect/build/vmicollect"),
                    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                    "host": platform.platform(), "created_unix": time.time()}
        write_json(out / "session.json", metadata)
        subprocess.run(user_command(["virsh", "-c", "qemu:///session", "dumpxml", p["domain"]]),
                       stdout=(out / "domain.xml").open("x"), check=True)
        print(f"session: {out}", flush=True)
        traffic = collector = None
        status = {"completed": False}
        def interrupted(signum, _frame):
            raise InterruptedError(f"signal {signum}")
        old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            # Stop only the generator managed by this project; the VM stays up.
            subprocess.run(user_command([sys.executable, ROOT / "scripts/labctl.py", "traffic-stop"]), check=True)
            s = p["scenarios"][a.scenario]
            traffic_command = [sys.executable, ROOT / "scripts/host_traffic.py", "--profile", "lab",
                               "--target", p["target"], "--dur", "0", "--seed", str(a.seed),
                               "--vlakien", str(s["workers"]), "--burst", str(s["burst"]),
                               "--catalog-share", str(s["catalog_share"]), "--write-share", str(s["write_share"]),
                               "--out", str(out / "traffic.json")]
            with (out / "traffic.log").open("x") as log:
                traffic = subprocess.Popen(traffic_command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            time.sleep(p["warmup_s"])
            metrics = json.loads((out / "traffic.json").read_text())
            if traffic.poll() is not None or not metrics["ok"] or metrics["errors"]:
                raise ValueError("warmup traffic failed")
            write_json(out / "traffic_before.json", metrics)
            env = dict(os.environ, VMIC_DOMAIN=p["domain"], VMIC_INTERVAL=str(p["interval_s"]),
                       VMIC_FULL_EVERY=str(p["full_every"]), VMIC_OUT=str(out / "raw"))
            cycles = p["pilot_cycles"] if a.role == "pilot" else p["cycles"]
            status["capture_started_unix"] = time.time()
            with (out / "capture.log").open("x") as log:
                collector = subprocess.Popen(["bash", "scripts/lab_capture.sh", str(cycles)],
                                             env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            while collector.poll() is None:
                if traffic.poll() is not None:
                    raise ValueError("traffic generator exited during capture")
                if shutil.disk_usage(out).free < p["min_free_gib"] * 2**30:
                    raise ValueError("disk reserve reached; preserving partial session")
                time.sleep(1)
            status["capture_finished_unix"] = time.time()
            status["collector_rc"] = collector.returncode
            if collector.returncode:
                raise ValueError("collector failed; see capture.log")
            status["guest_after"] = guest_identity(p)
            if status["guest_after"] != before:
                raise ValueError("guest rebooted or changed during capture")
            status["completed"] = True
        except BaseException as exc:
            status["error"] = str(exc)
            raise
        finally:
            for process in (collector, traffic):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            write_json(out / "end.json", status)
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
            if "SUDO_UID" in os.environ:
                for path in [out, *out.rglob("*")]:
                    os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        print(f"Audit: python3 scripts/collection.py audit {out}")


def audit_session(directory, p, protocol_path, output=None):
    directory = Path(directory).resolve()
    native = (directory / "session.json").exists()
    raw = directory / "raw" if native else directory
    metadata = json.loads((directory / "session.json").read_text()) if native else {}
    reasons = []
    if not native:
        reasons.append("historical capture without protocol/session provenance; exploratory only")
    elif metadata["protocol_sha256"] != digest(protocol_path):
        reasons.append("protocol hash mismatch")
    end = json.loads((directory / "end.json").read_text()) if native and (directory / "end.json").exists() else {}
    if native and (not end.get("completed") or end.get("guest_after") != metadata["guest_before"]):
        reasons.append("incomplete capture or changed guest identity")
    if native:
        hashes = {str(f.relative_to(directory / "profile")): digest(f)
                  for f in (directory / "profile").rglob("*") if f.is_file()}
        if hashes != metadata["profile_sha256"]:
            reasons.append("kernel profile changed since capture")
        capture = json.loads((raw / "capture.json").read_text())
        if (capture["values"]["collector_sha256"] != metadata["collector_sha256"]
                or capture["values"]["full_every"] != p["full_every"]
                or capture["values"]["interval_s"] != p["interval_s"]):
            reasons.append("collector binary or temporal settings mismatch")
    sidecars = []
    for path in raw.glob("*.json"):
        doc = json.loads(path.read_text())
        if doc.get("schema") == "vmicollect/1":
            validate_sidecar(doc)
            if doc["features"]["bin_bytes"] != p["bin_bytes"]:
                reasons.append("bin width differs from protocol")
            sidecars.append((path, doc))
    sidecars.sort(key=lambda item: item[1]["seq"])
    if not sidecars:
        raise ValueError("no collector sidecars")
    if len(list(raw.glob("*.vmicd"))) != len(sidecars):
        reasons.append("image/sidecar count mismatch")
    expected = p["pilot_cycles"] if metadata.get("role") == "pilot" else p["cycles"]
    if len(sidecars) != expected:
        reasons.append("snapshot count differs from assigned protocol")
    if [d["seq"] for _, d in sidecars] != list(range(len(sidecars))):
        reasons.append("sequence must start at zero and be contiguous")
    source_hashes = {}
    total_bytes = 0
    for path, side in sidecars:
        image = path.with_suffix(".vmicd")
        sha = digest(image)
        source_hashes[image.name] = sha
        source_hashes[path.name] = digest(path)
        total_bytes += image.stat().st_size
        if native and side["output"]["full"] != (side["seq"] % p["full_every"] == 0):
            reasons.append("full snapshot cadence differs from protocol")
        if native and side["output"].get("sha256") != sha:
            reasons.append("image checksum mismatch: " + image.name)
        if side["stats"]["read_errors"] or side["stats"]["filled_zero"] or side["sched"]["skipped_before"]:
            reasons.append("read errors/fill/missed slots: " + image.name)
        if side["capture"]["total_ms"] >= p["interval_s"] * 1000:
            reasons.append("collector cycle exceeded period")
    result = retazec(str(raw), str(directory / "profile" if native else ROOT / p["profile"]), p["max_gap_s"])
    rows = snimky_z_matice(directory.name, result["matica"], MENA, result["casy"], result["seq"], result["valid"])
    windows = okna(rows, dlzka=p["window_rows"], max_medzera_s=p["max_gap_s"])
    if not all(result["valid"]):
        reasons.append("incomplete object traversal or model-input integrity checks")
    coverage = len(windows) / len(rows)
    if coverage < .85:
        reasons.append("score coverage below design gate 0.85")
    if any(b - a != 1 for a, b in zip(result["seq"], result["seq"][1:])):
        reasons.append("sequence gap")
    if any(not 0 < b - a <= p["max_gap_s"] for a, b in zip(result["casy"], result["casy"][1:])):
        reasons.append("timestamp gap")
    span = result["casy"][-1] - result["casy"][0]
    if abs(span - (len(rows) - 1) * p["interval_s"]) > p["interval_s"]:
        reasons.append("sampling period differs from protocol")
    if native:
        before = json.loads((directory / "traffic_before.json").read_text())
        after = json.loads((directory / "traffic.json").read_text())
        if after["started_at"] != before["started_at"] or after["ok"] <= before["ok"] or after["errors"] != before["errors"]:
            reasons.append("traffic failed or no successful requests during capture")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = Path(output).resolve() if output else directory / f"audit_{stamp}.json"
    feature_path = output.with_suffix(".npz")
    save(feature_path, result)
    values = {"accepted": not reasons, "reasons": sorted(set(reasons)),
              "role": metadata.get("role"), "protocol_sha256": digest(protocol_path),
              "snapshots": len(rows), "windows": len(windows), "score_coverage": coverage,
              "raw_bytes": total_bytes, "source_sha256": source_hashes,
              "session_sha256": digest(directory / "session.json") if native else None,
              "extractor_sha256": {str(f.relative_to(ROOT)): digest(f)
                                    for d in ("features", "guestparse") for f in (ROOT / d).rglob("*.py")
                                    if "tests" not in f.parts},
              "features": str(feature_path), "features_sha256": digest(feature_path),
              "layout": result["layout"], "session_dir": str(directory),
              "text_integrity_inconclusive_rows": sum("text_integrity" in q["inconclusive"] for q in result["quality"]),
              "feature_extraction_s": result["trvanie_s"],
              "note": "Offline feature audit. Does not certify live scoring latency, integrity baseline or detection."}
    report = {"schema": "hyptcn3/collection-audit/1", "date": datetime.now(timezone.utc).isoformat(),
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "commit_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "host": platform.platform(), "guest": metadata.get("guest_before"),
              "command": " ".join(sys.argv), "n": len(rows), "values": values}
    write_json(output, report)
    print(json.dumps({"report": str(output), **{k: values[k] for k in
                     ("accepted", "reasons", "snapshots", "windows", "score_coverage", "raw_bytes")}}, indent=2))
    return 0 if values["accepted"] else 2


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--protocol", type=Path, default=DEFAULT)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    run = sub.add_parser("run")
    run.add_argument("--role", choices=["pilot", "train", "dev", "calibration", "test_benign"], required=True)
    run.add_argument("--scenario", default="steady")
    run.add_argument("--group", required=True)
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--pilot-report", type=Path)
    audit = sub.add_parser("audit")
    audit.add_argument("directory", type=Path)
    audit.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    p = protocol(a.protocol)
    if a.command == "plan":
        print(json.dumps(plan(p), indent=2))
        return 0
    if a.command == "run":
        run_session(a, p)
        return 0
    return audit_session(a.directory, p, a.protocol, a.out)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, FeatureError, WindowError, subprocess.SubprocessError) as error:
        print(f"collection: {error}", file=sys.stderr)
        sys.exit(2)
