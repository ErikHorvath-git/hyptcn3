"""Host CLI for fitting, replaying and running the shared safeguard pipeline."""
import argparse
import json
from pathlib import Path
import sys

from .bundle import load_bundle
from .runtime import replay_archive, run_directory

ROOT = Path(__file__).resolve().parents[1]


def parser():
    p = argparse.ArgumentParser(description="Host-side TCN and kernel-integrity safeguard")
    p.add_argument("--threads", type=int, default=4, help="CPU threads for PyTorch (default: 4)")
    sub = p.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train", help="fit train, select dev, threshold calibration; test remains held out")
    train.add_argument("--corpus", required=True, type=Path)
    train.add_argument("--out", required=True, type=Path)
    train.add_argument("--epochs", type=int, default=10)
    train.add_argument("--batch-size", type=int, default=32)
    train.add_argument("--seed", type=int, default=0)
    train.add_argument("--fpr", type=float, default=0.01)
    train.add_argument("--k", type=int, default=3)
    train.add_argument("--n", type=int, default=5)
    train.add_argument("--diagnostic", action="store_true", help="mark bundle diagnostic; never silently deploy it")
    for name in ("inspect", "replay", "watch", "run"):
        command = sub.add_parser(name)
        command.add_argument("--bundle", required=True, type=Path)
        if name != "run":
            command.add_argument("--allow-diagnostic", action="store_true")
        if name != "inspect":
            command.add_argument("--out", required=True, type=Path, help="new output directory; never overwrite")
        if name in ("replay", "watch", "run"):
            command.add_argument("--profile", type=Path, default=ROOT / "profiles/debian12-6.1.0-42-cloud-amd64")
        if name == "replay":
            source = command.add_mutually_exclusive_group(required=True)
            source.add_argument("--archive", type=Path)
            source.add_argument("--snapshots", type=Path)
        if name == "watch":
            command.add_argument("--snapshots", required=True, type=Path)
            command.add_argument("--idle-timeout", type=float)
        if name == "run":
            command.add_argument("--protocol", type=Path, default=ROOT / "config/collection-v1.json")
            command.add_argument("--domain", default="hyptcn-lab")
            command.add_argument("--cycles", type=int)
    status = sub.add_parser("status")
    status.add_argument("--out", required=True, type=Path)
    demo = sub.add_parser("smoke", help="synthetic train/save/load/replay, no live VM or malware")
    demo.add_argument("--out", required=True, type=Path)
    return p


def execute(a):
    if a.command == "status":
        completed = a.out / "result.json"
        if completed.is_file():
            return json.loads(completed.read_text())
        path = a.out / "detector/status.json"
        if not path.is_file():
            path = a.out / "status.json"
        return json.loads(path.read_text())
    import torch
    torch.set_num_threads(a.threads)
    if a.command == "smoke":
        from .demo import smoke
        return smoke(a.out)
    if a.command == "train":
        from .training import train_bundle
        index = json.loads(a.corpus.read_text())
        protocol = index["protocol_config"]
        return train_bundle(a.corpus, a.out, window_rows=protocol["window_rows"],
                            max_gap_s=protocol["max_gap_s"], epochs=a.epochs,
                            batch_size=a.batch_size, seed=a.seed, fpr=a.fpr,
                            k=a.k, n=a.n, diagnostic=a.diagnostic)
    bundle = load_bundle(a.bundle, allow_diagnostic=getattr(a, "allow_diagnostic", False))
    if a.command == "inspect":
        return bundle.manifest
    if a.command == "run":
        from .supervisor import supervise
        return supervise(bundle, a.protocol, a.profile, a.domain, a.out, cycles=a.cycles)
    if a.command == "replay" and a.archive:
        from .demo import write_json
        a.out.mkdir(parents=True, exist_ok=False)
        (a.out / "evidence").mkdir()
        write_json(a.out / "configuration.json", {"schema": "hyptcn3/safeguard-configuration/1",
                   "bundle_manifest": bundle.manifest, "archive": str(a.archive.resolve()),
                   "preserve": False, "follow": False})
        try:
            rows = replay_archive(bundle, a.archive)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            write_json(a.out / "status.json", {"schema": "hyptcn3/safeguard-run/1",
                       "running": False, "state": "input_error", "ok": False,
                       "diagnostic": bundle.manifest["diagnostic"], "error": str(exc)})
            raise
        with (a.out / "events.jsonl").open("x") as stream:
            event_number = 0
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
                if row["alarm_event"]:
                    event_number += 1
                    write_json(a.out / "evidence" / f"event-{event_number:06d}.json", row)
        result = {"schema": "hyptcn3/safeguard-run/1", "diagnostic": bundle.manifest["diagnostic"],
                  "running": False, "processed": len(rows),
                  "scored": sum(r["score"] is not None for r in rows),
                  "input_errors": sum(r["model_state"] == "input_error" for r in rows),
                  "alarm_events": sum(r["alarm_event"] for r in rows),
                  "fatal": any(r["fatal"] for r in rows), "stop_reason": "replay_complete",
                  "state": rows[-1]["state"] if rows else "input_error", "last": rows[-1] if rows else None}
        result["ok"] = bool(rows) and not result["input_errors"]
        write_json(a.out / "status.json", result)
        return result
    from .supervisor import _termination_handlers
    with _termination_handlers():
        return run_directory(bundle, a.snapshots, a.profile, a.out,
                             follow=a.command == "watch", preserve=a.command == "watch",
                             idle_timeout=getattr(a, "idle_timeout", None),
                             hold_binary=str(ROOT / "vmicollect/build/vmicollect"))


def main(argv=None):
    p = parser()
    a = p.parse_args(argv)
    if a.threads < 1:
        p.error("--threads must be positive")
    try:
        result = execute(a)
    except KeyboardInterrupt:
        print("Safeguard stopped; inspect the output status and collector log.", file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"safeguard: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if result.get("ok", True) else 2
