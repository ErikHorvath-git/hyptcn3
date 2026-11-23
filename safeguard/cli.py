"""Host CLI for fitting, replaying and running the shared safeguard pipeline."""
import argparse
import json
from pathlib import Path
import sys

from features.quality import invalid_rows_rule, tolerated_input_errors
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
    # The analysis parameters (package B6b, safeguard/training.py OPTIONS) are not given by default. Under protocol
    # schema 3 the analysis plan of the protocol states them and a given one is refused unless --diagnostic (a
    # planned seed of analysis.seeds is a choice); schemas 1 and 2 keep legacy_schema_2 (today's values).
    for option, kind in (("--epochs", int), ("--batch-size", int), ("--seed", int), ("--fpr", float), ("--k", int),
                         ("--n", int)):
        train.add_argument(option, type=kind, default=None,
                           help="analysis parameter, not given by default: protocol schema 3 takes it from its "
                                "analysis plan and refuses it outside --diagnostic; schemas 1 and 2 keep today's "
                                "value (legacy_schema_2, safeguard/training.py LEGACY_VALUES)")
    train.add_argument("--diagnostic", action="store_true",
                       help="mark bundle diagnostic; never silently deploy it; under protocol schema 3 the only way "
                            "to override an analysis parameter (the manifest lists each override)")
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
            command.add_argument("--protocol", type=Path, default=ROOT / "config/collection-v2.json")
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
        # None (not given) passes through: train_bundle decides by the protocol of the corpus.
        return train_bundle(a.corpus, a.out, window_rows=protocol["window_rows"],
                            max_gap_s=protocol["max_gap_s"], epochs=a.epochs,
                            batch_size=a.batch_size, seed=a.seed, fpr=a.fpr,
                            k=a.k, n=a.n, diagnostic=a.diagnostic)
    if a.command == "replay" and a.archive:
        # The seal (package B7c, tcn/pecat.py) before the bundle is loaded or anything is written: a sealed archive of
        # a campaign is refused by name outside the final run that consumed its seal (exit 2, no output directory).
        from tcn import pecat
        pecat.kontrola(a.archive, purpose="safeguard replay --archive")
    elif a.command in ("replay", "watch"):
        # The raw snapshots of a session likewise, by the session its session.json names (tcn/pecat.py SNAPSHOT_RULE);
        # run_directory checks them again before it writes.
        from tcn import pecat
        pecat.kontrola_snimok(a.snapshots, purpose=f"safeguard {a.command} --snapshots")
    bundle = load_bundle(a.bundle, allow_diagnostic=getattr(a, "allow_diagnostic", False))
    if a.command == "inspect":
        return bundle.manifest
    if a.command == "run":
        from .supervisor import supervise
        return supervise(bundle, a.protocol, a.profile, a.domain, a.out, cycles=a.cycles)
    if a.command == "replay" and a.archive:
        return replay_directory(bundle, a.archive, a.out)
    from .supervisor import _termination_handlers
    with _termination_handlers():
        return run_directory(bundle, a.snapshots, a.profile, a.out,
                             follow=a.command == "watch", preserve=a.command == "watch",
                             idle_timeout=getattr(a, "idle_timeout", None),
                             hold_binary=str(ROOT / "vmicollect/build/vmicollect"))


def replay_directory(bundle, archive, out):
    """`safeguard replay --archive` of a loaded bundle into the new directory `out`: configuration.json (with the
    archive's sha256 and the seal's decision, tcn/pecat.py kontrola: a rehearsal's archive carries the rehearsal
    mark), events.jsonl, evidence/ and status.json (with the unscored stretches, safeguard.runtime.unscored: each
    nevyhodnotené); returns the status. The seal is checked first, before anything is written (package B7c): the final
    command (python -m tcn.finalne) replays the sealed archives of its run through this function in its process."""
    from tcn import pecat
    from .demo import write_json
    from .runtime import unscored
    archive, out = Path(archive), Path(out)
    seal = pecat.kontrola(archive, purpose="safeguard replay --archive")
    # The verdict below applies the invalid_rows rule of the bundle's protocol; a malformed rule ends the
    # replay before it writes anything.
    protocol = bundle.manifest.get("provenance", {}).get("protocol") or {}
    invalid_rows_rule(protocol)
    out.mkdir(parents=True, exist_ok=False)
    (out / "evidence").mkdir()
    write_json(out / "configuration.json", {"schema": "hyptcn3/safeguard-configuration/1",
               "bundle_manifest": bundle.manifest, "archive": str(archive.resolve()),
               "archive_sha256": seal["sha256"], "seal": seal, "preserve": False, "follow": False})
    try:
        rows = replay_archive(bundle, archive)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        write_json(out / "status.json", {"schema": "hyptcn3/safeguard-run/1",
                   "running": False, "state": "input_error", "ok": False,
                   "diagnostic": bundle.manifest["diagnostic"], "error": str(exc)})
        raise
    with (out / "events.jsonl").open("x") as stream:
        event_number = 0
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
            if row["alarm_event"]:
                event_number += 1
                write_json(out / "evidence" / f"event-{event_number:06d}.json", row)
    result = {"schema": "hyptcn3/safeguard-run/1", "diagnostic": bundle.manifest["diagnostic"],
              "running": False, "processed": len(rows),
              "scored": sum(r["score"] is not None for r in rows),
              "input_errors": sum(r["model_state"] == "input_error" for r in rows),
              "alarm_events": sum(r["alarm_event"] for r in rows),
              "fatal": any(r["fatal"] for r in rows), "stop_reason": "replay_complete",
              "state": rows[-1]["state"] if rows else "input_error", "last": rows[-1] if rows else None}
    # An input error that is only a row the bundle protocol's invalid_rows rule tolerates does not fail the replay.
    tolerated = tolerated_input_errors(rows, protocol)
    result["tolerated_invalid_rows"] = len(tolerated or [])
    result["ok"] = bool(rows) and tolerated is not None
    result["unscored"] = unscored(rows, protocol.get("interval_s"))
    result["seal"] = {key: seal[key] for key in ("allowed", "stage", "rehearsal", "mark", "identity")}
    write_json(out / "status.json", result)
    return result


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
