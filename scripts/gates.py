#!/usr/bin/env python3
"""Readiness stages of protocol v5: one record per stage, each stage needs the ones before it.

  python3 scripts/gates.py status  --protocol P
  python3 scripts/gates.py require G2 --protocol P     exit 2 unless G0 and G1 have valid records
  python3 scripts/gates.py record  G1 --protocol P --criteria C.json --verification V.json --command "..."

A stage has passed when its newest record
  - names this protocol file and the current measurement code by sha256 (a documentation
    commit does not invalidate a stage, a change of measurement code or protocol does);
    stages G0 to G3b hash the protocol without the values that its determined_at assigns to
    later stages, so determining such a value keeps them valid, and G4 to G6 hash the file's
    bytes (stage_binding),
  - lists exactly the criteria of the stage (CRITERIA below), each passed with evidence,
  - carries an independent verification in which every criterion is confirmed.
The tool keeps the chain honest. What a criterion means is written in
docs/NAVRH_PROTOKOL_V5.sk.md (chapter 10) and docs/HARNESS_V5.sk.md; the evidence is produced
by the commands named there, never typed in by hand.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import collection  # noqa: E402

SCHEMA = "hyptcn3/gate-record/1"
STAGES = ("G0", "G1", "G2", "G3a", "G3b", "G4", "G5", "G6")
# Criteria per stage. A record must list exactly these keys; adding a criterion here
# invalidates older records of that stage on purpose.
CRITERIA = {
    "G0": ("tests", "protocol_selfcheck", "audit_selftest", "corpus_to_training", "analysis_plan_bound",
           "test_sealed", "audit_probes_reproduced"),
    "G1": ("chain_end_to_end", "null_generator", "structured_generator", "diagnostics_controls",
           "marginal_change", "unscored_spans", "fault_injections"),
    "G2": ("guest_matches_repository", "event_effects", "restart_loops_bounded", "marked_rows_per_event",
           "profiles_load", "traffic_realism", "ground_truth_under_load", "controls_paired",
           "live_fault_injections", "worst_case_timing", "live_archive_parity"),
    "G3a": ("campaign_shaped_run", "feature_qualification", "changes_logged"),
    "G3b": ("candidate_commit_untouched", "chain_end_to_end", "replacement_limit", "no_unexplained_periodicity",
            "audit_bounds_hold", "owner_decision"),
    "G4": ("tag", "protocol_and_plan_hashed", "preregistration_pushed", "deviation_log_open"),
    "G5": ("plan_complete", "stop_rules", "campaign_record"),
    "G6": ("single_final_run", "report", "claims_check"),
}
VERDICTS = ("confirmed", "refuted", "unverifiable")
# What a record's protocol_sha256 is the hash of; the record names it as protocol_hash_rule.
BYTES_RULE = "sha256 of the file bytes"
STAGE_RULE = ("sha256 of the UTF-8 of json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False) of the "
              "protocol without the paths that determined_at assigns to stages after {stage}")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(doc):
    """The canonical JSON of a protocol document, as STAGE_RULE names it."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def later_paths(determined_at, stage):
    """The paths (lists of keys) that determined_at assigns to stages after `stage`.

    Refuses a determined_at under which a record could stop binding a value of its own or an
    earlier stage: one that does not map stage names to lists of dotted paths, a path that starts
    at determined_at itself or with '*', and a path that would delete a path of an earlier stage.
    """
    if type(determined_at) is not dict or any(
            name not in STAGES or type(paths) is not list
            or not all(type(path) is str and all(path.split(".")) for path in paths)
            for name, paths in determined_at.items()):
        raise ValueError("determined_at must map stage names to lists of dotted paths")
    found = [(STAGES.index(name), name, path, path.split("."))
             for name, paths in determined_at.items() for path in paths]
    for order, name, path, keys in found:
        if keys[0] in ("*", "determined_at"):
            raise ValueError("determined_at path must start with a protocol key other than determined_at: " + path)
        for earlier, earlier_name, other, other_keys in found:
            if earlier < order and len(keys) <= len(other_keys) and all(
                    a == b or "*" in (a, b) for a, b in zip(keys, other_keys)):
                raise ValueError(f"determined_at path {path} ({name}) would delete {other} ({earlier_name})")
    return [keys for order, _, _, keys in found if order > STAGES.index(stage)]


def delete_path(node, keys):
    """Delete from `node` the keys that the path `keys` names; '*' stands for every key of an object."""
    if type(node) is dict:
        for name in list(node) if keys[0] == "*" else [keys[0]] if keys[0] in node else []:
            if len(keys) > 1:
                delete_path(node[name], keys[1:])
            else:
                del node[name]


def stage_binding(protocol_path, stage):
    """(sha256, rule) with which a record of `stage` binds the protocol file.

    G0 to G3b hash the canonical JSON of the document without the paths that its determined_at
    assigns to a later stage (the keys deleted), so filling or changing a value of a later stage
    keeps them valid, while every other change, determined_at itself included, reopens them.
    G4 to G6 hash the file's bytes, as does every stage of a document without determined_at
    (schemas 1 and 2) and of a file that is not a JSON object.
    """
    if stage not in STAGES:
        raise ValueError("unknown stage: " + str(stage))
    data = Path(protocol_path).read_bytes()
    try:
        doc = json.loads(data)
    except ValueError:
        doc = None
    if type(doc) is not dict or "determined_at" not in doc or STAGES.index(stage) >= STAGES.index("G4"):
        return hashlib.sha256(data).hexdigest(), BYTES_RULE
    for keys in later_paths(doc["determined_at"], stage):
        delete_path(doc, keys)
    return hashlib.sha256(canonical(doc).encode()).hexdigest(), STAGE_RULE.format(stage=stage)


def stage_sha256(protocol_path, stage):
    """The protocol hash that a valid record of `stage` carries (stage_binding)."""
    return stage_binding(protocol_path, stage)[0]


def measurement_sha256():
    """One hash over the measurement sources that collection.py pins for pilots and campaigns."""
    return hashlib.sha256(json.dumps(collection.measurement_sources(), sort_keys=True).encode()).hexdigest()


def commit():
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def problems(record, stage, protocol_sha, measurement):
    """Why this record does not prove the stage for the current protocol and code; [] when it does.

    protocol_sha is the current stage_sha256 of the protocol for this stage.
    """
    out = []
    v = record.get("values", {})
    if record.get("schema") != SCHEMA or v.get("stage") != stage:
        return ["not a record of stage " + stage]
    if v.get("protocol_sha256") != protocol_sha:
        out.append("protocol file changed since the record")
    if v.get("measurement_sha256") != measurement:
        out.append("measurement code changed since the record")
    criteria = v.get("criteria")
    if type(criteria) is not dict or set(criteria) != set(CRITERIA[stage]):
        return out + ["criteria differ from the stage definition"]
    for name in CRITERIA[stage]:
        item = criteria[name]
        if type(item) is not dict or item.get("passed") is not True:
            out.append("criterion not passed: " + name)
        elif not isinstance(item.get("evidence"), str) or not item["evidence"].strip():
            out.append("criterion without evidence: " + name)
    check = v.get("verification")
    if type(check) is not dict or check.get("independent") is not True or not check.get("by"):
        return out + ["no independent verification"]
    verdicts = check.get("verdicts")
    if type(verdicts) is not dict or set(verdicts) != set(CRITERIA[stage]):
        return out + ["verification does not cover every criterion"]
    out += [f"verification {verdict}: {name}" for name, verdict in sorted(verdicts.items()) if verdict != "confirmed"]
    return out


def newest(results, stage):
    found = []
    for path in sorted(Path(results).glob(f"gate_{stage}_*.json")):
        record = json.loads(path.read_text())
        found.append((record.get("date", ""), path, record))
    return max(found, key=lambda item: item[0])[1:] if found else (None, None)


def status(results, protocol):
    measurement = measurement_sha256()
    rows, open_before = [], False
    for stage in STAGES:
        path, record = newest(results, stage)
        why = ["no record"] if record is None else problems(record, stage, stage_sha256(protocol, stage), measurement)
        if open_before and not why:
            why = ["an earlier stage is not valid"]
        rows.append({"stage": stage, "passed": not why, "record": str(path) if path else None, "problems": why})
        open_before = open_before or bool(why)
    return rows


def require(results, protocol, stage):
    """Raise unless every stage before `stage` has a valid record for this protocol and code."""
    if stage not in STAGES:
        raise ValueError("unknown stage: " + str(stage))
    for row in status(results, protocol)[:STAGES.index(stage)]:
        if not row["passed"]:
            raise ValueError(f"stage {row['stage']} is not valid: " + "; ".join(row["problems"]))


def write_record(results, protocol, stage, criteria, verification, command, now=None):
    """Write a stage record. Refuses a stage whose predecessors are not valid, and refuses to overwrite."""
    require(results, protocol, stage)
    now = now or datetime.now(timezone.utc)
    protocol_sha, rule = stage_binding(protocol, stage)
    values = {"stage": stage, "protocol": str(protocol), "protocol_sha256": protocol_sha, "protocol_hash_rule": rule,
              "measurement_sha256": measurement_sha256(), "harness_sha256": sha256(__file__),
              "criteria": criteria, "verification": verification}
    record = {"schema": SCHEMA, "date": now.isoformat(timespec="seconds"), "commit": commit(),
              "host": socket.gethostname(), "guest": "pozri dokazy jednotlivych kriterii", "command": command,
              "n": len(CRITERIA[stage]), "values": values,
              "note": "Zaznam stupna pripravenosti protokolu v5; nie je to meranie. Platnost pocita scripts/gates.py status."}
    why = problems(record, stage, values["protocol_sha256"], values["measurement_sha256"])
    values["passed"] = not why
    values["problems"] = why
    path = Path(results) / f"gate_{stage}_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    with path.open("x") as stream:
        json.dump(record, stream, indent=1, ensure_ascii=False)
        stream.write("\n")
    return path, why


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("status", "require", "record"):
        p = sub.add_parser(name)
        if name != "status":
            p.add_argument("stage", choices=STAGES)
        p.add_argument("--protocol", type=Path, required=True)
        p.add_argument("--results", type=Path, default=ROOT / "data/results")
        if name == "record":
            p.add_argument("--criteria", type=Path, required=True, help="JSON {criterion: {passed, evidence}}")
            p.add_argument("--verification", type=Path, required=True, help="JSON {independent, by, verdicts}")
            p.add_argument("--command", required=True, help="the command that produced the evidence")
    a = parser.parse_args(argv)
    try:
        if a.action == "status":
            rows = status(a.results, a.protocol)
            print(json.dumps(rows, indent=1, ensure_ascii=False))
            return 0 if all(row["passed"] for row in rows) else 2
        if a.action == "require":
            require(a.results, a.protocol, a.stage)
            return 0
        path, why = write_record(a.results, a.protocol, a.stage, json.loads(a.criteria.read_text()),
                                 json.loads(a.verification.read_text()), a.command)
        print(json.dumps({"record": str(path), "passed": not why, "problems": why}, indent=1, ensure_ascii=False))
        return 0 if not why else 2
    except ValueError as error:
        print("gates: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
