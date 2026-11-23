"""Build an explicit corpus index from accepted collection audits.

No random window split or automatic chronological re-split is performed here.
The index freezes roles assigned before capture; training must honor them.

Completeness (package B6a, design section 1.3). Under protocol schema 3 a corpus holds the plan of one mode, campaign
or rehearsal (scripts/protocol_v5.py planned_rows): every planned row has exactly one accepted session and every
accepted session holds exactly one row, matched by (role, group, scenario, vm). The index names this rule
"plan:<mode>", records the mode as plan_mode and gives every session the position of its row. Schemas 1 and 2 keep
their rule, every scenario in every group of their four roles, named "every_scenario_every_group" (plan_mode and
position null). In both the roles follow each other in time by protocol_v5.TIME_RANK; the two test roles share a
rank and interleave.
"""
import argparse
import hashlib
import json
from pathlib import Path

from .acceptance import require_accepted
from .archive import load
from .quality import require_log_audit


ROLES = ("train", "dev", "calibration", "test_benign", "test_controls")
# The roles training fits on (normalization, checkpoint selection and threshold). The test roles are indexed and never
# loaded by training (safeguard/training.py, tcn/porovnanie.py).
FIT_ROLES = ("train", "dev", "calibration")
# The roles of a protocol of schema 1 or 2; test_controls exists only under schema 3.
LEGACY_ROLES = ("train", "dev", "calibration", "test_benign")
EVERY_SCENARIO_EVERY_GROUP = "every_scenario_every_group"  # The allocation rule of schemas 1 and 2.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def allocation(protocol, mode):
    """(rule, roles, planned rows) of a corpus of this protocol (design B6a 1.3). Schema 3: the rule "plan:<mode>",
    ROLES and the rows of protocol_v5.planned_rows, which refuses an unknown mode; the mode has no default. Schemas 1
    and 2: EVERY_SCENARIO_EVERY_GROUP over LEGACY_ROLES and no rows; a mode is refused. ValueError names the reason."""
    from scripts.protocol_v5 import SCHEMA, planned_rows
    if type(protocol) is dict and protocol.get("schema") == SCHEMA:
        if mode is None:
            raise ValueError("a corpus of protocol schema 3 needs its plan mode (campaign or rehearsal)")
        try:
            rows = planned_rows(protocol, mode)
        except ValueError as error:
            raise ValueError(f"no planned rows of mode {mode}: {error}") from None
        return "plan:" + str(mode), ROLES, rows
    if mode is not None:
        raise ValueError(f"plan mode {mode} applies only to protocol schema 3; schemas 1 and 2 keep "
                         + EVERY_SCENARIO_EVERY_GROUP)
    return EVERY_SCENARIO_EVERY_GROUP, LEGACY_ROLES, None


def row_key(session):
    """The key of the planned row a session holds (design B6a 1.2): role, group, scenario and VM (None for a protocol
    of one unnamed VM). A replacement keeps all four, and no group repeats a scenario."""
    return session["role"], session["group"], session["scenario"], session.get("vm")


def named(session):
    """A session or a planned row in a message: its id or label, then role, group, scenario and VM."""
    return (f"{session.get('id', session.get('label'))} ({session['role']}, {session['group']}, {session['scenario']}, "
            f"VM {session.get('vm')})")


def chronology(records):
    """(last record of a rank, first record of the next rank) when the roles are out of time order, else None. Every
    session of a role ends before any session of a role of a later rank (protocol_v5.TIME_RANK) starts; the two test
    roles share a rank and interleave (design B6a 1.3), whatever the order of ROLES."""
    from scripts.protocol_v5 import TIME_RANK
    ranks = sorted({TIME_RANK[r["role"]] for r in records})
    for low, high in zip(ranks, ranks[1:]):
        last = max((r for r in records if TIME_RANK[r["role"]] == low), key=lambda r: r["end"])
        first = min((r for r in records if TIME_RANK[r["role"]] == high), key=lambda r: r["start"])
        if last["end"] >= first["start"]:
            return last, first
    return None


def build(audits, protocol, protocol_sha, *, mode=None):
    """The corpus index of accepted audits. mode: the plan mode of a corpus of protocol schema 3, required there and
    refused under schemas 1 and 2 (allocation()). A session that holds no planned row is refused; a planned row
    without a session is an allocation mismatch with its reason, and the index is then not complete."""
    from scripts.protocol_v5 import plans_events  # Under schema 3 every protocol has an events section.
    rule, roles, rows = allocation(protocol, mode)
    planned = None if rows is None else {row_key(row): row for row in rows}
    records, seen_ids, seen_features = [], set(), set()
    boot_roles, group_roles, layouts, extractors, environments = {}, {}, set(), set(), set()
    boot_groups, group_boots, assignments = {}, {}, set()
    for path in audits:
        report = json.loads(Path(path).read_text())
        v = report["values"]
        if v.get("accepted") is not True or v["protocol_sha256"] != protocol_sha:
            raise ValueError("unaccepted audit or protocol mismatch: " + str(path))
        directory = Path(v["session_dir"])
        meta_path = directory / "session.json"
        m = json.loads(meta_path.read_text())
        environments.add((m["guest_before"]["stack_sha256"], m["collector_sha256"]))
        if v.get("session_sha256") != sha(meta_path):
            raise ValueError("session metadata changed since audit")
        if m["typ"] != "benign" or m["role"] not in roles:
            raise ValueError("pilot/attack data must not enter the benign corpus")
        identity = m["session_id"]
        if identity in seen_ids or v["features_sha256"] in seen_features:
            raise ValueError("duplicate session/features")
        seen_ids.add(identity)
        seen_features.add(v["features_sha256"])
        for registry, key in ((boot_roles, m["guest_before"]["boot_id"]), (group_roles, m["group"])):
            if registry.setdefault(key, m["role"]) != m["role"]:
                raise ValueError("boot/group shared between dataset roles")
        boot = m["guest_before"]["boot_id"]
        if (boot_groups.setdefault(boot, m["group"]) != m["group"]
                or group_boots.setdefault(m["group"], boot) != boot):
            raise ValueError("boot/group mapping is not one to one")
        assignment = (m["group"], m["scenario"])
        if assignment in assignments:
            raise ValueError("duplicate group/scenario assignment")
        assignments.add(assignment)
        if planned is None:
            prefix = protocol.get("group_prefix", "")
            expected_groups = {f"{prefix}{m['role']}-{i + 1}" for i in range(protocol["roles"][m["role"]])}
            if m["group"] not in expected_groups or m["scenario"] not in protocol["scenarios"]:
                raise ValueError("assignment is outside the planned allocation")
            position = None  # The rule of schemas 1 and 2 has no plan rows.
        else:
            row = planned.get(row_key(m))
            if row is None:
                raise ValueError(f"assignment is outside the planned allocation: session {named(dict(m, id=identity))} "
                                 f"holds no row of {rule}")
            position = row["position"]
        feature_path = Path(v["features"])
        if sha(feature_path) != v["features_sha256"]:
            raise ValueError("feature archive changed since audit")
        data = load(feature_path)
        from .quality import protocol_policy
        if str(data["quality_policy"]) != protocol_policy(protocol):
            raise ValueError("feature quality policy differs from corpus protocol")
        # The acceptance is decided again from the archive and must equal the audit record (features/acceptance.py).
        require_accepted(data, protocol, directory.name, m["role"], v)
        # So is the log audit where the session still keeps its logs; the row says whether (features/quality.py).
        log_audit = require_log_audit(m, v, snapshot_times=data["casy"])
        layouts.add(json.dumps(v["layout"], sort_keys=True))
        extractors.add(json.dumps(v["extractor_sha256"], sort_keys=True))
        records.append({"id": identity, "role": m["role"], "group": m["group"], "vm": m.get("vm"),
                        "boot_id": m["guest_before"]["boot_id"], "kernel": m["guest_before"]["kernel"],
                        "typ": m["typ"], "guest": m["guest_before"],
                        "collector_sha256": m["collector_sha256"],
                        "protocol_sha256": protocol_sha,
                        "session": str(meta_path.resolve()), "session_sha256": sha(meta_path),
                        "scenario": m["scenario"], "position": position, "seed": m["seed"],
                        "start": float(data["casy"][0]), "end": float(data["casy"][-1]),
                        "audit": str(Path(path).resolve()), "audit_sha256": sha(path),
                        "features": str(feature_path.resolve()), "features_sha256": v["features_sha256"],
                        "log_audit": log_audit})
        # events.json is asked for when the protocol plans events (as the log audit) or the session lists them.
        if plans_events(protocol) or "events" in protocol and "events" in m:
            # Protokol v4 (krok B): udalosti su sucastou normalu vo vsetkych rolach;
            # ich zaznam ide do korpusu pre E2' (tcn.eval udalosti --role).
            events = directory / "events.json"
            if not events.is_file():
                raise ValueError("protocol with events but session has no events.json: " + str(directory))
            records[-1].update(events=str(events.resolve()), events_sha256=sha(events))
    if (len(layouts) > 1 or len(extractors) > 1 or len(environments) > 1
            or len({r["kernel"] for r in records}) > 1):
        raise ValueError("mixed memory layout, kernel or extraction implementation")
    if not records:
        raise ValueError("no accepted sessions")
    # The full order is fixed before collection, including development and calibration.
    late = chronology(records)
    if late is not None:
        raise ValueError(f"dataset roles are not chronologically separated: {late[0]['role']} session {late[0]['id']} "
                         f"ends after {late[1]['role']} session {late[1]['id']} starts")
    missing = []
    if planned is None:
        for role in roles:
            for scenario in protocol["scenarios"]:
                count = sum(r["role"] == role and r["scenario"] == scenario for r in records)
                if count != protocol["roles"][role]:
                    missing.append({"role": role, "scenario": scenario,
                                    "expected": protocol["roles"][role], "actual": count})
    else:
        held = {row_key(r) for r in records}
        missing = [dict(row, reason="missing planned session") for row in rows if row_key(row) not in held]
    return {"schema": "hyptcn3/corpus-index/1", "protocol_sha256": protocol_sha,
            "protocol_config": protocol, "allocation_rule": rule, "plan_mode": mode,
            "complete": not missing, "allocation_mismatches": missing,
            "sessions": sorted(records, key=lambda r: r["start"]),
            "normalization_fit_role": "train", "threshold_fit_role": "calibration",
            "test_is_read_only": True}


def main():
    from scripts.protocol_v5 import MODES
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--protocol", required=True, type=Path)
    ap.add_argument("--mode", choices=MODES,
                    help="plan mode of a corpus of protocol schema 3 (required there, refused for schemas 1 and 2)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("audits", nargs="+", type=Path)
    a = ap.parse_args()
    try:
        result = build(a.audits, json.loads(a.protocol.read_text()), sha(a.protocol), mode=a.mode)
        result["protocol"] = str(a.protocol.resolve())
        with a.out.open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
        print(f"sessions={len(result['sessions'])} complete={result['complete']} rule={result['allocation_rule']}")
        return 0 if result["complete"] else 2
    except (ValueError, OSError, KeyError) as exc:
        ap.exit(2, f"dataset: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
