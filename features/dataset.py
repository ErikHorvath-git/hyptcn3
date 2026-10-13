"""Build an explicit corpus index from accepted collection audits.

No random window split or automatic chronological re-split is performed here.
The index freezes roles assigned before capture; training must honor them.
"""
import argparse
import hashlib
import json
from pathlib import Path

from .archive import load


ROLES = ("train", "dev", "calibration", "test_benign")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(audits, protocol, protocol_sha):
    records, seen_ids, seen_features = [], set(), set()
    boot_roles, group_roles, layouts, extractors, environments = {}, {}, set(), set(), set()
    boot_groups, group_boots, assignments = {}, {}, set()
    for path in audits:
        report = json.loads(Path(path).read_text())
        v = report["values"]
        if not v["accepted"] or v["protocol_sha256"] != protocol_sha:
            raise ValueError("unaccepted audit or protocol mismatch: " + str(path))
        directory = Path(v["session_dir"])
        meta_path = directory / "session.json"
        m = json.loads(meta_path.read_text())
        environments.add((m["guest_before"]["stack_sha256"], m["collector_sha256"]))
        if v.get("session_sha256") != sha(meta_path):
            raise ValueError("session metadata changed since audit")
        if m["typ"] != "benign" or m["role"] not in ROLES:
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
        expected_groups = {f"{m['role']}-{i + 1}" for i in range(protocol["roles"][m["role"]])}
        if m["group"] not in expected_groups or m["scenario"] not in protocol["scenarios"]:
            raise ValueError("assignment is outside the planned allocation")
        feature_path = Path(v["features"])
        if sha(feature_path) != v["features_sha256"]:
            raise ValueError("feature archive changed since audit")
        data = load(feature_path)
        from .quality import protocol_policy
        if str(data["quality_policy"]) != protocol_policy(protocol):
            raise ValueError("feature quality policy differs from corpus protocol")
        if not data["valid"].all():
            raise ValueError("incomplete features in accepted audit")
        layouts.add(json.dumps(v["layout"], sort_keys=True))
        extractors.add(json.dumps(v["extractor_sha256"], sort_keys=True))
        records.append({"id": identity, "role": m["role"], "group": m["group"],
                        "boot_id": m["guest_before"]["boot_id"], "kernel": m["guest_before"]["kernel"],
                        "typ": m["typ"], "guest": m["guest_before"],
                        "collector_sha256": m["collector_sha256"],
                        "protocol_sha256": protocol_sha,
                        "session": str(meta_path.resolve()), "session_sha256": sha(meta_path),
                        "scenario": m["scenario"], "seed": m["seed"],
                        "start": float(data["casy"][0]), "end": float(data["casy"][-1]),
                        "audit": str(Path(path).resolve()), "audit_sha256": sha(path),
                        "features": str(feature_path.resolve()), "features_sha256": v["features_sha256"]})
    if (len(layouts) > 1 or len(extractors) > 1 or len(environments) > 1
            or len({r["kernel"] for r in records}) > 1):
        raise ValueError("mixed memory layout, kernel or extraction implementation")
    if not records:
        raise ValueError("no accepted sessions")
    # The full order is fixed before collection, including development and calibration.
    for left, right in zip(ROLES, ROLES[1:]):
        a, b = [r for r in records if r["role"] == left], [r for r in records if r["role"] == right]
        if a and b and max(r["end"] for r in a) >= min(r["start"] for r in b):
            raise ValueError("dataset roles are not chronologically separated")
    missing = []
    for role in ROLES:
        for scenario in protocol["scenarios"]:
            count = sum(r["role"] == role and r["scenario"] == scenario for r in records)
            if count != protocol["roles"][role]:
                missing.append({"role": role, "scenario": scenario,
                                "expected": protocol["roles"][role], "actual": count})
    return {"schema": "hyptcn3/corpus-index/1", "protocol_sha256": protocol_sha,
            "protocol_config": protocol,
            "complete": not missing, "allocation_mismatches": missing,
            "sessions": sorted(records, key=lambda r: r["start"]),
            "normalization_fit_role": "train", "threshold_fit_role": "calibration",
            "test_is_read_only": True}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--protocol", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("audits", nargs="+", type=Path)
    a = ap.parse_args()
    try:
        result = build(a.audits, json.loads(a.protocol.read_text()), sha(a.protocol))
        result["protocol"] = str(a.protocol.resolve())
        with a.out.open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
        print(f"sessions={len(result['sessions'])} complete={result['complete']}")
        return 0 if result["complete"] else 2
    except (ValueError, OSError, KeyError) as exc:
        ap.exit(2, f"dataset: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
