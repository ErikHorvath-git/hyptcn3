#!/usr/bin/env python3
"""Self-test of the session audit checks (protocol v5, package B3; proposal 6.2).

  python3 scripts/audit_selftest.py --protocol P [--out PATH]

Under protocol P it builds, in a temporary directory, the clean session and every bad session of
scripts/tests/audit_cases.py (CASES) and audits each with the real scripts/collection.py audit_session. Only
collection.retazec, the feature extraction from guest RAM, is replaced by the synthetic extraction result of the
session; the record says so. The record (data/results/audit_selftest_<UTC stamp>.json unless --out names
another file; never overwritten) binds the protocol file, the measurement code (as scripts/gates.py) and the case
files by SHA-256. Exit 0 when the clean session is accepted and every case is refused (code 2) with exactly its
expected reasons, else 2.

require_selftest() is what scripts/collection.py run asks before every capture: no session is collected without
a passed record for the current code and protocol.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCHEMA = "hyptcn3/audit-selftest/1"
RESULTS = ROOT / "data/results"
# The files of scripts/tests the cases and their sessions come from; cases_sha256 covers them.
CASE_FILES = ("scripts/tests/audit_case.py", "scripts/tests/audit_cases.py",
              "scripts/tests/audit_cases_logs.py",
              "scripts/tests/boundary_sessions.py", "scripts/tests/test_collection_logs.py",
              "scripts/tests/test_traffic_log.py")
REFUSED = "no valid audit self-test record for the current code and protocol"
REPLACED = ("collection.retazec (the feature extraction from guest RAM) returned the synthetic extraction result "
            "of each session; everything else ran as scripts/collection.py audit_session runs")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def measurement_sha256():
    """One hash over the measurement sources, as scripts/gates.py binds its stage records."""
    from scripts.gates import measurement_sha256 as current
    return current()


def cases_sha256():
    """One hash over the case files (a file not there counts as null)."""
    files = {name: digest(ROOT / name) if (ROOT / name).is_file() else None for name in CASE_FILES}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def cases():
    """The cases of the self-test: RAM side and log audit (scripts/tests/audit_cases.py CASES)."""
    from scripts.tests import audit_cases
    return audit_cases.CASES


def commit():
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def run(protocol_path, work):
    """Audit the clean session and every case under the protocol file; returns the record's values."""
    from scripts import collection
    from scripts.tests import audit_cases
    protocol_path = Path(protocol_path).resolve()
    p = collection.protocol(protocol_path)
    clean = audit_cases.run_case(work, p, protocol_path)
    shutil.rmtree(Path(work) / "clean")
    out = []
    for case in cases():
        reasons = audit_cases.expected(case, p)
        entry = {"id": case.id, "check": case.check, "expected": reasons}
        try:
            audit = audit_cases.run_case(work, p, protocol_path, case)
            entry.update(reasons=audit.values["reasons"], code=audit.code,
                         passed=audit.code == 2 and audit.values["reasons"] == reasons)
        except Exception as error:  # noqa: BLE001 - a case that cannot be built or audited has failed
            entry.update(reasons=None, code=None, passed=False, error=f"{type(error).__name__}: {error}"[:500])
        shutil.rmtree(Path(work) / case.id.replace("/", "_"), ignore_errors=True)  # The work directory may be a tmpfs.
        out.append(entry)
    clean_entry = {"code": clean.code, "reasons": clean.values["reasons"]}
    return {"clean": clean_entry, "cases": out, "unreachable": dict(audit_cases.UNREACHABLE),
            "passed": clean.code == 0 and clean.values["reasons"] == [] and all(c["passed"] for c in out)}


def record(protocol_path, work, now=None):
    """The self-test record of the protocol file (not written)."""
    started = time.monotonic()
    values = run(protocol_path, work)
    now = now or datetime.now(timezone.utc)
    return {"schema": SCHEMA, "date": now.isoformat(timespec="seconds"), "commit": commit(),
            "command": " ".join(map(str, sys.argv)), "protocol": str(Path(protocol_path).resolve()),
            "protocol_sha256": digest(protocol_path), "measurement_sha256": measurement_sha256(),
            "cases_sha256": cases_sha256(), "replaced": REPLACED, **values,
            "seconds": round(time.monotonic() - started, 1),
            "note": "Self-test of the audit checks on synthetic sessions; not a measurement."}


def require_selftest(protocol_path, directory=None):
    """The newest self-test record for this protocol file, measurement code and case files; ValueError unless it
    passed with the current cases.

    `directory` holds the records (default data/results, files audit_selftest_*.json). A record for another
    protocol file, older measurement code or other case files does not count; the newest of those that remain
    must state passed and list exactly the ids of the current cases, in order.
    """
    current = (digest(protocol_path), measurement_sha256(), cases_sha256())
    found = []
    for path in sorted(Path(RESULTS if directory is None else directory).glob("audit_selftest_*.json")):
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if (type(doc) is dict and doc.get("schema") == SCHEMA
                and (doc.get("protocol_sha256"), doc.get("measurement_sha256"), doc.get("cases_sha256")) == current):
            found.append((str(doc.get("date")), path.name, doc))
    if not found:
        raise ValueError(REFUSED)
    doc = max(found, key=lambda item: item[:2])[2]
    listed = doc.get("cases")
    ids = [case.get("id") for case in listed if type(case) is dict] if type(listed) is list else None
    if doc.get("passed") is not True or ids != [case.id for case in cases()]:
        raise ValueError(REFUSED)
    return doc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--out", type=Path, help="record file (default data/results/audit_selftest_<UTC stamp>.json)")
    a = parser.parse_args(argv)
    from scripts import collection
    with tempfile.TemporaryDirectory(prefix="audit_selftest_") as work:
        doc = record(a.protocol, Path(work))
    out = a.out or RESULTS / f"audit_selftest_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    collection.write_json(out, doc)
    failed = [case["id"] for case in doc["cases"] if not case["passed"]]
    print(json.dumps({"record": str(out), "passed": doc["passed"], "clean": doc["clean"], "cases": len(doc["cases"]),
                      "failed": failed, "seconds": doc["seconds"]}, indent=1, ensure_ascii=False))
    return 0 if doc["passed"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(f"audit_selftest: {error}", file=sys.stderr)
        sys.exit(2)
