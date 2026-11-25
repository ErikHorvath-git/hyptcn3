"""The writer of the values that a stage after G0 determines (protocol v5, package H1a; the lead's answer to Q66).

    python -m tcn.hodnoty zapis STAGE --protocol P --values VALUES.json --record data/results/hodnoty_<STAGE>_<UTC>.json
        [--partial]

One writer for every stage that determined_at names (G1, G2, G3a, G3b; the lead's answer to Q66: one path, tested
once). It lies outside the measurement code and outside the harness hash that the record of G0 binds
(scripts/collection.py is_measurement does not take tcn/, and scripts/gates.py stays as it is), so writing a value
keeps measurement_sha256 and harness_sha256.

What it does (WRITE_RULE):
  - it writes into the protocol file P only the concrete paths of determined_at.<STAGE>: a wildcard expands to the
    keys P holds (protocol_v5.expand), so G2's seven patterns are 11 paths (4 scenarios, 2 profiles); a path of
    VALUES outside them is refused by name, and so is a final write (without --partial) that does not name every
    one of them, before anything is written;
  - gates.stage_binding(P, s) of every stage s before STAGE is read before and after and must stay equal (writing G2
    keeps G0 and G1), else the write is refused;
  - the new file must pass the protocol loader (collection.protocol) and the self-check of
    protocol_v5.selfcheck in both plan modes, at stage G0 for a partial write and at STAGE for a final one;
  - its bytes keep the form of the project's protocol files, json.dumps(doc, indent=2) plus a newline (FORM_RULE;
    a file not in that form is refused, so that a write changes the values and nothing else);
  - the record (--record, check E's header: commit, date, host, guest, command, n, values) states per path the old
    and the new value, the rule quoted from the protocol (RULES: its notes) and where proposal 10.9 has a row for it
    the row of its table "Čo sa kedy určí", the sources of the value with their sha256 and how the value follows from
    them, the protocol's sha256 before and after, the bindings of the earlier stages, and the reminder that a new
    record of the audit self-test is due (SELFTEST_DUE);
  - the write is atomic: the new protocol and the record go to temporary files first, the record is linked to its
    name (refused when it exists) and the protocol renamed over P; a refusal leaves both untouched. No value has a
    default: every path names its value, its sources and its derivation.

VALUES.json:
    {"stage": "G2",
     "values": {"scenarios.eshop_high.rate": {"value": 9.392,
                                              "sources": ["/home/eh/hyptcn3-logs/.../record.json", ...],
                                              "derivation": "peak_share 0.8 x the throughput 11.74 of ..."},
                ...},
     "note": "optional"}
A source is a file (relative paths are read from the current directory); its sha256 goes into the record.

The options (the executor's choice, package H1a): STAGE is positional as in gates.py record STAGE; --protocol names
the file it changes (no default, the file being changed is named); --values is a file, since every path carries its
sources and derivation, which a command line does not hold; --record is the record's path with no default, refused
when it exists before anything is read, and named hodnoty_<STAGE>_<YYYYMMDDTHHMMSSZ>.json with the stage it writes;
--partial is the deliberate choice of a write that leaves paths of the stage for later (G2 writes its rates first,
its caps and controls.baseline next, the rest last: map H0 point C), while the default, the final write, names every
path of the stage once more, so its record holds the provenance of all of them.
"""
import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python -m tcn.hodnoty from another directory
    sys.path.insert(0, str(ROOT))

from scripts import collection, gates, protocol_v5  # noqa: E402

SCHEMA = "hyptcn3/stage-values/1"  # The record.
STAGES = protocol_v5.DETERMINED  # The stages a path of determined_at belongs to: G1, G2, G3a, G3b.
RECORD_NAME = r"hodnoty_(?P<stage>G1|G2|G3a|G3b)_\d{8}T\d{6}Z\.json"
DESIGN = "docs/NAVRH_PROTOKOL_V5.sk.md"
DESIGN_TABLE = "### 10.9 Čo sa kedy určí"  # Proposal 10.9: the table of what is determined when.
VALUES_KEYS = {"stage", "values"}
VALUES_OPTIONAL = {"note"}
PATH_KEYS = {"value", "sources", "derivation"}
FORM_RULE = "json.dumps(doc, indent=2) + newline, the form of config/collection-v5.json and scripts/lab_trial.py copies"
# Where the rule of each path of determined_at is written (the executor's table, package H1a): the protocol's own
# texts (a "*" stands for the key the path holds at the pattern's "*", in order) and the first cell of the row of
# proposal 10.9 (None where the table has no row: the gate follows invalid_rows.max by its note, rate and baseline
# are stated by scenario_rule and controls.note). Every pattern of determined_at needs an entry; a path without one is
# refused by name (tcn/tests/test_hodnoty.py pins that every pattern of config/collection-v5.json has its texts).
RULES = {
    "analysis.k1.m": (("analysis.k1.rule",), "hranice m pre K1 a K2"),
    "analysis.k2a.m": (("analysis.k2a.rule",), "hranice m pre K1 a K2"),
    "analysis.k2b.m": (("analysis.k2b.rule",), "hranice m pre K1 a K2"),
    "invalid_rows.max": (("invalid_rows.note",), "tolerancia neplatných riadkov na session"),
    "min_score_coverage": (("invalid_rows.note",), None),
    "scenarios.*.rate": (("scenario_rule.basis", "scenario_rule.note"), None),
    "audit.warnings_allowed": (("exceptions.collector_warnings.cause", "exceptions.collector_warnings.decision"),
                               "zoznam povolených varovaní zberača"),
    "audit.collector_majflt_max": (("audit.collector_majflt_note",), "major faulty zberača na cyklus"),
    "controls.baseline": (("controls.note",), None),
    "profiles.*.max_concurrent": (("profiles.*.note",), "strop súbežnosti profilov (`profiles.*.max_concurrent`)"),
    "analysis.methods.Z1.grid": (("analysis.selection",), "mriežky metód, maska stĺpcov"),
    "analysis.methods.Z3.grid": (("analysis.selection",), "mriežky metód, maska stĺpcov"),
    "analysis.methods.Z5.grid": (("analysis.selection",), "mriežky metód, maska stĺpcov"),
    "analysis.columns": (("analysis.qualification.note",), "mriežky metód, maska stĺpcov"),
    "exceptions.*.expected": (("exceptions.*.cause", "exceptions.*.decision"), "očakávané počty v registri výnimiek"),
    "replacement.max_per_campaign": (("replacement.note",), "limit náhrad"),
    "audit.rule_closed_rows_max": (("exceptions.rule_closed_rows.decision",),
                                   "strop riadkov uzavretých pravidlom na session; hranica skorého zastavenia"),
    "audit.early_stop.marked_rows_rate_per_type.*": (
        ("audit.early_stop.note",), "strop riadkov uzavretých pravidlom na session; hranica skorého zastavenia"),
}
WRITE_RULE = (
    "the lead's answer to Q66 (one writer for every stage): only the concrete paths of determined_at.<stage> are "
    "written, a wildcard expanded to the keys of the file; any other path is refused by name before anything is "
    "written, and a final write names every path of the stage; gates.stage_binding of every earlier stage is equal "
    "before and after; the loader and protocol_v5.selfcheck in both plan modes pass on the new file, at stage G0 for "
    "a partial write and at the stage for a final one; the bytes keep FORM_RULE; the protocol and the record go to "
    "temporary files, the record is linked to its name (refused when it exists) and the protocol renamed over the "
    "file; no value has a default")
SELFTEST_DUE = (
    "the bytes of the protocol file changed: before the next capture a new record of the audit self-test is due "
    "(python3 scripts/audit_selftest.py --protocol P; scripts/audit_selftest.py require_selftest binds the file's "
    "sha256 and scripts/collection.py run refuses a capture without a passed record for it)")
NOTE = ("Provenance of values a stage after G0 determines (proposal 10.9), written by python -m tcn.hodnoty zapis; "
        "not a measurement, the sources hold the measurements.")


class Refused(ValueError):
    """A write the rules refuse; nothing was written."""


def _git(*args):
    try:
        done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _strict_json(text, what):
    """JSON without NaN or Infinity and without a key twice in an object (json would keep the last silently)."""
    def pairs(items):
        keys = [key for key, _ in items]
        twice = sorted({key for key in keys if keys.count(key) > 1})
        if twice:
            raise Refused(f"{what}: a key appears twice in one object: {', '.join(twice)}")
        return dict(items)

    def constant(name):
        raise Refused(f"{what}: {name} is no JSON number")
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except Refused:
        raise
    except ValueError as error:
        raise Refused(f"{what}: not JSON ({error})") from None


def form(doc):
    """The bytes of a protocol document in the project's form (FORM_RULE)."""
    return (json.dumps(doc, indent=2) + "\n").encode()


def concrete_paths(doc, stage):
    """{concrete dotted path: its pattern} of determined_at.<stage> in `doc`; a pattern that names no key is refused."""
    determined = doc.get("determined_at")
    patterns = determined.get(stage) if type(determined) is dict else None
    if type(patterns) is not list or not patterns:
        raise Refused(f"the protocol's determined_at names no path of stage {stage}")
    out = {}
    for pattern in patterns:
        found = [path for path, _ in protocol_v5.expand(doc, pattern)]
        if not found:
            raise Refused(f"determined_at.{stage} pattern {pattern} names no key of the protocol")
        out.update(dict.fromkeys(found, pattern))
    return out


def _bind(pattern, path, source):
    """The text path `source` of the rule of `path` (an expansion of `pattern`), its '*' replaced by the keys `path`
    holds at the pattern's '*', in order."""
    keys = [key for key, part in zip(path.split("."), pattern.split(".")) if part == "*"]
    parts = source.split(".")
    if parts.count("*") > len(keys):
        raise Refused(f"tcn/hodnoty.py RULES: {source} has more '*' than {pattern}")
    bound = iter(keys)
    return ".".join(next(bound) if part == "*" else part for part in parts)


def _get(doc, path):
    node = doc
    for key in path.split("."):
        if type(node) is not dict or key not in node:
            raise KeyError(path)
        node = node[key]
    return node


def _set(doc, path, value):
    keys = path.split(".")
    node = doc
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value


def design_row(text, cell, stage):
    """The row of proposal 10.9's table whose first cell is `cell`: (the row as written, its three cells); Refused
    when the table has no such row or the row names another stage."""
    if DESIGN_TABLE not in text:
        raise Refused(f"{DESIGN} has no section '{DESIGN_TABLE}'")
    section = text.split(DESIGN_TABLE, 1)[1].split("\n#", 1)[0]
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == 3 and cells[0] == cell:
            if cells[1] != stage:
                raise Refused(f"the row '{cell}' of proposal 10.9 names stage {cells[1]}, not {stage}")
            return line, cells
    raise Refused(f"the table of proposal 10.9 ({DESIGN}) has no row '{cell}'")


def rule_of(doc, path, pattern, stage, design):
    """The rule of one path: [{source, text}] quoted from the protocol (RULES) and, where proposal 10.9 has a row for
    it, that row; `design` is (text, sha256) of the proposal. Refused for a path without an entry or a missing text."""
    if pattern not in RULES:
        raise Refused(f"no rule source for {path} (pattern {pattern}): tcn/hodnoty.py RULES names none")
    texts, cell = RULES[pattern]
    out = []
    for source in texts:
        where = _bind(pattern, path, source)
        try:
            text = _get(doc, where)
        except KeyError:
            raise Refused(f"the rule of {path}: the protocol has no text at {where}") from None
        if type(text) is not str or not text.strip():
            raise Refused(f"the rule of {path}: {where} is no text")
        out.append({"source": f"protocol:{where}", "text": text})
    if cell is not None:
        line, cells = design_row(design[0], cell, stage)
        out.append({"source": f"{DESIGN} 10.9", "sha256": design[1], "text": line,
                    "cells": dict(zip(("value", "stage", "rule"), cells))})
    return out


def read_values(path, stage):
    """{path: {value, sources, derivation}} of VALUES for `stage`, its note and its sha256; Refused by name."""
    data = Path(path).read_bytes()
    doc = _strict_json(data.decode("utf-8"), f"--values {path}")
    if type(doc) is not dict or not VALUES_KEYS <= set(doc) <= VALUES_KEYS | VALUES_OPTIONAL:
        raise Refused(f"--values {path}: an object with exactly {sorted(VALUES_KEYS)} (and optionally note)")
    if doc["stage"] != stage:
        raise Refused(f"--values {path} states stage {doc['stage']!r}, the command writes {stage}")
    values = doc["values"]
    if type(values) is not dict or not values:
        raise Refused(f"--values {path}: values is an object of at least one path")
    for name, item in values.items():
        if type(item) is not dict or set(item) != PATH_KEYS:
            raise Refused(f"--values {path}: {name} is an object with exactly {sorted(PATH_KEYS)} (no default)")
        sources = item["sources"]
        if (type(sources) is not list or not sources or any(type(s) is not str or not s for s in sources)
                or len(set(sources)) != len(sources)):
            raise Refused(f"--values {path}: {name}.sources is a list of distinct files, at least one")
        if type(item["derivation"]) is not str or not item["derivation"].strip():
            raise Refused(f"--values {path}: {name}.derivation is the text of how the value follows from its sources")
    note = doc.get("note")
    if note is not None and type(note) is not str:
        raise Refused(f"--values {path}: note is a text")
    return values, note, _sha256(data)


def source_records(sources):
    out = []
    for given in sources:
        path = Path(given).absolute()
        if not path.is_file():
            raise Refused(f"source {given} is no file")
        out.append({"path": given, "resolved": str(path), "size": path.stat().st_size, "sha256": _file_sha256(path)})
    return out


def _selfcheck(path, stage):
    """[(mode, problem)] of protocol_v5.selfcheck on `path` at `stage` in both plan modes; [] when all passed."""
    out = []
    for mode in protocol_v5.MODES:
        report = protocol_v5.selfcheck(path, mode=mode, stage=stage)
        out += [(mode, f"{c['check']} {c['result']}" + (": " + "; ".join(c["reasons"]) if c["reasons"] else ""))
                for c in report["checks"] if c["result"] != "passed"]
    return out


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_temporary(path, data):
    with open(path, "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def zapis(stage, protocol, values_path, record, *, partial, command, now=None):
    """Write the values of `values_path` for `stage` into the protocol file `protocol` and the record `record`
    (WRITE_RULE); returns the record. Refused (a ValueError) names why nothing was written."""
    if stage not in STAGES:
        raise Refused(f"unknown stage {stage}: determined_at names {', '.join(STAGES)}")
    record = Path(record).absolute()
    if record.exists() or record.is_symlink():
        raise Refused(f"the record {record} exists; nothing was read or written")
    match = re.fullmatch(RECORD_NAME, record.name)
    if match is None or match["stage"] != stage:
        raise Refused(f"the record is named hodnoty_{stage}_<YYYYMMDDTHHMMSSZ>.json, not {record.name}")
    if not record.parent.is_dir():
        raise Refused(f"the directory of the record {record.parent} does not exist")
    values, note, values_sha = read_values(values_path, stage)
    protocol = Path(protocol).absolute()
    design_path = ROOT / DESIGN
    design_bytes = design_path.read_bytes()
    design = (design_bytes.decode("utf-8"), _sha256(design_bytes))
    temporary = protocol.with_name(f".{protocol.name}.{os.getpid()}.tmp")
    staged = record.with_name(f".{record.name}.{os.getpid()}.tmp")
    lock = os.open(protocol.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)  # One writer of the protocol's directory at a time, as tcn/pecat.py.
        raw = protocol.read_bytes()
        doc = _strict_json(raw.decode("utf-8"), f"--protocol {protocol}")
        if type(doc) is not dict or doc.get("schema") != protocol_v5.SCHEMA:
            raise Refused(f"--protocol {protocol} is no protocol of schema {protocol_v5.SCHEMA}")
        if form(doc) != raw:
            raise Refused(f"--protocol {protocol} is not in the project's form ({FORM_RULE}); a write would change "
                          "more than its values")
        allowed = concrete_paths(doc, stage)
        outside = sorted(set(values) - set(allowed))
        if outside:
            raise Refused(f"not paths of determined_at.{stage}, nothing written: {', '.join(outside)} (the stage's "
                          f"paths: {', '.join(sorted(allowed))})")
        missing = sorted(set(allowed) - set(values))
        if missing and not partial:
            raise Refused(f"a final write of {stage} names every path of determined_at.{stage}; missing: "
                          f"{', '.join(missing)} (a write of some of them is --partial)")
        paths = []
        new = copy.deepcopy(doc)
        for path in sorted(values):
            item = values[path]
            paths.append({"path": path, "pattern": allowed[path], "old": copy.deepcopy(_get(doc, path)),
                          "new": item["value"], "rule": rule_of(doc, path, allowed[path], stage, design),
                          "sources": source_records(item["sources"]), "derivation": item["derivation"]})
            _set(new, path, copy.deepcopy(item["value"]))
        data = form(new)
        _write_temporary(temporary, data)
        earlier = gates.STAGES[:gates.STAGES.index(stage)]
        bindings = {}
        for name in earlier:
            before, rule = gates.stage_binding(protocol, name)
            after, _ = gates.stage_binding(temporary, name)
            if before != after:
                raise Refused(f"the write changes the binding of stage {name} ({before} -> {after}); nothing written")
            bindings[name] = {"sha256": before, "rule": rule}
        try:
            collection.protocol(temporary)
        except (ValueError, KeyError, TypeError) as error:
            raise Refused(f"the protocol loader refuses the new file, nothing written: {error}") from None
        checked = "G0" if partial else stage
        problems = _selfcheck(temporary, checked)
        if problems:
            raise Refused(f"protocol_v5.selfcheck at stage {checked} fails on the new file, nothing written: "
                          + " | ".join(f"{mode}: {problem}" for mode, problem in problems))
        own = gates.stage_binding(temporary, stage)
        status = _git("status", "--porcelain")
        doc_record = {
            "schema": SCHEMA, "commit": (_git("rev-parse", "HEAD") or "").strip() or None,
            "commit_dirty": None if status is None else bool(status),
            "date": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
            "host": socket.gethostname(), "guest": None, "command": command, "n": len(paths),
            "values": {"stage": stage, "partial": partial, "protocol": str(protocol),
                       "protocol_sha256_before": _sha256(raw), "protocol_sha256_after": _sha256(data),
                       "earlier_bindings": bindings, "stage_binding_after": {"sha256": own[0], "rule": own[1]},
                       "paths": paths,
                       "values_file": {"path": str(values_path), "resolved": str(Path(values_path).absolute()),
                                       "sha256": values_sha, "note": note},
                       "checks": {"loader": "collection.protocol accepted the new file",
                                  "selfcheck": {"stage": checked, "modes": list(protocol_v5.MODES), "passed": True},
                                  "form": FORM_RULE, "earlier_bindings": "equal before and after"},
                       "selftest_due": SELFTEST_DUE, "rule": WRITE_RULE},
            "note": NOTE}
        _write_temporary(staged, (json.dumps(doc_record, indent=1, ensure_ascii=False, allow_nan=False)
                                  + "\n").encode())
        if _sha256(protocol.read_bytes()) != _sha256(raw):
            raise Refused(f"the protocol {protocol} changed while it was being written; nothing written")
        try:
            os.link(staged, record)  # Exclusive: never over an existing record.
        except FileExistsError:
            raise Refused(f"the record {record} appeared meanwhile; nothing written") from None
        try:
            os.replace(temporary, protocol)
        except OSError:
            record.unlink()  # The record of a write that did not happen goes with it.
            raise
        _fsync_dir(protocol.parent)
        _fsync_dir(record.parent)
        return doc_record
    finally:
        os.close(lock)
        for path in (temporary, staged):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m tcn.hodnoty", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    write = sub.add_parser("zapis", help="write values of determined_at.<STAGE> into a protocol file, with a record")
    write.add_argument("stage", choices=STAGES)
    write.add_argument("--protocol", type=Path, required=True, help="the protocol file the values go into")
    write.add_argument("--values", type=Path, required=True,
                       help="JSON {stage, values: {path: {value, sources, derivation}}}")
    write.add_argument("--record", type=Path, required=True,
                       help="the new record, hodnoty_<STAGE>_<YYYYMMDDTHHMMSSZ>.json (refused when it exists)")
    write.add_argument("--partial", action="store_true",
                       help="a write of some paths of the stage (self-check at G0); without it every path is named "
                            "and the self-check runs at STAGE")
    a = parser.parse_args(argv)
    try:
        done = zapis(a.stage, a.protocol, a.values, a.record, partial=a.partial,
                     command=shlex.join(["python", "-m", "tcn.hodnoty", *argv]))
    except (OSError, ValueError) as error:
        print(f"tcn.hodnoty: {error}", file=sys.stderr)
        return 2
    v = done["values"]
    print(json.dumps({"record": str(a.record), "stage": v["stage"], "partial": v["partial"],
                      "paths": {p["path"]: {"old": p["old"], "new": p["new"]} for p in v["paths"]},
                      "protocol_sha256_before": v["protocol_sha256_before"],
                      "protocol_sha256_after": v["protocol_sha256_after"], "selftest_due": v["selftest_due"]},
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
