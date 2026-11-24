"""The test of the table of the audit's probes (protocol v5, package B10, agent A; skeleton B10 1.2, design B10 decisions
2 to 4).

The table is scripts/tests/audit_probes.py. Its checks:
    problems()         the classification holds exactly the 72 risk ids of the record; every risk of class P and every
                       row of the lead's skeleton section 2 has its row (design decision 2), rows 1 to 15 are the
                       skeleton's rows in its order with its packages, and every further row holds a risk of class P;
    phrase_problems()  each class rests on a phrase that stands verbatim in its reader's text of the record;
    commit_problems()  the fixing commits name their package and `before` is the parent of the oldest (skeleton 6);
    reason_problems()  each exact reason stands verbatim on its line of the file (design decision 3);
and every test id of the table exists and passes in one run of its own (design decision 4). Each check has its good
input (the table as it is) and, where the design names the failure, one bad input with exactly its problem. That every
test of the table fails on its commit `before` is the record dokazy/B10/pred_po/, and dokazy/B10/pred_po_zlucene/ for
the merged tree (design decision 5), not a test here. The table, a module of package B10, is imported inside the tests
(_table), so this file collects on the code before B10 and fails there test by test. Only a table and its checks: no
number here is a measurement.
"""
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
# The run of every test of the table ends within this time or fails (judgment: three times the 300 s above which
# design B10 decision 4 asks for a note before anything changes; the run took 60 s on the collection PC, 2026-11-24).
RUN_TIMEOUT_S = 900


def _table():
    from scripts.tests import audit_probes
    return audit_probes


@pytest.fixture(scope="module")
def record():
    """{(area, risk id): {"A": the auditor's evidence, "V": the verifier's evidence and corrected statement, or None
    without a verdict}} of the record of the code audit."""
    doc = json.loads((ROOT / _table().RECORD).read_text())
    risks = {}
    for area in doc["values"]["dimensions"]:
        verdicts = {v["id"]: v for v in area["verify"]["verdicts"]}
        for risk in area["audit"]["risks"]:
            verdict = verdicts.get(risk["id"])
            risks[area["key"], risk["id"]] = {
                "A": risk["evidence"],
                "V": None if verdict is None else verdict["evidence"] + "\n" + verdict["corrected_statement"]}
    return risks


def _name(risks):
    return ", ".join(f"{area} {rid}" for area, rid in risks)


def problems(record, classes, rows, skeleton):
    """Every way the table breaks the design's decisions 1 and 2, sorted (empty: none)."""
    table = _table()
    out = [f"risk {_name([key])} of the record has no class" for key in record if key not in classes]
    out += [f"class of {_name([key])}, which the record does not hold" for key in classes if key not in record]
    out += [f"class {cls} of {_name([key])} is none of {', '.join(table.CLASS_NAMES)}"
            for key, (cls, _, _) in classes.items() if cls not in table.CLASS_NAMES]
    out += [f"row {row.number} names {_name([key])}, which the record does not hold"
            for row in rows for key in row.risks if key not in record]
    placed = Counter(key for row in rows for key in row.risks)
    out += [f"risk {_name([key])} of class P has no row" for key, (cls, _, _) in classes.items()
            if cls == "P" and not placed[key]]
    out += [f"risk {_name([key])} sits in {count} rows" for key, count in placed.items() if count > 1]
    numbers = [row.number for row in rows]
    if numbers != list(range(1, len(rows) + 1)):
        out.append(f"the rows are numbered {numbers}, not 1 to {len(rows)}")
    for n, (risks, packages) in enumerate(skeleton, 1):
        match = [row for row in rows if set(row.risks) == set(risks)]
        if not match:
            out.append(f"row {n} of the skeleton ({_name(risks)}) has no row")
            continue
        if match[0].number != n:
            out.append(f"row {match[0].number} holds row {n} of the skeleton ({_name(risks)})")
        fixed = [package for package, _ in match[0].fixed]
        if not (all(any(p.startswith(s) for s in packages) for p in fixed)
                and all(any(p.startswith(s) for p in fixed) for s in packages)):
            out.append(f"row {match[0].number}: packages {', '.join(fixed)} are not the skeleton's "
                       f"{', '.join(packages)}")
    rows_of_skeleton = [set(risks) for risks, _ in skeleton]
    for row in rows:
        if set(row.risks) not in rows_of_skeleton and not any(classes.get(key, ("",))[0] == "P" for key in row.risks):
            out.append(f"row {row.number} is no row of the skeleton and holds no risk of class P")
        if row.kind not in table.KINDS or not row.tests or not row.reasons or not row.fixed:
            out.append(f"row {row.number} lacks its kind, a test, a reason or a fix")
    return sorted(out)


def phrase_problems(record, classes):
    """A class whose reader has no text in the record, or whose phrase is not verbatim in that text."""
    table, out = _table(), []
    for key, (cls, reader, phrase) in classes.items():
        text = record.get(key, {}).get(reader)
        if reader not in table.READERS or text is None:
            out.append(f"{_name([key])}: the record holds no text of reader {reader}")
        elif phrase not in text:
            out.append(f"{_name([key])}: {phrase!r} is not in {table.READERS[reader]}")
    return out


def _git(*args):
    done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True)
    return done.stdout.strip()


def commit_problems(rows, git=_git):
    """A fixing commit whose subject does not name its package, fixes out of time order, or a `before` that is not
    the parent of the oldest fix (skeleton 6: of two packages the older one)."""
    out = []
    for row in rows:
        full = [git("rev-parse", commit + "^{commit}") for _, commit in row.fixed]
        for (package, commit), sha in zip(row.fixed, full):
            if f"package {package}:" not in git("log", "-1", "--format=%s", sha):
                out.append(f"row {row.number}: commit {commit} does not name package {package}")
        if any(git("merge-base", a, b) != a for a, b in zip(full, full[1:])):
            out.append(f"row {row.number}: the fixes are not oldest first")
        if git("rev-parse", row.before + "^{commit}") != git("rev-parse", full[0] + "^"):
            out.append(f"row {row.number}: before {row.before} is not the parent of {row.fixed[0][1]}")
    return out


def reason_problems(rows, root=ROOT):
    """An exact reason that does not stand verbatim on its line; the message names the lines that hold it now."""
    out = []
    for row in rows:
        for text, where in row.reasons:
            path, line = where.rsplit(":", 1)
            lines = (root / path).read_text().splitlines()
            if not 0 < int(line) <= len(lines) or text not in lines[int(line) - 1]:
                found = [i for i, source in enumerate(lines, 1) if text in source]
                out.append(f"row {row.number}: {text!r} is not on {where} (it stands on lines {found})")
    return out


def test_the_table_has_a_class_for_every_risk_and_a_row_for_every_probe_and_skeleton_row(record):
    table = _table()
    assert len(record) == 72 and len(table.ROWS) == 18 and len(table.SKELETON) == 15
    assert problems(record, table.CLASSES, table.ROWS, table.SKELETON) == []
    # The classes of the code map's definitions (MAPA_KODU section 1; GF-8 read as C, the module's docstring).
    assert Counter(cls for cls, _, _ in table.CLASSES.values()) == {"P": 11, "D": 6, "C": 9, "N": 46}
    assert [row.kind for row in table.ROWS if row.kind != "refusal"] == ["limit", "status"]  # Rows 9 and 11.
    assert [row.number for row in table.ROWS if row.kind != "refusal"] == [9, 11]


def _without_class(classes, rows, skeleton):
    return {key: value for key, value in classes.items() if key != ("process", "R12")}, rows, skeleton


def _without_row_17(classes, rows, skeleton):
    return classes, rows[:16] + (rows[17]._replace(number=17),), skeleton


def _skeleton_row_more(classes, rows, skeleton):
    return classes, rows, skeleton + (((("process", "R12"),), ("B9",)),)


def _twice(classes, rows, skeleton):
    return classes, rows[:15] + (rows[15]._replace(risks=rows[15].risks + (("capture", "R5"),)),) + rows[16:], skeleton


def _other_package(classes, rows, skeleton):
    return classes, rows[:6] + (rows[6]._replace(fixed=(("B5a", "2a95852"),)),) + rows[7:], skeleton


def _extra_row(classes, rows, skeleton):
    return classes, rows + (rows[17]._replace(number=19, risks=(("process", "R12"),)),), skeleton


@pytest.mark.parametrize("change, expected", [
    (None, []),
    (_without_class, ["risk process R12 of the record has no class"]),
    (_without_row_17, ["risk capture R11 of class P has no row"]),
    (_skeleton_row_more, ["row 16 of the skeleton (process R12) has no row"]),
    (_twice, ["risk capture R5 sits in 2 rows"]),
    (_other_package, ["row 7: packages B5a are not the skeleton's B4"]),
    (_extra_row, ["row 19 is no row of the skeleton and holds no risk of class P"]),
], ids=["as_it_is", "risk_without_class", "probe_without_row", "skeleton_row_without_row", "risk_in_two_rows",
        "package_not_the_skeletons", "row_without_a_reason_to_be"])
def test_each_check_of_the_table_names_its_break(record, change, expected):
    """Design decision 2: a risk id of the record without a class, a risk of class P without a row and a row of the
    skeleton without a row each fail the table, and so do a risk in two rows, a fix of another package than the
    skeleton's and a row that is neither a row of the skeleton nor one of a probe."""
    table = _table()
    classes, rows, skeleton = table.CLASSES, table.ROWS, table.SKELETON
    if change is not None:
        classes, rows, skeleton = change(classes, rows, skeleton)
    assert problems(record, classes, rows, skeleton) == sorted(expected)


@pytest.mark.parametrize("change, expected", [
    (None, []),
    (("capture", "R5", "V", "a probe with lateness 4.0 s in one sidecar was accepted"),
     ["capture R5: 'a probe with lateness 4.0 s in one sidecar was accepted' is not in the verifier's evidence or "
      "corrected statement"]),
    (("capture", "R11", "V", "probe: sidecars without capture.queue_wait_ms were accepted"),
     ["capture R11: the record holds no text of reader V"]),
], ids=["as_it_is", "phrase_not_in_the_record", "verdict_absent"])
def test_each_class_rests_on_a_phrase_of_the_record(record, change, expected):
    classes = dict(_table().CLASSES)
    if change is not None:
        area, rid, reader, phrase = change
        classes[area, rid] = (classes[area, rid][0], reader, phrase)
    assert phrase_problems(record, classes) == expected


@pytest.mark.parametrize("change, expected", [
    (None, []),
    ({"before": "0b3c276"}, ["row 1: before 0b3c276 is not the parent of 0b3c276"]),
    ({"fixed": (("B5a", "2a95852"), ("B3", "0b3c276"))},
     ["row 1: the fixes are not oldest first", "row 1: before c39accb is not the parent of 2a95852"]),
    ({"fixed": (("B4", "0b3c276"),)}, ["row 1: commit 0b3c276 does not name package B4"]),
], ids=["as_it_is", "before_is_the_fix", "fixes_out_of_order", "package_not_in_the_subject"])
def test_the_before_commit_is_the_parent_of_the_oldest_fix(change, expected):
    table = _table()
    rows = table.ROWS if change is None else (table.ROWS[0]._replace(**change),)
    assert commit_problems(rows) == expected


def test_each_exact_reason_stands_on_its_line():
    table = _table()
    assert reason_problems(table.ROWS) == []
    moved = table.ROWS[0]._replace(reasons=(("cycle start later than the audit bound", "scripts/collection.py:1"),))
    lines = [i for i, source in enumerate((ROOT / "scripts/collection.py").read_text().splitlines(), 1)
             if "cycle start later than the audit bound" in source]
    assert reason_problems([moved]) == [
        f"row 1: 'cycle start later than the audit bound' is not on scripts/collection.py:1 (it stands on lines "
        f"{lines})"]


def test_every_test_of_the_table_exists_and_passes(tmp_path, request):
    """Design decision 4: every test id of the table is collected, then all of them run in one pytest of their own
    under this test's tmp_path, and each passes (none skipped). The run's time is printed and kept as the user
    property seconds of this test. No test of this file is in the table, and none of table.GONE."""
    table = _table()
    ids = [test for row in table.ROWS for test in row.tests]
    assert len(set(ids)) == len(ids) and not set(ids) & set(table.GONE)
    assert not any(test.startswith("scripts/tests/test_audit_probes.py::") for test in ids)
    base = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "--basetemp"]
    collected = subprocess.run([*base, str(tmp_path / "collect"), "--collect-only", "-q", *ids], cwd=ROOT,
                               capture_output=True, text=True, timeout=RUN_TIMEOUT_S)
    assert collected.returncode == 0, collected.stdout[-3000:] + collected.stderr[-3000:]
    assert sorted(line for line in collected.stdout.splitlines() if "::" in line) == sorted(ids)
    start = time.monotonic()
    run = subprocess.run([*base, str(tmp_path / "run"), "-q", "-rA", *ids], cwd=ROOT, capture_output=True, text=True,
                         timeout=RUN_TIMEOUT_S)
    seconds = round(time.monotonic() - start, 1)
    request.node.user_properties.append(("seconds", seconds))
    print(f"the {len(ids)} tests of the table ran in {seconds} s")
    passed = sorted(line[len("PASSED "):] for line in run.stdout.splitlines() if line.startswith("PASSED "))
    assert (run.returncode, passed) == (0, sorted(ids)), run.stdout[-5000:]
