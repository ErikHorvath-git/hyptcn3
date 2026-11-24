"""The test of the table of the audit's probes (protocol v5, package B10, agent A; skeleton B10 1.2, design B10 decisions
2 to 4).

The table is scripts/tests/audit_probes.py. Its checks:
    problems()         the classification holds exactly the 72 risk ids of the record; every risk of class P and every
                       row of the lead's skeleton section 2 has its row (design decision 2), rows 1 to 15 are the
                       skeleton's rows in its order with its packages, beside which only a later fix of B10 stands
                       (LATER, with the item it fixes; the verification of B10, F2), and every further row holds a
                       risk of class P; the item of a later fix is a deferred item of a package of its row or the
                       lead's answer (the verification of B10, N1);
    phrase_problems()  each class rests on a phrase that stands verbatim in its reader's text of the record;
    commit_problems()  the fixing commits name their package (a later fix of B10 its package and its item, and it is
                       a commit of one parent tied to its row by the lines it adds: the verification of B10, N1) and
                       `before` is the parent of the oldest (skeleton 6);
    reason_problems()  each exact reason stands verbatim on its line of the file (design decision 3);
and every test id of the table exists and passes in one run of its own (design decision 4). Each check has its good
input (the table as it is) and, where the design names the failure, one bad input with exactly its problem. That every
test of the table fails on its commit `before` is the record dokazy/B10/pred_po/, and dokazy/B10/pred_po_zlucene/ for
the merged tree (design decision 5), not a test here. The table, a module of package B10, is imported inside the tests
(_table), so this file collects on the code before B10 and fails there test by test. Only a table and its checks: no
number here is a measurement.
"""
import ast
from collections import Counter
import json
from pathlib import Path
import re
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


# The forms of the item of a later fix (the verification of B10, N1); problems() gives their derivation.
PACKAGE = r"B[1-9]\d*[a-z]?"
FINDING = r"[SFNPV][1-9]\d*\+?"
DEFERRED = re.compile(rf"(?P<package>{PACKAGE}) {FINDING}|{FINDING} of (?P<of>{PACKAGE})")
ANSWER = re.compile(r"Q[1-9]\d*")


def later_item(item):
    """The package of the item of a later fix when it is a deferred item, "" when it is the lead's answer, and None
    when it is neither (the forms of problems())."""
    if ANSWER.fullmatch(item):
        return ""
    match = DEFERRED.fullmatch(item)
    return None if match is None else match["package"] or match["of"]


def problems(record, classes, rows, skeleton):
    """Every way the table breaks the design's decisions 1 and 2, sorted (empty: none).

    The item of a later fix (LATER, commit, item) is a deferred item or the lead's answer (the verification of B10,
    N1). The forms come from the deferred lists dokazy/*/odlozene*.md and the lead's questions OTAZKY_VEDUCEMU.md
    (both under /home/eh/hyptcn3-logs/v5/, as they stood on 2026-11-24; later_item() holds the forms, and nothing here
    reads those files):
      - each deferred list belongs to one package, named in its file name (B5/odlozene_B5a.md) or by its directory
        (B3/odlozene.md): B, the package's number and the letter of a part, PACKAGE. The lists are those of B2, B3,
        B4, B4b, B5a, B5b, B5c, B6a, B6b, B7a, B7b, B7c, B8, B9a, B9b, B10 and B11;
      - its items carry ids, in the first column of its table (at the head of each bullet in B4b's list): a letter
        and a number, FINDING. These are S1 to S11 (the should_fix of B3, B4, B4b and B8), F1 to F8 (B5a to B7a),
        N1 to N5 (the new findings of a confirmation), P1 to P5 (B10) and V1 to V4 (B11), and once a plus (F1+ of
        B5b). B2 numbers its points without a letter, and the rows marked "—" have no id, so neither has a form here
        (no subject of B10 names one);
      - one id stands in several lists (S1 in those of B3, B4, B4b and B8), so a deferred item names its package,
        DEFERRED: "B3 S1", or the id "of" the package as the subjects of eba487a and e687235 write it ("V1 of B11",
        "V2 of B11");
      - every question of the lead is a heading "## Q<number> (...)", Q1 to Q30, so the lead's answer is Q and its
        number, ANSWER: "Q29".
    A bare id ("V1", "G1"), a package alone ("B10") or a word ("agent") is none of these. The package of a deferred
    item is the package of another fix of its row (the executor's judgment, G2 preparation: B10 makes the deferred
    fixes of the closed packages, design B10 decision 6, so a later fix completes what a package that fixed the row
    left for later; B5b F4 on row 4, a probe of N1, is of B5b, which fixed nothing of row 4). The lead's answer is of
    no package."""
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
        named = [entry[0] for entry in match[0].fixed]
        fixed = [package for package in named if package != table.LATER]  # A later fix of B10 stands beside them.
        if not (all(any(p.startswith(s) for s in packages) for p in fixed)
                and all(any(p.startswith(s) for p in fixed) for s in packages)):
            out.append(f"row {match[0].number}: packages {', '.join(named)} are not the skeleton's "
                       f"{', '.join(packages)}")
    rows_of_skeleton = [set(risks) for risks, _ in skeleton]
    for row in rows:
        if set(row.risks) not in rows_of_skeleton and not any(classes.get(key, ("",))[0] == "P" for key in row.risks):
            out.append(f"row {row.number} is no row of the skeleton and holds no risk of class P")
        if row.kind not in table.KINDS or not row.tests or not row.reasons or not row.fixed:
            out.append(f"row {row.number} lacks its kind, a test, a reason or a fix")
        for entry in row.fixed:  # (package, commit), or (LATER, commit, item) for a later fix of B10.
            if not (len(entry) == 2 and entry[0] != table.LATER
                    or len(entry) == 3 and entry[0] == table.LATER and type(entry[2]) is str and entry[2]):
                out.append(f"row {row.number}: fix {entry} is neither (package, commit) nor ({table.LATER}, commit, "
                           "item)")
            elif len(entry) == 3:  # A later fix: its item's form and package (N1).
                package = later_item(entry[2])
                if package is None:
                    out.append(f"row {row.number}: item {entry[2]!r} is neither a deferred item (a package and its "
                               "finding) nor the lead's answer (Q and its number)")
                elif package and package not in [other[0] for other in row.fixed if other[0] != table.LATER]:
                    out.append(f"row {row.number}: item {entry[2]} is of package {package}, which none of the row's "
                               "other fixes is")
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
    """A fixing commit whose subject does not name its package, fixes out of time order, or a `before` that is not the
    parent of the oldest fix (skeleton 6: of two packages the older one).

    A later fix (LATER, commit, item) of B10 is accepted only when these hold, in this order; the first that fails is
    its message (the verification of B10, F2 and N1; the form and the package of its item are problems()'s):
        1. the commit's subject names package B10 as a word and the item as a whole phrase (F2);
        2. the commit has one parent P: a merge only carries the fixes of its parents, and the entry names the commit
           that made its fix (the merge 1044114 of agent Q's a446043 is a probe of N1);
        3. the commit is tied to the row (N1). It changes one of the row's test files, the files F of its test ids
           F::T and F::T[I] (git diff --name-only P commit), and it adds one of the lines below. An added line is a
           line that `git diff -U0 P commit` marks with +, numbered as in the commit's version of its file (a changed
           line is one; a removed line is none), and that version is read with git's own line numbers
           (git grep -n '' commit -- F):
             - a line of the row's test function: a line of F inside the definition of T in the commit's F (in its
               class, for F::C::T), from its first decorator to its last line (ast), so with its parametrization;
             - a line of the row's case id I: a line of F inside the definition of the function named I at the top
               level of F (a case given by its function, as FILE_CASES of test_protocol_v5.py gives them), or a line
               of F, outside every function and class of F, that holds a string constant equal to I (a table of
               cases);
             - a line of the row's reason: a line of the reason's file that holds the reason's text.
           A case id that a case module defines (scripts/tests/audit_cases.py and audit_cases_logs.py, for the cases
           of the self-test) stands in no line of F, so such a case ties a commit only through T or a reason."""
    later, out = _table().LATER, []
    for row in rows:
        full = [git("rev-parse", entry[1] + "^{commit}") for entry in row.fixed]
        for entry, sha in zip(row.fixed, full):
            package, commit, subject = entry[0], entry[1], git("log", "-1", "--format=%s", sha)
            if package != later:
                if f"package {package}:" not in subject:
                    out.append(f"row {row.number}: commit {commit} does not name package {package}")
            elif not re.search(rf"\bpackage {later}\b", subject):
                out.append(f"row {row.number}: commit {commit} does not name package {later}")
            elif len(entry) < 3 or not re.search(rf"(?<!\w){re.escape(str(entry[2]))}(?!\w)", subject):
                item = entry[2] if len(entry) > 2 else None
                out.append(f"row {row.number}: commit {commit} does not name the item {item}")
            else:
                problem = _later_commit_problem(row, sha, git)
                if problem is not None:
                    out.append(f"row {row.number}: commit {commit} {problem}")
        if any(git("merge-base", a, b) != a for a, b in zip(full, full[1:])):
            out.append(f"row {row.number}: the fixes are not oldest first")
        if git("rev-parse", row.before + "^{commit}") != git("rev-parse", full[0] + "^"):
            out.append(f"row {row.number}: before {row.before} is not the parent of {row.fixed[0][1]}")
    return out


def _test_file(test):
    """The file F of a test id F::T or F::T[I]."""
    return test.partition("[")[0].split("::")[0]


def _later_commit_problem(row, sha, git):
    """Conditions 2 and 3 of commit_problems() for the commit sha of a later fix of the row (None: both hold)."""
    parents = git("log", "-1", "--format=%P", sha).split()
    if len(parents) != 1:
        return f"has {len(parents)} parents, not one"
    paths = sorted({_test_file(test) for test in row.tests} | {where.rsplit(":", 1)[0] for _, where in row.reasons})
    changed = [path for path in git("diff", "--name-only", "--no-renames", parents[0], sha, "--", *paths).split("\n")
               if path]
    added = {path: _added(git("diff", "-U0", "--no-color", "--no-ext-diff", "--no-renames", parents[0], sha, "--",
                              path)) for path in changed}
    return tie_problem(row, changed, added, lambda path: _version(git, sha, path))


def _added(diff):
    """{number: text} of the lines a `git diff -U0` of one file adds, numbered as in its new version."""
    out, number = {}, None
    for line in diff.split("\n"):
        if line.startswith("@@"):
            number = int(re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)[1])
        elif number is not None and line.startswith("+"):
            out[number] = line[1:]
            number += 1
    return out


def _version(git, sha, path):
    """The text of path in commit sha from `git grep -n '' sha -- path`: every line comes with git's number, so the
    numbers stay those of the diff although git() strips its output."""
    prefix, lines = f"{sha}:{path}:", []
    for line in git("grep", "-n", "--no-color", "--no-column", "-e", "", sha, "--", path).split("\n"):
        number, colon, text = line.removeprefix(prefix).partition(":")
        if not (line.startswith(prefix) and colon and number == str(len(lines) + 1)):
            raise ValueError(f"line {len(lines) + 1} of {path} in {sha} is not in git grep's output: {line!r}")
        lines.append(text)
    return "\n".join(lines)


def _definitions(body, names):
    """(first line, last line) of each function at the path names (its classes, then its name) among the statements
    body; a definition runs from its first decorator to its last line."""
    *classes, function = names
    for name in classes:
        body = [stmt for node in body if isinstance(node, ast.ClassDef) and node.name == name for stmt in node.body]
    return [(min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)]), node.end_lineno)
            for node in body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function]


def _module_strings(tree, value):
    """(first line, last line) of each string constant equal to value outside every function and class of tree."""
    return [(node.lineno, node.end_lineno) for stmt in tree.body
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            for node in ast.walk(stmt) if isinstance(node, ast.Constant) and type(node.value) is str
            and node.value == value]


def tie_problem(row, changed, added, source):
    """Condition 3 of commit_problems() (None: it holds) for a commit that changes the paths `changed` and adds the
    lines `added`, {path: {number: text}}; source(path) is the commit's version of a file."""
    if not {_test_file(test) for test in row.tests} & set(changed):
        return "changes none of the row's test files"
    trees = {}
    for test in row.tests:
        base, _, case = test.partition("[")
        path, *names = base.split("::")
        if not added.get(path):
            continue
        tree = trees[path] = trees.get(path) or ast.parse(source(path))
        spans = _definitions(tree.body, names)
        if case:
            spans += _definitions(tree.body, [case[:-1]]) + _module_strings(tree, case[:-1])
        if any(first <= line <= last for first, last in spans for line in added[path]):
            return None
    for text, where in row.reasons:
        if any(text in line for line in added.get(where.rsplit(":", 1)[0], {}).values()):
            return None
    return "adds no line of the row's test functions, case ids or reasons"


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


# The verification of B10, F2: a later fix of B10 stands beside the skeleton's packages, with its item, and only B10's.

def _later_fix_alone(classes, rows, skeleton):
    return classes, rows[:3] + (rows[3]._replace(fixed=rows[3].fixed[1:]),) + rows[4:], skeleton


def _later_fix_of_another_package(classes, rows, skeleton):
    return classes, rows[:3] + (rows[3]._replace(fixed=(("B3", "0b3c276"), ("B9b", "f700204"))),) + rows[4:], skeleton


def _later_fix_without_its_item(classes, rows, skeleton):
    return classes, rows[:4] + (rows[4]._replace(fixed=rows[4].fixed[:2] + (("B10", "a446043"),)),) + rows[5:], skeleton


def _item_of_a_skeleton_package(classes, rows, skeleton):
    return classes, (rows[0]._replace(fixed=(("B3", "0b3c276", "S1"),)),) + rows[1:], skeleton


@pytest.mark.parametrize("change, expected", [
    (None, []),
    (_without_class, ["risk process R12 of the record has no class"]),
    (_without_row_17, ["risk capture R11 of class P has no row"]),
    (_skeleton_row_more, ["row 16 of the skeleton (process R12) has no row"]),
    (_twice, ["risk capture R5 sits in 2 rows"]),
    (_other_package, ["row 7: packages B5a are not the skeleton's B4"]),
    (_extra_row, ["row 19 is no row of the skeleton and holds no risk of class P"]),
    (_later_fix_alone, ["row 4: packages B10 are not the skeleton's B3",
                        "row 4: item B3 S1 is of package B3, which none of the row's other fixes is"]),
    (_later_fix_of_another_package, ["row 4: packages B3, B9b are not the skeleton's B3"]),
    (_later_fix_without_its_item, ["row 5: fix ('B10', 'a446043') is neither (package, commit) nor (B10, commit, "
                                   "item)"]),
    (_item_of_a_skeleton_package, ["row 1: fix ('B3', '0b3c276', 'S1') is neither (package, commit) nor (B10, commit, "
                                   "item)"]),
], ids=["as_it_is", "risk_without_class", "probe_without_row", "skeleton_row_without_row", "risk_in_two_rows",
        "package_not_the_skeletons", "row_without_a_reason_to_be", "later_fix_alone", "later_fix_of_another_package",
        "later_fix_without_its_item", "item_of_a_skeleton_package"])
def test_each_check_of_the_table_names_its_break(record, change, expected):
    """Design decision 2: a risk id of the record without a class, a risk of class P without a row and a row of the
    skeleton without a row each fail the table, and so do a risk in two rows, a fix of another package than the
    skeleton's and a row that is neither a row of the skeleton nor one of a probe. The verification of B10, F2: beside
    the skeleton's packages a later fix of B10 stands with the item it fixes (rows 4 and 5 as they are), never alone,
    and the later fix of another package, a B10 fix without its item or an item on another fix still fail. The
    verification of B10, N1: the later fix alone also has an item of a package that none of its row's other fixes is."""
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
    # The verification of B10, F2: the commit of a later fix of B10 names package B10 and the item in its subject.
    ({"fixed": (("B3", "0b3c276"), ("B10", "2a95852", "B5a"))}, ["row 1: commit 2a95852 does not name package B10"]),
    ({"fixed": (("B3", "0b3c276"), ("B10", "a446043", "B3 S1"))},
     ["row 1: commit a446043 does not name the item B3 S1"]),
    # The verification of B10, N1: f0506e8, the later fix of row 4, is not tied to row 1 either.
    ({"fixed": (("B10", "f0506e8", "B3 S1"), ("B3", "0b3c276"))},
     ["row 1: commit f0506e8 adds no line of the row's test functions, case ids or reasons",
      "row 1: the fixes are not oldest first", "row 1: before c39accb is not the parent of f0506e8"]),
], ids=["as_it_is", "before_is_the_fix", "fixes_out_of_order", "package_not_in_the_subject", "later_fix_not_of_b10",
        "later_fix_of_another_item", "later_fix_before_the_skeletons"])
def test_the_before_commit_is_the_parent_of_the_oldest_fix(change, expected):
    table = _table()
    rows = table.ROWS if change is None else (table.ROWS[0]._replace(**change),)
    assert commit_problems(rows) == expected


# The verification of B10, N1: a later fix of B10 is tied to its row, and its item is a deferred item of a package of
# the row or the lead's answer.

def _later(rows, number, entry):
    """The table with entry as the later fix of row `number`, in place of the row's own (as the verifier's probe of
    N1, dokazy/B10/overenie/sondy/potvrdenie/sonda_f2.py, builds its variants)."""
    later = _table().LATER
    return tuple(row._replace(fixed=tuple(fix for fix in row.fixed if fix[0] != later) + (entry,))
                 if row.number == number else row for row in rows)


NO_FORM = "is neither a deferred item (a package and its finding) nor the lead's answer (Q and its number)"
UNTIED = "adds no line of the row's test functions, case ids or reasons"


@pytest.mark.parametrize("number, entry, by_problems, by_commits", [
    (5, ("B10", "f0506e8", "B3 S1"), [], [f"row 5: commit f0506e8 {UNTIED}"]),
    (5, ("B10", "1044114", "Q29"), [], ["row 5: commit 1044114 has 2 parents, not one"]),
    (5, ("B10", "a446043", "B10"), [f"row 5: item 'B10' {NO_FORM}"], []),
    (5, ("B10", "a446043", "agent"), [f"row 5: item 'agent' {NO_FORM}"], []),
    (4, ("B10", "f0506e8", "B5b F4"), ["row 4: item B5b F4 is of package B5b, which none of the row's other fixes is"],
     []),
    (4, ("B10", "cdfebae", "G1"), [f"row 4: item 'G1' {NO_FORM}"],
     ["row 4: commit cdfebae changes none of the row's test files"]),
], ids=["row_5_names_the_fix_of_row_4", "row_5_names_the_merge_of_its_fix", "item_is_the_word_b10",
        "item_is_the_word_agent", "row_4_names_another_item_of_its_commit", "row_4_names_the_injected_errors_of_g1"])
def test_each_wrong_later_fix_of_the_probe_is_refused_by_name(record, number, entry, by_problems, by_commits):
    """The six wrong later fixes of the verifier's probe of N1, which problems() and commit_problems() both passed at
    ecbc04a: D's fix of row 4 named on row 5, the merge 1044114 that carries agent Q's a446043, the items "B10" and
    "agent" (whole words of a446043's subject), another item of f0506e8 on row 4, and G's cdfebae for G1 on row 4.
    Each is refused with exactly its messages."""
    table = _table()
    rows = _later(table.ROWS, number, entry)
    assert (problems(record, table.CLASSES, rows, table.SKELETON), commit_problems([rows[number - 1]])) == (
        by_problems, by_commits)


@pytest.mark.parametrize("number, entry, expected", [
    (4, ("B10", "f0506e8", "S1 of B3"), []),
    (8, ("B10", "7eb6ac2", "B5b F1+"), []),
    (13, ("B10", "a446043", "Q29"), []),
    (4, ("B10", "f0506e8", "B3 S1, S3"), [f"row 4: item 'B3 S1, S3' {NO_FORM}"]),
    (4, ("B10", "f0506e8", "S1"), [f"row 4: item 'S1' {NO_FORM}"]),
    (4, ("B10", "f0506e8", "B3 A1"), [f"row 4: item 'B3 A1' {NO_FORM}"]),
    (5, ("B10", "a446043", "Q0"), [f"row 5: item 'Q0' {NO_FORM}"]),
    (4, ("B10", "f0506e8", "F4 of B5b"), ["row 4: item F4 of B5b is of package B5b, which none of the row's other "
                                          "fixes is"]),
    (5, ("B10", "a446043", "B5b F4"), ["row 5: item B5b F4 is of package B5b, which none of the row's other fixes "
                                       "is"]),
    (13, ("B10", "a446043", "B11 V1"), ["row 13: item B11 V1 is of package B11, which none of the row's other fixes "
                                        "is"]),
], ids=["id_of_its_package", "id_with_a_plus", "answer_on_a_row_of_any_package", "two_items", "bare_id",
        "name_of_a_mutant", "question_zero", "package_after_of", "other_part_of_the_skeletons_package",
        "package_whose_name_extends_the_rows"])
def test_the_item_of_a_later_fix_has_its_form_and_its_rows_package(record, number, entry, expected):
    """Mutant killers of the forms and the package of problems() (judged without git, so the commit plays no part):
    the spelling "<id> of <package>" (killed: no such spelling), an id with a plus (killed: no plus), and the lead's
    answer on a row of any package (killed: the package rule on the answer) pass; two items in one ("B3 S1, S3"; killed:
    a search instead of a whole match), a bare id (killed: an id without its package), a mutant's name, which no list
    uses as an id ("A1" of B8 S8 in f0506e8's subject; killed: any capital letter) and Q0 (killed: Q and any digits)
    have no form; and the package after "of" (killed: only the package in front read), B5b on row 5, whose fix is B5a
    (killed: the skeleton's B5 by prefix), and B11 on row 13 of B1 (killed: a package by prefix) fail the package."""
    table = _table()
    rows = _later(table.ROWS, number, entry)
    assert problems(record, table.CLASSES, rows, table.SKELETON) == expected


# A test file of a synthetic row for condition 3 of commit_problems(), line by line from 1.
TIE_FILE = "t/test_x.py"
TIE_SOURCE = "\n".join([
    '"""A test file."""',                                    # 1
    "import pytest",                                         # 2
    'CASES = ["zero", "three"]',                             # 3
    "def locked_to_grid(doc):",                              # 4
    "    return doc",                                        # 5
    "def helper():",                                         # 6
    '    return "zero"',                                     # 7
    '@pytest.mark.parametrize("cap", [0, 3], ids=CASES)',    # 8
    "def test_one(cap):",                                    # 9
    "    assert cap is not None",                            # 10
    "class TestGroup:",                                      # 11
    "    def test_two(self):",                               # 12
    "        assert True",                                   # 13
])
REASON = ("refused for a reason", "src/code.py:7")


@pytest.mark.parametrize("tests, changed, added, expected", [
    ((TIE_FILE + "::test_one[three]",), [TIE_FILE], {TIE_FILE: {8: "@pytest..."}}, None),
    ((TIE_FILE + "::test_p[locked_to_grid]",), [TIE_FILE], {TIE_FILE: {5: "    return doc"}}, None),
    ((TIE_FILE + "::test_one[zero]",), [TIE_FILE], {TIE_FILE: {3: 'CASES = ["zero", "three"]'}}, None),
    ((TIE_FILE + "::TestGroup::test_two",), [TIE_FILE], {TIE_FILE: {13: "        assert True"}}, None),
    ((TIE_FILE + "::test_one",), [TIE_FILE, "src/code.py"],
     {TIE_FILE: {2: "import pytest"}, "src/code.py": {7: '    raise ValueError("refused for a reason")'}}, None),
    ((TIE_FILE + "::test_one",), [TIE_FILE], {TIE_FILE: {2: "import pytest"}}, UNTIED),
    ((TIE_FILE + "::test_one[zero]",), [TIE_FILE], {TIE_FILE: {7: '    return "zero"'}}, UNTIED),
    (("t/test_y.py::test_q[zero]", TIE_FILE + "::test_one"), [TIE_FILE],
     {TIE_FILE: {3: 'CASES = ["zero", "three"]'}}, UNTIED),
    ((TIE_FILE + "::test_one",), [TIE_FILE, "src/other.py"],
     {TIE_FILE: {2: "import pytest"}, "src/other.py": {7: '    raise ValueError("refused for a reason")'}}, UNTIED),
    ((TIE_FILE + "::test_one",), ["src/code.py"], {"src/code.py": {7: '    raise ValueError("refused for a reason")'}},
     "changes none of the row's test files"),
], ids=["decorator_of_its_test", "function_of_its_case", "table_of_its_case", "method_of_its_test_class",
        "line_of_its_reason", "other_line_of_its_test_file", "string_of_its_case_in_another_function",
        "case_of_another_test_file", "reason_in_another_file", "reason_without_a_test_file"])
def test_a_later_fix_is_tied_to_its_row_by_a_line_its_commit_adds(tests, changed, added, expected):
    """Mutant killers of condition 3 of commit_problems(), on a synthetic row and commit (tie_problem() takes the
    changed paths, the added lines and the commit's version of the file, so no git runs). A line of the test's
    decorator (killed: a definition from its def line), of the function of its case (killed: no case function), of a
    module-level table that holds its case id (killed: no case table), of a method of its test class (killed: classes
    not followed) and of its reason in the reason's file (killed: no reason line) ties the commit. Another line of a
    test file (killed: any line of a test file ties), the case id as a string inside another function (killed: a
    string anywhere in the file), the case id of a test of another file (killed: a case looked up in every changed
    test file), the reason's text in another file (killed: the reason in any file) and a reason line without a change
    of a test file (killed: no test file needed) do not."""
    row = _table().ROWS[0]._replace(tests=tests, reasons=(REASON,))
    assert tie_problem(row, changed, added, {TIE_FILE: TIE_SOURCE}.__getitem__) == expected


def test_the_lines_a_diff_adds_and_the_version_of_a_file_keep_gits_numbers():
    """Mutant killers of the readers of commit_problems(). _added numbers the + lines of a `git diff -U0` from each
    hunk's new start, skips the removed lines and the file's header, and keeps a line whose text starts with ++
    (killed: counting removed lines; the old start; a header read as a line). _version rebuilds the commit's file
    from `git grep -n` and refuses a line it cannot place (killed: the number read up to the last colon; numbers not
    checked)."""
    diff = "\n".join(["diff --git a/f.py b/f.py", "index 1111111..2222222 100644", "--- a/f.py", "+++ b/f.py",
                      "@@ -3 +3 @@ def a():", "-    x = 1", "+    x = 2",
                      "@@ -10,0 +11,2 @@ def b():", "+    y = 3", "+++z",
                      "@@ -20,2 +21,0 @@ def c():", "-gone", "-gone too", "\\ No newline at end of file"])
    assert _added(diff) == {3: "    x = 2", 11: "    y = 3", 12: "++z"}

    def git(*output):
        def run(*args):
            assert args == ("grep", "-n", "--no-color", "--no-column", "-e", "", "c0ffee", "--", "f.py")
            return "\n".join(output)
        return run
    assert _version(git("c0ffee:f.py:1:first", "c0ffee:f.py:2:", "c0ffee:f.py:3:a: b"), "c0ffee", "f.py") == (
        "first\n\na: b")
    with pytest.raises(ValueError, match="^line 2 of f.py in c0ffee is not in git grep's output: "):
        _version(git("c0ffee:f.py:1:first", "c0ffee:f.py:3:third"), "c0ffee", "f.py")


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
