"""Register of periodic processes in the guest (lab/periods.json, proposal 5.6, KOSTRA B5 section 5 item 6).

The scan finds in the deployed files of lab/ every Restart= of a unit (also in a .conf drop-in), every timer (a
systemd one and nginx's log flush) and every loop that sleeps or waits (also in code another process runs:
python3 -c and bash -c strings), and the test fails on one the
register does not name at its source line, or on a register line that no longer points at one. A process
creating entry must be bounded or have a random delay (proposal 5.6).
"""
import ast
import json
from pathlib import Path
import re
import shutil

import pytest

LAB = Path(__file__).resolve().parents[1]
DISCOVERED = ("restart", "timer", "loop")  # Kinds the scan finds; "system" entries are declared only.
SLEEPS = {"sleep", "wait", "pg_sleep"}  # A loop that calls one of these waits between rounds.
LOOPS = {"serve_forever"}  # Calls that are themselves a waiting loop (socketserver polls every 0.5 s).
TIMER = re.compile(r"On(Calendar|ActiveSec|BootSec|StartupSec|UnitActiveSec|UnitInactiveSec)\s*=")
# A .conf file is a systemd drop-in or a configuration of nginx (finding F1 of the B5a verification: nginx flushes
# its buffered access log on a timer); .sql and .json are data the scripts read, with no loop of their own.
SCANNED = {".py", ".sh", ".service", ".timer", ".conf"}
NOT_PERIODIC = {".sql", ".json"}
NGINX_TIMER = re.compile(r"\bflush=\d")  # access_log ... flush=<time>: a write at least that often.


def unit_items(text):
    found = set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        restart = re.match(r"Restart\s*=\s*(\S+)", line)
        if restart and restart[1] != "no":
            found.add(("restart", number))
        if TIMER.match(line):
            found.add(("timer", number))
    return found


def shell_items(text):
    """Shell loops (for, while, until ... done) that run sleep; each open loop at its first line."""
    found, open_loops = set(), []
    for number, line in enumerate(text.splitlines(), 1):
        for token in re.findall(r"[A-Za-z_]+", line.split("#", 1)[0]):
            if token in ("for", "while", "until"):
                open_loops.append(number)
            elif token == "done" and open_loops:
                open_loops.pop()
            elif token == "sleep":
                found.update(("loop", n) for n in open_loops)
    return found


def _calls(node):
    """Calls inside node, not inside a nested function, class or lambda."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, ast.Call):
            yield child
        stack.extend(ast.iter_child_nodes(child))


def _name(call):
    return getattr(call.func, "attr", None) or getattr(call.func, "id", None)


def string_items(text):
    """Periodic code in a string another process runs (python3 -c, bash -c, a unit file written by a script)."""
    try:
        found = python_items(text)
    except SyntaxError:
        found = set()
    return {kind for kind, _ in found | shell_items(text) | unit_items(text)}


CODE = re.compile(r"\b(sleep|wait)\b|Restart=|" + TIMER.pattern)  # A string that may hold periodic code.


def python_items(text):
    tree = ast.parse(text)
    docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                  if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                  and node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and any(_name(c) in SLEEPS for c in _calls(node)):
            found.add(("loop", node.lineno))
        elif isinstance(node, ast.Call) and _name(node) in LOOPS:
            found.add(("loop", node.lineno))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
              and CODE.search(node.value)):
            found.update((kind, node.lineno) for kind in string_items(node.value))
    return found


def scan(lab):
    """{(kind, "lab/<file>:<line>")} of every periodic construct in the top-level files of `lab`."""
    found = set()
    for path in sorted(p for p in lab.iterdir() if p.is_file()):
        text = path.read_text()
        if path.suffix == ".py":
            items = python_items(text)
        elif path.suffix == ".sh":
            items = shell_items(text)
        elif path.suffix in (".service", ".timer"):
            items = unit_items(text)
        elif path.suffix == ".conf":
            items = unit_items(text) | {("timer", n) for n, line in enumerate(text.splitlines(), 1)
                                        if NGINX_TIMER.search(line.split("#", 1)[0])}
        else:
            items = set()
        found.update((kind, f"lab/{path.name}:{line}") for kind, line in items)
    return found


def compare(lab, register):
    """(unregistered, stale): constructs the register does not name, register lines that point at none."""
    named = {(e["kind"], e["source"]) for e in register["periods"] if e["kind"] in DISCOVERED}
    found = scan(lab)
    return sorted(found - named), sorted(named - found)


def register():
    return json.loads((LAB / "periods.json").read_text())


def test_register_names_every_periodic_construct_of_lab_at_its_line():
    unregistered, stale = compare(LAB, register())
    assert unregistered == [], "periodic constructs missing in lab/periods.json"
    assert stale == [], "lab/periods.json names lines without a periodic construct"


def test_every_deployed_file_type_is_scanned_or_known_to_have_no_loop():
    suffixes = {p.suffix for p in LAB.iterdir() if p.is_file()}
    assert suffixes <= SCANNED | NOT_PERIODIC, sorted(suffixes - SCANNED - NOT_PERIODIC)


def test_entries_are_complete_and_process_creating_ones_are_bounded_or_random():
    doc = register()
    assert doc["schema"] == "hyptcn3/lab-periods/1"
    names = [e["name"] for e in doc["periods"]]
    assert len(names) == len(set(names))
    for entry in doc["periods"]:
        # "exception": only a process outside the lab's code, with the decision that admits it (proposal 5.6).
        assert set(entry) - {"exception"} == {"name", "source", "kind", "period_s", "random_s", "bounded",
                                               "creates_processes", "active", "note"}, entry["name"]
        assert "exception" not in entry or entry["kind"] == "system" and "Q3" in entry["exception"], entry["name"]
        assert entry["kind"] in (*DISCOVERED, "system"), entry["name"]
        assert entry["period_s"] is None or entry["period_s"] > 0, entry["name"]
        random_s = entry["random_s"]
        assert random_s == 0 or (len(random_s) == 2 and random_s[0] < random_s[1]), entry["name"]
        assert type(entry["creates_processes"]) is bool and type(entry["active"]) is bool, entry["name"]
        if entry["creates_processes"] and entry["active"]:  # Proposal 5.6, independent of the ratio to 5 s.
            assert entry["bounded"] or random_s != 0 or "exception" in entry, entry["name"]
        if entry["source"].startswith("lab/"):
            name, line = entry["source"][4:].rsplit(":", 1)
            assert 1 <= int(line) <= len((LAB / name).read_text().splitlines()), entry["name"]


def _entry(kind, prefix):
    return next(e for e in register()["periods"] if e["kind"] == kind and e["source"].startswith(prefix))


def test_bounds_and_random_delays_of_the_register_are_those_of_the_source():
    unit = (LAB / "hyptcn-lab@.service").read_text()
    head = unit.split("[Service]", 1)[0]  # StartLimit* belong to [Unit].
    burst, interval = (int(re.search(rf"^{key}=(\d+)$", head, re.M)[1]) for key in ("StartLimitBurst",
                                                                                       "StartLimitIntervalSec"))
    assert (burst, interval) == (5, 60)  # KOSTRA B5 section 1.
    restart = _entry("restart", "lab/hyptcn-lab@.service:")
    assert f"StartLimitBurst={burst}" in restart["bounded"] and f"StartLimitIntervalSec={interval}" in restart["bounded"]
    timer_text = (LAB / "hyptcn-lab-udrzba.timer").read_text()
    timer = _entry("timer", "lab/hyptcn-lab-udrzba.timer:")
    assert timer["period_s"] == 60 * int(re.search(r"^OnCalendar=\*:0/(\d+)$", timer_text, re.M)[1]) == 600
    assert timer["random_s"] == [0, int(re.search(r"^RandomizedDelaySec=(\d+)$", timer_text, re.M)[1])] == [0, 300]
    assert re.search(r"^AccuracySec=1s$", timer_text, re.M) and re.search(r"^WantedBy=timers.target$", timer_text, re.M)
    low, high = map(float, re.search(r"^PAUSE_S = \(([\d.]+), ([\d.]+)\)$", (LAB / "services.py").read_text(), re.M)
                    .groups())
    worker = _entry("loop", "lab/services.py:")
    mean = (low + high) / 2
    assert (low, high) == (.8, 1.2) and worker["period_s"] == mean
    assert worker["random_s"] == [round(low - mean, 6), round(high - mean, 6)]
    # Autovacuum stays at PostgreSQL's default (lead's answer to Q3): no lab file changes it, the register lists it
    # as the one admitted exception, and the deployment does not touch PostgreSQL's configuration.
    assert not (LAB / "hyptcn-lab-postgresql.conf").exists() and "autovacuum" not in (LAB / "install.sh").read_text()
    autovacuum = next(e for e in register()["periods"] if e["name"] == "PostgreSQL autovacuum launcher")
    assert autovacuum["active"] is True and autovacuum["bounded"] is None and autovacuum["random_s"] == 0
    assert [e["name"] for e in register()["periods"] if "exception" in e] == ["PostgreSQL autovacuum launcher"]


@pytest.mark.parametrize("name,text,kind,line", [
    ("hyptcn-lab-extra.service", "[Service]\nExecStart=/bin/true\nRestart=always\n", "restart", 3),
    ("hyptcn-lab-extra.timer", "[Timer]\nOnUnitActiveSec=30s\n", "timer", 2),
    ("extra.py", "import time\n\n\ndef poll():\n    while True:\n        time.sleep(5)\n", "loop", 5),
    ("extra.sh", "#!/bin/sh\nwhile true; do\n    curl -fsS http://127.0.0.1:8080/healthz\n    sleep 5\ndone\n",
     "loop", 2),
    ("extra2.py", "import subprocess\nsubprocess.Popen(['bash', '-c', 'for i in 1 2 3; do date; sleep 2; done'])\n",
     "loop", 2),
    ("extra3.py", "DROPIN = '[Service]\\nRestart=always\\nRestartSec=1\\n'\n", "restart", 1),
    ("hyptcn-lab-catalog-override.conf", "[Service]\nRestart=always\nRestartSec=1\n", "restart", 2),
    ("extra-nginx.conf", "server {\n    access_log /var/log/x.jsonl json buffer=8k flush=5s;\n}\n", "timer", 2),
])
def test_an_unregistered_restart_timer_or_sleeping_loop_fails(tmp_path, name, text, kind, line):
    copy = tmp_path / "lab"
    shutil.copytree(LAB, copy, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    assert compare(copy, register()) == ([], [])
    (copy / name).write_text(text)
    assert compare(copy, register()) == ([(kind, f"lab/{name}:{line}")], [])


def test_a_register_line_that_moved_fails(tmp_path):
    doc = register()
    entry = next(e for e in doc["periods"] if e["source"].startswith("lab/services.py:"))
    entry["source"] = entry["source"].rsplit(":", 1)[0] + ":1"
    unregistered, stale = compare(LAB, doc)
    assert stale == [(entry["kind"], "lab/services.py:1")] and len(unregistered) == 1
