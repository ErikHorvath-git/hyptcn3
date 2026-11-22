"""Register of periodic processes on the host (scripts/host_periods.json; proposal 5.6, design B5b section 4, lead's
answer to Q4), in the manner of lab/tests/test_periods.py.

The scan finds in the sources of the host processes that run during a session every Restart= and RestartSec= of a
unit (also as a --property of systemd-run), every timer (On...= of a unit, --on-... of systemd-run) and every loop
that sleeps or waits, also in code another process runs (python3 -c and bash -c strings, the body of a shell here
document). The test fails on a construct the register does not name at its source line and on a register line that
no longer points at one. A process-creating active entry must be bounded or have a random delay (proposal 5.6). The
collection grid, the drift of two concurrent collectors and the host's timers outside the repository are declared
only (kind "system"); a schema-3 session records the latter at its start (session.json host_context.timers). The old
generator's user unit (scripts/labctl.py traffic) restarts at the collection period: it has the start limit of the
guest units and never starts under a protocol of schema 3. Names package B5b adds are read inside the tests.
"""
import ast
import json
from pathlib import Path
import re
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "scripts/host_periods.json"
# The host processes of a session (lead's answer to Q4): the runner with the collector's capture script, the traffic
# generator, the host monitor, labctl with the units it starts, the preflight check the runner starts at every
# session start (beside the other VM's measured phase), and the campaign runner with its waiting loops.
SOURCES = ("scripts/collection.py", "scripts/lab_capture.sh", "scripts/host_traffic.py", "scripts/host_monitor.py",
           "scripts/labctl.py", "scripts/lab_smoke.py", "scripts/campaign.py")
DISCOVERED = ("restart", "timer", "loop")  # Kinds the scan finds; "system" entries are declared only.
SLEEPS = {"sleep", "wait"}  # A loop that calls one of these waits between rounds (time.sleep, Event.wait, Popen.wait).
# Blocking calls that wait when given a timeout: queue get and put, Thread.join, select and poll (finding F1 of the
# B5b verification: the generator's log writer waited on queue.get(timeout=...) and was in no register).
BLOCKING = {"get", "put", "join", "select", "poll"}
LOOPS = {"serve_forever"}  # Calls that are themselves a waiting loop.
RESTART = re.compile(r"(?<![A-Za-z])Restart(Sec)?=(\S*)")
TIMER = re.compile(r"(?<![A-Za-z])On(Calendar|ActiveSec|BootSec|StartupSec|UnitActiveSec|UnitInactiveSec)="
                   r"|--on-(calendar|active|boot|startup|unit-active|unit-inactive)\b")
CODE = re.compile(r"\b(sleep|wait)\b|" + RESTART.pattern + "|" + TIMER.pattern)  # A string that may hold periodic code.
HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
FIELDS = {"name", "source", "kind", "period_s", "random_s", "bounded", "creates_processes", "active", "note"}


def unit_items(text):
    """Restart= other than no, RestartSec= and timers, at their lines, wherever a line holds them."""
    found = set()
    for number, line in enumerate(text.splitlines(), 1):
        for match in RESTART.finditer(line):
            if match[1] or match[2] != "no":
                found.add(("restart", number))
        if TIMER.search(line):
            found.add(("timer", number))
    return found


def shell_items(text):
    """Shell loops (for, while, until ... done) that run sleep or wait, each at its first line, and the units and
    timers of the script; the body of a here document is code of another process (string_items)."""
    found, open_loops, lines = set(), [], text.splitlines()
    number = 0
    while number < len(lines):
        line = lines[number]
        number += 1
        for kind, _ in unit_items(line):
            found.add((kind, number))
        for token in re.findall(r"[A-Za-z_]+", line.split("#", 1)[0]):
            if token in ("for", "while", "until"):
                open_loops.append(number)
            elif token == "done" and open_loops:
                open_loops.pop()
            elif token in SLEEPS:
                found.update(("loop", n) for n in open_loops)
        heredoc = HEREDOC.search(line)
        if heredoc:
            start = number
            body = []
            while number < len(lines) and lines[number].strip() != heredoc[2]:
                body.append(lines[number])
                number += 1
            number += 1  # The terminator line.
            found.update((kind, start) for kind in string_items("\n".join(body) + "\n"))
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
    """The kinds of periodic code in a string another process runs (python3 -c, bash -c, a unit or a drop-in)."""
    try:
        found = python_items(text)
    except SyntaxError:
        found = set()
    return {kind for kind, _ in found | shell_items(text) | unit_items(text)}


def _waits(call):
    """The call waits between rounds: a sleep or wait, or a blocking call given a timeout (a `timeout` keyword, the
    fourth argument of select, the argument of a poll object's poll)."""
    name = _name(call)
    if name in SLEEPS:
        return True
    if name not in BLOCKING:
        return False
    return (any(k.arg == "timeout" for k in call.keywords) or name == "select" and len(call.args) >= 4
            or name == "poll" and len(call.args) >= 1)


def python_items(text):
    tree = ast.parse(text)
    docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                  if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                  and node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and any(_waits(c) for c in _calls(node)):
            found.add(("loop", node.lineno))
        elif isinstance(node, ast.Call) and _name(node) in LOOPS:
            found.add(("loop", node.lineno))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
              and CODE.search(node.value)):
            found.update((kind, node.lineno) for kind in string_items(node.value))
    return found


def scan(root):
    """{(kind, "scripts/<file>:<line>")} of every periodic construct in the host sources under `root`."""
    found = set()
    for name in SOURCES:
        text = (root / name).read_text()
        items = python_items(text) if name.endswith(".py") else shell_items(text)
        found.update((kind, f"{name}:{line}") for kind, line in items)
    return found


def compare(root, register):
    """(unregistered, stale): constructs the register does not name, register lines that point at none."""
    named = {(e["kind"], e["source"]) for e in register["periods"] if e["kind"] in DISCOVERED}
    found = scan(root)
    return sorted(found - named), sorted(named - found)


def register():
    return json.loads(REGISTER.read_text())


def _entry(name):
    return next(e for e in register()["periods"] if e["name"] == name)


def test_register_names_every_periodic_construct_of_the_host_at_its_line():
    unregistered, stale = compare(ROOT, register())
    assert unregistered == [], "periodic constructs missing in scripts/host_periods.json"
    assert stale == [], "scripts/host_periods.json names lines without a periodic construct"


def test_every_scanned_source_exists_and_is_python_or_shell():
    assert all((ROOT / name).is_file() and name.endswith((".py", ".sh")) for name in SOURCES)
    assert register()["sources"] == list(SOURCES)  # The register states what the scan covers.


def test_entries_are_complete_and_process_creating_ones_are_bounded_or_random():
    doc = register()
    assert set(doc) == {"schema", "note", "sources", "periods"} and doc["schema"] == "hyptcn3/host-periods/1"
    names = [e["name"] for e in doc["periods"]]
    assert len(names) == len(set(names))
    for entry in doc["periods"]:
        assert set(entry) == FIELDS, entry["name"]
        assert entry["kind"] in (*DISCOVERED, "system"), entry["name"]
        assert entry["period_s"] is None or entry["period_s"] > 0, entry["name"]
        random_s = entry["random_s"]
        assert random_s == 0 or (len(random_s) == 2 and random_s[0] < random_s[1]), entry["name"]
        assert type(entry["creates_processes"]) is bool and type(entry["active"]) is bool, entry["name"]
        assert type(entry["note"]) is str and entry["note"].strip(), entry["name"]
        if entry["creates_processes"] and entry["active"]:  # Proposal 5.6, independent of the ratio to 5 s.
            assert entry["bounded"] or random_s != 0, entry["name"]
        if entry["source"].startswith(("scripts/", "vmicollect/")):
            name, line = entry["source"].rsplit(":", 1)
            assert 1 <= int(line) <= len((ROOT / name).read_text().splitlines()), entry["name"]


def test_the_collection_grid_the_drift_of_two_collectors_and_the_host_timers_are_declared():
    """The reference entry is the grid itself: vmicollect's schedule at interval_s of the v5 file (5 s)."""
    v5 = json.loads((ROOT / "config/collection-v5.json").read_text())
    grid = _entry("collection grid")
    assert (grid["kind"], grid["period_s"], grid["random_s"], grid["active"]) == ("system", v5["interval_s"], 0, True)
    name, line = grid["source"].rsplit(":", 1)
    assert "interval" in (ROOT / name).read_text().splitlines()[int(line) - 1]
    drift = _entry("drift of the two collectors' grids")
    assert (drift["kind"], drift["period_s"]) == ("system", None) and "B9" in drift["note"]
    timers = _entry("host timers outside the repository")
    assert timers["kind"] == "system" and "host_context.timers" in timers["bounded"]


def test_the_old_generator_unit_has_the_start_limit_of_the_guest_units(monkeypatch, tmp_path):
    """The unit restarts after RestartSec=5, the collection period; at most StartLimitBurst starts within
    StartLimitIntervalSec, as lab/hyptcn-lab@.service (KOSTRA B5 section 1)."""
    from scripts import labctl
    guest = (ROOT / "lab/hyptcn-lab@.service").read_text().split("[Service]", 1)[0]
    limits = {key: re.search(rf"^{key}=(\d+)$", guest, re.M)[1] for key in ("StartLimitBurst", "StartLimitIntervalSec")}
    v5 = json.loads((ROOT / "config/collection-v5.json").read_text())
    assert labctl.TRAFFIC_UNIT_PROPERTIES == ("Restart=on-failure", f"RestartSec={v5['interval_s']}",
                                              *(f"{key}={value}" for key, value in limits.items()))
    calls = []
    monkeypatch.setattr(labctl.Lab, "health", lambda self: "http://127.0.0.1:18080")
    monkeypatch.setattr(labctl, "REPO", tmp_path)  # The status file goes below tmp_path.
    monkeypatch.setattr(labctl.subprocess, "run", lambda argv, **kw: labctl.subprocess.CompletedProcess(argv, 3))
    monkeypatch.setattr(labctl, "run", lambda args, **kw: calls.append([str(a) for a in args]))
    labctl.Lab().traffic()
    (argv,) = calls
    assert [a for a in argv if a.startswith("--property=")] == [f"--property={v}" for v in
                                                                labctl.TRAFFIC_UNIT_PROPERTIES]
    unit = next(e for e in register()["periods"] if e["kind"] == "restart" and e["source"].startswith(
        "scripts/labctl.py:"))
    assert all(value in unit["bounded"] for value in labctl.TRAFFIC_UNIT_PROPERTIES[2:])
    assert (unit["period_s"], unit["creates_processes"]) == (v5["interval_s"], True)


@pytest.mark.parametrize("command", ["traffic-start", "up"])
def test_the_old_generator_unit_never_starts_under_a_protocol_of_schema_3(monkeypatch, command):
    from scripts import labctl
    steps = []
    for name in ("clone", "start", "swap_step", "deploy", "health", "traffic"):
        monkeypatch.setattr(labctl.Lab, name, lambda self, *a, name=name: steps.append(name))
    with pytest.raises(RuntimeError) as refused:
        labctl.main([command, "--protocol", str(ROOT / "config/collection-v5.json")])
    assert str(refused.value) == labctl.OLD_GENERATOR_UNDER_V5 and steps == []
    labctl.main([command, "--protocol", str(ROOT / "config/collection-v2.json")])  # Schema 2: as before.
    assert steps[-1] == "traffic"


def test_an_unreadable_protocol_of_the_old_generator_unit_is_a_usage_error(tmp_path, capsys):
    from scripts import labctl
    bad = tmp_path / "protocol.json"
    bad.write_text("{")
    with pytest.raises(SystemExit) as stopped:
        labctl.main(["traffic-start", "--protocol", str(bad)])
    assert stopped.value.code == 2 and "cannot read --protocol" in capsys.readouterr().err


@pytest.mark.parametrize("name,text,kind,marker", [
    ("scripts/host_monitor.py", "\n\ndef planted():\n    while True:\n        time.sleep(5)\n", "loop", "while True"),
    ("scripts/host_monitor.py", "\n\ndef planted(stop):\n    for _ in range(9):\n        stop.wait(2)\n", "loop",
     "for _ in"),
    ("scripts/labctl.py", "\nPLANTED = ['systemd-run', '--user', '--property=Restart=always']\n", "restart",
     "PLANTED"),
    ("scripts/labctl.py", "\nPLANTED = '[Service]\\nRestartSec=1\\n'\n", "restart", "PLANTED"),
    ("scripts/collection.py", "\nPLANTED = ['systemd-run', '--user', '--on-active=30s', 'true']\n", "timer",
     "PLANTED"),
    ("scripts/collection.py", "\nPLANTED = '[Timer]\\nOnUnitActiveSec=30s\\n'\n", "timer", "PLANTED"),
    ("scripts/campaign.py", "\nPLANTED = ['bash', '-c', 'while true; do date; sleep 2; done']\n", "loop", "PLANTED"),
    ("scripts/lab_capture.sh", "while true; do\n    curl -fsS http://127.0.0.1:18080/healthz\n    sleep 5\ndone\n",
     "loop", "while true"),
    ("scripts/lab_capture.sh", "python3 - <<'PY'\nimport time\nwhile True:\n    time.sleep(1)\nPY\n", "loop",
     "python3 - <<'PY'"),
    ("scripts/host_monitor.py", "\n\ndef planted(items):\n    while True:\n        items.get(timeout=1)\n", "loop",
     "while True"),
    ("scripts/collection.py", "\n\ndef planted(fd):\n    for _ in range(9):\n        select.select([fd], [], [], 5)\n",
     "loop", "for _ in"),
])
def test_an_unregistered_restart_timer_or_sleeping_loop_fails(tmp_path, name, text, kind, marker):
    copy = tmp_path / "host"
    for source in SOURCES:
        (copy / source).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, copy / source)
    assert compare(copy, register()) == ([], [])
    changed = (copy / name).read_text() + text
    (copy / name).write_text(changed)
    line = next(i for i, row in enumerate(changed.splitlines(), 1) if marker in row and i > len(
        (ROOT / name).read_text().splitlines()))
    assert compare(copy, register()) == ([(kind, f"{name}:{line}")], [])


def test_a_register_line_that_moved_fails():
    doc = register()
    entry = next(e for e in doc["periods"] if e["source"].startswith("scripts/host_monitor.py:"))
    entry["source"] = entry["source"].rsplit(":", 1)[0] + ":1"
    unregistered, stale = compare(ROOT, doc)
    assert stale == [(entry["kind"], "scripts/host_monitor.py:1")] and len(unregistered) == 1
