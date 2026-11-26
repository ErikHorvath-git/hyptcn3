"""The mode controls of scripts/campaign_report.py (package H1b2 of stage G2): the table of shifts of the controls on
the VMs and their paired negatives, criterion controls_paired (the lead's answers Q46 to Q48 and Q20).

The recorded files of a G2 session with controls are written here as the capture, the wrapper (skuska/kontroly.py)
and the audit leave them: session.json of a diagnostic run listing the controls of one session of the draw of
config/collection-v5.json, its copy protocol.json, controls.json with the records of a faultless run
(scripts/tests/audit_cases_logs.py control_records), the feature archive of a clean session on the protocol's grid
(scripts/tests/boundary_sessions.py extraction_result, 32 bins of 16 MiB) in which every column of a control moves by
more than its expected shift in the rows wholly inside the occurrence and nothing moves for a negative, an audit record
binding them, and a RAM image in raw/ that cannot be read (the mode never opens one). The levels and shifts are numbers
of these tests, not measurements; the expected counts and texts are written out from the draw, never made by the
mode's code. The 10 sessions of the draw hold its 30 occurrences; dropping one of them leaves three kinds one short,
which the table names by the count. No VM, no network, nothing written outside the test's directories.
"""
import json
import hashlib
from pathlib import Path
import shutil

import pytest

from features.snapshot import MENA
from scripts import campaign_report as cr
from scripts import collection, protocol_v5
from scripts.tests import audit_cases_logs as cases
from scripts.tests import boundary_sessions as bs
from skuska import kontroly

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
P = collection.protocol(REAL)
KINDS = sorted(P["controls"]["kinds"])
PROVENANCE = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.
T0 = 1.9e9  # The time of the first row of the first session (synthetic).
BINS = 32  # 32 bins of 16 MiB: a guest of 512 MiB, every bin counted (analysis.scale.min_bin_pages 1024 pages).
PID = 4321  # effect.evidence.members of control_records: the process whose W+X and memfd patterns the parser sees.
STAMP = "20261126T120000000000Z"
NOT_JUDGED = ("not judged in G2: the lead's answer to Q47 judges channel_reacted only descriptively with the bundle "
              "of the parity check, and protocol v5 has no bundle before G3a")
# Every column of a kind at its level in every row (test values).
LEVEL = {"proc_wx": 0, "proc_memfd": 0, "mod_total": 30, "sock_listen": 7, "mem_changed_ratio": .02,
         "mem_changed_max": .1, "mem_entropy_mean": 3., "proc_new": 0, "proc_gone": 0, "proc_total": 120}
# The test's shift of a column in the rows wholly inside a control, by its dose: above the expected shift of
# config/collection-v5.json; the writer's ratio 1.25 times its dose's share of the 512 MiB, so the parser sees the dose.
SHIFT = {"proc_wx": lambda d: 1, "proc_memfd": lambda d: 1, "mod_total": lambda d: 1, "sock_listen": lambda d: 1,
         "mem_changed_ratio": lambda d: 1.25 * d / 512, "mem_changed_max": lambda d: .6,
         "mem_entropy_mean": lambda d: 1.5, "proc_new": lambda d: 2 * d, "proc_gone": lambda d: 2 * d,
         "proc_total": lambda d: 2 * d + 4}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc):
    Path(path).write_text(json.dumps(doc, indent=1) + "\n")


def recorded(root, s, number, *, refused=(), still=(), name=None):
    """The recorded files of the G2 session of draw session `s` (the module docstring) in root/<session id>: the
    records `refused` (indices) as a start the return predicate refused (not executed), the controls `still` without
    any move of their columns. Returns the directory."""
    d = Path(root) / (name or f"g2-{s['vm']}-{s['id']}-1")
    d.mkdir(parents=True)
    shutil.copyfile(REAL, d / "protocol.json")
    t0 = T0 + 10000 * number
    result, _ = bs.extraction_result(d.name, P["cycles"], P["full_every"], t0=t0, interval_s=P["interval_s"],
                                     bins=BINS, max_gap_s=P["max_gap_s"])
    matrix = result["matica"]
    for row in matrix:
        for column, level in LEVEL.items():
            row[MENA.index(column)] = level
    records = cases.control_records(s["controls"], t0)
    for i, (item, record) in enumerate(zip(s["controls"], records)):
        if i in refused:
            cases._refused_start(record)
        if item["polarity"] != "control" or i in still or i in refused:
            continue
        for seq, t in enumerate(result["casy"]):
            if record["host_started_unix"] + P["interval_s"] <= t <= record["host_stop_unix"]:
                for column in P["controls"]["kinds"][item["kind"]]["columns"]:
                    matrix[seq][MENA.index(column)] = LEVEL[column] + SHIFT[column](item["dose"])
                if item["kind"] == "kontrola_wx_memfd":
                    result["quality"][seq]["memory_patterns"] = [{"pid": PID, "comm": "python3", "kind": kind}
                                                                 for kind in ("wx", "memfd_fd")]
    features, features_sha = bs.save_archive(d / f"audit_{STAMP}.npz", result)
    write(d / "controls.json", {"schema": protocol_v5.CONTROLS_SCHEMA, "controls": records})
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": d.name, "campaign_id": "g2",
                               "vm": s["vm"], "role": "diagnostic", "group": f"g2-{s['vm']}-20261126T120000Z-1",
                               "scenario": s["scenario"], "seed": s["seed"], "cycles": P["cycles"], "events": [],
                               "controls": s["controls"], "protocol_sha256": sha(d / "protocol.json"),
                               "guest_before": {"kernel": "6.1.0-test", "boot_id": f"boot-{number}"}})
    write(d / f"audit_{STAMP}.json", {
        "schema": "hyptcn3/collection-audit/1", "commit": "c" * 40, "date": "2026-11-26T12:00:00+00:00",
        "host": "test-host", "guest": None, "command": "scripts/collection.py audit (recorded by the test)",
        "n": P["cycles"], "values": {"accepted": True, "reasons": [], "session_dir": str(d),
                                     "session_sha256": sha(d / "session.json"),
                                     "protocol_sha256": sha(d / "protocol.json"), "features": str(features),
                                     "features_sha256": features_sha}})
    (d / "raw").mkdir()
    image = d / "raw" / "frame000000.vmicd"
    image.write_bytes(b"synthetic RAM image")
    image.chmod(0)  # Never opened by the mode: reading it would fail.
    return d


@pytest.fixture(scope="module")
def draw():
    return kontroly.draw_controls(P)


@pytest.fixture(scope="module")
def sessions(draw, tmp_path_factory):
    """The 10 sessions of the draw as recorded files."""
    root = tmp_path_factory.mktemp("g2")
    return [recorded(root, s, number) for number, s in enumerate(draw["sessions"])]


def table(dirs, out, capsys):
    """(exit code, the record or None, stdout lines, stderr) of the mode controls over `dirs`."""
    code = cr.main(["controls", *map(str, dirs), "--out", str(out)])
    captured = capsys.readouterr()
    doc = json.loads(Path(out).read_text()) if Path(out).exists() else None
    return code, doc, captured.out.splitlines(), captured.err


def expected_shift(kind, column, dose):
    e = P["controls"]["kinds"][kind]["expect"][column]
    return e["shift"][P["controls"]["kinds"][kind]["doses"].index(dose)] if type(e["shift"]) is list else e["shift"]


def test_the_table_of_the_draw_shows_every_kind_with_its_minimum(sessions, draw, tmp_path, capsys):
    """The 30 occurrences of the draw: per occurrence VM, session, kind, polarity, the guest's effect and cleanup,
    parser_saw, column_moved per column against expect (per dose for class B), sensor_scored and channel_reacted as not
    judged in G2; every kind counts 3 controls and 3 negatives against the minimum 3; no finding; check E's header."""
    out = tmp_path / "tabulka.json"
    code, doc, lines, err = table(sessions, out, capsys)
    assert code == 0, err
    assert set(PROVENANCE) <= set(doc) and (doc["schema"], doc["n"]) == ("hyptcn3/g2-controls-table/1", 30)
    assert doc["command"] == "scripts/campaign_report.py controls " + " ".join(map(str, sessions)) + f" --out {out}"
    v = doc["values"]
    assert (v["criterion"], v["needed"], v["kinds"], v["minimums_met"], v["missing"]) == (
        "controls_paired", 3, KINDS, True, [])
    assert (v["expect_findings"], v["parser_findings"], v["unscored"]) == ([], [], [])
    for kind in KINDS:
        for polarity in ("control", "negative"):
            row = v["counts"][kind][polarity]
            assert (row["counted"], row["occurrences"], row["needed"], row["missing"]) == (3, 3, 3, 0)
            assert sorted(row["by_vm"].values()) == [1, 2]
    items = [(s, x) for s in draw["sessions"] for x in s["controls"]]
    assert [(row["session"], row["vm"], row["kind"], row["polarity"], row["dose"]) for row in v["occurrences"]] == [
        (f"g2-{s['vm']}-{s['id']}-1", s["vm"], x["kind"], x["polarity"], x["dose"]) for s, x in items]
    for row in v["occurrences"]:
        assert row["channel_reacted"] == NOT_JUDGED and row["counted"] is True and row["why_not_counted"] is None
        assert (row["effect"], row["cleanup"], row["executed"], row["audit_accepted"]) == ({"ok": True}, {"ok": True},
                                                                                           True, True)
        assert (row["parser_saw"]["ok"], row["column_moved"]["ok"], row["sensor_scored"]) == (True, True, True)
        kind = P["controls"]["kinds"][row["kind"]]
        assert sorted(row["column_moved"]["columns"]) == sorted(kind["columns"])
        for column, moved in row["column_moved"]["columns"].items():
            assert (moved["expect"], moved["direction"]) == (expected_shift(row["kind"], column, row["dose"]), "up")
            control = row["polarity"] == "control"
            assert moved["shift"] == pytest.approx(SHIFT[column](row["dose"]) if control else 0)
            assert moved["reached"] is control
        assert row["column_moved"]["reference_rows"] == 12 and row["window"]["scored"] > 0
    assert lines == [f"{kind}: controls 3/3, negatives 3/3" for kind in KINDS] + [
        "controls_paired minimums: met; 0 expectation finding(s), 0 parser finding(s), 0 unscored"]
    for entry, path in zip(v["sessions"], sessions):
        assert (entry["path"], entry["role"], entry["occurrences"], entry["audit"]["accepted"]) == (
            str(path), "diagnostic", 3, True)
        assert entry["features"]["sha256"] == sha(path / f"audit_{STAMP}.npz")
        assert entry["session_json_sha256"] == sha(path / "session.json")
    assert "never a RAM image" in v["rule"] and v["channel_reacted"] == NOT_JUDGED


def test_a_missing_occurrence_is_named_by_the_count(sessions, draw, tmp_path, capsys):
    """Without the last session of the draw (k10 on VM b) its three kinds have one occurrence less of its polarity:
    the table is written, names each by the count and exits 1."""
    dropped = draw["sessions"][-1]
    code, doc, lines, err = table(sessions[:-1], tmp_path / "tabulka.json", capsys)
    assert code == 1, err
    short = sorted((x["kind"], x["polarity"]) for x in dropped["controls"])
    assert doc["values"]["missing"] == [f"{kind}: 2 of 3 {polarity}s counted (1 missing; 2 recorded)"
                                        for kind, polarity in short]
    assert doc["values"]["minimums_met"] is False and doc["n"] == 27
    for kind, polarity in short:
        assert doc["values"]["counts"][kind][polarity]["missing"] == 1
        assert any(line.startswith(f"{kind}: ") and f"{polarity}s 2/3 (1 missing)" in line for line in lines)
    assert lines[-1].startswith("controls_paired minimums: missing: " + doc["values"]["missing"][0])


def test_an_occurrence_that_did_not_run_does_not_count(draw, tmp_path, capsys):
    """The first record of k01 as a start the return predicate refused: its row says why it does not count, and the
    count of its kind and polarity names the occurrence missing (the table of k01 alone: 1 recorded, 0 counted)."""
    s = draw["sessions"][0]
    variant = recorded(tmp_path / "variant", s, 0, refused=(0,))
    code, doc, _, err = table([variant], tmp_path / "tabulka.json", capsys)
    assert code == 1, err
    kind, polarity = s["controls"][0]["kind"], s["controls"][0]["polarity"]
    row = doc["values"]["occurrences"][0]
    assert (row["kind"], row["executed"], row["counted"], row["effect"]) == (kind, False, False, {"ok": False})
    assert row["why_not_counted"] == f"its outcomes were not computed: control not executed: {kind}"
    assert (row["parser_saw"], row["column_moved"], row["sensor_scored"]) == (None, None, None)
    assert f"{kind}: 0 of 3 {polarity}s counted (3 missing; 1 recorded)" in doc["values"]["missing"]
    assert [row["counted"] for row in doc["values"]["occurrences"]] == [False, True, True]


def test_a_control_below_its_expected_shift_is_a_finding_and_still_counts(draw, tmp_path, capsys):
    """Q20: a control that ran faultlessly but whose column did not move counts (the table of k02 alone); the miss of
    its expected shift and the parser that did not see it are findings for the lead, not refusals."""
    s = draw["sessions"][1]
    index = next(i for i, x in enumerate(s["controls"]) if x["polarity"] == "control"
                 and x["kind"] == "kontrola_modul_jadra")
    variant = recorded(tmp_path / "variant", s, 1, still=(index,))
    code, doc, lines, err = table([variant], tmp_path / "tabulka.json", capsys)
    assert code == 1, err  # One session: every kind misses its minimum.
    name = f"kontrola_modul_jadra control in {variant.name} (#{index})"
    v = doc["values"]
    assert v["expect_findings"] == [f"{name}: mod_total moved 0 against the expected 0.5 up"]
    assert v["parser_findings"] == [f"{name}: parser_saw False"] and v["unscored"] == []
    assert v["counts"]["kontrola_modul_jadra"]["control"]["counted"] == 1
    assert v["occurrences"][index]["counted"] is True and v["occurrences"][index]["column_moved"]["ok"] is False
    assert lines[-1].endswith("; 1 expectation finding(s), 1 parser finding(s), 0 unscored")


def _write_json(path, change):
    doc = json.loads(Path(path).read_text())
    change(doc)
    write(path, doc)


@pytest.mark.parametrize("case, said", [
    ("out_exists", "campaign_report: --out already exists, nothing was read or written"),
    ("twice", "campaign_report: controls: a session directory is named more than once"),
    ("role", 'names the role "test_controls", not diagnostic'),
    ("no_controls", "session.json lists no controls (no session with controls"),
    ("protocol", "protocol.json has the sha256"),
    ("no_audit", "no audit record of the session"),
    ("audit_protocol", "audited under the protocol"),
    ("features", "the audit's values.features_sha256"),
    ("controls_schema", 'controls.json: its schema is "hyptcn3/session-controls/9"'),
    ("out_inside", "inside the session directory"),
], ids=lambda value: value if " " not in value else "")
def test_the_refusals_are_named_and_nothing_is_written(draw, tmp_path, capsys, case, said):
    """Each data error of CONTROLS_RULE refused by name, exit 2, no record written."""
    d = recorded(tmp_path / "s", draw["sessions"][0], 0)
    out = tmp_path / "tabulka.json"
    dirs = [d]
    audit = d / f"audit_{STAMP}.json"
    if case == "out_exists":
        out.write_text("{}\n")
    elif case == "twice":
        dirs = [d, d]
    elif case == "role":
        _write_json(d / "session.json", lambda doc: doc.update(role="test_controls"))
    elif case == "no_controls":
        _write_json(d / "session.json", lambda doc: doc.update(controls=[]))
    elif case == "protocol":
        (d / "protocol.json").write_text((d / "protocol.json").read_text() + " ")
    elif case == "no_audit":
        _write_json(d / "session.json", lambda doc: doc.update(seed=doc["seed"] + 1))  # The audit binds the old file.
    elif case == "audit_protocol":
        _write_json(audit, lambda doc: doc["values"].update(protocol_sha256="0" * 64))
    elif case == "features":
        _write_json(audit, lambda doc: doc["values"].update(features_sha256="0" * 64))
    elif case == "controls_schema":
        _write_json(d / "controls.json", lambda doc: doc.update(schema="hyptcn3/session-controls/9"))
    elif case == "out_inside":
        out = d / "tabulka.json"
    before = out.read_text() if out.exists() else None
    code, _, _, err = table(dirs, out, capsys)
    assert code == 2 and said in err
    assert (out.read_text() if out.exists() else None) == before
