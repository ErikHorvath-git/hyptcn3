"""The mode marked of scripts/campaign_report.py (package H1b6b of stage G2): the rows the rule marks per occurrence of
an event, criterion marked_rows_per_event, and the proposal of invalid_rows.max and min_score_coverage by the model of
the lead's answer to Q49 (map rows 4 and 14).

The recorded files of a G2 session are written here as the capture, the audit and the driver leave them: session.json
of a diagnostic run of one session of the deck of skuska/g2.py on config/collection-v5.json, its copy protocol.json,
events.json with the host times of the deck's occurrences (each measured from the session's first row), a feature
archive with the keys the mode reads (seq, casy, valid, quality_json; numpy, no pickle), an audit record binding them
whose facts and counts by type are made as scripts/collection.py makes them, and the session's G2 record
(<g2 dir>/zaznamy/<session>.json). The marked rows are placed by the tests; the expected counts, phases, rates and
proposals are written out or counted here from the Poisson law, never made by the mode's code. No VM, no network,
nothing written outside the test's directories.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil

import numpy as np
import pytest

from features.acceptance import marked_rows_by_type
from scripts import campaign_report as cr
from scripts import protocol_v5
from scripts.collection_logs import event_window
from skuska import cas, g2, poruchy

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
P = json.loads(REAL.read_text())
TYPES = sorted(P["events"]["types"])
PROVENANCE = ("commit", "date", "host", "guest", "command", "n")  # Check E of scripts/check_claims.sh.
T0 = 1.9e9  # The time of the first row of the first session (synthetic).
GRID = 0.25  # The phase of the collector's grid in the audit's values.timing (synthetic: every row 0.25 s late).
STARTED, STOPPED = 0.4, 1.5  # The start and the stop call of an occurrence take this long (synthetic).
GOOD = {"truncated_traversals": [], "read_errors": 0, "filled_zero": 0, "process_walk": "next", "findings": []}
STAMP = "20261126T120000000000Z"


@pytest.fixture(autouse=True)
def one_git_state(monkeypatch):
    """The record's commit without asking git (the provenance keys are checked, not the commit)."""
    monkeypatch.setattr(cr, "git_identity", lambda: {"commit": "synthetic", "dirty": False, "changed_paths": 0})


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=1) + "\n")


DECK = g2.draw_deck(P)["sessions"]


def origin(number):
    return T0 + 10000 * number


def host_times(item, number):
    """The host times of one occurrence of the deck in session `number`: its start call at its start_s after the
    session's first row, its stop call at the end of its duration."""
    start = origin(number) + item["start_s"]
    stop = start + item["duration_s"]
    return {"host_start_unix": start, "host_started_unix": start + STARTED, "host_stop_unix": stop,
            "host_stopped_unix": stop + STOPPED}


def seq_at(number, unix):
    """The first row at or after the time `unix` in session `number` (rows every interval_s from the origin)."""
    return math.ceil((unix - origin(number) - GRID) / P["interval_s"])


def row_time(number, seq):
    return origin(number) + GRID + P["interval_s"] * seq


def recorded(root, g2_dir, s, number, *, invalid=None, closed=None, kind="deck", excluded=None, counted=True,
             beside=(), protocol=REAL, events=True, name=None):
    """The recorded files of deck session `s` as session `number` (the module docstring) under root/<vm>/<id> and its
    record under g2_dir/zaznamy: invalid {seq: truncated traversals} rows invalid for these traversals (or
    {"read_errors": 1} for a read error), closed {seq: walk} rows a parser rule closed. Returns the audit's path."""
    sid = name or f"g2-{s['vm']}-{s['id']}-1"
    d = Path(root) / s["vm"] / sid
    d.mkdir(parents=True)
    shutil.copyfile(protocol, d / "protocol.json")
    cycles = P["cycles"]
    quality = []
    for seq in range(cycles):
        q = dict(GOOD)
        cause = (invalid or {}).get(seq)
        if isinstance(cause, dict):
            q.update(cause, truncated_traversals=[])
        elif cause is not None:
            q["truncated_traversals"] = list(cause)
        if seq in (closed or {}):
            q["process_walk"] = closed[seq]
        quality.append(q)
    valid = [not q["truncated_traversals"] and not q["read_errors"] for q in quality]
    times = [row_time(number, seq) for seq in range(cycles)]
    archive = d / f"audit_{STAMP}.npz"
    np.savez_compressed(archive, seq=np.arange(cycles, dtype=np.int64), casy=np.array(times, dtype=np.float64),
                        valid=np.array(valid, dtype=bool), quality_json=json.dumps(quality))
    planned = s["events"] if events else []
    records = [dict(item, executed=True, effect={"ok": True}, **host_times(item, number)) for item in planned]
    if events:
        write(d / "events.json", {"schema": "hyptcn3/session-events/1", "events": records})
    write(d / "session.json", {"schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": "g2",
                               "vm": s["vm"], "role": "diagnostic", "group": f"g2-{s['vm']}-block-1",
                               "scenario": s["scenario"], "seed": s["seed"], "cycles": cycles, "events": planned,
                               "event_grace_s": P["events"]["grace_s"], "protocol_sha256": sha(d / "protocol.json")})
    facts = {"invalid_rows": [{"seq": seq, "truncated_traversals": q["truncated_traversals"],
                               "read_errors": q["read_errors"], "filled_zero": q["filled_zero"]}
                              for seq, (q, good) in enumerate(zip(quality, valid)) if not good],
             "rule_closed_seq": sorted(closed or {})}
    flagged = sorted({row["seq"] for row in facts["invalid_rows"]} | set(facts["rule_closed_seq"]))
    windows = [(r["type"], *event_window(r, P["events"]["grace_s"])) for r in records]
    by_type, occurrences, outside = marked_rows_by_type(flagged, dict(enumerate(times)), windows, TYPES)
    audit = d / f"audit_{STAMP}.json"
    write(audit, {"schema": "hyptcn3/collection-audit/1", "commit": "c" * 40, "date": "2026-11-26T12:00:00+00:00",
                  "host": "test-host", "guest": None, "command": "scripts/collection.py audit (recorded by the test)",
                  "n": cycles, "values": {
                      "accepted": not facts["invalid_rows"], "reasons": [], "session_dir": str(d),
                      "session_sha256": sha(d / "session.json"), "protocol_sha256": sha(d / "protocol.json"),
                      "features": str(archive), "features_sha256": sha(archive), "acceptance": {"facts": facts},
                      "timing": {"grid_phase_s": round((origin(number) + GRID) % P["interval_s"], 6)},
                      "marked_rows_by_type": by_type, "event_occurrences_by_type": occurrences,
                      "marked_rows_outside_events": outside}})
    write(Path(g2_dir) / "zaznamy" / f"{sid}.json", {
        "schema": "hyptcn3/g2-session/1", "commit": "c" * 40, "date": "2026-11-26T12:00:00+00:00", "host": "pcc",
        "guest": {"vm": s["vm"]}, "command": "python -m skuska.g2 block (recorded by the test)", "n": 4,
        "values": {"stage": "G2", "kind": kind, "vm": s["vm"], "session_id": sid, "session_dir": str(d),
                   "session_json_sha256": sha(d / "session.json"), "excluded": excluded, "counted": counted,
                   "load": {"summary": {"counted": counted,
                                        "reasons": [] if counted else ["heavy: C4 (tcn.suchy_beh): python -m "
                                                                       "tcn.suchy_beh"]}},
                   "done": True, "beside": list(beside), "audit": {"report": str(audit), "sha256": sha(audit)}}})
    return audit


def deck(root, g2_dir, changes=None):
    """The audits of the 38 sessions of the deck; changes {deck id: keyword arguments of recorded()}."""
    return [recorded(root, g2_dir, s, number, **(changes or {}).get(s["id"], {})) for number, s in enumerate(DECK)]


def table(tmp_path, audits, capsys, *, protocol=REAL, out=None):
    """(exit code, the record or None, stdout lines, stderr) of the mode marked over `audits`."""
    out = tmp_path / "marked.json" if out is None else out
    code = cr.main(["marked", *map(str, audits), "--protocol", str(protocol), "--g2-dir", str(tmp_path / "g2"),
                    "--out", str(out)])
    captured = capsys.readouterr()
    doc = json.loads(Path(out).read_text()) if Path(out).exists() else None
    return code, doc, captured.out.splitlines(), captured.err


def poisson_above(mu, k):
    """P(N > k) for N ~ Poisson(mu), summed here term by term."""
    return 1 - sum(math.exp(-mu) * mu ** i / math.factorial(i) for i in range(k + 1))


# ---------------------------------------------------------------- the table of the deck

def test_the_deck_counts_every_occurrence_with_its_rows_at_the_start_and_the_stop(tmp_path, capsys):
    """The 38 sessions of the deck (114 occurrences, 19 of each type, 9 or 10 on each VM): in e01 an invalid row with
    processes 3 s after the start of its first occurrence and a row a parser rule closed 3 s after its stop; in e02
    an invalid row with processes 3 s after the stop of its second occurrence. Every occurrence is a row of the table
    with its window and the phase of both boundaries against the grid; the sums by type hold exactly these rows;
    every minimum is met; lambda = 2 rows over 228 boundaries gives invalid_rows.max 1 and min_score_coverage
    623/720; check E's header with the stage G2."""
    first, second = DECK[0], DECK[1]
    a = host_times(first["events"][0], 0)
    b = host_times(second["events"][1], 1)
    start_row, closed_row, stop_row = seq_at(0, a["host_start_unix"] + 3), seq_at(0, a["host_stop_unix"] + 3), \
        seq_at(1, b["host_stop_unix"] + 3)
    audits = deck(tmp_path / "s", tmp_path / "g2", {
        first["id"]: {"invalid": {start_row: ["processes"]}, "closed": {closed_row: "prev"}},
        second["id"]: {"invalid": {stop_row: ["processes"]}}})
    code, doc, lines, err = table(tmp_path, audits, capsys)
    assert code == 0, err
    assert set(PROVENANCE) <= set(doc) and (doc["schema"], doc["n"]) == ("hyptcn3/g2-marked-table/1", 114)
    assert doc["command"] == ("scripts/campaign_report.py marked " + " ".join(map(str, audits)) + f" --protocol {REAL} "
                              f"--g2-dir {tmp_path / 'g2'} --out {tmp_path / 'marked.json'}")
    v = doc["values"]
    assert (v["stage"], v["criterion"], v["value"], v["types"], v["vms"]) == (
        "G2", "marked_rows_per_event", "invalid_rows.max", TYPES, ["a", "b"])
    assert len(v["counted_sessions"]) == 38 and v["left_out"] == [] and v["minimums_met"] and v["missing"] == []
    rows = v["occurrences"]
    assert [(r["session_id"], r["type"]) for r in rows] == [(f"g2-{s['vm']}-{s['id']}-1", x["type"])
                                                           for s in DECK for x in s["events"]]
    one = rows[0]
    assert one["window"] == [a["host_start_unix"] - 1, a["host_stopped_unix"] + P["events"]["grace_s"]]
    grid = doc["values"]["sessions"][0]["grid_phase_s"]
    assert one["phase_s"]["start"] == round((a["host_start_unix"] - grid) % 5, 6)
    assert one["phase_s"]["stop"] == round((a["host_stop_unix"] - grid) % 5, 6)
    assert one["planned"] == {key: first["events"][0][key] for key in ("start_s", "duration_s", "start_phase_s",
                                                                        "stop_phase_s")}
    assert one["start"] == {"invalid_processes": [start_row], "invalid_other": [], "rule_closed": []}
    assert one["stop"] == {"invalid_processes": [], "invalid_other": [], "rule_closed": [closed_row]}
    assert rows[4]["stop"]["invalid_processes"] == [stop_row] and rows[4]["start"]["invalid_processes"] == []
    marked = {(r["session_id"], r["index"]) for r in rows if any(r[end][part] for end in ("start", "stop")
                                                                 for part in r["start"])}
    assert marked == {(rows[0]["session_id"], 0), (rows[4]["session_id"], 1)}
    for kind in TYPES:
        row = v["by_type"][kind]
        mine = [(s["vm"], x) for s in DECK for x in s["events"] if x["type"] == kind]
        assert row["occurrences"] == {"both": 19, "by_vm": {vm: sum(m == vm for m, _ in mine) for vm in "ab"}}
    for kind, end in ((first["events"][0]["type"], "start"), (second["events"][1]["type"], "stop")):
        assert v["by_type"][kind]["invalid_processes"][end] >= 1
    assert sum(v["by_type"][kind]["invalid_processes"]["total"] for kind in TYPES) == 2
    assert sum(v["by_type"][kind]["rule_closed"]["total"] for kind in TYPES) == 1
    m = v["model"]
    assert (m["rows_in_windows"], m["occurrences"], m["boundaries"]) == (2, 114, 228)
    assert m["lambda"] == pytest.approx(2 / 228) and m["mu"] == pytest.approx(6 * 2 / 228)
    assert poisson_above(6 * 2 / 228, 0) >= .01 > poisson_above(6 * 2 / 228, 1)
    assert m["proposal"]["invalid_rows.max"] == 1
    assert m["proposal"]["gate_interval"]["high_windows"] == 623 and m["proposal"]["min_score_coverage"] == \
        pytest.approx(623 / 720)
    assert m["findings"] == [] and v["findings"] == []
    session = v["sessions"][0]
    assert {f["name"] for f in session["files"]} == {"audit record", "session.json", "protocol.json", "G2 record",
                                                    "feature archive", "events.json"}
    assert all(f["sha256"] == sha(f["path"]) for f in session["files"])
    assert lines[-1] == "marked_rows_per_event minimums: met; 38 of 38 session(s) counted, 0 finding(s)"
    assert lines[len(TYPES)].startswith("invalid_rows.max proposal: 1 (lambda 0.00877193 over 228 boundaries")


@pytest.mark.parametrize("change, why", [
    ({"excluded": {"criteria": ["event_effects", "marked_rows_per_event", "invalid_rows.max"],
                   "rule": "Q62: the ground truth"}},
     "its record leaves it out of marked_rows_per_event, invalid_rows.max (values.excluded: Q62: the ground truth)"),
    ({"counted": False},
     "not counted by the host load (skuska/g2.py LOAD_RULE): heavy: C4 (tcn.suchy_beh): python -m tcn.suchy_beh"),
    ({"kind": "cas"}, "a session of H4 (kind cas): Q49 counts none"),
    ({"beside": [{"hook": "parita", "g2_values": False}]},
     "a hook beside its run says that it gives no value of G2 (values.beside, g2_values false)"),
], ids=["excluded", "heavy_process", "h4", "no_g2_values"])
def test_a_session_the_records_leave_out_is_listed_and_not_counted(tmp_path, capsys, change, why):
    """One session of the deck whose record leaves it out: it is listed with the record's words, its occurrences are
    rows of the table but not counted, so the three types it holds have 18 of their 19 occurrences: exit 1, each
    missing one named."""
    left = DECK[5]
    audits = deck(tmp_path / "s", tmp_path / "g2", {left["id"]: change})
    code, doc, lines, _ = table(tmp_path, audits, capsys)
    v = doc["values"]
    sid = f"g2-{left['vm']}-{left['id']}-1"
    assert code == 1 and v["left_out"] == [{"session_id": sid, "why": why}] and len(v["counted_sessions"]) == 37
    assert [r["counted"] for r in v["occurrences"] if r["session_id"] == sid] == [False] * 3
    types = sorted(x["type"] for x in left["events"])
    assert v["missing"] == [f"{kind}: 18 of 19 occurrences counted on both VMs together (1 missing)" for kind in types]
    assert v["model"]["occurrences"] == 111
    assert lines[-1].startswith("marked_rows_per_event minimums: missing: " + v["missing"][0])


def test_a_type_short_on_one_vm_is_named(tmp_path, capsys):
    """Two sessions of VM a left out: a type that had 9 there has 8 or fewer, named per VM when below 8."""
    on_a = [s for s in DECK if s["vm"] == "a"]
    kind = on_a[0]["events"][0]["type"]
    mine = [s for s in on_a if kind in {x["type"] for x in s["events"]}]
    count = len(mine)
    left = mine[:count - 7]  # 7 occurrences of the type stay on VM a.
    audits = deck(tmp_path / "s", tmp_path / "g2", {s["id"]: {"counted": False} for s in left})
    code, doc, _, _ = table(tmp_path, audits, capsys)
    assert code == 1 and f"{kind}: 7 of 8 occurrences counted on VM a (1 missing)" in doc["values"]["missing"]


# ---------------------------------------------------------------- rows outside every window and other causes

def test_rows_outside_every_window_and_rows_of_another_cause_are_findings(tmp_path, capsys):
    """In e01: an invalid row with processes 100 s before its first occurrence (outside every window), an invalid row
    of the traversal modules at the start of its first occurrence (another cause: in the table, not in lambda) and a
    row with a read error outside every window. The first two are findings to explain before any write, the cause
    the rule does not tolerate is a finding; lambda counts no row, which is the finding of lambda = 0 and its
    write."""
    s = DECK[0]
    a = host_times(s["events"][0], 0)
    before, other, error = (seq_at(0, a["host_start_unix"] - 100), seq_at(0, a["host_start_unix"] + 3),
                            seq_at(0, a["host_start_unix"] - 200))
    audits = deck(tmp_path / "s", tmp_path / "g2", {s["id"]: {"invalid": {
        before: ["processes"], other: ["modules"], error: {"read_errors": 1}}}})
    code, doc, _, _ = table(tmp_path, audits, capsys)
    v = doc["values"]
    entry = v["sessions"][0]
    sid = entry["session_id"]
    assert code == 0 and entry["counted"]
    assert entry["outside"]["invalid_processes"] == [{"seq": before, "time_unix": row_time(0, before)}]
    assert entry["outside"]["invalid_other"] == [{"seq": error, "time_unix": row_time(0, error)}]
    assert v["occurrences"][0]["start"]["invalid_other"] == [other]
    assert entry["outside_rule"] == sorted([other, error])
    assert v["model"]["rows_in_windows"] == 0 and v["model"]["proposal"]["invalid_rows.max"] == 0
    assert v["model"]["proposal"]["gate_interval"]["high_windows"] == 656
    assert v["findings"][:3] == [
        f"{sid}: 1 invalid row(s) (with processes) outside every event window, seq {before}: to explain before any "
        "write (Q49)",
        f"{sid}: 1 invalid row(s) (of another cause) outside every event window, seq {error}: to explain before any "
        "write (Q49)",
        f"{sid}: invalid row(s) of a cause the rule does not tolerate, seq {min(other, error)}, {max(other, error)}"]
    assert v["findings"][3].startswith("lambda = 0: no invalid row with processes inside a window, the condition "
                                       "under which decision D4 is reopened")
    assert v["model"]["background"] == {"rows_outside": 1, "sessions": 38, "beta": pytest.approx(1 / 38),
                                        "mu": pytest.approx(1 / 38), "k": 1}


# ---------------------------------------------------------------- the model of Q49 on fixed counts

@pytest.mark.parametrize("rows, k, windows", [(6, 2, 590), (38, 4, 524), (2, 1, 623)])
def test_the_model_of_q49_on_fixed_counts(rows, k, windows):
    """lambda = rows / (2 x 114); N ~ Poisson(6 lambda); the smallest k <= 6 with P(N > k) < 0.01 (counted here), and
    the upper end of the gate interval of that max (the inequality of invalid_rows.note: 656 - 33 max of 720)."""
    mu = 6 * rows / 228
    assert all(poisson_above(mu, j) >= .01 for j in range(k)) and poisson_above(mu, k) < .01
    m = cr.marked_model(rows, 114, {}, 0, 38, P)
    assert (m["lambda"], m["mu"]) == (pytest.approx(rows / 228), pytest.approx(mu))
    assert m["p_above"] == [pytest.approx(poisson_above(mu, j)) for j in range(7)]
    proposal = m["proposal"]
    assert (proposal["invalid_rows.max"], proposal["gate_interval"]["high_windows"]) == (k, windows)
    assert proposal["min_score_coverage"] == pytest.approx(windows / 720)
    assert proposal["gate_interval"]["low_windows"] == windows - 33
    above = [text for text in m["findings"] if "SULAD_S_TEXTOM_PRACE.md" in text]
    assert len(above) == (k > 3)


def test_lambda_zero_is_a_finding_and_a_write():
    """The lead's addition to Q49: at lambda = 0 max is 0 and min_score_coverage the upper end for max 0, 656/720."""
    m = cr.marked_model(0, 114, {}, 0, 38, P)
    assert (m["lambda"], m["mu"], m["proposal"]["invalid_rows.max"]) == (0, 0, 0)
    assert m["proposal"]["min_score_coverage"] == pytest.approx(656 / 720)
    assert m["findings"] == [
        "lambda = 0: no invalid row with processes inside a window, the condition under which decision D4 is reopened "
        "(proposal 12), a finding and also a write: invalid_rows.max 0 and min_score_coverage 0.9111111111 (656/720 "
        "windows) by the inequality of invalid_rows.note (the lead's addition to Q49)"]


def test_no_k_up_to_six_gives_no_value():
    """lambda = 1 (N ~ Poisson(6)): P(N > 6) is far above 0.01, so the rule gives no value; a finding."""
    m = cr.marked_model(228, 114, {}, 0, 38, P)
    assert poisson_above(6, 6) > .01 and m["proposal"] is None
    assert m["findings"] == [f"no k <= 6 has P(N > k) < 0.01 at lambda 1 (N ~ Poisson(6), P(N > 6) = "
                             f"{poisson_above(6, 6):.6g}): no value of invalid_rows.max by the rule"]


def smallest_k(mu):
    """The smallest k <= 6 with P(N > k) < 0.01, counted here; None when there is none."""
    return next((j for j in range(7) if poisson_above(mu, j) < .01), None)


def test_the_rate_per_type_and_the_variant_with_a_background_term():
    """Beside the proposal, descriptive only: lambda_T = rows_T / (2 n_T) of each type with the k it would give, and
    N ~ Poisson(6 lambda + beta), beta the rows outside every window per counted session."""
    m = cr.marked_model(4, 114, {"zataz_pamate": (3, 19), "naprazdno": (0, 19), "udrzba_zaloha": (1, 19)}, 3, 38, P)
    assert m["per_type"] == {
        "zataz_pamate": {"rows": 3, "occurrences": 19, "lambda": pytest.approx(3 / 38), "k": smallest_k(18 / 38)},
        "naprazdno": {"rows": 0, "occurrences": 19, "lambda": 0, "k": 0},
        "udrzba_zaloha": {"rows": 1, "occurrences": 19, "lambda": pytest.approx(1 / 38), "k": smallest_k(6 / 38)}}
    assert (smallest_k(18 / 38), smallest_k(6 / 38)) == (3, 2)
    mu = 6 * 4 / 228 + 3 / 38
    assert m["background"] == {"rows_outside": 3, "sessions": 38, "beta": pytest.approx(3 / 38),
                               "mu": pytest.approx(mu), "k": smallest_k(mu)}
    assert m["proposal"]["invalid_rows.max"] == smallest_k(6 * 4 / 228)


def test_the_constants_are_those_of_the_code_they_name():
    assert cr.MARKED_CAP == protocol_v5.MAX_INVALID_ROWS
    assert cr.G2T_RECORD_SCHEMA == g2.SESSION_SCHEMA and cr.G2T_ROLE == g2.ROLE
    assert cr.G2T_H4_KINDS == (cas.KIND, poruchy.KIND_FAULT, poruchy.KIND_CLEAN)
    assert cr.G2T_FAULT_KIND == poruchy.KIND_FAULT


# ---------------------------------------------------------------- data and usage errors

def tamper(audit, change):
    doc = json.loads(Path(audit).read_text())
    change(doc["values"])
    Path(audit).write_text(json.dumps(doc, indent=1) + "\n")


@pytest.mark.parametrize("case", ["session_json", "archive", "facts", "counts", "no_record", "record_of_another",
                                  "protocol_g0"])
def test_a_session_whose_files_do_not_bind_is_a_data_error(tmp_path, capsys, case):
    s = DECK[0]
    audit = recorded(tmp_path / "s", tmp_path / "g2", s, 0)
    d, sid = audit.parent, audit.parent.name
    protocol = REAL
    if case == "session_json":
        (d / "session.json").write_text((d / "session.json").read_text() + " ")
        words = f"{audit}: {d / 'session.json'} is not the session.json the audit read"
    elif case == "archive":
        tamper(audit, lambda v: v.update(features_sha256="0" * 64))
        words = f"{d / f'audit_{STAMP}.npz'}: its sha256 is"
    elif case == "facts":
        tamper(audit, lambda v: v["acceptance"]["facts"]["rule_closed_seq"].append(7))
        words = "the invalid rows or the rows closed by a parser rule of the feature archive differ"
    elif case == "counts":
        tamper(audit, lambda v: v.update(marked_rows_outside_events=1))
        words = f"{audit}: the marked rows by type counted again"
    elif case == "no_record":
        (tmp_path / "g2" / "zaznamy" / f"{sid}.json").unlink()
        words = f"{d}: no G2 record of the session"
    elif case == "record_of_another":
        path = tmp_path / "g2" / "zaznamy" / f"{sid}.json"
        doc = json.loads(path.read_text())
        doc["values"]["session_json_sha256"] = "0" * 64
        path.write_text(json.dumps(doc))
        words = f"{path}: the G2 record is of the session {json.dumps(sid)}"
    else:
        doc = json.loads(REAL.read_text())
        doc["window_rows"] = 30
        protocol = tmp_path / "other.json"
        protocol.write_text(json.dumps(doc, indent=2) + "\n")
        words = f"{d}: protocol.json has the G0 binding"
    code, doc, lines, err = table(tmp_path, [audit], capsys, protocol=protocol)
    assert (code, doc, lines) == (2, None, [])
    assert words in err and "marked: 1 refusal(s): no table, nothing written" in err


def test_another_protocol_value_of_g2_is_no_data_error(tmp_path, capsys):
    """--protocol differs from the sessions' copies only in the values of G2 (invalid_rows.max and
    min_score_coverage, as a write of G2 changes them): the same G0 binding, so the sessions are read."""
    audit = recorded(tmp_path / "s", tmp_path / "g2", DECK[0], 0)
    doc = json.loads(REAL.read_text())
    doc["invalid_rows"]["max"], doc["min_score_coverage"] = 4, 524 / 720
    protocol = tmp_path / "written.json"
    protocol.write_text(json.dumps(doc, indent=2) + "\n")
    code, record, _, err = table(tmp_path, [audit], capsys, protocol=protocol)
    assert code == 1 and record["values"]["counted_sessions"] == [audit.parent.name], err


def test_an_audit_named_twice_or_two_audits_of_one_session_are_refused(tmp_path, capsys):
    audit = recorded(tmp_path / "s", tmp_path / "g2", DECK[0], 0)
    code, doc, _, err = table(tmp_path, [audit, audit.parent / ".." / audit.parent.name / audit.name], capsys)
    assert (code, doc) == (2, None) and f"an audit record is named more than once: {audit}" in err
    other = audit.with_name("audit_20261126T130000000000Z.json")
    shutil.copyfile(audit, other)
    code, doc, _, err = table(tmp_path, [audit, other], capsys)
    assert (code, doc) == (2, None) and f"2 audit records name one session, {os.path.realpath(audit.parent)}" in err


def test_an_existing_out_is_refused_before_anything_is_read(tmp_path, capsys, monkeypatch):
    out = tmp_path / "marked.json"
    out.write_text("kept\n")

    def unread(*args):
        raise AssertionError("read before --out was refused")
    monkeypatch.setattr(cr, "marked_protocol", unread)
    monkeypatch.setattr(cr, "marked_audit", unread)
    code = cr.main(["marked", str(tmp_path / "no-audit.json"), "--protocol", str(tmp_path / "none.json"), "--out",
                    str(out)])
    captured = capsys.readouterr()
    assert (code, captured.out, out.read_text()) == (2, "", "kept\n")
    assert f"--out already exists, nothing was read or written: {out}" in captured.err


def test_an_out_inside_a_session_directory_is_refused(tmp_path, capsys):
    audit = recorded(tmp_path / "s", tmp_path / "g2", DECK[0], 0)
    out = audit.parent / "marked.json"
    code, doc, _, err = table(tmp_path, [audit], capsys, out=out)
    assert (code, doc, out.exists()) == (2, None, False)
    assert f"refusing to write {out} inside the session directory {audit.parent}" in err
