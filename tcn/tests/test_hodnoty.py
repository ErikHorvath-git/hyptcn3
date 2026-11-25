"""The writer of the values of a stage (tcn/hodnoty.py, package H1a; the lead's answer to Q66).

Every test writes into a copy of config/collection-v5.json and a records directory under tmp_path; nothing goes to
config/ or data/results/.
"""
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from scripts import collection, gates, protocol_v5
from scripts.tests import protokol_g0
from tcn import hodnoty

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
# The file as the G0 record holds it (scripts/tests/protokol_g0.py): the writes here start from it, Write 1 of map H0
# point C from the rates null and the caps 500 and 250, while G2 writes its values into V5 from its Zápis 1 on.
G0 = protokol_g0.g0_file()
G1_FINAL = {"analysis.k1.m": 0.05, "analysis.k2a.m": 0.1, "analysis.k2b.m": 0.1}
G2_FINAL = {"invalid_rows.max": 3, "min_score_coverage": 557 / 720, "scenarios.eshop_low.rate": 3.522,
            "scenarios.eshop_high.rate": 9.392, "scenarios.corp_low.rate": 3.0, "scenarios.corp_high.rate": 8.0,
            "audit.warnings_allowed": [], "audit.collector_majflt_max": 0,
            "controls.baseline": {"processes": [-3, 4], "MemAvailable_kb": [-20480, 10240]},
            "profiles.eshop.max_concurrent": 1200, "profiles.corp.max_concurrent": 1000}


@pytest.fixture
def w(tmp_path):
    protocol = tmp_path / "config" / "collection-v5.json"
    protocol.parent.mkdir()
    protocol.write_bytes(G0.read_bytes())
    results = tmp_path / "results"
    results.mkdir()
    source = tmp_path / "zdroj.json"
    source.write_text('{"zdroj": 1}\n')
    return SimpleNamespace(tmp=tmp_path, protocol=protocol, results=results, source=source)


def values_file(w, stage, values, name="hodnoty.json"):
    path = w.tmp / name
    path.write_text(json.dumps({"stage": stage, "values": {
        key: {"value": value, "sources": [str(w.source)], "derivation": f"the test's value of {key}"}
        for key, value in values.items()}}))
    return path


def record_path(w, stage, time="20261125T120000Z"):
    return w.results / f"hodnoty_{stage}_{time}.json"


def write(w, stage, values, *, partial, time="20261125T120000Z"):
    record = record_path(w, stage, time)
    doc = hodnoty.zapis(stage, w.protocol, values_file(w, stage, values, f"hodnoty_{stage}_{time}.in.json"), record,
                        partial=partial, command="test")
    return doc, record


def untouched(w, record):
    """Nothing was written: the protocol is the original file, no record and no temporary file."""
    assert w.protocol.read_bytes() == G0.read_bytes()
    assert not record.exists()
    assert sorted(p.name for p in w.protocol.parent.iterdir()) == ["collection-v5.json"]
    assert not list(w.results.glob(".*"))


def test_a_g2_write_of_one_path(w):
    """--partial with one path of determined_at.G2: the file changes at that path only, in the project's form, the
    loader takes it, G0 and G1 keep their bindings, and the record names the old and new value, the rule quoted from
    the protocol and the source by sha256."""
    before = {stage: gates.stage_binding(w.protocol, stage) for stage in gates.STAGES}
    doc, record = write(w, "G2", {"scenarios.eshop_high.rate": 9.392}, partial=True)
    new = json.loads(w.protocol.read_text())
    old = json.loads(G0.read_text())
    old["scenarios"]["eshop_high"]["rate"] = 9.392
    assert new == old
    assert w.protocol.read_bytes() == (json.dumps(new, indent=2) + "\n").encode()
    collection.protocol(w.protocol)
    after = {stage: gates.stage_binding(w.protocol, stage) for stage in gates.STAGES}
    assert [s for s in gates.STAGES if before[s] == after[s]] == ["G0", "G1"]
    v = doc["values"]
    assert json.loads(record.read_text()) == doc
    assert (v["stage"], v["partial"], doc["n"]) == ("G2", True, 1)
    assert v["earlier_bindings"] == {s: {"sha256": before[s][0], "rule": before[s][1]} for s in ("G0", "G1")}
    assert v["protocol_sha256_before"] == hodnoty._sha256(G0.read_bytes())
    assert v["protocol_sha256_after"] == hodnoty._sha256(w.protocol.read_bytes())
    [path] = v["paths"]
    assert (path["path"], path["pattern"], path["old"], path["new"]) == (
        "scenarios.eshop_high.rate", "scenarios.*.rate", None, 9.392)
    assert [r["source"] for r in path["rule"]] == ["protocol:scenario_rule.basis", "protocol:scenario_rule.note"]
    assert path["rule"][0]["text"] == json.loads(V5.read_text())["scenario_rule"]["basis"]
    assert path["sources"] == [{"path": str(w.source), "resolved": str(w.source), "size": w.source.stat().st_size,
                                "sha256": hodnoty._file_sha256(w.source)}]
    assert v["checks"]["selfcheck"] == {"stage": "G0", "modes": ["campaign", "rehearsal"], "passed": True}
    assert "audit self-test is due" in v["selftest_due"] and "audit_selftest.py" in v["selftest_due"]


def test_a_final_write_names_every_path_of_the_stage(w):
    """Without --partial a write of one path of G2 is refused by name, listing the paths it leaves out."""
    record = record_path(w, "G2")
    with pytest.raises(hodnoty.Refused, match=r"a final write of G2 names every path of determined_at\.G2; missing: "
                                              r"audit\.collector_majflt_max, .*profiles\.eshop\.max_concurrent"):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"scenarios.eshop_high.rate": 9.392}), record,
                      partial=False, command="test")
    untouched(w, record)


def test_a_partial_write(w):
    """Write 1 of map H0 point C: the four rates and the two caps, --partial; the self-check runs at G0, the record
    quotes the row of proposal 10.9 for the caps, and the stage's own binding moves while G0 and G1 stay."""
    values = {f"scenarios.{name}.rate": rate for name, rate in
              (("eshop_low", 3.522), ("eshop_high", 9.392), ("corp_low", 3.0), ("corp_high", 8.0))}
    values.update({"profiles.eshop.max_concurrent": 2255, "profiles.corp.max_concurrent": 1920})
    g2_before = gates.stage_binding(w.protocol, "G2")
    doc, _ = write(w, "G2", values, partial=True)
    v = doc["values"]
    assert doc["n"] == 6 and sorted(p["path"] for p in v["paths"]) == sorted(values)
    assert {p["path"]: p["new"] for p in v["paths"]} == values
    caps = [p for p in v["paths"] if p["pattern"] == "profiles.*.max_concurrent"]
    assert [p["old"] for p in caps] == [250, 500]
    for cap in caps:
        name = cap["path"].split(".")[1]
        assert cap["rule"][0] == {"source": f"protocol:profiles.{name}.note",
                                  "text": json.loads(V5.read_text())["profiles"][name]["note"]}
        row = cap["rule"][1]
        assert row["source"] == "docs/NAVRH_PROTOKOL_V5.sk.md 10.9" and row["cells"]["stage"] == "G2"
        assert row["text"].startswith("| strop súbežnosti profilov") and "dvojnásobok" in row["cells"]["rule"]
    assert v["stage_binding_after"]["sha256"] != g2_before[0]
    assert set(v["earlier_bindings"]) == {"G0", "G1"}
    assert protocol_v5.selfcheck(w.protocol, stage="G0")["passed"]


@pytest.mark.parametrize("path", ["audit.lateness_max_s", "analysis.k1.m", "scenarios.*.rate", "scenarios.eshop.rate",
                                  "determined_at"])
def test_a_path_outside_determined_at_g2_is_refused_by_name(w, path):
    """A G0 value, a path of G1, the pattern itself instead of its paths, a key the file does not have and
    determined_at: each is refused by its name before anything is written, with the rates beside it."""
    record = record_path(w, "G2")
    with pytest.raises(hodnoty.Refused, match=r"not paths of determined_at\.G2, nothing written: " + re.escape(path)
                       + r" \(the stage's paths: "):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"scenarios.eshop_high.rate": 9.392, path: 1}), record,
                      partial=True, command="test")
    untouched(w, record)


def test_a_change_of_an_earlier_stage_binding_is_refused(w, monkeypatch):
    """The bindings of G0 and G1 are read before and after: a write that would change one is refused, even when the
    path check let it through (here a stand-in that admits controls.note, a text of G0)."""
    real = hodnoty.concrete_paths
    monkeypatch.setattr(hodnoty, "concrete_paths", lambda doc, stage: {**real(doc, stage), "controls.note": "G0"})
    monkeypatch.setitem(hodnoty.RULES, "G0", (("controls.note",), None))
    record = record_path(w, "G2")
    with pytest.raises(hodnoty.Refused, match=r"the write changes the binding of stage G0 \(\w{64} -> \w{64}\); "
                                              r"nothing written"):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"controls.note": "another text"}), record,
                      partial=True, command="test")
    untouched(w, record)


def test_a_g1_write_of_k1_m(w):
    """G1 with the same writer (Q66): analysis.k1.m alone is partial and keeps G0's binding; its rule is
    analysis.k1.rule and the row of 10.9 for the bounds m; the final G1 write names the three bounds and passes
    the self-check at G1 in both modes."""
    g0 = gates.stage_binding(w.protocol, "G0")
    doc, _ = write(w, "G1", {"analysis.k1.m": 0.05}, partial=True)
    v = doc["values"]
    assert (v["stage"], v["earlier_bindings"], gates.stage_binding(w.protocol, "G0")) == (
        "G1", {"G0": {"sha256": g0[0], "rule": g0[1]}}, g0)
    [path] = v["paths"]
    assert (path["path"], path["old"], path["new"]) == ("analysis.k1.m", None, 0.05)
    assert path["rule"][0] == {"source": "protocol:analysis.k1.rule",
                               "text": "95th percentile on >= 20 structure-free seeds (G1)"}
    assert path["rule"][1]["cells"] == {"value": "hranice m pre K1 a K2", "stage": "G1",
                                        "rule": "95. percentil na dátach bez štruktúry, aspoň 20 seedov"}
    doc, _ = write(w, "G1", G1_FINAL, partial=False, time="20261125T120100Z")
    assert doc["values"]["checks"]["selfcheck"]["stage"] == "G1"
    assert protocol_v5.selfcheck(w.protocol, stage="G1")["passed"]
    assert not protocol_v5.selfcheck(w.protocol, stage="G2")["passed"]


def test_a_final_g2_write_after_g1(w):
    """H5's write: all 11 paths of G2 named once, the self-check at G2 in both modes, G0 and G1 kept; a value that
    stays (invalid_rows.max 3) is written with its rule and source as well."""
    write(w, "G1", G1_FINAL, partial=False)
    before = {stage: gates.stage_binding(w.protocol, stage) for stage in ("G0", "G1")}
    doc, _ = write(w, "G2", G2_FINAL, partial=False, time="20261125T120100Z")
    v = doc["values"]
    assert (doc["n"], v["partial"], v["checks"]["selfcheck"]["stage"]) == (11, False, "G2")
    assert {p["path"]: (p["old"], p["new"]) for p in v["paths"]}["invalid_rows.max"] == (3, 3)
    assert {stage: gates.stage_binding(w.protocol, stage) for stage in ("G0", "G1")} == before
    assert all(protocol_v5.selfcheck(w.protocol, mode=mode, stage="G2")["passed"] for mode in protocol_v5.MODES)


def test_the_record_header(w, monkeypatch, capsys):
    """The record carries check E's header (scripts/check_claims.sh: commit, date, host, guest, command, n and the
    block values), the command line of python -m tcn.hodnoty, and is named by its stage."""
    values = values_file(w, "G2", {"audit.collector_majflt_max": 0})
    record = record_path(w, "G2")
    argv = ["zapis", "G2", "--protocol", str(w.protocol), "--values", str(values), "--record", str(record),
            "--partial"]
    assert hodnoty.main(argv) == 0
    printed = json.loads(capsys.readouterr().out)
    doc = json.loads(record.read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert doc["schema"] == hodnoty.SCHEMA and doc["guest"] is None and doc["n"] == len(doc["values"]["paths"]) == 1
    assert doc["command"] == "python -m tcn.hodnoty " + " ".join(argv)
    assert doc["commit"] == hodnoty._git("rev-parse", "HEAD").strip()
    assert printed["paths"] == {"audit.collector_majflt_max": {"old": None, "new": 0}}
    assert doc["values"]["paths"][0]["rule"][0]["source"] == "protocol:audit.collector_majflt_note"


def test_an_existing_record_is_refused_before_anything_is_read(w):
    """An existing --record is refused first: neither the values file nor the protocol is read (both are missing
    here) and the record stays as it was."""
    record = record_path(w, "G2")
    record.write_text("{}\n")
    with pytest.raises(hodnoty.Refused, match="exists; nothing was read or written"):
        hodnoty.zapis("G2", w.tmp / "no-protocol.json", w.tmp / "no-values.json", record, partial=True,
                      command="test")
    assert record.read_text() == "{}\n"
    assert hodnoty.main(["zapis", "G2", "--protocol", str(w.protocol), "--values", str(w.tmp / "none.json"),
                         "--record", str(record), "--partial"]) == 2
    assert w.protocol.read_bytes() == G0.read_bytes()


@pytest.mark.parametrize("name", ["hodnoty_G1_20261125T120000Z.json", "hodnoty_G2.json",
                                  "zapis_G2_20261125T120000Z.json"])
def test_a_record_named_otherwise_is_refused(w, name):
    record = w.results / name
    with pytest.raises(hodnoty.Refused, match=r"the record is named hodnoty_G2_<YYYYMMDDTHHMMSSZ>\.json"):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"audit.collector_majflt_max": 0}), record,
                      partial=True, command="test")
    untouched(w, record)


@pytest.mark.parametrize("text, reason", [
    ('{"stage": "G1", "values": {}}', "states stage 'G1', the command writes G2"),
    ('{"stage": "G2", "values": {"audit.collector_majflt_max": {"value": 0, "sources": ["S"]}}}',
     "is an object with exactly"),
    ('{"stage": "G2", "values": {"audit.collector_majflt_max": {"value": 0, "sources": [], "derivation": "d"}}}',
     "sources is a list of distinct files, at least one"),
    ('{"stage": "G2", "values": {"audit.collector_majflt_max": {"value": NaN, "sources": ["S"], "derivation": "d"}}}',
     "NaN is no JSON number"),
    ('{"stage": "G2", "values": {"audit.collector_majflt_max": {"value": 0, "sources": ["S"], "derivation": "d"}, '
     '"audit.collector_majflt_max": {"value": 1, "sources": ["S"], "derivation": "d"}}}', "a key appears twice"),
    ('{"stage": "G2", "values": {"audit.collector_majflt_max": {"value": 0, "sources": ["nowhere"], '
     '"derivation": "d"}}}', "source nowhere is no file"),
], ids=["stage", "no-derivation", "no-source", "nan", "twice", "missing-source"])
def test_a_values_file_without_a_value_source_or_derivation_is_refused(w, text, reason):
    """No silent default: every path names its value, its sources (existing files) and how the value follows."""
    values = w.tmp / "values.json"
    values.write_text(text.replace('"S"', json.dumps(str(w.source))))
    record = record_path(w, "G2")
    with pytest.raises(hodnoty.Refused, match=reason.replace("(", r"\(").replace(")", r"\)")):
        hodnoty.zapis("G2", w.protocol, values, record, partial=True, command="test")
    untouched(w, record)


def test_a_new_file_the_loader_or_the_selfcheck_refuses_is_not_written(w):
    """A rate below zero (the loader) and a gate outside the interval of invalid_rows.max (the self-check): each is
    refused by its check's reason, and nothing is written."""
    record = record_path(w, "G2")
    with pytest.raises(hodnoty.Refused, match="the protocol loader refuses the new file, nothing written: invalid "
                                              "scenarios"):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"scenarios.eshop_high.rate": -1}), record,
                      partial=True, command="test")
    untouched(w, record)
    with pytest.raises(hodnoty.Refused, match="nothing written"):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"invalid_rows.max": 5}), record, partial=True,
                      command="test")
    untouched(w, record)


def test_a_protocol_not_in_the_projects_form_is_refused(w):
    w.protocol.write_text(json.dumps(json.loads(G0.read_text()), indent=1) + "\n")
    before = w.protocol.read_bytes()
    record = record_path(w, "G2")
    with pytest.raises(hodnoty.Refused, match=r"is not in the project's form \(json\.dumps\(doc, indent=2\)"):
        hodnoty.zapis("G2", w.protocol, values_file(w, "G2", {"audit.collector_majflt_max": 0}), record,
                      partial=True, command="test")
    assert w.protocol.read_bytes() == before and not record.exists()


def test_the_v5_file_is_in_the_form_the_writer_keeps():
    """FORM_RULE: config/collection-v5.json is json.dumps(doc, indent=2) plus a newline, the form scripts/lab_trial.py
    writes its copies in and the tests write theirs in; the writer refuses another form and keeps this one."""
    assert hodnoty.form(json.loads(V5.read_text())) == V5.read_bytes()


def test_every_path_of_determined_at_has_its_rule():
    """The writer serves every stage (Q66): each pattern of the v5 file's determined_at has an entry in RULES, each
    concrete path finds its texts in the file, and each row of proposal 10.9 it names exists and names that stage."""
    doc = json.loads(V5.read_text())
    design = ((ROOT / hodnoty.DESIGN).read_text(), "sha")
    patterns = [pattern for paths in doc["determined_at"].values() for pattern in paths]
    assert sorted(patterns) == sorted(hodnoty.RULES)
    counts = {}
    for stage in hodnoty.STAGES:
        paths = hodnoty.concrete_paths(doc, stage)
        counts[stage] = len(paths)
        for path, pattern in paths.items():
            rule = hodnoty.rule_of(doc, path, pattern, stage, design)
            assert rule and all(item["text"].strip() for item in rule)
            assert all(item["cells"]["stage"] == stage for item in rule if "cells" in item)
    assert counts["G2"] == 11 and counts["G1"] == 3
