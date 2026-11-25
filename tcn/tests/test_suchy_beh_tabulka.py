"""The commands hranice and tabulka of the G1 dry run (tcn/suchy_beh.py; protocol v5, G1 preparation, package C4a).

Point 3 of the brief of C4a (dokazy/G1/zadania/C4a.md):
1. on synthetic records with a known answer, both commands give the hand-computed m, decisions, table "bez jedného"
   and rows of znamy_odpovede.json;
2. the lead's check (for_the_lead, exit 3) fires at a difference just above 0.02 (K1) and 0.05 (K2), not just below;
3. every refusal of hranice names its cause;
4. on the records of the small-protocol beh (the fixtures of scripts/tests/test_suchy_beh.py: twenty copies of its
   null run and three of its structured run, the seed of each copy relabeled, since one seed twice is one run), both
   commands run end to end, check E is clean on their --out, and the values file is accepted by the one writer,
   tcn.hodnoty zapis G1, on a copy of config/collection-v5.json in the test's directory;
5. each test of a command fails on the base (the commands do not exist there).
A synthetic run is a directory with the files the commands read of the --out of beh (RUN_RULE): zaznam.json,
final.json (the records of tcn/tests/test_suchy_beh.py, their claims built by the code under test from hand-chosen
values per boot), generator.json, vlozene_chyby.json, kontrola_E.log and suchy_beh.log; the end-to-end test reads real
runs. No test writes config/collection-v5.json, data/results, the ledger of record or docs/. Only mechanics on
synthetic numbers: no number here is a result (HONESTY P4).
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.tests.test_suchy_beh import (  # noqa: F401 - the fixtures of package C3, used by name
    _nothing_of_the_repository_changes, nulovy, strukturovany, svet)
from tcn import suchy_beh as sb
from tcn.tests import test_suchy_beh as c2

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_FILE = ROOT / "config" / "collection-v5.json"
PROTOCOL_SHA256 = hashlib.sha256(PROTOCOL_FILE.read_bytes()).hexdigest()
CLAIMS = ("k1", "k2a", "k2b")
COMMIT, OTHER_COMMIT = "c" * 40, "d" * 40
LIKE, UNLIKE, UNEVALUATED = "threshold-like", "not threshold-like", "nevyhodnotené"
ALL_LIKE = {"Z1": (LIKE, LIKE), "Z2": (LIKE, LIKE), "Z3": (LIKE, LIKE)}
# The working copy of the synthetic runs (zaznam.json values.copy): the values it fills, the same for both generators
# but the column mask (each generator has its own qualification pass); the structured runs run under the file with m
# filled (another sha256 and hash of stage G1, the same hash of stage G0).
FILLED = {"scenarios.eshop_low.rate": 4.4, "scenarios.eshop_high.rate": 11.74, "scenarios.corp_low.rate": 5.7,
          "scenarios.corp_high.rate": 15.0, **{f"analysis.methods.{z}.grid": g for z, g in c2.GRIDS.items()},
          "replacement.max_per_campaign": 9}
MASK = {"nulovy": {"mem_changed_ratio": "neural", "proc_wx": "rule"},
        "strukturovany": {"mem_changed_ratio": "neural", "proc_wx": "rule", "sock_total": "neural"}}
COPY_SHA = {"nulovy": "6" * 64, "strukturovany": "7" * 64}
PROTOCOL = {"nulovy": {"path": "/synteticky/protokol.json", "sha256": "1" * 64, "g0_stage_sha256": "2" * 64,
                       "g1_stage_sha256": "3" * 64},
            "strukturovany": {"path": "/synteticky/protokol.json", "sha256": "4" * 64, "g0_stage_sha256": "2" * 64,
                              "g1_stage_sha256": "5" * 64}}
CHAIN = {"record": {"stage": "suchy", "status": "complete"},
         "group_prefixes": {"campaign": "v5-", "rehearsal": "g5-", "groups": ["g5-train-1", "v5-train-1"]},
         "vms": ["a", "b"], "events": {"sessions": 2, "occurrences": 6}, "controls": {"sessions": 1, "occurrences": 2},
         "tolerated_invalid_rows": {"rows": 3}, "rehearsal": {"sessions": 15, "ending": "/synteticky/generalka.json"},
         "campaign": {"ending": "/synteticky/kampan.json", "corpus_sessions": 30, "planned_sessions": 30,
                      "replacements_used": 1},
         "replacement": {"replaced": [{"session": "v5-train-1_01", "replacement": "v5-train-1_01-r1"}]},
         "report_exit": 0, "check_E": {"exit": 0}}
MARGINAL = {"first_seq": 10, "rows": 3, "column": "mem_changed_ratio"}  # In tb-1 of c2._series: rows 10 to 12.


@pytest.fixture(autouse=True)
def _the_protocol_file_is_never_written():
    """The commands never write the protocol (VALUES_FILE_RULE): config/collection-v5.json keeps its bytes."""
    yield
    assert hashlib.sha256(PROTOCOL_FILE.read_bytes()).hexdigest() == PROTOCOL_SHA256


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _header(schema, values, commit=COMMIT):
    """The header of check E of a synthetic file."""
    return {"schema": schema, "commit": commit, "commit_dirty": False, "date": "2026-11-25T00:00:00+00:00",
            "host": "test", "guest": None, "guest_note": "synthetic", "command": "the test", "n": 1, "values": values}


def _write(path, doc):
    Path(path).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    return Path(path)


def _faults():
    """The values of a vlozene_chyby.json of beh with nine of nine refused and the clean targets admitted."""
    from scripts.tests import vlozene_chyby as vc
    return {"errors": [{"id": chyba.id, "expected": ["the reason"], "got": ["the reason"], "equal": True}
                       for chyba in vc.vsetky()], "refused_as_expected": 9, "of": 9, "clean_admitted": True}


def _nine(faults):
    """The check fault_injections of beh: nine of nine refused as expected and the clean targets admitted."""
    return faults["refused_as_expected"] == faults["of"] == 9 and faults["clean_admitted"] is True


def run_dir(root, generator, seed, record, *, sessions=None, chyby=False, commit=COMMIT, changed=(), start=(),
            filled=None, mask=None, protocol=None, faults=None, change=None):
    """A synthetic --out of beh of `generator` and `seed` below `root` (RUN_RULE): final.json the record (a function of
    the directory gives one that names files in it), its tree on `commit` with the paths `changed`, generator.json with
    `sessions` (GENERATOR_KEYS), vlozene_chyby.json with --chyby, zaznam.json of a run that ended with exit 0 (`change`
    edits its document before it is written), kontrola_E.log with the two blocks of beh and suchy_beh.log whose S2
    header lists the porcelain lines `start`. Returns its path."""
    d = Path(root) / f"{generator}_{seed}"
    d.mkdir(parents=True)
    record = copy.deepcopy(record(d) if callable(record) else record)
    record.update(commit=commit, commit_dirty=bool(changed), date="2026-11-25T00:00:00+00:00", host="test",
                  guest=None, command="tcn.finalne.evaluate(the test)", n=1)
    record["values"]["tree"] = {"commit": commit, "changed": list(changed), "changed_code": []}
    record["values"]["corpus"]["protocol_sha256"] = COPY_SHA[generator]
    final = _write(d / "final.json", record)
    gen = _write(d / "generator.json", _header(sb.SCHEMA_GENERATOR, {
        "generator": {"rezim": generator, "seed": seed}, "sessions": sessions or {}}, commit))
    files = {"copy": {"path": "/synteticky/kopia.json", "sha256": COPY_SHA[generator]},
             "final": {"path": str(final), "sha256": _sha(final)}, "generator": {"path": str(gen), "sha256": _sha(gen)}}
    if chyby:
        path = _write(d / "vlozene_chyby.json", _header(sb.SCHEMA_FAULTS, faults or _faults(), commit))
        files["faults"] = {"path": str(path), "sha256": _sha(path)}
    protocol = protocol or PROTOCOL[generator]
    values = {"status": "complete", "failure": None, "generator": generator, "seed": seed, "cesta": "skratena",
              "chyby": chyby, "protocol": protocol,
              "copy": {"values": {path: {"value": value, "origin": "the test", "file": None}
                                  for path, value in {**(filled or FILLED), sb.COLUMNS: mask or MASK[generator]}.items()},
                       "check": {"paths": sorted(FILLED), "stages": {
                           "G0": {"file": protocol["g0_stage_sha256"], "copy": protocol["g0_stage_sha256"]},
                           "G1": {"file": protocol["g1_stage_sha256"], "copy": protocol["g1_stage_sha256"]}}}},
              "gates": [{"protocol": protocol["path"], "stage": "G1", "requires": "G0", "passed": True},
                        {"protocol": files["copy"]["path"], "stage": "G1", "requires": "G0", "passed": True}],
              "files": files,
              "checks": [{"check": "final_record", "holds": True, "detail": "stage suchy, status complete"},
                         {"check": "report", "holds": True, "detail": "exit 0"},
                         *([{"check": "fault_injections", "holds": _nine(faults or _faults()), "detail": "the test"}]
                           if chyby else [])],
              "known_answers": {"chain_end_to_end": copy.deepcopy(CHAIN)}}
    doc = _header(sb.SCHEMA_RUN, values, commit)
    if change is not None:
        change(doc)
    _write(d / "zaznam.json", doc)
    block = f"# commit {commit}\n# git status --porcelain: (none)\n# when {{}}\ncheck_claims.sh: ok\nexit 0\n"
    (d / "kontrola_E.log").write_text(block.format(sb.E_BEFORE) + block.format(sb.E_AFTER))
    status = "# git status --porcelain:" + ("".join(f"\n#   {line}" for line in start) if start else " (none)")
    (d / "suchy_beh.log").write_text(f"# commit {commit}\n# date 2026-11-25T00:00:00+00:00\n# host test\n{status}\n"
                                     f"# command python -m tcn.suchy_beh beh --generator {generator} --seed {seed}\n")
    return d


def hranice(dirs, out, capsys=None):
    """python -m tcn.suchy_beh hranice: (exit code, the summary or None, stderr)."""
    code = sb.main(["hranice", "--behy", *map(str, dirs), "--out", str(out)])
    captured = capsys.readouterr() if capsys is not None else None
    summary = json.loads(captured.out.strip().splitlines()[-1]) if captured and captured.out.strip() else None
    return code, summary, captured.err if captured else None


def tabulka(dirs, bounds, out, capsys=None):
    """python -m tcn.suchy_beh tabulka: (exit code, the summary or None, stderr)."""
    code = sb.main(["tabulka", "--behy", *map(str, dirs), "--hranice", str(bounds), "--out", str(out)])
    captured = capsys.readouterr() if capsys is not None else None
    summary = json.loads(captured.out.strip().splitlines()[-1]) if captured and captured.out.strip() else None
    return code, summary, captured.err if captured else None


def _values(path):
    return json.loads(Path(path).read_text())["values"]


def _check_e(directory):
    return subprocess.run(["bash", str(ROOT / "scripts/check_claims.sh"), "--json-hlavicky"], cwd=ROOT,
                          env=dict(os.environ, VMIC_RESULTS_DIR=str(directory)), capture_output=True, text=True)


# ------------------------------------------------------------------ the synthetic families


def _const(values_by_method, claim):
    """{method: {boot: value}} of `claim`, every boot of a method at its value (c2's boots)."""
    boots = c2.K1_BOOTS if claim == "k1" else c2.K2_BOOTS
    return {z: dict.fromkeys(boots, float(values_by_method[z])) for z in c2.COMPARE[claim]}


def _flat(k1, k2a=0.0, k2b=0.0):
    """Per claim the values of every method: the same value on every method and boot."""
    return {"k1": _const(dict.fromkeys(c2.COMPARE["k1"], k1), "k1"),
            "k2a": _const(dict.fromkeys(c2.COMPARE["k2a"], k2a), "k2a"),
            "k2b": _const(dict.fromkeys(c2.COMPARE["k2b"], k2b), "k2b")}


_OPISNE = []


def _opisne(likeness=ALL_LIKE, **unscored):
    """opisné of a record the readers read: c2's unscored stretches and metrics (_unscored_record, its arguments
    breaking one of them) and the threshold-likeness of Z1 to Z3 (c2._likeness of `likeness`)."""
    if not unscored and not _OPISNE:
        _OPISNE.append(c2._unscored_record()["values"]["opisné"])
    found = copy.deepcopy(_OPISNE[0] if not unscored else c2._unscored_record(**unscored)["values"]["opisné"])
    found["diagnostics"] = {"threshold_likeness": c2._likeness(likeness)}
    return found


def null_record(per_claim, *, likeness=ALL_LIKE, **unscored):
    """A record of a null run at a null m (c2._record) with the parts the readers read."""
    return c2._record(per_claim, extra={"opisné": _opisne(likeness, **unscored)})


_STRUCTURED = {}


def structured_record(*, m=None, likeness=ALL_LIKE, replay_1=14, control_better=False):
    """A function of the run's directory giving a record of a structured run (c2._structured: M better by every claim
    at about 0.5, the two networks about -0.5, the shuffled one about 0.5 with control_better), undecided at m None or
    decided at m, with the readers' parts: the threshold-likeness, the unscored stretches, and the attachment series
    of c2._series in the directory, where Z1 rises at seq 12 of tb-1 and the replays of seeds 0 and 1 at seq 11 and
    `replay_1` (the marginal change MARGINAL at seq 10 to 12, its horizon of 20 s seq 10 to 14)."""
    key = (json.dumps(m, sort_keys=True), control_better)
    if key not in _STRUCTURED:
        _STRUCTURED[key] = c2._structured(m, control_better=control_better)

    def build(d):
        record = copy.deepcopy(_STRUCTURED[key])
        record["values"]["opisné"].update({k: v for k, v in _opisne(likeness).items() if k != "diagnostics"})
        record["values"]["opisné"]["diagnostics"]["threshold_likeness"] = c2._likeness(likeness)
        record["values"]["attachments"] = {"series": c2._series(
            d / "final.series.npz", z1_edges=[("tb-1", 12)],
            replay_edges={0: [("tb-1", 11, "model_anomaly")], 1: [("tb-1", replay_1, "model_anomaly")]})}
        return record
    return build


def sessions(marginal=False):
    """The sessions of generator.json: c2's inserted invalid rows and unevaluated occurrences, with the marginal
    change MARGINAL in tb-1 for a structured run."""
    found = copy.deepcopy(c2.UNSCORED_GENERATOR["sessions"])
    if marginal:
        found["tb-1"]["marginal_changes"] = [dict(MARGINAL)]
    return found


def family_f():
    """Twenty null runs counted by hand in c2's test of the table without one run: run r = 1..20 has every value per
    boot of K1 at r/64 (so every interval [r/64, r/64]), K2a and K2b at 0."""
    return {r: null_record(_flat(r / 64)) for r in range(1, 21)}


def family_p():
    """Twenty null runs whose table without one run has no exception: run r = 1..18 at r/64 as family_f, runs 19 and
    20 at 18/64."""
    return {r: null_record(_flat(min(r, 18) / 64)) for r in range(1, 21)}


def null_dirs(root, records, *, likeness=None, chyby=(1,)):
    """The null runs of `records` {seed: record} below root, seed 1 with --chyby; likeness {seed: outcomes} replaces
    the threshold-likeness of a run."""
    out = []
    for seed, record in records.items():
        if likeness and seed in likeness:
            record = copy.deepcopy(record)
            record["values"]["opisné"]["diagnostics"]["threshold_likeness"] = c2._likeness(likeness[seed])
        out.append(run_dir(root, "nulovy", seed, record, sessions=sessions(), chyby=seed in chyby))
    return out


def structured_dirs(root, m, *, records=None, chyby=(0,), change=None, faults=None, n=3):
    """The structured runs 0..n-1 below root: seeds 1 and 2 undecided at a null m and seed 0 decided at m (both are
    read at the m of hranice_m.json), seed 0 with --chyby; records {seed: function}, change {seed: function of
    zaznam.json} and faults {seed: values of vlozene_chyby.json} replace a run's record, edit its zaznam.json or its
    errors."""
    records, faults = records or {}, faults or {}
    return [run_dir(root, "strukturovany", seed, records.get(seed) or structured_record(m=m if seed == 0 else None),
                    sessions=sessions(marginal=True), chyby=seed in chyby, change=(change or {}).get(seed),
                    faults=faults.get(seed)) for seed in range(n)]


# ------------------------------------------------------------------ 1. hranice: the hand-computed bounds


def test_hranice_writes_the_hand_computed_bounds_the_lead_check_and_the_values_file(tmp_path, capsys):
    """BOUND_RULE on the twenty runs of c2._null_runs, counted by hand there: K1 Z3 19/64 + 0.05/64, Z5 21/64 +
    0.05/64 sets m of K1; K2a 19/128 + 0.05/128 by all four methods; K2b 0.05 by Z5; the spread of K1 2/64 is above
    0.02, so the lead's check fires (LEAD_RULE): for_the_lead names K1 with both percentiles and the command exits 3
    after writing hranice_m.json, nulove.json and the values file. The values file is what tcn/hodnoty.py read_values
    takes: the three paths of G1, each m with its sources (hranice_m.json, then zaznam.json and final.json of every
    run by path) and its derivation; every JSON of --out has the header of check E and check E is clean there."""
    from tcn import hodnoty
    runs = c2._null_runs()
    dirs = [run_dir(tmp_path / "behy", "nulovy", int(name.split("_")[1]), record) for name, record in runs.items()]
    out = tmp_path / "hranice"
    code, summary, err = hranice(dirs, out, capsys)
    assert code == sb.EXIT_LEAD == 3 and summary["exit"] == 3 and summary["for_the_lead"] == ["k1"]
    assert "for the lead before m is written" in err and "k1" in err
    m = {"k1": 21 / 64 + 0.05 / 64, "k2a": 19 / 128 + 0.05 / 128, "k2b": 0.05}
    found = _values(out / "hranice_m.json")
    assert found["m"] == pytest.approx(m, rel=1e-12) and summary["m"] == found["m"]
    assert found["bounds"] == json.loads(json.dumps(sb.hranice_m(runs)))  # C2's hranice_m of the same records
    assert found["bounds"]["claims"]["k1"]["set_by"] == ["Z5"] and found["bounds"]["claims"]["k2b"]["set_by"] == ["Z5"]
    beside = found["bounds"]["claims"]["k1"]["methods"]["Z3"]
    assert set(beside) >= {"percentile", "pooled_boot_values", "mean_plus_1645_sd", "point_estimates"}
    assert len(beside["point_estimates"]) == 20
    lead, = found["for_the_lead"]
    assert (lead["claim"], lead["spread_bound"], lead["set_by"]) == ("k1", 0.02, ["Z5"])
    assert lead["spread"] == pytest.approx(2 / 64, rel=1e-12)
    assert lead["percentiles"] == pytest.approx({"Z3": 19.05 / 64, "Z5": 21.05 / 64}, rel=1e-12)
    assert found["lead_check"] == {"raised": True, "exit": 3, "rule": sb.LEAD_RULE}
    assert sorted(found["runs"]) == sorted(runs) and found["family"]["commit"] == COMMIT
    values_file = out / sb.VALUES_FILE
    assert found["values_file"]["path"] == str(values_file) and "tcn.hodnoty zapis G1" in found["values_file"]["writer"]
    written, note, _ = hodnoty.read_values(values_file, "G1")
    assert sorted(written) == ["analysis.k1.m", "analysis.k2a.m", "analysis.k2b.m"] and note
    sources = [str(out / "hranice_m.json"), *(str(d / name) for d in sorted(dirs, key=lambda d: int(d.name[7:]))
                                              for name in ("zaznam.json", "final.json"))]
    for claim in CLAIMS:
        item = written[f"analysis.{claim}.m"]
        assert item["value"] == found["m"][claim] and item["sources"] == sources
        assert repr(found["m"][claim]) in item["derivation"] and _sha(out / "hranice_m.json") in item["derivation"]
    null = _values(out / "nulove.json")
    assert null["m"] == found["m"] and null["hranice_m"] == {"path": str(out / "hranice_m.json"),
                                                              "sha256": _sha(out / "hranice_m.json")}
    assert null["decisions"] == json.loads(json.dumps(sb.rozhodnutia(runs, found["m"])))
    assert null["leave_one_out"] == json.loads(json.dumps(sb.bez_jedneho(runs)))
    assert {p.name for p in out.iterdir()} == {"hranice_m.json", "nulove.json", sb.VALUES_FILE, "kontrola_E.log"}
    for name in ("hranice_m.json", "nulove.json"):
        doc = json.loads((out / name).read_text())
        assert all(key in doc for key in ("commit", "date", "host", "guest", "command", "n", "values"))
        assert doc["guest"] is None and doc["guest_note"] == sb.GUEST_NOTE and doc["n"] == 20
    assert _check_e(out).returncode == 0 and "exit 0" in (out / "kontrola_E.log").read_text()


# ------------------------------------------------------------------ 1. both commands: the hand-computed table


@pytest.fixture(scope="module")
def passing(tmp_path_factory):
    """Family P (family_p) and its hranice: m of K1 18/64 exactly (h = 18.05 between two runs at 18/64), K2a and K2b
    0; no spread, so exit 0."""
    root = tmp_path_factory.mktemp("rodina_p")
    dirs = null_dirs(root / "behy", family_p(), likeness={2: {**ALL_LIKE, "Z3": (LIKE, UNEVALUATED)}})
    code = sb.main(["hranice", "--behy", *map(str, dirs), "--out", str(root / "hranice")])
    return root, dirs, code


def _rows(out):
    return {row["criterion"]: row for row in _values(out / "znamy_odpovede.json")["rows"]}


def test_both_commands_give_the_hand_computed_decisions_table_and_rows(passing, tmp_path, capsys):
    """Family P: hranice exits 0 with m {k1 18/64, k2a 0, k2b 0} and no claim for the lead; at m runs 18 to 20
    (intervals [18/64, 18/64]) are undecided and runs 1 to 17 not better, and without one run m stays 18/64 for every
    run (dropping run 18, 19 or 20 leaves two runs at 18/64 at h = 17.1 and 17.1 + 1, dropping another leaves three),
    so neither table has an exception; K2a and K2b undecided everywhere ([0, 0] at 0). tabulka over these twenty and
    three structured runs (M better at about 0.5, both networks not better at about -0.5; the marginal change caught by
    Z1 at 10 s and the replays at 5 s and 20 s of its 20 s horizon; Z1 to Z3 threshold-like everywhere but in null run
    2, whose Z3 is nevyhodnotené for the share of one member, so it is not counted; c2's unscored stretches; null run 1
    and structured run 0 with nine of nine errors) passes every row and exits 0."""
    from scripts import gates
    root, dirs, code = passing
    assert code == 0
    found = _values(root / "hranice" / "hranice_m.json")
    assert found["m"] == {"k1": 18 / 64, "k2a": 0.0, "k2b": 0.0} and found["for_the_lead"] == []
    null = _values(root / "hranice" / "nulove.json")
    outcomes = {name: run["k1"]["outcome"] for name, run in null["decisions"]["runs"].items()}
    assert outcomes == {f"nulovy_{r}": "undecided" if r >= 18 else "not_better" for r in range(1, 21)}
    assert {run["m"]["k1"] for run in null["leave_one_out"]["runs"].values()} == {18 / 64}
    assert all(null["leave_one_out"]["runs"][f"nulovy_{r}"]["claims"]["k1"]["outcome"] == outcomes[f"nulovy_{r}"]
               for r in range(1, 21))
    for claim in ("k2a", "k2b"):
        assert null["decisions"]["claims"][claim]["counts"]["undecided"] == 20
    assert null["reading"]["holds"] is True and all(
        (c["exceptions_at_m"], c["exceptions_leave_one_out"]) == ([], []) for c in null["reading"]["claims"].values())
    structured = structured_dirs(tmp_path / "behy", found["m"])
    out = tmp_path / "tabulka"
    code, summary, _ = tabulka(dirs + structured, root / "hranice" / "hranice_m.json", out, capsys)
    assert code == 0 and summary["passed"] is True
    rows = _rows(out)
    assert list(rows) == list(gates.CRITERIA["G1"])
    assert all(row["passed"] and row["verdict"] == "passed" for row in rows.values())
    assert all(row["reading"] == sb.READINGS[name] for name, row in rows.items())
    assert rows["null_generator"]["detail"]["m"] == found["m"]
    assert set(rows["chain_end_to_end"]["detail"]["runs"]) == {*(f"nulovy_{r}" for r in range(1, 21)),
                                                               "strukturovany_0", "strukturovany_1", "strukturovany_2"}
    assert rows["structured_generator"]["detail"]["strukturovany_1"] == {
        "holds": True, "claims": dict.fromkeys(CLAIMS, "better"),
        "controls": {net: dict.fromkeys(CLAIMS, "not_better") for net in ("shuffled context", "random weights")}}
    diagnostics = rows["diagnostics_controls"]["detail"]["runs"]
    assert diagnostics["nulovy_2"] == {"evaluated": False, "holds": None}
    assert diagnostics["nulovy_3"] == diagnostics["strukturovany_0"] == {"evaluated": True, "holds": True}
    marginal = rows["marginal_change"]["detail"]
    assert marginal["structured"]["strukturovany_2"]["judged"] == 1 and set(marginal["null_runs_changes"].values()) == {0}
    assert rows["fault_injections"]["detail"]["runs_with_faults"] == {"nulovy": ["nulovy_1"],
                                                                      "strukturovany": ["strukturovany_0"]}
    files = {name: out / name for name in sb.SCHEMA_TABLE}
    assert str(files["strukturovane.json"]) in rows["structured_generator"]["files"]
    assert str(dirs[0] / "final.json") in rows["null_generator"]["files"]
    assert str(root / "hranice" / "nulove.json") in rows["null_generator"]["files"]
    assert _values(files["okrajova_zmena.json"])["structured"]["strukturovany_0"]["holds"] is True
    assert _values(files["neskorovane.json"])["unscored"]["nulovy_5"]["holds"] is True
    for path in files.values():
        doc = json.loads(path.read_text())
        assert doc["schema"] == sb.SCHEMA_TABLE[path.name] and doc["guest"] is None and doc["n"] == 23
    assert _check_e(out).returncode == 0


def test_the_table_without_one_run_fails_null_generator_where_the_decisions_at_m_do_not(tmp_path, capsys):
    """Family F (c2's hand count): at the bound of all twenty, 19/64 + 0.05/64, run 20 is better and run 19 not, one
    exception; without run 19 the bound is 18.2/64, without run 20 18.1/64 and without run 18 19.1/64, so runs 19 and
    20 are both better there: two exceptions, and the reading of null_generator (at most one in each table) does not
    hold; tabulka writes the row not passed and exits 1."""
    root = tmp_path
    dirs = null_dirs(root / "behy", family_f())
    code, _, _ = hranice(dirs, root / "hranice", capsys)
    assert code == 0
    null = _values(root / "hranice" / "nulove.json")
    assert null["m"]["k1"] == pytest.approx(19.05 / 64, rel=1e-12)
    loo = null["leave_one_out"]["runs"]
    assert loo["nulovy_19"]["m"]["k1"] == pytest.approx(18.2 / 64, rel=1e-12)
    assert loo["nulovy_20"]["m"]["k1"] == pytest.approx(18.1 / 64, rel=1e-12)
    assert loo["nulovy_18"]["m"]["k1"] == pytest.approx(19.1 / 64, rel=1e-12)
    assert null["reading"]["claims"]["k1"] == {"exceptions_at_m": ["nulovy_20"],
                                               "exceptions_leave_one_out": ["nulovy_19", "nulovy_20"], "holds": False}
    assert null["reading"]["holds"] is False
    m = _values(root / "hranice" / "hranice_m.json")["m"]
    code, summary, _ = tabulka(dirs + structured_dirs(root / "behy", m), root / "hranice" / "hranice_m.json",
                               root / "tabulka", capsys)
    assert code == 1 and summary["rows"] == {**dict.fromkeys(summary["rows"], True), "null_generator": False}
    assert _rows(root / "tabulka")["null_generator"]["detail"]["reading"] == null["reading"]


@pytest.mark.parametrize("case, rows", [
    ("diagnostics_not_evaluated_in_a_structured_run", {"diagnostics_controls"}),
    ("diagnostics_z2_not_threshold_like", {"diagnostics_controls"}),
    ("marginal_change_missed_by_a_replay", {"marginal_change"}),
    ("control_network_better", {"structured_generator"}),
    ("no_structured_run_with_errors", {"fault_injections"}),
    ("eight_of_nine_errors", {"fault_injections", "chain_end_to_end"}),
    ("no_replacement", {"chain_end_to_end"}),
    ("a_check_did_not_hold", {"chain_end_to_end"}),
    ("one_invalid_row_too_few", {"unscored_spans"})])
def test_each_row_fails_by_its_known_answer(case, rows, passing, tmp_path, capsys):
    """One known answer broken in the structured runs of family P, and only its rows fail: the diagnostics not
    evaluated in a structured run (a finding for the lead, Q41) or Z2 not threshold-like by the tree there; the replay
    of seed 1 rising at seq 15, 25 s after the change, beyond its 20 s horizon; the shuffled network better; no
    structured run with --chyby; eight of nine errors refused as expected (the run's own check fault_injections then
    fails, it ended with exit 1, so its chain fails too); no replacement in a structured run; one of its checks not
    held (exit 1: the table reads the run and its chain fails); one row of invalid_input too few in an unscored
    stretch."""
    root, dirs, _ = passing
    m = _values(root / "hranice" / "hranice_m.json")["m"]
    records, chyby, change, faults = {}, (0,), {}, {}
    if case == "diagnostics_not_evaluated_in_a_structured_run":
        records[1] = structured_record(likeness={**ALL_LIKE, "Z1": (UNEVALUATED, LIKE)})
    elif case == "diagnostics_z2_not_threshold_like":
        records[1] = structured_record(likeness={**ALL_LIKE, "Z2": (UNLIKE, LIKE)})
    elif case == "marginal_change_missed_by_a_replay":
        records[2] = structured_record(replay_1=15)
    elif case == "control_network_better":
        records[1] = structured_record(control_better=True)
    elif case == "no_structured_run_with_errors":
        chyby = ()
    elif case == "eight_of_nine_errors":
        faults[0] = _faults()
        faults[0]["errors"][3]["equal"], faults[0]["refused_as_expected"] = False, 8
    elif case == "no_replacement":
        def none(doc):
            doc["values"]["known_answers"]["chain_end_to_end"]["campaign"]["replacements_used"] = 0
            doc["values"]["known_answers"]["chain_end_to_end"]["replacement"]["replaced"] = []
        change[1] = none
    elif case == "a_check_did_not_hold":
        def failed(doc):
            doc["values"]["checks"].append({"check": "reader marginal_change", "holds": False, "detail": "the test"})
        change[1] = failed
    elif case == "one_invalid_row_too_few":
        def few(d):
            record = structured_record()(d)
            record["values"]["opisné"].update({k: v for k, v in _opisne(invalid=1).items() if k != "diagnostics"})
            return record
        records[2] = few
    structured = structured_dirs(tmp_path / "behy", m, records=records, chyby=chyby, change=change, faults=faults)
    code, summary, _ = tabulka(dirs + structured, root / "hranice" / "hranice_m.json", tmp_path / "tabulka", capsys)
    assert code == 1 and summary["passed"] is False
    assert {name for name, passed in summary["rows"].items() if not passed} == rows
    table = _rows(tmp_path / "tabulka")
    if case == "diagnostics_not_evaluated_in_a_structured_run":
        detail = table["diagnostics_controls"]["detail"]
        assert detail["structured_not_evaluated"] == ["strukturovany_1"] and "Q41" in detail["finding_for_the_lead"]
    if case == "marginal_change_missed_by_a_replay":
        assert table["marginal_change"]["detail"]["structured"]["strukturovany_2"]["caught"] == {
            "Z1": 1, "seed 0": 1, "seed 1": 0}
    if case == "eight_of_nine_errors":
        assert table["fault_injections"]["detail"]["runs"]["strukturovany_0"] == {
            "refused_as_expected": 8, "of": 9, "clean_admitted": True, "holds": False}
        chain = table["chain_end_to_end"]["detail"]["runs"]["strukturovany_0"]
        assert chain["exit_reasons"] == ["checks that did not hold: fault_injections"]
    if case == "a_check_did_not_hold":
        found = table["chain_end_to_end"]["detail"]["runs"]["strukturovany_1"]
        assert found["conditions"]["exit_0"] is False and found["conditions"]["replacement"] is True
        assert found["exit_reasons"] == ["checks that did not hold: reader marginal_change"]


# ------------------------------------------------------------------ 2. the lead's check


@pytest.mark.parametrize("claim, difference, fires", [
    ("k1", 0.0201, True), ("k1", 0.0199, False), ("k2a", 0.0501, True), ("k2a", 0.0499, False),
    ("k2b", 0.0501, True), ("k2b", 0.0499, False)])
def test_the_lead_check_fires_just_above_its_bound_and_not_just_below(claim, difference, fires, tmp_path, capsys):
    """LEAD_RULE (the lead's answer to Q33): twenty runs whose every method of every claim is 0 on every boot but the
    last method of `claim`, at `difference`; the percentile of a method of equal point estimates is that value, so the
    percentiles of `claim` differ by `difference`: just above 0.02 (K1) or 0.05 (K2) the claim is named under
    for_the_lead and hranice exits 3 after writing its files, just below for_the_lead is empty and it exits 0."""
    last = c2.COMPARE[claim][-1]
    per = {c: _const({z: difference if (c, z) == (claim, last) else 0.0 for z in c2.COMPARE[c]}, c) for c in CLAIMS}
    record = c2._record(per)
    dirs = [run_dir(tmp_path / "behy", "nulovy", seed, record) for seed in range(20)]
    code, summary, err = hranice(dirs, tmp_path / "hranice", capsys)
    found = _values(tmp_path / "hranice" / "hranice_m.json")
    assert found["bounds"]["claims"][claim]["spread"] == pytest.approx(difference, abs=1e-15)
    assert (code, summary["for_the_lead"], [item["claim"] for item in found["for_the_lead"]]) == (
        (3, [claim], [claim]) if fires else (0, [], []))
    assert ("for the lead before m is written" in err) is fires
    assert (tmp_path / "hranice" / sb.VALUES_FILE).is_file() and (tmp_path / "hranice" / "nulove.json").is_file()


# ------------------------------------------------------------------ 3. the refusals of hranice


_BASE = []


def _base_record():
    """One record of a null run at a null m with every value 0 (built once)."""
    if not _BASE:
        _BASE.append(c2._record(_flat(0.0)))
    return copy.deepcopy(_BASE[0])


@pytest.fixture(scope="module")
def good(tmp_path_factory):
    """Twenty null runs (seeds 0 to 19, every value 0) that hranice takes: exit 0, m 0 for every claim."""
    root = tmp_path_factory.mktemp("dobre")
    dirs = [run_dir(root / "behy", "nulovy", seed, _base_record()) for seed in range(20)]
    code = sb.main(["hranice", "--behy", *map(str, dirs), "--out", str(root / "hranice")])
    return dirs, code


@pytest.mark.parametrize("case, cause", [
    ("fewer_than_20", "19 null runs: the bound m is the 95th percentile on at least 20 runs"),
    ("structured", "is a run of the structured generator: the bound m comes from the runs of the null generator"),
    ("same_seed_twice", "run nulovy_3 is given twice"),
    ("not_complete", "did not complete (status 'failed'"),
    ("a_check_did_not_hold", "did not end with exit 0: checks that did not hold: report"),
    ("check_e_after_zaznam", "did not end with exit 0: kontrola_E.log holds the blocks"),
    ("check_e_now", "check E is not clean over its --out"),
    ("final_changed", "is not the final.json its zaznam.json names"),
    ("commit", "runs nulovy_0 and nulovy_19 ran with another commit"),
    ("commits_within_a_run", "its records name the commits"),
    ("measurement_at_the_final_evaluation", "its measurement code is not that of its commit"),
    ("measurement_at_the_start", "changed measurement code at its start (the S2 header of suchy_beh.log): "
                                 "features/qualification.py"),
    ("protocol", "ran with another protocol file"),
    ("mask", "ran with another column mask"),
    ("copy", "ran with another working copy of the protocol"),
    ("marginal_change", "its generator.json inserted marginal changes into tb-1")])
def test_every_refusal_of_hranice_names_its_cause(case, cause, good, tmp_path, capsys):
    """The twenty null runs of `good`, which hranice takes, with one defect in place of the last of them (or one run
    less, or one more): fewer than 20 null runs; a run of the structured generator; the same seed twice; a run that did
    not complete, that ended with a check not held or a check E after zaznam.json not clean, or whose --out check E
    finds unclean now; a final.json that is not the one its zaznam.json names; another commit, or two commits in the
    records of one run; measurement code changed at the final evaluation or at the start; another protocol file,
    column mask or working copy; a marginal change in a null run (Q36). Each is refused with exit 2 naming its cause,
    before --out is created."""
    dirs, code = good
    assert code == 0
    dirs, last = list(dirs), 19
    edits = {
        "not_complete": {"change": lambda doc: doc["values"].update(status="failed", failure={"step": "8", "error": "x"})},
        "a_check_did_not_hold": {"change": lambda doc: doc["values"]["checks"][1].update(holds=False)},
        "commit": {"commit": OTHER_COMMIT},
        "commits_within_a_run": {"change": lambda doc: doc.update(commit=OTHER_COMMIT)},
        "measurement_at_the_final_evaluation": {"changed": ["scripts/collection.py", "docs/MERANIA.md"]},
        "measurement_at_the_start": {"start": [" M features/qualification.py", "?? data/results/x.json"]},
        "protocol": {"protocol": dict(PROTOCOL["nulovy"], g1_stage_sha256="9" * 64)},
        "mask": {"mask": {"mem_changed_ratio": "rule", "proc_wx": "rule"}},
        "copy": {"filled": dict(FILLED, **{"scenarios.eshop_high.rate": 11.0})},
        "marginal_change": {"sessions": sessions(marginal=True)},
    }
    if case in edits:
        dirs[last] = run_dir(tmp_path / "behy", "nulovy", last, _base_record(), **edits[case])
    elif case in ("check_e_after_zaznam", "check_e_now", "final_changed"):
        dirs[last] = Path(shutil.copytree(dirs[last], tmp_path / "behy" / dirs[last].name))
        if case == "check_e_after_zaznam":
            log = dirs[last] / "kontrola_E.log"
            text = log.read_text()
            at = text.rindex("exit 0")
            log.write_text(text[:at] + "exit 1" + text[at + len("exit 0"):])
        elif case == "check_e_now":
            (dirs[last] / "bez_hlavicky.json").write_text("{}\n")
        else:
            (dirs[last] / "final.json").write_text((dirs[last] / "final.json").read_text() + "\n")
    elif case == "fewer_than_20":
        dirs = dirs[:19]
    elif case == "structured":
        dirs.append(run_dir(tmp_path / "behy", "strukturovany", 0, _base_record()))
    elif case == "same_seed_twice":
        dirs.append(run_dir(tmp_path / "ina", "nulovy", 3, _base_record()))
    out = tmp_path / "hranice"
    code, summary, err = hranice(dirs, out, capsys)
    assert (code, summary) == (2, None) and not out.exists()
    assert err.startswith("tcn.suchy_beh hranice: ") and cause in err, err


def test_the_command_line_of_hranice(tmp_path, capsys):
    """hranice: --behy and --out are required, and an existing --out is refused before anything is read, each with
    exit 2."""
    assert sb.main(["hranice", "--out", str(tmp_path / "x")]) == 2
    assert "the following arguments are required: --behy" in capsys.readouterr().err
    (tmp_path / "je").mkdir()
    assert sb.main(["hranice", "--behy", str(tmp_path / "nie"), "--out", str(tmp_path / "je")]) == 2
    assert f"--out {tmp_path / 'je'} exists" in capsys.readouterr().err


def test_the_command_line_of_tabulka(tmp_path, capsys):
    """tabulka: --behy, --hranice and --out are required, and a --hranice that is no hranice_m.json is refused before
    --out is created, each with exit 2."""
    assert sb.main(["tabulka", "--behy", str(tmp_path), "--out", str(tmp_path / "x")]) == 2
    assert "the following arguments are required: --hranice" in capsys.readouterr().err
    _write(tmp_path / "hranice_m.json", _header("hyptcn3/other/1", {}))
    assert sb.main(["tabulka", "--behy", str(tmp_path / "nie"), "--hranice", str(tmp_path / "hranice_m.json"),
                    "--out", str(tmp_path / "t")]) == 2
    assert "is no hranice_m.json of python -m tcn.suchy_beh hranice" in capsys.readouterr().err
    assert not (tmp_path / "t").exists()


# ------------------------------------------------------------------ the refusals of tabulka


@pytest.mark.parametrize("case, cause", [
    ("a_null_run_missing", "the null runs given are not those of"),
    ("a_null_run_changed", "is not the one"),
    ("hranice_m_edited", "is not what hranice computes from its null runs"),
    ("nulove_edited", "is not what hranice computes from the null runs of"),
    ("nulove_missing", "nulove.json cannot be read"),
    ("two_structured_runs", "2 structured runs: the table reads at least 3"),
    ("structured_at_another_m", "was decided at analysis.k1.m"),
    ("structured_with_another_rate", "ran with other values of the working copy (all but analysis.columns)"),
    ("structured_runs_differ", "ran with another column mask"),
    ("structured_on_an_unknown_commit", "cannot be compared")])
def test_tabulka_refuses_what_is_not_the_family_of_hranice_by_name(case, cause, passing, tmp_path, capsys):
    """TABLE_RULE and FAMILY_RULE: tabulka reads exactly the null runs of hranice_m.json, a hranice_m.json and a
    nulove.json that hranice computes from them, at least three structured runs of one family, run under the values
    of the copy of the null runs (but their mask) on the same measurement code (the commits compared by git) and
    decided at the m of hranice_m.json or at a null m; otherwise exit 2 naming the cause, before --out is created."""
    root, dirs, _ = passing
    bounds_dir = tmp_path / "hranice"
    shutil.copytree(root / "hranice", bounds_dir)
    m = _values(bounds_dir / "hranice_m.json")["m"]
    nulls, records, change, n = list(dirs), {}, {}, 3
    if case == "a_null_run_missing":
        nulls = nulls[1:]
    elif case == "a_null_run_changed":
        copied = tmp_path / "nulovy_1"
        shutil.copytree(dirs[0], copied)
        doc = json.loads((copied / "zaznam.json").read_text())
        doc["values"]["cesta"] = "plna"
        _write(copied / "zaznam.json", doc)
        nulls[0] = copied
    elif case in ("hranice_m_edited", "nulove_edited"):
        name = "hranice_m.json" if case == "hranice_m_edited" else "nulove.json"
        doc = json.loads((bounds_dir / name).read_text())
        doc["values"]["m"]["k1"] = 0.25
        if case == "hranice_m_edited":
            doc["values"]["bounds"]["m"]["k1"] = 0.25
        _write(bounds_dir / name, doc)
    elif case == "nulove_missing":
        (bounds_dir / "nulove.json").unlink()
    elif case == "two_structured_runs":
        n = 2
    elif case == "structured_at_another_m":
        records[0] = structured_record(m=dict(m, k1=0.25))
    elif case == "structured_with_another_rate":
        def rate(doc):
            doc["values"]["copy"]["values"]["scenarios.corp_low.rate"]["value"] = 5.0
        change = {seed: rate for seed in range(3)}
    elif case == "structured_runs_differ":
        def mask(doc):
            doc["values"]["copy"]["values"][sb.COLUMNS]["value"] = MASK["nulovy"]
        change = {2: mask}
    structured = (structured_dirs(tmp_path / "behy", m, records=records, change=change, n=n)
                  if case != "structured_on_an_unknown_commit" else
                  [run_dir(tmp_path / "behy", "strukturovany", seed, structured_record(), commit=OTHER_COMMIT,
                           sessions=sessions(marginal=True), chyby=seed == 0) for seed in range(3)])
    out = tmp_path / "tabulka"
    code, summary, err = tabulka(nulls + structured, bounds_dir / "hranice_m.json", out, capsys)
    assert (code, summary) == (2, None) and not out.exists()
    assert err.startswith("tcn.suchy_beh tabulka: ") and cause in err, err


# ------------------------------------------------------------------ 4. end to end on the records of beh


def _relabeled(source, target, seed):
    """A copy of the --out `source` of a run as the run of `seed`: zaznam.json and generator.json name the seed, and
    zaznam.json the sha256 of the new generator.json; everything else, final.json and its attachments included, is the
    run's (twenty copies of one null run stand for the twenty runs, as in C3's test)."""
    shutil.copytree(source, target)
    generator = json.loads((target / "generator.json").read_text())
    generator["values"]["generator"]["seed"] = seed
    _write(target / "generator.json", generator)
    zaznam = json.loads((target / "zaznam.json").read_text())
    zaznam["values"]["seed"] = seed
    zaznam["values"]["files"]["generator"]["sha256"] = _sha(target / "generator.json")
    _write(target / "zaznam.json", zaznam)
    return target


def test_both_commands_run_end_to_end_on_the_records_of_beh(nulovy, strukturovany, tmp_path, capsys):
    """The small-protocol runs of scripts/tests/test_suchy_beh.py (the null one with --chyby), twenty copies of the
    null run and three of the structured run: hranice writes its files and exits 3 exactly when it names a claim for
    the lead, m being the maximum over the methods of the run's point estimates (twenty equal values); tabulka writes
    the six files with one row per criterion of G1 in its order, the chain passing in every run; on the small protocol
    the known answers need not hold (C3: max_epochs 1), and fault_injections cannot, with no structured run with
    --chyby, so it exits 1. The readers' answers in the table are the runs' own (zaznam.json known_answers); check E is
    clean on both --out; tcn.hodnoty zapis G1 takes the values file on a copy of config/collection-v5.json, writing the
    three m and keeping the binding of stage G0."""
    from scripts import gates
    from tcn import hodnoty
    assert nulovy.code == 0 and strukturovany.code == 0
    null = [_relabeled(nulovy.out, tmp_path / "behy" / f"nulovy_{seed}", seed) for seed in range(20)]
    structured = [_relabeled(strukturovany.out, tmp_path / "behy" / f"strukturovany_{seed}", seed) for seed in range(3)]
    code, summary, err = hranice(null, tmp_path / "hranice", capsys)
    bounds = _values(tmp_path / "hranice" / "hranice_m.json")
    assert code == (3 if bounds["for_the_lead"] else 0) and summary["exit"] == code and summary["check_E"] == 0
    for claim in CLAIMS:
        means = [item["mean"] for item in nulovy.zaznam["values"]["claims"][claim]["methods"].values()]
        assert bounds["m"][claim] == pytest.approx(max(means), rel=1e-12)
    assert bounds["family"]["commit"] == nulovy.zaznam["commit"] and len(bounds["runs"]) == 20
    code, summary, _ = tabulka(null + structured, tmp_path / "hranice" / "hranice_m.json", tmp_path / "tabulka", capsys)
    assert code == 1 and summary["check_E"] == 0
    rows = _rows(tmp_path / "tabulka")
    assert list(rows) == list(gates.CRITERIA["G1"])
    assert rows["chain_end_to_end"]["passed"] is True and len(rows["chain_end_to_end"]["detail"]["runs"]) == 23
    assert rows["fault_injections"]["passed"] is False
    assert rows["fault_injections"]["detail"]["runs_with_faults"]["strukturovany"] == []
    assert all(found["holds"] for found in rows["fault_injections"]["detail"]["runs"].values())
    answers = {run.out: run.zaznam["values"]["known_answers"] for run in (nulovy, strukturovany)}
    for name, values in (("diagnostiky.json", "diagnostics"), ("neskorovane.json", "unscored")):
        found = _values(tmp_path / "tabulka" / name)[values]
        key = {"diagnostics": "diagnostics_controls", "unscored": "unscored_spans"}[values]
        assert found["nulovy_7"] == answers[nulovy.out][key] and found["strukturovany_1"] == answers[
            strukturovany.out][key]
    assert _values(tmp_path / "tabulka" / "okrajova_zmena.json")["structured"]["strukturovany_2"] == answers[
        strukturovany.out]["marginal_change"]
    for out in (tmp_path / "hranice", tmp_path / "tabulka"):
        found = _check_e(out)
        assert found.returncode == 0, found.stdout + found.stderr
        assert all(json.loads(p.read_text())["guest"] is None for p in out.glob("*.json"))
    protocol = tmp_path / "zapis" / "collection-v5.json"
    protocol.parent.mkdir()
    shutil.copyfile(PROTOCOL_FILE, protocol)
    g0 = gates.stage_sha256(protocol, "G0")
    record = hodnoty.zapis("G1", protocol, tmp_path / "hranice" / sb.VALUES_FILE,
                           tmp_path / "zapis" / "hodnoty_G1_20261125T000000Z.json", partial=False, command="the test")
    written = json.loads(protocol.read_text())["analysis"]
    assert {claim: written[claim]["m"] for claim in CLAIMS} == bounds["m"]
    assert gates.stage_sha256(protocol, "G0") == g0 and record["values"]["values_file"]["sha256"] == _sha(
        tmp_path / "hranice" / sb.VALUES_FILE)
