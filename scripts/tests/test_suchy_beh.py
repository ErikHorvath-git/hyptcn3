"""The command of the G1 dry run, python -m tcn.suchy_beh beh (protocol v5, G1 preparation, package C3).

The column "Hotové, keď" of row C3 of the skeleton dokazy/G1/kostra/KOSTRA.md, with the lead's answers to Q32 and Q37
and point 5 of his POKYNY_TEMPO_2026-11-25, as the coordinator's brief of C3 lists it:
1. on the small v5 protocol (features/tests/test_dataset_plan.py protocol_doc) with events: the whole beh once per
   generator at seed 0 through the full path, and the same seed through the shortened path, with the I and D and the
   intervals of both equal; the final run at a null m; --chyby 9 of 9;
2. a copy with a changed value of G0 refused by name, by the check and by the command;
3. every row of section 2 of the skeleton read from zaznam.json and the records;
4. the fakes named under fakes in zaznam.json and nothing else patched; the run calls scripts/gates.py require of G1
   on the real file and on the copy (a missing record of G0 refuses the run);
5. the header of check E on every record of a run and the full header of S2 on every log.
Package C3b (the lead's answer to Q72 point 2) adds, as the coordinator's brief of C3b lists it:
6. for a session of each scenario at the rates of Zápis 1 of G2 (on a copy of the small protocol), the offered load
   Z4 reads equals the planned load the counts follow (suchy_generatory.ponukana_zataz) within the log audit's
   tolerance, the real audit accepting the clean session; the traffic logs are the generator's and reproducible.
The real plan runs in C4 only. The small protocol takes the numbers its corpus can carry (as
tcn/tests/test_finalne.py _protocol): they are the test's, no judgment of the protocol. Its record of G0 is the
test's, in a directory of the test (--vysledky); no test writes data/results, the ledger of record or docs/. Only
mechanics on synthetic sessions: no number here is a result of detection (HONESTY P4).
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "data" / "results"
TRACKED_LEDGER = RESULTS / "kniha_pecati.json"
CLAIMS = ("k1", "k2a", "k2b")
HEADER_E = ("commit", "date", "host", "guest", "command", "n")
# Package C3b (the test's judgment): the small protocol is 7.5 times shorter than config/collection-v5.json (96 rows
# against 720), and its think times are divided by the same factor (maly_protokol).
THINK_SCALE = 720 / 96


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else None


LISTING = sorted(path.name for path in RESULTS.iterdir())
TRACKED = _digest(TRACKED_LEDGER)
DOCS = {path: _digest(path) for path in (ROOT / "docs/MERANIA.md", ROOT / "docs/ODCHYLKY_V5.sk.md",
                                         ROOT / "docs/PRIRUCKA.md")}


@pytest.fixture(autouse=True)
def _nothing_of_the_repository_changes():
    """No test writes data/results (its listing), the ledger of record or the documents."""
    yield
    assert sorted(path.name for path in RESULTS.iterdir()) == LISTING
    assert _digest(TRACKED_LEDGER) == TRACKED
    assert {path: _digest(path) for path in DOCS} == DOCS


def maly_protokol(root):
    """The small protocol of the v5 shape of features/tests/test_dataset_plan.py protocol_doc (five roles, two groups
    each on two VMs, sessions of 96 rows of 5 s, a window of 8 rows) with the events suchy_generatory needs (per_session
    [0, 3], as config/collection-v5.json: a full round of the six types in two sessions of a group), min_free_gib 0
    (sessions of a few MB on pytest's tmpfs, as kampan_v5 Harness.protocol) and the analysis numbers a corpus of this
    size carries, as tcn/tests/test_finalne.py _protocol takes them: 4 carrier boots, short blocks, few repetitions and
    resamples, an evaluable occurrence of 10 s, a horizon and a reverberation of 20 s, 2 positive episodes; the
    controls' horizon 30 s. Package C3b: the think times of both profiles (think_s mean and max) divided by
    THINK_SCALE, so that a user session of the real generator (suchy_kampan.PREVADZKA_RULE) is as long against the
    session and its events as on the plan of config/collection-v5.json; with the file's think times an eshop user
    session that orders outlasts the gaps of up to three event windows of 30 to 60 s in 8 minutes, and the log audit's
    order share, read outside every window (scripts/traffic_log.py realism), refuses the session. Its later-stage
    values are those protocol_doc gives (rates and grids null, every column neural, no replacement): the working copy
    of the command fills them. Returns the path of the file."""
    from features.tests import test_dataset_plan as dp
    from scripts import collection
    profile = root / "profile"
    profile.mkdir()
    (profile / "symbols.txt").write_text("synthetic profile\n")
    doc = dp.protocol_doc(profile)
    doc["events"]["per_session"] = [0, 3]
    doc["min_free_gib"] = 0
    a = doc["analysis"]
    a.update(reverberation_s=20, horizon_s=20, evaluable={"first_s": 10, "scored_share": 0.5}, min_occurrences=1)
    a["interventions"]["min_evaluable"] = 1
    a["interventions"]["boots"] = 4
    for cls in ("C", "D"):
        a["interventions"][cls].update(lengths=[2, 4], per_boot=2)
    a["matched_rate"]["z0_repetitions"] = 3
    a["statistics"]["bootstrap"] = 200
    a["diagnostics"]["min_positive_episodes"] = 2
    doc["controls"]["horizon_s"] = 30
    for params in doc["profiles"].values():
        params["think_s"] = dict(params["think_s"], mean=params["think_s"]["mean"] / THINK_SCALE,
                                 max=params["think_s"]["max"] / THINK_SCALE)
    path = root / "protokol.json"
    collection.write_json(path, doc)
    collection.protocol(path)
    return path


def zaznam_g0(results, protocol):
    """The test's record of stage G0 for the small protocol in `results`: what scripts/gates.py status reads as valid
    for it and the current measurement code (every criterion passed, an independent verification)."""
    from scripts import gates
    record = {"schema": gates.SCHEMA, "date": "2026-11-25T00:00:00+00:00",
              "values": {"stage": "G0", "protocol_sha256": gates.stage_sha256(protocol, "G0"),
                         "measurement_sha256": gates.measurement_sha256(),
                         "criteria": {name: {"passed": True, "evidence": "the test's record of G0"}
                                      for name in gates.CRITERIA["G0"]},
                         "verification": {"independent": True, "by": "the test",
                                          "verdicts": dict.fromkeys(gates.CRITERIA["G0"], "confirmed")}}}
    (results / "gate_G0_20261125T000000Z.json").write_text(json.dumps(record))


@pytest.fixture(scope="module")
def svet(tmp_path_factory):
    root = tmp_path_factory.mktemp("suchy")
    protocol = maly_protokol(root)
    results = root / "vysledky"
    results.mkdir()
    zaznam_g0(results, protocol)
    return SimpleNamespace(root=root, protocol=protocol, results=results)


def beh(svet, name, generator, cesta, *extra, results=None):
    """python -m tcn.suchy_beh beh of the small protocol at seed 0 (tcn.suchy_beh main)."""
    from tcn import suchy_beh
    out, praca = svet.root / name / "out", svet.root / name / "praca"
    code = suchy_beh.main(["beh", "--generator", generator, "--seed", "0", "--out", str(out), "--praca", str(praca),
                           "--cesta", cesta, "--protocol", str(svet.protocol),
                           "--vysledky", str(results or svet.results), *extra])
    zaznam = out / "zaznam.json"
    return SimpleNamespace(code=code, out=out, praca=praca,
                           zaznam=json.loads(zaznam.read_text()) if zaznam.exists() else None)


@pytest.fixture(scope="module")
def nulovy(svet):
    return beh(svet, "nulovy", "nulovy", "plna", "--chyby")


@pytest.fixture(scope="module")
def strukturovany(svet):
    return beh(svet, "strukturovany", "strukturovany", "plna")


def _record(run):
    return json.loads((run.out / "final.json").read_text())


def _generator(run):
    return json.loads((run.out / "generator.json").read_text())["values"]


def _plain(value):
    from tcn.finalne import _json_default
    return json.loads(json.dumps(value, default=_json_default))


# ------------------------------------------------------------------ 1. the whole run, the null m, --chyby


@pytest.mark.parametrize("name", ["nulovy", "strukturovany"])
def test_the_whole_run_of_each_generator_ends_with_its_record_at_a_null_m(name, request):
    """Each generator at seed 0, the full path: exit 0, every check of the run held; the final record is of stage
    suchy, complete, written by the real tcn.finalne evaluate on the run's own ledger, and at a null m every claim is
    evaluated with its intervals and the outcome null with the sentence of M_NULL_RULE; the threads are VLAKNA
    (Q37), no internet socket connected, and the session directories were deleted after the run (CLEANUP_RULE)."""
    from tcn import finalne, suchy_beh
    run = request.getfixturevalue(name)
    assert run.code == 0, run.zaznam["values"].get("failure") or run.zaznam["values"]["checks"]
    values = run.zaznam["values"]
    assert (values["status"], values["generator"], values["seed"], values["cesta"]) == ("complete", name, 0, "plna")
    assert values["checks"] and all(check["holds"] for check in values["checks"])
    record = _record(run)
    assert (record["schema"], record["stage"], record["values"]["status"]) == (finalne.SCHEMA, "suchy", "complete")
    assert record["values"]["seal"]["ledger"] == str((run.praca / "kniha" / "kniha_pecati.json").resolve())
    for claim in CLAIMS:
        found, conclusion = record["values"]["claims"][claim], record["values"]["conclusions"][claim]
        assert (found["m"], found["outcome"], conclusion["status"]) == (None, None, "evaluated")
        assert conclusion["conclusion"] == finalne.M_NULL
        assert all(len(item["interval"]) == 2 for item in found["methods"].values())
    assert values["threads"]["torch_threads"] == suchy_beh.VLAKNA == 2
    chain = values["known_answers"]["chain_end_to_end"]
    assert chain["network"]["attempts"] == []
    assert not (run.praca / "kampan" / "collections").exists() and (run.praca / "kampan" / "archive").is_dir()
    assert str(run.praca / "kampan" / "collections") in values["cleanup"]["removed"]


def test_the_nine_injected_errors_are_refused_by_their_reasons_and_the_clean_targets_admitted(nulovy):
    """--chyby (FAULTS_RULE): the nine errors of scripts/tests/vlozene_chyby.py vsetky in its order, on the run's own
    targets, each refused by exactly the reasons its injection expects, each reason a form of the constants of its
    error; a clean target of each kind admitted."""
    from scripts.tests import vlozene_chyby as vc
    doc = json.loads((nulovy.out / "vlozene_chyby.json").read_text())
    values = doc["values"]
    errors = vc.vsetky()
    assert [row["id"] for row in values["errors"]] == [error.id for error in errors]
    for row, error in zip(values["errors"], errors):
        assert row["got"] == row["expected"] and row["equal"] and row["got"], row
        assert row["ciel"] == error.ciel.__name__ and row["krok"] == error.krok.__name__
        for reason in row["got"]:
            forms = [re.escape(form).replace(r"\{", "{").replace(r"\}", "}") for form in error.dovody]
            patterns = [re.sub(r"\{[a-z_0-9]+\}", ".+", form) for form in forms]
            assert any(re.fullmatch(pattern, reason) for pattern in patterns), (row["id"], reason)
    assert (values["refused_as_expected"], values["of"], values["clean_admitted"]) == (9, 9, True)
    clean = values["clean_targets"]
    assert clean["Session"]["got"] == [] and clean["Korpus"]["got"] == []
    assert clean["Pecat"]["krok_finalne"]["status"] == "complete"
    assert clean["Pecat"]["krok_prehratie"]["allowed"] == "not_sealed"
    assert nulovy.zaznam["values"]["known_answers"]["fault_injections"]["refused_as_expected"] == 9


# ------------------------------------------------------------------ 1. the shortened path


@pytest.fixture(scope="module")
def nulovy_skratena(svet):
    return beh(svet, "nulovy-skratena", "nulovy", "skratena")


@pytest.fixture(scope="module")
def strukturovany_skratena(svet):
    return beh(svet, "strukturovany-skratena", "strukturovany", "skratena")


def _metody(claims):
    """{claim: {method: (values per boot, mean, interval)}} of the claims of a record."""
    return {claim: {z: (item["values"], item["mean"], item["interval"]) for z, item in found["methods"].items()}
            for claim, found in claims.items()}


@pytest.mark.parametrize("generator", ["nulovy", "strukturovany"])
def test_the_shortened_path_gives_the_i_d_and_intervals_of_the_full_one(generator, request):
    """POKYNY_TEMPO point 5: the same seed 0 through the whole beh by the shortened path (--cesta skratena) gives the
    same I (K1) and D (K2a, K2b) per boot, the same point estimates and the same intervals as the full path, as do the
    shares of K2 of M and of every compared method, the threshold-likeness of Z1 to Z3 and the known answers of the
    diagnostics, the marginal change and the unscored stretches; in the structured run the claims of the model with
    shuffled context and of the network with random weights are the full path's too. What it left out is missing: the
    descriptive methods, the context truncation, and the networks of the diagnostics but those two in the structured
    run (all of them in the null run)."""
    from tcn import finalne, suchy_beh
    full_run, short_run = request.getfixturevalue(generator), request.getfixturevalue(generator + "_skratena")
    assert short_run.code == 0, short_run.zaznam["values"].get("failure") or short_run.zaznam["values"]["checks"]
    values = short_run.zaznam["values"]
    assert values["cesta"] == "skratena" and values["shortening"] == {
        "rule": suchy_beh.SHORT_RULE, "kept_networks": list(suchy_beh.KEPT_NETWORKS[generator])}
    full, short = _record(full_run)["values"], _record(short_run)["values"]
    assert _metody(short["claims"]) == _metody(full["claims"])
    assert short["k2_values"]["shares"] == full["k2_values"]["shares"]
    for name in ("diagnostics_controls", "marginal_change", "unscored_spans"):
        assert values["known_answers"][name] == full_run.zaznam["values"]["known_answers"][name], name
    opisne_full, opisne_short = full[finalne.OPISNE], short[finalne.OPISNE]
    assert opisne_short["diagnostics"]["threshold_likeness"] == opisne_full["diagnostics"]["threshold_likeness"]
    assert opisne_full["descriptive_methods"]["methods"] and not opisne_short["descriptive_methods"]["methods"]
    assert opisne_full["diagnostics"]["context"] and opisne_short["diagnostics"]["context"] == {}
    kept = suchy_beh.KEPT_NETWORKS[generator]
    assert sorted(opisne_short["diagnostics"]["models"]) == sorted(kept)
    assert len(opisne_full["diagnostics"]["models"]) == len(finalne._variants())
    claims_full, claims_short = opisne_full["diagnostics"]["claims"], opisne_short["diagnostics"]["claims"]
    if kept:
        for name in kept:
            assert _metody(claims_short[name]["claims"]) == _metody(claims_full[name]["claims"])
    else:
        assert claims_short["not_computed"] == suchy_beh.SHORT_RULE


def test_the_shortened_path_replaces_only_what_the_criteria_do_not_read():
    """SHORT_RULE: inside skratena_cesta only fit_methods, diagnostic_fits, _variants and control_claims of tcn.finalne
    differ, and evaluate, k1_claim and k2_claims of tcn/finalne.py, k2_values of tcn/k2.py and tcn.tvrdenia are the
    same objects (I and D by the same functions, not a copy); everything is restored after the block."""
    from tcn import finalne, k2, tvrdenia, suchy_beh
    names = ("evaluate", "k1_claim", "k2_claims", "fit_methods", "diagnostic_fits", "_variants", "control_claims",
             "sealed_part", "unsealed_part", "undecided_claim")
    before = {name: getattr(finalne, name) for name in names}
    fixed = (k2.k2_values, tvrdenia.rozhodni, tvrdenia.vysledok)
    with suchy_beh.skratena_cesta("strukturovany"):
        changed = {name for name in names if getattr(finalne, name) is not before[name]}
        assert (k2.k2_values, tvrdenia.rozhodni, tvrdenia.vysledok) == fixed
    assert changed == {"fit_methods", "diagnostic_fits", "_variants", "control_claims"}
    assert all(getattr(finalne, name) is before[name] for name in names)


# ------------------------------------------------------------------ 2. the working copy


def _copy(svet, tmp_path, change=None):
    """The working copy of the command (hodnoty_kopie) of the small protocol, `change(doc)` applied; its path."""
    from tcn import suchy_beh
    doc = json.loads(svet.protocol.read_text())
    for path, item in suchy_beh.hodnoty_kopie(doc).items():
        suchy_beh._nastav(doc, path, item["value"])
    if change is not None:
        change(doc)
    path = tmp_path / f"kopia-{len(list(tmp_path.iterdir()))}.json"
    path.write_text(json.dumps(doc))
    return path


@pytest.mark.parametrize("path, value", [("cycles", 97), ("analysis.seeds", [0, 1, 2, 3]),
                                         ("analysis.k1.compare", ["Z3"]), ("analysis.k2a.m", 0.1),
                                         ("events.per_session", [0, 2]),
                                         ("determined_at.G3a", ["analysis.columns"])])
def test_a_copy_with_a_changed_value_of_g0_or_g1_is_refused_by_name(path, value, svet, tmp_path):
    """COPY_RULE (the lead's answer to Q32): the copy differs from the file only at paths of stages after G1; a copy
    that changes a value of G0, a bound m of G1 or determined_at itself is refused naming the path, and scripts/gates.py
    require of G1 refuses it as well (its hash of G0 is no longer the record's). The copy of the command itself passes
    with its paths listed and the stage hashes of the file."""
    from scripts import gates
    from tcn import suchy_beh
    good = suchy_beh.over_kopiu(svet.protocol, _copy(svet, tmp_path))
    assert {path.split(".")[0] for path in good["paths"]} == {"analysis", "replacement", "scenarios"}
    assert all(item["file"] == item["copy"] for item in good["stages"].values())
    assert suchy_beh._gate(svet.results, _copy(svet, tmp_path))["passed"] is True
    bad = _copy(svet, tmp_path, lambda doc: suchy_beh._nastav(doc, path, value))
    with pytest.raises(ValueError, match=re.escape(f"differs from the protocol file {svet.protocol} at {path}, which "
                                                   "determined_at assigns to no stage after G1")):
        suchy_beh.over_kopiu(svet.protocol, bad)
    if path.split(".")[0] != "determined_at" and path != "analysis.k2a.m":
        with pytest.raises(ValueError, match="stage G0 is not valid"):
            gates.require(svet.results, bad, "G1")


def test_the_copy_takes_the_rate_of_the_file_where_g2_wrote_it():
    """The lead's answer to Q72 point 3: the copy takes the file's rate of a scenario where it is not null (after
    Zápis 1 of G2), with that origin in zaznam.json, and the lab trial's rate where it is null."""
    from features.tests import test_dataset_plan as dp
    from tcn import suchy_beh
    doc = dp.protocol_doc("profile")
    doc["scenarios"]["eshop_high"]["rate"] = 11.7376
    rates = {path: item for path, item in suchy_beh.hodnoty_kopie(doc).items() if path.endswith(".rate")}
    assert rates.pop("scenarios.eshop_high.rate") == {"value": 11.7376, "origin": suchy_beh.FILE_RATE_ORIGIN}
    assert rates == {f"scenarios.{name}.rate": {"value": suchy_beh.RATES[s["intensity"]],
                                                "origin": suchy_beh.RATE_ORIGIN}
                     for name, s in doc["scenarios"].items() if name != "eshop_high"}


def test_the_command_refuses_a_copy_with_a_changed_value_of_g0_by_name(svet, monkeypatch):
    """The command checks its own copy (COPY_RULE): when the values it fills hold a value of G0 (here cycles, the
    only change of the test), the run is refused at its second step naming the path, with exit 2 and zaznam.json."""
    from tcn import suchy_beh
    real = suchy_beh.hodnoty_kopie
    monkeypatch.setattr(suchy_beh, "hodnoty_kopie",
                        lambda doc: {**real(doc), "cycles": {"value": doc["cycles"] + 1, "origin": "the test"}})
    run = beh(svet, "zmena_g0", "nulovy", "plna")
    assert run.code == 2
    failure = run.zaznam["values"]["failure"]
    assert failure["step"] == "2 pracovna kopia bez masky"
    assert "at cycles, which determined_at assigns to no stage after G1" in failure["error"]
    assert not (run.praca / "kampan").exists()


def test_the_run_calls_the_gate_of_g1_on_the_file_and_on_the_copy(nulovy, svet):
    """The run calls the real scripts/gates.py require of G1 (a valid record of G0) on the protocol file and on its
    copy, whose hashes of G0 and G1 are the file's; without a record of G0 the run is refused at its first step."""
    from scripts import gates
    values = nulovy.zaznam["values"]
    files = values["files"]
    assert [gate["protocol"] for gate in values["gates"]] == [str(svet.protocol), files["copy"]["path"]]
    assert all(gate["passed"] and gate["stage"] == "G1" and gate["requires"] == "G0" for gate in values["gates"])
    assert {gate["g0_stage_sha256"] for gate in values["gates"]} == {gates.stage_sha256(svet.protocol, "G0")}
    assert values["copy"]["check"]["stages"]["G1"]["copy"] == gates.stage_sha256(svet.protocol, "G1")
    empty = svet.root / "bez_g0"
    empty.mkdir()
    run = beh(svet, "bez_g0_beh", "nulovy", "plna", results=empty)
    assert run.code == 2
    assert run.zaznam["values"]["failure"]["step"] == "1 protokol a stupne"
    assert "stage G0 is not valid: no record" in run.zaznam["values"]["failure"]["error"]


def test_the_copy_holds_the_values_of_later_stages_with_their_origin(nulovy):
    """Q32: the copy's values, each with its origin and the file's value: the rates of the lab trial, the full grids of
    Z1, Z3 and Z5 with their edge members, the limit of proposal 7.5 and the mask of the qualification pass, whose
    record names the classes by construction beside it."""
    from tcn import suchy_beh
    values = nulovy.zaznam["values"]["copy"]["values"]
    assert {path: item["value"] for path, item in values.items() if path.endswith(".rate")} == {
        "scenarios.eshop_low.rate": 1.2, "scenarios.eshop_high.rate": 3.2, "scenarios.corp_low.rate": 1.2,
        "scenarios.corp_high.rate": 3.2}
    assert values["analysis.methods.Z1.grid"]["value"] == {"moving_average_rows": [2, 4, 8],
                                                          "cusum_shift": [0.0, 0.25, 0.5, 1.0, 2.0]}
    assert values["analysis.methods.Z3.grid"]["value"]["ewma_alpha"][-1] == 1.0
    assert values["analysis.methods.Z5.grid"]["value"]["ridge_alpha"][-1] == 1e4
    assert values["replacement.max_per_campaign"]["value"] == 9
    assert all(item["origin"] for item in values.values())
    assert values["replacement.max_per_campaign"]["file"] == 0  # protocol_doc's: no rule, nothing replaced
    kvalifikacia = json.loads((nulovy.out / "kvalifikacia.json").read_text())["values"]
    assert values["analysis.columns"]["value"] == kvalifikacia["proposed_columns"]
    assert (kvalifikacia["generator"], kvalifikacia["seed"]) == ("nulovy", 0)
    assert kvalifikacia["classes_by_construction"] and kvalifikacia["rule"] == suchy_beh.MASK_RULE
    assert {s["role"] for s in kvalifikacia["sessions"]} == {"train", "dev"}


# ------------------------------------------------------------------ 3. section 2, read from zaznam.json and the records


def test_every_row_of_section_2_can_be_read_from_zaznam_json_and_the_records(nulovy, strukturovany):
    """Every criterion of G1 (scripts/gates.py CRITERIA) has its entry in zaznam.json, and the readers of
    tcn/suchy_beh.py read it again from final.json and generator.json: the chain (prefixes, two VMs, events, controls,
    tolerated invalid rows, rehearsal and campaign, one replacement of the injected rejection, check E), the bounds
    and decisions over the null run's record (20 copies of it stand for the 20 runs of C4), the structured run's
    claims at given bounds, the diagnostics, the marginal change (none in the null run, one per group of test_benign
    in the structured one), the unscored stretches and the injected errors."""
    from scripts import gates
    from tcn import suchy_beh
    for run in (nulovy, strukturovany):
        values = run.zaznam["values"]
        answers = values["known_answers"]
        assert sorted(answers) == sorted(gates.CRITERIA["G1"])
        final, generator = run.out / "final.json", _generator(run)
        chain = answers["chain_end_to_end"]
        assert (chain["record"]["stage"], chain["record"]["status"]) == ("suchy", "complete")
        assert chain["vms"] == ["a", "b"]
        assert {group[:3] for group in chain["group_prefixes"]["groups"]} == {"v5-", "g5-"}
        assert chain["events"]["occurrences"] > 0 and chain["controls"]["occurrences"] > 0
        assert chain["tolerated_invalid_rows"]["rows"] >= 5
        assert len(chain["replacement"]["replaced"]) == 1 and chain["replacement"]["rejected"][0]["read_error"]
        assert chain["campaign"]["replacements_used"] == 1 and chain["rehearsal"]["sessions"] == 15
        assert chain["check_E"]["exit"] == 0 and chain["report_exit"] == 0
        assert answers["diagnostics_controls"] == _plain(suchy_beh.diagnostiky(final))
        assert answers["marginal_change"] == _plain(suchy_beh.okrajova_zmena(final, generator))
        assert answers["unscored_spans"] == _plain(suchy_beh.neskorovane(final, generator))
        assert answers["unscored_spans"]["holds"] is True
        assert values["claims"] == suchy_beh._riadky_tvrdeni(_record(run)["values"])
    bounds = suchy_beh.hranice_m({f"nulovy_{i}": nulovy.out / "final.json" for i in range(suchy_beh.MIN_RUNS)})
    for claim in CLAIMS:
        estimates = {z: item["mean"] for z, item in nulovy.zaznam["values"]["claims"][claim]["methods"].items()}
        assert bounds["m"][claim] == pytest.approx(max(estimates.values()))
    decided = suchy_beh.rozhodnutia({"nulovy_0": nulovy.out / "final.json"}, bounds["m"])
    assert set(decided["runs"]["nulovy_0"]) == set(CLAIMS)
    structured = suchy_beh.strukturovane(strukturovany.out / "final.json", bounds["m"])
    assert set(structured["controls"]) == {"shuffled context", "random weights"}
    assert strukturovany.zaznam["values"]["known_answers"]["structured_generator"]["applies"] is True
    assert nulovy.zaznam["values"]["known_answers"]["marginal_change"]["changes"] == []
    changes = strukturovany.zaznam["values"]["known_answers"]["marginal_change"]["changes"]
    assert len(changes) == 2 and all(change["rows"] == 12 for change in changes)
    assert strukturovany.zaznam["values"]["known_answers"]["fault_injections"] == {"not_run": "the run had no --chyby"}


# ------------------------------------------------------------------ 4. the fakes


def test_the_fakes_are_named_and_nothing_else_is_patched(nulovy, svet, tmp_path):
    """The harness of the run (suchy_kampan.Kampan) patches exactly the attributes FAKES and INFRASTRUCTURE name, the
    environment as the fake root names it, and the ledger of record stays the tracked file (stage suchy); zaznam.json
    names the fakes, the infrastructure and the command's own patches."""
    import scripts.audit_selftest
    import scripts.campaign
    import scripts.collection
    import scripts.gates
    import tcn.pecat
    from scripts import collection
    from scripts.tests import suchy_kampan as sk
    from tcn import suchy_beh
    modules = {"scripts.campaign": scripts.campaign, "scripts.collection": scripts.collection,
               "scripts.gates": scripts.gates, "scripts.audit_selftest": scripts.audit_selftest, "tcn.pecat": tcn.pecat,
               "subprocess": subprocess, "os": os}
    before = {name: dict(vars(module)) for name, module in modules.items()}
    environment = dict(os.environ)
    copy_path = Path(nulovy.zaznam["values"]["files"]["copy"]["path"])
    p = collection.protocol(copy_path)
    with pytest.MonkeyPatch.context() as mp:
        (tmp_path / "kniha").mkdir()
        sk.Kampan(tmp_path / "kampan", mp, protokol=p, rezim="nulovy", seed=0, kniha=tmp_path / "kniha" / "k.json")
        changed = {f"{name}.{key}" for name, module in modules.items() for key, value in vars(module).items()
                   if before[name].get(key, before) is not value}
        env = {f"env {key}" for key in set(environment) | set(os.environ)
               if environment.get(key) != os.environ.get(key)}
        ledger_of_record = tcn.pecat.ZAZNAM
    named = {patch for item in (*sk.FAKES, *sk.INFRASTRUCTURE) for patch in item["patches"]}
    assert changed == {patch for patch in named if not patch.startswith("env ")}
    assert "env SUDO_USER" in env and env <= {patch for patch in named if patch.startswith("env ")}
    assert ledger_of_record == before["tcn.pecat"]["ZAZNAM"]
    values = nulovy.zaznam["values"]
    assert values["fakes"] == _plain(list(sk.FAKES)) and values["infrastructure"] == _plain(list(sk.INFRASTRUCTURE))
    assert values["command_patches"] == _plain(list(suchy_beh.COMMAND_PATCHES))
    assert [item["fake"] for item in sk.FAKES][:6] == ["lab", "host identity and swap", "archive",
                                                      "the stages and the self-test of the campaign", "sleep inhibitor",
                                                      "root"]


# ------------------------------------------------------------------ 5. the headers


S2 = re.compile(r"# commit [0-9a-f]{40}\n# date \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00\n# host .+\n"
                r"# git status --porcelain:.*\n(#   .*\n)*# command .+\n")


def test_every_record_has_the_header_of_check_e_and_every_log_that_of_s2(nulovy, strukturovany):
    """Every JSON file a run writes into --out has the header of check E (scripts/check_claims.sh: commit, date, host,
    guest, command, n and values), its own records with guest null and the reason; check E itself finds nothing there;
    every log begins with the full header of S2 (commit, date, host, git status --porcelain, the command as run)."""
    for run in (nulovy, strukturovany):
        records = sorted(run.out.rglob("*.json"))
        assert {path.name for path in records} >= {"zaznam.json", "generator.json", "kvalifikacia.json", "final.json"}
        for path in records:
            doc = json.loads(path.read_text())
            assert all(key in doc for key in (*HEADER_E, "values")), path
            if path.name != "final.json":
                assert doc["guest"] is None and doc["guest_note"]
        logs = sorted(run.out.glob("*.log"))
        assert {path.name for path in logs} == {"suchy_beh.log", "sprava.log", "kontrola_E.log"}
        for path in logs:
            assert S2.match(path.read_text()), path
        assert run.zaznam["command"].startswith("python -m tcn.suchy_beh beh --generator ")
        found = subprocess.run(["bash", str(ROOT / "scripts/check_claims.sh"), "--json-hlavicky"], cwd=ROOT,
                               env=dict(os.environ, VMIC_RESULTS_DIR=str(run.out)), capture_output=True, text=True)
        assert found.returncode == 0, found.stdout + found.stderr


# ------------------------------------------------------------------ 6. the traffic of a session (package C3b)

# Zápis 1 of G2 as the coordinator's brief of C3b states it: user sessions a second at the envelope's peak of the high
# and the low scenarios, and the preliminary profiles.*.max_concurrent; config/collection-v5.json has them once G2 wrote
# them, and the working copy takes the file's rates (FILE_RATE_ORIGIN). Here on a copy of the small protocol only.
ZAPIS_1 = {"high": 11.7376, "low": 4.4016}
ZAPIS_1_CAP = 2818


def _zapis_1(doc):
    for s in doc["scenarios"].values():
        s["rate"] = ZAPIS_1[s["intensity"]]
    for params in doc["profiles"].values():
        params["max_concurrent"] = ZAPIS_1_CAP


def _postav(svet, tmp_path, scenario, name="s", role=None):
    """(row, the copy loaded, the Session, its real audit) of the planned session of the scenario (and the role, when
    given) with the most events (the first of them) in the campaign plan of the working copy of the small protocol at
    the rates of Zápis 1, built by the fake capture of the run (suchy_kampan.postav_session) and audited by the real
    audit (boundary_sessions.audit), as tcn/suchy_beh.py kvalifikacny_prechod does."""
    from scripts import collection, protocol_v5 as pv
    from scripts.tests import boundary_sessions as bs, kampan_v5 as kv, suchy_kampan as sk
    copy_path = _copy(svet, tmp_path, _zapis_1)
    protokol = collection.protocol(copy_path)
    rows = [dict(s, attempt=1) for s in pv.plan(protokol, "campaign")["sessions"]
            if s["scenario"] == scenario and role in (None, s["role"])]
    row = max(rows, key=lambda s: len(s.get("events", [])))
    p = collection.for_vm(protokol, row["vm"])
    guest = {"kernel": kv.KERNEL, "boot_id": "c3b-" + row["group"], "machine_id": "machine-" + row["vm"],
             "stack_sha256": kv.STACK, "stack_manifest": list(bs.STACK_MANIFEST)}
    qemu = {"pid": kv.FIRST_PID, "start_ticks": 1, "host_boot": kv.HOST_BOOT}
    root = tmp_path / name
    root.mkdir()
    session = sk.postav_session(root, p, copy_path, row, "strukturovany", 0, protokol, session_id="c3b_" + scenario,
                                prvy_riadok_unix=kv.Clock().now, guest=guest, qemu=qemu)
    return row, protokol, session, bs.audit(session, p, output=tmp_path / f"{name}_audit.json")


def _zaznamy(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


@pytest.mark.parametrize("scenario", ["eshop_low", "eshop_high", "corp_low", "corp_high"])
def test_the_offered_load_z4_reads_is_the_planned_load_the_counts_follow(scenario, svet, tmp_path):
    """Package C3b (the lead's answer to Q72 point 2): a session of each scenario of the small protocol at the rates of
    Zápis 1, built by the fake capture and accepted by the real audit, every realism requirement of the log audit and
    its offered load met. The offered load Z4 reads of every row (features/qualification.py offered_load over the
    times of the archive, as tcn/finalne.py load_session reads it) equals the planned offered load the counts of the
    generator follow (suchy_generatory.ponukana_zataz) within the log audit's offered_load_tolerance. The logs are those
    of the generator: its header (generator, the copy's rate from the protocol, the envelope draw_envelope draws from
    the row's traffic seed as ponukana_zataz draws it); a summary interval that holds most of a row's interval offers
    its planned sessions to less than two, every other one holds the generator's planned arrivals (arrival_times of
    the stream traffic_arrivals) at their times; the traffic begins warmup_s before the measurement, the frame in
    which the events' and controls' windows lie where the plan puts them."""
    import random
    import numpy as np
    from features import archive as feature_archive
    from features import qualification as fq
    from features.audit_policy import audit_bounds
    from scripts import host_traffic as ht
    from scripts.tests import suchy_generatory as sg
    row, protokol, session, audit = _postav(svet, tmp_path, scenario)
    tolerance = audit_bounds(protokol)["traffic"]["offered_load_tolerance"]
    times = [float(t) for t in session.result["casy"]]  # The times of the rows, which the archive keeps.
    d = session.directory
    load = fq.offered_load(d / "traffic_intervals.jsonl", times, protokol["interval_s"])
    plan = sg.ponukana_zataz(row, protokol)
    assert type(load) is list and len(load) == len(plan) == protokol["cycles"]
    assert all(abs(got - want) <= tolerance * want for got, want in zip(load, plan)), max(
        abs(got - want) / want for got, want in zip(load, plan))
    assert (audit.code, audit.values["reasons"]) == (0, [])
    assert [float(t) for t in feature_archive.load(audit.archive)["casy"]] == times
    logs = json.loads(audit.path.read_text())["values"]["logs"]
    realism = logs["sections"]["realism"]
    assert all(item["ok"] for item in realism["requirements"]) and realism["offered_load"]["ok"]
    requests, intervals = _zaznamy(d / "traffic_requests.jsonl"), _zaznamy(d / "traffic_intervals.jsonl")
    header, s = requests[0], protokol["scenarios"][scenario]
    warmup, interval_s = protokol["warmup_s"], protokol["interval_s"]
    dur = warmup + protokol["cycles"] * interval_s
    envelope, _ = ht.draw_envelope(protokol["profiles"][s["profile"]]["arrivals"],
                                   random.Random(row["seeds"]["traffic"]), dur, warmup,
                                   protokol["scenario_rule"]["min_peak_to_mean"])
    assert (header["generator"], header["rate"], header["rate_source"]) == (ht.V5_GENERATOR, s["rate"], "protocol")
    assert header["envelope"] == envelope.as_dict() and header["seeds"]["traffic"] == row["seeds"]["traffic"]
    end = json.loads((d / "end.json").read_text())
    origin = header["start_unix"]
    assert end["measure_start_unix"] - origin == warmup and min(times) - end["measure_start_unix"] == pytest.approx(
        sg.FIRST_ROW_S)
    events = json.loads((d / "events.json").read_text())["events"]
    assert events and [e["host_start_unix"] for e in events] == [end["measure_start_unix"] + e["start_s"]
                                                                  for e in row["events"]]
    planned = ht.arrival_times(envelope, s["rate"], random.Random(row["seeds"]["traffic_arrivals"]))
    arrivals = [r["t_mono"] for r in requests if r.get("type") == "arrival"]
    ivs = [r for r in intervals if r.get("type") == "interval"]
    held = set()
    for t in np.asarray(times) - origin:  # The summary interval that holds most of each row's interval.
        overlap = [min(iv["mono_end"], t) - max(iv["mono_start"], t - interval_s) for iv in ivs]
        held.add(int(np.argmax(overlap)))
    assert min(plan) >= 0.5 / tolerance and len(held) == len(times)
    for i, iv in enumerate(ivs):
        mine = [t for t in arrivals if iv["mono_start"] <= t < iv["mono_end"]]
        assert iv["offered_sessions"] == len(mine)
        if i in held:
            assert abs(iv["offered_sessions"] - iv["planned_sessions"]) < 2, iv
        else:
            assert mine == [t for t in planned if iv["mono_start"] <= t < iv["mono_end"]], iv["interval"]


def test_the_controls_of_a_session_lie_where_the_plan_puts_them(svet, tmp_path):
    """The controls of a session of test_controls start where the plan puts them, start_s after the measurement,
    which begins warmup_s after the traffic; the real audit accepts the session, and the offered load Z4 reads follows
    the plan as in a session with events."""
    from features import qualification as fq
    from features.audit_policy import audit_bounds
    from scripts.tests import suchy_generatory as sg
    row, protokol, session, audit = _postav(svet, tmp_path, "corp_low", role="test_controls")
    assert (audit.code, audit.values["reasons"]) == (0, [])
    d = session.directory
    end = json.loads((d / "end.json").read_text())
    planned = [c for c in row["controls"] if c.get("kind") is not None]
    records = json.loads((d / "controls.json").read_text())["controls"]
    assert planned and [r["host_start_unix"] for r in records] == [end["measure_start_unix"] + c["start_s"]
                                                                    for c in planned]
    assert end["measure_start_unix"] - _zaznamy(d / "traffic_requests.jsonl")[0]["start_unix"] == protokol["warmup_s"]
    tolerance = audit_bounds(protokol)["traffic"]["offered_load_tolerance"]
    load = fq.offered_load(d / "traffic_intervals.jsonl", session.result["casy"], protokol["interval_s"])
    assert all(abs(got - want) <= tolerance * want for got, want in zip(load, sg.ponukana_zataz(row, protokol)))


def test_a_session_built_twice_has_the_same_traffic(svet, tmp_path):
    """PREVADZKA_RULE: the run id comes from the session id, the arrivals and the user sessions from the row's traffic
    seeds, so the same session built twice has the same arrivals, requests, phases and summary intervals in its logs,
    the same nginx and journal lines and the same status of the generator."""
    import gzip
    _, _, first, _ = _postav(svet, tmp_path, "corp_high", "prvy")
    _, _, second, _ = _postav(svet, tmp_path, "corp_high", "druhy")

    def records(d):
        out = {}
        for name in ("traffic_requests.jsonl", "traffic_intervals.jsonl"):
            found = _zaznamy(d / name)
            out[name] = [r for r in found if r.get("type") != "header"]
            out[name + " header"] = {k: v for k, v in found[0].items() if k not in ("config", "pid")}
        for name in ("session", "journal"):
            segment = json.loads((d / "guest" / f"{name}_segment.json").read_text())
            out[name] = [gzip.decompress((d / "guest" / entry["file"]).read_bytes()) for entry in segment["files"]]
        out["status"] = {k: v for k, v in json.loads((d / "traffic.json").read_text()).items()
                         if k not in ("requests_log", "intervals_log")}
        return out
    assert records(first.directory) == records(second.directory)
    assert records(first.directory)["traffic_requests.jsonl header"]["run_id"] == hashlib.sha256(
        b"c3b_corp_high").hexdigest()[:12]


# ------------------------------------------------------------------ the command line


def test_the_command_line_of_the_dry_run(svet, capsys):
    """python -m tcn.suchy_beh: --help prints the module's docstring; a call without --praca or --cesta, an unknown
    command, an existing --out and a --praca inside data/results (where the run's ledger may not lie) are refused with
    exit 2, before anything runs or is created."""
    from tcn import suchy_beh
    assert suchy_beh.main(["--help"]) == 0 and "python -m tcn.suchy_beh beh" in capsys.readouterr().out
    out = svet.root / "prikaz" / "out"
    assert suchy_beh.main(["beh", "--generator", "nulovy", "--seed", "0", "--out", str(out)]) == 2
    assert "the following arguments are required: --praca, --cesta" in capsys.readouterr().err
    assert suchy_beh.main(["hranice"]) == 2 and "invalid choice" in capsys.readouterr().err
    out.mkdir(parents=True)
    assert suchy_beh.main(["beh", "--generator", "nulovy", "--seed", "0", "--out", str(out), "--praca",
                           str(svet.root / "prikaz" / "praca"), "--cesta", "plna", "--protocol",
                           str(svet.protocol)]) == 2
    assert f"--out {out} exists" in capsys.readouterr().err
    assert not (svet.root / "prikaz" / "praca").exists()
    inside = RESULTS / "suchy_beh_test_praca"
    assert suchy_beh.main(["beh", "--generator", "nulovy", "--seed", "0", "--out", str(svet.root / "prikaz" / "out2"),
                           "--praca", str(inside), "--cesta", "plna", "--protocol", str(svet.protocol)]) == 2
    assert f"--praca {inside} lies in {RESULTS}" in capsys.readouterr().err
    assert not inside.exists() and not (svet.root / "prikaz" / "out2").exists()
