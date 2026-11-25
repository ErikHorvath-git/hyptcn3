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
Package C4b (the lead's answer to Q73 point 2, 2026-11-25T21:20Z: the shortened path neither writes nor audits the
traffic logs) adds, as the coordinator's brief of C4b lists it:
7. no traffic log in a session of the shortened path, and the offered load of its rows equals that of the full path
   for every row of a session of each scenario; no audit reads them in a whole shortened run, whose --chyby still
   refuses all nine errors;
8. the full path's check that the offered load of its logs is that of the one function (suchy_kampan.ZATAZ_RULE)
   fires on a log whose offered user sessions differ from the function's, and in a capture;
9. the match of the two paths on the small protocol for both generators: the same alarms of Z4 by both its variants
   and the same I and D, read by the command zhoda (tcn/suchy_beh.py ZHODA_RULE), which names a difference.
The real plan runs in C4 only. The small protocol takes the numbers its corpus can carry (as
tcn/tests/test_finalne.py _protocol): they are the test's, no judgment of the protocol. Its record of G0 is the
test's, in a directory of the test (--vysledky); no test writes data/results, the ledger of record or docs/. Only
mechanics on synthetic sessions: no number here is a result of detection (HONESTY P4).
"""
import contextlib
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
    order share, read outside every window (scripts/traffic_log.py realism), refuses the session. Package B13: D_max of
    the order share (audit.traffic.order_share_session_max_s), an upper bound of a user session's duration, is divided
    by THINK_SCALE as well, so that the user sessions it leaves out before a window are as many as on the plan. Its
    later-stage values are those protocol_doc gives on config/collection-v5.json as the G0 record holds it
    (scripts/tests/protokol_g0.py; rates and grids null, every column neural, no replacement), while G2 writes its
    values into the file from its Zápis 1 on: the working copy of the command fills them. Returns the path of the
    file."""
    from features.tests import test_dataset_plan as dp
    from scripts import collection
    from scripts.tests import boundary_sessions as bs, protokol_g0
    profile = root / "profile"
    profile.mkdir()
    (profile / "symbols.txt").write_text("synthetic profile\n")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(bs, "V5", protokol_g0.g0_file())
        bs._v5_file.cache_clear()
        try:
            doc = dp.protocol_doc(profile)
        finally:
            bs._v5_file.cache_clear()  # The next reader takes the file itself again.
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
    doc["audit"]["traffic"]["order_share_session_max_s"] /= THINK_SCALE
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
    # Package C4b: with --chyby, as a structured run of C4 by the shortened path (tabulka reads --chyby of a structured
    # run, tcn/suchy_beh.py READINGS fault_injections).
    return beh(svet, "strukturovany-skratena", "strukturovany", "skratena", "--chyby")


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
    run (all of them in the null run). Package C4b (the lead's answer to Q73 point 2: 'zhodné alarmy Z4 a I/D'): the
    shortened path wrote and audited no traffic logs, and still Z4 by both its variants has the same matched thresholds
    and the same alarms (exceed, up, edge of every row) in the attachments series and copies, so it read the same
    offered load; the command zhoda finds the two paths equal (exit 0)."""
    import numpy as np
    from tcn import finalne, metody, suchy_beh
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
    labels = [f"{metody.Z4.name}:{variant}" for variant in metody.Z4_VARIANTS]
    for attachment in ("series", "copies"):
        a, b = suchy_beh._priloha(full, attachment), suchy_beh._priloha(short, attachment)
        za, zb = ([i for i, name in enumerate(found["label_name"]) if str(name) == "Z4"] for found in (a, b))
        assert [str(a["label"][i]) for i in za] == [str(b["label"][i]) for i in zb] == labels
        assert np.array_equal(a["row_seq"], b["row_seq"]) and np.array_equal(a["row_time"], b["row_time"])
        for i, j in zip(za, zb):
            assert a["threshold"][i] == b["threshold"][j], (attachment, a["label"][i])
            for key in ("exceed", "up", "edge"):
                assert np.array_equal(a[key][i], b[key][j]), (attachment, a["label"][i], key)
    code, summary = suchy_beh.zhoda(full_run.out, short_run.out)
    assert (code, summary["equal"], summary["first_difference"], summary["run"]) == (0, True, None, generator + "_0")
    assert summary["compared"][-3:] == ["k1 (I)", "k2a (D)", "k2b (D)"] and len(summary["compared"]) == 9


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
    for scenario in doc["scenarios"].values():  # The file before G2 wrote its rates (protocol_doc takes the file's).
        scenario["rate"] = None
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
        sk.Kampan(tmp_path / "kampan", mp, protokol=p, rezim="nulovy", seed=0, kniha=tmp_path / "kniha" / "k.json",
                  prevadzka=True)
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


def _postav(svet, tmp_path, scenario, name="s", role=None, *, prevadzka=True, ponuky=None):
    """(row, the copy loaded, the Session, its real audit) of the planned session of the scenario (and the role, when
    given) with the most events (the first of them) in the campaign plan of the working copy of the small protocol at
    the rates of Zápis 1, built by the fake capture of the run (suchy_kampan.postav_session) and audited by the real
    audit (boundary_sessions.audit), as tcn/suchy_beh.py kvalifikacny_prechod does: by the full path, or with prevadzka
    false by the shortened one (suchy_kampan.SKRATENA_RULE: the audit without its log audit); ponuky receives the
    session's Ponuka (suchy_kampan.ZATAZ_RULE)."""
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
                                prvy_riadok_unix=kv.Clock().now, guest=guest, qemu=qemu, prevadzka=prevadzka,
                                ponuky=ponuky)
    with contextlib.nullcontext() if prevadzka else sk.bez_auditu_logov():
        audit = bs.audit(session, p, output=tmp_path / f"{name}_audit.json")
    return row, protokol, session, audit


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


# ------------------------------------------------------------------ 7. to 9. the shortened path's traffic (package C4b)


def _riadky_segmentu(d, name, suffix):
    """The lines of the guest log segment guest/<name>-<suffix> of a session directory."""
    import gzip
    segment = json.loads((d / "guest" / f"{name}_segment.json").read_text())
    entry = next(entry for entry in segment["files"] if entry["name"].endswith("-" + suffix))
    return gzip.decompress((d / "guest" / entry["file"]).read_bytes()).decode().splitlines()


@pytest.mark.parametrize("scenario", ["eshop_low", "eshop_high", "corp_low", "corp_high"])
def test_a_session_of_the_shortened_path_holds_no_traffic_and_the_load_of_the_full_one(scenario, svet, tmp_path):
    """Package C4b (the lead's answer to Q73 point 2; suchy_kampan.SKRATENA_RULE and ZATAZ_RULE): the same planned
    session of each scenario of the small protocol at the rates of Zápis 1, built by the full path and by the
    shortened one. The shortened session holds no traffic log, no status or log of the generator and no seal of the
    logs (logs_manifest.json, and in end.json neither traffic_rc nor the manifest's sha256), its guest segments no line
    of a request, while the full one holds all of them; its session.json keeps the same traffic block, its events, rows
    and snapshots are those of the full session. The real audit without its log audit accepts it, its record of the
    log audit names the rule and reads nothing. The offered load of every row from the one function equals that
    features/qualification.py offered_load reads from the full session's log, exactly."""
    from features import qualification as fq
    from scripts import collection_logs
    from scripts.tests import suchy_kampan as sk
    ponuky = {}
    _, protokol, full, full_audit = _postav(svet, tmp_path, scenario, "plna", ponuky=ponuky)
    _, _, short, short_audit = _postav(svet, tmp_path, scenario, "skratena", prevadzka=False, ponuky=ponuky)
    d, e = full.directory, short.directory
    assert all((d / name).is_file() for name in (*sk.TRAFFIC_FILES, "logs_manifest.json"))
    assert not any((e / name).exists() for name in (*sk.TRAFFIC_FILES, "logs_manifest.json"))
    end_full, end_short = (json.loads((x / "end.json").read_text()) for x in (d, e))
    assert {"traffic_rc", "logs_manifest_sha256"} <= set(end_full)
    assert {key: value for key, value in end_full.items() if key not in ("traffic_rc", "logs_manifest_sha256")} == \
        end_short
    meta_full, meta_short = (json.loads((x / "session.json").read_text()) for x in (d, e))
    assert meta_short == meta_full and meta_short["traffic"]["scenario"] == scenario
    assert _riadky_segmentu(d, "session", "nginx-access.jsonl") and not _riadky_segmentu(e, "session",
                                                                                          "nginx-access.jsonl")
    assert not [line for line in _riadky_segmentu(e, "journal", "journal.txt") if " rid=" in line]
    assert (e / "events.json").read_bytes() == (d / "events.json").read_bytes()
    assert short.result == full.result
    assert sorted((e / "raw").iterdir()) and [path.read_bytes() for path in sorted((e / "raw").glob("*.json"))] == [
        path.read_bytes() for path in sorted((d / "raw").glob("*.json"))]
    assert (full_audit.code, full_audit.values["reasons"]) == (0, [])
    assert (short_audit.code, short_audit.values["reasons"]) == (0, [])
    logs = short_audit.values["logs"]
    assert (logs["schema"], logs["accepted"], logs["problems"], logs["not_run"]) == (
        collection_logs.SCHEMA, True, [], sk.SKRATENA_RULE)
    assert logs["sections"]["metadata"]["session_sha256"] == short_audit.values["session_sha256"]
    assert "not_run" not in full_audit.values["logs"]
    times = [float(t) for t in short.result["casy"]]
    load = fq.offered_load(d / "traffic_intervals.jsonl", times, protokol["interval_s"])
    assert type(load) is list and len(load) == len(times) == protokol["cycles"]
    assert ponuky[str(e.resolve())].zataz(times, protokol["interval_s"]) == load
    assert ponuky[str(d.resolve())].zataz(times, protokol["interval_s"]) == load


def test_the_full_path_refuses_a_log_whose_offered_sessions_differ_from_the_function(svet, tmp_path, monkeypatch):
    """ZATAZ_RULE: the full path checks by name that the offered load read from its traffic_intervals.jsonl
    (features/qualification.py offered_load) equals that of the one function at the time of every row
    (suchy_kampan.over_zataz_logov). The check holds on the session's log; one user session more offered in the summary
    interval that holds most of a row's interval makes it name that row; and a capture whose function gives another
    offered load than its log is refused by name."""
    from scripts.tests import suchy_kampan as sk
    ponuky = {}
    _, protokol, session, _ = _postav(svet, tmp_path, "corp_high", "plna", ponuky=ponuky)
    d, interval_s = session.directory, protokol["interval_s"]
    ponuka = ponuky[str(d.resolve())]
    times = [float(t) for t in session.result["casy"]]
    assert sk.over_zataz_logov(d, ponuka, times, interval_s) == ponuka.zataz(times, interval_s)
    records = _zaznamy(d / "traffic_intervals.jsonl")
    intervals = [i for i, r in enumerate(records) if r.get("type") == "interval"]
    row = 10
    t = times[row] - ponuka.origin
    held = max(intervals, key=lambda i: min(records[i]["mono_end"], t) - max(records[i]["mono_start"], t - interval_s))
    records[held]["offered_sessions"] += 1
    (d / "traffic_intervals.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    first = next(i for i, ti in enumerate(times) if ti - ponuka.origin > records[held]["mono_start"])
    with pytest.raises(ValueError, match=r"differs from suchy_kampan\.ponuka_relacii at the row of time "
                                         + re.escape(repr(times[first])) + r" .*ZATAZ_RULE"):
        sk.over_zataz_logov(d, ponuka, times, interval_s)
    assert first <= row
    real = sk.Ponuka.zataz
    monkeypatch.setattr(sk.Ponuka, "zataz", lambda self, at, step: [x + 1 for x in real(self, at, step)])
    with pytest.raises(ValueError, match=r"differs from suchy_kampan\.ponuka_relacii at the row of time .*ZATAZ_RULE"):
        _postav(svet, tmp_path, "corp_high", "znova")


# The files of the traffic generator in a session directory (scripts/collection.py capture_session: the two logs and
# the status of traffic_command, the child's log, traffic_before.json of check_warmup), named here by the test.
TRAFFIC_LOGS = ("traffic_requests.jsonl", "traffic_intervals.jsonl", "traffic.json", "traffic_before.json",
                "traffic.log")


def _korpus(run):
    """The corpus index of the campaign of a run of beh (it stays in --praca, CLEANUP_RULE)."""
    return json.loads(Path(run.zaznam["values"]["files"]["index"]["path"]).read_text())


@pytest.mark.parametrize("name", ["nulovy_skratena", "strukturovany_skratena"])
def test_the_shortened_run_writes_and_audits_no_traffic_log(name, request, nulovy):
    """Package C4b (the lead's answer to Q73 point 2: the shortened path neither writes nor audits the traffic logs):
    no session of a whole shortened run, in the archive of its rehearsal and campaign, holds a traffic log, a status or
    log of the generator or a seal of the logs; the log audit of no session ran (its record names
    suchy_kampan.SKRATENA_RULE), the corpus build repeated none (features/quality.py NOT_REPEATED no_logs, where the
    full run repeated every one) and zaznam.json names the fakes of the shortened path. With --chyby (the structured
    run) all nine errors are refused by their reasons: the event that did not run by the log audit of the Session
    target, which is built with its traffic (FAULTS_RULE)."""
    from features import quality
    from scripts.tests import suchy_kampan as sk
    run = request.getfixturevalue(name)
    assert run.code == 0, run.zaznam["values"].get("failure") or run.zaznam["values"]["checks"]
    archived = sorted(path.parent for path in (run.praca / "kampan" / "archive").rglob("session.json"))
    assert len(archived) >= len(_korpus(run)["sessions"]) > 0
    for d in archived:
        assert [file for file in (*TRAFFIC_LOGS, "logs_manifest.json") if (d / file).exists()] == [], d
    assert sk.TRAFFIC_FILES == TRAFFIC_LOGS
    audits = [path for d in archived for path in d.glob("*audit*.json")]
    assert {path.parent for path in audits} == set(archived)  # The campaign's audit records, archived with them.
    for path in audits:
        assert json.loads(path.read_text())["values"]["logs"]["not_run"] == sk.SKRATENA_RULE, path
    assert {r["log_audit"] for r in _korpus(run)["sessions"]} == {quality.NOT_REPEATED["no_logs"]}
    assert {r["log_audit"] for r in _korpus(nulovy)["sessions"]} == {quality.REPEATED}
    values = run.zaznam["values"]
    assert values["fakes"] == _plain(list(sk.fakes(False))) and values["rules"]["short_traffic"] == sk.SKRATENA_RULE
    if values["chyby"]:
        faults = json.loads((run.out / "vlozene_chyby.json").read_text())["values"]
        assert (faults["refused_as_expected"], faults["of"], faults["clean_admitted"]) == (9, 9, True)
        event = next(row for row in faults["errors"] if row["id"] == "neprebehnuta_udalost")
        assert event["got"] == event["expected"] and event["got"][0].startswith("logs: event_not_executed:")


def test_the_shortened_path_names_its_fakes_and_patches_nothing_else(nulovy, tmp_path):
    """FAKES_SKRATENA: the harness of the shortened path (suchy_kampan.Kampan with prevadzka false) patches exactly the
    attributes of FAKES, FAKES_SKRATENA and INFRASTRUCTURE, and the session audit without its log audit is restored
    after the qualification pass's block (bez_auditu_logov)."""
    import scripts.collection
    import scripts.campaign
    from scripts import collection
    from scripts.tests import suchy_kampan as sk
    modules = {"scripts.campaign": scripts.campaign, "scripts.collection": scripts.collection}
    before = {name: dict(vars(module)) for name, module in modules.items()}
    p = collection.protocol(Path(nulovy.zaznam["values"]["files"]["copy"]["path"]))
    with pytest.MonkeyPatch.context() as mp:
        (tmp_path / "kniha").mkdir()
        h = sk.Kampan(tmp_path / "kampan", mp, protokol=p, rezim="nulovy", seed=0, kniha=tmp_path / "kniha" / "k.json",
                      prevadzka=False)
        changed = {f"{name}.{key}" for name, module in modules.items() for key, value in vars(module).items()
                   if before[name].get(key, before) is not value}
        assert collection.audit_logs is sk.audit_logov_skratenej and h.ponuky == {}
    named = {patch for item in (*sk.FAKES, *sk.FAKES_SKRATENA, *sk.INFRASTRUCTURE) for patch in item["patches"]}
    assert changed == {patch for patch in named if any(patch.startswith(module + ".") for module in modules)}
    assert collection.audit_logs is before["scripts.collection"]["audit_logs"]
    with sk.bez_auditu_logov():
        assert collection.audit_logs is sk.audit_logov_skratenej
    assert collection.audit_logs is before["scripts.collection"]["audit_logs"]
    with pytest.raises(ValueError, match="no default"):
        sk.Kampan(tmp_path / "bez", None, protokol=p, rezim="nulovy", seed=0, kniha=tmp_path / "k.json", prevadzka=None)


def test_the_final_evaluation_of_the_shortened_path_reads_the_load_of_the_function(tmp_path):
    """ZATAZ_FINALNE_RULE: inside zataz_skratenej_cesty, tcn/finalne.py check_inputs runs as it is with the
    traffic_intervals.jsonl of exactly the sessions of the mapping counted as present, so it accepts them and still
    refuses another session without the log by its own reason (LOAD_RULE), and features/qualification.py offered_load
    gives Ponuka.zataz of those sessions and its own answer for any other; both are restored after the block."""
    from features import qualification as fq
    from scripts.tests import suchy_kampan as sk
    from tcn import finalne, suchy_beh
    records, ponuky = [], {}
    for role in ("train", "dev", "calibration", "test_benign", "test_controls"):
        d = tmp_path / role
        d.mkdir()
        (d / "session.json").write_text("{}")
        (d / "events.json").write_text('{"events": []}')
        record = {"id": "s-" + role, "role": role, "session": str(d / "session.json"), "events": str(d / "events.json"),
                  "events_sha256": _digest(d / "events.json")}
        if role == "test_controls":
            (d / "controls.json").write_text('{"controls": []}')
            record.update(controls=str(d / "controls.json"), controls_sha256=_digest(d / "controls.json"))
        records.append(record)
        ponuky[str(d.resolve())] = sk.Ponuka(1000.0, [0.0, 5.0, 10.0, 15.0], [2, 4, 6], [], {})
    real_check, real_load = finalne.check_inputs, fq.offered_load
    with pytest.raises(ValueError, match="session s-train has no traffic_intervals.jsonl"):
        finalne.check_inputs(records)
    log = tmp_path / "train" / "traffic_intervals.jsonl"
    with suchy_beh.zataz_skratenej_cesty(ponuky):
        assert finalne.check_inputs(records) is None
        assert fq.offered_load(log, [1010.0, 1015.0], 5.0) == [4.0, 6.0] == ponuky[str(log.parent.resolve())].zataz(
            [1010.0, 1015.0], 5.0)
        assert fq.offered_load(tmp_path / "x" / "traffic_intervals.jsonl", [1010.0], 5.0) == \
            "no traffic_intervals.jsonl in the session directory"
        del ponuky[str((tmp_path / "dev").resolve())]
    with suchy_beh.zataz_skratenej_cesty(ponuky):
        with pytest.raises(ValueError, match="session s-dev has no traffic_intervals.jsonl: " + re.escape(
                finalne.LOAD_RULE)):
            finalne.check_inputs(records)
    assert (finalne.check_inputs, fq.offered_load) == (real_check, real_load)
    with pytest.raises(ValueError, match="no mapping"):
        suchy_beh.zataz_skratenej_cesty(None)


def test_zhoda_names_the_first_difference_and_refuses_what_is_no_pair(nulovy, nulovy_skratena, strukturovany_skratena,
                                                                     tmp_path, capsys):
    """ZHODA_RULE: python -m tcn.suchy_beh zhoda --plna --skratena exits 0 on the two paths of the null run at seed 0,
    printing its summary; a value per boot of I changed in the shortened run's record, or an alarm of Z4 that begins
    at another row of its attachment series, is the first difference, named by the claim, the method and the boot or by
    the label, the row, its seq and session; the paths swapped, or two runs of two generators, are refused with exit
    2."""
    import copy
    import numpy as np
    from tcn import suchy_beh
    assert suchy_beh.main(["zhoda", "--plna", str(nulovy.out), "--skratena", str(nulovy_skratena.out)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert (printed["schema"], printed["equal"], printed["run"]) == (suchy_beh.SCHEMA_ZHODA, True, "nulovy_0")
    full, short = suchy_beh.nacitaj_beh(nulovy.out), suchy_beh.nacitaj_beh(nulovy_skratena.out)
    changed = copy.deepcopy(short)
    method = changed["record"]["values"]["claims"]["k1"]["compare"][0]
    values = changed["record"]["values"]["claims"]["k1"]["methods"][method]["values"]
    boot = sorted(values)[-1]
    before = values[boot]
    values[boot] += 1e-9
    found = suchy_beh.porovnaj_cesty(full, changed)
    assert found["equal"] is False and found["first_difference"] == {
        "item": "k1 (I)", "detail": f"method {method}, boot {boot}: the value {before!r} and {values[boot]!r}"}
    changed = copy.deepcopy(short)
    item = changed["record"]["values"]["attachments"]["series"]
    data = suchy_beh._priloha(changed["record"]["values"], "series")
    z4 = [i for i, name in enumerate(data["label_name"]) if str(name) == "Z4"][1]
    data["edge"][z4, 7] = not data["edge"][z4, 7]
    item["path"] = str(tmp_path / "series.npz")
    np.savez(item["path"], **data)
    item["sha256"] = _digest(item["path"])
    found = suchy_beh.porovnaj_cesty(full, changed)
    assert found["first_difference"]["item"] == "alarms of Z4, attachment series"
    assert found["first_difference"]["detail"].startswith(f"{data['label'][z4]}: edge differs at 1 of ")
    assert f"row 7 (seq {int(data['row_seq'][7])} of " in found["first_difference"]["detail"]
    assert suchy_beh.main(["zhoda", "--plna", str(nulovy_skratena.out), "--skratena", str(nulovy.out)]) == 2
    assert "is a run of the path 'skratena', not 'plna'" in capsys.readouterr().err
    assert suchy_beh.main(["zhoda", "--plna", str(nulovy.out), "--skratena", str(strukturovany_skratena.out)]) == 2
    assert "zhoda compares the two paths of one generator and seed" in capsys.readouterr().err


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
    # hranice is a command since C4a; an unknown one:
    assert suchy_beh.main(["nic"]) == 2 and "invalid choice" in capsys.readouterr().err
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
