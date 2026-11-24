"""The nine injected errors of the G1 dry run (protocol v5, package B10, agent G; the lead's skeleton
dokazy/B10/kostra/KOSTRA.md section 4, the design dokazy/B10/navrh/NAVRH_B10.md section G).

The real code refuses each injection of scripts/tests/vlozene_chyby.py with exactly its reason, and admits the same
target without it. The targets come from the harnesses of section 4 of the code map dokazy/B10/navrh/MAPA_KODU.md:
- the clean session of the audit self-test (scripts/tests/audit_cases.py clean_session), under the real protocol file
  config/collection-v5.json;
- the campaign corpus of features/tests/test_dataset_plan.py make_corpus;
- the campaign corpus of tcn/tests/test_finalne.py _corpus, with a ledger of the test's own.
tcn.pecat.KNIHA and ZAZNAM point under the test's directory, and a write of the tracked ledger is refused before it
happens. The expected reasons are literals of this file, never taken from the module under test. The names of
package B10 are imported inside the tests, so this file collects on the code before it and fails there test by test.
Only mechanics on synthetic sessions; nothing here is a measurement (HONESTY P4).
"""
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
TRACKED_LEDGER = ROOT / "data/results/kniha_pecati.json"
# Proposal 10.2 (docs/NAVRH_PROTOKOL_V5.sk.md, the table of G1): the injected errors, in its order.
CHYBY = ("boot v dvoch rolách", "chýbajúci events.json", "o jeden neplatný riadok viac", "zmeškaný slot",
         "cudzia identita VM", "druhé finálne vyhodnotenie", "prehratie zapečatenej roly", "neprebehnutá udalosť",
         "zastaraný hash hosťa")
MIDDLE = 180  # The snapshot the injections change: the middle of the first chain, full_every 360 of the file, // 2.
SEALED = ("test_benign", "test_controls")


def read(path):
    return json.loads(Path(path).read_text())


@pytest.fixture(autouse=True)
def ledgers(tmp_path, monkeypatch):
    """tcn.pecat.KNIHA and ZAZNAM under tmp_path (no test creates that file); a write of the tracked ledger is refused
    before it happens; no final run stays open after a test."""
    from tcn import pecat
    process = tmp_path / "process" / "kniha_pecati.json"
    monkeypatch.setattr(pecat, "KNIHA", process)
    monkeypatch.setattr(pecat, "ZAZNAM", process)
    original = pecat._write

    def write(path, doc, command):
        if Path(path).resolve() == TRACKED_LEDGER.resolve():
            raise AssertionError("a test wrote the tracked ledger " + str(TRACKED_LEDGER))
        return original(path, doc, command)
    monkeypatch.setattr(pecat, "_write", write)
    yield
    run = pecat.otvoreny()
    if run is not None:
        run.close("failed", "left open by a test")
        pytest.fail("a final run stayed open")


@pytest.fixture(scope="module")
def v5():
    from scripts import collection
    return collection.protocol(V5)


def clean(root, p):
    """The clean session of the audit self-test below `root`, under the real protocol file: (directory, result)."""
    from scripts.tests import audit_cases
    session = audit_cases.clean_session(root, p, V5, audit_cases.SESSION)
    return session.directory, session.result


@pytest.fixture(scope="module")
def accepted(tmp_path_factory, v5):
    """The good input of the injections into a session: the clean session, audited by the real audit: (code,
    reasons)."""
    from scripts.tests import audit_cases, boundary_sessions as bs
    session = audit_cases.clean_session(tmp_path_factory.mktemp("clean"), v5, V5, audit_cases.SESSION)
    audit = bs.audit(session, v5)
    return audit.code, audit.values["reasons"]


@pytest.fixture
def plan_corpus(tmp_path):
    """The accepted audits of the campaign plan of features/tests/test_dataset_plan.py (its own small protocol of the
    v5 shape; no session keeps logs): the namespace of make_corpus."""
    from features.tests import test_dataset_plan as dp
    return dp.make_corpus(tmp_path / "plan", "campaign")


@pytest.fixture(scope="module")
def sealed_corpus(tmp_path_factory):
    """The campaign corpus of tcn/tests/test_finalne.py (_corpus in mode campaign): {index, protocol, records}."""
    from tcn.tests import test_finalne
    return test_finalne._corpus(tmp_path_factory.mktemp("finalne") / "corpus", "campaign")


@pytest.fixture
def own_ledger(tmp_path, sealed_corpus):
    """A ledger of the test's own with the seal of sealed_corpus, as the campaign writes it (tcn.pecat zaloz and
    zapis_korpus); its path."""
    from tcn import pecat
    path = tmp_path / "own" / "kniha_pecati.json"
    path.parent.mkdir()
    pecat.zaloz(command="test_vlozene_chyby", ledger=path)
    pecat.zapis_korpus(sealed_corpus["index"], command="the test's campaign", ledger=path)
    return path


def test_vsetky_gives_the_nine_errors_of_proposal_10_2_in_its_order():
    """vsetky(): the nine errors in the order of proposal 10.2, each with the module's function of its id, the target it
    takes, the real step that refuses it and the constant named after it first among its reasons; the module is test
    tooling, outside the measurement hash and no case file of the audit self-test."""
    from scripts import audit_selftest, collection
    from scripts.tests import vlozene_chyby as vc
    chyby = vc.vsetky()
    assert [c.chyba for c in chyby] == list(CHYBY)
    assert [(c.id, c.ciel, c.krok) for c in chyby] == [
        ("boot_v_dvoch_rolach", vc.Korpus, vc.krok_korpus), ("chybajuci_events_json", vc.Korpus, vc.krok_korpus),
        ("neplatny_riadok_navyse", vc.Session, vc.krok_audit), ("zmeskany_slot", vc.Session, vc.krok_audit),
        ("cudzia_identita_vm", vc.Session, vc.krok_audit), ("druhe_finalne_vyhodnotenie", vc.Pecat, vc.krok_finalne),
        ("prehratie_zapecatenej_roly", vc.Pecat, vc.krok_prehratie),
        ("neprebehnuta_udalost", vc.Session, vc.krok_audit), ("zastarany_hash_hosta", vc.Session, vc.krok_audit)]
    assert all(c.vloz is getattr(vc, c.id) and c.dovody[0] == getattr(vc, c.id.upper()) for c in chyby)
    name = "scripts/tests/vlozene_chyby.py"
    assert not collection.is_measurement(name) and name not in audit_selftest.CASE_FILES


def test_a_boot_in_two_roles_is_refused_by_the_corpus_build(plan_corpus):
    """The corpus of the plan, every group in a boot of its own, is indexed; after the injection a dev session ran in
    the boot of a train session, and the build refuses the corpus by name."""
    from scripts.tests import vlozene_chyby as vc
    c = plan_corpus
    target = vc.Korpus(list(c.audits.values()), c.p, c.sha, c.mode)
    assert vc.krok_korpus(target) == []
    assert vc.boot_v_dvoch_rolach(target) == ["boot/group shared between dataset roles"]
    roles = {}
    for audit in target.audits:
        meta = read(Path(read(audit)["values"]["session_dir"]) / "session.json")
        roles.setdefault(meta["guest_before"]["boot_id"], set()).add(meta["role"])
    assert [sorted(held) for held in roles.values() if len(held) > 1] == [["dev", "train"]]
    assert vc.krok_korpus(target) == ["boot/group shared between dataset roles"]


@pytest.mark.parametrize("shape", ["without_logs", "with_logs"])
def test_a_missing_events_json_is_refused_by_the_corpus_build(shape, request, tmp_path, v5):
    """without_logs: the corpus of the plan, whose sessions keep no logs: the build does not repeat their log audit,
    asks for events.json and names the session. with_logs: a corpus of the self-test's clean session with its real
    audit under the real protocol file; the session keeps its logs, the build audits them again first, and that audit
    differs from the record. Each corpus is indexed without the injection."""
    from scripts import collection
    from scripts.tests import vlozene_chyby as vc
    if shape == "without_logs":
        c = request.getfixturevalue("plan_corpus")
        target = vc.Korpus(list(c.audits.values()), c.p, c.sha, c.mode)
        directory = Path(read(target.audits[0])["values"]["session_dir"])
        expected = [f"protocol with events but session has no events.json: {directory}"]
    else:
        directory, result = clean(tmp_path / "clean", v5)
        assert vc.krok_audit(vc.Session(directory, V5, v5, result)) == []
        target = vc.Korpus([directory / "audit.json"], v5, collection.digest(V5), "campaign")
        expected = ["log audit differs from the record"]
    assert vc.krok_korpus(target) == []
    assert vc.chybajuci_events_json(target) == expected
    assert not (directory / "events.json").exists()
    assert vc.krok_korpus(target) == expected


def test_one_invalid_row_more_than_the_rule_tolerates_is_refused_by_the_audit(tmp_path, v5):
    """Under the real protocol file: invalid_rows.max rows in a row, invalid only because the walk of the processes
    did not close, are admitted and listed as tolerated; one row more is refused for the count alone."""
    from scripts.tests import vlozene_chyby as vc
    most = v5["invalid_rows"]["max"]  # 3 in the file, preliminary until G2 (its note).
    assert v5["full_every"] // 2 == MIDDLE and most >= 1
    directory, result = clean(tmp_path / "max", v5)
    boundary = vc.Session(directory, V5, v5, result)
    assert vc.neplatne_riadky(boundary, most) == list(range(MIDDLE, MIDDLE + most))
    assert vc.krok_audit(boundary) == []
    assert read(directory / "audit.json")["values"]["quality"]["tolerated_invalid_seq"] == list(
        range(MIDDLE, MIDDLE + most))
    directory, result = clean(tmp_path / "max_plus_1", v5)
    session = vc.Session(directory, V5, v5, result)
    assert vc.neplatny_riadok_navyse(session) == ["incomplete model inputs under behavioral-inputs-v1"]
    assert [seq for seq, valid in zip(result["seq"], result["valid"]) if not valid] == list(
        range(MIDDLE, MIDDLE + most + 1))
    assert vc.krok_audit(session) == ["incomplete model inputs under behavioral-inputs-v1"]


def _sidecar(directory):
    return read(Path(directory) / "raw" / f"frame{MIDDLE}.json")


def _stale(directory):
    """The guest's manifest differs from the clean one in its first line only, the hash of the same file, before and
    after the capture alike."""
    from scripts.tests import boundary_sessions as bs
    before = read(Path(directory) / "session.json")["guest_before"]["stack_manifest"]
    after = read(Path(directory) / "end.json")["guest_after"]["stack_manifest"]
    changed = [i for i, (line, kept) in enumerate(zip(before, bs.STACK_MANIFEST)) if line != kept]
    return before == after and len(before) == len(bs.STACK_MANIFEST) and changed == [0] and (
        before[0][64:] == bs.STACK_MANIFEST[0][64:])


# id: (the exact reason, what the injection left in the session).
AUDIT = {
    "zmeskany_slot": (f"read errors/fill/missed slots: frame{MIDDLE}.vmicd",
                      lambda d: _sidecar(d)["sched"]["skipped_before"] == 1),
    "cudzia_identita_vm": ("sidecar VM identity differs from session",
                           lambda d: [_sidecar(d)["vm"][key] for key in ("domain", "vmid")] == ["hyptcn-lab-b", 4243]),
    "neprebehnuta_udalost": ("logs: event_not_executed:restart_sluzby",
                             lambda d: [e["executed"] for e in read(Path(d) / "events.json")["events"]] == [False]),
    "zastarany_hash_hosta": ("deployed guest files differ from lab/", _stale),
}


@pytest.mark.parametrize("ident", list(AUDIT))
def test_the_audit_refuses_the_injection_with_exactly_its_reason(ident, accepted, tmp_path, v5):
    """A missed slot, a foreign VM identity, an event that did not run and a stale guest hash, each injected into a
    clean session of the self-test under the real protocol file (VM a of the file, QEMU pid 4242), are refused by the
    real audit with exactly their reason; the clean session is accepted."""
    from scripts.tests import vlozene_chyby as vc
    reason, injected = AUDIT[ident]
    assert accepted == (0, [])
    directory, result = clean(tmp_path / ident, v5)
    session = vc.Session(directory, V5, v5, result)
    assert getattr(vc, ident)(session) == [reason]
    assert injected(directory)
    assert vc.krok_audit(session) == [reason]


@pytest.mark.parametrize("first", ["by_the_injection", "by_the_dry_run"])
def test_a_second_final_evaluation_is_refused_by_the_final_command(first, sealed_corpus, own_ledger, tmp_path):
    """The campaign's seal on the test's own ledger is ready (stage suchy), and a first final run consumes it: the
    injection's own, or the dry run's (its sealed final evaluation, before the injection). The final command run again
    is refused by name at its step 0, before anything is computed: it writes nothing and the ledger keeps the one
    run."""
    from tcn import pecat
    from scripts.tests import vlozene_chyby as vc
    work = tmp_path / "work"
    work.mkdir()
    target = vc.Pecat(sealed_corpus["index"], own_ledger, work)
    state = pecat.stav(target.index, ledger=own_ledger)
    assert (state["ready"], state["consumed"], state["runs"], state["stage"]) == (True, False, [], "suchy")
    out = work / "prvy_beh.json"
    if first == "by_the_dry_run":
        out = tmp_path / "final.json"
        with pecat.spotrebuj(target.index, out=out, command="the dry run's final evaluation", ledger=own_ledger):
            pass
    expected = vc.druhe_finalne_vyhodnotenie(target)
    run, = read(own_ledger)["values"]["runs"]
    hashes = sorted(r["features_sha256"] for r in sealed_corpus["records"] if r["role"] in SEALED)
    assert (run["number"], run["identity"], run["closed"]["outcome"], run["out"]) == (
        1, hashlib.sha256("".join(h + "\n" for h in hashes).encode()).hexdigest(), "completed", str(out.resolve()))
    reason = (f"{target.index.resolve()}: the seal of the corpus cannot be consumed on the ledger "
              f"{own_ledger.resolve()} (its seal was consumed by the final run 1 of seal {run['identity']} opened "
              f"{run['opened']['date']} (out {run['out']}): a second final run is refused); refused before anything "
              "is computed (tcn.pecat stav, RUN_RULE)")
    assert expected == [reason]
    before = own_ledger.read_bytes()
    assert vc.krok_finalne(target) == [reason]
    assert own_ledger.read_bytes() == before and list(work.iterdir()) == []


@pytest.mark.parametrize("when", ["before_the_final_run", "after_the_final_run"])
def test_the_replay_of_a_sealed_role_is_refused(when, sealed_corpus, own_ledger, tmp_path):
    """The archive of a train session of the corpus is no sealed archive, and the seal lets its replay through; the
    replay of the first session of a sealed role is refused by name, before or after the final run consumed the seal,
    before a model is read or anything is written."""
    from tcn import pecat
    from scripts.tests import vlozene_chyby as vc
    work = tmp_path / "work"
    work.mkdir()
    target = vc.Pecat(sealed_corpus["index"], own_ledger, work)
    records = read(sealed_corpus["index"])["sessions"]
    train = next(r for r in records if r["role"] == "train")
    assert pecat.kontrola(train["features"], purpose="tcn.porovnanie replay", ledger=own_ledger)["allowed"] == (
        "not_sealed")
    consumed = ""
    if when == "after_the_final_run":
        with pecat.spotrebuj(target.index, out=tmp_path / "final.json", command="the final run", ledger=own_ledger):
            pass
        run, = read(own_ledger)["values"]["runs"]
        consumed = f"; its seal was consumed by the final run opened {run['opened']['date']} (out {run['out']})"
    sealed = next(r for r in records if r["role"] in SEALED)
    reason = (f"tcn.porovnanie replay: refused, the archive {sealed['features']} is sealed (sha256 "
              f"{sealed['features_sha256']}; session {sealed['id']} of role {sealed['role']}, plan finalne-test, "
              f"ledger {own_ledger.resolve()}): a sealed archive of a campaign is replayed or scored only by the final "
              f"command (python -m tcn.finalne) in the run that consumes its seal (tcn/pecat.py GUARD_RULE){consumed}")
    assert vc.prehratie_zapecatenej_roly(target) == [reason]
    assert vc.krok_prehratie(target) == [reason]
    assert list(work.iterdir()) == []
