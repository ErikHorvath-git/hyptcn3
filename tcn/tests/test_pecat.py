"""The seal of the test roles (protocol v5, package B7c, agent S): the ledger, the guards and the one final run.

The lead's skeleton dokazy/B7/kostra/KOSTRA.md section 7 with the B7c row of section 8 and the design
dokazy/B7/navrh/NAVRH_B7c.md sections 1.1 and 2. The tests of the B7c row: replaying a sealed archive is refused (at
every guarded entry point), a second final run is refused, a copy of the corpus under another path is refused (the
same seal), an unscored stretch is nevyhodnotené in the output, a rehearsal is marked. Beside them the ledger (the
identity, a write and its provenance, a missing or malformed ledger), the final run that opens its archives once, the
window sets of the wrapper and the outcomes of the controls (finding S4 of the verification of B8). The event index
from the plan is tested in scripts/tests/test_event_index.py, the controls of the index in
features/tests/test_dataset_plan.py, the copies of the interventions in tcn/tests/test_zasahy.py.

Every corpus here is synthetic: feature archives of scripts/tests/boundary_sessions.py extraction_result in a corpus
index under the real protocol file. Each test writes its own ledger under tmp_path and tcn.pecat.KNIHA points at it,
so the guards read it as they read the tracked ledger. A run on it has stage suchy (STAGE_RULE, design B7c 5.1); a
test of stage final or generalka makes it the ledger of record as well (the fixture of_record: tcn.pecat.ZAZNAM), and
one of stage final takes the ledger at HEAD to hold the seal (the fixture in_git), whose refusal has its own test.
The expected messages are literals of this file. Names of
package B7c are imported inside the tests, so this file collects on the code before it. Only mechanics; no number
here is a detection result (HONESTY P4).
"""
import hashlib
import json
from pathlib import Path
import shutil

import numpy as np
import pytest

from scripts.tests import boundary_sessions as bs

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
ROWS, FULL_EVERY, T0, INTERVAL, WINDOW, GAP = 24, 12, 10000., 5, 3, 7.5
SEALED = (("tb-1", "test_benign"), ("tb-2", "test_benign"), ("tc-1", "test_controls"))
UNSEALED = ("tr-1", "train")
INVALID = 7  # The invalid row of every archive (an unclosed traversal, a row the protocol tolerates).
GUARD = ("a sealed archive of a campaign is replayed or scored only by the final command (python -m tcn.finalne) in "
         "the run that consumes its seal (tcn/pecat.py GUARD_RULE)")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protocol():
    return json.loads(V5.read_text())


def plan_name(mode):
    doc = protocol()
    return doc["name"] + (doc["rehearsal"]["name_suffix"] if mode == "rehearsal" else "")


def write_archive(path, name, seed):
    """A feature archive of ROWS rows, a full snapshot every FULL_EVERY, row INVALID invalid; (path, sha256)."""
    result, _ = bs.extraction_result(name, ROWS, FULL_EVERY, t0=T0, interval_s=INTERVAL, seed=seed,
                                     quality={INVALID: bs.unclosed_row()})
    return bs.save_archive(path, result)


def corpus(root, mode="campaign", sessions=(*SEALED, UNSEALED)):
    """A corpus index (the fields features/dataset.py build writes that the seal reads) of `sessions`, each with an
    archive of its own under `root`; (index path, {id: record})."""
    records = {}
    for seed, (ident, role) in enumerate(sessions):
        path, digest = write_archive(Path(root) / ident / "features.npz", ident, seed)
        records[ident] = {"id": ident, "role": role, "group": f"g-{ident}", "vm": "a", "scenario": "eshop_low",
                          "features": str(path), "features_sha256": digest}
    return write_index(Path(root) / "corpus.json", list(records.values()), mode), records


def write_index(path, records, mode):
    path.write_text(json.dumps({"schema": "hyptcn3/corpus-index/1", "protocol_config": protocol(),
                                "protocol_sha256": sha(V5), "plan_mode": mode, "sessions": records}))
    return path


def sealed_message(purpose, what, record, mode, ledger, consumed=""):
    return (f"{purpose}: refused, {what} is sealed (sha256 {record['features_sha256']}; session {record['id']} of role "
            f"{record['role']}, plan {plan_name(mode)}, ledger {ledger}): {GUARD}{consumed}")


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    """The ledger of the test, tcn.pecat.KNIHA for the guards; no final run stays open after a test."""
    from tcn import pecat
    path = tmp_path / "ledger" / "kniha_pecati.json"
    path.parent.mkdir()
    monkeypatch.setattr(pecat, "KNIHA", path)
    pecat.zaloz(command="test_pecat", ledger=path)
    yield path
    run = pecat.otvoreny()
    if run is not None:
        run.close("failed", "left open by a test")
        pytest.fail("a final run stayed open")


@pytest.fixture
def of_record(ledger, monkeypatch):
    """The test's ledger as the ledger of record (tcn.pecat.ZAZNAM, design B7c 5.1): a run on it has the stage of its
    plan mode, final or generalka."""
    from tcn import pecat
    monkeypatch.setattr(pecat, "ZAZNAM", ledger)
    return ledger


@pytest.fixture
def in_git(monkeypatch):
    """The ledger at HEAD holds every seal a run consumes (tcn.pecat._in_git true): what stage final requires
    (SEAL_IN_GIT_RULE, design B7c 5.2); its refusal is test_stage_final_needs_the_ledger_at_head_to_hold_the_seal."""
    from tcn import pecat
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: True)


@pytest.fixture
def sealed(tmp_path, ledger):
    """A campaign corpus whose sealed sessions the ledger holds (as the campaign writes them): (index, records)."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus")
    pecat.zapis_korpus(index, command="campaign", ledger=ledger)
    return index, records


class Bundle:
    """A score oracle with the interface of safeguard.bundle.Bundle (as safeguard/tests/test_runtime.py FakeBundle):
    every window of WINDOW rows scores 2, above the threshold 1; the contract is that of the archive's first frame."""
    threshold, k, n, anchored = 1.0, 1, 1, False
    min_bin_pages = None  # Package B11 (question Q10): the bins run_directory extracts from, every bin.

    def __init__(self, archive, interval_s=INTERVAL):
        from safeguard.features import feature_contract, frames_from_archive
        with np.load(archive, allow_pickle=False) as data:
            first = frames_from_archive(data, "contract")[0]
        self.contract = feature_contract(first, WINDOW, GAP)
        self.manifest = {"diagnostic": False, "calibration": {"diagnostic": True},
                         "provenance": {"protocol": {"interval_s": interval_s}}}

    @property
    def rule_channel(self):
        return {"columns": [], "quantity": {}, "ranges": {}, "k": self.k, "n": self.n}

    def score(self, window):
        return {"score": 2.0}


def window_sets(records, roles):
    """Window sets of the wrapper (tcn.metody.Okna.from_sessions) of each (session, role) of `roles` from the
    archives of `records`, under one normalizer fitted on the first (all columns neural: the diagnostic rule of the v5
    file, whose analysis.columns is null until G3a)."""
    from safeguard.features import FeatureNormalizer, NormalizationRule, feature_contract, frames_from_archive
    from tcn.metody import Okna
    frames = {}
    for ident, _ in roles:
        with np.load(records[ident]["features"], allow_pickle=False) as data:
            frames[ident] = frames_from_archive(data, ident)
    rule = NormalizationRule.from_protocol(protocol(), diagnostic=True)
    first = frames[roles[0][0]]
    normalizer = FeatureNormalizer.fit([f for f in first if f.measured], rule)
    contract = feature_contract(first[0], WINDOW, GAP)
    return [Okna.from_sessions([(dict(records[ident], role=role), frames[ident])], normalizer, contract, role=role,
                               interval_s=INTERVAL) for ident, role in roles]


# ------------------------------------------------------------------ the ledger


def test_sealed_roles_are_the_test_roles():
    """The sealed roles are those training never loads (features/dataset.py ROLES without FIT_ROLES)."""
    from features.dataset import FIT_ROLES, ROLES
    from tcn import pecat
    assert pecat.SEALED_ROLES == tuple(role for role in ROLES if role not in FIT_ROLES) == SEALED_ROLES


SEALED_ROLES = ("test_benign", "test_controls")


@pytest.mark.parametrize("hashes,reason", [
    (["a" * 64, "a" * 64], "a seal is the identity of distinct sha256 hex digests of feature archives, at least one"),
    (["A" * 64], "a seal is the identity of distinct sha256 hex digests of feature archives, at least one"),
    ([], "a seal is the identity of distinct sha256 hex digests of feature archives, at least one"),
    (["b" * 64, "a" * 64], None),
])
def test_the_identity_is_that_of_the_sorted_archives(hashes, reason):
    """IDENTITY_RULE: sha256 of the sorted lines of the archives' sha256 (sort | sha256sum), whatever their order."""
    from tcn import pecat
    if reason is not None:
        with pytest.raises(ValueError) as error:
            pecat.identita(hashes)
        assert str(error.value) == reason
        return
    expected = hashlib.sha256(("a" * 64 + "\n" + "b" * 64 + "\n").encode()).hexdigest()
    assert pecat.identita(hashes) == pecat.identita(hashes[::-1]) == expected


def test_zapis_seals_the_test_roles_with_the_provenance_of_a_record(tmp_path, ledger):
    """zapis of a corpus writes the archives of its sealed sessions and no other, once (a second write keeps the
    ledger as it is); the ledger carries the provenance fields of a record of data/results (check E of
    scripts/check_claims.sh) and its values."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus")
    first = pecat.zapis_korpus(index, command="campaign", ledger=ledger)
    sealed = sorted(records[ident]["features_sha256"] for ident, _ in SEALED)
    assert (first["written"], first["already"], first["not_sealed"], first["mode"], first["plan"]) == (
        sealed, [], {"train": 1}, "campaign", plan_name("campaign"))
    doc = json.loads(ledger.read_text())
    assert {"commit", "commit_dirty", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"], doc["command"], doc["guest"]) == ("hyptcn3/seal-ledger/1", 3, "campaign", None)
    assert set(doc["values"]["created"]) == {"date", "commit", "commit_dirty", "command"}  # Verification of B7c, F5.
    assert type(doc["commit_dirty"]) is bool or doc["commit_dirty"] is None
    entry = doc["values"]["archives"][records["tc-1"]["features_sha256"]]
    assert {key: entry[key] for key in ("role", "session", "plan", "mode", "protocol_sha256")} == {
        "role": "test_controls", "session": "tc-1", "plan": plan_name("campaign"), "mode": "campaign",
        "protocol_sha256": sha(V5)}
    before = ledger.read_bytes()
    again = pecat.zapis_korpus(index, command="again", ledger=ledger)
    assert (again["written"], again["already"], ledger.read_bytes()) == ([], sealed, before)


@pytest.mark.parametrize("case", ["changed_archive", "another_session", "another_plan", "schema_2", "no_mode"])
def test_zapis_refuses_by_name(tmp_path, ledger, case):
    """One bad input per check of zapis: an archive whose bytes changed since its record, an archive the ledger seals
    for another session, one it seals for the same session under another plan and mode (the rehearsal's; mutant P10
    of the verification of B7c), a protocol of schema 2 and an index without its plan mode; the ledger stays as it
    was."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus")
    record = records["tb-1"]
    doc = json.loads(index.read_text())
    if case == "changed_archive":
        Path(record["features"]).write_bytes(Path(records["tb-2"]["features"]).read_bytes())
        reason = (f"the feature archive of session tb-1 changed since its record: {record['features']} has sha256 "
                  f"{records['tb-2']['features_sha256']}, the record {record['features_sha256']}")
    elif case == "another_session":
        pecat.zapis([dict(record, id="other")], protocol=protocol(), protocol_sha256=sha(V5), mode="campaign",
                    command="earlier", ledger=ledger)
        reason = (f"{record['features']}: the ledger seals this archive for session other of role test_benign, plan "
                  f"{plan_name('campaign')} (campaign), not for session tb-1 of role test_benign, plan "
                  f"{plan_name('campaign')} (campaign)")
    elif case == "another_plan":
        pecat.zapis([record], protocol=protocol(), protocol_sha256=sha(V5), mode="rehearsal", command="the rehearsal",
                    ledger=ledger)
        reason = (f"{record['features']}: the ledger seals this archive for session tb-1 of role test_benign, plan "
                  f"{plan_name('rehearsal')} (rehearsal), not for session tb-1 of role test_benign, plan "
                  f"{plan_name('campaign')} (campaign)")
    elif case == "schema_2":
        doc["protocol_config"]["schema"] = "hyptcn3/collection-protocol/2"
        index.write_text(json.dumps(doc))
        reason = ("the seal is that of protocol v5 (protocol schema hyptcn3/collection-protocol/3), not of "
                  "'hyptcn3/collection-protocol/2': a corpus of schema 1 or 2 keeps tcn.eval --final")
    else:
        doc["plan_mode"] = None
        index.write_text(json.dumps(doc))
        reason = "plan mode None: a seal names the plan mode of its corpus, campaign or rehearsal"
    before = ledger.read_bytes()
    with pytest.raises(ValueError) as error:
        pecat.zapis_korpus(index, command="campaign", ledger=ledger)
    assert str(error.value) == reason and ledger.read_bytes() == before


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_zapis_refuses_a_second_archive_of_a_sealed_session(tmp_path, ledger, mode):
    """Verification of B7c, F8 (SEALED_RULE): the seal binds the session, not only the bytes of its archive. In plan
    mode campaign a second archive with other bytes for a session the ledger seals (a re-extraction: the same plan,
    mode, role and id) is refused by name and the ledger stays as it was; a rehearsal keeps it beside the first (not
    enforced)."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus", mode)
    pecat.zapis_korpus(index, command="the campaign", ledger=ledger)
    old = records["tb-1"]
    path, digest = write_archive(tmp_path / "reextracted" / "features.npz", "tb-1", 99)
    assert digest != old["features_sha256"]
    again = dict(old, features=str(path), features_sha256=digest)
    before = ledger.read_bytes()
    if mode == "campaign":
        with pytest.raises(pecat.Zapecatene) as error:
            pecat.zapis([again], protocol=protocol(), protocol_sha256=sha(V5), mode=mode, command="re-extraction",
                        ledger=ledger)
        assert str(error.value) == (
            f"{path}: the ledger seals session tb-1 of role test_benign, plan {plan_name(mode)} (campaign) by the "
            f"archive {old['features_sha256']}; a second archive with other bytes of a sealed session (a "
            "re-extraction) is refused: the seal binds the session, not only the bytes of its archive (SEALED_RULE)")
        assert ledger.read_bytes() == before
        return
    out = pecat.zapis([again], protocol=protocol(), protocol_sha256=sha(V5), mode=mode, command="re-extraction",
                      ledger=ledger)
    entry = json.loads(ledger.read_text())["values"]["archives"][digest]
    assert (out["written"], entry["session"], entry["beside"]) == ([digest], "tb-1", [old["features_sha256"]])


@pytest.mark.parametrize("case", ["missing", "malformed", "created_twice"])
def test_a_missing_or_malformed_ledger_is_refused(tmp_path, ledger, case):
    """Without the ledger no archive can be told sealed or not: kontrola refuses a missing or malformed ledger by
    name; a ledger is created once."""
    from tcn import pecat
    archive, _ = write_archive(tmp_path / "a.npz", "a", 0)
    if case == "created_twice":
        with pytest.raises(ValueError) as error:
            pecat.zaloz(command="again", ledger=ledger)
        assert str(error.value) == f"the ledger {ledger} exists: a ledger is created once"
        return
    if case == "missing":
        ledger.unlink()
        reason = (f"the ledger {ledger} is missing: it is a tracked file of the repository (git checkout "
                  "data/results/kniha_pecati.json); without it no archive can be told sealed or not")
    else:
        ledger.write_text(json.dumps({"schema": "hyptcn3/seal-ledger/1", "values": {"archives": []}}))
        reason = f"the ledger {ledger} is no seal ledger of schema hyptcn3/seal-ledger/1"
    with pytest.raises(ValueError) as error:
        pecat.kontrola(archive, purpose="test")
    assert str(error.value) == reason


def test_the_tracked_ledger_is_a_record_of_data_results():
    """data/results/kniha_pecati.json is a valid seal ledger (tcn.pecat reads it) with the provenance fields of check E
    of scripts/check_claims.sh and commit_dirty in its header and its created block, its rules are the code's (RULES;
    verification of B7c, F5: a change of a rule recreates it), and no run has consumed a seal yet."""
    from tcn import pecat
    path = ROOT / "data/results/kniha_pecati.json"
    doc = json.loads(path.read_text())
    assert pecat._read(path.resolve()) == doc
    assert {"commit", "commit_dirty", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert set(doc["values"]["created"]) == {"date", "commit", "commit_dirty", "command"}
    assert doc["values"]["rules"] == pecat.RULES
    assert (doc["schema"], doc["values"]["roles"], doc["values"]["runs"]) == (
        "hyptcn3/seal-ledger/1", list(SEALED_ROLES), [])


# ------------------------------------------------------------------ the guards


def replay_runtime(path, out):
    from safeguard.runtime import replay_archive
    return replay_archive(Bundle(path), path)


def replay_cli(path, out):
    """safeguard replay --archive on the command line (the threads of torch as they are)."""
    import torch
    from safeguard import cli
    return cli.main(["--threads", str(torch.get_num_threads()), "replay", "--bundle", str(out.parent / "no-bundle"),
                     "--archive", str(path), "--out", str(out)])


def replay_porovnanie(path, out):
    from tcn import porovnanie
    return porovnanie.replay(out.parent / "no-model", path, out)


ENTRY_POINTS = {"safeguard.runtime.replay_archive": replay_runtime, "safeguard replay --archive": replay_cli,
                "tcn.porovnanie replay": replay_porovnanie}


@pytest.mark.parametrize("purpose", ENTRY_POINTS)
def test_replay_of_a_sealed_archive_is_refused(sealed, ledger, tmp_path, capsys, purpose):
    """Every replay entry point refuses a sealed archive of a campaign by name before it loads the bundle or writes
    anything; the command line exits 2 with the reason and leaves no output directory."""
    from tcn import pecat
    index, records = sealed
    record, out = records["tb-1"], tmp_path / "out"
    expected = sealed_message(purpose, f"the archive {record['features']}", record, "campaign", ledger)
    if purpose == "safeguard replay --archive":
        assert ENTRY_POINTS[purpose](Path(record["features"]), out) == 2
        assert capsys.readouterr().err == f"safeguard: {expected}\n"
    else:
        with pytest.raises(pecat.Zapecatene) as error:
            ENTRY_POINTS[purpose](Path(record["features"]), out)
        assert str(error.value) == expected
    assert not out.exists()


def test_the_unsealed_twin_is_replayed(sealed, tmp_path, monkeypatch):
    """The twin: the archive of the train session of the same corpus is no sealed archive; it is replayed, and the
    replay's configuration names the decision."""
    from safeguard import cli
    _, records = sealed
    path = Path(records["tr-1"]["features"])
    assert len(replay_runtime(path, None)) == ROWS
    monkeypatch.setattr(cli, "load_bundle", lambda bundle, allow_diagnostic: Bundle(path))
    assert replay_cli(path, tmp_path / "out") == 2  # ok false: the bundle's protocol tolerates no invalid row.
    seal = json.loads((tmp_path / "out" / "configuration.json").read_text())["seal"]
    assert (seal["allowed"], seal["sealed"], seal["sha256"], seal["mark"]) == (
        "not_sealed", False, records["tr-1"]["features_sha256"], None)


def test_a_copy_of_a_sealed_archive_under_another_path_is_refused(sealed, ledger, tmp_path):
    """The ledger keys on the bytes: a copy of a sealed archive under another path is the same sealed archive."""
    from tcn import pecat
    _, records = sealed
    record = records["tc-1"]
    copy = tmp_path / "elsewhere" / "copy.npz"
    copy.parent.mkdir()
    shutil.copyfile(record["features"], copy)
    with pytest.raises(pecat.Zapecatene) as error:
        replay_runtime(copy, None)
    assert str(error.value) == sealed_message("safeguard.runtime.replay_archive", f"the archive {copy}", record,
                                              "campaign", ledger)


def model(windows):
    """M of seed 0 over the normalizer of `windows` (tcn.metody.MetodaM): a bundle in memory (safeguard/bundle.py
    Bundle, as safeguard/tests/test_channels.py bundle()) with an untrained TCN."""
    import torch
    from safeguard.bundle import Bundle
    from safeguard.model import Classifier, Predictor, architecture
    from tcn.metody import MetodaM
    torch.manual_seed(0)
    config = architecture(WINDOW, global_features=len(windows.normalizer.input_names))
    manifest = {"feature_contract": {"window_rows": WINDOW, "max_gap_s": GAP}, "classes": ["eshop_low"],
                "calibration": {"threshold": 1e9, "k": 1, "n": 1, "diagnostic": True}, "training": {"seed": 0}}
    return MetodaM(Bundle(manifest, Predictor(config).eval(), Classifier(config, 1).eval(), windows.normalizer))


def session_directory(root, ident, *, session_json=True):
    """A session directory as a capture leaves it: session.json naming `ident` (or none) and an empty raw/ (the guards
    refuse before a snapshot is read); (session directory, raw)."""
    directory = Path(root) / ident
    (directory / "raw").mkdir(parents=True)
    if session_json:
        (directory / "session.json").write_text(json.dumps({"session_id": ident, "role": "test_benign"}))
    return directory, directory / "raw"


def snapshots_cli(source, out, command="replay"):
    """safeguard replay (or watch) --snapshots on the command line (the threads of torch as they are)."""
    import torch
    from safeguard import cli
    return cli.main(["--threads", str(torch.get_num_threads()), command, "--bundle", str(out.parent / "no-bundle"),
                     "--snapshots", str(source), "--out", str(out)])


def snapshots_runtime(source, out):
    from safeguard.runtime import run_directory
    return run_directory(None, source, out.parent / "no-profile", out, preserve=False)


def snapshots_validation(source, out):
    from scripts import validate_safeguard
    return validate_safeguard.main(["--raw", str(source), "--profile", str(out.parent / "no-profile"), "--out",
                                    str(out), "--result", str(out.parent / "result.json")])


# (the entry point, the directory it is given: the session directory, or its raw/ whose parent names the session)
SNAPSHOT_POINTS = {"safeguard replay --snapshots": (snapshots_cli, "raw"),
                   "safeguard watch --snapshots": (lambda source, out: snapshots_cli(source, out, "watch"), "raw"),
                   "safeguard.runtime.run_directory": (snapshots_runtime, "session"),
                   "scripts/validate_safeguard.py": (snapshots_validation, "raw")}


@pytest.mark.parametrize("purpose", SNAPSHOT_POINTS)
def test_the_snapshots_of_a_sealed_session_are_refused(sealed, ledger, tmp_path, capsys, purpose):
    """Verification of B7c, F1 (SNAPSHOT_RULE): the raw snapshots of a session the ledger seals for a campaign are
    refused by name at every snapshot entry point before anything is read or written: the session is the one whose
    session_id the session.json of the directory names, or that of its parent for a raw/ directory; the command line
    exits 2 with the reason and leaves no output directory."""
    from tcn import pecat
    _, records = sealed
    record, out = records["tb-1"], tmp_path / "out"
    entry, layout = SNAPSHOT_POINTS[purpose]
    directory, raw = session_directory(tmp_path / "sessions", "tb-1")
    source = raw if layout == "raw" else directory
    expected = sealed_message(purpose, f"the snapshot directory {source.resolve()} of session tb-1", record, "campaign",
                              ledger)
    if purpose.endswith("--snapshots"):
        assert entry(source, out) == 2
        assert capsys.readouterr().err == f"safeguard: {expected}\n"
    else:
        with pytest.raises(pecat.Zapecatene) as error:
            entry(source, out)
        assert str(error.value) == expected
    assert not out.exists()


@pytest.mark.parametrize("case", ["rehearsal", "not_sealed", "no_session", "no_session_id"])
def test_the_session_of_a_snapshot_directory_decides(tmp_path, ledger, of_record, case):
    """SNAPSHOT_RULE: the snapshot directory of a rehearsal's session is let through with the rehearsal mark, which the
    replay of the directory records (configuration.json and status.json of run_directory); a session the ledger does
    not hold is not sealed; a directory without a session.json in it or its parent names no session
    (NO_SESSION_RULE); a session.json without a session_id is refused by name."""
    from safeguard.runtime import run_directory
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus", "rehearsal" if case == "rehearsal" else "campaign")
    if case == "rehearsal":
        pecat.zapis_korpus(index, command="the rehearsal", ledger=ledger)
    directory, raw = session_directory(tmp_path / "sessions", "tb-1", session_json=case != "no_session")
    if case == "no_session_id":
        (directory / "session.json").write_text(json.dumps({"role": "test_benign"}))
        with pytest.raises(ValueError) as error:
            pecat.kontrola_snimok(raw, purpose="test")
        assert str(error.value) == (f"{directory.resolve() / 'session.json'} names no session_id: the session of the "
                                    f"snapshot directory {raw.resolve()} cannot be told (tcn/pecat.py SNAPSHOT_RULE)")
        return
    out = tmp_path / "replay"
    summary = run_directory(Bundle(Path(records["tb-1"]["features"])), raw, tmp_path / "no-profile", out,
                            preserve=False)
    configuration = json.loads((out / "configuration.json").read_text())["seal"]
    allowed, session = {"rehearsal": ("rehearsal", "tb-1"), "not_sealed": ("not_sealed", "tb-1"),
                        "no_session": ("no_session", None)}[case]
    assert (configuration["allowed"], configuration["session"], summary["seal"]["allowed"]) == (
        allowed, session, allowed)
    mark = pecat.REHEARSAL_MARK if case == "rehearsal" else None
    assert (summary["seal"]["mark"], summary["seal"]["rehearsal"], configuration["mark"]) == (
        mark, case == "rehearsal", mark)
    assert summary["stop_reason"] == "empty_input"  # The empty raw/: nothing was read.


def archived_session(root, ident, meta=None):
    """A session directory of `ident` with two raw members and its verified archive (scripts/collection_archive.py
    archive_session, members stored plain); (the archive, the session.json's document)."""
    from scripts import collection_archive as arc
    meta = {"session_id": ident, "campaign_id": "kampan-1", "role": "test_benign"} if meta is None else meta
    source = Path(root) / "sessions" / ident
    (source / "raw").mkdir(parents=True)
    for name in ("frame0.vmicd", "frame0.json"):
        (source / "raw" / name).write_bytes(b"synthetic " + name.encode())
    (source / "session.json").write_text(json.dumps(meta))
    archive = Path(root) / "archive" / ident
    arc.archive_session(source, archive, lambda: None)
    return archive, meta


def test_the_snapshots_restored_from_the_archive_of_a_sealed_session_are_refused_by_name(sealed, ledger, tmp_path):
    """The lead's answer to question Q19 (finding N1 of the B7c confirmation, package B10):
    scripts/collection_archive.py restore_raw writes into the new directory the marker restored_from.json, which names
    the session of the archive's session.json (its session_id and campaign_id), the archive and its sha256 as the
    receipt states it (the sha256 of the manifest) and the sha256 of the session.json; the snapshot guard reads it as a
    session.json, so the raw snapshots of a sealed session restored from its archive are refused by name, at the guard
    and at an entry point, before anything is written. A restored raw/ of a session the ledger does not hold is not
    sealed and names its marker; a marker without a session_id is refused by name, as a session.json without one."""
    from safeguard.runtime import run_directory
    from scripts import collection_archive as arc
    from tcn import pecat
    _, records = sealed
    archive, meta = archived_session(tmp_path, "tb-1")
    target = tmp_path / "restored" / "raw"
    summary = arc.restore_raw(archive, target)
    where = (f"the snapshot directory {target.resolve()} of session tb-1, restored from an archive "
             f"({target.resolve() / 'restored_from.json'})")
    with pytest.raises(pecat.Zapecatene) as error:
        pecat.kontrola_snimok(target, purpose="test")
    assert str(error.value) == sealed_message("test", where, records["tb-1"], "campaign", ledger)
    out = tmp_path / "replay"
    with pytest.raises(pecat.Zapecatene) as error:
        run_directory(None, target, tmp_path / "no-profile", out, preserve=False)
    assert str(error.value) == sealed_message("safeguard.runtime.run_directory", where, records["tb-1"], "campaign",
                                              ledger)
    assert not out.exists()
    assert pecat.RESTORED == arc.RESTORED == "restored_from.json"
    marker = json.loads((target / "restored_from.json").read_text())
    assert {key: marker[key] for key in ("schema", "session_id", "campaign_id", "archive", "manifest_sha256",
                                         "session_json_sha256", "rule")} == {
        "schema": "hyptcn3/restored-raw/1", "session_id": "tb-1", "campaign_id": "kampan-1", "archive": str(archive),
        "manifest_sha256": sha(archive / "archive-manifest.json"), "session_json_sha256": sha(archive / "session.json"),
        "rule": arc.RESTORE_RULE}
    assert sorted(p.name for p in target.iterdir()) == ["frame0.json", "frame0.vmicd", "restored_from.json"]
    assert (summary["restored_from"], summary["session_id"]) == (str(target / "restored_from.json"), "tb-1")
    # A session the ledger does not hold: not sealed, the decision names the marker.
    other, _ = archived_session(tmp_path / "other", "tr-9")
    decision = pecat.kontrola_snimok(arc.restore_raw(other, tmp_path / "other-raw")["target"], purpose="test")
    assert (decision["allowed"], decision["session"], decision["session_json"], decision["restored_from"]) == (
        "not_sealed", "tr-9", None, str((tmp_path / "other-raw" / "restored_from.json").resolve()))
    # An archive whose session.json names no session: its marker is refused by name.
    nameless, _ = archived_session(tmp_path / "nameless", "x", meta={"role": "test_benign"})
    restored = Path(arc.restore_raw(nameless, tmp_path / "nameless-raw")["target"]).resolve()
    with pytest.raises(ValueError) as error:
        pecat.kontrola_snimok(restored, purpose="test")
    assert str(error.value) == (f"{restored / 'restored_from.json'} names no session_id: the session of the snapshot "
                                f"directory {restored} cannot be told (tcn/pecat.py SNAPSHOT_RULE)")


def test_a_method_given_a_window_set_of_a_sealed_archive_refuses_it(sealed, ledger):
    """The methods of the wrapper (tcn/metody.py Z0 and M) and the descriptive ones (tcn/opisne.py, the z-score)
    refuse a window set that holds a sealed archive, by name; the window sets of train and dev, which hold none, are
    fitted and scored."""
    from tcn import opisne, pecat
    from tcn.metody import Z0
    _, records = sealed
    train, dev, test = window_sets(records, [("tr-1", "train"), ("tr-1", "dev"), ("tb-1", "test_benign")])
    assert test.archives == (records["tb-1"]["features_sha256"],)
    for method, name, seed in ((Z0(), "Z0", 0), (opisne.method("zscore"), "zscore", None), (model(test), "M:seed 0",
                                                                                            0)):
        method.fit(train, dev, protocol=protocol(), seed=seed)
        assert method.scores(dev).shape == (len(dev),)
        with pytest.raises(pecat.Zapecatene) as error:
            method.scores(test)
        assert str(error.value) == sealed_message(f"{name} scores a window set of role test_benign",
                                                  "an archive of the window set", records["tb-1"], "campaign", ledger)


@pytest.mark.parametrize("case", ["missing_hash", "bad_hash"])
def test_a_window_set_names_the_archive_of_its_sessions(sealed, case):
    """A window set of a sealed role built from index records names the archive of every session (features_sha256),
    which a derived set keeps (tcn/diagnostiky.py truncated); a record of a sealed role without it, and a hash that is
    none, are refused by name."""
    from tcn import diagnostiky
    from tcn.metody import Okna
    _, records = sealed
    test, = window_sets(records, [("tb-1", "test_benign")])
    assert diagnostiky.truncated(test, 1).archives == test.archives == (records["tb-1"]["features_sha256"],)
    assert test.session_arrays(0)["features_sha256"] == records["tb-1"]["features_sha256"]
    if case == "missing_hash":
        with pytest.raises(ValueError) as error:
            Okna.from_sessions([({"id": "tb-1", "role": "test_benign", "scenario": "s"}, [])], test.normalizer,
                               None, role="test_benign", interval_s=INTERVAL)
        assert str(error.value) == ("a session of the sealed role test_benign names the sha256 of its feature archive "
                                    "(features_sha256 of its index record): tcn/pecat.py decides by it whether it is "
                                    "sealed")
    else:
        session = dict(test.session_arrays(0), features_sha256="F" * 64)
        with pytest.raises(ValueError) as error:
            Okna([session], [tuple(int(x) for x in test.index[0][:2]) + (None,)], role="test_benign",
                 normalizer=test.normalizer, window_rows=WINDOW, max_gap_s=GAP, interval_s=INTERVAL)
        assert str(error.value) == ("session tb-1: features_sha256 is the sha256 of its feature archive (64 lowercase "
                                    "hex digits) or absent")


# ------------------------------------------------------------------ the final run


def test_the_final_run_replays_its_sealed_archives_once(sealed, ledger, of_record, in_git, tmp_path):
    """Inside the final run every guard lets its archives through (decision final_run, stage final on the ledger of
    record, whose seal the ledger at HEAD holds); the run is in the ledger before the first replay and closes
    completed; after it the archives are refused again."""
    from tcn import pecat
    from tcn.metody import Z0
    index, records = sealed
    record = records["tb-2"]
    train, dev, test = window_sets(records, [("tr-1", "train"), ("tr-1", "dev"), ("tb-2", "test_benign")])
    method = Z0()
    method.fit(train, dev, protocol=protocol(), seed=0)
    with pecat.spotrebuj(index, out=tmp_path / "final.json", command="python -m tcn.finalne", ledger=ledger) as run:
        assert pecat.otvoreny() is run
        opened = json.loads(ledger.read_text())["values"]["runs"]
        assert [(r["number"], r["closed"]) for r in opened] == [(1, None)]
        decision = pecat.kontrola(record["features"], purpose="test")
        assert (decision["allowed"], decision["stage"], decision["rehearsal"], decision["identity"]) == (
            "final_run", "final", False, run.identity)
        assert len(replay_runtime(Path(record["features"]), None)) == ROWS
        assert method.scores(test).shape == (len(test),)
    assert pecat.otvoreny() is None
    entry, = json.loads(ledger.read_text())["values"]["runs"]
    hashes = sorted(records[ident]["features_sha256"] for ident, _ in SEALED)
    assert {key: entry[key] for key in ("identity", "number", "mode", "stage", "archives", "roles", "corpus", "out",
                                        "seal_in_git")} == {
        "identity": hashlib.sha256("".join(h + "\n" for h in hashes).encode()).hexdigest(), "number": 1,
        "mode": "campaign", "stage": "final", "archives": hashes, "roles": {"test_benign": 2, "test_controls": 1},
        "corpus": str(index), "out": str(tmp_path / "final.json"), "seal_in_git": True}
    assert entry["closed"]["outcome"] == "completed" and run.record()["mark"]["stage"] == "final"
    consumed = (f"; its seal was consumed by the final run opened {entry['opened']['date']} (out "
                f"{tmp_path / 'final.json'})")
    with pytest.raises(pecat.Zapecatene) as error:
        replay_runtime(Path(record["features"]), None)
    assert str(error.value) == sealed_message("safeguard.runtime.replay_archive", f"the archive {record['features']}",
                                              record, "campaign", ledger, consumed)


def second_corpus(tmp_path, index, records, case):
    """The index of a second final run: the same file, a byte-identical copy under another path, an index over copies
    of the archives under another directory, or an index of part of the sealed sessions."""
    if case == "same_index":
        return index
    if case == "copy_of_the_index":
        other = tmp_path / "copy" / "corpus-copy.json"
        other.parent.mkdir()
        shutil.copyfile(index, other)
        return other
    if case == "copy_of_the_corpus":
        moved = []
        for record in records.values():
            target = tmp_path / "moved" / record["id"] / "features.npz"
            target.parent.mkdir(parents=True)
            shutil.copyfile(record["features"], target)
            moved.append(dict(record, features=str(target)))
        return write_index(tmp_path / "moved" / "corpus.json", moved, "campaign")
    part = [records["tb-1"], records["tr-1"]]
    return write_index(tmp_path / "part.json", part, "campaign")


@pytest.mark.parametrize("case", ["same_index", "copy_of_the_index", "copy_of_the_corpus", "part_of_the_corpus"])
def test_a_second_final_run_is_refused(sealed, ledger, tmp_path, case):
    """After the final run of a campaign a second one is refused by name: through the same index, a copy of the index
    under another path, an index over copies of the archives elsewhere (the same seal) or of part of its sessions;
    the ledger keeps the one run."""
    from tcn import pecat
    index, records = sealed
    pecat.spotrebuj(index, out=tmp_path / "first.json", command="first", ledger=ledger).close()
    first, = json.loads(ledger.read_text())["values"]["runs"]
    other = second_corpus(tmp_path, index, records, case)
    with pytest.raises(pecat.Zapecatene) as error:
        pecat.spotrebuj(other, out=tmp_path / "second.json", command="second", ledger=ledger)
    assert str(error.value) == (
        f"{other}: a second final run is refused: the seal of its sealed archives was consumed by the final run of "
        f"seal {first['identity']} opened {first['opened']['date']} (corpus {index}, out {tmp_path / 'first.json'}); "
        "the identity is that of the archives, so a copy of the corpus under another path has the same seal "
        "(RUN_RULE)")
    assert pecat.otvoreny() is None and len(json.loads(ledger.read_text())["values"]["runs"]) == 1
    if case != "part_of_the_corpus":
        assert pecat.stav(other, ledger=ledger)["identity"] == first["identity"]


def test_a_session_of_an_earlier_campaign_run_is_refused_with_another_archive(sealed, ledger, tmp_path):
    """Verification of B7c, F8 (RUN_RULE): after the final run of a campaign, a corpus of one of its sessions with
    another archive of it (a re-extraction, written into the ledger by hand or by a ledger before this rule: zapis
    refuses it now) is refused by name, and stav tells it consumed and not ready; the ledger keeps the one run."""
    from tcn import pecat
    index, records = sealed
    pecat.spotrebuj(index, out=tmp_path / "first.json", command="first", ledger=ledger).close()
    first, = json.loads(ledger.read_text())["values"]["runs"]
    path, digest = write_archive(tmp_path / "reextracted" / "tb-1" / "features.npz", "tb-1", 99)
    doc = json.loads(ledger.read_text())
    doc["values"]["archives"][digest] = dict(doc["values"]["archives"][records["tb-1"]["features_sha256"]],
                                             features=str(path))
    ledger.write_text(json.dumps(doc))
    other = write_index(tmp_path / "reextracted" / "corpus.json",
                        [dict(records["tb-1"], features=str(path), features_sha256=digest), records["tr-1"]],
                        "campaign")
    state = pecat.stav(other, ledger=ledger)
    assert (state["consumed"], state["ready"], [r["identity"] for r in state["runs"]]) == (
        True, False, [first["identity"]])
    with pytest.raises(pecat.Zapecatene) as error:
        pecat.spotrebuj(other, out=tmp_path / "second.json", command="second", ledger=ledger)
    assert str(error.value) == (
        f"{other}: a second final run is refused: session tb-1 of plan {plan_name('campaign')} was in the final run of "
        f"seal {first['identity']} opened {first['opened']['date']} (corpus {index}, out {tmp_path / 'first.json'}) "
        "with another archive; the seal binds the sessions, not only the bytes of their archives (RUN_RULE)")
    assert len(json.loads(ledger.read_text())["values"]["runs"]) == 1
    assert first["sessions"] == [{"plan": plan_name("campaign"), "role": role, "session": ident}
                                 for ident, role in sorted(SEALED)]


def test_stav_tells_an_archive_consumed_under_another_session(sealed, ledger, tmp_path):
    """The archive of a consumed seal stays consumed whatever session an index names for it: stav of an index that
    names the sealed archive of tb-1 for another session tells it consumed by the earlier campaign run (by its archives,
    where no session of the index was in that run: mutant P11 of the verification of B7c, which the session rule of F8
    would otherwise hide), mismatched and not ready."""
    from tcn import pecat
    index, records = sealed
    pecat.spotrebuj(index, out=tmp_path / "first.json", command="first", ledger=ledger).close()
    other = write_index(tmp_path / "renamed.json", [dict(records["tb-1"], id="renamed"), records["tr-1"]], "campaign")
    state = pecat.stav(other, ledger=ledger)
    assert (state["consumed"], state["mismatched"], state["ready"], len(state["runs"])) == (True, ["renamed"], False, 1)


def test_a_final_run_opens_its_own_archives_only(sealed, ledger, tmp_path):
    """Inside the final run of one corpus the sealed archive of another campaign corpus stays refused (mutant P3 of
    the verification of B7c: an open run must not admit every sealed archive), while the run's own is let through."""
    from tcn import pecat
    index, records = sealed
    other, mine = corpus(tmp_path / "other", sessions=(("ob-1", "test_benign"),))
    pecat.zapis_korpus(other, command="another campaign", ledger=ledger)
    with pecat.spotrebuj(index, out=tmp_path / "final.json", command="final", ledger=ledger):
        assert pecat.kontrola(records["tb-1"]["features"], purpose="test")["allowed"] == "final_run"
        with pytest.raises(pecat.Zapecatene) as error:
            pecat.kontrola(mine["ob-1"]["features"], purpose="test")
        assert str(error.value) == sealed_message("test", f"the archive {mine['ob-1']['features']}", mine["ob-1"],
                                                  "campaign", ledger)


@pytest.mark.parametrize("case", ["not_in_the_ledger", "a_run_is_open"])
def test_a_final_run_without_a_seal_to_consume_is_refused(tmp_path, ledger, case):
    """A campaign whose sealed sessions the ledger does not hold has no seal to consume; one final run is open in a
    process at a time."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus")
    if case == "not_in_the_ledger":
        reason = (f"{index}: the archive of session tb-1 (role test_benign, sha256 {records['tb-1']['features_sha256']}) "
                  f"is not in the ledger {ledger}: the campaign writes every sealed session into it before the final "
                  "run (tcn/pecat.py zapis), so this corpus has no seal to consume (RUN_RULE)")
        assert pecat.stav(index, ledger=ledger)["ready"] is False
    else:
        pecat.zapis_korpus(index, command="campaign", ledger=ledger)
        rehearsal, _ = corpus(tmp_path / "rehearsal", "rehearsal", sessions=(("r-1", "test_benign"),))
        run = pecat.spotrebuj(rehearsal, out=tmp_path / "r.json", command="rehearsal", ledger=ledger)
        reason = f"a final run is open in this process (seal {run.identity}, run 1): one run at a time"
    try:
        with pytest.raises(pecat.Zapecatene) as error:
            pecat.spotrebuj(index, out=tmp_path / "final.json", command="final", ledger=ledger)
        assert str(error.value) == reason
    finally:
        if pecat.otvoreny() is not None:
            pecat.otvoreny().close()
    assert [r["mode"] for r in json.loads(ledger.read_text())["values"]["runs"]] == (
        [] if case == "not_in_the_ledger" else ["rehearsal"])


def test_a_rehearsal_is_kept_marked_and_not_enforced(tmp_path, ledger, of_record, monkeypatch):
    """A rehearsal (plan mode rehearsal) on the ledger of record: its archives are kept in the ledger (written by its
    first run when the campaign did not), every guard lets them through with the rehearsal mark, the final command may
    run again (runs 1 and 2, stage generalka) and the replay's output carries the mark."""
    from safeguard import cli
    from tcn import pecat
    index, records = corpus(tmp_path / "rehearsal", "rehearsal")
    record = records["tb-1"]
    with pecat.spotrebuj(index, out=tmp_path / "1.json", command="rehearsal 1", ledger=ledger) as first:
        assert (first.number, first.stage, first.rehearsal, first.mark["mark"]) == (
            1, "generalka", True, pecat.REHEARSAL_MARK)
    entry = json.loads(ledger.read_text())["values"]["archives"][record["features_sha256"]]
    assert (entry["mode"], entry["plan"], entry["session"]) == ("rehearsal", plan_name("rehearsal"), "tb-1")
    decision = pecat.kontrola(record["features"], purpose="test")
    assert (decision["allowed"], decision["sealed"], decision["stage"], decision["rehearsal"], decision["mark"]) == (
        "rehearsal", True, "generalka", True, pecat.REHEARSAL_MARK)
    monkeypatch.setattr(cli, "load_bundle", lambda bundle, allow_diagnostic: Bundle(Path(record["features"])))
    replay_cli(Path(record["features"]), tmp_path / "out")
    configuration = json.loads((tmp_path / "out" / "configuration.json").read_text())
    status = json.loads((tmp_path / "out" / "status.json").read_text())
    assert (configuration["seal"]["mark"], status["seal"]["rehearsal"], status["seal"]["stage"]) == (
        pecat.REHEARSAL_MARK, True, "generalka")
    with pecat.spotrebuj(index, out=tmp_path / "2.json", command="rehearsal 2", ledger=ledger) as second:
        assert (second.number, second.identity, second.record()["mark"]["rehearsal"]) == (2, first.identity, True)
    assert [r["number"] for r in json.loads(ledger.read_text())["values"]["runs"]] == [1, 2]


def test_a_failed_final_run_still_consumed_its_seal(sealed, ledger, tmp_path):
    """The run is recorded before its first replay: a final run that fails closes failed with its error, and its
    seal stays consumed."""
    from tcn import pecat
    index, _ = sealed
    with pytest.raises(RuntimeError):
        with pecat.spotrebuj(index, out=tmp_path / "final.json", command="final", ledger=ledger):
            raise RuntimeError("a replay failed")
    entry, = json.loads(ledger.read_text())["values"]["runs"]
    assert (entry["closed"]["outcome"], entry["closed"]["error"]) == ("failed", "RuntimeError: a replay failed")
    assert pecat.stav(index, ledger=ledger)["consumed"] is True


# ------------------------------------------------------------------ the output of a replay


def test_an_unscored_stretch_is_nevyhodnotene_in_the_output(tmp_path, ledger, monkeypatch):
    """safeguard replay --archive reports every unscored stretch as nevyhodnotené, not as silence: a window of 3 rows
    after the full snapshots at seq 0 and 12 (the snapshot and two rows warming up) and after the invalid row 7 (the
    row, the next without a predecessor and two rows warming up), 10 rows of 5 s."""
    from safeguard import cli
    path, _ = write_archive(tmp_path / "a.npz", "a", 0)
    monkeypatch.setattr(cli, "load_bundle", lambda bundle, allow_diagnostic: Bundle(path))
    replay_cli(path, tmp_path / "out")
    unscored = json.loads((tmp_path / "out" / "status.json").read_text())["unscored"]
    assert [(s["first_seq"], s["last_seq"], s["rows"], s["seconds"], s["reasons"], s["status"])
            for s in unscored["stretches"]] == [
        (0, 2, 3, 15.0, {"full_snapshot": 1, "warmup": 2}, "nevyhodnotené"),
        (7, 10, 4, 20.0, {"invalid_input": 1, "no_predecessor": 1, "warmup": 2}, "nevyhodnotené"),
        (12, 14, 3, 15.0, {"full_snapshot": 1, "warmup": 2}, "nevyhodnotené")]
    assert (unscored["rows"], unscored["seconds"], unscored["share"], unscored["status"]) == (
        10, 50.0, 10 / ROWS, "nevyhodnotené")


@pytest.mark.parametrize("rows,stretches", [
    ([("a", 0, None), ("a", 1, None), ("b", 2, None)], [("a", 0, 1), ("b", 2, 2)]),  # Another session.
    ([("a", 0, None), ("a", 2, None)], [("a", 0, 0), ("a", 2, 2)]),  # A seq gap.
    ([("a", 0, None), ("a", 1, 2.0), ("a", 2, None)], [("a", 0, 0), ("a", 2, 2)]),  # A scored row.
    ([("a", 0, 2.0)], []),
])
def test_a_stretch_is_one_session_with_consecutive_seq(rows, stretches):
    """UNSCORED_RULE on hand-made rows: a stretch ends at a scored row, at another session and at a seq gap; without
    the protocol's interval the seconds are null (named, never a default)."""
    from safeguard.runtime import unscored
    found = unscored([{"session": a, "seq": seq, "score": score, "reason": "warmup"} for a, seq, score in rows], None)
    assert [(s["session"], s["first_seq"], s["last_seq"]) for s in found["stretches"]] == stretches
    assert found["seconds"] is None and all(s["seconds"] is None for s in found["stretches"])


# ------------------------------------------------------------------ the outcomes of the controls (finding S4 of B8)


def control_case(tmp_path, ledger, case):
    """(archive, stage, final_evaluation) of a case of the seal of scripts/controls.py outcomes."""
    from tcn import pecat
    if case == "no_archive":
        return None, "skuska", False
    mode = {"campaign_sealed": "campaign", "rehearsal_sealed": "rehearsal"}.get(case, "campaign")
    index, records = corpus(tmp_path / case, mode, sessions=(("tc-1", "test_controls"),))
    if case in ("campaign_sealed", "rehearsal_sealed", "in_the_run"):
        pecat.zapis_korpus(index, command="campaign", ledger=ledger)
    if case == "in_the_run":
        pecat.spotrebuj(index, out=tmp_path / "final.json", command="final", ledger=ledger)
    return records["tc-1"]["features"], "final" if case.endswith("run") else "skuska" if case != "rehearsal_sealed" \
        else "generalka", case.endswith("run")


@pytest.mark.parametrize("case,allowed", [
    ("campaign_sealed", None), ("no_archive", None), ("outside_the_run", None),
    ("not_sealed", "not_sealed"), ("rehearsal_sealed", "rehearsal"), ("in_the_run", "final_run"),
])
def test_the_outcomes_of_the_controls_follow_the_ledger(tmp_path, ledger, case, allowed):
    """The stage the caller states no longer opens role test_controls (finding S4 of B8): a sealed archive of a
    campaign is refused at stage skuska, a stage before the final one names the archive, final_evaluation=True needs
    the final run of this process; an archive the ledger does not hold is not sealed, a rehearsal's carries its mark
    and the final run's opens."""
    from scripts.controls import outcomes
    from scripts.tests import test_controls_outcomes as tco
    from tcn import pecat
    archive, stage, final = control_case(tmp_path, ledger, case)
    purpose = "scripts/controls.py outcomes of a control of role test_controls"
    try:
        if allowed is None:
            with pytest.raises(ValueError) as error:
                outcomes(tco.occurrence(tco.KIND), tco.session(tco.KIND), tco.protocol(), role="test_controls",
                         archive=archive, stage=stage, final_evaluation=final)
            record = {"id": "tc-1", "role": "test_controls", "features_sha256": archive and sha(archive)}
            assert str(error.value) == {
                "campaign_sealed": sealed_message(purpose, f"the archive {archive}", record, "campaign", ledger),
                "no_archive": "sealed role test_controls: at stage skuska the outcomes name the session's feature "
                              "archive (archive=), so that the ledger (tcn/pecat.py) decides whether it is sealed, "
                              "not the stage the caller states",
                "outside_the_run": "sealed role test_controls: final_evaluation=True is given only by the final "
                                   "command (tcn/pecat.py spotrebuj); no final run is open in this process"}[case]
            return
        out = outcomes(tco.occurrence(tco.KIND), tco.session(tco.KIND), tco.protocol(), role="test_controls",
                       archive=archive, stage=stage, final_evaluation=final)
        assert (out["parser_saw"]["ok"], out["seal"]["allowed"], out["seal"]["rehearsal"]) == (
            True, allowed, case == "rehearsal_sealed")
    finally:
        if pecat.otvoreny() is not None:
            pecat.otvoreny().close()


# ------------------------------------------------------------------ the command line


def test_the_command_line_writes_tells_and_checks(tmp_path, ledger, capsys):
    """python -m tcn.pecat: zapis writes the corpus's seal, stav tells it unconsumed and ready, kontrola refuses its
    sealed archive with exit 3."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus")
    assert pecat.main(["zapis", "--corpus", str(index), "--ledger", str(ledger)]) == 0
    assert json.loads(capsys.readouterr().out)["written"] == sorted(records[i]["features_sha256"] for i, _ in SEALED)
    assert pecat.main(["stav", "--corpus", str(index), "--ledger", str(ledger)]) == 0
    state = json.loads(capsys.readouterr().out)
    assert (state["sessions"], state["in_ledger"], state["consumed"], state["ready"], state["roles"]) == (
        3, 3, False, True, {"test_benign": 2, "test_controls": 1})
    assert pecat.main(["kontrola", "--archive", records["tb-1"]["features"]]) == 3
    assert capsys.readouterr().err == "tcn.pecat: " + sealed_message(
        "python -m tcn.pecat kontrola", f"the archive {records['tb-1']['features']}", records["tb-1"], "campaign",
        ledger) + "\n"


# ------------------------------------------------------------------ the stage of a run (design B7c 5.1 and 5.2)


@pytest.mark.parametrize("mode", ["campaign", "rehearsal"])
def test_a_run_on_another_ledger_is_suchy_and_marked(tmp_path, ledger, mode):
    """STAGE_RULE (design B7c 5.1, question Q15): a final run on a ledger other than the ledger of record has stage
    suchy and the mark of a dry run whatever its plan mode; stav tells it before, the ledger records it, the decisions
    of kontrola inside the run carry it, and so does the decision for a rehearsal's archive outside the run. Its twins
    on the ledger of record are test_the_final_run_replays_its_sealed_archives_once (final) and
    test_a_rehearsal_is_kept_marked_and_not_enforced (generalka)."""
    from tcn import pecat
    index, records = corpus(tmp_path / "corpus", mode)
    if mode == "campaign":
        pecat.zapis_korpus(index, command="campaign", ledger=ledger)
    mark = {"stage": "suchy", "rehearsal": mode == "rehearsal", "mark": pecat.DRY_MARK}
    assert pecat.stav(index, ledger=ledger)["stage"] == "suchy"
    with pecat.spotrebuj(index, out=tmp_path / "dry.json", command="dry run", ledger=ledger) as run:
        assert (run.stage, run.mark, run.record()["mark"]) == ("suchy", mark, mark)
        decision = pecat.kontrola(records["tb-1"]["features"], purpose="test")
        assert (decision["allowed"], decision["stage"], decision["mark"]) == ("final_run", "suchy", pecat.DRY_MARK)
    entry, = json.loads(ledger.read_text())["values"]["runs"]
    assert (entry["stage"], entry["closed"]["outcome"]) == ("suchy", "completed")
    if mode == "rehearsal":
        decision = pecat.kontrola(records["tb-1"]["features"], purpose="test")
        assert (decision["allowed"], decision["stage"], decision["rehearsal"], decision["mark"]) == (
            "rehearsal", "suchy", True, pecat.DRY_MARK)


def test_inside_vlastna_kniha_a_sealed_archive_of_that_ledger_is_refused(tmp_path, ledger):
    """vlastna_kniha (design B7c 5.1): inside the block every guard reads the dry run's own ledger, so a sealed archive
    of its campaign is refused outside the run, as on the ledger of record (the injected error 'a replay of a sealed
    role' of proposal 10.2), and a final run on it has stage suchy; outside the block the process ledger, which does
    not hold it, lets it through, and the block restores it."""
    from tcn import pecat
    own = tmp_path / "own" / "kniha_pecati.json"
    own.parent.mkdir()
    index, records = corpus(tmp_path / "corpus")
    pecat.zapis_korpus(index, command="the dry run's campaign", ledger=own)
    path = Path(records["tb-1"]["features"])
    assert len(replay_runtime(path, None)) == ROWS  # The process ledger does not hold it.
    with pecat.vlastna_kniha(own) as switched:
        assert switched == pecat.KNIHA == own.resolve()
        with pytest.raises(pecat.Zapecatene) as error:
            replay_runtime(path, None)
        assert str(error.value) == sealed_message("safeguard.runtime.replay_archive", f"the archive {path}",
                                                  records["tb-1"], "campaign", own.resolve())
        with pecat.spotrebuj(index, out=tmp_path / "dry.json", command="dry run") as run:
            assert run.stage == "suchy" and len(replay_runtime(path, None)) == ROWS
    assert pecat.KNIHA == ledger and len(replay_runtime(path, None)) == ROWS


@pytest.mark.parametrize("case", ["under_data_results", "a_run_is_open"])
def test_vlastna_kniha_refuses_by_name(tmp_path, ledger, case):
    """vlastna_kniha refuses a ledger under data/results, where the ledger of record is kept, and a switch under an
    open final run; the process ledger stays as it was."""
    from tcn import pecat
    if case == "under_data_results":
        path = ROOT / "data" / "results" / "own_ledger.json"
        with pytest.raises(ValueError) as error:
            with pecat.vlastna_kniha(path):
                pass
        assert str(error.value) == (f"{path}: a ledger of its own lies outside {ROOT / 'data' / 'results'}, where the "
                                    "ledger of record is kept (tcn/pecat.py STAGE_RULE)")
        assert not path.exists() and pecat.KNIHA == ledger
        return
    rehearsal, _ = corpus(tmp_path / "rehearsal", "rehearsal", sessions=(("r-1", "test_benign"),))
    run = pecat.spotrebuj(rehearsal, out=tmp_path / "r.json", command="rehearsal", ledger=ledger)
    try:
        with pytest.raises(ValueError) as error:
            with pecat.vlastna_kniha(tmp_path / "own.json"):
                pass
        assert str(error.value) == (f"a final run is open in this process (seal {run.identity}, run 1): the ledger its "
                                    "guards read is not switched under it (tcn/pecat.py STAGE_RULE)")
    finally:
        run.close()
    assert pecat.KNIHA == ledger


@pytest.mark.parametrize("case", ["not_at_head", "outside_the_repository"])
def test_stage_final_needs_the_ledger_at_head_to_hold_the_seal(sealed, ledger, of_record, tmp_path, monkeypatch,
                                                               case):
    """SEAL_IN_GIT_RULE (design B7c 5.2): at stage final (the ledger of record, plan mode campaign) a run is refused
    when the ledger as committed at HEAD does not hold every sealed archive of the corpus, and when that cannot be
    shown (here the ledger outside the repository: seal_in_git null); stav tells the seal not ready, and nothing is
    written."""
    from tcn import pecat
    index, _ = sealed
    if case == "not_at_head":
        monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: False)
        why = f"the ledger {ledger.resolve()} as committed at HEAD does not hold every sealed archive of the corpus"
    else:
        why = (f"whether the ledger at HEAD holds the seal cannot be shown (the ledger {ledger.resolve()} lies outside "
               f"the repository {ROOT}, or git is unavailable)")
    state = pecat.stav(index, ledger=ledger)
    assert (state["stage"], state["seal_in_git"], state["ready"]) == (
        "final", False if case == "not_at_head" else None, False)
    before = ledger.read_bytes()
    with pytest.raises(pecat.Zapecatene) as error:
        pecat.spotrebuj(index, out=tmp_path / "final.json", command="final", ledger=ledger)
    assert str(error.value) == (f"{index.resolve()}: a final run of stage final is refused: {why}; commit the ledger "
                                "with the campaign's seal before the final run (SEAL_IN_GIT_RULE)")
    assert pecat.otvoreny() is None and ledger.read_bytes() == before


def test_stage_applies_the_stage_rule_to_a_ledger(tmp_path, ledger, of_record):
    """tcn.pecat stage, the public form of STAGE_RULE that tcn.eval's records use (verification of B7c, F4): on the
    ledger of record a campaign is final and a rehearsal generalka; on any other ledger, given or the process's own
    inside vlastna_kniha, the stage is suchy; a plan mode that is none is refused by name."""
    from tcn import pecat
    other = tmp_path / "other" / "kniha_pecati.json"
    assert (pecat.stage("campaign"), pecat.stage("rehearsal"), pecat.stage("campaign", ledger=ledger)) == (
        "final", "generalka", "final")
    assert pecat.stage("campaign", ledger=other) == pecat.stage("rehearsal", ledger=other) == "suchy"
    with pecat.vlastna_kniha(other):
        assert pecat.stage("campaign") == "suchy"
    with pytest.raises(ValueError) as error:
        pecat.stage("generalka")
    assert str(error.value) == "plan mode 'generalka': a stage is that of a plan mode, campaign or rehearsal"


# ----------------------------------------------------------- the stage of a record (finding N2 of B7c, package B9b)


def record_basis(path, **changes):
    """The basis of tcn.pecat record_stage of a record of plan mode campaign over the corpus of `sealed` on the ledger
    of record at `path`, with the values given changed."""
    from tcn import pecat
    return {"rule": pecat.RECORD_STAGE_RULE, "ledger": str(path.resolve()), "of_record": True, "mode": "campaign",
            "sealed": len(SEALED), "missing": [], "seal_in_git": True, "why": None, **changes}


def test_record_stage_is_final_only_when_the_ledger_of_record_and_head_hold_every_sealed_session(
        sealed, of_record, monkeypatch):
    """Finding N2 of the confirmation of B7c (RECORD_STAGE_RULE): a record of plan mode campaign over the sessions of
    a corpus is final when the ledger of record holds the archive of every session of its sealed roles and the ledger
    at HEAD holds them too, whether the sessions are the records of an index (id) or the rows of a campaign's record
    (session); when HEAD does not hold them, or that cannot be shown (here the ledger lies outside the repository),
    the record is suchy and its basis says why."""
    from tcn import pecat
    _, records = sealed
    sessions, real = list(records.values()), pecat._in_git
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: True)
    assert pecat.record_stage("campaign", sessions) == {"stage": "final", "basis": record_basis(of_record)}
    rows = [{"session": r["id"], "vm": r["vm"], "role": r["role"], "state": "accepted",
             "features_sha256": r["features_sha256"]} for r in sessions]
    assert pecat.record_stage("campaign", rows) == {"stage": "final", "basis": record_basis(of_record)}
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: False)
    assert pecat.record_stage("campaign", sessions) == {"stage": "suchy", "basis": record_basis(
        of_record, seal_in_git=False, why=f"the ledger {of_record.resolve()} as committed at HEAD does not hold every "
                                          "archive of the sessions of the sealed roles")}
    monkeypatch.setattr(pecat, "_in_git", real)
    assert pecat.record_stage("campaign", sessions) == {"stage": "suchy", "basis": record_basis(
        of_record, seal_in_git=None, why=f"whether the ledger at HEAD holds them cannot be shown (the ledger "
                                         f"{of_record.resolve()} lies outside the repository {ROOT}, or git is "
                                         "unavailable)")}


def test_record_stage_is_suchy_for_a_corpus_whose_seal_the_ledger_of_record_does_not_hold(tmp_path, of_record,
                                                                                         monkeypatch):
    """Finding N2 (the risk of question Q15): a synthetic campaign corpus whose archives the ledger of record does
    not hold is suchy, never final, and so is one whose archives it holds for another plan mode; a rehearsal on the
    ledger of record is generalka without a ledger at HEAD; a record without a session of a sealed role is suchy, and
    so is every record on a ledger other than the ledger of record."""
    from tcn import pecat
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: True)
    _, records = corpus(tmp_path / "corpus")
    sessions = list(records.values())
    ids = [ident for ident, _ in SEALED]
    assert pecat.record_stage("campaign", sessions) == {"stage": "suchy", "basis": record_basis(
        of_record, missing=ids, seal_in_git=None,
        why="the ledger of record holds no archive of 3 of the 3 sessions of the sealed roles for their session, "
            "role and plan mode campaign (first tb-1): their seal is not the campaign's")}
    pecat.zapis(sessions, protocol=protocol(), protocol_sha256=sha(V5), mode="rehearsal", command="rehearsal",
                ledger=of_record)
    assert pecat.record_stage("rehearsal", sessions) == {"stage": "generalka", "basis": record_basis(
        of_record, mode="rehearsal", seal_in_git=None)}
    assert pecat.record_stage("campaign", sessions)["basis"]["missing"] == ids
    assert pecat.record_stage("campaign", [records[UNSEALED[0]]]) == {"stage": "suchy", "basis": record_basis(
        of_record, sealed=0, missing=None, seal_in_git=None,
        why="the record covers no session of the sealed roles test_benign, test_controls: the ledger of record "
            "cannot tie it to the seal of a plan")}
    rows = [{"session": "tb-1", "role": "test_benign"}, {"session": "tb-2", "role": "test_benign",
                                                         "features_sha256": records["tb-2"]["features_sha256"]}]
    assert pecat.record_stage("rehearsal", rows) == {"stage": "suchy", "basis": record_basis(
        of_record, mode="rehearsal", sealed=2, missing=["tb-1"], seal_in_git=None,
        why="1 of the 2 sessions of the sealed roles name no sha256 of their feature archive (first tb-1): their "
            "seal cannot be shown")}
    other = tmp_path / "other" / "kniha_pecati.json"
    assert pecat.record_stage("rehearsal", sessions, ledger=other) == {"stage": "suchy", "basis": record_basis(
        of_record, ledger=str(other.resolve()), of_record=False, mode="rehearsal", missing=None, seal_in_git=None,
        why=f"the ledger {other.resolve()} is not the ledger of record {of_record.resolve()} (a G1 dry run or a "
            "test)")}


def test_record_stage_of_an_ending_record_does_not_ask_the_ledger_at_head(tmp_path, sealed, of_record, monkeypatch):
    """Question Q21 (package B9b, accepted by the lead 2026-11-24): the ending record of a campaign
    passes at_head False, since its runner writes it before the ledger is committed. A record of plan mode campaign
    is then final when the ledger of record in the working tree holds the archive of every session of the sealed
    roles, the ledger at HEAD never asked; its basis says so and names the ledger's sha256 and that tcn.finalne checks
    the ledger at HEAD. A missing seal and another ledger stay suchy as before, and the default (the records of
    tcn.eval) keeps the whole rule of N2."""
    from tcn import pecat
    _, records = sealed
    sessions = list(records.values())
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: pytest.fail("at_head False asks no ledger at HEAD"))
    assert pecat.record_stage("campaign", sessions, at_head=False) == {"stage": "final", "basis": record_basis(
        of_record, seal_in_git=None, at_head=False, ledger_sha256=sha(of_record), head=pecat.HEAD_BY_FINALNE)}
    other = dict(sessions[0], features_sha256="0" * 64)
    missing = pecat.record_stage("campaign", [other, *sessions[1:]], at_head=False)
    assert (missing["stage"], missing["basis"]["missing"]) == ("suchy", [other["id"]]), missing
    elsewhere = pecat.record_stage("campaign", sessions, ledger=tmp_path / "other" / "kniha_pecati.json",
                                   at_head=False)
    assert elsewhere["stage"] == "suchy" and "is not the ledger of record" in elsewhere["basis"]["why"]
    monkeypatch.setattr(pecat, "_in_git", lambda path, hashes: False)
    assert pecat.record_stage("campaign", sessions)["stage"] == "suchy"


@pytest.mark.parametrize("mode, sessions, message", [
    ("generalka", [], "plan mode 'generalka': a stage is that of a plan mode, campaign or rehearsal"),
    ("campaign", "tb-1", "the sessions of a record are a list (index records, or the rows of a campaign's record)"),
    ("campaign", [{"id": "tb-1"}], "a session of a record names its id (id, or session in the row of a campaign's "
                                   "record) and its role"),
], ids=["no_plan_mode", "no_list", "no_role"])
def test_record_stage_refuses_what_it_cannot_judge(mode, sessions, message, ledger):
    from tcn import pecat
    with pytest.raises(ValueError) as error:
        pecat.record_stage(mode, sessions)
    assert str(error.value) == message


# ------------------------------------------------------------------ the legacy tools (verification of B7c, F1)


def test_the_activity_classifier_refuses_a_sealed_archive(sealed, ledger):
    """tcn/klasifikator.py, the legacy activity classifier (VO6), loads and scores the archives of an index; its train
    and its evaluation load every archive through _frames, which asks the seal first (GUARD_RULE): a sealed archive of
    a campaign is refused by name before it is opened."""
    from tcn import klasifikator, pecat
    _, records = sealed
    record = records["tb-1"]
    with pytest.raises(pecat.Zapecatene) as error:
        klasifikator._frames(record)
    assert str(error.value) == sealed_message("tcn.klasifikator", f"the archive {record['features']}", record,
                                              "campaign", ledger)


def test_the_legacy_detector_refuses_the_snapshots_of_a_sealed_session(sealed, ledger, tmp_path, capsys):
    """scripts/detektor.py, the standalone detector of iteration 1 over --snapshots, checks the directory by the seal
    before it reads the model or a snapshot (SNAPSHOT_RULE): the snapshots of a session the ledger seals for a
    campaign are refused by name with exit 2, and no output is written."""
    from scripts import detektor
    _, records = sealed
    _, raw = session_directory(tmp_path / "sessions", "tb-1")
    out = tmp_path / "out.jsonl"
    assert detektor.main(["--snapshots", str(raw), "--profile", "unused", "--model", str(tmp_path / "no-model"),
                          "--prah", "1", "--out", str(out)]) == 2
    assert capsys.readouterr().err == "scripts/detektor.py: " + sealed_message(
        "scripts/detektor.py", f"the snapshot directory {raw.resolve()} of session tb-1", records["tb-1"], "campaign",
        ledger) + "\n"
    assert not out.exists()
