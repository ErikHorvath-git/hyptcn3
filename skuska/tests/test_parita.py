"""The live/archive parity of G2 (skuska/parita.py, package H1b5), with fakes of every lab, root and training step.

No test touches a VM, runs as root, trains a model, runs safeguard watch or replay for real, or writes outside
tmp_path (checked after every test for data/results, data/diagnostics, data/collections and docs/MERANIA.md).
"""
import hashlib
import inspect
import time
from pathlib import Path

import pytest

from skuska import parita

ROOT = Path(__file__).resolve().parents[2]
WATCHED = [ROOT / "data/results", ROOT / "data/diagnostics", ROOT / "data/collections"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def listing(path):
    return sorted(str(p.relative_to(path)) for p in path.rglob("*")) if path.exists() else None


@pytest.fixture(autouse=True)
def _repository_unchanged():
    """No test leaves a file in data/results, data/diagnostics or data/collections, or changes docs/MERANIA.md."""
    before = {path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")
    yield
    assert ({path: listing(path) for path in WATCHED}, sha(ROOT / "docs/MERANIA.md")) == before


# ------------------------------------------------------------------ the tolerance (Q45)

def test_the_tolerance_follows_q45_from_the_precision_of_the_code():
    """Q45: float64 and the same batch 1e-9, float32 or another batch 1e-5. The code the rule was read from is the
    code here (PRECISION_SOURCES); Bundle.score casts its window to float32 and makes a batch of one, the models are
    float32, and both paths give every frame to Detector.process, which scores at most one window per frame."""
    import torch
    from safeguard import bundle, model, runtime, cli
    assert {name: sha(ROOT / name) for name in parita.PRECISION_SOURCES} == parita.PRECISION_SOURCES
    score = inspect.getsource(bundle.Bundle.score)
    assert score.count("dtype=torch.float32") == 2 and ".unsqueeze(0)" in score and "float64" not in score
    for module in (bundle, model, runtime):
        assert "set_default_dtype" not in inspect.getsource(module) and ".double()" not in inspect.getsource(module)
    config = model.architecture(32, global_features=4)
    assert {p.dtype for net in (model.Predictor(config), model.Classifier(config, 2)) for p in net.parameters()} == {
        torch.float32}
    process = inspect.getsource(runtime.Detector.process)
    assert process.count("self.bundle.score(window)") == 1
    assert "detector.process(frame)" in inspect.getsource(runtime.replay_archive)
    assert "detector.process(frame)" in inspect.getsource(runtime.run_directory)
    assert "replay_archive(bundle, archive)" in inspect.getsource(cli.replay_directory)
    assert "torch.set_num_threads(a.threads)" in inspect.getsource(cli.execute)
    assert (parita.NETWORK_DTYPE, parita.BATCH, parita.THREADS) == ("float32", {"watch": 1, "replay": 1}, 1)
    assert parita.tolerance("float32", True) == parita.tolerance("float64", False) == 1e-5
    assert parita.tolerance("float64", True) == 1e-9
    assert parita.SCORE_REL_TOL == parita.tolerance(parita.NETWORK_DTYPE, len(set(parita.BATCH.values())) == 1)
    assert parita.SCORE_ABS_TOL == 0.0
    with pytest.raises(ValueError, match="Q45 names float32 and float64"):
        parita.tolerance("bfloat16", True)


@pytest.mark.parametrize("live, replay, agrees", [
    (2.0, 2.0, True), (2.0, 2.0 * (1 + 9e-6), True), (2.0, 2.0 * (1 + 1.1e-5), False), (0.0, 0.0, True),
    (0.0, 1e-300, False), (-3.0, -3.0 * (1 - 9e-6), True)])
def test_a_score_agrees_within_the_relative_tolerance_and_abs_tol_0(live, replay, agrees):
    assert parita.score_agrees(live, replay) is agrees


# ------------------------------------------------------------------ the bundle (Q61)

import json  # noqa: E402
import shutil  # noqa: E402

import numpy as np  # noqa: E402

from scripts import collection, gates  # noqa: E402
from skuska import g2  # noqa: E402

# The layout of the hyptcn-lab VMs as an audit records it (a tracked audit record of a pilot session, read only):
# 130 bins, 128 of 4096 pages, one of 1 page and one of 64 pages.
PILOT = ROOT / "data/results/collection_pilot_7_20261026_audit.json"
LAYOUT = json.loads(PILOT.read_text())["values"]["layout"]
BINY = [entry[0] for entry in LAYOUT["bins"]]
LEDGER = ROOT / "data/results/kniha_pecati.json"


def other_layout():
    """A VM with one region of 1 GiB: 64 bins of 4096 pages."""
    return {"bin_bytes": 16777216, "page_size": 4096, "bins": [[b, 4096] for b in range(64)],
            "regions": [{"gpa": 0, "bytes": 1 << 30}], "memsize": 1 << 30, "vcpus": 2}


def g2_audit(root, vm, protocol, layout=LAYOUT, *, role="diagnostic", campaign="g2", biny=None, edit=None):
    """The audit record of a real G2 session of VM `vm` as scripts/collection.py audit_session leaves it, as far as
    read_audit reads it: session.json and protocol.json of the session, the record and its feature archive."""
    d = Path(root) / f"g2-{vm}-e0{1 if vm == 'a' else 2}-1"
    d.mkdir(parents=True)
    shutil.copyfile(protocol, d / "protocol.json")
    (d / "session.json").write_text(json.dumps({"session_id": d.name, "vm": vm, "role": role, "campaign_id": campaign}))
    npz = d / "audit_20261127T000000000000Z.npz"
    np.savez_compressed(npz, biny=np.array([e[0] for e in layout["bins"]] if biny is None else biny, dtype=np.int64),
                        layout_json=json.dumps(layout, sort_keys=True))
    values = {"session_dir": str(d), "session_sha256": sha(d / "session.json"), "features": str(npz),
              "features_sha256": sha(npz), "layout": layout, "protocol_sha256": sha(d / "protocol.json")}
    if edit:
        edit(values)
    path = npz.with_suffix(".json")
    path.write_text(json.dumps({"schema": "hyptcn3/collection-audit/1", "values": values}))
    return path


def test_relayout_deals_the_generators_bins_over_the_layout_of_the_audit():
    """LAYOUT_RULE: bin j of the layout takes the generator's bin j mod 4, changed_ratio in whole pages of its bin and
    at least one page, zero_ratio and entropy_mean as drawn, has_changed 1; biny and layout the audit's; every row is
    a valid frame of that layout."""
    from features.snapshot import MENA
    from safeguard.features import Frame
    rng = np.random.default_rng(3)
    drawn = np.stack([np.rint(rng.uniform(0.01, 0.3, (5, 4)) * 4096) / 4096, rng.uniform(0.1, 0.9, (5, 4)),
                      rng.uniform(1, 7, (5, 4)), np.ones((5, 4))], axis=-1)
    drawn[0, 1, 0] = 1 / 4096  # One page of a full bin: in a bin of 64 pages still one page.
    result = {"perbin": drawn.tolist(), "biny": [0, 1, 2, 3], "layout": {"bins": [[b, 4096] for b in range(4)]},
              "matica": [[0.0]], "quality": ["q"]}
    out = parita.relayout(result, LAYOUT, BINY)
    perbin = np.asarray(out["perbin"])
    assert perbin.shape == (5, 130, 4) and out["biny"] == BINY and out["layout"] == LAYOUT
    assert (out["matica"], out["quality"]) == (result["matica"], result["quality"]) and result["biny"] == [0, 1, 2, 3]
    pages = np.array([p for _, p in LAYOUT["bins"]])
    for j in (0, 1, 5, 127, 128, 129):
        assert np.array_equal(perbin[:, j, 1:3], drawn[:, j % 4, 1:3]) and (perbin[:, j, 3] == 1).all()
        changed = perbin[:, j, 0] * pages[j]
        assert np.allclose(changed, np.rint(changed)) and (changed >= 1).all()
    assert perbin[0, 129, 0] == 1 / 64 and (perbin[:, 128, 0] == 1.0).all()  # The bins of 64 pages and of 1 page.
    assert np.allclose(perbin[:, 0, 0], drawn[:, 0, 0])
    quality = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "inconclusive": [],
               "findings": [], "read_errors": 0, "filled_zero": 0}
    for row in perbin:
        Frame("s", 1, 1.0, np.zeros(len(MENA)), row, tuple(BINY), quality, "c", LAYOUT)
    with pytest.raises(ValueError, match="not biny in order"):
        parita.relayout(result, LAYOUT, BINY[::-1])


def test_read_audit_takes_the_layout_of_a_g2_session_and_refuses_what_is_none(tmp_path):
    """read_audit: the layout and the bins of the audit of a G2 session; refused by name: no audit record, a session
    that is no G2 session, a feature archive that differs from its sha256 or holds another layout or other bins."""
    protocol = ROOT / "config/collection-v5.json"
    found = parita.read_audit(g2_audit(tmp_path / "ok", "a", protocol))
    assert (found["vm"], found["session_id"], found["layout"], found["biny"]) == ("a", "g2-a-e01-1", LAYOUT, BINY)
    assert found["min_bin_pages"] == 1024 and found["layout_sha256"] == parita._canonical(
        {"layout": LAYOUT, "biny": BINY})
    cases = {"pilot": dict(role="pilot"), "campaign": dict(campaign="normal"),
             "bins": dict(biny=BINY[::-1]),
             "sha": dict(edit=lambda v: v.update(features_sha256="0" * 64)),
             "layout": dict(edit=lambda v: v.update(layout=other_layout()))}
    expected = {"pilot": "is no audit of a G2 session", "campaign": "is no audit of a G2 session",
                "bins": "not the bins of the layout in order", "sha": "missing or differs from values.features_sha256",
                "layout": "differs from values.layout"}
    for name, options in cases.items():
        with pytest.raises(parita.Refused, match=expected[name]):
            parita.read_audit(g2_audit(tmp_path / name, "a", protocol, **options))
    (tmp_path / "x.json").write_text(json.dumps({"schema": "other"}))
    with pytest.raises(parita.Refused, match="is no audit record"):
        parita.read_audit(tmp_path / "x.json")


def safeguard_args(argv):
    """The arguments safeguard's own parser makes of a command line (its prefix up to python -m safeguard dropped)."""
    from safeguard import cli
    argv = [str(x) for x in argv]
    i = next(i for i, (a, b) in enumerate(zip(argv, argv[1:])) if a == "-m" and b == "safeguard")
    return cli.parser().parse_args(argv[i + 2:]), argv[:i - 1]


class FakeTrainer:
    """The training's child without a training: it parses the command line with safeguard's parser and writes a bundle
    whose feature contract is that of the first train session of the corpus (safeguard/training.py: from its first
    frame), so a corpus in another layout gives a bundle in it; `layout` overrides the contract."""

    def __init__(self, layout=None, code=0, diagnostic=True):
        self.layout, self.code, self.diagnostic, self.calls = layout, code, diagnostic, []

    def __call__(self, argv, log, timeout):
        from safeguard.features import feature_contract, frames_from_archive
        a, prefix = safeguard_args(argv)
        self.calls.append((a, prefix, timeout))
        index = json.loads(a.corpus.read_text())
        protocol = index["protocol_config"]
        if index.get("fake"):  # The corpus of fake_chain: its layout as it names it.
            contract = {"layout": index["layout"], "biny": index["biny"]}
        else:
            first = next(r for r in index["sessions"] if r["role"] == "train")
            with np.load(parita._resolved(a.corpus.parent, first["features"]), allow_pickle=False) as data:
                frame = frames_from_archive(data, first["id"])[0]
            contract = feature_contract(frame, protocol["window_rows"], protocol["max_gap_s"])
        if self.layout is not None:
            contract["layout"] = self.layout
        Path(log).write_text("the fake training\n")
        if self.code == 0:
            a.out.mkdir(parents=True)
            (a.out / "predictor.pt").write_bytes(b"p")
            (a.out / "classifier.pt").write_bytes(b"c")
            (a.out / "manifest.json").write_text(json.dumps({
                "schema": "hyptcn3/safeguard-bundle/1", "diagnostic": a.diagnostic and self.diagnostic,
                "feature_contract": contract,
                "normalizer": {"rule": {"name": "analysis", "min_bin_pages": protocol["analysis"]["scale"][
                    "min_bin_pages"]}}, "calibration": {"threshold": 0.5, "k": 3, "n": 5},
                "rule_channel": {"columns": ["mod_total"]},
                "parameters": {"overrides": {} if a.epochs is None else {"epochs": {"applied": a.epochs}},
                               "stopping": {"max_epochs": a.epochs}},
                "provenance": {"corpus_index_sha256": sha(a.corpus)}}))
        return self.code


def quiet():
    return iter([(1, [b"/usr/bin/bash"])])


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    """The small protocol of the dry run (scripts/tests/test_suchy_beh.py) with the test's record of G0, and the audits
    of a G2 session of each VM in the layout of the hyptcn-lab VMs."""
    from scripts.tests.test_suchy_beh import maly_protokol, zaznam_g0
    root = tmp_path_factory.mktemp("parita")
    protocol = maly_protokol(root)
    results = root / "vysledky"
    results.mkdir()
    zaznam_g0(results, protocol)
    audits = [g2_audit(root / "g2", vm, protocol) for vm in ("a", "b")]
    return {"root": root, "protocol": protocol, "results": results, "audits": audits}


@pytest.fixture(scope="module")
def made(small):
    """python -m skuska.parita zvazok on the small protocol: the real chain of G1 up to its corpus, a fake trainer."""
    trainer = FakeTrainer()
    before = sha(LEDGER)
    started = time.monotonic()
    doc = parita.make_bundles(small["protocol"], small["audits"], small["root"] / "praca", small["root"] / "out", 2,
                              vysledky=small["results"], command="python -m skuska.parita zvazok ...", run=trainer,
                              processes=quiet, tmpfs=True)
    return {"doc": doc, "trainer": trainer, "seconds": time.monotonic() - started, "ledger": before}


def test_the_bundle_of_the_real_chain_holds_the_layout_of_the_audits(small, made):
    """BUNDLE_RULE on the small protocol: one layout for both VMs gives one bundle; the chain of G1 ran its steps 1 to
    5 and every session of its corpus was audited in the layout of the audits (its archives hold their biny, layout
    and 130 bins of perbin); the training is the real command line of safeguard train --diagnostic with --epochs 2 at
    2 threads, nice 19; the record carries check E's header, the sha256 of every file of the bundle and of their list,
    the VMs it serves and the seconds of the chain and the training; the ledger of record is untouched."""
    from safeguard.features import feature_contract, frames_from_archive
    doc = made["doc"]
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc) and doc["n"] == 1
    v = doc["values"]
    assert (doc["schema"], v["stage"], v["g2_values"], v["epochs"]) == (parita.BUNDLE_SCHEMA, "G2", False, 2)
    assert v["vms"] == {"a": "zvazok_a_b", "b": "zvazok_a_b"} and [a["vm"] for a in v["audits"]] == ["a", "b"]
    (bundle,) = v["bundles"]
    target = Path(bundle["dir"])
    assert target == small["root"] / "out" / "zvazok_a_b" and bundle["vms"] == ["a", "b"]
    assert bundle["files"] == parita.bundle_files(target) and bundle["sha256"] == parita._canonical(bundle["files"])
    assert bundle["manifest_sha256"] == sha(target / "manifest.json") and bundle["diagnostic"] is True
    assert [s["step"] for s in bundle["chain"]["steps"]] == [
        "1 protokol a stupne", "2 pracovna kopia bez masky", "3 kvalifikacny prechod", "4 pracovna kopia",
        "5 generalka a kampan"] and not any("error" in s for s in bundle["chain"]["steps"])
    index = Path(bundle["corpus"]["index"])
    assert bundle["corpus"]["index_sha256"] == sha(index) and bundle["corpus"]["sessions"] >= 5
    records = json.loads(index.read_text())["sessions"]
    for record in records:
        with np.load(parita._resolved(index.parent, record["features"]), allow_pickle=False) as data:
            assert [int(b) for b in data["biny"]] == BINY and json.loads(str(data["layout_json"])) == LAYOUT
            assert data["perbin"].shape[1:] == (130, 4)
            frames = frames_from_archive(data, record["id"])
        contract = feature_contract(frames[1], 8, 7.5)
        assert (contract["layout"], contract["biny"]) == (LAYOUT, BINY)
    (a, prefix, timeout), = made["trainer"].calls
    assert (a.command, a.threads, a.diagnostic, a.epochs, a.corpus, a.out) == (
        "train", 2, True, 2, index, target)
    assert prefix[:3] == ["nice", "-n", "19"] and timeout == parita.TRAIN_TIMEOUT_S
    assert bundle["training"]["exit_code"] == 0 and Path(bundle["training"]["log"]).is_file()
    assert set(bundle["seconds"]) == {"chain", "training"} and v["praca_bytes"] > 0
    assert sha(LEDGER) == made["ledger"]
    assert json.loads((small["root"] / "out" / parita.BUNDLE_RECORD).read_text()) == doc
    print(f"the chain of the small protocol: {bundle['seconds']['chain']} s, {bundle['corpus']['sessions']} "
          f"sessions in the corpus, {bundle['chain']['captures']} captures, --praca {v['praca_bytes']} bytes")


class FakeChain:
    """The chain of G1 without the harness: a corpus index that names the layout it was asked for."""

    def __init__(self):
        self.calls = []

    def __call__(self, protocol, work, vysledky, layout, biny, command):
        self.calls.append({"work": Path(work), "layout": layout, "biny": biny})
        Path(work).mkdir(parents=True)
        index = Path(work) / "corpus.json"
        p = json.loads(Path(protocol).read_text())
        index.write_text(json.dumps({"fake": True, "layout": layout, "biny": biny, "protocol_config": p,
                                     "sessions": []}))
        return {"index": str(index), "index_sha256": sha(index), "sessions": 0, "roles": {}, "steps": [],
                "generator": "nulovy", "seed": 0, "path": "skratena"}


def bundles(tmp_path, audits, *, chain=None, run=None, processes=quiet, epochs=2, tmpfs=True, out="out",
            praca="praca"):
    chain = chain or FakeChain()
    doc = parita.make_bundles(ROOT / "config/collection-v5.json", audits, tmp_path / praca, tmp_path / out, epochs,
                              vysledky=tmp_path, command="python -m skuska.parita zvazok", chain=chain,
                              run=run or FakeTrainer(), processes=processes, tmpfs=tmpfs)
    return doc, chain


def test_vms_of_two_layouts_get_a_bundle_each(tmp_path):
    """Q61: per VM where the layout differs: one chain and one training per layout, each bundle names its VMs."""
    protocol = ROOT / "config/collection-v5.json"
    audits = [g2_audit(tmp_path / "s", "a", protocol), g2_audit(tmp_path / "s", "b", protocol, other_layout())]
    doc, chain = bundles(tmp_path, audits)
    v = doc["values"]
    assert v["vms"] == {"a": "zvazok_a", "b": "zvazok_b"} and doc["n"] == 2
    assert [c["layout"] for c in chain.calls] == [LAYOUT, other_layout()]
    assert [c["work"] for c in chain.calls] == [tmp_path / "praca" / "zvazok_a", tmp_path / "praca" / "zvazok_b"]
    assert [b["vms"] for b in v["bundles"]] == [["a"], ["b"]] and len(v["layouts"]) == 2
    assert v["protocol_g0_binding"] == gates.stage_sha256(protocol, "G0")


def test_the_bundle_command_refuses_by_name_before_anything_is_made(tmp_path):
    """BUNDLE_RULE: an --out that exists, a --praca inside --out, a --praca on a tmpfs, --epochs 0, two audits of one
    VM, a VM the protocol has not, a session protocol with another min_bin_pages, a host that is not quiet; nothing is
    made."""
    protocol = ROOT / "config/collection-v5.json"
    a = g2_audit(tmp_path / "s", "a", protocol)
    (tmp_path / "exists").mkdir()
    with pytest.raises(parita.Refused, match="--out .* exists"):
        bundles(tmp_path, [a], out="exists")
    with pytest.raises(parita.Refused, match="neither inside the other"):
        bundles(tmp_path, [a], praca="out/praca")
    with pytest.raises(parita.Refused, match="lies on a tmpfs"):
        bundles(tmp_path, [a], tmpfs=False)
    with pytest.raises(parita.Refused, match="--epochs 0"):
        bundles(tmp_path, [a], epochs=0)
    second = g2_audit(tmp_path / "t", "a", protocol)
    with pytest.raises(parita.Refused, match="two audits of VM a"):
        bundles(tmp_path, [a, second])
    c = g2_audit(tmp_path / "u", "c", protocol)
    with pytest.raises(parita.Refused, match="VM c is no VM of the protocol"):
        bundles(tmp_path, [c])
    d = g2_audit(tmp_path / "v", "b", protocol)
    session_protocol = Path(json.loads(d.read_text())["values"]["session_dir"]) / "protocol.json"
    doc = json.loads(session_protocol.read_text())
    doc["analysis"]["scale"]["min_bin_pages"] = 1
    session_protocol.write_text(json.dumps(doc))
    with pytest.raises(parita.Refused, match="another analysis.scale.min_bin_pages"):
        bundles(tmp_path, [d])

    def busy_host():
        return iter([(5, [b"/opt/vmicollect", b"vm.domain=hyptcn-lab-a"]),
                     (6, [b"/x/python", b"scripts/collection.py", b"--protocol", b"P", b"run", b"--vm", b"b"]),
                     (7, [b"/x/python", b"-m", b"skuska.poruchy", b"block", b"--vm", b"a"]),
                     (8, [b"grep", b"collection.py run"])])
    with pytest.raises(parita.Refused) as refused:
        bundles(tmp_path, [a], processes=busy_host)
    assert ("collector of hyptcn-lab-a (PID 5)" in str(refused.value)
            and "collection.py run (PID 6)" in str(refused.value) and "a block of G2 (PID 7)" in str(refused.value)
            and "PID 8" not in str(refused.value))
    assert not (tmp_path / "out").exists() and not (tmp_path / "praca").exists()


def test_a_failed_or_foreign_training_and_a_host_busy_before_it_are_refused(tmp_path):
    """BUNDLE_RULE: the host is checked again before the training; a training that fails or gives a bundle that is
    not diagnostic or holds another layout is refused by name, and no record is written."""
    protocol = ROOT / "config/collection-v5.json"
    a = g2_audit(tmp_path / "s", "a", protocol)
    calls = []

    def busy_later():
        calls.append(1)
        return iter([] if len(calls) == 1 else [(9, [b"/x/python", b"scripts/lab_trial.py", b"long", b"--vm", b"a"])])
    with pytest.raises(parita.Refused, match=r"the training does not start, .*lab_trial.py on a VM \(PID 9\)"):
        bundles(tmp_path, [a], processes=busy_later, out="o1", praca="p1")
    for n, (trainer, why) in enumerate([(FakeTrainer(code=1), "ended with exit 1 and no bundle"),
                                        (FakeTrainer(layout=other_layout()), "holds another layout than its audits"),
                                        (FakeTrainer(diagnostic=False), "it is not diagnostic")]):
        with pytest.raises(parita.Refused, match=why):
            bundles(tmp_path, [a], run=trainer, out=f"o{n + 2}", praca=f"p{n + 2}")
        assert not (tmp_path / f"o{n + 2}" / parita.BUNDLE_RECORD).exists()


def test_the_command_line_of_the_bundle(tmp_path, monkeypatch, capsys):
    """python -m skuska.parita zvazok: --epochs N or plan, every option required but --vysledky; a refusal exits 2."""
    seen = {}
    monkeypatch.setattr(parita, "make_bundles", lambda *args, **kwargs: seen.update(args=args, kwargs=kwargs) or {
        "values": {"vms": {"a": "zvazok_a"}, "bundles": []}})
    argv = ["zvazok", "--protocol", "P", "--audit", "A1", "--audit", "A2", "--praca", str(tmp_path / "w"), "--out",
            str(tmp_path / "o"), "--epochs", "plan"]
    assert parita.main(argv) == 0
    assert seen["args"][1:] == ([Path("A1"), Path("A2")], tmp_path / "w", tmp_path / "o", "plan")
    assert seen["kwargs"]["vysledky"] == ROOT / "data/results" and seen["kwargs"]["command"].startswith(
        "python -m skuska.parita zvazok --protocol P")
    assert parita.main([*argv[:-1], "3"]) == 0 and seen["args"][4] == 3
    with pytest.raises(SystemExit):
        parita.main([*argv[:-1], "0"])
    monkeypatch.setattr(parita, "make_bundles", lambda *a, **k: (_ for _ in ()).throw(parita.Refused("no")))
    assert parita.main(argv) == 2 and "skuska.parita: Refused: no" in capsys.readouterr().err
