"""The live/archive parity of G2 (skuska/parita.py, package H1b5), with fakes of every lab, root and training step.

No test touches a VM, runs as root, trains a model, runs safeguard watch or replay for real, or writes outside
tmp_path (checked after every test for data/results, data/diagnostics, data/collections and docs/MERANIA.md).
"""
import contextlib
import hashlib
import inspect
import io
import json
from pathlib import Path
import shutil
import threading
import time

import numpy as np
import pytest

from scripts import collection, gates, protocol_v5
from skuska import g2, parita
from skuska.tests.test_g2 import FakeLab

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


# ------------------------------------------------------------------ the parity sessions, watch beside them, the block

REAL = ROOT / "config/collection-v5.json"  # The protocol with the rates of Zápis 1, as the blocks of G2 read it.
P = collection.protocol(REAL)


def parity_rows(n=6):
    """The rows of one path: warming up, then scored with the rule channel's alarm up from seq 3, its hold failed."""
    out = []
    for seq in range(n):
        alarm = seq >= 3
        out.append({"seq": seq, "score": 0.5 + seq if seq >= 2 else None,
                    "model_state": "monitoring" if seq >= 2 else "warming_up",
                    "reason": "scored" if seq >= 2 else "warming_up", "alarm": alarm, "alarm_event": seq == 3,
                    "alarm_sources": ["rule_anomaly"] if seq == 3 else [], "model_alarm": False, "rule_alarm": alarm,
                    "integrity_alarm": False, "channel": ["rule"] if alarm else [],
                    "evidence": {"status": "error" if alarm else "not_requested"}, "snapshot_age_ms": 800.0})
    return out


def write_output(directory, configuration, rows, status):
    directory.mkdir(parents=True)
    (directory / "configuration.json").write_text(json.dumps(configuration))
    (directory / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (directory / "status.json").write_text(json.dumps(status))


class FakeWatchProcess:
    """safeguard watch without a model: at its end it writes the output run_directory writes, with `rows`."""

    def __init__(self, a, rows, forever):
        self.a, self.rows, self.forever, self.stop, self.pid = a, rows, forever, threading.Event(), 4321

    def wait(self, timeout=None):
        if self.forever:
            self.stop.wait(30)
        manifest = json.loads((self.a.bundle / "manifest.json").read_text())
        write_output(self.a.out, {"bundle_manifest": manifest, "snapshots": str(self.a.snapshots.resolve()),
                                  "profile": str(self.a.profile.resolve()), "follow": True, "preserve": True,
                                  "idle_timeout": self.a.idle_timeout}, self.rows,
                     {"stop_reason": "stop_requested" if self.forever else "idle_timeout",
                      "processed": len(self.rows), "evidence_errors": 3, "ok": False})
        return -15 if self.forever else 2


class FakeEnv:
    """The hook's host without a process: start() parses the command line with safeguard's parser and records whether
    raw/ and profile/ of the session existed when watch started."""

    def __init__(self, rows=None, forever=False):
        self.rows, self.forever, self.started, self.calls, self.ended = rows, forever, threading.Event(), [], []

    def now(self):
        return time.time()

    def wait(self, event, seconds):
        return event.wait(seconds)

    def start(self, command, log):
        a, prefix = safeguard_args(command)
        self.calls.append({"args": a, "prefix": prefix, "raw": a.snapshots.is_dir(), "profile": a.profile.is_dir(),
                           "command": command})
        Path(log).write_text("watch\n")
        self.process = FakeWatchProcess(a, parity_rows() if self.rows is None else self.rows, self.forever)
        self.started.set()
        return self.process

    def end(self, process, grace):
        self.ended.append((process, grace))
        process.stop.set()
        return -15


class ParityLab(FakeLab):
    """FakeLab whose run makes profile/ before raw/ (as scripts/collection.py run does) and lasts until watch beside
    it started; the replay writes the output replay_directory writes, and the comparison is the real mode of
    scripts/campaign_report.py in this process."""

    def __init__(self, protocol_path, *, replay_rows=None, run_wait=5, **options):
        super().__init__(protocol_path, **options)
        self.replay_rows, self.replays, self.comparisons, self.env = replay_rows, [], [], None
        self.run_wait = run_wait

    def child(self, command, log, *, timeout, lock_fd=None):
        command = [str(x) for x in command]
        if "safeguard" in command and "replay" in command:
            a, prefix = safeguard_args(command)
            self.events.append(("replay", a.archive.name))
            self.replays.append((a, prefix, timeout))
            manifest = json.loads((a.bundle / "manifest.json").read_text())
            write_output(a.out, {"bundle_manifest": manifest, "archive": str(a.archive),
                                 "archive_sha256": sha(a.archive), "follow": False, "preserve": False},
                         parity_rows() if self.replay_rows is None else self.replay_rows,
                         {"stop_reason": "replay_complete"})
            log.write_text("replay\n")
            return 0
        if any(Path(x).name == "campaign_report.py" for x in command):
            from scripts import campaign_report
            i = next(i for i, x in enumerate(command) if Path(x).name == "campaign_report.py")
            self.events.append(("parity",))
            self.comparisons.append(command)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = campaign_report.main(command[i + 1:])
            log.write_text(out.getvalue() + err.getvalue())
            return code
        if "--session-id" in command:
            sid = command[command.index("--session-id") + 1]
            if sid not in self.no_directory:
                (Path(command[command.index("--collections-dir") + 1]) / sid / "profile").mkdir(parents=True)
            code = super().child(command, log, timeout=timeout, lock_fd=lock_fd)
            self.env.started.wait(self.run_wait)  # The run lasts until watch beside it started (or run_wait s).
            return code
        return super().child(command, log, timeout=timeout, lock_fd=lock_fd)


def fake_bundle(root, vms=("a", "b")):
    """A bundle directory without weights and its record as python -m skuska.parita zvazok writes it."""
    d = Path(root) / "zvazky" / "zvazok_a_b"
    d.mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({"schema": "hyptcn3/safeguard-bundle/1", "diagnostic": True}))
    (d / "predictor.pt").write_bytes(b"p")
    (d / "classifier.pt").write_bytes(b"c")
    files = parita.bundle_files(d)
    path = d.parent / parita.BUNDLE_RECORD
    path.write_text(json.dumps({"schema": parita.BUNDLE_SCHEMA, "values": {
        "vms": {vm: d.name for vm in vms}, "bundles": [{"name": d.name, "dir": str(d), "files": files,
                                                        "sha256": parita._canonical(files)}]}}))
    return path, d


@pytest.fixture
def deck_file(tmp_path):
    path = tmp_path / "balicek.json"
    g2.write_deck(REAL, path, "python -m skuska.g2 deck --protocol config/collection-v5.json --out balicek.json")
    return path


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(parita, "POLL_S", 0.01)


def parity_block(tmp_path, deck_file, *, lab=None, env=None, zvazok=None, seal=lambda: None, **options):
    lab = lab or ParityLab(REAL)
    lab.env = env = env or FakeEnv()
    zvazok = zvazok or fake_bundle(tmp_path)[0]
    places = g2.Places(tmp_path / "G2", diagnostics=tmp_path / "diag")
    b = parita.ParityBlock(REAL, deck_file, "a", zvazok=zvazok, env_factory=lambda: env, seal=seal,
                           other_vm=options.pop("other_vm", "g2"), places=places, lab=lab,
                           command="python -m skuska.parita block --vm a", **options)
    return b, lab, env


def session_record(b, sid="g2-a-w01-1"):
    return json.loads((b.places.records / f"{sid}.json").read_text())


def test_the_parity_plan_is_one_session_at_rate_high_on_each_vm():
    """PLAN_RULE: w01 on VM a (corp_high) and w02 on VM b (eshop_high), the protocol's cycles, no events, seeds of
    their own group, none of a stream of the plan or of the deck."""
    sessions = parita.plan(P)
    assert [(s["id"], s["vm"], s["scenario"], s["cycles"], s["events"]) for s in sessions] == [
        ("w01", "a", "corp_high", 720, None), ("w02", "b", "eshop_high", 720, None)]
    assert [s["seed"] for s in sessions] == [protocol_v5.seed(P["name"], "traffic", f"G2/w0{n}", n, 1) for n in (1, 2)]
    used = {seed for mode in protocol_v5.MODES for s in protocol_v5.plan(P, mode)["sessions"]
            for seed in s["seeds"].values()}
    used |= {seed for s in g2.draw_deck(P)["sessions"] for seed in s["seeds"].values()}
    assert not {s["seed"] for s in sessions} & used
    assert parita.excluded(P) == [*parita.EXCLUDED_CRITERIA, *P["determined_at"]["G2"]]


def test_a_parity_session_runs_watch_beside_after_raw_then_the_replay_and_the_comparison(tmp_path, deck_file, fast):
    """WATCH_RULE and REPLAY_RULE with fakes: watch starts once raw/ and profile/ exist, with safeguard's own command
    line (--threads 1 as the replay, the session's raw/ and profile/, --idle-timeout 60, the VM's bundle,
    --allow-diagnostic, nice 19), its output outside the session's directory; after the audit the replay of the
    audit's feature archive and the real comparison; nothing goes into the session's directory; the record says that
    watch ran beside the run and which tables leave the session out."""
    b, lab, env = parity_block(tmp_path, deck_file)
    summary = b.run()
    assert summary["stopped"] is None and [s["session_id"] for s in summary["sessions"]] == ["g2-a-w01-1"]
    session = tmp_path / "diag" / "a" / "g2-a-w01-1"
    base = tmp_path / "G2" / "parita" / "g2-a-w01-1"
    (call,) = env.calls
    a = call["args"]
    assert call["raw"] and call["profile"] and call["prefix"][:3] == ["nice", "-n", "19"]
    assert (a.command, a.threads, a.allow_diagnostic, a.idle_timeout) == ("watch", 1, True, 60.0)
    assert (a.bundle, a.snapshots, a.profile, a.out) == (
        tmp_path / "zvazky" / "zvazok_a_b", session / "raw", session / "profile", base / "watch")
    (replay, prefix, _), = lab.replays
    assert (replay.command, replay.threads, replay.allow_diagnostic, replay.bundle) == ("replay", a.threads, True,
                                                                                          a.bundle)
    assert replay.archive.parent == session and replay.archive.suffix == ".npz" and replay.out == base / "replay"
    assert prefix[:3] == ["nice", "-n", "19"]
    (compare,) = lab.comparisons
    assert compare[compare.index(str(ROOT / "scripts/campaign_report.py")) + 1:] == [
        "parity", str(base / "watch"), str(base / "replay"), "--out", str(base / "parita.json")]
    order = [e[0] for e in lab.events if e[0] in ("run", "levels", "audit", "replay", "parity", "archive")]
    assert order == ["run", "levels", "audit", "replay", "parity", "archive"]
    names = sorted(str(p.relative_to(session)) for p in session.rglob("*"))
    audit = next(n for n in names if n.endswith(".json") and n.startswith("audit_"))
    assert names == sorted(["end.json", "profile", "protocol.json", "raw", "raw/000001.vmicd", "session.json", audit,
                            audit[:-5] + ".npz"])
    assert sorted(p.name for p in base.iterdir()) == ["parita.json", "replay", "watch", "watch.json", "watch.log"]
    doc = session_record(b)
    v = doc["values"]
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc) and v["kind"] == parita.KIND
    assert v["done"] is True and v["deck"]["item"]["id"] == "w01" and v["deck"]["item"]["rule"] == parita.PLAN_RULE
    assert v["excluded"] == {"criteria": parita.excluded(P), "rule": parita.EXCLUDED_RULE}
    hook = next(x for x in v["beside"] if x["hook"] == parita.KIND)
    assert (hook["started"], hook["exit_code"], hook["terminated"], hook["error_free"], hook["g2_values"]) == (
        True, 2, False, False, False)
    assert hook["record"] == str(base / "watch.json") and hook["sha256"] == sha(base / "watch.json")
    watch = json.loads((base / "watch.json").read_text())
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(watch)
    w = watch["values"]
    assert w["command"] == call["command"] and w["status"]["stop_reason"] == "idle_timeout" and watch["n"] == 6
    assert w["times"]["raw_seen_unix"] <= w["times"]["watch_started_unix"] <= w["times"]["watch_ended_unix"]
    assert w["bundle"]["sha256"] == b.bundle["sha256"] and w["error_free"] is False
    steps = {s["step"]: s for s in v["steps"]}
    assert steps["replay"]["exit_code"] == 0 and steps["parity"]["exit_code"] == 0
    assert steps["parity"]["holds"] is True and steps["parity"]["rows"] == 6
    assert steps["parity"]["alarms"] == {"watch": {"alarm_rows": 3, "alarm_events": 1},
                                         "replay": {"alarm_rows": 3, "alarm_events": 1}}
    table = json.loads((base / "parita.json").read_text())
    assert table["values"]["holds"] and table["values"]["failed_holds"]["rows"] == 3
    assert b.done(v) and v["exit_codes"]["replay"] == 0


def test_a_finding_of_the_comparison_is_recorded_and_the_block_goes_on(tmp_path, deck_file, fast):
    """A row the replay has and watch lacks: the comparison exits 1 and names it, the session is done (the comparison
    was written) and the block is not stopped."""
    b, lab, env = parity_block(tmp_path, deck_file, env=FakeEnv(rows=parity_rows()[:-1]))
    summary = b.run()
    assert summary["stopped"] is None
    steps = {s["step"]: s for s in session_record(b)["values"]["steps"]}
    assert steps["parity"]["exit_code"] == 1 and steps["parity"]["holds"] is False
    assert steps["parity"]["findings_by_kind"] == {"only_replay": 1}
    with pytest.raises(g2.Refused, match="every parity session of VM a is done"):
        parity_block(tmp_path, deck_file, zvazok=b.zvazok_path)[0].specs()
    again = parity_block(tmp_path, deck_file, zvazok=b.zvazok_path, only=["w01"])[0].specs()
    assert [(s["session_id"], s["attempt"]) for s in again] == [("g2-a-w01-2", 2)]


def test_watch_that_outlasts_its_wait_is_ended_by_name(tmp_path, deck_file, fast, monkeypatch):
    """WATCH_RULE: after the run the hook waits WATCH_WAIT_S for watch to end by its idle timeout, then ends the exact
    process group of its own child and says so."""
    monkeypatch.setattr(parita, "WATCH_WAIT_S", 0.2)
    b, lab, env = parity_block(tmp_path, deck_file, env=FakeEnv(forever=True))
    b.run()
    (ended, grace), = env.ended
    assert ended is env.process and grace == parita.TERM_GRACE_S
    hook = next(x for x in session_record(b)["values"]["beside"] if x["hook"] == parita.KIND)
    assert (hook["terminated"], hook["exit_code"]) == (True, -15)
    watch = json.loads((tmp_path / "G2" / "parita" / "g2-a-w01-1" / "watch.json").read_text())["values"]
    assert watch["terminated"] is True and watch["status"]["stop_reason"] == "stop_requested"


def test_a_run_that_makes_no_raw_starts_no_watch_and_no_replay(tmp_path, deck_file, fast):
    """WATCH_RULE: a run that ends before raw/ and profile/ exist leaves watch unstarted, by name; no audit, no
    replay, no comparison; the session is not done."""
    b, lab, env = parity_block(tmp_path, deck_file, lab=ParityLab(REAL, no_directory={"g2-a-w01-1"}, rc={
        "g2-a-w01-1": 1}, run_wait=0))
    b.run()
    assert env.calls == [] and not any(e[0] in ("replay", "parity") for e in lab.events)
    v = session_record(b)["values"]
    hook = next(x for x in v["beside"] if x["hook"] == parita.KIND)
    assert hook["started"] is False and "watch never started" in hook["why_not"] and v["done"] is False


def test_the_replay_is_skipped_by_name_when_watch_wrote_nothing(tmp_path, deck_file, fast):
    """REPLAY_RULE: no output of watch, no replay and no comparison; the record says why."""
    b, lab, env = parity_block(tmp_path, deck_file)
    real_start = env.start

    def failing(command, log):
        process = real_start(command, log)
        process.wait = lambda timeout=None: 1
        return process
    env.start = failing
    b.run()
    steps = session_record(b)["values"]["steps"]
    assert {"step": "replay", "skipped": "safeguard watch wrote no output"} in steps
    assert not any(e[0] in ("replay", "parity") for e in lab.events)


def test_the_parity_block_refuses_a_foreign_bundle_a_bundle_unlike_its_record_and_an_unreadable_ledger(
        tmp_path, deck_file):
    """PARITY_BLOCK_RULE: no bundle for the VM, a bundle file that differs from its record, a seal ledger the guard
    cannot read, and a record of no bundles refuse the block before anything starts."""
    record, d = fake_bundle(tmp_path / "x", vms=("b",))
    b, _, _ = parity_block(tmp_path, deck_file, zvazok=record)
    with pytest.raises(g2.Refused, match="has no bundle for VM a"):
        b.run()
    record, d = fake_bundle(tmp_path / "y")
    (d / "predictor.pt").write_bytes(b"other")
    b, _, _ = parity_block(tmp_path, deck_file, zvazok=record)
    with pytest.raises(g2.Refused, match="differs from its record"):
        b.run()

    def unreadable():
        raise ValueError("the seal ledger is malformed")
    record, d = fake_bundle(tmp_path / "z")
    b, lab, _ = parity_block(tmp_path, deck_file, zvazok=record, seal=unreadable)
    with pytest.raises(g2.Refused, match="safeguard's guard cannot read it"):
        b.run()
    (tmp_path / "none.json").write_text("{}")
    b, lab, _ = parity_block(tmp_path, deck_file, zvazok=tmp_path / "none.json")
    with pytest.raises(g2.Refused, match="is no record of python -m skuska.parita zvazok"):
        b.run()
    assert not [e for e in lab.events if e[0] in ("run", "lock")]


def test_a_parity_directory_inside_the_session_or_of_another_run_gets_no_file(tmp_path, deck_file, fast):
    """WATCH_RULE: a parity directory that exists (a session id runs once) starts no watch and writes nothing there."""
    b, lab, env = parity_block(tmp_path, deck_file, lab=ParityLab(REAL, run_wait=0))
    base = tmp_path / "G2" / "parita" / "g2-a-w01-1"
    base.mkdir(parents=True)
    (base / "other").write_text("of another run")
    b.run()
    assert env.calls == [] and sorted(p.name for p in base.iterdir()) == ["other"]
    hook = next(x for x in session_record(b)["values"]["beside"] if x["hook"] == parita.KIND)
    assert "exists: a session id runs once" in hook["why_not"] and hook["record"] is None
    watch = parita.Watch(b, {"session_id": "s"}, {"session": tmp_path / "G2" / "s"}, FakeEnv())
    watch.dir = tmp_path / "G2" / "s" / "parita"
    watch.start()
    assert "lies inside the session's directory" in watch.why_not and watch.stop()["record"] is None
    assert not (tmp_path / "G2" / "s").exists()


def test_the_dry_run_and_the_command_line_of_the_block(tmp_path, deck_file, monkeypatch, capsys):
    """The dry run starts nothing and gives the commands of watch, the replay and the comparison; main builds the
    block from its options."""
    b, lab, env = parity_block(tmp_path, deck_file)
    out = b.plan()
    (row,) = out["sessions"]
    assert row["session_id"] == "g2-a-w01-1" and safeguard_args(row["watch"])[0].command == "watch"
    assert safeguard_args(row["replay"])[0].archive == Path("<the feature archive of the session's audit>")
    assert out["bundle"]["name"] == "zvazok_a_b" and out["rules"]["watch"] == parita.WATCH_RULE
    assert env.calls == [] and not [e for e in lab.events if e[0] in ("run", "lock")]
    seen = {}

    class Stub:
        def __init__(self, *args, **kwargs):
            seen.update(args=args, kwargs=kwargs)

        def plan(self):
            return {"refusals": []}
    monkeypatch.setattr(parita, "ParityBlock", Stub)
    assert parita.main(["block", "--protocol", "P", "--deck", "D", "--zvazok", "Z", "--vm", "b", "--other-vm", "g2",
                        "--only", "w02", "--dry-run"]) == 0
    assert seen["args"] == (Path("P"), Path("D"), "b") and seen["kwargs"]["zvazok"] == Path("Z")
    assert seen["kwargs"]["only"] == ["w02"] and seen["kwargs"]["other_vm"] == "g2"
    capsys.readouterr()
    assert parita.main(["plan", "--protocol", str(REAL)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["sessions"] == parita.plan(P) and printed["rule"] == parita.PLAN_RULE
