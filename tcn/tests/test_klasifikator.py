"""
Testy klasifikatora aktivit (tcn/klasifikator.py) na syntetickych datach.

Overuje sa MECHANIKA: znacka okna z intervalov udalosti, pevne rozdelenie
skupin, nemenny prediktor, determinizmus a cely beh train + eval. Ziadne
cislo tu nie je meranie (HONESTY P4). Dataset 1 a balik vyrobia pomocky
safeguard/tests/test_training.py, index udalosti ma tvar zo scripts/campaign.py.
"""

import json

import numpy as np
import pytest
import torch

from features.archive import BEHAVIOR_NAMES, save
from features.snapshot import MENA
from safeguard.bundle import digest, load_bundle
from safeguard.tests.test_training import make_corpus
from safeguard.training import train_bundle
from tcn import klasifikator as kl

G = len(BEHAVIOR_NAMES)

LAYOUT = {"bin_bytes": 4096, "page_size": 4096, "bins": [[0, 1], [1, 1], [2, 1]],
          "regions": [{"gpa": 0, "bytes": 12288}], "memsize": 12288, "vcpus": 2}
TYPY = {"zamok_tabulky": "chyba_aplikacie", "udrzba_zaloha": "udrzba"}
RIADKOV = 80


def _konfig(cesta, trening=("test_events-1", "test_events-3", "test_events-5", "test_events-7"),
            test=("test_events-2", "test_events-4", "test_events-6", "test_events-8"), epochs=2):
    cesta.write_text(json.dumps({
        "schema": kl.SCHEMA_KONFIG, "skupiny": {"trening": list(trening), "test": list(test)},
        "seed": 0, "epochs": epochs, "batch_size": 16, "lr": 0.001, "vahy_tried": "inverzna_frekvencia",
        "vyber_checkpointu": "dev", "pravidlo_znacky": "synteticky test"}))
    return cesta


def _archiv(cesta, casy, scenar_i, udalosti, meno, seed):
    rng = np.random.default_rng(seed)
    n = len(casy)
    matica = rng.normal(1 + scenar_i, 0.1, size=(n, len(MENA)))
    for u in udalosti:  # Pocas udalosti sa spravanie posunie, aby sa dalo co ucit.
        matica[(casy >= u["host_start_unix"]) & (casy <= u["host_stopped_unix"]), :G] += 3
    matica[:, G:] = 0
    matica[1:, -2] = 1
    matica[0, -1] = 1
    local = np.zeros((n, 3, 4))
    local[..., 0] = rng.uniform(0.1, 0.3, size=(n, 3))
    local[..., 1] = rng.uniform(0.2, 0.6, size=(n, 3))
    local[..., 2] = rng.uniform(2, 5, size=(n, 3))
    local[..., 3] = 1
    kvalita = [{"model_valid": True, "behavior_valid": True, "traversals_complete": True,
                "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0}
               for _ in range(n)]
    return save(cesta, {"matica": matica, "seq": list(range(n)), "casy": casy, "valid": [True] * n,
                        "perbin": local, "biny": [0, 1, 2], "chain_ids": [meno] * n,
                        "snimky": [str(i) for i in range(n)], "trvanie_s": [0] * n,
                        "poznamky": [[] for _ in range(n)], "quality": kvalita,
                        "quality_policy": "behavioral-inputs-v1", "layout": LAYOUT, "max_medzera_s": 1.5})


def make_events_index(adresar):
    adresar.mkdir(parents=True, exist_ok=True)
    zaznamy = []
    for g in range(1, 9):
        meno = f"v3-s{g}"
        d = adresar / meno
        d.mkdir()
        t0 = 100000.0 + 1000 * g
        casy = t0 + np.arange(RIADKOV, dtype=float)
        udalosti = [{"type": "zamok_tabulky", "class": "chyba_aplikacie", "executed": True,
                     "host_start_unix": t0 + 20, "host_stopped_unix": t0 + 30},
                    {"type": "udrzba_zaloha", "class": "udrzba", "executed": g != 8,
                     "host_start_unix": t0 + 50, "host_stopped_unix": t0 + 58}]
        scenar = ("quiet", "busy")[g % 2]
        archiv = _archiv(d / "features.npz", casy, g % 2, udalosti, meno, g)
        (d / "events.json").write_text(json.dumps({"events": udalosti}))
        zaznamy.append({"id": meno, "role": "test_events", "group": f"v3-test_events-{g}", "boot_id": f"b{g}",
                        "scenario": scenar, "start": float(casy[0]), "end": float(casy[-1]),
                        "features": str(archiv), "features_sha256": digest(archiv),
                        "events": str(d / "events.json"), "events_sha256": digest(d / "events.json")})
    protokol = {"name": "server-events-v3", "interval_s": 1, "max_gap_s": 1.5, "window_rows": 8,
                "group_prefix": "v3-", "roles": {"test_events": 8}, "events": {"classes": TYPY}}
    index = adresar / "events_index.json"
    index.write_text(json.dumps({"schema": "hyptcn3/event-index/1", "complete": True, "protocol_sha256": "p",
                                 "protocol_config": protokol, "sessions": zaznamy}))
    return index


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    d = tmp_path_factory.mktemp("klasifikator")
    korpus = make_corpus(d / "corpus")
    old = torch.get_num_threads()
    torch.set_num_threads(2)
    train_bundle(korpus, d / "bundle", window_rows=8, max_gap_s=1.5, epochs=1, batch_size=16,
                 fpr=0.1, diagnostic=True)
    index = make_events_index(d / "v3")
    konfig = _konfig(d / "konfig.json")
    manifest = kl.trenuj(d / "bundle", korpus, index, konfig, d / "klas", diagnostic=True)
    yield {"d": d, "korpus": korpus, "bundle": d / "bundle", "index": index, "konfig": konfig,
           "out": d / "klas", "manifest": manifest}
    torch.set_num_threads(old)


def test_znacka_okna_na_hraniciach_udalosti():
    W, T = 4, 5.0  # sirka okna 15 s
    u = {"type": "zamok_tabulky", "executed": True, "host_start_unix": 300.0, "host_stopped_unix": 400.0}
    casy = [295.0, 300.0, 415.0, 420.0, 715.0, 720.0]
    assert kl.znacky_okien(casy, [u], "steady", T, W, TYPY) == [
        ("steady", None), ("zamok_tabulky", 0), ("zamok_tabulky", 0), (None, None), (None, None), ("steady", None)]
    u["executed"] = False  # Nevykonana udalost: jej okna aj dozvuk sa vynechaju, nie su profilom.
    assert kl.znacky_okien(casy, [u], "steady", T, W, TYPY) == [
        ("steady", None), (None, None), (None, None), (None, None), (None, None), ("steady", None)]


def test_znacka_odmietne_nejednoznacne_udalosti():
    a = {"type": "zamok_tabulky", "executed": True, "host_start_unix": 300.0, "host_stopped_unix": 400.0}
    b = dict(a, type="udrzba_zaloha", host_start_unix=410.0, host_stopped_unix=500.0)
    with pytest.raises(ValueError, match="to iste okno"):
        kl.znacky_okien([405.0], [a, b], "steady", 5.0, 4, TYPY)
    with pytest.raises(ValueError, match="mimo protokolu"):
        kl.znacky_okien([405.0], [dict(a, type="neznamy")], "steady", 5.0, 4, TYPY)


def test_odmietne_prekryv_a_neuplne_rozdelenie(tmp_path, data):
    with pytest.raises(ValueError, match="prekryvaju"):
        kl.nacitaj_konfig(_konfig(tmp_path / "a.json", test=("test_events-1", "test_events-2")))
    konfig, _ = kl.nacitaj_konfig(_konfig(tmp_path / "b.json", test=("test_events-2", "test_events-4")))
    kontrakt = load_bundle(data["bundle"], allow_diagnostic=True).contract
    with pytest.raises(ValueError, match="prave v jednej"):
        kl.nacitaj_index_udalosti(data["index"], konfig, kontrakt, 1, diagnostic=True)
    with pytest.raises(FileExistsError):
        kl.trenuj(data["bundle"], data["korpus"], data["index"], data["konfig"], data["out"], diagnostic=True)


def test_prediktor_sa_nemeni_a_testovacie_archivy_sa_neotvoria(data):
    m = data["manifest"]
    bundle = load_bundle(data["bundle"], allow_diagnostic=True)
    assert digest(data["bundle"] / "predictor.pt") == bundle.manifest["weights"]["predictor"]["sha256"]
    assert m["balik"]["predictor_sha256"] == bundle.manifest["weights"]["predictor"]["sha256"]
    assert m["triedy"] == ["busy", "quiet", "udrzba_zaloha", "zamok_tabulky"]
    otvorene = set(m["vstupy"]["otvorene_archivy"])
    assert {"v3-s1", "v3-s3", "v3-s5", "v3-s7"} <= otvorene
    assert not otvorene & {"v3-s2", "v3-s4", "v3-s6", "v3-s8"}
    assert not any("calibration" in s or "test_benign" in s for s in otvorene)
    assert all(m["trening"]["okien_trening"].values())
    assert digest(data["out"] / "klasifikator.pt") == m["vahy"]["sha256"]


def test_deterministicky_pri_rovnakom_seede(data):
    druhy = data["d"] / "klas2"
    kl.trenuj(data["bundle"], data["korpus"], data["index"], data["konfig"], druhy, diagnostic=True)
    a = torch.load(data["out"] / "klasifikator.pt", weights_only=True)
    b = torch.load(druhy / "klasifikator.pt", weights_only=True)
    assert a.keys() == b.keys() and all(torch.equal(a[k], b[k]) for k in a)


def test_train_a_eval_cez_prikaz(data, tmp_path):
    out = tmp_path / "vysledok.json"
    assert kl._hlavny(["eval", "--classifier", str(data["out"]), "--events-index", str(data["index"]),
                       "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    for kluc in ("commit", "date", "host", "guest", "command", "n", "values"):
        assert kluc in doc
    v = doc["values"]
    assert set(v["testovacie_relacie"]) == {"v3-s2", "v3-s4", "v3-s6", "v3-s8"} and v["skupin"] == 4
    # Okna na relaciu: koniec 8..19 profil, 20..37 zamok, dozvuk po nom vynechany; udrzba (50..65)
    # je v dozvuku, vstupi iba vykonana (nie v v3-s8).
    assert v["okna"]["n"] == 4 * (12 + 18) + 3 * 16
    assert sum(map(sum, v["okna"]["confusion"])) == v["okna"]["n"]
    assert v["udalosti"]["planovanych"] == 8 and v["udalosti"]["hodnotenych"] == 7
    assert v["relacie_profil"]["relacie"]["spolu"] == 4
    assert v["relacie_profil"]["okna"]["n"] == 4 * 12
    with pytest.raises(FileExistsError):
        kl._hlavny(["eval", "--classifier", str(data["out"]), "--events-index", str(data["index"]),
                    "--out", str(out)])
    with pytest.raises(FileExistsError):
        kl._hlavny(["train", "--bundle", str(data["bundle"]), "--corpus", str(data["korpus"]),
                    "--events-index", str(data["index"]), "--config", str(data["konfig"]),
                    "--out", str(data["out"]), "--diagnostic"])


def test_konfig_v1_je_platny():
    konfig, _ = kl.nacitaj_konfig(kl.REPO + "/config/klasifikator-v1.json")
    assert konfig["skupiny"]["trening"] == [f"test_events-{i}" for i in (1, 3, 5, 7)]
    assert konfig["skupiny"]["test"] == [f"test_events-{i}" for i in (2, 4, 6, 8)]
