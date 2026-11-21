"""
Odovzdanie korpusu treningu (docs/HARNESS_V5.sk.md balik B1, kriterium G0 corpus_to_training).

Korpus ma tvar uzavretej kampane: skupiny s predponou protokolu, udalosti
a v kazdej role dve relacie (prva relacia kazdej VM), kazda s jednym
tolerovanym neplatnym riadkom (pravidlo invalid_rows). Relacie planuje
collection.plan, prijima ich kod auditu (collection.analyze_windows) a index
stavia features/dataset.py tak isto ako scripts/campaign.py finish_corpus.
Ten isty index potom musi prejst ostrou kontrolou, treningom, kazdou metodou
porovnania, prehratim a vyhodnotenim - bez priznaku diagnostic a tymi istymi
prikazmi, ake pusti clovek.

Zaznam auditu relacie sklada test z vystupu analyze_windows sam: cely
collection.audit_session cita surove snimky a denniky relacie, ktore synteticka
kampan nema. Posledny test preto jednu relaciu s tolerovanym riadkom prevedie
celym audit_session (nahradena je iba extrakcia z RAM), jej zaznam da stavbe
korpusu a drzi tvar rucne zlozeneho zaznamu pri tom, co pise audit.

Druha polovica drzi opacnu stranu, kazde miesto tym, co samo cita. Ostra
kontrola indexu odmietne rozdelenie mimo planu protokolu (skupina bez predpony
alebo s predponou navyse, chybajuca skupina). Trening a metody odmietnu archiv
s riadkom neuvedenym v audite, nad pocet alebo s inou pricinou. Prehratie
a vyhodnotenie (FAR aj udalosti) zoznam tolerovanych riadkov v audite necitaju
(vyhodnotenie udalosti berie z auditu relacie iba hashe extrakcie): odmietnu
riadok nad pocet alebo s inou pricinou. Vyhodnotenie odmietne aj iny dovod
chyby vstupu a stav prehratia, ktory nesedi s jeho riadkami; prehratie odmietne
aj pravidlo s chybnym tvarom a archiv bez riadkov a nad suborom archivu, ktory
sa neda precitat, nevrati nulu.

Iba MECHANIKA na syntetickych riadkoch - ziadne cislo tu nie je vysledok
detekcie (HONESTY P4).
"""
import contextlib
import copy
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import shutil
import zipfile

import numpy as np
import pytest
import torch

from features import dataset
from features.archive import save
from features.snapshot import MENA, SCHEMA
from safeguard import cli
from safeguard.training import ROLES, train_bundle, validate_index
from scripts import campaign, collection
from tcn import eval as ev
from tcn import porovnanie as po

KAMPAN = "odovzdanie-v5-test"
CYKLY, PLNA_KAZDA, OKNO = 96, 64, 8
RIADOK = 30  # seq tolerovaneho riadku: mimo plnej snimky aj jej zahrievania
FPR = 0.05
ROZLOZENIE = {"bin_bytes": 16777216, "page_size": 4096, "bins": [[i, 4096] for i in range(3)],
              "regions": [{"gpa": 0, "bytes": 50331648}], "memsize": 50331648, "vcpus": 2}
DOBRY = {"model_valid": True, "behavior_valid": True, "traversals_complete": True, "truncated_traversals": [],
         "inconclusive": ["text_integrity"], "findings": [], "read_errors": 0, "filled_zero": 0}
# Riadok, ktoremu sa neuzavrel prechod procesov: jediny druh, ktory pravidlo protokolu toleruje.
NEUZAVRETY = dict(DOBRY, model_valid=False, behavior_valid=False, traversals_complete=False,
                  truncated_traversals=["processes"])
INY_PRECHOD = dict(NEUZAVRETY, truncated_traversals=["modules"])
# Od tolerovaneho riadku sa lisi iba chybou citania RAM: pravidlo ho odmietne pre nu, nie pre chybajuci prechod.
CHYBA_CITANIA = dict(NEUZAVRETY, read_errors=1)


def _sha(cesta):
    return hashlib.sha256(Path(cesta).read_bytes()).hexdigest()


def _protokol(profil):
    return {
        "schema": "hyptcn3/collection-protocol/3", "name": "odovzdanie-korpusu-test",
        "quality_policy": "behavioral-inputs-v1", "profile": str(profil),
        "interval_s": 5, "max_gap_s": 7.5, "bin_bytes": 16777216, "window_rows": OKNO, "stride": 1,
        "full_every": PLNA_KAZDA, "cycles": CYKLY, "pilot_cycles": CYKLY, "min_score_coverage": 0.7,
        "scenarios": {"steady": {"workers": 4, "burst": 1, "catalog_share": 0.6, "write_share": 0.1},
                      "bursty": {"workers": 4, "burst": 8, "catalog_share": 0.6, "write_share": 0.1}},
        "roles": {"train": 2, "dev": 2, "calibration": 2, "test_benign": 2},
        "vms": [{"name": "a", "domain": "hyptcn-test-a", "port": 28080},
                {"name": "b", "domain": "hyptcn-test-b", "port": 28081}],
        "group_prefix": "v5-",
        "events": {"note": "synteticky rozvrh testu",
                   "classes": {"zamok_tabulky": "chyba_aplikacie", "udrzba_zaloha": "udrzba"},
                   "per_session": [1, 1], "duration_s": [30, 60], "first_s": 60, "min_gap_s": 60,
                   "tail_s": 60, "grace_s": 10,
                   "pilot": [{"type": "zamok_tabulky", "start_s": 60, "duration_s": 30}]},
        "invalid_rows": {"max": 1, "traversals": ["processes"]},
    }


def _vysledok(sid, t0, scenar_i, seed, neplatne=None):
    """Vysledok extrakcie jednej relacie (tvar features.snapshot.retazec), hodnoty ako safeguard.demo.

    neplatne: {seq: kvalita riadku}. Neplatny riadok si predchodcu ponecha, riadok po nom ho straca.
    """
    neplatne = neplatne or {}
    rng = np.random.default_rng(seed)
    t = np.arange(CYKLY)
    uroven = 0.02 + scenar_i * 0.08
    matica = np.zeros((CYKLY, len(MENA)))
    matica[:, :8] = np.clip(uroven + rng.normal(0, 0.005, (CYKLY, 8)), 0, 1)
    matica[:, 8:18] = 20 + scenar_i * 10 + rng.integers(0, 5, (CYKLY, 10))
    predchodca, plna = MENA.index("ma_predchodcu"), MENA.index("je_plna")
    matica[:, predchodca] = 1
    matica[t % PLNA_KAZDA == 0, plna] = 1
    matica[t % PLNA_KAZDA == 0, predchodca] = 0
    for seq in neplatne:
        matica[seq + 1, predchodca] = 0
    for meno in ("proc_new", "proc_gone", "mod_delta"):  # bez predchodcu niet rozdielu
        matica[matica[:, predchodca] == 0, MENA.index(meno)] = 0
    lokalne = np.zeros((CYKLY, len(ROZLOZENIE["bins"]), 4))
    lokalne[:, :, 0] = np.clip(uroven + rng.normal(0, 0.01, lokalne.shape[:2]), 0, 1)
    lokalne[:, :, 1] = rng.uniform(0.1, 0.3, lokalne.shape[:2])
    lokalne[:, :, 3] = lokalne[:, :, 0] > 0
    lokalne[:, :, 2] = np.clip(4 + scenar_i + rng.normal(0, 0.1, lokalne.shape[:2]), 0, 8) * lokalne[:, :, 3]
    kvalita = [copy.deepcopy(neplatne.get(int(i), DOBRY)) for i in t]
    return {"schema": SCHEMA, "mena": MENA, "matica": matica.tolist(), "perbin": lokalne.tolist(),
            "seq": [int(i) for i in t], "casy": [t0 + 5.0 * int(i) for i in t],
            "valid": [q["behavior_valid"] for q in kvalita], "quality": kvalita,
            "quality_policy": "behavioral-inputs-v1", "biny": [b[0] for b in ROZLOZENIE["bins"]],
            "chain_ids": [f"{sid}-chain-{int(i) // PLNA_KAZDA}" for i in t],
            "snimky": [f"synteticka-{int(i)}" for i in t], "trvanie_s": [0.0] * CYKLY,
            "poznamky": [[] for _ in t], "layout": ROZLOZENIE, "max_medzera_s": 7.5}


def _kampan(koren, predpona="v5-"):
    """Uzavreta kampan v adresari koren: relacie podla planu protokolu, prijate kodom auditu, a index korpusu.

    predpona=None: protokol bez group_prefix, skupiny planu sa volaju iba rolou a poradim.
    """
    koren.mkdir(parents=True, exist_ok=True)
    profil = koren / "profile"
    profil.mkdir()
    (profil / "symbols.txt").write_text("synteticky profil testu\n")
    protokol_cesta = koren / "protocol.json"
    protokol = _protokol(profil)
    if predpona is None:
        del protokol["group_prefix"]
    collection.write_json(protokol_cesta, protokol)
    p = collection.protocol(protokol_cesta)
    protokol_sha = _sha(protokol_cesta)
    plan = collection.plan(p)["sessions"]
    poradie, audity, relacie, s_riadkom, okna = {}, [], {}, set(), dict.fromkeys(p["roles"], 0)
    for i, s in enumerate(plan):
        sid = "_".join([KAMPAN, f"{i + 1:02d}", s["vm"], s["role"], s["scenario"]])
        miesto = poradie.setdefault((s["role"], s["vm"]), [])
        # Roly idu po sebe v case, relacie jednej VM tiez; dve VM bezia naraz.
        t0 = 1700000000.0 + list(p["roles"]).index(s["role"]) * 4000 + len(miesto) * 600
        s_neplatnym = not miesto  # prva relacia kazdej VM: v kazdej role dve relacie s tolerovanym riadkom
        miesto.append(sid)
        relacie[sid] = {"sid": sid, "t0": t0, "scenar_i": list(p["scenarios"]).index(s["scenario"]),
                        "seed": s["seed"]}
        vysledok = _vysledok(**relacie[sid], neplatne={RIADOK: NEUZAVRETY} if s_neplatnym else None)
        if s_neplatnym:
            s_riadkom.add(sid)
        riadky, okna_relacie, pokrytie, dovody, kvalita = collection.analyze_windows(vysledok, p, sid, p["cycles"])
        assert dovody == [], (sid, dovody)  # audit by relaciu prijal
        okna[s["role"]] += len(okna_relacie)
        adresar = koren / "sessions" / sid
        adresar.mkdir(parents=True)
        collection.write_json(adresar / "session.json", {
            "schema": "hyptcn3/collection-session/2", "session_id": sid, "campaign_id": KAMPAN,
            "vm": s["vm"], "role": s["role"], "group": s["group"], "group_attempt": 1,
            "scenario": s["scenario"], "typ": "benign", "seed": s["seed"], "cycles": s["cycles"],
            "guest_before": {"boot_id": "boot-" + s["group"], "kernel": "6.1.0-test", "stack_sha256": "5" * 64},
            "events": s["events"], "event_grace_s": p["events"]["grace_s"], "protocol_sha256": protokol_sha,
            "collector_sha256": "c" * 64, "profile_sha256": {"symbols.txt": _sha(profil / "symbols.txt")}})
        collection.write_json(adresar / "events.json", {"schema": "hyptcn3/session-events/1", "events": [
            dict(u, executed=True, host_start_unix=t0 + u["start_s"], start={"ok": True},
                 host_started_unix=t0 + u["start_s"] + 1.0, host_stop_unix=t0 + u["start_s"] + u["duration_s"],
                 stop={"ok": True, "health": 200}, host_stopped_unix=t0 + u["start_s"] + u["duration_s"] + 1.0)
            for u in s["events"]], "note": "synteticky zaznam testu"})
        archiv = save(adresar / "audit_test.npz", vysledok)
        relacia_sha = _sha(adresar / "session.json")
        collection.write_json(adresar / "audit_test.json", {"schema": "hyptcn3/collection-audit/1", "n": len(riadky), "values": {
            "accepted": True, "reasons": [], "role": s["role"], "protocol_sha256": protokol_sha,
            "snapshots": len(riadky), "windows": len(okna_relacie), "score_coverage": pokrytie,
            "coverage": kvalita.pop("coverage", None),
            "logs": {"schema": "hyptcn3/collection-logs-audit/1", "accepted": True, "problems": [],
                     "sections": {"metadata": {"session_sha256": relacia_sha}}},
            "quality": kvalita, "session_sha256": relacia_sha, "extractor_sha256": campaign.extractor_hashes(),
            "features": str(archiv), "features_sha256": _sha(archiv), "layout": vysledok["layout"],
            "session_dir": str(adresar)}})
        audity.append(adresar / "audit_test.json")
    # Index ako scripts/campaign.py finish_corpus.
    doc = dataset.build(audity, p, protokol_sha)
    doc["protocol"] = str(protokol_cesta)
    assert doc["complete"], doc["allocation_mismatches"]
    index = koren / "corpus.json"
    collection.write_json(index, doc)
    return {"index": index, "plan": plan, "relacie": relacie, "s_riadkom": s_riadkom, "okna": okna,
            "dev": [z for z in doc["sessions"] if z["role"] == "dev"]}


def _podvrh(kampan, neplatne, uvedene):
    """Index, v ktorom archiv jednej relacie train a zoznam v jej audite vymenil niekto mimo stavby korpusu."""
    doc = json.loads(kampan["index"].read_text())
    zaznam = next(z for z in doc["sessions"] if z["role"] == "train" and z["id"] in kampan["s_riadkom"])
    archiv, audit_cesta = Path(zaznam["features"]), Path(zaznam["audit"])
    archiv.unlink()
    save(archiv, _vysledok(**kampan["relacie"][zaznam["id"]], neplatne=neplatne))
    audit = json.loads(audit_cesta.read_text())
    audit["values"]["features_sha256"] = _sha(archiv)
    audit["values"]["quality"]["tolerated_invalid_seq"] = uvedene
    audit_cesta.write_text(json.dumps(audit))
    zaznam["features_sha256"], zaznam["audit_sha256"] = _sha(archiv), _sha(audit_cesta)
    kampan["index"].write_text(json.dumps(doc))
    return kampan["index"]


def _relacia_cez_audit(koren, monkeypatch, riadok):
    """Relacia train s jednym neuzavretym riadkom, ktoru posudil cely collection.audit_session.

    Dokazy relacie (prevadzka, denniky hosta, manifest, udalost) stavia pomocka testov auditu
    dennikov; nahradena je iba extrakcia z RAM. Vracia (protokol, cesta protokolu, cesta auditu, kod auditu).
    """
    from features.tests.test_collection_contract import sample_sidecar
    from features.tests.test_coverage import data
    from safeguard.tests.test_features import sample as snimka
    from scripts.tests import test_collection_logs as dokazy

    adresar = dokazy.build(koren, event=True)
    (adresar / "profile").mkdir()
    (adresar / "profile" / "symbols.txt").write_text("synteticky profil testu\n")
    # Dokazy pomocky maju desat snimok v dvoch sekundach; brana pokrytia je preto nizsie nez v kampani.
    p = dict(_protokol(adresar / "profile"), interval_s=.1, max_gap_s=.15, window_rows=3, cycles=10,
             min_score_coverage=.25)
    protokol_cesta = adresar / "protocol.json"
    dokazy.write(protokol_cesta, p)
    meta = json.loads((adresar / "session.json").read_text())
    meta.update(role="train", typ="benign", group="v5-train-1", scenario="steady", vm="a",
                guest_before=dict(meta["guest_before"], stack_sha256="5" * 64),
                profile_sha256={"symbols.txt": _sha(adresar / "profile" / "symbols.txt")},
                protocol_sha256=_sha(protokol_cesta))
    dokazy.write(adresar / "session.json", meta)
    koniec = json.loads((adresar / "end.json").read_text())
    dokazy.write(adresar / "end.json", dict(koniec, guest_after=meta["guest_before"]))
    zber = json.loads((adresar / "raw/capture.json").read_text())
    zber["values"].update(interval_s=p["interval_s"], full_every=p["full_every"])
    dokazy.write(adresar / "raw/capture.json", zber)
    snimky = [snimka(i, full=i == 0, predecessor=i not in (0, riadok + 1), timestamp=dokazy.BASE + 1.1 + i * .1)
              for i in range(10)]
    snimky[riadok] = replace(snimky[riadok], quality=copy.deepcopy(NEUZAVRETY))
    vysledok = data(snimky)
    vysledok.update(snimky=[str(i) for i in range(10)], poznamky=[[]] * 10, trvanie_s=[0.] * 10, max_medzera_s=.15)
    for s in snimky:
        obraz = adresar / "raw" / f"frame{s.seq}.vmicd"
        obraz.write_bytes(b"synteticka RAM")
        sidecar = sample_sidecar()
        sidecar.update(seq=s.seq, timestamp_unix=s.timestamp, sched={"skipped_before": 0}, capture={"total_ms": .1})
        sidecar["output"].update(full=s.full, sha256=_sha(obraz))
        dokazy.write(obraz.with_suffix(".json"), sidecar)
    monkeypatch.setattr(collection, "retazec", lambda *a, **kw: vysledok)
    dokazy.seal(adresar)
    audit = adresar / "audit_test.json"
    return p, protokol_cesta, audit, collection.audit_session(adresar, p, protokol_cesta, audit)


def _mimo_tvaru(rucne, ostre, cesta):
    """Kluce rucne zlozenej hodnoty, ktore ostry zaznam nema alebo ich pise s inym typom."""
    if type(rucne) is not type(ostre):
        return [cesta]
    if not isinstance(rucne, dict):
        return []
    return [chyba for kluc in rucne for chyba in
            ([cesta + "." + kluc] if kluc not in ostre else _mimo_tvaru(rucne[kluc], ostre[kluc], cesta + "." + kluc))]


def _prikaz(hlavny, *argv):
    """Navratovy kod prikazu (cli.main, po._hlavny, ev._hlavny) a to, co vypisal na chybovy vystup."""
    chyby = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(chyby):
        kod = hlavny([str(a) for a in argv])
    return kod, chyby.getvalue()


def _prejde(hlavny, *argv):
    kod, chyby = _prikaz(hlavny, *argv)
    assert kod == 0, chyby


@pytest.fixture(scope="module", autouse=True)
def _vlakna():
    povodne = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(povodne)  # prikazy --threads nastavuju globalne a nevracaju


@pytest.fixture(scope="module")
def kampan(tmp_path_factory):
    return _kampan(tmp_path_factory.mktemp("odovzdanie") / "kampan")


@pytest.fixture(scope="module")
def balik(kampan, tmp_path_factory):
    """Hlavny balik: python3 -m safeguard train nad indexom kampane."""
    out = tmp_path_factory.mktemp("balik") / "balik"
    _prejde(cli.main, "--threads", 2, "train", "--corpus", kampan["index"], "--out", out,
            "--epochs", 1, "--batch-size", 64, "--fpr", FPR)
    return out


@pytest.fixture(scope="module")
def metody(kampan, balik, tmp_path_factory):
    """Kazda metoda porovnania: python3 -m tcn.porovnanie fit nad tym istym indexom, s odkazom na hlavny balik."""
    koren = tmp_path_factory.mktemp("metody")
    for meno in po.MODELY:
        _prejde(po._hlavny, "--threads", 2, "fit", "--corpus", kampan["index"], "--model", meno,
                "--out", koren / meno, "--epochs", 1, "--batch-size", 64, "--fpr", FPR, "--reference", balik)
    return {meno: koren / meno for meno in po.MODELY}


@pytest.fixture(scope="module")
def prehratia(kampan, balik, metody, tmp_path_factory):
    """Prehratie relacii roly dev hlavnym balikom aj kazdou metodou: {metoda: [(zaznam, adresar, kod, chyby)]}."""
    koren = tmp_path_factory.mktemp("prehratia")
    vysledok = {}
    for meno, model in {"tcn": balik, **metody}.items():
        (koren / meno).mkdir()
        vysledok[meno] = []
        for zaznam in kampan["dev"]:
            out = koren / meno / zaznam["id"]
            hlavny, volba = (cli.main, "--bundle") if meno == "tcn" else (po._hlavny, "--model")
            kod, chyby = _prikaz(hlavny, "--threads", 2, "replay", volba, model,
                                 "--archive", zaznam["features"], "--out", out)
            vysledok[meno].append((zaznam, out, kod, chyby))
    return vysledok


def test_korpus_ma_tvar_kampane(kampan):
    index = json.loads(kampan["index"].read_text())
    relacie = index["sessions"]
    assert index["complete"] is True and len(relacie) == len(kampan["plan"]) == 16
    assert {z["group"] for z in relacie} == {s["group"] for s in kampan["plan"]}
    assert all(z["group"].startswith("v5-" + z["role"] + "-") for z in relacie)
    assert all(_sha(z["events"]) == z["events_sha256"] for z in relacie)
    tolerovane = {z["id"]: json.loads(Path(z["audit"]).read_text())["values"]["quality"]["tolerated_invalid_seq"]
                  for z in relacie}
    assert {i for i, seq in tolerovane.items() if seq} == kampan["s_riadkom"]
    assert all(tolerovane[i] == [RIADOK] for i in kampan["s_riadkom"])
    assert sorted(z["role"] for z in relacie if z["id"] in kampan["s_riadkom"]) == sorted(ROLES * 2)
    assert {(z["role"], z["vm"]) for z in relacie if z["id"] in kampan["s_riadkom"]} == {
        (rola, vm) for rola in ROLES for vm in "ab"}


def test_ostra_kontrola_indexu_prijme_predponu_skupin(kampan):
    """Ta ista kontrola, ktorou finish_corpus konci kampan (bez diagnostic)."""
    _, protokol, zaznamy = validate_index(kampan["index"])
    assert len(zaznamy) == 16 and protokol["group_prefix"] == "v5-"


def _premenuj_skupinu(index, stara, nova):
    """Index, v ktorom sa jedna skupina vola inak; jej relacie, audity a zaznamy indexu ostavaju navzajom zhodne."""
    doc = json.loads(index.read_text())
    zaznamy = [z for z in doc["sessions"] if z["group"] == stara]
    assert len(zaznamy) == 2
    for zaznam in zaznamy:
        relacia, audit_cesta = Path(zaznam["session"]), Path(zaznam["audit"])
        relacia.write_text(json.dumps(dict(json.loads(relacia.read_text()), group=nova)))
        audit = json.loads(audit_cesta.read_text())
        audit["values"]["session_sha256"] = _sha(relacia)
        audit["values"]["logs"]["sections"]["metadata"]["session_sha256"] = _sha(relacia)
        audit_cesta.write_text(json.dumps(audit))
        zaznam.update(group=nova, session_sha256=_sha(relacia), audit_sha256=_sha(audit_cesta))
    index.write_text(json.dumps(doc))
    return index


def test_ostra_kontrola_indexu_odmietne_skupinu_bez_predpony(tmp_path):
    """Skupina, ktorej chyba predpona protokolu, nie je skupinou planu."""
    index = _kampan(tmp_path / "kampan")["index"]
    validate_index(index)
    with pytest.raises(ValueError, match="incomplete planned allocation"):
        validate_index(_premenuj_skupinu(index, "v5-train-1", "train-1"))


def test_ostra_kontrola_indexu_odmietne_chybajucu_skupinu(tmp_path):
    """Index bez jednej skupiny planu neprejde, aj ked sa sam oznacuje za uplny."""
    index = _kampan(tmp_path / "kampan")["index"]
    validate_index(index)
    doc = json.loads(index.read_text())
    doc["sessions"] = [z for z in doc["sessions"] if z["group"] != "v5-dev-2"]
    assert doc["complete"] is True and len(doc["sessions"]) == 14
    index.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="incomplete planned allocation"):
        validate_index(index)


def test_ostra_kontrola_indexu_bez_predpony_v_protokole(tmp_path):
    """Protokol bez group_prefix: skupiny planu predponu nemaju a skupina s predponou do planu nepatri."""
    index = _kampan(tmp_path / "kampan", predpona=None)["index"]
    _, protokol, zaznamy = validate_index(index)
    assert "group_prefix" not in protokol
    assert {z["group"] for z in zaznamy} == {f"{rola}-{i}" for rola in ROLES for i in (1, 2)}
    with pytest.raises(ValueError, match="incomplete planned allocation"):
        validate_index(_premenuj_skupinu(index, "train-1", "v5-train-1"))


@pytest.mark.parametrize("predpona, nova", [("v5-", lambda skupina: "x-" + skupina.removeprefix("v5-")),
                                            (None, lambda skupina: "v5-" + skupina)], ids=["cudzia", "navyse"])
def test_ostra_kontrola_indexu_berie_predponu_z_protokolu(tmp_path, predpona, nova):
    """Predponu skupin urcuje protokol, nie index: ked ju zhodne vymenia alebo pridaju vsetky skupiny, plan to nie je."""
    index = _kampan(tmp_path / "kampan", predpona=predpona)["index"]
    validate_index(index)
    skupiny = sorted({z["group"] for z in json.loads(index.read_text())["sessions"]})
    assert len(skupiny) == 8
    for skupina in skupiny:
        _premenuj_skupinu(index, skupina, nova(skupina))
    with pytest.raises(ValueError, match="incomplete planned allocation"):
        validate_index(index)


def test_trening_prijme_tolerovany_riadok(kampan, balik):
    manifest = json.loads((balik / "manifest.json").read_text())
    assert manifest["diagnostic"] is False
    assert manifest["training"]["test_feature_arrays_loaded"] is False
    # Okna pocita audit tym istym postupom ako trening: dve relacie bez neplatneho riadku a dve s nim.
    assert manifest["training"]["windows"] == {rola: kampan["okna"][rola] for rola in ROLES[:-1]}
    assert set(kampan["okna"].values()) == {2 * 80 + 2 * 71}


def test_kazda_metoda_prijme_tolerovany_riadok(metody):
    assert set(metody) == set(po.MODELY)
    for meno, adresar in metody.items():
        manifest = json.loads((adresar / "manifest.json").read_text())
        assert manifest["model"] == meno and manifest["diagnostic"] is False


def test_prehratie_s_tolerovanym_riadkom_konci_nulou(kampan, prehratia):
    assert set(prehratia) == {"tcn", *po.MODELY}
    for meno, behy in prehratia.items():
        assert len(behy) == 4
        for zaznam, out, kod, chyby in behy:
            stav = json.loads((out / "status.json").read_text())
            neplatnych = int(zaznam["id"] in kampan["s_riadkom"])
            assert kod == 0, (meno, zaznam["id"], chyby, stav)
            assert stav["ok"] is True and stav["stop_reason"] == "replay_complete"
            assert stav["input_errors"] == stav["tolerated_invalid_rows"] == neplatnych
            assert stav["processed"] == CYKLY and stav["scored"] == 80 - 9 * neplatnych
        assert sum(json.loads((out / "status.json").read_text())["input_errors"] for _, out, _, _ in behy) == 2


@pytest.mark.parametrize("neplatne", [
    {RIADOK: NEUZAVRETY, RIADOK + 20: NEUZAVRETY},  # o riadok viac, nez pravidlo dovoli
    {RIADOK: INY_PRECHOD},  # prechod, ktory pravidlo neuvadza
    {RIADOK: CHYBA_CITANIA},  # ina pricina nez neuzavrety prechod
], ids=["nad_pocet", "iny_prechod", "chyba_citania"])
def test_prehratie_odmietne_riadok_mimo_pravidla(balik, metody, tmp_path, neplatne):
    archiv = save(tmp_path / "mimo.npz", _vysledok("mimo", 1700090000.0, 0, 7, neplatne))
    for meno, model in {"tcn": balik, **metody}.items():
        hlavny, volba = (cli.main, "--bundle") if meno == "tcn" else (po._hlavny, "--model")
        out = tmp_path / meno
        kod, _ = _prikaz(hlavny, "--threads", 2, "replay", volba, model, "--archive", archiv, "--out", out)
        stav = json.loads((out / "status.json").read_text())
        assert kod == 2 and stav["ok"] is False, meno
        assert stav["input_errors"] == len(neplatne) and stav["tolerated_invalid_rows"] == 0, meno


def test_prehratie_odmietne_chybne_pravidlo_pred_zapisom(kampan, balik, metody, tmp_path):
    """Pravidlo s chybnym tvarom v manifeste balika: prehratie skonci skor, nez nieco zapise."""
    s_riadkom, bez_riadku = (next(z["features"] for z in kampan["dev"] if (z["id"] in kampan["s_riadkom"]) == ano)
                             for ano in (True, False))
    for hlavny, volba, model in ((cli.main, "--bundle", balik), (po._hlavny, "--model", metody["zscore"])):
        kopia = Path(shutil.copytree(model, tmp_path / volba.strip("-")))
        manifest = json.loads((kopia / "manifest.json").read_text())
        manifest["provenance"]["protocol"]["invalid_rows"] = {"max": "1", "traversals": ["processes"]}
        (kopia / "manifest.json").write_text(json.dumps(manifest))
        for i, archiv in enumerate((s_riadkom, bez_riadku)):
            out = tmp_path / f"{volba.strip('-')}-{i}"
            argv = ("--threads", 2, "replay", volba, kopia, "--archive", archiv, "--out", out)
            if hlavny is cli.main:  # safeguard chybu vypise a vrati kod 2, tcn.porovnanie ju necha prejst
                kod, chyby = _prikaz(hlavny, *argv)
                assert kod == 2 and "invalid invalid_rows rule" in chyby
            else:
                with pytest.raises(ValueError, match="invalid invalid_rows rule"):
                    _prikaz(hlavny, *argv)
            assert not out.exists()


@pytest.mark.parametrize("protokol", ["chyba", None, {}], ids=["bez_kluca", "null", "prazdny"])
def test_prehratie_bez_protokolu_v_manifeste_nic_netoleruje(kampan, balik, metody, tmp_path, protokol):
    """Manifest, ktory nenesie protokol, nema pravidlo: riadok, ktory pravidlo korpusu toleruje, prehratie kazi.

    Metodu porovnania bez protokolu nacitanie prijme a verdikt prehratia bez pravidla netoleruje nic.
    Hlavny balik bez protokolu odmietne uz nacitanie (safeguard/bundle.py), skor nez prehratie nieco zapise;
    null namiesto protokolu tam konci vynimkou, ktoru prikaz nezachyti.
    """
    s_riadkom = next(z["features"] for z in kampan["dev"] if z["id"] in kampan["s_riadkom"])
    for hlavny, volba, model in ((cli.main, "--bundle", balik), (po._hlavny, "--model", metody["zscore"])):
        kopia = Path(shutil.copytree(model, tmp_path / volba.strip("-")))
        manifest = json.loads((kopia / "manifest.json").read_text())
        assert manifest["provenance"]["protocol"]["invalid_rows"] == {"max": 1, "traversals": ["processes"]}
        if protokol == "chyba":
            del manifest["provenance"]["protocol"]
        else:
            manifest["provenance"]["protocol"] = protokol
        (kopia / "manifest.json").write_text(json.dumps(manifest))
        out = tmp_path / (volba.strip("-") + "-out")
        argv = ("--threads", 2, "replay", volba, kopia, "--archive", s_riadkom, "--out", out)
        if hlavny is po._hlavny:
            kod, _ = _prikaz(hlavny, *argv)
            stav = json.loads((out / "status.json").read_text())
            assert kod == 2 and stav["ok"] is False
            assert stav["input_errors"] == 1 and stav["tolerated_invalid_rows"] == 0
        elif protokol is None:
            with pytest.raises(AttributeError):
                _prikaz(hlavny, *argv)
            assert not out.exists()
        else:
            kod, chyby = _prikaz(hlavny, *argv)
            assert kod == 2 and chyby.startswith("safeguard: ") and not out.exists()


def test_prehratie_archivu_bez_riadkov_neskonci_nulou(balik, metody, tmp_path):
    """Archiv bez riadkov nie je uspesne prehratie, hoci v nom niet chyby vstupu.

    features.archive.save zapise prazdnu maticu s jednym rozmerom a taky archiv odmietne uz citanie;
    verdikt nad nula riadkami preto dosiahne iba archiv zlozeny rucne.
    """
    archiv = tmp_path / "prazdny.npz"
    np.savez_compressed(
        archiv, schema=SCHEMA, mena=np.array(MENA), matica=np.zeros((0, len(MENA))),
        seq=np.zeros(0, dtype=np.int64), casy=np.zeros(0), valid=np.zeros(0, dtype=bool),
        perbin=np.zeros((0, len(ROZLOZENIE["bins"]), 4)), biny=np.array([b[0] for b in ROZLOZENIE["bins"]]),
        chain_ids=np.array([], dtype=str), quality_json="[]", quality_policy="behavioral-inputs-v1",
        layout_json=json.dumps(ROZLOZENIE, sort_keys=True))
    for hlavny, volba, model in ((cli.main, "--bundle", balik), (po._hlavny, "--model", metody["zscore"])):
        out = tmp_path / volba.strip("-")
        kod, _ = _prikaz(hlavny, "--threads", 2, "replay", volba, model, "--archive", archiv, "--out", out)
        stav = json.loads((out / "status.json").read_text())
        assert kod == 2 and stav["ok"] is False
        assert stav["processed"] == 0 and stav["stop_reason"] == "replay_complete"


@pytest.mark.parametrize("subor, vynimka", [("prazdny", EOFError), ("skrateny", zipfile.BadZipFile),
                                            ("smeti", ValueError), ("chyba", FileNotFoundError)])
def test_prehratie_necitatelneho_archivu_neskonci_nulou(kampan, balik, metody, tmp_path, subor, vynimka):
    """Subor archivu, ktory sa neda precitat: prehratie nevrati nulu a nenecha stav s ok=true.

    safeguard replay zachyti iba cast chyb citania (kod 2 a status.json s ok=false); prazdny a skrateny
    subor koncia vynimkou mimo nich a status.json nevznikne. tcn.porovnanie replay nezachyti ziadnu.
    """
    dobry = Path(kampan["dev"][0]["features"]).read_bytes()
    archiv = tmp_path / "archiv.npz"
    if subor != "chyba":
        archiv.write_bytes({"prazdny": b"", "skrateny": dobry[:len(dobry) // 2], "smeti": b"nie je archiv\n"}[subor])
    for hlavny, volba, model in ((cli.main, "--bundle", balik), (po._hlavny, "--model", metody["zscore"])):
        out = tmp_path / volba.strip("-")
        argv = ("--threads", 2, "replay", volba, model, "--archive", archiv, "--out", out)
        zachytena = hlavny is cli.main and vynimka in (ValueError, FileNotFoundError)
        if zachytena:
            assert _prikaz(hlavny, *argv)[0] == 2
        else:
            with pytest.raises(vynimka):
                _prikaz(hlavny, *argv)
        stav = json.loads((out / "status.json").read_text()) if (out / "status.json").exists() else None
        assert stav is None or stav["ok"] is False
        if hlavny is cli.main:
            assert (stav is not None) == zachytena


def test_vyhodnotenie_far_uvadza_tolerovane_riadky(kampan, prehratia, tmp_path):
    out = tmp_path / "far.json"
    _prejde(ev._hlavny, "far", "--corpus", kampan["index"], "--role", "dev",
            "--replay", *[beh[1] for beh in prehratia["tcn"]], "--out", out)
    values = json.loads(out.read_text())["values"]
    dane = values["dane_prijatim_korpusu"]
    assert dane["chyb_vstupu"] == dane["neplatnych_riadkov"] == 2  # sucet cez dve relacie s riadkom
    assert "invalid_rows" in dane["poznamka"]
    assert values["merane"]["skupin"] == 2


def test_suhrn_relacie_odlisi_neplatny_riadok_od_inej_chyby_vstupu(kampan, prehratia):
    """neplatnych_riadkov su iba riadky, ake moze tolerovat pravidlo; chyb_vstupu je kazda chyba vstupu."""
    _, out, _, _ = next(beh for beh in prehratia["tcn"] if beh[0]["id"] in kampan["s_riadkom"])
    riadky = [json.loads(r) for r in (out / "events.jsonl").read_text().splitlines()]
    suhrn = ev.suhrn_relacie(riadky, 5.0, 7.5)
    assert (suhrn["chyb_vstupu"], suhrn["neplatnych_riadkov"]) == (1, 1)
    chybny, = [r for r in riadky if r["model_state"] == "input_error"]
    i, = [i for i, r in enumerate(riadky) if r["seq"] == RIADOK + 20]
    riadky[i] = dict(copy.deepcopy(chybny), seq=riadky[i]["seq"], timestamp=riadky[i]["timestamp"],
                     reason="frame_order: sequence did not advance")
    suhrn = ev.suhrn_relacie(riadky, 5.0, 7.5)
    assert (suhrn["chyb_vstupu"], suhrn["neplatnych_riadkov"]) == (2, 1)


def test_vyhodnotenie_udalosti_nad_korpusom_kazdou_metodou(kampan, prehratia, tmp_path):
    for meno, behy in prehratia.items():
        out = tmp_path / (meno + ".json")
        _prejde(ev._hlavny, "udalosti", "--index", kampan["index"], "--role", "dev",
                "--replay", *[beh[1] for beh in behy], "--out", out)
        values = json.loads(out.read_text())["values"]
        assert set(values["prostredie_voci_baliku"].values()) == {"zhodne"}, meno
        assert values["udalosti"]["planovanych"] == values["udalosti"]["vykonanych"] == 4
        assert values["merane"]["prevadzka"] is not None and values["merane"]["skupin"] == 2
        dane = values["dane_prijatim_relacii"]
        assert dane["chyb_vstupu"] == dane["neplatnych_riadkov"] == 2, meno
        assert "invalid_rows" in dane["poznamka"]
        assert sorted(s["neplatnych_riadkov"] for s in values["relacie"].values()) == [0, 0, 1, 1]


def _prehratia_so_zmenou(kampan, behy, kam, zmena):
    """Kopie prehrati roly dev; v jednej relacii s tolerovanym riadkom prepise vystup zmena(riadky, chybny, stav).

    Zmenena je posledna z relacii s riadkom: kontrolu, ktora by citala iba prve prehratie, by zmena minula.
    """
    zmenena = [zaznam["id"] for zaznam, _, _, _ in behy if zaznam["id"] in kampan["s_riadkom"]][-1]
    assert zmenena != behy[0][0]["id"]
    adresare = []
    for zaznam, out, _, _ in behy:
        kopia = Path(shutil.copytree(out, kam / out.name))
        adresare.append(kopia)
        if zaznam["id"] == zmenena:
            riadky = [json.loads(r) for r in (kopia / "events.jsonl").read_text().splitlines()]
            stav = json.loads((kopia / "status.json").read_text())
            chybny, = [r for r in riadky if r["model_state"] == "input_error"]
            zmena(riadky, chybny, stav)
            (kopia / "events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in riadky))
            (kopia / "status.json").write_text(json.dumps(stav))
    return adresare


def _iny_prechod(riadky, chybny, stav):
    chybny["quality"]["truncated_traversals"] = ["modules"]


def _chyba_citania(riadky, chybny, stav):
    chybny["quality"]["read_errors"] = 1


def _iny_dovod(riadky, chybny, stav):
    chybny["reason"] = "frame_order: sequence did not advance"


def _druhy_neplatny(riadky, chybny, stav):
    """O riadok viac, nez pravidlo dovoli: skorovany riadok je druhym neplatnym a stav prehratia s tym sedi."""
    i, = [i for i, r in enumerate(riadky) if r["seq"] == RIADOK + 20]
    assert riadky[i]["score"] is not None and not riadky[i]["alarm_event"]
    riadky[i] = dict(copy.deepcopy(chybny), seq=riadky[i]["seq"], timestamp=riadky[i]["timestamp"])
    stav.update(input_errors=stav["input_errors"] + 1, scored=stav["scored"] - 1)


@pytest.mark.parametrize("zmena", [_druhy_neplatny, _iny_prechod, _chyba_citania, _iny_dovod],
                         ids=["nad_pocet", "iny_prechod", "chyba_citania", "iny_dovod"])
def test_vyhodnotenie_odmietne_chybu_vstupu_mimo_pravidla(kampan, prehratia, tmp_path, zmena):
    """Prehratie s chybou vstupu, ktoru pravidlo netoleruje, sa nevyhodnoti: FAR ani udalosti, TCN ani metoda."""
    adresare = {meno: _prehratia_so_zmenou(kampan, prehratia[meno], tmp_path / meno, zmena)
                for meno in ("tcn", "zscore")}
    with pytest.raises(ValueError, match="netoleruje"):
        ev.vyhodnot_far(kampan["index"], "dev", adresare["tcn"])
    for meno in adresare:
        with pytest.raises(ValueError, match="netoleruje"):
            ev.vyhodnot_udalosti(kampan["index"], adresare[meno], rola="dev")


def _zamlcany_riadok(riadky, chybny, stav):
    stav["input_errors"] = 0


def _skorovany_navyse(riadky, chybny, stav):
    stav["scored"] += 1


def _alarm_navyse(riadky, chybny, stav):
    stav["alarm_events"] += 1


@pytest.mark.parametrize("zmena", [_zamlcany_riadok, _skorovany_navyse, _alarm_navyse],
                         ids=["chyby_vstupu", "skorovane", "alarmy"])
def test_vyhodnotenie_odmietne_stav_ktory_nesedi_s_riadkami(kampan, prehratia, tmp_path, zmena):
    """Stav prehratia, ktory sa s riadkami rozchadza v jednom pocte, vyhodnotenie neprijme: FAR ani udalosti.

    Kazdy z troch poctov (chyby vstupu, skorovane riadky, alarmove udalosti) sa meni samostatne;
    stav s nulou chyb vstupu by tolerovany riadok zamlcal.
    """
    adresare = {meno: _prehratia_so_zmenou(kampan, prehratia[meno], tmp_path / meno, zmena)
                for meno in ("tcn", "zscore")}
    with pytest.raises(ValueError, match="status.json nesedi"):
        ev.vyhodnot_far(kampan["index"], "dev", adresare["tcn"])
    for meno in adresare:
        with pytest.raises(ValueError, match="status.json nesedi"):
            ev.vyhodnot_udalosti(kampan["index"], adresare[meno], rola="dev")


@pytest.mark.parametrize("neplatne, uvedene, hlaska", [
    ({RIADOK: NEUZAVRETY}, [], "incomplete features in accepted audit"),
    ({RIADOK: NEUZAVRETY, RIADOK + 20: NEUZAVRETY}, [RIADOK, RIADOK + 20],
     "more invalid rows than the protocol tolerates"),
    ({RIADOK: INY_PRECHOD}, [RIADOK], "cause the protocol does not tolerate"),
    ({RIADOK: CHYBA_CITANIA}, [RIADOK], "cause the protocol does not tolerate"),
], ids=["neuvedeny_v_audite", "nad_pocet", "iny_prechod", "chyba_citania"])
def test_trening_a_metody_odmietnu_riadok_mimo_pravidla(tmp_path, neplatne, uvedene, hlaska):
    """Index, ktory nevznikol stavbou korpusu: nacitanie treningu aj metod pravidlo overi samo."""
    index = _podvrh(_kampan(tmp_path / "kampan"), neplatne, uvedene)
    validate_index(index)
    with pytest.raises(ValueError, match=hlaska):
        train_bundle(index, tmp_path / "balik", window_rows=OKNO, max_gap_s=7.5, epochs=1, batch_size=64, fpr=FPR)
    with pytest.raises(ValueError, match=hlaska):
        po.nacitaj_role(index)


def test_zaznam_celeho_auditu_prijme_stavba_korpusu(kampan, tmp_path, monkeypatch):
    """Riadok, ktory toleruje cely audit_session, prijme stavba korpusu; rucne zlozene audity maju jeho tvar."""
    p, protokol_cesta, audit_cesta, kod = _relacia_cez_audit(tmp_path, monkeypatch, riadok=4)
    ostry = json.loads(audit_cesta.read_text())
    assert kod == 0 and ostry["values"]["accepted"] is True, ostry["values"]["reasons"]
    assert ostry["values"]["quality"]["tolerated_invalid_seq"] == [4]
    assert ostry["values"]["windows"] == 3  # okna koncia v riadkoch 3, 8 a 9; neplatny riadok stoji window_rows + 1 okien
    doc = dataset.build([audit_cesta], p, _sha(protokol_cesta))
    assert [z["group"] for z in doc["sessions"]] == ["v5-train-1"] and "events" in doc["sessions"][0]
    assert doc["complete"] is False  # jedna relacia planu; uplny korpus drzia testy vyssie
    index = json.loads(kampan["index"].read_text())
    for zaznam in index["sessions"]:
        rucny = json.loads(Path(zaznam["audit"]).read_text())
        # coverage a quality vracia analyze_windows v oboch pripadoch; ich kluce zavisia od priebehu relacie.
        hodnoty = {k: v for k, v in rucny["values"].items() if k not in ("coverage", "quality")}
        assert _mimo_tvaru(dict(rucny, values=hodnoty), ostry, "audit") == []
        assert set(rucny["values"]) <= set(ostry["values"])
        assert rucny["values"]["extractor_sha256"] == ostry["values"]["extractor_sha256"]
