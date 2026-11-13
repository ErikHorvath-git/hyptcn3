"""
klasifikator.py - samostatny klasifikator aktivit (VO6) nad oknami detektora.

CO TO JE
--------
Detektor anomalii (prediktor balika safeguard) sa uci iba na datasete 1
(benigny korpus) a tu sa nemeni: z balika sa vezme zmrazeny normalizator,
kontrakt priznakov a architektura, prediktor sa nenacita do optimalizatora
a jeho vahy sa po treningu overia proti manifestu balika. Klasifikator je NOVY
safeguard.model.Classifier nad tymi istymi oknami; jeho triedy su profily zataze
balika (quiet, steady, ...) a typy prevadzkovych udalosti protokolu v3
(protocol_config.events.classes v indexe udalosti). Ulohou je vysvetlit alarm
("co sa vo VM deje"), nie rozhodnut o skodlivosti (HONESTY P4).

ZNACKA OKNA (nikdy cela relacia pre relacie s udalostami, HONESTY kap. 5)
-----------------------------------------------------------------------
dataset 1, rola train/dev: znacka = scenar (profil) relacie - v nich ziadna
    udalost nie je;
dataset 2 (index udalosti v3): kategoria posledneho riadku okna podla
    tcn.eval.kategorie_udalosti, teda okno [t - (W-1)*perioda, t]:
      prekryva interval vykonanej udalosti -> typ udalosti,
      prekryva nevykonanu udalost alebo je v dozvuku (DOZVUK_S po udalosti)
        -> okno sa vynecha (znacka nie je ista),
      inak -> profil relacie.
Dve udalosti, ktore by mohli zasiahnut to iste okno, sa odmietnu.

ROZDELENIE
----------
Skupiny (boot) datasetu 2 su pevne v konfiguracii (config/klasifikator-v1.json):
polovica na trening klasifikatora, polovica na jeho test; prekryv alebo skupina
mimo rozdelenia sa odmietne. Checkpoint sa vybera iba podla roly dev datasetu 1
(krizova entropia na profiloch); okna udalosti vo vybere nie su, co je
obmedzenie zapisane v manifeste. Rola calibration a test_benign datasetu 1 sa
neotvara (test_benign je jednorazovy zaverecny test detektora, METODIKA kap. 5),
presnost profilov na nej sa preto tu neuvadza.

Pokracovanie mimo tohto modulu: zapojenie do `safeguard run` (aktivita pri
alarme) by menilo merajuci kod a balik, preto tu nie je.

python3 -m tcn.klasifikator train --bundle B --corpus C --events-index I \
    --config config/klasifikator-v1.json --out DIR
python3 -m tcn.klasifikator eval --classifier DIR --events-index I --out VYSLEDOK.json
"""

import argparse
import collections
import copy
import datetime
import json
import math
import os
import platform
import random
import shlex
import shutil
import sys
import tempfile

import numpy as np
import torch
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from torch import nn

from features.archive import load as load_archive
from safeguard.bundle import digest, load_bundle
from safeguard.features import WindowBuffer, arrays, check_frame, frames_from_archive
from safeguard.model import Classifier
from safeguard.training import validate_index
from tcn.eval import (DOZVUK_S, REPO, SCHEMA_INDEX_UDALOSTI, _alfa, _git_stav,
                      kategorie_udalosti, klasifikacia_aktivit)

SCHEMA_KONFIG = "hyptcn3/klasifikator-config/1"
SCHEMA_MANIFEST = "hyptcn3/activity-classifier/1"
SCHEMA_VYSLEDOK = "hyptcn3/activity-classifier-eval/1"
VAHY = ("inverzna_frekvencia", "ziadne")
ZDROJE = ("tcn/klasifikator.py", "tcn/eval.py", "safeguard/model.py", "safeguard/features.py",
          "safeguard/bundle.py", "tcn/model.py")


def _json(cesta):
    with open(cesta, encoding="utf-8") as fh:
        return json.load(fh)


def _cele(hodnota, minimum):
    return type(hodnota) is int and hodnota >= minimum


def nacitaj_konfig(cesta):
    """Konfiguracia a jej sha256; nejasne rozdelenie sa odmietne."""
    k = _json(cesta)
    if k.get("schema") != SCHEMA_KONFIG:
        raise ValueError("konfiguracia nema schemu %s" % SCHEMA_KONFIG)
    sk = k.get("skupiny", {})
    trening, test = sk.get("trening"), sk.get("test")
    for zoznam in (trening, test):
        if (not isinstance(zoznam, list) or not zoznam or len(set(zoznam)) != len(zoznam)
                or any(not isinstance(s, str) or not s for s in zoznam)):
            raise ValueError("skupiny trening/test musia byt neprazdne zoznamy roznych mien")
    if set(trening) & set(test):
        raise ValueError("skupiny treningu a testu klasifikatora sa prekryvaju: %s"
                         % ", ".join(sorted(set(trening) & set(test))))
    if not all(_cele(k.get(p), m) for p, m in (("seed", 0), ("epochs", 1), ("batch_size", 1))):
        raise ValueError("seed, epochs a batch_size musia byt cele cisla")
    lr = k.get("lr")
    if isinstance(lr, bool) or not isinstance(lr, (int, float)) or not math.isfinite(lr) or lr <= 0:
        raise ValueError("lr musi byt kladne konecne cislo")
    if not isinstance(k.get("pravidlo_znacky"), str) or not k["pravidlo_znacky"]:
        raise ValueError("konfiguracia nema popis pravidla znacky okna")
    if k.get("vahy_tried") not in VAHY or k.get("vyber_checkpointu") != "dev":
        raise ValueError("vahy_tried musi byt %s a vyber_checkpointu 'dev'" % " alebo ".join(VAHY))
    return k, digest(cesta)


def _skupina(zaznam, predpona):
    if not zaznam["group"].startswith(predpona):
        raise ValueError("skupina %s nema predponu protokolu %r" % (zaznam["group"], predpona))
    return zaznam["group"][len(predpona):]


def nacitaj_index_udalosti(cesta, konfig, kontrakt, perioda_s, diagnostic=False):
    """Index udalosti v3 s overenymi hashmi; relacie roztriedene podla rozdelenia konfiguracie."""
    index = _json(cesta)
    if index.get("schema") != SCHEMA_INDEX_UDALOSTI:
        raise ValueError("nie je index %s" % SCHEMA_INDEX_UDALOSTI)
    if index.get("complete") is not True and not diagnostic:
        raise ValueError("neuplny index udalosti je iba pre diagnosticky beh")
    p = index["protocol_config"]
    if (p["interval_s"], p["max_gap_s"], p["window_rows"]) != (
            perioda_s, kontrakt["max_gap_s"], kontrakt["window_rows"]):
        raise ValueError("perioda, medzera alebo okno indexu sa lisia od balika")
    typy = p["events"]["classes"]
    predpona = p.get("group_prefix", "")
    relacie = {"trening": [], "test": []}
    for z in index["sessions"]:
        skupina = _skupina(z, predpona)
        casti = [c for c in relacie if skupina in konfig["skupiny"][c]]
        if len(casti) != 1:
            raise ValueError("skupina %s nie je prave v jednej casti rozdelenia" % skupina)
        relacie[casti[0]].append(dict(z, skupina=skupina))
    for c, zoznam in relacie.items():
        chyba = set(konfig["skupiny"][c]) - {z["skupina"] for z in zoznam}
        if chyba:
            raise ValueError("skupiny %s nie su v indexe udalosti" % ", ".join(sorted(chyba)))
    return index, typy, relacie


def znacky_okien(casy, udalosti, profil, perioda_s, okno, typy):
    """Pre kazdy riadok (koniec okna): (znacka alebo None, poradie udalosti alebo None)."""
    sirka = (okno - 1) * perioda_s
    poradie = sorted(udalosti, key=lambda u: u["host_start_unix"])
    for a, b in zip(poradie, poradie[1:]):
        if b["host_start_unix"] - a["host_stopped_unix"] <= sirka:
            raise ValueError("dve udalosti mozu zasiahnut to iste okno; znacka by nebola jednoznacna")
    for u in udalosti:
        if u["type"] not in typy or type(u["executed"]) is not bool \
                or not u["host_start_unix"] <= u["host_stopped_unix"]:
            raise ValueError("udalost mimo protokolu alebo s neplatnym intervalom")
    kategorie = kategorie_udalosti([{"timestamp": t} for t in casy], udalosti, perioda_s, okno)
    out = []
    for t, k in zip(casy, kategorie):
        if k is None or k == "po_udalosti":
            out.append((None, None))
        elif k == "prevadzka":
            out.append((profil, None))
        else:
            i = next(i for i, u in enumerate(udalosti)
                     if u["host_start_unix"] <= t and t - sirka <= u["host_stopped_unix"])
            out.append((k, i))
    return out


class Okna:
    """Normalizovane polia relacii a indexy (relacia, koniec okna, znacka, udalost)."""

    def __init__(self, normalizer, kontrakt):
        self.normalizer, self.kontrakt = normalizer, kontrakt
        self.relacie, self.indexy = [], []

    def pridaj(self, meno, frames, znacky):
        """znacky: index triedy alebo None pre kazdy riadok; udalost: poradie udalosti alebo None."""
        if len(znacky) != len(frames):
            raise ValueError("pocet znaciek sa lisi od poctu riadkov")
        g, loc = self.normalizer.transform(*arrays(frames))
        r = len(self.relacie)
        self.relacie.append((meno, g, loc))
        buffer = WindowBuffer(self.kontrakt["window_rows"], self.kontrakt["max_gap_s"])
        for pozicia, (frame, (znacka, udalost)) in enumerate(zip(frames, znacky)):
            check_frame(frame, self.kontrakt)
            if buffer.push(frame) is not None and znacka is not None:
                self.indexy.append((r, pozicia, znacka, udalost))

    def batch(self, vyber):
        w = self.kontrakt["window_rows"]
        g, loc, y = [], [], []
        for i in vyber:
            r, koniec, znacka, _ = self.indexy[int(i)]
            _, ga, la = self.relacie[r]
            g.append(ga[koniec + 1 - w:koniec + 1])
            loc.append(la[koniec + 1 - w:koniec + 1])
            y.append(znacka)
        return (torch.as_tensor(np.stack(g), dtype=torch.float32),
                torch.as_tensor(np.stack(loc), dtype=torch.float32), torch.tensor(y, dtype=torch.long))

    def batches(self, velkost, poradie=None):
        poradie = np.arange(len(self.indexy)) if poradie is None else poradie
        for zaciatok in range(0, len(poradie), velkost):
            yield self.batch(poradie[zaciatok:zaciatok + velkost])


def _frames(zaznam, otvorene=None):
    if digest(zaznam["features"]) != zaznam["features_sha256"]:
        raise ValueError("archiv %s sa zmenil od indexu" % zaznam["id"])
    frames = frames_from_archive(load_archive(zaznam["features"]), zaznam["id"])
    if not frames or frames[0].timestamp != zaznam["start"] or frames[-1].timestamp != zaznam["end"]:
        raise ValueError("casy archivu %s sa lisia od indexu" % zaznam["id"])
    if otvorene is not None:
        otvorene.append(zaznam["id"])
    return frames


def _udalosti(zaznam):
    if digest(zaznam["events"]) != zaznam["events_sha256"]:
        raise ValueError("events.json relacie %s sa zmenil od indexu" % zaznam["id"])
    return _json(zaznam["events"])["events"]


def _okna_udalosti(okna, zaznamy, triedy, typy, perioda_s, otvorene=None):
    ind = {t: i for i, t in enumerate(triedy)}
    udalosti_relacii = {}
    for z in zaznamy:
        if z["scenario"] not in ind or z["scenario"] in typy:
            raise ValueError("scenar %s nie je profilom balika" % z["scenario"])
        frames, udalosti = _frames(z, otvorene), _udalosti(z)
        znacky = znacky_okien([f.timestamp for f in frames], udalosti, z["scenario"], perioda_s,
                              okna.kontrakt["window_rows"], typy)
        okna.pridaj(z["id"], frames, [(None if t is None else ind[t], u) for t, u in znacky])
        udalosti_relacii[z["id"]] = udalosti
    return udalosti_relacii


def _seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def _strata_dev(model, okna, velkost):
    model.eval()
    spolu = 0.0
    with torch.inference_mode():
        for g, loc, y in okna.batches(velkost):
            spolu += float(nn.functional.cross_entropy(model(g, loc), y, reduction="sum"))
    strata = spolu / len(okna.indexy)
    if not math.isfinite(strata):
        raise ValueError("nekonecna strata na dev")
    return strata


def _predikuj(model, okna, velkost):
    model.eval()
    out = []
    with torch.inference_mode():
        for g, loc, _ in okna.batches(velkost):
            out += model(g, loc).argmax(dim=-1).tolist()
    return out


def _zdroje():
    return {m: digest(os.path.join(REPO, m)) for m in ZDROJE}


def trenuj(balik_cesta, korpus, index_cesta, konfig_cesta, out, diagnostic=False):
    """Natrenuje klasifikator aktivit; prediktor balika sa nemeni. Vrati manifest."""
    konfig, konfig_sha = nacitaj_konfig(konfig_cesta)
    out = os.path.realpath(out)
    if os.path.exists(out):
        raise FileExistsError("vystup klasifikatora existuje; zvol novu nemennu cestu")
    balik = load_bundle(balik_cesta, allow_diagnostic=diagnostic)
    m = balik.manifest
    if m["provenance"]["corpus_index_sha256"] != digest(korpus):
        raise ValueError("balik nebol trenovany na tomto korpuse (dataset 1)")
    prediktor_sha = digest(os.path.join(balik_cesta, m["weights"]["predictor"]["file"]))
    prediktor_pred = copy.deepcopy(balik.predictor.state_dict())
    kontrakt, perioda = balik.contract, m["provenance"]["protocol"]["interval_s"]
    _, _, zaznamy1 = validate_index(korpus, diagnostic)
    index, typy, relacie2 = nacitaj_index_udalosti(index_cesta, konfig, kontrakt, perioda, diagnostic)
    profily = list(m["classes"])
    if set(profily) & (set(typy) | {"prevadzka", "po_udalosti"}):
        raise ValueError("typ udalosti ma rovnake meno ako profil")
    triedy = profily + sorted(typy)
    hashe1 = {z["features_sha256"] for z in zaznamy1}
    if any(z["features_sha256"] in hashe1 for c in relacie2.values() for z in c):
        raise ValueError("relacia indexu udalosti je aj v datasete 1")
    otvorene = []
    okna = {"trening": Okna(balik.normalizer, kontrakt), "dev": Okna(balik.normalizer, kontrakt)}
    for z in zaznamy1:
        if z["role"] in ("train", "dev"):  # calibration ani test_benign sa neotvara
            frames = _frames(z, otvorene)
            if z["scenario"] not in profily:
                raise ValueError("scenar %s nie je triedou balika" % z["scenario"])
            okna["trening" if z["role"] == "train" else "dev"].pridaj(
                z["id"], frames, [(profily.index(z["scenario"]), None)] * len(frames))
    _okna_udalosti(okna["trening"], relacie2["trening"], triedy, typy, perioda, otvorene)
    if {z["id"] for z in relacie2["test"]} & set(otvorene):
        raise RuntimeError("trening otvoril archiv testovacej skupiny")
    pocty = collections.Counter(okna["trening"].indexy[i][2] for i in range(len(okna["trening"].indexy)))
    chybaju = [triedy[i] for i in range(len(triedy)) if not pocty[i]]
    if chybaju or not okna["dev"].indexy:
        raise ValueError("trieda bez trenovacieho okna (%s) alebo prazdny dev" % ", ".join(chybaju))
    n = sum(pocty.values())
    vahy = (torch.tensor([n / (len(triedy) * pocty[i]) for i in range(len(triedy))], dtype=torch.float32)
            if konfig["vahy_tried"] == "inverzna_frekvencia" else None)
    stare_vlakna = torch.get_num_threads()
    torch.set_num_threads(min(stare_vlakna, 4))
    try:
        _seed(konfig["seed"])
        model = Classifier(m["architecture"], len(triedy))
        opt = torch.optim.Adam(model.parameters(), lr=konfig["lr"])
        rng = np.random.default_rng(konfig["seed"])
        najlepsia, stav, epocha_vyberu, historia = float("inf"), None, None, []
        for epocha in range(1, konfig["epochs"] + 1):
            model.train()
            spolu = 0.0
            for g, loc, y in okna["trening"].batches(konfig["batch_size"], rng.permutation(n)):
                opt.zero_grad(set_to_none=True)
                strata = nn.functional.cross_entropy(model(g, loc), y, weight=vahy)
                if not torch.isfinite(strata):
                    raise ValueError("nekonecna strata treningu")
                strata.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 5)
                opt.step()
                spolu += float(strata.detach()) * len(y)
            dev = _strata_dev(model, okna["dev"], konfig["batch_size"])
            historia.append({"epocha": epocha, "trening_strata": spolu / n, "dev_strata": dev})
            if dev < najlepsia:
                najlepsia, stav, epocha_vyberu = dev, copy.deepcopy(model.state_dict()), epocha
        model.load_state_dict(stav)
    finally:
        torch.set_num_threads(stare_vlakna)
    # Prediktor balika sa nemeni: ani subor, ani nacitane vahy.
    if digest(os.path.join(balik_cesta, m["weights"]["predictor"]["file"])) != prediktor_sha or any(
            not torch.equal(v, balik.predictor.state_dict()[k]) for k, v in prediktor_pred.items()):
        raise RuntimeError("vahy prediktora sa zmenili")
    commit, zmeny = _git_stav()
    manifest = {
        "schema": SCHEMA_MANIFEST, "diagnostic": bool(diagnostic),
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
        "triedy": triedy, "profily": profily, "typy_udalosti": dict(sorted(typy.items())),
        "architektura": m["architecture"],
        "konfig": konfig, "konfig_cesta": os.path.realpath(konfig_cesta), "konfig_sha256": konfig_sha,
        "seed": konfig["seed"], "rozdelenie": konfig["skupiny"],
        "balik": {"cesta": os.path.realpath(balik_cesta),
                  "manifest_sha256": digest(os.path.join(balik_cesta, "manifest.json")),
                  "predictor_sha256": prediktor_sha, "prediktor_nezmeneny": True,
                  "normalizator": "zmrazeny z balika (fit na role train datasetu 1)"},
        "vstupy": {"korpus": os.path.realpath(korpus), "korpus_sha256": digest(korpus),
                   "index_udalosti": os.path.realpath(index_cesta), "index_udalosti_sha256": digest(index_cesta),
                   "protocol_sha256": index["protocol_sha256"],
                   "relacie_datasetu_1": {z["id"]: z["features_sha256"] for z in zaznamy1
                                          if z["role"] in ("train", "dev")},
                   "relacie_datasetu_2_trening": {z["id"]: {"skupina": z["skupina"],
                                                            "features_sha256": z["features_sha256"],
                                                            "events_sha256": z["events_sha256"]}
                                                  for z in relacie2["trening"]},
                   "otvorene_archivy": otvorene},
        "trening": {"epochs": konfig["epochs"], "batch_size": konfig["batch_size"], "lr": konfig["lr"],
                    "vahy_tried": konfig["vahy_tried"], "vybrana_epocha": epocha_vyberu,
                    "historia": historia,
                    "okien_trening": {triedy[i]: pocty[i] for i in range(len(triedy))},
                    "okien_dev": len(okna["dev"].indexy),
                    "testovacie_archivy_otvorene": False,
                    "neotvorene_role_datasetu_1": ["calibration", "test_benign"]},
        "znacka_okna": konfig["pravidlo_znacky"], "dozvuk_s": DOZVUK_S,
        "zdroje_sha256": _zdroje(),
        "obmedzenia": [
            "checkpoint sa vybera iba podla dev datasetu 1 (profily); okna udalosti vo vybere nie su",
            "trieda je zaznamenane nastavenie zataze alebo typ benignej prevadzkovej udalosti, "
            "nie skodlivost ani rodina malveru (HONESTY P4)",
            "okna jednej relacie a jednej udalosti nie su nezavisle; nezavislou jednotkou je skupina (boot)"],
        "vahy": {},
    }
    rodic = os.path.dirname(out)
    os.makedirs(rodic, exist_ok=True)
    docasny = tempfile.mkdtemp(prefix="." + os.path.basename(out) + ".", dir=rodic)
    try:
        subor = os.path.join(docasny, "klasifikator.pt")
        torch.save(model.state_dict(), subor)
        manifest["vahy"] = {"subor": "klasifikator.pt", "sha256": digest(subor)}
        with open(os.path.join(docasny, "manifest.json"), "x", encoding="utf-8") as fh:
            fh.write(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
        os.rename(docasny, out)  # zlyha, ked medzitym vznikol neprazdny out
    finally:
        if os.path.exists(docasny):
            shutil.rmtree(docasny)
    return manifest


def nacitaj_klasifikator(adresar):
    """(manifest, model, balik); hashe vah, balika a rozdelenia sa overia."""
    manifest = _json(os.path.join(adresar, "manifest.json"))
    if manifest.get("schema") != SCHEMA_MANIFEST:
        raise ValueError("nie je klasifikator %s" % SCHEMA_MANIFEST)
    subor = os.path.join(adresar, manifest["vahy"]["subor"])
    if digest(subor) != manifest["vahy"]["sha256"]:
        raise ValueError("hash vah klasifikatora nesedi")
    b = manifest["balik"]
    if digest(os.path.join(b["cesta"], "manifest.json")) != b["manifest_sha256"]:
        raise ValueError("balik sa zmenil od treningu klasifikatora")
    balik = load_bundle(b["cesta"], allow_diagnostic=manifest["diagnostic"])
    model = Classifier(manifest["architektura"], len(manifest["triedy"]))
    model.load_state_dict(torch.load(subor, map_location="cpu", weights_only=True), strict=True)
    model.eval()
    return manifest, model, balik


def _clopper_pearson(k, m, alfa):
    from scipy.stats import beta
    if m == 0:
        return None
    return [0.0 if k == 0 else float(beta.ppf(alfa / 2, k, m - k + 1)),
            1.0 if k == m else float(beta.ppf(1 - alfa / 2, k + 1, m - k))]


def metriky_okien(y_true, y_pred, triedy):
    """Ten isty tvar ako klasifikacia_aktivit()['okna'] v tcn/eval.py."""
    ind = list(range(len(triedy)))
    p, r, f1, n = precision_recall_fscore_support(y_true, y_pred, labels=ind, zero_division=0)
    pritomne = sorted(set(y_true))
    return {"n": len(y_true), "presnost": float(np.mean(np.array(y_true) == np.array(y_pred))),
            "f1_macro": float(np.mean([f1[i] for i in pritomne])),
            "f1_macro_nad_triedami": [triedy[i] for i in pritomne],
            "na_triedu": {triedy[i]: {"precision": float(p[i]), "recall": float(r[i]),
                                      "f1": float(f1[i]), "n": int(n[i])} for i in pritomne},
            "predikovanych_na_triedu": {triedy[i]: int(c) for i, c in
                                        sorted(collections.Counter(y_pred).items())},
            "confusion": confusion_matrix(y_true, y_pred, labels=ind).tolist(), "poradie_tried": list(triedy)}


def vyhodnot(adresar, index_cesta, alfa=0.05):
    """Test klasifikatora na testovacich skupinach datasetu 2 (okna, udalosti, relacie)."""
    alfa = _alfa(alfa)
    manifest, model, balik = nacitaj_klasifikator(adresar)
    if digest(index_cesta) != manifest["vstupy"]["index_udalosti_sha256"]:
        raise ValueError("index udalosti nie je ten, s ktorym sa klasifikator trenoval")
    konfig = manifest["konfig"]
    triedy, profily = manifest["triedy"], manifest["profily"]
    perioda = balik.manifest["provenance"]["protocol"]["interval_s"]
    _, typy, relacie2 = nacitaj_index_udalosti(index_cesta, konfig, balik.contract, perioda,
                                               manifest["diagnostic"])
    okna = Okna(balik.normalizer, balik.contract)
    udalosti = _okna_udalosti(okna, relacie2["test"], triedy, typy, perioda)
    if not okna.indexy:
        raise ValueError("testovacie skupiny nemaju ziadne okno so znackou")
    y_pred = _predikuj(model, okna, konfig["batch_size"])
    y_true = [ix[2] for ix in okna.indexy]
    # Profily: vacsinovy hlas relacie cez okna mimo udalosti a dozvuku (klasifikacia_aktivit).
    relacie = {meno: {"scenario": next(z["scenario"] for z in relacie2["test"] if z["id"] == meno),
                      "predikcie_aktivity": collections.Counter()} for meno, _, _ in okna.relacie}
    po_udalostiach = collections.defaultdict(collections.Counter)
    for (r, _, znacka, u), pred in zip(okna.indexy, y_pred):
        meno = okna.relacie[r][0]
        if u is None:
            relacie[meno]["predikcie_aktivity"][triedy[pred]] += 1
        else:
            po_udalostiach[(meno, u)][triedy[pred]] += 1
    profil = klasifikacia_aktivit({k: dict(v, predikcie_aktivity=dict(v["predikcie_aktivity"]))
                                   for k, v in relacie.items() if v["predikcie_aktivity"]}, triedy, alfa)
    zoznam = []
    for meno in sorted(udalosti):
        skupina = next(z["skupina"] for z in relacie2["test"] if z["id"] == meno)
        for i, u in enumerate(udalosti[meno]):
            pocty = po_udalostiach.get((meno, i), {})
            vacsina = max(sorted(pocty), key=lambda t: pocty[t]) if pocty else None
            zoznam.append({"relacia": meno, "skupina": skupina, "type": u["type"], "executed": u["executed"],
                           "start_unix": u["host_start_unix"], "stop_unix": u["host_stopped_unix"],
                           "okien": sum(pocty.values()), "predikcie": dict(sorted(pocty.items())),
                           "vacsinova_predikcia": vacsina, "spravne": vacsina == u["type"] if pocty else None})
    hodnotene = [z for z in zoznam if z["spravne"] is not None]
    spravne = sum(z["spravne"] for z in hodnotene)
    na_typ = {}
    for t in sorted(typy):
        h = [z for z in hodnotene if z["type"] == t]
        k = sum(z["spravne"] for z in h)
        na_typ[t] = {"spravnych": k, "spolu": len(h), "interval": _clopper_pearson(k, len(h), alfa)}
    return {
        "schema": SCHEMA_VYSLEDOK, "alfa": alfa, "synteticke_alebo_diagnosticke": manifest["diagnostic"],
        "klasifikator": os.path.realpath(adresar),
        "klasifikator_manifest_sha256": digest(os.path.join(adresar, "manifest.json")),
        "klasifikator_vahy_sha256": manifest["vahy"]["sha256"],
        "balik_manifest_sha256": manifest["balik"]["manifest_sha256"],
        "index_udalosti": os.path.realpath(index_cesta), "index_udalosti_sha256": digest(index_cesta),
        "konfig_sha256": manifest["konfig_sha256"], "rozdelenie": manifest["rozdelenie"],
        "testovacie_relacie": {z["id"]: {"skupina": z["skupina"], "features_sha256": z["features_sha256"],
                                         "events_sha256": z["events_sha256"]} for z in relacie2["test"]},
        "triedy": triedy, "znacka_okna": manifest["znacka_okna"],
        "okna": metriky_okien(y_true, y_pred, triedy),
        "relacie_profil": profil,
        "udalosti": {"planovanych": len(zoznam), "vykonanych": sum(z["executed"] for z in zoznam),
                     "hodnotenych": len(hodnotene), "spravnych": spravne,
                     "presnost": spravne / len(hodnotene) if hodnotene else None,
                     "interval": _clopper_pearson(spravne, len(hodnotene), alfa),
                     "interval_metoda": "Clopper-Pearson", "na_typ": na_typ, "zoznam": zoznam},
        "skupin": len({z["skupina"] for z in relacie2["test"]}),
        "poznamka": ("Test na skupinach datasetu 2, ktore klasifikator ani detektor nevideli. Trieda je profil "
                     "zataze alebo typ benignej udalosti, nie skodlivost (HONESTY P4). Okna jednej relacie a "
                     "udalosti nie su nezavisle; uvadza sa preto aj vacsinovy hlas na udalost a relaciu."),
    }


def _hlavny(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="python3 -m tcn.klasifikator", description="klasifikator aktivit (VO6)")
    sub = p.add_subparsers(dest="prikaz", required=True)
    t = sub.add_parser("train", help="natrenuje klasifikator nad zmrazenym balikom")
    t.add_argument("--bundle", required=True, help="adresar balika safeguard (prediktor sa nemeni)")
    t.add_argument("--corpus", required=True, help="index datasetu 1 (corpus.json), na ktorom bol balik trenovany")
    t.add_argument("--events-index", required=True, help="events_index.json datasetu 2 (protokol v3)")
    t.add_argument("--config", required=True, help="napr. config/klasifikator-v1.json")
    t.add_argument("--out", required=True, help="novy adresar; existujuci sa neprepise")
    t.add_argument("--diagnostic", action="store_true", help="iba synteticke/diagnosticke vstupy")
    e = sub.add_parser("eval", help="test klasifikatora na testovacich skupinach datasetu 2")
    e.add_argument("--classifier", required=True, help="vystup prikazu train")
    e.add_argument("--events-index", required=True)
    e.add_argument("--out", required=True, help="novy JSON; existujuci sa neprepise")
    e.add_argument("--alfa", type=float, default=0.05)
    a = p.parse_args(argv)
    if a.prikaz == "train":
        m = trenuj(a.bundle, a.corpus, a.events_index, a.config, a.out, a.diagnostic)
        print(json.dumps({"out": os.path.realpath(a.out), "triedy": m["triedy"],
                          "vybrana_epocha": m["trening"]["vybrana_epocha"]}, ensure_ascii=False))
        return 0
    values = vyhodnot(a.classifier, a.events_index, a.alfa)
    commit, zmeny = _git_stav()
    doc = {"commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
           "evaluator_sha256": digest(os.path.abspath(__file__)),
           "date": datetime.datetime.now(datetime.timezone.utc).isoformat(), "host": platform.platform(),
           "guest": None if values["synteticke_alebo_diagnosticke"] else "hyptcn-guest (index udalosti v3)",
           "command": shlex.join(["python3", "-m", "tcn.klasifikator", *argv]), "cwd": os.getcwd(),
           "n": values["okna"]["n"], "values": values}
    with open(a.out, "x", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"okna_presnost": values["okna"]["presnost"], "okna_f1_macro": values["okna"]["f1_macro"],
                      "udalosti": [values["udalosti"]["spravnych"], values["udalosti"]["hodnotenych"]],
                      "relacie": [values["relacie_profil"]["relacie"]["spravnych"],
                                  values["relacie_profil"]["relacie"]["spolu"]]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_hlavny())
