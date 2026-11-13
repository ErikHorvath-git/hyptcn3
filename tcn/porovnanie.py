"""
porovnanie.py - anomalne baseliny a pamatova ablacia TCN nad vstupmi safeguardu (E4, VO4).

CO SA POROVNAVA
---------------
TCN prediktor safeguardu (safeguard.training.train_bundle) proti detektorom
anomalii trenovanym IBA na benignych oknach toho isteho korpusu (dataset 1):

  zscore     ZScoreAnomalia nad priemerom okna (tcn/baselines.py)
  iforest    IsolationForestAnomalia nad rozvinutym oknom
  gru        GRUPrediktor, pocet parametrov najblizsie k TCN prediktoru
  lstm       LSTMPrediktor, to iste s LSTM
  tcn_pamat  ablacia (konfunder): ten isty safeguard.model.Predictor, ale
             globalna vetva dostane iba 8 pamatovych agregatov (mem_*),
             bez poctov procesov, modulov a socketov; per-bin vetva ostava.
             Otazka: pochadza vysledok iba z poctov, ktore sa menia so zatazou?

ROVNAKE OKNA, ROVNAKY PRAH, ROVNAKY ALARM
----------------------------------------
Okna, normalizacia a roly su presne tie zo safeguard/training.py: overenie
indexu validate_index, Windows (32 riadkov, bariery WindowBuffer), normalizer
FeatureNormalizer fitnuty na train, test_benign sa nenacita vobec. Fit na
train, vyber checkpointu na dev (iba siete; zscore a iforest nemaju co
vyberat - pevne hyperparametre), prah = safeguard.training.calibrate nad
skore roly calibration (kvantil 1 - fpr, metoda "higher", porovnanie ">").
Prehratie archivu ide cez safeguard.runtime.replay_archive - ten isty
Detector s tym istym pravidlom k z n a resetmi na barierach; tento modul
mu podstrci iba objekt s rozhranim balika (contract, threshold, k, n,
manifest, score). Riadky events.jsonl maju preto schemu a tvar
hyptcn3/safeguard-events/1 a adresar prehratia je ten, ktory cita
tcn.eval._nacitaj_prehratie (configuration.json, status.json, events.jsonl);
vyhodnot_udalosti ho spracuje bez zmeny.

CO BASELINY VIDIA
-----------------
18 globalnych behavioralnych stlpcov a per-bin tenzor ZHRNUTY cez biny
(baselines.zluc_biny: priemer a maximum 4 per-bin kanalov, ako
safeguard.model.Classifier) - 26 stlpcov na krok. GRU/LSTM predpovedaju z
krokov 1..L-1 krok L: 18 globalnych a 6 zhrnutych hodnotovych kanalov (masky
has_changed sa nepredpovedaju, rovnako ako v TCN); skore = 0.5 * mean(chyba
globalnych) + 0.5 * mean(chyba zhrnutych binov). TCN vidi biny jednotlivo a
berie maximum chyby cez biny; baseliny tuto lokalizaciu nemaju - to je
vlastnost porovnania, nie chyba.

OBMEDZENIA
----------
Riadky nemaju klasifikaciu aktivity (activity = None, classes = []), preto
tcn.eval.vyhodnot_far (ktory pocita aj klasifikaciu aktivit) na tieto
prehratia nepouzivat; FAR na cistej prevadzke a pri udalostiach dava
vyhodnot_udalosti. iforest sa uklada pickle-om; nacitanie overi sha256 z
manifestu (ochrana proti poskodeniu, nie autentifikacia).
"""

import argparse
import copy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import pickle
import platform
import random
import shlex
import shutil
import sys
import tempfile

import numpy as np
import torch
from torch import nn

from features.archive import load as load_archive
from safeguard.bundle import digest
from safeguard.features import (GLOBAL_NAMES, LOCAL_NAMES, FeatureNormalizer, WindowBuffer,
                                arrays, check_frame, feature_contract, frames_from_archive)
from safeguard.model import Predictor, anomaly_score, architecture, prediction_errors
from safeguard.runtime import replay_archive
from safeguard.training import ROLES, Windows, calibrate, validate_index
from tcn.baselines import (GRUPrediktor, IsolationForestAnomalia, LSTMPrediktor,
                           ZScoreAnomalia, skryte_pre_prediktor, zluc_biny)
from tcn.model import TCNPrediktor, pocet_parametrov

SCHEMA_MODEL = "hyptcn3/porovnanie-model/1"
SCHEMA_KONFIGURACIA = "hyptcn3/safeguard-configuration/1"
SCHEMA_STAV = "hyptcn3/safeguard-run/1"
MODELY = ("zscore", "iforest", "gru", "lstm", "tcn_pamat")
REPO = Path(__file__).resolve().parents[1]

PAMAT = tuple(GLOBAL_NAMES[:8])
if not all(meno.startswith("mem_") for meno in PAMAT) or any(
        meno.startswith("mem_") for meno in GLOBAL_NAMES[8:]):
    raise ImportError("poradie GLOBAL_NAMES sa zmenilo; pamatove stlpce nie su prvych 8")
ZLUCENE = (tuple(GLOBAL_NAMES) + tuple("bin_mean_" + m for m in LOCAL_NAMES)
           + tuple("bin_max_" + m for m in LOCAL_NAMES))
# Ciel GRU/LSTM: globalne + zhrnute hodnotove kanaly; maska has_changed nie je ciel.
G = len(GLOBAL_NAMES)
CIEL = tuple(range(G)) + tuple(G + i for i in range(3)) + tuple(G + 4 + i for i in range(3))

VZORCE = {
    "zscore": "mean_f(((mean_t x_f) - mu_f) / sd_f)^2 nad 26 zlucenymi stlpcami; mu, sd z train okien",
    "iforest": "-score_samples(rozvinute okno L x 26); IsolationForest(200 stromov) fit na train oknach",
    "gru": "0.5 * mean(chyba^2 18 globalnych) + 0.5 * mean(chyba^2 6 zhrnutych per-bin kanalov)",
    "lstm": "0.5 * mean(chyba^2 18 globalnych) + 0.5 * mean(chyba^2 6 zhrnutych per-bin kanalov)",
    "tcn_pamat": "0.5 * mean(global_squared_error nad 8 mem_*) + 0.5 * max(bin_masked_mse)",
}


# ------------------------------------------------------------------ data


def nacitaj_role(korpus, *, diagnostic=False):
    """Roly train/dev/calibration ako Windows - tym istym postupom ako train_bundle.

    test_benign sa nenacita (iba metadata a hashe overi validate_index).
    """
    index, protokol, zaznamy = validate_index(korpus, diagnostic)
    window_rows, max_gap = protokol["window_rows"], protokol["max_gap_s"]
    relacie = {rola: [] for rola in ROLES[:-1]}
    kontrakt = None
    for zaznam in zaznamy:
        if zaznam["role"] == "test_benign":
            continue
        snimky = list(frames_from_archive(load_archive(zaznam["features"]), zaznam["id"]))
        if not snimky or snimky[0].timestamp != zaznam["start"] or snimky[-1].timestamp != zaznam["end"]:
            raise ValueError("casy archivu sa lisia od indexu korpusu")
        if any(not s.valid for s in snimky):
            raise ValueError("prijaty archiv obsahuje neplatne riadky")
        if kontrakt is None:
            kontrakt = feature_contract(snimky[0], window_rows, max_gap)
        if snimky[0].layout != json.loads(Path(zaznam["audit"]).read_text())["values"]["layout"]:
            raise ValueError("layout archivu sa lisi od auditu")
        for s in snimky:
            check_frame(s, kontrakt)
        relacie[zaznam["role"]].append((zaznam, snimky))
    fit_riadky = [s for _, snimky in relacie["train"] for s in snimky
                  if s.valid and s.has_predecessor and not s.full]
    normalizer = FeatureNormalizer.fit(fit_riadky)
    triedy = sorted({z["scenario"] for z, _ in relacie["train"]})
    data = {rola: Windows(r, normalizer, kontrakt, triedy) for rola, r in relacie.items()}
    return {"index": index, "protokol": protokol, "zaznamy": zaznamy, "kontrakt": kontrakt,
            "normalizer": normalizer, "fit_riadky": len(fit_riadky), "data": data}


def _davky(okna, velkost, poradie=None):
    for g, lokalne, _ in okna.batches(velkost, poradie):
        yield g, lokalne


# ------------------------------------------------------------------ modely


class PrediktorPamat(Predictor):
    """safeguard.model.Predictor s globalnou vetvou iba nad 8 pamatovymi stlpcami.

    forward a per-bin vetva su zdedene bez zmeny; meni sa iba vstupny rozmer
    globalneho TCNPrediktora (8 namiesto 18). Konfiguracia je architecture().
    """

    def __init__(self, config):
        super().__init__(config)
        self.global_tcn = TCNPrediktor(len(PAMAT), kanaly=config["channels"], k=config["kernel"],
                                       blokov=config["blocks"], dropout=config["dropout"],
                                       dlzka_okna=config["window_rows"])

    def forward(self, global_context, local_context):
        if global_context.shape[-1] != len(PAMAT):
            raise ValueError("PrediktorPamat ocakava presne %d globalnych stlpcov" % len(PAMAT))
        return super().forward(global_context, local_context)


def _chyba_zlucena(predikcia, ciel):
    e = (predikcia - ciel).square()
    return 0.5 * e[:, :G].mean(dim=-1) + 0.5 * e[:, G:].mean(dim=-1)


class _Siet:
    """Spolocny trening sieti: Adam 1e-3, orezanie gradientu 5, vyber na dev."""

    def __init__(self, meno, window_rows, siet=None, skryte=None):
        self.meno = meno
        self.window_rows = window_rows
        self.cielovy_pocet = pocet_parametrov(Predictor(architecture(window_rows)))
        if meno == "tcn_pamat":
            self.config = architecture(window_rows)
            self.siet = siet or PrediktorPamat(self.config)
            self.skryte = None
        else:
            trieda = GRUPrediktor if meno == "gru" else LSTMPrediktor
            if skryte is None:
                skryte, _ = skryte_pre_prediktor(trieda, len(ZLUCENE), len(CIEL), self.cielovy_pocet)
            self.skryte = skryte
            self.siet = siet or trieda(len(ZLUCENE), skryte, len(CIEL))

    def _chyby(self, g, lokalne):
        if self.meno == "tcn_pamat":
            gp = g[..., :len(PAMAT)]
            pred = self.siet(gp[:, :-1], lokalne[:, :-1])
            return prediction_errors(pred, gp[:, -1], lokalne[:, -1])
        x = zluc_biny(g, lokalne)
        return (_chyba_zlucena(self.siet(x[:, :-1]), x[:, -1, list(CIEL)]),)

    def _strata(self, g, lokalne):
        chyby = self._chyby(g, lokalne)
        if self.meno == "tcn_pamat":
            return 0.5 * chyby[0].mean() + 0.5 * chyby[1].mean()
        return chyby[0].mean()

    def skore(self, g, lokalne):
        self.siet.eval()
        with torch.inference_mode():
            chyby = self._chyby(torch.as_tensor(g, dtype=torch.float32),
                                torch.as_tensor(lokalne, dtype=torch.float32))
            s = anomaly_score(*chyby) if self.meno == "tcn_pamat" else chyby[0]
        return s.double().numpy()

    def _dev(self, okna, velkost):
        self.siet.eval()
        spolu = 0.0
        with torch.inference_mode():
            for g, lokalne in _davky(okna, velkost):
                spolu += float(self._strata(g, lokalne)) * len(g)
        vysledok = spolu / len(okna.indices)
        if not math.isfinite(vysledok):
            raise ValueError("nekonecna strata na dev")
        return vysledok

    def fit(self, data, *, seed, epochy, davka):
        generator = np.random.default_rng(seed)
        opt = torch.optim.Adam(self.siet.parameters(), lr=0.001)
        najlepsia, stav, epocha_vyberu, historia = float("inf"), None, None, []
        for epocha in range(1, epochy + 1):
            self.siet.train()
            spolu, pocet = 0.0, 0
            poradie = generator.permutation(len(data["train"].indices))
            for g, lokalne in _davky(data["train"], davka, poradie):
                opt.zero_grad(set_to_none=True)
                strata = self._strata(g, lokalne)
                if not torch.isfinite(strata):
                    raise ValueError("nekonecna strata pri treningu")
                strata.backward()
                nn.utils.clip_grad_norm_(self.siet.parameters(), 5)
                opt.step()
                spolu += float(strata.detach()) * len(g)
                pocet += len(g)
            dev = self._dev(data["dev"], davka)
            historia.append({"epoch": epocha, "train_loss": spolu / pocet, "dev_loss": dev})
            if dev < najlepsia:
                najlepsia, stav, epocha_vyberu = dev, copy.deepcopy(self.siet.state_dict()), epocha
        self.siet.load_state_dict(stav)
        self.siet.eval()
        return {"checkpoint_selection_role": "dev", "selected_epoch": epocha_vyberu,
                "dev_loss": najlepsia, "history": historia}

    def parametre(self):
        return {"parametrov": pocet_parametrov(self.siet), "parametrov_tcn_prediktor": self.cielovy_pocet,
                "skryte": self.skryte,
                "architektura": self.config if self.meno == "tcn_pamat" else None,
                "globalne_stlpce": list(PAMAT) if self.meno == "tcn_pamat" else list(GLOBAL_NAMES)}

    def uloz(self, adresar):
        subor = adresar / "model.pt"
        torch.save(self.siet.state_dict(), subor)
        return {"file": subor.name, "sha256": digest(subor)}

    @classmethod
    def nacitaj(cls, adresar, manifest):
        p = manifest["parametre"]
        model = cls(manifest["model"], manifest["feature_contract"]["window_rows"], skryte=p["skryte"])
        model.siet.load_state_dict(torch.load(adresar / "model.pt", map_location="cpu", weights_only=True),
                                   strict=True)
        model.siet.eval()
        if pocet_parametrov(model.siet) != p["parametrov"]:
            raise ValueError("pocet parametrov sa lisi od manifestu")
        return model


class _ZScore:
    meno = "zscore"

    def __init__(self, m=None):
        self.m = m or ZScoreAnomalia(ZLUCENE, indikatory=())

    @staticmethod
    def _priemery(g, lokalne):
        # (N, 1, F): ZScoreAnomalia priemeruje cez os 1, takze vysledok je ten isty
        return zluc_biny(g, lokalne).double().numpy().mean(axis=1, keepdims=True)

    def fit(self, data, *, seed, epochy, davka):
        self.m.fit(np.concatenate([self._priemery(g, l) for g, l in _davky(data["train"], 256)]))
        return {"checkpoint_selection_role": None, "dovod": "bez hyperparametrov na vyber"}

    def skore(self, g, lokalne):
        return self.m.skore(self._priemery(g, lokalne))

    def parametre(self):
        return {"mu": self.m.mu.tolist(), "sd": self.m.sd.tolist(), "stlpce": list(ZLUCENE)}

    def uloz(self, adresar):
        return None

    @classmethod
    def nacitaj(cls, adresar, manifest):
        m = ZScoreAnomalia(ZLUCENE, indikatory=())
        p = manifest["parametre"]
        if p["stlpce"] != list(ZLUCENE):
            raise ValueError("zscore: ine stlpce nez tento kod")
        m.mu, m.sd = np.asarray(p["mu"], dtype=np.float64), np.asarray(p["sd"], dtype=np.float64)
        return cls(m)


class _IForest:
    meno = "iforest"

    def __init__(self, m=None, seed=0):
        self.m = m or IsolationForestAnomalia(seed=seed)

    @staticmethod
    def _okna(g, lokalne):
        return zluc_biny(g, lokalne).double().numpy()

    def fit(self, data, *, seed, epochy, davka):
        self.m = IsolationForestAnomalia(seed=seed)
        self.m.fit(np.concatenate([self._okna(g, l) for g, l in _davky(data["train"], 256)]))
        return {"checkpoint_selection_role": None, "dovod": "pevne hyperparametre (200 stromov, auto)"}

    def skore(self, g, lokalne):
        return self.m.skore_nezaporne(self._okna(g, lokalne))

    def parametre(self):
        return {"n_estimators": self.m.m.n_estimators, "stlpce": list(ZLUCENE)}

    def uloz(self, adresar):
        subor = adresar / "iforest.pkl"
        subor.write_bytes(pickle.dumps(self.m.m, protocol=pickle.HIGHEST_PROTOCOL))
        return {"file": subor.name, "sha256": digest(subor)}

    @classmethod
    def nacitaj(cls, adresar, manifest):
        m = IsolationForestAnomalia()
        m.m = pickle.loads((adresar / "iforest.pkl").read_bytes())  # sha256 overene vopred
        return cls(m)


def _trieda(meno):
    if meno not in MODELY:
        raise ValueError("neznamy model %r; moznosti: %s" % (meno, ", ".join(MODELY)))
    return {"zscore": _ZScore, "iforest": _IForest}.get(meno, _Siet)


def _novy_model(meno, window_rows):
    trieda = _trieda(meno)
    return trieda(meno, window_rows) if trieda is _Siet else trieda()


# ------------------------------------------------------------------ balik


class Balik:
    """Objekt s rozhranim safeguard.bundle.Bundle, ktory pouziva runtime.Detector."""

    def __init__(self, manifest, model, normalizer):
        self.manifest, self.model, self.normalizer = manifest, model, normalizer

    @property
    def contract(self):
        return self.manifest["feature_contract"]

    @property
    def threshold(self):
        return float(self.manifest["calibration"]["threshold"])

    @property
    def k(self):
        return self.manifest["calibration"]["k"]

    @property
    def n(self):
        return self.manifest["calibration"]["n"]

    def score(self, window):
        # Ta ista kontrola okna ako safeguard.bundle.Bundle.score.
        if len(window) != self.contract["window_rows"]:
            raise ValueError("dlzka okna sa lisi od modelu")
        buffer = WindowBuffer(self.contract["window_rows"], self.contract["max_gap_s"])
        prijate = None
        for snimka in window:
            check_frame(snimka, self.contract)
            prijate = buffer.push(snimka)
        if prijate is None:
            raise ValueError("neplatne alebo prerusene okno: " + str(buffer.reason))
        g, lokalne = self.normalizer.transform(*arrays(window))
        s = float(self.model.skore(g[None], lokalne[None])[0])
        if not math.isfinite(s):
            raise ValueError("nekonecne skore modelu")
        return {"score": s, "baseline": self.manifest["model"], "activity": None,
                "activity_probabilities": {}}


def _skore_roly(model, okna, davka=256):
    return np.concatenate([np.asarray(model.skore(g, l), dtype=np.float64) for g, l in _davky(okna, davka)])


def _hlavicka(argv):
    from tcn.eval import _git_stav
    commit, zmeny = _git_stav()
    return {"commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
            "zmenene": zmeny, "porovnanie_sha256": digest(Path(__file__)),
            "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
            "command": shlex.join(["python3", "-m", "tcn.porovnanie", *(argv or [])]), "cwd": os.getcwd()}


def _referencia(cesta, korpus_sha):
    manifest = json.loads((Path(cesta) / "manifest.json").read_text())
    if manifest["provenance"]["corpus_index_sha256"] != korpus_sha:
        raise ValueError("referencny balik TCN nebol trenovany na tomto korpuse")
    from tcn.eval import _manifest_sha
    return manifest, _manifest_sha(manifest)


def fit(korpus, meno, out, *, seed=0, epochy=10, davka=32, fpr=0.01, k=3, n=5,
        diagnostic=False, referencia=None, argv=None):
    """Fit na train, vyber na dev, prah na calibration; vysledok je adresar modelu."""
    if (type(seed) is not int or type(epochy) is not int or epochy < 1 or type(davka) is not int
            or davka < 1 or type(k) is not int or type(n) is not int or not 1 <= k <= n
            or not math.isfinite(fpr) or not 0 < fpr < 1):
        raise ValueError("neplatne parametre fitu")
    trieda = _trieda(meno)
    out = Path(out).resolve()
    if out.exists():
        raise FileExistsError("vystup existuje; zvol novu cestu")
    korpus = Path(korpus).resolve()
    korpus_sha = digest(korpus)
    ref = None
    if referencia is not None:
        ref_manifest, ref_sha = _referencia(referencia, korpus_sha)
        kal = ref_manifest["calibration"]
        if (kal["fpr_design"], kal["k"], kal["n"]) != (fpr, k, n):
            raise ValueError("fpr/k/n sa lisia od referencneho balika TCN (%s, %s, %s)"
                             % (kal["fpr_design"], kal["k"], kal["n"]))
        ref = {"balik": str(Path(referencia).resolve()), "manifest_sha256": ref_sha,
               "threshold": kal["threshold"], "seed": ref_manifest["training"]["seed"]}
    d = nacitaj_role(korpus, diagnostic=diagnostic)
    protokol, data = d["protokol"], d["data"]
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    stare = torch.get_num_threads()
    torch.set_num_threads(min(stare, 4))
    try:
        model = _novy_model(meno, protokol["window_rows"])
        trening = model.fit(data, seed=seed, epochy=epochy, davka=davka)
        skore_kal = _skore_roly(model, data["calibration"])
        kalibracia = calibrate(skore_kal, data["calibration"], fpr=fpr, k=k, n=n,
                               interval_s=protokol["interval_s"], diagnostic=diagnostic)
        skore_dev = _skore_roly(model, data["dev"])
    finally:
        torch.set_num_threads(stare)
    prvy = d["zaznamy"][0]
    meta = json.loads(Path(prvy["session"]).read_text())
    audit = json.loads(Path(prvy["audit"]).read_text())
    zdroje = {str(p.relative_to(REPO)): digest(p)
              for adresar in ("safeguard", "tcn", "features", "guestparse")
              for p in (REPO / adresar).rglob("*.py") if "tests" not in p.parts}
    manifest = {
        "schema": SCHEMA_MODEL, "model": meno, "diagnostic": bool(diagnostic),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "feature_contract": d["kontrakt"], "normalizer": d["normalizer"].to_dict(),
        "vstup": {"globalne": list(PAMAT) if meno == "tcn_pamat" else list(GLOBAL_NAMES),
                  "per_bin": ("kazdy bin zvlast (zdielany TCN)" if meno == "tcn_pamat"
                              else "zhrnute cez biny: priemer a maximum 4 kanalov (zluc_biny)"),
                  "stlpce_na_krok": None if meno == "tcn_pamat" else list(ZLUCENE)},
        "score_formula": VZORCE[meno], "parametre": model.parametre(), "classes": [],
        "environment": {"kernel": meta["guest_before"]["kernel"],
                        "stack_sha256": meta["guest_before"]["stack_sha256"],
                        "collector_sha256": meta["collector_sha256"],
                        "profile_sha256": meta.get("profile_sha256", {}),
                        "extractor_sha256": audit["values"]["extractor_sha256"]},
        "calibration": kalibracia, "weights": {}, "referencny_tcn": ref,
        "training": {"seed": seed, "epochs": epochy, "batch_size": davka,
                     "normalization_fit_role": "train", **trening,
                     "windows": {rola: len(okna.indices) for rola, okna in data.items()},
                     "normalization_rows": d["fit_riadky"], "test_feature_arrays_loaded": False,
                     "dev_skore": {"n": len(skore_dev), "priemer": float(skore_dev.mean()),
                                   "median": float(np.median(skore_dev)),
                                   "nad_prahom_podiel": float((skore_dev > kalibracia["threshold"]).mean())}},
        "provenance": {"corpus_index": str(korpus), "corpus_index_sha256": korpus_sha,
                       "protocol_sha256": d["index"]["protocol_sha256"], "protocol": protokol,
                       "source_sha256": zdroje, "sessions": d["zaznamy"]},
        "zaznam": _hlavicka(argv),
        "limitations": ["Anomalne skore nie je verdikt o malveri; alarm urcuje az kalibracny prah.",
                        "Riadky nemaju klasifikaciu aktivity; tcn.eval.vyhodnot_far na ne nepouzivat.",
                        "dev vybera checkpoint sieti, preto metriky na dev nie su drzane bokom."]}
    out.parent.mkdir(parents=True, exist_ok=True)
    docasny = Path(tempfile.mkdtemp(prefix="." + out.name + ".", dir=out.parent))
    try:
        vahy = model.uloz(docasny)
        if vahy is not None:
            manifest["weights"]["model"] = vahy
        (docasny / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
        balik = nacitaj(docasny, allow_diagnostic=diagnostic)
        s, koniec = data["calibration"].indices[0]
        okno = data["calibration"].sessions[s][1][koniec + 1 - protokol["window_rows"]:koniec + 1]
        if not math.isclose(balik.score(okno)["score"], float(skore_kal[0]), rel_tol=1e-5, abs_tol=1e-6):
            raise ValueError("skore nacitaneho modelu sa lisi od kalibracneho")
        os.rename(docasny, out)
    finally:
        if docasny.exists():
            shutil.rmtree(docasny)
    return {"model": str(out), "typ": meno, "seed": seed, "diagnostic": bool(diagnostic),
            "calibration": kalibracia, "training": {k_: v for k_, v in manifest["training"].items()
                                                    if k_ != "history"},
            "parametre": {k_: v for k_, v in manifest["parametre"].items() if k_ not in ("mu", "sd")}}


def nacitaj(adresar, allow_diagnostic=False):
    adresar = Path(adresar)
    manifest = json.loads((adresar / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA_MODEL:
        raise ValueError("nie je model tcn.porovnanie")
    if type(manifest.get("diagnostic")) is not bool:
        raise ValueError("chyba priznak diagnostic")
    if manifest["diagnostic"] and not allow_diagnostic:
        raise ValueError("diagnosticky model; pouzi --allow-diagnostic")
    kal = manifest["calibration"]
    if (kal.get("role") != "calibration" or kal.get("method") != "benign_score_quantile_higher"
            or kal.get("comparison") != ">" or kal.get("diagnostic") != manifest["diagnostic"]
            or not isinstance(kal.get("threshold"), (int, float)) or not math.isfinite(kal["threshold"])
            or kal["threshold"] < 0 or type(kal.get("k")) is not int or type(kal.get("n")) is not int
            or not 1 <= kal["k"] <= kal["n"]):
        raise ValueError("neplatna kalibracia modelu")
    tr = manifest["training"]
    if tr.get("test_feature_arrays_loaded") is not False or tr.get("normalization_fit_role") != "train":
        raise ValueError("neplatna proveniencia treningu")
    for zaznam in manifest["weights"].values():
        if digest(adresar / zaznam["file"]) != zaznam["sha256"]:
            raise ValueError("kontrolny sucet vah nesedi")
    trieda = _trieda(manifest["model"])
    if trieda is not _ZScore and "model" not in manifest["weights"]:
        raise ValueError("chybaju vahy modelu")
    normalizer = FeatureNormalizer.from_dict(manifest["normalizer"])
    if tr.get("normalization_rows") != normalizer.fit_rows:
        raise ValueError("normalizer nesedi s treningom")
    return Balik(manifest, trieda.nacitaj(adresar, manifest), normalizer)


def _zapis(cesta, hodnota):
    with Path(cesta).open("x", encoding="utf-8") as fh:
        fh.write(json.dumps(hodnota, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def replay(model, archiv, out, *, allow_diagnostic=False, argv=None):
    """Prehratie archivu tym istym Detectorom ako `safeguard replay --archive`; ten isty vystup."""
    balik = nacitaj(model, allow_diagnostic=allow_diagnostic)
    out, archiv = Path(out), Path(archiv)
    out.mkdir(parents=True, exist_ok=False)
    (out / "evidence").mkdir()
    _zapis(out / "configuration.json", {
        "schema": SCHEMA_KONFIGURACIA, "bundle_manifest": balik.manifest, "archive": str(archiv.resolve()),
        "archive_sha256": digest(archiv), "porovnanie_model": str(Path(model).resolve()),
        "preserve": False, "follow": False, "zaznam": _hlavicka(argv)})
    try:
        riadky = replay_archive(balik, archiv)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        _zapis(out / "status.json", {"schema": SCHEMA_STAV, "running": False, "state": "input_error",
                                     "ok": False, "diagnostic": balik.manifest["diagnostic"], "error": str(exc)})
        raise
    with (out / "events.jsonl").open("x", encoding="utf-8") as fh:
        cislo = 0
        for r in riadky:
            fh.write(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n")
            if r["alarm_event"]:
                cislo += 1
                _zapis(out / "evidence" / f"event-{cislo:06d}.json", r)
    stav = {"schema": SCHEMA_STAV, "diagnostic": balik.manifest["diagnostic"], "running": False,
            "processed": len(riadky), "scored": sum(r["score"] is not None for r in riadky),
            "input_errors": sum(r["model_state"] == "input_error" for r in riadky),
            "alarm_events": sum(r["alarm_event"] for r in riadky),
            "fatal": any(r["fatal"] for r in riadky), "stop_reason": "replay_complete",
            "state": riadky[-1]["state"] if riadky else "input_error", "last": riadky[-1] if riadky else None}
    stav["ok"] = bool(riadky) and not stav["input_errors"]
    _zapis(out / "status.json", stav)
    return stav


# ------------------------------------------------------------------ CLI


def _hlavny(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="python3 -m tcn.porovnanie",
                                description="Anomalne baseliny a pamatova ablacia TCN nad vstupmi safeguardu (E4)")
    p.add_argument("--threads", type=int, default=4)
    sub = p.add_subparsers(dest="prikaz", required=True)
    f = sub.add_parser("fit", help="fit train, vyber dev, prah calibration; test_benign sa nenacita")
    f.add_argument("--corpus", required=True, type=Path)
    f.add_argument("--model", required=True, choices=MODELY)
    f.add_argument("--seed", type=int, default=0)
    f.add_argument("--out", required=True, type=Path, help="novy adresar; existujuci sa neprepise")
    f.add_argument("--epochs", type=int, default=10)
    f.add_argument("--batch-size", type=int, default=32)
    f.add_argument("--fpr", type=float, default=0.01)
    f.add_argument("--k", type=int, default=3)
    f.add_argument("--n", type=int, default=5)
    f.add_argument("--reference", type=Path,
                   help="balik TCN (safeguard train): over rovnaky korpus a rovnake fpr/k/n")
    f.add_argument("--diagnostic", action="store_true")
    r = sub.add_parser("replay", help="prehratie archivu; vystup ako safeguard replay --archive")
    r.add_argument("--model", required=True, type=Path)
    r.add_argument("--archive", required=True, type=Path)
    r.add_argument("--out", required=True, type=Path)
    r.add_argument("--allow-diagnostic", action="store_true")
    a = p.parse_args(argv)
    if a.threads < 1:
        p.error("--threads musi byt kladne")
    torch.set_num_threads(a.threads)
    if a.prikaz == "fit":
        vysledok = fit(a.corpus, a.model, a.out, seed=a.seed, epochy=a.epochs, davka=a.batch_size,
                       fpr=a.fpr, k=a.k, n=a.n, diagnostic=a.diagnostic, referencia=a.reference, argv=argv)
    else:
        vysledok = replay(a.model, a.archive, a.out, allow_diagnostic=a.allow_diagnostic, argv=argv)
    print(json.dumps(vysledok, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if vysledok.get("ok", True) else 2


if __name__ == "__main__":
    sys.exit(_hlavny())
