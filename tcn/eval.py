"""
eval.py - metriky, tabulka, ulozenie vysledku a FAR z udalosti detektora.

DVE ULOHY NARAZ
---------------
Zadanie ziada detekciu anomalii aj klasifikaciu aktivit, preto sa z tych
istych pravdepodobnosti pocita oboje:

  binarne     benigna trieda proti vsetkemu ostatnemu (skore = 1 - p(benigna)),
              vratane ROC AUC - to je "je to ine spravanie nez benigne?";
  viactriedne argmax cez vsetky triedy, presnost, macro F1, metriky na triedu
              a matica zamien - to je "ktora trieda?".

BASELINY SU V TEJ ISTEJ TABULKE
-------------------------------
Nie v prilohe a nie az vtedy, ked vyjdu horsie. HONESTY.md P8: ked baseline
dorovna alebo prekona TCN, je to vysledok a patri do zaveru.

HLAVICKA VYSLEDKU
-----------------
Kazdy JSON v data/results/ ma {commit, date, host, guest, command, n} a cely
vystup pod 'values' (HONESTY.md, kapitola 4). Pri behu nad syntetickymi datami
je 'guest' null a v poznamke je, preco - synteticky beh nie je meranie nad
hostom a tvarit sa, ze je, by bolo presne to nafuknutie, proti ktoremu je
HONESTY.md.

UDALOSTI DETEKTORA (FAR/h)
--------------------------
`python3 -m tcn.eval far` cita prehratia `python3 -m safeguard replay --archive`
jednej roly korpusu a pocita podla docs/METODIKA_ZBERU.sk.md, kap. 7: alarmove
UDALOSTI (nabezna hrana pravidla k z n, pole alarm_event), nie okna nad prahom;
FAR za hodinu k celemu sledovanemu casu aj k efektivnemu casu skorovania, vzdy
s exaktnym intervalom neistoty (nula udalosti neznamena nulovu mieru); podiel
casu bez skore. Integrita, vypadky a chyby vstupu su na prijatych relaciach
korpusu nulove uz z prijatia (scripts/collection.py audit), preto idu do casti
'dane_prijatim_korpusu' bez intervalu. test_benign je zaverecny test (kap. 5):
prikaz ho pusti iba s --final, nad commitnutym tcn/eval.py a iba raz na korpus
(zaznam '<corpus>.test_benign-final.json' vedla indexu vznikne az po --out). Detekciu utokov ani
cas do detekcie z toho odvodit nemozno. Ten isty prikaz vyhodnoti aj
klasifikator profilu zataze (trieda okna = scenar relacie), aby jedno
zaverecne spustenie na test_benign dalo oboje.

DETEKCIA MALVERU (dataset 3)
----------------------------
`python3 -m tcn.eval malver --index I --config config/malver-v1.json --replay ...`
cita index behov (hyptcn3/malver-index/1, pozri nacitaj_index_malveru) a ich
prehratia tym istym balikom. Miera detekcie (Clopper-Pearson) a TTD su zvlast
pre alarm modelu a pre nalez kontroly integrity, iba nad behmi s dokazanou
aktivaciou (dokaz zo strany hosta), porovnane s pravdepodobnostou nahodneho
alarmu v rovnako dlhom useku kontrolnych behov; po skupinach spravania a
rodinach, s predregistrovanou ocakavanou reakciou skupiny z konfiguracie.
Scenare spravania sa vyhodnocuju oddelene od skutocnych vzoriek.
"""

import argparse
import collections
import datetime
import hashlib
import json
import math
import os
import platform
import shlex
import subprocess
import sys

import numpy as np
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _commit():
    try:
        return subprocess.check_output(["git", "-C", REPO, "rev-parse", "HEAD"],
                                       text=True).strip()
    except Exception:
        return None


def vyhodnot(y_true, proba, triedy, benigna):
    """Binarne aj viactriedne metriky z jednych pravdepodobnosti."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(proba).argmax(axis=1)
    ind = list(range(len(triedy)))
    p, r, f1, n = precision_recall_fscore_support(
        y_true, y_pred, labels=ind, zero_division=0)
    # Trieda, ktora v testovacej casti ani raz nie je (napr. ma jedinu session
    # a ta vysla do treningu), nema metriky - ma null a poznamku. Nula by sa
    # citala ako namerany zly vysledok a do macro priemeru by ho stiahla, hoci
    # sa nic nemeralo (HONESTY.md: ticho doplnena nula je zakazana).
    pritomne = [i for i in ind if n[i] > 0]
    viac = {
        "presnost": float((y_pred == y_true).mean()),
        "f1_macro": float(np.mean([f1[i] for i in pritomne])),
        "f1_macro_nad_triedami": [triedy[i] for i in pritomne],
        "na_triedu": {triedy[i]: (
            {"precision": float(p[i]), "recall": float(r[i]),
             "f1": float(f1[i]), "n": int(n[i])} if n[i] > 0 else
            {"precision": None, "recall": None, "f1": None, "n": 0,
             "poznamka": "v testovacej casti nie je ani jedno okno tejto triedy"})
            for i in ind},
        "confusion": confusion_matrix(y_true, y_pred, labels=ind).tolist(),
        "poradie_tried": list(triedy),
    }
    yb = (y_true != benigna).astype(int)
    pb = (y_pred != benigna).astype(int)
    skore = 1.0 - np.asarray(proba)[:, benigna]
    bp, br, bf1, _ = precision_recall_fscore_support(
        yb, pb, labels=[1], zero_division=0)
    bin_ = {"presnost": float((pb == yb).mean()), "precision": float(bp[0]),
            "recall": float(br[0]), "f1": float(bf1[0]),
            "n_nebenignych": int(yb.sum()), "n": int(len(yb))}
    # AUC ma zmysel iba ked su v teste obe triedy; inak sa nepise nula, ale
    # null a dovod - nula by sa citala ako namerany zly vysledok.
    bin_["auc"] = (float(roc_auc_score(yb, skore))
                   if 0 < yb.sum() < len(yb) else None)
    if bin_["auc"] is None:
        bin_["auc_poznamka"] = "v testovacej casti je iba jedna z tried"
    return {"binarne": bin_, "viactriedne": viac}


def tabulka(vysledky, data):
    """Textova tabulka: vsetky modely vedla seba, jeden riadok = jeden model."""
    r = ["okien train/test : %d / %d" % (len(data["y_train"]), len(data["y_test"])),
         "sessions train   : %s" % ", ".join(data["train_sessions"]),
         "sessions test    : %s" % ", ".join(data["test_sessions"]),
         "fit normalizacie : %s" % ", ".join(data["fit_sessions"]),
         "triedy           : %s" % ", ".join(data["triedy"]),
         "vynechanych okien bez predchodcu: %d" % data["okien_bez_predchodcu"],
         "",
         "%-16s %8s %8s %8s %8s %8s" % ("model", "bin_f1", "bin_auc",
                                        "bin_acc", "viac_acc", "viac_f1")]
    for meno in sorted(vysledky):
        v = vysledky[meno]
        auc = v["binarne"]["auc"]
        r.append("%-16s %8.3f %8s %8.3f %8.3f %8.3f"
                 % (meno, v["binarne"]["f1"],
                    "-" if auc is None else "%.3f" % auc,
                    v["binarne"]["presnost"], v["viactriedne"]["presnost"],
                    v["viactriedne"]["f1_macro"]))
    for meno in sorted(vysledky):
        if "parametrov" in vysledky[meno]:
            r.append("%s: %d parametrov" % (meno, vysledky[meno]["parametrov"]))
    r.append("")
    r.append("matica zamien (riadok = skutocna trieda, poradie %s):"
             % ", ".join(data["triedy"]))
    for meno in sorted(vysledky):
        r.append("  %s: %s" % (meno, vysledky[meno]["viactriedne"]["confusion"]))
    return "\n".join(r)


def uloz(vysledky, data, cesta, prikaz, synteticke=False):
    """Vysledok s hlavickou podla HONESTY.md kapitoly 4."""
    doc = {
        "commit": _commit(),
        "date": datetime.date.today().isoformat(),
        "host": platform.node(),
        "guest": None if synteticke else "hyptcn-guest",
        "command": prikaz,
        "n": int(len(data["y_test"])),
        "values": {
            "synteticke_data": bool(synteticke),
            "triedy": data["triedy"],
            "dlzka_okna": data["dlzka_okna"],
            "train_sessions": data["train_sessions"],
            "test_sessions": data["test_sessions"],
            "fit_sessions": data["fit_sessions"],
            "okien_train": int(len(data["y_train"])),
            "okien_test": int(len(data["y_test"])),
            "okien_bez_predchodcu": data["okien_bez_predchodcu"],
            "konstantne_priznaky": data["konstantne_priznaky"],
            "modely": vysledky,
        },
    }
    if synteticke:
        doc["provenance_note"] = ("beh nad syntetickymi datami; guest je null, "
                                  "lebo ziadna snimka hosta v nom nie je")
    os.makedirs(os.path.dirname(os.path.abspath(cesta)), exist_ok=True)
    with open(cesta, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    return cesta


# ------------------------------------------------------------- udalosti safeguardu

ROLY_FAR = ("dev", "test_benign")
SCHEMA_FAR = "hyptcn3/safeguard-far/2"
SCHEMA_KORPUS = "hyptcn3/corpus-index/1"
SCHEMA_KONFIGURACIA = "hyptcn3/safeguard-configuration/1"
SCHEMA_STAV = "hyptcn3/safeguard-run/1"
SCHEMA_RIADOK = "hyptcn3/safeguard-events/1"
# Kod, ktory urcuje vyznam udalosti a skore; jeho zhoda s balikom sa zapisuje.
ZDROJE_UDALOSTI = ("safeguard/runtime.py", "safeguard/features.py", "safeguard/model.py",
                   "safeguard/bundle.py", "tcn/model.py")
PREDPOKLADY = [
    "obojstranny exaktny Garwoodov interval s alfa/2 na kazdu stranu; pri 0 udalostiach je horna "
    "hranica -ln(alfa/2) udalosti",
    "odhaduje sa miera vazena expoziciou tychto relacii; udalosti v relacii sa beru ako nezavisle "
    "(pravidlo k z n ich moze zhlukovat, casy udalosti su pri relaciach)",
    "variabilita medzi bootmi v intervale nie je; jednotkou neistoty je skupina (METODIKA kap. 1), "
    "pocet skupin je vo vysledku",
    "intervaly po scenaroch a skupinach nie su simultanne",
]


def _alfa(alfa):
    if isinstance(alfa, bool) or not isinstance(alfa, (int, float)) or not math.isfinite(alfa) \
            or not 0 < alfa < 1:
        raise ValueError("alfa musi byt konecne cislo v (0, 1)")
    return float(alfa)


def poissonov_interval(k, alfa=0.05):
    """Exaktny (Garwoodov) obojstranny interval stredneho poctu udalosti pri k."""
    from scipy.stats import chi2
    alfa = _alfa(alfa)
    dolna = 0.0 if k == 0 else float(chi2.ppf(alfa / 2, 2 * k) / 2)
    return dolna, float(chi2.ppf(1 - alfa / 2, 2 * k + 2) / 2)


def suhrn_relacie(riadky, perioda_s, max_medzera_s):
    """Pocty a casy jednej prehratej relacie (riadky events.jsonl).

    Udalost je riadok s alarm_event: detektor ho oznaci iba na nabeznej hrane
    zdroja, takze trvajuci alarm sa rata raz; riadok moze mat oba zdroje naraz.
    Vypadok senzora je odstup snimok nad max_medzera_s; jeho cas je odstup
    mensi o jednu periodu.
    """
    if not riadky:
        raise ValueError("prehratie bez riadkov")
    if any(r.get("schema") != SCHEMA_RIADOK for r in riadky):
        raise ValueError("riadok prehratia nema schemu %s" % SCHEMA_RIADOK)
    casy = [float(r["timestamp"]) for r in riadky]
    if any(b <= a for a, b in zip(casy, casy[1:])):
        raise ValueError("casy riadkov prehratia nerastu")
    medzery = [b - a for a, b in zip(casy, casy[1:]) if b - a > max_medzera_s]
    skorovanych = sum(r["score"] is not None for r in riadky)
    chyb = sum(r["model_state"] == "input_error" for r in riadky)
    udalosti = [r for r in riadky if r["alarm_event"]]
    model = [r for r in udalosti if "model_anomaly" in r["alarm_sources"]]
    sledovany = casy[-1] - casy[0] + perioda_s
    return {
        "riadkov": len(riadky),
        "skorovanych": skorovanych,
        "udalosti": len(udalosti),
        "udalosti_model": len(model),
        "udalosti_integrita": sum("kernel_integrity" in r["alarm_sources"] for r in udalosti),
        "casy_udalosti_model_s": [float(r["timestamp"]) - casy[0] for r in model],
        "sledovany_s": sledovany,
        "skorovany_s": skorovanych * perioda_s,
        "bez_skore_cas_podiel": max(0.0, 1 - skorovanych * perioda_s / sledovany),
        "bez_skore_riadkov_podiel": 1 - skorovanych / len(riadky),
        "chyb_vstupu": chyb,
        "chyb_vstupu_s": chyb * perioda_s,
        "vypadkov": len(medzery),
        "vypadky_s": sum(d - perioda_s for d in medzery),
        "integrita_uzavretych_riadkov": sum(bool(r["integrity"]["conclusive"]) for r in riadky),
        "integrita_neuzavrete": dict(sorted(collections.Counter(
            c for r in riadky for c in r["integrity"]["inconclusive"]).items())),
        "predikcie_aktivity": dict(sorted(collections.Counter(
            r["activity"] for r in riadky if r["score"] is not None).items())),
    }


def far(suhrny, alfa=0.05):
    """FAR modelu za hodinu zo suhrnov relacii, s intervalom a kontrolou rozptylu."""
    from scipy.stats import chi2
    alfa = _alfa(alfa)
    kluce = ("riadkov", "skorovanych", "udalosti_model", "sledovany_s", "skorovany_s")
    spolu = {k: sum(s[k] for s in suhrny) for k in kluce}
    spolu["relacii"] = len(suhrny)
    spolu["bez_skore_cas_podiel"] = (max(0.0, 1 - spolu["skorovany_s"] / spolu["sledovany_s"])
                                     if spolu["sledovany_s"] else None)
    k = spolu["udalosti_model"]
    dolna, horna = poissonov_interval(k, alfa)
    far_h = {}
    for cas in ("sledovany", "skorovany"):
        hodiny = spolu[cas + "_s"] / 3600
        far_h[cas] = ({"udalosti_h": k / hodiny, "dolna_h": dolna / hodiny, "horna_h": horna / hodiny}
                      if hodiny > 0 else None)
    # Rozptyl medzi relaciami (jednotka = beh): Pearsonovo X^2 pocet udalosti
    # proti ocakavaniu podla skorovaneho casu; bez udalosti sa neda odhadnut.
    if k == 0 or len(suhrny) < 2:
        disperzia = {"x2": None, "df": None, "p": None,
                     "dovod": "bez udalosti modelu" if k == 0 else "jedna relacia"}
    else:
        ocak = [k * s["skorovany_s"] / spolu["skorovany_s"] for s in suhrny]
        x2 = sum((s["udalosti_model"] - e) ** 2 / e for s, e in zip(suhrny, ocak) if e > 0)
        df = len(suhrny) - 1
        disperzia = {"x2": float(x2), "df": df, "p": float(chi2.sf(x2, df)), "dovod": None}
    return {"spolu": spolu, "far_h": far_h, "disperzia": disperzia}


def klasifikacia_aktivit(relacie, triedy, alfa=0.05):
    """Presnost klasifikatora profilu zataze; trieda okna = scenar jeho relacie.

    Okna jednej relacie maju tu istu znacku a nie su nezavisle, preto sa okrem
    metrik na okna uvadza aj pocet relacii, ktorych vacsinova predikcia sedi,
    s exaktnym (Clopperovym-Pearsonovym) intervalom.
    """
    from scipy.stats import beta
    alfa = _alfa(alfa)
    ind = {t: i for i, t in enumerate(triedy)}
    y_true, y_pred, na_relaciu = [], [], {}
    for sid, s in sorted(relacie.items()):
        if s["scenario"] not in ind:
            raise ValueError("scenar %s nie je triedou balika" % s["scenario"])
        pocty = s["predikcie_aktivity"]
        for trieda, n in pocty.items():
            y_true += [ind[s["scenario"]]] * n
            y_pred += [ind[trieda]] * n
        vacsina = max(sorted(pocty), key=lambda t: pocty[t]) if pocty else None
        na_relaciu[sid] = {"scenar": s["scenario"], "vacsinova_predikcia": vacsina,
                           "spravne_okna_podiel": (pocty.get(s["scenario"], 0) / sum(pocty.values())
                                                   if pocty else None)}
    if not y_true:
        raise ValueError("ziadne skorovane okno s predikciou aktivity")
    pritomne = sorted(set(y_true))
    p, r, f1, n = precision_recall_fscore_support(y_true, y_pred, labels=list(range(len(triedy))),
                                                  zero_division=0)
    spravne = sum(v["vacsinova_predikcia"] == v["scenar"] for v in na_relaciu.values())
    m = len(na_relaciu)
    dolna = 0.0 if spravne == 0 else float(beta.ppf(alfa / 2, spravne, m - spravne + 1))
    horna = 1.0 if spravne == m else float(beta.ppf(1 - alfa / 2, spravne + 1, m - spravne))
    return {
        "triedy": list(triedy),
        "okna": {"n": len(y_true), "presnost": float(np.mean(np.array(y_true) == np.array(y_pred))),
                 "f1_macro": float(np.mean([f1[i] for i in pritomne])),
                 "f1_macro_nad_triedami": [triedy[i] for i in pritomne],
                 "na_triedu": {triedy[i]: {"precision": float(p[i]), "recall": float(r[i]),
                                           "f1": float(f1[i]), "n": int(n[i])} for i in pritomne},
                 "confusion": confusion_matrix(y_true, y_pred, labels=list(range(len(triedy)))).tolist()},
        "relacie": {"spravnych": spravne, "spolu": m, "presnost": spravne / m,
                    "interval": [dolna, horna], "interval_metoda": "Clopper-Pearson",
                    "na_relaciu": na_relaciu},
        "poznamka": ("trieda je zaznamenane nastavenie zataze session, nie skodlivost ani rodina malveru; "
                     "okna jednej relacie nie su nezavisle, nezavislou jednotkou je relacia"),
    }


def _digest(cesta):
    with open(cesta, "rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _nacitaj_prehratie(adresar):
    subory = {n: os.path.join(adresar, n) for n in ("configuration.json", "status.json", "events.jsonl")}
    konf = json.loads(open(subory["configuration.json"], encoding="utf-8").read())
    stav = json.loads(open(subory["status.json"], encoding="utf-8").read())
    if konf.get("schema") != SCHEMA_KONFIGURACIA or "archive" not in konf:
        raise ValueError("%s: nie je vystup 'safeguard replay --archive'" % adresar)
    if stav.get("schema") != SCHEMA_STAV:
        raise ValueError("%s: status.json nema schemu %s" % (adresar, SCHEMA_STAV))
    with open(subory["events.jsonl"], encoding="utf-8") as fh:
        riadky = [json.loads(line) for line in fh if line.strip()]
    if stav.get("fatal") or stav.get("stop_reason") != "replay_complete" or stav.get("processed") != len(riadky):
        raise ValueError("%s: prehratie nie je uplne" % adresar)
    return konf, stav, riadky, {n: _digest(c) for n, c in subory.items()}


def _manifest_sha(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def vyhodnot_far(korpus, rola, prehratia, alfa=0.05, final=False, kampan=None):
    """FAR jednej roly korpusu z prehrati; kazda relacia roly prave raz."""
    alfa = _alfa(alfa)
    if rola not in ROLY_FAR:
        raise ValueError("FAR sa pocita iba pre role %s" % ", ".join(ROLY_FAR))
    if (rola == "test_benign") != bool(final):
        raise ValueError("test_benign je zaverecny test (METODIKA kap. 5) a pusti sa iba s --final; "
                         "--final plati iba pre test_benign")
    index = json.loads(open(korpus, encoding="utf-8").read())
    if index.get("schema") != SCHEMA_KORPUS or index.get("complete") is not True:
        raise ValueError("korpus nie je uplny index %s" % SCHEMA_KORPUS)
    protokol = index["protocol_config"]
    perioda, max_medzera = protokol["interval_s"], protokol["max_gap_s"]
    zaznamy = {z["features_sha256"]: z for z in index["sessions"] if z["role"] == rola}
    if not zaznamy:
        raise ValueError("korpus nema relacie roly %s" % rola)
    korpus_sha = _digest(korpus)
    balik, balik_sha, relacie = None, None, {}
    for adresar in prehratia:
        konf, stav, riadky, hashe = _nacitaj_prehratie(adresar)
        zaznam = zaznamy.get(_digest(konf["archive"]))
        if zaznam is None:
            raise ValueError("%s: archiv nie je relaciou roly %s v tomto korpuse" % (adresar, rola))
        if zaznam["id"] in relacie:
            raise ValueError("%s: relacia %s je prehrata dvakrat" % (adresar, zaznam["id"]))
        manifest = konf["bundle_manifest"]
        if manifest.get("diagnostic") is not False:
            raise ValueError("%s: diagnosticky balik nema FAR" % adresar)
        if manifest["provenance"]["corpus_index_sha256"] != korpus_sha:
            raise ValueError("%s: balik nebol trenovany na tomto korpuse" % adresar)
        kontrakt = manifest["feature_contract"]
        if kontrakt["max_gap_s"] != max_medzera or kontrakt["window_rows"] != protokol["window_rows"]:
            raise ValueError("%s: casove nastavenia balika sa lisia od protokolu korpusu" % adresar)
        if balik is None:
            balik, balik_sha = manifest, _manifest_sha(manifest)
        elif _manifest_sha(manifest) != balik_sha:
            raise ValueError("%s: prehratia pouzili rozne baliky" % adresar)
        if riadky[0]["timestamp"] != zaznam["start"] or riadky[-1]["timestamp"] != zaznam["end"]:
            raise ValueError("%s: prehratie nepokryva celu relaciu" % adresar)
        suhrn = suhrn_relacie(riadky, perioda, max_medzera)
        if (stav.get("scored"), stav.get("input_errors"), stav.get("alarm_events")) != (
                suhrn["skorovanych"], suhrn["chyb_vstupu"], suhrn["udalosti"]):
            raise ValueError("%s: status.json nesedi s events.jsonl" % adresar)
        relacie[zaznam["id"]] = dict(suhrn, scenario=zaznam["scenario"], skupina=zaznam["group"],
                                     features_sha256=zaznam["features_sha256"],
                                     archiv=os.path.realpath(konf["archive"]),
                                     prehratie=os.path.realpath(adresar), subory_sha256=hashe)
    chybaju = sorted(z["id"] for z in zaznamy.values() if z["id"] not in relacie)
    if chybaju:
        raise ValueError("chybaju prehratia relacii: %s" % ", ".join(chybaju))
    zoznam = list(relacie.values())
    podla = lambda kluc: {h: far([s for s in zoznam if s[kluc] == h], alfa)
                          for h in sorted({s[kluc] for s in zoznam})}
    neuzavrete = collections.Counter()
    for s in zoznam:
        neuzavrete.update(s["integrita_neuzavrete"])
    zdroje = {}
    for meno in ZDROJE_UDALOSTI:
        ulozeny = balik["provenance"].get("source_sha256", {}).get(meno)
        zdroje[meno] = ("bez_zaznamu_v_baliku" if ulozeny is None else
                        "zhodny" if ulozeny == _digest(os.path.join(REPO, meno)) else "iny")
    if kampan is None:
        kampan_v = {"zaznam": None, "dovod": "neuvedene (--campaign); zamietnute behy tu nie su"}
    else:
        kv = json.loads(open(kampan, encoding="utf-8").read())["values"]
        kampan_v = {"zaznam": os.path.realpath(kampan), "zaznam_sha256": _digest(kampan),
                    "planned_sessions": kv["planned_sessions"], "accepted_sessions": kv["accepted_sessions"],
                    "rejected_sessions": kv["rejected_sessions"]}
    poznamka = ("FAR z alarmovych udalosti benigneho behu prijatych relacii; nehovori nic o detekcii "
                "utokov ani o presnosti voci malveru (HONESTY P4).")
    if rola == "dev":
        poznamka += (" Rola dev vyberala checkpointy prediktora aj klasifikatora (checkpoint_selection_role), "
                     "toto FAR ani presnost klasifikacie preto nie su drzane bokom; zaverecne su iba na "
                     "test_benign (--final).")
    return {
        "schema": SCHEMA_FAR, "rola": rola, "final": bool(final), "alfa": alfa,
        "korpus": os.path.realpath(korpus), "korpus_sha256": korpus_sha, "kampan": kampan_v,
        "balik": {"manifest_sha256": balik_sha, "created_utc": balik["created_utc"],
                  "weights": balik["weights"], "calibration": balik["calibration"],
                  "training": {k: balik["training"][k] for k in ("seed", "epochs", "batch_size")}},
        "perioda_s": perioda, "max_medzera_s": max_medzera,
        "merane": {"spolu": far(zoznam, alfa), "skupiny": podla("skupina"), "scenare": podla("scenario"),
                   "skupin": len({s["skupina"] for s in zoznam})},
        "dane_prijatim_korpusu": {
            "udalosti_integrita": sum(s["udalosti_integrita"] for s in zoznam),
            "chyb_vstupu": sum(s["chyb_vstupu"] for s in zoznam),
            "vypadkov": sum(s["vypadkov"] for s in zoznam),
            "vypadky_s": sum(s["vypadky_s"] for s in zoznam),
            "integrita_uzavretych_riadkov": sum(s["integrita_uzavretych_riadkov"] for s in zoznam),
            "integrita_neuzavrete": dict(sorted(neuzavrete.items())),
            "poznamka": ("prijatie do korpusu zamieta relacie s nalezom integrity, medzerou, chybou citania "
                         "alebo neplatnym riadkom (scripts/collection.py audit), takze tieto hodnoty nie su "
                         "meranim detektora; vypadky senzora a integritu bez vyberu meria safeguard run"),
        },
        "klasifikacia_aktivit": klasifikacia_aktivit(relacie, balik["classes"], alfa),
        "relacie": relacie, "zdroje_udalosti": zdroje, "predpoklady": PREDPOKLADY, "poznamka": poznamka,
    }, balik


SCHEMA_INDEX_UDALOSTI = "hyptcn3/event-index/1"
SCHEMA_FAR_UDALOSTI = "hyptcn3/safeguard-event-far/1"
# Po skonceni udalosti, ked uz okno neobsahuje jej snimku: cas, v ktorom sa sleduje, ci alarm odznie.
DOZVUK_S = 300.0
PREDPOKLADY_UDALOSTI = [
    "okno patri udalosti, ked sa jeho snimky [t - (W-1)*perioda, t] prekryvaju s intervalom udalosti "
    "[host start, host stop hotovy]; cas udalosti obsahuje aj prechod (METODIKA kap. 3, znacka transition)",
    "dozvuk je %d s po poslednom okne, ktore udalost obsahovalo; mimo udalosti a dozvuku je cista prevadzka"
    % DOZVUK_S,
    "udalost bez dokazu (executed false) a jej okna do metrik nevstupuju (NAVRH_PROTOKOL_V3 kap. 5)",
    "porovnanie s cistou prevadzkou je podmieneny exaktny binomicky test dvoch Poissonovych mier "
    "(jednostranne: viac alarmov pri udalosti); relacie a boot nie su v teste zohladnene",
]


def kategorie_udalosti(riadky, udalosti, perioda_s, okno):
    """Kategoria kazdeho riadku: typ udalosti, 'po_udalosti', 'prevadzka' alebo None (vylucene)."""
    sirka = (okno - 1) * perioda_s
    vysledok = []
    for r in riadky:
        t = float(r["timestamp"])
        prekryv = [u for u in udalosti if u["host_start_unix"] <= t and t - sirka <= u["host_stopped_unix"]]
        dozvuk = [u for u in udalosti if u["host_stopped_unix"] < t - sirka <= u["host_stopped_unix"] + DOZVUK_S]
        if prekryv or dozvuk:
            vykonane = all(u["executed"] for u in prekryv + dozvuk)
            vysledok.append(None if not vykonane else prekryv[0]["type"] if prekryv else "po_udalosti")
        else:
            vysledok.append("prevadzka")
    return vysledok


def _expozicia(riadky, kategorie, perioda_s):
    """Suhrny ako suhrn_relacie, po kategoriach jednej relacie (vstup pre far)."""
    out = {}
    for r, k in zip(riadky, kategorie):
        if k is None:
            continue
        s = out.setdefault(k, {"riadkov": 0, "skorovanych": 0, "udalosti_model": 0, "udalosti_integrita": 0,
                               "sledovany_s": 0.0, "skorovany_s": 0.0})
        s["riadkov"] += 1
        s["sledovany_s"] += perioda_s
        if r["score"] is not None:
            s["skorovanych"] += 1
            s["skorovany_s"] += perioda_s
        if r["alarm_event"]:
            s["udalosti_model"] += "model_anomaly" in r["alarm_sources"]
            s["udalosti_integrita"] += "kernel_integrity" in r["alarm_sources"]
    return out


def priebeh_udalosti(riadky, udalost, perioda_s, okno):
    """Oneskorenie prveho alarmu modelu od zaciatku udalosti a ci alarm odznie po dozvuku."""
    sirka = (okno - 1) * perioda_s
    koniec = udalost["host_stopped_unix"] + sirka
    pocas = [r for r in riadky if udalost["host_start_unix"] <= float(r["timestamp"]) <= koniec]
    dozvuk = [r for r in riadky if koniec < float(r["timestamp"]) <= koniec + DOZVUK_S]
    prvy = next((float(r["timestamp"]) for r in pocas if r["alarm_event"] and "model_anomaly" in r["alarm_sources"]),
                None)
    return {"type": udalost["type"], "class": udalost["class"], "executed": udalost["executed"],
            "start_unix": udalost["host_start_unix"], "stop_unix": udalost["host_stopped_unix"],
            "alarm_modelu": prvy is not None,
            "oneskorenie_s": None if prvy is None else prvy - udalost["host_start_unix"],
            "alarm_riadkov": sum(bool(r.get("model_alarm")) for r in pocas),
            "alarm_v_dozvuku_riadkov": sum(bool(r.get("model_alarm")) for r in dozvuk),
            "alarm_na_konci_dozvuku": bool(dozvuk and dozvuk[-1].get("model_alarm")),
            "dozvuk_riadkov": len(dozvuk)}


def porovnanie_mier(k1, e1, k0, e0):
    """Jednostranny podmieneny exaktny test: je miera 1 vacsia nez miera 0 (Poisson, expozicie e)?"""
    from scipy.stats import binomtest
    if e1 <= 0 or e0 <= 0:
        return {"p": None, "dovod": "bez expozicie"}
    if k1 + k0 == 0:
        return {"p": 1.0, "pomer_mier": None, "dovod": "bez udalosti modelu"}
    test = binomtest(k1, k1 + k0, e1 / (e1 + e0), alternative="greater")
    return {"p": float(test.pvalue), "pomer_mier": (k1 / e1) / (k0 / e0) if k0 else None, "dovod": None}


def vyhodnot_udalosti(index_cesta, prehratia, alfa=0.05):
    """FAR dnesneho balika pocas prevadzkovych udalosti protokolu v3 (krok A), po typoch a triedach."""
    alfa = _alfa(alfa)
    index = json.loads(open(index_cesta, encoding="utf-8").read())
    if index.get("schema") != SCHEMA_INDEX_UDALOSTI or index.get("complete") is not True:
        raise ValueError("nie je uplny index %s" % SCHEMA_INDEX_UDALOSTI)
    protokol = index["protocol_config"]
    perioda, max_medzera, okno = protokol["interval_s"], protokol["max_gap_s"], protokol["window_rows"]
    triedy = protokol["events"]["classes"]
    zaznamy = {z["features_sha256"]: z for z in index["sessions"]}
    balik, balik_sha, relacie, priebehy = None, None, {}, []
    po_kategoriach = collections.defaultdict(list)
    for adresar in prehratia:
        konf, stav, riadky, hashe = _nacitaj_prehratie(adresar)
        zaznam = zaznamy.get(_digest(konf["archive"]))
        if zaznam is None:
            raise ValueError("%s: archiv nie je relaciou tohto indexu" % adresar)
        if zaznam["id"] in relacie:
            raise ValueError("%s: relacia %s je prehrata dvakrat" % (adresar, zaznam["id"]))
        manifest = konf["bundle_manifest"]
        if manifest.get("diagnostic") is not False:
            raise ValueError("%s: diagnosticky balik nema FAR" % adresar)
        kontrakt = manifest["feature_contract"]
        if kontrakt["max_gap_s"] != max_medzera or kontrakt["window_rows"] != okno:
            raise ValueError("%s: casove nastavenia balika sa lisia od protokolu" % adresar)
        if balik is None:
            balik, balik_sha = manifest, _manifest_sha(manifest)
        elif _manifest_sha(manifest) != balik_sha:
            raise ValueError("%s: prehratia pouzili rozne baliky" % adresar)
        if riadky[0]["timestamp"] != zaznam["start"] or riadky[-1]["timestamp"] != zaznam["end"]:
            raise ValueError("%s: prehratie nepokryva celu relaciu" % adresar)
        if _digest(zaznam["events"]) != zaznam["events_sha256"]:
            raise ValueError("%s: events.json sa zmenil od indexu" % adresar)
        udalosti = json.loads(open(zaznam["events"], encoding="utf-8").read())["events"]
        suhrn = suhrn_relacie(riadky, perioda, max_medzera)
        kategorie = kategorie_udalosti(riadky, udalosti, perioda, okno)
        for kategoria, e in _expozicia(riadky, kategorie, perioda).items():
            po_kategoriach[kategoria].append(dict(e, relacia=zaznam["id"], skupina=zaznam["group"]))
        priebehy += [dict(priebeh_udalosti(riadky, u, perioda, okno), relacia=zaznam["id"], skupina=zaznam["group"])
                     for u in udalosti]
        relacie[zaznam["id"]] = dict(suhrn, scenario=zaznam["scenario"], skupina=zaznam["group"],
                                     features_sha256=zaznam["features_sha256"], archiv=os.path.realpath(konf["archive"]),
                                     prehratie=os.path.realpath(adresar), subory_sha256=hashe,
                                     udalosti_sha256=zaznam["events_sha256"],
                                     vylucenych_riadkov=sum(k is None for k in kategorie))
    chybaju = sorted(z["id"] for z in zaznamy.values() if z["id"] not in relacie)
    if chybaju:
        raise ValueError("chybaju prehratia relacii: %s" % ", ".join(chybaju))

    def miera(zoznam):
        vysledok = far(zoznam, alfa)
        vysledok["skupin"] = len({s["skupina"] for s in zoznam})
        vysledok["udalosti_integrita"] = sum(s["udalosti_integrita"] for s in zoznam)
        return vysledok

    typy = {k: v for k, v in po_kategoriach.items() if k in triedy}
    podla_triedy = collections.defaultdict(list)
    for typ, zoznam in typy.items():
        podla_triedy[triedy[typ]] += zoznam
    cista = po_kategoriach.get("prevadzka", [])
    vsetky = [s for zoznam in typy.values() for s in zoznam]
    k0, e0 = sum(s["udalosti_model"] for s in cista), sum(s["skorovany_s"] for s in cista)
    porovnaj = lambda zoznam: porovnanie_mier(sum(s["udalosti_model"] for s in zoznam),
                                              sum(s["skorovany_s"] for s in zoznam), k0, e0)
    env = balik["environment"]
    relacie_env = {"kernel": {z["guest"]["kernel"] for z in index["sessions"]},
                   "stack_sha256": {z["guest"]["stack_sha256"] for z in index["sessions"]},
                   "collector_sha256": {z["collector_sha256"] for z in index["sessions"]},
                   "extractor_sha256": {json.dumps(z["extractor_sha256"], sort_keys=True) for z in index["sessions"]}}
    prostredie = {k: "zhodne" if v == {env[k] if k != "extractor_sha256" else json.dumps(env[k], sort_keys=True)}
                  else "ine" for k, v in relacie_env.items()}
    vykonane = [p for p in priebehy if p["executed"]]
    return {
        "schema": SCHEMA_FAR_UDALOSTI, "alfa": alfa, "dozvuk_s": DOZVUK_S,
        "index": os.path.realpath(index_cesta), "index_sha256": _digest(index_cesta),
        "protokol": protokol["name"], "protocol_sha256": index["protocol_sha256"],
        "balik": {"manifest_sha256": balik_sha, "created_utc": balik["created_utc"],
                  "corpus_index_sha256": balik["provenance"]["corpus_index_sha256"],
                  "calibration": balik["calibration"]},
        "prostredie_voci_baliku": prostredie,
        "perioda_s": perioda, "okno_riadkov": okno,
        "merane": {
            "prevadzka": miera(cista) if cista else None,
            "po_udalosti": miera(po_kategoriach["po_udalosti"]) if po_kategoriach.get("po_udalosti") else None,
            "vsetky_udalosti": {**miera(vsetky), "voci_prevadzke": porovnaj(vsetky)} if vsetky else None,
            "typy": {t: {**miera(z), "trieda": triedy[t], "voci_prevadzke": porovnaj(z)} for t, z in sorted(typy.items())},
            "triedy": {t: {**miera(z), "voci_prevadzke": porovnaj(z)} for t, z in sorted(podla_triedy.items())},
            "skupin": len({s["skupina"] for s in relacie.values()}),
        },
        "udalosti": {"planovanych": len(priebehy), "vykonanych": len(vykonane),
                     "s_alarmom_modelu": sum(p["alarm_modelu"] for p in vykonane),
                     "alarm_na_konci_dozvuku": sum(p["alarm_na_konci_dozvuku"] for p in vykonane),
                     "priebeh": priebehy},
        "relacie": relacie, "predpoklady": [*PREDPOKLADY, *PREDPOKLADY_UDALOSTI],
        "poznamka": ("Prevadzkove udalosti su benigne; kazdy alarm je falosny. Vysledok plati iba pre tieto typy "
                     "udalosti v labe a nehovori nic o detekcii utokov ani malveru (HONESTY P4)."),
    }, balik


# ------------------------------------------------------------- malver (dataset 3)

SCHEMA_INDEX_MALVERU = "hyptcn3/malver-index/1"
SCHEMA_KONFIG_MALVERU = "hyptcn3/malver-config/1"
SCHEMA_MALVER = "hyptcn3/safeguard-malver/1"
DRUHY_BEHU = ("vzorka", "scenar", "kontrola")
ZDROJE_DOKAZU = ("host", "guest", "inetsim")
# Dokaz aktivacie, ktory nezavisi od hosta pod utokom (log INetSim, CPU procesu QEMU, ...).
ZDROJE_HOSTA = ("host", "inetsim")
ZDROJE_ALARMU = {"model": "model_anomaly", "integrita": "kernel_integrity"}
PREDPOKLADY_MALVERU = [
    "beh je aktivovany prave vtedy, ked ma cas aktivacie a aspon jeden dokaz zo strany hosta "
    "(zdroj host alebo inetsim); dokaz iba z hosta pod utokom (guest) nestaci, lebo malver ho moze "
    "podvrhnut alebo skryt",
    "neaktivovany beh nie je detekcia ani platny negativ: do menovatela nevstupuje, je iba spocitany a vymenovany",
    "detekcia = alarmova udalost (nabezna hrana, pole alarm_event) daneho zdroja v [aktivacia, aktivacia + "
    "horizont]; alarm, ktory zacal pred aktivaciou, sa nerata (je pri behu zvlast)",
    "Clopperov-Pearsonov interval je obojstranny s alfa/2 na kazdu stranu; behy sa beru ako nezavisle "
    "(kazda vzorka bezi raz, na cerstvom boote z cisteho obrazu)",
    "pravdepodobnost nahodneho alarmu v useku dlzky horizontu je 1 - exp(-miera * horizont), miera je "
    "Poissonov odhad z kontrolnych behov k ich sledovanemu casu; interval je Garwoodov interval miery "
    "prenesany tou istou funkciou; empiricky odhad su po sebe iduce neprekryvajuce sa useky kontrol",
    "test detekcie proti nahode je jednostranny binomicky test s bodovym odhadom pravdepodobnosti "
    "nahodneho alarmu (neistota odhadu z kontrol v teste nie je)",
    "skupina reaguje zdrojom, ked ho detekuje aspon prah_reakcie_podiel aktivovanych behov skupiny; "
    "zhoda = pozorovana reakcia sa rovna predregistrovanej v konfiguracii",
    "scenare spravania (simulacie technik) sa vyhodnocuju oddelene od skutocnych vzoriek",
]


def clopper_pearson(k, n, alfa=0.05):
    """Exaktny obojstranny interval podielu k z n; pri n = 0 None."""
    from scipy.stats import beta
    alfa = _alfa(alfa)
    if n == 0:
        return None
    dolna = 0.0 if k == 0 else float(beta.ppf(alfa / 2, k, n - k + 1))
    horna = 1.0 if k == n else float(beta.ppf(1 - alfa / 2, k + 1, n - k))
    return [dolna, horna]


def _cislo(x, meno, kladne=True):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or (kladne and x <= 0):
        raise ValueError("%s musi byt konecne %scislo" % (meno, "kladne " if kladne else ""))
    return float(x)


def _hex64(x):
    return isinstance(x, str) and len(x) == 64 and all(c in "0123456789abcdef" for c in x)


def nacitaj_konfig_malveru(konfig):
    """Konfiguracia vyhodnotenia malveru (cesta alebo dict) -> (konfig, sha256, cesta alebo None)."""
    if isinstance(konfig, dict):
        k, cesta = konfig, None
    else:
        cesta = os.path.realpath(konfig)
        k = json.loads(open(cesta, encoding="utf-8").read())
    if k.get("schema") != SCHEMA_KONFIG_MALVERU:
        raise ValueError("konfiguracia nema schemu %s" % SCHEMA_KONFIG_MALVERU)
    _cislo(k.get("horizont_s"), "horizont_s")
    _cislo(k.get("min_cisty_usek_s"), "min_cisty_usek_s")
    _alfa(k.get("alfa"))
    prah = _cislo(k.get("prah_reakcie_podiel"), "prah_reakcie_podiel")
    if prah > 1:
        raise ValueError("prah_reakcie_podiel musi byt v (0, 1]")
    skupiny = k.get("skupiny")
    if not isinstance(skupiny, dict) or not skupiny:
        raise ValueError("konfiguracia nema skupiny")
    for meno, s in skupiny.items():
        ocak = s.get("ocakavane") if isinstance(s, dict) else None
        if not isinstance(ocak, dict) or set(ocak) != set(ZDROJE_ALARMU) or \
                not all(isinstance(v, bool) for v in ocak.values()):
            raise ValueError("skupina %s: ocakavane musi mat prave %s ako true/false"
                             % (meno, ", ".join(ZDROJE_ALARMU)))
        kontroly = s.get("kontroly_integrity")
        if kontroly is not None and (not isinstance(kontroly, list) or not kontroly
                                     or not all(isinstance(c, str) and c for c in kontroly)):
            raise ValueError("skupina %s: kontroly_integrity musi byt neprazdny zoznam nazvov" % meno)
    minimum = k.get("minimum")
    if not isinstance(minimum, dict) or set(minimum) != {"vzorky", "rodiny", "na_skupinu"} or \
            not all(type(v) is int and v >= 0 for v in minimum.values()):
        raise ValueError("minimum musi mat cele nezaporne vzorky, rodiny, na_skupinu")
    scenare = k.get("scenare")
    if not isinstance(scenare, list) or not all(isinstance(x, str) and x for x in scenare) \
            or len(set(scenare)) != len(scenare):
        raise ValueError("scenare musi byt zoznam roznych nazvov")
    return k, hashlib.sha256(json.dumps(k, sort_keys=True).encode()).hexdigest(), cesta


def aktivacia_behu(beh):
    """(aktivovany, cas aktivacie alebo None, dovod alebo None) podla pravidla dokazu.

    Pravidlo: beh je aktivovany prave vtedy, ked activation.timestamp_unix nie je null
    a medzi dokazmi je aspon jeden zo strany hosta (source host alebo inetsim).
    Dokazy iba z hosta pod utokom (source guest) nestacia - beh sa berie ako
    neaktivovany, nie ako negativ.
    """
    akt = beh["activation"]
    hostove = [d for d in akt["evidence"] if d["source"] in ZDROJE_HOSTA]
    if akt["timestamp_unix"] is None:
        return False, None, "bez_casu_aktivacie" if akt["evidence"] else "bez_dokazu"
    if not hostove:
        return False, None, "bez_dokazu_zo_strany_hosta"
    return True, float(akt["timestamp_unix"]), None


def _over_beh(beh, konfig):
    """Kontrola jedneho zaznamu indexu; nejednoznacny zaznam je ValueError."""
    bid = beh.get("id")
    if not isinstance(bid, str) or not bid:
        raise ValueError("beh bez id")
    druh = beh.get("kind")
    if druh not in DRUHY_BEHU:
        raise ValueError("%s: kind musi byt %s" % (bid, "|".join(DRUHY_BEHU)))
    if not _hex64(beh.get("archive_sha256")) or not isinstance(beh.get("archive"), str):
        raise ValueError("%s: chyba archive alebo archive_sha256" % bid)
    start, end = _cislo(beh.get("start"), "start", False), _cislo(beh.get("end"), "end", False)
    if end <= start:
        raise ValueError("%s: end nie je po start" % bid)
    akt = beh.get("activation")
    if druh == "kontrola":
        if beh.get("sample_sha256") is not None or beh.get("launch_unix") is not None or \
                beh.get("group") is not None or (akt not in (None, {}) and akt != {"timestamp_unix": None, "evidence": []}):
            raise ValueError("%s: kontrolny beh nema vzorku, spustenie, skupinu ani aktivaciu" % bid)
        return
    if beh.get("group") not in konfig["skupiny"]:
        raise ValueError("%s: skupina %r nie je v konfiguracii" % (bid, beh.get("group")))
    if not isinstance(beh.get("family"), str) or not beh["family"]:
        raise ValueError("%s: chyba family" % bid)
    if druh == "vzorka":
        if not _hex64(beh.get("sample_sha256")):
            raise ValueError("%s: vzorka potrebuje sample_sha256 (64 hex, male pismena)" % bid)
    else:
        if beh.get("scenario") not in konfig["scenare"]:
            raise ValueError("%s: scenar %r nie je v konfiguracii" % (bid, beh.get("scenario")))
        if beh.get("sample_sha256") is not None:
            raise ValueError("%s: scenar nema sample_sha256" % bid)
    spustenie = _cislo(beh.get("launch_unix"), "launch_unix", False)
    if not start <= spustenie <= end:
        raise ValueError("%s: spustenie mimo behu" % bid)
    if spustenie - start < konfig["min_cisty_usek_s"]:
        raise ValueError("%s: cisty usek pred spustenim %.1f s je kratsi nez %.0f s"
                         % (bid, spustenie - start, konfig["min_cisty_usek_s"]))
    if not isinstance(akt, dict) or set(akt) != {"timestamp_unix", "evidence"} or \
            not isinstance(akt["evidence"], list):
        raise ValueError("%s: activation musi byt {timestamp_unix, evidence}" % bid)
    for d in akt["evidence"]:
        if not isinstance(d, dict) or d.get("source") not in ZDROJE_DOKAZU or \
                not isinstance(d.get("kind"), str) or not d["kind"]:
            raise ValueError("%s: dokaz musi mat source %s a kind" % (bid, "|".join(ZDROJE_DOKAZU)))
    if akt["timestamp_unix"] is not None:
        t = _cislo(akt["timestamp_unix"], "activation.timestamp_unix", False)
        if not spustenie <= t <= end:
            raise ValueError("%s: aktivacia pred spustenim alebo po konci behu" % bid)
        if aktivacia_behu(beh)[0] and t + konfig["horizont_s"] > end:
            raise ValueError("%s: beh konci skor nez horizont po aktivacii; negativ by bol nejednoznacny" % bid)


def nacitaj_index_malveru(index_cesta, konfig):
    """Index behov datasetu 3 (schema hyptcn3/malver-index/1), skontrolovany voci konfiguracii.

    {"schema": "hyptcn3/malver-index/1", "complete": true,
     "protocol_config": {"interval_s", "max_gap_s", "window_rows"},
     "bundle_manifest_sha256": volitelne - ked je, vsetky prehratia ho musia mat,
     "runs": [{"id", "kind": "vzorka"|"scenar"|"kontrola",
               "sample_sha256" (vzorka; inak null), "scenario" (scenar), "family", "group" (nie kontrola),
               "archive", "archive_sha256", "start", "end" (cas prvej a poslednej snimky),
               "launch_unix" (nie kontrola),
               "activation": {"timestamp_unix": cas alebo null,
                              "evidence": [{"source": "host"|"guest"|"inetsim", "kind", ...}]}}]}
    Kazda vzorka bezi prave raz (sample_sha256 sa neopakuje); pravidlo aktivacie je v aktivacia_behu.
    """
    index = json.loads(open(index_cesta, encoding="utf-8").read())
    if index.get("schema") != SCHEMA_INDEX_MALVERU or index.get("complete") is not True:
        raise ValueError("nie je uplny index %s" % SCHEMA_INDEX_MALVERU)
    protokol = index.get("protocol_config")
    if not isinstance(protokol, dict) or not {"interval_s", "max_gap_s", "window_rows"} <= set(protokol):
        raise ValueError("index nema protocol_config s interval_s, max_gap_s, window_rows")
    behy = index.get("runs")
    if not isinstance(behy, list) or not behy:
        raise ValueError("index nema behy")
    for beh in behy:
        _over_beh(beh, konfig)
    for kluc, meno in (("id", "id"), ("archive_sha256", "archiv")):
        pocty = collections.Counter(b[kluc] for b in behy)
        dvakrat = sorted(x for x, n in pocty.items() if n > 1)
        if dvakrat:
            raise ValueError("%s sa v indexe opakuje: %s" % (meno, ", ".join(dvakrat)))
    vzorky = collections.Counter(b["sample_sha256"] for b in behy if b["kind"] == "vzorka")
    dvakrat = sorted(x for x, n in vzorky.items() if n > 1)
    if dvakrat:
        raise ValueError("vzorka bezi viac nez raz: %s" % ", ".join(dvakrat))
    return index


def priebeh_malveru(riadky, beh, aktivacia, horizont_s, kontroly_integrity=None):
    """Alarmove udalosti jedneho behu vzhladom na spustenie a aktivaciu, po zdrojoch.

    Integrita sa pri skupine s kontroly_integrity rata iba z udalosti, ktorych riadok
    ma nalez niektorej z tychto kontrol (pole check v integrity.findings).
    """
    def zdroj(r, meno):
        if not r["alarm_event"] or ZDROJE_ALARMU[meno] not in r["alarm_sources"]:
            return False
        if meno == "integrita" and kontroly_integrity:
            return any(f.get("check") in kontroly_integrity for f in r["integrity"].get("findings", []))
        return True

    start = float(riadky[0]["timestamp"])
    spustenie = beh.get("launch_unix")
    out = {}
    for meno in ZDROJE_ALARMU:
        casy = [float(r["timestamp"]) for r in riadky if zdroj(r, meno)]
        v = {"udalosti": len(casy)}
        if spustenie is not None:
            v["pred_spustenim"] = sum(t < spustenie for t in casy)
            koniec = aktivacia if aktivacia is not None else float("inf")
            v["medzi_spustenim_a_aktivaciou"] = sum(spustenie <= t < koniec for t in casy)
        if aktivacia is not None:
            v_horizonte = [t for t in casy if aktivacia <= t <= aktivacia + horizont_s]
            v["detekcia"] = bool(v_horizonte)
            v["ttd_s"] = v_horizonte[0] - aktivacia if v_horizonte else None
            v["udalosti_v_horizonte"] = len(v_horizonte)
            if meno == "integrita":
                v["kontroly_v_horizonte"] = sorted({
                    f.get("check") for r in riadky if zdroj(r, meno)
                    and aktivacia <= float(r["timestamp"]) <= aktivacia + horizont_s
                    for f in r["integrity"].get("findings", [])})
        out[meno] = v
    if aktivacia is not None:
        pred = [r for r in riadky if float(r["timestamp"]) <= aktivacia]
        out["alarm_modelu_aktivny_pri_aktivacii"] = bool(pred and pred[-1].get("model_alarm"))
        out["cisty_usek_s"] = spustenie - start
    return out


def useky_kontroly(riadky, perioda_s, horizont_s):
    """Pocet neprekryvajucich sa usekov dlzky horizontu od zaciatku kontroly a usekov s udalostou zdroja."""
    start = float(riadky[0]["timestamp"])
    pocet = int((float(riadky[-1]["timestamp"]) - start + perioda_s) // horizont_s)
    out = {"usekov": pocet}
    for meno, zdroj in ZDROJE_ALARMU.items():
        s_alarmom = {int((float(r["timestamp"]) - start) // horizont_s) for r in riadky
                     if r["alarm_event"] and zdroj in r["alarm_sources"]}
        out["s_alarmom_" + meno] = sum(i < pocet for i in s_alarmom)
    return out


def _nahoda(kontroly, horizont_s, alfa):
    """Pravdepodobnost nahodneho alarmu v useku dlzky horizontu z kontrolnych behov, po zdrojoch."""
    if not kontroly:
        return None
    expozicia = sum(s["sledovany_s"] for s in kontroly)
    usekov = sum(s["useky"]["usekov"] for s in kontroly)
    out = {"kontrol": len(kontroly), "sledovany_s": expozicia, "horizont_s": horizont_s}
    for meno in ZDROJE_ALARMU:
        k = sum(s["udalosti_model" if meno == "model" else "udalosti_integrita"] for s in kontroly)
        dolna, horna = poissonov_interval(k, alfa)
        p = lambda mu: 1 - math.exp(-mu / expozicia * horizont_s)
        s_alarmom = sum(s["useky"]["s_alarmom_" + meno] for s in kontroly)
        out[meno] = {"udalosti": k, "miera_h": k / expozicia * 3600,
                     "p_poisson": p(k), "p_poisson_interval": [p(dolna), p(horna)],
                     "empiricky": {"usekov": usekov, "s_alarmom": s_alarmom,
                                   "podiel": s_alarmom / usekov if usekov else None,
                                   "interval": clopper_pearson(s_alarmom, usekov, alfa)}}
    return out


def _miery_detekcie(behy, nahoda, alfa, min_ttd_s):
    """Miera detekcie, TTD a porovnanie s nahodou nad aktivovanymi behmi, po zdrojoch."""
    from scipy.stats import binomtest
    aktivne = [b for b in behy if b["aktivovany"]]
    n = len(aktivne)
    out = {"spustenych": len(behy), "aktivovanych": n,
           "neaktivovanych": sorted(b["id"] for b in behy if not b["aktivovany"])}
    for meno in ZDROJE_ALARMU:
        detegovane = [b for b in aktivne if b["priebeh"][meno]["detekcia"]]
        ttd = sorted(b["priebeh"][meno]["ttd_s"] for b in detegovane)
        v = {"detegovanych": len(detegovane), "miera": len(detegovane) / n if n else None,
             "interval": clopper_pearson(len(detegovane), n, alfa), "interval_metoda": "Clopper-Pearson",
             "ttd_s": {b["id"]: b["priebeh"][meno]["ttd_s"] for b in detegovane},
             "ttd_median_s": float(np.median(ttd)) if ttd else None,
             "ttd_min_s": ttd[0] if ttd else None, "ttd_max_s": ttd[-1] if ttd else None}
        if meno == "model":
            v["ttd_min_mozny_s"] = min_ttd_s
        if nahoda is not None and n:
            p0 = nahoda[meno]["p_poisson"]
            v["voci_nahode"] = {"p_nahody": p0, "p_nahody_interval": nahoda[meno]["p_poisson_interval"],
                                "p": float(binomtest(len(detegovane), n, min(max(p0, 0.0), 1.0),
                                                     alternative="greater").pvalue) if p0 > 0 else
                                (1.0 if not detegovane else 0.0),
                                "test": "jednostranny binomicky (viac detekcii nez nahoda)"}
        else:
            v["voci_nahode"] = None
        out[meno] = v
    return out


def _reakcie(behy, konfig, alfa):
    """Ocakavana (predregistrovana) a pozorovana reakcia na skupinu spravania."""
    out = {}
    for meno, s in sorted(konfig["skupiny"].items()):
        clenovia = [b for b in behy if b["skupina"] == meno]
        aktivne = [b for b in clenovia if b["aktivovany"]]
        n = len(aktivne)
        zdroje = {}
        for zdroj in ZDROJE_ALARMU:
            k = sum(b["priebeh"][zdroj]["detekcia"] for b in aktivne)
            pozorovane = (k / n >= konfig["prah_reakcie_podiel"]) if n else None
            zdroje[zdroj] = {"ocakavane": s["ocakavane"][zdroj], "pozorovane": pozorovane,
                             "detegovanych": k, "aktivovanych": n, "interval": clopper_pearson(k, n, alfa),
                             "zhoda": None if pozorovane is None else pozorovane == s["ocakavane"][zdroj]}
        zhody = [z["zhoda"] for z in zdroje.values()]
        out[meno] = {"spustenych": len(clenovia), "aktivovanych": n,
                     "kontroly_integrity": s.get("kontroly_integrity"), "zdroje": zdroje,
                     "zhoda": None if None in zhody else all(zhody),
                     "dovod": "bez aktivovaneho behu" if not n else None}
    return out


def _podla(behy, kluc, alfa):
    out = {}
    for hodnota in sorted({b[kluc] for b in behy}):
        clenovia = [b for b in behy if b[kluc] == hodnota]
        aktivne = [b for b in clenovia if b["aktivovany"]]
        out[hodnota] = {"skupina": sorted({b["skupina"] for b in clenovia}),
                        "spustenych": len(clenovia), "aktivovanych": len(aktivne)}
        for zdroj in ZDROJE_ALARMU:
            k = sum(b["priebeh"][zdroj]["detekcia"] for b in aktivne)
            out[hodnota][zdroj] = {"detegovanych": k, "interval": clopper_pearson(k, len(aktivne), alfa)}
    return out


def vyhodnot_malver(index_cesta, prehratia, konfig, alfa=None):
    """Detekcia malveru (dataset 3) z prehrati safeguard replay --archive; kazdy beh prave raz.

    Vzorky a scenare spravania sa vyhodnocuju oddelene; kontrolne behy (izolovana siet
    bez vzorky) davaju pravdepodobnost nahodneho alarmu v useku dlzky horizontu.
    Minima poctu vzoriek sa iba hlasia, vyhodnotenie neodmietnu.
    """
    konfig, konfig_sha, konfig_cesta = nacitaj_konfig_malveru(konfig)
    alfa = _alfa(konfig["alfa"] if alfa is None else alfa)
    horizont = float(konfig["horizont_s"])
    index = nacitaj_index_malveru(index_cesta, konfig)
    protokol = index["protocol_config"]
    perioda, max_medzera, okno = protokol["interval_s"], protokol["max_gap_s"], protokol["window_rows"]
    zaznamy = {b["archive_sha256"]: b for b in index["runs"]}
    balik, balik_sha, relacie = None, None, {}
    for adresar in prehratia:
        konf, stav, riadky, hashe = _nacitaj_prehratie(adresar)
        beh = zaznamy.get(_digest(konf["archive"]))
        if beh is None:
            raise ValueError("%s: archiv nie je behom tohto indexu" % adresar)
        if beh["id"] in relacie:
            raise ValueError("%s: beh %s je prehraty dvakrat" % (adresar, beh["id"]))
        manifest = konf["bundle_manifest"]
        if manifest.get("diagnostic") is not False:
            raise ValueError("%s: diagnosticky balik sa nevyhodnocuje" % adresar)
        kontrakt = manifest["feature_contract"]
        if kontrakt["max_gap_s"] != max_medzera or kontrakt["window_rows"] != okno:
            raise ValueError("%s: casove nastavenia balika sa lisia od protokolu" % adresar)
        if balik is None:
            balik, balik_sha = manifest, _manifest_sha(manifest)
        elif _manifest_sha(manifest) != balik_sha:
            raise ValueError("%s: prehratia pouzili rozne baliky" % adresar)
        if riadky[0]["timestamp"] != beh["start"] or riadky[-1]["timestamp"] != beh["end"]:
            raise ValueError("%s: prehratie nepokryva cely beh" % adresar)
        suhrn = suhrn_relacie(riadky, perioda, max_medzera)
        if (stav.get("scored"), stav.get("input_errors"), stav.get("alarm_events")) != (
                suhrn["skorovanych"], suhrn["chyb_vstupu"], suhrn["udalosti"]):
            raise ValueError("%s: status.json nesedi s events.jsonl" % adresar)
        zaznam = {"id": beh["id"], "druh": beh["kind"], "rodina": beh.get("family"), "skupina": beh.get("group"),
                  "scenar": beh.get("scenario"), "sample_sha256": beh.get("sample_sha256"),
                  "archiv": os.path.realpath(konf["archive"]), "archive_sha256": beh["archive_sha256"],
                  "prehratie": os.path.realpath(adresar), "subory_sha256": hashe,
                  "suhrn": {k: suhrn[k] for k in ("riadkov", "skorovanych", "udalosti_model", "udalosti_integrita",
                                                   "sledovany_s", "skorovany_s", "bez_skore_cas_podiel",
                                                   "chyb_vstupu", "vypadkov", "vypadky_s")}}
        if beh["kind"] == "kontrola":
            zaznam["useky"] = useky_kontroly(riadky, perioda, horizont)
        else:
            aktivovany, cas, dovod = aktivacia_behu(beh)
            kontroly = konfig["skupiny"][beh["group"]].get("kontroly_integrity")
            zaznam.update(aktivovany=aktivovany, aktivacia_unix=cas, dovod_neaktivovany=dovod,
                          spustenie_unix=float(beh["launch_unix"]),
                          dokazy_zdroje=sorted({d["source"] for d in beh["activation"]["evidence"]}),
                          priebeh=priebeh_malveru(riadky, beh, cas, horizont, kontroly))
        relacie[beh["id"]] = zaznam
    chybaju = sorted(b["id"] for b in index["runs"] if b["id"] not in relacie)
    if chybaju:
        raise ValueError("chybaju prehratia behov: %s" % ", ".join(chybaju))
    if index.get("bundle_manifest_sha256") not in (None, balik_sha):
        raise ValueError("prehratia nepouzili balik uvedeny v indexe")

    kontroly = [dict(r["suhrn"], useky=r["useky"]) for r in relacie.values() if r["druh"] == "kontrola"]
    nahoda = _nahoda(kontroly, horizont, alfa)
    min_ttd = balik["calibration"]["k"] * perioda if "k" in balik["calibration"] else None
    casti = {}
    for druh in ("vzorka", "scenar"):
        behy = [r for r in relacie.values() if r["druh"] == druh]
        if not behy:
            casti[druh] = None
            continue
        casti[druh] = {"spolu": _miery_detekcie(behy, nahoda, alfa, min_ttd),
                       "skupiny": {g: _miery_detekcie([b for b in behy if b["skupina"] == g], nahoda, alfa, min_ttd)
                                   for g in sorted({b["skupina"] for b in behy})},
                       "reakcie": _reakcie(behy, konfig, alfa),
                       "podla_rodiny" if druh == "vzorka" else "podla_scenara":
                           _podla(behy, "rodina" if druh == "vzorka" else "scenar", alfa)}
    vzorky = [r for r in relacie.values() if r["druh"] == "vzorka" and r["aktivovany"]]
    minimum = konfig["minimum"]
    na_skupinu = {g: sum(r["skupina"] == g for r in vzorky) for g in sorted(konfig["skupiny"])}
    minima = {"vzorky": {"aktivovanych": len({r["sample_sha256"] for r in vzorky}), "minimum": minimum["vzorky"]},
              "rodiny": {"aktivovanych": len({r["rodina"] for r in vzorky}), "minimum": minimum["rodiny"]},
              "na_skupinu": {"aktivovanych": na_skupinu, "minimum": minimum["na_skupinu"]}}
    for kluc in ("vzorky", "rodiny"):
        minima[kluc]["splnene"] = minima[kluc]["aktivovanych"] >= minima[kluc]["minimum"]
    minima["na_skupinu"]["splnene"] = all(v >= minimum["na_skupinu"] for v in na_skupinu.values())
    minima["vsetky_splnene"] = all(minima[k]["splnene"] for k in ("vzorky", "rodiny", "na_skupinu"))
    minima["poznamka"] = "rataju sa iba aktivovane skutocne vzorky; nesplnene minimum vyhodnotenie neodmietne"
    return {
        "schema": SCHEMA_MALVER, "alfa": alfa, "horizont_s": horizont,
        "min_cisty_usek_s": float(konfig["min_cisty_usek_s"]),
        "index": os.path.realpath(index_cesta), "index_sha256": _digest(index_cesta),
        "konfiguracia": konfig_cesta, "konfiguracia_sha256": konfig_sha,
        "konfiguracia_subor_sha256": _digest(konfig_cesta) if konfig_cesta else None,
        "balik": {"manifest_sha256": balik_sha, "created_utc": balik["created_utc"],
                  "corpus_index_sha256": balik["provenance"]["corpus_index_sha256"],
                  "calibration": balik["calibration"]},
        "perioda_s": perioda, "okno_riadkov": okno,
        "nahodny_alarm": nahoda,
        "vzorky": casti["vzorka"], "scenare": casti["scenar"],
        "minima": minima,
        "pocty": {d: sum(r["druh"] == d for r in relacie.values()) for d in DRUHY_BEHU},
        "relacie": relacie, "predpoklady": [*PREDPOKLADY, *PREDPOKLADY_MALVERU],
        "poznamka": ("Detekcia plati pre tieto vzorky v tomto labe, s tymto balikom a prahom; alarm modelu a nalez "
                     "kontroly integrity su oddelene zdroje. Najmensi mozny TTD modelu je k * perioda (pravidlo k z n)."),
    }, balik


def _git_stav():
    """(commit, zoznam zmenenych ciest) alebo (None, None), ked git nie je k dispozicii."""
    try:
        commit = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True)
        stav = subprocess.run(["git", "-C", REPO, "status", "--porcelain"], capture_output=True, text=True)
    except OSError:
        return None, None
    if commit.returncode or stav.returncode:
        return None, None
    return commit.stdout.strip(), [riadok[3:] for riadok in stav.stdout.splitlines()]


def _arg_alfa(text):
    try:
        return _alfa(float(text))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _hlavny(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="python3 -m tcn.eval",
                                description="FAR/h z prehrati safeguardu (METODIKA_ZBERU.sk.md, kap. 7)")
    sub = p.add_subparsers(dest="prikaz", required=True)
    f = sub.add_parser("far", help="FAR jednej roly korpusu z prehrati safeguard replay --archive")
    f.add_argument("--corpus", required=True, help="index korpusu (corpus.json)")
    f.add_argument("--role", required=True, choices=ROLY_FAR)
    f.add_argument("--replay", required=True, nargs="+", help="vystupne adresare safeguard replay --archive")
    f.add_argument("--out", required=True, help="novy JSON; existujuci sa neprepise")
    f.add_argument("--campaign", help="zaznam kampane v data/results (planovane, prijate a zamietnute behy)")
    f.add_argument("--alfa", type=_arg_alfa, default=0.05)
    f.add_argument("--final", action="store_true",
                   help="povinne pre test_benign: zaverecne FAR, raz na korpus, nad commitnutym kodom")
    u = sub.add_parser("udalosti", help="FAR dnesneho balika pocas prevadzkovych udalosti (protokol v3, krok A)")
    u.add_argument("--index", required=True, help="events_index.json testovacej kampane v3")
    u.add_argument("--replay", required=True, nargs="+", help="vystupne adresare safeguard replay --archive")
    u.add_argument("--out", required=True, help="novy JSON; existujuci sa neprepise")
    u.add_argument("--alfa", type=_arg_alfa, default=0.05)
    m = sub.add_parser("malver", help="detekcia malveru (dataset 3): miera detekcie, TTD, reakcie skupin")
    m.add_argument("--index", required=True, help="index behov (schema %s)" % SCHEMA_INDEX_MALVERU)
    m.add_argument("--config", required=True, help="konfiguracia vyhodnotenia (config/malver-v1.json)")
    m.add_argument("--replay", required=True, nargs="+", help="vystupne adresare safeguard replay --archive")
    m.add_argument("--out", required=True, help="novy JSON; existujuci sa neprepise")
    m.add_argument("--alfa", type=_arg_alfa, default=None, help="predvolene alfa z konfiguracie")
    a = p.parse_args(argv)
    if a.prikaz == "udalosti":
        return _udalosti(a, argv)
    if a.prikaz == "malver":
        return _malver(a, argv)
    values, balik = vyhodnot_far(a.corpus, a.role, a.replay, a.alfa, a.final, a.campaign)
    doc = _zaznam(values, balik, argv)
    commit, zmeny = doc["commit"], doc.pop("_zmeny")
    vlastny = os.path.relpath(os.path.abspath(__file__), REPO)
    if a.final and (commit is None or zmeny is None or vlastny in zmeny):
        raise SystemExit("--final vyzaduje git a commitnuty %s" % vlastny)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    # Vystup vznikne skor nez zaznam o zaverecnom teste: ked --out existuje alebo
    # jeho adresar chyba, jedine zaverecne FAR korpusu sa tym nespotrebuje.
    with open(a.out, "x", encoding="utf-8") as fh:
        if a.final:
            try:
                with open(os.path.realpath(a.corpus) + ".test_benign-final.json", "x", encoding="utf-8") as zaznam:
                    json.dump({"date": doc["date"], "out": os.path.realpath(a.out), "commit": commit,
                               "evaluator_sha256": doc["evaluator_sha256"],
                               "manifest_sha256": values["balik"]["manifest_sha256"]}, zaznam, indent=2)
            except FileExistsError:
                fh.close()
                os.unlink(a.out)
                raise
        fh.write(text)
    spolu = values["merane"]["spolu"]
    klas = values["klasifikacia_aktivit"]
    print(json.dumps({"rola": a.role, "relacii": doc["n"], "udalosti_model": spolu["spolu"]["udalosti_model"],
                      "far_model_skorovany_h": spolu["far_h"]["skorovany"],
                      "aktivity_okna_presnost": klas["okna"]["presnost"],
                      "aktivity_relacie": [klas["relacie"]["spravnych"], klas["relacie"]["spolu"]]},
                     ensure_ascii=False))
    return 0


def _zaznam(values, balik, argv):
    commit, zmeny = _git_stav()
    doc = {"commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
           "evaluator_sha256": _digest(os.path.abspath(__file__)),
           "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "host": platform.platform(),
           "guest": "jadro %s, stack_sha256 %s" % (balik["environment"]["kernel"],
                                                   balik["environment"]["stack_sha256"]),
           "command": shlex.join(["python3", "-m", "tcn.eval", *argv]), "cwd": os.getcwd(),
           "n": len(values["relacie"]), "values": values, "_zmeny": zmeny}
    if zmeny is None:
        doc["commit_note"] = "git nedostupny; kod urcuje evaluator_sha256"
    elif zmeny:
        doc["commit_note"] = "neulozene zmeny: %s; kod urcuje evaluator_sha256" % ", ".join(zmeny)
    return doc


def _udalosti(a, argv):
    values, balik = vyhodnot_udalosti(a.index, a.replay, a.alfa)
    doc = _zaznam(values, balik, argv)
    doc.pop("_zmeny")
    with open(a.out, "x", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
    m = values["merane"]
    print(json.dumps({"relacii": doc["n"], "udalosti": [values["udalosti"]["vykonanych"], values["udalosti"]["planovanych"]],
                      "prevadzka_far_h": m["prevadzka"] and m["prevadzka"]["far_h"]["skorovany"],
                      "udalosti_far_h": m["vsetky_udalosti"] and m["vsetky_udalosti"]["far_h"]["skorovany"]},
                     ensure_ascii=False))
    return 0


def _malver(a, argv):
    values, balik = vyhodnot_malver(a.index, a.replay, a.config, a.alfa)
    doc = _zaznam(values, balik, argv)
    doc.pop("_zmeny")
    with open(a.out, "x", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
    v = values["vzorky"]
    print(json.dumps({"behov": doc["n"], "pocty": values["pocty"],
                      "vzorky_aktivovanych": v and v["spolu"]["aktivovanych"],
                      "detekcia_model": v and [v["spolu"]["model"]["detegovanych"], v["spolu"]["aktivovanych"]],
                      "detekcia_integrita": v and [v["spolu"]["integrita"]["detegovanych"], v["spolu"]["aktivovanych"]],
                      "minima_splnene": values["minima"]["vsetky_splnene"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_hlavny())
