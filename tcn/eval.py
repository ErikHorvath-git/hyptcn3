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
(zaznam '<corpus>.test_benign-final.json' vedla indexu). Detekciu utokov ani
cas do detekcie z toho odvodit nemozno. Ten isty prikaz vyhodnoti aj
klasifikator profilu zataze (trieda okna = scenar relacie), aby jedno
zaverecne spustenie na test_benign dalo oboje.
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
    a = p.parse_args(argv)
    values, balik = vyhodnot_far(a.corpus, a.role, a.replay, a.alfa, a.final, a.campaign)
    commit, zmeny = _git_stav()
    vlastny = os.path.relpath(os.path.abspath(__file__), REPO)
    if a.final and (commit is None or zmeny is None or vlastny in zmeny):
        raise SystemExit("--final vyzaduje git a commitnuty %s" % vlastny)
    doc = {"commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
           "evaluator_sha256": _digest(os.path.abspath(__file__)),
           "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "host": platform.platform(),
           "guest": "jadro %s, stack_sha256 %s" % (balik["environment"]["kernel"],
                                                   balik["environment"]["stack_sha256"]),
           "command": shlex.join(["python3", "-m", "tcn.eval", *argv]), "cwd": os.getcwd(),
           "n": len(values["relacie"]), "values": values}
    if zmeny is None:
        doc["commit_note"] = "git nedostupny; kod urcuje evaluator_sha256"
    elif zmeny:
        doc["commit_note"] = "neulozene zmeny: %s; kod urcuje evaluator_sha256" % ", ".join(zmeny)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if a.final:
        # Jedno zaverecne FAR na korpus: zaznam vedla indexu vznikne pred vysledkom.
        with open(os.path.realpath(a.corpus) + ".test_benign-final.json", "x", encoding="utf-8") as fh:
            json.dump({"date": doc["date"], "out": os.path.realpath(a.out), "commit": commit,
                       "evaluator_sha256": doc["evaluator_sha256"],
                       "manifest_sha256": values["balik"]["manifest_sha256"]}, fh, indent=2)
    with open(a.out, "x", encoding="utf-8") as fh:
        fh.write(text)
    spolu = values["merane"]["spolu"]
    klas = values["klasifikacia_aktivit"]
    print(json.dumps({"rola": a.role, "relacii": doc["n"], "udalosti_model": spolu["spolu"]["udalosti_model"],
                      "far_model_skorovany_h": spolu["far_h"]["skorovany"],
                      "aktivity_okna_presnost": klas["okna"]["presnost"],
                      "aktivity_relacie": [klas["relacie"]["spravnych"], klas["relacie"]["spolu"]]},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_hlavny())
