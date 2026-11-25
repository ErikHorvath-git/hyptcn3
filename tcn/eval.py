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
casu bez skore. Nalezy integrity, vypadky a chyby vstupu na prijatych relaciach
korpusu urcuje uz prijatie (scripts/collection.py audit): nalezy a vypadky su
nulove, chybou vstupu je iba riadok, ktory toleruje pravidlo invalid_rows
protokolu. Taky riadok detektor neskoruje a prehratie ho uvadza ako chybu
vstupu. Preto idu tieto pocty do casti 'dane_prijatim_korpusu' bez intervalu
a prehratie s chybou vstupu mimo toho pravidla prikaz odmietne. Tak isto to
overuje `python3 -m tcn.eval udalosti` (cast 'dane_prijatim_relacii').
test_benign je zaverecny test (kap. 5):
prikaz ho pusti iba s --final, nad commitnutym tcn/eval.py a iba raz na korpus
(zaznam '<corpus>.test_benign-final.json' vedla indexu vznikne az po --out). Detekciu utokov ani
cas do detekcie z toho odvodit nemozno. Ten isty prikaz vyhodnoti aj
klasifikator profilu zataze (trieda okna = scenar relacie), aby jedno
zaverecne spustenie na test_benign dalo oboje.

PROTOKOL V5 (balik B7c, agent M)
--------------------------------
Navrh dokazy/B7/navrh/NAVRH_B7c.md 1.2 a 1.3, kostra dokazy/B7/kostra/KOSTRA.md bod 7 a doplnok 2 body 2 a 4.
Pri korpuse protokolu schemy 3 `far` aj `udalosti` pocitaju okrem dnesnych tabuliek blok `v5` (metriky_v5):
po kanaloch detektora (rule, neural, kernel_integrity) a za ich zjednotenie (union) z riadkov prehratia
(channel_edges: nabezne hrany zdrojov z alarm_sources, zjednotenie z prechodov pola alarm):
  o2          falosne alarmy v cistej prevadzke za pozorovanu hodinu s jednostrannou hranicou (navrh 4.2, 9.2)
  thesis      metriky textu prace: alarmy za hodinu vyhodnoteneho casu s Garwoodovym intervalom, pocet bootovych
              skupin, test rozptylu medzi session, miera pocas udalosti proti cistej prevadzke (jednostranny
              exaktny test), spolu a po typoch udalosti
  o3          podiel hodnotitelnych vyskytov udalosti s alarmom po typoch, s hranicou (navrh 4.2, 6.4)
  o4          kontroly na VM (channel_reacted nad oknom scripts/controls.py outcomes), zachytene z planovanych,
              "nezachytené, senzor neskóroval" zvlast
  classifier  presnost a makro-F1 nad oknami, vacsinova trieda na session a na vyskyt (balik bez tried ho nema)
  unscored    neskorovany cas po session, kontextoch, typoch a kontrolach ako "nevyhodnotené", nikdy ako ticho
Cista prevadzka je pravidlo tcn/metody.py (otazka Q12, prijate veducim 2026-11-24; CONTEXT_RULE),
dozvuk je analysis.reverberation_s, horizont analysis.horizon_s, hodnotitelny vyskyt analysis.evaluable a cisla
metrik analysis.metrics (scripts/protocol_v5.py metrics_problem). Roly su dev, calibration, test_benign a
test_controls; zapecatenu rolu (test_benign, test_controls) vyhodnoti iba finalny prikaz (final_evaluation=True)
alebo index generalky (plan_mode rehearsal, kazdy vystup nesie jej znacku, tcn.pecat REHEARSAL_MARK); --final a jeho
znacka vedla indexu ostavaju schemam 1 a 2. Kazde prehratie korpusu schemy 3 pred citanim riadkov skontroluje pecat
podla archive_sha256 jeho configuration.json (SEAL_RULE, navrh B7c 5.5): prehratie zapecateneho archivu kampane sa
cita iba vnutri finalneho behu, ktory jeho pecat spotreboval. Neskorovane useky su useky safeguard.runtime.unscored
(jedno pravidlo, navrh B7c 5.6). Zaznam far a udalosti nesie stupen (navrh 11.1) podla tcn.pecat STAGE_RULE z rezimu
planu a knihy procesu, sprisneneho nalezom N2 B7c (balik B9b, tcn.pecat record_stage, RECORD_STAGE_RULE): final alebo
generalka iba ked kniha zaznamu drzi archiv kazdej relacie zapecatenych roli indexu (pri final aj kniha na HEAD),
inak suchy, s dovodom v stage_basis; O4 dava v kazdej skupine prirastok neuronoveho kanala nad pravidlovym
(INCREMENT_RULE) a miera textu prace aj Garwoodov interval za skorovanu hodinu. Pri kazdom treningu (otazka Q11,
prijate veducim 2026-11-24) training_summary dava stratu modelu voci Z3 a Z5 a suhrn skore po kontexte a scenari a
training_record zaznam, ktory menuje balik.
`malver` sa nemeni (D16).

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

# Package B7c: the constants it shares (the channels and sources of a replay row, the roles a training reads, the
# protocol schema 3 with its plan modes and the role of the controls, the one rehearsal mark of design B7c 5.1);
# none of these modules imports torch.
from features.dataset import FIT_ROLES
from safeguard.runtime import CHANNELS, SOURCES
from scripts.protocol_v5 import CONTROL_ROLE, MODES, SCHEMA as SCHEMA_PROTOKOLU_V5
from tcn.pecat import REHEARSAL_MARK

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
    # Neplatny riadok archivu (detektor ho neskoruje); iba taku chybu vstupu moze tolerovat pravidlo invalid_rows.
    neplatnych = sum(r["model_state"] == "input_error" and r.get("reason") == "invalid_input" for r in riadky)
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
        "neplatnych_riadkov": neplatnych,
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


def _pecat_prehratia(adresar, rola, prikaz):
    """SEAL_RULE for one replay directory of a corpus of protocol schema 3, before its rows are read: (the decision of
    tcn.pecat kontrola, the archive_sha256 the replay names)."""
    from tcn import pecat
    konf = json.loads(open(os.path.join(adresar, "configuration.json"), encoding="utf-8").read())
    sha = konf.get("archive_sha256") if type(konf) is dict else None
    if not _hex64(sha):
        raise ValueError(f"{adresar}: the replay of a session of role {rola} names no archive_sha256 in its "
                         "configuration.json (safeguard replay --archive and tcn.porovnanie replay write it since "
                         "package B7c): under protocol schema 3 the seal decides by it whether the replay may be read "
                         "(tcn.eval SEAL_RULE)")
    # The archive's path, which safeguard replay --archive writes beside its sha256, lets the seal bind the replay by
    # the session of its directory and by its content too, not by its bytes alone (the lead's answer to Q31 and his
    # note on the second G0 verification, 2026-11-25).
    archive = konf.get("archive")
    paths = [archive] if type(archive) is str else None
    return pecat.kontrola(sha256=sha, paths=paths, purpose=f"tcn.eval {prikaz}",
                          what=f"the archive of the replay {adresar}"), sha


def _archiv_prehratia(adresar, konf, archiv_sha):
    """The sha256 of the archive a replay names; under protocol schema 3 (archiv_sha the archive_sha256 the seal was
    checked by) it must be that archive_sha256 (SEAL_RULE)."""
    digest = _digest(konf["archive"])
    if archiv_sha is not None and digest != archiv_sha:
        raise ValueError(f"{adresar}: the archive {konf['archive']} has sha256 {digest}, the replay names "
                         f"archive_sha256 {archiv_sha}: the replay is not of this archive (tcn.eval SEAL_RULE)")
    return digest


def _manifest_sha(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def _over_chyby_vstupu(adresar, stav, riadky, suhrn, protokol):
    """Stav prehratia sedi s riadkami a chybou vstupu je iba riadok, ktory toleruje pravidlo invalid_rows.

    Relacie korpusu aj indexu udalosti prijal audit podla protokolu, takze v
    prehrati prijateho archivu moze byt chybou vstupu iba riadok tolerovany tym
    pravidlom. Je to to iste pravidlo ako v audite, stavbe korpusu a treningu
    (features/quality.py); prehratie s inou chybou vstupu sa nevyhodnocuje.
    """
    from features.quality import tolerated_input_errors
    if (stav.get("scored"), stav.get("input_errors"), stav.get("alarm_events")) != (
            suhrn["skorovanych"], suhrn["chyb_vstupu"], suhrn["udalosti"]):
        raise ValueError("%s: status.json nesedi s events.jsonl" % adresar)
    if tolerated_input_errors(riadky, protokol) is None:
        raise ValueError("%s: chyba vstupu, ktoru pravidlo invalid_rows protokolu netoleruje" % adresar)


def _nacitaj_rolu(korpus, rola, prehratia, *, final, final_evaluation):
    """Prehratia jednej roly korpusu, skontrolovane; kazda relacia roly prave raz (vyhodnot_far, nacitaj_v5).

    Schemy 1 a 2: roly ROLY_FAR a znacka --final ako doteraz. Schema 3 (balik B7c): roly ROLY_V5 a pecat
    (_rola_v5), pecat kazdeho prehratia pred citanim jeho riadkov (SEAL_RULE, _pecat_prehratia); ku kazdej relacii
    jej events.json a pri test_controls jej controls.json (hashe indexu)."""
    index = json.loads(open(korpus, encoding="utf-8").read())
    if index.get("schema") != SCHEMA_KORPUS or index.get("complete") is not True:
        raise ValueError("korpus nie je uplny index %s" % SCHEMA_KORPUS)
    protokol = index["protocol_config"]
    rezim = None
    if _je_v5(protokol):
        rezim = _rola_v5(index, rola, final=final, final_evaluation=final_evaluation, prikaz="far")
    else:
        if final_evaluation is not False:
            raise ValueError("final_evaluation patri finalnemu prikazu protokolu schemy 3 (balik B7c)")
        if rola not in ROLY_FAR:
            raise ValueError("FAR sa pocita iba pre role %s" % ", ".join(ROLY_FAR))
        if (rola == "test_benign") != bool(final):
            raise ValueError("test_benign je zaverecny test (METODIKA kap. 5) a pusti sa iba s --final; "
                             "--final plati iba pre test_benign")
    perioda, max_medzera = protokol["interval_s"], protokol["max_gap_s"]
    zaznamy = {z["features_sha256"]: z for z in index["sessions"] if z["role"] == rola}
    if not zaznamy:
        raise ValueError("korpus nema relacie roly %s" % rola)
    korpus_sha = _digest(korpus)
    balik, balik_sha, relacie, v5, rozhodnutia = None, None, {}, [], {}
    for adresar in prehratia:
        rozhodnutie, archiv_sha = _pecat_prehratia(adresar, rola, "far") if rezim is not None else (None, None)
        konf, stav, riadky, hashe = _nacitaj_prehratie(adresar)
        zaznam = zaznamy.get(_archiv_prehratia(adresar, konf, archiv_sha))
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
        # Chyby vstupu sa nizsie uvadzaju ako dane prijatim korpusu; to plati iba pre riadky tolerovane pravidlom.
        _over_chyby_vstupu(adresar, stav, riadky, suhrn, protokol)
        relacie[zaznam["id"]] = dict(suhrn, scenario=zaznam["scenario"], skupina=zaznam["group"],
                                     features_sha256=zaznam["features_sha256"],
                                     archiv=os.path.realpath(konf["archive"]),
                                     prehratie=os.path.realpath(adresar), subory_sha256=hashe)
        if rezim is not None:
            udalosti, kontroly = _subory_v5(zaznam, rola)
            v5.append({"zaznam": zaznam, "riadky": riadky, "udalosti": udalosti, "kontroly": kontroly})
            rozhodnutia[zaznam["id"]] = rozhodnutie["allowed"]
    chybaju = sorted(z["id"] for z in zaznamy.values() if z["id"] not in relacie)
    if chybaju:
        raise ValueError("chybaju prehratia relacii: %s" % ", ".join(chybaju))
    if type(balik.get("classes")) is not list:
        raise ValueError("manifest balika nema zoznam tried (classes)")
    return {"index": index, "protokol": protokol, "korpus_sha": korpus_sha, "relacie": relacie, "balik": balik,
            "balik_sha": balik_sha, "rezim": rezim, "v5": v5 if rezim is not None else None,
            "pecat": {"decisions": dict(sorted(rozhodnutia.items())), "definition": SEAL_RULE} if rezim is not None
            else None}


def vyhodnot_far(korpus, rola, prehratia, alfa=0.05, final=False, kampan=None, *, final_evaluation=False,
                 vysledky_kontrol=None):
    """FAR jednej roly korpusu z prehrati; kazda relacia roly prave raz.

    Schema 3 (balik B7c): roly ROLY_V5, zapecatenu rolu iba s final_evaluation=True (finalny prikaz) alebo pri indexe
    generalky, kazde prehratie az po pecati (SEAL_RULE: prehratie zapecateneho archivu kampane iba vnutri finalneho
    behu); values navyse nesu blok v5 (metriky_v5; vysledky_kontrol pre O4 roly test_controls), rezim planu, znacku
    generalky a rozhodnutia pecate (pecat). Balik bez tried (zakladna metoda tcn/porovnanie.py) nema tabulky
    klasifikatora."""
    alfa = _alfa(alfa)
    d = _nacitaj_rolu(korpus, rola, prehratia, final=final, final_evaluation=final_evaluation)
    if d["rezim"] is None and vysledky_kontrol is not None:
        raise ValueError("vysledky kontrol (O4) patria role test_controls korpusu protokolu schemy 3")
    protokol, relacie, balik, balik_sha, korpus_sha = (d[k] for k in ("protokol", "relacie", "balik", "balik_sha",
                                                                      "korpus_sha"))
    perioda, max_medzera = protokol["interval_s"], protokol["max_gap_s"]
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
                     + ("test_benign (--final)." if d["rezim"] is None else
                        "zapecatenych rolach (finalny prikaz, protokol schemy 3)."))
    if rola == "calibration":
        poznamka += (" Z roly calibration je prah balika (threshold_fit_role), toto FAR preto nie je drzane bokom.")
    triedy = balik["classes"]
    values = {
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
            "neplatnych_riadkov": sum(s["neplatnych_riadkov"] for s in zoznam),
            "vypadkov": sum(s["vypadkov"] for s in zoznam),
            "vypadky_s": sum(s["vypadky_s"] for s in zoznam),
            "integrita_uzavretych_riadkov": sum(s["integrita_uzavretych_riadkov"] for s in zoznam),
            "integrita_neuzavrete": dict(sorted(neuzavrete.items())),
            "poznamka": ("prijatie do korpusu zamieta relacie s nalezom integrity, medzerou, chybou citania "
                         "alebo neplatnym riadkom mimo pravidla invalid_rows protokolu (scripts/collection.py "
                         "audit), takze tieto hodnoty nie su meranim detektora; riadok tolerovany tym pravidlom "
                         "detektor neskoruje, prehratie ho uvadza ako chybu vstupu (neplatnych_riadkov) a okna "
                         "s nim su v podiele bez skore; vypadky senzora a integritu bez vyberu meria safeguard run"),
        },
        "klasifikacia_aktivit": klasifikacia_aktivit(relacie, triedy, alfa) if triedy else None,
        "relacie": relacie, "zdroje_udalosti": zdroje, "predpoklady": PREDPOKLADY, "poznamka": poznamka,
    }
    if not triedy:
        values["klasifikacia_aktivit_dovod"] = BEZ_TRIED
    if d["rezim"] is not None:
        values.update(_znacka_v5(d["rezim"], final_evaluation, d["index"]["sessions"]), pecat=d["pecat"],
                      v5=metriky_v5(protokol, d["v5"], triedy=triedy, rola=rola, vysledky_kontrol=vysledky_kontrol))
    return values, balik


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
# Schema 3 (balik B7c): kategorie riadkov su CONTEXT_RULE s dozvukom analysis.reverberation_s, nie pravidlo vyssie.
PREDPOKLADY_UDALOSTI_V5 = [
    "kategoria riadku podla CONTEXT_RULE (tcn/metody.py CLEAN_RULE, otazka Q12, prijate veducim 2026-11-24): "
    "rozpatie riadku od riadku o required_rows - 1 skor po riadok; udalost, ked rozpatie zasahuje [host start, host "
    "stop hotovy], dozvuk analysis.reverberation_s po nej, kontrola s dozvukom ako udalost (kategoria kontrola), "
    "inak cista prevadzka",
    PREDPOKLADY_UDALOSTI[2], PREDPOKLADY_UDALOSTI[3],
]


def kategorie_udalosti(riadky, udalosti, perioda_s, okno, dozvuk_s=DOZVUK_S):
    """Kategoria kazdeho riadku: typ udalosti, 'po_udalosti', 'prevadzka' alebo None (vylucene).

    Pravidlo protokolov v3 a v4 (schemy 1 a 2) s dozvukom dozvuk_s; pod schemou 3 plati CONTEXT_RULE
    (_kategorie_v5)."""
    sirka = (okno - 1) * perioda_s
    vysledok = []
    for r in riadky:
        t = float(r["timestamp"])
        prekryv = [u for u in udalosti if u["host_start_unix"] <= t and t - sirka <= u["host_stopped_unix"]]
        dozvuk = [u for u in udalosti if u["host_stopped_unix"] < t - sirka <= u["host_stopped_unix"] + dozvuk_s]
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


def priebeh_udalosti(riadky, udalost, perioda_s, okno, dozvuk_s=DOZVUK_S):
    """Oneskorenie prveho alarmu modelu od zaciatku udalosti a ci alarm odznie po dozvuku (dozvuk_s)."""
    sirka = (okno - 1) * perioda_s
    koniec = udalost["host_stopped_unix"] + sirka
    pocas = [r for r in riadky if udalost["host_start_unix"] <= float(r["timestamp"]) <= koniec]
    dozvuk = [r for r in riadky if koniec < float(r["timestamp"]) <= koniec + dozvuk_s]
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


def alokacia_indexu_udalosti(index):
    """
    Alokacia indexu udalosti: uplna, alebo vyslovne prijata neuplna.

    Bezec kampane zapise index iba pri uplnej alokacii (scripts/campaign.py
    finish_corpus). Index uzavretej kampane s mensim poctom relacii ma
    complete false a blok incomplete_allocation s rozhodnutim vlastnika
    (zostavuje ho zaznam kampane v data/results). Bez neho sa neuplny index
    odmietne, uplny index s takym blokom tiez (protireci si). S blokom musia
    sediet pocty: planovane = indexovane + zamietnute +
    nezozbierane, mena sa neopakuju a pocty v skupinach su zo zaznamov.
    Popis ide do vysledku, aby sa neuplnost nestratila.
    """
    a = index.get("incomplete_allocation")
    if index.get("complete") is True:
        if a is not None:
            raise ValueError("index udalosti je uplny a zaroven ma blok neuplnej alokacie")
        return {"uplna": True}
    if index.get("complete") is not False or not isinstance(a, dict) or a.get("accepted") is not True:
        raise ValueError("neuplny index %s bez vyslovne prijatej neuplnej alokacie" % SCHEMA_INDEX_UDALOSTI)
    if not isinstance(a.get("decision"), str) or not a["decision"].strip():
        raise ValueError("neuplna alokacia indexu udalosti nema rozhodnutie")
    ostatne = {}
    for kluc in ("rejected", "not_captured"):
        zoznam = a.get(kluc)
        if not isinstance(zoznam, list) or any(not isinstance(z, dict) or not isinstance(z.get("id"), str)
                                               for z in zoznam):
            raise ValueError("neuplna alokacia indexu udalosti: %s musi byt zoznam relacii s id" % kluc)
        ostatne[kluc] = [z["id"] for z in zoznam]
    relacie = [z["id"] for z in index["sessions"]]
    vsetky = relacie + ostatne["rejected"] + ostatne["not_captured"]
    skupiny = dict(sorted(collections.Counter(z["group"] for z in index["sessions"]).items()))
    if (len(set(vsetky)) != len(vsetky) or len(vsetky) != index.get("planned_sessions")
            or a.get("planned_sessions") != index.get("planned_sessions")
            or a.get("indexed_sessions") != len(relacie) or a.get("sessions_per_group") != skupiny):
        raise ValueError("pocty neuplnej alokacie indexu udalosti nesedia so zaznamami")
    return {"uplna": False, "planovanych": index["planned_sessions"], "indexovanych": len(relacie),
            "zamietnute": ostatne["rejected"], "nezozbierane": ostatne["not_captured"],
            "relacii_v_skupinach": skupiny, "rozhodnutie": a["decision"]}


def udalosti_z_korpusu(korpus, rola):
    """Krok B (E2'): relacie jednej roly korpusu s udalostami v tvare indexu udalosti.

    Korpus musi byt uplny a jeho protokol musi mat udalosti v kazdej relacii
    (protokol v4, NAVRH_PROTOKOL_V3 kap. 4, krok B). Rola test_benign je
    odlozeny test; ze ho balik nevidel, overi vyhodnot_udalosti cez
    provenance.corpus_index_sha256.
    """
    if korpus.get("complete") is not True:
        raise ValueError("korpus nie je uplny index %s" % SCHEMA_KORPUS)
    roly = ROLY_V5 if _je_v5(korpus.get("protocol_config")) else ROLY_FAR
    if rola not in roly:
        raise ValueError("FAR pocas udalosti z korpusu sa pocita iba pre role %s" % ", ".join(roly))
    if "events" not in korpus["protocol_config"]:
        raise ValueError("protokol korpusu nema udalosti")
    relacie = [z for z in korpus["sessions"] if z["role"] == rola]
    if not relacie or any("events" not in z or "events_sha256" not in z for z in relacie):
        raise ValueError("relacie roly %s nemaju zaznam udalosti" % rola)
    # Index udalosti nesie hashe extrakcie pri kazdej relacii; korpus ich ma v audite relacie, na ktory sa viaze hashom.
    for i, z in enumerate(relacie):
        if _digest(z["audit"]) != z["audit_sha256"]:
            raise ValueError("audit relacie %s sa zmenil od indexu korpusu" % z["id"])
        audit = json.loads(open(z["audit"], encoding="utf-8").read())
        relacie[i] = dict(z, extractor_sha256=audit["values"]["extractor_sha256"])
    return {"schema": SCHEMA_INDEX_UDALOSTI, "complete": True, "planned_sessions": len(relacie),
            "protocol_sha256": korpus["protocol_sha256"], "protocol_config": korpus["protocol_config"],
            "sessions": relacie}


def vyhodnot_udalosti(index_cesta, prehratia, alfa=0.05, rola=None, *, final_evaluation=False):
    """FAR balika pocas prevadzkovych udalosti, po typoch a triedach.

    Krok A: index udalosti testovacej kampane v3 (rola None). Krok B (E2'):
    korpus protokolu v4 a jeho rola; balik musi byt natrenovany na tomto korpuse.
    Schema 3 (balik B7c): iba korpus a rola z ROLY_V5 s pecatou ako vyhodnot_far (_rola_v5, pecat kazdeho
    prehratia SEAL_RULE), dozvuk analysis.reverberation_s, kategorie riadkov podla CONTEXT_RULE (kontrola je
    kategoria 'kontrola') a blok v5 (metriky_v5, bez vysledkov kontrol: O4 dava far).
    """
    alfa = _alfa(alfa)
    index = json.loads(open(index_cesta, encoding="utf-8").read())
    korpus_sha, rezim, relacie_korpusu = None, None, None
    if index.get("schema") == SCHEMA_KORPUS:
        if rola is None:
            raise ValueError("pri korpuse treba urcit rolu")
        if _je_v5(index.get("protocol_config")):
            rezim = _rola_v5(index, rola, final=False, final_evaluation=final_evaluation, prikaz="udalosti")
            relacie_korpusu = index["sessions"]  # Balik B9b: stupen zaznamu podla relacii celeho korpusu (N2 B7c).
        elif final_evaluation is not False:
            raise ValueError("final_evaluation patri finalnemu prikazu protokolu schemy 3 (balik B7c)")
        index, korpus_sha = udalosti_z_korpusu(index, rola), _digest(index_cesta)
    elif rola is not None:
        raise ValueError("rola plati iba pre korpus %s" % SCHEMA_KORPUS)
    elif final_evaluation is not False:
        raise ValueError("final_evaluation patri finalnemu prikazu protokolu schemy 3 (balik B7c)")
    elif _je_v5(index.get("protocol_config")):
        raise ValueError("pri protokole schemy 3 cita udalosti korpus a rolu (pecat roly, balik B7c), nie index "
                         "udalosti")
    if index.get("schema") != SCHEMA_INDEX_UDALOSTI:
        raise ValueError("nie je index %s" % SCHEMA_INDEX_UDALOSTI)
    alokacia = alokacia_indexu_udalosti(index)
    protokol = index["protocol_config"]
    perioda, max_medzera, okno = protokol["interval_s"], protokol["max_gap_s"], protokol["window_rows"]
    dozvuk = dozvuk_s(protokol)
    v5 = []
    # Schema 3 (protocol v5, scripts/protocol_v5.py) names the map of event types to classes events.types.
    triedy = protokol["events"]["types" if protokol.get("schema") == "hyptcn3/collection-protocol/3" else "classes"]
    zaznamy = {z["features_sha256"]: z for z in index["sessions"]}
    balik, balik_sha, relacie, priebehy, rozhodnutia = None, None, {}, [], {}
    po_kategoriach = collections.defaultdict(list)
    for adresar in prehratia:
        rozhodnutie, archiv_sha = (_pecat_prehratia(adresar, rola, "udalosti") if rezim is not None
                                   else (None, None))
        konf, stav, riadky, hashe = _nacitaj_prehratie(adresar)
        zaznam = zaznamy.get(_archiv_prehratia(adresar, konf, archiv_sha))
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
        if korpus_sha is not None and manifest["provenance"]["corpus_index_sha256"] != korpus_sha:
            raise ValueError("%s: balik nie je natrenovany na tomto korpuse" % adresar)
        if riadky[0]["timestamp"] != zaznam["start"] or riadky[-1]["timestamp"] != zaznam["end"]:
            raise ValueError("%s: prehratie nepokryva celu relaciu" % adresar)
        if _digest(zaznam["events"]) != zaznam["events_sha256"]:
            raise ValueError("%s: events.json sa zmenil od indexu" % adresar)
        udalosti = json.loads(open(zaznam["events"], encoding="utf-8").read())["events"]
        suhrn = suhrn_relacie(riadky, perioda, max_medzera)
        _over_chyby_vstupu(adresar, stav, riadky, suhrn, protokol)
        if rezim is None:
            kategorie = kategorie_udalosti(riadky, udalosti, perioda, okno)
        else:
            udalosti, kontroly = _subory_v5(zaznam, rola)
            kategorie = _kategorie_v5(riadky, udalosti, kontroly, protokol, zaznam["id"])
            v5.append({"zaznam": zaznam, "riadky": riadky, "udalosti": udalosti, "kontroly": kontroly})
            rozhodnutia[zaznam["id"]] = rozhodnutie["allowed"]
        for kategoria, e in _expozicia(riadky, kategorie, perioda).items():
            po_kategoriach[kategoria].append(dict(e, relacia=zaznam["id"], skupina=zaznam["group"]))
        priebehy += [dict(priebeh_udalosti(riadky, u, perioda, okno, dozvuk), relacia=zaznam["id"],
                          skupina=zaznam["group"]) for u in udalosti]
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
    values = {
        "schema": SCHEMA_FAR_UDALOSTI, "alfa": alfa, "dozvuk_s": dozvuk,
        "index": os.path.realpath(index_cesta), "index_sha256": _digest(index_cesta),
        "protokol": protokol["name"], "protocol_sha256": index["protocol_sha256"], "alokacia": alokacia,
        "korpus_rola": rola,
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
        "dane_prijatim_relacii": {
            "chyb_vstupu": sum(s["chyb_vstupu"] for s in relacie.values()),
            "neplatnych_riadkov": sum(s["neplatnych_riadkov"] for s in relacie.values()),
            "poznamka": ("prijatie relacie (scripts/collection.py audit) zamieta neplatny riadok mimo pravidla "
                         "invalid_rows protokolu, takze tieto hodnoty nie su meranim detektora; riadok tolerovany "
                         "tym pravidlom detektor neskoruje, prehratie ho uvadza ako chybu vstupu a riadky bez skore "
                         "(on a zahrievanie okna po nom) su v sledovanom case svojej kategorie, nie v skorovanom; "
                         "pocty su za cele relacie, takze zahrnaju aj riadok vo vylucenom useku (udalost bez dokazu "
                         "a jej dozvuk), ktory nie je v case ziadnej kategorie a relacia ho ma vo vylucenych_riadkov; "
                         "prehratie s inou chybou vstupu sa nevyhodnoti"),
        },
        "relacie": relacie,
        "predpoklady": [*PREDPOKLADY, *(PREDPOKLADY_UDALOSTI if rezim is None else PREDPOKLADY_UDALOSTI_V5)],
        "poznamka": ("Prevadzkove udalosti su benigne; kazdy alarm je falosny. Vysledok plati iba pre tieto typy "
                     "udalosti v labe a nehovori nic o detekcii utokov ani malveru (HONESTY P4)."),
    }
    if rezim is not None:
        if type(balik.get("classes")) is not list:
            raise ValueError("manifest balika nema zoznam tried (classes)")
        values.update(_znacka_v5(rezim, final_evaluation, relacie_korpusu),
                      pecat={"decisions": dict(sorted(rozhodnutia.items())), "definition": SEAL_RULE},
                      v5=metriky_v5(protokol, v5, triedy=balik["classes"], rola=rola))
    return values, balik


# Pod schemou 3 sa kategorie CONTEXT_RULE pomenuju ako kategorie protokolov v3 a v4 (prevadzka, po_udalosti, typ
# udalosti, None); riadok pri kontrole ma kategoriu 'kontrola' (nie je cistou prevadzkou ani vylucenym usekom).
KATEGORIE_V5 = {"clean": "prevadzka", "reverberation": "po_udalosti", "control": "kontrola"}


def _kategorie_v5(riadky, udalosti, kontroly, protokol, ident):
    return [None if c is None else t if c == "event" else KATEGORIE_V5[c]
            for c, t in row_contexts(riadky, udalosti, kontroly, protokol, ident=ident)]


# ------------------------------------------------------------- protokol v5 (balik B7c, agent M)
#
# The metrics of design B7c 1.3 on the replays of one role of a corpus of protocol schema 3 and one model (a bundle
# of M at one seed, or a baseline of tcn/porovnanie.py), per channel of the detector and for their union. The final
# command (tcn/finalne.py, agent E) calls them for every sealed role and model: vyhodnot_far (or nacitaj_v5 and
# metriky_v5 on what it loaded), channel_reacted for every control occurrence (scripts/controls.py outcomes inside the
# final command), training_summary and training_record per training. No function here opens a feature archive: the
# replays are read, the archives only hashed (as since iteration 1).

SCHEMA_V5 = "hyptcn3/v5-metrics/1"  # values["v5"] of far and udalosti under schema 3 (metriky_v5)
SCHEMA_REAKCIE = "hyptcn3/channel-reacted/1"  # channel_reacted
SCHEMA_TRENING = "hyptcn3/training-evaluation/1"  # training_record
SCHEMA_SUHRN_TRENINGU = "hyptcn3/training-summary/1"  # training_summary
# The source of each channel (safeguard.runtime CHANNELS and SOURCES name them in different orders) and the union.
CHANNEL_SOURCES = {"rule": "rule_anomaly", "neural": "model_anomaly", "kernel_integrity": "kernel_integrity"}
assert tuple(CHANNEL_SOURCES) == CHANNELS and set(CHANNEL_SOURCES.values()) == set(SOURCES)
SOURCE_CHANNELS = {source: channel for channel, source in CHANNEL_SOURCES.items()}
UNION = "union"
OUTPUTS = (*CHANNELS, UNION)  # Every metric of the block v5 is given for each channel and for the union.
ROLY_V5 = ("dev", "calibration", "test_benign", "test_controls")  # The roles far and udalosti take under schema 3.
SEALED_ROLES = ("test_benign", "test_controls")  # Design B7c 1.1: the roles of the seal.
CONTEXTS = ("clean", "event", "reverberation", "control")
# Question Q11 (accepted by the lead 2026-11-24: package B7): the summary of a training reads a held-out fit role
# (features/dataset.py FIT_ROLES but train, which the predictor is fitted on; judgment); never a sealed role.
TRAINING_ROLES = tuple(role for role in FIT_ROLES if role != "train")
# Proposal 6.4: what is not evaluated (tcn/metody.py UNEVALUATED, one string; a test pins it), and the three results
# of a control's channel (O4): detected, not detected, and its own result when the sensor scored no row.
UNEVALUATED = "nevyhodnotené"
EVALUATED = "evaluated"
DETECTED, MISSED, NOT_SCORED = "zachytené", "nezachytené", "nezachytené, senzor neskóroval"

EDGE_RULE = (
    "the edges of a replay (safeguard.runtime Detector: one row per frame of the archive, one session): a channel "
    "(rule, neural, kernel_integrity) rises at a row whose alarm_sources holds its source (rule_anomaly, "
    "model_anomaly, kernel_integrity), where its alarm is up and was not up before by the detector's own state; the "
    "union rises at a row whose alarm (the union of the channels up) is true while it was false at the row before it, "
    "or at the first row when true there (the detector starts with every alarm down), so an alarm of two channels at "
    "once is one alarm of the union (design B7c 1.3, finding F2 of the verification of B6b); a channel judges a row "
    "when the row has its input (neural: a score; rule: rule.state judged; kernel_integrity: integrity.conclusive), "
    "the union when one of them does, and a rate of a channel that judged no row of its set is nevyhodnotené")
CONTEXT_RULE = (
    "the context of a replay row (question Q12, accepted by the lead 2026-11-24: tcn/metody.py CLEAN_RULE and "
    "OBSERVED_RULE applied to the rows of the replay): the span of a row runs from the row L - 1 rows before it (the "
    "replay's first row when fewer; L the required_rows of the replay, window_rows and the anchor when anchored) to "
    "the row; the row is excluded when its span meets the closed interval [host_start_unix, host_stopped_unix + "
    "analysis.reverberation_s] of an event that did not run (executed false: such an event and its windows enter no "
    "metric, NAVRH_PROTOKOL_V3 kap. 5); else it is in the event whose [host_start_unix, host_stopped_unix] its span "
    "meets (context event, with the event's type); else in a control when its span meets the closed interval "
    "[host_start_unix, host_stopped_unix + reverberation_s] of a control (controls.json, either polarity, as "
    "tcn/metody.py CLEAN_RULE); else in the reverberation of an event when it meets [host_start_unix, "
    "host_stopped_unix + reverberation_s]; else it is clean traffic (proposal 4.2: the time outside the events and "
    "their reverberation); the observed time is one interval_s per row, the scored time one per row with a score "
    "(tcn/metody.py OBSERVED_RULE); a window of a window set takes the span of its frames (training_summary)")
O2_RULE = (
    "O2 (proposal 4.2): the alarms of each channel and of the union that begin at a clean row (an edge, EDGE_RULE, at "
    "a row of context clean, CONTEXT_RULE) per observed hour of clean traffic, with the exact one-sided upper bound "
    "of analysis.metrics.o2_bound, chi2.ppf(level, 2k + 2) / 2 alarms over those hours; beside them the scored clean "
    "hours, the alarms per scored clean hour, the scored share and the unscored clean time, nevyhodnotené (proposal "
    "6.4, G1: an unscored stretch is reported, never silence) and the same bound per scored clean hour; tables by "
    "boot (its group: one boot of the VM), by VM, by profile and by scenario; the edges are those of the replay, at "
    "the threshold of the replayed bundle")
THESIS_RATE_RULE = (
    "the false alarms per hour of evaluated time (the thesis; the lead's skeleton B7, addendum 2 point 2): on a benign "
    "role every alarm is false (the events are part of normal, D10), so the alarms of each channel and of the union "
    "that begin at any row that is not excluded (CONTEXT_RULE) per observed hour of those rows, with the exact "
    "two-sided interval of Garwood at analysis.metrics.alarm_rate_interval.level (chi2.ppf((1 - level) / 2, 2k) / 2, "
    "0 at k = 0, and chi2.ppf((1 + level) / 2, 2k + 2) / 2); beside them the rate per scored hour with the same "
    "Garwood interval per scored hour (judgment: the evaluated time of the thesis is read as the observed time, as O2 "
    "reads it; iteration 1 and the documents that quote its FAR give the scored hour, so it stands beside it with its "
    "interval), the number of boot groups and the tables by boot, VM, profile and scenario")
DISPERSION_RULE = (
    "the dispersion of the alarm counts over the sessions (analysis.metrics.dispersion): Pearson's X2, the sum over "
    "the sessions of (k_s - e_s)^2 / e_s with e_s = k times the observed time of session s over that of all "
    "(judgment: the main denominator of proposal 4.2; iteration 1 took the scored time), over the sessions with "
    "observed time, their number - 1 degrees of freedom, p the chi-square survival function at X2; not computed, "
    "with the reason, without an alarm or with one session")
EVENT_TEST_RULE = (
    "the alarm rate during events against clean traffic (analysis.metrics.event_vs_clean): k1 alarms that begin at "
    "event rows in e1 observed seconds against k0 at clean rows in e0 seconds, the exact conditional test, p = "
    "P(X >= k1) for X binomial(k1 + k0, e1 / (e1 + e0)) (scipy binomtest, alternative greater); the rate is higher "
    "during events when p < alpha; in total and per event type; p 1 without an alarm, none without exposure and "
    "nevyhodnotené for a channel that judged no row of the events or of clean traffic (the reason given)")
OCCURRENCE_RULE = (
    "an occurrence (an event of events.json, a control of controls.json) is judged on the rows of its horizon, those "
    "with host_start_unix < t <= host_start_unix + h (a row at t covers (t - interval_s, t]: scripts/controls.py's "
    "rule; h = analysis.horizon_s for an event, controls.horizon_s through the outcome's window for a control); it is "
    "evaluable (proposal 6.4) when its scored rows with host_start_unix < t <= host_start_unix + "
    "analysis.evaluable.first_s, times interval_s, reach analysis.evaluable.scored_share of first_s, else it is "
    "nevyhodnotené; a channel or the union reacts to it when it rises (EDGE_RULE) at a row of its horizon: an alarm up "
    "before it is no reaction (whether it was up at the last row at or before the start is recorded); the unscored "
    "time of its horizon is reported")
O3_RULE = (
    "O3 (proposal 4.2 and 6.4): per event type and over every type (judgment: the total takes the minimum of a type), "
    "the share of the evaluable occurrences a channel or the union reacts to (OCCURRENCE_RULE), with the exact "
    "one-sided upper bound of analysis.metrics.o3_bound, beta.ppf(level, k + 1, n - k) and 1 at k = n; an occurrence "
    "that is not evaluable leaves the denominator and is listed apart (nevyhodnotené); a type with fewer than "
    "analysis.min_occurrences evaluable occurrences is nevyhodnotené (its counts are given, its share and bound are "
    "none), and so is a channel that judged no row of the horizons of its evaluable occurrences (EDGE_RULE); beside the"
    " share (descriptive, judgment: the horizon misses an alarm late in a long event) the evaluable occurrences with an"
    " alarm that begins during the event, at a row whose span meets [host_start_unix, host_stopped_unix], and in its "
    "reverberation, reported apart (proposal 12: the reverberation is reported separately); an event that did not run "
    "is listed apart; tables by boot, VM, profile and scenario over every type")
O4_RULE = (
    "O4 (proposal 4.2 and 6.4): per polarity, class and kind of control, a channel or the union detects an "
    "occurrence when it rises at a row of the occurrence's horizon (channel_reacted, OCCURRENCE_RULE); the denominator "
    "is the planned occurrences (every planned control of an accepted session ran: the log audit refuses "
    "control_not_executed); an occurrence without a scored row in its horizon is nezachytené, senzor neskóroval, its "
    "own result and no success, counted apart (tables by boot, VM, profile and scenario beside those by class and "
    "kind); a channel that judged no row of the horizon (EDGE_RULE: a rule "
    "channel without columns) is nevyhodnotené there, no miss; a class or kind with fewer than "
    "analysis.min_occurrences evaluable occurrences is nevyhodnotené (its counts are given, its share is none), and so "
    "is the share of a channel nevyhodnotené at every occurrence of its group; for a negative a detection is a false "
    "alarm; every group gives the increment of the neural channel over the rule channel (INCREMENT_RULE)")
INCREMENT_RULE = (
    "the sensitivity increment of the neural channel over the rule channel (proposal 8.2; question Q6, its wording "
    "accepted by the lead 2026-11-24): in every group of O4 the planned occurrences the neural channel detects "
    "(zachytené) and the rule channel does not, over the planned occurrences, which is share(rule or neural) - "
    "share(rule), with the counts (planned, rule, rule_or_neural, neural_not_rule); a channel that judged no row of an "
    "occurrence detects nothing there (nevyhodnotené is no detection); nevyhodnotené when the group is or when the "
    "neural channel judged no row of its occurrences; for a negative control a detection is a false alarm")
CLASSIFIER_RULE = (
    "the activity classifier (analysis.metrics.classifier, proposal 4.2 row O6): the class of a scored row is the "
    "activity the bundle predicts there; the scored rows of clean traffic carry the scenario of their session (the "
    "bundle's classes are the train scenarios: judgment, the profile of O6 is the scenario's) and give the accuracy "
    "and the macro-F1 over the classes present, beside the most frequent class (the accuracy of always naming it) and "
    "chance (one over the classes); the rows of the reverberation are left out (O6); an occurrence (an event or a "
    "control) is judged by its majority class, the most frequent predicted class of the scored rows whose span meets "
    "[host_start_unix, host_stopped_unix] (ties to the first class by name, as since iteration 1), right when it is "
    "the scenario of its session (judgment: the bundle cannot name an event type, so the question is whether it keeps "
    "the session's activity during the occurrence); the majority class of a session is that of its clean rows; a "
    "bundle without classes (a baseline of tcn/porovnanie.py) has no classifier, and its tables are skipped with the "
    "reason")
UNSCORED_RULE = (
    "the unscored time (proposal 6.4: per session, per event type and per control; G1: an unscored stretch is "
    "nevyhodnotené in the output, never silence): the stretches of a replay are those of safeguard.runtime.unscored, "
    "the one rule of the unscored stretches (its UNSCORED_RULE: a run of rows without a score, the warmup, a full "
    "snapshot, an invalid row and the windows after them, of one session in replay order with consecutive seq, with "
    "its first and last seq and time, its rows, its seconds (rows times interval_s), the reasons of its rows and the "
    "status nevyhodnotené; design B7c 5.6); the unscored seconds are also given per context, per occurrence (in its "
    "horizon) and per event type and kind of control")
SEAL_RULE = (
    "the seal of a replay (design B7c 5.5, question Q17): under protocol schema 3 every replay directory is checked by "
    "tcn.pecat kontrola before its rows are read, by the archive_sha256 of its configuration.json (safeguard replay "
    "--archive, tcn.porovnanie replay and so the final command write it since package B7c), which must be the sha256 "
    "of the archive it names; the replay of a sealed archive of a campaign is read only inside the final run that "
    "consumed its seal (tcn/pecat.py GUARD_RULE), so the replays a final run wrote are refused after it as its "
    "archives are; a replay without archive_sha256 is refused by name")
O4_NOT_GIVEN = ("not computed: no outcome of a control was given (scripts/controls.py outcomes, computed inside the "
                "final command for role test_controls; vysledky_kontrol)")


def _je_v5(protokol):
    return type(protokol) is dict and protokol.get("schema") == SCHEMA_PROTOKOLU_V5


def _cislo_v5(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def hodnota_v5(protokol, cesta):
    """The value at the dotted `cesta` of a protocol of schema 3; a missing key is refused by name."""
    value = protokol
    for part in cesta.split("."):
        if type(value) is not dict or part not in value:
            raise ValueError(f"protocol key {cesta} is missing (protocol v5, design B7c 1.3)")
        value = value[part]
    return value


def dozvuk_s(protokol):
    """The reverberation in seconds: analysis.reverberation_s of a protocol of schema 3 (design B7c 1.3), the 300 s of
    protocols v3 and v4 (DOZVUK_S, NAVRH_PROTOKOL_V3 kap. 5) for schemas 1 and 2."""
    if not _je_v5(protokol):
        return DOZVUK_S
    value = hodnota_v5(protokol, "analysis.reverberation_s")
    if not (_cislo_v5(value) and value >= 0):
        raise ValueError("analysis.reverberation_s must be a number of at least 0")
    return float(value)


def metriky_protokolu(protokol):
    """analysis.metrics of a protocol of schema 3, checked by scripts/protocol_v5.py metrics_problem (one check for the
    protocol and this module)."""
    from scripts.protocol_v5 import metrics_problem
    value = hodnota_v5(protokol, "analysis.metrics")
    problem = metrics_problem(value)
    if problem is not None:
        raise ValueError(problem)
    return value


def vyskyt_protokolu(protokol):
    """{horizon_s, reverberation_s, first_s, scored_share, min_occurrences, interval_s} of a protocol of schema 3
    (OCCURRENCE_RULE)."""
    out = {"horizon_s": hodnota_v5(protokol, "analysis.horizon_s"),
           "reverberation_s": dozvuk_s(protokol),
           "first_s": hodnota_v5(protokol, "analysis.evaluable.first_s"),
           "scored_share": hodnota_v5(protokol, "analysis.evaluable.scored_share"),
           "min_occurrences": hodnota_v5(protokol, "analysis.min_occurrences"),
           "interval_s": hodnota_v5(protokol, "interval_s")}
    if not all(_cislo_v5(out[k]) and out[k] > 0 for k in ("horizon_s", "first_s", "interval_s")):
        raise ValueError("analysis.horizon_s, analysis.evaluable.first_s and interval_s must be positive numbers")
    if not (_cislo_v5(out["scored_share"]) and 0 < out["scored_share"] <= 1):
        raise ValueError("analysis.evaluable.scored_share must be a number in (0, 1]")
    if type(out["min_occurrences"]) is not int or out["min_occurrences"] < 1:
        raise ValueError("analysis.min_occurrences must be an integer of at least 1")
    return {k: (v if k == "min_occurrences" else float(v)) for k, v in out.items()}


# ------------------------------------------------- the edges, the contexts and the unscored time of one replay


def _riadok_v5(r, i):
    """The fields of a replay row of safeguard.runtime the block v5 reads, checked: what the detector writes into
    every row (Detector._finish and input_error)."""
    where = f"replay row {i} (seq {r.get('seq')})"
    alarm, event, sources, channel = r.get("alarm"), r.get("alarm_event"), r.get("alarm_sources"), r.get("channel")
    if type(alarm) is not bool or type(event) is not bool:
        raise ValueError(f"{where}: alarm and alarm_event are true or false (safeguard.runtime)")
    if (type(channel) is not list or len(set(channel)) != len(channel) or any(c not in CHANNELS for c in channel)
            or channel != [c for c in CHANNELS if c in channel]):
        raise ValueError(f"{where}: channel lists channels of {', '.join(CHANNELS)} in that order")
    if type(sources) is not list or len(set(sources)) != len(sources) or any(s not in SOURCE_CHANNELS
                                                                            for s in sources):
        raise ValueError(f"{where}: alarm_sources lists sources of {', '.join(SOURCES)}")
    if alarm != bool(channel) or event != bool(sources) or any(SOURCE_CHANNELS[s] not in channel for s in sources):
        raise ValueError(f"{where}: alarm, alarm_event, alarm_sources and channel disagree (safeguard.runtime: "
                         "alarm is the union of the channels up, a source rises only where its channel is up)")
    if not _cislo_v5(r.get("timestamp")) or type(r.get("seq")) is not int:
        raise ValueError(f"{where}: a replay row has its seq and a finite timestamp")
    if type(r.get("rule")) is not dict or type(r.get("integrity")) is not dict:
        raise ValueError(f"{where}: a replay row has its rule and integrity (safeguard.runtime, package B6b)")


def _posudzuje(r):
    """{output: whether it judged the row} (EDGE_RULE)."""
    out = {"neural": r.get("score") is not None, "rule": r["rule"].get("state") == "judged",
           "kernel_integrity": r["integrity"].get("conclusive") is True}
    out[UNION] = any(out.values())
    return out


def channel_edges(rows):
    """{output: [index of each row where it rises]} of one replay, for each channel and the union (EDGE_RULE). Every
    row is checked (_riadok_v5); the seq and the times increase."""
    out = {o: [] for o in OUTPUTS}
    previous = False
    for i, r in enumerate(rows):
        _riadok_v5(r, i)
        if i and (r["seq"] <= rows[i - 1]["seq"] or r["timestamp"] <= rows[i - 1]["timestamp"]):
            raise ValueError(f"replay row {i}: the seq and the times of a replay increase")
        for channel in CHANNELS:
            if CHANNEL_SOURCES[channel] in r["alarm_sources"]:
                out[channel].append(i)
        if r["alarm"] and not previous:
            out[UNION].append(i)
        previous = r["alarm"]
    return out


def _vyskyty(zaznamy, ident, co):
    """[(record, start, stop)] of the event or control records of one session (host_start_unix <= host_stopped_unix)."""
    if type(zaznamy) not in (list, tuple):
        raise ValueError(f"the {co} of session {ident} are a list of records")
    out = []
    for z in zaznamy:
        a, b = (z.get(k) if type(z) is dict else None for k in ("host_start_unix", "host_stopped_unix"))
        if not (_cislo_v5(a) and _cislo_v5(b) and a <= b):
            raise ValueError(f"a record of the {co} of session {ident} needs host_start_unix <= host_stopped_unix")
        if co == "events" and (type(z.get("type")) is not str or type(z.get("executed")) is not bool):
            raise ValueError(f"an event of session {ident} needs its type and executed true or false")
        out.append((z, float(a), float(b)))
    return out


def _kontext(first, last, udalosti, kontroly, dozvuk):
    """(context, event type or None) of a span [first, last] (CONTEXT_RULE); context None: excluded."""
    def meets(a, b):
        return last >= a and first <= b
    if any(not z["executed"] and meets(a, b + dozvuk) for z, a, b in udalosti):
        return None, None
    hit = next((z for z, a, b in udalosti if meets(a, b)), None)
    if hit is not None:
        return "event", hit["type"]
    if any(meets(a, b + dozvuk) for _, a, b in kontroly):
        return "control", None
    if any(meets(a, b + dozvuk) for _, a, b in udalosti):
        return "reverberation", None
    return "clean", None


def required_rows(rows):
    """L of CONTEXT_RULE: the required_rows of a replay (window_rows and the anchor when anchored), one value for every
    row that states it (an input error row states none)."""
    found = {r["required_rows"] for r in rows if "required_rows" in r}
    if len(found) != 1 or type(next(iter(found))) is not int or next(iter(found)) < 1:
        raise ValueError("the rows of a replay state one required_rows (safeguard.runtime), not %s" % sorted(found))
    return found.pop()


def row_contexts(rows, events, controls, protocol, *, ident="?"):
    """[(context, event type or None)] of every row of one replay (CONTEXT_RULE): context clean, event,
    reverberation, control, or None for an excluded row. events and controls: the records of the session's events.json
    and of its controls (controls.json, the slots with a kind; [] for a session without one)."""
    dozvuk = dozvuk_s(protocol)
    udalosti, kontroly = _vyskyty(events, ident, "events"), _vyskyty(controls, ident, "controls")
    frames = required_rows(rows)
    times = [float(r["timestamp"]) for r in rows]
    return [_kontext(times[max(i - (frames - 1), 0)], t, udalosti, kontroly, dozvuk) for i, t in enumerate(times)]


def unscored_stretches(rows, interval_s):
    """The unscored stretches of the rows of one replay (UNSCORED_RULE): those of safeguard.runtime.unscored, the one
    rule (design B7c 5.6), [{session, first_seq, last_seq, rows, seconds, first_unix, last_unix, reasons, status
    nevyhodnotené}]."""
    from safeguard.runtime import unscored
    return unscored(rows, interval_s)["stretches"]


def _relacia_v5(zaznam, riadky, udalosti, kontroly, protokol):
    """The state of one session the block v5 reads: its record's identity, its rows, edges, contexts and spans."""
    ident = zaznam["id"]
    edges = channel_edges(riadky)
    contexts = row_contexts(riadky, udalosti, kontroly, protokol, ident=ident)
    frames = required_rows(riadky)
    times = [float(r["timestamp"]) for r in riadky]
    scenarios = hodnota_v5(protokol, "scenarios")
    if zaznam["scenario"] not in scenarios:
        raise ValueError(f"session {ident}: scenario {zaznam['scenario']!r} is no scenario of the protocol")
    return {"id": ident, "group": zaznam["group"], "vm": zaznam.get("vm"), "scenario": zaznam["scenario"],
            "profile": scenarios[zaznam["scenario"]].get("profile"), "rows": riadky, "edges": edges,
            "contexts": contexts, "times": times,
            "first": [times[max(i - (frames - 1), 0)] for i in range(len(times))],
            "events": _vyskyty(udalosti, ident, "events"), "controls": _vyskyty(kontroly, ident, "controls"),
            "judged": [_posudzuje(r) for r in riadky]}


# ------------------------------------------------- the rates (O2, the thesis' rate, dispersion, event against clean)

TABLES = {"by_boot": "group", "by_vm": "vm", "by_profile": "profile", "by_scenario": "scenario"}


def poissonov_horna(k, uroven):
    """The exact one-sided upper bound of a Poisson mean at k events and level `uroven` (O2_RULE)."""
    from scipy.stats import chi2
    return float(chi2.ppf(uroven, 2 * k + 2) / 2)


def garwood(k, uroven):
    """The exact two-sided interval of Garwood of a Poisson mean at k events and level `uroven` (THESIS_RATE_RULE):
    poissonov_interval with alfa = 1 - uroven."""
    return poissonov_interval(k, 1 - uroven)


def clopper_pearson_horna(k, n, uroven):
    """The exact one-sided upper bound of Clopper and Pearson of a share k of n at level `uroven` (O3_RULE)."""
    from scipy.stats import beta
    if n == 0:
        return None
    return 1.0 if k == n else float(beta.ppf(uroven, k + 1, n - k))


def _expozicia_v5(s, keep):
    """The rows of session s whose (context, type) passes keep: their count, the scored ones, the judged ones of each
    output and the alarms of each output that begin there."""
    mine = [i for i, c in enumerate(s["contexts"]) if keep(c)]
    selected = set(mine)
    return {"session": s["id"], "group": s["group"], "vm": s["vm"], "profile": s["profile"],
            "scenario": s["scenario"], "rows": len(mine),
            "scored_rows": sum(s["rows"][i].get("score") is not None for i in mine),
            "judged_rows": {o: sum(s["judged"][i][o] for i in mine) for o in OUTPUTS},
            "alarms": {o: sum(i in selected for i in s["edges"][o]) for o in OUTPUTS}}


def _miera(expozicie, interval_s, interval):
    """The rate block of a set of exposures: per output the alarms, the rate per observed and per scored hour and the
    interval or bound interval(k) in alarms over each of them (bounds_per_hour, bounds_per_scored_hour); a channel
    that judged no row is nevyhodnotené."""
    rows = sum(e["rows"] for e in expozicie)
    scored = sum(e["scored_rows"] for e in expozicie)
    hours, scored_hours = rows * interval_s / 3600, scored * interval_s / 3600
    out = {"sessions": len(expozicie), "rows": rows, "scored_rows": scored, "observed_hours": hours,
           "scored_hours": scored_hours, "scored_share": scored / rows if rows else None,
           "unscored_seconds": (rows - scored) * interval_s,
           "unscored_status": UNEVALUATED if rows > scored else None}
    for o in OUTPUTS:
        k = sum(e["alarms"][o] for e in expozicie)
        judged = sum(e["judged_rows"][o] for e in expozicie)
        bounds = interval(k)
        if not judged or not hours:
            out[o] = {"alarms": k, "judged_rows": judged, "status": UNEVALUATED, "per_hour": None,
                      "bounds_per_hour": None, "per_scored_hour": None, "bounds_per_scored_hour": None,
                      "why": "the channel judged no row of this set" if not judged else "no observed time"}
            continue
        out[o] = {"alarms": k, "judged_rows": judged, "status": EVALUATED, "per_hour": k / hours,
                  "bounds_per_hour": [b / hours for b in bounds],
                  "per_scored_hour": k / scored_hours if scored_hours else None,
                  "bounds_per_scored_hour": [b / scored_hours for b in bounds] if scored_hours else None}
    return out


def _tabulky(expozicie, interval_s, interval):
    return {name: {str(value): _miera([e for e in expozicie if e[key] == value], interval_s, interval)
                   for value in sorted({e[key] for e in expozicie}, key=str)} for name, key in TABLES.items()}


def _disperzia(expozicie):
    """DISPERSION_RULE per output over the sessions of the exposures."""
    from scipy.stats import chi2
    out = {}
    observed = [e for e in expozicie if e["rows"] > 0]  # A session without a row of the set has no expectation.
    total = sum(e["rows"] for e in observed)
    for o in OUTPUTS:
        k = sum(e["alarms"][o] for e in observed)
        if k == 0 or len(observed) < 2:
            out[o] = {"x2": None, "df": None, "p": None, "sessions": len(observed),
                      "why": "no alarm" if k == 0 else "one session with observed time"}
            continue
        x2 = sum((e["alarms"][o] - k * e["rows"] / total) ** 2 / (k * e["rows"] / total) for e in observed)
        out[o] = {"x2": float(x2), "df": len(observed) - 1, "p": float(chi2.sf(x2, len(observed) - 1)),
                  "sessions": len(observed), "why": None}
    return out


def porovnanie_v5(k1, e1, k0, e0, alfa):
    """EVENT_TEST_RULE for one output: k1 alarms in e1 seconds of events against k0 in e0 seconds of clean traffic."""
    out = {"event_alarms": k1, "event_seconds": e1, "clean_alarms": k0, "clean_seconds": e0, "alpha": alfa}
    if e1 <= 0 or e0 <= 0:
        return dict(out, p=None, rate_ratio=None, higher=None, why="no exposure of the events or of clean traffic")
    if k1 + k0 == 0:
        return dict(out, p=1.0, rate_ratio=None, higher=False, why="no alarm")
    from scipy.stats import binomtest
    p = float(binomtest(k1, k1 + k0, e1 / (e1 + e0), alternative="greater").pvalue)
    return dict(out, p=p, rate_ratio=(k1 / e1) / (k0 / e0) if k0 else None, higher=p < alfa, why=None)


def _udalosti_proti_cistej(relacie, interval_s, alfa):
    """EVENT_TEST_RULE in total and per event type, per output."""
    def test(keep):
        events = [_expozicia_v5(s, keep) for s in relacie]
        clean = [_expozicia_v5(s, lambda c: c[0] == "clean") for s in relacie]
        out = {}
        for o in OUTPUTS:
            k1, k0 = (sum(e["alarms"][o] for e in x) for x in (events, clean))
            e1, e0 = (sum(e["rows"] for e in x) * interval_s for x in (events, clean))
            if not all(sum(e["judged_rows"][o] for e in x) for x in (events, clean)) and e1 > 0 and e0 > 0:
                out[o] = dict(porovnanie_v5(k1, e1, k0, e0, alfa), p=None, higher=None, status=UNEVALUATED,
                              why="the channel judged no row of the events or of clean traffic")
                continue
            out[o] = porovnanie_v5(k1, e1, k0, e0, alfa)
        return out
    types = sorted({z["type"] for s in relacie for z, _, _ in s["events"] if z["executed"]})
    return {"total": test(lambda c: c[0] == "event"),
            "by_type": {t: test(lambda c, t=t: c == ("event", t)) for t in types},
            "definition": EVENT_TEST_RULE}


# ------------------------------------------------- the occurrences (O3, O4)


def _vyskyt(s, start, horizon_s, first_s, scored_share, interval_s, horizon=None, stop=None, dozvuk=None):
    """OCCURRENCE_RULE for one occurrence at `start` of session s: the rows of its horizon (by time, or the indices
    `horizon` given), its scored share of the first first_s seconds and what each output does; for an event (its stop
    and the reverberation given) also whether each output rises during the event (a row whose span meets [start,
    stop]) and in its reverberation (one whose span meets it only with the reverberation), beside the horizon."""
    times, rows = s["times"], s["rows"]
    if horizon is None:
        horizon = [i for i, t in enumerate(times) if start < t <= start + horizon_s]
    first = [i for i, t in enumerate(times) if start < t <= start + first_s]
    share = sum(rows[i].get("score") is not None for i in first) * interval_s / first_s
    before = [i for i, t in enumerate(times) if t <= start]
    last = rows[before[-1]] if before else None
    scored = [i for i in horizon if rows[i].get("score") is not None]
    inside = set(horizon)
    judged = [_posudzuje(rows[i]) for i in horizon]
    outputs = {}
    for o in OUTPUTS:
        edges = [i for i in s["edges"][o] if i in inside]
        up = None if last is None else (last["alarm"] if o == UNION else o in last["channel"])
        outputs[o] = {"reacted": bool(edges), "edges": len(edges), "judged": any(j[o] for j in judged),
                      "first_edge_s": times[edges[0]] - start if edges else None, "up_at_start": up}
        if stop is not None:
            meets = [i for i in s["edges"][o] if times[i] >= start and s["first"][i] <= stop + dozvuk]
            outputs[o].update(during_event=any(s["first"][i] <= stop for i in meets),
                              in_reverberation=any(s["first"][i] > stop for i in meets))
    return {"start_unix": start, "horizon_rows": len(horizon), "scored_horizon_rows": len(scored),
            "unscored_horizon_s": (len(horizon) - len(scored)) * interval_s, "first_s_scored_share": share,
            "evaluable": share >= scored_share, "status": EVALUATED if share >= scored_share else UNEVALUATED,
            "outputs": outputs}


def _udalosti_vyskyty(relacie, pravidla):
    out = []
    for s in relacie:
        for z, a, b in s["events"]:
            base = {"session": s["id"], "group": s["group"], "vm": s["vm"], "profile": s["profile"],
                    "scenario": s["scenario"], "type": z["type"], "start_unix": a, "stopped_unix": b,
                    "executed": z["executed"]}
            if not z["executed"]:
                out.append(dict(base, status="not run"))
                continue
            out.append(dict(_vyskyt(s, a, pravidla["horizon_s"], pravidla["first_s"], pravidla["scored_share"],
                                    pravidla["interval_s"], stop=b, dozvuk=pravidla["reverberation_s"]), **base))
    return out


def _podiel(vyskyty, minimum, uroven):
    """The share of the evaluable occurrences of a group that each output reacts to (O3_RULE), with the bound and the
    status by the minimum of evaluable ones; beside it the evaluable occurrences with an alarm during the event and in
    its reverberation (descriptive); its unscored horizon time."""
    evaluable = [v for v in vyskyty if v["evaluable"]]
    status = EVALUATED if len(evaluable) >= minimum else UNEVALUATED
    out = {"occurrences": len(vyskyty), "evaluable": len(evaluable), "not_evaluable": len(vyskyty) - len(evaluable),
           "status": status, "unscored_horizon_s": sum(v["unscored_horizon_s"] for v in vyskyty)}
    for o in OUTPUTS:
        k = sum(v["outputs"][o]["reacted"] for v in evaluable)
        beside = {key: sum(v["outputs"][o][key] for v in evaluable) for key in ("during_event", "in_reverberation")}
        if status == EVALUATED and not any(v["outputs"][o]["judged"] for v in evaluable):
            out[o] = {"reacted": k, "share": None, "upper": None, "status": UNEVALUATED, **beside,
                      "why": "the channel judged no row of these horizons"}
            continue
        out[o] = {"reacted": k, "share": k / len(evaluable) if status == EVALUATED else None,
                  "upper": clopper_pearson_horna(k, len(evaluable), uroven) if status == EVALUATED else None,
                  "status": status, **beside}
    return out


def _o3(relacie, protokol, metriky):
    pravidla = vyskyt_protokolu(protokol)
    vyskyty = _udalosti_vyskyty(relacie, pravidla)
    ran = [v for v in vyskyty if v["executed"]]
    level, minimum = metriky["o3_bound"]["level"], pravidla["min_occurrences"]

    def share(items):
        return _podiel(items, minimum, level)
    return {"total": share(ran), "by_type": {t: share([v for v in ran if v["type"] == t])
                                             for t in sorted({v["type"] for v in ran})},
            **{name: {str(value): share([v for v in ran if v[key] == value])
                      for value in sorted({v[key] for v in ran}, key=str)} for name, key in TABLES.items()},
            "not_evaluable": [{k: v[k] for k in ("session", "type", "start_unix", "first_s_scored_share", "status")}
                              for v in ran if not v["evaluable"]],
            "not_run": [{k: v[k] for k in ("session", "type", "start_unix")} for v in vyskyty if not v["executed"]],
            "occurrences": vyskyty, "level": level, "min_occurrences": minimum, "horizon_s": pravidla["horizon_s"],
            "evaluable_rule": {"first_s": pravidla["first_s"], "scored_share": pravidla["scored_share"]},
            "definition": O3_RULE}


def _vysledok_kontroly(outcome):
    """The fields of an outcome of scripts/controls.py outcomes() that channel_reacted reads, checked."""
    from scripts.controls import SCHEMA
    window = outcome.get("window") if type(outcome) is dict else None
    if type(outcome) is not dict or outcome.get("schema") != SCHEMA or type(window) is not dict:
        raise ValueError(f"an outcome of a control is a record of scripts/controls.py outcomes (schema {SCHEMA})")
    if not (_cislo_v5(window.get("start_unix")) and all(
            type(window.get(k)) is list and all(type(x) is int for x in window[k]) for k in ("horizon", "scored"))):
        raise ValueError("the window of an outcome of a control has its start_unix and the seq of its horizon and of "
                         "its scored rows")
    if outcome.get("polarity") not in ("control", "negative") or type(outcome.get("kind")) is not str:
        raise ValueError("an outcome of a control names its kind and its polarity control or negative")
    return window


def channel_reacted(outcome, rows, protocol):
    """The reaction of each channel and of the union to one control occurrence (O4_RULE, OCCURRENCE_RULE; the
    docstring of scripts/controls.py: B7 judges channel_reacted on the rows of the outcome's horizon).

    outcome: the occurrence's record of scripts/controls.py outcomes() (computed inside the final command for role
    test_controls); rows: the replay rows of its session (events.jsonl of the replay of that archive); protocol: the
    protocol of schema 3 (analysis.evaluable). The horizon is the outcome's window.horizon (the rows with
    host_start_unix < t <= host_start_unix + controls.horizon_s), matched by seq; every one of them must be a row of
    the replay, and a row the replay scored must be one the outcome's coverage scores (window.scored: the
    non-anchored coverage scores every row the detector does, map section 9 point 8), else the two describe different
    data. Without a scored row in the horizon every output is nezachytené, senzor neskóroval (NOT_SCORED), its own
    result and no success; else an output that judged no row of the horizon (a rule channel without columns) is
    nevyhodnotené, and every other one zachytené when it rises at a row of the horizon, nezachytené otherwise.

    Returns {schema, kind, class, polarity, dose, sensor_scored, coverage_scored_rows, start_unix, horizon_rows,
    scored_horizon_rows, unscored_horizon_s, first_s_scored_share, evaluable, status, outputs {rule, neural,
    kernel_integrity, union: {result, reacted, edges, judged, first_edge_s, up_at_start}}, definition}.

    The rule texts of the block v5 are under the key definition: the channel of the rule is named rule."""
    window = _vysledok_kontroly(outcome)
    s = {"rows": rows, "times": [float(r["timestamp"]) for r in rows], "edges": channel_edges(rows)}
    at = {r["seq"]: i for i, r in enumerate(rows)}
    missing = [seq for seq in window["horizon"] if seq not in at]
    if missing:
        raise ValueError(f"the replay has no row of seq {missing[0]} of the horizon of the control {outcome['kind']}")
    horizon = [at[seq] for seq in window["horizon"]]
    scored = {rows[i]["seq"] for i in horizon if rows[i].get("score") is not None}
    beyond = sorted(scored - set(window["scored"]))
    if beyond:
        raise ValueError(f"the replay scored the row of seq {beyond[0]} in the horizon of the control "
                         f"{outcome['kind']}, which the outcome's coverage does not score: they describe other data")
    pravidla = vyskyt_protokolu(protocol)
    record = _vyskyt(s, float(window["start_unix"]), None, pravidla["first_s"], pravidla["scored_share"],
                     pravidla["interval_s"], horizon=horizon)
    sensor = bool(scored)
    for o in OUTPUTS:
        mine = record["outputs"][o]
        # The channel judged no row of the horizon (a rule channel without columns): no miss, nevyhodnotené.
        mine["result"] = (NOT_SCORED if not sensor else UNEVALUATED if not mine["judged"]
                          else DETECTED if mine["reacted"] else MISSED)
    return {"schema": SCHEMA_REAKCIE, "kind": outcome["kind"], "class": outcome.get("class"),
            "polarity": outcome["polarity"], "dose": outcome.get("dose"), "sensor_scored": sensor,
            "coverage_scored_rows": len(window["scored"]), **record, "definition": OCCURRENCE_RULE}


def _o4(reakcie, protokol):
    """O4_RULE over the reactions of every control occurrence of the role (channel_reacted)."""
    minimum = vyskyt_protokolu(protokol)["min_occurrences"]

    def group(items):
        evaluable = sum(r["evaluable"] for r in items)
        status = EVALUATED if evaluable >= minimum else UNEVALUATED
        out = {"planned": len(items), "evaluable": evaluable, "status": status,
               "sensor_did_not_score": sum(not r["sensor_scored"] for r in items),
               "unscored_horizon_s": sum(r["unscored_horizon_s"] for r in items)}
        for o in OUTPUTS:
            counts = collections.Counter(r["outputs"][o]["result"] for r in items)
            judged = items and counts[UNEVALUATED] < len(items)
            out[o] = {DETECTED: counts[DETECTED], MISSED: counts[MISSED], NOT_SCORED: counts[NOT_SCORED],
                      UNEVALUATED: counts[UNEVALUATED],
                      "share": counts[DETECTED] / len(items) if status == EVALUATED and judged else None}
        out["neural_over_rule"] = _prirastok(items, status)
        return out
    out = {}
    for polarity in ("control", "negative"):
        mine = [r for r in reakcie if r["polarity"] == polarity]
        out[polarity] = {"total": group(mine),
                         "by_class": {str(c): group([r for r in mine if r["class"] == c])
                                      for c in sorted({r["class"] for r in mine}, key=str)},
                         "by_kind": {k: group([r for r in mine if r["kind"] == k])
                                     for k in sorted({r["kind"] for r in mine})},
                         **{name: {str(value): group([r for r in mine if r.get(key) == value])
                                   for value in sorted({r.get(key) for r in mine}, key=str)}
                            for name, key in TABLES.items()}}
    return dict(out, occurrences=reakcie, min_occurrences=minimum, definition=O4_RULE,
                increment_definition=INCREMENT_RULE)


def _prirastok(items, status):
    """INCREMENT_RULE for the reactions of one group of O4 of status `status`."""
    rule = [r["outputs"]["rule"]["result"] == DETECTED for r in items]
    neural = [r["outputs"]["neural"]["result"] == DETECTED for r in items]
    only = sum(n and not r for r, n in zip(rule, neural))
    evaluated = status == EVALUATED and any(r["outputs"]["neural"]["result"] != UNEVALUATED for r in items)
    return {"planned": len(items), "rule": sum(rule), "rule_or_neural": sum(r or n for r, n in zip(rule, neural)),
            "neural_not_rule": only, "share": only / len(items) if evaluated else None,
            "status": EVALUATED if evaluated else UNEVALUATED}


# ------------------------------------------------- the classifier and the unscored time


def _vacsina(pocty):
    return max(sorted(pocty), key=lambda t: pocty[t]) if pocty else None


def _klasifikator_v5(relacie, triedy):
    """CLASSIFIER_RULE; a bundle without classes skips it with the reason."""
    if not triedy:
        return {"skipped": "the bundle has no classes (a baseline of tcn/porovnanie.py): no activity classifier",
                "definition": CLASSIFIER_RULE}
    ind = {t: i for i, t in enumerate(triedy)}
    y_true, y_pred, sessions, occurrences = [], [], {}, []
    for s in relacie:
        if s["scenario"] not in ind:
            raise ValueError(f"session {s['id']}: scenario {s['scenario']} is no class of the bundle")
        clean = collections.Counter()
        for i, r in enumerate(s["rows"]):
            if r.get("score") is None or s["contexts"][i][0] != "clean":
                continue
            if r.get("activity") not in ind:
                raise ValueError(f"session {s['id']}: row of seq {r['seq']} predicts {r.get('activity')!r}, no class "
                                 "of the bundle")
            clean[r["activity"]] += 1
            y_true.append(ind[s["scenario"]])
            y_pred.append(ind[r["activity"]])
        majority = _vacsina(clean)
        sessions[s["id"]] = {"scenario": s["scenario"], "majority": majority, "clean_windows": sum(clean.values()),
                             "right": None if majority is None else majority == s["scenario"]}
        for what, items in (("event", s["events"]), ("control", s["controls"])):
            for z, a, b in items:
                if what == "event" and not z["executed"]:
                    continue
                counts = collections.Counter(
                    r["activity"] for i, r in enumerate(s["rows"])
                    if r.get("score") is not None and s["times"][i] >= a and s["first"][i] <= b)
                if any(c not in ind for c in counts):
                    raise ValueError(f"session {s['id']}: a prediction is no class of the bundle")
                m = _vacsina(counts)
                occurrences.append({"session": s["id"], "what": what, "type": z.get("type", z.get("kind")),
                                    "start_unix": a, "scenario": s["scenario"], "windows": sum(counts.values()),
                                    "majority": m, "right": None if m is None else m == s["scenario"]})
    if not y_true:
        return {"skipped": "no scored window of clean traffic", "definition": CLASSIFIER_RULE}
    labels = list(range(len(triedy)))
    present = sorted(set(y_true))
    _, _, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    frequent = collections.Counter(y_true).most_common(1)[0]
    judged = [o for o in occurrences if o["right"] is not None]
    voted = [v for v in sessions.values() if v["right"] is not None]

    def beside(items):
        """The most frequent class among the true classes of `items` and its share, and chance (proposal 4.2 O6)."""
        if not items:
            return {"most_frequent_class": None, "chance": 1 / len(triedy)}
        name, count = collections.Counter(x["scenario"] for x in items).most_common(1)[0]
        return {"most_frequent_class": {"class": name, "accuracy": count / len(items)}, "chance": 1 / len(triedy)}
    by_type = {}
    for t in sorted({o["type"] for o in judged}, key=str):
        mine = [o for o in judged if o["type"] == t]
        by_type[str(t)] = {"occurrences": len(mine), "right": sum(o["right"] for o in mine)}
    return {"classes": list(triedy),
            "windows": {"n": len(y_true), "accuracy": float(np.mean(np.array(y_true) == np.array(y_pred))),
                        "macro_f1": float(np.mean([f1[i] for i in present])),
                        "macro_f1_over": [triedy[i] for i in present],
                        "most_frequent_class": {"class": triedy[frequent[0]], "accuracy": frequent[1] / len(y_true)},
                        "chance": 1 / len(triedy),
                        "confusion": confusion_matrix(y_true, y_pred, labels=labels).tolist()},
            "sessions": {"right": sum(v["right"] for v in voted), "of": len(voted),
                         "without_clean_window": len(sessions) - len(voted), **beside(voted),
                         "per_session": sessions},
            "occurrences": {"right": sum(o["right"] for o in judged), "of": len(judged),
                            "without_scored_window": sum(o["right"] is None for o in occurrences), **beside(judged),
                            "by_type": by_type, "per_occurrence": occurrences},
            "definition": CLASSIFIER_RULE}


def _neskorovane_v5(relacie, interval_s):
    """UNSCORED_RULE per session and per context."""
    out = {}
    for s in relacie:
        rows = s["rows"]
        unscored = sum(r.get("score") is None for r in rows)
        by_context = {}
        for c in (*CONTEXTS, None):
            mine = [r for r, k in zip(rows, s["contexts"]) if k[0] == c]
            if mine:
                by_context[str(c) if c else "excluded"] = {
                    "rows": len(mine), "unscored_seconds": sum(r.get("score") is None for r in mine) * interval_s}
        out[s["id"]] = {"rows": len(rows), "unscored_rows": unscored, "unscored_seconds": unscored * interval_s,
                        "unscored_share": unscored / len(rows), "by_context": by_context,
                        "stretches": unscored_stretches(rows, interval_s)}
    return {"sessions": out, "unscored_seconds": sum(v["unscored_seconds"] for v in out.values()),
            "status": UNEVALUATED, "definition": UNSCORED_RULE}


# ------------------------------------------------- the block v5 of one role and one model


def metriky_v5(protokol, relacie, *, triedy, rola, vysledky_kontrol=None):
    """The block v5 of one role and one model (module docstring; design B7c 1.3).

    protokol: the protocol of schema 3 of the corpus; relacie: per session of the role {zaznam (the index record),
    riadky (the replay rows), udalosti (the records of its events.json), kontroly (the records of its controls.json
    with a kind; [] outside test_controls)}; triedy: the classes of the bundle ([] for a baseline); rola: the role;
    vysledky_kontrol: for test_controls {session id: [outcome of scripts/controls.py outcomes() of each control
    occurrence]} (O4), None elsewhere or when not given (O4 then states O4_NOT_GIVEN)."""
    if not _je_v5(protokol):
        raise ValueError("the block v5 is computed for a corpus of protocol schema 3")
    if rola not in ROLY_V5:
        raise ValueError(f"the block v5 is computed for the roles {', '.join(ROLY_V5)}, not {rola!r}")
    metriky = metriky_protokolu(protokol)
    interval_s = float(hodnota_v5(protokol, "interval_s"))
    if type(relacie) not in (list, tuple) or not relacie:
        raise ValueError("the block v5 takes the sessions of the role, at least one")
    stav = [_relacia_v5(r["zaznam"], r["riadky"], r["udalosti"], r["kontroly"], protokol) for r in relacie]
    if len({s["id"] for s in stav}) != len(stav):
        raise ValueError("a session is given twice")
    if vysledky_kontrol is not None and rola != CONTROL_ROLE:
        raise ValueError(f"outcomes of controls are given for role {CONTROL_ROLE} only")
    o2_level = metriky["o2_bound"]["level"]
    thesis_level = metriky["alarm_rate_interval"]["level"]

    def upper(k):
        return [0.0, poissonov_horna(k, o2_level)]

    def two_sided(k):
        return list(garwood(k, thesis_level))
    clean = [_expozicia_v5(s, lambda c: c[0] == "clean") for s in stav]
    evaluated = [_expozicia_v5(s, lambda c: c[0] is not None) for s in stav]
    if vysledky_kontrol is None:
        o4 = {"computed": False, "why": O4_NOT_GIVEN} if rola == CONTROL_ROLE else None
    else:
        if type(vysledky_kontrol) is not dict or set(vysledky_kontrol) - {s["id"] for s in stav}:
            raise ValueError("vysledky_kontrol maps sessions of the role to the outcomes of their controls")
        reakcie = []
        for s in stav:
            for outcome in vysledky_kontrol.get(s["id"], []):
                reakcie.append(dict(channel_reacted(outcome, s["rows"], protokol), session=s["id"], group=s["group"],
                                    vm=s["vm"], profile=s["profile"], scenario=s["scenario"]))
        planned = sum(len(s["controls"]) for s in stav)
        if len(reakcie) != planned:
            raise ValueError(f"{len(reakcie)} outcomes of controls given for the {planned} planned controls of the "
                             "role's sessions: O4 counts every planned occurrence")
        o4 = dict(_o4(reakcie, protokol), computed=True)
    return {
        "schema": SCHEMA_V5, "role": rola, "outputs": list(OUTPUTS), "sessions": len(stav),
        "o2": {"total": _miera(clean, interval_s, upper), **_tabulky(clean, interval_s, upper), "level": o2_level,
               "bound": "one-sided upper, [0, upper] in alarms per hour", "definition": O2_RULE},
        "thesis": {"rate": {"total": _miera(evaluated, interval_s, two_sided),
                            **_tabulky(evaluated, interval_s, two_sided), "level": thesis_level,
                            "definition": THESIS_RATE_RULE},
                   "boot_groups": len({s["group"] for s in stav}),
                   "dispersion": dict(_disperzia(evaluated), definition=DISPERSION_RULE),
                   "event_vs_clean": _udalosti_proti_cistej(stav, interval_s, metriky["event_vs_clean"]["alpha"])},
        "o3": _o3(stav, protokol, metriky), "o4": o4,
        "classifier": _klasifikator_v5(stav, list(triedy)),
        "unscored": _neskorovane_v5(stav, interval_s),
        "definitions": {"edges": EDGE_RULE, "contexts": CONTEXT_RULE}, "reverberation_s": dozvuk_s(protokol),
    }


# ------------------------------------------------- loading the replays of one role (schema 3)


FINAL_V5 = ("--final and its mark next to the index serve protocol schemas 1 and 2; under schema 3 a test role is "
            "evaluated once, by the final command (python -m tcn.finalne), which consumes the seal of the ledger "
            "(tcn/pecat.py, design B7c 1.1)")
BEZ_TRIED = ("balik nema triedy (zakladna metoda tcn/porovnanie.py): riadky nemaju klasifikaciu aktivity, "
             "tabulky klasifikatora sa vynechavaju (navrh B7c 1.3)")


def _znacka_v5(rezim, final_evaluation, relacie):
    """The plan mode of the index, the rehearsal mark every output of a rehearsal carries (design B7c 1.1) and the
    stage of the record (proposal 11.1, _stupen_v5) over the sessions of its corpus index (relacie), with its basis
    (stage_basis, package B9b)."""
    from tcn import pecat
    stupen = _stupen_v5(rezim, relacie)
    return {"plan_mode": rezim, "rehearsal": rezim == "rehearsal",
            "rehearsal_mark": REHEARSAL_MARK if rezim == "rehearsal" else None, "final_evaluation": final_evaluation,
            "stage": stupen["stage"], "stage_rule": pecat.STAGE_RULE, "stage_basis": stupen["basis"]}


def _stupen_v5(rezim, relacie):
    """The stage of a record of protocol schema 3 (proposal 11.1; the fix of F4 of B7c, tightened by finding N2 of its
    confirmation, package B9b): tcn.pecat record_stage (RECORD_STAGE_RULE) for the plan mode of the index over the
    sessions of the whole corpus index, on the ledger of this process (tcn.pecat.KNIHA): final or generalka only
    when that is the ledger of record and it holds the archive of every session of the sealed roles of the index,
    final only when the ledger at HEAD holds them as well; suchy otherwise (a G1 dry run in tcn.pecat vlastna_kniha,
    a test, a synthetic corpus whose archives the ledger of record does not hold), with the basis; the function is
    pecat's, so the rule is not copied here."""
    from tcn import pecat
    return pecat.record_stage(rezim, relacie)


def _rola_v5(index, rola, *, final, final_evaluation, prikaz):
    """The role and the seal of an index of schema 3 (design B7c 1.1 and 1.3): the plan mode of the index; ValueError
    for another role, for --final (schemas 1 and 2 only) and for a sealed role of a campaign index outside the final
    command."""
    if rola not in ROLY_V5:
        raise ValueError(f"under protocol schema 3 {prikaz} evaluates the roles {', '.join(ROLY_V5)}, not {rola!r}")
    if final:
        raise ValueError(FINAL_V5)
    if type(final_evaluation) is not bool:
        raise ValueError("final_evaluation is true (only the final command) or false")
    mode = index.get("plan_mode")
    if mode not in MODES:
        raise ValueError(f"the index of protocol schema 3 names no plan mode of {', '.join(MODES)} (plan_mode "
                         f"{mode!r}; features/dataset.py build)")
    if rola in SEALED_ROLES and mode == "campaign" and not final_evaluation:
        raise ValueError(f"sealed role {rola} (design B7c 1.1): only the final command evaluates it "
                         "(final_evaluation=True, python -m tcn.finalne); an index of plan mode rehearsal is "
                         "evaluated freely and every output carries the rehearsal mark")
    return mode


def _subory_v5(zaznam, rola):
    """(events, controls) of the session of an index record of schema 3: its events.json (hash of the index) and, for
    role test_controls, the slots of its controls.json that hold a control (features.dataset.controls_of, which checks
    the hash of the index: the keys controls and controls_sha256 of package B7c, agent S)."""
    if "events" not in zaznam or "events_sha256" not in zaznam:
        raise ValueError(f"session {zaznam['id']}: the index of schema 3 records its events.json (events, "
                         "events_sha256; features/dataset.py)")
    if _digest(zaznam["events"]) != zaznam["events_sha256"]:
        raise ValueError(f"session {zaznam['id']}: events.json changed since the index")
    udalosti = json.loads(open(zaznam["events"], encoding="utf-8").read())["events"]
    if rola != CONTROL_ROLE:
        return udalosti, []
    if "controls" not in zaznam or "controls_sha256" not in zaznam:
        raise ValueError(f"session {zaznam['id']} of role {CONTROL_ROLE}: the index does not hash its controls.json "
                         "(controls, controls_sha256; features/dataset.py, package B7c)")
    from features.dataset import controls_of  # The one reader of the controls of a corpus (design B7c 5.6).
    return udalosti, control_records(controls_of(zaznam))


def control_records(doc):
    """The records of the controls of a session's controls.json (schema hyptcn3/session-controls/1): the slots that
    hold a control (an empty slot of the plan has no kind and never runs)."""
    from scripts.protocol_v5 import CONTROLS_SCHEMA
    if type(doc) is not dict or doc.get("schema") != CONTROLS_SCHEMA or type(doc.get("controls")) is not list:
        raise ValueError(f"controls.json is a document of schema {CONTROLS_SCHEMA} with its controls")
    return [z for z in doc["controls"] if type(z) is dict and z.get("kind") is not None]


def nacitaj_v5(korpus, rola, prehratia, *, final_evaluation=False):
    """The replays of every session of one role of a corpus of schema 3 for one model, checked as vyhodnot_far checks
    them (_nacitaj_rolu: every session of the role exactly once, one bundle trained on this index, the whole session,
    only tolerated input errors, the hashes of events.json and controls.json): (index, protocol, sessions for
    metriky_v5, the bundle manifest, its sha256). The final command calls it with final_evaluation=True, or
    vyhodnot_far, which loads the same way."""
    d = _nacitaj_rolu(korpus, rola, prehratia, final=False, final_evaluation=final_evaluation)
    if d["v5"] is None:
        raise ValueError("nacitaj_v5 reads a corpus of protocol schema 3")
    return d["index"], d["protokol"], d["v5"], d["balik"], d["balik_sha"]


# ------------------------------------------------- per training (question Q11, accepted by the lead 2026-11-24)


TRAINING_RULE = (
    "per training (proposal 8.6; question Q11, accepted by the lead 2026-11-24: package B7): on the window set of one "
    "fit role (dev or calibration; never a sealed role, which only the final command reads) the loss of the bundle M "
    "(LOSS_FORMULA of tcn/metody.py MetodaM) against the methods of analysis.k1.compare (Z3, Z5, fitted on train and "
    "dev), the mean per context of CONTEXT_RULE (a window by the span of its frames) and over every window, with I = 1 "
    "- loss(M) / loss(Z) of the means (descriptive: K1 is decided per boot on test_benign); the score of M "
    "(SCORE_FORMULA) summarized by context and by scenario: the windows, the mean, the median, the quantiles 0.95 and "
    "0.99 (numpy, linear; judgment: the tail the threshold at fpr 0.01 lies in), the maximum and the share above the "
    "bundle's threshold")


def _suhrn_skore(x, prah):
    x = np.asarray(x, dtype=np.float64)
    if not len(x):
        return {"windows": 0}
    return {"windows": int(len(x)), "mean": float(x.mean()), "median": float(np.median(x)),
            "q95": float(np.quantile(x, .95)), "q99": float(np.quantile(x, .99)), "max": float(x.max()),
            "above_threshold": float((x > prah).mean())}


def window_contexts(windows, events, protocol, *, controls=None):
    """[(context, event type or None)] of every window of a window set (tcn.metody.Okna) by the span of its frames,
    from its first frame (the anchor of an anchored window) to its last row (CONTEXT_RULE, tcn/metody.py CLEAN_RULE).
    events and controls map the id of every session of the set to its records (controls None: no controls, refused
    for role test_controls)."""
    dozvuk = dozvuk_s(protocol)
    ids = list(windows.session_ids)
    if type(events) is not dict or set(events) != set(ids):
        raise ValueError("events maps the id of every session of the window set to its event records")
    if controls is None:
        if windows.role == CONTROL_ROLE:
            raise ValueError(f"the sessions of role {CONTROL_ROLE} hold controls: give their records")
        controls = {ident: [] for ident in ids}
    elif type(controls) is not dict or set(controls) != set(ids):
        raise ValueError("controls maps the id of every session of the window set to its control records")
    spans = {ident: (_vyskyty(events[ident], ident, "events"), _vyskyty(controls[ident], ident, "controls"))
             for ident in ids}
    return [_kontext(float(a), float(b), *spans[ids[s]], dozvuk)
            for s, a, b in zip(windows.window_session, windows.start, windows.timestamp)]


def training_summary(windows, events, protocol, *, model, methods, scenarios, controls=None):
    """TRAINING_RULE on the window set `windows` (tcn.metody.Okna of a fit role, M's normalizer): model is M of one
    seed (tcn.metody.MetodaM: scores, losses, threshold, label), methods {name: fitted method} for exactly the methods
    of analysis.k1.compare (Z3 and Z5 of tcn/metody.py, fitted on train and dev), scenarios {session id: scenario}
    for every session of the set. The record of the training is training_record."""
    if getattr(windows, "role", None) not in TRAINING_ROLES:
        raise ValueError(f"the summary of a training reads a window set of role {' or '.join(TRAINING_ROLES)}, not "
                         f"{getattr(windows, 'role', None)!r}: a sealed role is the final command's")
    compare = hodnota_v5(protocol, "analysis.k1.compare")
    if type(methods) is not dict or set(methods) != set(compare):
        raise ValueError(f"the loss is compared with the methods of analysis.k1.compare {compare}, given "
                         f"{sorted(methods) if type(methods) is dict else methods!r}")
    if type(scenarios) is not dict or set(scenarios) != set(windows.session_ids):
        raise ValueError("scenarios maps the id of every session of the window set to its scenario")
    contexts = window_contexts(windows, events, protocol, controls=controls)
    scores = np.asarray(model.scores(windows), dtype=np.float64)
    losses = {"M": np.asarray(model.losses(windows), dtype=np.float64)}
    for name in compare:
        mine = methods[name].losses(windows)
        if mine is None:
            raise ValueError(f"{name} gives no loss: the loss is compared with predictors")
        losses[name] = np.asarray(mine, dtype=np.float64)
    if any(v.shape != (len(windows),) or not np.isfinite(v).all() for v in (scores, *losses.values())):
        raise ValueError("the scores and the losses are finite numbers, one per window")
    kind = np.array(["excluded" if c[0] is None else c[0] for c in contexts])
    loss = {}
    for c in ("all", *CONTEXTS, "excluded"):
        mask = np.ones(len(kind), dtype=bool) if c == "all" else kind == c
        if not mask.any():
            continue
        means = {name: float(v[mask].mean()) for name, v in losses.items()}
        loss[c] = {
            "windows": int(mask.sum()), "mean": means,
            "improvement": {name: (1 - means["M"] / means[name] if means[name] > 0 else None) for name in compare}}
    prah = float(model.threshold)
    session_scenario = np.array([scenarios[ident] for ident in windows.session_ids], dtype=object)[
        windows.window_session]
    return {"schema": SCHEMA_SUHRN_TRENINGU, "role": windows.role, "model": getattr(model, "label", None),
            "threshold": prah, "windows": len(windows), "compare": list(compare), "loss": loss,
            "score": {"by_context": {c: _suhrn_skore(scores[kind == c], prah)
                                     for c in (*CONTEXTS, "excluded") if (kind == c).any()},
                      "by_scenario": {sc: _suhrn_skore(scores[session_scenario == sc], prah)
                                      for sc in sorted(set(scenarios.values()))}},
            "definition": TRAINING_RULE, "contexts": CONTEXT_RULE}


def training_record(summary, manifest, command):
    """The evaluation record of one training that names its bundle (question Q11): the provenance header of every
    record of this module (_zaznam: commit, date, host, guest, command, n; command the full command line of the caller,
    a list) and values {schema, bundle {manifest_sha256, seed, created_utc, corpus_index_sha256}, summary}."""
    if type(summary) is not dict or summary.get("schema") != SCHEMA_SUHRN_TRENINGU:
        raise ValueError("training_record takes a summary of training_summary")
    values = {"schema": SCHEMA_TRENING,
              "bundle": {"manifest_sha256": _manifest_sha(manifest), "seed": manifest["training"]["seed"],
                         "created_utc": manifest["created_utc"],
                         "corpus_index_sha256": manifest["provenance"]["corpus_index_sha256"]},
              "summary": summary}
    if type(command) not in (list, tuple) or not command or not all(type(x) is str for x in command):
        raise ValueError("the command of a record is the caller's command line, a list of strings")
    doc = _zaznam(values, manifest, None, n=summary["windows"], prikaz=list(command))
    doc.pop("_zmeny")
    return doc


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
    f.add_argument("--role", required=True, choices=ROLY_V5,
                   help="schemy 1 a 2: dev, test_benign; schema 3: aj calibration a test_controls")
    f.add_argument("--replay", required=True, nargs="+", help="vystupne adresare safeguard replay --archive")
    f.add_argument("--out", required=True, help="novy JSON; existujuci sa neprepise")
    f.add_argument("--campaign", help="zaznam kampane v data/results (planovane, prijate a zamietnute behy)")
    f.add_argument("--alfa", type=_arg_alfa, default=0.05)
    f.add_argument("--final", action="store_true",
                   help="povinne pre test_benign: zaverecne FAR, raz na korpus, nad commitnutym kodom")
    u = sub.add_parser("udalosti", help="FAR balika pocas prevadzkovych udalosti (krok A: index v3; "
                                        "krok B, E2': korpus v4 a rola)")
    u.add_argument("--index", required=True, help="events_index.json kampane v3 alebo corpus.json protokolu v4")
    u.add_argument("--role", choices=ROLY_V5, help="iba pri korpuse: rola, z ktorej sa FAR pocita")
    u.add_argument("--final", action="store_true",
                   help="povinne pre test_benign: zaverecne E2', raz na korpus, nad commitnutym kodom")
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
    vypis = {"rola": a.role, "relacii": doc["n"], "udalosti_model": spolu["spolu"]["udalosti_model"],
             "far_model_skorovany_h": spolu["far_h"]["skorovany"],
             "aktivity_okna_presnost": klas and klas["okna"]["presnost"],
             "aktivity_relacie": klas and [klas["relacie"]["spravnych"], klas["relacie"]["spolu"]]}
    if "v5" in values:
        vypis.update(plan_mode=values["plan_mode"], rehearsal_mark=values["rehearsal_mark"],
                     o2_union_per_hour=values["v5"]["o2"]["total"][UNION]["per_hour"])
    print(json.dumps(vypis, ensure_ascii=False))
    return 0


def _zaznam(values, balik, argv, n=None, prikaz=None):
    """Hlavicka zaznamu v data/results (HONESTY kap. 4); n su relacie values, ak nie je dane, a prikaz je
    `python3 -m tcn.eval` s argv, ak volajuci nedal svoj cely prikaz (training_record)."""
    commit, zmeny = _git_stav()
    doc = {"commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
           "evaluator_sha256": _digest(os.path.abspath(__file__)),
           "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "host": platform.platform(),
           "guest": "jadro %s, stack_sha256 %s" % (balik["environment"]["kernel"],
                                                   balik["environment"]["stack_sha256"]),
           "command": shlex.join(prikaz if prikaz is not None else ["python3", "-m", "tcn.eval", *argv]),
           "cwd": os.getcwd(),
           "n": len(values["relacie"]) if n is None else n, "values": values, "_zmeny": zmeny}
    if "stage" in values:  # A record of protocol schema 3 (_znacka_v5): its stage beside its provenance (11.1).
        doc["stage"] = values["stage"]
    if zmeny is None:
        doc["commit_note"] = "git nedostupny; kod urcuje evaluator_sha256"
    elif zmeny:
        doc["commit_note"] = "neulozene zmeny: %s; kod urcuje evaluator_sha256" % ", ".join(zmeny)
    return doc


def _udalosti(a, argv):
    index = json.loads(open(a.index, encoding="utf-8").read())
    if index.get("schema") == SCHEMA_KORPUS and _je_v5(index.get("protocol_config")):
        if a.final:
            raise SystemExit(FINAL_V5)  # Schema 3: the seal of the final command, not the mark (balik B7c).
    elif (a.role == "test_benign") != bool(a.final):
        raise SystemExit("test_benign je zaverecny test a pusti sa iba s --final; --final plati iba pre test_benign")
    values, balik = vyhodnot_udalosti(a.index, a.replay, a.alfa, a.role)
    doc = _zaznam(values, balik, argv)
    commit, zmeny = doc["commit"], doc.pop("_zmeny")
    vlastny = os.path.relpath(os.path.abspath(__file__), REPO)
    if a.final and (commit is None or zmeny is None or vlastny in zmeny):
        raise SystemExit("--final vyzaduje git a commitnuty %s" % vlastny)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    with open(a.out, "x", encoding="utf-8") as fh:
        if a.final:
            # Vlastny zaznam vedla korpusu: E2' sa pocita raz, z toho isteho
            # zaverecneho prehratia test_benign ako FAR (prikaz far --final).
            try:
                with open(os.path.realpath(a.index) + ".test_benign-final-udalosti.json", "x",
                          encoding="utf-8") as zaznam:
                    json.dump({"date": doc["date"], "out": os.path.realpath(a.out), "commit": commit,
                               "evaluator_sha256": doc["evaluator_sha256"],
                               "manifest_sha256": values["balik"]["manifest_sha256"]}, zaznam, indent=2)
            except FileExistsError:
                fh.close()
                os.unlink(a.out)
                raise
        fh.write(text)
    m = values["merane"]
    print(json.dumps({"relacii": doc["n"], "uplna_alokacia": values["alokacia"]["uplna"],
                      "udalosti": [values["udalosti"]["vykonanych"], values["udalosti"]["planovanych"]],
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
