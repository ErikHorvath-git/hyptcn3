"""
eval.py - metriky, tabulka a ulozenie vysledku.

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
"""

import datetime
import json
import os
import platform
import subprocess

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
