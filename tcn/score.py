"""
score.py - skorovaci proces: adresar so snimkami -> vektor -> okno -> TCN -> cislo.

MODEL NIE JE NATRENOVANY A SKORE NIE JE DETEKCIA
------------------------------------------------
Korpus neexistuje: na tomto stroji nie su ziadne realne malverove vzorky,
takze niet co oznacit a niet na com trenovat. Vahy modelu su nahodne
inicializovane s pevnym seedom. Cislo, ktore tento proces vypise, preto
NEHOVORI NIC o tom, ci sa vo VM nieco deje - je to dokaz, ze cela cesta
(pamat VM -> snimka -> priznakovy vektor -> klzave okno -> TCN -> cislo)
bezi ako jeden celok. Ziadna hodnota z tohto programu sa nesmie uviest ako
vysledok detekcie (HONESTY.md, P4 a P7).

Upozornenie je na troch miestach zamerne: v tomto docstringu, na zaciatku
kazdeho vypisu programu a v kazdom JSON vystupe (kluc `model_natrenovany`).
Kto cislo odniekial skopiruje, musi na upozornenie narazit.

PRECO TENTO SUBOR EXISTUJE
--------------------------
Zadanie ziada zakladnu implementaciu alebo integraciu TCN modelu.
Implementacia je v tcn/model.py, trening v tcn/train.py - oboje ale pracuje
s maticami z .npz suborov a snimku z bezicej VM nikdy nevidelo. Tu sa model
prvykrat napaja na vystup zberaca.

CO SA CITA A KEDY JE SNIMKA HOTOVA
----------------------------------
Sleduje sa ten isty adresar, do ktoreho pise `vmicollect run`
(output.dir). Jedna snimka su dva subory: `<id>.vmicd` (stranky) a `<id>.json`
(sidecar). Zberac zapisuje sidecar az po obraze (vmic_meta_write az za
meranim v collector.c), takze prave sidecar je znamenie, ze snimka je cela na
disku. Ked sa sidecar nacitat neda, este sa zapisuje a skusi sa v dalsom kole.

Vektor sa pocita cez features/snapshot.py (dvadsat priznakov + ma_predchodcu),
teda tou istou funkciou ako pri priprave dat na trening - v jednom datasete
nesmu byt cisla z dvoch implementacii.

KLZAVE OKNO
-----------
Drzia sa posledne L snimok (L = features.windows.DLZKA_OKNA = 16, dovody su
v hlavicke windows.py). Kym okno plne nie je, skore sa nepocita a vypisuje sa,
na kolko snimok sa este caka. Ticho nerobit nic by vyzeralo ako porucha.

CO TU ZAMERNE NIE JE
--------------------
Normalizacia (features/normalize.py). mu/sd sa fituje na benignych
trenovacich sessions; ziadne natrenovane mu/sd neexistuje a vymysliet ho tu
by znamenalo, ze skorovanie pouziva inu skalu nez trening. Az bude model
natrenovany, nacita sa spolu s jeho mu/sd a normalizacia patri sem, medzi
`vektor_snimky` a okno.

NAVRATOVE KODY (rovnake ako `python3 -m features`)
  0  prebehlo
  2  snimka, sidecar alebo profil sa nedaju precitat
"""

import argparse
import collections
import json
import os
import sys
import time

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.normalize import Normalizer                  # noqa: E402
from features.perbin import FeatureError                    # noqa: E402
from features.snapshot import MENA, vektor_snimky           # noqa: E402
from features.windows import DLZKA_OKNA                     # noqa: E402
from tcn.model import TCN, TCNPrediktor                     # noqa: E402

SCHEMA = "hyptcn3/latencia-skore/1"
EXIT_OK = 0
EXIT_ERROR = 2

# Pocet vystupnych tried. Dve, lebo taky je tvar ulohy v tcn/train.py
# (benigna / ostatne); bez treningu je to iba tvar vystupu, nie triedy.
TRIED = 2
SEED = 0

UPOZORNENIE = (
    "POZOR: model NIE JE NATRENOVANY - korpus neexistuje (na tomto stroji nie "
    "su realne malverove vzorky).",
    "Vahy su nahodne inicializovane seedom %d. Vypisane skore NIE JE detekcia "
    "ani pravdepodobnost napadnutia;" % SEED,
    "je to dokaz, ze cesta snimka -> vektor -> okno -> TCN bezi. Ako vysledok "
    "sa uviest nesmie (HONESTY.md P4, P7).",
)


def model_bez_treningu(dlzka_okna, seed=SEED):
    """Nahodne inicializovany TCN v rezime eval (bez dropoutu).

    Seed je pevny, aby sa ten isty beh dal zopakovat - nie preto, ze by mal
    vystup nejaky vyznam.
    """
    torch.manual_seed(seed)
    m = TCN(len(MENA), TRIED, dlzka_okna=dlzka_okna)
    m.eval()
    return m


def skore(model, okno):
    """Okno L vektorov -> zoznam TRIED cisel (softmax nad logitmi).

    Softmax preto, ze sa cisla daju vypisat vedla seba a sucet je 1. Nie je to
    pravdepodobnost niecoho - model nebol trenovany.
    """
    x = torch.tensor([list(okno)], dtype=torch.float32)
    with torch.no_grad():
        p = torch.softmax(model(x), dim=1)[0]
    return [float(v) for v in p]


def cakam_text(mam, dlzka):
    """Hlaska o nenaplnenom okne; pri plnom okne vrati prazdny retazec."""
    if mam >= dlzka:
        return ""
    return ("okno nie je plne (%d z %d), skore sa nepocita - cakam na %d "
            "dalsich snimok" % (mam, dlzka, dlzka - mam))


def nove_sidecary(adresar, videne):
    """Sidecary, ktore v adresari pribudli, v poradi seq.

    Vracia zoznam (seq, id, timestamp_unix). Sidecar, ktory sa nenacita, sa
    preskoci bez zaznamu do `videne` - zberac ho prave pise a v dalsom kole
    tam bude cely.
    """
    out = []
    for meno in sorted(os.listdir(adresar)):
        if not meno.endswith(".json") or meno in videne:
            continue
        try:
            with open(os.path.join(adresar, meno), encoding="utf-8") as fh:
                doc = json.load(fh)
            seq = int(doc["seq"])
            cas = float(doc["timestamp_unix"])
        except (ValueError, KeyError, OSError):
            continue
        videne.add(meno)
        out.append((seq, doc.get("id", meno[:-len(".json")]), cas))
    return sorted(out)


def beh(adresar, profil, dlzka=DLZKA_OKNA, cakaj=0.0, perioda=0.5, vypis=print):
    """Hlavna slucka. Vracia zoznam zaznamov, jeden na spracovanu snimku."""
    for r in UPOZORNENIE:
        vypis(r)
    vypis("adresar snimok : %s" % adresar)
    vypis("dlzka okna     : %d snimok" % dlzka)

    model = model_bez_treningu(dlzka)
    okno = collections.deque(maxlen=dlzka)
    videne, zaznamy, predch = set(), [], None
    posledna = time.monotonic()

    while True:
        nove = nove_sidecary(adresar, videne)
        if not nove:
            if time.monotonic() - posledna >= cakaj:
                break
            time.sleep(perioda)
            continue
        posledna = time.monotonic()

        for seq, sid, cas_snimky in nove:
            videne_unix = time.time()
            t0 = time.monotonic()
            vektor, predch, pozn = vektor_snimky(adresar, profil, seq, predch)
            t_vektor = time.monotonic() - t0

            okno.append(vektor)
            z = {"seq": seq, "id": sid, "timestamp_unix": cas_snimky,
                 "videne_unix": videne_unix,
                 "vektor_ms": round(t_vektor * 1000, 3),
                 "model_ms": None, "skore": None, "okno_plne": len(okno) >= dlzka,
                 "poznamky": list(pozn)}

            for p in pozn:
                vypis("snimka %s: poznamka: %s" % (sid, p))

            caka = cakam_text(len(okno), dlzka)
            if caka:
                vypis("snimka %s: vektor za %.0f ms; %s"
                      % (sid, t_vektor * 1000, caka))
            else:
                t1 = time.monotonic()
                s = skore(model, okno)
                t_model = time.monotonic() - t1
                hotovo = time.time()
                z["model_ms"] = round(t_model * 1000, 3)
                z["skore"] = s
                z["skore_unix"] = hotovo
                z["spracovanie_ms"] = round((hotovo - videne_unix) * 1000, 3)
                z["latencia_od_snimky_ms"] = round(
                    (hotovo - cas_snimky) * 1000, 3)
                vypis("snimka %s: vektor za %.0f ms, model za %.1f ms, "
                      "skore (NENATRENOVANY model) = [%s]"
                      % (sid, t_vektor * 1000, t_model * 1000,
                         ", ".join("%.4f" % v for v in s)))
            zaznamy.append(z)
    return zaznamy


def suhrn(zaznamy, kluc):
    """median, p95, min, max, n z jedneho kluca zaznamov; None, ked niet z coho."""
    h = sorted(z[kluc] for z in zaznamy if z.get(kluc) is not None)
    if not h:
        return {"n": 0, "median": None, "p95": None, "min": None, "max": None}
    stred = h[len(h) // 2] if len(h) % 2 else (h[len(h) // 2 - 1]
                                               + h[len(h) // 2]) / 2.0
    # p95 metodou najblizsieho poradia, rovnako ako features/snapshot.py
    i = min(len(h) - 1, max(0, -(-95 * len(h) // 100) - 1))
    return {"n": len(h), "median": round(stred, 3), "p95": round(h[i], 3),
            "min": round(h[0], 3), "max": round(h[-1], 3)}


# ------------------------------------------------------ E2: chyba predikcie


def nacitaj_prediktor(cesta):
    """Model + normalizacia z treningu (--uloz-model v tcn/train.py)."""
    doc = torch.load(cesta, map_location="cpu")
    m = TCNPrediktor(doc["priznakov"], dlzka_okna=doc["dlzka_okna"])
    m.load_state_dict(doc["state_dict"])
    m.eval()
    norm = Normalizer.load(cesta + ".manifest.json", priznaky=tuple(MENA))
    return m, norm, doc


def chyba_predikcie_okna(model, norm, okno):
    """Okno L vektorov -> (skore, chyby na priznak, predpoved).

    Skore = priemerna stvorcova chyba cez priznaky BEZ indikatorov
    ma_predchodcu/je_plna (tie su 0/1 znacky o tom, co riadok je - nie
    meranie, predikovat ich nema zmysel a ich chyba by skore zriedila).
    """
    X = np.asarray([list(okno)], dtype=np.float64)
    Xn = norm.transform(X)                       # (1, L, F)
    vstup, ciel = Xn[:, :-1, :], Xn[:, -1, :]
    with torch.no_grad():
        p = model(torch.tensor(vstup, dtype=torch.float32))[0].numpy()
    chyby = (p - ciel[0]) ** 2
    indikatory = ("ma_predchodcu", "je_plna")
    mask = np.array([n not in indikatory for n in norm.priznaky])
    skore = float(np.mean(chyby[mask]))
    return skore, [float(v) for v in chyby], [float(v) for v in p]


def beh_predikcia(adresar, profil, dlzka, model, norm, cakaj=0.0, perioda=0.5,
                  vypis=print):
    """Hlavna slucka pre predikcny rezim: skore = chyba predikcie okna."""
    vypis("rezim          : predikcia normalu (E2), skore = chyba predikcie")
    vypis("adresar snimok : %s" % adresar)
    vypis("dlzka okna     : %d snimok" % dlzka)

    okno = collections.deque(maxlen=dlzka)
    videne, zaznamy, predch = set(), [], None
    posledna = time.monotonic()

    while True:
        nove = nove_sidecary(adresar, videne)
        if not nove:
            if time.monotonic() - posledna >= cakaj:
                break
            time.sleep(perioda)
            continue
        posledna = time.monotonic()

        for seq, sid, cas_snimky in nove:
            videne_unix = time.time()
            t0 = time.monotonic()
            vektor, predch, pozn = vektor_snimky(adresar, profil, seq, predch)
            t_vektor = time.monotonic() - t0

            okno.append(vektor)
            z = {"seq": seq, "id": sid, "timestamp_unix": cas_snimky,
                 "videne_unix": videne_unix,
                 "vektor_ms": round(t_vektor * 1000, 3),
                 "model_ms": None, "skore": None, "chyby": None,
                 "okno_plne": len(okno) >= dlzka,
                 "poznamky": list(pozn)}
            for p in pozn:
                vypis("snimka %s: poznamka: %s" % (sid, p))

            caka = cakam_text(len(okno), dlzka)
            if caka:
                vypis("snimka %s: vektor za %.0f ms; %s"
                      % (sid, t_vektor * 1000, caka))
            else:
                t1 = time.monotonic()
                sk, chyby, _ = chyba_predikcie_okna(model, norm, okno)
                t_model = time.monotonic() - t1
                hotovo = time.time()
                top = sorted(range(len(chyby)), key=lambda i: -chyby[i])[:3]
                z["model_ms"] = round(t_model * 1000, 3)
                z["skore"] = sk
                z["chyby"] = chyby
                z["top_priznaky"] = [
                    {"priznak": norm.priznaky[i], "chyba": chyby[i]}
                    for i in top]
                z["skore_unix"] = hotovo
                z["spracovanie_ms"] = round((hotovo - videne_unix) * 1000, 3)
                z["latencia_od_snimky_ms"] = round(
                    (hotovo - cas_snimky) * 1000, 3)
                vypis("snimka %s: vektor za %.0f ms, model za %.1f ms, "
                      "chyba predikcie = %.6f (top: %s)"
                      % (sid, t_vektor * 1000, t_model * 1000, sk,
                         ", ".join(norm.priznaky[i] for i in top)))
            zaznamy.append(z)
    return zaznamy


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="python3 -m tcn.score",
        description="skorovanie snimok z adresara zberaca; model NIE JE "
                    "natrenovany a skore nie je detekcia")
    ap.add_argument("--snapshots", required=True,
                    help="adresar, do ktoreho pise vmicollect (output.dir)")
    ap.add_argument("--profile", required=True,
                    help="adresar profilu jadra hosta (kallsyms.txt, btf.txt)")
    ap.add_argument("--dlzka", type=int, default=DLZKA_OKNA,
                    help="dlzka okna v snimkach (vychodzia %d)" % DLZKA_OKNA)
    ap.add_argument("--uloha", default="skore",
                    choices=("skore", "predikcia"),
                    help="skore = netrenovany klasifikator (dokaz cesty); "
                         "predikcia = natrenovany prediktor normalu (E2)")
    ap.add_argument("--model", default=None,
                    help="predikcia: <cesta>.pt z tcn.train --uloz-model "
                         "(vedla musi byt <cesta>.pt.manifest.json)")
    ap.add_argument("--cakaj", type=float, default=0.0, metavar="S",
                    help="ako dlho cakat na dalsiu snimku, kym sa skonci "
                         "(0 = spracovat, co je v adresari, a skoncit)")
    ap.add_argument("--json", metavar="SUBOR",
                    help="kam zapisat zaznamy a suhrn casov")
    a = ap.parse_args(argv)

    if a.uloha == "predikcia" and not a.model:
        ap.error("--uloha predikcia vyzaduje --model <cesta>.pt")

    try:
        if a.uloha == "predikcia":
            model, norm, doc_modelu = nacitaj_prediktor(a.model)
            zaznamy = beh_predikcia(a.snapshots, a.profile, a.dlzka,
                                    model, norm, a.cakaj)
        else:
            doc_modelu = None
            zaznamy = beh(a.snapshots, a.profile, a.dlzka, a.cakaj)
    except FeatureError as exc:
        print("chyba: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print("chyba: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    so_skore = [z for z in zaznamy if z["skore"] is not None]
    print("spracovanych snimok: %d, z toho so skore: %d"
          % (len(zaznamy), len(so_skore)))
    if a.uloha == "predikcia" and so_skore:
        s = [z["skore"] for z in so_skore]
        print("chyba predikcie: median=%.6f, p95=%.6f, max=%.6f (n=%d)"
              % (sorted(s)[len(s) // 2],
                 sorted(s)[min(len(s) - 1, -(-95 * len(s) // 100) - 1)],
                 max(s), len(s)))
    if not so_skore:
        print("ziadne okno sa nenaplnilo - na skore treba aspon %d snimok"
              % a.dlzka)

    if a.json:
        doc = {
            "schema": SCHEMA,
            "model_natrenovany": a.uloha == "predikcia",
            "model_poznamka": (UPOZORNENIE[0] + " " + UPOZORNENIE[1]
                               if a.uloha != "predikcia" else ""),
            "uloha": a.uloha,
            "model": os.path.abspath(a.model) if a.model else None,
            "dlzka_okna": a.dlzka,
            "adresar": os.path.abspath(a.snapshots),
            "profil": os.path.abspath(a.profile),
            "vektor_ms": suhrn(zaznamy, "vektor_ms"),
            "model_ms": suhrn(zaznamy, "model_ms"),
            "spracovanie_ms": suhrn(zaznamy, "spracovanie_ms"),
            "latencia_od_snimky_ms": suhrn(zaznamy, "latencia_od_snimky_ms"),
            "latencia_poznamka":
                "latencia_od_snimky_ms ma zmysel iba pri zivom zbere; nad "
                "ulozenou snimkou je to jej vek, nie latencia",
            "zaznamy": zaznamy,
        }
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
        print("zapisane: %s" % a.json)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
