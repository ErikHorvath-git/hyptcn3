"""
hodnotenie.py - blok H: kompletne vyhodnotenie z artefaktov sedeni.

Sklada vsetko, co predchadzajuce bloky pripravili, do jedneho behu:

  data/sessions/<stamp>_<label>_<typ>/  (manifest.json, aktivita.json,
        ground truth) + data/raw/<stamp>_session/ (snimky, sidecary)

  1. vektory: features.session -> npz (rovnaka cesta ako trening);
  2. okna + prediktor + chyby (skore anomálie) pre kazde sedenie;
  3. kalibracia (E3) na ODLOZENYCH benígnych sedeniach;
  4. FAR/h na benígnych sedeniach, ktore kalibracia NEVIDELA;
  5. detekcia a cas-do-detekcie PER technika/rodina (len aktivne behy, G3);
  6. vsetko do jedneho JSON (HONESTY hlavicka, n, commit).

Ziadne cislo sa tu NEVYMYSLA: ked chyba aktivita.json, beh sa nepocita do
detekcie; ked chyba model, krok skonci s jasnou chybou.

POUZITIE
  python3 -m tcn.hodnotenie --sessions data/sessions --raw data/raw
      --profile profiles/debian12-6.1.0-42-cloud-amd64
      --model <cesta>.pt [--out data/results/hodnotenie_<stamp>.json]
"""

import argparse
import datetime
import json
import os
import sys

import numpy as np

from features.snapshot import MENA
from features.windows import DLZKA_OKNA, okna, snimky_z_matice
from tcn.kalibracia import kalibracia
from tcn.eval import detekcia_per_technika, far_h


def nacitaj_sedenia(adresar_sessions, adresar_raw, profil, dlzka=DLZKA_OKNA):
    """
    Vsetky sedenia -> {meno: {label, typ, aktivny, skore_okien, t0_s, n_okien,
    poznamky}}. Vektory sa pocitaju rovnako ako pri treningu (features.session
    nema API pre import - preto sa spusta ako podproces do docasneho npz).
    """
    import subprocess
    import tempfile

    out = {}
    mena = sorted(os.listdir(adresar_sessions))
    tmp = tempfile.mkdtemp(prefix="hodnotenie_")
    for meno in mena:
        sdir = os.path.join(adresar_sessions, meno)
        manifest = os.path.join(sdir, "manifest.json")
        if not os.path.isfile(manifest):
            continue
        try:
            doc = json.load(open(manifest, encoding="utf-8"))
            typ = doc.get("typ", "benign")
            label = doc.get("label", "n/a")
            stamp = doc.get("stamp", meno[:15])
            raw = doc.get("vystupy", {}).get("snimky_adresar")
        except (OSError, ValueError):
            continue
        # raw adresar: manifest drzi relativnu cestu od korena repa
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if raw:
            raw_dir = os.path.join(repo, raw)
        else:
            raw_dir = os.path.join(adresar_raw, stamp + "_session")
        if not os.path.isdir(raw_dir) or not any(
                f.endswith(".vmicd") for f in os.listdir(raw_dir)):
            out[meno] = {"label": label, "typ": typ, "chyba":
                         "chybaju snimky v %s" % raw_dir}
            continue
        # vektory cez features.session (rovnaka cesta ako trening)
        npz = os.path.join(tmp, meno + ".npz")
        r = subprocess.run(
            [sys.executable, "-m", "features", "session",
             "--snapshot", raw_dir, "--profile", profil, "--out", npz],
            capture_output=True, text=True, cwd=os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
        if r.returncode != 0:
            out[meno] = {"label": label, "typ": typ, "chyba":
                         r.stderr.strip()[-300:]}
            continue
        data = np.load(npz, allow_pickle=False)
        matica = np.asarray(data["matica"], dtype=np.float64)
        snimky = snimky_z_matice(meno, matica, MENA)
        o = okna(snimky, dlzka=dlzka)
        out[meno] = {
            "label": label, "typ": typ,
            "okien": len(o),
            "okna_X": o.X,
            "vynechane": o.pocty_vynechanych(),
        }
        # aktivita (G3): bez nej sa detekcia nad behom nepocita
        akt = os.path.join(sdir, "aktivita.json")
        if os.path.isfile(akt):
            try:
                out[meno]["aktivny"] = json.load(
                    open(akt, encoding="utf-8")).get("aktivny")
            except (OSError, ValueError):
                out[meno]["aktivny"] = None
        else:
            out[meno]["aktivny"] = None
    return out


def skore_sedeni(sedenia, model, norm):
    """Chyby predikcie (skore anomálie) pre kazde sedenie s oknami."""
    from tcn.score import chyba_predikcie_okna

    out = {}
    for meno, s in sedenia.items():
        if "okna_X" not in s or not len(s["okna_X"]):
            continue
        skore = []
        for i in range(len(s["okna_X"])):
            okno = s["okna_X"][i]
            sk, _, _ = chyba_predikcie_okna(model, norm, okno)
            skore.append(sk)
        s["skore"] = np.asarray(skore)
    return sedenia


def hodnotenie(sedenia, perioda_s=5.0, fp_za_den=1.0, k=3, n=5,
               podiel_validacie=0.3, seed=0):
    """
    Kalibracia + FAR/h + detekcia per technika. Vracia dict do JSON.

    Benígne sedenia sa CHRONOLOGICKY rozdelia: starsie na kalibraciu,
    novsie na meranie FAR/h (kalibracia nesmie vidiet to, na com sa
    meria). Skodlive behy sa pocitaju len ked su AKTIVNE (G3).
    """
    ben = sorted((m for m, s in sedenia.items()
                  if s["typ"] == "benign" and "skore" in s))
    if len(ben) < 2:
        raise ValueError("treba aspon 2 benigne sedenia so skore, je ich %d"
                         % len(ben))
    kk = max(1, int(round(len(ben) * podiel_validacie)))
    kal_s, far_s = ben[:kk], ben[kk:]

    chyby_val = np.concatenate([sedenia[m]["skore"] for m in kal_s])
    kal = kalibracia(chyby_val, perioda_s=perioda_s, fp_za_den=fp_za_den,
                     k=k, n=n, seed=seed)

    far = far_h([sedenia[m]["skore"] for m in far_s],
                kal["prah"], perioda_s=perioda_s, k=k, n=n) if far_s else {
                    "n": 0, "far_h": None,
                    "poznamka": "ziadne benigne sedenie mimo kalibracie"}

    behy = []
    vynechane_neaktivne = []
    for m in sorted(sedenia):
        s = sedenia[m]
        if s["typ"] != "malicious" or "skore" not in s:
            continue
        if s.get("aktivny") is not True:
            vynechane_neaktivne.append(m)
            continue
        behy.append({"label": s["label"], "skore": s["skore"], "t0_s": 0.0})
    det = detekcia_per_technika(behy, kal["prah"], k, n, perioda_s)

    return {
        "kalibracia": kal,
        "far_h": far,
        "far_sedenia": far_s,
        "kalibracne_sedenia": kal_s,
        "detekcia_per_technika": det,
        "neaktivne_vynechane": vynechane_neaktivne,
        "poznamka": ("far_h je z benígnych sedení, ktoré kalibrácia NEVIDELA; "
                     "detekcia len nad aktívnymi behmi (G3)"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="vyhodnotenie H z artefaktov")
    ap.add_argument("--sessions", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--model", required=True,
                    help="<cesta>.pt z tcn.train --uloz-model")
    ap.add_argument("--perioda", type=float, default=5.0)
    ap.add_argument("--fp-den", type=float, default=1.0)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    from tcn.score import nacitaj_prediktor
    model, norm, doc_modelu = nacitaj_prediktor(a.model)

    sedenia = nacitaj_sedenia(a.sessions, a.raw, a.profile)
    sedenia = skore_sedeni(sedenia, model, norm)
    res = hodnotenie(sedenia, perioda_s=a.perioda, fp_za_den=a.fp_den,
                     k=a.k, n=a.n)

    chyby = {m: s.get("chyba") for m, s in sedenia.items() if "chyba" in s}
    if chyby:
        res["sedenia_s_chybou"] = chyby
    res["model"] = os.path.abspath(a.model)
    res["model_mse_test"] = doc_modelu.get("mse_test")

    print("kalibracia: prah=%.4f, n_okien=%d, fpr_merane=%.3g"
          % (res["kalibracia"]["prah"], res["kalibracia"]["n_okien"],
             res["kalibracia"]["fpr_okno_odmerane"]))
    print("FAR/h (mimo kalibracie): %s"
          % (res["far_h"]["far_h"] if res["far_h"]["far_h"] is not None
             else "n/a"))
    for lab, d in sorted(res["detekcia_per_technika"].items()):
        print("  %-16s detegovanych %d/%d, ttd_median %s s"
              % (lab, d["detegovanych"], d["n_behov"],
                 d["ttd_median_s"] if d["ttd_median_s"] is not None else "-"))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        print("zapisane: %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
