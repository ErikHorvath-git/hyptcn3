"""
seedy.py - rozptyl TCN cez seedy inicializacie (E4/VO6, doplnok k finalnemu modelu).

Seedy (balik B6b, navrh NAVRH_B6b 1.6). Pri protokole schemy 3 su seedy
z planu analyzy (analysis.seeds, 0 az 4; balik na nasadenie je
analysis.deploy_seed = 0, D14): bez --seeds sa trenuju vsetky, seed 0
vratane; seed mimo planu prejde iba s --diagnostic (manifest ho uvedie ako
prepisanie). Pri schemach 1 a 2 ostava dnesne pravidlo legacy_schema_2:
bez --seeds seedy 1..4 (SEEDY). Kazdy seed trenuje ten isty
safeguard.training.train_bundle na tom istom korpuse; ostatne parametre
analyzy (--epochs, --batch-size, --fpr, --k, --n) su predvolene nezadane
a train_bundle ich pri scheme 3 mimo --diagnostic odmietne. Rozptyl:
metriky na dev (vyber checkpointu, kalibracia) a vysledky na datasetoch 2/3
(tcn.eval udalosti, buduci malver); suhrn vysledky roly test_benign
odmietne (zaverecny test patri baliku B7).

Modul je tenky: `train` iba vola train_bundle pre kazdy seed do
<out-root>/seed-<s>; `suhrn` je cista funkcia nad manifestmi a JSON
vysledkami (offline, testovatelna bez treningu).
"""

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import shlex
import sys

import numpy as np

SCHEMA_SUHRN = "hyptcn3/seed-spread/1"
SEEDY = (1, 2, 3, 4)  # legacy_schema_2: seedy bez --seeds pri protokole schemy 1 a 2 (dnesne)
FINALNY_SEED = 0


def _over_seedy(seedy):
    """Tvar zoznamu seedov: neprazdny, nezaporne cele cisla, kazdy raz. Seed 0 je dovoleny (D14: balik na
    nasadenie ma seed 0; SULAD: vsetkych pat seedov v jednom finalnom behu)."""
    seedy = list(seedy)
    if not seedy or any(type(s) is not int or s < 0 for s in seedy):
        raise ValueError("seedy musia byt nezaporne cele cisla")
    if len(set(seedy)) != len(seedy):
        raise ValueError("seed je zadany viackrat")
    return seedy


def seedy_planu(protokol, seedy=None, *, diagnostic=False):
    """Seedy treningu pri protokole: schema 3 berie analysis.seeds (scripts/protocol_v5.py analysis_plan); zadany
    seed mimo nich odmietne s menovanym dovodom, okrem diagnostiky. Schemy 1 a 2 (legacy_schema_2): bez zadanych
    SEEDY, inak zadane."""
    from scripts.protocol_v5 import SCHEMA, analysis_plan
    if seedy is not None:
        seedy = _over_seedy(seedy)
    if protokol.get("schema") != SCHEMA:
        return list(SEEDY) if seedy is None else seedy
    planovane = list(analysis_plan(protokol)["seeds"])
    if seedy is None:
        return planovane
    mimo = [s for s in seedy if s not in planovane]
    if mimo and not diagnostic:
        raise ValueError(f"seed {mimo[0]} nie je v analysis.seeds {planovane} protokolu schemy 3; seed mimo planu "
                         "analyzy sa trenuje iba pre diagnosticky balik (--diagnostic)")
    return seedy


def trenuj_seedy(korpus, out_root, seedy=None, **kwargs):
    """train_bundle pre kazdy seed (seedy_planu nad protokolom korpusu); existujuci vystup sa nikdy neprepise.
    Zadane seedy sa skontroluju este pred citanim korpusu, vsetky pred prvym treningom."""
    from safeguard.training import train_bundle
    if seedy is not None:
        seedy = _over_seedy(seedy)
    if "seed" in kwargs:
        raise ValueError("seed sa zadava cez zoznam seedov")
    out_root = Path(out_root)

    def ciele(zoznam):
        mapa = {s: out_root / f"seed-{s}" for s in zoznam}
        existuju = [str(c) for c in mapa.values() if c.exists()]
        if existuju:
            raise FileExistsError("vystup existuje: " + ", ".join(existuju))
        return mapa
    if seedy is not None:
        ciele(seedy)
    protokol = json.loads(Path(korpus).read_text())["protocol_config"]
    mapa = ciele(seedy_planu(protokol, seedy, diagnostic=kwargs.get("diagnostic", False)))
    vysledky = {}
    for s, ciel in mapa.items():
        vysledky[s] = train_bundle(korpus, ciel, seed=s, **kwargs)
    return vysledky


# ------------------------------------------------------------------ suhrn


def _manifest_sha(manifest):
    from tcn.eval import _manifest_sha as sha
    return sha(manifest)


def metriky_balika(manifest):
    """Dev a kalibracne metriky jedneho balika (vybraty checkpoint). Prediktor a klasifikator sa od balika B6b
    ucia oddelene: krivka prediktora je training.history, klasifikatora training.classifier_history."""
    tr, kal = manifest["training"], manifest["calibration"]
    if "classifier_history" not in tr:
        raise ValueError("manifest nema training.classifier_history (balik spred balika B6b)")
    pred = {h["epoch"]: h for h in tr["history"]}[tr["selected_predictor_epoch"]]
    klas = {h["epoch"]: h for h in tr["classifier_history"]}[tr["selected_classifier_epoch"]]
    return {"dev_prediction_loss": pred["dev_prediction_loss"],
            "dev_classification_loss": klas["dev_classification_loss"],
            "selected_predictor_epoch": tr["selected_predictor_epoch"],
            "selected_classifier_epoch": tr["selected_classifier_epoch"],
            "calibration_threshold": kal["threshold"],
            "calibration_alarm_events_per_hour": kal["calibration_alarm_events_per_hour"],
            "calibration_window_exceedance_fraction": kal["window_exceedance_fraction"]}


def _far_h(blok):
    if not blok or not blok.get("far_h") or not blok["far_h"].get("skorovany"):
        return None
    return blok["far_h"]["skorovany"]["udalosti_h"]


def metriky_vysledku(values):
    """Ciselne metriky z `values` vysledku tcn.eval (far alebo udalosti)."""
    schema = values.get("schema")
    if schema == "hyptcn3/safeguard-far/2":
        if values.get("rola") == "test_benign" or values.get("final"):
            raise ValueError("test_benign je zaverecny test finalneho modelu; do rozptylu seedov nepatri")
        klas = values["klasifikacia_aktivit"]
        return {"far_h": _far_h(values["merane"]["spolu"]),
                "udalosti_model": values["merane"]["spolu"]["spolu"]["udalosti_model"],
                "aktivity_okna_presnost": klas["okna"]["presnost"],
                "aktivity_okna_f1_macro": klas["okna"]["f1_macro"],
                "aktivity_relacie_presnost": klas["relacie"]["presnost"]}
    if schema == "hyptcn3/safeguard-event-far/1":
        m, u = values["merane"], values["udalosti"]
        out = {"prevadzka_far_h": _far_h(m["prevadzka"]), "po_udalosti_far_h": _far_h(m["po_udalosti"]),
               "udalosti_far_h": _far_h(m["vsetky_udalosti"]),
               "udalosti_s_alarmom_podiel": (u["s_alarmom_modelu"] / u["vykonanych"]) if u["vykonanych"] else None}
        for trieda, blok in sorted(m["triedy"].items()):
            out["trieda_%s_far_h" % trieda] = _far_h(blok)
        return out
    raise ValueError("nepodporovana schema vysledku: %r" % schema)


def rozptyl(hodnoty):
    """mean, sd (n-1), min, max cez seedy; None hodnoty sa vynechaju a pocitaju."""
    platne = [float(v) for v in hodnoty.values() if v is not None]
    if any(not math.isfinite(v) for v in platne):
        raise ValueError("nekonecna hodnota metriky")
    a = np.asarray(platne)
    return {"n": len(a), "chyba": len(hodnoty) - len(a),
            "priemer": float(a.mean()) if len(a) else None,
            "sd": float(a.std(ddof=1)) if len(a) > 1 else None,
            "min": float(a.min()) if len(a) else None, "max": float(a.max()) if len(a) else None,
            "seedy": {str(s): v for s, v in sorted(hodnoty.items())}}


def suhrn(manifesty, vysledky):
    """Rozptyl cez seedy.

    manifesty: zoznam manifestov balikov (kazdy seed raz, vratane 0, ak ho chces v rozptyle);
    vysledky:  {stitok: [values, ...]} - values z JSON tcn.eval; balik sa
               priradi podla values.balik.manifest_sha256.
    """
    podla_sha, seedy, korpusy = {}, set(), set()
    for m in manifesty:
        s = m["training"]["seed"]
        if s in seedy:
            raise ValueError("seed %s je zadany viackrat" % s)
        seedy.add(s)
        korpusy.add(m["provenance"]["corpus_index_sha256"])
        podla_sha[_manifest_sha(m)] = s
    if len(seedy) < 2:
        raise ValueError("rozptyl potrebuje aspon dva seedy")
    if len(korpusy) != 1:
        raise ValueError("baliky boli trenovane na roznych korpusoch")
    tabulka = {}
    for m in manifesty:
        for meno, v in metriky_balika(m).items():
            tabulka.setdefault("dev." + meno, {})[m["training"]["seed"]] = v
    for stitok, zoznam in sorted(vysledky.items()):
        videne = set()
        for values in zoznam:
            sha = values["balik"]["manifest_sha256"]
            if sha not in podla_sha:
                raise ValueError("vysledok %s patri baliku, ktory nie je v zozname" % stitok)
            s = podla_sha[sha]
            if s in videne:
                raise ValueError("vysledok %s pre seed %s je zadany viackrat" % (stitok, s))
            videne.add(s)
            for meno, v in metriky_vysledku(values).items():
                tabulka.setdefault("%s.%s" % (stitok, meno), {})[s] = v
    return {"schema": SCHEMA_SUHRN, "seedy": sorted(seedy), "finalny_seed": FINALNY_SEED,
            "korpus_sha256": korpusy.pop(),
            "metriky": {k: rozptyl(v) for k, v in sorted(tabulka.items())},
            "poznamka": ("rozptyl cez seedy inicializacie na tom istom korpuse; dev vyberal checkpointy, "
                         "preto nie je drzany bokom; test_benign sa vyhodnocuje iba pre finalny seed 0")}


# ------------------------------------------------------------------ CLI


def _digest(cesta):
    from safeguard.bundle import digest
    return digest(cesta)


def _hlavny(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="python3 -m tcn.seedy", description="Rozptyl TCN cez seedy planu analyzy")
    sub = p.add_subparsers(dest="prikaz", required=True)
    t = sub.add_parser("train", help="safeguard train pre seedy planu do <out-root>/seed-<s>")
    t.add_argument("--corpus", required=True, type=Path)
    t.add_argument("--out-root", required=True, type=Path)
    # Predvolene nezadane (balik B6b): schema 3 berie seedy aj ostatne parametre z planu analyzy protokolu,
    # schemy 1 a 2 dnesne hodnoty (legacy_schema_2; seedy SEEDY).
    t.add_argument("--seeds", type=int, nargs="+", default=None,
                   help="seedy; schema 3: z analysis.seeds, mimo nich iba s --diagnostic; schemy 1 a 2: SEEDY")
    for volba, typ in (("--epochs", int), ("--batch-size", int), ("--fpr", float), ("--k", int), ("--n", int)):
        t.add_argument(volba, type=typ, default=None,
                       help="parameter analyzy; schema 3 ho berie z planu a mimo --diagnostic odmietne")
    t.add_argument("--threads", type=int, default=4)
    t.add_argument("--diagnostic", action="store_true")
    s = sub.add_parser("suhrn", help="mean/sd/min/max dev metrik a vysledkov tcn.eval cez seedy")
    s.add_argument("--bundle", required=True, nargs="+", type=Path, help="adresare balikov (vratane seed 0)")
    s.add_argument("--result", nargs="*", default=[], metavar="STITOK=JSON",
                   help="vysledok tcn.eval (far dev / udalosti / ...), napr. d2=data/results/e3_seed1.json")
    s.add_argument("--out", required=True, type=Path, help="novy JSON; existujuci sa neprepise")
    a = p.parse_args(argv)
    if a.prikaz == "train":
        import torch
        torch.set_num_threads(a.threads)
        protokol = json.loads(a.corpus.read_text())["protocol_config"]
        vysledok = trenuj_seedy(a.corpus, a.out_root, a.seeds, window_rows=protokol["window_rows"],
                                max_gap_s=protokol["max_gap_s"], epochs=a.epochs, batch_size=a.batch_size,
                                fpr=a.fpr, k=a.k, n=a.n, diagnostic=a.diagnostic)
        print(json.dumps({str(k): {"bundle": v["bundle"], "threshold": v["calibration"]["threshold"]}
                          for k, v in vysledok.items()}, indent=2))
        return 0
    manifesty = [json.loads((b / "manifest.json").read_text()) for b in a.bundle]
    vysledky, vstupy = {}, {}
    for polozka in a.result:
        stitok, sep, cesta = polozka.partition("=")
        if not sep or not stitok or not cesta:
            raise SystemExit("--result ocakava STITOK=JSON: %r" % polozka)
        vysledky.setdefault(stitok, []).append(json.loads(Path(cesta).read_text())["values"])
        vstupy[os.path.realpath(cesta)] = _digest(cesta)
    for b in a.bundle:
        vstupy[os.path.realpath(b / "manifest.json")] = _digest(b / "manifest.json")
    values = suhrn(manifesty, vysledky)
    from tcn.eval import _git_stav
    commit, zmeny = _git_stav()
    doc = {"commit": commit, "commit_dirty": None if zmeny is None else bool(zmeny),
           "seedy_sha256": _digest(os.path.abspath(__file__)),
           "date": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
           "command": shlex.join(["python3", "-m", "tcn.seedy", *argv]), "cwd": os.getcwd(),
           "vstupy_sha256": vstupy, "n": len(values["seedy"]), "values": values}
    with open(a.out, "x", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({k: {x: v[x] for x in ("n", "priemer", "sd")} for k, v in values["metriky"].items()},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_hlavny())
