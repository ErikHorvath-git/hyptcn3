"""
seedy.py - rozptyl TCN cez seedy inicializacie (E4/VO6, doplnok k finalnemu modelu).

Finalny model je seed 0 (safeguard train --seed 0) a ten sa tu NEtrenuje
znova. Seedy 1..4 sa trenuju tym istym safeguard.training.train_bundle na tom
istom korpuse a sluzia iba na rozptyl: metriky na dev (vyber checkpointu,
kalibracia) a vysledky na datasetoch 2/3 (tcn.eval udalosti, buduci malver).
test_benign je zaverecny test jedineho finalneho modelu - suhrn vysledky roly
test_benign odmietne.

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
SEEDY = (1, 2, 3, 4)
FINALNY_SEED = 0


def _over_seedy(seedy):
    seedy = list(seedy)
    if not seedy or any(type(s) is not int or s < 0 for s in seedy):
        raise ValueError("seedy musia byt nezaporne cele cisla")
    if len(set(seedy)) != len(seedy):
        raise ValueError("seed je zadany viackrat")
    if FINALNY_SEED in seedy:
        raise ValueError("seed 0 je finalny model; znova sa netrenuje (pouzi existujuci balik)")
    return seedy


def trenuj_seedy(korpus, out_root, seedy=SEEDY, **kwargs):
    """train_bundle pre kazdy seed; existujuci vystup sa nikdy neprepise."""
    from safeguard.training import train_bundle
    seedy = _over_seedy(seedy)
    if "seed" in kwargs:
        raise ValueError("seed sa zadava cez zoznam seedov")
    out_root = Path(out_root)
    ciele = {s: out_root / f"seed-{s}" for s in seedy}
    existuju = [str(c) for c in ciele.values() if c.exists()]
    if existuju:
        raise FileExistsError("vystup existuje: " + ", ".join(existuju))
    vysledky = {}
    for s, ciel in ciele.items():
        vysledky[s] = train_bundle(korpus, ciel, seed=s, **kwargs)
    return vysledky


# ------------------------------------------------------------------ suhrn


def _manifest_sha(manifest):
    from tcn.eval import _manifest_sha as sha
    return sha(manifest)


def metriky_balika(manifest):
    """Dev a kalibracne metriky jedneho balika (vybraty checkpoint)."""
    tr, kal = manifest["training"], manifest["calibration"]
    historia = {h["epoch"]: h for h in tr["history"]}
    pred, klas = historia[tr["selected_predictor_epoch"]], historia[tr["selected_classifier_epoch"]]
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
    p = argparse.ArgumentParser(prog="python3 -m tcn.seedy", description="Rozptyl TCN cez seedy 1..4")
    sub = p.add_subparsers(dest="prikaz", required=True)
    t = sub.add_parser("train", help="safeguard train pre seedy (nie 0) do <out-root>/seed-<s>")
    t.add_argument("--corpus", required=True, type=Path)
    t.add_argument("--out-root", required=True, type=Path)
    t.add_argument("--seeds", type=int, nargs="+", default=list(SEEDY))
    t.add_argument("--epochs", type=int, default=10)
    t.add_argument("--batch-size", type=int, default=32)
    t.add_argument("--fpr", type=float, default=0.01)
    t.add_argument("--k", type=int, default=3)
    t.add_argument("--n", type=int, default=5)
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
