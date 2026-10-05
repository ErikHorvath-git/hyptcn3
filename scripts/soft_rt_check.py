#!/usr/bin/env python3
"""
soft_rt_check.py - blok H: dokaz soft real-time z artefaktov, nie zo slov.

Overuje nad sidecarmi zberaca a (volitelne) nad JSONom z tcn.score:

  1. seq su suvisle (ziadna snimka nezahodena);
  2. sched.skipped_before == 0 pre kazdu snimku (0 zmeskanych slotov);
  3. total_ms kazdej snimky < perioda (latencia cyklu vnutri slotu);
  4. latencia snímka -> skóre (z tcn.score, latencia_od_snimky_ms)
     p95 < perioda (soft real-time: spracovanie stíha, kym prichadza
     dalsia snimka).

Vystup: JSON s verdiktom a cislami - falzifikovatelne kriteria, nie
tvrdenie. Pouzitie:
  soft_rt_check.py --snapshots <dir> [--score score.json] [--perioda 5]
"""

import argparse
import json
import os
import sys


def sidecary(adresar):
    out = []
    for meno in sorted(os.listdir(adresar)):
        if not meno.endswith(".json"):
            continue
        try:
            doc = json.load(open(os.path.join(adresar, meno),
                                 encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if "seq" not in doc:
            continue
        out.append(doc)
    out.sort(key=lambda d: d["seq"])
    return out


def _najvacsi_retazec(sides):
    """Jeden beh moze v adresari zanechat viac retazcov (selftest); kontroluje
    sa najvacsi a ostatne sa priznaju, nie ticho zmiesaju. Delta retazec sa
    pozna podla chain_id; raw behy (chain_id 0) sa zdruzuju podla casovej
    peciatky v mene snimky."""
    import re
    groups = {}
    for d in sides:
        cid = (d.get("output") or {}).get("chain_id")
        if cid:
            key = "chain-%s" % cid
        else:
            key = "raw-" + re.sub(r"_\d{6}_", "_", d.get("id", "?"))
        groups.setdefault(key, []).append(d)
    best = max(groups.values(), key=len)
    return best, groups


def _skontroluj_retazec(sides, perioda_s, score_doc=None):
    """Kontrola JEDNEHO retazca; vracia dict s chybami a cislami."""
    chyby = []
    seqy = [d["seq"] for d in sides]
    if not seqy:
        chyby.append("ziadne sidecary")
    elif seqy != list(range(seqy[0], seqy[-1] + 1)):
        chyby.append("seq nie su suvisle")

    skipped = [d.get("sched", {}).get("skipped_before", 0) for d in sides]
    max_skip = max(skipped) if skipped else None
    if max_skip:
        chyby.append("zmeskanych slotov: max %d" % max_skip)

    total = [d.get("capture", {}).get("total_ms") for d in sides]
    chyba_cas = any(t is None for t in total)
    total = [t for t in total if t is not None]
    if chyba_cas:
        chyby.append("sidecary nemaju casy (capture.total_ms) - bez nich "
                     "sa soft real-time NEDA preukazat")
    nad = [t for t in total if t > perioda_s * 1000.0]
    if nad:
        chyby.append("cyklus nad periodou: %d z %d (max %.1f ms)"
                     % (len(nad), len(total), max(nad)))

    lat = None
    if score_doc:
        z = [r for r in score_doc.get("zaznamy", [])
             if r.get("latencia_od_snimky_ms") is not None]
        l = sorted(r["latencia_od_snimky_ms"] for r in z)
        if l:
            p95 = l[min(len(l) - 1, -(-95 * len(l) // 100) - 1)]
            med = l[len(l) // 2] if len(l) % 2 else (l[len(l) // 2 - 1]
                                                     + l[len(l) // 2]) / 2
            lat = {"n": len(l), "median_ms": round(med, 3),
                   "p95_ms": round(p95, 3)}
            if p95 > perioda_s * 1000.0:
                chyby.append("p95 latencie snímka->skóre %.1f ms > perioda "
                             "%.1f s" % (p95, perioda_s))
        else:
            chyby.append("score JSON nema latencie (latencia_od_snimky_ms) "
                         "- bez nich sa cas snímka->skóre NEDA preukazat")
    elif "latencia_skore" not in ("",):
        pass

    return {
        "perioda_s": float(perioda_s),
        "snimok": len(sides),
        "max_skipped_before": max_skip,
        "cyklov_nad_periodou": len(nad) if total else None,
        "cyklov_celkom": len(total),
        "latencia_skore": lat,
        "verdict": "OK" if not chyby else "NEUSPECH",
        "chyby": chyby,
    }


def skontroluj(sides, perioda_s, score_doc=None):
    """Kontroluju sa VSETKY retazce v adresari, nie len najvacsi -
    inak by zmeskane sloty v malom retazci (napr. po restarte) presli."""
    groups = _najvacsi_retazec(sides)[1]
    retazec_chyby = {}
    chyby = []
    for key, r in sorted(groups.items()):
        r2 = _skontroluj_retazec(r, perioda_s, score_doc)
        if r2["chyby"]:
            retazec_chyby[key] = r2["chyby"]
            chyby.append("retazec %s: %s" % (key[:24],
                                             "; ".join(r2["chyby"])))
    najvacsi = max(groups.values(), key=len)
    res = _skontroluj_retazec(najvacsi, perioda_s, score_doc)
    res["schema"] = "hyptcn3/soft-rt/1"
    res["retazcov_v_adresari"] = len(groups)
    res["retazce_s_chybami"] = retazec_chyby
    res["verdict"] = "OK" if not chyby else "NEUSPECH"
    res["chyby"] = chyby
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="dokaz soft real-time z artefaktov")
    ap.add_argument("--snapshots", required=True)
    ap.add_argument("--score", default=None,
                    help="JSON z 'python3 -m tcn.score --json'")
    ap.add_argument("--perioda", type=float, default=5.0)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    sides = sidecary(a.snapshots)
    score_doc = None
    if a.score:
        score_doc = json.load(open(a.score, encoding="utf-8"))
    res = skontroluj(sides, a.perioda, score_doc)
    json.dump(res, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
    return 0 if res["verdict"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
