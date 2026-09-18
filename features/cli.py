"""
Prikazovy riadok balika `features`.

Kontrakt (na tento sa spoliehaju ostatne casti prace):

  python3 -m features perbin     --snapshot <cesta> [--sidecar <json>]
                                 [--memslots <json>] [--bin-bytes N] [--json]
  python3 -m features crosscheck --snapshot <cesta> --c <sidecar|adresar>
                                 [--memslots <json>] [--bin-bytes N]
                                 [--out <json>]

--snapshot prijima adresar s retazcom .vmicd alebo jeden .vmicd (plnu snimku).
--memslots je subor s rozsahmi memslotov; bez neho sa skusi sidecar snimky a
ked ani ten rozsahy nema, prikaz skonci chybou. NEHADA sa - vypln namiesto
memslotov by dala vektor, ktory vyzera spravne a nie je (viz perbin.py).

NAVRATOVE KODY:

  0  prebehlo a nic sa nerozislo
  1  nezhoda: bud padol invariant proti sidecaru, alebo sa C a referencia
     lisia. PRECO nie 0: krizova kontrola sa da zaradit do skriptu a
     "vektory sa lisia" sa nesmie stratit v uspesnom kode
  2  chyba: snimka, memsloty alebo vystup C sa nedaju precitat
"""

import argparse
import datetime
import json
import os
import subprocess
import sys

from . import crosscheck as cc
from .perbin import (DEFAULT_BIN_BYTES, FeatureError, check_against_sidecar,
                     load_memslots, per_bin, sidecar_for, _chain_parts)

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_ERROR = 2

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_size(text):
    """'16777216', '16MiB', '16M', '4K' -> bajty."""
    t = str(text).strip().lower().replace("ib", "")
    mult = 1
    if t.endswith("k"):
        mult, t = 1024, t[:-1]
    elif t.endswith("m"):
        mult, t = 1024 * 1024, t[:-1]
    elif t.endswith("g"):
        mult, t = 1024 * 1024 * 1024, t[:-1]
    return int(t, 0) * mult


def _memslots(args, snapshot):
    """
    Zdroj rozsahov memslotov. Poradie: --memslots, potom sidecar snimky.
    Ked ani jeden rozsahy nema, je to chyba s vysvetlenim, nie odhad.
    """
    if args.memslots:
        return load_memslots(args.memslots)
    side = args.sidecar or sidecar_for(snapshot)
    if side:
        try:
            return load_memslots(side)
        except FeatureError as exc:
            raise FeatureError(
                "%s\n\nSidecar snimky rozsahy memslotov dnes neobsahuje "
                "(capture.regions je konfiguracia zberu a pri zbere celej "
                "RAM je prazdna). Zadaj --memslots s vystupom "
                "'vmicollect probe -v' (data/results/probe_*.json)." % exc)
    raise FeatureError(
        "snimka nema vedla seba sidecar .json a --memslots nebolo zadane; "
        "bez rozsahov memslotov sa vektor pocitat neda")


def _stamp(values, command, n):
    """Hlavicka podla HONESTY.md kap. 4 - nic sa v nej nevymysla."""
    try:
        commit = subprocess.check_output(
            ["git", "-C", REPO, "rev-parse", "HEAD"], text=True).strip()
        dirty = bool(subprocess.check_output(
            ["git", "-C", REPO, "status", "--porcelain"], text=True).strip())
    except Exception:
        commit, dirty = None, None
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "schema": "hyptcn3/vysledok-hlavicka/1",
        "schema_dat": "hyptcn3/perbin-crosscheck/1",
        "commit": commit,
        "commit_dirty": dirty,
        "date": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": ("Fedora Linux 43, jadro 7.1.13-100.fc43.x86_64, "
                 "hostname fedora"),
        "guest": ("snimky pamate libvirt domeny hyptcn-guest (Debian 12, "
                  "jadro 6.1.0-42-cloud-amd64). Domena pri vypocte nebezala "
                  "- pocitalo sa zo suborov so snimkami."),
        "command": command,
        "n": n,
        "n_poznamka": ("n = pocet snimok, nad ktorymi krizova kontrola "
                       "bezala. Nejde o opakovane meranie casu, cisla nemaju "
                       "rozptyl."),
        "values": values,
    }


# ------------------------------------------------------------------ perbin


def cmd_perbin(args):
    slots = _memslots(args, args.snapshot)
    res = per_bin(args.snapshot, slots, bin_bytes=args.bin_bytes,
                  until_seq=args.until_seq)
    side = args.sidecar or sidecar_for(args.snapshot, until_seq=args.until_seq)
    if side:
        res["kontrola"]["proti_sidecaru"] = check_against_sidecar(res, side)

    if args.json:
        json.dump(res, sys.stdout, indent=1, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        _print_perbin(res)

    proti = res["kontrola"].get("proti_sidecaru")
    if proti and proti.get("zhoda") is False:
        return EXIT_MISMATCH
    return EXIT_OK


def _print_perbin(res):
    f = res["features"]
    s = res["snapshot"]
    m = res["memslots"]
    k = res["kontrola"]
    print("snimka          : %s (seq %d, %s)"
          % (", ".join(s["parts"]), s["seq"],
             "plna" if s["full"] else "delta"))
    print("memsloty        : %d rozsahov, %d podlozenych stranok (%s)"
          % (m["count"], m["pages_total"], m["source"]))
    print("velkost binu    : %d B" % f["bin_bytes"])
    print("binov           : %d" % f["bins_total"])
    print()
    print("%6s %14s %8s %9s %9s %9s %9s %3s"
          % ("bin", "gpa", "total", "changed", "chg_r", "zero_r", "H_mean",
             "has"))
    for row in f["bins"]:
        print("%6d %14d %8d %9d %9.6f %9.6f %9.6f %3d"
              % (row["bin"], row["gpa"], row["pages_total"],
                 row["pages_changed"], row["changed_ratio"],
                 row["zero_ratio"], row["entropy_mean"], row["has_changed"]))
    print()
    print("sucet pages_changed : %d" % k["pages_changed_sucet"])
    print("sucet pages_total   : %d" % k["pages_total_sucet"])
    if k["stranok_mimo_memslotov_v_stave"]:
        print("POZOR: %d stranok stavu lezi mimo memslotov (priklady: %s)"
              % (k["stranok_mimo_memslotov_v_stave"],
                 k["priklady_stranok_mimo"]))
    proti = k.get("proti_sidecaru")
    if proti and proti.get("zhoda") is None:
        print("proti sidecaru %s: neoverene - %s"
              % (proti["sidecar"], proti.get("pozn")))
    elif proti:
        print("proti sidecaru %s: pages_changed %d/%d %s, "
              "pages_total %d/%d %s"
              % (proti["sidecar"],
                 proti["pages_changed_referencia"],
                 proti["pages_changed_sidecar"],
                 "OK" if proti["pages_changed_zhoda"] else "NEZHODA",
                 proti["pages_total_referencia"],
                 proti["pages_total_sidecar"],
                 "OK" if proti["pages_total_zhoda"] else "NEZHODA"))


# -------------------------------------------------------------- crosscheck


def _c_features_for(cpath, snap_id):
    """
    Najde blok features z C pre snimku s danym id.

    cpath je bud konkretny subor, alebo adresar - vtedy sa hlada
    '<id>.json'. Ked sa nenajde, vrati (None, dovod) - chybajuci vystup C
    nie je chyba behu, je to stav, ktory sa ma zapisat do reportu.
    """
    if cpath is None:
        return None, None, "vystup C nebol zadany"
    if os.path.isdir(cpath):
        cand = os.path.join(cpath, "%s.json" % snap_id)
        if not os.path.exists(cand):
            return None, None, ("v '%s' nie je '%s.json'" % (cpath, snap_id))
        cpath = cand
    try:
        block, src = cc.load_c_features(cpath)
    except (ValueError, OSError) as exc:
        return None, None, str(exc)
    return block, src, None


def cmd_crosscheck(args):
    slots = _memslots(args, args.snapshot)
    heads = _chain_parts(args.snapshot)
    snimky = []
    rc = EXIT_OK

    for h in heads:
        sid = os.path.basename(h["path"])[:-len(".vmicd")]
        res = per_bin(args.snapshot, slots, bin_bytes=args.bin_bytes,
                      until_seq=h["seq"])
        side = sidecar_for(args.snapshot, until_seq=h["seq"])
        zaznam = {
            "snapshot": sid,
            "seq": h["seq"],
            "full": h["full"],
            "bins_total": res["features"]["bins_total"],
            "invariant": None,
            "porovnanie": None,
            "c_vystup": None,
        }
        if side:
            inv = check_against_sidecar(res, side)
            zaznam["invariant"] = inv
            if inv.get("zhoda") is False:
                rc = EXIT_MISMATCH
        else:
            zaznam["invariant"] = {
                "zhoda": None,
                "pozn": "snimka nema vedla seba sidecar, invariant sa nedal "
                        "overit",
            }

        block, src, dovod = _c_features_for(args.c, sid)
        if block is None:
            zaznam["c_vystup"] = {"dostupny": False, "dovod": dovod}
        else:
            zaznam["c_vystup"] = {"dostupny": True, "zdroj": src}
            por = cc.compare(res["features"], block, tol=args.tolerancia)
            zaznam["porovnanie"] = por
            if not por["zhoda"]:
                rc = EXIT_MISMATCH

        if args.ulozit_vektory:
            zaznam["vektor_referencia"] = res["features"]
        snimky.append(zaznam)

    hotove = [z for z in snimky if z["c_vystup"]["dostupny"]]
    values = {
        "schema": "hyptcn3/perbin-crosscheck/1",
        "pripad": args.label,
        "bin_bytes": args.bin_bytes,
        "snapshot_arg": os.path.abspath(args.snapshot),
        "c_arg": os.path.abspath(args.c) if args.c else None,
        "memslots": slots.as_json(),
        "snimok": len(snimky),
        "snimok_s_vystupom_c": len(hotove),
        "vsetky_invarianty_ok": all(
            z["invariant"].get("zhoda") is True for z in snimky),
        # Ked sa neporovnavalo nic, nie je to ani "ok" ani "nie ok" - je to
        # neurcene. False by sa citalo ako "nasla sa nezhoda".
        "vsetky_porovnania_ok": (all(z["porovnanie"]["zhoda"] for z in hotove)
                                 if hotove else None),
        "snimky": snimky,
    }
    if not hotove:
        dovody = sorted({z["c_vystup"]["dovod"] for z in snimky
                         if z["c_vystup"].get("dovod")})
        values["poznamka"] = (
            "Per-bin vektor z C modulu sa k tymto snimkam nenasiel, "
            "porovnanie sa teda NEROBILO - overene boli iba invarianty "
            "referencie proti sidecarom zberaca. Dovod pri prvej snimke: %s"
            % (dovody[0] if dovody else "neuvedeny"))

    doc = _stamp(values, " ".join([sys.executable, "-m", "features"] +
                                  sys.argv[1:]), len(snimky))
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        print("zapisane: %s" % args.out)
    else:
        json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
        sys.stdout.write("\n")

    _print_crosscheck(values)
    return rc


def _print_crosscheck(values):
    print()
    for z in values["snimky"]:
        inv = z["invariant"]
        stav = {True: "OK", False: "NEZHODA", None: "neoverene"}[
            inv.get("zhoda")]
        print("seq %d %-52s invariant %s, binov %d"
              % (z["seq"], z["snapshot"], stav, z["bins_total"]))
        if inv.get("zhoda") is False:
            print("    pages_changed referencia %s, sidecar %s"
                  % (inv["pages_changed_referencia"],
                     inv["pages_changed_sidecar"]))
            print("    pages_total   referencia %s, sidecar %s"
                  % (inv["pages_total_referencia"],
                     inv["pages_total_sidecar"]))
        if not z["c_vystup"]["dostupny"]:
            print("    C: %s" % z["c_vystup"]["dovod"])
            continue
        por = z["porovnanie"]
        if por["zhoda"]:
            print("    C vs referencia: zhoda (%d binov, najvacsi rozdiel %s)"
                  % (por["binov_c"], por["max_abs_rozdiel"]))
            print("    poli mimo tlacenej presnosti C: %d"
                  % por["mimo_tlacenej_presnosti"])
        else:
            print("    C vs referencia: %d rozdielov" % por["rozdielov"])
            for d in por["rozdiely"][:20]:
                print("      bin %s %-14s referencia=%s C=%s rozdiel=%s"
                      % (d["bin"], d["pole"], d["referencia"], d["c"],
                         d["rozdiel"]))
            if por["rozdielov"] > 20:
                print("      ... a dalsich %d" % (por["rozdielov"] - 20))
            if por["biny_iba_v_referencii"]:
                print("      biny iba v referencii: %s"
                      % por["biny_iba_v_referencii"])
            if por["biny_iba_v_c"]:
                print("      biny iba v C: %s" % por["biny_iba_v_c"])


# ------------------------------------------------------------------- main


def build_parser():
    ap = argparse.ArgumentParser(
        prog="python3 -m features",
        description="per-bin priznakovy vektor (referencia) a krizova "
                    "kontrola proti C modulu")
    sub = ap.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--snapshot", required=True,
                        help="adresar s retazcom .vmicd alebo jeden .vmicd")
        sp.add_argument("--memslots", default=None,
                        help="JSON s rozsahmi memslotov (napr. vystup "
                             "'vmicollect probe -v')")
        sp.add_argument("--bin-bytes", default=DEFAULT_BIN_BYTES,
                        type=parse_size, dest="bin_bytes",
                        help="velkost binu v bajtoch, mocnina dvojky "
                             "(vychodzie 16MiB)")

    p = sub.add_parser("perbin", help="spocitaj vektor jednej snimky")
    common(p)
    p.add_argument("--sidecar", default=None,
                   help="sidecar .json snimky (vychodzie: vedla .vmicd)")
    p.add_argument("--until-seq", default=None, type=int, dest="until_seq",
                   help="stav po tejto casti retazca (vychodzie: posledna)")
    p.add_argument("--json", action="store_true", help="cisty JSON na stdout")
    p.set_defaults(func=cmd_perbin)

    p = sub.add_parser("crosscheck",
                       help="porovnaj referenciu s vektorom z C modulu")
    common(p)
    p.add_argument("--c", default=None,
                   help="sidecar z C modulu, alebo adresar s nimi "
                        "(hlada sa <id snimky>.json)")
    p.add_argument("--out", default=None, help="kam zapisat vysledok")
    p.add_argument("--label", default=None,
                   help="nazov pripadu (zapise sa do vysledku ako 'pripad')")
    p.add_argument("--tolerancia", default=cc.DEFAULT_TOL, type=float,
                   help="tolerancia pre desatinne polia (vychodzie 5e-7)")
    p.add_argument("--ulozit-vektory", action="store_true",
                   dest="ulozit_vektory",
                   help="zapisat do vysledku aj cely vektor referencie")
    p.set_defaults(func=cmd_crosscheck)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except FeatureError as exc:
        print("chyba: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except (ValueError, OSError) as exc:
        print("chyba: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
