"""
Prikazovy riadok balika.

Kontrakt (na tento sa spoliehaju ostatne casti prace, nemeni sa):

  python3 -m guestparse ps       --snapshot <cesta> --profile <adresar> [--json]
  python3 -m guestparse lsmod    --snapshot <cesta> --profile <adresar> [--json]
  python3 -m guestparse ss       --snapshot <cesta> --profile <adresar> [--json]
  python3 -m guestparse info     --snapshot <cesta> --profile <adresar> [--json]
  python3 -m guestparse checks   --snapshot <cesta> --profile <adresar> [--json]
  python3 -m guestparse procmap  --snapshot <retazec> --profile <adresar>
        [--bin N] [--bin-bytes B]   # zmenene stranky binov -> procesy (A4)
  python3 -m guestparse textbaseline --snapshot <cista_snimka> --profile <adresar>
        [--force]          # baseline textu jadra pre kontrolu (d) do profilu
  python3 -m guestparse validate --snapshot <cesta> --profile <adresar> \
        --ps-before F --ps-after F [--lsmod F] [--ss F] --out results.json

--snapshot prijima adresar s retazcom .vmicd, jeden .vmicd alebo raw obraz.
--profile je adresar s kallsyms.txt a btf.txt.

Bez --json sa tlaci citatelna tabulka, s --json ide na stdout iba JSON, aby sa
vystup dal rurou posunut dalej. Varovania (neuplny zoznam) idu na stderr.

Podprikazy `checks` a `validate` implementuju moduly guestparse.checks a
guestparse.validate. Ocakavana vstupna funkcia:
    run(args, view) -> dict        # vysledok, ktory sa vytlaci ako JSON
Kym modul neexistuje, podprikaz skonci navratovym kodom 3 a hlaskou, nie stopou.

NAVRATOVE KODY:

  0  vsetko prebehlo a nic sa nenaslo
  1  kontrola nieco nasla (`checks`). PRECO nie 0: prikaz sa da zaradit do
     skriptu a "nasiel som hook" sa nesmie stratit v uspesnom kode
  2  chyba: snimka sa neda otvorit (aj rozbity retazec .vmicd), profil sa neda
     nacitat, posun jadra sa nenasiel
  3  podprikaz nie je implementovany (chyba modul balika)
  4  `checks`: nic sa nenaslo, ALE aspon jedna kontrola sa neuzavrela
     (summary.inconclusive nie je prazdny). Nula z neuzavretej kontroly nie
     je dokaz cistoty, preto sa nesmie hlasit ako 0. Ked su nalezy aj
     neuzavrete kontroly naraz, vyhrava kod 1 - nalez je silnejsia sprava.
  5  NESULAD PROFILU: kallsyms v profile je z ineho startu jadra (KASLR), nez
     je snimka - typicky preto, ze hosta medzitym niekto restartoval a profil
     v repe je z predchadzajuceho bootu. Diagnozu stanovi
     GuestView.profile_boot_mismatch(): symbol sa linearne precitat DA, ale
     prechod tabuliek stranok pre jeho VA konci na nepritomnej polozke.
     Od bloku A2 sa nesulad najprv SKUSA preukotvit (GuestView.reanchor():
     posun zmerany z tabuliek stranok, dvojita kotva init_task+linux_banner);
     az ked preukotvenie NEJDE (FGKASLR, chybajuce stranky), plati kod 5.
     PRECO VLASTNY KOD a preco nie 4: nie je to neuzavreta kontrola ("neviem"),
     je to CHYBA VSTUPU - nastroju sa dal profil, ktory k snimke nepatri.
     Preto prebija aj nalez (1), aj neuzavretost (4): nalez zo zleho profilu
     nalezom nie je. Plati pre vsetky podprikazy: pri citacich (`info`, `ps`,
     `lsmod`, `ss`, `checks`) sa vysledok aj tak vypise (je oznaceny ako
     NEUPLNY) a diagnoza ide na stderr; `validate` sa nespusti vobec, lebo
     by po sebe nechal subor v data/results.
"""

import argparse
import json
import os
import sys

from . import checks
from .view import build_view

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_NOT_IMPLEMENTED = 3
EXIT_INCONCLUSIVE = 4
EXIT_PROFILE_MISMATCH = 5


def _add_common(sp):
    sp.add_argument("--snapshot", required=True,
                    help="adresar s retazcom .vmicd, subor .vmicd alebo raw obraz")
    sp.add_argument("--profile", required=True,
                    help="adresar s kallsyms.txt a btf.txt")
    sp.add_argument("--json", action="store_true", help="cisty JSON na stdout")
    sp.add_argument("--banner", default=None,
                    help="retazec banneru na hladanie posunu "
                         "(vychodzie: 'Linux version ')")
    sp.add_argument("--chain-until", type=int, default=None, metavar="SEQ",
                    dest="chain_until",
                    help="pouzi retazec .vmicd iba po danu cast (seq); "
                         "rovnaky vyznam ako 'vmicollect restore --until'")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="python3 -m guestparse",
        description="Rekonstrukcia objektov hosta z pamatovej snimky "
                    "(procesy, moduly, sokety).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, helptext in (
            ("ps", "zoznam procesov z init_task.tasks"),
            ("lsmod", "zoznam nacitanych modulov"),
            ("ss", "sietove spojenia (IPv4 aj IPv6)"),
            ("info", "profil, posun jadra a krizova kontrola prekladu adries"),
            ("checks", "kontroly podozrivych vzorcov"),
    ):
        sp = sub.add_parser(name, help=helptext)
        _add_common(sp)

    sp = sub.add_parser("validate", help="porovnanie s pozemnou pravdou z hosta")
    _add_common(sp)
    sp.add_argument("--ps-before", required=True)
    sp.add_argument("--ps-after", required=True)
    sp.add_argument("--lsmod")
    sp.add_argument("--ss")
    sp.add_argument("--out", required=True)

    sp = sub.add_parser("textbaseline",
                        help="baseline textu jadra (kontrola (d); zapise "
                             "text_baseline.json do profilu). Bez --vmlinux "
                             "ide o baseline z cistej snimky, s --vmlinux "
                             "z linkovaneho obrazu (silnejsia, boot-"
                             "independent).")
    _add_common(sp)
    sp.add_argument("--force", action="store_true",
                    help="prepis existujucu baseline")
    sp.add_argument("--vmlinux", default=None,
                    help="cesta k vmlinux (default: data/raw/profile-assets/"
                         "vmlinux-<release> podla profilu)")

    sp = sub.add_parser("procmap",
                        help="ktoremu procesu patria zmenene stranky binov "
                             "(A4)")
    _add_common(sp)
    sp.add_argument("--bin", type=int, action="append", default=None,
                    metavar="INDEX",
                    help="obmedz na index binu (da sa opakovat); bez = "
                         "vsetky biny so zmenou")
    sp.add_argument("--bin-bytes", type=int, default=16 * 1024 * 1024,
                    dest="bin_bytes",
                    help="velkost binu v bajtoch (vychodzie 16777216)")
    return ap


# ------------------------------------------------------------- tabulky


def _warn(res):
    if res.get("truncated"):
        sys.stderr.write("upozornenie: prechod zoznamu sa prerusil (%s); "
                         "vysledok je dolna hranica\n"
                         % (res.get("stop_reason") or "bez dovodu"))


def _print_ps(res):
    print("%6s %6s %-18s %s" % ("PID", "TGID", "COMM", "TYP"))
    for p in res["processes"]:
        print("%6d %6s %-18s %s" % (
            p["pid"],
            "-" if p["tgid"] is None else p["tgid"],
            p["comm"],
            "jadro" if p["kernel_thread"] else "pouzivatel"))
    print("spolu: %d procesov%s" % (res["count"],
                                    ", NEUPLNE" if res["truncated"] else ""))


def _print_lsmod(res):
    print("%-28s %s" % ("MODUL", "ADRESA"))
    for m in res["modules"]:
        print("%-28s 0x%x" % (m["name"], m["module_va"]))
    print("spolu: %d modulov%s" % (res["count"],
                                   ", NEUPLNE" if res["truncated"] else ""))


def _endpoint(addr, port, family):
    # IPv6 adresa sa v zapise s portom uzatvara do hranatych zatvoriek
    return "[%s]:%d" % (addr, port) if family == "IPv6" else "%s:%d" % (addr, port)


def _print_ss(res):
    print("%-5s %-5s %-12s %-30s %-30s %s"
          % ("PROTO", "RODIN", "STAV", "LOKALNA", "VZDIALENA", "PID/PROGRAM"))
    for s in res["sockets"]:
        print("%-5s %-5s %-12s %-30s %-30s %d/%s" % (
            s["proto"],
            "v6" if s["family"] == "IPv6" else "v4",
            s["state"],
            _endpoint(s["saddr"], s["sport"], s["family"]),
            _endpoint(s["daddr"], s["dport"], s["family"]),
            s["pid"], s["comm"]))
    print("spolu: %d socketov%s" % (res["count"],
                                    ", NEUPLNE" if res["truncated"] else ""))


def _print_info(res):
    im, pr = res["image"], res["profile"]
    print("snimka:        %s (%d stranok po %d B)"
          % (im["kind"], im["pages_present"], im["page_size"]))
    for f in im["files"]:
        print("               %s" % f)
    ch = im.get("chain")
    if ch:
        print("retazec:       chain_id %s, casti %d, seq %s..%s, baseline %s, "
              "overeny %s"
              % (ch["chain_id"], ch["parts"], ch["seq_from"], ch["seq_to"],
                 "ano" if ch["full_baseline"] else "NIE",
                 "ano" if ch["validated"] else "NIE"))
    print("profil:        %d symbolov, struktury: %s"
          % (pr["symbols"], ", ".join(pr["structs"])))
    print("               %s" % pr["kallsyms"])
    print("               %s" % pr["btf"])
    if pr.get("boot_id"):
        print("profil z bootu %s, odobraty %s"
              % (pr["boot_id"], pr.get("captured") or "bez datumu"))
        print("               porovnaj s hostom: "
              "cat /proc/sys/kernel/random/boot_id")
    else:
        print("profil z bootu ? (profil nema boot.json - obnov ho cez "
              "scripts/get_profile.sh)")
    if not res["resolved"]:
        print("posun jadra:   NENAJDENY - %s" % res["resolve_problem"])
        return
    print("banner:        %s" % res["banner"])
    print("banner PA:     0x%x (kandidat %d)"
          % (res["banner_pa"], res["banner_candidates"]))
    shift = res["ktext_shift"]
    print("posun jadra:   %s0x%x" % ("-" if shift < 0 else "", abs(shift)))
    if res.get("reanchored"):
        print("preukotvenie:  %+d - profil bol z ineho bootu (KASLR), "
              "adresy su posunute" % res["reanchored"])
    pob = res["page_offset_base"]
    print("page_offset:   %s" % ("0x%x" % pob if pob else "?"))
    print("krizova kontrola prekladu (linearne vs. tabulky stranok):")
    for r in res["translation_check"]:
        print("  %-14s 0x%-12x %s 0x%-12x %s"
              % (r["symbol"],
                 r["linear_pa"] or 0,
                 "==" if r["match"] else "!=",
                 r["walk_pa"] or 0,
                 "zhoda" if r["match"] else "NEZHODA"))
        if not r["match"] and r["walk_reason"]:
            print("  %-14s prechod skoncil na %s: %s"
                  % ("", r["walk_level"] or "?", r["walk_reason"]))
    if res.get("profile_mismatch"):
        print(res["profile_mismatch"])


def _print_checks(res):
    s = res["summary"]
    for t in res["syscall_tables"]:
        if not t["available"]:
            print("%-22s NEDOSTUPNA (%s)" % (t["name"], t["reason"]))
            continue
        print("%-22s %d poloziek v [0x%x, 0x%x), nalezov: %d"
              % (t["name"], t["entries"], t["text_range"][0],
                 t["text_range"][1], len(t["findings"])))
    p = res["process_cross_view"]
    if p["available"]:
        print("%-22s tasks %d vs. children/sibling %d, nalezov: %d"
              % ("procesy krizovo", p["list_count"], p["tree_count"],
                 len(p["findings"])))
    else:
        print("%-22s NEDOSTUPNA (%s)" % ("procesy krizovo", p["reason"]))
    m = res["modules"]
    if m.get("sysfs_available"):
        print("%-22s modules %d vs. module_kset %d (z %d kobjektov), nalezov: %d"
              % ("moduly krizovo", m["list_count"], m["sysfs_count"],
                 m["sysfs_kset_entries"], len(m["findings"])))
    else:
        print("%-22s len meno a adresa, nalezov: %d (%s)"
              % ("moduly krizovo", len(m["findings"]), m.get("reason")))
    t = res.get("text_integrity")
    if t:
        if t["available"]:
            print("%-22s %d/%d stranok precitanych, nalezov: %d%s"
                  % ("text jadra", t["pages_checked"], t["pages_total"],
                     len(t["findings"]),
                     "" if t["conclusive"] else " (NEUZAVRETA)"))
        else:
            print("%-22s NEDOSTUPNA (%s)" % ("text jadra", t["reason"]))
    if s["inconclusive"]:
        print("NEUZAVRETE kontroly: %s - ich nulovy vysledok nic nedokazuje "
              "(preto navratovy kod %d, nie 0)"
              % (", ".join(s["inconclusive"]), EXIT_INCONCLUSIVE))
    print("nalezov spolu: %d (z toho hookov v tabulke volani: %d)"
          % (res["finding_count"], s["syscall_hooks"]))
    for f in res["findings"]:
        print("  %s" % f)


def _print_procmap(res):
    print("bin   gpa_od          zmenenych   jadro   procesy (top 5)")
    for b in sorted(res["bins"]):
        row = res["bins"][b]
        proc = ", ".join("%d/%s:%d" % (p["pid"], p["comm"], p["stranky"])
                         for p in row["procesy"][:5])
        print("%4d  0x%-12x %9d %7d   %s"
              % (b, row["gpa_od"], row["zmenenych_stranok"],
                 row["jadro_stranky"], proc))
    print("mapovane_stranky=%d, capped=%s, cas=%.2f s (%s)"
          % (res["mapovane_stranky"], res["capped"], res["cas_s"],
             res["sposob"]))


def _print_validate(res):
    p = res["processes"]
    print("procesy: ps pred %d, ps po %d, stabilnych %d (z toho %d s doslovne "
          "rovnakym menom), zo snimky %d"
          % (p["ps_before"], p["ps_after"], p["stable"],
             p["stable_name_identical"], p["snapshot"]))
    print("         najdenych %d/%d, chybajucich %d, falosnych %d, "
          "nezhoda mien %d"
          % (p["found"], p["stable"], p["missing"], p["false_positive"],
             p["name_mismatch"]))
    print("         pravidla zhody mien: %s" % p["name_match_rules"])
    m, s = res["modules"], res["sockets"]
    if m.get("compared") is False:
        print("moduly:  neporovnane (%s), zo snimky %d" % (m["reason"],
                                                           m["snapshot"]))
    else:
        print("moduly:  sediacich %d, chybajucich %d, navyse %d"
              % (m["matched"], m["missing"], m["extra"]))
    if s.get("compared") is False:
        print("sokety:  neporovnane (%s), zo snimky %d" % (s["reason"],
                                                           s["snapshot"]))
    else:
        print("sokety:  sediacich %d, chybajucich %d, navyse %d "
              "(ine protokoly zo snimky: %s)"
              % (s["matched"], s["missing"], s["extra"],
                 s["snapshot_other_protocols"] or "ziadne"))
    print("kontroly: %s" % res["checks"])


# ------------------------------------------------------------- beh


def checks_exit_code(res):
    """
    Navratovy kod podprikazu `checks` z jeho vysledku.

    Poradie sprav: nalez (1) je silnejsi nez neuzavreta kontrola (4), a nula
    sa smie vratit iba vtedy, ked sa VSETKY kontroly uzavreli. Inak by sa
    "neviem" nedalo v skripte odlisit od "ciste".
    """
    if res["finding_count"]:
        return EXIT_FINDINGS
    return (EXIT_INCONCLUSIVE if res["summary"]["inconclusive"] else EXIT_OK)


def _external(modname, args, view):
    """Podprikaz, ktory implementuje samostatny modul balika."""
    try:
        mod = __import__("guestparse.%s" % modname, fromlist=["run"])
    except ImportError:
        sys.stderr.write(
            "podprikaz '%s' zatial nie je implementovany "
            "(chyba modul guestparse/%s.py)\n" % (modname, modname))
        return None
    return mod.run(args, view)


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        view, img = build_view(args.snapshot, args.profile, args.banner,
                               until_seq=args.chain_until)
    except Exception as exc:
        sys.stderr.write("chyba: %s\n" % exc)
        return EXIT_ERROR

    try:
        # Nesulad profilu s bootom snimky sa zistuje raz, pred vykonom prikazu:
        # tyka sa vsetkeho, co z profilu cita adresy, nie iba `info`.
        mismatch = view.profile_boot_mismatch()

        # A2: namiesto padu s kodom 5 sa profil skusi preukotvit na boot
        # snimky. Uspech = pokracuje sa s preukotvenym profilom; neuspech
        # (napr. FGKASLR) = doterajsie spravanie, kod 5.
        if mismatch:
            ok, why = view.reanchor()
            if ok:
                sys.stderr.write(
                    "POZOR: profil bol z ineho bootu (KASLR); preukotvenie "
                    "o %+d uspelo - pokracujem s preukotvenym profilom\n"
                    % why["delta"])
                mismatch = view.profile_boot_mismatch()
            else:
                sys.stderr.write("POZOR: preukotvenie neprebehlo: %s\n" % why)

        def final(rc):
            """Chyba vstupu prebija kazdy iny kod - viz navratove kody vyssie."""
            return EXIT_PROFILE_MISMATCH if mismatch else rc

        if args.cmd == "info":
            res = view.info()
            if args.json:
                print(json.dumps(res, indent=2))
                if mismatch:
                    sys.stderr.write("%s\n" % mismatch)
            else:
                _print_info(res)
            if not res["resolved"]:
                return EXIT_ERROR
            return final(EXIT_OK)

        if mismatch:
            sys.stderr.write("%s\n" % mismatch)

        if view.ktext_shift is None:
            sys.stderr.write("chyba: posun jadra sa nenasiel - %s\n"
                             % view.resolve_problem())
            return EXIT_ERROR

        if args.cmd == "ps":
            res = view.processes()
            _warn(res)
            print(json.dumps(res, indent=2)) if args.json else _print_ps(res)
            return final(EXIT_OK)
        if args.cmd == "lsmod":
            res = view.modules()
            _warn(res)
            print(json.dumps(res, indent=2)) if args.json else _print_lsmod(res)
            return final(EXIT_OK)
        if args.cmd == "ss":
            res = view.sockets()
            _warn(res)
            print(json.dumps(res, indent=2)) if args.json else _print_ss(res)
            return final(EXIT_OK)

        # baseline textu jadra sa smie vyrobit len zo snimky, ktora sedi
        # s profilom (inak by patrila inemu bootu) a z UPLNEJ snimky
        # (inak by kontrola slepla prave tam, kde by hook bol)
        if args.cmd == "textbaseline":
            if mismatch:
                sys.stderr.write("%s\n" % mismatch)
                sys.stderr.write("baseline z iného bootu sa NEvytvori\n")
                return EXIT_PROFILE_MISMATCH
            out = os.path.join(view.p.dir, checks.TEXT_BASELINE_FILE)
            if os.path.exists(out) and not args.force:
                sys.stderr.write("chyba: %s uz existuje (prepis len "
                                 "s --force)\n" % out)
                return EXIT_ERROR
            vmlinux = args.vmlinux
            if vmlinux is None:
                release = ((view.p.meta or {}).get("release")
                           or (view.p.meta or {}).get("guest_kernel"))
                if release:
                    repo = os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__)))
                    kandidat = os.path.join(repo, "data", "raw",
                                            "profile-assets",
                                            "vmlinux-%s" % release)
                    if os.path.isfile(kandidat):
                        vmlinux = kandidat
            try:
                doc = checks.build_text_baseline(view, vmlinux_path=vmlinux)
            except ValueError as exc:
                sys.stderr.write("chyba: %s\n" % exc)
                return EXIT_ERROR
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=1)
                fh.write("\n")
            sys.stderr.write("zapisane: %s (%d stranok, zdroj %s, boot %s)\n"
                             % (out, len(doc["pages"]), doc.get("zdroj"),
                                doc.get("boot_id") or "neznamy"))
            return EXIT_OK

        # `validate` po sebe necha subor v data/results - vysledok z profilu,
        # ktory k snimke nepatri, sa preto nevyraba vobec. Citacie podprikazy
        # vyssie vypisu, co videli, a nesulad hlasia na stderr.
        if args.cmd == "validate" and mismatch:
            sys.stderr.write("porovnanie s pozemnou pravdou sa nespustilo a "
                             "%s sa nezapisal\n" % args.out)
            return EXIT_PROFILE_MISMATCH

        res = _external(args.cmd, args, view)
        if res is None:
            return EXIT_NOT_IMPLEMENTED
        if args.cmd == "validate":
            with open(args.out, "w") as fh:
                json.dump(res, fh, indent=2)
            sys.stderr.write("zapisane: %s\n" % args.out)
            print(json.dumps(res, indent=2)) if args.json else _print_validate(res)
            return final(EXIT_OK)
        if args.cmd == "checks":
            print(json.dumps(res, indent=2)) if args.json else _print_checks(res)
            return final(checks_exit_code(res))
        if args.cmd == "procmap":
            print(json.dumps(res, indent=2)) if args.json else _print_procmap(res)
            return final(EXIT_OK)
        if args.json:
            print(json.dumps(res, indent=2))
        return final(EXIT_OK)
    finally:
        img.close()


if __name__ == "__main__":
    sys.exit(main())
