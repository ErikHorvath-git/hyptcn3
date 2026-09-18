#!/usr/bin/env python3
"""
Doplni do artefaktov v data/results/ kluce proveniencie, ktore chybaju.

Preco to nie je sucast zapisovacich skriptov: artefakty vznikali postupne a kazdy
si niesol trochu iny tvar. Namiesto prepisovania uz overenych dat sa sem doplna
IBA to, co sa da odvodit zo samotneho suboru alebo z env.json vedla neho.

Pravidlo: nic sa nevymysla. Ked sa hodnota neda odvodit, kluc sa doplni s hodnotou
null a do "provenance_note" sa napise preco. Prazdny kluc s poznamkou je poctivejsi
nez pravdepodobne spravny udaj.

Pouzitie:
    python3 scripts/stamp_results.py [--dry-run]
"""

import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "data", "results")

# Adresare so surovym vystupom senzora - tie maju vlastnu schemu 'vmicollect/1'
# a hlavicku tohto typu mat nemaju, su to vstupne data, nie vysledok.
SKIP_DIRS = {"sidecars", "logs", "ground_truth", "snap"}

PROVENANCE = ["commit", "date", "host", "guest", "command", "n"]


def git(*args):
    try:
        return subprocess.check_output(["git", "-C", REPO, *args], text=True).strip()
    except Exception:
        return None


def load_env(path):
    """env.json lezi vedla artefaktu a nesie popis stroja aj hosta."""
    d = os.path.dirname(path)
    while d.startswith(RESULTS):
        cand = os.path.join(d, "env.json")
        if os.path.exists(cand) and os.path.abspath(cand) != os.path.abspath(path):
            try:
                with open(cand, encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                return None
        d = os.path.dirname(d)
    return None


def derive(doc, path, env):
    """Vrati (doplnene_kluce, poznamky) - meni doc na mieste."""
    added, notes = [], {}

    if "commit" not in doc:
        c = git("rev-parse", "HEAD")
        if c:
            doc["commit"] = c
            notes["commit"] = ("doplnene dodatocne z HEAD repozitara; artefakt "
                               "sam commit neuvadzal")
            added.append("commit")

    if "date" not in doc:
        for k in ("generated", "timestamp", "date_unix"):
            if k in doc:
                doc["date"] = doc[k] if isinstance(doc[k], str) else None
                break
        if "date" not in doc or doc.get("date") is None:
            ts = os.path.getmtime(path)
            import datetime
            doc["date"] = datetime.datetime.utcfromtimestamp(ts).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            notes["date"] = "odvodene z casu zmeny suboru, nie z behu"
        added.append("date")

    if "host" not in doc:
        if env and "host" in env:
            doc["host"] = env["host"]
            notes["host"] = "prevzate z env.json v tom istom behu"
        else:
            doc["host"] = None
            notes["host"] = "neda sa odvodit zo suboru ani z env.json"
        added.append("host")

    if "guest" not in doc:
        dom = doc.get("domain")
        if dom and env and isinstance(env.get("guest"), (str, dict)):
            doc["guest"] = env["guest"]
            notes["guest"] = ("prevzate z env.json; domena v artefakte ('%s') "
                              "sa zhoduje" % dom)
        elif dom:
            doc["guest"] = {"domain": dom}
            notes["guest"] = ("v artefakte bola len domena; verzia jadra hosta "
                              "sa z neho odvodit neda")
        elif env and "guest" in env:
            doc["guest"] = env["guest"]
            notes["guest"] = "prevzate z env.json v tom istom behu"
        else:
            doc["guest"] = None
            notes["guest"] = "neda sa odvodit zo suboru ani z env.json"
        added.append("guest")

    if "command" not in doc:
        doc["command"] = None
        notes["command"] = ("prikaz nie je v artefakte zaznamenany; "
                            "postup je popisany v docs/MERANIA.md")
        added.append("command")

    if "n" not in doc:
        n = None
        for k in ("behy", "runs", "repetitions"):
            if isinstance(doc.get(k), list):
                n = len(doc[k])
                break
        if n is None and isinstance(doc.get("values"), dict):
            v = doc["values"]
            for k in ("snapshots", "snimok", "cycles"):
                if isinstance(v.get(k), int):
                    n = v[k]
                    break
        if n is None and isinstance(doc.get("summary"), dict):
            # periodicky zber: n je pocet dokoncenych cyklov, nie jeden beh
            for k in ("cycles_done", "snapshots", "snimok", "cycles"):
                if isinstance(doc["summary"].get(k), int):
                    n = doc["summary"][k]
                    notes["n"] = "pocet dokoncenych cyklov zberu (summary.%s)" % k
                    break
        if n is None and isinstance(doc.get("params"), dict):
            if isinstance(doc["params"].get("max_cycles"), int):
                n = doc["params"]["max_cycles"]
                notes["n"] = "pozadovany pocet cyklov (params.max_cycles)"
        if n is None:
            n = 1
            notes["n"] = ("artefakt je z jedineho behu; pocet opakovani v nom "
                          "zaznamenany nebol")
        doc["n"] = n
        added.append("n")

    return added, notes


def main():
    dry = "--dry-run" in sys.argv
    if not os.path.isdir(RESULTS):
        print("data/results/ neexistuje", file=sys.stderr)
        return 1

    changed = 0
    for dirpath, dirnames, filenames in os.walk(RESULTS):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not name.endswith(".json"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, REPO)
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except Exception as exc:
                print("%s: neda sa precitat (%s)" % (rel, exc))
                continue
            if not isinstance(doc, dict):
                continue
            if all(k in doc for k in PROVENANCE):
                continue

            env = load_env(path)
            added, notes = derive(doc, path, env)
            if not added:
                continue
            if notes:
                old = doc.get("provenance_note") or {}
                if isinstance(old, dict):
                    old.update(notes)
                    doc["provenance_note"] = old
                else:
                    doc["provenance_note"] = notes

            print("%s: doplnene %s" % (rel, ", ".join(added)))
            for k, v in notes.items():
                print("    %-8s %s" % (k, v))
            changed += 1
            if not dry:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh, indent=1, ensure_ascii=False)
                    fh.write("\n")

    print("\nspolu %d suborov%s" % (changed, " (nic sa nezapisalo)" if dry else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
