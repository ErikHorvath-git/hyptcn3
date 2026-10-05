#!/usr/bin/env python3
"""
mb_fetch.py - blok G2: MalwareBazaar fetcher.

PRAVIDLA (HONESTY P4 + zadanie):
- do gitu idu LEN hashe a metadáta (SHA-256, rodina, first_seen, tags) -
  binárky vzoriek NIKDY (ukladajú sa do data/raw/malware/, ktoré je
  v .gitignore a nikdy sa necommitne);
- vzorky sa používajú LEN v teste/validácii detekcie, nikdy na tréning;
- filter ELF x86-64 sa robí DVOJSTUPŇOVO: API dá `file_type`, ale verí sa
  mu až po stiahnutí a overení príkazom `file` - metadáta z API sa označia
  ako `file_type_api`, skutočné overenie ako `file_type_verified`.

POUZITIE
  mb_fetch.py recent [--limit N] [--selector time|100] [--out JSON]
  mb_fetch.py get --sha256 H [--out DIR]   # stiahne + overí + manifest

API: https://mb-api.abuse.ch/api/v1/ (query=get_recent / get_file).
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

API = "https://mb-api.abuse.ch/api/v1/"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "data", "results", "malwarebazaar")
BIN_DIR = os.path.join(REPO, "data", "raw", "malware")


def api_post(data):
    """POST na MalwareBazaar API. Od 2025 API vyzaduje API-KEY - nastav
    ho do premennej MB_API_KEY (registracia: bazaar.abuse.ch/api)."""
    key = os.environ.get("MB_API_KEY", "")
    if not key:
        raise RuntimeError(
            "chyba MB_API_KEY: MalwareBazaar API vyzaduje kluc "
            "(bazaar.abuse.ch/api) - nastav: export MB_API_KEY=<kluc>")
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(API, data=body,
                                 headers={"User-Agent": "hyptcn3-mb-fetch/1",
                                          "API-KEY": key})
    with urllib.request.urlopen(req, timeout=60) as r:
        doc = json.loads(r.read().decode())
    if doc.get("query_status") not in ("ok", "no_results"):
        raise RuntimeError("API vratila status %r: %s"
                           % (doc.get("query_status"), doc.get("query_status")))
    return doc


def _zaznam(e):
    return {
        "sha256": e["sha256_hash"],
        "family": e.get("signature") or e.get("tags") or "n/a",
        "first_seen": e.get("first_seen"),
        "file_type_api": e.get("file_type"),
        "file_type_mime": e.get("file_type_mime"),
        "tags": e.get("tags"),
        "reporter": e.get("reporter"),
        "velkost_b": e.get("file_size"),
    }


def cmd_recent(args):
    doc = api_post({"query": "get_recent",
                    "selector": args.selector,
                    "limit": str(args.limit)})
    data = doc.get("data") or []
    if not data:
        print("mb_fetch: API nevratila ziadne vzorky (moze byt rate-limit)")
        return 1
    elf = [e for e in data if str(e.get("file_type", "")).startswith("elf")]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ")
    out = {
        "schema": "hyptcn3/malwarebazaar-recent/1",
        "date": stamp,
        "api": API,
        "selector": args.selector,
        "limit": args.limit,
        "zaznamov": len(elf),
        "zaznamy": [_zaznam(e) for e in elf],
        "poznamka": ("iba hashe a metadáta - binárky nie su sucastou repa; "
                     "file_type_api je udaj od API, realne overenie urobi "
                     "az 'mb_fetch.py get' prikazom file"),
    }
    os.makedirs(RESULTS, exist_ok=True)
    path = args.out or os.path.join(RESULTS, "recent_%s.json" % stamp)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print("mb_fetch: %d ELF zaznamov z %d vzoriek -> %s"
          % (len(elf), len(data), path))
    for e in elf[:10]:
        print("  %s  %-24s first_seen=%s size=%s"
              % (e["sha256_hash"][:16], _zaznam(e)["family"][:24],
                 e.get("first_seen"), e.get("file_size")))
    return 0


def cmd_get(args):
    doc = api_post({"query": "get_file", "sha256_hash": args.sha256})
    data = doc.get("data") or []
    if not data:
        print("mb_fetch: vzorka %s sa nenašla (alebo rate-limit)" % args.sha256)
        return 1
    e = data[0]
    outdir = args.out or BIN_DIR
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "%s.bin" % args.sha256)
    url = "https://mb-api.abuse.ch/downloads/%s/" % args.sha256
    urllib.request.urlretrieve(url, path)
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if sha != args.sha256:
        os.unlink(path)
        raise RuntimeError("SHA-256 stiahnutej vzorky nesedi (API/transport "
                           "problem): %s != %s" % (sha, args.sha256))
    file_out = subprocess.run(["file", path], capture_output=True,
                              text=True).stdout.strip()
    elf64 = ("ELF" in file_out and "x86-64" in file_out)
    manifest = {
        "schema": "hyptcn3/malwarebazaar-vzorka/1",
        "sha256": args.sha256,
        "family": e.get("signature") or "n/a",
        "first_seen": e.get("first_seen"),
        "file_type_api": e.get("file_type"),
        "file_type_verified": file_out,
        "elf_x86_64": elf64,
        "velkost_b": os.path.getsize(path),
        "cesta": path,
        "poznamka": ("binarka NIE JE v gite; je v data/raw/ (gitignored). "
                     "Pouzit LEN v teste, nikdy na trening."),
    }
    mpath = path + ".manifest.json"
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print("mb_fetch: %s -> %s" % (args.sha256, path))
    print("  %s" % file_out)
    if not elf64:
        print("  POZOR: vzorka NIE JE ELF x86-64 - do behov ju nepustit")
        return 2
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="MalwareBazaar fetcher (G2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("recent", help="zoznam nedavnych ELF vzoriek (hashe)")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--selector", default="time", choices=("time", "100"))
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_recent)
    p = sub.add_parser("get", help="stiahni a over vzorku (binarka mimo gitu)")
    p.add_argument("--sha256", required=True)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_get)
    a = ap.parse_args(argv)
    try:
        return a.func(a)
    except (OSError, RuntimeError, ValueError) as exc:
        print("mb_fetch: chyba: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
