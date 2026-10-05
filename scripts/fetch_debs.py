#!/usr/bin/env python3
"""
fetch_debs.py - stiahne .deb baliky s riesenim zavislosti pre VM (blok C).

APT vo VM cez NAT je merane nepouzitelne (~50 min bez dokoncenia), ale
sieť HOSTITELA je rychla a host->guest cez virbr0 ide bez forwardingu.
Preto: index Packages (bookworm/main) sa citá na hostitela, zavislosti sa
vyriesia tu, .deb sa stiahnu na hosta a do VM sa prenesu scp/ssh.

Pouzitie:
  python3 scripts/fetch_debs.py nginx wrk postgresql gcc zstd rsync \\
      --out data/raw/debs --index /tmp/bwmain.gz
"""

import argparse
import gzip
import os
import subprocess
import sys
import urllib.request

BASE = "https://deb.debian.org/debian"
ARCH = "amd64"


def load_index(path):
    """Package -> {Filename, Size, Depends} z Packages(.gz)."""
    if path.endswith(".gz"):
        text = gzip.open(path, "rt", encoding="utf-8").read()
    else:
        text = open(path, encoding="utf-8").read()
    out = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("Package: "):
            cur = line.split(":", 1)[1].strip()
            out[cur] = {}
        elif cur and line.startswith("Filename: "):
            out[cur]["Filename"] = line.split(":", 1)[1].strip()
        elif cur and line.startswith("Depends: "):
            out[cur]["Depends"] = line.split(":", 1)[1].strip()
    return out


def alternativy(dep_str):
    """'a (>= 1), b | c' -> [['a'], ['b', 'c']]."""
    if not dep_str:
        return []
    out = []
    for cast in dep_str.split(","):
        alt = [x.strip().split(" ")[0].split(":")[0] for x in cast.split("|")]
        alt = [a for a in alt if a and not a.startswith("${")]
        if alt:
            out.append(alt)
    return out


def uzavret(index, wanted):
    """Uzavretie zavislosti; alternativy = prvy balik, ktory v indexe je."""
    vybrane, fronte = set(), list(wanted)
    while fronte:
        p = fronte.pop(0)
        if p in vybrane or p not in index:
            continue
        vybrane.add(p)
        for alt in alternativy(index[p].get("Depends")):
            zvoleny = next((a for a in alt if a in index), None)
            if zvoleny and zvoleny not in vybrane:
                fronte.append(zvoleny)
    return sorted(vybrane)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("baliky", nargs="+")
    ap.add_argument("--index", default="/tmp/bwmain.gz")
    ap.add_argument("--out", default="data/raw/debs")
    ap.add_argument("--ssh", default="root@192.168.122.100")
    ap.add_argument("--len-stahni", action="store_true",
                    help="neprenasaj do VM, len stiahni na hosta")
    a = ap.parse_args(argv)

    index = load_index(a.index)
    zoznam = uzavret(index, a.baliky)
    print("fetch_debs: %d balikov (zavislosti vratane)" % len(zoznam))
    os.makedirs(a.out, exist_ok=True)
    subory = []
    for p in zoznam:
        fn = index[p]["Filename"]
        ciel = os.path.join(a.out, os.path.basename(fn))
        if not os.path.exists(ciel):
            url = "%s/%s" % (BASE, fn)
            print("  %s" % url)
            urllib.request.urlretrieve(url, ciel)
        subory.append(ciel)
    print("fetch_debs: stiahnutych %d suborov do %s" % (len(subory), a.out))

    if not a.len_stahni:
        # prenos do VM a lokalna instalacia (dpkg vyriesi poradie sam)
        tar = os.path.join(a.out, "debs.tar")
        subprocess.run(["tar", "cf", tar, "-C", a.out] +
                       [os.path.basename(s) for s in subory], check=True)
        r = subprocess.run(["scp", "-q", tar, "%s:/tmp/debs.tar" % a.ssh])
        if r.returncode != 0:
            print("fetch_debs: scp zlyhalo (rc=%d)" % r.returncode)
            return 1
        cmd = ("mkdir -p /tmp/debs && tar xf /tmp/debs.tar -C /tmp/debs "
               "&& dpkg -i /tmp/debs/*.deb || apt-get -f install -y")
        r = subprocess.run(["ssh", a.ssh, cmd], text=True)
        print("fetch_debs: instalacia v %s skoncila rc=%d" % (a.ssh,
                                                              r.returncode))
        return r.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
