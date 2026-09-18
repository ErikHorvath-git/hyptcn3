#!/usr/bin/env python3
"""
Vyrobi malu snimku mini.vmicd pre testy, ktore musia bezat aj v cerstvom klone.

PRECO: realne snimky (/var/tmp/vmic-val, stovky MiB) do gitu nepatria a mimo
tohto stroja neexistuju. Bez nich sa vsak preskoci aj injekcny test detektora
hookov, cize jediny pozitivny dokaz detekcie v celej praci. Mala snimka drzi
presne tie stranky, ktore testy naozaj citaju, a nic viac.

CO SA VYBERA: skript otvori realnu snimku cez guestparse, vykona nad nou
presne tie operacie, ktore robia testy, a zapamata si KAZDU fyzicku stranku,
z ktorej sa pritom citalo. Zoznam teda nevznikol odhadom - je to presna
mnozina stranok, bez ktorych by operacie nezbehli:

  - stranka s bannerom ("Linux version ...") a stranka s init_task.comm
    (najdenie posunu jadra / KASLR),
  - stranka so symbolom page_offset_base (baza priameho mappingu),
  - tabulky stranok, ktore treba na prechod init_top_pgt pre overovane adresy,
  - prvych N task_struct zo zoznamu init_task.tasks,
  - prvych M struct module z oblasti modulov,
  - stranky s obsahom sys_call_table.

CO TO NIE JE: nie je to cela pamat hosta a nedaju sa nad nou robit merania.
Je to podmnozina jednej realnej snimky, urcena na test parsera a detektora.
Vsetky bajty su povodne - nic sa neupravuje ani nedopisuje.

Pouzitie (z korena repa):
    python3 guestparse/tests/data/make_mini.py \
        --src /var/tmp/vmic-val \
        --profile profiles/debian12-6.1.0-42-cloud-amd64
"""

import argparse
import datetime
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO)

from guestparse import checks                                  # noqa: E402
from guestparse.image import (VMICD_HDR, VMICD_MAGIC, VMICD_VERSION,  # noqa: E402
                              VMICD_FLAG_FULL, VmicdImage, chain_headers,
                              open_image)
from guestparse.profile import Profile                         # noqa: E402
from guestparse.view import GuestView                          # noqa: E402


class Recorder:
    """
    Obal nad snimkou, ktory si pamata indexy stranok, z ktorych sa citalo.

    Iteracia pages() sa nezaznamenava zamerne: sken banneru prejde celu
    snimku a zaznamenal by vsetko. Do vyberu ide iba to, co si parser naozaj
    adresne vyziadal cez read().
    """

    def __init__(self, img):
        self.img = img
        self.touched = set()
        self.kind = img.kind
        self.page_size = img.page_size
        self.memsize = img.memsize
        self.paths = img.paths

    def read(self, pa, n):
        if pa is not None and pa >= 0 and n > 0:
            first = pa // self.page_size
            last = (pa + n - 1) // self.page_size
            for idx in range(first, last + 1):
                self.touched.add(idx)
        return self.img.read(pa, n)

    def pages(self):
        return self.img.pages()

    def page_count(self):
        return self.img.page_count()

    def close(self):
        self.img.close()


def collect(src, profile_dir, tasks, modules):
    """Vrati (mnozina indexov stranok, hlavicka zdroja, zaznam o behu)."""
    headers = chain_headers(src) if os.path.isdir(src) else [
        VmicdImage.header(src)]
    img = open_image(src)
    rec = Recorder(img)
    prof = Profile.from_dir(profile_dir)
    view = GuestView(rec, prof)

    if not view.resolve():
        raise SystemExit("posun jadra sa v %s nenasiel - zla snimka alebo "
                         "profil z ineho jadra" % src)
    note = {"ktext_shift": view.ktext_shift,
            "page_offset_base": view.page_offset_base,
            "banner": view.banner,
            "banner_pa": view.banner_pa}

    after_resolve = len(rec.touched)
    view.info()                       # krizova kontrola prekladu adries
    after_info = len(rec.touched)
    pres = view.processes(limit=tasks)
    after_tasks = len(rec.touched)
    mres = view.modules(limit=modules)
    after_mods = len(rec.touched)
    tabs = checks.syscall_tables(view)
    after_tabs = len(rec.touched)

    note["processes"] = [{"pid": p["pid"], "comm": p["comm"],
                          "kernel_thread": p["kernel_thread"]}
                         for p in pres["processes"]]
    note["modules"] = [m["name"] for m in mres["modules"]]
    note["syscall_tables"] = [{"name": t["name"], "entries": t["entries"],
                               "findings": len(t["findings"])} for t in tabs]
    note["pages_by_step"] = {
        "resolve": after_resolve,
        "info": after_info - after_resolve,
        "processes": after_tasks - after_info,
        "modules": after_mods - after_tasks,
        "syscall_tables": after_tabs - after_mods,
    }
    pages = sorted(rec.touched)
    data = {idx: img.read(idx * img.page_size, img.page_size) for idx in pages}
    missing = [i for i, b in data.items() if b is None]
    if missing:
        raise SystemExit("stranky %s sa zo zdroja nedaju precitat" % missing[:5])
    img.close()
    return data, headers[0], note


def write_mini(out_path, data, src_hdr):
    """Zapise .vmicd s vybranymi strankami; hlavicka je z zdrojovej snimky."""
    psz = src_hdr["page_size"]
    hdr = struct.pack("<8sIIQQQQQQ", VMICD_MAGIC, VMICD_VERSION, psz,
                      src_hdr["chain_id"], src_hdr["seq"], src_hdr["memsize"],
                      len(data), VMICD_FLAG_FULL, src_hdr["region_sig"])
    assert len(hdr) == VMICD_HDR
    with open(out_path, "wb") as fh:
        fh.write(hdr)
        for idx in sorted(data):
            fh.write(struct.pack("<Q", idx))
            fh.write(data[idx])


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--src", default="/var/tmp/vmic-val",
                    help="zdrojova snimka (adresar s retazcom alebo .vmicd)")
    ap.add_argument("--profile",
                    default=os.path.join(REPO, "profiles",
                                         "debian12-6.1.0-42-cloud-amd64"))
    ap.add_argument("--out", default=os.path.join(HERE, "mini.vmicd"))
    ap.add_argument("--manifest", default=os.path.join(HERE, "mini.json"))
    ap.add_argument("--tasks", type=int, default=8,
                    help="kolko task_struct zo zaciatku zoznamu vziat")
    ap.add_argument("--modules", type=int, default=3,
                    help="kolko struct module zo zaciatku zoznamu vziat")
    a = ap.parse_args(argv)

    data, src_hdr, note = collect(a.src, a.profile, a.tasks, a.modules)
    write_mini(a.out, data, src_hdr)

    src_files = ([os.path.join(a.src, n) for n in sorted(os.listdir(a.src))
                  if n.endswith(".vmicd")] if os.path.isdir(a.src) else [a.src])
    manifest = {
        "schema": "hyptcn3/guestparse-mini/1",
        "generated": datetime.datetime.now().astimezone().isoformat(
            timespec="seconds"),
        "generator": "guestparse/tests/data/make_mini.py",
        "source": [{"path": p, "bytes": os.path.getsize(p),
                    "sha256": sha256(p)} for p in src_files],
        "source_header": {k: src_hdr[k] for k in
                          ("version", "page_size", "chain_id", "seq",
                           "memsize", "records", "full", "region_sig")},
        "selection": {"tasks": a.tasks, "modules": a.modules},
        "result": {
            "file": os.path.basename(a.out),
            "pages": len(data),
            "bytes": os.path.getsize(a.out),
            "sha256": sha256(a.out),
        },
        "observed": note,
    }
    with open(a.manifest, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=False)
        fh.write("\n")

    print("zapisane %s: %d stranok, %d B"
          % (a.out, len(data), os.path.getsize(a.out)))
    print("stranky podla kroku: %s" % note["pages_by_step"])
    print("procesy: %s" % ", ".join(
        "%d/%s" % (p["pid"], p["comm"]) for p in note["processes"]))
    print("moduly: %s" % ", ".join(note["modules"]))
    print("tabulky volani: %s" % note["syscall_tables"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
