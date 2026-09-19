#!/usr/bin/env python3
"""mass_file_rewrite.py - opakovane prepisuje vela suborov vo vlastnom adresari.

PRECO: spravanie podobne hromadnemu sifrovaniu suborov - vela otvoreni, zapisov
a zatvoreni v kratkom case, pri kazdom zapise iny obsah. NIC SA NESIFRUJE a
scenar nesiahne mimo svoj docasny adresar; v praci sa preto vola podla
spravania, nie podla rodiny malveru (HONESTY.md P4).

Zapisuje sa cez os.urandom, aby nove bajty neboli stlacitelne a nepodobali sa
predchadzajucim - rovnako ako pri sifrovani. Odtial ma prist stopa v pamati:
stranky page cache a entropia v binoch, ktore ich pokryvaju.

Spustenie:  python3 mass_file_rewrite.py [sekundy]
"""
import json
import os
import shutil
import sys
import tempfile
import time

POCET_SUBOROV = 200
VELKOST = 64 * 1024


def main():
    trvanie = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    zaciatok = time.time()
    adresar = tempfile.mkdtemp(prefix="mass_file_rewrite.")
    zapisov = 0
    bajtov = 0
    try:
        cesty = [os.path.join(adresar, "f%03d" % i) for i in range(POCET_SUBOROV)]
        for c in cesty:
            with open(c, "wb") as fh:
                fh.write(os.urandom(VELKOST))
            zapisov += 1
            bajtov += VELKOST
        while time.time() - zaciatok < trvanie:
            for c in cesty:
                if time.time() - zaciatok >= trvanie:
                    break
                with open(c, "wb") as fh:
                    fh.write(os.urandom(VELKOST))
                zapisov += 1
                bajtov += VELKOST
    finally:
        # Upratanie je vo finally, nie na konci tela: keby scenar skoncil
        # vynimkou alebo prerusenim, subory by v hostovi zostali a dalsie
        # sedenie by zbieralo pamat so zvyskami po predchadzajucom.
        shutil.rmtree(adresar, ignore_errors=True)
    print(json.dumps({"scenar": "mass_file_rewrite",
                      "trvanie_s": round(time.time() - zaciatok, 3),
                      "suborov": POCET_SUBOROV,
                      "zapisov": zapisov,
                      "mib_zapisanych": round(bajtov / 1048576.0, 2),
                      "adresar_zmazany": not os.path.exists(adresar)}))


if __name__ == "__main__":
    main()
