#!/usr/bin/env python3
"""proc_scan.py - opakovane prechadza /proc a cita informacie o procesoch.

PRECO: prieskum stroja (kto tu bezi, pod kym, s akym prikazovym riadkom) je
prvy krok vacsiny scenarov utoku a zaroven sa nepodoba ani na zataz CPU, ani
na pracu so subormi: cita sa iba virtualny suborovy system, takze zataz je
v jadre a v jeho strukturach.

Scenar iba CITA. Nic nezapisuje a nic nespusta.

Spustenie:  python3 proc_scan.py [sekundy]
"""
import json
import os
import sys
import time

SUBORY = ("stat", "status", "cmdline", "maps")


def main():
    trvanie = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    zaciatok = time.time()
    prechodov = 0
    precitanych = 0
    bajtov = 0
    while time.time() - zaciatok < trvanie:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            for meno in SUBORY:
                try:
                    with open("/proc/%s/%s" % (pid, meno), "rb") as fh:
                        bajtov += len(fh.read())
                    precitanych += 1
                except OSError:
                    # Proces mohol medzitym skoncit - to nie je chyba scenara,
                    # je to bezny stav /proc a preskakuje sa ticho.
                    pass
        prechodov += 1
        time.sleep(0.05)
    print(json.dumps({"scenar": "proc_scan",
                      "trvanie_s": round(time.time() - zaciatok, 3),
                      "prechodov": prechodov,
                      "precitanych_suborov": precitanych,
                      "mib_precitanych": round(bajtov / 1048576.0, 3)}))


if __name__ == "__main__":
    main()
