#!/usr/bin/env python3
"""anon_exec.py - alokuje anonymnu pamat, zapise do nej a spusti z nej kod.

PRECO: spravanie podobne bezsuborovemu malveru - kod, ktory sa nikdy neobjavi
ako subor na disku, ale iba ako zapisovatelna a zaroven spustitelna anonymna
oblast v pamati procesu. Presne toto je stopa, ktoru ma introspekcia RAM sancu
vidiet a kontrola suborov nie.

Co sa naozaj spusta: sest bajtov strojoveho kodu x86-64, ktore vratia konstantu
(mov eax, 42; ret). Zvysok oblasti sa vyplni nahodnymi bajtmi, aby stranky
neboli nulove a mali vysoku entropiu.

Spustenie:  python3 anon_exec.py [sekundy]
"""
import ctypes
import json
import mmap
import os
import platform
import sys
import time

KOD = b"\xb8\x2a\x00\x00\x00\xc3"   # mov eax, 42 ; ret
OCAKAVANE = 42
VELKOST = 1024 * 1024


def raz():
    """Jedno kolo: mmap RWX -> zapis -> volanie -> munmap. Vrati navratovu
    hodnotu spusteneho kodu, aby sa dalo overit, ze sa naozaj spustil."""
    oblast = mmap.mmap(-1, VELKOST,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    oblast.write(os.urandom(VELKOST))
    oblast.seek(0)
    oblast.write(KOD)
    buf = ctypes.c_char.from_buffer(oblast)
    funkcia = ctypes.CFUNCTYPE(ctypes.c_int)(ctypes.addressof(buf))
    vysledok = funkcia()
    # Pohlad do buffera treba pustit skor, nez sa oblast zatvori - inak
    # mmap.close() vyhodi BufferError a oblast by zostala namapovana.
    del funkcia
    del buf
    oblast.close()
    return vysledok


def main():
    if platform.machine() != "x86_64":
        print(json.dumps({"scenar": "anon_exec", "chyba":
                          "strojovy kod je x86-64, host hlasi %s"
                          % platform.machine()}))
        return 1
    trvanie = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    zaciatok = time.time()
    kol = 0
    zlych = 0
    while time.time() - zaciatok < trvanie:
        if raz() != OCAKAVANE:
            zlych += 1
        kol += 1
        time.sleep(0.05)
    print(json.dumps({"scenar": "anon_exec",
                      "trvanie_s": round(time.time() - zaciatok, 3),
                      "kol": kol,
                      "mib_spolu": round(kol * VELKOST / 1048576.0, 2),
                      "zlych_navratov": zlych}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
