#!/usr/bin/env python3
"""cpu_burn.py - vytazi CPU celociselnym vypoctom.

PRECO: oddeluje "vytazeny stroj" od "stroj sahajuci na pamat a subory".
V hypTcn002 sa model naucil prave tento rozdiel a vydaval ho za detekciu
malveru; aby sa to dalo zmerat, musi byt zataz CPU vlastnou triedou.

Scenar zamerne NEalokuje pamat (pocita nad malymi celymi cislami v lokalnej
premennej) a nesaha na subory, takze zmena v pamati ma prist iba z planovaca
a zo zasobnika procesu.

Spustenie:  python3 cpu_burn.py [sekundy]
"""
import json
import sys
import time


def main():
    trvanie = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    zaciatok = time.time()
    x = 1
    iteracii = 0
    # Cas sa kontroluje raz za davku, nie po kazdej iteracii - time.time() by
    # inak tvoril vacsinu prace a scenar by meral volanie systemu, nie vypocet.
    while time.time() - zaciatok < trvanie:
        for _ in range(200000):
            x = (x * 1103515245 + 12345) % 2147483648
        iteracii += 200000
    print(json.dumps({"scenar": "cpu_burn",
                      "trvanie_s": round(time.time() - zaciatok, 3),
                      "iteracii": iteracii,
                      "kontrolna_hodnota": x}))


if __name__ == "__main__":
    main()
