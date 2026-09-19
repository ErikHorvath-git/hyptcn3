#!/usr/bin/env python3
"""idle.py - referencny scenar: nerobi nic, iba spi.

PRECO: bez referencie sa neda povedat, ci model rozoznal SPRAVANIE, alebo iba
"stroj nieco robi" oproti "stroj stoji". Trieda 'idle' je ta druha strana.

Spustenie:  python3 idle.py [sekundy]
Vystup:     jeden riadok JSON so suhrnom (cita ho scripts/collect_corpus.sh).
"""
import json
import sys
import time

# Kazdy scenar je samostatny subor bez importov z repa. Dovod nie je stylovy:
# do hosta sa prenasa JEDEN subor cez base64 v prikaze (host nema siet ani scp),
# takze spolocny modul by sa musel prenasat tiez a scenar by prestal byt
# spustitelny sam o sebe.
def main():
    trvanie = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    zaciatok = time.time()
    # Spi po kuskoch, nie jednym sleep(trvanie): tak sa da scenar prerusit
    # signalom a nezostane visiet dlhsie, nez ma.
    while time.time() - zaciatok < trvanie:
        time.sleep(min(0.5, trvanie - (time.time() - zaciatok)))
    print(json.dumps({"scenar": "idle",
                      "trvanie_s": round(time.time() - zaciatok, 3)}))


if __name__ == "__main__":
    main()
