#!/usr/bin/env python3
"""fork_storm.py - vytvara a hned ukoncuje vela kratkozijucich procesov.

PRECO: rychla obmena procesov meni zoznam init_task.tasks medzi snimkami, cize
priznaky proc_new a proc_gone. Zaroven to odlisuje "vela prace v jednom
procese" (cpu_burn) od "vela procesov".

Deti sa vytvaraju po davkach a kazda davka sa pred dalsou cela pozbiera, takze
naraz nezije viac nez POCET_V_DAVKE deti a po skonceni nezostane ani jedno
(waitpid na kazde dieta, ziadne zombie).

Spustenie:  python3 fork_storm.py [sekundy]
"""
import json
import os
import sys
import time

POCET_V_DAVKE = 20


def davka():
    deti = []
    for _ in range(POCET_V_DAVKE):
        pid = os.fork()
        if pid == 0:
            # Dieta nesmie pokracovat v tele cyklu ani spustit atexit handlery
            # rodica - preto os._exit, nie sys.exit.
            os._exit(0)
        deti.append(pid)
    for pid in deti:
        os.waitpid(pid, 0)
    return len(deti)


# Pocet pozbieranych deti sa nezistuje volanim 'ps' - to by samo vyrobilo dalsie
# dieta a suhrn by hlasil zvysok, ktory scenar nespravil. Zaruka je v kode:
# davka() sa vrati az po waitpid na kazde vytvorene dieta.


def main():
    trvanie = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    zaciatok = time.time()
    deti = 0
    davok = 0
    while time.time() - zaciatok < trvanie:
        deti += davka()
        davok += 1
        time.sleep(0.02)
    print(json.dumps({"scenar": "fork_storm",
                      "trvanie_s": round(time.time() - zaciatok, 3),
                      "davok": davok,
                      "deti": deti,
                      "pozbieranych": deti}))


if __name__ == "__main__":
    main()
