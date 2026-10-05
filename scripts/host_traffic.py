#!/usr/bin/env python3
"""
host_traffic.py - REALNA externa premavka: HOSTITEL vola sluzby v hostovi
cez siet (virbr0 -> nginx router -> python backends -> postgres).

Bezi NA HOSTITELOVI (ziadny root netreba), sedenia ho pustaju paralelne
s injekciou: tcpdump na moste zachyti skutocny host->guest traffic, nie
len lokalny 127.0.0.1 v hostovi. Mix ciest + fazy (klud -> burst) su
seedovane, aby sa dali sedenia reprodukovat.

Pouzitie:
  python3 scripts/host_traffic.py --target http://192.168.122.100 \
      [--dur 120] [--seed 1] [--vlakien 8] [--burst 1.0]
"""

import argparse
import random
import sys
import threading
import time
import urllib.request

CESTY = ["/auth", "/orders", "/", "/auth?u=%d", "/orders?page=%d"]


def pozadavok(target, cesta, ok, err):
    try:
        with urllib.request.urlopen(target + cesta, timeout=3) as r:
            r.read(128)
            ok[0] += 1
    except Exception:
        err[0] += 1


def vlakno(target, rng, stop, ok, err, burst):
    while not stop.is_set():
        n = rng.randint(1, 6 if burst() else 2)
        for _ in range(n):
            if stop.is_set():
                return
            cesta = random.choice(CESTY)
            if "%d" in cesta:
                cesta = cesta % rng.randint(1, 999)
            pozadavok(target, cesta, ok, err)
        time.sleep(rng.uniform(0.05, 0.4))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://192.168.122.100")
    ap.add_argument("--dur", type=float, default=120.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--vlakien", type=int, default=8)
    ap.add_argument("--burst", type=float, default=1.0,
                    help="podiel casu v burst rezime (0..1)")
    a = ap.parse_args(argv)

    rng = random.Random(a.seed)
    stop = threading.Event()
    ok, err = [0], [0]
    t0 = time.monotonic()
    threads = [threading.Thread(target=vlakno,
                                args=(a.target, rng, stop, ok, err,
                                      lambda: (rng.random() < a.burst)),
                                daemon=True) for _ in range(a.vlakien)]
    for t in threads:
        t.start()
    print("host_traffic: %d vlakien -> %s, %ds, seed=%d"
          % (a.vlakien, a.target, a.dur, a.seed), flush=True)
    while time.monotonic() - t0 < a.dur:
        time.sleep(1)
    stop.set()
    for t in threads:
        t.join(timeout=2)
    rps = ok[0] / max(a.dur, 0.1)
    print("host_traffic: koniec - %d ok, %d chyb, %.1f req/s"
          % (ok[0], err[0], rps))
    return 0 if err[0] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
