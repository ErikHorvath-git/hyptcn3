#!/usr/bin/env python3
"""
detektor.py - prepojenie celej detekcnej cesty (blok H, Codex bod 3):
snimky -> vektor -> okno -> prediktor -> skore -> kalibrovany prah ->
alarm (k z n) -> HOLD retazca (vmicollect hold) + zaznam latencie.

Doteraz komponenty existovali oddelene: per-bin okna v sidecaroch,
prediktor v tcn/, HOLD v zberaci, kalibracia v tcn/kalibracia.py. Toto
ich spaja do jednej slucky - presne tou cestou, ktorou pobezi aj ziva
reakcia (A7 react_hook dostane alarm z rovnakeho zdroja, ak bezi
v procese zberaca; standalone detektor HOLD len oznacuje retazec).

POUZITIE
  python3 scripts/detektor.py --snapshots <dir> --profile <prof>
      --model <model.pt> --prah <x> [--k 3 --n 5] [--hold-bin <cesta>]
      [--cakaj <s>] [--out <jsonl>]

Vystup: riadky JSON {ts, seq, skore, alarm, hold_rc, latencia_ms}.
"""

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tcn.score import chyba_predikcie_okna, nacitaj_prediktor  # noqa: E402


def alarm_pravidlo(skore, prah, k, n):
    """True, ked k z n poslednych skore je nad prahom (okno je PLNE)."""
    if len(skore) < n:
        return False
    return sum(1 for s in skore[-n:] if s >= prah) >= k


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshots", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--prah", type=float, required=True)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--hold-bin", default="vmicollect/build/vmicollect")
    ap.add_argument("--cakaj", type=float, default=0.0,
                    help="0 = spracuj co je a skonci; >0 = zivy rezim")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    model, norm, _ = nacitaj_prediktor(a.model)
    out = open(a.out, "a", encoding="utf-8") if a.out else sys.stdout

    def emit(**kw):
        out.write(json.dumps(kw, ensure_ascii=False) + "\n")
        out.flush()

    import collections
    from features.windows import DLZKA_OKNA
    from tcn.score import beh_predikcia, nove_sidecary
    from features.snapshot import vektor_snimky

    okno = collections.deque(maxlen=DLZKA_OKNA)
    skore_hist = collections.deque(maxlen=a.n)
    videne, predch = set(), None
    posledna = time.monotonic()
    hold = None

    while True:
        nove = nove_sidecary(a.snapshots, videne)
        if not nove:
            if time.monotonic() - posledna >= a.cakaj:
                break
            time.sleep(0.5)
            continue
        posledna = time.monotonic()
        for seq, sid, _ in nove:
            t0 = time.monotonic()
            vektor, predch, _ = vektor_snimky(a.snapshots, a.profile, seq,
                                              predch)
            okno.append(vektor)
            if len(okno) < DLZKA_OKNA:
                continue
            sk, _, _ = chyba_predikcie_okna(model, norm, okno)
            skore_hist.append(sk)
            alarm = alarm_pravidlo(skore_hist, a.prah, a.k, a.n)
            hold_rc = None
            if alarm:
                # HOLD: oznac retazec, ktory vyvolal alarm (flight recorder)
                hold = subprocess.run(
                    [a.hold_bin, "hold", "--chain", str(seq)],
                    capture_output=True, text=True)
                hold_rc = hold.returncode
            emit(ts_unix_ms=int(time.time() * 1000), seq=seq, skore=sk,
                 alarm=alarm, hold_rc=hold_rc,
                 latencia_ms=round((time.monotonic() - t0) * 1000, 2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
