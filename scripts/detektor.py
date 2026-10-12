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
import math
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tcn.score import chyba_predikcie_okna, nacitaj_prediktor  # noqa: E402
from features.stream import WindowStream, valid_state  # noqa: E402


def alarm_pravidlo(skore, prah, k, n):
    """True, ked k z n poslednych skore je nad prahom (okno je PLNE)."""
    if len(skore) < n:
        return False
    return sum(1 for s in list(skore)[-n:] if s >= prah) >= k


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
    ap.add_argument("--max-medzera-s", type=float, default=None)
    a = ap.parse_args(argv)

    if (not math.isfinite(a.prah) or a.prah < 0 or not 1 <= a.k <= a.n
            or not math.isfinite(a.cakaj) or a.cakaj < 0):
        ap.error("potrebny konecny prah >= 0, 1 <= k <= n a cakaj >= 0")
    model, norm, checkpoint = nacitaj_prediktor(a.model)
    dlzka = int(checkpoint["dlzka_okna"])
    out = open(a.out, "a", encoding="utf-8") if a.out else sys.stdout

    def emit(**kw):
        out.write(json.dumps(kw, ensure_ascii=False) + "\n")
        out.flush()

    import collections
    from tcn.score import nove_sidecary
    from features.snapshot import vektor_snimky

    gap = a.max_medzera_s if a.max_medzera_s is not None else (checkpoint.get("max_medzera_s") or 7.5)
    okno = WindowStream(dlzka, gap)
    retazce = collections.deque(maxlen=dlzka)
    skore_hist = collections.deque(maxlen=a.n)
    videne, predch = set(), None
    posledna = time.monotonic()
    drzane = set()

    while True:
        nove = nove_sidecary(a.snapshots, videne)
        if not nove:
            if time.monotonic() - posledna >= a.cakaj:
                break
            time.sleep(0.5)
            continue
        posledna = time.monotonic()
        for seq, sid, cas_snimky in nove:
            t0 = time.monotonic()
            if okno.discontinuity(seq, cas_snimky):
                retazce.clear()
                skore_hist.clear()
                predch = None
            sidecar = json.loads((Path(a.snapshots) / (sid + ".json")).read_text())
            chain_id = str(sidecar["output"]["chain_id"])
            vektor, predch, _ = vektor_snimky(a.snapshots, a.profile, seq,
                                              predch)
            window = okno.push(seq, cas_snimky, vektor, valid_state(predch))
            if okno.reset:
                retazce.clear()
                skore_hist.clear()
            if not valid_state(predch):
                predch = None
            retazce.append(chain_id)
            if window is None:
                emit(seq=seq, stav="zahrievanie", dovod=okno.reason,
                     okno=len(okno.rows), potrebne=dlzka)
                continue
            sk, _, _ = chyba_predikcie_okna(model, norm, window)
            if not math.isfinite(sk):
                raise ValueError("prediktor vratil nekonecne alebo NaN skore")
            skore_hist.append(sk)
            alarm = alarm_pravidlo(skore_hist, a.prah, a.k, a.n)
            hold_rc = None
            hold_error = None
            if alarm:
                # HOLD takes an output directory and actual chain IDs (not
                # snapshot sequence numbers). Preserve the pre-alarm window.
                nove_retazce = sorted(set(retazce) - drzane)
                if nove_retazce:
                    hold = subprocess.run(
                        [a.hold_bin, "hold", a.snapshots, *nove_retazce],
                        capture_output=True, text=True)
                    hold_rc = hold.returncode
                    if hold_rc == 0:
                        drzane.update(nove_retazce)
                    else:
                        hold_error = hold.stderr.strip()
                else:
                    hold_rc = 0
            zaznam = dict(ts_unix_ms=int(time.time() * 1000), seq=seq,
                          chain_id=chain_id, skore=sk, alarm=alarm,
                          hold_rc=hold_rc, hold_error=hold_error,
                          drzane_retazce=sorted(drzane),
                          latencia_ms=round((time.monotonic() - t0) * 1000, 2),
                          od_snimky_ms=round((time.time() - cas_snimky) * 1000, 2))
            emit(**zaznam)
            if alarm:
                alarm_path = Path(a.snapshots) / "alarm.json"
                temporary = alarm_path.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(zaznam) + "\n")
                temporary.replace(alarm_path)
            if hold_error is not None:
                if out is not sys.stdout:
                    out.close()
                return 2
    if out is not sys.stdout:
        out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
