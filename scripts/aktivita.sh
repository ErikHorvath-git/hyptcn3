#!/usr/bin/env bash
#
# aktivita.sh - G3: oznacenie behu aktívny/neaktívny z NEZAVISLEHO
# pozorovania (pozemná pravda pred/po - nie zo zberaca).
#
#   scripts/aktivita.sh <adresar_sedenia>
#
# Porovna ps/lsmod/ss pred vs. po a zoznamy suborov (/tmp, /root, /var/tmp)
# a zapise aktivita.json do adresara sedenia. Detekcia sa potom pocita
# LEN nad aktivnymi behmi (H: eval.py filtruje podla tohto suboru).
#
set -uo pipefail

SESS="${1:?pouzitie: aktivita.sh <adresar_sedenia>}"
[ -d "$SESS" ] || { echo "aktivita: $SESS nie je adresar" >&2; exit 2; }

python3 - "$SESS" <<'PYEOF'
import datetime
import json
import os
import sys

sess = sys.argv[1]

def riadky(meno):
    p = os.path.join(sess, meno)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8", errors="replace") as fh:
        return set(fh.read().splitlines())

ps_b, ps_a = riadky("ps_before.txt"), riadky("ps_after.txt")
lsmod_b, lsmod_a = riadky("lsmod_before.txt"), riadky("lsmod_after.txt")
ss_b, ss_a = riadky("ss_before.txt"), riadky("ss_after.txt")
files_b, files_a = riadky("files_before.txt"), riadky("files_after.txt")

def pidy(ps):
    if ps is None:
        return set()
    out = set()
    for r in ps:
        cast = r.split()
        if cast and cast[0].isdigit():
            out.add(cast[0])
    return out

nove_procesy = pidy(ps_a) - pidy(ps_b) if ps_b is not None and ps_a is not None else None
nove_moduly = (lsmod_a - lsmod_b) if lsmod_b is not None and lsmod_a is not None else None
nove_sockety = (ss_a - ss_b) if ss_b is not None and ss_a is not None else None
nove_subory = (files_a - files_b) if files_b is not None and files_a is not None else None

def pocet(s):
    return None if s is None else len(s)

aktivny = bool(
    (nove_procesy and len(nove_procesy) > 0) or
    (nove_moduly and len(nove_moduly) > 0) or
    (nove_sockety and len(nove_sockety) > 0) or
    (nove_subory and len(nove_subory) > 0))

doc = {
    "schema": "hyptcn3/aktivita/1",
    "date": datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"),
    "aktivny": aktivny,
    "poznamka": ("aktivita sa pozoruje NEZAVISLE od zberaca (pozemná pravda "
                 "pred/po z hosta); detekcia sa pocita len nad aktivnymi "
                 "behmi. Prazdne hodnoty (null) znamenaju chybajucu "
                 "pozemnú pravdu - vtedy je oznacenie nedokazane, nie "
                 "neaktivne."),
    "pocty": {
        "nove_procesy": pocet(nove_procesy),
        "nove_moduly": pocet(nove_moduly),
        "nove_sockety": pocet(nove_sockety),
        "nove_subory": pocet(nove_subory),
    },
    "dokaz": {
        "nove_procesy": sorted(nove_procesy)[:50] if nove_procesy else None,
        "nove_moduly": sorted(nove_moduly)[:50] if nove_moduly else None,
        "nove_sockety": sorted(nove_sockety)[:50] if nove_sockety else None,
        "nove_subory": sorted(nove_subory)[:50] if nove_subory else None,
    },
}
out = os.path.join(sess, "aktivita.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=1, ensure_ascii=False)
    fh.write("\n")
print("aktivita: %s -> %s (nove procesy=%s, moduly=%s, sockety=%s, subory=%s)"
      % ("AKTIVNY" if aktivny else "neaktivny", out,
         pocet(nove_procesy), pocet(nove_moduly),
         pocet(nove_sockety), pocet(nove_subory)))
PYEOF
