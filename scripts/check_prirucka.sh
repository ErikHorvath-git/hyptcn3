#!/usr/bin/env bash
#
# check_prirucka.sh - je docs/PRIRUCKA.md este zhodna s kodom?
#
# PRECO SAMOSTATNY SKRIPT: kontrola potrebuje zostavenu binarku (prirucka cita
# prikazy, prepinace a vychodzie hodnoty z nej). check_claims.sh je textova
# kontrola, ktora bezi aj bez prekladaca - preto tu bezi zvlast a check_claims
# ju iba zavola. Da sa spustit aj sama. Bezicu domenu ani roota netreba.
#
# PRECO SA NAJPRV PREKLADA: bez 'make' by generator citalo to, co sa naposledy
# zostavilo. Premenovanie konfiguracneho kluca, zmena vychodzej hodnoty alebo
# premenovanie pola sidecaru v zdrojaku by tak prebehlo ako "sedi s kodom".
# Kontrola musi vidiet zdrojak. Polia sidecaru preto generator neberie
# z ulozeneho artefaktu, ale z prave prelozenej binarky: spusti ju nad obrazom
# v docasnom subore (backend 'file'), takze domenu ani roota to stale nepotrebuje.
#
# Prirucka sa pregeneruje do docasneho suboru a porovna s tou v repe:
#
#   generator skoncil 0 a subory su zhodne   -> ciste, navratovy kod 0
#   generator skoncil 0 a subory sa lisia    -> prirucka je zastarana, kod 1
#   generator skoncil 5                      -> text odkazuje na neexistujucu cestu, kod 1
#   preklad alebo generator zlyhali inak     -> aktualnost sa NEDALA overit, kod 1
#
# Posledny pripad je oddeleny zamerne. Ked dolezity fakt zistit nejde (nepodari
# sa preklad), prirucka nie je dokazatelne zastarana ani dokazatelne aktualna;
# hlasit "zastarana" by bolo tvrdenie bez podkladu.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PRIRUCKA="$REPO_DIR/docs/PRIRUCKA.md"
GENERATOR="$SCRIPT_DIR/gen_prirucka.py"

TMP="$(mktemp)"
LOG="$(mktemp)"
trap 'rm -f "$TMP" "$LOG"' EXIT

if [ ! -f "$GENERATOR" ]; then
  echo "docs/PRIRUCKA.md: chyba generator scripts/gen_prirucka.py"
  exit 1
fi

if [ ! -f "$PRIRUCKA" ]; then
  echo "docs/PRIRUCKA.md neexistuje, spusti scripts/gen_prirucka.py"
  exit 1
fi

make -C "$REPO_DIR/vmicollect" >"$LOG" 2>&1
if [ $? -ne 0 ]; then
  echo "docs/PRIRUCKA.md: aktualnost sa nedala overit, 'make -C vmicollect' zlyhal"
  tail -n 20 "$LOG" | sed 's/^/  /'
  exit 1
fi

python3 "$GENERATOR" --out "$TMP" >"$LOG" 2>&1
rc=$?

if [ "$rc" -eq 5 ]; then
  echo "docs/PRIRUCKA.md odkazuje na cesty, ktore neexistuju"
  sed 's/^/  /' "$LOG"
  exit 1
fi

if [ "$rc" -ne 0 ]; then
  echo "docs/PRIRUCKA.md: aktualnost sa nedala overit, gen_prirucka.py skoncil kodom $rc"
  sed 's/^/  /' "$LOG"
  exit 1
fi

if ! cmp -s "$PRIRUCKA" "$TMP"; then
  echo "docs/PRIRUCKA.md je zastarana, spusti scripts/gen_prirucka.py"
  diff -u "$PRIRUCKA" "$TMP" | sed -n '3,40p' | sed 's/^/  /'
  exit 1
fi

echo "check_prirucka.sh: docs/PRIRUCKA.md sedi s kodom"
exit 0
