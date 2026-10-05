#!/usr/bin/env bash
#
# run.sh - spustí jeden generátor benígnej záťaže V HOSŤOVI (blok C).
#
#   scripts/loads/run.sh <load> [--seed N] [--dur S] [--out LOG]
#
# <load> je meno generátora: idle, nginx_wrk, pgbench, build, rsync_tar, mix.
# Seed riadi VŠETKY náhodné parametre (RANDOM=$seed + odvodené), takže beh
# je reprodukovateľný. Skript beží v hosťovi cez guest_exec.sh (ssh alebo
# guest-agent); výstup generátora (seed, parametre, merané čísla) ide na
# stdout volajúceho a patrí do manifestu sedenia.
#
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
GUEST_EXEC="$REPO/scripts/guest_exec.sh"

LOAD="${1:?pouzitie: run.sh <load> [--seed N] [--dur S]}"
shift
SEED="${LOAD_SEED:-$(( $(date +%s) % 100000 ))}"
DUR="${LOAD_DUR:-120}"

while [ $# -gt 0 ]; do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --dur)  DUR="$2"; shift 2 ;;
        *) echo "run.sh: neznamy prepinac $1" >&2; exit 2 ;;
    esac
done

GEN="$REPO/scripts/loads/${LOAD}.sh"
[ -f "$GEN" ] || { echo "run.sh: nepoznam generator '$LOAD' (subor $GEN chyba)" >&2; exit 2; }

echo "load: $LOAD, seed=$SEED, dur=$DUR s"
# guest_exec.sh NEPREPOSIELA stdin (zamerne, pozri jeho hlavicku), takže
# telo generátora sa do hosťa dostane cez base64 - žiadne dočasné súbory.
B64=$(base64 -w0 "$GEN")
"$GUEST_EXEC" -- "echo $B64 | base64 -d | SEED=$SEED DUR=$DUR bash -s"
