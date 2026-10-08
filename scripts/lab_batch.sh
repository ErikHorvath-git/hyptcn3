#!/usr/bin/env bash
# lab_batch.sh - K ohranicenych zberov labu za sebou (kalibracny korpus E3).
#
#   sudo scripts/lab_batch.sh <pocet> [--cykly 24] [--pauza 30]
#
# Kazdy zber = lab_capture.sh (24 cyklov, ~2 min, 0 zmeskanych slotov,
# nedestruktivny). Medzi zbermi kratka pauza; trvaly generátor premavky
# (labctl) bezi stale, takze kazdy zber zachyti iny usek prevadzky.
# Vystup: data/raw/<stamp>_lab pre kazdy zber + data/results/lab_*.json.
#
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
COUNT="${1:?pouzitie: lab_batch.sh <pocet> [--cykly N] [--pauza S]}"
shift
CYCLES=24
PAUZA=30

while [ $# -gt 0 ]; do
    case "$1" in
        --cykly) CYCLES="$2"; shift 2 ;;
        --pauza) PAUZA="$2"; shift 2 ;;
        *) echo "lab_batch: neznamy argument $1" >&2; exit 2 ;;
    esac
done

PASS=0
for i in $(seq 1 "$COUNT"); do
    echo "=== lab_batch: zber $i/$COUNT ($CYCLES cyklov) ==="
    if "$HERE/lab_capture.sh" "$CYCLES"; then
        PASS=$((PASS+1))
    else
        echo "lab_batch: zber $i zlyhal - koncim" >&2
        break
    fi
    [ "$i" -lt "$COUNT" ] && sleep "$PAUZA"
done
echo "lab_batch: hotovo - preslo $PASS/$COUNT zberov"
[ "$PASS" -eq "$COUNT" ]
