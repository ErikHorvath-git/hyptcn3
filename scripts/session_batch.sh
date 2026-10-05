#!/usr/bin/env bash
#
# session_batch.sh - JEDEN sudo = N sedení za sebou (blok B5).
#
#   sudo scripts/root_run.sh batch <pocet> [--manifest <cesta>]
#                                   [--label <label>] [--seed-zaciatok N]
#                                   [--dlhy-beh <sekundy>] [--pauza N]
#
# Kazde sedenie = session.sh s inym seedom a stampom (manifest na disku
# nemeni, sedenie si robi vlastnu kopiu argumentov). Sedenia idu za sebou;
# pri chybe skonci a vypise, ktore presli. Po kazdom sedeni kratka pauza,
# aby sa VM medzi behmi usadila.
#
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$HERE")
MANIFEST="$REPO/harness/session_manifest.example.json"
LABEL="idle"
SEED_START=100
PAUZA=20
DRY=0
COUNT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --label)    LABEL="$2"; shift 2 ;;
        --seed-zaciatok) SEED_START="$2"; shift 2 ;;
        --pauza)    PAUZA="$2"; shift 2 ;;
        --dry-run)  DRY=1; shift ;;
        *) [ -z "$COUNT" ] && COUNT="$1" && shift \
             || { echo "session_batch: neznamy argument $1" >&2; exit 2; } ;;
    esac
done
[ -n "$COUNT" ] || { echo "pouzitie: session_batch.sh <pocet> [--manifest C] [--label L]" >&2; exit 2; }

[ -f "$MANIFEST" ] || { echo "session_batch: manifest $MANIFEST neexistuje" >&2; exit 2; }

PASS=0; FAIL=0
for i in $(seq 1 "$COUNT"); do
    SEED=$((SEED_START + i - 1))
    BM="/tmp/hyptcn_batch_manifest.$$.json"
    jq --arg s "$SEED" --arg l "$LABEL" \
        '.seed = ($s | tonumber) | .label = $l' "$MANIFEST" > "$BM" \
        || { echo "session_batch: jq zlyhal" >&2; exit 2; }
    echo "=== session_batch: sedenie $i/$COUNT (seed=$SEED, label=$LABEL) ==="
    LOG="$REPO/data/sessions/batch_$(date -u +%Y%m%dT%H%M%SZ)_$LABEL.log"
    if [ "$DRY" -eq 1 ]; then
        "$HERE/session.sh" "$BM" --dry-run && PASS=$((PASS+1)) \
            || { FAIL=$((FAIL+1)); echo "session_batch: dry-run $i zlyhal"; }
    elif setsid "$HERE/session.sh" "$BM" > "$LOG" 2>&1; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "session_batch: sedenie $i zlyhalo - koncim (log: $LOG)" >&2
        rm -f "$BM"
        break
    fi
    rm -f "$BM"
    [ "$i" -lt "$COUNT" ] && sleep "$PAUZA"
done
echo "session_batch: hotovo - preslo $PASS, zlyhalo $FAIL"
[ "$FAIL" -eq 0 ]
