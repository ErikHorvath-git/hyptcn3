#!/usr/bin/env bash
# mix - náhodná podmnožina ostatných generátorov naraz (paralelne).
set -uo pipefail
RANDOM="${SEED:-1}"
DUR="${DUR:-120}"

# dostupné generátory (mix ich spúšťa podľa seedu)
AVAIL=(nginx_wrk pgbench build rsync_tar)
COUNT=$(( 2 + RANDOM % ${#AVAIL[@]} ))
chosen=()
idx=(0 1 2 3)
for i in $(seq 1 "$COUNT"); do
    k=$(( RANDOM % ${#idx[@]} ))
    chosen+=("${AVAIL[${idx[$k]}]}")
    idx=("${idx[@]:0:$k}" "${idx[@]:$((k+1))}")
done
echo "mix: seed=${SEED} dur=${DUR}s generatory: ${chosen[*]}"

HERE=$(dirname "$(readlink -f "$0")")
pids=()
for g in "${chosen[@]}"; do
    SEED=$(( SEED + RANDOM )) DUR="$DUR" bash "$HERE/$g.sh" &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || true; done
echo "mix: koniec"
