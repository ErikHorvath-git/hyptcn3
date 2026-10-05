#!/usr/bin/env bash
# pgbench - databázová záťaž PostgreSQL. Parametre zo seedu.
set -uo pipefail
command -v pgbench >/dev/null || { echo "pgbench: chyba pgbench (apt_packages: postgresql)" >&2; exit 2; }

RANDOM="${SEED:-1}"
SCALE=$(( 1 + RANDOM % 10 ))
CLIENTS=$(( 1 + RANDOM % 16 ))
DUR="${DUR:-120}"
echo "pgbench: scale=$SCALE clients=$CLIENTS dur=${DUR}s"

service postgresql start >/dev/null 2>&1 || true
sleep 2
su postgres -c "psql -c 'DROP DATABASE IF EXISTS bench;' -c 'CREATE DATABASE bench;'" >/dev/null 2>&1
su postgres -c "pgbench -i -s $SCALE bench" >/dev/null 2>&1
T0=$(date +%s)
while [ $(( $(date +%s) - T0 )) -lt "$DUR" ]; do
    su postgres -c "pgbench -c $CLIENTS -j 2 -T 5 bench" 2>/dev/null \
        | grep -E "tps|latency" | sed 's/^/  /'
done
echo "pgbench: koniec"
