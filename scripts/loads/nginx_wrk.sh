#!/usr/bin/env bash
# nginx_wrk - webová záťaž: nginx servuje vygenerované súbory, wrk ich
# bombarduje. Všetky parametre sú odvodené zo seedu.
set -uo pipefail
command -v nginx >/dev/null || { echo "nginx_wrk: chyba nginx (nainstaluj cez manifest sedenia: apt_packages)" >&2; exit 2; }
command -v wrk >/dev/null || { echo "nginx_wrk: chyba wrk" >&2; exit 2; }

RANDOM="${SEED:-1}"
THREADS=$(( 1 + RANDOM % 8 ))
CONNS=$(( THREADS * (2 + RANDOM % 20) ))
FILES=$(( 10 + RANDOM % 200 ))
SIZE_KB=$(( 1 + RANDOM % 64 ))
DUR="${DUR:-120}"
echo "nginx_wrk: threads=$THREADS conns=$CONNS files=$FILES size=${SIZE_KB}kB dur=${DUR}s"

W=/tmp/nginx_wrk
mkdir -p "$W"
for i in $(seq 1 "$FILES"); do
    head -c $((SIZE_KB * 1024)) /dev/urandom > "$W/f$i"
done
cat > /tmp/nginx_wrk.conf <<EOF
pid /tmp/nginx.pid;
error_log /dev/null;
events { worker_connections 1024; }
http {
  access_log off;
  server {
    listen 127.0.0.1:8091;
    location / { root $W; }
  }
}
EOF
nginx -c /tmp/nginx_wrk.conf
trap 'nginx -c /tmp/nginx_wrk.conf -s quit 2>/dev/null' EXIT

T0=$(date +%s)
while [ $(( $(date +%s) - T0 )) -lt "$DUR" ]; do
    wrk -t"$THREADS" -c"$CONNS" -d5s "http://127.0.0.1:8091/f$(( 1 + RANDOM % FILES ))" 2>/dev/null \
        | grep -E "Requests/sec|Transfer/sec" | sed 's/^/  /'
done
echo "nginx_wrk: koniec"
