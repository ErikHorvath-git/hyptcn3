#!/usr/bin/env bash
# mikrosluzby.sh - C: realisticka "produkcna" premavka v hostovi.
#
# Topologia (vsetko lokalne v hostovi):
#   klienti (wrk + curl slucka) -> nginx (router/lb :80)
#        -> /auth  -> python sluzba auth (:8081)
#        -> /orders-> python sluzba orders (:8082) -> PostgreSQL (trafficdb)
#        -> /      -> staticke subory (nginx)
#   pgbench (periodicky, seedovany) -> PostgreSQL
#   sluzby zapisuju logy (suborova aktivita), restartuju sa (procesova
#   churn), sockety vznika/zanikaju - vsetko to, co per-bin priznaky a
#   prediktor maju vidiet pri REALNEJ premavke.
#
# SEED vybera mix premavky, DUR je dlzka behu v sekundach.
set -uo pipefail
export PATH=/usr/bin:/bin
DUR="${DUR:-120}"
SEED="${SEED:-1}"
LOGDIR=/var/log/mikrosluzby
mkdir -p "$LOGDIR"

cleanup() {
    pkill -f "mikro_auth" 2>/dev/null || true
    pkill -f "mikro_orders" 2>/dev/null || true
    pkill -f pgbench 2>/dev/null || true
    pkill -f "wrk " 2>/dev/null || true
}
trap cleanup EXIT

# --- postgres + pgbench init -------------------------------------------------
pg_ctlcluster 15 main start >/dev/null 2>&1 || true
sleep 1
su postgres -c "createdb trafficdb" >/dev/null 2>&1 || true
# init (minuty) len ked trafficdb este nema data - snapshot ho ma
# predpripraveny, takze sedenia ho preskocia
if ! su postgres -c "psql -t -A trafficdb -c 'select 1 from pgbench_accounts limit 1'" 2>/dev/null | grep -q 1; then
    su postgres -c "pgbench -i -s 10 trafficdb" >/dev/null 2>&1 || true
fi
echo "mikrosluzby: pgbench init ok (trafficdb)"

# --- backendove sluzby (python, bez instalacii) ------------------------------
cat > /tmp/mikro_auth.py <<'PY'
import http.server, socketserver, sys, time, random
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(random.uniform(0.002, 0.02))
        body = (b'{"user": "u%d", "token": "%x", "sluzba": "auth"}\n'
                % (random.randint(1, 99), random.getrandbits(64)))
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        open("/var/log/mikrosluzby/auth.log", "a").write("%s\n" % (self.path,))
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 8081), H).serve_forever()
PY
cat > /tmp/mikro_orders.py <<'PY'
import http.server, socketserver, subprocess, random
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # kazdy request = dotaz do postgres (realna IO aktivita)
        try:
            out = subprocess.check_output(
                ["su", "postgres", "-c",
                 "psql -t -A trafficdb -c \"select count(*) from "
                 "pgbench_accounts\""], timeout=3)
        except Exception:
            out = b"-1"
        body = b'{"orders": %s, "sluzba": "orders"}\n' % out.strip()
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        open("/var/log/mikrosluzby/orders.log", "a").write("%s\n" % (self.path,))
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 8082), H).serve_forever()
PY
python3 /tmp/mikro_auth.py & AUTH_PID=$!
python3 /tmp/mikro_orders.py & ORD_PID=$!
sleep 2
echo "mikrosluzby: backends auth=8081 orders=8082 (pid $AUTH_PID,$ORD_PID)"

# --- nginx ako router --------------------------------------------------------
cat > /etc/nginx/conf.d/mikrosluzby.conf <<'NGX'
upstream auth_svc   { server 127.0.0.1:8081; }
upstream orders_svc { server 127.0.0.1:8082; }
server {
    listen 80;
    location /auth   { proxy_pass http://auth_svc; }
    location /orders { proxy_pass http://orders_svc; }
}
NGX
# default server (listen 80 default_server) by vyhral pred nasim serverom
# na rovnakom porte - musi prec, inak /auth a /orders padaju na 404
rm -f /etc/nginx/sites-enabled/default
nginx -s reload 2>/dev/null || systemctl restart nginx >/dev/null 2>&1 || true
sleep 1
echo "mikrosluzby: nginx router ok"

# --- premavka (mix podla seedu) ----------------------------------------------
RANDOM="$SEED"
END=$((SECONDS + DUR))
while [ $SECONDS -lt $END ]; do
    # hlavna zataz: wrk cez router (periodicka vlna)
    wrk -t2 -c20 -d3s http://127.0.0.1/orders >/dev/null 2>&1 &
    sleep 1
    # druhy druh premavky: autorizacia + statika cez curl slucku
    for i in $(seq 1 $((3 + RANDOM % 8))); do
        curl -s http://127.0.0.1/auth >/dev/null 2>&1
        curl -s http://127.0.0.1/ >/dev/null 2>&1
    done
    # periodicky pgbench (transakcna zataz s nahodnou fazou)
    if [ $((RANDOM % 4)) -eq 0 ]; then
        su postgres -c "pgbench -c 4 -T 3 trafficdb" >/dev/null 2>&1 &
    fi
    sleep 2
done
# POZOR: bezargumentovy `wait` by cakal aj na backendove sluzby
# (auth/orders), ktore bezia az do cleanu - zatazove joby sa nechaju
# dobehnut cez trap, ktory ich zabije.
echo "mikrosluzby: koniec (${DUR}s, seed=$SEED)"
