#!/usr/bin/env bash
# Runs inside the benign lab VM only. Repeated deployments retain the database.
set -euo pipefail
cd /opt/hyptcn-lab
if ! command -v nginx >/dev/null || ! command -v psql >/dev/null || ! python3 -c 'import psycopg2' 2>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    timeout 240 apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 update
    timeout 240 apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 install -y nginx postgresql python3-psycopg2
fi
id hyptcnlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin hyptcnlab
systemctl enable --now postgresql nginx
if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='hyptcnlab'" | grep -qx 1; then
    runuser -u postgres -- createuser hyptcnlab
fi
if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='hyptcn_lab'" | grep -qx 1; then
    runuser -u postgres -- createdb --owner=hyptcnlab hyptcn_lab
fi
runuser -u hyptcnlab -- psql -v ON_ERROR_STOP=1 hyptcn_lab -f schema.sql
if [ ! -f /etc/hyptcn-lab.env ]; then
    umask 077
    python3 -c 'import secrets; print("LAB_SECRET=" + secrets.token_hex(32))' > /etc/hyptcn-lab.env
fi
install -m 644 hyptcn-lab@.service /etc/systemd/system/hyptcn-lab@.service
install -m 644 nginx.conf /etc/nginx/conf.d/hyptcn-lab.conf
systemctl daemon-reload
systemctl enable hyptcn-lab@auth hyptcn-lab@catalog hyptcn-lab@orders hyptcn-lab@worker
systemctl restart hyptcn-lab@auth hyptcn-lab@catalog hyptcn-lab@orders hyptcn-lab@worker
nginx -t
systemctl reload nginx
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/healthz; then
        echo
        echo 'Lab services ready'
        exit 0
    fi
    sleep 1
done
echo 'Lab services did not become healthy' >&2
exit 1
