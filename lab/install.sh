#!/usr/bin/env bash
# Runs inside the benign lab VM only. Repeated deployments retain the database; a database of an older
# schema is recreated (lab/schema.sql) and seeded once with seed 0. A group of sessions starts from
# python3 /opt/hyptcn-lab/guest_state.py reset --seed S (protocol v5, proposal 5.4).
set -euo pipefail
cd /opt/hyptcn-lab
if ! command -v nginx >/dev/null || ! command -v psql >/dev/null || ! python3 -c 'import psycopg2' 2>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    timeout 240 apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 update
    timeout 240 apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 install -y nginx postgresql python3-psycopg2
fi
id hyptcnlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin hyptcnlab
systemctl enable --now postgresql nginx
# PostgreSQL keeps its defaults except autovacuum_naptime 67 s (proposal chapter 12, lead's answer to Q9, 2026-11-24).
# The deployed file is the setting, linked like the maintenance units below, so the guest manifest covers it; the
# restart applies it before the lab's units start again, and a server without it ends the deployment.
ln -sfn /opt/hyptcn-lab/hyptcn-lab-postgresql.conf /etc/postgresql/15/main/conf.d/hyptcn-lab.conf
systemctl restart postgresql@15-main
naptime=$(runuser -u postgres -- psql -XtAc 'SHOW autovacuum_naptime')
autovacuum=$(runuser -u postgres -- psql -XtAc 'SHOW autovacuum')
if [ "$naptime" != 67s ] || [ "$autovacuum" != on ]; then
    echo "PostgreSQL runs with autovacuum_naptime $naptime and autovacuum $autovacuum, not 67s and on" \
         "(lab/hyptcn-lab-postgresql.conf)" >&2
    exit 1
fi
if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='hyptcnlab'" | grep -qx 1; then
    runuser -u postgres -- createuser hyptcnlab
fi
if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='hyptcn_lab'" | grep -qx 1; then
    runuser -u postgres -- createdb --owner=hyptcnlab hyptcn_lab
fi
runuser -u hyptcnlab -- psql -v ON_ERROR_STOP=1 hyptcn_lab -f schema.sql
if [ ! -f /etc/hyptcn-lab.env ]; then
    # A subshell: the umask of the secret must not reach the static files and documents written below
    # (finding F5 of the B5a verification: nginx and the docs service could not read them on a new VM).
    (umask 077; python3 -c 'import secrets; print("LAB_SECRET=" + secrets.token_hex(32))' > /etc/hyptcn-lab.env)
fi
# Documents, reports, the report spool and the document log of lab/services.py (ReadWritePaths of the units);
# static files for nginx (www-data reads them).
install -d -m 0755 -o root -g root /var/lib/hyptcn-lab /var/lib/hyptcn-lab/static
install -d -m 0750 -o hyptcnlab -g hyptcnlab /var/lib/hyptcn-lab/docs /var/lib/hyptcn-lab/reports \
    /var/lib/hyptcn-lab/logs /var/lib/hyptcn-lab/spool /var/lib/hyptcn-lab/spool/queued \
    /var/lib/hyptcn-lab/spool/running /var/lib/hyptcn-lab/spool/failed
python3 seed.py static --seed 0 --out /var/lib/hyptcn-lab/static
if [ "$(runuser -u hyptcnlab -- psql -XtAc 'SELECT count(*) FROM products' hyptcn_lab)" = 0 ]; then
    python3 guest_state.py reset --seed 0
fi
install -m 644 hyptcn-lab@.service /etc/systemd/system/hyptcn-lab@.service
# Links as well: the deployed files are the units, so the guest manifest covers them.
ln -sfn /opt/hyptcn-lab/hyptcn-lab-udrzba.service /etc/systemd/system/hyptcn-lab-udrzba.service
ln -sfn /opt/hyptcn-lab/hyptcn-lab-udrzba.timer /etc/systemd/system/hyptcn-lab-udrzba.timer
# nginx workers (www-data) reopen their logs here after each segment cut;
# without search permission they keep writing to the closed file.
install -d -m 0755 -o root -g adm /var/log/hyptcn-lab
install -d -m 0750 -o root -g adm /var/log/hyptcn-lab/segments
install -m 644 nginx.conf /etc/nginx/conf.d/hyptcn-lab.conf
systemctl daemon-reload
# Package refreshes and maintenance jobs are not part of the benign workload
# model; they would change the guest or add unplanned activity mid-campaign.
# logrotate/dpkg-db-backup fire at midnight; systemd-tmpfiles-clean (static,
# 15 min after boot, then daily) can only be masked. The lab's own logs are
# cut between sessions by the collection runner. The runner records active
# timers in the guest identity, so a re-enabled one stops a campaign.
# The lab's own maintenance (hyptcn-lab-udrzba.timer) is part of the workload in every profile.
for timer in apt-daily.timer apt-daily-upgrade.timer man-db.timer fstrim.timer e2scrub_all.timer \
             logrotate.timer dpkg-db-backup.timer; do
    if systemctl list-unit-files "$timer" >/dev/null 2>&1; then systemctl disable --now "$timer" >/dev/null 2>&1 || true; fi
done
systemctl mask --now systemd-tmpfiles-clean.timer >/dev/null 2>&1
systemctl enable hyptcn-lab@auth hyptcn-lab@catalog hyptcn-lab@orders hyptcn-lab@docs hyptcn-lab@worker
# A deployment restarts every unit; the start counter of StartLimitBurst starts from zero again.
systemctl reset-failed 'hyptcn-lab@*' >/dev/null 2>&1 || true
systemctl restart hyptcn-lab@auth hyptcn-lab@catalog hyptcn-lab@orders hyptcn-lab@docs hyptcn-lab@worker
systemctl enable --now hyptcn-lab-udrzba.timer
nginx -t
systemctl reload nginx
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/healthz && curl -fsS http://127.0.0.1:8084/healthz >/dev/null; then
        echo
        echo 'Lab services ready'
        exit 0
    fi
    sleep 1
done
echo 'Lab services did not become healthy' >&2
exit 1
