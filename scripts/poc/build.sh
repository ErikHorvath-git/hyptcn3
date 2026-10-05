#!/usr/bin/env bash
# build.sh - G1: skompiluje lokálne PoC zdroje V HOSŤOVI a vráti SHA-256.
#
# Po spustení vypíše do stdout zoznam: <subor> <sha256> - tie idú do
# manifestu sedenia (injekcia.subor + sha256). Binárky ostávajú v /tmp
# overlayu a po sedení zmiznú s rever tom.
set -uo pipefail

HERE=$(dirname "$(readlink -f "$0")")
cd /tmp
gcc -O2 -o memfd_exec "$HERE/memfd_exec.c" || exit 2
gcc -shared -fPIC -o hider.so "$HERE/hider.c" -ldl || exit 2
sha256sum memfd_exec hider.so
echo "poc_build: ok - /tmp/memfd_exec, /tmp/hider.so"
