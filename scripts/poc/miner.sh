#!/usr/bin/env bash
# miner.sh - G1: kryptominer (xmrig) z pripnutého release.
#
# URL a SHA-256 sa berú z manifestu sedenia (alebo premenných) - binárka
# NIKDY nejde do gitu. Beží DUR sekúnd na obmedzených vláknach.
set -uo pipefail

URL="${MINER_URL:?nastav MINER_URL v manifeste}"
SHA="${MINER_SHA:?nastav MINER_SHA v manifeste}"
DUR="${DUR:-60}"
THREADS="${MINER_THREADS:-1}"

command -v wget >/dev/null || { echo "miner: chyba wget" >&2; exit 2; }

cd /tmp
rm -rf miner_work; mkdir miner_work; cd miner_work
wget -q -O miner.tar.gz "$URL" || { echo "miner: stiahnutie zlyhalo"; exit 2; }
echo "$SHA  miner.tar.gz" | sha256sum -c - >/dev/null || { echo "miner: SHA-256 nesedi"; exit 2; }
tar xzf miner.tar.gz
BIN=$(find . -type f -name 'xmrig' | head -1)
[ -n "$BIN" ] || { echo "miner: xmrig sa v archíve nenašiel"; exit 2; }
echo "miner: $BIN, ${THREADS} vlakien, ${DUR}s"
"$BIN" --threads="$THREADS" --url=pool.supportxmr.com:443 --user=not-a-real-miner \
       --donate-level=0 > miner.log 2>&1 &
MPID=$!
sleep "$DUR"
kill "$MPID" 2>/dev/null || true
echo "miner: koniec (log: /tmp/miner_work/miner.log)"
