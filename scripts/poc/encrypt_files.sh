#!/usr/bin/env bash
# encrypt_files.sh - G1: sifrovanie testovacich suborov.
# Zaifruje /tmp/victim/** (deterministicky seed -> rovnaky kluc), originaly
# zmaze. Pozemna pravda: subory pred/po (ls + sha256).
set -uo pipefail
command -v openssl >/dev/null || { echo "encrypt_files: chyba openssl" >&2; exit 2; }

SEED="${SEED:-1}"
DIR=/tmp/victim
RANDOM="$SEED"
N=$(( 5 + RANDOM % 20 ))
SIZE_KB=$(( 4 + RANDOM % 64 ))

rm -rf "$DIR"; mkdir -p "$DIR"
for i in $(seq 1 "$N"); do
    head -c $((SIZE_KB * 1024)) /dev/urandom > "$DIR/doc$i.txt"
done
echo "encrypt_files: $N suborov po ${SIZE_KB}kB v $DIR, seed=$SEED"

KEY=$(head -c 32 /dev/urandom | openssl enc -base64 -A 2>/dev/null || true)
ENC=0
for f in "$DIR"/*; do
    openssl enc -aes-256-cbc -salt -in "$f" -out "$f.enc" -pass "pass:$SEED" 2>/dev/null \
        && rm -f "$f" && ENC=$((ENC+1))
done
echo "encrypt_files: zasifrovanych $ENC, originály zmazané"
sleep "${DUR:-10}"
