#!/usr/bin/env bash
# rsync_tar - I/O záťaž: generovanie dát, rsync kópia, tar|zstd kompresia.
set -uo pipefail
command -v rsync >/dev/null || { echo "rsync_tar: chyba rsync" >&2; exit 2; }
command -v zstd >/dev/null || { echo "rsync_tar: chyba zstd (apt_packages: zstd)" >&2; exit 2; }

RANDOM="${SEED:-1}"
FILES=$(( 5 + RANDOM % 40 ))
SIZE_KB=$(( 16 + RANDOM % 1024 ))
DUR="${DUR:-120}"
echo "rsync_tar: files=$FILES size=${SIZE_KB}kB dur=${DUR}s"

W=/tmp/rsync_work
rm -rf "$W"; mkdir -p "$W/src"
for i in $(seq 1 "$FILES"); do
    head -c $((SIZE_KB * 1024)) /dev/urandom > "$W/src/f$i"
done

T0=$(date +%s)
ROUND=0
while [ $(( $(date +%s) - T0 )) -lt "$DUR" ]; do
    ROUND=$((ROUND+1))
    rm -rf "$W/dst" "$W/a.tar.zst"
    rsync -a "$W/src/" "$W/dst/"
    tar -C "$W/src" -cf - . | zstd -q -o "$W/a.tar.zst"
    SZ=$(du -sk "$W/src" | cut -f1)
    echo "  kolo $ROUND: ${SZ}kB src -> dst + tar.zst"
done
echo "rsync_tar: koniec"
