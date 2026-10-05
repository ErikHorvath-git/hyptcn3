#!/usr/bin/env bash
# build - kompilácia: vygeneruje N malých C súborov a prekladá ich.
# Parametre zo seedu. (apt_packages: gcc)
set -uo pipefail
command -v gcc >/dev/null || { echo "build: chyba gcc (apt_packages: gcc)" >&2; exit 2; }

RANDOM="${SEED:-1}"
FILES=$(( 4 + RANDOM % 24 ))
FUNCS=$(( 10 + RANDOM % 200 ))
DUR="${DUR:-120}"
echo "build: files=$FILES funcs=$FUNCS dur=${DUR}s"

W=/tmp/build_work
rm -rf "$W"; mkdir -p "$W"
for f in $(seq 1 "$FILES"); do
    {
        for i in $(seq 1 "$FUNCS"); do
            echo "int f${f}_${i}(int x){ return x ^ $((RANDOM % 100000)); }"
        done
        echo "int main(void){ int s=0;"
        for i in $(seq 1 "$FUNCS"); do echo "s += f${f}_${i}($i);"; done
        echo "return s & 1; }"
    } > "$W/gen$f.c"
done

T0=$(date +%s)
ROUND=0
while [ $(( $(date +%s) - T0 )) -lt "$DUR" ]; do
    ROUND=$((ROUND+1))
    for f in $(seq 1 "$FILES"); do
        gcc -O2 -o "$W/gen$f" "$W/gen$f.c" 2>/dev/null || true
    done
    echo "  kolo $ROUND: $FILES suborov prelozenych"
done
echo "build: koniec"
