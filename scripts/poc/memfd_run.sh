#!/usr/bin/env bash
# memfd_run.sh - G1: zbuildi memfd_exec v hostovi a spusti /bin/sh z pamate
# (fileless). Ground truth: ziadny novy subor na disku, ale novy proces bezi.
set -uo pipefail
DUR="${DUR:-60}"

command -v gcc >/dev/null || { echo "memfd_run: chyba gcc" >&2; exit 2; }
mkdir -p /tmp/memfd_build
cat > /tmp/memfd_build/memfd_exec.c <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    int fd = syscall(SYS_memfd_create, "hyptcn", 0);
    if (fd < 0) { perror("memfd_create"); return 1; }
    FILE *in = fopen("/bin/sh", "rb");
    if (!in) { perror("sh"); return 1; }
    char buf[65536]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        size_t o = 0;
        while (o < n) {
            ssize_t w = write(fd, buf + o, n - o);
            if (w <= 0) { perror("write"); return 1; }
            o += (size_t)w;
        }
    }
    fclose(in);
    char *av[] = {"hyptcn-memfd", "-c", "echo memfd_zije; sleep 55", NULL};
    char *env[] = {"PATH=/usr/bin:/bin", NULL};
    printf("memfd_run: spustam /bin/sh z pamate (pid %ld)\\n", (long)getpid());
    fflush(stdout);
    fexecve(fd, av, env);
    perror("fexecve");
    return 1;
}
C
gcc -O2 -o /tmp/memfd_build/memfd_exec /tmp/memfd_build/memfd_exec.c || exit 2
END=$((SECONDS + DUR))
while [ $SECONDS -lt $END ]; do
    /tmp/memfd_build/memfd_exec &
    sleep 3
    pkill -f hyptcn-memfd 2>/dev/null || true
done
echo "memfd_run: koniec (${DUR}s)"
