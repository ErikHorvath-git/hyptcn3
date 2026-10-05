/*
 * memfd_exec.c - fileless spustenie (G1).
 *
 * Vytvori anonymny subor cez memfd_create, zapise do neho payload (z
 * premennej PAYLOAD, default /bin/sleep) a spusti ho cez fexecve. Na disku
 * po spusteni nezostane ziadny subor - proces bezi z cistej pamate.
 *
 * Preklad (v hostovi): gcc -O2 -o memfd_exec memfd_exec.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *payload = "/bin/sleep";
    if (argc > 1) payload = argv[1];
    const char *davka = (argc > 2) ? argv[2] : "5";

    int fd = syscall(SYS_memfd_create, "hyptcn", MFD_CLOEXEC);
    if (fd < 0) { perror("memfd_create"); return 1; }

    FILE *in = fopen(payload, "rb");
    if (!in) { perror(payload); return 1; }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        size_t off = 0;
        while (off < n) {
            ssize_t w = write(fd, buf + off, n - off);
            if (w <= 0) { perror("write"); return 1; }
            off += (size_t)w;
        }
    }
    fclose(in);

    char *cargv[] = {(char *)"hyptcn-memfd", (char *)davka, NULL};
    char *cenv[] = {"PATH=/usr/bin:/bin", NULL};
    printf("memfd_exec: spustam %s (%zu bajtov z pamate), pid %ld\n",
           payload, (size_t)lseek(fd, 0, SEEK_END), (long)getpid());
    fflush(stdout);
    fexecve(fd, cargv, cenv);
    perror("fexecve");
    return 1;
}
