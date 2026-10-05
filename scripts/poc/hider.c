/*
 * hider.c - LD_PRELOAD "hider" (G1, userspace demo).
 *
 * SKRYVA adresar /tmp/hidden v readdir(): proces, ktory nacita tuto
 * kniznicu, ho v 'ls' neuvidi. TOTO NIE JE ROOTKIT - je to klasicka
 * userspace technika (LD_PRELOAD), ktorou sa da oklamat bezny nastroj
 * bez akehokolvek zasahu do jadra. Sluzi ako ground-truth pre citlivost
 * systemu: zberca (per-bin priznaky) by mala vidiet aktivitu, ktora
 * v pozemnej pravde procesov NIE JE (porovnanie ps z hosta vs. zo snimky).
 *
 * Preklad (v hostovi, scripts/poc/build.sh):  gcc -shared -fPIC -o hider.so hider.c -ldl
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>

static const char *SKRYTE = "/tmp/hidden";

typedef struct dirent *(*readdir_fn)(DIR *);
static readdir_fn real_readdir = NULL;

struct dirent *readdir(DIR *dirp)
{
    if (!real_readdir)
        real_readdir = (readdir_fn)dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real_readdir(dirp)) != NULL) {
        if (e->d_name[0] == '.' && (e->d_name[1] == '\0' ||
            (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;                      /* . a .. nechaj tak */
        if (strcmp(e->d_name, "hidden") == 0) {
            /* /tmp sa neda z readdir identifikovat priamo; skryjeme kazdy
               zaznam s tymto menom - pre demo staci */
            continue;
        }
        break;
    }
    return e;
}
