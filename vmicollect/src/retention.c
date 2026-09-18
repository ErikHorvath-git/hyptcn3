/*
 * retention.c - automaticke mazanie starych snimok.
 *
 * Periodicky zber zaplni disk rychlejsie ako si myslis: 4 GiB VM
 * kazdych 5 s = 2.8 TB/h. Bez retencie ti to zabije stroj skor ako
 * stihnes nieco zmerat.
 *
 * JEDNA VEC, KTORA TU NIE JE ZREJMA:
 * Pri delta zbere sa NESMIE zmazat plna snimka bez jej delt - zvysok
 * retazca by sa uz nedal obnovit. Preto sa maze po CELYCH RETAZCOCH,
 * nie po jednotlivych suboroch. Pri raw zbere je kazdy subor sam sebe
 * retazcom, takze rovnaky kod funguje pre oboje.
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DELTA_EXT ".vmicd"

typedef struct {
    char     path[VMIC_PATH_MAX];
    char     sidecar[VMIC_PATH_MAX];
    bool     has_sidecar;
    uint64_t chain_id;      /* 0 = samostatny subor (raw)             */
    uint64_t bytes;
    int64_t  mtime_ns;      /* POZOR: nanosekundy, nie sekundy!       */
} item_t;

typedef struct {
    uint64_t chain_id;
    uint64_t bytes;
    int64_t  newest_ns;     /* najmladsi subor v retazci              */
    size_t   count;
    size_t  *idx;           /* indexy do pola poloziek                */
    size_t   idx_cap;
} chain_t;

static bool ends_with(const char *s, const char *suf)
{
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

static bool is_snapshot_file(const char *name)
{
    return ends_with(name, ".raw")    || ends_with(name, ".raw.gz") ||
           ends_with(name, ".elf")    || ends_with(name, ".elf.gz") ||
           ends_with(name, DELTA_EXT);
}

/* Z hlavicky .vmicd suboru precita id retazca. 0 = nie je delta. */
static uint64_t read_chain_id(const char *path)
{
    if (!ends_with(path, DELTA_EXT)) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    uint8_t hdr[24];
    ssize_t n = vmic_read_full(fd, hdr, sizeof(hdr));
    close(fd);
    if (n != (ssize_t)sizeof(hdr) || memcmp(hdr, "VMICDLT1", 8) != 0) return 0;
    uint64_t id = 0;
    for (int i = 7; i >= 0; i--) id = (id << 8) | hdr[16 + i];
    return id;
}

/*
 * Zoradenie od najstarsieho po najnovsi.
 *
 * PRECO NANOSEKUNDY: pri kratkej periode vznikne cely retazec v ramci
 * jednej sekundy. Keby sme porovnavali len st_mtime (sekundy), vsetky
 * retazce by boli "rovnako stare", qsort() nie je stabilny a poradie by
 * bolo nahodne - retencia by potom vedela zmazat aj retazec, do ktoreho
 * sa prave zapisuje, a jeho delty by uz neslo obnovit.
 *
 * Ako druhy kluc pouzivame chain_id, ktore je samo o sebe casovou
 * peciatkou v milisekundach - takze poradie je vzdy jednoznacne.
 */
static int cmp_chain_age(const void *a, const void *b)
{
    const chain_t *x = (const chain_t *)a;
    const chain_t *y = (const chain_t *)b;
    if (x->newest_ns < y->newest_ns) return -1;
    if (x->newest_ns > y->newest_ns) return 1;
    if (x->chain_id  < y->chain_id)  return -1;
    if (x->chain_id  > y->chain_id)  return 1;
    return 0;
}

int vmic_retention_apply(const vmic_config_t *cfg, uint64_t protect_chain)
{
    if (!cfg->max_snapshots && !cfg->max_bytes && cfg->max_age_s <= 0.0)
        return VMIC_OK;                       /* retencia je vypnuta */

    DIR *d = opendir(cfg->dir);
    if (!d) {
        LOGW("retencia: nedaji sa otvorit '%s': %s", cfg->dir, strerror(errno));
        return VMIC_ERR;
    }

    size_t cap = 128, n = 0;
    item_t *items = malloc(cap * sizeof(*items));
    if (!items) { closedir(d); return VMIC_ERR; }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;     /* .part a spol. ignorujeme */
        if (!is_snapshot_file(e->d_name)) continue;

        char path[VMIC_PATH_MAX];
        if (vmic_join(path, sizeof(path), cfg->dir, e->d_name) != 0) continue;

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (n == cap) {
            cap *= 2;
            item_t *bigger = realloc(items, cap * sizeof(*items));
            if (!bigger) { free(items); closedir(d); return VMIC_ERR; }
            items = bigger;
        }
        item_t *it = &items[n];
        memset(it, 0, sizeof(*it));
        snprintf(it->path, sizeof(it->path), "%s", path);
        it->bytes    = (uint64_t)st.st_blocks * 512;
        it->mtime_ns = (int64_t)st.st_mtim.tv_sec * 1000000000LL
                     + (int64_t)st.st_mtim.tv_nsec;
        it->chain_id = read_chain_id(path);

        /* k snimke patri aj .json - odrezeme priponu a skusime */
        char base[VMIC_PATH_MAX];
        snprintf(base, sizeof(base), "%s", path);
        char *dot = strrchr(base, '.');
        if (dot && strcmp(dot, ".gz") == 0) {  /* .raw.gz -> odrezat dvakrat */
            *dot = '\0';
            dot = strrchr(base, '.');
        }
        if (dot) {
            *dot = '\0';
            snprintf(it->sidecar, sizeof(it->sidecar), "%s.json", base);
            struct stat sst;
            if (stat(it->sidecar, &sst) == 0) {
                it->has_sidecar = true;
                it->bytes += (uint64_t)sst.st_blocks * 512;
            }
        }
        n++;
    }
    closedir(d);

    if (n == 0) { free(items); return VMIC_OK; }

    /* --- zoskupenie do retazcov --------------------------------- */
    chain_t *chains = calloc(n, sizeof(*chains));
    if (!chains) { free(items); return VMIC_ERR; }
    size_t cn = 0;

    for (size_t i = 0; i < n; i++) {
        chain_t *c = NULL;
        if (items[i].chain_id) {
            for (size_t k = 0; k < cn; k++)
                if (chains[k].chain_id == items[i].chain_id) { c = &chains[k]; break; }
        }
        if (!c) {
            c = &chains[cn++];
            c->chain_id = items[i].chain_id;
            c->idx_cap  = 8;
            c->idx      = malloc(c->idx_cap * sizeof(size_t));
            if (!c->idx) goto oom;
            c->count     = 0;
            c->bytes     = 0;
            c->newest_ns = 0;
        }
        if (c->count == c->idx_cap) {
            c->idx_cap *= 2;
            size_t *bigger = realloc(c->idx, c->idx_cap * sizeof(size_t));
            if (!bigger) goto oom;
            c->idx = bigger;
        }
        c->idx[c->count++] = i;
        c->bytes += items[i].bytes;
        if (items[i].mtime_ns > c->newest_ns) c->newest_ns = items[i].mtime_ns;
    }

    qsort(chains, cn, sizeof(*chains), cmp_chain_age);   /* najstarsie prve */

    /* --- co vsetko mame --------------------------------------- */
    uint64_t total_bytes = 0, total_files = 0;
    for (size_t k = 0; k < cn; k++) {
        total_bytes += chains[k].bytes;
        total_files += chains[k].count;
    }

    struct timespec now_ts;
    clock_gettime(CLOCK_REALTIME, &now_ts);
    int64_t now_ns = (int64_t)now_ts.tv_sec * 1000000000LL + now_ts.tv_nsec;

    size_t removed_chains = 0;
    uint64_t removed_bytes = 0, removed_files = 0;

    /*
     * CO SA NESMIE ZMAZAT.
     *
     * Zberac prave zapisuje do jedneho konkretneho retazca a ten musi
     * prezit - bez jeho plnej snimky su vsetky jeho delty nepouzitelne.
     * Identifikujeme ho podla ID, nie podla casu suboru: staci, aby do
     * adresara nieco zapisal iny proces (druha instancia, kopirovanie
     * dumpu, posun hodin) a "najnovsi podla mtime" by uz bol niekto iny.
     *
     * Ako poistku (napr. pri raw writeri, kde ziadne ID neexistuje)
     * chranime aj retazec s najnovsim casom.
     */
    size_t protect = 0;
    for (size_t k = 1; k < cn; k++)
        if (cmp_chain_age(&chains[k], &chains[protect]) > 0) protect = k;

    size_t protect_by_id = (size_t)-1;
    if (protect_chain) {
        for (size_t k = 0; k < cn; k++)
            if (chains[k].chain_id == protect_chain) { protect_by_id = k; break; }
    }

    for (size_t k = 0; k < cn; k++) {
        if (k == protect || k == protect_by_id) continue;
        bool drop = false;
        const char *why = "";

        if (cfg->max_snapshots && total_files > cfg->max_snapshots) {
            drop = true; why = "pocet";
        }
        if (!drop && cfg->max_bytes && total_bytes > cfg->max_bytes) {
            drop = true; why = "velkost";
        }
        if (!drop && cfg->max_age_s > 0.0 &&
            (double)(now_ns - chains[k].newest_ns) / 1e9 > cfg->max_age_s) {
            drop = true; why = "vek";
        }
        if (!drop) continue;

        for (size_t j = 0; j < chains[k].count; j++) {
            item_t *it = &items[chains[k].idx[j]];
            if (unlink(it->path) == 0) {
                removed_files++;
                LOGD("retencia: zmazane %s (%s)", it->path, why);
            } else {
                LOGW("retencia: nedaji sa zmazat %s: %s", it->path, strerror(errno));
            }
            if (it->has_sidecar) unlink(it->sidecar);
        }
        total_files -= chains[k].count;
        total_bytes -= chains[k].bytes;
        removed_bytes += chains[k].bytes;
        removed_chains++;
    }

    if (removed_files) {
        char human[32];
        vmic_human_size(removed_bytes, human, sizeof(human));
        LOGI("retencia: zmazanych %" PRIu64 " suborov (%zu %s, %s), "
             "zostava %" PRIu64,
             removed_files, removed_chains,
             removed_chains == 1 ? "retazec" : "retazcov", human, total_files);
    }

    for (size_t k = 0; k < cn; k++) free(chains[k].idx);
    free(chains);
    free(items);
    return VMIC_OK;

oom:
    for (size_t k = 0; k < cn; k++) free(chains[k].idx);
    free(chains);
    free(items);
    LOGE("retencia: nedostatok pamate");
    return VMIC_ERR;
}
