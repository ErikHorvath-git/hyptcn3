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

/*
 * Marker HOLD (subor 'HOLD' vo vystupnom adresari): retazce, ktore sa
 * NESMU zmazat, ani ked prekrocia retencne limity. Flight recorder: po
 * alarme oznacis retazec spred alarmu a forenzny material prezije
 * upratovanie. Marker cita kazdy beh vmic_retention_apply() z disku, takze
 * prezije aj restart zberaca - na rozdiel od ochrany aktivneho retazca,
 * ktora zije len v pamati.
 *
 * Format: jeden zaznam na riadok; prazdne riadky a riadky zacinajuce '#'
 * sa preskakuju. Zaznam je bud cislo = chain_id retazca (delta zber), alebo
 * meno suboru snimky (napr. pri raw zbere, kde chain_id neexistuje) - drzi
 * sa potom CELY retazec, v ktorom ten subor je.
 *
 * Zapise sa prikazom:  vmicollect hold <adresar> <chain_id|subor>...
 */

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

typedef struct {
    bool     is_id;         /* true: chain_id; false: meno suboru     */
    uint64_t id;
    char     name[VMIC_PATH_MAX];
} hold_t;

/* Dopise jeden zaznam do markera HOLD. Zaznam nesmie obsahovat novy
 * riadok (je to jeden riadok suboru). */
int vmic_hold_mark(const char *dir, const char *entry)
{
    if (!entry || !entry[0] || strchr(entry, '\n') || strchr(entry, '\r'))
        return VMIC_ERR;
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), dir, VMIC_HOLD_MARKER) != 0)
        return VMIC_ERR;
    FILE *f = fopen(path, "a");
    if (!f) {
        LOGW("hold: nedaji sa otvorit %s: %s", path, strerror(errno));
        return VMIC_ERR;
    }
    int rc = fprintf(f, "%s\n", entry) < 0 ? VMIC_ERR : VMIC_OK;
    if (rc == VMIC_OK)
        LOGI("hold: oznaceny %s v %s", entry, path);
    else
        LOGW("hold: zapis do %s zlyhal: %s", path, strerror(errno));
    fclose(f);
    return rc;
}

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

/* Nacita marker HOLD z vystupneho adresara. Chybajuci subor = ziadne
 * zaznamy (nie chyba). Vracia pocet zaznamov, -1 pri chybe citania. */
static ssize_t load_holds(const char *dir, hold_t **out)
{
    *out = NULL;
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), dir, VMIC_HOLD_MARKER) != 0) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        LOGW("retencia: HOLD '%s' sa nedal citat: %s", path, strerror(errno));
        return -1;
    }

    size_t cap = 8, n = 0;
    hold_t *h = malloc(cap * sizeof(*h));
    if (!h) { fclose(f); return -1; }

    char line[VMIC_PATH_MAX + 64];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\n' || *s == '\0' || *s == '#') continue;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                         e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
        if (!*s) continue;
        if (n == cap) {
            cap *= 2;
            hold_t *bigger = realloc(h, cap * sizeof(*h));
            if (!bigger) { free(h); fclose(f); return -1; }
            h = bigger;
        }
        hold_t *it = &h[n];
        memset(it, 0, sizeof(*it));
        it->is_id = strspn(s, "0123456789") == strlen(s);
        if (it->is_id) {
            char *end = NULL;
            errno = 0;
            unsigned long long v = strtoull(s, &end, 10);
            if (errno || !end || *end) {
                LOGW("retencia: HOLD riadok '%s' nie je ani chain_id, ani "
                     "meno; preskakujem", s);
                continue;
            }
            it->id = (uint64_t)v;
        } else {
            snprintf(it->name, sizeof(it->name), "%s", s);
        }
        n++;
    }
    fclose(f);
    *out = h;
    return (ssize_t)n;
}

/* Plati hold pre dany retazec? Cez chain_id alebo cez meno ktorehokolvek
 * suboru retazca (drzi sa potom cely retazec - bez plnej snimky by jeho
 * delty nebolo z coho obnovit). */
static bool chain_held(const chain_t *c, const item_t *items,
                       const hold_t *holds, size_t nholds)
{
    if (!nholds) return false;
    for (size_t j = 0; j < c->count; j++) {
        const item_t *it = &items[c->idx[j]];
        const char *base = strrchr(it->path, '/');
        base = base ? base + 1 : it->path;
        for (size_t h = 0; h < nholds; h++) {
            if (holds[h].is_id) {
                if (holds[h].id == it->chain_id) return true;
            } else if (strcmp(holds[h].name, base) == 0) {
                return true;
            }
        }
    }
    return false;
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

    hold_t *holds = NULL;
    ssize_t nholds = load_holds(cfg->dir, &holds);
    if (nholds < 0) {                         /* citatelny HOLD je sucast
                                                 kontraktu, nie optional */
        LOGE("retencia: marker HOLD sa nedal nacitat, retencia sa NESKUSILA "
             "- snimky sa nemazu naslepo");
        return VMIC_ERR;
    }

    DIR *d = opendir(cfg->dir);
    if (!d) {
        LOGW("retencia: nedaji sa otvorit '%s': %s", cfg->dir, strerror(errno));
        return VMIC_ERR;
    }

    size_t cap = 128, n = 0;
    item_t *items = malloc(cap * sizeof(*items));
    if (!items) { free(holds); closedir(d); return VMIC_ERR; }

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
            if (!bigger) { free(items); free(holds); closedir(d); return VMIC_ERR; }
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
    if (!chains) { free(items); free(holds); return VMIC_ERR; }
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
     *
     * Treti druh ochrany je marker HOLD z disku (chain_id alebo meno
     * suboru) - ten tu nechranime navyse, retazce s markerom sa preskocia
     * pri mazani nizsie.
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

        if (chain_held(&chains[k], items, holds, nholds)) {
            LOGI("retencia: retazec %" PRIu64 " je drzany markerom HOLD, "
                 "nemazem ho (%s)", chains[k].chain_id, why);
            continue;
        }

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
    free(holds);
    return VMIC_OK;

oom:
    for (size_t k = 0; k < cn; k++) free(chains[k].idx);
    free(chains);
    free(items);
    free(holds);
    LOGE("retencia: nedostatok pamate");
    return VMIC_ERR;
}
