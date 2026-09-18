/*
 * backend.c - register backendov + SPOLOCNA CITACIA SLUCKA.
 *
 * Funkcia vmic_capture() nizsie je jedno z dvoch miest, kde sa rozhoduje
 * o vykone celeho modulu (to druhe je writer). Preto ma tolko komentarov.
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "internal.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* prototypy jednotlivych driverov - pozri src/internal.h */

/* ------------------------------------------------------------------ */
/* Register                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    const vmic_backend_ops_t *ops;
    int (*alloc)(vmic_backend_t *);
    const char *desc;
} entry_t;

static const entry_t REGISTRY[] = {
    { &vmic_backend_ebpf, vmic_backend_ebpf_alloc,
#ifdef VMIC_HAVE_EBPF
      "introspekcia bezicej KVM domeny cez eBPF (potrebuje roota)" },
#else
      "NEDOSTUPNY v tomto builde - chybal clang alebo libbpf" },
#endif
    { &vmic_backend_file, vmic_backend_file_alloc,
      "raw obraz na disku (vyvoj, testy, prehravanie)" },
};
#define REGISTRY_COUNT (sizeof(REGISTRY) / sizeof(REGISTRY[0]))

const vmic_backend_ops_t *vmic_backend_find(const char *name)
{
    for (size_t i = 0; i < REGISTRY_COUNT; i++)
        if (strcmp(REGISTRY[i].ops->name, name) == 0)
            return REGISTRY[i].ops;
    return NULL;
}

void vmic_backend_print_list(void *stream)
{
    FILE *out = stream ? (FILE *)stream : stdout;
    for (size_t i = 0; i < REGISTRY_COUNT; i++)
        fprintf(out, "  %-8s %-14s %s\n",
                REGISTRY[i].ops->name,
                REGISTRY[i].ops->random_access ? "[nahodny]" : "[hromadny]",
                REGISTRY[i].desc);
}

const char *vmic_backend_ext(const vmic_backend_t *b)
{
    if (b->ext[0]) return b->ext;
    return b->ops->ext ? b->ops->ext : ".bin";
}

int vmic_backend_create(vmic_backend_t *b, const vmic_config_t *cfg)
{
    memset(b, 0, sizeof(*b));
    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        if (strcmp(REGISTRY[i].ops->name, cfg->backend) != 0) continue;
        b->ops = REGISTRY[i].ops;
        b->cfg = cfg;
        if (REGISTRY[i].alloc(b) != VMIC_OK) {
            LOGE("backend '%s': nedostatok pamate", cfg->backend);
            return VMIC_FATAL;
        }
        return VMIC_OK;
    }
    LOGE("neznamy backend '%s'", cfg->backend);
    return VMIC_FATAL;
}

void vmic_backend_destroy(vmic_backend_t *b)
{
    if (!b || !b->ops) return;
    if (b->paused) {                 /* nikdy nenechat VM zamrznutu! */
        vmic_backend_resume(b);
    }
    if (b->ops->close) b->ops->close(b);
    free(b->priv);
    b->priv = NULL;
    b->ops  = NULL;
}

/* ------------------------------------------------------------------ */
/* Pauza s ucotvanim stavu                                             */
/* ------------------------------------------------------------------ */

int vmic_backend_pause(vmic_backend_t *b)
{
    if (b->paused) return VMIC_OK;
    if (!b->ops->pause) return VMIC_OK;
    int rc = b->ops->pause(b);
    if (rc == VMIC_OK) b->paused = true;
    return rc;
}

int vmic_backend_resume(vmic_backend_t *b)
{
    if (!b->paused) return VMIC_OK;
    if (!b->ops->resume) { b->paused = false; return VMIC_OK; }

    /*
     * Priznak zhasiname AZ PO USPECHU. Zapauzovana VM je najhorsi mozny
     * koncovy stav - napr. Xen ma pause refcount, takze jedno zlyhane
     * xc_domain_unpause() by domenu zamrazilo natrvalo a dalsie
     * pause/resume pary by refcount uz nikdy nevratili na nulu.
     * Ked prvy pokus zlyha, skusime to este dvakrat s kratkou pauzou.
     */
    for (int attempt = 0; attempt < 3; attempt++) {
        if (b->ops->resume(b) == VMIC_OK) {
            b->paused = false;
            if (attempt) LOGW("VM sa rozbehla az na %d. pokus", attempt + 1);
            return VMIC_OK;
        }
        usleep(50000);
    }
    LOGE("VM sa NEPODARILO rozbehnut ani na 3 pokusy - zostava pozastavena!");
    return VMIC_ERR;
}

uint64_t vmic_vminfo_addressable(const vmic_vminfo_t *vi)
{
    if (vi->has_max_paddr && vi->max_paddr) return vi->max_paddr;
    if (vi->has_memsize   && vi->memsize)   return vi->memsize;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CITACIA SLUCKA                                                      */
/* ------------------------------------------------------------------ */

int vmic_capture(vmic_backend_t *b, vmic_writer_t *w,
                 const vmic_region_t *regions, size_t region_count,
                 vmic_stats_t *stats, volatile sig_atomic_t *stop)
{
    const vmic_config_t *cfg = b->cfg;
    memset(stats, 0, sizeof(*stats));

    /* --- hromadne backendy: prenechame pracu externemu nastroju --- */
    if (!b->ops->random_access) {
        if (!w->ops->staging || !w->ops->adopt) {
            LOGE("backend '%s' vie iba hromadny vypis, ale writer '%s' "
                 "ocakava prud blokov", b->ops->name, w->ops->name);
            return VMIC_FATAL;
        }
        const char *path = w->ops->staging(w);
        double t0 = vmic_now_mono();
        int rc = b->ops->dump_to(b, path);
        stats->read_seconds = vmic_now_mono() - t0;
        if (rc != VMIC_OK) return rc;

        int64_t produced = vmic_file_size(path);
        if (produced < 0) {
            LOGE("hromadny vypis nevytvoril subor '%s'", path);
            return VMIC_ERR;
        }
        stats->bytes_requested = (uint64_t)produced;
        stats->bytes_read      = (uint64_t)produced;
        stats->chunks          = 1;
        return w->ops->adopt(w);
    }

    /* --- backendy s nahodnym pristupom ---------------------------- */
    /*
     * Buffer alokujeme RAZ a recyklujeme. Pri 4 GiB RAM a 1 MiB bloku
     * to znamena 4096 volani read_pa() a NULA dalsich alokacii - to je
     * podstatne, pretoze tento kod bezi s pozastavenou VM.
     *
     * Zarovnanie na 4096 nie je kozmetika: umoznuje jadru pouzit
     * priamejsiu cestu pri kopirovani a v util.c to nechava rychlu
     * 8-bajtovu vetvu v is_zero()/hash64().
     */
    size_t chunk = cfg->chunk_size;
    uint8_t *buf = NULL;
    if (posix_memalign((void **)&buf, 4096, chunk) != 0 || !buf) {
        LOGE("nedostatok pamate na buffer %zu B", chunk);
        return VMIC_FATAL;
    }

    int rc = VMIC_OK;
    double t0 = vmic_now_mono();

    for (size_t r = 0; r < region_count && rc == VMIC_OK; r++) {
        uint64_t start = regions[r].start;
        uint64_t size  = regions[r].size;

        for (uint64_t off = 0; off < size; ) {
            if (stop && *stop) {
                LOGW("citanie prerusene signalom na 0x%" PRIx64, start + off);
                rc = VMIC_STOP;
                break;
            }

            uint64_t remain = size - off;
            size_t want = (remain < (uint64_t)chunk) ? (size_t)remain : chunk;
            uint64_t paddr = start + off;

            int64_t got = b->ops->read_pa(b, paddr, buf, want);
            stats->chunks++;
            stats->bytes_requested += want;

            /*
             * Signal moze prist aj UPROSTRED citania bloku. Backend vtedy
             * vrati kratky vysledok - a keby sme sa spolahli len na test
             * na zaciatku dalsej iteracie, pri PRERUSENI V POSLEDNOM bloku
             * by cyklus dobehol "uspesne" a snimka by sa dokoncila s
             * tichym nulovym chvostom. Preto sa priznak testuje hned tu.
             */
            if (stop && *stop) {
                LOGW("citanie prerusene signalom na 0x%" PRIx64, paddr);
                rc = VMIC_STOP;
                break;
            }

            if (got < 0) {                       /* tvrda chyba driveru */
                LOGE("read_pa(0x%" PRIx64 ", %zu) zlyhalo", paddr, want);
                rc = VMIC_ERR;
                break;
            }

            if ((size_t)got < want) {
                /*
                 * Cast bloku sa necitala - diery uz vyplnil sam backend
                 * nulami (viz kontrakt read_pa v vmic.h), takze offset v
                 * subore stale zodpoveda fyzickej adrese. My len zratame,
                 * kolko toho bolo, a rozhodneme sa ci pokracovat.
                 */
                stats->read_errors++;
                stats->filled_zero += want - (size_t)got;
                if (!cfg->skip_read_errors) {
                    LOGE("nenamapovana pamat na 0x%" PRIx64
                         " (chcel som %zu B, dostal %" PRId64 " B)",
                         paddr, want, got);
                    rc = VMIC_ERR;
                    break;
                }
                if (cfg->max_read_errors &&
                    stats->read_errors > cfg->max_read_errors) {
                    LOGE("prekroceny limit chyb citania (%" PRIu64 ")",
                         cfg->max_read_errors);
                    rc = VMIC_ERR;
                    break;
                }
            }
            stats->bytes_read += (uint64_t)got;

            if (w->ops->feed(w, paddr, buf, want) != VMIC_OK) {
                rc = VMIC_ERR;
                break;
            }
            off += want;
        }
    }

    stats->read_seconds = vmic_now_mono() - t0;
    free(buf);

    /*
     * Nulovy vytazok pri nenulovej poziadavke je takmer vzdy mrtve
     * spojenie (VM sa vypla, driver stratil pristup), nie diera v pamati.
     * Radsej to nahlasime ako chybu cyklu, nez by sme ukladali samé nuly.
     */
    if (rc == VMIC_OK && stats->bytes_requested && stats->bytes_read == 0) {
        LOGE("z pamate sa nepodarilo precitat ani bajt - bezi este domena?");
        rc = VMIC_ERR;
    }
    return rc;
}
