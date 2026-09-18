/*
 * perbin_test.c - regresny test per-bin priznakoveho vektora (perbin.c).
 *
 * Bezi bez roota a bez VM: pouziva backend 'file' nad synteticky vyrobenym
 * obrazom a [capture].regions nastavene tak, aby mali DIERY - inak by sa
 * netestovalo to podstatne, teda ze biny vznikaju iba nad podlozenymi
 * rozsahmi a diera medzi nimi ziadny bin nevyrobi.
 *
 * Co sa overuje:
 *   1. INVARIANT   sucet pages_changed cez biny == pages_changed snimky,
 *                  sucet pages_total cez biny == pocet podlozenych stranok.
 *   2. GEOMETRIA   vznikli presne tie biny, ktore protinaju oblasti, maju
 *                  spravne gpa a spravny pocet podlozenych stranok.
 *   3. ENTROPIA    stranka z jedineho opakovaneho bajtu ma 0 b/B, stranka
 *                  s rovnomernym rozdelenim 256 hodnot ma 8 b/B; priemer
 *                  cez tieto dve zmenene stranky teda musi byt presne 4.
 *   4. NULOVE      oblast plna nul ma zero_ratio = 1 a has_changed = 0
 *                  (nezmenila sa - to je nieco ine nez "entropia je 0").
 *   5. DETERMINIZMUS  dva behy nad rovnakym obrazom daju rovnaky vektor
 *                  do posledneho bitu, vratane suctov entropie.
 *
 * Spustenie:  make -C vmicollect test-perbin
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"

#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IMG   (8u << 20)      /* obraz 8 MiB                              */
#define PS    4096u
#define BIN   (1u << 20)      /* bin 1 MiB - aby sa test zmestil do obrazu */

/* "memsloty" testu: tri oblasti s dvoma dierami medzi nimi */
#define NREG 3
static const uint64_t R_START[NREG] = { 0,          3u << 20,     7u << 20 };
static const uint64_t R_SIZE [NREG] = { 1u << 20,   512u << 10,   1u << 20 };
/* z toho vyplyvajuce biny a ich pocty podlozenych stranok */
static const uint64_t WANT_BIN  [NREG] = { 0,   3,   7   };
static const uint64_t WANT_PAGES[NREG] = { 256, 128, 256 };

static int fail;

static void bad(const char *fmt, ...)
{
    va_list ap;
    fputs("ZLE: ", stdout);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fail = 1;
}

/* ------------------------------------------------------------------ */
/* Synteticky obraz                                                    */
/* ------------------------------------------------------------------ */

static void build_image(uint8_t *mem)
{
    for (size_t i = 0; i < IMG; i++) mem[i] = (uint8_t)(i * 31u + 7u);
    /* posledny megabajt necham cely nulovy - kvoli zero_ratio */
    memset(mem + (7u << 20), 0, 1u << 20);
}

static int write_image(const char *path, const uint8_t *mem)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    int rc = vmic_write_all(fd, mem, IMG);
    close(fd);
    return rc;
}

/*
 * Dve stranky so ZNAMOU entropiou, obe v oblasti na 3 MiB (teda v bine 3):
 *   - stranka z jedineho bajtu        -> H = 0 b/B
 *   - kazda hodnota bajtu 16-krat     -> H = 8 b/B
 * Priemer cez zmenene stranky binu tak musi vyjst presne 4.
 */
static void patch_known_entropy(uint8_t *mem)
{
    uint8_t *flat = mem + (3u << 20);
    memset(flat, 0xAA, PS);

    uint8_t *uni = mem + (3u << 20) + PS;
    for (uint32_t i = 0; i < PS; i++) uni[i] = (uint8_t)(i & 0xFFu);
}

/* ------------------------------------------------------------------ */
/* Jeden beh: plna snimka + delta po zmene dvoch stranok               */
/* ------------------------------------------------------------------ */

/* Vysledok behu si odkladame, aby sa dva behy dali porovnat bajt po bajte. */
typedef struct {
    vmic_bin_t *bins;
    size_t      count;
    uint64_t    pages_total;
    uint64_t    pages_changed;
} run_t;

static int run_once(const char *dir, run_t *out)
{
    static volatile sig_atomic_t stop = 0;
    char image[VMIC_PATH_MAX], snapdir[VMIC_PATH_MAX];

    if (vmic_mkdir_p(dir) != 0) { bad("nedaji sa vytvorit '%s'", dir); return -1; }
    vmic_join(image,   sizeof(image),   dir, "memory.img");
    vmic_join(snapdir, sizeof(snapdir), dir, "snapshots");

    uint8_t *mem = malloc(IMG);
    if (!mem) return -1;
    build_image(mem);
    if (write_image(image, mem) != 0) { bad("zapis obrazu zlyhal"); free(mem); return -1; }

    vmic_config_t cfg;
    vmic_config_defaults(&cfg);
    snprintf(cfg.backend,    sizeof(cfg.backend),    "file");
    snprintf(cfg.image_path, sizeof(cfg.image_path), "%s", image);
    snprintf(cfg.domain,     sizeof(cfg.domain),     "perbin");
    snprintf(cfg.dir,        sizeof(cfg.dir),        "%s", snapdir);
    snprintf(cfg.writer,     sizeof(cfg.writer),     "delta");
    cfg.sidecar         = false;          /* vektor citame priamo zo snimky */
    cfg.hash            = VMIC_HASH_NONE; /* SHA-256 tu nic netestuje       */
    cfg.delta_page_size = PS;
    cfg.feat_enable     = true;
    cfg.feat_bin_bytes  = BIN;
    cfg.feat_entropy    = true;

    char regions[256];
    snprintf(regions, sizeof(regions),
             "capture.regions=0x%" PRIx64 ":0x%" PRIx64 ", 0x%" PRIx64
             ":0x%" PRIx64 ", 0x%" PRIx64 ":0x%" PRIx64,
             R_START[0], R_SIZE[0], R_START[1], R_SIZE[1],
             R_START[2], R_SIZE[2]);
    if (vmic_config_set(&cfg, regions) != 0) { bad("regions sa nedaju nastavit"); free(mem); return -1; }
    if (vmic_config_validate(&cfg, true) != 0) { bad("config nepresiel"); free(mem); return -1; }

    vmic_collector_t col;
    if (vmic_collector_init(&col, &cfg, &stop) != VMIC_OK) {
        bad("collector sa nedal inicializovat");
        free(mem);
        return -1;
    }

    vmic_snapshot_t snap;
    int rc = -1;
    for (int cycle = 0; cycle < 2; cycle++) {
        if (cycle == 1) {
            patch_known_entropy(mem);
            if (write_image(image, mem) != 0) { bad("zapis zmien zlyhal"); break; }
        }
        if (vmic_collector_cycle(&col, &snap) != VMIC_OK) {
            bad("cyklus %d zlyhal", cycle);
            break;
        }
        if (!snap.features) {
            bad("cyklus %d: snimka nema per-bin vektor", cycle);
            break;
        }
        /* invariant plati v KAZDOM cykle, nie len v poslednom */
        uint64_t st = 0, sc = 0;
        for (size_t i = 0; i < snap.features->bins_total; i++) {
            st += snap.features->bins[i].pages_total;
            sc += snap.features->bins[i].pages_changed;
        }
        if (st != snap.pages_total || sc != snap.pages_changed) {
            bad("cyklus %d: invariant neplati - biny %" PRIu64 "/%" PRIu64
                ", snimka %" PRIu64 "/%" PRIu64,
                cycle, st, sc, snap.pages_total, snap.pages_changed);
            break;
        }
        printf("cyklus %d: stranky %" PRIu64 "/%" PRIu64 ", binov %zu, "
               "priznaky %.3f ms\n", cycle, snap.pages_changed,
               snap.pages_total, snap.features->bins_total,
               snap.features->compute_ms);
        if (cycle == 1) rc = 0;
    }

    if (rc == 0) {
        out->count = snap.features->bins_total;
        out->bins  = malloc(out->count * sizeof(vmic_bin_t));
        if (!out->bins) rc = -1;
        else memcpy(out->bins, snap.features->bins,
                    out->count * sizeof(vmic_bin_t));
        out->pages_total   = snap.pages_total;
        out->pages_changed = snap.pages_changed;
    }

    vmic_collector_fini(&col);
    free(mem);
    return rc;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *base = (argc > 1) ? argv[1] : "build/perbintest";
    char d1[VMIC_PATH_MAX], d2[VMIC_PATH_MAX];
    snprintf(d1, sizeof(d1), "%s/a", base);
    snprintf(d2, sizeof(d2), "%s/b", base);

    vmic_log_open(VMIC_LOG_WARN, NULL, false);

    run_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    if (run_once(d1, &a) != 0) return 1;
    if (run_once(d2, &b) != 0) return 1;

    /* --- geometria binov ------------------------------------------ */
    if (a.count != NREG)
        bad("vzniklo %zu binov, ocakaval som %d (diery nesmu vyrobit bin)",
            a.count, NREG);

    uint64_t want_total = 0;
    for (int i = 0; i < NREG && (size_t)i < a.count; i++) {
        const vmic_bin_t *x = &a.bins[i];
        want_total += WANT_PAGES[i];
        if (x->bin != WANT_BIN[i])
            bad("bin[%d] ma index %" PRIu64 ", ocakaval som %" PRIu64,
                i, x->bin, WANT_BIN[i]);
        if (x->gpa != WANT_BIN[i] * (uint64_t)BIN)
            bad("bin %" PRIu64 " ma gpa 0x%" PRIx64 ", ocakaval som 0x%" PRIx64,
                x->bin, x->gpa, WANT_BIN[i] * (uint64_t)BIN);
        if (x->pages_total != WANT_PAGES[i])
            bad("bin %" PRIu64 " ma %" PRIu64 " podlozenych stranok, "
                "ocakaval som %" PRIu64,
                x->bin, x->pages_total, WANT_PAGES[i]);
    }
    if (a.pages_total != want_total)
        bad("snimka ma %" PRIu64 " podlozenych stranok, z oblasti vychadza %"
            PRIu64, a.pages_total, want_total);

    /* --- co sa v druhom cykle zmenilo ----------------------------- */
    if (a.count == NREG) {
        if (a.bins[0].pages_changed != 0 || a.bins[2].pages_changed != 0)
            bad("zmenili sa aj biny, do ktorych sa nezapisovalo (%" PRIu64
                ", %" PRIu64 ")",
                a.bins[0].pages_changed, a.bins[2].pages_changed);
        if (a.bins[1].pages_changed != 2)
            bad("bin 3 ma %" PRIu64 " zmenenych stranok, ocakaval som 2",
                a.bins[1].pages_changed);

        /* H = 0 (jediny bajt) a H = 8 (rovnomerne) -> priemer presne 4 */
        if (a.bins[1].pages_changed) {
            double mean = a.bins[1].entropy_sum / (double)a.bins[1].pages_changed;
            if (fabs(mean - 4.0) > 1e-9)
                bad("bin 3 ma entropy_mean %.9f, ocakaval som 4.0", mean);
        }

        /* nulova oblast: vsetky stranky nulove a nic sa v nej nezmenilo */
        if (a.bins[2].pages_zero != a.bins[2].pages_total)
            bad("bin 7 ma %" PRIu64 " nulovych stranok z %" PRIu64,
                a.bins[2].pages_zero, a.bins[2].pages_total);
        if (a.bins[2].entropy_sum != 0.0)
            bad("bin 7 sa nezmenil, ale ma nenulovy sucet entropie (%.9f)",
                a.bins[2].entropy_sum);
    }

    /* --- determinizmus -------------------------------------------- */
    if (a.count != b.count)
        bad("dva behy daly rozny pocet binov (%zu vs %zu)", a.count, b.count);
    else if (memcmp(a.bins, b.bins, a.count * sizeof(vmic_bin_t)) != 0)
        bad("dva behy nad rovnakym obrazom daly rozny vektor");

    free(a.bins);
    free(b.bins);

    if (fail) return 1;
    printf("OK: %zu binov, invariant sedi, entropia 0/8 -> priemer 4, "
           "dva behy zhodne\n", a.count);
    return 0;
}
