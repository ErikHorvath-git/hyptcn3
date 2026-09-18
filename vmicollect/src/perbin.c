/*
 * perbin.c - per-bin priznakovy vektor pocitany priamo v module.
 *
 * Meno suboru (a nie features.c) vysvetluje hlavicka perbin.h.
 *
 * PRECO TO ROBI MODUL A NIE SKRIPT POTOM:
 *   Cielom je hypervisor modul, ktory sam generuje vektory pripravene na
 *   sekvencnu analyzu. Offline post-processing nad .vmicd subormi by dal
 *   rovnake cisla, ale az po zbere a mimo modulu - a navyse by musel
 *   znovu precitat vsetky stranky, ktore tu uz v ruke mame.
 *
 * PRECO SA TO VEZIE NA DELTA WRITERI:
 *   Delta writer uz kazdu stranku hashuje (vmic_hash64), takze rozhodnutie
 *   "zmenila sa" existuje. Zostava k nemu pridat pocitadla na bin, test
 *   nulovej stranky a entropiu - stranka je pritom este v keske.
 *
 * PRECO IBA NAD PODLOZENYMI ROZSAHMI:
 *   Fyzicky priestor x86 je deravy. Pri 2 GiB VM je max_paddr 4 GiB, takze
 *   pri rovnomernom rozdeleni celeho rozsahu by bola vyse polovica binov
 *   trvale nulova. Model by sa ucil na vypln a rozmer vektora by klamal.
 *   Preto bin, ktory neprotina ziadnu zbieranu oblast, vobec nevznikne.
 *
 * INDEX BINU JE VIAZANY NA ADRESU, nie na poradie: bin = gpa >> log2(bin).
 * Ked pribudne alebo zmizne memslot, ostatne biny si svoje cislo nechaju
 * a rady v case zostanu porovnatelne.
 */

#define _GNU_SOURCE
#include "perbin.h"
#include "log.h"
#include "util.h"

#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/*
 * Horny limit velkosti mapy "index binu -> slot". Mapa je priame pole cez
 * cely rozsah fyzickych adries, lebo vyhladanie binu je v najteplejsej
 * slucke modulu (raz na stranku). Pri 16 MiB binoch a 4 GiB rozsahu ma
 * 256 poloziek; limit je tu iba na to, aby nezmyselne mala bin_bytes
 * nezobrala gigabajty.
 */
#define FEAT_MAP_MAX (1u << 26)

typedef struct {
    int32_t  *map;         /* index binu -> slot v bins[], -1 = neexistuje */
    uint64_t  map_len;
    uint64_t  sig;         /* podpis oblasti, pre ktore je mapa postavena  */
    unsigned  bin_shift;
    unsigned  page_shift;
    uint64_t  pages_seen;  /* kolko stranok sme naozaj dostali             */
    uint64_t  unbinned;    /* stranka mimo vsetkych binov = chyba          */

    /*
     * Tabulka c*log2(c) pre c = 0..page_size. Shannonova entropia z
     * histogramu sa da napisat ako
     *      H = log2(n) - (1/n) * sum_j c_j*log2(c_j),
     * takze s tabulkou nie je na stranku potrebne ani jedno volanie log2().
     * Pri stotisicoch zmenenych stranok v plnej snimke to nie je detail.
     */
    double   *clog2;
    uint32_t  clog2_n;
    double    log2_ps;
} feat_priv_t;

/* ------------------------------------------------------------------ */
/* Drobnosti                                                           */
/* ------------------------------------------------------------------ */

static bool is_pow2_u64(uint64_t v)
{
    return v && (v & (v - 1)) == 0;
}

static unsigned shift_of(uint64_t pow2)
{
    unsigned s = 0;
    while ((pow2 >> s) > 1) s++;
    return s;
}

/* ------------------------------------------------------------------ */
/* Mapa binov                                                          */
/* ------------------------------------------------------------------ */

/*
 * Postavi zoznam binov a mapu z indexu binu na slot v nom. Ide sa dva
 * razy cez oblasti: prvy prechod oznaci, ktore biny vobec existuju,
 * druhy im pridel slot vzostupne podla indexu - vdaka tomu je pole
 * `bins` zoradene a rovnaky bin ma v sidecari vzdy rovnake miesto.
 */
static int build_map(vmic_features_t *f, feat_priv_t *p,
                     const vmic_region_t *regions, size_t rcount)
{
    uint64_t end_max = 0;
    for (size_t i = 0; i < rcount; i++) {
        uint64_t end = regions[i].start + regions[i].size;
        if (end > end_max) end_max = end;
    }
    if (!end_max) {
        LOGE("features: nemam ziadnu zbieranu oblast");
        return VMIC_ERR;
    }

    uint64_t map_len = ((end_max - 1) >> p->bin_shift) + 1;
    if (map_len > FEAT_MAP_MAX) {
        LOGE("features: pri bin_bytes = %" PRIu64 " by mapa binov mala %"
             PRIu64 " poloziek (limit %u) - zvac features.bin_bytes",
             f->bin_bytes, map_len, FEAT_MAP_MAX);
        return VMIC_ERR;
    }

    int32_t *map = malloc((size_t)map_len * sizeof(int32_t));
    if (!map) return VMIC_FATAL;
    for (uint64_t i = 0; i < map_len; i++) map[i] = -1;

    size_t present = 0;
    for (size_t i = 0; i < rcount; i++) {
        uint64_t end = regions[i].start + regions[i].size;
        if (end <= regions[i].start) continue;
        uint64_t b0 = regions[i].start >> p->bin_shift;
        uint64_t b1 = (end - 1) >> p->bin_shift;
        for (uint64_t b = b0; b <= b1; b++)
            if (map[b] == -1) { map[b] = -2; present++; }   /* -2 = bude bin */
    }

    vmic_bin_t *bins = calloc(present ? present : 1, sizeof(vmic_bin_t));
    if (!bins) { free(map); return VMIC_FATAL; }

    size_t slot = 0;
    for (uint64_t b = 0; b < map_len; b++) {
        if (map[b] != -2) continue;
        map[b] = (int32_t)slot;
        bins[slot].bin = b;
        bins[slot].gpa = b << p->bin_shift;
        slot++;
    }

    /*
     * pages_total sa pocita z geometrie oblasti, nie z toho, kolko stranok
     * nakoniec pritecie. Menovatel pomerov tak existuje aj vtedy, ked sa
     * cyklus prerusi, a zhoda "sucet pages_total == pocet podlozenych
     * stranok" je potom skutocna kontrola, nie tautologia.
     */
    for (size_t i = 0; i < rcount; i++) {
        uint64_t start = regions[i].start;
        uint64_t end   = start + regions[i].size;
        if (end <= start) continue;
        uint64_t b0 = start >> p->bin_shift;
        uint64_t b1 = (end - 1) >> p->bin_shift;
        for (uint64_t b = b0; b <= b1; b++) {
            uint64_t lo = b << p->bin_shift;
            uint64_t hi = lo + f->bin_bytes;
            if (lo < start) lo = start;
            if (hi > end)   hi = end;
            bins[map[b]].pages_total += (hi - lo) >> p->page_shift;
        }
    }

    free(p->map);
    free(f->bins);
    p->map     = map;
    p->map_len = map_len;
    f->bins       = bins;
    f->bins_total = present;
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Entropia jednej stranky                                             */
/* ------------------------------------------------------------------ */

/*
 * Shannonova entropia nad histogramom 256 hodnot bajtov, vysledok v bitoch
 * na bajt (0..8). Pocita sa iba zo ZMENENYCH stranok - nezmenena stranka
 * by do priemeru priniesla tu istu hodnotu ako minule a zamaskovala by
 * prave to, co nas zaujima.
 */
static double page_entropy(const feat_priv_t *p, const uint8_t *page,
                           uint32_t len)
{
    uint32_t hist[256];
    memset(hist, 0, sizeof(hist));
    for (uint32_t i = 0; i < len; i++) hist[page[i]]++;

    double s = 0.0;
    for (unsigned j = 0; j < 256; j++)
        if (hist[j]) s += p->clog2[hist[j]];

    double h = p->log2_ps - s / (double)len;
    /* Pri stranke z jedineho opakovaneho bajtu vyjde rozdiel dvoch
       rovnakych cisel - zaokruhlenie ho moze posunut tesne pod nulu. */
    if (h < 0.0) h = 0.0;
    if (h > 8.0) h = 8.0;
    return h;
}

static int entropy_table(feat_priv_t *p, uint32_t page_size)
{
    if (p->clog2 && p->clog2_n == page_size) return VMIC_OK;
    double *t = malloc(((size_t)page_size + 1) * sizeof(double));
    if (!t) return VMIC_FATAL;
    t[0] = 0.0;
    for (uint32_t c = 1; c <= page_size; c++) t[c] = (double)c * log2((double)c);
    free(p->clog2);
    p->clog2   = t;
    p->clog2_n = page_size;
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Zivotny cyklus                                                      */
/* ------------------------------------------------------------------ */

int vmic_features_begin(vmic_features_t *f, const vmic_config_t *cfg,
                        const vmic_region_t *regions, size_t region_count,
                        uint32_t page_size, uint64_t region_sig)
{
    feat_priv_t *p = (feat_priv_t *)f->priv;
    if (!p) {
        p = calloc(1, sizeof(*p));
        if (!p) return VMIC_FATAL;
        f->priv = p;
    }

    /* Zapamataj si, nad cim sa binovalo. Ukazovatel patri writerovi a zije
       cely cyklus - rovnako ako `regions` v jeho stave. */
    f->regions      = regions;
    f->region_count = region_count;

    if (!is_pow2_u64(cfg->feat_bin_bytes) || !is_pow2_u64(page_size) ||
        cfg->feat_bin_bytes < page_size) {
        LOGE("features: bin_bytes (%" PRIu64 ") musi byt mocnina 2 a aspon "
             "velkost stranky (%u)", cfg->feat_bin_bytes, page_size);
        return VMIC_ERR;
    }
    if (!region_count) {
        LOGE("features: prazdny zoznam oblasti");
        return VMIC_ERR;
    }

    unsigned bin_shift  = shift_of(cfg->feat_bin_bytes);
    unsigned page_shift = shift_of(page_size);

    bool rebuild = (p->map == NULL) || (p->sig != region_sig) ||
                   (p->bin_shift != bin_shift) || (p->page_shift != page_shift);

    f->bin_bytes  = cfg->feat_bin_bytes;
    f->page_size  = page_size;
    f->entropy    = cfg->feat_entropy;
    f->compute_ms = 0.0;
    p->bin_shift  = bin_shift;
    p->page_shift = page_shift;
    p->pages_seen = 0;
    p->unbinned   = 0;

    if (rebuild) {
        int rc = build_map(f, p, regions, region_count);
        if (rc != VMIC_OK) return rc;
        p->sig = region_sig;
        LOGD("features: %zu binov po %" PRIu64 " B", f->bins_total, f->bin_bytes);
    } else {
        /* Geometria sa nezmenila - staci vynulovat pocitadla snimky.
           `bin`, `gpa` a `pages_total` su vlastnosti mapy, nie snimky. */
        for (size_t i = 0; i < f->bins_total; i++) {
            f->bins[i].pages_changed = 0;
            f->bins[i].pages_zero    = 0;
            f->bins[i].entropy_sum   = 0.0;
        }
    }

    if (f->entropy) {
        if (entropy_table(p, page_size) != VMIC_OK) return VMIC_FATAL;
        p->log2_ps = log2((double)page_size);
    }
    return VMIC_OK;
}

void vmic_features_page(vmic_features_t *f, uint64_t paddr,
                        const uint8_t *page, bool changed)
{
    feat_priv_t *p = (feat_priv_t *)f->priv;

    uint64_t b = paddr >> p->bin_shift;
    int32_t slot = (b < p->map_len) ? p->map[b] : -1;
    if (slot < 0) {
        /* Stranka mimo vsetkych binov znamena, ze writer dostal iny rozsah
           nez z akeho je mapa. Nemlcime o tom - finish() to vyhlasi. */
        p->unbinned++;
        return;
    }
    vmic_bin_t *bin = &f->bins[slot];
    p->pages_seen++;

    /*
     * Nulovost sa testuje presne, nie porovnanim hashu s hashom nulovej
     * stranky: hash je na detekciu zmeny, a "s velkou pravdepodobnostou
     * nulova" nie je priznak, ktory by sa dal obhajit. vmic_is_zero()
     * navyse konci na prvom nenulovom slove, takze na nenulovych strankach
     * stoji takmer nic.
     */
    if (vmic_is_zero(page, f->page_size)) bin->pages_zero++;

    if (!changed) return;
    bin->pages_changed++;
    if (f->entropy) bin->entropy_sum += page_entropy(p, page, f->page_size);
}

int vmic_features_finish(vmic_features_t *f, uint64_t pages_total,
                         uint64_t pages_changed)
{
    feat_priv_t *p = (feat_priv_t *)f->priv;
    if (!p) return VMIC_ERR;

    if (p->unbinned) {
        LOGE("features: %" PRIu64 " stranok nepatrilo do ziadneho binu",
             p->unbinned);
        return VMIC_ERR;
    }

    uint64_t sum_total = 0, sum_changed = 0;
    for (size_t i = 0; i < f->bins_total; i++) {
        sum_total   += f->bins[i].pages_total;
        sum_changed += f->bins[i].pages_changed;
    }

    if (sum_total != pages_total || sum_changed != pages_changed ||
        p->pages_seen != pages_total) {
        LOGE("features: invariant neplati - biny maju %" PRIu64 "/%" PRIu64
             " (total/changed), snimka %" PRIu64 "/%" PRIu64
             ", videnych stranok %" PRIu64,
             sum_total, sum_changed, pages_total, pages_changed,
             p->pages_seen);
        return VMIC_ERR;
    }
    return VMIC_OK;
}

void vmic_features_release(vmic_features_t *f)
{
    feat_priv_t *p = (feat_priv_t *)f->priv;
    if (p) {
        free(p->map);
        free(p->clog2);
        free(p);
    }
    free(f->bins);
    f->bins       = NULL;
    f->bins_total = 0;
    f->priv       = NULL;
}
