/*
 * writer_delta.c - inkrementalny zber: uklada IBA ZMENENE STRANKY.
 *
 * PRECO to pri periodickom zbere potrebujes:
 *   Snimky kazdych 5 s zo 4 GiB VM = 2.8 TB za hodinu. Nepouzitelne.
 *   Medzi dvoma snimkami sa ale typicky zmeni len 0.5-5 % stranok.
 *   Delta zber teda znizi objem o 1-2 rady a zaroven ti dava presne to,
 *   co potrebujes na sekvencnu analyzu: "co sa zmenilo od minula".
 *
 * AKO to funguje:
 *   - pamat sa deli na stranky (vychodzie 4 KiB, [output].delta_page_size)
 *   - pre kazdu stranku sa spocita rychly 64-bitovy hash (util.c)
 *   - zapise sa iba stranka, ktorej hash sa lisi od predchadzajuceho cyklu
 *   - kazdych N snimok ([output].delta_full_every) sa zapise PLNA snimka,
 *     ktora zacina novy "retazec" - aby sa chyba nesirila donekonecna
 *     a aby sa dalo zacat prehravat od lubovolneho miesta
 *
 * FORMAT SUBORU (.vmicd) - zamerne trivialny, aby si ho vedel precitat
 * aj vlastnym skriptom:
 *
 *   hlavicka, 64 B, little-endian:
 *     0  char[8]  "VMICDLT1"
 *     8  u32      verzia (1)
 *    12  u32      velkost stranky
 *    16  u64      id retazca
 *    24  u64      poradove cislo snimky
 *    32  u64      logicka velkost pamate (koniec poslednej oblasti)
 *    40  u64      pocet zaznamov v tomto subore
 *    48  u64      priznaky (bit 0 = plna snimka)
 *    56  u64      podpis konfiguracie oblasti
 *
 *   potom `pocet zaznamov` krat:
 *     u64      index stranky (fyz. adresa / velkost stranky)
 *     u8[ps]   obsah stranky
 *
 * Obnovenie: `vmicollect restore` (funkcia vmic_delta_restore nizsie).
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "internal.h"
#include "perbin.h"
#include "log.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DELTA_MAGIC   "VMICDLT1"
#define DELTA_HDR     64u
#define DELTA_VERSION 1u
#define DELTA_FLAG_FULL 1ull
#define DELTA_EXT     ".vmicd"

typedef struct {
    /* --- stav prezivajuci medzi snimkami ------------------------- */
    uint64_t *hash;        /* hash kazdej stranky z minuleho cyklu   */
    uint64_t  hash_len;    /* pocet poloziek v `hash`                */
    uint64_t  zero_hash;   /* hash uplne nulovej stranky             */
    uint64_t  chain_id;
    uint64_t  region_sig;  /* podpis konfiguracie oblasti            */
    bool      have_chain;

    /* --- stav jednej snimky -------------------------------------- */
    int       fd;
    char      staging[VMIC_PATH_MAX];
    char      final[VMIC_PATH_MAX];
    uint32_t  page_size;
    uint64_t  pages_written;
    uint64_t  pages_seen;
    uint64_t  mem_size;
    bool      full;
    bool      active;
    bool      hashing;

    /* --- per-bin priznakovy vektor (perbin.c) --------------------- */
    vmic_features_t feat;
    bool      feat_on;     /* pocitame ho v tejto snimke?            */
    /*
     * Priznak "zmenila sa" pre stranky prave spracovavaneho bloku.
     * Priznaky sa pocitaju az druhym prechodom cez blok, nie v tej istej
     * slucke ako zapis: iba tak sa da cas vypoctu zmerat samostatne
     * (compute_ms v sidecari) bez volania hodin na kazdu stranku. Blok
     * ma vychodzo 1 MiB, takze pri druhom prechode je este v keske.
     */
    uint8_t  *chg;
    size_t    chg_cap;
} delta_priv_t;

/* ------------------------------------------------------------------ */
/* Male pomocky na little-endian zapis                                 */
/* ------------------------------------------------------------------ */

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ------------------------------------------------------------------ */
/* Tabulka hashov                                                      */
/* ------------------------------------------------------------------ */

/*
 * Tabulku inicializujeme hodnotou "hash nulovej stranky". To nie je
 * kozmetika: obnova zacina prazdnym (nulovym) suborom, takze "este som
 * tu stranku nevidel" a "stranka je nulova" su z pohladu obnovy to iste.
 * Vdaka tomu netreba ziadny extra bitmapovy priznak.
 */
static int hash_ensure(delta_priv_t *p, uint64_t need)
{
    if (need <= p->hash_len) return 0;

    uint64_t cap = p->hash_len ? p->hash_len : 4096;
    while (cap < need) {
        if (cap > UINT64_MAX / 2) { cap = need; break; }
        cap *= 2;
    }
    if (cap > (uint64_t)SIZE_MAX / sizeof(uint64_t)) return -1;

    uint64_t *n = realloc(p->hash, (size_t)cap * sizeof(uint64_t));
    if (!n) return -1;
    for (uint64_t i = p->hash_len; i < cap; i++) n[i] = p->zero_hash;
    p->hash     = n;
    p->hash_len = cap;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Zaciatok snimky                                                     */
/* ------------------------------------------------------------------ */

static int delta_begin(vmic_writer_t *w, vmic_snapshot_t *s)
{
    delta_priv_t *p = (delta_priv_t *)w->priv;
    const vmic_config_t *cfg = w->cfg;

    p->page_size = cfg->delta_page_size;

    /* hash nulovej stranky sa da spocitat az ked poznam jej velkost */
    if (!p->zero_hash) {
        uint8_t *zero = calloc(1, p->page_size);
        if (!zero) return VMIC_FATAL;
        p->zero_hash = vmic_hash64(zero, p->page_size);
        free(zero);
        /* uz alokovanu tabulku (ina velkost stranky) zahodime */
        for (uint64_t i = 0; i < p->hash_len; i++) p->hash[i] = p->zero_hash;
    }

    /*
     * Podpis oblasti: ked sa zmenia zbierane oblasti, stare hashe uz
     * nehovoria o tom istom rozsahu a retazec by sa rozbil. Preto zmenu
     * detegujeme a vynutime novu plnu snimku.
     *
     * Podstatne je, ze sa berie z EFEKTIVNYCH oblasti (co sa naozaj
     * zbiera), nie z [capture].regions. Pri prazdnom nastaveni je totiz
     * konfiguracia stale rovnaka, ale rozsah sa aj tak zmenit moze -
     * hotplug pamate alebo restart domeny s inou velkostou RAM.
     */
    const vmic_region_t *rlist = s->regions ? s->regions : cfg->regions;
    size_t rcount = s->regions ? s->region_count : cfg->region_count;

    uint64_t sig = 0xa5a5a5a5ull ^ (uint64_t)p->page_size;
    for (size_t i = 0; i < rcount; i++) {
        sig ^= rlist[i].start * 0x9e3779b97f4a7c15ull;
        sig  = (sig << 7) | (sig >> 57);
        sig ^= rlist[i].size;
    }

    p->full = (!p->have_chain) ||
              (sig != p->region_sig) ||
              (cfg->delta_full_every <= 1) ||
              (s->seq % cfg->delta_full_every == 0);

    if (p->full) {
        /* novy retazec: id = cas v milisekundach (staci na jednoznacnost) */
        p->chain_id = (uint64_t)s->wall.tv_sec * 1000ull +
                      (uint64_t)(s->wall.tv_nsec / 1000000L);
        if (p->have_chain && sig != p->region_sig)
            LOGW("delta: zmenil sa rozsah zbieranej pamate - zacinam novy "
                 "retazec");
        /* pri novom retazci sa obnova zacina od nul, takze aj nasa
           predstava o "predchadzajucom stave" musi byt nulova */
        for (uint64_t i = 0; i < p->hash_len; i++) p->hash[i] = p->zero_hash;
    }
    p->region_sig = sig;
    p->have_chain = true;

    /* delta ma vlastnu priponu bez ohladu na backend */
    snprintf(s->ext, sizeof(s->ext), "%s", DELTA_EXT);

    char name[VMIC_NAME_MAX + 32];
    snprintf(name, sizeof(name), ".%s%s.part", s->id, s->ext);
    if (vmic_join(p->staging, sizeof(p->staging), cfg->dir, name) != 0)
        return VMIC_ERR;
    snprintf(name, sizeof(name), "%s%s", s->id, s->ext);
    if (vmic_join(p->final, sizeof(p->final), cfg->dir, name) != 0)
        return VMIC_ERR;

    p->fd = open(p->staging, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (p->fd < 0) {
        LOGE("delta: nedaji sa vytvorit '%s': %s", p->staging, strerror(errno));
        return VMIC_ERR;
    }

    /* hlavicku zapiseme teraz s nulami a na konci ju prepiseme */
    uint8_t hdr[DELTA_HDR];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, DELTA_MAGIC, 8);
    put_u32(hdr + 8,  DELTA_VERSION);
    put_u32(hdr + 12, p->page_size);
    put_u64(hdr + 16, p->chain_id);
    put_u64(hdr + 24, s->seq);
    put_u64(hdr + 48, p->full ? DELTA_FLAG_FULL : 0ull);
    put_u64(hdr + 56, sig);
    if (vmic_write_all(p->fd, hdr, sizeof(hdr)) != 0) {
        LOGE("delta: zapis hlavicky zlyhal: %s", strerror(errno));
        close(p->fd);
        p->fd = -1;
        unlink(p->staging);       /* nenechavat po sebe .part subor */
        p->have_chain = false;    /* retazec je rozbity - dalsia snimka plna */
        return VMIC_ERR;
    }

    p->pages_written = 0;
    p->pages_seen    = 0;
    p->mem_size      = 0;
    p->active        = true;
    p->hashing       = (cfg->hash == VMIC_HASH_SHA256);

    /*
     * Priznaky su volitelne a ich zlyhanie NESMIE zhodit zber - snimka je
     * podstatnejsia nez vektor. Ked sa nedaju pocitat, povie sa to nahlas
     * a sidecar blok "features" jednoducho nebude mat; ticho doplneny
     * prazdny vektor by bol horsi, lebo by sa tvaril ako meranie.
     */
    p->feat_on = false;
    if (cfg->feat_enable) {
        if (vmic_features_begin(&p->feat, cfg, rlist, rcount,
                                p->page_size, sig) == VMIC_OK)
            p->feat_on = true;
        else
            LOGW("delta: per-bin priznaky sa nedaju pocitat - sidecar ich "
                 "mat nebude");
    }
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Porovnavanie stranok                                                */
/* ------------------------------------------------------------------ */

static int delta_feed(vmic_writer_t *w, uint64_t paddr,
                      const uint8_t *buf, size_t len)
{
    delta_priv_t *p = (delta_priv_t *)w->priv;
    const uint32_t ps = p->page_size;

    if (paddr + len > p->mem_size) p->mem_size = paddr + len;

    /*
     * Collector zarovnal oblasti na velkost stranky a chunk_size je jej
     * nasobok, takze tu mozeme pocitat s celymi strankami. Keby predsa
     * len prisiel nezarovnany blok, radsej hlasna chyba nez ticho zly
     * vysledok.
     */
    if ((paddr % ps) != 0 || (len % ps) != 0) {
        LOGE("delta: blok 0x%" PRIx64 "+%zu nie je zarovnany na %u B",
             paddr, len, ps);
        return VMIC_ERR;
    }

    uint64_t first = paddr / ps;
    size_t   count = len / ps;
    if (hash_ensure(p, first + count) != 0) {
        LOGE("delta: nedostatok pamate pre tabulku hashov");
        return VMIC_ERR;
    }
    if (p->feat_on && count > p->chg_cap) {
        uint8_t *n = realloc(p->chg, count);
        if (!n) {
            LOGW("delta: nedostatok pamate na priznaky - vektor tejto "
                 "snimky nevznikne");
            p->feat_on = false;
        } else {
            p->chg     = n;
            p->chg_cap = count;
        }
    }

    uint8_t rec[8];
    for (size_t i = 0; i < count; i++) {
        const uint8_t *page = buf + i * (size_t)ps;
        uint64_t idx = first + i;
        uint64_t h   = vmic_hash64(page, ps);
        p->pages_seen++;

        bool changed = (h != p->hash[idx]);
        p->hash[idx] = h;
        if (p->feat_on) p->chg[i] = changed ? 1u : 0u;
        if (!changed) continue;

        put_u64(rec, idx);
        if (vmic_write_all(p->fd, rec, sizeof(rec)) != 0 ||
            vmic_write_all(p->fd, page, ps) != 0) {
            LOGE("delta: zapis stranky %" PRIu64 " zlyhal: %s",
                 idx, strerror(errno));
            return VMIC_ERR;
        }
        p->pages_written++;
    }

    if (p->feat_on) {
        double t0 = vmic_now_mono();
        for (size_t i = 0; i < count; i++)
            vmic_features_page(&p->feat, paddr + (uint64_t)i * ps,
                               buf + i * (size_t)ps, p->chg[i] != 0);
        p->feat.compute_ms += (vmic_now_mono() - t0) * 1000.0;
    }
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Koniec snimky                                                       */
/* ------------------------------------------------------------------ */

static int delta_finish(vmic_writer_t *w, vmic_snapshot_t *s)
{
    delta_priv_t *p = (delta_priv_t *)w->priv;
    if (!p->active) return VMIC_ERR;
    p->active = false;

    /* doplnime dve polia, ktore sme na zaciatku este nepoznali */
    /*
     * KAZDA chybova vetva tu musi zhodit retazec (have_chain = false).
     * delta_feed() uz totiz posunul p->hash[] na NOVY stav pamate. Ked
     * subor nevznikne, tie hashe klamu: dalsia delta by porovnavala voci
     * stavu, ktory nikde nie je zapisany, a zmenene stranky by TICHO
     * preskocila. Zhodenim retazca vynutime, aby dalsia snimka bola plna.
     */
    uint8_t patch[8];
    put_u64(patch, p->mem_size);
    if (vmic_pwrite_all(p->fd, patch, 8, 32) != 0) {
        LOGE("delta: oprava hlavicky zlyhala: %s", strerror(errno));
        close(p->fd); p->fd = -1; unlink(p->staging);
        p->have_chain = false;
        return VMIC_ERR;
    }
    put_u64(patch, p->pages_written);
    if (vmic_pwrite_all(p->fd, patch, 8, 40) != 0) {
        LOGE("delta: oprava hlavicky zlyhala: %s", strerror(errno));
        close(p->fd); p->fd = -1; unlink(p->staging);
        p->have_chain = false;
        return VMIC_ERR;
    }
    if (fsync(p->fd) != 0) LOGW("delta: fsync zlyhal: %s", strerror(errno));
    close(p->fd);
    p->fd = -1;

    if (rename(p->staging, p->final) != 0) {
        LOGE("delta: rename zlyhal: %s", strerror(errno));
        unlink(p->staging);
        p->have_chain = false;
        return VMIC_ERR;
    }

    snprintf(s->path, sizeof(s->path), "%s", p->final);
    s->chain_id      = p->chain_id;
    s->is_full       = p->full;
    s->pages_total   = p->pages_seen;
    s->pages_changed = p->pages_written;

    /*
     * Vektor pripneme k snimke az ked sedi s pocitadlami writera. Nezhoda
     * znamena chybu v mape binov, a vektor, ktoreho sucet nesedi so
     * snimkou, by tichu chybu preniesol az do trenovacich dat.
     */
    if (p->feat_on) {
        if (vmic_features_finish(&p->feat, p->pages_seen,
                                 p->pages_written) == VMIC_OK)
            s->features = &p->feat;
        else
            LOGE("delta: per-bin vektor nesedi so snimkou - do sidecaru "
                 "nejde");
    }
    s->bytes_logical = p->mem_size;
    int64_t on_disk = vmic_file_disk_usage(p->final);
    s->bytes_on_disk = on_disk > 0 ? (uint64_t)on_disk : 0;

    /*
     * Hash az tu, po odpauzovani VM, a nad KONTAJNEROM (.vmicd) - nie nad
     * logickym obrazom pamate. Delta subor je maly (typicky jednotky MB),
     * takze to nic nestoji, a `vmicollect verify` ho vie skontrolovat
     * rovnako ako raw snimku.
     */
    if (p->hashing && vmic_hash_file(p->final, s->sha256) == 0)
        s->has_hash = true;
    s->hash_covers_file = true;
    return VMIC_OK;
}

static void delta_abort(vmic_writer_t *w)
{
    delta_priv_t *p = (delta_priv_t *)w->priv;
    if (p->fd >= 0) { close(p->fd); p->fd = -1; }
    if (p->staging[0]) unlink(p->staging);
    p->active = false;
    /*
     * Prerusena snimka mohla zmenit tabulku hashov, ale jej subor
     * neexistuje - retazec by sa rozisiel. Preto vynutime, aby dalsia
     * snimka bola plna.
     */
    p->have_chain = false;
}

static void delta_destroy(vmic_writer_t *w)
{
    delta_priv_t *p = (delta_priv_t *)w->priv;
    if (!p) return;
    if (p->fd >= 0) close(p->fd);
    vmic_features_release(&p->feat);
    free(p->chg);
    free(p->hash);
    free(p);
    w->priv = NULL;
}

const vmic_writer_ops_t vmic_writer_delta = {
    .name                = "delta",
    .needs_random_access = true,
    .begin   = delta_begin,
    .feed    = delta_feed,
    .staging = NULL,          /* hromadny backend sa tu pouzit neda */
    .adopt   = NULL,
    .finish  = delta_finish,
    .abort   = delta_abort,
    .destroy = delta_destroy,
};

int vmic_writer_delta_alloc(vmic_writer_t *w)
{
    delta_priv_t *p = calloc(1, sizeof(delta_priv_t));
    if (!p) return VMIC_FATAL;
    p->fd = -1;
    w->priv = p;
    return VMIC_OK;
}

/* ================================================================== */
/* OBNOVA RETAZCA                                                      */
/* ================================================================== */

typedef struct {
    char     path[VMIC_PATH_MAX];
    uint64_t chain_id;
    uint64_t seq;
    uint64_t pages;
    uint64_t mem_size;
    uint64_t region_sig;
    uint32_t page_size;
    bool     full;
} chunk_info_t;

static int read_header(const char *path, chunk_info_t *out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t hdr[DELTA_HDR];
    ssize_t n = vmic_read_full(fd, hdr, sizeof(hdr));
    close(fd);
    if (n != (ssize_t)sizeof(hdr)) return -1;
    if (memcmp(hdr, DELTA_MAGIC, 8) != 0) return -1;
    if (get_u32(hdr + 8) != DELTA_VERSION) return -1;

    snprintf(out->path, sizeof(out->path), "%s", path);
    out->page_size = get_u32(hdr + 12);
    out->chain_id  = get_u64(hdr + 16);
    out->seq       = get_u64(hdr + 24);
    out->mem_size  = get_u64(hdr + 32);
    out->pages      = get_u64(hdr + 40);
    out->full       = (get_u64(hdr + 48) & DELTA_FLAG_FULL) != 0;
    out->region_sig = get_u64(hdr + 56);
    return 0;
}

static int cmp_seq(const void *a, const void *b)
{
    const chunk_info_t *x = (const chunk_info_t *)a;
    const chunk_info_t *y = (const chunk_info_t *)b;
    if (x->seq < y->seq) return -1;
    if (x->seq > y->seq) return 1;
    return 0;
}

int vmic_delta_restore(const char *dir, const char *out_path,
                       uint64_t chain_id, uint64_t until_seq)
{
    DIR *d = opendir(dir);
    if (!d) {
        LOGE("restore: nedaji sa otvorit '%s': %s", dir, strerror(errno));
        return VMIC_FATAL;
    }

    size_t cap = 64, n = 0;
    chunk_info_t *list = malloc(cap * sizeof(*list));
    if (!list) { closedir(d); return VMIC_FATAL; }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < sizeof(DELTA_EXT) ||
            strcmp(e->d_name + len - (sizeof(DELTA_EXT) - 1), DELTA_EXT) != 0)
            continue;

        char full[VMIC_PATH_MAX];
        if (vmic_join(full, sizeof(full), dir, e->d_name) != 0) continue;

        chunk_info_t info;
        if (read_header(full, &info) != 0) {
            LOGW("restore: '%s' nie je platny .vmicd subor - preskakujem",
                 e->d_name);
            continue;
        }
        if (n == cap) {
            cap *= 2;
            chunk_info_t *bigger = realloc(list, cap * sizeof(*list));
            if (!bigger) { free(list); closedir(d); return VMIC_FATAL; }
            list = bigger;
        }
        list[n++] = info;
    }
    closedir(d);

    if (!n) {
        LOGE("restore: v '%s' nie su ziadne .vmicd subory", dir);
        free(list);
        return VMIC_FATAL;
    }

    /* ked pouzivatel nepovedal ktory retazec, vezmeme najnovsi */
    if (chain_id == 0) {
        for (size_t i = 0; i < n; i++)
            if (list[i].chain_id > chain_id) chain_id = list[i].chain_id;
        LOGI("restore: vyberam najnovsi retazec %" PRIu64, chain_id);
    }

    /* vyfiltrujeme retazec a zoradime podla poradia */
    size_t keep = 0;
    for (size_t i = 0; i < n; i++) {
        if (list[i].chain_id != chain_id) continue;
        if (until_seq && list[i].seq > until_seq) continue;
        list[keep++] = list[i];
    }
    n = keep;
    if (!n) {
        LOGE("restore: retazec %" PRIu64 " sa nenasiel", chain_id);
        free(list);
        return VMIC_FATAL;
    }
    qsort(list, n, sizeof(*list), cmp_seq);

    if (!list[0].full) {
        LOGE("restore: retazec %" PRIu64 " nezacina plnou snimkou - "
             "chyba baseline (zmazala ho retencia?)", chain_id);
        free(list);
        return VMIC_FATAL;
    }

    /*
     * OVERENIE SUVISLOSTI RETAZCA.
     *
     * Delta sa aplikuje NA PREDCHADZAJUCI stav, takze chybajuca snimka
     * uprostred nie je "trochu horsi vysledok" - je to TICHO ZLY obraz:
     * stranky zmenene v chybajucej snimke by v nom ostali v starom stave
     * a nic by na to neupozornilo. Preto radsej odmietneme obnovu, nez
     * by sme vydali obraz, ktoremu sa neda verit.
     */
    uint32_t ps = list[0].page_size;
    uint64_t mem = 0;
    for (size_t i = 0; i < n; i++) {
        if (list[i].page_size != ps) {
            LOGE("restore: nekonzistentna velkost stranky v retazci "
                 "(%u vs %u)", list[i].page_size, ps);
            free(list);
            return VMIC_FATAL;
        }
        if (list[i].region_sig != list[0].region_sig) {
            LOGE("restore: snimka seq=%" PRIu64 " bola zozbierana s inou "
                 "konfiguraciou oblasti - retazec nie je konzistentny",
                 list[i].seq);
            free(list);
            return VMIC_FATAL;
        }
        if (i > 0) {
            if (list[i].seq == list[i - 1].seq) {
                LOGE("restore: dve snimky s rovnakym seq=%" PRIu64
                     " ('%s' a '%s')", list[i].seq,
                     list[i - 1].path, list[i].path);
                free(list);
                return VMIC_FATAL;
            }
            if (list[i].seq != list[i - 1].seq + 1) {
                LOGE("restore: v retazci chyba snimka seq=%" PRIu64
                     " (mam %" PRIu64 ", potom rovno %" PRIu64 ") - obnova "
                     "by dala TICHO nespravny obraz, koncim",
                     list[i - 1].seq + 1, list[i - 1].seq, list[i].seq);
                LOGE("  -> pouzi --until %" PRIu64 " ak ti staci stav po "
                     "poslednej suvislej snimke", list[i - 1].seq);
                free(list);
                return VMIC_FATAL;
            }
        }
        if (list[i].mem_size > mem) mem = list[i].mem_size;
    }

    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) {
        LOGE("restore: nedaji sa vytvorit '%s': %s", out_path, strerror(errno));
        free(list);
        return VMIC_FATAL;
    }

    uint8_t *page = malloc(ps);
    if (!page) { close(out); free(list); return VMIC_FATAL; }

    int rc = VMIC_OK;
    uint64_t applied = 0;

    for (size_t i = 0; i < n && rc == VMIC_OK; i++) {
        int in = open(list[i].path, O_RDONLY | O_CLOEXEC);
        if (in < 0) {
            LOGE("restore: '%s': %s", list[i].path, strerror(errno));
            rc = VMIC_FATAL;
            break;
        }
        if (lseek(in, DELTA_HDR, SEEK_SET) < 0) { close(in); rc = VMIC_FATAL; break; }

        for (uint64_t k = 0; k < list[i].pages; k++) {
            uint8_t idxbuf[8];
            if (vmic_read_full(in, idxbuf, 8) != 8 ||
                vmic_read_full(in, page, ps) != (ssize_t)ps) {
                LOGE("restore: '%s' je skrateny (zaznam %" PRIu64 "/%" PRIu64 ")",
                     list[i].path, k, list[i].pages);
                rc = VMIC_FATAL;
                break;
            }
            uint64_t idx = get_u64(idxbuf);
            /*
             * Index zo suboru je nedoveryhodny vstup (poskodeny subor,
             * ina verzia formatu). Bez tejto kontroly by idx * ps mohlo
             * pretiect a zapisat na uplne inu adresu.
             */
            if (ps == 0 || idx > (mem / ps) || idx > (UINT64_MAX / ps)) {
                LOGE("restore: '%s' obsahuje neplatny index stranky %"
                     PRIu64 " (limit %" PRIu64 ")",
                     list[i].path, idx, mem / ps);
                rc = VMIC_FATAL;
                break;
            }
            if (vmic_pwrite_all(out, page, ps, (off_t)(idx * ps)) != 0) {
                LOGE("restore: zapis zlyhal: %s", strerror(errno));
                rc = VMIC_FATAL;
                break;
            }
            applied++;
        }
        close(in);
        LOGI("restore: %s  seq=%" PRIu64 "  %s  %" PRIu64 " stranok",
             list[i].path, list[i].seq, list[i].full ? "PLNA " : "delta",
             list[i].pages);
    }

    if (rc == VMIC_OK && ftruncate(out, (off_t)mem) != 0)
        LOGW("restore: ftruncate zlyhal: %s", strerror(errno));

    free(page);
    close(out);
    free(list);

    if (rc == VMIC_OK) {
        char human[32];
        vmic_human_size(mem, human, sizeof(human));
        LOGI("restore: hotovo -> %s (%s, %" PRIu64 " zapisanych stranok)",
             out_path, human, applied);
    } else {
        unlink(out_path);
    }
    return rc;
}
