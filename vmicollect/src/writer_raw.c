/*
 * writer_raw.c - ukladanie surovej snimky.
 *
 * Dve veci, ktore stoja za pozornost:
 *
 * 1) OFFSET V SUBORE == FYZICKA ADRESA.
 *    Nezhusťujeme, nepresuvame. Vdaka tomu je vysledok priamo pouzitelny
 *    v kazdom dalsom nastroji (Volatility, tvoj parser) a nemusis nikde
 *    prepocitavat adresy. Diery vo fyzickom priestore su v subore diery.
 *
 * 2) RIEDKY ZAPIS (sparse).
 *    Nulove bloky vobec nezapisujeme - iba posunieme koniec suboru.
 *    Typicka VM ma velku cast RAM nulovu, takze to setri aj miesto aj
 *    cas, a cas je tu kriticky: tento kod bezi s pozastavenou VM.
 *
 * 3) HASH SA POCITA PRIEBEZNE, GZIP AZ PO ODPAUZOVANI.
 *    Povodne sa SHA-256 pocital v finish() nad hotovym suborom. Pri
 *    riedkej snimke to znamenalo precitat cely subor od nuly po
 *    end_offset - teda aj vsetky diery, ktore sa nikdy nezapisali.
 *    Dnes hashujeme ten isty prud bajtov uz vo feed(): zapisane bloky
 *    priamo z buffra a diery ako nuly z pamate, bez citania z disku.
 *
 *    SEMANTIKA HASHU SA NEMENI. Je to stale SHA-256 obsahu suboru
 *    vratane dier, takze 'vmicollect verify' aj selftest ho overia
 *    rovnako ako predtym (verify subor precita a hash prepocita).
 *
 *    Priebezny hash sa vypina v dvoch pripadoch:
 *      - capture.pause = true: feed() vtedy bezi s pozastavenymi vCPU
 *        a hashovanie by pauzu VM predlzilo (presne ten dovod, pre
 *        ktory tu hash povodne nebol);
 *      - hromadny backend (adopt): subor zapisal externy nastroj,
 *        cez feed() nepresiel ani bajt.
 *    V oboch pripadoch sa hashuje hotovy subor v finish(), ako predtym.
 *
 *    gzip zostava v finish(), teda az po vmi_resume_vm().
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "internal.h"
#include "log.h"
#include "sha256.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

typedef struct {
    int            fd;
    char           staging[VMIC_PATH_MAX];
    char           final[VMIC_PATH_MAX];
    bool           hashing;      /* pouzivatel chce SHA-256             */
    bool           stream;       /* pocitame ho priebezne vo feed()     */
    vmic_sha256_t  sha;          /* rozpracovany priebezny hash         */
    uint64_t       hashed;       /* kolko bajtov uz preslo cez sha      */
    uint64_t       end_offset;   /* najvyssi zapisany offset + 1        */
    uint64_t       logical;      /* kolko bajtov preslo cez feed()      */
    bool           bulk;         /* subor vytvoril externy nastroj      */
    bool           active;
} raw_priv_t;

/* ------------------------------------------------------------------ */

/*
 * Diera v riedkom subore je z pohladu citatela postupnost nul. Do
 * priebezneho hashu ju teda davame ako nuly - z konstantneho buffra
 * v pamati, nie citanim z disku. Hash tym zostava hashom OBSAHU suboru.
 */
static void raw_hash_zeros(raw_priv_t *p, uint64_t n)
{
    static const uint8_t zero[4096] = { 0 };
    while (n) {
        size_t take = n < sizeof(zero) ? (size_t)n : sizeof(zero);
        vmic_sha256_update(&p->sha, zero, take);
        n -= take;
    }
}

static int raw_open_fd(raw_priv_t *p)
{
    if (p->fd >= 0) return VMIC_OK;
    p->fd = open(p->staging, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (p->fd < 0) {
        LOGE("raw: nedaji sa vytvorit '%s': %s", p->staging, strerror(errno));
        return VMIC_ERR;
    }
    return VMIC_OK;
}

static int raw_begin(vmic_writer_t *w, vmic_snapshot_t *s)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;

    /*
     * Zapisujeme do '.part' a az na konci premenujeme. Rename je v ramci
     * jedneho suboroveho systemu atomicky, takze ziadny iny proces nikdy
     * neuvidi rozpisanu snimku - dolezite, ked na adresar niekto pozera
     * (napr. tvoj feature extractor alebo inotify watcher).
     */
    char name[VMIC_NAME_MAX + 32];
    snprintf(name, sizeof(name), ".%s%s.part", s->id, s->ext);
    if (vmic_join(p->staging, sizeof(p->staging), w->cfg->dir, name) != 0) {
        LOGE("raw: prilis dlha cesta k docasnemu suboru");
        return VMIC_ERR;
    }
    snprintf(name, sizeof(name), "%s%s", s->id, s->ext);
    if (vmic_join(p->final, sizeof(p->final), w->cfg->dir, name) != 0) {
        LOGE("raw: prilis dlha cesta k vystupu");
        return VMIC_ERR;
    }

    p->fd         = -1;
    p->end_offset = 0;
    p->logical    = 0;
    p->bulk       = false;
    p->active     = true;
    p->hashing    = (w->cfg->hash == VMIC_HASH_SHA256);

    /*
     * Priebezny hash zapneme, len ked feed() NEBEZI v pauze VM.
     * Pri capture.pause = true by hashovanie predlzilo cas, ked su vCPU
     * zastavene - vtedy radsej zaplatime druhy prechod suborom v
     * finish(), ked uz VM bezi.
     */
    p->stream     = p->hashing && !w->cfg->pause;
    p->hashed     = 0;
    if (p->stream) vmic_sha256_init(&p->sha);

    /* fd otvarame az lenivo vo feed() - hromadny backend si subor
       vytvori sam a nesmieme mu don zasahovat */
    return VMIC_OK;
}

static int raw_feed(vmic_writer_t *w, uint64_t paddr,
                    const uint8_t *buf, size_t len)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;
    if (raw_open_fd(p) != VMIC_OK) return VMIC_ERR;

    p->logical += len;

    /*
     * Hashujeme PRED zapisom a nad tym istym buffrom - vratane blokov,
     * ktore sa kvoli riedkemu zapisu na disk vobec nedostanu (su nulove,
     * takze v subore aj tak citatelne ako nuly).
     *
     * Predpoklad: bloky chodia vzostupne podla fyzickej adresy a
     * neprekryvaju sa (vmic_capture() ide po oblastiach, ktore backend
     * vracia zoradene a zlucene). Ked to niekedy neplati, priebezny
     * hash zahodime a spocitame ho z hotoveho suboru - hodnota je
     * potom ta ista, len pomalsie.
     */
    if (p->stream) {
        if (paddr < p->hashed) {
            LOGD("raw: blok 0x%" PRIx64 " sa prekryva s uz zahashovanou "
                 "castou (0x%" PRIx64 ") - hashujem az hotovy subor",
                 paddr, p->hashed);
            p->stream = false;
        } else {
            if (paddr > p->hashed) raw_hash_zeros(p, paddr - p->hashed);
            vmic_sha256_update(&p->sha, buf, len);
            p->hashed = paddr + len;
        }
    }

    bool skip = w->cfg->sparse && vmic_is_zero(buf, len);
    if (!skip) {
        if (vmic_pwrite_all(p->fd, buf, len, (off_t)paddr) != 0) {
            LOGE("raw: zapis na offset 0x%" PRIx64 " zlyhal: %s",
                 paddr, strerror(errno));
            return VMIC_ERR;
        }
    }
    if (paddr + len > p->end_offset) p->end_offset = paddr + len;
    return VMIC_OK;
}

static const char *raw_staging(vmic_writer_t *w)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;
    p->bulk = true;
    return p->staging;
}

/* Externy nastroj uz subor zapisal - staci nam jeho velkost.
   Cez feed() nepresiel ani bajt, takze priebezny hash tu neexistuje a
   SHA-256 sa spocita z hotoveho suboru v finish(). */
static int raw_adopt(vmic_writer_t *w)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;
    int64_t sz = vmic_file_size(p->staging);
    if (sz < 0) return VMIC_ERR;
    p->end_offset = (uint64_t)sz;
    p->logical    = (uint64_t)sz;
    p->stream     = false;
    return VMIC_OK;
}

/* gzip az po odpauzovani VM */
static int raw_gzip(const char *src, char *dst, size_t dstn)
{
    snprintf(dst, dstn, "%s.gz", src);

    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    gzFile out = gzopen(dst, "wb1");        /* uroven 1 = rychlost > pomer */
    if (!out) { close(in); return -1; }

    uint8_t *buf = malloc(1u << 20);
    if (!buf) { close(in); gzclose(out); unlink(dst); return -1; }

    int rc = 0;
    for (;;) {
        ssize_t n = vmic_read_full(in, buf, 1u << 20);
        if (n < 0)  { rc = -1; break; }
        if (n == 0) break;
        if (gzwrite(out, buf, (unsigned)n) != (int)n) { rc = -1; break; }
        if ((size_t)n < (1u << 20)) break;
    }
    free(buf);
    close(in);
    if (gzclose(out) != Z_OK) rc = -1;
    if (rc != 0) { unlink(dst); return -1; }
    unlink(src);
    return 0;
}

static int raw_finish(vmic_writer_t *w, vmic_snapshot_t *s)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;
    if (!p->active) return VMIC_ERR;
    p->active = false;

    if (p->fd >= 0) {
        /*
         * ftruncate posunie koniec suboru na koniec poslednej oblasti.
         * Bez toho by chybali koncove nuly (riedky zapis ich nezapisal)
         * a subor by bol kratsi ako pamat, ktoru ma reprezentovat.
         */
        if (ftruncate(p->fd, (off_t)p->end_offset) != 0)
            LOGW("raw: ftruncate zlyhal: %s", strerror(errno));
        if (fsync(p->fd) != 0)
            LOGW("raw: fsync zlyhal: %s", strerror(errno));
        close(p->fd);
        p->fd = -1;
    }

    if (rename(p->staging, p->final) != 0) {
        LOGE("raw: rename '%s' -> '%s': %s",
             p->staging, p->final, strerror(errno));
        unlink(p->staging);
        return VMIC_ERR;
    }

    /*
     * Hash je vzdy nad NEKOMPRIMOVANYM obsahom suboru. Vdaka tomu je
     * porovnatelny bez ohladu na to, ci sa neskor komprimovalo - a
     * `vmicollect verify` vie .gz najprv rozbalit.
     *
     * Rychla cesta: priebezny hash z feed(). Podmienka p->hashed ==
     * p->end_offset je poistka - ked by sa poradie blokov niekedy
     * zmenilo, radsej sa vratime k hashu hotoveho suboru, nez by sme
     * zapisali do metadat nespravnu hodnotu.
     */
    if (p->hashing) {
        bool ok;
        if (p->stream && !p->bulk && p->hashed == p->end_offset) {
            vmic_sha256_final(&p->sha, s->sha256);
            ok = true;
        } else {
            ok = (vmic_hash_file(p->final, s->sha256) == 0);
            if (!ok)
                LOGW("raw: hash sa nepodarilo spocitat: %s", strerror(errno));
        }
        s->has_hash = ok;
    }

    if (w->cfg->post_compress == VMIC_COMPRESS_GZIP) {
        char gz[VMIC_PATH_MAX];
        if (raw_gzip(p->final, gz, sizeof(gz)) == 0) {
            snprintf(p->final, sizeof(p->final), "%s", gz);
            /* pozor: snprintf() so zdrojom == cielom je nedefinovane
               spravanie, preto cez pomocny buffer */
            char newext[sizeof(s->ext)];
            snprintf(newext, sizeof(newext), "%s.gz", s->ext);
            memcpy(s->ext, newext, sizeof(s->ext));
        } else {
            LOGW("raw: gzip zlyhal, nechavam nekomprimovane");
        }
    }

    snprintf(s->path, sizeof(s->path), "%s", p->final);
    s->bytes_logical = p->logical;
    int64_t on_disk = vmic_file_disk_usage(p->final);
    s->bytes_on_disk = on_disk > 0 ? (uint64_t)on_disk : 0;
    s->is_full   = true;      /* raw snimka je vzdy uplna */
    s->chain_id  = 0;
    /* hash je nad obsahom suboru (po pripadnom rozbaleni .gz) */
    s->hash_covers_file = true;
    return VMIC_OK;
}

static void raw_abort(vmic_writer_t *w)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;
    if (p->fd >= 0) { close(p->fd); p->fd = -1; }
    if (p->staging[0]) unlink(p->staging);
    p->active = false;
}

static void raw_destroy(vmic_writer_t *w)
{
    raw_priv_t *p = (raw_priv_t *)w->priv;
    if (!p) return;
    if (p->fd >= 0) close(p->fd);
    free(p);
    w->priv = NULL;
}

const vmic_writer_ops_t vmic_writer_raw = {
    .name                = "raw",
    .needs_random_access = false,
    .begin   = raw_begin,
    .feed    = raw_feed,
    .staging = raw_staging,
    .adopt   = raw_adopt,
    .finish  = raw_finish,
    .abort   = raw_abort,
    .destroy = raw_destroy,
};

int vmic_writer_raw_alloc(vmic_writer_t *w)
{
    raw_priv_t *p = calloc(1, sizeof(raw_priv_t));
    if (!p) return VMIC_FATAL;
    p->fd = -1;
    w->priv = p;
    return VMIC_OK;
}
