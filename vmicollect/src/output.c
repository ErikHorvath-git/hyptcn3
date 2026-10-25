/*
 * output.c - fronta snimok a vlakno vmic-writer (pozri output.h).
 *
 * PRECO: kampan benign-v4 zamietla session, lebo jeden cyklus trval
 * 5,083 s pri periode 5 s. Zapis plnej snimky (stovky MiB) zostal v page
 * cache a jadro ho neskor zapisovalo naraz; SSD bez DRAM pritom stal na
 * 100 % s priepustnostou par MB/s a vytvorenie, zapis ci rename suboru na
 * tom istom ext4 cakali. Vzorkovacie vlakno to vsetko robilo samo, takze
 * cakanie disku sa pripocitalo k cyklu. Tu sa disk od cyklu oddeluje:
 * vzorkovac iba kopiruje do pamate a zapisuje vlakno vmic-writer.
 *
 * VZORKOVAC NEALOKUJE: deskriptory snimok aj kusy pamate su pripravene pri
 * starte. Alokacia v cykle by pri uzamknutej pamati (output.mlock) mohla
 * skoncit v uvolnovani pamate v jadre a to moze cakat na zapis na disk.
 *
 * ZARUKY PRE CITATELOV VYSTUPU (audit, safeguard, verify):
 *   - snimky sa zverejnuju v poradi seq (jedna FIFO fronta, jedno vlakno);
 *   - snimka je zverejnena cela, alebo vobec: data aj sidecar sa najprv
 *     zapisu pod docasnymi menami (.<id>.vmicd.part, .<id>.json.tmp) a az
 *     potom sa hned po sebe premenuju - najprv data, potom sidecar; ked
 *     zlyha premenovanie sidecaru, data sa znovu zmazu;
 *   - docasne mena su bodkove a nekoncia na .vmicd ani .json; premenovanie
 *     ma RENAME_NOREPLACE, takze sa nikdy nic neprepise;
 *   - hash v sidecari je SHA-256 presne tych bajtov, ktore sa zapisali.
 *
 * KONIEC PO VYPRSANOM LIMITE (vmic_output_drain): zvysok fronty sa zahodi
 * a zapocita ako chyba; zapisovac pri najblizsej kontrole (po kazdom kuse
 * dat a pred kazdym krokom) snimku vzdá a sam zmaze svoje docasne subory.
 * Hlavne vlakno na ne nesiaha - unlink by cakal na ten isty zaseknuty disk.
 * Ked zapisovac stoji v jedinom syscalle dlhsie nez kratku lehotu, proces
 * skonci bez neho: docasny bodkovy subor potom moze zostat a ked syscall
 * bol prave premenovanie dat, aj .vmicd bez sidecaru. Je to iba cesta uz
 * neuspesneho behu (koniec ma E > 0, kod 4).
 */

#define _GNU_SOURCE
#include "output.h"
#include "log.h"
#include "sha256.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHUNK        (1u << 20)
/* prvych 8 B kusa je odkaz na dalsi kus snimky, zvysok su data */
#define CHUNK_LINK   sizeof(uint8_t *)
#define CHUNK_DATA   (CHUNK - CHUNK_LINK)
#define HDR_MAX      64u
#define EXTRA_BYTES  (512ull << 20)
#define JOBS_MAX     1024u        /* deskriptory: hodina backlogu pri 5 s */
#define JOBS_MIN     16u
#define BINS_STORE_MAX (256ull << 20)
#define WAIT_SLICE_S 0.1          /* cakania kontroluju *stop takto casto */
#define STALL_WARN_S 30.0         /* prve varovanie o zaseknutom zapise   */
#define STALL_EVERY_S 60.0
#define STOP_BUDGET_S 40.0        /* dobehnutie po signale (SIGKILL o 60 s) */
#define ABANDON_GRACE_S 3.0       /* lehota na upratanie zapisovacom      */

/* Operacie zapisovaca: strazca hlasi tu, ktora trva, suhrn najdlhsiu z kazdej. */
static const char *const OP_NAMES[VMIC_OUTPUT_OPS] = {
    "vytvorenie", "zapis", "fsync", "sidecar", "rename", "hook", "retencia"
};
enum { OP_CREATE, OP_WRITE, OP_FSYNC, OP_SIDECAR, OP_RENAME, OP_HOOK, OP_RETENTION, OP_NONE };

struct vmic_job {
    vmic_job_t     *next;          /* fronta alebo volne deskriptory   */
    /* kopia snimky; jej ukazovatele vedu do poli nizsie, nie do zberaca */
    vmic_snapshot_t snap;
    vmic_vminfo_t   vm;
    vmic_region_t   regions[VMIC_MAX_REGIONS];
    vmic_features_t feat;
    vmic_region_t   feat_regions[VMIC_MAX_REGIONS];
    vmic_bin_t     *bins;          /* kapacita o->max_bins, z prealokacie */

    uint8_t         hdr[HDR_MAX];
    size_t          hdr_len;
    char            staging[VMIC_PATH_MAX];
    char            sidecar_tmp[VMIC_PATH_MAX];
    uint8_t        *first, *last;  /* zretazene kusy poolu             */
    size_t          fill;          /* data v poslednom kuse            */
    uint64_t        bytes;         /* dlzka dat za hlavickou           */
    double          t_start;       /* monotonny zaciatok cyklu          */
    double          wait_ms;       /* vzorkovac cakal na pamat/deskriptor */
};

struct vmic_output {
    const vmic_config_t   *cfg;
    vmic_hooks_t          *hooks;
    volatile sig_atomic_t *stop;

    uint8_t    *pool;
    size_t      pool_bytes;
    uint8_t   **free_chunks;
    size_t      free_count;
    vmic_job_t *jobs;
    size_t      njobs;
    vmic_bin_t *bins_store;
    size_t      max_bins;
    vmic_job_t *free_jobs;

    pthread_mutex_t mu;
    pthread_cond_t  cv_work;       /* zapisovac: nova snimka / koniec  */
    pthread_cond_t  cv_space;      /* vzorkovac: uvolnila sa pamat     */
    pthread_cond_t  cv_idle;       /* drain: fronta prazdna            */
    vmic_job_t *head, *tail;
    uint64_t    queued_jobs;
    uint64_t    queued_bytes;      /* data snimok vo fronte            */
    uint64_t    inflight_bytes;    /* nezapisane data snimky v zapise  */
    bool        busy;              /* zapisovac prave spracuva snimku  */
    bool        stopping;
    bool        abandon;           /* drain vyprsal: zvysok sa zahodi  */
    pthread_t   thread;

    /* strazca: co zapisovac robi a odkedy (cita ho vzorkovac) */
    int         op;
    double      op_since;
    uint64_t    op_seq;
    double      stall_warned;

    uint64_t    broken_chain;      /* retazec poslednej zlyhanej snimky */
    bool        fatal;
    vmic_output_stats_t st;
};

/* ------------------------------------------------------------------ */
/* Pomocky                                                             */
/* ------------------------------------------------------------------ */

static inline uint8_t *chunk_next(const uint8_t *c)
{
    uint8_t *n;
    memcpy(&n, c, sizeof(n));
    return n;
}

static inline void chunk_link(uint8_t *c, uint8_t *next)
{
    memcpy(c, &next, sizeof(next));
}

/* Absolutny termin pre pthread_cond_timedwait na CLOCK_MONOTONIC. */
static struct timespec deadline_in(double seconds)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long add = (long)(seconds * 1e9);
    ts.tv_sec  += add / 1000000000L;
    ts.tv_nsec += add % 1000000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return ts;
}

uint64_t vmic_output_pool_bytes(const vmic_config_t *cfg,
                                const vmic_region_t *regions, size_t region_count)
{
    if (cfg->queue_mib) return cfg->queue_mib << 20;
    uint64_t pages = 0;
    for (size_t i = 0; i < region_count; i++)
        pages += regions[i].size / cfg->delta_page_size;
    /* plna snimka so vsetkymi strankami: (index + stranka) na stranku */
    uint64_t full = pages * (8ull + cfg->delta_page_size);
    return ((full + CHUNK_DATA - 1) / CHUNK_DATA) * CHUNK + EXTRA_BYTES;
}

size_t vmic_output_max_bins(const vmic_config_t *cfg,
                            const vmic_region_t *regions, size_t region_count)
{
    if (!cfg->feat_enable || !cfg->feat_bin_bytes) return 0;   /* ziadny vektor */
    size_t bins = 0;
    for (size_t i = 0; i < region_count; i++)
        bins += (size_t)(regions[i].size / cfg->feat_bin_bytes) + 2;
    /* rezerva pre zmenu pamate VM za behu */
    return bins * 2 + 16;
}

/* Pocet deskriptorov: kopie vektorov spolu najviac BINS_STORE_MAX. */
static size_t jobs_for(size_t max_bins)
{
    if (!max_bins) return JOBS_MAX;
    uint64_t per = (uint64_t)max_bins * sizeof(vmic_bin_t);
    uint64_t fit = BINS_STORE_MAX / per;
    return fit >= JOBS_MAX ? JOBS_MAX : (size_t)fit;
}

uint64_t vmic_output_overhead_bytes(size_t max_bins)
{
    size_t jobs = jobs_for(max_bins);
    if (jobs < JOBS_MIN) jobs = JOBS_MIN;
    return (uint64_t)jobs * (sizeof(vmic_job_t) + (uint64_t)max_bins * sizeof(vmic_bin_t));
}

/* Heartbeat zapisovaca: zapise trvanie predoslej operacie do maxim a zacne
   dalsiu. Vrati true, ked drain vyprsal a zapisovac ma snimku vzdat. */
static bool set_op(vmic_output_t *o, int op, uint64_t seq)
{
    double now = vmic_now_mono();
    pthread_mutex_lock(&o->mu);
    if (o->op != OP_NONE && now - o->op_since > o->st.op_max_s[o->op])
        o->st.op_max_s[o->op] = now - o->op_since;
    o->op = op;
    o->op_since = now;
    o->op_seq = seq;
    bool abandon = o->abandon;
    pthread_mutex_unlock(&o->mu);
    return abandon;
}

static bool abandoning(vmic_output_t *o)
{
    pthread_mutex_lock(&o->mu);
    bool a = o->abandon;
    pthread_mutex_unlock(&o->mu);
    return a;
}

/* ------------------------------------------------------------------ */
/* Pool a deskriptory                                                  */
/* ------------------------------------------------------------------ */

static void chunk_put_locked(vmic_output_t *o, uint8_t *chunk)
{
    o->free_chunks[o->free_count++] = chunk;
}

/*
 * Pocka na volny kus alebo deskriptor. Vrati VMIC_OK, VMIC_STOP (prisiel
 * signal) alebo VMIC_ERR (snimka by potrebovala viac nez cely pool:
 * zapisovac nic nerobi, fronta je prazdna a vsetko drzi rozpracovana snimka).
 */
static int wait_for(vmic_output_t *o, double *waited_ms, bool want_job)
{
    double t0 = 0.0;
    int rc = VMIC_OK;
    while (want_job ? !o->free_jobs : !o->free_count) {
        if (!o->busy && !o->head) { rc = VMIC_ERR; break; }
        if (o->stop && *o->stop) { rc = VMIC_STOP; break; }
        if (t0 == 0.0) t0 = vmic_now_mono();
        struct timespec until = deadline_in(WAIT_SLICE_S);
        pthread_cond_timedwait(&o->cv_space, &o->mu, &until);
    }
    if (t0 != 0.0) *waited_ms += (vmic_now_mono() - t0) * 1000.0;
    return rc;
}

static void job_release_locked(vmic_output_t *o, vmic_job_t *j)
{
    for (uint8_t *c = j->first; c; ) {
        uint8_t *next = chunk_next(c);
        chunk_put_locked(o, c);
        c = next;
    }
    j->first = j->last = NULL;
    j->next = o->free_jobs;
    o->free_jobs = j;
    pthread_cond_broadcast(&o->cv_space);
}

/* ------------------------------------------------------------------ */
/* Vzorkovacie vlakno                                                  */
/* ------------------------------------------------------------------ */

int vmic_output_job_new(vmic_output_t *o, vmic_job_t **out)
{
    *out = NULL;
    double waited = 0.0;
    pthread_mutex_lock(&o->mu);
    int rc = wait_for(o, &waited, true);
    if (rc == VMIC_OK) {
        vmic_job_t *j = o->free_jobs;
        o->free_jobs = j->next;
        vmic_bin_t *bins = j->bins;
        memset(j, 0, sizeof(*j));
        j->bins = bins;
        j->wait_ms = waited;
        *out = j;
    }
    pthread_mutex_unlock(&o->mu);
    return rc;
}

int vmic_output_job_append(vmic_output_t *o, vmic_job_t *j, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len) {
        if (!j->last || j->fill == CHUNK_DATA) {
            pthread_mutex_lock(&o->mu);
            int rc = wait_for(o, &j->wait_ms, false);
            uint8_t *chunk = rc == VMIC_OK ? o->free_chunks[--o->free_count] : NULL;
            pthread_mutex_unlock(&o->mu);
            if (!chunk) return rc;
            chunk_link(chunk, NULL);
            if (j->last) chunk_link(j->last, chunk); else j->first = chunk;
            j->last = chunk;
            j->fill = 0;
        }
        size_t n = CHUNK_DATA - j->fill;
        if (n > len) n = len;
        memcpy(j->last + CHUNK_LINK + j->fill, p, n);
        j->fill  += n;
        j->bytes += n;
        p   += n;
        len -= n;
    }
    return VMIC_OK;
}

void vmic_output_job_free(vmic_output_t *o, vmic_job_t *j)
{
    if (!o || !j) return;
    pthread_mutex_lock(&o->mu);
    job_release_locked(o, j);
    pthread_mutex_unlock(&o->mu);
}

double vmic_output_job_wait_ms(const vmic_job_t *j)
{
    return j ? j->wait_ms : 0.0;
}

int vmic_output_job_submit(vmic_output_t *o, vmic_job_t *j, const vmic_snapshot_t *s,
                           const uint8_t *hdr, size_t hdr_len, const char *staging,
                           double t_start)
{
    if (hdr_len > HDR_MAX) return VMIC_ERR;
    size_t nbins = s->features ? s->features->bins_total : 0;
    if (nbins > o->max_bins) {
        LOGE("zapis: snimka ma %zu binov, deskriptor iba %zu", nbins, o->max_bins);
        return VMIC_FATAL;            /* kazda dalsia snimka by zlyhala tiez */
    }
    vmic_bin_t *bins = j->bins;
    j->snap = *s;
    j->vm = *s->vm;
    j->snap.vm = &j->vm;
    if (s->regions && s->region_count <= VMIC_MAX_REGIONS) {
        memcpy(j->regions, s->regions, s->region_count * sizeof(*s->regions));
        j->snap.regions = j->regions;
    } else {
        j->snap.regions = NULL;
        j->snap.region_count = 0;
    }
    j->snap.features = NULL;
    if (nbins) {
        const vmic_features_t *f = s->features;
        memcpy(bins, f->bins, nbins * sizeof(*f->bins));
        j->feat = *f;
        j->feat.bins = bins;
        j->feat.priv = NULL;
        j->feat.region_count = f->region_count <= VMIC_MAX_REGIONS ? f->region_count : 0;
        if (j->feat.region_count)
            memcpy(j->feat_regions, f->regions, j->feat.region_count * sizeof(*f->regions));
        j->feat.regions = j->feat_regions;
        j->snap.features = &j->feat;
    }
    memcpy(j->hdr, hdr, hdr_len);
    j->hdr_len = hdr_len;
    /* Obe docasne mena su pevne uz pri zaradeni a zapisovac ich nemeni. */
    snprintf(j->staging, sizeof(j->staging), "%s", staging);
    char name[VMIC_NAME_MAX + 32];
    snprintf(name, sizeof(name), ".%s.json.tmp", s->id);
    if (vmic_join(j->sidecar_tmp, sizeof(j->sidecar_tmp), o->cfg->dir, name) != 0) return VMIC_ERR;
    j->t_start = t_start;
    j->snap.queue_pool_bytes = o->pool_bytes;

    pthread_mutex_lock(&o->mu);
    /* backlog = snimky vo fronte + nezapisany zvysok snimky, ktoru zapisovac
       prave pise (aj ked je to plna snimka, ktora sa zasekla) */
    j->snap.queue_bytes = o->queued_bytes + o->inflight_bytes;
    j->snap.queue_jobs  = o->queued_jobs + (o->busy ? 1 : 0);
    if (j->snap.queue_bytes > o->st.max_queue_bytes) o->st.max_queue_bytes = j->snap.queue_bytes;
    if (j->snap.queue_jobs > o->st.max_queue_jobs) o->st.max_queue_jobs = j->snap.queue_jobs;
    o->queued_bytes += j->bytes;
    o->queued_jobs++;
    o->st.submitted++;
    if (j->wait_ms > 0.0) {
        o->st.wait_ms += j->wait_ms;
        o->st.wait_cycles++;
    }
    j->next = NULL;
    if (o->tail) o->tail->next = j; else o->head = j;
    o->tail = j;
    pthread_cond_signal(&o->cv_work);
    pthread_mutex_unlock(&o->mu);
    return VMIC_OK;
}

bool vmic_output_chain_broken(vmic_output_t *o, uint64_t chain_id)
{
    pthread_mutex_lock(&o->mu);
    bool broken = chain_id && o->broken_chain == chain_id;
    pthread_mutex_unlock(&o->mu);
    return broken;
}

const char *vmic_output_op_name(int op)
{
    return op >= 0 && op < VMIC_OUTPUT_OPS ? OP_NAMES[op] : "?";
}

bool vmic_output_fatal(vmic_output_t *o)
{
    if (!o) return false;
    pthread_mutex_lock(&o->mu);
    bool fatal = o->fatal;
    pthread_mutex_unlock(&o->mu);
    return fatal;
}

void vmic_output_watch(vmic_output_t *o)
{
    if (!o) return;
    double now = vmic_now_mono();
    pthread_mutex_lock(&o->mu);
    double age = o->busy ? now - o->op_since : 0.0;
    double oldest = o->head ? now - o->head->t_start : 0.0;
    const char *op = o->op != OP_NONE ? OP_NAMES[o->op] : NULL;
    uint64_t seq = o->op_seq, jobs = o->queued_jobs + (o->busy ? 1 : 0);
    uint64_t bytes = o->queued_bytes + o->inflight_bytes;
    bool warn = (age > STALL_WARN_S || oldest > STALL_WARN_S) &&
                now - o->stall_warned > STALL_EVERY_S;
    if (warn) o->stall_warned = now;
    pthread_mutex_unlock(&o->mu);
    if (warn) {
        char human[32];
        vmic_human_size(bytes, human, sizeof(human));
        LOGW("zapisovac: '%s' snimky seq=%" PRIu64 " trva %.0f s, najstarsia snimka "
             "vo fronte caka %.0f s, fronta %" PRIu64 " snimok (%s)",
             op ? op : "?", seq, age, oldest, jobs, human);
    }
}

/* ------------------------------------------------------------------ */
/* Vlakno vmic-writer                                                  */
/* ------------------------------------------------------------------ */

static void fail(vmic_output_t *o, vmic_job_t *j, bool break_chain)
{
    pthread_mutex_lock(&o->mu);
    o->st.failed++;
    /* Hashe vo vzorkovaci uz pocitaju s touto snimkou: retazec je rozbity,
       dalsie delty z neho sa zahodia a dalsia snimka bude plna. */
    if (break_chain) o->broken_chain = j->snap.chain_id;
    pthread_mutex_unlock(&o->mu);
}

/* Snimka vzdana po vyprsanom drain: zapocita sa tu, nie v drain(). */
static void gave_up(vmic_output_t *o)
{
    pthread_mutex_lock(&o->mu);
    o->st.abandoned++;
    pthread_mutex_unlock(&o->mu);
}

/* Kus dat je zapisany (alebo uz zbytocny): vrat ho do poolu. */
static void chunk_done(vmic_output_t *o, uint8_t *c, size_t len)
{
    pthread_mutex_lock(&o->mu);
    chunk_put_locked(o, c);
    o->inflight_bytes = o->inflight_bytes > len ? o->inflight_bytes - len : 0;
    pthread_cond_broadcast(&o->cv_space);
    pthread_mutex_unlock(&o->mu);
}

/* Data snimky do .part: hlavicka a kusy, SHA-256 tych istych bajtov, fsync.
   VMIC_STOP = drain vyprsal; .part je uz zmazany. */
static int write_data(vmic_output_t *o, vmic_job_t *j, bool hashing)
{
    vmic_sha256_t sha;
    if (hashing) vmic_sha256_init(&sha);
    double sha_s = 0.0;

    if (set_op(o, OP_CREATE, j->snap.seq)) return VMIC_STOP;
    double t0 = vmic_now_mono();
    int fd = open(j->staging, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOGE("zapis: nedaji sa vytvorit '%s': %s", j->staging, strerror(errno));
        return VMIC_ERR;
    }
    bool stopped = set_op(o, OP_WRITE, j->snap.seq);
    const char *failed = NULL;
    int err = 0;
    if (!stopped && vmic_write_all(fd, j->hdr, j->hdr_len) != 0) { failed = "zapis hlavicky"; err = errno; }
    if (hashing) vmic_sha256_update(&sha, j->hdr, j->hdr_len);
    uint8_t *c = j->first;
    while (c) {
        uint8_t *next = chunk_next(c);
        size_t len = next ? CHUNK_DATA : j->fill;
        if (!stopped && !failed) stopped = abandoning(o);   /* po kazdom kuse */
        if (!stopped && !failed && vmic_write_all(fd, c + CHUNK_LINK, len) != 0) {
            failed = "zapis dat";
            err = errno;
        }
        if (!stopped && !failed && hashing) {
            double ts = vmic_now_mono();
            vmic_sha256_update(&sha, c + CHUNK_LINK, len);
            sha_s += vmic_now_mono() - ts;
        }
        /* pamat sa uvolnuje priebezne, vzorkovac ju moze hned pouzit */
        chunk_done(o, c, len);
        c = next;
    }
    j->first = j->last = NULL;
    if (stopped) {
        close(fd);
        unlink(j->staging);
        return VMIC_STOP;
    }
    /* output.fsync=true: snimka sa zverejni az po uspesnom fsync; zlyhany
       fsync alebo close je chyba snimky, nie varovanie. */
    if (!failed && o->cfg->fsync) {
        set_op(o, OP_FSYNC, j->snap.seq);
        if (fsync(fd) != 0) { failed = "fsync"; err = errno; }
    }
    /* bytes_on_disk ma rovnaky vyznam ako predtym: alokovane miesto
       (st_blocks * 512, pri ext4 vratane rezervacie oneskorenej alokacie) */
    struct stat st;
    if (!failed && fstat(fd, &st) == 0) j->snap.bytes_on_disk = (uint64_t)st.st_blocks * 512u;
    if (close(fd) != 0 && !failed) { failed = "close"; err = errno; }
    if (failed) {
        LOGE("zapis: %s '%s' zlyhal: %s", failed, j->snap.path, strerror(err));
        unlink(j->staging);
        return VMIC_ERR;
    }
    double t1 = vmic_now_mono();
    j->snap.write_ms       = (t1 - t0 - sha_s) * 1000.0;
    j->snap.sha_ms         = sha_s * 1000.0;
    /* Iba po zavretie dat: sidecar nemoze obsahovat cas vlastneho
       premenovania. Cele zverejnenie je v suhrne zapisovaca. */
    j->snap.data_closed_ms = (t1 - j->t_start) * 1000.0;
    if (hashing) {
        vmic_sha256_final(&sha, j->snap.sha256);
        j->snap.has_hash = true;
        /* hash sa pocital az po cykle vo vlakne a sidecar vznikne az s nim */
        j->snap.hash_deferred = true;
    }
    return VMIC_OK;
}

/* Sidecar do .<id>.json.tmp (O_EXCL). */
static int write_sidecar_tmp(vmic_output_t *o, vmic_job_t *j)
{
    char hex[VMIC_SHA256_BYTES * 2 + 1] = "";
    if (j->snap.has_hash) vmic_hex(j->snap.sha256, VMIC_SHA256_BYTES, hex);
    char *buf = NULL;
    size_t len = 0;
    if (set_op(o, OP_SIDECAR, j->snap.seq)) return VMIC_STOP;
    if (vmic_meta_render(&j->snap, hex, &buf, &len, j->snap.sidecar_path,
                         sizeof(j->snap.sidecar_path)) != VMIC_OK) {
        LOGE("sidecar: vykreslenie '%s' zlyhalo", j->snap.id);
        return VMIC_ERR;
    }
    int rc = VMIC_ERR;
    int fd = open(j->sidecar_tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOGE("sidecar: nedaji sa vytvorit '%s': %s", j->sidecar_tmp, strerror(errno));
    } else {
        int bad = vmic_write_all(fd, buf, len) != 0;
        int err = errno;
        if (close(fd) != 0 && !bad) { bad = 1; err = errno; }
        if (bad) {
            LOGE("sidecar: zapis '%s' zlyhal: %s", j->sidecar_tmp, strerror(err));
            unlink(j->sidecar_tmp);
        } else {
            rc = VMIC_OK;
        }
    }
    free(buf);
    return rc;
}

static int rename_noreplace(const char *from, const char *to)
{
    return renameat2(AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE);
}

static void process(vmic_output_t *o, vmic_job_t *j)
{
    const vmic_config_t *cfg = o->cfg;
    int rc = write_data(o, j, cfg->hash == VMIC_HASH_SHA256);
    if (rc == VMIC_STOP) { gave_up(o); return; }
    if (rc != VMIC_OK) {
        fail(o, j, true);
        return;
    }
    rc = cfg->sidecar ? write_sidecar_tmp(o, j) : VMIC_OK;
    if (rc != VMIC_OK) {
        unlink(j->staging);
        if (rc == VMIC_STOP) gave_up(o); else fail(o, j, true);
        return;
    }
    /* Zverejnenie: obe premenovania hned po sebe, najprv data. Po vyprsanom
       drain sa uz nezverejnuje a docasne subory si zapisovac zmaze sam. */
    if (set_op(o, OP_RENAME, j->snap.seq)) {
        unlink(j->staging);
        if (cfg->sidecar) unlink(j->sidecar_tmp);
        gave_up(o);
        return;
    }
    if (rename_noreplace(j->staging, j->snap.path) != 0) {
        LOGE("zapis: rename '%s' zlyhal: %s", j->snap.path, strerror(errno));
        unlink(j->staging);
        if (cfg->sidecar) unlink(j->sidecar_tmp);
        fail(o, j, true);
        return;
    }
    if (cfg->sidecar && rename_noreplace(j->sidecar_tmp, j->snap.sidecar_path) != 0) {
        LOGE("sidecar: rename '%s' zlyhal: %s - snimka sa nezverejni",
             j->snap.sidecar_path, strerror(errno));
        unlink(j->sidecar_tmp);
        unlink(j->snap.path);         /* .vmicd nikdy nezostane bez sidecaru */
        fail(o, j, true);
        return;
    }
    double published_ms = (vmic_now_mono() - j->t_start) * 1000.0;
    pthread_mutex_lock(&o->mu);
    o->st.published++;
    o->st.published_bytes += j->snap.bytes_on_disk;
    if (published_ms > o->st.max_publish_ms) o->st.max_publish_ms = published_ms;
    bool skip = o->fatal || o->abandon;
    pthread_mutex_unlock(&o->mu);

    /* Hooky a retencia az po zverejneni: vidia hotovy subor aj sidecar.
       Po zlyhani hooku v striktnom rezime sa hooky uz nevolaju, snimky sa
       zverejnuju dalej a zberac skonci s kodom 3. Po vyprsanom drain uz nie. */
    if (skip) return;
    set_op(o, OP_HOOK, j->snap.seq);
    if (vmic_hooks_fire(o->hooks, &j->snap) != VMIC_OK) {
        pthread_mutex_lock(&o->mu);
        o->fatal = true;
        pthread_mutex_unlock(&o->mu);
    }
    if (set_op(o, OP_RETENTION, j->snap.seq)) return;
    vmic_retention_apply(cfg, j->snap.chain_id);
}

static void *writer_main(void *arg)
{
    vmic_output_t *o = arg;
    /* Nizsia priorita: SHA-256 plnej snimky trva sekundy a nesmie brat jadro
       vzorkovacu. Nice plati v Linuxe pre jednotlive vlakna. */
    setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), 5);

    pthread_mutex_lock(&o->mu);
    for (;;) {
        while (!o->head && !o->stopping)
            pthread_cond_wait(&o->cv_work, &o->mu);
        if (!o->head) break;
        vmic_job_t *j = o->head;
        o->head = j->next;
        if (!o->head) o->tail = NULL;
        o->queued_bytes -= j->bytes;
        o->queued_jobs--;
        o->inflight_bytes = j->bytes;
        o->busy = true;
        uint64_t broken = o->broken_chain;
        bool abandon = o->abandon;
        pthread_mutex_unlock(&o->mu);

        if (abandon) {
            /* uz zapocitane v st.abandoned (drain vyprsal) */
        } else if (broken && j->snap.chain_id == broken) {
            LOGE("zapis: snimka seq=%" PRIu64 " sa nezverejni - retazec %" PRIu64
                 " prerusila chyba zapisu", j->snap.seq, broken);
            pthread_mutex_lock(&o->mu);
            o->st.dropped++;
            pthread_mutex_unlock(&o->mu);
        } else {
            process(o, j);
        }

        set_op(o, OP_NONE, 0);               /* zapise trvanie poslednej operacie */
        pthread_mutex_lock(&o->mu);
        job_release_locked(o, j);
        o->inflight_bytes = 0;
        o->busy = false;
        if (!o->head) pthread_cond_broadcast(&o->cv_idle);
    }
    pthread_mutex_unlock(&o->mu);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Zivotny cyklus                                                      */
/* ------------------------------------------------------------------ */

static void free_parts(vmic_output_t *o)
{
    free(o->free_chunks);
    free(o->jobs);
    free(o->bins_store);
    if (o->pool && o->pool != MAP_FAILED) munmap(o->pool, o->pool_bytes);
    free(o);
}

int vmic_output_create(vmic_output_t **out, const vmic_config_t *cfg, vmic_hooks_t *hooks,
                       uint64_t pool_bytes, size_t max_bins, volatile sig_atomic_t *stop)
{
    *out = NULL;
    if (pool_bytes < 2ull * CHUNK) pool_bytes = 2ull * CHUNK;
    pool_bytes = ((pool_bytes + CHUNK - 1) / CHUNK) * CHUNK;

    size_t njobs = jobs_for(max_bins);
    if (njobs < JOBS_MIN) {
        LOGE("zapis: per-bin vektor ma az %zu binov - kopie pre %u snimok vo fronte by "
             "potrebovali viac nez %llu MiB (zvacsi features.bin_bytes)", max_bins, JOBS_MIN,
             (unsigned long long)(BINS_STORE_MAX >> 20));
        return VMIC_FATAL;
    }

    vmic_output_t *o = calloc(1, sizeof(*o));
    if (!o) { LOGE("zapis: nedostatok pamate"); return VMIC_FATAL; }
    o->cfg = cfg;
    o->hooks = hooks;
    o->stop = stop;
    o->pool_bytes = (size_t)pool_bytes;
    o->max_bins = max_bins;
    o->njobs = njobs;
    o->st.pool_bytes = pool_bytes;
    o->op = OP_NONE;
    /* Nedotknute kusy nestoja RAM; s output.mlock ich zberac uzamkne
       a namapuje este pred prvym cyklom (collector.c). Deti procesu (fork
       v hooku) pool nededia. */
    o->pool = mmap(NULL, o->pool_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (o->pool == MAP_FAILED) {
        LOGE("zapis: nedaji sa vyhradit %" PRIu64 " MiB pre frontu snimok: %s",
             pool_bytes >> 20, strerror(errno));
        free_parts(o);
        return VMIC_FATAL;
    }
    madvise(o->pool, o->pool_bytes, MADV_DONTFORK);
    size_t chunks = o->pool_bytes / CHUNK;
    o->free_chunks = malloc(chunks * sizeof(*o->free_chunks));
    o->jobs = calloc(njobs, sizeof(*o->jobs));
    o->bins_store = max_bins ? calloc(njobs * max_bins, sizeof(*o->bins_store)) : NULL;
    if (!o->free_chunks || !o->jobs || (max_bins && !o->bins_store)) {
        LOGE("zapis: nedostatok pamate na deskriptory fronty (%zu snimok, %zu binov)",
             njobs, max_bins);
        free_parts(o);
        return VMIC_FATAL;
    }
    /* odzadu, aby sa ako prve brali kusy zo zaciatku oblasti */
    for (size_t i = 0; i < chunks; i++)
        o->free_chunks[o->free_count++] = o->pool + (chunks - 1 - i) * (size_t)CHUNK;
    for (size_t i = njobs; i-- > 0; ) {
        o->jobs[i].bins = max_bins ? o->bins_store + i * max_bins : NULL;
        o->jobs[i].next = o->free_jobs;
        o->free_jobs = &o->jobs[i];
    }

    pthread_mutex_init(&o->mu, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&o->cv_work, &ca);
    pthread_cond_init(&o->cv_space, &ca);
    pthread_cond_init(&o->cv_idle, &ca);
    pthread_condattr_destroy(&ca);

    /* Signaly patria vzorkovaciemu vlaknu (jeho clock_nanosleep). */
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 2u << 20);   /* hooky dostanu dost zasobnika */
    pthread_sigmask(SIG_BLOCK, &block, &old);
    int rc = pthread_create(&o->thread, &attr, writer_main, o);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        LOGE("zapis: vlakno sa nepodarilo spustit: %s", strerror(rc));
        pthread_cond_destroy(&o->cv_idle);
        pthread_cond_destroy(&o->cv_space);
        pthread_cond_destroy(&o->cv_work);
        pthread_mutex_destroy(&o->mu);
        free_parts(o);
        return VMIC_FATAL;
    }
    pthread_setname_np(o->thread, "vmic-writer");
    *out = o;
    return VMIC_OK;
}

uint64_t vmic_output_drain(vmic_output_t *o, double budget_s, bool *abandoned)
{
    if (abandoned) *abandoned = false;
    if (!o) return 0;
    double t0 = vmic_now_mono(), last_report = t0;
    double deadline = budget_s > 0.0 ? t0 + budget_s : 0.0;
    bool stop_seen = o->stop && *o->stop;
    pthread_mutex_lock(&o->mu);
    while (o->head || o->busy) {
        double now = vmic_now_mono();
        /* Signal pocas dobehnutia skrati zvysok na STOP_BUDGET_S od neho:
           volajuci po SIGTERM posiela SIGKILL o 60 s. */
        if (!stop_seen && o->stop && *o->stop) {
            stop_seen = true;
            if (!deadline || deadline > now + STOP_BUDGET_S) deadline = now + STOP_BUDGET_S;
        }
        if (deadline && now >= deadline) {
            /* Zvysok fronty sa zahodi a zapocita ako chyba. Snimku v zapise
               vzdá zapisovac sam pri najblizsej kontrole (a zapocita ju);
               kratka lehota mu na to stacia, ak nestoji v jedinom syscalle. */
            o->abandon = true;
            o->st.abandoned += o->queued_jobs;
            uint64_t seq = o->op_seq;
            const char *op = o->op != OP_NONE ? OP_NAMES[o->op] : "?";
            struct timespec until = deadline_in(ABANDON_GRACE_S);
            while (o->busy && pthread_cond_timedwait(&o->cv_idle, &o->mu, &until) == 0)
                ;
            bool stuck = o->busy;
            if (stuck) o->st.abandoned++;      /* nedokonci sa pred koncom procesu */
            uint64_t lost = o->st.failed + o->st.dropped + o->st.abandoned;
            uint64_t gone = o->st.abandoned;
            pthread_mutex_unlock(&o->mu);
            LOGE("zapis: dobehnutie fronty prekrocilo %.0f s - %" PRIu64 " snimok sa "
                 "nezverejni (zapisovac: '%s' snimky seq=%" PRIu64 "%s)",
                 now - t0, gone, op, seq, stuck ? ", stale v nej" : "");
            if (abandoned) *abandoned = stuck;
            return lost;
        }
        if (now - last_report >= 10.0) {
            char human[32];
            vmic_human_size(o->queued_bytes + o->inflight_bytes, human, sizeof(human));
            LOGW("zapis: dobieham frontu %.0f s - %" PRIu64 " snimok (%s), zapisovac: '%s'",
                 now - t0, o->queued_jobs + (o->busy ? 1 : 0), human,
                 o->op != OP_NONE ? OP_NAMES[o->op] : "?");
            last_report = now;
        }
        struct timespec until = deadline_in(0.5);
        pthread_cond_timedwait(&o->cv_idle, &o->mu, &until);
    }
    uint64_t lost = o->st.failed + o->st.dropped + o->st.abandoned;
    pthread_mutex_unlock(&o->mu);
    return lost;
}

void vmic_output_get_stats(vmic_output_t *o, vmic_output_stats_t *st)
{
    memset(st, 0, sizeof(*st));
    if (!o) return;
    pthread_mutex_lock(&o->mu);
    *st = o->st;
    pthread_mutex_unlock(&o->mu);
}

void vmic_output_destroy(vmic_output_t *o)
{
    if (!o) return;
    pthread_mutex_lock(&o->mu);
    bool stuck = o->abandon && (o->busy || o->head);
    pthread_mutex_unlock(&o->mu);
    if (stuck) {
        /* zapisovac moze stat v nedokoncenom syscalle - proces aj tak konci */
        return;
    }
    vmic_output_drain(o, 0.0, NULL);
    pthread_mutex_lock(&o->mu);
    o->stopping = true;
    pthread_cond_signal(&o->cv_work);
    pthread_mutex_unlock(&o->mu);
    pthread_join(o->thread, NULL);
    pthread_cond_destroy(&o->cv_idle);
    pthread_cond_destroy(&o->cv_space);
    pthread_cond_destroy(&o->cv_work);
    pthread_mutex_destroy(&o->mu);
    free_parts(o);
}
