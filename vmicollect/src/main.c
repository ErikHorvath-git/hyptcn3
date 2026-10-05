/*
 * main.c - prikazovy riadok zberaca.
 *
 *   vmicollect run       periodicky zber (hlavny rezim)
 *   vmicollect once      jedna snimka a koniec
 *   vmicollect probe     iba sa pripoj a vypis co vidis (nic nezapisuje)
 *   vmicollect restore   poskladaj plny obraz z delta retazca
 *   vmicollect verify    prekontroluj kontrolne sucty snimok
 *   vmicollect config    vypis efektivnu konfiguraciu
 *   vmicollect backends  zoznam backendov
 *   vmicollect selftest  overenie celej cesty bez potreby VM
 *
 * Kazdy prikaz berie -c <subor> a lubovolny pocet -o sekcia.kluc=hodnota.
 * Prave to -o je najrychlejsi sposob ako sa s modulom pohrat:
 *
 *   vmicollect run -c my.conf -o schedule.interval_s=1 -o output.writer=delta
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "sha256.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

/* ------------------------------------------------------------------ */
/* Signaly                                                             */
/* ------------------------------------------------------------------ */

/*
 * Obsluha signalu smie robit len jedinu vec: nastavit priznak. Vsetko
 * ostatne (logovanie, malloc, zatvaranie suborov) nie je async-signal-safe
 * a v obsluhe by to bolo chybou. Samotne ukoncenie riesi hlavna slucka -
 * a to je aj dovod, preco NEDAVAME SA_RESTART: chceme, aby signal
 * prerusil clock_nanosleep() a Ctrl-C zabralo okamzite.
 */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                 /* zamerne BEZ SA_RESTART */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    /* zapis do zavretej rury nesmie zabit zberac */
    signal(SIGPIPE, SIG_IGN);
}

/* ------------------------------------------------------------------ */
/* Napoveda                                                            */
/* ------------------------------------------------------------------ */

static void usage(FILE *f)
{
    fprintf(f,
"vmicollect %s - periodicky zber pamatovych snimok virtualnych strojov\n"
"\n"
"POUZITIE\n"
"  vmicollect <prikaz> [-c subor.conf] [-o sekcia.kluc=hodnota]...\n"
"\n"
"PRIKAZY\n"
"  run                periodicky zber (Ctrl-C korektne ukonci)\n"
"  once               jedna snimka a koniec\n"
"  probe              pripoj sa a vypis parametre VM (nic nezapisuje)\n"
"  restore            poskladaj plny obraz z delta retazca\n"
"                       --dir D --out F [--chain ID] [--until SEQ]\n"
"  hold <dir> <id>... oznac retazce markerom HOLD (retencia ich nezmaže)\n"
"                       <id> = chain_id (delta zber) alebo meno suboru\n"
"  verify [adresar]   over kontrolne sucty snimok podla .json\n"
"  config             vypis efektivnu konfiguraciu\n"
"  config --keys      vypis vsetky nastavitelne parametre\n"
"  backends           zoznam dostupnych backendov\n"
"  selftest [adresar] over celu cestu bez potreby VM\n"
"\n"
"PREPINACE\n"
"  -c, --config F     konfiguracny subor (INI)\n"
"  -o, --set K=V      prebi jeden parameter (da sa opakovat)\n"
"  -v, --verbose      log na urovni DEBUG\n"
"  -q, --quiet        log iba ERROR\n"
"  -V, --version      vypis verziu\n"
"  -h, --help         tato napoveda\n"
"\n"
"PRIKLADY\n"
"  # rychly test bez VM\n"
"  vmicollect selftest /tmp/vmic\n"
"\n"
"  # co vlastne vidime na domene 'win10' (ostry zber vzdy pod rootom)\n"
"  sudo vmicollect probe -o vm.domain=win10\n"
"\n"
"  # kazde 2 s inkrementalne, 100 snimok, do /var/tmp/snap\n"
"  sudo vmicollect run -o vm.domain=win10 -o schedule.interval_s=2 \\\n"
"                 -o output.writer=delta -o schedule.max_cycles=100 \\\n"
"                 -o output.dir=/var/tmp/snap\n"
"\n"
"  # obnova plneho obrazu z posledneho retazca\n"
"  vmicollect restore --dir /var/tmp/snap --out /var/tmp/mem.raw\n"
"\n", VMIC_VERSION);
}

/* ------------------------------------------------------------------ */
/* Spolocne spracovanie prepinacov                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *config_file;
    const char *sets[64];
    size_t      set_count;
    int         verbose;   /* +1 / -1 */
    const char *positional[8];
    size_t      pos_count;
    /* restore */
    const char *dir;
    const char *out;
    uint64_t    chain;
    uint64_t    until;
    bool        keys;
} args_t;

static int parse_args(int argc, char **argv, args_t *a)
{
    memset(a, 0, sizeof(*a));

    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];

        if (!strcmp(s, "-c") || !strcmp(s, "--config")) {
            if (++i >= argc) { fprintf(stderr, "chyba: -c ocakava subor\n"); return -1; }
            a->config_file = argv[i];
        } else if (!strcmp(s, "-o") || !strcmp(s, "--set")) {
            if (++i >= argc) { fprintf(stderr, "chyba: -o ocakava kluc=hodnota\n"); return -1; }
            if (a->set_count >= 64) { fprintf(stderr, "chyba: prilis vela -o\n"); return -1; }
            a->sets[a->set_count++] = argv[i];
        } else if (!strcmp(s, "-v") || !strcmp(s, "--verbose")) {
            a->verbose = 1;
        } else if (!strcmp(s, "-q") || !strcmp(s, "--quiet")) {
            a->verbose = -1;
        } else if (!strcmp(s, "--keys")) {
            a->keys = true;
        } else if (!strcmp(s, "--dir")) {
            if (++i >= argc) return -1;
            a->dir = argv[i];
        } else if (!strcmp(s, "--out")) {
            if (++i >= argc) return -1;
            a->out = argv[i];
        } else if (!strcmp(s, "--chain")) {
            if (++i >= argc) return -1;
            a->chain = strtoull(argv[i], NULL, 0);
        } else if (!strcmp(s, "--until")) {
            if (++i >= argc) return -1;
            a->until = strtoull(argv[i], NULL, 0);
        } else if (s[0] == '-' && s[1]) {
            fprintf(stderr, "chyba: neznamy prepinac '%s'\n", s);
            return -1;
        } else {
            if (a->pos_count < 8) a->positional[a->pos_count++] = s;
        }
    }
    return 0;
}

/* Nacita config, aplikuje -o, otvori log, zvaliduje. */
static int build_config(const args_t *a, vmic_config_t *cfg, bool need_target)
{
    vmic_config_defaults(cfg);

    /* Log otvarame docasne uz teraz, aby bolo vidiet chyby v configu. */
    vmic_log_open(a->verbose > 0 ? VMIC_LOG_DEBUG : VMIC_LOG_INFO, NULL, false);

    if (a->config_file && vmic_config_load(cfg, a->config_file) != 0)
        return -1;

    for (size_t i = 0; i < a->set_count; i++)
        if (vmic_config_set(cfg, a->sets[i]) != 0)
            return -1;

    if (a->verbose > 0)      cfg->log_level = VMIC_LOG_DEBUG;
    else if (a->verbose < 0) cfg->log_level = VMIC_LOG_ERROR;

    /* teraz uz s finalnym nastavenim */
    vmic_log_open(cfg->log_level, cfg->log_file, cfg->log_json);

    return vmic_config_validate(cfg, need_target) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* run / once                                                          */
/* ------------------------------------------------------------------ */

static int cycle_adapter(uint64_t seq, double deadline,
                         const vmic_sched_ctx_t *ctx, void *user)
{
    (void)seq; (void)deadline;
    vmic_collector_t *c = (vmic_collector_t *)user;
    c->sched_lateness_s   = ctx->lateness_s;
    c->sched_skipped_before = ctx->skipped_before;
    return vmic_collector_cycle(c, NULL);
}

static int cmd_run(const args_t *a, bool once)
{
    vmic_config_t cfg;
    if (build_config(a, &cfg, true) != 0) return 2;

    if (once) {
        cfg.max_cycles = 1;
        cfg.duration_s = 0;
    }

    vmic_collector_t col;
    int rc = vmic_collector_init(&col, &cfg, &g_stop);
    if (rc != VMIC_OK) return 3;

    LOGI("zacinam zber: perioda %.3f s, writer '%s', vystup '%s'",
         cfg.interval_s, cfg.writer, cfg.dir);

    vmic_sched_stats_t st;
    rc = vmic_sched_run(&cfg, cycle_adapter, &col, &g_stop, &st);

    char human[32];
    vmic_human_size(col.total_bytes, human, sizeof(human));
    LOGI("koniec: %" PRIu64 " snimok, %" PRIu64 " chyb, %" PRIu64
         " zmeskanych slotov, najvacsie meskanie %.3f s, spolu %s",
         st.cycles_done, st.cycles_failed, st.cycles_skipped,
         st.worst_lateness_s, human);

    vmic_collector_fini(&col);
    vmic_log_close();

    if (rc == VMIC_FATAL) return 3;
    return st.cycles_done ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* probe                                                               */
/* ------------------------------------------------------------------ */

static int cmd_probe(const args_t *a)
{
    vmic_config_t cfg;
    if (build_config(a, &cfg, true) != 0) return 2;

    vmic_backend_t b;
    if (vmic_backend_create(&b, &cfg) != VMIC_OK) return 3;
    if (b.ops->open(&b) != VMIC_OK) { vmic_backend_destroy(&b); return 3; }

    vmic_vminfo_t vi;
    if (b.ops->probe(&b, &vi) != VMIC_OK) {
        vmic_backend_destroy(&b);
        return 3;
    }

    char human[32] = "?", maxp[32] = "?";
    if (vi.has_memsize)   vmic_human_size(vi.memsize, human, sizeof(human));
    if (vi.has_max_paddr) vmic_human_size(vi.max_paddr, maxp, sizeof(maxp));

    printf("domena           : %s\n", vi.domain);
    printf("backend          : %s\n", vi.backend);
    if (vi.has_vmid)      printf("id domeny        : %" PRIu64 "\n", vi.vmid);
    printf("velkost RAM      : %s\n", human);
    printf("max. fyz. adresa : %s (0x%" PRIx64 ")\n", maxp, vi.max_paddr);
    if (vi.has_vcpus)     printf("pocet vCPU       : %u\n", vi.num_vcpus);
    if (vi.address_width) printf("sirka adresy     : %u B\n", vi.address_width);
    else                  printf("sirka adresy     : n/a\n");
    printf("strankovanie     : %s\n", vi.page_mode);
    printf("nahodny pristup  : %s\n", b.ops->random_access ? "ano" : "nie (iba cely obraz)");
    printf("pripona vystupu  : %s\n", vmic_backend_ext(&b));

    /* male meranie priepustnosti - 16 MiB je dost na odhad a dost malo
       na to, aby VM nezavahala */
    if (b.ops->random_access && vmic_vminfo_addressable(&vi)) {
        size_t probe_len = 16u << 20;
        uint64_t limit = vmic_vminfo_addressable(&vi);
        if ((uint64_t)probe_len > limit) probe_len = (size_t)limit;

        uint8_t *buf = malloc(probe_len);
        if (buf) {
            double t0 = vmic_now_mono();
            int64_t got = b.ops->read_pa(&b, 0, buf, probe_len);
            double dt = vmic_now_mono() - t0;
            free(buf);
            if (got > 0 && dt > 0.0)
                printf("test citania     : %" PRId64 " B za %.1f ms = %.0f MiB/s\n",
                       got, dt * 1000.0,
                       ((double)got / (1024.0 * 1024.0)) / dt);
        }
    }

    vmic_backend_destroy(&b);
    vmic_log_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* verify                                                              */
/* ------------------------------------------------------------------ */

/* velmi jednoduchy vytahovac hodnoty z nasho vlastneho JSON */
static bool json_field(const char *text, const char *key, char *out, size_t n)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(text, pattern);
    if (!p) return false;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        const char *e = strchr(p, '"');
        if (!e) return false;
        size_t len = (size_t)(e - p);
        if (len >= n) len = n - 1;
        memcpy(out, p, len);
        out[len] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '\n' && *p != '}' && i + 1 < n)
            out[i++] = *p++;
        out[i] = '\0';
    }
    return true;
}

static int hash_file(const char *path, uint8_t out[VMIC_SHA256_BYTES])
{
    bool gz = strlen(path) > 3 && !strcmp(path + strlen(path) - 3, ".gz");
    uint8_t *buf = malloc(1u << 20);
    if (!buf) return -1;

    vmic_sha256_t c;
    vmic_sha256_init(&c);
    int rc = 0;

    if (gz) {
        gzFile f = gzopen(path, "rb");
        if (!f) { free(buf); return -1; }
        for (;;) {
            int n = gzread(f, buf, 1u << 20);
            if (n < 0) { rc = -1; break; }
            if (n == 0) break;
            vmic_sha256_update(&c, buf, (size_t)n);
        }
        gzclose(f);
    } else {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { free(buf); return -1; }
        for (;;) {
            ssize_t n = vmic_read_full(fd, buf, 1u << 20);
            if (n < 0) { rc = -1; break; }
            if (n == 0) break;
            vmic_sha256_update(&c, buf, (size_t)n);
            if ((size_t)n < (1u << 20)) break;
        }
        close(fd);
    }
    free(buf);
    if (rc == 0) vmic_sha256_final(&c, out);
    return rc;
}

static int cmd_verify(const args_t *a)
{
    vmic_config_t cfg;
    if (build_config(a, &cfg, false) != 0) return 2;

    const char *dir = a->pos_count ? a->positional[0] : cfg.dir;
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "verify: nedaji sa otvorit '%s': %s\n",
                dir, strerror(errno));
        return 3;
    }

    int ok = 0, bad = 0, skipped = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 6 || strcmp(e->d_name + len - 5, ".json") != 0) continue;

        char meta[VMIC_PATH_MAX];
        if (vmic_join(meta, sizeof(meta), dir, e->d_name) != 0) continue;

        FILE *f = fopen(meta, "re");
        if (!f) continue;
        char text[8192];
        size_t n = fread(text, 1, sizeof(text) - 1, f);
        fclose(f);
        text[n] = '\0';

        char path[VMIC_PATH_MAX], want[128], covers[16], writer[32];
        if (!json_field(text, "path", path, sizeof(path)) ||
            !json_field(text, "sha256", want, sizeof(want)) || !want[0]) {
            skipped++;
            continue;
        }
        json_field(text, "sha256_covers_file", covers, sizeof(covers));
        json_field(text, "writer", writer, sizeof(writer));

        (void)writer;
        if (strcmp(covers, "true") != 0) {
            printf("PRESKOCENE %s (hash nepokryva subor)\n", path);
            skipped++;
            continue;
        }

        uint8_t got[VMIC_SHA256_BYTES];
        if (hash_file(path, got) != 0) {
            printf("CHYBA      %s (nedaji sa precitat)\n", path);
            bad++;
            continue;
        }
        char hex[VMIC_SHA256_BYTES * 2 + 1];
        vmic_hex(got, VMIC_SHA256_BYTES, hex);

        if (strcmp(hex, want) == 0) { printf("OK         %s\n", path); ok++; }
        else                        { printf("NESEDI     %s\n", path); bad++; }
    }
    closedir(d);

    printf("\nspolu: %d v poriadku, %d chybnych, %d preskocenych\n",
           ok, bad, skipped);
    vmic_log_close();
    return bad ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* selftest                                                            */
/* ------------------------------------------------------------------ */

/*
 * Overi celu cestu (backend -> capture -> writer -> restore) bez toho,
 * aby si potreboval VM, roota alebo patchnuty QEMU. Vytvori synteticky
 * obraz pamate, medzi cyklami do neho zapise zmeny a na konci porovna
 * obnoveny obraz s originalom.
 */
static void fill_pattern(uint8_t *buf, size_t len, uint64_t seed)
{
    uint64_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i + 8 <= len; i += 8) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;   /* xorshift64 */
        memcpy(buf + i, &x, 8);
    }
}

static int cmd_selftest(const args_t *a)
{
    char dir[VMIC_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s",
             a->pos_count ? a->positional[0] : "/tmp/vmicollect-selftest");

    vmic_log_open(a->verbose > 0 ? VMIC_LOG_DEBUG : VMIC_LOG_INFO, NULL, false);
    LOGI("selftest: pracovny adresar %s", dir);

    if (vmic_mkdir_p(dir) != 0) {
        LOGE("selftest: nedaji sa vytvorit '%s': %s", dir, strerror(errno));
        return 3;
    }

    /* --- 1. synteticky obraz pamate --------------------------------- */
    const size_t IMG = 16u << 20;          /* 16 MiB staci */
    const size_t PS  = 4096;
    char image[VMIC_PATH_MAX], snapdir[VMIC_PATH_MAX], restored[VMIC_PATH_MAX];
    vmic_join(image,    sizeof(image),    dir, "memory.img");
    vmic_join(snapdir,  sizeof(snapdir),  dir, "snapshots");
    vmic_join(restored, sizeof(restored), dir, "restored.raw");

    uint8_t *mem = calloc(1, IMG);
    if (!mem) return 3;
    /* prvu polovicu naplnime datami, druhu nechame nulovu - nech je
       vidiet aj riedky zapis */
    fill_pattern(mem, IMG / 2, 0xC0FFEE);

    int fd = open(image, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0 || vmic_write_all(fd, mem, IMG) != 0) {
        LOGE("selftest: nedaji sa zapisat '%s': %s", image, strerror(errno));
        if (fd >= 0) close(fd);
        free(mem);
        return 3;
    }
    close(fd);
    LOGI("selftest: vytvoreny obraz %s (16 MiB, druha polovica nulova)", image);

    /* --- 2. zber s delta writerom ----------------------------------- */
    vmic_config_t cfg;
    vmic_config_defaults(&cfg);
    snprintf(cfg.backend, sizeof(cfg.backend), "file");
    snprintf(cfg.image_path, sizeof(cfg.image_path), "%s", image);
    snprintf(cfg.domain, sizeof(cfg.domain), "selftest");
    snprintf(cfg.dir, sizeof(cfg.dir), "%s", snapdir);
    snprintf(cfg.writer, sizeof(cfg.writer), "delta");
    cfg.delta_page_size  = (uint32_t)PS;
    cfg.delta_full_every = 100;            /* iba prva snimka bude plna */
    cfg.log_level        = cfg.log_level;
    if (vmic_config_validate(&cfg, true) != 0) { free(mem); return 3; }

    vmic_collector_t col;
    if (vmic_collector_init(&col, &cfg, &g_stop) != VMIC_OK) {
        free(mem);
        return 3;
    }

    const int CYCLES = 4;
    uint64_t expected_changed[CYCLES];

    for (int i = 0; i < CYCLES; i++) {
        if (i > 0) {
            /* zmenime presne 3 stranky - delta ich musi najst */
            int fdw = open(image, O_WRONLY | O_CLOEXEC);
            if (fdw < 0) { LOGE("selftest: open na zapis zlyhal"); break; }
            for (int k = 0; k < 3; k++) {
                size_t page = (size_t)(i * 37 + k * 11) % (IMG / PS);
                uint8_t tmp[4096];
                fill_pattern(tmp, PS, (uint64_t)(i * 1000 + k + 1));
                vmic_pwrite_all(fdw, tmp, PS, (off_t)(page * PS));
                memcpy(mem + page * PS, tmp, PS);
            }
            close(fdw);
            expected_changed[i] = 3;
        } else {
            expected_changed[i] = 0;    /* prva snimka je plna - nekontrolujeme */
        }

        vmic_snapshot_t snap;
        if (vmic_collector_cycle(&col, &snap) != VMIC_OK) {
            LOGE("selftest: cyklus %d zlyhal", i);
            vmic_collector_fini(&col);
            free(mem);
            return 3;
        }
        if (i > 0 && snap.pages_changed != expected_changed[i]) {
            LOGE("selftest: cyklus %d nasiel %" PRIu64 " zmenenych stranok, "
                 "ocakaval som %" PRIu64,
                 i, snap.pages_changed, expected_changed[i]);
            vmic_collector_fini(&col);
            free(mem);
            return 1;
        }
    }
    vmic_collector_fini(&col);

    /* --- 3. obnova a porovnanie ------------------------------------- */
    if (vmic_delta_restore(snapdir, restored, 0, 0) != VMIC_OK) {
        free(mem);
        return 1;
    }

    int rfd = open(restored, O_RDONLY | O_CLOEXEC);
    if (rfd < 0) { LOGE("selftest: obnoveny subor sa neda otvorit"); free(mem); return 1; }
    uint8_t *back = malloc(IMG);
    if (!back) { close(rfd); free(mem); return 3; }
    ssize_t got = vmic_read_full(rfd, back, IMG);
    close(rfd);

    int rc = 0;
    if (got != (ssize_t)IMG) {
        LOGE("selftest: obnoveny obraz ma %zd B, ocakaval som %zu B", got, IMG);
        rc = 1;
    } else if (memcmp(back, mem, IMG) != 0) {
        size_t first = 0;
        while (first < IMG && back[first] == mem[first]) first++;
        LOGE("selftest: obnoveny obraz sa lisi od originalu na offsete 0x%zx "
             "(stranka %zu)", first, first / PS);
        rc = 1;
    } else {
        LOGI("selftest: OK - obnoveny obraz je bajt po bajte zhodny");
    }

    /* --- 4. este raw writer + kontrolny sucet ----------------------- */
    if (rc == 0) {
        snprintf(cfg.writer, sizeof(cfg.writer), "raw");
        cfg.sparse = true;
        if (vmic_collector_init(&col, &cfg, &g_stop) == VMIC_OK) {
            vmic_snapshot_t snap;
            if (vmic_collector_cycle(&col, &snap) == VMIC_OK) {
                uint8_t want[VMIC_SHA256_BYTES];
                vmic_sha256_t c;
                vmic_sha256_init(&c);
                vmic_sha256_update(&c, mem, IMG);
                vmic_sha256_final(&c, want);
                if (!snap.has_hash || memcmp(want, snap.sha256, sizeof(want)) != 0) {
                    LOGE("selftest: raw snimka ma iny kontrolny sucet");
                    rc = 1;
                } else {
                    LOGI("selftest: OK - raw snimka ma spravny SHA-256");
                }
            } else {
                LOGE("selftest: raw cyklus zlyhal");
                rc = 1;
            }
            vmic_collector_fini(&col);
        }
    }

    free(back);
    free(mem);

    if (rc == 0)
        LOGI("selftest: VSETKO PRESLO. Data su v %s", dir);
    vmic_log_close();
    return rc;
}

/* ------------------------------------------------------------------ */
/* hold: dopis markeru HOLD do vystupneho adresara                     */
/* ------------------------------------------------------------------ */

static int cmd_hold(const args_t *a)
{
    if (a->pos_count < 2) {
        fprintf(stderr, "hold: ocakavam <adresar> a aspon jeden "
                        "<chain_id|subor>\n");
        return 2;
    }
    const char *dir = a->positional[0];
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), dir, VMIC_HOLD_MARKER) != 0) {
        fprintf(stderr, "hold: cesta je prilis dlha\n");
        return 2;
    }
    FILE *f = fopen(path, "a");
    if (!f) {
        fprintf(stderr, "hold: %s: %s\n", path, strerror(errno));
        return 1;
    }
    size_t written = 0;
    for (size_t i = 1; i < a->pos_count; i++) {
        const char *e = a->positional[i];
        if (!e[0] || strchr(e, '\n') || strchr(e, '\r')) {
            fprintf(stderr, "hold: zaznam '%s' nie je platny riadok\n", e);
            fclose(f);
            return 2;
        }
        if (fprintf(f, "%s\n", e) < 0) {
            fprintf(stderr, "hold: zapis do %s zlyhal: %s\n", path,
                    strerror(errno));
            fclose(f);
            return 1;
        }
        written++;
    }
    fclose(f);
    printf("hold: %zu zaznamov dopisanych do %s\n", written, path);
    return 0;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) { usage(stderr); return 2; }

    const char *cmd = argv[1];
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
        usage(stdout);
        return 0;
    }
    if (!strcmp(cmd, "-V") || !strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
        printf("vmicollect %s\n", VMIC_VERSION);
        return 0;
    }

    args_t a;
    if (parse_args(argc, argv, &a) != 0) return 2;

    install_signals();
    vmic_random_seed();

    if (!strcmp(cmd, "run"))      return cmd_run(&a, false);
    if (!strcmp(cmd, "once"))     return cmd_run(&a, true);
    if (!strcmp(cmd, "probe"))    return cmd_probe(&a);
    if (!strcmp(cmd, "verify"))   return cmd_verify(&a);
    if (!strcmp(cmd, "selftest")) return cmd_selftest(&a);
    if (!strcmp(cmd, "hold"))     return cmd_hold(&a);

    if (!strcmp(cmd, "backends")) {
        printf("dostupne backendy:\n");
        vmic_backend_print_list(stdout);
        return 0;
    }

    if (!strcmp(cmd, "config")) {
        if (a.keys) {
            printf("nastavitelne parametre (-o sekcia.kluc=hodnota):\n");
            vmic_config_help_keys(stdout);
            return 0;
        }
        vmic_config_t cfg;
        if (build_config(&a, &cfg, false) != 0) return 2;
        vmic_config_dump(&cfg, stdout);
        return 0;
    }

    if (!strcmp(cmd, "restore")) {
        vmic_config_t cfg;
        if (build_config(&a, &cfg, false) != 0) return 2;
        const char *dir = a.dir ? a.dir : cfg.dir;
        if (!a.out) {
            fprintf(stderr, "restore: chyba --out <subor>\n");
            return 2;
        }
        int rc = vmic_delta_restore(dir, a.out, a.chain, a.until);
        vmic_log_close();
        return rc == VMIC_OK ? 0 : 1;
    }

    fprintf(stderr, "neznamy prikaz '%s'\n\n", cmd);
    usage(stderr);
    return 2;
}
