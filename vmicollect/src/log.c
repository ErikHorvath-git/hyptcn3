#define _GNU_SOURCE
#include "log.h"
#include "util.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static FILE *g_out   = NULL;
static bool  g_owned = false;
static int   g_level = VMIC_LOG_INFO;
static bool  g_json  = false;

static const char *const LEVEL_NAMES[] = { "DEBUG", "INFO", "WARN", "ERROR", "NONE" };

/*
 * Asynchronny rezim (zberovy beh). Vzorkovacie vlakno nesmie zapisovat do
 * suboru: log je na tom istom ext4 ako snimky a zapis tam pri zaseknutom
 * zapise na pozadi caka sekundy (kampan benign-v4: cyklus 369 session 37).
 * Riadok sa preto poskladá v pamati volajuceho (cas sa berie v okamihu
 * volania) a pod mutexom iba skopiruje do kruhoveho buffera; do suboru ho
 * zapise vlakno vmic-log mimo mutexu. Mutex sa nikdy nedrzi pocas write().
 * Plny buffer riadok zahodi a zrata; pri zastaveni sa to oznami riadkom
 * ERROR, takze strata nikdy nie je ticha.
 */
#define LOG_RING_BYTES  (4u << 20)
#define LOG_BATCH_BYTES (64u << 10)
/* Posledne riadky behu (suhrn, koniec) mozu siahnut aj do tejto rezervy,
   ostatne sa pri nej uz zahadzuju - koniec sa tak nestrati ani pri plnom
   buffri a zostane v poradi za vsetkym ostatnym. */
#define LOG_RESERVE     (64u << 10)

static struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    pthread_cond_t  cv_done;            /* CLOCK_MONOTONIC: vlakno skoncilo */
    bool            exited;
    pthread_t       thread;
    char           *ring;
    char           *batch;              /* kopia pre write() mimo mutexu */
    size_t          head, tail, used;   /* zapis / citanie / obsadene */
    bool            active;             /* LOG ide do buffera          */
    bool            stopping;
    bool            final;              /* posledne riadky: smu do rezervy */
    size_t          inflight;           /* davka prave zapisovana do suboru */
    uint64_t        dropped;
    uint64_t        write_errors;
    int             fd;
} g_async = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .fd = -1 };

int vmic_log_level_from_name(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i <= VMIC_LOG_NONE; i++)
        if (strcasecmp(name, LEVEL_NAMES[i]) == 0)
            return i;
    /* pohodlie: bezne synonyma */
    if (strcasecmp(name, "WARNING") == 0)  return VMIC_LOG_WARN;
    if (strcasecmp(name, "OFF") == 0)      return VMIC_LOG_NONE;
    if (strcasecmp(name, "TRACE") == 0)    return VMIC_LOG_DEBUG;
    return -1;
}

const char *vmic_log_level_name(int level)
{
    if (level < 0 || level > VMIC_LOG_NONE) return "?";
    return LEVEL_NAMES[level];
}

int vmic_log_open(int level, const char *file, bool json)
{
    vmic_log_close();
    g_level = level;
    g_json  = json;
    if (file && *file) {
        g_out = fopen(file, "ae");   /* 'e' = O_CLOEXEC, nech to nededia deti */
        if (!g_out) {
            g_out = stderr;
            g_owned = false;
            fprintf(stderr, "vmicollect: nedaji sa otvorit log '%s': %s\n",
                    file, strerror(errno));
            return -1;
        }
        g_owned = true;
    } else {
        g_out = stderr;
        g_owned = false;
    }
    setvbuf(g_out, NULL, _IOLBF, 0);   /* riadkovy buffer - log nezaostava */
    return 0;
}

void vmic_log_close(void)
{
    (void)vmic_log_async_stop(5.0);
    pthread_mutex_lock(&g_async.mu);
    bool alive = g_async.active;        /* vlakno nedobehlo: deskriptor drzi ono */
    pthread_mutex_unlock(&g_async.mu);
    if (alive) return;
    if (g_out && g_owned) fclose(g_out);
    g_out = NULL;
    g_owned = false;
}

/* Escapovanie pre JSON rezim do buffera; vrati dlzku (bez nuly). */
static size_t json_escape(char *dst, size_t cap, const char *s)
{
    size_t n = 0;
    for (; *s && n + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  dst[n++] = '\\'; dst[n++] = '"';  break;
        case '\\': dst[n++] = '\\'; dst[n++] = '\\'; break;
        case '\n': dst[n++] = '\\'; dst[n++] = 'n';  break;
        case '\r': dst[n++] = '\\'; dst[n++] = 'r';  break;
        case '\t': dst[n++] = '\\'; dst[n++] = 't';  break;
        default:
            if (c < 0x20) n += (size_t)snprintf(dst + n, cap - n, "\\u%04x", c);
            else          dst[n++] = (char)c;
        }
    }
    dst[n] = '\0';
    return n;
}

/* Cely riadok vratane konca riadku; vrati jeho dlzku. */
static size_t format_line(char *line, size_t cap, int level, const char *fmt, va_list ap)
{
    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char when[40];
    strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%S", &tm);

    int head;
    size_t n;
    if (g_json) {
        head = snprintf(line, cap, "{\"ts\":\"%s.%03ldZ\",\"level\":\"%s\",\"msg\":\"",
                        when, ts.tv_nsec / 1000000L, vmic_log_level_name(level));
        n = (size_t)head;
        n += json_escape(line + n, cap - n - 4, msg);
        memcpy(line + n, "\"}\n", 4);
        n += 3;
    } else {
        head = snprintf(line, cap, "%s.%03ldZ %-5s %s\n",
                        when, ts.tv_nsec / 1000000L, vmic_log_level_name(level), msg);
        n = (size_t)head < cap ? (size_t)head : cap - 1;
        if (line[n - 1] != '\n') line[n - 1] = '\n';   /* orezany riadok */
    }
    return n;
}

static void ring_put(const char *line, size_t len)
{
    size_t first = LOG_RING_BYTES - g_async.head;
    if (first > len) first = len;
    memcpy(g_async.ring + g_async.head, line, first);
    memcpy(g_async.ring, line + first, len - first);
    g_async.head = (g_async.head + len) % LOG_RING_BYTES;
    g_async.used += len;
}

void vmic_logv(int level, const char *fmt, va_list ap)
{
    if (level < g_level || g_level >= VMIC_LOG_NONE) return;

    /* Riadok sa najprv poskladá do buffera - kvoli JSON escapovaniu a kvoli
       tomu, aby sa zapisal naraz. */
    char line[8192];
    size_t len = format_line(line, sizeof(line), level, fmt, ap);

    pthread_mutex_lock(&g_async.mu);
    if (g_async.active) {
        size_t room = LOG_RING_BYTES - g_async.used;
        if (room >= len + (g_async.final ? 0 : LOG_RESERVE)) {
            ring_put(line, len);
            pthread_cond_signal(&g_async.cv);
        } else {
            g_async.dropped++;
        }
        pthread_mutex_unlock(&g_async.mu);
        return;
    }
    pthread_mutex_unlock(&g_async.mu);

    if (!g_out) g_out = stderr;
    fwrite(line, 1, len, g_out);
}

void vmic_log(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vmic_logv(level, fmt, ap);
    va_end(ap);
}

static void *log_main(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_async.mu);
    for (;;) {
        while (!g_async.used && !g_async.stopping)
            pthread_cond_wait(&g_async.cv, &g_async.mu);
        if (!g_async.used) {             /* stopping a nic nezostalo */
            g_async.active = false;      /* dalsie riadky uz synchronne */
            g_async.exited = true;
            pthread_cond_broadcast(&g_async.cv_done);
            break;
        }
        size_t n = g_async.used < LOG_BATCH_BYTES ? g_async.used : LOG_BATCH_BYTES;
        size_t first = LOG_RING_BYTES - g_async.tail;
        if (first > n) first = n;
        memcpy(g_async.batch, g_async.ring + g_async.tail, first);
        memcpy(g_async.batch + first, g_async.ring, n - first);
        g_async.tail = (g_async.tail + n) % LOG_RING_BYTES;
        g_async.used -= n;
        g_async.inflight = n;
        pthread_mutex_unlock(&g_async.mu);
        int bad = vmic_write_all(g_async.fd, g_async.batch, n) != 0;
        pthread_mutex_lock(&g_async.mu);
        g_async.inflight = 0;
        if (bad) g_async.write_errors++;
    }
    pthread_mutex_unlock(&g_async.mu);
    return NULL;
}

int vmic_log_async_start(void)
{
    if (!g_out) g_out = stderr;
    pthread_mutex_lock(&g_async.mu);
    bool running = g_async.active;
    pthread_mutex_unlock(&g_async.mu);
    if (running) return 0;

    char *ring = malloc(LOG_RING_BYTES);
    char *batch = malloc(LOG_BATCH_BYTES);
    if (!ring || !batch) { free(ring); free(batch); return -1; }
    memset(ring, 0, LOG_RING_BYTES);          /* stranky su potom uz namapovane */
    memset(batch, 0, LOG_BATCH_BYTES);
    fflush(g_out);

    pthread_mutex_lock(&g_async.mu);
    g_async.ring = ring;
    g_async.batch = batch;
    g_async.head = g_async.tail = g_async.used = 0;
    g_async.dropped = g_async.write_errors = 0;
    g_async.stopping = false;
    g_async.final = false;
    g_async.inflight = 0;
    g_async.exited = false;
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_async.cv_done, &ca);
    pthread_condattr_destroy(&ca);
    g_async.fd = fileno(g_out);
    g_async.active = true;
    pthread_mutex_unlock(&g_async.mu);

    /* Signaly patria vzorkovaciemu vlaknu: jeho clock_nanosleep ich musi
       dostat, inak by Ctrl-C/SIGTERM nezabrali okamzite. */
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &block, &old);
    int rc = pthread_create(&g_async.thread, NULL, log_main, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (rc != 0) {
        pthread_mutex_lock(&g_async.mu);
        g_async.active = false;
        g_async.ring = g_async.batch = NULL;
        pthread_mutex_unlock(&g_async.mu);
        free(ring);
        free(batch);
        return -1;
    }
    pthread_setname_np(g_async.thread, "vmic-log");
    return 0;
}

void vmic_log_final(void)
{
    pthread_mutex_lock(&g_async.mu);
    g_async.final = true;
    pthread_mutex_unlock(&g_async.mu);
}

uint64_t vmic_log_async_stop(double timeout_s)
{
    pthread_mutex_lock(&g_async.mu);
    if (!g_async.active || g_async.stopping) {
        pthread_mutex_unlock(&g_async.mu);
        return 0;
    }
    g_async.stopping = true;
    pthread_cond_signal(&g_async.cv);
    pthread_mutex_unlock(&g_async.mu);

    /* Vlakno moze stat v zapise na zaseknuty disk: caka sa najviac
       timeout_s (monotonne hodiny), potom sa zvysok vzdá. Do toho istého
       suboru sa potom uz nezapisuje - aj ten zapis by stal. */
    struct timespec until;
    clock_gettime(CLOCK_MONOTONIC, &until);
    long add = (long)(timeout_s * 1e9);
    until.tv_sec  += add / 1000000000L;
    until.tv_nsec += add % 1000000000L;
    if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
    /* Cakanie na priznak z vlakna (podmienka na monotonnych hodinach) a az
       potom obycajny pthread_join - prenositelne a bez casu z kalendara. */
    pthread_mutex_lock(&g_async.mu);
    while (!g_async.exited &&
           pthread_cond_timedwait(&g_async.cv_done, &g_async.mu, &until) == 0)
        ;
    bool joined = g_async.exited;
    pthread_mutex_unlock(&g_async.mu);
    if (joined) pthread_join(g_async.thread, NULL);

    pthread_mutex_lock(&g_async.mu);
    uint64_t dropped = g_async.dropped, errors = g_async.write_errors;
    size_t left = g_async.used + g_async.inflight;
    if (joined) {
        free(g_async.ring);
        free(g_async.batch);
        g_async.ring = g_async.batch = NULL;
        g_async.stopping = false;
        g_async.active = false;
    }
    /* Pri nedobehnutom vlakne zostava active: dalsie riadky idu do buffera
       (ktory uz nikto nezapise), nie synchronne na zaseknuty deskriptor. */
    pthread_mutex_unlock(&g_async.mu);
    if (!joined) {
        if (g_owned)
            fprintf(stderr, "vmicollect: zapis logu nedobehol do %.0f s - %zu B logu chyba\n",
                    timeout_s, left);
        return 1 + dropped + errors;
    }
    /* Teraz uz synchronne do toho isteho suboru; ked zlyhaval prave on,
       povie to navratovy kod (cmd_run) a pri logu v subore aj stderr. */
    if (dropped)
        LOGE("log: %" PRIu64 " riadkov sa nezmestilo do buffera logu a chyba ich", dropped);
    if (errors)
        LOGE("log: %" PRIu64 " zapisov logu zlyhalo", errors);
    if ((dropped || errors) && g_owned)
        fprintf(stderr, "vmicollect: log je neuplny (%" PRIu64 " zahodenych, %" PRIu64
                " zlyhanych zapisov)\n", dropped, errors);
    return dropped + errors;
}
