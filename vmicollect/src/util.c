#define _GNU_SOURCE
#include "util.h"
#include "log.h"
#include "sha256.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Cas                                                                 */
/* ------------------------------------------------------------------ */

double vmic_now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

void vmic_now_real(struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

void vmic_ts_compact(char *out, size_t n, const struct timespec *ts)
{
    struct tm tm;
    gmtime_r(&ts->tv_sec, &tm);
    char base[32];
    strftime(base, sizeof(base), "%Y%m%dT%H%M%S", &tm);
    snprintf(out, n, "%s%03ldZ", base, ts->tv_nsec / 1000000L);
}

void vmic_ts_iso(char *out, size_t n, const struct timespec *ts)
{
    struct tm tm;
    gmtime_r(&ts->tv_sec, &tm);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, n, "%s.%03ldZ", base, ts->tv_nsec / 1000000L);
}

int vmic_sleep_until(double deadline_mono)
{
    struct timespec ts;
    if (!isfinite(deadline_mono)) return -1;
    if (deadline_mono < 0) deadline_mono = 0;
    ts.tv_sec  = (time_t)deadline_mono;
    ts.tv_nsec = (long)((deadline_mono - (double)ts.tv_sec) * 1e9);
    if (ts.tv_nsec > 999999999L) { ts.tv_nsec = 999999999L; }
    if (ts.tv_nsec < 0)          { ts.tv_nsec = 0; }

    /*
     * TIMER_ABSTIME je kluc k bezdriftovemu planovaniu: spime do
     * ABSOLUTNEHO terminu, nie "este X sekund". Ked nas prerusi signal,
     * clock_nanosleep vrati EINTR a my sa vratime hore - takze Ctrl-C
     * zaberie okamzite a nemusime cakat do konca periody.
     */
    int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
    if (rc == 0)     return 0;
    if (rc == EINTR) return 1;

    /*
     * Ina chyba (typicky EINVAL pri nezmyselnom termine). Tvarit sa, ze
     * sme dospali, by bola pasca: volajuci je slucka `while (now < target)
     * sleep(target)`, takze by z nej bolo ciste aktivne cakanie na 100 %
     * CPU. Vratime -1 a planovac beh ukonci.
     */
    return -1;
}

/* ------------------------------------------------------------------ */
/* Cesty                                                               */
/* ------------------------------------------------------------------ */

int vmic_mkdir_p(const char *path)
{
    if (!path || !*path) return -1;
    char tmp[VMIC_UTIL_PATHBUF];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

int vmic_join(char *out, size_t n, const char *dir, const char *name)
{
    if (!dir || !*dir) return snprintf(out, n, "%s", name) < (int)n ? 0 : -1;
    size_t dl = strlen(dir);
    const char *sep = (dl && dir[dl - 1] == '/') ? "" : "/";
    return snprintf(out, n, "%s%s%s", dir, sep, name) < (int)n ? 0 : -1;
}

void vmic_sanitize(char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || c == '-' || c == '_' || c == '.') continue;
        *s = '_';
    }
}

int64_t vmic_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

int64_t vmic_file_disk_usage(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_blocks * 512;
}

bool vmic_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* ------------------------------------------------------------------ */
/* I/O                                                                 */
/* ------------------------------------------------------------------ */

int vmic_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) { errno = EIO; return -1; }
        p   += (size_t)w;
        len -= (size_t)w;
    }
    return 0;
}

int vmic_pwrite_all(int fd, const void *buf, size_t len, off_t off)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        ssize_t w = pwrite(fd, p, len, off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) { errno = EIO; return -1; }
        p   += (size_t)w;
        len -= (size_t)w;
        off += w;
    }
    return 0;
}

ssize_t vmic_read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = read(fd, p + done, len - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;        /* koniec suboru */
        done += (size_t)r;
    }
    return (ssize_t)done;
}

ssize_t vmic_pread_full(int fd, void *buf, size_t len, off_t off)
{
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = pread(fd, p + done, len - done, off + (off_t)done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        done += (size_t)r;
    }
    return (ssize_t)done;
}

/* ------------------------------------------------------------------ */
/* Data                                                                */
/* ------------------------------------------------------------------ */

void vmic_hex(const uint8_t *in, size_t n, char *out)
{
    static const char D[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = D[in[i] >> 4];
        out[i * 2 + 1] = D[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

bool vmic_is_zero(const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    /* zarovnanie na 8 B */
    while (len && ((uintptr_t)p & 7u)) {
        if (*p++) return false;
        len--;
    }
    const uint64_t *w = (const uint64_t *)(const void *)p;
    size_t words = len / 8;
    for (size_t i = 0; i < words; i++)
        if (w[i]) return false;
    p = (const uint8_t *)(w + words);
    for (size_t i = 0; i < len % 8; i++)
        if (p[i]) return false;
    return true;
}

uint64_t vmic_hash64(const void *buf, size_t len)
{
    /*
     * Varianta FNV-1a pracujuca po 8 B slovach. Nie je kryptograficka -
     * sluzi VYHRADNE na porovnanie "zmenila sa stranka?". Pri 4 KiB
     * strankach a milione stranok je pravdepodobnost falosnej zhody
     * rádovo 1e-8, co je pre periodicky zber uplne v poriadku (a stranka
     * sa aj tak znovu zachyti v najblizsej plnej snimke).
     */
    const uint64_t PRIME = 0x100000001b3ull;
    uint64_t h = 0xcbf29ce484222325ull ^ (uint64_t)len;

    const uint8_t *p = (const uint8_t *)buf;
    while (len && ((uintptr_t)p & 7u)) {
        h = (h ^ *p++) * PRIME;
        len--;
    }
    const uint64_t *w = (const uint64_t *)(const void *)p;
    size_t words = len / 8;
    for (size_t i = 0; i < words; i++) {
        h ^= w[i];
        h *= PRIME;
        h ^= h >> 29;          /* premiesa horne bity do dolnych */
    }
    p = (const uint8_t *)(w + words);
    for (size_t i = 0; i < len % 8; i++)
        h = (h ^ p[i]) * PRIME;
    return h ^ (h >> 32);
}

int vmic_hash_file(const char *path, uint8_t out[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    const size_t BUF = 1u << 20;
    uint8_t *buf = malloc(BUF);
    if (!buf) { close(fd); return -1; }

    vmic_sha256_t c;
    vmic_sha256_init(&c);

    int rc = 0;
    for (;;) {
        ssize_t n = vmic_read_full(fd, buf, BUF);
        if (n < 0)  { rc = -1; break; }
        if (n == 0) break;
        vmic_sha256_update(&c, buf, (size_t)n);
        if ((size_t)n < BUF) break;      /* koniec suboru */
    }
    free(buf);
    close(fd);
    if (rc == 0) vmic_sha256_final(&c, out);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Sablona nazvu                                                       */
/* ------------------------------------------------------------------ */

int vmic_render_name(char *out, size_t n, const char *tmpl,
                     const char *domain, uint64_t seq, const char *ts,
                     const char *backend)
{
    size_t o = 0;
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%ld", (long)getpid());

    for (const char *p = tmpl; *p; ) {
        if (*p != '{') {
            if (o + 1 >= n) return -1;
            out[o++] = *p++;
            continue;
        }
        const char *end = strchr(p, '}');
        if (!end) return -1;

        char key[64];
        size_t klen = (size_t)(end - p - 1);
        if (klen >= sizeof(key)) return -1;
        memcpy(key, p + 1, klen);
        key[klen] = '\0';

        /* volitelny format za dvojbodkou: {seq:06d} */
        char *fmt = strchr(key, ':');
        if (fmt) *fmt++ = '\0';

        char piece[VMIC_NAME_BUF];
        if (strcmp(key, "domain") == 0) {
            snprintf(piece, sizeof(piece), "%s", domain ? domain : "vm");
            vmic_sanitize(piece);
        } else if (strcmp(key, "ts") == 0) {
            snprintf(piece, sizeof(piece), "%s", ts ? ts : "");
        } else if (strcmp(key, "backend") == 0) {
            snprintf(piece, sizeof(piece), "%s", backend ? backend : "");
        } else if (strcmp(key, "pid") == 0) {
            snprintf(piece, sizeof(piece), "%s", pidbuf);
        } else if (strcmp(key, "seq") == 0) {
            if (fmt && *fmt) {
                /* z "06d" spravime "%06" PRIu64 - povolime iba cislice a 'd' */
                char width[16];
                size_t wi = 0;
                for (const char *f = fmt; *f && wi + 1 < sizeof(width); f++)
                    if (isdigit((unsigned char)*f)) width[wi++] = *f;
                width[wi] = '\0';
                char spec[32];
                snprintf(spec, sizeof(spec), "%%0%s%s", width, PRIu64);
                snprintf(piece, sizeof(piece), spec, seq);
            } else {
                snprintf(piece, sizeof(piece), "%" PRIu64, seq);
            }
        } else {
            return -1;   /* neznamy zastupny symbol - radsej hlasna chyba */
        }

        size_t plen = strlen(piece);
        if (o + plen + 1 > n) return -1;
        memcpy(out + o, piece, plen);
        o += plen;
        p = end + 1;
    }
    out[o] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Velkosti a nahoda                                                   */
/* ------------------------------------------------------------------ */

int vmic_parse_size(const char *s, uint64_t *out)
{
    if (!s || !*s) return -1;
    while (isspace((unsigned char)*s)) s++;

    /* strtoull() prijme aj "-1" a ticho z toho spravi UINT64_MAX.
       Vsetky velkosti v configu su nezaporne, takze to zamietneme hned -
       inak by sa "-1" prejavilo az ako "nedostatok pamate na 18 EB". */
    if (*s == '-') return -1;
    if (*s == '+') s++;

    errno = 0;
    char *end = NULL;
    unsigned long long base = strtoull(s, &end, 0);   /* 0 = pozna 0x/0 */
    if (end == s || errno == ERANGE) return -1;

    while (isspace((unsigned char)*end)) end++;

    static const struct { const char *suf; uint64_t mul; } U[] = {
        { "kib", 1024ull }, { "mib", 1024ull * 1024 },
        { "gib", 1024ull * 1024 * 1024 }, { "tib", 1024ull * 1024 * 1024 * 1024 },
        { "kb", 1000ull },  { "mb", 1000000ull },
        { "gb", 1000000000ull }, { "tb", 1000000000000ull },
        { "k", 1024ull },   { "m", 1024ull * 1024 },
        { "g", 1024ull * 1024 * 1024 }, { "t", 1024ull * 1024 * 1024 * 1024 },
        { "b", 1ull },      { "", 1ull },
    };
    char low[8];
    size_t i = 0;
    for (const char *p = end; *p && i + 1 < sizeof(low); p++)
        low[i++] = (char)tolower((unsigned char)*p);
    low[i] = '\0';

    for (size_t k = 0; k < sizeof(U) / sizeof(U[0]); k++) {
        if (strcmp(low, U[k].suf) == 0) {
            if (U[k].mul && base > UINT64_MAX / U[k].mul) return -1;
            *out = (uint64_t)base * U[k].mul;
            return 0;
        }
    }
    return -1;
}

void vmic_human_size(uint64_t bytes, char *out, size_t n)
{
    static const char *U[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double v = (double)bytes;
    size_t u = 0;
    while (v >= 1024.0 && u + 1 < sizeof(U) / sizeof(U[0])) { v /= 1024.0; u++; }
    if (u == 0) snprintf(out, n, "%" PRIu64 " B", bytes);
    else        snprintf(out, n, "%.2f %s", v, U[u]);
}

static unsigned int g_seed = 0;

void vmic_random_seed(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    g_seed = (unsigned int)(ts.tv_nsec ^ (long)getpid() ^ (ts.tv_sec << 8));
    if (!g_seed) g_seed = 1;
}

double vmic_jitter_unit(void)
{
    if (!g_seed) vmic_random_seed();
    /* rand_r je reentrantny a deterministicky - staci na rozhodenie fazy */
    int r = rand_r(&g_seed);
    return ((double)r / (double)RAND_MAX) * 2.0 - 1.0;
}
