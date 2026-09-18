#define _GNU_SOURCE
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE *g_out   = NULL;
static bool  g_owned = false;
static int   g_level = VMIC_LOG_INFO;
static bool  g_json  = false;

static const char *const LEVEL_NAMES[] = { "DEBUG", "INFO", "WARN", "ERROR", "NONE" };

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
    if (g_out && g_owned) fclose(g_out);
    g_out = NULL;
    g_owned = false;
}

/* Escapovanie pre JSON rezim. */
static void json_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f);  break;
        case '\r': fputs("\\r", f);  break;
        case '\t': fputs("\\t", f);  break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else          fputc(c, f);
        }
    }
}

void vmic_logv(int level, const char *fmt, va_list ap)
{
    if (level < g_level || g_level >= VMIC_LOG_NONE) return;
    if (!g_out) g_out = stderr;

    /* Sprava sa najprv poskladá do buffera - kvoli JSON escapovaniu
       a kvoli tomu, aby sa riadok zapisal jednym fputs (atomickejsie). */
    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char when[40];
    strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%S", &tm);

    if (g_json) {
        fprintf(g_out, "{\"ts\":\"%s.%03ldZ\",\"level\":\"%s\",\"msg\":\"",
                when, ts.tv_nsec / 1000000L, vmic_log_level_name(level));
        json_escape(g_out, msg);
        fputs("\"}\n", g_out);
    } else {
        fprintf(g_out, "%s.%03ldZ %-5s %s\n",
                when, ts.tv_nsec / 1000000L, vmic_log_level_name(level), msg);
    }
}

void vmic_log(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vmic_logv(level, fmt, ap);
    va_end(ap);
}
