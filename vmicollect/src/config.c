/*
 * config.c - konfiguracia zberaca.
 *
 * NAJDOLEZITEJSIA VEC V TOMTO SUBORE je tabulka FIELDS. Kazdy riadok v nej
 * je jeden nastavitelny parameter a zaroven urcuje:
 *      - ako sa cita z .conf suboru,
 *      - ako sa da prebit z prikazoveho riadku (-o sekcia.kluc=hodnota),
 *      - ako sa vypise cez `vmicollect config`,
 *      - ako sa validuje.
 *
 * Ked chces pridat vlastny prepinac, staci pridat pole do vmic_config_t
 * (vmic.h) a jeden riadok sem. Nikde inde sa nic menit nemusi.
 *
 * Format suboru je zamerne obycajne INI - bez externeho parseru:
 *
 *      [vm]
 *      domain  = win10
 *      backend = ebpf
 *
 *      [capture]
 *      chunk_size = 1MiB
 *      regions    = 0x0:16MiB, 0x100000000:1GiB
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Popis jedneho parametra                                             */
/* ------------------------------------------------------------------ */

typedef enum {
    T_STR,        /* retazec do pola pevnej velkosti          */
    T_BOOL,       /* true/false, yes/no, 1/0, on/off          */
    T_U64,        /* cele cislo (aj s priponou 1MiB)          */
    T_SIZE,       /* to iste, ale ulozene do size_t           */
    T_U32,        /* to iste, ale ulozene do uint32_t         */
    T_DOUBLE,
    T_ENUM_STR,   /* jedna z povolenych hodnot, ulozi retazec */
    T_ENUM_INT,   /* jedna z povolenych hodnot, ulozi index   */
    T_REGIONS,    /* "start:dlzka, start:dlzka, ..."          */
    T_HOOK,       /* pridava sa do zoznamu (moze sa opakovat) */
    T_LOGLEVEL
} ftype_t;

typedef struct {
    const char *section;
    const char *key;
    ftype_t     type;
    size_t      offset;
    size_t      bufsize;               /* iba T_STR / T_ENUM_STR */
    const char *const *choices;        /* iba T_ENUM_*           */
    const char *help;
} field_t;

static const char *const CH_BACKEND[]  = { "ebpf", "file", NULL };
static const char *const CH_OVERRUN[]  = { "skip", "catch_up", "stretch", NULL };
static const char *const CH_WRITER[]   = { "raw", "delta", NULL };
static const char *const CH_HASH[]     = { "none", "sha256", NULL };
static const char *const CH_COMPRESS[] = { "none", "gzip", NULL };

#define F(sec, key, type, member, ...) \
    { sec, key, type, offsetof(vmic_config_t, member), sizeof(((vmic_config_t *)0)->member), __VA_ARGS__ }

static const field_t FIELDS[] = {
/*   sekcia      kluc               typ           clen             choices      napoveda */
F("vm",       "domain",           T_STR,       domain,           NULL, "meno domeny, 'pid:N' alebo pid; prazdne = jedina bezica"),
F("vm",       "backend",          T_ENUM_STR,  backend,          CH_BACKEND, "odkial citame pamat"),
F("vm",       "bpf_object",       T_STR,       bpf_object,       NULL, "backend 'ebpf': vlastny .bpf.o (prazdne = vlozeny)"),
F("vm",       "image_path",       T_STR,       image_path,       NULL, "backend 'file': cesta k raw obrazu"),

F("schedule", "interval_s",       T_DOUBLE,    interval_s,       NULL, "perioda medzi zaciatkami snimok"),
F("schedule", "jitter",           T_DOUBLE,    jitter,           NULL, "nahodny rozptyl 0.0-0.99 (podiel periody)"),
F("schedule", "overrun",          T_ENUM_INT,  overrun,          CH_OVERRUN, "co robit ked snimka presiahne periodu"),
F("schedule", "max_cycles",       T_U64,       max_cycles,       NULL, "0 = bez limitu"),
F("schedule", "duration_s",       T_DOUBLE,    duration_s,       NULL, "0 = bez limitu"),
F("schedule", "align",            T_BOOL,      align,            NULL, "zarovnat prvy termin na nasobok periody"),

F("capture",  "pause",            T_BOOL,      pause,            NULL, "pozastavit vCPU pocas citania (ebpf to nevie)"),
F("capture",  "pause_max_ms",     T_DOUBLE,    pause_max_ms,     NULL, "nad tento cas pauzy varujeme"),
F("capture",  "chunk_size",       T_SIZE,      chunk_size,       NULL, "velkost jedneho citania"),
F("capture",  "regions",          T_REGIONS,   region_count,     NULL, "'start:dlzka, ...'; prazdne = cela RAM"),
F("capture",  "skip_read_errors", T_BOOL,      skip_read_errors, NULL, "diery v pamati vyplnit nulami"),
F("capture",  "max_read_errors",  T_U64,       max_read_errors,  NULL, "0 = bez limitu"),

F("output",   "dir",              T_STR,       dir,              NULL, "adresar so snimkami"),
F("output",   "writer",           T_ENUM_STR,  writer,           CH_WRITER, "format vystupu"),
F("output",   "name_template",    T_STR,       name_template,    NULL, "{domain} {seq:06d} {ts} {backend} {pid}"),
F("output",   "sparse",           T_BOOL,      sparse,           NULL, "preskakovat nulove bloky (riedky subor)"),
F("output",   "post_compress",    T_ENUM_INT,  post_compress,    CH_COMPRESS, "kompresia az PO odpauzovani VM"),
F("output",   "hash",             T_ENUM_INT,  hash,             CH_HASH, "kontrolny sucet do metadat"),
F("output",   "sidecar",          T_BOOL,      sidecar,          NULL, "zapisovat .json s metadatami"),
F("output",   "delta_page_size",  T_U32,       delta_page_size,  NULL, "granularita porovnavania (mocnina 2)"),
F("output",   "delta_full_every", T_U64,       delta_full_every, NULL, "kazdych N snimok plna zaloha"),

F("retention","max_snapshots",    T_U64,       max_snapshots,    NULL, "0 = nemazat"),
F("retention","max_bytes",        T_U64,       max_bytes,        NULL, "0 = nemazat"),
F("retention","max_age_s",        T_DOUBLE,    max_age_s,        NULL, "0 = nemazat"),

F("hooks",    "load",             T_HOOK,      hook_count,       NULL, "./plugin.so[:argumenty] (da sa opakovat)"),
F("hooks",    "strict",           T_BOOL,      hooks_strict,     NULL, "chyba v hooku ukonci zber"),

F("log",      "level",            T_LOGLEVEL,  log_level,        NULL, "DEBUG|INFO|WARN|ERROR|NONE"),
F("log",      "file",             T_STR,       log_file,         NULL, "prazdne = stderr"),
F("log",      "json",             T_BOOL,      log_json,         NULL, "jeden JSON riadok na zaznam"),
};

#define FIELD_COUNT (sizeof(FIELDS) / sizeof(FIELDS[0]))

/* ------------------------------------------------------------------ */
/* Vychodzie hodnoty                                                   */
/* ------------------------------------------------------------------ */

void vmic_config_defaults(vmic_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    snprintf(cfg->backend, sizeof(cfg->backend), "ebpf");

    cfg->interval_s = 5.0;
    cfg->jitter     = 0.0;
    cfg->overrun    = VMIC_OVERRUN_SKIP;
    cfg->max_cycles = 0;
    cfg->duration_s = 0.0;
    cfg->align      = false;

    cfg->pause            = false;
    cfg->pause_max_ms     = 500.0;
    cfg->chunk_size       = 1u << 20;
    cfg->region_count     = 0;
    cfg->skip_read_errors = true;
    cfg->max_read_errors  = 0;

    snprintf(cfg->dir, sizeof(cfg->dir), "./snapshots");
    snprintf(cfg->writer, sizeof(cfg->writer), "raw");
    snprintf(cfg->name_template, sizeof(cfg->name_template),
             "{domain}_{seq:06d}_{ts}");
    cfg->sparse           = true;
    cfg->post_compress    = VMIC_COMPRESS_NONE;
    cfg->hash             = VMIC_HASH_SHA256;
    cfg->sidecar          = true;
    cfg->delta_page_size  = 4096;
    cfg->delta_full_every = 20;

    cfg->hooks_strict = false;
    cfg->log_level    = VMIC_LOG_INFO;
    cfg->log_json     = false;
}

/* ------------------------------------------------------------------ */
/* Pomocne parsery hodnot                                              */
/* ------------------------------------------------------------------ */

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static int parse_bool(const char *s, bool *out)
{
    if (!strcasecmp(s, "true")  || !strcasecmp(s, "yes") ||
        !strcasecmp(s, "on")    || !strcmp(s, "1")) { *out = true;  return 0; }
    if (!strcasecmp(s, "false") || !strcasecmp(s, "no")  ||
        !strcasecmp(s, "off")   || !strcmp(s, "0")) { *out = false; return 0; }
    return -1;
}

static int parse_double(const char *s, double *out)
{
    errno = 0;
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == s || errno == ERANGE) return -1;
    while (isspace((unsigned char)*end)) end++;
    if (*end) return -1;
    *out = v;
    return 0;
}

static int choice_index(const char *const *choices, const char *value)
{
    for (int i = 0; choices[i]; i++)
        if (strcasecmp(choices[i], value) == 0) return i;
    return -1;
}

static void choices_join(const char *const *choices, char *out, size_t n)
{
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; choices[i]; i++)
        o += (size_t)snprintf(out + o, o < n ? n - o : 0, "%s%s",
                              i ? "|" : "", choices[i]);
}

/*
 * "0x0:16MiB, 0x100000000:1GiB"  ->  cfg->regions[]
 * Povoleny je aj oddelovac '+' a ';' medzi polozkami.
 */
static int parse_regions(vmic_config_t *cfg, const char *value)
{
    cfg->region_count = 0;
    char buf[1024];
    if (snprintf(buf, sizeof(buf), "%s", value) >= (int)sizeof(buf)) {
        LOGE("capture.regions: zoznam je prilis dlhy");
        return -1;
    }

    char *save = NULL;
    for (char *tok = strtok_r(buf, ",;", &save); tok;
         tok = strtok_r(NULL, ",;", &save)) {
        char *item = trim(tok);
        if (!*item) continue;
        if (cfg->region_count >= VMIC_MAX_REGIONS) {
            LOGE("capture.regions: maximum je %d oblasti", VMIC_MAX_REGIONS);
            return -1;
        }
        char *sep = strpbrk(item, ":+");
        if (!sep) {
            LOGE("capture.regions: '%s' nema tvar start:dlzka", item);
            return -1;
        }
        *sep = '\0';
        uint64_t start = 0, size = 0;
        char *lhs = trim(item);
        char *rhs = trim(sep + 1);
        if (vmic_parse_size(lhs, &start) != 0 ||
            vmic_parse_size(rhs, &size)  != 0) {
            LOGE("capture.regions: neviem prelozit '%s:%s'", lhs, rhs);
            return -1;
        }
        if (size == 0) {
            LOGE("capture.regions: dlzka musi byt > 0");
            return -1;
        }
        if (start > UINT64_MAX - size) {
            LOGE("capture.regions: 0x%" PRIx64 "+0x%" PRIx64 " pretecie", start, size);
            return -1;
        }
        cfg->regions[cfg->region_count].start = start;
        cfg->regions[cfg->region_count].size  = size;
        cfg->region_count++;
    }
    return 0;
}

/* Zoradi oblasti a zluci prekryvy - inak by sme ten isty blok citali
   dvakrat a v delta writeri by sme si prepisali hash tej istej stranky. */
static void merge_regions(vmic_config_t *cfg)
{
    if (cfg->region_count < 2) return;
    for (size_t i = 1; i < cfg->region_count; i++) {   /* insertion sort */
        vmic_region_t key = cfg->regions[i];
        size_t j = i;
        while (j > 0 && cfg->regions[j - 1].start > key.start) {
            cfg->regions[j] = cfg->regions[j - 1];
            j--;
        }
        cfg->regions[j] = key;
    }
    size_t out = 0;
    for (size_t i = 1; i < cfg->region_count; i++) {
        uint64_t end = cfg->regions[out].start + cfg->regions[out].size;
        if (cfg->regions[i].start <= end) {
            uint64_t new_end = cfg->regions[i].start + cfg->regions[i].size;
            if (new_end > end)
                cfg->regions[out].size = new_end - cfg->regions[out].start;
        } else {
            cfg->regions[++out] = cfg->regions[i];
        }
    }
    cfg->region_count = out + 1;
}

static int add_hook(vmic_config_t *cfg, const char *value)
{
    if (cfg->hook_count >= VMIC_MAX_HOOKS) {
        LOGE("hooks.load: maximum je %d pluginov", VMIC_MAX_HOOKS);
        return -1;
    }
    /* "cesta.so:argumenty" - delime na PRVEJ dvojbodke za priponou .so,
       aby fungovali aj absolutne cesty a argumenty s dvojbodkou. */
    const char *so = strstr(value, ".so");
    const char *split = NULL;
    if (so && so[3] == ':') split = so + 3;
    else                    split = NULL;

    size_t i = cfg->hook_count;
    if (split) {
        size_t plen = (size_t)(split - value);
        if (plen >= sizeof(cfg->hook_path[i])) return -1;
        memcpy(cfg->hook_path[i], value, plen);
        cfg->hook_path[i][plen] = '\0';
        snprintf(cfg->hook_args[i], sizeof(cfg->hook_args[i]), "%s", split + 1);
    } else {
        snprintf(cfg->hook_path[i], sizeof(cfg->hook_path[i]), "%s", value);
        cfg->hook_args[i][0] = '\0';
    }
    cfg->hook_count++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Nastavenie jedneho pola                                             */
/* ------------------------------------------------------------------ */

static const field_t *find_field(const char *section, const char *key)
{
    for (size_t i = 0; i < FIELD_COUNT; i++)
        if (strcasecmp(FIELDS[i].section, section) == 0 &&
            strcasecmp(FIELDS[i].key, key) == 0)
            return &FIELDS[i];
    return NULL;
}

static int apply_field(vmic_config_t *cfg, const field_t *f, const char *value)
{
    void *slot = (char *)cfg + f->offset;

    switch (f->type) {
    case T_STR:
        if (strlen(value) >= f->bufsize) {
            LOGE("%s.%s: hodnota je dlhsia ako %zu znakov",
                 f->section, f->key, f->bufsize - 1);
            return -1;
        }
        snprintf((char *)slot, f->bufsize, "%s", value);
        return 0;

    case T_ENUM_STR: {
        int idx = choice_index(f->choices, value);
        if (idx < 0) {
            char list[128];
            choices_join(f->choices, list, sizeof(list));
            LOGE("%s.%s: '%s' nie je povolene (%s)", f->section, f->key, value, list);
            return -1;
        }
        snprintf((char *)slot, f->bufsize, "%s", f->choices[idx]);
        return 0;
    }

    case T_ENUM_INT: {
        int idx = choice_index(f->choices, value);
        if (idx < 0) {
            char list[128];
            choices_join(f->choices, list, sizeof(list));
            LOGE("%s.%s: '%s' nie je povolene (%s)", f->section, f->key, value, list);
            return -1;
        }
        *(int *)slot = idx;
        return 0;
    }

    case T_BOOL:
        if (parse_bool(value, (bool *)slot) != 0) {
            LOGE("%s.%s: ocakavam true/false, dostal som '%s'",
                 f->section, f->key, value);
            return -1;
        }
        return 0;

    case T_DOUBLE:
        if (parse_double(value, (double *)slot) != 0) {
            LOGE("%s.%s: '%s' nie je cislo", f->section, f->key, value);
            return -1;
        }
        return 0;

    case T_U64: case T_SIZE: case T_U32: {
        uint64_t v = 0;
        if (vmic_parse_size(value, &v) != 0) {
            LOGE("%s.%s: '%s' nie je cislo (skus napr. 4096 / 0x1000 / 1MiB)",
                 f->section, f->key, value);
            return -1;
        }
        if (f->type == T_U64)       *(uint64_t *)slot = v;
        else if (f->type == T_SIZE) {
            if (v > (uint64_t)SIZE_MAX) { LOGE("%s.%s: prilis velke", f->section, f->key); return -1; }
            *(size_t *)slot = (size_t)v;
        } else {
            if (v > UINT32_MAX) { LOGE("%s.%s: prilis velke", f->section, f->key); return -1; }
            *(uint32_t *)slot = (uint32_t)v;
        }
        return 0;
    }

    case T_LOGLEVEL: {
        int lv = vmic_log_level_from_name(value);
        if (lv < 0) {
            LOGE("log.level: neznama uroven '%s'", value);
            return -1;
        }
        *(int *)slot = lv;
        return 0;
    }

    case T_REGIONS:
        return parse_regions(cfg, value);

    case T_HOOK:
        return add_hook(cfg, value);
    }
    return -1;
}

int vmic_config_set(vmic_config_t *cfg, const char *assignment)
{
    const char *eq = strchr(assignment, '=');
    if (!eq) {
        LOGE("override '%s' nema tvar sekcia.kluc=hodnota", assignment);
        return -1;
    }
    char lhs[128];
    size_t llen = (size_t)(eq - assignment);
    if (llen >= sizeof(lhs)) { LOGE("override: prilis dlhy kluc"); return -1; }
    memcpy(lhs, assignment, llen);
    lhs[llen] = '\0';

    char *dot = strchr(lhs, '.');
    if (!dot) {
        LOGE("override '%s': chyba sekcia (napr. schedule.interval_s=2)", lhs);
        return -1;
    }
    *dot = '\0';

    char *section = trim(lhs);
    char *key     = trim(dot + 1);
    const field_t *f = find_field(section, key);
    if (!f) {
        LOGE("neznamy parameter '%s.%s' (zoznam: vmicollect config --help-keys)",
             section, key);
        return -1;
    }
    char value[1024];
    int need = snprintf(value, sizeof(value), "%s", eq + 1);
    if (need < 0 || (size_t)need >= sizeof(value)) {
        /* ticha strata konca hodnoty by pri capture.regions znamenala
           orezanu poslednu oblast - radsej hlasna chyba */
        LOGE("override %s.%s: hodnota je prilis dlha (%d znakov, max %zu)",
             section, key, need, sizeof(value) - 1);
        return -1;
    }
    return apply_field(cfg, f, trim(value));
}

/* ------------------------------------------------------------------ */
/* Citanie suboru                                                      */
/* ------------------------------------------------------------------ */

int vmic_config_load(vmic_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "re");
    if (!f) {
        LOGE("konfiguracia '%s': %s", path, strerror(errno));
        return -1;
    }

    char section[64] = "";
    char line[2048];
    int lineno = 0, errors = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if (!*s || *s == '#' || *s == ';') continue;

        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) {
                LOGE("%s:%d: neuzavreta sekcia", path, lineno);
                errors++;
                continue;
            }
            *end = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) {
            LOGE("%s:%d: riadok nema tvar kluc = hodnota", path, lineno);
            errors++;
            continue;
        }
        *eq = '\0';
        char *key   = trim(s);
        char *value = trim(eq + 1);

        /* uvodzovky su volitelne; v nich sa '#' neberie ako komentar */
        if (*value == '"' || *value == '\'') {
            char q = *value;
            char *close = strrchr(value + 1, q);
            if (close) { *close = '\0'; value++; }
        } else {
            char *hash = strpbrk(value, "#;");
            if (hash) { *hash = '\0'; value = trim(value); }
        }

        if (!*section) {
            LOGE("%s:%d: '%s' je mimo sekcie", path, lineno, key);
            errors++;
            continue;
        }
        const field_t *fd = find_field(section, key);
        if (!fd) {
            LOGE("%s:%d: neznamy parameter [%s] %s", path, lineno, section, key);
            errors++;
            continue;
        }
        if (apply_field(cfg, fd, value) != 0) {
            LOGE("%s:%d: chybna hodnota", path, lineno);
            errors++;
        }
    }
    fclose(f);

    if (errors) {
        LOGE("konfiguracia obsahuje %d chyb", errors);
        return -1;
    }
    snprintf(cfg->source_path, sizeof(cfg->source_path), "%s", path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Validacia                                                           */
/* ------------------------------------------------------------------ */

/* Ktore backendy vedia citat lubovolny rozsah - od toho zavisi, ci sa
   daju pouzit [capture].regions a writer 'delta'. Dnes to vedia oba, ale
   kontrola tu zostava: hromadny backend (napr. externy dump) by inak
   ticho rozbil delta retazec.                                         */
static bool backend_is_random_access(const vmic_config_t *cfg)
{
    return strcmp(cfg->backend, "ebpf") == 0 ||
           strcmp(cfg->backend, "file") == 0;
}

/*
 * POZOR NA NaN: kazde porovnanie s NaN je false, takze testy tvaru
 * `x <= 0.0` NaN bez problemov PREPUSTIA. strtod() pritom "nan" aj "inf"
 * ochotne prijme. Nekonecny interval by potom v planovaci sposobil
 * nekonecne aktivne cakanie na 100 % CPU. Preto sa vsetky desatinne
 * hodnoty najprv testuju na konecnost.
 */
static bool finite_ok(const char *what, double v, double lo, double hi)
{
    if (!isfinite(v)) {
        LOGE("%s: '%g' nie je platne cislo (nan/inf)", what, v);
        return false;
    }
    if (v < lo || v > hi) {
        LOGE("%s: musi byt v rozsahu <%g, %g>, dostal som %g", what, lo, hi, v);
        return false;
    }
    return true;
}

/* horna hranica casovych parametrov: 1 rok v sekundach.
   Drzi nas bezpecne v rozsahu time_t aj pri prepocte na nanosekundy. */
#define VMIC_MAX_SECONDS (365.0 * 24 * 3600)

int vmic_config_validate(vmic_config_t *cfg, bool need_target)
{
    int bad = 0;

    if (!finite_ok("schedule.interval_s", cfg->interval_s, 0.001, VMIC_MAX_SECONDS))
        bad++;
    if (!finite_ok("schedule.jitter", cfg->jitter, 0.0, 0.99))
        bad++;
    if (!finite_ok("schedule.duration_s", cfg->duration_s, 0.0, VMIC_MAX_SECONDS))
        bad++;
    if (!finite_ok("retention.max_age_s", cfg->max_age_s, 0.0, VMIC_MAX_SECONDS))
        bad++;
    if (!finite_ok("capture.pause_max_ms", cfg->pause_max_ms, 0.0, 1e9))
        bad++;
    if (cfg->chunk_size < 4096) {
        LOGE("capture.chunk_size musi byt aspon 4096 B"); bad++;
    }
    bool page_size_ok = (cfg->delta_page_size >= 512 &&
                         (cfg->delta_page_size & (cfg->delta_page_size - 1)) == 0);
    if (!page_size_ok) {
        LOGE("output.delta_page_size musi byt mocnina 2 a aspon 512"); bad++;
    }
    if (cfg->delta_full_every < 1) {
        LOGE("output.delta_full_every musi byt aspon 1"); bad++;
    }
    if (!cfg->dir[0]) {
        LOGE("output.dir nesmie byt prazdny"); bad++;
    }
    if (!cfg->name_template[0]) {
        LOGE("output.name_template nesmie byt prazdny"); bad++;
    }

    /*
     * Povinne polia podla backendu - iba ked sa naozaj pripajame.
     * Backend 'ebpf' vm.domain NEvyzaduje: ked na stroji bezi jedina KVM
     * domena, najde si ju sam (a ked ich je viac, vypise zoznam).
     */
    if (need_target && strcmp(cfg->backend, "file") == 0 && !cfg->image_path[0]) {
        LOGE("backend 'file' vyzaduje vm.image_path");
        bad++;
    }

    /*
     * Sablona musi obsahovat nieco, co sa medzi snimkami MENI. Inak by
     * kazdy cyklus zapisoval do toho isteho suboru a prepisal predchadzajuci
     * (pri delta writeri by prva delta prepisala plnu snimku a cely retazec
     * by sa uz nedal obnovit - a zberac by pritom hlasil same uspechy).
     */
    if (cfg->name_template[0] &&
        !strstr(cfg->name_template, "{seq") &&
        !strstr(cfg->name_template, "{ts}")) {
        LOGE("output.name_template musi obsahovat {seq} alebo {ts}, inak "
             "kazda snimka prepise tu predchadzajucu");
        bad++;
    }

    /* kombinacie, ktore technicky nedavaju zmysel */
    if (strcmp(cfg->writer, "delta") == 0) {
        if (!backend_is_random_access(cfg)) {
            LOGE("writer 'delta' potrebuje backend s nahodnym pristupom "
                 "(ebpf alebo file); backend '%s' vie iba vysypat cely obraz",
                 cfg->backend);
            bad++;
        }
        /* delitel overujeme az tu - pri delta_page_size = 0 by modulo
           zhodilo proces na SIGFPE este pred vypisom chyby */
        if (page_size_ok && (cfg->chunk_size % cfg->delta_page_size)) {
            LOGE("capture.chunk_size (%zu) musi byt nasobkom "
                 "output.delta_page_size (%u)",
                 cfg->chunk_size, cfg->delta_page_size);
            bad++;
        }
    }
    if (cfg->region_count && !backend_is_random_access(cfg)) {
        LOGE("capture.regions su podporovane iba pri backende s nahodnym "
             "pristupom (ebpf / file)");
        bad++;
    }
    if (cfg->post_compress == VMIC_COMPRESS_GZIP &&
        strcmp(cfg->writer, "delta") == 0) {
        LOGW("output.post_compress sa pri writeri 'delta' ignoruje "
             "(delta uz sama o sebe zapisuje iba zmeny)");
    }

    merge_regions(cfg);
    return bad ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Vypis                                                               */
/* ------------------------------------------------------------------ */

void vmic_config_dump(const vmic_config_t *cfg, void *stream)
{
    FILE *out = stream ? (FILE *)stream : stdout;
    const char *cur = "";

    fprintf(out, "# vmicollect %s - efektivna konfiguracia\n", VMIC_VERSION);
    if (cfg->source_path[0])
        fprintf(out, "# zdroj: %s\n", cfg->source_path);

    for (size_t i = 0; i < FIELD_COUNT; i++) {
        const field_t *f = &FIELDS[i];
        if (strcmp(cur, f->section) != 0) {
            cur = f->section;
            fprintf(out, "\n[%s]\n", cur);
        }
        const void *slot = (const char *)cfg + f->offset;

        switch (f->type) {
        case T_STR: case T_ENUM_STR:
            fprintf(out, "%-16s = %s\n", f->key, (const char *)slot);
            break;
        case T_ENUM_INT:
            fprintf(out, "%-16s = %s\n", f->key, f->choices[*(const int *)slot]);
            break;
        case T_BOOL:
            fprintf(out, "%-16s = %s\n", f->key, *(const bool *)slot ? "true" : "false");
            break;
        case T_DOUBLE:
            fprintf(out, "%-16s = %g\n", f->key, *(const double *)slot);
            break;
        case T_U64:
            fprintf(out, "%-16s = %" PRIu64 "\n", f->key, *(const uint64_t *)slot);
            break;
        case T_SIZE:
            fprintf(out, "%-16s = %zu\n", f->key, *(const size_t *)slot);
            break;
        case T_U32:
            fprintf(out, "%-16s = %u\n", f->key, *(const uint32_t *)slot);
            break;
        case T_LOGLEVEL:
            fprintf(out, "%-16s = %s\n", f->key,
                    vmic_log_level_name(*(const int *)slot));
            break;
        case T_REGIONS:
            fprintf(out, "%-16s = ", f->key);
            for (size_t r = 0; r < cfg->region_count; r++)
                fprintf(out, "%s0x%" PRIx64 ":0x%" PRIx64,
                        r ? ", " : "", cfg->regions[r].start, cfg->regions[r].size);
            fputc('\n', out);
            break;
        case T_HOOK:
            for (size_t h = 0; h < cfg->hook_count; h++)
                fprintf(out, "%-16s = %s%s%s\n", f->key, cfg->hook_path[h],
                        cfg->hook_args[h][0] ? ":" : "", cfg->hook_args[h]);
            if (!cfg->hook_count)
                fprintf(out, "# %-14s = (ziadny plugin)\n", f->key);
            break;
        }
    }
    fputc('\n', out);
}

/* Napoveda ku vsetkym klucom - pouziva ju main.c */
void vmic_config_help_keys(void *stream)
{
    FILE *out = stream ? (FILE *)stream : stdout;
    const char *cur = "";
    for (size_t i = 0; i < FIELD_COUNT; i++) {
        const field_t *f = &FIELDS[i];
        if (strcmp(cur, f->section) != 0) {
            cur = f->section;
            fprintf(out, "\n[%s]\n", cur);
        }
        char list[160] = "";
        if (f->choices) {
            char joined[128];
            choices_join(f->choices, joined, sizeof(joined));
            snprintf(list, sizeof(list), "  (%s)", joined);
        }
        fprintf(out, "  %-18s %s%s\n", f->key, f->help, list);
    }
}
