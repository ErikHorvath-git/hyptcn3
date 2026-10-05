/*
 * meta.c - JSON subor s metadatami vedla kazdej snimky (.json).
 *
 * Tento subor je rozhranie medzi zberom a vsetkym, co pride po nom.
 * Su v nom presne tie cisla, ktore potrebujes na vyhodnotenie vykonu
 * (pause_ms, capture_ms, priepustnost) aj na dalsie spracovanie
 * (cesta k datam, hash, ktore stranky sa zmenili).
 *
 * JSON si zapisujeme sami - je to par riadkov a modul tak nema dalsiu
 * zavislost.
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "util.h"
#include "log.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s && *s; s++) {
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
    fputc('"', f);
}

int vmic_meta_write(const vmic_snapshot_t *s, char *out_path, size_t n)
{
    const vmic_config_t *cfg = s->cfg;

    char path[VMIC_PATH_MAX];
    char name[VMIC_NAME_MAX + 16];
    snprintf(name, sizeof(name), "%s.json", s->id);
    if (vmic_join(path, sizeof(path), cfg->dir, name) != 0) return VMIC_ERR;

    FILE *f = fopen(path, "we");
    if (!f) {
        LOGE("meta: nedaji sa vytvorit '%s': %s", path, strerror(errno));
        return VMIC_ERR;
    }

    char iso[48];
    vmic_ts_iso(iso, sizeof(iso), &s->wall);

    char hex[VMIC_SHA256_BYTES * 2 + 1] = "";
    if (s->has_hash) vmic_hex(s->sha256, VMIC_SHA256_BYTES, hex);

    double mbps = (s->stats.read_seconds > 0.0)
        ? ((double)s->stats.bytes_read / (1024.0 * 1024.0)) / s->stats.read_seconds
        : 0.0;

    fprintf(f, "{\n");
    fprintf(f, "  \"schema\": \"vmicollect/1\",\n");
    fprintf(f, "  \"version\": \"%s\",\n", VMIC_VERSION);
    fprintf(f, "  \"seq\": %" PRIu64 ",\n", s->seq);
    fprintf(f, "  \"id\": ");        json_str(f, s->id);   fprintf(f, ",\n");
    fprintf(f, "  \"path\": ");      json_str(f, s->path); fprintf(f, ",\n");
    fprintf(f, "  \"timestamp\": "); json_str(f, iso);     fprintf(f, ",\n");
    fprintf(f, "  \"timestamp_unix\": %lld.%03ld,\n",
            (long long)s->wall.tv_sec, s->wall.tv_nsec / 1000000L);

    /* --- cielova VM --- */
    fprintf(f, "  \"vm\": {\n");
    fprintf(f, "    \"domain\": ");  json_str(f, s->vm->domain);  fprintf(f, ",\n");
    fprintf(f, "    \"backend\": "); json_str(f, s->vm->backend); fprintf(f, ",\n");
    if (s->vm->has_vmid)
        fprintf(f, "    \"vmid\": %" PRIu64 ",\n", s->vm->vmid);
    if (s->vm->has_memsize)
        fprintf(f, "    \"memsize\": %" PRIu64 ",\n", s->vm->memsize);
    if (s->vm->has_max_paddr)
        fprintf(f, "    \"max_paddr\": %" PRIu64 ",\n", s->vm->max_paddr);
    if (s->vm->has_vcpus)
        fprintf(f, "    \"num_vcpus\": %u,\n", s->vm->num_vcpus);
    fprintf(f, "    \"address_width\": %u,\n", s->vm->address_width);
    fprintf(f, "    \"page_mode\": "); json_str(f, s->vm->page_mode);
    fprintf(f, "\n  },\n");

    /* --- ako sa zbieralo (a co to stalo) --- */
    fprintf(f, "  \"capture\": {\n");
    fprintf(f, "    \"regions\": [");
    for (size_t i = 0; i < cfg->region_count; i++)
        fprintf(f, "%s{\"start\": %" PRIu64 ", \"size\": %" PRIu64 "}",
                i ? ", " : "", cfg->regions[i].start, cfg->regions[i].size);
    fprintf(f, "],\n");
    fprintf(f, "    \"chunk_size\": %zu,\n", cfg->chunk_size);
    /* to, co sa NAOZAJ stalo - backend bez pause() VM nezastavi, aj ked
       to config ziada */
    fprintf(f, "    \"paused\": %s,\n", s->paused ? "true" : "false");
    fprintf(f, "    \"pause_ms\": %.3f,\n", s->pause_ms);
    fprintf(f, "    \"pause_exceeded\": %s,\n", s->pause_exceeded ? "true" : "false");
    fprintf(f, "    \"capture_ms\": %.3f,\n", s->capture_ms);
    fprintf(f, "    \"write_ms\": %.3f,\n", s->write_ms);
    fprintf(f, "    \"total_ms\": %.3f\n", s->total_ms);
    fprintf(f, "  },\n");

    /* --- surove pocitadla --- */
    fprintf(f, "  \"stats\": {\n");
    fprintf(f, "    \"bytes_requested\": %" PRIu64 ",\n", s->stats.bytes_requested);
    fprintf(f, "    \"bytes_read\": %" PRIu64 ",\n", s->stats.bytes_read);
    fprintf(f, "    \"chunks\": %" PRIu64 ",\n", s->stats.chunks);
    fprintf(f, "    \"read_errors\": %" PRIu64 ",\n", s->stats.read_errors);
    fprintf(f, "    \"filled_zero\": %" PRIu64 ",\n", s->stats.filled_zero);
    fprintf(f, "    \"read_mib_s\": %.2f\n", mbps);
    fprintf(f, "  },\n");

    /* --- planovac (blok A8): meskanie tohto cyklu a zmeskane sloty
           PRED nim - tak ma dlhy beh evidenciu pri kazdej vzorke, nie len
           v zaverecnom logu --- */
    fprintf(f, "  \"sched\": {\"lateness_s\": %.6f, \"skipped_before\": "
               "%" PRIu64 "},\n",
            s->sched_lateness_s, s->sched_skipped_before);

    /* --- vysledok --- */
    fprintf(f, "  \"output\": {\n");
    fprintf(f, "    \"writer\": ");  json_str(f, cfg->writer); fprintf(f, ",\n");
    fprintf(f, "    \"full\": %s,\n", s->is_full ? "true" : "false");
    if (s->chain_id)
        fprintf(f, "    \"chain_id\": %" PRIu64 ",\n", s->chain_id);
    fprintf(f, "    \"bytes_logical\": %" PRIu64 ",\n", s->bytes_logical);
    fprintf(f, "    \"bytes_on_disk\": %" PRIu64 ",\n", s->bytes_on_disk);
    if (s->pages_total) {
        fprintf(f, "    \"pages_total\": %" PRIu64 ",\n", s->pages_total);
        fprintf(f, "    \"pages_changed\": %" PRIu64 ",\n", s->pages_changed);
        fprintf(f, "    \"page_size\": %u,\n", cfg->delta_page_size);
        fprintf(f, "    \"changed_ratio\": %.6f,\n",
                (double)s->pages_changed / (double)s->pages_total);
    }
    fprintf(f, "    \"sha256_covers_file\": %s,\n",
            s->hash_covers_file ? "true" : "false");
    fprintf(f, "    \"sha256\": "); json_str(f, hex);
    fprintf(f, "\n  }");

    /* --- per-bin priznakovy vektor ------------------------------- */
    /*
     * Blok je tu iba vtedy, ked vektor naozaj vznikol a presiel kontrolou
     * invariantu (pozri perbin.c). Jeho chybanie je teda informacia, nie
     * detail formatu - nikdy sa nedopisuje prazdny alebo nulovy vektor.
     *
     * `entropy_mean` sa vypisuje iba pri zapnutej entropii. Ked je
     * [features].entropy vypnuta, kluc v objekte binu NIE JE - nula by sa
     * nedala odlisit od naozaj nulovej entropie. To, ze sa bin nezmenil,
     * hovori `has_changed`; entropy_mean je vtedy 0 a je to definovane.
     */
    if (s->features && s->features->bins_total) {
        const vmic_features_t *ft = s->features;
        fprintf(f, ",\n  \"features\": {\n");
        fprintf(f, "    \"schema\": \"hyptcn3/perbin/1\",\n");
        fprintf(f, "    \"bin_bytes\": %" PRIu64 ",\n", ft->bin_bytes);
        fprintf(f, "    \"page_size\": %u,\n", ft->page_size);
        fprintf(f, "    \"entropy\": %s,\n", ft->entropy ? "true" : "false");
        fprintf(f, "    \"compute_ms\": %.3f,\n", ft->compute_ms);
        fprintf(f, "    \"bins_total\": %zu,\n", ft->bins_total);
        /* Oblasti, nad ktorymi biny vznikli. Bez nich sa z ulozenej snimky
           neda overit, ze bin nesiaha do diery vo fyzickom priestore.
           Nevolaju sa "memslots" zamerne: su to EFEKTIVNE oblasti zberu
           odvodene z memslotov, pricom susediace su zlucene - pri tejto VM
           10 memslotov dava 5 oblasti. Nazvat ich memslotmi by znamenalo
           tvrdit o sidecari nieco, co v nom nie je. */
        fprintf(f, "    \"regions\": [");
        for (size_t i = 0; i < ft->region_count; i++)
            fprintf(f, "%s{\"gpa\": %" PRIu64 ", \"bytes\": %" PRIu64 "}",
                    i ? ", " : "", ft->regions[i].start, ft->regions[i].size);
        fprintf(f, "],\n");
        fprintf(f, "    \"bins\": [\n");
        for (size_t i = 0; i < ft->bins_total; i++) {
            const vmic_bin_t *b = &ft->bins[i];
            double denom = (double)b->pages_total;
            fprintf(f, "      {\"bin\": %" PRIu64 ", \"gpa\": %" PRIu64
                       ", \"pages_total\": %" PRIu64
                       ", \"pages_changed\": %" PRIu64
                       ", \"changed_ratio\": %.6f, \"zero_ratio\": %.6f",
                    b->bin, b->gpa, b->pages_total, b->pages_changed,
                    denom > 0.0 ? (double)b->pages_changed / denom : 0.0,
                    denom > 0.0 ? (double)b->pages_zero / denom : 0.0);
            if (ft->entropy)
                fprintf(f, ", \"entropy_mean\": %.6f",
                        b->pages_changed
                            ? b->entropy_sum / (double)b->pages_changed : 0.0);
            fprintf(f, ", \"has_changed\": %d}%s\n",
                    b->pages_changed ? 1 : 0,
                    (i + 1 < ft->bins_total) ? "," : "");
        }
        fprintf(f, "    ]\n  }");
    }
    fprintf(f, "\n}\n");

    int err = ferror(f);
    if (fclose(f) != 0 || err) {
        LOGE("meta: zapis '%s' zlyhal", path);
        return VMIC_ERR;
    }
    if (out_path) snprintf(out_path, n, "%s", path);
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Alarm (blok A6): alarm.json = posledny, alarms.jsonl = historia     */
/* ------------------------------------------------------------------ */

/* Kompaktny jedno-riadkovy JSON objekt alarmu (bez konca riadku). */
static void alarm_fprint(FILE *f, const vmic_alarm_t *a)
{
    struct timespec ts = {
        (time_t)(a->ts_unix_ms / 1000ull),
        (long)(a->ts_unix_ms % 1000ull) * 1000000L,
    };
    char iso[48];
    vmic_ts_iso(iso, sizeof(iso), &ts);

    fprintf(f, "{\"schema\": \"hyptcn3/alarm/1\", ");
    fprintf(f, "\"timestamp\": "); json_str(f, iso);
    fprintf(f, ", \"timestamp_unix_ms\": %" PRIu64, a->ts_unix_ms);
    fprintf(f, ", \"seq\": %" PRIu64, a->seq);
    fprintf(f, ", \"chain_id\": %" PRIu64, a->chain_id);
    fprintf(f, ", \"zdroj\": "); json_str(f, a->zdroj);
    fprintf(f, ", \"score\": %.6g", a->score);
    fprintf(f, ", \"top_bins\": [");
    for (size_t i = 0; i < a->top_bins_n && i < VMIC_ALARM_TOPBINS; i++)
        fprintf(f, "%s%" PRIu64, i ? ", " : "", a->top_bins[i]);
    fprintf(f, "], \"invariants\": ");
    json_str(f, a->invariants);
    fprintf(f, "}");
}

int vmic_alarm_write(const char *dir, const vmic_alarm_t *a)
{
    char path[VMIC_PATH_MAX];

    /* posledny alarm - prehliadne ho clovek aj skript bez prehladavania */
    if (vmic_join(path, sizeof(path), dir, "alarm.json") != 0) return VMIC_ERR;
    FILE *f = fopen(path, "we");
    if (!f) {
        LOGE("alarm: nedaji sa vytvorit '%s': %s", path, strerror(errno));
        return VMIC_ERR;
    }
    alarm_fprint(f, a);
    fputc('\n', f);
    int err = ferror(f);
    if (fclose(f) != 0 || err) {
        LOGE("alarm: zapis '%s' zlyhal", path);
        return VMIC_ERR;
    }

    /* historia - kazdy alarm jeden riadok, append je atomicky dost na to,
       aby sa riadky nemiesali */
    if (vmic_join(path, sizeof(path), dir, "alarms.jsonl") != 0) return VMIC_ERR;
    f = fopen(path, "ae");
    if (!f) {
        LOGE("alarm: nedaji sa dopisat do '%s': %s", path, strerror(errno));
        return VMIC_ERR;
    }
    alarm_fprint(f, a);
    fputc('\n', f);
    err = ferror(f);
    if (fclose(f) != 0 || err) {
        LOGE("alarm: zapis '%s' zlyhal", path);
        return VMIC_ERR;
    }
    return VMIC_OK;
}
