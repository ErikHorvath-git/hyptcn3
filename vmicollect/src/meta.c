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
    fprintf(f, "\n  }\n}\n");

    int err = ferror(f);
    if (fclose(f) != 0 || err) {
        LOGE("meta: zapis '%s' zlyhal", path);
        return VMIC_ERR;
    }
    if (out_path) snprintf(out_path, n, "%s", path);
    return VMIC_OK;
}
