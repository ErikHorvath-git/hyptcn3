/* writer.c - register writerov */

#define _GNU_SOURCE
#include "vmic.h"
#include "internal.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const vmic_writer_ops_t *ops;
    int (*alloc)(vmic_writer_t *);
} entry_t;

static const entry_t REGISTRY[] = {
    { &vmic_writer_raw,   vmic_writer_raw_alloc   },
    { &vmic_writer_delta, vmic_writer_delta_alloc },
};
#define REGISTRY_COUNT (sizeof(REGISTRY) / sizeof(REGISTRY[0]))

const vmic_writer_ops_t *vmic_writer_find(const char *name)
{
    for (size_t i = 0; i < REGISTRY_COUNT; i++)
        if (strcmp(REGISTRY[i].ops->name, name) == 0)
            return REGISTRY[i].ops;
    return NULL;
}

int vmic_writer_create(vmic_writer_t *w, const vmic_config_t *cfg)
{
    memset(w, 0, sizeof(*w));
    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        if (strcmp(REGISTRY[i].ops->name, cfg->writer) != 0) continue;
        w->ops = REGISTRY[i].ops;
        w->cfg = cfg;
        if (REGISTRY[i].alloc(w) != VMIC_OK) {
            LOGE("writer '%s': nedostatok pamate", cfg->writer);
            return VMIC_FATAL;
        }
        return VMIC_OK;
    }
    LOGE("neznamy writer '%s'", cfg->writer);
    return VMIC_FATAL;
}

void vmic_writer_destroy(vmic_writer_t *w)
{
    if (!w || !w->ops) return;
    if (w->ops->destroy) w->ops->destroy(w);
    w->ops = NULL;
}
