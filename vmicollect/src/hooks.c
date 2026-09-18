/*
 * hooks.c - MIESTO, KDE MODUL ROZSIRUJES.
 *
 * Po kazdej hotovej snimke sa zavolaju vsetky nacitane pluginy. Plugin je
 * obycajne zdielana kniznica (.so), ktoru si prelozis sam a zavesis cez
 * konfiguraciu:
 *
 *     [hooks]
 *     load = ./hooks/example_hook.so:argumenty
 *
 * Plugin musi exportovat tri funkcie (pozri hooks/example_hook.c):
 *
 *     int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **st);
 *     int  vmic_hook_snapshot(void *st, const vmic_snapshot_t *snap);
 *     void vmic_hook_fini(void *st);
 *
 * Preco dlopen a nie proste callback v kode? Lebo takto mozes menit
 * spracovanie snimok bez toho, aby si prekladal (a znovu spustal) zberac.
 * Presne sem neskor zavesis parsovanie struktur a extrakciu priznakov.
 *
 * POZOR NA CAS: hook bezi SYNCHRONNE v hlavnej slucke, uz po odpauzovani
 * VM, ale este pred dalsim cyklom. Ked bude trvat dlhsie ako perioda,
 * zberac zacne zmeskavat sloty. Nieco narocne (ML inferencia) preto
 * radsej zapis do fronty a spracuj mimo.
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void                  *handle;
    vmic_hook_snapshot_fn  on_snapshot;
    vmic_hook_fini_fn      fini;
    void                  *state;
    char                   path[VMIC_PATH_MAX];
    bool                   disabled;   /* po chybe v non-strict rezime */
} loaded_t;

struct vmic_hooks {
    loaded_t        item[VMIC_MAX_HOOKS];
    size_t          count;
    bool            strict;
    vmic_hook_api_t api;
};

/* logovacia sluzba, ktoru dostane plugin */
static void hook_log(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vmic_logv(level, fmt, ap);
    va_end(ap);
}

vmic_hooks_t *vmic_hooks_load(const vmic_config_t *cfg)
{
    if (!cfg->hook_count) return NULL;

    vmic_hooks_t *h = calloc(1, sizeof(*h));
    if (!h) {
        LOGE("hooks: nedostatok pamate");
        return NULL;
    }
    h->strict   = cfg->hooks_strict;
    h->api.abi  = VMIC_HOOK_ABI;
    h->api.cfg  = cfg;
    h->api.log  = hook_log;

    for (size_t i = 0; i < cfg->hook_count; i++) {
        const char *path = cfg->hook_path[i];
        const char *args = cfg->hook_args[i];

        /* RTLD_NOW: chceme vediet o chybajucich symboloch HNED, nie az
           uprostred zberu. RTLD_LOCAL: plugin nezanesie svoje symboly
           do globalneho priestoru. */
        void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!lib) {
            LOGE("hooks: nedaji sa nacitat '%s': %s", path, dlerror());
            if (h->strict) goto fail;
            continue;
        }

        dlerror();   /* vycistit stary chybovy stav */
        vmic_hook_init_fn     init = (vmic_hook_init_fn)    dlsym(lib, "vmic_hook_init");
        vmic_hook_snapshot_fn snap = (vmic_hook_snapshot_fn)dlsym(lib, "vmic_hook_snapshot");
        vmic_hook_fini_fn     fini = (vmic_hook_fini_fn)    dlsym(lib, "vmic_hook_fini");

        if (!snap) {
            LOGE("hooks: '%s' neexportuje vmic_hook_snapshot()", path);
            dlclose(lib);
            if (h->strict) goto fail;
            continue;
        }

        loaded_t *slot = &h->item[h->count];
        memset(slot, 0, sizeof(*slot));
        slot->handle      = lib;
        slot->on_snapshot = snap;
        slot->fini        = fini;
        snprintf(slot->path, sizeof(slot->path), "%s", path);

        if (init && init(&h->api, args, &slot->state) != 0) {
            LOGE("hooks: vmic_hook_init() v '%s' zlyhal", path);
            dlclose(lib);
            if (h->strict) goto fail;
            continue;
        }
        h->count++;
        LOGI("hooks: nacitany '%s'%s%s", path, args[0] ? " s argumentmi: " : "", args);
    }
    return h;

fail:
    vmic_hooks_unload(h);
    return NULL;
}

int vmic_hooks_fire(vmic_hooks_t *h, const vmic_snapshot_t *snap)
{
    if (!h) return VMIC_OK;

    for (size_t i = 0; i < h->count; i++) {
        loaded_t *it = &h->item[i];
        if (it->disabled) continue;

        int rc = it->on_snapshot(it->state, snap);
        if (rc == 0) continue;

        if (h->strict) {
            LOGE("hooks: '%s' vratil %d - koncim (hooks.strict = true)",
                 it->path, rc);
            return VMIC_FATAL;
        }
        /*
         * Nestriktny rezim: chybny plugin nesmie zhodit zber. Vypneme ho
         * a ideme dalej - inak by ti jeden pokazeny hook zabil aj tie
         * data, ktore uz zbierat ide.
         */
        LOGW("hooks: '%s' vratil %d - vypinam ho do konca behu", it->path, rc);
        it->disabled = true;
    }
    return VMIC_OK;
}

void vmic_hooks_unload(vmic_hooks_t *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->count; i++) {
        if (h->item[i].fini) h->item[i].fini(h->item[i].state);
        if (h->item[i].handle) dlclose(h->item[i].handle);
    }
    free(h);
}
