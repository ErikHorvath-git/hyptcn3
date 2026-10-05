/*
 * collector.c - spaja vsetky styri vrstvy do jedneho cyklu.
 *
 * Cely modul sa da precitat odtialto: init() pripoji backend, zisti
 * parametre VM a pripravi oblasti; cycle() spravi jednu snimku.
 *
 * PORADIE OPERACII V CYKLE JE NAVRHNUTE TAK, ABY BOLA PAUZA VM CO
 * NAJKRATSIA. Vsetko, co sa da spravit pred pauzou (vytvorenie suboru,
 * zostavenie nazvu) alebo po nej (hash na disku, gzip, metadata, hooky,
 * retencia), sa robi mimo pauzy. Vnutri pauzy je IBA citanie pamate
 * a zapis blokov.
 *
 *      begin_cycle()-> mimo pauzy (co vlastne zbierame)
 *      begin()      -> mimo pauzy
 *      pause()      -+
 *      capture()     |  <-- iba toto stoji VM cas
 *      resume()     -+
 *      finish()     -> mimo pauzy (gzip, fsync, rename)
 *      meta + hooks -> mimo pauzy
 *      retention    -> mimo pauzy
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Priprava oblasti na citanie                                         */
/* ------------------------------------------------------------------ */

static int prepare_regions(vmic_collector_t *c)
{
    const vmic_config_t *cfg = c->cfg;
    uint64_t limit = vmic_vminfo_addressable(&c->vm);

    if (cfg->region_count == 0 && c->vm.ram_count) {
        /*
         * Backend vie presne, ktore useky fyzickeho priestoru su
         * namapovane (ebpf ich ma z memslotov). Zbierame teda iba ich a
         * diery medzi nimi vobec nenavstivime: neplytva sa casom na
         * citanie nul, delta ich nezapocita do pages_total a chyby
         * citania zostanu naozaj chybami.
         */
        c->region_count = 0;
        for (size_t i = 0; i < c->vm.ram_count && i < VMIC_MAX_REGIONS; i++)
            c->regions[c->region_count++] = c->vm.ram[i];
    } else if (cfg->region_count == 0) {
        /* backend to nevie -> cela fyzicka pamat aj s dierami */
        if (!limit) {
            LOGE("backend nevie zistit velkost pamate - zadaj rozsah rucne "
                 "cez [capture].regions (napr. 0x0:2GiB)");
            return VMIC_FATAL;
        }
        c->regions[0].start = 0;
        c->regions[0].size  = limit;
        c->region_count     = 1;
    } else {
        c->region_count = 0;
        for (size_t i = 0; i < cfg->region_count; i++) {
            uint64_t start = cfg->regions[i].start;
            uint64_t size  = cfg->regions[i].size;

            if (limit) {
                if (start >= limit) {
                    LOGW("oblast 0x%" PRIx64 "+0x%" PRIx64 " je nad koncom "
                         "pamate (0x%" PRIx64 ") - preskakujem",
                         start, size, limit);
                    continue;
                }
                if (start + size > limit) size = limit - start;
            }
            c->regions[c->region_count].start = start;
            c->regions[c->region_count].size  = size;
            c->region_count++;
        }
        if (!c->region_count) {
            LOGE("po orezani na velkost pamate nezostala ziadna oblast");
            return VMIC_FATAL;
        }
    }

    /*
     * Delta writer porovnava cele stranky, takze musi dostavat bloky
     * zarovnane na velkost stranky. Zarovnavame tu (a nie v writeri),
     * lebo tu este vieme opravit aj zaciatok oblasti.
     */
    if (strcmp(cfg->writer, "delta") == 0) {
        uint64_t ps = cfg->delta_page_size;
        for (size_t i = 0; i < c->region_count; i++) {
            uint64_t start = c->regions[i].start & ~(ps - 1);
            uint64_t end   = c->regions[i].start + c->regions[i].size;
            end = (end + ps - 1) & ~(ps - 1);
            c->regions[i].start = start;
            c->regions[i].size  = end - start;
        }
    }

    uint64_t total = 0;
    for (size_t i = 0; i < c->region_count; i++) total += c->regions[i].size;

    char human[32];
    vmic_human_size(total, human, sizeof(human));
    LOGI("zbierane oblasti: %zu, spolu %s", c->region_count, human);
    for (size_t i = 0; i < c->region_count; i++)
        LOGD("  [%zu] 0x%" PRIx64 " + 0x%" PRIx64,
             i, c->regions[i].start, c->regions[i].size);
    return VMIC_OK;
}

/*
 * Znovu sa spytat backendu, ako VM vyzera, a ked sa nieco zmenilo,
 * prisposobit tomu zbierane oblasti.
 *
 * Bez tohto by boli parametre VM zmrazene z inicializacie: po hotplugu
 * pamate by sa nova pamat nikdy nezbierala a po restarte domeny (backend
 * sa vie pripojit na novy pid) by kazda snimka niesla v metadatach stare
 * meno, stary pid aj starú velkost RAM.
 */
static int refresh_vm(vmic_collector_t *c)
{
    vmic_vminfo_t fresh;

    if (c->backend.ops->probe(&c->backend, &fresh) != VMIC_OK)
        return VMIC_ERR;
    if (memcmp(&fresh, &c->vm, sizeof(fresh)) == 0)
        return VMIC_OK;

    char human[32] = "?";
    if (fresh.has_memsize) vmic_human_size(fresh.memsize, human, sizeof(human));
    LOGW("parametre VM sa zmenili: '%s' [%s], RAM %s, max_paddr 0x%" PRIx64
         " - prepocitavam zbierane oblasti",
         fresh.domain, fresh.backend, human, fresh.max_paddr);

    c->vm = fresh;
    return prepare_regions(c);
}

/* ------------------------------------------------------------------ */
/* Inicializacia                                                       */
/* ------------------------------------------------------------------ */

int vmic_collector_init(vmic_collector_t *c, const vmic_config_t *cfg,
                        volatile sig_atomic_t *stop)
{
    memset(c, 0, sizeof(*c));
    c->cfg  = cfg;
    c->stop = stop;

    if (vmic_mkdir_p(cfg->dir) != 0) {
        LOGE("nedaji sa vytvorit vystupny adresar '%s'", cfg->dir);
        return VMIC_FATAL;
    }

    int rc = vmic_backend_create(&c->backend, cfg);
    if (rc != VMIC_OK) return rc;
    c->backend.stop = stop;

    rc = c->backend.ops->open(&c->backend);
    if (rc != VMIC_OK) { vmic_backend_destroy(&c->backend); return rc; }

    rc = c->backend.ops->probe(&c->backend, &c->vm);
    if (rc != VMIC_OK) {
        LOGE("nepodarilo sa zistit parametre VM");
        vmic_backend_destroy(&c->backend);
        return VMIC_FATAL;
    }

    char human[32] = "?";
    if (c->vm.has_memsize) vmic_human_size(c->vm.memsize, human, sizeof(human));
    LOGI("VM '%s' [%s]: RAM %s, max_paddr 0x%" PRIx64 ", vCPU %u, strankovanie %s",
         c->vm.domain, c->vm.backend, human, c->vm.max_paddr,
         c->vm.num_vcpus, c->vm.page_mode);

    rc = prepare_regions(c);
    if (rc != VMIC_OK) { vmic_backend_destroy(&c->backend); return rc; }

    /* kombinacie sa validuju uz v configu, ale backend mohol byt
       vybraty inak (napr. cez -o), tak radsej este raz */
    if (!c->backend.ops->random_access && c->writer.ops == NULL &&
        strcmp(cfg->writer, "delta") == 0) {
        LOGE("writer 'delta' sa neda pouzit s backendom '%s'", cfg->backend);
        vmic_backend_destroy(&c->backend);
        return VMIC_FATAL;
    }

    rc = vmic_writer_create(&c->writer, cfg);
    if (rc != VMIC_OK) { vmic_backend_destroy(&c->backend); return rc; }

    c->hooks = vmic_hooks_load(cfg);
    if (!c->hooks && cfg->hook_count && cfg->hooks_strict) {
        vmic_writer_destroy(&c->writer);
        vmic_backend_destroy(&c->backend);
        return VMIC_FATAL;
    }
    return VMIC_OK;
}

void vmic_collector_fini(vmic_collector_t *c)
{
    if (!c) return;
    vmic_hooks_unload(c->hooks);
    c->hooks = NULL;
    vmic_writer_destroy(&c->writer);
    vmic_backend_destroy(&c->backend);
}

/* ------------------------------------------------------------------ */
/* Jeden cyklus                                                        */
/* ------------------------------------------------------------------ */

int vmic_collector_cycle(vmic_collector_t *c, vmic_snapshot_t *out)
{
    const vmic_config_t *cfg = c->cfg;

    vmic_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.seq = c->seq;
    snap.sched_lateness_s   = c->sched_lateness_s;
    snap.sched_skipped_before = c->sched_skipped_before;
    snap.vm  = &c->vm;
    snap.cfg = cfg;
    vmic_now_real(&snap.wall);

    double t_total0 = vmic_now_mono();

    /* --- nazov suboru (mimo pauzy) -------------------------------- */
    char ts[40];
    vmic_ts_compact(ts, sizeof(ts), &snap.wall);
    snprintf(snap.ext, sizeof(snap.ext), "%s", vmic_backend_ext(&c->backend));

    if (vmic_render_name(snap.id, sizeof(snap.id), cfg->name_template,
                         c->vm.domain, snap.seq, ts,
                         c->backend.ops->name) != 0) {
        LOGE("nepodarilo sa zostavit nazov podla sablony '%s'",
             cfg->name_template);
        return VMIC_FATAL;
    }
    vmic_sanitize(snap.id);

    /* --- co vlastne ideme zbierat (mimo pauzy) -------------------- */
    /*
     * Backendu najprv povieme "zacina novy cyklus, over si, co vies":
     * 'ebpf' si tu znovu vypyta memsloty od jadra, lebo VM mohla medzitym
     * dostat pamat navyse, presunut BAR zariadenia, alebo zhasnut a
     * nabehnut pod novym pid. Bez toho by sa citalo podla neplatnej mapy
     * GPA -> HVA, teda z cudzej pamate procesu VMM.
     *
     * PORADIE JE DOLEZITE: musi to byt PRED writer.ops->begin(), pretoze
     * delta writer si prave tam podla zbieranych oblasti rozhoduje, ci
     * moze pokracovat v retazci, alebo musi zacat novou plnou snimkou.
     * Keby sa oblasti prepocitali az potom, prva snimka po zmene mapy
     * pamate by sa zapisala ako delta proti hashom ineho rozsahu.
     */
    if (c->backend.ops->begin_cycle &&
        c->backend.ops->begin_cycle(&c->backend) != VMIC_OK) {
        LOGW("backend nevedel pripravit novy cyklus - data mozu byt zastarale");
    }
    if (refresh_vm(c) != VMIC_OK) {
        LOGW("parametre VM sa nedali overit - zbieram podla poslednych znamych");
    }
    snap.regions      = c->regions;
    snap.region_count = c->region_count;

    /* --- priprava suboru (mimo pauzy) ----------------------------- */
    int rc = c->writer.ops->begin(&c->writer, &snap);
    if (rc != VMIC_OK) return rc;

    /* --- PAUZA -> CITANIE -> BEH ---------------------------------- */
    /*
     * Merat pauzu ma zmysel iba vtedy, ked ju backend naozaj vie. Bez
     * ops->pause() by sa ako "cas, ked VM stala" vykazal cely cas
     * citania - v metadatach by to bola vymyslenina a pause_exceeded by
     * planiho poplachu robilo kazdy cyklus. (Hromadne backendy si pauzu
     * riadia samy vo svojom nastroji, preto tiez nie.)
     */
    bool do_pause = cfg->pause && c->backend.ops->random_access &&
                    c->backend.ops->pause;
    double t_pause0 = 0.0;

    if (cfg->pause && !do_pause && c->seq == 0)
        LOGW("capture.pause je zapnute, ale backend '%s' VM zastavit nevie "
             "- snimka bude 'ziva' (stranky su z roznych okamihov)",
             c->backend.ops->name);

    if (do_pause) {
        t_pause0 = vmic_now_mono();
        if (vmic_backend_pause(&c->backend) != VMIC_OK) {
            LOGW("VM sa nepodarilo pozastavit - snimka bude 'rozmazana' "
                 "(pamat sa meni pocas citania)");
        }
    }

    rc = vmic_capture(&c->backend, &c->writer,
                      c->regions, c->region_count, &snap.stats, c->stop);

    if (do_pause) {
        /* rozbehnut VM MUSIME aj ked citanie zlyhalo */
        if (vmic_backend_resume(&c->backend) != VMIC_OK)
            LOGE("VM sa nepodarilo rozbehnut! skontroluj ju rucne "
                 "(virsh resume '%s')", cfg->domain);
        snap.paused   = true;
        snap.pause_ms = (vmic_now_mono() - t_pause0) * 1000.0;
        snap.pause_exceeded = (cfg->pause_max_ms > 0.0 &&
                               snap.pause_ms > cfg->pause_max_ms);
        if (snap.pause_exceeded)
            LOGW("pauza VM trvala %.1f ms (limit %.1f ms) - zvaz mensie "
                 "oblasti, vacsi chunk_size alebo capture.pause = false",
                 snap.pause_ms, cfg->pause_max_ms);
    }
    snap.capture_ms = snap.stats.read_seconds * 1000.0;

    if (rc != VMIC_OK) {
        c->writer.ops->abort(&c->writer);
        return rc;
    }

    /* --- dokoncenie zapisu (mimo pauzy) --------------------------- */
    double t_write0 = vmic_now_mono();
    rc = c->writer.ops->finish(&c->writer, &snap);
    snap.write_ms = (vmic_now_mono() - t_write0) * 1000.0;
    if (rc != VMIC_OK) {
        /* Invariant: kazdy zacaty snimok sa musi bud dokoncit, alebo
           zrusit. Bez abort() by po neuspesnom finish() zostal writer v
           rozpracovanom stave (a delta by mala "posunute" hashe). */
        c->writer.ops->abort(&c->writer);
        return rc;
    }

    snap.total_ms = (vmic_now_mono() - t_total0) * 1000.0;
    c->seq++;
    c->total_bytes += snap.bytes_on_disk;

    /* --- metadata ------------------------------------------------- */
    if (cfg->sidecar)
        vmic_meta_write(&snap, snap.sidecar_path, sizeof(snap.sidecar_path));

    /* --- zhrnutie do logu ----------------------------------------- */
    char disk[32], logical[32];
    vmic_human_size(snap.bytes_on_disk, disk, sizeof(disk));
    vmic_human_size(snap.bytes_logical, logical, sizeof(logical));

    if (snap.pages_total) {
        LOGI("#%" PRIu64 " %s  %s/%s  stranky %" PRIu64 "/%" PRIu64
             " (%.2f %%)  pauza %.1f ms  citanie %.1f ms  spolu %.1f ms",
             snap.seq, snap.is_full ? "PLNA " : "delta",
             disk, logical, snap.pages_changed, snap.pages_total,
             100.0 * (double)snap.pages_changed / (double)snap.pages_total,
             snap.pause_ms, snap.capture_ms, snap.total_ms);
    } else {
        double mbps = snap.stats.read_seconds > 0.0
            ? ((double)snap.stats.bytes_read / (1024.0 * 1024.0)) / snap.stats.read_seconds
            : 0.0;
        LOGI("#%" PRIu64 "  %s (%s na disku)  pauza %.1f ms  citanie %.1f ms"
             "  %.0f MiB/s  spolu %.1f ms",
             snap.seq, logical, disk, snap.pause_ms, snap.capture_ms,
             mbps, snap.total_ms);
    }
    if (snap.stats.read_errors)
        LOGD("  nenamapovanych blokov: %" PRIu64 " (%" PRIu64 " B vyplnenych nulami)",
             snap.stats.read_errors, snap.stats.filled_zero);

    /* --- pouzivatelske rozsirenia --------------------------------- */
    rc = vmic_hooks_fire(c->hooks, &snap);
    if (rc != VMIC_OK) return rc;

    /* --- upratovanie ---------------------------------------------- */
    /* aktivny retazec chranime podla ID, nie podla casu suboru */
    vmic_retention_apply(cfg, snap.chain_id);

    if (out) *out = snap;
    return VMIC_OK;
}
