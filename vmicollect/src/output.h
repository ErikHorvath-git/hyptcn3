/*
 * output.h - zapis snimok mimo vzorkovacieho cyklu (writer 'delta').
 *
 * Vzorkovacie vlakno (planovac -> cyklus) smie robit iba to, co nezavisi
 * od disku: citat pamat VM, porovnavat stranky, pocitat priznaky a kopirovat
 * zmenene stranky do vopred vyhradenej pamate. Vsetko ostatne - vytvorenie
 * suboru, zapis, fsync, rename, SHA-256, sidecar, hooky, retencia - robi
 * vlakno vmic-writer v poradi, v akom snimky vznikli.
 *
 * Zivotny cyklus jednej snimky:
 *
 *      job_new()     vzorkovac, zaciatok snimky (deskriptor z prealokacie)
 *      job_append()  vzorkovac, kazdy zmeneny zaznam (memcpy do poolu)
 *      job_submit()  vzorkovac, koniec cyklu (kopia metadat, fronta)
 *      ...           vmic-writer: subory, rename, sidecar, hooky, retencia
 *
 * Pool je jedna oblast pamate rozdelena na 1 MiB kusy. Ked kusy alebo
 * deskriptory dojdu, vzorkovac caka (cas ide do sidecaru ako queue_wait_ms)
 * - cyklus sa tym predlzi a audit to uvidi. Zamlcane zahodenie neexistuje.
 * Kazde cakanie kontroluje priznak `stop`, takze signal ho ukonci.
 */
#ifndef VMIC_OUTPUT_H
#define VMIC_OUTPUT_H

#include "vmic.h"

typedef struct vmic_output vmic_output_t;
typedef struct vmic_job    vmic_job_t;

#define VMIC_OUTPUT_OPS 7   /* vytvorenie zapis fsync sidecar rename hook retencia */

typedef struct {
    uint64_t submitted;        /* snimky odovzdane vzorkovacom            */
    uint64_t published;        /* zverejnene cele (data aj sidecar)        */
    uint64_t published_bytes;  /* ich bytes_on_disk                        */
    uint64_t failed;           /* zlyhal zapis dat alebo sidecaru          */
    uint64_t dropped;          /* zahodene: zavisia od zlyhanej snimky     */
    uint64_t abandoned;        /* nezapisane, lebo dobehnutie vyprsalo     */
    uint64_t max_queue_bytes;  /* najvacsi backlog pri zaradeni snimky     */
    uint64_t max_queue_jobs;
    double   max_publish_ms;   /* najdlhsie od zaciatku cyklu po rename sidecaru */
    double   wait_ms;          /* vzorkovac cakal na volnu pamat (sucet)   */
    uint64_t wait_cycles;      /* v kolkych cykloch cakal                  */
    uint64_t pool_bytes;
    double   op_max_s[VMIC_OUTPUT_OPS];  /* najdlhsia operacia zapisovaca */
} vmic_output_stats_t;

/* Mena operacii v poradi op_max_s. */
const char *vmic_output_op_name(int op);

/* Velkost poolu: [output].queue_mib, alebo pri 0 najvacsia mozna plna
   snimka danych oblasti (vsetky stranky) + 512 MiB na delty. */
uint64_t vmic_output_pool_bytes(const vmic_config_t *cfg,
                                const vmic_region_t *regions, size_t region_count);
/* Kapacita kopie per-bin vektora v kazdom deskriptore (0 = bez vektora). */
size_t   vmic_output_max_bins(const vmic_config_t *cfg,
                              const vmic_region_t *regions, size_t region_count);
/* Pamat deskriptorov fronty (okrem poolu) pre dany pocet binov. */
uint64_t vmic_output_overhead_bytes(size_t max_bins);

int  vmic_output_create(vmic_output_t **out, const vmic_config_t *cfg, vmic_hooks_t *hooks,
                        uint64_t pool_bytes, size_t max_bins, volatile sig_atomic_t *stop);
/* Ukonci vlakno (po dobehnuti fronty). Po vyprsanom drain() nerobi nic:
   zapisovac moze stat v nedokoncenom syscalle a proces aj tak konci. */
void vmic_output_destroy(vmic_output_t *o);

/* --- vzorkovacie vlakno ------------------------------------------- */
/* VMIC_OK / VMIC_STOP (signal pocas cakania na deskriptor). */
int  vmic_output_job_new(vmic_output_t *o, vmic_job_t **out);
/* Skopiruje bajty na koniec snimky. VMIC_STOP = signal pocas cakania na
   pamat; VMIC_ERR = snimka sa nezmesti do celeho poolu - cyklus zlyha,
   nic sa nezablokuje. */
int  vmic_output_job_append(vmic_output_t *o, vmic_job_t *j, const void *data, size_t len);
void vmic_output_job_free(vmic_output_t *o, vmic_job_t *j);
/* Zaradi snimku. `s` sa skopiruje (vm, oblasti, priznaky), `hdr` je hotova
   hlavicka suboru, `staging` docasne meno, `t_start` monotonny zaciatok
   cyklu. Po uspechu snimku vlastni zapisovac a vzorkovac sa jej nedotkne. */
int  vmic_output_job_submit(vmic_output_t *o, vmic_job_t *j, const vmic_snapshot_t *s,
                            const uint8_t *hdr, size_t hdr_len, const char *staging,
                            double t_start);
/* Cas, ktory vzorkovac pri tejto snimke cakal na pamat alebo deskriptor. */
double vmic_output_job_wait_ms(const vmic_job_t *j);
/* Zlyhal zapis snimky z retazca `chain_id`? Dalsia snimka potom musi byt plna. */
bool vmic_output_chain_broken(vmic_output_t *o, uint64_t chain_id);
/* Hook v striktnom rezime zlyhal - zber treba ukoncit (kod 3). */
bool vmic_output_fatal(vmic_output_t *o);
/* Strazca: varuje (WARN, najviac raz za minutu), ked jedna operacia
   zapisovaca alebo cakanie najstarsej snimky vo fronte trva dlhsie ako 30 s.
   Iba citanie stavu pod mutexom - ziadny systemovy zapis. */
void vmic_output_watch(vmic_output_t *o);

/* Pocka na zapis vsetkeho vo fronte, najviac `budget_s` sekund (0 = bez
   limitu); signal pocas cakania skrati zvysok na 40 s. Vrati pocet snimok,
   ktore sa nezverejnili cele (zlyhane, zahodene, a po vyprsani aj
   nezapisane). `abandoned` = zapisovac zostal stat v jednom syscalle. */
uint64_t vmic_output_drain(vmic_output_t *o, double budget_s, bool *abandoned);
void     vmic_output_get_stats(vmic_output_t *o, vmic_output_stats_t *st);

#endif /* VMIC_OUTPUT_H */
