/*
 * perbin.h - vnutorne rozhranie vypoctu per-bin priznakoveho vektora.
 *
 * PRECO SA NEVOLA features.h: Makefile preklada s -Isrc a glibc si v
 * <signal.h> vklada svoj vlastny <features.h>. Hlavicka s tym menom by
 * mu ho prekryla a preklad by spadol v kazdom .c subore. Meno `perbin`
 * navyse sedi so schemou sidecaru "hyptcn3/perbin/1".
 *
 * Verejne su iba datove struktury (vmic_bin_t, vmic_features_t v vmic.h),
 * lebo ich cita sidecar aj kazdy hook. Funkcie nizsie pouziva jedine
 * delta writer - odtial sa vektor plni, lebo tam uz kazda stranka svoj
 * hash aj rozhodnutie "zmenila sa" ma.
 *
 * Zivotny cyklus je rovnaky ako u writera:
 *
 *      begin(oblasti)  na zaciatku snimky   - postavi/obnovi mapu binov
 *      page(...)       pre kazdu stranku    - hotove miesto v poli
 *      finish(...)     na konci snimky      - kontrola invariantu
 *      release()       pri ruseni writera
 */
#ifndef VMIC_PERBIN_H
#define VMIC_PERBIN_H

#include "vmic.h"

/*
 * Pripravi vektor na novu snimku. `regions` musia byt TIE ISTE oblasti,
 * ktore dostane writer (teda efektivne zbierane useky - pri backende
 * 'ebpf' su to memsloty), a `region_sig` ich podpis: ked sa nezmenil,
 * mapa binov sa iba vynuluje a nestavia sa znovu.
 *
 * Vrati VMIC_OK / VMIC_ERR (zle parametre) / VMIC_FATAL (nedostatok pamate).
 */
int  vmic_features_begin(vmic_features_t *f, const vmic_config_t *cfg,
                         const vmic_region_t *regions, size_t region_count,
                         uint32_t page_size, uint64_t region_sig);

/* Jedna stranka na fyzickej adrese `paddr`. `changed` je rozhodnutie
   delta writera, nie nas odhad. */
void vmic_features_page(vmic_features_t *f, uint64_t paddr,
                        const uint8_t *page, bool changed);

/*
 * Uzavrie snimku a overi invariant proti pocitadlam writera:
 *   sucet pages_changed cez biny == pages_changed snimky
 *   sucet pages_total   cez biny == pocet podlozenych stranok
 * Pri nezhode vrati VMIC_ERR - vektor sa potom do sidecaru NEZAPISE,
 * lebo cislo, ktoremu sa neda verit, je horsie nez ziadne cislo.
 */
int  vmic_features_finish(vmic_features_t *f, uint64_t pages_total,
                          uint64_t pages_changed);

void vmic_features_release(vmic_features_t *f);

#endif /* VMIC_PERBIN_H */
