/*
 * example_hook.c - vzorovy plugin. TOTO JE MIESTO, KDE MODUL ROZSIRIS.
 *
 * Preklad:
 *      make hooks
 *   alebo rucne:
 *      gcc -O2 -fPIC -shared -Iinclude -o example_hook.so hooks/example_hook.c
 *
 * Zapnutie:
 *      [hooks]
 *      load = ./build/example_hook.so:./snapshots/index.csv
 *   alebo z prikazoveho riadku:
 *      -o hooks.load=./build/example_hook.so:/tmp/index.csv
 *
 * Co robi: po kazdej snimke pripise riadok do CSV. Nic uzitocnejsie
 * zamerne nerobi - ma byt co najkratsi, aby bolo hned vidiet, kde si
 * mas dopisat svoje (parsovanie struktur, extrakcia priznakov, ...).
 *
 * TRI PRAVIDLA PRE HOOK:
 *   1. Bezi SYNCHRONNE v hlavnej slucke. Ked bude trvat dlhsie ako
 *      perioda, zberac zacne zmeskavat sloty. Nieco narocne daj do
 *      fronty / iného vlakna.
 *   2. Bezi UZ PO odpauzovani VM. Nespomaluje teda hosta, len zberac.
 *   3. Vrat 0 pri uspechu. Nenulova hodnota znamena chybu - podla
 *      [hooks].strict sa bud vypne tento plugin, alebo skonci cely zber.
 */

#include "vmic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    FILE *csv;
    unsigned long seen;
} state_t;

/* Vola sa raz pri starte. `args` je to, co je v configu za dvojbodkou. */
int vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **state)
{
    if (api->abi != VMIC_HOOK_ABI) {
        /* zberac a plugin boli prelozene proti roznym verziam vmic.h */
        return 1;
    }

    state_t *st = calloc(1, sizeof(*st));
    if (!st) return 1;

    const char *path = (args && *args) ? args : "vmicollect-index.csv";
    st->csv = fopen(path, "ae");
    if (!st->csv) {
        api->log(VMIC_LOG_ERROR, "example_hook: nedaji sa otvorit '%s'", path);
        free(st);
        return 1;
    }
    /* hlavicku zapiseme len ak je subor prazdny */
    if (ftell(st->csv) == 0)
        fprintf(st->csv, "seq,timestamp_unix,path,bytes_on_disk,"
                         "pause_ms,capture_ms,total_ms,pages_changed,pages_total\n");

    api->log(VMIC_LOG_INFO, "example_hook: zapisujem index do '%s'", path);
    *state = st;
    return 0;
}

/* Vola sa po KAZDEJ hotovej snimke. */
int vmic_hook_snapshot(void *state, const vmic_snapshot_t *snap)
{
    state_t *st = (state_t *)state;
    st->seen++;

    fprintf(st->csv, "%llu,%lld.%03ld,%s,%llu,%.3f,%.3f,%.3f,%llu,%llu\n",
            (unsigned long long)snap->seq,
            (long long)snap->wall.tv_sec, snap->wall.tv_nsec / 1000000L,
            snap->path,
            (unsigned long long)snap->bytes_on_disk,
            snap->pause_ms, snap->capture_ms, snap->total_ms,
            (unsigned long long)snap->pages_changed,
            (unsigned long long)snap->pages_total);
    fflush(st->csv);

    /*
     * ------------------------------------------------------------------
     * SEM PATRI TVOJ KOD.
     *
     * K dispozicii mas:
     *   snap->path            cesta k hotovej snimke na disku
     *   snap->bytes_logical   kolko pamate pokryva
     *   snap->pages_changed   kolko stranok sa zmenilo od minula (delta)
     *   snap->vm->*           velkost RAM, pocet vCPU, strankovanie
     *   snap->stats.*         surove pocitadla citania
     *
     * Typicky dalsi krok: otvorit snap->path, prejst pamatove struktury
     * a vysledok poslat dalej (subor / socket / fronta).
     * ------------------------------------------------------------------
     */
    return 0;
}

/* Vola sa raz na konci. */
void vmic_hook_fini(void *state)
{
    state_t *st = (state_t *)state;
    if (!st) return;
    if (st->csv) fclose(st->csv);
    free(st);
}
