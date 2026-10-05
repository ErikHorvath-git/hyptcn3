/*
 * alarm_hook.c - priklad detektora, ktory vyhlasi alarm (blok A6).
 *
 * NIE JE TO DETEKCIA ANOMALIE. Je to priklad, ktory ukazuje kontrakt:
 * plugin pocita nad kazdou snimkou (tu: pocet zmenenych stranok), a ked
 * prekroci prah, zavola api->alarm(). Zberac alarm zapise do alarm.json
 * a alarms.jsonl, oznac retazec markerom HOLD a posle ho kazdemu pluginu,
 * ktory exportuje vmic_hook_alarm().
 *
 * Argumenty: <csv_cesta>[,<prah_pages_changed>]
 *   csv_cesta            sem sa dopisuje kazdy PRIJATY alarm (riadok na
 *                        alarm; prijme aj alarmy inych pluginov)
 *   prah_pages_changed   nad tuto hodnotu snimka vyhlasi alarm
 *                        (vychodzie 0 = prva snimka so zmenou)
 *
 * Preklad:  make hooks   (vznikne build/alarm_hook.so)
 * Pouzitie: sudo vmicollect run -o output.writer=delta \
 *               -o hooks.load=./build/alarm_hook.so:/tmp/alarms.csv,100
 */

#define _GNU_SOURCE
#include "vmic.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    const vmic_hook_api_t *api;
    FILE  *csv;
    uint64_t threshold;             /* nad tento pocet zmenenych stranok */
} state_t;

int vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **st)
{
    state_t *s = calloc(1, sizeof(*s));
    if (!s) return 1;
    s->api = api;

    char buf[VMIC_PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", args);
    char *comma = strchr(buf, ',');
    if (comma) {
        *comma = '\0';
        s->threshold = (uint64_t)strtoull(comma + 1, NULL, 0);
    }

    s->csv = fopen(buf, "ae");
    if (!s->csv) {
        api->log(2, "alarm_hook: %s: %s", buf, "nepodarilo sa otvorit");
        free(s);
        return 1;
    }
    long pos = ftell(s->csv);
    if (pos == 0)
        fprintf(s->csv, "ts_unix_ms,seq,chain_id,score,top_bins_n\n");
    fflush(s->csv);

    *st = s;
    return 0;
}

/* top biny podla pages_changed (najviac zmenene biny na prvych miestach).
 * Snapshot ma biny uz zratane (perbin.c), tu sa len vyberu najvacsie. */
static void top_bins(const vmic_snapshot_t *snap, vmic_alarm_t *a)
{
    const vmic_features_t *f = snap->features;
    if (!f || !f->bins) return;

    uint64_t bins[VMIC_ALARM_TOPBINS];
    uint64_t vals[VMIC_ALARM_TOPBINS];
    size_t n = 0;

    for (size_t i = 0; i < f->bins_total; i++) {
        uint64_t v = f->bins[i].pages_changed;
        if (!v) continue;

        size_t j = n;
        while (j > 0 && vals[j - 1] < v) j--;
        if (j < VMIC_ALARM_TOPBINS) {
            for (size_t k = n > VMIC_ALARM_TOPBINS - 1
                                ? VMIC_ALARM_TOPBINS - 1 : n; k > j; k--) {
                bins[k] = bins[k - 1];
                vals[k] = vals[k - 1];
            }
            bins[j] = f->bins[i].bin;
            vals[j] = v;
            if (n < VMIC_ALARM_TOPBINS) n++;
        }
    }
    for (size_t i = 0; i < n; i++) a->top_bins[i] = bins[i];
    a->top_bins_n = n;
}

int vmic_hook_snapshot(void *st, const vmic_snapshot_t *snap)
{
    state_t *s = (state_t *)st;
    if (snap->pages_changed <= s->threshold) return 0;

    vmic_alarm_t a;
    memset(&a, 0, sizeof(a));
    a.chain_id = snap->chain_id;
    a.seq      = snap->seq;
    snprintf(a.zdroj, sizeof(a.zdroj), "example:pages_changed");
    a.score = (double)snap->pages_changed;
    snprintf(a.invariants, sizeof(a.invariants), "n/a (prikladovy detektor)");
    top_bins(snap, &a);

    /* vrat hodnotu z api->alarm: v striktnom rezime moze znamenat koniec */
    return s->api->alarm(s->api, &a);
}

int vmic_hook_alarm(void *st, const vmic_alarm_t *a)
{
    state_t *s = (state_t *)st;
    fprintf(s->csv, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6g,%zu\n",
            a->ts_unix_ms, a->seq, a->chain_id, a->score, a->top_bins_n);
    fflush(s->csv);
    return 0;
}

void vmic_hook_fini(void *st)
{
    state_t *s = (state_t *)st;
    if (s->csv) fclose(s->csv);
    free(s);
}
