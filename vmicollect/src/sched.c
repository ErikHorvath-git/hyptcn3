/*
 * sched.c - periodicky planovac.
 *
 * Naivne riesenie "spracuj a potom sleep(interval)" ma dve chyby:
 *
 *   1) DRIFT. Kazdy cyklus sa perioda predlzi o cas spracovania. Po
 *      hodine ti casova rada nesedi a analyza sekvencii je nezmyselna.
 *   2) NEPRERUSITELNOST. Ctrl-C sa prejavi az po dospani celej periody.
 *
 * Riesenie: pocitame ABSOLUTNE terminy na monotonnych hodinach a spime
 * do nich cez clock_nanosleep(TIMER_ABSTIME). Chyba sa nekumuluje a
 * signal spanok okamzite preruSI.
 *
 * Ked cyklus presiahne periodu, treba sa rozhodnut - preto tri rezimy
 * [schedule].overrun:
 *
 *   skip     drz povodnu casovu mriezku, zmeskane sloty zahod
 *            (spravna volba pre casove rady - vzorky ostavaju na
 *             nasobkoch periody, len niektore chybaju)
 *   catch_up dobehni zmeskane sloty hned za sebou
 *            (pouzitelne ked nesmies stratit ziadnu vzorku, ale sposobi
 *             davku snimok za sebou a este vacsie zatazenie)
 *   stretch  dalsi termin = teraz + perioda
 *            (bez davok, ale mriezka sa posuva - drift je akceptovany)
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"

#include <inttypes.h>
#include <math.h>
#include <string.h>

int vmic_sched_run(const vmic_config_t *cfg,
                   int (*work)(uint64_t seq, double deadline, void *user),
                   void *user,
                   volatile sig_atomic_t *stop,
                   vmic_sched_stats_t *out)
{
    vmic_sched_stats_t st;
    memset(&st, 0, sizeof(st));

    const double interval = cfg->interval_s;
    const double t_start  = vmic_now_mono();
    double next = t_start;

    /*
     * Zarovnanie: prvy termin posunieme tak, aby padol na cely nasobok
     * periody od polnoci UTC. Ked bezi viac zberacov na roznych strojoch,
     * budu vzorkovat v rovnakych okamihoch a data sa daju porovnavat.
     */
    if (cfg->align) {
        struct timespec rt;
        vmic_now_real(&rt);
        double real  = (double)rt.tv_sec + (double)rt.tv_nsec * 1e-9;
        double phase = interval - fmod(real, interval);
        if (phase >= interval) phase = 0.0;
        next = t_start + phase;
        LOGI("planovac: prvy termin zarovnany, o %.3f s", phase);
    }

    const double t_end = (cfg->duration_s > 0.0)
                         ? t_start + cfg->duration_s : 0.0;

    uint64_t seq = 0;
    int rc = VMIC_OK;

    for (;;) {
        if (*stop) { rc = VMIC_STOP; break; }
        if (cfg->max_cycles && seq >= cfg->max_cycles) break;
        /*
         * Limit dlzky behu musime porovnavat aj so SKUTOCNYM casom, nie len
         * s planovanym terminom: v rezime catch_up 'next' za realnym casom
         * zaostava, takze samotne 'next >= t_end' by beh ukoncilo az
         * ovela neskor, nez pouzivatel ziadal.
         */
        if (t_end > 0.0 && (next >= t_end || vmic_now_mono() >= t_end)) break;

        /* --- cakanie na termin (s volitelnym rozptylom) ------------ */
        double target = next;
        if (cfg->jitter > 0.0) {
            /*
             * Rozptyl sa pripocitava k TERMINU, nie k perióde - dlhodoba
             * kadencia teda ostava presna, len jednotlive vzorky su
             * rozhodene. Bez toho by sa zber mohol "zosynchronizovat"
             * s periodickou aktivitou hosta a systematicky ju bud vzdy
             * trafit, alebo vzdy minut (aliasing).
             */
            target += vmic_jitter_unit() * cfg->jitter * interval;
        }

        for (;;) {
            if (*stop) { rc = VMIC_STOP; break; }
            double now = vmic_now_mono();
            if (now >= target) break;
            if (vmic_sleep_until(target) < 0) {
                /* neplatny termin - dalsie kolo by bolo aktivne cakanie */
                LOGE("planovac: nepodarilo sa uspat do terminu %.3f - koncim",
                     target);
                rc = VMIC_FATAL;
                break;
            }
        }
        if (rc != VMIC_OK) break;

        /* --- samotna praca ---------------------------------------- */
        double began = vmic_now_mono();
        double late  = began - next;
        if (late > st.worst_lateness_s) st.worst_lateness_s = late;

        int wrc = work(seq, next, user);
        seq++;

        if (wrc == VMIC_OK)          st.cycles_done++;
        else if (wrc == VMIC_ERR)    st.cycles_failed++;
        else if (wrc == VMIC_STOP)   { rc = VMIC_STOP; break; }
        else                         { rc = VMIC_FATAL; break; }

        /* --- posun terminu podla zvoleneho rezimu ------------------ */
        double after = vmic_now_mono();
        next += interval;

        if (next < after) {
            switch (cfg->overrun) {
            case VMIC_OVERRUN_SKIP: {
                double behind = after - next;
                uint64_t missed = (uint64_t)floor(behind / interval) + 1;
                st.cycles_skipped += missed;
                next += (double)missed * interval;
                LOGW("planovac: cyklus %" PRIu64 " trval %.3f s (perioda %.3f s)"
                     " - zahadzujem %" PRIu64 " slotov",
                     seq - 1, after - began, interval, missed);
                break;
            }
            case VMIC_OVERRUN_CATCHUP:
                /* termin nechavame v minulosti -> dalsi cyklus ide hned */
                LOGW("planovac: cyklus %" PRIu64 " trval %.3f s - dobieham",
                     seq - 1, after - began);
                break;
            case VMIC_OVERRUN_STRETCH:
                next = after + interval;
                LOGW("planovac: cyklus %" PRIu64 " trval %.3f s"
                     " - posuvam mriezku", seq - 1, after - began);
                break;
            }
        }
    }

    if (out) *out = st;
    return rc;
}
