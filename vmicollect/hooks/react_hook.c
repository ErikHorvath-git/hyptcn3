/*
 * react_hook.c - A7: VOLITEĽNÁ reakcia na úrovni hypervízora cez libvirt.
 *
 * DEFAULT VYPNUTÁ: zberac bez tohto pluginu NEREAGUJE nijako. Reakcia sa
 * zapne len jeho nacitanim do [hooks].load - a aj vtedy je to plugin, ktory
 * sa da nahradit bez prekladu zberaca.
 *
 * Co vie: pri kazdom alarme (vmic_hook_alarm) vykona JEDNU akciu cez
 * libvirt (qemu:///session, spustena pod uctom pouzivatela cez runuser):
 *   suspend   virsh suspend <domena>              - pozastavenie VM
 *   netoff    virsh domif-setlink ... down        - odpojenie siete
 *   snapshot  virsh snapshot-create-as ...        - snimok VM na forenzu
 * Latencia alarm -> spustenie akcie sa MERIA a zapisuje do
 * alarm_reakcia.jsonl vo vystupnom adresari.
 *
 * Argumenty: <akcia>,<user>,<domena>[,dry]
 *   akcia    suspend | netoff | snapshot
 *   user     ucet, pod ktorym bezi libvirt session (napr. 'eh')
 *   domena   libvirt domena (napr. 'hyptcn-guest')
 *   dry      (volitelne) len zapis, ziadne virsh - na testy bez VM
 *
 * BEZPECNOST: plugin bezi SYNCHRONNE v slucke zberaca - akcia je jedno
 * volanie virsh, nie blokujuce cakanie. Ked virsh zlyha, zapise sa to do
 * logu a zber ide dalej (reakcia je best-effort, detekcia bezi stale).
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
    char  akcia[16];
    char  user[64];
    char  domena[128];
    int   dry;
    char  log_path[VMIC_PATH_MAX];
} state_t;

static double mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **st)
{
    state_t *s = calloc(1, sizeof(*s));
    if (!s) return 1;
    s->api = api;

    char buf[512];
    snprintf(buf, sizeof(buf), "%s", args);
    char *save = NULL;
    char *a1 = strtok_r(buf, ",", &save);
    char *a2 = strtok_r(NULL, ",", &save);
    char *a3 = strtok_r(NULL, ",", &save);
    char *a4 = strtok_r(NULL, ",", &save);
    if (!a1 || !a2 || !a3) {
        api->log(VMIC_LOG_ERROR, "react_hook: argumenty maju byt "
                    "<akcia>,<user>,<domena>[,dry]");
        free(s);
        return 1;
    }
    snprintf(s->akcia, sizeof(s->akcia), "%s", a1);
    snprintf(s->user, sizeof(s->user), "%s", a2);
    snprintf(s->domena, sizeof(s->domena), "%s", a3);
    if (strcmp(s->akcia, "suspend") && strcmp(s->akcia, "netoff") &&
        strcmp(s->akcia, "snapshot")) {
        api->log(VMIC_LOG_ERROR, "react_hook: neznama akcia '%s' "
                 "(suspend|netoff|snapshot)", s->akcia);
        free(s);
        return 1;
    }
    if (a4 && !strcmp(a4, "dry")) s->dry = 1;

    snprintf(s->log_path, sizeof(s->log_path), "%s/alarm_reakcia.jsonl",
             api->cfg->dir);
    api->log(VMIC_LOG_DEBUG, "react_hook: akcia='%s' domena='%s' user='%s'%s",
             s->akcia, s->domena, s->user, s->dry ? " DRY" : "");
    *st = s;
    return 0;
}

static void zaznam(state_t *s, const vmic_alarm_t *a, double lat_ms,
                   int rc, const char *pozn)
{
    FILE *f = fopen(s->log_path, "ae");
    if (!f) return;
    fprintf(f, "{\"ts_unix_ms\": %" PRIu64 ", \"alarm_seq\": %" PRIu64
               ", \"akcia\": \"%s\", \"latencia_alarm_reakcia_ms\": %.3f"
               ", \"rc\": %d, \"pozn\": \"%s\"}\n",
            a->ts_unix_ms, a->seq, s->akcia, lat_ms, rc, pozn ? pozn : "");
    fclose(f);
}

int vmic_hook_alarm(void *st, const vmic_alarm_t *a)
{
    state_t *s = (state_t *)st;
    double t0 = mono_ms();

    if (s->dry) {
        zaznam(s, a, mono_ms() - t0, 0, "dry - ziadna akcia");
        s->api->log(VMIC_LOG_DEBUG, "react_hook: alarm seq=%" PRIu64 " - DRY, ziadna akcia",
                    a->seq);
        return 0;
    }

    /* virsh pod uctom pouzivatela (libvirt qemu:///session): zberac bezi
       ako root a pod rootom by session URI nevidel */
    char cmd[640];
    if (!strcmp(s->akcia, "suspend")) {
        snprintf(cmd, sizeof(cmd),
                 "runuser -u %s -- env XDG_RUNTIME_DIR=/run/user/$(id -u %s) "
                 "HOME=$(getent passwd %s | cut -d: -f6) "
                 "virsh --connect qemu:///session suspend %s",
                 s->user, s->user, s->user, s->domena);
    } else if (!strcmp(s->akcia, "snapshot")) {
        snprintf(cmd, sizeof(cmd),
                 "runuser -u %s -- env XDG_RUNTIME_DIR=/run/user/$(id -u %s) "
                 "HOME=$(getent passwd %s | cut -d: -f6) "
                 "virsh --connect qemu:///session snapshot-create-as %s "
                 "alarm-%" PRIu64 " 'alarm seq %" PRIu64 "'",
                 s->user, s->user, s->user, s->domena, a->seq, a->seq);
    } else { /* netoff */
        snprintf(cmd, sizeof(cmd),
                 "runuser -u %s -- env XDG_RUNTIME_DIR=/run/user/$(id -u %s) "
                 "HOME=$(getent passwd %s | cut -d: -f6) "
                 "bash -c 'for i in $(virsh --connect qemu:///session "
                 "domiflist %s | awk \"NR>2{print \\$1}\"); do "
                 "virsh --connect qemu:///session domif-setlink %s $i down; "
                 "done'",
                 s->user, s->user, s->user, s->domena, s->domena);
    }

    int rc = system(cmd);
    double lat = mono_ms() - t0;
    zaznam(s, a, lat, rc, NULL);
    s->api->log(VMIC_LOG_DEBUG, "react_hook: akcia '%s' rc=%d latencia=%.1f ms",
                s->akcia, rc, lat);
    return 0;
}

void vmic_hook_fini(void *st)
{
    free(st);
}
