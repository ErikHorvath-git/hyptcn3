/*
 * alarm_test.c - regresny test alarmoveho rozhrania (blok A6).
 *
 * End-to-end cez skutocny kod hooks.c + meta.c + retention.c: nacita sa
 * prikladovy detektor (build/alarm_hook.so), do ktoreho sa posle snimka
 * nad prahom. Detektor vyhlasi alarm cez api->alarm() a overi sa, ze:
 *
 *   - alarm.json vznikne s casom, skore, seq, chain_id a zdrojom,
 *   - alarms.jsonl ma jeden riadok na alarm,
 *   - marker HOLD obsahuje chain_id alarmu (flight recorder, A5),
 *   - vmic_hook_alarm() dostal alarm (riadok v CSV detektora),
 *   - alarmy pod prahom nevznikaju (druha snimka ticho prejde).
 *
 * Spustenie: make test-alarm
 */
#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[VMIC_PATH_MAX];
static char g_hook[VMIC_PATH_MAX];
static char g_csv[VMIC_PATH_MAX];
static int  g_fails = 0;

static void check(int cond, const char *what)
{
    if (cond) {
        printf("  OK   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        g_fails++;
    }
}

static int file_contains(const char *name, const char *needle)
{
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), g_dir, name) != 0) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, needle)) { found = 1; break; }
    fclose(f);
    return found;
}

static int count_lines(const char *name)
{
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), g_dir, name) != 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) n++;
    fclose(f);
    return n;
}

int main(int argc, char **argv)
{
    snprintf(g_hook, sizeof(g_hook), "%s",
             argc > 1 ? argv[1] : "build/alarm_hook.so");
    snprintf(g_dir, sizeof(g_dir), "/tmp/vmic-alarm-XXXXXX");
    if (!mkdtemp(g_dir)) {
        fprintf(stderr, "alarm_test: mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    vmic_join(g_csv, sizeof(g_csv), g_dir, "prijate.csv");

    vmic_log_open(VMIC_LOG_WARN, NULL, false);

    vmic_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.dir, sizeof(cfg.dir), "%s", g_dir);
    cfg.hook_count = 1;
    snprintf(cfg.hook_path[0], sizeof(cfg.hook_path[0]), "%s", g_hook);
    snprintf(cfg.hook_args[0], sizeof(cfg.hook_args[0]), "%s,0", g_csv);
    cfg.hooks_strict = false;

    vmic_hooks_t *h = vmic_hooks_load(&cfg);
    check(h != NULL, "detektor sa nacital (alarm_hook.so)");

    /* snimka nad prahom: detektor vyhlasi alarm */
    vmic_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.seq = 3;
    snap.chain_id = 777;
    snap.pages_changed = 5;
    clock_gettime(CLOCK_REALTIME, &snap.wall);
    snap.cfg = &cfg;

    int rc = vmic_hooks_fire(h, &snap);
    check(rc == VMIC_OK, "vmic_hooks_fire nad snimkou nad prahom -> OK");

    check(file_contains("alarm.json", "\"seq\": 3"),
          "alarm.json ma seq alarmu");
    check(file_contains("alarm.json", "\"chain_id\": 777"),
          "alarm.json ma chain_id");
    check(file_contains("alarm.json", "\"score\": 5"),
          "alarm.json ma skore");
    check(file_contains("alarm.json", "\"zdroj\": \"example:pages_changed\""),
          "alarm.json ma zdroj");
    check(file_contains("alarm.json", "\"timestamp_unix_ms\""),
          "alarm.json ma cas");
    check(file_contains("alarm.json", "\"top_bins\""),
          "alarm.json ma pole top_bins");
    check(count_lines("alarms.jsonl") == 1,
          "alarms.jsonl ma prave jeden riadok");
    check(file_contains(VMIC_HOLD_MARKER, "777"),
          "marker HOLD obsahuje chain_id alarmu (flight recorder)");

    /* prijatie alarmu cez vmic_hook_alarm: CSV detektora ma hlavicku + 1 */
    int csv_lines = count_lines("prijate.csv");
    check(csv_lines == 2, "detektor prijal alarm cez vmic_hook_alarm (1 riadok)");

    /* snimka pod prahom: ziadny dalsi alarm */
    snap.seq = 4;
    snap.pages_changed = 0;
    rc = vmic_hooks_fire(h, &snap);
    check(rc == VMIC_OK && count_lines("alarms.jsonl") == 1 &&
          count_lines("prijate.csv") == 2,
          "snimka pod prahom nevyhlasi dalsi alarm");

    vmic_hooks_unload(h);

    if (g_fails) {
        printf("alarm_test: %d testov NEpreslo (adresar: %s)\n",
               g_fails, g_dir);
        return 1;
    }
    printf("alarm_test: VSETKO PRESLO (adresar: %s)\n", g_dir);
    return 0;
}
