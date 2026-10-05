/*
 * retention_test.c - regresny test markera HOLD v retencii (blok A5).
 *
 * Retencia maze cele retazce podla max_snapshots/max_bytes/max_age_s.
 * Marker HOLD (subor 'HOLD' vo vystupnom adresari) oznacuje retazce, ktore
 * sa nesmu zmazat - flight recorder: po alarme sa oznac retazec spred
 * alarmu a forenzny material prezije upratovanie.
 *
 * Test sa linkuje proti skutocnym .o suborom modulu (retention.c a spol.)
 * a vola vmic_retention_apply() priamo nad vlastnymi subormi v /tmp.
 * Overuje sa:
 *   - hold podla chain_id drzi cely retazec (delta zber),
 *   - hold podla mena suboru drzi retazec, v ktorom ten subor je,
 *   - hold podla mena funguje aj pri raw suboroch (chain_id = 0),
 *   - bez markera sa retencia sprava ako doteraz.
 *
 * Spustenie: make test-retention
 */
#define _GNU_SOURCE
#include "vmic.h"
#include "log.h"
#include "util.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static char g_dir[VMIC_PATH_MAX];
static int  g_fails = 0;

/* Vytvori subor snimky. Pri chain_id != 0 zapise hlavicku .vmicd s tym
 * istom id (rovnako ako put_u64 vo writer_delta.c: little-endian na
 * offset 16), inak subor bez hlavicky (= raw). `age_s` urcuje mtime. */
static int make_snap(const char *name, uint64_t chain_id, long age_s)
{
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), g_dir, name) != 0) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (chain_id) {
        uint8_t hdr[64];
        memset(hdr, 0, sizeof(hdr));
        memcpy(hdr, "VMICDLT1", 8);
        for (int i = 0; i < 8; i++)
            hdr[16 + i] = (uint8_t)(chain_id >> (8 * i));
        if (write(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr) ||
            write(fd, "x", 1) != 1) {
            close(fd);
            return -1;
        }
    } else {
        if (write(fd, "x", 1) != 1) { close(fd); return -1; }
    }
    close(fd);
    struct timespec ts[2];
    ts[0].tv_sec = 1000000 - age_s; ts[0].tv_nsec = 0;
    ts[1].tv_sec = 1000000 - age_s; ts[1].tv_nsec = 0;
    utimensat(AT_FDCWD, path, ts, 0);
    return 0;
}

static int exists(const char *name)
{
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), g_dir, name) != 0) return -1;
    return access(path, F_OK) == 0;
}

static void rm(const char *name)
{
    char path[VMIC_PATH_MAX];
    if (vmic_join(path, sizeof(path), g_dir, name) == 0) unlink(path);
}

static void write_hold(const char *text)
{
    char path[VMIC_PATH_MAX];
    vmic_join(path, sizeof(path), g_dir, VMIC_HOLD_MARKER);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "write_hold: %s\n", strerror(errno)); exit(1); }
    fputs(text, f);
    fclose(f);
}

static void remove_hold(void)
{
    char path[VMIC_PATH_MAX];
    vmic_join(path, sizeof(path), g_dir, VMIC_HOLD_MARKER);
    unlink(path);
}

static int apply_retention(void)
{
    vmic_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.dir, sizeof(cfg.dir), "%s", g_dir);
    cfg.max_snapshots = 1;      /* najprisnejsia politika, ktoru test vie */
    return vmic_retention_apply(&cfg, 0);
}

static void check(int cond, const char *what)
{
    if (cond) {
        printf("  OK   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        g_fails++;
    }
}

/* hold podla chain_id: oznaceny retazec prezije, neoznaceny najstarsi nie */
static void test_hold_by_chain_id(void)
{
    printf("hold podla chain_id (delta zber)\n");
    make_snap("c1_000000_x.vmicd", 100, 30);
    make_snap("c1_000001_x.vmicd", 100, 29);
    make_snap("c2_000000_x.vmicd", 200, 10);

    /* bez markera: najstarsi retazec (100) padne za obet */
    apply_retention();
    check(!exists("c1_000000_x.vmicd") && !exists("c1_000001_x.vmicd") &&
          exists("c2_000000_x.vmicd"),
          "bez HOLD sa zmazal najstarsi retazec, najnovsi ostal");

    /* marker drzi retazec 100 */
    make_snap("c1_000000_x.vmicd", 100, 30);
    make_snap("c1_000001_x.vmicd", 100, 29);
    write_hold("100\n");
    apply_retention();
    check(exists("c1_000000_x.vmicd") && exists("c1_000001_x.vmicd") &&
          exists("c2_000000_x.vmicd"),
          "HOLD s chain_id 100 drzi cely retazec 100");

    /* marker presunuty na retazec 200: retazec 100 sa zmaze */
    write_hold("200\n");
    apply_retention();
    check(!exists("c1_000000_x.vmicd") && exists("c2_000000_x.vmicd"),
          "HOLD s chain_id 200 drzi 200, retazec 100 sa zmazal");

    remove_hold();
    apply_retention();
    check(exists("c2_000000_x.vmicd"),
          "bez HOLD ostal chraneny najnovsi retazec");
    rm("c2_000000_x.vmicd");
}

/* hold podla mena suboru drzi CELY retazec, v ktorom ten subor je */
static void test_hold_whole_chain_by_file(void)
{
    printf("hold podla mena suboru drzi cely retazec\n");
    make_snap("c1_000000_x.vmicd", 100, 30);
    make_snap("c1_000001_x.vmicd", 100, 29);
    make_snap("c2_000000_x.vmicd", 200, 10);

    write_hold("c1_000001_x.vmicd\n");
    apply_retention();
    check(exists("c1_000000_x.vmicd") && exists("c1_000001_x.vmicd") &&
          exists("c2_000000_x.vmicd"),
          "HOLD s menom jednej delty drzi cely retazec 100");

    write_hold("c2_000000_x.vmicd\n");
    apply_retention();
    check(!exists("c1_000000_x.vmicd") && exists("c2_000000_x.vmicd"),
          "HOLD presunuty na 200: retazec 100 sa zmazal");

    remove_hold();
    rm("c2_000000_x.vmicd");
}

/* raw subory nemaju chain_id (kazdy je sam sebe retazcom) - hold ide cez
 * meno suboru */
static void test_hold_raw_by_name(void)
{
    printf("hold podla mena pri raw zbere\n");
    make_snap("a.raw", 0, 30);
    make_snap("b.raw", 0, 10);

    apply_retention();
    check(!exists("a.raw") && exists("b.raw"),
          "bez HOLD sa zmazal starsi raw subor");

    make_snap("a.raw", 0, 30);
    write_hold("a.raw\n");
    apply_retention();
    check(exists("a.raw") && exists("b.raw"),
          "HOLD s menom a.raw drzi raw subor pred retenciou");

    remove_hold();
    apply_retention();
    check(!exists("a.raw") && exists("b.raw"),
          "po zruseni HOLD sa a.raw zmaze");
    rm("b.raw");
}

/* komentare a prazdne riadky v HOLD sa preskakuju, nezmyli to parsovanie */
static void test_hold_file_comments(void)
{
    printf("HOLD: komentare a prazdne riadky\n");
    make_snap("c1_000000_x.vmicd", 100, 30);
    make_snap("c2_000000_x.vmicd", 200, 10);

    write_hold("# forenzny material spred alarmu\n\n  100  \n");
    apply_retention();
    check(exists("c1_000000_x.vmicd") && exists("c2_000000_x.vmicd"),
          "HOLD s komentarom a bielymi znakmi drzi retazec 100");

    remove_hold();
    rm("c1_000000_x.vmicd");
    rm("c2_000000_x.vmicd");
}

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/vmic-retention-XXXXXX");
    if (!mkdtemp(g_dir)) {
        fprintf(stderr, "retention_test: mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    vmic_log_open(VMIC_LOG_WARN, NULL, false);

    test_hold_by_chain_id();
    test_hold_whole_chain_by_file();
    test_hold_raw_by_name();
    test_hold_file_comments();

    if (g_fails) {
        printf("retention_test: %d testov NEpreslo (adresar: %s)\n",
               g_fails, g_dir);
        return 1;
    }
    printf("retention_test: VSETKO PRESLO (adresar: %s)\n", g_dir);
    return 0;
}
