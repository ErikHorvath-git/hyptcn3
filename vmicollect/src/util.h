/* util.h - drobnosti pouzivane naprie modulom (cas, cesty, I/O, hashe) */
#ifndef VMIC_UTIL_H
#define VMIC_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define VMIC_UTIL_PATHBUF 1024
#define VMIC_NAME_BUF     256

/* ---- cas ---------------------------------------------------------- */
/* CLOCK_MONOTONIC: nikdy neskace dozadu, imunny voci NTP a letnemu casu.
   Vsetko planovanie a meranie trvania pouziva TENTO hodinky.          */
double vmic_now_mono(void);
/* CLOCK_REALTIME: iba na pomenovanie snimok a do metadat.             */
void   vmic_now_real(struct timespec *ts);
/* "20260825T195200Z" - kompaktna, zoraditelna, bezpecna v nazve suboru */
void   vmic_ts_compact(char *out, size_t n, const struct timespec *ts);
/* ISO 8601 s milisekundami do metadat */
void   vmic_ts_iso(char *out, size_t n, const struct timespec *ts);
/* Spanok po absolutny monotonny termin; prerusitelny signalom.
   0 = dospal, 1 = prerusil ho signal, -1 = chyba (neplatny termin).   */
int    vmic_sleep_until(double deadline_mono);

/* ---- cesty a subory ----------------------------------------------- */
int  vmic_mkdir_p(const char *path);
int  vmic_join(char *out, size_t n, const char *dir, const char *name);
/* nahradi znaky nebezpecne v nazve suboru podtrznikom (in-place)      */
void vmic_sanitize(char *s);
/* velkost suboru; -1 pri chybe */
int64_t vmic_file_size(const char *path);
/* kolko blokov subor realne zabera (riedke subory!); -1 pri chybe     */
int64_t vmic_file_disk_usage(const char *path);
bool vmic_file_exists(const char *path);

/* ---- I/O, ktore znasa kratke zapisy a EINTR ----------------------- */
int  vmic_write_all(int fd, const void *buf, size_t len);
int  vmic_pwrite_all(int fd, const void *buf, size_t len, off_t off);
ssize_t vmic_read_full(int fd, void *buf, size_t len);
ssize_t vmic_pread_full(int fd, void *buf, size_t len, off_t off);

/* ---- data --------------------------------------------------------- */
void vmic_hex(const uint8_t *in, size_t n, char *out);   /* out: 2n+1 B */
/* rychla kontrola "je cely blok nulovy" (po 8 B slovach)              */
bool vmic_is_zero(const void *buf, size_t len);
/*
 * Rychly 64-bitovy hash na DETEKCIU ZMENY stranky (nie na integritu!).
 * Pracuje po 8 B slovach, takze je radovo rychlejsi ako SHA-256 -
 * pri delta zbere sa hashuje cela RAM v kazdom cykle, takze to je
 * kriticke miesto z hladiska dlzky pauzy VM.
 */
uint64_t vmic_hash64(const void *buf, size_t len);

/* Spocita SHA-256 hotoveho suboru. Vola sa AZ PO odpauzovani VM -
   hashovanie 4 GiB trva sekundy a v pauze by bolo neprijatelne. */
int vmic_hash_file(const char *path, uint8_t out[32]);

/* ---- ostatne ------------------------------------------------------ */
/* Vyplni sablonu: {domain} {seq} {ts} {backend} {pid}.
   Podporuje aj sirku: {seq:06d}. Vrati 0 / -1.                        */
int vmic_render_name(char *out, size_t n, const char *tmpl,
                     const char *domain, uint64_t seq, const char *ts,
                     const char *backend);
/* "1MiB", "0x1000", "4096" -> bajty. Vrati 0 / -1. */
int vmic_parse_size(const char *s, uint64_t *out);
void vmic_human_size(uint64_t bytes, char *out, size_t n);
/* nahodne cislo v <-1,1> pre jitter (seedovane pri starte) */
double vmic_jitter_unit(void);
void   vmic_random_seed(void);

#endif
