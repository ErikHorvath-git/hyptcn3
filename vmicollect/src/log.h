/* log.h - jednoduche logovanie s urovnami, volitelne v JSON riadkoch */
#ifndef VMIC_LOG_H
#define VMIC_LOG_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

/* urovne VMIC_LOG_* su vo verejnej hlavicke - potrebuju ich aj pluginy */
#include "vmic.h"

int  vmic_log_level_from_name(const char *name);
const char *vmic_log_level_name(int level);

/* `file` == NULL alebo "" -> stderr */
int  vmic_log_open(int level, const char *file, bool json);
void vmic_log_close(void);
/*
 * Asynchronny rezim: od start() po stop() LOG* iba skopiruje hotovy riadok
 * do buffera v pamati a do suboru ho zapise vlakno vmic-log. Pouziva ho
 * `run`, aby vzorkovacie vlakno nikdy nezapisovalo do logu na disku.
 * stop() zapise vsetko, co zostalo, a vlakno ukonci; potom sa loguje znovu
 * synchronne. Vrati 0, alebo -1 (zostava synchronny rezim).
 */
int  vmic_log_async_start(void);
/* Odteraz idu posledne riadky behu (suhrn, koniec): smu pouzit rezervu. */
void vmic_log_final(void);
/* Zastavi vlakno (najviac timeout_s); vrati pocet strateneho (zahodene
   riadky + zlyhane zapisy, pri nedobehnutom vlakne aspon 1). */
uint64_t vmic_log_async_stop(double timeout_s);
void vmic_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void vmic_logv(int level, const char *fmt, va_list ap);

#define LOGD(...) vmic_log(VMIC_LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) vmic_log(VMIC_LOG_INFO,  __VA_ARGS__)
#define LOGW(...) vmic_log(VMIC_LOG_WARN,  __VA_ARGS__)
#define LOGE(...) vmic_log(VMIC_LOG_ERROR, __VA_ARGS__)

#endif
