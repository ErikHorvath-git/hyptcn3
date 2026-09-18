/*
 * internal.h - vnutorne prepojenie medzi .c subormi modulu.
 *
 * Verejne API je v include/vmic.h. Sem patri to, co potrebuje register
 * backendov a writerov, ale co nema vidiet nikto zvonka (ani plugin).
 *
 * Ked pridavas vlastny backend alebo writer, pridas sem dva riadky
 * (ops + alloc) a jeden riadok do REGISTRY v backend.c / writer.c.
 */
#ifndef VMIC_INTERNAL_H
#define VMIC_INTERNAL_H

#include "vmic.h"

/* --- backendy ---------------------------------------------------- */
extern const vmic_backend_ops_t vmic_backend_ebpf;
extern const vmic_backend_ops_t vmic_backend_file;

int vmic_backend_ebpf_alloc(vmic_backend_t *b);
int vmic_backend_file_alloc(vmic_backend_t *b);

/* --- writery ----------------------------------------------------- */
extern const vmic_writer_ops_t vmic_writer_raw;
extern const vmic_writer_ops_t vmic_writer_delta;

int vmic_writer_raw_alloc(vmic_writer_t *w);
int vmic_writer_delta_alloc(vmic_writer_t *w);

#endif
