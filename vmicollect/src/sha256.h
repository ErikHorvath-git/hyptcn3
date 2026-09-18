/*
 * sha256.h - vlastna implementacia SHA-256 (FIPS 180-4).
 *
 * Preco nie OpenSSL? Modul tak nema ziadnu zavislost navyse okrem libbpf
 * a zlib, da sa prelozit aj v minimalnom prostredi a v praci sa da presne
 * ukazat, co sa s datami deje. Rychlost ~250 MB/s na beznom CPU staci -
 * uzkym hrdlom je citanie pamate hosta, nie hash.
 */
#ifndef VMIC_SHA256_H
#define VMIC_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} vmic_sha256_t;

void vmic_sha256_init(vmic_sha256_t *c);
void vmic_sha256_update(vmic_sha256_t *c, const void *data, size_t len);
void vmic_sha256_final(vmic_sha256_t *c, uint8_t out[32]);

#endif
