/*
 * sha256.c - SHA-256 (FIPS 180-4).
 *
 * Su tu dve implementacie kompresnej funkcie a za behu sa vybera podla
 * toho, co vie CPU:
 *
 *   sha256_blocks_scalar()  prenosna, prelozi sa vsade;
 *   sha256_blocks_shani()   instrukcie SHA-NI (sha256rnds2/msg1/msg2),
 *                           x86-64, rozpoznane cez CPUID.
 *
 * PRECO: hash raw snimky bezi nad celym suborom vratane dier - pri
 * 4 GiB je to najdrahsia cast cyklu. Skalarna verzia je na tomto stroji
 * merane ~350 MiB/s, co je pri 4 GiB ~12 s. SHA-NI ten isty vypocet
 * urychli radovo (namerane cisla su v docs/MERANIA.md).
 *
 * VYSLEDOK JE BIT PO BITE ROVNAKY. SHA-NI nie je iny algoritmus, su to
 * len instrukcie, ktore rovnaky vypocet spravia naraz nad styrmi kolami.
 * Premennou prostredia VMIC_SHA256_SCALAR=1 sa da rychla cesta vypnut -
 * pouziva sa na overenie, ze obe vetvy davaju ten isty hash.
 *
 * PROVENIENCIA: poradie intrinsic volani vo vetve SHA-NI je standardna
 * schema z referencnej implementacie Intel SHA Extensions (Sean Gulley
 * a spol.), rozsirena verejne napr. ako noloader/SHA-Intrinsics
 * (public domain). Konstanty K su z FIPS 180-4. Skalarna vetva je
 * povodny kod tohto modulu.
 */
#include "sha256.h"

#include <stdlib.h>
#include <string.h>

/* SHA-NI vieme prelozit iba na x86-64 prekladacom, ktory pozna
   atribut target() a hlavicku <immintrin.h>. Inde zostane iba
   skalarna vetva - kod sa prelozi a funguje rovnako, len pomalsie. */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(VMIC_NO_SHANI)
#  define VMIC_HAVE_SHANI 1
#  include <cpuid.h>
#  include <immintrin.h>
#endif

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define BSIG1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SSIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_block_scalar(uint32_t state[8], const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 64; i++)
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

    uint32_t a = state[0], b = state[1], cc = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += cc; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


/* ------------------------------------------------------------------ */
/* SHA-NI vetva                                                        */
/* ------------------------------------------------------------------ */
#ifdef VMIC_HAVE_SHANI

/*
 * Jedno kolo makra sha256rnds2 spracuje dve kola SHA-256 naraz, preto
 * je 64 kol zapisanych ako 16 skupin po styroch. Stav sa drzi v dvoch
 * 128-bitovych registroch v poradi ABEF / CDGH (tak ho instrukcie
 * ocakavaju), preto to premiesavanie na zaciatku a na konci.
 */
__attribute__((target("sha,sse4.1,ssse3")))
static void sha256_blocks_shani(uint32_t state[8], const uint8_t *data,
                                size_t blocks)
{
    __m128i STATE0, STATE1, MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x((long long)0x0c0d0e0f08090a0bULL,
                                        (long long)0x0405060700010203ULL);

    TMP    = _mm_loadu_si128((const __m128i *)(const void *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)(const void *)&state[4]);

    TMP    = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);       /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);       /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);    /* CDGH */

    while (blocks--) {
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* kola 0-3 */
        MSG  = _mm_loadu_si128((const __m128i *)(const void *)(data + 0));
        MSG0 = _mm_shuffle_epi8(MSG, MASK);
        MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0xE9B5DBA5B5C0FBCFULL,
                                                  (long long)0x71374491428A2F98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* kola 4-7 */
        MSG1 = _mm_loadu_si128((const __m128i *)(const void *)(data + 16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0xAB1C5ED5923F82A4ULL,
                                                  (long long)0x59F111F13956C25BULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* kola 8-11 */
        MSG2 = _mm_loadu_si128((const __m128i *)(const void *)(data + 32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0x550C7DC3243185BEULL,
                                                  (long long)0x12835B01D807AA98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* kola 12-15 */
        MSG3 = _mm_loadu_si128((const __m128i *)(const void *)(data + 48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0xC19BF1749BDC06A7ULL,
                                                  (long long)0x80DEB1FE72BE5D74ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* kola 16-19 */
        MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0x240CA1CC0FC19DC6ULL,
                                                  (long long)0xEFBE4786E49B69C1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* kola 20-23 */
        MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0x76F988DA5CB0A9DCULL,
                                                  (long long)0x4A7484AA2DE92C6FULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* kola 24-27 */
        MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0xBF597FC7B00327C8ULL,
                                                  (long long)0xA831C66D983E5152ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* kola 28-31 */
        MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0x1429296706CA6351ULL,
                                                  (long long)0xD5A79147C6E00BF3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* kola 32-35 */
        MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0x53380D134D2C6DFCULL,
                                                  (long long)0x2E1B213827B70A85ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* kola 36-39 */
        MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0x92722C8581C2C92EULL,
                                                  (long long)0x766A0ABB650A7354ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* kola 40-43 */
        MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0xC76C51A3C24B8B70ULL,
                                                  (long long)0xA81A664BA2BFE8A1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* kola 44-47 */
        MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0x106AA070F40E3585ULL,
                                                  (long long)0xD6990624D192E819ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* kola 48-51 */
        MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x((long long)0x34B0BCB52748774CULL,
                                                  (long long)0x1E376C0819A4C116ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);   /* posledny msg1 */

        /* kola 52-55 */
        MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x((long long)0x682E6FF35B9CCA4FULL,
                                                  (long long)0x4ED8AA4A391C0CB3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* kola 56-59 */
        MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x((long long)0x8CC7020884C87814ULL,
                                                  (long long)0x78A5636F748F82EEULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* kola 60-63 */
        MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x((long long)0xC67178F2BEF9A3F7ULL,
                                                  (long long)0xA4506CEB90BEFFFAULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        data += 64;
    }

    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);       /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);    /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);       /* HGFE */

    _mm_storeu_si128((__m128i *)(void *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)(void *)&state[4], STATE1);
}

/*
 * Ma toto CPU SHA-NI? Pytame sa CPUID raz a vysledok si zapamatame.
 * Bit 29 v EBX listu 7/0 je SHA; navyse potrebujeme SSSE3 a SSE4.1
 * (pshufb, palignr, pblendw), ktore su v ECX listu 1.
 */
static int sha256_use_shani(void)
{
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = 0;

    if (getenv("VMIC_SHA256_SCALAR") == NULL) {
        unsigned int a = 0, b = 0, c = 0, d = 0;
        if (__get_cpuid(1, &a, &b, &c, &d) &&
            (c & bit_SSSE3) && (c & bit_SSE4_1)) {
            unsigned int a7 = 0, b7 = 0, c7 = 0, d7 = 0;
            if (__get_cpuid_count(7, 0, &a7, &b7, &c7, &d7) &&
                (b7 & (1u << 29)))
                cached = 1;
        }
    }
    return cached;
}
#endif /* VMIC_HAVE_SHANI */

/* Spracuje N celych 64-bajtovych blokov; vyber vetvy je tu, na jednom
   mieste, takze zvysok suboru o SHA-NI nemusi vediet. */
static void sha256_blocks(uint32_t state[8], const uint8_t *p, size_t blocks)
{
    if (!blocks) return;
#ifdef VMIC_HAVE_SHANI
    if (sha256_use_shani()) {
        sha256_blocks_shani(state, p, blocks);
        return;
    }
#endif
    for (size_t i = 0; i < blocks; i++)
        sha256_block_scalar(state, p + i * 64);
}

void vmic_sha256_init(vmic_sha256_t *c)
{
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bitlen = 0;
    c->buflen = 0;
}

void vmic_sha256_update(vmic_sha256_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)len * 8u;

    if (c->buflen) {                       /* dokoncit rozpracovany blok */
        size_t need = 64 - c->buflen;
        size_t take = len < need ? len : need;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            sha256_blocks(c->state, c->buf, 1);
            c->buflen = 0;
        }
    }
    if (len >= 64) {                       /* cele bloky priamo zo vstupu */
        size_t blocks = len / 64;
        sha256_blocks(c->state, p, blocks);
        p   += blocks * 64;
        len -= blocks * 64;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void vmic_sha256_final(vmic_sha256_t *c, uint8_t out[32])
{
    uint64_t bits = c->bitlen;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        memset(c->buf + c->buflen, 0, 64 - c->buflen);
        sha256_blocks(c->state, c->buf, 1);
        c->buflen = 0;
    }
    memset(c->buf + c->buflen, 0, 56 - c->buflen);
    for (int i = 0; i < 8; i++)
        c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_blocks(c->state, c->buf, 1);

    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}
