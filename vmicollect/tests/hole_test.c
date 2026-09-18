/*
 * hole_test.c - regresny test na najzradnejsiu chybu v celom module.
 *
 * PROBLEM: fyzicky priestor x86 nie je suvisly (VGA diera na 0xA0000,
 * PCI hole pod 4 GiB, MMIO). Backend, ktory sa na prvej necitatelnej
 * stranke ZASTAVI a zvysok bloku len doplni nulami, zahodi tym aj VSETKU
 * citatelnu pamat ZA dierou - pri 1 MiB bloku a VGA diere sa strati aj
 * shadow BIOS na 0xC0000, co je normalna RAM. Snimka by pritom vyzerala
 * uplne v poriadku: ziadna chyba, len ticho o 256 KiB nul viac.
 *
 * Backend 'ebpf' toto riesi mapou memslotov (dieru preskoci celu naraz),
 * ale kontrakt read_pa() plati pre kazdy backend - preto tento test
 * pouziva fake backend s tou najhorsou moznou semantikou.
 *
 * TEST: fake backend sa zastavi na prvej chybnej stranke a overi sa, ze:
 *   - obraz je bajt po bajte zhodny s referenciou,
 *   - nulami sa vyplnila PRESNE diera, nie viac.
 *
 * Spustenie:  make test-holes
 */
#include "vmic.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MEM   (2u << 20)
#define PAGE  4096u
#define HOLE_LO 0xA0000u
#define HOLE_HI 0xC0000u

static uint8_t *g_mem;
static uint8_t *g_got;
static uint64_t g_len;

static int fb_open(vmic_backend_t *b){(void)b;return VMIC_OK;}
static int fb_probe(vmic_backend_t *b, vmic_vminfo_t *o){(void)b;memset(o,0,sizeof(*o));
  snprintf(o->domain,sizeof(o->domain),"fake");snprintf(o->backend,sizeof(o->backend),"fake");
  o->memsize=MEM;o->has_memsize=true;o->max_paddr=MEM;o->has_max_paddr=true;return VMIC_OK;}

/* najhorsi mozny backend: cita po strankach a stopne na prvej chybnej */
static int64_t fb_read(vmic_backend_t *b, uint64_t pa, void *buf, size_t len)
{
    (void)b;
    uint8_t *out=buf; size_t done=0; uint64_t ok=0;
    while (done < len) {
        size_t got=0;
        uint64_t p = pa+done;
        while (got < len-done) {
            uint64_t page = (p+got) & ~(uint64_t)(PAGE-1);
            if (page >= HOLE_LO && page < HOLE_HI) break;   /* diera */
            size_t n = PAGE - ((p+got) % PAGE);
            if (n > len-done-got) n = len-done-got;
            memcpy(out+done+got, g_mem+p+got, n);
            got += n;
        }
        done += got; ok += got;
        if (done >= len) break;
        size_t skip = PAGE - ((pa+done) % PAGE);
        if (skip > len-done) skip = len-done;
        memset(out+done, 0, skip);
        done += skip;
        if (got==0 && skip==0) break;
    }
    return (int64_t)ok;
}
static const vmic_backend_ops_t FAKE = {
  .name="fake",.random_access=true,.ext=".raw",
  .open=fb_open,.probe=fb_probe,.read_pa=fb_read };

static int sk_feed(vmic_writer_t *w,uint64_t pa,const uint8_t *b,size_t n)
{ (void)w; memcpy(g_got+pa,b,n); if(pa+n>g_len)g_len=pa+n; return VMIC_OK; }
static const vmic_writer_ops_t SINK = { .name="sink", .feed=sk_feed };

int main(void)
{
    vmic_log_open(VMIC_LOG_WARN, NULL, false);
    g_mem=malloc(MEM); g_got=malloc(MEM);
    for(size_t i=0;i<MEM;i++) g_mem[i]=(uint8_t)(i*7+1);
    memset(g_mem+HOLE_LO,0,HOLE_HI-HOLE_LO);   /* diera = nuly aj v referencii */
    memset(g_got,0xAA,MEM);

    vmic_config_t cfg; vmic_config_defaults(&cfg);
    snprintf(cfg.domain,sizeof(cfg.domain),"fake");
    if (vmic_config_validate(&cfg,false)!=0) return 9;

    vmic_backend_t b; memset(&b,0,sizeof(b)); b.ops=&FAKE; b.cfg=&cfg;
    vmic_writer_t w;  memset(&w,0,sizeof(w));  w.ops=&SINK;  w.cfg=&cfg;
    vmic_region_t r={0,MEM}; vmic_stats_t st; volatile sig_atomic_t stop=0;

    if (vmic_capture(&b,&w,&r,1,&st,&stop)!=VMIC_OK){puts("capture ZLYHAL");return 1;}

    printf("chunks=%llu read_errors=%llu filled_zero=%llu bytes_read=%llu\n",
      (unsigned long long)st.chunks,(unsigned long long)st.read_errors,
      (unsigned long long)st.filled_zero,(unsigned long long)st.bytes_read);

    if (memcmp(g_got,g_mem,MEM)!=0){
        size_t i=0; while(i<MEM && g_got[i]==g_mem[i]) i++;
        printf("ZLE: prvy rozdiel na 0x%zx (stranka %zu, za dierou 0x%x)\n",
               i,i/PAGE,HOLE_HI);
        return 1;
    }
    if (st.filled_zero != (HOLE_HI - HOLE_LO)) {
        printf("ZLE: nulami vyplnenych %llu B, ocakaval som presne %u B "
               "(velkost diery) - backend zahadzuje aj pamat za dierou\n",
               (unsigned long long)st.filled_zero, HOLE_HI - HOLE_LO);
        return 1;
    }
    puts("OK: pamat za dierou sa zachovala, obraz je zhodny s referenciou");
    return 0;
}
