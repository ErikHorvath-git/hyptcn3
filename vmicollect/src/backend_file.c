/*
 * backend_file.c - "hypervizor" ktory je obycajny subor.
 *
 * Nesledovat ziadnu VM, len citat raw obraz pamate z disku. Znie to
 * zbytocne, ale je to najpouzitelnejsi backend na vyvoj:
 *
 *   - da sa spustit bez VM a bez roota (na rozdiel od backendu 'ebpf')
 *   - sprava sa presne ako ostry backend (rovnake rozhranie)
 *   - pouziva ho `vmicollect selftest`
 *   - da sa nim prehrat uz zozbierany dump a testovat na nom writery
 *
 * Ked ti nieco nefunguje s ostrou VM, najprv to vyskusaj tu.
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "internal.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    int      fd;
    uint64_t size;
} file_priv_t;

static int f_open(vmic_backend_t *b)
{
    file_priv_t *p = (file_priv_t *)b->priv;
    if (p->fd >= 0) return VMIC_OK;

    p->fd = open(b->cfg->image_path, O_RDONLY | O_CLOEXEC);
    if (p->fd < 0) {
        LOGE("file: nedaji sa otvorit '%s': %s",
             b->cfg->image_path, strerror(errno));
        return VMIC_FATAL;
    }
    struct stat st;
    if (fstat(p->fd, &st) != 0) {
        LOGE("file: fstat zlyhal: %s", strerror(errno));
        close(p->fd);
        p->fd = -1;
        return VMIC_FATAL;
    }
    p->size = (uint64_t)st.st_size;
    LOGI("file: '%s' otvoreny, %" PRIu64 " B", b->cfg->image_path, p->size);
    return VMIC_OK;
}

static void f_close(vmic_backend_t *b)
{
    file_priv_t *p = (file_priv_t *)b->priv;
    if (p->fd >= 0) close(p->fd);
    p->fd = -1;
}

static int f_probe(vmic_backend_t *b, vmic_vminfo_t *out)
{
    file_priv_t *p = (file_priv_t *)b->priv;
    memset(out, 0, sizeof(*out));
    snprintf(out->backend, sizeof(out->backend), "file");

    const char *base = strrchr(b->cfg->image_path, '/');
    snprintf(out->domain, sizeof(out->domain), "%s",
             b->cfg->domain[0] ? b->cfg->domain
                               : (base ? base + 1 : b->cfg->image_path));

    out->memsize      = p->size;
    out->has_memsize  = true;
    out->max_paddr    = p->size;
    out->has_max_paddr = true;
    snprintf(out->page_mode, sizeof(out->page_mode), "n/a");
    return VMIC_OK;
}

/* Subor nikam nebezi, takze pauza je no-op - ale musi vratit OK, aby
   sa merania pause_ms spravali rovnako ako pri ostrej VM. */
static int f_pause(vmic_backend_t *b)  { (void)b; return VMIC_OK; }
static int f_resume(vmic_backend_t *b) { (void)b; return VMIC_OK; }

static int64_t f_read_pa(vmic_backend_t *b, uint64_t paddr,
                         void *buf, size_t len)
{
    file_priv_t *p = (file_priv_t *)b->priv;
    uint8_t *out = (uint8_t *)buf;

    /* Kontrakt (viz vmic.h): buffer musime vyplnit CELY, aj tam kde
       data nie su - inak by v snimke ostali zvysky predchadzajuceho bloku. */
    if (paddr >= p->size) {
        memset(out, 0, len);
        return 0;
    }
    size_t avail = (paddr + len > p->size) ? (size_t)(p->size - paddr) : len;

    ssize_t got = vmic_pread_full(p->fd, out, avail, (off_t)paddr);
    if (got < 0) {
        LOGD("file: pread na 0x%" PRIx64 " zlyhal: %s", paddr, strerror(errno));
        got = 0;
    }
    if ((size_t)got < len) memset(out + got, 0, len - (size_t)got);
    return got;
}

const vmic_backend_ops_t vmic_backend_file = {
    .name          = "file",
    .random_access = true,
    .ext           = ".raw",
    .open          = f_open,
    .close         = f_close,
    .probe         = f_probe,
    .pause         = f_pause,
    .resume        = f_resume,
    .read_pa       = f_read_pa,
    .dump_to       = NULL,
};

int vmic_backend_file_alloc(vmic_backend_t *b)
{
    file_priv_t *p = calloc(1, sizeof(file_priv_t));
    if (!p) return VMIC_FATAL;
    p->fd = -1;
    b->priv = p;
    return VMIC_OK;
}
