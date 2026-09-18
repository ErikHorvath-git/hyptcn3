/*
 * backend_ebpf.c - zber pamate KVM hosta cez eBPF. Jediny ostry backend.
 *
 * Cely modul stoji na jednom napade: to, co o virtualnom stroji vie IBA
 * jadro, sa nema hadat zvonka - ma sa to spytat priamo v jadre. Preto je
 * tato vrstva rozdelena presne na dve casti:
 *
 *   jadro (bpf/vmic_kvm.bpf.c)   najde struct kvm, precita memsloty
 *                                (GPA -> HVA) a skopiruje stranky
 *   userspace (tento subor)      zisti, KTORY proces je ktora VM, nacita
 *                                BPF program, posle mu offsety struktur
 *                                a vysledok posunie do vmic_capture()
 *
 * CO NAM TO DAVA OPROTI OSTATNYM CESTAM
 *
 *   LibVMI + KVM     vyzaduje patchnute QEMU alebo KVMi socket
 *   virsh dump       vzdy cely obraz, ziadny inkrementalny zber
 *   process_vm_readv bajty ano, ale ziadna mapa GPA -> HVA
 *   ebpf (toto)      bezi na neupravenom QEMU/KVM a mapu dostane presne
 *                    tak, ako ju vidi samotny hypervizor
 *
 * CO TENTO BACKEND NEVIE
 *
 * Pozastavit VM. eBPF nie je riadiace rozhranie hypervizora a nema ako
 * povedat "zastav vCPU" - preto je ops->pause NULL a snimka je "ziva":
 * pocas citania sa pamat moze menit. Kazda stranka je precitana jednym
 * volanim, cize sama v sebe konzistentna, ale dve stranky mozu byt z
 * roznych okamihov. Pre periodicky zber priznakov to je prijatelne, pre
 * forenznu analyzu jednej snimky nie - v takom pripade treba VM zastavit
 * inym nastrojom (virsh suspend) a az potom spustit `vmicollect once`.
 */

#define _GNU_SOURCE
#include "vmic.h"
#include "internal.h"
#include "log.h"

#include <stdlib.h>

/*
 * Bez clangu (preklad BPF casti) alebo bez libbpf (nacitanie do jadra) sa
 * tento backend prelozit neda. Zberac ale ostane pouzitelny - backend
 * ostane v zozname a pri pokuse o pouzitie povie, co chyba. Vdaka tomu sa
 * da `make test` a backend 'file' spustit aj na stroji bez BPF nastrojov.
 */
#ifdef VMIC_HAVE_EBPF

#include "util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "vmic_bpf_abi.h"

/* ------------------------------------------------------------------ */
/* Vlozeny BPF program                                                 */
/* ------------------------------------------------------------------ */
/*
 * Prelozeny bpf/vmic_kvm.bpf.o je v binarke ako blob (Makefile ho tam
 * prilepi cez `ld -r -b binary`), takze zberac je jeden subor a nema co
 * stratit pri kopirovani. Symboly su slabe: ked sa niekto rozhodne
 * prelozit modul bez BPF casti, prelozi sa to a chyba pride az za behu.
 * Cestu sa da prebit cez vm.bpf_object - hodi sa pri ladeni programu.
 */
extern const unsigned char _binary_vmic_kvm_bpf_o_start[] __attribute__((weak));
extern const unsigned char _binary_vmic_kvm_bpf_o_end[]   __attribute__((weak));

/* ------------------------------------------------------------------ */
/* Stav backendu                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    struct bpf_object  *obj;
    int                 fd_probe;      /* prog vmic_probe               */
    int                 fd_read;       /* prog vmic_read                */
    int                 map_koff;
    int                 map_slots;
    int                 map_pages;

    uint8_t            *win;           /* mmap okno mapy `pages`        */
    size_t              win_size;

    uint32_t            pid;           /* proces VMM (QEMU)             */
    uint32_t            fd_hint;       /* cislo fd "kvm-vm" z /proc     */
    char                name[VMIC_NAME_MAX];   /* meno domeny           */

    struct vmic_bpf_vminfo info;       /* posledna tabulka slotov       */
    bool                have_info;
    uint64_t            last_generation;

    uint8_t            *blob;          /* nacitany .bpf.o zo suboru     */
    size_t              blob_size;
} ebpf_priv_t;

/* ------------------------------------------------------------------ */
/* Logovanie z libbpf                                                  */
/* ------------------------------------------------------------------ */
/*
 * Vypisy libbpf su pri ladeni to najcennejsie, co mame - hlaska
 * verifikatora povie presne, ktora instrukcia programu sa nepacila.
 * Preto ich neposielame na stderr, ale do nasho logu; na urovni WARN
 * prejde iba to podstatne, cely vypis je vidiet pri -v.
 */
static int libbpf_to_log(enum libbpf_print_level level, const char *fmt,
                         va_list ap)
{
    int lvl = (level == LIBBPF_WARN) ? VMIC_LOG_WARN : VMIC_LOG_DEBUG;
    char *msg = NULL;

    /*
     * POZOR NA OREZANIE: cely vypis verifikatora pride ako JEDEN retazec
     * dlhy aj desiatky kB a to podstatne - dovod odmietnutia - je na jeho
     * KONCI. Keby sme ho naformatovali do pola pevnej velkosti, ostal by
     * z neho zaciatok vypisu instrukcii a chybu by uzivatel nikdy
     * nevidel. Preto vasprintf() a rozsekanie na riadky (nas logger si
     * navyse konce riadkov pridava sam).
     */
    if (vasprintf(&msg, fmt, ap) < 0 || !msg) return 0;

    for (char *line = msg; line && *line; ) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (*line) vmic_log(lvl, "%s", line);
        line = nl ? nl + 1 : NULL;
    }
    free(msg);
    return 0;
}

/* ------------------------------------------------------------------ */
/* BTF: kde presne v jadre lezi ktore pole                             */
/* ------------------------------------------------------------------ */
/*
 * BPF program nepozna ziadnu jadrovu strukturu - offsety mu posleme v
 * mape `koff`. Berieme ich z BTF, ktore ma jadro samo o sebe. Vyhoda
 * oproti pevne prelozenym offsetom (alebo CO-RE proti vmlinux.h) je, ze
 * ked sa nieco posunie alebo premenuje, dozvieme sa to menom pri starte
 * a nie tichym citanim smeti.
 *
 * Pozor na anonymne uniony: v jadre 7.x je `file->f_path` aj
 * `dentry->d_name` vnorene v anonymnom unione (const-ifikacia VFS), cize
 * hladanie clena podla mena musi vediet zostupit aj do bezmennych clenov.
 */

typedef struct {
    struct btf *vmlinux;
    struct btf *module;    /* /sys/kernel/btf/kvm, ked je kvm modul */
} btfset_t;

static const struct btf_type *skip_mods(const struct btf *btf, __s32 id,
                                        __s32 *out_id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);
    while (t && (btf_kind(t) == BTF_KIND_TYPEDEF ||
                 btf_kind(t) == BTF_KIND_CONST ||
                 btf_kind(t) == BTF_KIND_VOLATILE ||
                 btf_kind(t) == BTF_KIND_RESTRICT)) {
        id = t->type;
        t  = btf__type_by_id(btf, id);
    }
    if (out_id) *out_id = id;
    return t;
}

/* Najde clena `name` v strukture/unione `t`, aj cez anonymne cleny.
   Vrati 0 a doplni offset (v bajtoch) a typ clena. */
static int member_lookup(const struct btf *btf, const struct btf_type *t,
                         const char *name, __u32 *off, __s32 *type_id)
{
    if (!t || (btf_kind(t) != BTF_KIND_STRUCT && btf_kind(t) != BTF_KIND_UNION))
        return -1;

    const struct btf_member *m = btf_members(t);
    for (unsigned i = 0; i < btf_vlen(t); i++, m++) {
        const char *mn = btf__name_by_offset(btf, m->name_off);
        __u32 mo = btf_member_bit_offset(t, i) / 8;

        if (mn && *mn) {
            if (strcmp(mn, name) == 0) {
                *off += mo;
                *type_id = m->type;
                return 0;
            }
            continue;
        }
        /* bezmenny clen - anonymny struct/union, skus vnutri */
        __s32 sub_id = 0;
        const struct btf_type *sub = skip_mods(btf, m->type, &sub_id);
        __u32 tmp = *off + mo;
        if (member_lookup(btf, sub, name, &tmp, type_id) == 0) {
            *off = tmp;
            return 0;
        }
    }
    return -1;
}

/* "f_path.dentry" - kazda bodka je jeden krok dovnutra struktury. */
static int btf_path_offset(const struct btf *btf, const struct btf_type *root,
                           const char *path, __u32 *off, __s32 *last_type)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", path);

    const struct btf_type *cur = root;
    __u32 total = 0;
    __s32 tid = 0;

    for (char *tok = strtok(buf, "."); tok; tok = strtok(NULL, ".")) {
        if (member_lookup(btf, cur, tok, &total, &tid) != 0) return -1;
        cur = skip_mods(btf, tid, &tid);
    }
    *off = total;
    if (last_type) *last_type = tid;
    return 0;
}

/* Struktura moze byt v zakladnom BTF alebo az v BTF modulu kvm. */
static const struct btf_type *find_struct(const btfset_t *set, const char *name,
                                          const struct btf **owner)
{
    const struct btf *srcs[2] = { set->vmlinux, set->module };
    for (int i = 0; i < 2; i++) {
        if (!srcs[i]) continue;
        __s32 id = btf__find_by_name_kind(srcs[i], name, BTF_KIND_STRUCT);
        if (id < 0) id = btf__find_by_name_kind(srcs[i], name, BTF_KIND_UNION);
        if (id < 0) continue;
        *owner = srcs[i];
        return btf__type_by_id(srcs[i], id);
    }
    return NULL;
}

/* Co presne chceme z BTF vytiahnut. */
typedef enum {
    W_OFF,       /* bajtovy offset pola                       */
    W_ARR_N,     /* pocet prvkov pola                         */
    W_ARR_SIZE   /* velkost jedneho prvku pola                */
} want_t;

static const struct {
    const char *type;
    const char *path;
    want_t      want;
    size_t      dst;      /* offsetof v struct vmic_bpf_koff */
} KFIELDS[] = {
#define KF(t, p, w, m) { t, p, w, offsetof(struct vmic_bpf_koff, m) }
    KF("task_struct",     "files",          W_OFF,      task_files),
    KF("files_struct",    "fdt",            W_OFF,      files_fdt),
    KF("fdtable",         "max_fds",        W_OFF,      fdtable_max_fds),
    KF("fdtable",         "fd",             W_OFF,      fdtable_fd),
    KF("file",            "private_data",   W_OFF,      file_private_data),
    KF("file",            "f_path",         W_OFF,      file_f_path),
    KF("path",            "dentry",         W_OFF,      path_dentry),
    KF("dentry",          "d_name",         W_OFF,      dentry_d_name),
    KF("qstr",            "name",           W_OFF,      qstr_name),
    KF("hlist_head",      "first",          W_OFF,      hlist_head_first),
    KF("hlist_node",      "next",           W_OFF,      hlist_node_next),

    KF("kvm",             "memslots",       W_OFF,      kvm_memslots),
    KF("kvm",             "memslots",       W_ARR_SIZE, kvm_memslots_stride),
    KF("kvm",             "memslots",       W_ARR_N,    kvm_memslots_count),
    KF("kvm",             "online_vcpus",   W_OFF,      kvm_online_vcpus),
    KF("kvm",             "userspace_pid",  W_OFF,      kvm_userspace_pid),

    KF("kvm_memslots",    "generation",     W_OFF,      ms_generation),
    KF("kvm_memslots",    "id_hash",        W_OFF,      ms_id_hash),
    KF("kvm_memslots",    "id_hash",        W_ARR_N,    hash_buckets),
    KF("kvm_memslots",    "node_idx",       W_OFF,      ms_node_idx),

    KF("kvm_memory_slot", "id_node",        W_OFF,      slot_id_node),
    KF("kvm_memory_slot", "id_node",        W_ARR_SIZE, slot_id_node_stride),
    KF("kvm_memory_slot", "base_gfn",       W_OFF,      slot_base_gfn),
    KF("kvm_memory_slot", "npages",         W_OFF,      slot_npages),
    KF("kvm_memory_slot", "userspace_addr", W_OFF,      slot_userspace_addr),
    KF("kvm_memory_slot", "flags",          W_OFF,      slot_flags),
    KF("kvm_memory_slot", "id",             W_OFF,      slot_id),
#undef KF
};
#define KFIELD_COUNT (sizeof(KFIELDS) / sizeof(KFIELDS[0]))

static int resolve_offsets(struct vmic_bpf_koff *out)
{
    btfset_t set = { NULL, NULL };
    int bad = 0;

    memset(out, 0, sizeof(*out));

    set.vmlinux = btf__parse("/sys/kernel/btf/vmlinux", NULL);
    if (!set.vmlinux) {
        LOGE("ebpf: jadro nema BTF (/sys/kernel/btf/vmlinux): %s",
             strerror(errno));
        LOGE("ebpf: bez CONFIG_DEBUG_INFO_BTF sa tento backend pouzit neda");
        return VMIC_FATAL;
    }
    /* Ked je kvm modul, jeho typy su v samostatnom (split) BTF. Na
       jadrach s KVM zabudovanym natvrdo tento subor neexistuje a vsetko
       sa najde uz vo vmlinux - preto to nie je chyba. */
    set.module = btf__parse_split("/sys/kernel/btf/kvm", set.vmlinux);

    for (size_t i = 0; i < KFIELD_COUNT; i++) {
        const struct btf *owner = NULL;
        const struct btf_type *st = find_struct(&set, KFIELDS[i].type, &owner);
        __u32 off = 0;
        __s32 tid = 0;

        if (!st) {
            LOGE("ebpf: v BTF jadra nie je struktura '%s'", KFIELDS[i].type);
            bad++;
            continue;
        }
        if (btf_path_offset(owner, st, KFIELDS[i].path, &off, &tid) != 0) {
            LOGE("ebpf: struktura '%s' v tomto jadre nema pole '%s'",
                 KFIELDS[i].type, KFIELDS[i].path);
            bad++;
            continue;
        }

        __u32 value = off;
        if (KFIELDS[i].want != W_OFF) {
            const struct btf_type *t = skip_mods(owner, tid, &tid);
            if (!t || btf_kind(t) != BTF_KIND_ARRAY) {
                LOGE("ebpf: '%s.%s' nie je pole", KFIELDS[i].type,
                     KFIELDS[i].path);
                bad++;
                continue;
            }
            const struct btf_array *a = btf_array(t);
            if (KFIELDS[i].want == W_ARR_N) {
                value = a->nelems;
            } else {
                __s64 sz = btf__resolve_size(owner, a->type);
                if (sz <= 0) {
                    LOGE("ebpf: neviem velkost prvku '%s.%s'",
                         KFIELDS[i].type, KFIELDS[i].path);
                    bad++;
                    continue;
                }
                value = (__u32)sz;
            }
        }
        /* memcpy a nie pretypovany zapis: hodnota je zarovnana (kazdy
           KFIELDS[].dst je offsetof clena __u32), ale clang na taky cast
           pod -Wcast-align pravom nadava a prekladac z toho aj tak spravi
           jediny store. */
        memcpy((uint8_t *)out + KFIELDS[i].dst, &value, sizeof(value));
    }

    btf__free(set.module);
    btf__free(set.vmlinux);

    if (bad) return VMIC_FATAL;

    /* Poistky proti nezmyslom, ktore by BPF program dostal az za behu. */
    if (out->kvm_memslots_stride != sizeof(void *) ||
        out->kvm_memslots_count == 0 ||
        out->hash_buckets == 0 || out->hash_buckets > VMIC_BPF_MAX_BUCKETS ||
        out->slot_id_node_stride == 0) {
        LOGE("ebpf: rozlozenie memslotov v tomto jadre nesedi "
             "(stride %u, adresne priestory %u, buckety %u)",
             out->kvm_memslots_stride, out->kvm_memslots_count,
             out->hash_buckets);
        return VMIC_FATAL;
    }

    /* Cely vypis je pri ladeni to prve, co chces vidiet: ked nieco necita
       zmysluplne hodnoty, chyba je bud tu, alebo nikde. */
    LOGD("ebpf: BTF vfs: task.files +%u, files.fdt +%u, fdt.max_fds +%u, "
         "fdt.fd +%u, file.private_data +%u, file.f_path +%u, path.dentry +%u, "
         "dentry.d_name +%u, qstr.name +%u, hlist.first +%u, hlist.next +%u",
         out->task_files, out->files_fdt, out->fdtable_max_fds,
         out->fdtable_fd, out->file_private_data, out->file_f_path,
         out->path_dentry, out->dentry_d_name, out->qstr_name,
         out->hlist_head_first, out->hlist_node_next);
    LOGD("ebpf: BTF kvm: memslots +%u (%u x %u B), online_vcpus +%u, "
         "userspace_pid +%u | memslots: generation +%u, id_hash +%u (%u), "
         "node_idx +%u | slot: id_node +%u (%u B), base_gfn +%u, npages +%u, "
         "userspace_addr +%u, flags +%u, id +%u",
         out->kvm_memslots, out->kvm_memslots_count, out->kvm_memslots_stride,
         out->kvm_online_vcpus, out->kvm_userspace_pid,
         out->ms_generation, out->ms_id_hash, out->hash_buckets,
         out->ms_node_idx, out->slot_id_node, out->slot_id_node_stride,
         out->slot_base_gfn, out->slot_npages, out->slot_userspace_addr,
         out->slot_flags, out->slot_id);
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Kto je tu vlastne VM: /proc/<pid>/fd -> anon_inode:kvm-vm           */
/* ------------------------------------------------------------------ */
/*
 * Kazdy proces, ktory ma otvorenu VM, drzi deskriptor s anonymnym inode
 * menom "kvm-vm" (virt/kvm/kvm_main.c). Je to najspolahlivejsi priznak
 * "toto je hypervizor": nezavisi na mene procesu, funguje rovnako pre
 * QEMU, crosvm aj cokolvek dalsie, a nepotrebuje libvirt.
 *
 * Meno domeny berieme z prikazoveho riadku (-name guest=win10,...), cize
 * presne to, pod akym VM pozna aj libvirt - ale bez zavislosti na nom.
 */

typedef struct {
    uint32_t pid;
    uint32_t fd;      /* deskriptor "kvm-vm" - tip pre BPF program */
    char     name[VMIC_NAME_MAX];
    char     comm[64];
} vmcand_t;

/* Vrati cislo deskriptora "kvm-vm", alebo -1 ked proces ziadny nema. */
static long proc_kvm_fd(const char *pid)
{
    char dirpath[64];
    snprintf(dirpath, sizeof(dirpath), "/proc/%s/fd", pid);

    DIR *d = opendir(dirpath);
    if (!d) return -1;

    long found = -1;
    struct dirent *e;
    while (found < 0 && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char link[VMIC_PATH_MAX], target[128];
        snprintf(link, sizeof(link), "%s/%s", dirpath, e->d_name);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = '\0';
        if (strcmp(target, "anon_inode:kvm-vm") == 0)
            found = strtol(e->d_name, NULL, 10);
    }
    closedir(d);
    return found;
}

/* Vytiahne "-name guest=X,..." alebo "-name X" z prikazoveho riadku. */
static void guest_name_from_cmdline(const char *pid, char *out, size_t n)
{
    char path[64], buf[4096];
    out[0] = '\0';

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t got = vmic_read_full(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) return;
    buf[got] = '\0';

    for (ssize_t i = 0; i < got; ) {
        const char *arg = buf + i;
        size_t len = strlen(arg);
        i += (ssize_t)len + 1;
        if (strcmp(arg, "-name") != 0 || i >= got) continue;

        const char *val = buf + i;
        if (strncmp(val, "guest=", 6) == 0) val += 6;
        snprintf(out, n, "%s", val);
        char *comma = strchr(out, ',');     /* guest=win10,debug-threads=on */
        if (comma) *comma = '\0';
        return;
    }
}

static void read_comm(const char *pid, char *out, size_t n)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    out[0] = '\0';
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t got = vmic_read_full(fd, out, n - 1);
    close(fd);
    if (got <= 0) { out[0] = '\0'; return; }
    out[got] = '\0';
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
}

static size_t scan_vms(vmcand_t *out, size_t max)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        LOGE("ebpf: nedaji sa citat /proc: %s", strerror(errno));
        return 0;
    }

    size_t n = 0;
    struct dirent *e;
    while (n < max && (e = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;

        long fd = proc_kvm_fd(e->d_name);
        if (fd < 0) continue;

        out[n].pid = (uint32_t)strtoul(e->d_name, NULL, 10);
        out[n].fd  = (uint32_t)fd;
        guest_name_from_cmdline(e->d_name, out[n].name, sizeof(out[n].name));
        read_comm(e->d_name, out[n].comm, sizeof(out[n].comm));
        if (!out[n].name[0])
            snprintf(out[n].name, sizeof(out[n].name), "pid:%u", out[n].pid);
        n++;
    }
    closedir(proc);
    return n;
}

/*
 * Vyber domeny podla vm.domain:
 *   prazdne     -> ked bezi prave jedna VM, vezmi ju
 *   "pid:1234"  -> podla pid
 *   "1234"      -> to iste
 *   ine         -> podla mena z prikazoveho riadku (presne, inak podretazec)
 */
static int pick_vm(const char *domain, vmcand_t *out)
{
    vmcand_t cand[64];
    size_t n = scan_vms(cand, sizeof(cand) / sizeof(cand[0]));

    if (!n) {
        LOGE("ebpf: na tomto stroji nebezi ziadna KVM domena "
             "(ziadny proces nema otvoreny /dev/kvm)");
        if (geteuid() != 0)
            LOGE("ebpf: pozor, bezis ako uid %u - cudzie /proc/<pid>/fd "
                 "vidi iba root", (unsigned)geteuid());
        return VMIC_FATAL;
    }

    if (!domain || !domain[0]) {
        if (n == 1) {
            *out = cand[0];
            LOGI("ebpf: vm.domain nie je zadane, beri jedinu bezicu domenu "
                 "'%s' (pid %u)", cand[0].name, cand[0].pid);
            return VMIC_OK;
        }
        LOGE("ebpf: bezi %zu domen, vyber jednu cez vm.domain:", n);
        for (size_t i = 0; i < n; i++)
            LOGE("   %-32s pid %u (%s)", cand[i].name, cand[i].pid,
                 cand[i].comm);
        return VMIC_FATAL;
    }

    /* podla pid */
    const char *num = domain;
    if (strncmp(domain, "pid:", 4) == 0) num = domain + 4;
    if (num[0] && strspn(num, "0123456789") == strlen(num)) {
        uint32_t pid = (uint32_t)strtoul(num, NULL, 10);
        for (size_t i = 0; i < n; i++)
            if (cand[i].pid == pid) { *out = cand[i]; return VMIC_OK; }
        LOGE("ebpf: proces %u nema otvorenu ziadnu KVM domenu", pid);
        return VMIC_FATAL;
    }

    for (size_t i = 0; i < n; i++)
        if (strcmp(cand[i].name, domain) == 0) { *out = cand[i]; return VMIC_OK; }

    /* podretazec - pomaha, ked libvirt prilepi k menu este nieco */
    ssize_t hit = -1;
    for (size_t i = 0; i < n; i++) {
        if (!strstr(cand[i].name, domain)) continue;
        if (hit >= 0) {
            LOGE("ebpf: '%s' sedi na viac domen, zadaj presne meno alebo pid",
                 domain);
            return VMIC_FATAL;
        }
        hit = (ssize_t)i;
    }
    if (hit >= 0) { *out = cand[hit]; return VMIC_OK; }

    LOGE("ebpf: domenu '%s' som nenasiel; bezia:", domain);
    for (size_t i = 0; i < n; i++)
        LOGE("   %-32s pid %u (%s)", cand[i].name, cand[i].pid, cand[i].comm);
    return VMIC_FATAL;
}

/* ------------------------------------------------------------------ */
/* Cim je pamat hosta podlozena                                        */
/* ------------------------------------------------------------------ */
/*
 * Toto nie je kozmetika, ale jediny sposob, ako sa vyhnut tichemu
 * poskodeniu merania:
 *
 * Citanie ide cez access_process_vm(), cize sa sprava ako obycajny
 * pristup do pamate procesu. Pri ANONYMNOM mapovani (vychodzie QEMU bez
 * -mem-path a bez memory-backend-memfd) je citanie stranky, ktorej sa
 * host este nedotkol, zadarmo: jadro namapuje spolocnu nulovu stranku a
 * hostitelovi nepribudne ani bajt.
 *
 * Pri shmem podlozeni (memfd, /dev/shm, hugetlbfs) to NEPLATI - tam
 * citanie diery stranku naozaj vytvori. Zberac by tak postupne "nafukol"
 * VM na plnu velkost RAM, co je presny opak minimalizacie vplyvu na
 * bezici stroj. Preto to zistime hned na zaciatku a povieme nahlas.
 */
static void warn_backing(ebpf_priv_t *p)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", p->pid);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;

    /* maps sa musi citat naraz - je to "zivy" subor a medzi read()-mi sa
       moze zmenit. 1 MiB je na QEMU s prehladom dost. */
    size_t cap = 1u << 20;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return; }
    ssize_t got = vmic_read_full(fd, buf, cap - 1);
    close(fd);
    if (got <= 0) { free(buf); return; }
    buf[got] = '\0';

    uint64_t shared_bytes = 0;
    char example[128] = "";

    for (uint32_t i = 0; i < p->info.nslots; i++) {
        uint64_t hva = p->info.slots[i].userspace_addr;

        for (char *line = buf, *nl; line && *line; line = nl ? nl + 1 : NULL) {
            nl = strchr(line, '\n');
            if (nl) *nl = '\0';

            /*
             * Format riadku: zaciatok-koniec prava offset zar:iad inode
             * [cesta]. Pri anonymnej pamati cesta chyba uplne - preto sa
             * pozicia za inode berie cez %n a nie hladanim medzery
             * (cesta moze obsahovat medzery aj zatvorky "(deleted)").
             */
            unsigned long start = 0, end = 0, foff = 0, inode = 0;
            char perms[8], dev[16];
            int pos = 0;
            bool hit = false;

            if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                       &start, &end, perms, &foff, dev, &inode, &pos) == 6) {
                hit = (hva >= start && hva < end);
                if (hit) {
                    const char *name = (pos > 0) ? line + pos : "";
                    /* iba skutocna cesta znamena shmem/subor; [heap] a
                       spol. su stale anonymna pamat */
                    if (name[0] == '/') {
                        shared_bytes += p->info.slots[i].npages
                                        << VMIC_BPF_PAGE_SHIFT;
                        if (!example[0])
                            snprintf(example, sizeof(example), "%s", name);
                    }
                }
            }
            if (nl) *nl = '\n';
            if (hit) break;
        }
    }
    free(buf);

    if (shared_bytes) {
        char human[32];
        vmic_human_size(shared_bytes, human, sizeof(human));
        LOGW("ebpf: %s pamate hosta nie je anonymna (%s) - citanie stranky, "
             "ktorej sa host este nedotkol, ju hostitelovi NAOZAJ alokuje",
             human, example);
        LOGW("ebpf: pri takejto VM zbieraj radsej konkretne oblasti "
             "(capture.regions), nech nenafuknes jej pamat na plnu velkost");
    }
}

/* ------------------------------------------------------------------ */
/* Nacitanie BPF programu                                              */
/* ------------------------------------------------------------------ */

static int load_bpf(ebpf_priv_t *p, const char *path_override)
{
    const void *blob = NULL;
    size_t blob_len = 0;

    /*
     * Najprv BTF, az potom jadro. Je to lacne, nepotrebuje to ziadne
     * privilegia a ked sa rozlozenie struktur v jadre nezhoduje, chyba
     * povie meno pola - to je uzitocnejsie nez hlaska verifikatora o
     * instrukcii c. 214.
     */
    struct vmic_bpf_koff koff;
    int rc = resolve_offsets(&koff);
    if (rc != VMIC_OK) return rc;

    if (path_override && path_override[0]) {
        int64_t sz = vmic_file_size(path_override);
        int fd = open(path_override, O_RDONLY | O_CLOEXEC);
        if (sz <= 0 || fd < 0) {
            LOGE("ebpf: '%s' sa neda nacitat: %s", path_override,
                 strerror(errno));
            if (fd >= 0) close(fd);
            return VMIC_FATAL;
        }
        p->blob = malloc((size_t)sz);
        if (!p->blob) { close(fd); return VMIC_FATAL; }
        if (vmic_read_full(fd, p->blob, (size_t)sz) != (ssize_t)sz) {
            LOGE("ebpf: '%s' sa nedal docitat", path_override);
            close(fd);
            return VMIC_FATAL;
        }
        close(fd);
        p->blob_size = (size_t)sz;
        blob = p->blob;
        blob_len = p->blob_size;
        LOGI("ebpf: BPF program z '%s' (%zu B)", path_override, blob_len);
    } else {
        const unsigned char *bstart = _binary_vmic_kvm_bpf_o_start;
        const unsigned char *bend   = _binary_vmic_kvm_bpf_o_end;
        if (!bstart || !bend || bend <= bstart) {
            LOGE("ebpf: binarka neobsahuje BPF program - prelozil si to "
                 "bez clangu? (skus `make bpf` alebo vm.bpf_object=cesta)");
            return VMIC_FATAL;
        }
        blob = bstart;
        blob_len = (size_t)(bend - bstart);
    }

    libbpf_set_print(libbpf_to_log);

    LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "vmic_kvm");
    p->obj = bpf_object__open_mem(blob, blob_len, &oo);
    if (!p->obj) {
        LOGE("ebpf: BPF objekt sa nedal otvorit: %s", strerror(errno));
        return VMIC_FATAL;
    }

    struct bpf_program *pr_probe =
        bpf_object__find_program_by_name(p->obj, "vmic_probe");
    struct bpf_program *pr_read =
        bpf_object__find_program_by_name(p->obj, "vmic_read");
    if (!pr_probe || !pr_read) {
        LOGE("ebpf: v objekte chyba vmic_probe alebo vmic_read");
        return VMIC_FATAL;
    }

    /*
     * bpf_copy_from_user_task() smie volat iba "sleepable" program - inak
     * ho verifikator odmietne s tym, ze helper moze spat. libbpf priznak
     * pre SEC("syscall") nastavuje sam, ale nastavime ho aj tu: je to
     * idempotentne a usetri to hodinu hladania, keby to raz prestal robit.
     */
    bpf_program__set_flags(pr_probe,
                           bpf_program__flags(pr_probe) | BPF_F_SLEEPABLE);
    bpf_program__set_flags(pr_read,
                           bpf_program__flags(pr_read) | BPF_F_SLEEPABLE);

    if (bpf_object__load(p->obj) != 0) {
        LOGE("ebpf: BPF program sa nepodarilo nacitat do jadra: %s",
             strerror(errno));
        if (geteuid() != 0)
            LOGE("ebpf: nacitanie BPF programu vyzaduje roota "
                 "(alebo CAP_BPF+CAP_PERFMON) - skus `sudo`");
        return VMIC_FATAL;
    }

    p->fd_probe  = bpf_program__fd(pr_probe);
    p->fd_read   = bpf_program__fd(pr_read);
    p->map_koff  = bpf_map__fd(bpf_object__find_map_by_name(p->obj, "koff"));
    p->map_slots = bpf_map__fd(bpf_object__find_map_by_name(p->obj, "slots"));
    p->map_pages = bpf_map__fd(bpf_object__find_map_by_name(p->obj, "pages"));

    if (p->fd_probe < 0 || p->fd_read < 0 || p->map_koff < 0 ||
        p->map_slots < 0 || p->map_pages < 0) {
        LOGE("ebpf: BPF objekt nema vsetky programy a mapy");
        return VMIC_FATAL;
    }

    /*
     * Mapa `pages` je BPF_F_MMAPABLE, takze si ju namapujeme priamo do
     * svojho adresneho priestoru. Stranky hosta tak prekrocia hranicu
     * jadro/userspace presne raz - v jadre sa zapisu do tejto mapy a my
     * ich odtial iba precitame.
     */
    p->win_size = VMIC_BPF_MAX_CHUNK;
    p->win = mmap(NULL, p->win_size, PROT_READ, MAP_SHARED, p->map_pages, 0);
    if (p->win == MAP_FAILED) {
        p->win = NULL;
        LOGE("ebpf: mapa `pages` sa neda mmap-nut: %s", strerror(errno));
        return VMIC_FATAL;
    }

    __u32 zero = 0;
    if (bpf_map_update_elem(p->map_koff, &zero, &koff, BPF_ANY) != 0) {
        LOGE("ebpf: offsety sa nedali poslat do jadra: %s", strerror(errno));
        return VMIC_FATAL;
    }
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Spustanie BPF programov                                             */
/* ------------------------------------------------------------------ */
/*
 * SEC("syscall") program sa spusta cez BPF_PROG_TEST_RUN. Napriek menu to
 * nie je testovacie rozhranie: je to jediny sposob, ako si zavolat BPF
 * program vtedy, ked chceme MY - bez toho, aby sme ho vesali na nejaku
 * jadrovu udalost. Vysledok jadro skopiruje SPAT do toho isteho buffra
 * (ctx_in), ctx_out sa pri tomto type programu pouzit neda.
 */
static int run_prog(int prog_fd, void *ctx, size_t ctx_size, const char *what)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .ctx_in = ctx,
                .ctx_size_in = (__u32)ctx_size);

    if (bpf_prog_test_run_opts(prog_fd, &opts) != 0) {
        LOGE("ebpf: %s sa nepodarilo spustit: %s", what, strerror(errno));
        return VMIC_ERR;
    }
    return VMIC_OK;
}

static const char *bpf_err_text(int32_t err)
{
    switch (err) {
    case VMIC_BPF_E_OK:      return "ok";
    case VMIC_BPF_E_NOTASK:  return "proces uz nezije";
    case VMIC_BPF_E_NOFILES: return "proces nema tabulku deskriptorov";
    case VMIC_BPF_E_NOKVM:   return "proces uz nema otvorenu VM";
    case VMIC_BPF_E_NOSLOTS: return "VM nema citatelnu pamat";
    case VMIC_BPF_E_TRUNC:   return "VM ma viac memslotov, nez vieme spracovat";
    case VMIC_BPF_E_RACE:    return "mapa pamate sa prave meni";
    case VMIC_BPF_E_NOMAP:   return "interna chyba: chyba BPF mapa";
    case VMIC_BPF_E_RANGE:   return "neplatny rozsah";
    default:                 return "neznama chyba";
    }
}

/* Znovu precita memsloty. Vola sa na zaciatku kazdeho cyklu - VM moze
   medzitym pridat pamat, zhasnut alebo sa presunut. */
static int refresh_slots(vmic_backend_t *b, bool verbose)
{
    ebpf_priv_t *p = (ebpf_priv_t *)b->priv;

    struct vmic_bpf_probe_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pid     = p->pid;
    ctx.as_id   = 0;                /* normalny adresny priestor, nie SMM */
    ctx.fd_hint = p->fd_hint;

    /*
     * Priznak zhasiname UZ TERAZ. Ked cokolvek nizsie zlyha, nesmie sa
     * citat podla tabulky z minuleho cyklu: pid sa medzitym mohol
     * recyklovat a HVA by potom ukazovali do pamate cudzieho procesu.
     */
    p->have_info = false;

    int rc = run_prog(p->fd_probe, &ctx, sizeof(ctx), "vmic_probe");
    if (rc != VMIC_OK) return rc;

    if (ctx.err != VMIC_BPF_E_OK && ctx.err != VMIC_BPF_E_TRUNC) {
        LOGE("ebpf: domena '%s' (pid %u): %s", p->name, p->pid,
             bpf_err_text(ctx.err));
        return (ctx.err == VMIC_BPF_E_NOTASK || ctx.err == VMIC_BPF_E_NOKVM)
                   ? VMIC_FATAL : VMIC_ERR;
    }
    if (ctx.err == VMIC_BPF_E_TRUNC)
        LOGW("ebpf: VM ma viac ako %u memslotov, zvysok sa zbierat nebude",
             VMIC_BPF_MAX_SLOTS);

    __u32 zero = 0;
    if (bpf_map_lookup_elem(p->map_slots, &zero, &p->info) != 0) {
        LOGE("ebpf: tabulka slotov sa nedala precitat: %s", strerror(errno));
        return VMIC_ERR;
    }
    p->have_info = true;

    if (verbose || p->info.generation != p->last_generation) {
        char human[32];
        vmic_human_size(p->info.total_pages * VMIC_BPF_PAGE_SIZE,
                        human, sizeof(human));
        LOGI("ebpf: '%s' (pid %u): %u memslotov, %s pamate, "
             "max GPA 0x%" PRIx64 "%s",
             p->name, p->pid, p->info.nslots, human,
             (uint64_t)(p->info.max_gfn << VMIC_BPF_PAGE_SHIFT),
             p->last_generation && p->info.generation != p->last_generation
                 ? " (mapa pamate sa zmenila)" : "");
        for (uint32_t i = 0; i < p->info.nslots; i++)
            LOGD("   slot %2d: GPA 0x%012" PRIx64 "-0x%012" PRIx64
                 "  HVA 0x%" PRIx64 "  flags 0x%x",
                 p->info.slots[i].id,
                 (uint64_t)(p->info.slots[i].base_gfn << VMIC_BPF_PAGE_SHIFT),
                 (uint64_t)(((p->info.slots[i].base_gfn +
                              p->info.slots[i].npages)
                             << VMIC_BPF_PAGE_SHIFT) - 1),
                 (uint64_t)p->info.slots[i].userspace_addr,
                 p->info.slots[i].flags);
        if (p->info.skipped)
            LOGW("ebpf: %u slotov sa cez adresny priestor VMM precitat neda "
                 "(guest_memfd / prave sa meni) - budu nulove",
                 p->info.skipped);
    }
    p->last_generation = p->info.generation;
    return VMIC_OK;
}

/* ------------------------------------------------------------------ */
/* Operacie backendu                                                   */
/* ------------------------------------------------------------------ */

static int eb_open(vmic_backend_t *b)
{
    ebpf_priv_t *p = (ebpf_priv_t *)b->priv;
    if (p->obj) return VMIC_OK;

    vmcand_t vm;
    int rc = pick_vm(b->cfg->domain, &vm);
    if (rc != VMIC_OK) return rc;

    p->pid     = vm.pid;
    p->fd_hint = vm.fd;
    snprintf(p->name, sizeof(p->name), "%s", vm.name);

    rc = load_bpf(p, b->cfg->bpf_object);
    if (rc != VMIC_OK) return rc;

    rc = refresh_slots(b, true);
    if (rc != VMIC_OK) return VMIC_FATAL;

    warn_backing(p);

    if (b->cfg->pause)
        LOGW("ebpf: capture.pause sa ignoruje - eBPF vie citat, nie riadit "
             "hypervizor; snimka bude 'ziva' (stranky su z roznych okamihov)");
    return VMIC_OK;
}

static void eb_close(vmic_backend_t *b)
{
    ebpf_priv_t *p = (ebpf_priv_t *)b->priv;
    if (p->win) { munmap(p->win, p->win_size); p->win = NULL; }
    if (p->obj) { bpf_object__close(p->obj); p->obj = NULL; }
    free(p->blob);
    p->blob = NULL;
}

/*
 * Memsloty -> zoznam namapovanych usekov GPA, zoradeny a zluceny.
 *
 * Zberacu to setri viac, nez sa zda: bez toho by sa kazdy cyklus citala
 * (a pri delta zbere aj hashovala) cela diera medzi poslednou RAM pod
 * 4 GiB a pamatou nad 4 GiB - pri beznej 4 GiB VM su to 2 GiB nul v
 * kazdej snimke. Naviac by kazdy taky blok skoncil v statistike ako
 * "chyba citania", hoci ide o uplne zdravy stroj.
 */
static size_t ram_ranges(const struct vmic_bpf_vminfo *info,
                         vmic_region_t *out, size_t max)
{
    vmic_region_t tmp[VMIC_BPF_MAX_SLOTS];
    size_t n = 0;

    for (uint32_t i = 0; i < info->nslots && i < VMIC_BPF_MAX_SLOTS; i++) {
        tmp[n].start = (uint64_t)info->slots[i].base_gfn << VMIC_BPF_PAGE_SHIFT;
        tmp[n].size  = (uint64_t)info->slots[i].npages   << VMIC_BPF_PAGE_SHIFT;
        n++;
    }

    /* sloty chodia v poradi hash tabulky, nie podla adresy */
    for (size_t i = 1; i < n; i++) {
        vmic_region_t key = tmp[i];
        size_t j = i;
        while (j > 0 && tmp[j - 1].start > key.start) {
            tmp[j] = tmp[j - 1];
            j--;
        }
        tmp[j] = key;
    }

    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t end = tmp[i].start + tmp[i].size;

        if (k && tmp[i].start <= out[k - 1].start + out[k - 1].size) {
            uint64_t prev_end = out[k - 1].start + out[k - 1].size;
            if (end > prev_end) out[k - 1].size = end - out[k - 1].start;
            continue;
        }
        if (k >= max) break;      /* nemoze nastat: max >= poc. slotov */
        out[k++] = tmp[i];
    }
    return k;
}

static int eb_probe(vmic_backend_t *b, vmic_vminfo_t *out)
{
    ebpf_priv_t *p = (ebpf_priv_t *)b->priv;

    if (!p->have_info) {
        int rc = refresh_slots(b, true);
        if (rc != VMIC_OK) return rc;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->domain, sizeof(out->domain), "%s", p->name);
    snprintf(out->backend, sizeof(out->backend), "ebpf/kvm");
    out->vmid          = p->pid;
    out->has_vmid      = true;
    out->memsize       = p->info.total_pages << VMIC_BPF_PAGE_SHIFT;
    out->has_memsize   = true;
    out->max_paddr     = p->info.max_gfn << VMIC_BPF_PAGE_SHIFT;
    out->has_max_paddr = true;
    out->num_vcpus     = p->info.online_vcpus;
    out->has_vcpus     = p->info.online_vcpus > 0;
    out->ram_count     = ram_ranges(&p->info, out->ram, VMIC_MAX_REGIONS);
    /* Preklad virtualnych adries tento backend nerobi - zbiera fyzicky
       priestor tak, ako ho vidi hypervizor. */
    snprintf(out->page_mode, sizeof(out->page_mode), "n/a");
    return VMIC_OK;
}

/*
 * Zaciatok cyklu: znovu si vypytat mapu pamate. Nie je to formalita -
 * VM medzitym mohla dostat pamat navyse, presunut BAR zariadenia, alebo
 * uplne zhasnut. Zberac bezi tyzdne, VM sa restartuje kazdy den.
 */
static int eb_begin_cycle(vmic_backend_t *b)
{
    ebpf_priv_t *p = (ebpf_priv_t *)b->priv;

    int rc = refresh_slots(b, false);
    if (rc != VMIC_FATAL) return rc;

    /*
     * Domena zmizla. Mohla sa vsak iba restartovat - vtedy bezi pod novym
     * pid. Hladame ju POVODNYM vyberom (vm.domain), nie odvodenym menom:
     * VM bez -name dostane synteticke meno "pid:1234", takze hladanim
     * podla neho by sme po restarte hladali mrtvy pid a este by sme sa
     * mohli chytit na cudzi proces, ktory ten pid medzitym dostal.
     * Prazdne vm.domain znamena "jedina bezica" - a to plati aj teraz.
     */
    vmcand_t vm;
    if (pick_vm(b->cfg->domain, &vm) != VMIC_OK) return VMIC_ERR;
    if (vm.pid == p->pid) return VMIC_ERR;

    LOGW("ebpf: domena '%s' bezi pod novym pid %u (predtym %u) - "
         "pripajam sa nanovo", p->name, vm.pid, p->pid);
    p->pid     = vm.pid;
    p->fd_hint = vm.fd;
    snprintf(p->name, sizeof(p->name), "%s", vm.name);
    p->last_generation = 0;
    return refresh_slots(b, true);
}

/*
 * read_pa: jedno volanie BPF programu obsluzi suvisly usek vnutri jedneho
 * memslotu, najviac VMIC_BPF_MAX_CHUNK. Cyklus nizsie preto beha dovtedy,
 * kym nie je cely blok hotovy - hranice slotov aj diery si program riesi
 * sam a nam vracia, kolko toho pokryl.
 *
 * Kontrakt (viz vmic.h): buffer sa MUSI vyplnit cely, diery nulami, a
 * vratit sa ma pocet naozaj precitanych bajtov.
 */
static int64_t eb_read_pa(vmic_backend_t *b, uint64_t paddr,
                          void *buf, size_t len)
{
    ebpf_priv_t *p = (ebpf_priv_t *)b->priv;
    uint8_t *out = (uint8_t *)buf;
    uint64_t done = 0, really_read = 0;

    if (!p->have_info) {
        LOGE("ebpf: tabulka memslotov nie je platna");
        return -1;
    }

    while (done < len) {
        if (b->stop && *b->stop) {          /* Ctrl-C aj uprostred bloku */
            memset(out + done, 0, len - done);
            break;
        }

        uint64_t cur  = paddr + done;
        uint64_t page = cur & ~(uint64_t)(VMIC_BPF_PAGE_SIZE - 1);
        uint32_t skip = (uint32_t)(cur - page);   /* nezarovnany zaciatok */
        uint64_t need = (uint64_t)skip + (len - done);
        uint64_t npages = (need + VMIC_BPF_PAGE_SIZE - 1) / VMIC_BPF_PAGE_SIZE;

        if (npages > VMIC_BPF_MAX_PAGES) npages = VMIC_BPF_MAX_PAGES;

        struct vmic_bpf_read_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.pid    = p->pid;
        ctx.npages = (uint32_t)npages;
        ctx.gpa    = page;

        if (run_prog(p->fd_read, &ctx, sizeof(ctx), "vmic_read") != VMIC_OK)
            return -1;

        if (ctx.err != VMIC_BPF_E_OK) {
            LOGE("ebpf: citanie 0x%" PRIx64 ": %s", page,
                 bpf_err_text(ctx.err));
            return -1;
        }
        /*
         * Poistka: `served` riadi aj memcpy z mmap okna. Nula by znamenala
         * nekonecny cyklus, vacsia hodnota nez sme pytali by citala za
         * koncom okna. Ani jedno by sa stat nemalo - o to viac to chceme
         * vediet hned a nie az podla poskodenej snimky.
         */
        if (!ctx.served || ctx.served > npages) {
            LOGE("ebpf: BPF program vratil na 0x%" PRIx64 " nezmyselny pocet "
                 "stranok (%u z %" PRIu64 ")", page, ctx.served, npages);
            return -1;
        }

        /* kolko z tohto behu naozaj patri volajucemu */
        uint64_t span = (uint64_t)ctx.served * VMIC_BPF_PAGE_SIZE;
        uint64_t take = span - skip;
        if (take > len - done) take = len - done;

        if (ctx.kind == VMIC_BPF_KIND_HOLE) {
            /* Diera vo fyzickom priestore (PCI hole, MMIO, nenamapovany
               rozsah). Vyplnime nulami a citame dalej - preskocit, nie sa
               zastavit. */
            memset(out + done, 0, take);
        } else {
            memcpy(out + done, p->win + skip, take);

            /*
             * Pocitame STRATENE bajty a nie uspesne stranky: `copied` sa
             * rata od zaciatku stranky, kdezto `take` od `page + skip`,
             * takze pri nezarovnanej poziadavke by "uspesne * 4096"
             * pohltilo celu chybnu stranku a vmic_capture by nulami
             * vyplneny blok povazoval za uplne precitany.
             */
            uint64_t lost = (uint64_t)(ctx.served - ctx.copied)
                            * VMIC_BPF_PAGE_SIZE;
            really_read += take - (lost > take ? take : lost);

            if (ctx.copied < ctx.served)
                LOGD("ebpf: 0x%" PRIx64 ": %u z %u stranok necitatelnych "
                     "(prva na +0x%x)", page, ctx.served - ctx.copied,
                     ctx.served, ctx.first_fail << VMIC_BPF_PAGE_SHIFT);
        }
        done += take;
    }
    return (int64_t)really_read;
}

/* ------------------------------------------------------------------ */
/* Tabulka operacii                                                    */
/* ------------------------------------------------------------------ */
/*
 * pause/resume su zamerne NULL: eBPF je pozorovacie, nie riadiace
 * rozhranie hypervizora. collector.c si chybajuci pause() vsimne a
 * pauzu vobec nemeria (inak by ako "cas, ked VM stala" vykazal cely cas
 * citania - a to by bola v metadatach cista vymyslenina).
 */
const vmic_backend_ops_t vmic_backend_ebpf = {
    .name          = "ebpf",
    .random_access = true,
    .ext           = ".raw",
    .open          = eb_open,
    .close         = eb_close,
    .probe         = eb_probe,
    .pause         = NULL,
    .resume        = NULL,
    .begin_cycle   = eb_begin_cycle,
    .read_pa       = eb_read_pa,
    .dump_to       = NULL,
};

int vmic_backend_ebpf_alloc(vmic_backend_t *b)
{
    ebpf_priv_t *p = calloc(1, sizeof(ebpf_priv_t));
    if (!p) return VMIC_FATAL;
    p->fd_probe = p->fd_read = -1;
    p->map_koff = p->map_slots = p->map_pages = -1;
    b->priv = p;
    return VMIC_OK;
}

#else  /* !VMIC_HAVE_EBPF */

static int eb_unavailable(vmic_backend_t *b)
{
    (void)b;
    LOGE("backend 'ebpf' nie je v tomto builde - chybal clang alebo libbpf");
    LOGE("nainstaluj ich (dnf install clang libbpf-devel) a prelozi to znovu");
    return VMIC_FATAL;
}

const vmic_backend_ops_t vmic_backend_ebpf = {
    .name          = "ebpf",
    .random_access = true,
    .ext           = ".raw",
    .open          = eb_unavailable,
    .close         = NULL,
    .probe         = NULL,
    .pause         = NULL,
    .resume        = NULL,
    .begin_cycle   = NULL,
    .read_pa       = NULL,
    .dump_to       = NULL,
};

int vmic_backend_ebpf_alloc(vmic_backend_t *b)
{
    b->priv = calloc(1, 1);
    return b->priv ? VMIC_OK : VMIC_FATAL;
}

#endif /* VMIC_HAVE_EBPF */
