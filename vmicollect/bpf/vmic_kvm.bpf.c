/*
 * vmic_kvm.bpf.c - jadrova cast zberaca: cita pamat KVM hosta z vnutra jadra.
 *
 * PRECO VOBEC BPF, KED SA DA CITAT AJ ZVONKA
 * ------------------------------------------
 * Pamat hosta zije v adresnom priestore procesu QEMU. Samotne bajty by sa
 * dali vytiahnut aj cez process_vm_readv(), lenze zvonka sa neda zistit to
 * podstatne: KTORA cast toho procesu je ktora FYZICKA adresa hosta. Tuto
 * tabulku (GPA -> HVA) drzi modul kvm vo svojich memslotoch a von ju
 * neposkytuje ziadnym rozhranim. Bez nej by zberac musel hadat z
 * /proc/<pid>/maps, alebo si vypytat patchnute QEMU / KVMi socket - presne
 * tomu sa chceme vyhnut.
 *
 * BPF program preto robi dve veci, ktore userspace spravit nevie:
 *
 *   vmic_probe  najde v procese VMM deskriptor "kvm-vm", z neho struct kvm
 *               a prejde hash tabulku memslotov -> presna mapa GPA -> HVA
 *   vmic_read   prelozi GPA na HVA a skopiruje stranky z adresneho
 *               priestoru VMM do mmap-nuteho buffra zberaca
 *
 * Oba su SEC("syscall"), takze ich zberac spusta sam cez bpf_prog_test_run()
 * presne vtedy, ked ma naplanovany termin - ziadny tracepoint sa nevesa na
 * horuce cesty KVM a bezica VM o nas nevie.
 *
 * ROZLOZENIE JADROVYCH STRUKTUR SA TU NEPREKLADA
 * ----------------------------------------------
 * Program nepozna ani jednu jadrovu strukturu; vsetky offsety dostane v
 * mape `koff`. Zberac ich vycita z BTF, ktore ma jadro o sebe samom
 * (/sys/kernel/btf/vmlinux a /sys/kernel/btf/kvm). Dosledok: nepotrebujeme
 * vmlinux.h ani bpftool a program prezije aj presun poli v novom jadre -
 * a ked nejake pole zmizne uplne, zberac to povie menom.
 *
 * BEZPECNOST UKAZOVATELOV
 * -----------------------
 * `struct kvm *` sa NIKDY neuklada medzi behmi. Kazdy beh si ho znovu najde
 * cez tabulku deskriptorov procesu, a to pod bpf_rcu_read_lock() - fdtable
 * aj struct file sa uvolnuju cez RCU, takze pod tymto zamkom nam nezmiznu
 * pod rukami. Citanie samotnej pamate uz ziadny jadrovy ukazovatel
 * nepouziva: bezi nad kopiou tabulky slotov v mape `slots`.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "vmic_bpf_abi.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/* kfunkcie jadra                                                      */
/* ------------------------------------------------------------------ */
/* Su registrovane pre BPF_PROG_TYPE_UNSPEC, cize dostupne kazdemu typu
   programu. bpf_task_from_vpid() vracia zapocitanu referenciu - verifikator
   trva na tom, aby ju kazda cesta programu vratila cez bpf_task_release(). */
extern struct task_struct *bpf_task_from_vpid(__s32 vpid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* ------------------------------------------------------------------ */
/* Mapy                                                                */
/* ------------------------------------------------------------------ */

/* offsety jadrovych struktur; naplna zberac hned po nacitani */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vmic_bpf_koff);
} koff SEC(".maps");

/* tabulka GPA -> HVA; zapisuje vmic_probe, cita vmic_read aj zberac */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vmic_bpf_vminfo);
} slots SEC(".maps");

/*
 * Prenosovy buffer. BPF_F_MMAPABLE znamena, ze si ho zberac mmap-ne a cita
 * priamo z neho - stranky hosta teda prejdu hranicou jadro/userspace
 * PRESNE RAZ (copy_from_user v kontexte VMM -> tato mapa). Ziadny ringbuf,
 * ziadne kopirovanie navyse.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_MMAPABLE);
    __type(key, __u32);
    __uint(value_size, VMIC_BPF_MAX_CHUNK);
} pages SEC(".maps");

/* ------------------------------------------------------------------ */
/* Pomocne                                                             */
/* ------------------------------------------------------------------ */

/* Citanie jadrovej pamate je vzdy "moze zlyhat" - preto bpf_probe_read_*,
   ktore pri neplatnej adrese vrati chybu namiesto oopsu. */
#define RDK(dst, sz, addr) \
    bpf_probe_read_kernel((dst), (sz), (const void *)(unsigned long)(addr))

/* Je za deskriptorom `i` nasa VM? Vrati struct kvm, alebo 0. */
static __always_inline __u64 kvm_from_fd(__u64 fdarr, __u32 i,
                                         const struct vmic_bpf_koff *k)
{
    __u64 file = 0, dentry = 0, name = 0, kvm = 0;
    char nm[8];

    if (RDK(&file, 8, fdarr + (__u64)i * 8) || !file) return 0;
    if (RDK(&dentry, 8, file + k->file_f_path + k->path_dentry) || !dentry)
        return 0;
    if (RDK(&name, 8, dentry + k->dentry_d_name + k->qstr_name) || !name)
        return 0;

    /* Nazov citame ako retazec: pri "kvm-vm-stats" sa do 8 bajtov
       nezmesti aj s koncovou nulou a helper vrati chybu, takze sa na
       podobne meno nechytime. */
    if (bpf_probe_read_kernel_str(nm, sizeof(nm),
                                  (const void *)(unsigned long)name)
        != (long)VMIC_BPF_VM_FNAME_LEN)
        return 0;
    if (nm[0] != 'k' || nm[1] != 'v' || nm[2] != 'm' || nm[3] != '-' ||
        nm[4] != 'v' || nm[5] != 'm' || nm[6] != '\0')
        return 0;

    if (RDK(&kvm, 8, file + k->file_private_data)) return 0;
    return kvm;
}

/*
 * Najde v procese deskriptor anonymneho inode "kvm-vm" a vrati z neho
 * struct kvm. Bezat to MUSI pod bpf_rcu_read_lock().
 */
static __always_inline __u64 find_kvm(__u64 task, __u32 fd_hint,
                                      const struct vmic_bpf_koff *k,
                                      __s32 *err)
{
    __u64 files = 0, fdt = 0, fdarr = 0;
    __u32 max_fds = 0;

    if (RDK(&files, 8, task + k->task_files) || !files) {
        *err = VMIC_BPF_E_NOFILES;
        return 0;
    }
    if (RDK(&fdt, 8, files + k->files_fdt) || !fdt) {
        *err = VMIC_BPF_E_NOFILES;
        return 0;
    }
    if (RDK(&max_fds, 4, fdt + k->fdtable_max_fds) ||
        RDK(&fdarr, 8, fdt + k->fdtable_fd) || !fdarr) {
        *err = VMIC_BPF_E_NOFILES;
        return 0;
    }
    /*
     * Najprv tip zo zberaca. Bezny pripad je teda tri citania namiesto
     * tisicky - a pri procese s viac ako VMIC_BPF_MAX_FDS deskriptormi je
     * to jedina cesta, ako sa k VM vobec dostat.
     */
    if (fd_hint < max_fds) {
        __u64 kvm = kvm_from_fd(fdarr, fd_hint, k);
        if (kvm) return kvm;
    }

    if (max_fds > VMIC_BPF_MAX_FDS) max_fds = VMIC_BPF_MAX_FDS;

    for (__u32 i = 0; i < VMIC_BPF_MAX_FDS; i++) {
        if (i >= max_fds) break;

        __u64 kvm = kvm_from_fd(fdarr, i, k);
        if (kvm) return kvm;
    }

    *err = VMIC_BPF_E_NOKVM;
    return 0;
}

/*
 * Prejde hash tabulku memslotov a odpise ju do mapy `slots`.
 *
 * Jadro nad nou chodi cez hash_for_each(slots->id_hash, bkt, memslot,
 * id_node[slots->node_idx]) (include/linux/kvm_host.h:1107), cize kazdy
 * slot je v hlist zavesenej za svoje id_node[node_idx] - odtial to
 * odcitanie pri prepocte uzla spat na zaciatok slotu.
 *
 * Sloty sa menia iba pri zmene mapy pamate (start VM, hotplug, presun BAR
 * zariadenia), teda takmer nikdy. Aj tak sa pred aj po prechode cita
 * generation: ked sa medzitym zmenila, tabulka je nekonzistentna a cyklus
 * radsej preskocime, nez by sme citali podla neplatnych HVA.
 */
static __always_inline __s32 walk_slots(__u64 kvm, __u32 as_id,
                                        const struct vmic_bpf_koff *k,
                                        struct vmic_bpf_vminfo *info)
{
    if (as_id >= k->kvm_memslots_count) return VMIC_BPF_E_RANGE;

    __u64 ms = 0;
    if (RDK(&ms, 8, kvm + k->kvm_memslots +
                    (__u64)as_id * k->kvm_memslots_stride) || !ms)
        return VMIC_BPF_E_NOSLOTS;

    __u64 gen_before = 0, gen_after = 0;
    __u32 node_idx = 0;
    if (RDK(&gen_before, 8, ms + k->ms_generation)) return VMIC_BPF_E_RACE;
    if (RDK(&node_idx, 4, ms + k->ms_node_idx) || node_idx > 1)
        return VMIC_BPF_E_RACE;

    __u32 buckets = k->hash_buckets;
    if (buckets > VMIC_BPF_MAX_BUCKETS) buckets = VMIC_BPF_MAX_BUCKETS;

    const __u64 hash  = ms + k->ms_id_hash;
    const __u64 shift = (__u64)k->slot_id_node +
                        (__u64)node_idx * k->slot_id_node_stride;

    __u32 n = 0, skipped = 0, trunc = 0;
    __u64 total = 0, maxg = 0;

    for (__u32 b = 0; b < VMIC_BPF_MAX_BUCKETS; b++) {
        if (b >= buckets) break;

        __u64 node = 0;
        if (RDK(&node, 8, hash + (__u64)b * 8 + k->hlist_head_first)) continue;

        for (__u32 c = 0; c <= VMIC_BPF_MAX_CHAIN; c++) {
            if (!node) break;
            /* Prilis dlhy retazec by znamenal, ze sme cast slotov
               nevideli - a tie by sa v snimke tvarili ako diera plna nul.
               Radsej to nahlas: nedokoncena mapa pamate je horsia nez
               preskoceny cyklus. */
            if (c == VMIC_BPF_MAX_CHAIN) { trunc = 1; break; }

            __u64 slot = node - shift;
            __u64 base = 0, np = 0, ua = 0;
            __u32 fl = 0;
            /* id je v jadre `short` - citat 4 bajty by za nim zobralo aj
               susedne as_id a cislo slotu by bolo nezmyselne */
            __s16 id = 0;
            long bad = 0;

            bad |= RDK(&base, 8, slot + k->slot_base_gfn);
            bad |= RDK(&np,   8, slot + k->slot_npages);
            bad |= RDK(&ua,   8, slot + k->slot_userspace_addr);
            bad |= RDK(&fl,   4, slot + k->slot_flags);
            bad |= RDK(&id,   2, slot + k->slot_id);

            /* dalsi clanok retazca este predtym, nez uzol opustime */
            if (RDK(&node, 8, node + k->hlist_node_next)) node = 0;
            if (bad) continue;

            /* Poistka proti smetiam: keby sme trafili uvolneny slot,
               cisla nedavaju zmysel a je lepsie ich zahodit, nez podla
               nich citat cudziu pamat. 2^34 stranok = 64 TiB. */
            if (!np || np > (1ULL << 34) || base > (1ULL << 52)) continue;
            if (base + np < base) continue;

            if (maxg < base + np) maxg = base + np;

            /* Slot, ktory sa cez adresny priestor VMM precitat neda:
               prave sa prekresluje (INVALID), je cely v guest_memfd
               (GMEM_ONLY), alebo proste nema HVA. Patri do diery. */
            if (!ua || (ua & (VMIC_BPF_PAGE_SIZE - 1)) ||
                (fl & (VMIC_BPF_MEMSLOT_INVALID |
                       VMIC_BPF_MEMSLOT_GMEM_ONLY))) {
                skipped++;
                continue;
            }
            if (n >= VMIC_BPF_MAX_SLOTS) { trunc = 1; continue; }

            struct vmic_bpf_slot *s = &info->slots[n];
            s->base_gfn       = base;
            s->npages         = np;
            s->userspace_addr = ua;
            s->flags          = fl;
            s->id             = id;
            n++;
            total += np;
        }
    }

    if (RDK(&gen_after, 8, ms + k->ms_generation) || gen_after != gen_before)
        return VMIC_BPF_E_RACE;

    info->kvm         = kvm;
    info->generation  = gen_before;
    info->total_pages = total;
    info->max_gfn     = maxg;
    info->nslots      = n;
    info->skipped     = skipped;
    RDK(&info->online_vcpus,  4, kvm + k->kvm_online_vcpus);   /* atomic_t */
    RDK(&info->userspace_pid, 4, kvm + k->kvm_userspace_pid);

    if (!n) return VMIC_BPF_E_NOSLOTS;
    return trunc ? VMIC_BPF_E_TRUNC : VMIC_BPF_E_OK;
}

/* ------------------------------------------------------------------ */
/* vmic_probe - kto je ta VM a ako vyzera jej fyzicky priestor         */
/* ------------------------------------------------------------------ */

SEC("syscall")
int vmic_probe(struct vmic_bpf_probe_ctx *ctx)
{
    __u32 zero = 0;
    const struct vmic_bpf_koff *k = bpf_map_lookup_elem(&koff, &zero);
    struct vmic_bpf_vminfo *info  = bpf_map_lookup_elem(&slots, &zero);

    if (!k || !info) {
        ctx->err = VMIC_BPF_E_NOMAP;
        return 0;
    }

    /* Stary obsah zahadzujeme hned - keby sme skoncili chybou, nesmie sa
       citat podla tabulky z minuleho cyklu. */
    info->nslots = 0;
    info->skipped = 0;
    info->total_pages = 0;
    info->max_gfn = 0;
    info->kvm = 0;
    info->generation = 0;
    info->online_vcpus = 0;
    info->userspace_pid = 0;

    ctx->err = VMIC_BPF_E_OK;
    ctx->nslots = 0;
    ctx->kvm = 0;
    ctx->total_pages = 0;
    ctx->max_gfn = 0;
    ctx->online_vcpus = 0;
    ctx->skipped = 0;
    ctx->userspace_pid = 0;

    struct task_struct *task = bpf_task_from_vpid((__s32)ctx->pid);
    if (!task) {
        ctx->err = VMIC_BPF_E_NOTASK;
        return 0;
    }

    __s32 err = VMIC_BPF_E_OK;

    bpf_rcu_read_lock();
    __u64 kvm = find_kvm((__u64)task, ctx->fd_hint, k, &err);
    if (kvm) err = walk_slots(kvm, ctx->as_id, k, info);
    bpf_rcu_read_unlock();

    bpf_task_release(task);

    ctx->err = err;
    if (err != VMIC_BPF_E_OK && err != VMIC_BPF_E_TRUNC) {
        info->nslots = 0;          /* nedovol citat podla polovicnej mapy */
        return 0;
    }

    ctx->nslots       = info->nslots;
    ctx->kvm          = info->kvm;
    ctx->total_pages  = info->total_pages;
    ctx->max_gfn      = info->max_gfn;
    ctx->online_vcpus = info->online_vcpus;
    ctx->skipped      = info->skipped;
    ctx->userspace_pid = info->userspace_pid;
    return 0;
}

/* ------------------------------------------------------------------ */
/* vmic_read - prelozi GPA a skopiruje stranky                         */
/* ------------------------------------------------------------------ */
/*
 * Jeden beh obsluzi suvisly usek VNUTRI jedneho memslotu. Ked poziadavka
 * presahuje za koniec slotu, vrati sa iba prva cast (`served`) a zvysok si
 * zberac vypyta dalsim volanim - vdaka tomu tu nie su vnorene cykly a
 * verifikator ma jednoduchu pracu.
 *
 * Ked GPA nepatri do ziadneho slotu, vrati sa KIND_HOLE a dlzka diery az
 * po najblizsi dalsi slot. Zberac ju vyplni nulami. Presne toto je to
 * "diery sa musia PRESKAKOVAT, nie orezavat" z README - len tu vieme
 * povedat aj to, kde diera konci, takze sa nemusi hadat po strankach.
 */

SEC("syscall")
int vmic_read(struct vmic_bpf_read_ctx *ctx)
{
    __u32 zero = 0;
    struct vmic_bpf_vminfo *info = bpf_map_lookup_elem(&slots, &zero);
    __u8 *buf = bpf_map_lookup_elem(&pages, &zero);

    if (!info || !buf) {
        ctx->err = VMIC_BPF_E_NOMAP;
        return 0;
    }

    ctx->served = 0;
    ctx->copied = 0;
    ctx->kind = VMIC_BPF_KIND_DATA;
    ctx->fallback = 0;
    ctx->slot_id = -1;
    ctx->hva = 0;
    ctx->first_fail = 0;
    ctx->err = VMIC_BPF_E_OK;

    __u32 want = ctx->npages;
    if (!want || want > VMIC_BPF_MAX_PAGES ||
        (ctx->gpa & (VMIC_BPF_PAGE_SIZE - 1))) {
        ctx->err = VMIC_BPF_E_RANGE;
        return 0;
    }

    __u64 gfn = ctx->gpa >> VMIC_BPF_PAGE_SHIFT;
    __u32 nslots = info->nslots;
    if (!nslots) {
        ctx->err = VMIC_BPF_E_NOSLOTS;
        return 0;
    }
    if (nslots > VMIC_BPF_MAX_SLOTS) nslots = VMIC_BPF_MAX_SLOTS;

    __u64 hva = 0, avail = 0, next_start = ~0ULL;
    __s32 sid = -1;

    for (__u32 i = 0; i < VMIC_BPF_MAX_SLOTS; i++) {
        if (i >= nslots) break;

        __u64 base = info->slots[i].base_gfn;
        __u64 np   = info->slots[i].npages;

        if (gfn >= base && (gfn - base) < np) {
            avail = np - (gfn - base);
            hva   = info->slots[i].userspace_addr +
                    ((gfn - base) << VMIC_BPF_PAGE_SHIFT);
            sid   = info->slots[i].id;
            break;
        }
        if (base > gfn && base < next_start) next_start = base;
    }

    if (!avail) {
        __u64 gap = (next_start == ~0ULL) ? (__u64)want : next_start - gfn;
        if (gap > (__u64)want) gap = want;
        ctx->kind   = VMIC_BPF_KIND_HOLE;
        ctx->served = (__u32)gap;
        return 0;
    }

    __u32 served = want;
    if (avail < (__u64)served) served = (__u32)avail;
    if (served > VMIC_BPF_MAX_PAGES) served = VMIC_BPF_MAX_PAGES;

    ctx->served  = served;
    ctx->slot_id = sid;
    ctx->hva     = hva;

    struct task_struct *task = bpf_task_from_vpid((__s32)ctx->pid);
    if (!task) {
        ctx->served = 0;
        ctx->err = VMIC_BPF_E_NOTASK;
        return 0;
    }

    /*
     * Bezny pripad je jedno velke kopirovanie celeho useku. Ked zlyha
     * (helper v tom pripade buffer vynuluje), este raz to skusime po
     * strankach - jedna nenamapovana stranka tak nezhodi cely blok.
     * bpf_copy_from_user_task() ide cez access_process_vm(), takze cita
     * bez ohladu na to, ci VM prave bezi. Pri ANONYMNOM podlozeni pamate
     * (vychodzie QEMU) sa nedotknuta stranka nacita ako nulova a
     * hostitelovi nic nepribudne; pri shmem podlozeni (memfd, hugetlbfs)
     * ju citanie naozaj vytvori - na to upozornuje zberac pri starte.
     */
    __u32 len = served << VMIC_BPF_PAGE_SHIFT;

    if (bpf_copy_from_user_task(buf, len,
                                (const void *)(unsigned long)hva, task, 0) == 0) {
        ctx->copied = served;
    } else {
        __u32 ok = 0, first = served;

        ctx->fallback = 1;
        for (__u32 i = 0; i < VMIC_BPF_MAX_PAGES; i++) {
            if (i >= served) break;

            __u32 off = i << VMIC_BPF_PAGE_SHIFT;
            if (off > VMIC_BPF_MAX_CHUNK - VMIC_BPF_PAGE_SIZE) break;

            if (bpf_copy_from_user_task(buf + off, VMIC_BPF_PAGE_SIZE,
                                        (const void *)(unsigned long)(hva + off),
                                        task, 0) == 0)
                ok++;
            else if (first == served)
                first = i;
        }
        ctx->copied     = ok;
        ctx->first_fail = first;
    }

    bpf_task_release(task);
    return 0;
}
