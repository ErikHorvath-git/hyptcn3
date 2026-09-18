/*
 * vmic_bpf_abi.h - spolocne rozhranie medzi BPF programom a zberacom.
 *
 * Tento subor prekladaju OBAJA: clang pre cielovu architekturu bpf
 * (bpf/vmic_kvm.bpf.c) aj gcc pre userspace (src/backend_ebpf.c). Preto tu
 * nesmie byt nic okrem typov s pevnou velkostou - ziadne funkcie, ziadne
 * hlavicky. Typy __u32/__u64 si dodava ten, kto tento subor vklada
 * (BPF strana cez <linux/bpf.h>, zberac cez <linux/types.h>).
 *
 * NAJDOLEZITEJSIA MYSLIENKA CELEHO ROZHRANIA:
 *
 * BPF program NEPOZNA rozlozenie jadrovych struktur - vsetky offsety mu
 * posle zberac v mape `koff`. Zberac ich vycita z BTF, ktore ma jadro samo
 * o sebe (/sys/kernel/btf/vmlinux + /sys/kernel/btf/kvm). Vdaka tomu:
 *
 *   - nepotrebujeme vmlinux.h ani bpftool,
 *   - program nie je prelozeny natvrdo proti jednej verzii jadra,
 *   - ked sa struktura v novom jadre posunie, zberac to zisti sam a vypise,
 *     ktore pole nenasiel - namiesto ticheho citania smeti.
 */

#ifndef VMIC_BPF_ABI_H
#define VMIC_BPF_ABI_H

/* Stranka HOSTA. KVM adresuje pamat v jednotkach gfn = GPA >> 12, takze
   toto je jednotka, v ktorej rozpravaju memsloty - nie velkost stranky
   hostitela a uz vobec nie output.delta_page_size. */
#define VMIC_BPF_PAGE_SHIFT   12u
#define VMIC_BPF_PAGE_SIZE    (1u << VMIC_BPF_PAGE_SHIFT)

/* Kolko memslotov vieme zapamatat. QEMU ich pre bezne VM vyrobi 3-8
   (pod 4G RAM, nad 4G RAM, SMRAM, pripadne BAR-y priradenych zariadeni). */
#define VMIC_BPF_MAX_SLOTS    64u

/* Velkost prenosoveho buffra (mapa `pages`, mmap-nuta do zberaca).
   Je to zaroven strop pre capture.chunk_size pri backende ebpf: velkost
   buffra kontroluje verifikator, takze musi byt konstanta znama uz pri
   preklade BPF programu. */
#define VMIC_BPF_MAX_CHUNK    (2u << 20)                 /* 2 MiB */
#define VMIC_BPF_MAX_PAGES    (VMIC_BPF_MAX_CHUNK / VMIC_BPF_PAGE_SIZE)

/* Kolko poloziek tabulky deskriptorov prehladame, kym to vzdame.
   QEMU ich ma typicky par desiatok; strop je tu kvoli verifikatoru. */
#define VMIC_BPF_MAX_FDS      1024u

/* Prechod hash tabulky memslotov (kvm_memslots.id_hash).
   Jadro ma DECLARE_HASHTABLE(id_hash, 7) = 128 bucketov; skutocny pocet
   posle zberac v koff.hash_buckets a program si ho oreze na toto maximum. */
#define VMIC_BPF_MAX_BUCKETS  128u
#define VMIC_BPF_MAX_CHAIN    8u

/* Meno anonymneho inode, ktory KVM vyrobi pre kazdu VM
   (virt/kvm/kvm_main.c: anon_inode_getfile("kvm-vm", ...)).
   Pozor: v kvm.ko je aj "kvm-vm-stats", preto sa porovnava aj koncova
   nula - inak by sa zberac chytil na nespravny deskriptor. */
#define VMIC_BPF_VM_FNAME_LEN 7u   /* "kvm-vm" vratane '\0' */

/*
 * Priznaky memslotu. Prve dva su verejne (uapi/linux/kvm.h:49-58), druhe
 * dva vnutorne (include/linux/kvm_host.h:57-58) - kopirujeme ich sem, aby
 * backend nemusel tahat kvm.h.
 *
 * POZOR: KVM_MEM_GUEST_MEMFD sam o sebe NEZNAMENA, ze slot nema HVA -
 * confidential VM ma cez neho namapovanu iba svoju privatnu cast a zdielana
 * cast ostava normalne citatelna. Necitatelny je az slot s GMEM_ONLY alebo
 * bez userspace_addr. INVALID nesie slot, ktory sa prave prekresluje.
 */
#define VMIC_BPF_MEM_READONLY        (1u << 1)
#define VMIC_BPF_MEM_GUEST_MEMFD     (1u << 2)
#define VMIC_BPF_MEMSLOT_INVALID     (1u << 16)
#define VMIC_BPF_MEMSLOT_GMEM_ONLY   (1u << 17)

/* Chybove kody, ktore BPF program vracia cez ctx.err. */
enum {
    VMIC_BPF_E_OK       = 0,
    VMIC_BPF_E_NOTASK   = 1,  /* pid uz nezije                            */
    VMIC_BPF_E_NOFILES  = 2,  /* proces nema tabulku deskriptorov         */
    VMIC_BPF_E_NOKVM    = 3,  /* proces nema otvoreny fd "kvm-vm"         */
    VMIC_BPF_E_NOSLOTS  = 4,  /* VM nema ziadny citatelny memslot         */
    VMIC_BPF_E_TRUNC    = 5,  /* slotov je viac ako VMIC_BPF_MAX_SLOTS    */
    VMIC_BPF_E_RACE     = 6,  /* memsloty sa pocas citania menili         */
    VMIC_BPF_E_NOMAP    = 7,  /* interna chyba: mapa nie je dostupna      */
    VMIC_BPF_E_RANGE    = 8   /* nezmyselna poziadavka (npages, gpa)      */
};

/* Co vratil `vmic_read`: data v buffri, alebo dieru vo fyzickom priestore. */
enum {
    VMIC_BPF_KIND_DATA = 0,
    VMIC_BPF_KIND_HOLE = 1
};

/* ------------------------------------------------------------------ */
/* Offsety jadrovych struktur - vyplna ich zberac z BTF                */
/* ------------------------------------------------------------------ */
/*
 * Vsetko su bajtove offsety vnutri prislusnej struktury, `*_stride` su
 * velkosti prvkov poli. Nula je platna hodnota (hlist_head.first naozaj
 * offset 0 ma), takze sa NEDA pouzit ako "nenasiel som" - kazde pole
 * kontroluje zberac uz pri nacitani a ked jedine chyba, program vobec
 * nespusti.
 */
struct vmic_bpf_koff {
    /* vmlinux: cesta task -> files -> fdtable -> file -> dentry */
    __u32 task_files;
    __u32 files_fdt;
    __u32 fdtable_max_fds;
    __u32 fdtable_fd;
    __u32 file_private_data;
    __u32 file_f_path;
    __u32 path_dentry;
    __u32 dentry_d_name;
    __u32 qstr_name;
    __u32 hlist_head_first;
    __u32 hlist_node_next;

    /* modul kvm: struct kvm */
    __u32 kvm_memslots;        /* pole ukazovatelov na kvm_memslots     */
    __u32 kvm_memslots_stride; /* = sizeof(void *)                      */
    __u32 kvm_memslots_count;  /* pocet adresnych priestorov (x86: 2)   */
    __u32 kvm_online_vcpus;
    __u32 kvm_userspace_pid;

    /* modul kvm: struct kvm_memslots */
    __u32 ms_generation;
    __u32 ms_id_hash;
    __u32 ms_node_idx;
    __u32 hash_buckets;        /* pocet hlist_head v id_hash            */

    /* modul kvm: struct kvm_memory_slot */
    __u32 slot_id_node;        /* hlist_node id_node[2] - zaciatok pola */
    __u32 slot_id_node_stride; /* = sizeof(struct hlist_node)           */
    __u32 slot_base_gfn;
    __u32 slot_npages;
    __u32 slot_userspace_addr;
    __u32 slot_flags;
    __u32 slot_id;
    __u32 pad_;
};

/* ------------------------------------------------------------------ */
/* Jeden memslot: kus fyzickeho priestoru hosta (GPA) namapovany do    */
/* adresneho priestoru VMM (HVA)                                       */
/* ------------------------------------------------------------------ */
struct vmic_bpf_slot {
    __u64 base_gfn;         /* prve gfn slotu                          */
    __u64 npages;           /* dlzka v strankach hosta                 */
    __u64 userspace_addr;   /* HVA zodpovedajuca base_gfn              */
    __u32 flags;            /* KVM_MEM_*                               */
    __s32 id;               /* cislo slotu podla KVM                   */
};

/*
 * Cely obraz pamate VM tak, ako ho vidi KVM. Zije v mape `slots`:
 * zapisuje ho `vmic_probe` (raz za cyklus), cita ho `vmic_read` (pri
 * kazdom bloku) aj zberac (kvoli velkosti pamate a diagnostike).
 */
struct vmic_bpf_vminfo {
    __u64 kvm;              /* adresa struct kvm - iba do logu         */
    __u64 generation;       /* memslots->generation pri citani         */
    __u64 total_pages;      /* sucet npages citatelnych slotov         */
    __u64 max_gfn;          /* najvyssie gfn + 1 (s dierami!)          */
    __u32 nslots;
    __u32 skipped;          /* sloty bez HVA (guest_memfd)             */
    __u32 online_vcpus;
    __u32 userspace_pid;    /* kvm->userspace_pid                      */
    struct vmic_bpf_slot slots[VMIC_BPF_MAX_SLOTS];
};

/* ------------------------------------------------------------------ */
/* Kontexty programov                                                  */
/* ------------------------------------------------------------------ */
/*
 * SEC("syscall") program dostane ukazovatel na kopiu tejto struktury a
 * jadro ju po skonceni skopiruje spat do zberaca (ctx_in / ctx_out v
 * bpf_prog_test_run_opts). Vstup aj vystup teda ide jednou cestou.
 *
 * POZOR: do ctx sa da pristupovat iba s KONSTANTNYM offsetom (kontroluje
 * to verifikator), takze sem nepatri nic indexovane premennou.
 */
struct vmic_bpf_probe_ctx {
    __u32 pid;              /* in:  pid procesu VMM (QEMU)             */
    __u32 as_id;            /* in:  adresny priestor (0 = normalny)    */
    /* in: cislo deskriptora "kvm-vm", ako ho videl zberac v /proc.
       Program ho skusi ako prvy a az potom prehladava celu tabulku -
       usetri to tisicku citani jadrovej pamate v kazdom cykle a hlavne
       to funguje aj pri procese s viac ako VMIC_BPF_MAX_FDS deskriptormi.
       ~0u = nemam tip. */
    __u32 fd_hint;
    __u32 pad2_;
    __s32 err;              /* out: VMIC_BPF_E_*                       */
    __u32 nslots;           /* out: kolko slotov sa naslo              */
    __u64 kvm;              /* out: adresa struct kvm (diagnostika)    */
    __u64 total_pages;      /* out: citatelna pamat v strankach        */
    __u64 max_gfn;          /* out: najvyssie gfn + 1                  */
    __u32 online_vcpus;     /* out                                     */
    __u32 skipped;          /* out: preskocene sloty (guest_memfd)     */
    __u32 userspace_pid;    /* out: kvm->userspace_pid                 */
    __u32 pad_;
};

struct vmic_bpf_read_ctx {
    __u32 pid;              /* in:  pid procesu VMM                    */
    __u32 npages;           /* in:  kolko stranok chceme (<= MAX_PAGES)*/
    __u64 gpa;              /* in:  fyzicka adresa hosta (zarovnana)   */

    __u32 served;           /* out: kolko stranok tento beh pokryva    */
    __u32 kind;             /* out: VMIC_BPF_KIND_*                    */
    __u32 copied;           /* out: kolko stranok sa naozaj precitalo  */
    __u32 fallback;         /* out: 1 = muselo sa ist po strankach     */
    __s32 slot_id;          /* out: ktory memslot to obsluzil          */
    __s32 err;              /* out: VMIC_BPF_E_*                       */
    __u64 hva;              /* out: HVA zaciatku - diagnostika         */
    __u32 first_fail;       /* out: index prvej necitatelnej stranky   */
    __u32 pad_;
};

#endif /* VMIC_BPF_ABI_H */
