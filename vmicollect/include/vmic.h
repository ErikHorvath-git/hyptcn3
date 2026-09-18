/*
 * vmic.h - verejne rozhranie modulu pre periodicky zber pamatovych snimok VM
 *
 * Modul je rozdeleny na styri nezavisle vrstvy. Ked chces nieco upravit,
 * takmer vzdy sa dotknes iba jednej z nich:
 *
 *   1. BACKEND  (backend_*.c)  - "odkial berieme bajty"
 *                                eBPF nad KVM / raw subor na disku
 *   2. WRITER   (writer_*.c)   - "kam a v akom tvare ich ukladame"
 *                                raw (+sparse, +gzip) / delta (iba zmeny)
 *   3. SCHEDULER(sched.c)      - "kedy presne sa ma zbierat"
 *   4. HOOKS    (hooks.c)      - "co sa ma stat po kazdej snimke"
 *                                dlopen() plugin, tvoj vlastny .so
 *
 * Vrstvy sa vidia iba cez struktury s ukazovatelmi na funkcie (vtable)
 * definovane nizsie; collector.c ich len spaja dokopy.
 */

#ifndef VMIC_H
#define VMIC_H

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMIC_VERSION       "1.0.0"
#define VMIC_PATH_MAX      1024
#define VMIC_NAME_MAX      256
#define VMIC_MAX_REGIONS   64
#define VMIC_MAX_HOOKS     16
#define VMIC_SHA256_BYTES  32

/* ------------------------------------------------------------------ */
/* Urovne logovania                                                    */
/* ------------------------------------------------------------------ */
/* Su tu (a nie v src/log.h), lebo ich potrebuje aj plugin - dostava
   ukazovatel na logovaciu funkciu cez vmic_hook_api_t. */
enum {
    VMIC_LOG_DEBUG = 0,
    VMIC_LOG_INFO,
    VMIC_LOG_WARN,
    VMIC_LOG_ERROR,
    VMIC_LOG_NONE
};

/* ------------------------------------------------------------------ */
/* Navratove kody                                                      */
/* ------------------------------------------------------------------ */
/*
 * Rozlisenie ERR / FATAL je dolezite: pri ERR zberac iba preskoci cyklus
 * a skusi to o periodu neskor (VM sa napr. prave migruje), pri FATAL
 * skonci (domena neexistuje, chyba kniznica, plny disk).
 */
typedef enum {
    VMIC_OK    =  0,
    VMIC_ERR   = -1,   /* docasna chyba - cyklus preskocime          */
    VMIC_FATAL = -2,   /* nema zmysel pokracovat - koncime           */
    VMIC_STOP  = -3    /* prisiel SIGINT/SIGTERM - korektne koncime  */
} vmic_rc_t;

/* ------------------------------------------------------------------ */
/* Konfiguracia                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    VMIC_OVERRUN_SKIP = 0,   /* zahod zmeskane sloty, drz povodnu mriezku */
    VMIC_OVERRUN_CATCHUP,    /* dobehni zmeskane sloty hned za sebou      */
    VMIC_OVERRUN_STRETCH     /* dalsi termin = teraz + perioda            */
} vmic_overrun_t;

typedef enum { VMIC_HASH_NONE = 0, VMIC_HASH_SHA256 } vmic_hash_t;
typedef enum { VMIC_COMPRESS_NONE = 0, VMIC_COMPRESS_GZIP } vmic_compress_t;

/* (start, dlzka) vo FYZICKYCH adresach hosta */
typedef struct {
    uint64_t start;
    uint64_t size;
} vmic_region_t;

typedef struct {
    /* ---- [vm] : koho a cez co sledujeme -------------------------- */
    /* meno domeny z prikazoveho riadku VMM, "pid:1234" alebo holy pid;
       prazdne = jedina bezica KVM domena na stroji                   */
    char     domain[VMIC_NAME_MAX];
    char     backend[32];             /* ebpf | file                  */
    /* prazdne = pouzije sa BPF program vlozeny v binarke; cesta k
       vlastnemu .bpf.o sa hodi pri jeho ladeni                       */
    char     bpf_object[VMIC_PATH_MAX];
    char     image_path[VMIC_PATH_MAX];   /* backend "file"           */

    /* ---- [schedule] : kedy zbierame ------------------------------ */
    double         interval_s;
    double         jitter;            /* 0.0 - 0.99, podiel periody   */
    vmic_overrun_t overrun;
    uint64_t       max_cycles;        /* 0 = bez limitu               */
    double         duration_s;        /* 0 = bez limitu               */
    bool           align;             /* zarovnat na nasobok periody  */

    /* ---- [capture] : ako citame ---------------------------------- */
    /* Pozastavit vCPU pocas citania. Ziadny sucasny backend to nevie
       (eBPF je pozorovacie, nie riadiace rozhranie) - zostava tu preto,
       ze meranie pause_ms je sucastou vyhodnotenia a backend, ktory by
       to vedel, sa da doplnit bez zmeny zberaca.                     */
    bool          pause;
    double        pause_max_ms;       /* nad tento cas varujeme       */
    size_t        chunk_size;
    vmic_region_t regions[VMIC_MAX_REGIONS];
    size_t        region_count;       /* 0 = cela fyzicka pamat       */
    bool          skip_read_errors;   /* diery vyplnit nulami         */
    uint64_t      max_read_errors;    /* 0 = bez limitu               */

    /* ---- [output] : kam ukladame --------------------------------- */
    char           dir[VMIC_PATH_MAX];
    char           writer[16];        /* raw | delta                  */
    char           name_template[128];
    bool           sparse;
    vmic_compress_t post_compress;    /* AZ po odpauzovani VM         */
    vmic_hash_t    hash;
    bool           sidecar;           /* .json s metadatami           */
    uint32_t       delta_page_size;
    uint64_t       delta_full_every;  /* kazdych N snimok plna zaloha */

    /* ---- [retention] : co mazeme (0 = vypnute) ------------------- */
    uint64_t max_snapshots;
    uint64_t max_bytes;
    double   max_age_s;

    /* ---- [hooks] ------------------------------------------------- */
    char   hook_path[VMIC_MAX_HOOKS][VMIC_PATH_MAX];
    char   hook_args[VMIC_MAX_HOOKS][VMIC_NAME_MAX];
    size_t hook_count;
    bool   hooks_strict;              /* chyba v hooku = koniec zberu */

    /* ---- [log] --------------------------------------------------- */
    int    log_level;                 /* pozri log.h                  */
    char   log_file[VMIC_PATH_MAX];
    bool   log_json;

    char   source_path[VMIC_PATH_MAX];/* odkial sa config nacital     */
} vmic_config_t;

/* ------------------------------------------------------------------ */
/* Informacie o cielovej VM                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char     domain[VMIC_NAME_MAX];
    char     backend[32];
    uint64_t vmid;
    uint64_t memsize;      /* velkost RAM podla hypervizora           */
    uint64_t max_paddr;    /* najvyssia fyz. adresa + 1 (s dierami!)  */
    unsigned num_vcpus;
    unsigned address_width;
    char     page_mode[16];
    bool     has_vmid, has_memsize, has_max_paddr, has_vcpus;

    /*
     * Ktore useky fyzickeho priestoru su NAOZAJ namapovane - zoradene a
     * zlucene. Backend, ktory to vie (ebpf z memslotov), tym usetri zber
     * dier: fyzicky priestor x86 ma medzi RAM oblastami aj viac GiB
     * medzier (PCI hole, MMIO) a citat z nich nuly je cista strata casu,
     * ktora navyse skresluje statistiky delta zberu.
     * Prazdne = backend to nevie, pouzije sa suvisle [0, max_paddr).
     */
    vmic_region_t ram[VMIC_MAX_REGIONS];
    size_t        ram_count;
} vmic_vminfo_t;

/* Kolko bajtov ma zmysel precitat, ked pouzivatel nezadal [capture].regions */
uint64_t vmic_vminfo_addressable(const vmic_vminfo_t *vi);

/* ------------------------------------------------------------------ */
/* Merania jedneho citania - surovina pre vyhodnotenie vykonu          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t bytes_requested;
    uint64_t bytes_read;
    uint64_t chunks;
    uint64_t read_errors;
    uint64_t filled_zero;   /* bajty nahradene nulami (MMIO diery)    */
    double   read_seconds;
} vmic_stats_t;

/* ------------------------------------------------------------------ */
/* Zaznam o jednej snimke - dostane ho writer, sidecar aj kazdy hook   */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t seq;                       /* poradove cislo od startu   */
    uint64_t chain_id;                  /* delta: id retazca          */
    bool     is_full;                   /* delta: je to plna zaloha?  */
    char     id[VMIC_NAME_MAX];         /* meno bez pripony           */
    char     ext[16];                   /* pripona vratane bodky      */
    char     path[VMIC_PATH_MAX];       /* finalny subor              */
    char     sidecar_path[VMIC_PATH_MAX];

    struct timespec wall;               /* CLOCK_REALTIME zaciatku    */
    double   pause_ms;                  /* ako dlho stala VM          */
    double   capture_ms;                /* citanie pamate             */
    double   write_ms;                  /* dokoncenie zapisu + gzip   */
    double   total_ms;                  /* cely cyklus                */
    bool     pause_exceeded;            /* prekrocene pause_max_ms    */

    uint64_t bytes_logical;             /* kolko pamate snimka pokryva */
    uint64_t bytes_on_disk;             /* realna velkost suboru      */
    uint64_t pages_total;               /* delta                      */
    uint64_t pages_changed;             /* delta                      */

    /* Zastavila sa VM naozaj? Nie to, co si zelal config: backend bez
       pause() (ebpf) ju zastavit nevie, a vtedy nesmie pause_ms tvrdit,
       ze VM stala cely cas citania. */
    bool     paused;

    /* Oblasti, ktore tato snimka naozaj pokryva. Ukazuje do zberaca a
       zije po celu dobu cyklu; writer podla nich pozna svoj rozsah. */
    const vmic_region_t *regions;
    size_t               region_count;

    uint8_t  sha256[VMIC_SHA256_BYTES];
    bool     has_hash;
    /* true = kontrolny sucet pokryva presne obsah suboru;
       false = pokryva iba zozbierane oblasti (nesuvisle [capture].regions),
       takze sa neda porovnat s hashom suboru na disku */
    bool     hash_covers_file;

    vmic_stats_t          stats;
    const vmic_vminfo_t  *vm;
    const vmic_config_t  *cfg;
} vmic_snapshot_t;

/* ------------------------------------------------------------------ */
/* VRSTVA 1: BACKEND                                                   */
/* ------------------------------------------------------------------ */

typedef struct vmic_backend vmic_backend_t;
typedef struct vmic_writer  vmic_writer_t;

typedef struct {
    const char *name;
    /* true  -> backend vie precitat lubovolny rozsah (read_pa)
       false -> backend vie iba vysypat cely obraz naraz (dump_to)    */
    bool random_access;
    /* prirodzena pripona vystupu ('.raw', '.elf', ...)               */
    const char *ext;

    int  (*open)  (vmic_backend_t *b);
    void (*close) (vmic_backend_t *b);
    int  (*probe) (vmic_backend_t *b, vmic_vminfo_t *out);
    int  (*pause) (vmic_backend_t *b);
    int  (*resume)(vmic_backend_t *b);

    /*
     * Volitelne: zavola sa na zaciatku KAZDEHO cyklu.
     * Sem patri vsetko, co sa medzi dvoma snimkami mohlo zmenit a co
     * backend drzi v kesi - pri 'ebpf' je to mapa GPA -> HVA (memsloty),
     * ktoru si tu znovu vypyta od jadra. Ked to backend neurobi,
     * periodicky zber bude citat podla zastaraneho obrazu pamate.
     */
    int (*begin_cycle)(vmic_backend_t *b);

    /*
     * random_access == true: naplni CELY buffer - precitanymi bajtmi a
     * nulami tam, kde pamat nie je namapovana. Vrati pocet bajtov, ktore
     * sa NAOZAJ podarilo precitat (0..len), alebo -1 pri tvrdej chybe.
     *
     * POZOR: diery mozu byt kdekolvek vnutri bloku, nie len na konci -
     * fyzicky priestor x86 ma medzery (PCI hole, MMIO) a jednotlive
     * stranky mozu byt vyballonovane. Backend preto musi cez dieru
     * PRESKOCIT a citat dalej, nie sa na nej zastavit.
     */
    int64_t (*read_pa)(vmic_backend_t *b, uint64_t paddr,
                       void *buf, size_t len);

    /* random_access == false: vytvor uplny obraz na ceste `path`     */
    int (*dump_to)(vmic_backend_t *b, const char *path);
} vmic_backend_ops_t;

struct vmic_backend {
    const vmic_backend_ops_t *ops;
    const vmic_config_t      *cfg;
    void                     *priv;   /* privatny stav driveru        */
    bool                      paused;
    /* priznak "koncime" - backend ho ma kontrolovat pri kazdej dlhej
       operacii, aby sa Ctrl-C prejavilo aj pocas viacminutoveho vypisu */
    volatile sig_atomic_t    *stop;
    /* open() sem moze zapisat priponu, ked ju vie az za behu
       (napr. `virsh dump` produkuje ELF, `vmi-dump-memory` raw).
       Prazdne = pouzije sa ops->ext. */
    char                      ext[16];
};

/* Vrati priponu, ktoru ma vystup backendu naozaj mat. */
const char *vmic_backend_ext(const vmic_backend_t *b);

/* registry - backends.c */
const vmic_backend_ops_t *vmic_backend_find(const char *name);
const char              **vmic_backend_list(size_t *count);
int   vmic_backend_create(vmic_backend_t *b, const vmic_config_t *cfg);
void  vmic_backend_destroy(vmic_backend_t *b);
int   vmic_backend_pause(vmic_backend_t *b);
int   vmic_backend_resume(vmic_backend_t *b);

/* Spolocna slucka citania pre random_access backendy: rozseka oblasti
   na bloky `chunk_size` a posle ich do writeru. */
int vmic_capture(vmic_backend_t *b, vmic_writer_t *w,
                 const vmic_region_t *regions, size_t region_count,
                 vmic_stats_t *stats, volatile sig_atomic_t *stop);

/* ------------------------------------------------------------------ */
/* VRSTVA 2: WRITER                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    bool needs_random_access;   /* delta nevie pracovat s hromadnym vypisom */

    int  (*begin) (vmic_writer_t *w, vmic_snapshot_t *s);
    /* suvisly blok fyzickej pamate od `paddr` */
    int  (*feed)  (vmic_writer_t *w, uint64_t paddr,
                   const uint8_t *buf, size_t len);
    /* pre hromadne backendy: kam ma externy nastroj zapisat */
    const char *(*staging)(vmic_writer_t *w);
    /* staging subor je hotovy, prevezmi ho */
    int  (*adopt) (vmic_writer_t *w);
    int  (*finish)(vmic_writer_t *w, vmic_snapshot_t *s);
    void (*abort) (vmic_writer_t *w);
    void (*destroy)(vmic_writer_t *w);
} vmic_writer_ops_t;

struct vmic_writer {
    const vmic_writer_ops_t *ops;
    const vmic_config_t     *cfg;
    void                    *priv;
};

const vmic_writer_ops_t *vmic_writer_find(const char *name);
int  vmic_writer_create(vmic_writer_t *w, const vmic_config_t *cfg);
void vmic_writer_destroy(vmic_writer_t *w);

/* ------------------------------------------------------------------ */
/* VRSTVA 3: SCHEDULER                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t cycles_done;
    uint64_t cycles_skipped;   /* zmeskane sloty (overrun = skip)     */
    uint64_t cycles_failed;
    double   worst_lateness_s; /* najvacsie meskanie oproti terminu   */
} vmic_sched_stats_t;

/* Vrati VMIC_OK / VMIC_FATAL / VMIC_STOP. `work` dostane poradove cislo
   a plánovany termin (monotonny cas), vracia vmic_rc_t. */
int vmic_sched_run(const vmic_config_t *cfg,
                   int (*work)(uint64_t seq, double deadline, void *user),
                   void *user,
                   volatile sig_atomic_t *stop,
                   vmic_sched_stats_t *out);

/* ------------------------------------------------------------------ */
/* VRSTVA 4: HOOKS (dlopen plugin)                                     */
/* ------------------------------------------------------------------ */

#define VMIC_HOOK_ABI 1u

/* Sluzby, ktore modul poskytuje pluginu. */
typedef struct {
    unsigned abi;
    const vmic_config_t *cfg;
    void (*log)(int level, const char *fmt, ...);
} vmic_hook_api_t;

/*
 * Plugin (.so) musi exportovat tieto tri symboly. Pozri hooks/example_hook.c
 *
 *   int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **st);
 *   int  vmic_hook_snapshot(void *st, const vmic_snapshot_t *snap);
 *   void vmic_hook_fini(void *st);
 */
typedef int  (*vmic_hook_init_fn)(const vmic_hook_api_t *, const char *, void **);
typedef int  (*vmic_hook_snapshot_fn)(void *, const vmic_snapshot_t *);
typedef void (*vmic_hook_fini_fn)(void *);

/* Zmluva pluginu - tieto tri funkcie musis v svojom .so definovat.
   (Zberac ich nedefinuje, iba ich hlada cez dlsym.) */
int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **state);
int  vmic_hook_snapshot(void *state, const vmic_snapshot_t *snap);
void vmic_hook_fini(void *state);

typedef struct vmic_hooks vmic_hooks_t;

vmic_hooks_t *vmic_hooks_load(const vmic_config_t *cfg);
int           vmic_hooks_fire(vmic_hooks_t *h, const vmic_snapshot_t *snap);
void          vmic_hooks_unload(vmic_hooks_t *h);

/* ------------------------------------------------------------------ */
/* Zberac - spaja vsetky styri vrstvy                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    const vmic_config_t *cfg;
    vmic_backend_t       backend;
    vmic_writer_t        writer;
    vmic_vminfo_t        vm;
    vmic_hooks_t        *hooks;
    vmic_region_t        regions[VMIC_MAX_REGIONS];
    size_t               region_count;
    uint64_t             seq;
    uint64_t             total_bytes;
    volatile sig_atomic_t *stop;
} vmic_collector_t;

int  vmic_collector_init(vmic_collector_t *c, const vmic_config_t *cfg,
                         volatile sig_atomic_t *stop);
int  vmic_collector_cycle(vmic_collector_t *c, vmic_snapshot_t *out);
void vmic_collector_fini(vmic_collector_t *c);

/* ------------------------------------------------------------------ */
/* Konfiguracia - config.c                                             */
/* ------------------------------------------------------------------ */

void vmic_config_defaults(vmic_config_t *cfg);
int  vmic_config_load(vmic_config_t *cfg, const char *path);
/* jednorazovy override z prikazoveho riadku: "sekcia.kluc=hodnota" */
int  vmic_config_set(vmic_config_t *cfg, const char *assignment);
/* `need_target` = true pri prikazoch, ktore sa naozaj pripajaju na VM
   (run/once/probe). Prikazy ako verify/restore/config ziadny backend
   nepotrebuju, takze by ich nemalo brzdit chybajuce vm.domain. */
int  vmic_config_validate(vmic_config_t *cfg, bool need_target);
void vmic_config_dump(const vmic_config_t *cfg, void *stream);
void vmic_config_help_keys(void *stream);
void vmic_backend_print_list(void *stream);

/* Sidecar metadata - meta.c */
int vmic_meta_write(const vmic_snapshot_t *snap, char *out_path, size_t n);

/* Retencia - retention.c
   `protect_chain` je id retazca, do ktoreho sa PRAVE zapisuje; nikdy sa
   nezmaze. 0 = nechranit nic (napr. pri raw writeri). */
int vmic_retention_apply(const vmic_config_t *cfg, uint64_t protect_chain);

/* Restore delta retazca - writer_delta.c */
int vmic_delta_restore(const char *dir, const char *out_path,
                       uint64_t chain_id, uint64_t until_seq);

#ifdef __cplusplus
}
#endif
#endif /* VMIC_H */
