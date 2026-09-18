# Architektúra a rozhrania

Dokument popisuje vrstvy, dátové toky, formáty a rozhrania tejto práce na úrovni
architektúry aj implementácie. Pokrýva bod zadania **I13 (API rozhranie)** a **D1
(dokumentácia architektúry a implementácie)**.

Pravidlá, ktorými sa dokument riadi:

- Každý komponent má cestu do repozitára a počet riadkov zistený príkazom `wc -l`.
- Každé rozhranie má **reálny príklad vstupu a výstupu**. Všetky výpisy nižšie sú
  výstupy behov spustených 2026-09-18 medzi 16:42 a 16:55 UTC nad týmto repozitárom.
  Jediná úprava výpisov je skrátenie dlhej cesty dočasného adresára na `$D` a vynechanie
  riadkov označené `...`; oboje je pri výpise napísané.
- Predlohou bol `vmicollect/README.md`, ale každé tvrdenie je overené proti zdrojovému
  kódu. Miesta, kde sa README a kód rozchádzajú, sú v časti 11.
- Odkazy do kódu sú na **súbor a meno funkcie alebo štruktúry**, nie na číslo riadku:
  repozitár sa počas písania menil a čísla riadkov by zastarali skôr než text.
- Čo nie je overené behom, je označené `UNVERIFIED` (`HONESTY.md`, P5).

---

## 1. Celkový pohľad

Reťazec má dve časti, ktoré spolu komunikujú **iba cez súbory na disku** — natívny formát
snímky `.vmicd` a JSON sidecar. Žiadny spoločný proces, žiadny socket, žiadna zdieľaná
pamäť.

```
 hostiteľ (Fedora 43, jadro 7.1.13-100.fc43.x86_64), root
 ┌──────────────────────────────────────────────────────────────────┐
 │ vmicollect (C + eBPF)                                            │
 │   číta fyzickú RAM bežiacej domény cez mapu memslotov modulu kvm  │
 │   výstup: <id>.vmicd (dáta) + <id>.json (metadáta)                │
 └───────────────────────────┬──────────────────────────────────────┘
                             │ súbory
 ┌───────────────────────────▼──────────────────────────────────────┐
 │ guestparse (Python 3, bez závislostí mimo štandardnej knižnice)   │
 │   + profil jadra hosťa (kallsyms + BTF)                           │
 │   výstup: procesy / moduly / sokety / kontroly ako JSON           │
 └──────────────────────────────────────────────────────────────────┘
```

Rozdelenie nie je kozmetické: zberač beží pod rootom a musí stihnúť periódu, parser beží
bez privilégií a môže bežať aj dlho po zbere, nad uloženou snímkou.

### 1.1 Komponenty, cesty a počty riadkov

Zistené 2026-09-18 o 16:55 UTC príkazom

```sh
wc -l vmicollect/include/vmic.h vmicollect/bpf/* vmicollect/src/* \
      vmicollect/hooks/*.c vmicollect/tests/*.c guestparse/*.py guestparse/tests/*.py
```

Na repozitári v tom čase paralelne pracovali ďalšie kroky práce, takže počty sú snímkou
stavu k uvedenému času a menia sa; príkaz vyššie ich vypíše znovu. Menia sa najmä súbory,
do ktorých sa dopĺňajú testy a kontroly.

| Komponent | Cesta | Riadkov | Čo robí |
|---|---|---:|---|
| verejné C API | `vmicollect/include/vmic.h` | 456 | všetky dátové typy a tabuľky operácií |
| ABI jadro ↔ zberač | `vmicollect/bpf/vmic_bpf_abi.h` | 217 | kontexty, chybové kódy, limity |
| BPF programy | `vmicollect/bpf/vmic_kvm.bpf.c` | 592 | `vmic_probe` (memsloty), `vmic_read` (stránky) |
| backend eBPF | `vmicollect/src/backend_ebpf.c` | 1214 | nájdenie domény, BTF, načítanie BPF, `read_pa` |
| backend súbor | `vmicollect/src/backend_file.c` | 132 | raw obraz na disku (vývoj, testy) |
| register backendov + čítacia slučka | `vmicollect/src/backend.c` | 282 | `vmic_capture()`, delenie na bloky |
| zberný cyklus | `vmicollect/src/collector.c` | 376 | spojenie štyroch vrstiev do jedného cyklu |
| plánovač | `vmicollect/src/sched.c` | 153 | absolútne termíny, jitter, politika pri preťažení |
| writer delta | `vmicollect/src/writer_delta.c` | 644 | formát `.vmicd`, reťazce, obnova |
| writer raw | `vmicollect/src/writer_raw.c` | 346 | celý obraz, riedky zápis, gzip, SHA-256 |
| hooky | `vmicollect/src/hooks.c` | 160 | `dlopen()` pluginu, volanie po každej snímke |
| sidecar | `vmicollect/src/meta.c` | 148 | JSON `vmicollect/1` |
| retencia | `vmicollect/src/retention.c` | 287 | mazanie starých snímok po reťazcoch |
| konfigurácia | `vmicollect/src/config.c` | 751 | INI parser riadený tabuľkou `FIELDS` |
| CLI zberača | `vmicollect/src/main.c` | 682 | `run`, `once`, `probe`, `restore`, `verify`, `selftest` |
| pomocné | `vmicollect/src/util.c`, `sha256.c`, `log.c`, `writer.c` | 442, 403, 117, 53 | čas, I/O, hashe, logovanie, register writerov |
| vzorový hook | `vmicollect/hooks/example_hook.c` | 108 | plugin, ktorý po každej snímke pripíše riadok do CSV |
| regresný test dier | `vmicollect/tests/hole_test.c` | 111 | kontrakt `read_pa()` s falošným backendom |
| čítanie snímok | `guestparse/image.py` | 391 | `.vmicd` bez rozbaľovania, overenie reťazca, raw obraz |
| profil jadra | `guestparse/profile.py` | 198 | kallsyms + offsety polí z BTF |
| pohľad na hosťa | `guestparse/view.py` | 608 | preklad adries, procesy, moduly, sokety |
| kontroly integrity | `guestparse/checks.py` | 445 | `sys_call_table`, krížové pohľady |
| porovnanie s pozemnou pravdou | `guestparse/validate.py` | 288 | `ps` / `lsmod` / `ss` vs. snímka |
| CLI parsera | `guestparse/cli.py` | 332 | podpríkazy `ps`, `lsmod`, `ss`, `info`, `checks`, `validate` |
| testy parsera | `guestparse/tests/` | 1519 | 88 testov, pozri časť 10 |

Súčet zdrojového kódu zberača (hlavičky, C, BPF, hook, test): 7828 riadkov.
Balík `guestparse` bez testov: 2296 riadkov, s testami 3815 riadkov.

---

## 2. Vrstvy zberača

Zberač má štyri vrstvy, ktoré sa navzájom vidia iba cez tabuľky ukazovateľov na funkcie
(`vmic_backend_ops_t`, `vmic_writer_ops_t`). Všetko je deklarované v
`vmicollect/include/vmic.h`.

```
        ┌────────────────────────────────────────────────┐
        │ sched.c            KEDY sa zbiera              │
        │ absolútne termíny na monotónnych hodinách,     │
        │ jitter, politika pri preťažení (skip /         │
        │ catch_up / stretch)                            │
        └───────────────────┬────────────────────────────┘
                            │ work(seq, deadline)
        ┌───────────────────▼────────────────────────────┐
        │ collector.c        JEDEN CYKLUS                │
        │ begin_cycle → refresh_vm → writer.begin →      │
        │ [pause] → vmic_capture → [resume] →            │
        │ writer.finish → meta → hooks → retention       │
        └────┬───────────────────────────────┬───────────┘
             │ ODKIAĽ bajty                  │ KAM ich uložiť
  ┌──────────▼──────────────┐    ┌───────────▼─────────────────┐
  │ backend_ebpf.c  KVM     │    │ writer_delta.c  iba zmeny   │
  │ backend_file.c  súbor   │    │ writer_raw.c    celý obraz  │
  └──────────┬──────────────┘    └─────────────────────────────┘
             │ bpf_prog_test_run()
  ┌──────────▼──────────────┐
  │ bpf/vmic_kvm.bpf.c      │  BEŽÍ V JADRE
  │  vmic_probe  memsloty   │  struct kvm → mapa GPA ↔ HVA
  │  vmic_read   stránky    │  bpf_copy_from_user_task → mapa `pages`
  └─────────────────────────┘
```

**Poradie operácií v cykle** je v `collector.c` (funkcia `vmic_collector_cycle`)
navrhnuté tak, aby bol prípadný čas zastavenia VM čo najkratší. Overené proti kódu:

| Poradie | Volanie | Vnútri pauzy? |
|---:|---|---|
| 1 | `ops->begin_cycle()` — obnova mapy memslotov | nie |
| 2 | `refresh_vm()` — prepočet zbieraných oblastí | nie |
| 3 | `writer.ops->begin()` — vytvorenie súboru | nie |
| 4 | `vmic_backend_pause()` | hranica pauzy |
| 5 | `vmic_capture()` — čítanie pamäte a kŕmenie writera | **áno** |
| 6 | `vmic_backend_resume()` | hranica pauzy |
| 7 | `writer.ops->finish()` — gzip, `fsync`, `rename` | nie |
| 8 | `vmic_meta_write()` — JSON sidecar | nie |
| 9 | `vmic_hooks_fire()` — používateľské pluginy | nie |
| 10 | `vmic_retention_apply()` | nie |

Kroky 4 a 6 sa vykonajú len vtedy, keď backend pauzu vie. Pri backende `ebpf` je
`ops->pause == NULL`, takže sa pauza nezapne a nemeria vôbec:

```
$ grep -n "\.pause " vmicollect/src/backend_ebpf.c vmicollect/src/backend_file.c
vmicollect/src/backend_file.c:119:    .pause         = f_pause,
vmicollect/src/backend_ebpf.c:1167:    .pause         = NULL,
vmicollect/src/backend_ebpf.c:1201:    .pause         = NULL,
```

(Druhý výskyt je náhradná tabuľka pre build bez podpory eBPF.) Dôsledky sú
v `docs/LIMITACIE.md`, časť L1.

### 2.1 Vrstva 1: backend

Backend odpovedá na otázku „odkiaľ berieme bajty“. Kontrakt je `vmic_backend_ops_t`.

| Pole | Význam | `ebpf` | `file` |
|---|---|---|---|
| `random_access` | vie čítať ľubovoľný rozsah cez `read_pa` | `true` | `true` |
| `open` / `close` | pripojenie / odpojenie | áno | áno |
| `probe` | parametre VM do `vmic_vminfo_t` | áno | áno |
| `pause` / `resume` | zastavenie vCPU | **`NULL`** | áno |
| `begin_cycle` | čo sa mohlo medzi snímkami zmeniť (memsloty) | áno | `NULL` |
| `read_pa` | čítanie rozsahu fyzických adries | áno | áno |
| `dump_to` | hromadný výpis celého obrazu | `NULL` | `NULL` |

Kontrakt `read_pa()` je najprísnejší bod modulu a je slovne zapísaný v komentári nad
deklaráciou vo `vmic.h`: funkcia naplní **celý** buffer (prečítanými bajtmi a nulami tam,
kde pamäť namapovaná nie je), vráti počet naozaj prečítaných bajtov, a **cez dieru musí
preskočiť, nie sa na nej zastaviť**. Dôvod je v hlavičke `tests/hole_test.c`: backend,
ktorý sa na prvej nečitateľnej stránke zastaví a zvyšok bloku doplní nulami, ticho zahodí
aj čitateľnú pamäť za dierou.

### 2.2 Vrstva 2: writer

Writer odpovedá na otázku „kam a v akom tvare“. Kontrakt `vmic_writer_ops_t`:
`begin` → `feed` (opakovane, súvislé bloky) → `finish`, alebo `abort`. Pre hromadné
backendy existuje dvojica `staging` / `adopt`. `writer_delta.c` má
`needs_random_access = true`, lebo s hromadným výpisom pracovať nevie.

### 2.3 Vrstva 3: plánovač

`vmic_sched_run()` počíta **absolútne** termíny na monotónnych hodinách a spí do nich cez
`clock_nanosleep(TIMER_ABSTIME)`. Dôvod je v hlavičke `sched.c`: naivné „spracuj a potom
`sleep(interval)`“ kumuluje drift, takže časová rada po hodine nesedí, a `Ctrl-C` sa
prejaví až po dospaní celej periódy.

Politika pri preťažení (`[schedule].overrun`):

| Hodnota | Správanie | Kedy sa hodí |
|---|---|---|
| `skip` | drží pôvodnú mriežku, zmeškané sloty zahodí | časové rady — vzorky ostávajú na násobkoch periódy |
| `catch_up` | dobehne zmeškané sloty hneď za sebou | keď sa nesmie stratiť vzorka |
| `stretch` | ďalší termín = teraz + perióda | bez dávok, ale mriežka sa posúva |

### 2.4 Vrstva 4: hooky

Po každej hotovej snímke sa zavolajú načítané pluginy. Detaily v časti 4.

---

## 3. C API: `vmicollect/include/vmic.h`

Hlavička je jediné verejné rozhranie zberača (456 riadkov):

| Sekcia | Obsah |
|---|---|
| úrovne logovania, `vmic_rc_t` | `VMIC_OK` / `VMIC_ERR` / `VMIC_FATAL` / `VMIC_STOP` |
| `vmic_config_t` | celá konfigurácia v jednej štruktúre |
| `vmic_vminfo_t` | parametre cieľovej VM vrátane zoznamu skutočne namapovaných oblastí |
| `vmic_stats_t` | surové počítadlá jedného čítania |
| `vmic_snapshot_t` | záznam o jednej snímke; dostane ho writer, sidecar aj každý hook |
| `vmic_backend_ops_t`, `vmic_capture()` | vrstva backendu |
| `vmic_writer_ops_t` | vrstva writera |
| `vmic_sched_run()` | plánovač |
| `vmic_hook_api_t`, `vmic_hooks_*` | hooky |
| `vmic_collector_t` | zberač |
| `vmic_config_*`, `vmic_meta_write`, `vmic_retention_apply`, `vmic_delta_restore` | ostatné |

Rozlíšenie `VMIC_ERR` a `VMIC_FATAL` nie je formalita: pri `ERR` zberač preskočí cyklus
a skúsi to o periódu neskôr (VM sa napríklad práve migruje), pri `FATAL` končí.

### 3.1 Reálny príklad: zber s vlastným pluginom

Príklad používa backend `file`, takže **nepotrebuje root ani bežiacu VM** a dá sa
zopakovať na ktoromkoľvek stroji, kde sa repozitár preloží. Overuje naraz štyri veci:
konfiguráciu cez `-o`, plánovač, writer `delta` a hook API.

Vstup:

```sh
D=$(mktemp -d)                      # v tomto behu dočasný adresár mimo repozitára
python3 -c "import os; open('$D/mem.raw','wb').write(os.urandom(64*1024)); os.truncate('$D/mem.raw', 8*1024*1024)"

make -C vmicollect          # -> build/vmicollect
make -C vmicollect hooks    # -> build/example_hook.so

./vmicollect/build/vmicollect run \
  -o vm.backend=file -o vm.image_path=$D/mem.raw \
  -o output.dir=$D/snap -o output.writer=delta \
  -o schedule.interval_s=1 -o schedule.max_cycles=3 \
  -o hooks.load=./vmicollect/build/example_hook.so:$D/index.csv
```

Výstup (doslovne; cesta dočasného adresára je v prepise nahradená `$D`):

```
2026-09-18T16:54:15.545Z INFO  file: '$D/mem.raw' otvoreny, 8388608 B
2026-09-18T16:54:15.545Z INFO  VM 'mem.raw' [file]: RAM 8.00 MiB, max_paddr 0x800000, vCPU 0, strankovanie n/a
2026-09-18T16:54:15.545Z INFO  zbierane oblasti: 1, spolu 8.00 MiB
2026-09-18T16:54:15.545Z INFO  example_hook: zapisujem index do '$D/index.csv'
2026-09-18T16:54:15.545Z INFO  hooks: nacitany './vmicollect/build/example_hook.so' s argumentmi: $D/index.csv
2026-09-18T16:54:15.545Z INFO  zacinam zber: perioda 1.000 s, writer 'delta', vystup '$D/snap'
2026-09-18T16:54:15.549Z INFO  #0 PLNA   68.00 KiB/8.00 MiB  stranky 16/2048 (0.78 %)  pauza 0.0 ms  citanie 3.1 ms  spolu 3.3 ms
2026-09-18T16:54:16.548Z INFO  #1 delta  4.00 KiB/8.00 MiB  stranky 0/2048 (0.00 %)  pauza 0.0 ms  citanie 2.8 ms  spolu 3.0 ms
2026-09-18T16:54:17.552Z INFO  #2 delta  4.00 KiB/8.00 MiB  stranky 0/2048 (0.00 %)  pauza 0.0 ms  citanie 6.0 ms  spolu 6.1 ms
2026-09-18T16:54:17.552Z INFO  koniec: 3 snimok, 0 chyb, 0 zmeskanych slotov, najvacsie meskanie 0.000 s, spolu 76.00 KiB
```

Súbor, ktorý zapísal plugin (`$D/index.csv`), doslovne:

```
seq,timestamp_unix,path,bytes_on_disk,pause_ms,capture_ms,total_ms,pages_changed,pages_total
0,1789750455.545,$D/snap/mem.raw_000000_20260918T165415545Z.vmicd,69632,0.000,3.146,3.305,16,2048
1,1789750456.545,$D/snap/mem.raw_000001_20260918T165416545Z.vmicd,4096,0.000,2.818,2.973,0,2048
2,1789750457.546,$D/snap/mem.raw_000002_20260918T165417546Z.vmicd,4096,0.000,5.958,6.142,0,2048
```

A adresár, ktorý z toho vznikol:

```
$ ls -l $D/snap
-rw-r--r--. 1 eh eh  1249 Sep 18 18:54 mem.raw_000000_20260918T165415545Z.json
-rw-r--r--. 1 eh eh 65728 Sep 18 18:54 mem.raw_000000_20260918T165415545Z.vmicd
-rw-r--r--. 1 eh eh  1248 Sep 18 18:54 mem.raw_000001_20260918T165416545Z.json
-rw-r--r--. 1 eh eh    64 Sep 18 18:54 mem.raw_000001_20260918T165416545Z.vmicd
-rw-r--r--. 1 eh eh  1248 Sep 18 18:54 mem.raw_000002_20260918T165417546Z.json
-rw-r--r--. 1 eh eh    64 Sep 18 18:54 mem.raw_000002_20260918T165417546Z.vmicd
```

Prvá snímka je plná (16 nenulových stránok z 2048, súbor 65 728 B = 64 + 16 × 4104).
Ďalšie dve sú delty s nula zmenenými stránkami: súbor má presne 64 bajtov, teda iba
hlavičku. `bytes_on_disk` je pri nich 4096, lebo to je najmenšia alokácia na súborovom
systéme (rozdiel vysvetľuje časť 5.3).

---

## 4. Hook ABI

### 4.1 Čo hook dostane

Plugin je zdieľaná knižnica načítaná cez `dlopen(RTLD_NOW)` a musí exportovať tri
symboly:

```c
int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **state);
int  vmic_hook_snapshot(void *state, const vmic_snapshot_t *snap);
void vmic_hook_fini(void *state);
```

Pri inicializácii dostane `vmic_hook_api_t`. **Celá štruktúra má tri polia:**

```c
typedef struct {
    unsigned abi;                  /* VMIC_HOOK_ABI, dnes 1 */
    const vmic_config_t *cfg;      /* konfigurácia, iba na čítanie */
    void (*log)(int level, const char *fmt, ...);
} vmic_hook_api_t;
```

Pri každej snímke dostane `const vmic_snapshot_t *`: poradové číslo, id reťazca, cestu
k hotovému súboru na disku, cestu k sidecaru, čas, časy `pause_ms` / `capture_ms` /
`write_ms` / `total_ms`, `bytes_logical`, `bytes_on_disk`, `pages_total`, `pages_changed`,
skutočný príznak `paused`, zbierané oblasti, SHA-256 a ukazovatele na `vmic_vminfo_t`
a `vmic_config_t`.

### 4.2 Čo hook NEDOSTANE

Toto je vlastnosť rozhrania, nie prehliadnutie, a treba ju priznať, lebo od nej závisí
návrh skórovacieho hooku:

- **Nedostane `read_pa` ani inú funkciu na čítanie pamäte hosťa.** V `vmic_hook_api_t`
  nie je ukazovateľ na backend ani na zberač; jediná služba je `log`.
- **Nedostane obsah stránok.** Ani ukazovateľ do buffra, ani mapované okno. Dostane iba
  `snap->path`, teda cestu k súboru, ktorý si musí otvoriť sám.
- **Nedostane príznakový vektor.** Rozhranie pozná iba počítadlá zo `stats`
  a dvojicu `pages_changed` / `pages_total`.
- **Nedostane možnosť ovplyvniť zber.** Návratová hodnota má dva významy: 0 = v poriadku,
  nenulová = chyba. Pri `[hooks].strict = true` zberač skončí, inak sa plugin vypne do
  konca behu a zber pokračuje (`vmic_hooks_fire` v `hooks.c`).

**Rozhranie je teda notifikačné.** Hook sa dozvie, že snímka existuje a kde leží. Všetko
ostatné si musí urobiť sám zo súboru.

Tri ďalšie vlastnosti, ktoré z toho vyplývajú (hlavička `hooks.c`, hlavička
`example_hook.c`):

1. Hook beží **synchrónne v hlavnej slučke**. Keď trvá dlhšie ako perióda, zberač začne
   zmeškávať sloty.
2. Hook beží **až po dokončení zápisu snímky** (a keď backend pauzuje, až po odpauzovaní
   VM). Nespomaľuje teda hosťa, iba zberač.
3. `abi` sa kontroluje v `vmic_hook_init`; keď sa zberač a plugin preložili proti rôznym
   verziám `vmic.h`, plugin má vrátiť nenulovú hodnotu.

### 4.3 Dôsledok pre skórovací hook

Skórovací hook, ktorý má vracať výstup modelu späť do modulu, nemôže čítať pamäť cez
rozhranie hooku. Má dve možnosti: otvoriť si `snap->path` sám (a zaplatiť čítanie z disku),
alebo pracovať iba s tým, čo mu odovzdá sidecar a delta writer. Tento dôsledok patrí do
kapitoly o návrhu; tu je zapísaný ako fakt o rozhraní.

---

## 5. Formát `.vmicd`

Formát zapisuje `vmicollect/src/writer_delta.c`, číta ho tá istá jednotka
(`vmic_delta_restore`) a nezávisle od nej `guestparse/image.py`.

### 5.1 Hlavička, 64 bajtov, little-endian

Konštanty sú `DELTA_MAGIC "VMICDLT1"`, `DELTA_HDR 64`, `DELTA_VERSION 1`,
`DELTA_FLAG_FULL 1` (`writer_delta.c`), na strane parsera `VMICD_MAGIC`, `VMICD_HDR`,
`VMICD_VERSION`, `VMICD_FLAG_FULL` (`image.py`).

| Offset | Typ | Pole | Poznámka |
|---:|---|---|---|
| 0 | `char[8]` | magic | `VMICDLT1` |
| 8 | `u32` | verzia | dnes 1 |
| 12 | `u32` | veľkosť stránky | `[output].delta_page_size`, štandardne 4096 |
| 16 | `u64` | id reťazca | milisekundová značka prvej plnej snímky reťazca |
| 24 | `u64` | poradové číslo snímky | `seq` od štartu zberača |
| 32 | `u64` | logická veľkosť pamäte | koniec poslednej zbieranej oblasti |
| 40 | `u64` | počet záznamov v tomto súbore | |
| 48 | `u64` | príznaky | bit 0 = plná snímka |
| 56 | `u64` | podpis konfigurácie oblastí | zmena vynúti novú plnú snímku |

Za hlavičkou nasleduje `počet záznamov` × (`u64` index stránky, `u8[veľkosť stránky]`
obsah). Záznamy sú pevne dlhé, takže index sa dá postaviť čítaním samotných indexov bez
kopírovania obsahu — presne to robí `VmicdImage._load`.

Dve konštrukčné rozhodnutia, ktoré treba poznať, aby formát dával zmysel:

- **Podpis oblastí** sa počíta zo *skutočne zbieraných* oblastí, nie z `[capture].regions`.
  Pri prázdnom nastavení je konfigurácia stále rovnaká, ale rozsah sa zmeniť môže (hotplug
  pamäte, reštart domény s inou veľkosťou RAM) a staré hashe by potom hovorili o inom
  rozsahu.
- **Tabuľka hashov sa inicializuje hodnotou „hash nulovej stránky“.** Obnova začína
  prázdnym súborom, takže „túto stránku som ešte nevidel“ a „stránka je nulová“ sú
  z pohľadu obnovy to isté a netreba žiadny bitmapový príznak.

### 5.2 Overenie: obe strany čítajú formát rovnako

**(a) Hlavička.** Nezávislé čítanie cez `struct.unpack("<8sIIQQQQQQ")` proti
`guestparse.image.VmicdImage.header()`, nad reálnou delta snímkou z bežiacej domény
`hyptcn-guest`:

```
$ python3 hdr.py data/raw/20260918T154742Z_run/hyptcn-guest_000001_20260918T154748651Z.vmicd
nezavisle citanie hlavicky (struct.unpack '<8sIIQQQQQQ'):
  magic       = b'VMICDLT1'
  verzia      = 1
  page_size   = 4096
  chain_id    = 1789746463651
  seq         = 1
  memsize     = 4294967296
  records     = 324
  flags       = 0x0 (plna snimka: False)
  region_sig  = 0xe512fc77dd5cc558
  velkost suboru = 1329760 B
  64 + records*(8+page_size) = 1329760 B  -> sedi
guestparse.VmicdImage.header():
  version     = 1
  page_size   = 4096
  chain_id    = 1789746463651
  seq         = 1
  memsize     = 4294967296
  records     = 324
  full        = False
  region_sig  = 16506533176011441496
obe citania daju rovnake hodnoty: True
```

Veľkosť súboru presne sedí so vzorcom `64 + záznamy × (8 + veľkosť stránky)`, takže medzi
záznammi nie je zarovnanie ani výplň.

**(b) Obsah.** Reálny reťazec z domény `hyptcn-guest` (plná snímka, 124 005 stránok) sa
obnovil C implementáciou a zároveň sa ten istý reťazec prečítal Pythonom. Porovnala sa
každá stránka:

```
$ ./vmicollect/build/vmicollect restore \
      --dir data/sessions/20260918T154914Z_validate/snap --out $SC/real_restored.raw
2026-09-18T16:42:24.325Z INFO  restore: vyberam najnovsi retazec 1789746556673
2026-09-18T16:42:24.533Z INFO  restore: data/sessions/.../hyptcn-guest_000000_20260918T154916673Z.vmicd  seq=0  PLNA   124005 stranok
2026-09-18T16:42:24.533Z INFO  restore: hotovo -> $SC/real_restored.raw (4.00 GiB, 124005 zapisanych stranok)

$ python3 cross_real.py data/sessions/20260918T154914Z_validate/snap $SC/real_restored.raw
stranok v retazci: 124005 (po 4096 B)
rozdielnych voci C obnove: 0
kontrolovanych chybajucich stranok: 926, nenulovych: 0
logicka velkost podla hlavicky: 4294967296 B
```

Nula rozdielnych stránok zo 124 005 a nula nenulových medzi kontrolovanou vzorkou
chýbajúcich stránok. **Obe implementácie teda čítajú `.vmicd` rovnako**, vrátane dohody,
že stránka, ktorá v reťazci nie je, je nulová.

Rovnaká kontrola nad krátkym reťazcom z časti 3.1 ukazuje, že sa zhoduje aj výsledný
SHA-256 celého obrazu a že obnova sedí s pôvodným súborom bajt po bajte:

```
$ ./vmicollect/build/vmicollect restore --dir $D/snap --out $D/restored.raw
2026-09-18T16:54:17.557Z INFO  restore: vyberam najnovsi retazec 1789750455545
2026-09-18T16:54:17.557Z INFO  restore: $D/snap/mem.raw_000000_20260918T165415545Z.vmicd  seq=0  PLNA   16 stranok
2026-09-18T16:54:17.557Z INFO  restore: $D/snap/mem.raw_000001_20260918T165416545Z.vmicd  seq=1  delta  0 stranok
2026-09-18T16:54:17.557Z INFO  restore: $D/snap/mem.raw_000002_20260918T165417546Z.vmicd  seq=2  delta  0 stranok
2026-09-18T16:54:17.557Z INFO  restore: hotovo -> $D/restored.raw (8.00 MiB, 16 zapisanych stranok)

$ cmp $D/mem.raw $D/restored.raw && echo "cmp: bez rozdielu"
cmp: bez rozdielu

$ python3 cross.py $D/snap $D/restored.raw
stranok porovnanych: 2048 po 4096 B
rozdielnych stranok: 0
sha256 z Python citania: c2a8871ac09f669e6b2f6eab1005b6384f331d2f9f309aaae1dc059dd7cfdca8
sha256 z C obnovy     : c2a8871ac09f669e6b2f6eab1005b6384f331d2f9f309aaae1dc059dd7cfdca8
```

**(c) Výber reťazca a jeho overenie.** Keď používateľ reťazec nezadá, obe strany berú ten
s najvyšším `chain_id` a prehrávajú ho v poradí `seq`; neskorší záznam prepisuje starší.
Miešanie dvoch reťazcov by dalo pamäť, ktorá v hosťovi nikdy naraz neexistovala, preto to
nerobí ani jedna strana. Parser navyše reťazec pri otvorení **overí** a nekompletný
odmietne výnimkou `ChainError` — s rovnakým odôvodnením, aké má `vmic_delta_restore`.

### 5.3 Dve veľkosti, ktoré si netreba zamieňať

- `bytes_logical` (a pole „logická veľkosť pamäte“ v hlavičke) je koniec poslednej
  zbieranej oblasti — pre doménu `hyptcn-guest` je to 4 294 967 296 B, hoci RAM má
  2 164 396 032 B. Rozdiel je diera vo fyzickom priestore pod 4 GiB.
- `bytes_on_disk` v sidecari **nie je veľkosť súboru**, ale skutočná alokácia
  `st_blocks × 512` (`vmic_file_disk_usage` v `util.c`). Pri delta snímke z časti 5.2 má
  súbor 1 329 760 B, ale `bytes_on_disk` je 1 331 200 B, lebo súborový systém alokoval
  2600 blokov po 512 B.

---

## 6. Formát JSON sidecaru (`schema: "vmicollect/1"`)

Vedľa každej snímky vzniká `.json` so všetkými metadátami (`meta.c`). Je to rozhranie
medzi zberom a všetkým, čo príde po ňom; JSON si modul zapisuje sám, aby nemal ďalšiu
závislosť.

Reálny príklad — plná delta snímka domény `hyptcn-guest`, súbor
`data/sessions/20260918T154914Z_validate/snap/hyptcn-guest_000000_20260918T154916673Z.json`,
vložený doslovne:

```json
{
  "schema": "vmicollect/1",
  "version": "1.0.0",
  "seq": 0,
  "id": "hyptcn-guest_000000_20260918T154916673Z",
  "path": "/home/eh/Desktop/hyptcn3/data/sessions/20260918T154914Z_validate/snap/hyptcn-guest_000000_20260918T154916673Z.vmicd",
  "timestamp": "2026-09-18T15:49:16.673Z",
  "timestamp_unix": 1789746556.673,
  "vm": {
    "domain": "hyptcn-guest",
    "backend": "ebpf/kvm",
    "vmid": 1353046,
    "memsize": 2164396032,
    "max_paddr": 4294967296,
    "num_vcpus": 2,
    "address_width": 0,
    "page_mode": "n/a"
  },
  "capture": {
    "regions": [],
    "chunk_size": 1048576,
    "paused": false,
    "pause_ms": 0.000,
    "pause_exceeded": false,
    "capture_ms": 946.415,
    "write_ms": 1631.550,
    "total_ms": 2578.064
  },
  "stats": {
    "bytes_requested": 2164396032,
    "bytes_read": 2164396032,
    "chunks": 2067,
    "read_errors": 0,
    "filled_zero": 0,
    "read_mib_s": 2181.00
  },
  "output": {
    "writer": "delta",
    "full": true,
    "chain_id": 1789746556673,
    "bytes_logical": 4294967296,
    "bytes_on_disk": 508919808,
    "pages_total": 528417,
    "pages_changed": 124005,
    "page_size": 4096,
    "changed_ratio": 0.234673,
    "sha256_covers_file": true,
    "sha256": "13d795cc83a28b210116280d4b25c53d8e33c5a6ae6fbde2a05d3a748c93d21a"
  }
}
```

Poznámky k poliam, overené proti `meta.c`:

| Pole | Význam |
|---|---|
| `capture.regions` | obsah `[capture].regions` z konfigurácie; prázdne pole znamená „nezadané“, nie „nič sa nezbieralo“ — skutočne zbierané oblasti vypíše zberač do logu |
| `capture.paused` | **skutočnosť, nie želanie konfigurácie**. Backend bez `pause()` VM nezastaví, aj keď to config žiada |
| `stats.bytes_read` | koľko bajtov sa naozaj podarilo prečítať; rozdiel oproti `bytes_requested` je strata |
| `stats.filled_zero` | bajty nahradené nulami (diery vo fyzickom priestore) |
| `stats.read_mib_s` | `bytes_read / read_seconds` |
| `output.pages_*` | zapisuje sa iba pri writeri s delta počítadlami |
| `output.sha256_covers_file` | `true` = kontrolný súčet pokrýva presne obsah súboru; `false` = iba zozbierané oblasti, takže sa nedá porovnať s hashom súboru na disku |

Sidecar delta snímky sa líši iba v `capture` a `output`; napríklad druhá snímka toho
istého behu (`data/raw/20260918T154742Z_run/hyptcn-guest_000001_20260918T154748651Z.json`)
má `"full": false`, `"pages_changed": 324`, `"changed_ratio": 0.000613`,
`"capture_ms": 557.064` a `"write_ms": 7.741`.

---


### 6.1 Blok `features` — per-bin príznakový vektor

Od fázy F2 modul do sidecaru pripisuje blok `features` (schéma `hyptcn3/perbin/1`).
Počíta ho `src/perbin.c`, napojený na delta writer — ten už každú stránku hashuje, takže
rozhodnutie „zmenila sa" tam existuje a per-bin počty sú takmer zadarmo. Raw writer vektor
nepočíta.

Binuje sa **iba nad memslotmi**; bin, ktorý neprotína žiadny memslot, nevzniká. Index binu
je `gpa >> log2(bin_bytes)`, teda viazaný na fyzickú adresu, nie na poradie — zostáva rovnaký
medzi snímkami aj keď sa počet memslotov zmení. Pole `regions` je v bloku preto, aby sa vlastnosť „biny sú iba nad memslotmi" dala overiť
zo samotnej archivovanej snímky, bez prístupu k bežiacej VM. Sú to **efektívne oblasti zberu**
odvodené z memslotov, so zlúčenými susedmi — pri doméne `hyptcn-guest` dáva 10 memslotov
5 oblastí. Nevolajú sa „memslots" práve preto, aby sidecar netvrdil viac, než v ňom je.

Reálna ukážka (skrátená na tri biny), súbor
`hyptcn-guest_000003_20260918T190343784Z.json`:

```json
{
  "schema": "hyptcn3/perbin/1",
  "bin_bytes": 16777216,
  "page_size": 4096,
  "entropy": true,
  "compute_ms": 52.801,
  "bins_total": 131,
  "regions": [ {"gpa": 0, "bytes": 655360}, ... 5 položiek ... ],
  "bins": [
    {
      "bin": 0,
      "gpa": 0,
      "pages_total": 4064,
      "pages_changed": 0,
      "changed_ratio": 0.0,
      "zero_ratio": 0.145177,
      "entropy_mean": 0.0,
      "has_changed": 0
    },
    {
      "bin": 1,
      "gpa": 16777216,
      "pages_total": 4096,
      "pages_changed": 40,
      "changed_ratio": 0.009766,
      "zero_ratio": 0.196777,
      "entropy_mean": 1.429049,
      "has_changed": 1
    },
    {
      "bin": 2,
      "gpa": 33554432,
      "pages_total": 4096,
      "pages_changed": 15,
      "changed_ratio": 0.003662,
      "zero_ratio": 0.125244,
      "entropy_mean": 2.279149,
      "has_changed": 1
    }
  ]
}
```

| pole | význam |
|---|---|
| `pages_total` | stránky binu podložené memslotmi — menovateľ pomerov |
| `pages_changed` | z nich zmenené oproti predchádzajúcej snímke |
| `changed_ratio` | `pages_changed / pages_total` |
| `zero_ratio` | podiel úplne nulových stránok zo všetkých podložených |
| `entropy_mean` | priemerná Shannonova entropia (bity/bajt, 0–8) **zmenených** stránok |
| `has_changed` | samostatný príznak 0/1 |

`has_changed` existuje preto, aby sa „bin sa nezmenil" dalo odlíšiť od „entropia vyšla 0".
Ticho doplnená nula by z týchto dvoch rôznych stavov spravila jeden. Keď je
`[features].entropy` vypnutá, kľúč `entropy_mean` v binoch **vôbec nie je** — chýbajúci kľúč
je poctivejší než nula, ktorá by sa dala prečítať ako meranie.

**Invariant, ktorý modul kontroluje sám:** súčet `pages_changed` cez biny sa musí rovnať
`output.pages_changed` a súčet `pages_total` počtu podložených stránok. Pri nezhode sa blok
do sidecaru nezapíše a vypíše sa chyba. Kontrolu robí `vmic_features_finish()`.

Obmedzenia vektora (kolinearita na plnej snímke, cena výpočtu, závislosť počtu binov na
veľkosti VM) sú v `docs/LIMITACIE.md`, položka L13.

---

## 7. Rozhranie `guestparse`

Balík má dve rozhrania — Python API a CLI — a obe stoja na tom istom objekte `GuestView`.

### 7.1 Python API

Verejné mená sú vymenované v `guestparse/__init__.py`:

| Meno | Modul | Čo robí |
|---|---|---|
| `open_image(cesta, chain_id=None, until_seq=None, validate=True)` | `image.py` | otvorí adresár s reťazcom `.vmicd`, jeden `.vmicd`, alebo raw obraz; rozbitý reťazec odmietne |
| `VmicdImage`, `RawImage` | `image.py` | čítanie snímky: `read(pa, n)`, `pages()`, `page_count()`, `header(path)` |
| `chain_files(adresar, ...)` | `image.py` | vyberie a zoradí jeden overený reťazec |
| `Profile`, `ProfileError`, `btf_offsets` | `profile.py` | symboly z kallsyms, offsety polí z BTF |
| `build_view(snimka, profil)` | `view.py` | otvorí snímku, načíta profil, nájde posun jadra; vracia `(view, image)` |
| `GuestView` | `view.py` | `processes()`, `modules()`, `sockets()`, `info()`, `to_pa()`, `walk_pa()` |
| `check_all(view)` | `checks.py` | kontroly integrity |

Reálny príklad — vstup:

```python
from guestparse import build_view, check_all

view, img = build_view(
    "data/sessions/20260918T154914Z_validate/snap",
    "profiles/debian12-6.1.0-42-cloud-amd64")
try:
    print("posun jadra: -0x%x" % abs(view.ktext_shift))
    ps = view.processes()
    print("procesov: %d, neuplne: %s" % (ps["count"], ps["truncated"]))
    print("prvy:", ps["processes"][0])
    so = view.sockets()
    print("socketov: %d, z toho LISTEN: %d"
          % (so["count"], sum(1 for s in so["sockets"] if s["state"] == "LISTEN")))
    res = check_all(view)
    print("nalezov kontrol: %d" % res["finding_count"])
finally:
    img.close()
```

Výstup (doslovne):

```
posun jadra: -0x200000
procesov: 80, neuplne: False
prvy: {'pid': 1, 'tgid': 1, 'comm': 'systemd', 'kernel_thread': False, 'task_va': 18446631688392985728}
socketov: 13, z toho LISTEN: 6
nalezov kontrol: 0
```

Každý výsledok prechodu zoznamu má tvar
`{'<kľúč>': [...], 'count': N, 'truncated': bool, 'stop_reason': str|None}`. Pole
`truncated` je povinná súčasť odpovede: tichý polovičný zoznam by sa nedal odlíšiť od
skutočného stavu hosťa.

### 7.2 CLI

Kontrakt je zapísaný v hlavičke `guestparse/cli.py` a je označený za nemenný, lebo sa naň
spoliehajú ostatné časti práce:

```
python3 -m guestparse ps       --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse lsmod    --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse ss       --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse info     --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse checks   --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse validate --snapshot <cesta> --profile <adresár> \
      --ps-before F --ps-after F [--lsmod F] [--ss F] --out results.json
```

Návratové kódy:

| Kód | Znamená |
|---:|---|
| 0 | prebehlo a nič sa nenašlo |
| 1 | kontrola niečo našla (`checks`) — zámerne nie 0, aby sa nález nestratil v skripte |
| 2 | chyba: snímka sa nedá otvoriť (aj rozbitý reťazec), profil sa nedá načítať, posun jadra sa nenašiel |
| 3 | podpríkaz nie je implementovaný |
| 4 | `checks`: nič sa nenašlo, ale aspoň jedna kontrola sa neuzavrela — nula z neuzavretej kontroly nie je dôkaz čistoty |

Výpisy nižšie sú zo snímky domény `hyptcn-guest` zozbieranej 2026-09-18 o 15:49:16 UTC.
Spoločné parametre:

```sh
S=data/sessions/20260918T154914Z_validate/snap
P=profiles/debian12-6.1.0-42-cloud-amd64
```

**`info`** — profil, posun jadra a krížová kontrola prekladu adries:

```
$ python3 -m guestparse info --snapshot $S --profile $P
snimka:        vmicd (124005 stranok po 4096 B)
               data/sessions/20260918T154914Z_validate/snap/hyptcn-guest_000000_20260918T154916673Z.vmicd
profil:        92716 symbolov, struktury: fdtable, file, files_struct, module, sock_common, socket, task_struct
               profiles/debian12-6.1.0-42-cloud-amd64/kallsyms.txt
               profiles/debian12-6.1.0-42-cloud-amd64/btf.txt
banner:        Linux version 6.1.0-42-cloud-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30)
banner PA:     0x16f1f560 (kandidat 10)
posun jadra:   -0x200000
page_offset:   0xffff99c940000000
krizova kontrola prekladu (linearne vs. tabulky stranok):
  linux_banner   0x16f1f560     == 0x16f1f560     zhoda
  init_task      0x1781aa40     == 0x1781aa40     zhoda
```

**`ps`** — procesy (prvých sedem a posledné tri riadky, stred vynechaný):

```
$ python3 -m guestparse ps --snapshot $S --profile $P
   PID   TGID COMM               TYP
     1      1 systemd            pouzivatel
     2      2 kthreadd           jadro
     3      3 rcu_gp             jadro
     4      4 rcu_par_gp         jadro
     5      5 slub_flushwq       jadro
     6      6 netns              jadro
     8      8 kworker/0:0H       jadro
...
  1701   1701 systemd            pouzivatel
  1702   1702 (sd-pam)           pouzivatel
spolu: 80 procesov
```

**`ss`** — sieťové spojenia (úplný výpis):

```
$ python3 -m guestparse ss --snapshot $S --profile $P
PROTO RODIN STAV         LOKALNA                        VZDIALENA                      PID/PROGRAM
RAW   v6    UNCONN       [::]:58                        [::]:0                         248/systemd-network
UDP   v4    UNCONN       0.0.0.0:0                      0.0.0.0:0                      248/systemd-network
UDP   v4    UNCONN       0.0.0.0:5355                   0.0.0.0:0                      364/systemd-resolve
TCP   v4    LISTEN       0.0.0.0:5355                   0.0.0.0:0                      364/systemd-resolve
UDP   v6    UNCONN       [::]:5355                      [::]:0                         364/systemd-resolve
TCP   v6    LISTEN       [::]:5355                      [::]:0                         364/systemd-resolve
UDP   v4    UNCONN       127.0.0.53:53                  0.0.0.0:0                      364/systemd-resolve
TCP   v4    LISTEN       127.0.0.53:53                  0.0.0.0:0                      364/systemd-resolve
UDP   v4    UNCONN       127.0.0.54:53                  0.0.0.0:0                      364/systemd-resolve
TCP   v4    LISTEN       127.0.0.54:53                  0.0.0.0:0                      364/systemd-resolve
UDP   v4    ESTABLISHED  192.168.122.100:53027          192.168.122.1:53               365/systemd-timesyn
TCP   v4    LISTEN       0.0.0.0:22                     0.0.0.0:0                      388/sshd
TCP   v6    LISTEN       [::]:22                        [::]:0                         388/sshd
spolu: 13 socketov
```

**`lsmod`** — načítané moduly (výpis skrátený):

```
$ python3 -m guestparse lsmod --snapshot $S --profile $P
MODUL                        ADRESA
raw_diag                     0xffffffffc04e9040
tcp_diag                     0xffffffffc0761040
udp_diag                     0xffffffffc075c040
inet_diag                    0xffffffffc07570c0
binfmt_misc                  0xffffffffc0716400
...
virtio_ring                  0xffffffffc03ab340
spolu: 51 modulov
```

**`checks`** — kontroly integrity (úplný výpis):

```
$ python3 -m guestparse checks --snapshot $S --profile $P
sys_call_table         451 poloziek v [0xffffffff96000000, 0xffffffff96e01ef2), nalezov: 0
procesy krizovo        tasks 80 vs. children/sibling 80, nalezov: 0
moduly krizovo         modules 51 vs. module_kset 51 (z 109 kobjektov), nalezov: 0
nalezov spolu: 0 (z toho hookov v tabulke volani: 0)
$ echo $?
0
```

Návratový kód 0 (a nie 4) znamená, že sa v tomto behu uzavreli všetky tri kontroly.
Čo nulový nález **nedokazuje**, je v `docs/LIMITACIE.md`, časť L10.

---

## 8. Tok dát od pamäte VM po JSON

Jeden cyklus, kompletne:

```
 1. fyzická RAM hosťa (doména hyptcn-guest, 2,02 GiB v 10 memslotoch)
      │
 2. modul kvm v jadre hostiteľa: struct kvm → kvm_memslots → mapa GPA ↔ HVA
      │  bpf/vmic_kvm.bpf.c: vmic_probe (prechod id_hash cez bpf_loop)
      ▼
 3. backend_ebpf.c: eb_begin_cycle() si mapu vypýta na začiatku KAŽDÉHO cyklu
      │  (bez toho by periodický zber čítal podľa zastaraného obrazu pamäte)
      ▼
 4. read_pa(paddr, buf, len)  →  bpf_prog_test_run(vmic_read)
      │  v jadre: bpf_copy_from_user_task(hva) → BPF mapa `pages` (2 MiB okno)
      │  v používateľskom priestore: memcpy z mmap tejto mapy
      ▼
 5. vmic_capture() (backend.c) delí oblasti na bloky [capture].chunk_size
      │  (v meraných behoch 1 MiB) a každý blok posunie writeru
      ▼
 6. writer_delta.c: pre každú stránku 64-bitový hash (vmic_hash64);
      │  zapíše sa iba stránka, ktorej hash sa líši od minulého cyklu
      ▼
 7. <id>.vmicd na disku  +  <id>.json (meta.c, schema vmicollect/1)
      │
      │   ── tu končí zberač; ďalej sa pracuje iba so súbormi ──
      ▼
 8. guestparse.image.open_image(): overenie reťazca, index stránok
      │  (index → súbor, offset); obsah sa nekopíruje, chýbajúca stránka = nulová
      ▼
 9. guestparse.profile.Profile: kallsyms (92716 symbolov) + offsety polí z BTF
      ▼
10. guestparse.view.GuestView.resolve(): sken banneru → kandidáti na posun jadra
      │  → overenie init_task.comm == "swapper/0" → ktext_shift, page_offset_base
      ▼
11. preklad adries: lineárne vetvy (obraz jadra, priamy mapping) alebo
      │  prechod tabuliek stránok z init_top_pgt (moduly, vmalloc)
      ▼
12. prechod spájaných zoznamov jadra → procesy / moduly / sokety
      ▼
13. JSON na stdout (--json) alebo do súboru (validate --out)
```

Krok 4 sa v texte práce nesmie nazvať „nulovým kopírovaním“: je to **jedno prekročenie
hranice jadro/používateľ a jeden `memcpy` v používateľskom priestore** (`HONESTY.md`, P5).

### 8.1 Kde presne sa prekonáva semantic gap

Semantic gap je rozdiel medzi tým, čo vidí hypervízor (bajty na fyzických adresách), a tým,
čo znamenajú vnútri hosťa (procesy, moduly, sokety). V tomto reťazci sa prekonáva na
**troch miestach, všetkých v `guestparse`** — zberač semantiku hosťa nepozná vôbec a ani
ju poznať nepotrebuje.

**Miesto 1 — nájdenie kotvy (`GuestView.resolve` vo `view.py`).** Bez nej nemá žiadna
adresa zo symbolu zmysel, lebo obraz jadra je pri KASLR posunutý o neznámu hodnotu.
Postup:

1. Prehľadá sa celá snímka na výskyt reťazca `"Linux version "`; pomocná funkcia `_find`
   spája susedné stránky, aby sa reťazec na hranici stránok nestratil.
2. Každý výskyt je kandidát na fyzickú adresu symbolu `linux_banner`; z neho vyplýva
   posun `shift = pa − (banner_va − __START_KERNEL_map)`.
3. Kandidát platí až vtedy, keď pri jeho posune `init_task.comm` naozaj obsahuje
   `"swapper/0"`. **Posun sa teda nehádže.** V meranej snímke bol správny až 10. kandidát
   — reťazec sa v pamäti nachádza aj v logu jadra a v dátach `/proc`, takže samotný nález
   nestačí.

Výsledok pre meranú snímku: posun `-0x200000`, `banner PA = 0x16f1f560`,
`page_offset_base = 0xffff99c940000000`.

**Miesto 2 — preklad adries (`view.py`).** Tri cesty, presne ako v jadre x86_64:

| Oblasť | Vzťah | Funkcia |
|---|---|---|
| obraz jadra | `PA = VA − __START_KERNEL_map + posun` | `ktext_pa()` |
| priamy mapping | `PA = VA − page_offset_base` | `direct_pa()` |
| moduly a vmalloc | prechod 4 úrovní tabuliek stránok z `init_top_pgt` | `walk_pa()` |

`to_pa()` skúša najprv lacné lineárne vetvy a až potom tabuľky. Horná hranica lineárnej
vetvy je `MODULES_VADDR`: nad ňou lineárny vzťah neplatí a výpočet by ticho vrátil cudziu
stránku. `walk_pa()` rozpoznáva veľké stránky podľa bitu PSE. Správnosť sa kontroluje
krížovo — `info` porovná lineárny výpočet a prechod tabuliek pre `linux_banner`
a `init_task`; v meranej snímke obe sedia (výpis v časti 7.2).

**Miesto 3 — rekonštrukcia objektov (`view.py`, `checks.py`).** Offsety polí sa berú z BTF
hosťa, nie z hlavičkových súborov: rozloženie štruktúr závisí od konfigurácie jadra
(`CONFIG_*`), nie iba od verzie, takže číslo opísané zo zdrojákov by pri inom `.config`
ticho ukazovalo na iné pole. Prechádzajú sa spájané zoznamy jadra:

- **procesy**: `init_task.tasks`, strop 8192 položiek, detekcia cyklu, kontrola
  rozumnosti PID;
- **moduly**: zoznam `modules`, strop 1024 položiek;
- **sokety**: tabuľka deskriptorov procesu → `file->f_op == socket_file_ops` →
  `struct socket` → `sock_common`. Protokol sa **neuhádne z čísla portu**, ale porovnaním
  ukazovateľa `skc_prot` so symbolmi `tcp_prot` / `udp_prot` / `raw_prot` a ich IPv6
  dvojičkami `tcpv6_prot` / `udpv6_prot` / `rawv6_prot`.

---

## 9. Konfiguračné rozhranie

Konfigurácia je jedna štruktúra `vmic_config_t`; načítava ju `config.c` z INI súboru
a `-o sekcia.kluc=hodnota` z príkazového riadku prebíja súbor.

| Sekcia | Kľúče (výber) |
|---|---|
| `[vm]` | `domain`, `backend`, `bpf_object`, `image_path` |
| `[schedule]` | `interval_s`, `jitter`, `overrun`, `max_cycles`, `duration_s`, `align` |
| `[capture]` | `pause`, `pause_max_ms`, `chunk_size`, `regions`, `skip_read_errors`, `max_read_errors` |
| `[output]` | `dir`, `writer`, `name_template`, `sparse`, `post_compress`, `hash`, `sidecar`, `delta_page_size`, `delta_full_every` |
| `[retention]` | `max_snapshots`, `max_bytes`, `max_age_s` |
| `[hooks]` | `load` (až 16×), `strict` |
| `[features]` | `enable`, `bin_bytes` (16 MiB), `entropy` — per-bin vektor, viď 6.1 |
| `[log]` | `level`, `file`, `json` |

Validácia je prísna a hlási zmysluplne — napríklad pri pokuse nastaviť
`output.delta_full_every=0`:

```
$ ./vmicollect/build/vmicollect run -o output.delta_full_every=0 ...
2026-09-18T16:31:13.882Z ERROR output.delta_full_every musi byt aspon 1
```

Úplný zoznam kľúčov vypíše `vmicollect config --keys`, efektívnu konfiguráciu
`vmicollect config`.

### 9.1 CLI zberača

```
$ ./vmicollect/build/vmicollect --help
vmicollect 1.0.0 - periodicky zber pamatovych snimok virtualnych strojov

POUZITIE
  vmicollect <prikaz> [-c subor.conf] [-o sekcia.kluc=hodnota]...

PRIKAZY
  run                periodicky zber (Ctrl-C korektne ukonci)
  once               jedna snimka a koniec
  probe              pripoj sa a vypis parametre VM (nic nezapisuje)
  restore            poskladaj plny obraz z delta retazca
                       --dir D --out F [--chain ID] [--until SEQ]
  verify [adresar]   over kontrolne sucty snimok podla .json
  config             vypis efektivnu konfiguraciu
  config --keys      vypis vsetky nastavitelne parametre
  backends           zoznam dostupnych backendov
  selftest [adresar] over celu cestu bez potreby VM
```

---

## 10. Ako sa architektúra overuje

Dva príkazy, obidva bez roota a bez bežiacej VM:

```
$ make -C vmicollect test
build/hole_test
chunks=2 read_errors=1 filled_zero=131072 bytes_read=1966080
OK: pamat za dierou sa zachovala, obraz je zhodny s referenciou
build/vmicollect selftest build/selftest
...
2026-09-18T16:42:32.442Z INFO  restore: hotovo -> build/selftest/restored.raw (16.00 MiB, 2057 zapisanych stranok)
2026-09-18T16:42:32.449Z INFO  selftest: OK - obnoveny obraz je bajt po bajte zhodny
2026-09-18T16:42:32.475Z INFO  selftest: OK - raw snimka ma spravny SHA-256
2026-09-18T16:42:32.476Z INFO  selftest: VSETKO PRESLO. Data su v build/selftest
```

```
$ python3 -m pytest -q
........................................................................ [ 81%]
................                                                         [100%]
88 passed in 1.61s
```

Čo tieto testy **netestujú**, je vymenované v `docs/LIMITACIE.md`, časti L5 a L6.
Rýchlosť čítania, ktorú vypisuje `selftest`, je rýchlosť čítania súboru z page cache
a nemá vzťah k čítaniu pamäte bežiacej VM (`HONESTY.md`, kapitola 3).

---

## 11. Kde sa `README.md` rozchádza s kódom

Predlohou tohto dokumentu bol `vmicollect/README.md`. Pri porovnaní so zdrojovým kódom sa
našli tieto rozdiely; podľa `HONESTY.md` P12 platí kód:

1. **Schéma v README kreslí `hooks.c` pod blokom BPF programu**, akoby hooky viseli na
   backende. V kóde ich volá `vmic_collector_cycle` na konci cyklu, až po zápise snímky
   a po sidecare, a pred retenciou. Schéma v časti 2 tohto dokumentu je opravená.
2. **README uvádza pri delta writeri podiel zmenených stránok a objem dát za hodinu** ako
   motiváciu (to isté je v hlavičke `src/writer_delta.c`). Sú to rádové odhady, nie
   merania na tomto stroji — sú vedené v `HONESTY.md`, kapitole 3, a do textu práce sa
   neprepisujú.
3. **Príklad JSON sidecaru v README** (doména `win10`, nenulový `read_errors`) je
   vymyslený. Reálny príklad je v časti 6 tohto dokumentu.
4. README vymenúva, čo netreba („žiadna LibVMI“), ale nespomína, že parser potrebuje
   **profil jadra hosťa** získaný z hosťa. Priznané je to v `docs/LIMITACIE.md`, časť L3,
   a v `profiles/debian12-6.1.0-42-cloud-amd64/README.md`.

Vecné časti README, ktoré sa s kódom zhodujú a boli sem prevzaté po overení: štyri vrstvy
a tabuľka súborov, tabuľka `[sekcia].kľúč`, zoznam príkazov CLI, poznámka o confidential
VM, poznámka „jeden adresár = jeden zberač“.

---

## 12. Provenienčná poznámka

Podľa `HONESTY.md` P9: autorstvo pôvodného kódu `vmicollect` **nie je známe** a takto sa
uvádza, kým sa nezistí. Do repozitára vstúpil ako celok (stav 2026-08-26) a jediný súbor
zmenený oproti prevzatej verzii je `bpf/vmic_kvm.bpf.c` — štyri opravy potrebné na to,
aby program prešiel verifikátorom. Balík `guestparse` vznikol rozdelením prototypu
`vmi_parse.py` (2026-09-18) do modulov; poznámka o pôvode je v hlavičke
`guestparse/__init__.py` a `guestparse/image.py`.
