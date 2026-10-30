# Architektúra a rozhrania

Dokument popisuje vrstvy, dátové toky, formáty a rozhrania tejto práce na úrovni
architektúry aj implementácie. Pokrýva tie časti zadania (`zadanie-zp_105826.pdf`,
Charakter práce), ktoré žiadajú „návrh systému (architektúra hypervisor modulu, VMI
komponenty, feature extraction pipeline, TCN integrácia)“ a v implementácii „API
rozhranie“.

Pravidlá, ktorými sa dokument riadi:

- Každý komponent má cestu do repozitára a počet riadkov zistený príkazom `wc -l`.
- Každé rozhranie má **reálny príklad vstupu a výstupu**. Výpisy sú doslovné prepisy
  behov z 2026-09-18 nad týmto repozitárom, ak pri výpise nie je uvedené inak. Kde dnešný
  kód dáva iný výstup, je to napísané pri výpise (overené 2026-10-29 nad commitom
  `709ee7f`). Jediná úprava výpisov je skrátenie dlhej cesty dočasného adresára na `$D`
  alebo pracovného adresára mimo repozitára na `$SC` a vynechanie riadkov alebo ich častí
  označené `...`; oboje je pri výpise napísané.
- Príklady sú z domény `hyptcn-guest`. Korpus a `safeguard` zbierajú doménu `hyptcn-lab`
  (časť 1.3), ktorej rozloženie pamäte je iné; čísla z príkladov pre ňu neplatia.
- Predlohou bol `vmicollect/README.md`, ale každé tvrdenie je overené proti zdrojovému
  kódu. Miesta, kde sa README a kód pri odvodení dokumentu rozchádzali, sú v časti 11.
- Odkazy do kódu sú na **súbor a meno funkcie alebo štruktúry**, nie na číslo riadku:
  repozitár sa počas písania menil a čísla riadkov by zastarali skôr než text.
- Označenia blokov (napríklad A2 až A8) sú tie isté ako v komentároch v kóde; legenda
  všetkých blokov je v [`STAV.sk.md`](STAV.sk.md), časť 3.
- Čo nie je overené behom, je označené `UNVERIFIED` (`HONESTY.md`, P5).

---

## 1. Celkový pohľad

Systém má tri časti. Zberač a ostatné časti spolu komunikujú **iba cez súbory na disku** —
natívny formát snímky `.vmicd`, JSON sidecar a marker `HOLD`. Žiadny socket ani zdieľaná
pamäť; kde jedna časť potrebuje zberač, spustí ho ako samostatný proces (`safeguard run`
spúšťa `vmicollect run`, detektor pri alarme `vmicollect hold`). V detektore bežia parser
aj príznaky v jednom procese Pythonu: `features` a `safeguard` volajú `guestparse` priamo.

```
 hostiteľ s KVM, root
 ┌──────────────────────────────────────────────────────────────────┐
 │ vmicollect (C + eBPF)                                            │
 │   číta fyzickú RAM bežiacej domény cez mapu memslotov modulu kvm │
 │   výstup: <id>.vmicd (dáta) + <id>.json (metadáta, per-bin blok) │
 └───────────────────────────┬──────────────────────────────────────┘
                             │ súbory
 ┌───────────────────────────▼──────────────────────────────────────┐
 │ guestparse (Python 3, bez závislostí mimo štandardnej knižnice)  │
 │   + profil jadra hosťa (kallsyms + BTF)                          │
 │   výstup: procesy / moduly / sokety / kontroly ako JSON          │
 └───────────────────────────┬──────────────────────────────────────┘
                             │ volania v tom istom procese
 ┌───────────────────────────▼──────────────────────────────────────┐
 │ features + safeguard (Python 3, numpy, PyTorch)                  │
 │   okná, normalizácia, TCN, prah a pravidlo k z n, integrita      │
 │   výstup: udalosti JSON; pri alarme vmicollect hold → HOLD       │
 └──────────────────────────────────────────────────────────────────┘
```

Rozdelenie nie je kozmetické: zberač beží pod rootom a musí stihnúť periódu, parser
privilégiá nepotrebuje a môže bežať aj dlho po zbere, nad uloženou snímkou. Aby zberač
stíhal periódu, nebeží v jeho slučke ani detektor: pracuje nad výstupným adresárom ako
samostatný proces (časť 4.3).

Výpisy z 2026-09-18 v tomto dokumente vznikli na vývojovom hostiteľovi (Fedora 43) s jadrom
7.1.13-100.fc43, behy z 2026-10-29 na tom istom stroji s jadrom 7.2.5-100.fc43; artefakty
vývojového hostiteľa v `data/results/` zaznamenávajú 7.2.5-100.fc43 od 2026-10-05 (prvý je
`probe_20261005T154929Z.json`). Fakty o hostiteľovi v časti 1.2 boli 2026-10-29 overené
znovu na 7.2.5-100.fc43. Piloty z 2026-10-13 bežali na vývojovom hostiteľovi; artefakty
zberu korpusu od 2026-10-20 (piloty 3 až 7, kampane `benign-v2` až `benign-v5`) pochádzajú
zo samostatného zberového PC (jadro `7.2.9+deb13-amd64` podľa ich hlavičiek). Obe
prostredia porovnáva [`STAV.sk.md`](STAV.sk.md), časť 4.

### 1.1 Komponenty zberača a parsera, cesty a počty riadkov

Zistené 2026-10-29 nad commitom `709ee7f` príkazom

```sh
wc -l vmicollect/include/vmic.h vmicollect/bpf/* vmicollect/src/* \
      vmicollect/hooks/*.c vmicollect/tests/*.c guestparse/*.py guestparse/tests/*.py
```

Počty sú snímkou stavu k uvedenému commitu; príkaz vyššie ich vypíše znovu. Ostatné časti
systému sú v časti 1.3.

| Komponent | Cesta | Riadkov | Čo robí |
|---|---|---:|---|
| verejné C API | `vmicollect/include/vmic.h` | 665 | všetky dátové typy a tabuľky operácií |
| ABI jadro ↔ zberač | `vmicollect/bpf/vmic_bpf_abi.h` | 217 | kontexty, chybové kódy, limity |
| BPF programy | `vmicollect/bpf/vmic_kvm.bpf.c` | 592 | `vmic_probe` (memsloty), `vmic_read` (stránky) |
| backend eBPF | `vmicollect/src/backend_ebpf.c` | 1214 | nájdenie domény, BTF, načítanie BPF, `read_pa` |
| backend súbor | `vmicollect/src/backend_file.c` | 132 | raw obraz na disku (vývoj, testy) |
| register backendov + čítacia slučka | `vmicollect/src/backend.c` | 298 | `vmic_capture()`, `vmic_capture_timed()`, delenie na bloky |
| zberný cyklus | `vmicollect/src/collector.c` | 588 | spojenie štyroch vrstiev do jedného cyklu, fronta zápisu a `output.mlock` pri štarte |
| plánovač | `vmicollect/src/sched.c` | 160 | absolútne termíny, jitter, politika pri preťažení, kontext cyklu |
| writer delta | `vmicollect/src/writer_delta.c` | 723 | formát `.vmicd`, reťazce, obnova |
| zápis mimo cyklu | `vmicollect/src/output.c`, `output.h` | 882, 99 | fronta snímok a vlákno `vmic-writer`: súbor, `fsync`, SHA-256, sidecar, hooky, retencia (zberač 1.1, časť 2) |
| per-bin príznaky | `vmicollect/src/perbin.c`, `perbin.h` | 353, 55 | per-bin vektor nad memslotmi, kontrola invariantu súčtov (časť 6.1) |
| writer raw | `vmicollect/src/writer_raw.c` | 352 | celý obraz, riedky zápis, gzip, SHA-256 |
| hooky | `vmicollect/src/hooks.c` | 241 | `dlopen()` pluginu, volanie po každej snímke, alarmy (`vmic_alarm_raise`) |
| sidecar | `vmicollect/src/meta.c` | 323 | JSON `vmicollect/1`, `alarm.json` a `alarms.jsonl` |
| retencia | `vmicollect/src/retention.c` | 432 | mazanie starých snímok po reťazcoch, marker `HOLD` (časť 2.5) |
| konfigurácia | `vmicollect/src/config.c` | 808 | INI parser riadený tabuľkou `FIELDS` |
| CLI zberača | `vmicollect/src/main.c` | 794 | `run`, `once`, `probe`, `restore`, `hold`, `verify`, `config`, `backends`, `selftest` |
| pomocné | `vmicollect/src/util.c`, `sha256.c`, `log.c`, `writer.c` | 442, 403, 363, 53 | čas, I/O, hashe, logovanie (vlákno `vmic-log`), register writerov |
| interné hlavičky | `vmicollect/src/internal.h`, `log.h`, `sha256.h`, `util.h` | 29, 39, 26, 74 | deklarácie zdieľané medzi `src/*.c` |
| vzorový hook | `vmicollect/hooks/example_hook.c` | 110 | plugin, ktorý po každej snímke pripíše riadok do CSV |
| vzorový detektor | `vmicollect/hooks/alarm_hook.c` | 129 | prah na počet zmenených stránok, `api->alarm()` (časť 4.2) |
| voliteľná reakcia | `vmicollect/hooks/react_hook.c` | 152 | po alarme jedna akcia cez libvirt (blok A7), predvolene nenačítaný |
| regresný test dier | `vmicollect/tests/hole_test.c` | 111 | kontrakt `read_pa()` s falošným backendom |
| regresné testy | `vmicollect/tests/perbin_test.c`, `retention_test.c`, `alarm_test.c` | 283, 237, 157 | per-bin vektor, marker `HOLD` v retencii, alarmy |
| čítanie snímok | `guestparse/image.py` | 503 | `.vmicd` bez rozbaľovania, overenie reťazca, `ChainCursor`, raw obraz |
| profil jadra | `guestparse/profile.py` | 260 | kallsyms + offsety polí z BTF, boot profilu (`boot.json`) |
| pohľad na hosťa | `guestparse/view.py` | 970 | preklad adries, procesy, moduly, sokety, preukotvenie profilu |
| kontroly integrity | `guestparse/checks.py` | 924 | (a) `sys_call_table`, (b) procesy krížovo, (c) moduly krížovo, (d) text jadra proti baseline |
| bin → proces | `guestparse/procmap.py` | 213 | ktorému procesu patria zmenené stránky binu (blok A4) |
| identita bootu | `guestparse/context.py` | 53 | boot UUID zaznamenané pri zbere (`session.json`, `run.json`) |
| porovnanie s pozemnou pravdou | `guestparse/validate.py` | 288 | `ps` / `lsmod` / `ss` vs. snímka |
| CLI parsera | `guestparse/cli.py` | 503 | podpríkazy `ps`, `lsmod`, `ss`, `info`, `checks`, `validate`, `textbaseline`, `procmap` |
| vstupné body balíka | `guestparse/__init__.py`, `__main__.py` | 30, 8 | verejné mená (časť 7.1), `python3 -m guestparse` |
| testy parsera | `guestparse/tests/*.py` | 2995 | 177 testov, pozri časť 10 |

Súčet zdrojového kódu zberača (hlavičky, C, BPF, hooky, testy): 11536 riadkov.
Balík `guestparse` bez testov: 3752 riadkov, s testami 6747 riadkov.

### 1.2 Prečo „hypervisor modul“

**Pôvod tohto riešenia — najprv to podstatné.** Prístup **navrhol autor práce**: periodický
zber cez eBPF a len pre KVM. Zberač `vmicollect` vrátane oboch programov BPF je vlastnou
prácou autora zo staršej vetvy projektu; do repozitára vstúpil ako celok, bez zmien
(`git log --diff-filter=A -- vmicollect/bpf/vmic_kvm.bpf.c` → `6b9053d`; `HONESTY.md`, P9;
časť 12 tohto dokumentu). Cesta cez eBPF v tomto stave nikdy nebola overená proti
bežiacemu jadru. V tejto práci sa program proti nemu **overil** — a nenačítal sa; štyri príčiny
sa našli a opravili (nezhoda BTF pri `bpf_task_from_vpid` a trikrát limit verifikátora, riešené
cez `bpf_loop()`) a až potom sa dalo merať. Odseky nižšie posudzujú, či tento prístup zodpovedá
zadaniu a kde má hranice.

**Kde beží ktorá časť.** Zadanie žiada „modul postavený na open-source hypervízore“
(`zadanie-zp_105826.pdf`, Anotácia); formu nepredpisuje. Na tomto hostiteľovi je KVM zavedený
ako jadrový modul (`lsmod | grep '^kvm'` vypíše `kvm` a `kvm_intel`); pri `CONFIG_KVM=y` by
nevypísal nič a kód s tým počíta (komentár pri `btf__parse_split`). Zberač je delený rovnako:
`pick_vm` a `resolve_offsets` (`backend_ebpf.c`) nájdu proces VMM a offsety z BTF, v jadre bežia
`vmic_probe` a `vmic_read` (`vmicollect/bpf/vmic_kvm.bpf.c`). To, že bežia v jadre, samo osebe
nedokazuje nič — v jadre beží každý program BPF. Nosné je, **čo** čítajú: `struct kvm`
z deskriptora `kvm-vm` a jej tabuľku memslotov, teda mapu GPA ↔ HVA.

**Prečo nestačí `process_vm_readv`.** Bajty by `process_vm_readv()` z adresného priestoru QEMU
prečítal, zvonka sa však nedá zistiť, **ktorá časť toho priestoru je ktorá fyzická adresa
hosťa**; bez mapy z memslotov by zberač hádal z `/proc/<pid>/maps` (`vmicollect/README.md`,
časť „Preco eBPF…“). Zásluhy poctivo: kopíruje sa cez `bpf_copy_from_user_task()`, teda
`access_process_vm()` — to isté, čo `process_vm_readv()`. V kopírovaní bajtov sú si obe cesty
rovnocenné; prínosom eBPF je výhradne tá mapa.

**Prečo nie modul `.ko`.** Dva z bežne uvádzaných dôvodov na tomto stroji neplatia a uvádzať
ich by bolo nepoctivé: podpis sa nevynucuje (`CONFIG_MODULE_SIG_FORCE is not set`,
`/sys/module/module/parameters/sig_enforce` = `N`) a jadro je už teraz označené ako zmenené
(`cat /proc/sys/kernel/tainted` → 12288, kvôli modulom `nvidia*`). Obstoja dva iné: `.ko` sa
viaže na konkrétne jadro (modul s iným `vermagic`, než vypíše `modinfo kvm | grep vermagic`,
sa nezavedie), kým program BPF berie offsety z BTF; a chyba v `.ko` zhodí hostiteľa aj so
všetkými virtuálnymi strojmi, kým program BPF musí prejsť verifikátorom jadra.

**Alternatívne cesty k mape memslotov.** Prvé tri riadky sú prevzaté z `vmicollect/README.md`
(časť „Preco eBPF…“), štvrtý je doplnený a posledný preformulovaný. Nie sú to merania.

| cesta | čo si pýta |
|---|---|
| LibVMI + KVM legacy | patchnuté QEMU |
| LibVMI + KVMi | jadro s KVMi a socket |
| `virsh dump` | libvirt, a vždy celý obraz naraz |
| samotný VMM (QMP, libvirt) | bežiaci a spolupracujúci management stack |
| eBPF (toto riešenie) | root na tom istom stroji a jadro s BTF |

Mapu neposkytuje **modul `kvm`**; QEMU ju pozná, lebo ju samo zapísalo cez
`KVM_SET_USER_MEMORY_REGION` (tvrdenie o rozhraní KVM, v tomto repozitári sa overiť nedá).
Cesta cez VMM je odmietnutá preto, že je to jeho pohľad na seba samého: potrebuje spolupracujúci
management stack a vypovedá o tom, čo si VMM myslí. Overené nebolo, v akej podobe je mapa cez
QMP vôbec dostupná — `info mtree -f` vypisuje rozsahy GPA a mená regiónov, nie adresy
v procese VMM.

**Čo BTF rieši a čo nie.** Z BTF sa čítajú **offsety**; mená typov a polí sú natvrdo v `KFIELDS`
v `backend_ebpf.c` — 27 položiek nad 12 typmi (`grep -c 'KF("' vmicollect/src/backend_ebpf.c`).
Rieši teda **presun** poľa, nie premenovanie ani zmenu spôsobu uloženia. Nejde o hypotetickú
hrozbu do budúcna: `KFIELDS` už dnes číta `kvm_memslots.id_hash` a `node_idx`, teda usporiadanie
zavedené prechodom KVM na hash tabuľku — na to, aby sa prechod prispôsobil, nestačili nové
offsety, musel sa napísať nový prechod. Rozpor nekončí tichým čítaním smetí: `resolve_offsets`
chýbajúce pole vypíše menom a vráti `VMIC_FATAL`.

**Čím to nie je.** Nie je to modul jadra ani patch hypervízora. Nezachytáva udalosti VM:
v zdrojovom kóde nie je iná programová sekcia než `SEC("syscall")` a v preloženom objekte nie je
ani jedna sekcia typu `kprobe`, `tracepoint` či `fentry` (`readelf -S vmicollect/build/vmic_kvm.bpf.o`;
objekt vznikne príkazom `make -C vmicollect bpf`), takže programy nie sú zavesené na nič
a spúšťa ich zberač (`run_prog`) v termíne plánovača.
A nie je to pamäťová forenzika v obvyklom zmysle — hoci hranica je tenšia, než sa zdá: Volatility
cez vrstvu adresného priestoru LibVMI vie čítať aj bežiaci virtuálny stroj zvonka. Rozdiel je
v tom, že zber je tu periodický a inkrementálny (`sched.c`, `writer_delta.c`) a výstupom je
časový rad, nie jedna analýza obrazu. Ústupok: rekonštrukcia objektov zo snímky (`guestparse`)
je tá istá disciplína ako pamäťová forenzika, len nad iným zdrojom.

**Čo si to pýta a čo to stojí.** Hypervízor ani jadro hostiteľa sa nemenia, prostredie však
požiadavky má: root (`CAP_BPF` a `CAP_PERFMON`; hláška v `load_bpf`), jadro s BPF a preložené
s `CONFIG_DEBUG_INFO_BTF` — bez neho `resolve_offsets` `/sys/kernel/btf/vmlinux` neotvorí, ohlási
chýbajúcu voľbu a vráti `VMIC_FATAL`. V hosťovi nebeží bezpečnostný agent; `qemu-guest-agent`
beží, ale na orchestráciu a pozemnú pravdu (`HONESTY.md`, P6), a parser potrebuje profil jadra
hosťa (`docs/LIMITACIE.md`, L3). Neinvazívnosť má výnimku: číta sa cez adresný priestor VMM,
takže pri non-anonymnom podložení (shmem, `memfd`, `hugetlbfs`) sa nedotknutá stránka jej
prečítaním na hostiteľovi reálne alokuje (L2). Čítacie rozhranie je pozorovacie, nie
riadiace: `vmic_backend_ebpf` má `.pause = NULL` a snímka je živá (L1). Jediná riadiaca
cesta v module je voliteľný plugin `react_hook.so` (blok A7, predvolene nenačítaný), ktorý
po alarme cez libvirt VM pozastaví, odpojí jej sieť alebo vytvorí snapshot (časť 4.2);
počas čítania VM nezastavuje a nad bežiacou VM je **UNVERIFIED**.

**FORMULÁCIA DO TEXTU PRÁCE.**

> Hypervízor KVM je na použitom hostiteľovi zavedený ako jadrový modul a nástroj použitý v tejto
> práci je delený rovnako: používateľská časť nájde proces virtualizačného monitora a deskriptor
> virtuálneho stroja, samotné čítanie robia dva programy eBPF v jadre hostiteľa. Podstatné nie je,
> že bežia v jadre — tam beží každý program eBPF —, ale že čítajú vnútorné dátové štruktúry práve
> modulu `kvm`, totiž tabuľku memslotov s mapovaním fyzických adries hosťa na virtuálne adresy
> procesu monitora. Táto mapa je dôvodom, prečo nestačí prečítať pamäť monitora volaním
> `process_vm_readv`: bajty by sa tým získať dali, zvonka sa však nedá zistiť, ktorá časť
> adresného priestoru monitora zodpovedá ktorej fyzickej adrese hosťa. V kopírovaní bajtov sú si
> obe cesty rovnocenné, pretože program eBPF používa ten istý mechanizmus prístupu do pamäte
> cudzieho procesu; prínosom je mapa prečítaná z jadra. Prístup cez eBPF navrhol autor práce
> a zberač je jeho vlastnou prácou; pôvodná cesta cez eBPF v ňom nikdy nebola overená proti
> bežiacemu jadru. Súčasťou práce je aj overenie zberača proti bežiacemu jadru, odstránenie
> štyroch príčin, pre ktoré sa program nenačítal, a posúdenie hraníc tohto prístupu. Proti vlastnému modulu jadra hovorí, že by sa viazal na
> konkrétnu verziu jadra a že jeho chyba by zhodila hostiteľa aj so všetkými virtuálnymi strojmi.
> Čím riešenie nie je: nie je to zavedený modul jadra ani patch hypervízora a nezachytáva udalosti
> virtuálneho stroja, pretože programy nie sú zavesené na žiadnu udalosť a spúšťa ich zberač
> v naplánovanom termíne. Čítanie pamäte je pozorovacie, nie riadiace: virtuálny stroj počas
> čítania nezastavuje, a preto je snímka pamäte živá. Nástroj obsahuje aj voliteľný zásuvný
> modul, ktorý má po vyhlásenom alarme stroj pozastaviť alebo odpojiť jeho sieť; predvolene nie
> je načítaný a nad bežiacim strojom nebol overený. Cenou je závislosť od vnútorného rozloženia
> štruktúr modulu `kvm`, požiadavka na roota a na jadro preložené s ladiacimi informáciami BTF
> a to, že pri non-anonymne podloženej pamäti hosťa čítanie nedotknutej stránky ju na
> hostiteľovi alokuje.

### 1.3 Ostatné časti systému a ich hranice

Počty riadkov sú zistené 2026-10-29 nad commitom `709ee7f` príkazom `wc -l` nad uvedenými
súbormi (bez testov; pri `lab/` nad `git ls-files lab`); `tcn/eval.py` 2026-10-30 po pridaní
vyhodnocovača.

| Komponent | Cesta | Riadkov | Čo robí |
|---|---|---:|---|
| príznaky snímky | `features/*.py` okrem `normalize.py`, `manifest.py` a `stream.py` | 2677 | vektor snímky z RAM a objektov hosťa (`snapshot.py`), per-bin blok zo sidecaru a okná (`windows.py`), politiky platnosti (`quality.py`), archív sedenia (`archive.py`), index korpusu (`dataset.py`), Python referencia per-bin vektora (`perbin.py`, `crosscheck.py`) |
| detektor | `safeguard/*.py` | 2001 | `Frame`, okno a normalizácia (`features.py`), modely, tréning, balík modelu, detektor (`runtime.py`), vlastný proces zberača (`supervisor.py`), CLI `python3 -m safeguard` |
| TCN | `tcn/model.py` | 143 | kauzálne dilatované bloky, na ktorých stavia `safeguard/model.py` |
| vyhodnotenie | `tcn/eval.py` | 533 | FAR za hodinu z alarmových udalostí a presnosť klasifikátora aktivít z prehratí `safeguard replay` (`python3 -m tcn.eval far`, od `591a061`); metriky staršej cesty (`vyhodnot`, `tabulka`, `uloz`) |
| staršia 22-stĺpcová cesta | `tcn/train.py`, `score.py`, `baselines.py`; `features/normalize.py`, `manifest.py`, `stream.py`; `scripts/detektor.py`, `soft_rt_check.py` | 578, 383, 181; 264, 335, 56; 154, 178 | tréning, skórovanie, metriky a baseline nad 22-stĺpcovým vektorom snímky, jeho normalizácia a okná, detektor nad touto cestou a kontrola časovania nad sidecarmi a výstupom `tcn.score`; diagnostická a historická, v repozitári ostáva do konca experimentov |
| zber korpusu | `scripts/collection.py`, `campaign.py`, `collection_archive.py`, `lab_capture.sh` | 944, 809, 501, 110 | plán, zber, audit a archív benígnych sedení, kampaň |
| laboratórium | `scripts/labctl.py`, `lab/` | 368, 558 | serverová VM `hyptcn-lab` (klon `hyptcn-guest`, voľba `--source`) a jej služby |
| etapa útokov | `scripts/poc/*.sh`, `scripts/poc/*.c`, `scripts/aktivita.sh`, `scripts/mb_fetch.py`, `harness/net_isolated.*` | 188, 93, 130, 173, 53 | pripravené stavebné bloky; táto etapa sa ešte neuskutočnila ([`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md), časť 7) |
| starý harness sedení | `scripts/session.sh`, `session_batch.sh`, `scripts/loads/*.sh`, `harness/session_manifest*.json` | 362, 64, 315, 154 | sedenia nad doménou `hyptcn-guest` (bloky B4, B5 a C); historický, zber korpusu ho nepoužíva |

**Hranice.** Zberač od ostatných častí nezávisí: vstupom je konfigurácia, výstupom súbory
vo výstupnom adresári. Zber korpusu (`scripts/collection.py` cez `scripts/lab_capture.sh`)
aj `safeguard run` (`collector_command` v `safeguard/supervisor.py`) ho spúšťajú ako
podproces s backendom `ebpf`, writerom `delta`, per-bin vektorom, vypnutou retenciou a bez
pluginov. Detektor číta tie isté súbory (`run_directory` v `safeguard/runtime.py`) a pri
alarme volá `vmicollect hold` (časť 2.5). Integrovanou detekčnou cestou je `safeguard`;
zo staršej cesty používa iba `tcn/model.py`. Tok od snímky po udalosť je v časti 8.
Podrobnosti detektora sú v [`SAFEGUARD.sk.md`](SAFEGUARD.sk.md), protokol zberu
v [`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md) a [`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md),
laboratórium v [`LAB.sk.md`](LAB.sk.md).
Falošné alarmy za hodinu a presnosť klasifikátora z prehratí `safeguard` počíta
`python3 -m tcn.eval far` ([`SAFEGUARD.sk.md`](SAFEGUARD.sk.md)); čas do detekcie a podiel
detegovaných incidentov zatiaľ nepočíta žiadny kód.

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
                            │ work(seq, deadline, ctx)
        ┌───────────────────▼────────────────────────────┐
        │ collector.c        JEDEN CYKLUS                │
        │ begin_cycle → refresh_vm → writer.begin →      │
        │ [pause] → vmic_capture → [resume] →            │
        │ writer.finish, potom                           │
        │   delta: publish → vlákno vmic-writer          │
        │          (output.c): súbor, meta, hooks,       │
        │          retention                             │
        │   raw:   meta → hooks → retention              │
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

Plánovač podáva práci kontext cyklu (`vmic_sched_ctx_t`: meškanie začiatku cyklu oproti
termínu a zmeškané sloty pred ním); zberač ho zapisuje do sidecaru každej snímky ako blok
`sched` (časť 6).

**Poradie operácií v cykle** je v `collector.c` (funkcia `vmic_collector_cycle`)
navrhnuté tak, aby bol prípadný čas zastavenia VM čo najkratší. Overené proti kódu:

| Poradie | Volanie | Vnútri pauzy? |
|---:|---|---|
| 1 | `ops->begin_cycle()` — obnova mapy memslotov | nie |
| 2 | `refresh_vm()` — prepočet zbieraných oblastí | nie |
| 3 | `writer.ops->begin()` — `delta`: deskriptor snímky z fronty; `raw`: vytvorenie súboru | nie |
| 4 | `vmic_backend_pause()` | hranica pauzy |
| 5 | `vmic_capture_timed()` — čítanie pamäte a kŕmenie writera (`delta`: kópia zmenených stránok do fronty) | **áno** |
| 6 | `vmic_backend_resume()` | hranica pauzy |
| 7 | `writer.ops->finish()` — `delta`: hlavička a polia snímky; `raw`: gzip, `fsync`, `rename` | nie |
| 8 | `writer.ops->publish()` — `delta`: odovzdanie snímky vláknu `vmic-writer` | nie |
| 9 | `vmic_meta_write()` — JSON sidecar (`raw`; pri `delta` ho vlákno vykreslí cez `vmic_meta_render` a premenuje po dátach) | nie |
| 10 | `vmic_hooks_fire()` — používateľské pluginy (`raw`; pri `delta` vo vlákne) | nie |
| 11 | `vmic_retention_apply()` (`raw`; pri `delta` vo vlákne) | nie |

Pri writeri `delta` (zberač verzie 1.1, `vmicollect/src/output.c`) cyklus na disk
nesiaha: súbor, `fsync`, SHA-256, sidecar, hooky aj retenciu robí vlákno `vmic-writer`
v poradí snímok a riadky logu zapisuje vlákno `vmic-log`. Snímka sa zverejní celá,
alebo vôbec (dáta a sidecar pod bodkovými dočasnými menami, potom dve premenovania
s `RENAME_NOREPLACE`, najprv dáta). Plánovač totiž započíta do slotu všetko, čo sa
v cykle stane; kampaň `benign-v4-20261022` stratila slot, keď zápis súboru v cykle
čakal na SSD.

Zmenené stránky cyklus kopíruje do fronty v pamäti (pool z kusov po 1 MiB, vyhradený pri
štarte). Jej veľkosť určuje `output.queue_mib` (0 = najväčšia možná plná snímka zbieraných
oblastí + 512 MiB), `output.mlock` uzamkne pamäť procesu (`mlockall`) a `output.drain_s`
obmedzí dobehnutie fronty po poslednom cykle (časť 9). Keď pamäť alebo deskriptory fronty
dôjdu, cyklus čaká a čas ide do `capture.queue_wait_ms`; ticho sa nič nezahodí. Zlyhaný
zápis snímky vo vlákne preruší reťazec: jeho ďalšie delty sa nezverejnia a ďalšia snímka je
plná. Každá nezverejnená snímka sa započíta ako chyba a `run` skončí kódom 4 (časť 9.1).
Pri writeri `raw` zapisuje súbor aj sidecar naďalej cyklus (kroky 7 a 9).

Kroky 4 a 6 sa vykonajú len vtedy, keď backend pauzu vie. Pri backende `ebpf` je
`ops->pause == NULL`, takže sa pauza nezapne a nemeria vôbec (výpis z 2026-10-29):

```
$ grep -n "\.pause *=" vmicollect/src/backend_file.c vmicollect/src/backend_ebpf.c
vmicollect/src/backend_file.c:119:    .pause         = f_pause,
vmicollect/src/backend_ebpf.c:1167:    .pause         = NULL,
vmicollect/src/backend_ebpf.c:1201:    .pause         = NULL,
```

(Druhý výskyt je náhradná tabuľka pre build bez podpory eBPF.) Dôsledky sú
v `docs/LIMITACIE.md`, časť L1.

### 2.1 Vrstva 1: backend

Backend odpovedá na otázku „odkiaľ berieme bajty“. Kontrakt je `vmic_backend_ops_t`.
Backend číta fyzické adresy hosťa cez memsloty a obsahu nerozumie; posun jadra hosťa
(KASLR) ho preto neovplyvňuje — kotvu a preukotvenie profilu rieši až `guestparse`
(časť 8.1).

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
`needs_random_access = true`, lebo s hromadným výpisom pracovať nevie. Voliteľné `publish`
(zberač 1.1) odovzdá hotovú snímku na zápis mimo cyklu (`output.c`); writer `raw` ho nemá,
súbor zapíše už vo `finish` a sidecar potom zapíše zberač.

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

Po každej hotovej snímke sa zavolajú načítané pluginy. Plugin môže vyhlásiť alarm; zberač
ho zapíše a reťazec, ku ktorému patrí, označí markerom `HOLD` (časť 2.5). Detaily v časti 4.

### 2.5 Retencia a marker `HOLD`

Periodický zber zaplní disk, preto `vmic_retention_apply()` (`retention.c`) po každom cykle
maže staré snímky podľa troch nezávislých limitov `[retention]`: `max_snapshots`,
`max_bytes`, `max_age_s` (0 = vypnuté; predvolene sú vypnuté všetky tri). Maže **po celých
reťazcoch**, najstaršie prvé, nie po jednotlivých súboroch: plná snímka bez svojich delt by
znemožnila obnovu zvyšku reťazca. Pri raw zbere je každý súbor sám sebe reťazcom, takže ten
istý kód funguje pre oboje. Nikdy nezmaže reťazec, do ktorého sa práve zapisuje (podľa
`chain_id`), ani reťazec s najnovším časom (poistka pri raw writeri bez `chain_id`).
Súbory začínajúce bodkou (dočasné súbory zapisovača) preskakuje. Pri writeri `delta` ju
volá vlákno `vmic-writer` po zverejnení snímky (časť 2).

Tretiu ochranu dáva súbor `HOLD` vo výstupnom adresári (`VMIC_HOLD_MARKER`, blok A5, commit
`580fc58`): reťazce v ňom uvedené retencia nezmaže, ani keď prekročia limity. Formát: jeden
záznam na riadok, prázdne riadky a riadky začínajúce `#` sa preskočia; záznam je číslo
(`chain_id` pri delta zbere) alebo meno súboru snímky, a vtedy sa drží celý reťazec, v ktorom
ten súbor je. Záznam dopíše príkaz `vmicollect hold <adresár> <chain_id|súbor>...` (kód 0,
pri chybných argumentoch 2, pri chybe zápisu 1) alebo `vmic_hold_mark()` pri alarme
(časť 4.2). Marker sa číta z disku pri každom upratovaní, takže prežije aj reštart zberača.
Chýbajúci marker znamená žiadne záznamy; keď sa existujúci prečítať nedá, retencia v tom
cykle nezmaže nič. Overuje to `retention_test` (časť 10).

`vmic_retention_apply()` dostane iba konfiguráciu a `chain_id` chráneného reťazca, nie
identitu domény: dva zberače v jednom adresári by si navzájom mazali snímky
(`docs/LIMITACIE.md`, L11). Zber korpusu aj `safeguard run` spúšťajú zberač s vypnutou
retenciou (časť 1.3); zberač tam nemaže nič a `HOLD` zaznamenáva, ktoré reťazce patria ku
kontextu alarmu.

---

## 3. C API: `vmicollect/include/vmic.h`

Hlavička je jediné verejné rozhranie zberača (665 riadkov, časť 1.1):

| Sekcia | Obsah |
|---|---|
| úrovne logovania, `vmic_rc_t` | `VMIC_OK` / `VMIC_ERR` / `VMIC_FATAL` / `VMIC_STOP` |
| `vmic_config_t` | celá konfigurácia v jednej štruktúre |
| `vmic_vminfo_t` | parametre cieľovej VM vrátane zoznamu skutočne namapovaných oblastí |
| `vmic_stats_t` | surové počítadlá jedného čítania |
| `vmic_bin_t`, `vmic_features_t` | per-bin príznakový vektor (časť 6.1) |
| `vmic_snapshot_t` | záznam o jednej snímke; dostane ho writer, sidecar aj každý hook |
| `vmic_backend_ops_t`, `vmic_capture()`, `vmic_capture_timed()` | vrstva backendu |
| `vmic_writer_ops_t` | vrstva writera; `publish` odovzdá snímku vláknu `vmic-writer` (časť 2.2) |
| `vmic_sched_run()`, `vmic_sched_ctx_t` | plánovač a kontext cyklu, ktorý podáva práci `work(seq, deadline, ctx, user)` |
| `VMIC_HOOK_ABI`, `vmic_hook_api_t`, `vmic_hooks_*` | hooky (časť 4) |
| `vmic_alarm_t`, `VMIC_ALARM_TOPBINS`, `vmic_alarm_raise`, `vmic_alarm_write` | alarmy (časť 4.2) |
| `vmic_collector_t`, `vmic_collector_flush` | zberač; `flush` počká, kým vlákno `vmic-writer` zapíše snímky z fronty, a vráti počet nezverejnených |
| `VMIC_HOLD_MARKER`, `vmic_hold_mark`, `vmic_retention_apply` | marker `HOLD` a retencia (časť 2.5) |
| `vmic_config_*`, `vmic_meta_write`, `vmic_meta_render`, `vmic_delta_restore` | ostatné; `vmic_meta_render` vykreslí sidecar do pamäte pre vlákno `vmic-writer` |

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
make -C vmicollect hooks    # -> build/example_hook.so, alarm_hook.so, react_hook.so

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

Ten istý príklad 2026-10-29 (commit `709ee7f`, zberač 1.1) dal rovnaké veľkosti `.vmicd`,
rovnaké počty stránok v logu a v CSV rovnaké stĺpce aj `bytes_on_disk`; líšia sa časy. Log
má navyše riadok o veľkosti fronty zápisu (`zapis snimok mimo cyklu: fronta …`) a dva
súhrnné riadky `zapisovac: …` pred riadkom `koniec`. Riadok cyklu pri writeri `delta`
uvádza veľkosť dát snímky (`64.19 KiB`, `64 B`), nie alokáciu na disku, lebo tú zistí až
vlákno `vmic-writer`. Sidecary majú 2089 a 2085 B, lebo pribudli blok `sched`, nové polia
v `capture` a `output` (časť 6) a blok `features` (časť 6.1); ich veľkosť závisí aj od dĺžky
cesty `$D` v poli `path`.

Prvá snímka je plná (16 nenulových stránok z 2048, súbor 65 728 B = 64 + 16 × 4104).
Ďalšie dve sú delty s nula zmenenými stránkami: súbor má presne 64 bajtov, teda iba
hlavičku. `bytes_on_disk` je pri nich 4096, lebo to je najmenšia alokácia na súborovom
systéme (rozdiel vysvetľuje časť 5.3).

---

## 4. Hook ABI

### 4.1 Čo hook dostane

Plugin je zdieľaná knižnica načítaná cez `dlopen(RTLD_NOW | RTLD_LOCAL)`. Zmluva vo
`vmic.h` má tri povinné symboly a štvrtý voliteľný:

```c
int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **state);
int  vmic_hook_snapshot(void *state, const vmic_snapshot_t *snap);
void vmic_hook_fini(void *state);
int  vmic_hook_alarm(void *state, const vmic_alarm_t *alarm);   /* voliteľný */
```

`vmic_hooks_load` v `hooks.c` je voči zmluve mäkší: plugin odmietne, iba keď nemá ani
`vmic_hook_snapshot`, ani `vmic_hook_alarm`, a `vmic_hook_init` aj `vmic_hook_fini` zavolá,
len ak existujú. Plugin bez `vmic_hook_snapshot` iba prijíma alarmy; tak je napísaný
`react_hook.c`.

Pri inicializácii dostane `vmic_hook_api_t`. **Štruktúra má štyri polia** (`struct
vmic_hook_api` vo `vmic.h`, komentáre doplnené):

```c
struct vmic_hook_api {
    unsigned abi;                  /* VMIC_HOOK_ABI, dnes 2 */
    const vmic_config_t *cfg;      /* konfigurácia, iba na čítanie */
    void (*log)(int level, const char *fmt, ...);
    int  (*alarm)(const struct vmic_hook_api *api, const vmic_alarm_t *a);
};
```

`VMIC_HOOK_ABI` je 2 od commitu `b431013` (2026-10-05, blok A6), ktorý pridal pole `alarm`;
predtým bol 1 a štruktúra mala tri polia. Zberač 1.1 ABI nezmenil: nové polia pridal na
koniec `vmic_config_t` a `vmic_snapshot_t` a miesto zrušeného `output.hash_async` drží pole
`hash_async_removed`, aby sa polia, ktoré plugin číta cez `api->cfg`, neposunuli.

Pri každej snímke dostane `const vmic_snapshot_t *`: poradové číslo, id reťazca a príznak
plnej snímky `is_full`, cestu k hotovému súboru na disku, cestu k sidecaru, čas, časy
`pause_ms` / `capture_ms` / `write_ms` / `total_ms`, `bytes_logical`, `bytes_on_disk`,
`pages_total`, `pages_changed`, skutočný príznak `paused`, zbierané oblasti, SHA-256
s príznakmi `hash_covers_file` a `hash_deferred`, surové počítadlá `stats`, per-bin vektor
`features` (časť 4.2), kontext plánovača `sched_lateness_s` / `sched_skipped_before`,
ukazovatele na `vmic_vminfo_t` a `vmic_config_t` a od verzie 1.1 aj príznak `async_write`,
časy a stav fronty zápisu (`begin_ms`, `backend_read_ms`, `queue_wait_ms`, `queue_jobs`,
`queue_bytes`, `queue_pool_bytes`, `sha_ms`, `data_closed_ms`) a `getrusage` vzorkovača
(časť 6).

### 4.2 Čo hook NEDOSTANE a čo môže vrátiť

Toto je vlastnosť rozhrania, nie prehliadnutie, a treba ju priznať, lebo od nej závisí
návrh skórovania (časť 4.3):

- **Nedostane `read_pa` ani inú funkciu na čítanie pamäte hosťa.** V `vmic_hook_api_t`
  nie je ukazovateľ na backend ani na zberač; služby sú dve, `log` a `alarm`.
- **Nedostane obsah stránok.** Ani ukazovateľ do buffra, ani mapované okno. Dostane iba
  `snap->path`, teda cestu k súboru, ktorý si musí otvoriť sám.
- **Príznakový vektor dostane, pamäť nie.** Per-bin vektor aktuálnej snímky je
  v `snap->features` (časť 6.1); `NULL` znamená, že sa nepočítal (vypnutý, iný writer než
  delta, alebo neprešiel kontrolou invariantu). Pri writeri `delta` dostane hook kópiu
  snímky vo vlákne `vmic-writer` a ukazovatele (aj `features`) platia iba počas volania.
- **Nedostane možnosť riadiť zber.** Návratová hodnota `vmic_hook_snapshot` má dva
  významy: 0 = v poriadku, nenulová = chyba. Pri `[hooks].strict = true` zberač skončí
  (pri writeri `delta` pred ďalším cyklom, `run` vráti 3), inak sa plugin vypne do konca
  behu a zber pokračuje (`vmic_hooks_fire` v `hooks.c`).

**Čo môže vrátiť: alarm.** Plugin zavolá `api->alarm(api, &alarm)`; `vmic_alarm_t` nesie
čas, `seq`, `chain_id`, zdroj, skóre, najviac `VMIC_ALARM_TOPBINS` (8) indexov binov
a krátky text o stave invariantov. `vmic_alarm_raise` v `hooks.c` potom:

1. ak má alarm `chain_id`, dopíše ho do markera `HOLD` (`vmic_hold_mark`), takže retencia
   reťazec nezmaže (časť 2.5);
2. prepíše `alarm.json` (posledný alarm) a pridá riadok do `alarms.jsonl` (história), oboje
   so schémou `hyptcn3/alarm/1` (`vmic_alarm_write` v `meta.c`);
3. doručí alarm každému pluginu, ktorý exportuje `vmic_hook_alarm`.

Zlyhaný zápis do `HOLD` alebo do alarmových súborov sa iba zaloguje. Alarm zber nezruší;
výnimkou je striktný režim, v ktorom zlyhanie prijímajúceho pluginu vráti `VMIC_FATAL`
a volajúci plugin ho má vrátiť zo `vmic_hook_snapshot`, čím zber skončí. Prijímajúce
pluginy sa volajú synchrónne v tom istom vlákne, takže `api->alarm()` sa vráti až po nich.
Overuje to `alarm_test` (časť 10).

Reálny príklad z 2026-10-29: `alarm_test` podá detektoru `alarm_hook.so` s prahom 0 snímku
so `seq` 3, `chain_id` 777 a 5 zmenenými stránkami, bez per-bin vektora. V pracovnom
adresári testu potom je `HOLD` s jediným riadkom `777` a `alarm.json` s týmto obsahom
(rovnaký riadok je v `alarms.jsonl`):

```json
{"schema": "hyptcn3/alarm/1", "timestamp": "2026-10-29T20:15:02.852Z", "timestamp_unix_ms": 1793304902852, "seq": 3, "chain_id": 777, "zdroj": "example:pages_changed", "score": 5, "top_bins": [], "invariants": "n/a (prikladovy detektor)"}
```

Vzorový detektor `hooks/alarm_hook.c` nie je detekcia anomálie: vyhlási alarm, keď
`pages_changed` prekročí prah z argumentu, a do `top_bins` vyberie biny s najviac
zmenenými stránkami zo `snap->features`. Voliteľný `hooks/react_hook.c` (blok A7) pri
každom alarme spustí cez `system()` jednu akciu cez libvirt (`virsh suspend`,
`domif-setlink … down` alebo `snapshot-create-as`) a jej trvanie zapíše do
`alarm_reakcia.jsonl` vo výstupnom adresári. Predvolene sa nenačíta; `alarm_test` ho
spúšťa v režime `dry` bez volania `virsh`, takže reakcia nad bežiacou VM je **UNVERIFIED**.

**Voči pamäti hosťa je rozhranie teda notifikačné**: hook sa dozvie, že snímka existuje,
kde leží a aký má per-bin vektor, a obsah si musí prečítať zo súboru. **Voči modulu je
signalizačné**: alarm, `HOLD` a cez voliteľný plugin reakcia.

Tri ďalšie vlastnosti, ktoré z toho vyplývajú (hlavička `hooks.c`, hlavička
`example_hook.c`):

1. Pri writeri `delta` (zberač verzie 1.1) beží hook **vo vlákne `vmic-writer`**, až po
   zverejnení snímky, nad jej kópiou (ukazovatele platia iba počas volania). Dlhý hook
   cyklus nezdrží, ale oneskorí zverejnenie ďalších snímok (fronta je FIFO) a až po
   vyčerpaní pamäte fronty aj cyklus. Pri writeri `raw` beží **synchrónne v hlavnej
   slučke** a hook dlhší ako perióda spôsobí zmeškané sloty (do verzie 1.0 aj pri `delta`).
   Alarm sa spracuje v tom istom vlákne ako hook, ktorý ho vyhlásil.
2. Hook beží **až po dokončení zápisu snímky a sidecaru** (a keď backend pauzuje, až po
   odpauzovaní VM). Nespomaľuje teda hosťa, iba zberač. Vlákno `vmic-writer` má zablokované
   signály SIGINT/SIGTERM/SIGHUP; dieťa spustené z hooku ich zdedí zablokované. Hlavička
   `hooks.c` preto radí spúšťať deti s prázdnou maskou (`posix_spawnattr_setsigmask`);
   `react_hook.c` volá `system()`.
3. Zberač `abi` sám nekontroluje; kontrola patrí do `vmic_hook_init` pluginu. Keď sa zberač
   a plugin preložili proti rôznym verziám `vmic.h`, plugin má vrátiť nenulovú hodnotu
   (`example_hook.c` to robí).

### 4.3 Dôsledok pre skórovanie

Skórovací hook, ktorý má vracať výstup modelu späť do modulu, nemôže čítať pamäť cez
rozhranie hooku. Môže si otvoriť `snap->path` sám (a zaplatiť čítanie z disku) alebo
pracovať iba s per-bin vektorom a sidecarom; výsledok vráti do modulu cez `api->alarm()`.

Detektor tejto práce (`safeguard`) preto nie je plugin, ale samostatný proces nad výstupným
adresárom zberača (`run_directory` v `safeguard/runtime.py`). Dôvody, ktoré sa dajú doložiť
kódom: pomalý hook oneskorí zverejnenie ďalších snímok a po vyčerpaní fronty aj cyklus
(bod 1 vyššie) a hlavička `example_hook.c` radí náročné spracovanie dať do fronty alebo
iného vlákna; rekonštrukcia objektov hosťa (`guestparse`) aj tak číta súbor `.vmicd`;
detektor je v Pythone s PyTorch, zberač v C.

Snímku spracuje, až keď je jej sidecar úplný JSON so schémou `vmicollect/1` a vedľa neho
leží `.vmicd`. Pri writeri `delta` (zberač 1.1) sa sidecar zverejní premenovaním až po
dátach, takže neúplný sidecar sa v adresári neobjaví; writer `raw` zapisuje sidecar priamo
do cieľového súboru (`vmic_meta_write`). Preto `safeguard watch` a `run` neúplný sidecar
čítajú znova až 15 s (`_INCOMPLETE_GRACE`) a nasledujúca snímka ho medzitým nepredbehne. Pri
alarme detektor volá `vmicollect hold <raw> <chain_id>...` ako podproces (`Detector._hold`).
`safeguard run` spúšťa zberač bez pluginov (časť 1.3), takže `api->alarm()`, `alarm.json`
ani `react_hook.so` v tejto ceste nevystupujú. Príkazy a stavy detektora opisuje
[`SAFEGUARD.sk.md`](SAFEGUARD.sk.md).

---

## 5. Formát `.vmicd`

Formát zapisuje `vmicollect/src/writer_delta.c` (od verzie 1.1 hlavičku a záznamy skladá
v pamäti a na disk ich zapíše vlákno `vmic-writer` v `output.c`), číta ho tá istá jednotka
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

Skripty `hdr.py`, `cross_real.py` a `cross.py` z výpisov nižšie boli jednorazové a v
repozitári nie sú. Snímky `.vmicd` a adresár `data/raw/` sa do gitu nedávajú (`.gitignore`);
zo snímok týchto behov je v gite iba sidecar
`data/sessions/20260918T154914Z_validate/snap/hyptcn-guest_000000_20260918T154916673Z.json`.
Opakovateľne overujú tú istú sémantiku `guestparse/tests/test_chain.py`, `test_image.py`,
`test_full_reset.py` a selftest v `make -C vmicollect test` (časť 10).

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

**(c) Výber reťazca a jeho overenie.** Bez obmedzenia na `seq` obe strany berú reťazec
s najvyšším `chain_id` a prehrávajú ho v poradí `seq`; neskorší záznam prepisuje starší.
Parser pri viacerých reťazcoch v adresári vypíše upozornenie na stderr. Každá plná snímka
začína nový reťazec (predvolene `output.delta_full_every = 20`), takže dlhší beh ich nechá
v adresári viac. S obmedzením na `seq` sa strany rozchádzajú: `guestparse --chain-until SEQ`
(`chain_headers` v `image.py`, od commitu `c221c6a`) zloží časovú os zo všetkých reťazcov
adresára až po dané `seq`, pričom zmena `chain_id` je prípustná iba na plnej snímke a plná
snímka predchádzajúci obsah zahodí (`guestparse/tests/test_full_reset.py`);
`vmicollect restore --until SEQ` bez `--chain` ostáva v najnovšom reťazci
(`vmic_delta_restore`). Pri viacerých reťazcoch treba v C zadať `--chain`. Nápoveda voľby
`--chain-until` v `guestparse/cli.py` uvádza „rovnaky vyznam ako 'vmicollect restore
--until'“; pri viacerých reťazcoch to neplatí (platí kód, `HONESTY.md`, P12). Miešanie delt
z dvoch reťazcov bez plnej snímky medzi nimi by dalo pamäť, ktorá v hosťovi nikdy naraz
neexistovala, preto to nerobí ani jedna strana. Parser navyše reťazec pri otvorení
**overí** a nekompletný odmietne výnimkou `ChainError` — s rovnakým odôvodnením, aké má
`vmic_delta_restore`.

### 5.3 Dve veľkosti, ktoré si netreba zamieňať

- `bytes_logical` (a pole „logická veľkosť pamäte“ v hlavičke) je koniec poslednej
  zbieranej oblasti — pre doménu `hyptcn-guest` je to 4 294 967 296 B, hoci RAM má
  2 164 396 032 B. Rozdiel sú diery vo fyzickom priestore pod 4 GiB: 10 memslotov sa
  zlúči do 5 oblastí (pole `features.regions` v sidecari
  `data/sessions/20260919T004123Z_validate/snap/hyptcn-guest_000000_20260919T004126406Z.json`)
  a medzi nimi sú štyri diery — 128 KiB nad 640 KiB, 1968 MiB nad 2 GiB, 46 MiB
  a 17,75 MiB pod 4 GiB, spolu 2 130 571 264 B (vlastný prepočet z týchto oblastí).
- `bytes_on_disk` v sidecari **nie je veľkosť súboru**, ale skutočná alokácia
  `st_blocks × 512` (`vmic_file_disk_usage` v `util.c`; vo verzii 1.1 pri writeri `delta`
  `fstat` vo vlákne `vmic-writer` pred `close`). Pri delta snímke z časti 5.2 má
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

Príklad je zo zberača 1.0.0 (2026-09-18). Neskôr pribudli blok
`"sched": {"lateness_s": …, "skipped_before": …}` medzi `stats` a `output` (commit
`170f385`, blok A8), polia `output.fsync` (`5468e30`) a `output.hash_deferred` (`bbf624d`),
pri delta writeri so zapnutými príznakmi blok `features` na konci (časť 6.1) a polia
verzie 1.1 v tabuľke nižšie. Schéma ostáva `vmicollect/1`.

Poznámky k poliam, overené proti `meta.c`:

| Pole | Význam |
|---|---|
| `capture.regions` | obsah `[capture].regions` z konfigurácie; prázdne pole znamená „nezadané“, nie „nič sa nezbieralo“ — skutočne zbierané oblasti vypíše zberač do logu |
| `capture.paused` | **skutočnosť, nie želanie konfigurácie**. Backend bez `pause()` VM nezastaví, aj keď to config žiada |
| `stats.bytes_read` | koľko bajtov sa naozaj podarilo prečítať; rozdiel oproti `bytes_requested` je strata |
| `stats.filled_zero` | bajty nahradené nulami (diery vo fyzickom priestore) |
| `stats.read_mib_s` | `bytes_read / read_seconds` |
| `sched.lateness_s` | meškanie začiatku cyklu oproti termínu plánovača v sekundách |
| `sched.skipped_before` | zmeškané sloty pred týmto cyklom |
| `output.fsync` | hodnota `[output].fsync`: či sa snímka pred zverejnením zapísala na disk cez `fsync` |
| `output.pages_*` | zapisuje sa iba pri writeri s delta počítadlami |
| `output.sha256_covers_file` | `true` = kontrolný súčet pokrýva presne obsah súboru; `false` = iba zozbierané oblasti, takže sa nedá porovnať s hashom súboru na disku |

Sidecar delta snímky má tie isté polia s inými hodnotami; napríklad druhá snímka
skoršieho behu `20260918T154742Z_run` (lokálny súbor
`data/raw/20260918T154742Z_run/hyptcn-guest_000001_20260918T154748651Z.json`) má
`"full": false`, `"pages_changed": 324`, `"changed_ratio": 0.000613`,
`"capture_ms": 557.064` a `"write_ms": 7.741`.

**Zberač verzie 1.1** (`"version": "1.1.0"`, `output.async: true`; oprava po kampani
`benign-v4-20261022`) píše súbory vo vlákne `vmic-writer` mimo cyklu, takže niektoré
polia majú nový význam a pribudli ďalšie (schéma zostáva `vmicollect/1`, nové kľúče
stoja pred blokom `features`, `path` a prvý `sha256` sú stále v prvých 8 KiB):

| Pole | Význam vo verzii 1.1 |
|---|---|
| `capture.capture_ms` | čítanie pamäte + porovnanie stránok + príznaky + kópia zmenených stránok do fronty + prípadné čakanie na jej pamäť; do 1.0 aj zápis každej zmenenej stránky do súboru |
| `capture.backend_read_ms` | iba volania `read_pa` backendu (nový kľúč; „čítanie“ v starších záznamoch je `capture_ms`) |
| `capture.begin_ms`, `capture.queue_wait_ms` | začiatok cyklu po `begin` writera; čakanie na pamäť alebo deskriptor fronty (audit ho zamietne vždy) |
| `capture.rusage` | `getrusage(RUSAGE_THREAD)` vzorkovacieho vlákna počas cyklu: `majflt`, `minflt`, `nvcsw`, `nivcsw`, `cpu_ms` |
| `capture.write_ms` | vlákno `vmic-writer`: vytvorenie, zápis, `fsync` a `close` súboru (bez SHA-256) |
| `capture.total_ms` | cyklus vzorkovača od začiatku po hotovú snímku (odovzdanie do fronty a riadok logu nasledujú, plánovač ich započíta do slotu) |
| `output.async` | `true` = súbory snímky zapísalo vlákno `vmic-writer` (writer `delta`); pri writeri `raw` `false` a polia fronty v sidecari nie sú |
| `output.bytes_on_disk` | ako predtým `st_blocks × 512` (zapisovač volá `fstat` pred `close`) |
| `output.hash_deferred` | `true` pri každej snímke writera `delta` (pri `raw` `false`): SHA-256 sa počíta po cykle vo vlákne a sidecar vznikne až s ním |
| `output.mlock`, `output.queue_pool_bytes` | uzamknutie pamäte zberača a veľkosť poolu fronty |
| `output.queue_jobs`, `output.queue_bytes` | snímky a dáta vo fronte pred touto snímkou (backlog zapisovača) |
| `output.sha_ms`, `output.data_closed_ms` | SHA-256 vo vlákne; od začiatku cyklu po zapísané a zatvorené dáta (sidecar a obe premenovania nasledujú, je to dolná hranica zverejnenia) |

Hodnoty `capture_ms` a `total_ms` z verzií 1.0 a 1.1 preto nie sú porovnateľné. Pri
writeri `raw` zapisuje súbor aj vo verzii 1.1 cyklus a `capture_ms` obsahuje aj zápis
blokov (`pwrite()` vo `feed()`, `writer_raw.c`).

Okrem snímok a sidecarov môžu vo výstupnom adresári vzniknúť `HOLD` (chránené reťazce,
časť 2.5), `alarm.json` a `alarms.jsonl` (alarmy, časť 4.2) a pri `react_hook.so`
`alarm_reakcia.jsonl`. Dočasné súbory zapisovača (`.<id>.vmicd.part`, `.<id>.json.tmp`)
začínajú bodkou a nekončia na `.vmicd` ani `.json`. Sidecar je pre spotrebiteľov signál
dokončenej snímky: pri writeri `delta` sa premenuje až po dátach, pri writeri `raw` ho zberač
zapíše až po premenovaní snímky, a `safeguard` snímku bez úplného sidecaru nespracuje
(časť 4.3).

---


### 6.1 Blok `features` — per-bin príznakový vektor

Od commitu `9765072` (2026-09-18) modul do sidecaru pripisuje blok `features` (schéma
`hyptcn3/perbin/1`). Počíta ho `src/perbin.c`, napojený na delta writer — ten už každú
stránku hashuje, takže rozhodnutie „zmenila sa" tam existuje a per-bin počty sú takmer
zadarmo. Raw writer vektor nepočíta.

Binuje sa **iba nad memslotmi**; bin, ktorý neprotína žiadny memslot, nevzniká. Index binu
je `gpa >> log2(bin_bytes)`, teda viazaný na fyzickú adresu, nie na poradie — zostáva rovnaký
medzi snímkami aj keď sa počet memslotov zmení. Pole `regions` je v bloku preto, aby sa vlastnosť „biny sú iba nad memslotmi" dala overiť
zo samotnej archivovanej snímky, bez prístupu k bežiacej VM. Sú to **efektívne oblasti zberu**
odvodené z memslotov, so zlúčenými susedmi — pri doméne `hyptcn-guest` dáva 10 memslotov
5 oblastí. Nevolajú sa „memslots" práve preto, aby sidecar netvrdil viac, než v ňom je.

Reálna ukážka (skrátená na tri biny), súbor
`data/results/perbin_c_20260918/sidecars/on/hyptcn-guest_000003_20260918T190343784Z.json`.
Pole `regions` tento skorší sidecar ešte nemá; má ho napríklad
`data/sessions/20260919T004123Z_validate/snap/hyptcn-guest_000000_20260919T004126406Z.json`
(5 oblastí, prvá `{"gpa": 0, "bytes": 655360}`).

```json
{
  "schema": "hyptcn3/perbin/1",
  "bin_bytes": 16777216,
  "page_size": 4096,
  "entropy": true,
  "compute_ms": 52.801,
  "bins_total": 131,
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
| `open_image(cesta, chain_id=None, until_seq=None, validate=True)` | `image.py` | otvorí adresár s reťazcom `.vmicd`, jeden `.vmicd`, alebo raw obraz; rozbitý reťazec odmietne výnimkou `ChainError` |
| `VmicdImage`, `RawImage` | `image.py` | čítanie snímky: `read(pa, n)`, `page_present(pa)`, `pages()`, `page_count()`; `VmicdImage` aj `header(path)` a `chain_info()` |
| `chain_files(adresar, chain_id=None, until_seq=None)` | `image.py` | vyberie a zoradí overený reťazec (časť 5.2) |
| `validate_chain(headers)`, `ChainError`, `PAGE` | `image.py` | overenie reťazca podľa hlavičiek, jeho výnimka, veľkosť stránky |
| `Profile`, `ProfileError`, `btf_offsets` | `profile.py` | symboly z kallsyms, offsety polí z BTF |
| `build_view(snimka, profil, banner_text=None, until_seq=None, *, expected_boot_id=None, image=None)` | `view.py` | otvorí snímku, načíta profil, nájde posun jadra; vracia `(view, image)` |
| `GuestView` | `view.py` | `processes()`, `modules()`, `sockets()`, `info()`, `to_pa()`, `walk_pa()`, `walk_pa_detail()`, `translation_check()`, `profile_boot_mismatch()`, `reanchor()`, `resolve_problem()` |
| `check_all(view, procs=None, mods=None, text_baseline=None)` | `checks.py` | kontroly integrity (a)–(d) |

Mimo `__init__.py` používajú ostatné časti práce aj `guestparse.image.ChainCursor` (postupné
otváranie reťazca po `seq` bez opakovaného indexovania, commit `5bf8e31`; volá ho
`features/snapshot.py`) a `guestparse.context.capture_boot_id` (boot UUID zaznamenaný pri
zbere; volá ho aj `scripts/validate_campaign_archive.py`). Mapovanie bin → proces je dostupné
cez CLI (`procmap`, časť 7.2).

Reálny príklad — vstup:

```python
from guestparse import build_view, check_all

view, img = build_view(
    "data/sessions/20260918T154914Z_validate/snap",
    "profiles/debian12-6.1.0-42-cloud-amd64")
try:
    if view.profile_boot_mismatch():       # profil z iného bootu: ako CLI (blok A2)
        ok, why = view.reanchor()
        print("preukotvenie:", ok)
    print("posun jadra: -0x%x" % abs(view.ktext_shift))
    ps = view.processes()
    print("procesov: %d, neuplne: %s" % (ps["count"], ps["truncated"]))
    print("prvy:", ps["processes"][0])
    so = view.sockets()
    print("socketov: %d, z toho LISTEN: %d"
          % (so["count"], sum(1 for s in so["sockets"] if s["state"] == "LISTEN")))
    res = check_all(view)
    print("nalezov kontrol: %d, neuzavrete: %s"
          % (res["finding_count"], res["summary"]["inconclusive"]))
finally:
    img.close()
```

Výstup (doslovne, beh 2026-10-29 nad commitom `709ee7f`):

```
preukotvenie: True
posun jadra: -0x200000
procesov: 80, neuplne: False
prvy: {'pid': 1, 'tgid': 1, 'comm': 'systemd', 'kernel_thread': False, 'task_va': 18446631688392985728}
socketov: 13, z toho LISTEN: 6
nalezov kontrol: 0, neuzavrete: ['text_integrity']
```

Snímka je z 2026-09-18 a jej `.vmicd` je iba lokálny (časť 5.2), profil v repozitári je
z bootu 2026-09-19. Samotný `build_view` profil nanovo neukotvuje; preto príklad volá
`profile_boot_mismatch()` a `reanchor()` rovnako ako CLI (časť 7.2). Bez preukotvenia vyšiel
ten istý beh s posunom `-0x1aa00000`, neúplným zoznamom procesov, 0 soketmi a 451 nálezmi.
Pôvodný výpis z 2026-09-18 (vtedajší profil, bez preukotvenia) mal rovnaké hodnoty a 0 nálezov
z troch kontrol. Štvrtá kontrola, `text_integrity`, je neuzavretá: baseline textu jadra
v profile je z bootu 2026-09-19 a so snímkou podľa hlášky kontroly nesedí ani po posune
o rozdiel KASLR.

Každý výsledok prechodu zoznamu má tvar
`{'<kľúč>': [...], 'count': N, 'truncated': bool, 'stop_reason': str|None}`. Pole
`truncated` je povinná súčasť odpovede: tichý polovičný zoznam by sa nedal odlíšiť od
skutočného stavu hosťa. `processes()` vracia navyše `walk` (`'next'`, `'prev'` alebo
`'tail'`), pri `'prev'` a `'tail'` aj `forward_stop_reason` a pri neuzavretom zozname
`backward_stop_reason` (časť 8.1).

### 7.2 CLI

Kontrakt je zapísaný v hlavičke `guestparse/cli.py` a je označený za nemenný, lebo sa naň
spoliehajú ostatné časti práce:

```
python3 -m guestparse ps       --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse lsmod    --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse ss       --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse info     --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse checks   --snapshot <cesta> --profile <adresár> [--json]
python3 -m guestparse procmap  --snapshot <reťazec> --profile <adresár> \
      [--bin N] [--bin-bytes B] [--json]
python3 -m guestparse textbaseline --snapshot <čistá snímka> --profile <adresár> \
      [--force] [--vmlinux F]
python3 -m guestparse validate --snapshot <cesta> --profile <adresár> \
      --ps-before F --ps-after F [--lsmod F] [--ss F] --out results.json
```

`procmap` (blok A4) priradí zmenené stránky binov procesom; `textbaseline` (blok A3) zapíše
do profilu baseline textu jadra pre kontrolu (d). Všetky podpríkazy majú navyše spoločné
voľby `--banner TEXT`, `--boot-id UUID` (boot zaznamenaný pri zbere) a `--chain-until SEQ`
(časť 5.2).

Návratové kódy:

| Kód | Znamená |
|---:|---|
| 0 | prebehlo a nič sa nenašlo |
| 1 | kontrola niečo našla (`checks`) — zámerne nie 0, aby sa nález nestratil v skripte |
| 2 | chyba: snímka sa nedá otvoriť (aj rozbitý reťazec), profil sa nedá načítať, posun jadra sa nenašiel; pri `textbaseline` aj existujúca baseline bez `--force` |
| 3 | podpríkaz nie je implementovaný (chýba modul balíka) |
| 4 | `checks`: nič sa nenašlo, ale aspoň jedna kontrola sa neuzavrela — nula z neuzavretej kontroly nie je dôkaz čistoty |
| 5 | nesúlad profilu, ktorý preukotvenie neodstránilo: `kallsyms` je z iného štartu jadra (KASLR) než snímka a `GuestView.reanchor()` zlyhal (napr. FGKASLR, chýbajúce stránky). Pri úspešnom preukotvení príkaz pokračuje s varovaním na stderr a kód 5 nevráti. Platí pre všetky podpríkazy a prebíja 1 aj 4 — nález zo zlého profilu nálezom nie je. Čítacie podpríkazy výpis vypíšu a označia `NEUPLNE`, `validate` sa nespustí a JSON nezapíše, `textbaseline` baseline nevytvorí |

Výpisy nižšie sú zo snímky domény `hyptcn-guest` zozbieranej 2026-09-18 o 15:49:16 UTC.
Sú to doslovné prepisy vtedajších behov a nemenia sa; profil sa po reštarte hosťa
2026-09-19 odoberal nanovo, takže dnešný má iný počet symbolov aj iné adresy (L17).
Každý z týchto príkazov 2026-10-29 najprv vypíše na stderr `POZOR: profil bol z ineho bootu
(KASLR); preukotvenie o -444596224 uspelo - pokracujem s preukotvenym profilom` a pokračuje
s preukotveným profilom. `ps`, `ss` a `lsmod` vypíšu to isté ako nižšie. `info` má navyše
riadky `retazec:`, `profil z bootu …` a `preukotvenie:`, iný počet symbolov a štruktúr
profilu a pri `banner PA` namiesto `(kandidat 10)` údaj `(vyskytov bannera 11)`; posun
jadra aj krížová kontrola prekladu vyjdú rovnako ako nižšie.
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
Od bloku A3 (commit `7134058`, 2026-10-05) má `checks` štyri kontroly. Ten istý príkaz
2026-10-29 vypíše prvé tri riadky rovnako, navyše riadok `text jadra NEDOSTUPNA (baseline
textu nesedi s profilom ani po posune o KASLR rozdiel (ine jadro); obnov ju nad cistou
snimkou)` a riadok `NEUZAVRETE kontroly: text_integrity …`, a skončí kódom 4: baseline textu
v profile je z bootu 2026-09-19, snímka z 2026-09-18 (`docs/LIMITACIE.md`, L18).
Čo nulový nález **nedokazuje**, je v `docs/LIMITACIE.md`, časť L10.

---

## 8. Tok dát od pamäte VM po JSON

Jeden cyklus zberača a parsera:

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
      │  iba stránka, ktorej hash sa líši od minulého cyklu, ide do fronty v pamäti
      ▼
 7. output.c, vlákno vmic-writer: <id>.vmicd na disku  +  <id>.json
      │  (meta.c, schema vmicollect/1), oba pod dočasným menom, potom premenované
      │
      │   ── tu končí zberač; ďalej sa pracuje iba so súbormi ──
      ▼
 8. guestparse.image.open_image(): overenie reťazca, index stránok
      │  (index → súbor, offset); obsah sa nekopíruje, chýbajúca stránka = nulová
      ▼
 9. guestparse.profile.Profile: kallsyms (92698 symbolov v dnešnom profile) + offsety z BTF
      ▼
10. guestparse.view.GuestView.resolve(): sken banneru → kandidáti na posun jadra
      │  → init_task.comm == "swapper/0" + identita bootu → jediná kotva
      │  → ktext_shift, page_offset_base
      ▼
11. preklad adries: lineárne vetvy (obraz jadra, priamy mapping) alebo
      │  prechod tabuliek stránok z init_top_pgt (moduly, vmalloc)
      ▼
12. prechod spájaných zoznamov jadra → procesy / moduly / sokety
      ▼
13. JSON na stdout (--json) alebo do súboru (validate --out)
```

V detektore (`safeguard`) prebehnú kroky 8–12 vo `features.snapshot` a namiesto kroku 13
pokračuje cesta takto (podrobne [`SAFEGUARD.sk.md`](SAFEGUARD.sk.md), časť Dátová cesta):

```
14. safeguard.features.frame_from_snapshot(): sidecar + features.snapshot (guestparse)
      │  → Frame: globálne príznaky, per-bin blok zo sidecaru, kvalita, nálezy integrity
      ▼
15. WindowBuffer: časové okno; plná snímka, chýbajúci predchodca, neplatný vstup
      │  alebo medzera v čase, seq či reťazci ho prerušia
      ▼
16. uložená normalizácia → globálna TCN + zdieľaná per-bin TCN (prediktor),
      │  klasifikátor profilu záťaže → skóre a trieda aktivity
      ▼
17. skóre > kalibrovaný prah aspoň k-krát z posledných n → alarm modelu;
      │  nález integrity → alarm nezávisle od modelu
      ▼
18. events.jsonl a status.json; pri alarme vmicollect hold <raw> <chain_id>...
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
3. Kandidát musí mať pri tomto posune `init_task.comm == "swapper/0"`.
   Samotná dvojica ešte nestačí: RAM po reštarte môže obsahovať viac kópií jadra.
4. Pri native zbere `guestparse.context` načíta boot UUID zaznamenané pred zberom
   a resolver ho porovná so `sysctl_bootid` každej kópie. Vyžaduje jedinú zhodu.
   Bez metadát vyžaduje jediného kandidáta alebo explicitne doloženú identitu;
   nejednoznačnosť znamená chybu vstupu. Boot profilu neurčuje boot snímky.
   Kandidáti a vybraná identita sú v `info --json`. Rozhodnutie nevyužíva
   modelové skóre, úplnosť procesného zoznamu ani výsledok kontrol integrity.

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
a `init_task`; v meranej snímke obe sedia (výpis v časti 7.2). Z tej istej dvojice stavia
`GuestView.profile_boot_mismatch()` diagnózu „profil je z iného štartu jadra".
Za nesúlad považuje aj úspešný preklad na inú fyzickú stránku. Pred parsovaním
sa skúsi preukotvenie s oboma kotvami; ak neuspeje, platí kód 5 (L17).

**Miesto 3 — rekonštrukcia objektov (`view.py`, `checks.py`).** Offsety polí sa berú z BTF
hosťa, nie z hlavičkových súborov: rozloženie štruktúr závisí od konfigurácie jadra
(`CONFIG_*`), nie iba od verzie, takže číslo opísané zo zdrojákov by pri inom `.config`
ticho ukazovalo na iné pole. Prechádzajú sa spájané zoznamy jadra:

- **procesy**: `init_task.tasks`, strop 8192 položiek, detekcia cyklu, kontrola
  rozumnosti PID. Živá snímka môže zoznam roztrhnúť; keď sa prechod dopredu neuzavrie,
  prejde sa dozadu cez `prev`. Prijmú sa uzly, ktoré prechod dopredu prešiel pred prvým
  spojením nezhodným s opačným smerom, a to iba vtedy, keď sa prechod dozadu uzavrel cez
  presne tie isté uzly (`walk` = `'prev'`, commit `0b61ffd`). Pri vložení na koniec zoznamu
  (`walk` = `'tail'`, commit `b065ee4`) sa tie isté uzly prijmú aj bez toho, ak
  `init_task.prev` ukazuje práve na prvý nezhodný uzol a ten je vláknom (`tgid` ≠ `pid`),
  ktorého vodca je medzi zhodnými uzlami pred ním; nový proces pribudne v ďalšej snímke.
  Inak je zoznam `truncated` (`processes()` vo `view.py`, zvyškové riziko v
  `docs/LIMITACIE.md`, L1);
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
| `[output]` | `dir`, `writer`, `name_template`, `sparse`, `post_compress`, `hash`, `sidecar`, `delta_page_size`, `delta_full_every`, `fsync` (predvolene `true`), `queue_mib` (predvolene 0 = najväčšia plná snímka + 512 MiB), `mlock` (predvolene `false`), `drain_s` (predvolene 240 s); fronta zápisu a jej dobehnutie, časť 2 |
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

Kľúč `output.hash_async` (commit `bbf624d`, SHA-256 plnej snímky vo vlákne) zberač 1.1
zrušil (`625d8f9`); vlákno `vmic-writer` dnes hashuje mimo cyklu každú snímku. Zadaný kľúč
validácia 2026-10-29 odmietla ako neznámy parameter a `run` skončil kódom 2.

Úplný zoznam kľúčov vypíše `vmicollect config --keys`, efektívnu konfiguráciu
`vmicollect config`.

### 9.1 CLI zberača

Výpis z 2026-10-29 (commit `709ee7f`); sekcie `PREPINACE` a `PRIKLADY` sú vynechané:

```
$ ./vmicollect/build/vmicollect --help
vmicollect 1.1.0 - periodicky zber pamatovych snimok virtualnych strojov

POUZITIE
  vmicollect <prikaz> [-c subor.conf] [-o sekcia.kluc=hodnota]...

PRIKAZY
  run                periodicky zber (Ctrl-C korektne ukonci)
  once               jedna snimka a koniec
  probe              pripoj sa a vypis parametre VM (nic nezapisuje)
  restore            poskladaj plny obraz z delta retazca
                       --dir D --out F [--chain ID] [--until SEQ]
  hold <dir> <id>... oznac retazce markerom HOLD (retencia ich nezmaže)
                       <id> = chain_id (delta zber) alebo meno suboru
  verify [adresar]   over kontrolne sucty snimok podla .json
  config             vypis efektivnu konfiguraciu
  config --keys      vypis vsetky nastavitelne parametre
  backends           zoznam dostupnych backendov
  selftest [adresar] over celu cestu bez potreby VM
...
```

Návratové kódy `run` a `once` (`cmd_run` v `main.c`); na kód 0 sa spolieha napríklad
`safeguard/supervisor.py`, ktorého výsledok je `ok` iba pri kóde 0 zberača:

| Kód | Znamená |
|---:|---|
| 0 | všetky cykly prebehli a všetky snímky sa zverejnili |
| 1 | nezverejnila sa ani jedna snímka |
| 2 | chyba konfigurácie alebo argumentov |
| 3 | zberač sa nepodarilo pripraviť (výstupný adresár, backend, VM, writer, striktné hooky, fronta zápisu, `output.mlock`, vlákno logu), fatálna chyba počas zberu alebo zlyhaný hook v striktnom režime |
| 4 | aspoň jeden cyklus zlyhal, niektorá snímka sa nezverejnila celá (zlyhaný zápis, delta zahodená po chybe zápisu v jej reťazci, snímka nezapísaná do konca `output.drain_s`) alebo sa stratil riadok logu |

---

## 10. Ako sa architektúra overuje

Dva príkazy, obidva bez roota a bez bežiacej VM. `make -C vmicollect test` spustí štyri
regresné testy v C (`hole_test`, `perbin_test`, `retention_test`, `alarm_test`) a selftest;
`python3 -m pytest -q` v koreni repozitára spustí testy balíkov `guestparse`, `features`,
`safeguard`, `scripts` a `tcn`. Oboje naraz spustí `make test` v koreni, kontrolu tvrdení
`make check` (`scripts/check_claims.sh`). Výpisy sú z 2026-10-29 nad commitom `709ee7f`;
zberač bol preložený s `BUILD=$SC/build`, preto cesty začínajú `$SC`. `retention_test`
a `alarm_test` si vytvoria pracovný adresár `/tmp/vmic-*` a nezmažú ho.

Vynechané sú riadky prekladu a výpisy jednotlivých kontrol testov:

```
$ make -C vmicollect BUILD=$SC/build test
...
$SC/build/hole_test
chunks=2 read_errors=1 filled_zero=131072 bytes_read=1966080
OK: pamat za dierou sa zachovala, obraz je zhodny s referenciou
$SC/build/perbin_test $SC/build/perbintest
...
OK: 3 binov, invariant sedi, entropia 0/8 -> priemer 4, dva behy zhodne
$SC/build/retention_test
...
retention_test: VSETKO PRESLO (adresar: /tmp/vmic-retention-Xqo8ck)
...
alarm_test: VSETKO PRESLO (adresar: /tmp/vmic-alarm-eVimgE)
$SC/build/vmicollect selftest $SC/build/selftest
...
2026-10-29T20:15:02.897Z INFO  restore: hotovo -> $SC/build/selftest/restored.raw (16.00 MiB, 2057 zapisanych stranok)
2026-10-29T20:15:02.902Z INFO  selftest: OK - obnoveny obraz je bajt po bajte zhodny
2026-10-29T20:15:02.922Z INFO  selftest: OK - raw snimka ma spravny SHA-256
2026-10-29T20:15:02.923Z INFO  selftest: VSETKO PRESLO. Data su v $SC/build/selftest
```

```
$ PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider --basetemp=$SC/pytest_tmp
...
POZOR: preskocilo sa 24 testov - preskoceny test NIE JE presiel.
   19x Skipped: chyba validacna snimka /var/tmp/vmic-val (nastav GUESTPARSE_VAL)
    2x Skipped: retazec delta snimok nie je na tomto stroji: /var/tmp/vmic-delta
    2x Skipped: chyba delta retazec /var/tmp/vmic-delta (nastav GUESTPARSE_DELTA)
    1x Skipped: mini snimka neobsahuje ziadnu stranku textu jadra
684 passed, 24 skipped in 151.32s (0:02:31)
```

`PYTHONDONTWRITEBYTECODE`, `-p no:cacheprovider` a `--basetemp` iba bránia zápisu dočasných
súborov do repozitára. Zo 708 zozbieraných testov je 177 v balíku `guestparse`, 143 vo
`features`, 102 v `safeguard`, 244 v `scripts` a 42 v `tcn` (`--collect-only` po balíkoch).
Z 24 preskočených potrebuje 23 lokálne snímky mimo gitu (`/var/tmp/vmic-val`,
`/var/tmp/vmic-delta`; premenné `GUESTPARSE_VAL` a `GUESTPARSE_DELTA`) a jeden sa preskočí,
lebo mini snímka neobsahuje stránku textu jadra.

Čo tieto testy **netestujú**, je vymenované v `docs/LIMITACIE.md`, časti L5 a L6.
Rýchlosť čítania, ktorú vypisuje `selftest`, je rýchlosť čítania súboru z page cache
a nemá vzťah k čítaniu pamäte bežiacej VM (`HONESTY.md`, kapitola 3).

---

## 11. Kde sa `README.md` rozchádza s kódom

Predlohou tohto dokumentu bol `vmicollect/README.md` v stave z 2026-09-18. Pri porovnaní so
zdrojovým kódom sa vtedy našli tieto rozdiely; podľa `HONESTY.md` P12 platí kód:

1. **Schéma v README kreslila `hooks.c` pod blokom BPF programu**, akoby hooky viseli na
   backende. V kóde ich volá `vmic_collector_cycle` na konci cyklu, až po zápise snímky
   a po sidecare, a pred retenciou (od verzie 1.1 pri writeri `delta` vlákno `vmic-writer`
   v tom istom poradí). Schéma v časti 2 tohto dokumentu je opravená.
2. **README uvádzalo pri delta writeri podiel zmenených stránok a objem dát za hodinu** ako
   motiváciu (to isté je v hlavičke `src/writer_delta.c`). Sú to rádové odhady, nie
   merania na tomto stroji — sú vedené v `HONESTY.md`, kapitole 3, a do textu práce sa
   neprepisujú.
3. **Príklad JSON sidecaru v README** (doména `win10`, nenulový `read_errors`) je
   vymyslený. Reálny príklad je v časti 6 tohto dokumentu.
4. README vymenúvalo, čo netreba („žiadna LibVMI“), ale nespomínalo, že parser potrebuje
   **profil jadra hosťa** získaný z hosťa. Priznané je to v `docs/LIMITACIE.md`, časť L3,
   a v `profiles/debian12-6.1.0-42-cloud-amd64/README.md`.

README sa odvtedy reviduje samostatne, takže tento zoznam je záznam z odvodenia tohto
dokumentu, nie opis dnešného README. Kde sa README s kódom rozchádza, platí kód.

Vecné časti README, ktoré sa s kódom zhodujú a boli sem prevzaté po overení: štyri vrstvy
a tabuľka súborov, tabuľka `[sekcia].kľúč`, zoznam príkazov CLI, poznámka o confidential
VM, poznámka „jeden adresár = jeden zberač“. Opis markera `HOLD`, alarmov a zápisu mimo
cyklu (časti 2, 2.5 a 4.2) je zapísaný priamo podľa `retention.c`, `hooks.c` a `output.c`.

---

## 12. Provenienčná poznámka

Pôvod kódu sa tu uvádza podľa `HONESTY.md` P9. Zberač `vmicollect` je vlastná práca autora
zo staršej vetvy projektu. Do repozitára vstúpil ako celok v commite `6b9053d` (stav
2026-08-26, bez zmien); slovo „prevzatý“ v správe tohto commitu znamená prenesenie zo
staršej vetvy projektu, nie cudzie autorstvo. Pôvodná cesta cez eBPF nikdy nebola overená
proti bežiacemu jadru. Prvá zmena zberača po `6b9053d` je commit `178ce4f`
v `bpf/vmic_kvm.bpf.c` — štyri opravy potrebné
na to, aby sa program načítal do jadra a prešiel verifikátorom; overenie proti bežiacemu
jadru aj tieto opravy sú prácou tejto diplomovej práce. Neskoršie commity zberač
rozšírili a upravili; všetky commity po `6b9053d`, ktoré sa ho týkajú, vypíše
`git log --oneline 6b9053d..HEAD -- vmicollect`.

Balík `guestparse` nadväzuje na prototyp parsera `vmi_parse.py` z prípravnej fázy. Prototyp
(537 riadkov) je mimo repozitára; do modulov balíka sa rozdelil 2026-09-18 (prvý commit
balíka `18d4eaf`), pôvod uvádzajú aj hlavičky `guestparse/__init__.py` a
`guestparse/image.py`. Z prototypu je podľa záznamu v `docs/MERANIA.md` (2026-09-18, časť
o rekonštrukcii objektov hosťa) čítanie `.vmicd` na mieste s indexom stránok, profil
z kallsyms a offsetov z BTF, preklad adries (dve lineárne vetvy a štvorúrovňový prechod
`init_top_pgt`), nájdenie posunu jadra skenom banneru s kontrolou
`init_task.comm == "swapper/0"`, krížová kontrola prekladu a prechod procesov, modulov
a soketov s protokolom IPv4. Pri rozdelení a po ňom pribudli: protokol soketov IPv6,
kontroly integrity (a)–(c) a porovnanie s pozemnou pravdou (`checks.py`, `validate.py`,
2026-09-18), profil viazaný na boot (`boot.json`, `b574b8d`), preukotvenie profilu (blok A2,
`61a8980`), kontrola (d) textu jadra (A3, `7134058`), mapovanie bin → proces (`procmap.py`,
A4, `88608d7`), časová os cez viac reťazcov (`c221c6a`), `ChainCursor` (`5bf8e31`),
identita bootu zo záznamu zberu (`context.py`, `bf6ed37`) a potvrdenie zoznamu procesov
prechodom dozadu (`0b61ffd`) a pravidlom `tail` (`b065ee4`). Či už prototyp overoval
celistvosť reťazca (`validate_chain`, `ChainError`), sa bez neho doložiť nedá; v balíku je
od `18d4eaf`.

Integračný balík `safeguard/` vznikol pre tento projekt. Spája existujúci
zberač a parser s jednotnou tvorbou vstupov, normalizáciou, explicitnými
rolami korpusu, verziovaným uložením modelov a hostiteľským detektorom.
`safeguard/model.py` používa kauzálne dilatované bloky z `tcn/model.py`,
ktoré implementujú architektúrny princíp TCN podľa Bai, Kolter a Koltun
(2018); zdieľaná per-bin vetva, spojenie chýb, klasifikátor záťaže a ich
integrácia sú zapísané v tomto repozitári. Nejde o prevzatie cudzích
natrénovaných váh. Staršia detekčná cesta nad 22-stĺpcovým vektorom snímky
(`tcn/train.py`, `tcn/score.py` a ďalšie súbory z časti 1.3) je v repozitári ponechaná ako
diagnostická a historická do konca experimentov; `safeguard` z nej používa iba
`tcn/model.py`. Kontrakt, príkazy a hranice overenia opisuje
[`SAFEGUARD.sk.md`](SAFEGUARD.sk.md). Syntetický integračný test nie je
experimentom účinnosti voči malvéru.
