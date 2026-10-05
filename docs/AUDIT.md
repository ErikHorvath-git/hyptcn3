# AUDIT — stav repozitára hyptcn3 k 2026-10-05 (fáza 0)

Audit bežal **spustením kódu a testov, nie čítaním docs**. Commit auditu: `97b0c43`,
vetva `main`, pracovný strom čistý, sync s `origin/main`
(`github.com/ErikHorvath-git/hyptcn3.git`). Každé tvrdenie nižšie má za sebou príkaz,
ktorý ho overil; kľúčové výstupy sú v kapitole „Dôkazy“.

## Prostredie, na ktorom sa overovalo (zmerané dnes)

| položka | hodnota |
|---|---|
| hostiteľ | Fedora 43, jadro `7.2.5-100.fc43.x86_64`, 16 CPU, 15 GiB RAM, 215 GB voľných |
| BTF jadra | `/sys/kernel/btf/vmlinux` (7,0 MB) aj `/sys/kernel/btf/kvm` (409 KB) existujú |
| nástroje | clang 21.1.8, gcc 15.3.1, bpftool 7.6.0, libbpf 1.6, QEMU 10.1.5, libvirt 11.6.0 (`qemu:///session`) |
| python | 3.14.7 + torch 2.11.0, numpy 2.3.5, scipy 1.17.1, sklearn 1.8.0, pytest 8.3.5 |
| root | `sudo` vyžaduje heslo (interaktívne) → eBPF load/ostrý zber sa bez hesla overiť nedal |
| BPF policy | `unprivileged_bpf_disabled=2` (neprivilegovaný load nie je možný) |
| VM | `hyptcn-guest`: Debian 12.13, jadro `6.1.0-42-cloud-amd64`, 2 vCPU, 2 GiB; disk `/home/eh/vms/hyptcn-guest.qcow2` (overlay nad `debian-12-base.qcow2`), sieť `virbr0` (NAT) |
| VM stav | počas auditu **spustená** (nový boot, `boot_id=0201e643…` ≠ profil `82b778a3…` z 2026-09-19); ssh `root@192.168.122.100` aj qemu-guest-agent 7.2.22 fungujú |

## Súhrn testov spustených dnes

| príkaz | výsledok |
|---|---|
| `make -C vmicollect && make -C vmicollect test` | **OK** — selftest (plná snímka, 3 delty, restore bajt-po-bajte zhodný, SHA-256 sedí), hole_test, perbin_test |
| `python3 -m pytest -q` (celé repo) | **192 passed, 21 skipped** (skipy potrebujú `/var/tmp/vmic-{val,delta}` z iného stroja) |
| `python3 -m pytest guestparse -q` | 80 passed, 19 skipped |
| `python3 -m pytest features -q` | 88 passed, 2 skipped |
| `python3 -m pytest tcn -q` | 24 passed (kauzalita, receptívne pole, determinizmus, split, konvergencia) |
| `scripts/check_claims.sh` | **EXIT=1, 37 nálezov v 97 súboroch — všetkých 37 v `docs/notebookLM.md`** (čísla z predchádzajúceho repa hypTcn002) |
| `scripts/check_prirucka.sh` | OK — `docs/PRIRUCKA.md` sedí s kódom |
| `scripts/guest_exec.sh --self-test` | OK — 4/4 (ssh aj guest-agent cesta na živej VM) |

`check_claims.sh = 0 nálezov` **dnes neplatí** — jediným zdrojom nálezov je
`docs/notebookLM.md` (importovaný vysvetľujúci dokument), ktorý cituje metriky
staršieho projektu (hypTcn002) zakázané pravidlom P1/P3/P11 (konkrétne čísla
sú v tom istom výpise kontroly).

## Overenie podľa kontrolného zoznamu fázy 0

### Hypervisor modul (`vmicollect/`)

| komponent | stav | čo konkrétne chýba | súbor |
|---|---|---|---|
| `pick_vm` — výber VM podľa mena | **hotové** | výber menom medzi viacerými VM je implementovaný (presná zhoda → substring → chyba pri nejednoznačnosti, `pid:N`); ide cez sken `/proc/*/fd` (anon_inode:kvm-vm) + QEMU cmdline, **nie cez libvirt** | `src/backend_ebpf.c:493-587` |
| znovupripojenie po reštarte hosťa | **hotové v kóde, live neoverené** | `eb_begin_cycle()` každý cyklus znova `pick_vm` pôvodným menom pri novom pide + `refresh_vm()`; overiť treba reštartom VM počas behu | `src/backend_ebpf.c:1028-1054`, `src/collector.c:125-142` |
| memsloty z `struct kvm` | **hotové (v BPF)** | enumerácia cez hash `kvm_memslots.id_hash` v jadre (nie ioctl `KVM_GET_USER_MEMORY_REGION`); kontrola `generation` pred/po | `bpf/vmic_kvm.bpf.c:235-356` |
| posuny z BTF | **hotové** | runtime BTF z `/sys/kernel/btf/{vmlinux,kvm}` cez libbpf, nie CO-RE ani hardcoded; **offsety vyriešené dnes naživo na jadre 7.2.5** (`memslots +4360, online_vcpus +4440, userspace_pid +6928, id_hash +40, slot.id_node +0, base_gfn +176, npages +184, userspace_addr +248, flags +256, id +260`) | `src/backend_ebpf.c:257-402` |
| podpríkaz `probe` | **hotové** | bez roota funguje s `file` backendom (2865 MiB/s); s `ebpf` nájde VM, vyrieši BTF a skončí EPERM korektnou hláškou (exit 3) | `src/main.c:253-307` |
| plný + delta writer | **hotové** | selftest pokrýva obe cesty; hlavička `.vmicd` (`VMICDLT1`) overená po bajtoch; restore bajt-po-bajte zhodný | `src/writer_raw.c`, `src/writer_delta.c`, selftest `src/main.c:462-618` |
| SHA-256 so SHA-NI | **hotové** | CPUID detekcia + skalárny fallback; obe vetvy dávajú rovnaký hash (overené `VMIC_SHA256_SCALAR=1`); `sha_ni` na CPU prítomné | `src/sha256.c:99-342` |
| plánovač (pevná perióda) | **hotové** | absolútne termíny `CLOCK_MONOTONIC`, jitter, overrun `skip/catch_up/stretch`, počítanie zmeškaných slotov — overené naživo („1 zmeskanych slotov“ pri 5 ms perióde) | `src/sched.c:36-153` |
| sidecar JSON | **hotové** | všetky polia overené v reálnom výstupe | `src/meta.c:42-202` |
| `retention.c` | **čiastočné** | mazanie celých reťazcov podľa `max_snapshots/max_bytes/max_age_s` áno; **žiadny trvalý „hold“ marker** (ochrana len v pamäti: aktívny + najnovší reťazec) — blok A5 | `src/retention.c:101-287` |
| hooky | **čiastočné** | jeden event (po snímke, `vmic_hook_snapshot`); **žiadny alarm interface, žiadny `alarm.json`** — blok A6; `example_hook.so` = CSV index (overené) | `src/hooks.c:62-160`, `vmicollect/include/vmic.h:432-462` |
| eBPF sa načíta do bežiaceho jadra | **neoverené dnes — treba root** | objekt sa stavia aj embeduje (`vmic_kvm.bpf.embed.o`), `bpftool gen skeleton` exit 0, `bpftool prog load` → EPERM (bez CAP_BPF, `unprivileged_bpf_disabled=2`). Na kernele **7.2.5 dnes nenačítaný**; naposledy zdokumentovaný load na 7.1.13 (artefakty `data/results/probe_*.json`). Prvý krok po potvrdení plánu: `sudo scripts/root_run.sh probe` | `bpf/vmic_kvm.bpf.c`, `src/backend_ebpf.c:682-823`, `Makefile:132-133` |

Poznámka ku KASLR v zberači: zberač číta len fyzickú pamäť, KASLR ho neovplyvňuje —
preukotvenie patrí do `guestparse` (nižšie), nie sem.

### Parser (`guestparse/`)

| komponent | stav | čo konkrétne chýba | súbor |
|---|---|---|---|
| profil (kallsyms + BTF) | **hotové** | kallsyms.txt + btf.raw/btf.txt + boot.json; odber `get_profile.sh` cez ssh aj guest-agent | `guestparse/profile.py:68-232`, `scripts/get_profile.sh:215-272` |
| preklad adries (jadro) | **hotové pre jadro** | 3 cesty x86-64 (kernel image, direct map, 4-úrovňový PGD/PUD/PMD/PTE walk z `init_top_pgt`); KASLR posun sa hľadá skenom banneru `Linux version ` + `init_task.comm=="swapper/0"` | `guestparse/view.py:76-112,165-275` |
| rekonštrukcia ps / lsmod / ss | **hotové pri sediacom profile** | historický artefakt so sediacim profilom: procesy 80/80, moduly 51/51, sokety 11/12 (`data/results/validate_20260918T154914Z_ssbefore.json`); pri nesúlade profilu: ps/lsmod ešte rekonštruujú (označené `NEUPLNE`), **ss vráti 0** (soket sa identifikuje cez `socket_file_ops` symbol z profilu) | `guestparse/view.py:320-572`, `:456,506` |
| `validate` | **hotové mechanicky** | pri nesúlade profilu sa odmietne (exit 5, nič nezapíše) — korektné; vzorová relácia `20260918T154914Z_validate` je zo staršieho bootu, takže sa dnes z repa nedá zopakovať | `guestparse/validate.py:111-288`, `guestparse/cli.py:356-369` |
| 3 invarianty v `checks.py` | **hotové** | (a) `sys_call_table` → každá položka do `[_stext,_etext)`, (b) procesy `tasks` vs. strom, (c) moduly `modules` vs. `module_kset`; unit testy + injekčný test (hook index 59 nájdený); priznané slepé miesto: hook **vnútri** rozsahu textu → invariant #1 ho nevidí (blok A3) | `guestparse/checks.py:105-158,231-278,333-396`, `docs/kontroly.md:53-59` |
| reštart hosťa / KASLR posun | **detekcia hotová, preukotvenie chýba** | overené naživo: `guestparse info` na snímke z iného bootu → `NESULAD PROFILU` + **exit 5** s presnou diagnózou (posun nájdený `-0x1aa00000`, walk skončil `PMD[396]/[401] nie je pritomna`); nástroj vie nájsť banner, vypočítať posun a potvrdiť lineárne čítanie, ale namiesto pokračovania vyžaduje ručný `get_profile.sh -f` — **blok A2 stavia presne na tomto** | `guestparse/cli.py:309-359`, `guestparse/view.py:657-738` |

### Príznaky (`features/`)

| komponent | stav | čo konkrétne chýba | súbor |
|---|---|---|---|
| `perbin.c` (C modul) | **hotové** | per-bin vektor do sidecaru (changed_ratio, zero_ratio, entropy_mean, has_changed); invariant súčtov pred zápisom; `perbin_test` overuje geometriu, entropiu 0/8→4, determinizmus | `vmicollect/src/perbin.c:94-339` |
| Python referencia | **hotové** | nezávislá implementácia toho istého kontraktu | `features/perbin.py:332-429` |
| `crosscheck` | **hotové** | C vs. referencia pole po poli (int presne, float tol. 5e-7); reprodukované dnes na reťazci `/var/tmp/perbin_c/on`: **6/6 snímok zhoda, max diff ≈ 4,4–5,0e-07, 0 polí mimo presnosti C**; vzorová snímka z 15:49Z nemá v sidecari blok `features` (zber pred dokončením perbin.c) — čitateľná chyba, nie tichá hodnota | `features/crosscheck.py:50-148` |
| 22-rozmerný vektor `snapshot.py` | **hotové** | presne 22 príznakov: 8 pamäťových agregátov + proc_total/proc_user/proc_kernel/proc_new/proc_gone + mod_total/mod_delta + sock_total/sock_listen/sock_estab + chk_syscall_hooks/chk_crossview + ma_predchodcu/je_plna; overený čistý vektor na snímke z nového bootu | `features/snapshot.py:103-112,172-309` |
| okná `windows.py` | **hotové len (N,L,22)** | dnes iba agregovaný tvar `(N, L, 22)`, `DLZKA_OKNA=16`, segmenty po sedeniach, okná s plnou snímkou/bez predchodcu sa zamietajú celé | `features/windows.py:8-23,57-78,238-335` |
| per-bin vetva v `windows.py` | **zmazaná — potvrdené** | git: `9765072` (18. 9.) zaviedol per-bin tvar `(N,L,B,4)` + `ako_kanaly()→(N,L,B*4)`; **`b574b8d` (19. 9. 2026 14:03) ho zmazal**. Tvar `(N,L,B*4+22)` **neexistoval v žiadnom commite**. Obnova je možná z `b574b8d~1` (`vektor_z_binov`, `snimka_zo_sidecaru`, `nacitaj_session`, `ako_kanaly`) — blok D | git história, `features/manifest.py:60-78,126-210` (rezim `bin_priznak` ostal) |
| `normalize.py` + manifest | **mechanika hotová, prepojenie čiastočné** | z-score fit **len na benigných tréningových sedeniach**, manifest so schema/commit/date/priznaky_hash/save+load overením; ALE `tcn/train.py` manifest **neukladá** a `tcn/score.py` ho **nenačíta** | `features/normalize.py:78-260`, `features/manifest.py:126-326`, `tcn/train.py:197-223`, `tcn/score.py:45-48` |

### Model (`tcn/`)

| komponent | stav | čo konkrétne chýba | súbor |
|---|---|---|---|
| `model.py` (kauzálne dilatované konv.) | **hotové** | padding iba zľava, reziduálne bloky, RF = 1+2(k−1)(2^B−1) = 29; **testy kauzality a receptívneho poľa (cez gradienty) prechádzajú** | `tcn/model.py:47-87`, `tcn/tests/test_tcn.py:29-73` |
| `train.py` | **klasifikátor hotový, prediktor chýba** | len `nn.CrossEntropyLoss()` a labely; **regresná hlava / MSE / tréning bez štítkov neexistuje** — blok E1 | `tcn/train.py:159-245` |
| `eval.py` | **klasifikačné metriky hotové** | accuracy/macro-F1/per-trieda/confusion + binárny benign-vs-rest AUC; **FAR, time-to-detection chýba** — blok H | `tcn/eval.py:49-88` |
| `baselines.py` | **klasifikačné hotové** | LogReg / BagOfFrames / GRU (GRU 5442 param vs TCN 5394, rozumne porovnateľné); **anomálne baseliny chýbajú** — blok F | `tcn/baselines.py:43-86` |
| `score.py` | **hotové (dôkaz cesty, nie detekcia)** | online skórovanie okien z bežiaceho zberu, medián/p95 latencie, JSON s `model_natrenovany=false`; **per-bin lokalizácia chyby chýba** — blok E2 | `tcn/score.py:103-112,146-216` |
| natrénovaný model / korpus | **chýba** | žiadne `*.pt`, žiadne `.npz`, žiadne `labely.json`; jediné ML artefakty sú 2 syntetické smoke JSONy (`synteticke_data=true, guest=null`) | `data/results/smoke/` |

Dnešná TCN je **klasifikátor** (potrebuje štítky) — potvrdené. Prediktor normálu (E1)
a kalibrácia (E3) neexistujú.

### Skripty a harness

| komponent | stav | čo konkrétne chýba | súbor |
|---|---|---|---|
| `root_run.sh` | **probe/validate/once/run hotové** | v každom výstupe commit/príkaz/SHA-256; **žiadny `session` podpríkaz, žiadny revert overlayu, žiadna sieť, žiadny manifest, žiadna injekcia, žiadny tcpdump** — bloky B2–B5 | `scripts/root_run.sh:602-643` |
| `guest_exec.sh` | **hotové** | ssh + qemu-guest-agent s fallback (auto), rc kontrakt, `--json`; self-test 4/4 na živej VM | `scripts/guest_exec.sh:136-257` |
| `check_claims.sh` | **funguje, ale 37 nálezov** | všetky v `docs/notebookLM.md` (čísla hypTcn002); požiadavka „0 nálezov“ dnes nesplnená | `scripts/check_claims.sh` |
| `get_profile.sh` | **hotové** | kallsyms + BTF cez ssh/agent, validácie, boot.json | `scripts/get_profile.sh` |
| golden image | **čiastočné mimo repa** | na disku existuje backing `debian-12-base.qcow2` + `cloud-init.iso` (`/home/eh/vms/`), ale **definícia (cloud-init yaml + doména XML) nie je v repe** — blok B1 | mimo repa |
| overlay + snapshot-revert | **štruktúra áno, revert nie** | overlay `hyptcn-guest.qcow2` nad backing existuje, ale `virsh snapshot-list hyptcn-guest` je **prázdny** — blok B2 | mimo repa |
| izolovaná sieť | **chýba** | len `default` (virbr0, NAT); bez-NAT sieť neexistuje — blok B3 | `virsh net-list` |
| dáta | — | ≈33 snímok (28 `data/raw` + 5 `data/sessions`), najdlhší beh 10 cyklov po 5 s; zmeškané sloty = 0 vo všetkých run/once; do gitu idú len hashe/metadáta (`.vmicd`, `.raw`, `.qcow2` sú v `.gitignore`) | `data/` |

## Čo z plánu (bloky A–H) je už hotové — neprepisovať

- **A1 (výber podľa mena + reconnect)**: hotové v kóde (`pick_vm`, `eb_begin_cycle`); chýba len live test s 2. doménou a reštartom VM počas behu.
- **A2 (čiastočne)**: detekcia nesúladu, hľadanie banneru, výpočet posunu aj diagnóza sú hotové a otestované naživo; chýba pokračovanie po zistení posunu (preukotvenie) namiesto pádu s kódom 5.
- **Zber/delta/SHA-NI/plánovač/sidecar/per-bin C/referencia/crosscheck/okná (N,L,22)/normalizácia/TČN klasifikátor/baseliny/skórovacia cesta**: hotové a dnes znovu otestované (čísla vyššie).
- **Zmeškané sloty**: počítajú sa a hlásia sa na konci behu; chýba ich persistencia do sidecaru a dlhý beh (A8, H).

## Čo chýba (mapované na bloky)

Stav po bloku 1 (2026-10-05, commity `2da4651`..`88608d7`): **A2, A3, A4, A5, A6, D
sú HOTOVÉ** (každý s testami); **A1 hotový z časti** — výber domény podľa mena pri
dvoch VM je dokázaný artefaktom `data/results/a1_vyber_vm_20261005.json`,
znovupripojenie po reštarte má pripravený `scripts/a1_restart_test.sh` (čaká na
jedno `sudo`). Riadky nižšie s ~~škrtom~~ sú vyriešené a nechávajú sa kvôli
porovnaniu so zadaním.

| blok | čo chýba | existujúci kód, z ktorého stavať |
|---|---|---|
| A1 | ~~výber podľa mena~~ HOTOVÉ (živý test, artefakt); znovupripojenie po reštarte = `scripts/a1_restart_test.sh` (sudo) | `vmicollect/src/backend_ebpf.c:493-587,1028-1054` |
| A2 | ~~auto-preukotvenie profilu po KASLR posune~~ HOTOVÉ 2026-10-05 (delta meraný z tabuliek stránok, kotvy init_task+linux_banner) | `guestparse/view.py:reanchor`, `guestparse/tests/test_reanchor.py` |
| A3 | ~~4. invariant: zmena binov rozsahu textu jadra~~ HOTOVÉ 2026-10-05 (SHA-256 strán textu proti baseline z čistej snímky) | `guestparse/checks.py:text_integrity`, podpríkaz `textbaseline` |
| A4 | ~~mapovanie bin → proces cez page tables hosťa~~ HOTOVÉ 2026-10-05 (zostup tabuľkami z `mm->pgd`; VMA zoznam v BTF tohto jadra nie je) | `guestparse/procmap.py`, podpríkaz `procmap` |
| A5 | ~~`hold` marker v retencii~~ HOTOVÉ 2026-10-05 (subor HOLD, chain_id aj meno suboru) | `vmicollect/src/retention.c`, podpríkaz `hold` |
| A6 | ~~`alarm.json` + alarmový hook~~ HOTOVÉ 2026-10-05 (api->alarm, alarm.json + alarms.jsonl, HOLD reťazca, vmic_hook_alarm) | `vmicollect/src/hooks.c`, `src/meta.c:vmic_alarm_write` |
| A7 | voliteľná libvirt reakcia s meranou latenciou | `vmicollect/src/backend.c:102-133` (`vmic_backend_pause/resume`), prázdne ops `backend_ebpf.c:1167-1168` |
| A8 | dlhý beh (hodiny) + persistovaná evidencia zmeškaných slotov | `vmicollect/src/sched.c:110-134`, `vmicollect/include/vmic.h:413-418`, `scripts/root_run.sh run` |
| B1 | golden image definícia v repe | `/home/eh/vms/` (cloud-init.iso, debian-12-base.qcow2), `scripts/get_profile.sh` |
| B2 | overlay qcow2 + `virsh snapshot-revert` pred sedením | overlay/backing na disku; `scripts/root_run.sh` |
| B3 | izolovaná libvirt sieť bez NAT | — |
| B4 | `root_run.sh session <manifest>`: revert→štart→zber→injekcia→beh→ground truth→stop→zahoď overlay→manifest+tcpdump | `root_run.sh probe/validate/once/run`, `guest_exec.sh`, `stamp_results.py` |
| B5 | identický priebeh benígnych aj škodlivých sedení | návrh manifestu sedenia |
| C | benígne záťaže (idle/nginx+wrk/pgbench/build/rsync+tar/mix) | `guest_exec.sh` |
| D | ~~per-bin okná `(N,L,B*4+22)`~~ HOTOVÉ 2026-10-05 (voliteľný tvar popri `(N,L,22)` + loader z C sidecaru) | `features/windows.py:okna_s_perbin`, `features/tests/test_windows_perbin.py` |
| E1 | regresná hlava TCN (predikcia vektora v t+1, MSE, bez štítkov) | `tcn/model.py`, `tcn/train.py:197-245`, testy kauzality |
| E2 | skóre anomálie = chyba predikcie, per-bin lokalizácia | `tcn/score.py:103-216`, `features/perbin.py` |
| E3 | `tcn/kalibracia.py` (kvantil, rozpočet FP, k-z-n okien) | `tcn/eval.py`, `features/normalize.py` |
| E4 | klasifikátor aktivít = dnešná TCN (treba korpus + labely) | `tcn/train.py`, `tcn/baselines.py`, `tcn/eval.py` |
| F | anomálne baseliny (z-score, Isolation Forest, GRU prediktor) do jednej tabuľky s TCN | `tcn/baselines.py:43-86`, `tcn/eval.py` |
| G1 | PoC techniky (ground truth, len test/validácia) | `guest_exec.sh`, `data/sessions/` (vzor ground truth) |
| G2 | MalwareBazaar (API, filter ELF x86-64, manifest; len hashe do repa) | — |
| G3 | označenie behu aktívny/neaktívny z nezávislého pozorovania | `guest_exec.sh` |
| H | FAR/h, time-to-detection per technika/rodina, konfunder, A/B/A vplyv, soft real-time dôkaz | `tcn/eval.py:49-88`, `scripts/measure_latency.sh`, `data/results/optim_hash_20260918.json` |

## Nález: dokázať sa dnes nedá

1. **eBPF do jadra 7.2.5** — treba `sudo scripts/root_run.sh probe` (heslo má používateľ).
2. **Vzorová validačná relácia `20260918T154914Z_validate`** — jej snímka je z bootu 18. 9.,
   jediný profil v repe je z 19. 9. → každý príkaz dnes skončí exit 5 (`NESULAD PROFILU`).
   Je to zároveň najlepší dôkaz, že A2 treba.
3. **`check_claims.sh = 0`** — blokuje ho 37 citácií hypTcn002 v `docs/notebookLM.md`
   (treba vyčistiť alebo zdôvodnene vyňať).

## Zoznam GitHub issues

Jeden issue na blok (A1–A8, B1–B5, C, D, E1–E4, F, G1–G3, H) je pripravený
v [docs/ISSUES.md](ISSUES.md) — každý s odkazom na existujúci kód, z ktorého stavať.
