# Stav repozitára voči zadaniu

Stav k 2026-10-29 nad commitom `39a6bdf` (záznam dokončenej kampane `benign-v6-20261026`)
a upratovacími commitmi z toho istého dňa (kap. 5).
Nie je to meranie. Riadky odkazujú na kód, testy a artefakty v `data/results/`; merania
a rozhodnutia vlastní [`MERANIA.md`](MERANIA.md), aktuálny pilot a pripravenosť kampane
[`PRIPRAVENOST_KAMPANE.sk.md`](PRIPRAVENOST_KAMPANE.sk.md). Dokument nahrádza audit a návrhy
issues z 2026-10-05, posudok zadania a vysvetľujúci dokument z 2026-09-19. Cesty súborov
odstránených 2026-10-29 vypíše `git diff --name-only --diff-filter=D 01c2088 HEAD`, ich znenie
`git show 01c2088:<cesta>` (napr. `git show 01c2088:docs/AUDIT.md`).

## 1. Zadanie → repozitár

Požiadavky sú citované zo zadania [`zadanie-zp_105826.pdf`](../zadanie-zp_105826.pdf) (cieľ,
jadro a charakter práce). **Overené na VM** znamená uložený výstup behu nad bežiacou VM,
**overené testami** iba jednotkové alebo syntetické testy, **neoverené** kód bez behu a
**chýba** kód, ktorý v repe nie je. Behy na VM pochádzajú z kódu spred 2026-10-29; merací kód
sa v ten deň nezmenil (kap. 5).

| | požiadavka | čo v repe zodpovedá | dôkaz | stav |
|---|---|---|---|---|
| R1 | „hypervisor modul postavený na open-source hypervízore (QEMU/KVM, Xen alebo BareFlank)“ | `vmicollect/`: eBPF nad KVM (`vmicollect/bpf/vmic_kvm.bpf.c`) a zberač v používateľskom priestore hostiteľa, od verzie 1.1 so zápisom vo vlákne `vmic-writer` (`vmicollect/src/output.c`); iba KVM, QEMU ani KVM sa neupravujú | `data/results/probe_20261005T154929Z.json` (vývojový hostiteľ), `data/results/collection_pilot_7_20261026_audit.json` (zberové PC, zberač 1.1) | overené na VM |
| R2 | „schopný vykonávať real-time introspekciu RAM virtuálnych strojov“ | pevná perióda bez pozastavenia VM (`vmicollect/src/sched.c`; `interval_s` v `config/collection-v2.json`); `scripts/measure_latency.sh`; časy `extraction_ms`, `processing_ms` a `snapshot_age_ms` v udalostiach (`safeguard/runtime.py`) | pilot 7: delta cyklus p50 850,4 {{res:collection_pilot_7_20261026_timing.json:values.delta_total_ms.p50}} ms, najdlhší cyklus 1881,1 {{res:collection_pilot_7_20261026_timing.json:values.cycle_total_ms_max}} ms pri perióde 5 s; snímka → per-bin vektor: `data/results/latency_vector_20260918.json` (zberač 1.0); snímka → skóre počas zberu: artefakt nie je | overené na VM (perióda, cyklus, snímka → vektor); neoverené (snímka → skóre) |
| R3 | „generovať per-bin feature vektory pripravené na analýzu pomocou TCN“ | blok `features` v sidecari (`vmicollect/src/perbin.c`), nezávislá referencia `features/perbin.py` a `features/crosscheck.py`; per-bin okná v `safeguard/features.py`, zdieľaná per-bin TCN v `safeguard/model.py` | `data/results/perbin_crosscheck_20260918.json`, `data/results/crosscheck_110017Z_20261005.json`; `vmicollect/tests/perbin_test.c`, `features/tests/test_perbin.py`, `safeguard/tests/test_training.py` | overené na VM (vektor, zhoda C a Pythonu); overené testami (vstup TCN) |
| R4 | „komponenty pre pripojenie k hypervizoru“ | `vmicollect/src/backend_ebpf.c` (`scan_vms`, `pick_vm`, offsety z BTF, memsloty, `eb_begin_cycle` pri novom procese QEMU); `scripts/root_run.sh probe`, `scripts/a1_restart_test.sh` | `data/results/a1_vyber_vm_20261005.json` (dve domény), `data/results/a1_restart_20261005T204555Z.json` (reštart VM počas behu) | overené na VM |
| R5 | „periodický zber pamäťových snímok“ | `vmicollect/src/sched.c`, `vmicollect/src/writer_delta.c` (reťazec `.vmicd`), `vmicollect/src/output.c` (fronta a vlákno `vmic-writer`), `vmicollect/src/retention.c` (HOLD); `scripts/collection.py`, `scripts/campaign.py` | pilot 7: 480 {{res:collection_pilot_7_20261026_timing.json:values.collector_end.snapshots}} snímok, 0 {{res:collection_pilot_7_20261026_timing.json:values.collector_end.missed_slots}} zmeškaných slotov; kampaň v5 (zberač 1.1): 17 {{res:collection_campaign_benign_v5_20261025.json:values.final_status.accepted_archived}} prijatých hodinových session, 0 {{res:collection_campaign_benign_v5_20261025.json:values.summary.accepted_missed_slots}} zmeškaných slotov; kampaň `benign-v6-20261026`: 48 {{res:collection_campaign_benign_v6_20261026.json:values.summary.accepted_sessions}} prijatých hodinových session, 0 {{res:collection_campaign_benign_v6_20261026.json:values.summary.accepted_missed_slots}} zmeškaných slotov; selftest a `vmicollect/tests/retention_test.c` | overené na VM (session 720 cyklov po 5 s); neoverené (súvislý beh dlhší ako jedna session, retencia počas zberu) |
| R6 | „parsovanie pamäťových štruktúr“ | `guestparse/` (profil z kallsyms a BTF, preklad adries, prechod zoznamov jadra s pravidlami `prev` a `tail` pre roztrhnutý zoznam procesov, preukotvenie po KASLR); `profiles/debian12-6.1.0-42-cloud-amd64/` | `data/results/2026-09-18_zmrazeny_host/validate2.json`, `data/results/boot_anchor_validation_20261013_a.json`, `data/results/collection_process_walk_insert_20261026_reaudit.json`; `guestparse/tests/` | overené na VM (jediné jadro hosťa `6.1.0-42-cloud-amd64`) |
| R7 | „extrakciu príznakov z RAM vrátane procesných informácií“ | procesy z `init_task.tasks` (`guestparse/view.py`), bin → proces (`guestparse/procmap.py`), `proc_*` vo `features/snapshot.py`; 18 vstupov modelu (`BEHAVIOR_NAMES` vo `features/archive.py`) | `data/results/2026-09-18_zmrazeny_host/validate2.json`: 81 {{res:2026-09-18_zmrazeny_host/validate2.json:processes.found}} nájdených, 0 {{res:2026-09-18_zmrazeny_host/validate2.json:processes.missing}} chýba; `features/tests/test_snapshot.py`, `guestparse/tests/test_procmap.py` | overené na VM |
| R8 | „analýzy načítaných modulov“ | zoznam `modules` (`guestparse/view.py`), `module_checks` proti `module_kset` (`guestparse/checks.py`); `mod_total`, `mod_delta` | `data/results/2026-09-18_zmrazeny_host/validate2.json`: 51 {{res:2026-09-18_zmrazeny_host/validate2.json:modules.matched}} zhodných, 0 {{res:2026-09-18_zmrazeny_host/validate2.json:modules.missing}} chýba; `guestparse/tests/test_checks.py` | overené na VM; skrytý modul v hosťovi neoverený |
| R9 | „monitorovania sieťových spojení“ | `sockets` v `guestparse/view.py` (TCP, UDP, RAW; IPv4 aj IPv6); `sock_total`, `sock_listen`, `sock_estab` | `data/results/2026-09-18_zmrazeny_host/validate2.json`: 10 {{res:2026-09-18_zmrazeny_host/validate2.json:sockets.matched}} zhodných, 2 {{res:2026-09-18_zmrazeny_host/validate2.json:sockets.extra}} navyše (vysvetlenie v [`MERANIA.md`](MERANIA.md), 2026-09-18) | overené na VM (pozemná pravda iba z `hyptcn-guest`) |
| R10 | „detekcie podozrivých vzorcov v pamäti“ | `guestparse/checks.py`: `syscall_table`, `process_cross_view`, `module_checks`, `text_integrity`; potvrdenie krížového rozdielu susednou snímkou (`potvrd_krizove` vo `features/snapshot.py`); alarm integrity nezávislý od modelu (`safeguard/runtime.py`) | bez nálezu na benígnych dátach: `data/results/checks_20260918_val.json`, pilot 7: 0 {{res:collection_pilot_7_20261026_audit.json:values.quality.integrity_findings}} nálezov; nález iba po zápise do kópie snímky: `data/results/a3_pozitivny_20261005.json`, `guestparse/tests/test_injection.py` | overené na VM (bez nálezu); overené testami (nález); technika v hosťovi neoverená |
| R11 | „štatistických charakteristík pamäťových oblastí“ | `changed_ratio`, `zero_ratio`, `entropy_mean`, `has_changed` na bin 16 MiB (`vmicollect/src/perbin.c`, kontrakt `features/PERBIN.md`); agregáty `mem_*` vo `features/snapshot.py` | `data/results/perbin_crosscheck_20260918.json`, `data/results/perbin_c_20260918/perbin_c_20260918.json`; `vmicollect/tests/perbin_test.c` | overené na VM |
| R12 | „mechanizmus pre generovanie sekvenčných feature vektorov s normalizáciou dát“ | okná `WindowBuffer` a normalizácia `FeatureNormalizer` (fit iba na role `train`) v `safeguard/features.py`; `safeguard/training.py`; archív príznakov `features/archive.py`, index korpusu `features/dataset.py` | okná z reálnych dát: pilot 7, 416 {{res:collection_pilot_7_20261026_audit.json:values.windows}} skórovateľných okien; normalizácia: `safeguard/tests/test_features.py`, `safeguard/tests/test_training.py` | overené na VM (okná); overené testami (normalizácia, na korpuse `benign-v6-20261026` zatiaľ nefitovaná) |
| R13 | „základná implementácia alebo integrácia TCN modelu pre detekciu anomálií a klasifikáciu aktivít“ | `tcn/model.py` (`TCN`, `TCNPrediktor`); `safeguard/model.py` (`Predictor`: globálna a per-bin TCN, `Classifier`: profil záťaže); `python3 -m safeguard train` (`safeguard/training.py`: výber na `dev`, prah z kvantilu na `calibration`, pravidlo k z n); `Detector` v `safeguard/runtime.py` | `tcn/tests/test_tcn.py` (kauzalita, receptívne pole), `safeguard/tests/test_training.py`, `safeguard/tests/test_integration.py` (syntetický `smoke`) | overené testami; korpus `benign-v6-20261026` je nazbieraný, model z neho chýba |
| R14 | „optimalizovaný z hľadiska výkonu a minimalizácie vplyvu na bežiace virtuálne stroje“ | zápis iba zmenených stránok (`vmicollect/src/writer_delta.c`), SHA-256 so SHA-NI (`vmicollect/src/sha256.c`), čítanie bez pozastavenia VM; od zberača 1.1 súbory, SHA-256 a sidecar vo vlákne `vmic-writer` mimo vzorkovacieho cyklu, uzamknutá fronta (`output.mlock`) a zápis bez `fsync` (`COLLECTOR_FSYNC` v `scripts/collection.py`); časová os hostiteľa `scripts/host_monitor.py` | `data/results/optim_hash_20260918.json` (cyklus so SHA-256 a bez neho), `data/results/collection_io_interference_20261021.json` (zmeraný dopad spätného zápisu na VM), `data/results/collection_writer_diagnostic_20261025_timing.json` (zberač 1.1 pri umelej záťaži SSD) | overené na VM (čas cyklu); neoverené (vplyv na VM párovaným meraním) |
| R15a | „s vyhodnotením presnosti detekcie malvérových vzorcov“ | stavebné bloky bez behu techniky alebo vzorky: `scripts/poc/`, `scripts/mb_fetch.py`, `scripts/aktivita.sh`, `harness/net_isolated.xml`, `harness/net_isolated.sh`, starší harness sedení `scripts/session.sh`; klasifikačné metriky `vyhodnot` v `tcn/eval.py` | v `data/results/` nie je beh techniky ani vzorky; `data/sessions/*/manifest.json` majú iba `"typ": "benign"` | chýba (aj vyhodnocovač FAR/h a oneskorenia detekcie) |
| R15b | „výkonnostných náročností“ | `scripts/measure_latency.sh`, `scripts/host_monitor.py`, `scripts/campaign_report.py`; časy v sidecari (`capture.backend_read_ms`, `capture.queue_wait_ms`, `output.data_closed_ms`) | `data/results/latency_vector_20260918.json`, `data/results/collection_pilot_7_20261026_timing.json`, `data/results/collection_full_snapshot_growth_20261022.json` | overené na VM (cyklus, snímka → vektor, rast plnej snímky); neoverené (súhrnné CPU a RAM zberača a detektora, snímka → skóre, iné periódy ako 5 s a 2 s) |
| R15c | „použiteľnosti v reálnych scenároch“ | serverové laboratórium `lab/` (nginx, služby auth, catalog a orders, PostgreSQL), `scripts/labctl.py`, `scripts/host_traffic.py`, `scripts/campaign.py`, protokol `config/collection-v2.json` | prijaté audity pilotov 3 až 7 (posledný `data/results/collection_pilot_7_20261026_audit.json`); kampane v2 až v5 uzavreté s 2 {{res:collection_campaign_benign_v2_20261022.json:values.final_status.accepted_archived}}, 2 {{res:collection_campaign_benign_v3_20261022.json:values.final_status.accepted_archived}}, 36 {{res:collection_campaign_benign_v4_20261022.json:values.final_status.accepted_archived}} a 17 {{res:collection_campaign_benign_v5_20261025.json:values.final_status.accepted_archived}} prijatými session zo 48 {{res:collection_campaign_benign_v5_20261025.json:values.planned_sessions}}, žiadna s indexom korpusu; kampaň `benign-v6-20261026` z pilota 7 prijala 48 {{res:collection_campaign_benign_v6_20261026.json:values.final_status.accepted_archived}} zo 48 {{res:collection_campaign_benign_v6_20261026.json:values.planned_sessions}} session s indexom korpusu (`data/results/collection_campaign_benign_v6_20261026.json`) | overené na VM (benígny zber, offline audit); neoverené (detektor v tomto prostredí) |
| R16 | „API rozhranie“ | C API a hook ABI 2 (`vmicollect/include/vmic.h`: `api->alarm()`, voliteľný `vmic_hook_alarm`), pluginy `vmicollect/hooks/`; CLI s JSON výstupom (`vmicollect`, `python3 -m guestparse … --json`, `python3 -m safeguard`); Python `guestparse.build_view` | `vmicollect/tests/alarm_test.c` (alarm, HOLD, `react_hook` v režime `dry`); JSON z behov na VM: `data/results/probe_*.json`, `data/results/2026-09-18_zmrazeny_host/validate2.json` | overené testami (hook, alarm); overené na VM (CLI, JSON); sieťové API nie je |
| R17 | „testovanie (funkčné, výkonnostné, validácia detekcie)“ | `make -C vmicollect test`, `python3 -m pytest -q`, `scripts/check_claims.sh`, `scripts/check_prirucka.sh`; audity `scripts/collection.py audit` a `scripts/collection_logs.py` | výsledky testov v kap. 4; funkčné a výkonnostné behy na VM: R1 až R15c | overené testami (funkčné); výkonnostné čiastočne (R15b); validácia detekcie chýba (R15a) |

Teoretickú časť zadania (typy virtualizácie, princípy VMI, TCN a porovnanie s LSTM/GRU)
obsahuje text práce. Adresár `thesis/` v repe nie je.

## 2. Čo je otvorené

Body na seba nadväzujú: bez tréningu a vyhodnocovača nie je výsledok detekcie.

1. **Tréning safeguardu na korpuse `benign-v6-20261026`.** Kampaň z pilota 7
   (`20261026T155027013358Z_pilot_bursty`, commit `9762e55`) prijala a archivovala všetkých
   48 plánovaných session ([záznam](../data/results/collection_campaign_benign_v6_20261026.json),
   [`MERANIA.md`](MERANIA.md) 2026-10-29); index `corpus.json` a archívy snímok sú na zberovom
   PC. `python3 -m safeguard train` je otestovaný iba synteticky, balík modelov z reálnych dát
   nie je. `Classifier` sa trénoval iba v syntetickom `smoke` (triedy `quiet` a `steady`,
   `safeguard/demo.py`); presnosť na reálnom korpuse nie je zmeraná. `validate_index` v
   `safeguard/training.py` prijme iba korpus s jednou implementáciou extrakcie zhodnou s dnešnými
   súbormi `*.py` mimo testov vo `features/` a `guestparse/`, preto sa do tréningu nemenia (kap. 5).
2. **Vyhodnocovač detekcie nad udalosťami safeguardu.** Metriky z
   [`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md), kap. 7 (alarmové udalosti, FAR za hodinu
   benígnej prevádzky, podiel detegovaných aktivovaných incidentov, oneskorenie od
   aktivácie, výpadky senzora) nepočíta žiadny kód. `calibrate` v `safeguard/training.py`
   dáva iba frekvenciu udalostí na role `calibration`, nie FAR na `test_benign`. Staršie
   funkcie `far_h`, `cas_do_detekcie` a `detekcia_per_technika` (blok H) počítali okná
   staršej cesty s porovnaním `>=`, nie udalosti; `709ee7f` ich odstránil. Samostatný test
   falošných alarmov pri zálohách, reštartoch služieb a údržbe (metodika, kap. 5) neprebehol.
3. **Etapa útokov.** Stavebné bloky (R15a) nemajú runner podľa metodiky (kap. 7: oddelené
   izolované prostredie s rovnakým serverovým stackom). Starší harness sedení nad
   `hyptcn-guest` (`scripts/session.sh`, manifesty `harness/session_manifest_g1_*.json`)
   ostáva ako historický. V hosťovi nebežala žiadna technika ani vzorka.
4. **Vplyv na VM a hostiteľa.** Párované merania bez introspekcie, so zberačom a s celým
   detektorom (metodika, kap. 7, „Výkonnosť“) neexistujú. `scripts/host_monitor.py`
   zapisuje `cpu_pct` a `rss_kb` procesov zberača, súhrnný artefakt nie je. Bez neho sa
   „minimálny vplyv“ tvrdiť nesmie ([`HONESTY.md`](../HONESTY.md), P7).
5. **Živý `safeguard run`.** Spoločný beh zberača s detektorom (`safeguard/supervisor.py`)
   na VM nebežal. Preto nie je ani živá latencia snímka → skóre.
6. **Baseliny a LSTM.** `tcn/baselines.py` (LogReg, bag-of-frames, GRU, z-score, Isolation
   Forest, GRU prediktor) volá iba diagnostický `tcn/train.py` nad 22-stĺpcovými oknami
   `(N, L, F)`, nie nad globálnym a per-bin vstupom safeguardu. Porovnanie TCN s baselinami
   nad rovnakými rolami a vstupmi (metodika, kap. 7, „Porovnania“) nie je. LSTM v kóde nie
   je, iba GRU; porovnanie s LSTM/GRU zadanie spomína v teoretickej časti.
7. **Integrita textu jadra na zberovom PC.** V pilote 7 je `text_integrity` neuzavretá
   v 480 {{res:collection_pilot_7_20261026_audit.json:values.text_integrity_inconclusive_rows}}
   riadkoch, teda vo všetkých; rozhodujú tri ostatné kontroly.
8. **Bloky A7 a A8.** Beh so zapnutou reakciou `react_hook` (`vmicollect/hooks/react_hook.c`)
   na VM nie je, iba `dry` v `alarm_test`. Artefakt súvislého behu dlhšieho ako jedna
   session (720 cyklov po 5 s) v `data/results/` nie je.

## 3. Legenda blokov

Označenia pochádzajú z plánu z 2026-10-05. Používajú ich komentáre v kóde a
[`LIMITACIE.md`](LIMITACIE.md). Posledný stĺpec opisuje `main` pri `709ee7f`.

| blok | čo bolo | commit | na `main` |
|---|---|---|---|
| A1 | výber domény menom pri viacerých VM, znovupripojenie po reštarte hosťa | `0683775`, `9ec44db` | existuje: `pick_vm`, `eb_begin_cycle` vo `vmicollect/src/backend_ebpf.c`, `scripts/a1_restart_test.sh` |
| A2 | preukotvenie profilu po posune KASLR namiesto kódu 5 | `61a8980` | existuje: `GuestView.reanchor` v `guestparse/view.py` |
| A3 | 4. invariant: integrita textu jadra proti baseline | `7134058`, `689c384`, `9ec44db` | existuje: `text_integrity` v `guestparse/checks.py`, podpríkaz `textbaseline`, `scripts/get_vmlinux.sh`; zvyšok rozdielu medzi bootmi opisuje L18 |
| A4 | bin → proces cez tabuľky stránok z `mm->pgd` | `88608d7`, `66ec043` | existuje: `guestparse/procmap.py`, podpríkaz `procmap` |
| A5 | marker HOLD v retencii | `580fc58` | existuje: `vmicollect/src/retention.c`, príkaz `vmicollect hold` |
| A6 | alarmové rozhranie: `api->alarm()`, `alarm.json`, `alarms.jsonl`, `vmic_hook_alarm` | `b431013` | existuje: `vmicollect/include/vmic.h` (ABI 2), `vmicollect/hooks/alarm_hook.c`, `vmicollect/tests/alarm_test.c` |
| A7 | voliteľná reakcia cez libvirt, predvolene vypnutá, s latenciou alarm → reakcia | `582a1b7` | existuje: `vmicollect/hooks/react_hook.c` |
| A8 | štatistiky plánovača v každom sidecari | `170f385` | existuje: `sched.lateness_s`, `sched.skipped_before` (`vmicollect/src/meta.c`) |
| B1 | definícia zlatého obrazu v repe | `550a686`, `32f8060`, `f00ca67` | existuje: `harness/cloud-init/`, `harness/make_golden.sh`, `harness/hyptcn-guest.xml`, `harness/golden.manifest.json` |
| B2 | overlay a `virsh snapshot-revert hyptcn-clean` pred sedením | `d7801bf`, `fac54be` | revert robí `scripts/session.sh` (historický harness); snapshot `hyptcn-clean` je mimo repa |
| B3 | izolovaná sieť `hyptcn-iso` bez NAT | `550a686` | existuje: `harness/net_isolated.xml`, `harness/net_isolated.sh`; žiadne zaznamenané meranie ju nepoužilo |
| B4 | `scripts/root_run.sh session <manifest>` (`scripts/session.sh`) | `d7801bf`, `915ba38` | existuje ako historický harness nad `hyptcn-guest`; s manifestom dokončil iba štyri sedenia `idle` z 2026-10-05 a 2026-10-06 (`data/sessions/*_idle_benign/manifest.json`) |
| B5 | rovnaký priebeh benígnych a škodlivých sedení, `scripts/session_batch.sh`, `scripts/root_run.sh batch`, manifesty G1 | `d7801bf`, `69c4bf5` | existuje ako historický harness; benígny zber dnes riadi `scripts/campaign.py` nad `hyptcn-lab` |
| C | benígne záťaže `scripts/loads/` (idle, nginx_wrk, pgbench, build, rsync_tar, mix) | `7e8f35f` | existuje, používa ju iba starší harness; profily záťaže labu sú v `config/collection-v2.json` a `scripts/host_traffic.py` |
| D | per-bin okná `okna_s_perbin()` vo `features/windows.py` | `2da4651` | existuje; safeguard skladá per-bin okná sám v `safeguard/features.py` |
| E1 | regresná hlava TCN (prediktor normálu) | `63fee0c` | `TCNPrediktor` v `tcn/model.py` používa `safeguard/model.py`; tréner `tcn/train.py` ostáva ako diagnostický |
| E2 | skóre anomálie ako chyba predikcie (`tcn/score.py`) | `63fee0c` | existuje ako diagnostické (volá ho `scripts/detektor.py`); skóre safeguardu je `anomaly_score` v `safeguard/model.py` |
| E3 | kalibrácia prahu (`tcn/kalibracia.py`) | `63fee0c` | odstránené v `709ee7f`; kalibrácia safeguardu je `calibrate` v `safeguard/training.py` |
| E4 | klasifikátor aktivít; v pláne z 2026-10-05 otvorený | `733c5a7` | `Classifier` v `safeguard/model.py`, trénovaný iba synteticky |
| F | anomálne baseliny (z-score, Isolation Forest, GRU prediktor) | `b289add` | `tcn/baselines.py`, volá ho iba diagnostický `tcn/train.py` |
| G1 | PoC techniky na validáciu citlivosti, nikdy na tréning | `2829eb7`, `1236c3f` | existujú `scripts/poc/` a manifesty `harness/session_manifest_g1_*.json`, v hosťovi nikdy nebežali; simulácia v kópii snímky: `data/results/g1_citlivost_sim_20261005.json` |
| G2 | sťahovanie vzoriek z MalwareBazaar, do repa iba hashe | `c7d5c75` | existuje: `scripts/mb_fetch.py`; vzorový beh nie je |
| G3 | označenie behu aktívny/neaktívny z pozemnej pravdy | `c7d5c75` | existuje: `scripts/aktivita.sh`; vstupy mu dáva `scripts/session.sh` |
| H | vyhodnotenie: FAR/h, čas do detekcie, konfunder, kontrola periódy, detektor k z n | `43405ce`, `a5a6eb9`, `cd5c183`, `252582e`, `3e7b2b9` | existujú `scripts/soft_rt_check.py`, `scripts/detektor.py`, `beh_konfunder` v `tcn/train.py` a artefakt `data/results/konfunder_5sess_20261008.json`; `tcn/hodnotenie.py` a funkcie FAR/h, času do detekcie a detekcie po technikách v `tcn/eval.py` odstránil `709ee7f` |

## 4. Prostredia

| | vývojový hostiteľ | zberové PC |
|---|---|---|
| zdroj | príkazy spustené 2026-10-29 | hlavička `data/results/collection_pilot_7_20261026_audit.json` (2026-10-26) |
| systém | Fedora Linux 43, jadro `7.2.5-100.fc43.x86_64`; BTF v `/sys/kernel/btf/vmlinux` a `/sys/kernel/btf/kvm` | `Linux-7.2.9+deb13-amd64-x86_64-with-glibc2.41` (pole `host`) |
| procesor | Intel Core i7-12650H, 16 logických CPU, príznak `sha_ni` v `/proc/cpuinfo` | artefakt neuvádza; [`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md) uvádza i5-8400 bez SHA-NI |
| nástroje | clang 21.1.8, gcc 15.3.1, bpftool v7.6.0 s libbpf v1.6, QEMU 10.1.5, libvirt 11.6.0 | artefakt neuvádza |
| Python | 3.14.7; numpy 2.3.5, scikit-learn 1.8.0, torch 2.11.0+cu130, pytest 8.3.5 (`requirements.txt`) | artefakt neuvádza; príkazy sa spúšťajú z `.venv` ([`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md)) |
| práva | `sudo` vyžaduje heslo, `kernel.unprivileged_bpf_disabled` je 2: BPF a živý zber spúšťa iba používateľ | — |
| VM | domény `hyptcn-guest` a `hyptcn-lab` v `qemu:///session`, snapshot `hyptcn-clean` domény `hyptcn-guest`, sieť `hyptcn-iso` definovaná a neaktívna | `hyptcn-lab`, jadro hosťa `6.1.0-42-cloud-amd64`, nginx `1.22.1-9+deb12u10`, PostgreSQL `15+248+deb12u1` (pole `guest`); zberač 1.1 z commitu `9762e55` |
| testy pri `709ee7f` | `make -C vmicollect test` (selftest, `hole_test`, `perbin_test`, `retention_test`, `alarm_test`) prešiel; `python3 -m pytest -q`: 684 prešlo, 24 preskočených (23 z nich čaká na snímky mimo gitu: `GUESTPARSE_VAL`, `GUESTPARSE_DELTA`, `FEATURES_DELTA`) | nespustené |

## 5. Upratanie 2026-10-29

Commit `709ee7f` odstránil `tcn/hodnotenie.py`, `tcn/kalibracia.py` a funkcie `far_h`,
`cas_do_detekcie` a `detekcia_per_technika` z `tcn/eval.py`; žiadna z nich nevyrobila
artefakt. Commit `5df1f3d` odstránil duplicitné pomocné funkcie reportu kampane a kontroly
tvrdení, výstupy sa nezmenili. Úprava dokumentácie z toho istého dňa odstránila
`docs/AUDIT.md`, `docs/ISSUES.md`, posudok zadania a vysvetľujúci dokument z 2026-09-19 (aj
jeho PDF). Merací kód, teda 116 súborov, ktoré `is_measurement` v `scripts/collection.py`
počíta do `measurement_sha256` session, je bajtovo zhodný s commitom kampane `benign-v6-20261026` (`01c2088`) aj pilota 7
(`9762e55`); audity korpusu tejto kampane preto `safeguard train` prijme a
`measurement_changes` v `scripts/campaign.py` nový pilot nežiada. Bajtovo zhodný ostal aj profil jadra hosťa
(`profiles/debian12-6.1.0-42-cloud-amd64/`, hash `profile_sha256` overuje `pilot_gate`
aj `safeguard train`, takže sa nemení ani jeho `README.md`) a protokol
`config/collection-v2.json`. Staršia 22-stĺpcová cesta (`tcn/train.py`,
`tcn/score.py`, `features/normalize.py`, `features/manifest.py`, `features/stream.py`,
`scripts/detektor.py`, `scripts/soft_rt_check.py`) a harness sedení nad `hyptcn-guest`
(`scripts/session.sh`, `scripts/session_batch.sh`, `scripts/loads/`) ostávajú do konca
experimentov ako diagnostické a historické. Ich úplné odstránenie je pripravené na lokálnej
vetve `upratanie-meracieho-kodu` nad starším základom `49db41c`. Mení merací kód aj extraktor
(`features/`, `guestparse/`), takže po zlúčení by `safeguard train` audity korpusu
`benign-v6-20261026` odmietol a ďalšia kampaň by potrebovala nový pilot; zlúčiť ju má zmysel
až po tréningu a vyhodnotení nad týmto korpusom. Artefakty odstráneného kódu v `data/` ostávajú
([`HONESTY.md`](../HONESTY.md), P10).
