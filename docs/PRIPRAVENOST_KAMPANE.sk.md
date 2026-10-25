# Pripravenosť benígnej kampane

Stav k 2026-10-25 (UTC) po uzavretí kampaní `benign-v2-20261022`,
`benign-v3-20261022` a `benign-v4-20261022`, po prijatí pilota 6 a pred `campaign.py init`
kampane `benign-v5`. Dokument nie je meranie;
odkazuje na uložené výsledky v `data/results/` a na záznamy v
[MERANIA.md](MERANIA.md). Prevádzka kampane je v
[AUTOMATICKY_ZBER.sk.md](AUTOMATICKY_ZBER.sk.md), laboratórium v
[LAB.sk.md](LAB.sk.md).

- **PASS**: overené na zberovom PC, dôkaz je uložený.
- **FAIL**: overenie zlyhalo; uvedené je, čo sa zmenilo a čím sa to overilo.
- **UNVERIFIED**: implementované a pokryté syntetickými testami, živé
  overenie chýba alebo príde až počas kampane.

Rozhodujúci je pilot 3 `20261022T003017919708Z_pilot_bursty` (skupina
`pilot-3-20261021`, commit `c15cda4`, profil `bursty`):
[audit](../data/results/collection_pilot_3_20261021_audit.json),
[súhrn časovania](../data/results/collection_pilot_3_20261021_timing.json).
Audit ho prijal s
416 {{res:collection_pilot_3_20261021_audit.json:values.windows}}
oknami z
480 {{res:collection_pilot_3_20261021_audit.json:values.snapshots}}
snímok. Kampaň `benign-v2-20261022` z neho vyšla, prijala dve session a po
zamietnutí tretej sa uzavrela
([záznam](../data/results/collection_campaign_benign_v2_20261022.json),
[MERANIA.md](MERANIA.md)). Commit `8498670` zmenil merací kód (potvrdenie
krížového rozdielu), preto ďalšia kampaň vychádza z pilota 4
`20261022T073059077133Z_pilot_bursty` (skupina `pilot-4-20261022`, commit
`d25c027`): [audit](../data/results/collection_pilot_4_20261022_audit.json),
[súhrn časovania](../data/results/collection_pilot_4_20261022_timing.json).
Audit ho prijal s
416 {{res:collection_pilot_4_20261022_audit.json:values.windows}}
oknami,
0 {{res:collection_pilot_4_20261022_audit.json:values.quality.integrity_findings}}
nálezmi a plnými snímkami
2421.2 {{res:collection_pilot_4_20261022_timing.json:values.full_snapshots.seq_360.cycle_ms}}
ms pri
902.42 {{res:collection_pilot_4_20261022_timing.json:values.full_snapshots.seq_360.mib}}
MiB. Kampaň `benign-v3-20261022` z neho vyšla, prijala dve session a po
zamietnutí tretej sa uzavrela
([záznam](../data/results/collection_campaign_benign_v3_20261022.json),
[MERANIA.md](MERANIA.md)). Commit `0b61ffd` zmenil merací kód (roztrhnutý
zoznam procesov potvrdí prechod dozadu, monitor zapisuje vo vlákne, limit
klienta je 10 s), preto ďalšia kampaň vychádza z pilota 5
`20261022T142659087837Z_pilot_bursty` (skupina `pilot-5-20261022`, commit
`e774c69` s meracím kódom z `0b61ffd`):
[audit](../data/results/collection_pilot_5_20261022_audit.json),
[súhrn časovania](../data/results/collection_pilot_5_20261022_timing.json).
Audit ho prijal s
416 {{res:collection_pilot_5_20261022_audit.json:values.windows}}
oknami,
0 {{res:collection_pilot_5_20261022_audit.json:values.quality.integrity_findings}}
nálezmi a plnými snímkami
2735.9 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.cycle_ms}}
ms pri
271254 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.pages}}
stránkach. Kampaň `benign-v4-20261022` z neho vyšla, prijala
36 {{res:collection_campaign_benign_v4_20261022.json:values.summary.accepted_sessions}}
session a po zamietnutí 37. sa uzavrela
([záznam](../data/results/collection_campaign_benign_v4_20261022.json),
[MERANIA.md](MERANIA.md)). Commit `625d8f9` zmenil zberač (verzia 1.1 robí
prácu so súbormi a s logom mimo vzorkovacieho cyklu), preto ďalšia kampaň
vyžadovala pilot 6. Pilot 6 (commit `cd67470`) audit prijal
([audit](../data/results/collection_pilot_6_20261025_audit.json), [súhrn](../data/results/collection_pilot_6_20261025_timing.json),
[MERANIA.md](MERANIA.md)). Živá
diagnostika zberača 1.1 s umelou záťažou SSD je v
[zázname](../data/results/collection_writer_diagnostic_20261025_timing.json).

## Zber a dôkazy

| Požiadavka | Stav | Dôkaz a poznámka |
|---|---|---|
| Záznam každej požiadavky a 5 s súhrny s fázami | PASS | pilot 3: `traffic_requests.jsonl`, `traffic_intervals.jsonl`; logový audit prijatý |
| Logy servera s request ID a párovanie s generátorom | PASS | pilot 3: nginx JSON, journal služieb, korelácia v logovom audite |
| Časová os hostiteľa (CPU, pamäť, swap, disky, procesy, teploty; 1 s) | PASS, zostatkové riziko | pilot 3: najväčšia medzera vzoriek 1.0 {{res:collection_pilot_3_20261021_timing.json:values.monitor_max_gap_s}} s; kampaň v2: 2.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.monitor_max_gap_s}} s v session 1 a 2.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.monitor_max_gap_s}} s v session 3 počas spätného zápisu plnej snímky; limit auditu je 2,5 s |
| Žiadny zmeškaný slot zberača | PASS so zberačom 1.1 (v kampani v4 FAIL) | pilot 6: 0 {{res:collection_pilot_6_20261025_timing.json:values.collector_end.missed_slots}} zmeškaných slotov, najdlhší cyklus 1579.9 {{res:collection_pilot_6_20261025_timing.json:values.cycle_total_ms_max}} ms ([súhrn](../data/results/collection_pilot_6_20261025_timing.json)); kampaň v4: session 37 zmeškala 1 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.36.scheduler_skips.0.slots}} slot, lebo cyklus zberača 1.0 čakal na spätný zápis SSD ([záznam](../data/results/collection_writeback_stall_20261024.json)); commit `625d8f9` (zberač 1.1) zapisuje súbory, SHA-256 a log vo vláknach mimo cyklu; [diagnostika](../data/results/collection_writer_diagnostic_20261025_timing.json): počas 71.7 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.duration_s}} s umelej záťaže SSD najdlhší cyklus 860.8 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.cycle_total_ms_max}} ms, za celý beh 0 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_end.missed_slots}} zmeškaných slotov |
| Uzamknutá fronta zberača | PASS, diagnostika | zberač 1.1 kopíruje zmenené stránky do fronty v pamäti uzamknutej `mlockall`; [diagnostika](../data/results/collection_writer_diagnostic_20261025_timing.json): VmRSS po uzamknutí 2596 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_mlock.vmrss_mib}} MiB, `Mlocked` hostiteľa najviac 2609 {{res:collection_writer_diagnostic_20261025_timing.json:values.during_capture.mlocked_mib_max}} MiB, čakanie na pamäť fronty najviac 0.0 {{res:collection_writer_diagnostic_20261025_timing.json:values.queue_wait_ms_max}} ms; audit zamietne každé čakanie na pamäť fronty |
| Prvý pilot (swap hostiteľa, disk VM spolu so snímkami) | FAIL, opravené | [záznam](../data/results/collection_io_interference_20261021.json); opatrenia overil pilot 3 |
| Pamäť hosťa nie je odswapovaná pri plnej snímke | PASS, zostatkové riziko | `vm.swappiness = 1`, krok `prefault`; pilot 3: swap QEMU 0 kB na začiatku aj na konci; jadro napriek tomu pamäť QEMU odsúva: v kampani v4 mal proces QEMU na začiatku 16 {{res:collection_campaign_benign_v4_20261022.json:values.summary.qemu_swap_at_start_count}} z 37 {{res:collection_campaign_benign_v4_20261022.json:n}} session (pred krokom `prefault`) časť pamäte vo swape, najviac 101272 {{res:collection_campaign_benign_v4_20261022.json:values.summary.qemu_swap_kb_at_start_max}} kB, a monitor, ktorý beží od zahrievania po zber dôkazov z hosťa, ju v nich nezachytil; zachytil ju iba v session 14, najviac 5744 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.13.qemu_swap_during.kb_max}} kB; diagnostika pri umelej záťaži SSD 2588 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.first_sample_qemu_swap_kb}} kB; podľa `smaps` prečítaného po zbere ležalo všetkých 2580 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.swapped_kb_outside_guest_ram}} kB odsunutej pamäte QEMU mimo mapovania pamäte hosťa (0 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.guest_ram_mapping.swap_kb}} kB, [záznam](../data/results/collection_writer_diagnostic_20261025_qemu_swap.json)); odsunutú stránku hosťa by zberač čítal zo swapu na HDD a dlhý cyklus zistí audit |
| Disk VM oddelený od výstupu snímok | PASS | `vms/hyptcn-lab.qcow2` na HDD; pilot 3: 0 {{res:collection_pilot_3_20261021_timing.json:values.traffic.errors}} chybných požiadaviek |
| Monitor nečaká na `fsync` počas vzorkovania | PASS | test s falošnými hodinami; pilot 3 bez medzery |
| Monitor nečaká ani na zápis riadku | PASS | pilot 5: 0 {{res:collection_pilot_5_20261022_timing.json:values.monitor_missed_ticks}} vynechaných vzoriek; kampaň v3: 2.01 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.monitor_max_gap_s}} s a 2.04 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.monitor_max_gap_s}} s pri spätnom zápise; commit `0b61ffd` zapisuje z fronty vo vlákne, test so zablokovaným zápisom; kampaň v4: najväčšia medzera 1.05 {{res:collection_campaign_benign_v4_20261022.json:values.summary.monitor_max_gap_s}} s, 0 {{res:collection_campaign_benign_v4_20261022.json:values.summary.monitor_missed_ticks}} vynechaných vzoriek |
| Rezerva limitu klienta | PASS | kampaň v3: najpomalšia požiadavka 2348.6 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.measure_latency.max_ms}} ms pri limite 4 s; od commitu `0b61ffd` je limit 10 s; pilot 5: najpomalšia 2003.5 {{res:collection_pilot_5_20261022_timing.json:values.measure_latency.max_ms}} ms; kampaň v4: najpomalšia 2252.5 {{res:collection_campaign_benign_v4_20261022.json:values.summary.measure_latency_max_ms}} ms |
| Rezerva plnej snímky voči perióde 5 s | PASS, zostatkové riziko | kampaň v4: najdlhšia plná snímka 3022.7 {{res:collection_campaign_benign_v4_20261022.json:values.summary.full_ms_max}} ms, najväčšia 323173 {{res:collection_campaign_benign_v4_20261022.json:values.summary.full_pages_max}} stránok; zberač 1.1 v cykle nezapisuje súbory, ale číta pamäť, porovnáva stránky, počíta príznaky a kopíruje zmenené stránky do fronty, diagnostika: 1539.6 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_snapshots.seq_360.total_ms}} ms pri 185293 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_snapshots.seq_360.pages}} stránkach, z toho čítanie pamäte 312.0 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_backend_read_ms.seq_360}} ms; pilot 5: 2735.9 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.cycle_ms}} ms pri 271254 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.pages}} stránkach; kampaň v3: najdlhšia plná snímka 2458.5 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.full_snapshots_ms.1}} ms pri 917.43 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.full_snapshots_mib.1}} MiB; kampaň v2: najdlhšia plná snímka 2168.1 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.full_snapshots_ms.1}} ms pri 735.27 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.full_snapshots_mib.1}} MiB; pilot 3: 1831.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_0.cycle_ms}} ms a 3483.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_360.cycle_ms}} ms (súbežný spätný zápis); po reštarte skupiny ostáva v RAM starý obsah, takže plné snímky v kampani budú väčšie (pilot 1: ~920 MiB). Prekročenie audit zistí a kampaň zastaví |
| Rast stránok pridelených VM | PASS, zostatkové riziko | [záznam](../data/results/collection_full_snapshot_growth_20261022.json): na jednom procese QEMU rástla plná snímka s reštartmi hosťa zo 117993 {{res:collection_full_snapshot_growth_20261022.json:values.by_guest_boot.0.pages_min}} na 271254 {{res:collection_full_snapshot_growth_20261022.json:values.by_guest_boot.5.pages_max}} stránok; pri všetkých stránkach odhad 4355.3 {{res:collection_full_snapshot_growth_20261022.json:values.estimate_all_pages_ms}} ms. Kampaň v4: rast aj v rámci jedného bootu, skupina `train-1` z 129609 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-1.first_full_pages}} na 252248 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-1.last_full_pages}} stránok ([oprava v MERANIA.md](MERANIA.md)). Pred kampaňou nový proces QEMU, počas kampane sa VM nereštartuje; reštarty hosťa na hraniciach skupín zostávajú a vek procesu QEMU je možný zmätočný faktor príznakov (L13 v [LIMITACIE.md](LIMITACIE.md)) |
| Časovače v hosťovi | PASS | identita hosťa `timers:` je prázdna; zmena zastaví kampaň |
| Údržba hostiteľa | PASS | aktualizácie vypnuté; `anacron`, `logrotate`, `dpkg-db-backup`, `systemd-tmpfiles-clean` a `e2scrub_all` zostávajú, monitor ich zaznamená |
| Procesy na pozadí hostiteľa | PASS, zaznamenané | `plymouthd` (zvyšok bootovacej obrazovky) a `dsh-web` bežali aj počas pilota; celkové CPU je v monitore |
| Hodiny hosťa | PASS | synchronizácia nad 0,25 s, audit do 1 s |

## Audit, archív a kampaň

| Požiadavka | Stav | Dôkaz a poznámka |
|---|---|---|
| Prijatý pilot so súčasným meracím kódom | PASS | pilot 6 (commit `cd67470`, zberač 1.1): audit prijal 480 {{res:collection_pilot_6_20261025_audit.json:values.snapshots}} snímok a 416 {{res:collection_pilot_6_20261025_audit.json:values.windows}} okien ([audit](../data/results/collection_pilot_6_20261025_audit.json)); `measurement_dirty` prázdne ([súhrn](../data/results/collection_pilot_6_20261025_timing.json)); pilot 5 (commit `e774c69`) platil pre kampaň v4 |
| Offline extrakcia s kurzorom reťazca | PASS | [overenie](../data/results/chain_cursor_validation_20261021.json) |
| Trvanie auditu 720 snímok pod limitom 3 h | PASS | kampaň v2: 927.8 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.stage_s.audit}} s až 1001.9 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.stage_s.audit}} s; kampaň v3: najviac 1218.2 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.stage_s.audit}} s; kampaň v4: najviac 3522.4 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.22.stage_s.audit}} s |
| Archív zstd s overením dekompresiou, obnova | PASS | [overenie](../data/results/collection_archive_roundtrip_20261020.json); kampaň v2: `verify-archives` nad 3 session, obnova session 3 (1442 {{res:collection_crossview_race_20261022.json:values.restore.files}} súborov s kontrolou SHA-256); kampaň v3: `verify-archives` nad 3 session za 198.7 {{res:collection_campaign_benign_v3_20261022.json:values.verify_archives.wall_s}} s, obnova session 3 (1442 {{res:collection_process_walk_race_20261022.json:values.restore.files}} súborov); kampaň v4: `verify-archives` nad 37 {{res:collection_campaign_benign_v4_20261022.json:values.verify_archives.n_verified}} session za 2800.0 {{res:collection_campaign_benign_v4_20261022.json:values.verify_archives.wall_s}} s |
| Pravdivé zastavenie (`systemctl stop`) | PASS | [overenie](../data/results/collection_stop_validation_20261020.json); znovu pri pilote 2 ([záznam](../data/results/collection_pilot_hdd_20261021_stopped.json)) |
| Zastavenie na hranici session (`request-stop`) | PASS | kampaň v4: dve žiadosti `request-stop` zastavili runner na hranici session, po session 33 a 36 (`operator_stop_requests`, `stopped_states` v [zázname](../data/results/collection_campaign_benign_v4_20261022.json)); testy `scripts/tests/test_campaign.py` |
| Opakovanie pokusu, ktorý skončil pred meraním | UNVERIFIED | testy; živý výskyt sa zaznamená v `attempts/` |
| Reštart alebo obnova procesu QEMU uprostred skupiny zastaví kampaň | UNVERIFIED | testy; obnova libvirtom sa úmyselne nevyvoláva |
| Uzavretie kampane a nová kampaň (`close`) | PASS | `close` kampaní v2, v3 a v4 zapísal `closed.json` s dôvodom; `init` kampaní v3 a v4 z pilotov 4 a 5 prešiel |
| Krížová kontrola procesov pri živej snímke | FAIL, opravené | [záznam](../data/results/collection_crossview_race_20261022.json): rozdiel jednej snímky zastavil kampaň v2; commit `8498670` ho potvrdzuje susednou snímkou, opätovný audit session prijal; pilot 4 so zmeneným kódom prijatý |
| Roztrhnutý zoznam procesov pri živej snímke | FAIL, opravené | [záznam](../data/results/collection_process_walk_race_20261022.json): cyklus v zozname `tasks` (snímka 505) zastavil kampaň v3; commit `0b61ffd` ho uzavrie prechodom dozadu cez tie isté uzly, opätovný audit session prijal; pilot 5 so zmeneným kódom prijatý |
| Výpadok napájania alebo reštart hostiteľa počas merania | UNVERIFIED | správanie: neúplná session, kampaň stojí; `close` a nová kampaň |
| Úložisko | PASS | `init` overí odhad z pilotu pre SSD aj archív na HDD |
| Regresné testy | PASS | celá sada `pytest` a C testy (počty v [PRIRUCKA.md](PRIRUCKA.md)) |
| Report session a kampane | PASS | `scripts/campaign_report.py`, testy a beh nad 14 uloženými session |
| Iba benígne profily | PASS | runner spúšťa iba `host_traffic.py --profile lab`; žiadny malvér |

## Počas kampane

Nemeniť repozitár (ani poznámky), commit, protokol, profil, Python balíky,
stack vo VM ani nastavenie hostiteľa (`vm.swappiness`, umiestnenie disku VM).
Nespúšťať druhý generátor, testy, tréning, report ani iné náročné úlohy.
Plánované prerušenie: `campaign.py request-stop`. Okamžité `systemctl stop`
počas merania session zneplatní a kampaň zastaví. Pred `campaign.py init` sa
VM vypne a znova spustí (nový proces QEMU); počas kampane sa VM nereštartuje,
reštarty hosťa na hraniciach skupín robí runner.
