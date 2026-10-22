# Pripravenosť benígnej kampane

Stav k 2026-10-22 (UTC) po uzavretí kampaní `benign-v2-20261022`
a `benign-v3-20261022` a pred ďalším `campaign.py init`. Dokument nie je meranie;
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
klienta je 10 s), preto ďalšia kampaň potrebuje nový pilot so súčasným kódom.

## Zber a dôkazy

| Požiadavka | Stav | Dôkaz a poznámka |
|---|---|---|
| Záznam každej požiadavky a 5 s súhrny s fázami | PASS | pilot 3: `traffic_requests.jsonl`, `traffic_intervals.jsonl`; logový audit prijatý |
| Logy servera s request ID a párovanie s generátorom | PASS | pilot 3: nginx JSON, journal služieb, korelácia v logovom audite |
| Časová os hostiteľa (CPU, pamäť, swap, disky, procesy, teploty; 1 s) | PASS, zostatkové riziko | pilot 3: najväčšia medzera vzoriek 1.0 {{res:collection_pilot_3_20261021_timing.json:values.monitor_max_gap_s}} s; kampaň v2: 2.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.monitor_max_gap_s}} s v session 1 a 2.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.monitor_max_gap_s}} s v session 3 počas spätného zápisu plnej snímky; limit auditu je 2,5 s |
| Žiadny zmeškaný slot zberača | PASS | pilot 3: 0 {{res:collection_pilot_3_20261021_timing.json:values.collector_end.missed_slots}} zmeškaných slotov |
| Prvý pilot (swap hostiteľa, disk VM spolu so snímkami) | FAIL, opravené | [záznam](../data/results/collection_io_interference_20261021.json); opatrenia overil pilot 3 |
| Pamäť hosťa nie je odswapovaná pri plnej snímke | PASS | `vm.swappiness = 1`, krok `prefault`; pilot 3: swap QEMU 0 kB na začiatku aj na konci |
| Disk VM oddelený od výstupu snímok | PASS | `vms/hyptcn-lab.qcow2` na HDD; pilot 3: 0 {{res:collection_pilot_3_20261021_timing.json:values.traffic.errors}} chybných požiadaviek |
| Monitor nečaká na `fsync` počas vzorkovania | PASS | test s falošnými hodinami; pilot 3 bez medzery |
| Monitor nečaká ani na zápis riadku | UNVERIFIED | kampaň v3: 2.01 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.monitor_max_gap_s}} s a 2.04 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.monitor_max_gap_s}} s pri spätnom zápise; commit `0b61ffd` zapisuje z fronty vo vlákne, test so zablokovaným zápisom; živé overenie príde s pilotom |
| Rezerva limitu klienta | UNVERIFIED | kampaň v3: najpomalšia požiadavka 2348.6 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.measure_latency.max_ms}} ms pri limite 4 s; od commitu `0b61ffd` je limit 10 s |
| Rezerva plnej snímky voči perióde 5 s | PASS, zostatkové riziko | kampaň v3: najdlhšia plná snímka 2458.5 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.full_snapshots_ms.1}} ms pri 917.43 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.full_snapshots_mib.1}} MiB; kampaň v2: najdlhšia plná snímka 2168.1 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.full_snapshots_ms.1}} ms pri 735.27 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.full_snapshots_mib.1}} MiB; pilot 3: 1831.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_0.cycle_ms}} ms a 3483.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_360.cycle_ms}} ms (súbežný spätný zápis); po reštarte skupiny ostáva v RAM starý obsah, takže plné snímky v kampani budú väčšie (pilot 1: ~920 MiB). Prekročenie audit zistí a kampaň zastaví |
| Časovače v hosťovi | PASS | identita hosťa `timers:` je prázdna; zmena zastaví kampaň |
| Údržba hostiteľa | PASS | aktualizácie vypnuté; `anacron`, `logrotate`, `dpkg-db-backup`, `systemd-tmpfiles-clean` a `e2scrub_all` zostávajú, monitor ich zaznamená |
| Procesy na pozadí hostiteľa | PASS, zaznamenané | `plymouthd` (zvyšok bootovacej obrazovky) a `dsh-web` bežali aj počas pilota; celkové CPU je v monitore |
| Hodiny hosťa | PASS | synchronizácia nad 0,25 s, audit do 1 s |

## Audit, archív a kampaň

| Požiadavka | Stav | Dôkaz a poznámka |
|---|---|---|
| Prijatý pilot so súčasným meracím kódom | UNVERIFIED | pilot 4 (commit `d25c027`) platí pre kód pred `0b61ffd`; nový pilot ešte nebežal |
| Offline extrakcia s kurzorom reťazca | PASS | [overenie](../data/results/chain_cursor_validation_20261021.json) |
| Trvanie auditu 720 snímok pod limitom 3 h | PASS | kampaň v2: 927.8 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.stage_s.audit}} s až 1001.9 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.stage_s.audit}} s; kampaň v3: najviac 1218.2 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.stage_s.audit}} s |
| Archív zstd s overením dekompresiou, obnova | PASS | [overenie](../data/results/collection_archive_roundtrip_20261020.json); kampaň v2: `verify-archives` nad 3 session, obnova session 3 (1442 {{res:collection_crossview_race_20261022.json:values.restore.files}} súborov s kontrolou SHA-256); kampaň v3: `verify-archives` nad 3 session za 198.7 {{res:collection_campaign_benign_v3_20261022.json:values.verify_archives.wall_s}} s, obnova session 3 (1442 {{res:collection_process_walk_race_20261022.json:values.restore.files}} súborov) |
| Pravdivé zastavenie (`systemctl stop`) | PASS | [overenie](../data/results/collection_stop_validation_20261020.json); znovu pri pilote 2 ([záznam](../data/results/collection_pilot_hdd_20261021_stopped.json)) |
| Zastavenie na hranici session (`request-stop`) | UNVERIFIED | testy `scripts/tests/test_campaign.py`; hranicu `--stop-after` overili kampane v2 a v3 |
| Opakovanie pokusu, ktorý skončil pred meraním | UNVERIFIED | testy; živý výskyt sa zaznamená v `attempts/` |
| Reštart alebo obnova procesu QEMU uprostred skupiny zastaví kampaň | UNVERIFIED | testy; obnova libvirtom sa úmyselne nevyvoláva |
| Uzavretie kampane a nová kampaň (`close`) | PASS | `close` kampaní v2 a v3 zapísal `closed.json` s dôvodom; `init` kampane v3 z pilota 4 prešiel |
| Krížová kontrola procesov pri živej snímke | FAIL, opravené | [záznam](../data/results/collection_crossview_race_20261022.json): rozdiel jednej snímky zastavil kampaň v2; commit `8498670` ho potvrdzuje susednou snímkou, opätovný audit session prijal; pilot 4 so zmeneným kódom prijatý |
| Roztrhnutý zoznam procesov pri živej snímke | FAIL, opravené | [záznam](../data/results/collection_process_walk_race_20261022.json): cyklus v zozname `tasks` (snímka 505) zastavil kampaň v3; commit `0b61ffd` ho uzavrie prechodom dozadu cez tie isté uzly, opätovný audit session prijal; pilot so zmeneným kódom ešte nebežal |
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
počas merania session zneplatní a kampaň zastaví.
