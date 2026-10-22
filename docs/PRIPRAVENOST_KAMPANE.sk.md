# Pripravenosť benígnej kampane

Stav k 2026-10-22 (UTC) pred `campaign.py init`. Dokument nie je meranie;
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
snímok a vstupná brána kampane (`pilot_gate`) prešla so súčasným kódom.

## Zber a dôkazy

| Požiadavka | Stav | Dôkaz a poznámka |
|---|---|---|
| Záznam každej požiadavky a 5 s súhrny s fázami | PASS | pilot 3: `traffic_requests.jsonl`, `traffic_intervals.jsonl`; logový audit prijatý |
| Logy servera s request ID a párovanie s generátorom | PASS | pilot 3: nginx JSON, journal služieb, korelácia v logovom audite |
| Časová os hostiteľa (CPU, pamäť, swap, disky, procesy, teploty; 1 s) | PASS | pilot 3: najväčšia medzera vzoriek 1.0 {{res:collection_pilot_3_20261021_timing.json:values.monitor_max_gap_s}} s |
| Žiadny zmeškaný slot zberača | PASS | pilot 3: 0 {{res:collection_pilot_3_20261021_timing.json:values.collector_end.missed_slots}} zmeškaných slotov |
| Prvý pilot (swap hostiteľa, disk VM spolu so snímkami) | FAIL, opravené | [záznam](../data/results/collection_io_interference_20261021.json); opatrenia overil pilot 3 |
| Pamäť hosťa nie je odswapovaná pri plnej snímke | PASS | `vm.swappiness = 1`, krok `prefault`; pilot 3: swap QEMU 0 kB na začiatku aj na konci |
| Disk VM oddelený od výstupu snímok | PASS | `vms/hyptcn-lab.qcow2` na HDD; pilot 3: 0 {{res:collection_pilot_3_20261021_timing.json:values.traffic.errors}} chybných požiadaviek |
| Monitor nečaká na `fsync` počas vzorkovania | PASS | test s falošnými hodinami; pilot 3 bez medzery |
| Rezerva plnej snímky voči perióde 5 s | PASS, zostatkové riziko | pilot 3: 1831.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_0.cycle_ms}} ms a 3483.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_360.cycle_ms}} ms (súbežný spätný zápis); po reštarte skupiny ostáva v RAM starý obsah, takže plné snímky v kampani budú väčšie (pilot 1: ~920 MiB). Prekročenie audit zistí a kampaň zastaví |
| Časovače v hosťovi | PASS | identita hosťa `timers:` je prázdna; zmena zastaví kampaň |
| Údržba hostiteľa | PASS | aktualizácie vypnuté; `anacron`, `logrotate`, `dpkg-db-backup`, `systemd-tmpfiles-clean` a `e2scrub_all` zostávajú, monitor ich zaznamená |
| Procesy na pozadí hostiteľa | PASS, zaznamenané | `plymouthd` (zvyšok bootovacej obrazovky) a `dsh-web` bežali aj počas pilota; celkové CPU je v monitore |
| Hodiny hosťa | PASS | synchronizácia nad 0,25 s, audit do 1 s |

## Audit, archív a kampaň

| Požiadavka | Stav | Dôkaz a poznámka |
|---|---|---|
| Prijatý pilot so súčasným meracím kódom | PASS | pilot 3; `measurement_dirty: []` |
| Offline extrakcia s kurzorom reťazca | PASS | [overenie](../data/results/chain_cursor_validation_20261021.json) |
| Trvanie auditu 720 snímok pod limitom 3 h | UNVERIFIED | 480 snímok: 563.607 {{res:collection_pilot_3_20261021_timing.json:values.audit_timing.wall_s}} s; zmeria prvá session |
| Archív zstd s overením dekompresiou, obnova | PASS | [overenie](../data/results/collection_archive_roundtrip_20261020.json); archív session kampane overí prvá session |
| Pravdivé zastavenie (`systemctl stop`) | PASS | [overenie](../data/results/collection_stop_validation_20261020.json); znovu pri pilote 2 ([záznam](../data/results/collection_pilot_hdd_20261021_stopped.json)) |
| Zastavenie na hranici session (`request-stop`) | UNVERIFIED | testy `scripts/tests/test_campaign.py` |
| Opakovanie pokusu, ktorý skončil pred meraním | UNVERIFIED | testy; živý výskyt sa zaznamená v `attempts/` |
| Reštart alebo obnova procesu QEMU uprostred skupiny zastaví kampaň | UNVERIFIED | testy; obnova libvirtom sa úmyselne nevyvoláva |
| Uzavretie kampane a nová kampaň (`close`) | UNVERIFIED | testy |
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
