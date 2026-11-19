# Plán: nová iterácia merania na 2 VM (od 2026-11-14)

Cieľ: nový, poctivo zozbieraný dataset (zmrazený kód, nový pilot, predregistrované pravidlá,
`test_benign` aj testovacie skupiny udalostí vyhodnotené iba raz). Iterácia v6/v3 a výsledok
E2 (krok A) ostávajú nezmenené ako predchádzajúca iterácia.

## 1. Opravy kódu a ich overenie

| # | Oprava | Stav | Overenie |
|---|---|---|---|
| 1 | Roztrhnutý zoznam procesov zo session 46 (uzol odstránený `list_del_rcu`, `prev == LIST_POISON2`, pri vkladaní na chvost) | hotové, `d46899f` | 6 jednotkových testov v `guestparse/tests/test_defensive.py`; skutočná snímka 270 zo s46 (diagnostika `torn-walk-20261112`) sa prijme so 110 procesmi, 269 a 271 ostávajú `next` |
| 2 | Príznaky `proc_wx` (W+X stránky z používateľských stránkovacích tabuliek) a `proc_memfd` (memfd v fdtable a `exe_file`) | hotové, `d46899f` | 10 testov `guestparse/tests/test_memory_patterns.py`, kontrakt 24 stĺpcov, 20 vstupov modelu; na lab VM 0 a 0, ~75 ms na snímku |
| 3 | Ďalšie príčiny zamietnutých session: A7 (`prev` cez odstránený uzol), A8 (`tail` s otráveným `prev`), A11 (zastarané tabuľky stránok: strop 4096 na mm, adresy mimo RAM, opakovaná tabuľka → proces sa vynechá, `skipped_wx`) | hotové v kóde | syntetické tvary v `test_defensive.py` a `test_memory_patterns.py`; na skutočných dátach: re-audit session 46 a jednej v6 session zmrazeným kódom pred pilotom |
| 4 | Multi-VM v `scripts/labctl.py`, `scripts/campaign.py`, `scripts/collection.py` (pozri kap. 2) | hotové v kóde (34 testov `scripts/tests/test_multivm.py`); `campaign_report.py` a `experimenty/aba.py` ešte predpokladajú jednu VM | jednotkové testy bez root (stav, porty, jednotky, výber skupín per VM, exkluzivita per doména), suchý beh `campaign.py plan` pre 2 VM |
| 5 | (hotové v kóde) Protokol v4 (`config/collection-v4.json`, `config/collection-v4-events.json`) a `config/klasifikator-v2.json`; `features/dataset.py` nesie `events.json` do korpusu, `tcn.eval udalosti` prijme korpus s rolou `test_benign` (E2') | otvorené | testy načítania a predregistrácie (rozdelenie skupín je pevné pred zberom), `check_claims` |
| 6 | Pozitívna kontrola W+X/memfd v pilote (benígny program v hosťovi: `mmap` RWX + `memfd_create`) | hotové v kóde (súhlas 2026-11-14), `events.pilot_controls`, brána `positive_controls` v audite pilota | v pilotnej session musia oba príznaky v danom okne nenulovo stúpnuť a po skončení klesnúť |

Kód sa zmrazí po bodoch 3 až 5 (commit + tag), na zberovom PC `git pull --ff-only` a plný
`pytest`. Každá ďalšia zmena meracieho kódu znamená nový pilot.

## 2. Dizajn multi-VM

- **N = 2** VM z toho istého obrazu (Debian 12, kernel 6.1.0-42-cloud-amd64, profil
  `profiles/debian12-6.1.0-42-cloud-amd64`). N = 3 iba ak pilot ukáže rezervu CPU, RAM aj IO.
- **Identita VM:** `hyptcn-lab-a`, `hyptcn-lab-b` (alebo ponechať `hyptcn-lab` ako `a`). Klon z
  čistého `hyptcn-guest.qcow2`; v klone sa pred prvým bootom nastaví nový `machine-id` a
  hostname, aby sa VM dali odlíšiť v logoch a `guest_boot`.
- **Per VM:** vlastná doména libvirt, port hostfwd (18080, 18081), cieľ generátora, stavový
  súbor (`vms/lab-state-<vm>.json`), jednotka premávky (`hyptcn-lab-traffic@<vm>`), proces
  `vmicollect` a výstupný adresár session (`.../<kampan>/<vm>/<session>`).
- **Boot skupiny a roly sa prideľujú per VM.** Každá skupina = jeden boot jednej VM; skupina
  nikdy nepokrýva dve VM. Rozvrh je pevný pred zberom (`collection.plan`): počty rolí
  v protokole sú celkové za všetky VM, VM skupiny k je `(k + k // N + rola) % N`, takže každá
  rola má skupiny na oboch VM a nepárne aj párne skupiny ležia na oboch VM. Poradie rolí platí
  globálne (bariéra `wait_for_earlier_roles`): `dev` sa začne až po archivácii všetkých `train`
  na oboch VM atď., ako to vyžaduje kontrola korpusu `features/dataset.py`.
- **VM ako os rozdelenia:** v zázname sa uvádza a vyhodnotenie ho hlási ako ďalšiu os
  (výsledok zvlášť po VM, ako kontrola, nie ako nový test). Hlavné rozdelenie ostáva bootové.
- **Zaťaženie hostiteľa:** monitor zberu sa rozšíri o per-VM procesy (QEMU, `vmicollect`,
  `passt`, `host_traffic.py` podľa domény) a celkové CPU, RAM, swap, IO util. Záznam session
  obsahuje aj stav druhej VM.
- **Zdroje (i5-8400, 6 jadier, 15 GiB):** 1 VM pri zbere ~8 % CPU, QEMU 1850 MiB + vmicollect
  2609 MiB mlock. 2 VM ≈ 8,7 GiB, zostane ~4,9 GiB; `check_memory` druhého zberača to musí
  v pilote pustiť. vCPU 2 + 2 zo 6 jadier, generátory premávky na hostiteľovi ~1 jadro.
- **Disk (hlavné obmedzenie):** SSD 62,9 GB voľných. `capacity_guard` počíta odhad session
  tejto VM (~16,8 GB z pilota), nezapísanú časť odhadu druhej VM a rezervu 30 GiB: dve VM
  naraz potrebujú ~65,8 GB, teda sa dnes nezmestia. Audity a archivácia idú cez
  `data/collections/.audit.lock` po jednom. Uvoľniť sa dá ~50,8 GB so súhlasom (po overenej
  zálohe na Seagate). HDD 210 GB voľných, 2 kampane ~190 až 205 GB + rezerva + disky VM: archívy v6
  a v3 (93,7 + 97,6 GB) presunúť až po overenej zálohe na Seagate.

## 3. Protokol nových datasetov (krok B podľa predregistrovaného pravidla E2)

E2 (krok A) ukázal štatisticky vyššiu FAR pri 4 zo 7 typov udalostí, takže podľa kap. 4
`docs/NAVRH_PROTOKOL_V3.sk.md` nasleduje krok B: udalosti patria do normálu, klasifikátor sa
učí triedy udalostí, vyhodnotenie raz na odložených skupinách.

- **Dataset 1 (normál, `config/collection-v4.json`):** roly ako v2 na každej VM (spolu
  `train` 6, `dev` 2, `calibration` 4, `test_benign` 4 skupiny, 96 session). Každá session vo všetkých rolách obsahuje
  2 až 3 udalosti ako v3 (s ≥ 10 min čistej prevádzky pred, medzi a po nich). Pravidlo kroku B
  („vyhodnotí sa raz na jej vlastnej `test_benign`“) tým platí doslova: odložené `test_benign`
  skupiny s udalosťami sú testovacie skupiny E2'. E2' = FAR nového balíka počas udalostí, po
  typoch, a v čistej prevádzke medzi nimi, rovnaká metrika a kód ako E2. Čistá prevádzka je
  zároveň porovnanie s FAR v6 na `test_benign`.
- **Dataset 2 (udalosti, `config/collection-v4-events.json`):** skupiny `test_events-1..16`
  (8 na VM, 96 session); nepárne pre
  tréning klasifikátora tried udalostí, párne pre jeho test (`config/klasifikator-v2.json`, VO6).
  Prediktor sa učí iba na datasete 1.
- **Poradie:** všetky trénovacie skupiny sa časovo nezbierajú až po testovacích (train pred
  test v rámci každej VM, testovacie skupiny vložené tak, aby nepredchádzali tréningu).
- **Raz a dosť:** `test_benign` a párne `test_events` sa vyhodnotia raz, po
  zmrazení balíka; prah a výber checkpointu iba z `dev` a `calibration`.
- **Porovnanie A vs. B** je výsledok práce (HONESTY P8), uvedie sa aj pri horšom výsledku.

## 4. Kontrolné body s používateľom

0. **Pravidlo prijatia (B5), rozhodnuté 2026-11-14:** zamietnutá session sa nahradí novou
   s tou istou VM, rolou a profilom, najviac 2 náhrady na kampaň, potom kampaň zastaví;
   predregistrované v `replacement` protokolov v4.
1. Pred zmrazením: prehľad opráv a protokolu v4 (bez potreby root).
2. Pred vytvorením druhej VM a pred akýmkoľvek `sudo` (BPF, jednotky): používateľ zadá heslo.
3. Uvoľnenie SSD (~50,8 GB) a presun archívov HDD: iba po zálohe na Seagate a so súhlasom.
4. Pred pilotom (root, ~3 h): plán, čas, disk. Po pilote: výsledok auditu a zaťaženia.
5. Pred spustením kampaní (dni): plán skupín, čas a disk.
6. Pred tréningom (> 2 h) a pred jednorazovými vyhodnoteniami na test skupinách.

## 5. Odhad času

| Krok | Odhad |
|---|---|
| Kód: bod 3 až 5, testy, dokumenty | 1 až 2 dni |
| Druhá VM, nasadenie, testy na zberovom PC | 0,5 dňa (+ čas používateľa pre `sudo`) |
| Pilot 2 VM (480 cyklov + audit) | ~3 až 4 h |
| Kampaň dataset 1: 8 skupín × 6 session na VM = 96 session, ~2,6 h/session, 2 VM súbežne, audity serializované | ~5 až 6 dní |
| Kampaň dataset 2: 8 skupín × 6 session na VM = 96 session | ~5 až 6 dní |
| Tréning seed 0 + seedy 1 až 4 | ~0,5 až 1 deň |
| VO6, E2', E4, potom E1 a E5 | ~1 deň |

Spolu ~2 až 2,5 týždňa; ak disk nedovolí 2 súbežné VM, kampane bežia postupne (~2× dlhšie).

## 6. Model pre každý krok

| Krok | Model |
|---|---|
| Oprava extraktora (s46, W+X/memfd) | Opus 5.5, hotové pred týmto plánom (`d46899f`) |
| Multi-VM v `campaign.py`, `labctl.py`, `collection.py` | Fable 5.2 (subagent), revízia Opus |
| Hľadanie ďalších príčin zamietnutí | Fable 5.2 |
| Protokol v4, klasifikátor v2, dokumenty | Opus 5.5 |
| Testy, nasadenie, pilot, kampane, tréning, vyhodnotenia | Opus 5.5 |

Míľniky sa hlásia diplomovka-8a: kód zmrazený, pilot prijatý, štart a koniec kampaní, tréning
a vyhodnotenia hotové (čísla a commity).

## 7. Kampaň normal-v4-20261115 a oprava (2026-11-17)

Prvá kampaň datasetu 1 sa zastavila na 10 z 96 session (4 zamietnutia, náhrady minuté):
- rušenie medzi VM (audit a archivácia jednej VM vytlačili QEMU druhej do swapu): opravené
  izoláciou auditu (systemd scope s obmedzenou pamäťou, nízka priorita), uvoľňovaním page
  cache a timeoutom agenta hosťa 60 s (`2d7af76`);
- roztrhnutý zoznam procesov na hraniciach udalostí: pravidlo `meet` (`2fcc4b3`), overené na
  oboch skutočných snímkach;
- pravidlo prijatia: `invalid_rows` najviac 3 riadky (iba prechod procesov) a 6 náhrad.

Ďalej: uzavretie starej kampane, nové zmrazenie, re-audit oboch zamietnutých session a jednej
prijatej novým kódom, piloty na oboch VM, nová kampaň datasetu 1.

## 8. Dodatok k protokolu v4: pokračovacia kampaň (predregistrované 2026-11-19)

Tento dodatok je zapísaný a odoslaný do repozitára pred zberom prvej session rolí `calibration`
a `test_benign` a pred akýmkoľvek tréningom na dátach v4. Rozhodnutie vlastníka z 2026-11-19.

### 8.1 Stav pri zápise (2026-11-19 21:03 UTC)

Kampaň `normal-v4c-20261117` (commit `c7cf446`, protokol `config/collection-v4.json`,
sha256 `ca0ea98c4c0d321c9b13f0fd0bb690bf062df46264457c232abc60ab8594bbe5`) beží od
2026-11-17 16:45 UTC. Prijaté a archivované: `train` 36 z 36, `dev` 7 z 12, `calibration` 0 z 24,
`test_benign` 0 z 24. Zamietnutých je 5 session, všetky nahradené; zo 6 náhrad ostáva 1.

| Zamietnutá session | Dátum (UTC) | Príčina |
|---|---|---|
| `15_b_train_write_heavy` | 2026-11-18 10:20 | zmeškaný slot: pamäť VM b odložená do swapu počas archivácie VM a, cyklus 6,7 s |
| `15_b_train_write_heavy-r1` | 2026-11-18 12:16 | to isté, cykly 6,6 s a 5,9 s |
| `23_a_train_bursty` | 2026-11-18 13:21 | to isté na VM a, cyklus 11,6 s (zber 11:24 až 12:24, pred zmenou swapu) |
| `33_b_train_mixed` | 2026-11-19 02:54 | chyba lab aplikácie v hosťovi (timeout backendu, traceback), brána logov |
| `39_b_dev_quiet` | 2026-11-19 17:50 | 3 neplatné riadky (cyklus v zozname procesov, 308, 343, 358), pokrytie 0,842 < 0,85 |

Zásah operátora 2026-11-18 13:23 UTC: `MemorySwapMax=0` (runtime) na cgroup, v ktorej bežia obe
QEMU (`session-2730.scope`). Odvtedy žiadna session nezmeškala slot. Kód ani protokol sa nemenil.

Z 26 session meraných po tomto zásahu boli 2 zamietnuté (24 prijatých). Pri tejto miere sa
zvyšných 53 session s jednou náhradou pravdepodobne nedokončí. Bežiaca kampaň sa zmeniť nedá: `verify_frozen` ju
viaže na commit a hash protokolu a zamietnutie bez náhrady ju zastaví natrvalo.

### 8.2 Pravidlo

1. **Kedy.** Ak sa kampaň `normal-v4c-20261117` zastaví preto, že pravidlo `replacement` už
   session nahradiť nemôže (limit je minutý alebo boot skupiny zanikol), vlastník ju uzavrie
   (`campaign.py close`) a zvyšok rozvrhu zozbiera jedna pokračovacia kampaň.
2. **Rovnaký protokol.** Pokračovacia kampaň používa bajtovo zhodný súbor protokolu (ten istý
   sha256). Brány auditu, `invalid_rows`, `min_score_coverage`, scenáre, udalosti, rozvrh skupín
   a semená sa nemenia. Nemení sa ani kód zberu, auditu a extrakcie (`features/`, `guestparse/`,
   `vmicollect/`, `lab/`, `scripts/collection.py`, `scripts/collection_archive.py`); mení sa iba
   `scripts/campaign.py` (ktoré session sa spustia). Pred pokračovaním prebehne nový pilot na
   oboch VM, ako pri každej zmene meracieho kódu.
3. **Prevzaté skupiny.** Skupina, ktorej všetkých 6 priradení je prijatých a archivovaných, sa
   prevezme bez zmeny (jej audity a príznaky sa nepočítajú znova).
4. **Neúplné skupiny.** Skupina, ktorá pri zastavení nie je úplná (vrátane tej so zamietnutím bez
   náhrady a rozpracovanej skupiny druhej VM), sa do korpusu nedostane ani čiastočne. Jej session
   ostanú v archíve. Celá skupina sa zozbiera znova v novom boote tej istej VM, s tými istými
   scenármi a semenami. Platí teda ďalej: jedna skupina je jeden boot jednej VM.
5. **Poradie rolí** ostáva (`train`, `dev`, `calibration`, `test_benign`), aj medzi kampaňami.
6. **Limit náhrad.** Pre pokračovaciu kampaň platí limit protokolu znova (6), spolu teda najviac
   12 náhrad. Ďalšia pokračovacia kampaň nie je dovolená: ak sa zastaví aj táto, zber datasetu 1
   podľa protokolu v4 sa končí bez korpusu a rozhoduje vlastník (nový protokol, nový zber).
7. **Vykazovanie.** Práca uvedie všetky nepoužité session oboch kampaní podľa príčin, zahodené
   skupiny a to, že korpus tvoria dve kampane. Ako obmedzenie uvedie, že „normál“ tvoria iba
   session, ktoré prešli auditom (bez chyby aplikácie v hosťovi a s uzavretým zoznamom procesov).

### 8.3 Zdôvodnenie

Dodatok nemení, ktorá session je prijateľná, iba koľkokrát sa smie neprijateľná session
zopakovať. O prijatí rozhodujú brány auditu zapísané pred zberom; výsledky modelu neexistujú,
tréning sa začne až po úplnom korpuse. Limit 6 bol určený bez znalosti miery zamietnutí pri
dvoch súbežných VM a jeho účel (zastaviť zber na kontrolu, nie potichu nahrádzať) ostáva: každé
zamietnutie je zaznamenané s príčinou a vykázané.

### 8.4 Zistenie k pravidlu `invalid_rows`

Tolerancia najviac 3 neplatných riadkov sa s bránou pokrytia 0,85 prekrýva: každý osamotený
neplatný riadok vyradí približne 16 okien (656 okien pri 720 riadkoch, pokrytie 0,911). Tri
osamotené riadky dajú 0,842 a session zamietne brána pokrytia (`39_b_dev_quiet`). V praxi teda
prejdú najviac dva osamotené neplatné riadky. Pravidlo sa nemení, uvádza sa ako zistenie.
