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
| 6 | Pozitívna kontrola W+X/memfd v pilote (benígny program v hosťovi: `mmap` RWX + `memfd_create`) | návrh, čaká na súhlas | v pilotnej session musia oba príznaky v danom okne nenulovo stúpnuť a po skončení klesnúť |

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

0. **Rozhodnutie o pravidle prijatia (B5):** dnes jeden neplatný riadok zamietne session a
   kampaň sa zastaví bez náhrady (5 kampaní takto skončilo). Možnosti: ponechať; povoliť
   náhradnú session v tej istej skupine; alebo tolerovať malý počet neplatných riadkov pri
   pokrytí skóre ≥ 0,85. Rozhodnutie sa predregistruje v protokole v4 pred zmrazením.
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
