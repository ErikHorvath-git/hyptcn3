# Rozpracované — stav k 2026-09-19

Tento súbor je dočasný. Keď sa položky nižšie dokončia, zmaže sa; dovtedy je to jediné
miesto, kde je napísané, čo je rozrobené a prečo. Hotové veci sem nepatria — tie sú
v `docs/PRIRUCKA.md` a v `docs/MERANIA.md`.

## Čo je hotové a overené

Spojenie oboch vetiev do jedného príznakového vektora **funguje**. Jedna snímka dá 21 čísel:
osem štatistík pamäťových blokov a dvanásť z rekonštruovaných objektov hosťa (procesy,
moduly, sokety, kontroly integrity), plus príznak `ma_predchodcu`.

Overené nezávislým prepočtom (revízia 2026-09-19): objektová časť sedí presne s `guestparse`
(procesy 77/76, moduly 51/51, sokety 13/13, hooky 0/0), pamäťová do 5·10⁻⁶ proti sidecarom.
Dva behy nad tým istým reťazcom dajú bajt po bajte rovnaký vektor.

TCN existuje: dilatované kauzálne konvolúcie, 34 riadkov kódu, 5 330 parametrov.
**Kauzalita overená testom** — zmena vstupu v čase t+1 nezmení výstup v čase t.
Baseliny: logistická regresia, bag-of-frames (nevidí poradie), GRU.

Celá cesta `.vmicd` → `features session` → `tcn.train` prešla na syntetických dátach.

## Čo je otvorené — v tomto poradí

### 1. Zber korpusu dnes nevyrobí ani jedno okno (blokuje všetko ostatné)

`scripts/collect_corpus.sh:43-44` má `DURATION=60` a `INTERVAL=5.0`, čo dá 12 snímok na
sedenie. Dĺžka okna je 16 (`features/windows.py`). Kto spustí dokumentovaný príkaz, dostane
nula okien a tréning spadne.

Treba: perióda 2 s, trvanie ~180 s (90 snímok ≈ 75 okien na sedenie) a kontrola v
`--dry-run`, ktorá odmietne bežať, keď by okien bolo málo. Zároveň po každom sedení spočítať
vektor a surové `.vmicd` zmazať — inak korpus zaberie ~15 GiB, kým vektory majú kilobajty.

### 2. Objektové príznaky sa zatiaľ nehýbu

V žiadnom nazbieranom sedení sa `proc_new`, `proc_gone` ani `mod_delta` nepohli z nuly —
**vrátane `fork_storm`**, ktorý ich má rozhýbať. Dôvod: pri perióde 5 s a čase snímky ~0,5 s
sa krátkožijúci proces medzi dvoma snímkami nestihne ukázať.

Nie je to chyba kódu, je to časové rozlíšenie metódy. Treba dvoje:
- scenáre upraviť tak, aby vyrábali správanie pozorovateľné pri danej perióde (deti, ktoré
  žijú sekundy, nie milisekundy) a **zmerať, ktoré príznaky sa pohli a o koľko**;
- pridať to do `docs/LIMITACIE.md` ako limitáciu s konkrétnym číslom.

Kým sa toto nevyrieši, polovica vektora nenesie informáciu a model nemá na čom stavať.

### 3. Riadok plnej snímky má iný fyzikálny význam

V plnej snímke je `pages_changed` počet **nenulových** stránok, nie zmenených, takže
`mem_changed_ratio` vyjde presne `1 − mem_zero_ratio`. Príznak `ma_predchodcu` to nekryje —
ten sa týka len príznakov 12, 13 a 15. Dnes to nevadí iba náhodou, lebo plná snímka je prvá
v sedení; pri `output.delta_full_every` by prišla aj uprostred.

Treba: vlastný príznak `je_plna` a stavba okien nech vylúči okno, ktoré takýto riadok
obsahuje.

### 4. Zdvojené okná

`tcn/train.py:135` má vlastnú funkciu `okna_zo_session()` a z `features/windows.py` si berie
iba konštanty. `features/windows.py` (419 riadkov) plus jeho testy (303) pritom existujú
práve na to, aby okno neprekročilo hranicu sedenia, dieru v `seq` ani časovú medzeru.
Sedemsto riadkov sa nepoužíva a ich úlohu robí päť riadkov bez ochrán.

Treba: `train.py` nech používa `features/windows.py`. Ak je per-bin vetva vo `windows.py`
už nepotrebná, zmazať ju — mazanie je vítané.

### 5. Drobnosti

- `scenarios/mass_file_rewrite.py` prekračuje zadané trvanie (15 s zadané, 24,8 s skutočné);
  vytvorenie súborov a upratovanie sú mimo rozpočtu.
- `data/raw/20260919T011728Z_mass_file_rewrite/labels.json` má `zvysne_procesy_v_hostovi: 1`,
  hoci `scenarios/README.md` tvrdí, že po behu nič nezostane. Pravdepodobne sa počíta sám
  príkaz cez ssh — treba overiť a zosúladiť README so skutočnosťou.
- `scenarios/` nie je v tabuľke „Čo je kde" v príručke: zoznam `ADRESARE` v
  `scripts/gen_prirucka.py` je pevný a položka pre `scenarios/` v ňom chýba.

## Poradie prác na zajtra

1. Položky 1 a 2 vyššie — bez nich sa korpus nedá zozbierať zmysluplne.
2. Spustiť zber korpusu (6 tried × 5 sedení × 3 min ≈ 90 minút čistého behu).
3. Tréning a vyhodnotenie: TCN + tri baseliny na tom istom session-disjunktnom splite,
   per-class metriky a confusion matrix, povinné confound testy.
4. Položky 3 a 4 sa dajú spraviť paralelne, ale pred tréningom — menia tvar dát.

## Stav prostredia

VM `hyptcn-guest` je **vypnutá** (korektný `shutdown` 2026-09-19). Zmrazenie platí:
starý agent zakázaný, `unattended-upgrades` zamaskované, jadro pinnuté na 6.1.0-42,
takže profil v `profiles/` bude po štarte ďalej sedieť. Po štarte VM netreba nič nastavovať.
