# TCN-gui: grafický prehliadač detektora

Webová stránka, ktorá zoberie jednu session snímok (napríklad hodinu) a natrénovaný
balík `safeguard`. Ukáže, či model alebo kontroly integrity hlásia alarm, a aj to, čím
je skóre spôsobené. Druhá záložka ukazuje, ako sa model učil a z akých dát.

Prehratie ide cez `safeguard.runtime.Detector`, takže skóre, prah, pravidlo k z n aj
alarmy sú presne tie, ktoré by vydal detektor pri ostrom behu (test
`tests/test_analyza.py` to porovnáva s `replay_archive`). GUI nič nezapisuje do
repozitára ani do dát.

## Spustenie

```sh
python3 TCN-gui/server.py                 # dáta z data/ v repozitári
python3 TCN-gui/server.py --data /cesta/k/hyptcn3-data --port 8765
```

Potom otvor `http://127.0.0.1:8765/`. Na zberovom PC sa použije interpreter z `.venv`
(`.venv/bin/python TCN-gui/server.py`). Server počúva iba na 127.0.0.1. Z iného PC
sa naň dostaneš cez tunel:

```sh
ssh -L 8765:127.0.0.1:8765 hyptcn     # potom http://127.0.0.1:8765/ lokálne
```

Kým na danom PC beží zber (`hyptcn-collection.service` alebo `collection.py run`),
server skórovanie odmietne. Prehratie zaťažuje CPU a disk a narušilo by meranie
(`docs/AUTOMATICKY_ZBER.sk.md`). Prepínač `--allow-during-collection` je iba pre
iný stroj, kde sa nezbiera.

Grafy kreslí Plotly. Stránka ho najprv hľadá v `TCN-gui/static/vendor/plotly.min.js`
(mimo gitu, kvôli práci bez internetu) a potom ho načíta z jsdelivr. Na offline použitie:

```sh
mkdir -p TCN-gui/static/vendor
curl -Lo TCN-gui/static/vendor/plotly.min.js https://cdn.jsdelivr.net/npm/plotly.js-dist-min@2.35.2/plotly.min.js
```

## Vstupy

- **Model:** adresár balíka so súborom `manifest.json`, napríklad `data/models/server-v2-benign-v6`.
  Diagnostický balík (syntetický, `safeguard smoke`) sa načíta iba po zaškrtnutí voľby
  v sekcii „Rozšírené“.
- **Snímky:** jedna z možností:
  - archív príznakov session (`.npz`, napríklad `campaign_audit_*.npz` v adresári session);
  - adresár session, z ktorého sa vezme najnovší archív;
  - adresár so snímkami `.vmicd` a ich sidecarmi (alebo session s podadresárom `raw/`).
    Tie sa najprv extrahujú cez `guestparse` s profilom jadra, štandardne
    `profiles/debian12-6.1.0-42-cloud-amd64`.
- Ak je v adresári session `events.json` (protokol v3), prevádzkové udalosti sa
  vyznačia v grafe skóre.

## Čo grafy ukazujú

| Graf | Význam |
|---|---|
| Verdikt | `BEZ ALARMU`, `ANOMÁLIA` (alarm modelu podľa pravidla k z n), `NÁLEZ INTEGRITY JADRA`, `NEDOSTATOČNÉ POKRYTIE` (skórovaná je menej ako polovica snímok) alebo `CHYBA VSTUPU` |
| Skóre anomálie v čase | skóre každého okna, kalibrovaný prah, pásy alarmu, udalosti a nálezy integrity |
| Pamäťový chromatogram | čas × bin RAM hosťa (GPA v MiB), farba je chyba predikcie per-bin TCN; do skóre ide najhorší bin |
| Vstup `changed_ratio` | ten istý rozsah ako chromatogram, ale surový podiel zmenených stránok na porovnanie |
| Rozklad skóre | `0,5 · globálne príznaky + 0,5 · najhorší bin`, presne podľa `SCORE_FORMULA` |
| Najrelevantnejšie biny | priemerná chyba binu a počet okien, v ktorých bol najhorší |
| Príspevok globálnych príznakov | `0,5 · chyba príznaku / 18` pre procesy, moduly, sokety a pamäť; súčet riadkov dáva globálnu časť skóre |
| Profil záťaže | pravdepodobnosti klasifikátora scenára záťaže (opisuje prevádzku, nie škodlivosť) |
| Model | krivky učenia `train`/`dev`, vybrané epochy, prah a pravidlo z kalibrácie, okná podľa rolí, prostredie a obmedzenia z manifestu |

Logaritmická mierka sa prepína pri grafe skóre a platí aj pre farby oboch heatmáp.

## Ako čítať výsledok

`BEZ ALARMU` znamená, že session sa správala ako benígna prevádzka, na ktorej sa
model učil. Nie je to dôkaz, že hosť je čistý. `ANOMÁLIA` je odchýlka od tej istej
prevádzky, nie verdikt o malvéri (`HONESTY.md`, P4). Miera falošných alarmov
modelu je zmeraná v `docs/MERANIA.md` a v `docs/STAV.sk.md` (R13); prevádzkové
udalosti meria protokol v3 (`docs/NAVRH_PROTOKOL_V3.sk.md`).

## Testy

```sh
python3 -m pytest -q TCN-gui/tests
```

Testy natrénujú malý syntetický balík zo `safeguard.demo` a overia zhodu skóre
s detektorom, presný rozklad skóre, alarm pri umelej odchýlke v jednom bine,
odmietnutie diagnostického balíka bez povolenia a HTTP rozhranie servera.
