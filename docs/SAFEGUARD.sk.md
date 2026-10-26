# Safeguard: zber, modely a detektor na hostiteľovi

Balík [`safeguard/`](../safeguard/) spája príznaky, normalizáciu, tréning,
uloženie modelov a detektor pod `python3 -m safeguard`. Softvérová cesta je
implementovaná; jej overovanie rozlišuje syntetický test, prehratie uložených
dát a nový beh nad VM. Diagnostický model nie je modelom natrénovaným na
serverovom korpuse. Účinnosť proti útokom, falošné alarmy pri dlhšej prevádzke
a vplyv celého detektora na VM ešte neboli touto integráciou vyhodnotené.

Pilot podľa [`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md) má
[prijatý audit](../data/results/collection_pilot_v2_20261013_reaudit.json).
Nový benígny korpus zostáva podmienkou tréningu a ďalšej experimentálnej etapy.
Jeho automatický zber a archiváciu riadi
[`scripts/campaign.py`](../scripts/campaign.py); postup je v
[`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md).
Nový spoločný beh `run` s hostiteľským eBPF zberom je
zatiaľ **UNVERIFIED**; staršie overenie samostatného zberača ho nenahrádza.
Výstupy vykonaných overení sa evidujú v [`MERANIA.md`](MERANIA.md).
Konkrétny integračný záznam vrátane zhody spracovania uložených RAM dát je
[`safeguard_validation_20261013_a.json`](../data/results/safeguard_validation_20261013_a.json).

## Dátová cesta

```text
QEMU/KVM RAM
  → vmicollect: periodické .vmicd + JSON s per-bin príznakmi
  → guestparse + features.snapshot: objekty jadra, kvalita, kontroly
  → safeguard.features: Frame, časové okno, uložená normalizácia
  → globálna TCN + zdieľaná TCN pre jednotlivé biny
  → skóre odchýlky + samostatný klasifikátor profilu záťaže
  → kalibrovaný prah, pravidlo k z n, nezávislé nálezy integrity
  → JSON udalosti, stav, HOLD reťazcov pri alarme
```

Zber aj rozhodovanie prebiehajú na hostiteľovi. Bezpečnostný agent v hosťovi
sa nepoužíva. Profil jadra je priznaný vstup; qemu-guest-agent slúži
existujúcej orchestrácii a overeniu identity prostredia.

| Súbor | Zodpovednosť |
|---|---|
| `safeguard/features.py` | Import archívu aj surových snímok, geometria RAM, kvalita, okná a normalizácia |
| `safeguard/model.py` | Prediktor globálnych a per-bin príznakov; klasifikátor záťaže |
| `safeguard/training.py` | Explicitné roly korpusu, tréning, výber checkpointu a kalibrácia |
| `safeguard/bundle.py` | Manifest, načítanie váh a spoločné skórovanie okna |
| `safeguard/runtime.py` | Stav detektora, alarmy, uchovanie dôkazov a čítanie pribúdajúcich snímok |
| `safeguard/supervisor.py` | Vlastný proces zberača, zámok zberu a kontrola disku |
| `safeguard/cli.py` | Príkazové rozhranie |

## Príznaky, tréning a načítanie

Archív naďalej obsahuje pôvodných 22 stĺpcov. Model používa prvých 18
behaviorálnych stĺpcov a tenzor `čas × bin × 4`. Kontroly integrity, príznaky
úplnosti, PID a identifikátory VM nie sú číselnými vstupmi modelu. Každý bin
nesie `changed_ratio`, `zero_ratio`, `entropy_mean`, `has_changed`.

`Frame` vyžaduje štruktúrovanú kvalitu, čas a sekvenciu, identitu reťazca
a geometriu pamäte. Plná snímka, chýbajúci predchodca alebo neplatné meranie
prerušia okno. Zmena session/reťazca a medzera v čase alebo sekvencii
prerušia aj históriu hlasovania. Nerastúce časy a duplicitné sekvencie sú
chybou. Nezodpovedajúca geometria alebo poradie príznakov sa neprepočítajú
potichu na iný vstup modelu.

Aktuálny kontrakt `hyptcn3/safeguard-features/2` vyžaduje archív
`hyptcn3/snapshot-vektor/3` s politikou `behavioral-inputs-v1`.
`behavior_valid` vyjadruje úspešné čítanie RAM a úplné primárne prechody
procesov, modulov a soketov. Roztrhnutý zoznam procesov môže uzavrieť aj prechod dozadu
alebo `init_task.prev` pred posledným uzlom so stránkou z iného okamihu
(`quality.process_walk` `prev` alebo `tail`, pravidlo 3 v [METODIKA_ZBERU.sk.md](METODIKA_ZBERU.sk.md)). Neuzavretá nezávislá kontrola integrity zostáva
viditeľná v udalosti, ale tieto namerané vstupy nezneplatňuje. Nález integrity
stále vyvolá alarm nezávisle od modelu. Krížový rozdiel procesov alebo modulov
je nálezom až vtedy, keď ho ukáže aj bezprostredne predchádzajúca snímka tej
istej session. Rozdiel z jedinej živej snímky je v `integrity.unconfirmed`
a kontrola je `inconclusive` (pozri [kontroly.md](kontroly.md)); alarm
skrytého objektu preto príde o jednu periódu neskôr. Staršie archívy alebo manifesty sa
odmietnu; vyžadujú novú extrakciu a tréning, nie ručné prepísanie verzie.

Normalizátor vidí iba vhodné riadky role `train`, každý práve raz. Parametre
lokálnych príznakov sú spoločné pre biny; entropia sa fituje iba tam, kde
`has_changed=1`. Pri transformácii má nemeraná entropia hodnotu nula a maska
sa nemení. Nulová numerická variabilita má bezpečnú mierku. Tieto parametre
sa pri prehrávaní ani živom skórovaní znovu nefitujú.

Prediktor používa všetky kroky okna okrem posledného a predpovedá posledný
krok. Maska merania sa nepredikuje. Chyba entropie sa započíta iba pri
pozorovanej entropii cieľového binu. Aktuálna verzia má skóre určené vzorcom:

```text
0.5 × priemerná štvorcová chyba globálnych príznakov
  + 0.5 × maximum maskovanej priemernej štvorcovej chyby jednotlivých binov
```

Klasifikátor používa globálne príznaky spolu s priemerom a maximom lokálnych
príznakov cez biny. Jeho triedami sú zaznamenané profily záťaže. Výstup
`activity` nie je klasifikácia škodlivosti ani identifikácia rodiny malvéru.
Priradenie chyby fyzickému binu samo neidentifikuje vinný proces.

Tréning číta index `hyptcn3/corpus-index/1` a overuje hashe aj provenienciu.
`train` určuje váhy a normalizáciu, `dev` vyberá checkpointy prediktora
a klasifikátora, `calibration` nastaví prah. Pole príznakov `test_benign`
sa počas tréningu nenačíta. Boot/skupina nesmie patriť viacerým rolám.

`--fpr` určuje kvantil benígnych skóre, nie garantovaný počet alarmov za
hodinu. Nadprahové skóre znamená `score > threshold`. Alarm modelu vyžaduje
aspoň `k` prekročení v posledných `n` skóre, až keď je celá história dostupná.
Kalibrácia eviduje aj udalosti pravidla k z n; nezávislé FAR sa meria až na
odloženom teste. Po vyhodnotení testu sa prah neladí podľa jeho výsledku.

Nový adresár modelu obsahuje `manifest.json`, `predictor.pt` a `classifier.pt`.
Manifest ukladá poradie príznakov, biny, geometriu, okno, normalizáciu,
architektúru, triedy, vzorce skórovania, kalibráciu, hashe váh a provenienciu.
Načítanie overí kompatibilitu a kontrolné súčty. Hashe chránia pred zmenou
súborov oproti manifestu; neoverujú pôvod balíka od neznámeho autora.

## Príkazy

Príkazy sa spúšťajú z koreňa repozitára. Pri vytváraní výstupu musí `--out`
označovať nový adresár; `status` číta existujúci výstup. Cesty v ukážkach
sú názvy plánovaných výstupov; neznamenajú, že už
existuje prijatý korpus alebo model z jeho tréningu.

**Skúška bez VM a bez roota:**

```sh
python3 -m safeguard smoke --out data/safeguard/smoke-01
python3 -m safeguard inspect --bundle data/safeguard/smoke-01/bundle --allow-diagnostic
```

`smoke` vytvorí syntetický korpus, vykoná krátky tréning, uloží a načíta oba
modely a prehrá samostatné syntetické testovacie dáta. Výstupy sú označené
`diagnostic`. Kontroluje aj odmietnutie bežného načítania diagnostického
balíka. Výsledok je v `report.json`, udalosti v `events.jsonl`. Nie je to
meranie detekcie alebo presnosti klasifikátora na skutočnej prevádzke.

**Tréning po prijatí celého korpusu:**

```sh
python3 -m safeguard train --corpus data/corpus-v2.json --out data/models/server-v2 --epochs 10 --seed 0
python3 -m safeguard inspect --bundle data/models/server-v2
```

Časové nastavenia sa preberajú z protokolu v indexe. Neúplný korpus sa pre
bežný tréning odmietne. `--diagnostic` je výslovný režim skúšania mechaniky;
nenahrádza splnenie podmienok finálneho korpusu.

**Konečné prehratie uložených dát:**

```sh
python3 -m safeguard replay --bundle data/models/server-v2 --archive data/collections/SESSION/audit_TIMESTAMP.npz --out data/safeguard/replay-01
python3 -m safeguard replay --bundle data/models/server-v2 --snapshots data/collections/SESSION/raw --profile data/collections/SESSION/profile --out data/safeguard/replay-raw-01
```

`replay` nemení retenciu surových dát a nespúšťa zberač. Pre diagnostický
balík treba pridať `--allow-diagnostic`. Rozloženie a vstupný kontrakt musia
sedieť aj v diagnostickom režime.

**Sledovanie adresára, do ktorého už zapisuje zberač:**

```sh
python3 -m safeguard watch --bundle data/models/server-v2 --snapshots data/safeguard/existing-capture/raw --profile profiles/debian12-6.1.0-42-cloud-amd64 --out data/safeguard/watch-01
```

`watch` nevytvára druhý zberač. Spracúva pribúdajúce súbory a pri alarme
volá HOLD. Vyžaduje právo čítať snímky a zapisovať retenčné značky.
`--idle-timeout` obmedzí čakanie bez nových dát. Bez neho pokračuje do
prerušenia používateľom. Na rozdiel od `run` nevykonáva preflight bežiacej
VM; operátor zodpovedá za pôvod snímok a profil. Výslovné diagnostické
načítanie je možné, jeho výsledky zostávajú diagnostické.

**Spoločný zber a detektor nad bežiacim laboratóriom:**

```sh
make lab-up
sudo env PYTHONPATH="$(python3 -m site --user-site)" python3 -m safeguard run --bundle data/models/server-v2 --protocol config/collection-v2.json --domain hyptcn-lab --profile profiles/debian12-6.1.0-42-cloud-amd64 --out data/safeguard/live-01
python3 -m safeguard status --out data/safeguard/live-01
```

`run` potrebuje oprávnenie na eBPF a bežiacu VM; `PYTHONPATH` v ukážke sprístupní pod `sudo` lokálnu inštaláciu PyTorch.
Vyžaduje model z reálneho korpusu; diagnostický balík sa odmietne a príkaz nemá voľbu
`--allow-diagnostic`. Pred zberom sa kontroluje protokol, jadro
a serverový stack hosťa, profil, implementácia extrakcie a skórovania aj binárka zberača
proti proveniencii modelu. Nekompatibilita je dôvodom skončiť s chybou.

Beh je konečný: počet cyklov preberá z protokolu, prípadne z `--cycles`.
Zdieľa zámok s výskumným runnerom a nesmie s ním súbežne zbierať. Rezerva
disku a časový limit môžu beh ukončiť ako neúspešný. Prerušenie ukončí iba
zberač spustený týmto príkazom; VM a premávka zostávajú pod `labctl`.
Tento beh nenahrádza plánovaný zber korpusu cez `scripts/collection.py`.

Zberač tu beží s predvolenými nastaveniami výstupu (`output.fsync=true`,
`output.mlock=false`), nie s nastaveniami kampane. Od verzie 1.1 zapisuje
súbory vlákno mimo vzorkovacieho cyklu, takže `fsync` predlžuje zverejnenie
snímky (sidecar), nie cyklus; nasledovník na chýbajúci sidecar čaká najviac
15 s. Táto kombinácia nebola na zberovom PC meraná. Po SIGTERM dostane zberač
60 s na zápis snímok z fronty, potom SIGKILL.

## Stav, alarm a dôkazy

`status` číta uložený JSON priebehu. Po skončení spoločného behu prednostne
zobrazí `result.json` vrátane výsledku zberača. Počas behu číta
`detector/status.json`; pri samostatnom prehrávaní alebo sledovaní
`status.json`. Je to posledný zapísaný stav, nie samostatná sonda živosti
procesu. Surové snímky spoločného behu sú v `raw/`, výstup zberača
v `collector.log`, konfigurácia v `run.json` a ukončenie v `result.json`.

| Stav | Význam |
|---|---|
| `warming_up` | Zatiaľ nie je celé vhodné okno; modelové skóre chýba |
| `monitoring` | Vypočítané skóre a trieda aktivity |
| `input_error` | Vstup nemožno vyhodnotiť; dôvod a možnosť pokračovania sú vo výstupe |
| `alarm` | Modelové pravidlo alebo kontrola integrity má nález |

`model_state` a `integrity` sú samostatné polia. Nález integrity sa nestratí
počas zahrievania ani pri neplatnom modelovom vstupe. Chýbajúci baseline
textu jadra sa uvádza ako `inconclusive`. Stav bez nálezu nie je tvrdením,
že RAM neobsahuje útok.

Udalosti sú v `events.jsonl`; nová alarmová udalosť sa zapisuje aj do
`evidence/event-*.json`. Prehrávanie archívu aj spracovanie surových dát
ukladajú konfiguráciu do `configuration.json`. Prehrávanie má
`preserve=false`, preto uloženie opisu udalosti neznamená vykonanie HOLD.
Pri sledovaní a spoločnom zbere HOLD zachováva
reťazce kontextu alarmu; výsledok príkazu je súčasťou záznamu a chyba sa
neskrýva. Fyzické biny majú samostatné chyby predikcie. Vypnutie VM,
odpojenie siete ani spustenie C reakčného hooku táto integrácia nevykonáva.

Pri surových snímkach sa zaznamenáva čas extrakcie a celého spracovania.
`snapshot_age_ms` zahŕňa vek snímky a prípadný backlog; pri prehrávaní
starých dát nie je latenciou detekcie. Tieto polia ešte nenahrádzajú
dlhodobé meranie časovania, spotreby zdrojov a vplyvu na služby hosťa.

## Čo zostáva experimentálne overiť

- Nazbierať benígny korpus s oddelenými bootmi a rolami; pilotný audit je prijatý.
- Natrénovať modely nad touto prevádzkou a zmraziť kalibráciu pred testami.
- Overiť spoločný hostiteľský zber a detektor vrátane dlhého reťazca a backlogu.
- Porovnať TCN s alternatívami a vyhodnotiť klasifikáciu aj falošné alarmy.
- V oddelenom izolovanom prostredí vyhodnotiť aktivované útoky a reálny malvér.

Presnosť voči reálnym malvérovým vzorkám nebola meraná touto integračnou
skúškou. Označenie „day-0“ pomenúva zamýšľaný experiment s neznámym
správaním, nie záruku jeho zachytenia.
