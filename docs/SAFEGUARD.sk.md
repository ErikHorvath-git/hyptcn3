# Safeguard: zber, modely a detektor na hostiteľovi

Balík [`safeguard/`](../safeguard/) spája príznaky, normalizáciu, tréning,
uloženie modelov a detektor pod `python3 -m safeguard`. Softvérová cesta je
implementovaná; jej overovanie rozlišuje syntetický test, prehratie uložených
dát a nový beh nad VM. Diagnostický model nie je modelom natrénovaným na
serverovom korpuse. Účinnosť proti útokom, falošné alarmy na odloženom teste a pri dlhšej
živej prevádzke a vplyv celého detektora na VM ešte neboli touto integráciou vyhodnotené.

Na zberovom PC audit prijal piloty 3 až 7 podľa [`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md)
(posledný [pilot 7](../data/results/collection_pilot_7_20261026_audit.json), stav v
[`PRIPRAVENOST_KAMPANE.sk.md`](PRIPRAVENOST_KAMPANE.sk.md)). Pilot pôvodného PC má
[prijatý audit](../data/results/collection_pilot_v2_20261013_reaudit.json); pre zberové PC sa nepoužije.
Kampane `benign-v2-20261022` až `benign-v5-20261025` sa uzavreli bez úplného korpusu.
Benígny korpus `benign-v6-20261026` vyšiel z pilota 7 a je nazbieraný: audit prijal
48 {{res:collection_campaign_benign_v6_20261026.json:values.summary.accepted_sessions}}
session ([záznam](../data/results/collection_campaign_benign_v6_20261026.json), [MERANIA.md](MERANIA.md)). Balík modelov
z neho je natrénovaný, vyhodnotený na vývojovej role `dev`, ktorá vyberala jeho checkpointy
(časť [Natrénovaný balík a rola dev](#natrénovaný-balík-a-rola-dev)), a 2026-11-04 raz záverečne na
`test_benign` ([`MERANIA.md`](MERANIA.md)); test pri prevádzkových poruchách a údržbe zostáva.
Automatický zber a archiváciu korpusu riadi
[`scripts/campaign.py`](../scripts/campaign.py); postup je v
[`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md).
Nový spoločný beh `run` s hostiteľským eBPF zberom je
zatiaľ **UNVERIFIED**; staršie overenie samostatného zberača ho nenahrádza.
Výstupy vykonaných overení sa evidujú v [`MERANIA.md`](MERANIA.md).
Integračný záznam
[`safeguard_validation_20261013_a.json`](../data/results/safeguard_validation_20261013_a.json)
(syntetický model, zhoda spracovania uložených RAM dát) vznikol ešte
s kontraktom `hyptcn3/safeguard-features/1`; aktuálny kontrakt zaviedol commit
`6fcd6f9`. Pre aktuálny kontrakt sa prehratie uložených RAM dát zatiaľ nezopakovalo.

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
| `safeguard/model.py` | Prediktor globálnych a per-bin príznakov; klasifikátor záťaže; bloky TCN z `tcn/model.py` |
| `safeguard/training.py` | Explicitné roly korpusu, tréning, výber checkpointu a kalibrácia |
| `safeguard/bundle.py` | Manifest, načítanie váh a spoločné skórovanie okna |
| `safeguard/runtime.py` | Stav detektora, alarmy, uchovanie dôkazov a čítanie pribúdajúcich snímok |
| `safeguard/supervisor.py` | Vlastný proces zberača, zámok zberu a kontrola disku |
| `safeguard/demo.py` | Syntetický korpus a príkaz `smoke` |
| `safeguard/cli.py` | Príkazové rozhranie |

## Príznaky, tréning a načítanie

Archív naďalej obsahuje pôvodných 22 stĺpcov. Model používa prvých 18
behaviorálnych stĺpcov a tenzor `čas × bin × 4`. Kontroly integrity, príznaky
úplnosti, PID a identifikátory VM nie sú číselnými vstupmi modelu. Každý bin
nesie `changed_ratio`, `zero_ratio`, `entropy_mean`, `has_changed`.

`Frame` vyžaduje štruktúrovanú kvalitu, čas a sekvenciu, identitu reťazca
a geometriu pamäte. Plná snímka, chýbajúci predchodca, neplatné meranie,
zmena session alebo reťazca aj medzera v čase či sekvencii vyprázdnia okno
aj históriu hlasovania k z n. Nerastúce časy a duplicitné sekvencie sú
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

Normalizátor vidí iba vhodné riadky role `train`, každý práve raz, a riadi sa
pravidlom normalizácie z protokolu (balík B6b, `safeguard.features.NormalizationRule`):
pod schémou 3 triedami stĺpcov z `analysis.columns` a pravidlom mierky
z `analysis.scale`, pod schémou 1 a 2 pomenovaným pravidlom `legacy_schema_2`
(všetky stĺpce, jedna spoločná mierka binov, mierka na úrovni strojového epsilonu
je 1, každý bin). Kým je `analysis.columns` `null` (pred G3a), ostrý tréning sa
odmietne a diagnostický berie pravidlo `all_neural_diagnostic` (všetky stĺpce
neurónové). Vstupom TCN sú stĺpce triedy `neural` (hodnota) a `differenced`
(prvá diferencia proti poslednému meranému riadku tej istej session, aj cez
vylúčený riadok, ako ju berie kvalifikácia); stĺpce `rule` a `rule_differenced`
idú do pravidlového kanála (pri `rule_differenced` sa posudzuje zmena od prvého
meraného riadka session, otázka Q8, prijaté vedúcim 2026-11-24) a `dropped` nikam.
Mierka stĺpca je aspoň jeho dolná hranica (pri počtoch jedna jednotka). Bin s menej
ako `min_bin_pages` stránkami sa nefituje ani neskóruje; z tých istých binov s aspoň
`min_bin_pages` stránkami počíta extraktor aj všetkých osem globálnych pamäťových
stĺpcov vrátane `mem_bins_active` (jeden predikát `features.snapshot.counted_bin` pre
extraktor aj normalizér, odpoveď vedúceho na otázku Q10 z 2026-11-24): audit
s hodnotou z protokolu, živý beh s hodnotou z balíka (`Bundle.min_bin_pages`), pod
schémou 1 a 2 z každého binu. Jedna zmenená stránka binu s jednou stránkou tak nikdy
nedá `mem_changed_max` 1,0. Hodnota nemá predvolenú hodnotu a sidecar bez takého
binu je chyba extrakcie. Každý ďalší bin má pri `per_bin` vlastnú mierku. Entropia
sa fituje iba tam, kde `has_changed=1`; pri transformácii má nemeraná entropia
hodnotu nula a maska sa nemení. Pravidlo ide s parametrami do manifestu a pri
prehrávaní ani živom skórovaní sa nič znovu nefituje. Okno s diferencovaným
vstupom potrebuje aj meraný riadok pred sebou, takže na začiatku session
`window_rows + 1` meraných riadkov (po bariére vnútri session stačí znova
`window_rows`).

Prediktor používa všetky kroky okna okrem posledného a predpovedá posledný
krok. Maska merania sa nepredikuje. Chyba entropie sa započíta iba pri
pozorovanej entropii cieľového binu. Aktuálna verzia má skóre určené vzorcom:

```text
0.5 × priemerná štvorcová chyba vstupných stĺpcov TCN
  + 0.5 × maximum maskovanej priemernej štvorcovej chyby skórovaných binov
```

Skóre nesie `attribution`: chybu každého vstupného stĺpca (ich súčet je globálna
časť), každého skórovaného binu s počtom stránok, najhorší bin (jeho chyba je
binová časť skóre) a priemer troch najhorších binov (citlivostná analýza). Balík
so vzorcom spred balíka B6b sa odmietne.

Klasifikátor používa globálne príznaky spolu s priemerom a maximom lokálnych
príznakov cez biny. Jeho triedami sú zaznamenané profily záťaže. Výstup
`activity` nie je klasifikácia škodlivosti ani identifikácia rodiny malvéru.
Priradenie chyby fyzickému binu samo neidentifikuje vinný proces.

Tréning číta index `hyptcn3/corpus-index/1` a overuje hashe aj provenienciu.
`train` určuje váhy a normalizáciu, `dev` vyberá checkpointy prediktora
a klasifikátora, `calibration` nastaví prah. Pole príznakov `test_benign`
sa počas tréningu nenačíta. Boot/skupina nesmie patriť viacerým rolám.

`--fpr` určuje kvantil benígnych skóre, nie garantovaný počet alarmov za
hodinu. Nadprahové skóre znamená `score > threshold`. Alarm modelu (neurónový
kanál, zdroj `model_anomaly`) vyžaduje aspoň `k` prekročení v posledných `n`
skóre, až keď je celá história dostupná. Pravidlový kanál posúdi každý meraný
riadok: hodnota stĺpca triedy `rule` alebo zmena stĺpca triedy `rule_differenced`
od prvého meraného riadka session mimo rozsahu z `train` a `calibration` je
prekročenie (iná stála úroveň v novom boote teda nie je prekročenie, trvalý krok
áno; stav prítomný už v prvom meranom riadku session toto pravidlo nevidí a v živom
behu je prvým riadkom prvý riadok po štarte detektora, čo manifest uvádza medzi
obmedzeniami, odpoveď vedúceho na otázku Q8 z 2026-11-24) a alarm
je to isté pravidlo `k` z `n` s vlastnou históriou a tými istými resetmi (zdroj
`rule_anomaly`); nikdy sa neuvádza ako neurónová detekcia. Každý riadok nesie
`channel`: kanály (`rule`, `neural`, `kernel_integrity`), ktorých alarm je na ňom
zapnutý.
Kalibrácia eviduje aj udalosti pravidla k z n; nezávislé FAR sa meria až na
odloženom teste. FAR za hodinu z udalostí safeguardu počíta `python3 -m tcn.eval far`
(časť Príkazy); čas do detekcie zatiaľ nepočíta žiadny kód. Po vyhodnotení testu sa
prah neladí podľa jeho výsledku.

Nový adresár modelu obsahuje `manifest.json`, `predictor.pt` a `classifier.pt`.
Manifest ukladá poradie príznakov, biny, geometriu, okno, normalizáciu s jej
pravidlom, architektúru, triedy, vzorce skórovania, kalibráciu, rozsahy
pravidlového kanála (pri stĺpci `rule_differenced` aj s obmedzením z otázky Q8,
ktoré je potom aj v `limitations`), vopred zapísané znenie pre prípad, že všetku
detekciu nesie pravidlový kanál (`analysis_wording.rule_channel_only`, doslovne
z kap. 8.2 návrhu, so zdrojom potvrdeným vedúcim 2026-11-24, otázka Q6), hashe váh
a provenienciu.
Načítanie overí kompatibilitu a kontrolné súčty. Hashe chránia pred zmenou
súborov oproti manifestu; neoverujú pôvod balíka od neznámeho autora.

## Príkazy

Príkazy sa spúšťajú z koreňa repozitára. Globálna voľba `--threads N` pred
podpríkazom (predvolene 4) určuje počet vlákien PyTorch. Pri vytváraní
výstupu musí `--out` označovať nový adresár; `status` číta existujúci výstup.
Cesty v ukážkach sú ilustračné; index prijatého korpusu `benign-v6-20261026` je na
zberovom PC v `data/campaigns/benign-v6-20261026/corpus.json` a balík z jeho tréningu
v `data/models/server-v2-benign-v6` (oba adresáre sú mimo gitu).

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
bežný tréning odmietne. Audit, ktorého `extractor_sha256` sa líši od súčasného
kódu `features/` a `guestparse/`, tréning tiež odmietne (`stale extractor
implementation`); surové dáta treba znovu auditovať
([KONTROLA_ZBERU.sk.md](KONTROLA_ZBERU.sk.md)). Tréning odmietne aj audit bez uloženého
verdiktu prijatia (`values.acceptance`) a audit, ktorého verdikt sa líši od rozhodnutia
`features/acceptance.py` nad uloženými faktami alebo session neprijíma; roly `train`,
`dev` a `calibration` pred fitovaním rozhodne znova aj z archívu príznakov. `--diagnostic`
je výslovný režim skúšania mechaniky; nenahrádza splnenie podmienok finálneho korpusu.

**Konečné prehratie uložených dát:**

```sh
python3 -m safeguard replay --bundle data/models/server-v2 --archive data/collections/SESSION/audit_TIMESTAMP.npz --out data/safeguard/replay-01
python3 -m safeguard replay --bundle data/models/server-v2 --snapshots data/collections/SESSION/raw --profile data/collections/SESSION/profile --out data/safeguard/replay-raw-01
```

`replay` nemení retenciu surových dát a nespúšťa zberač. Pre diagnostický
balík treba pridať `--allow-diagnostic`. Rozloženie a vstupný kontrakt musia
sedieť aj v diagnostickom režime. Session archivovaná kampaňou má v `raw/`
odkaz na komprimované snímky `.vmicd.zst`, ktoré `replay` nečíta. Najprv ju
obnov do nového adresára `raw` a vedľa neho skopíruj `session.json`
(`scripts.collection_archive restore`, postup v
[AUTOMATICKY_ZBER.sk.md](AUTOMATICKY_ZBER.sk.md)); potom použi
`--snapshots <nový>/raw`.

Príkaz skončí kódom 0, keď `status.json` nesie `ok=true`, a kódom 2, keď nesie
`ok=false` alebo keď príkaz chybu zachytí skôr, než `status.json` vznikne. Prázdny
alebo skrátený súbor archívu medzi zachytené chyby nepatrí: príkaz vtedy skončí
výnimkou s kódom 1 a `status.json` nezapíše. Prerušenie z klávesnice končí kódom 130.
Neplatný riadok archívu detektor neskóruje a zapíše ho ako `input_error` s dôvodom
`invalid_input`. Prehratie archívu (`--archive`) číta pravidlo `invalid_rows`
z protokolu, ktorý je v manifeste balíka (`provenance.protocol`). Keď sú všetky
chyby vstupu iba také riadky a pravidlo ich toleruje (počet najviac `max`, neuzavretý
iba prechod z `traversals`, žiadna chyba čítania ani doplnené nuly), prehratie končí
`ok=true` a ich počet uvádza `tolerated_invalid_rows`; `input_errors` ich počíta
naďalej. Iná chyba vstupu, riadok mimo pravidla, neplatný riadok pri balíku bez
pravidla alebo archív bez riadkov znamená `ok=false`. Pravidlo s chybným tvarom
ukončí prehratie skôr, než vznikne výstupný adresár.

Pole `ok` je verdikt prehratia; `state` a `last` opisujú iba posledný riadok. Stav
s `ok=true` môže niesť `input_errors` väčšie než nula (tolerované riadky) a, keď je
tolerovaný riadok posledný, aj `state` `input_error`. Verdikt porovnáva riadky
prehratia s pravidlom protokolu balíka. Audit session prehratie nečíta: nezisťuje, či
audit ten riadok uviedol ani či balík vznikol z korpusu tejto session. Tolerovaný
riadok zruší okno aj hlasy pravidla k z n; alarm modelu, ktorý trval cez taký riadok,
sa po novom naplnení okna a hlasov počíta ako ďalšia alarmová udalosť. Schéma
`status.json` sa nezmenila a stav zapísaný starším kódom pole `tolerated_invalid_rows`
nemá. To isté pravidlo (`features/quality.py`) uplatňuje rozhodnutie o prijatí session
(`features/acceptance.py`), ktoré používa audit session, stavba korpusu, index udalostí
kampane, tréning aj základné metódy `tcn/porovnanie.py`; pilotu a session s rolou, ktorú
protokol nepriraďuje, netoleruje žiadny neplatný riadok. Základné metódy pravidlo uplatňujú
aj pri svojom prehratí (`python3 -m tcn.porovnanie replay` rozhoduje o `ok` rovnako, chybu
čítania archívu a chybné pravidlo však nezachytáva a končí výnimkou). Prehratie surových snímok
(`--snapshots`), `watch` ani `run` pravidlo neuplatňujú: každá chyba vstupu tam
znamená `ok=false`.

**Vyhodnotenie FAR a klasifikátora z prehratí:**

```sh
python3 -m tcn.eval far --corpus data/campaigns/benign-v6-20261026/corpus.json --role dev --replay data/safeguard/far-dev-benign-v6/* --campaign data/results/collection_campaign_benign_v6_20261026.json --out data/results/safeguard_far_dev_NAZOV.json
```

`tcn.eval far` (`tcn/eval.py`) číta výstupy `replay --archive` všetkých session jednej
roly korpusu, `dev` alebo `test_benign`, a počíta veličiny benígnej prevádzky
z [`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md), kap. 7. Prehratie surových snímok
(`--snapshots`) neprijme. Prehratie priradí k session indexu podľa SHA-256 archívu.
Skončí chybou, keď index nie je úplný; keď archív nepatrí session tejto roly alebo
session chýba, je prehratá dvakrát či nie celá (prehratie musí skončiť `replay_complete`
a pokryť session od začiatku po koniec); keď prehratia použili rôzne balíky,
diagnostický balík, balík z iného indexu alebo s inou dĺžkou okna či maximálnou
medzerou než protokol indexu; keď `status.json` nesedí s `events.jsonl`; aj keď
prehratie obsahuje chybu vstupu, ktorú pravidlo `invalid_rows` protokolu indexu
netoleruje.

`test_benign` vyhodnotí iba s `--final` a `--final` platí iba pre `test_benign`.
Vyžaduje git a `tcn/eval.py` bez neuložených zmien a beží raz na korpus: po vytvorení
`--out` vytvorí vedľa indexu záznam s menom indexu a príponou `.test_benign-final.json`
a pri ďalšom pokuse skončí chybou, lebo záznam už existuje (prázdny `--out` vtedy zmaže).
Je to poistka postupu, nie dôkaz: po zmazaní záznamu sa dá spustiť znova. Keď `--out`
existuje alebo jeho adresár chýba, príkaz skončí skôr, než záznam vznikne, a záverečné
spustenie sa nespotrebuje. Existujúci `--out` sa neprepíše nikdy. `--campaign` doplní
plánované, prijaté a zamietnuté session zo záznamu kampane, `--alfa` mení hladinu
intervalov.

Výsledok má schému `hyptcn3/safeguard-far/2`, hlavičku podľa
[`HONESTY.md`](../HONESTY.md), kap. 4, a navyše `commit_dirty`, `evaluator_sha256`
a `cwd`. Pod `values.merane` sú alarmové udalosti modelu (riadky s `alarm_event`
a zdrojom `model_anomaly`, teda nábežné hrany pravidla k z n, nie okná nad prahom),
FAR za hodinu sledovaného aj skórovaného času s exaktným Garwoodovým intervalom,
podiel času bez skóre a Pearsonov test rozptylu udalostí medzi session; spolu,
po skupinách a po scenároch. Počty udalostí integrity, výpadkov senzora a chýb vstupu
sú v `values.dane_prijatim_korpusu` bez intervalu: prijatie do korpusu zamieta session
s nálezom integrity, medzerou, chybou čítania alebo neplatným riadkom mimo pravidla
`invalid_rows` protokolu, takže tieto počty nie sú meraním detektora; počty neuzavretých
kontrol integrity sú tam tiež. Riadok tolerovaný tým pravidlom detektor neskóruje:
prehratie ho uvádza ako chybu vstupu, vyhodnotenie ho počíta v `chyb_vstupu` aj
v `neplatnych_riadkov` a okná s ním sú v podiele času bez skóre. Schéma výsledku
sa s poľom `neplatnych_riadkov` nezmenila; výsledok zapísaný starším kódom ho nemá.
`tcn.eval udalosti` (FAR počas prevádzkových udalostí) odmieta prehratie pre tie isté
dve príčiny (`status.json` nesedí s `events.jsonl`, chyba vstupu mimo pravidla)
a počty chýb vstupu a neplatných riadkov (`chyb_vstupu`, `neplatnych_riadkov`) uvádza
vo `values.dane_prijatim_relacii`. Tie počty sú za celé session: zahŕňajú aj riadok
vo vylúčenom úseku (udalosť bez dôkazu a jej dozvuk), ktorý nie je v čase žiadnej
kategórie.
`values.klasifikacia_aktivit` hodnotí klasifikátor profilu záťaže (trieda okna je scenár
jeho session): presnosť a macro-F1 na okná, metriky tried, maticu zámen a počet session
so správnou väčšinovou predikciou s Clopperovým-Pearsonovým intervalom, lebo okná jednej
session nie sú nezávislé. `values.zdroje_udalosti` uvádza, či sa súbory skórovania
zhodujú s provenienciou balíka, `values.relacie` nesie výsledky a SHA-256 súborov
každého prehratia. Čas do detekcie ani detekciu útokov z výsledku odvodiť nemožno.

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

`run` potrebuje oprávnenie na eBPF a bežiacu VM; `PYTHONPATH` v ukážke sprístupní
pod `sudo` lokálnu inštaláciu PyTorch v používateľskom site-packages. Na zberovom
PC, kde systémový `python3` nemá NumPy, sa namiesto toho spustí
`sudo .venv/bin/python -m safeguard run` s rovnakými voľbami.
Vyžaduje model z reálneho korpusu; diagnostický balík sa odmietne a príkaz nemá voľbu
`--allow-diagnostic`. Pred zberom sa kontroluje protokol, jadro
a serverový stack hosťa, profil, implementácia extrakcie a skórovania aj binárka zberača
proti proveniencii modelu. Nekompatibilita je dôvodom skončiť s chybou.

Beh je konečný: počet cyklov preberá z protokolu, prípadne z `--cycles`.
Zdieľa zámok s výskumným runnerom a nesmie s ním súbežne zbierať. Rezerva
disku a časový limit môžu beh ukončiť ako neúspešný. Prerušenie ukončí iba
zberač spustený týmto príkazom; VM a premávka zostávajú pod `labctl`.
Tento beh nenahrádza zber korpusu kampaňou (`scripts/campaign.py`, `scripts/collection.py`).

Zberač tu beží s predvoleným `output.fsync=true` (kampaň zapisuje bez `fsync`),
s frontou uzamknutou cez `output.mlock=true` ako v kampani a s `output.drain_s=90`
(v kampani 180 s); kroky `prefault` a synchronizácie hodín hosťa tu nie sú.
Od verzie 1.1 zapisuje súbory vlákno mimo vzorkovacieho cyklu, takže `fsync`
predlžuje zverejnenie snímky (sidecar), nie cyklus; nasledovník na chýbajúci
sidecar čaká najviac 15 s. Táto kombinácia nebola na zberovom PC meraná. Po
SIGTERM dostane zberač 60 s na zápis snímok z fronty, potom SIGKILL.

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

## Natrénovaný balík a rola dev

Balík `server-v2-benign-v6` vznikol 2026-10-29 na zberovom PC z čistého stromu v commite
`51d512d`:

```sh
.venv/bin/python -m safeguard train --corpus data/campaigns/benign-v6-20261026/corpus.json --out data/models/server-v2-benign-v6 --epochs 10 --seed 0
```

Adresár balíka je mimo gitu a zostal na zberovom PC. Záznam tréningu s celým manifestom je
[`safeguard_train_benign_v6_20261029.json`](../data/results/safeguard_train_benign_v6_20261029.json).
Tréning použil 36 {{res:safeguard_train_benign_v6_20261029.json:n}} session:
18 {{res:safeguard_train_benign_v6_20261029.json:values.sessions_by_role.train}} roly `train`,
6 {{res:safeguard_train_benign_v6_20261029.json:values.sessions_by_role.dev}} roly `dev`
a 12 {{res:safeguard_train_benign_v6_20261029.json:values.sessions_by_role.calibration}} roly `calibration`;
polia príznakov
12 {{res:safeguard_train_benign_v6_20261029.json:values.sessions_by_role.test_benign}}
session `test_benign` nenačítal (`test_feature_arrays_loaded` je `false`). Okien bolo
11808 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.windows.train}}
v `train`,
3936 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.windows.dev}}
v `dev` a
7872 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.windows.calibration}}
v `calibration`. Strata predikcie na `dev` klesala v každej epoche, z
0.330 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.history.0.dev_prediction_loss}}
na
0.274 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.history.9.dev_prediction_loss}};
checkpoint prediktora je z epochy
10 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.selected_predictor_epoch}}.
Strata klasifikátora na `dev` bola najnižšia po prvej epoche,
1.82 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.history.0.dev_classification_loss}},
a v každej ďalšej vyššia, kým na `train` klesla z
0.467 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.history.0.train_classification_loss}}
na
0.0123 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.history.9.train_classification_loss}}:
klasifikátor sa pretrénoval a jeho checkpoint je z epochy
1 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.selected_classifier_epoch}}.

Kalibrácia na role `calibration` nastavila prah
14.43 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.threshold}}
ako kvantil benígnych skóre pre `--fpr`
0.01 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.fpr_design}},
s pravidlom `k`
3 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.k}}
z `n`
5 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.n}}.
Nad prahom bol podiel
0.0099 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.window_exceedance_fraction}}
zo
7872 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.n_scores}}
skóre a pravidlo dalo
1 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.alarm_events}}
udalosť za
10.93 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.scorable_hours}}
skórovaných hodín, teda
0.0915 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.calibration.calibration_alarm_events_per_hour}}
za hodinu. Je to frekvencia na dátach, z ktorých vznikol prah, nie FAR.

Prehratia všetkých
6 {{res:safeguard_far_dev_benign_v6_20261029_b.json:n}}
session roly `dev` týmto balíkom (`safeguard replay --archive`, výstupy zostali na zberovom
PC v `data/safeguard/far-dev-benign-v6/`) vyhodnotil `tcn.eval far` v commite `591a061` iba
pre FAR ([záznam](../data/results/safeguard_far_dev_benign_v6_20261029.json), schéma `/1`)
a v commite `a1a4b9b` aj s klasifikátorom
([záznam](../data/results/safeguard_far_dev_benign_v6_20261029_b.json), schéma `/2`);
časť FAR je v oboch záznamoch zhodná. Hashe váh vo výsledku sa zhodujú so záznamom tréningu.
Rola `dev` má
1 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.skupin}}
skupinu (boot) a
4320 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.spolu.riadkov}}
riadkov, v každej session
656 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.relacie.benign-v6-20261026_19_dev_steady.skorovanych}}
skórovaných zo
720 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.relacie.benign-v6-20261026_19_dev_steady.riadkov}}.
Model dal
1 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.spolu.udalosti_model}}
alarmovú udalosť, v session `benign-v6-20261026_19_dev_steady`
2555 s {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.relacie.benign-v6-20261026_19_dev_steady.casy_udalosti_model_s.0}}
po jej začiatku. Skórovaný čas bol
19680 s {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.spolu.skorovany_s}}
z
21600 s {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.spolu.sledovany_s}}
sledovaného; podiel času bez skóre
0.089 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.spolu.bez_skore_cas_podiel}}
pripadá na zahrievanie okna po plnej snímke na začiatku oboch reťazcov každej session.
FAR modelu bol
0.183 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.far_h.skorovany.udalosti_h}}
udalosti za skórovanú hodinu (interval
0.0046 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.far_h.skorovany.dolna_h}}
až
1.019 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.far_h.skorovany.horna_h}})
a
0.167 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.far_h.sledovany.udalosti_h}}
za sledovanú hodinu (interval
0.0042 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.far_h.sledovany.dolna_h}}
až
0.929 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.far_h.sledovany.horna_h}});
interval je obojstranný exaktný Garwoodov pri alfa
0.05 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.alfa}},
predpokladá nezávislé udalosti a variabilitu medzi bootmi neobsahuje. Test rozptylu medzi
session (X²
5.0 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.disperzia.x2}},
df
5 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.disperzia.df}},
p
0.42 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.merane.spolu.disperzia.p}})
pri jedinej udalosti nič nehovorí. Udalosti integrity
(0 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.udalosti_integrita}}),
výpadky
(0 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.vypadkov}})
a chyby vstupu
(0 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.chyb_vstupu}})
sú dané prijatím do korpusu, nie meraním detektora. Kontrola textu jadra bola neuzavretá
vo všetkých
4320 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.integrita_neuzavrete.text_integrity}}
riadkoch (L18 v [LIMITACIE.md](LIMITACIE.md)) a krížový pohľad na procesy v
5 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.integrita_neuzavrete.process_cross_view}},
takže všetky kontroly integrity nemal uzavreté ani jeden riadok
(0 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.integrita_uzavretych_riadkov}}).
Súbory skórovania (`values.zdroje_udalosti`) sa zhodovali s provenienciou balíka.

Klasifikátor profilu záťaže mal na `dev` presnosť na okná
0.663 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.presnost}}
a macro-F1
0.607 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.f1_macro}}
nad
3936 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.n}}
oknami; väčšinová predikcia sedela v
4 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.relacie.spravnych}}
zo
6 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.relacie.spolu}}
session (Clopperov-Pearsonov interval
0.223 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.relacie.interval.0}}
až
0.957 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.relacie.interval.1}}).
`quiet`, `bursty` a `read_heavy` rozpoznal vo všetkých oknách. Negatívny výsledok:
z
656 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.na_triedu.steady.n}}
okien `steady` nerozpoznal ani jedno,
653 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.4.3}}
označil ako `read_heavy`; z
656 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.na_triedu.mixed.n}}
okien `mixed` označil
368 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.1.5}}
ako `write_heavy` a správne
286 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.1.1}},
z
656 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.na_triedu.write_heavy.n}}
okien `write_heavy`
299 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.5.1}}
ako `mixed` a správne
356 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.5.5}}.
Väčšinová predikcia session `steady` bola `read_heavy` a session `mixed` `write_heavy`.
Trieda je zaznamenané nastavenie záťaže session, nie škodlivosť ani rodina malvéru.

Rola `dev` vyberala checkpointy prediktora aj klasifikátora, preto toto FAR ani presnosť
klasifikátora nie sú odložené a nie sú záverečným výsledkom. Záverečné čísla dá jediné
spustenie s `--final` nad prehratiami
12 {{res:safeguard_train_benign_v6_20261029.json:values.sessions_by_role.test_benign}}
session `test_benign` v
2 {{res:safeguard_train_benign_v6_20261029.json:values.manifest.provenance.protocol.roles.test_benign}}
skupinách. Prebehlo 2026-11-04 ([záznam](../data/results/safeguard_far_test_benign_v6_20261104.json)):
1 {{res:safeguard_far_test_benign_v6_20261104.json:values.merane.spolu.spolu.udalosti_model}}
udalosť modelu, FAR
0.0915 {{res:safeguard_far_test_benign_v6_20261104.json:values.merane.spolu.far_h.skorovany.udalosti_h}}
za skórovanú hodinu (Garwood do
0.510 {{res:safeguard_far_test_benign_v6_20261104.json:values.merane.spolu.far_h.skorovany.horna_h}}
), klasifikátor správne v
5 {{res:safeguard_far_test_benign_v6_20261104.json:values.klasifikacia_aktivit.relacie.spravnych}}
z
12 {{res:safeguard_far_test_benign_v6_20261104.json:values.klasifikacia_aktivit.relacie.spolu}}
session. Ani v `dev`, ani v `test_benign` útok nebežal: detekciu útokov ani malvéru tieto
čísla nemerajú ([`HONESTY.md`](../HONESTY.md), P4).

## Čo zostáva experimentálne overiť

- Zmerať falošné alarmy balíka `server-v2-benign-v6` pri prevádzkových poruchách a údržbe
  ([`NAVRH_PROTOKOL_V3.sk.md`](NAVRH_PROTOKOL_V3.sk.md)); kalibrácia je uložená v manifeste
  balíka a podľa záverečného testu sa neladí.
- Overiť spoločný hostiteľský zber a detektor vrátane dlhého reťazca a backlogu.
- Porovnať TCN s alternatívami nad rovnakými rolami a vstupmi.
  Baseliny v `tcn/baselines.py` a metriky `tcn.eval.vyhodnot` používa iba
  diagnostické CLI `tcn.train` staršej 22-stĺpcovej cesty; na vstupy safeguardu
  ich zatiaľ nenapája žiadny runner.
- V oddelenom izolovanom prostredí vyhodnotiť aktivované útoky a reálny malvér;
  čas do detekcie a podiel detegovaných incidentov zatiaľ nepočíta žiadny kód.

Presnosť voči reálnym malvérovým vzorkám nebola meraná touto integračnou
skúškou. Označenie „day-0“ pomenúva zamýšľaný experiment s neznámym
správaním, nie záruku jeho zachytenia.
