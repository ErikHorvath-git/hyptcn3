# Metodika zberu RAM a príznakov — protokol server-normal-v2

Tento dokument uzatvára **návrh zberu**, nie výsledky detekcie. Časy,
počty behov a hranice prijatia nižšie sú plánované parametre. Stav protokolu
je `pilot_required`: dlhý zber nesmie začať bez prijatého pilotného auditu.
Účinnosť safeguardu, online latencia a vplyv na VM sa merajú v ďalšej etape.

Strojovo čitateľná konfigurácia: [`config/collection-v2.json`](../config/collection-v2.json).
Zber a audit jednej session: [`scripts/collection.py`](../scripts/collection.py);
celá kampaň: [`scripts/campaign.py`](../scripts/campaign.py).
Implementovaný tréning, načítanie a detektor:
[`SAFEGUARD.sk.md`](SAFEGUARD.sk.md), CLI `python3 -m safeguard`; vyhodnotenie FAR
a klasifikátora z prehratí: `python3 -m tcn.eval far`.
Rozhodnutia platia pre jednu konfiguráciu Linux/QEMU/KVM; prenos na iné jadro,
veľkosť RAM alebo iný serverový stack je osobitný experiment.

Verzia v2 vznikla po zamietnutom pilote v1, opísanom v `MERANIA.md`.
Oddeľuje platnosť behaviorálnych vstupov od dostupnosti nezávislých kontrol
integrity. Dĺžka okna, perióda, rotácia, hranica pokrytia aj zákaz dopĺňania
chýbajúcich vstupov zostávajú rovnaké. Pôvodná konfigurácia v1 a jej zamietnutý
audit sú zachované; prehratie starých dát slúži iba na diagnostiku zmeny.
Prijatie v2 vyžaduje nový pilot zozbieraný podľa jeho vopred uloženého protokolu.
Pilot z pôvodného PC má [prijatý audit](../data/results/collection_pilot_v2_20261013_reaudit.json)
po oprave výberu aktuálneho jadra z RAM; priebeh a pôvodné zamietnutia zachováva
`MERANIA.md`. Tento audit nedokazuje pripravenosť zberového PC z 2026-10-20:
iný hostiteľ, disky, VM, logovanie aj kód runnera. Kampaň na ňom potrebuje nový
pilot s vlastným auditom. Na zberovom PC audit prijal piloty 3 až 7 (posledný
[pilot 7](../data/results/collection_pilot_7_20261026_audit.json)); z pilota 7
vyšla kampaň `benign-v6-20261026`, ktorá prijala všetkých
48 {{res:collection_campaign_benign_v6_20261026.json:values.accepted_sessions}}
session plánu a vytvorila úplný index korpusu
([záznam](../data/results/collection_campaign_benign_v6_20261026.json),
[MERANIA.md](MERANIA.md) 2026-10-29). Po zmene meracieho kódu `pilot_gate`
v `scripts/campaign.py` starší pilot odmietne a treba nový (stav
v [`PRIPRAVENOST_KAMPANE.sk.md`](PRIPRAVENOST_KAMPANE.sk.md)).
Konfigurácia sa neprepisuje na `accepted`: splnenie podmienky sa dokladá
konkrétnym auditom, ktorý sa podá cez `--pilot-report`.

## 1. Otázky experimentu a jednotka merania

Hlavná otázka: vie model naučený na normálnej prevádzke rozlíšiť odchýlky
v RAM počas rovnakej serverovej prevádzky pri prijateľnom počte falošných alarmov?
Vysoké skóre pri prechode z prázdnej VM na server nie je odpoveďou na túto otázku.

- **Snímka:** postupné čítanie RAM bez zastavenia VM, s časom začiatku a dobou čítania.
  Nie je atómovým obrazom všetkých CPU. Súbežné zmeny môžu spôsobiť neuzavretý prechod.
- **Okno:** po sebe idúce platné delta snímky jedného behu; nesmie preskočiť chybu.
- **Beh/session:** jeden súvislý zber s vopred určeným profilom záťaže, rolou a seedom.
- **Skupina:** jeden boot VM, v ktorom sa vykonajú profily záťaže. Celá skupina patrí
  jednej role. Znovuspustenie zberača nevytvorí nezávislý boot.
- **Nezávislá jednotka pre neistotu výsledkov:** skupina/beh alebo útočný incident,
  nikdy jednotlivé prekrývajúce sa okno.

## 2. Pevné nastavenia zberu

| Parameter | Návrh v protokole | Dôvod |
|---|---|---|
| Perióda | 5 s, pevný časovač | Zachovanie časového významu rozdielových príznakov |
| Maximálna medzera | 7,5 s | Vynechaný slot musí prerušiť okno |
| Bin | 16 MiB, iba podložené oblasti | Identita = fyzický index; diery sa nedopĺňajú nulami |
| Stránka | podľa zberača, kontrolovaná voči sidecaru | Zachovanie menovateľov pomerov |
| Dĺžka okna | 32 riadkov, krok 1 | Pri predikcii 31 vstupných krokov a nasledujúci cieľ |
| Plná snímka | každých 360 snímok | Obmedzenie reťazca pri zachovaní väčšiny delta okien |
| Bežný beh | 720 snímok | Približne hodina pri zvolenej perióde |
| Pilot | 480 snímok | Zachytí aj obnovu okna po ďalšej plnej snímke |
| Zahrievanie záťaže | 120 s pred začiatkom zberu | Oddelenie rozbehu generátora od hodnoteného intervalu |
| Rezerva disku | 30 GiB | Pri dosiahnutí rezervy sa zber ukončí ako neúplný |

Pri 5 s perióde pokrýva 32 riadkov interval 155 s medzi prvým a posledným
časom. To **nie je detekčné oneskorenie**. Plná snímka má iný význam
`pages_changed`; všetky okná, ktoré ju obsahujú, sa vylúčia. Po rozbehu,
rotácii reťazca a chybe vzniká čas bez skóre. Tento čas sa vykazuje a útok
v ňom sa zo záverečného vyhodnotenia neodstráni.

Tieto hodnoty sa overia pilotom. Ak dlhý reťazec nestíha spracovanie alebo
spotreba disku nevyhovuje, vznikne nová verzia protokolu a nový pilot.
Hodnoty sa nemenia uprostred korpusu. Retencia pri výskumnom zbere nemaže
snímky; súbory majú SHA-256. Výstupný adresár a výsledky sa neprepisujú.

## 3. Príznaky a ich fyzikálny význam

Archív `hyptcn3/snapshot-vektor/3` uchováva:

- `matica[T,22]` a explicitné poradie `mena`;
- `perbin[T,B,4]`, `biny[B]`, rozloženie memslotov a počet podložených stránok;
- pôvodné `seq`, `casy`, `chain_ids`, identifikátory snímok a dobu extrakcie;
- `valid`, štruktúrovanú kvalitu prechodov, nálezy kontrol a neuzavreté kontroly;
- explicitnú `quality_policy`, podľa ktorej vznikli maska aj rozdielové príznaky;
- časový kontrakt `max_medzera_s`.

| Skupina | Stĺpce | Interpretácia |
|---|---|---|
| Zmeny RAM | `mem_changed_ratio`, `mem_bins_active`, `mem_changed_max`, `mem_changed_p95`, `mem_changed_spread` | Rozsah a rozloženie zmenených stránok medzi susednými snímkami |
| Obsah RAM | `mem_entropy_mean`, `mem_entropy_max`, `mem_zero_ratio` | Entropia **zmenených** stránok a podiel nulových stránok v aktuálnom stave |
| Procesy | `proc_total`, `proc_user`, `proc_kernel`, `proc_new`, `proc_gone` | Počty a rozdiel množín PID |
| Moduly | `mod_total`, `mod_delta` | Počet a jeho rozdiel |
| Sieť | `sock_total`, `sock_listen`, `sock_estab` | Rekonštruované sokety a ich stavy |
| Integrita | `chk_syscall_hooks`, `chk_crossview` | Počty nálezov a krížových rozdielov v snímke (pred potvrdením); navyše sa uchová celý štruktúrovaný verdikt |
| Platnosť riadku | `ma_predchodcu`, `je_plna` | Metadáta, nie predikované správanie |

Lokálny vektor každého binu je v poradí `changed_ratio`, `zero_ratio`,
`entropy_mean`, `has_changed`. Pomer zmien sa počíta z celočíselných počtov,
nie z tlačeného zaokrúhleného pomeru. Entropia pri `has_changed=0` nebola
nameraná nad žiadnou zmenenou stránkou; nula musí zostať spolu s maskou.
Entropia nie je dôkaz šifrovania ani malvéru.

PID nie je stabilná identita procesu: opätovné použitie PID a proces žijúci
kratšie než perióda sa nemusia prejaviť. Počet soketov nie je počet požiadaviek.
Fyzický bin nie je proces; pripísanie oblasti procesu vyžaduje samostatné
mapovanie. Do modelu nejdú PID, adresy, boot ID, názov scenára, seed ani názov VM.

**Implementované vstupy safeguardu:** `safeguard.features.arrays()` poskytuje
18 globálnych behaviorálnych stĺpcov a celý per-bin tenzor. Kontroly integrity
a príznaky platnosti sa vyhodnocujú samostatne. Globálna TCN predpovedá
nasledujúci globálny vektor; zdieľaná lokálna TCN predpovedá príznaky každého
binu. Absolútne fyzické adresy sa neučia ako čísla. Aktuálna verzia kombinuje
polovicu globálnej priemernej štvorcovej chyby s polovicou maxima maskovaných
chýb binov; presný vzorec je súčasťou manifestu. Klasifikátor profilov záťaže
je samostatný model. Porovnanie globálnych, lokálnych a kombinovaných vstupov
ostáva experimentom na vývojovej množine pred zmrazením finálnej verzie.
Starý 22-stĺpcový prediktor zostáva diagnostickou cestou mimo nového balíka.

Normalizátor sa fituje iba na platných tréningových riadkoch, každý raz,
nie na opakovaniach v prekrývajúcich sa oknách. Pri per-bin entropii sa fit
počíta iba tam, kde je maska merania aktívna; maska sa nenormalizuje a chýbajúca
entropia sa po transformácii maskuje. Numericky konštantný príznak má
bezpečnú uloženú mierku. Rovnaký manifest
normalizácie a poradie príznakov sa musia použiť pri každom skórovaní.

## 4. Kvalita dát a jednotná tvorba okien

Tréning, prehrávanie, audit protokolu v2 a živý safeguard používajú
`safeguard.features.WindowBuffer`. Historický protokol v1 používa
`features.windows`. Pravidlá sú:

1. Overiť schému, konečné čísla, pomery, počty stránok, identitu binov a ich súčty.
2. Overiť ukotvenie profilu po KASLR ešte pred parsovaním objektov.
   Pri native zbere sa `sysctl_bootid` v RAM musí zhodovať s boot UUID,
   ktoré orchestrácia uložila pred zberom. RAM po reštarte môže obsahovať
   aj staré jadro s platným bannerom a `init_task`; prvá nájdená kópia nestačí.
   Nejednoznačná alebo chýbajúca kotva znamená chybu vstupu. Historická
   samostatná snímka bez metadát potrebuje jediného kandidáta, prípadne
   explicitný doložený `--boot-id` v CLI parsera. Boot profilu sa nepoužije
   ako identita snímky. Táto kontrola nevyberá jadro podľa počtu procesov,
   modelového skóre ani výsledku kontrol integrity.
3. Neúplný prechod procesov, modulov alebo soketov nie je normálny počet.
   Taká snímka má `behavior_valid=false` a nesmie vstúpiť do modelového okna.
   Zoznam procesov je obojsmerný: keď sa prechod dopredu roztrhne, zoznam
   tvoria uzly prejdené dopredu pred prvým spojením nezhodným s opačným
   smerom, ak sa prechod dozadu uzavrel cez presne tie isté uzly. Taký riadok
   je úplný, má `quality.process_walk = "prev"` a audit ho vykazuje
   v `process_walk_prev_seq`. Tie isté uzly tvoria zoznam aj vtedy, keď
   `init_task.prev` ukazuje práve na prvý nezhodný uzol a jeho obsah je
   vlákno (tgid ≠ pid) procesu spomedzi nich: stránka toho uzla je z iného
   okamihu ako spojenia naň (zvyškové riziko, keď taký riadok vynechá proces,
   je v L1 v [LIMITACIE.md](LIMITACIE.md)). Taký riadok má
   `quality.process_walk = "tail"` a audit ho vykazuje
   v `process_walk_tail_seq`. Samotné uzavretie prechodu nestačí
   (pozri L1 v [LIMITACIE.md](LIMITACIE.md)).
   Krížový pohľad na procesy/moduly, tabuľky volaní a text jadra nie sú vstupmi
   behaviorálneho modelu: ich `inconclusive` preto nemení jeho platnosť.
   Dostupnosť týchto kontrol a ich nálezy sa vykazujú osobitne v každom audite
   a pri každom kroku živého detektora. Nález zostáva dôvodom alarmu aj vtedy,
   keď model ešte nemá okno alebo nemôže skórovať. Krížový rozdiel je nálezom
   až po zopakovaní v bezprostredne nasledujúcej snímke; rozdiel jedinej živej
   snímky je nepotvrdený (`unconfirmed_findings`, kontrola `inconclusive`),
   audit ho vykazuje v `integrity_unconfirmed_seq` a benígnu session nezamieta.
4. Plná snímka, chýbajúci predchodca a neplatný riadok zamedzia skórovaniu okna.
5. Medzera v sekvencii alebo čase, nová session alebo reťazec prerušia
   modelový kontext a históriu hlasovania alarmu.
   Riadky sa neinterpolujú, chýbajúce čísla sa nenahradia nulami.
6. Zmena rozloženia RAM, duplicitné číslo snímky alebo nerastúci čas znamenajú
   chybu vstupu. Model sa nesmie potichu prispôsobiť inému počtu binov.

Text integrity bez čistého baseline ostáva `inconclusive`. Nemusí blokovať
behaviorálny korpus, pretože text integrity nie je jeho vstup. Blokuje však
tvrdenie o úspešnej kontrole textu jadra. Pred experimentmi integrity sa baseline
vytvorí z dôveryhodného čistého stavu príslušného bootu a overí samostatne.

Audit zamietne neúplný benígny beh; zachová jeho dáta aj dôvod. Vo výsledkoch
sa uvedie aj počet zamietnutých behov. Pri testovaní útokov sa neplatné riadky
zachovajú v časovej osi a výpadok senzora sa vykáže oddelene od skóre modelu.
Úspešnosť sa nesmie počítať iba zo vzoriek, pri ktorých parser náhodou uspel.

Politika `behavioral-inputs-v1` používa iba úplné primárne prechody a úspešné
čítanie RAM. Pri nej sa predchodca zachová aj cez neuzavretú nezávislú kontrolu,
pretože namerané množiny PID a počty modulov sú dostupné. Pri chybe primárneho
prechodu alebo čítania sa predchodca zahodí. Starý stĺpcový prediktor používa
osobitnú politiku `legacy-vector-v1` a príznak `model_valid`, ktorý vyžaduje aj
uzavreté kontroly poskytujúce jeho stĺpce integrity. Archívy týchto politík
sa nezamieňajú. Staršie archívy a balíky vyžadujú novú extrakciu/tréning;
nedostávajú spätne predpokladanú platnosť.

Úplné okno modelu neznamená úplnú kontrolu integrity. Audit uvádza počet
neuzavretých riadkov pre každú kontrolu a sekvencie neplatných vstupov modelu.
Benígny beh s nálezom integrity sa zamietne do jeho samostatného preskúmania,
aj keď sú behaviorálne vstupy úplné. Zmena dostupnosti kontroly sa nesmie
v budúcich útokových experimentoch zameniť za úspešnú detekciu.

Oprava chyby parsera nad nezmenenými surovými dátami vyžaduje nový audit
a nový archív príznakov s hashmi opraveného extraktora. Pôvodné výstupy
zostávajú zachované spolu s dôvodom opravy; nejde o nový živý zber.
Konfigurácia experimentu a pravidlá prijatia sa tým nemenia. Korpus nesmie
miešať výstupy rôznych verzií extraktora.

## 5. Rozdelenie korpusu a scenáre

Plán `make collection-plan` prideľuje všetky roly pred spustením zberu:

| Rola | Skupiny/booty | Beh každého profilu | Plánované trvanie |
|---|---|---|---|
| `train` | 3 | v každej skupine | 18 h |
| `dev` | 1 | v každej skupine | 6 h |
| `calibration` | 2 | v každej skupine | 12 h |
| `test_benign` | 2 | v každej skupine | 12 h |

Spolu je plánovaných 48 hodinových behov. Pilot, skúšky integrity, útoky
a merania réžie sú samostatné. Ide o alokáciu, nie záruku dostatočnej
štatistickej sily. Požiadavka na veľmi nízky FAR môže vyžadovať dlhší nezávislý test.

Profily `quiet`, `steady`, `bursty`, `read_heavy`, `write_heavy`, `mixed`
menia súbežnosť a pomer požiadaviek toho istého stacku nginx/auth/catalog/orders/
PostgreSQL/worker. `quiet` je nízka aktivita, nie vypnutý server. `bursty`
znamená krátke náhodné skupiny požiadaviek podľa generátora, nie kalibrovaný
model produkčných špičiek. Poradie profilov v skupine je deterministicky premiešané.
Fixný seed určuje voľby generátora; negarantuje rovnaké plánovanie vlákien alebo RAM.

Všetky roly obsahujú všetky profily. Zakázaný je experiment „idle = benign,
vyťažený server = útok“. Útoky sa neskôr párujú s benígnymi kontrolami na rovnakej
záťaži. Zálohy, kompresia, veľké legitímne zápisy, reštarty služieb a údržba
budú navyše samostatným testom falošných alarmov. Ich absencia v tréningu
sa prizná ako obmedzenie distribúcie; nemožno ich označiť za malvér.

Skupiny majú odlišné booty a nezdieľajú rolu. Pri prechode na ďalšiu skupinu
sa VM riadene reštartuje; runner ju sám nerevertuje ani nemaže databázu.
Databáza počas benígneho zberu prirodzene rastie. Je to časový drift,
ktorý sa sleduje cez požiadavky a retenčné metadáta; experiment netvrdí
identický stav disku každého behu. Zmeny aplikácie/jadra/hardvéru uprostred
kampane vyžadujú novú verziu prostredia a samostatný korpus.

Počet a typy modelov, okno, agregácia skóre a alarmové pravidlo sa určia
pred kalibráciou; prípadné porovnania používajú `dev`. Implementovaný tréner
na `dev` vyberá checkpointy. `--fpr` určuje kvantil skóre na `calibration`,
nie garantovaný FAR za hodinu. Frekvencia alarmových udalostí pravidla k z n
sa vypíše osobitne. `test_benign` sa použije raz na záverečné FAR, nie na ladenie.
Žiadne okno, boot ani interval kalibrácie nevstúpi do tréningu normalizátora.
`features.dataset` odmietne zdieľaný boot/skupinu, duplicitný archív, zmenené
hashe, zmiešané rozloženie alebo časovo premiešané roly.

Staršie CLI `tcn.train --data` má historický automatický split a slúži iba na
diagnostiku; CLI `tcn.hodnotenie` bolo 2026-10-29 odstránené.
`python3 -m safeguard train` už číta explicitné roly z nového indexu, overuje
provenienciu a nepoužíva testové polia pri fitovaní.
Spoločný balík modelov uchová normalizáciu, oba modely, kalibráciu aj kontrakt
vstupu. Diagnostický syntetický model sa nesmie zameniť za finálny tréning.
Alarmové udalosti, FAR benígnej prevádzky s intervalom a podiel času bez skóre z časti 7
aj presnosť klasifikátora profilu záťaže počíta z prehratí `python3 -m tcn.eval far`
(`tcn/eval.py`); `test_benign` vyhodnotí iba s `--final`, s commitnutým `tcn/eval.py`
a raz na korpus. Podiel detegovaných incidentov a oneskorenie od aktivácie zatiaľ
implementované nie sú.

## 6. Spustenie pilotu a prijatie dát

```sh
make lab-up
make lab-test
.venv/bin/python scripts/collection.py plan
sudo .venv/bin/python scripts/collection.py --protocol config/collection-v2.json run --role pilot --group <pilot-skupina> --scenario bursty --seed <seed>
```

Systémový `python3` na zberovom PC nemá NumPy, preto sa používa interpreter
z `.venv`; cieľ `make collection-plan` volá systémový `python3`. Piloty na
zberovom PC bežali s profilom `bursty`. Z pilota `campaign.py init` odhaduje
priestor celej kampane; náročnejší profil môže tento odhad prekročiť. Ručný
beh treba spustiť v `tmux` alebo ako dočasnú systémovú službu; zatvorený
terminál (SIGHUP) beh riadene ukončí ako neúplný.

Pilot trvá približne 40 minút zberu plus zahrievanie. Runner vypne iba trvalý
generátor tohto projektu a spustí vlastný meraný generátor. VM zostáva bežať.
Pred zahrievaním overí, že nebeží iný generátor, zmeria posun hodín hosťa
(nad 0,25 s ich synchronizuje a overí znova; audit odmietne viac ako 1 s
na začiatku aj na konci; drift pod 0,04 s/h z diagnostiky 2026-10-20 uvádza
iba komentár v `scripts/collection.py`, artefakt sa neuložil), počká, kým
`/healthz` vráti 200 (krok hodín dopredu krátko zneplatní heartbeat workera),
a vykoná funkčnú kontrolu (token, katalóg, vytvorenie a čítanie objednávky,
spracovanie workerom). Potom uzavrie
segment logov nginx a overí, že sa v ňom nájdu request ID všetkých
kontrolných požiadaviek. Zaznamená aj stav služieb a databázy. Nakoniec,
ešte pred zahrievaním, načíta späť pamäť procesu QEMU, ktorú hostiteľ odložil
do swapu (krok `prefault`; plná snímka by ju inak čítala zo swapu a prekročila
periódu). Väčšie logy
hosťa prenáša až po zbere, mimo meraného intervalu.
Nespúšťať druhý generátor, smoke test ani ďalšie úlohy vo VM počas merania.
Hostiteľské náročné úlohy, spánok hosta a zmeny konfigurácie tiež kontaminujú beh.

Runner vypíše cestu `data/collections/<session>`. Následne bez roota:

```sh
.venv/bin/python scripts/collection.py audit data/collections/<session>
```

Audit overí kontrolné súčty obrazov, konfiguráciu, počet snímok, medzery,
čítacie chyby, rotáciu reťazca, stabilnú identitu VM, kvalitu príznakov
a klientské, nginx a aplikačné logy vrátane request ID, kontrolných súčtov,
časového pokrytia a reštartov služieb. Rozpis skórovateľných okien a samostatné
príkazy bez opakovanej extrakcie sú v [KONTROLA_ZBERU.sk.md](KONTROLA_ZBERU.sk.md).
Návratový kód 0 znamená prijatie;
kód 2 znamená chybu alebo zamietnutie. Vytvorí nový JSON a NPZ; nikdy neprepíše
staré meranie. Čitateľné, ale metodicky nevyhovujúce dáta sa zachovajú pre diagnostiku.

Návrhová hranica je aspoň 85 % časových krokov so skórovateľným oknom,
žiadne chyby čítania, žiadne zmeškané sloty a každý cyklus kratší než perióda.
Cyklus je od verzie zberača 1.1 (oprava po kampani `benign-v4-20261022`)
práca vzorkovacieho vlákna: čítanie pamäte, porovnanie stránok, príznaky,
kópia zmenených stránok do fronty v pamäti a prípadné čakanie na jej pamäť
(`capture.total_ms` v sidecari); plánovač do slotu započíta aj všetko ostatné,
čo sa v cykle stane. Súbory, SHA-256, sidecar a log zapisujú vlákna
`vmic-writer` a `vmic-log` mimo cyklu. Čas po zapísané dáta snímky
(`output.data_closed_ms`, dolná hranica zverejnenia) audit vykazuje
v `values.publication`, ale nehodnotí;
čakanie na pamäť fronty zamietne vždy. Do verzie 1.0 obsahoval cyklus aj zápis
každej zmenenej stránky, premenovanie a SHA-256 súboru.
Audit je **offline**: jeho prijatie nepotvrdzuje latenciu živého detektora.
Pred nahrávaním celej kampane treba ešte skontrolovať distribúciu časov extrakcie
v audite, odhadnúť priestor celej kampane a pripraviť úložisko. Odhad priestoru
počíta `campaign.py init` z prijatého pilota a runner ho kontroluje pred každou
session. Rezerva disku je núdzové zastavenie, nie dôkaz, že sa celá kampaň
zmestí. V kampani
`benign-v6-20261026` bol medián extrakcie na snímku v prvom reťazci najviac
1.808 {{res:collection_campaign_benign_v6_20261026.json:values.summary.extraction_chain_0_p50_s_max}} s; druhý reťazec bol pomalší v session 40 a 46 a miernejšie
v 26 a 28 (extrakcia pri každej snímke prečíta celý rekonštruovaný obraz; čakanie na jeho čítanie
zo SSD je pravdepodobná, no neoverená príčina) a audit trval najviac 4659.8 {{res:collection_campaign_benign_v6_20261026.json:values.summary.audit_s_max}} s pri limite 3 h ([záznam](../data/results/collection_campaign_benign_v6_20261026.json),
[MERANIA.md](MERANIA.md) 2026-10-29).

Pre ďalšie behy sa z výpisu plánu preberú presné `role`, `group`, `scenario`
a `seed`; navyše sa zadá `--pilot-report <prijatý-audit.json>`. Runner overí
pridelenie, protokol a priestor odvodený z pilotu s rezervou. Medzi skupinami
treba nový boot. Prvý tréningový boot musí byť odlišný aj od pilotného.

Pilot pôvodného PC (`collection_pilot_v2_20261013_reaudit.json`) a jeho odhad
kapacity ([`collection_pilot_readiness_20261013_a.json`](../data/results/collection_pilot_readiness_20261013_a.json))
patria inému hostiteľovi a archívu; pre zberové PC sa nepoužijú. Tamojší odhad
prenášal objem scenára `steady` na ostatné scenáre, ktoré ho môžu prekročiť.
Na zberovom PC je pracovné úložisko SSD a archív systémový HDD (rozloženie
v [`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md)). `scripts/campaign.py`
spája zmrazený plán, reštarty skupín, zbery, audity, overené presuny
a vytvorenie indexu. Po verifikácii úplnej archívnej kópie uvoľní iba surové
pracovné súbory svojej kampane. Lokálne metadáta a príznaky ostávajú na pôvodných cestách, `raw/`
sa zmení na odkaz do archívu. Tým zostane zachovaná evidencia bootov aj vstup
trénera. Staršie piloty sa týmto mechanizmom neuvoľňujú.
Príkazy, obnova po prerušení a pravidlá zastavenia sú v
[`AUTOMATICKY_ZBER.sk.md`](AUTOMATICKY_ZBER.sk.md).

Automatická kampaň po prijatí všetkých behov vytvorí a overí vlastný
`data/campaigns/<id>/corpus.json`. Pri manuálnom zbere sa index zostaví takto:

```sh
python3 -m features.dataset --protocol config/collection-v2.json --out data/corpus-v2.json <audit1.json> <audit2.json> ...
```

Index s `complete=false` nie je hotový korpus. Opravou chyby extraktora
sa výsledky neprepisujú: surové dáta sa spracujú znovu do nových archívov
a celý index musí používať rovnakú implementáciu extrakcie.

Po prijatí korpusu sa použije nový tréner:

```sh
python3 -m safeguard train --corpus data/corpus-v2.json --out data/models/server-v2 --epochs 10 --seed 0
python3 -m safeguard inspect --bundle data/models/server-v2
```

Bez korpusu možno mechaniku overiť príkazom
`python3 -m safeguard smoke --out data/safeguard/smoke-01`.
Ten používa syntetické dáta a nepreukazuje
latenciu živého zberu ani účinnosť detekcie. Spoločný `safeguard run` nad
novým modelom bude samostatným overením; pilot výskumného zberu ho nenahrádza.

## 7. Nadväzujúce merania safeguardu

**Klasifikácia aktivít:** samostatný cieľ od anomálie. Profil generátora je
známy experimentálny režim a trieda implementovaného klasifikátora, nie pravda
o každom procese v RAM. Jeho presnosť počíta `python3 -m tcn.eval far` spolu s FAR
(trieda okna je scenár session, nezávislou jednotkou je session); na odloženej role
`test_benign` sa ešte musí zmerať.
Pri budúcej klasifikácii
konkrétnej aktivity sa uchová presný interval začiatku/konca a dôkaz vykonania;
okná cez prechod majú označenie `transition`, nie náhodnú triedu celej session.

**Útoky a malvér:** oddelené izolované prostredie s rovnakým serverovým stackom.
Dnešný `passt` forwarding nie je malvérová izolácia. Žiadny škodlivý kód nevstúpi
do tréningu normálu. Vývojové PoC a finálne testy sú oddelené; výber vzoriek,
hash, aktivácia, časový priebeh a dôvod neaktivácie sa zaznamenajú. Injektovaný
scenár a reálna vzorka sa reportujú oddelene. Neaktivovaná vzorka nie je úspešná
detekcia ani platný negatívny prípad. Táto etapa sa ešte neuskutočnila.

**Detekčné metriky:** počet alarmových udalostí (nie počet nadprahových okien),
FAR za hodinu benígnej prevádzky, podiel detegovaných aktivovaných incidentov,
oneskorenie od preukázanej aktivácie, výpadky senzora a podiel času bez skóre.
Uviesť aj nedetekované incidenty; nepodmieňovať výsledok dostupnosťou skóre.
Pri FAR uviesť celý sledovaný čas aj efektívny čas skórovania. Nulové alarmy
neznamenajú nulovú skutočnú mieru; interval neistoty patrí k výsledku.

**Výkonnosť:** párované opakovania bez introspekcie, so zberačom a s celým
detektorom pri rovnakom profile záťaže. Striedať poradie podmienok. Merať
HTTP priepustnosť a latencie, chyby, CPU/RAM hosta, objem zápisu a latenciu
snímka → príznaky → skóre. Generátor od 2026-10-20 ukladá úplný záznam
požiadaviek a 5 s intervaly so zlúčiteľnými histogramami (definície v
[`LAB.sk.md`](LAB.sk.md)). Celobežné percentily sa počítajú z úplného záznamu
požiadaviek, nie z intervalov ani z posuvného okna stavového súboru.
Generátor je uzavretý cyklus klientov, nie pevná frekvencia; pri porovnaní
podmienok sa preto mení aj počet požiadaviek, nielen ich latencia. Samotné
prevádzkové logy nedokazujú kauzálny vplyv zberača; na ten treba párované
kontrolné merania.

Porovnania: TCN proti GRU a jednoduchým modelom nad rovnakými rolami a vstupmi;
globálne proti per-bin vstupom; iba pamäť proti objektom; kontroly integrity
samostatne proti ich spojeniu s modelom. Výsledok horší než baseline sa nezamlčí.
Všetky tieto merania ostávajú otvorenou etapou po zbere, nie splneným tvrdením.
