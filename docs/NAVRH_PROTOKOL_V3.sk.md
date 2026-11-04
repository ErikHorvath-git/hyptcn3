# Návrh protokolu v3: prevádzkové udalosti bez malvéru

**Stav: návrh z 2026-11-04, schválený smer, neimplementovaný.** Platný protokol zberu
je `server-normal-v2` ([`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md),
[`config/collection-v2.json`](../config/collection-v2.json)), stav práce voči zadaniu
je v [`STAV.sk.md`](STAV.sk.md). Po implementácii sa z návrhu stane kapitola metodiky
a súbor protokolu; tento dokument sa potom zmaže.

Rozhodnutia vlastníka z 2026-11-04:

1. Záverečný test modelu `server-v2-benign-v6` na `test_benign` korpusu v6 prebehol
   ([`MERANIA.md`](MERANIA.md), 2026-11-04). Je referenčným číslom pre tento návrh.
2. Všetko musí byť relevantné voči zadaniu (kap. 1).
3. Vetva `upratanie-meracieho-kodu` sa zlúči hneď, ale odstráni sa iba mŕtvy kód;
   čo je použiteľné do budúcna, ostáva (kap. 6).
4. Žiadne útoky ani malvér. Zbierajú sa iba prevádzkové udalosti bez malvéru, aby
   bolo spektrum prevádzky širšie. Najprv sa vyhodnotí, či dnešný model na ne dáva
   falošné alarmy; nový tréning až podľa výsledku (kap. 4).

## 1. Väzba na zadanie

Korpus `benign-v6-20261026` obsahuje iba ustálenú prevádzku šiestich profilov
generátora. Záverečný test na ňom dal jednu falošnú udalosť modelu, no reálna
prevádzka má aj chyby, reštarty a údržbu, ktoré v korpuse nie sú.

| Požiadavka zadania | Čo dnes chýba | Čo pridá protokol v3 |
|---|---|---|
| R15c „použiteľnosti v reálnych scenároch“ | FAR iba na ustálenej prevádzke (METODIKA, kap. 5) | FAR pri bežných prevádzkových udalostiach: zlá konfigurácia, pád a reštart služby, údržba |
| R13 „detekciu anomálií a klasifikáciu aktivít“ | triedy klasifikátora sú nastavenia generátora a väčšinu z nich na `test_benign` nerozlíšil | triedy podľa toho, čo sa vo VM deje (kap. 3) |
| R17 „validácia detekcie“ | validácia iba na čistej prevádzke | falošné alarmy po typoch udalostí, s intervalom neistoty |
| R14, R15b výkon | párové merania zostávajú samostatnou úlohou | bez zmeny |

Detekcia malvéru (R15a) touto etapou zmeraná nebude a nikde sa tak nesmie uvádzať
(HONESTY P4). Stavebné bloky útokov v `scripts/poc/` ostávajú na neskoršiu etapu.

## 2. Čo sa nemení

Zberač, príznaky, perióda 5 s, okno 32 snímok, plná snímka každých 360 cyklov,
hodinová session, skupina = jeden boot, server v labe (nginx, auth, catalog, orders,
PostgreSQL, worker) a základná premávka z dnešných profilov. Tým ostanú dáta
porovnateľné s korpusom v6 a dnešný model ich môže skórovať.

## 3. Prevádzkové udalosti a triedy

Triedy sa určia pred zberom a po výsledkoch sa nemenia. Trieda patrí časovému
intervalu udalosti, nie celej session; okná cez prechod majú značku `transition`.

| Trieda | Udalosť | Ako sa vyvolá v labe |
|---|---|---|
| `prevadzka` | iba základná premávka | náhodný profil v2 |
| `zla_konfiguracia` | vývojár nasadí chybnú konfiguráciu, služba spadne a systemd ju opakovane reštartuje | neplatná hodnota v konfigurácii služby API, po čase návrat správnej |
| `zla_konfiguracia` | chybná konfigurácia nginx, upstream vracia 502 | zlý `upstream` v konfigurácii nginx, potom oprava a `reload` |
| `restart_sluzby` | plánovaný reštart PostgreSQL alebo služby API počas premávky | `systemctl restart` |
| `chyba_aplikacie` | aplikácia vracia 5xx, napríklad vyčerpané spojenia do DB alebo zámok tabuľky s pomalými dotazmi | zámok tabuľky alebo obmedzenie spojení na pár minút |
| `udrzba` | záloha DB s kompresiou, `logrotate`, inštalácia a odstránenie balíka z lokálneho `.deb`, úloha `cron` | príkazy údržby v hosťovi |
| `zataz_pamate` | legitímny pamäťovo náročný proces (napríklad report nad DB) | dávkový skript v hosťovi |

Udalosti sú vždy benígne. Ak niektorá vyvolá alarm, je to falošný alarm, nie
detekcia. Zoznam pokrýva časté prevádzkové situácie servera; nie je úplný a výsledok
sa bude vzťahovať iba na tieto typy.

## 4. Postup: najprv vyhodnotiť, potom prípadne trénovať

**Krok A: vyhodnotenie dnešného modelu bez tréningu.** Zbierajú sa session so
základnou premávkou a 2 až 4 vloženými udalosťami (každá 2 až 10 minút, medzi nimi
najmenej 10 minút čistej prevádzky). Každý typ udalosti sa zopakuje v niekoľkých
bootoch, aby jednotkou neistoty bola skupina (METODIKA, kap. 1). Všetky tieto session
sú iba testovacie. Model `server-v2-benign-v6` sa na nich prehrá a výsledok je:

- falošné alarmové udalosti počas každého typu udalosti a počas čistej prevádzky medzi nimi,
- FAR za hodinu s intervalom pre každý typ zvlášť,
- oneskorenie alarmu od začiatku udalosti a jeho trvanie (či alarm odznie po skončení),
- zvlášť alarmy modelu a nálezy kontrol integrity.

**Rozhodnutie po kroku A.** Ak falošných alarmov pri udalostiach nie je viac než pri
čistej prevádzke, model je pre tieto situácie použiteľný a výsledok sa uvedie. Ak ich
je viac, nasleduje krok B a výsledok kroku A sa uvedie aj tak (HONESTY P8).

**Krok B: tréning so širším normálom, iba ak treba.** Nová kampaň s rolami ako v2,
kde udalosti patria do normálu a klasifikátor sa učí triedy z kap. 3. Vyhodnotí sa raz
na jej vlastnej `test_benign`. Porovnanie A a B je výsledok práce.

## 5. Pozemná pravda

Orchestrácia zapíše čas začiatku a konca každej udalosti a nezávislý dôkaz, že nastala
(stav a journal služby, odpovede 5xx v zázname generátora, výstup údržby). Udalosť bez
dôkazu sa označí ako nevykonaná a do metrík nevstupuje.

## 6. Upratanie kódu v tej istej dávke

Zmeny meracieho kódu pre v3 vyžadujú nový pilot, preto sa v tej istej dávke zlúči
upratanie. Odstráni sa iba mŕtvy kód: funkcie a parametre bez volajúceho, skripty bez
použitia a duplicitné kópie. Ostáva všetko, čo je použiteľné do budúcna: stavebné bloky
útokov (`scripts/poc/`, `scripts/aktivita.sh`, `scripts/mb_fetch.py`, `harness/net_isolated.*`),
baseliny a metriky v `tcn/` (porovnanie TCN s GRU, METODIKA kap. 7) a nástroje, ktoré
vyrobili citované merania. Presný zoznam odstráneného sa zapíše do správy commitu.

**Podmienka kroku A:** upratanie mení súbory `features/` a `guestparse/`, a tým hash
extraktora. Pred zberom sa preto overí, že nový kód vypočíta z tých istých surových
snímok korpusu v6 bajtovo rovnaké archívy príznakov. Bez tejto zhody by dnešný model
nové dáta neskóroval férovo a krok A by odpadol.

## 7. Čo treba zmeniť v kóde

| Zmena | Kde |
|---|---|
| spúšťanie udalostí v hosťovi podľa plánu a záznam ich intervalov s dôkazom | `lab/`, `scripts/collection.py` |
| plán s udalosťami, typmi a seedom | `scripts/collection.py plan`, `config/collection-v3.json` |
| mená skupín s predponou protokolu (dnešné `train-1` … kolidujú s dokončenou kampaňou v6) | `scripts/collection.py`, `scripts/campaign.py` |
| audit, ktorý v intervaloch udalostí pripustí očakávané chyby klienta a reštarty služieb | `scripts/collection_logs.py`, `scripts/collection.py` |
| vyhodnotenie falošných alarmov po typoch udalostí, oneskorenie a trvanie alarmu | `tcn/eval.py` |
| značky okien z intervalov udalostí (iba pre krok B) | `features/dataset.py`, `safeguard/training.py` |

## 8. Poradie

1. Upratanie mŕtveho kódu a overenie zhody extraktora na korpuse v6 (kap. 6).
2. Implementácia udalostí, plánu, auditu a vyhodnotenia (kap. 7) s testami.
3. Nový pilot, potom zber testovacích session kroku A a záloha dát.
4. Vyhodnotenie kroku A, zápis do `MERANIA.md`, rozhodnutie o kroku B.
