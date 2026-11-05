# Návrh protokolu v3: prevádzkové udalosti bez malvéru

**Stav: návrh z 2026-11-04, krok A implementovaný (kap. 7), prvý pilot audit
zamietol (kap. 7), zber ešte nebežal.** Protokol kroku A je [`config/collection-v3.json`](../config/collection-v3.json)
(`server-events-v3`). Platný trénovací protokol ostáva `server-normal-v2`
([`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md),
[`config/collection-v2.json`](../config/collection-v2.json)), stav práce voči zadaniu
je v [`STAV.sk.md`](STAV.sk.md). Po vyhodnotení kroku A sa z návrhu stane kapitola
metodiky; tento dokument sa potom zmaže.

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
základnou premávkou a 2 až 3 vloženými udalosťami (každá 2 až 6 minút, pred prvou,
medzi nimi aj po poslednej najmenej 10 minút čistej prevádzky; pôvodných 2 až 4
udalostí po 2 až 10 minút sa do hodinovej session s týmito medzerami nezmestí). Každý typ udalosti sa zopakuje v niekoľkých
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

## 7. Zmeny v kóde

| Zmena | Kde | Stav |
|---|---|---|
| udalosti v hosťovi: `start`/`stop`, `stop` vždy vráti nasadený stav, odpoveď JSON s dôkazom (stav jednotiek, `/healthz`, hash skriptu) | `lab/udalosti.py`, `scripts/labctl.py event` | hotové |
| plán: 4 skupiny `test_events` × 6 scenárov (24 h), každý typ udalosti v každom boote, seedované časy | `scripts/collection.py plan`, `config/collection-v3.json` | hotové |
| spúšťanie podľa plánu počas merania, záznam `events.json` s časmi hosťa aj hostiteľa; prerušenie aj zlyhaný štart udalosť zastaví | `scripts/collection.py` (`Events`) | hotové |
| mená skupín s predponou `v3-`; plán v2 je bajtovo nezmenený (test) | `scripts/collection.py` | hotové |
| audit: v intervale udalosti a 60 s po nej pripustí zlyhané požiadavky, chyby nginx, traceback v journale a reštart jednotiek, ktoré udalosť reštartuje; mimo intervalov ostáva prísny | `scripts/collection_logs.py` | hotové |
| testovacia kampaň bez roly `train` dostane `events_index.json` namiesto korpusu | `scripts/campaign.py` | hotové |
| FAR po typoch a triedach udalostí, dozvuk, čistá prevádzka, oneskorenie alarmu, test proti čistej prevádzke | `tcn/eval.py udalosti` | hotové |
| značky okien z intervalov udalostí (iba pre krok B) | `features/dataset.py`, `safeguard/training.py` | iba pri kroku B |

Typy udalostí kroku A (`lab/udalosti.py`): `zla_konfiguracia_sluzby` (preklep v drop-ine
jednotky catalog, systemd ju reštartuje každé 3 s), `zla_konfiguracia_nginx` (zlý port
upstreamu catalog, 502), `restart_databazy` (PostgreSQL; jednotky labu majú
`Requires=postgresql.service`, reštartujú sa s ním), `restart_sluzby` (orders),
`zamok_tabulky` (`LOCK TABLE orders`, dotazy narazia na 3 s `statement_timeout`),
`udrzba_zaloha` (`pg_dump` a `tar` `/etc` s kompresiou) a `zataz_pamate` (proces
s 400 MiB dotknutej pamäte). `logrotate` a čistenie journalu sa nevolajú, lebo by
rozdelili segmenty logov, ktoré audit overuje.

Pilot v3 obsahuje dve udalosti (`config/collection-v3.json`, `events.pilot`), aby
audit udalostí prešiel na skutočnom labe ešte pred kampaňou. Identita hosťa
(`stack_sha256`) skript udalostí nezahŕňa, takže ostáva porovnateľná s prostredím
balíka v6; hash skriptu je v každej odpovedi udalosti a audit ho porovná s hashom
pri štarte session. Prvý pilot (`20261104T161025010961Z_pilot_steady`, commit 4f024d8) audit
zamietol: šesť riadkov nginx `GET /healthz` bez `X-Request-Id` pochádzalo z kontroly zdravia
v samotnom `lab/udalosti.py`. Audit ich odvtedy pripustí iba vnútri okna udalosti
(`event_health_checks`); mimo okna ostávajú neznámou požiadavkou. Kolektor sa po upratovaní (commit 625fe0f) preložil z iného
zdroja, preto vyhodnotenie zapíše zhodu prostredia s balíkom po položkách.

## 8. Poradie

1. Upratanie mŕtveho kódu a overenie zhody extraktora na korpuse v6 (kap. 6).
2. Implementácia udalostí, plánu, auditu a vyhodnotenia (kap. 7) s testami.
3. Nový pilot, potom zber testovacích session kroku A a záloha dát.
4. Vyhodnotenie kroku A, zápis do `MERANIA.md`, rozhodnutie o kroku B.
