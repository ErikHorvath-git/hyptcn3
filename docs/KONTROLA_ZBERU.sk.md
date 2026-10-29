# Pokrytie okien a kontrola logov zberu

Zber na hostiteľovi číta RAM bežiacej VM. Nginx, auth, catalog, orders,
PostgreSQL a worker tvoria benígnu serverovú záťaž; HTTP generátor beží
na hostiteľovi. Logy aplikácie dokladajú priebeh experimentu, nevstupujú do
TCN. Zadanie v `zadanie-zp_105826.pdf` vyžaduje aj per-bin vektory, sekvencie
a vyhodnotenie: úspešný HTTP beh sám nestačí na prijatie RAM dát.

## Rýchla kontrola uloženého behu

Bez roota a bez opätovného parsovania RAM:

```sh
python3 scripts/collection_logs.py data/diagnostics/SESSION \
  --out /tmp/logs-nova-kontrola.json

.venv/bin/python scripts/collection.py coverage \
  data/diagnostics/SESSION/audit_POVODNY.npz \
  --expected-snapshots 400 --out /tmp/pokrytie-nova-kontrola.json
```

`SESSION` a názov NPZ nahraď konkrétnym uloženým behom. Počet
`--expected-snapshots` musí byť pridelený počet cyklov zo `session.json`;
pri pilote protokolu v2 je to 480 a pri bežnej session 720. Neodvodzuje sa
z počtu zostávajúcich súborov: chýbajúca snímka musí zostať v menovateli.
Oba príkazy vracajú 0 pri splnení svojej kontroly a 2 pri zamietnutí.
Výstupná cesta musí byť nová. Samostatné splnenie hranice pokrytia nie je
prijatím session: napríklad nález integrity môže blokovať benígny korpus.

Po archivácii môže byť `raw/` odkazom mimo session. Novú kontrolu logov
alebo úplný RAM audit spúšťaj nad obnovenou pracovnou kópiou: skopíruj
zachované metadáta a logy do nového adresára s pôvodným názvom session
a obnov doň `raw/` podľa [AUTOMATICKY_ZBER.sk.md](AUTOMATICKY_ZBER.sk.md).
Pôvodný názov musí sedieť so `session_id`. Audit logov úmyselne odmieta
cesty mimo pracovnej session; archivácia nemení historický prijatý alebo
zamietnutý verdikt. Kontrola pokrytia zo zachovaného NPZ obnovu RAM nepotrebuje.

Úplný audit, ktorý opäť overí RAM aj vyrobí príznaky:

```sh
.venv/bin/python scripts/collection.py audit data/collections/SESSION
```

Obsahuje kontrolu logov v `values.logs`, rozpis pokrytia v `values.coverage`
a verdikt v `values.accepted`. Existujúce audity sa nemenia. Audit zaznamená
hashe extraktora (`values.extractor_sha256`); `pilot_gate` v `scripts/campaign.py`
aj `safeguard train` bez `--diagnostic` prijmú iba audit so súčasným kódom
`features/` a `guestparse/`. Po zmene tohto kódu treba session znovu auditovať
do nového výstupu (predvolený názov `audit_<čas>.json` alebo nová cesta `--out`).
Nové spravované sessions schémy `/2` potrebujú prijatú kontrolu logov aj pri
zostavení korpusu, tréningu a prijatí pilotu do kampane. Historická schéma
`/1` zostáva čitateľná; nedostáva tým dodatočné tvrdenie o logoch, ktoré
nezaznamenala.

## Čo znamená skórovateľné okno

Audit protokolu v2 používa rovnaký `WindowBuffer` a validáciu celých
globálnych aj per-bin vstupov ako tréning a živý safeguard. Pri dĺžke 32
je prvých 31 riadkov kontext a posledný riadok cieľ predikcie. Netreba
ďalšiu 33. snímku. Offline kontrola nevykonáva inferenciu modelu.

Plná snímka, neplatný vstup, chýbajúci predchodca, medzera v čase/sekvencii
a zmena reťazca prerušia kontext. Neplatný riadok sa nedopĺňa ani
nepreskakuje. Po chybe primárneho prechodu je aj ďalší riadok bez
predchodcu; potom sa znova plní celé okno. Samostatne sa vykazujú:

- `state_rows`: priame dôvody, zahrievanie a skórovateľné kroky;
- `barriers`: sekvencie prerušení vrátane poznámok parsera;
- `ranges`: úseky so skórom a bez skóre, s príčinou posledného prerušenia;
- `missing_snapshots`: chýbajúce kroky oproti pridelenému počtu;
- `score_coverage`: počet skórovateľných okien / pridelený počet snímok;
- `ideal_score_coverage`: teoretický strop pri bezchybnom zbere a predpísanej rotácii;
- `lost_windows_vs_ideal`: rozdiel oproti tomuto stropu;
- `nominal_scored_s`, `nominal_unscored_s`: počty krokov krát predpísaná perióda.

Posledné dve časové hodnoty sú nominálne, nie nameraná dostupnosť živého
detektora. Latencia extrakcie, inferencie a alarmu vyžaduje samostatné meranie.
Príčiny výpadkov sa neprekrývajú v súčte `unscored_rows_by_cause`; následný
chýbajúci predchodca ostáva pripísaný chybe vstupu. Pri viacerých blízkych
chybách nemožno každej bez dvojitého počítania pripísať celé nové okno.

Z parametrov protokolu vyplýva: pri 400 cykloch, okne 32 a rotácii 360
vznikne najviac 336 okien, teda 84 %. Taký krátky diagnostický beh nemôže
splniť hranicu 85 %. Pilot so 480 cyklami má strop 416 okien; hodinový
beh so 720 cyklami 656. Sú to výpočty z konfigurácie, nie namerané výsledky.
Skrátenie okna alebo zmena rotácie by boli zmenou experimentu a potrebovali
by nový protokol a pilot. Kontrola ich nemení.

## Čo kontroluje audit logov

1. Úplný koncový záznam, návratové kódy zberača/generátora/monitora,
   identitu session a bootu a uložený protokol.
2. SHA-256 manifestu logov a všetkých uvedených súborov, veľkosti,
   počty a ukončenie riadkov. Pri prenesených segmentoch overí aj gzip
   a dekomprimovaný obsah proti údajom z hosťa.
3. Hlavičky, číslovanie, koncové záznamy, fázy a konfiguráciu HTTP logov,
   intervalové počty a histogramy proti jednotlivým požiadavkám,
   chyby požiadaviek a súhrnný `traffic.json`.
4. Čas merania proti fázam generátora; úplný RAM audit navyše porovná
   časy snímok s intervalom meranej premávky.
5. Každé klientské request ID práve raz v nginx, rovnaký status/metódu/cestu
   a preposlané ID; potom odpoveď správnej služby v journale. Pre orders
   kontroluje aj interné auth/catalog volania a pre healthz obe závislosti.
   Cudzie alebo chýbajúce požiadavky sa hlásia. Kontrolné požiadavky pred
   zberom sa párujú vo vlastnom segmente.
6. Aktívne služby, nezmenené PID/InvocationID a počítadlá reštartov,
   odchýlku hodín hosťa najviac 1 s a neistotu odhadu najviac 1 s.
7. Úplnosť a časové pokrytie hostiteľského monitora, koncové počty zberača,
   chyby a zmeškané sloty; chyby nginx a známky zahodených správ v journale.

Upozornenia zberača ostávajú v reporte aj pri úspešnej kontrole. Napríklad
hlásený fallback libbpf sa automaticky nezamieňa za neúspešný zber. Chýbajúci
alebo poškodený dôkaz vyrobí zamietnutý JSON s dôvodmi; nerobí sa oprava
pôvodných logov. Prerušený beh sa nesmie označiť za čistý podľa toho, že
stihol zapísať časť snímok. Kontrola dokazuje vnútornú zhodu uložených
dôkazov, nie kryptograficky nezávislú pozemnú pravdu z nedôveryhodného hosťa.

## Obmena databázových procesov

Pôvodný `ThreadedConnectionPool(1, 12)` v `lab/services.py` uchovával iba
jedno nečinné spojenie. Nainštalovaná implementácia psycopg2 `_putconn`
pri návrate nad `minconn` spojenie zatvára. Pri súbežných požiadavkách tak
môže opakovane vznikať a zanikať backend PostgreSQL. Neatómový zber RAM
môže počas zmien procesného zoznamu zachytiť neuzavretý prechod.

Kód teraz uchováva všetkých 12 spojení pre catalog/orders a jedno pre
workera. Ide o úpravu serverového workloadu s novou identitou stacku.
Nasadenie vo VM prebehlo 2026-10-20; funkčná kontrola je uložená ako
[`lab_smoke_pool_20261020.json`](../data/results/lab_smoke_pool_20261020.json).
Doterajšie snímky ani verdikty sa tým neopravujú. Piloty 3 až 7 po zmene
dosiahli strop 416 okien z 480; párované porovnanie so starým poolom sa
nevykonalo, takže podiel tejto zmeny na pokrytí zmeraný nie je. Krátko žijúci
proces PostgreSQL sa v snímke objavil aj po zmene (kampaň v2, session 3,
snímka 645: [záznam](../data/results/collection_crossview_race_20261022.json)).
Rovnaké nastavenie má platiť pre všetky profily záťaže a neskoršie
testovacie scenáre.

## Úložisko pred pilotmi na zberovom PC (2026-10-20)

[`collection_storage_20261020.json`](../data/results/collection_storage_20261020.json)
obsahuje namerané pôvodné a komprimované objemy starých diagnostík, identity
diskov, uvoľnené pracovné kópie a odhad kampane. Archív je v
`/home/eh/hyptcn3-archive/diagnostics/`; zostávajúce metadáta a výsledky sú
na pôvodných cestách v `data/diagnostics/`. Neúplné a zamietnuté behy si
zachovávajú svoj pôvodný stav.

Plánovací odhad používa najväčší hodinový objem z úplných diagnostických
behov, násobí ho počtom pridelených session a plánovacou rezervou. K tomu
pripočítava núdzovú rezervu protokolu. Pracovný SSD potrebuje miesto na
nekomprimovanú session; HDD uchováva komprimovaný korpus. Bol to odhad zo
starého workloadu. Kampane odhadujú priestor z prijatého pilota
(`campaign.py init`) a runner ho kontroluje pred každou session; tento odhad
zo starých diagnostík sa už nepoužíva.

## Úložisko pred kampaňou benign-v5

`campaign.py init` a runner pred každou session vyžadujú na pracovnom SSD
voľné miesto aspoň vo výške odhadu session z prijatého pilota (surové dáta
pilota × 720/480 × 1,5) a rezervy protokolu 30 GiB. Z pilota 6 to bolo
53.34 {{res:collection_storage_20261025.json:values.gib.required_free_before_each_session}}
GiB, voľných však bolo
49.49 {{res:collection_storage_20261025.json:values.gib.working_free_before}}
GiB (prepočet pred spustením `init`). So súhlasom zadávateľa sa preto
2026-10-25 surové dáta dvoch najstarších pilotov
(`20261021T230727556324Z_pilot_bursty` a pilot 3
`20261022T003017919708Z_pilot_bursty`) archivovali do
`/home/eh/hyptcn3-archive/pilots/` tými istými overenými krokmi ako session
kampane: SHA-256, komprimované členy overené dekompresiou, väzba na audit
pilota a nezávislé `collection_archive verify`
([záznam](../data/results/collection_storage_20261025.json)). Uvoľnilo sa
20.75 {{res:collection_storage_20261025.json:values.gib.reclaimed}}
GiB a pred `init` bolo voľných
70.24 {{res:collection_storage_20261025.json:values.gib.working_free_after}}
GiB, o
16.9 {{res:collection_storage_20261025.json:values.gib.margin_after_archival}}
GiB viac, než pravidlo kampane vyžaduje. Metadáta, audity a logy oboch
pilotov zostali na pôvodných cestách, `raw/` odkazuje do archívu a obnoví
ho `collection_archive.py restore`. Archív je odteraz jedinou kópiou týchto
snímok, nie druhou zálohou.

## Úložisko pred kampaňou benign-v6

Z pilota 7 vyžaduje pravidlo kampane pred každou session
54.62 {{res:collection_storage_20261026.json:values.gib.required_free_before_each_session}}
GiB voľného miesta na pracovnom SSD a voľných bolo
57.94 {{res:collection_storage_20261026.json:values.gib.working_free_before}}
GiB. Každá session však na SSD nechá svoje metadáta (odhad z voľného miesta
pred kampaňou v5 a po nej: asi 70 MB), takže pri 48 session by rezerva
nestačila. So súhlasom zadávateľa sa preto 2026-10-26 tými istými overenými
krokmi archivovali surové dáta pilota 4 `20261022T073059077133Z_pilot_bursty`
do `/home/eh/hyptcn3-archive/pilots/`, vrátane nezávislého
`collection_archive verify` ([záznam](../data/results/collection_storage_20261026.json)). Uvoľnilo sa
10.7 {{res:collection_storage_20261026.json:values.gib.reclaimed}}
GiB a pred `init` bolo voľných
68.64 {{res:collection_storage_20261026.json:values.gib.working_free_after}}
GiB, o
14.02 {{res:collection_storage_20261026.json:values.gib.margin_after_archival}}
GiB viac, než pravidlo vyžaduje. Metadáta, audit a logy pilota zostali na
pôvodných cestách, `raw/` odkazuje do archívu a obnoví ho
`collection_archive.py restore`. Archív je odteraz jedinou kópiou týchto
snímok.

## Reset pamäte pri ďalšej plnej snímke

Kontrola pred ostrým zberom odhalila chybu Python čítača: pri rekonštrukcii
časovej osi cez ďalšiu plnú snímku zostávali v indexe aj stránky z jej
predchodcov. Plná snímka vynecháva nulové stránky, preto sa chýbajúca
stránka musí stať nulovou, nie zdediť starý obsah. Pri čítaní samotného
nového reťazca sa chyba neprejavovala.

Čítač teraz pri každej plnej snímke vyprázdni index a až potom načíta jej
záznamy. Overenie celej predchádzajúcej histórie ostáva zachované: plná
snímka nezakryje chýbajúcu deltu ani skrátený súbor. Regresné testy
porovnávajú celý stav pamäte pred resetom, pri ňom a po nasledujúcej delte.

Reálny pilot po zmene fondu spojení potvrdil aj tento problém parsera.
Overenie opravy na hranici plnej snímky a na konci série je uložené v
[`full_snapshot_reset_20261021.json`](../data/results/full_snapshot_reset_20261021.json).
Pôvodné výstupy sa neprepisujú. Staršie rekonštrukcie, ktoré prechádzali
cez ďalšiu plnú snímku, treba pred použitím znovu auditovať opraveným
čítačom; úspešný audit logov tento problém pamäte nezistí. Starší pilot
nespĺňa požiadavku na aktuálnu verziu extraktora a meracieho kódu.
