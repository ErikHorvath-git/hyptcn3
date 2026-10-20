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
a verdikt v `values.accepted`. Existujúce audity sa nemenia. Nové spravované
sessions schémy `/2` potrebujú prijatú kontrolu logov aj pri zostavení korpusu,
tréningu a prijatí pilotu do kampane. Historická schéma `/1` zostáva čitateľná;
nedostáva tým dodatočné tvrdenie o logoch, ktoré nezaznamenala.

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
Doterajšie snímky ani verdikty sa tým neopravujú. Zlepšenie RAM pokrytia
touto zmenou ešte nebolo merané; zostáva hypotézou na overenie novým
pilotom. Rovnaké nastavenie má platiť pre všetky profily záťaže a neskoršie
testovacie scenáre.

## Úložisko pred novým pilotom

[`collection_storage_20261020.json`](../data/results/collection_storage_20261020.json)
obsahuje namerané pôvodné a komprimované objemy starých diagnostík, identity
diskov, uvoľnené pracovné kópie a odhad kampane. Archív je v
`/home/eh/hyptcn3-archive/diagnostics/`; zostávajúce metadáta a výsledky sú
na pôvodných cestách v `data/diagnostics/`. Neúplné a zamietnuté behy si
zachovávajú svoj pôvodný stav.

Plánovací odhad používa najväčší hodinový objem z úplných diagnostických
behov, násobí ho počtom pridelených session a plánovacou rezervou. K tomu
pripočítava núdzovú rezervu protokolu. Pracovný SSD potrebuje miesto na
nekomprimovanú session; HDD uchováva komprimovaný korpus. Ide o odhad zo
starého workloadu, ktorý treba porovnať s novým prijatým pilotom a náročnými
profilmi. `campaign.py init` vykoná vlastný prepočet a kontrolu voľného miesta.
