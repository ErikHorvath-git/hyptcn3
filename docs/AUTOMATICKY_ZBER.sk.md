# Automatický benígny zber

`scripts/campaign.py` vykonáva zmrazený plán z `config/collection-v2.json`:
nový boot skupiny → zahrievanie a zber → offline audit → overený archív
→ ďalšia session → úplný index pre tréning. Plán obsahuje 48 hodinových
zberov v ôsmich bootových skupinách. Zahrievanie, reštarty, extrakcia a
archivácia sa pripočítavajú k času zberu; nie sú ďalšími hodinami merania.
Runner spúšťa iba benígne profily existujúceho laboratória.

## Príprava a spustenie

VM aj stack musia byť pripravené podľa [LAB.sk.md](LAB.sk.md), pilot musí mať
prijatý audit. Zdrojový strom musí byť commitnutý a čistý. `init` zaznamená
UUID, mountpoint, koreň (`FSROOT`) a súborový systém archívu aj pracovného
úložiska `data/collections`, nie názov zariadenia (`sdX` sa po reštarte môže
zmeniť). Pred každou session sa obe identity overia; iný disk na rovnakej
ceste zastaví beh. Pred začiatkom sa kontroluje priestor pre celý
odhad z pilotu s plánovacou rezervou a samostatnou núdzovou rezervou protokolu.

Rozloženie na zberovom PC (od 2026-10-21, bez externého disku):

| Úložisko | Disk | Účel |
|---|---|---|
| `data/collections`, `data/diagnostics` | SSD (`sda2`, UUID `7d763f4d-…`) cez bind mount z `/mnt/ssd/hyptcn3-work/` | vznikajúce snímky, logy a príznaky |
| `vms/hyptcn-lab.qcow2` | systémový HDD (`sdb2`) | disk VM `hyptcn-lab`, oddelený od výstupu snímok |
| archív kampane | systémový HDD (`/`) | overené komprimované kópie session |

Disk VM bol od 2026-10-20 na SSD spolu so snímkami. Spätný zápis plnej
snímky potom brzdil commity databázy hosťa (pozri [LAB.sk.md](LAB.sk.md)),
preto sa vrátil na HDD. Hostiteľ má `vm.swappiness = 1`; `init` hodnotu
zmrazí s pilotom a jej zmena kampaň zastaví pred ďalšou session.

Adresáre pod bind mountami majú na HDD príznak `chattr +i`. Ak SSD nie je
pripojený, zápis do nich zlyhá aj pre roota (overené `Operation not permitted`).
Zber zapisuje bez `fsync` a SHA-256 plnej snímky počíta vlákno zberača až
po cykle (`output.hash_async`). S `fsync` trvali plné snímky na tomto SSD
4,7–10,7 s po súvislom zápise delt (diagnostika 2026-10-20, profily
`write_heavy` a `bursty`), na HDD už samotný zápis 370 MB 4,6–5,8 s; perióda
je 5 s. Ani bez `fsync` cyklus nestačil (716 MiB, 5,46 s). Procesor i5-8400
nemá SHA-NI, takže skalárny SHA-256 spracuje ~230 MB/s a plné snímky
s pamäťou hosťa rastú. Sidecar plnej snímky vznikne až s hotovým hashom
(`hash_deferred: true`). Zberač pred skončením na hash počká; ak zlyhá,
sidecar chýba, zberač vráti kód 4 a audit zber zamietne.
Snímka sa zverejní z page cache. Jej SHA-256 zo sidecaru znovu overí audit
aj archivácia, ktorá kópie zapisuje s `fsync` a overuje dekompresiou. Pád PC
môže stratiť ešte nearchivovanú session; tá je potom neúplná, nikdy potichu
prijatá. Archív na systémovom disku musí byť
výslovne povolený; HDD a SSD sú dva fyzické disky, ale po uvoľnení raw ostane
jediná kópia RAM. Nie je to záloha.

```sh
.venv/bin/python scripts/campaign.py init \
  --name <kampaň> \
  --pilot-report <prijatý-audit-pilotu.json> \
  --archive-root <adresár-archívu-na-HDD> --archive-on-system-disk

sudo .venv/bin/python scripts/campaign.py launch data/campaigns/<kampaň>
```

Systémový `python3` nemá NumPy, preto sa príkazy spúšťajú interpreterom z `.venv`.
`init` zmrazí konfiguráciu, seed a poradie každého behu, hash pilotu, commit,
profil, extraktor, binárku zberača, verzie Python balíkov a identitu stacku.
Kompresný pomer archívu (zstd -3) zmeria na všetkých obrazoch pilotu a z neho
odhadne priestor; ostatné súbory session počíta nekomprimované. Kópie plánu
a vstupov sú lokálne aj v archíve. Pilot zostáva mimo tréningu, vývoja,
kalibrácie a testu. `launch` vytvorí systémovú službu
`hyptcn-collection.service`; heslo sa neukladá. Libvirt a audit bežia pod
pôvodným používateľom, eBPF zber potrebuje root. Hlavným procesom služby je
samotný runner; uspanie blokuje pomocný `systemd-inhibit`, ktorý zanikne
spolu s runnerom. Služba pokračuje po zatvorení terminálu.

Počas kampane nemeniť commit, protokol, profil, Python balíky ani stack vo VM.
Nespúšťať druhý generátor, testy laboratória, tréning ani intenzívne hostiteľské
úlohy. Nevytvárať ani neupravovať súbory v repozitári (ani poznámky či
výsledky); na to slúži iný adresár. Pred každým zberom aj auditom sa overí
celý strom a akákoľvek zmena zastaví ďalší krok; po jej vrátení sa pokračuje
rovnakým `launch`. Session a audit samy zaznamenávajú `commit_dirty` (celý
strom, informatívne) a `measurement_dirty` (iba merací kód). Kampaň prijme
iba `measurement_dirty: []` pri zmrazenom commite. Verdikt auditu, ktorý
vznikol pri inom commite alebo zmenenom meracom kóde, zostane uložený, ale
nevyberie sa a audit sa po obnovení zmrazeného stromu zopakuje pod novým
názvom. Nemiešajú sa verzie extraktora. Ani úspešné prijatie dát nemeria
vplyv samotného detektora na VM.

## Priebeh a uložené dáta

```sh
.venv/bin/python scripts/campaign.py status data/campaigns/<kampaň>
sudo journalctl -fu hyptcn-collection.service
```

Stav obsahuje aktuálnu fázu, session, skupinu, počet obrazov aktuálneho zberu
a počet prijatých a archivovaných session. Existencia obrazu ešte neznamená
úspešný audit. `running` kontroluje aj identitu procesu a boot hostiteľa,
aby starý stav po páde nevyzeral ako živý zber.

| Umiestnenie | Obsah |
|---|---|
| `data/campaigns/<id>/campaign.json`, `protocol.json`, `pilot.json`, `plan.json` | Nemenný plán a vstupy |
| `data/campaigns/<id>/groups/` | Zámer reštartu a potvrdená identita bootu |
| `data/campaigns/<id>/events/`, `logs/`, `attempts/` | História fáz, výstupy procesov a odkazy na verdikty |
| `data/campaigns/<id>/status.json` | Aktualizovaný prevádzkový stav; nie výsledok merania |
| `data/collections/<session>/` | Lokálne metadáta, profil, audit, príznaky a dôkazy session |
| `<archív>/campaigns/<id>/collections/<session>/` | Overená úplná kópia vrátane surových snímok |

Dôkazy každej session v jej adresári:

| Súbor | Obsah |
|---|---|
| `preflight_smoke.json` | funkčná kontrola pred meraním (token, katalóg, objednávka, worker) s request ID |
| `traffic_requests.jsonl`, `traffic_intervals.jsonl` | úplný záznam požiadaviek a 5 s súhrny vrátane fáz |
| `traffic.json`, `traffic_before.json`, `traffic.log` | stav generátora po zahriatí a na konci |
| `host_monitor.jsonl` | časová os CPU, pamäte, swapu, diskov, voľného miesta, procesov a teplôt (1 s) |
| `guest/` | stav hosťa a DB pred a po, posun hodín, uzavreté segmenty nginx logov a journal (gzip so SHA-256) |
| `logs_manifest.json`, `end.json` | veľkosti a SHA-256 všetkých dôkazov; pravdivý záznam o ukončení |

Audit a presun prebiehajú medzi session. Archív sa najprv skladá v dočasnom
adresári. Každý súbor má veľkosť a SHA-256; kontrolujú sa zdroj aj cieľ,
nemennosť zdroja a zhoda s obrazmi, metadátami a príznakmi použitými auditom.
Obrazy `.vmicd` a logy `.jsonl` sa ukladajú ako `.zst`. Každý člen sa pred
zverejnením úplne dekomprimuje a jeho pôvodná veľkosť a SHA-256 sa porovnajú.
Zápisy sa synchronizujú na disk pred publikovaním manifestu a archívu.

Až potom vznikne lokálny `archive_receipt.json`. Pracovný `raw/` sa dočasne
premenuje, nahradí odkazom na archívny `raw/` a overené lokálne raw súbory sa
odstránia. Metadáta a príznaky zostávajú na pôvodných cestách; dataset
a tréner ďalej používajú nemenné cesty auditov. Komprimovaný `raw/` parser
priamo nečíta. Pred novou extrakciou sa obnoví do nového adresára `raw`,
vedľa ktorého treba skopírovať `session.json` (bootový kontext):

```sh
.venv/bin/python -m scripts.collection_archive verify <archív>/campaigns/<id>/collections/<session>
.venv/bin/python -m scripts.collection_archive restore <archív>/campaigns/<id>/collections/<session> <nový>/raw
```

Obnova a opätovná extrakcia boli overené na reálnom diagnostickom behu
([výsledok](../data/results/collection_archive_roundtrip_20261020.json)):
obnovili sa všetky snímky a vedľajšie súbory, príznaky prvého súvislého
úseku sa zhodovali s pôvodným NPZ. Report uvádza presný rozsah porovnania;
opätovná extrakcia celého behu sa v tomto overení nevykonávala.
Automatická kampaň neuvoľňuje pôvodné piloty ani cudzie adresáre.
Pri používateľom povolenej archivácii starých diagnostík zostávajú metadáta
a výsledky na pôvodných cestách, `raw/` odkazuje do overeného archívu
`/home/eh/hyptcn3-archive/diagnostics/`. Na nové parsovanie sa použije obnova
vyššie; komprimované snímky parser priamo nečíta.
Režim presunu povoľuje iba session patriace danej kampani.

Odpojený alebo zamenený disk, nedostatok priestoru, nezhoda hashu a zmenený
zdroj spôsobia zastavenie. Nedokončené kópie neoprávňujú zmazanie zdroja.
Po presune je archívny disk hlavným úložiskom RAM, nie druhou nezávislou
zálohou. Malé lokálne súbory a archív sa preto majú zachovať spolu.
Obnova na inom hostiteľovi potrebuje nové explicitné mapovanie ciest;
pôvodné absolútne cesty v auditoch sa neprepisujú.

## Zastavenie a pokračovanie

Plánované zastavenie bez straty session (bez roota, na bežiacu kampaň):

```sh
.venv/bin/python scripts/campaign.py request-stop data/campaigns/<kampaň>
```

Runner dokončí práve bežiacu session vrátane auditu a archivácie a pred ďalším
zberom (aj pred reštartom novej skupiny) skončí so stavom
`stopped/between-sessions` a správou `operator stop request`. Požiadavka sa
presunie do `events/`. Platí iba pre bežiaci runner; požiadavku, ktorá zostala
po predchádzajúcom behu, nové spustenie odloží ako `*_stop-request-stale.json`.
Môže to trvať až jednu session s auditom a archiváciou (odhad okolo 1,5 h,
zatiaľ nezmeraný). Pri `launch` alebo priamom `run` možno aj vopred pridať
`--stop-after N`; limit počíta nové dokončené session daného spustenia
a nemení plán ani pravidlá prijatia. Pokračuje sa rovnakým príkazom
`launch`. Celú kampaň chráni spoločný zámok aj proti ručne spustenému
`collection.py run`.

Okamžité zastavenie:

```sh
sudo systemctl stop hyptcn-collection.service
sudo .venv/bin/python scripts/campaign.py launch data/campaigns/<kampaň>
```

Pri `systemctl stop` dostane SIGTERM iba runner (`KillMode=mixed`). Runner
pošle jeden SIGTERM práve bežiacemu dieťaťu a čaká na jeho upratovanie
(najviac 150 s). Zberový proces zastaví v poradí zberač, generátor a monitor,
zapíše `logs_manifest.json` a `end.json` s `completed=false` a dôvodom.
Ďalšie signály počas upratovania iba zaznamená. Runner potom zapíše stav
`stopped/interrupted` aj s prijatými signálmi a uvoľní zámok aj blokovanie
uspania. Čo po 240 s ešte beží, systemd ukončí cez SIGKILL. Segment nginx
logu prerušenej session sa neuzatvára hneď. Jeho riadky prevezme segment `pre`
nasledujúcej session, takže sa nestratia. **Okamžité zastavenie počas
meranej fázy session zneplatní a kampaň sa na nej zastaví** (pozri nižšie);
na plánované prerušenie slúži `request-stop`. Zastavenie počas auditu alebo
archivácie je obnoviteľné.

Pôvodná chyba (chýbajúci `end.json`, stav `running` po zastavení) vznikala
opakovaným SIGTERM: systemd poslal signál všetkým procesom jednotky a runner
navyše celej skupine dieťaťa, čím prerušil jeho upratovanie. Hlavným procesom
bol `systemd-inhibit`, ktorý signály neposúval. Oprava je pokrytá testami.
Skutočné `systemctl stop` bolo overené na tomto PC počas diagnostického
zberu ([výsledok](../data/results/collection_stop_validation_20261020.json)).
Prípravný runner použil rovnaké `campaign.run_child`, `collection.Interrupts`
a `KillMode=mixed`; deti skončili, zámok aj blokovanie spánku sa uvoľnili
a logový audit prerušenú session zamietol. Celá orchestrácia kampane vrátane
obnovy po reštarte týmto testom overená nie je (UNVERIFIED).

Pri SIGKILL alebo výpadku napájania upratovanie zaručiť nemožno. V súbore
stavu potom ostane `running`. `status` ho podľa živosti procesu označí ako
`stale` a ďalšie spustenie zaznamená `unclean-end`. Session bez `end.json`
sa považuje za neúplnú session s meraním.

Rovnaký príkaz pokračuje z existujúcich artefaktov, nezačína novú kampaň.
Dokončené session sa nezbierajú znova. Prerušené kopírovanie a uvoľňovanie
pracovných raw kópií sú obnoviteľné. Prerušená extrakcia dostane nový názov
výstupu, pôvodný čiastočný výstup zostáva. Hotový zamietavý verdikt sa nesmie
obísť opakovaním auditu. Zber sa po prerušení nedopĺňa chýbajúcimi snímkami.
Neúplný JSON auditu nie je hotovým verdiktom a nezamkne výber ďalšieho auditu.

### Pokus, ktorý skončil pred meraním

Ak zber skončí ešte pred meranou fázou (napr. zlyhaná funkčná kontrola,
synchronizácia hodín, uzavretie segmentu logu, zahrievanie alebo zastavenie
počas nich), `end.json` má `measurement_started: false` a session nemá
`raw/`, teda ani jeden obraz RAM. Taký pokus nie je výskumná session. Runner
jeho adresár premenuje na `data/collections/<session>.attempt-<n>`, zapíše
`attempts/<session>.attempt-<n>.json` s dôvodom a po 60 s spustí rovnaké
priradenie (rovnaký seed) znova v tom istom boote skupiny. Riadky logov
neúspešného pokusu sa nestratia: sú v jeho vlastnom segmente `pre`, alebo ich
prevezme segment `pre` ďalšieho pokusu. V jednom behu
runnera sú najviac tri pokusy na session; tretí neúspešný pokus zastaví
kampaň s chybou a jeho adresár ponechá na kontrolu. Po odstránení príčiny
nové spustenie odloží aj ten a pokračuje. Pokus bez metadát (chyba ešte pred
`session.json`) sa odloží rovnako. Zber, ktorý dosiahol meranú fázu, sa
nikdy neopakuje.

### Neúplná alebo zamietnutá session a uzavretie kampane

Ak sa zber po začiatku merania nedokončil alebo audit session zamietol, runner
uloží jej archív a zastaví alokáciu. Nevymení ju automaticky za úspešnejšiu
session; každé ďalšie spustenie sa zastaví na tej istej session. Rovnako sa
automaticky nepokračuje po zmene bootu alebo procesu QEMU uprostred skupiny
(reštart, uloženie a obnova VM). Pri chybe ešte pred vznikom metadát sa
zachová rozpracovaný adresár na kontrolu.

Dôvod treba preskúmať a metodické rozhodnutie zaznamenať (`docs/MERANIA.md`,
`docs/ISSUES.md`). Ak kampaň nemá pokračovať, uzavrie sa:

```sh
.venv/bin/python scripts/campaign.py close data/campaigns/<kampaň> --reason "<zaznamenané rozhodnutie>"
```

`close` vyžaduje voľný zámok zberu (nebeží žiadny runner). Zapíše
`closed.json` s dôvodom a predchádzajúcim stavom lokálne aj do archívu
a stav `closed`. Session, audity a archívy zostávajú; korpusový index
nevznikne. Uzavretú kampaň už nemožno spustiť. Až uzavretie uvoľní názvy
bootových skupín (`train-1` …) pre novú kampaň; `init` inak odmietne
skupinu, ktorá už má dáta. Nová kampaň potrebuje prijatý pilot so súčasným
meracím kódom; prijaté session uzavretej kampane sa do jej korpusu
nepresúvajú.

Úplnú opätovnú kontrolu archivovaných dát možno vykonať mimo merania:

```sh
.venv/bin/python scripts/campaign.py verify-archives data/campaigns/<kampaň>
```

## Report

Súhrn session alebo celej kampane (CSV, JSON a SVG grafy) mimo merania:

```sh
.venv/bin/python scripts/campaign_report.py campaign data/campaigns/<kampaň> --out <nový-adresár>
.venv/bin/python scripts/campaign_report.py sessions data/collections/<session> ... --out <nový-adresár>
```

Report číta iba uložené dôkazy (RAM obrazy neotvára, archív nedekomprimuje)
a každú hodnotu viaže na vstupný súbor so SHA-256. Chýbajúca hodnota má
uvedený dôvod, nikdy odhad. Výstupný adresár musí byť nový a mimo vstupov.
Odložené pokusy (`<session>.attempt-<n>`), žiadosti o zastavenie a uzavretie
kampane uvádza osobitne. Počas bežiacej kampane ho nespúšťať, lebo zaťaží
hostiteľa.

Stav pripravenosti pred spustením kampane je v
[PRIPRAVENOST_KAMPANE.sk.md](PRIPRAVENOST_KAMPANE.sk.md).

## Dokončenie a rozsah overenia

Po prijatí a archivovaní celého plánu vznikne
`data/campaigns/<id>/corpus.json`. Runner overí kompletnosť indexu aj jeho
prijatie validačnou cestou trénera a uloží kópiu do archívu. Stav
`complete` patrí až tomuto kroku. Tréning ani kalibrácia sa nespúšťajú
automaticky; ich výsledky vyžadujú samostatné merania.

Testy používajú syntetické súbory a nahradené procesy zberača/auditu na
overenie riadenia kampane. Pokrývajú zlyhanie, opätovné spustenie, bootové
hranice, zámok, poškodenie dát, prerušenie kopírovania a prerušenie uvoľnenia
pracovnej kópie. Nie sú dôkazom dokončeného živého korpusu.
`scripts/validate_campaign_archive.py` samostatne overuje reálny disk:
kopíruje existujúci pilot bez zmeny pôvodných dát a uvoľňovanie skúša na
syntetickej pracovnej kópii. Vykonaný beh je v
[`campaign_archive_validation_20261013_a.json`](../data/results/campaign_archive_validation_20261013_a.json).
Výsledky vykonaných overení patria do
[`MERANIA.md`](MERANIA.md), nie do označenia plánovaných session za merania.
