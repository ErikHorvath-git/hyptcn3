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
Vzorkovací cyklus zberača (verzia 1.1) na disk nesiaha: zmenené stránky
kopíruje do fronty v pamäti a súbor, `rename`, SHA-256, sidecar, hooky aj
retenciu robí vlákno `vmic-writer`, log zapisuje vlákno `vmic-log`. Kampaň
`benign-v4-20261022` totiž zamietla session 37, keď jeden cyklus 5,08 s čakal
na SSD, ktorý práve zapisoval stovky MB snímok z page cache (perióda 5 s);
predtým cyklus vytváral, zapisoval, premenúval a hašoval súbory sám.
Zber zapisuje bez `fsync`: s ním trvali plné snímky na tomto SSD 4,7–10,7 s
po súvislom zápise delt (diagnostika 2026-10-20, profily `write_heavy`
a `bursty`), na HDD už samotný zápis 370 MB 4,6–5,8 s. Procesor i5-8400 nemá
SHA-NI, takže skalárny SHA-256 spracuje ~230 MB/s; zapisovač ho počíta z tých
istých bajtov, ktoré zapisuje, a sidecar vznikne až s hotovým hashom
(`hash_deferred: true` pri každej snímke). Snímka sa zverejní celá, alebo
vôbec: dáta aj sidecar sa zapíšu pod bodkovými dočasnými menami a premenujú
sa hneď po sebe bez prepisu (`RENAME_NOREPLACE`). Čas od začiatku cyklu po
zapísané dáta je v sidecari `output.data_closed_ms` (sidecar a premenovania
nasledujú, je to dolná hranica zverejnenia); najdlhšie celé zverejnenie
a najdlhšiu operáciu zapisovača uvádza súhrn na konci `collect.log`.
Fronta má predvolene veľkosť najväčšej možnej plnej snímky + 512 MiB (pri VM
s 2 GiB asi 2,5 GiB) a kampaň ju s `output.mlock` uzamkne (`mlockall`), aby
cyklus nedostal page fault ani swap-in na pamäti zberača (čítanie pamäte VM
môže odswapované stránky QEMU načítať aj tak; proti tomu je `vm.swappiness = 1`
a krok `prefault`). Pred meranou fázou runner a pri štarte aj zberač overia,
že voľnej pamäte je aspoň na frontu, zvyšok pamäte VM, ktorý si QEMU ešte môže
vziať, a 2 GiB rezervy; inak pokus skončí pred meraním. Dočasné súbory testov
v `/tmp` (tmpfs) túto pamäť zaberajú, preto sa pred zberom mažú. Keď zapisovač zaostane
tak, že pamäť fronty dôjde, cyklus čaká (`queue_wait_ms`) a audit session
zamietne. Pred skončením zberač zapíše celú frontu (najviac `output.drain_s`,
v kampani 180 s, a po signále najviac 40 s); čo nestihne alebo nezapíše, je
chyba: chýba, zberač vráti kód 4 a audit zber zamietne.
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
úlohy. Neprechádzať rekurzívne repozitár ani archív (napríklad `grep -r` z koreňa repozitára
číta živé adresáre v `data/` aj súbory na HDD, kde je disk VM).
Nevytvárať ani neupravovať súbory v repozitári (ani poznámky či
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

Obnova zapíše do nového adresára pred prvým členom aj značku `restored_from.json`: `session_id`
a `campaign_id` z archívneho `session.json`, cestu archívu a sha256 jeho manifestu (ako ho uvádza
potvrdenka). Stráž snímok (`tcn/pecat.py kontrola_snimok`) ju číta ako `session.json`, takže snímky
zapečatenej session obnovené z archívu odmietne menom (odpoveď vedúceho na Q19, balík B10).

Obnova a opätovná extrakcia boli overené na reálnom diagnostickom behu
([výsledok](../data/results/collection_archive_roundtrip_20261020.json)):
obnovili sa všetky snímky a vedľajšie súbory, príznaky prvého súvislého
úseku sa zhodovali s pôvodným NPZ. Report uvádza presný rozsah porovnania;
opätovná extrakcia celého behu sa v tomto overení nevykonávala.
Automatická kampaň neuvoľňuje pôvodné piloty ani cudzie adresáre.
Pri používateľom povolenej archivácii starých diagnostík a pilotov zostávajú
metadáta a výsledky na pôvodných cestách, `raw/` odkazuje do overeného archívu
`/home/eh/hyptcn3-archive/diagnostics/` alebo `/home/eh/hyptcn3-archive/pilots/`
([KONTROLA_ZBERU.sk.md](KONTROLA_ZBERU.sk.md)). Na nové parsovanie sa použije obnova
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
Môže to trvať až jednu session s auditom a archiváciou (najdlhšia session
kampane v4, session 23: zber
3740.1 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.22.stage_s.capture}}
s, audit
3522.4 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.22.stage_s.audit}}
s a archivácia
522.5 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.22.stage_s.archive}}
s; časy dvoch žiadostí a zastavení sú v `operator_stop_requests` a
`stopped_states` toho [záznamu](../data/results/collection_campaign_benign_v4_20261022.json)). Pri `launch` alebo priamom `run` možno aj vopred pridať
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
Skutočné `systemctl stop` bolo overené na zberovom PC počas diagnostického
zberu ([výsledok](../data/results/collection_stop_validation_20261020.json)).
Prípravný runner použil rovnaké `campaign.run_child`, `collection.Interrupts`
a `KillMode=mixed`; deti skončili, zámok aj blokovanie spánku sa uvoľnili
a logový audit prerušenú session zamietol. Bežnú orchestráciu (reštart
skupiny, zber, audit, archív, zastavenie na hranici session a pokračovanie
po ňom, zastavenie po zamietnutej session, `close` a `verify-archives`)
prešli živé kampane `benign-v2-20261022` až `benign-v6-20261026`
([MERANIA.md](MERANIA.md)). Obnova po reštarte hostiteľa alebo výpadku
napájania zostáva UNVERIFIED.

Pri SIGKILL alebo výpadku napájania upratovanie zaručiť nemožno. V súbore
stavu potom ostane `running`. `status` ho podľa živosti procesu označí ako
`stale` a ďalšie spustenie zaznamená `unclean-end`. Session bez `end.json`
sa považuje za neúplnú session s meraním.

### Protokol v5: poradie testovacích skupín, ukončenia a ich záznamy

Pred každým behom na oboch VM (skúška G2 na dvoch VM, generálky G3a a G3b,
kampaň G5) sa obe VM raz vypnú (`labctl stop` každej s jej `--domain`, `--vm`
a `--port`). Až potom `labctl start` (alebo `labctl daemon`, ktorý vypíše
záznam démona) spustí démona relácie libvirt v jeho jednotke
`hyptcn-libvirtd.service`, a QEMU každej VM vznikne v nej (cesta 1, oddiel
o démonovi v jednotke v [LAB.sk.md](LAB.sk.md)). Démona mimo jednotky
`labctl` nenahradí, kým beží niektorá doména. Prvý začiatok skupiny by potom
zlyhal na kroku `start`, lebo cesta 2 presunie proces, nie jeho pamäť,
a kampaň by sa zastavila s príčinou `group_start` (nález F4 z B5a, pokyn
vedúceho 2026-11-24).

Bežec kampane protokolu v5 začne skupinu roly `test_benign` alebo
`test_controls` až vtedy, keď na druhej VM začala každá skupina týchto rolí,
ktorá je v pláne pred ňou (`ORDER_RULE` v `scripts/campaign.py`). Táto bariéra
pridáva kampani nečinný čas: v modeli overovateľa so session rovnakej dĺžky
skončí kampaň v5 po 72 namiesto 66 dĺžkach session, asi o 9 % neskôr (model,
nie meranie). Zastavenie jedného bežca zastaví aj druhého pri jeho
najbližšej testovacej skupine, ktorá naň čaká (dôvod: bežec druhej VM nie je
aktívny). Bariéra usporiada začiatky testovacích skupín, nie ich konce: test 2
kostry B9 platí z konštrukcie iba pre plán, ktorého prekladaná postupnosť
končí skupinou `test_benign`, ako plán kampane (`v5-test_benign-12`);
generálka končí `g5-test_controls-2` a pri oneskorení asi o jednu skupinu ho
poruší, čo záznam ukončenia uvedie v odchýlkach.

Každé ukončenie kampane v5 zapíše jeden záznam
`data/results/kampan_<kampaň>_<ukončenie>_<čas UTC>.json` (`ENDING_RULE`):
`complete` (úplná, ešte pred indexom; `finish_corpus` bez neho odmietne),
`paused` (pozastavená), `stopped` (zastavená: skoré zastavenie, chyba bežca,
zlyhaný začiatok skupiny, žiadosť operátora), `invalid` (neplatná)
a `closed` (uzavretá operátorom). Stupeň záznamu (otázka Q21, prijatá
vedúcim 2026-11-24): v režime `campaign` je `final`, keď kniha
záznamu v pracovnom strome drží každú prijatú session zapečatených rolí;
báza menuje sha256 knihy, lebo kniha sa commitne až po kampani a knihu na HEAD
preverí `tcn.finalne`, keď záznam číta. Generálka dostane `generalka`.
Inak je `suchy` s dôvodom: vlastná kniha testu alebo suchého behu G1,
chýbajúca pečať, alebo záznam bez prijatej session zapečatených rolí.
Kým beží iný bežec, ukončenie čaká
v `ending.json` adresára kampane a ten bežec sa zastaví pri najbližšej
kontrole; záznam zapíše posledný bežec, ktorý sa zastaví (po jeho páde ďalší
`run`, `launch` alebo `close`). `request-stop` kampane v5 žiada `--reason`,
ktorý záznam uvedie medzi odchýlkami. Zastaveniu na hranici `--stop-after`
a zastaveniu preto, že bežec druhej VM nie je aktívny, záznam nepatrí.

Každý záznam nesie medzi odchýlkami aj históriu kampane: každé skoršie
zaznamenané ukončenie (druh, príčinu, meno záznamu a sha256), každý nečistý
koniec a každú písomnú príčinu obnovenia po skorom zastavení (nižšie).
Záznam zastavenia skorým zastavením uvedie medzi odchýlkami aj toto skoré
zastavenie so session a rozhodnutím (vedúci 2026-11-24, Q24: každé
zastavenie aj obnova idú do záznamu ako odchýlka).
Nečistý koniec zistí beh, ktorý pri voľnom zámku nájde stav svojej VM
`running` (SIGKILL, pád, výpadok napájania). Pred pokračovaním ho zapíše ako
`deviations/<čas UTC>_unclean-end_<vm>.json` s VM, s tým stavom (etapa,
session, `updated_at`) a s časom zistenia. Je to odchýlka, nie ukončenie, lebo
bežec druhej VM mohol pokračovať. Session má v zázname jeden zo štyroch
stavov: `accepted` (kontrolný bod), `rejected` (záznam zamietnutia),
`captured, not judged` (adresár session bez oboch: bežec sa zastavil počas jej
zberu, auditu alebo pri zámku auditu) a `not run` (bez adresára session).
Úplnú kampaň s hotovým indexom a kampaň uzavretú operátorom `run` ani `launch`
už nespustia: odmietnu ich menom ešte pred kontrolou zmrazeného stromu, bez
ďalšieho ukončenia a záznamu, takže commit záznamov po kampani nič nepokazí.
Kampaň, ktorej bežec po zázname úplného ukončenia zanikol skôr, než dostaval
index, sa spustí znova a nový beh index dostavia (výklad opravy B9b).

Skoré zastavenie (otázka Q24, prijatá vedúcim 2026-11-24 s doplnením
nižšie): po každom audite
dokončeného zberu bežec zapíše `marked/<session>.json` (VM, session,
`audited_at`, označené riadky a výskyty po typoch udalostí z auditu, sha256
záznamu auditu), sčíta súbory oboch VM od začiatku kampane alebo od jej
posledného zaznamenaného ukončenia so spúšťačom skorého zastavenia
a rozhodne
`features/audit_policy.py early_stop`. Session zamietnutá pre periodicitu,
alebo počet kampane C_T označených riadkov pri type T nad 99. percentilom
Poissonovho rozdelenia so strednou hodnotou miera_T × n_T výskytov
(`audit.early_stop.marked_rows_rate_per_type`), zastaví kampaň. Session sa
pritom najprv prijme a zapečatí, alebo zamietne a nahradí. Príčina menuje typ,
počet, výskyty, mieru a hranicu. Miery sú `null` do G3b: počty sa iba vytlačia
v stave bežca a kampaň ide ďalej. Skoré zastavenie, ktoré sa nedá rozhodnúť,
zastaví kampaň ako chybu menom, nikdy nie ako „bez zastavenia“.
Pokračovanie počíta ďalej (text odpovede na Q24: „s náhradami aj
s pokračovaním“; balík B11): kým nemá vlastné ukončenie so spúšťačom skorého
zastavenia, sčíta aj súbory pozastavenej kampane, ktorú pokračuje, od jej
bodu znovuzačatia. Jej adresár musí niesť `campaign.json` so sha256, ktorý
pokračovanie zmrazilo, inak sa skoré zastavenie nedá rozhodnúť a kampaň sa
zastaví ako chyba menom. Príčina zastavenia potom menuje aj pozastavenú
kampaň. Predtým pokračovanie počítalo iba svoje session; to bolo spresnenie
koordinátora, ktoré prijatému textu odporovalo.
Skoré zastavenie je zastavenie a otázka (HARNESS, kap. 7; `RESUME_RULE`):
kým je posledným zaznamenaným ukončením zastavenie so skorým zastavením,
`run` aj `launch` ho odmietnu menom. Kampaň pokračuje až s písomným rozborom
príčiny, `run --vm <vm> --cause "<rozbor>"` alebo `launch --cause "<rozbor>"`,
a počet skorého zastavenia potom začne znova od toho zastavenia. Podľa
doplnenia vedúceho k Q24 (2026-11-24) sa smie obnoviť iba vtedy, keď rozbor
nenájde príčinu v meracom kóde ani v labe a hashe sú nezmenené. Príkaz preto
najprv porovná zmrazený merací kód a lab po súboroch. Ak sa niektorý súbor
zmenil alebo chýba, nič nezapíše ani neodmietne a beh alebo `launch` kampaň
pri kontrole zmrazeného stromu zneplatní (`invalid`), s `--cause` aj bez neho.
Inak zapíše obnovu ako `deviations/<čas UTC>_resume-after-early-stop_<vm>.json`
(pri `launch` všetkých VM bez VM) s menom a sha256 záznamu, na ktorý
odpovedá, s podmienkou obnovy a so zmrazenými mapami, ktoré našiel
nezmenené. Každý ďalší záznam ju uvedie medzi odchýlkami. Jedna odpoveď
stačí obom VM. Obnova po skorom zastavení nie je pokračovaním a jedno
pokračovanie po vyčerpanom limite náhrad nespotrebuje. Počet náhrad ide cez
ňu ďalej, nič sa neobnoví ani nezaťaží. Prázdny `--cause` a `--cause` po inom
ukončení ako skorom zastavení sa odmietnu menom. Ostatné zastavenia (žiadosť
operátora, signál, zlyhaný začiatok skupiny, chyba) pokračujú obyčajným `run`
alebo `launch`.

Zlyhaný začiatok skupiny (otázka Q22, prijatá vedúcim 2026-11-24: zlyhaný
štart skupiny nie je session a limit náhrad nezaťažuje) nie je zamietnutím
session, lebo žiadna session sa nemerala. Zapíše sa ako
`groups/<skupina>.start-failed-<čas UTC>.json` s krokom, výstupom a príčinou
`group_start` a kampaň skončí ako zastavená s touto príčinou. Nič sa
nenahrádza a limit náhrad sa nezaťaží. Obnovený `run` začne skupinu znova od
začiatku (stop, start, reset, pretouch) a zachytí jej session podľa plánu,
ako pokus 1. Každý zlyhaný začiatok uvedie každý ďalší záznam ukončenia
(`group_start_failures`) aj v odchýlkach.

Vyčerpaný limit náhrad v režime `campaign` kampaň pozastaví na rozbor: oba
bežce skončia so stavom `paused` a `run` ani `launch` ju už nespustia.
Pozastavená kampaň má jedno pokračovanie:

```sh
.venv/bin/python scripts/campaign.py init --continue data/campaigns/<pozastavená kampaň> \
  --cause "<písomná príčina>" --mode campaign --estimate-from <generálka> \
  --protocol config/collection-v5.json --archive-root <archív>
```

Žiada záznam pozastavenia (commitnutý: `init` žiada čistý strom), neprázdnu
príčinu a nezmenený merací kód aj lab po súboroch
(`collection.measurement_sources`, `collection.lab_sha256`) oproti zmrazeniu
pozastavenej kampane; zmenený alebo chýbajúci súbor odmietne menom, nový súbor
tiež (treba ho odstrániť a skúsiť znova); limit platí znova ten istý. Druhé
vyčerpanie v pokračovaní alebo zmena meracieho kódu či labu počas kampane ju
zneplatní (`invalid`, bez korpusu). Záznamy pokračovania nesú medzi
odchýlkami aj odchýlky záznamu pozastavenia, prečítané po kontrole jeho
sha256, každú s menom pozastavenej kampane a jej záznamu. Záznam, ktorý sa
nedá prečítať, menujú namiesto nich (Q24, balík B11). `init` zmrazí oba po súboroch
(`measurement_files_sha256` vedľa `measurement_sha256`, `lab_sha256`) a kampaň
je neplatná, len keď sa zmrazený súbor zmenil alebo chýba. Nový súbor vedľa
nich (odkladací súbor editora `lab/.udalosti.py.swp`, alebo súbor, ktorý git
ignoruje a `labctl deploy` by ho skopíroval do hosťa) je zmenou stromu: beh ho
odmietne menom (`campaign source changed`, s menom nového súboru), kampaň sa
zastaví a po jeho odstránení pokračuje. Zastavenú kampaň
možno po odstránení príčiny spustiť znova (`run`, `launch`). Zamietnutie
session bez náhrady, ktoré nastalo po začiatku merania (príčina mimo
`replacement.covers`, strata bootu, pokus, ktorý sa nedá vylosovať), však
nechá kampaň zastavenú. Každé ďalšie spustenie sa zastaví na tom istom
zamietnutí, kým ju operátor neuzavrie (`close`). Po kampani sa záznamy jej
ukončení a kniha pečatí commitnú a odošlú spolu.

Po ukončení, ktoré kampaň uzavrie (`complete`, `invalid`, `closed`), patrí do
toho istého commitu so záznamami a knihou pečatí aj položka v
[MERANIA.md](MERANIA.md) a za každú odchýlku zápis v
[ODCHYLKY_V5.sk.md](ODCHYLKY_V5.sk.md); bez nich sa surové dáta nemažú (návrh,
kap. 11.6). Položka uvádza kampaň a ukončenie, meno a sha256 záznamu,
plánované, prijaté, zamietnuté a nahradené session, neskórovaný čas
a odchýlky. Záznam takého ukončenia ju nesie v `values.merania_entry`, každé
číslo so značkou `{{res:…}}` kontroly C, a príkaz, ktorý záznam zapísal, ju
vypíše aj so sha256 záznamu, ktorý záznam sám v sebe niesť nemôže. Po
zastavení sa dokumentácia ani záznamy necommitujú: zmrazený strom
(`FROZEN_TREE_RULE`) by ďalší beh odmietol.

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
(reštart, uloženie a obnova VM). Ak zber nevytvorí ani adresár session,
runner skončí s chybou `capture could not start`; adresár bez metadát sa
odloží ako `.attempt-<n>` (oddiel vyššie).

Dôvod treba preskúmať a metodické rozhodnutie zaznamenať ako nový záznam
v [MERANIA.md](MERANIA.md); otvorenú položku a stav práce eviduje
[STAV.sk.md](STAV.sk.md). Ak kampaň nemá pokračovať, uzavrie sa; `--reason`
uloží rozhodnutie aj do `closed.json`:

```sh
.venv/bin/python scripts/campaign.py close data/campaigns/<kampaň> --reason "<zaznamenané rozhodnutie>"
```

`close` vyžaduje voľný zámok zberu (nebeží žiadny runner). Zapíše
`closed.json` s dôvodom a predchádzajúcim stavom lokálne aj do archívu
a stav `closed`. Session, audity a archívy zostávajú; korpusový index
nevznikne. Uzavretú kampaň už nemožno spustiť. Až uzavretie uvoľní názvy
bootových skupín (`train-1` …) pre novú kampaň; `init` inak odmietne
skupinu, ktorá už má dáta. Dokončenú kampaň (stav `complete`) `close`
odmietne, jej skupiny preto pre novú kampaň zostávajú obsadené. Nová kampaň
potrebuje prijatý pilot so súčasným meracím kódom; prijaté session uzavretej
kampane sa do jej korpusu nepresúvajú. Jediná výnimka je pokračovacia kampaň.

### Pokračovacia kampaň

Kampaň, ktorá sa zastavila natrvalo (session, ktorú pravidlo `replacement` už
nenahradí, alebo zaniknutý boot skupiny) a ktorú operátor uzavrel, môže mať
jedno pokračovanie. Pravidlo je predregistrované v `PLAN_multivm_dataset.md`,
kap. 8.

```sh
.venv/bin/python scripts/campaign.py init --continue data/campaigns/<uzavretá kampaň> \
  --protocol config/collection-v4.json --name <nová kampaň> \
  --pilot-report a=<audit pilota a> --pilot-report b=<audit pilota b> \
  --archive-root <archív>
```

`init --continue` odmietne pokračovanie, ak sa oproti uzavretej kampani líši
súbor protokolu (sha256), rozvrh, extraktor (`features/`, `guestparse/`),
profil, runtime (hostiteľ, Python, balíky, kolektor, `vm.swappiness`) alebo
prostredie hosťa niektorej VM. Odmietne aj neuzavretú kampaň, pokračovanie
pokračovania a druhé pokračovanie tej istej kampane. Výnimkou je pokračovanie
uzavreté skôr, než čokoľvek zmeralo; to sa smie založiť znova.

- **Prevzaté skupiny.** Skupina, ktorej všetky priradenia sú v uzavretej
  kampani prijaté a archivované, sa nezbiera ani neaudituje znova. `init`
  overí zhodu jej záznamov (kontrolný bod, vybraný audit, `session.json`,
  príznaky, manifest archívu, boot skupiny) a zapíše ju do `campaign.json`
  pod `continues.sessions`. Do indexu ide cez pôvodný audit; každý beh znova
  overí jeho sha256.
- **Zahodené skupiny.** Každá iná začatá skupina je v `continues.discarded_groups`.
  Zozbiera sa znova celá v novom boote tej istej VM, s tými istými scenármi
  a semenami. Jej pôvodné session ostávajú v archíve a do indexu nejdú.
- **Náhrady.** Limit `replacement.max_per_campaign` sa počíta pre pokračovanie
  znova.
- **Index.** `corpus.json` pokračovania pokrýva obe kampane a pod kľúčom
  `continues` uvádza prevzaté session, zahodené skupiny a počet náhrad
  uzavretej kampane.

`status` ukazuje pri každej VM `continues` a `taken_over` (počet prevzatých
priradení); `accepted_archived` ich započítava.

`accepted_archived` je vždy počet session vlastnej VM. Runner, ktorý postaví
index všetkých VM, zapíše počet session indexu pod vlastný kľúč
`indexed_sessions` (oprava B9a: predtým ho zapísal do `accepted_archived`
a `campaign_report.py` by ho porovnal s kontrolnými bodmi jednej VM).

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
kampane uvádza osobitne, rovnako zlyhané začiatky skupín (po skupinách s VM,
krokom, časom, príčinou a tým, či sa skupina začala znova), oddelene od
zamietnutí po príčinách. Počas bežiacej kampane ho nespúšťať, lebo zaťaží
hostiteľa.

Stav pripravenosti pred spustením kampane je v
[PRIPRAVENOST_KAMPANE.sk.md](PRIPRAVENOST_KAMPANE.sk.md).

## Dokončenie a rozsah overenia

Po prijatí a archivovaní celého plánu vznikne
`data/campaigns/<id>/corpus.json`. Runner overí kompletnosť indexu aj jeho
prijatie validačnou cestou trénera a uloží kópiu do archívu. Stav
`complete` patrí až tomuto kroku. Kampaň `benign-v6-20261026` ho dosiahla
s indexom
48 {{res:collection_campaign_benign_v6_20261026.json:values.corpus.sessions}}
session ([záznam](../data/results/collection_campaign_benign_v6_20261026.json)).
Tréning ani kalibrácia sa nespúšťajú
automaticky; ich výsledky vyžadujú samostatné merania.

Testy používajú syntetické súbory a nahradené procesy zberača/auditu na
overenie riadenia kampane. Pokrývajú zlyhanie, opätovné spustenie, bootové
hranice, zámok, poškodenie dát, prerušenie kopírovania a prerušenie uvoľnenia
pracovnej kópie. Nie sú dôkazom dokončeného živého korpusu.
Pokračovaciu kampaň (`init --continue`) pokrývajú zatiaľ iba tieto testy
(`scripts/tests/test_continuation.py`, rozloženie s dvoma VM); na živých dátach
a pre kampaň s jednou VM je UNVERIFIED.
`scripts/validate_campaign_archive.py` samostatne overuje reálny disk:
kopíruje existujúci pilot bez zmeny pôvodných dát a uvoľňovanie skúša na
syntetickej pracovnej kópii. Beh z 2026-10-13
([`campaign_archive_validation_20261013_a.json`](../data/results/campaign_archive_validation_20261013_a.json))
overil nekomprimovaný archív na externom disku pôvodného PC. Komprimovaný
archív na zberovom PC overili [obnova](../data/results/collection_archive_roundtrip_20261020.json)
a `verify-archives` kampaní v2 až v6.
Výsledky vykonaných overení patria do
[`MERANIA.md`](MERANIA.md), nie do označenia plánovaných session za merania.
