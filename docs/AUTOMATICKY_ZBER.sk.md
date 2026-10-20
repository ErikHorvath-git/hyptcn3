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
UUID, mountpoint a súborový systém archívu aj pracovného úložiska
`data/collections`. Pred každou session sa obe identity overia; iný disk
na rovnakej ceste zastaví beh. Pred začiatkom sa kontroluje priestor pre celý
odhad z pilotu s plánovacou rezervou a samostatnou núdzovou rezervou protokolu.

Rozloženie na zberovom PC (2026-10-20, bez externého disku):

| Úložisko | Disk | Účel |
|---|---|---|
| `/mnt/ssd/hyptcn3-work/vms/` | SSD (`sda2`, UUID `7d763f4d-…`) | disk VM `hyptcn-lab` |
| `data/collections`, `data/diagnostics` | rovnaký SSD cez bind mount z `/mnt/ssd/hyptcn3-work/` | vznikajúce snímky, logy a príznaky |
| archív kampane | systémový HDD (`/`) | overené komprimované kópie session |

Adresáre pod bind mountami majú na HDD príznak `chattr +i`. Ak SSD nie je
pripojený, zápis do nich zlyhá aj pre roota (overené `Operation not permitted`).
Zber zapisuje bez `fsync`. S `fsync` trvali plné snímky na tomto SSD 4,7–10,7 s
po súvislom zápise delt (diagnostika 2026-10-20, profily `write_heavy`
a `bursty`), na HDD už samotný zápis 370 MB 4,6–5,8 s; perióda je 5 s.
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
úlohy. Zdrojová zmena zastaví ďalší krok; nemiešajú sa verzie extraktora.
Ani úspešné prijatie dát nemeria vplyv samotného detektora na VM.

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

Celý reťazec obnova → opätovná extrakcia nad reálnymi snímkami zatiaľ
nebol overený (UNVERIFIED). Pôvodné piloty ani cudzie adresáre sa neuvoľňujú.
Režim presunu povoľuje iba session patriace danej kampani.

Odpojený alebo zamenený disk, nedostatok priestoru, nezhoda hashu a zmenený
zdroj spôsobia zastavenie. Nedokončené kópie neoprávňujú zmazanie zdroja.
Po presune je archívny disk hlavným úložiskom RAM, nie druhou nezávislou
zálohou. Malé lokálne súbory a archív sa preto majú zachovať spolu.
Obnova na inom hostiteľovi potrebuje nové explicitné mapovanie ciest;
pôvodné absolútne cesty v auditoch sa neprepisujú.

## Zastavenie a pokračovanie

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
nasledujúcej session, takže sa nestratia.

Pôvodná chyba (chýbajúci `end.json`, stav `running` po zastavení) vznikala
opakovaným SIGTERM: systemd poslal signál všetkým procesom jednotky a runner
navyše celej skupine dieťaťa, čím prerušil jeho upratovanie. Hlavným procesom
bol `systemd-inhibit`, ktorý signály neposúval. Oprava je pokrytá testami;
skutočné `systemctl stop` na tomto PC zatiaľ overené nebolo (UNVERIFIED).

Pri SIGKILL alebo výpadku napájania upratovanie zaručiť nemožno. V súbore
stavu potom ostane `running`. `status` ho podľa živosti procesu označí ako
`stale` a ďalšie spustenie zaznamená `unclean-end`. Neúplná session sa
archivuje ako neúplná a alokácia sa zastaví.

Rovnaký príkaz pokračuje z existujúcich artefaktov, nezačína novú kampaň.
Dokončené session sa nezbierajú znova. Prerušené kopírovanie a uvoľňovanie
pracovných raw kópií sú obnoviteľné. Prerušená extrakcia dostane nový názov
výstupu, pôvodný čiastočný výstup zostáva. Hotový zamietavý verdikt sa nesmie
obísť opakovaním auditu. Zber sa po prerušení nedopĺňa chýbajúcimi snímkami.
Neúplný JSON auditu nie je hotovým verdiktom a nezamkne výber ďalšieho auditu.

Ak sa zber nedokončil alebo audit session zamietol, runner uloží jej archív
a zastaví alokáciu. Nevymení ju automaticky za úspešnejšiu session. Dôvod
treba preskúmať a metodické rozhodnutie zaznamenať. Rovnako sa automaticky
nepokračuje po zmene bootu uprostred skupiny. Pri chybe ešte pred vznikom
metadát sa zachová rozpracovaný adresár na kontrolu.

Pre plánované zastavenie na hranici dokončenej session možno pri `launch`
alebo priamom `run` pridať `--stop-after 1`. Limit počíta nové dokončené
session daného spustenia; nemení plán ani pravidlá prijatia. Celú kampaň
chráni spoločný zámok aj proti ručne spustenému `collection.py run`.

Úplnú opätovnú kontrolu archivovaných dát možno vykonať mimo merania:

```sh
.venv/bin/python scripts/campaign.py verify-archives data/campaigns/<kampaň>
```

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
