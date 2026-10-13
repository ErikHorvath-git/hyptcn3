# Automatický benígny zber

`scripts/campaign.py` vykonáva zmrazený plán z `config/collection-v2.json`:
nový boot skupiny → zahrievanie a zber → offline audit → overený archív
→ ďalšia session → úplný index pre tréning. Plán obsahuje 48 hodinových
zberov v ôsmich bootových skupinách. Zahrievanie, reštarty, extrakcia a
archivácia sa pripočítavajú k času zberu; nie sú ďalšími hodinami merania.
Runner spúšťa iba benígne profily existujúceho laboratória.

## Príprava a spustenie

VM aj stack musia byť pripravené podľa [LAB.sk.md](LAB.sk.md), pilot musí mať
prijatý audit. Zdrojový strom musí byť commitnutý a čistý. Na tomto stroji
je archív na disku Seagate; init zaznamená jeho UUID, mountpoint a súborový
systém. Rovnaká cesta bez pripojeného disku sa nesmie použiť ako náhradné
úložisko. Pred začiatkom sa kontroluje priestor pre celý odhad z pilotu
s plánovacou rezervou a samostatnou núdzovou rezervou protokolu.

```sh
python3 scripts/campaign.py init \
  --name benign-v2-20261013 \
  --pilot-report data/results/collection_pilot_v2_20261013_reaudit.json \
  --archive-root '/run/media/eh/Seagate Expansion Drive/hyptcn3'

sudo python3 scripts/campaign.py launch data/campaigns/benign-v2-20261013
```

`init` zmrazí konfiguráciu, seed a poradie každého behu, hash pilotu, commit,
profil, extraktor, binárku zberača, verzie Python balíkov a identitu stacku.
Kópie plánu a vstupov sú lokálne aj na externom disku. Pilot zostáva mimo
tréningu, vývoja, kalibrácie a testu. `launch` vytvorí systémovú službu
`hyptcn-collection.service`; heslo sa neukladá. Libvirt a audit bežia pod
pôvodným používateľom, eBPF zber potrebuje root. Služba drží blokovanie
uspania hostiteľa a pokračuje po zatvorení terminálu.

Počas kampane nemeniť commit, protokol, profil, Python balíky ani stack vo VM.
Nespúšťať druhý generátor, testy laboratória, tréning ani intenzívne hostiteľské
úlohy. Zdrojová zmena zastaví ďalší krok; nemiešajú sa verzie extraktora.
Ani úspešné prijatie dát nemeria vplyv samotného detektora na VM.

## Priebeh a uložené dáta

```sh
python3 scripts/campaign.py status data/campaigns/benign-v2-20261013
journalctl -fu hyptcn-collection.service
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
| `data/collections/<session>/` | Lokálne metadáta, profil, audit a príznaky |
| `Seagate/hyptcn3/campaigns/<id>/collections/<session>/` | Overená úplná kópia vrátane surových snímok |

Snímky vznikajú na internom SSD, aby USB prenos nezasahoval do meraného zberu.
Audit a presun prebiehajú medzi session. Archív sa najprv skladá v dočasnom
adresári. Každý súbor má veľkosť a SHA-256; kontrolujú sa zdroj aj cieľ,
nemennosť zdroja a zhoda s obrazmi, metadátami a príznakmi použitými auditom.
Zápisy sa synchronizujú na disk pred publikovaním manifestu a archívu.

Až potom vznikne lokálny `archive_receipt.json`. Pracovný `raw/` sa dočasne
premenuje, nahradí odkazom na externý `raw/` a overené lokálne raw súbory sa
odstránia. Metadáta a príznaky zostávajú na pôvodných cestách. Parser nájde
bootové metadáta aj po vyriešení odkazu; dataset a tréner ďalej používajú
nemenné cesty auditov. Pôvodné piloty ani cudzie adresáre sa neuvoľňujú.
Režim presunu povoľuje iba session patriace danej kampani.

Odpojený alebo zamenený disk, nedostatok priestoru, nezhoda hashu a zmenený
zdroj spôsobia zastavenie. Nedokončené kópie neoprávňujú zmazanie zdroja.
Po presune je externý disk hlavným úložiskom RAM, nie druhou nezávislou
zálohou. Malé lokálne súbory a archív sa preto majú zachovať spolu.
Obnova na inom hostiteľovi potrebuje nové explicitné mapovanie ciest;
pôvodné absolútne cesty v auditoch sa neprepisujú.

## Zastavenie a pokračovanie

```sh
sudo systemctl stop hyptcn-collection.service
sudo python3 scripts/campaign.py launch data/campaigns/benign-v2-20261013
```

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
python3 scripts/campaign.py verify-archives data/campaigns/benign-v2-20261013
```

## Dokončenie a rozsah overenia

Po prijatí a archivovaní celého plánu vznikne
`data/campaigns/<id>/corpus.json`. Runner overí kompletnosť indexu aj jeho
prijatie validačnou cestou trénera a uloží kópiu na externý disk. Stav
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
