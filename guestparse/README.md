# `guestparse` — rekonštrukcia objektov hosťa z pamäťovej snímky

Balík číta snímku, ktorú vyrobil `vmicollect` (natívny formát `.vmicd`, prípadne
surový obraz), a rekonštruuje z nej procesy, načítané moduly a sieťové sokety.
Snímka sa **nerozbaľuje** — reťazec `.vmicd` sa číta na mieste, index stránok drží
iba dvojicu (súbor, offset).

Vstupnou závislosťou je profil jadra hosťa (`kallsyms` + BTF). Získal sa raz, z hosťa,
mimo behu zberu — rovnako, ako profil používa LibVMI alebo Volatility. Nie je to teda
introspekcia „bez akejkoľvek znalosti hosťa“; pozri `profiles/*/README.md`.

## Spustenie

Balík **sa spúšťa z koreňa repozitára**:

```sh
cd /cesta/k/hyptcn3
python3 -m guestparse info --snapshot guestparse/tests/data/mini.vmicd --profile profiles/debian12-6.1.0-42-cloud-amd64
```

`mini.vmicd` je malá snímka verzionovaná v repozitári (`tests/data/README.md`).
Reálne snímky sú mimo gitu (`data/raw/`, `data/collections/`).

Balík zámerne nemá inštalačný súbor (`pyproject.toml`) a neinštaluje sa do systému —
je to súčasť repozitára práce, nie knižnica na distribúciu. `python3 -m guestparse`
preto nájde balík len vtedy, keď je v ceste importu koreň repozitára. Z iného adresára
sa spúšťa cez `PYTHONPATH`:

```sh
PYTHONPATH=/cesta/k/hyptcn3 python3 -m guestparse info --snapshot ... --profile ...
```

Bez jedného z toho skončí príkaz hláškou `No module named guestparse`.

Testy túto podmienku nemajú — `guestparse/` aj `guestparse/tests/` majú `__init__.py`,
takže pytest si koreň repozitára do cesty importu pridá sám a beh z ľubovoľného
adresára funguje.

## Podpríkazy

| Príkaz | Čo urobí |
|---|---|
| `ps` | zoznam procesov z `init_task.tasks` |
| `lsmod` | načítané moduly zo zoznamu `modules` |
| `ss` | sokety IPv4 aj IPv6 (protokol sa určuje podľa `skc_prot`, nie podľa portu) |
| `info` | profil, reťazec snímky, posun jadra a krížová kontrola prekladu adries |
| `checks` | kontroly integrity: `sys_call_table`, procesy krížovo, moduly krížovo, text jadra |
| `procmap` | zmenené stránky binov → ktorému procesu patria (`--bin N`, `--bin-bytes B`) |
| `textbaseline` | baseline textu jadra pre kontrolu (d) do `text_baseline.json` v profile: SHA-256 stránok textu z úplnej snímky, s ktorou profil sedí, s maskovanými miestami, ktoré jadro pri štarte patchuje; `--vmlinux` (predvolene `data/raw/profile-assets/vmlinux-<release>`, ak existuje) pridá masky relokácií a alternatív z linkovaného obrazu a masky static calls z tabuľky v snímke; existujúci súbor prepíše iba `--force` |
| `validate` | porovnanie s pozemnou pravdou z hosťa (`ps`, `lsmod`, `ss`) |

Označenia A2 a A4 v pomocníkovi CLI a v komentároch kódu sú bloky plánu
z 2026-10-05 (preukotvenie profilu, priradenie binu procesu); legenda blokov
je v [`docs/STAV.sk.md`](../docs/STAV.sk.md).

Spoločné parametre: `--snapshot` (adresár s reťazcom `.vmicd`, jeden `.vmicd` alebo
surový obraz), `--profile` (adresár s `kallsyms.txt` a `btf.txt`), `--json` (na stdout
ide iba JSON; upozornenia idú na stderr), `--banner` (iný reťazec bannera),
`--chain-until SEQ` (použi snímky iba po danú časť `seq`, podobne ako
`vmicollect restore --until`; rozdiel pri viacerých reťazcoch je v časti o overení reťazca).
Parameter `--boot-id UUID` zadáva doloženú identitu bootu pre samostatný obraz.
Pri native zbere sa identita načíta z `session.json` (collection) alebo `run.json`
(safeguard) vedľa adresára `raw`; explicitný parameter s ňou nesmie byť v rozpore.

Po teplom reštarte môžu v RAM zostať staré kópie jadra vrátane banneru,
`init_task` a tabuliek stránok. Parser preto kontroluje `sysctl_bootid` v RAM
proti identite zaznamenanej pred zberom. Bez nej vyžaduje jedinú kotvu;
viac kandidátov, chýbajúca identita alebo viac zhodných kópií sú chybou vstupu.
`info --json` uchováva kandidátov, vybraný boot aj očakávaný boot. Identita
profilu z `boot.json` sa nezamieňa s identitou snímky. Ide o kontrolu súladu
vstupov, nie o kryptografické overenie nezmeneného jadra.

## Návratové kódy

| Kód | Znamená |
|---|---|
| 0 | prebehlo a nič sa nenašlo |
| 1 | `checks` niečo našiel — nesmie zaniknúť v úspešnom kóde |
| 2 | chyba: snímka sa nedá otvoriť (aj rozbitý reťazec), profil sa nedá načítať, posun jadra sa nenašiel |
| 3 | podpríkaz nie je implementovaný (chýba modul balíka; dnes majú moduly všetky podpríkazy, kód v `cli.py` zostáva) |
| 4 | `checks`: nič sa nenašlo, **ale aspoň jedna kontrola sa neuzavrela** |
| 5 | **nesúlad profilu**: `kallsyms` je z iného štartu jadra (KASLR) než snímka a preukotvenie (nižšie) neprebehlo |

Kód 5 platí pre **všetky** podpríkazy a zisťuje sa pred ich výkonom
(`GuestView.profile_boot_mismatch()`). Od 2026-10-05 sa nesúlad najprv **skúsi preukotviť**
(`GuestView.reanchor()`): posun medzi bootom profilu a bootom snímky sa zmeria z tabuliek
stránok (spätné hľadanie VA pre fyzickú adresu `init_task`, potvrdené druhou kotvou
`linux_banner`) a adresy profilu sa posunú; úspech sa oznámi na stderr a pokračuje sa.
Kód 5 nastáva až vtedy, keď preukotvenie nejde (FGKASLR, chýbajúce stránky tabuliek) —
nie je to neuzavretá kontrola („neviem"), ale chyba vstupu, preto prebíja aj nález (1),
aj neuzavretosť (4). Čítacie podpríkazy (`info`, `ps`, `lsmod`, `ss`, `checks`) výsledok
aj tak vypíšu, označený ako `NEUPLNE`, a diagnózu vypíšu na stderr (`info` bez `--json`
na stdout); `validate` sa nespustí vôbec a výstupný JSON nezapíše, aby po sebe nenechal
súbor v `data/results`.

Kód 4 je tam preto, že nula z prerušeného prechodu nie je dôkaz čistoty. Snímka je živá
(VM sa pri zbere nezastavuje), takže spájaný zoznam sa môže roztrhnúť; vtedy je výsledok
„neviem“, nie „čisté“, a skript, ktorý príkaz volá, to musí vedieť rozlíšiť. Keď sú
nálezy aj neuzavreté kontroly naraz, vyhráva kód 1 — nález je silnejšia správa.

## Overenie reťazca `.vmicd`

Delta nesie iba stránky, ktoré sa od predchádzajúcej snímky zmenili, takže sa aplikuje
na predchádzajúci stav. Keď v reťazci chýba delta uprostred, stránky, ktoré mala
priniesť, zostanú v stave spred nej — výsledkom je pamäť, ktorá v hosťovi nikdy naraz
neexistovala, a nič na to neupozorní.

Preto sa reťazec pri otvorení overuje a pri poruche sa **vyhodí `ChainError`** s presným
popisom. Kontroly zodpovedajú tým, ktoré robí `vmic_delta_restore()` v
`vmicollect/src/writer_delta.c`:

1. reťazec nie je prázdny;
2. `chain_id` sa smie zmeniť iba na plnej snímke. Každá plná snímka začína nový
   reťazec (`output.delta_full_every`). Bez `--chain-until` sa z adresára berie iba
   najnovší reťazec, rovnako ako vo `vmicollect restore`; s `--chain-until` sa
   berú časti všetkých reťazcov po dané `seq`, aby sa dal zrekonštruovať aj stav
   z obdobia pred poslednou plnou snímkou;
3. časti idú v rastúcom `seq` a žiadne `seq` sa neopakuje;
4. prvá časť je **plná snímka** (baseline);
5. `seq` sú súvislé — žiadna časť nesmie chýbať;
6. `page_size` je v celom reťazci rovnaká;
7. `region_sig` je v celom reťazci rovnaký;
8. navyše: súbor nesmie byť kratší, než sľubuje hlavička, a verzia formátu musí sedieť.

Príklad hlásenia (chýba `seq=2` v reťazci zo šiestich častí):

```
chyba: v retazci 1789741878834 chyba snimka seq=2 (mam 1, potom rovno 3) - stranky,
ktore mala priniest, by ostali v stave spred nej a citala by sa TICHO nekonzistentna
pamat. Ak staci stav po poslednej suvislej casti, pouzi --chain-until 1.
```

Súbor `.vmicd`, ktorý sa nedá prečítať, sa preskočí a **nahlási** sa na stderr; ticho
nezmizne. Kontrolu sa dá vypnúť iba programovo (`open_image(..., validate=False)`) —
slúži na skúmanie rozbitých snímok v testoch, nie na bežné čítanie.

## Testy

```sh
cd /cesta/k/hyptcn3
python3 -m pytest -q -rs guestparse                          # celý balík
python3 -m pytest -q -m "not realsnap" guestparse            # ako v čerstvom klone
GUESTPARSE_REQUIRE_REAL=1 python3 -m pytest -q guestparse    # chýbajúci vstup = chyba, nie preskočenie
python3 -m pytest -q --require-real guestparse               # to isté prepínačom
```

Prepínač `--require-real` zavádza `conftest.py` balíka, takže pytest ho pozná iba vtedy,
keď sa v príkaze objaví cesta do balíka (`guestparse`). Premenná prostredia
`GUESTPARSE_REQUIRE_REAL=1` funguje aj bez nej. Bez cesty pytest z koreňa repozitára
zbiera testy všetkých balíkov, nielen tohto.

Vstupy sú troch druhov:

- **malá snímka v repozitári** (`tests/data/mini.vmicd`, 110 kB) — je vždy k dispozícii,
  takže základné testy rekonštrukcie aj **injekčný test detektora hookov** bežia aj
  v čerstvom klone. Odkiaľ pochádza a čo v nej je: `tests/data/README.md`;
- **reálna snímka hosťa** (predvolene `/var/tmp/vmic-val` a `/var/tmp/vmic-delta`; cesty
  menia premenné `GUESTPARSE_VAL` a `GUESTPARSE_DELTA`, profil `GUESTPARSE_PROFILE`) —
  ležala iba na stroji, kde sa zbieralo, a k 2026-10-29 už ani tam nie je, takže testy
  so značkou `realsnap` sa preskočia;
- **výstup zo `make -C vmicollect test`** — značka `selftest`.

Keď chýba vstup, test sa preskočí **nahlas**: `conftest.py` zapína `-rs` a na konci
behu vypíše, koľko testov sa preskočilo a prečo. Preskočený test nie je prešiel.

## Čo balík nerobí

- neparsuje obsah pamäte procesov. Používateľské tabuľky stránok (koreň `mm->pgd`,
  nie registre vCPU) prechádza iba `procmap`, aby zmenené stránky binov priradil
  procesom; podporuje iba 4-úrovňové tabuľky a zdieľanú stránku priradí prvému
  procesu, ktorý ju mapuje;
- nezastavuje VM — snímka je živá, stránky pochádzajú z rôznych okamihov, a preto má
  každý prechod zoznamu strop, detekciu cyklu a príznak `truncated`; zoznam procesov
  tvoria pri roztrhnutom spojení uzly, ktoré prechod dopredu prešiel pred prvým
  spojením nezhodným s opačným smerom, iba ak prechod dozadu prejde presne tie uzly
  (`walk: "prev"`), alebo ak `init_task.prev` ukazuje práve na prvý nezhodný uzol
  a jeho obsah je vlákno procesu spomedzi tých uzlov (`walk: "tail"`: stránka
  posledného uzla je z iného okamihu ako spojenia naň);
- nerobí detekciu malvéru. `checks` porovnáva dva zdroje, ktoré musia sedieť, a nález je
  ich rozdiel — nie skóre a nie odhad.
