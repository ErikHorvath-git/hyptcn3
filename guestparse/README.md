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
python3 -m guestparse info --snapshot /var/tmp/vmic-val --profile profiles/debian12-6.1.0-42-cloud-amd64
```

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
| `checks` | kontroly integrity: `sys_call_table`, procesy krížovo, moduly krížovo |
| `validate` | porovnanie s pozemnou pravdou z hosťa (`ps`, `lsmod`, `ss`) |

Spoločné parametre: `--snapshot` (adresár s reťazcom `.vmicd`, jeden `.vmicd` alebo
surový obraz), `--profile` (adresár s `kallsyms.txt` a `btf.txt`), `--json` (na stdout
ide iba JSON; upozornenia idú na stderr), `--banner` (iný reťazec bannera),
`--chain-until SEQ` (použi reťazec iba po danú časť — ako `vmicollect restore --until`).

## Návratové kódy

| Kód | Znamená |
|---|---|
| 0 | prebehlo a nič sa nenašlo |
| 1 | `checks` niečo našiel — nesmie zaniknúť v úspešnom kóde |
| 2 | chyba: snímka sa nedá otvoriť (aj rozbitý reťazec), profil sa nedá načítať, posun jadra sa nenašiel |
| 3 | podpríkaz nie je implementovaný (chýba modul balíka) |
| 4 | `checks`: nič sa nenašlo, **ale aspoň jedna kontrola sa neuzavrela** |
| 5 | **nesúlad profilu**: `kallsyms` je z iného štartu jadra (KASLR) než snímka a preukotvenie (nižšie) neprebehlo |

Kód 5 platí pre **všetky** podpríkazy a zisťuje sa pred ich výkonom
(`GuestView.profile_boot_mismatch()`). Od bloku A2 sa nesúlad najprv **skúsi preukotviť**
(`GuestView.reanchor()`): posun medzi bootom profilu a bootom snímky sa zmeria z tabuliek
stránok (spätné hľadanie VA pre fyzickú adresu `init_task`, potvrdené druhou kotvou
`linux_banner`) a adresy profilu sa posunú; úspech sa oznámi na stderr a pokračuje sa.
Kód 5 nastáva až vtedy, keď preukotvenie nejde (FGKASLR, chýbajúce stranky tabuliek) —
nie je to neuzavretá kontrola („neviem"), ale chyba vstupu, preto prebíja aj nález (1),
aj neuzavretosť (4). Čítacie podpríkazy (`info`, `ps`, `lsmod`, `ss`, `checks`) výsledok
aj tak vypíšu, označený ako `NEUPLNE`, a diagnózu vypíšu na stderr; `validate` sa nespustí
vôbec a výstupný JSON nezapíše, aby po sebe nenechal súbor v `data/results`.

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
popisom. Kontroly sú tie isté, aké robí `vmic_delta_restore()` v
`vmicollect/src/writer_delta.c`:

1. reťazec nie je prázdny;
2. všetky časti majú rovnaké `chain_id`;
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
python3 -m pytest -q -rs                          # celý balík
python3 -m pytest -q -m "not realsnap"            # ako v čerstvom klone
GUESTPARSE_REQUIRE_REAL=1 python3 -m pytest -q    # chýbajúci vstup = chyba, nie preskočenie
python3 -m pytest -q --require-real guestparse    # to isté prepínačom
```

Prepínač `--require-real` zavádza `conftest.py` balíka, takže pytest ho pozná iba vtedy,
keď sa v príkaze objaví cesta do balíka (`guestparse`). Bez cesty sa to isté dosiahne
premennou prostredia `GUESTPARSE_REQUIRE_REAL=1`.

Vstupy sú troch druhov:

- **malá snímka v repozitári** (`tests/data/mini.vmicd`, 110 kB) — je vždy k dispozícii,
  takže základné testy rekonštrukcie aj **injekčný test detektora hookov** bežia aj
  v čerstvom klone. Odkiaľ pochádza a čo v nej je: `tests/data/README.md`;
- **reálna snímka hosťa** (`/var/tmp/vmic-val`, `/var/tmp/vmic-delta`) — existuje iba na
  stroji, kde sa zbieralo; testy nad ňou majú značku `realsnap`;
- **výstup zo `make -C vmicollect test`** — značka `selftest`.

Keď chýba vstup, test sa preskočí **nahlas**: `conftest.py` zapína `-rs` a na konci
behu vypíše, koľko testov sa preskočilo a prečo. Preskočený test nie je prešiel.

## Čo balík nerobí

- neprekladá adresy používateľského priestoru (backend nečíta registre vCPU), takže
  obsah pamäte procesov sa neparsuje;
- nezastavuje VM — snímka je živá, stránky pochádzajú z rôznych okamihov, a preto má
  každý prechod zoznamu strop, detekciu cyklu a príznak `truncated`;
- nerobí detekciu malvéru. `checks` porovnáva dva zdroje, ktoré musia sedieť, a nález je
  ich rozdiel — nie skóre a nie odhad.
