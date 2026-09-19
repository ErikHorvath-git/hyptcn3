# Testovacie dáta balíka `guestparse`

## `mini.vmicd` — malá snímka v repozitári

### Prečo existuje

Reálne snímky (`/var/tmp/vmic-val`, 463 MiB) ležia mimo repozitára a nie sú trvalé.
Kým testy záviseli iba na nich, v čerstvom klone sa **ticho preskočilo 17 testov**,
medzi nimi všetky tri testy z `test_injection.py` — teda jediný pozitívny dôkaz, že
detektor hookov v `sys_call_table` niečo nájde. „50 passed“ pritom vyzeralo rovnako
ako beh, kde prebehlo všetko.

`mini.vmicd` je výrez z jednej reálnej snímky, dosť veľký na to, aby nad ním bežala
rekonštrukcia procesov, modulov aj injekčný test, a dosť malý na to, aby sa dal
verzionovať (110 872 B, 27 stránok).

### Odkiaľ dáta pochádzajú

| Položka | Hodnota |
|---|---|
| Zdrojový súbor | `data/raw/20260919T111417Z_once/hyptcn-guest_000000_20260919T111419066Z.vmicd` (po výrobe zmazaný, je mimo gitu) |
| SHA-256 zdroja | `d6069336d422446ec80745353f69eb8499a9215bd36a25ad9e2da4314277849e` |
| Veľkosť zdroja | 368 662 384 B (89 830 stránok) |
| Hosť | doména `hyptcn-guest`, Debian 12, jadro `6.1.0-42-cloud-amd64` |
| Boot hosťa | `82b778a3-89f8-4b04-b518-5db8ebeb4ab4` (štart 2026-09-19 10:30:31) |
| Zber | `vmicollect`, backend `ebpf/kvm`, `chain_id` 1789816459066, `seq` 0, plná snímka |
| Dátum zberu | 2026-09-19 |
| Vyrobené | 2026-09-19 skriptom `make_mini.py` |
| SHA-256 výsledku | `a1356050132e0e320a260192078c97bb845a8dce53b8d1cb83241ce2377cf1a9` |

### Patrí k jednému bootu hosťa — rovnako ako profil

`mini.vmicd` je pamäť jadra z jedného konkrétneho štartu hosťa, takže sa dá rozobrať
**len profilom z toho istého štartu**. KASLR posúva obraz jadra pri každom bootnutí a
tabuľky stránok v snímke sú indexované virtuálnymi adresami práve toho bootu.

Preto platí: keď sa obnoví `profiles/debian12-6.1.0-42-cloud-amd64/` (po reštarte
hosťa), musí sa **spolu s ním** vyrobiť znovu aj táto snímka. Inak testy nad ňou
spadnú na diagnóze `NESULAD PROFILU` — čo je správne správanie, nie chyba testov
(pozri `guestparse/tests/test_profile_boot.py`). Táto snímka a profil v repe pochádzajú
z bootu uvedeného v tabuľke vyššie.

Úplný záznam je v `mini.json` (manifest vzniká spolu so snímkou a testy z neho čítajú
očakávané hodnoty — nie sú prepísané ručne).

### Čo v nej je

Skript `make_mini.py` nič neodhaduje: otvorí reálnu snímku, vykoná nad ňou presne tie
operácie, ktoré robia testy, a zapamätá si **každú fyzickú stránku, z ktorej sa pritom
čítalo**. Do `mini.vmicd` ide táto množina a nič iné:

| Krok | Stránok |
|---|---|
| nájdenie posunu jadra (banner + `init_task.comm` + `page_offset_base`) | 5 |
| krížová kontrola prekladu adries (tabuľky stránok z `init_top_pgt`) | 3 |
| prvých 8 `task_struct` zo zoznamu `init_task.tasks` | 10 |
| prvé 3 `struct module` z oblasti modulov | 7 |
| obsah `sys_call_table` (451 položiek) | 2 |
| **spolu** | **27** |

Počty stránok na krok závisia od toho, ako sa štruktúry v danom bootne rozložili na
stránky — po novej výrobe snímky sa menia. Berú sa z `mini.json`, neprepisujú sa ručne.

Všetky bajty sú pôvodné — nič sa neupravuje ani nedopisuje. Hlavička `.vmicd` je
prevzatá zo zdrojovej snímky (rovnaká `page_size`, `memsize`, `region_sig`, `chain_id`),
zmenil sa iba počet záznamov, takže súbor je platná plná snímka a otvorí ho aj
`vmicollect restore`.

Obsahom sú stránky pamäte jadra testovacej VM: reťazec bannera, `task_struct` prvých
ôsmich procesov (mená a PID), tri `struct module`, tabuľka systémových volaní a
niekoľko tabuliek stránok. Stránky používateľských procesov v nej nie sú.

### Čo to nie je

Nie je to pamäť hosťa. Je to podmnožina jednej snímky, vybraná podľa toho, čo čítajú
testy. **Nedajú sa nad ňou robiť merania** a čísla z nej nepatria do textu práce.
Prechody zoznamov sa nad ňou neuzavrú (deviaty `task_struct` v nej už nie je), takže
`ps` aj `lsmod` nad ňou hlásia `NEÚPLNE` a krížové kontroly procesov a modulov sú
`NEUZAVRETÉ` — testy to overujú, lebo mlčky polovičný zoznam je presne to, čo sa
nesmie stať.

### Ako ju vyrobiť znovu

Potrebná je reálna snímka a profil jadra hosťa (z koreňa repozitára):

```sh
sudo scripts/root_run.sh once -w delta            # snímka z AKTUÁLNEHO bootu hosťa
scripts/get_profile.sh -f root@192.168.122.100    # profil z toho istého bootu
python3 guestparse/tests/data/make_mini.py \
    --src data/raw/<stamp>_once \
    --profile profiles/debian12-6.1.0-42-cloud-amd64 \
    --tasks 8 --modules 3
rm -rf data/raw/<stamp>_once                      # zdroj je veľký, v repe nemá čo robiť
```

Skript prepíše `mini.vmicd` aj `mini.json`. Po zmene sa musia opraviť aj hodnoty
v tomto súbore (SHA-256 a počty) — test `test_mini_snimka_sa_nemeni` kontroluje, že
súbor sedí s manifestom.

### Prečo je `.vmicd` v gite

Koreňový `.gitignore` vylučuje `*.vmicd`, lebo tak sa volajú snímky s veľkosťou stoviek
MiB. Miestny `.gitignore` v tomto adresári výnimku vracia späť pre jediný súbor
`mini.vmicd` — rovnako, ako to robí `profiles/.gitignore` pre `btf.raw`. Strop veľkosti
stráži test `test_mini_je_mala` (512 KiB).
