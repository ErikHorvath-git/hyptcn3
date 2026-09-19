<!-- SABLONA: Toto je ŠABLÓNA. Generovaný výsledok je docs/PRIRUCKA.md.
     Značky tvaru "zavinac zavinac MENO zavinac zavinac" dosadzuje
     scripts/gen_prirucka.py z kódu a z uložených artefaktov.
     Číslo ani cestu sem nepíš ručne: taký údaj zostarne ticho. Keď potrebuješ
     nový fakt, pridaj preň funkciu do generátora. -->
# Príručka k hyptcn3

Vstupný dokument repozitára; stav kódu a artefaktov k @@DATUM_STAVU@@. Súbor je
generovaný a needituje sa ručne — ako, hovorí kapitola 10.

## 1. Čo to je

Program číta pamäť bežiaceho virtuálneho stroja zvonku, z hostiteľa, a periodicky z nej
ukladá snímky. Druhý program zo snímky poskladá zoznam procesov, modulov jadra a sieťových
spojení tak, ako ich v tej chvíli videl hosťovaný systém. Z každej snímky sa počíta krátky
číselný vektor o tom, kde a ako sa pamäť oproti predchádzajúcej zmenila; vektory idú za
sebou do okien a okno je vstupom modelu (Temporal Convolutional Network), ktorý z neho
vypočíta jedno číslo. Model je implementovaný a napojený, ale **natrénovaný nie je** —
korpus neexistuje, takže to číslo nie je detekcia. Vnútri sledovaného stroja pritom nebeží
nič, čo by sa dalo vypnúť.

## 2. Čo treba mať

- hostiteľ s KVM, QEMU a libvirt a na ňom doména so sledovaným systémom;
- `clang` s podporou cieľa BPF, `libbpf`, `zlib`, `libdl`, GNU `make`, Python 3;
- root na hostiteľovi — iba na čítanie pamäte VM (`CAP_BPF`, `CAP_PERFMON`);
- profil jadra hosťa v `profiles/` (kapitola 4); bez neho parser neurobí ani krok.

Vnútri hosťa netreba nič inštalovať. `qemu-guest-agent` alebo ssh potrebuje odber
profilu a pozemnej pravdy, teda príprava a overovanie — nie samotný zber.

## 3. Preklad a testy (bez VM a bez roota)

```bash
make -C vmicollect        # -> ./vmicollect/build/vmicollect
make -C vmicollect test   # plná snímka, tri delty, obnova reťazca, kontrolný súčet
python3 -m pytest -q      # testy parsera a príznakov
```

`make test` prejde celú cestu zberu nad syntetickým obrazom veľkosti
@@SELFTEST_OBRAZ@@, ktorý si sám vyrobí. Testov je @@TESTY@@.

## 4. Ako vznikne snímka

Skripty pracujú s doménou `hyptcn-guest`; inú zadáš prepínačom `-d/--domain` alebo
premennou `VMIC_DOMAIN`. Profil jadra hosťa (symboly z `kallsyms`, offsety polí štruktúr
z BTF) **pre túto doménu už v repozitári je** — priznaná vstupná závislosť, rovnako ako
profil pri LibVMI alebo Volatility.

**Pozor na boot.** Adresy v `kallsyms` sú randomizované pri každom štarte hosťa (KASLR),
takže profil platí pre ten boot, v ktorom vznikol; offsety polí z BTF platia pre verziu
jadra a reštart prežijú. **Po každom reštarte hosťa treba profil odobrať nanovo** —
existujúci `get_profile.sh` bez `-f` neprepíše. Nesúlad sa neprehliadne: zisťuje sa pred
každým podpríkazom, nástroj vypíše `NESULAD PROFILU` aj s príčinou (KASLR, symbol, úroveň
tabuliek stránok a položka), výpisy označí `NEUPLNE` a skončí kódom 5; `validate` sa ani
nespustí a JSON nezapíše. Raz sa to už stalo, celý výstup je v `docs/MERANIA.md` (L17).

```bash
scripts/get_profile.sh -f root@192.168.122.100  # po reštarte hosťa; -f prepíše starý profil
sudo scripts/root_run.sh probe                  # vidno doménu a jej memsloty?
sudo scripts/root_run.sh run -w delta -i 5 -N 6 # šesť cyklov, perióda 5 s
python3 -m guestparse ps --snapshot data/raw/<stamp>_run --profile @@PROFIL@@
python3 -m features perbin --snapshot data/raw/<stamp>_run
```

`sudo` sa na heslo spýta interaktívne; root treba iba na tie dva riadky, teda na samotné
čítanie pamäte. Tretí príkaz zapíše snímky do `data/raw/<stamp>_run/` (mimo gitu) a súhrn
behu do `data/results/run_<stamp>.json`. Jedna snímka je súbor `.vmicd`: hlavička, rozsahy
fyzických adries a ich obsah, celý alebo iba zmenené stránky. `--snapshot` berie taký
súbor aj celý adresár s reťazcom snímok.

Merania sa nespúšťajú ručne, ale cez `scripts/root_run.sh probe|once|run|validate`, ktorý
do každého výstupu zapíše commit, dátum, presný príkaz a SHA-256 binárky. „`probe` nič
nezapisuje“ v kapitole 6 platí o binárke; skript okolo nej `data/results/probe_<stamp>.json`
zapíše.

## 5. Čo je kde

| adresár | čo rieši | kde začať čítať | súborov spolu / riadkov v `.c .h .py .sh .md` |
|---|---|---|---|
@@STROM@@

## 6. Ako to funguje

```
pamäť bežiacej VM
  │  vmicollect  (eBPF nad KVM, beží na hostiteľovi)
  ▼
snímka .vmicd  +  sidecar .json (metadáta snímky vedľa nej)
  ├─► guestparse ──► procesy, moduly, sokety hosťa
  └─► perbin.c   ──► per-bin vektor (zapísaný do sidecaru)
                       │  features/snapshot.py + features/windows.py
                       ▼
                     okná (okno, čas, bin, príznak)
                       │  tcn/model.py — TCN
                       ▼
                     skóre: jedno číslo na okno
                     tcn/score.py nad bežiacim zberom, tcn/train.py nad uloženými
                     oknami; model NIE JE natrénovaný, skóre NIE JE detekcia
```

**1. Čítanie pamäte** — `vmicollect/src/backend_ebpf.c`, slučka `vmicollect/src/backend.c`.
KVM drží pamäť hosťa ako zoznam blokov; blok sa volá **memslot** a hovorí, ktorý rozsah
fyzických adries hosťa leží na ktorej adrese v procese QEMU. Zberač číta iba memsloty —
priestor medzi nimi je diera bez pamäte, nie nuly. VM sa pritom nezastavuje.

**2. Zápis snímky** — `vmicollect/src/writer_raw.c` uloží celú pamäť,
`vmicollect/src/writer_delta.c` iba stránky zmenené od predchádzajúcej (porovnáva sa ich
hash). Plná je prvá snímka reťazca a potom každá N-tá podľa `output.delta_full_every`
(východzie @@FULL_EVERY@@) a je referenciou pre delty za ňou. Pri `output.sidecar`
(východzie `@@SIDECAR_KLUC@@`) vzniká vedľa snímky sidecar `.json`; robí ho `meta.c`.

**3. Rekonštrukcia objektov hosťa** — `guestparse/view.py`. V snímke sú iba bajty; že na
istej adrese začína zoznam procesov a meno procesu leží istý počet bajtov od jeho začiatku,
v nej nie je. Tejto medzere sa hovorí **semantic gap** a preklenie ju profil jadra hosťa
z `profiles/`. Výsledok sa porovnáva s **pozemnou pravdou** odobratou zvnútra hosťa
príkazmi `ps`, `lsmod` a `ss` tesne pred snímkou a po nej (`python3 -m guestparse validate`).

**4. Príznaky** — `vmicollect/src/perbin.c`, referencia `features/perbin.py`.
**Per-bin vektor**: pamäť sa podľa fyzickej adresy rozdelí na rovnako veľké bloky (biny,
východzie @@BIN@@) a za každý bin sa uloží podiel zmenených stránok, podiel nulových
stránok, priemerná entropia zmenených stránok a príznak, či sa bin zmenil. Index binu je
adresa delená veľkosťou binu, takže ten istý bin je v každej snímke ten istý kus pamäte;
bin bez memslotu nevzniká. To isté počíta C aj Python a `features crosscheck` ich porovná.

**5. Okná a normalizácia** — `features/windows.py` skladá po sebe idúce vektory do poľa
tvaru `(okno, čas, bin, príznak)`. `features/normalize.py` preškáluje každý príznak na
z-score; priemer a odchýlku počíta iba zo záznamov bez škodlivého správania a uloží ich do
manifestu, aby na testovacích dátach platili tie isté. Podrobnosti v `features/PERBIN.md`.

**6. Model a skóre** — `tcn/model.py` (kauzálne dilatované konvolúcie, reziduálne bloky),
baseliny `tcn/baselines.py`, metriky `tcn/eval.py`. Okno vojde, jedno číslo vyjde.
`tcn/train.py` beží nad uloženými oknami, `tcn/score.py` nad adresárom, do ktorého píše
`vmicollect run`. **Model natrénovaný nie je** — váhy sú náhodné, korpus neexistuje
(`docs/LIMITACIE.md`, L16), takže číslo hovorí len to, že cesta beží ako celok.

**Príkazy zberača**

| príkaz | čo robí |
|---|---|
@@PRIKAZY_VMIC@@

Prepínače: @@PREPINACE_VMIC@@.

Podpríkazy `python3 -m guestparse`: @@PODPRIKAZY_GUESTPARSE@@.
Podpríkazy `python3 -m features`: @@PODPRIKAZY_FEATURES@@.

**Konfiguračné kľúče** (`vmicollect config --keys`, prebijú sa cez `-o sekcia.kluc=hodnota`):

@@KONFIG@@

Východzie hodnoty kľúčov, ktoré text spomína: @@VYCHODZIE@@.

**Polia sidecaru**, ktoré sú vstupom ďalších krokov:

@@SIDECAR@@

## 7. Namerané čísla

Merané @@DATUMY@@ na doméne `hyptcn-guest` v zmrazenom stave (bez agenta v hosťovi).

| čo | hodnota | n | artefakt |
|---|---|---|---|
@@CISLA@@

Stabilná množina procesov sú tie, ktoré boli v `ps` pred snímkou aj po nej. Sokety
„navyše“ nie sú falošné pozitíva: `ss -tulpn` vypisuje iba počúvajúce sokety, zo snímky
je vidieť aj nenaviazaný UDP soket a dopyt na DNS.

Staršie číslo pre cyklus so zapnutým kontrolným súčtom už neplatí: SHA-256 sa vtedy
počítal v `finish()` nad celým riedkym súborom, dnes v `feed()` (`docs/MERANIA.md`).

Prostredie, na ktorom merania bežali (z artefaktov, nie z tohto stroja dnes):

@@PROSTREDIE_MERANI@@

Commity, z ktorých merania pochádzajú:

@@COMMITY@@

## 8. Čo nefunguje a čo ešte nie je

Skórovanie (`tcn/score.py`) beží, model natrénovaný nie je, takže jeho výstup nie je
detekcia. Živá latencia snímka → skóre, teda meraná počas zberu, meraná nie je; odmerané
je len spracovanie nad uloženou snímkou (`data/results/latency_score_20260919.json`).
Slovo „real-time“ v názve práce preto znamená periodický zber s meraným časom cyklu.
Presnosť voči malvérovým vzorkám sa merať nebude: vzorky nie sú k dispozícii
a **nenahrádzajú sa ničím** — napísané syntetické scenáre sa na tréning vedome nepoužili,
lebo model natrénovaný na nich by klasifikoval scenáre autora, nie malvér (L16). Pri
načítaní BPF programu sa objaví nefatálne `@@LIBBPF@@` — zber funguje, príčina neznáma.

Ostatné obmedzenia vlastní `docs/LIMITACIE.md` (@@LIMITACIE@@); prerozprávať ich tu by
znamenalo držať dve znenia toho istého. Nadpisy sú preto dosadené z neho, skrátené:

@@LIMITACIE_NADPISY@@

## 9. Kam ďalej

Každý typ faktu má jeden dokument, ktorý ho vlastní; keď si odporujú, platí tabuľka.

| dokument | čo vlastní | riadkov |
|---|---|---|
@@DOKUMENTY@@

## 10. Ako sa táto príručka udržiava

`docs/PRIRUCKA.md` je generovaný, needituj ho: próza sa mení v šablóne
`docs/PRIRUCKA.sk.md`, nový fakt sa pridáva ako funkcia do generátora.

```bash
python3 scripts/gen_prirucka.py     # prepíše docs/PRIRUCKA.md zo šablóny
scripts/check_prirucka.sh           # ohlási, že sa príručka s kódom rozišla
```

**Čo na tomto súbore drží kontrola.** Generátor dosadí z kódu strom adresárov a počty
riadkov, príkazy, prepínače a podpríkazy z `--help`, konfiguračné kľúče a ich východzie
hodnoty, veľkosť obrazu v selfteste, polia sidecaru (z čerstvého sidecaru vyrobeného práve
preloženou binárkou), počet testov a znenia nadpisov limitácií; z artefaktov len to, čo sa
bez merania zistiť nedá. Próza je ručná a overuje sa pri nej jediné: že každá cesta
k súboru v texte existuje — vecne zlú vetu bez čísla kontrola nezachytí.

`scripts/check_prirucka.sh` si volá aj `scripts/check_claims.sh`, takže zastaraná príručka je
nález ako každý iný; kód si najprv preloží, aby videla zmenu v zdrojáku, nie v starej binárke.
Bežiacu doménu ani roota generátor nepotrebuje, zostavenú binárku áno — bez nej dá na
miesto faktu `NEZISTENE (dôvod)` a skončí nenulovým kódom; taký súbor sa necommituje.
