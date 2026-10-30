<!-- SABLONA: Toto je ŠABLÓNA. Generovaný výsledok je docs/PRIRUCKA.md.
     Značky tvaru "zavinac zavinac MENO zavinac zavinac" dosadzuje
     scripts/gen_prirucka.py z kódu a z uložených artefaktov.
     Číslo sem nepíš ručne: taký údaj zostarne ticho. Keď potrebuješ nový fakt,
     pridaj preň funkciu do generátora. Cestu v spätných apostrofoch alebo
     v bloku príkazov generátor overí a neexistujúcu ohlási kódom 5. -->
# Príručka k hyptcn3

Vstupný dokument repozitára; stav kódu a artefaktov k @@DATUM_STAVU@@. Súbor je
generovaný a needituje sa ručne — ako, hovorí kapitola 10.

## 1. Čo to je

Program číta pamäť bežiaceho virtuálneho stroja zvonku, z hostiteľa, a periodicky z nej
ukladá snímky. Druhý program zo snímky poskladá zoznam procesov, modulov jadra a sieťových
spojení tak, ako ich v tej chvíli videl hosťovaný systém. Z každej snímky sa počíta krátky
číselný vektor o tom, kde a ako sa pamäť oproti predchádzajúcej zmenila; vektory idú za sebou do okien pre
TCN prediktor normálu v balíku `safeguard/` (`python3 -m safeguard`), ktorý z chyby predikcie a z kontrol
integrity robí alarm. Model nad serverovým korpusom je natrénovaný, záverečný test zatiaľ nebežal (kapitola 8).

## 2. Čo treba mať

- hostiteľ s KVM, QEMU a libvirt a na ňom doména so sledovaným systémom;
- C prekladač, `clang` s cieľom BPF, `pkg-config`, `libbpf`, `zlib`, `libdl`, GNU `make`; Python 3 s balíkmi z `requirements.txt`;
- root na hostiteľovi — iba na čítanie pamäte VM (`CAP_BPF`, `CAP_PERFMON`);
- profil jadra hosťa v `profiles/` (kapitola 4); bez neho parser neurobí ani krok.

Vnútri hosťa netreba pre zber nič inštalovať. `qemu-guest-agent` alebo ssh slúži na odber
profilu a pozemnej pravdy a v laboratóriu aj na orchestráciu a overenie identity prostredia.

## 3. Preklad a testy (bez VM a bez roota)

```bash
make -C vmicollect        # -> ./vmicollect/build/vmicollect
make -C vmicollect test   # plná snímka, tri delty, obnova reťazca, kontrolný súčet
python3 -m pytest -q      # parser, príznaky, tcn, safeguard a skripty zberu
```

`make test` prejde celú cestu zberu nad syntetickým obrazom veľkosti @@SELFTEST_OBRAZ@@, ktorý si sám vyrobí. Testov je @@TESTY@@.

## 4. Ako vznikne snímka

`scripts/root_run.sh` pracuje s doménou `hyptcn-guest` (inú zadáš `-d/--domain` alebo
`VMIC_DOMAIN`), laboratórium a zber korpusu s jej kópiou `hyptcn-lab` (`config/collection-v2.json`).
Profil jadra hosťa (symboly z `kallsyms`, offsety polí z BTF) pre jadro oboch domén **už
v repozitári je** — priznaná vstupná závislosť, rovnako ako profil pri LibVMI alebo Volatility.

**Pozor na boot.** Adresy v `kallsyms` sú randomizované pri každom štarte hosťa (KASLR);
offsety polí z BTF reštart prežijú. Pri nesúlade sa profil sám **preukotví** (blok A2
v `docs/STAV.sk.md`; posun sa zmeria z tabuliek stránok, kotvy `init_task` + `linux_banner`);
až keď to nejde (FGKASLR, chýbajúce stránky), nástroj vypíše `NESULAD PROFILU` a skončí kódom 5.

```bash
scripts/get_profile.sh -f root@192.168.122.100  # nové jadro hosťa alebo kód 5
sudo scripts/root_run.sh probe                  # prvý beh: vidno doménu a jej memsloty?
make lab-up && make lab-test                    # VM hyptcn-lab, služby a premávka
sudo python3 scripts/collection.py run --role pilot --group <skupina> --scenario steady --seed <seed>
python3 scripts/collection.py audit data/collections/<session>
python3 -m guestparse ps --snapshot data/collections/<session>/raw --profile @@PROFIL@@
```

`sudo` sa na heslo spýta interaktívne; root treba iba na eBPF zber (`probe`, `run`). Pilot zapíše
snímky so sidecarmi a logy do `data/collections/<session>/` (mimo gitu) a `audit` z nich bez roota
vyextrahuje príznaky a rozhodne o prijatí (`docs/METODIKA_ZBERU.sk.md`); kampaň z prijatého pilota
vykoná `scripts/campaign.py` (`docs/AUTOMATICKY_ZBER.sk.md`). Na zberovom PC sa namiesto `python3`
používa interpreter z `.venv`. Snímka writera `delta` je súbor `.vmicd`: hlavička a záznamy
„index stránky + obsah“. Merania sa nespúšťajú ručne poskladanými príkazmi: `scripts/root_run.sh`
(`probe|once|run|validate`) aj skripty zberu zapíšu do výstupu commit a SHA-256 binárky zberača;
podpríkazy `session|batch` spúšťajú staršie diagnostické sedenia (`harness/README.md`). „`probe`
nič nezapisuje“ v kapitole 6 platí o binárke; skript okolo nej `data/results/probe_<stamp>.json` zapíše.

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
  ├─► guestparse ──► procesy, moduly, sokety hosťa a kontroly integrity
  └─► perbin.c   ──► per-bin vektor (zapísaný do sidecaru)
                       │  features/snapshot.py → safeguard/features.py
                       ▼
                     okno: príznaky snímky + čas × bin × príznak binu
                       │  safeguard/model.py — TCN z tcn/model.py
                       ▼
                     skóre odchýlky a profil záťaže → prah, k z n → alarm a HOLD
```

**1. Čítanie pamäte** — `vmicollect/src/backend_ebpf.c`, slučka `vmicollect/src/backend.c`.
KVM drží pamäť hosťa ako zoznam blokov; blok sa volá **memslot** a hovorí, ktorý rozsah
fyzických adries hosťa leží na ktorej adrese v procese QEMU. Zberač číta iba memsloty —
priestor medzi nimi je diera bez pamäte, nie nuly. VM sa pritom nezastavuje.

**2. Zápis snímky** — `vmicollect/src/writer_raw.c` uloží celú pamäť, `vmicollect/src/writer_delta.c`
iba stránky zmenené od predchádzajúcej (porovnáva sa ich hash). Plná je prvá snímka reťazca a potom
každá N-tá podľa `output.delta_full_every` (východzie @@FULL_EVERY@@) a je referenciou pre delty za ňou.
Pri `output.sidecar` (východzie `@@SIDECAR_KLUC@@`) vzniká vedľa snímky sidecar `.json`; robí ho `meta.c`.
Od verzie 1.1 snímku writera `delta`, jej SHA-256 aj sidecar zapisuje vlákno `vmic-writer`
(`vmicollect/src/output.c`); vzorkovací cyklus zmenené stránky namiesto zápisu kopíruje do fronty.

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

**5. Okná a normalizácia** — `safeguard/features.py` skladá okná z príznakov správania celej
snímky (`features/snapshot.py`) a z per-bin bloku `čas × bin × príznak`. Normalizácia sa fituje
iba na riadkoch role `train` a pri prehrávaní ani živom skórovaní sa znova nefituje
(`docs/SAFEGUARD.sk.md`). Príznaky a ich kontrakt opisuje `features/PERBIN.md`.

**6. Model a skóre** — `safeguard/model.py`: globálna a zdieľaná per-bin TCN z blokov `tcn/model.py`
(kauzálne dilatované konvolúcie, reziduálne bloky) predpovedajú posledný krok okna a chyba predikcie
je skóre; samostatný klasifikátor určí profil záťaže. Kalibrovaný prah s pravidlom k z n robí zo
skóre alarm, nález integrity ho vyvolá sám (`safeguard/runtime.py`). Staršia diagnostická cesta
(`tcn/train.py`, `tcn/score.py`, `scripts/detektor.py`) zostáva do konca experimentov; jej prediktor
sa trénoval iba na krátkych benígnych sedeniach, nie na korpuse `benign-v6-20261026`.

| príkaz zberača | čo robí |
|---|---|
@@PRIKAZY_VMIC@@

Prepínače: @@PREPINACE_VMIC@@.

Podpríkazy: `python3 -m guestparse` — @@PODPRIKAZY_GUESTPARSE@@; `python3 -m features` — @@PODPRIKAZY_FEATURES@@; `python3 -m safeguard` (`docs/SAFEGUARD.sk.md`) — @@PODPRIKAZY_SAFEGUARD@@; `scripts/collection.py` (`docs/METODIKA_ZBERU.sk.md`) — @@PODPRIKAZY_COLLECTION@@; `scripts/campaign.py` (`docs/AUTOMATICKY_ZBER.sk.md`) — @@PODPRIKAZY_CAMPAIGN@@.

**Konfiguračné kľúče** (`vmicollect config --keys`, prebijú sa cez `-o sekcia.kluc=hodnota`):

@@KONFIG@@

Východzie hodnoty kľúčov, ktoré text spomína: @@VYCHODZIE@@.

**Polia sidecaru**, ktoré sú vstupom ďalších krokov:

@@SIDECAR@@

## 7. Namerané čísla

Merané @@DATUMY@@ na vývojovom hostiteľovi, doména `hyptcn-guest` v zmrazenom stave (bez agenta
v hosťovi). Piloty a kampane na zberovom PC vlastní `docs/MERANIA.md`.

| čo | hodnota | n | artefakt |
|---|---|---|---|
@@CISLA@@

Stabilná množina procesov sú tie, ktoré boli v `ps` pred snímkou aj po nej. Sokety
„navyše“ nie sú falošné pozitíva: `ss -tulpn` vypisuje iba počúvajúce sokety, zo snímky
je vidieť aj nenaviazaný UDP soket a dopyt na DNS.

Prostredie, na ktorom merania bežali (z artefaktov, nie z tohto stroja dnes):

@@PROSTREDIE_MERANI@@

Commity, z ktorých merania pochádzajú:

@@COMMITY@@

## 8. Čo nefunguje a čo ešte nie je

Modely detekčnej cesty `safeguard/` sú natrénované na korpuse `benign-v6-20261026`, `python3 -m tcn.eval far`
ich však vyhodnotil iba na role `dev`, ktorá vyberala checkpointy: **výsledok nie je odložený**. Klasifikátor
na nej nerozlíšil `steady` od `read_heavy` a zamieňal `mixed` s `write_heavy`. Záverečný test na `test_benign`
zatiaľ nebežal, čas do detekcie nepočíta žiadny kód a `smoke` overuje iba mechaniku (`docs/SAFEGUARD.sk.md`,
L16); otvorené body voči zadaniu vlastní `docs/STAV.sk.md`. Živá latencia snímka → skóre počas zberu meraná
nie je, len spracovanie uložených snímok (napr. staršou cestou `tcn.score`,
`data/results/latency_score_20260919.json`; L12). Slovo „real-time“ v názve práce preto znamená periodický
zber s meraným časom cyklu (kapitola 7). Presnosť voči reálnym malvérovým vzorkám zatiaľ nebola meraná;
syntetický scenár sa za také meranie nevydáva. Plán ďalšej etapy je v `docs/METODIKA_ZBERU.sk.md`. Pri
načítaní BPF programu sa objaví nefatálne `@@LIBBPF@@` — zber funguje, príčina neznáma.

Ostatné obmedzenia vlastní `docs/LIMITACIE.md` (@@LIMITACIE@@); prerozprávať ich tu by
znamenalo držať dve znenia toho istého. Nadpisy sú preto dosadené z neho, skrátené:

@@LIMITACIE_NADPISY@@

## 9. Kam ďalej

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

**Čo na tomto súbore drží kontrola.** Čísla, príkazy, prepínače, podpríkazy, konfiguračné kľúče, polia
sidecaru (z čerstvého sidecaru práve preloženej binárky), strom adresárov, testy a nadpisy limitácií
dosadí generátor z kódu a artefaktov. Pri ručnej próze overí iba to, že každá cesta k súboru v texte
existuje — vecne zlú vetu bez čísla nezachytí. `scripts/check_claims.sh` bez argumentov volá aj
`scripts/check_prirucka.sh`, ktorý kód najprv preloží, príručku pregeneruje a porovná, takže zastaraná
príručka je nález ako každý iný. Bežiacu doménu ani roota generátor nepotrebuje, zostavenú binárku
áno — bez nej dá na miesto faktu `NEZISTENE (dôvod)` a skončí nenulovým kódom; taký súbor sa necommituje.
