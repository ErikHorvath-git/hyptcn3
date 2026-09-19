# Posudok funkčnosti: zadanie vs. repozitár hyptcn3

Stav k 2026-09-19, pracovný strom nad commitom `da8ad2e` s neuloženými zmenami (o. i. `tcn/score.py`
a `tcn/tests/test_score.py` nie sú v gite vôbec; `scenarios/` a `scripts/collect_corpus.sh` sú
zmazané). Posudzoval som to, čo beží dnes, nie HEAD.

**Odpoveď:** zberná a rekonštrukčná časť zadania je pokrytá a dá sa spustiť; detekčná časť
(natrénovaný TCN, presnosť voči malvéru, reálne scenáre) pokrytá nie je.

## Tabuľka

| Požiadavka zadania (doslovne) | Čo v repe zodpovedá | Overil som spustením? | Stav |
|---|---|---|---|
| „hypervisor modul postavený na open-source hypervízore (QEMU/KVM, Xen alebo BareFlank)“ | `vmicollect/`, eBPF nad KVM, backend `ebpf` | `sudo -A scripts/root_run.sh probe`: doména `hyptcn-guest`, 10 memslotov, 2,02 GiB, 2 vCPU, test čítania 1371 MiB/s | FUNGUJE |
| „komponenty pre pripojenie k hypervizoru“ | `vmicollect/src/backend_ebpf.c`, `vmicollect backends` | to isté; `backends` vypíše `ebpf` a `file` | FUNGUJE |
| „periodický zber pamäťových snímok“ | `vmicollect run`, delta writer, sidecar | `sudo -A scripts/root_run.sh run -w delta -i 5 -N 8 -H none -o <dir>`: 8 snímok, 0 chýb, 0 zmeškaných slotov, delta cyklus ~650 ms | FUNGUJE |
| „real-time introspekciu RAM“ | periodický zber bez zastavenia VM, meraná latencia | živý beh + `python3 -m tcn.score --cakaj 25 --dlzka 4`: latencia snímka → skóre medián 1052 ms, p95 1264 ms (n=5), perióda 5 s | ČIASTOČNE — je to periodický zber s meraným časom, nie garantovaný real-time; vplyv na hosťa nemeraný |
| „parsovanie pamäťových štruktúr“ | `guestparse` (profil jadra, preklad adries, zoznamy jadra) | `python3 -m guestparse info --snapshot data/raw/20260919T110155Z_once --profile profiles/debian12-6.1.0-42-cloud-amd64`: krížová kontrola prekladu `zhoda` pre `linux_banner` aj `init_task` | FUNGUJE |
| „extrakciu príznakov z RAM vrátane procesných informácií“ | `guestparse ps`, príznaky `proc_*` v `features/snapshot.py` | `guestparse ps` nad tou istou snímkou: 78 procesov, úplný výpis; živá validácia proti `ps` v hosťovi: 80/80 stabilných, 0 chýbajúcich, 0 falošných | FUNGUJE |
| „analýzy načítaných modulov“ | `guestparse lsmod`, `mod_*` | `guestparse lsmod`: 47 modulov; živá validácia proti `lsmod`: 50 sediacich, 0 chýba, 0 navyše | FUNGUJE |
| „monitorovania sieťových spojení“ | `guestparse ss` (IPv4/IPv6, TCP/UDP), `sock_*` | `guestparse ss`: 13 soketov s PID; živá validácia proti `ss`: 10 sediacich, 2 chýbajúce, 2 navyše (SSH relácia pozemnej pravdy a nenaviazaný UDP, rovnako ako v `docs/kontroly.md`) | FUNGUJE |
| „detekcie podozrivých vzorcov v pamäti“ | `guestparse checks`: `sys_call_table` v texte jadra, procesy `tasks` vs. strom, moduly vs. `module_kset` | `guestparse checks`: 451 položiek, 0 nálezov, všetky kontroly uzavreté; `GUESTPARSE_VAL=data/raw/20260919T110155Z_once pytest guestparse/tests/test_injection.py`: 5 prešlo (nález index 59), 1 padol — poistka „originál je iba na čítanie“, lebo `data/raw/` je zapisovateľný; detekcia sama prešla | ČIASTOČNE — tri invariantné kontroly; pozitívny prípad je zápis do kópie snímky, nie rootkit |
| „štatistických charakteristík pamäťových oblastí“ | per-bin: podiel zmenených a nulových stránok, entropia, `has_changed` | `python3 -m features perbin --snapshot <once .vmicd>`: biny 0–127, 251, 254, 255; súčty 89483/89483 a 528417/528417 sedia so sidecarom | FUNGUJE |
| „generovať per-bin feature vektory“ | `vmicollect/src/perbin.c` píše blok `features` do sidecaru | krížová kontrola C proti Pythonu, `features crosscheck --snapshot <run> --memslots <probe.json> --c <run>`: 10 snímok, 131 binov, zhoda, 0 polí mimo presnosti | FUNGUJE |
| „mechanizmus pre generovanie sekvenčných feature vektorov s normalizáciou dát“ | `features/session`, `features/windows.py`, `features/normalize.py` | `python3 -m features session --snapshot data/raw/20260919T110017Z_run --profile …`: 10 riadkov × 22 stĺpcov, 0,17–0,56 s na snímku; okná a z-score bežia v `tcn.train --syn` a v `pytest` | ČIASTOČNE — nad reálnymi dátami neexistuje žiadne fitnuté mu/sd; `tcn/score.py` normalizáciu zámerne preskakuje |
| „základná implementácia alebo integrácia TCN modelu pre detekciu anomálií a klasifikáciu aktivít“ | `tcn/model.py` (dilatované konvolúcie, reziduálne bloky), `tcn/train.py`, `tcn/score.py`, baseliny | `python3 -m tcn.score --snapshots data/raw/20260919T110017Z_run --dlzka 4`: 10 snímok, 7 so skóre, vektor medián 177 ms, model 0,7 ms; `python3 -m tcn.train --syn`: všetky 4 modely 1,000 na syntetike | ČIASTOČNE — cesta beží, model nie je natrénovaný; ani detekcia, ani klasifikácia aktivít reálnej VM neexistuje |
| „optimalizovaný z hľadiska výkonu a minimalizácie vplyvu na bežiace virtuálne stroje“ | delta writer, SHA-NI, vypínateľná entropia; artefakty `optim_hash_20260918.json`, `latency_vector_20260918.json` | sám: plná snímka 1693 ms, delta ~650 ms, 0 zmeškaných slotov; artefakty som prečítal, neopakoval | ČIASTOČNE — vplyv na hosťa aj hostiteľa je `UNVERIFIED` (L12), takže „minimalizácia vplyvu“ nie je zmeraná |
| „API rozhranie“ | C API `vmicollect/include/vmic.h`, hook API (notifikačný), Python `GuestView` | `vmicollect once -o vm.backend=file … -o hooks.load=build/example_hook.so:<csv>`: hook sa načítal a zapísal riadok indexu | FUNGUJE (hook nemá prístup k pamäti, L9) |
| „komplexne testovaný“ | `make test`, `pytest`, `check_claims.sh` | `make -C vmicollect && make -C vmicollect test`: OK; `pytest -q`: 192 prešlo, 21 preskočených (chýba `/var/tmp/vmic-val`); `scripts/check_claims.sh`: čisté, 94 súborov | ČIASTOČNE — 21 testov na reálnej snímke sa bez ručne dodanej cesty nespustí |
| „vyhodnotením presnosti detekcie malvérových vzorcov“ | nič; `docs/LIMITACIE.md` L16 to priznáva | v `data/results/` nie je žiadna metrika nad snímkami hosťa; `smoke/tcn_syn_*.json` sú syntetika | CHÝBA |
| „výkonnostných náročností“ | latencie cyklu, snímka → vektor, snímka → skóre nad uloženou snímkou | čísla v tabuľke vyššie som zopakoval; hostiteľské CPU/RAM zberača nemerané | ČIASTOČNE |
| „použiteľnosti v reálnych scenároch“ | jedna nečinná Debian VM; scenáre správania odstránené | dve sedenia so scenármi v `data/raw/` majú `labels.json`, ale nič ich nespracúva | CHÝBA |

## Čo ma prekvapilo

- Živá latencia snímka → skóre, ktorú `docs/LIMITACIE.md` L12 vedie ako `UNVERIFIED`, sa dá
  zmerať hneď: `tcn.score --cakaj` nad adresárom bežiaceho `run` dala medián 1052 ms pri
  perióde 5 s. Dokumentácia je tu prísnejšia než kód.
- `python3 -m features crosscheck --snapshot <dir>` tak, ako ho uvádza `docs/PRIRUCKA.md`
  („`features crosscheck` ich porovná“), padne: `AttributeError: 'Namespace' object has no
  attribute 'sidecar'` (`features/cli.py:69`). Prejde iba s `--memslots` a `--c`. Číslo „6 z 6
  snímok sedí“ v príručke sa teda dokumentovaným príkazom dnes nezopakuje; s prepínačmi áno.
- `scripts/root_run.sh validate` pozemnú pravdu odoberie a snímku urobí, ale samotné porovnanie
  nespustí; `validate.json` v relácii obsahuje iba časy a výpisy. Porovnanie treba spustiť ručne
  cez `python3 -m guestparse validate`. Príručka to nehovorí.
- Skórovací komponent (`tcn/score.py`) a jeho test existujú len v pracovnom strome, nie v gite.
  Profil v `profiles/` bol dnes prepísaný (KASLR po reštarte) a tiež nie je commitnutý.
- V dobrom: čísla v `docs/PRIRUCKA.md`, ktoré som opakoval (131 binov, 451 položiek, 0 nálezov,
  80/80 procesov), vyšli rovnako. Zastavenie pri nesúlade profilu s bootom (kód 5, L17) som
  neoveril — profil dnes k hosťovi sedí a starý `kallsyms` je len v histórii gitu.

## Na čom by som to lámal

- „Detekcia“ v názve a v cieli zadania: model má náhodné váhy so seedom 0. Program to síce
  hlási na troch miestach, ale funkčne sa nedá ukázať ani jeden prípad, kde by systém niečo
  odlíšil. Otázka „čo teda váš modul deteguje?“ nemá spustiteľnú odpoveď.
- Pozitívny prípad kontrol podozrivých vzorcov je 8 bajtov prepísaných v kópii súboru. Hook
  ukazujúci dovnútra textu jadra alebo proces odpojený z oboch zoznamov kontroly nevidia
  (priznané v `docs/kontroly.md`). Otázka „spustili ste v hosťovi aspoň jeden rootkit?“ — nie.
- Profil jadra platí pre jeden boot. Bez `ssh` do hosťa po každom reštarte parser nebeží.
  Otázka „kde končí neinvazívnosť VMI, keď do hosťa musíte pred každým meraním“.
- „Minimalizácia vplyvu na bežiace VM“ je bez čísla: vplyv na hosťa ani hostiteľa nikto nemeral.
  Prečítanie nedotknutej stránky ju navyše hostiteľovi alokuje (varovanie zberača pri `probe`).
- Dve sedenia v `data/raw/` (`mass_file_rewrite`, `fork_storm`) majú labely, ale scenáre,
  ktoré ich vyrobili, sú zo stromu zmazané. Sedenia sa dnes nedajú reprodukovať.
- Príručka je „generovaná z kódu“, a napriek tomu dokumentuje príkaz, ktorý padá. Kontrola
  `check_prirucka.sh` overuje existenciu ciest, nie beh príkazov.
