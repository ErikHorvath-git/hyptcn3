# hyptcn3

Diplomová práca: **Návrh a implementácia hypervisor modulu pre real-time RAM introspekciu
s využitím Temporal Convolutional Networks** (UKF Nitra, aplikačný charakter).

Repozitár obsahuje zberač pamäťových snímok bežiacich virtuálnych strojov nad QEMU/KVM
(`vmicollect`), parser štruktúr hosťovaného systému zo snímky (`guestparse`), profil jadra
hosťa (`profiles/`), skripty na root behy a kontrolu textu (`scripts/`), uložené výsledky
meraní (`data/results/`), log meraní (`docs/MERANIA.md`) a — postupne — príznaky, model
a text práce. Zadanie je v `zadanie-zp_105826.pdf`.

Čo znamená „real-time“ v tejto práci: **periodický zber s nastaviteľnou periódou**.
Zmeraný je čas jedného cyklu zberu (čítanie pamäte + zápis snímky) a meškanie voči
plánovanej perióde. Latencia snímka → príznakový vektor ani snímka → skóre zmeraná **nie
je** — príznakový priestor ani model zatiaľ neexistujú, tie merania sú kroky K16 a K21.
Čas cyklu a latencia po skóre nie sú to isté a v texte sa nezamieňajú (HONESTY.md, P7).
VM sa počas snímky nezastavuje (`paused=false`, `pause_ms=0` vo všetkých uložených
sidecaroch) a eBPF programy sú pozorovacie.

---

## Stav k 2026-09-18

### Overené behom na tomto stroji

#### Zostavenie a testy

```
make -C vmicollect          rc=0
make -C vmicollect test      rc=0
python3 -m pytest -q         88 passed
```

Overované 2026-09-18. Preklad bežal nad kópiou stromu `vmicollect/` mimo repozitára, aby
sa neprepísala binárka v `vmicollect/build/`, ktorú v tom čase používal prebiehajúci beh;
zdrojové súbory boli tie z repa.

`make test` prejde celú cestu zberu nad syntetickým 16 MiB obrazom, bez VM a bez roota.
Skutočný výstup behu:

```
chunks=2 read_errors=1 filled_zero=131072 bytes_read=1966080
OK: pamat za dierou sa zachovala, obraz je zhodny s referenciou
...
selftest: OK - obnoveny obraz je bajt po bajte zhodny
selftest: OK - raw snimka ma spravny SHA-256
selftest: VSETKO PRESLO.
```

Teda: kontrakt collectora pri chybe čítania (`hole_test`), reťazec plná snímka + 3 delty,
obnova reťazca bajt po bajte zhodná s originálom a kontrola SHA-256 raw snímky.
`python3 -m pytest -q` spúšťa 88 testov `guestparse/tests/`. Časť z nich potrebuje
snímku mimo repa; keď chýba, testy sa preskočia **nahlas** (`pytest` to vypíše a upozorní,
že preskočený test nie je prejdený). Injekčný test detekcie hookov beží vždy — má v repe
vlastnú malú snímku `guestparse/tests/data/mini.vmicd`.

#### Zber nad bežiacou VM — binárkou z tohto repozitára

Doména `hyptcn-guest` (Debian 12, jadro `6.1.0-42-cloud-amd64`, 2 vCPU, 2,02 GiB),
hypervízor `qemu:///session`. Binárka `vmicollect/build/vmicollect`, commit `178ce4f`
(pracovný strom `dirty`), sha256 `5cdb2963…`. Spúšťané cez `scripts/root_run.sh`.

| Čo | Nameraná hodnota | Artefakt |
|---|---|---|
| pripojenie k hypervízoru (`probe`) | 10 memslotov, 2,02 GiB, 2 vCPU, test čítania 16 646 144 B za 6,6 ms = 2394 MiB/s | `data/results/probe_20260918T154840Z.json` |
| `run`, writer `delta`, perióda 5 s | 3 dokončené cykly, 0 zlyhaných, 0 zmeškaných, najväčšie meškanie 0,000 s | `data/results/run_20260918T154742Z.json` |
| plná snímka (cyklus #0) | čítanie 969,7 ms, cyklus 2592,8 ms, 484,70 MiB na disku, 123 841 / 528 417 stránok (23,44 %) | tamže, pole `stderr` |
| delta snímky (cykly #1, #2) | čítanie 557,1 a 554,5 ms, cyklus 565,2 a 564,8 ms, 1,27 MiB a 844,00 KiB | tamže, pole `stderr` |
| chyby čítania / pauza VM | 0 / 0,0 ms (`paused=false`) | tamže |

Sidecary tohto behu ležia v `data/raw/`, ktorý `.gitignore` z repa vylučuje; riadky
s časmi cyklov sú preto zachované v poli `stderr` výsledkového JSONu, ktorý v repe je.

#### Zber nad bežiacou VM — binárkou spred importu do repa (prvý beh, 14:30–14:43 UTC)

Rovnaká doména, ale binárka zo scratchpadu (sha256 `c53ce6ee…`) — zdroják BPF programu je
v repe zhodný, samotný artefakt repa sa v tomto behu proti jadru neoveroval.
Artefakty: `data/results/2026-09-18_prvy_beh/`.

| Čo | Nameraná hodnota |
|---|---|
| pripojenie k hypervízoru (`probe`) | 10 memslotov, 2,02 GiB, 2 vCPU, test čítania 2297 MiB/s (výstup sa neuložil) |
| jedna plná raw snímka (2,02 GiB) | čítanie 430,6 ms, cyklus 42 204,7 ms, 307,12 MiB reálne na disku |
| tá istá raw snímka s `output.hash=none` | cyklus 748,5 ms, 0 zmeškaných slotov |
| plná delta snímka | čítanie 766,4 ms, cyklus 3618,1 ms, 276,25 MiB na disku |
| delta snímka, perióda 5 s (n = 5) | čítanie 547,8–563,6 ms, cyklus 566,6–584,7 ms, 1,06–1,28 MiB |
| plná snímka naprieč všetkými behmi dňa (n = 4) | čítanie 430,6–947,4 ms |
| chyby čítania / zmeškané sloty / pauza VM | 0 / 0 / 0,0 ms (`paused=false`) |

Posledné dva riadky prvej polovice tabuľky sú pár pred/po k jednej optimalizácii: SHA-256
sa počítal nad celým 4 GiB riedkym súborom vrátane dier, ktoré sa nikdy nezapísali.
Nie je to čistý A/B — rozbor je v `docs/MERANIA.md`.

**Výhrada k tomuto behu:** v hosťovi počas neho bežal bezpečnostný agent staršieho
projektu (`hyptcn_guest_ag`, pid 376; zastavený až 15:29:20 UTC). Je to vidieť v uloženej
pozemnej pravde (`ground_truth/ps_before.txt`, `ps_after.txt`). Podrobne aj s časovou osou
v `docs/MERANIA.md`. Platná referencia sú merania po tomto čase, na zmrazenom hostovi.

#### Zmena pamäte nečinnej VM medzi snímkami

Zo všetkých uložených delta snímok, obidva behy spolu:

| beh | delta snímok | zmenené stránky z 528 417 | podiel |
|---|---|---|---|
| 14:31 UTC, binárka zo scratchpadu (v hosťovi bežal agent) | 5 | 271–326 | 0,051–0,062 % |
| 15:47 UTC, binárka z repa (agent už zastavený) | 2 | 210–324 | 0,040–0,061 % |
| spolu | 7 | 210–326 | 0,040–0,062 % |

Skoršia verzia tohto súboru uvádzala rozsah 271–326 stránok (0,05–0,06 %); nezahŕňala
delta snímky z behu binárkou z repa, kde je minimum 210 stránok. „Nečinná“ pritom platí
len pre druhý riadok — v prvom behu VM nečinná nebola.

#### Rekonštrukcia štruktúr hosťa parserom z repa

`python3 -m guestparse validate` a `... checks`, bez roota, nad uloženými snímkami.
Artefakty: `data/results/validate_*.json`, `data/results/checks_*.json`,
`data/results/k11_beh_20260918.log`. Rozbor v `docs/kontroly.md`.

| snímka | procesy | moduly | sokety | `syscall_hooks` |
|---|---|---|---|---|
| relácia `20260918T154914Z_validate` (úplná pozemná pravda) | 80 / 80 stabilných, 0 chýbajúcich, 0 falošných, 0 nezhôd mien | 51 sediacich, 0 chýbajúcich, 0 navyše | 11 sediacich, 1 chýbajúci, 1 navyše | 0 zo 451 kontrolovaných položiek |
| `/var/tmp/vmic-val` (pozemná pravda len `ps`) | 80 / 80 stabilných, 0 chýbajúcich, 0 falošných | 47 zo snímky (nebolo s čím porovnať) | 13 zo snímky (nebolo s čím porovnať) | 0 zo 451 |

Rozdiel medzi soketmi „chýbajúce“ a „navyše“ nie je chyba parsera — sú to SSH spojenia,
cez ktoré sa brala pozemná pravda, a nenaviazaný UDP soket, ktorý `ss` nevypisuje;
vysvetlené v `docs/kontroly.md`.

#### Priznané obmedzenie zberu: čítanie nie je celkom pasívne

`vmicollect` pri každom behu nad touto doménou vypíše varovanie, že časť pamäte hosťa nie
je anonymná a že **čítanie stránky, ktorej sa hosť ešte nedotkol, ju hostiteľovi naozaj
alokuje**. Zber teda VM nezastavuje, ale na strane hostiteľa môže nafúknuť jej pamäťovú
stopu. Doslovné znenie varovania a rozbor sú v `docs/MERANIA.md`; o koľko MiB ide pre
`hyptcn-guest`, zmerané nie je.

### Implementované, neoverené

- `vmicollect/hooks/` — notifikačné hook ABI (`vmic_hook_init/snapshot/fini`) aj
  s príkladovým pluginom; nad ostrou VM nebežalo.
- `vmicollect/src/retention.c` — mazanie starých reťazcov; v dlhšom behu netestované.
- Vetva `KIND_HOLE` v BPF programe (chýbajúca stránka v memslote). `tests/hole_test.c`
  testuje kontrakt collectora s umelým backendom, nie túto vetvu.
- `scripts/root_run.sh` — podpríkazy `probe`, `run` a `validate` majú uložený výstup
  v `data/results/`; podpríkaz `once` uložený výstup nemá.
- Nefatálna hláška `bpf_create_map_xattr(pages): -EINVAL, retrying without BTF` —
  mapa sa vytvorí, príčina nezistená. Je aj v stderr oboch dnešných artefaktov.

### Zatiaľ neexistuje

V repozitári nie sú adresáre `features/` (príznakový priestor), `tcn/` (model a baseline),
`scoring/` (skórovacia integrácia), `scenarios/` (scenáre správania) ani `thesis/` (text
práce a bibliografia).

Nezmerané ostáva:

- vplyv zberu na výkon vnútri hosťa (benchmark v VM so zberom a bez neho, krok K22);
- o koľko zber zväčší pamäťovú stopu VM na hostiteľovi (viď varovanie vyššie);
- latencia snímka → príznakový vektor a snímka → skóre (kroky K16, K21);
- opakované meranie dvojice `hash=sha256` / `hash=none` s n > 1 (krok K23);
- presnosť voči reálnym malvérovým vzorkám — a merať sa nebude, validácia detekcie
  prebehne na syntetických scenároch správania (HONESTY.md, P4).

---

## Zostavenie a spustenie

Závislosti: `clang` (preklad BPF časti), `libbpf`, `zlib`, `libdl`, GNU `make`.
Overené na Fedora 43, jadro 7.1.13, clang 21.1.8, libbpf 1.6.1.

```sh
make -C vmicollect          # -> vmicollect/build/vmicollect
make -C vmicollect test     # bez VM a bez roota
python3 -m pytest -q        # testy guestparse, bez VM a bez roota
```

Parser štruktúr hosťa nad už odobratou snímkou (bez roota):

```sh
python3 -m guestparse --help    # podpríkazy: ps, lsmod, ss, info, checks, validate
python3 -m guestparse ps       --profile profiles/debian12-6.1.0-42-cloud-amd64 --snapshot <dir>
python3 -m guestparse checks   --profile profiles/debian12-6.1.0-42-cloud-amd64 --snapshot <dir>
python3 -m guestparse validate --profile profiles/debian12-6.1.0-42-cloud-amd64 --snapshot <dir> ...
```

Kontrola textu proti pravidlám z `HONESTY.md`:

```sh
scripts/check_claims.sh     # 0 = čisté, 1 = nálezy
```

### Čo vyžaduje root

Root je potrebný na čítanie pamäte cudzieho procesu QEMU cez eBPF: načítanie BPF programu
(`CAP_BPF`/`CAP_SYS_ADMIN`), pripojenie na `kvm` a čítanie memslotov. Bez roota bežia:
`make`, `make test`, `pytest`, `guestparse`, `restore`, `verify` a všetko, čo pracuje s už
odobratými snímkami.

Root behy sú zabalené v `scripts/root_run.sh` (609 riadkov), aby sa merania nespúšťali
ručne poskladanými príkazmi a aby každý výstup niesol commit, dátum, presný príkaz
a verziu binárky:

```sh
scripts/root_run.sh --dry-run probe   # vypíše plán, root netreba
sudo scripts/root_run.sh probe        # -> data/results/probe_<stamp>.json
sudo scripts/root_run.sh validate     # pozemná pravda PRED -> snímka -> pozemná pravda PO
sudo scripts/root_run.sh once
sudo scripts/root_run.sh run -w delta -i 5 -N 6
```

Profil jadra hosťa sa berie raz na verziu jadra:

```sh
scripts/get_profile.sh <cieľ>         # kallsyms + BTF cez ssh alebo qemu-guest-agent
```

---

## Štruktúra repozitára

```
hyptcn3/
├── README.md                    tento súbor
├── HONESTY.md                   pravidlá proti nafukovaniu, zoznam zakázaných čísel
├── zadanie-zp_105826.pdf
├── docs/
│   ├── MERANIA.md               log meraní, append-only (617 r.)
│   ├── ARCHITEKTURA.md          vrstvy, dátové toky, formáty, rozhrania (956 r.)
│   ├── LIMITACIE.md             vedomé obmedzenia a ich formulácie do textu (531 r.)
│   └── kontroly.md              rozbor kontrol integrity a validácie (212 r.)
├── guestparse/                  parser štruktúr hosťa zo snímky, Python (3815 r. aj s testami)
│   ├── image.py profile.py view.py checks.py validate.py cli.py
│   └── tests/                   88 testov (pytest), vrátane malej snímky v tests/data/
├── profiles/debian12-6.1.0-42-cloud-amd64/
│   ├── kallsyms.txt btf.raw btf.txt   profil jadra hosťa (vstupná závislosť)
│   └── README.md                pôvod, overenie, čo sa stane po reštarte hosťa
├── scripts/
│   ├── root_run.sh              jediný skript spúšťaný pod rootom (609 r.)
│   ├── get_profile.sh           odber profilu jadra hosťa (330 r.)
│   ├── guest_exec.sh            príkazy v hosťovi pre pozemnú pravdu (288 r.)
│   └── check_claims.sh          kontrola textu podľa HONESTY.md (303 r.)
├── data/
│   ├── results/                 výsledkové JSONy, verzionované
│   ├── sessions/                pozemná pravda a snímky validačných relácií
│   └── raw/                     surové snímky — mimo gitu (.gitignore)
└── vmicollect/                  zberač snímok (C + eBPF), 7828 riadkov .c/.h
    ├── bpf/                     BPF program (592 r.) + ABI hlavička (217 r.)
    ├── src/                     backendy, collector, writery, scheduler, retencia, konfigurácia
    ├── include/vmic.h           verejné C API (456 r.)
    ├── hooks/example_hook.c     príklad hook pluginu (108 r.)
    ├── tests/hole_test.c        test kontraktu pri chybe čítania (111 r.)
    └── Makefile, README.md, vmicollect.example.conf
```

Počty riadkov sú z príkazov:

```sh
wc -l vmicollect/src/*.c vmicollect/include/*.h vmicollect/bpf/*.c \
      vmicollect/bpf/*.h vmicollect/hooks/*.c vmicollect/tests/*.c
wc -l guestparse/*.py guestparse/tests/*.py scripts/*.sh docs/*.md
```

Súbor `vmicollect-index.csv` v koreni je výstup príkladového hook pluginu z testovacieho
behu nad `file` backendom (mimo VM), nie výsledok merania.

---

## Pôvod kódu

`vmicollect/` je prevzatý kód zo staršej vetvy projektu (súbory z 2026-08-25/26);
autorstvo sa zatiaľ nepodarilo doložiť a uvádza sa ako neznáme. Commit
`6b9053d` obsahuje tento stav bajt po bajte bez zmien. Commit `178ce4f` mení jediný súbor,
`bpf/vmic_kvm.bpf.c`, a opravuje štyri dôvody, prečo sa BPF program nenačítal do jadra 7.1
(nezhoda BTF pri `bpf_task_from_vpid` a trikrát limit verifikátora riešený `bpf_loop()`).
Bez týchto opráv `probe` nad bežiacou VM zlyhával. Rozbor v `docs/MERANIA.md`.

`guestparse/` nadväzuje na prototyp parsera `vmi_parse.py` z prípravnej fázy (537 riadkov,
mimo repa). Provenienciu jednotlivých častí uvádza `docs/ARCHITEKTURA.md` (kapitola o pôvode);
hlavičky súborov `guestparse/` ju neopakujú.

Profil jadra hosťa (`profiles/`) je priznaná jednorazová vstupná závislosť získaná
z hosťa — rovnako ako profil pri LibVMI alebo Volatility. Podrobne v
`profiles/debian12-6.1.0-42-cloud-amd64/README.md`.

---

## Pravidlá pre text a čísla

Platí `HONESTY.md`. Zhrnutie: každé číslo v texte práce má značku `{{res:subor.json:kluc}}`
na súbor v `data/results/`; čísla z predchádzajúcej iterácie projektu (`hypTcn002`) sú na
čiernej listine a smú sa objaviť iba v kapitole o retrakciách; čo nikdy nebežalo, je
označené `UNVERIFIED`; `docs/MERANIA.md` je append-only. Kontrolu robí
`scripts/check_claims.sh` a pred odovzdaním musí vrátiť 0 nálezov.
