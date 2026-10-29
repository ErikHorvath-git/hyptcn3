# PoC techniky - LEN na vývoj a overenie citlivosti

Tieto techniky slúžia **výlučne** na vývoj a overenie citlivosti systému
(ground-truth sedenia). Žiadny škodlivý kód nevstúpi do tréningu normálu
([`docs/METODIKA_ZBERU.sk.md`](../../docs/METODIKA_ZBERU.sk.md), časť 7). Sú to
stavebné bloky útokovej etapy, ktorá sa ešte neuskutočnila (tamže). V komentároch
kódu majú označenie bloku G1 (`scripts/aktivita.sh` G3) z plánu z 2026-10-05;
legenda blokov je v [`docs/STAV.sk.md`](../../docs/STAV.sk.md).

**Stav (2026-10-29): žiadne PoC sedenie zatiaľ nebežalo – UNVERIFIED (HONESTY P5).**
Skripty vznikli pre historický tok sedení `scripts/session.sh` a manifesty
`harness/session_manifest_g1_*.json` ([`harness/README.md`](../../harness/README.md));
v `data/sessions/` nie je žiadne sedenie `*_malicious`. Súčasný zber
(`scripts/collection.py`) útočné vzorky nespúšťa a runner útokovej etapy zatiaľ
neexistuje; má bežať v oddelenom izolovanom prostredí, nie v `hyptcn-lab`
(METODIKA, časť 7). Výsledky k citlivosti sú iba syntetické zápisy do kópie
snímky, nie beh techniky v hosťovi: `data/results/g1_citlivost_sim_20261005.json`
(používateľská pamäť procesu `sshd`), `data/results/a3_pozitivny_20261005.json`
(text jadra) a `data/results/k11_beh_20260918.log` (`sys_call_table`).

## Čo je kde

| súbor | technika | čo v hosťovi robí |
|---|---|---|
| `hider_run.sh` | LD_PRELOAD hider | skompiluje (gcc) knižnicu, ktorá v `readdir()` skryje adresár `/tmp/hidden`, a `DUR` s spúšťa `ls /tmp` s `LD_PRELOAD` (klasický userspace hider; **nie** rootkit); manifest `g1_hider` |
| `memfd_run.sh` | fileless spustenie | skompiluje `memfd_exec` (`memfd_create` + kópia `/bin/sh` + `fexecve`) a `DUR` s opakovane spúšťa shell z pamäte - proces bez súboru na disku; manifest `g1_memfd` |
| `encrypt_files.sh` | šifrovanie súborov | vytvorí v `/tmp/victim` testovacie súbory (počet a veľkosť zo `SEED`, obsah z `/dev/urandom`), zašifruje ich `openssl` (AES-256-CBC, heslo = `SEED`) a originály zmaže; manifest `g1_encrypt` |
| `diamorphine.sh` | Diamorphine LKM | stiahne Diamorphine z GitHubu (commit z `DIAMORPHINE_COMMIT`, inak vetva `master`), zbuildí ho proti hlavičkám jadra hosťa a zavedie `insmod`; **rootkit na úrovni jadra - len v overlayi sedenia**; manifest `g1_diamorphine` |
| `miner.sh` | kryptominer | stiahne archív z `MINER_URL`, overí jeho SHA-256 (`MINER_SHA`) a `DUR` s spúšťa xmrig na `MINER_THREADS` vláknach (pool `pool.supportxmr.com:443`, vymyslený používateľ); manifest pre miner nie je |
| `hider.c`, `memfd_exec.c`, `build.sh` | samostatné zdroje | `build.sh` ich skompiluje v hosťovi (gcc) a vypíše SHA-256; žiadny manifest ich nepoužíva a bežce `hider_run.sh` a `memfd_run.sh` majú vlastnú, odlišnú kópiu zdroja (heredoc) |

`session.sh` prenesie do hosťa jediný súbor a spustí ho s premennými `SEED`
a `DUR`. `DIAMORPHINE_COMMIT`, `MINER_URL` ani `MINER_SHA` neodovzdá, takže
Diamorphine by sa ním stiahol z vetvy `master`, `miner.sh` by skončil chybou
a `build.sh` by nenašiel zdroje `.c` vedľa seba.

## Pravidlá

- Binárky ani stiahnuté zdroje NIKDY nejdú do gitu: do manifestu sedenia ide
  iba SHA-256 injikovaného súboru (`injekcia.sha256_merane`); `diamorphine.sh`
  vypíše aj commit, ktorý stiahol.
- Diamorphine a miner potrebujú pri behu sieť v hosťovi (GitHub, URL archívu);
  pre izolovaný beh treba zdroj pripraviť dopredu. `diamorphine.sh` potrebuje
  v hosťovi `git`, `make`, `gcc` a `linux-headers-$(uname -r)`; manifest
  `g1_diamorphine` doinštaluje iba `gcc` a `git`.
- Každé PoC sedenie má manifest `typ=malicious`, `label=<technika>` a beh cez
  `scripts/session.sh` s rovnakým mechanizmom injekcie a ukončenia ako benígne
  sedenie. Rozdiely v manifeste (sieť, balíky, prevádzka z hostiteľa) sa musia
  zapísať a vyhodnotiť ako možný confound (`harness/README.md`).
- Úspech techniky sa overuje pozemnou pravdou (nový proces v `ps`, modul,
  zmenené súbory, sieť): `scripts/aktivita.sh <adresar_sedenia>` porovná
  `*_before.txt` a `*_after.txt`, ktoré zapisuje `session.sh`, a zapíše
  `aktivita.json` (označenie aktívny/neaktívny). Pri každom behu sa zaznamená
  výber techniky, hash, aktivácia, časový priebeh a dôvod neaktivácie;
  neaktivovaná technika nie je úspešná detekcia ani platný negatívny prípad
  (METODIKA, časť 7).
