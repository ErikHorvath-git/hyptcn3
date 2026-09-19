# Príručka k hyptcn3

Vstupný dokument repozitára; stav kódu a artefaktov k 2026-09-18. Súbor je
generovaný a needituje sa ručne — ako, hovorí kapitola 10.

## 1. Čo to je

Program číta pamäť bežiaceho virtuálneho stroja zvonku, z hostiteľa, a periodicky z nej
ukladá snímky. Druhý program zo snímky poskladá zoznam procesov, modulov jadra a sieťových
spojení tak, ako ich v tej chvíli videl hosťovaný systém. Z každej snímky sa počíta krátky
číselný vektor o tom, kde a ako sa pamäť oproti predchádzajúcej zmenila; vektory idú za
sebou do okien a tie majú byť vstupom modelu (Temporal Convolutional Network), ktorý
hotový nie je. Vnútri sledovaného stroja pritom nebeží nič, čo by sa dalo vypnúť.

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
16 MiB, ktorý si sám vyrobí. Testov je 193 v `pytest` a 2 v C (`hole_test`, `perbin_test`).

## 4. Ako vznikne snímka

Skripty pracujú s doménou `hyptcn-guest`; inú zadáš prepínačom `-d/--domain` alebo
premennou `VMIC_DOMAIN`. Profil jadra hosťa (symboly z `kallsyms`, offsety polí štruktúr
z BTF) **pre túto doménu už v repozitári je** — priznaná vstupná závislosť, rovnako ako
profil pri LibVMI alebo Volatility. Prvý riadok nižšie preto preskoč: `get_profile.sh`
je iba pre iného hosťa alebo inú verziu jadra, existujúci profil neprepíše a skončí kódom 1.

```bash
scripts/get_profile.sh root@192.168.122.100     # iba pre iného hosťa
sudo scripts/root_run.sh probe                  # vidno doménu a jej memsloty?
sudo scripts/root_run.sh run -w delta -i 5 -N 6 # šesť cyklov, perióda 5 s
python3 -m guestparse ps --snapshot data/raw/<stamp>_run --profile profiles/debian12-6.1.0-42-cloud-amd64
python3 -m features perbin --snapshot data/raw/<stamp>_run
```

`sudo` sa na heslo spýta interaktívne; root treba iba na tie dva riadky, teda na samotné
čítanie pamäte. Tretí príkaz zapíše snímky do `data/raw/<stamp>_run/` (mimo gitu) a súhrn
behu do `data/results/run_<stamp>.json`. Jedna snímka je súbor `.vmicd`: vlastný formát
zberača — hlavička, zoznam rozsahov fyzických adries a ich obsah, celý alebo iba zmenené
stránky. `--snapshot` berie taký súbor aj celý adresár s reťazcom snímok.

Merania sa nespúšťajú ručne, ale cez `scripts/root_run.sh probe|once|run|validate`, ktorý
do každého výstupu zapíše commit, dátum, presný príkaz a SHA-256 binárky. Pozor na rozdiel:
v tabuľke v kapitole 6 stojí pri `probe`, že nič nezapisuje — platí to o binárke, ale
`scripts/root_run.sh probe` okolo nej zapíše `data/results/probe_<stamp>.json`.

## 5. Čo je kde

| adresár | čo rieši | kde začať čítať | súborov spolu / riadkov v `.c .h .py .sh .md` |
|---|---|---|---|
| `vmicollect/` | zberač snímok pamäte VM: C a eBPF nad QEMU/KVM | `vmicollect/src/collector.c` | 31 / 9 167 |
| `guestparse/` | rekonštrukcia procesov, modulov a soketov zo snímky | `guestparse/view.py` | 25 / 4 264 |
| `features/` | per-bin príznakový vektor (referencia), okná, normalizácia | `features/perbin.py` | 17 / 4 129 |
| `profiles/` | profil jadra hosťa: symboly a offsety polí štruktúr | `profiles/debian12-6.1.0-42-cloud-amd64/README.md` | jeden adresár na verziu jadra hosťa |
| `scripts/` | root behy, príkazy v hosťovi, kontroly tvrdení | `scripts/root_run.sh` | 9 / 4 019 |
| `data/` | výsledkové JSONy z meraní (`data/results/`) a pozemná pravda odobratá v hosťovi (`data/sessions/`); samotné snímky `.vmicd` sú mimo gitu (`data/raw/`) | `data/results/2026-09-18_zmrazeny_host/README.md` | rastie s každým meraním, nepočíta sa |

## 6. Ako to funguje

```
pamäť bežiacej VM
  │  vmicollect  (eBPF nad KVM, beží na hostiteľovi)
  ▼
snímka .vmicd  +  sidecar .json (metadáta snímky vedľa nej)
  ├─► guestparse ──► procesy, moduly, sokety hosťa
  └─► perbin.c   ──► per-bin vektor (zapísaný do sidecaru)
                       │  features/windows.py
                       ▼
                     okná (okno, čas, bin, príznak) pre model
```

**1. Čítanie pamäte** — `vmicollect/src/backend_ebpf.c`, spoločná slučka
`vmicollect/src/backend.c`. KVM drží pamäť hosťa ako zoznam blokov; jeden blok sa volá
**memslot** a hovorí, ktorý rozsah fyzických adries hosťa leží na ktorej adrese
v procese QEMU. Zberač číta iba memsloty — priestor medzi nimi je diera bez pamäte,
nie nuly. Virtuálny stroj sa pritom nezastavuje.

**2. Zápis snímky** — `vmicollect/src/writer_raw.c` uloží celú pamäť,
`vmicollect/src/writer_delta.c` iba stránky zmenené od predchádzajúcej snímky
(porovnáva sa ich hash). Plná je prvá snímka reťazca a potom každá N-tá podľa
`output.delta_full_every` (východzie 20); plná snímka je referencia pre
delty za ňou. Pri zapnutom `output.sidecar` (východzie `true`) vzniká
vedľa každej snímky sidecar `.json` s metadátami; robí ho `vmicollect/src/meta.c`.

**3. Rekonštrukcia objektov hosťa** — `guestparse/view.py`. V snímke sú iba bajty; že na
určitej adrese začína zoznam procesov a že meno procesu leží istý počet bajtov od jeho
začiatku, v nej nie je. Tejto medzere medzi bajtmi a významom sa hovorí **semantic gap**
a preklenie ju profil jadra hosťa z `profiles/`. Výsledok sa porovnáva s **pozemnou
pravdou**: zoznamom procesov, modulov a soketov odobratým zvnútra hosťa príkazmi `ps`,
`lsmod` a `ss` tesne pred snímkou a po nej (`python3 -m guestparse validate`).

**4. Príznaky** — `vmicollect/src/perbin.c`, referencia `features/perbin.py`.
**Per-bin vektor**: pamäť sa podľa fyzickej adresy rozdelí na rovnako veľké bloky
(biny, východzie 16 MiB) a za každý bin sa uloží podiel zmenených stránok, podiel
nulových stránok, priemerná entropia zmenených stránok a príznak, či sa bin vôbec
zmenil. Index binu je adresa delená veľkosťou binu, takže bin číslo 5 je v každej
snímke ten istý kus pamäte; bin bez memslotu nevzniká. To isté číslo počíta C aj
Python a `features crosscheck` ich porovnáva.

**5. Okná a normalizácia** — `features/windows.py` skladá po sebe idúce vektory do
poľa tvaru `(okno, čas, bin, príznak)`. `features/normalize.py` každý príznak preškáluje
na nulový priemer a jednotkovú odchýlku (z-score); priemer a odchýlku počíta iba zo
záznamov bez škodlivého správania a uloží ich do manifestu, aby na testovacích dátach
platili tie isté hodnoty. Podrobnosti sú v `features/PERBIN.md`.

**Príkazy zberača**

| príkaz | čo robí |
|---|---|
| `run` | periodicky zber (Ctrl-C korektne ukonci) |
| `once` | jedna snimka a koniec |
| `probe` | pripoj sa a vypis parametre VM (nic nezapisuje) |
| `restore` | poskladaj plny obraz z delta retazca — `--dir D --out F [--chain ID] [--until SEQ]` |
| `verify [adresar]` | over kontrolne sucty snimok podla .json |
| `config` | vypis efektivnu konfiguraciu; s `--keys` vypis vsetky nastavitelne parametre |
| `backends` | zoznam dostupnych backendov |
| `selftest [adresar]` | over celu cestu bez potreby VM |

Prepínače: `-c, --config F` konfiguracny subor (INI), `-o, --set K=V` prebi jeden parameter (da sa opakovat), `-v, --verbose` log na urovni DEBUG, `-q, --quiet` log iba ERROR.

Podpríkazy `python3 -m guestparse`: `ps` zoznam procesov z init_task.tasks, `lsmod` zoznam nacitanych modulov, `ss` sietove spojenia (IPv4 aj IPv6), `info` profil, posun jadra a krizova kontrola prekladu adries, `checks` kontroly podozrivych vzorcov, `validate` porovnanie s pozemnou pravdou z hosta.
Podpríkazy `python3 -m features`: `perbin` spocitaj vektor jednej snimky, `crosscheck` porovnaj referenciu s vektorom z C modulu, `session` pamat aj objekty hosta do jedneho vektora na snimku.

**Konfiguračné kľúče** (`vmicollect config --keys`, prebijú sa cez `-o sekcia.kluc=hodnota`):

- `[vm]` — domain, backend, bpf_object, image_path
- `[schedule]` — interval_s, jitter, overrun, max_cycles, duration_s, align
- `[capture]` — pause, pause_max_ms, chunk_size, regions, skip_read_errors, max_read_errors
- `[output]` — dir, writer, name_template, sparse, post_compress, hash, sidecar, delta_page_size, delta_full_every
- `[features]` — enable, bin_bytes, entropy
- `[retention]` — max_snapshots, max_bytes, max_age_s
- `[hooks]` — load, strict
- `[log]` — level, file, json

Východzie hodnoty kľúčov, ktoré text spomína: `schedule.interval_s` = `5`, `output.writer` = `raw`, `output.hash` = `sha256`, `output.sidecar` = `true`, `output.delta_full_every` = `20`, `features.bin_bytes` = 16 MiB.

**Polia sidecaru**, ktoré sú vstupom ďalších krokov:

- `output` — writer, full, chain_id, bytes_logical, bytes_on_disk, pages_total, pages_changed, page_size, changed_ratio, sha256_covers_file, sha256
- `features` — schema, bin_bytes, page_size, entropy, compute_ms, bins_total, regions, bins
- jeden bin v `features.bins` — bin, gpa, pages_total, pages_changed, changed_ratio, zero_ratio, entropy_mean, has_changed
- zdroj: sidecar vyrobený pri generovaní práve preloženou binárkou (backend `file` nad 4 MiB obrazom, writer `delta`), nie uložený artefakt

## 7. Namerané čísla

Merané 2026-09-18 na doméne `hyptcn-guest` v zmrazenom stave (bez agenta v hosťovi).

| čo | hodnota | n | artefakt |
|---|---|---|---|
| Doména, na ktorej sa meralo | 10 memslotov, 2,02 GiB RAM, 2 vCPU | 1 | `data/results/2026-09-18_zmrazeny_host/summary.json` |
| Plná snímka (cyklus #0, delta writer) | čítanie 922,0 ms, zápis 1 638,7 ms, spolu 2 560,8 ms; 123 845 z 528 417 stránok | 1 | `data/results/2026-09-18_zmrazeny_host/summary.json` |
| Prírastková snímka, nečinná VM | medián 245 stránok (212–265) zmenených, teda 0,0464 % pamäte; 7 z 11 prírastkových cyklov behu — tie, počas ktorých v hosťovi nebola prihlasovacia relácia | 7 | `data/results/2026-09-18_zmrazeny_host/summary.json` |
| Beh s periódou 5 s | 12 cyklov, 0 chýb, 0 zmeškaných slotov, najväčšie meškanie 0,0 s | 1 | `data/results/2026-09-18_zmrazeny_host/run_delta_5s.json` |
| Latencia snímka → vektor, perióda 2 s, príznaky zapnuté | medián 604,3 ms, p95 612,6 ms | 12 | `data/results/latency_vector_20260918.json` |
| To isté s vypnutými príznakmi | medián 555,1 ms, p95 561,0 ms | 12 | `data/results/latency_vector_20260918.json` |
| Cena príznakov v cykle | prírastková snímka +46,4 ms (8,4 %), plná +456,7 ms (48,0 %) | 6 | `data/results/perbin_c_20260918/perbin_c_20260918.json` |
| Z toho entropia | 3,498 µs na zmenenú stránku navyše | 6 | `data/results/perbin_c_20260918/perbin_c_20260918.json` |
| Vektor z C proti Python referencii | 6 z 6 snímok sedí, 131 binov na snímku, žiadny rozdiel | 6 | `data/results/perbin_crosscheck_20260918.json` |
| Rekonštrukcia proti pozemnej pravde v hosťovi | procesy 81 z 81 stabilných (v `ps` ich bolo 83), moduly 51 z 51, počúvajúce sokety 10 z 10 a 2 navyše | 1 | `data/results/2026-09-18_zmrazeny_host/summary.json` |
| SHA-256 nad pamäťou (mikrobenchmark) | 2 150,7 MiB/s s inštrukciami SHA-NI, 357,3 MiB/s bez nich | 3 | `data/results/optim_hash_20260918.json` |

Stabilná množina procesov sú tie, ktoré boli v `ps` pred snímkou aj po nej. Sokety
„navyše“ nie sú falošné pozitíva: `ss -tulpn` vypisuje iba počúvajúce sokety, zo snímky
je vidieť aj nenaviazaný UDP soket a dopyt na DNS.

Staršie číslo pre cyklus so zapnutým kontrolným súčtom už neplatí: SHA-256 sa vtedy
počítal až v `finish()` nad hotovým riedkym súborom vrátane dier, dnes sa počíta priebežne
v `feed()` nad tým, čo sa naozaj zapisuje. Vetva s inštrukciami SHA-NI je k tomu prídavok,
nie príčina — v prevzatom stave už bola (`docs/MERANIA.md`).

Prostredie, na ktorom merania bežali (z artefaktov, nie z tohto stroja dnes):

- hostiteľ: Fedora Linux 43 (Workstation Edition), jadro `7.1.13-100.fc43.x86_64`, QEMU emulator version 10.1.5 (qemu-10.1.5-1.fc43), libvirt 11.6.0;
- hosť: Debian GNU/Linux 12 (bookworm), verzia 12.13, jadro `6.1.0-42-cloud-amd64`, 2 vCPU.

Commity, z ktorých merania pochádzajú:

- `178ce4f bpf: opravit styri dovody, preco sa program nenacital do jadra 7.1` — 2026-09-18_zmrazeny_host/run_delta_5s.json *, 2026-09-18_zmrazeny_host/summary.json, optim_hash_20260918.json
- `104af34 odstranit vmicollect-index.csv z repa` — latency_vector_20260918.json *, perbin_c_20260918/perbin_c_20260918.json *, perbin_crosscheck_20260918.json *
- `*` — binárka, ktorá merala, nezodpovedá presne tomuto commitu: pracovný strom mal v čase merania neuložené zmeny

## 8. Čo nefunguje a čo ešte nie je

Model ani skórovanie neexistujú, takže latencia snímka → skóre meraná nie je a slovo
„real-time“ v názve práce znamená periodický zber s meraným časom cyklu. Presnosť voči
malvérovým vzorkám sa merať nebude: vzorky nie sú k dispozícii, nahrádzajú sa syntetickými
scenármi. Pri načítaní BPF programu sa objaví nefatálne `libbpf: Error in bpf_create_map_xattr(pages): -EINVAL. Retrying without BTF.` — zber funguje,
príčina zistená nebola.

Ostatné obmedzenia vlastní `docs/LIMITACIE.md` (L1 až L14); prerozprávať ich tu by
znamenalo držať dve znenia toho istého. Nadpisy sú preto dosadené z neho, skrátené:

- **L1** — Živá snímka: VM sa nezastavuje
- **L2** — Čítanie nie je úplne pasívne
- **L3** — Profil jadra hosťa je vstupná závislosť získaná z hosťa
- **L4** — Parsuje sa pamäť jadra, nie pamäť procesov
- **L5** — `hole_test` netestuje BPF vetvu
- **L6** — Injekčný test je injekcia do kópie snímky
- **L7** — Confidential VM (SEV-SNP, TDX) sa takto prečítať nedá
- **L8** — Prenos cez mmap nie je „nulové kopírovanie“
- **L9** — Hook je notifikačný
- **L10** — Kontroly integrity majú pomenované slepé miesta
- **L11** — Jeden výstupný adresár na jeden zberač
- **L12** — Čo ešte nie je zmerané
- **L13** — Príznakový vektor: čo o ňom treba vedieť pred tým, než sa na…
- **L14** — Procesy, moduly a sokety do príznakového vektora nevstupujú…

## 9. Kam ďalej

Každý typ faktu má jeden dokument, ktorý ho vlastní; keď si odporujú, platí tabuľka.

| dokument | čo vlastní | riadkov |
|---|---|---|
| `docs/ARCHITEKTURA.md` | rozhrania, formát `.vmicd` a sidecaru, tok dát podrobne | 1042 |
| `docs/MERANIA.md` | log meraní: čo, kedy, akým príkazom a s akým výsledkom | 705 |
| `docs/LIMITACIE.md` | L1 až L14: čo systém nevie a čo z toho plynie pre text | 654 |
| `docs/kontroly.md` | kontroly podozrivých vzorcov a validačný príkaz | 212 |
| `HONESTY.md` | pravidlá pre čísla a slová v texte práce | 269 |
| `README.md` | rozcestník repozitára a pôvod prevzatého kódu | 46 |
| `vmicollect/README.md` | zberač zvnútra: vrstvy, hooky, formáty | 420 |
| `guestparse/README.md` | parser zvnútra: preklad adries, prechod zoznamami | 132 |
| `features/PERBIN.md` | definícia príznakov a ich kontrakt | 163 |

## 10. Ako sa táto príručka udržiava

`docs/PRIRUCKA.md` je generovaný, needituj ho: próza sa mení v šablóne
`docs/PRIRUCKA.sk.md`, nový fakt sa pridáva ako funkcia do generátora.

```bash
python3 scripts/gen_prirucka.py     # prepíše docs/PRIRUCKA.md zo šablóny
scripts/check_prirucka.sh           # ohlási, že sa príručka s kódom rozišla
```

**Čo na tomto súbore drží kontrola.** Generátor dosadí z kódu strom adresárov a počty
riadkov, príkazy, prepínače a podpríkazy z `--help`, konfiguračné kľúče aj ich východzie
hodnoty, veľkosť obrazu v selfteste, polia sidecaru (vyrobí si preň čerstvý sidecar práve
preloženou binárkou), počet testov a znenia nadpisov limitácií. Z uložených artefaktov iba
to, čo sa bez merania zistiť nedá: namerané čísla s `n`, commity a prostredie meraní,
hlásenie libbpf. Próza medzi nimi je ručná a overuje sa pri nej jediné: že každá cesta
k súboru v texte existuje. Vecne zlú vetu bez čísla kontrola nezachytí, preto číslo patrí
do generovanej časti, nie do prózy.

`scripts/check_prirucka.sh` si volá aj `scripts/check_claims.sh`, takže zastaraná príručka je
nález ako každý iný; kód si najprv preloží, aby videla zmenu v zdrojáku, nie v starej binárke.
Bežiacu doménu ani roota generátor nepotrebuje, zostavenú binárku áno — bez nej dá na
miesto faktu `NEZISTENE (dôvod)` a skončí nenulovým kódom; taký súbor sa necommituje.
