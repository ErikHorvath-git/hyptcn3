# Príručka k hyptcn3

Vstupný dokument repozitára; stav kódu a artefaktov k 2026-10-29. Súbor je
generovaný a needituje sa ručne — ako, hovorí kapitola 10.

## 1. Čo to je

Program číta pamäť bežiaceho virtuálneho stroja zvonku, z hostiteľa, a periodicky z nej
ukladá snímky. Druhý program zo snímky poskladá zoznam procesov, modulov jadra a sieťových
spojení tak, ako ich v tej chvíli videl hosťovaný systém. Z každej snímky sa počíta krátky
číselný vektor o tom, kde a ako sa pamäť oproti predchádzajúcej zmenila; vektory idú za
sebou do okien pre TCN prediktor normálu v balíku `safeguard/` (`python3 -m safeguard`), ktorý z chyby
predikcie a z kontrol integrity robí alarm. Model nad serverovým korpusom zatiaľ natrénovaný nie je.

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

`make test` prejde celú cestu zberu nad syntetickým obrazom veľkosti 16 MiB, ktorý si sám vyrobí. Testov je 684 prešlých a 24 preskočených v `pytest` (spolu 708 zozbieraných; preskočený test nie je prešiel) a 4 v C (`alarm_test`, `hole_test`, `perbin_test`, `retention_test`).

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
python3 -m guestparse ps --snapshot data/collections/<session>/raw --profile profiles/debian12-6.1.0-42-cloud-amd64
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
| `vmicollect/` | zberač snímok pamäte VM: C a eBPF nad QEMU/KVM | `vmicollect/src/collector.c` | 37 / 12 178 |
| `guestparse/` | rekonštrukcia procesov, modulov a soketov zo snímky; kontroly integrity | `guestparse/view.py` | 34 / 7 257 |
| `features/` | per-bin referencia k C, vektor snímky, okná, kvalita riadkov, archív sedenia a index korpusu; staršia normalizácia pre `tcn/` | `features/perbin.py` | 27 / 5 611 |
| `tcn/` | TCN bloky pre `safeguard/model.py`, baseliny a metriky; staršia diagnostická cesta tréningu a skórovania (`tcn/train.py`, `tcn/score.py`) | `tcn/model.py` | 11 / 1 993 |
| `safeguard/` | integrovaná detekčná cesta: okná a normalizácia, modely, kalibrácia, balík a hostiteľský detektor | `safeguard/cli.py` | 16 / 3 378 |
| `profiles/` | profil jadra hosťa: symboly a offsety polí štruktúr | `profiles/debian12-6.1.0-42-cloud-amd64/README.md` | jeden adresár na verziu jadra hosťa; nový boot rieši preukotvenie (L17) |
| `scripts/` | zber a audit sedenia, kampaň (`scripts/campaign.py`), laboratórium a premávka, root behy, PoC techniky na validáciu citlivosti (`scripts/poc/`), kontroly tvrdení; staršie diagnostické sedenia a detektor (`scripts/session.sh`, `scripts/detektor.py`) | `scripts/collection.py` | 61 / 18 825 |
| `lab/` | trvalé benígne API služby, PostgreSQL a nginx vo VM `hyptcn-lab` | `lab/services.py` | 7 / 471 |
| `harness/` | zlatý obraz hosťa, šablóna domény `hyptcn-guest`, izolovaná sieť bez NAT a manifesty starších sedení | `harness/README.md` | 15 / 264 |
| `config/` | zmrazené protokoly zberu korpusu: doména, perióda, okná, roly a scenáre | `config/collection-v2.json` | 2 / 0 |
| `data/` | výsledkové JSONy z meraní (`data/results/`) a pozemná pravda odobratá v hosťovi (`data/sessions/`); samotné snímky sú mimo gitu (`data/raw/`, zber korpusu `data/collections/<session>/`) | `data/results/2026-09-18_zmrazeny_host/README.md` | rastie s každým meraním, nepočíta sa |

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
každá N-tá podľa `output.delta_full_every` (východzie 20) a je referenciou pre delty za ňou.
Pri `output.sidecar` (východzie `true`) vzniká vedľa snímky sidecar `.json`; robí ho `meta.c`.
Od verzie 1.1 snímku writera `delta`, jej SHA-256 aj sidecar zapisuje vlákno `vmic-writer`
(`vmicollect/src/output.c`); vzorkovací cyklus zmenené stránky namiesto zápisu kopíruje do fronty.

**3. Rekonštrukcia objektov hosťa** — `guestparse/view.py`. V snímke sú iba bajty; že na
istej adrese začína zoznam procesov a meno procesu leží istý počet bajtov od jeho začiatku,
v nej nie je. Tejto medzere sa hovorí **semantic gap** a preklenie ju profil jadra hosťa
z `profiles/`. Výsledok sa porovnáva s **pozemnou pravdou** odobratou zvnútra hosťa
príkazmi `ps`, `lsmod` a `ss` tesne pred snímkou a po nej (`python3 -m guestparse validate`).

**4. Príznaky** — `vmicollect/src/perbin.c`, referencia `features/perbin.py`.
**Per-bin vektor**: pamäť sa podľa fyzickej adresy rozdelí na rovnako veľké bloky (biny,
východzie 16 MiB) a za každý bin sa uloží podiel zmenených stránok, podiel nulových
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
sa trénoval iba na krátkych benígnych sedeniach, nad korpusom `benign-v6-20261026` zatiaľ nič (L16).

| príkaz zberača | čo robí |
|---|---|
| `run` | periodicky zber (Ctrl-C korektne ukonci) |
| `once` | jedna snimka a koniec |
| `probe` | pripoj sa a vypis parametre VM (nic nezapisuje) |
| `restore` | poskladaj plny obraz z delta retazca — `--dir D --out F [--chain ID] [--until SEQ]` |
| `hold <dir> <id>...` | oznac retazce markerom HOLD (retencia ich nezmaže) — `<id> = chain_id (delta zber) alebo meno suboru` |
| `verify [adresar]` | over kontrolne sucty snimok podla .json |
| `config` | vypis efektivnu konfiguraciu; s `--keys` vypis vsetky nastavitelne parametre |
| `backends` | zoznam dostupnych backendov |
| `selftest [adresar]` | over celu cestu bez potreby VM |

Prepínače: `-c, --config F` konfiguracny subor (INI), `-o, --set K=V` prebi jeden parameter (da sa opakovat), `-v, --verbose` log na urovni DEBUG, `-q, --quiet` log iba ERROR.

Podpríkazy: `python3 -m guestparse` — `ps` zoznam procesov z init_task.tasks, `lsmod` zoznam nacitanych modulov, `ss` sietove spojenia (IPv4 aj IPv6), `info` profil, posun jadra a krizova kontrola prekladu adries, `checks` kontroly podozrivych vzorcov, `validate` porovnanie s pozemnou pravdou z hosta, `textbaseline` baseline textu jadra (kontrola (d); zapise text_baseline.json do profilu). Bez --vmlinux ide o baseline z cistej snimky, s --vmlinux z linkovaneho obrazu (silnejsia, boot-independent)., `procmap` ktoremu procesu patria zmenene stranky binov (A4); `python3 -m features` — `perbin` spocitaj vektor jednej snimky, `crosscheck` porovnaj referenciu s vektorom z C modulu, `session` pamat aj objekty hosta do jedneho vektora na snimku; `python3 -m safeguard` (`docs/SAFEGUARD.sk.md`) — `train`, `inspect`, `replay`, `watch`, `run`, `status`, `smoke`; `scripts/collection.py` (`docs/METODIKA_ZBERU.sk.md`) — `plan`, `run`, `audit`, `coverage`; `scripts/campaign.py` (`docs/AUTOMATICKY_ZBER.sk.md`) — `init`, `run`, `launch`, `status`, `verify-archives`, `request-stop`, `close`.

**Konfiguračné kľúče** (`vmicollect config --keys`, prebijú sa cez `-o sekcia.kluc=hodnota`):

- `[vm]` — domain, backend, bpf_object, image_path
- `[schedule]` — interval_s, jitter, overrun, max_cycles, duration_s, align
- `[capture]` — pause, pause_max_ms, chunk_size, regions, skip_read_errors, max_read_errors
- `[output]` — dir, writer, name_template, sparse, post_compress, hash, sidecar, delta_page_size, delta_full_every, fsync, queue_mib, mlock, drain_s
- `[features]` — enable, bin_bytes, entropy
- `[retention]` — max_snapshots, max_bytes, max_age_s
- `[hooks]` — load, strict
- `[log]` — level, file, json

Východzie hodnoty kľúčov, ktoré text spomína: `schedule.interval_s` = `5`, `output.writer` = `raw`, `output.hash` = `sha256`, `output.sidecar` = `true`, `output.delta_full_every` = `20`, `features.bin_bytes` = 16 MiB.

**Polia sidecaru**, ktoré sú vstupom ďalších krokov:

- `capture` — regions, chunk_size, paused, pause_ms, pause_exceeded, capture_ms, backend_read_ms, begin_ms, queue_wait_ms, rusage, write_ms, total_ms
- `output` — writer, full, fsync, async, mlock, queue_pool_bytes, queue_jobs, queue_bytes, sha_ms, data_closed_ms, chain_id, bytes_logical, bytes_on_disk, pages_total, pages_changed, page_size, changed_ratio, sha256_covers_file, hash_deferred, sha256
- `features` — schema, bin_bytes, page_size, entropy, compute_ms, bins_total, regions, bins
- jeden bin v `features.bins` — bin, gpa, pages_total, pages_changed, changed_ratio, zero_ratio, entropy_mean, has_changed
- zdroj: sidecar vyrobený pri generovaní práve preloženou binárkou (backend `file` nad 4 MiB obrazom, writer `delta`), nie uložený artefakt

## 7. Namerané čísla

Merané 2026-09-18 na vývojovom hostiteľovi, doména `hyptcn-guest` v zmrazenom stave (bez agenta
v hosťovi). Piloty a kampane na zberovom PC vlastní `docs/MERANIA.md`.

| čo | hodnota | n | artefakt |
|---|---|---|---|
| Doména, na ktorej sa meralo | 10 memslotov, 2,02 GiB RAM, 2 vCPU | 1 | `data/results/2026-09-18_zmrazeny_host/summary.json` |
| Plná snímka (cyklus #0, delta writer) | čítacia slučka vrátane zápisu stránok 922,0 ms, dokončenie súboru (fsync, SHA-256) 1 638,7 ms, spolu 2 560,8 ms; 123 845 z 528 417 stránok | 1 | `data/results/2026-09-18_zmrazeny_host/summary.json` |
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

Prostredie, na ktorom merania bežali (z artefaktov, nie z tohto stroja dnes):

- hostiteľ: Fedora Linux 43 (Workstation Edition), jadro `7.1.13-100.fc43.x86_64`, QEMU emulator version 10.1.5 (qemu-10.1.5-1.fc43), libvirt 11.6.0;
- hosť: Debian GNU/Linux 12 (bookworm), verzia 12.13, jadro `6.1.0-42-cloud-amd64`, 2 vCPU.

Commity, z ktorých merania pochádzajú:

- `178ce4f bpf: opravit styri dovody, preco sa program nenacital do jadra 7.1` — 2026-09-18_zmrazeny_host/run_delta_5s.json *, 2026-09-18_zmrazeny_host/summary.json, optim_hash_20260918.json
- `104af34 odstranit vmicollect-index.csv z repa` — latency_vector_20260918.json *, perbin_c_20260918/perbin_c_20260918.json *, perbin_crosscheck_20260918.json *
- `*` — binárka, ktorá merala, nezodpovedá presne tomuto commitu: pracovný strom mal v čase merania neuložené zmeny

## 8. Čo nefunguje a čo ešte nie je

Detekčná cesta `safeguard/` je implementovaná, **model nad serverovým korpusom však natrénovaný
nie je**: korpus `benign-v6-20261026` je nazbieraný, tréning a nezávislé vyhodnotenie zostávajú
a `smoke` overuje iba mechaniku (`docs/SAFEGUARD.sk.md`, L16). Vyhodnocovač FAR/h a času do
detekcie zatiaľ nie je; otvorené body voči zadaniu vlastní `docs/STAV.sk.md`. Živá latencia
snímka → skóre počas zberu meraná nie je, len spracovanie uložených snímok (napr. staršou
cestou `tcn.score`, `data/results/latency_score_20260919.json`; L12). Slovo „real-time“ v názve
práce preto znamená periodický zber s meraným časom cyklu (kapitola 7). Presnosť voči reálnym
malvérovým vzorkám zatiaľ nebola meraná; syntetický scenár sa za také meranie nevydáva. Plán
ďalšej etapy je v `docs/METODIKA_ZBERU.sk.md`. Pri načítaní BPF programu sa objaví nefatálne
`libbpf: Error in bpf_create_map_xattr(pages): -EINVAL. Retrying without BTF.` — zber funguje, príčina neznáma.

Ostatné obmedzenia vlastní `docs/LIMITACIE.md` (L1 až L18); prerozprávať ich tu by
znamenalo držať dve znenia toho istého. Nadpisy sú preto dosadené z neho, skrátené:

- **L1** — Živá snímka: VM sa nezastavuje
- **L2** — Čítanie nie je úplne pasívne
- **L3** — Profil jadra hosťa je vstupná závislosť získaná z hosťa
- **L4** — Parsuje sa pamäť jadra, nie pamäť procesov — **ČIASTOČNE ODSTRÁNENÉ 2026-10-05 (A4)**
- **L5** — `hole_test` netestuje BPF vetvu
- **L6** — Injekčný test je injekcia do kópie snímky
- **L7** — Confidential VM (SEV-SNP, TDX) sa takto prečítať nedá
- **L8** — Prenos cez mmap nie je „nulové kopírovanie“
- **L9** — Hook je notifikačný
- **L10** — Kontroly integrity majú pomenované slepé miesta
- **L11** — Jeden výstupný adresár na jeden zberač
- **L12** — Čo ešte nie je zmerané
- **L13** — Príznakový vektor: čo o ňom treba vedieť pred tým, než sa na…
- **L14** — Procesy, moduly a sokety do príznakového vektora nevstupujú — **VYRIEŠENÉ 2026-09-19**
- **L15** — Časové rozlíšenie: proces kratší než perióda zberu je nevidi…
- **L16** — Presnosť detekcie malvéru nebola meraná
- **L17** — Profil jadra hosťa platí pre jeden boot, nie pre verziu jadr… — **VYRIEŠENÉ 2026-10-05 (preukotvenie, blok A2)**
- **L18** — Kontrola textu jadra: rozdiel medzi bootmi, baseline nesedí

## 9. Kam ďalej

| dokument | čo vlastní | riadkov |
|---|---|---|
| `docs/STAV.sk.md` | stav voči zadaniu, otvorené body, legenda blokov A1..H, prostredia | 155 |
| `docs/ARCHITEKTURA.md` | rozhrania, formát `.vmicd` a sidecaru, tok dát podrobne | 1606 |
| `docs/MERANIA.md` | log meraní: čo, kedy, akým príkazom a s akým výsledkom | 2817 |
| `docs/LIMITACIE.md` | L1 až L18: čo systém nevie a čo z toho plynie pre text | 1244 |
| `docs/kontroly.md` | kontroly podozrivých vzorcov a validačný príkaz | 338 |
| `HONESTY.md` | pravidlá pre čísla a slová v texte práce | 298 |
| `README.md` | rozcestník repozitára, preklad a testy, pôvod kódu | 100 |
| `docs/LAB.sk.md` | serverové laboratórium, premávka z hostiteľa a RAM zber | 331 |
| `docs/METODIKA_ZBERU.sk.md` | protokol zberu, príznaky, rozdelenie korpusu a audit | 412 |
| `docs/KONTROLA_ZBERU.sk.md` | pokrytie okien, kontrola logov a úložisko uloženého zberu | 222 |
| `docs/AUTOMATICKY_ZBER.sk.md` | kampaň: spustenie, uložené dáta, zastavenie, archív, report | 347 |
| `docs/PRIPRAVENOST_KAMPANE.sk.md` | pripravenosť kampane a zvyškové riziká (PASS/FAIL/UNVERIFIED) | 140 |
| `docs/SAFEGUARD.sk.md` | tréning modelového balíka, replay a spustenie detektora | 270 |
| `vmicollect/README.md` | zberač zvnútra: vrstvy, hooky, formáty | 642 |
| `guestparse/README.md` | parser zvnútra: preklad adries, prechod zoznamami | 180 |
| `features/PERBIN.md` | definícia príznakov a ich kontrakt | 194 |

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
