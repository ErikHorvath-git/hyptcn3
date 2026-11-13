# Experimenty nad meracím reťazcom

Balík `experimenty/` nie je súčasťou zberu ani auditu (nie je v
`MEASUREMENT_DIRS` v `scripts/collection.py`). Jeho zmena preto nemení
odtlačky meracieho kódu kampaní. Volá iba existujúce nástroje repozitára.

## E5 (VO5): réžia monitorovacieho modulu, návrh A/B/A

`experimenty/aba.py` meria, koľko stojí monitorovací modul VM aj hostiteľa.
Používa tri podmienky a v každej rovnaký profil HTTP záťaže.

| Podmienka | Čo beží popri laboratórnej VM |
|---|---|
| A | iba záťaž `scripts/host_traffic.py`, bez zberu |
| B | zberač `vmicollect` s presne tými voľbami, ktoré mu dáva `safeguard run` (`safeguard/supervisor.py:collector_command`), bez detektora |
| C | celý detektor `python3 -m safeguard run` (vlastný zberač a skórovanie) |

Rozdiel C − B je potom cena samotného detektora (čítanie snímok, príznaky, TCN).

### Rozvrh a vyváženie poradia

Jedno opakovanie má päť blokov a každý blok B alebo C má po oboch stranách
blok A: `A-B-A-C-A` alebo `A-C-A-B-A`. Vzory sa v opakovaniach striedajú v
poradí ABBA (P0 P1 P1 P0 …). B aj C sú tak rovnako často na pozícii 1 aj 3.
Pri párnom počte opakovaní majú v behu aj rovnaký priemerný index. Lineárny
posun prostredia (teplota, page cache, rast databázy) sa preto nezamení
s účinkom. Nepárny počet opakovaní nástroj odmietne, ak nedostane
`--allow-unbalanced`.

Účinok v jednej trojici je `X − (A_pred + A_po) / 2`. Účinok podmienky je
priemer cez jej trojice. Lineárny posun sa v trojici odčíta.

```sh
python3 -m experimenty.aba plan --repetitions 4        # rozvrh ako JSON, bez vedľajších účinkov
```

### Beh

Najprv suchý beh. Vypíše každý krok a presný príkaz každého bloku a nič
nevytvára ani nespúšťa:

```sh
python3 -m experimenty.aba run --dry-run --out data/safeguard/e5-YYYYMMDD
```

Ostrý beh spúšťa používateľ zo svojho účtu (vlastník VM) cez sudo, rovnako
ako `scripts/collection.py run` a `safeguard run`. Suchý beh vypíše presný
príkaz, napríklad:

```sh
sudo env PYTHONPATH="$(python3 -m site --user-site)" python3 -m experimenty.aba run --execute \
  --out data/safeguard/e5-YYYYMMDD --protocol config/collection-v2.json --scenario steady \
  --traffic-seed 1 --repetitions 4 --warmup-s 240 --measure-s 600 --rest-s 60 \
  --bundle data/models/server-v2-benign-v6
```

Predvolené hodnoty: protokol `config/collection-v2.json` (protokol balíka
`server-v2-benign-v6`, `safeguard run` iný neprijme), scenár `steady`,
4 opakovania × 5 blokov, zahrievanie 240 s, meranie 600 s, pauza 60 s.
Spolu je to asi 5 h. Zahrievanie musí pokryť aspoň jedno okno detektora
(`window_rows × interval_s` = 160 s). V podmienke C tak detektor pri začiatku
merania už skóruje a prvá plná snímka zberača padne do zahrievania.

Pred behom má byť VM spustená (`labctl.py status`), zberač zostavený
(`make build`) a pri C dostupný balík modelu. Nesmie bežať kampaň ani detektor.
Bežec drží zámok `data/collections/.lock` (v blokoch A a B; v bloku C ho drží
`safeguard run`).

Priebeh jedného bloku:

1. kontrola: žiadny cudzí `host_traffic.py`, rovnaký proces QEMU ako na začiatku behu;
2. `/healthz`, potom `prefault` odswapovanej pamäte QEMU (`scripts/collection.py`);
   v B/C aj kontrola pamäte pre uzamknutú frontu zberača a diskovej rezervy;
3. štart `host_monitor.py run` (1 s) a `host_traffic.py` vo fáze `warmup`
   s rovnakými argumentmi a seedom v každom bloku;
4. B: štart zberača, C: štart `safeguard run --cycles N`, kde
   N = ⌈(warmup + measure) / interval⌉ + 4;
5. po zahrievaní SIGUSR1 (fáza `measure`), po meraní SIGUSR2 (`post`);
6. B/C: čaká sa, kým zberač alebo detektor skončí sám, záťaž medzitým beží ďalej
   (fáza `post` sa nevyhodnocuje); až potom sa zastaví záťaž a monitor;
7. `block.json` (časy, návratové kódy, identita QEMU, prefault, pamäť).

Ako root bežia `prefault`, monitor, generátor, zberač a `safeguard run`.
Kroky labctl (`traffic-stop`, identita hosťa) bežia cez `runuser` ako
vlastník VM (`scripts/collection.py:user_command`). Trvalý generátor
`hyptcn-lab-traffic` sa na začiatku zastaví a znova sa nespúšťa. Na konci sa
vlastníctvo výstupov vráti používateľovi (`SUDO_UID`).

### Výstupy behu

```
<out>/run.json            konfigurácia, rozvrh, commit, measurement_dirty, identita hosťa a QEMU,
                          SHA-256 zberača a použitých skriptov
<out>/run_end.json        dokončené bloky, identita hosťa po behu, signály
<out>/blocks/<id>/        block.json, traffic_requests.jsonl, traffic_intervals.jsonl, traffic.json,
                          host_monitor.jsonl, *.log; B: raw/ (snímky), C: safeguard/ (výstup detektora)
```

Snímky v `raw/` a `safeguard/raw/` zaberajú niekoľko GiB na blok. Výstup
patrí na disk so snímkami, nie na disk VM (pozri I/O interferenciu v
`docs/LAB.sk.md`). Bežec snímky sám nemaže.

### Vyhodnotenie (offline)

```sh
python3 -m experimenty.aba summarize data/safeguard/e5-YYYYMMDD \
  --out data/results/e5_rezia_aba_YYYYMMDD.json [--bootstrap 2000 --seed 0 --cluster-intervals 6]
```

Vyhodnotenie číta iba zaznamenané logy. Každý blok najprv skontrolujú
existujúce audity: `scripts/traffic_log.py summarize` (bez jediného
problému, `session_id` = blok) a `scripts/host_monitor.py summarize` nad
meraným oknom (pokrytie, medzery vzoriek). Vyhodnotenie potom odmietne
(kód 2, nič nezapíše):

- chýbajúci alebo neúplný súbor, nedokončený beh alebo blok, neplánovaný blok;
- inú konfiguráciu záťaže v niektorom bloku, ako mal beh;
- iný proces QEMU alebo inú identitu hosťa (reštart, obnovenie);
- dĺžku merania mimo ±5 % plánu;
- nesúlad podmienky s procesmi, ktoré monitor videl v meranom okne: v A nesmie
  bežať `vmicollect` ani `safeguard`, v B musí bežať `vmicollect` v každej
  vzorke, v C oba;
- zberač alebo detektor, ktorý neskončil sám s kódom 0.

Výsledný JSON má hlavičku ako ostatné záznamy v `data/results/` (`command`,
`commit`, `commit_dirty`, `date`, `host`, `guest`, `n`) a v `values`:

- `run`, `config`, `inputs_sha256` (všetky čítané súbory), `definitions`, `bootstrap`;
- `blocks`: metriky každého bloku vrátane chýb a časových okien;
- `conditions`: zlúčený opis A/B/C. Latencia p50/p95 (všetky požiadavky,
  presný nearest-rank ako v `traffic_log.py`), priepustnosť, priemerné CPU,
  iowait, disk R/W MB/s, použitá RAM, PSI I/O, CPU procesov qemu/vmicollect/safeguard;
- `differences`: `B_minus_A`, `C_minus_A`, `C_minus_B` s odhadom, relatívnou
  zmenou a 95 % CI. Pri B a C aj hodnoty jednotlivých trojíc;
- `drift_A`: rozdiel posledného a prvého A v každom opakovaní.

CI je neparametrický zhlukový bootstrap s pevným seedom, stratifikovaný po
blokoch. Merané okno bloku sa rozdelí na zhluky po 6 po sebe idúcich 5 s
intervaloch (30 s). Požiadavky a vzorky monitora zostávajú v zhluku spolu.
Zhluky sa v každom bloku vyberajú s opakovaním a celá štatistika sa vypočíta
znova. Výsledok je percentilový interval.

### Obmedzenia

- Záťaž je uzavretý cyklus: vyššia latencia sama znižuje priepustnosť.
  Priepustnosť preto nie je nezávislý ukazovateľ.
- CI zachytáva variabilitu vnútri blokov. Rozdiely medzi opakovaniami sú
  vidieť iba v `per_triplet` a `drift_A`. Pri 4 opakovaniach je to opis,
  nie samostatný test.
- `full_every` = 360 (30 min) je dlhšie ako blok. V meranom okne sú preto iba
  delta snímky a cena periodickej plnej snímky v ňom nie je; prvá plná
  snímka padne do zahrievania. Kampaňové merania plnej snímky sú v
  `docs/MERANIA.md`.
- Monitor hľadá procesy podľa príkazového riadku každých 10 s. Kontrola
  prítomnosti preto vyžaduje, aby komponent bežal celé merané okno.

Testy (syntetické logy): `python3 -m pytest -q experimenty/tests`.
