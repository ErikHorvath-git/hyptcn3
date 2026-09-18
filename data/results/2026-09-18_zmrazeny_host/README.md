# Referenčná sada meraní z zmrazeného hosťa (2026-09-18)

Obsah tohto adresára vznikol 2026-09-18 medzi 16:30 a 16:34 UTC binárkou
`vmicollect/build/vmicollect` **zostavenou z tohto repozitára**
(sha256 `5cdb2963…`, celé v `env.json`), nad bežiacou doménou `hyptcn-guest`.

Dôvod merania: predchádzajúca sada (`../2026-09-18_prvy_beh/`) bola odobratá medzi
14:30 a 14:43, keď v hosťovi ešte bežal bezpečnostný agent staršieho projektu
(`hyptcn_guest_ag`), a binárkou zo scratchpadu, nie z repozitára. Táto sada je
odobratá z hosťa, v ktorom ten agent nebeží a `unattended-upgrades` je zamaskovaný.

## Súbory

| Súbor | Čo je v ňom |
|---|---|
| `summary.json` | agregát všetkých čísel s hlavičkou `{commit, date, host, guest, command, n, values}`; **toto je súbor, na ktorý sa odkazuje text práce** |
| `env.json` | prostredie merania (hostiteľ, hosť, verzie, sha256 binárky) |
| `probe.json` | výstup `root_run.sh probe` vrátane úplného stdout/stderr |
| `once_raw_sha256_{1,2,3}.json` | výstupy `root_run.sh once -w raw` (predvolený hash sha256) |
| `once_raw_none_{1,2,3}.json` | výstupy `root_run.sh once -w raw -H none` |
| `run_delta_5s.json` | výstup `root_run.sh run -w delta -i 5 -N 12` |
| `validate2.json` | výstup `python3 -m guestparse validate`, pozemná pravda = `ss -tulpn` |
| `validate2_ss_vsetky.json` | ten istý parser, pozemná pravda = `ss -tuanp` (aj nepočúvajúce sokety) |
| `sidecars/` | sidecar JSONy jednotlivých snímok (samotné `.raw`/`.vmicd` sú mimo repa) |
| `logs/host_cistota.txt` | dôkaz, že hosť je zmrazený (pgrep, systemctl, uname, ps, lsmod) |
| `logs/host_journal_pocas_run.txt` | journal hosťa počas behu `run` – vysvetľuje zvýšené `changed_ratio` v cykloch #4–#7 |
| `logs/once_behy.txt`, `logs/run_delta.txt` | úplné výstupy behov vrátane sha256 binárky pred každým behom |
| `logs/env_zdroj.txt` | surové výstupy príkazov, z ktorých je `env.json` |
| `logs/kontrola_stara_binarka.txt` | pokus zopakovať beh starou binárkou zo scratchpadu – neúspešný (návratový kód 3) |
| `make_summary.py` | skript, ktorý zo sidecarov a výstupov poskladá `summary.json` |
| `porovnanie_prvy_beh.py`, `logs/porovnanie_prvy_beh.txt` | tabuľka prvý beh vs. zmrazený hosť, zostavená zo `summary.json` oboch sád |
| `SHA256SUMS` | kontrolné súčty všetkých súborov v tomto adresári |

Validačné sedenie (pozemná pravda pred/po + snímka) je v
`../../sessions/20260918_validate2/`. Snímka `snap/*.vmicd` má 508 136 824 B
a je mimo gitu (`.gitignore`: `*.vmicd`); bez nej sa `validate2.json` nedá zopakovať.

## Čo tieto čísla nie sú

- Nie sú to merania vplyvu zberu na hosťa – vplyv na VM sa v tejto sade nemeral.
- `test citania` v `probe.json` (1436 MiB/s) je jedno krátke čítanie 16,6 MB,
  nie priepustnosť plnej snímky.
- `changed_ratio` plnej snímky (0,23437) je podiel stránok, ktoré writer zapísal,
  nie miera zmeny medzi snímkami.
- Cykly #4–#7 behu `run` nemerajú nečinnú VM: o 16:32:36 UTC sa do hosťa prihlásil
  a odhlásil ssh (`sshd[2154]`, relácia 141). Preto sú v `summary.json` oddelené.

## Binárka sa po meraniach zmenila

O 16:40:33 UTC – teda po poslednom behu tejto sady (16:33:38 UTC) – iný agent
zmenil `vmicollect/src/sha256.c` a `vmicollect/src/writer_raw.c` a binárku znovu
zostavil; `vmicollect/build/vmicollect` má odvtedy sha256 `4450f257…`.
Všetkých deväť výstupných JSONov tejto sady (probe, 6× once, run, validate) má
v poli `binary.sha256` hodnotu `5cdb2963…`, takže celá sada pochádza z jednej
binárky spred tejto zmeny. Čísla z tejto sady preto neplatia pre binárku, ktorá
je v `build/` teraz.

## Čo sa nepodarilo overiť

Beh `once -w raw` s predvoleným `hash=sha256` trval v tejto sade 13,4–14,3 s,
v prvom behu 42,2 s. Aby sa dalo povedať, či je rozdiel v binárke alebo v stave
hosťa, skúsil som starú binárku zo scratchpadu (sha256 `c53ce6ee…`) spustiť na
zmrazenom hosťovi. Oba pokusy skončili návratovým kódom 3 – jej BPF program sa
do jadra hostiteľa nenačítal (`bpf_task_from_vpid`: nezlučiteľný prototyp
s BTF jadra). Rozdiel preto zostáva nevysvetlený a obe čísla sa nedajú
porovnávať ako dve merania tej istej veci.

## Odchýlka od požiadavky na hlavičku

Požadovanú hlavičku `{commit, date, host, guest, command, n, values}` majú
`summary.json` a `env.json`. JSONy, ktoré vyrába `scripts/root_run.sh`
(`probe.json`, `once_*.json`, `run_delta_5s.json`), nesú
`{schema, date, commit, commit_dirty, domain, libvirt_uri, command, binary, host}`
– chýba im `guest` a `n` a okrem `probe.json` aj `values`. Skript `root_run.sh`
som nemenil, patrí inému agentovi; čísla z týchto súborov sú preto agregované
do `summary.json`, ktorý hlavičku má.
