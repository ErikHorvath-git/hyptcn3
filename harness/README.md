# Harness: zlatý obraz, overlay, sieť a sedenia

Harness pre benígne aj škodlivé sedenia **bez Kubernetes** —
stačí libvirt (`qemu:///session`). Tento adresár definuje všetko, čo sa nedá
zmerať: golden image, doménu, izolovanú sieť a manifest sedenia.

**Stav (2026-10-29).** Tok sedení nad doménou `hyptcn-guest` (`scripts/session.sh`,
`scripts/session_batch.sh`, záťaže `scripts/loads/`, manifesty
`harness/session_manifest*.json` a podpríkazy `session` a `batch`
v `scripts/root_run.sh`) je v repozitári, ale je **historický** a zostáva tu do
konca experimentov. Benígny korpus sa zbiera inak: nad trvalou doménou
`hyptcn-lab` cez `scripts/collection.py` a `scripts/campaign.py`
([`docs/LAB.sk.md`](../docs/LAB.sk.md),
[`docs/AUTOMATICKY_ZBER.sk.md`](../docs/AUTOMATICKY_ZBER.sk.md)). Metodika korpusu
([`docs/METODIKA_ZBERU.sk.md`](../docs/METODIKA_ZBERU.sk.md), časť 5) zakazuje
experiment „idle = benígne, vyťažený server = útok“ a útoky páruje s benígnymi
kontrolami na rovnakej záťaži; tok nižšie na to navrhnutý nebol. Cez `session.sh`
sa s manifestom dokončili iba štyri sedenia `idle` z 2026-10-05/06
(`data/sessions/*_idle_benign/manifest.json`; manifest prvého z nich sa doplnil
po behu, pole `priebeh`), dávky `nginx_wrk` a `mikrosluzby` zlyhali na
`snapshot-revert` (`data/sessions/batch_20261006T002039Z_*.log`) a škodlivé
sedenie nebežalo nikdy – UNVERIFIED (HONESTY P5).

Komentáre v týchto súboroch, v `scripts/session*.sh` a v `scripts/loads/`
používajú označenia blokov B1 (zlatý obraz), B3 (izolovaná sieť), B4 (sedenie
podľa manifestu), B5 (rovnaký priebeh sedení) a C (záťaže) z plánu
z 2026-10-05; legenda blokov je v [`docs/STAV.sk.md`](../docs/STAV.sk.md).

## Čo je kde

| súbor | čo definuje |
|---|---|
| `cloud-init/user-data`, `cloud-init/meta-data` | seed pre zlatý obraz: účty `debian` a `root` iba s SSH kľúčom hostiteľa (bez hesiel), qemu-guest-agent a balíky `nginx`, `wrk`, `postgresql`, `gcc`, `zstd`, `rsync` |
| `make_golden.sh` | stiahne pripnutý Debian 12 cloud obraz, vyrobí seed ISO a `vms/debian-12-base.qcow2`, zapíše `golden.manifest.json` |
| `golden.manifest.json` | záznam posledného behu `make_golden.sh`: URL a SHA-256 obrazu, SHA-256 seedu, dátum, commit |
| `hyptcn-guest.xml` | šablóna domény `hyptcn-guest` so zástupnými symbolmi `@@DISK@@`, `@@SEED@@` a `@@BRIDGE@@`; žiadny skript ich nedosádza, dopĺňajú sa ručne |
| `net_isolated.xml`, `net_isolated.sh` | izolovaná sieť `hyptcn-iso` **bez NAT**: hosť vidí iba hostiteľa |
| `session_manifest.example.json` | vzor manifestu sedenia (záťaž `idle`; predvolený manifest `session_batch.sh`) |
| `session_manifest_nginx.json`, `session_manifest_mikro.json` | benígne sedenia so záťažou `nginx_wrk` a `mikrosluzby` a prevádzkou z hostiteľa (`host_traffic`) |
| `session_manifest_g1_diamorphine.json`, `_encrypt.json`, `_hider.json`, `_memfd.json` | manifesty PoC sedení ([`scripts/poc/README.md`](../scripts/poc/README.md)); žiadny sa nespustil |

## Tok sedenia (historický)

`scripts/session.sh` vedie každé sedenie — **benígne aj škodlivé — rovnakým
mechanizmom**:

```
revert overlayu (virsh snapshot-revert hyptcn-clean)
  → štart VM → zahriatie (warmup_s)
  → apt_packages z manifestu (iba v overlayi)
  → tcpdump na moste (voliteľný)
  → pozemná pravda PRED (ps/lsmod/ss cez guest_exec)
  → štart zberu (vmicollect run, root)
  → injekcia binárky cez guest-agent (guest-file-open/write/close)
  → chmod a exec cez guest_exec (ssh, pri zlyhaní spojenia agent)
  → pevný čas behu (runtime_s)
  → pozemná pravda PO → stop zberu → stop VM → revert overlayu
  → manifest sedenia (typ, štítok, SHA-256, commit, čas, tcpdump)
```

Mechanizmus injekcie, zahriatie a ukončenie sú pre oba typy rovnaké. Manifest
však smie pridať aj ďalšie rozdiely: prevádzku z hostiteľa (`host_traffic`
v manifestoch `nginx` a `mikro`), sieť (`net: isolated` v `g1_diamorphine`)
a balíky (`apt_packages` `gcc` a `git` v `g1_diamorphine`, `g1_hider`
a `g1_memfd`). Tie sú možný confound: pri
porovnaní benígnych a škodlivých sedení musia byť rovnaké, alebo sa musia
vyhodnotiť zvlášť. Že sa model nenaučí harness namiesto správania, by musel
ukázať test confoundu medzi benígnymi a škodlivými sedeniami; škodlivé sedenie
týmto tokom nebežalo. Priebeh sa zaznamenáva do manifestu, aby sa dal overiť.

**Politika payloadov.** Injikovaný súbor sa musí dať spustiť v hosťovi
(Debian 12); binárky z hostiteľa (Fedora 43, novší glibc) v ňom nebežia.
Benígne sedenia preto injikujú **záťažové skripty z `scripts/loads/`**
(`injekcia.subor = scripts/loads/<load>.sh`, `SEED`/`DUR` sa odovzdajú pri
spustení) — mechanizmus (guest-file-write cez agenta, chmod +x, exec, kill
po `runtime_s`) je doslova ten istý ako pri škodlivej binárke. Do hosťa sa
prenáša jediný súbor; `scripts/poc/hider_run.sh` a `scripts/poc/memfd_run.sh` si
preto zdroj C nesú v sebe a kompilujú ho až v hosťovi (`scripts/poc/diamorphine.sh`
si zdroj stiahne z GitHubu). Binárky nikdy nejdú do gitu; do manifestu sedenia
ide SHA-256 injikovaného súboru (`injekcia.sha256_merane`).

## Zlatý obraz

`bash harness/make_golden.sh [--fresh]` (potrebuje `curl`, `qemu-img`,
`genisoimage`, `sha256sum`) stiahne pripnutý obraz
`debian-12-genericcloud-amd64-20241004-1890`, z `cloud-init/` vyrobí seed ISO
`vms/cloud-init.iso` a base qcow2 `vms/debian-12-base.qcow2` (3 GiB, overlay nad
stiahnutým obrazom v `vms/`). Existujúci base prepíše iba `--fresh`. SHA-256
obrazu a seedu zapíše do `golden.manifest.json`; posledný záznam je
z 2026-10-05.

Pripnutý obraz je z 2024-10-04, kým jadro `6.1.0-42-cloud-amd64`, pre ktoré je
profil v `profiles/`, je zostavené 2025-12-30 (`/proc/version` v
[`profiles/debian12-6.1.0-42-cloud-amd64/README.md`](../profiles/debian12-6.1.0-42-cloud-amd64/README.md)),
a cloud-init balíky neaktualizuje (`package_upgrade: false`). VM zo zlatého
obrazu preto bez aktualizácie jadra s týmto profilom nesedí; ktoré jadro obraz
obsahuje, sa neoverovalo (UNVERIFIED).

Doména `hyptcn-guest`, z ktorej je profil jadra v `profiles/` a merania
z 2026-09-18/19, z `make_golden.sh` nevznikla. Na vývojovom hostiteľovi (Fedora 43;
overené cez `virsh dumpxml` a `qemu-img info` 2026-10-29) má disk
`/home/eh/vms/hyptcn-guest.qcow2` s podkladom `/home/eh/vms/debian-12-base.qcow2`
(nie `vms/debian-12-base.qcow2` z repozitára), seed `/home/eh/vms/cloud-init.iso`,
rozhranie na moste `virbr0` (NAT) a snapshot `hyptcn-clean`. Tento podkladový
obraz je vstupná závislosť meraní; jeho cestu a veľkosť zapisuje
`data/results/2026-09-18_prvy_beh/env.json` (`guest.backing_image`), kontrolný
súčet v artefaktoch nie je.

Doména zberu korpusu `hyptcn-lab` vzniká pri prvom `make lab-up` klonom disku
zastavenej domény `hyptcn-guest` (`scripts/labctl.py`, `qemu-img convert`), nie
zo zlatého obrazu; podrobnosti sú v [`docs/LAB.sk.md`](../docs/LAB.sk.md).

Čistá VM na inom počítači (postup ako celok neprebehol – UNVERIFIED):

1. `bash harness/make_golden.sh`;
2. overlay pre doménu s absolútnou cestou k podkladu, napr.
   `qemu-img create -f qcow2 -F qcow2 -b "$PWD/vms/debian-12-base.qcow2" vms/hyptcn-guest.qcow2`
   (z koreňa repozitára);
3. kópia `hyptcn-guest.xml` s dosadenými `@@DISK@@` (overlay), `@@SEED@@`
   (`vms/cloud-init.iso`) a `@@BRIDGE@@` (most, ktorý povoľuje
   `/etc/qemu/bridge.conf`; na vývojovom hostiteľovi `virbr0`), potom
   `virsh -c qemu:///session define <kópia>`;
4. prvý štart: cloud-init nainštaluje qemu-guest-agent a balíky (potrebuje sieť);
5. VM vypnúť a `make lab-up` z nej urobí `hyptcn-lab`.

## Izolovaná sieť

`harness/net_isolated.sh up|down|state` definuje (ak treba), spustí alebo
zastaví sieť `hyptcn-iso` z `net_isolated.xml`: most `virbr1`,
192.168.99.1/24, DHCP pre hosťa, **bez forward/NAT**. Hosť v nej dosiahne iba
hostiteľa — tam majú bežať falošné služby (DNS/HTTP/SMTP, INetSim alebo
FakeNet) pre malvérové sedenia; ich nastavenie v repozitári nie je. Pozemná
pravda v tejto sieti ide cez `scripts/guest_exec.sh -m agent`
(qemu-guest-agent funguje aj bez siete).

Doména `hyptcn-guest` má rozhranie na `virbr0` (NAT). Pri `net: isolated`
`session.sh` spustí `hyptcn-iso`, pripojí k tej istej doméne druhé rozhranie na
nej (`virsh attach-interface`) a po sedení ho odpojí (`detach-interface`).
Pôvodné rozhranie na NAT pritom zostáva, takže úplnú izoláciu tento postup
nezaručuje. Na vývojovom hostiteľovi je sieť v `qemu:///session` definovaná, ale
neaktívna (2026-10-29), žiadne zaznamenané meranie ju nepoužilo a či sa
v session režime dá pripojiť (`/etc/qemu/bridge.conf` tam povoľuje iba
`virbr0`), sa neoverilo – UNVERIFIED. Sieť `passt` v `hyptcn-lab` izoláciou
pre malvér nie je ([`docs/METODIKA_ZBERU.sk.md`](../docs/METODIKA_ZBERU.sk.md),
časť 7).
