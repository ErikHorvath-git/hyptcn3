# Harness: zlatý obraz, overlay, sieť a sedenia (bloky B1–B5)

Reprodukovateľný harness pre benígne aj škodlivé sedenia **bez Kubernetes** —
stačí libvirt (`qemu:///session`). Tento adresár definuje všetko, čo sa nedá
zmerať: golden image, doménu, izolovanú sieť a manifest sedenia.

## Čo je kde

| súbor | čo definuje |
|---|---|
| `cloud-init/user-data`, `cloud-init/meta-data` | seed pre golden image (kľúče, qemu-guest-agent, sshd) |
| `make_golden.sh` | stiahne Debian 12 cloud image (pripnutá verzia), vyrobí seed ISO a `debian-12-base.qcow2` |
| `hyptcn-guest.xml` | šablóna domény (cesty k disku/seedu sa dosadia) |
| `net_isolated.xml`, `net_isolated.sh` | izolovaná sieť `hyptcn-iso` **bez NAT** (B3): hosť vidí iba hostiteľa s falošnými službami |
| `session_manifest.example.json` | vzor manifestu sedenia (B4) |

## Tok sedenia (B4 + B5 — kritické)

Každé sedenie — **benígne aj škodlivé — má identický priebeh**:

```
revert overlayu (virsh snapshot-revert hyptcn-clean)
  → štart VM → zahriatie (warmup_s)
  → tcpdump na moste (voliteľný)
  → pozemná pravda PRED (ps/lsmod/ss cez guest_exec)
  → štart zberu (vmicollect run, root)
  → injekcia binárky cez guest-agent (guest-file-open/write → chmod → exec)
  → pevný čas behu (runtime_s)
  → pozemná pravda PO → stop zberu → stop VM → revert overlayu
  → manifest sedenia (typ, štítok, SHA-256, commit, čas, tcpdump)
```

Jediný rozdiel medzi benígnym a škodlivým sedením je **obsah injikovanej
binárky** (B5): benígne sedenie injikuje benígnu binárku (napr. `sleep`),
škodlivé PoC/malvér. Zahriatie, injekcia cez agenta, ukončenie — všetko
rovnako dlho a rovnako. Preto sa model nemôže naučiť harness namiesto
správania. Priebeh sa zaznamenáva do manifestu, aby sa dal overiť.

**Politika payloadov.** Injikovaný súbor sa musí dať spustiť v hosťovi
(Debian 12); binárky z hostiteľa (Fedora 43, novší glibc) v ňom nebežia.
Benígne sedenia preto injikujú **záťažové skripty z `scripts/loads/`**
(`injekcia.subor = scripts/loads/<load>.sh`, `SEED`/`DUR` sa odovzdajú pri
spustení) — mechanizmus (guest-file-write cez agenta, chmod +x, exec, kill
po `runtime_s`) je doslova ten istý ako pri škodlivej binárke. PoC pre G1
sa budú kompilovať pre Debian 12 (v hosťovi alebo musl-static) a nikdy
nepôjdu do gitu — do manifestu ide len ich SHA-256.

## Zlatý obraz

`make_golden.sh` stiahne pripnutú verziu `debian-12-genericcloud-amd64`
(základ pre `hyptcn-guest`: Debian 12.13, jadro `6.1.0-42-cloud-amd64`),
vyrobí seed ISO a base qcow2 (3 GiB). Výstup: SHA-256 do
`golden.manifest.json`. Existujúci base obraz na tomto stroji
(`/home/eh/vms/debian-12-base.qcow2`) je vstupná závislosť meraní — jeho
identita je v `data/results/` artefaktoch (`env.json`), nie tu.

## Izolovaná sieť (B3)

`net_isolated.sh` definuje a spustí sieť `hyptcn-iso` (most `virbr1`,
192.168.99.1/24, DHCP pre hosťa, **bez forward/NAT**). Hosť v nej dosiahne
len hostiteľa — tam bežia falošné služby (DNS/HTTP/SMTP, INetSim alebo
FakeNet) pre malvérové sedenia. Pozemná pravda v tejto sieti ide cez
`guest_exec.sh -m agent` (qemu-guest-agent funguje aj bez siete).
Doména `hyptcn-guest` má v XML rozhranie na `virbr0` (NAT) — pre sedenia
s izoláciou sa používa klon domény s rozhraním na `hyptcn-iso`
(`virsh attach-interface`/`detach-interface` v session.sh).
