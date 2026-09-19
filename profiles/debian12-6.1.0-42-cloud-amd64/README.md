# Profil jadra hosťa: debian 12, 6.1.0-42-cloud-amd64 (x86_64)

Tento adresár vygeneroval `scripts/get_profile.sh` dňa 2026-09-19T13:19:15+02:00.

## Pôvod

| položka | hodnota |
|---|---|
| cieľ | `root@192.168.122.100` |
| prenos | ssh |
| **boot_id hosťa** | `82b778a3-89f8-4b04-b518-5db8ebeb4ab4` |
| **hosť naštartovaný** | 2026-09-19 10:30:31 |
| jadro hosťa | `6.1.0-42-cloud-amd64` |
| `/proc/version` hosťa | `Linux version 6.1.0-42-cloud-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30)` |
| jadro hostiteľa | `7.1.13-100.fc43.x86_64` |
| bpftool na hostiteľovi | bpftool v7.6.0 |

Príkazy, ktorými súbory vznikli:

```
ssh -o BatchMode=yes root@192.168.122.100 cat /proc/kallsyms            > kallsyms.txt
ssh -o BatchMode=yes root@192.168.122.100 cat /sys/kernel/btf/vmlinux   > btf.raw
bpftool btf dump file btf.raw format raw                  > btf.txt
```

## Súbory

| súbor | riadkov / bajtov | obsah |
|---|---|---|
| `kallsyms.txt` | 98695 riadkov | adresy symbolov bežiaceho jadra hosťa – **platia iba pre boot `82b778a3-89f8-4b04-b518-5db8ebeb4ab4`** |
| `btf.raw` | 4104445 B | binárne BTF z `/sys/kernel/btf/vmlinux` – viazané na verziu jadra, nie na boot |
| `btf.txt` | 223941 riadkov | výpis BTF, z neho parser číta offsety polí |
| `boot.json` | – | `boot_id`, dátum odberu a verzia jadra; číta ho `guestparse` a vypisuje v `info` |

## Kľúčové symboly, ktoré parser číta

| symbol | adresa | na čo |
|---|---|---|
| `linux_banner` | 0xffffffffb191f560 | kotva pre určenie posunu obrazu jadra (KASLR) |
| `init_task` | 0xffffffffb221aa40 | začiatok zoznamu procesov, kontrola posunu (`comm == swapper/0`) |
| `modules` | 0xffffffffb23273a0 | hlavička zoznamu načítaných modulov |
| `page_offset_base` | 0xffffffffb1b95ce0 | odtiaľ sa číta začiatok priameho mapovania |
| `init_top_pgt` | 0xffffffffb2210000 | koreň tabuliek stránok pre oblasti mimo lineárnych vetiev |
| `socket_file_ops` | 0xffffffffb18f6920 | rozpoznanie deskriptora, ktorý je socket |
| `tcp_prot` | 0xffffffffb23ed8a0 | určenie protokolu podľa `skc_prot` |
| `udp_prot` | 0xffffffffb23ee060 | to isté pre UDP |
| `tcpv6_prot` | 0xffffffffb23f4a20 | to isté pre TCP nad IPv6 |
| `udpv6_prot` | 0xffffffffb23f3ec0 | to isté pre UDP nad IPv6 |
| `_stext` | 0xffffffffb0800000 | dolná hranica textu jadra |
| `_etext` | 0xffffffffb1601ef2 | horná hranica textu jadra |
| `sys_call_table` | 0xffffffffb1800360 | tabuľka, ktorej integrita sa kontroluje |

Tieto adresy platia **iba pre boot `82b778a3-89f8-4b04-b518-5db8ebeb4ab4`** (hosť naštartovaný 2026-09-19 10:30:31).

## Poctivo o tom, čo to znamená

Profil je **jednorazová vstupná závislosť získaná z hosťa** – rovnako ako profil
pri LibVMI alebo Volatility. Nejde teda o rekonštrukciu „bez akejkoľvek znalosti
hosťa“: adresy symbolov a offsety polí pochádzajú z bežiaceho hosťa a boli
odobraté raz, mimo behu zberu. Samotný zber snímok ani parsovanie už do hosťa
nesiahajú.

## Profil je viazaný na jeden štart hosťa

| časť profilu | na čo je viazaná | prežije reštart? |
|---|---|---|
| `kallsyms.txt` (adresy symbolov) | konkrétny **štart** jadra – KASLR posunie obraz jadra pri každom bootnutí | **nie** |
| `btf.raw`, `btf.txt` (offsety polí štruktúr) | **verziu a konfiguráciu** jadra | áno |
| `boot.json` | zapisuje `boot_id` a dátum odberu, aby sa nesúlad dal zistiť porovnaním | – |

Preto po každom reštarte hosťa:

```sh
scripts/get_profile.sh -f root@192.168.122.100     # -f: prepíše profil z predchádzajúceho bootu
```

Rýchla kontrola bez spúšťania parsera – `boot_id` v `boot.json` sa musí
zhodovať s hosťom:

```sh
python3 -c 'import json;print(json.load(open("boot.json"))["boot_id"])'
ssh root@192.168.122.100 cat /proc/sys/kernel/random/boot_id
```

Reštart do **inej verzie jadra** (napr. po `unattended-upgrades`) je iný prípad:
prestanú sedieť aj offsety polí. Vznikne nový adresár podľa novej verzie jadra
a validácia sa musí zopakovať celá.

## Čo sa stane, keď sa použije profil z iného bootu

Zmerané 2026-09-19 na snímke z aktuálneho bootu a profile z predchádzajúceho:

- posun jadra sa **nájde** – sken banneru ho nakalibruje, takže časť výstupu
  vyzerá normálne;
- krížová kontrola prekladu adries **zlyhá**: lineárny výpočet dá adresu, na
  ktorej symbol naozaj je, ale prechod tabuliek stránok pre jeho virtuálnu
  adresu skončí na neprítomnej položke – tabuľky sú indexované skutočnými
  virtuálnymi adresami tohto bootu, nie tými zo starého `kallsyms.txt`;
- prechod zoznamu procesov sa **neuzavrie** (hlavička zoznamu má starú adresu),
  výsledok je označený `NEUPLNE`.

`guestparse` to pomenuje priamo: vypíše `NESULAD PROFILU`, povie, na ktorej
úrovni tabuliek prechod skončil, a skončí **návratovým kódom 5** (chyba vstupu,
nie neuzavretá kontrola). Platí to pre `info` aj pre `ps`, `lsmod`, `ss`,
`checks` a `validate`.

Bez hosťa a bez druhej snímky to overuje test
`guestparse/tests/test_profile_boot.py`: profil z iného bootu sa v ňom vyrobí
posunutím všetkých adries jadra o konštantu – presne to robí KASLR pri štarte.

## Staršie snímky

V repozitári je **jeden adresár na verziu jadra hosťa a v ňom profil
z posledného štartu** – staré profily sa neodkladajú. Dôsledok treba povedať
nahlas: snímka odobratá pred reštartom hosťa sa s týmto profilom už rozobrať
nedá a profil, ktorý k nej patril, sa spätne nevyrobí (KASLR posun toho bootu
už nikde nie je). Snímka z iného bootu preto potrebuje profil odobratý počas
toho bootu; ak sa nezachoval, je použiteľná len na to, čo profil nepotrebuje
(veľkosť, kontrolné súčty, reťazec `.vmicd`). Testovacia snímka
`guestparse/tests/data/mini.vmicd` sa z tohto dôvodu vyrába znova vždy spolu
s profilom.
