# Profil jadra hosťa: Debian 12, `6.1.0-42-cloud-amd64` (x86_64)

Profil je vstup parsera `guestparse` – hovorí mu, kde v pamäti hosťa hľadať
(adresy symbolov) a ako sú poskladané štruktúry jadra (offsety polí).
Bez neho sa zo snímky nedá prečítať nič viac než bajty.

## Pôvod

| položka | hodnota |
|---|---|
| hosť | libvirt doména `hyptcn-guest` (QEMU/KVM, `qemu:///session`), 2 vCPU, 2 GiB |
| distribúcia | Debian GNU/Linux 12 (bookworm) |
| jadro hosťa | `6.1.0-42-cloud-amd64` |
| `/proc/version` | `Linux version 6.1.0-42-cloud-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30)` |
| odobraté | 2026-09-18, `kallsyms.txt` a `btf.raw` o 16:34, `btf.txt` o 16:35 (miestny čas, +02:00) |
| kanál | `ssh -o BatchMode=yes root@192.168.122.100` (v hosťovi `kernel.kptr_restrict = 0`) |
| výpis BTF urobený na | hostiteľovi (Fedora 43, jadro `7.1.13-100.fc43.x86_64`), `bpftool v7.6.0` |

Príkazy, ktorými sa profil získava:

```
ssh -o BatchMode=yes root@192.168.122.100 cat /proc/kallsyms          > kallsyms.txt
ssh -o BatchMode=yes root@192.168.122.100 cat /sys/kernel/btf/vmlinux > btf.raw
bpftool btf dump file btf.raw format raw                              > btf.txt
```

Samotný odber o 16:34 urobil skorší krok tejto práce a jeho príkazový riadok
nebol zapísaný. Tieto tri príkazy sú overené spätne: o 17:37 zopakované nad tým
istým hosťom dali bajt po bajte rovnaké `btf.raw` aj `btf.txt` a rovnakú množinu
symbolov vmlinux (podrobne v časti „Overenie“ nižšie). Preto sa uvádzajú ako
príkazy, ktorými sa tento profil reprodukuje.

Výpis BTF sa robí **na hostiteľovi**, nie v hosťovi: Debian cloud image `bpftool`
nemá a do hosťa sa kvôli profilu nič neinštaluje. Z hosťa sa berie iba obsah
dvoch súborov.

Tieto tri príkazy sú zabalené v `scripts/get_profile.sh` (ten vie okrem `ssh`
použiť aj `qemu-guest-agent`, keď v hosťovi nie je SSH).

## Súbory

| súbor | veľkosť | obsah |
|---|---|---|
| `kallsyms.txt` | 4 231 263 B, 98 713 riadkov | kópia `/proc/kallsyms` hosťa – adresy symbolov |
| `btf.raw` | 4 104 445 B | kópia `/sys/kernel/btf/vmlinux` hosťa – binárne BTF |
| `btf.txt` | 9 049 370 B, 223 941 riadkov | výpis BTF (`bpftool ... format raw`), z neho sa čítajú offsety polí |

SHA-256:

```
2dd95254496d2adedfb44f31048e0cf711cc9a98ca6088febd78d40b8dac5847  kallsyms.txt
7d68818a28c8089b929918b10d7cc2da82b7ee169330d97d44dbd9a199f77ac3  btf.raw
5d296517137d1435f7084655798ee67d30b642cb62f532376249d3d8698c92c8  btf.txt
```

`btf.txt` je odvodený súbor – dá sa kedykoľvek vyrobiť z `btf.raw` jedným
príkazom. V repe je preto, aby sa parser dal spustiť aj tam, kde `bpftool` nie je.
Ak by 8,6 MiB v histórii repozitára prekážalo, `btf.txt` je jediný z týchto troch
súborov, ktorý sa dá vypustiť bez straty informácie; `btf.raw` a `kallsyms.txt`
vypustiť nemožno, tie sa už nedajú znova získať inak než z hosťa (a po reštarte
hosťa by vyšli iné, viď nižšie).

Koreňový `.gitignore` vylučuje `*.raw`, čo by ticho vynechalo aj `btf.raw`.
Preto je v `profiles/.gitignore` výnimka `!btf.raw`.

## Kľúčové symboly, ktoré parser číta

Adresy sú z `kallsyms.txt` v tomto adresári.

| symbol | adresa | na čo ju parser potrebuje |
|---|---|---|
| `linux_banner` | `0xffffffff9711f560` | kotva na určenie posunu obrazu jadra: reťazec sa nájde skenovaním snímky a z rozdielu voči tejto adrese vyjde posun (KASLR) |
| `init_task` | `0xffffffff97a1aa40` | začiatok zoznamu procesov (`init_task.tasks`) a kontrola posunu (`comm == "swapper/0"`) |
| `modules` | `0xffffffff97b273a0` | hlavička zoznamu načítaných modulov |
| `page_offset_base` | `0xffffffff97395ce0` | odtiaľ sa **z pamäte** prečíta začiatok priameho mapovania (pri KASLR je iný pri každom štarte) |
| `init_top_pgt` | `0xffffffff97a10000` | koreň tabuliek stránok jadra – nutný pre oblasť modulov (`0xffffffffc0000000+`), ktorá lineárne mapovaná nie je |
| `socket_file_ops` | `0xffffffff970f6920` | deskriptor je socket vtedy, keď `file->f_op` ukazuje sem |
| `tcp_prot` | `0xffffffff97bed8a0` | protokol socketu podľa `skc_prot`, nie podľa heuristiky |
| `udp_prot` | `0xffffffff97bee060` | to isté pre UDP |
| `tcpv6_prot` | `0xffffffff97bf4a20` | to isté pre TCP nad IPv6 (bez toho sa protokol IPv6 socketov reportuje ako „?“) |
| `udpv6_prot` | `0xffffffff97bf3ec0` | to isté pre UDP nad IPv6 |
| `_stext` | `0xffffffff96000000` | dolná hranica textu jadra pre kontrolu `sys_call_table` |
| `_etext` | `0xffffffff96e01ef2` | horná hranica textu jadra |
| `sys_call_table` | `0xffffffff97000360` | tabuľka, ktorej integrita sa kontroluje (handler mimo `[_stext, _etext)`) |

Z `btf.txt` sa čítajú offsety polí. Pre toto jadro napríklad
`task_struct.tasks = 2192`, `task_struct.comm = 2976`, `task_struct.pid = 2416`,
`module.list = 8`, `module.name = 24` (overené behom parsera, viď nižšie).
Offsety nie sú v kóde zadrátované – berú sa z BTF toho jadra, ktoré v hosťovi beží.

## Poctivo o tom, čo tento adresár znamená

Profil je **jednorazová vstupná závislosť získaná z hosťa** – presne ako profil
pri LibVMI alebo pri Volatility. Nejde teda o rekonštrukciu „bez akejkoľvek
znalosti hosťa“: adresy aj offsety pochádzajú z bežiaceho hosťa a boli odobraté
raz, mimo behu zberu. Rozsah tejto závislosti je ale ohraničený:

- profil sa berie **raz na verziu jadra**, nie pri každej snímke;
- samotný zber snímok (`vmicollect`) ani parsovanie do hosťa nesiahajú;
- v hosťovi nemá bežať žiadny bezpečnostný agent – `ssh` aj `qemu-guest-agent`
  sa používajú iba na odobratie profilu a na pozemnú pravdu pri validácii,
  a to je v práci priznané.

**Výhrada k času odberu tohto profilu.** Keď sa profil o 16:34 bral, v hosťovi
ešte bežal bezpečnostný agent staršieho projektu `hypTcn002`
(`hyptcn-guest-agent.service`, proces `hyptcn_guest_ag`, pid 376); zastavený bol
až o 15:29:20Z, teda takmer hodinu po odbere. Časová os a doklad zo žurnálu hosťa
sú v `docs/MERANIA.md`. Na obsah profilu to nemá vplyv, čo je overené opakovaným
odberom **po** zastavení agenta (2026-09-18, 16:33Z a 16:42Z):

```sh
ssh -o BatchMode=yes root@192.168.122.100 cat /sys/kernel/btf/vmlinux > btf_now.raw
cmp profiles/debian12-6.1.0-42-cloud-amd64/btf.raw btf_now.raw   # bez rozdielu, rc=0
# sha256 oboch: 7d68818a28c8089b929918b10d7cc2da82b7ee169330d97d44dbd9a199f77ac3

grep -vc ']$' profiles/debian12-6.1.0-42-cloud-amd64/kallsyms.txt   # 87143
grep -vc ']$' kallsyms_now.txt                                      # 87143
```

`btf.raw` je teda bajt po bajte zhodný (a `btf.txt` je z neho odvodený jedným
príkazom `bpftool`), `kallsyms.txt` má rovnakú množinu symbolov vmlinux
a všetkých 13 kľúčových symbolov z tabuľky vyššie má rovnaké adresy. Menia sa
iba dynamické symboly modulov a JIT-ovaných BPF programov, z ktorých parser
nečíta nič.

## Čo sa stane po reštarte hosťa

- **Reštart toho istého jadra.** KASLR zvolí iný posun, takže absolútne adresy
  v `kallsyms.txt` už nebudú sedieť s pamäťou. Parser posun dopočítava z polohy
  `linux_banner` nájdenej v snímke a používa iba rozdiely medzi symbolmi, ktoré
  sa v rámci rovnakého obrazu jadra nemenia. Toto je vlastnosť kódu, nie zmeraný
  výsledok – po reštarte treba validáciu zopakovať a výsledok zapísať.
- **Reštart do iného jadra** (v hosťovi je v `/lib/modules` už aj `6.1.0-43`).
  Profil prestane sedieť úplne: iné adresy aj iné offsety polí. Parser v lepšom
  prípade nenájde banner a skončí, v horšom prečíta nezmysly. Vtedy treba
  spustiť `scripts/get_profile.sh <cieľ>`, ktorý vyrobí nový adresár
  `profiles/debian12-<nová verzia>/`, a **zopakovať celú validáciu** – čísla
  namerané so starým profilom pre nové jadro neplatia.

Preto je hosť na čas meraní zmrazený (`unattended-upgrades` zamaskované, jadro
pinnuté) a verzia jadra sa zapisuje do každého záznamu merania.

## Overenie tohto profilu (2026-09-18)

1. **Reprodukovateľnosť odberu.** `scripts/get_profile.sh` spustený o 17:37
   (`ssh`) a 17:38 (`qemu-guest-agent`) nad tým istým hosťom dal:
   - `btf.raw` a `btf.txt` **bajt po bajte zhodné** so súbormi v tomto adresári
     (`cmp` bez rozdielu);
   - `kallsyms.txt` s **identickou množinou symbolov vmlinux** (87 143 riadkov
     bez prípony `[modul]`, `diff` prázdny) a s identickými adresami všetkých
     13 kľúčových symbolov z tabuľky vyššie;
   - navyše riadky symbolov diagnostických modulov a rozdiel v symboloch
     JIT-ovaných BPF programov. Rozpis nižšie **nie je** z tohto behu, ale
     z opakovaného odberu o 16:33Z (príkaz za týmto zoznamom): navyše 128
     riadkov symbolov **štyroch** diagnostických modulov (`inet_diag` 80,
     `udp_diag` 19, `tcp_diag` 17, `raw_diag` 12) a rozdiel v 40 riadkoch so
     symbolmi JIT-ovaných BPF programov (29 zaniklo, 11 pribudlo; sú to
     programy systemd – `sd_fw_ingress`, `sd_fw_egress`, `sd_devices`).
     Symboly modulov a JIT-ovaných BPF programov sú dynamické; parser z nich
     nečíta nič.
   - Oba prenosy (`ssh` aj `qemu-guest-agent`) dali navzájom bajt po bajte
     zhodné súbory.

   Skoršia verzia tohto súboru tu uvádzala 116 riadkov a menovala iba tri
   diagnostické moduly – vynechala `raw_diag` (12 riadkov), a tvrdila, že hosť
   dnes hlási 50 modulov. Obidve čísla sú opravené podľa behu z 2026-09-18,
   16:33Z:

```sh
ssh -o BatchMode=yes root@192.168.122.100 cat /proc/kallsyms > kallsyms_now.txt
diff <(sort profiles/debian12-6.1.0-42-cloud-amd64/kallsyms.txt) <(sort kallsyms_now.txt) \
  | grep '^>' | grep -oP '\[[a-z0-9_]+\]$' | sort | uniq -c | sort -rn
#      80 [inet_diag]
#      19 [udp_diag]
#      17 [tcp_diag]
#      12 [raw_diag]
#      11 [bpf]

ssh -o BatchMode=yes root@192.168.122.100 'lsmod | tail -n +2 | wc -l'
# 51
ssh -o BatchMode=yes root@192.168.122.100 'lsmod | grep -c diag'
# 4
```

   Hosť teda hlási **51** modulov, nie 50: profil pozná 47 a k nim pribudli
   štyri diagnostické moduly (47 + 4 = 51). Do hosťa ich zaviedol až príkaz
   `ss`, ktorým sa brala pozemná pravda – v `kallsyms.txt` v tomto adresári
   (odber o 16:34 miestneho času) nie je ani jeden ich symbol. Tých istých 51
   modulov je uložených aj v repe, v pozemnej pravde validačnej relácie:
   `data/sessions/20260918T154914Z_validate/lsmod_before.txt` (51 riadkov,
   z toho 4 diagnostické).
2. **Použiteľnosť profilu z repa.** Prototyp parsera spustený s **týmito**
   súbormi nad snímkou `/var/tmp/vmic-val/hyptcn-guest_000000_20260918T143954722Z.vmicd`:
   posun obrazu jadra `-0x200000`, `page_offset_base = 0xffff99c940000000`,
   82 procesov, 47 modulov, krížová kontrola prekladu adries
   (lineárny výpočet vs. prechod tabuliek stránok) `linux_banner`
   `0x16f1f560 = 0x16f1f560` a `init_task` `0x1781aa40 = 0x1781aa40`.
   Celé spustenie trvalo 0,6 s.

Porovnanie zoznamu procesov a modulov s pozemnou pravdou z hosťa sem nepatrí –
to je predmet validačného kroku a jeho výsledok je v `data/results/`.
