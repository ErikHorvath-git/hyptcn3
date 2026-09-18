# Log meraní

Tento súbor je **append-only**. Platia preň tri pravidlá:

1. **Záznam sa nikdy neprepisuje ani nemaže.** Ak sa neskôr ukáže, že číslo je nesprávne
   alebo neplatné, pridá sa **nový záznam s retrakciou**, ktorý pomenuje, ktorý záznam
   ruší a prečo. Pôvodný záznam zostáva v súbore aj s nesprávnym číslom.
2. **Každý záznam má dátum, príkaz a odkaz do `data/results/`.** Číslo bez uloženého
   artefaktu v `data/results/` sa smie zapísať len s výslovnou poznámkou, že artefakt
   neexistuje, a s uvedením, odkiaľ číslo pochádza.
3. **Každý záznam hovorí, ktorá binárka meranie vyrobila** (commit repa, prípadne sha256
   binárky, ak nebola zostavená z repa).

Čo v tomto súbore nemá čo hľadať: čísla z projektu hypTcn002 ako výsledok tejto práce
(ich zoznam je v `HONESTY.md`, tu sa zámerne neopakujú, aby ich kontrola nenašla v tomto
súbore), ilustračné čísla z README `vmicollect` a odhady bez behu.

---

## 2026-09-18 — prvý beh zberača `vmicollect` nad bežiacou doménou

- **Dáta:** `data/results/2026-09-18_prvy_beh/` (sidecary, `env.json`, `summary.json`,
  `snapshots.json`, pozemná pravda k procesom, `SHA256SUMS`)
- **Commit repa v čase importu:** `178ce4fd83e7c504e02fb06a5756de3e79255007`
- **Binárka:** `vmic-exp/build/vmicollect` zo scratchpadu,
  sha256 `c53ce6eec7670286ff00bc0b2005fe23779c42ab38284bfb48e36a2f7cb45583`,
  BPF objekt sha256 `ff0ca425ab743dd5ea3a0e3daf174e7a9dd2fa9039765602d0a5c87dba16b58b`
- **Príkazy:** presný tvar príkazového riadka sa v čase merania nezaznamenal. Zo sidecarov
  je rekonštruovateľná konfigurácia: `once`/`run` nad doménou `hyptcn-guest`, backend
  `ebpf/kvm`, `chunk_size` 1 MiB, writer `raw` resp. `delta`, perióda 5 s, výstupné
  adresáre `/var/tmp/vmic-{test,delta,nohash,val}`. Toto je nedostatok tohto behu; krok
  K06 má príkaz uložiť do výsledkového JSONu.

### Prostredie

Hostiteľ Fedora 43, jadro 7.1.13-100.fc43.x86_64, 16 CPU, 15,2 GiB RAM, clang 21.1.8,
libbpf 1.6.1, QEMU 10.1.5, libvirt 11.6.0. Hypervízor beží v **session** režime
(`qemu:///session`), teda proces QEMU beží pod účtom používateľa, nie pod rootom.

Hosť: libvirt doména `hyptcn-guest` (QEMU pid 1353046 — zhoduje sa s `vm.vmid` vo všetkých
sidecaroch tohto behu), Debian 12 (bookworm), jadro 6.1.0-42-cloud-amd64, 2 vCPU, 2 GiB
RAM, disk qcow2 nad `debian-12-base.qcow2`. Presné hodnoty a príkazy, ktorými sa zistili,
sú v `data/results/2026-09-18_prvy_beh/env.json`.

Verzia hosťovského OS bola nezávisle zistená **zo samotnej snímky** (banner
„Linux version 6.1.0-42-cloud-amd64“ na fyzickej adrese 0x825fa40), nie iba z hosťa.

### Stav pred zásahom

`vmicollect probe` nad bežiacou VM zlyhal — BPF program sa nikdy nenačítal do jadra.
Zdedený `build/vmic_kvm.bpf.o` teda nikdy nebol overený proti bežiacemu jadru.

### Štyri defekty, ktoré to blokovali (všetky opravené, commit `178ce4f`)

1. **BTF: dopredná deklarácia verzus plná štruktúra jadra.**
   `extern struct task_struct *bpf_task_from_vpid(__s32) __ksym;` bez definície typu
   vyrobí v BTF objektu `FWD 'task_struct'`, kým vmlinux BTF má `STRUCT 'task_struct'`.
   libbpf porovnáva druh typu a nezhodu odmietne:
   `extern (func ksym) 'bpf_task_from_vpid': func_proto [33] incompatible with vmlinux [45837]`.
   Oprava: prázdna (nepriehľadná) definícia štruktúry — druh aj meno sedia, obsah sa
   nikdy nečíta.
2. **Verifikátor: limit zložitosti skokov (8192) pri prehľadávaní tabuľky deskriptorov.**
   `for (i = 0; i < 1024; i++) kvm_from_fd(...)` s asi ôsmimi vetvami na iteráciu:
   `The sequence of 8193 jumps is too complex` → `-E2BIG`. Oprava: `bpf_loop()`, telo
   cyklu verifikátor overí raz.
3. **Verifikátor: limit 10^6 inštrukcií pri prechode hash tabuľky memslotov.**
   128 bucketov × reťazec do 8 uzlov × 5 čítaní:
   `BPF program is too large. Processed 1000001 insn`. Oprava: `bpf_loop()` nad bucketmi.
4. **Verifikátor: limit 10^6 inštrukcií pri záložnom kopírovaní po stránkach.**
   512 stránok × vetvenia v tele → 42 900 stavov, opäť `-E2BIG`. Oprava: `bpf_loop()`;
   `task` sa v každom kroku získava znovu (`bpf_task_from_vpid` / `bpf_task_release`),
   lebo započítaná referencia sa do callbacku preniesť nedá. Záložná cesta sa berie len
   vtedy, keď veľké kopírovanie zlyhá.

### probe (pripojenie k hypervízoru)

```
'hyptcn-guest' (pid 1353046): 10 memslotov, 2.02 GiB pamate, max GPA 0x100000000
pocet vCPU: 2
test citania: 16646144 B za 6.9 ms = 2297 MiB/s
```

Výstup `probe` sa **neuložil do súboru** — v `data/results/` k nemu artefakt nie je.
V `summary.json` je preto označený `"zdroj": "MERANIA_2026-09-18.md"`.

### once, writer `raw`, jedna plná snímka 2,02 GiB

Sidecar: `sidecars/vmic-test/hyptcn-guest_000000_20260918T143014076Z.json`

| veličina | hodnota |
|---|---|
| čítanie pamäte | 430,6 ms (4793,85 MiB/s) |
| zápis na disk | 41 774,1 ms |
| spolu | 42 204,7 ms |
| chyby čítania | 0 |
| pauza VM | 0,0 ms (`paused=false`) |
| výstup | 4,00 GiB riedky súbor, 307,12 MiB reálne na disku |

Pri perióde 5 s to znamenalo 8 zmeškaných slotov. Úzkym miestom je zápis, nie
introspekcia — príčina nižšie v časti o SHA-256.

### run, writer `delta`, perióda 5 s, 6 cyklov

Sidecary: `sidecars/vmic-delta/` (šesť súborov)

| snímka | typ | zmenené stránky | veľkosť | čítanie | cyklus spolu |
|---|---|---|---|---|---|
| #0 | plná | 70 582 / 528 417 (13,36 %) | 276,25 MiB | 766,4 ms | 3618,1 ms |
| #1 | delta | 301 (0,057 %) | 1,18 MiB | 563,6 ms | 583,4 ms |
| #2 | delta | 271 (0,051 %) | 1,06 MiB | 552,5 ms | 572,0 ms |
| #3 | delta | 278 (0,053 %) | 1,09 MiB | 547,8 ms | 566,6 ms |
| #4 | delta | 326 (0,062 %) | 1,28 MiB | 563,4 ms | 584,7 ms |
| #5 | delta | 314 (0,059 %) | 1,23 MiB | 562,0 ms | 582,7 ms |

- 0 chýb čítania, 0 zmeškaných slotov, najväčšie meškanie 0,000 s.
- Cyklus prírastkovej snímky 0,567–0,585 s (n = 5) pri perióde 5 s.
- Nečinná VM zmení medzi snímkami rádovo 0,05–0,06 % stránok.

Počet zmeškaných slotov a meškanie **nie sú v sidecari** — schéma `vmicollect/1` také pole
nemá. Sú prepísané zo stdout behu, ktorý sa neuložil.

### Plná snímka naprieč všetkými behmi dňa

Zo štyroch snímok s `output.full=true` (`summary.json` → `values.plna_snimka`):

| veličina | min | medián | max | n |
|---|---|---|---|---|
| `capture_ms` | 430,6 | 660,4 | 947,4 | 4 |
| `read_mib_s` | 2178,6 | 3208,5 | 4793,9 | 4 |

Vo všetkých štyroch: `read_errors=0`, `paused=false`, `pause_ms=0`. V texte práce sa uvádza
tento rozsah, nie jediné najnižšie číslo. Rozptyl je veľký a jeho príčina nie je zmeraná —
snímky sa líšia writerom (`raw` / `delta`), nastavením hashu aj momentálnym stavom stroja.

### Výkonová chyba v raw writeri a jej odstránenie

Prvá plná snímka trvala 42,2 s, z toho „zápis“ 41,8 s pri 307 MiB dát na disku (asi
7 MiB/s). Príčina nie je zápis: `finish()` počíta SHA-256 nad **celým súborom**, teda nad
4,00 GiB vrátane dier, ktoré sa nikdy nezapísali.

Overenie jedným parametrom (`output.hash=none`), rovnaká VM, rovnaký zberač:

| režim | čítanie | zápis | cyklus spolu | zmeškané sloty |
|---|---|---|---|---|
| `hash=sha256` (východzie) | 430,6 ms | 41 774,1 ms | 42 204,7 ms | 8 |
| `hash=none` | 554,3 ms | 194,2 ms | 748,5 ms | 0 |

Pomer celkových časov 56,4. Dôsledok pre návrh: kontrolný súčet sa má počítať nad
zapísanými stránkami priebežne, nie nad riedkym súborom po dokončení. Delta writer tento
problém nemá (hashuje iba svoje záznamy) — preto 3,6 s namiesto 42 s.

Poznámka k tejto dvojici: nie je to čistý A/B. Obe snímky vznikli v iných časoch
(14:30 a 14:43) a líši sa aj množstvo dát reálne zapísaných na disk (307,1 MiB verzus
493,1 MiB). Záver o SHA-256 nad riedkym súborom to nemení, ale za opakované meranie
s n > 1 to nejde vydávať — to je úloha kroku K23.

### Rekonštrukcia objektov hosťa (semantic gap)

Parser `vmi_parse.py` (537 riadkov, v čase merania v scratchpade, nie v repe) číta priamo
natívny formát zberača `.vmicd`, takže sa nič nerozbaľuje do 4 GiB raw obrazu. Index
70 598 stránok sa postaví za 0,1 s.

Vstup: plná delta snímka `sidecars/vmic-val/hyptcn-guest_000000_20260918T143954722Z.json`.

**Profil jadra hosťa** bol získaný RAZ, mimo behu zberu (rovnako ako to robí LibVMI so
svojím profilom): `/proc/kallsyms` z hosťa pre adresy symbolov (`linux_banner`,
`init_task`, `modules`, `page_offset_base`, `init_top_pgt`) a `/sys/kernel/btf/vmlinux`
z hosťa pre offsety polí (`task_struct.tasks` 2192, `.comm` 2976, `.pid` 2416,
`module.list` 8, `.name` 24). Offsety nie sú v kóde zadrátované. Toto je vstupná závislosť
na hosťovi a v práci sa priznáva; nejde o prácu „bez akejkoľvek znalosti hosťa“.

**Preklad adries.** Dve lineárne vetvy jadra x86_64 (obraz jadra `PA = VA -
0xffffffff80000000 + posun`, priamy mapping `PA = VA - page_offset_base`) plus plný
štvorúrovňový prechod `init_top_pgt` pre oblasť modulov (`0xffffffffc0000000+`), ktorá
lineárna nie je. Posun sa nehádal: skenovaním sa našlo päť výskytov banneru a vybral sa
ten, pri ktorom `init_task.comm == "swapper/0"`. Výsledok: posun `-0x200000`,
`page_offset_base = 0xffff99c940000000` (KASLR).

Krížová kontrola prekladu (lineárny výpočet verzus prechod tabuliek):
`linux_banner` 0x16f1f560 = 0x16f1f560; `init_task` 0x1781aa40 = 0x1781aa40.

**Procesy** (`init_task.tasks`). Protokol: `ps -eo pid,comm` v hosťovi pred snímkou,
snímka, `ps` po snímke; porovnáva sa stabilná množina (procesy prítomné v oboch behoch
`ps`). Pozemná pravda je uložená: `ground_truth/ps_before.txt`, `ps_after.txt`.

| veličina | hodnota |
|---|---|
| `ps` pred | 84 procesov |
| `ps` po | 82 procesov |
| stabilná množina | 80 |
| rekonštruovaných zo snímky | 82 |
| nájdených zo stabilnej množiny | 80 / 80 |
| chýbajúce | 0 |
| falošné (v snímke, v žiadnom `ps`) | 0 |
| nezhoda mien | 0 |

**Moduly** (`modules`): rekonštruovaných 47, `lsmod` v hosťovi v čase snímky hlásil 47,
zoznam sedí vrátane poradia zavádzania. Výstup `lsmod` sa **neuložil**, takže táto zhoda
sa z repa dnes overiť nedá.

**Sokety**: pre každý proces sa prejde tabuľka deskriptorov; deskriptor je soket vtedy, keď
`file->f_op == socket_file_ops` (symbol hosťa, nie heuristika), protokol sa určí
porovnaním `skc_prot` s `tcp_prot` / `udp_prot`. Polia `skc_daddr`, `skc_rcv_saddr`,
`skc_dport`, `skc_num` sú v jadre 6.1 vnorené v anonymných unionoch (BTF ich uvádza ako
`'(anon)'`), extraktor offsetov do nich musí zostúpiť; bez toho chýbajú úplne.
Rekonštruovaných 13 socketov, z toho všetkých 10 počúvajúcich sedí s `ss -tulpn`
(sshd :22, systemd-resolved :53 a :5355, IPv4 aj IPv6); navyše je vidieť nadviazané UDP
spojenie systemd-timesyncd 192.168.122.100:57436 → 192.168.122.1:53, ktoré `ss -tulpn`
nezobrazuje. Výstup `ss` sa **neuložil**. Priznaný limit: IPv6 adresy sa zatiaľ čítajú ako
IPv4 polia a protokol IPv6 socketov sa neurčí (chýba `skc_v6_daddr` a
`tcpv6_prot`/`udpv6_prot`) — v tabuľke sa zobrazia ako „?“. Rieši krok K10.

### Čo z tohto behu vyplýva a čo ešte nie je dokázané

- **Dokázané:** pripojenie k hypervízoru cez eBPF, periodický zber, delta zber, žiadne
  zastavenie VM (`paused=false`, `pause_ms=0` vo všetkých deviatich sidecaroch), nulové
  chyby čítania, rýchlosť čítania, rekonštrukcia procesov proti uloženej pozemnej pravde.
- **Nedokázané:** vplyv zberu na výkon vnútri hosťa (chýba benchmark v VM so zberom a bez
  neho — krok K22), príznakový priestor, TCN. Rekonštrukcia modulov a socketov je
  zmeraná, ale jej pozemná pravda sa neuložila, takže sa musí zopakovať (K09).
- **Otvorené:** `libbpf: Error in bpf_create_map_xattr(pages): -EINVAL. Retrying without
  BTF.` — nefatálne (mapa sa vytvorí bez BTF), príčina nezistená.

### Poctivá poznámka k platnosti tohto záznamu

Tieto merania vznikli **binárkou zo scratchpadu** ešte pred tým, než sa opravy BPF programu
dostali do repa. Commit `178ce4f` obsahuje ten istý opravený zdrojový kód, ale zostavený
artefakt repa sa proti bežiacemu jadru v tomto behu neoveroval.

**Krok K06 má merania zopakovať binárkou zostavenou z repa.** K06 je čiastočne urobený:
`probe` z repa podľa hlásenia orchestrátora dal test čítania 2401 MiB/s. Toto číslo
**nemá uložený artefakt** v `data/results/`, nie je overené v rámci tohto záznamu a do
textu práce sa citovať nesmie, kým K06 neuloží `probe_*.json`.

### Kontroly spustené pri importe (2026-09-18, krok K04)

Nie sú to nové merania zberača, ale overenie toho, čo sa do repa importovalo:

- `sha256sum` každej snímky verzus `output.sha256` v jej sidecari: 8 z 9 sedí, deviata
  (`vmic-nohash`) sidecar sha256 nemá, lebo bežala s `output.hash=none`. Výsledok je
  v `snapshots.json`.
- Prepočet stabilnej množiny z uloženej pozemnej pravdy: prienik podľa PID je 80, teda
  sedí s číslom vyššie. Prienik podľa dvojice (PID, meno) je 77 — trom vláknam `kworker`
  sa medzi oboma behmi `ps` zmenil názov podľa práve vykonávanej práce (napríklad
  `kworker/1:0-events` → `kworker/1:0-mm_percpu_wq`). Stabilná množina je teda definovaná
  cez PID a pri porovnaní mien s tým treba počítať.
- `sha256sum -c SHA256SUMS` nad celým adresárom `data/results/2026-09-18_prvy_beh/`: OK.

---

## 2026-09-18 — kontroly podozrivých vzorcov (K11) a validačný príkaz (K09)

- **Dáta:** `data/results/checks_20260918_{val,delta,session}.json`,
  `data/results/validate_20260918_vmic-val.json`,
  `data/results/validate_20260918T154914Z_{ssbefore,ssafter}.json`,
  úplný výpis behov `data/results/k11_beh_20260918.log`
- **Commit repa v čase merania:** `178ce4fd83e7c504e02fb06a5756de3e79255007` (pracovný
  strom obsahoval navyše `guestparse/checks.py`, `guestparse/validate.py`,
  `guestparse/tests/test_checks.py`, `guestparse/tests/test_injection.py` a úpravu
  `guestparse/cli.py` — teda kód tohto záznamu)
- **Čím sa meralo:** `python3 -m guestparse` z repa, Python 3.14.7, pytest 8.3.5,
  bez roota. Zberač `vmicollect` v tomto kroku nebežal; snímky sú tie, ktoré už na disku
  boli.
- **Podrobný rozbor:** `docs/kontroly.md`

### `guestparse checks` nad tromi reálnymi snímkami

| snímka | `sys_call_table` | procesy `tasks` vs. strom potomkov | moduly `modules` vs. `module_kset` | nálezy |
|---|---|---|---|---|
| `/var/tmp/vmic-val` | 451 položiek | 82 vs. 82 | 47 vs. 47 (zo 105 kobjektov) | 0 |
| `/var/tmp/vmic-delta` (1 plná + 5 delt) | 451 položiek | 76 vs. 76 | 47 vs. 47 (zo 105 kobjektov) | 0 |
| `data/sessions/20260918T154914Z_validate/snap` | 451 položiek | 80 vs. 80 | 51 vs. 51 (zo 109 kobjektov) | 0 |

`summary.inconclusive` bolo vo všetkých troch behoch prázdne, teda všetky tri kontroly
sa uzavreli a nula je nula, nie „prechod sa roztrhol".

### Injekčný test (pozitívny prípad)

`pytest guestparse/tests/test_injection.py` — 3 testy prešli. **Ide o prepis 8 bajtov
v kópii snímkového súboru, nie o skutočný rootkit v hosťovi**; do hosťa sa vlastný modul
načítať ani nedá, nemá `gcc` ani hlavičky jadra. Nedotknutá kópia reálnej snímky: 0
nálezov. Kópia s položkou 59 (`__NR_execve`) prepísanou na `0xffffffffc0001000`
(oblasť modulov): presne 1 nález s `index=59`, `in_module_area=true`, ostatné dve
kontroly naďalej 0.

### `guestparse validate` — snímka `/var/tmp/vmic-val`

Pozemná pravda: pár `ps` pred/po zo scratchpadu (`lsmod` ani `ss` k tejto snímke uložené
nie sú, takže sa neporovnávali a JSON to hovorí explicitne).

`ps` pred 84, `ps` po 82, stabilná množina 80 (z toho 77 s doslovne rovnakým menom),
zo snímky 82 procesov → **nájdených 80/80 = 100,0 %**, chýbajúce 0, falošné 0,
nezhoda mien 0. Pravidlá zhody mien: `exact` 64, `worker` 13, `truncated` 3.
`checks.syscall_hooks` 0.

Toto číslo je zhodné s číslom zo záznamu o prvom behu, ale po prvý raz je vyrobené
príkazom z repa a uložené ako artefakt.

### `guestparse validate` — relácia `20260918T154914Z_validate` (úplná pozemná pravda)

Uvádzajú sa obidva behy `ss`/`lsmod`, lebo sa medzi nimi výsledok soketov líši.

| veličina | proti výpisom **pred** | proti výpisom **po** |
|---|---|---|
| procesy: stabilné / nájdené | 80 / **80 (100,0 %)** | 80 / 80 |
| procesy: chýbajúce / falošné / nezhoda mien | 0 / 0 / 0 | 0 / 0 / 0 |
| moduly: sediace / chýbajúce / navyše | **51 / 0 / 0** | 51 / 0 / 0 |
| sokety: sediace / chýbajúce / navyše | **11 / 1 / 1** | 10 / 2 / 2 |
| `checks.syscall_hooks` | 0 | 0 |

Nezhody pri soketoch (rozobrané v `docs/kontroly.md`): chýbajúce sú SSH spojenia, cez
ktoré sa spúšťala samotná pozemná pravda (každý príkaz si otvára vlastné spojenie, v čase
snímky žiadne nebežalo — snímka obsahuje iba počúvajúci `sshd` pid 388); „navyše" je
nenaviazaný UDP soket `systemd-networkd`, ktorý `ss` nevypisuje, lebo číta
`/proc/net/udp`. Proti výpisom „po" pribúda ešte `systemd-timesyncd`, ktorému sa medzi
snímkou a druhým výpisom zmenil zdrojový port (53027 → 57006). RAW soket (ICMPv6) sa do
„navyše" nezapočítava, `ss -tuanp` RAW sokety nevypisuje; v JSONe je uvedený samostatne.

### Čo tento záznam NEDOKAZUJE

Detekciu skutočného rootkitu (overený je jeden syntetický zápis do kópie snímky), hook
prepísaný na inú adresu **vnútri** `[_stext, _etext)` (rozsahová kontrola ho z princípu
nevidí), a skrytie procesu či modulu, ktoré odpojí uzol z oboch porovnávaných štruktúr
naraz.

---

## 2026-09-18 — doplnenia a retrakcie k prvému behu, prvé merania binárkou z repa (K06)

Tento záznam **nemení** predošlé záznamy — podľa pravidla P10 v `HONESTY.md` sa meranie
nikdy neprepisuje. Dopĺňa k nim tri veci, ktoré v nich chýbali alebo boli nesprávne,
a pridáva dva behy zberača binárkou zostavenou z tohto repozitára.

- **Dáta:** `data/results/probe_20260918T154840Z.json`,
  `data/results/run_20260918T154742Z.json`
- **Commit repa v čase merania:** `178ce4fd83e7c504e02fb06a5756de3e79255007`
  (pracovný strom bol `dirty`, pole `commit_dirty` v oboch JSONoch)
- **Binárka:** `vmicollect/build/vmicollect` **z tohto repa**, `vmicollect 1.0.0`,
  sha256 `5cdb296364b5803355e8d7b534e7e0e2ce6acd9484032dc3b7a45270a0431738`
- **Príkazy:** uložené doslovne v poli `command` oboch JSONov; spúšťané cez
  `scripts/root_run.sh`

### 1. RETRAKCIA: „probe z repa dal 2401 MiB/s a nemá uložený artefakt“

Záznam „2026-09-18 — prvý beh zberača `vmicollect` nad bežiacou doménou“, časť „Poctivá
poznámka k platnosti tohto záznamu“, uvádza, že `probe` z repa podľa hlásenia
orchestrátora dal test čítania 2401 MiB/s a že toto číslo nemá uložený artefakt
v `data/results/`. Obidve tvrdenia sú nesprávne:

- artefakt **existuje**: `data/results/probe_20260918T154840Z.json`, vznikol
  2026-09-18 o 15:48:41Z — teda skôr, než bola tá poznámka napísaná;
- uložená hodnota je **2394 MiB/s** {{res:probe_20260918T154840Z.json:values.read_test.mib_s}}.

RETRAKCIA: číslo 2401 MiB/s nepochádza zo žiadneho uloženého behu, nedá sa dohľadať
a v texte práce sa nesmie použiť. Platné číslo je 2394 MiB/s z artefaktu vyššie.

### 2. `probe` binárkou z repa (15:48:41Z)

Príkaz: `vmicollect probe -v -o vm.domain=hyptcn-guest`, návratový kód 0 {{res:probe_20260918T154840Z.json:exit_code}}.

| veličina | hodnota |
|---|---|
| memsloty | 10 {{res:probe_20260918T154840Z.json:values.memslots}} |
| RAM domény | 2,02 GiB (`values.ram_human`, presne `values.ram_bytes`) |
| vCPU | 2 {{res:probe_20260918T154840Z.json:values.vcpus}} |
| max. fyzická adresa | `0x100000000` (`values.max_paddr`) |
| test čítania | 16 646 144 B za 6,6 ms {{res:probe_20260918T154840Z.json:values.read_test.ms}} = 2394 MiB/s {{res:probe_20260918T154840Z.json:values.read_test.mib_s}} |

Toto je prvé číslo rýchlosti čítania, ktoré vyrobila binárka z repa a ktoré má uložený
artefakt. Oproti prvému behu (2297 MiB/s, výstup sa neuložil) je to iný beh, iná binárka
a iný okamih — nie je to opakované meranie tej istej veličiny s n = 2.

### 3. `run`, writer `delta`, perióda 5 s, 3 cykly (15:47:42–15:47:54Z)

Príkaz je v poli `command`; podstatné parametre: `output.writer=delta`,
`output.hash=sha256`, `schedule.interval_s=5`, `schedule.max_cycles=3`.

| veličina | hodnota |
|---|---|
| perióda | 5 s {{res:run_20260918T154742Z.json:params.interval_s}} |
| dokončené cykly | 3 {{res:run_20260918T154742Z.json:summary.cycles_done}} |
| zlyhané cykly | 0 {{res:run_20260918T154742Z.json:summary.cycles_failed}} |
| preskočené cykly | 0 {{res:run_20260918T154742Z.json:summary.cycles_skipped}} |
| najväčšie meškanie | 0,000 s {{res:run_20260918T154742Z.json:summary.worst_lateness_s}} |
| návratový kód | 0 {{res:run_20260918T154742Z.json:exit_code}} |

Sidecary jednotlivých snímok ležia v `data/raw/20260918T154742Z_run/`, ktorý koreňový
`.gitignore` z repozitára vylučuje (surové snímky majú spolu 486,79 MiB). Riadky s časmi
cyklov sú preto zachované doslovne v poli `stderr` súboru `run_20260918T154742Z.json`,
ktorý v repe je — odtiaľ je aj táto tabuľka:

| snímka | typ | zmenené stránky | veľkosť | čítanie | cyklus spolu |
|---|---|---|---|---|---|
| #0 | plná | 123 841 / 528 417 (23,44 %) | 484,70 MiB | 969,7 ms | 2592,8 ms |
| #1 | delta | 324 (0,06 %) | 1,27 MiB | 557,1 ms | 565,2 ms |
| #2 | delta | 210 (0,04 %) | 844,00 KiB | 554,5 ms | 564,8 ms |

0 chýb čítania, 0 zmeškaných slotov, `pauza 0.0 ms` vo všetkých troch cykloch.

**Zmena pamäte VM medzi snímkami naprieč oboma behmi.** Prvý záznam uvádzal 271–326
stránok (0,05–0,06 %) z piatich delta snímok. Delta snímky binárkou z repa idú nižšie —
210 stránok je 0,04 %, teda pod uvedeným rozsahom:

| beh | delta snímok | zmenené stránky z 528 417 | podiel |
|---|---|---|---|
| 14:31Z, binárka zo scratchpadu | 5 | 271–326 | 0,051–0,062 % |
| 15:47Z, binárka z repa | 2 | 210–324 | 0,040–0,061 % |
| spolu | n = 7 | 210–326 | 0,040–0,062 % |

Tie dve množiny nie sú z rovnakých podmienok: počas prvého behu bežal v hosťovi agent
staršieho projektu (bod 4 nižšie), takže „nečinná VM“ platí len pre druhý riadok.

### 4. ZAMLČANÉ OBMEDZENIE: počas prvého behu bežal v hosťovi agent staršieho projektu

Žiadny doterajší dokument to nespomína, hoci je to priamo v uloženej pozemnej pravde
v repe:

```
$ grep -n hyptcn data/results/2026-09-18_prvy_beh/ground_truth/ps_before.txt
68:376 hyptcn_guest_ag
$ grep -n hyptcn data/results/2026-09-18_prvy_beh/ground_truth/ps_after.txt
66:376 hyptcn_guest_ag
```

Ide o `hyptcn_guest_ag`, pid 376, jednotka `hyptcn-guest-agent.service` („hypTcn guest
eBPF agent — forwards syscall events to host via virtio“), teda **bezpečnostný agent
v hosťovi zo staršieho projektu `hypTcn002`**. Presné časy zo žurnálu hosťa:

```
$ ssh -o BatchMode=yes root@192.168.122.100 \
    journalctl -u hyptcn-guest-agent -o short-iso --no-pager
2026-09-18T14:24:10+0000 Started hyptcn-guest-agent.service - hypTcn guest eBPF agent.
2026-09-18T15:27:49+0000 Stopping hyptcn-guest-agent.service...
2026-09-18T15:29:19+0000 hyptcn-guest-agent.service: State 'stop-sigterm' timed out. Killing.
2026-09-18T15:29:19+0000 Killing process 376 (hyptcn_guest_ag) with signal SIGKILL.
2026-09-18T15:29:20+0000 Main process exited, code=killed, status=9/KILL
2026-09-18T15:29:20+0000 Stopped hyptcn-guest-agent.service.
```

Časová os (všetko UTC, 2026-09-18):

| čas | udalosť | agent v hosťovi |
|---|---|---|
| 14:24:08 | štart hosťa (`uptime -s`) | — |
| 14:24:10 | štart `hyptcn-guest-agent.service` | beží |
| 14:30:14 | raw snímka `vmic-test` (430,6 ms / 42 204,7 ms) | beží |
| 14:31:18–14:31:43 | beh `run` delta, 6 cyklov | beží |
| 14:34 | odber profilu jadra hosťa (`kallsyms`, BTF) | beží |
| 14:39:54 | snímka `vmic-val`, z ktorej parser čítal procesy a moduly | beží |
| 14:39:53 / 14:40:01 | `ps` pred/po — v oboch výpisoch je pid 376 | beží |
| 14:43:19 | raw snímka `vmic-nohash` (748,5 ms) | beží |
| 15:27:49–15:29:20 | zastavenie agenta (SIGTERM, po 90 s SIGKILL) | končí |
| 15:47:42–15:47:54 | `run` binárkou z repa | nebeží |
| 15:48:41 | `probe` binárkou z repa | nebeží |
| 15:49:14–15:49:19 | validačná relácia `20260918T154914Z_validate` | nebeží |

Stav overený 2026-09-18 po skončení agenta:

```
$ ssh -o BatchMode=yes root@192.168.122.100 'systemctl is-enabled hyptcn-guest-agent; ps -eo pid,comm | grep -c hyptcn'
disabled
0
$ grep -c hyptcn data/sessions/20260918T154914Z_validate/ps_before.txt
0
```

**Čo z toho plynie.**

- `HONESTY.md` P6 hovorí: bezpečnostný agent v hosťovi protirečí zadaniu, nepoužíva sa
  a **pred meraniami sa v hosťovi ukončí a zaznamená sa to**. Pri prvom behu sa ani jedno
  z toho neurobilo. Toto je záznam, ktorý tam mal byť od začiatku.
- Všetky hlavné čísla, ktoré dokumentácia doteraz uvádzala, pochádzajú z tohto behu:
  430,6 ms; 42 204,7 ms; 748,5 ms; 80/80 procesov; 47 modulov; 13 socketov. Vznikli
  s cudzím agentom bežiacim v hosťovi.
- Čo to kazí: proces pid 376 je súčasťou stabilnej množiny 80 procesov, takže „80/80“
  je počet **vrátane** agenta. Agent tiež mení pamäť hosťa, takže počty zmenených stránok
  medzi snímkami z tohto behu nie sú počty nečinnej VM.
- Čo to nekazí priamo: čas čítania a zápisu sa meria na hostiteľovi a je daný veľkosťou
  pamäte a writerom. Ako veľmi agent tieto časy ovplyvnil, ale zmerané nie je — rozdiel
  voči behu bez agenta sa nedá vyčísliť, lebo obidva behy sa líšia aj binárkou.
- Vplyv agenta na výkon hosťa sa nemeral vôbec a číslo overheadu z projektu `hypTcn002`
  sem nepatrí (je na čiernej listine v `HONESTY.md`).

**Platná referencia sú merania po 15:29:20Z**, teda na zmrazenom hostovi bez agenta.
Merania z prvého behu ostávajú v tomto súbore ako záznam, ale v texte práce sa uvádzajú
len s touto výhradou, alebo sa nahradia meraniami zo zmrazeného hosťa.

### 5. Nezaznamenané obmedzenie zberača: čítanie nie je celkom pasívne

`vmicollect` pri každom behu nad touto doménou vypíše dve varovania. Sú v poli `stderr`
oboch dnešných artefaktov (`probe_20260918T154840Z.json`, `run_20260918T154742Z.json`),
ale doteraz ich žiadny dokument neuvádzal:

```
WARN  ebpf: 4.00 KiB pamate hosta nie je anonymna (/dev/zero (deleted)) - citanie
            stranky, ktorej sa host este nedotkol, ju hostitelovi NAOZAJ alokuje
WARN  ebpf: pri takejto VM zbieraj radsej konkretne oblasti (capture.regions), nech
            nenafuknes jej pamat na plnu velkost
```

Prečo je to dôležité: zber sa v práci opisuje ako pasívny v tom zmysle, že VM sa
nezastavuje (`paused=false`, `pause_ms=0`). To platí. Neplatí však, že by zber nemal
**žiadny** vplyv — pri pamäti, ktorá nie je anonymná, čítanie stránky, ktorej sa hosť
nikdy nedotkol, ju na strane hostiteľa naozaj alokuje. Plná snímka číta celý rozsah,
takže pamäťová stopa VM na hostiteľovi sa tým môže nafúknuť až na jej plnú veľkosť.

Čo je a čo nie je zmerané:

- Zmerané (hlási to zberač): pri tejto doméne ide o 4,00 KiB neanonymnej pamäte, teda
  o jedinú stránku, mapovanie `/dev/zero (deleted)`.
- Nezmerané (`UNVERIFIED`): o koľko MiB narastie stopa VM na hostiteľovi počas plnej
  snímky. Merania RSS procesu QEMU pred zberom a po ňom sa neurobili. Kým sa neurobia,
  v texte sa nesmie napísať, že zber pamäťovú stopu VM nemení.
- Obchádzka, ktorú zberač sám navrhuje — zbierať len konkrétne oblasti
  (`capture.regions`) — sa nepoužila; všetky uložené behy majú `regions: []`, teda celý
  rozsah.

---

## 2026-09-18 — meranie na zmrazenom hosťovi (bez agenta v hosťovi)

Doplnené orchestrátorom po skončení behov. Hosť je zmrazený: agent staršieho projektu
zastavený, `unattended-upgrades` zamaskované, jadro pinnuté na 6.1.0-42-cloud-amd64.
Doložené pozemnou pravdou tejto relácie: `grep -c hyptcn data/sessions/20260918_validate2/ps_before.txt` → 0.

Binárka: commit `178ce4f`, artefakty v `data/results/2026-09-18_zmrazeny_host/`.

### Pripojenie k hypervízoru (`probe`)

10 memslotov, 2.02 GiB RAM, 2 vCPU.
Artefakt: `data/results/2026-09-18_zmrazeny_host/probe.json`.

### Periodický zber, writer delta, perióda 5 s, 12 cyklov

| veličina | hodnota |
|---|---|
| dokončených cyklov | 12 |
| zlyhaných / zmeškaných | 0 / 0 |
| najväčšie meškanie | 0.0 s |
| cyklus delta snímky (n=11) | medián 564.5 ms, rozsah 552.6–629.6 ms |
| zmena pamäte medzi snímkami (n=11) | 0.040–0.659 % stránok |

Poznámka k hornej hranici zmeny pamäte: štyri z jedenástich delta snímok majú
0.2–0.66 % namiesto obvyklých 0.040 %. V tom čase sa v hosťovi
zbierala pozemná pravda (`ps`, `lsmod`, `ss` cez SSH), čo je samo o sebe činnosť. „Nečinná VM"
teda znamená „bez používateľskej záťaže", nie „bez akejkoľvek činnosti" — a merací zásah
sám o sebe je v dátach viditeľný.

### Rekonštrukcia objektov hosťa proti pozemnej pravde

Protokol: `ps`/`lsmod`/`ss` v hosťovi pred snímkou, snímka, `ps` po snímke; porovnáva sa
stabilná množina (procesy prítomné v oboch behoch `ps`).
Artefakt: `data/results/2026-09-18_zmrazeny_host/validate2.json`.

| veličina | hodnota |
|---|---|
| `ps` pred / po | 83 / 83 |
| stabilná množina | 81 |
| nájdených zo stabilnej množiny | **81/81** |
| chýbajúcich / falošných / nezhoda mien | 0 / 0 / 0 |
| moduly (pozemná pravda / zhoda) | 51 / **51**, chýbajúcich 0, navyše 0 |
| počúvajúce sokety (`ss -tulpn`) | 10 / **10**, chýbajúcich 0 |
| `sys_call_table` | 451 položiek skontrolovaných, 0 nálezov |
| prechod zoznamov prerušený? | procesy False, moduly False, sokety False |

Zhoda mien nie je len reťazcové porovnanie — `ps` a `task_struct.comm` sa líšia pri
jadrových workeroch a pri menách dlhších než 15 znakov. Použité pravidlá a ich počty:
{'exact': 63, 'worker': 15, 'truncated': 3}. Pravidlá sú v `guestparse/validate.py`, aby bolo
vidno, čo presne sa považuje za zhodu.

Dva sokety „navyše" oproti `ss -tulpn` nie sú chyba: `ss -tulpn` vypisuje iba počúvajúce
sokety, kým zo snímky je vidieť aj nenaviazaný UDP soket a nadviazaný dopyt na DNS
(192.168.122.100:34087 → 192.168.122.1:53). Zo snímky je navyše vidieť
1 soket protokolu RAW.

### Optimalizácia: kontrolný súčet (bod I12 zadania)

Pôvodný stav: SHA-256 sa počítal až v `finish()` nad hotovým riedkym súborom, teda aj nad
dierami, ktoré sa nikdy nezapísali. Oprava: hash sa počíta priebežne v `feed()` nad tým, čo
sa naozaj zapisuje (diery sa do hashu dopĺňajú nulami z pamäte, nie čítaním z disku),
plus vetva SHA-NI s behovou detekciou. Hash ostal hashom obsahu súboru, takže `verify`
aj selftest platia ďalej.

Meranie pred/po, rovnaká VM, `once -w raw`, n=3 na variant:

| variant | čítanie (medián) | zápis (medián) | cyklus spolu (medián) |
|---|---|---|---|
| pred, `hash=sha256` | 388.1 ms | 12983.7 ms | **13364.9 ms** |
| pred, `hash=none` | 387.4 ms | 206.8 ms | 589.9 ms |
| po, `hash=sha256` | 2287.9 ms | 196.2 ms | **2480.9 ms** |

Cyklus so zapnutým hashom klesol z 13364.9 ms na 2480.9 ms, teda
5.4×.

**Čo sa tým zhoršilo, a treba to povedať:** hashovanie sa presunulo do fázy čítania, takže
okno, počas ktorého sa číta pamäť bežiacej VM, sa predĺžilo z 388.1 ms na
2287.9 ms. Snímka je živá (VM sa nezastavuje), takže dlhšie okno znamená väčšiu
šancu, že dve stránky pochádzajú z odlišnejších okamihov. Pre celkovú priepustnosť je to
výhodná výmena, pre konzistenciu snímky nie. Kto potrebuje čo najkratšie okno čítania, má
naďalej `output.hash=none` (387.4 ms). Táto výmena nie je zmeraná z hľadiska
vplyvu na presnosť rekonštrukcie — to je otvorená položka.

Artefakty: `data/results/optim_hash_20260918.json` (súhrn),
`data/results/optim_hash_20260918_surove.json` (surové behy).

### Porovnanie s prvým (kontaminovaným) behom

| veličina | prvý beh (agent v hosťovi bežal) | zmrazený hosť |
|---|---|---|
| procesy nájdené/stabilné | 80/80 | 81/81 |
| moduly | 47/47 | 51/51 |
| cyklus delta snímky | 566–585 ms | 552.6–629.6 ms |

Rozdiel v počte modulov (47 → 51) nie je nezhodou merania: medzičasom si samotný zber
pozemnej pravdy (`ss -tulpn`) zaviedol do hosťa diagnostické moduly `inet_diag`, `tcp_diag`,
`udp_diag` a `raw_diag`. Podrobne v `profiles/debian12-6.1.0-42-cloud-amd64/README.md`.
Rekonštrukcia sa v oboch prípadoch zhodovala s tým, čo hlásil hosť v čase snímky.
