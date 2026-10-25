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


---

## 2026-09-18 — per-bin príznakový vektor v module (fáza F2)

Modul od tejto zmeny počíta príznakový vektor sám, v C, a zapisuje ho do JSON sidecaru
(blok `features`, schéma `hyptcn3/perbin/1`). Dôvod, prečo v module a nie skriptom potom:
cieľová veta zadania hovorí o module „schopnom generovať per-bin feature vektory", takže
offline post-processing by ju nesplnil.

Rozhodnutia potvrdené používateľom pred implementáciou: **binuje sa iba nad memslotmi**,
veľkosť binu **16 MiB**.

### Koľko binov vzniklo a prečo

VM má 2,02 GiB RAM rozprestretých v 4 GiB fyzickom priestore (10 memslotov).

| spôsob | počet binov |
|---|---|
| naivne cez `max_paddr` (4 GiB / 16 MiB) | 256, z toho ~126 trvale prázdnych |
| naivne cez veľkosť RAM (2,02 GiB / 16 MiB) | ~129 |
| **skutočnosť (iba nad memslotmi)** | **131** |

Biny 0–127 pokrývajú RAM `0x0–0xa0000` a `0xc0000–0x80000000`, ďalej existujú bin 251
(`0xfb000000`), bin 254 (`0xfee00000`, jediná stránka) a bin 255 (`0xfffc0000–0x100000000`).
Bin 128 neexistuje, lebo RAM končí presne na 2 GiB. Bin 0 má 4064 stránok, nie 4096 — chýba
mu VGA diera. Bin, ktorý neprotína žiadny memslot, nevzniká vôbec; nevypĺňa sa nulami.

### Invariant je vynútený v kóde, nie iba v teste

`vmic_features_finish()` porovná súčet `pages_total` a `pages_changed` cez biny s počítadlami
writera. Pri nezhode sa vypíše chyba a blok `features` sa do sidecaru **nezapíše** — radšej
chýbajúci vektor než vektor, ktorému sa nedá veriť. `pages_total` sa pritom počíta z geometrie
oblastí, nie z toho, koľko stránok pritieklo, takže porovnanie nie je tautológia.

### Krížová kontrola C proti Pythonu

Nezávislá Python referencia (`features/perbin.py`) číta `.vmicd` a počíta ten istý vektor.
Porovnanie 6 snímok × 131 binov × 8 polí = **6288 polí, 0 rozdielov** po zaokrúhlení na
6 desatinných miest, ktoré C vypisuje. Celočíselné polia sedia presne; najväčší rozdiel
v desatinných je 5·10⁻⁷, teda polovica posledného vypísaného miesta — zaokrúhlenie výpisu,
nie rozdiel vo vzorci. Artefakt: `data/results/perbin_crosscheck_20260918.json`.

### Čo výpočet stojí

Tri behy po 6 cyklov, perióda 5 s, tá istá VM:

| variant | plná snímka | delta cyklus (medián z 5) |
|---|---|---|
| bez príznakov | 952,0 ms | 550,4 ms |
| príznaky bez entropie | 989,4 ms | 589,2 ms |
| príznaky vrátane entropie | 1408,8 ms | 596,8 ms |

`compute_ms` (modul si ho meria sám): plná snímka 483,8 ms s entropiou, 52,8 ms bez nej;
delta cyklus 52,6 / 51,0 ms. Základ (test nulovej stránky + počítadlá cez všetkých 528 417
stránok) stojí ~51–53 ms bez ohľadu na to, koľko sa zmenilo. Entropia stojí ~3,5 µs na
**zmenenú** stránku — v delta cykle (~200 stránok) ~1,6 ms, v plnej snímke ~431 ms.
Preto je entropia samostatný prepínač; východzie nastavenie je zapnuté a cena je tu zapísaná.

Rozdiel `capture_ms` medzi variantmi (46,4 ms) pochádza z troch behov oddelených v čase,
takže obsahuje aj kolísanie záťaže. Nezávislejším údajom je `compute_ms`, ktorý meria
samotný výpočet.

### Latencia snímka → vektor

Meria sa od začiatku cyklu zberu po zavretie sidecaru s blokom `features` na disku
(cez `inotify close_write`), teda vrátane zápisu sidecaru, ktorý `total_ms` neobsahuje.
Poradie variantov striedané, `writer=delta`, `hash=none`.

| variant | n | medián | p95 | min–max |
|---|---|---|---|---|
| príznaky zapnuté, perióda 5 s, delta | 24 | 605.2 ms | 617.9 ms | 594.7–630.3 ms |
| príznaky vypnuté, perióda 5 s, delta | 24 | 554.5 ms | 558.7 ms | 542.6–563.7 ms |
| príznaky zapnuté, perióda 2 s, delta | 12 | 604.3 ms | 612.6 ms | 596.4–618.7 ms |
| príznaky zapnuté, perióda 2 s, **plná snímka** | 1 | 1588.0 ms | — | — |

**Falzifikovateľné kritérium použiteľnosti: p95 latencie cyklu < perióda zberu.**
Pri perióde 2 s je p95 delta cyklu 612.6 ms, teda kritérium platí s rezervou ~3×.
Plná snímka pri perióde 2 s trvá 1588 ms — stále pod periódou, ale rezerva je
malá a pri väčšej VM by nemusela stačiť. Preto sa plná snímka v zbere korpusu plánuje mimo
meraného okna. Vo všetkých šiestich behoch bolo 0 zmeškaných slotov a 0 chýb.

Toto je prvé z dvoch čísel, ktoré dávajú slovu „real-time" v názve práce obsah. Druhé
(snímka → skóre modelu) zatiaľ zmerané nie je a nesmie sa tvrdiť.

Artefakty: `data/results/perbin_c_20260918/`, `data/results/latency_vector_20260918.json`,
`data/results/perbin_crosscheck_20260918.json`.

---

## 2026-09-19 — profil jadra hosťa je viazaný na konkrétny boot (KASLR)

- **Dáta:** snímka `data/raw/20260919T110155Z_once/` (mimo gitu; sprievodný záznam behu je
  `data/results/once_20260919T110155Z.json`). **Vlastný výsledkový JSON tento záznam nemá**
  — nešlo o meranie veličiny, ale o krížovú kontrolu, ktorej celý výstup je nižšie doslovne.
  Čísla pochádzajú z výpisov príkazov uvedených pri nich, spustených na hostiteľovi
  2026-09-19.
- **Commit repa:** `da8ad2ec5c60520afff814109dc081b8faf123e7`, pracovný strom zmenený
  (docs/, scripts/, tcn/, features/)
- **Binárka:** `vmicollect/build/vmicollect` 1.0.0,
  sha256 začína `25f1d3e61905574a55f00880c455f56eddb4ea81` (celý je v
  `data/results/once_20260919T110155Z.json`, kľúč `binary.sha256`)

### Čo sa stalo

Doména `hyptcn-guest` bola 2026-09-18 vypnutá a 2026-09-19 nanovo naštartovaná. Profil
v repozitári (`profiles/debian12-6.1.0-42-cloud-amd64/`) pochádza z **včerajšieho** bootu.
Adresy symbolov v `kallsyms` sú randomizované KASLR-om pri každom štarte; offsety polí
štruktúr z BTF sú naopak viazané na verziu jadra, a tie reštart prežijú.

```sh
$ grep -E ' (init_task|linux_banner)$' profiles/debian12-6.1.0-42-cloud-amd64/kallsyms.txt
ffffffff9711f560 D linux_banner
ffffffff97a1aa40 D init_task
$ grep -E ' (init_task|linux_banner)$' <kallsyms z dnešného bootu>
ffffffffb191f560 D linux_banner
ffffffffb221aa40 D init_task
```

### Starý profil nad dnešnou snímkou

```
$ python3 -m guestparse info --snapshot data/raw/20260919T110155Z_once \
      --profile profiles/debian12-6.1.0-42-cloud-amd64
banner PA:     0x771f560 (kandidat 3)
posun jadra:   -0xfa00000
krizova kontrola prekladu (linearne vs. tabulky stranok):
  linux_banner   0x771f560      != 0x0            NEZHODA
  init_task      0x801aa40      != 0x0            NEZHODA
$ python3 -m guestparse ps --snapshot ... --profile profiles/debian12-6.1.0-42-cloud-amd64
spolu: 78 procesov, NEUPLNE
$ python3 -m guestparse lsmod --snapshot ... --profile profiles/debian12-6.1.0-42-cloud-amd64
spolu: 47 modulov, NEUPLNE
```

Posun jadra sa **našiel** — skenuje sa banner v pamäti, a ten sa nájde bez ohľadu na to,
z ktorého bootu je `kallsyms`. Časť nástroja preto beží ďalej a vyzerá funkčne. Krížová
kontrola prekladu adries však zlyhala: prechod tabuľkami stránok vrátil pre obe adresy
`0x0`, lebo tabuľky sú indexované skutočnými virtuálnymi adresami tohto bootu, nie starými
zo súboru `kallsyms`. Prechod padol na úrovni PMD s kódom `chyba_polozka`, teda tabuľka
v snímke je, ale položka pre tú adresu v nej prítomná nie je: `PMD[184]` pre `linux_banner`
a `PMD[189]` pre `init_task` (overené cez `GuestView.walk_pa_detail` nad tou istou snímkou
a profilom obnoveným z commitu `da8ad2e`).
Prechod zoznamu procesov sa neuzavrel — výpis je označený `NEUPLNE`.

### Čerstvý profil z toho istého bootu

```
$ python3 -m guestparse info --snapshot data/raw/20260919T110155Z_once --profile <profil z dnešného bootu>
banner PA:     0x771f560 (kandidat 3)
posun jadra:   -0x2a200000
krizova kontrola prekladu (linearne vs. tabulky stranok):
  linux_banner   0x771f560      == 0x771f560      zhoda
  init_task      0x801aa40      == 0x801aa40      zhoda
$ python3 -m guestparse ps    --snapshot ... --profile <profil z dnešného bootu>
spolu: 78 procesov
$ python3 -m guestparse lsmod --snapshot ... --profile <profil z dnešného bootu>
spolu: 47 modulov
```

Krížová kontrola sedí na bit a obidva výpisy sú úplné. (Orchestrátor dostal v ten istý deň
nad inou snímkou toho istého bootu 80 úplných procesov a 47 z 47 modulov proti `lsmod`
v hosťovi; počet procesov sa medzi snímkami líši, pretože sa líši v hosťovi. Tu uvedené
čísla sú z behov nad snímkou `20260919T110155Z_once`.)

### Čo z toho platí

1. Nástroj **neklamal**: výsledok so starým profilom označil `NEUPLNE` a krížová kontrola
   spadla. Zlyhanie bolo tiché len v tom zmysle, že návratový kód bol nula a text
   `NEUPLNE` sa dal prehliadnuť.
2. `profiles/` nie je jeden profil na verziu jadra, ako tvrdila `docs/PRIRUCKA.md`
   (kapitola 5, štvrtý stĺpec) — pre `kallsyms` je to jeden profil **na boot**.
   Za platnosť BTF ručí verzia jadra, za platnosť adries zo `kallsyms` nič.
3. Každé meranie, ktoré používa `guestparse`, musí byť z toho istého bootu ako profil,
   alebo musí mať uloženú krížovú kontrolu ako dôkaz, že profil k snímke sedí.
   Zapísané ako obmedzenie L17 v `docs/LIMITACIE.md`.

### Doplnok k tomuto záznamu (ten istý deň)

Profil v `profiles/debian12-6.1.0-42-cloud-amd64/` bol 2026-09-19 odobratý nanovo
z dnešného bootu, takže k hosťovi sedí a krížová kontrola nad snímkou
`20260919T110155Z_once` dáva `zhoda` pre obe kontrolné adresy. Behy zo stĺpca „starý
profil“ vyššie sa preto z repozitára už zopakovať nedajú — `kallsyms` z predchádzajúceho
bootu zostáva iba v histórii gitu. Adresy oboch verzií sú uvedené vyššie, takže sa dá
overiť, čo sa zmenilo.


## 2026-10-06 — serverové laboratórium a premávka z hostiteľa

Samostatná VM `hyptcn-lab` bola vytvorená kópiou zastaveného
`hyptcn-guest`. Nasadené nginx, auth, catalog, orders, PostgreSQL a worker;
HTTP prichádza cez `passt` na `http://127.0.0.1:18080`. Kód je v pracovnom
strome po commite `c221c6a`; artefakty obsahujú `commit_dirty` a hashe zdrojov.

Príkaz `python3 scripts/lab_smoke.py` overil zdravotný stav, autentizáciu,
odmietnutie neplatných vstupov a dokončenie objednávky workerom. Výstup:
`data/results/lab_smoke_20261006T130615775462Z.json`.

Ohraničený beh `python3 scripts/host_traffic.py --profile lab --target
http://127.0.0.1:18080 --dur 30 --vlakien 8 --seed 42 --out
data/lab/verification-traffic.json` zaznamenal 1485 {{res:lab_traffic_20261006T131108470896Z.json:values.ok}} úspešných požiadaviek.
HTTP chýb bolo 0 {{res:lab_traffic_20261006T131108470896Z.json:values.errors}}.
Súbežne bežal aj trvalý generátor; ide o funkčné overenie toku požiadaviek,
nie izolovaný benchmark priepustnosti ani meranie vplyvu introspekcie.
Artefakt: `data/results/lab_traffic_20261006T131108470896Z.json`.

Tento beh neposkytuje výsledok detekcie ani kalibráciu TCN. Živý eBPF zber
laboratória vyžaduje hostiteľské oprávnenia cez `scripts/lab_capture.sh`.


### 2026-10-06 — živý zber nového laboratória a oprava KASLR príznakov

Používateľ spustil `sudo scripts/lab_capture.sh 24`. Záznam
`data/results/lab_live_20261006T132412264043Z.json` obsahuje identitu binárky,
metadáta zberu, cykly, HTTP počty pred/po a kontrolu rekonštrukcie objektov.
Vzniklo 24 {{res:lab_live_20261006T132412264043Z.json:values.snapshots}} snímok.
Chýb čítania bolo 0 {{res:lab_live_20261006T132412264043Z.json:values.read_errors}},
zmeškaných slotov 0 {{res:lab_live_20261006T132412264043Z.json:values.skipped_slots}}.
Počas zberu pribudlo 3062 {{res:lab_live_20261006T132412264043Z.json:values.http_ok_delta}} úspešných HTTP požiadaviek.
Ide o tento ohraničený beh, nie dôkaz dlhodobého časového správania.

Prvý výpočet príznakov odhalil chybu: `features.snapshot` volal `build_view`,
ale nevolal KASLR preukotvenie, ktoré už CLI parsera vykonávalo. V novom
boote sa preto zoznamy neuzavreli a sokety vyšli nulové. Po oprave sa príznaky
vypočítali znova; posledná snímka má uzavreté prechody procesov, modulov
a soketov. Kernelová kontrola textu ostáva bez baseline tohto bootu neuzavretá.

Staršie tréningové artefakty, vrátane
`data/results/trenovanie_prediktor_4idle_20261006.json`, sa nemenia. Ich
príznaky treba znovu overiť a vygenerovať opravenou cestou pred novým tréningom;
pôvodný checkpoint nie je validovaný model nového laboratória. Ani skorší
`data/results/detector_offline_smoke_20261006T131628600669Z.json` nedokazuje
správnosť objektových počtov — overoval dokončenie výpočtu a počet výstupov.


## 2026-10-13 — metodika korpusu a zhodnosť offline/stream okien

Protokol a návrh príznakov sú v `docs/METODIKA_ZBERU.sk.md`, vykonateľné
parametre v `config/collection-v1.json`. Ide o plán zberu, nie nový tréning
ani meranie účinnosti detekcie. Nový privilegovaný runner zatiaľ neprešiel
živým pilotom; protokol má preto stav `pilot_required`.

Nad pôvodným zberom laboratória sa zopakovala extrakcia a porovnalo sa
offline skladanie okien s cestou `tcn.score.beh_predikcia`. Použil sa
historický idle checkpoint výlučne na porovnanie mechaniky. Artefakt:
`data/results/methodology_validation_20261012T221950635871Z.json`.
Z 24 {{res:methodology_validation_20261012T221950635871Z.json:values.snapshots}}
snímok bolo pri uloženom okne 8 {{res:methodology_validation_20261012T221950635871Z.json:values.window_rows}}
v oboch cestách 12 {{res:methodology_validation_20261012T221950635871Z.json:values.offline_windows}}
skórovateľných okien. Koncové sekvencie a skóre sa zhodovali presne.
Archív zároveň zachoval pôvodné sekvencie, časy, kvalitu prechodov a per-bin tenzor.

Oprava: živá cesta predtým používala aj okná obsahujúce plnú snímku;
tréning ich vylučoval. Teraz obe cesty používajú rovnaké pravidlá.
Do nového tréningového importu sa neprijme starý archív bez časov a kvality;
musí sa znovu odvodiť zo surových dát. Historické artefakty sa nemenia.

Krátky zber nie je prijatý do nového korpusu: chýba mu nová proveniencia
a dostatočne dlhé okná podľa plánovaného protokolu. Toto je očakávané
zamietnutie, nie zlyhanie pôvodného funkčného overenia. Ani zhodné skóre
nepotvrdzuje detekciu malvéru, kalibráciu, dostupnosť baseline textu jadra
alebo latenciu počas živého zberu.

## Integrovaný safeguard — diagnostické overenie softvéru, október 2026

Artefakt: `data/results/safeguard_validation_20261013_a.json`. Reprodukčný
príkaz aj hashe vstupných RAM súborov, zdrojového kódu, archívu príznakov
a modelového manifestu sú uložené v artefakte. Beh vykonal
`scripts/validate_safeguard.py`; výstupy sú v
`data/lab/safeguard-validation-20261013-a`.

Čerstvý syntetický korpus overil tréning prediktora a klasifikátora záťaže,
oddelenie rolí, kalibráciu, uloženie, načítanie a odmietnutie diagnostického
balíka pri bežnom načítaní. Tieto modely sa použili výlučne na skúšku
spracovania už uložených RAM snímok. Modely neboli natrénované na prevádzke
serverového labu a ich alarmy nie sú meraním falošných poplachov.

Prehralo sa 24 {{res:safeguard_validation_20261013_a.json:values.real_replay_rows}}
reálnych snímok; skórovateľných bolo
12 {{res:safeguard_validation_20261013_a.json:values.real_replay_scored}}
okien. Skóre, chyby jednotlivých binov a pravdepodobnosti klasifikácie
sa presne zhodovali medzi archivovanými príznakmi a opakovanou extrakciou
zo surovej RAM cez nový detektor. Plné snímky prerušili modelové okná.
Prehratie nemenilo pôvodný zber a nespúšťalo príkaz HOLD.

Toto overuje prepojenie softvéru. Nový spoločný privilegovaný beh zberača
a detektora je zatiaľ UNVERIFIED na živom hosťovi; jeho riadenie procesov
a chybové vetvy overujú testy s náhradným procesom. Živý pilot, tréning
na plánovanom korpuse, nezávislé metriky a merania reálnych malvérových
vzoriek zostávajú ďalšou etapou.


## 2026-10-13 — prvý živý pilot: zber dokončený, audit zamietnutý

Session `data/collections/20261013T121136639363Z_pilot_steady` vznikla príkazom
`sudo python3 scripts/collection.py run --role pilot --group pilot-1 --scenario steady --seed 101`
z commitu `733c5a7`. Pôvodný audit je bez zmien skopírovaný do
`data/results/collection_pilot_20261013_audit.json`; pôvodné RAM snímky,
archív príznakov a audit v session sa nemenia.

Zber vytvoril 480 {{res:collection_pilot_20261013_diagnosis_v2.json:values.capture.snapshots}}
snímok. Chýb čítania bolo
0 {{res:collection_pilot_20261013_diagnosis_v2.json:values.capture.read_errors}},
zmeškaných slotov
0 {{res:collection_pilot_20261013_diagnosis_v2.json:values.capture.skipped_slots}}.
Celý generátor premávky vrátane zahrievania zaznamenal
19152 {{res:collection_pilot_20261013_diagnosis_v2.json:values.traffic.ok}}
úspešných požiadaviek a
0 {{res:collection_pilot_20261013_diagnosis_v2.json:values.traffic.errors}} chýb.

Audit pilot neprijal. Platných vstupných riadkov bolo
478 {{res:collection_pilot_20261013_diagnosis_v2.json:values.original_model_valid_rows}},
ale po vylúčení okien pretínajúcich neplatné alebo plné snímky zostalo iba
354 {{res:collection_pilot_20261013_audit.json:values.windows}} okien.
Podiel skórovateľných krokov bol
0,7375 {{res:collection_pilot_20261013_audit.json:values.score_coverage}},
pod návrhovou hranicou protokolu. Neúplné kontroly zároveň samostatne
porušili podmienku prijatia. Pilot sa nepoužije na tréning ani kalibráciu.

Diagnostické prehratie odhalilo cykly v zoznamoch `children/sibling` pri
sekvenciách uvedených v `values.original_invalid_seq` diagnostického artefaktu.
Hlavný zoznam `tasks` aj susedné kontrolované snímky sa uzavreli. Presný pôvod
cyklov toto prehratie neurčuje; rozdiel oproti neúplnému stromu nie je dôkaz
skrývania procesu ani malvéru.

Parser pred opravou zapisoval aj rozdiely neúplných krížových pohľadov medzi
`findings`, čím mohol vyvolať alarm integrity. Teraz ich zachováva osobitne
v `inconclusive_differences`. Nezávislé nálezy zostávajú účinné. Prechod stromom
rozlišuje cyklus od neplatného ukazovateľa a neprijme nečitateľný odkaz ako
uzavretý zoznam. Oprava nemení pravidlá platnosti modelových vstupov ani
hranicu prijatia pilotu. Pôvodné archívy s nálezmi podľa starej implementácie
sa nesmú vydávať za výstup opraveného parsera; pred použitím v detektore
vyžadujú novú extrakciu do nového artefaktu.

Príkazy prehratia a hashe kódu sú v
`data/results/collection_pilot_20261013_diagnosis_v2.json`. Ide o kontrolu
vybraných snímok, nie nový audit celej session. Chýbajúca baseline textu jadra
tohto bootu zostáva priznaná ako neuzavretá kontrola. Účinnosť detekcie,
falošné poplachy nasadeného modelu ani živá latencia detektora sa týmto
pilotom nemerali. Pred ďalším zberom treba vyriešiť dostupnosť súvislých
modelových okien a kapacitu úložiska pre celú kampaň.

Oprava pomocného reportu: prvý súbor
`data/results/collection_pilot_20261013_diagnosis.json` nesprávne rátal všetky
JSON súbory v adresári ako snímky a čítal počítadlá z nesprávnej úrovne.
Jeho `values.capture` nahrádza vyššie citovaný artefakt s príponou `_v2`,
ktorý vyberá sidecary podľa pôvodného auditu a overuje ich hashe. Záznamy
prehratia sú rovnaké; pôvodný report zostáva zachovaný.


## 2026-10-13 — návrh v2: oddelenie vstupov modelu a integrity

Po zamietnutí prvého pilotu vznikol samostatný protokol
`config/collection-v2.json`. Hranica pokrytia, dĺžka okna, perióda a rotácia
sa nemenia. Platnosť behaviorálnych vstupov sa vyhodnocuje podľa úplnosti
primárnych prechodov a čítania RAM; dostupnosť nezávislých kontrol integrity
sa vykazuje osobitne. Benígny audit s nálezom integrity sa zamietne na
preskúmanie. Chýbajúce vstupy sa nenahrádzajú ani nepreskakujú.

Archív má novú schému a explicitnú politiku platnosti. Historická cesta so
stĺpcami integrity má vlastnú politiku a ostáva prísnejšia. Tréning ani
detektor nemôžu prijať archív s inou politikou či starý modelový kontrakt.

Artefakt `data/results/quality_policy_validation_20261013_a.json` zaznamenáva
prehratie 6 {{res:quality_policy_validation_20261013_a.json:n}} vybraných
uložených snímok okolo oboch problémových miest. Hashe pôvodných vstupov
boli overené. Príznaky bez závislosti od predchodcu a lokálne biny sa zhodovali
s pôvodnou extrakciou. Zachovanie dostupného predchodcu obnovilo aj merané
rozdiely množín PID po neuzavretej krížovej kontrole. Kontrola zostala označená
ako neuzavretá; nevytvorila nález integrity.

Krátke diagnostické okno v tomto overení slúži iba na kontrolu kontinuity.
Nie je to okno výskumného protokolu, meranie pokrytia nového pilotu ani
výsledok detekcie. Zamietnutý pilot v1 sa nepreklasifikoval na prijatý;
v2 vyžaduje nový zber s vopred určenou konfiguráciou.


## 2026-10-13 — pilot v2: dokončený zber, chybná kotva po reštarte

Session `data/collections/20261013T140853080075Z_pilot_steady` vznikla
podľa nezmeneného `config/collection-v2.json` z commitu `6fcd6f9`, skupina
`pilot-2`, scenár `steady`, seed `102`. Zber aj prvý audit prebehli s čistým
pracovným stromom. Pôvodný audit je bez zmeny uložený ako
`data/results/collection_pilot_v2_20261013_audit.json`; podporné počítadlá,
zdroje a postup ich agregácie obsahuje
`data/results/collection_pilot_v2_20261013_summary.json`.

Zber dokončil 480 {{res:collection_pilot_v2_20261013_summary.json:values.capture.snapshots}}
snímok, s počtom chýb čítania
0 {{res:collection_pilot_v2_20261013_summary.json:values.capture.read_errors}}
a vynechaných intervalov
0 {{res:collection_pilot_v2_20261013_summary.json:values.capture.skipped_slots}}.
Najdlhší cyklus zberača trval
1972,359 ms {{res:collection_pilot_v2_20261013_summary.json:values.capture.max_cycle_ms}}.
Surové obrazy zaberajú
5,492 GiB {{res:collection_pilot_v2_20261013_summary.json:values.capture.raw_gib}}.
Premávka vrátane zahrievania skončila s počtom úspešných požiadaviek
19144 {{res:collection_pilot_v2_20261013_summary.json:values.traffic.including_warmup.ok}}
a chýb
0 {{res:collection_pilot_v2_20261013_summary.json:values.traffic.including_warmup.errors}}.

Prvý audit v2 napriek tomu zamietol všetky vstupy: počet platných okien bol
0 {{res:collection_pilot_v2_20261013_audit.json:values.windows}}.
V RAM zostali dve kópie banneru a `init_task` z rôznych bootov. Starý
resolver vybral prvú obsahovo zodpovedajúcu dvojicu, ktorej zvyšné objekty
už nepatrili aktívnemu jadru. Reukotvenie KASLR samo osebe túto chybu
neodhalilo: aj stará kópia mala zvyšky zodpovedajúcich tabuliek stránok.

Oprava overuje `sysctl_bootid` z RAM proti boot UUID uloženému orchestráciou
pred zberom. Nepýta sa bežiaceho hosťa počas extrakcie. Pri chýbajúcej alebo
nejednoznačnej zhode zlyhá; bez identity pripustí iba jedinú kotvu.
Profilový `boot.json` nie je dôkazom bootu snímky. Rovnaká funkcia sa používa
pri audite aj pri spracovaní surovej RAM safeguardom. Krížová kontrola adries
zároveň odmieta aj mapovanie symbolu na inú fyzickú stránku, nielen chýbajúcu
položku tabuľky.

Diagnostika `data/results/boot_anchor_validation_20261013_a.json` overila
6 {{res:boot_anchor_validation_20261013_a.json:n}} uložených snímok zo začiatku,
priebehu, rotácie a konca zberu. Každá obsahovala starú aj aktuálnu kotvu;
vybraná identita sa zhodovala s metadátami zberu. Po preukotvení sa obe
kontrolované adresy zhodovali s prechodom tabuliek a primárne prechody boli
úplné. Pamäťové príznaky a lokálne biny sa oproti pôvodnej extrakcii nezmenili.
Hashe všetkých surových vstupov boli overené. Táto diagnostika nie je audit
celej session ani výsledok detekcie; nový úplný audit ešte musí prebehnúť.

Overená kópia pôvodnej session je na
`/run/media/eh/Seagate Expansion Drive/hyptcn3/collections/20261013T140853080075Z_pilot_steady`.
Kopírovanie overilo SHA-256 zdroja aj cieľa pre každý z
980 {{res:collection_pilot_v2_20261013_summary.json:values.archive.files}} súborov
aj nemennosť zdroja počas prenosu. Cesta a hash úplného manifestu sú v súhrne.
Pôvodné dáta na internom disku zostávajú zachované; absolútne cesty vo vnútri
metadát sa pri zálohe neprepisovali.


## 2026-10-13 — pilot v2 prijatý po novej extrakcii rovnakých RAM dát

Nový audit z čistého commitu `bf6ed37` je uložený bez zmien ako
`data/results/collection_pilot_v2_20261013_reaudit.json`. Ide o opravenú
extrakciu a audit rovnakej session, nie nezávislé opakovanie živého zberu.
Pôvodný zamietnutý audit a jeho archív príznakov zostali zachované.

Prijatý audit má
480 {{res:collection_pilot_v2_20261013_reaudit.json:values.quality.behavior_valid_rows}}
platných behaviorálnych riadkov a
416 {{res:collection_pilot_v2_20261013_reaudit.json:values.windows}}
skórovateľných okien. Podiel skórovateľných časových krokov je
0,8667 {{res:collection_pilot_v2_20261013_reaudit.json:values.score_coverage}}.
Okno sa naďalej neskladá cez plné snímky a chýbajúci kontext po ich vložení.
Konfigurácia, časová perióda, pravidlá platnosti a návrhová hranica prijatia
sa nemenili. Pilot zostáva v role `pilot`, mimo tréningu, kalibrácie aj testu.

Nálezy integrity: počet
0 {{res:collection_pilot_v2_20261013_reaudit.json:values.quality.integrity_findings}}.
Kontrola textu jadra zostala neuzavretá vo všetkých
480 {{res:collection_pilot_v2_20261013_reaudit.json:values.quality.integrity_inconclusive_rows.text_integrity}}
riadkoch pre chýbajúcu baseline. Prijatie behaviorálnych dát nepotvrdzuje
kontrolu textu jadra. Účinnosť voči malvéru, falošné alarmy, živá latencia
a vplyv celého detektora na VM sa týmto auditom nemerali.

`data/results/collection_pilot_v2_20261013_reanalysis.json` dokladá zhodu
manifestu surových vstupov, metadát session aj protokolu medzi oboma auditmi.
Časové osi, globálne pamäťové príznaky a celý per-bin tenzor sa zhodovali
pre celý zber. Zmenila sa rekonštrukcia objektov jadra a z nej odvodené
príznaky, kvalita a okná. Nové súbory sú overene skopírované osobitne pod
`/run/media/eh/Seagate Expansion Drive/hyptcn3/derived/`; cesta, súbory a hash
manifestu sú v tomto artefakte. Pôvodný archív sa neprepisoval.

Plánovací odhad `data/results/collection_pilot_readiness_20261013_a.json`
prenáša priemerný objem snímky tohto scenára na celý vopred určený plán.
Odhaduje
395,43 GiB {{res:collection_pilot_readiness_20261013_a.json:values.projected_raw_gib}}
surových obrazov; po pridaní plánovacej rezervy
593,14 GiB {{res:collection_pilot_readiness_20261013_a.json:values.projected_with_50_percent_reserve_gib}}.
V čase kontroly mal externý disk voľných
785,54 GiB {{res:collection_pilot_readiness_20261013_a.json:values.external_free_gib}}.
Ide o extrapoláciu jedného scenára, nie o nameranú veľkosť budúceho korpusu;
núdzová rezerva protokolu sa ponechá navyše. Artefakt uchováva aj rozdelenie
časovača `feature_extraction_s` z offline auditu. Živý spoločný zber a detektor
stále vyžadujú samostatné meranie. Pred kampaňou zostáva dokončiť priebežné
archivovanie a správu pracovných kópií na internom disku.


## 2026-10-13 — overenie automatickej archivácie na Seagate

`scripts/campaign.py` implementuje zmrazený plán benígneho zberu, riadené
reštarty skupín, spustenie zberača, offline audity, archiváciu a zostavenie
indexu. Jednotkové integračné testy používajú nahradené procesy zberača a
auditu; overujú riadenie a chybové stavy, nie nový živý korpus.
Postup obsluhy je v `docs/AUTOMATICKY_ZBER.sk.md`.

`data/results/campaign_archive_validation_20261013_a.json` obsahuje
2 {{res:campaign_archive_validation_20261013_a.json:n}} funkčné prípady
z commitu `ea3dc4b`: kopírovanie existujúcej reálnej session a uvoľnenie
samostatnej syntetickej pracovnej kópie. Nie sú to nezávislé opakovania
RAM zberu ani experimenty detekcie.

Kópia prijatého pilotu na pripojenom Seagate má
982 {{res:campaign_archive_validation_20261013_a.json:values.real_session_copied_files}}
súborov. Archivácia overila ich SHA-256 aj nemennosť zdroja, zviazala
archivované obrazy a príznaky s prijatým auditom a samostatne znovu overila
publikovaný archív. Artefakt obsahuje cestu a hash manifestu aj UUID disku.
Pôvodná session aj jej surové súbory zostali na internom disku nezmenené.

Syntetický prípad obsahoval
4 {{res:campaign_archive_validation_20261013_a.json:values.synthetic_reclamation_files}}+súbory. Po overení kópie sa lokálny `raw/` nahradil odkazom do archívu
a pracovné raw súbory sa odstránili. Opätovné spustenie prešlo, lokálna
cesta príznakov sa nezmenila a vyhľadanie native bootových metadát fungovalo
aj po vyriešení odkazu. Syntetické bajty sa neparsovali ako RAM a nevstúpili
do datasetu.

Kód navyše ošetruje prerušenie pri zápise manifestu, premenovaní raw adresára,
odstraňovaní už overených pracovných súborov a neúplnom zápise auditu. Také
prípady majú regresné testy; hotový zamietavý verdikt sa opakovaním neobchádza.
Adresárové položky novej archívnej cesty sa synchronizujú pred uvoľnením
zdroja. Plná živá kampaň zostáva samostatným zberom; tento záznam nepotvrdzuje
jej dokončenie, pripravený natrénovaný model ani účinnosť voči malvéru.

## 2026-10-20 — offline kontrola logov a dostupnosti modelových okien

Artefakt [collection_readiness_20261020_logs_coverage.json](../data/results/collection_readiness_20261020_logs_coverage.json)
obsahuje dodatočnú kontrolu uložených diagnostických zberov z tohto dňa.
Nejde o nový pilot ani nové snímky. Pôvodné audity a NPZ sa nemenili;
pred čítaním NPZ sa jeho SHA-256 porovnal s pôvodným auditom. Report
zachováva hashe použitých nástrojov a príkazy na zopakovanie kontroly.

Pri `20261020T170034679155Z_diagnostic_bursty` sú klientské, nginx
a aplikačné logy navzájom zhodné; overenie zahŕňa aj manifesty,
komprimované segmenty, stav služieb, hostiteľský monitor a koniec zberača.
Tento výsledok sa týka logov, nie prijatia RAM dát. Z
400 {{res:collection_readiness_20261020_logs_coverage.json:values.coverage.observed_snapshots}}
snímok vzniklo
145 {{res:collection_readiness_20261020_logs_coverage.json:values.coverage.scorable_windows}}
skórovateľných okien, podiel
0,3625 {{res:collection_readiness_20261020_logs_coverage.json:values.coverage.score_coverage}}.
Neplatných primárnych vstupov bolo
9 {{res:collection_readiness_20261020_logs_coverage.json:values.coverage.state_rows.invalid_input}};
poznámky parsera pri nich hlásia cyklus v zozname procesov. Po každom
takom vstupe sa stratí predchodca a musí sa znovu nazbierať celé okno.
Prvý skórovateľný krok mal sekvenciu
105 {{res:collection_readiness_20261020_logs_coverage.json:values.coverage.first_score_seq}}.
Report vysvetľuje jednotlivé úseky bez skóre. Inferencia modelu sa nevykonávala.

Pri tejto pridelenej dĺžke a predpísanej rotácii je výpočtový strop
336 {{res:collection_readiness_20261020_logs_coverage.json:values.coverage.ideal_windows}}
okien. Aj bez neplatných vstupov by krátka diagnostika nedosiahla hranicu
protokolu; štandardný pilot je dlhší. Pokrytie sa nezvyšovalo skrátením
okna, zmenou pravidiel platnosti ani doplnením chýbajúcich dát.

`20261020T142021156420Z_diagnostic_write_heavy` kontrolou logov neprešiel:
generátor bol násilne ukončený, chýbajú koncové záznamy a posledný interval,
nginx obsahuje požiadavky bez dokončeného klientského záznamu a zberač
hlási zmeškané sloty. `20261020T173655582088Z_diagnostic_steady` je
prerušený beh s chýbajúcimi záverečnými dôkazmi. Obe zamietnutia sú
v tom istom artefakte; žiadne z týchto dát sa touto kontrolou neprijímajú
do benígneho korpusu.

Pri čítaní nainštalovaného kódu psycopg2 vo VM sa overilo, že pôvodný pool
zachováva len `minconn` nečinných spojení. Úprava v `lab/services.py`
uchováva celý ohraničený pool, aby sa spojenia pri súbežných požiadavkách
opakovane nezatvárali. Súvis medzi obmenou backendov PostgreSQL a chybami
neatómových RAM snímok zostáva hypotézou. Úprava nebola počas tohto
overenia nasadená a jej vplyv na pokrytie nebol meraný. Vyžaduje nový
pilot s novou identitou stacku. Postup kontroly: [KONTROLA_ZBERU.sk.md](KONTROLA_ZBERU.sk.md).

## 2026-10-20 — nasadenie trvalého databázového poolu

Úprava `lab/services.py` bola nasadená do `hyptcn-lab`. Funkčná kontrola
[`lab_smoke_pool_20261020.json`](../data/results/lab_smoke_pool_20261020.json)
vykonala
13 {{res:lab_smoke_pool_20261020.json:n}}
HTTP kontrol vrátane autentifikácie, katalógu, zápisu objednávky a jej
dokončenia workerom. Artefakt obsahuje hashe nasadených zdrojov a stavy
odpovedí. Toto overenie nedokazuje zlepšenie skórovateľných RAM okien;
to musí zmerať nový pilot. Predchádzajúci záznam o nenasadenej úprave
popisuje stav pri skoršej offline kontrole a zostáva zachovaný.

## 2026-10-20 — odstránenie regenerovateľných pracovných súborov

Po kontrole proti `git ls-files` sa odstránili Python/pytest cache a
syntetické výstupy C testov v `vmicollect/build/selftest` a `perbintest`.
[`collection_cleanup_20261020.json`](../data/results/collection_cleanup_20261020.json)
zaznamenáva konkrétne adresáre, logické aj alokované veľkosti a
226 {{res:collection_cleanup_20261020.json:values.removed_files}}
odstránených súborov. Verzionované súbory a dôkazy meraní sa týmto krokom
nemažú. Cache môžu pri ďalších kontrolách opäť vzniknúť; nejde o meranie
zníženia nárokov samotného zberača alebo modelu.

## 2026-10-20 — obnova komprimovaných reálnych snímok a príznakov

[`collection_archive_roundtrip_20261020.json`](../data/results/collection_archive_roundtrip_20261020.json)
dokladá obnovu všetkých raw členov diagnostiky
`20261020T170034679155Z_diagnostic_bursty` z archívu zstd na systémovom HDD.
Archív obsahuje
400 {{res:collection_archive_roundtrip_20261020.json:values.total_snapshots}}
reálnych RAM snímok; pôvodné aj obnovené obsahy sa overili pomocou SHA-256.
S pôvodným bootovým kontextom sa opäť extrahovalo prvých
40 {{res:collection_archive_roundtrip_20261020.json:values.reextracted_rows}}
nadväzujúcich snímok. Globálne/per-bin vstupy, sekvencie, časy snímok,
platnosť, kvalita, poznámky a modelový kontrakt boli zhodné s pôvodným NPZ.
Namerané trvania extrakcie sa neporovnávali. Nový NPZ a kópia použitého
prípravného skriptu sú uložené pri výsledku.

Nejde o nový zber, úplnú opätovnú extrakciu celého behu ani o prijatie
zamietnutej diagnostiky do korpusu. Pracovná raw kópia bola uvoľnená až
po overení archívu, obnove, porovnaní príznakov a opätovnom overení
identity pracovných súborov. Archív, metadáta, pôvodný audit a príznaky
zostávajú zachované; dočasné obnovené kópie sa odstránili.

## 2026-10-20 — komprimovaný archív diagnostík a odhad kapacity

[`collection_storage_20261020.json`](../data/results/collection_storage_20261020.json)
zaznamenáva archiváciu
5 {{res:collection_storage_20261020.json:n}}
diagnostických behov na HDD. Archív zstd sa overoval dekompresiou a SHA-256;
pri jedinom už auditovanom behu sa naviazal aj na pôvodný audit a NPZ.
Po overení sa uvoľnili iba pracovné raw kópie, metadáta a výsledky zostali
na pôvodných cestách. Žiadny zamietnutý beh sa týmto neprijal do korpusu.
Report obsahuje manifesty, potvrdenia presunu, pôvodné/uložené veľkosti
a voľný priestor pred a po operácii. Kópia prípravného skriptu je uložená
pri výsledku obnovy vyššie.

Odhad plánovanej kampane vychádza z najväčšieho komprimovaného objemu na
snímku medzi úplnými diagnostikami. Prepočítava sa na hodinovú session,
celý plán, plánovaciu a núdzovú rezervu. Krátky prerušený beh sa na tento
odhad nepoužil. Ide o extrapoláciu starého workloadu pred zmenou poolu,
nie o výsledok nového pilotu ani záruku kapacity všetkých budúcich scenárov.

## 2026-10-20 — riadené zastavenie živého diagnostického zberu

[`collection_stop_validation_20261020.json`](../data/results/collection_stop_validation_20261020.json)
dokladá `systemctl stop` jednotky s `KillMode=mixed` po
4 {{res:collection_stop_validation_20261020.json:n}}
skutočných RAM snímkach. Prípravný runner použil riadenie procesov z
`campaign.run_child`, `collection.Interrupts` a rovnaké blokovanie spánku.
Zberač, HTTP generátor aj monitor skončili cez SIGTERM, nezostali živé
deti, zámok bolo možné znovu získať a blokovanie spánku sa uvoľnilo.
Runner zapísal `interrupted`, session `completed=false` a logový audit ju
zamietol. Návratový kód runnera pri úmyselnom prerušení je uložený v reporte.

Test používal samostatný diagnostický protokol so skráteným zahrievaním;
jeho plán je súčasťou reportu. Nie je pilotom pokrytia ani dátami korpusu.
Neoveruje celú kampaň, jej reštarty skupín, opätovné spustenie ani konečný
index. Záznam zachováva zdrojové hashe a kópiu prípravného runnera.

## 2026-10-21 — oprava stavu pamäte po ďalšej plnej snímke

[`full_snapshot_reset_20261021.json`](../data/results/full_snapshot_reset_20261021.json)
dokladá chybu `guestparse.image.VmicdImage`: nová plná snímka nevyprázdnila
index stránok z predchádzajúcej histórie. Stránky, ktoré v novej plnej
snímke chýbali ako nulové, tak mohli niesť starý obsah. Pri reálnom pilote
po nasadení poolu zostalo za druhou plnou snímkou
140 {{res:full_snapshot_reset_20261021.json:values.before.obsolete_nonzero_pages}}
takých nenulových stránok. Štyri varianty syntetického regresného testu
chybu pred opravou zachytili; kontrola chýbajúcej alebo skrátenej histórie
bola a zostáva samostatnou požiadavkou.

Oprava vyprázdni index pred načítaním každej plnej snímky. Na reálnych
dátach sa porovnal celý index fyzickej pamäte s nezávisle otvoreným novým
reťazcom pri plnej snímke, nasledujúcej delte, obnovenom kontexte okna
a poslednej snímke. Všetky
4 {{res:full_snapshot_reset_20261021.json:n}}
porovnania sa zhodovali. Rozsah a hashe zdrojov sú v reporte; čas týchto
diagnostík sa pre súbeh s offline auditom nepoužíva ako výkonnostné meranie.

Staršie výsledky sa neprepisujú. Rekonštrukcie prechádzajúce cez ďalšiu
plnú snímku potrebujú nový audit pred použitím. Pôvodný audit tohto pilotu
dobiehal bez zmeny zdrojov; jeho prípadný kladný verdikt nie je prijatím
po zistení chyby. Oprava sa overí novým pilotom s aktuálnym meracím kódom.
Predchádzajúca skúška archívu porovnávala iba prvý súvislý úsek a túto
hranicu nepokrývala; jej deklarovaný rozsah zostáva nezmenený.

Pôvodný nezmenený audit dobehol a vykázal
416 {{res:collection_pilot_pool_20261021_superseded.json:values.reported_windows}}
okien a žiadny dodatočný výpadok. Známa chyba parsera tento pilot vylučuje
z prijatia korpusu; výsledok logov zostáva samostatným zistením.
[`collection_pilot_pool_20261021_superseded.json`](../data/results/collection_pilot_pool_20261021_superseded.json)
uchováva dôvod vyradenia a overenie, že aktuálna vstupná kontrola kampane
starší pilot odmietne. Doslovný pôvodný audit ostáva v samostatnej kópii.

Úplné `make test` po oprave prešlo: Python vykonal
580 {{res:full_snapshot_reset_checks_20261021.json:values.passed}}
úspešných testov a
33 {{res:full_snapshot_reset_checks_20261021.json:values.skipped}}
preskočených testov. C testy tiež prešli. Výstup a dôvody preskočenia sú
v [`full_snapshot_reset_checks_20261021.json`](../data/results/full_snapshot_reset_checks_20261021.json)
a pripojenom doslovnom logu. Tieto testy nenahrádzajú nový živý pilot.

Pracovné RAM kópie vyradeného pilotu a riadeného testu zastavenia boli
po overení kompresie, pôvodných hashov a väzby pilotu na jeho audit
odstránené z SSD. Presné objemy, archívne manifesty a miesto pred a po sú
v [`collection_preflight_cleanup_20261021.json`](../data/results/collection_preflight_cleanup_20261021.json).
Metadáta, príznaky a pôvodné verdikty ostávajú na pôvodných cestách;
komprimované RAM dôkazy sú v archíve. Nový korpus tieto skúšobné behy
neobsahuje. Skript údržby je zachovaný spolu s reportom.

## 2026-10-21 — offline extrakcia s kurzorom reťazca (ChainCursor)

[`chain_cursor_validation_20261021.json`](../data/results/chain_cursor_validation_20261021.json)
dokladá zmenu offline extrakcie. `features.snapshot.retazec` predtým pre každú
snímku znovu otváral reťazec od prvej plnej snímky, takže čas na riadok rástol
s pozíciou v session. Predchádzajúci audit toho istého diagnostického behu trval
41.8 {{res:chain_cursor_validation_20261021.json:values.previous_audit_total_min}}
min. `guestparse.image.ChainCursor` načíta každú časť delty raz a pri ďalšej
plnej snímke index vyprázdni rovnako ako `open_image`.

Overenie prebehlo na obnovenej kópii zamietnutého diagnostického behu
`20261020T170034679155Z_diagnostic_bursty` s
400 {{res:chain_cursor_validation_20261021.json:n}}
snímkami a druhou plnou snímkou pri seq 360. Index fyzickej pamäte sa zhodoval
s nezávisle otvoreným reťazcom pri všetkých kontrolovaných pozíciách (vrátane
358–362 a 399). Riadky 0–359 sa bitovo zhodovali s pôvodným auditom a riadky
360, 361, 380 a 399 s výpočtom bez kurzora. Celý reťazec trval
684.3 {{res:chain_cursor_validation_20261021.json:values.retazec_s_with_cursor}}
s. Je to diagnostika mimo korpusu; obnovená pracovná kópia bola potom z SSD
odstránená, pôvodný archív zostáva.

## 2026-10-21 — pilot zamietnutý: swap hostiteľa a spoločný disk VM a snímok

Pilot `20261021T230727556324Z_pilot_bursty` (skupina `pilot-reset-20261021`,
commit `183d1d7`, profil `bursty`) zozbieral
480 {{res:collection_pilot_reset_20261021_audit.json:values.snapshots}}
snímok a audit ho zamietol
([audit](../data/results/collection_pilot_reset_20261021_audit.json)).
Príčiny sú v
[`collection_io_interference_20261021.json`](../data/results/collection_io_interference_20261021.json)
a pochádzajú z prostredia hostiteľa, nie z hosťa:

- Swap. Pred zberom mala QEMU vo swape
  331228 {{res:collection_io_interference_20261021.json:values.qemu_swap_kb_first_sample}}
  kB (swappiness 60, swap na systémovom HDD). Prvá plná snímka
  (924.9 {{res:collection_io_interference_20261021.json:values.first_full.mib}} MiB)
  ich čítala späť
  7341.1 {{res:collection_io_interference_20261021.json:values.first_full.read_ms}}
  ms pri perióde 5 s a zberač zahodil
  1 {{res:collection_io_interference_20261021.json:values.missed_slots}}
  slot. Druhá plná snímka už bez swapu trvala
  2446.6 {{res:collection_io_interference_20261021.json:values.second_full.read_ms}}
  ms.
- Spoločný disk. Plná snímka zostala v page cache a zapísala sa naraz až po
  132.6 {{res:collection_io_interference_20261021.json:values.writeback_burst_after_first_full.seconds_after_full}}
  s, druhá po
  111.5 {{res:collection_io_interference_20261021.json:values.writeback_burst_after_second_full.seconds_after_full}}
  s. Druhý taký zápis trval
  12.0 {{res:collection_io_interference_20261021.json:values.writeback_burst_after_second_full.duration_s}}
  s pri iowait až
  51.163 {{res:collection_io_interference_20261021.json:values.writeback_burst_after_second_full.iowait_max_pct}}
  %. Disk VM bol na tom istom súborovom systéme ext4, takže commity
  databázy hosťa čakali za týmto zápisom:
  4 {{res:collection_io_interference_20261021.json:values.request_failures.count}}
  požiadavky `POST /api/orders` prekročili limit klienta 4 s. Logový audit
  zamietol ich chýbajúce odpovede, záznamy 499 v nginx, tracebacky služby
  aj 3 s medzeru monitora hostiteľa.

Ostatné kontroly prešli: všetky riadky majú platné behaviorálne vstupy, audit
nenašiel nález integrity a korelácia request ID fungovala. Pokrytie bolo
0.8646 {{res:collection_pilot_reset_20261021_audit.json:values.score_coverage}}
pri strope
0.8667 {{res:collection_pilot_reset_20261021_audit.json:values.coverage.ideal_score_coverage}};
jedna medzera v časovej osi stála jedno okno. Extrakcia 480 riadkov s kurzorom
trvala spolu
702.7 {{res:collection_io_interference_20261021.json:values.audit_timing.extraction_s_sum}}
s (medián
1.433 {{res:collection_io_interference_20261021.json:values.audit_timing.extraction_s_median}}
s na riadok), celý audit
756.683 {{res:collection_io_interference_20261021.json:values.audit_timing.wall_s}}
s. Hodinová session (720 riadkov) by pri rovnakom tempe trvala okolo 20 min;
limit kampane je 3 h. Ide o odhad, nie meranie.

Pred ďalším pilotom sa zmenilo prostredie a merací kód: `vm.swappiness = 1`
v `/etc/sysctl.d/90-hyptcn3-collection.conf`, swap sa raz vyprázdnil, runner
pred zahrievaním načíta späť odswapované rozsahy QEMU (`prefault`) a do
`session.json` zapisuje swappiness a swap QEMU. Kampaň swappiness zmrazí.
Disk VM sa vrátil na HDD, teda na iné zariadenie a iný súborový systém ako
výstup snímok (overená kópia so zhodnou SHA-256). Tento pilot sa nepoužije;
opatrenia overí nový pilot.

## 2026-10-21 — druhý pilot zastavený pre `fsync` monitora

Pri rozbore prvého pilota sa ukázala ďalšia väzba na spätný zápis snímok:
monitor hostiteľa volal `fsync` každých 60 s na tom istom súborovom systéme
SSD a počas zápisu plnej snímky čakal (3 s medzera vzoriek, ktorú logový
audit odmieta). Monitor sa zmenil, takže druhý pilot
`20261022T002132864698Z_pilot_bursty` (skupina `pilot-hdd-20261021`, disk VM
už na HDD, `vm.swappiness = 1`) by kampaň aj tak nemohol otvoriť. Bol riadene
zastavený cez `systemctl stop` hneď po prvej snímke
([záznam](../data/results/collection_pilot_hdd_20261021_stopped.json)).
Zastavenie zapísalo pravdivý koncový záznam (`interrupted`, meraná fáza
začala, zberač, generátor a monitor zastavené v tomto poradí). Prvá plná
snímka po čerstvom štarte QEMU mala
461.81 {{res:collection_pilot_hdd_20261021_stopped.json:values.first_full.mib}}
MiB a trvala
1678.6 {{res:collection_pilot_hdd_20261021_stopped.json:values.first_full.read_ms}}
ms; QEMU nemala nič vo swape, krok `prefault` nemal čo načítať. Ide
o diagnostiku, nie o korpus ani o prijatý pilot.

## 2026-10-22 — prijatý pilot 3

Pilot `20261022T003017919708Z_pilot_bursty` (skupina `pilot-3-20261021`,
commit `c15cda4`, profil `bursty`, seed 20261021, nový boot VM) bežal
s opatreniami po prvom pilote: `vm.swappiness = 1`, krok `prefault`, disk
VM na HDD a monitor bez `fsync` počas vzorkovania. Audit ho prijal
([audit](../data/results/collection_pilot_3_20261021_audit.json)):
480 {{res:collection_pilot_3_20261021_audit.json:values.snapshots}}
snímok,
416 {{res:collection_pilot_3_20261021_audit.json:values.windows}}
okien a pokrytie
0.8667 {{res:collection_pilot_3_20261021_audit.json:values.score_coverage}},
čo je strop protokolu. Logový audit nenašiel problém a nálezov integrity bolo
0 {{res:collection_pilot_3_20261021_audit.json:values.quality.integrity_findings}}.

[Súhrn časovania](../data/results/collection_pilot_3_20261021_timing.json):
zberač mal
0 {{res:collection_pilot_3_20261021_timing.json:values.collector_end.errors}}
chýb a
0 {{res:collection_pilot_3_20261021_timing.json:values.collector_end.missed_slots}}
zmeškaných slotov. Plné snímky trvali
1831.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_0.cycle_ms}}
ms a
3483.0 {{res:collection_pilot_3_20261021_timing.json:values.full_snapshots.seq_360.cycle_ms}}
ms (druhá počas súbežného spätného zápisu), delty mali medián
966.7 {{res:collection_pilot_3_20261021_timing.json:values.delta_cycle_ms.p50}}
ms a maximum
2340.1 {{res:collection_pilot_3_20261021_timing.json:values.delta_cycle_ms.max}}
ms. Generátor poslal
122956 {{res:collection_pilot_3_20261021_timing.json:values.traffic.requests}}
požiadaviek s
0 {{res:collection_pilot_3_20261021_timing.json:values.traffic.errors}}
chybami. Najväčšia medzera monitora bola
1.0 {{res:collection_pilot_3_20261021_timing.json:values.monitor_max_gap_s}}
s; QEMU nemala nič vo swape na začiatku ani na konci. Audit trval
563.607 {{res:collection_pilot_3_20261021_timing.json:values.audit_timing.wall_s}}
s. Vstupná brána kampane (`pilot_gate`) prešla bez zmeny meracieho kódu od
pilota.

Zostatkové riziko je čas plnej snímky. Po reštarte skupiny ostáva v RAM hosťa
starý obsah, preto budú plné snímky v kampani väčšie ako v tomto pilote.
V prvom pilote mala druhá plná snímka bez swapu
922.15 {{res:collection_io_interference_20261021.json:values.second_full.mib}}
MiB a trvala
2446.6 {{res:collection_io_interference_20261021.json:values.second_full.read_ms}}
ms. Prekročenie periódy audit zistí ako zmeškaný slot a kampaň zastaví.
Stav pripravenosti je v [PRIPRAVENOST_KAMPANE.sk.md](PRIPRAVENOST_KAMPANE.sk.md).

## 2026-10-22 — kampaň benign-v2-20261022 uzavretá po krížovom rozdiele jednej snímky

Kampaň `benign-v2-20261022` (commit `813ce12`, pilot 3,
48 {{res:collection_campaign_benign_v2_20261022.json:values.planned_sessions}}
plánovaných session) prijala a archivovala dve session
([záznam](../data/results/collection_campaign_benign_v2_20261022.json)).
Session 1 (`write_heavy`) mala
720 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.snapshots}}
snímok,
656 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.windows}}
okien a
0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.collector_end.missed_slots}}
zmeškaných slotov; plné snímky trvali
2090.7 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.full_snapshots_ms.0}}
ms a
2090.6 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.full_snapshots_ms.1}}
ms, najpomalšia delta
1807.2 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.delta_ms.max}}
ms. Generátor poslal
60095 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.requests}}
požiadaviek s
0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.request_errors}}
chybami. Najväčšia medzera monitora bola
2.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.monitor_max_gap_s}}
s; obe vynechané vzorky padli do spätného zápisu plnej snímky na SSD.
Audit 720 snímok trval
927.8 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.stage_s.audit}}
s a archivácia
463.4 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.0.stage_s.archive}}
s. Session 2 (`quiet`) mala plné snímky
2052.1 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.1.full_snapshots_ms.0}}
ms a
2044.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.1.full_snapshots_ms.1}}
ms a medzeru monitora
1.0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.1.monitor_max_gap_s}}
s. Po uzavretí kampane `verify-archives` overil dekompresiou všetky tri
archívy za
196.4 {{res:collection_campaign_benign_v2_20261022.json:values.verify_archives.wall_s}}
s.

Session 3 (`bursty`) zberač zachytil bez chyby
(0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.collector_end.missed_slots}}
zmeškaných slotov,
181634 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.requests}}
požiadaviek s
0 {{res:collection_campaign_benign_v2_20261022.json:values.sessions.2.request_errors}}
chybami), ale audit ju zamietol pre jeden nález integrity a kampaň sa
zastavila ([záznam](../data/results/collection_crossview_race_20261022.json),
[audit](../data/results/collection_crossview_race_20261022_audit.json)).
V snímke
645 {{res:collection_crossview_race_20261022.json:values.old_rule_audit.finding_rows.0.seq}}
bol proces `postgres` s pid
450961 {{res:collection_crossview_race_20261022.json:values.old_rule_audit.finding_rows.0.findings.0.pid}}
v zozname `tasks`, ale nie v strome `children`/`sibling`; oba prechody sa
uzavreli. Rozbor obnoveného reťazca: rodičom bol postmaster (pid
398 {{res:collection_crossview_race_20261022.json:values.probe.task_at_645.parent_pid}}),
proces nemal `PF_EXITING` a v zozname potomkov postmastra
(30 {{res:collection_crossview_race_20261022.json:values.probe.parent_children_at_645}}
položiek) chýbal. Snímky 643 a 644 mali v oboch pohľadoch
109 {{res:collection_crossview_race_20261022.json:values.probe.by_seq.1.tasks}}
procesov, snímka 645
110 {{res:collection_crossview_race_20261022.json:values.probe.by_seq.2.tasks}}
oproti
109 {{res:collection_crossview_race_20261022.json:values.probe.by_seq.2.tree}}
a snímky 646 a 647 znova
109 {{res:collection_crossview_race_20261022.json:values.probe.by_seq.3.tree}}
v oboch. Krátko žijúci potomok postmastra vznikol alebo zanikol medzi
prečítaním stránok s dvoma spojkami; živá snímka (L1) tak vytvorila rozdiel
bez skrývania.

Rozhodnutie: commit `8498670` berie krížový rozdiel za nález až vtedy, keď ho
ukáže aj bezprostredne predchádzajúca snímka tej istej session
([kontroly.md](kontroly.md), L10 v [LIMITACIE.md](LIMITACIE.md)). Opätovný
audit tej istej obnovenej session týmto commitom
([audit](../data/results/collection_crossview_race_20261022_reaudit.json))
ju prijal:
0 {{res:collection_crossview_race_20261022.json:values.confirmation_rule_reaudit.quality.integrity_findings}}
nálezov,
1 {{res:collection_crossview_race_20261022.json:values.confirmation_rule_reaudit.quality.integrity_unconfirmed}}
nepotvrdený rozdiel (snímka 645) a
656 {{res:collection_crossview_race_20261022.json:values.confirmation_rule_reaudit.windows}}
okien. Matica príznakov a maska platných vstupov sú zhodné s pôvodným
auditom; zmenil sa iba záznam kvality snímky 645. Historický verdikt
kampane sa nemení. Kampaň je uzavretá (`closed.json`); session 1 a 2
zostávajú v jej archíve a do novej kampane sa nepresúvajú. Zmena meracieho
kódu vyžaduje nový pilot.

## 2026-10-22 — prijatý pilot 4 s potvrdzovaním krížových rozdielov

Pilot `20261022T073059077133Z_pilot_bursty` (skupina `pilot-4-20261022`,
commit `d25c027`, profil `bursty`, seed 20261022, nový boot VM) overil merací
kód s potvrdzovaním krížových rozdielov. Audit ho prijal
([audit](../data/results/collection_pilot_4_20261022_audit.json)):
480 {{res:collection_pilot_4_20261022_audit.json:values.snapshots}}
snímok,
416 {{res:collection_pilot_4_20261022_audit.json:values.windows}}
okien a pokrytie
0.8667 {{res:collection_pilot_4_20261022_audit.json:values.score_coverage}}
(strop protokolu). Nálezov integrity bolo
0 {{res:collection_pilot_4_20261022_audit.json:values.quality.integrity_findings}}
a nepotvrdených krížových rozdielov
0 {{res:collection_pilot_4_20261022_audit.json:values.quality.integrity_unconfirmed}};
logový audit nenašiel problém.

[Súhrn časovania](../data/results/collection_pilot_4_20261022_timing.json):
pred zahrievaním mala QEMU vo swape
176696 {{res:collection_pilot_4_20261022_timing.json:values.prefault.swap_kb_before}}
kB (po auditoch a obnove kampane v2); krok `prefault` ich za
5.105 {{res:collection_pilot_4_20261022_timing.json:values.prefault.seconds}}
s načítal späť a na konci bolo vo swape
0 {{res:collection_pilot_4_20261022_timing.json:values.host_memory_after.qemu_swap_kb}}
kB. Zberač mal
0 {{res:collection_pilot_4_20261022_timing.json:values.collector_end.missed_slots}}
zmeškaných slotov. Plné snímky mali
901.04 {{res:collection_pilot_4_20261022_timing.json:values.full_snapshots.seq_0.mib}}
a
902.42 {{res:collection_pilot_4_20261022_timing.json:values.full_snapshots.seq_360.mib}}
MiB a trvali
2414.6 {{res:collection_pilot_4_20261022_timing.json:values.full_snapshots.seq_0.cycle_ms}}
a
2421.2 {{res:collection_pilot_4_20261022_timing.json:values.full_snapshots.seq_360.cycle_ms}}
ms; delty mali medián
959.9 {{res:collection_pilot_4_20261022_timing.json:values.delta_cycle_ms.p50}}
ms a maximum
1149.7 {{res:collection_pilot_4_20261022_timing.json:values.delta_cycle_ms.max}}
ms. Generátor poslal
122201 {{res:collection_pilot_4_20261022_timing.json:values.traffic.requests}}
požiadaviek s
0 {{res:collection_pilot_4_20261022_timing.json:values.traffic.errors}}
chybami. Najväčšia medzera monitora bola
1.0 {{res:collection_pilot_4_20261022_timing.json:values.monitor_max_gap_s}}
s. Audit trval
792.98 {{res:collection_pilot_4_20261022_timing.json:values.audit_timing.wall_s}}
s. Pilot je vstupom ďalšej kampane.

## 2026-10-22 — kampaň benign-v3-20261022 uzavretá po roztrhnutom zozname procesov

Kampaň `benign-v3-20261022` (commit `5cafb46`, pilot 4,
48 {{res:collection_campaign_benign_v3_20261022.json:values.planned_sessions}}
plánovaných session) prijala a archivovala dve session
([záznam](../data/results/collection_campaign_benign_v3_20261022.json)).
Session 1 (`write_heavy`) mala
720 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.snapshots}}
snímok,
656 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.windows}}
okien a
0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.collector_end.missed_slots}}
zmeškaných slotov. Plné snímky mali
897.59 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.full_snapshots_mib.0}}
a
888.09 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.full_snapshots_mib.1}}
MiB a trvali
2355.2 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.full_snapshots_ms.0}}
a
2354.1 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.full_snapshots_ms.1}}
ms. Najpomalšia delta (snímka 376) trvala
2648.0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.long_cycles.2.total_ms}}
ms, z toho čítanie
2579.3 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.long_cycles.2.read_ms}}
ms. Generátor poslal
60093 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.requests}}
požiadaviek s
0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.request_errors}}
chybami; najpomalšia požiadavka meranej fázy trvala
1691.0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.measure_latency.max_ms}}
ms. Najväčšia medzera monitora bola
2.01 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.monitor_max_gap_s}}
s. Audit trval
1202.0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.stage_s.audit}}
s a archivácia
452.8 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.stage_s.archive}}
s. Session 2 (`quiet`) mala plné snímky
2346.9 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.1.full_snapshots_ms.0}}
a
2330.9 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.1.full_snapshots_ms.1}}
ms, medzeru monitora
1.04 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.1.monitor_max_gap_s}}
s a najpomalšiu požiadavku
773.1 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.1.measure_latency.max_ms}}
ms. Po uzavretí kampane `verify-archives` overil dekompresiou všetky tri
archívy za
198.7 {{res:collection_campaign_benign_v3_20261022.json:values.verify_archives.wall_s}}
s.

Session 3 (`bursty`) zberač zachytil bez chyby
(0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.collector_end.missed_slots}}
zmeškaných slotov,
180896 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.requests}}
požiadaviek s
0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.request_errors}}
chybami), ale audit ju zamietol pre neúplné vstupy modelu a kampaň sa
zastavila ([záznam](../data/results/collection_process_walk_race_20261022.json),
[audit](../data/results/collection_process_walk_race_20261022_audit.json)).
V snímke 505 sa prechod zoznamu `tasks` dopredu zacyklil. Po
110 {{res:collection_process_walk_race_20261022.json:values.snapshot_505.first_inconsistent_forward_link.at_index}}
procesoch ukazoval `next` posledného vlákna na proces `python3` s pid
388899 {{res:collection_process_walk_race_20261022.json:values.snapshot_505.forward_only_task.pid}}
a `exit_state`
16 {{res:collection_process_walk_race_20261022.json:values.snapshot_505.forward_only_task.exit_state}}
(`EXIT_DEAD`). Jeho `prev` neukazoval späť a jeho `next` viedol späť do
zoznamu. Prechod dozadu sa uzavrel cez
110 {{res:collection_process_walk_race_20261022.json:values.snapshot_505.backward_count}}
procesov; snímky 504 a 506 mali oboma smermi
110 {{res:collection_process_walk_race_20261022.json:values.snapshot_505.neighbors.504.forward_count}}
procesov. Prechod oboma smermi vo všetkých
720 {{res:collection_process_walk_race_20261022.json:values.both_directions_all_snapshots.snapshots}}
snímkach obnovenej session: dopredu sa neuzavrela iba snímka 505, dozadu sa
uzavreli všetky. V snímke 529 sa však prechod dozadu uzavrel cez
78 {{res:collection_process_walk_race_20261022.json:values.both_directions_all_snapshots.directions_differ.5.backward}}
procesov, kým prechod dopredu a susedné snímky mali
110 {{res:collection_process_walk_race_20261022.json:values.both_directions_all_snapshots.directions_differ.5.forward}}.
Uzavretý prechod teda sám nie je dôkaz správnosti. V ďalších piatich
snímkach sa smery líšili o jeden krátko žijúci proces.

Session 3 ukázala aj zmenšujúce sa rezervy. Medzera monitora bola
2.04 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.monitor_max_gap_s}}
s pri
3 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.monitor_missed_ticks}}
vynechaných vzorkách (hranica auditu je 2,5 s). Dve z nich padli do snímky
26, ktorej čítanie trvalo
877.2 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.long_cycles.1.read_ms}}
ms a celý cyklus
1903.6 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.long_cycles.1.total_ms}}
ms. Najpomalšia požiadavka trvala
2348.6 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.measure_latency.max_ms}}
ms a
19 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.2.measure_latency.over_2s}}
požiadaviek prekročilo 2 s (limit klienta bol 4 s).

Rozhodnutie: commit `0b61ffd` berie zoznam procesov dopredu. Keď sa
roztrhne, zoznam tvoria uzly prejdené pred prvým spojením nezhodným
s opačným smerom, ale iba ak sa prechod dozadu uzavrel cez presne tie isté
uzly ([kontroly.md](kontroly.md), L1 v [LIMITACIE.md](LIMITACIE.md)).
Monitor hostiteľa zapisuje riadky z fronty vo vlastnom vlákne a limit klienta
generátora je 10 s ([LAB.sk.md](LAB.sk.md)). Opätovný audit tej istej
obnovenej session týmto commitom
([audit](../data/results/collection_process_walk_race_20261022_reaudit.json))
ju prijal s
656 {{res:collection_process_walk_race_20261022.json:values.confirmed_walk_reaudit.windows}}
oknami,
0 {{res:collection_process_walk_race_20261022.json:values.confirmed_walk_reaudit.quality.integrity_findings}}
nálezmi a prechodom dozadu v snímke
505 {{res:collection_process_walk_race_20261022.json:values.confirmed_walk_reaudit.quality.process_walk_prev_seq.0}}.
Oproti pôvodnému auditu sa zmenili iba riadky 505 (počty procesov
110 {{res:collection_process_walk_race_20261022.json:values.reaudit_vs_audit.vector_changed.0.columns.proc_total.1}}
namiesto
111 {{res:collection_process_walk_race_20261022.json:values.reaudit_vs_audit.vector_changed.0.columns.proc_total.0}})
a 506 (má platného predchodcu). Historický verdikt kampane sa nemení.
Kampaň je uzavretá (`closed.json`); session 1 a 2 zostávajú v jej archíve
a do novej kampane sa nepresúvajú. Zmena meracieho kódu vyžaduje nový pilot.

## 2026-10-22 — prijatý pilot 5 a rast plnej snímky s reštartmi hosťa

Pilot `20261022T142659087837Z_pilot_bursty` (skupina `pilot-5-20261022`,
commit `e774c69` s meracím kódom z `0b61ffd`, profil `bursty`, seed
202610225, nový boot VM) overil potvrdenie roztrhnutého zoznamu procesov
prechodom dozadu, zapisovanie monitora z fronty vo vlákne a limit klienta
10 s. Audit ho prijal
([audit](../data/results/collection_pilot_5_20261022_audit.json)):
480 {{res:collection_pilot_5_20261022_audit.json:values.snapshots}}
snímok,
416 {{res:collection_pilot_5_20261022_audit.json:values.windows}}
okien a pokrytie
0.8667 {{res:collection_pilot_5_20261022_audit.json:values.score_coverage}}
(strop protokolu). Nálezov integrity bolo
0 {{res:collection_pilot_5_20261022_audit.json:values.quality.integrity_findings}}
a nepotvrdených krížových rozdielov
0 {{res:collection_pilot_5_20261022_audit.json:values.quality.integrity_unconfirmed}};
žiadna snímka nepotrebovala prechod dozadu a logový audit nenašiel problém.

[Súhrn časovania](../data/results/collection_pilot_5_20261022_timing.json):
pred zahrievaním mala QEMU vo swape
220912 {{res:collection_pilot_5_20261022_timing.json:values.prefault.swap_kb_before}}
kB (po obnove a overení archívov kampane v3); krok `prefault` ich za
6.708 {{res:collection_pilot_5_20261022_timing.json:values.prefault.seconds}}
s načítal späť a na konci bolo vo swape
0 {{res:collection_pilot_5_20261022_timing.json:values.host_memory_after.qemu_swap_kb}}
kB. Zberač mal
0 {{res:collection_pilot_5_20261022_timing.json:values.collector_end.missed_slots}}
zmeškaných slotov; delty mali medián
945.2 {{res:collection_pilot_5_20261022_timing.json:values.delta_cycle_ms.p50}}
ms a maximum
1176.6 {{res:collection_pilot_5_20261022_timing.json:values.delta_cycle_ms.max}}
ms. Generátor poslal
122001 {{res:collection_pilot_5_20261022_timing.json:values.traffic.requests}}
požiadaviek s
0 {{res:collection_pilot_5_20261022_timing.json:values.traffic.errors}}
chybami; najpomalšia požiadavka meranej fázy trvala
2003.5 {{res:collection_pilot_5_20261022_timing.json:values.measure_latency.max_ms}}
ms. Monitor mal
0 {{res:collection_pilot_5_20261022_timing.json:values.monitor_missed_ticks}}
vynechaných vzoriek. Audit trval
826.61 {{res:collection_pilot_5_20261022_timing.json:values.audit_timing.wall_s}}
s.

Plné snímky boli väčšie ako v predchádzajúcich behoch:
269600 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_0.pages}}
a
271254 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.pages}}
stránok za
2691.4 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_0.cycle_ms}}
a
2735.9 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.cycle_ms}}
ms. Všetkých
19 {{res:collection_full_snapshot_growth_20261022.json:n}}
plných snímok pilotov a kampaní od 2026-10-22 00:12 UTC prečítal zberač
z jedného procesu QEMU
([záznam](../data/results/collection_full_snapshot_growth_20261022.json)).
Plná snímka číta stránky, ktoré hostiteľ hosťovi pridelil, a tých
s reštartmi hosťa pribúdalo: pri prvom boote
117993 {{res:collection_full_snapshot_growth_20261022.json:values.by_guest_boot.0.pages_min}}
stránok, pri šiestom
271254 {{res:collection_full_snapshot_growth_20261022.json:values.by_guest_boot.5.pages_max}}
z
524353 {{res:collection_full_snapshot_growth_20261022.json:values.guest_pages_total}}.
Priamka času cyklu podľa počtu stránok (bez plnej snímky pilota 3 so
súbežným spätným zápisom) má sklon
0.0066 {{res:collection_full_snapshot_growth_20261022.json:values.fit_cycle_ms_per_page.slope_ms}}
ms na stránku a posun
875.7 {{res:collection_full_snapshot_growth_20261022.json:values.fit_cycle_ms_per_page.intercept_ms}}
ms. Pri všetkých stránkach hosťa by plná snímka trvala okolo
4355.3 {{res:collection_full_snapshot_growth_20261022.json:values.estimate_all_pages_ms}}
ms pri perióde 5 s; ide o odhad, nie meranie. Kampaň má 8 skupín a každá
začína reštartom hosťa. Pred kampaňou sa preto VM vypne a znova spustí
(nový proces QEMU), aby plné snímky začínali na malom počte stránok.
Pilot je vstupom ďalšej kampane.

## 2026-10-25 — kampaň benign-v4-20261022 uzavretá po zmeškanom slote pri spätnom zápise na SSD

Kampaň `benign-v4-20261022` (commit `cbea764`, pilot 5,
48 {{res:collection_campaign_benign_v4_20261022.json:values.planned_sessions}}
plánovaných session) prijala a archivovala
36 {{res:collection_campaign_benign_v4_20261022.json:values.summary.accepted_sessions}}
session ([záznam](../data/results/collection_campaign_benign_v4_20261022.json)).
Každá prijatá mala
656 {{res:collection_campaign_benign_v4_20261022.json:values.summary.windows_min}}
okien; spolu mali
0 {{res:collection_campaign_benign_v4_20261022.json:values.summary.integrity_findings}}
nálezov integrity,
0 {{res:collection_campaign_benign_v4_20261022.json:values.summary.accepted_missed_slots}}
zmeškaných slotov a
0 {{res:collection_campaign_benign_v4_20261022.json:values.summary.accepted_collector_errors}}
chýb zberača. Plné snímky mali
129609 {{res:collection_campaign_benign_v4_20261022.json:values.summary.full_pages_min}}
až
323173 {{res:collection_campaign_benign_v4_20261022.json:values.summary.full_pages_max}}
stránok a trvali
1745.1 {{res:collection_campaign_benign_v4_20261022.json:values.summary.full_ms_min}}
až
3022.7 {{res:collection_campaign_benign_v4_20261022.json:values.summary.full_ms_max}}
ms. Vo všetkých
37 {{res:collection_campaign_benign_v4_20261022.json:n}}
session (vrátane zamietnutej session 37) poslal generátor
2494474 {{res:collection_campaign_benign_v4_20261022.json:values.summary.requests}}
požiadaviek s
0 {{res:collection_campaign_benign_v4_20261022.json:values.summary.request_errors}}
chybami; najpomalšia požiadavka meranej fázy trvala
2252.5 {{res:collection_campaign_benign_v4_20261022.json:values.summary.measure_latency_max_ms}}
ms. Najväčšia medzera monitora bola
1.05 {{res:collection_campaign_benign_v4_20261022.json:values.summary.monitor_max_gap_s}}
s pri
0 {{res:collection_campaign_benign_v4_20261022.json:values.summary.monitor_missed_ticks}}
vynechaných vzorkách. Po uzavretí kampane `verify-archives` overil
dekompresiou všetkých
37 {{res:collection_campaign_benign_v4_20261022.json:values.verify_archives.n_verified}}
archívov za
2800.0 {{res:collection_campaign_benign_v4_20261022.json:values.verify_archives.wall_s}}
s.

Kampaň mala tri prevádzkové odchýlky. Obe zastavenia runnera cez
`request-stop` sú v `operator_stop_requests` a `stopped_states` (tam je
navyše zastavenie po session 1 na hranici `--stop-after` a záverečný stav
`error`) a nový proces QEMU v `groups`; časy žiadostí o zastavenie a samotných
zastavení sú strojové záznamy (`operator_stop_requests[].date`,
`stopped_states[].updated_at`). Dôvody zastavení, časy vypnutia VM
a `fstrim` a zmeškaný reštart sú vyjadrenia operátora z logu relácie,
zapísané iba v poznámke záznamu (`values.note`). Plné snímky rástli
s vekom procesu QEMU (pozri opravu nižšie), preto operátor so súhlasom
zadávateľa plánoval reštart VM na hraniciach skupín. Reštart pred skupinou
`calibration-2` (po session 30) nestihol, takže skupiny `train-1` až
`calibration-2` bežali na jednom procese QEMU. Po session 33 runner zastavil
cez `request-stop` iba kvôli `fstrim` SSD, bez zásahu do VM. Po session 36 ho
zastavil pred skupinou `test_benign-1`, VM korektne vypol a spustil (nový
proces QEMU
1838642 {{res:collection_campaign_benign_v4_20261022.json:values.groups.test_benign-1.qemu.pid}},
studený boot) a znovu spustil `fstrim`.

Session 37 (`test_benign`, `mixed`, prvá na novom procese QEMU) audit
zamietol a kampaň sa zastavila
([záznam](../data/results/collection_writeback_stall_20261024.json),
[audit](../data/results/collection_writeback_stall_20261024_audit.json)).
Cyklus 369 trval
5082.8 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.total_ms}}
ms pri perióde 5 s, plánovač zahodil
1 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.36.scheduler_skips.0.slots}}
slot a audit session zamietol pre cyklus dlhší než perióda a zmeškaný slot.
Cyklus začal
43.2 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.seconds_after_full}}
s po plnej snímke so
574.95 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.36.full_snapshots.1.mib}}
MiB. Vo všetkých
4 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.samples_whole_interval}}
vzorkách monitora hostiteľa, ktorých celý interval ležal v cykle, bolo SSD
(`sda`) vyťažené na
99.2 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.series.26.sda_util_pct}}
až
100 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.sda_util_max_pct}}
% pri zápise
4.19 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.sda_write_mb_s_min}}
až
8.39 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.sda_write_mb_s_max}}
MB/s. Zberač mal v prvej z nich
12 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.series.26.collector_cpu_pct}}
% CPU a v ďalších troch
0 {{res:collection_writeback_stall_20261024.json:values.events_over_4500_ms.benign-v4-20261022_37_test_benign_mixed#369.collector_cpu_min_pct}}
%: jadro práve zapisovalo neuložené dáta snímok z page cache. Zberač verzie
1.0 vytváral, zapisoval a premenúval súbory snímok a hašoval delta súbory
vo vzorkovacom vlákne v meranom cykle, takže čakanie disku sa pripočítalo
k cyklu (SHA-256 plnej snímky počítalo pri `output.hash_async` samostatné
vlákno po cykle). Sidecar delty a riadok logu zapisovalo to isté vlákno až
po zmeraní cyklu, takže cyklus nepredĺžili; plánovač ich započítal iba do
slotu. Z
26640 {{res:collection_writeback_stall_20261024.json:n}}
cyklov kampane bolo
25 {{res:collection_writeback_stall_20261024.json:values.long_delta_cycles}}
delta cyklov dlhších než 2 s. V
22 {{res:collection_writeback_stall_20261024.json:values.long_delta_cycles_with_sda_util_ge_99}}
z nich mal SSD vyťaženie 99 % a viac vo vzorke monitora, ktorej celý
interval ležal v cykle. V zvyšných troch (session 14 cyklus 54, session 26
cyklus 417, session 36 cyklus 563) mala 99 % a viac iba vzorka, ktorej
interval začal pred cyklom a do cyklu zasahoval
0.407 {{res:collection_writeback_stall_20261024.json:values.cycles.17.boundary.in_cycle_s}}
až
0.865 {{res:collection_writeback_stall_20261024.json:values.cycles.23.boundary.in_cycle_s}}
s; vzorky celé v cykle tam mali
66.8 {{res:collection_writeback_stall_20261024.json:values.cycles.23.sda_util_max_pct}}
až
88.4 {{res:collection_writeback_stall_20261024.json:values.cycles.17.sda_util_max_pct}}
% a vzorka, ktorej interval presahoval koniec cyklu, najviac
22 {{res:collection_writeback_stall_20261024.json:values.cycles.5.end_boundary.sda_util_pct}}
%. Najbližšie k limitu
bola predtým session 35 s
4680.1 {{res:collection_campaign_benign_v4_20261022.json:values.summary.delta_ms_max_accepted}}
ms. Ktoré volanie v cykle čakalo, záznam nezachytáva.

Rozhodnutie: commit `625d8f9` (zberač 1.1) presúva všetku prácu so
súbormi a s logom mimo vzorkovacieho cyklu: zmenené stránky sa kopírujú do
uzamknutej fronty v pamäti a súbory, SHA-256, sidecar, hooky a retenciu
robí vlákno `vmic-writer`, log vlákno `vmic-log` ([AUTOMATICKY_ZBER.sk.md](AUTOMATICKY_ZBER.sk.md),
[METODIKA_ZBERU.sk.md](METODIKA_ZBERU.sk.md)). Podmienky prijatia sa
nemenia; audit navyše zamietne každé čakanie na pamäť fronty. Opätovný audit
session 37 nie je možný - zmeškaný slot je v nameraných dátach. Historický
verdikt kampane sa nemení. Kampaň je uzavretá (`closed.json`); session 1 až
36 zostávajú v jej archíve a do novej kampane sa nepresúvajú. Zmena
meracieho kódu vyžaduje nový pilot.

## 2026-10-25 — oprava: plná snímka rástla aj v rámci jedného bootu hosťa

Záznam „2026-10-22 — prijatý pilot 5 a rast plnej snímky s reštartmi hosťa“
pripisuje rast plnej snímky reštartom hosťa na jednom procese QEMU. Kampaň
`benign-v4-20261022` ukázala, že rastie aj v rámci jedného bootu
([záznam](../data/results/collection_campaign_benign_v4_20261022.json),
`values.summary.by_group`): skupina `train-1` (jeden boot) začala na
129609 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-1.first_full_pages}}
stránkach a skončila na
252248 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-1.last_full_pages}},
skupina `train-2` začala na
263336 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-2.first_full_pages}}
a skončila na
284782 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-2.last_full_pages}}.
Skupina `train-3` klesla na
289920 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.14.full_snapshots.1.pages}}
stránok a skončila na
294716 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-3.last_full_pages}},
len o málo vyššie, než začala. V skupinách `dev-1`, `calibration-1`
a `calibration-2` už v rámci bootu nerástol (každá skončila nižšie, než
začala; skupina `dev-1` začala na
306095 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.dev-1.first_full_pages}}
a skončila na
303119 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.dev-1.last_full_pages}}
stránkach), no po každom reštarte hosťa začala skupina vyššie, než skončila
predchádzajúca: `train-3` na
294419 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.train-3.first_full_pages}},
`dev-1` na
306095 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.dev-1.first_full_pages}},
`calibration-1` na
319482 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.calibration-1.first_full_pages}}
a `calibration-2` na
323173 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.calibration-2.first_full_pages}}
stránkach. Lineárny model a odhad pre všetky stránky z pôvodného záznamu
zostávajú; pôvodný záznam aj jeho JSON zostávajú zachované. Plná snímka
teda rastie v rámci bootu (v tejto kampani na prvom procese QEMU
v skupinách `train-1` a `train-2`, v `train-3` len o málo) aj s reštartmi
hosťa a závisí od veku procesu QEMU, nielen od počtu reštartov
hosťa (dôsledok pre príznaky je v L13 v [LIMITACIE.md](LIMITACIE.md)).

## 2026-10-25 — oprava: „čítanie“ zberača do verzie 1.0 zahŕňalo zápis stránok

Záznamy kampaní a pilotov uvádzajú hodnotu `citanie` z logu zberača
(v súhrnoch `read_ms`) ako čas čítania pamäte, napríklad „z toho čítanie
2579.3 ms“ v zázname „2026-10-22 — kampaň benign-v3-20261022 uzavretá po
roztrhnutom zozname procesov“. Do verzie zberača 1.0 to bol čas celej
čítacej slučky vrátane dvoch volaní `write()` pre každú zmenenú stránku
(delta writer, `vmicollect/src/writer_delta.c` v commite `cbea764`), takže
dlhé „čítanie“ mohlo byť čakanie na zápis na disk. Rozdiel medzi celým
cyklom a „čítaním“ preto nebol čas zápisu stránok, ale práca cyklu pred
čítacou slučkou a po nej: obnova memslotov a parametrov VM, vytvorenie
súboru `.part` so zápisom hlavičky (`delta_begin`), oprava hlavičky dvoma
`pwrite()`, `close`, premenovanie, `stat` a SHA-256 delty (`delta_finish`).

Rovnako to platí pre záznamy z 2026-09-18, ktoré nie sú kampane ani piloty:
„2026-09-18 — prvý beh zberača `vmicollect` nad bežiacou doménou“ (časti
„once, writer `raw`“, „run, writer `delta`“, „Plná snímka naprieč všetkými
behmi dňa“ a „Výkonová chyba v raw writeri a jej odstránenie“), časť 3
záznamu „2026-09-18 — doplnenia a retrakcie k prvému behu, prvé merania
binárkou z repa (K06)“ a časť „Optimalizácia: kontrolný súčet“ záznamu
„2026-09-18 — meranie na zmrazenom hosťovi (bez agenta v hosťovi)“. Ich
„čítanie“, `capture_ms` a `read_mib_s` obsahujú aj prácu writera vo
`feed()`: delta writer v ňom volal dvakrát `write()` na zmenenú stránku,
raw writer `pwrite()` pre každý nenulový blok (`vmicollect/src/writer_raw.c`
v commite `178ce4f`). Nie sú to teda čisté časy ani rýchlosti čítania
pamäte. Na rozdiel od kampaní volal `finish()` v týchto behoch vždy
`fsync()`, takže ich „zápis“ (rozdiel celého cyklu a čítania) obsahoval aj
zápis na disk.

Od verzie 1.1 je čistý čas čítania
pamäte v sidecari `capture.backend_read_ms`. Pri delta writeri
(`output.async: true`, kampane a piloty) `capture_ms` už neobsahuje
žiadny zápis na disk ([ARCHITEKTURA.md](ARCHITEKTURA.md), časť 6); pri raw
writeri `capture_ms` aj vo verzii 1.1 obsahuje zápis blokov (`pwrite()`
vo `feed()`, `vmicollect/src/writer_raw.c` v commite `625d8f9`). Pôvodné
záznamy zostávajú zachované.

## 2026-10-25 — diagnostika zberača 1.1 pri umelej záťaži SSD

Diagnostický beh `20261025T042258276904Z_diagnostic_write_heavy` (skupina `diag-writer-20261025`, commit
`625d8f9`, profil `write_heavy`, seed
20261025 {{res:collection_writer_diagnostic_20261025_timing.json:values.seed}},
480 cyklov, mimo korpusu)
overil zberač 1.1 so zápisom vo vlákne na zberovom PC
([súhrn](../data/results/collection_writer_diagnostic_20261025_timing.json),
[audit](../data/results/collection_writer_diagnostic_20261025_audit.json)). Audit ho prijal:
480 {{res:collection_writer_diagnostic_20261025_audit.json:values.snapshots}}
snímok a
416 {{res:collection_writer_diagnostic_20261025_audit.json:values.windows}}
okien. Zberač si pred meraním uzamkol pamäť za
1.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_mlock.seconds}}
s (VmRSS
2596 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_mlock.vmrss_mib}}
MiB, fronta
2689597440 {{res:collection_writer_diagnostic_20261025_timing.json:values.writer.pool_bytes}}
bajtov). Plné snímky mali
177839 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_snapshots.seq_0.pages}}
a
185293 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_snapshots.seq_360.pages}}
stránok a cyklus trval
1509.2 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_snapshots.seq_0.total_ms}}
a
1539.6 {{res:collection_writer_diagnostic_20261025_timing.json:values.full_snapshots.seq_360.total_ms}}
ms. Delta cykly mali medián
823.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.delta_total_ms.p50}}
ms a maximum
870.8 {{res:collection_writer_diagnostic_20261025_timing.json:values.delta_total_ms.max}}
ms. Čakanie na pamäť fronty bolo najviac
0.0 {{res:collection_writer_diagnostic_20261025_timing.json:values.queue_wait_ms_max}}
ms a zberač skončil s
480 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_end.snapshots}}
snímkami,
0 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_end.errors}}
chybami a
0 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_end.missed_slots}}
zmeškanými slotmi; fronta na konci dobehla bez straty
(`zapisovac: 480 zverejnenych, 0 zlyhanych, 0 zahodenych, 0 nezapisanych, najvacsia fronta 0 snimok (0 B), najdlhsie zverejnenie 4.971 s, cakanie na pamat fronty 0.0 ms v 0 cykloch, dobehnutie 0.068 s`).

Vlákno `vmic-writer` malo dáta zapísané a zatvorené
(`data_closed_ms`, od začiatku cyklu; sidecar a obe premenovania nasledujú,
takže je to dolná hranica zverejnenia) v mediáne za
898.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.data_closed_ms.p50}}
ms a najneskôr za
4971.3 {{res:collection_writer_diagnostic_20261025_timing.json:values.data_closed_ms.max}}
ms pri druhej plnej snímke (seq
360 {{res:collection_writer_diagnostic_20261025_timing.json:values.data_closed_ms.max_seq}}); najdlhšie operácie vlákna boli
`vytvorenie 0.648 s, zapis 3.432 s, fsync 0.000 s, sidecar 0.006 s, rename 1.048 s, hook 0.000 s, retencia 0.000 s`. Tento čas cyklus nepredlžuje.

Po druhej plnej snímke zapísal skript `ballast.sh` (v adresári
záznamu) na ten istý súborový systém SSD 6 GiB náhodných dát s jedným
`fdatasync`, aby disk zahltil podobne ako spätný zápis v kampani
`benign-v4-20261022`. Záťaž trvala
71.7 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.duration_s}}
s; monitor v nej mal
72 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.monitor_samples}}
vzoriek, z toho
65 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.samples_sda_util_ge_99}}
s vyťažením `sda` aspoň 99 %, zápis pri plnom vyťažení klesal až na
4.2 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.sda_write_mb_s_min_when_saturated}}
MB/s a `Dirty` vystúpilo na
1877 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.dirty_mib_max}}
MiB. Zberač v tom čase dokončil
14 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.cycles}}
cyklov, najdlhší za
860.8 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.cycle_total_ms_max}}
ms (medián
836.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.cycle_total_ms_p50}}
ms). Čas po zapísané a zatvorené dáta (`data_closed_ms`) mal v záťaži
medián
933.5 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.data_closed_ms_p50}}
ms a najviac
1588.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.data_closed_ms_max}}
ms; po záťaži mal pri
100 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.after_snapshots}}
snímkach medián
897.5 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.after_data_closed_ms_p50}}
ms a najviac
940.8 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.after_data_closed_ms_max}}
ms. Celé zverejnenie (so sidecarom a premenovaniami) záznam pre jednotlivé
snímky nemá, súhrn zapisovača uvádza iba maximum za celý beh. Počas zberu
bolo QEMU vo swape najviac
2588 {{res:collection_writer_diagnostic_20261025_timing.json:values.during_capture.qemu_swap.max_kb}}
kB, stránok odsunutých do swapu pribudlo
4471 {{res:collection_writer_diagnostic_20261025_timing.json:values.during_capture.pswpout_delta}}
a `Mlocked` hostiteľa bolo najviac
2609 {{res:collection_writer_diagnostic_20261025_timing.json:values.during_capture.mlocked_mib_max}}
MiB. Monitor mal najväčšiu medzeru
1.00 {{res:collection_writer_diagnostic_20261025_timing.json:values.monitor_max_gap_s}}
s a generátor
0 {{res:collection_writer_diagnostic_20261025_timing.json:values.traffic.errors}}
chýb. Audit trval
582.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.audit_timing.wall_s}}
s.

Kritériá diagnostiky boli určené pred behom v pracovných poznámkach mimo
repozitára; v repozitári ani v zázname nie sú, takže to, že vznikli pred
behom, repozitár nedokladá. Bolo ich sedem: (1) každý cyklus kratší než 4 s
(0,8 periódy, hranica tejto diagnostiky; audit zamieta až cyklus, ktorý
dosiahne periódu 5 s), (2) dĺžka cyklu nesleduje vyťaženie SSD, (3) nulové
čakanie na pamäť fronty, (4) koniec s toľkými snímkami, koľko bolo cyklov,
bez chýb, zmeškaných slotov a riadkov `ERROR` v logu
(0 {{res:collection_writer_diagnostic_20261025_timing.json:values.log_error_lines}}),
(5) čas po zapísané dáta (`data_closed_ms`) sa pri záťaži predĺži a po nej
vráti, (6) zaznamenané dobehnutie fronty a (7) QEMU bez swapu (swap QEMU
0 kB a žiadne nové odsunuté stránky). Beh splnil kritériá 1 až 6 a
nesplnil kritérium 7. Kritérium 3 sa nemohlo porušiť, lebo fronta pri
žiadnej snímke nedržala čakajúcu snímku (najviac
0 {{res:collection_writer_diagnostic_20261025_timing.json:values.writer.queue_jobs_max}}
úloh); kapacitu fronty pri nahromadení zápisu teda beh neoveril. Kritérium 5
dokladá záznam iba dolnou hranicou zverejnenia.

Počas záťaže, ktorá trvala
71.7 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.duration_s}}
s, jadro odsunulo do swapu
4468 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.pswpout_delta_in_ballast}}
stránok (rozdiel `pswpout` za celé okno záťaže; kedy v ňom, záznam
neuvádza), z toho
2588 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.first_sample_qemu_swap_kb}}
kB pamäte QEMU naraz medzi dvoma vzorkami (prvá vzorka so swapom QEMU
o 04:55:44 UTC, záťaž začala o 04:55:34 UTC; potom swap QEMU už nerástol),
hoci `vm.swappiness` je 1 a `MemAvailable` neklesla pod
10208 {{res:collection_writer_diagnostic_20261025_timing.json:values.during_capture.mem_available_mib_min}}
MiB; page cache klesla z
7902 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.cached_mib_before_ballast}}
MiB pred záťažou najnižšie na
3556 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.cached_mib_min_in_ballast}}
MiB v okne záťaže. Pred záťažou pribudli
3 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.pswpout_delta_before_ballast}}
odsunuté stránky, po nej
0 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.monitor.pswpout_delta_after_ballast}}.
Podľa `/proc/PID/smaps` prečítaného po zbere
([záznam](../data/results/collection_writer_diagnostic_20261025_qemu_swap.json))
ležalo všetkých
2580 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.swapped_kb_outside_guest_ram}}
kB odsunutej pamäte QEMU v
31 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:n}}
iných mapovaniach (anonymné oblasti a súkromné stránky binárky QEMU
a jej knižníc);
mapovanie pamäte hosťa malo vo swape
0 {{res:collection_writer_diagnostic_20261025_qemu_swap.json:values.guest_ram_mapping.swap_kb}}
kB. Zberač číta každú stránku hosťa v každom cykle cez
`access_process_vm`, ktoré odsunutú stránku vráti zo swapu (režim `swap`
testu `gup_fault_check.c` nižšie), takže 0 kB po zbere nevylučuje, že jadro
stránku hosťa počas záťaže na chvíľu odsunulo; či čítanie zberača stránky
hosťa pred odsunutím chráni, záznam nemeria. Najdlhší cyklus v záťaži bol
kratší než najdlhší delta cyklus behu
(860.8 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.cycle_total_ms_max}}
ms proti
870.8 {{res:collection_writer_diagnostic_20261025_timing.json:values.delta_total_ms.max}}
ms), medián v záťaži bol
836.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.cycle_total_ms_p50}}
ms proti
823.1 {{res:collection_writer_diagnostic_20261025_timing.json:values.delta_total_ms.p50}}
ms za celý beh. Vzorkovacie vlákno, ktoré stránky hosťa číta, nemalo
v žiadnom cykle veľký výpadok stránky (`majflt` najviac
0 {{res:collection_writer_diagnostic_20261025_timing.json:values.rusage_max.majflt}}).
Veľký výpadok, pri ktorom jadro číta stránku z disku, pripisuje pri čítaní
cez `access_process_vm` čítajúcemu vláknu; test `gup_fault_check.c`
s [výstupom](../data/results/collection_writer_diagnostic_20261025/gup_fault_check.txt)
v adresári záznamu to overil pre stránky súboru mimo page cache (`majflt`
+1 pri 256 stránkach načítaných z disku). Pamäť hosťa je anonymná a z disku
by sa vracala zo swapu na HDD; ten prípad test neoveril (v režime `swap`
mal `majflt` +0 a nezaznamenal, či stránky prišli zo swap cache alebo
z disku) a že ho jadro počíta ako veľký výpadok čítajúceho vlákna, sa
opiera iba o kód jadra. Nulový `majflt` teda ukazuje nanajvýš to, že
vzorkovacie vlákno samo nespustilo čítanie stránky hosťa zo swapu, nie že
na disk nečakalo: podľa kódu jadra je malým výpadkom aj stránka, ktorú zo
swapu už načítava iné vlákno (napríklad vlákno vCPU QEMU), aj stránka
vrátená zo swap cache bez čítania z disku.
Odsunutie pamäte QEMU nie je nové:
v kampani `benign-v4-20261022` ho monitor zachytil v session 14 (najviac
5744 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.13.qemu_swap_during.kb_max}}
kB, [záznam](../data/results/collection_campaign_benign_v4_20261022.json)). Keby jadro odsunulo stránku hosťa,
zberač ju načíta zo swapu na HDD a cyklus sa predĺži; dlhý cyklus audit
zistí.

Diagnostika nenahrádza pilot: trvala 40 minút, záťaž iba
71.7 {{res:collection_writer_diagnostic_20261025_timing.json:values.ballast.duration_s}}
s a degradáciu SSD po hodinách zápisu nenapodobňuje. Ak by disk dlhodobo
zapisoval pomalšie, než zberač produkuje dáta, fronta sa zaplní a audit
session zamietne pre čakanie na pamäť fronty. Podmienky prijatia overí
pilot 6.

## 2026-10-25 — pilot 6 so zberačom 1.1

Pilot `20261025T083820398613Z_pilot_bursty` (skupina `pilot-6-20261025`, commit
`cd67470` so zberačom 1.1, profil `bursty`, seed
202610256 {{res:collection_pilot_6_20261025_timing.json:values.seed}},
nový boot hosťa na procese QEMU
1838642 {{res:collection_pilot_6_20261025_timing.json:values.qemu.pid}},
na ktorom bežala aj session 37 kampane v4) overil zberač, ktorý robí prácu
so súbormi a s logom mimo vzorkovacieho cyklu. Audit ho prijal
([audit](../data/results/collection_pilot_6_20261025_audit.json)):
480 {{res:collection_pilot_6_20261025_audit.json:values.snapshots}}
snímok,
416 {{res:collection_pilot_6_20261025_audit.json:values.windows}}
okien a pokrytie
0.8667 {{res:collection_pilot_6_20261025_audit.json:values.score_coverage}}
(strop protokolu). Nálezov integrity bolo
0 {{res:collection_pilot_6_20261025_audit.json:values.quality.integrity_findings}}
a nepotvrdených krížových rozdielov
0 {{res:collection_pilot_6_20261025_audit.json:values.quality.integrity_unconfirmed}}.

[Súhrn časovania](../data/results/collection_pilot_6_20261025_timing.json): pred zahrievaním mal proces QEMU
vo swape
4132 {{res:collection_pilot_6_20261025_timing.json:values.prefault.swap_kb_before}}
kB; krok `prefault` ich za
0.728 {{res:collection_pilot_6_20261025_timing.json:values.prefault.seconds}}
s načítal späť. Počas zberu bolo QEMU vo swape najviac
0 {{res:collection_pilot_6_20261025_timing.json:values.during_capture.qemu_swap.max_kb}}
kB a na konci
0 {{res:collection_pilot_6_20261025_timing.json:values.host_memory_after.qemu_swap_kb}}
kB. Zberač si pred meraním uzamkol pamäť (VmRSS
2596 {{res:collection_pilot_6_20261025_timing.json:values.collector_mlock.vmrss_mib}}
MiB, `Mlocked` hostiteľa počas zberu najviac
2609 {{res:collection_pilot_6_20261025_timing.json:values.during_capture.mlocked_mib_max}}
MiB) a skončil s
480 {{res:collection_pilot_6_20261025_timing.json:values.collector_end.snapshots}}
snímkami,
0 {{res:collection_pilot_6_20261025_timing.json:values.collector_end.errors}}
chybami a
0 {{res:collection_pilot_6_20261025_timing.json:values.collector_end.missed_slots}}
zmeškanými slotmi; riadkov `ERROR` v logu bolo
0 {{res:collection_pilot_6_20261025_timing.json:values.log_error_lines}}.
Najdlhší cyklus trval
1579.9 {{res:collection_pilot_6_20261025_timing.json:values.cycle_total_ms_max}}
ms pri perióde 5 s. Plné snímky mali
186537 {{res:collection_pilot_6_20261025_timing.json:values.full_snapshots.seq_0.pages}}
a
187360 {{res:collection_pilot_6_20261025_timing.json:values.full_snapshots.seq_360.pages}}
stránok a cyklus trval
1572.5 {{res:collection_pilot_6_20261025_timing.json:values.full_snapshots.seq_0.total_ms}}
a
1579.9 {{res:collection_pilot_6_20261025_timing.json:values.full_snapshots.seq_360.total_ms}}
ms, z toho čítanie pamäte
320.2 {{res:collection_pilot_6_20261025_timing.json:values.full_backend_read_ms.seq_0}}
a
311.9 {{res:collection_pilot_6_20261025_timing.json:values.full_backend_read_ms.seq_360}}
ms. Delta cykly mali medián
860.9 {{res:collection_pilot_6_20261025_timing.json:values.delta_total_ms.p50}}
ms a maximum
884.5 {{res:collection_pilot_6_20261025_timing.json:values.delta_total_ms.max}}
ms. Čakanie na pamäť fronty bolo najviac
0.0 {{res:collection_pilot_6_20261025_timing.json:values.queue_wait_ms_max}}
ms a fronta pri odovzdaní snímky najviac
0 {{res:collection_pilot_6_20261025_timing.json:values.writer.queue_jobs_max}}
úloh. Vlákno `vmic-writer` malo dáta zapísané a zatvorené
(`data_closed_ms`, dolná hranica zverejnenia) v mediáne za
950.0 {{res:collection_pilot_6_20261025_timing.json:values.data_closed_ms.p50}}
ms a najneskôr za
5125.6 {{res:collection_pilot_6_20261025_timing.json:values.data_closed_ms.max}}
ms pri plnej snímke seq
0 {{res:collection_pilot_6_20261025_timing.json:values.data_closed_ms.max_seq}},
teda dlhšie než perióda, ale mimo vzorkovacieho cyklu. Keďže fronta pri
žiadnom odovzdaní nedržala nedokončenú úlohu, zápis plnej snímky skončil
skôr, než prišla nasledujúca snímka. Súhrn zapisovača:
`zapisovac: 480 zverejnenych, 0 zlyhanych, 0 zahodenych, 0 nezapisanych, najvacsia fronta 0 snimok (0 B), najdlhsie zverejnenie 5.126 s, cakanie na pamat fronty 0.0 ms v 0 cykloch, dobehnutie 0.108 s`.

Generátor poslal
121655 {{res:collection_pilot_6_20261025_timing.json:values.traffic.requests}}
požiadaviek s
0 {{res:collection_pilot_6_20261025_timing.json:values.traffic.errors}}
chybami; najpomalšia požiadavka meranej fázy trvala
2073.8 {{res:collection_pilot_6_20261025_timing.json:values.measure_latency.max_ms}}
ms. Monitor mal najväčšiu medzeru
1.00 {{res:collection_pilot_6_20261025_timing.json:values.monitor_max_gap_s}}
s a
0 {{res:collection_pilot_6_20261025_timing.json:values.monitor_missed_ticks}}
vynechaných vzoriek; SSD bolo vyťažené na 99 % a viac v
12 {{res:collection_pilot_6_20261025_timing.json:values.during_capture.sda_util_ge_99_samples}}
vzorkách monitora počas zberu. Audit trval
651.5 {{res:collection_pilot_6_20261025_timing.json:values.audit_timing.wall_s}}
s.

Podmienky prijatia pilota (každý cyklus kratší než perióda, žiadny
zmeškaný slot) sa oproti pilotu 5 nezmenili. Pilot je vstupom kampane
`benign-v5`; pred jej `campaign.py init` sa VM vypne a znova spustí (nový
proces QEMU) a počas kampane sa nereštartuje (L13 v
[LIMITACIE.md](LIMITACIE.md)).
