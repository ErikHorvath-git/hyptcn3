# Limitácie

Zoznam vedomých obmedzení tejto práce. Každé je overené v zdrojovom kóde alebo v uložených
artefaktoch — nie prevzaté z dokumentácie a nie odhadnuté. Ku každému patrí:

- **Fakt** — čo presne platí;
- **Overenie** — príkaz a jeho skutočný výstup;
- **Formulácia do textu práce** — veta v tvare, v akom sa dá prevziať do kapitoly
  limitácií, bez zmäkčovania;
- **Čo by to odstránilo** — čo by sa muselo zmeniť, aby obmedzenie zmizlo (tam, kde to
  má odpoveď).

Všetky výpisy nižšie sú z behov spustených 2026-09-18 medzi 16:42 a 16:55 UTC nad týmto
repozitárom. Priznaná limitácia je silnejšia pozícia než zamlčaná: recenzent ju nájde tak
či tak, a rozdiel je iba v tom, či ju nájde napísanú, alebo objavenú.

| # | Limitácia |
|---|---|
| [L1](#l1--živá-snímka-vm-sa-nezastavuje) | Živá snímka: VM sa nezastavuje |
| [L2](#l2--čítanie-nie-je-úplne-pasívne) | Čítanie nie je úplne pasívne |
| [L3](#l3--profil-jadra-hosťa-je-vstupná-závislosť-získaná-z-hosťa) | Profil jadra hosťa je vstupná závislosť získaná z hosťa |
| [L4](#l4--parsuje-sa-pamäť-jadra-nie-pamäť-procesov) | Parsuje sa pamäť jadra, nie pamäť procesov |
| [L5](#l5--hole_test-netestuje-bpf-vetvu) | `hole_test` netestuje BPF vetvu |
| [L6](#l6--injekčný-test-je-injekcia-do-kópie-snímky) | Injekčný test je injekcia do kópie snímky |
| [L7](#l7--confidential-vm-sev-snp-tdx-sa-takto-prečítať-nedá) | Confidential VM (SEV-SNP, TDX) sa takto prečítať nedá |
| [L8](#l8--prenos-cez-mmap-nie-je-nulové-kopírovanie) | Prenos cez mmap nie je „nulové kopírovanie“ |
| [L9](#l9--hook-je-notifikačný) | Hook je notifikačný |
| [L10](#l10--kontroly-integrity-majú-pomenované-slepé-miesta) | Kontroly integrity majú pomenované slepé miesta |
| [L11](#l11--jeden-výstupný-adresár-na-jeden-zberač) | Jeden výstupný adresár na jeden zberač |
| [L12](#l12--čo-ešte-nie-je-zmerané) | Čo ešte nie je zmerané |

---

## L1 — Živá snímka: VM sa nezastavuje

**Fakt.** Backend `ebpf` nemá operáciu `pause`. Vo `vmic_backend_ops_t` je
`.pause = NULL` a `.resume = NULL`, pretože eBPF je pozorovacie, nie riadiace rozhranie
hypervízora. Zberač si chýbajúcu pauzu všimne a pauzu **vôbec nemeria** — inak by ako
„čas, keď VM stála“ vykázal celý čas čítania.

Dôsledok je vecný, nie formálny: čítanie 2,02 GiB trvá stovky milisekúnd až sekundu
a hosť medzitým beží. Stránka prečítaná na začiatku a stránka prečítaná na konci
pochádzajú z rôznych okamihov. Spájaný zoznam jadra sa preto môže počas prechodu roztrhnúť
a výsledkom môže byť stav pamäte, ktorý v hosťovi v jednom okamihu neexistoval.

**Overenie.**

```
$ grep -n "\.pause " vmicollect/src/backend_ebpf.c vmicollect/src/backend_file.c
vmicollect/src/backend_file.c:119:    .pause         = f_pause,
vmicollect/src/backend_ebpf.c:1167:    .pause         = NULL,
vmicollect/src/backend_ebpf.c:1201:    .pause         = NULL,
```

(Druhý výskyt v `backend_ebpf.c` je náhradná tabuľka pre build bez podpory eBPF; ani tá
pauzu nemá.) Zberač na to pri zapnutom `capture.pause` upozorní hláškou „snimka bude
'ziva' (stranky su z roznych okamihov)“ a do sidecaru zapíše skutočnosť, nie želanie
konfigurácie. Vo všetkých 14 sidecaroch uložených v repozitári:

```
$ grep -h '"paused"\|"pause_ms"' data/raw/*/*.json data/sessions/*/snap/*.json \
        data/results/2026-09-18_prvy_beh/sidecars/*/*.json | sed 's/^ *//' | sort | uniq -c
     14 "paused": false,
     14 "pause_ms": 0.000,
```

Parser s tým počíta: každý prechod zoznamu má strop, detekciu cyklu a kontrolu rozumnosti
hodnôt, a keď sa preruší, hlási to poľom `truncated` a dôvodom v `stop_reason`. Tichý
polovičný zoznam by sa nedal odlíšiť od skutočného stavu hosťa.

**Formulácia do textu práce.**

> Snímka je živá: virtuálny stroj sa počas čítania nezastavuje, pretože použité rozhranie
> hypervízora (eBPF nad modulom `kvm`) je pozorovacie a zastavenie vCPU neponúka
> (`vmic_backend_ops_t.pause == NULL` v `backend_ebpf.c`). Stránky jednej snímky preto
> pochádzajú z rôznych okamihov a prechod spájaného zoznamu jadra sa môže roztrhnúť.
> Parser je voči tomu obranný — každý prechod má strop, detekciu cyklu a kontrolu
> rozumnosti hodnôt — a nekompletný výsledok označuje príznakom `truncated`, takže sa
> nedá zameniť za skutočný stav hosťa. Merania pauzy sa neuvádzajú, lebo pauza
> neexistuje: vo všetkých uložených snímkach je `paused = false` a `pause_ms = 0`.

**Čo by to odstránilo.** Backend, ktorý vie vCPU zastaviť (napríklad cez QMP `stop`/`cont`
alebo KVMi). Rozhranie zberača s tým počíta: `vmic_config_t` má `pause` a `pause_max_ms`,
`vmic_snapshot_t` má `paused`, `pause_ms` a `pause_exceeded`, a `collector.c` ich používa
hneď, ako backend `pause()` poskytne. Zastavenie VM by však znamenalo priamy vplyv na
hosťa, ktorý by sa musel zmerať.

---

## L2 — Čítanie nie je úplne pasívne

**Fakt.** Pri **anonymnom** podložení pamäte VM (predvolené QEMU) sa stránka, ktorej sa
hosť ešte nedotkol, načíta ako nulová a hostiteľovi nič nepribudne. Pri **non-anonymnom**
podložení (shmem, `memfd`, `hugetlbfs`, súbor) ju čítanie **naozaj alokuje**: čítanie
nedotknutej stránky spôsobí, že sa fyzická stránka na hostiteľovi vytvorí. Zber vtedy
zväčšuje skutočnú spotrebu pamäte VM na hostiteľovi.

Nie je to teoretická možnosť — nastalo to aj v meraných behoch tejto práce a zberač to
zapísal do stderr uložených artefaktov.

**Overenie.** Zberač pri štarte prejde `/proc/<pid>/maps` cieľového procesu a pre každý
memslot zisťuje, či je jeho HVA v mapovaní s reálnou cestou. Keď áno, varuje. Z uloženého
behu `data/results/probe_20260918T154840Z.json`, pole `stderr`:

```
2026-09-18T15:48:41.583Z WARN  ebpf: 4.00 KiB pamate hosta nie je anonymna (/dev/zero (deleted)) - citanie stranky, ktorej sa host este nedotkol, ju hostitelovi NAOZAJ alokuje
2026-09-18T15:48:41.583Z WARN  ebpf: pri takejto VM zbieraj radsej konkretne oblasti (capture.regions), nech nenafuknes jej pamat na plnu velkost
```

To isté varovanie je v `data/results/run_20260918T154742Z.json` aj
`data/sessions/20260918T154914Z_validate/validate.json`. V týchto behoch išlo o 4 KiB,
čo je zanedbateľné; pri VM podloženej `memfd` alebo `hugetlbfs` by to bola celá RAM.

Zdroj správania je v BPF programe (`bpf/vmic_kvm.bpf.c`): čítanie ide cez
`bpf_copy_from_user_task()`, teda cez `access_process_vm()`, a to má pri shmem podložení
práve tento efekt.

**Formulácia do textu práce.**

> Introspekcia sa označuje za pasívnu v tom zmysle, že v hosťovi nebeží žiadny agent
> a virtuálny stroj sa nezastavuje. **Nie je však úplne bez vedľajšieho účinku.** Čítanie
> prechádza cez adresný priestor procesu VMM (`bpf_copy_from_user_task`, teda
> `access_process_vm`). Ak je pamäť hosťa podložená anonymne, nedotknutá stránka sa
> prečíta ako nulová a hostiteľovi nič nepribudne. Ak je podložená non-anonymne (shmem,
> `memfd`, `hugetlbfs`, súbor), čítanie nedotknutej stránky ju na hostiteľovi skutočne
> alokuje, čím sa spotreba pamäte VM zväčší až na jej plnú veľkosť. Zberač tento stav
> deteguje z `/proc/<pid>/maps` a pri štarte naň upozorní; v meraných behoch bola takto
> podložená iba jedna stránka a varovanie je súčasťou uložených artefaktov.

**Čo to zmierňuje.** Zbierať iba konkrétne oblasti cez `[capture].regions` namiesto celej
fyzickej pamäte — presne to odporúča druhá riadka varovania.

---

## L3 — Profil jadra hosťa je vstupná závislosť získaná z hosťa

**Fakt.** Parser potrebuje profil jadra hosťa: `kallsyms` (adresy symbolov) a BTF
(offsety polí v štruktúrach). Bez neho sa zo snímky nedá prečítať nič viac než bajty.
Profil sa získal **raz, z hosťa, mimo behu zberu** — rovnako, ako profil používa LibVMI
alebo Volatility. Nikde v tejto práci sa preto nesmie napísať „bez akejkoľvek znalosti
hosťa“.

Profil je naviazaný na **konkrétnu verziu jadra**. Rozloženie štruktúr závisí od
konfigurácie jadra (`CONFIG_*`), nie iba od čísla verzie, takže offsety opísané zo
zdrojových kódov by pri inom `.config` ticho ukazovali na iné pole. Po aktualizácii jadra
v hosťovi prestane profil sedieť.

**Overenie.** Provenienčný list je v `profiles/debian12-6.1.0-42-cloud-amd64/README.md`
a uvádza dátum odberu, kanál a príkazy:

```sh
ssh -o BatchMode=yes root@192.168.122.100 cat /proc/kallsyms          > kallsyms.txt
ssh -o BatchMode=yes root@192.168.122.100 cat /sys/kernel/btf/vmlinux > btf.raw
bpftool btf dump file btf.raw format raw                              > btf.txt
```

Z hosťa sa berie iba obsah dvoch súborov; výpis BTF sa robí na hostiteľovi, aby sa do
hosťa kvôli profilu nič neinštalovalo. Naviazanosť na verziu jadra je priamo v názve
adresára profilu a je vidieť aj vo výstupe `guestparse info`, ktorý banner zo snímky
vypíše:

```
banner:        Linux version 6.1.0-42-cloud-amd64 ... Debian 6.1.159-1 (2025-12-30)
```

Rozhodnutie čítať offsety z BTF a nie z hlavičkových súborov je zdôvodnené v hlavičke
`guestparse/profile.py`.

**Formulácia do textu práce.**

> Parser štruktúr hosťa vyžaduje profil jadra: zoznam symbolov (`/proc/kallsyms`)
> a typové informácie BTF (`/sys/kernel/btf/vmlinux`). Profil sa získal jednorazovo,
> priamo z hosťa a mimo meraného okna zberu — rovnaký vstup vyžadujú aj LibVMI
> a Volatility. Nejde teda o introspekciu bez akejkoľvek znalosti hosťa, ale o
> introspekciu bez agenta bežiaceho v hosťovi počas merania. Profil je naviazaný na
> konkrétnu verziu jadra vrátane jeho konfigurácie; po aktualizácii jadra v hosťovi
> prestane sedieť a musí sa odobrať znovu. Odber profilu je zdokumentovaný vrátane dátumu,
> kanála a príkazov.

**Poznámka k rozlíšeniu.** `qemu-guest-agent` sa v práci používa na orchestráciu
experimentu a na zbieranie pozemnej pravdy (`ps`, `lsmod`, `ss` v čase snímky). To je
priznané a obhájiteľné, lebo to nie je senzor, z ktorého sa detekuje. Bezpečnostný agent
v hosťovi by protirečil zadaniu, nepoužíva sa, a pred meraniami sa v hosťovi ukončil
(`HONESTY.md`, P6).

---

## L4 — Parsuje sa pamäť jadra, nie pamäť procesov

**Fakt.** Preklad adries pokrýva **priestor jadra**: obraz jadra a priamy mapping
lineárnym vzťahom, oblasti modulov a vmalloc prechodom tabuliek stránok z `init_top_pgt`.
Obsah pamäte používateľských procesov sa **neparsuje**. Chýba na to vstup: preklad
používateľských adries potrebuje hodnotu CR3 konkrétneho vCPU (alebo `mm_struct->pgd`
procesu) a **backend registre vCPU nečíta** — z modulu `kvm` berie mapu memslotov, a z
vCPU iba ich počet.

Prakticky to znamená: procesy, moduly a sokety sa zo snímky rekonštruujú, ale ich
používateľské dáta (argumenty, obsah haldy, načítané knižnice v pamäti procesu, spustiteľný
kód procesu) nie.

**Overenie.** Na strane parsera sa CR3 ani registre vCPU nespomínajú:

```
$ grep -rniE "cr3|vcpu|\bregs\b|register" guestparse/*.py | wc -l
0
$ grep -n "mm_struct\|pgd\|user space\|pouzivatelsk" guestparse/*.py | head
(žiadny výstup)
```

Na strane BPF programu je z vCPU čítaný jediný údaj, a je to počítadlo:

```
$ grep -rn "vcpu" vmicollect/bpf/vmic_kvm.bpf.c
vmicollect/bpf/vmic_kvm.bpf.c:351:    RDK(&info->online_vcpus,  4, kvm + k->kvm_online_vcpus);   /* atomic_t */
vmicollect/bpf/vmic_kvm.bpf.c:382:    info->online_vcpus = 0;
vmicollect/bpf/vmic_kvm.bpf.c:390:    ctx->online_vcpus = 0;
vmicollect/bpf/vmic_kvm.bpf.c:419:    ctx->online_vcpus = info->online_vcpus;
```

Ide o `atomic_t online_vcpus`, teda počet spustených vCPU, ktorý sa objaví v sidecari ako
`"num_vcpus": 2`. Žiadny register sa nečíta.

**Formulácia do textu práce.**

> Preklad adries implementovaný v práci pokrýva priestor jadra hosťa: obraz jadra
> a priamy mapping dvoma lineárnymi vzťahmi, oblasť modulov a vmalloc prechodom
> štvorúrovňových tabuliek stránok z `init_top_pgt`. Obsah pamäte používateľských procesov
> sa neparsuje. Dôvod je vo vstupe, nie v implementácii parsera: preklad používateľských
> adries vyžaduje koreň tabuliek stránok daného procesu, ktorý sa získava z registra CR3
> príslušného vCPU, a použitý backend registre vCPU nečíta — z modulu `kvm` číta mapu
> memslotov a z vCPU iba ich počet. Zo snímky sa preto rekonštruujú jadrové objekty
> (procesy, načítané moduly, sieťové spojenia), nie používateľské dáta procesov.

**Čo by to odstránilo.** Buď rozšírenie BPF programu o čítanie `vcpu->arch.cr3`, alebo
prechod cez `task_struct->mm->pgd`, ktorý je v pamäti a CR3 nepotrebuje. Druhá cesta je
v dosahu súčasného návrhu, ale nie je implementovaná ani zmeraná — `UNVERIFIED`.

---

## L5 — `hole_test` netestuje BPF vetvu

**Fakt.** `vmicollect/tests/hole_test.c` je regresný test na najzradnejšiu chybu modulu:
backend, ktorý sa zastaví na prvej nečitateľnej stránke, zahodí aj čitateľnú pamäť za
dierou. Test to overuje s **falošným backendom**, ktorý má tú najhoršiu možnú sémantiku.
Testuje sa tým **kontrakt collectora a spoločnej čítacej slučky**, nie vetva `KIND_HOLE`
v BPF programe. Tá v testoch nikdy nebežala.

**Overenie.** Test sa spúšťa bez VM a bez roota a používa vlastný backend definovaný
priamo v súbore testu:

```
$ make -C vmicollect test
build/hole_test
chunks=2 read_errors=1 filled_zero=131072 bytes_read=1966080
OK: pamat za dierou sa zachovala, obraz je zhodny s referenciou
```

Hlavička `tests/hole_test.c` to hovorí sama: „Backend 'ebpf' toto riesi mapou memslotov
(dieru preskoci celu naraz), ale kontrakt read_pa() plati pre kazdy backend - preto tento
test pouziva fake backend s tou najhorsou moznou semantikou.“

**Formulácia do textu práce.**

> Regresný test `hole_test` overuje, že zberač správne prekračuje diery vo fyzickom
> adresnom priestore a nestratí pamäť za nimi. Test to robí nad falošným backendom
> s najhoršou prípustnou sémantikou, takže overuje kontrakt rozhrania `read_pa()`
> a spoločnú čítaciu slučku. **Neoveruje vetvu spracovania dier v samotnom BPF programe**
> — tá sa v testoch nespúšťa a jej správnosť je doložená iba tým, že v reálnych behoch nad
> doménou `hyptcn-guest` bol počet chýb čítania nulový.

---

## L6 — Injekčný test je injekcia do kópie snímky

**Fakt.** Detektor hookov v `sys_call_table` má pozitívny testovací prípad. Ten
**neinštaluje rootkit**. Urobí sa kópia reálnej snímky, v kópii sa jedna položka tabuľky
prepíše na adresu v oblasti modulov, a overí sa, že detektor taký zápis nájde a správne ho
pomenuje. V hosťovi sa nemení nič.

Prečo to tam musí byť: kontrola, ktorá na čistom hosťovi vždy vráti nulu, je na
nerozoznanie od funkcie, ktorá vždy vracia nulu. Negatívny aj pozitívny prípad musia bežať
oba.

Prečo to nie je skutočný rootkit: hosť nemá `gcc`, `make` ani hlavičky jadra, a nemá
funkčné DNS, takže sa ani nedajú doinštalovať. Zavedenie modulu jadra je v tomto
prostredí nedosiahnuteľné.

**Overenie.** Hlavička `guestparse/tests/test_injection.py`:

> Test si urobi KOPIU realnej snimky a v KOPII prepise jednu polozku tabulky volani jadra
> na adresu v oblasti modulov. V hostovi sa NIC nemeni a ziadny rootkit sa nikam
> neinstaluje (...) Ide teda o injekciu do datoveho suboru, nie o realny utok; dokazuje sa
> tym iba to, ze detektor taky zapis najde a spravne ho pomenuje.

Test je súčasťou sady, ktorá prechádza:

```
$ python3 -m pytest -q
........................................................................ [ 81%]
................                                                         [100%]
88 passed in 1.61s
```

**Formulácia do textu práce.**

> Pozitívny prípad detekcie hookov v tabuľke systémových volaní bol overený injekčným
> testom: do kópie reálnej snímky sa prepísala jedna položka tabuľky na adresu v oblasti
> modulov a detektor ju nahlásil. **Ide o injekciu do dátového súboru, nie o skutočný
> rootkit.** V hosťovi nebol zavedený žiadny modul jadra — prostredie to neumožňuje
> (hosť nemá prekladač, nástroje `make`, hlavičky jadra ani funkčné rozlíšenie mien).
> Test preto dokazuje, že detektor taký zápis nájde a správne pomenuje, nie že by
> odhalil reálny útok na jadro.

---

## L7 — Confidential VM (SEV-SNP, TDX) sa takto prečítať nedá

**Fakt.** Pamäť dôverného virtuálneho stroja (AMD SEV-SNP, Intel TDX) je v `guest_memfd`
a cez adresný priestor VMM sa prečítať nedá. Celá metóda tejto práce stojí na čítaní
pamäte hosťa cez adresný priestor procesu QEMU — pri takej VM tam pamäť jednoducho nie je.
Zberač také sloty preskočí, oznámi, koľko ich bolo, a v snímke budú nulové.

Dôležitá jemnosť, ktorú kód rozlišuje: samotný príznak `KVM_MEM_GUEST_MEMFD` ešte
neznamená, že slot nemá HVA — dôverná VM má cez neho namapovanú iba svoju privátnu časť
a zdieľaná časť ostáva čitateľná. Nečitateľný je až slot s príznakom `GMEM_ONLY` alebo
bez `userspace_addr`.

**Overenie.**

```
$ grep -n "guest_memfd" vmicollect/src/backend_ebpf.c vmicollect/bpf/vmic_bpf_abi.h vmicollect/README.md
vmicollect/bpf/vmic_bpf_abi.h:163:    __u32 skipped;          /* sloty bez HVA (guest_memfd)             */
vmicollect/bpf/vmic_bpf_abi.h:196:    __u32 skipped;          /* out: preskocene sloty (guest_memfd)     */
vmicollect/src/backend_ebpf.c:902:                 "(guest_memfd / prave sa meni) - budu nulove",
vmicollect/README.md:418:**Confidential VM (SEV-SNP, TDX).** Pamat takej VM je v `guest_memfd` a cez
```

Rozlíšenie privátnej a zdieľanej časti je popísané v komentári nad príznakmi memslotu
v `vmicollect/bpf/vmic_bpf_abi.h` (`VMIC_BPF_MEM_GUEST_MEMFD`, `VMIC_BPF_MEMSLOT_GMEM_ONLY`).

Hláška, ktorú zberač v takom prípade vypíše, znie: „N slotov sa cez adresny priestor VMM
precitat neda (guest_memfd / prave sa meni) - budu nulove“. V meraných behoch nad
doménou `hyptcn-guest` (bežná VM, nie dôverná) bol počet preskočených slotov nulový —
varovanie sa v žiadnom uloženom stderr neobjavuje.

**Formulácia do textu práce.**

> Metóda je nepoužiteľná na dôverné virtuálne stroje (AMD SEV-SNP, Intel TDX). Pamäť
> takej VM je umiestnená v `guest_memfd` a cez adresný priestor procesu VMM, z ktorého
> zberač číta, nie je dostupná. Zberač takéto pamäťové sloty preskočí, ich počet oznámi,
> a v snímke ostanú nulové. Ide o architektonické obmedzenie zvoleného prístupu, nie
> o chybu implementácie: dôvernosť pamäte hosťa voči hostiteľovi je práve účelom týchto
> technológií. Introspekcia dôvernej VM by vyžadovala iný mechanizmus, so spoluprácou
> firmvéru platformy.

---

## L8 — Prenos cez mmap nie je „nulové kopírovanie“

**Fakt.** Čítanie ide takto: BPF program v jadre skopíruje stránky z adresného priestoru
VMM do BPF mapy `pages` (okno 2 MiB), a zberač ich v používateľskom priestore prekopíruje
z `mmap` tejto mapy do svojho bufferu. Je to **jedno prekročenie hranice jadro/používateľ
a jeden `memcpy` v používateľskom priestore**. Nie je to nulové kopírovanie a tak sa to
v texte nesmie nazvať.

**Overenie.**

```
$ grep -n "mmap(NULL\|memcpy(out + done\|run_prog(p->fd_read" vmicollect/src/backend_ebpf.c
787:    p->win = mmap(NULL, p->win_size, PROT_READ, MAP_SHARED, p->map_pages, 0);
1097:        if (run_prog(p->fd_read, &ctx, sizeof(ctx), "vmic_read") != VMIC_OK)
1128:            memcpy(out + done, p->win + skip, take);
```

**Formulácia do textu práce.**

> Prenos dát z jadra do zberača využíva BPF mapu typu array namapovanú cez `mmap`, takže
> sa vyhýba opakovaným systémovým volaniam na jednotlivé stránky. Nejde však o prenos bez
> kopírovania: v jadre sa stránky kopírujú do prenosového okna a v používateľskom
> priestore nasleduje jeden `memcpy` z tohto okna do cieľového bufferu. Presný opis je
> teda „jedno prekročenie hranice jadro/používateľ a jedno kopírovanie v používateľskom
> priestore na blok“, nie „nulové kopírovanie“.

---

## L9 — Hook je notifikačný

**Fakt.** Rozhranie pluginu (`vmic_hook_api_t`) má tri polia: číslo ABI, ukazovateľ na
konfiguráciu iba na čítanie, a logovaciu funkciu. **Neobsahuje `read_pa`** ani inú cestu
k pamäti hosťa, ani ukazovateľ na backend či zberač. Plugin dostane pri každej snímke
`const vmic_snapshot_t *` — teda cestu k hotovému súboru, časy a počítadlá — a ak chce
obsah, musí si súbor otvoriť sám.

Hook beží synchrónne v hlavnej slučke, takže keď trvá dlhšie ako perióda, zberač začne
zmeškávať sloty.

**Overenie.** Celé rozhranie, ktoré plugin dostane, je v `vmicollect/include/vmic.h`:

```c
typedef struct {
    unsigned abi;
    const vmic_config_t *cfg;
    void (*log)(int level, const char *fmt, ...);
} vmic_hook_api_t;
```

Reálny beh s pluginom (backend `file`, bez roota, výpis skrátený; cesta dočasného
adresára nahradená `$D`):

```
2026-09-18T16:54:15.545Z INFO  example_hook: zapisujem index do '$D/index.csv'
2026-09-18T16:54:15.545Z INFO  hooks: nacitany './vmicollect/build/example_hook.so' s argumentmi: $D/index.csv
2026-09-18T16:54:15.549Z INFO  #0 PLNA   68.00 KiB/8.00 MiB  stranky 16/2048 (0.78 %)  pauza 0.0 ms  citanie 3.1 ms  spolu 3.3 ms
```

a to, čo plugin z rozhrania naozaj videl:

```
seq,timestamp_unix,path,bytes_on_disk,pause_ms,capture_ms,total_ms,pages_changed,pages_total
0,1789750455.545,$D/snap/mem.raw_000000_20260918T165415545Z.vmicd,69632,0.000,3.146,3.305,16,2048
```

**Formulácia do textu práce.**

> Rozširujúce rozhranie modulu (hook) je notifikačné. Plugin je zdieľaná knižnica načítaná
> cez `dlopen` a po každej dokončenej snímke dostane záznam s cestou k súboru, časmi
> jednotlivých fáz cyklu a počítadlami zmenených stránok. **Nedostáva funkciu na čítanie
> pamäte hosťa ani obsah stránok**; ak potrebuje dáta, musí si uloženú snímku otvoriť sám.
> Plugin beží synchrónne v hlavnej slučke zberača, takže výpočet dlhší než perióda zberu
> spôsobí zmeškávanie plánovaných termínov. Návrh skórovacieho komponentu musí s oboma
> vlastnosťami počítať.

---

## L10 — Kontroly integrity majú pomenované slepé miesta

**Fakt.** Kontroly nad snímkou porovnávajú dva zdroje, ktoré musia sedieť, a nálezom je
ich rozdiel. Nie je to skóre ani odhad — a práve preto majú presne opísateľné slepé
miesta:

1. **Hook prepísaný na adresu vnútri `[_stext, _etext)`** kontrola rozsahu z princípu
   nevidí.
2. **Skrytie, ktoré odpojí uzol z oboch porovnávaných štruktúr naraz** (zo zoznamu
   `tasks` aj zo stromu `children`/`sibling`) nevytvorí rozdiel, teda ani nález.
3. **Nulový nález z neuzavretej kontroly nič nedokazuje.** Keď sa prechod zoznamu
   roztrhne (L1), rozdiel dvoch zoznamov nie je dôkaz skrývania. Preto každá kontrola
   hlási, či sa uzavrela, CLI to vypíše a vracia kód 4 namiesto 0.

**Overenie.** Zdôvodnenie je v hlavičke `guestparse/checks.py`. Na meranej snímke sa
uzavreli všetky tri kontroly a nález bol nulový:

```
$ python3 -m guestparse checks --snapshot $S --profile $P
sys_call_table         451 poloziek v [0xffffffff96000000, 0xffffffff96e01ef2), nalezov: 0
procesy krizovo        tasks 80 vs. children/sibling 80, nalezov: 0
moduly krizovo         modules 51 vs. module_kset 51 (z 109 kobjektov), nalezov: 0
nalezov spolu: 0 (z toho hookov v tabulke volani: 0)
$ echo $?
0
```

**Formulácia do textu práce.**

> Kontroly integrity nad snímkou sú porovnaním dvoch nezávislých zdrojov, ktoré musia
> sedieť: položky tabuľky systémových volaní proti rozsahu textu jadra, zoznam procesov
> proti stromu potomkov, zoznam modulov proti objektom v `module_kset`. Ich slepé miesta
> sú známe a pomenované: prepísanie obsluhy na inú adresu **vnútri** rozsahu textu jadra
> rozsahová kontrola nevidí; skrytie, ktoré odpojí uzol z oboch porovnávaných štruktúr
> naraz, nevytvorí rozdiel; a nulový výsledok kontroly, ktorá sa pre neúplný prechod
> zoznamu neuzavrela, nie je dôkazom čistoty — nástroj takýto prípad označuje samostatne
> a nehlási ho ako úspech.

---

## L11 — Jeden výstupný adresár na jeden zberač

**Fakt.** Retencia pracuje nad celým `output.dir` a nerozlišuje domény. Keď do jedného
adresára zbierajú dva zberače, mažú si navzájom snímky. Každej doméne treba dať vlastný
`output.dir`.

**Overenie.** `vmicollect/README.md`, časť „Poznamky k prostrediu“; v kóde je to vidieť na
tom, že `vmic_retention_apply()` dostane iba konfiguráciu a id chráneného reťazca, nie
identitu domény.

**Formulácia do textu práce.**

> Mechanizmus retencie je viazaný na výstupný adresár, nie na doménu: pri behu nad viacerými
> virtuálnymi strojmi musí mať každý z nich vlastný výstupný adresár, inak by si zberače
> navzájom mazali snímky. Toto obmedzenie ovplyvňuje nasadenie, nie namerané výsledky
> tejto práce, ktoré vznikli pri zbere z jednej domény.

---

## L12 — Čo ešte nie je zmerané

**Fakt.** Nasledujúce veličiny **nemajú v tejto práci uložené meranie** a do textu sa
nesmú dostať ako výsledok. Podľa `HONESTY.md` P5 a P7 sú označené `UNVERIFIED`, kým
nevznikne artefakt v `data/results/`.

| Veličina | Stav | Čo na ňu treba |
|---|---|---|
| latencia snímka → príznakový vektor | `UNVERIFIED` | príznakový priestor zatiaľ neexistuje |
| latencia snímka → skóre modelu | `UNVERIFIED` | model ani skórovací komponent zatiaľ neexistujú |
| vplyv zberu na výkon vnútri hosťa | `UNVERIFIED` | benchmark s pevne daným objemom práce v hosťovi, schéma A/B/A, medián a IQR z aspoň 12 opakovaní |
| vplyv zberu na hostiteľa | `UNVERIFIED` | meranie spotreby CPU a pamäte procesu zberača počas behu |
| dlhý beh s retenciou | `UNVERIFIED` | beh rádovo v hodinách: zmeškané sloty, rast obsadeného miesta, správanie pri reštarte domény |
| správanie pri periódach iných než 2 s a 5 s | `UNVERIFIED` | sweep periódy a veľkosti bloku |
| presnosť detekcie voči reálnym malvérovým vzorkám | **nebude zmeraná** | vzorky nie sú dostupné; nahrádza sa syntetickými scenármi správania (`HONESTY.md`, P4) |

Ďalšia nedoriešená vec, ktorá patrí do priznaných: pri načítaní BPF programu sa objavuje
nefatálne hlásenie `libbpf: Error in bpf_create_map_xattr(pages): -EINVAL. Retrying
without BTF.` Mapa sa vytvorí aj bez BTF a zber funguje, ale príčina nebola zistená.

**Formulácia do textu práce.**

> Práca neuvádza latenciu od zosnímania pamäte po príznakový vektor ani po skóre modelu,
> vplyv zberu na výkon hosťa, vplyv na hostiteľa, ani správanie pri dlhodobom behu.
> Nejde o vynechanie: tieto veličiny neboli v rámci tejto práce namerané, a formulácie
> typu „minimálny vplyv na virtuálny stroj“ alebo „spracovanie v reálnom čase“ by preto
> boli tvrdením bez podkladu. Tam, kde je to potrebné, sa namiesto nich uvádza konkrétna
> perióda zberu a namerané trvanie jednotlivých fáz cyklu, ktoré uložené artefakty majú.
> Presnosť voči reálnym malvérovým vzorkám nebola meraná.

---

## L13 — Príznakový vektor: čo o ňom treba vedieť pred tým, než sa naň natrénuje model

**Na plnej snímke sú `changed_ratio` a `zero_ratio` kolineárne.** Delta writer porovnáva
stránky proti tabuľke hashov, ktorá je na začiatku reťazca nulová, takže „zmenená" tam
znamená „nenulová" a platí presne `changed_ratio = 1 − zero_ratio` (overené na sidecari
seq 0: 0,854823 + 0,145177 = 1,000000 na všetkých binoch). Riadok plnej snímky má teda iný
význam než riadky delta snímok. `features/windows.py` to rieši voľbou, čo s plnými snímkami
robiť, a východzie správanie je zdokumentované — ale kto pridá nový príznak alebo nový
model, musí o tom vedieť.

**Formulácia do textu práce:** „Prvá snímka reťazca je referenčná; príznaky odvodené od zmeny
majú v nej definíciu, ktorá sa líši od nasledujúcich snímok, preto sa v sekvenciách
spracúvajú osobitne."

**Výpočet príznakov predlžuje cyklus.** Základ stojí ~51–53 ms na cyklus bez ohľadu na
množstvo zmien (prejde sa všetkých 528 417 stránok), entropia ďalších ~3,5 µs na zmenenú
stránku. Na plnej snímke to je ~431 ms navyše. Čísla sú v `docs/MERANIA.md`, záznam
z 2026-09-18 (fáza F2).

**Formulácia do textu práce:** „Extrakcia príznakov je súčasťou cyklu zberu a jej cena je
zmeraná; pri perióde 2 s zostáva p95 latencie cyklu pod periódou s rezervou približne
trojnásobku."

**Počet binov je viazaný na geometriu konkrétnej VM.** Pri 2,02 GiB VM vzniká 131 binov;
pri inej veľkosti pamäte alebo inom rozložení memslotov ich bude iný počet. Model, ktorý by
bral biny ako pevný počet vstupov, by bol použiteľný len na VM rovnakej veľkosti. Ako sa
s tým naloží, je otvorené rozhodnutie fázy F3 a nesmie sa „vyriešiť" tichým doplnením núl
do pevnej dĺžky.

**Vektor sa meral iba na jednej doméne.** Geometria s inou veľkosťou binu (1 MiB) je overená
testom nad synteticky deravým obrazom, nie nad druhou skutočnou VM. Správanie pri hotplugu
pamäte za behu je v kóde ošetrené podpisom oblastí, ale nebolo odskúšané behom.

---

## L14 — Procesy, moduly a sokety do príznakového vektora nevstupujú — VYRIEŠENÉ 2026-09-19

**Stav.** Toto obmedzenie už neplatí. Zo zoznamu sa neodstraňuje: priznané obmedzenie,
ktoré zmizne bez stopy, vyzerá, ako by nikdy nebolo. Pôvodné znenie je zachované nižšie.

**Čím sa vyriešilo.** Modul `features/snapshot.py` (pridaný 2026-09-19; commit sa tu
neuvádza, lebo zmena v čase písania tohto záznamu ešte nebola zapísaná do histórie)
skladá z jednej snímky **jeden vektor pevnej dĺžky**: dvadsať príznakov plus pole
`ma_predchodcu`. Pamäťová časť (príznaky 1–8) je agregát bloku `features` zo sidecaru
snímky, ktorý počíta modul `vmicollect`; objektová časť (príznaky 9–20) sa číta cez
`guestparse` nad **tou istou** snímkou:

| Príznaky | Čo v nich je | Veta zadania |
|---|---|---|
| 1–8 | `mem_changed_ratio`, `mem_bins_active`, `mem_changed_max`, `mem_changed_p95`, `mem_changed_spread`, `mem_entropy_mean`, `mem_entropy_max`, `mem_zero_ratio` | štatistické charakteristiky pamäťových oblastí |
| 9–13 | `proc_total`, `proc_user`, `proc_kernel`, `proc_new`, `proc_gone` | procesné informácie |
| 14–15 | `mod_total`, `mod_delta` | analýza načítaných modulov |
| 16–18 | `sock_total`, `sock_listen`, `sock_estab` | monitorovanie sieťových spojení |
| 19–20 | `chk_syscall_hooks`, `chk_crossview` | detekcia podozrivých vzorcov v pamäti |

Príkaz: `python3 -m features session --snapshot <adresár> --profile <profil> --out <súbor.npz> [--csv <súbor.csv>]`.
Mená príznakov sa ukladajú spolu s maticou, takže poradie stĺpcov sa dá spätne overiť.

**Prečo pevná dĺžka a nie biny ako kanály.** Počet binov závisí od veľkosti a rozloženia
memslotov virtuálneho stroja (pri doméne `hyptcn-guest` ich je 131). Biny ako kanály by
model priviazali na jednu veľkosť pamäte, preto sa cez biny agreguje — je to cesta (a)
z otvoreného rozhodnutia vo `features/windows.py`. Cenou je strata informácie o tom,
**ktorá** oblasť pamäte sa menila; per-bin vektor kvôli tomu nezaniká, zostáva
v `features/perbin.py` a v sidecari.

**Prvá snímka reťazca.** Príznaky `proc_new`, `proc_gone` a `mod_delta` potrebujú
predchádzajúcu snímku. Zvolená cesta: riadok sa nevynecháva, ale nesie `ma_predchodcu` = 0
a tieto tri príznaky sú v ňom nula. Je to tá istá dohoda ako `has_changed` v `perbin.py` —
nula, vedľa ktorej stojí príznak hovoriaci, že sa nemerala. Ticho doplnená nula je v tomto
projekte zakázaná (`HONESTY.md`); kto maticu spracúva, musí `ma_predchodcu` čítať.

**Overenie.** `features/tests/test_snapshot.py` (13 testov, všetky prešli 2026-09-19
aj s `FEATURES_REQUIRE_REAL=1`) kontroluje dĺžku vektora, mená príznakov, ručne spočítanú
pamäťovú agregáciu, `ma_predchodcu` = 0 na prvej snímke, zhodu `proc_new` a `proc_gone`
s ručne spočítaným rozdielom množín PID medzi dvoma snímkami a determinizmus. Nad
`guestparse/tests/data/mini.vmicd` sa navyše overuje, že bez sidecaru s blokom `features`
skončí výpočet chybou a pamäťová časť sa **nedopočítava** inou cestou.

**Čo to stojí.** Spracovanie jednej snímky (rekonštrukcia objektov hosťa + agregácia
sidecaru) trvalo medián 0,383 s, rozsah 0,373–0,580 s; n = 18, tri prechody reťazca
šiestich snímok z `data/raw/20260919T004036Z_run`, teplá vyrovnávacia pamäť stránok
hostiteľa. Pri perióde zberu 5 s to je zlomok periódy, takže spracovanie stíha. Merané
na reťazci šiestich častí; ako cena rastie pri dlhšom reťazci, merané nebolo.

**Formulácia do textu práce:** „Rekonštrukcia objektov hosťa a štatistiky pamäťových
oblastí vstupujú do jedného príznakového vektora pevnej dĺžky, jeden vektor na snímku.
Pamäťová časť je agregátom per-bin vektora, ktorý počíta modul zberu; objektová časť
pochádza z rekonštrukcie zoznamu procesov, načítaných modulov, sieťových soketov
a kontrol integrity nad tou istou snímkou. Príznaky, ktoré potrebujú predchádzajúcu
snímku, sú v prvom časovom kroku označené príznakom `ma_predchodcu` = 0."

---

### Pôvodné znenie (2026-09-18), ponechané ako záznam

Zadanie žiada „extrakciu príznakov z RAM vrátane procesných informácií, analýzy načítaných
modulov, monitorovania sieťových spojení, detekcie podozrivých vzorcov v pamäti
a štatistických charakteristík pamäťových oblastí". Tieto dve časti sú dnes v repozitári
oddelené a nestretávajú sa:

- `guestparse` rekonštruuje **procesy, moduly a sokety** a porovnáva ich s pozemnou pravdou.
  Výstup je zoznam objektov, nie vektor čísel, a nikam ďalej nejde.
- `perbin.c` počíta **príznakový vektor**, ktorý má na bin štyri hodnoty plus príznak:
  `pages_changed`, `changed_ratio`, `zero_ratio`, `entropy_mean`, `has_changed`. Sú to
  výhradne štatistiky pamäťových blokov. Ani jedno číslo o procesoch, moduloch ani
  spojeniach v ňom nie je.

Model, ktorý na tento vektor nadviaže, teda o procesoch hosťa nevie nič. Veta zo zadania
je splnená v časti „extrakcia", nie v časti „príznaky pre model".

**Formulácia do textu práce:** „Rekonštrukcia objektov hosťa a príznakový vektor pre model
sú v tejto verzii dva oddelené výstupy. Príznakový vektor obsahuje štatistické
charakteristiky pamäťových oblastí; procesné, modulové a sieťové informácie sa
rekonštruujú a validujú, ale do vstupu modelu nevstupujú."

**Čo by to znamenalo odstrániť:** doplniť per-proces alebo agregované príznaky
(počet procesov, počet jadrových vlákien, počet a stav soketov, zmeny v zozname modulov)
ako ďalšie zložky časového kroku. Je to návrhové rozhodnutie fázy F3, nie oprava chyby —
a súvisí s otvorenou otázkou vo `features/windows.py`, ako spraviť model nezávislým
od počtu binov.

---

## Ako sa tento zoznam udržiava

Limitácia sa z tohto súboru neodstraňuje, kým nezmizne z kódu. Keď sa odstráni, pridá sa
k nej dátum, commit a odkaz na meranie, ktoré to dokladá — rovnako, ako je to zavedené pre
`docs/MERANIA.md` (`HONESTY.md`, P10). Nové obmedzenie sa pridáva hneď, ako sa zistí, aj
keď ešte nie je jasné, či sa bude riešiť.
