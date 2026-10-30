# Limitácie

Zoznam vedomých obmedzení tejto práce. Každé je overené v zdrojovom kóde alebo v uložených
artefaktoch — nie prevzaté z dokumentácie a nie odhadnuté. Ku každému patrí:

- **Fakt** — čo presne platí;
- **Overenie** — príkaz a jeho skutočný výstup;
- **Formulácia do textu práce** — veta v tvare, v akom sa dá prevziať do kapitoly
  limitácií, bez zmäkčovania;
- **Čo by to odstránilo** — čo by sa muselo zmeniť, aby obmedzenie zmizlo (tam, kde to
  má odpoveď).

Výpisy sú z behov nad týmto repozitárom. Pôvodné sú z 2026-09-18 (16:42–16:55 UTC),
neskoršie majú pri sebe dátum alebo artefakt. Stav položiek bol overený proti kódu
v commite `709ee7f` (2026-10-29); výpis, ktorý sa odvtedy zmenil, je opravený alebo
označený dátumom. Identifikátory blokov (A2, A3, A4) v nadpisoch a v komentároch kódu
vysvetľuje legenda v [`STAV.sk.md`](STAV.sk.md). Priznaná limitácia je silnejšia pozícia
než zamlčaná: recenzent ju nájde tak či tak, a rozdiel je iba v tom, či ju nájde
napísanú, alebo objavenú.

| # | Limitácia |
|---|---|
| [L1](#l1--živá-snímka-vm-sa-nezastavuje) | Živá snímka: VM sa nezastavuje |
| [L2](#l2--čítanie-nie-je-úplne-pasívne) | Čítanie nie je úplne pasívne |
| [L3](#l3--profil-jadra-hosťa-je-vstupná-závislosť-získaná-z-hosťa) | Profil jadra hosťa je vstupná závislosť získaná z hosťa |
| [L4](#l4--parsuje-sa-pamäť-jadra-nie-pamäť-procesov--čiastočne-odstránené-2026-10-05-a4) | Parsuje sa pamäť jadra, nie pamäť procesov — ČIASTOČNE ODSTRÁNENÉ |
| [L5](#l5--hole_test-netestuje-bpf-vetvu) | `hole_test` netestuje BPF vetvu |
| [L6](#l6--injekčný-test-je-injekcia-do-kópie-snímky) | Injekčný test je injekcia do kópie snímky |
| [L7](#l7--confidential-vm-sev-snp-tdx-sa-takto-prečítať-nedá) | Confidential VM (SEV-SNP, TDX) sa takto prečítať nedá |
| [L8](#l8--prenos-cez-mmap-nie-je-nulové-kopírovanie) | Prenos cez mmap nie je „nulové kopírovanie“ |
| [L9](#l9--hook-je-notifikačný) | Hook je notifikačný |
| [L10](#l10--kontroly-integrity-majú-pomenované-slepé-miesta) | Kontroly integrity majú pomenované slepé miesta |
| [L11](#l11--jeden-výstupný-adresár-na-jeden-zberač) | Jeden výstupný adresár na jeden zberač |
| [L12](#l12--čo-ešte-nie-je-zmerané) | Čo ešte nie je zmerané |
| [L13](#l13--príznakový-vektor-čo-o-ňom-treba-vedieť-pred-tým-než-sa-naň-natrénuje-model) | Príznakový vektor: čo o ňom treba vedieť pred tréningom |
| [L14](#l14--procesy-moduly-a-sokety-do-príznakového-vektora-nevstupujú--vyriešené-2026-09-19) | Procesy, moduly a sokety do príznakového vektora nevstupujú — VYRIEŠENÉ |
| [L15](#l15--časové-rozlíšenie-proces-kratší-než-perióda-zberu-je-neviditeľný) | Časové rozlíšenie: proces kratší než perióda zberu je neviditeľný |
| [L16](#l16--presnosť-detekcie-malvéru-nebola-meraná) | Presnosť detekcie malvéru nebola meraná |
| [L17](#l17--profil-jadra-hosťa-platí-pre-jeden-boot-nie-pre-verziu-jadra--vyriešené-2026-10-05-preukotvenie-blok-a2) | Profil jadra hosťa platí pre jeden boot — VYRIEŠENÉ |
| [L18](#l18--kontrola-textu-jadra-rozdiel-medzi-bootmi-baseline-nesedí) | Kontrola textu jadra: rozdiel medzi bootmi, baseline nesedí |

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
vmicollect/src/backend_ebpf.c:935:        LOGW("ebpf: capture.pause sa ignoruje - eBPF vie citat, nie riadit "
vmicollect/src/backend_ebpf.c:1167:    .pause         = NULL,
vmicollect/src/backend_ebpf.c:1201:    .pause         = NULL,
```

(Riadok 935 je varovanie opísané nižšie; v pôvodnom výpise chýbal. Posledný výskyt
v `backend_ebpf.c` je náhradná tabuľka pre build bez podpory eBPF; ani tá
pauzu nemá.) Zberač na to pri zapnutom `capture.pause` upozorní hláškou „snimka bude
'ziva' (stranky su z roznych okamihov)“ a do sidecaru zapíše skutočnosť, nie želanie
konfigurácie. Vo všetkých sidecaroch, ktoré nájde príkaz nižšie (2026-09-18 ich bolo 14;
2026-10-29 ich je 167, z toho 15 v gite, ostatné v `data/raw/`, ktorý je mimo gitu),
je `paused` = false a `pause_ms` = 0; hodnota `true` sa nevyskytuje:

```
$ grep -h '"paused"\|"pause_ms"' data/raw/*/*.json data/sessions/*/snap/*.json \
        data/results/2026-09-18_prvy_beh/sidecars/*/*.json | sed 's/^ *//' | sort | uniq -c
    167 "paused": false,
    167 "pause_ms": 0.000,
```

Parser s tým počíta: každý prechod zoznamu má strop, detekciu cyklu a kontrolu rozumnosti
hodnôt, a keď sa preruší, hlási to poľom `truncated` a dôvodom v `stop_reason`. Tichý
polovičný zoznam by sa nedal odlíšiť od skutočného stavu hosťa.

Uzavretý prechod však ešte nie je správny prechod. V benígnej session
`benign-v3-20261022_03_train_bursty` (720 snímok, profil `bursty`) sa zoznam `tasks`
prešiel oboma smermi ([záznam](../data/results/collection_process_walk_race_20261022.json)).
Dopredu sa neuzavrel iba v snímke 505: `next` posledného vlákna ukazoval na už ukončený
proces `python3` (`EXIT_DEAD`) so starými ukazovateľmi a prechod sa zacyklil. Dozadu sa
uzavrel cez tých istých 110 procesov ako susedné snímky. Dozadu sa uzavrela každá snímka,
v snímke 529 však cez 78 procesov namiesto 110. V piatich snímkach sa smery líšili
o jeden krátko žijúci proces, čo je bežné rozmazanie živej snímky. Parser preto berie
zoznam dopredu. Keď sa roztrhne, zoznam tvoria uzly, ktoré prechod dopredu prešiel pred
prvým spojením nezhodným s opačným smerom, a to iba v dvoch prípadoch. Buď prechod
dozadu prejde presne tie uzly (`walk: "prev"`). Alebo `init_task.prev` ukazuje práve na
prvý nezhodný uzol a jeho obsah je vlákno (tgid ≠ pid) procesu spomedzi tých uzlov
(`walk: "tail"`): jadro do zoznamu `tasks` zapája iba vodcov skupín, takže taká stránka
pochádza z iného okamihu ako spojenia, ktoré na uzol vedú. Inak zoznam zostáva
`truncated`.

V kampani `benign-v5-20261025` sa zoznam roztrhol opačne
([záznam](../data/results/collection_process_walk_insert_20261026.json)). V snímke 613
session 18 ukazovali `next` posledného procesu aj `init_task.prev` na nové vlákno jadra,
ktoré `kthreadd` vložil do recyklovaného `task_struct`. Jeho stránka sa však prečítala
skôr a mala ešte obsah ukončeného vlákna procesu `python3` so spojeniami skopírovanými
od vodcu skupiny. Prechod dopredu sa preto zacyklil a prechod dozadu prešiel iba 79
zo 110 uzlov. V snímke 70 tej istej session ten istý jav zasiahol iba prechod dozadu.
Pravidlo `tail` takú snímku uzavrie bez nového uzla a ten pribudne v ďalšej snímke.
Zvyšné riziko: z jedného obrazu sa nedá vylúčiť, že `task_struct` vodcu, ktorého
vedľajšie vlákno práve robí `exec` na konci zoznamu, sa po uvoľnení recykluje na vlákno
iného procesu zo zoznamu skôr, ako sa jeho stránka prečíta. Riadok by potom bol bez
procesu, ktorý v zozname bol celý čas. Vyžaduje to `exec` z vedľajšieho vlákna
najnovšieho procesu počas čítania jednej snímky, čo služby laboratória nerobia. Iné tvary
roztrhnutia, napríklad obsah ukončeného vodcu skupiny namiesto vlákna, riadok naďalej
zneplatnia a session zamietnu. V kampani `benign-v6-20261026` audit použil pravidlo `tail`
v 3 {{res:collection_campaign_benign_v6_20261026.json:values.summary.process_walk_tail_rows}} riadkoch a pravidlo `prev` v 11 {{res:collection_campaign_benign_v6_20261026.json:values.summary.process_walk_prev_rows}}
riadkoch; počet procesov v nich ležal v rozsahu susedných snímok (porovnanie počtov,
nie zoznamov) a audit prijal všetky session ([záznam](../data/results/collection_campaign_benign_v6_20261026.json), [MERANIA.md](MERANIA.md) 2026-10-29).

**Formulácia do textu práce.**

> Snímka je živá: virtuálny stroj sa počas čítania nezastavuje, pretože použité rozhranie
> hypervízora (eBPF nad modulom `kvm`) je pozorovacie a zastavenie vCPU neponúka
> (`vmic_backend_ops_t.pause == NULL` v `backend_ebpf.c`). Stránky jednej snímky preto
> pochádzajú z rôznych okamihov a prechod spájaného zoznamu jadra sa môže roztrhnúť.
> Parser je voči tomu obranný — každý prechod má strop, detekciu cyklu a kontrolu
> rozumnosti hodnôt — a nekompletný výsledok označuje príznakom `truncated` (s výnimkou
> zvyškového rizika pravidla pre koniec zoznamu nižšie), takže sa
> nedá zameniť za skutočný stav hosťa. Samotné uzavretie prechodu nepovažuje za dôkaz
> správnosti: roztrhnutý zoznam procesov uzavrie iba vtedy, keď prechod v opačnom smere
> prejde presne tie isté uzly, alebo keď koniec zoznamu (`init_task.prev`) ukazuje práve
> na prvý nezhodný uzol, ktorého obsah je vlákno procesu zo zoznamu, teda stránka
> z iného okamihu. Toto pravidlo má zvyškové riziko: ak vedľajšie vlákno najnovšieho
> procesu počas čítania jednej snímky urobí `exec` a `task_struct` jeho vodcu sa stihne
> recyklovať na vlákno iného procesu zo zoznamu, riadok je bez tohto procesu a príznak
> `truncated` nemá. Merania pauzy sa neuvádzajú, lebo pauza
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

Zdroj správania je v BPF programe (`vmicollect/bpf/vmic_kvm.bpf.c`): čítanie ide cez
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
Profil sa získal **z hosťa, mimo behu zberu** — rovnako, ako profil používa LibVMI
alebo Volatility. Nikde v tejto práci sa preto nesmie napísať „bez akejkoľvek znalosti
hosťa“. Odber sa raz zopakoval: profil v repe je z 2026-09-19 (boot `82b778a3…`), lebo
profil z 2026-09-18 po reštarte hosťa prestal sedieť (L17). Odvtedy sa znova neodoberal
(`git log -- 'profiles/*/kallsyms.txt'`): adresy sa pre snímky iných bootov aj pre klon
`hyptcn-lab` s tým istým jadrom preukotvujú.

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
> a typové informácie BTF (`/sys/kernel/btf/vmlinux`). Profil sa získal
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

## L4 — Parsuje sa pamäť jadra, nie pamäť procesov — ČIASTOČNE ODSTRÁNENÉ 2026-10-05 (A4)

**Fakt (pôvodný).** Preklad adries pokrýva **priestor jadra**: obraz jadra a priamy mapping
lineárnym vzťahom, oblasti modulov a vmalloc prechodom tabuliek stránok z `init_top_pgt`.
Obsah pamäte používateľských procesov sa **neparsuje**. Chýba na to vstup: preklad
používateľských adries potrebuje hodnotu CR3 konkrétneho vCPU (alebo `mm_struct->pgd`
procesu) a **backend registre vCPU nečíta** — z modulu `kvm` berie mapu memslotov, a z
vCPU iba ich počet.

Prakticky to znamená: procesy, moduly a sokety sa zo snímky rekonštruujú, ale ich
používateľské dáta (argumenty, obsah haldy, načítané knižnice v pamäti procesu, spustiteľný
kód procesu) nie.

**Zmena 2026-10-05 (blok A4, commit `88608d7` a oprava `66ec043`, `guestparse/procmap.py`).**
Registre vCPU stále nečíta nič, ale pre **priradenie zmenených binov procesom** sa
registre nepotrebujú: pre každý proces
sa koreň tabuliek vezme z `mm->pgd` (ukazovateľ v pamäti jadra, preloží sa rovnako ako
iné jadrové adresy) a zostúpi sa celými používateľskými tabuľkami — bez VMA zoznamu,
ktorý v BTF tohto jadra (Debian 6.1.159, maple tree) ani nie je. Výsledok:
`python3 -m guestparse procmap` priradí zmenené stranky binu konkrétnym procesom.
Čísla, ktoré tu stáli pôvodne (bin 21: 3560 strán jadro, 512 systemd), sú z `88608d7`;
zneplatnila ich oprava `66ec043`, ktorá zostup obmedzila na používateľskú polovicu PGD
(predtým sa procesu priraďovali zrkadlené jadrové mapovania). Test
`guestparse/tests/test_procmap.py` čísla neobsahuje a artefakt v `data/results/` k nim nie
je. Výstup 2026-10-29 (commit `709ee7f`) na tej istej snímke z 18. 9. (súbor `.vmicd` je
mimo gitu):

```
$ python3 -m guestparse procmap --snapshot data/sessions/20260918T154914Z_validate/snap \
        --profile profiles/debian12-6.1.0-42-cloud-amd64 --bin 21
POZOR: profil bol z ineho bootu (KASLR); preukotvenie o -444596224 uspelo - pokracujem s preukotvenym profilom
bin   gpa_od          zmenenych   jadro   procesy (top 5)
  21  0x15000000          4072    3787   1/systemd:141, 377/qemu-ga:61, 364/systemd-resolve:32, 1702/(sd-pam):19, 1701/systemd:13
mapovane_stranky=12194, capped=False, cas=0.09 s (zostup uzivatelskymi tabulkami z mm->pgd (VMA zoznam nie je v BTF tohto jadra))
```

Čo sa NEZMENILO: obsah používateľskej pamäte sa stále neparsuje (žiadne argumenty,
halda, knižnice) — mapovanie bin→proces je len o **vlastníctve stránok**, nie o čítaní
ich obsahu.

**Overenie.** Na strane parsera sa CR3 ani registre vCPU nespomínajú (2026-09-18
aj 2026-10-29). Pôvodný druhý príkaz
(`grep -n "mm_struct\|pgd\|user space\|pouzivatelsk" guestparse/*.py`) 2026-09-18
nevypísal nič. Od 2026-10-05 je v `guestparse/procmap.py`
koreň používateľských tabuliek, ktorý sa číta z pamäte jadra (`mm->pgd`), nie z registra:

```
$ grep -rniE "cr3|vcpu|\bregs\b|register" guestparse/*.py | wc -l
0
$ grep -n "mm->pgd" guestparse/procmap.py
5:cele uzivatelske tabulky stranok kazdeho procesu (koren = mm->pgd, prelozeny
13:verzie jadra (staci mm->pgd, ktory v BTF je) a vidi presne to, co proces
70:    Zostup celymi uzivatelskymi tabulkami z mm->pgd. Vracia True, ked sa
200:        "sposob": ("zostup uzivatelskymi tabulkami z mm->pgd (VMA zoznam nie "
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
> štvorúrovňových tabuliek stránok z `init_top_pgt`. Používateľské tabuľky stránok
> procesov sa prechádzajú tiež, ale iba na priradenie zmenených fyzických stránok
> procesom: ich koreň sa číta z `mm->pgd` v pamäti jadra, registre vCPU (CR3) použitý
> backend nečíta — z modulu `kvm` číta mapu memslotov a z vCPU iba ich počet. Obsah
> pamäte používateľských procesov sa neparsuje. Zo snímky sa preto rekonštruujú jadrové
> objekty (procesy, načítané moduly, sieťové spojenia) a vlastníctvo zmenených stránok,
> nie používateľské dáta procesov (argumenty, halda, knižnice, kód).

**Čo by to odstránilo.** Prechod cez `task_struct->mm->pgd` je od 2026-10-05
implementovaný (`guestparse procmap`, testy `guestparse/tests/test_procmap.py`), ale slúži
iba na vlastníctvo stránok. Čítanie obsahu používateľskej pamäte — napríklad oblastí VMA,
ktoré v BTF tohto jadra nie sú ako zoznam (maple tree) — nie je implementované ani
zmerané (`UNVERIFIED`).

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

Hlavička `vmicollect/tests/hole_test.c` to hovorí sama: „Backend 'ebpf' toto riesi mapou memslotov
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
**neinštaluje rootkit**. Urobí sa kópia snímky (vždy `guestparse/tests/data/mini.vmicd`,
27-stránkový výrez reálnej snímky z 2026-09-19 v repe, a navyše reálna snímka, ak je na
stroji), v kópii sa jedna položka tabuľky prepíše na adresu v oblasti modulov, a overí
sa, že detektor taký zápis nájde a správne ho pomenuje. V hosťovi sa nemení nič.

Prečo to tam musí byť: kontrola, ktorá na čistom hosťovi vždy vráti nulu, je na
nerozoznanie od funkcie, ktorá vždy vracia nulu. Negatívny aj pozitívny prípad musia bežať
oba.

Prečo to nie je skutočný rootkit: v meraniach sa do hosťa žiadny modul jadra nezaviedol.
Pôvodný dôvod (2026-09-18): hosť `hyptcn-guest` nemal `gcc`, `make` ani hlavičky jadra
a nemal funkčné DNS, takže sa nedali ani doinštalovať. Od 2026-10-05 (commit `2829eb7`)
existuje PoC skutočného rootkitu `scripts/poc/diamorphine.sh` (Diamorphine LKM; v hosťovi
potrebuje `git`, `make`, `gcc` a hlavičky jadra). Spúšťa ho starý harness sedení
`scripts/session.sh` s manifestom `harness/session_manifest_g1_diamorphine.json`
v zahadzovanom overlayi; harness v repozitári zostáva ako historický a diagnostický
a izolovanej útokovej etape (`METODIKA_ZBERU.sk.md`, kap. 7) nezodpovedá. Beh PoC nie je
doložený: v `data/sessions/` k nemu sedenie nie je a artefakt nemá (`UNVERIFIED`).

**Overenie.** Hlavička `guestparse/tests/test_injection.py` (stav 2026-10-29):

> Test si urobi KOPIU snimky a v KOPII prepise jednu polozku tabulky volani
> jadra na adresu v oblasti modulov. V hostovi sa NIC nemeni a ziadny rootkit
> sa nikam neinstaluje (...) Ide teda o injekciu do datoveho suboru, nie o realny utok;
> dokazuje sa tym iba to, ze detektor taky zapis najde a spravne ho pomenuje.
> (...) KDE TO BEZI: nad malou snimkou verzionovanou v repe (tests/data/mini.vmicd),
> teda aj v cerstvom klone bez pristupu k tomuto stroju, a navyse nad realnou
> snimkou hosta, ked na stroji je (znacka 'realsnap').

Výsledok 2026-10-29 na tomto stroji: tri testy nad `mini.vmicd` prešli, tri testy nad
reálnou snímkou sa preskočili, lebo `/var/tmp/vmic-val` už neexistuje (v behu
2026-09-18 bežali nad ňou):

```
$ python3 -m pytest -q guestparse/tests/test_injection.py
3 passed, 3 skipped in 0.31s
```

Počet testov celej sady sa tu ručne neuvádza; generuje ho kapitola 3 `docs/PRIRUCKA.md`.

**Formulácia do textu práce.**

> Pozitívny prípad detekcie hookov v tabuľke systémových volaní bol overený injekčným
> testom: do kópie reálnej snímky sa prepísala jedna položka tabuľky na adresu v oblasti
> modulov a detektor ju nahlásil. **Ide o injekciu do dátového súboru, nie o skutočný
> rootkit.** V hosťovi nebol zavedený žiadny modul jadra: pôvodný hosť na to nemal
> prekladač, nástroje `make`, hlavičky jadra ani funkčné rozlíšenie mien a pripravený
> test so skutočným rootkitom nemá doložený beh.
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
$ grep -n "guest_memfd" vmicollect/src/backend_ebpf.c vmicollect/bpf/vmic_bpf_abi.h
vmicollect/bpf/vmic_bpf_abi.h:163:    __u32 skipped;          /* sloty bez HVA (guest_memfd)             */
vmicollect/bpf/vmic_bpf_abi.h:196:    __u32 skipped;          /* out: preskocene sloty (guest_memfd)     */
vmicollect/src/backend_ebpf.c:902:                 "(guest_memfd / prave sa meni) - budu nulove",
$ grep -h "guest_memfd" vmicollect/README.md
**Confidential VM (SEV-SNP, TDX).** Pamat takej VM je v `guest_memfd` a cez
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

**Fakt.** Rozhranie pluginu (`vmic_hook_api_t`, od 2026-10-05 ABI 2) má štyri položky:
číslo ABI, ukazovateľ na konfiguráciu iba na čítanie, logovaciu funkciu a `alarm()`,
ktorou plugin vyhlási alarm. Zberač alarm zapíše do `alarm.json` a `alarms.jsonl`
a reťazec označí markerom HOLD, aby ho retencia nezmazala. **Neobsahuje `read_pa`** ani
inú cestu k pamäti hosťa, ani ukazovateľ na backend či zberač. Plugin dostane pri každej
snímke `const vmic_snapshot_t *` — teda cestu k hotovému súboru, časy a počítadlá — a ak
chce obsah, musí si súbor otvoriť sám. Reakciu na alarm má voliteľný plugin
`vmicollect/hooks/react_hook.c` (pozastavenie VM, odpojenie siete alebo snapshot cez
libvirt); bez jeho načítania zberač nereaguje nijako.

Od verzie zberača 1.1 (2026-10-25) beží hook pri writeri `delta` vo vlákne `vmic-writer`,
až po zverejnení snímky (súbor aj sidecar existujú), nad jej kópiou; ukazovatele v zázname
platia iba počas volania. Dlhý hook tak cyklus nezdrží, ale oneskorí zverejnenie každej
ďalšej snímky (fronta je FIFO) a až po vyčerpaní pamäte fronty aj cyklus. Pri writeri `raw`
beží hook naďalej synchrónne v hlavnej slučke a hook dlhší ako perióda spôsobí zmeškané sloty.
Do verzie 1.0 platilo toto aj pre `delta`. Vlákno `vmic-writer` má zablokované signály
SIGINT/SIGTERM/SIGHUP; dieťa spustené z hooku (napr. `system()`) ich zdedí zablokované.

**Overenie.** Celé rozhranie, ktoré plugin dostane, je v `vmicollect/include/vmic.h`:

```c
struct vmic_hook_api {
    unsigned abi;
    const vmic_config_t *cfg;
    void (*log)(int level, const char *fmt, ...);
    int  (*alarm)(const struct vmic_hook_api *api, const vmic_alarm_t *a);
};
```

(stav 2026-10-29, komentáre vynechané; pred commitom `b431013` z 2026-10-05 mala štruktúra
iba prvé tri položky). Reálny beh s pluginom z 2026-09-18 (backend `file`, bez roota,
výpis skrátený; cesta dočasného adresára nahradená `$D`):

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
> jednotlivých fáz cyklu a počítadlami zmenených stránok. Môže vyhlásiť alarm, ktorý
> zberač zapíše a pri ktorom chráni príslušný reťazec snímok pred retenciou; reakciu
> na úrovni hypervízora vykoná iba voliteľný plugin, predvolene vypnutý. **Nedostáva
> funkciu na čítanie pamäte hosťa ani obsah stránok**; ak potrebuje dáta, musí si uloženú
> snímku otvoriť sám.
> Pri inkrementálnom zápise (writer `delta`, zberač verzie 1.1) beží plugin vo vlákne, ktoré
> súbory zverejňuje mimo vzorkovacieho cyklu: výpočet dlhší než perióda zberu neposunie
> vzorkovanie, ale oneskorí zverejnenie ďalších snímok a pri dlhodobom zaostávaní vyčerpá
> pamäť fronty. Návrh skórovacieho komponentu musí s oboma vlastnosťami počítať.

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
4. **Krížový rozdiel kratší než jedna perióda nie je nález.** Aj pri dvoch uzavretých
   prechodoch živej snímky (L1) môže fork alebo exit krátkeho procesu vytvoriť rozdiel
   bez skrývania; v benígnej session to raz nastalo
   ([záznam](../data/results/collection_crossview_race_20261022.json)) a v kampani
   `benign-v6-20261026` malo taký rozdiel 16 {{res:collection_campaign_benign_v6_20261026.json:values.summary.integrity_unconfirmed_rows}} riadkov v
   8 {{res:collection_campaign_benign_v6_20261026.json:values.summary.integrity_unconfirmed_sessions}} z 48 {{res:collection_campaign_benign_v6_20261026.json:n}} session, všetky pri procesoch `postgres`,
   pri 0 {{res:collection_campaign_benign_v6_20261026.json:values.summary.integrity_findings}} potvrdených nálezoch ([záznam](../data/results/collection_campaign_benign_v6_20261026.json)). Extrakcia,
   audit a safeguard preto berú krížový rozdiel za nález až vtedy, keď ho ukáže aj
   bezprostredne predchádzajúca snímka. Objekt skrytý kratšie ako jednu periódu nález
   nevytvorí a alarm skrytého objektu príde o periódu neskôr.

**Overenie.** Zdôvodnenie je v hlavičke `guestparse/checks.py`. Na meranej snímke sa
2026-09-18 uzavreli všetky vtedajšie tri kontroly a nález bol nulový:

```
$ python3 -m guestparse checks --snapshot $S --profile $P
sys_call_table         451 poloziek v [0xffffffff96000000, 0xffffffff96e01ef2), nalezov: 0
procesy krizovo        tasks 80 vs. children/sibling 80, nalezov: 0
moduly krizovo         modules 51 vs. module_kset 51 (z 109 kobjektov), nalezov: 0
nalezov spolu: 0 (z toho hookov v tabulke volani: 0)
$ echo $?
0
```

Ten istý príkaz 2026-10-29 (commit `709ee7f`;
`S=data/sessions/20260918T154914Z_validate/snap`,
`P=profiles/debian12-6.1.0-42-cloud-amd64`) profil najprv preukotví (L17) a vypíše štyri
kontroly. Štvrtá, obsah textu jadra, je nedostupná pre nesediacu baseline (L18), preto
príkaz skončí kódom 4:

```
$ python3 -m guestparse checks --snapshot $S --profile $P
POZOR: profil bol z ineho bootu (KASLR); preukotvenie o -444596224 uspelo - pokracujem s preukotvenym profilom
sys_call_table         451 poloziek v [0xffffffff96000000, 0xffffffff96e01ef2), nalezov: 0
procesy krizovo        tasks 80 vs. children/sibling 80, nalezov: 0
moduly krizovo         modules 51 vs. module_kset 51 (z 109 kobjektov), nalezov: 0
text jadra             NEDOSTUPNA (baseline textu nesedi s profilom ani po posune o KASLR rozdiel (ine jadro); obnov ju nad cistou snimkou)
NEUZAVRETE kontroly: text_integrity - ich nulovy vysledok nic nedokazuje (preto navratovy kod 4, nie 0)
nalezov spolu: 0 (z toho hookov v tabulke volani: 0)
$ echo $?
4
```

**Formulácia do textu práce.**

> Kontroly integrity nad snímkou sú porovnaním dvoch nezávislých zdrojov, ktoré musia
> sedieť: položky tabuľky systémových volaní proti rozsahu textu jadra, zoznam procesov
> proti stromu potomkov, zoznam modulov proti objektom v `module_kset` a obsah stránok
> textu jadra proti baseline v profile (v uložených dátach pilotov a kampaní táto
> štvrtá kontrola nebola vyhodnotená, L18). Ich slepé miesta sú známe a pomenované:
> prepísanie obsluhy na inú adresu **vnútri** rozsahu textu jadra
> rozsahová kontrola nevidí; skrytie, ktoré odpojí uzol z oboch porovnávaných štruktúr
> naraz, nevytvorí rozdiel; a nulový výsledok kontroly, ktorá sa pre neúplný prechod
> zoznamu neuzavrela, nie je dôkazom čistoty — nástroj takýto prípad označuje samostatne
> a nehlási ho ako úspech. Keďže snímka je živá, krížový rozdiel sa za nález považuje až
> po zopakovaní v nasledujúcej snímke; skrytie kratšie ako jedna perióda zberu sa tak
> nezistí.

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
nevznikne artefakt v `data/results/`. Výnimkou je pamäť zberača v riadku „vplyv zberu
na hostiteľa“: tá je zmeraná (diagnostika 2026-10-25); CPU zberača monitor hostiteľa
zaznamenáva, žiadny záznam v `data/results/` ho však ako spotrebu nevyhodnocuje
(`collection_writeback_stall_20261024.json` ho uvádza iba vo vzorkách okolo dlhých cyklov).
Riadky vplyvu na hosťa a na hostiteľa uvádzajú navyše pozorovanie z prostredia so
spoločným diskom VM a snímok (2026-10-21), ktoré párované meranie nenahrádza.

| Veličina | Stav | Čo na ňu treba |
|---|---|---|
| živá latencia snímka → skóre modelu | `UNVERIFIED` | meranie počas spoločného behu zberača a detektora `python3 -m safeguard run`: latencia od konca cyklu po vypočítané skóre, medián a p95 z aspoň 12 cyklov; doteraz zmerané iba nad uloženými snímkami (`latency_score_20260919.json`, `latencia_predikcia_real_20261005.json`; obe vyrobila staršia cesta `tcn/score.py`, ktorá v repozitári zostáva ako historická a diagnostická) |
| vplyv zberu na výkon vnútri hosťa | `UNVERIFIED` | benchmark s pevne daným objemom práce v hosťovi, schéma A/B/A, medián a IQR z aspoň 12 opakovaní; párované meranie podľa `METODIKA_ZBERU.sk.md` (kap. 7, Výkonnosť) chýba. Pozorované, nie zmerané A/B/A: keď bol disk VM na tom istom súborovom systéme ako snímky, spätný zápis plnej snímky oneskoril databázu hosťa a 4 {{res:collection_io_interference_20261021.json:values.request_failures.count}} požiadavky prekročili limit klienta 4 s ([záznam](../data/results/collection_io_interference_20261021.json), [MERANIA.md](MERANIA.md) 2026-10-21); disk VM sa potom presunul na iné zariadenie |
| vplyv zberu na hostiteľa | `UNVERIFIED` (pamäť zmeraná, CPU zaznamenané, nevyhodnotené) | pamäť: zberač 1.1 s `output.mlock` drží frontu uzamknutú v RAM (najväčšia možná plná snímka + 512 MiB), monitor kampane ju zaznamenáva (`Mlocked`); diagnostika 2026-10-25 pri VM s 2 GiB: VmRSS po uzamknutí 2596 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_mlock.vmrss_mib}} MiB, `Mlocked` hostiteľa počas zberu najviac 2609 {{res:collection_writer_diagnostic_20261025_timing.json:values.during_capture.mlocked_mib_max}} MiB ([záznam](../data/results/collection_writer_diagnostic_20261025_timing.json), [MERANIA.md](MERANIA.md) 2026-10-25; jeden 40-minútový beh mimo korpusu); chýba vyhodnotená spotreba CPU celého procesu (monitor hostiteľa ju zaznamenáva po 1 s za všetky vlákna spolu, teda aj za `vmic-writer` so SHA-256 a `vmic-log`, ako `procs.vmicollect.cpu_pct` v `host_monitor.jsonl`; záznam diagnostiky ju nevyhodnocuje a má iba maximum vzorkovacieho vlákna na cyklus, `rusage_max.cpu_ms`), priemer za celý beh a vplyv na ostatnú záťaž hostiteľa; pozorovaný je vplyv spätného zápisu plnej snímky na I/O hostiteľa pri spoločnom disku VM a snímok: 12.0 {{res:collection_io_interference_20261021.json:values.writeback_burst_after_second_full.duration_s}} s pri iowait až 51.163 {{res:collection_io_interference_20261021.json:values.writeback_burst_after_second_full.iowait_max_pct}} % ([záznam](../data/results/collection_io_interference_20261021.json), zamietnutý pilot so zberačom 1.0) |
| dlhý beh s retenciou | `UNVERIFIED` | beh jedného procesu zberača rádovo v hodinách s retenciou: zmeškané sloty, rast obsadeného miesta, správanie pri reštarte domény počas behu; zatiaľ existujú iba hodinové behy bez retencie: kampaň `benign-v4-20261022` mala 37 {{res:collection_campaign_benign_v4_20261022.json:n}} samostatných behov zberača po 720 {{res:collection_campaign_benign_v4_20261022.json:values.sessions.0.collector_end.snapshots}} cykloch (nový proces zberača v každej session, reštart hosťa na hraniciach skupín), spolu 26640 {{res:collection_writeback_stall_20261024.json:n}} cyklov a jeden zmeškaný slot pri spätnom zápise na SSD (zberač 1.0, [záznam](../data/results/collection_campaign_benign_v4_20261022.json), [MERANIA.md](MERANIA.md) 2026-10-25); zberač 1.1 bežal v kampani `benign-v5-20261025` tiež iba v hodinových behoch bez retencie: 18 {{res:collection_campaign_benign_v5_20261025.json:n}} behov po 720 {{res:collection_campaign_benign_v5_20261025.json:values.sessions.0.collector_end.snapshots}} cykloch (nový proces zberača v každej session), 0 {{res:collection_campaign_benign_v5_20261025.json:values.summary.scheduler_skips}} hlásení plánovača o zahodenom slote ([záznam](../data/results/collection_campaign_benign_v5_20261025.json), [MERANIA.md](MERANIA.md) 2026-10-26); v kampani `benign-v6-20261026` 48 {{res:collection_campaign_benign_v6_20261026.json:n}} behov po 720 {{res:collection_campaign_benign_v6_20261026.json:values.sessions.0.collector_end.snapshots}} cykloch, 0 {{res:collection_campaign_benign_v6_20261026.json:values.summary.scheduler_skips}} hlásení plánovača o zahodenom slote ([záznam](../data/results/collection_campaign_benign_v6_20261026.json), [MERANIA.md](MERANIA.md) 2026-10-29); reštart domény počas behu jedného procesu zberača doložil iba krátky beh s 8 {{res:a1_restart_20261005T204555Z.json:n_sidecars}} snímkami nad doménou `hyptcn-guest` ([záznam](../data/results/a1_restart_20261005T204555Z.json), 2026-10-05) |
| správanie pri periódach iných než 2 s a 5 s | `UNVERIFIED` | sweep periódy a veľkosti bloku |
| FAR benígnej prevádzky a presnosť klasifikátora profilu záťaže na odloženej role `test_benign` | nezmerané | jediné spustenie `python3 -m tcn.eval far --role test_benign --final` nad prehratiami všetkých 12 {{res:safeguard_train_benign_v6_20261029.json:values.sessions_by_role.test_benign}} session `test_benign` balíkom `server-v2-benign-v6` (raz na korpus, rozhodnutie vlastníka; [`SAFEGUARD.sk.md`](SAFEGUARD.sk.md)); rola `dev` je vyhodnotená ([záznam](../data/results/safeguard_far_dev_benign_v6_20261029_b.json)), ale vyberala checkpointy prediktora aj klasifikátora, takže jej FAR ani presnosť nie sú odložené a do textu sa ako záverečný výsledok nesmú dostať |
| presnosť detekcie voči reálnym malvérovým vzorkám | nezmeraná | plánovaná izolovaná etapa (`METODIKA_ZBERU.sk.md`, kap. 7), zatiaľ neuskutočnená; PoC techniky `scripts/poc/` a sťahovanie vzoriek `scripts/mb_fetch.py` existujú, ale nemajú artefakt (`UNVERIFIED`) — podrobne v [L16](#l16--presnosť-detekcie-malvéru-nebola-meraná) |

**Čo z tejto tabuľky medzičasom odišlo.** Latencia snímka → príznakový vektor tu stála
so stavom `UNVERIFIED` a s dôvodom „príznakový priestor zatiaľ neexistuje“. Oboje už
neplatí: `features/` existuje a latencia je zmeraná 2026-09-18 (`scripts/measure_latency.sh`,
artefakt `data/results/latency_vector_20260918.json`, rozpis v `docs/MERANIA.md`).
Riadok bol preto 2026-09-19 z tabuľky odstránený.

**Prečo je živá latencia snímka → skóre ďalej `UNVERIFIED`, hoci skórovanie existuje.**
Model aj skórovací komponent hotové sú — dôvod, ktorý tu stál („model ani skórovací
komponent zatiaľ neexistujú“), bol nepravdivý a 2026-09-19 sa opravil. Integrovanou
detekčnou cestou je dnes `safeguard/` (`python3 -m safeguard`, skórovanie
v `safeguard/runtime.py`, model nad `tcn/model.py`); staršia cesta `tcn/score.py`
(používajú ju `scripts/detektor.py` a `scripts/soft_rt_check.py`) zostáva v repozitári ako
historická a diagnostická. Nezmerané je niečo iné: skórovanie sa zatiaľ meralo len nad
**uloženými** snímkami, mimo behu zberu (`data/results/latency_score_20260919.json`, kľúč
`co_sa_NEMERALO` to hovorí aj v samotnom artefakte, a
`data/results/latencia_predikcia_real_20261005.json`; obe vyrobil `tcn/score.py`).
Spoločný beh zberača a detektora `python3 -m safeguard run` je podľa
[`SAFEGUARD.sk.md`](SAFEGUARD.sk.md) `UNVERIFIED`, takže číslo pre živú cestu nie je.
Druhá vec, ktorá z toho čísla nevyplýva: kvalita rozhodnutia. Obe merania bežali s modelom,
ktorý nebol natrénovaný na korpuse (náhodné váhy v `latency_score_20260919.json`, smoke model
v `latencia_predikcia_real_20261005.json`); natrénované boli dovtedy iba diagnostické modely
(syntetický model v `data/results/safeguard_validation_20261013_a.json`, malé idle a lab
sedenia v `data/results/trenovanie_prediktor_*.json`). Balík natrénovaný 2026-10-29 na korpuse
`benign-v6-20261026` ([záznam](../data/results/safeguard_train_benign_v6_20261029.json)) v žiadnom
meraní latencie nebežal a aj s ním by šlo o čas cesty, nie o kvalitu rozhodnutia (L16).
(Do 2026-10-30 tu stálo, že model na korpuse `benign-v6-20261026` natrénovaný nie je.)

Ďalšia nedoriešená vec, ktorá patrí do priznaných: pri načítaní BPF programu sa objavuje
nefatálne hlásenie `libbpf: Error in bpf_create_map_xattr(pages): -EINVAL. Retrying
without BTF.` Mapa sa vytvorí aj bez BTF a zber funguje, ale príčina nebola zistená.
V novších behoch má hlásenie tvar
`Error in bpf_create_map_xattr(pages):Invalid argument(-22). Retrying without BTF.`;
posledný uložený výskyt je z pilota 7 z 2026-10-26 (`collection_pilot_7_20261026_audit.json`,
`values.logs.sections.collector.warnings`), záznam kampane `benign-v6-20261026` varovania
zberača neukladá.

**Formulácia do textu práce.**

> Práca uvádza latenciu od zosnímania pamäte po príznakový vektor, ale neuvádza latenciu
> po skóre modelu meranú počas bežiaceho zberu — zmerané je len spracovanie nad uloženou
> snímkou. Neuvádza ani vplyv zberu na výkon hosťa, spotrebu procesora zberačom na
> hostiteľovi a správanie pri dlhodobom behu jedného procesu zberača. Z nárokov na
> hostiteľa je vyhodnotená iba pamäť: zberač drží frontu snímok uzamknutú v RAM, pri
> virtuálnom stroji s 2 GiB to v jednom diagnostickom behu bolo
> 2596 {{res:collection_writer_diagnostic_20261025_timing.json:values.collector_mlock.vmrss_mib}} MiB rezidentnej pamäte.
> Spotrebu procesora celým procesom zberača monitor hostiteľa počas zberu zaznamenával
> každú sekundu, v práci však vyhodnotená nie je. Pozorovaný je ešte vplyv spätného zápisu
> plných snímok na vstupno-výstupné operácie hostiteľa, ktorý pri spoločnom disku
> virtuálneho stroja a snímok oneskoril aj hosťa; párovým meraním overený nie je.
> Pri ostatných veličinách nejde o vynechanie: v rámci tejto práce neboli namerané, a formulácie
> typu „minimálny vplyv na virtuálny stroj“ alebo „spracovanie v reálnom čase“ by preto
> boli tvrdením bez podkladu. Tam, kde je to potrebné, sa namiesto nich uvádza konkrétna
> perióda zberu a namerané trvanie jednotlivých fáz cyklu, ktoré uložené artefakty majú.
> Falošné alarmy a presnosť klasifikátora profilu záťaže sú vyhodnotené iba na vývojovej
> množine, ktorá slúžila na výber modelu; na odloženej testovacej množine zmerané neboli.
> Presnosť voči reálnym malvérovým vzorkám nebola meraná.

---

## L13 — Príznakový vektor: čo o ňom treba vedieť pred tým, než sa naň natrénuje model

**Na plnej snímke sú `changed_ratio` a `zero_ratio` kolineárne.** Delta writer porovnáva
stránky proti tabuľke hashov, ktorá je na začiatku reťazca nulová, takže „zmenená" tam
znamená „nenulová" a platí presne `changed_ratio = 1 − zero_ratio` (overené na sidecari
seq 0: 0,854823 + 0,145177 = 1,000000 na všetkých binoch). Riadok plnej snímky má teda iný
význam než riadky delta snímok. `features/windows.py` okno, ktoré obsahuje plnú snímku,
neposkladá vôbec (dôvod je v `Okna.vynechane`), rovnako `safeguard/features.py`; riadok
zostáva v matici s príznakom `je_plna`. Kto pridá nový príznak alebo nový model, musí
o tom vedieť.

**Formulácia do textu práce:** „Prvá snímka reťazca je referenčná; príznaky odvodené od zmeny
majú v nej definíciu, ktorá sa líši od nasledujúcich snímok, preto sa v sekvenciách
spracúvajú osobitne."

**Výpočet príznakov predlžuje cyklus.** Základ stojí ~51–53 ms na cyklus bez ohľadu na
množstvo zmien (prejde sa všetkých 528 417 stránok), entropia ďalších ~3,5 µs na zmenenú
stránku. Na plnej snímke to je ~431 ms navyše. Čísla sú v `docs/MERANIA.md`, záznam
z 2026-09-18 (fáza F2).

**Formulácia do textu práce:** „Extrakcia príznakov je súčasťou cyklu zberu a jej cena je
zmeraná; na nečinnej doméne `hyptcn-guest` pri perióde 2 s zostal p95 latencie cyklu pod
periódou s rezervou približne trojnásobku."

Rezerva platí iba pre toto meranie (F2: nečinná VM, zberač 1.0). Pod serverovou záťažou
laboratória `hyptcn-lab` pri perióde 5 s trval so zberačom 1.0, ktorého cyklus zahŕňal aj
volania `write()` pre zmenené stránky ([MERANIA.md](MERANIA.md), oprava z 2026-10-25),
najpomalší delta cyklus session 1 kampane `benign-v3-20261022`
2648.0 {{res:collection_campaign_benign_v3_20261022.json:values.sessions.0.long_cycles.2.total_ms}}
ms a druhá plná snímka pilota 5
2735.9 {{res:collection_pilot_5_20261022_timing.json:values.full_snapshots.seq_360.cycle_ms}}
ms; plná snímka všetkých stránok hosťa by podľa lineárneho odhadu z pilota 5 trvala okolo
4355.3 {{res:collection_full_snapshot_growth_20261022.json:values.estimate_all_pages_ms}}
ms (odhad, nie meranie). So zberačom 1.1, ktorý zapisuje mimo vzorkovacieho cyklu, mala
kampaň `benign-v5-20261025` najdlhší cyklus
1821.1 {{res:collection_campaign_benign_v5_20261025.json:values.summary.cycle_total_ms_max}}
ms (plná snímka) a najdlhšiu deltu
894.8 {{res:collection_campaign_benign_v5_20261025.json:values.summary.delta_ms_max_all}}
ms ([MERANIA.md](MERANIA.md), záznam z 2026-10-26); kampaň `benign-v6-20261026` mala
najdlhší cyklus
2009.0 {{res:collection_campaign_benign_v6_20261026.json:values.summary.cycle_total_ms_max}}
ms (plná snímka) a najdlhšiu deltu
897.3 {{res:collection_campaign_benign_v6_20261026.json:values.summary.delta_ms_max_all}}
ms ([MERANIA.md](MERANIA.md), záznam z 2026-10-29).

**Počet binov je viazaný na geometriu konkrétnej VM.** Pri 2,02 GiB VM vzniká 131 binov;
pri inej veľkosti pamäte alebo inom rozložení memslotov ich bude iný počet. Model, ktorý by
bral biny ako pevný počet vstupov, by bol použiteľný len na VM rovnakej veľkosti.
Rozhodnuté je to v `safeguard/`: globálny vektor agreguje cez biny a lokálna vetva je
jedna TCN zdieľaná cez všetky biny (`safeguard/model.py`), takže jej váhy od počtu binov
nezávisia. Kontrakt príznakov uloženého modelu však zmrazuje zoznam binov aj rozloženie
pamäte (`feature_contract` a `check_frame` v `safeguard/features.py`), takže model je
použiteľný iba na VM s rovnakou geometriou; zmena geometrie vyžaduje nový tréning. Tiché
doplnenie núl do pevnej dĺžky sa nepoužíva.

**Vektor sa meral na dvoch doménach s rovnakým jadrom.** `hyptcn-guest` má 131 binov,
klon `hyptcn-lab` 130 binov po 16 MiB v troch oblastiach (`values.layout` v
`data/results/collection_pilot_7_20261026_audit.json`). Geometria s inou veľkosťou binu
(1 MiB) je overená iba testom nad synteticky deravým obrazom. Správanie pri hotplugu
pamäte za behu je v kóde ošetrené podpisom oblastí, ale nebolo odskúšané behom.

**`zero_ratio` a `mem_zero_ratio` závisia od veku procesu QEMU.** Stránka, ktorej sa proces
QEMU ešte nedotkol, sa číta ako nulová. Počet nenulových stránok preto rastie s vekom procesu:
v kampani `benign-v4-20261022` z ~130 tisíc na ~320 tisíc stránok. Po každom reštarte hosťa
začala skupina vyššie, než skončila predchádzajúca; v rámci bootu počet na prvom procese QEMU
rástol iba v prvých dvoch skupinách, v `train-3` sa takmer nezmenil a v `dev-1`, `calibration-1`
a `calibration-2` klesol; na novom procese QEMU v jedinej session skupiny `test_benign-1` vzrástol
zo 134873 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.test_benign-1.first_full_pages}} na
146900 {{res:collection_campaign_benign_v4_20261022.json:values.summary.by_group.test_benign-1.last_full_pages}} stránok
([MERANIA.md](MERANIA.md), oprava z 2026-10-25). Tieto príznaky sú vstupom modelu, takže
skupiny zozbierané neskôr na tom istom procese majú systematicky iné hodnoty než skupiny
zozbierané skôr - a v pláne kampane nasledujú tréningové skupiny pred testovacími. Kampaň
`benign-v5-20261025` bežala na jednom procese QEMU spustenom pred `init` (bez reštartov VM
počas kampane): v skupine `train-1` rástol počet zo
122354 {{res:collection_campaign_benign_v5_20261025.json:values.summary.by_group.train-1.first_full_pages}} na
238818 {{res:collection_campaign_benign_v5_20261025.json:values.summary.by_group.train-1.last_full_pages}} stránok
a v `train-3` bol najviac
264999 {{res:collection_campaign_benign_v5_20261025.json:values.summary.by_group.train-3.max_full_pages}}.
Rovnako bežala kampaň `benign-v6-20261026`: v skupine `train-1` rástol počet zo
131986 {{res:collection_campaign_benign_v6_20261026.json:values.summary.by_group.train-1.first_full_pages}} na
251451 {{res:collection_campaign_benign_v6_20261026.json:values.summary.by_group.train-1.last_full_pages}} stránok
a v `test_benign-1` bol najviac
318946 {{res:collection_campaign_benign_v6_20261026.json:values.summary.by_group.test_benign-1.max_full_pages}}.
Vek procesu je teda súbežný s poradím skupín a pri
vyhodnotení ho treba brať ako možný zmätočný faktor (napr. porovnať rozdelenie
`mem_zero_ratio` medzi skupinami).

**Formulácia do textu práce:** „Podiel nulových stránok závisí aj od toho, koľko pamäte hosťa už
hypervízor alokoval; keďže skupiny korpusu vznikali postupne na jednom procese virtuálneho
stroja, tento príznak sa medzi skupinami posúva aj bez zmeny správania hosťa."

**Klasifikátor profilu záťaže nad týmto vektorom zamieňal dva páry profilov (rola `dev`,
2026-10-29).** Balík `server-v2-benign-v6` mal na vývojovej role presnosť na okná
0.663 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.presnost}}
a macro-F1
0.607 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.f1_macro}}
([záznam](../data/results/safeguard_far_dev_benign_v6_20261029_b.json),
`values.klasifikacia_aktivit`). `quiet`, `bursty` a `read_heavy` rozpoznal vo všetkých oknách.
Okná `steady` označil ako `read_heavy`
(653 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.4.3}}
z
656 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.na_triedu.steady.n}},
žiadne správne) a profily `mixed` a `write_heavy` zamieňal navzájom: správne bolo
286 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.1.1}}
okien `mixed` a
356 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.confusion.5.5}}
okien `write_heavy`, každej triedy z
656 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.okna.na_triedu.mixed.n}}.
Väčšinová predikcia sedela v
4 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.relacie.spravnych}}
zo
6 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.klasifikacia_aktivit.relacie.spolu}}
session. Rola `dev` vyberala checkpoint klasifikátora (epocha
1 {{res:safeguard_train_benign_v6_20261029.json:values.train_result.training.selected_classifier_epoch}},
v ďalších epochách bola strata na `dev` vyššia), takže čísla nie sú odložené a výsledok na
`test_benign` chýba. Či tieto profily nerozlišuje vektor, alebo model, sa nezisťovalo.

**Formulácia do textu práce:** „Klasifikátor profilu záťaže na vývojovej množine nerozlíšil
profil steady od read_heavy a zamieňal profily mixed a write_heavy. Vývojová množina slúžila
na výber modelu, preto to nie je nezávislé meranie; výsledok na odloženej testovacej množine
zatiaľ nie je."

---

## L14 — Procesy, moduly a sokety do príznakového vektora nevstupujú — VYRIEŠENÉ 2026-09-19

**Stav.** Toto obmedzenie už neplatí. Zo zoznamu sa neodstraňuje: priznané obmedzenie,
ktoré zmizne bez stopy, vyzerá, ako by nikdy nebolo. Pôvodné znenie je zachované nižšie.

**Čím sa vyriešilo.** Modul `features/snapshot.py` (pridaný 2026-09-19 commitom
`da8ad2e`) skladá z jednej snímky **jeden vektor pevnej dĺžky**: dvadsať príznakov plus
dve polia o samotnom riadku, `ma_predchodcu` a `je_plna` — spolu **22 stĺpcov** (`MENA`
vo `features/snapshot.py`). Pamäťová časť (príznaky 1–8) je agregát bloku `features` zo
sidecaru snímky, ktorý počíta modul `vmicollect`; objektová časť (príznaky 9–20) sa číta
cez `guestparse` nad **tou istou** snímkou. Pole `je_plna` pribudlo v commite `b574b8d`
(2026-09-19):

| Príznaky | Čo v nich je | Veta zadania |
|---|---|---|
| 1–8 | `mem_changed_ratio`, `mem_bins_active`, `mem_changed_max`, `mem_changed_p95`, `mem_changed_spread`, `mem_entropy_mean`, `mem_entropy_max`, `mem_zero_ratio` | štatistické charakteristiky pamäťových oblastí |
| 9–13 | `proc_total`, `proc_user`, `proc_kernel`, `proc_new`, `proc_gone` | procesné informácie |
| 14–15 | `mod_total`, `mod_delta` | analýza načítaných modulov |
| 16–18 | `sock_total`, `sock_listen`, `sock_estab` | monitorovanie sieťových spojení |
| 19–20 | `chk_syscall_hooks`, `chk_crossview` | detekcia podozrivých vzorcov v pamäti |
| 21–22 | `ma_predchodcu`, `je_plna` | nie sú príznaky zo zadania: hovoria, čím riadok je |

Príkaz: `python3 -m features session --snapshot <adresár> --profile <profil> --out <súbor.npz> [--csv <súbor.csv>]`.
Mená príznakov sa ukladajú spolu s maticou, takže poradie stĺpcov sa dá spätne overiť.

**Zmena 2026-10-13 (protokol server-normal-v2).** Do modelu `safeguard` vstupuje iba
prvých 18 stĺpcov (`BEHAVIOR_NAMES = MENA[:18]` vo `features/archive.py`) a per-bin blok
so štyrmi hodnotami na bin, ktorý spracúva jedna TCN zdieľaná cez biny
(`safeguard/model.py`). Stĺpce 19–22 zostávajú v matici, ale model ich nečíta; nálezy
kontrol integrity sú samostatný alarm, nie vstup modelu ([MERANIA.md](MERANIA.md), záznam
„návrh v2“ z 2026-10-13). Staršia detekčná cesta nad všetkými 22 stĺpcami
(`tcn/train.py`, `tcn/score.py`) v repozitári zostáva ako historická a diagnostická.

**Prečo pevná dĺžka a nie biny ako kanály.** Počet binov závisí od veľkosti a rozloženia
memslotov virtuálneho stroja (pri doméne `hyptcn-guest` ich je 131). Biny ako kanály by
model priviazali na jednu veľkosť pamäte, preto sa cez biny agreguje — je to cesta (a)
z vtedy otvoreného rozhodnutia (hlavičky `features/snapshot.py` a `features/windows.py`).
Cenou je strata informácie o tom,
**ktorá** oblasť pamäte sa menila; per-bin vektor kvôli tomu nezaniká, zostáva
v `features/perbin.py` a v sidecari a od 2026-10-13 je lokálnou vetvou modelu `safeguard`
(L13).

**Prvá snímka reťazca a plná snímka.** Príznaky `proc_new`, `proc_gone` a `mod_delta`
potrebujú predchádzajúcu snímku. Zvolená cesta: riadok sa nevynecháva, ale nesie
`ma_predchodcu` = 0 a tieto tri príznaky sú v ňom nula. Je to tá istá dohoda ako
`has_changed` v `perbin.py` — nula, vedľa ktorej stojí príznak hovoriaci, že sa nemerala.
Druhé pole, `je_plna`, hovorí o inom: v plnej snímke zapíše delta writer všetky nenulové
stránky, takže príznaky 1–7 opisujú celý obsah pamäte, nie jej zmenu, a `mem_changed_ratio`
vyjde presne `1 − mem_zero_ratio`. Je to rovnaké číslo s iným významom a `ma_predchodcu`
to nepokrýva. Ticho doplnená nula aj ticho iný význam sú v tomto projekte zakázané
(`HONESTY.md`); kto maticu spracúva, musí čítať obe polia.

**Overenie.** `features/tests/test_snapshot.py` (2026-09-19: 15 testov; 2026-10-29:
30 testov; zakaždým prešli všetky aj s `FEATURES_REQUIRE_REAL=1`) kontroluje dĺžku
vektora, mená príznakov, ručne spočítanú pamäťovú agregáciu, `ma_predchodcu` = 0 na prvej
snímke, `je_plna` proti hlavičkám reťazca `.vmicd` (nie proti poradiu v reťazci) aj doplnkovosť zmeny a nulového podielu
v plnej snímke, zhodu `proc_new` a `proc_gone` s ručne spočítaným rozdielom množín PID
medzi dvoma snímkami a determinizmus. Nad
`guestparse/tests/data/mini.vmicd` sa navyše overuje, že bez sidecaru s blokom `features`
skončí výpočet chybou a pamäťová časť sa **nedopočítava** inou cestou.

**Čo to stojí.** Spracovanie jednej snímky (rekonštrukcia objektov hosťa + agregácia
sidecaru) trvalo medián 0,383 s, rozsah 0,373–0,580 s; n = 18, tri prechody reťazca
šiestich snímok z `data/raw/20260919T004036Z_run`, teplá vyrovnávacia pamäť stránok
hostiteľa (2026-09-19; samostatný artefakt v `data/results/` ani záznam v
`docs/MERANIA.md` k tomu nie je). Pri perióde zberu 5 s to je zlomok periódy. Merané
na reťazci šiestich častí. Pri dlhom reťazci čas na snímku rástol s pozíciou v session,
lebo sa reťazec otváral pre každú snímku znova; od 2026-10-21 to odstraňuje
`guestparse.image.ChainCursor` ([MERANIA.md](MERANIA.md), záznam z 2026-10-21). Na
`hyptcn-lab` trvala offline extrakcia v audite pilota 7 spolu
862.2 {{res:collection_pilot_7_20261026_timing.json:values.audit_timing.extraction_s_sum}}
s za
480 {{res:collection_pilot_7_20261026_audit.json:values.snapshots}}
snímok a najdlhšia snímka
5.73 {{res:collection_pilot_7_20261026_timing.json:values.audit_timing.extraction_s_max}}
s, teda dlhšie ako perióda 5 s. Či živá cesta stíha, zmerané nie je (L12).

**Formulácia do textu práce:** „Rekonštrukcia objektov hosťa a štatistiky pamäťových
oblastí vstupujú do jedného príznakového vektora pevnej dĺžky, jeden vektor na snímku.
Pamäťová časť je agregátom per-bin vektora, ktorý počíta modul zberu; objektová časť
pochádza z rekonštrukcie zoznamu procesov, načítaných modulov, sieťových soketov
a kontrol integrity nad tou istou snímkou. Príznaky, ktoré potrebujú predchádzajúcu
snímku, sú v prvom časovom kroku označené príznakom `ma_predchodcu` = 0. Do vstupu
modelu vstupujú behaviorálne príznaky a per-bin blok; kontroly integrity sa
vyhodnocujú osobitne ako nezávislé nálezy."

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

## L15 — Časové rozlíšenie: proces kratší než perióda zberu je neviditeľný

**Fakt.** Metóda je snímková: vidí len to, čo v hosťovi existuje v okamihu snímky. Proces,
ktorý vznikne a zanikne medzi dvoma snímkami, nezanechá v rekonštruovanom zozname procesov
žiadnu stopu. Príznaky `proc_new`, `proc_gone` a `mod_delta` sa preto pri perióde 5 s
nepohli z nuly ani v sedení, ktoré bolo pripravené práve na ich rozhýbanie.

**Overenie.** Sedenie `data/raw/20260919T011815Z_fork_storm`: v hosťovi 10 sekúnd bežalo
vetvenie procesov, ktoré podľa vlastného súhrnu vytvorilo a pozbieralo 8320 detí v 416
dávkach (`labels.json`, kľúč `scenar.suhrn`); zber bežal s periódou 5 s a urobil 2 snímky.

```sh
python3 -m features session \
  --snapshot data/raw/20260919T011815Z_fork_storm/snap \
  --profile profiles/debian12-6.1.0-42-cloud-amd64 \
  --out /tmp/fork_storm.npz --csv /tmp/fork_storm.csv
```

Objektová časť oboch riadkov výsledného CSV (beh 2026-09-19):

```
snimka                                   proc_total proc_new proc_gone mod_delta ma_predchodcu
hyptcn-guest_000000_20260919T011817285Z  81         0        0         0         0
hyptcn-guest_000001_20260919T011822285Z  81         0        0         0         1
```

V prvom riadku je nula dohodou, nie meraním (`ma_predchodcu` = 0, pozri L14). V druhom
riadku je to meranie: medzi dvoma snímkami vzdialenými 5 sekúnd sa množina PID v hosťovi
nezmenila ani o jeden prvok, hoci v tom intervale v ňom vzniklo a zaniklo rádovo tisíce
procesov.

**Čo z toho plynie.** Nie je to chyba implementácie a nedá sa to odstrániť lepším
parsovaním. Horná hranica toho, čo periodická introspekcia pamäte zachytí v zozname
objektov, je daná periódou zberu. Správanie kratšie než perióda je pozorovateľné len
nepriamo, cez stopu v obsahu pamäte (zmenené stránky, entropia) — v tom istom sedení
`mem_changed_ratio` medzi snímkami kleslo z 0,2647 na 0,0137, takže pamäťová časť vektora
rozdiel vidí, objektová nie. Kratšia perióda hranicu posunie, neodstráni ju, a zvýši
záťaž zberu.

**Formulácia do textu práce.**

> Časové rozlíšenie metódy je ohraničené periódou zberu. Proces, ktorý vznikne a zanikne
> medzi dvoma snímkami, sa v rekonštruovanom zozname objektov hosťa neobjaví: v overovacom
> sedení s periódou 5 sekúnd, počas ktorého v hosťovi vzniklo a zaniklo 8320 procesov,
> zostali príznaky odvodené od zmeny zoznamu procesov na nule, kým príznaky odvodené
> od obsahu pamäte sa medzi snímkami zmenili. Krátkodobé správanie je pre túto vrstvu
> pozorovateľné len cez stopu v pamäti, nie cez zoznam objektov.

**Čo by to odstránilo.** Nič v rozsahu tejto práce. Zachytenie vzniku procesu nezávisle
od periódy vyžaduje udalostný zdroj (hook na `execve` alebo na plánovač), teda inú vrstvu
než periodické čítanie pamäte — a hook je v tejto práci notifikačný (L9).

---

## L16 — Presnosť detekcie malvéru nebola meraná

**Aktualizácia 2026-10-13:** nasledujúci text zachytáva historické rozhodnutie
nepokračovať v zbere bez vzoriek. Aktuálny plán je v
[`METODIKA_ZBERU.sk.md`](METODIKA_ZBERU.sk.md): najprv benígny korpus a tréning
normálu, potom izolované testy. Malvér nie je podmienkou tréningu normálu.
Staré tvrdenie, že sa korpus ani tréning nerobia, už neplatí. Presnosť voči
reálnym vzorkám stále nie je zmeraná a zostáva otvorenou časťou zadania.

**Aktualizácia 2026-10-29:** pôvodný nadpis („… a v tejto verzii sa merať nedá“) sa skrátil,
lebo meranie je plánovaná izolovaná etapa (`METODIKA_ZBERU.sk.md`, kap. 7), ktorá sa ešte
neuskutočnila. Časť nástrojov na ňu existuje, ale nemá artefakt: PoC techniky
v `scripts/poc/` (spúšťa ich starý harness `scripts/session.sh` nad doménou
`hyptcn-guest`, ponechaný ako historický a diagnostický, L6) a sťahovanie vzoriek
`scripts/mb_fetch.py`. Runner izolovanej útokovej etapy nad serverovým stackom
laboratória ani vyhodnocovač udalostí `safeguard` (FAR za hodinu, čas do detekcie)
v tom čase neexistovali (vyhodnocovač FAR pribudol v commite `591a061`, pozri nižšie), takže
na rozdiel od vety „vtedy sa nemení kód“ v historickom texte nižšie treba dopísať aj kód.
Platí prvá časť nadpisu: v `data/results/` nie je metrika detekcie útokov ani malvéru.

**Aktualizácia 2026-10-30:** vyhodnocovač udalostí `safeguard` pre benígnu prevádzku
existuje: `python3 -m tcn.eval far` (`tcn/eval.py`, commity `591a061` a `a1a4b9b`) počíta
z prehratí jednej roly korpusu alarmové udalosti, FAR za hodinu s intervalom a presnosť
klasifikátora profilu záťaže ([`SAFEGUARD.sk.md`](SAFEGUARD.sk.md)). Čas do detekcie
a podiel detegovaných incidentov nepočíta žiadny kód a runner útokovej etapy stále nie je.
Balík natrénovaný na korpuse `benign-v6-20261026`
([záznam](../data/results/safeguard_train_benign_v6_20261029.json)) je vyhodnotený iba
na role `dev` ([záznam](../data/results/safeguard_far_dev_benign_v6_20261029_b.json)),
ktorá vyberala jeho checkpointy, takže výsledok nie je odložený; záverečné spustenie na
`test_benign` neprebehlo. V `dev` útok nebežal a trieda klasifikátora je nastavenie záťaže,
nie škodlivosť: ani jedno z týchto čísel nie je metrikou detekcie útokov alebo malvéru,
prvá časť nadpisu teda platí ďalej.

### Historické zdôvodnenie pôvodného rozsahu

**Fakt.** Na stroji, na ktorom táto práca vznikla, nie sú žiadne reálne malvérové vzorky.
Bez nich sa nedá zmerať, ako dobre model odlíši malvér od bežnej záťaže. Zber korpusu ani
tréning detekčného modelu sa preto v tejto verzii nerobia. Vetva zberu korpusu
(`scenarios/`, `scripts/collect_corpus.sh`) bola z pracovného stromu odstránená; v histórii
zostáva, commit `da8ad2e`.

**Čo to znamená pre zadanie.** Bod zadania „vyhodnotenie presnosti detekcie malvérových
vzorcov" je **nesplnený**. Dôvod nie je v implementácii: cesta dát od pamäte virtuálneho
stroja cez príznakový vektor po skóre modelu je zostavená a overená (L14,
`docs/PRIRUCKA.md`). Chýba vstup — vzorky. Bod sa dá splniť až v izolovanom prostredí
s prístupom k vzorkám; vtedy sa nemení kód, dopĺňajú sa dáta a označenia.

**Prečo sa syntetické scenáre nepoužili na tréning.** Šesť scenárov správania (`cpu_burn`,
`mass_file_rewrite`, `proc_scan`, `anon_exec`, `fork_storm`, `idle`) bolo napísaných
a odskúšaných; dve sedenia z nich sú v `data/raw/`. Na tréning sa **vedome** nepoužili.
Model natrénovaný na nich by nebol detektorom malvéru, ale klasifikátorom šiestich
skriptov, ktoré napísal autor práce — rozlišoval by presne tie vzorce, ktoré doňho autor
vložil. Číslo z takého vyhodnotenia by v texte znelo ako presnosť detekcie, hoci by meralo
zhodu s vlastným generátorom. Je to tá istá chyba, pre ktorú bola predchádzajúca iterácia
projektu retrahovaná (`HONESTY.md`, kapitola 2): tam číslo vzniklo z rozdielu medzi
vyťaženým a nečinným strojom, tu by vzniklo z rozdielu medzi šiestimi skriptami.

**Overenie.** V pracovnom strome nie je vetva zberu a v `data/results/` nie je žiadna
detekčná metrika nad snímkami hosťa:

```sh
$ ls scenarios scripts/collect_corpus.sh
ls: cannot access 'scenarios': No such file or directory
ls: cannot access 'scripts/collect_corpus.sh': No such file or directory
$ ls data/raw/*/labels.json | wc -l
2
```

Dva súbory metriky obsahujú a **nie sú výsledkom detekcie**:
`data/results/smoke/tcn_syn_20260919_hodnota.json` a
`data/results/smoke/tcn_syn_20260919_poradie.json`. Od 2026-09-19 sú v podadresári
`smoke/`, aby to, čo sú, bolo vidieť už z cesty; `provenance_note` v oboch to hovorí aj
v samotnom súbore. Sú to výstupy
`python3 -m tcn.train --syn`, teda beh nad dátami, ktoré vyrobil generátor v `tcn/`
(`guest` je v nich `null`, `fit_sessions` sú `20260101T000000Z_idle_0`
a `20260102T000000Z_idle_1` — dátumy, ktoré nikdy neboli). Metriky v nich sú `1.0`, lebo
generátor vyrába triedy, ktoré sú oddeliteľné; overujú, že cesta dát a tréning bežia,
nič viac. Do textu práce nepatria a ak sa tam objavia, je to nález.

Ďalšie súbory s číslami z modelu nie sú detekčnou metrikou: chyby predikcie a test
confoundu nad nečinnými a lab sedeniami (`data/results/trenovanie_prediktor_*.json`,
`data/results/chyba_predikcie_lab_vs_idle_20261008.json`,
`data/results/konfunder_5sess_20261008.json`) a diagnostické overenie `safeguard`
so syntetickým modelom (`data/results/safeguard_validation_20261013_a.json`).

**Formulácia do textu práce (do abstraktu aj do záveru).**

> Presnosť detekcie voči reálnym malvérovým vzorkám nebola v tejto práci meraná, pretože
> vzorky neboli k dispozícii; pripravené syntetické scenáre správania sa na tréning
> vedome nepoužili, lebo model natrénovaný na nich by klasifikoval vlastné scenáre,
> nie malvér.

**Čo by to odstránilo.** Korpus reálnych vzoriek v izolovanom prostredí, s označením na
úrovni vzorky aj procesu, so splitom disjunktným na úrovni vzorky a s kontrolou confoundu
podľa `HONESTY.md` (P8). Dovtedy zostáva bod nesplnený a text práce to musí uviesť
na každom mieste, kde by inak vznikol dojem, že detekcia bola vyhodnotená.

---

## L17 — Profil jadra hosťa platí pre jeden boot, nie pre verziu jadra — VYRIEŠENÉ 2026-10-05 (preukotvenie, blok A2)

**Fakt.** Profil v `profiles/` má dve časti a každá starne inak. Offsety polí štruktúr
z BTF sú viazané na verziu jadra a reštart hosťa prežijú. Adresy symbolov v `kallsyms`
nie — jadro ich pri každom štarte posúva (KASLR), takže profil odobratý pri jednom boote
neplatí pre snímku z iného bootu toho istého jadra.

**Overenie.** Doména `hyptcn-guest` bola 2026-09-18 vypnutá a 2026-09-19 naštartovaná;
`init_task` sa presunul z `0xffffffff97a1aa40` na `0xffffffffb221aa40`. Starý profil nad
dnešnou snímkou: posun jadra sa našiel (skenuje sa banner v pamäti), ale krížová kontrola
prekladu adries vrátila pre obe kontrolné adresy `0x0` a výpisy procesov aj modulov boli
označené `NEUPLNE`. Čerstvý profil z toho istého bootu: krížová kontrola sedí na bit,
výpisy úplné. Celý výstup oboch behov je v `docs/MERANIA.md`, záznam z 2026-09-19.

**Vyriešené 2026-10-05 (blok A2, commit `61a8980`).** Namiesto pádu s kódom 5 sa profil
preukotví. Posun medzi bootom profilu a bootom snimky sa **meria z tabuliek stránok**:
pre známu fyzickú adresu `init_task` (overenú obsahom `comm == "swapper/0"` pri skene
banneru) sa spätne nájde virtuálna adresa, ktorá ju mapuje, a rozdiel voči adrese
v profile sa aplikuje na všetky symboly obrazu jadra. Druhá kotva (`linux_banner`) musí
s tým istým posunom sedieť, inak sa posun neprijme. Overené na páre
snímka z 18. 9. (`data/sessions/20260918T154914Z_validate/snap`; v gite je iba sidecar,
súbor `.vmicd` je mimo gitu, iba na tomto stroji) + profil z 19. 9.
— pred A2 `ss` vrátil 0 socketov a každý podpríkaz končil kódom 5; po A2 sa profil
preukotvil o `-0x1a800000`, `ss` rekonštruuje 13 socketov (rovnako ako historický
artefakt so sediacim profilom) a `validate` beží. Drží to
`guestparse/tests/test_reanchor.py` a `guestparse/tests/test_profile_boot.py`.
Pozor na detail: posun sa NEBERIE priamo zo skenu banneru — ten dáva správne fyzické
adresy, ale virtuálne o konštantu inak (obraz jadra sa mapuje s reziduálnym posunom
2 MiB), preto sa meria z tabuliek. Znovu overené 2026-10-29 (commit `709ee7f`) na tom
istom páre: preukotvenie o `-444596224` (= `-0x1a800000`), `ss` vypíše 13 socketov a
`validate` (`ps` pred aj po, `lsmod` a `ss` pred snímkou) skončí kódom 0 (80/80 procesov,
moduly 51/0/0, sokety 11/1/1). Samostatný artefakt ani záznam v `docs/MERANIA.md`
k overeniu na tomto páre nie je; príkazy sú v L10 a v `docs/kontroly.md`.

**Doplnok 2026-10-13: kotvy z viacerých bootov.** Po reštarte hosťa môžu v RAM zostať
banner a `init_task` aj zo starého bootu. Pri pilote v2 starý postup vybral prvú
obsahovo zodpovedajúcu dvojicu, ktorá už nepatrila bežiacemu jadru, a preukotvenie túto
chybu neodhalilo ([MERANIA.md](MERANIA.md), záznam „pilot v2: dokončený zber, chybná
kotva po reštarte“). Kotva sa odvtedy vyberá podľa `sysctl_bootid` v RAM, ktoré musí
sedieť s boot UUID uloženým pred zberom (prepínač `--boot-id`, pri natívnych session
z metadát); bez tejto identity sa pripustí iba jediná kotva
(`GuestView.resolve()` v `guestparse/view.py`, testy `guestparse/tests/test_boot_anchor.py`,
diagnostika `data/results/boot_anchor_validation_20261013_a.json`).
Preukotvuje aj knižničná cesta výpočtu príznakov (`features/snapshot.py`), ktorá to do
2026-10-06 nerobila ([MERANIA.md](MERANIA.md), záznam z 2026-10-06).

**Čo to znamená pre prácu (po vyriešení).** Nástroj chybu nezakrýva a od 2026-09-19 sa
už nedala prehliadnuť; od 2026-10-05 ju navyše sám opraví. `guestparse/cli.py` pred
výkonom každého podpríkazu volá `GuestView.profile_boot_mismatch()` a pri nesúlade sa
pokúsi o preukotvenie (`GuestView.reanchor()`); úspech oznámi na stderr a pokračuje.
Kód **5** (`EXIT_PROFILE_MISMATCH`) a hlásenie `NESULAD PROFILU` zostávajú pre prípad,
keď preukotvenie nejde — kotva sa v tabuľkách nenájde (FGKASLR, chýbajúce stranky) —
a vtedy platí pôvodné správanie vrátane rady obnoviť profil cez `scripts/get_profile.sh`.
Kód 5 prebíja aj nález (1), aj neuzavretosť (4): nález zo zlého profilu nálezom nie je.

**Formulácia do textu práce.**

> Profil jadra hosťa, ktorý preklenuje semantic gap, sa skladá z offsetov polí štruktúr
> a z adries symbolov. Prvé sú viazané na verziu jadra, druhé na konkrétny štart systému,
> pretože jadro adresy pri každom štarte randomizuje. Modul preto posun medzi bootom
> profilu a bootom snímky zmeria priamo z tabuliek stránok snímky (spätné hľadanie
> virtuálnej adresy pre fyzickú adresu `init_task`, potvrdené druhou kotvou `linux_banner`)
> a adresy profilu preukotví; keď sa kotva nenájde, rekonštrukciu označí ako neúplnú
> a skončí vyhradeným návratovým kódom.
> Rovnaká závislosť platí pre LibVMI aj Volatility.

**Čo to odstránilo.** Odvodenie zo samotnej snímky, kde v tomto štarte leží obraz jadra
vo virtuálnom priestore, a prepočet virtuálnych adries z `kallsyms` týmto rozdielom —
presne postup, ktorý navrhoval pôvodný text tejto položky z 2026-09-19 (v súbore už nie
je; `git show b574b8d:docs/LIMITACIE.md`). Sken banneru dáva len rozdiel medzi
virtuálnou adresou z profilu a fyzickou adresou v snímke; s ním sedí lineárne čítanie,
ale prechod tabuliek stránok nie, lebo tie sú indexované skutočnými virtuálnymi
adresami tohto štartu. Preukotvenie (A2) preto posun meria z tabuliek, nie z banneru.

---

## L18 — Kontrola textu jadra: rozdiel medzi bootmi, baseline nesedí

(Do 2026-10-29 stála táto položka pred L17 pod nadpisom „L18 - A3: zvyskovy rozdiel textu
medzi bootmi“ a bez častí nižšie.)

**Fakt.** Kontrola (d) v `guestparse/checks.py` (blok A3, commity `7134058`, `689c384`,
`9ec44db`) porovnáva SHA-256 každej stránky textu jadra `[_stext, _etext)` s baseline
`text_baseline.json` v profile. Baseline maskuje miesta, ktoré jadro pri štarte legitímne
patchuje: static keys z `__jump_table` a pri vyrobení s `vmlinux` aj absolútne relokácie
`R_X86_64_64/32/32S`, alternatives z `.altinstructions` a static calls. Kontrola má dve
obmedzenia:

1. **Zvyšok rozdielu medzi bootmi.** Podľa správy commitu `9ec44db` (2026-10-05) maskovanie
   na jadre `6.1.0-42-cloud-amd64` pokrylo rozdiel oproti čistej snímke toho istého bootu
   úplne (0 nálezov na 3586 stránkach), medzi dvoma bootmi však zostalo ~1116 stránok
   s rozdielom. Príčinou je zrejme ďalšia trieda patchov, ktorá sa zatiaľ nemaskuje
   (neoverené; kandidáti: prepisovanie retpoline/rethunk, zvyškové paravirt miesta;
   tabuľka `__parainstructions` je na tejto VM prázdna). Artefakt v `data/results/` ani
   záznam v `docs/MERANIA.md` k týmto číslam nie je.
2. **Baseline v profile nesedí so súradnicami profilu.** Kontrola žiada, aby sa rozsah
   baseline po posune o preukotvenie (L17) zhodoval s `_stext` a `_etext` profilu.
   Sledovaná baseline (naposledy zmenená commitom `c221c6a`, 2026-10-06; v `689c384`
   a `9ec44db` mala `stext` profilu) má `stext` `0xffffffff90400000`, profil má `_stext`
   `0xffffffffb0800000`, hoci baseline nesie `boot_id` profilu. Zodpovedá to baseline
   vyrobenej zo snímky iného bootu cez preukotvený pohľad: `build_text_baseline` uloží
   adresy preukotveného profilu, ale `boot_id` z `boot.json` profilu. Baseline vyrába
   v každom sedení starý harness `scripts/session.sh` (v repozitári ponechaný ako
   historický a diagnostický), z prvej snímky bežiaceho bootu s `--force` priamo do
   zdieľaného profilu; v sedení na inom boote, než je boot profilu, vznikne práve taká
   baseline. Kontrola (d) je preto pri dnešných súboroch nedostupná pre každú
   snímku, aj pre snímku z bootu profilu, a `checks` končí kódom 4 (L10). Kampaňový zber
   (`scripts/collection.py`, `scripts/campaign.py`) baseline nevyrába vôbec.

**Overenie.** 2026-10-29, commit `709ee7f`:

```
$ python3 -c "import json; print(hex(json.load(open('profiles/debian12-6.1.0-42-cloud-amd64/text_baseline.json'))['stext']))"
0xffffffff90400000
$ grep -w "_stext" profiles/debian12-6.1.0-42-cloud-amd64/kallsyms.txt
ffffffffb0800000 T _stext
$ python3 -m guestparse checks --snapshot data/raw/20260919T110017Z_run \
        --profile profiles/debian12-6.1.0-42-cloud-amd64 | grep "text jadra"
text jadra             NEDOSTUPNA (baseline textu nesedi s profilom ani po posune o KASLR rozdiel (ine jadro); obnov ju nad cistou snimkou)
```

`data/raw/20260919T110017Z_run` je snímka z bootu profilu (mimo gitu, iba na tomto
stroji; `checks` nad ňou profil nepreukotvuje). Nad kópiou tej istej snímky s 8 bajtmi
zapísanými na `_stext` kontrola 2026-10-05 so staršou baseline nález našla
(`data/results/a3_pozitivny_20261005.json`, `nearest_symbol` `startup_64`). Vo všetkých
kópiách auditov v `data/results/` (piloty od 2026-10-13 po pilot 7 z 2026-10-26, vybrané
session kampaní a diagnostiky) zostala kontrola textu neuzavretá v každom riadku, napr.
480 {{res:collection_pilot_7_20261026_audit.json:values.text_integrity_inconclusive_rows}}
z
480 {{res:collection_pilot_7_20261026_audit.json:values.snapshots}}
v pilote 7 a
480 {{res:collection_pilot_v2_20261013_reaudit.json:values.text_integrity_inconclusive_rows}}
v pilote v2. Rovnako v korpuse: záznam kampane `benign-v6-20261026` má kontrolu textu
neuzavretú vo všetkých riadkoch každej zo
48 {{res:collection_campaign_benign_v6_20261026.json:n}}
session (`values.sessions.*.integrity_inconclusive_rows.text_integrity`), napr.
720 {{res:collection_campaign_benign_v6_20261026.json:values.sessions.0.integrity_inconclusive_rows.text_integrity}}
z
720 {{res:collection_campaign_benign_v6_20261026.json:values.sessions.0.snapshots}}
v session 1. Detektor `safeguard` ju pri prehratí roly `dev` balíkom `server-v2-benign-v6`
mal neuzavretú vo všetkých
4320 {{res:safeguard_far_dev_benign_v6_20261029_b.json:values.dane_prijatim_korpusu.integrita_neuzavrete.text_integrity}}
riadkoch ([záznam](../data/results/safeguard_far_dev_benign_v6_20261029_b.json), 2026-10-29).
Audity dôvod neuzavretia neukladajú; záznamy v `docs/MERANIA.md`
z 2026-10-06 a 2026-10-13 ho uvádzajú ako chýbajúcu baseline (tohto bootu).

**Formulácia do textu práce.**

> Štvrtá kontrola porovnáva obsah stránok textu jadra s baseline uloženou v profile
> a maskuje miesta, ktoré jadro pri štarte legitímne patchuje. Maskovanie neodstráni
> celý rozdiel medzi dvoma štartmi toho istého jadra. V zozbieraných dátach pilotov
> a kampaní zostala táto kontrola neuzavretá a baseline, ktorá je v profile, ju
> nevyhodnotí pre žiadnu snímku, lebo nezodpovedá súradniciam profilu; zmenu textu jadra
> by v týchto dátach nález nezachytil. Ostatné tri kontroly sa vyhodnocovali.

**Čo by to odstránilo.** Nová baseline v súradniciach profilu — zo snímky z bootu profilu
bez preukotvenia, alebo úprava `build_text_baseline` v `guestparse/checks.py` tak, aby
ukladala adresy profilu — zaznamenaná novým záznamom v `docs/MERANIA.md`; znovu zmeraný
a uložený zvyšok rozdielu medzi bootmi; maskovanie ďalšej triedy patchov. Nová baseline
mení profil a úprava `build_text_baseline` merací kód; `pilot_gate` v `scripts/campaign.py`
potom vyžaduje nový pilot. Kým sa to nestane, kontrola (d) v nových dátach nález vytvoriť
nemôže.

---

## Ako sa tento zoznam udržiava

Limitácia sa z tohto súboru neodstraňuje, kým nezmizne z kódu. Keď sa odstráni, pridá sa
k nej dátum, commit a odkaz na meranie, ktoré to dokladá — rovnako, ako je to zavedené pre
`docs/MERANIA.md` (`HONESTY.md`, P10). Nové obmedzenie sa pridáva hneď, ako sa zistí, aj
keď ešte nie je jasné, či sa bude riešiť.
