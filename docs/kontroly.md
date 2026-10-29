# Kontroly podozrivých vzorcov v pamäti a validačný príkaz

Kontroly integrity nad snímkou (`guestparse/checks.py`), porovnanie s pozemnou pravdou
(`guestparse/validate.py`) a injekčné testy (`guestparse/tests/test_injection.py`,
`guestparse/tests/test_text_integrity.py`). Pôvodne kroky K11 a K09 pracovného plánu,
ktorý v repozitári nie je.

Čísla nižšie pochádzajú z behov zaznamenaných v
`data/results/k11_beh_20260918.log`, z artefaktov `data/results/checks_*.json`
a `data/results/validate_*.json` a pri krížových rozdieloch a roztrhnutom zozname procesov
z artefaktov `data/results/collection_crossview_race_20261022.json`,
`data/results/collection_process_walk_race_20261022.json` (benígne kampane z 2026-10-22)
a `data/results/collection_process_walk_insert_20261026.json` (kampaň `benign-v5-20261025`).
Snímky `/var/tmp/vmic-val` a `/var/tmp/vmic-delta`, nad ktorými behy z 2026-09-18 bežali,
boli mimo repozitára a na tomto stroji už nie sú (overené 2026-10-29); ich výsledky
zostávajú v uvedených artefaktoch.

## Čo sa kontroluje a prečo práve toto

Zo samotnej pamäte sa dá overiť len to, čo má jadro dané invariantne. Každá zo štyroch
kontrol porovnáva dva zdroje, ktoré musia sedieť; nález je ich **rozdiel**, nie skóre
a nie odhad. Žiadna kontrola nemá voľný prah, ktorý by sa dal doladiť na požadovaný
výsledok.

### (a) `sys_call_table`

Každá položka musí ukazovať do rozsahu textu jadra `[_stext, _etext)`. Obe hranice aj
adresa tabuľky sú symboly v `kallsyms`, takže kontrola nemá parameter.

Dĺžka tabuľky sa **neberie** z hlavičkových súborov ani z konštanty `__NR_syscalls` —
odvodí sa zo vzdialenosti k najbližšiemu ďalšiemu symbolu v `kallsyms`
(`sys_call_table` 0xffffffff97000360 → `vdso_mapping` 0xffffffff97001180, teda
452 slotov). Zarovnávacia výplň na konci sa odstrihne až podľa obsahu, a to len ak je
nulová: hook je nenulový ukazovateľ, takže sa odstrihnúť nemôže. Výsledok na tomto
hosťovi: **451 kontrolovaných položiek** (položka 450 je
`__x64_sys_set_mempolicy_home_node`, čo sedí s `__NR_syscalls = 451` v jadre 6.1).

32-bitové tabuľky (`ia32_sys_call_table`, `x32_sys_call_table`) tento hosť nemá, takže sa
nekontrolujú; ak by symbol existoval, kontrola sa spustí aj nad nimi.

### (b) Procesy krížovo

Zoznam `init_task.tasks` proti druhému, nezávislému pohľadu: zostup stromom potomkov
z `init_task` cez `children`/`sibling`. Sú to dve rôzne spojkové štruktúry toho istého
`task_struct`. Rootkit, ktorý odpojí uzol z jednej, musí odpojiť aj druhú, inak vznikne
rozdiel.

Poznámka k počtom: strom začína v `init_task`, ktorý v zozname `tasks` nie je, takže sa
z porovnania vyníma.

### (c) Moduly krížovo

Zoznam `modules` proti kobjektom v `module_kset` — to, čo je vidieť ako `/sys/module`.
Do porovnania idú len tie kobjekty, ktorých `module_kobject.mod != NULL`; ostatné sú
vstavané moduly s parametrami, ktoré v zozname `modules` nikdy nie sú (preto je kobjektov
vždy viac než modulov: 105 ku 47 na snímke `/var/tmp/vmic-val`).

Navyše sa pri každom module overuje, že meno je tlačiteľný ASCII reťazec a že adresa
`struct module` leží v oblasti modulov `[0xffffffffc0000000, 0xffffffffff000000)`.

### (d) Text jadra sa nemení

Obsah každej stranky `[_stext, _etext)` sa porovná so SHA-256 **baseline v profile**
(súbor `text_baseline.json`). Text sa po boote nesmie meniť, takže každá zmenená
stranka je nález — práve toto chytí inline hook, ktorý smeruje **do vnútra** textu
a kontrola (a) ho nevidí (tá overuje len kam ukazuje tabuľka, nie čo v texte je).
Pri hašovaní sa maskujú miesta, ktoré jadro pri štarte legitímne patchuje: static keys
z `__jump_table` a pri baseline vyrobenej s `vmlinux` aj absolútne relokácie,
alternatives a static calls. Pri snímke z iného bootu sa baseline posúva o posun
preukotvenia (`docs/LIMITACIE.md`, L17); rozsah baseline musí po tom istom posune sedieť
s `_stext` a `_etext` preukotveného profilu, teda baseline musí byť v súradniciach
profilu, inak je kontrola nedostupná. Zvyšok rozdielu medzi bootmi, ktorý maskovanie
nepokryje, opisuje L18.

Baseline vzniká z čistej snímky príkazom:

```sh
python3 -m guestparse textbaseline --snapshot <cista_snimka> \
        --profile profiles/debian12-6.1.0-42-cloud-amd64 \
        [--vmlinux data/raw/profile-assets/vmlinux-6.1.0-42-cloud-amd64] [--force]
```

a zapíše sa do adresára profilu. Bez `--vmlinux` sa použije
`data/raw/profile-assets/vmlinux-<release>`, ak existuje (súbor mimo gitu; na tomto
stroji `vmlinux` so symbolmi a ladiacimi informáciami, podľa správy commitu `9ec44db`
z Debian balíka dbg; `scripts/get_vmlinux.sh` má do tej cesty rozbaliť `vmlinux`
z `vmlinuz` hosťa, ten však sekcie relokácií nemá, overené 2026-10-29); existujúcu
baseline príkaz bez `--force` neprepíše. Z **neúplnej** snímky sa
vyrobiť nedá — príkaz sa odmietne, lebo baseline, ktorej časť chýba, by kontrolu umelo
zúžila (hook v chýbajúcej stranke by bol neviditeľný). Profil z iného bootu sa najprv
preukotví a baseline sa odmietne vyrobiť iba vtedy, keď preukotvenie zlyhá. Baseline
z preukotveného pohľadu však nesie adresy toho bootu, nie súradnice profilu, a kontrola
ju potom odmieta; vyrábať ju treba zo snímky z bootu profilu.

Známe obmedzenie: `jump labels`/`static keys` text jadra za behu naozaj prepisujú
(prepínanie vetiev cez `text_poke`). Tieto miesta sa maskujú; nález sa hlási
**s najbližším symbolom** (`nearest_symbol`). Meranie na čistom hosťovi (koľko stránok
sa medzi dvoma snímkami zmení bez zásahu) uložený artefakt nemá; čísla zo správy commitu
`9ec44db` uvádza L18.

**Stav 2026-10-29 (commit `709ee7f`).** Baseline v profile nesedí so súradnicami
profilu (`stext` `0xffffffff90400000` oproti `_stext` `0xffffffffb0800000`, L18), preto
je kontrola (d) pri každej snímke nedostupná a `checks` končí kódom 4 — aj pri snímke
z bootu profilu (`data/raw/20260919T110017Z_run`, mimo gitu). V kópiách auditov pilotov
a session kampaní v `data/results/` zostala neuzavretá vo všetkých riadkoch.

### Čo kontrola nehovorí

Každá kontrola hlási `conclusive`. Snímka sa odoberá bez zastavenia VM, takže prechod
zoznamu sa môže roztrhnúť; keď sa niektorý prechod neuzavrel, rozdiel dvoch zoznamov
**nie je** dôkaz skrývania a nulový výsledok nič nedokazuje. V takom prípade je názov
kontroly v poli `summary.inconclusive`. Rozdiely neúplných pohľadov na procesy
a moduly sú v `inconclusive_differences`, nie vo `findings`; nevytvárajú preto
alarm integrity. Nezávislé nálezy (napríklad neprípustné meno modulu alebo hook
v tabuľke volaní) sa vyhodnocujú aj pri neuzavretej krížovej kontrole.

Uzavreté prechody ešte neznamenajú jeden okamih. Stránky so spojkami `tasks`
a `children`/`sibling` sa čítajú v rôznom čase, takže fork alebo exit krátkeho
procesu medzi nimi vytvorí rozdiel bez skrývania. V benígnej session
`benign-v2-20261022_03_train_bursty` mala snímka 645 navyše v zozname
`tasks` potomka postmastra (`postgres`, pid 450961), ktorý v strome chýbal;
snímky 643, 644, 646 a 647 sa zhodovali
([záznam](../data/results/collection_crossview_race_20261022.json)).
Príkaz `checks` vypisuje rozdiely jednej snímky. Extrakcia príznakov,
audit a safeguard ich za nález považujú, až keď ten istý rozdiel ukáže aj
bezprostredne predchádzajúca snímka tej istej session (`features/snapshot.py`,
`potvrd_krizove`). Rozdiel jedinej snímky je v `unconfirmed_findings`
a kontrola je v `inconclusive`. Skrytý objekt zostáva skrytý aj v ďalšej
snímke; objekt skrytý kratšie ako jednu periódu takto ako nález nevyjde.

Zoznam `tasks` je obojsmerný. Keď sa prechod dopredu roztrhne (v session
`benign-v3-20261022_03_train_bursty` ukazoval v snímke 505 `next`
posledného vlákna na už ukončený proces so starými ukazovateľmi), zoznam
tvoria uzly prejdené dopredu pred prvým spojením nezhodným s opačným smerom,
ak sa prechod dozadu uzavrel cez presne tie isté uzly (`walk: "prev"`).
Opačný prípad je vloženie na koniec (session `benign-v5-20261025_18_train_quiet`,
snímka 613): `next` posledného procesu aj `prev` v `init_task` už ukazovali na
nové vlákno jadra, ale jeho `task_struct` sa prečítal skôr, ešte s obsahom
ukončeného vlákna iného procesu. Keď `init_task.prev` ukazuje práve na prvý
nezhodný uzol a jeho obsah je vlákno (tgid ≠ pid) procesu spomedzi uzlov
pred ním, zoznam tvoria tie uzly (`walk: "tail"`); jadro do zoznamu `tasks`
zapája iba vodcov skupín. Krížová kontrola nad takým zoznamom beží normálne;
keď ho nepotvrdí ani jedno pravidlo, kontrola zostáva `inconclusive`.

Neuzavretá kontrola tabuľky volaní, procesov alebo modulov zneplatňuje historický
22-stĺpcový vektor so stĺpcami integrity (`model_valid` vo `features/snapshot.py`,
politika `legacy-vector-v1`); neuzavretá kontrola textu jadra ho nezneplatňuje. Protokol
server-normal-v2 posudzuje behaviorálne vstupy osobitne; neuzavretá kontrola
sa vykazuje aj vtedy, keď sú tieto vstupy úplné (pozri `METODIKA_ZBERU.sk.md`).
Pri kontrole (d) `conclusive` znamená, že
každá stranka baseline bola v snímke naozaj prečítaná; chýbajúca stranka je „neviem“,
nie „čisté“.

## Namerané: čistý hosť

`python3 -m guestparse checks --snapshot <cesta> --profile profiles/debian12-6.1.0-42-cloud-amd64`

| snímka | `sys_call_table` | procesy `tasks` vs. strom | moduly `modules` vs. `module_kset` | nálezy |
|---|---|---|---|---|
| `/var/tmp/vmic-val` (1 plná) | 451 položiek | 82 vs. 82 | 47 vs. 47 (zo 105 kobjektov) | **0** |
| `/var/tmp/vmic-delta` (1 plná + 5 delt) | 451 položiek | 76 vs. 76 | 47 vs. 47 (zo 105 kobjektov) | **0** |
| `data/sessions/20260918T154914Z_validate/snap` | 451 položiek | 80 vs. 80 | 51 vs. 51 (zo 109 kobjektov) | **0** |

Vo všetkých troch behoch bolo `summary.inconclusive` prázdne, teda vtedajšie tri kontroly
sa uzavreli. (Štvrtá kontrola — text jadra — vtedy ešte neexistovala; potrebuje
baseline z čistej snímky, pozri (d).)
Artefakty: `data/results/checks_20260918_{val,delta,session}.json`. Prvé dve snímky už
neexistujú (pozri úvod). Tretia, ktorej súbor `.vmicd` je mimo gitu iba na tomto stroji,
dáva pri dnešnom kóde (2026-10-29) po preukotvení profilu rovnaké počty v prvých troch
kontrolách, kontrola textu jadra je však nedostupná a príkaz skončí kódom 4
(`docs/LIMITACIE.md`, L10).

## Injekčný test — čo to je a čo to NIE je

Kontrola, ktorá na čistom hosťovi vždy vráti nulu, je na nerozoznanie od funkcie, ktorá
vždy vracia nulu. Preto k negatívnemu prípadu patrí aj pozitívny.

**Ide o injekciu do kópie snímkového súboru, nie o skutočný rootkit v hosťovi.**
Test (`guestparse/tests/test_injection.py`) si urobí kópiu snímky, v kópii prepíše
8 bajtov jednej položky `sys_call_table` na adresu v oblasti modulov
(`0xffffffffc0001000`) a spustí detektor nad kópiou. Kopíruje vždy
`guestparse/tests/data/mini.vmicd` z repa (27-stránkový výrez reálnej snímky
z 2026-09-19) a navyše reálnu snímku, ak je na stroji (`GUESTPARSE_VAL`, značka
`realsnap`); bez nej sa tri testy nad reálnou snímkou preskočia, ako na tomto stroji
2026-10-29 (3 prešli, 3 preskočené). V hosťovi sa nemení nič, žiadny modul sa nikam
nenačítava. V meraniach sa do hosťa žiadny modul jadra nezaviedol: pôvodný hosť nemal
`gcc` ani hlavičky jadra a pripravený PoC so skutočným rootkitom
(`scripts/poc/diamorphine.sh`, spúšťa ho starý harness `scripts/session.sh`) nemá
doložený beh (`UNVERIFIED`, `docs/LIMITACIE.md`, L6). Test teda dokazuje presne jedno:
že detektor takýto zápis nájde, správne ho zaradí a pomenuje index položky. Nedokazuje
nič o detekcii skutočného malvéru.

Prepisuje sa položka s indexom 59 (`__NR_execve` na x86_64) — typický cieľ hookovania.
Originál sa nikdy neotvára na zápis; test to má aj ako samostatnú poistku
(`test_original_snimka_je_len_na_citanie`, pri reálnej snímke); nemennosť `mini.vmicd`
overuje `test_mini_snimka_sa_nemeni` (SHA-256 proti `mini.json`).

Výsledok behu (`data/results/k11_beh_20260918.log`):

| prípad | očakávané | namerané |
|---|---|---|
| nedotknutá kópia reálnej snímky | 0 nálezov | **0** |
| kópia s prepísanou položkou 59 | presne 1 nález, index 59 | **1**, `index=59`, `value=0xffffffffc0001000`, `in_module_area=true` |

Pri injikovanej kópii ostali ostatné dve kontroly na nule (`process_cross_view` 0,
`module_findings` 0), takže zápis do tabuľky sa neprelial do iných kontrol.

To isté sa overilo aj celou cestou cez príkazový riadok, na kópii reťazca
`/var/tmp/vmic-delta` (1 plná snímka + 5 delt) s prepísanou tou istou položkou:
`guestparse checks` vypísal jeden nález s `index=59` a skončil **návratovým kódom 1**.
Výpis je v `data/results/k11_beh_20260918.log`.

Pole `nearest_symbol` je pri tomto náleze `null`: adresa `0xffffffffc0001000` leží
v diere medzi koncom obrazu jadra (`_end` 0xffffffff98830000) a najnižším symbolom
v oblasti modulov, ktorý `kallsyms` pozná (0xffffffffc01a37a8, ide o BPF program),
takže jej žiadny symbol nepatrí. Meno symbolu
sa uvádza len vtedy, keď je posun v ňom menší než 1 MiB — inak by výpis pomenoval
náhodný posledný symbol a vyzeral by presvedčivejšie, než aký je.

## Validačný príkaz

```
python3 -m guestparse validate --snapshot <cesta> --profile <adresár> \
      --ps-before F --ps-after F [--lsmod F] [--ss F] --out results.json
```

Pozemná pravda sú výpisy `ps`, `lsmod` a `ss` spustené **v hosťovi** tesne pred snímkou
a tesne po nej. Porovnáva sa **stabilná množina**: pid prítomný v oboch behoch `ps`, teda
proces, ktorý bežal cez celé okno odberu. Proces, ktorý sa objaví len v jednom behu,
nie je ani chyba parsera, ani nález.

### Mená procesov

Jadro drží v `task_struct.comm` 16 bajtov, teda 15 znakov. `ps` ale tlačí pri vláknach
jadra dlhšie meno (`/proc/PID/stat` ho skladá z `kthread` full_name a z popisu pracovného
vlákna). Porovnanie preto pozná tri pravidlá a **každé použitie počíta**, aby bolo vidieť,
koľko zhôd je doslovných:

- `exact` — reťazce sú totožné,
- `truncated` — `comm` je prvých 15 znakov mena z `ps` (`rcu_tasks_kthre` ↔ `rcu_tasks_kthread`),
- `worker` — `ps` pripája popis práce (`kworker/0:0H` ↔ `kworker/0:0H-events_highpri`).

Popis pracovného vlákna sa medzi dvoma behmi `ps` bežne zmení, hoci `comm` v pamäti
je po celý čas rovnaké. Preto sa meno porovnáva proti obom behom `ps` a stabilná množina
sa tvorí podľa pid, nie podľa mena; koľko pidov malo v oboch behoch doslovne to isté meno,
hlási pole `stable_name_identical`.

### Namerané: snímka `/var/tmp/vmic-val`

Pozemná pravda: `ps` pred a po (ten istý pár, z ktorého vznikla snímka; v čase merania
uložený v dočasnom adresári mimo repa, ktorého cesta je v poli `command` artefaktu
a ktorý už neexistuje).
`lsmod` a `ss` k tejto snímke uložené nie sú, takže sa neporovnávali — v JSONe je to
napísané (`"compared": false`), nie vynechané.

| veličina | hodnota |
|---|---|
| `ps` pred / po | 84 / 82 |
| stabilná množina | 80 (z toho 77 s doslovne rovnakým menom) |
| rekonštruovaných zo snímky | 82 |
| **nájdených zo stabilnej množiny** | **80 / 80 = 100,0 %** |
| chýbajúce | 0 |
| falošné (v snímke, v žiadnom `ps`) | 0 |
| nezhoda mien | 0 |
| pravidlá zhody mien | `exact` 64, `worker` 13, `truncated` 3 |
| `checks.syscall_hooks` | 0 |

Artefakt: `data/results/validate_20260918_vmic-val.json`.

### Namerané: relácia `data/sessions/20260918T154914Z_validate`

Tu je pozemná pravda úplná (`ps`, `lsmod`, `ss` pred aj po). Uvádzajú sa obidva behy `ss`,
lebo výsledok sa medzi nimi líši a vybrať si jeden by bol výber čísla podľa výsledku.

| veličina | proti `ss`/`lsmod` **pred** | proti `ss`/`lsmod` **po** |
|---|---|---|
| procesy: stabilné | 80 (79 s rovnakým menom) | 80 |
| procesy: nájdené | **80 / 80 = 100,0 %** | 80 / 80 |
| procesy: chýbajúce / falošné / nezhoda mien | 0 / 0 / 0 | 0 / 0 / 0 |
| moduly: sediace / chýbajúce / navyše | **51 / 0 / 0** | 51 / 0 / 0 |
| sokety: sediace / chýbajúce / navyše | **11 / 1 / 1** | 10 / 2 / 2 |
| `checks.syscall_hooks` | 0 | 0 |

Artefakty: `data/results/validate_20260918T154914Z_ssbefore.json`,
`data/results/validate_20260918T154914Z_ssafter.json`.

**Rozdiely pri soketoch sú vysvetlené, nie odfiltrované:**

- *Chýba* TCP `192.168.122.100:22 → 192.168.122.1:53600` (proti `ss` pred) resp.
  `…:46882` (proti `ss` po). Je to SSH spojenie, cez ktoré sa spúšťala samotná pozemná
  pravda. Každý príkaz si otvára vlastné spojenie, takže v čase snímky žiadne nebežalo —
  zoznam procesov zo snímky obsahuje presne 80 stabilných procesov a ani jeden `sshd`
  relácie. Nejde o chybu rekonštrukcie, ide o to, že meraný stav sa medzi dvoma výpismi
  zmenil.
- *Navyše* UDP `0.0.0.0:0 → 0.0.0.0:0` procesu `systemd-network`. Je to AF_INET soket
  bez väzby; `ss` ho nevypisuje, lebo číta `/proc/net/udp`, kam sa nenaviazaný soket
  nedostane. Rekonštrukcia z pamäte teda v tomto jednom prípade vidí viac než `ss`.
- Proti `ss` po pribúda ešte UDP `192.168.122.100:53027 → 192.168.122.1:53`
  (`systemd-timesyncd`): v `ss` pred aj v snímke má zdrojový port 53027, v `ss` po už
  57006. Soket sa medzi snímkou a druhým výpisom previazal.
- RAW soket (ICMPv6, `systemd-network`) sa do `navyše` nezapočítava, lebo `ss -tuanp`
  RAW sokety nevypisuje a nie je to s čím porovnať. V JSONe je uvedený samostatne
  (`snapshot_other_protocols`), nie zamlčaný.

## Návratové kódy

`checks` končí kódom **1**, keď niečo našiel, **0**, keď nenašiel nič a všetky kontroly
sa uzavreli, a **4**, keď nenašiel nič, ale aspoň jedna kontrola sa neuzavrela. Príkaz sa
dá zaradiť do skriptu a „našiel som hook" sa nesmie stratiť v úspešnom návratovom kóde.

`validate` končí 0, keď prebehol; čísla nezhody sú výsledok, nie chyba behu. Keď je
profil z iného štartu jadra než snímka (KASLR, `docs/LIMITACIE.md`, L17), `validate` aj
čítacie podpríkazy najprv skúsia profil preukotviť; pri úspechu to oznámia na stderr
a bežia ďalej. Overené 2026-10-29 (bez artefaktu v `data/results/`, L17): `validate` nad
`data/sessions/20260918T154914Z_validate` s profilom z 19. 9. (`ps` pred aj po, `lsmod`
a `ss` pred snímkou) skončil po preukotvení kódom 0 (80/80 procesov, moduly 51/0/0,
sokety 11/1/1, rovnako ako v tabuľke vyššie). Jedna výnimka zostáva: keď sa
preukotvenie nepodarí (napr. FGKASLR alebo chýbajúce stránky), `validate` sa **vôbec
nespustí**, skončí kódom **5** a súbor `--out` nezapíše — porovnanie s pozemnou pravdou
nad profilom, ktorý k snímke nepatrí, nie je nezhoda, ale chyba vstupu, a nesmie po sebe
nechať výsledok v `data/results`. Čítacie podpríkazy vtedy výpis vypíšu, označia ho
`NEUPLNE` a takisto skončia kódom 5.

## Čo z tohto NIE JE dokázané

- Detekcia skutočného rootkitu. Overené sú dva syntetické zápisy do kópie snímky
  (`sys_call_table`: `data/results/k11_beh_20260918.log`; text jadra:
  `data/results/a3_pozitivny_20261005.json`, nález s `nearest_symbol` `startup_64`)
  a simulácia zápisu do používateľskej pamäte procesu `sshd`, ktorú kontroly nevidia,
  ale per-bin vektor a `procmap` áno (`data/results/g1_citlivost_sim_20261005.json`).
- Detekcia hooku, ktorý ukazuje **do** textu jadra (napr. prepísaná položka na inú,
  legitímnu adresu vnútri `[_stext, _etext)`). Rozsahová kontrola taký zápis z princípu
  nevidí; na to by bolo treba porovnanie s očakávaným symbolom pre daný index.
- Skrytie procesu, ktoré odpojí uzol z oboch štruktúr naraz (`tasks` aj
  `children`/`sibling`). Krížový pohľad je na to slepý; tretím pohľadom by mohol byť
  pid hash alebo sken pamäte na `task_struct`, ani jeden z nich implementovaný nie je.
- Rovnako pri moduloch: modul, ktorý sa odpojí zo zoznamu `modules` aj z `module_kset`,
  týmito dvoma pohľadmi vidieť nebude.
