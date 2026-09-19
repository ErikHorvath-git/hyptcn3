# Kontroly podozrivých vzorcov v pamäti a validačný príkaz

Krok K11 plánu a validačná časť K09. Modul `guestparse/checks.py`, porovnanie s pozemnou
pravdou `guestparse/validate.py`, test `guestparse/tests/test_injection.py`.

Všetky čísla nižšie pochádzajú z behov zaznamenaných v
`data/results/k11_beh_20260918.log` a z artefaktov `data/results/checks_*.json`
a `data/results/validate_*.json`.

## Čo sa kontroluje a prečo práve toto

Zo samotnej pamäte sa dá overiť len to, čo má jadro dané invariantne. Každá z troch
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

### Čo kontrola nehovorí

Každá kontrola hlási `conclusive`. Snímka sa odoberá bez zastavenia VM, takže prechod
zoznamu sa môže roztrhnúť; keď sa niektorý prechod neuzavrel, rozdiel dvoch zoznamov
**nie je** dôkaz skrývania a nulový výsledok nič nedokazuje. V takom prípade je názov
kontroly v poli `summary.inconclusive`.

## Namerané: čistý hosť

`python3 -m guestparse checks --snapshot <cesta> --profile profiles/debian12-6.1.0-42-cloud-amd64`

| snímka | `sys_call_table` | procesy `tasks` vs. strom | moduly `modules` vs. `module_kset` | nálezy |
|---|---|---|---|---|
| `/var/tmp/vmic-val` (1 plná) | 451 položiek | 82 vs. 82 | 47 vs. 47 (zo 105 kobjektov) | **0** |
| `/var/tmp/vmic-delta` (1 plná + 5 delt) | 451 položiek | 76 vs. 76 | 47 vs. 47 (zo 105 kobjektov) | **0** |
| `data/sessions/20260918T154914Z_validate/snap` | 451 položiek | 80 vs. 80 | 51 vs. 51 (zo 109 kobjektov) | **0** |

Vo všetkých troch behoch bolo `summary.inconclusive` prázdne, teda všetky tri kontroly
sa uzavreli. Artefakty: `data/results/checks_20260918_{val,delta,session}.json`.

## Injekčný test — čo to je a čo to NIE je

Kontrola, ktorá na čistom hosťovi vždy vráti nulu, je na nerozoznanie od funkcie, ktorá
vždy vracia nulu. Preto k negatívnemu prípadu patrí aj pozitívny.

**Ide o injekciu do kópie snímkového súboru, nie o skutočný rootkit v hosťovi.**
Test (`guestparse/tests/test_injection.py`) si urobí kópiu reálnej snímky, v kópii prepíše
8 bajtov jednej položky `sys_call_table` na adresu v oblasti modulov
(`0xffffffffc0001000`) a spustí detektor nad kópiou. V hosťovi sa nemení nič, žiadny
modul sa nikam nenačítava. Do hosťa by sa to ani načítať nedalo — nemá `gcc` ani hlavičky
jadra, takže vlastný modul sa v ňom preložiť nedá. Test teda dokazuje presne jedno:
že detektor takýto zápis nájde, správne ho zaradí a pomenuje index položky. Nedokazuje
nič o detekcii skutočného malvéru.

Prepisuje sa položka s indexom 59 (`__NR_execve` na x86_64) — typický cieľ hookovania.
Originál vo `/var/tmp` sa nikdy neotvára na zápis; test to má aj ako samostatnú poistku
(`test_original_snimka_je_len_na_citanie`).

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

Pozemná pravda: `ps` pred a po (scratchpad, ten istý pár, z ktorého vznikla snímka).
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

`validate` končí 0, keď prebehol; čísla nezhody sú výsledok, nie chyba behu. Jedna výnimka:
keď je profil z iného štartu jadra než snímka (KASLR, `docs/LIMITACIE.md`, L17), `validate`
sa **vôbec nespustí**, skončí kódom **5** a súbor `--out` nezapíše — porovnanie s pozemnou
pravdou nad profilom, ktorý k snímke nepatrí, nie je nezhoda, ale chyba vstupu, a nesmie po
sebe nechať výsledok v `data/results`. To isté zisťovanie beží pred každým podpríkazom;
čítacie podpríkazy výpis vypíšu, označia ho `NEUPLNE` a takisto skončia kódom 5.

## Čo z tohto NIE JE dokázané

- Detekcia skutočného rootkitu. Overený je jeden syntetický zápis do kópie snímky.
- Detekcia hooku, ktorý ukazuje **do** textu jadra (napr. prepísaná položka na inú,
  legitímnu adresu vnútri `[_stext, _etext)`). Rozsahová kontrola taký zápis z princípu
  nevidí; na to by bolo treba porovnanie s očakávaným symbolom pre daný index.
- Skrytie procesu, ktoré odpojí uzol z oboch štruktúr naraz (`tasks` aj
  `children`/`sibling`). Krížový pohľad je na to slepý; tretím pohľadom by mohol byť
  pid hash alebo sken pamäte na `task_struct`, ani jeden z nich implementovaný nie je.
- Rovnako pri moduloch: modul, ktorý sa odpojí zo zoznamu `modules` aj z `module_kset`,
  týmito dvoma pohľadmi vidieť nebude.
