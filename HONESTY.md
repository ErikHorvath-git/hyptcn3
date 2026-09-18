# HONESTY.md — pravidlá proti nafukovaniu

Tento dokument je záväzný pre všetok text a kód v tomto repozitári (`thesis/`, `docs/`,
`README.md`, komentáre v zdrojákoch). Vznikol preto, že predchádzajúca iterácia projektu
(`hypTcn002`) vyprodukovala čísla, ktoré neobstáli pri kontrole — a nešlo o preklep,
ale o systematickú chybu v metodike. Pravidlá nižšie sú zápisom toho, čo sa nesmie zopakovať.

Strojovú časť kontroly robí `scripts/check_claims.sh`. Skript nezachytí všetko;
zachytí to, čo sa dá zachytiť textovo.

---

## 1. Dvanásť pravidiel

### P1 — Zakázané čísla

Čísla zo zoznamu v kapitole 2 sa nikdy neuvádzajú ako výsledok tejto práce. Smú sa
objaviť výhradne v kapitole o predchádzajúcich iteráciách a ich retrakciách, na riadku,
ktorý obsahuje slovo `RETRAKCIA`, spolu s commit hashom a vetou, čo ich zneplatnilo.
`check_claims.sh` ich hľadá grepom.

### P2 — Ilustračné čísla nie sú merania

Čísla v `vmicollect/README.md` a v hlavičkových komentároch zdrojákov, ktoré slúžia ako
príklad formátu alebo ako rádový odhad (kapitola 3), nie sú namerané hodnoty. Do textu
práce sa neprepisujú. Do prevzatej dokumentácie sa buď dopĺňa poznámka „ilustračné“,
alebo sa nahradia nameranou hodnotou.

### P3 — Každé číslo v texte má značku zdroja

Každé číslo v `thesis/` musí mať značku `{{res:subor.json:kluc}}` ukazujúcu na súbor
v `data/results/` (kapitola 4). Čierna listina sama nestačí — tá zachytí iba čísla, ktoré
už poznáme; značka zachytí aj nové nepodložené číslo. `check_claims.sh` hlási každé číslo
bez značky a každú značku, ktorej súbor alebo kľúč neexistuje, aj rozdiel medzi hodnotou
v texte a hodnotou v JSON.

### P4 — Detekčné výsledky sa volajú syntetické scenáre správania

Žiadna tabuľka, graf ani veta o detekcii sa nesmie nazvať výsledkom nad malvérom.
Triedy sa pomenúvajú podľa správania (`cpu_burn`, `mass_file_rewrite`, `proc_scan`,
`anon_exec`, `idle`, `mixed_work`), nie podľa rodín malvéru. Veta „presnosť voči reálnym
malvérovým vzorkám nebola meraná“ patrí do abstraktu, do kapitoly o testovaní aj do záveru.

### P5 — „Funguje“ vyžaduje výstup behu z tohto repa

Tvrdenie o funkčnosti platí len vtedy, keď existuje uložený výstup behu binárky
zostavenej z tohto repozitára. Čo nikdy nebežalo, je označené `UNVERIFIED`. Konkrétne
známe prípady, ktoré sa nesmú preháňať:

- `tests/hole_test.c` testuje kontrakt collectora s *fake* backendom — netestuje BPF vetvu
  `KIND_HOLE`;
- hook API je notifikačné (nemá `read_pa`);
- prenos cez mmap je „jedno prekročenie hranice jadro/používateľ + jeden `memcpy`
  v používateľskom priestore“, nie „nulové kopírovanie“.

### P6 — Profil jadra hosťa je priznaná vstupná závislosť

`kallsyms` a BTF hosťa sa získali raz, z hosťa, mimo behu zberu — rovnako ako profil pri
LibVMI alebo Volatility. Nikde sa nepíše „bez akejkoľvek znalosti hosťa“. Rozlišuje sa:

- `qemu-guest-agent` — orchestrácia experimentu a pozemná pravda; priznané a obhájiteľné;
- bezpečnostný agent v hosťovi — protirečí zadaniu, nepoužíva sa a pred meraniami sa v
  hosťovi ukončí a zaznamená sa to.

### P7 — Nemeranú vlastnosť nemožno nazvať vlastnosťou

„Minimálny vplyv na VM“ sa smie napísať len s číslom a jeho intervalom spoľahlivosti
z merania vplyvu na hosťa. „Real-time“ sa v texte nahrádza konkrétnou periódou zberu
a nameranou latenciou snímka → vektor a snímka → skóre. Slovo bez čísla sa škrtá.

### P8 — Negatívny výsledok sa uvádza

Ak baseline (LogReg, bag-of-frames, GRU) dorovná alebo prekoná TCN, je to v tabuľke aj
v závere. Ak padne confound test, výsledok sa označí za neplatný a vysvetlí sa.
Labely sa po vyhodnotení nemenia.

### P9 — Provenience prevzatého kódu

Každý prevzatý kus kódu (architektúra TCN, príznaky nad stránkami, predlohy scenárov,
`vmi_parse.py`, opravy BPF programu) má pôvod uvedený v hlavičke súboru a v
`docs/ARCHITEKTURA.md`. Autorstvo `vmicollect` sa uvádza ako neznáme, kým sa nezistí.

### P10 — `docs/MERANIA.md` je append-only

Meranie sa nikdy neprepisuje. Oprava alebo retrakcia je nový záznam s dátumom, ktorý
odkazuje na pôvodný. Platí to aj pre `data/results/*.json` — súbor sa nemení, pridáva sa nový.

### P11 — Zakázané slová

V `thesis/` a `docs/` sa nepoužíva: *state-of-the-art*, *robustný*, *komplexný*,
*inovatívny*, *unikátny*, *production-ready*. Na žiadosť zadávateľa práce sú v kontrole
navyše *výrazne* a *revolučný*. Nahrádza sa buď číslom, alebo sa veta škrtne.
`check_claims.sh` hľadá aj tvary bez diakritiky a ohnuté tvary (kmeň slova).

### P12 — Dokumentácia sa overuje proti kódu, nie naopak

Keď sa text a kód nezhodujú, platí kód a opraví sa text. Doložené prípady zastaranej
dokumentácie z predchádzajúcich iterácií: dokumentácia uvádzala jadro hosťa `6.1.0-44`,
kým v hosťovi bežalo `6.1.0-42`; systemd unit `hyptcn_guest_ag` bol `inactive`, hoci
proces bežal; `ARCHITECTURE.md` v `hypTcn002` popisoval Poissonovské plánovanie, kým kód
mal pevný ticker.

---

## 2. Zakázané čísla

Všetky pochádzajú z projektu `hypTcn002`. Spoločný dôvod neplatnosti je **confound zo
session-level labelov**: každé okno v rámci jednej session dostalo label podľa toho, čo sa
v tej session spúšťalo, a benígne aj „malvérové“ sessions sa líšili úrovňou aktivity
systému. Okná z jednej session sa navyše miešali medzi tréningovú a testovaciu množinu,
takže testovacie okno malo v tréningu susedné okno z tej istej session. Model sa naučil
rozlíšiť „vyťažený stroj“ od „nečinného stroja“, nie malvér od benígneho softvéru.
Takto nafúknuté číslo sa nedá „opraviť prepočítaním“ — je neplatné, lebo neplatí
experiment, ktorý ho vyrobil.

| Číslo | Čo to malo byť | Prečo je neplatné |
|---|---|---|
| F1 = 99,70 | F1 binárnej detekcie | session-level labely + miešanie okien medzi split |
| AUC = 99,98 | ROC AUC binárnej detekcie | to isté |
| 0,9997; 0,9995; 0,9998; 0,9984 | metriky na okno | to isté |
| 0,9869; 0,9861; 0,9956 | metriky na okno | to isté |
| 95,5 % (5 tried) | presnosť viactriednej klasifikácie | to isté, navyše trieda = session |
| 0,86; 0,8583; 0,8633 | metriky po oprave splitu | opravený bol split, nie labely; confound zostal |
| 0,999 | AUC | to isté |
| LogReg 0,852 | baseline | to isté; baseline dorovnal model, čo bol samo o sebe signál confoundu |
| 26/33 (78,8 %) | detegované vzorky | pomer zo vzoriek, ktoré neboli overené ako spustené |
| SPRT p = 1,75e-12 | sekvenčný test | p-hodnota z nezávislých okien, ktoré nezávislé neboli |
| overhead 1,76 % | vplyv na VM | merané iným senzorom (in-guest eBPF agent), inou metodikou, bez CI |
| 4,08 f/s | priepustnosť | iný senzor |
| 3,4 ms | latencia | iný senzor, bez n a bez rozdelenia |
| 0,741 ± 0,020 | per-PID AUC po kontrole confoundu | jediné číslo z hypTcn002, ktoré prežilo kontrolu — **ale patrí inému senzoru a inému modelu**, preto sa smie uviesť iba v kapitole o predchádzajúcich iteráciách, na riadku s `RETRAKCIA` |

Zoznam je zámerne širší než to, čo by sa dalo obhájiť: ak sa nejaké z týchto čísel
objaví v texte ako nový výsledok tejto práce, je to zhoda, ktorú treba vysvetliť, nie
prehliadnuť. Číslo, ktoré tu je a naozaj bolo namerané nanovo, sa uvedie so značkou
zdroja a riadok sa vyjme z kontroly komentárom `<!-- noclaim: dôvod -->`.

---

## 3. Ilustračné čísla v prevzatej dokumentácii

Tieto čísla sú v `vmicollect/README.md` ako príklad formátu alebo rádový odhad. Nikdy
neboli namerané na tomto stroji. Overené grepom 2026-09-18 (príkaz nižšie), riadky platia
pre stav repozitára v commite `178ce4f`:

| Číslo | Súbor : riadok | Čo to v skutočnosti je | Čím sa nahrádza |
|---|---|---|---|
| `"read_mib_s": 1043.2` | `vmicollect/README.md:360` | vymyslený príklad JSON sidecaru (doména `win10`, `read_errors: 3`, `memsize` 4 GiB) | nameranou rýchlosťou čítania z konkrétneho behu |
| `"pages_changed": 812` | `vmicollect/README.md:362` | ten istý vymyslený príklad | nameraným počtom zmenených stránok zo sidecaru |
| `2,8 TB za hodinu` | `vmicollect/README.md:260` | rádový odhad „4 GiB VM každých 5 s“, nie meranie; to isté je v `src/writer_delta.c:5` a `src/retention.c:5` | nameraným objemom: plná delta snímka 276,25 MiB, delta snímka 1,06–1,28 MiB pri perióde 5 s (VM 2,02 GiB) |
| `0,5-5 % stránok` | `vmicollect/README.md:261` | rádový odhad; to isté v `src/writer_delta.c:6` | nameranou zmenou 0,05–0,06 % stránok medzi snímkami nečinnej VM |

```sh
grep -n -E '1043\.2|"pages_changed": 812|2,8 TB|0,5-5 %' vmicollect/README.md
```

**Rýchlosť čítania zo selftestu nie je rýchlosť introspekcie.** `make -C vmicollect test`
vypisuje MiB/s pre `file` backend, teda čítanie súboru z page cache; v behu 2026-09-18 to
bolo 3642 MiB/s, v inom behu 3745 MiB/s. Číslo kolíše podľa stavu cache a nemá vzťah
k čítaniu pamäte bežiacej VM. Do textu nepatrí.

Číslo `812` a rozsah `0,5-5 %` sú na grep príliš všeobecné, preto ich `check_claims.sh`
nemá na čiernej listine — v `thesis/` ich zachytí kontrola „číslo bez značky zdroja“.

Odkedy kontrola pokrýva aj `vmicollect/README.md` a komentáre v zdrojákoch, hlásila by
čísla z tejto tabuľky na ich vlastnom mieste. Sú preto v poli `EXEMPT`
v `scripts/check_claims.sh` (štyri položky, každá s dôvodom, vypíšu sa pri každom behu —
podrobnosti v kapitole 5). Je to dočasné riešenie: prevzaté súbory patria inému kroku
a poznámka „ilustračné, nie meranie“ priamo pri čísle je lepšia než zoznam vedľa.

---

## 4. Značka zdroja

Formát:

```
{{res:subor.json:kluc}}
```

- `subor.json` — názov súboru v `data/results/` (dá sa uviesť aj podadresár,
  napr. `2026-09-18_prvy_beh/probe.json`);
- `kluc` — cesta ku kľúču v JSON, úrovne oddelené bodkou, index poľa číslom
  (`values.cycle_ms.0`).

Značka sa píše **hneď za číslo**, na ten istý riadok, aj s jednotkou:

```markdown
Čítanie plnej snímky trvalo 430,6 ms {{res:2026-09-18_prvy_beh/once_raw.json:capture.capture_ms}}.
```

Čo `scripts/check_claims.sh` overí:

1. súbor `data/results/<subor.json>` existuje;
2. kľúč v ňom existuje;
3. číslo napísané pred značkou sa po zaokrúhlení na rovnaký počet desatinných miest
   zhoduje s hodnotou v JSON. Ak sa nezhoduje, je to nález — text sa opraví, JSON nikdy.

Každý JSON v `data/results/` má hlavičku `{commit, date, host, guest, command, n, values}`,
aby sa dalo dohľadať, ktorá binárka a ktorý stroj číslo vyrobili. Pôvodný výstup nástroja
je celý pod kľúčom `values`; hlavička sa dopĺňa okolo neho, nie doňho.

Túto hlavičku strojovo kontroluje `scripts/check_claims.sh --json-hlavicky` (kontrola E,
kód nálezu `JSON-HLAVICKA`); spúšťa sa aj pri behu bez argumentov. Nekontrolujú sa dva
druhy adresárov, lebo v nich nie sú odvodené výsledky, ale doslovné výstupy — `sidecars/`
(výstup `vmicollect`, schéma `vmicollect/1`) a `ground_truth/` (výstup príkazov v hosťovi).
Dopísať hlavičku do nich by znamenalo zmeniť nameraný súbor.

Ak sa niektorý údaj hlavičky spätne zistiť nedá, píše sa `null` a k nemu poznámka, prečo —
nikdy sa nedopĺňa odhadom. Keď `commit` neurčuje kód, ktorý súbor vyrobil (napríklad preto,
že príslušný adresár v tom commite ešte nebol sledovaný), patrí to do poznámky pri `commit`.

---

## 5. Spustenie kontroly

```sh
scripts/check_claims.sh            # východzí rozsah (nižšie), návratový kód 0 = čisté, 1 = nálezy
scripts/check_claims.sh thesis/09_testovanie.md
scripts/check_claims.sh --json-hlavicky   # iba kontrola hlavičiek v data/results/
```

Východzí rozsah zodpovedá prvej vete tohto dokumentu: `thesis/`, `docs/`, `README.md`
v koreni, `vmicollect/README.md` a komentáre v zdrojákoch (`vmicollect/{src,include,bpf,hooks,tests}`,
`guestparse/`, `scripts/`). Do 2026-09-18 bol rozsah iba `thesis/` a `docs/` — koreňový
`README.md`, teda súbor s hlavnými nameranými číslami, sa nekontroloval nikdy.

V zdrojáku sa kontroluje **text komentárov**, nie kód: konštanta `0.86` v algoritme nie je
metrika z `hypTcn002`, kým tá istá hodnota vo vete v komentári tvrdením je.

Kódy nálezov:

| Kód | Znamená |
|---|---|
| `ZAKAZANE-CISLO` | číslo z čiernej listiny (kapitola 2) mimo riadku s `RETRAKCIA` |
| `BEZ-ZNACKY` | číslo v `thesis/` bez značky `{{res:...}}` |
| `ZNACKA-TVAR` | značka nemá tvar `{{res:subor.json:kluc}}` |
| `ZNACKA-SUBOR` | súbor v `data/results/` neexistuje alebo sa nedá prečítať |
| `ZNACKA-KLUC` | kľúč v JSON nie je |
| `ZNACKA-HODNOTA` | hodnota v texte sa nezhoduje s hodnotou v JSON |
| `ZAKAZANE-SLOVO` | slovo z P11 |
| `JSON-HLAVICKA` | JSON v `data/results/` bez hlavičky z kapitoly 4 |

Výnimky v texte (každá je stopa v texte, nie tichý zoznam vedľa):

| Zápis | Účinok |
|---|---|
| `RETRAKCIA` na riadku | riadok smie obsahovať zakázané číslo aj číslo bez značky — staré číslo žiadny JSON v `data/results/` nemá a mať nemá |
| `<!-- noclaim: dôvod -->` | riadok sa preskočí vo všetkých kontrolách; dôvod je povinný |
| `<!-- prevzate:start -->` … `<!-- prevzate:end -->` | prevzatá tabuľka s vlastnou citáciou; kontrola „číslo bez značky“ sa v nej nerobí |
| oplotený blok kódu (```` ``` ````) | zakázané čísla **aj** zakázané slová sa v ňom hľadajú — výsledok sa v texte bežne uvádza práve ako ukážka výstupu (`{"f1": 99.70}`) a je to tvrdenie ako každé iné; kontrola „číslo bez značky“ a kontrola značiek sa v ňom naopak nerobia (čísla vo výpise sú legitímne a `{{res:...}}` v bloku je ukážka zápisu) |
| `thesis/.claims-allow` | regexy tokenov, ktoré číslami tvrdenia nie sú; súbor je verzionovaný, takže je vidieť, čo sa vyňalo |

Výnimka mimo textu je len jedna a platí pre prevzaté súbory: pole `EXEMPT`
v `scripts/check_claims.sh`. Každá položka je trojica `súbor | vzor | dôvod`, platí iba pre
ten jeden súbor (v `thesis/` a `docs/` zostáva to isté číslo nálezom) a skript uplatnené
výnimky na konci každého behu vypíše, takže vyňatie nie je tiché. Dnes sú v ňom štyri
položky — ilustračné čísla z kapitoly 3 v `vmicollect/README.md`, `vmicollect/src/writer_delta.c`
a `vmicollect/src/retention.c`. Správnejšie je napísať „ilustračné, nie meranie“ priamo
k číslu v tých súboroch a položky z `EXEMPT` zmazať; dovtedy drží výnimku zoznam.

Čo kontrola **nezachytí**: nepravdivú vetu bez čísla, číslo prepísané aj v JSON aj v texte,
zlú metodiku za správne uloženým číslom, číslo v kóde mimo komentára, prítomnosť hlavičky
ako záruku, že sú v nej pravdivé údaje. Skript je sito na to, čo sa dá overiť textovo —
nie dôkaz poctivosti.

Kontrola je súčasťou finálneho auditu (krok K30): pred odovzdaním musí vrátiť 0 nálezov.
Tento súbor (`HONESTY.md`) sa zámerne nekontroluje — obsahuje zoznam zakázaných čísel,
takže by hlásil sám seba.
