# Návrh protokolu v5: zber, beh VM, model a vyhodnotenie

**Stav:** druhá verzia z 2026-11-21 po dvoch nezávislých recenziách (metodika, fakty).
Otvorené otázky rozhodol autor návrhu z poverenia vlastníka (kap. 12); vlastník ich môže
zmeniť do začiatku stupňa G1. Súbor protokolu v5 zatiaľ neexistuje; vznikne v stupni G0.

**Čo je na vetve `v5-protocol`** (pripravené, necommitnuté, na VM nikdy nebežalo): služba
`worker` pri zamknutej tabuľke nekončí (`lab/services.py`), audit logov pozná jej chybový
riadok (`scripts/collection_logs.py`), schéma protokolu 3 kontroluje dosiahnuteľnosť pravidla
prijatia (`scripts/collection.py`, `features/quality.py`), testy k tomu.

**Podklad:** audit šiestich oblastí kódu z 2026-11-20
([záznam](../data/results/audit_kodu_v5_20261120.json)). Zo 72 rizík má 68 verdikt druhého
čitateľa: 53 potvrdených, 15 spresnených, žiadne vyvrátené. Štyri riziká nízkej závažnosti
verdikt nemajú a 30 doplnení overovateľa čítal iba on. Surové datasety už neexistujú, dôkazom
je kód, testy a záznamy v `data/results/`. Viaceré tvrdenia auditu stoja na jednorazových
skúšobných skriptoch, ktoré v repozitári nie sú; v texte sú označené slovom „skúška“ a ich
zopakovateľný test je úlohou stupňa G0.

**Slovník.** *Stupeň* G0 až G6 je krok pripravenosti. *Kontrola auditu* rozhoduje o prijatí
jednej session. *Označený riadok* je neplatný riadok alebo riadok, ktorého zoznam procesov
uzavrelo pravidlo parsera. *Dozvuk* je 300 s po skončení udalosti. *Kontrola na VM* je
benígny program s nezvyčajným správaním spustený v hosťovi; *zásah* je úprava príznakov
odloženej session bez zberu. *Kanál* znamená vždy kanál skóre (kap. 8.2).

---

## 0. Zhrnutie

1. **Doterajšie pravidlá dokazovali pôvod dát, nie to, že protokol môže uspieť.** Zmrazený
   commit, hash protokolu a pilot strážili, že dáta vznikli z deklarovaného kódu. Nikto
   neoveril, či si pravidlá prijatia neprotirečia, či limit náhrad zodpovedá miere zamietnutí
   a či pilot spustí to, čo kampaň (kap. 1).
2. **Aj dokončená kampaň v4 by skončila chybou.** Tréning odmieta korpus, ktorý audit prijme
   (predpona skupín, tolerované neplatné riadky). Žiadna kampaň v4 nedobehla a testy tento krok
   nahrádzajú atrapou, preto sa to nezistilo (kap. 2.6).
3. **Obava „glorifikovaný if-else“ má oporu vo výpočte, nie v meraní.** V jedinom uloženom
   modeli stačila zmena jedného počúvajúceho soketu, aby jeden riadok prekročil prah, a stĺpce
   konštantné v tréningu model takmer nevidí. Ktorý vstup niesol skutočné alarmy a či sieť
   využíva časovú štruktúru, merané nebolo (kap. 2.1).
4. **Bez pozitívnej strany sa model posúdiť nedá.** Benígne dáta merajú iba falošné alarmy
   a prah je kvantil skóre, takže podiel okien nad prahom je vopred daný pre akékoľvek skóre.
   Rozdiel medzi modelom a triviálnou metódou ukáže až citlivosť pri zhodnej miere alarmov.
5. **Návrh má dve potvrdzujúce tvrdenia a zvyšok je opisný** (kap. 4). Každý test, ktorý
   môže vyhlásiť úspech, musí najprv na dátach bez štruktúry vyhlásiť neúspech (kap. 8.4).
6. **Cesta k datasetu má osem stupňov** (kap. 10): kód, suchý beh so známymi odpoveďami,
   skúška na VM, prieskumná generálka, potvrdzujúca generálka, zmrazenie, kampaň, jedno
   vyhodnotenie. Generálky sú malé kampane, ktoré do datasetu nikdy nejdú.
7. **Laboratórium dostane profily prevádzky** (e-shop, firemný server), premenlivú záťaž
   a benígne činnosti v pozadí (kap. 5).
8. **Rozsah je väčší než doterajšie iterácie.** Kód a skúšky pred kampaňou sú práca na
   týždne, nie dni (kap. 14). Celkový zber sa nezvyšuje: namiesto dvoch kampaní po 96 session
   je jedna so 132 a dve generálky po 30.

---

## 1. Čo sa pokazilo a prečo to pravidlá nezachytili

| # | Zlyhanie | Príčina | Prečo to prešlo | Opatrenie vo v5 |
|---|---|---|---|---|
| 1 | Kampane v4 a v4c sa zastavili na limite náhrad (10 z 96 a 47 z 96 session podľa `PLAN_multivm_dataset.md` a `docs/STAV.sk.md`; úhrnný záznam neexistuje) | tri príčiny nižšie | limit náhrad (2, potom 6) určený úsudkom | limit z nameranej miery (kap. 7.5) |
| 2 | Zmeškané sloty zberača | pamäť jednej VM odložená do swapu počas archivácie druhej | zákaz swapu bol ručné nastavenie operátora, kód ho nenastavuje ani nekontroluje; archivácia beží mimo obmedzeného scope (`scripts/campaign.py:997-1003`) | zákaz swapu v kóde, kontrola pred štartom, kontrola auditu (kap. 6.2) |
| 3 | Roztrhnutý zoznam procesov v každom piatom riadku | služba `worker` končila počas `zamok_tabulky` každých 6,25 s {{res:collection_worker_resonance_20261120.json:values.worker_restart.period_s_mean}}; štyri periódy sú 25,0 s {{res:collection_worker_resonance_20261120.json:values.worker_restart.four_periods_s}}, teda päť intervalov zberu | pilot túto udalosť nespúšťa; audit logov reštarty `worker` od 2026-11-04 ospravedlňoval ako zámer (commit `4f024d8`) | oprava služby je pripravená, v hosťovi UNVERIFIED; ohraničené slučky, sken periodicity, generálka so všetkými udalosťami (kap. 5.5, 5.6, 10) |
| 4 | Pravidlo prijatia si protirečilo | povolené 3 neplatné riadky, brána pokrytia pustila 1: z 656 {{res:collection_worker_resonance_20261120.json:values.coverage_gate.ideal_windows}} okien vyradí jeden riadok 33 {{res:collection_worker_resonance_20261120.json:values.coverage_gate.windows_lost_per_isolated_invalid_row}} | pravidlá sa nikdy neprepočítali proti sebe | jedna funkcia prijatia, test hraničných prípadov (kap. 6.3) |
| 5 | Pilot nič z toho neukázal | jedna session, jeden scenár, 2 zo 7 typov udalostí, bez archivácie, bez nároku na druhú VM (`scripts/collection.py:290-299`, `scripts/campaign.py:186-210`) | pilot bol kontrola kódu, nie skúška kampane | generálky v tvare kampane (kap. 10) |
| 6 | Po neúspešných kampaniach neostal úhrnný záznam | `campaign.py close` žiada iba text dôvodu; zápis v `docs/MERANIA.md` vznikol až 2026-11-20 po zmazaní dát | pravidlo P10 nemá strojovú kontrolu | povinný záznam pri uzavretí, mazanie až po ňom (kap. 11) |

Z 54 {{res:collection_worker_resonance_20261120.json:values.attempts}} pokusov kampane v4c
malo udalosť `zamok_tabulky` 20 {{res:collection_worker_resonance_20261120.json:values.lock_event.attempts}}.
V 4 {{res:collection_worker_resonance_20261120.json:values.lock_event.attempts_in_step}} z nich
boli v okne udalosti aspoň tri označené riadky (definícia záznamu, určená až po zbere)
a 3 {{res:collection_worker_resonance_20261120.json:values.lock_event.attempts_in_step_rejected_by_coverage}}
zamietla brána pokrytia. V okne udalosti vrátane 60 s po jej konci ležalo
9 {{res:collection_worker_resonance_20261120.json:values.lock_event.invalid_rows_inside}}
z 13 {{res:collection_worker_resonance_20261120.json:values.invalid_rows}} neplatných riadkov
kampane; samotné udalosti pokrývali 999 {{res:collection_worker_resonance_20261120.json:values.lock_event.exposure_rows}}
z 38880 {{res:collection_worker_resonance_20261120.json:values.rows}} riadkov.

Spoločný vzorec: na každú poruchu prišla tolerancia, pravidlo v parseri alebo vyšší limit,
overené na jednej až dvoch pokazených snímkach. Príčina v laboratóriu sa začala opravovať až
po tretej zastavenej kampani. Preto v5 zavádza pravidlo „najprv príčina, potom tolerancia“.

---

## 2. Čo ukázal audit systému

### 2.1 Model

Prediktor je kauzálna TCN s dvoma vetvami: globálna má 20 vstupov, binová 4 hodnoty na bin
pamäte (128 binov po 16 MiB a dva malé), jedna sieť je zdieľaná cez všetky biny. Má 4 bloky
po 16 filtroch a 12 967 parametrov (spočítané vytvorením modelu; `safeguard/model.py:20-26,
50-63`). Učí sa predpovedať ďalší riadok. Skóre je polovica priemeru štvorcov normalizovaných
chýb globálnych stĺpcov plus polovica chyby najhoršieho binu (`safeguard/model.py:84-92`).
Prah je kvantil 0,99 skóre všetkých okien roly `calibration`; alarm vznikne pri 3 z 5
posledných skóre nad prahom (`safeguard/training.py:228-260`, `safeguard/runtime.py:209-212`).

| Nález | Dôkaz | Dôsledok |
|---|---|---|
| Jeden nepredpovedaný kus v takmer konštantnom počte rozhodne o jednom riadku | prah modelu v6 bol 14,43 {{res:safeguard_train_benign_v6_20261029.json:values.manifest.calibration.threshold}}; z normalizéra toho istého záznamu vychádza, že jedna jednotka v `sock_listen` pridá ku skóre asi 90 a v `proc_user` asi 20 (výpočet 0,5·(1/σ)²/18) | riadok nad prahom ešte nie je alarm (treba 3 z 5) a ktorý vstup niesol uložené alarmy, overené nie je; riziko, že časť detektora je prah na jednom počte, je však vyčíslené |
| Stĺpec konštantný v tréningu dostane mierku 1 a je takmer neviditeľný | `safeguard/features.py:392-393`; v6: `mod_total`, `mod_delta`; jedna jednotka pridá asi 0,03 (výpočet) | načítaný modul jadra model neuvidí; to isté hrozí stĺpcom `proc_wx` a `proc_memfd` (neoverené, dáta nie sú) |
| Chýba porovnanie s triviálnou predpoveďou | manifest ukladá iba stratu na `train` a `dev`; skúška na syntetických dátach bez časovej štruktúry dala stratu: priemer 0,946, posledná hodnota 0,397, priemer okna 0,236, TCN 0,209 | TCN tam vyšla o 11 % lepšie než priemer okna, hoci sa nebolo čo naučiť; hranice testov sa preto musia kalibrovať na nulovom prípade (kap. 8.4) |
| Tréning skončil na strope epoch | vybraná epocha 10 {{res:safeguard_train_benign_v6_20261029.json:values.manifest.training.selected_predictor_epoch}} z 10, strata na `dev` stále klesala | počet epoch bol neregistrovaná voľba |
| Existujúce základné metódy nie sú zrovnateľné | z-skóre priemeruje celé okno (`tcn/porovnanie.py:284-287`), GRU a LSTM dostanú biny iba ako priemer a maximum (`:94-95`); na vstupoch detektora neexistuje žiadny uložený výsledok porovnania (iba dva rané záznamy z októbra na desiatkach okien) | výhra TCN nad nimi by na otázku neodpovedala |
| Poistka „test iba raz“ sa dá obísť | značka je viazaná na cestu súboru (`tcn/eval.py:1226-1237`), kópia indexu ju obíde (skúška); `safeguard replay` berie ľubovoľný archív (`safeguard/cli.py:82-112`); finálny postup v6 prehral testovacie session pred zápisom značky | zapečatenie podľa obsahu, jeden finálny príkaz |
| Parametre analýzy sú voľné | epochy, seed, `fpr`, `k`, `n` sú argumenty príkazového riadka (`safeguard/cli.py:20-25`) | plán analýzy patrí do hashovaného protokolu |
| Neskórovaný čas pri výskyte sa nevykazuje | po plnej snímke, neplatnom riadku alebo medzere sa 32 riadkov neskóruje (`safeguard/features.py:319-330`) a hlasovanie sa nuluje (`safeguard/runtime.py:187-200`); súhrnný podiel sa vykazuje, pri jednotlivom výskyte udalosti počet skórovaných riadkov chýba (`tcn/eval.py:517-532`) | výskyt bez skóre vyzerá ako „bez alarmu“ |
| Pravidlo 3 z 5 obmedzuje, čo sa dá zachytiť | alarm potrebuje aspoň 3 prekročenia v 5 skóre; jednorazové zásahy mali 0 {{res:safeguard_far_events_v3_20261114_summary.json:values.by_type.restart_sluzby.with_model_alarm}} zo 16 {{res:safeguard_far_events_v3_20261114_summary.json:values.by_type.restart_sluzby.occurrences}} alarmov, trvalé 15 {{res:safeguard_far_events_v3_20261114_summary.json:values.by_type.zamok_tabulky.with_model_alarm}} z 15 {{res:safeguard_far_events_v3_20261114_summary.json:values.by_type.zamok_tabulky.occurrences}} | súvislosť s trvaním je domnienka: prekročenia po oknách uložené nie sú a reštart databázy, tiež jednorazový, mal 14 zo 16 |

### 2.2 Príznaky

| Nález | Dôkaz | Dôsledok |
|---|---|---|
| Úrovňový stĺpec `mem_zero_ratio` sa posúva s vekom procesu QEMU a s poradím rolí | medián po session bol v `train` 0,478 až 0,700 a v `calibration` 0,427 až 0,438 (`safeguard_far_events_v3_20261114_summary.json`, `values.mem_zero_ratio_benign_v6`); v neskorších skupinách kampane udalostí 0,236 až 0,320 (`values.mem_zero_ratio_p50.groups_5_8`); vnútri skupín nie je monotónny | prah sa kalibruje na posunutom rozdelení; stĺpec môže slúžiť ako skratka pre rolu |
| Sokety sú v tomto labe takmer bez informácie | počítajú sa iba IPv4 a IPv6; služby idú na databázu cez unixový soket; v6: `sock_listen` 20,0002 ± 0,018 (normalizér záznamu v6); nové spojenie na každú požiadavku je predvolené správanie nginx, v hosťovi nekontrolované | zmeniť služby tak, aby stav spojení bol viditeľný, alebo dať sokety do pravidlového kanála |
| Riadky uzavreté pravidlom sú platné a neobmedzené | pravidlá `prev`, `tail`, `meet` vrátia `truncated = false` (`guestparse/view.py:463-504`); vo v4c 28 {{res:collection_worker_resonance_20261120.json:values.rows_closed_by_rule.prev}} a 12 {{res:collection_worker_resonance_20261120.json:values.rows_closed_by_rule.tail}} takých riadkov | strop na session, periodicita ako varovný signál, citlivostná analýza bez nich |
| Počty soketov a W+X sú dolné hranice bez príznaku | preskočená úloha zníži počet, riadok ostane platný (`guestparse/view.py:781-830` pre sokety, `:935-1001` pre W+X) | počty preskočení do kvality riadku |
| Pozemná pravda pod záťažou chýba | porovnania s `ps`, `lsmod`, `ss` sú z nečinného hosťa zo septembra | overenie pod záťažou v stupni G2 |
| Poradie scenárov v skupine nie je vyvážené | vo všetkých štyroch skupinách `test_benign` plánu v4 je prvý `mixed` (`scripts/collection.py:339-346`, výpočet plánu) | vyvážený rozvrh v protokole |
| Zoznam vstupov je konštanta v hashovanom extraktore | `features/archive.py:13`; zmena po kampani znamená nový audit všetkých session | maska stĺpcov a pravidlo mierky ako dáta protokolu |
| Binová vetva: spoločná mierka, maximum cez nerovnaké biny | `safeguard/features.py:385-388`, `safeguard/model.py:91-92`; rozloženie má aj bin s 1 stránkou a bin so 64 stránkami | minimálna veľkosť binu, pravidlo mierky a jedna alternatívna agregácia (kap. 8.2) |
| Dôkazy o príznakoch prežili náhodou | jediné rozdelenie stĺpcov je priemer a odchýlka v jednom manifeste | každý audit ukladá súhrn každého stĺpca |

### 2.3 Zber a audit session

| Nález | Dôkaz | Dôsledok |
|---|---|---|
| Príkazy udalostí sú fázovo zviazané so zberom | začiatky a trvania sú násobky 30 s; prvá snímka prichádza 2,9 až 4,0 s po začiatku merania (15 uložených auditov, všetky z jednej VM); všetkých 60 oneskorení prvého alarmu v kampani udalostí má zvyšok po delení 5 s medzi 2,09 a 3,46 s | každý prechod vidíme v jedinej fáze; začiatky treba losovať spojito |
| Väčšina kontrol auditu nemá test, ktorý by ich spustil | 19 z 24 dôvodov zamietnutia na strane RAM a 53 zo 73 kľúčov auditu logov (počty z auditu) | samotest kontrol: jedna zlá session na každú |
| Meškanie cyklu nečíta žiadna kontrola | `lateness_s` sa zapisuje a vypisuje ho iba správa kampane; skúšobná session s meškaním 4,0 s v každom cykle bola prijatá (skúška) | kontrola meškania a odchýlky od mriežky |
| Varovania zberača session nezamietnu | `scripts/collection_logs.py:359-363` | zoznam povolených varovaní, ostatné zamietajú |
| Udalosť, ktorá neprebehla, sa prijme | ak hosť na štart odpovedal, `executed=false` je iba záznam; zámok, záloha a záťaž pamäte vrátia úspech hneď po spustení (`lab/udalosti.py:44-50`) | predikát účinku pre každý typ udalosti |
| Snímky nie sú viazané na VM session | sidecar nesie doménu a PID, audit ich neporovná | kontrola identity VM |
| Rezerva času cyklu pre dve VM je nezmeraná | najdlhšia uložená plná snímka trvala 2728,8 ms {{res:collection_campaign_events_v3_20261108.json:values.summary.full_ms_max}} pri jednej VM | najhorší prípad v stupni G2 |
| Dva zberače na rovnakej mriežke majú stály vzájomný posun | `vmicollect/src/sched.c:46-48, 130` | posun zapísať pri každej session a pokryť oba režimy |

### 2.4 Laboratórium

| Nález | Dôkaz | Dôsledok |
|---|---|---|
| Normál je takmer statický | kód labu mimo udalostí procesy nevytvára: služby sú vláknové s pevnými poolmi, časovače vypnuté (`lab/services.py:224-231`, `lab/install.sh:36-40`); v6 bol priemer `proc_new` 0,005 na riadok | či na oddelenie udalostí stačí prah na jednej premennej, overené nie je; proti hovorí, že záloha a reštart služby procesy vytvárajú a alarm nemali |
| Šesť scenárov je šesť stálych úrovní jedného API | od 1,46 do 48,27 požiadavky za sekundu; súčty jedného scenára sa medzi session líšia najviac o 3,2 % (záznam kampane v6) | profily s premenlivou záťažou |
| Uzavretá slučka generátora | pomalý server zníži ponúkanú záťaž (`scripts/host_traffic.py:420-442`) | otvorená slučka so stropom súbežnosti |
| Slučka pádov ostáva v udalosti `zla_konfiguracia_sluzby` | `RestartSec=3`; v kampani udalostí boli postihnuté riadky v 9 z 11 medzier 13 snímok od seba, čo zodpovedá perióde asi 3,25 s (odvodené, v hosťovi nemerané) | každú slučku, ktorá vytvára procesy, ohraničiť |
| Perióda 60 s v PostgreSQL | v kampani v6 boli všetky medzery medzi nepotvrdenými riadkami násobkom 12 snímok | register periód vrátane nastavení databázy |
| Stopa spúšťača udalostí | každý štart a stop ide cez agenta hosťa: shell, `python3`, šesť volaní `systemctl` | udalosť naprázdno ako negatívna kontrola |
| Prvá záťaž pamäte natrvalo posunie vstup modelu | v kampani udalostí klesol `mem_zero_ratio` v jednej session z 0,587 na 0,370 a nevrátil sa (záznam kampane) | definovaný počiatočný stav pamäte skupiny |
| Typ udalosti je zviazaný s počtom udalostí | balíček typov aj rozvrh berú ten istý seed (`scripts/collection.py:313-353`) | nezávislé prúdy náhody podľa účelu |
| Nasadený kód hosťa sa neporovnáva s repozitárom | hash nasadených súborov (`scripts/collection.py:470-486`) sa porovná iba s hosťom pilota (`scripts/campaign.py:350-369`) | kontrola zhody pred každým behom |

### 2.5 Vyhodnotenie

| Nález | Dôkaz | Dôsledok |
|---|---|---|
| S udalosťami v normále klesnú falošné alarmy už konštrukciou | prah je kvantil všetkých okien `calibration` vrátane udalostí a mierka normalizéra sa učí aj na udalostiach | citlivosť je hlavný výsledok; prah z čistej prevádzky sa uvedie vedľa |
| Skupina bootu je deklarovaná jednotka, žiadny interval ju nepoužíva | všetky intervaly sú presné vzorce nad zlúčenými počtami (`tcn/eval.py:198-206`); `test_benign` v6 mal 2 {{res:safeguard_far_test_benign_v6_20261104.json:values.merane.skupin}} skupiny | tabuľka po bootoch, viac kratších skupín |
| Veľkosť testu neunesie prísne tvrdenia | kap. 9.2 | falošné alarmy sa uvedú ako odhad s hranicou |
| Výskyt v neskórovanom úseku sa ráta ako ticho | v zázname kampane udalostí začali všetky štyri oneskorenia nad 30 s v neskórovanom úseku po plnej snímke | „hodnotiteľný výskyt“, zákaz udalostí okolo plnej snímky |
| Porovnanie s predchádzajúcou iteráciou je zmiešané s inými zmenami | medzi krokmi sa zmenil lab, VM aj počet vstupov | iba opisne; kontrola vnútri v5 ako rozšírenie (kap. 8.7) |
| Reťaz vyhodnotení nikdy nebežala na dátach s 20 vstupmi | žiadny záznam pre porovnanie metód, klasifikátor, seedy, réžiu | generálka musí prejsť celú reťaz |

Východiskové čísla z predchádzajúcej iterácie (model bez udalostí v tréningu): v čistej
prevádzke 0,047 {{res:safeguard_far_events_v3_20261114.json:values.merane.prevadzka.far_h.skorovany.udalosti_h}}
alarmu za skórovanú hodinu, počas udalostí 5,63 {{res:safeguard_far_events_v3_20261114.json:values.merane.vsetky_udalosti.far_h.skorovany.udalosti_h}},
na `test_benign` 0,091 {{res:safeguard_far_test_benign_v6_20261104.json:values.merane.spolu.far_h.skorovany.udalosti_h}}.

### 2.6 Proces

| Nález | Dôkaz | Dôsledok |
|---|---|---|
| Odovzdanie korpusu tréningu zlyhá až po kampani | `validate_index` čaká skupiny bez predpony (`safeguard/training.py:154-158`), kampaň ho volá v poslednom kroku (`scripts/campaign.py:1255-1257`); `train_bundle` odmietne session s tolerovaným neplatným riadkom (`safeguard/training.py:286-287`); oboje zopakované skúškou | suchý beh celej reťaze na skutočnom súbore protokolu je podmienkou štartu |
| Audit a brána pilota rozhodujú rôzne | audit uplatní toleranciu neplatných riadkov aj na pilot, `pilot_gate` žiada všetky riadky platné (`scripts/campaign.py:194`) | jedna funkcia prijatia |
| Existujúci „smoke“ nič nedokazuje | `safeguard smoke`: hračkársky protokol, nemusí vzniknúť alarm; testy kampane nahrádzajú zber, audit aj záverečný index atrapou | suchý beh so známymi odpoveďami |
| Zadanie žiada viac než benígne dáta | presnosť detekcie malvérových vzorcov, réžia, použiteľnosť (`docs/STAV.sk.md:25-43`) | v5 pomenuje každý experiment a jeho hranice (kap. 4) |

---

## 3. Zásady protokolu v5

1. **Uskutočniteľnosť sa dokazuje pred zberom.** Každé pravidlo prijatia, limit a rozpočet má
   test alebo simuláciu, ktorá ukáže, že kampaň s nameranými mierami dobehne.
2. **Známa odpoveď pred skutočnými dátami.** Celá reťaz najprv prejde syntetické dáta, kde
   vieme, čo má vyjsť.
3. **Každý test má aj zápornú skúšku.** Test, ktorý môže vyhlásiť úspech, musí na dátach bez
   hľadaného javu vyhlásiť neúspech. Platí to pre hypotézy o modeli aj pre diagnostiky.
4. **Prieskum oddelený od potvrdenia.** Ladí sa iba na prieskumnej generálke. Potvrdzujúca
   generálka a finálny dataset sa nevidia, kým nie je všetko zmrazené.
5. **Žiadne tiché zlyhanie.** Čo systém nevie posúdiť, hlási ako „nevyhodnotené“, nikdy ako
   „bez nálezu“. Chýbajúci kľúč alebo súbor zamieta.
6. **Hranice z mechanizmu, nie z výsledku.** Kde sa dá, hranica plynie z konštrukcie (okná
   stratené na riadok, podiel intervalu). Kde treba meranie, je vopred zapísaný vzorec
   (kap. 10.9), nie číslo zvolené po pohľade na dáta.
7. **Príčina pred toleranciou.** Nová tolerancia, pravidlo parsera alebo vyšší limit sa pridá
   až po pomenovaní príčiny a rozhodnutí, či sa dá odstrániť pri zdroji.
8. **PoC, nie produkt.** Každý mechanizmus odpovedá na nález z kap. 1 alebo 2. Kapitola 14
   delí prácu na jadro a rozšírenia.

---

## 4. Čo má dataset podoprieť

### 4.1 Dve potvrdzujúce tvrdenia

Len tieto dve majú pravidlo rozhodnutia. Každé má tri možné výsledky: **lepší**, **nie lepší**,
**nerozhodnuté**. Znenie záveru pre každý výsledok sa zapíše pred zberom (kap. 8.4).

| | Tvrdenie | Meranie | Dáta |
|---|---|---|---|
| K1 | Sieť predpovedá ďalší riadok lepšie než metódy bez učenia a lineárna metóda | zlepšenie straty modelu voči každej zo základných metód Z3 a Z5, po bootoch | `test_benign` |
| K2 | Sieť zachytí časové a medzipríznakové zásahy, ktoré prahové metódy nezachytia | rozdiel podielu zachytených zásahov tried C a D pri zhodnej miere alarmov, po bootoch; K2a voči prahovým metódam Z1, Z2, Z4, K2b voči Z3 a Z5 | zásahy do odložených session rolí `test_benign` a `test_controls` |

### 4.2 Opisné výsledky

| | Výsledok | Metrika |
|---|---|---|
| O1 | Senzor | podiel prijatých session po príčinách, neskórovaný čas, meškanie cyklu |
| O2 | Falošné alarmy v čistej prevádzke | alarmy za pozorovanú hodinu s presnou jednostrannou hranicou, po kanáloch aj spolu, tabuľka po bootoch a po VM |
| O3 | Falošné alarmy pri benígnych udalostiach | podiel hodnotiteľných výskytov s alarmom po typoch, s hranicou |
| O4 | Kontroly na VM (triedy A a B) | zachytené z plánovaných; výsledok „senzor neskóroval“ zvlášť |
| O5 | Diagnostiky modelu | strom, podiel jedného člena, ablácie kontextu (kap. 8.5) |
| O6 | Klasifikácia činnosti | väčšinový hlas na výskyt, vedľa najčastejšej triedy a náhody |
| O7 | Réžia monitorovania | rozdiel latencie a priepustnosti v behoch A/B/A |
| O8 | Živý beh | zhoda živého detektora s prehratím archívu po riadkoch |

Čistá prevádzka je čas mimo udalostí a mimo dozvuku. Hlavný menovateľ je pozorovaná hodina;
podiel neskórovaného času sa uvádza vedľa. Značky pre O6 dáva `events.json`: okno v udalosti
nesie typ udalosti, okno v dozvuku sa vynecháva, ostatné nesú profil.

Mimo tohto protokolu ostáva presnosť voči reálnym malvérovým vzorkám (zadanie, požiadavka
R15a). Je to samostatná časť vlastníka. Kým nebude zmeraná, platí veta z HONESTY P4.

---

## 5. Laboratórium: služby na VM a prevádzka

### 5.1 Čo je dnes

Jedno API s piatimi cestami (nginx, služby `auth`, `catalog`, `orders`, PostgreSQL), päť
produktov, bez statických súborov, nahrávania, vyhľadávania a relácií. Jediná úloha v pozadí
je slučka `worker`. Šesť scenárov sa líši počtom vlákien generátora, pravdepodobnosťou
dávky a podielmi ciest; tri z nich majú rovnaký mix ciest. Záťaž je stála celú hodinu.

### 5.2 Profily prevádzky

Profil je pomenovaný druh servera. Všetky služby sú nasadené na oboch VM naraz, profil určuje
iba prevádzku, takže VM nie je zviazaná s profilom.

| Profil | Čo pribudne v hosťovi | Prevádzka |
|---|---|---|
| `eshop` (jadro) | katalóg s tisíckami produktov, stránkovanie a vyhľadávanie, košík, objednávka s položkami, statické súbory cez nginx | relácie zákazníkov ako lievik (prezeranie, hľadanie, košík, platba), čas na rozmyslenie s dlhým chvostom |
| `corp` (jadro) | prihlasovanie heslom, nahrávanie a sťahovanie dokumentov, periodická zostava a viacstupňová dávka zo systemd časovača s náhodným oneskorením, skript údržby správcu | vlny prihlásení, práca s dokumentmi, dávky na pozadí |
| `batch` (rozšírenie) | fronta úloh spúšťaných ako podprocesy | málo HTTP, dlhé dávky |
| `idle` (rozšírenie) | nič | sonda dohľadu raz za 30 až 90 s |

Každý profil má dve intenzity (nízku a vysokú), spolu štyri scenáre jadra.

**Dôvod:** kód labu dnes mimo udalostí nevytvára procesy a záťaž je rovná čiara (kap. 2.4).
Viacstupňové dávky v profile `corp` dodávajú benígne deje s časovou štruktúrou.

### 5.3 Príchody a priebeh záťaže

- Otvorená slučka: relácie prichádzajú podľa seedovanej obálky intenzity (nábehy, skrátený
  denný cyklus, krátka špička). Súbežnosť má strop; požiadavka nad stropom sa zahodí
  a zapíše.
- Log nesie ponúkanú aj doručenú záťaž. Kontrola auditu porovnáva **ponúkanú** záťaž mimo
  okien udalostí s plánom (±20 %). Doručená záťaž počas udalostí sa iba vykazuje, aby
  zamietnutie nezáviselo od typu udalosti.
- 1 až 3 % chýb klienta (404, 401, 400).

### 5.4 Stav hosťa

- Každá skupina štartuje z definovaného stavu: nový proces QEMU a databáza obnovená na
  seedovanú úroveň. Pred prvou session prebehne zaznamenaný krok, ktorý sa dotkne rovnakého
  množstva pamäte ako najväčšia udalosť.
- Na začiatku každej session sa zapíšu hodnoty úrovňových príznakov.

### 5.5 Benígne prevádzkové udalosti

- Päť typov a udalosť naprázdno (rozhodnutie D8). Menej typov znamená viac výskytov na typ
  pri rovnakom počte hodín.
- Každý typ má **predikát účinku** overený z hosťa (zámok viditeľný v `pg_locks` a chyby 503,
  vyšší `NRestarts`, veľkosť procesu záťaže, súbor zálohy). Udalosť bez účinku session zamieta.
- **Udalosť naprázdno:** prebehne iba spúšťač cez agenta hosťa. Je to negatívna kontrola
  stopy spúšťača.
- Session má buď žiadnu udalosť, alebo tri. Typy sa rozdávajú z balíčka tak, aby mal každý
  typ v role rovnaký počet výskytov (rozdiel najviac 1).
- Začiatok a trvanie sa losujú spojito; fáza každého štartu a stopu voči najbližšej snímke
  sa zapíše.
- Žiadna udalosť ani kontrola nezačne medzi 60 s pred plnou snímkou a prvým skórovaným
  riadkom po nej. Plán to overí pri načítaní.
- Každý účel má vlastný prúd náhody: hash z názvu protokolu, skupiny, session, pokusu
  a účelu.

### 5.6 Periodické deje

- Každá slučka, ktorá vytvára procesy, je ohraničená (`StartLimitBurst`) alebo má náhodné
  oneskorenie, bez ohľadu na pomer k intervalu zberu. Známa slučka s periódou asi 3,25 s by
  testom malých celočíselných pomerov prešla.
- Register periodických dejov v hosťovi aj na hostiteľovi so zdrojovým riadkom je súčasť
  protokolu; skutočné periódy sa zmerajú v G2 zo žurnálu hosťa.
- Hlavnou kontrolou je **autokorelácia označených riadkov** v každej session: opakujúci sa
  rozstup session označí a kampaň pozastaví.
- Mriežka zberu ostáva pevná (rozhodnutie D11). Zberač má nepoužitú voľbu rozfázovania
  (`vmicollect/src/config.c:139-144`), tá by však zmenila dĺžku intervalu a s ňou príznaky
  počítané ako zmena za interval.

### 5.7 Realizmus prevádzky

Zhodu s prevádzkou konkrétnej firmy overiť nevieme, žiadnu stopu nemáme. Kritériom je zhoda
s vlastnosťami webovej prevádzky opísanými v literatúre (príloha C). Počíta sa z logov
generátora, nginx a hosťa pre každý profil a intenzitu v stupni G2 a potom pri každej session.

| Vlastnosť | Požiadavka | Opora |
|---|---|---|
| príchody relácií | otvorená slučka; v úseku so stálou intenzitou má rozstup príchodov variačný koeficient 0,8 až 1,2 | modely SURGE a TPC-W |
| čas na rozmyslenie (`eshop`) | priemer 7 s, najviac 70 s, dlhý chvost | TPC-W |
| pomer prezerania a objednávania (`eshop`) | nízka intenzita 95 : 5, vysoká 80 : 20 | mixy TPC-W |
| sústredenie odkazov | desatina najžiadanejších objektov dostane aspoň polovicu požiadaviek | invarianty webových serverov; hranica je návrh autora |
| úspešnosť | podiel úspešných odpovedí aspoň 88 % a menej než 100 % mimo udalostí | invarianty webových serverov; dnešný lab má nulu chýb |
| veľkosti odpovedí | rozsah cez aspoň dva rády | SURGE |
| premenlivosť | pomer špičky k priemeru intenzity v session aspoň 2 | návrh autora |
| činnosť na pozadí (`corp`) | periodické úlohy s náhodným oneskorením, vlny prihlásení, dokumenty s dlhým chvostom veľkostí | návrh autora bez priameho zdroja |

Session, ktorá požiadavky neplní, sa zamietne ako session s nesprávnou záťažou. Čo sa takto
overiť nedá: zloženie prevádzky skutočného podniku, obsah požiadaviek a správanie skutočných
používateľov. Práca to uvedie ako obmedzenie. Presné parametre zdrojov sa overia pri písaní
práce; tu slúžia ako opora návrhu.

---

## 6. Zber a prijatie session

### 6.1 Čo ostáva

Perióda 5 s, okno 32 riadkov, 720 cyklov na session, plná snímka každých 360 cyklov, dve VM,
audit a archivácia po jednej, zmrazený commit a hash protokolu.

### 6.2 Nové kontroly auditu

| Kontrola | Hranica | Dôvod (kap. 2.3) |
|---|---|---|
| swap procesu QEMU je nula v každej vzorke; `memory.swap.max` skupiny QEMU je 0 už pred štartom a zapíše sa | z mechanizmu | zmeškané sloty v4 a v4c |
| meškanie začiatku cyklu | najviac 0,5 s (desatina intervalu) | meškanie dnes nikto nekontroluje |
| čas cyklu | delta najviac 1,5 s, plná snímka najviac 3,5 s | rezerva pre dve VM je nezmeraná |
| varovanie zberača mimo zoznamu povolených vzorov zamieta | zoznam z G2 | varovania sa dnes iba ukladajú |
| doména a PID v každom sidecari sa zhodujú so session | presná zhoda | chýbajúca väzba na VM |
| každá plánovaná udalosť prebehla a má účinok | predikát | udalosť bez účinku sa dnes prijme |
| nasadené súbory v hosťovi sa zhodujú s `lab/` v commite | presná zhoda | zastaraný hosť prejde pilotom |
| počet riadkov uzavretých pravidlom | vzorec, kap. 10.9 | sedem riadkov presne po piatich snímkach prešlo bez povšimnutia |
| periodicita označených riadkov | opakovaný rozstup | to isté |
| každý auditovaný kľúč je povinný | bez predvolených hodnôt | tiché predvolené hodnoty |

Hranice z mechanizmu sa určia v G0. Stupne G2 a G3 overia iba to, či ich systém plní; keď
nie, opravuje sa systém, nie hranica. Do kvality riadku pribudne výsledok prechodu zoznamu
procesov v oboch smeroch a počty preskočených úloh; pri každej session sa zapíše posun
mriežok oboch zberačov.

Každá kontrola má test, ktorý ju spustí na zlej session a dostane presne očakávaný dôvod
(samotest kontrol). Bez platného záznamu samotestu pre aktuálny kód sa zber nespustí.

### 6.3 Pravidlo prijatia

Jedna funkcia prijatia, ktorú volá načítanie protokolu, audit, stavba korpusu aj tréning.
Test prejde hraničné session (0 až maximum plus jeden neplatný riadok, osamotené aj zhluknuté)
a overí, že všetky miesta rozhodnú rovnako. Doterajší pilot s 600 cyklami a `pilot_gate`
nahrádzajú generálky s plnou dĺžkou session; krátke session stupňa G2 majú rolu `pilot`
a žiadne pravidlo tolerancie.

Tolerované neplatné riadky ostávajú (rozhodnutie D4). Ich počet určí vzorec v kap. 10.9;
jeden osamotený riadok vyradí 33 okien, tri nechajú 557 zo 720.

### 6.4 Neskórovaný čas

- Pre každú session, každý typ udalosti a každú kontrolu sa vykazuje neskórovaný čas.
- Výskyt je **hodnotiteľný**, keď je skórovaná aspoň polovica jeho prvých 60 s.
- Pri falošných alarmoch (O3) vypadne nehodnotiteľný výskyt z menovateľa a uvedie sa zvlášť.
- Pri citlivosti (O4, K2) je menovateľom **počet plánovaných** výskytov. Výskyt, pri ktorom
  senzor neskóroval, je vlastný výsledok „nezachytené, senzor neskóroval“, nie úspech.
- Typ alebo trieda s menej než 8 hodnotiteľnými výskytmi sa označí „nevyhodnotené“.
- Citlivostná analýza: hlavné výsledky ešte raz s riadkami uzavretými pravidlom počítanými
  ako neplatné.

---

## 7. Dizajn dát

### 7.1 Jednotky

VM, skupina bootu, session, okno. Nezávislou jednotkou je skupina bootu; VM je druhá úroveň
a výsledky sa uvádzajú aj po VM. Okná sa prekrývajú 31 z 32 riadkov a nikdy sa neberú ako
nezávislé vzorky.

### 7.2 Roly a rozvrh

Skupina má 3 session, aby pri rovnakom počte hodín vzniklo dvakrát toľko bootov. Veľkosti sú
určené teraz z kap. 9.2, nie z generálky.

| Rola | Skupiny | Session | Bez udalostí | Výskyty na typ |
|---|---|---|---|---|
| `train` | 12 | 36 | 12 | 12 |
| `dev` | 4 | 12 | 4 | 4 |
| `calibration` | 8 | 24 | 8 | 8 |
| `test_benign` | 12 | 36 | 12 | 12 |
| `test_controls` | 8 | 24 | — | 7 kontrol a 7 párových negatívnych na druh |
| spolu | 44 | 132 | | |

Odhad času: 132 pokusov je asi 5,9 dňa, s 12 náhradami 6,5 dňa. Základ je 58,5 h na 54
pokusov kampane v4c podľa `docs/STAV.sk.md`, nie záznam.

Samostatný dataset udalostí pre klasifikátor odpadá: udalosti sú vo všetkých rolách a značky
dáva `events.json` (rozhodnutie D9).

### 7.3 Poradie, vyváženie, seedy

- Roly ostávajú v časovom poradí `train`, `dev`, `calibration`, potom testovacie. Booty rolí
  `test_benign` a `test_controls` sa v čase striedajú, aby obe ležali v rovnakom režime.
- Štyri scenáre v skupinách po troch tvoria vyvážený neúplný blokový rozvrh: v každých
  štyroch skupinách je každý scenár trikrát, raz na každej pozícii. Počty skupín všetkých rolí
  sú násobkom štyroch. V rámci jednej VM platí vyváženie s rozdielom najviac 1.
- Samokontrola protokolu rozvrh overí a pri porušení vyváženia alebo minimálnych počtov na
  typ protokol nenačíta.
- Seedy sú nové. Rozvrh v4 sa pri rozbore porúch prezeral.
- Náhrada zachová priradenie (VM, rola, skupina, scenár, typy udalostí); fázy a trvania si
  vylosuje z prúdu s číslom pokusu.

### 7.4 Pozitívna strana

**Zásahy do príznakov (triedy C a D, potvrdzujúce).** Úprava príznakov odloženej benígnej
session, ktorá zachováva rozdelenie každého stĺpca:

| Trieda | Zásah | Čo ruší |
|---|---|---|
| C iba časová | blok riadkov v obrátenom alebo náhodnom poradí | poradie v čase |
| D iba medzipríznaková | skupina stĺpcov v bloku nahradená tým istým úsekom inej session rovnakého scenára a pozície | vzťah medzi skupinami stĺpcov |

Dĺžky bloku 6, 12, 24 a 48 riadkov; najkratšia je zámerne pod rozlíšením pravidla 3 z 5
a očakáva sa, že zachytená nebude. Šesť zásahov každej triedy na boot v 20 odložených bootoch.
Každý zásah prejde **predikátom platnosti** počítaným iba z príznakov: každý stĺpec, jeho
prvá diferencia a kĺzavý priemer ležia v kvantiloch roly `train`. Zásah, ktorý neprejde, sa
preradí do objemovej triedy, nevyhadzuje sa.

Tieto zásahy merajú, či model využíva štruktúru. Nie sú modelom útoku.

**Kontroly na VM (triedy A a B, opisné).**

| Trieda | Druhy | Čo má ukázať |
|---|---|---|
| A okrajová | proces so stránkou W+X a memfd (existuje), načítanie neškodného modulu jadra, nový počúvajúci soket | zachytí ju aj pravidlo na jednej premennej |
| B objemová | zapisovač pamäte známej veľkosti a entropie, dávka krátkych procesov | odozva na dávku |

Každá kontrola má **párovú negatívnu kontrolu** (rovnaký strom procesov a veľkosť pamäte bez
anomálnej vlastnosti), trvanie aspoň 60 s, horizont 180 s od začiatku a tri zapísané výsledky:
parser ju videl, stĺpec sa pohol o očakávanú hodnotu, kanál zareagoval. Pred každým výskytom
musí platiť predikát návratu do východiskového stavu. Poradie je náhodné.

**Zoznam, veľkosti a trvania zásahov aj kontrol sa zmrazia v G0**, pred akýmkoľvek zberom,
vrátane dávok, pri ktorých sa nezachytenie očakáva.

### 7.5 Limit náhrad a zastavenie

- Limit je najmenšie číslo, pri ktorom je predpovedná pravdepodobnosť dokončenia plánu
  aspoň 0,95. Predpoveď berie mieru zamietnutí z potvrdzujúcej generálky (Jeffreysovo
  apriórne rozdelenie) a session generálky sa pred tým znova posúdia podľa konečných hraníc.
- Orientačne pre 132 session a generálku s 30 pokusmi (výpočet): žiadne zamietnutie dá limit
  9, jedno 20, dve 29, tri 38.
- Keby vyšiel limit nad tretinu plánu (44), generálka sa raz predĺži o ďalších 30 pokusov
  a počíta sa zo všetkých. Ak nestačí ani to, protokol nie je pripravený.
- Vyčerpaný limit kampaň **pozastaví na rozbor**. Jedno pokračovanie s tým istým limitom je
  dovolené, ak je príčina mimo meracieho kódu a labu; inak je kampaň neplatná.
- Skoré zastavenie: počet označených riadkov pri niektorom type udalosti nad hranicou
  z kap. 10.9, alebo periodicita označených riadkov.

---

## 8. Model: je to viac než if-else?

### 8.1 Kvalifikácia príznakov

Počíta sa na prieskumnej generálke, pred tréningom, iba z príznakov (nikdy zo skóre).
Hranice sú zapísané v G0.

| Kontrola | Pravidlo | Náprava |
|---|---|---|
| rozptyl | konštantný: nulový rozptyl; takmer konštantný: menej než 1 % riadkov mimo modu | pravidlový kanál |
| totožnosť | jednoduchý model z jedného riadku nesmie v rámci profilu a pozície uhádnuť skupinu, VM ani poradie session nad AUC 0,75 na `train` a `dev` | úrovňový stĺpec sa nahradí prvou diferenciou; iný stĺpec vypadne |
| duplicity | presná lineárna kombinácia iných stĺpcov | vypadne |
| záťaž | R² regresie stĺpca na ponúkanej záťaži toho istého intervalu | iba sa vykazuje |
| odozva | stĺpec reaguje na svoju kontrolu očakávanou veľkosťou | iba sa vykazuje |

Maska stĺpcov a pravidlo mierky sú **dáta protokolu**: zmrazený tréning ich použije na
štatistiky roly `train` kampane a zapíše do manifestu. Kontroly sa na dátach kampane zopakujú
a rozdiel oproti generálke sa vykáže.

### 8.2 Kanály skóre (rozhodnutie D3)

Pre počty objektov jadra neexistuje prirodzená mierka: buď je jedna jednotka nad prahom
(kap. 2.1), alebo je po zavedení dolnej hranice mierky takmer neviditeľná.

| Kanál | Vstupy | Povaha |
|---|---|---|
| kontroly integrity | existujú, nie sú vstupom modelu | pravidlá |
| pravidlový | stĺpce triedy konštantný a takmer konštantný | deklarované pravidlá s rozsahom z `train` a `calibration`; nikdy sa neuvádzajú ako neurónová detekcia |
| neurónový | ostatné stĺpce a biny | TCN |

- Výsledky O2 a O4 sa uvádzajú po kanáloch aj za ich zjednotenie; navyše prírastok citlivosti
  neurónového kanála nad pravidlovým.
- Vnútri neurónového kanála ostáva dolná hranica mierky (jedna jednotka pri počtoch), aby
  stĺpec tesne nad hranicou „takmer konštantný“ nedostal obrovskú váhu.
- Biny: do skóre vstupuje iba bin s aspoň 1024 stránkami; mierka sa počíta na bin; vedľa
  maxima sa ako citlivostná analýza uvedie priemer troch najhorších binov a prah na
  `mem_changed_max`.
- Vopred zapísané znenie pre prípad, že všetku detekciu nesie pravidlový kanál.
- Hlava klasifikátora sa oddelí od tréningu prediktora (dnes majú spoločné orezanie
  gradientu).

Alternatíva je jedno skóre s dolnou hranicou mierky: menej práce, odpoveď na otázku if-else
ostane zmiešaná.

### 8.3 Základné metódy

Všetky dostanú tie isté okná, ten istý normalizér a to isté pravidlo 3 z 5. **Zhodná miera
alarmov** znamená: prah každej metódy sa nastaví tak, aby mala na čistej prevádzke roly
`calibration` rovnaký počet alarmov za pozorovanú hodinu ako model. Skutočná miera na
`test_benign` sa uvedie pri každej.

| | Metóda | Prečo tam je |
|---|---|---|
| Z0 | nikdy nealarmuje; náhodné alarmy v zhodnej miere | dno |
| Z1 | prah na každý stĺpec zvlášť: hodnota, prvá diferencia, kĺzavý priemer, CUSUM; aj prah na `mem_changed_max` | doslovný if-else |
| Z2 | „niektorý počet sa líši od svojho modu“ | pravidlo, na ktoré sa dnešné skóre môže redukovať |
| Z3 | predpoveď poslednou hodnotou, priemerom okna, EWMA (bez parametrov) | čo dá čas bez učenia |
| Z4 | prah na ponúkanej záťaži; regresia príznakov na záťaži | či model nie je merač záťaže |
| Z5 | lineárna autoregresia (ridge) na tom istom okne | lineárna štruktúra |
| M | TCN, päť seedov | skúmaný model |

Rozšírenia: PCA, izolačný les, malá sieť bez času, GRU v tom istom obale.

Každá metóda s voľnými parametrami má vopred zapísanú mriežku a jeden postup výberu na
`dev`. Keď je vybraná epocha posledná, tréning sa raz zopakuje s dvojnásobným stropom.

### 8.4 Potvrdzujúce testy K1 a K2

**Štatistika.** K1: zlepšenie I = 1 − strata(M) / strata(Z), na boot. K2: rozdiel D podielu
zachytených zásahov M a Z, na boot. Model vstupuje mediánom cez päť seedov; všetky seedy sa
uvedú. Interval je 95 % z hodnôt po bootoch, test je permutačný so zámenou znamienka.

**Hranica z nulového prípadu.** V stupni G1 sa celá reťaz spustí na aspoň 20 seedoch
generátora bez časovej a medzipríznakovej štruktúry. Hranica m je 95. percentil I (resp. D)
na týchto dátach. Dôvod: pri skúške na dátach bez štruktúry vyšla TCN o 11 % lepšie než
priemer okna; pevná hranica 10 % by teda prešla, hoci sa nebolo čo naučiť.

| Výsledok | Podmienka | Znenie záveru |
|---|---|---|
| lepší | dolná hranica intervalu nad m, voči každej porovnávanej metóde | „neurónový kanál využíva naučenú štruktúru; rozdiel oproti … je …“ |
| nie lepší | horná hranica intervalu pod m pri niektorej metóde | „na týchto dátach je neurónový kanál rovnocenný s metódou …“ |
| nerozhodnuté | inak | „dáta nestačia na rozhodnutie; interval je …“ |

K2 sa rozhoduje zvlášť voči prahovým metódam (K2a) a voči metódam s časom bez učenia (K2b).
Výsledok sa uvádza tak, ako vyjde, v tabuľke aj v závere (HONESTY P8). Predchádzajúci projekt
bol stiahnutý pre zámenu značiek session; to, že základná metóda dorovnala model, bolo
prehliadnutým varovaním (HONESTY, kap. 2).

### 8.5 Diagnostiky a ablácie (opisné)

- **Kontext:** model pretrénovaný s kontextom skráteným na 1, 2, 4, 8, 16 a 31 riadkov;
  premiešanie kontextu, ktoré ponechá posledný riadok. Tá istá úprava sa urobí aj metódam
  Z3 a Z5.
- **Strom:** rozhodovací strom hĺbky najviac 3 nad surovými stĺpcami posledného riadku, ich
  diferenciami a maximom binovej zmeny má reprodukovať prekročenia prahu. Učí sa a meria
  krížovo po bootoch.
- **Podiel jedného člena:** podiel okien nad prahom, v ktorých jeden stĺpec alebo bin sám
  prekročí prah.
- Obe diagnostiky sa počítajú aj pre Z1 až Z3. Tam musia vyjsť ako „prahové“; ak nevyjdú,
  diagnostika sa nepoužije. Pri menej než 20 kladných epizódach je výsledok „nevyhodnotené“.
- Ďalej: sieť s náhodnými váhami, iba globálna a iba binová časť, krivka učenia podľa počtu
  skupín, citlivosť na pravidlo k z n (2 z 3, 3 z 5, 4 z 7), rozsah prahu pri vynechaní
  jedného bootu kalibrácie, podiel prekročení po oknách.

### 8.6 Čo sa pri každom tréningu ukladá

Tabuľka citlivosti (aká zmena jedného stĺpca sama prekročí prah), triedy stĺpcov, strata voči
Z3 a Z5, krivky učenia, súhrn skóre po kontexte (udalosť, dozvuk, čistá prevádzka) a po
scenári. Návrh: `Bundle.score` bude vracať chybu po stĺpcoch a chyby najhoršieho binu, aby sa
každý alarm dal pripísať (dnes vracia jednu globálnu chybu a chyby po binoch).

### 8.7 Udalosti v normále

Prah zo všetkých okien `calibration` je hlavný. Vedľa neho sa uvádza prah iba z čistej
prevádzky a citlivosť pri oboch. Porovnanie s predchádzajúcou iteráciou je iba opisné.
Rozšírenie: druhý balík z toho istého korpusu, v ktorom sú okná udalostí a dozvuku vynechané
z učenia, normalizácie aj kalibrácie, izoluje vplyv tréningu s udalosťami.

---

## 9. Štatistika

### 9.1 Pravidlá

- Každé hlavné číslo má tabuľku po bootoch, po VM a po profile.
- Počty alarmov: presná Poissonova hranica nad súčtom, vedľa nej tabuľka po bootoch. Pri
  nulových počtoch sa bootstrap nepoužíva.
- Rozdiely metód (K1, K2): hodnoty po bootoch, permutačný test, interval.
- Žiadne p-hodnoty nad oknami.
- Potvrdzujúce sú iba K1 a K2. Všetko ostatné sa zapisuje pod kľúč „opisné“.
- Pri udalostiach je metrikou podiel hodnotiteľných výskytov s alarmom, nie miera za hodinu:
  odozva bola pri každom type takmer deterministická.

### 9.2 Čo unesie daná veľkosť

Jednostranná 95 % horná hranica falošných alarmov za pozorovanú hodinu čistej prevádzky
(výpočet, Poissonov model; session s tromi udalosťami má asi 55 % čistého času):

| `test_benign` | Čisté hodiny | 0 alarmov | 1 alarm | 2 alarmy |
|---|---|---|---|---|
| 24 session, 8 bez udalostí | 16,8 | 0,18 | 0,28 | 0,37 |
| 36 session, 12 bez udalostí (návrh) | 25,2 | 0,12 | 0,19 | 0,25 |
| 48 session, 16 bez udalostí | 33,6 | 0,09 | 0,14 | 0,19 |

Pri mierach z predchádzajúcej iterácie (0,047 až 0,091 za hodinu) treba v 25 hodinách čakať
jeden až dva alarmy; pravdepodobnosť najviac jedného je 0,67 až 0,33. Falošné alarmy sa preto
uvádzajú ako odhad s hranicou, nie ako splnené alebo nesplnené. Tvrdenie „najviac jeden
falošný alarm za deň“ by potrebovalo asi 72 čistých hodín bez alarmu.

Pri type udalosti s 12 hodnotiteľnými výskytmi a žiadnym alarmom je horná hranica
pravdepodobnosti alarmu 0,22. Znamienkový test cez 4 booty nemôže dať p pod 0,125, cez
8 bootov 0,008.

---

## 10. Stupne pripravenosti

Každý stupeň má záznam v `data/results/` s commitom a hashom protokolu. Ďalší stupeň sa bez
platného záznamu predchádzajúceho nespustí.

### 10.1 G0 Kód (bez VM)

- Opraviť odovzdanie korpusu tréningu (predpona skupín, tolerované riadky v tréningu,
  v základných metódach, v návratovom kóde prehratia a v poznámke vyhodnotenia).
- Jedna funkcia prijatia, samotest kontrol, nové kontroly auditu (kap. 6).
- Plán analýzy v hashovanom protokole: architektúra, pravidlo zastavenia, seedy 0 až 4,
  `fpr`, `k`, `n`, zoznam metód s mriežkami, K1 a K2, zoznam zásahov a kontrol, horizont,
  dozvuk, definícia hodnotiteľného výskytu. Tréning ich číta z protokolu a mimo
  diagnostického režimu odmieta prepísanie z príkazového riadka.
- Zapečatenie testu: kniha v gite viazaná na zoradené hashe príznakov testovacích session;
  prehratie odmietne archív zapečatenej roly; jeden finálny príkaz pre vopred zapísaný zoznam
  modelov.
- Profily, otvorená slučka, predikáty účinku, udalosť naprázdno, register periód, nezávislé
  prúdy náhody, rozvrh a jeho samokontrola.
- Súhrn každého stĺpca v každom audite; chyby po stĺpcoch pri každom skóre.
- Zhoda živej a archívnej cesty extrakcie.
- Povinný záznam kampane pri uzavretí.
- Testy, ktoré zopakujú skúšky z auditu (odovzdanie korpusu, meškanie, obídenie značky).

**Kritérium:** testy prejdú; samokontrola protokolu prejde; záznam samotestu kontrol.

### 10.2 G1 Suchý beh so známymi odpoveďami (bez VM, bez roota)

Jeden príkaz prejde skutočný súbor protokolu od plánu po správu: syntetické session
(predpony skupín, dve VM, udalosti, tolerované neplatné riadky), audit, korpus, ostrá
kontrola indexu, tréning M a všetkých metód, kalibrácia, zapečatené finálne vyhodnotenie,
správa, kontrola tvrdení.

| Známa odpoveď | Musí vyjsť |
|---|---|
| generátor **bez štruktúry**, aspoň 20 seedov | K1 aj K2 vyjdú „nie lepší“ alebo „nerozhodnuté“ najviac s jednou výnimkou z 20; z týchto behov sa určia hranice m |
| generátor **so štruktúrou** (periodická a autoregresná dynamika, väzby medzi stĺpcami) | K1 a K2 vyjdú „lepší“; model s premiešaným kontextom a sieť s náhodnými váhami nie |
| diagnostiky na metódach Z1 až Z3 | strom aj podiel jedného člena ich označia za prahové |
| vložená okrajová zmena | zachytí ju Z1 aj M |
| vložené neskórované úseky | vo výstupe sú ako nevyhodnotené, nie ako ticho |
| vložené chyby: boot v dvoch rolách, chýbajúci `events.json`, o jeden neplatný riadok viac, zmeškaný slot, cudzia identita VM, druhé finálne vyhodnotenie, prehratie zapečatenej roly, neprebehnutá udalosť, zastaraný hash hosťa | každá odmietnutá s očakávaným dôvodom |

**Kritérium:** všetky riadky tabuľky. Suchý beh dokazuje logiku reťaze, nie vedu ani senzor.
Generátor navrhuje ten istý autor ako model; preto je rozhodujúci jeho záporný riadok, nie
kladný.

### 10.3 G2 Skúška na VM (so sudo; dáta sa nikdy nestanú datasetom)

- Zhoda nasadeného kódu s repozitárom na oboch VM.
- Každý typ udalosti aspoň 19-krát (porucha s výskytom 15 % sa tak s pravdepodobnosťou 95 %
  ukáže aspoň raz): predikát účinku, perióda reštartov, označené riadky, fázy rozložené cez
  cyklus zberu.
- Každý profil a intenzita: požiadavky na realizmus prevádzky z kap. 5.7, ponúkaná a doručená
  záťaž, návrat do definovaného stavu.
- Pozemná pravda pod záťažou: `ps`, `lsmod`, `ss` v hosťovi proti parseru; krížová kontrola
  binových hodnôt na vybraných snímkach.
- Každá kontrola s párovou negatívnou, tri výsledky na kontrolu.
- Vyvolané poruchy na skutočnom systéme: zabitý zberač, zdržaný procesor, tlak na pamäť,
  reštart VM počas session, zastavený generátor, zabitá služba hosťa mimo udalosti. Každá
  musí skončiť hlasným zamietnutím.
- Najhorší prípad času: záťaž pamäte cez plnú snímku, kým sa session druhej VM audituje
  a archivuje; oba režimy vzájomného posunu zberačov.
- Zhoda živého detektora (`safeguard watch` popri zbere) s prehratím archívu.

**Kritérium:** každý bod splnený a hranice z kap. 6.2 dodržané.

### 10.4 G3a Prieskumná generálka (nikdy v datasete)

Malá kampaň na oboch VM so skutočnou automatikou, pod vlastným názvom protokolu a so
skutočnými názvami rolí: 10 skupín po 3 session (každá rola na každej VM), asi 1,4 dňa.
Smie sa opakovať; každé opakovanie a každá zmena sa zapíše. Na nej sa ladí všetko, čo sa
ladiť smie: lab, kontroly auditu, maska stĺpcov podľa pravidiel z kap. 8.1, mriežky metód.
Hranice K1 a K2, zoznam zásahov a kontrol, horizont a definície sa neladia; sú zmrazené
od G1.

### 10.5 G3b Potvrdzujúca generálka (nikdy v datasete)

Jedna, na commite, ktorý kandiduje na zmrazenie, bez zásahu do kódu. Rovnaký tvar ako G3a.

- Prejde celú reťaz vrátane K1 a K2. Výsledky sú označené ako generálka.
- Dodá mieru zamietnutí pre limit náhrad a hodnoty pre vzorce z kap. 10.9.
- **Kritérium:** limit náhrad v medziach kap. 7.5; žiadna nevysvetlená periodicita; reťaz
  prešla bez zásahu; rozhodnutie vlastníka. Zmena kódu po G3b znamená novú G3b.

### 10.6 G4 Zmrazenie a predregistrácia

Tag, hash protokolu vrátane plánu analýzy, dokument predregistrácie, odoslanie do
vzdialeného repozitára ako časová pečiatka, otvorený denník odchýlok.

### 10.7 G5 Kampaň

Počas zberu sa sledujú iba kontroly kvality. Skóre modelu na zapečatených rolách nikto
nevidí. Platia pravidlá zastavenia z kap. 7.5.

### 10.8 G6 Jedno vyhodnotenie

Jeden príkaz vyhodnotí všetky vopred zapísané modely a metódy na tých istých prehratiach
a zapíše jednu knihu. Správa obsahuje tabuľky po bootoch a VM, neskórovaný čas, zamietnuté
a nahradené session po príčinách, odchýlky a zapísané znenia záverov.

### 10.9 Čo sa kedy určí

| Hodnota | Kedy | Pravidlo |
|---|---|---|
| hranice kontrol auditu (meškanie, čas cyklu, záťaž) | G0 | z mechanizmu, kap. 6.2 |
| triedy stĺpcov, AUC totožnosti, minimálny bin | G0 | kap. 8.1, 8.2 |
| zoznam a veľkosti zásahov a kontrol, horizont 180 s, dozvuk 300 s, hodnotiteľný výskyt | G0 | kap. 6.4, 7.4 |
| veľkosti rolí a rozvrh | G0 | kap. 7.2, 9.2 |
| `fpr` 0,01 a pravidlo 3 z 5 | G0 | prevzaté; citlivosť na pravidlo sa vykáže (kap. 8.5) |
| hranice m pre K1 a K2 | G1 | 95. percentil na dátach bez štruktúry, aspoň 20 seedov |
| mriežky metód, maska stĺpcov | G3a | podľa pravidiel zapísaných v G0 |
| očakávané počty v registri výnimiek | G3a | najväčší počet na prijatú session posledného behu G3a; G3b ich porovná s pozorovanými (vedúci 2026-11-22, odpoveď na otázku Q2) |
| limit náhrad | G3b | kap. 7.5 |
| tolerancia neplatných riadkov na session | G2 | najmenšie číslo, pri ktorom je podľa miery na hranicu udalosti z G2 pravdepodobnosť prekročenia v jednej session pod 1 %; najviac 6 |
| strop riadkov uzavretých pravidlom na session; hranica skorého zastavenia | G3b | 99. percentil Poissonovho rozdelenia pri miere z G2 a G3b spolu, na typ udalosti |
| zoznam povolených varovaní zberača | G2 | všetky vzory pozorované pri bezchybných behoch |

Čísla v riadkoch G0 sú návrh autora podľa úsudku. Sú zapísané pred akýmikoľvek dátami
a vlastník ich môže zmeniť iba pred G1.

---

## 11. Výskumná disciplína

1. **Stupeň v každom zázname** (`suchy`, `skuska`, `generalka`, `final`). Kontrola tvrdení
   pustí do textu práce iba čísla zo záznamov `final`.
2. **Predregistrácia** pred prvou session kampane.
3. **Denník odchýlok** a denník opakovaní prieskumnej generálky (iba pridávanie).
4. **Register výnimiek** v protokole: každá tolerovaná podmienka má príčinu, rozhodnutie
   a očakávaný počet. Audit tlačí pozorované počty vedľa očakávaných; test zlyhá na
   neregistrovanej výnimke v kóde auditu.
5. **Príčina pred toleranciou.**
6. **Záznam pred mazaním:** uzavretie kampane zapíše záznam do `data/results/` a položku do
   `docs/MERANIA.md`. Bez toho sa surové dáta nemažú.
7. **Uchovanie:** finálny dataset, generálky a ich záznamy ostávajú do obhajoby s jednou
   overenou kópiou (rozhodnutie D12).
8. **Disciplína hostiteľa:** počas zberu žiadny agent so shellom na zberovom PC; záťaž
   hostiteľa sa zapisuje.
9. **Nezávislé čítanie pred G4:** druhý čitateľ dostane iba protokol a kód.

---

## 12. Rozhodnutia

Vlastník 2026-11-21 poveril autora návrhu, aby otvorené otázky rozhodol podľa dôkazov alebo
dedukcie z faktov. Každé rozhodnutie má podklad a podmienku, ktorá by ho zmenila. Vlastník
môže ktorékoľvek zmeniť do začiatku stupňa G1.

| # | Rozhodnutie | Podklad | Čo by ho zmenilo |
|---|---|---|---|
| D1 | Stupne G0 až G6 sú podmienkou zberu. | Z príčin v kap. 1 sa päť dalo zistiť bez zberu a audit našiel ďalšiu, ktorá by zastavila aj úplnú kampaň v4 v poslednom kroku (kap. 2.6). Predchádzajúci projekt bol stiahnutý (HONESTY, kap. 2), takže neplatný výsledok stojí viac než príprava. | nič z doterajších dôkazov |
| D2 | Profily `eshop` a `corp`, každý v nízkej a vysokej intenzite. `batch` a `idle` sa v tejto iterácii nerobia. | Zadanie žiada „použiteľnosť v reálnych scenároch“ a vlastník menoval e-shop a firemný server. Štyri scenáre v skupinách po troch dávajú vyvážený rozvrh (kap. 7.3) a 33 session na scenár; pri ôsmich scenároch by to bolo 16 a rozvrh by nesedel s počtami skupín. Dávky sú súčasťou `corp`, pokoj pokrýva nízka intenzita. | ak by generálka ukázala, že nízka intenzita nedáva úseky bez požiadaviek |
| D3 | Dva kanály skóre: pravidlový a neurónový. | Výpočet zo záznamu v6: pri mierke zo smerodajnej odchýlky pridá jedna jednotka v `sock_listen` asi 90 pri prahu 14,43; pri dolnej hranici mierky jedna jednotka pridá 0,025, teda 0,2 % prahu. Medzi „jednotka rozhodne“ a „jednotku nevidno“ niet prirodzenej strednej voľby, takže reakcia na jednotkovú zmenu počtu je pravidlo. Zodpovedá to aj zadaniu: moduly, spojenia a podozrivé vzorce sú počty, „štatistické charakteristiky pamäťových oblastí“ a sekvenčné vektory sú vstup TCN. | ak by v generálke žiadny stĺpec nebol takmer konštantný |
| D4 | Tolerované neplatné riadky ostávajú. Ich počet určí vzorec v G2 (kap. 10.9), najviac šesť. Tréning aj základné metódy ich musia prijať. | Vo v4c štyri z 13 neplatných riadkov nesúviseli s reštartmi `worker`; bez tolerancie by to boli štyri zamietnuté session z 54. Dedukcia: losovanie začiatkov udalostí cez celú fázu zberu zvýši podiel začiatkov, ktoré padnú do čítania pamäte (čítanie trvá asi 0,85 s z 5 s; doteraz začiatky ležali v jednej fáze mimo neho). Bez tolerancie by teda miera zamietnutí rástla práve pre opatrenie, ktoré má odstrániť fázovú väzbu. | ak G2 nameria, že udalosti zoznam procesov netrhajú |
| D5 | Dve potvrdzujúce tvrdenia K1 a K2, ostatné opisne. | Päť hypotéz v konjunkcii má silu súčinu síl; pri ôsmich bootoch vyšla recenzentovi sila jednej z nich 0,44 až 0,64. Nulový príklad (11 % „zlepšenie“ bez štruktúry) ukazuje, že pevné hranice by vyhlásili úspech neprávom. | nič |
| D6 | 132 session, skupiny po troch, veľkosti podľa kap. 7.2. | Tabuľka 9.2: 36 testovacích session dá hranicu 0,19 za hodinu pri najviac jednom alarme, 24 iba 0,28. Aspoň osem bootov na testovaciu rolu umožní test po bootoch. Celkový zber sa nezvyšuje: plán v4 mal dve kampane po 96 session, v5 má 132 a dve generálky po 30. | prísnejší cieľ pre falošné alarmy (48 session), alebo časový strop |
| D7 | Rola `test_controls` a zásahy do príznakov sú súčasťou datasetu. | Benígne dáta samy model neposúdia (kap. 2.1, 2.5). Zadanie žiada vyhodnotenie „presnosti detekcie malvérových vzorcov“; kontroly pomenované podľa správania sú podľa HONESTY P4 to, čo sa dá zmerať bez vzoriek. | nič |
| D8 | Päť typov udalostí a udalosť naprázdno. Vypadnú `restart_sluzby` a `zla_konfiguracia_nginx`. | Pri 72 výskytoch na rolu pripadá 12 na druh pri šiestich druhoch a 9 pri ôsmich (hranica 0,22 proti 0,28 pri žiadnom alarme). `restart_sluzby` je podmnožina `restart_databazy`, ktorá reštartuje všetky služby. `zla_konfiguracia_nginx` nevytvára procesy a jej chybový režim (zlyhané požiadavky) nesie aj `zla_konfiguracia_sluzby`. Oba typy mali predtým 0 zo 16 a 1 zo 17 alarmov, takže ich vypustenie výsledok o falošných alarmoch neprikrášľuje. | ak by klasifikácia činnosti mala byť potvrdzujúca |
| D9 | Klasifikácia činnosti je opisná, samostatný dataset udalostí sa nezbiera. | Zadanie žiada „základnú implementáciu“ klasifikácie, nie úroveň presnosti. Klasifikátor scenára v balíku v6 určil 5 z 12 session a jeho strata na `dev` rástla od prvej epochy. Udalosti vo všetkých rolách dajú 12 výskytov na druh v `train` aj v teste, čo stačí na opis s hranicou. Ušetrí 96 session. | požiadavka školiteľa na potvrdzujúci výsledok klasifikácie |
| D10 | Udalosti ostávajú súčasťou normálu vo všetkých rolách. | Pravidlo zapísané pred meraním (`NAVRH_PROTOKOL_V3.sk.md`, kap. 4) a jeho výsledok: 5,63 alarmu za hodinu počas udalostí proti 0,047 v čistej prevádzke. Riziko, že falošné alarmy klesnú konštrukciou, kryje prah z čistej prevádzky a tvrdenie K2. | nič |
| D11 | Mriežka zberu ostáva pevná. | Štyri z ôsmich pamäťových stĺpcov merajú množstvo zmeny za interval, takže by sa menili s dĺžkou intervalu. Voľba rozfázovania v zberači nikdy nebežala (UNVERIFIED). Príčiny periodických porúch sa riešia pri zdroji (kap. 5.5, 5.6). | ak autokorelácia označených riadkov v generálke ostane aj po ohraničení slučiek |
| D12 | Finálny dataset (surový archív, príznaky, audity) sa uchová do obhajoby s jednou overenou kópiou. Z generálok ostávajú záznamy, audity a príznaky; surové dáta sa po G4 presunú na externý disk. | HONESTY P3, P5, P10; po zmazaní z 2026-11-20 sa výsledky predchádzajúcej iterácie nedajú prepočítať. HDD zberového PC má 379 GiB voľných; 132 session s náhradami je asi 330 GiB (odhad z veľkosti session vo v4c, s novými profilmi neoverený), takže 60 session generálok sa popri nich nezmestí. | veľkosť session nameraná v G3b |
| D13 | Zákaz swapu pre QEMU nastaví a overí kontrola pred štartom; bez neho sa zber nespustí. | Zamietnutia vo v4 a v4c; ručné nastavenie sa stratí pri reštarte hostiteľa alebo novom prihlásení. | nič |
| D14 | Balík na nasadenie je seed 0; K1 a K2 sa rozhodujú podľa mediánu piatich seedov. | Doterajšia konvencia v kóde (`tcn/seedy.py`); medián odstraňuje výber seedu po výsledku. | nič |
| D15 | Rozsah je jadro z kap. 14, bez rozšírení. Kontrolný bod: ak potvrdzujúca generálka neprejde do ôsmich týždňov od začiatku G0 alebo na druhý pokus, prechádza sa na najmenší rozsah. | Zadanie má dátum 27. 10. 2025; termín odovzdania v repozitári nie je. Predpoklad, ktorý musí vlastník potvrdiť: odovzdanie na jar 2027. Jadro (šesť až deväť týždňov) by od 2026-11-21 skončilo medzi 2. a 23. januárom 2027 a nechalo čas na text. Rozšírenia odpoveď na K1 a K2 nemenia. | skutočný termín odovzdania |
| D16 | Vzorky malvéru nie sú súčasťou tohto protokolu. | Poradie závislostí: detekciu vzoriek možno merať až na zmrazenom balíku, inak by sa ladilo na pozitívnych dátach. Vyhodnocovač a konfigurácia existujú (`tcn.eval malver`, `config/malver-v1.json`); časť so vzorkami robí vlastník po G6. Dovtedy platí veta z HONESTY P4 a „malvérové vzorce“ zo zadania pokrývajú kontroly podľa správania. Asistent so vzorkami nepracuje. | nič |
| D17 | Staré dáta na vývojovom PC sú zmazané (rozhodol vlastník 2026-11-21). | Ponechané: balíky a obraz jadra pre profil, staré skúšobné modely (144 KiB) a jedna validačná snímka (486 MiB), ktorú testy parsera menujú ako vstup. | pokyn vlastníka zmazať aj tú |

Ďalšie otázky z auditu:

| Otázka | Rozhodnutie | Podklad |
|---|---|---|
| `fpr`, `k`, `n` | 0,01 a 3 z 5 ostávajú | jediné nastavenie s uloženým výsledkom; zmena bez dát by bola voľba bez opory; citlivosť sa vykáže (kap. 8.5) |
| označenie „E1“ v pláne | ruší sa | v repozitári nemá definíciu experimentu |
| poradie rolí | chronologické | vynucuje ho kontrola korpusu a zodpovedá nasadeniu |
| stav databázy na začiatku skupiny | pevný seedovaný stav | posun vstupov v predchádzajúcej iterácii (kap. 2.2) |
| náhrada session | tie isté typy udalostí, nové fázy a trvania | deterministická príčina sa nemá opakovať |
| nastavenia PostgreSQL | ostávajú predvolené a zapíšu sa do registra periód | perióda 60 s dala v kampani v6 iba nepotvrdené riadky, žiadny neplatný; zmena bez preukázanej škody odporuje zásade 7 |
| činnosť správcu v profile `corp` | skript a časovač v hosťovi, nie ssh | či je v obraze hosťa sshd, repozitár neukazuje |
| dozvuk | 300 s, mimo čistej prevádzky, vykazuje sa zvlášť | tak je definovaný uložený výsledok predchádzajúcej iterácie |
| seedy a rozvrh | nové | rozvrh v4 sa pri rozbore porúch prezeral |

---

## 13. Validácia samotného protokolu

Vykonanie stupňov, ich záznamy a rozdelenie práce opisuje [HARNESS_V5.sk.md](HARNESS_V5.sk.md).

Protokol sa overuje štyrmi spôsobmi: strojovo (samokontrola), známymi odpoveďami (G1),
čítaním proti zoznamu hrozieb a sledovateľnosťou voči auditu
([NAVRH_PROTOKOL_V5_SLEDOVATELNOST.sk.md](NAVRH_PROTOKOL_V5_SLEDOVATELNOST.sk.md): každý nález
auditu má kapitolu, alebo dôvod, prečo prijatý nebol).

**Samokontrola protokolu ako testy:** dosiahnuteľnosť každého pravidla prijatia; zhoda
všetkých miest, ktoré rozhodujú o prijatí; simulácia dokončenia kampane; rozpočet času
a disku z nameraných časov krokov; ohraničenie slučiek; vyváženie rozvrhu a minimálne počty
na typ; nezávislosť prúdov náhody; zákaz udalostí okolo plnej snímky; zhoda zoznamu vstupov
v dokumente s konštantami v kóde.

| Hrozba | Ošetrenie |
|---|---|
| model sa učí identitu session, bootu alebo VM | kap. 8.1; delenie po bootoch |
| model je merač záťaže | metóda Z4 |
| model je prah na jednom stĺpci | Z1, Z2, K2a, kanály, diagnostiky |
| sieť sa nič nenaučila | K1, sieť s náhodnými váhami, krivka učenia |
| čas sa nevyužíva | K2 na triede C, ablácie kontextu |
| test prejde aj bez javu | hranice z nulového prípadu; diagnostiky overené na Z1 až Z3 |
| zásahy a kontroly vybrané podľa výsledku | zoznam zmrazený v G0 vrátane dávok, ktoré sa zachytiť nemajú |
| ladenie na dátach, ktoré potom potvrdzujú | G3a a G3b oddelené |
| falošné alarmy klesli konštrukciou | kap. 8.7; citlivosť ako hlavný výsledok |
| neskórovaný čas vyzerá ako ticho alebo ako úspech | kap. 6.4 |
| výber iba „pekných“ session | zamietnuté a nahradené session v každom menovateli |
| testovacie dáta videné vopred | zapečatenie, jeden finálny príkaz |
| voľné parametre analýzy | plán analýzy v hashi |
| posun v čase zamenený s rolou | definovaný stav skupiny, striedanie testovacích rolí, metóda Z3 |
| stopa spúšťača udalostí | udalosť naprázdno |
| kontrola dokazuje parser, nie detektor | párové negatívne kontroly, tri výsledky |
| periodické deje v kroku so zberom | ohraničené slučky, autokorelácia označených riadkov, losované fázy |
| rušenie medzi VM | kontroly swapu, meškania a času cyklu; najhorší prípad v G2 |
| protirečivé pravidlá | jedna funkcia prijatia, hraničné testy |
| limit a rozpočet odhadom | vzorce z generálky |
| všetku detekciu nesie pravidlový kanál | výsledky po kanáloch, prírastok neurónového kanála, zapísané znenie |

Čo protokol neošetrí a treba to priznať: jeden hostiteľ, jeden obraz hosťa, jedno jadro; živé
čítanie bez zastavenia VM; zásahy do príznakov nie sú útoky; zovšeobecnenie mimo tohto labu;
reálny malvér. Generátor suchého behu, model aj testy píše ten istý autor; nezávislé čítanie
pred G4 to zmierňuje, neodstraňuje.

---

## 14. Práca a čas

Odhady, nie merania. Kód píše asistent; čas na VM je daný hodinami zberu a tým, že kroky so
sudo spúšťa vlastník.

| Krok | Jadro | Odhad |
|---|---|---|
| G0: odovzdanie korpusu, funkcia prijatia, samotest a nové kontroly auditu | áno | 4 až 6 dní |
| G0: plán analýzy v protokole, zapečatenie, chyby po stĺpcoch, záznam pri uzavretí | áno | 3 až 4 dni |
| G0: profily `eshop` a `corp`, otvorená slučka, predikáty účinku, stav skupiny, rozvrh, zmeny kampane (roly, pozastavenie) | áno | 6 až 9 dní |
| G0: metódy Z0 až Z5, zhodná miera alarmov, zásahy do príznakov, kvalifikácia príznakov, kanály | áno | 5 až 7 dní |
| G0: kontroly na VM s párovými negatívnymi | áno | 2 až 3 dni |
| G1: generátory a príkaz suchého behu | áno | 3 až 4 dni |
| G2: skúška na VM | áno | 2 až 3 dni, so sudo |
| G3a a G3b: dve generálky a ich rozbor | áno | po 1,4 dňa zberu a 1 až 2 dni rozboru; treba rátať s opakovaním G3a |
| G5: kampaň 132 session | áno | 5,9 až 6,5 dňa |
| G6: vyhodnotenie a správa | áno | 2 až 3 dni |
| réžia A/B/A a živý beh (O7, O8) | áno | 1 až 2 dni, mimo kampane |
| profily `batch`, `idle`; PCA, izolačný les, sieť bez času, GRU | rozšírenie | 4 až 6 dní |

Jadro spolu je zhruba 30 až 45 dní práce a zberu, teda šesť až deväť týždňov. Najmenší rozsah,
ktorý ešte odpovie na otázku o modeli: jeden profil s premenlivou záťažou a dávkami, zásahy
do príznakov, metódy Z0, Z1, Z3, Z5 a M, kontroly na VM iba triedy A. Ušetrí asi tretinu
práce v G0; veľkosť kampane sa nemení.

---

## Prílohy

**A. Zdroje dôkazov.** Audit: `data/results/audit_kodu_v5_20261120.json` (nálezy z čítania
kódu, nie merania). Záznam o reštartoch `worker`:
`data/results/collection_worker_resonance_20261120.json`. Tréning a prah predchádzajúceho
modelu: `data/results/safeguard_train_benign_v6_20261029.json`. Falošné alarmy:
`data/results/safeguard_far_test_benign_v6_20261104.json`,
`data/results/safeguard_far_events_v3_20261114.json` a jeho súhrn. Kampane:
`data/results/collection_campaign_benign_v6_20261026.json`,
`data/results/collection_campaign_events_v3_20261108.json`. Riadky kódu platia pre vetvu
`v5-protocol` s pripravenými zmenami z 2026-11-20.

**C. Zdroje ku kap. 5.7.** TPC-W (špecifikácia webového obchodu, tri mixy interakcií, čas na
rozmyslenie): <https://www.tpc.org/tpcw/>. Barford, Crovella: Generating Representative Web
Workloads for Network and Server Performance Evaluation, SIGMETRICS 1998 (SURGE):
<https://cs-web.bu.edu/fac/crovella/paper-archive/sigm98-surge.pdf>. Arlitt, Williamson: Web
Server Workload Characterization: The Search for Invariants, 1996:
<https://cs.uwaterloo.ca/~brecht/servers/readings-new/arlitt97.pdf>. Williams, Arlitt,
Williamson, Barker: Web Workload Characterization: Ten Years Later, 2005:
<https://cspages.ucalgary.ca/~cwill/papers/2005/WebWorkload.pdf>.

**B. Čo zmenili recenzie.** Metodická recenzia (25 pripomienok): hranice testov z nulového
prípadu namiesto pevných čísel; dve potvrdzujúce tvrdenia s troma výsledkami namiesto piatich
hypotéz v konjunkcii; rozšírená rodina prahových metód a zhodná miera alarmov; zásahy
zachovávajúce rozdelenie stĺpcov namiesto ťažko definovateľných kontrol na VM; zoznam zásahov
zmrazený v G0; dve generálky; vzorec pre každú odvodenú hodnotu; limit náhrad z predpovede;
citlivosť počítaná z plánovaných výskytov; rozvrh, ktorý sa dá splniť; rozsah práce.
Recenzia faktov (30 opráv): počty verdiktov, zdroje čísel, štyri odkazy na kód, tvrdenia,
ktoré overovateľ auditu označil za neoverené, terminológia.
