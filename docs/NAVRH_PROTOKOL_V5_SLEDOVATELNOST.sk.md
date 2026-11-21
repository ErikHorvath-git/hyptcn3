# Sledovateľnosť: nálezy auditu a návrh protokolu v5

Každý nález auditu z 2026-11-20 ([záznam](../data/results/audit_kodu_v5_20261120.json)) a kde
ho rieši [NAVRH_PROTOKOL_V5.sk.md](NAVRH_PROTOKOL_V5.sk.md). Identifikátory sú zo záznamu
(`values.dimensions[*].audit.risks[*].id`); riadky s „+“ sú doplnenia overovateľa
(`verify.missed`) v poradí zo záznamu. „Čiastočne“ a „neprijaté“ majú uvedený dôvod.

## Zber a audit session (`capture`)

| ID | Nález | Kde v návrhu | Poznámka |
|---|---|---|---|
| R1 | príkazy udalostí sú fázovo zviazané so zberom | 5.5 | spojité losovanie, fáza sa zapisuje |
| R2 | periodické deje v hosťovi a pevná mriežka | 5.6, 6.2, 7.5 | ohraničené slučky, autokorelácia označených riadkov |
| R3 | riadky uzavreté pravidlom sa prijímajú bez limitu | 6.2, 6.4, 10.9 | strop zo vzorca, citlivostná analýza |
| R4 | zákaz swapu je mimo kódu a swap sa nekontroluje | 6.2, D13 | |
| R5 | meškanie cyklu sa neaudituje | 6.2 | |
| R6 | varovania zberača session nezamietnu | 6.2, 10.9 | |
| R7 | udalosť bez účinku sa prijme | 5.5, 6.2 | predikát účinku |
| R8 | väčšina kontrol nemá test | 6.2, 10.1 | samotest kontrol |
| R9 | pilot neskúša kampaň | 10.3 až 10.5 | |
| R10 | pravidlo prijatia je nekonzistentné a uvoľnené po neúspechu | 3 (zásada 6), 6.3, 10.9 | pracovné súbory protokolu v5 s hodnotami 0,77 a 10 boli odstránené |
| R11 | kontroly porovnávajú hodnotu so sebou, tiché predvolené hodnoty | 6.2 | čiastočne: povinné kľúče áno; zápis nastavení zberačom do sidecaru nie (zmena binárky zberača, malý prínos pre PoC) |
| R12 | rezerva času cyklu pre dve VM je nezmeraná | 6.2, 10.3 | |
| +1 | nič nedokazuje, že oprava `worker` je nasadená | 6.2, 10.3 | zhoda hashov hosťa s repozitárom |
| +2 | dva zberače majú stály vzájomný posun | 6.2, 10.3 | |
| +3 | brána pokrytia nevidí, že stratené okná ležia v udalostiach | 6.4, 7.5 | |
| +4 | snímky nie sú viazané na VM session | 6.2 | |
| +5 | spúšťač udalostí sám ruší hosťa | 5.5 | udalosť naprázdno |

## Príznaky (`features`)

| ID | Nález | Kde v návrhu | Poznámka |
|---|---|---|---|
| GF-1 | takmer konštantné počty robia z detektora prah na jednej premennej | 8.1, 8.2, 8.5, 8.6 | |
| GF-2 | stĺpce konštantné v tréningu sú mŕtve vstupy | 8.1, 8.2 | pravidlový kanál |
| GF-3 | úrovňové pamäťové vstupy kódujú vek QEMU a rolu | 5.4, 8.1 | |
| GF-4 | platné riadky nesú opravené alebo nekontrolované zoznamy procesov | 6.2, 6.4, 10.3 | |
| GF-5 | počty soketov a W+X sú dolné hranice bez príznaku | 6.2, 10.3 | |
| GF-6 | neskórované riadky sa zhlukujú tam, kde na tom záleží | 6.4 | |
| GF-7 | mriežka 5 s je súmerateľná s časovačmi hosťa | 5.6 | rozfázovanie zberača neprijaté (D11) |
| GF-8 | tréning neprečíta korpus, ktorý audit prijme | 10.1, 10.2 | |
| GF-9 | chýba pozemná pravda pod záťažou | 10.3 | |
| GF-10 | pamäťové vstupy môžu byť merač záťaže | 8.1, 8.2, 8.3 (Z4) | |
| GF-11 | duplicitné a zle pomenované stĺpce | 8.1 | čiastočne: duplicity vypadnú; kontrola očakávanej veľkosti iba pre druhy kontrol z kap. 7.4 |
| GF-12 | dôkazy o príznakoch prežili náhodou | 10.1, 13 | súhrn stĺpcov v každom audite |
| +1 | poradie scenárov v skupine je nevyvážené | 7.3 | |
| +2 | binová vetva: spoločná mierka, maximum, dva malé biny | 8.2 | |
| +3 | zoznam vstupov je konštanta v hashovanom extraktore | 8.1 | maska ako dáta protokolu |
| +4 | pozitívna kontrola dokazuje parser, nie detektor | 7.4 | párová negatívna kontrola, tri výsledky |
| +5 | sokety sú v tomto labe bez informácie | 8.1, 8.2 | čiastočne: pôjdu do pravidlového kanála; udržiavané spojenia v službách sú rozšírenie |

## Model (`model`)

| ID | Nález | Kde v návrhu | Poznámka |
|---|---|---|---|
| M1 | skóre sa dá zredukovať na prahy po stĺpcoch | 8.2, 8.4 (K2a), 8.5, 8.6 | |
| M2 | chýba porovnanie s triviálnou predpoveďou | 8.4 (K1), 8.6 | |
| M3 | benígne falošné alarmy modely nerozlíšia | 4.1, 7.4, 8.3 | zhodná miera alarmov, citlivosť |
| M4 | tréning odmietne korpus v tvare v5 | 10.1, 10.2 | |
| M5 | poistka „test raz“ sa dá obísť | 10.1, 10.8 | |
| M6 | existujúce základné metódy nie sú zrovnateľné | 8.3 | |
| M7 | stĺpce konštantné v tréningu sú v skóre stlmené | 7.4, 8.1, 8.2 | |
| M8 | udalosti v kalibrácii zdvihnú prah | 8.6, 8.7 | |
| M9 | parametre analýzy sú voľné | 10.1, 10.9 | |
| M10 | maximum cez biny rozhoduje o polovici skóre | 8.2 | |
| M11 | „smoke“ korpus neoverí učenie | 10.2 | |
| M12 | málo nezávislých jednotiek, prekrývajúce sa okná | 7.1, 7.2, 9.1, 9.2 | |
| +1 | neskórované riadky nikdy nealarmujú | 6.4 | čiastočne: vykazovanie áno; alarm z nedostatku skóre v detektore nie (zmena detektora, námet na ďalšiu prácu) |
| +2 | pár trénovacích riadkov určí váhu stĺpca | 8.2, 8.6 | čiastočne: dolná hranica mierky a triedy stĺpcov; kontrola normalizéra s vynechanou skupinou je rozšírenie |
| +3 | živá cesta sa líši od archívnej | 10.1, 10.3, O8 | |
| +4 | posun v čase je zmiešaný s poradím rolí | 5.4, 7.3, 8.1, 8.3 (Z3) | |
| +5 | pravidlo 3 z 5 určuje, čo sa dá zachytiť | 7.4, 8.5 | krátka dávka, citlivosť na pravidlo |

## Vyhodnotenie (`evaluation`)

| ID | Nález | Kde v návrhu | Poznámka |
|---|---|---|---|
| R1 | falošné alarmy klesnú konštrukciou, citlivosť sa nemeria | 4.1, 7.4, 8.7 | |
| R2 | poistka jedného použitia nedrží | 10.1, 10.8 | |
| R3 | základné metódy a seedy sa k odloženej role nedostanú | 10.8 | jeden príkaz pre zoznam modelov |
| R4 | „viac než prahy“ sa dnešnými metódami nedá testovať | 8.3, 8.4, 8.5 | |
| R5 | boot je jednotka, žiadny interval ho nepoužíva | 7.1, 9.1 | |
| R6 | veľkosť testu neunesie tvrdenia | 7.2, 9.2 | falošné alarmy ako odhad s hranicou |
| R7 | neskórovaný čas leží pri udalostiach a ráta sa ako ticho | 5.5, 6.4 | |
| R8 | chýba hlavná metrika, veľa porovnaní | 4, 9.1, 10.1 | dve potvrdzujúce tvrdenia |
| R9 | chronologické roly zamieňajú rolu s posunom | 5.4, 7.3 | čiastočne: striedanie rolí v čase neprijaté (poradie je bližšie nasadeniu a vynucuje ho kontrola korpusu); posun sa odstraňuje pri zdroji a meria |
| R10 | reťaz vyhodnotení pobeží prvý raz až na skutočných dátach | 10.4, 10.5 | |
| R11 | miera za hodinu sa na udalosti nehodí | 9.1, O3 | |
| R12 | nedotrénovaný alebo triviálny prediktor by si nikto nevšimol | 8.3, 8.4 (K1), 8.6 | |
| +1 | tréning a základné metódy odmietnu session, ktorú pravidlo prijatia pustí | 10.1, 10.2 | |
| +2 | plná snímka uprostred session zatieni 160 s, kde sú udalosti | 5.5 | zákaz udalostí okolo plnej snímky |
| +3 | hladinu alarmu určuje mierka takmer konštantných počtov | 8.2, 8.3 (Z2) | |
| +4 | značky scenára na session, ktoré obsahujú udalosti | 4.2 (O6), 8.2 | značky z `events.json` |
| +5 | porovnanie A proti B je zmiešané s inými zmenami | 8.7 | opisne; kontrola vnútri v5 je rozšírenie |

## Laboratórium (`lab`)

| ID | Nález | Kde v návrhu | Poznámka |
|---|---|---|---|
| LAB-01 | začiatky udalostí sú fázovo zviazané so zberom | 5.5 | |
| LAB-02 | slučka pádov s `RestartSec=3` ostáva | 5.6 | ohraničiť každú slučku, ktorá vytvára procesy |
| LAB-03 | periodické zdroje mimo kódu labu nie sú spísané | 5.6 | register vrátane nastavení databázy |
| LAB-04 | udalosť môže nič neurobiť a ráta sa ako vykonaná | 5.5, 6.2 | |
| LAB-05 | statický normál | 5.2, 8.3 | |
| LAB-06 | šesť scenárov je šesť stálych úrovní | 5.2, 5.3, 9.1 | čiastočne: vynechanie jedného profilu z tréningu neprijaté (jadro má dva profily); výsledky sa uvádzajú po profile |
| LAB-07 | stopa spúšťača je zmiešaná s každou udalosťou | 5.5 | |
| LAB-08 | okná udalostí preceňujú jednorazové zásahy; málo výskytov na typ | 5.5, 7.2, 9.2 | čiastočne: počty na typ sú dané rozvrhom; meraná aktívna fáza udalosti je rozšírenie |
| LAB-09 | pilot nespúšťa to, čo kampaň | 10.3 až 10.5 | |
| LAB-10 | stav hosťa starne, roly idú za sebou | 5.4, 7.3 | |
| LAB-11 | seedy sa opakujú a zdieľajú medzi účelmi | 5.5, 7.3 | |
| LAB-12 | doručená záťaž sa neporovnáva so scenárom | 5.3 | |
| +1 | nasadený kód hosťa sa neporovnáva s repozitárom | 6.2 | |
| +2 | prvá záťaž pamäte natrvalo posunie vstup modelu | 5.4 | |
| +3 | spoločný seed viaže typ udalosti s počtom a trvaním | 5.5 | |
| +4 | neplatné riadky sa zhlukujú na začiatkoch udalostí | 6.4 | |
| +5 | brána pilota protirečí pravidlu tolerancie | 6.3 | |

## Proces (`process`)

| ID | Nález | Kde v návrhu | Poznámka |
|---|---|---|---|
| R1 | odovzdanie korpusu tréningu zlyhá po kampani | 10.1, 10.2 | |
| R2 | limit náhrad nie je z nameranej miery | 7.5 | |
| R3 | pilot nie je reprezentatívny | 10.3 až 10.5 | |
| R4 | periodická činnosť hosťa v kroku so zberom | 5.6 | |
| R5 | ochrana QEMU pred swapom je iba ručné nastavenie | 6.2, D13 | |
| R6 | „normál“ iba z prijatých session, neskórovaný čas pri udalostiach | 6.4, 10.8 | čiastočne: zamietnuté session sú v každom menovateli; prehratie na príznakoch zamietnutých session je rozšírenie |
| R7 | dvojice pravidiel si môžu protirečiť | 6.3 | |
| R8 | jedno použitie testu a voľby analýzy sú zamknuté iba sčasti | 10.1 | |
| R9 | po neúspešných kampaniach neostal záznam | 11 (bod 6) | zápis v `docs/MERANIA.md` z 2026-11-20 doplnený |
| R10 | protokol pokrýva iba benígne dáta | 4.2, D16 | |
| R11 | existujúci suchý beh obíde ťažké cesty | 10.2 | |
| R12 | disciplína hostiteľa a rozpočet času sú bez kontroly | 11 (bod 8), 13 | čiastočne: háčik pred commitom neprijatý (PoC) |
| +1 | známa chyba labu bola zakódovaná ako očakávané správanie | 11 (body 4 a 5) | register výnimiek |
| +2 | hosť nie je viazaný na commit; rovnosť VM sa overí až na konci | 6.2, 10.2, 10.5 | |
| +3 | poistka blokuje porovnanie metód na odloženej role | 10.8 | |
| +4 | riadky opravené pravidlom nemajú rozpočet ani varovanie | 6.2, 7.5 | |
| +5 | audit a archivácia sú úzke hrdlo, rezerva časového limitu je nezmeraná | 13, 10.5 | rozpočet času z časov krokov generálky |

## Čo návrh neprijal

- Rozfázovanie mriežky zberača (D11): zmenilo by príznaky počítané za interval.
- Striedanie rolí v čase: poradie rolí ostáva chronologické.
- Alarm z nedostatku skóre v detektore: zmena detektora nad rámec PoC; neskórovaný čas sa vykazuje.
- Zápis efektívnych nastavení zberačom do sidecaru: zmena binárky zberača.
- Vynechanie jedného profilu z tréningu: jadro má iba dva profily.
- Kontrola textu jadra, ktorá bola v predchádzajúcej iterácii nerozhodnutá, ostáva obmedzením
  (`docs/LIMITACIE.md`, L18); protokol ju nerieši.
