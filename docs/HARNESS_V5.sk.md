# Harness protokolu v5: stupne, záznamy a rozdelenie práce

Vykonávací dokument k [NAVRH_PROTOKOL_V5.sk.md](NAVRH_PROTOKOL_V5.sk.md). Návrh hovorí, **čo**
má platiť a prečo; tento dokument hovorí, **ako** sa to stavia a potvrdzuje. Pri rozpore platí
návrh; rozpor sa zapíše do denníka odchýlok
([ODCHYLKY_V5.sk.md](ODCHYLKY_V5.sk.md)).

## 1. Roly

| Rola | Kto | Čo robí |
|---|---|---|
| vlastník | autor práce | rozhoduje (návrh, kap. 12), spúšťa kroky so sudo, podpisuje stupne G3b a G4 |
| vykonávateľ | Claude Code na zberovom PC („pcc“) | píše kód, spúšťa stupne, vyrába dôkazy a záznamy |
| overovateľ | nezávislý čitateľ: nový agent bez kontextu vykonávateľa; pri G3b a G4 aj Claude na vývojovom PC | pokúša sa každé kritérium vyvrátiť |

Vykonávateľ nikdy neoveruje vlastnú prácu. Overovateľ dostane iba návrh, tento dokument, kód
a dôkazy stupňa, nie zdôvodnenie vykonávateľa.

## 2. Reťaz stupňov

`scripts/gates.py` drží poradie. Stupeň platí, keď jeho najnovší záznam
`data/results/gate_<stupeň>_<čas>.json`:

- nesie hash súboru protokolu a hash meracieho kódu, ktoré sa zhodujú s aktuálnym stavom
  (commit dokumentácie stupeň nezruší, zmena meracieho kódu alebo protokolu áno);
- obsahuje presne kritériá stupňa (`CRITERIA` v `scripts/gates.py`), každé splnené a s dôkazom;
- obsahuje nezávislé overenie, v ktorom je každé kritérium potvrdené.

```
python3 scripts/gates.py status  --protocol config/collection-v5.json
python3 scripts/gates.py require G2 --protocol config/collection-v5.json
python3 scripts/gates.py record  G1 --protocol config/collection-v5.json \
        --criteria kriteria.json --verification overenie.json --command "..."
```

Dôkaz kritéria je cesta k súboru, ktorý vyrobil príkaz (log testov, záznam v `data/results/`),
nikdy text napísaný rukou. Príkaz, ktorý stupeň spúšťa, volá na začiatku `require`.

| Stupeň | Kritériá v `gates.py` | Návrh |
|---|---|---|
| G0 | `tests`, `protocol_selfcheck`, `audit_selftest`, `corpus_to_training`, `analysis_plan_bound`, `test_sealed`, `audit_probes_reproduced` | kap. 10.1 |
| G1 | `chain_end_to_end`, `null_generator`, `structured_generator`, `diagnostics_controls`, `marginal_change`, `unscored_spans`, `fault_injections` | kap. 10.2 |
| G2 | `guest_matches_repository`, `event_effects`, `restart_loops_bounded`, `marked_rows_per_event`, `profiles_load`, `traffic_realism`, `ground_truth_under_load`, `controls_paired`, `live_fault_injections`, `worst_case_timing`, `live_archive_parity` | kap. 10.3, 5.7 |
| G3a | `campaign_shaped_run`, `feature_qualification`, `changes_logged` | kap. 10.4 |
| G3b | `candidate_commit_untouched`, `chain_end_to_end`, `replacement_limit`, `no_unexplained_periodicity`, `audit_bounds_hold`, `owner_decision` | kap. 10.5 |
| G4 | `tag`, `protocol_and_plan_hashed`, `preregistration_pushed`, `deviation_log_open` | kap. 10.6 |
| G5 | `plan_complete`, `stop_rules`, `campaign_record` | kap. 10.7 |
| G6 | `single_final_run`, `report`, `claims_check` | kap. 10.8 |

Pridať, odobrať alebo premenovať kritérium smie iba vlastník; zmena zruší staršie záznamy
toho stupňa.

## 3. Pracovné balíky stupňa G0

Poradie je záväzné tam, kde je uvedená závislosť. Každý balík končí testami, ktoré pred
zmenou zlyhajú a po nej prejdú, a nezávislým prečítaním.

| Balík | Obsah | Hotové, keď | Závisí od |
|---|---|---|---|
| B1 | odovzdanie korpusu tréningu: predpona skupín v `validate_index`; tolerované neplatné riadky v `train_bundle`, v `tcn/porovnanie.py`, v návratovom kóde prehratia a v poznámke vyhodnotenia | test postaví korpus v tvare kampane (predpony, udalosti, jeden tolerovaný riadok) cez `features/dataset.py` a prejde ostrou kontrolou indexu, tréningom, každou metódou, prehratím a vyhodnotením | — |
| B2 | jedna funkcia prijatia pre načítanie protokolu, audit, stavbu korpusu a tréning; koniec zvláštneho pravidla v `pilot_gate` | test hraničných session (0 až maximum plus jeden riadok, osamotené aj zhluknuté) dá na všetkých miestach rovnaké rozhodnutie | B1 |
| B3 | samotest kontrol auditu a nové kontroly (návrh, kap. 6.2): swap, meškanie, čas cyklu, varovania, identita VM, účinok udalostí, zhoda hosťa s repozitárom, riadky uzavreté pravidlom, periodicita, povinné kľúče, oba smery prechodu, počty preskočení, posun mriežok | každá kontrola má zlú session, ktorú zamietne s presne očakávaným dôvodom; čistá session prejde; záznam samotestu | B2 |
| B4 | súbor `config/collection-v5.json` (schéma 3) s plánom analýzy; rozvrh: skupiny po 3, roly vrátane `test_controls`, vyvážený blokový rozvrh, nezávislé prúdy náhody, udalosti (päť typov a naprázdno, žiadna alebo tri), zákaz okolo plnej snímky; príkaz samokontroly protokolu | samokontrola prejde na skutočnom súbore a zlyhá na každej úmyselnej chybe (nevyvážený rozvrh, udalosť pri plnej snímke, spoločný seed) | B2 |
| B5 | laboratórium: profily `eshop` a `corp`, otvorená slučka so stropom súbežnosti, predikáty účinku, udalosť naprázdno, ohraničené slučky, obnova stavu skupiny, register periód; metriky realizmu prevádzky (návrh, kap. 5.7) | jednotkové testy generátora a služieb; metriky realizmu sa počítajú zo syntetického logu so známou odpoveďou | B4 |
| B6 | príznaky a model: súhrn každého stĺpca v audite; maska stĺpcov a pravidlo mierky ako dáta protokolu; kanály skóre; chyby po stĺpcoch; pravidlá pre biny; oddelenie hlavy klasifikátora | test s konštantným a takmer konštantným stĺpcom skončí v pravidlovom kanáli; tabuľka citlivosti v manifeste | B1, B4 |
| B7 | metódy Z0 až Z5 so zhodnou mierou alarmov; zásahy do príznakov s predikátom platnosti; vyhodnotenie K1 a K2 s troma výsledkami; diagnostiky; zapečatenie testu a jeden finálny príkaz | testy na syntetických dátach so známou odpoveďou pre každú metódu a každý výsledok | B6 |
| B8 | kontroly na VM tried A a B s párovými negatívnymi a predikátom návratu | jednotkové testy skriptov; skutočné overenie až v G2 | B5 |
| B9 | zmeny kampane: nové roly, striedanie testovacích rolí, pozastavenie a jedno pokračovanie, pravidlá skorého zastavenia, povinný záznam pri uzavretí, generálka pod vlastným názvom protokolu | testy na atrapách zberu; záverečný index sa v testoch už nenahrádza atrapou | B2, B4 |
| B10 | testy, ktoré zopakujú skúšky z auditu (meškanie 4 s prijaté, obídenie značky kópiou indexu, udalosť bez účinku) | každý test pred opravou zlyhá a po nej prejde | B3, B7 |

G0 je hotový, keď platia všetky kritériá G0 a `python3 -m pytest` aj `scripts/check_claims.sh`
sú čisté na zberovom PC.

## 4. Ďalšie stupne

| Stupeň | Kto spúšťa | Sudo | Výstup |
|---|---|---|---|
| G1 suchý beh | vykonávateľ | nie | záznam s hranicami m z nulového generátora a s tabuľkou známych odpovedí |
| G2 skúška na VM | vlastník spustí pripravený skript, vykonávateľ vyhodnotí | áno | záznam s nameranými periódami, mierami označených riadkov, metrikami realizmu, vzorcami z kap. 10.9 |
| G3a prieskumná generálka | vlastník spustí, vykonávateľ sleduje a ladí | áno | záznam a denník zmien; smie sa opakovať |
| G3b potvrdzujúca generálka | vlastník spustí, vykonávateľ nezasahuje do kódu | áno | záznam s limitom náhrad; podpis vlastníka |
| G4 zmrazenie | vykonávateľ pripraví, vlastník potvrdí | nie | tag, predregistrácia, otvorený denník odchýlok |
| G5 kampaň | vlastník spustí, vykonávateľ sleduje iba kontroly kvality | áno | záznam kampane |
| G6 vyhodnotenie | vykonávateľ, raz | nie | kniha finálneho vyhodnotenia, správa |

## 5. Pravidlá pre vykonávateľa

1. **Kritérium sa nikdy neoslabuje, aby prešlo.** Keď niečo neprejde, opraví sa systém, alebo
   sa vec predloží vlastníkovi. Platí „príčina pred toleranciou“ (návrh, kap. 3).
2. **Rozhodnutia z kap. 12 návrhu sa nemenia.** Kto s niektorým nesúhlasí, napíše dôvod
   s dôkazom do hlásenia vlastníkovi a pokračuje podľa platného rozhodnutia.
3. **Hranice označené ako určené v G0 sa po G1 nemenia.** Odvodené hodnoty sa počítajú iba
   vzorcom z kap. 10.9 návrhu.
4. **Zapečatené roly sa neotvárajú** pred finálnym príkazom, ani pri ladení.
5. **Žiadny malvér, žiadne vzorky.** Kontroly sú benígne programy pomenované podľa správania.
6. **Sudo nemá.** Kroky so sudo pripraví ako skript s kontrolami pred štartom a odovzdá
   vlastníkovi s jedným príkazom.
7. **Mazanie dát iba po zázname a so súhlasom vlastníka.**
8. **Malé commity na vetve `v5-protocol`, pred každým testy a kontrola tvrdení.** Do `main` sa
   nezlučuje pred G4.
9. **Počas zberu sa repozitár ani hostiteľ nezaťažuje** (žiadne testy, audity mimo fronty,
   prehľadávanie diskov).
10. **Čo nebežalo, je UNVERIFIED** (HONESTY P5). Číslo bez záznamu sa do dokumentácie nepíše.

## 6. Nezávislé overenie

Po každom balíku a pred zápisom každého stupňa spustí vykonávateľ nového agenta s touto
úlohou: „Tu je kritérium, tu je dôkaz. Pokús sa ukázať, že kritérium splnené nie je.“ Verdikt
je `confirmed`, `refuted` alebo `unverifiable` s vlastným dôkazom. Pri `refuted` alebo
`unverifiable` sa stupeň nezapíše ako splnený. Pri G3b a G4 urobí druhé čítanie aj Claude na
vývojovom PC nad odoslanou vetvou.

## 7. Hlásenia a zastavenie

Vykonávateľ hlási vlastníkovi na konci každého balíka jedným odsekom (čo je hotové, čím je to
doložené, čo je ďalšie) a na konci každého stupňa cestou k záznamu. Zastaví sa a pýta sa, keď:

- treba sudo alebo iný zásah vlastníka;
- overovateľ vyvráti kritérium a oprava by menila návrh;
- nález ukáže, že niektoré rozhodnutie z kap. 12 stojí na nepravdivom predpoklade;
- pravidlo zastavenia kampane sa naplní.

## 8. Pracovný denník

`~/hyptcn3-logs/v5/STAV_PRACE.md` na zberovom PC: aktuálny balík, posledný commit, čo je
overené, čo čaká na vlastníka, otvorené otázky. Vykonávateľ ho aktualizuje po každom kroku
a číta na začiatku každej relácie, aby práca neprestala pri strate kontextu.

## 9. Rozpočet práce

Platí od 2026-11-22 z pokynu vlastníka. Dopĺňa kap. 6 a 8; kde sa od nich líši, platí táto kapitola.

### 9.1 Modely

- Hlavná relácia vykonávateľa beží na Opuse.
- Fable sa volá iba ako agent, a to na **kostru balíka**: jeden krátky výstup na balík, najviac jedna
  strana (ktoré súbory sa menia, v akom poradí, aké testy to doložia, čo zo zadania je sporné). Druhé
  použitie je posúdenie verdiktu `refuted` alebo `unverifiable`, ak by oprava menila návrh.
- Kód, testy, behy, overenie a hlásenia robí Opus.

### 9.2 Rozpočet overenia na balík

Balík je hotový, keď platí toto a nič viac:

1. testy balíka pred zmenou zlyhajú a po nej prejdú (stĺpec „Hotové, keď“ v kap. 3);
2. plná sada testov a kontrola tvrdení sú čisté;
3. **jedno** nezávislé overenie novým agentom proti stĺpcu „Hotové, keď“ (kap. 6); nálezy `must_fix` sa
   opravia a ten istý agent alebo druhý nový agent potvrdí opravu. Tým overenie končí.

- Kazenie kódu (mutanty) najviac jedno kolo na balík a iba nad jadrom zmeny. Preživšie varianty sa
  zapíšu do `odlozene.md` balíka s jednou vetou a neotvárajú ďalšie kolo.
- Žiadne panely, doplnky plánu ani ďalšie kolá bez pokynu vlastníka. Sporné miesto návrhu sa zapíše do
  hlásenia a pokračuje sa podľa najbližšieho čítania návrhu.
- Orientačný strop: jeden balík najviac 6 hodín práce relácie. Po prekročení nasleduje krátke hlásenie,
  čo chýba.

### 9.3 Denník a kontext

- `STAV_PRACE.md` (kap. 8) má najviac 120 riadkov: kde sme, čo je rozpracované, čo čaká na vlastníka,
  ďalší krok.
- Podrobnosti patria do `dennik/<balík>.md` v tom istom adresári; tie sa nečítajú celé, iba cez `grep`
  alebo po úsekoch. Rovnako sa číta starý denník `dennik/DENNIK_do_2026-11-22T12Z.md`.
- Výstupy príkazov a agentov idú do súborov; do kontextu iba posledné riadky a počty.
- Po každom uzavretom balíku sa začína nová relácia a pokračuje sa zo `STAV_PRACE.md`.
