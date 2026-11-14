# TCN-gui: jedno okno s výsledkom detektora

Malá desktopová aplikácia (Tkinter a matplotlib, bez servera a prehliadača). Vyberieš
natrénovaný balík `safeguard` a jednu session snímok, napríklad hodinu, a dostaneš
dva grafy so spoločnou časovou osou:

1. **Skóre anomálie** s prahom; červený pás je alarm modelu (k z n okien nad prahom),
   fialový pás prevádzková udalosť z `events.json`. Nadpis obsahuje verdikt
   (`BEZ ALARMU`, `ANOMÁLIA`, `NÁLEZ INTEGRITY JADRA`, `NEDOSTATOČNÉ POKRYTIE`,
   `CHYBA VSTUPU`).
2. **Chyba modelu po oblastiach pamäte** (chromatogram): os y je adresa RAM hosťa po
   16 MiB, farba chyba predikcie per-bin TCN. Svetlé miesto ukazuje, kde v pamäti sa
   hosť správa nezvyčajne.

Pod grafmi je jeden riadok: vybraná epocha tréningu, strata na `dev` a prevažujúca
trieda klasifikátora záťaže (druh prevádzky, nie škodlivosť).

Prehratie ide cez `safeguard.runtime.Detector` (`analyza.py`), takže skóre, prah
aj alarmy sú presne tie, ktoré by vydal detektor pri ostrom behu. Test
`tests/test_analyza.py` to porovnáva s `replay_archive`.

## Spustenie

```sh
python3 TCN-gui/tcn_gui.py                       # aplikácia
python3 TCN-gui/tcn_gui.py --bundle data/models/server-v2-benign-v6 --input data/collections/<session>
python3 TCN-gui/tcn_gui.py --bundle ... --input ... --png session.png   # bez okna, iba obrázok
```

Na zberovom PC sa použije `.venv/bin/python`.

Od schémy príznakov `hyptcn3/snapshot-vektor/4` (2026-11-14, príznaky `proc_wx` a
`proc_memfd`, 20 vstupov modelu) sa starší balík `server-v2-benign-v6` a archívy s 22
stĺpcami nenačítajú. Na ich zobrazenie treba repozitár na commite `500de07`.

## Ovládanie

- **Načítať model…** (Ctrl+M): adresár balíka so súborom `manifest.json`. Pod tlačidlom
  sa ukáže vybraná epocha, okno, počet binov, prah, pravidlo alarmu a triedy.
  Diagnostický (syntetický) balík sa načíta iba so začiarknutou voľbou.
- **Session…** (Ctrl+O): jeden archív príznakov `.npz`, ktorý sa hneď analyzuje.
- **Priečinok…** (Ctrl+D): napríklad `data/collections`. Do zoznamu sa načítajú session
  o jednu úroveň nižšie, teda adresáre s `.npz`, so snímkami `.vmicd` alebo s `raw/`.
- **Analyzovať vybranú** (Enter alebo dvojklik) a **Skontrolovať všetky**: v zozname
  pribudne výsledok (`✓ bez alarmu`, `✗ N alarm`, `? pokrytie`) a pomer maximálneho
  skóre k prahu. Analýza beží na pozadí, okno nezamrzne. Kliknutím na už
  skontrolovanú session sa zobrazí jej graf.
- **Súbor → Uložiť obrázok** (Ctrl+S, PNG/PDF/SVG) a **Uložiť prehľad (CSV)** so
  všetkými skontrolovanými session.
- Lišta pod grafom slúži na zväčšenie výrezu a posun.

## Porovnanie modelov (napríklad po týždňoch)

**Porovnať modely…** (Ctrl+P): pridáš dva a viac balíkov a jednu session (`.npz`).
Modely sa zoradia podľa dátumu tréningu a prvý je referencia. Obrázok má štyri časti:

1. **Skóre / vlastný prah** každého modelu na tej istej session. Nad 1 je okno nad
   prahom daného modelu, takže modely s rôznym prahom sú porovnateľné.
2. **Čo model považuje za normálne:** posun priemerov normalizéra (18 globálnych
   príznakov a 3 príznaky binov) voči prvému modelu, v smerodajných odchýlkach
   prvého modelu. Ukazuje, ako sa medzi tréningami posunula bežná prevádzka.
3. **Podobnosť vrstiev:** lineárne CKA (Kornblith a kol., 2019) medzi výstupmi
   každého bloku TCN a toho istého bloku prvého modelu, na rovnakých oknách session.
   Hodnota 1 znamená rovnakú reprezentáciu až na otočenie a mierku.
4. **Učenie:** strata predikcie na `dev` po epochách, vybraná epocha a prah.

Surové váhy sa prvok po prvku neporovnávajú. Dva samostatne natrénované modely
môžu mať rovnako naučené kanály v inom poradí a rozdiel matíc by ukazoval hlavne
túto zámenu. Všetky štyri pohľady od poradia kanálov nezávisia. Balík navyše
ukladá iba váhy vybranej epochy, preto priebeh váh počas jedného tréningu
zobraziť nejde.

Bez okna:
`python3 TCN-gui/tcn_gui.py --compare MODEL1 MODEL2 ... --input SESSION.npz --png porovnanie.png`

Posledný model a priečinok si aplikácia pamätá v `~/.config/hyptcn3-tcn-gui.json`.

Kým na danom PC beží zber, analýza sa nespustí. Prehratie zaťažuje CPU a disk
a narušilo by meranie (`docs/AUTOMATICKY_ZBER.sk.md`).

## Ako čítať výsledok

`BEZ ALARMU` znamená, že session sa správala ako benígna prevádzka, na ktorej sa
model učil. Nie je to dôkaz, že hosť je čistý. `ANOMÁLIA` je odchýlka od tej istej
prevádzky, nie verdikt o malvéri (`HONESTY.md`, P4). Miera falošných alarmov je
v `docs/MERANIA.md` a `docs/STAV.sk.md` (R13).

## Testy

```sh
python3 -m pytest -q TCN-gui/tests
```

Testy natrénujú malý syntetický balík zo `safeguard.demo` a overia:
- zhodu skóre s detektorom;
- presný rozklad skóre na globálne príznaky a najhorší bin;
- alarm pri umelej odchýlke v jednom bine;
- odmietnutie diagnostického balíka bez povolenia;
- vykreslenie obrázka bez okna;
- kontrolu priečinka v aplikácii (preskočí sa bez grafického displeja);
- nezávislosť CKA od poradia kanálov a porovnanie dvoch tréningov.
