# TCN-gui: jedno okno s výsledkom detektora

Malá desktopová aplikácia (Tkinter a matplotlib, bez servera a prehliadača). Vyberieš
natrénovaný balík `safeguard` a jednu session snímok, napríklad hodinu. Dostaneš jeden
obrázok so štyrmi panelmi:

1. **Skóre anomálie v čase** s kalibrovaným prahom. Červené pásy sú alarmy modelu
   (pravidlo k z n), fialové pásy prevádzkové udalosti z `events.json` (protokol v3)
   a krížiky nálezy kontroly integrity jadra. V nadpise okna je verdikt:
   `BEZ ALARMU`, `ANOMÁLIA`, `NÁLEZ INTEGRITY JADRA`, `NEDOSTATOČNÉ POKRYTIE` alebo `CHYBA VSTUPU`.
2. **Pamäťový chromatogram:** čas × oblasť RAM hosťa (bin, GPA v MiB). Farba je chyba
   predikcie per-bin TCN. Do skóre ide najhorší bin, takže jasné miesto ukazuje, *kde*
   v pamäti sa hosť správa nezvyčajne. Časová os je spoločná s panelom 1.
3. **Ako sa sieť učila:** strata predikcie a klasifikácie na `train` a `dev` po
   epochách a vybraná epocha (najnižšia strata na `dev`). V nadpise je počet okien podľa rolí.
4. **Klasifikácia záťaže v čase:** pravdepodobnosti scenárov z tréningu a v nadpise
   prevažujúci scenár a zaznamenaný scenár session. Klasifikátor opisuje druh
   prevádzky, nie škodlivosť.

Prehratie ide cez `safeguard.runtime.Detector` (`analyza.py`), takže skóre, prah
aj alarmy sú presne tie, ktoré by vydal detektor pri ostrom behu. Test
`tests/test_analyza.py` to porovnáva s `replay_archive`.

## Spustenie

```sh
python3 TCN-gui/tcn_gui.py                       # okno, model a snímky sa vyberú tlačidlami
python3 TCN-gui/tcn_gui.py --bundle data/models/server-v2-benign-v6 --input data/collections/<session>
python3 TCN-gui/tcn_gui.py --bundle ... --input ... --png session.png   # bez okna, iba obrázok
```

Na zberovom PC sa použije `.venv/bin/python`. Lišta matplotlib pod obrázkom slúži na
zväčšenie výrezu a uloženie obrázka.

- **Model:** adresár balíka so súborom `manifest.json`. Diagnostický (syntetický)
  balík sa načíta iba so začiarknutím voľby „diagnostický balík“ alebo s `--diagnostic`.
- **Snímky:** jedna z možností:
  - archív príznakov session (`.npz`, napríklad `campaign_audit_*.npz`);
  - adresár session, z ktorého sa vezme najnovší archív;
  - adresár so snímkami `.vmicd` a ich sidecarmi (alebo session s podadresárom `raw/`).
    Tie sa extrahujú cez `guestparse` s profilom `profiles/debian12-6.1.0-42-cloud-amd64`.

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
- vykreslenie obrázka bez okna.
