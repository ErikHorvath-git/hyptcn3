# Prvý beh zberača – 2026-09-18

Obsah tohto adresára je import meraní z 2026-09-18 (krok K04 plánu). Sú to jediné
čísla o zbere snímok, ktoré sa smú v práci citovať s dátumom 2026-09-18.

## Čo tu je

| Cesta | Čo to je |
|---|---|
| `sidecars/vmic-test/` | 1 sidecar: `once`, writer `raw`, predvolený `output.hash=sha256` |
| `sidecars/vmic-delta/` | 6 sidecarov: `run`, writer `delta`, perióda 5 s, 6 cyklov (#0 plná, #1–#5 prírastkové) |
| `sidecars/vmic-nohash/` | 1 sidecar: ten istý `once`/`raw` ako vyššie, ale s `output.hash=none` |
| `sidecars/vmic-val/` | 1 sidecar: plná delta snímka odobratá pre validáciu parsera |
| `ground_truth/ps_before.txt`, `ps_after.txt` | `ps -eo pid,comm` v hosťovi pred a po snímke z `vmic-val` |
| `env.json` | prostredie merania – hostiteľ, hosť, verzie nástrojov, commit |
| `summary.json` | strojovo čitateľný súhrn; naň ukazujú značky zdroja v texte práce (formát značky je v `HONESTY.md` a v `scripts/check_claims.sh`) |
| `snapshots.json` | identita samotných `.vmicd`/`.raw` súborov a kontrola ich sha256 |
| `make_summary.py` | generátor `summary.json` zo sidecarov |
| `SHA256SUMS` | kontrolné súčty všetkých súborov v tomto adresári |

Samotné snímky (`.vmicd`, `.raw`) tu **nie sú** – majú stovky MiB až 4 GiB (riedky
súbor) a `.gitignore` ich vylučuje. Zostávajú v `/var/tmp/vmic-{test,delta,nohash,val}/`
a ich identitu drží `snapshots.json`.

## Čo tieto čísla neznamenajú

1. **Beh nevznikol binárkou z tohto repa.** Zberač bol preložený v scratchpade
   (`vmic-exp/build/vmicollect`, sha256 v `env.json`). Krok K06 má merania zopakovať
   binárkou zostavenou z repa; do tej chvíle sú to čísla o zdrojovom kóde, ktorý je
   v repe ako commit `178ce4f`, nie o zostavenom artefakte repa.
2. **Počet zmeškaných slotov nie je v sidecaroch.** Schéma `vmicollect/1` také pole nemá.
   Čísla 0 / 8 / 0 pochádzajú zo stdout behu, ktorý sa nezachytil do súboru; v
   `summary.json` sú označené `"zdroj": "MERANIA_2026-09-18.md"`.
3. **Pozemná pravda je uložená len pre procesy.** Výstup `lsmod` a `ss -tulpn` sa
   nezachoval, takže zhoda 47/47 modulov a 10/10 počúvajúcich socketov sa dnes z tohto
   adresára overiť nedá – pri opakovaní (K09) sa musí uložiť.
4. **`changed_ratio` plnej snímky nie je miera zmeny medzi snímkami.** Pri prvej snímke
   reťazca hovorí, koľko stránok writer vôbec zapísal (0,134 a 0,224). Mieru zmeny medzi
   snímkami dávajú až prírastkové snímky (0,000513–0,000617).
5. **Rozsah, nie najnižšie číslo.** Čítanie plnej snímky trvalo 430,6–947,4 ms (n = 4) pri
   rôznych writeroch a konfiguráciách; jediné číslo 430,6 ms reprezentatívne nie je.

## Ako sa `summary.json` regeneruje

```
cd data/results/2026-09-18_prvy_beh && python3 make_summary.py
```

Skript číta iba `sidecars/` a `ground_truth/`; hodnoty, ktoré v nich nie sú, má zapísané
priamo v sebe a majú pole `"zdroj"` ukazujúce na `docs/MERANIA.md`.
