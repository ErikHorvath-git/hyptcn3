# Per-bin príznakový vektor počítaný modulom (krok K13) — meranie 2026-09-18

Čo je v tomto adresári:

| Súbor | Obsah |
|---|---|
| `perbin_c_20260918.json` | zhrnutie s hlavičkou proveniencie (`commit`, `date`, `host`, `guest`, `command`, `n`) |
| `sidecars/off/` | 6 sidecarov behu **bez** príznakov (`features.enable=false`) |
| `sidecars/noent/` | 6 sidecarov behu s príznakmi, **bez** entropie |
| `sidecars/on/` | 6 sidecarov behu s východzím nastavením (príznaky **aj** entropia) |
| `logs/*.log` | úplný výstup zberača z každého behu |
| `SHA256SUMS` | kontrolné súčty všetkého vyššie |

Snímky `.vmicd` tu nie sú — plná snímka behu má 482 MiB, do repozitára nepatrí.
Ostali v `/var/tmp/perbin_c/`.

## Ako sa meralo

Tri behy po sebe nad tou istou bežiacou doménou `hyptcn-guest`, každý 6 cyklov
s periódou 5 s, writer `delta`, `output.hash=none`. Cyklus 0 je vždy plná snímka,
cykly 1–5 sú delty.

```
sudo vmicollect run -o vm.domain=hyptcn-guest -o output.writer=delta \
     -o schedule.interval_s=5 -o schedule.max_cycles=6 -o output.hash=none \
     -o output.dir=/var/tmp/perbin_c/<variant> [-o features.enable=... -o features.entropy=...]
```

Behy nebežali súčasne, takže rozdiel `capture_ms` medzi variantmi obsahuje aj
kolísanie záťaže hostiteľa a hosťa. Nezávislým meraním ceny je `compute_ms`,
ktorý si modul meria sám vo writeri (druhý prechod cez blok, v ktorom sa
príznaky počítajú) a zapisuje do bloku `features` v sidecari.

## Koľko binov vzniklo a prečo práve toľko

`bins_total = 131`.

VM má 2,02 GiB RAM v 10 memslotoch, ale `max_paddr` je 4 GiB. Pri rovnomernom
delení celého rozsahu 16 MiB binmi by vzniklo 256 binov, z ktorých by vyše
polovica bola trvale prázdna. Binuje sa preto iba nad memslotmi:

| Rozsah memslotov (po zlúčení) | Biny |
|---|---|
| `0x0 – 0xa0000` a `0xc0000 – 0x80000000` | 0 – 127 (128 binov) |
| `0xfb000000 – 0xfc000000` | 251 |
| `0xfee00000 – 0xfee01000` | 254 |
| `0xfffc0000 – 0x100000000` | 255 |

Spolu 131. Bin 128 neexistuje, lebo hlavná oblasť RAM končí presne na 2 GiB.
Bin 0 má `pages_total = 4064`, nie 4096 — chýba v ňom 32 stránok VGA diery
`0xa0000 – 0xc0000`.

## Invariant

Zo sidecaru `sidecars/on/hyptcn-guest_000003_20260918T190343784Z.json`:

- súčet `pages_total` cez biny = 528 417 = `output.pages_total`
- súčet `pages_changed` cez biny = 242 = `output.pages_changed`

528 417 × 4096 B = 2 164 396 032 B, čo je presne súčet veľkostí memslotov
(`vm.memsize` v tom istom sidecari).

## Cena výpočtu

Medián delta cyklu (cykly 1–5), `capture_ms`:

| Variant | medián | rozdiel oproti „bez príznakov“ |
|---|---|---|
| bez príznakov | 550,4 ms | — |
| príznaky bez entropie | 589,2 ms | +38,8 ms |
| príznaky aj entropia | 596,8 ms | +46,4 ms (+8,4 %) |

Plná snímka (cyklus 0, ~123 000 zmenených stránok):

| Variant | `capture_ms` | `compute_ms` (z modulu) |
|---|---|---|
| bez príznakov | 952,0 ms | — |
| príznaky bez entropie | 989,4 ms | 52,8 ms |
| príznaky aj entropia | 1408,8 ms | 483,8 ms |

Rozdelenie ceny: základ (test nulovej stránky + počítadlá cez všetkých 528 417
stránok) stojí ~51–53 ms na cyklus bez ohľadu na to, koľko sa toho zmenilo.
Entropia sa počíta iba zo zmenených stránok, takže v delta cykle (~200 stránok)
pridá ~1,6 ms, ale v plnej snímke ~431 ms, teda **3,5 µs na zmenenú stránku**.

Preto je `features.entropy` samostatný prepínač. Východzie nastavenie je
zapnuté, aby bol vektor úplný; pri kratšej perióde než 5 s je to prvá vec,
ktorú sa oplatí vypnúť — cyklus sa tým skráti o cenu entropie, a v sidecari
sa to pozná: `"entropy": false` a kľúč `entropy_mean` v binoch chýba
(nedopĺňa sa nula).

## Ukážka binov z reálneho sidecaru

```json
{"bin": 1,   "gpa": 16777216,   "pages_total": 4096, "pages_changed": 40,
 "changed_ratio": 0.009766, "zero_ratio": 0.196777, "entropy_mean": 1.429049, "has_changed": 1}
{"bin": 0,   "gpa": 0,          "pages_total": 4064, "pages_changed": 0,
 "changed_ratio": 0.0,      "zero_ratio": 0.145177, "entropy_mean": 0.0,      "has_changed": 0}
{"bin": 27,  "gpa": 452984832,  "pages_total": 4096, "pages_changed": 0,
 "changed_ratio": 0.0,      "zero_ratio": 1.0,      "entropy_mean": 0.0,      "has_changed": 0}
{"bin": 254, "gpa": 4261412864, "pages_total": 1,    "pages_changed": 0,
 "changed_ratio": 0.0,      "zero_ratio": 1.0,      "entropy_mean": 0.0,      "has_changed": 0}
```

Bin 27 a bin 254 ukazujú, prečo je `has_changed` samostatný príznak:
`entropy_mean = 0` tu neznamená „stránky majú nulovú entropiu“, ale
„v tomto bine sa nič nezmenilo, takže priemer nemá z čoho vzniknúť“.

## Krížová kontrola C vs. nezávislý prepočet

`krizova_kontrola.py` prečíta `.vmicd` súbor (formát je v hlavičke
`vmicollect/src/writer_delta.c`) a nezávisle, v Pythone a numpy, dopočíta
`pages_changed`, `entropy_mean` a — pri plnej snímke — aj `zero_ratio`
pre každý bin. Výstup behu je v `krizova_kontrola.txt`:

- plná snímka, 123 208 zapísaných stránok, 36 binov so zmenou: zhoda,
- delta snímka, 242 zapísaných stránok, 21 binov so zmenou: zhoda.

Tolerancia pri entropii je 5e-6 b/B; ostatné hodnoty sa porovnávajú presne.
Pri delta snímke sa `zero_ratio` nekontroluje — súbor o nezmenených stránkach
mlčí, takže sa z neho odvodiť nedá.
