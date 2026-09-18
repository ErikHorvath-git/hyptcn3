# Per-bin príznakový vektor — Pythonová referencia (krok K14)

Tento súbor popisuje `features/perbin.py`, `features/crosscheck.py` a ich CLI.
Moduly `windows.py`, `normalize.py` a `manifest.py` patria ku kroku K15 a majú
vlastnú dokumentáciu vo svojich docstringoch.

## Prečo referencia existuje

Ten istý vektor počíta aj C modul (`vmicollect/src/perbin.c`, krok K13). Keď to
isté číslo vyrobia dve nezávislé implementácie, je to doklad, že vzorec je
správne zapísaný. Keď sa rozídu, jedna z nich je zlá a vie sa to hneď — nie až
po tom, čo sa na tom natrénuje model.

Referencia preto zámerne nepoužíva nič z `vmicollect/`: snímku číta cez
`guestparse.image`, rozsahy memslotov dostáva zvonku a všetko ostatné si počíta
sama.

## Kontrakt príznaku

Binuje sa **iba nad rozsahmi z memslotov**. Bin, ktorý nepretína žiadny
memslot, neexistuje — nevzniká ako nulový riadok. Dôvod: fyzický priestor x86
je deravý (VGA diera `0xA0000–0xBFFFF`, PCI diera pod 4 GiB). Pri doméne
`hyptcn-guest` je RAM 2,02 GiB, ale `max_paddr` 4 GiB, takže pri bine 16 MiB by
z 256 binov bolo 125 trvale nulových a model by sa učil na výplň. Namerané nad
touto doménou: **131 binov** (0–127, 251, 254, 255).

Index binu `= GPA >> log2(bin_bytes)`, teda je viazaný na fyzickú adresu, nie na
poradie memslotu. Veľkosť binu je parameter (`--bin-bytes`, východzie 16 MiB);
musí byť mocnina dvojky a násobok veľkosti stránky, inak taký posun neexistuje
a index by sa od C rozchádzal ticho.

Na každý bin:

| pole | význam |
|---|---|
| `bin` | index binu |
| `gpa` | začiatočná fyzická adresa binu |
| `pages_total` | koľko stránok binu je naozaj podložených memslotmi (menovateľ pomerov) |
| `pages_changed` | koľko stránok sa od predchádzajúcej snímky zmenilo |
| `changed_ratio` | `pages_changed / pages_total` |
| `zero_ratio` | podiel nulových stránok zo všetkých podložených stránok binu |
| `entropy_mean` | priemerná Shannonova entropia (bity na bajt, 0–8) **zmenených** stránok |
| `has_changed` | 0/1 — samostatný príznak, aby sa „bin sa nezmenil“ dalo odlíšiť od „entropia vyšla 0“ |

Ticho doplnená nula je zakázaná: keď `has_changed == 0`, je `entropy_mean`
nulová preto, že nebolo z čoho priemerovať, a hovorí to `has_changed`.

## Čo je „zmenená“ a čo „nulová“ stránka

**Zmenená** stránka = stránka zapísaná v `.vmicd` súbore tejto snímky. Delta
writer zapisuje presne tie stránky, ktorých 64-bitový hash sa líši od
predchádzajúceho cyklu. Pri plnej snímke je predchádzajúci stav nulový, takže
„zmenené“ = všetky nenulové stránky.

**Nulová** stránka sa berie z rekonštruovaného stavu pamäte v čase tejto
snímky, teda z celého reťazca po ňu vrátane — nie iba z jednej delty. Stránka,
ktorá v reťazci nie je, je nulová.

Toto je miesto, kde sú obe implementácie skutočne nezávislé a kde krížová
kontrola overuje aj niečo navyše:

- C testuje nulovosť na stránke **tak, ako ju práve prečítal z bežiacej VM**
  (`vmic_is_zero`, presné porovnanie, nie zhoda hashu s hashom nulovej stránky);
- referencia ju testuje na stránke **zrekonštruovanej z reťazca `.vmicd`**.

Zhoda `zero_ratio` teda zároveň hovorí, že reťazec delt reprodukuje to, čo
zberač videl. Rozdiel by mohol znamenať aj kolíziu 64-bitového hashu s hashom
nulovej stránky — a práve preto sa to nemá zakrývať.

Entropia sa počíta dvomi rôznymi cestami: C používa tabuľkovú podobu
`H = log2(n) − (1/n)·Σ c_j·log2(c_j)`, referencia priamo `−Σ p·log2(p)`.
Algebraicky je to to isté, numericky nie — preto sa desatinné polia porovnávajú
s toleranciou (východzie `5e-7`, keďže C tlačí `%.6f`), celočíselné bez nej.

## Rozsahy memslotov sa nehádajú

V hlavičke `.vmicd` je iba logická veľkosť (koniec poslednej oblasti) a
`region_sig` — 64-bitový podpis konfigurácie oblastí, z ktorého sa rozsahy
spätne odvodiť nedajú. Sidecar snímky má v `capture.regions` **konfiguráciu
zberu** (`[capture].regions`), nie memsloty, a pri zbere celej RAM je to prázdne
pole — vo všetkých dnešných sidecaroch je `"regions": []`.

**Referencia preto potrebuje zdroj rozsahov zvonku a bez neho odmietne
počítať.** Prijíma (v tomto poradí):

1. `values.memslot_ranges` — výstup `vmicollect probe -v`; dnes jediný zdroj,
   ktorý skutočné memsloty má (v repozitári:
   `data/results/2026-09-18_zmrazeny_host/probe.json`);
2. `features.memslots` — miesto, kam ich môže zapísať C modul; podporované
   dopredu, aby sa referencia nemusela meniť;
3. `memslots` — holý zoznam v ručne pripravenom súbore;
4. neprázdne `capture.regions` — vtedy sa zdroj pomenuje tak, aby bolo vidieť,
   že ide o konfiguráciu zberu, nie o memsloty.

Použitý zdroj je vždy vo výstupe pod `memslots.source`.

## Invarianty

Testované pri každom behu (`kontrola` vo výstupe, `--out` v krížovej kontrole):

- Σ `pages_changed` cez biny == `output.pages_changed` zo sidecaru,
- Σ `pages_total` cez biny == `output.pages_total` (= počet podložených
  stránok VM),
- žiadna stránka rekonštruovaného stavu neleží mimo memslotov.

## Použitie

```sh
# vektor jednej snímky
python3 -m features perbin \
    --snapshot data/sessions/20260918_validate2/snap \
    --memslots data/results/2026-09-18_zmrazeny_host/probe.json

# krížová kontrola celého reťazca proti výstupu C modulu
python3 -m features crosscheck \
    --snapshot /var/tmp/vmic-delta \
    --memslots data/results/2026-09-18_zmrazeny_host/probe.json \
    --c data/results/perbin_c_<dátum>/ \
    --out data/results/perbin_crosscheck_<dátum>.json
```

Návratové kódy: `0` = prebehlo a nič sa nerozišlo, `1` = nezhoda (padol
invariant alebo sa C a referencia líšia), `2` = chyba vstupu.

## Testy

```sh
python3 -m pytest features/tests -q
```

Testy kontraktu binovania a definícií príznakov bežia vždy (počítajú sa nad
vymyslenými memslotmi a nad stránkami so známym obsahom). Testy invariantov
potrebujú snímky mimo repozitára (`/var/tmp/vmic-val`, `/var/tmp/vmic-delta`,
`data/sessions/*/snap/*.vmicd` — `.vmicd` je v `.gitignore`) a v čerstvom klone
sa **preskočia**. Preskočený test nie je prešiel; na stroji, kde snímky sú, sa
preskočenie zakáže premennou `FEATURES_REQUIRE_REAL=1`.

## Výsledok krížovej kontroly (2026-09-18)

Porovnávalo sa proti behu `vmicollect` z 2026-09-18 19:02–19:03 UTC (6 snímok,
perióda 5 s, doména `hyptcn-guest`), tri konfigurácie `[features]`. Sidecary z C
sú v repozitári v `data/results/perbin_c_20260918/sidecars/`, snímky `.vmicd`
k nim ležia mimo repozitára v `/var/tmp/perbin_c/`.

| artefakt | konfigurácia | snímok | porovnaných polí | rozdielov |
|---|---|---|---|---|
| `data/results/perbin_crosscheck_20260918.json` | `enable=true, entropy=true` | 6 | 6288 | 0 |
| `data/results/perbin_crosscheck_20260918_noent.json` | `enable=true, entropy=false` | 6 | 5502 | 0 |
| `data/results/perbin_crosscheck_20260918_off.json` | `enable=false` | 6 | — (blok `features` v sidecari nie je) | — |
| `data/results/perbin_crosscheck_20260918_starsie.json` | snímky z 2026-09-18 14:31, zozbierané pred K13 | 6 | — (blok `features` v sidecari nie je) | — |

6288 = 6 snímok × 131 binov × 8 polí; pri vypnutej entropii 7 polí, teda 5502.

Zhoda je na **všetky miesta, ktoré C do sidecaru vytlačí** (`%.6f`): počet polí,
kde sa referencia zaokrúhlená na 6 desatinných miest líši od hodnoty z C, je
vo všetkých troch behoch **0**. Najväčší absolútny rozdiel pred zaokrúhlením je
rádu `5e-7`, teda presne polovica posledného tlačeného miesta — to je
zaokrúhlenie výpisu, nie rozdiel v algoritme. Presnejšie sa zo sidecaru porovnať
nedá; číslo za šiestym miestom v ňom nie je.

Invariant proti sidecarom zberača (Σ `pages_changed` = `output.pages_changed`,
Σ `pages_total` = `output.pages_total`) platí vo všetkých štyroch artefaktoch,
teda aj nad snímkami, ku ktorým vektor z C neexistuje.
