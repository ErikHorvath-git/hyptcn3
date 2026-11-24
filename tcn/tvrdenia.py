"""
tvrdenia.py - potvrdzujuce tvrdenia K1, K2a a K2b: hodnoty po bootoch, interval, test a tri vysledky (balik B7a).

Kostra dokazy/B7/kostra/KOSTRA.md bod 4 a navrh NAVRH_B7a 1.5; NAVRH_PROTOKOL_V5 kap. 4.1, 8.4, 9.1 a 9.2,
rozhodnutie D14. Modul je cisty: cita plan analyzy protokolu (scripts/protocol_v5.py analysis_plan) a hodnoty, ktore
mu da volajuci; ziadny archiv, prehratie ani rolu neotvara (testovacie roly skoruje az finalny prikaz baliku B7c).

  hodnoty_k1(protokol, straty_modelu, straty_metod, booty, ciste)
      zlepsenie I = 1 - strata(M) / strata(Z) na boot nad cistymi skorovanymi oknami roly, pre kazdu metodu
      analysis.k1.compare (Z3, Z5) zvlast; M vstupuje medianom strat svojich seedov analysis.seeds na boot (D14)
      a kazdy seed sa uvedie. Hranicu m nepotrebuje: z tychto hodnot ju urcuje stupen G1.
  rozhodni(protokol, tvrdenie, hodnoty, *, rezim)
      pre kazdu porovnavanu metodu percentilovy interval bootstrapom cez booty a obojstranny test zamenou
      znamienka hodnot (hodnota - m), oba z prudu bootstrap tohto porovnania; jeden z troch vysledkov (vysledok) a
      znenie zaveru z analysis.wording. Hranicu m null odmietne menom (analysis.<tvrdenie>.m). K2a a K2b (balik
      B7b) mu davaju svoje hodnoty D po bootoch.
  k1(protokol, straty_modelu, straty_metod, booty, ciste, *, rezim, rola)
      oboje pre tvrdenie K1; hranicu m null odmietne skor, nez cokolvek pocita.
  vysledok(intervaly, m)
      cista funkcia troch vysledkov: better, not_better, undecided (kluce analysis.wording).

Okna, ich straty a priznak cistej prevadzky dava volajuci (navrh B7a 1.1 az 1.3: tie iste okna a normalizer
balika M pre vsetky metody, strata je treningova strata safeguard/model.py LOSS_FORMULA; cista prevadzka su
skorovane okna mimo udalosti a ich dozvuku analysis.reverberation_s, navrh kap. 4.2, tcn/metody.py CLEAN_RULE:
otazka Q12, prijate veducim 2026-11-24, balik B7b; pasmo plnej snimky do nej nepatri).

Balik B7b (otazka Q13, prijate veducim 2026-11-24): K2a porovnava oba varianty Z4 ako dve
porovnania Z4:load a Z4:residual (analysis.k2a.compare), kazde s vlastnym prudom bootstrap (k2a/Z4:load,
k2a/Z4:residual); rozhodni ich berie z planu analyzy bez zmeny kodu a "lepsi" vyzaduje prekonat oba.
"""

from fractions import Fraction
import math

import numpy as np

SCHEMA = "hyptcn3/confirmatory-claim/1"
# Ako sa ratuje interval a test (analysis.statistics.note; text ide do zaznamu).
INTERVAL = ("percentile bootstrap of the mean over the boots: analysis.statistics.bootstrap resamples of the boots "
            "with replacement drawn first from the stream bootstrap of the comparison, the bounds the quantiles "
            "(1 - level)/2 and (1 + level)/2 of their means (numpy, method linear)")
TEST = ("two-sided sign-flip permutation test of the values minus m over the boots, statistic their sum computed "
        "exactly: all 2^n sign vectors up to analysis.statistics.exact_up_to_boots boots, else "
        "analysis.statistics.bootstrap random sign vectors drawn after the resamples, p = (1 + count) / (1 + vectors)")
# Usudok (analysis.statistics.note): bootstrap cez jeden boot nema rozptyl, tvrdenie sa nad nim nerozhoduje.
NAJMENEJ_BOOTOV = 2
NEHODNOTENY = "no clean scored window"  # Pomenovane pravidlo: boot bez cisteho skorovaneho okna do K1 nevstupuje.


def _plan(protokol):
    from scripts import protocol_v5  # Vo vnutri: scripts/ importuje features/, tcn/ ho nepotrebuje pri importe.
    return protocol_v5, protocol_v5.analysis_plan(protokol)


def _cislo(x):
    return isinstance(x, (int, float, np.integer, np.floating)) and not isinstance(x, (bool, np.bool_)) \
        and math.isfinite(x)


def _hranica(a, tvrdenie):
    """Hranica m tvrdenia zo skontrolovaneho planu analyzy; null odmietne menom (navrh B7a 1.5: m je null do G1)."""
    m = a[tvrdenie]["m"]
    if m is None:
        raise ValueError(f"analysis.{tvrdenie}.m je null: hranicu m urcuje stupen G1 (determined_at), tvrdenie "
                         f"{tvrdenie} sa bez nej nerozhoduje")
    return float(m)


def _rezim(protocol_v5, rezim):
    """Rezim planu (campaign alebo rehearsal) nema predvolbu: urcuje meno planu, z ktoreho su seedy prudov."""
    if rezim not in protocol_v5.MODES:
        raise ValueError(f"rezim planu {rezim!r} nie je jeden z {', '.join(protocol_v5.MODES)}")


def _metody(nazov, dane, planovane, cesta):
    """Kluce `dane` su presne `planovane` (seedy alebo metody planu analyzy na ceste `cesta`)."""
    if type(dane) is not dict:
        raise ValueError(f"{nazov} su objekt {{kluc: hodnoty}} podla {cesta}")
    if set(dane) != set(planovane):
        raise ValueError(f"{nazov} su pre {sorted(dane, key=str)}, {cesta} je {list(planovane)}")


# ------------------------------------------------------------------ hodnoty K1


def _booty(booty):
    """Zoznam nazvov bootov (bootova skupina je jeden boot VM, jej nazov je text)."""
    booty = list(booty)
    if not booty or not all(type(b) is str and b for b in booty):
        raise ValueError("boot okna je nazov jeho bootovej skupiny (neprazdny text)")
    return booty


def _straty_okien(nazov, straty, n, ciste):
    x = np.asarray(straty, dtype=float)
    if x.shape != (n,):
        raise ValueError(f"straty {nazov} maju tvar {x.shape}, booty a ciste {n} okien")
    zle = np.flatnonzero(ciste & ~(np.isfinite(x) & (x >= 0)))
    if len(zle):
        raise ValueError(f"strata {nazov} na cistom okne {int(zle[0])} nie je konecne nezaporne cislo: "
                         f"{float(x[zle[0]])!r}")
    return x


def hodnoty_k1(protokol, straty_modelu, straty_metod, booty, ciste):
    """Zlepsenie I = 1 - strata(M) / strata(Z) na boot pre kazdu metodu analysis.k1.compare (kap. 4.1, 8.4).

    Vstupy su zarovnane po oknach: i-te okno patri bootu booty[i], ciste[i] hovori, ci lezi v cistej prevadzke, a
    jeho strata je straty_modelu[seed][i] pre kazdy seed modelu M a straty_metod[metoda][i] pre kazdu metodu.
    Strata bootu je priemer strat jeho cistych okien. M vstupuje medianom strat svojich seedov na boot (D14); seedy
    musia byt presne analysis.seeds a metody presne analysis.k1.compare. Kazdy seed ma aj vlastne I (uvedie sa).
    Boot bez cisteho okna do K1 nevstupuje a zaznam ho uvedie (unevaluated_boots); menej nez NAJMENEJ_BOOTOV
    hodnotenych bootov sa odmietne. Hranicu m nepotrebuje.
    """
    _, a = _plan(protokol)
    seedy, metody = list(a["seeds"]), list(a["k1"]["compare"])
    _metody("straty modelu M", straty_modelu, seedy, "analysis.seeds (M vstupuje medianom vsetkych svojich seedov na "
            "boot, D14)")
    _metody("straty metod", straty_metod, metody, "analysis.k1.compare")
    booty = _booty(booty)
    n = len(booty)
    ciste = np.asarray(ciste)
    if ciste.dtype != bool or ciste.shape != (n,):
        raise ValueError(f"ciste je {n} pravdivostnych hodnot, jedna na okno (dostal {ciste.dtype} {ciste.shape})")
    model = {s: _straty_okien(f"M seedu {s}", straty_modelu[s], n, ciste) for s in seedy}
    ostatne = {z: _straty_okien(f"metody {z}", straty_metod[z], n, ciste) for z in metody}
    nazvy, kde = np.unique(np.asarray(booty), return_inverse=True)
    pocty = np.bincount(kde, weights=ciste.astype(float), minlength=len(nazvy)).astype(int)
    okna = {str(b): int(c) for b, c in zip(nazvy, pocty)}
    hodnotene = [str(b) for b, c in zip(nazvy, pocty) if c]
    if len(hodnotene) < NAJMENEJ_BOOTOV:
        raise ValueError(f"{len(hodnotene)} bootov s cistym skorovanym oknom, K1 ich potrebuje aspon "
                         f"{NAJMENEJ_BOOTOV} (usudok: jeden boot nema rozptyl)")

    def po_bootoch(x):
        sucty = np.bincount(kde, weights=np.where(ciste, x, 0.), minlength=len(nazvy))
        return {str(b): float(s / c) for b, s, c in zip(nazvy, sucty, pocty) if c}
    strata_m = {s: po_bootoch(x) for s, x in model.items()}
    median = {b: float(np.median([strata_m[s][b] for s in seedy])) for b in hodnotene}
    vysledky = {}
    for z in metody:
        strata_z = po_bootoch(ostatne[z])
        nula = [b for b in hodnotene if not strata_z[b] > 0]
        if nula:
            raise ValueError(f"strata metody {z} v boote {nula[0]} je {strata_z[nula[0]]!r}: zlepsenie I = 1 - "
                             "strata(M) / strata(Z) potrebuje kladnu stratu metody")
        hodnoty = {b: 1 - median[b] / strata_z[b] for b in hodnotene}
        za_seedy = []
        for s in seedy:
            mine = {b: 1 - strata_m[s][b] / strata_z[b] for b in hodnotene}
            za_seedy.append({"seed": s, "values": mine, "mean": float(np.mean(list(mine.values())))})
        vysledky[z] = {"loss": strata_z, "values": hodnoty, "mean": float(np.mean(list(hodnoty.values()))),
                       "per_seed": za_seedy}
    return {"seeds": seedy, "boots": hodnotene, "windows": okna,
            "unevaluated_boots": {b: NEHODNOTENY for b, c in okna.items() if not c},
            "model": {"median_loss": median, "per_seed_loss": [{"seed": s, "loss": strata_m[s]} for s in seedy]},
            "methods": vysledky}


# ------------------------------------------------------------------ interval a test


def percentilovy_interval(hodnoty, *, vyberov, uroven, generator):
    """Percentilovy bootstrap priemeru hodnot po bootoch: `vyberov` vyberov n bootov s opakovanim (indexy
    generator.integers(0, n, (vyberov, n)), prve cerpanie prudu), priemer kazdeho; hranice su kvantily
    (1 - uroven) / 2 a (1 + uroven) / 2 tychto priemerov (numpy, metoda linear). (dolna, horna)."""
    x = np.asarray(hodnoty, dtype=float)
    if x.ndim != 1 or len(x) < NAJMENEJ_BOOTOV or not np.isfinite(x).all():
        raise ValueError(f"interval potrebuje aspon {NAJMENEJ_BOOTOV} konecne hodnoty po bootoch")
    priemery = x[generator.integers(0, len(x), size=(vyberov, len(x)))].mean(axis=1)
    dolna, horna = np.quantile(priemery, [(1 - uroven) / 2, (1 + uroven) / 2])
    return float(dolna), float(horna)


def _cele(hodnoty):
    """Hodnoty ako cele cisla s jednym spolocnym menovatelom (float je dvojkovy zlomok, takze presne): sucty sa
    potom porovnavaju bez zaokruhlenia a rovnost dvoch suctov rozhodne ich hodnota, nie poradie scitania."""
    zlomky = [Fraction(float(x)) for x in hodnoty]
    menovatel = math.lcm(*(z.denominator for z in zlomky))
    return [int(z * menovatel) for z in zlomky]


def zamena_znamienka(odchylky, *, presne_do, vyberov, generator):
    """Obojstranny permutacny test zamenou znamienka odchylok d (hodnota - m) po bootoch: p je podiel vektorov
    znamienok e, pri ktorych |sum e_i d_i| >= |sum d_i| (kap. 8.4, 9.1; obojstranny, ako ho rata kap. 9.2: 4 booty
    nedaju p pod 0,125, 8 bootov pod 0,008). Pri n <= presne_do bootoch uplnym vymenovanim 2^n vektorov (v poradi
    Grayovho kodu; generator sa necerpa), inak z `vyberov` nahodnych vektorov (bity generator.integers(0, 2,
    (vyberov, n)), 1 je minus) s p = (1 + pocet) / (1 + vyberov) (usudok: pozorovany vektor sa pocita, p nie je
    nikdy 0). Sucty su presne (_cele). {p_value, kind, sign_vectors}."""
    if not len(odchylky) or not all(_cislo(x) for x in odchylky):
        raise ValueError("test potrebuje aspon jednu odchylku, kazdu konecne cislo")
    cele = _cele(odchylky)
    n = len(cele)
    ciel = abs(sum(cele))
    if n <= presne_do:
        sucet, znamienka, pocet = sum(cele), [1] * n, 1  # Vektor samych plus: |sucet| >= |sucet|.
        for k in range(1, 1 << n):
            j = (k & -k).bit_length() - 1  # Susedne kody Grayovho kodu sa lisia v bite j.
            sucet -= 2 * znamienka[j] * cele[j]
            znamienka[j] = -znamienka[j]
            pocet += abs(sucet) >= ciel
        return {"p_value": pocet / (1 << n), "kind": "exact", "sign_vectors": 1 << n}
    pocet = 0
    for bity in generator.integers(0, 2, size=(vyberov, n)).tolist():
        pocet += abs(sum(-c if b else c for b, c in zip(bity, cele))) >= ciel
    return {"p_value": (1 + pocet) / (1 + vyberov), "kind": "random", "sign_vectors": vyberov}


# ------------------------------------------------------------------ tri vysledky a znenie


def vysledok(intervaly, m):
    """Jeden z troch vysledkov (kap. 4.1, 8.4) z intervalov {metoda: (dolna, horna)} porovnavanych metod skupiny
    voci hranici m: "better", ked je dolna hranica nad m voci kazdej metode; "not_better", ked je horna hranica pod
    m pri niektorej; inak "undecided". Cista funkcia; hranicu m null odmietne."""
    if m is None:
        raise ValueError("hranica m je null: urcuje ju stupen G1 (determined_at), bez nej sa tvrdenie nerozhoduje")
    if not _cislo(m):
        raise ValueError(f"hranica m {m!r} nie je konecne cislo")
    if not intervaly:
        raise ValueError("vysledok potrebuje aspon jednu porovnavanu metodu")
    for metoda, interval in intervaly.items():
        if not (type(interval) in (list, tuple) and len(interval) == 2 and _cislo(interval[0])
                and _cislo(interval[1]) and interval[0] <= interval[1]):
            raise ValueError(f"interval metody {metoda} {list(interval)!r} nie je [dolna, horna] z konecnych cisel "
                             "s dolna <= horna")
    if all(dolna > m for dolna, _ in intervaly.values()):
        return "better"
    if any(horna < m for _, horna in intervaly.values()):
        return "not_better"
    return "undecided"


def _cislom(x):
    return f"{x:.4g}"


def _doplnenie(vysledok_, metody, poradie, m):
    """Co patri na miesta znenia (kap. 8.4), v poradi: better - porovnavane metody a rozdiel voci kazdej (priemer a
    interval); not_better - metody s hornou hranicou pod m; undecided - interval kazdej metody."""
    def interval(z):
        dolna, horna = metody[z]["interval"]
        return f"[{_cislom(dolna)}, {_cislom(horna)}]"
    if vysledok_ == "better":
        return [", ".join(poradie), "; ".join(f"{z} {_cislom(metody[z]['mean'])} {interval(z)}" for z in poradie)]
    if vysledok_ == "not_better":
        return [", ".join(z for z in poradie if metody[z]["interval"][1] < m)]
    return ["; ".join(f"{z} {interval(z)}" for z in poradie)]


def _rozhodujuce(vysledok_, metody, poradie, m):
    """Metody, ktore vysledok urcili: better vsetky, not_better tie s hornou hranicou pod m, undecided tie, ktorych
    dolna hranica nie je nad m."""
    if vysledok_ == "better":
        return list(poradie)
    if vysledok_ == "not_better":
        return [z for z in poradie if metody[z]["interval"][1] < m]
    return [z for z in poradie if not metody[z]["interval"][0] > m]


def rozhodni(protokol, tvrdenie, hodnoty, *, rezim):
    """Interval, test, vysledok a znenie jedneho potvrdzujuceho tvrdenia (k1, k2a, k2b) z hodnot po bootoch
    {metoda: {boot: hodnota}} voci kazdej metode analysis.<tvrdenie>.compare (kap. 4.1, 8.4, 9.1; kostra B7 bod 4).

    Hranica m je analysis.<tvrdenie>.m (null odmietne menom), parametre su analysis.statistics. Kazde porovnanie
    <tvrdenie>/<metoda> ma svoj prud bootstrap (scripts/protocol_v5.py analysis_seed v rezime planu `rezim`, ktory
    nema predvolbu): numpy.random.default_rng jeho seedu cerpa najprv vybery intervalu, potom (nad
    exact_up_to_boots bootmi) vektory testu. Vsetky metody maju tie iste booty. Rozhoduje interval, p-hodnota sa
    uvedie; znenie je analysis.wording.<tvrdenie>.<vysledok> slovo od slova a conclusion ho doplni na miestach ….
    """
    protocol_v5, a = _plan(protokol)
    if tvrdenie not in protocol_v5.CLAIMS:
        raise ValueError(f"{tvrdenie!r} nie je potvrdzujuce tvrdenie ({', '.join(protocol_v5.CLAIMS)})")
    m = _hranica(a, tvrdenie)
    _rezim(protocol_v5, rezim)
    poradie = list(a[tvrdenie]["compare"])
    _metody(f"hodnoty tvrdenia {tvrdenie}", hodnoty, poradie, f"analysis.{tvrdenie}.compare")
    booty = None
    for z in poradie:
        if type(hodnoty[z]) is not dict or not all(_cislo(v) for v in hodnoty[z].values()):
            raise ValueError(f"hodnoty metody {z} nie su {{boot: konecne cislo}}")
        mine = sorted(_booty(hodnoty[z]))
        if booty is not None and mine != booty:
            raise ValueError(f"metody tvrdenia {tvrdenie} maju rozne booty: {poradie[0]} {booty}, {z} {mine}")
        booty = mine
    if len(booty) < NAJMENEJ_BOOTOV:
        raise ValueError(f"{len(booty)} bootov, tvrdenie potrebuje aspon {NAJMENEJ_BOOTOV} (usudok: jeden boot nema "
                         "rozptyl)")
    s = a["statistics"]
    metody = {}
    for z in poradie:
        jednotka = f"{tvrdenie}/{z}"
        seed = protocol_v5.analysis_seed(protokol, "bootstrap", jednotka, mode=rezim)
        generator = np.random.default_rng(seed)
        x = [float(hodnoty[z][b]) for b in booty]
        dolna, horna = percentilovy_interval(x, vyberov=s["bootstrap"], uroven=s["level"], generator=generator)
        test = zamena_znamienka([v - m for v in x], presne_do=s["exact_up_to_boots"], vyberov=s["bootstrap"],
                                generator=generator)
        metody[z] = {"values": dict(zip(booty, x)), "mean": float(np.mean(x)), "interval": [dolna, horna],
                     "p_value": test["p_value"], "test": {"kind": test["kind"], "sign_vectors": test["sign_vectors"]},
                     "stream": {"purpose": "bootstrap", "unit": jednotka, "seed": seed}}
    vysledok_ = vysledok({z: metody[z]["interval"] for z in poradie}, m)
    znenie = a["wording"][tvrdenie][vysledok_]
    doplnenie = _doplnenie(vysledok_, metody, poradie, m)
    casti = znenie.split(protocol_v5.BLANK)  # Kontrola planu: tolko miest, kolko ich vysledok doplna (BLANKS).
    return {"schema": SCHEMA, "claim": tvrdenie, "mode": rezim, "statistic": a[tvrdenie]["statistic"], "m": m,
            "compare": poradie, "level": s["level"], "bootstrap": s["bootstrap"],
            "exact_up_to_boots": s["exact_up_to_boots"], "interval_rule": INTERVAL, "test_rule": TEST,
            "boots": booty, "methods": metody, "outcome": vysledok_,
            "decisive_methods": _rozhodujuce(vysledok_, metody, poradie, m), "wording": znenie, "fill": doplnenie,
            "conclusion": "".join(c + d for c, d in zip(casti, doplnenie + [""])), "numpy": np.__version__}


def k1(protokol, straty_modelu, straty_metod, booty, ciste, *, rezim, rola):
    """Tvrdenie K1 (kap. 4.1, 8.4; kostra B7 bod 4) nad oknami roly `rola`: hodnoty_k1 a rozhodni. Hranicu
    analysis.k1.m null odmietne menom skor, nez cokolvek pocita (finalny prikaz baliku B7c preto tiez). Zaznam
    rozhodni doplni o rolu, pocty cistych okien po bootoch, nehodnotene booty, straty modelu (median a kazdy seed)
    a pri kazdej metode jej straty a I kazdeho seedu."""
    protocol_v5, a = _plan(protokol)
    _hranica(a, "k1")
    _rezim(protocol_v5, rezim)
    if type(rola) is not str or not rola:
        raise ValueError("rola okien K1 je nazov roly (neprazdny text)")
    h = hodnoty_k1(protokol, straty_modelu, straty_metod, booty, ciste)
    out = rozhodni(protokol, "k1", {z: v["values"] for z, v in h["methods"].items()}, rezim=rezim)
    for z, v in out["methods"].items():
        v.update(loss=h["methods"][z]["loss"], per_seed=h["methods"][z]["per_seed"])
    poradie = list(out)
    pred = poradie.index("boots") + 1
    pridane = {"role": rola, "seeds": h["seeds"], "windows": h["windows"], "unevaluated_boots": h["unevaluated_boots"],
               "model": h["model"]}
    return {**{k: out[k] for k in poradie[:pred]}, **pridane, **{k: out[k] for k in poradie[pred:]}}
