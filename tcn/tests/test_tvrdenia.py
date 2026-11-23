"""
Testy potvrdzujucich tvrdeni (tcn/tvrdenia.py, balik B7a; navrh NAVRH_B7a 1.5 a 3, kostra B7 bod 4 a riadok B7a
bodu 8): kazdy z troch vysledkov, p-hodnota pre 12 bootov proti rucnemu poctu (vymenovanie 4096 vektorov
znamienok), interval zopakovatelny zo svojho seedu, odmietnuta hranica m null a znenie z protokolu. Hodnoty su
synteticke so znamou odpovedou; ziadny archiv ani rola sa necita. Mena balika B7a sa importuju vo vnutri testov,
aby subor zbieral aj na kode pred nim.
"""

from fractions import Fraction
import itertools
import json
import math
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "config/collection-v5.json"
NAVRH = ROOT / "docs/NAVRH_PROTOKOL_V5.sk.md"
BOOTY = [f"b{i:02d}" for i in range(1, 13)]  # 12 bootov ako rola test_benign v5 (zoradene)
SEEDY = [0, 1, 2, 3, 4]  # analysis.seeds
# Strata seedu s je NASOBOK[s] x strata seedu 2: median je seed 2, priemer (1,016) nie, takze priemer cez seedy
# namiesto medianu by dal ine I.
NASOBOK = {0: .97, 1: .99, 2: 1., 3: 1.02, 4: 1.1}
# I po bootoch (v poradi BOOTY) so znamou odpovedou voci m = 0,1:
VYSOKO = [.3 + .01 * (i % 3) for i in range(12)]  # dolna hranica intervalu vysoko nad m
NULA = [.01 * (i % 3) - .01 for i in range(12)]  # okolo 0: horna hranica pod m
OKOLO = [.4 if i % 2 else -.2 for i in range(12)]  # priemer 0,1 = m: interval obsahuje m
ROZNE = [.21, -.04, .17, .33, .02, .26, -.11, .09, .14, .38, .05, .19]  # 12 roznych hodnot: spojite kvantily
LEVEL = .95


def protokol(m=.1):
    """config/collection-v5.json s hranicou m pre K1, K2a a K2b (v subore null do G1)."""
    doc = json.loads(V5.read_text())
    for tvrdenie in ("k1", "k2a", "k2b"):
        doc["analysis"][tvrdenie]["m"] = m
    return doc


def okna(zlepsenia):
    """Okna so znamou odpovedou: v boote i (BOOTY) tri ciste okna, v ktorych ma model M stratu L = 1 + i/10 pri seede
    2 a L * NASOBOK[s] pri seede s (median je seed 2), a metoda Z stratu L / (1 - I), takze I = 1 - median /
    strata(Z) je I bootu zo `zlepsenia[Z]`; navyse jedno okno mimo cistej prevadzky so stratou 1e9 modelu a NaN
    metody, ktore do K1 nevstupuje."""
    booty, ciste, model, metody = [], [], {s: [] for s in SEEDY}, {z: [] for z in zlepsenia}
    for i, b in enumerate(BOOTY):
        strata = 1 + i / 10
        for _ in range(3):
            booty.append(b)
            ciste.append(True)
            for s in SEEDY:
                model[s].append(strata * NASOBOK[s])
            for z, hodnoty in zlepsenia.items():
                metody[z].append(strata / (1 - hodnoty[i]))
        booty.append(b)
        ciste.append(False)
        for s in SEEDY:
            model[s].append(1e9)
        for z in zlepsenia:
            metody[z].append(math.nan)
    return model, metody, booty, np.array(ciste)


@pytest.mark.parametrize("z5, vysledok, rozhodujuce", [
    (VYSOKO, "better", ["Z3", "Z5"]),
    (NULA, "not_better", ["Z5"]),
    (OKOLO, "undecided", ["Z5"]),
], ids=["better", "not_better", "undecided"])
def test_k1_da_kazdy_z_troch_vysledkov(z5, vysledok, rozhodujuce):
    """Kostra B7 bod 4: lepsi, ked je dolna hranica nad m voci Z3 aj Z5; nie lepsi, ked je horna hranica pod m pri
    niektorej; inak nerozhodnute. I po bootoch je to z konstrukcie, M je median svojich seedov a kazdy seed sa
    uvedie so svojim I; okno mimo cistej prevadzky do K1 nevstupuje."""
    from tcn import tvrdenia
    doc = protokol()
    r = tvrdenia.k1(doc, *okna({"Z3": VYSOKO, "Z5": z5}), rezim="campaign", rola="test_benign")
    assert (r["claim"], r["role"], r["m"], r["outcome"], r["decisive_methods"]) == (
        "k1", "test_benign", .1, vysledok, rozhodujuce)
    assert (r["boots"], r["windows"], r["unevaluated_boots"], r["seeds"]) == (BOOTY, dict.fromkeys(BOOTY, 3), {}, SEEDY)
    strata = {b: 1 + i / 10 for i, b in enumerate(BOOTY)}
    assert r["model"]["median_loss"] == pytest.approx(strata, rel=1e-12)
    assert r["model"]["per_seed_loss"] == [{"seed": s, "loss": pytest.approx({b: L * NASOBOK[s] for b, L in
                                                                              strata.items()}, rel=1e-12)}
                                           for s in SEEDY]
    for z, hodnoty in (("Z3", VYSOKO), ("Z5", z5)):
        mine = r["methods"][z]
        assert mine["loss"] == pytest.approx({b: strata[b] / (1 - v) for b, v in zip(BOOTY, hodnoty)}, rel=1e-12)
        assert mine["values"] == pytest.approx(dict(zip(BOOTY, hodnoty)), abs=1e-12)
        assert [x["seed"] for x in mine["per_seed"]] == SEEDY
        for x in mine["per_seed"]:  # I seedu s: 1 - NASOBOK[s] (1 - I)
            assert x["values"] == pytest.approx({b: 1 - NASOBOK[x["seed"]] * (1 - v) for b, v in zip(BOOTY, hodnoty)},
                                                abs=1e-12)
    dolna, horna = r["methods"]["Z5"]["interval"]
    assert {"better": dolna > .1, "not_better": horna < .1, "undecided": dolna <= .1 <= horna}[vysledok]
    assert r["methods"]["Z3"]["interval"][0] > .1
    assert r["wording"] == doc["analysis"]["wording"]["k1"][vysledok]
    assert r["conclusion"] == "".join(c + d for c, d in zip(r["wording"].split("…"), r["fill"] + [""]))


@pytest.mark.parametrize("intervaly, ocakavany", [
    ({"Z3": (.2, .4), "Z5": (.15, .3)}, "better"),
    ({"Z3": (.2, .4), "Z5": (-.1, .05)}, "not_better"),
    ({"Z3": (.2, .4), "Z5": (.05, .3)}, "undecided"),
    ({"Z3": (.1, .4), "Z5": (.2, .3)}, "undecided"),
    ({"Z3": (-.2, .1), "Z5": (.2, .3)}, "undecided"),
], ids=["better", "not_better", "undecided", "lower_bound_at_m", "upper_bound_at_m"])
def test_vysledok_je_cista_funkcia_intervalov_a_hranice(intervaly, ocakavany):
    """Hranica rovna m nie je nad m ani pod m: obe hranicne pripady su nerozhodnute."""
    from tcn import tvrdenia
    assert tvrdenia.vysledok(intervaly, .1) == ocakavany


@pytest.mark.parametrize("odchylky, pocet", [
    # 10 hodnot +0,25 a 2 hodnoty -0,25: |sum e d| = |2K - 12| / 4 >= 2 prave vtedy, ked je K >= 10 alebo K <= 2 z 12
    # clenov kladnych: 2 x (C(12, 0) + C(12, 1) + C(12, 2)) = 2 x 79 = 158 zo 4096 (rucny pocet).
    ([.25] * 10 + [-.25] * 2, 158),
    # Rozne hodnoty: test vymenuje 4096 vektorov znamienok sam, v presnych zlomkoch.
    ([.31, -.07, .12, .4, -.22, .05, .18, -.13, .27, .09, -.01, .33], None),
    # Kap. 9.2: cez 4 booty test neda p pod 0,125, cez 8 bootov pod 0,008 (obojstranny: 2 z 2^n vektorov).
    ([.5] * 4, 2),
    ([.5] * 8, 2),
], ids=["12_boots_by_hand", "12_boots_enumerated", "4_boots_chapter_9_2", "8_boots_chapter_9_2"])
def test_p_hodnota_proti_rucnemu_poctu(odchylky, pocet):
    """Obojstranny test zamenou znamienka uplnym vymenovanim (najviac 16 bootov): p = pocet vektorov e s
    |sum e_i d_i| >= |sum d_i| z 2^n; prud sa pritom necerpa."""
    from tcn import tvrdenia
    n = len(odchylky)
    if pocet is None:
        presne = [Fraction(x) for x in odchylky]
        ciel = abs(sum(presne))
        pocet = sum(abs(sum(e * x for e, x in zip(znamienka, presne))) >= ciel
                    for znamienka in itertools.product((1, -1), repeat=n))
    generator = np.random.default_rng(0)
    stav = generator.bit_generator.state
    assert tvrdenia.zamena_znamienka(odchylky, presne_do=16, vyberov=10000, generator=generator) == {
        "p_value": pocet / 2 ** n, "kind": "exact", "sign_vectors": 2 ** n}
    assert generator.bit_generator.state == stav
    assert {4: .125, 8: .0078125}.get(n, pocet / 2 ** n) == pocet / 2 ** n


def test_nad_16_bootmi_test_cerpa_nahodne_vektory_z_prudu():
    """Nad analysis.statistics.exact_up_to_boots bootmi je p = (1 + pocet) / (1 + vyberov) z nahodnych vektorov
    (bity generator.integers(0, 2, (vyberov, n)), 1 je minus) a lezi blizko presnej p z 2^17 vektorov (styri
    smerodajne odchylky 10000 vyberov). Hodnoty su nasobky 1/8, sucty v teste su teda presne."""
    from tcn import tvrdenia
    odchylky = [.125 * k for k in (3, -1, 2, 5, -4, 1, 2, -2, 6, 1, -3, 2, 4, -1, 3, 0, 2)]
    vysledok = tvrdenia.zamena_znamienka(odchylky, presne_do=16, vyberov=10000, generator=np.random.default_rng(5))
    ciel = abs(sum(odchylky))
    sucty = (1 - 2 * np.random.default_rng(5).integers(0, 2, size=(10000, 17))) @ np.array(odchylky)
    assert vysledok == {"p_value": (1 + int((np.abs(sucty) >= ciel).sum())) / 10001, "kind": "random",
                        "sign_vectors": 10000}
    vsetky = 1 - 2 * ((np.arange(2 ** 17)[:, None] >> np.arange(17)) & 1)
    assert abs(vysledok["p_value"] - float(np.mean(np.abs(vsetky @ np.array(odchylky)) >= ciel))) < .02


def test_nad_16_bootmi_cerpa_prud_porovnania_najprv_vybery_intervalu_potom_vektory_testu():
    """streams.rule: generator prudu bootstrap porovnania k1/Z3 cerpa najprv 10000 vyberov 17 bootov intervalu a az
    potom 10000 vektorov znamienok testu. Hranica m je tu 0, odchylky su teda hodnoty (nasobky 1/8, presne sucty)."""
    from scripts import protocol_v5
    from tcn import tvrdenia
    booty = [f"c{i:02d}" for i in range(1, 18)]
    hodnoty = [.125 * k for k in (3, -1, 2, 5, -4, 1, 2, -2, 6, 1, -3, 2, 4, -1, 3, 0, 2)]
    r = tvrdenia.rozhodni(protokol(m=0.), "k1", {z: dict(zip(booty, hodnoty)) for z in ("Z3", "Z5")},
                          rezim="campaign")
    generator = np.random.default_rng(protocol_v5.seed("server-normal-v5", "bootstrap", "k1/Z3", -1, 0))
    priemery = np.array(hodnoty)[generator.integers(0, 17, size=(10000, 17))].mean(axis=1)
    sucty = (1 - 2 * generator.integers(0, 2, size=(10000, 17))) @ np.array(hodnoty)
    assert r["methods"]["Z3"]["interval"] == list(np.quantile(priemery, [(1 - LEVEL) / 2, (1 + LEVEL) / 2]))
    assert (r["methods"]["Z3"]["p_value"], r["methods"]["Z3"]["test"]) == (
        (1 + int((np.abs(sucty) >= abs(sum(hodnoty))).sum())) / 10001, {"kind": "random", "sign_vectors": 10000})


def test_interval_sa_zopakuje_zo_seedu_svojho_porovnania():
    """Prud bootstrap porovnania k1/Z3 ma seed seed(meno planu, "bootstrap", "k1/Z3", -1, 0) (streams.rule): ten isty
    protokol a rezim daju ten isty zaznam, interval su kvantily priemerov 10000 vyberov bootov z
    numpy.random.default_rng tohto seedu, a generalka (vlastne meno planu) ma iny seed aj iny interval."""
    from scripts import protocol_v5
    from tcn import tvrdenia
    doc = protokol()
    hodnoty = {"Z3": dict(zip(BOOTY, ROZNE)), "Z5": dict(zip(BOOTY, VYSOKO))}
    prvy = tvrdenia.rozhodni(doc, "k1", hodnoty, rezim="campaign")
    assert tvrdenia.rozhodni(doc, "k1", hodnoty, rezim="campaign") == prvy
    seed = protocol_v5.seed("server-normal-v5", "bootstrap", "k1/Z3", -1, 0)
    assert prvy["methods"]["Z3"]["stream"] == {"purpose": "bootstrap", "unit": "k1/Z3", "seed": seed}
    priemery = np.array(ROZNE)[np.random.default_rng(seed).integers(0, 12, size=(10000, 12))].mean(axis=1)
    assert prvy["methods"]["Z3"]["interval"] == list(np.quantile(priemery, [(1 - LEVEL) / 2, (1 + LEVEL) / 2]))
    generalka = tvrdenia.rozhodni(doc, "k1", hodnoty, rezim="rehearsal")
    assert generalka["methods"]["Z3"]["stream"]["seed"] == protocol_v5.seed(
        "server-normal-v5-generalka", "bootstrap", "k1/Z3", -1, 0) != seed
    assert generalka["methods"]["Z3"]["interval"] != prvy["methods"]["Z3"]["interval"]


@pytest.mark.parametrize("volanie, dovod", [
    (lambda t, doc: t.k1(doc, None, None, None, None, rezim="campaign", rola="test_benign"),
     "analysis.k1.m je null: hranicu m urcuje stupen G1 (determined_at), tvrdenie k1 sa bez nej nerozhoduje"),
    (lambda t, doc: t.rozhodni(doc, "k2a", None, rezim="campaign"),
     "analysis.k2a.m je null: hranicu m urcuje stupen G1 (determined_at), tvrdenie k2a sa bez nej nerozhoduje"),
    (lambda t, doc: t.vysledok({"Z3": (.2, .4)}, None),
     "hranica m je null: urcuje ju stupen G1 (determined_at), bez nej sa tvrdenie nerozhoduje"),
], ids=["k1", "rozhodni", "vysledok"])
def test_hranica_m_null_sa_odmietne_menom(volanie, dovod):
    """Navrh B7a 1.5: m je null do G1 (subor protokolu dnes), funkcie ju odmietnu menom; k1 a rozhodni skor, nez
    citaju straty alebo hodnoty (tu None)."""
    from tcn import tvrdenia
    with pytest.raises(ValueError) as odmietnute:
        volanie(tvrdenia, json.loads(V5.read_text()))
    assert str(odmietnute.value) == dovod


def _tabulka_8_4():
    """Stlpec "Znenie záveru" tabulky kap. 8.4 navrhu: {vysledok: text medzi uvodzovkami „ “}."""
    riadky = NAVRH.read_text(encoding="utf-8").splitlines()
    i = riadky.index("| Výsledok | Podmienka | Znenie záveru |")
    out = {}
    for riadok in riadky[i + 2:i + 5]:
        vysledok, _, znenie = [c.strip() for c in riadok.strip().strip("|").split("|")]
        assert (znenie[0], znenie[-1]) == ("„", "“")
        out[vysledok] = znenie[1:-1]
    return out


def test_znenie_je_z_protokolu_a_protokol_ho_ma_z_kapitoly_8_4_slovo_od_slova():
    """analysis.wording.<tvrdenie>.<vysledok> je text tabulky kap. 8.4 slovo od slova (medzi uvodzovkami, s … tam, kde
    ich ma tabulka) pre K1, K2a aj K2b; rozhodni berie znenie z protokolu, ktory dostane, a v conclusion doplni jeho
    miesta … (better: metody a rozdiel voci kazdej; not_better: metody s hornou hranicou pod m; undecided: interval
    kazdej)."""
    from tcn import tvrdenia
    tabulka = _tabulka_8_4()
    znenie = {"better": tabulka["lepší"], "not_better": tabulka["nie lepší"], "undecided": tabulka["nerozhodnuté"]}
    assert json.loads(V5.read_text())["analysis"]["wording"] == {t: znenie for t in ("k1", "k2a", "k2b")}
    doc = protokol()
    doc["analysis"]["wording"]["k2b"]["not_better"] = "iné znenie: rovnocenný s … (skúška)"
    r = tvrdenia.rozhodni(doc, "k2b", {"Z3": dict(zip(BOOTY, VYSOKO)), "Z5": dict(zip(BOOTY, NULA))}, rezim="campaign")
    assert (r["outcome"], r["wording"], r["fill"], r["conclusion"]) == (
        "not_better", "iné znenie: rovnocenný s … (skúška)", ["Z5"], "iné znenie: rovnocenný s Z5 (skúška)")
    r = tvrdenia.rozhodni(doc, "k2b", {"Z3": dict(zip(BOOTY, VYSOKO)), "Z5": dict(zip(BOOTY, VYSOKO))},
                          rezim="campaign")
    vety = [f"{z} {v['mean']:.4g} [{v['interval'][0]:.4g}, {v['interval'][1]:.4g}]" for z, v in r["methods"].items()]
    assert (r["outcome"], r["fill"]) == ("better", ["Z3, Z5", "; ".join(vety)])
    assert r["conclusion"] == f"neurónový kanál využíva naučenú štruktúru; rozdiel oproti Z3, Z5 je {'; '.join(vety)}"


def _zmen(cast, zmena):
    """Dobre okna (better) so zmenou jedneho vstupu: cast je index v (model, metody, booty, ciste)."""
    vstupy = list(okna({"Z3": VYSOKO, "Z5": VYSOKO}))
    vstupy[cast] = zmena(vstupy[cast])
    return vstupy


def _nan_na_cistom(metody):
    return dict(metody, Z5=[math.nan] + metody["Z5"][1:])


def _nula_v_boote(metody):
    return dict(metody, Z3=[0.] * 3 + metody["Z3"][3:])


@pytest.mark.parametrize("vstupy, dovod", [
    (_zmen(0, lambda model: {s: v for s, v in model.items() if s != 4}),
     "straty modelu M su pre [0, 1, 2, 3], analysis.seeds (M vstupuje medianom vsetkych svojich seedov na boot, D14) "
     "je [0, 1, 2, 3, 4]"),
    (_zmen(1, lambda metody: {"Z3": metody["Z3"]}), "straty metod su pre ['Z3'], analysis.k1.compare je ['Z3', 'Z5']"),
    (_zmen(2, lambda booty: [None] + booty[1:]), "boot okna je nazov jeho bootovej skupiny (neprazdny text)"),
    (_zmen(3, lambda ciste: ciste.astype(int)),
     "ciste je 48 pravdivostnych hodnot, jedna na okno (dostal int64 (48,))"),
    (_zmen(1, lambda metody: dict(metody, Z3=metody["Z3"][:-1])), "straty metody Z3 maju tvar (47,), booty a ciste 48 "
                                                                   "okien"),
    (_zmen(1, _nan_na_cistom), "strata metody Z5 na cistom okne 0 nie je konecne nezaporne cislo: nan"),
    (_zmen(1, _nula_v_boote), "strata metody Z3 v boote b01 je 0.0: zlepsenie I = 1 - strata(M) / strata(Z) potrebuje "
                              "kladnu stratu metody"),
    (_zmen(3, lambda ciste: np.arange(48) < 3), "1 bootov s cistym skorovanym oknom, K1 ich potrebuje aspon 2 "
                                                "(usudok: jeden boot nema rozptyl)"),
], ids=["seed_missing", "method_missing", "boot_not_a_name", "clean_not_boolean", "losses_one_short", "nan_on_clean",
        "zero_loss_of_a_method", "one_boot"])
def test_k1_odmietne_zly_vstup_s_dovodom(vstupy, dovod):
    from tcn import tvrdenia
    with pytest.raises(ValueError) as odmietnute:
        tvrdenia.k1(protokol(), *vstupy, rezim="campaign", rola="test_benign")
    assert str(odmietnute.value) == dovod


def test_boot_bez_cisteho_okna_do_k1_nevstupuje_a_zaznam_ho_uvedie():
    """Pomenovane pravidlo (ziadna tichá predvolba): boot, ktoreho okna su vsetky mimo cistej prevadzky, nema stratu;
    zaznam ho uvedie v unevaluated_boots s nulou okien a K1 sa rozhodne nad ostatnymi 11 bootmi."""
    from tcn import tvrdenia
    model, metody, booty, ciste = okna({"Z3": VYSOKO, "Z5": VYSOKO})
    ciste = ciste & (np.asarray(booty) != "b12")
    r = tvrdenia.k1(protokol(), model, metody, booty, ciste, rezim="campaign", rola="test_benign")
    assert (r["boots"], r["unevaluated_boots"], r["windows"]["b12"], r["outcome"]) == (
        BOOTY[:11], {"b12": "no clean scored window"}, 0, "better")
    assert sorted(r["methods"]["Z3"]["values"]) == BOOTY[:11]


@pytest.mark.parametrize("tvrdenie, hodnoty, rezim, dovod", [
    ("k3", {}, "campaign", "'k3' nie je potvrdzujuce tvrdenie (k1, k2a, k2b)"),
    ("k1", {"Z3": dict(zip(BOOTY, VYSOKO))}, "campaign", "hodnoty tvrdenia k1 su pre ['Z3'], analysis.k1.compare je "
                                                         "['Z3', 'Z5']"),
    ("k1", {"Z3": dict(zip(BOOTY, VYSOKO)), "Z5": dict(zip(BOOTY[1:], VYSOKO))}, "campaign",
     f"metody tvrdenia k1 maju rozne booty: Z3 {BOOTY}, Z5 {BOOTY[1:]}"),
    ("k1", {"Z3": dict(zip(BOOTY, VYSOKO)), "Z5": dict(zip(BOOTY, [math.inf] + VYSOKO[1:]))}, "campaign",
     "hodnoty metody Z5 nie su {boot: konecne cislo}"),
    ("k2a", {}, "final", "rezim planu 'final' nie je jeden z campaign, rehearsal"),
], ids=["unknown_claim", "method_missing", "other_boots", "infinite_value", "unknown_mode"])
def test_rozhodni_odmietne_zly_vstup_s_dovodom(tvrdenie, hodnoty, rezim, dovod):
    from tcn import tvrdenia
    with pytest.raises(ValueError) as odmietnute:
        tvrdenia.rozhodni(protokol(), tvrdenie, hodnoty, rezim=rezim)
    assert str(odmietnute.value) == dovod
