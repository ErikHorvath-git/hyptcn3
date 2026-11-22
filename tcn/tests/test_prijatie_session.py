"""
Prijatie hranicnych session na kazdom mieste, ktore pusta session do korpusu (protokol v5, balik B2).

Kriterium balika: jedna funkcia prijatia pre nacitanie protokolu, audit, stavbu korpusu a trening; test
hranicnych session (0 az maximum plus jeden neplatny riadok, osamotene aj zhluknute) da na vsetkych miestach
rovnake rozhodnutie. Plan: PLAN_TESTOV_KRITERIA.md (sekcie 2 az 9 a 14) a jeho doplnok 2 (casti A, D, E, F).

Matica sa sklada z tabuliek na zaciatku suboru: rodina protokolu (sekcia 3) -> bunka (sekcia 4) -> ocakavane
rozhodnutie, okna a dovody; rola; miesto; falosny zaznam (sekcia 8) -> sprava (sekcia 14). Kazda kombinacia je
jedno id testu. Miesta sa volaju iba cez vstupy, ktorych podpis B2 nemeni (collection.protocol,
collection.audit_session cez bs.audit, dataset.build, validate_index, nacitaj_role, train_bundle), takze subor
bezi aj nad kodom pred B2 a tam zlyha tvrdenim o rozhodnuti alebo sprave. Testy samotnej funkcie (noha L10)
dostanu features.acceptance az v tele testu cez pytest.importorskip.

Session stavia a audituje pomocnik K0 (scripts/tests/boundary_sessions.py): realny audit_session, nahradena je
iba extrakcia z RAM. Ocakavana strana nikdy nepochadza z produktu: okna dava orakulum bs.window_count, rozhodnutia
a spravy su literaly tabuliek nizsie. Korpus kazdej rodiny sa stavia raz za modul a nikdy sa nemeni; kazdy falosny
zaznam, archiv a index je novy subor testu so vsetkymi hashmi, ktore miesta overuju, spravne, takze odmietnutie
moze prist iba z rozhodnutia.

Iba MECHANIKA na syntetickych session - ziadne cislo tu nie je vysledok detekcie (HONESTY P4).
"""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest
import torch

from features import dataset
from features.archive import load
from safeguard.training import train_bundle, validate_index
from scripts import collection
from scripts.tests import boundary_sessions as bs
from tcn import porovnanie as po

# ------------------------------------------------------------------ tabulky planu

RODINY = ("S3", "S2G", "V4")
ROLY = ("train", "dev", "calibration", "test_benign")
NACITANE = ("train", "dev", "calibration")  # roly, ktorych archivy otvara train_bundle a nacitaj_role
MIEST_NA_ROLU = {"S3": 6, "S2G": 6, "V4": 4}  # sekcia 6: collection.plan, 3 (V4: 2) skupiny x 2 scenare

# Sekcia 4: bunka -> (rozmiestnenie neplatnych riadkov, ich pocet).
BUNKY = {"k0": ("ziadne", 0), "k1": ("osamotene", 1), "k2i": ("osamotene", 2), "k2c": ("zhluknute", 2),
         "k3i": ("osamotene", 3), "k3c": ("zhluknute", 3), "k4i": ("osamotene", 4), "k4c": ("zhluknute", 4)}
PRIJATA, NA_ROVNOSTI = "prijata", "prijata na rovnosti"
IBA_POKRYTIE, POCET_A_POKRYTIE, IBA_POCET = "zamietnuta iba pokrytim", "zamietnuta poctom a pokrytim", "iba poctom"
PRIJATE = (PRIJATA, NA_ROVNOSTI)
# Sekcia 4: rodina -> bunka -> (rozhodnutie, okna). Okna su aj z orakula (test ich porovna).
ROZHODNUTIA = {
    "S3": {"k0": (PRIJATA, 80), "k1": (PRIJATA, 71), "k2i": (PRIJATA, 62), "k2c": (PRIJATA, 70),
           "k3i": (NA_ROVNOSTI, 53), "k3c": (PRIJATA, 69), "k4i": (POCET_A_POKRYTIE, 44), "k4c": (IBA_POCET, 68)},
    "S2G": {"k0": (PRIJATA, 80), "k1": (PRIJATA, 71), "k2i": (PRIJATA, 62), "k2c": (PRIJATA, 70),
            "k3i": (IBA_POKRYTIE, 53), "k3c": (PRIJATA, 69), "k4i": (POCET_A_POKRYTIE, 44), "k4c": (IBA_POCET, 68)},
    "V4": {"k0": (PRIJATA, 656), "k1": (PRIJATA, 623), "k2i": (IBA_POKRYTIE, 590), "k2c": (PRIJATA, 622),
           "k3i": (IBA_POKRYTIE, 557), "k3c": (PRIJATA, 621), "k4i": (POCET_A_POKRYTIE, 524),
           "k4c": (IBA_POCET, 620)},
}
ZAMIETNUTE = {r: [b for b, (roz, _) in ROZHODNUTIA[r].items() if roz not in PRIJATE] for r in RODINY}
# Druh zamietnutej bunky pre tabulku sprav sekcie 14.
DRUH = {IBA_POKRYTIE: "pokrytie", POCET_A_POKRYTIE: "pocet", IBA_POCET: "pocet"}

# Dovody auditu (zaciatky retazcov, ako ich pise produkt), v poradi zoradeneho zoznamu zaznamu (sekcia 7, L1).
POKRYTIE_DOVOD = "score coverage below design gate"
RIADKY_DOVOD = "incomplete model inputs under"
DOVODY = {PRIJATA: (), NA_ROVNOSTI: (), IBA_POKRYTIE: (POKRYTIE_DOVOD,),
          POCET_A_POKRYTIE: (RIADKY_DOVOD, POKRYTIE_DOVOD), IBA_POCET: (RIADKY_DOVOD,)}

# Spravy sekcii 9 a 14 (doslova, ako ich pise kod B2).
NEPRIJATY_INDEX = "audit provenance mismatch or unaccepted audit"
NEPRIJATY_BUILD = "unaccepted audit or protocol mismatch"
ODMIETA = "accepted audit of a session the protocol rejects: "
NAD_POCET = "more invalid rows than the protocol tolerates"
PRICINA = "invalid rows have a cause the protocol does not tolerate"
NEUPLNE = "incomplete features in accepted audit"
ROZDIEL = "audit record differs from the acceptance decision"
BEZ_VERDIKTU = "audit record carries no acceptance verdict"
NECISTY = "unaccepted audit: the record does not state a clean acceptance"
INA_ROLA = "unaccepted audit: recorded for another role"
POCET_SNIMOK = "snapshot count differs from assigned protocol"
POSTUPNOST = "sequence must start at zero and be contiguous"
INTEGRITA = "integrity findings require review before benign admission"
FAKTY = "invalid session facts"
NEDOSIAHNUTELNA = "score coverage gate is unreachable for "
NAJHORSI = "invalid_rows.max is unreachable under the score coverage gate"

MIESTA = ("build", "validate_index", "validate_index_diag", "nacitaj_role", "train_bundle")
SPOTREBITELIA = ("build", "validate_index", "nacitaj_role", "train_bundle")
# Sekcia 14: (falosny zaznam, druh bunky) -> (sprava validate_index a miest za nim, sprava build).
SPRAVY = {
    ("F1", "pokrytie"): (ODMIETA + POKRYTIE_DOVOD, ODMIETA + POKRYTIE_DOVOD),
    ("F1b", "pokrytie"): (ODMIETA + POKRYTIE_DOVOD, ODMIETA + POKRYTIE_DOVOD),
    ("F1", "pocet"): (NAD_POCET, NEUPLNE),
    ("F1b", "pocet"): (NAD_POCET, NEUPLNE),
    ("F1c", "pocet"): (NAD_POCET, NAD_POCET),
}
# Sekcia 8 a 14: variant F2 -> sprava miest, ktore otvaraju archiv (build, train_bundle, nacitaj_role).
# c2 je c s dvoma nalezmi v jednom riadku (doplnok D5: pocet nalezov nie je pocet riadkov).
F2_SPRAVY = {"a": NEUPLNE, "b": ODMIETA + POKRYTIE_DOVOD, "c": ODMIETA + INTEGRITA, "c2": ODMIETA + INTEGRITA,
             "d": ODMIETA + POCET_SNIMOK, "e": ODMIETA + POCET_SNIMOK, "f": ODMIETA + POSTUPNOST}
# Sekcia 7, L7: (rodina, varianty, miesto, roly). Plne na S3; na V4 variant b (build vsetky roly, inak train).
F2_MATICA = [("S3", ("a", "b", "c", "c2", "d", "e", "f"), "build", ROLY),
             ("S3", ("a", "b", "c", "d"), "train_bundle", NACITANE),
             ("S3", ("a", "b", "c", "d"), "nacitaj_role", NACITANE),
             ("V4", ("b",), "build", ROLY), ("V4", ("b",), "train_bundle", ("train",)),
             ("V4", ("b",), "nacitaj_role", ("train",))]
F2_PIN = [("S3", ("a", "b", "c", "c2", "d", "e", "f"), ROLY), ("V4", ("b",), ROLY)]
# Dvojca F2 (doplnok F3): ta ista stavba archivu a zaznamu bez porusenia; "+" = viac roli v jednom indexe.
F2_DVOJCE = [("S3", r, m) for m in ("build", "validate_index") for r in ROLY] + \
            [("S3", r, "nacitaj_role") for r in NACITANE] + [("S3", "+".join(NACITANE), "train_bundle")] + \
            [("V4", "train", m) for m in SPOTREBITELIA]


def _id(*casti):
    return "-".join(map(str, casti))


def _p(*casti):
    return pytest.param(*casti, id=_id(*casti))


# ------------------------------------------------------------------ stavba session a korpusu

def _neplatne(bunka, w, f):
    """seq neplatnych riadkov bunky (sekcia 4): osamotene po F // 6, zhluknute od F // 2."""
    rozmiestnenie, pocet = BUNKY[bunka]
    if not pocet:
        return []
    return (bs.isolated_seqs if rozmiestnenie == "osamotene" else bs.clustered_seqs)(pocet, w, f)


def _sha(cesta):
    return hashlib.sha256(Path(cesta).read_bytes()).hexdigest()


def _zapis(cesta, doc):
    Path(cesta).write_text(json.dumps(doc, indent=2))
    return Path(cesta)


def _relacia(koren, p, cesta, miesto, sid, slot, bunka, kvalita=None):
    w, f = p["window_rows"], p["full_every"]
    if kvalita is None:
        kvalita = {seq: bs.unclosed_row() for seq in _neplatne(bunka, w, f)}
    s = bs.build_session(koren / "s", p, cesta, miesto, session_id=sid, base=bs.time_base(p, miesto["role"], slot),
                         quality=kvalita)
    return SimpleNamespace(s=s, a=bs.audit(s, p), bunka=bunka, miesto=miesto)


class _Korpus(SimpleNamespace):
    """Prijaty korpus: session a audity hned, index (dataset.build) az pri prvom citani k.doc alebo k.index.

    L1 a L11 tak zavisia iba od session a auditov; zlyhanie stavby sa ukaze az v teste, ktory index cita."""

    @property
    def doc(self):
        return self.stavba()[0]

    @property
    def index(self):
        return self.stavba()[1]


def _index_korpusu(k):
    """Index prijateho korpusu tak, ako ho pisu volajuci: dataset.build a cesta k protokolu."""
    doc = dataset.build(k.audity, k.p, k.sha)
    doc["protocol"] = str(k.cesta)  # ako volajuci (scripts/campaign.py finish_corpus, dataset.main)
    return doc, _zapis(k.koren / "index.json", doc)


def _korpus(rodina, koren, raz):
    """Prijaty korpus rodiny (sekcia 6) a session navyse na mieste podvrhu kazdej roly; `raz(stavba)` postavi
    index najviac raz (fixtura korpusy)."""
    profil = bs.profile_dir(koren / "profil")
    cesta = bs.write_protocol(koren / "protokol.json", bs.family(rodina, profil))
    p = collection.protocol(cesta)
    n, w, f = p["cycles"], p["window_rows"], p["full_every"]
    prijate = [b for b in BUNKY if ROZHODNUTIA[rodina][b][0] in PRIJATE]
    assert prijate[0] == "k0" and list(p["roles"]) == list(ROLY)
    miesta, bunky, navyse, okna, audity = {}, {}, {}, {}, []
    for rola in ROLY:
        planovane = bs.places(p, rola)
        assert len(planovane) == MIEST_NA_ROLU[rodina]
        miesta[rola] = []
        for i, miesto in enumerate(planovane):
            # Kazda prijata bunka raz v kazdej roli, prve miesto (miesto podvrhu) nesie k0, volne miesta k0.
            rel = _relacia(koren, p, cesta, miesto, _id(rodina, rola, i), i, prijate[i] if i < len(prijate) else "k0")
            miesta[rola].append(rel)
            bunky.setdefault((rel.bunka, rola), rel)
            audity.append(rel.a.path)
        okna[rola] = sum(bs.window_count(n, w, f, _neplatne(rel.bunka, w, f)) for rel in miesta[rola])
        # Navyse: kazda zamietnuta bunka a k1 (kladna kontrola L9) na mieste podvrhu: ta ista rola, skupina,
        # scenar a boot id, vlastne id a vlastny casovy slot v useku roly.
        for j, bunka in enumerate([*ZAMIETNUTE[rodina], "k1"]):
            rel = _relacia(koren, p, cesta, planovane[0], _id(rodina, rola, "x" + bunka), len(planovane) + j, bunka)
            navyse[(bunka, rola)] = rel
            bunky.setdefault((bunka, rola), rel)
    sha = collection.digest(cesta)
    k = _Korpus(rodina=rodina, koren=koren, profil=profil, cesta=cesta, p=p, sha=sha, n=n, w=w, f=f, miesta=miesta,
                bunky=bunky, navyse=navyse, okna=okna, audity=audity, cisty={rola: miesta[rola][0] for rola in ROLY})
    k.stavba = lambda: raz(lambda: _index_korpusu(k))
    return k


def _trenuj(k, index, vystup):
    return train_bundle(index, vystup, window_rows=k.w, max_gap_s=k.p["max_gap_s"], epochs=1, batch_size=64,
                        fpr=0.05)


@contextlib.contextmanager
def _zaznam_jadra():
    """Zaznam volani jadra funkcie prijatia pocas bloku: rola kazdeho _verdict a meno session kazdeho session_facts
    (cesta require_accepted -> judge, teda vlastne rozhodnutie miesta nad archivom). Pred B2 funkcia nie je: prazdny
    zaznam. Fixtura modulu nemoze pouzit monkeypatch, preto nahrada a obnova rucne."""
    zaznam = SimpleNamespace(verdikty=[], archivy=[])
    try:
        from features import acceptance
    except ImportError:
        yield zaznam
        return
    verdikt, fakty = acceptance._verdict, acceptance.session_facts

    def zaznamenaj_verdikt(*args, **kwargs):
        zaznam.verdikty.append(args[1] if len(args) > 1 else kwargs.get("role"))
        return verdikt(*args, **kwargs)

    def zaznamenaj_fakty(*args, **kwargs):
        zaznam.archivy.append(args[2] if len(args) > 2 else kwargs.get("session"))
        return fakty(*args, **kwargs)
    acceptance._verdict, acceptance.session_facts = zaznamenaj_verdikt, zaznamenaj_fakty
    try:
        yield zaznam
    finally:
        acceptance._verdict, acceptance.session_facts = verdikt, fakty


@pytest.fixture(scope="module", autouse=True)
def _vlakna():
    povodne = torch.get_num_threads()
    torch.set_num_threads(2)
    yield
    torch.set_num_threads(povodne)


@pytest.fixture(scope="module")
def korpusy(tmp_path_factory):
    """korpusy(rodina): prijaty korpus rodiny, postaveny raz (index az pri prvom citani k.doc alebo k.index);
    korpusy.trening(rodina): jediny trening L2; korpusy.zaznam_treningu(rodina): volania jadra pocas neho."""
    hotove, indexy, treningy = {}, {}, {}

    def raz(cache, kluc, krok, stavba):
        if kluc not in cache:
            try:
                cache[kluc] = (True, stavba())
            except Exception as chyba:  # chyba stavby sa neopakuje v kazdom teste, uchova sa iba jej text
                cache[kluc] = (False, f"{type(chyba).__name__}: {chyba}")
                raise
        ok, hodnota = cache[kluc]
        if not ok:  # kazde dalsie pouzitie dostane novu vynimku (traceback nerastie s poctom testov)
            raise RuntimeError(f"{krok} {kluc} zlyhala: {hodnota}")
        return hodnota

    def daj(rodina):
        return raz(hotove, rodina, "stavba prijateho korpusu", lambda: _korpus(
            rodina, tmp_path_factory.mktemp("korpus_" + rodina),
            lambda stavba: raz(indexy, rodina, "stavba indexu prijateho korpusu", stavba)))

    def beh_treningu(rodina):
        k = daj(rodina)

        def stavba():
            index = k.index  # index vznikne pred zaznamom: zaznam patri iba treningu
            with _zaznam_jadra() as zaznam:
                vysledok = _trenuj(k, index, k.koren / "balik")
            return vysledok, zaznam
        return raz(treningy, rodina, "trening prijateho korpusu", stavba)
    daj.trening = lambda rodina: beh_treningu(rodina)[0]
    daj.zaznam_treningu = lambda rodina: beh_treningu(rodina)[1]
    return daj


# ------------------------------------------------------------------ podvrhy (sekcia 8)

def _sfalsuj(rel, ciel, *zmeny):
    """Novy subor zaznamu auditu: poctivy zaznam session `rel` po zmenach hodnot; zdielany zaznam sa nemeni."""
    zaznam = copy.deepcopy(rel.a.record)
    for zmena in zmeny:
        zmena(zaznam["values"])
    return _zapis(ciel, zaznam)


def _verdikt(v, **polia):
    """Zmena ulozeneho verdiktu iba tam, kde zaznam nejaky ma (pred B2 ho zaznam nema)."""
    if type(v.get("acceptance")) is dict:
        v["acceptance"].update(polia)


def _f1(v):
    v.update(accepted=True, reasons=[])


def _f1b(v):
    _f1(v)
    _verdikt(v, accepted=True, reasons=[], codes=[])


def _f1c(archiv):
    data = load(archiv)
    vsetky = sorted(int(s) for s, dobry in zip(data["seq"], data["valid"]) if not dobry)

    def zmena(v):
        _f1b(v)
        v["quality"]["tolerated_invalid_seq"] = list(vsetky)
        _verdikt(v, tolerated_invalid_seq=list(vsetky))
    return zmena


FALSIFIKATY = {"F1": lambda rel: _f1, "F1b": lambda rel: _f1b, "F1c": lambda rel: _f1c(rel.a.archive)}


def _zaznam_indexu(cesta_auditu, sha):
    """Zaznam indexu pre audit, s tymi poliami, ako ich features/dataset.py build odvodi zo session a archivu."""
    v = json.loads(Path(cesta_auditu).read_text())["values"]
    meta = Path(v["session_dir"]) / "session.json"
    m = json.loads(meta.read_text())
    casy = load(v["features"])["casy"]
    return {"id": m["session_id"], "role": m["role"], "group": m["group"], "vm": m.get("vm"),
            "boot_id": m["guest_before"]["boot_id"], "kernel": m["guest_before"]["kernel"], "typ": m["typ"],
            "guest": m["guest_before"], "collector_sha256": m["collector_sha256"], "protocol_sha256": sha,
            "session": str(meta.resolve()), "session_sha256": _sha(meta), "scenario": m["scenario"],
            "seed": m["seed"], "start": float(casy[0]), "end": float(casy[-1]),
            "audit": str(Path(cesta_auditu).resolve()), "audit_sha256": _sha(cesta_auditu),
            "features": str(Path(v["features"]).resolve()), "features_sha256": _sha(v["features"]),
            "log_audit": "repeated"}  # kazda session testu ma svoje logy, stavba audit logov zopakuje (B3)


def _index_s(k, nahrady, ciel):
    """Prijaty index, v ktorom miesto podvrhu kazdej roly z `nahrady` nesie dany zaznam; ostatne zaznamy ostanu."""
    doc = json.loads(k.index.read_text())
    zaznamy = {r["id"]: r for r in doc["sessions"]}
    for rola, cesta in nahrady.items():
        del zaznamy[k.cisty[rola].s.directory.name]
        novy = _zaznam_indexu(cesta, k.sha)
        zaznamy[novy["id"]] = novy
    doc["sessions"] = sorted(zaznamy.values(), key=lambda r: r["start"])
    return _zapis(ciel, doc)


def _audity_s(k, nahrady):
    mapa = {k.cisty[rola].a.path: Path(cesta) for rola, cesta in nahrady.items()}
    return [mapa.get(a, a) for a in k.audity]


def _na_mieste(k, miesto, nahrady, tmp_path):
    """Zavola miesto nad prijatym korpusom, v ktorom miesta podvrhu roli z `nahrady` nesu dane zaznamy."""
    if miesto == "build":
        return dataset.build(_audity_s(k, nahrady), k.p, k.sha)
    index = _index_s(k, nahrady, tmp_path / "index.json")
    if miesto == "validate_index":
        return validate_index(index)
    if miesto == "validate_index_diag":
        return validate_index(index, diagnostic=True)
    if miesto == "nacitaj_role":
        return po.nacitaj_role(index)
    assert miesto == "train_bundle"
    return _trenuj(k, index, tmp_path / "balik")


def _odmietne(sprava, volanie):
    with pytest.raises(ValueError, match="^" + re.escape(sprava)):
        volanie()


def _okna_roli(vysledok, miesto):
    if miesto == "nacitaj_role":
        return {rola: len(vysledok["data"][rola].indices) for rola in NACITANE}
    return dict(vysledok["training"]["windows"])


def _dva_nalezy():
    q = bs.finding_row()
    return dict(q, findings=[*q["findings"], dict(q["findings"][0], index=1)])


def _f2_archiv(k, rola, variant, ciel):
    """Archiv F2 so spravnym id, casovou zakladnou a rozlozenim cistej session miesta podvrhu (sekcia 8)."""
    cisty = k.cisty[rola]
    n, w, f, stred = k.n, k.w, k.f, k.f // 2  # stred: riadok prvej retaze mimo plnej snimky
    kw = dict(t0=cisty.s.result["casy"][0], interval_s=k.p["interval_s"], seed=cisty.miesto["seed"],
              max_gap_s=k.p["max_gap_s"])
    riadky, plna, kvalita, chyba = n, f, {}, set()
    if variant == "a":
        kvalita = {bs.isolated_seqs(1, w, f)[0]: bs.unclosed_row()}
    elif variant == "b":
        plna = 2 * w  # vsetky riadky platne, plne snimky castejsie: okna pod branou
        assert bs.window_count(n, w, plna) / n < k.p["min_score_coverage"]
    elif variant == "c":
        kvalita = {stred: bs.finding_row()}
    elif variant == "c2":
        kvalita = {stred: _dva_nalezy()}
    elif variant == "d":
        chyba = {stred}
    elif variant == "e":
        chyba = {n - 1}
    elif variant == "f":
        riadky, chyba = n + 1, {stred}
    else:
        assert variant == "dvojca"
    vysledok, _ = bs.extraction_result(cisty.s.directory.name, riadky, plna, quality=kvalita, missing=chyba, **kw)
    if variant in ("a", "b", "c", "c2", "d", "dvojca"):  # prvy a posledny cas ostava (train_bundle, nacitaj_role)
        assert (vysledok["casy"][0], vysledok["casy"][-1]) == (cisty.s.result["casy"][0], cisty.s.result["casy"][-1])
    return bs.save_archive(ciel, vysledok)


def _f2_zaznam(k, rola, variant, tmp_path):
    archiv, sha = _f2_archiv(k, rola, variant, tmp_path / "f2.npz")
    if variant != "dvojca":
        assert sha != k.cisty[rola].a.values["features_sha256"]
    return _sfalsuj(k.cisty[rola], tmp_path / "audit.json", lambda v: v.update(features=str(archiv),
                                                                                features_sha256=sha)), sha


# ------------------------------------------------------------------ L1, L11: audit a jeho zaznam

L1_IDS = [_p(r, b, rola) for r in RODINY for b in BUNKY for rola in ROLY]


def test_l1_tabulka_ma_specialne_bunky(tmp_path):
    """Okna tabulky su okna orakula a kazda rodina ma svoje specialne bunky (sekcia 4)."""
    for rodina in RODINY:
        p = bs.family(rodina, tmp_path)
        n, w, f, brana = p["cycles"], p["window_rows"], p["full_every"], p["min_score_coverage"]
        for bunka, (rozhodnutie, okna) in ROZHODNUTIA[rodina].items():
            assert bs.window_count(n, w, f, _neplatne(bunka, w, f)) == okna, (rodina, bunka)
            pocet_ok = BUNKY[bunka][1] <= p["invalid_rows"]["max"]
            if rozhodnutie == NA_ROVNOSTI:
                assert pocet_ok and okna / n == brana
            elif rozhodnutie == PRIJATA:
                assert pocet_ok and okna / n > brana
            elif rozhodnutie == IBA_POKRYTIE:
                assert pocet_ok and okna / n < brana
            elif rozhodnutie == POCET_A_POKRYTIE:
                assert not pocet_ok and okna / n < brana
            else:
                assert rozhodnutie == IBA_POCET and not pocet_ok and not okna / n < brana  # pasca: pokrytie prejde
        roz = [r for r, _ in ROZHODNUTIA[rodina].values()]
        assert (NA_ROVNOSTI in roz) == (rodina == "S3") and (IBA_POKRYTIE in roz) == (rodina != "S3")
        assert ROZHODNUTIA[rodina]["k4c"][0] == IBA_POCET


@pytest.mark.parametrize("rodina,bunka,rola", L1_IDS)
def test_l1_audit_rozhodne_podla_orakula(korpusy, rodina, bunka, rola):
    k = korpusy(rodina)
    rel = k.bunky[(bunka, rola)]
    rozhodnutie, okna = ROZHODNUTIA[rodina][bunka]
    neplatne = _neplatne(bunka, k.w, k.f)
    assert bs.window_count(k.n, k.w, k.f, neplatne) == okna
    v = rel.a.values
    prijata = rozhodnutie in PRIJATE
    assert (rel.a.code, v["accepted"], v["role"]) == (0 if prijata else 2, prijata, rola)
    assert (v["snapshots"], v["windows"], v["score_coverage"]) == (k.n, okna, okna / k.n)
    tolerovane = neplatne if BUNKY[bunka][1] <= k.p["invalid_rows"]["max"] else []
    assert v["quality"]["tolerated_invalid_seq"] == tolerovane
    dovody = DOVODY[rozhodnutie]
    assert len(v["reasons"]) == len(dovody) and all(d.startswith(z) for d, z in zip(v["reasons"], dovody)), v["reasons"]


@pytest.mark.parametrize("rodina", RODINY)
def test_l1_nalezy_sa_pocitaju_nie_riadky(korpusy, rodina, tmp_path):
    """Doplnok D5: jeden riadok s dvoma nalezmi integrity; audit pocita nalezy, okna su ako bez nich."""
    k = korpusy(rodina)
    rel = _relacia(tmp_path, k.p, k.cesta, k.cisty["train"].miesto, "nalezy", bs.SLOTS - 1, "k0",
                   kvalita={k.f // 2: _dva_nalezy()})
    v = rel.a.values
    assert (rel.a.code, v["accepted"], v["reasons"]) == (2, False, [INTEGRITA])
    assert (v["quality"]["integrity_findings"], v["quality"]["integrity_finding_rows"]) == (2, 1)
    assert v["windows"] == bs.window_count(k.n, k.w, k.f)


@pytest.mark.parametrize("rodina,bunka,rola", L1_IDS)
def test_l11_zaznam_nesie_verdikt(korpusy, rodina, bunka, rola):
    """C22: prijaty aj zamietnuty zaznam nesie verdikt; jeho polia opakuju polia zaznamu."""
    v = korpusy(rodina).bunky[(bunka, rola)].a.values
    verdikt = v.get("acceptance")
    assert type(verdikt) is dict
    for kluc in ("accepted", "reasons", "windows", "snapshots", "score_coverage"):
        assert verdikt[kluc] == v[kluc], kluc


@pytest.mark.parametrize("rodina,bunka,rola", L1_IDS)
def test_l11b_verdikt_nesie_rolu_a_tolerovane(korpusy, rodina, bunka, rola):
    """Doplnok 4 (must_fix 4): ulozeny verdikt nesie rolu session a tolerovane riadky podla tabulky - riadky bunky,
    ak ich pocet pravidlo pripusti (aj pri zamietnuti iba pokrytim), inak None (zaznam vtedy nesie [], L1)."""
    k = korpusy(rodina)
    verdikt = k.bunky[(bunka, rola)].a.values.get("acceptance")
    assert type(verdikt) is dict
    tolerovane = _neplatne(bunka, k.w, k.f) if BUNKY[bunka][1] <= k.p["invalid_rows"]["max"] else None
    assert (verdikt["role"], verdikt["tolerated_invalid_seq"]) == (rola, tolerovane)


# Doplnok 4 (must_fix 2): session roly, ktoru protokol nepridelil, a session bez roly.
ROLA_MIMO = "session role is not assigned by the protocol"
MIMO_KORPUSU = "pilot/attack data must not enter the benign corpus"
IBA_ROLY_KORPUSU = "only explicit benign corpus roles are accepted"
ROLY_MIMO = {"holdout": {"role": "holdout"}, "missing": {}, "null": {"role": None}}


def _relacia_mimo(koren, p, cesta, pripad):
    """Cista session dlzky korpusu mimo planu (ako K2): rola podla pripadu, vlastna skupina, posledny usek casu."""
    miesto = dict(ROLY_MIMO[pripad], group="other-1", scenario="steady", seed=11)
    s = bs.build_session(koren / "mimo", p, cesta, miesto, session_id="rola-" + pripad,
                         base=bs.time_base(p, miesto.get("role"), 0), quality={})
    return SimpleNamespace(s=s, a=bs.audit(s, p), miesto=miesto)


@pytest.mark.parametrize("rodina,pripad", [_p(r, pripad) for r in RODINY for pripad in ROLY_MIMO])
def test_rola_mimo_protokolu_na_audite(rodina, pripad, tmp_path):
    """Audit zamietne cistu session dlzky korpusu, ktorej rolu protokol nepridelil, jedinym dovodom roly; bez
    pridelenej dlzky nema pokrytie. Kladna dvojca: bunky k0 L1 (ta ista stavba na mieste planu)."""
    cesta = bs.write_protocol(tmp_path / "protokol.json", bs.family(rodina, bs.profile_dir(tmp_path / "profil")))
    p = collection.protocol(cesta)
    n, w, f = p["cycles"], p["window_rows"], p["full_every"]
    rel = _relacia_mimo(tmp_path, p, cesta, pripad)
    v = rel.a.values
    # Od balika B3 je chybajuca rola aj chybajucim klucom session.json (audit cita kazdy kluc povinne).
    chyba = ["missing key: session.json:role"] if pripad == "missing" else []
    assert (rel.a.code, v["accepted"], v["reasons"], v["score_coverage"]) == (2, False, chyba + [ROLA_MIMO], None)
    assert (v["snapshots"], v["windows"]) == (n, bs.window_count(n, w, f)) == (n, ROZHODNUTIA[rodina]["k0"][1])
    verdikt = v.get("acceptance")
    assert type(verdikt) is dict
    assert (verdikt["codes"], verdikt["role"], verdikt["assigned_rows"]) == (["role"], ROLY_MIMO[pripad].get("role"),
                                                                             None)


@pytest.mark.parametrize("miesto", SPOTREBITELIA)
def test_rola_mimo_protokolu_u_spotrebitelov(korpusy, miesto, tmp_path):
    """Pin (doplnok 4, P29): spotrebitelia odmietnu rolu mimo styroch roli korpusu vlastnou kontrolou struktury
    skor, nez sa opytaju funkcie prijatia. build: zaznam session roly holdout podvrhnuty na ciste prijatie (F1b);
    miesta indexu: prijaty index S3, v ktorom zaznam miesta podvrhu roly train nesie rolu holdout."""
    k = korpusy("S3")
    if miesto == "build":
        rel = _relacia_mimo(tmp_path, k.p, k.cesta, "holdout")
        zaznam = _sfalsuj(rel, tmp_path / "audit.json", _f1b)
        _odmietne(MIMO_KORPUSU, lambda: dataset.build(_audity_s(k, {"train": zaznam}), k.p, k.sha))
        return
    doc = json.loads(k.index.read_text())
    zmenene = [z for z in doc["sessions"] if z["id"] == k.cisty["train"].s.directory.name]
    assert len(zmenene) == 1
    zmenene[0]["role"] = "holdout"
    index = _zapis(tmp_path / "index.json", doc)
    volania = {"validate_index": lambda: validate_index(index), "nacitaj_role": lambda: po.nacitaj_role(index),
               "train_bundle": lambda: _trenuj(k, index, tmp_path / "balik")}
    _odmietne(IBA_ROLY_KORPUSU, volania[miesto])


# ------------------------------------------------------------------ L2: prijaty korpus na kazdom mieste

@pytest.mark.parametrize("rodina,miesto", [_p(r, m) for r in RODINY for m in SPOTREBITELIA])
def test_l2_prijaty_korpus(korpusy, rodina, miesto):
    k = korpusy(rodina)
    tabulka = {rola: sum(ROZHODNUTIA[rodina][rel.bunka][1] for rel in k.miesta[rola]) for rola in ROLY}
    assert tabulka == k.okna
    sessions = len(ROLY) * MIEST_NA_ROLU[rodina]
    if miesto == "build":
        assert (k.doc["complete"], k.doc["allocation_mismatches"], len(k.doc["sessions"])) == (True, [], sessions)
    elif miesto == "validate_index":
        doc, protokol, zaznamy = validate_index(k.index)
        assert protokol == json.loads(k.cesta.read_text()) and len(zaznamy) == sessions
    else:
        vysledok = po.nacitaj_role(k.index) if miesto == "nacitaj_role" else korpusy.trening(rodina)
        assert _okna_roli(vysledok, miesto) == {rola: tabulka[rola] for rola in NACITANE}


@pytest.mark.parametrize("rodina", RODINY)
def test_l2b_stavba_neodmietne_prijaty_korpus(korpusy, rodina):
    """Doplnok 4 (must_fix 4): build v tele testu, nie vo fixture - korpus prijatych session prijme cely a kazdy
    zaznam nesie rolu svojej session."""
    k = korpusy(rodina)
    try:
        doc = dataset.build(k.audity, k.p, k.sha)
    except ValueError as chyba:
        pytest.fail("stavba odmietla korpus prijatych session: " + str(chyba))
    assert (doc["complete"], doc["allocation_mismatches"]) == (True, [])
    assert {z["id"]: z["role"] for z in doc["sessions"]} == {rel.s.directory.name: rola for rola in ROLY
                                                             for rel in k.miesta[rola]}


# ------------------------------------------------------------------ L3 az L6: zaznamy zamietnutych session

L3_IDS = [_p(r, b, rola, m) for r in RODINY for b in ZAMIETNUTE[r] for rola in ROLY for m in SPOTREBITELIA]
L4_IDS = [_p(r, b, rola, m) for r in RODINY for b in ZAMIETNUTE[r] for rola in ROLY for m in MIESTA]
L5C_IDS = [_p(r, b, rola, m) for r in RODINY for b in ZAMIETNUTE[r] if DRUH[ROZHODNUTIA[r][b][0]] == "pocet"
           for rola in ROLY for m in MIESTA]


@pytest.mark.parametrize("rodina,bunka,rola,miesto", L3_IDS)
def test_l3_poctivy_zamietajuci_zaznam(korpusy, rodina, bunka, rola, miesto, tmp_path):
    k = korpusy(rodina)
    rel = k.navyse[(bunka, rola)]
    assert rel.a.code == 2
    _odmietne(NEPRIJATY_BUILD if miesto == "build" else NEPRIJATY_INDEX,
              lambda: _na_mieste(k, miesto, {rola: rel.a.path}, tmp_path))


def _falosny(korpusy, rodina, bunka, rola, miesto, tmp_path, falsifikat):
    k = korpusy(rodina)
    rel = k.navyse[(bunka, rola)]
    zaznam = _sfalsuj(rel, tmp_path / "audit.json", FALSIFIKATY[falsifikat](rel))
    sprava = SPRAVY[(falsifikat, DRUH[ROZHODNUTIA[rodina][bunka][0]])][miesto == "build"]
    _odmietne(sprava, lambda: _na_mieste(k, miesto, {rola: zaznam}, tmp_path))


@pytest.mark.parametrize("rodina,bunka,rola,miesto", L4_IDS)
def test_l4_f1_prepnuty_priznak(korpusy, rodina, bunka, rola, miesto, tmp_path):
    _falosny(korpusy, rodina, bunka, rola, miesto, tmp_path, "F1")


@pytest.mark.parametrize("rodina,bunka,rola,miesto", L4_IDS)
def test_l5_f1b_priznak_aj_vo_verdikte(korpusy, rodina, bunka, rola, miesto, tmp_path):
    _falosny(korpusy, rodina, bunka, rola, miesto, tmp_path, "F1b")


@pytest.mark.parametrize("rodina,bunka,rola,miesto", L5C_IDS)
def test_l5_f1c_riadky_vypisane(korpusy, rodina, bunka, rola, miesto, tmp_path):
    _falosny(korpusy, rodina, bunka, rola, miesto, tmp_path, "F1c")


@pytest.mark.parametrize("rodina,rola,miesto", [_p(r, rola, m) for r in RODINY for rola in ROLY
                                                for m in SPOTREBITELIA])
def test_l6_f3_prikraslene_cisla(korpusy, rodina, rola, miesto, tmp_path):
    """F3: poctivy prijimajuci zaznam k1 s oknami a pokrytim cistej session."""
    k = korpusy(rodina)
    ciste = bs.window_count(k.n, k.w, k.f)
    zaznam = _sfalsuj(k.navyse[("k1", rola)], tmp_path / "audit.json",
                      lambda v: v.update(windows=ciste, score_coverage=ciste / k.n))
    _odmietne(ROZDIEL, lambda: _na_mieste(k, miesto, {rola: zaznam}, tmp_path))


# ------------------------------------------------------------------ L7: presadeny archiv (F2)

@pytest.mark.parametrize("rodina,variant,rola,miesto", [_p(r, var, rola, m) for r, varianty, m, roly in F2_MATICA
                                                        for var in varianty for rola in roly])
def test_l7_f2_presadeny_archiv(korpusy, rodina, variant, rola, miesto, tmp_path):
    k = korpusy(rodina)
    zaznam, _ = _f2_zaznam(k, rola, variant, tmp_path)
    _odmietne(F2_SPRAVY[variant], lambda: _na_mieste(k, miesto, {rola: zaznam}, tmp_path))


@pytest.mark.parametrize("rodina,variant,rola", [_p(r, var, rola) for r, varianty, roly in F2_PIN
                                                 for var in varianty for rola in roly])
def test_l7_pin_validate_index_nevidi_f2(korpusy, rodina, variant, rola, tmp_path):
    """validate_index archiv neotvara: F2 neodmietne (zvysne riziko test_benign zatvara B7), build ano (L7)."""
    k = korpusy(rodina)
    zaznam, sha = _f2_zaznam(k, rola, variant, tmp_path)
    _, _, zaznamy = validate_index(_index_s(k, {rola: zaznam}, tmp_path / "index.json"))
    assert [z["features_sha256"] for z in zaznamy if z["id"] == k.cisty[rola].s.directory.name] == [sha]


@pytest.mark.parametrize("rodina,rola,miesto", [_p(*x) for x in F2_DVOJCE])
def test_l7_f2_dvojca(korpusy, rodina, rola, miesto, tmp_path):
    """Doplnok F3: stavba F2 bez porusenia da archiv cistej session; miesto ho prijme a zaznam je ako od build."""
    k = korpusy(rodina)
    nahrady = {}
    for i, r in enumerate(rola.split("+")):
        (tmp_path / str(i)).mkdir()
        nahrady[r], sha = _f2_zaznam(k, r, "dvojca", tmp_path / str(i))
        assert sha == k.cisty[r].a.values["features_sha256"]
    vysledok = _na_mieste(k, miesto, nahrady, tmp_path)
    if miesto == "build":
        assert vysledok["complete"] is True
        assert [z for z in vysledok["sessions"] if z["audit"] == str(nahrady[rola].resolve())] == \
               [_zaznam_indexu(nahrady[rola], k.sha)]
    elif miesto == "validate_index":
        assert str(nahrady[rola].resolve()) in [z["audit"] for z in vysledok[2]]
    else:
        assert _okna_roli(vysledok, miesto) == {r: k.okna[r] for r in NACITANE}


# ------------------------------------------------------------------ L8: nacitanie protokolu iff audit

def test_l8_s3_sa_nacita_a_audit_prijme_najhorsi_pripad(korpusy):
    k = korpusy("S3")
    assert collection.protocol(k.cesta) == json.loads(k.cesta.read_text())
    for bunka in ("k1", "k2i", "k2c", "k3i", "k3c"):  # najviac max tolerovanych riadkov, k3i je najhorsi pripad
        for rola in ROLY:
            a = k.bunky[(bunka, rola)].a
            assert (a.code, a.values["accepted"]) == (0, True), (bunka, rola)
    assert bs.window_count(k.n, k.w, k.f, _neplatne("k3i", k.w, k.f)) / k.n == k.p["min_score_coverage"]


def test_l8_s3plus_sa_nenacita(tmp_path):
    cesta = bs.write_protocol(tmp_path / "s3plus.json", bs.family("S3+", bs.profile_dir(tmp_path / "profil")))
    _odmietne(NAJHORSI, lambda: collection.protocol(cesta))


def test_l8_s2g_sa_nacita_a_k3i_zamietne_iba_pokrytie(korpusy, tmp_path):
    """Svedok: tie iste cisla pod schemou 2 sa nacitaju a audit zamietne k3i (najviac max riadkov) pokrytim."""
    k = korpusy("S2G")
    assert k.p["min_score_coverage"] == bs.family("S3+", tmp_path)["min_score_coverage"]
    assert collection.protocol(k.cesta) == json.loads(k.cesta.read_text())
    for rola in ROLY:
        a = k.bunky[("k3i", rola)].a
        assert (a.code, len(a.values["reasons"])) == (2, 1) and a.values["reasons"][0].startswith(POKRYTIE_DOVOD)


SCHEMY = {1: "hyptcn3/collection-protocol/1", 2: "hyptcn3/collection-protocol/2", 3: "hyptcn3/collection-protocol/3"}


def _protokol_brany(tmp_path, schema, kluc, navyse):
    """S3 pod danou schemou s branou na cistom podiele dlzky `kluc` plus `navyse` okien (sekcia 7, L8)."""
    doc = bs.family("S3", bs.profile_dir(tmp_path / "profil"))
    doc["schema"] = SCHEMY[schema]
    if schema == 1:
        del doc["quality_policy"]  # schema 1 politiku nenesie (legacy)
    if schema != 3:  # oddiely auditu a vynimiek nesie iba schema 3 (balik B3)
        del doc["audit"], doc["exceptions"]
    if kluc == "cycles":
        doc["pilot_cycles"] = 128  # dlhsi pilot: jeho cisty podiel (112 zo 128) je nad podielom session
    dlzka = doc[kluc]
    doc["min_score_coverage"] = (bs.window_count(dlzka, doc["window_rows"], doc["full_every"]) + navyse) / dlzka
    for k in ("pilot_cycles", "cycles"):
        if k != kluc:  # druha dlzka branu dosiahne, takze sprava menuje prave `kluc`
            assert not bs.window_count(doc[k], doc["window_rows"], doc["full_every"]) / doc[k] < \
                doc["min_score_coverage"]
    return bs.write_protocol(tmp_path / "protokol.json", doc)


@pytest.mark.parametrize("schema,kluc", [_p(s, kl) for s in SCHEMY for kl in ("pilot_cycles", "cycles")])
def test_l8_nedosiahnutelna_cista_brana(schema, kluc, tmp_path):
    cesta = _protokol_brany(tmp_path, schema, kluc, 1)
    with pytest.raises(ValueError, match="^" + re.escape(NEDOSIAHNUTELNA + kluc) + "$"):
        collection.protocol(cesta)


@pytest.mark.parametrize("schema,kluc", [_p(s, kl) for s in (1, 2) for kl in ("pilot_cycles", "cycles")])
def test_l8_brana_na_cistom_podiele_sa_nacita(schema, kluc, tmp_path):
    """Dvojca: brana presne na cistom podiele sa nacita (pod schemou 3 by ju odmietol najhorsi pripad)."""
    cesta = _protokol_brany(tmp_path, schema, kluc, 0)
    assert collection.protocol(cesta) == json.loads(cesta.read_text())


# ------------------------------------------------------------------ L9: kladna kontrola podvrhovania

@pytest.mark.parametrize("rodina,rola,miesto", [_p(r, rola, m) for r in RODINY for rola in ROLY
                                                for m in ("build", "validate_index", "nacitaj_role")])
def test_l9_kladna_kontrola(korpusy, rodina, rola, miesto, tmp_path):
    """Ten isty postup, ktory dava zamietnuty zaznam na miesto podvrhu, tam da prijatu session k1."""
    k = korpusy(rodina)
    rel = k.navyse[("k1", rola)]
    vysledok = _na_mieste(k, miesto, {rola: rel.a.path}, tmp_path)
    sid = rel.s.directory.name
    if miesto == "build":
        assert vysledok["complete"] is True
        assert [z for z in vysledok["sessions"] if z["id"] == sid] == [_zaznam_indexu(rel.a.path, k.sha)]
    elif miesto == "validate_index":
        ids = [z["id"] for z in vysledok[2]]
        assert sid in ids and k.cisty[rola].s.directory.name not in ids
    else:
        ocakavane = {r: k.okna[r] for r in NACITANE}
        if rola in NACITANE:
            ocakavane[rola] += ROZHODNUTIA[rodina]["k1"][1] - ROZHODNUTIA[rodina]["k0"][1]
        assert _okna_roli(vysledok, miesto) == ocakavane


@pytest.mark.parametrize("rodina", RODINY)
def test_l9_kladna_kontrola_treningu(korpusy, rodina, tmp_path):
    """k1 na mieste podvrhu vsetkych styroch roli naraz, jeden trening na rodinu."""
    k = korpusy(rodina)
    vysledok = _na_mieste(k, "train_bundle", {rola: k.navyse[("k1", rola)].a.path for rola in ROLY}, tmp_path)
    rozdiel = ROZHODNUTIA[rodina]["k1"][1] - ROZHODNUTIA[rodina]["k0"][1]
    assert _okna_roli(vysledok, "train_bundle") == {r: k.okna[r] + rozdiel for r in NACITANE}


DVOJCE_F1B = [_p(r, m) for r in RODINY for m in ("build", "validate_index", "nacitaj_role")] + \
             [_p("S3", "train_bundle")]


@pytest.mark.parametrize("rodina,miesto", DVOJCE_F1B)
def test_dvojca_f1b_prijateho_zaznamu(korpusy, rodina, miesto, tmp_path):
    """Doplnok F3 cez _sfalsuj (doplnok 4, should_fix 2): F1b prijateho zaznamu k1 je identita; na mieste podvrhu
    vsetkych styroch roli naraz ho miesto prijme s ocakavaniami kladnej kontroly L9."""
    k = korpusy(rodina)
    nahrady = {}
    for rola in ROLY:
        rel = k.navyse[("k1", rola)]
        nahrady[rola] = _sfalsuj(rel, tmp_path / (rola + ".json"), _f1b)
        assert json.loads(nahrady[rola].read_text()) == rel.a.record
    vysledok = _na_mieste(k, miesto, nahrady, tmp_path)
    if miesto == "build":
        assert vysledok["complete"] is True
        for rola in ROLY:
            sid = k.navyse[("k1", rola)].s.directory.name
            assert [z for z in vysledok["sessions"] if z["id"] == sid] == [_zaznam_indexu(nahrady[rola], k.sha)]
    elif miesto == "validate_index":
        ids = [z["id"] for z in vysledok[2]]
        for rola in ROLY:
            assert k.navyse[("k1", rola)].s.directory.name in ids and k.cisty[rola].s.directory.name not in ids
    else:
        rozdiel = ROZHODNUTIA[rodina]["k1"][1] - ROZHODNUTIA[rodina]["k0"][1]
        assert _okna_roli(vysledok, miesto) == {r: k.okna[r] + rozdiel for r in NACITANE}


# ------------------------------------------------------------------ L10: strazca a negativna kontrola (iba B2)

def _zaznamnik(monkeypatch):
    acceptance = pytest.importorskip("features.acceptance")
    povodny, volania = acceptance._verdict, []

    def zaznamenaj(*args, **kwargs):
        volania.append(args[1] if len(args) > 1 else kwargs.get("role"))
        return povodny(*args, **kwargs)
    monkeypatch.setattr(acceptance, "_verdict", zaznamenaj)
    return volania


def _zaznamnik_archivov(monkeypatch):
    """Mena session, ktorych archiv (alebo vysledok extrakcie) rozhodla funkcia: volania session_facts."""
    acceptance = pytest.importorskip("features.acceptance")
    povodny, mena = acceptance.session_facts, []

    def zaznamenaj(*args, **kwargs):
        mena.append(args[2] if len(args) > 2 else kwargs.get("session"))
        return povodny(*args, **kwargs)
    monkeypatch.setattr(acceptance, "session_facts", zaznamenaj)
    return mena


def _vzdy_prijme(monkeypatch):
    acceptance = pytest.importorskip("features.acceptance")
    povodny = acceptance._verdict
    monkeypatch.setattr(acceptance, "_verdict",
                        lambda *a, **kw: dict(povodny(*a, **kw), accepted=True, reasons=[], codes=[]))


@pytest.mark.parametrize("miesto", ["protocol", "audit", *SPOTREBITELIA])
def test_l10a_strazca(korpusy, miesto, monkeypatch, tmp_path):
    """Kazde miesto na vlastnom prijatom vstupe S3 zavola _verdict aspon raz a vrati svoj bezny vysledok; miesto,
    ktore otvara archivy, kazdy z nich rozhodne samo (session_facts s menom jeho session; doplnok 4, must_fix 1)."""
    pytest.importorskip("features.acceptance")
    k = korpusy("S3")  # korpus, index aj trening pred nahradou: zdielane fixtury vznikaju s povodnou funkciou
    index = k.index
    nacitane = {z["id"] for z in k.doc["sessions"] if z["role"] in NACITANE}  # archivy, ktore otvaraju nacitania
    if miesto == "train_bundle":
        vysledok = korpusy.trening("S3")  # jediny trening L2, ziadny druhy; zaznam volani je z jeho behu
        volania, archivy = korpusy.zaznam_treningu("S3").verdikty, korpusy.zaznam_treningu("S3").archivy
    else:
        volania, archivy = _zaznamnik(monkeypatch), _zaznamnik_archivov(monkeypatch)
        assert volania == []
        assert archivy == []
    if miesto == "protocol":
        assert collection.protocol(k.cesta) == json.loads(k.cesta.read_text())
    elif miesto == "audit":
        rel = k.navyse[("k1", "train")]
        a = bs.audit(rel.s, k.p, output=tmp_path / "audit.json")
        assert (a.code, a.values["accepted"]) == (0, True)
        assert rel.s.directory.name in archivy
    elif miesto == "build":
        assert dataset.build(k.audity, k.p, k.sha)["complete"] is True
        mena = {Path(a).parent.name for a in k.audity}  # adresar session = jej id (pomocnik K0)
        assert len(mena) == len(k.audity) and set(archivy) >= mena
    elif miesto == "validate_index":
        assert len(validate_index(index)[2]) == len(k.audity)
        assert len(volania) >= len(k.audity)  # aspon jeden _verdict na zaznam indexu
    else:
        if miesto == "nacitaj_role":
            vysledok = po.nacitaj_role(index)
        assert _okna_roli(vysledok, miesto) == {r: k.okna[r] for r in NACITANE}
        assert nacitane and set(archivy) >= nacitane
    assert len(volania) >= 1


def test_l10b_nacitanie_prijme_s3plus(monkeypatch, tmp_path):
    cesta = bs.write_protocol(tmp_path / "s3plus.json", bs.family("S3+", bs.profile_dir(tmp_path / "profil")))
    _vzdy_prijme(monkeypatch)
    assert collection.protocol(cesta) == json.loads(cesta.read_text())


@pytest.mark.parametrize("rodina,bunka", [_p("S2G", "k3i"), _p("V4", "k2i"), _p("V4", "k3i")])
def test_l10b_audit_prijme_bunku_iba_pokrytia(korpusy, rodina, bunka, monkeypatch, tmp_path):
    rel = korpusy(rodina).bunky[(bunka, "train")]
    assert rel.a.code == 2  # bez nahrady zamietnuta (L1)
    _vzdy_prijme(monkeypatch)
    a = bs.audit(rel.s, korpusy(rodina).p, output=tmp_path / "audit.json")
    assert (a.code, a.values["accepted"], a.values["reasons"]) == (0, True, [])


@pytest.mark.parametrize("miesto", SPOTREBITELIA)
def test_l10b_spotrebitel_prijme_f1b_bunky_iba_pokrytia(korpusy, miesto, monkeypatch, tmp_path):
    """Bez vlastneho pravidla miesta: s vzdy prijimajucim _verdict prejde F1b S2G k3i (bez nahrady L5 odmieta)."""
    k = korpusy("S2G")
    rel = k.navyse[("k3i", "train")]
    zaznam = _sfalsuj(rel, tmp_path / "audit.json", _f1b)
    _vzdy_prijme(monkeypatch)
    vysledok = _na_mieste(k, miesto, {"train": zaznam}, tmp_path)
    if miesto == "build":
        assert vysledok["complete"] is True
    elif miesto == "validate_index":
        assert rel.s.directory.name in [z["id"] for z in vysledok[2]]
    else:
        ocakavane = {r: k.okna[r] for r in NACITANE}
        ocakavane["train"] += ROZHODNUTIA["S2G"]["k3i"][1] - ROZHODNUTIA["S2G"]["k0"][1]
        assert _okna_roli(vysledok, miesto) == ocakavane


# ------------------------------------------------------------------ doplnok D2, D3, D6: polia a poradie kontrol

def _fakty(**polia):
    def zmena(v):
        if type(v.get("acceptance")) is dict:
            v["acceptance"]["facts"].update(polia)
    return zmena


def _neplatny(seq, **polia):
    return dict({"seq": seq, "truncated_traversals": ["processes"], "read_errors": 0, "filled_zero": 0}, **polia)


def _polia(k):
    """Doplnok D2 na mieste zaznamu: pole -> (zmena iba toho pola v prijatom zazname k1, sprava validate_index)."""
    n, w, f = k.n, k.w, k.f
    ciste, seq = bs.window_count(n, w, f), bs.isolated_seqs(4, w, f)
    pod_branou = max(o for o in range(n + 1) if o / n < k.p["min_score_coverage"])

    def bez_verdiktu(v):
        v.pop("acceptance", None)

    def verdikt_nie_slovnik(v):
        if "acceptance" in v:
            v["acceptance"] = [v["acceptance"]]
    return {
        # Polia suhrnu zaznamu (_same).
        "snapshots": (lambda v: v.update(snapshots=n - 1), ROZDIEL),
        "windows": (lambda v: v.update(windows=ciste), ROZDIEL),
        "score_coverage": (lambda v: v.update(score_coverage=ciste / n), ROZDIEL),
        "tolerated_invalid_seq": (lambda v: v["quality"].update(tolerated_invalid_seq=[]), ROZDIEL),
        "role": (lambda v: v.update(role="dev" if v["role"] != "dev" else "train"), NEPRIJATY_INDEX),
        # Polia ulozeneho verdiktu.
        "acceptance.schema": (lambda v: _verdikt(v, schema="hyptcn3/session-acceptance/0"), ROZDIEL),
        "acceptance.accepted": (lambda v: _verdikt(v, accepted=False), ROZDIEL),
        "acceptance.reasons": (lambda v: _verdikt(v, reasons=[POKRYTIE_DOVOD]), ROZDIEL),
        "acceptance.codes": (lambda v: _verdikt(v, codes=["coverage"]), ROZDIEL),
        "acceptance.role": (lambda v: _verdikt(v, role="dev" if v["role"] != "dev" else "train"), ROZDIEL),
        "acceptance.assigned_rows": (lambda v: _verdikt(v, assigned_rows=n - 1), ROZDIEL),
        "acceptance.gate": (lambda v: _verdikt(v, gate=1), ROZDIEL),
        "acceptance.snapshots": (lambda v: _verdikt(v, snapshots=n - 1), ROZDIEL),
        "acceptance.windows": (lambda v: _verdikt(v, windows=ciste), ROZDIEL),
        "acceptance.score_coverage": (lambda v: _verdikt(v, score_coverage=ciste / n), ROZDIEL),
        "acceptance.tolerated_invalid_seq": (lambda v: _verdikt(v, tolerated_invalid_seq=[]), ROZDIEL),
        # Fakty ulozene s verdiktom, rozhodnute znova.
        "facts.snapshots": (_fakty(snapshots=n - 1), ODMIETA + POCET_SNIMOK),
        "facts.sequence_contiguous": (_fakty(sequence_contiguous=False), ODMIETA + POSTUPNOST),
        "facts.invalid_rows.nad_max": (_fakty(invalid_rows=[_neplatny(s) for s in seq]), NAD_POCET),
        "facts.invalid_rows.pricina": (_fakty(invalid_rows=[_neplatny(seq[0], read_errors=1)]), PRICINA),
        "facts.invalid_rows.seq": (_fakty(invalid_rows=[_neplatny(seq[1])]), ROZDIEL),
        "facts.integrity_findings": (_fakty(integrity_findings=1), ODMIETA + INTEGRITA),
        "facts.windows.pod_branou": (_fakty(windows=pod_branou), ODMIETA + POKRYTIE_DOVOD),
        "facts.windows.ciste": (_fakty(windows=ciste), ROZDIEL),
        "facts.windows.text": (_fakty(windows=str(ROZHODNUTIA[k.rodina]["k1"][1])), FAKTY),
        "acceptance.chyba": (bez_verdiktu, BEZ_VERDIKTU),
        "acceptance.nie_slovnik": (verdikt_nie_slovnik, BEZ_VERDIKTU),
        "acceptance.kluc_navyse": (lambda v: _verdikt(v, note="navyse"), ROZDIEL),
    }


POLIA = ("snapshots", "windows", "score_coverage", "tolerated_invalid_seq", "role", "acceptance.schema",
         "acceptance.accepted", "acceptance.reasons", "acceptance.codes", "acceptance.role",
         "acceptance.assigned_rows", "acceptance.gate", "acceptance.snapshots", "acceptance.windows",
         "acceptance.score_coverage", "acceptance.tolerated_invalid_seq", "facts.snapshots",
         "facts.sequence_contiguous", "facts.invalid_rows.nad_max", "facts.invalid_rows.pricina",
         "facts.invalid_rows.seq", "facts.integrity_findings", "facts.windows.pod_branou", "facts.windows.ciste",
         "facts.windows.text", "acceptance.chyba", "acceptance.nie_slovnik", "acceptance.kluc_navyse")


@pytest.mark.parametrize("rodina,rola,pole", [_p(r, rola, pole) for r in RODINY for rola in ("train", "test_benign")
                                              for pole in POLIA])
def test_d2_pole_zaznamu(korpusy, rodina, rola, pole, tmp_path):
    """Zmena jedineho pola prijateho zaznamu k1; validate_index ho odmietne (pole role uz vlastnou kontrolou)."""
    k = korpusy(rodina)
    polia = _polia(k)
    assert set(polia) == set(POLIA)
    zmena, sprava = polia[pole]
    zaznam = _sfalsuj(k.navyse[("k1", rola)], tmp_path / "audit.json", zmena)
    _odmietne(sprava, lambda: _na_mieste(k, "validate_index", {rola: zaznam}, tmp_path))


@pytest.mark.parametrize("rodina", RODINY)
def test_d2_build_bez_verdiktu(korpusy, rodina, tmp_path):
    k = korpusy(rodina)
    zaznam = _sfalsuj(k.navyse[("k1", "train")], tmp_path / "audit.json", lambda v: v.pop("acceptance", None))
    _odmietne(BEZ_VERDIKTU, lambda: _na_mieste(k, "build", {"train": zaznam}, tmp_path))


def _okna_ciste(v, k):
    v.update(windows=bs.window_count(k.n, k.w, k.f))


# Doplnok D3: jeden pripad porusi dve kontroly naraz, vyhra sprava skorsej.
# pripad -> (rodina, bunka, zmeny(k), miesto, sprava)
DVE_PORUSENIA = {
    "validate_index-f1-zly_hash_vo_vysledku_auditu": (
        "S2G", "k3i", lambda k: [_f1, lambda v: v.update(features_sha256="0" * 64)], "validate_index",
        NEPRIJATY_INDEX),
    "validate_index-f1-okna": ("S2G", "k3i", lambda k: [_f1, lambda v: _okna_ciste(v, k)], "validate_index",
                               ODMIETA + POKRYTIE_DOVOD),
    "validate_index-f1-bez_verdiktu": ("S2G", "k3i", lambda k: [_f1, lambda v: v.pop("acceptance", None)],
                                       "validate_index", BEZ_VERDIKTU),
    "build-f1-ina_rola": ("S3", "k4i", lambda k: [_f1, lambda v: v.update(role="dev")], "build", INA_ROLA),
    "build-f1c-okna": ("S3", "k4i", lambda k: [_f1c(k.navyse[("k4i", "train")].a.archive),
                                               lambda v: _okna_ciste(v, k)], "build", NAD_POCET),
    "build-f1-bez_verdiktu": ("S2G", "k3i", lambda k: [_f1, lambda v: v.pop("acceptance", None)], "build",
                              ODMIETA + POKRYTIE_DOVOD),
}


@pytest.mark.parametrize("pripad", list(DVE_PORUSENIA))
def test_d3_dve_porusenia(korpusy, pripad, tmp_path):
    rodina, bunka, zmeny, miesto, sprava = DVE_PORUSENIA[pripad]
    k = korpusy(rodina)
    zaznam = _sfalsuj(k.navyse[(bunka, "train")], tmp_path / "audit.json", *zmeny(k))
    _odmietne(sprava, lambda: _na_mieste(k, miesto, {"train": zaznam}, tmp_path))


# Doplnok D6: zly typ vstupu, ktory miesto cita samo; prijaty zaznam k1 S3 roly train.
TYPY = {"build-accepted_1": ("build", {"accepted": 1}, NEPRIJATY_BUILD),
        "build-accepted_text": ("build", {"accepted": "true"}, NEPRIJATY_BUILD),
        "build-reasons_null": ("build", {"reasons": None}, NECISTY),
        "validate_index-accepted_1": ("validate_index", {"accepted": 1}, NEPRIJATY_INDEX),
        "validate_index-reasons_null": ("validate_index", {"reasons": None}, NECISTY)}


@pytest.mark.parametrize("pripad", list(TYPY))
def test_d6_typy_zaznamu(korpusy, pripad, tmp_path):
    miesto, polia, sprava = TYPY[pripad]
    k = korpusy("S3")
    zaznam = _sfalsuj(k.navyse[("k1", "train")], tmp_path / "audit.json", lambda v: v.update(polia))
    _odmietne(sprava, lambda: _na_mieste(k, miesto, {"train": zaznam}, tmp_path))


# ------------------------------------------------------------------ doplnok 4: D4 (n + 1 riadkov) a D2b

D4_ROLY = ("train", "test_benign")


@pytest.mark.parametrize("rodina,rola", [_p(r, rola) for r in RODINY for rola in D4_ROLY])
def test_d4_fakty_s_riadkom_navyse(korpusy, rodina, rola, tmp_path):
    """Doplnok D4, druha strana hranice poctu riadkov (D2 ma n - 1): ulozene fakty prijateho zaznamu k1 s n + 1
    snimkami; validate_index ich rozhodne znova a odmietne poctom riadkov."""
    k = korpusy(rodina)
    zaznam = _sfalsuj(k.navyse[("k1", rola)], tmp_path / "audit.json", _fakty(snapshots=k.n + 1))
    _odmietne(ODMIETA + POCET_SNIMOK, lambda: _na_mieste(k, "validate_index", {rola: zaznam}, tmp_path))


def _archiv_uplny(k, rola, riadky, ciel):
    """Archiv `riadky` uplnych riadkov (seq 0..riadky-1, nic nechyba) stavbou F2 z cistej session miesta podvrhu."""
    cisty = k.cisty[rola]
    vysledok, _ = bs.extraction_result(cisty.s.directory.name, riadky, k.f, t0=cisty.s.result["casy"][0],
                                       interval_s=k.p["interval_s"], quality={}, missing=set(),
                                       seed=cisty.miesto["seed"], max_gap_s=k.p["max_gap_s"])
    return bs.save_archive(ciel, vysledok)


@pytest.mark.parametrize("rodina,rola,miesto", [_p("S3", rola, "build") for rola in ROLY])
def test_d4_f2_archiv_s_riadkom_navyse(korpusy, rodina, rola, miesto, tmp_path):
    """Doplnok D4 na mieste archivu: cisty zaznam nad archivom n + 1 uplnych riadkov. Iba build: nacitania porovnaju
    posledny cas archivu s indexom skor a odmietli by ho vlastnou spravou."""
    k = korpusy(rodina)
    _, dvojca = _archiv_uplny(k, rola, k.n, tmp_path / "dvojca.npz")
    assert dvojca == k.cisty[rola].a.values["features_sha256"]  # ta ista stavba s n riadkami da cisty archiv
    archiv, sha = _archiv_uplny(k, rola, k.n + 1, tmp_path / "f2.npz")
    assert [int(s) for s in load(archiv)["seq"]] == list(range(k.n + 1))
    zaznam = _sfalsuj(k.cisty[rola], tmp_path / "audit.json",
                      lambda v: v.update(features=str(archiv), features_sha256=sha))
    _odmietne(ODMIETA + POCET_SNIMOK, lambda: _na_mieste(k, miesto, {rola: zaznam}, tmp_path))


# Doplnok 4 (should_fix 4): ostatne polia ulozeneho neplatneho riadku, jedno naraz (D2 meni read_errors).
D2B_POLIA = {"filled_zero": {"filled_zero": 1}, "truncated_traversals": {"truncated_traversals": ["modules"]}}


@pytest.mark.parametrize("rodina,rola,pole", [_p(r, rola, pole) for r in RODINY for rola in D4_ROLY
                                              for pole in D2B_POLIA])
def test_d2b_pricina_ulozeneho_riadku(korpusy, rodina, rola, pole, tmp_path):
    """Ulozeny riadok prijateho zaznamu k1 s pricinou, ktoru pravidlo netoleruje (pravidlo menuje iba processes)."""
    k = korpusy(rodina)
    seq = bs.isolated_seqs(4, k.w, k.f)
    zaznam = _sfalsuj(k.navyse[("k1", rola)], tmp_path / "audit.json",
                      _fakty(invalid_rows=[_neplatny(seq[0], **D2B_POLIA[pole])]))
    _odmietne(PRICINA, lambda: _na_mieste(k, "validate_index", {rola: zaznam}, tmp_path))


@pytest.mark.parametrize("rodina,rola", [_p(r, rola) for r in RODINY for rola in D4_ROLY])
def test_d2b_dvojca_ulozeneho_riadku(korpusy, rodina, rola, tmp_path):
    """Kladna dvojca D2b: ta ista zmena s poctivym riadkom je identita a validate_index zaznam prijme."""
    k = korpusy(rodina)
    rel = k.navyse[("k1", rola)]
    seq = bs.isolated_seqs(4, k.w, k.f)
    assert seq[:1] == _neplatne("k1", k.w, k.f)
    verdikt = rel.a.values.get("acceptance")
    if type(verdikt) is dict:  # pred B2 zaznam fakty nenesie a _fakty nic nemeni
        assert verdikt["facts"]["invalid_rows"] == [{"seq": seq[0], "truncated_traversals": ["processes"],
                                                     "read_errors": 0, "filled_zero": 0}]
    zaznam = _sfalsuj(rel, tmp_path / "audit.json", _fakty(invalid_rows=[_neplatny(seq[0])]))
    assert json.loads(zaznam.read_text()) == rel.a.record
    ids = [z["id"] for z in _na_mieste(k, "validate_index", {rola: zaznam}, tmp_path)[2]]
    assert rel.s.directory.name in ids and k.cisty[rola].s.directory.name not in ids
