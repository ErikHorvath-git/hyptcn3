"""
Manifest normalizacie: poradie priznakov, jeho hash a fitnute mu/sd.

PRECO samostatny modul: poradie priznakov je kontrakt medzi treningom a
inferenciou. V predchadzajucej iteracii (hypTcn002) sa z-score fitovala pri
treningu a pri skorovani sa pocitala znova z inych dat - model potom v
prevadzke videl ine rozdelenie nez pri treningu. Manifest existuje preto, aby
sa take nieco dalo zachytit strojovo: pri nacitani sa overuje schema, poradie
priznakov aj jeho hash, a nesedici manifest je chyba, nie varovanie.

KTORE KLUCE per-bin bloku su priznaky modelu (PRIZNAKY) a ktore nie
(NEPRIZNAKY):

  bin, gpa       identita binu. Bin je viazany na fyzicku adresu, takze index
                 sam o sebe nesie iba to, kde v RAM sme; ako cislo na vstupe
                 modelu by to bola konstanta na kanal (pri rezime po binoch)
                 alebo priamo adresa (pri zlucenych binoch). Poradie kanalov
                 tuto informaciu uz nesie.
  pages_total    podlozenost binu memslotmi. Medzi snimkami tej istej VM sa
                 nemeni (memsloty sa pocas behu nepresuvaju), takze by to bol
                 konstantny kanal; napriec VM roznej velkosti by to bol priamo
                 odtlacok velkosti VM - presne ten druh premennej, ktora robi
                 confound. Zostava ako menovatel pomerov, nie ako priznak.
  pages_changed  absolutny pocet zmenenych stranok. Je to changed_ratio krat
                 pages_total, teda ta ista informacia vynasobena velkostou
                 binu; biny s vacsou podlozenostou by dominovali. Do vektora
                 ide iba pomer, absolutny pocet zostava v sidecari na kontrolu
                 invariantu (sucet cez biny == output.pages_changed).

Normalizuju sa:  changed_ratio, zero_ratio, entropy_mean
Nenormalizuje sa: has_changed

  has_changed je indikator 0/1 s presnym vyznamom "bin sa od predchadzajucej
  snimky zmenil". Po z-score by z nuly bola nejaka zaporna hodnota zavisla od
  toho, ako casto sa biny menili vo fitovacej mnozine, a stratil by sa jediny
  udaj, ktory odlisuje "nezmenilo sa" od "entropia vysla 0". Ostava 0/1.
  Rozsah 0..1 aj tak ziadnu normalizaciu nepotrebuje.

  changed_ratio a zero_ratio su tiez v 0..1, ale ich rozdelenia su velmi
  nerovnake (vacsina binov sa medzi dvoma snimkami nezmeni, zero_ratio sa
  pohybuje blizko jednotky v nepouzitych oblastiach) - z-score ich prevedie na
  porovnatelnu skalu. entropy_mean je v 0..8 bitov/bajt, teda inej skale nez
  pomery.

Povod: manifest ani jeho format neboli prevzate, vznikli pre tuto pracu.
"""

import hashlib
import json
import os

SCHEMA = "hyptcn3/normalize/1"

# Schema per-bin bloku v sidecari, nad ktorym manifest plati. Ked ju zmeni
# vyroba vektora, nacitanie starsieho manifestu ma padnut, nie sa tvarit.
SCHEMA_PERBIN = "hyptcn3/perbin/1"

# Poradie priznakov v poslednej osi vektora. Je to kontrakt - meni sa iba
# spolu s verziou schemy.
PRIZNAKY = ("changed_ratio", "zero_ratio", "entropy_mean", "has_changed")

# Priznaky, ktore z-score nedostanu (dovod je v hlavicke modulu).
NENORMALIZOVANE = ("has_changed",)

# Kluce per-bin bloku, ktore priznakmi modelu nie su (dovod v hlavicke).
NEPRIZNAKY = ("bin", "gpa", "pages_total", "pages_changed")

# Priznak -> hradlovy priznak. mu/sd sa fituju iba na binoch, kde je hradlo 1.
# entropy_mean je definovana ako priemer cez ZMENENE stranky; v bine bez
# zmenenej stranky ziadna taka hodnota neexistuje a sidecar tam ma nulu. Keby
# tieto nuly vstupili do mu/sd, priemer by nehovoril o entropii pamate, ale o
# tom, kolko binov sa nemenilo. Do transformacie vstupuju vsetky hodnoty -
# nula sa po z-score stane zapornym cislom a model ma vedla seba has_changed,
# ktory povie, ze tam entropia nebola meranim.
PODMIENENE = {"entropy_mean": "has_changed"}

# Rezimy fitovania: jedna dvojica mu/sd na priznak, alebo zvlast na kazdy bin.
REZIMY = ("priznak", "bin_priznak")


class ManifestError(Exception):
    pass


def hash_priznakov(priznaky):
    """SHA-256 poradia priznakov.

    Hashuje sa poradie, nie mnozina: prehodenie dvoch priznakov by inak
    preslo, a model by dostal entropiu tam, kde caka pomer.
    """
    data = "\n".join(priznaky).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _tuple_str(hodnoty, kde):
    if isinstance(hodnoty, str) or not isinstance(hodnoty, (list, tuple)):
        raise ManifestError("%s ma byt zoznam retazcov, je %r" % (kde, type(hodnoty)))
    out = []
    for h in hodnoty:
        if not isinstance(h, str):
            raise ManifestError("%s obsahuje nepovolenu polozku %r" % (kde, h))
        out.append(h)
    return tuple(out)


def _pole_float(pole, kde):
    """Rekurzivne overi, ze pole obsahuje iba cisla, a vrati ho ako zoznamy."""
    if isinstance(pole, (list, tuple)):
        return [_pole_float(p, kde) for p in pole]
    if isinstance(pole, bool) or not isinstance(pole, (int, float)):
        raise ManifestError("%s obsahuje necislo %r" % (kde, pole))
    return float(pole)


def _tvar(pole):
    """Tvar vnoreneho zoznamu; nerovnomerny zoznam je chyba."""
    if not isinstance(pole, list):
        return ()
    tvary = {_tvar(p) for p in pole}
    if len(tvary) > 1:
        raise ManifestError("mu/sd nie su obdlznikove pole: tvary %r" % (sorted(tvary),))
    vnutro = tvary.pop() if tvary else ()
    return (len(pole),) + vnutro


class Manifest:
    """Ulozeny fit normalizacie aj s tym, na com bol fitnuty.

    Polia, ktore nesu dokaz o povode fitu (sessions, n_snimok, commit, date),
    nie su ozdoba: bez nich sa neda spatne overit, ze mu/sd vznikli iba z
    benignych trenovacich sessions.
    """

    def __init__(self, priznaky, nenormalizovane, rezim, mu, sd,
                 bin_bytes, biny=None, konstantne=(), podmienene=None,
                 sessions=(), n_snimok=0, n_binov=0, dlzka_okna=None,
                 commit=None, date=None, schema=SCHEMA,
                 schema_perbin=SCHEMA_PERBIN, priznaky_hash=None, poznamka=""):
        self.schema = schema
        self.schema_perbin = schema_perbin
        self.priznaky = _tuple_str(priznaky, "priznaky")
        self.nenormalizovane = _tuple_str(nenormalizovane, "nenormalizovane")
        self.rezim = rezim
        self.mu = _pole_float(list(mu), "mu")
        self.sd = _pole_float(list(sd), "sd")
        self.bin_bytes = int(bin_bytes)
        self.biny = tuple(int(b) for b in biny) if biny is not None else None
        self.konstantne = _tuple_str(konstantne, "konstantne")
        self.podmienene = dict(podmienene or {})
        self.sessions = _tuple_str(sessions, "sessions")
        self.n_snimok = int(n_snimok)
        self.n_binov = int(n_binov)
        self.dlzka_okna = int(dlzka_okna) if dlzka_okna is not None else None
        self.commit = commit
        self.date = date
        self.poznamka = poznamka
        self.priznaky_hash = priznaky_hash or hash_priznakov(self.priznaky)
        self._skontroluj()

    def _skontroluj(self):
        if self.schema != SCHEMA:
            raise ManifestError("neznama schema manifestu: %r (cakam %r)"
                                % (self.schema, SCHEMA))
        if self.rezim not in REZIMY:
            raise ManifestError("neznamy rezim fitu: %r (cakam %r)"
                                % (self.rezim, list(REZIMY)))
        if not self.priznaky:
            raise ManifestError("manifest bez priznakov")
        if len(set(self.priznaky)) != len(self.priznaky):
            raise ManifestError("poradie priznakov obsahuje duplicitu: %r"
                                % (self.priznaky,))
        ocakavany = hash_priznakov(self.priznaky)
        if self.priznaky_hash != ocakavany:
            raise ManifestError(
                "hash poradia priznakov nesedi: v manifeste %s, prepocitane %s"
                % (self.priznaky_hash, ocakavany))
        for meno in self.nenormalizovane:
            if meno not in self.priznaky:
                raise ManifestError("nenormalizovany priznak %r nie je v poradi"
                                    % (meno,))
        for meno, hradlo in self.podmienene.items():
            if meno not in self.priznaky or hradlo not in self.priznaky:
                raise ManifestError(
                    "podmieneny fit %r/%r odkazuje na priznak mimo poradia"
                    % (meno, hradlo))
        f = len(self.priznaky)
        if self.rezim == "priznak":
            cakany = (f,)
        else:
            if self.biny is None:
                raise ManifestError("rezim bin_priznak bez zoznamu binov")
            cakany = (len(self.biny), f)
        for meno, pole in (("mu", self.mu), ("sd", self.sd)):
            tvar = _tvar(pole)
            if tvar != cakany:
                raise ManifestError("%s ma tvar %r, cakam %r" % (meno, tvar, cakany))
        for hodnota in _splostit(self.sd):
            if not hodnota > 0.0:
                raise ManifestError("sd obsahuje nekladnu hodnotu %r; delenie "
                                    "nulou sa neopravuje ticho" % (hodnota,))
        if self.biny is not None:
            if list(self.biny) != sorted(self.biny):
                raise ManifestError("zoznam binov nie je vzostupny")
            if len(set(self.biny)) != len(self.biny):
                raise ManifestError("zoznam binov obsahuje duplicitu")
        if self.bin_bytes <= 0 or (self.bin_bytes & (self.bin_bytes - 1)) != 0:
            # index binu je GPA >> log2(bin_bytes), takze velkost musi byt
            # mocnina dvojky - inak posun neexistuje
            raise ManifestError("bin_bytes %d nie je kladna mocnina dvojky"
                                % (self.bin_bytes,))

    def to_dict(self):
        return {
            "schema": self.schema,
            "schema_perbin": self.schema_perbin,
            "date": self.date,
            "commit": self.commit,
            "rezim": self.rezim,
            "bin_bytes": self.bin_bytes,
            "dlzka_okna": self.dlzka_okna,
            "priznaky": list(self.priznaky),
            "priznaky_hash": self.priznaky_hash,
            "nenormalizovane": list(self.nenormalizovane),
            "podmienene": dict(self.podmienene),
            "konstantne": list(self.konstantne),
            "biny": list(self.biny) if self.biny is not None else None,
            "n_binov": self.n_binov,
            "n_snimok": self.n_snimok,
            "sessions": list(self.sessions),
            "mu": self.mu,
            "sd": self.sd,
            "poznamka": self.poznamka,
        }

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            raise ManifestError("manifest nie je objekt JSON")
        chybaju = [k for k in ("schema", "priznaky", "mu", "sd", "rezim", "bin_bytes")
                   if k not in d]
        if chybaju:
            raise ManifestError("v manifeste chybaju kluce: %s" % (", ".join(chybaju),))
        return cls(
            priznaky=d["priznaky"],
            nenormalizovane=d.get("nenormalizovane", ()),
            rezim=d["rezim"],
            mu=d["mu"],
            sd=d["sd"],
            bin_bytes=d["bin_bytes"],
            biny=d.get("biny"),
            konstantne=d.get("konstantne", ()),
            podmienene=d.get("podmienene"),
            sessions=d.get("sessions", ()),
            n_snimok=d.get("n_snimok", 0),
            n_binov=d.get("n_binov", 0),
            dlzka_okna=d.get("dlzka_okna"),
            commit=d.get("commit"),
            date=d.get("date"),
            schema=d["schema"],
            schema_perbin=d.get("schema_perbin", SCHEMA_PERBIN),
            priznaky_hash=d.get("priznaky_hash"),
            poznamka=d.get("poznamka", ""),
        )

    def save(self, cesta):
        """Zapise manifest ako JSON.

        sort_keys sa nepouziva: poradie klucov je dane to_dict a subor ma byt
        citatelny zhora nadol. Determinizmus zapisu drzi to_dict, nie triedic.
        """
        adresar = os.path.dirname(os.path.abspath(cesta))
        if adresar:
            os.makedirs(adresar, exist_ok=True)
        with open(cesta, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=True)
            fh.write("\n")
        return cesta

    @classmethod
    def load(cls, cesta):
        with open(cesta, encoding="utf-8") as fh:
            try:
                d = json.load(fh)
            except ValueError as e:
                raise ManifestError("manifest %s sa neda precitat ako JSON: %s"
                                    % (cesta, e))
        return cls.from_dict(d)

    def overit(self, priznaky=None, biny=None, bin_bytes=None,
               schema_perbin=None):
        """Porovna manifest s tym, co prislo na vstup. Nezhoda je vynimka.

        Toto je miesto, kde sa ma zachytit "model caka iny vektor, nez dostal".
        Kontroluje sa poradie (nie mnozina), pocet, velkost binu a - v rezime
        po binoch - aj konkretne indexy binov, lebo tie su viazane na fyzicku
        adresu a pri inej VM znamenaju ine miesto v RAM.
        """
        if priznaky is not None:
            priznaky = _tuple_str(priznaky, "priznaky")
            if len(priznaky) != len(self.priznaky):
                raise ManifestError(
                    "pocet priznakov nesedi: manifest %d, data %d"
                    % (len(self.priznaky), len(priznaky)))
            if priznaky != self.priznaky:
                raise ManifestError(
                    "poradie priznakov nesedi: manifest %r, data %r"
                    % (list(self.priznaky), list(priznaky)))
        if bin_bytes is not None and int(bin_bytes) != self.bin_bytes:
            raise ManifestError("bin_bytes nesedi: manifest %d, data %d"
                                % (self.bin_bytes, int(bin_bytes)))
        if schema_perbin is not None and schema_perbin != self.schema_perbin:
            raise ManifestError("schema per-bin bloku nesedi: manifest %r, data %r"
                                % (self.schema_perbin, schema_perbin))
        if biny is not None:
            biny = tuple(int(b) for b in biny)
            if self.rezim == "bin_priznak":
                if biny != self.biny:
                    raise ManifestError(
                        "indexy binov nesedia: manifest ma %d binov (%r...), "
                        "data %d (%r...)"
                        % (len(self.biny), list(self.biny[:4]),
                           len(biny), list(biny[:4])))
            # v rezime 'priznak' sa zoznam binov zamerne nekontroluje:
            # mu/sd nie su viazane na konkretny bin, takze manifest plati aj
            # pre VM s inym poctom binov
        return True


def _splostit(pole):
    if isinstance(pole, list):
        for p in pole:
            for x in _splostit(p):
                yield x
    else:
        yield pole
