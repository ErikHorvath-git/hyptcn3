"""
Z-score normalizacia snimkovych priznakov s ulozenym manifestom.

PRAVIDLO, kvoli ktoremu modul vznikol: mu a sd sa fituju IBA na benignych
TRENOVACICH sedeniach. Nikdy na testovacich a nikdy na sedeniach so scenarom.
V predchadzajucej iteracii (hypTcn002) sa statistiky pri skorovani pocitali
znova z prave videnych dat, takze model v prevadzke dostaval iny rozsah nez
pri treningu. Tu je fit artefakt: ulozi sa do manifestu (features/manifest.py)
spolu s poradim priznakov a jeho hashom, a pri nacitani sa overuje.

TVAR
----
Posledna os je priznak, vsetko pred nou je cokolvek (snimky, okna). Mu a sd su
jedna dvojica na priznak. Do 2026-09-19 vedel modul aj rezim `bin_priznak`,
teda mu/sd zvlast na kazdy bin nad per-bin vektorom (..., B, F) - ta vetva sa
zmazala spolu s per-bin oknami vo features/windows.py, lebo do modelu ide
snimkovy vektor z features/snapshot.py, v ktorom su biny uz agregovane.
Manifest (features/manifest.py) rezim aj tak ma; zapisuje sa don `priznak`.

CO SA NENORMALIZUJE
-------------------
Zoznam dava volajuci. Pre kontrakt z features/snapshot.py su to `ma_predchodcu`
a `je_plna`: su to indikatory 0/1, ktorych jedina uloha je povedat, co ten
riadok je. Z-score by tento vyznam zmazal - preto prejdu nezmenene (mu=0,
sd=1) a v manifeste je menom vidiet, ktore to boli.

FIT SA ROBI NAD SNIMKAMI, NIE NAD OKNAMI
----------------------------------------
Okna sa pri kroku 1 prekryvaju, takze ta ista snimka je v L oknach. Keby sa
mu/sd pocitali nad oknami, snimky zo stredu sedenia by mali az L-nasobnu vahu
oproti snimkam na kraji. Fit preto berie zoznam snimok (jedna snimka = jeden
casovy krok, zapocitana raz) a transform sa aplikuje na okna.

Povod: modul vznikol pre tuto pracu, nie je prevzaty.
"""

import datetime
import os
import subprocess

import numpy as np

from .manifest import Manifest, ManifestError
from .windows import Okna

# Pod touto hodnotou sa sd povazuje za nulove. Nedeli sa nim - priznak sa
# oznaci za konstantny, sd sa nastavi na 1.0 a meno ide do manifestu, aby bolo
# vidiet, ktory priznak vo fitovacej mnozine nekolisal.
EPS_SD = 1e-12

# Manifest je spolocny s per-bin priznakovym priestorom a pole bin_bytes v nom
# je povinne (musi byt kladna mocnina dvojky). Snimkovy vektor ziadne biny
# nema, preto sa zapisuje neutralna 1. Nie je to velkost niecoho nameraneho.
BIN_BYTES_MANIFEST = 1


class NormalizeError(Exception):
    pass


class NotFittedError(NormalizeError):
    pass


def _commit(repo=None):
    """Commit repozitara, aby sa dalo dohladat, ktory kod fit vyrobil."""
    repo = repo or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        out = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


class Normalizer:
    """Fit/transform z-score s manifestom.

    transform pred fitom vyhodi NotFittedError. Nie je to formalita: bez fitu
    by jedina bezpecna alternativa bola pocitat statistiky z prave videnych
    dat, co je presne ta chyba, ktoru ma tento modul zastavit.
    """

    def __init__(self, priznaky, nenormalizovane=()):
        self.priznaky = tuple(priznaky)
        if len(set(self.priznaky)) != len(self.priznaky):
            raise NormalizeError("poradie priznakov obsahuje duplicitu")
        nezname = [n for n in nenormalizovane if n not in self.priznaky]
        if nezname:
            raise NormalizeError("nenormalizovany priznak %s nie je v poradi"
                                 % (", ".join(nezname),))
        self.nenormalizovane = tuple(nenormalizovane)
        self._mu = None
        self._sd = None
        self._manifest = None

    # -- fit ---------------------------------------------------------------

    def fit(self, snimky, sessions_fit, labely=None, benigna_trieda="idle",
            dlzka_okna=None, poznamka=""):
        """Spocita mu/sd zo snimok uvedenych sedeni.

        sessions_fit je povinny a explicitny zoznam. Nie je to otravna
        formalita: "fitni na vsetkom, co si dostal" je presne ten prikaz,
        ktorym sa do statistik dostane testovacie sedenie.

        labely (session -> trieda) su volitelne; ked sa daju, kazde fitovacie
        sedenie musi mat triedu benigna_trieda, inak je to chyba. Ked sa
        nedaju, do manifestu ide poznamka, ze labely neboli overene - aby sa
        pri audite vedelo, ze tuto kontrolu nikto neurobil.
        """
        if isinstance(snimky, Okna):
            raise NormalizeError(
                "fit berie zoznam snimok, nie okna: pri kroku 1 sa okna "
                "prekryvaju a snimky zo stredu sedenia by dostali vacsiu vahu")
        snimky = list(snimky)
        if not snimky:
            raise NormalizeError("fit dostal prazdny zoznam snimok")
        if sessions_fit is None:
            raise NormalizeError(
                "sessions_fit je povinny; fit sa robi iba na benignych "
                "trenovacich sedeniach a ich zoznam musi byt v manifeste")
        sessions_fit = tuple(dict.fromkeys(sessions_fit))
        if not sessions_fit:
            raise NormalizeError("sessions_fit je prazdny")

        dostupne = {s.session for s in snimky}
        chybaju = [s for s in sessions_fit if s not in dostupne]
        if chybaju:
            raise NormalizeError("sessions %s nie su medzi snimkami"
                                 % (", ".join(chybaju),))
        if labely is not None:
            bez_labelu = [s for s in sessions_fit if s not in labely]
            if bez_labelu:
                raise NormalizeError("sessions bez labelu: %s"
                                     % (", ".join(bez_labelu),))
            zle = [s for s in sessions_fit if labely[s] != benigna_trieda]
            if zle:
                raise NormalizeError(
                    "fit smie bezat iba na benignych sedeniach (%r); tieto ju "
                    "nemaju: %s" % (benigna_trieda,
                                    ", ".join("%s=%s" % (s, labely[s]) for s in zle)))

        vybrane = [s for s in snimky if s.session in sessions_fit]
        if not vybrane:
            raise NormalizeError("po vybere sedeni nezostala ziadna snimka")
        for s in vybrane:
            if tuple(s.priznaky) != self.priznaky:
                raise NormalizeError(
                    "snimka %s/%d ma poradie priznakov %r, normalizator ma %r"
                    % (s.session, s.seq, list(s.priznaky), list(self.priznaky)))

        # S ma tvar (T, F): T casovych krokov, kazdy zapocitany raz
        S = np.stack([s.x for s in vybrane], axis=0)
        f = len(self.priznaky)
        mu = np.zeros(f, dtype=np.float64)
        sd = np.ones(f, dtype=np.float64)
        konstantne = []
        for i, meno in enumerate(self.priznaky):
            if meno in self.nenormalizovane:
                # mu=0, sd=1 -> hodnota prejde nezmenena; v manifeste je to
                # aj tak napisane menom v 'nenormalizovane'
                continue
            m = float(S[:, i].mean())
            s_ = float(S[:, i].std(ddof=0))
            if s_ <= EPS_SD:
                konstantne.append(meno)
                s_ = 1.0
            mu[i] = m
            sd[i] = s_

        self._mu = mu
        self._sd = sd
        pozn = poznamka
        if labely is None:
            dovetok = ("labely fitovacich sedeni neboli pri fite overene "
                       "(volajuci ich nedodal)")
            pozn = (pozn + "; " + dovetok) if pozn else dovetok
        self._manifest = Manifest(
            priznaky=self.priznaky,
            nenormalizovane=self.nenormalizovane,
            rezim="priznak",
            mu=mu.tolist(),
            sd=sd.tolist(),
            bin_bytes=BIN_BYTES_MANIFEST,
            konstantne=konstantne,
            sessions=sessions_fit,
            n_snimok=len(vybrane),
            dlzka_okna=dlzka_okna,
            commit=_commit(),
            date=datetime.date.today().isoformat(),
            poznamka=pozn,
        )
        return self

    # -- transform ---------------------------------------------------------

    @property
    def fitnuty(self):
        return self._mu is not None

    @property
    def manifest(self):
        """Manifest fitu. Je to property, nie metoda, zamerne: `fitnuty` je
        property a zmiesane API zvadza napisat `n.manifest.mu`, co by ticho
        vratilo atribut funkcie a spadlo az o kus dalej na nejasnej hlaske."""
        if not self.fitnuty:
            raise NotFittedError("manifest neexistuje, fit este nebezal")
        return self._manifest

    def transform(self, data):
        """Normalizuje okna (Okna) alebo pole s poslednou osou priznakov.

        Pred fitom (alebo pred nacitanim manifestu) vyhodi NotFittedError.
        """
        if self._mu is None or self._sd is None:
            raise NotFittedError(
                "transform pred fit: mu/sd neexistuju. Dopocitat ich z prave "
                "spracovavanych dat je zakazane - to je train/serve skew, "
                "kvoli ktoremu tento modul vznikol")
        if isinstance(data, Okna):
            self._manifest.overit(priznaky=data.priznaky)
            X = np.asarray(data.X, dtype=np.float64)
            return Okna((X - self._mu) / self._sd, data.meta, data.priznaky,
                        data.dlzka, data.krok, data.preskocene, data.vynechane)
        X = np.asarray(data, dtype=np.float64)
        if X.ndim < 1 or X.shape[-1] != len(self.priznaky):
            raise NormalizeError(
                "pole ma tvar %r, posledna os ma byt %d priznakov"
                % (X.shape, len(self.priznaky)))
        return (X - self._mu) / self._sd

    # -- ulozenie a nacitanie ---------------------------------------------

    def save(self, cesta):
        return self.manifest.save(cesta)

    @classmethod
    def from_manifest(cls, manifest):
        """Postavi normalizator z uz overeneho manifestu."""
        n = cls(priznaky=manifest.priznaky,
                nenormalizovane=manifest.nenormalizovane)
        n._mu = np.asarray(manifest.mu, dtype=np.float64)
        n._sd = np.asarray(manifest.sd, dtype=np.float64)
        n._manifest = manifest
        return n

    @classmethod
    def load(cls, cesta, priznaky=None):
        """Nacita manifest a hned ho porovna s tym, co caka volajuci.

        Kontroluje sa schema, hash poradia priznakov a - ked je zadane -
        poradie priznakov. Nesediaci manifest je vynimka, nie varovanie: model
        by inak dostal ine cisla, nez na akych sa ucil.
        """
        m = Manifest.load(cesta)
        m.overit(priznaky=priznaky)
        return cls.from_manifest(m)


__all__ = ["Normalizer", "NormalizeError", "NotFittedError", "EPS_SD",
           "BIN_BYTES_MANIFEST", "Manifest", "ManifestError"]
