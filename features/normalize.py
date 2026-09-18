"""
Z-score normalizacia per-bin priznakov s ulozenym manifestom.

PRAVIDLO, kvoli ktoremu modul vznikol: mu a sd sa fituju IBA na benignych
TRENOVACICH sessions. Nikdy na testovacich a nikdy na sessions so scenarom.
V predchadzajucej iteracii (hypTcn002) sa statistiky pri skorovani pocitali
znova z prave videnych dat, takze model v prevadzke dostaval iny rozsah nez
pri treningu. Tu je fit artefakt: ulozi sa do manifestu (features/manifest.py)
spolu s poradim priznakov a jeho hashom, a pri nacitani sa overuje.

CO SA NORMALIZUJE
-----------------
  changed_ratio   ano
  zero_ratio      ano
  entropy_mean    ano, ale mu/sd sa fituju iba na binoch s has_changed == 1
  has_changed     NIE

Zdovodnenie kazdeho riadku je v hlavicke features/manifest.py (konstanty
PRIZNAKY, NENORMALIZOVANE, PODMIENENE). V skratke: has_changed je indikator
0/1, ktoreho jedina uloha je odlisit "bin sa nezmenil" od "entropia vysla 0";
z-score by tento vyznam zmazal. entropy_mean je definovana ako priemer cez
zmenene stranky, takze v bine bez zmeny nejde o meranie - nuly z takych binov
do mu/sd nevstupuju, ale transformaciou prejdu (a model ma vedla nich
has_changed, ktory povie preco).

FIT SA ROBI NAD SNIMKAMI, NIE NAD OKNAMI
----------------------------------------
Okna sa pri kroku 1 prekryvaju, takze ta ista snimka je v L oknach. Keby sa
mu/sd pocitali nad oknami, snimky zo stredu session by mali az L-nasobnu vahu
oproti snimkam na kraji. Fit preto berie zoznam snimok (jedna snimka = jeden
casovy krok, zapocitana raz) a transform sa aplikuje na okna.

REZIMY FITU
-----------
  "priznak"      jedna dvojica mu/sd na priznak (spolocna cez vsetky biny).
                 Vychodzi. Manifest zostava pouzitelny aj pri VM s inym poctom
                 binov, lebo statistika nie je viazana na konkretny bin.
  "bin_priznak"  mu/sd zvlast na kazdy bin. Zachyti, ze bin s kodom jadra sa
                 spravaja inak nez bin s halda-pamatou, ale manifest tym
                 pribije na jedno rozlozenie memslotov a bin s malym poctom
                 vzoriek da nestabilne sd. Pouzitelne iba ked su vsetky VM
                 rovnake.

Povod: modul vznikol pre tuto pracu, nie je prevzaty.
"""

import datetime
import os
import subprocess

import numpy as np

from .manifest import (NENORMALIZOVANE, PODMIENENE, PRIZNAKY, Manifest,
                       ManifestError)
from .windows import Okna

# Pod touto hodnotou sa sd povazuje za nulove. Nedeli sa nim - priznak sa
# oznaci za konstantny, sd sa nastavi na 1.0 a meno ide do manifestu, aby bolo
# vidiet, ktory priznak vo fitovacej mnozine nekolisal.
EPS_SD = 1e-12


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

    def __init__(self, priznaky=PRIZNAKY, rezim="priznak",
                 nenormalizovane=NENORMALIZOVANE, podmienene=None):
        self.priznaky = tuple(priznaky)
        if len(set(self.priznaky)) != len(self.priznaky):
            raise NormalizeError("poradie priznakov obsahuje duplicitu")
        self.rezim = rezim
        if self.rezim not in ("priznak", "bin_priznak"):
            raise NormalizeError("neznamy rezim %r" % (rezim,))
        self.nenormalizovane = tuple(n for n in nenormalizovane
                                     if n in self.priznaky)
        self.podmienene = dict(PODMIENENE if podmienene is None else podmienene)
        for meno, hradlo in self.podmienene.items():
            if meno in self.priznaky and hradlo not in self.priznaky:
                raise NormalizeError("hradlo %r pre priznak %r nie je v poradi"
                                     % (hradlo, meno))
        self._mu = None
        self._sd = None
        self._manifest = None

    # -- fit ---------------------------------------------------------------

    def fit(self, snimky, sessions_fit, labely=None, benigna_trieda="idle",
            bin_bytes=None, dlzka_okna=None, poznamka=""):
        """Spocita mu/sd zo snimok uvedenych sessions.

        sessions_fit je povinny a explicitny zoznam. Nie je to otravna
        formalita: "fitni na vsetkom, co si dostal" je presne ten prikaz,
        ktorym sa do statistik dostane testovacia session.

        labely (session -> trieda) su volitelne; ked sa daju, kazda fitovacia
        session musi mat triedu benigna_trieda, inak je to chyba. Ked sa
        nedaju, do manifestu ide poznamka, ze labely neboli overene - aby sa
        pri audite vedelo, ze tuto kontrolu nikto neurobil.
        """
        if isinstance(snimky, Okna):
            raise NormalizeError(
                "fit berie zoznam snimok, nie okna: pri kroku 1 sa okna "
                "prekryvaju a snimky zo stredu session by dostali vacsiu vahu")
        snimky = list(snimky)
        if not snimky:
            raise NormalizeError("fit dostal prazdny zoznam snimok")
        if sessions_fit is None:
            raise NormalizeError(
                "sessions_fit je povinny; fit sa robi iba na benignych "
                "trenovacich sessions a ich zoznam musi byt v manifeste")
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
                    "fit smie bezat iba na benignych sessions (%r); tieto ju "
                    "nemaju: %s" % (benigna_trieda,
                                    ", ".join("%s=%s" % (s, labely[s]) for s in zle)))

        vybrane = [s for s in snimky if s.session in sessions_fit]
        if not vybrane:
            raise NormalizeError("po vybere sessions nezostala ziadna snimka")

        biny = vybrane[0].biny
        bb = vybrane[0].bin_bytes
        for s in vybrane:
            if tuple(s.priznaky) != self.priznaky:
                raise NormalizeError(
                    "snimka %s/%d ma poradie priznakov %r, normalizator ma %r"
                    % (s.session, s.seq, list(s.priznaky), list(self.priznaky)))
            if s.biny != biny:
                raise NormalizeError(
                    "snimka %s/%d ma inu mnozinu binov nez prva fitovacia "
                    "snimka (%d vs %d)" % (s.session, s.seq, len(s.biny),
                                           len(biny)))
            if s.bin_bytes != bb:
                raise NormalizeError("snimka %s/%d ma bin_bytes %d, prva %d"
                                     % (s.session, s.seq, s.bin_bytes, bb))
        if bin_bytes is not None and int(bin_bytes) != bb:
            raise NormalizeError("bin_bytes zo snimok (%d) nesedi so zadanym (%d)"
                                 % (bb, int(bin_bytes)))

        # S ma tvar (T, B, F): T casovych krokov, kazdy zapocitany raz
        S = np.stack([s.x for s in vybrane], axis=0)
        f = len(self.priznaky)
        if self.rezim == "priznak":
            mu = np.zeros(f, dtype=np.float64)
            sd = np.ones(f, dtype=np.float64)
        else:
            mu = np.zeros((len(biny), f), dtype=np.float64)
            sd = np.ones((len(biny), f), dtype=np.float64)
        konstantne = []

        for i, meno in enumerate(self.priznaky):
            if meno in self.nenormalizovane:
                # mu=0, sd=1 -> hodnota prejde nezmenena; v manifeste je to
                # aj tak napisane menom v 'nenormalizovane'
                continue
            hodnoty = S[:, :, i]
            hradlo = self.podmienene.get(meno)
            maska = None
            if hradlo is not None:
                hi = self.priznaky.index(hradlo)
                maska = S[:, :, hi] > 0.5
                if not maska.any():
                    raise NormalizeError(
                        "priznak %r sa fituje iba tam, kde %r == 1, ale vo "
                        "fitovacej mnozine taka hodnota nie je; nahradna "
                        "statistika by nebola meranim"
                        % (meno, hradlo))
            if self.rezim == "priznak":
                vzorka = hodnoty[maska] if maska is not None else hodnoty.ravel()
                m = float(vzorka.mean())
                s_ = float(vzorka.std(ddof=0))
                if s_ <= EPS_SD:
                    konstantne.append(meno)
                    s_ = 1.0
                mu[i] = m
                sd[i] = s_
            else:
                for b in range(len(biny)):
                    st = hodnoty[:, b]
                    if maska is not None:
                        st = st[maska[:, b]]
                    if st.size == 0:
                        raise NormalizeError(
                            "bin %d nema ani jednu vzorku priznaku %r s "
                            "hradlom %r == 1" % (biny[b], meno, hradlo))
                    m = float(st.mean())
                    s_ = float(st.std(ddof=0))
                    if s_ <= EPS_SD:
                        konstantne.append("bin%d/%s" % (biny[b], meno))
                        s_ = 1.0
                    mu[b, i] = m
                    sd[b, i] = s_

        self._mu = mu
        self._sd = sd
        pozn = poznamka
        if labely is None:
            dovetok = ("labely fitovacich sessions neboli pri fite overene "
                       "(volajuci ich nedodal)")
            pozn = (pozn + "; " + dovetok) if pozn else dovetok
        self._manifest = Manifest(
            priznaky=self.priznaky,
            nenormalizovane=self.nenormalizovane,
            rezim=self.rezim,
            mu=mu.tolist(),
            sd=sd.tolist(),
            bin_bytes=bb,
            biny=biny if self.rezim == "bin_priznak" else None,
            konstantne=konstantne,
            podmienene={k: v for k, v in self.podmienene.items()
                        if k in self.priznaky},
            sessions=sessions_fit,
            n_snimok=len(vybrane),
            n_binov=len(biny),
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
        """Normalizuje okna (Okna) alebo pole s poslednymi osami (..., B, F).

        Pred fitom (alebo pred nacitanim manifestu) vyhodi NotFittedError.
        """
        if self._mu is None or self._sd is None:
            raise NotFittedError(
                "transform pred fit: mu/sd neexistuju. Dopocitat ich z prave "
                "spracovavanych dat je zakazane - to je train/serve skew, "
                "kvoli ktoremu tento modul vznikol")
        if isinstance(data, Okna):
            self._skontroluj_okna(data)
            X = np.asarray(data.X, dtype=np.float64)
            Y = self._aplikuj(X)
            return Okna(Y, data.meta, data.priznaky, data.biny, data.bin_bytes,
                        data.dlzka, data.krok, data.preskocene)
        X = np.asarray(data, dtype=np.float64)
        if X.ndim < 2 or X.shape[-1] != len(self.priznaky):
            raise NormalizeError(
                "pole ma tvar %r, posledna os ma byt %d priznakov"
                % (X.shape, len(self.priznaky)))
        return self._aplikuj(X)

    def _aplikuj(self, X):
        if self.rezim == "priznak":
            return (X - self._mu) / self._sd
        if X.shape[-2] != self._mu.shape[0]:
            raise NormalizeError(
                "pole ma %d binov, manifest fitnuty na %d; v rezime "
                "bin_priznak su mu/sd viazane na konkretne biny"
                % (X.shape[-2], self._mu.shape[0]))
        return (X - self._mu) / self._sd

    def _skontroluj_okna(self, okna):
        self._manifest.overit(priznaky=okna.priznaky, biny=okna.biny,
                              bin_bytes=okna.bin_bytes)

    # -- ulozenie a nacitanie ---------------------------------------------

    def save(self, cesta):
        return self.manifest.save(cesta)

    @classmethod
    def from_manifest(cls, manifest):
        """Postavi normalizator z uz overeneho manifestu."""
        n = cls(priznaky=manifest.priznaky, rezim=manifest.rezim,
                nenormalizovane=manifest.nenormalizovane,
                podmienene=manifest.podmienene)
        n._mu = np.asarray(manifest.mu, dtype=np.float64)
        n._sd = np.asarray(manifest.sd, dtype=np.float64)
        n._manifest = manifest
        return n

    @classmethod
    def load(cls, cesta, priznaky=None, biny=None, bin_bytes=None):
        """Nacita manifest a hned ho porovna s tym, co caka volajuci.

        Kontroluje sa schema, hash poradia priznakov a - ked su zadane -
        poradie priznakov, biny a velkost binu. Nesedici manifest je vynimka,
        nie varovanie: model by inak dostal ine cisla, nez na akych sa ucil.
        """
        m = Manifest.load(cesta)
        m.overit(priznaky=priznaky, biny=biny, bin_bytes=bin_bytes)
        return cls.from_manifest(m)


def snimky_zo_sessions(sessions):
    """Spoji snimky z viacerych sessions do jedneho zoznamu.

    Samostatna funkcia preto, aby bolo na jednom mieste vidiet, ze sa snimky
    iba spajaju - hranice sessions drzi windows.segmenty, nie toto.
    """
    out = []
    for s in sessions:
        out.extend(s)
    return out


__all__ = ["Normalizer", "NormalizeError", "NotFittedError", "EPS_SD",
           "snimky_zo_sessions", "Manifest", "ManifestError"]
