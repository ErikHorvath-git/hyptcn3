"""
baselines.py - baseliny k TCN, klasifikacne aj ANOMALNE.

KLASIFIKACNE (vsetky nad tymi istymi oknami a splitom):
1. LogRegPriemer  - logisticka regresia nad spriemerovanym oknom. Ukazuje,
   kolko sa da dosiahnut bez modelu sekvencii vobec.
2. BagOfFrames    - priemer a smerodajna odchylka cez cas. Model NEVIDI
   poradie snimok (permutacia casu nezmeni vstup; overuje to
   test_bag_of_frames_nevidi_poradie). Toto je najdolezitejsi baseline:
   ked ho TCN neprekona, casova informacia v tychto datach nepomaha. Taky
   vysledok sa podla HONESTY.md P8 reportuje, nezamlcuje.
3. GRU            - rekurentna siet s porovnatelnym poctom parametrov ako
   TCN (zadanie ziada porovnanie s LSTM/GRU). "Porovnatelny" tu nie je odhad:
   skryty rozmer vybera skryte_pre_parametre() tak, aby sa pocty parametrov
   lisili co najmenej, a oba pocty sa vypisu.

ANOMALNE (blok F - predikcia normalu, bez stitkov):
4. ZScoreAnomalia        - z-score priemerov okien oproti benígnemu trenovaniu.
5. IsolationForestAnomalia - izolacny les nad rozvinutymi oknami.
6. GRUPrediktor         - GRU s regresnou hlavou, porovnatelny pocet
   parametrov s TCNPrediktorom.
7. LSTMPrediktor        - to iste s LSTM (zadanie ziada porovnanie s LSTM
   aj GRU); skryty rozmer vybera skryte_pre_prediktor().

VSTUP SAFEGUARD (E4): tcn/porovnanie.py dava anomalnym baselinom okna
safeguardu (18 globalnych behavioralnych stlpcov + per-bin tenzor). Per-bin
cast vidia ZHRNUTU cez biny funkciou zluc_biny(): priemer a maximum kazdeho
zo 4 per-bin kanalov, rovnako ako to robi safeguard.model.Classifier
("bin_mean_and_max"). Vstup na krok je teda 18 + 4 + 4 = 26 stlpcov; TCN
prediktor safeguardu vidi kazdy bin zvlast (zdielany TCN cez biny) a jeho
skore berie maximum cez biny - baseliny tuto lokalizaciu nemaju.

Vsetky anomálne modely fitnu IBA na benígnych trenovacích oknách a ich skóre
sa ma kalibrovat rovnakym postupom ako skore TCN - preto patria do jednej
tabulky s TCN. Skóre nie je detekcia: co je alarm, urci az kalibracny prah.

Rozhranie je zamerne uzke: sklearn baseliny maju fit/proba (klasifikacia)
alebo fit/skore (anomalia), siete su nn.Module s forward -> logity alebo
predikcia a treninguje ich trenuj_siet()/trenuj_prediktor() v train.py.
"""

import numpy as np
import torch
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from torch import nn


def _rozsir(p, triedy_modelu, tried):
    """Doplni stlpce tried, ktore v treningu neboli, nulovou pravdepodobnostou.

    Ked trieda v trenovacej casti chyba, sklearn ju v predict_proba nema a
    stlpce by sa posunuli. Nula je tu spravna: model tu triedu nikdy predikovat
    nemoze. Ze chybala, je vidiet v poli 'chybajuce_triedy' vo vysledku.
    """
    if len(triedy_modelu) == tried:
        return p
    out = np.zeros((p.shape[0], tried), dtype=np.float64)
    out[:, np.asarray(triedy_modelu, dtype=int)] = p
    return out


class LogRegPriemer:
    """Logisticka regresia nad priemerom okna cez cas."""

    def __init__(self, tried, seed=0):
        self.tried = tried
        self.m = LogisticRegression(max_iter=2000, random_state=seed)

    def vstup(self, X):
        return X.mean(axis=1)

    def fit(self, X, y):
        self.m.fit(self.vstup(X), y)
        return self

    def proba(self, X):
        return _rozsir(self.m.predict_proba(self.vstup(X)), self.m.classes_,
                       self.tried)


class BagOfFrames(LogRegPriemer):
    """Priemer + odchylka cez cas: model, ktory poradie snimok nevidi."""

    def vstup(self, X):
        return np.concatenate([X.mean(axis=1), X.std(axis=1)], axis=1)


class GRU(nn.Module):
    """Jednovrstvove GRU, klasifikuje posledny krok okna (ako TCN)."""

    def __init__(self, priznakov, tried, skryte):
        super().__init__()
        self.gru = nn.GRU(priznakov, skryte, batch_first=True)
        self.hlava = nn.Linear(skryte, tried)

    def forward(self, x, po_krokoch=False):
        h, _ = self.gru(x)
        logity = self.hlava(h)
        return logity if po_krokoch else logity[:, -1, :]


def skryte_pre_parametre(priznakov, tried, ciel, maximum=128):
    """Najmensi skryty rozmer s poctom parametrov najblizsie k `ciel`.

    Hlada sa skusanim, nie vzorcom: pocet parametrov GRU je zname cislo, ale
    zapisat ho tu druhy raz znamena mat dve definicie toho isteho a jednu z
    nich raz opravit a druhu nie.
    """
    najlepsie = None
    for h in range(1, maximum + 1):
        n = sum(p.numel() for p in GRU(priznakov, tried, h).parameters())
        if najlepsie is None or abs(n - ciel) < najlepsie[1]:
            najlepsie = (h, abs(n - ciel), n)
    return najlepsie[0], najlepsie[2]


# ---------------------------------------------------- anomálne baseliny (F)

INDIKATORY = ("ma_predchodcu", "je_plna")


class ZScoreAnomalia:
    """
    z-score priemerov okien oproti benígnemu trenovaniu (blok F).

    Z okna (L, F) sa spraví priemer cez cas (F,) - najjednoduchsi mozny
    agregat - a skore = stredna stvorcova z-hodnota cez priznaky BEZ
    indikatorov. Fit IBA na benígnych oknach, rovnako ako normalizacia
    TCN. Ked TCN toto neprekona, sekvencna informacia nepomaha (P8).
    """

    def __init__(self, priznaky, indikatory=INDIKATORY):
        self.priznaky = tuple(priznaky)
        self.indikatory = tuple(indikatory)
        self.mask = np.array([p not in indikatory for p in priznaky])
        self.mu = self.sd = None

    def _flat(self, X):
        return np.asarray(X, dtype=np.float64).mean(axis=1)

    def fit(self, X):
        flat = self._flat(X)
        self.mu = flat.mean(axis=0)
        self.sd = flat.std(axis=0)
        self.sd[self.sd < 1e-12] = 1e-12        # konstantny priznak -> 0/0
        return self

    def skore(self, X):
        if self.mu is None:
            raise ValueError("zscore: fit este nebezal")
        z = (self._flat(X) - self.mu) / self.sd
        return np.mean(z[:, self.mask] ** 2, axis=1)


class IsolationForestAnomalia:
    """
    Isolation Forest nad rozvinutymi oknami (blok F).

    contamination='auto': les si spociatocny prah urci sam, ale SKORE je len
    surova miera - prah alarmu urci az kalibracia, rovnako ako pre TCN.
    """

    def __init__(self, seed=0):
        self.m = IsolationForest(n_estimators=200, max_samples="auto",
                                 contamination="auto", random_state=seed)

    def _flat(self, X):
        a = np.asarray(X, dtype=np.float64)
        return a.reshape(a.shape[0], -1)

    def fit(self, X):
        self.m.fit(self._flat(X))
        return self

    def skore(self, X):
        # -decision_function: vacsie = anomalnejsie (konzistentne s chybou)
        return -self.m.decision_function(self._flat(X))

    def skore_nezaporne(self, X):
        """-score_samples v [0, 1]: to iste poradie ako skore(), iba posunute.

        skore() je -decision_function = -score_samples - offset a moze byt
        zaporne; kalibracia safeguardu (safeguard.training.calibrate) zaporne
        skore odmieta. Posun o konstantu nemeni kvantilovy prah ani alarmy.
        """
        return -self.m.score_samples(self._flat(X))


class GRUPrediktor(nn.Module):
    """GRU s regresnou hlavou - prediktor normalu, porovnatelny s TCN (F).

    vystupov=None predpoveda vsetky vstupne stlpce (povodne spravanie);
    inak len prvych `vystupov` (porovnanie.py nepredpoveda masky has_changed).
    """

    rekurencia = nn.GRU

    def __init__(self, priznakov, skryte, vystupov=None):
        super().__init__()
        self.gru = self.rekurencia(priznakov, skryte, batch_first=True)
        self.hlava = nn.Linear(skryte, priznakov if vystupov is None else vystupov)

    def forward(self, x, po_krokoch=False):
        h, _ = self.gru(x)
        pred = self.hlava(h)
        return pred if po_krokoch else pred[:, -1, :]


class LSTMPrediktor(GRUPrediktor):
    """Jednovrstvove LSTM s regresnou hlavou; okrem bunky zhodne s GRUPrediktor.

    Atribut sa vola `gru` aj tu, aby forward a trening boli jeden kod; typ
    rekurencie je nn.LSTM (overuje test_porovnanie).
    """

    rekurencia = nn.LSTM


def skryte_pre_prediktor(trieda, priznakov, vystupov, ciel, maximum=256):
    """Skryty rozmer prediktora `trieda` s poctom parametrov najblizsie k `ciel`.

    Ako skryte_pre_parametre(), ale pocita parametre presne toho prediktora,
    ktory sa bude trenovat (LSTM ma 4 brany, GRU 3 - jeden vzorec nestaci).
    Vracia (skryte, pocet_parametrov).
    """
    if ciel < 1 or maximum < 1:
        raise ValueError("ciel a maximum musia byt kladne")
    najlepsie = None
    for h in range(1, maximum + 1):
        n = sum(p.numel() for p in trieda(priznakov, h, vystupov).parameters())
        if najlepsie is None or abs(n - ciel) < najlepsie[1]:
            najlepsie = (h, abs(n - ciel), n)
    if najlepsie[0] == maximum:
        raise ValueError("skryty rozmer narazil na maximum %d; zvys maximum" % maximum)
    return najlepsie[0], najlepsie[2]


def zluc_biny(globalne, lokalne):
    """(N, L, G) a (N, L, B, 4) -> (N, L, G + 8): priemer a maximum cez biny.

    To iste zhrnutie ako safeguard.model.Classifier.forward; poradie stlpcov:
    globalne, priemery 4 per-bin kanalov, maxima 4 per-bin kanalov.
    """
    globalne = torch.as_tensor(globalne, dtype=torch.float32)
    lokalne = torch.as_tensor(lokalne, dtype=torch.float32)
    if lokalne.ndim != 4 or globalne.ndim != 3 or lokalne.shape[:2] != globalne.shape[:2]:
        raise ValueError("zluc_biny: ocakava (N, L, G) a (N, L, B, C) so zhodnym N, L")
    return torch.cat((globalne, lokalne.mean(dim=2), lokalne.max(dim=2).values), dim=-1)
