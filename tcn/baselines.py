"""
baselines.py - tri baseliny k TCN, vsetky nad tymi istymi oknami a splitom.

PRECO TRI
---------
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

Rozhranie je zamerne uzke: sklearn baseliny maju fit/proba, siete su
nn.Module s forward -> logity (N, C) a treninguje ich trenuj_siet() v
train.py. Spolocna abstraktna trieda nad tym by nic nezjednodusila.
"""

import numpy as np
import torch
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

    meno = "logreg_priemer"

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

    meno = "bag_of_frames"

    def vstup(self, X):
        return np.concatenate([X.mean(axis=1), X.std(axis=1)], axis=1)


class GRU(nn.Module):
    """Jednovrstvove GRU, klasifikuje posledny krok okna (ako TCN)."""

    meno = "gru"

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
