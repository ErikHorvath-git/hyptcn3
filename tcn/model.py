"""
model.py - TCN nad oknom snimok (kauzalne dilatovane konvolucie).

VSTUP A VYSTUP
--------------
Vstup je (N, L, F): N okien, L snimok v okne, F priznakov na snimku. F je
dlzka kontraktu z features/snapshot.py (dvadsat priznakov + ma_predchodcu),
takze do modelu ide pamatova aj objektova cast tej istej snimky. Vystup su
logity (N, C); s po_krokoch=True su (N, L, C), co potrebuje test kauzality.

KAUZALITA
---------
Konvolucia sa doplna nulami IBA zlava, o (k-1)*dilatacia vzoriek. Vystup v
case t preto zavisi vylucne od vstupov <= t. Nie je to len tvrdenie v
komentari: overuje ho tcn/tests/test_tcn.py::test_kauzalita tym, ze zmeni
vstup v case t+1 a porovna vystup v case t.

RECEPCNE POLE
-------------
Blok ma dve konvolucie s rovnakou dilataciou, bloky maju dilatacie 1, 2, 4,
... 2^(B-1). Kazda konvolucia predlzi dosah o (k-1)*dilatacia, takze

    RF = 1 + 2*(k-1)*(2^B - 1)

Pri vychodzich k=3 a B=3 je RF = 1 + 2*2*7 = 29 snimok. Okno ma
features.windows.DLZKA_OKNA = 16 snimok, takze 29 >= 16 a posledny casovy
krok vidi cele okno. Keby sa okno predlzilo nad 29, treba pridat blok:
B=4 dava RF = 61. Kontrolu robi funkcia skontroluj_rf() a test
test_recepcne_pole, ktory dosah zmeria cez gradienty, nie zo vzorca.

POCET PARAMETROV
----------------
Korpus je maly (radovo desiatky sessions), takze model je zamerne maly:
pri F=21, C=2, kanaly=16, k=3, B=3 ma 5330 parametrov (vypisuje sa pri
treningu). Radovo tisice, nie miliony.

Povod: architektura je port bezneho TCN (Bai, Kolter, Koltun 2018 -
An Empirical Evaluation of Generic Convolutional and Recurrent Networks
for Sequence Modeling), implementacia je napisana pre tuto pracu.
"""

import torch
from torch import nn
from torch.nn import functional as F


def recepcne_pole(k, blokov):
    """RF = 1 + 2*(k-1)*(2^B - 1); odvodenie je v hlavicke modulu."""
    return 1 + 2 * (k - 1) * (2 ** blokov - 1)


def skontroluj_rf(dlzka_okna, k, blokov):
    """Vyhodi vynimku, ked model nevidi cele okno.

    Ticho natrenovat model, ktory z okna vidi len jeho koniec, je horsie nez
    spadnut: vysledok by vyzeral ako vysledok nad celym oknom.
    """
    rf = recepcne_pole(k, blokov)
    if rf < dlzka_okna:
        raise ValueError(
            "recepcne pole %d < dlzka okna %d (k=%d, blokov=%d); pridaj blok "
            "alebo zvacsi jadro" % (rf, dlzka_okna, k, blokov))
    return rf


def pocet_parametrov(model):
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


class Blok(nn.Module):
    """Rezidualny blok: dve kauzalne konvolucie s rovnakou dilataciou."""

    def __init__(self, vstup, kanaly, k, dilatacia, dropout):
        super().__init__()
        self.pad = (k - 1) * dilatacia
        self.c1 = nn.Conv1d(vstup, kanaly, k, dilation=dilatacia)
        self.c2 = nn.Conv1d(kanaly, kanaly, k, dilation=dilatacia)
        self.drop = nn.Dropout(dropout)
        # Skratka meni pocet kanalov iba tam, kde sa lisi od vstupu.
        self.skratka = nn.Conv1d(vstup, kanaly, 1) if vstup != kanaly else None

    def forward(self, x):
        # Doplnenie zlava a ziadne sprava - v tom je cela kauzalita.
        y = self.drop(torch.relu(self.c1(F.pad(x, (self.pad, 0)))))
        y = self.drop(torch.relu(self.c2(F.pad(y, (self.pad, 0)))))
        s = x if self.skratka is None else self.skratka(x)
        return torch.relu(y + s)


class TCN(nn.Module):
    """Kauzalny dilatovany TCN. Vstup (N, L, F), vystup logity (N, C)."""

    def __init__(self, priznakov, tried, kanaly=16, k=3, blokov=3,
                 dropout=0.1, dlzka_okna=None):
        super().__init__()
        if dlzka_okna is not None:
            skontroluj_rf(dlzka_okna, k, blokov)
        self.rf = recepcne_pole(k, blokov)
        self.bloky = nn.ModuleList([
            Blok(priznakov if i == 0 else kanaly, kanaly, k, 2 ** i, dropout)
            for i in range(blokov)])
        self.hlava = nn.Linear(kanaly, tried)

    def forward(self, x, po_krokoch=False):
        h = x.transpose(1, 2)                     # (N, F, L) pre Conv1d
        for b in self.bloky:
            h = b(h)
        logity = self.hlava(h.transpose(1, 2))    # (N, L, C)
        # Bez po_krokoch sa klasifikuje posledny krok okna: rozhodnutie patri
        # k najnovsej snimke a ta vidi cele okno (RF >= L).
        return logity if po_krokoch else logity[:, -1, :]
