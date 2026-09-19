"""
train.py - data, split, normalizacia a trening. Spusta cely beh:

    python3 -m tcn.train --data data/sessions/vektory --out data/results/tcn.json
    python3 -m tcn.train --syn          # syntetika, ked korpus este nie je

VSTUPNE DATA
------------
Jedna session = jeden .npz zo `python3 -m features session --out <subor>`:
kluce `matica` (T x 21), `mena` (kontrakt z features/snapshot.py) a `snimky`.
Vedla nich `labely.json`: {meno_session: trieda}. Nic ine sa necita - vektor
sa tu uz nepocita, aby v jednom datasete neboli cisla z dvoch implementacii.

CHRONOLOGICKY A SESSION-DISJUNKTNY SPLIT
----------------------------------------
Okna sa robia s krokom 1, takze susedne okna nie su nezavisle vzorky. Keby
sa delilo po oknach, testovacie okno by malo v treningu takmer identickeho
suseda z tej istej session - presne to nafuklo vysledky v hypTcn002
(HONESTY.md, kapitola 2). Preto: delenie po SESSIONS, v ramci kazdej triedy
chronologicky, starsie sessions do treningu, novsie do testu. Session sa
nikdy nerozdeli. Chronologicke poradie sa berie z mena session, ktore zacina
casovou peciatkou (20260918T154914Z_...); meno bez nej je chyba, lebo
chronologicky sa to potom zoradit neda.

NORMALIZACIA
------------
mu/sd fituje features/normalize.py IBA na benignych TRENOVACICH sessions.
Normalizator je pisany na per-bin vektory (B binov x F priznakov), snimkovy
vektor je jeden riadok - ide don ako B=1. Preto `biny=(0,)` a `bin_bytes=1`
(manifest ziada kladnu mocninu dvojky, 1 je neutralna). `ma_predchodcu` sa
nenormalizuje, je to indikator 0/1 ako `has_changed`.

PRVA SNIMKA RETAZCA
-------------------
V riadku s `ma_predchodcu` = 0 su proc_new, proc_gone a mod_delta nuly, ktore
nie su meranim. Z dvoch ciest, ktore kontrakt pripusta, je zvolena tato: okno
s takym riadkom sa VYNECHA a pocet vynechanych je vo vysledku
(`okien_bez_predchodcu`). Priznak vo vektore zostava - pri skorovani v
prevadzke sa prva snimka zahodit neda a tam musi byt vidiet, ktory riadok to je.
"""

import argparse
import json
import os
import sys

import numpy as np
import torch
from torch import nn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.normalize import Normalizer                   # noqa: E402
from features.snapshot import MENA                          # noqa: E402
from features.windows import DLZKA_OKNA, KROK, Snimka       # noqa: E402
from tcn import eval as ev                                  # noqa: E402
from tcn.baselines import (GRU, BagOfFrames, LogRegPriemer,  # noqa: E402
                           skryte_pre_parametre)
from tcn.model import TCN, pocet_parametrov                 # noqa: E402

BENIGNA = "idle"


def nastav_seed(seed):
    """Fixny seed pre numpy aj torch. Beh je CPU-only, takze to staci."""
    np.random.seed(seed)
    torch.manual_seed(seed)


# ------------------------------------------------------------------- data


def nacitaj_sessions(adresar):
    """Sessions z adresara s .npz a labely.json."""
    with open(os.path.join(adresar, "labely.json"), encoding="utf-8") as fh:
        labely = json.load(fh)
    out = []
    for meno in sorted(labely):
        d = np.load(os.path.join(adresar, meno + ".npz"), allow_pickle=False)
        mena = tuple(str(m) for m in d["mena"])
        if mena != tuple(MENA):
            raise ValueError("session %s ma ine poradie priznakov nez kontrakt"
                             % meno)
        out.append({"meno": meno, "trieda": labely[meno],
                    "matica": np.asarray(d["matica"], dtype=np.float64)})
    if not out:
        raise ValueError("v %s nie je ziadna session" % adresar)
    return out


def syn_sessions(seed=0, na_triedu=4, dlzka=40, triedy=("idle", "cpu_burn"),
                 rezim="hodnota"):
    """Synteticke sessions v tvare kontraktu - na testy a na skusobny beh.

    NIE JE TO MERANIE a nic to nehovori o detekcii. Sluzi to na to, aby sa
    cely retazec (okna -> split -> normalizacia -> trening -> metriky) dal
    spustit a otestovat skor, nez korpus existuje. Tri rezimy:

      "hodnota"  trieda je v hodnote priznaku mem_changed_ratio (index 0),
                 takze uloha sa da vyriesit aj priemerom cez okno;
      "poradie"  obe triedy maju na priznaku 0 tu istu rampu, jedna ju ma
                 obratenu v case - priemer aj odchylka cez okno vyjdu rovnako,
                 takze sa to da vyriesit IBA z poradia. Ostatne priznaky su
                 konstantne nuly zamerne: ked v nich bol sum, model si
                 zapametal sum session (susedne okna zdielaju 15 zo 16 snimok)
                 a triedu uhadol z toho;
      "sum"      ziadny signal, iba sum. Trieda sa da uhadnut iba podla toho,
                 z ktorej session okno pochadza. Pri splite po sessions musi
                 vyjst nahoda; ked vyjde viac, split tecie.
    """
    if rezim not in ("hodnota", "poradie", "sum"):
        raise ValueError("neznamy rezim %r" % (rezim,))
    rng = np.random.default_rng(seed)
    out = []
    for ti, trieda in enumerate(triedy):
        for i in range(na_triedu):
            t = np.arange(dlzka)
            if rezim == "poradie":
                X = np.zeros((dlzka, len(MENA)))
                rampa = (t % 8) / 8.0
                X[:, 0] = (rampa if ti == 0 else rampa[::-1]) \
                    + rng.normal(0.0, 0.02, size=dlzka)
            else:
                X = rng.normal(0.0, 0.1, size=(dlzka, len(MENA)))
                if rezim == "hodnota" and ti > 0:
                    # Trieda 0 je pokojna, ostatne maju vlnu na priznaku 0.
                    X[:, 0] += ti * (1.0 + np.sin(t / 3.0))
            X[:, MENA.index("ma_predchodcu")] = 1.0
            X[0, MENA.index("ma_predchodcu")] = 0.0     # prva snimka retazca
            out.append({"meno": "202601%02dT000000Z_%s_%d" % (i + 1, trieda, i),
                        "trieda": trieda, "matica": X})
    return out


def okna_zo_session(matica, dlzka, krok=KROK):
    """(T, F) -> (N, L, F) posuvnym oknom; okna nikdy neprekrocia session."""
    T = matica.shape[0]
    zac = range(0, T - dlzka + 1, krok)
    return np.stack([matica[i:i + dlzka] for i in zac]) if T >= dlzka \
        else np.zeros((0, dlzka, matica.shape[1]))


def split_chronologicky(sessions, podiel=0.6):
    """(trenovacie mena, testovacie mena) - po sessions, v triede chronologicky.

    Delenie je v ramci kazdej triedy, aby obe casti obsahovali vsetky triedy;
    inak by trieda s dvoma sessions skoncila cela v jednej casti.
    """
    tr, te = [], []
    triedy = sorted({s["trieda"] for s in sessions})
    for t in triedy:
        mena = sorted(s["meno"] for s in sessions if s["trieda"] == t)
        for m in mena:
            if not m[:8].isdigit():
                raise ValueError(
                    "session %r nezacina casovou peciatkou, chronologicky "
                    "split sa neda urobit" % m)
        k = max(1, int(round(podiel * len(mena))))
        k = min(k, len(mena) - 1) if len(mena) > 1 else k
        tr.extend(mena[:k])
        te.extend(mena[k:])
    return sorted(tr), sorted(te)


def priprav(sessions, dlzka=DLZKA_OKNA, podiel=0.6, benigna=BENIGNA):
    """Okna, labely, split a normalizacia. Vracia slovnik s datami a popisom."""
    triedy = sorted({s["trieda"] for s in sessions})
    tr_mena, te_mena = split_chronologicky(sessions, podiel)
    labely = {s["meno"]: s["trieda"] for s in sessions}

    # Normalizacia: fit iba na benignych trenovacich sessions. Snimkovy vektor
    # ide do normalizatora ako jeden "bin" (tvar (1, F)).
    snimky = [Snimka(s["meno"], i, "", 0.0, (0,), r[None, :], 1, priznaky=MENA)
              for s in sessions for i, r in enumerate(s["matica"])]
    fit_mena = [m for m in tr_mena if labely[m] == benigna]
    if not fit_mena:
        raise ValueError("medzi trenovacimi sessions nie je ziadna benigna "
                         "(%r); mu/sd sa nema na com fitnut" % benigna)
    norm = Normalizer(priznaky=MENA, nenormalizovane=("ma_predchodcu",),
                      podmienene={})
    norm.fit(snimky, sessions_fit=fit_mena, labely=labely,
             benigna_trieda=benigna, dlzka_okna=dlzka)

    idx_pred = MENA.index("ma_predchodcu")
    casti, vynechane = {}, 0
    for cast, mena in (("train", tr_mena), ("test", te_mena)):
        X, y = [], []
        for s in sessions:
            if s["meno"] not in mena:
                continue
            W = okna_zo_session(s["matica"], dlzka)
            plne = (W[:, :, idx_pred] == 1).all(axis=1) if len(W) else \
                np.zeros(0, dtype=bool)
            vynechane += int((~plne).sum())
            W = W[plne]
            if len(W):
                X.append(W)
                y.extend([triedy.index(s["trieda"])] * len(W))
        if not X:
            raise ValueError("cast %s nema ani jedno okno" % cast)
        Xc = np.concatenate(X)
        # transform caka os binov; (N, L, F) -> (N, L, 1, F) a spat
        casti[cast] = (norm.transform(Xc[:, :, None, :])[:, :, 0, :],
                       np.asarray(y, dtype=np.int64))

    return {
        "triedy": triedy, "benigna": triedy.index(benigna),
        "train_sessions": tr_mena, "test_sessions": te_mena,
        "fit_sessions": fit_mena,
        "X_train": casti["train"][0], "y_train": casti["train"][1],
        "X_test": casti["test"][0], "y_test": casti["test"][1],
        "dlzka_okna": dlzka, "okien_bez_predchodcu": vynechane,
        "konstantne_priznaky": list(norm.manifest.konstantne),
    }


# --------------------------------------------------------------- trening


def trenuj_siet(model, X, y, seed=0, epochy=60, lr=0.01, davka=64):
    """Adam + cross-entropy, fixny seed, CPU. Vracia model v rezime eval()."""
    nastav_seed(seed)
    g = torch.Generator().manual_seed(seed)
    Xt = torch.as_tensor(X, dtype=torch.float32)
    yt = torch.as_tensor(y, dtype=torch.long)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    strata = nn.CrossEntropyLoss()
    model.train()
    for _ in range(epochy):
        for i in torch.randperm(len(Xt), generator=g).split(davka):
            opt.zero_grad()
            strata(model(Xt[i]), yt[i]).backward()
            opt.step()
    model.eval()
    return model


def proba_siete(model, X):
    with torch.no_grad():
        return torch.softmax(model(torch.as_tensor(X, dtype=torch.float32)),
                             dim=1).numpy()


def beh(data, seed=0, epochy=60):
    """Natrenuje TCN aj vsetky baseliny na tych istych datach a splite."""
    nastav_seed(seed)
    F_, C = data["X_train"].shape[2], len(data["triedy"])
    tcn = TCN(F_, C, dlzka_okna=data["dlzka_okna"])
    n_tcn = pocet_parametrov(tcn)
    skryte, n_gru = skryte_pre_parametre(F_, C, n_tcn)

    modely = [("tcn", tcn), ("gru", GRU(F_, C, skryte)),
              ("logreg_priemer", LogRegPriemer(C, seed)),
              ("bag_of_frames", BagOfFrames(C, seed))]
    vysledky = {}
    for meno, m in modely:
        if isinstance(m, nn.Module):
            trenuj_siet(m, data["X_train"], data["y_train"], seed, epochy)
            p = proba_siete(m, data["X_test"])
        else:
            m.fit(data["X_train"], data["y_train"])
            p = m.proba(data["X_test"])
        vysledky[meno] = ev.vyhodnot(data["y_test"], p, data["triedy"],
                                     data["benigna"])
    vysledky["tcn"]["parametrov"] = n_tcn
    vysledky["gru"]["parametrov"] = n_gru
    vysledky["gru"]["skryty_rozmer"] = skryte
    vysledky["tcn"]["recepcne_pole"] = tcn.rf
    return vysledky


def main(argv=None):
    ap = argparse.ArgumentParser(description="trening TCN a baselinov")
    ap.add_argument("--data", help="adresar s .npz a labely.json")
    ap.add_argument("--syn", action="store_true",
                    help="synteticke data (nie meranie) namiesto korpusu")
    ap.add_argument("--rezim", default="hodnota",
                    choices=("hodnota", "poradie", "sum"),
                    help="druh synteticnej ulohy, pozri syn_sessions()")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochy", type=int, default=60)
    ap.add_argument("--dlzka", type=int, default=DLZKA_OKNA)
    ap.add_argument("--podiel", type=float, default=0.6,
                    help="podiel starsich sessions v treningu")
    ap.add_argument("--out", help="JSON s vysledkami do data/results/")
    a = ap.parse_args(argv)
    if bool(a.data) == bool(a.syn):
        ap.error("zadaj bud --data, alebo --syn")

    sessions = (syn_sessions(a.seed, rezim=a.rezim) if a.syn
                else nacitaj_sessions(a.data))
    data = priprav(sessions, dlzka=a.dlzka, podiel=a.podiel)
    vysledky = beh(data, seed=a.seed, epochy=a.epochy)
    print(ev.tabulka(vysledky, data))
    if a.out:
        prikaz = "python3 -m tcn.train " + " ".join(sys.argv[1:])
        ev.uloz(vysledky, data, a.out, prikaz, synteticke=a.syn)
        print("zapisane: %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
