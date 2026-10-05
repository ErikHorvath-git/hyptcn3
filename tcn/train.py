"""
train.py - data, split, normalizacia a trening. Spusta cely beh:

    python3 -m tcn.train --data data/sessions/vektory --out data/results/tcn.json
    python3 -m tcn.train --syn          # syntetika, ked korpus este nie je

VSTUPNE DATA
------------
Jedno sedenie = jeden .npz zo `python3 -m features session --out <subor>`:
kluce `matica` (T x 22), `mena` (kontrakt z features/snapshot.py) a `snimky`.
Vedla nich `labely.json`: {meno_session: trieda}. Nic ine sa necita - vektor
sa tu uz nepocita, aby v jednom datasete neboli cisla z dvoch implementacii.

BEZ VZORIEK SA DETEKCIA NEMERIA
-------------------------------
Na tomto stroji nie su ziadne realne malverove vzorky, takze z tohto modulu
nemoze vyjst cislo o detekcii malveru. Rezimy v syn_sessions() su vzorce
(hodnota, poradie, sum), nie spravanie skodliveho kodu, a ich ulohou je overit
MECHANIKU: ze okna neprekrocia hranice sedenia, ze split nemiesa sedenia, ze
je beh deterministicky a ze sa siet na trivialnej ulohe vobec nauci. Presnost,
F1 ani AUC z takeho behu nie su vysledkom prace (HONESTY.md P4) a ulozeny JSON
ma preto `synteticke_data: true` a `guest: null`.

Co sa bez vzoriek zistit NEDA: ci model odlisi malver od benigneho softveru,
ake su falosne poplachy a uniky v prevadzke, ci sa priznaky prenesu na inu VM
a ktora cast vektora (pamatova alebo objektova) k rozhodnutiu prispieva.

OKNA SKLADA features/windows.py
-------------------------------
Tento modul si okna NEROBI sam. Posuvne okno je pat riadkov, ale hranice, cez
ktore okno prekrocit nesmie (ine sedenie, diera v seq, prilis dlha casova
medzera, plna snimka, snimka bez predchodcu), su cely modul - a duplikovat ich
znamena mat dve definicie toho isteho a jednu z nich raz opravit.

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
mu/sd fituje features/normalize.py IBA na benignych TRENOVACICH sedeniach a
iba z riadkov, ktore sa aj do okien dostanu. `ma_predchodcu` a `je_plna` sa
nenormalizuju - su to indikatory 0/1 o tom, co ten riadok je.

RIADKY, KTORE DO OKNA NEPATRIA
------------------------------
V riadku s `ma_predchodcu` = 0 su proc_new, proc_gone a mod_delta nuly, ktore
nie su meranim; v riadku s `je_plna` = 1 maju priznaky 1 az 7 iny fyzikalny
vyznam nez v delta riadkoch (hlavicka features/snapshot.py). Okno, ktore taky
riadok obsahuje, nevznikne, a pocty su vo vysledku (`okien_bez_predchodcu`,
`okien_s_plnou_snimkou`). Priznaky vo vektore zostavaju - pri skorovani v
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
from features.windows import (DLZKA_OKNA, DOVOD_PLNA,       # noqa: E402
                              DOVOD_PREDCHODCA, okna,
                              snimky_z_matice)
from tcn import eval as ev                                  # noqa: E402
from tcn.baselines import (GRU, BagOfFrames, LogRegPriemer,  # noqa: E402
                           skryte_pre_parametre)
from tcn.model import TCN, TCNPrediktor, pocet_parametrov                 # noqa: E402

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
            X[:, MENA.index("je_plna")] = 0.0
            X[0, MENA.index("je_plna")] = 1.0           # prva je vzdy plna
            out.append({"meno": "202601%02dT000000Z_%s_%d" % (i + 1, trieda, i),
                        "trieda": trieda, "matica": X})
    return out


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

    snimky = [sn for s in sessions
              for sn in snimky_z_matice(s["meno"], s["matica"], MENA)]

    # Normalizacia: fit iba na benignych trenovacich sedeniach a iba z
    # riadkov, ktore sa aj do okien dostanu. Riadok plnej snimky ma v
    # priznakoch 1 az 7 iny vyznam, takze by mu/sd posunul.
    fit_mena = [m for m in tr_mena if labely[m] == benigna]
    if not fit_mena:
        raise ValueError("medzi trenovacimi sedeniami nie je ziadne benigne "
                         "(%r); mu/sd sa nema na com fitnut" % benigna)
    norm = Normalizer(priznaky=MENA,
                      nenormalizovane=("ma_predchodcu", "je_plna"))
    norm.fit([sn for sn in snimky if not sn.dovody()],
             sessions_fit=fit_mena, labely=labely,
             benigna_trieda=benigna, dlzka_okna=dlzka)

    vsetky = okna(snimky, dlzka=dlzka)
    casti = {}
    for cast, mena in (("train", tr_mena), ("test", te_mena)):
        o = vsetky.vyber_sessions(mena)
        if not len(o):
            raise ValueError("cast %s nema ani jedno okno" % cast)
        y = [triedy.index(labely[m["session"]]) for m in o.meta]
        casti[cast] = (norm.transform(o).X, np.asarray(y, dtype=np.int64))

    pocty = vsetky.pocty_vynechanych()
    return {
        "triedy": triedy, "benigna": triedy.index(benigna),
        "train_sessions": tr_mena, "test_sessions": te_mena,
        "fit_sessions": fit_mena,
        "X_train": casti["train"][0], "y_train": casti["train"][1],
        "X_test": casti["test"][0], "y_test": casti["test"][1],
        "dlzka_okna": dlzka,
        "okien_bez_predchodcu": pocty.get(DOVOD_PREDCHODCA, 0),
        "okien_s_plnou_snimkou": pocty.get(DOVOD_PLNA, 0),
        "kratke_useky": list(vsetky.preskocene),
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


# ------------------------------------------------------- predikcia normalu
# (blok E1): regresna hlava nad rovnakym backbone-om, strata MSE, tréning
# BEZ štítkov. Zmluva: v predikčnom režime sú VŠETKY vstupné sedenia
# benígne (škodlivé vzorky sa nikdy netrénujú - HONESTY P4); labely.json sa
# preto nevyžaduje vôbec.


def syn_sessions_predikcia(seed=0, na_sessions=4, dlzka=40):
    """
    Synteticke sessions pre PREDIKCIU normalu (E1): deterministicka
    sinusoida + maly sum, vsetky sedenia z toho isteho procesu.

    NIE JE TO MERANIE. Overuje sa MECHANIKA: okna sa skladaju bez stitkov,
    chronologicky split po sedeniach nepreteka, MSE klesne pod var ciela
    (referencia "predpovedaj stred" = 1.0). Sinusoida ma periodu ~25
    snimok, takze z 15 krokov okna sa da pokracovanie naozaj predpovedat.
    """
    rng = np.random.default_rng(seed)
    out = []
    for i in range(na_sessions):
        t = np.arange(dlzka)
        X = np.zeros((dlzka, len(MENA)))
        X[:, 0] = np.sin(t / 4.0) + rng.normal(0.0, 0.05, size=dlzka)
        X[:, 1] = np.cos(t / 5.0) + rng.normal(0.0, 0.05, size=dlzka)
        X[:, MENA.index("ma_predchodcu")] = 1.0
        X[0, MENA.index("ma_predchodcu")] = 0.0     # prva snimka retazca
        X[:, MENA.index("je_plna")] = 0.0
        X[0, MENA.index("je_plna")] = 1.0           # prva je vzdy plna
        out.append({"meno": "202601%02dT000000Z_pred_%d" % (i + 1, i),
                    "trieda": "idle", "matica": X})
    return out


def priprav_predikcia(sessions, dlzka=DLZKA_OKNA, podiel=0.6):
    """Okna, chronologický split po sedeniach a normalizácia - bez štítkov."""
    mena = sorted(s["meno"] for s in sessions)
    for m in mena:
        if not m[:8].isdigit():
            raise ValueError(
                "session %r nezacina casovou peciatkou, chronologicky "
                "split sa neda urobit" % m)
    k = max(1, int(round(podiel * len(mena))))
    if k >= len(mena):
        raise ValueError("podiel %s necha prazdny test pri %d sedeniach"
                         % (podiel, len(mena)))
    tr_mena, te_mena = mena[:k], mena[k:]

    snimky = [sn for s in sessions
              for sn in snimky_z_matice(s["meno"], s["matica"], MENA)]
    # normalizacia: fit IBA na trenovacich (vsetky benigne - zmluva rezimu)
    norm = Normalizer(priznaky=MENA,
                      nenormalizovane=("ma_predchodcu", "je_plna"))
    norm.fit([sn for sn in snimky if not sn.dovody()],
             sessions_fit=tr_mena, dlzka_okna=dlzka)

    vsetky = okna(snimky, dlzka=dlzka)
    data = {"train_sessions": tr_mena, "test_sessions": te_mena,
            "dlzka_okna": dlzka, "normalizacia": norm}
    for cast, cm in (("train", tr_mena), ("test", te_mena)):
        o = vsetky.vyber_sessions(cm)
        if not len(o):
            raise ValueError("cast %s nema ani jedno okno" % cast)
        X = norm.transform(o).X
        # vstup BEZ posledneho kroku: kauzalny vystup na pozicii L-2
        # predpoveda krok L-1; keby ciel v okne bol, uloha by zdegenerovala
        # na kopirovanie (MSE ~ 0 bez ucenia) - pozri TCNPrediktor
        data["X_%s" % cast] = X[:, :-1, :]
        data["y_%s" % cast] = X[:, -1, :]
    data["okien_bez_predchodcu"] = vsetky.pocty_vynechanych().get(
        DOVOD_PREDCHODCA, 0)
    data["okien_s_plnou_snimkou"] = vsetky.pocty_vynechanych().get(
        DOVOD_PLNA, 0)
    data["kratke_useky"] = list(vsetky.preskocene)
    data["konstantne_priznaky"] = list(norm.manifest.konstantne)
    return data


def trenuj_prediktor(model, X, y, seed=0, epochy=60, lr=0.01, davka=64):
    """Adam + MSE, fixny seed, CPU. Vracia model v rezime eval()."""
    nastav_seed(seed)
    g = torch.Generator().manual_seed(seed)
    Xt = torch.as_tensor(X, dtype=torch.float32)
    yt = torch.as_tensor(y, dtype=torch.float32)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    strata = nn.MSELoss()
    model.train()
    for _ in range(epochy):
        for i in torch.randperm(len(Xt), generator=g).split(davka):
            opt.zero_grad()
            strata(model(Xt[i]), yt[i]).backward()
            opt.step()
    model.eval()
    return model


def chyba_predikcie(model, X, y):
    """Per-okno aj per-priznak stvorce chyb (E2 zaklad)."""
    with torch.no_grad():
        p = model(torch.as_tensor(X, dtype=torch.float32))
        t = torch.as_tensor(y, dtype=torch.float32)
        return ((p - t) ** 2).numpy()


def beh_predikcia(data, seed=0, epochy=60):
    """TCNPrediktor + referencia 'predpovedaj stred' (nula po z-score).

    Referencia je ta spravna dolna latka: ked model nevie nic, jeho MSE sa
    rovna rozptylu ciela. mse_na_var < 1 teda znamena, ze sa nieco naucil.
    """
    nastav_seed(seed)
    F_ = data["X_train"].shape[2]
    tcn = TCNPrediktor(F_, dlzka_okna=data["dlzka_okna"])
    n_tcn = pocet_parametrov(tcn)
    trenuj_prediktor(tcn, data["X_train"], data["y_train"], seed, epochy)
    err_te = chyba_predikcie(tcn, data["X_test"], data["y_test"])
    err_tr = chyba_predikcie(tcn, data["X_train"], data["y_train"])
    var_te = float(np.mean(data["y_test"] ** 2))
    data["model"] = tcn            # score.py/_uloz_prediktor pouziju ten isty
    return {
        "model": "tcn_prediktor", "parametrov": n_tcn,
        "recepcne_pole": tcn.rf, "dlzka_okna": data["dlzka_okna"],
        "mse_train": float(np.mean(err_tr)),
        "mse_test": float(np.mean(err_te)),
        "var_test_ciela": var_te,
        "mse_na_var": float(np.mean(err_te) / (var_te or 1.0)),
        "synteticke_data": True,          # hlavny beh s korpusom prepise
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="trening TCN a baselinov")
    ap.add_argument("--data", help="adresar s .npz a labely.json")
    ap.add_argument("--syn", action="store_true",
                    help="synteticke data (nie meranie) namiesto korpusu")
    ap.add_argument("--uloha", default="klasifikacia",
                    choices=("klasifikacia", "predikcia"),
                    help="klasifikacia aktivit (stitky) alebo predikcia "
                         "normalu (E1, bez stitkov)")
    ap.add_argument("--rezim", default="hodnota",
                    choices=("hodnota", "poradie", "sum"),
                    help="druh synteticnej ulohy, pozri syn_sessions()")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochy", type=int, default=60)
    ap.add_argument("--dlzka", type=int, default=DLZKA_OKNA)
    ap.add_argument("--podiel", type=float, default=0.6,
                    help="podiel starsich sessions v treningu")
    ap.add_argument("--out", help="JSON s vysledkami do data/results/")
    ap.add_argument("--uloz-model", default=None,
                    help="uloz natrenovany model + normalizacny manifest "
                         "(<cesta>.pt a <cesta>.manifest.json)")
    a = ap.parse_args(argv)
    if bool(a.data) == bool(a.syn):
        ap.error("zadaj bud --data, alebo --syn")

    if a.syn:
        sessions = (syn_sessions_predikcia(a.seed) if a.uloha == "predikcia"
                    else syn_sessions(a.seed, rezim=a.rezim))
    else:
        sessions = nacitaj_sessions(a.data)

    if a.uloha == "predikcia":
        data = priprav_predikcia(sessions, dlzka=a.dlzka, podiel=a.podiel)
        vysledky = beh_predikcia(data, seed=a.seed, epochy=a.epochy)
        print("predikcia normalu (E1):")
        print("  mse_test=%.4f, var ciela=%.4f, mse/var=%.3f (referencia "
              "stred = 1.0)" % (vysledky["mse_test"],
                                vysledky["var_test_ciela"],
                                vysledky["mse_na_var"]))
        if a.uloz_model:
            _uloz_prediktor(a.uloz_model, data, vysledky)
            print("zapisane: %s (+ manifest)" % a.uloz_model)
        if a.out:
            prikaz = "python3 -m tcn.train " + " ".join(sys.argv[1:])
            ev.uloz(vysledky, data, a.out, prikaz, synteticke=a.syn)
            print("zapisane: %s" % a.out)
        return 0

    data = priprav(sessions, dlzka=a.dlzka, podiel=a.podiel)
    vysledky = beh(data, seed=a.seed, epochy=a.epochy)
    print(ev.tabulka(vysledky, data))
    if a.out:
        prikaz = "python3 -m tcn.train " + " ".join(sys.argv[1:])
        ev.uloz(vysledky, data, a.out, prikaz, synteticke=a.syn)
        print("zapisane: %s" % a.out)
    return 0


def _uloz_prediktor(cesta, data, vysledky):
    """Model (state_dict + popis) a normalizacny manifest vedla seba.

    score.py bez manifestu nemôže preškálovať vstup tými istými mu/sd,
    ktorými sa trénovalo - preto sa ukladajú vždy spolu.
    """
    import torch as _torch
    model = data["model"]
    _torch.save({"state_dict": model.state_dict(),
                 "priznakov": data["X_train"].shape[2],
                 "dlzka_okna": data["dlzka_okna"],
                 "recepcne_pole": model.rf,
                 "mse_test": vysledky["mse_test"]},
                cesta)
    data["normalizacia"].save(cesta + ".manifest.json")


if __name__ == "__main__":
    sys.exit(main())
