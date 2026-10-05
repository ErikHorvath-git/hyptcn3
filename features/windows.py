"""
Sekvencne okna nad snimkovymi vektormi (jedna snimka = jeden casovy krok).

TVAR DAT
--------
Vystup je pole tvaru

    X[okno, cas, priznak]           (N, L, F)

a k nemu rovnako dlhy zoznam metadat (jeden zaznam na okno). F je dlzka
kontraktu z features/snapshot.py (MENA), teda jeden riadok = jedna snimka
so vsetkymi priznakmi, pamatovymi aj objektovymi.

PRECO UZ NIE PER-BIN TVAR (historia)
-------------------------------------
Do 2026-09-19 tento modul skladal okna z per-bin vektorov, teda tvar
(N, L, B, F) plus metoda ako_kanaly(), ktora ho splostila na (N, L, B*F).
Nepouzival to nikto: do modelu isiel snimkovy vektor z features/snapshot.py,
kde su biny uz agregovane (cesta (a) z vtedy otvoreneho rozhodnutia, pozri
hlavicku features/snapshot.py), a tcn/ si okna skladalo vlastnou funkciou bez
ochran nizsie. Per-bin vetva sa preto zmazala.

2026-10-05 (blok D) sa per-bin tvar VRACIA - ako VOLITELNY, popri agregovanom.
Dovod: anomaliu treba nielen detegovat, ale aj LOKALIZOVAT v pamati (E2), a na
to agregovany vektor nestaci. Tvar sa pritom NEVYPUSTA namiesto (N, L, F), ale
sklada sa OSOBITNE: okna_s_perbin() lepi za snimkovy vektor blok per-bin
priznakov, takze vystup je (N, L, F + B*4). Kto chce iba agregat, vola okna()
a dostane presne to, co doteraz.

PER-BIN BLOK A OBMEDZENIE POCTU BINOV
-------------------------------------
Per-bin priznaky su styri: changed_ratio, zero_ratio, entropy_mean,
has_changed (kontrakt v features/PERBIN.md). B je pocet binov a zalezi od VM
(bin = gpa >> log2(bin_bytes), bin bez memslotu neexistuje): pri hyptcn-guest
a bine 16 MiB je to 131. Tvar okna je preto VM-specificky a model natrenovany
na jednej VM sa na inu VM s inym B NEPRENESIE bez preprojekcie - toto je
priznane obmedzenie, nie chyba. Vsetky snimky jedneho retazca musia mat
ROVNAKU mnozinu binov (rovnake biny v rovnakom poradi), inak je to chyba:
do chybajuceho binu sa NEDOPLNA nula (rovnaka zasada ako pri priznakoch).
Zoradenie binov je vzostupne podla indexu - poradie riadkov v sidecari sa na
to nespolieha (perbin_zo_sidecaru() radi sam).

DLZKA OKNA
----------
Vychodzia dlzka je DLZKA_OKNA = 16 snimok. Dovody:

  - perioda zberu. Pri perioode 2 s pokryva okno 32 s, pri 5 s 80 s - dost na
    to, aby v nom bola vidiet faza spravania, a nie tolko, aby jedno okno
    pokrylo cely beh;
  - receptive field TCN. Pre kauzalnu dilatovanu siet s jadrom k a B blokmi
    plati RF = 1 + 2(k-1)(2^B - 1). Pri k=3 a B=3 je RF = 29 >= 16, takze
    posledny casovy krok vystupu vidi cele okno. Pri k=3 a B=2 je RF = 13 < 16
    a cast okna by do vystupu nevstupila vobec - to je chyba navrhu, nie
    vlastnost;
  - mocnina dvojky sa hodi k dilataciam 1, 2, 4, ktore sa zdvojnasobuju.

Dlzka je parameter a ma byt zdokumentovana pri kazdom vysledku. Konkretne:
retazec snimok z 2026-09-19 v data/raw/ ma 6 snimok, takze pri dlzke 16 z neho
nevznikne ZIADNE okno. Nie je to chyba tohto modulu ani dovod na potichu
skratene okno - je to dovod zbierat dlhsie sedenia.

HRANICE, CEZ KTORE SA OKNO NESKLADA
-----------------------------------
  1. hranica sedenia (session). Miesanie okien cez sedenia bolo pricinou
     confoundu v predchadzajucej iteracii projektu, kde sa okna z roznych
     behov dostali do treningu aj testu naraz. Okno tu vznika iba vnutri
     jedneho sedenia;
  2. nespojite seq. Cislo cyklu sa zvysuje az po vykonanej praci (overene vo
     vmicollect/src/sched.c, kde sa seq++ deje po volani work()), takze diera
     v seq znamena chybajuci alebo zahodeny sidecar, nie zmeskany slot;
  3. casova medzera vacsia nez max_medzera_s, ked je zadana. Zmeskany slot sa
     v seq NEPREJAVI (planovac posunie mriezku a zvysi cycles_skipped), takze
     jedine, cim sa da odhalit, je cas medzi snimkami.

RIADKY, KTORE V OKNE BYT NESMU
------------------------------
Dva druhy riadkov nemaju rovnaky vyznam ako ostatne, a okno, ktore taky riadok
obsahuje, preto nevznikne VOBEC (dovod je v Okna.vynechane):

  - `je_plna` = 1. V plnej snimke nie je voci comu pocitat zmenu: delta writer
     do nej zapise vsetky NENULOVE stranky, takze pages_changed je pocet
     nenulovych stranok a mem_changed_ratio vyjde presne 1 - mem_zero_ratio.
     Priznaky mem_changed_* a mem_entropy_* tak opisuju cely obsah pamate, nie
     jej zmenu - iste cislo s inym fyzikalnym vyznamom. Overuje to test
     features/tests/test_snapshot.py nad realnym retazcom;
  - `ma_predchodcu` = 0. Priznaky proc_new, proc_gone a mod_delta su v takom
     riadku nula, ktora nie je meranim (hlavicka features/snapshot.py).

Riadok sa NEVYHADZUJE zo sedenia, iba sa nim zamietne okno: vyhodit ho a
susedne snimky spojit by znamenalo okno, v ktorom medzi dvoma riadkami chyba
casovy krok. Prva snimka retazca je oboje naraz (plna aj bez predchodcu), pri
output.delta_full_every pride plna snimka aj uprostred sedenia - a vtedy ma
zamietnutie okna jediny ucinok.

Nic sa nedoplna nulami: chybajuci priznak alebo ina dlzka vektora su chyby,
nie hodnota 0.

Povod: modul vznikol pre tuto pracu, nie je prevzaty.
"""

import json

import numpy as np

# Vychodzia dlzka okna v snimkach; zdovodnenie je v hlavicke modulu.
DLZKA_OKNA = 16

# Per-bin priznaky kontraktu (features/PERBIN.md), v tomto poradi, jeden bin =
# jeden riadok matice (B, 4). Zoradene bin-major: za blok binu 0 ide blok binu
# 1, ... Poriadok sa NIKDE nepreusporiadava - je sucastou kontraktu tvaru.
BIN_PRIZNAKY = ("changed_ratio", "zero_ratio", "entropy_mean", "has_changed")


# Krok posunu okna. Pri 1 sa okna prekryvaju, co je zamer (viac vzoriek z
# kratkeho sedenia), ale znamena to, ze susedne okna nie su nezavisle vzorky -
# split na trenovaciu a testovaciu cast musi byt preto po sedeniach, nie po
# oknach.
KROK = 1

# Mena priznakov kontraktu (features/snapshot.py), podla ktorych sa rozhoduje,
# ci riadok smie byt v okne. Su povinne: bez nich by sa okna skladali aj z
# riadkov s inym vyznamom a nikto by sa to nedozvedel.
STLPEC_PLNA = "je_plna"
STLPEC_PREDCHODCA = "ma_predchodcu"

DOVOD_PLNA = "plna snimka"
DOVOD_PREDCHODCA = "bez predchodcu"


class WindowError(Exception):
    pass


class Snimka:
    """Jedna snimka ako jeden casovy krok: metadata + vektor priznakov.

    `x_perbin` a `biny` su VOLITELNE: matica (B, 4) per-bin priznakov a indexy
    jej riadkov (vzostupne). Bez nich sa da skladat len agregovane okno
    (okna()); okna_s_perbin() ich vyzaduje pri kazdej snimke.
    """

    __slots__ = ("session", "seq", "cas_unix", "x", "priznaky", "je_plna",
                 "ma_predchodcu", "x_perbin", "biny")

    def __init__(self, session, seq, x, priznaky, cas_unix=None,
                 je_plna=False, ma_predchodcu=True, x_perbin=None, biny=None):
        self.session = str(session)
        self.seq = int(seq)
        self.cas_unix = None if cas_unix is None else float(cas_unix)
        self.priznaky = tuple(priznaky)
        self.je_plna = bool(je_plna)
        self.ma_predchodcu = bool(ma_predchodcu)
        x = np.asarray(x, dtype=np.float64)
        if x.shape != (len(self.priznaky),):
            raise WindowError(
                "snimka %s/%d: vektor ma tvar %r, cakam (%d,)"
                % (self.session, self.seq, x.shape, len(self.priznaky)))
        self.x = x
        if x_perbin is None:
            self.x_perbin = None
            self.biny = ()
        else:
            xp = np.asarray(x_perbin, dtype=np.float64)
            if xp.ndim != 2 or xp.shape[1] != len(BIN_PRIZNAKY):
                raise WindowError(
                    "snimka %s/%d: per-bin matica ma tvar %r, cakam (B, %d)"
                    % (self.session, self.seq, xp.shape, len(BIN_PRIZNAKY)))
            if biny is None or len(biny) != xp.shape[0]:
                raise WindowError(
                    "snimka %s/%d: indexov binov je %s, riadkov matice %d"
                    % (self.session, self.seq,
                       len(biny) if biny is not None else None, xp.shape[0]))
            biny = tuple(int(b) for b in biny)
            if list(biny) != sorted(biny) or len(set(biny)) != len(biny):
                raise WindowError(
                    "snimka %s/%d: biny musia byt vzostupne a bez opakovania, "
                    "sú %r" % (self.session, self.seq, biny))
            self.x_perbin = xp
            self.biny = biny

    def dovody(self):
        """Preco tento riadok nesmie byt v okne; prazdne = smie."""
        d = []
        if self.je_plna:
            d.append(DOVOD_PLNA)
        if not self.ma_predchodcu:
            d.append(DOVOD_PREDCHODCA)
        return tuple(d)

    def __repr__(self):
        return ("Snimka(session=%r, seq=%d, priznaky=%d, je_plna=%r, "
                "ma_predchodcu=%r)" % (self.session, self.seq,
                                       len(self.priznaky), self.je_plna,
                                       self.ma_predchodcu))


class Okna:
    """Pole okien a metadata k nim. X ma tvar (N, L, F).

    Pri tvare 'snimka+perbin' (okna_s_perbin) ma X tvar (N, L, F + B*4):
    stlpce F snimkoveho vektora idu prve, za nimi per-bin blok bin-major.
    `biny` (indexy binov) a `bin_priznaky` (v tomto poradi) ho opisuju.
    """

    def __init__(self, X, meta, priznaky, dlzka, krok, preskocene=(),
                 vynechane=(), biny=(), bin_priznaky=(), tvar="snimka"):
        self.X = X
        self.meta = tuple(meta)
        self.priznaky = tuple(priznaky)
        self.dlzka = int(dlzka)
        self.krok = int(krok)
        # preskocene: usek bol kratsi nez okno. vynechane: okno by obsahovalo
        # riadok, ktory v nom byt nesmie. Oboje je sucastou vystupu zamerne -
        # "vzniklo 0 okien" sa nema zistovat az podla prazdneho pola.
        self.preskocene = tuple(preskocene)
        self.vynechane = tuple(vynechane)
        self.biny = tuple(int(b) for b in biny)
        self.bin_priznaky = tuple(bin_priznaky)
        if tvar not in ("snimka", "snimka+perbin"):
            raise WindowError("neznamy tvar okien: %r" % (tvar,))
        self.tvar = tvar

    def __len__(self):
        return int(self.X.shape[0])

    @property
    def b(self):
        """Pocet binov per-bin bloku (0 pri agregovanom tvare)."""
        return len(self.biny)

    @property
    def sessions(self):
        """Sedenia v poradi vyskytu; split sa robi po nich, nie po oknach."""
        out = []
        for m in self.meta:
            if m["session"] not in out:
                out.append(m["session"])
        return tuple(out)

    def pocty_vynechanych(self):
        """Dovod -> pocet okien. Okno moze mat dovodov viac a rata sa do
        kazdeho z nich (prva snimka retazca je plna AJ bez predchodcu)."""
        out = {}
        for v in self.vynechane:
            for d in v["dovody"]:
                out[d] = out.get(d, 0) + 1
        return out

    def vyber_sessions(self, sessions):
        """Podmnozina okien z danych sedeni (split po sedeniach)."""
        sessions = set(sessions)
        idx = [i for i, m in enumerate(self.meta) if m["session"] in sessions]
        return Okna(self.X[idx] if idx else self.X[:0],
                    [self.meta[i] for i in idx], self.priznaky, self.dlzka,
                    self.krok,
                    [p for p in self.preskocene if p["session"] in sessions],
                    [v for v in self.vynechane if v["session"] in sessions],
                    biny=self.biny, bin_priznaky=self.bin_priznaky,
                    tvar=self.tvar)

    def __repr__(self):
        return ("Okna(n=%d, dlzka=%d, priznaky=%d, tvar=%r, biny=%d, "
                "preskocene=%d, vynechane=%d)"
                % (len(self), self.dlzka, len(self.priznaky), self.tvar,
                   self.b, len(self.preskocene), len(self.vynechane)))


def snimky_z_matice(session, matica, priznaky, casy=None):
    """Riadky matice (T, F) jedneho sedenia ako zoznam Snimok.

    `je_plna` a `ma_predchodcu` sa citaju Z MATICE - su sucastou kontraktu
    vektora, nie metadatom dodanym vedla neho. Ked v poradi priznakov nie su,
    je to chyba: bez nich by sa okna skladali aj cez riadky s inym vyznamom.

    `casy` su volitelne unixove casy snimok. Bez nich sa da okno skladat, ale
    kontrola casovej medzery (max_medzera_s) nie - a povie to chybou, nie
    dopocitanym casom.
    """
    priznaky = tuple(priznaky)
    X = np.asarray(matica, dtype=np.float64)
    if X.ndim != 2 or X.shape[1] != len(priznaky):
        raise WindowError("matica ma tvar %r, cakam (T, %d)"
                          % (X.shape, len(priznaky)))
    for meno in (STLPEC_PLNA, STLPEC_PREDCHODCA):
        if meno not in priznaky:
            raise WindowError(
                "v poradi priznakov nie je %r; bez neho sa neda zistit, ktory "
                "riadok do okna nepatri" % (meno,))
    if casy is not None and len(casy) != len(X):
        raise WindowError("casov je %d, riadkov matice %d"
                          % (len(casy), len(X)))
    i_plna = priznaky.index(STLPEC_PLNA)
    i_pred = priznaky.index(STLPEC_PREDCHODCA)
    out = []
    for seq, riadok in enumerate(X):
        for i, meno in ((i_plna, STLPEC_PLNA), (i_pred, STLPEC_PREDCHODCA)):
            if riadok[i] not in (0.0, 1.0):
                raise WindowError("session %s, riadok %d: %s = %r, cakam 0/1"
                                  % (session, seq, meno, riadok[i]))
        out.append(Snimka(session=session, seq=seq, x=riadok,
                          priznaky=priznaky,
                          cas_unix=None if casy is None else casy[seq],
                          je_plna=riadok[i_plna] == 1.0,
                          ma_predchodcu=riadok[i_pred] == 1.0))
    return out


def segmenty(snimky, max_medzera_s=None):
    """Rozdeli snimky na spojite useky, cez ktore sa smie skladat okno.

    Rezy: ine sedenie, diera v seq a prilis dlha casova medzera. Dovody su
    v hlavicke modulu. Riadky, ktore v okne byt nesmu, sa TU nerezu - su to
    plnohodnotne casove kroky a zamieta sa az cele okno (pozri okna()).
    """
    usek = []
    out = []
    predch = None
    for s in snimky:
        rez = False
        if predch is not None:
            if s.session != predch.session:
                rez = True
            elif s.seq != predch.seq + 1:
                rez = True
            elif s.priznaky != predch.priznaky:
                raise WindowError("session %s: zmenilo sa poradie priznakov"
                                  % (s.session,))
            elif max_medzera_s is not None:
                if s.cas_unix is None or predch.cas_unix is None:
                    raise WindowError(
                        "session %s, seq %d: max_medzera_s je zadana, ale "
                        "snimka nema cas; medzera sa neda overit a dopocitat "
                        "sa nesmie" % (s.session, s.seq))
                if (s.cas_unix - predch.cas_unix) > max_medzera_s:
                    rez = True
        if rez and usek:
            out.append(usek)
            usek = []
        usek.append(s)
        predch = s
    if usek:
        out.append(usek)
    return out


def _poskladaj(snimky, dlzka, krok, max_medzera_s, priznaky, riadok):
    """Spolocne jadro okna() a okna_s_perbin(): jeden riadok okna = riadok(s)."""
    bloky, meta, preskocene, vynechane = [], [], [], []
    for usek in segmenty(snimky, max_medzera_s=max_medzera_s):
        if len(usek) < dlzka:
            preskocene.append({
                "session": usek[0].session,
                "seq_od": usek[0].seq,
                "seq_do": usek[-1].seq,
                "n_snimok": len(usek),
                "dovod": "usek kratsi nez dlzka okna (%d < %d)"
                         % (len(usek), dlzka),
            })
            continue
        for zac in range(0, len(usek) - dlzka + 1, krok):
            kus = usek[zac:zac + dlzka]
            zaznam = {
                "session": kus[0].session,
                "seq_od": kus[0].seq,
                "seq_do": kus[-1].seq,
                "n_snimok": dlzka,
            }
            dovody = sorted({d for s in kus for d in s.dovody()})
            if dovody:
                zaznam["dovody"] = dovody
                vynechane.append(zaznam)
                continue
            casy = [s.cas_unix for s in kus]
            zaznam["cas_unix_od"] = casy[0]
            zaznam["cas_unix_do"] = casy[-1]
            zaznam["trvanie_s"] = (None if casy[0] is None or casy[-1] is None
                                   else casy[-1] - casy[0])
            bloky.append(np.stack([riadok(s) for s in kus], axis=0))
            meta.append(zaznam)
    if bloky:
        X = np.stack(bloky, axis=0)
    else:
        X = np.zeros((0, dlzka, riadok(snimky[0]).shape[0]), dtype=np.float64)
    return X, meta, preskocene, vynechane


def okna(snimky, dlzka=DLZKA_OKNA, krok=KROK, max_medzera_s=None,
         priznaky=None):
    """Posklada okna tvaru (N, L, F) zo zoznamu snimok.

    Vstup nemusi byt zoradeny podla sedenia ani seq - zoradi sa tu, aby sa
    poradie suborov na disku nepremietalo do dat. Vracia Okna vratane zoznamu
    usekov, z ktorych okno nevzniklo, a okien zamietnutych pre riadok, ktory
    v nich byt nesmie.
    """
    if dlzka < 1:
        raise WindowError("dlzka okna musi byt aspon 1, je %d" % (dlzka,))
    if krok < 1:
        raise WindowError("krok musi byt aspon 1, je %d" % (krok,))
    snimky = sorted(snimky, key=lambda s: (s.session, s.seq))
    if not snimky:
        raise WindowError("ziadne snimky na vstupe")
    priznaky = tuple(priznaky) if priznaky is not None else snimky[0].priznaky
    for s in snimky:
        if s.priznaky != priznaky:
            raise WindowError("snimka %s/%d ma ine poradie priznakov: %r vs %r"
                              % (s.session, s.seq, list(s.priznaky),
                                 list(priznaky)))

    X, meta, preskocene, vynechane = _poskladaj(
        snimky, dlzka, krok, max_medzera_s, priznaky, riadok=lambda s: s.x)
    return Okna(X, meta, priznaky, dlzka, krok, preskocene, vynechane)


def okna_s_perbin(snimky, dlzka=DLZKA_OKNA, krok=KROK, max_medzera_s=None,
                  priznaky=None):
    """Okna tvaru (N, L, F + B*4): snimkovy vektor + per-bin blok.

    Za vektor priznakov (F, kontrakt snapshot.py) sa prilepi zrovnany per-bin
    blok (B * 4, bin-major, BIN_PRIZNAKY). Plati vsetko z okna() - hranice,
    zamietane riadky, zoradenie - a navyse: kazda snimka musi mat x_perbin a
    biny a mnozina binov musi byt vo VSETKYCH snimkach identicka (pocet binov
    zavisi od VM; rozchod = chyba, nie doplnenie nul).

    Vrati Okna s tvar='snimka+perbin', atributmi biny (indexy) a bin_priznaky.
    """
    if dlzka < 1:
        raise WindowError("dlzka okna musi byt aspon 1, je %d" % (dlzka,))
    if krok < 1:
        raise WindowError("krok musi byt aspon 1, je %d" % (krok,))
    snimky = sorted(snimky, key=lambda s: (s.session, s.seq))
    if not snimky:
        raise WindowError("ziadne snimky na vstupe")
    priznaky = tuple(priznaky) if priznaky is not None else snimky[0].priznaky
    for s in snimky:
        if s.priznaky != priznaky:
            raise WindowError("snimka %s/%d ma ine poradie priznakov: %r vs %r"
                              % (s.session, s.seq, list(s.priznaky),
                                 list(priznaky)))
        if s.x_perbin is None:
            raise WindowError(
                "snimka %s/%d nema per-bin blok; okna_s_perbin() ho vyzaduje "
                "pri kazdej snimke" % (s.session, s.seq))
    biny = snimky[0].biny
    for s in snimky:
        if s.biny != biny:
            raise WindowError(
                "snimka %s/%d ma biny %r, prva snimka %r; mnozina binov musi "
                "byt v celom retazci rovnaka (pocet binov zavisi od VM)"
                % (s.session, s.seq, list(s.biny), list(biny)))

    def riadok(s):
        return np.concatenate([s.x, s.x_perbin.reshape(-1)])

    X, meta, preskocene, vynechane = _poskladaj(
        snimky, dlzka, krok, max_medzera_s, priznaky, riadok=riadok)
    return Okna(X, meta, priznaky, dlzka, krok, preskocene, vynechane,
                biny=biny, bin_priznaky=BIN_PRIZNAKY, tvar="snimka+perbin")


def perbin_zo_sidecaru(path):
    """Z bloku 'features' sidecaru (pocital ho C modul) vrati (biny, matica).

    Vracia indexy binov vzostupne a maticu (B, 4) v poradi BIN_PRIZNAKY.
    Poradie riadkov v sidecari sa na to nespolieha - radi sa tu. Sidecar bez
    bloku per-bin vektora je chyba, nie ticha nula: ten blok pise iba zberac
    s modulom perbin.c (zber od 2026-09-18 21:43Z).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise WindowError("sidecar %s sa nedal precitat: %s" % (path, exc))
    feats = doc.get("features")
    if not isinstance(feats, dict) or not isinstance(feats.get("bins"), list):
        raise WindowError(
            "sidecar %s nema blok 'features' so zoznamom 'bins' (per-bin "
            "vektor); zber, ktory ho pisal, nemal modul perbin.c" % path)
    rows = sorted(feats["bins"], key=lambda r: r["bin"])
    biny = tuple(int(r["bin"]) for r in rows)
    if len(set(biny)) != len(biny):
        raise WindowError("sidecar %s: duplicitne indexy binov %r"
                          % (path, biny))
    matica = []
    for r in rows:
        for meno in BIN_PRIZNAKY:
            if meno not in r:
                raise WindowError("sidecar %s: bin %s nema pole %r"
                                  % (path, r.get("bin"), meno))
        if int(r["has_changed"]) not in (0, 1):
            raise WindowError("sidecar %s: bin %s ma has_changed=%r, cakam 0/1"
                              % (path, r["bin"], r["has_changed"]))
        if int(r["has_changed"]) == 0 and float(r["entropy_mean"]) != 0.0:
            raise WindowError(
                "sidecar %s: bin %s ma has_changed=0, ale entropy_mean=%r; "
                "podla kontraktu (features/PERBIN.md) ma byt 0"
                % (path, r["bin"], r["entropy_mean"]))
        matica.append([float(r[m]) for m in BIN_PRIZNAKY])
    return biny, np.asarray(matica, dtype=np.float64)
