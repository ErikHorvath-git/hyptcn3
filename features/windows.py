"""
Sekvencne okna nad snimkovymi vektormi (jedna snimka = jeden casovy krok).

TVAR DAT
--------
Vystup je pole tvaru

    X[okno, cas, priznak]           (N, L, F)

a k nemu rovnako dlhy zoznam metadat (jeden zaznam na okno). F je dlzka
kontraktu z features/snapshot.py (MENA), teda jeden riadok = jedna snimka
so vsetkymi priznakmi, pamatovymi aj objektovymi.

PRECO UZ NIE PER-BIN TVAR
--------------------------
Do 2026-09-19 tento modul skladal okna z per-bin vektorov, teda tvar
(N, L, B, F) plus metoda ako_kanaly(), ktora ho splostila na (N, L, B*F).
Nepouzival to nikto: do modelu ide snimkovy vektor z features/snapshot.py,
kde su biny uz agregovane (cesta (a) z vtedy otvoreneho rozhodnutia, pozri
hlavicku features/snapshot.py), a tcn/ si okna skladalo vlastnou funkciou bez
ochran nizsie. Per-bin vetva sa preto zmazala. Per-bin vektor tym nezanika -
zostava v features/perbin.py, v sidecari snimky a v features/PERBIN.md; iba
sa uz nedostava do okien.

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

import numpy as np

# Vychodzia dlzka okna v snimkach; zdovodnenie je v hlavicke modulu.
DLZKA_OKNA = 16

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
    """Jedna snimka ako jeden casovy krok: metadata + vektor priznakov."""

    __slots__ = ("session", "seq", "cas_unix", "x", "priznaky", "je_plna",
                 "ma_predchodcu")

    def __init__(self, session, seq, x, priznaky, cas_unix=None,
                 je_plna=False, ma_predchodcu=True):
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
    """Pole okien a metadata k nim. X ma tvar (N, L, F)."""

    def __init__(self, X, meta, priznaky, dlzka, krok, preskocene=(),
                 vynechane=()):
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

    def __len__(self):
        return int(self.X.shape[0])

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
                    [v for v in self.vynechane if v["session"] in sessions])

    def __repr__(self):
        return ("Okna(n=%d, dlzka=%d, priznaky=%d, preskocene=%d, "
                "vynechane=%d)" % (len(self), self.dlzka, len(self.priznaky),
                                   len(self.preskocene), len(self.vynechane)))


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
            bloky.append(np.stack([s.x for s in kus], axis=0))
            meta.append(zaznam)
    if bloky:
        X = np.stack(bloky, axis=0)
    else:
        X = np.zeros((0, dlzka, len(priznaky)), dtype=np.float64)
    return Okna(X, meta, priznaky, dlzka, krok, preskocene, vynechane)
