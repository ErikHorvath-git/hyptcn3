"""
Sekvencne okna nad per-bin vektormi (jedna snimka = jeden casovy krok).

TVAR DAT
--------
Vystup je pole tvaru

    X[okno, cas, bin, priznak]          (N, L, B, F)

a k nemu rovnako dlhy zoznam metadat (jeden zaznam na okno). Tvar je zvoleny
takto a nie hned splosteny na (N, L, B*F), lebo:

  - bin je viazany na fyzicku adresu (index = GPA >> log2(bin_bytes)), takze
    os binov ma vyznam a da sa cez nu agregovat. Ked sa splosti prilis skoro,
    agregacia cez biny sa uz bez prepocitavania indexov spravit neda;
  - pocet binov B zavisi od velkosti a rozlozenia memslotov VM. Ked je os
    binov samostatna, je na jednom mieste vidno, ako sa B meni, a nie je
    schovana v dlzke splosteneho vektora.

Pre model je k dispozicii metoda Okna.ako_kanaly(), ktora vrati (N, L, B*F)
s poradim bin-major, teda kanal = bin * F + priznak. TCN v tomto repozitari
ocakava (N, kanal, cas), co je transpozicia poslednych dvoch osi; robi sa az
v tcn/, aby windows.py nezavisel od tvaru vstupu konkretneho modelu.

OTVORENE ROZHODNUTIE PRE FAZU F3 (nezavislost modelu od poctu binov)
--------------------------------------------------------------------
Pri 2 GiB VM a bine 16 MiB vyjde radovo 130 binov, pri inej velkosti VM ina
hodnota. Model s pevnym poctom vstupnych kanalov teda nie je bez dalsieho
prenositelny medzi VM roznej velkosti. Mozne cesty, medzi ktorymi sa NEROZHODLO:

  (a) agregacia cez biny - na kazdy casovy krok sa z B binov spocitaju statistiky
      (priemer, max, kvantily, pocet binov s has_changed=1). Pocet kanalov je
      potom pevny a nezavisly od velkosti VM, ale straca sa informacia o tom,
      KTORA oblast pamate sa menila;
  (b) biny ako kanaly s pevnym poctom - zvoli sa pevny rozsah indexov binov
      (napr. prvych K binov nad memslotmi) a ostatne sa zahodia. Zachova sa
      poloha, ale model plati iba pre VM s rovnakym alebo vacsim rozsahom;
  (c) model, ktory os binov spracuje ako dalsiu os (konvolucia aj cez biny),
      teda pocet binov je dlzka, nie pocet kanalov.

Az do rozhodnutia tento modul nic z toho nerobi a vracia plnu os binov; ktora
cesta sa vyberie, sa zapise do manifestu (features/manifest.py) a do textu
prace ako navrh priznakoveho priestoru (bod M2 zadania).

DLZKA OKNA
----------
Vychodzia dlzka je DLZKA_OKNA = 16 snimok. Dovody:

  - perioda zberu. Korpus sa podla planu zbiera s periodou 2 s (60 cyklov na
    session), merania nakladu zberu bezali aj s periodou 5 s. Okno 16 snimok
    pokryva 32 s pri perioode 2 s a 80 s pri 5 s, teda dost na to, aby v nom
    bola vidiet faza scenara, a nie tolko, aby jedno okno pokrylo cely beh
    scenara. Zo session so 60 snimkami vznikne pri kroku 1 spolu 45 okien;
  - receptive field TCN. Pre kauzalnu dilatovanu siet s jadrom k a B blokmi
    plati RF = 1 + 2(k-1)(2^B - 1). Pri k=3 a B=3 je RF = 29 >= 16, takze
    posledny casovy krok vystupu vidi cele okno. Pri k=3 a B=2 je RF = 13 < 16
    a cast okna by do vystupu nevstupila vobec - to je chyba navrhu, nie
    vlastnost;
  - mocnina dvojky sa hodi k dilataciam 1, 2, 4, ktore sa zdvojnasobuju.

Dlzka je parameter a ma byt zdokumentovana pri kazdom vysledku. Konkretne:
retazec snimok z 2026-09-18 v /var/tmp/vmic-delta ma 6 snimok, takze pri
dlzke 16 z neho nevznikne ZIADNE okno. Nie je to chyba tohto modulu ani dovod
na potichu skratene okno - je to dovod zbierat dlhsie session (K18).

HRANICE, CEZ KTORE SA OKNO NESKLADA
-----------------------------------
  1. hranica session. Miesanie okien cez session bolo pricinou confoundu v
     predchadzajucej iteracii projektu, kde sa okna z roznych behov dostali do
     treningu aj testu naraz. Okno tu vznika iba vnutri jednej session;
  2. nespojite seq. Cislo cyklu sa zvysuje az po vykonanej praci (overene v
     vmicollect/src/sched.c, kde sa seq++ deje po volani work()), takze diera
     v seq znamena chybajuci alebo zahodeny sidecar, nie zmeskany slot;
  3. casova medzera vacsia nez max_medzera_s, ked je zadana. Zmeskany slot sa
     v seq NEPREJAVI (planovac posunie mriezku a zvysi cycles_skipped), takze
     jedine, cim sa da odhalit, je cas medzi snimkami. Bez tohto parametra
     moze okno pokryvat dlhsi realny cas, nez L krat perioda - preto ma kazde
     okno v metadatach trvanie_s;
  4. plna snimka, ked sa zada plne="vynechat". Prva snimka retazca je plna,
     takze je proti nicomu porovnana a pomery v nej opisuju cely obsah pamate,
     nie zmenu. Vynechanie takej snimky je zaroven rez - snimky pred nou a po
     nej sa do jedneho okna nespoja, lebo medzi nimi chyba casovy krok.

Nic sa nedoplna nulami: chybajuci bin, chybajuci priznak alebo zmena mnoziny
binov v ramci session su chyby, nie hodnota 0.

Povod: modul vznikol pre tuto pracu, nie je prevzaty.
"""

import json
import os

import numpy as np

from .manifest import PRIZNAKY, SCHEMA_PERBIN

# Vychodzia dlzka okna v snimkach; zdovodnenie je v hlavicke modulu.
DLZKA_OKNA = 16

# Krok posunu okna. Pri 1 sa okna prekryvaju, co je zamer (viac vzoriek z
# kratkej session), ale znamena to, ze susedne okna nie su nezavisle vzorky -
# split na trenovaciu a testovaciu cast musi byt preto po sessions, nie po
# oknach.
KROK = 1


class WindowError(Exception):
    pass


class Snimka:
    """Jedna snimka ako jeden casovy krok: metadata + per-bin vektor."""

    __slots__ = ("session", "seq", "cas", "cas_unix", "full", "biny", "x",
                 "bin_bytes", "priznaky", "zdroj")

    def __init__(self, session, seq, cas, cas_unix, biny, x, bin_bytes,
                 priznaky=PRIZNAKY, full=False, zdroj=""):
        self.session = str(session)
        self.seq = int(seq)
        self.cas = cas
        self.cas_unix = float(cas_unix)
        self.full = bool(full)
        self.biny = tuple(int(b) for b in biny)
        self.priznaky = tuple(priznaky)
        self.bin_bytes = int(bin_bytes)
        self.zdroj = zdroj
        x = np.asarray(x, dtype=np.float64)
        if x.shape != (len(self.biny), len(self.priznaky)):
            raise WindowError(
                "snimka %s/%d: vektor ma tvar %r, cakam (%d, %d)"
                % (self.session, self.seq, x.shape, len(self.biny),
                   len(self.priznaky)))
        self.x = x

    def __repr__(self):
        return ("Snimka(session=%r, seq=%d, biny=%d, priznaky=%d, full=%r)"
                % (self.session, self.seq, len(self.biny), len(self.priznaky),
                   self.full))


class Okna:
    """Pole okien a metadata k nim.

    X ma tvar (N, L, B, F). meta je n-tica slovnikov rovnakej dlzky ako N.
    """

    def __init__(self, X, meta, priznaky, biny, bin_bytes, dlzka, krok,
                 preskocene=()):
        self.X = X
        self.meta = tuple(meta)
        self.priznaky = tuple(priznaky)
        self.biny = tuple(biny)
        self.bin_bytes = int(bin_bytes)
        self.dlzka = int(dlzka)
        self.krok = int(krok)
        # preskocene: preco sa z niektorych useku okno neurobilo. Zoznam je
        # sucastou vystupu zamerne - "vzniklo 0 okien" sa nema zistovat az
        # podla prazdneho pola.
        self.preskocene = tuple(preskocene)

    def __len__(self):
        return int(self.X.shape[0])

    @property
    def sessions(self):
        """Sessions v poradi vyskytu; split sa robi po nich, nie po oknach."""
        out = []
        for m in self.meta:
            if m["session"] not in out:
                out.append(m["session"])
        return tuple(out)

    def ako_kanaly(self):
        """(N, L, B*F) s poradim bin-major: kanal = bin_index * F + priznak.

        Poradie je fixne a zhodne s poradim osi v X, takze sa da spatne
        rozlozit reshape-om. Manifest drzi poradie priznakov, zoznam binov
        drzi tento objekt.
        """
        n, l, b, f = self.X.shape
        return self.X.reshape(n, l, b * f)

    def vyber_sessions(self, sessions):
        """Podmnozina okien z danych sessions (split po sessions)."""
        sessions = set(sessions)
        idx = [i for i, m in enumerate(self.meta) if m["session"] in sessions]
        return Okna(self.X[idx] if idx else self.X[:0], [self.meta[i] for i in idx],
                    self.priznaky, self.biny, self.bin_bytes, self.dlzka,
                    self.krok, self.preskocene)

    def __repr__(self):
        return ("Okna(n=%d, dlzka=%d, biny=%d, priznaky=%d, preskocene=%d)"
                % (len(self), self.dlzka, len(self.biny), len(self.priznaky),
                   len(self.preskocene)))


def vektor_z_binov(biny_json, priznaky=PRIZNAKY):
    """Z bloku "bins" sidecaru spravi (indexy_binov, pole [B, F]).

    Chybajuci kluc je vynimka. Ticho doplnena nula by sa v treningu nedala
    odlisit od nameranej nuly - a prave to je dovod, preco ma kontrakt
    samostatny priznak has_changed.
    """
    if not isinstance(biny_json, (list, tuple)):
        raise WindowError("blok bins nie je zoznam, je %r" % (type(biny_json),))
    indexy = []
    riadky = []
    for i, b in enumerate(biny_json):
        if not isinstance(b, dict):
            raise WindowError("bin c. %d nie je objekt" % (i,))
        if "bin" not in b:
            raise WindowError("bin c. %d nema kluc 'bin'" % (i,))
        riadok = []
        for meno in priznaky:
            if meno not in b:
                raise WindowError("bin %r nema priznak %r; chybajuca hodnota sa "
                                  "nedoplna nulou" % (b["bin"], meno))
            hodnota = b[meno]
            if isinstance(hodnota, bool):
                hodnota = int(hodnota)
            if not isinstance(hodnota, (int, float)):
                raise WindowError("bin %r, priznak %r: necislo %r"
                                  % (b["bin"], meno, hodnota))
            riadok.append(float(hodnota))
        indexy.append(int(b["bin"]))
        riadky.append(riadok)
    if len(set(indexy)) != len(indexy):
        raise WindowError("blok bins obsahuje dvakrat ten isty bin")
    poradie = sorted(range(len(indexy)), key=lambda i: indexy[i])
    indexy = [indexy[i] for i in poradie]
    riadky = [riadky[i] for i in poradie]
    x = np.array(riadky, dtype=np.float64) if riadky else np.zeros((0, len(priznaky)))
    return tuple(indexy), x


def snimka_zo_sidecaru(cesta, session, priznaky=PRIZNAKY):
    """Precita jeden sidecar vmicollect/1 a vrati Snimku.

    Blok "features" do sidecaru zapisuje zberac (krok K13) alebo jeho python
    referencia (K14). Ked blok chyba, je to chyba vstupu - okna sa z neho
    nedaju poskladat a tvarit sa, ze snimka je nulova, by bola lez.
    """
    with open(cesta, encoding="utf-8") as fh:
        try:
            d = json.load(fh)
        except ValueError as e:
            raise WindowError("sidecar %s nie je platny JSON: %s" % (cesta, e))
    return snimka_zo_sidecar_dict(d, session, priznaky=priznaky, zdroj=cesta)


def snimka_zo_sidecar_dict(d, session, priznaky=PRIZNAKY, zdroj=""):
    """To iste ako snimka_zo_sidecaru, ale nad uz nacitanym slovnikom."""
    feats = d.get("features")
    if feats is None:
        raise WindowError("sidecar %s nema blok 'features' (per-bin vektor); "
                          "snimka bez vektora sa do okna nedava"
                          % (zdroj or d.get("id", "?"),))
    schema = feats.get("schema")
    if schema != SCHEMA_PERBIN:
        raise WindowError("sidecar %s: schema per-bin bloku je %r, cakam %r"
                          % (zdroj or d.get("id", "?"), schema, SCHEMA_PERBIN))
    if "bin_bytes" not in feats:
        raise WindowError("sidecar %s: blok features nema bin_bytes"
                          % (zdroj or d.get("id", "?"),))
    indexy, x = vektor_z_binov(feats.get("bins", []), priznaky=priznaky)
    bins_total = feats.get("bins_total")
    if bins_total is not None and int(bins_total) != len(indexy):
        raise WindowError("sidecar %s: bins_total=%s, ale v poli bins je %d binov"
                          % (zdroj or d.get("id", "?"), bins_total, len(indexy)))
    if "seq" not in d or "timestamp_unix" not in d:
        raise WindowError("sidecar %s nema seq alebo timestamp_unix"
                          % (zdroj or "?",))
    out = d.get("output", {})
    return Snimka(session=session, seq=d["seq"], cas=d.get("timestamp"),
                  cas_unix=d["timestamp_unix"], biny=indexy, x=x,
                  bin_bytes=feats["bin_bytes"], priznaky=priznaky,
                  full=bool(out.get("full", False)), zdroj=zdroj)


def nacitaj_session(adresar, session=None, priznaky=PRIZNAKY, vzor=".json"):
    """Nacita vsetky sidecary z adresara jednej session, zoradene podla seq.

    Meno session je vychodiskovo meno adresara - session je zberna relacia a
    v layoute repa jej zodpoveda prave jeden adresar v data/sessions/.
    """
    adresar = os.path.abspath(adresar)
    if session is None:
        session = os.path.basename(adresar.rstrip(os.sep))
    subory = sorted(os.path.join(adresar, n) for n in os.listdir(adresar)
                    if n.endswith(vzor))
    snimky = [snimka_zo_sidecaru(c, session, priznaky=priznaky) for c in subory]
    snimky.sort(key=lambda s: s.seq)
    seqs = [s.seq for s in snimky]
    if len(set(seqs)) != len(seqs):
        raise WindowError("session %s: dva sidecary s rovnakym seq" % (session,))
    return snimky


def segmenty(snimky, plne="ponechat", max_medzera_s=None):
    """Rozdeli snimky na spojite useky, cez ktore sa smie skladat okno.

    Rezy: ina session, diera v seq, prilis dlha casova medzera a (pri
    plne="vynechat") plna snimka. Dovody su v hlavicke modulu.
    """
    if plne not in ("ponechat", "vynechat"):
        raise WindowError("plne=%r; povolene je 'ponechat' alebo 'vynechat'"
                          % (plne,))
    usek = []
    out = []
    predch = None
    for s in snimky:
        rez = False
        if plne == "vynechat" and s.full:
            # plna snimka sa nielen vynecha, ale je aj rezom: bez nej medzi
            # susednymi snimkami chyba casovy krok
            if usek:
                out.append(usek)
            usek = []
            predch = None
            continue
        if predch is not None:
            if s.session != predch.session:
                rez = True
            elif s.seq != predch.seq + 1:
                rez = True
            elif s.biny != predch.biny:
                raise WindowError(
                    "session %s: medzi seq %d a %d sa zmenila mnozina binov "
                    "(%d vs %d); doplnanie chybajucich binov nulami je zakazane"
                    % (s.session, predch.seq, s.seq, len(predch.biny),
                       len(s.biny)))
            elif s.bin_bytes != predch.bin_bytes:
                raise WindowError("session %s: zmenila sa velkost binu (%d vs %d)"
                                  % (s.session, predch.bin_bytes, s.bin_bytes))
            elif s.priznaky != predch.priznaky:
                raise WindowError("session %s: zmenilo sa poradie priznakov"
                                  % (s.session,))
            elif max_medzera_s is not None and \
                    (s.cas_unix - predch.cas_unix) > max_medzera_s:
                rez = True
        if rez and usek:
            out.append(usek)
            usek = []
        usek.append(s)
        predch = s
    if usek:
        out.append(usek)
    return out


def okna(snimky, dlzka=DLZKA_OKNA, krok=KROK, plne="ponechat",
         max_medzera_s=None, priznaky=None):
    """Posklada okna tvaru (N, L, B, F) zo zoznamu snimok.

    Vstup nemusi byt zoradeny podla session ani seq - zoradi sa tu, aby sa
    poradie suborov na disku nepremietalo do dat. Vracia Okna vratane zoznamu
    useku, z ktorych okno nevzniklo, a preco.
    """
    if dlzka < 1:
        raise WindowError("dlzka okna musi byt aspon 1, je %d" % (dlzka,))
    if krok < 1:
        raise WindowError("krok musi byt aspon 1, je %d" % (krok,))
    snimky = sorted(snimky, key=lambda s: (s.session, s.seq))
    if not snimky:
        raise WindowError("ziadne snimky na vstupe")
    priznaky = tuple(priznaky) if priznaky is not None else snimky[0].priznaky
    biny = snimky[0].biny
    bin_bytes = snimky[0].bin_bytes
    for s in snimky:
        if s.priznaky != priznaky:
            raise WindowError("snimka %s/%d ma ine poradie priznakov: %r vs %r"
                              % (s.session, s.seq, list(s.priznaky),
                                 list(priznaky)))
        if s.biny != biny:
            raise WindowError(
                "snimka %s/%d ma inu mnozinu binov nez %s/%d (%d vs %d binov). "
                "Biny su viazane na fyzicku adresu; okna cez rozne rozlozenia "
                "memslotov sa neskladaju"
                % (s.session, s.seq, snimky[0].session, snimky[0].seq,
                   len(s.biny), len(biny)))
        if s.bin_bytes != bin_bytes:
            raise WindowError("snimka %s/%d ma bin_bytes %d, prva ma %d"
                              % (s.session, s.seq, s.bin_bytes, bin_bytes))

    bloky = []
    meta = []
    preskocene = []
    for usek in segmenty(snimky, plne=plne, max_medzera_s=max_medzera_s):
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
            bloky.append(np.stack([s.x for s in kus], axis=0))
            meta.append({
                "session": kus[0].session,
                "seq_od": kus[0].seq,
                "seq_do": kus[-1].seq,
                "cas_od": kus[0].cas,
                "cas_do": kus[-1].cas,
                "cas_unix_od": kus[0].cas_unix,
                "cas_unix_do": kus[-1].cas_unix,
                "trvanie_s": kus[-1].cas_unix - kus[0].cas_unix,
                "n_snimok": dlzka,
                "obsahuje_plnu": any(s.full for s in kus),
            })
    if bloky:
        X = np.stack(bloky, axis=0)
    else:
        X = np.zeros((0, dlzka, len(biny), len(priznaky)), dtype=np.float64)
    return Okna(X, meta, priznaky, biny, bin_bytes, dlzka, krok, preskocene)
