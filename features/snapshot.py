"""
snapshot.py - jedna snimka = jeden vektor pevnej dlzky.

PRECO EXISTUJE
--------------
Do tejto chvile mal repozitar dva oddelene vystupy: `guestparse` rekonstruoval
objekty hosta (procesy, moduly, sokety, kontroly) a tlacil ich ako zoznamy,
`perbin` pocital statistiky pamatovych oblasti. Model by sa z toho ucil iba
na pamati a o procesoch hosta by nevedel nic (docs/LIMITACIE.md, L14). Tento
modul obe vetvy spaja: z jednej snimky vyrobi JEDEN vektor, v ktorom su obe.

PRECO PEVNA DLZKA A NIE BINY AKO KANALY
----------------------------------------
Pocet binov zavisi od velkosti a rozlozenia memslotov VM (pri domene
hyptcn-guest ich je 131, pri inej velkosti pamate iny pocet). Keby biny boli
kanaly, model by sa priviazal na jednu velkost pamate. Preto sa cez biny
agreguje - to je cesta (a) z otvoreneho rozhodnutia vo `features/windows.py`.
Cenou je, ze sa straca informacia o tom, KTORA oblast pamate sa menila;
per-bin vektor kvoli tomu nezanika, zostava v perbin.py a v sidecari.

KONTRAKT VEKTORA (dohodnuty, nemeni sa bez dohody)
---------------------------------------------------
Dlzka je MENA - dvadsat priznakov plus dve polia o tom, co riadok vobec je:
`ma_predchodcu` a `je_plna`. Poradie je dane poradim v MENA a uklada sa spolu
s datami, aby sa dalo overit.

  Pamat (agregat z bloku "features" v sidecari, ktory pocita C modul):
     1  mem_changed_ratio   sucet pages_changed / sucet pages_total
     2  mem_bins_active     podiel binov s has_changed = 1
     3  mem_changed_max     najvyssi changed_ratio cez biny
     4  mem_changed_p95     95. percentil changed_ratio cez biny
     5  mem_changed_spread  normalizovana entropia rozdelenia pages_changed
     6  mem_entropy_mean    priemer entropy_mean, vazeny poctom zmenenych stranok
     7  mem_entropy_max     najvyssi entropy_mean cez biny so zmenou
     8  mem_zero_ratio      sucet nulovych stranok / sucet pages_total

  Objekty hosta (z guestparse nad tou istou snimkou):
     9  proc_total    10 proc_user    11 proc_kernel   12 proc_new
    13 proc_gone      14 mod_total    15 mod_delta     16 sock_total
    17 sock_listen    18 sock_estab   19 chk_syscall_hooks
    20 chk_crossview

  O riadku samotnom:
    21 ma_predchodcu  0/1 - bola pred touto snimkou ina?
    22 je_plna        0/1 - je to plna snimka, alebo delta?

PAMATOVA CAST SA NEDOPOCITAVA INAK
-----------------------------------
Berie sa vylucne z bloku "features" v sidecari snimky. Ked tam nie je,
funkcia skonci chybou a povie preco. Dopocitat ju tu z obrazu by znamenalo,
ze v jednom datasete by boli cisla z dvoch roznych implementacii a nedalo by
sa spatne zistit, ktory riadok je z ktorej.

Pomery `changed_ratio` sa pritom pocitaju z celych cisel `pages_changed` a
`pages_total`, nie z pola `changed_ratio` - to C tlaci cez printf zaokruhlene
na sest desatinnych miest a maximum ani percentil by potom neboli presne tie
hodnoty, ktore z celych cisel vyjdu.

PRVA SNIMKA RETAZCA
-------------------
Priznaky proc_new, proc_gone a mod_delta potrebuju predchadzajucu snimku.
Pri prvej snimke ziadna nie je. Zvolena cesta: vektor sa NEVYNECHA, ale nesie
pole `ma_predchodcu` = 0 a spomenute tri priznaky su v nom nula. Je to ta ista
dohoda ako `has_changed` v perbin.py - nula, ktora sa da odlisit od nameranej
nuly, lebo vedla nej stoji priznak, ktory hovori, ze sa nemerala. Dovod, preco
nie NaN: matica ide do normalizacie a do okien a NaN by sa cez ne rozliezol;
dovod, preco sa riadok nezahadzuje: pamatova cast prvej snimky namerana je
a zahodit ju by znamenalo zahodit aj ju.

PLNA SNIMKA MA INY FYZIKALNY VYZNAM
-----------------------------------
V plnej snimke nie je voci comu pocitat zmenu: delta writer do nej zapise
vsetky NENULOVE stranky (vmicollect/src/writer_delta.c), takze pages_changed
je pocet nenulovych stranok. Priznaky 1 az 7 preto opisuju cely obsah pamate,
nie jej zmenu, a mem_changed_ratio vyjde presne 1 - mem_zero_ratio. Je to
rovnake cislo s inym vyznamom nez v delta riadku a `ma_predchodcu` to
NEPOKRYVA - to sa tyka iba priznakov 12, 13 a 15.

Riadok preto nesie vlastny priznak `je_plna`. Dnes je plna snimka prva v
retazci, ale pri output.delta_full_every pride aj uprostred sedenia, takze
poradim sa spolahnut neda. Okno, ktore taky riadok obsahuje, sa v
features/windows.py NEPOSKLADA vobec (nie je to rez - riadok je plnohodnotny
casovy krok a vyhodit ho by znamenalo okno bez jedneho kroku).

KTO TO POUZIVA, MUSI `ma_predchodcu` A `je_plna` CITAT.
"""

import json
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guestparse import checks                              # noqa: E402
from guestparse.view import build_view                     # noqa: E402

from .perbin import FeatureError, _chain_parts             # noqa: E402

SCHEMA = "hyptcn3/snapshot-vektor/1"

MENA = (
    "mem_changed_ratio", "mem_bins_active", "mem_changed_max",
    "mem_changed_p95", "mem_changed_spread", "mem_entropy_mean",
    "mem_entropy_max", "mem_zero_ratio",
    "proc_total", "proc_user", "proc_kernel", "proc_new", "proc_gone",
    "mod_total", "mod_delta",
    "sock_total", "sock_listen", "sock_estab",
    "chk_syscall_hooks", "chk_crossview",
    "ma_predchodcu", "je_plna",
)

# Nalezy, ktore su krizovou nezrovnalostou (objekt vidi jeden pohlad a druhy
# nie). Ostatne nalezy kontrol (nerozumne meno modulu, struct module mimo
# oblasti modulov) su iny druh podozrenia a do chk_crossview nepatria.
KRIZOVE_NALEZY = ("process_cross_view", "module_cross_view",
                  "module_name_mismatch")


# ------------------------------------------------------------ pomocne vzorce


def percentil95(hodnoty):
    """
    95. percentil metodou najblizsieho poradia (bez interpolacie).

    Bez interpolacie zamerne: vysledok je vzdy niektora z nameranych hodnot,
    takze sa da v zozname binov najst. Pri interpolacii by vznikla hodnota,
    ktoru ziadny bin nema.
    """
    if not hodnoty:
        raise FeatureError("percentil z prazdneho zoznamu")
    s = sorted(hodnoty)
    i = math.ceil(0.95 * len(s)) - 1
    return s[max(i, 0)]


def entropia_rozdelenia(vahy):
    """
    Normalizovana Shannonova entropia rozdelenia vah medzi biny.

    0 = vsetka zmena je v jednom bine, 1 = rovnomerne cez vsetky biny.
    Normalizuje sa log2(pocet binov), nie log2(pocet binov so zmenou -
    inak by dve snimky s roznym poctom dotknutych binov mali obe hodnotu 1.

    Ked je sucet vah nulovy, rozdelenie neexistuje. Vracia sa 0 a je to
    rozoznatelne: mem_bins_active je vtedy tiez 0 a nula v nom iny vyznam
    mat nemoze.
    """
    celkom = sum(vahy)
    if celkom <= 0 or len(vahy) < 2:
        return 0.0
    h = 0.0
    for v in vahy:
        if v > 0:
            p = v / celkom
            h -= p * math.log2(p)
    return h / math.log2(len(vahy))


# ------------------------------------------------------------ pamatova cast


def sidecar_cesta(vmicd_path):
    """Sidecar patri k .vmicd suboru: rovnake meno, ina pripona."""
    if vmicd_path.endswith(".vmicd"):
        return vmicd_path[:-len(".vmicd")] + ".json"
    return vmicd_path + ".json"


def pamat_zo_sidecaru(cesta):
    """
    Osem pamatovych priznakov z bloku "features" v sidecari snimky.

    Kazdy dovod, preco to nejde, je chyba s vysvetlenim - nie nahradna
    hodnota. Vektor s tichou vypnou by vyzeral spravne a nebol by.
    """
    if not os.path.exists(cesta):
        raise FeatureError(
            "snimka nema vedla seba sidecar '%s'. Pamatova cast vektora sa "
            "berie vylucne z bloku 'features' v sidecari (pocita ho C modul) "
            "a inak sa NEDOPOCITAVA." % cesta)
    with open(cesta, encoding="utf-8") as fh:
        doc = json.load(fh)
    blok = doc.get("features")
    if not isinstance(blok, dict) or not isinstance(blok.get("bins"), list):
        raise FeatureError(
            "sidecar '%s' nema blok 'features' so zoznamom 'bins'. Zber musel "
            "bezat s per-bin vektorom zapnutym ([features] v konfiguracii "
            "vmicollect)." % cesta)
    bins = blok["bins"]
    if not bins:
        raise FeatureError("sidecar '%s': zoznam 'bins' je prazdny" % cesta)
    if blok.get("entropy") is False:
        raise FeatureError(
            "sidecar '%s': entropia bola pri zbere vypnuta, priznaky "
            "mem_entropy_mean a mem_entropy_max sa z neho ziskat nedaju"
            % cesta)

    pages_total = sum(b["pages_total"] for b in bins)
    pages_changed = sum(b["pages_changed"] for b in bins)
    if pages_total <= 0:
        raise FeatureError(
            "sidecar '%s': sucet pages_total je %d" % (cesta, pages_total))

    # Pomer z celych cisel, nie z pola changed_ratio (to je v subore
    # zaokruhlene na sest desatinnych miest).
    pomery = [b["pages_changed"] / b["pages_total"] if b["pages_total"] else 0.0
              for b in bins]
    zmenene = [b for b in bins if b["has_changed"]]

    # Pocet nulovych stranok binu C netlaci, tlaci ich podiel. Sucin s
    # pages_total je po zaokruhleni presne cele cislo: chyba podielu je
    # nanajvys polovica posledneho tlaceneho miesta, takze pri najvacsom
    # moznom pocte stranok binu zostava hlboko pod jednou strankou.
    nulove = sum(round(b["zero_ratio"] * b["pages_total"]) for b in bins)

    return [
        pages_changed / pages_total,
        sum(1 for b in bins if b["has_changed"]) / len(bins),
        max(pomery),
        percentil95(pomery),
        entropia_rozdelenia([b["pages_changed"] for b in bins]),
        (sum(b["entropy_mean"] * b["pages_changed"] for b in bins)
         / pages_changed) if pages_changed else 0.0,
        max((b["entropy_mean"] for b in zmenene), default=0.0),
        nulove / pages_total,
    ]


# ------------------------------------------------------------ objektova cast


def objekty_z_pohladu(view):
    """
    Dvanast objektovych priznakov (bez tych troch, co potrebuju predchodcu)
    plus stav, ktory sa podava dalsej snimke, plus zoznam poznamok.

    Poznamka vznikne vzdy, ked sa nejaky prechod neuzavrel: taky pocet je
    dolna hranica, nie pocet. Do vektora sa zapise, ale v reporte to musi byt
    vidiet - preto sa vracia von, nie iba do logu.
    """
    p = view.processes()
    m = view.modules()
    s = view.sockets(procs=p["processes"])
    c = checks.check_all(view, procs=p, mods=m)

    pozn = []
    for meno, res in (("procesy", p), ("moduly", m), ("sokety", s)):
        if res["truncated"]:
            pozn.append("%s: prechod sa neuzavrel (%s), pocet je dolna hranica"
                        % (meno, res["stop_reason"]))
    if c["summary"]["inconclusive"]:
        pozn.append("neuzavrete kontroly: %s"
                    % ", ".join(c["summary"]["inconclusive"]))

    sokety = s["sockets"]
    stav = {
        "pids": frozenset(pr["pid"] for pr in p["processes"]),
        "mod_total": m["count"],
    }
    hodnoty = {
        "proc_total": p["count"],
        "proc_user": sum(1 for pr in p["processes"]
                         if not pr["kernel_thread"]),
        "proc_kernel": sum(1 for pr in p["processes"] if pr["kernel_thread"]),
        "mod_total": m["count"],
        "sock_total": s["count"],
        "sock_listen": sum(1 for so in sokety if so["state"] == "LISTEN"),
        "sock_estab": sum(1 for so in sokety if so["state"] == "ESTABLISHED"),
        "chk_syscall_hooks": c["summary"]["syscall_hooks"],
        "chk_crossview": sum(1 for f in c["findings"]
                             if f["check"] in KRIZOVE_NALEZY),
    }
    return hodnoty, stav, pozn


# ------------------------------------------------------------ jedna snimka


def vektor_snimky(snapshot, profil, seq=None, predch=None):
    """
    Vektor jednej snimky retazca. Vracia (vektor, stav, poznamky).

    `seq` urcuje, po ktoru cast retazca sa stav pamate rekonstruuje (rovnako
    ako 'vmicollect restore --until'); None znamena poslednu cast.
    `predch` je `stav` z predchadzajucej snimky, alebo None pri prvej.
    """
    heads = _chain_parts(snapshot, until_seq=seq)
    # 'full' je z hlavicky .vmicd suboru tejto snimky, nie z poradia v
    # retazci: pri output.delta_full_every je plna snimka aj uprostred.
    je_plna = 1 if heads[-1]["full"] else 0
    pamat = pamat_zo_sidecaru(sidecar_cesta(heads[-1]["path"]))

    view, img = build_view(snapshot, profil, until_seq=seq)
    try:
        obj, stav, pozn = objekty_z_pohladu(view)
    finally:
        img.close()

    if predch is None:
        proc_new = proc_gone = mod_delta = 0
        ma_predchodcu = 0
    else:
        proc_new = len(stav["pids"] - predch["pids"])
        proc_gone = len(predch["pids"] - stav["pids"])
        mod_delta = stav["mod_total"] - predch["mod_total"]
        ma_predchodcu = 1

    vektor = pamat + [
        obj["proc_total"], obj["proc_user"], obj["proc_kernel"],
        proc_new, proc_gone,
        obj["mod_total"], mod_delta,
        obj["sock_total"], obj["sock_listen"], obj["sock_estab"],
        obj["chk_syscall_hooks"], obj["chk_crossview"],
        ma_predchodcu, je_plna,
    ]
    if len(vektor) != len(MENA):
        raise FeatureError("vektor ma %d cisel, kontrakt ma %d"
                           % (len(vektor), len(MENA)))
    return [float(x) for x in vektor], stav, pozn


# ------------------------------------------------------------ cely retazec


def retazec(snapshot, profil):
    """
    Cely retazec snimok: matica (cas x dlzka MENA) a mena priznakov.

    Riadky su v poradi seq, teda v case. Ku kazdemu riadku sa vracia aj id
    snimky, jej cas a trvanie spracovania - trvanie je udaj do kapitoly o
    real-time a nema zmysel ho merat zvlast inym behom.
    """
    heads = _chain_parts(snapshot)
    matica, snimky, poznamky, trvania = [], [], [], []
    predch = None
    for h in heads:
        t0 = time.monotonic()
        vektor, stav, pozn = vektor_snimky(snapshot, profil, h["seq"], predch)
        trvania.append(time.monotonic() - t0)
        matica.append(vektor)
        snimky.append(os.path.basename(h["path"])[:-len(".vmicd")])
        poznamky.append(pozn)
        predch = stav
    return {
        "schema": SCHEMA,
        "mena": list(MENA),
        "matica": matica,
        "snimky": snimky,
        "poznamky": poznamky,
        "trvanie_s": trvania,
    }
