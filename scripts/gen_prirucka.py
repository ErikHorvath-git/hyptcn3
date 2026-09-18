#!/usr/bin/env python3
"""
gen_prirucka.py - vyrobi docs/PRIRUCKA.md zo sablony docs/PRIRUCKA.sk.md.

PRECO EXISTUJE
--------------
Prirucka ma byt jediny vstupny dokument a zaroven sa nema rozist s kodom.
Kazdy udaj, ktory sa da zistit z kodu alebo z ulozeneho artefaktu, sa preto
do vysledku dosadzuje az pri generovani. V sablone je iba proza a zastupne
znacky @@NAZOV@@. Cislo prepisane rukou do sablony je chyba navrhu, nie
preklep: taky udaj zostarne ticho.

CO SA DOSADZUJE
---------------
  strom adresarov a pocty riadkov      git ls-files + wc -l
  prikazy, prepinace, podprikazy       --help zostavenej binarky a balikov
  konfiguracne kluce                   vmicollect config --keys
  vychodzie hodnoty klucov             vmicollect config (efektivna konfiguracia)
  velkost obrazu v selftest            vmicollect/src/main.c
  polia sidecaru                       sidecar vyrobeny PRI GENEROVANI prave
                                       prelozenou binarkou (backend 'file')
  pocet testov                         pytest --collect-only -q
  namerane cisla                       data/results/**/*.json (vzdy s n)
  commity merani                       git log --oneline nad SHA z artefaktov
  prostredie merani                    hlavicky a env.json ulozenych artefaktov
  znenia nadpisov L1..Ln               nadpisy v docs/LIMITACIE.md
  hlasenie libbpf                      stderr ulozeneho behu (probe.json)
  adresar profilu jadra hosta          profiles/*/kallsyms.txt

Rozdiel medzi "z kodu" a "z artefaktu" je podstatny. Z kodu sa cita vsetko, co
sa da zistit bez merania: napoveda, konfiguracia, velkost obrazu v selfteste
a odteraz aj polia sidecaru. Z ulozenych artefaktov sa citaju iba NAMERANE
hodnoty, prostredie a commity merani - teda to, co sa bez merania zistit neda.
Polia sidecaru medzi ne patrili omylom: ulozeny sidecar je snimka kodu v den
merania, takze premenovane pole vo vmicollect/src/meta.c by prirucka nevidela.

CO GENERATOR OVERUJE V PROZE
----------------------------
Jedinu vec: ze kazda cesta k suboru, ktora je v hotovom texte (v spatnych
apostrofoch alebo v bloku prikazov), naozaj existuje. Vecne zlu vetu bez cisla
nezachyti. Preto plati pravidlo: cislo patri do generovanej casti, nie do prozy.

CO SA NEDOSADZUJE
-----------------
Datum behu generatora ani zive verzie balikov hostitela. Keby v subore boli,
prirucka by sa rozchadzala sama so sebou po kazdom upgrade stroja a kontrola
aktualnosti by bola trvale cervena. Datumy a prostredie v texte su udaje
z artefaktov, teda z toho, na com sa naozaj meralo.

Z rovnakeho dovodu sa neuvadza HEAD repozitara: HEAD sa meni kazdym commitom
vratane toho, ktory prirucku prida. Uvadzaju sa commity, z ktorych pochadzaju
ulozene merania (pole "commit" v JSONoch) - tie sa menia az s novym meranim.

CO GENERATOR POTREBUJE
----------------------
Zostavenu binarku (make -C vmicollect) a Python. Binarku nielen cita: spusti ju
('--help', 'config', a kvoli sidecaru aj 'once' nad docasnym obrazom v subore).
Bezicu domenu, roota ani siet nie - backend 'file' je obycajny subor a docasny
adresar sa po sebe upratuje.

KED SA FAKT ZISTIT NEDA
-----------------------
Na jeho miesto ide viditelne 'NEZISTENE (dovod)' a skript skonci kodom 2.
Stary ani odhadnuty udaj sa nedosadi nikdy.

NAVRATOVE KODY
--------------
  0  vsetko zistene, subor zapisany
  2  aspon jeden fakt sa nezistil (subor je zapisany so znackami NEZISTENE)
  3  prirucka presiahla limit riadkov
  4  chyba v sablone (chybajuca alebo neznama znacka)
  5  text odkazuje na cestu, ktora neexistuje (subor je zapisany)

Kody 2 a 5 sa navzajom nezatienia: ked nastanu obidve veci naraz, vypisu sa
obidva zoznamy a vrati sa 2. Pred opravou sa hlasil iba kod 2 a o chybajucich
cestach sa citatel nedozvedel.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SABLONA = REPO / "docs" / "PRIRUCKA.sk.md"
VYSTUP = REPO / "docs" / "PRIRUCKA.md"
VYSLEDKY = REPO / "data" / "results"
# Strop dlzky vysledku. Zvyseny z 250 na 280 a je to rozhodnutie, nie ustupok:
#
#  - kapitola 8 uz limitacie neprerozprava prozou, ale dosadzuje jeden riadok na
#    kazdy nadpis z docs/LIMITACIE.md. Za presnost sa plati dlzkou a zoznam
#    rastie s cudzim dokumentom, nie s prozou tejto prirucky;
#  - pri 250 mala prirucka 249 riadkov. Taky strop uz neviedol ku kratsiemu
#    textu, ale k vytlacaniu viet inam, aby kontrola nesvietila na cerveno -
#    limit ma text drzat kratky, nie rozhodovat, co sa smie napisat.
#
# Ked sa aj tento strop naplni, patri sem dalsie rozhodnutie, nie tiche zvysenie:
# co z prirucky odchadza do docs/ARCHITEKTURA.md.
LIMIT_RIADKOV = 280

TEXT_PRIPONY = (".c", ".h", ".py", ".sh", ".md")

# Subory, ktore generator sam vyraba alebo cita. Do ziadneho poctu riadkov sa
# nepocitaju: inak by vysledok zavisel od svojej vlastnej dlzky a po kazdej
# zmene prozy by sa generator musel spustit dvakrat.
VLASTNE_SUBORY = ("docs/PRIRUCKA.md", "docs/PRIRUCKA.sk.md")


class Chyba(Exception):
    """Fakt sa nedal zistit. Text je dovod, ktory sa dostane do vystupu."""


# ---------------------------------------------------------------- pomocne


def spusti(cmd, timeout=180, cwd=None):
    """Spusti prikaz a vrati stdout. Zlyhanie je Chyba s citatelnym dovodom."""
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd or REPO),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise Chyba("prikaz '%s' nie je nainstalovany" % cmd[0])
    except subprocess.TimeoutExpired:
        raise Chyba("prikaz '%s' nedobehol do %d s" % (" ".join(cmd), timeout))
    if p.returncode != 0:
        posledny = (p.stderr.strip() or p.stdout.strip() or "bez vypisu").splitlines()
        raise Chyba(
            "prikaz '%s' skoncil kodom %d: %s"
            % (" ".join(cmd), p.returncode, posledny[-1][:120])
        )
    return p.stdout


def nacitaj_json(relcesta):
    cesta = VYSLEDKY / relcesta
    if not cesta.is_file():
        raise Chyba("artefakt data/results/%s neexistuje" % relcesta)
    try:
        with cesta.open(encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise Chyba("data/results/%s sa neda precitat: %s" % (relcesta, exc))


def kluc(doc, cesta, zdroj):
    """doc['a']['b'] cez retazec 'a.b' alebo cez zoznam ['a', 'b'] (ked ma
    nazov kluca v sebe bodku); chybajuci kluc je Chyba, nie ticha None."""
    cur = doc
    for cast in (cesta if isinstance(cesta, list) else cesta.split(".")):
        if isinstance(cur, list):
            try:
                cur = cur[int(cast)]
                continue
            except (ValueError, IndexError):
                raise Chyba("v %s chyba %s" % (zdroj, cesta))
        if not isinstance(cur, dict) or cast not in cur:
            raise Chyba("v %s chyba %s" % (zdroj, cesta))
        cur = cur[cast]
    return cur


def cislo(x, des=1):
    """Slovensky zapis cisla: desatinna ciarka, tisice oddelene medzerou."""
    if isinstance(x, int) or (isinstance(x, float) and x == int(x) and des == 0):
        s = "{:,}".format(int(x)).replace(",", " ")
        return s
    s = "{:,.{}f}".format(float(x), des)
    cela, _, zvysok = s.partition(".")
    return cela.replace(",", " ") + "," + zvysok


def bin_vmicollect():
    b = REPO / "vmicollect" / "build" / "vmicollect"
    if not b.is_file():
        raise Chyba("vmicollect/build/vmicollect nie je zostaveny (make -C vmicollect)")
    return str(b)


# ---------------------------------------------------- 1. strom a adresare

# Popis adresara, subor, ktorym sa v nom zacina citat, a stvrty stlpec tabulky.
# Popis je veta o zamere, tu z kodu precitat nejde. Cesta ano - a prave ta sa tu
# overuje: ked sa subor premenuje alebo zmaze, generator to ohlasi ako NEZISTENE.
#
# STVRTY STLPEC: None znamena "spocitaj subory a riadky". Retazec znamena
# "nepocitaj, napis toto".
#
# PRECO SA NEPOCITA VSADE: pocet suborov je uzitocny pri adresari s kodom - meni
# sa, ked niekto kod prida alebo zmaze, a to je zmena, po ktorej sa prirucka ma
# pregenerovat. Pri adresari, ktory rastie SPUSTENIM prikazu z tejto prirucky, je
# to pasca: kto sa riadi kapitolou 4, zapise 'root_run.sh probe|run' novy JSON do
# data/results/ a kontrola mu ohlasi "PRIRUCKA.md je zastarana", hoci sa ani
# v kode, ani v texte nic nezmenilo. Navod na pouzitie si tak sam rozbije
# kontrolu. Take adresare maju namiesto poctu vetu o tom, co v nich je.
#
# Tyka sa to data/ (results/ aj sessions/ rastu kazdym meranim; raw/ je mimo gitu,
# takze do poctu nesla nikdy) a profiles/, do ktoreho prida adresar kazde spustenie
# scripts/get_profile.sh nad hostom s inou verziou jadra - a to je tiez prikaz
# z kapitoly 4.
ADRESARE = [
    ("vmicollect/", "zberač snímok pamäte VM: C a eBPF nad QEMU/KVM",
     "vmicollect/src/collector.c", None),
    ("guestparse/", "rekonštrukcia procesov, modulov a soketov zo snímky",
     "guestparse/view.py", None),
    ("features/", "per-bin príznakový vektor (referencia), okná, normalizácia",
     "features/perbin.py", None),
    ("profiles/", "profil jadra hosťa: symboly a offsety polí štruktúr",
     "profiles/*/README.md", "jeden adresár na verziu jadra hosťa"),
    ("scripts/", "root behy, príkazy v hosťovi, kontroly tvrdení",
     "scripts/root_run.sh", None),
    ("data/", "výsledkové JSONy z meraní (`data/results/`) a pozemná pravda "
     "odobratá v hosťovi (`data/sessions/`); samotné snímky `.vmicd` sú mimo "
     "gitu (`data/raw/`)",
     "data/results/2026-09-18_zmrazeny_host/README.md",
     "rastie s každým meraním, nepočíta sa"),
]


def _riadkov(cesty):
    spolu = 0
    for c in cesty:
        if c in VLASTNE_SUBORY:
            continue
        p = REPO / c
        if p.suffix in TEXT_PRIPONY and p.is_file():
            with p.open("rb") as fh:
                spolu += fh.read().count(b"\n")
    return spolu


def strom():
    # --cached --others --exclude-standard = subory, ktore do repa patria:
    # verzionovane aj zatial nezacommitovane, ale bez tych z .gitignore.
    # Samotne 'git ls-files' by pocitalo iba verzionovane, takze kazdy novy
    # subor by prirucku zostaril az vo chvili 'git add' a nie hned.
    vystup = spusti(["git", "ls-files", "--cached", "--others", "--exclude-standard"])
    subory = [r for r in vystup.splitlines() if r]
    riadky = []
    for adresar, popis, start, velkost in ADRESARE:
        moje = [s for s in subory if s.startswith(adresar)]
        if not moje:
            raise Chyba("v gite nie je ziadny subor pod %s" % adresar)
        if "*" in start:
            najdene = sorted(glob.glob(str(REPO / start)))
            if not najdene:
                raise Chyba("vzoru %s nezodpoveda ziadny subor" % start)
            start = os.path.relpath(najdene[0], REPO)
        elif not (REPO / start).is_file():
            raise Chyba("subor %s, na ktory prirucka odkazuje, neexistuje" % start)
        if velkost is None:
            velkost = "%d / %s" % (len(moje), cislo(_riadkov(moje), 0))
        riadky.append(
            "| `%s` | %s | `%s` | %s |" % (adresar, popis, start, velkost)
        )
    return "\n".join(riadky)


# ------------------------------------------------------- 2. napovedy CLI


def _bloky_help(text):
    """Rozdeli napovedu vmicollect na bloky podla nadpisov pisanych velkymi."""
    bloky, meno = {}, None
    for r in text.splitlines():
        if r and not r[0].isspace() and r.strip() == r.strip().upper():
            meno = r.strip()
            bloky[meno] = []
        elif meno and r.strip():
            bloky[meno].append(r)
    return bloky


def _rozdel(text):
    """Oddeli nazov polozky od popisu. Napoveda ich oddeluje dvoma medzerami,
    ale nie vzdy ('selftest [adresar] over ...'), preto je aj zaloha: k prvemu
    slovu patria este slova zacinajuce '[' alebo '-', zvysok je popis."""
    cast = re.split(r"\s{2,}", text, maxsplit=1)
    if len(cast) == 2 and cast[1].strip():
        return cast[0].strip(), cast[1].strip()
    slova = text.split()
    i = 1
    while i < len(slova) and (slova[i].startswith("[") or slova[i].startswith("-")):
        i += 1
    return " ".join(slova[:i]), " ".join(slova[i:])


def _polozky(riadky, odsadenie=2):
    """Z odsadenych riadkov urobi dvojice (nazov, popis). Riadok odsadeny viac
    nez polozka je pokracovanie predchadzajucej - typicky tvar volania."""
    polozky = []
    for r in riadky:
        medzery = len(r) - len(r.lstrip())
        text = r.strip()
        if medzery <= odsadenie or not polozky:
            polozky.append(list(_rozdel(text)))
        else:
            polozky[-1][1] = ("%s — `%s`" % (polozky[-1][1], text)).strip()
    return polozky


def prikazy_vmicollect():
    """Tabulka prikazov. 'config --keys' nie je samostatny prikaz, ale prepinac
    prikazu 'config' - napoveda ho vypisuje ako vlastny riadok, tu sa vlozi do
    popisu prikazu, pod ktory patri."""
    bloky = _bloky_help(spusti([bin_vmicollect(), "--help"]))
    if "PRIKAZY" not in bloky:
        raise Chyba("napoveda vmicollect nema blok PRIKAZY")
    riadky = []
    for token, popis in _polozky(bloky["PRIKAZY"]):
        slova = token.split()
        if len(slova) > 1 and slova[1].startswith("-"):
            for i, (t, p) in enumerate(riadky):
                if t == slova[0]:
                    riadky[i] = (t, "%s; s `%s` %s"
                                 % (p, " ".join(slova[1:]), popis))
                    break
            else:
                riadky.append((token, popis))
            continue
        riadky.append((token, popis))
    return "\n".join("| `%s` | %s |" % (t, p) for t, p in riadky)


# Prepinace, ktore nenesu informaciu (kazdy program ich ma) a v prirucke iba
# zaberaju miesto.
PREPINACE_VON = ("-h", "--help", "-V", "--version")


def prepinace_vmicollect():
    bloky = _bloky_help(spusti([bin_vmicollect(), "--help"]))
    if "PREPINACE" not in bloky:
        raise Chyba("napoveda vmicollect nema blok PREPINACE")
    kusy = []
    for token, popis in _polozky(bloky["PREPINACE"]):
        mena = [s.strip(",") for s in token.split() if s.startswith("-")]
        if any(m in PREPINACE_VON for m in mena):
            continue
        kusy.append("`%s` %s" % (token, popis))
    if not kusy:
        raise Chyba("po odfiltrovani --help/--version neostal ziadny prepinac")
    return ", ".join(kusy)


def podprikazy_balika(modul):
    text = spusti([sys.executable, "-m", modul, "--help"])
    riadky, ber = [], False
    for r in text.splitlines():
        if r.startswith("positional arguments:"):
            ber = True
            continue
        if ber:
            if r.startswith("options:") or not r.strip():
                break
            if r.strip().startswith("{"):
                continue
            riadky.append(r)
    if not riadky:
        raise Chyba("napoveda 'python3 -m %s' nema zoznam podprikazov" % modul)
    return ", ".join(
        "`%s` %s" % (t, p) for t, p in _polozky(riadky, odsadenie=4)
    )


# --------------------------------------------------- 3. konfiguracne kluce


def konfiguracne_kluce():
    text = spusti([bin_vmicollect(), "config", "--keys"])
    sekcie, meno = [], None
    for r in text.splitlines():
        s = r.strip()
        if s.startswith("[") and s.endswith("]"):
            meno = s
            sekcie.append((meno, []))
        elif meno and s:
            sekcie[-1][1].append(s.split()[0])
    if not sekcie:
        raise Chyba("'config --keys' nevypisal ziadnu sekciu")
    return "\n".join(
        "- `%s` — %s" % (meno, ", ".join(kluce)) for meno, kluce in sekcie
    )


# Vychodzie hodnoty sa citaju z vypisu efektivnej konfiguracie, teda z toho, co
# binarka naozaj pouzije, ked jej nikto nic nenastavi. Prepisanie hodnoty
# v config.c sa tak prejavi v prirucke hned po 'make'.
_KONFIG_CACHE = {}


def _konfig_efektivna():
    if not _KONFIG_CACHE:
        text = spusti([bin_vmicollect(), "config"])
        sekcia = None
        for r in text.splitlines():
            s = r.strip()
            if s.startswith("[") and s.endswith("]"):
                sekcia = s[1:-1]
                continue
            if not sekcia or s.startswith("#") or "=" not in s:
                continue
            k, _, v = s.partition("=")
            _KONFIG_CACHE["%s.%s" % (sekcia, k.strip())] = v.strip()
        if not _KONFIG_CACHE:
            raise Chyba("'vmicollect config' nevypisal ziadny kluc")
    return _KONFIG_CACHE


def vychodzia(kluc):
    hodnoty = _konfig_efektivna()
    if kluc not in hodnoty:
        raise Chyba("'vmicollect config' nepozna kluc %s" % kluc)
    if hodnoty[kluc] == "":
        raise Chyba("kluc %s nema vychodziu hodnotu" % kluc)
    return hodnoty[kluc]


def _bajty(text, kluc):
    try:
        n = int(text)
    except ValueError:
        raise Chyba("hodnota kluca %s nie je cislo: %s" % (kluc, text))
    if n % (1024 ** 2):
        return "%s B" % cislo(n, 0)
    return "%s MiB" % cislo(n // 1024 ** 2, 0)


def bin_velkost():
    kluc_ = "features.bin_bytes"
    return _bajty(vychodzia(kluc_), kluc_)


def vychodzie_zhrnutie():
    """Hodnoty klucov, ktore proza vyssie spomina menom."""
    kusy = []
    for kluc_ in ("schedule.interval_s", "output.writer",
                  "output.hash", "output.sidecar", "output.delta_full_every"):
        kusy.append("`%s` = `%s`" % (kluc_, vychodzia(kluc_)))
    kusy.append("`features.bin_bytes` = %s" % bin_velkost())
    return ", ".join(kusy)


# ------------------------------------------- 3b. dalsie fakty z kodu a dokumentov


LIMITACIA_ZNAKOV = 60


def _limitacie():
    """Nadpisy L1..Ln z docs/LIMITACIE.md ako dvojice (cislo, cele znenie)."""
    cesta = REPO / "docs" / "LIMITACIE.md"
    if not cesta.is_file():
        raise Chyba("docs/LIMITACIE.md neexistuje")
    with cesta.open(encoding="utf-8") as fh:
        najdene = [(int(m.group(1)), m.group(0).lstrip("#").strip())
                   for m in re.finditer(r"^#+\s*L(\d+)\b.*$", fh.read(), re.M)]
    if not najdene:
        raise Chyba("v docs/LIMITACIE.md nie je ziadny nadpis tvaru 'L<cislo>'")
    cisla = [c for c, _ in najdene]
    if sorted(cisla) != list(range(1, len(cisla) + 1)):
        raise Chyba("cislovanie limitacii v docs/LIMITACIE.md nie je suvisle")
    return najdene


def _skrat(text, znakov=LIMITACIA_ZNAKOV):
    """Skrati nadpis na dany pocet znakov. Ked rez padne dovnutra spatnych
    apostrofov, doplni chybajuci - inak by rozbil zvysok tabulky."""
    if len(text) > znakov:
        text = text[:znakov].rstrip() + "…"
    if text.count("`") % 2:
        text += "`"
    return text


def limitacie_nadpisy():
    """Znenia nadpisov, nie ich pocet.

    Pocet je slaby dokaz: kto prepise nadpis L7 na opacne tvrdenie, pocet
    nezmeni a kontrola mlci. Znenie taku zmenu ukaze hned - prirucka sa
    rozide s docs/LIMITACIE.md a check_prirucka.sh to ohlasi.
    """
    riadky = []
    for cislo_, znenie in _limitacie():
        # z 'L7 — Confidential VM ...' ostane samotne tvrdenie; cislo uz je
        # v tucnom prefixe a opakovat ho by ubralo miesto zneniu
        _, oddelovac, zvysok = znenie.partition("—")
        riadky.append("- **L%d** — %s"
                      % (cislo_, _skrat((zvysok if oddelovac else znenie).strip())))
    return "\n".join(riadky)


def limitacie_rozsah():
    return "L1 až L%d" % len(_limitacie())


def selftest_obraz():
    """Velkost synteticheho obrazu v 'vmicollect selftest' - zo zdrojaku."""
    cesta = REPO / "vmicollect" / "src" / "main.c"
    if not cesta.is_file():
        raise Chyba("vmicollect/src/main.c neexistuje")
    with cesta.open(encoding="utf-8") as fh:
        m = re.search(r"IMG\s*=\s*(\d+)u?\s*<<\s*(\d+)", fh.read())
    if not m:
        raise Chyba("vo vmicollect/src/main.c sa nenasla velkost obrazu IMG")
    return _bajty(str(int(m.group(1)) << int(m.group(2))), "IMG")


def profil_adresar():
    """Adresar profilu jadra hosta - aby sa prikaz v prirucke dal spustit."""
    najdene = sorted(glob.glob(str(REPO / "profiles" / "*" / "kallsyms.txt")))
    if not najdene:
        raise Chyba("v profiles/ nie je ziadny adresar s kallsyms.txt")
    return os.path.relpath(os.path.dirname(najdene[0]), REPO)


def hlaska_libbpf():
    """Nefatalne hlasenie libbpf - doslovne z ulozeneho behu, nie z pamate."""
    doc = nacitaj_json(PROBE)
    riadky = [r for r in str(kluc(doc, "stderr", PROBE)).splitlines()
              if "bpf_create_map" in r]
    if not riadky:
        raise Chyba("v data/results/%s nie je hlasenie o bpf_create_map" % PROBE)
    # zo zaznamu 'cas UROVEN text' ostane text
    m = re.match(r"^\S+\s+\S+\s+(.*)$", riadky[0].strip())
    return (m.group(1) if m else riadky[0].strip())


# --------------------------------------------------------- 4. sidecar


SIDECAR_OBRAZ_MIB = 4


def _vyrob_sidecar(prac):
    """Vyrobi jeden sidecar prave prelozenou binarkou a vrati jeho obsah.

    Backend 'file' je obycajny subor namiesto hypervizora, takze na to netreba
    ani bezicu domenu, ani roota, ani siet. Writer 'delta' preto, ze blok
    'features' vznika iba pri nom.
    """
    obraz = os.path.join(prac, "pamat.img")
    # Par MiB staci: z artefaktu sa beru MENA poli, nie hodnoty. Polovica
    # nulova a polovica nahodna preto, aby zero_ratio aj entropia mali nad cim
    # pocitat a pole entropy_mean naozaj vzniklo.
    polovica = SIDECAR_OBRAZ_MIB * 1024 ** 2 // 2
    with open(obraz, "wb") as fh:
        fh.write(b"\0" * polovica)
        fh.write(os.urandom(polovica))
    vystup = os.path.join(prac, "out")
    spusti([bin_vmicollect(), "once",
            "-o", "vm.backend=file",
            "-o", "vm.image_path=" + obraz,
            "-o", "output.writer=delta",
            "-o", "output.dir=" + vystup])
    najdene = sorted(glob.glob(os.path.join(vystup, "*.json")))
    if not najdene:
        raise Chyba("'vmicollect once' nad obrazom v suboroch nezapisal ziadny sidecar")
    with open(najdene[0], encoding="utf-8") as fh:
        return json.load(fh)


def sidecar():
    """Polia sidecaru z CERSTVEHO sidecaru, nie z ulozeneho artefaktu.

    Ulozeny sidecar je snimka kodu v den merania. Ked sa pole vo
    vmicollect/src/meta.c premenuje, stary subor o tom nevie a prirucka by
    o premenovanom poli mlcala - presne ten tichy rozchod, kvoli ktoremu tento
    generator existuje. Preto sa sidecar vyrobi tu a teraz.
    """
    prac = tempfile.mkdtemp(prefix="gen_prirucka_")
    try:
        doc = _vyrob_sidecar(prac)
    except OSError as exc:
        raise Chyba("sidecar sa nepodarilo vyrobit: %s" % exc)
    finally:
        shutil.rmtree(prac, ignore_errors=True)
    for blok in ("output", "features"):
        if not isinstance(doc.get(blok), dict):
            raise Chyba("cerstvy sidecar nema blok '%s'" % blok)
    riadky = [
        "- `output` — %s" % ", ".join(doc["output"].keys()),
        "- `features` — %s" % ", ".join(doc["features"].keys()),
    ]
    biny = doc["features"].get("bins")
    if not (isinstance(biny, list) and biny and isinstance(biny[0], dict)):
        raise Chyba("cerstvy sidecar nema ani jeden bin v 'features.bins'")
    riadky.append("- jeden bin v `features.bins` — %s" % ", ".join(biny[0].keys()))
    riadky.append(
        "- zdroj: sidecar vyrobený pri generovaní práve preloženou binárkou "
        "(backend `file` nad %d MiB obrazom, writer `delta`), nie uložený artefakt"
        % SIDECAR_OBRAZ_MIB
    )
    return "\n".join(riadky)


# ----------------------------------------------------------- 5. testy


def pocet_testov():
    text = spusti([sys.executable, "-m", "pytest", "--collect-only", "-q"])
    m = re.search(r"(\d+) tests? collected", text)
    if not m:
        raise Chyba("z vystupu 'pytest --collect-only -q' sa necita pocet testov")
    ctesty = sorted(p.stem for p in (REPO / "vmicollect" / "tests").glob("*.c"))
    if not ctesty:
        raise Chyba("vmicollect/tests/ neobsahuje ziadny .c test")
    return "%s v `pytest` a %d v C (%s)" % (
        m.group(1),
        len(ctesty),
        ", ".join("`%s`" % t for t in ctesty),
    )


# ------------------------------------------------------- 6. namerane cisla
#
# Kazdy riadok tabulky je funkcia nad nacitanym artefaktom. Ked sa kluc v JSON
# premenuje alebo artefakt zmizne, riadok skonci ako NEZISTENE - cislo sa
# nedosadi z pamate.
#
# Aby to platilo aj pre riadky, ktore citaju kluc priamo cez d["kluc"], vedie
# kazde citanie cez _artefakt(): KeyError zvonku vyzeral ako traceback a rc=1,
# hoci tento subor sluboval NEZISTENE. Sluby o vlastnom spravani su tvrdenia
# ako kazde ine a musia platit.

ZMRAZENY = "2026-09-18_zmrazeny_host/summary.json"
ENV = "2026-09-18_zmrazeny_host/env.json"
PROBE = "2026-09-18_zmrazeny_host/probe.json"
RUN5 = "2026-09-18_zmrazeny_host/run_delta_5s.json"
LATENCIA = "latency_vector_20260918.json"
PERBIN = "perbin_c_20260918/perbin_c_20260918.json"
KRIZ = "perbin_crosscheck_20260918.json"
OPTIM = "optim_hash_20260918.json"


def _rozsah(doc, cesta, zdroj, jednotka="ms", des=1):
    blok = kluc(doc, cesta, zdroj)
    for k in ("median", "min", "max", "n"):
        if k not in blok:
            raise Chyba("v %s:%s chyba %s" % (zdroj, cesta, k))
    return (
        "medián %s %s (%s–%s)"
        % (
            cislo(blok["median"], des),
            jednotka,
            cislo(blok["min"], des),
            cislo(blok["max"], des),
        ),
        blok["n"],
    )


def r_domena(d):
    v = kluc(d, "values.probe", ZMRAZENY)
    return (
        "%d memslotov, %s GiB RAM, %d vCPU"
        % (v["memslots"], cislo(v["ram_bytes"] / 1024 ** 3, 2), v["vcpus"]),
        1,
    )


def r_plna(d):
    v = kluc(d, "values.run_delta_perioda_5s.plna_snimka_cyklus_0", ZMRAZENY)
    return (
        "čítanie %s ms, zápis %s ms, spolu %s ms; %s z %s stránok"
        % (
            cislo(v["capture_ms"]),
            cislo(v["write_ms"]),
            cislo(v["total_ms"]),
            cislo(v["pages_changed"], 0),
            cislo(v["pages_total"], 0),
        ),
        1,
    )


def r_prirastok(d):
    """Podmnozina prirastkovych cyklov behu: iba tie, pocas ktorych v hostovi
    nebola prihlasovacia relacia. Kriterium vyberu patri do tabulky, inak je to
    tichy vyber dat."""
    cesta = "values.run_delta_perioda_5s.prirastkove_snimky_bez_sedenia_ssh"
    text, n = _rozsah(d, cesta + ".pages_changed", ZMRAZENY, "stránok", 0)
    podiel = kluc(d, cesta + ".changed_ratio.median", ZMRAZENY)
    vsetkych = kluc(
        d,
        "values.run_delta_perioda_5s.prirastkove_snimky_vsetky.total_ms.n",
        ZMRAZENY,
    )
    return (
        "%s zmenených, teda %s pamäte; %d z %d prírastkových cyklov behu — tie, "
        "počas ktorých v hosťovi nebola prihlasovacia relácia"
        % (text, cislo(podiel * 100, 4) + " %", n, vsetkych),
        n,
    )


def r_beh(d):
    """n = 1: je to jeden beh, nie priemer z viacerych. Pocet cyklov je hodnota,
    nie pocet meraní."""
    v = kluc(d, "summary", RUN5)
    return (
        "%d cyklov, %d chýb, %d zmeškaných slotov, najväčšie meškanie %s s"
        % (
            v["cycles_done"],
            v["cycles_failed"],
            v["cycles_skipped"],
            cislo(v["worst_lateness_s"], 1),
        ),
        1,
    )


def _latencia(d, skupina):
    blok = kluc(d, ["values", "suhrn", skupina, "latencia_ms"], LATENCIA)
    return (
        "medián %s ms, p95 %s ms" % (cislo(blok["median"]), cislo(blok["p95"])),
        blok["n"],
    )


def r_lat_on(d):
    return _latencia(d, "on_2.0s_delta")


def r_lat_off(d):
    return _latencia(d, "off_2.0s_delta")


def r_cena(d):
    c = kluc(d, "values.cena", PERBIN)
    return (
        "prírastková snímka +%s ms (%s %%), plná +%s ms (%s %%)"
        % (
            cislo(c["delta_cyklus_median_ms"]["rozdiel_on_minus_off_ms"]),
            cislo(c["delta_cyklus_median_ms"]["rozdiel_on_minus_off_pct"]),
            cislo(c["plna_snimka_ms"]["rozdiel_on_minus_off_ms"]),
            cislo(c["plna_snimka_ms"]["rozdiel_on_minus_off_pct"]),
        ),
        kluc(d, "n", PERBIN),
    )


def r_entropia(d):
    us = kluc(d, "values.cena.entropia_us_na_zmenenu_stranku", PERBIN)
    return "%s µs na zmenenú stránku navyše" % cislo(us, 3), kluc(d, "n", PERBIN)


def r_kriz(d):
    v = kluc(d, "values", KRIZ)
    if not (v.get("vsetky_invarianty_ok") and v.get("vsetky_porovnania_ok")):
        raise Chyba("krizova kontrola v %s hlasi nezhodu" % KRIZ)
    biny = kluc(d, "values.snimky.0.bins_total", KRIZ)
    return (
        "%d z %d snímok sedí, %d binov na snímku, žiadny rozdiel"
        % (v["snimok_s_vystupom_c"], v["snimok"], biny),
        v["snimok"],
    )


def r_validacia(d):
    p = kluc(d, "values.validacia_voci_pozemnej_prave.procesy", ZMRAZENY)
    m = kluc(d, "values.validacia_voci_pozemnej_prave.moduly", ZMRAZENY)
    s = kluc(d, "values.validacia_voci_pozemnej_prave.sokety_voci_ss_tulpn", ZMRAZENY)
    return (
        "procesy %d z %d stabilných (v `ps` ich bolo %d), moduly %d z %d, "
        "počúvajúce sokety %d z %d a %d navyše"
        % (
            p["found"], p["stable"], p["ps_before"],
            m["matched"], m["ground_truth"],
            s["matched"], s["ground_truth"], s["extra"],
        ),
        1,
    )


def r_sha(d):
    v = kluc(d, "values.sha256_priepustnost_mib_s", OPTIM)
    return (
        "%s MiB/s s inštrukciami SHA-NI, %s MiB/s bez nich"
        % (cislo(v["shani_median"]), cislo(v["skalar_median"])),
        len(v["shani"]),
    )


# (popis riadku, artefakt v data/results/, funkcia, ktora z neho vytiahne
# hodnotu a n). Nazov artefaktu v tabulke sa neopisuje rukou - berie sa odtialto,
# takze premenovany subor sa v prirucke prejavi hned.
CISLA = [
    ("Doména, na ktorej sa meralo", ZMRAZENY, r_domena),
    ("Plná snímka (cyklus #0, delta writer)", ZMRAZENY, r_plna),
    ("Prírastková snímka, nečinná VM", ZMRAZENY, r_prirastok),
    ("Beh s periódou 5 s", RUN5, r_beh),
    ("Latencia snímka → vektor, perióda 2 s, príznaky zapnuté", LATENCIA, r_lat_on),
    ("To isté s vypnutými príznakmi", LATENCIA, r_lat_off),
    ("Cena príznakov v cykle", PERBIN, r_cena),
    ("Z toho entropia", PERBIN, r_entropia),
    ("Vektor z C proti Python referencii", KRIZ, r_kriz),
    ("Rekonštrukcia proti pozemnej pravde v hosťovi", ZMRAZENY, r_validacia),
    ("SHA-256 nad pamäťou (mikrobenchmark)", OPTIM, r_sha),
]


def _artefakt(subor, fn):
    """Spusti fn nad nacitanym artefaktom a premeni chybajuci kluc na Chybu.

    Meno suboru aj meno kluca musia byt v hlaske: bez nich by 'NEZISTENE'
    poslalo citatela hladat do prazdna."""
    doc = nacitaj_json(subor)
    try:
        return fn(doc)
    except Chyba:
        raise
    except KeyError as exc:
        raise Chyba("v data/results/%s chyba kluc %s" % (subor, exc))
    except (IndexError, TypeError, ValueError) as exc:
        raise Chyba("data/results/%s ma iny tvar, nez riadok caka: %s: %s"
                    % (subor, type(exc).__name__, exc))


def namerane_cisla(fakty):
    riadky = []
    for popis, subor, fn in CISLA:
        def uloha(subor=subor, fn=fn):
            return _artefakt(subor, fn)
        vysledok = fakty(popis, uloha)
        if isinstance(vysledok, tuple):
            hodnota, n = vysledok
        else:
            hodnota, n = vysledok, "?"
        riadky.append(
            "| %s | %s | %s | `data/results/%s` |" % (popis, hodnota, n, subor)
        )
    return "\n".join(riadky)


def _datumy():
    datumy = set()
    for subor in sorted({s for _, s, _ in CISLA} | {ENV}):
        doc = nacitaj_json(subor)
        if "date" not in doc:
            raise Chyba("v data/results/%s chyba kluc date" % subor)
        datumy.add(str(doc["date"])[:10])
    return sorted(datumy)


def datumy_merani():
    return ", ".join(_datumy())


def datum_stavu():
    """Datum najnovsieho pouziteho artefaktu. Nie datum behu generatora: ten by
    sa menil pri kazdom spusteni a kontrola aktualnosti by bola trvale cervena."""
    return _datumy()[-1]


# ------------------------------------------------------------ 7. commity


def commity_merani():
    """Priznak 'dirty' patri konkretnemu artefaktu, nie commitu: dva artefakty
    z toho isteho commitu sa v nom lisia a kluc commit_dirty nemusi mat ani
    jeden z nich. Preto sa pise za nazov suboru, ktory ho ma."""
    pouzitie = {}
    for _, subor, _ in CISLA:
        doc = nacitaj_json(subor)
        if "commit" not in doc:
            raise Chyba("v data/results/%s chyba kluc commit" % subor)
        pouzitie.setdefault(doc["commit"], {})[subor] = bool(
            doc.get("commit_dirty")
        )
    riadky = []
    for sha in sorted(pouzitie, key=lambda s: sorted(pouzitie[s])):
        popis = spusti(["git", "log", "--oneline", "-1", sha]).strip()
        if not popis:
            raise Chyba("commit %s nie je v repozitari" % sha[:7])
        zdroje = ", ".join(
            "%s%s" % (subor, " *" if pouzitie[sha][subor] else "")
            for subor in sorted(pouzitie[sha])
        )
        riadky.append("- `%s` — %s" % (popis, zdroje))
    if any(any(v.values()) for v in pouzitie.values()):
        riadky.append(
            "- `*` — binárka, ktorá merala, nezodpovedá presne tomuto commitu: "
            "pracovný strom mal v čase merania neuložené zmeny"
        )
    return "\n".join(riadky)


# --------------------------------------------------------- 8. prostredie


def prostredie_merani():
    """Prostredie, na ktorom merania NAOZAJ bezali - z artefaktu, nie zo stroja,
    na ktorom prave bezi generator. Zive verzie by po upgrade hostitela tvrdili,
    ze merania spred mesiacov bezali na novom jadre."""
    d = nacitaj_json(ENV)
    h = kluc(d, "values.hostitel", ENV)
    g = kluc(d, "values.host_guest", ENV)
    for k in ("os", "kernel", "qemu", "libvirt"):
        if k not in h:
            raise Chyba("v data/results/%s chyba values.hostitel.%s" % (ENV, k))
    for k in ("os", "debian_version", "kernel", "vcpu"):
        if k not in g:
            raise Chyba("v data/results/%s chyba values.host_guest.%s" % (ENV, k))
    return (
        "- hostiteľ: %s, jadro `%s`, %s, libvirt %s;\n"
        "- hosť: %s, verzia %s, jadro `%s`, %d vCPU."
        % (h["os"], h["kernel"], h["qemu"], h["libvirt"],
           g["os"], g["debian_version"], g["kernel"], g["vcpu"])
    )


# ------------------------------------------------------------ 9. dokumenty

DOKUMENTY = [
    ("docs/ARCHITEKTURA.md", "rozhrania, formát `.vmicd` a sidecaru, tok dát podrobne"),
    ("docs/MERANIA.md", "log meraní: čo, kedy, akým príkazom a s akým výsledkom"),
    ("docs/LIMITACIE.md", None),   # popis sa dopocita: rozsah L1..Ln
    ("docs/kontroly.md", "kontroly podozrivých vzorcov a validačný príkaz"),
    ("HONESTY.md", "pravidlá pre čísla a slová v texte práce"),
    ("README.md", "rozcestník repozitára a pôvod prevzatého kódu"),
    ("vmicollect/README.md", "zberač zvnútra: vrstvy, hooky, formáty"),
    ("guestparse/README.md", "parser zvnútra: preklad adries, prechod zoznamami"),
    ("features/PERBIN.md", "definícia príznakov a ich kontrakt"),
]


def dokumenty():
    riadky = []
    for cesta, popis in DOKUMENTY:
        if popis is None:
            popis = "%s: čo systém nevie a čo z toho plynie pre text" % limitacie_rozsah()
        p = REPO / cesta
        if not p.is_file():
            raise Chyba("dokument %s neexistuje" % cesta)
        with p.open("rb") as fh:
            n = fh.read().count(b"\n")
        riadky.append("| `%s` | %s | %d |" % (cesta, popis, n))
    return "\n".join(riadky)


# --------------------------------------------------- 10. kontrola ciest v texte
#
# Proza sa z kodu generovat neda. Da sa z neho overit aspon to, ze kazda cesta,
# ktoru proza cituje, existuje - premenovany subor je najcastejsi tichy rozchod
# dokumentacie s kodom.

_BACKTICK = re.compile(r"`([^`\n]+)`")


def _je_cesta(token):
    if "/" not in token or "://" in token:
        return False
    # Prepinac s dvoma tvarmi ('-d/--domain') ma lomitko, ale cesta to nie je.
    if token.startswith("-"):
        return False
    return not any(z in token for z in "<>{}|*$")


def _kandidati(text):
    """Cesty v spatnych apostrofoch a v blokoch prikazov. Z viacslovneho zapisu
    ('scripts/root_run.sh probe') sa berie prve slovo."""
    tokeny = []
    for span in _BACKTICK.findall(text):
        slova = span.split()
        if slova:
            tokeny.append(slova[0])
    v_bloku = False
    for riadok in text.splitlines():
        if riadok.startswith("```"):
            v_bloku = not v_bloku
            continue
        if v_bloku:
            tokeny.extend(riadok.split())
    cisto = []
    for t in tokeny:
        t = t.strip("`\"'").rstrip(".,;:)")
        if _je_cesta(t):
            cisto.append(t)
    return sorted(set(cisto))


def chybajuce_cesty(text):
    return [t for t in _kandidati(text) if not (REPO / t).exists()]


# ------------------------------------------------------------- generovanie


def main():
    ap = argparse.ArgumentParser(
        description="vyrobi docs/PRIRUCKA.md zo sablony docs/PRIRUCKA.sk.md"
    )
    ap.add_argument("--out", default=str(VYSTUP), help="kam zapisat (vychodzie: %s)" % VYSTUP)
    ap.add_argument("--sablona", default=str(SABLONA))
    args = ap.parse_args()

    if not os.path.isfile(args.sablona):
        print("gen_prirucka.py: sablona %s neexistuje" % args.sablona, file=sys.stderr)
        return 4

    chyby = []

    def fakty(znacka, fn):
        # Zachytava sa aj KeyError/IndexError/TypeError/ValueError: subor, ktory
        # o sebe tvrdi, ze nezisteny fakt oznaci a skonci kodom 2, nesmie skoncit
        # tracebackom a kodom 1. Presnu hlasku (subor a kluc) dava _artefakt();
        # toto je posledna zachrana pre zvysok.
        try:
            return fn()
        except Chyba as exc:
            chyby.append((znacka, str(exc)))
            return "**NEZISTENE (%s)**" % exc
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            dovod = "necakany tvar udaju: %s: %s" % (type(exc).__name__, exc)
            chyby.append((znacka, dovod))
            return "**NEZISTENE (%s)**" % dovod

    hodnoty = {
        "STROM": lambda: fakty("STROM", strom),
        "PRIKAZY_VMIC": lambda: fakty("PRIKAZY_VMIC", prikazy_vmicollect),
        "PREPINACE_VMIC": lambda: fakty("PREPINACE_VMIC", prepinace_vmicollect),
        "PODPRIKAZY_GUESTPARSE": lambda: fakty(
            "PODPRIKAZY_GUESTPARSE", lambda: podprikazy_balika("guestparse")),
        "PODPRIKAZY_FEATURES": lambda: fakty(
            "PODPRIKAZY_FEATURES", lambda: podprikazy_balika("features")),
        "KONFIG": lambda: fakty("KONFIG", konfiguracne_kluce),
        "VYCHODZIE": lambda: fakty("VYCHODZIE", vychodzie_zhrnutie),
        "BIN": lambda: fakty("BIN", bin_velkost),
        "FULL_EVERY": lambda: fakty(
            "FULL_EVERY", lambda: vychodzia("output.delta_full_every")),
        "SIDECAR_KLUC": lambda: fakty(
            "SIDECAR_KLUC", lambda: vychodzia("output.sidecar")),
        "SIDECAR": lambda: fakty("SIDECAR", sidecar),
        "TESTY": lambda: fakty("TESTY", pocet_testov),
        "SELFTEST_OBRAZ": lambda: fakty("SELFTEST_OBRAZ", selftest_obraz),
        "PROFIL": lambda: fakty("PROFIL", profil_adresar),
        "LIBBPF": lambda: fakty("LIBBPF", hlaska_libbpf),
        "LIMITACIE": lambda: fakty("LIMITACIE", limitacie_rozsah),
        "LIMITACIE_NADPISY": lambda: fakty("LIMITACIE_NADPISY", limitacie_nadpisy),
        "CISLA": lambda: namerane_cisla(fakty),
        "DATUMY": lambda: fakty("DATUMY", datumy_merani),
        "DATUM_STAVU": lambda: fakty("DATUM_STAVU", datum_stavu),
        "COMMITY": lambda: fakty("COMMITY", commity_merani),
        "PROSTREDIE_MERANI": lambda: fakty("PROSTREDIE_MERANI", prostredie_merani),
        "DOKUMENTY": lambda: fakty("DOKUMENTY", dokumenty),
    }

    with open(args.sablona, encoding="utf-8") as fh:
        sablona = fh.read()

    # Poznamka pre toho, kto edituje sablonu, do vysledku nepatri.
    sablona = re.sub(r"\A<!--\s*SABLONA:.*?-->\s*", "", sablona, flags=re.S)

    znacky = set(re.findall(r"@@([A-Z_]+)@@", sablona))
    neznamo = znacky - set(hodnoty)
    if neznamo:
        print("gen_prirucka.py: sablona ma neznamu znacku: %s"
              % ", ".join(sorted(neznamo)), file=sys.stderr)
        return 4
    nepouzite = set(hodnoty) - znacky
    if nepouzite:
        print("gen_prirucka.py: znacka sa v sablone nepouziva: %s"
              % ", ".join(sorted(nepouzite)), file=sys.stderr)
        return 4

    text = sablona
    for meno in sorted(znacky):
        text = text.replace("@@%s@@" % meno, str(hodnoty[meno]()))

    riadkov = text.count("\n")
    if riadkov > LIMIT_RIADKOV:
        print(
            "gen_prirucka.py: prirucka ma %d riadkov, limit je %d. "
            "Skrat text v sablone alebo presun cast do docs/ARCHITEKTURA.md."
            % (riadkov, LIMIT_RIADKOV),
            file=sys.stderr,
        )
        return 3

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)

    # Obidve kontroly sa vypisu vzdy. Skoreho 'return 2' by o chybajucich
    # cestach mlcal, takze pri sucasnom vyskyte by sa o nich citatel dozvedel
    # az po oprave nieceho ineho.
    if chyby:
        print("gen_prirucka.py: %d faktov sa nezistilo, v subore su znacky NEZISTENE:"
              % len(chyby), file=sys.stderr)
        for znacka, dovod in chyby:
            print("  %s: %s" % (znacka, dovod), file=sys.stderr)

    zle = chybajuce_cesty(text)
    if zle:
        print("gen_prirucka.py: text odkazuje na cesty, ktore neexistuju:",
              file=sys.stderr)
        for t in zle:
            print("  %s" % t, file=sys.stderr)

    if chyby:
        return 2
    if zle:
        return 5

    print("gen_prirucka.py: %s, %d riadkov (limit %d)" % (args.out, riadkov, LIMIT_RIADKOV))
    return 0


if __name__ == "__main__":
    sys.exit(main())
