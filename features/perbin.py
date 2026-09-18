"""
perbin.py - nezavisla referencia per-bin priznakoveho vektora.

PRECO EXISTUJE
--------------
Ten isty vektor pocita aj C modul (vmicollect, delta writer + sidecar). Ked to
iste cislo vyrobia dve nezavisle implementacie, je to dokaz, ze vzorec je
spravne zapisany. Ked sa rozidu, jedna z nich je zla a vie sa to hned - nie az
po tom, co sa na tom natrenuje model. Tento modul teda zamerne NEPOUZIVA nic z
vmicollect/: snimku cita cez guestparse.image, rozsahy memslotov dostava zvonku
a vsetko ostatne si pocita sam.

KONTRAKT PRIZNAKU (dohodnuty, nemeni sa bez dohody)
---------------------------------------------------
Binuje sa IBA nad rozsahmi z memslotov. Bin, ktory neprotina ziadny memslot,
NEEXISTUJE - nevznika ako nulovy riadok. Dovod: fyzicky priestor x86 je deravy
(VGA diera 0xA0000-0xBFFFF, PCI diera pod 4 GiB). Pri tejto VM je RAM 2,02 GiB,
ale max_paddr 4 GiB, takze pri bine 16 MiB by z 256 binov bolo 125 trvale
nulovych a model by sa ucil na vypln.

Index binu = GPA >> log2(bin_bytes). Index je viazany na fyzicku adresu, nie na
poradie memslotu - zostava rovnaky medzi snimkami aj ked sa pocet memslotov
zmeni.

Na kazdy bin:
    bin            index binu
    gpa            zaciatocna fyzicka adresa binu
    pages_total    kolko stranok binu je naozaj podlozenych memslotmi
    pages_changed  kolko stranok sa od predchadzajucej snimky zmenilo
    changed_ratio  pages_changed / pages_total
    zero_ratio     podiel NULOVYCH stranok zo vsetkych podlozenych stranok binu
    entropy_mean   priemerna Shannonova entropia (bity na bajt, 0..8)
                   ZMENENYCH stranok
    has_changed    0/1 - samostatny priznak, aby sa "bin sa nezmenil" dalo
                   odlisit od "entropia vysla 0". Ticho doplnena nula je
                   zakazana.

CO JE "ZMENENA" A CO "NULOVA" STRANKA
--------------------------------------
Zmenena stranka = stranka zapisana v .vmicd suboru TEJTO snimky. Delta writer
zapisuje presne tie stranky, ktorych 64-bitovy hash sa lisi od predchadzajuceho
cyklu (vmicollect/src/writer_delta.c). Pri plnej snimke je predchadzajuci stav
nulovy, takze "zmenene" = vsetky nenulove stranky.

Nulova stranka sa berie z REKONSTRUOVANEHO stavu pamate v case tejto snimky,
teda z celeho retazca po nu vratane - nie iba z tejto jednej delty. Stranka,
ktora v retazci nie je, je nulova (rovnako to definuje guestparse.image aj
vmic_delta_restore). Referencia to overuje porovnanim obsahu, nie hashom:
hash nulovej stranky je v C zastupca pre "nulova", tu je to priame porovnanie
so 4096 nulami. Ked by sa cisla rozisli prave tu, je to kolizia hashu a treba
to vidiet, nie zakryt.

ROZSAHY MEMSLOTOV SA NEHADAJU
------------------------------
V hlavicke .vmicd je iba logicka velkost (koniec poslednej oblasti) a
region_sig, co je 64-bitovy podpis konfiguracie oblasti - z podpisu sa rozsahy
spatne odvodit nedaju. Sidecar snimky ma dnes v "capture.regions" KONFIGURACIU
zberu ([capture].regions), nie memsloty, a pri zbere celej RAM je to prazdne
pole. Referencia preto rozsahy pozaduje zvonku a bez nich odmietne pocitat.
Prijate zdroje su v load_memslots(); pouzity zdroj sa vzdy zapise do vystupu
(kluc "memslots.source"), aby v reporte nebolo skryte, odkial cisla su.

Zavisi od stdlib a od balika guestparse. numpy sa pouzije, ak je - iba na
histogram bajtov; entropia sa pocita v oboch vetvach tym istym kodom z tych
istych celociselnych poctov, takze vysledok je bit po bite rovnaky (overuje
test test_entropia_obe_vetvy_rovnako).
"""

import bisect
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guestparse.image import PAGE, VmicdImage, chain_headers  # noqa: E402

SCHEMA = "hyptcn3/perbin/1"
DEFAULT_BIN_BYTES = 16 * 1024 * 1024

ZERO_PAGE = b"\0" * PAGE

try:
    import numpy as _np
except Exception:          # numpy nie je povinna zavislost
    _np = None


class FeatureError(ValueError):
    """Vektor sa neda spocitat tak, aby sa vysledku dalo verit."""


# --------------------------------------------------------------- memsloty


class Memslots:
    """
    Rozsahy fyzickej pamate, ktore su naozaj podlozene (memsloty KVM).

    Drzi ich ako polostvorene rozsahy STRANOK [first, end), lebo vsetky
    dalsie vypocty su po strankach a prepocet z bajtov na kazdom mieste
    znova by bol len dalsia prilezitost pomylit sa o jednu.
    """

    def __init__(self, ranges, source):
        norm = []
        for i, (start, size) in enumerate(ranges):
            if size <= 0:
                raise FeatureError("memslot %d ma velkost %d" % (i, size))
            if start % PAGE or size % PAGE:
                # Nezarovnany memslot by znamenal, ze stranka lezi ciastocne
                # v slote a ciastocne mimo neho; "podlozena stranka" by potom
                # nemala jednoznacny vyznam.
                raise FeatureError(
                    "memslot %d (0x%x+0x%x) nie je zarovnany na %d B"
                    % (i, start, size, PAGE))
            norm.append((start // PAGE, (start + size) // PAGE))
        norm.sort()
        for i in range(1, len(norm)):
            if norm[i][0] < norm[i - 1][1]:
                raise FeatureError(
                    "memsloty sa prekryvaju: stranky [%d,%d) a [%d,%d)"
                    % (norm[i - 1][0], norm[i - 1][1], norm[i][0], norm[i][1]))
        self.ranges = norm
        self.source = source
        self.starts = [r[0] for r in norm]
        self.pages_total = sum(e - s for s, e in norm)

    def contains(self, page):
        """Je stranka s tymto indexom podlozena memslotom?"""
        i = bisect.bisect_right(self.starts, page) - 1
        if i < 0:
            return False
        return page < self.ranges[i][1]

    def bin_pages(self, bin_bytes):
        """
        {index binu: pocet podlozenych stranok}. Biny bez jedinej podlozenej
        stranky v slovniku nie su - to je cely zmysel kontraktu.
        """
        shift = _shift(bin_bytes)
        per_bin = {}
        for first, end in self.ranges:
            b = (first * PAGE) >> shift
            last_bin = ((end * PAGE) - 1) >> shift
            while b <= last_bin:
                lo = max(first, (b << shift) // PAGE)
                hi = min(end, ((b + 1) << shift) // PAGE)
                if hi > lo:
                    per_bin[b] = per_bin.get(b, 0) + (hi - lo)
                b += 1
        return per_bin

    def as_json(self):
        return {
            "source": self.source,
            "count": len(self.ranges),
            "pages_total": self.pages_total,
            "bytes_total": self.pages_total * PAGE,
            "ranges": [{"gpa": s * PAGE, "size": (e - s) * PAGE}
                       for s, e in self.ranges],
        }


def _shift(bin_bytes):
    """log2(bin_bytes) s kontrolou, ze index binu ma vobec zmysel."""
    if bin_bytes <= 0 or bin_bytes & (bin_bytes - 1):
        # Index binu je definovany posunom GPA >> log2(bin_bytes). Pri
        # velkosti, ktora nie je mocninou dvojky, taky posun neexistuje a
        # delenie by dalo iny rozklad nez v C - teda tichy rozdiel.
        raise FeatureError("bin_bytes musi byt mocnina dvojky, dostal som %d"
                           % bin_bytes)
    if bin_bytes % PAGE:
        raise FeatureError("bin_bytes musi byt nasobok %d B, dostal som %d"
                           % (PAGE, bin_bytes))
    return bin_bytes.bit_length() - 1


def _slots_from_doc(doc, path):
    """
    Vytiahne rozsahy memslotov z uz nacitaneho JSON dokumentu.

    Poznane tvary, v poradi ako sa skusaju:
      1. values.memslot_ranges  - vystup `vmicollect probe -v` (gpa_start,
         size_bytes); toto je dnes JEDINY zdroj, ktory skutocne memsloty ma
      2. features.memslots      - miesto, kam ich ma zapisat C modul (K13);
         podporovane dopredu, aby sa referencia nemusela menit
      3. memslots               - holy zoznam (rucne pripraveny subor)
      4. capture.regions        - konfiguracia zberu zo sidecaru. NIE su to
         memsloty; berie sa iba ked je neprazdna, a zdroj sa pomenuje tak,
         aby v reporte bolo vidiet, co sa naozaj pouzilo
    """
    def pairs(items, kstart, ksize, kend=None):
        out = []
        for it in items:
            start = it[kstart]
            if ksize in it:
                size = it[ksize]
            elif kend is not None and kend in it:
                size = it[kend] - start + 1
            else:
                raise FeatureError("%s: polozka memslotu nema velkost: %r"
                                   % (path, it))
            out.append((int(start), int(size)))
        return out

    vals = doc.get("values") if isinstance(doc.get("values"), dict) else {}
    if isinstance(vals.get("memslot_ranges"), list) and vals["memslot_ranges"]:
        return (pairs(vals["memslot_ranges"], "gpa_start", "size_bytes",
                      "gpa_end"),
                "%s:values.memslot_ranges" % os.path.basename(path))

    feats = doc.get("features") if isinstance(doc.get("features"), dict) else {}
    if isinstance(feats.get("memslots"), list) and feats["memslots"]:
        return (pairs(feats["memslots"], "gpa", "size"),
                "%s:features.memslots" % os.path.basename(path))

    if isinstance(doc.get("memslots"), list) and doc["memslots"]:
        it = doc["memslots"][0]
        key = "gpa" if "gpa" in it else "start"
        return (pairs(doc["memslots"], key, "size"),
                "%s:memslots" % os.path.basename(path))

    cap = doc.get("capture") if isinstance(doc.get("capture"), dict) else {}
    if isinstance(cap.get("regions"), list) and cap["regions"]:
        return (pairs(cap["regions"], "start", "size"),
                "%s:capture.regions (konfiguracia zberu, nie memsloty)"
                % os.path.basename(path))

    return None, None


def load_memslots(path):
    """Nacita rozsahy memslotov zo suboru JSON. Nic nehada."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    ranges, source = _slots_from_doc(doc, path)
    if not ranges:
        raise FeatureError(
            "%s: nie su v nom rozsahy memslotov. Cakane kluce: "
            "values.memslot_ranges (vystup 'vmicollect probe -v'), "
            "features.memslots (sidecar z C modulu), memslots, alebo "
            "neprazdne capture.regions." % path)
    return Memslots(ranges, source)


# --------------------------------------------------------------- entropia


def entropy_from_counts(counts, total):
    """
    Shannonova entropia v bitoch na bajt (0..8) z histogramu 256 poctov.

    Pocita sa z celociselnych poctov a v pevnom poradi indexov 0..255, aby
    rychla (numpy) a zalozna (stdlib) vetva davali rovnaky float - inak by
    krizova kontrola hlasila rozdiel, ktory nie je v snimke, ale v scitani.
    """
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def _hist(page):
    if _np is not None:
        return _np.bincount(_np.frombuffer(page, dtype=_np.uint8),
                            minlength=256).tolist()
    counts = [0] * 256
    for b in page:
        counts[b] += 1
    return counts


def page_entropy(page):
    """Entropia jednej stranky (bity na bajt)."""
    return entropy_from_counts(_hist(page), len(page))


# ----------------------------------------------------------- citanie snimky


def _chain_parts(snapshot, chain_id=None, until_seq=None):
    """Cesty jedneho overeneho retazca .vmicd, v poradi seq."""
    if os.path.isdir(snapshot):
        heads = chain_headers(snapshot, chain_id, until_seq, warn=False)
    else:
        heads = [VmicdImage.header(snapshot)]
        if not heads[0]["full"]:
            raise FeatureError(
                "%s je delta bez baseline - bez predchadzajucich casti sa "
                "stav pamate zrekonstruovat neda. Zadaj adresar s retazcom."
                % snapshot)
    return heads


def _record_indices(header):
    """
    Indexy stranok zapisanych v JEDNOM subore .vmicd = mnozina ZMENENYCH
    stranok tejto snimky. Cita sa iba 8 B index kazdeho zaznamu, obsah sa
    nekopiruje.
    """
    psz = header["page_size"]
    out = set()
    with open(header["path"], "rb") as f:
        off = 64
        for _ in range(header["records"]):
            f.seek(off)
            raw = f.read(8)
            if len(raw) != 8:
                raise FeatureError("%s: subor konci uprostred zaznamov"
                                   % header["path"])
            out.add(int.from_bytes(raw, "little"))
            off += 8 + psz
    return out


# ------------------------------------------------------------- hlavny vypocet


def per_bin(snapshot, memslots, bin_bytes=DEFAULT_BIN_BYTES,
            chain_id=None, until_seq=None):
    """
    Spocita per-bin vektor pre stav pamate po poslednej casti retazca.

    Vracia slovnik s blokom "features" v tvare kontraktu plus blok "kontrola"
    s invariantmi (sucty), aby sa dali overit bez dalsieho prechodu.
    """
    shift = _shift(bin_bytes)
    heads = _chain_parts(snapshot, chain_id, until_seq)
    last = heads[-1]
    if last["page_size"] != PAGE:
        raise FeatureError(
            "snimka ma stranku %d B; referencia pocita s %d B - prepocet by "
            "zmenil vyznam vsetkych poctov" % (last["page_size"], PAGE))

    changed = _record_indices(last)
    per_bin_total = memslots.bin_pages(bin_bytes)

    nonzero = {}
    chg = {}
    ent_sum = {}
    mimo = {"changed": 0, "state": 0, "priklady": []}

    img = VmicdImage([h["path"] for h in heads], validate=True)
    try:
        # Prechadza sa REKONSTRUOVANY stav: index retazca po zlucenych
        # castiach. Stranka, ktora v nom nie je, je nulova a nezmenena,
        # takze do nonzero ani chg neprispieva a staci ju nepocitat.
        for idx, (fpath, foff) in img.index.items():
            if not memslots.contains(idx):
                # Stranka mimo memslotov by znamenala, ze zoznam rozsahov
                # nepatri k tejto snimke. Nezahadzuje sa ticho - pocita sa
                # a hlasi v kontrole.
                mimo["state"] += 1
                if idx in changed:
                    mimo["changed"] += 1
                if len(mimo["priklady"]) < 8:
                    mimo["priklady"].append(idx)
                continue
            fh = img.files[fpath]
            fh.seek(foff)
            page = fh.read(PAGE)
            b = (idx * PAGE) >> shift
            if page != ZERO_PAGE:
                nonzero[b] = nonzero.get(b, 0) + 1
            if idx in changed:
                chg[b] = chg.get(b, 0) + 1
                ent_sum[b] = ent_sum.get(b, 0.0) + page_entropy(page)
    finally:
        img.close()

    bins = []
    for b in sorted(per_bin_total):
        total = per_bin_total[b]
        c = chg.get(b, 0)
        zero_pages = total - nonzero.get(b, 0)
        bins.append({
            "bin": b,
            "gpa": b << shift,
            "pages_total": total,
            "pages_changed": c,
            "changed_ratio": c / total,
            "zero_ratio": zero_pages / total,
            # Bin bez zmenenej stranky nema z coho priemerovat. Nula tu nie
            # je nameranou entropiou - rozlisuje ju has_changed.
            "entropy_mean": (ent_sum.get(b, 0.0) / c) if c else 0.0,
            "has_changed": 1 if c else 0,
        })

    features = {
        "schema": SCHEMA,
        "bin_bytes": bin_bytes,
        "bins_total": len(bins),
        "bins": bins,
    }
    return {
        "features": features,
        "snapshot": {
            "parts": [os.path.basename(h["path"]) for h in heads],
            "chain_id": last["chain_id"],
            "seq": last["seq"],
            "full": last["full"],
            "records": last["records"],
            "page_size": last["page_size"],
            "memsize_logical": last["memsize"],
            "region_sig": last["region_sig"],
        },
        "memslots": memslots.as_json(),
        "kontrola": {
            "pages_changed_sucet": sum(x["pages_changed"] for x in bins),
            "pages_total_sucet": sum(x["pages_total"] for x in bins),
            "zaznamov_v_poslednej_casti": last["records"],
            "stranok_mimo_memslotov_v_stave": mimo["state"],
            "stranok_mimo_memslotov_zmenenych": mimo["changed"],
            "priklady_stranok_mimo": mimo["priklady"],
        },
    }


def check_against_sidecar(result, sidecar_path):
    """
    Porovna sucty s cislami, ktore o tej istej snimke napisal zberac.

    Toto je invariant zo zadania kroku: sucet pages_changed cez biny sa musi
    rovnat output.pages_changed zo sidecaru a sucet pages_total poctu
    podlozenych stranok VM (output.pages_total).
    """
    with open(sidecar_path, encoding="utf-8") as fh:
        side = json.load(fh)
    out = side.get("output")
    if side.get("schema") != "vmicollect/1" or not isinstance(out, dict):
        # Vedla .vmicd moze lezat aj iny .json (napr. manifest testovacej
        # snimky). Porovnavat s nim by znamenalo vymysliet si cisla zberaca.
        return {
            "sidecar": os.path.basename(sidecar_path),
            "zhoda": None,
            "pozn": ("subor nie je sidecar zberaca (schema '%s', ocakavana "
                     "'vmicollect/1'), invariant sa proti nemu overit neda"
                     % side.get("schema")),
        }
    k = result["kontrola"]
    rep = {
        "sidecar": os.path.basename(sidecar_path),
        "pages_changed_sidecar": out.get("pages_changed"),
        "pages_changed_referencia": k["pages_changed_sucet"],
        "pages_total_sidecar": out.get("pages_total"),
        "pages_total_referencia": k["pages_total_sucet"],
    }
    rep["pages_changed_zhoda"] = (
        rep["pages_changed_sidecar"] == rep["pages_changed_referencia"])
    rep["pages_total_zhoda"] = (
        rep["pages_total_sidecar"] == rep["pages_total_referencia"])
    rep["zhoda"] = rep["pages_changed_zhoda"] and rep["pages_total_zhoda"]
    return rep


def sidecar_for(snapshot, chain_id=None, until_seq=None):
    """Sidecar .json poslednej casti retazca (rovnake meno, ina pripona)."""
    heads = _chain_parts(snapshot, chain_id, until_seq)
    p = heads[-1]["path"]
    cand = p[:-len(".vmicd")] + ".json" if p.endswith(".vmicd") else p + ".json"
    if not os.path.exists(cand):
        return None
    return cand
