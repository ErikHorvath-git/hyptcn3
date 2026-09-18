"""
crosscheck.py - porovnanie per-bin vektora z C modulu a z tejto referencie.

PRECO po poliach a nie po suboroch: "JSONy sa lisia" nie je nalez, s ktorym sa
da nieco robit. Nalez je "bin 63, entropy_mean, C 7.981234, referencia
7.981199, rozdiel 3.5e-05". Preto sa porovnava kazde pole kazdeho binu a do
vysledku ide presne miesto a velkost rozdielu.

PRAVIDLO: ked sa cisla rozidu, referencia sa NEPRISPOSOBUJE. Hlada sa pricina.
Moze sa ukazat, ze chyba je na strane C - to je legitimny vysledok a zapise sa
tak isto ako opacny.

Tolerancie: celociselne polia (bin, gpa, pages_total, pages_changed,
has_changed) sa porovnavaju presne, bez tolerancie. Pomery a entropia su
desatinne cisla, ktore C tlaci do JSONu zaokruhlene, takze sa porovnavaju s
toleranciou; jej hodnota je v kazdom vysledku uvedena, aby bolo vidiet, co sa
este povazovalo za zhodu.
"""

import json
import os

INT_FIELDS = ("bin", "gpa", "pages_total", "pages_changed", "has_changed")
FLOAT_FIELDS = ("changed_ratio", "zero_ratio", "entropy_mean")

# Pocet desatinnych miest, na ktore C tlaci desatinne polia (printf %.6f).
# Presnejsie sa zo sidecaru porovnat neda - to, co je za nimi, v subore nie je.
C_DECIMALS = 6

# C tlaci pomery aj entropiu cez printf("%.6f"), takze zhoda sa nemoze
# vyzadovat presnejsie nez na polovicu posledneho tlaceneho miesta.
DEFAULT_TOL = 5e-7


def _index_by_bin(block, kde):
    bins = block.get("bins")
    if not isinstance(bins, list):
        raise ValueError("%s: blok nema zoznam 'bins'" % kde)
    out = {}
    for row in bins:
        b = row.get("bin")
        if b is None:
            raise ValueError("%s: riadok bez kluca 'bin': %r" % (kde, row))
        if b in out:
            raise ValueError("%s: bin %d je v zozname dvakrat" % (kde, b))
        out[b] = row
    return out


def compare(ref, c, tol=DEFAULT_TOL):
    """
    ref, c = bloky "features" (schema, bin_bytes, bins_total, bins).

    Vracia slovnik s vysledkom; "zhoda" je True iba ked nie je ziadny rozdiel
    ani v hlavicke, ani v mnozine binov, ani v jedinom poli.
    """
    hlavicka = []
    for key in ("schema", "bin_bytes", "bins_total"):
        rv, cv = ref.get(key), c.get(key)
        if rv != cv:
            hlavicka.append({"pole": key, "referencia": rv, "c": cv})

    rmap = _index_by_bin(ref, "referencia")
    cmap = _index_by_bin(c, "C")

    # [features].entropy sa da v module vypnut; vtedy kluc entropy_mean
    # v riadkoch binov NIE JE (viz meta.c). Porovnavat ho potom nemozno -
    # zapise sa to ako neporovnane pole, nie ako zhoda.
    float_fields = list(FLOAT_FIELDS)
    entropia_vypnuta = (c.get("entropy") is False)
    if entropia_vypnuta:
        float_fields.remove("entropy_mean")

    iba_ref = sorted(set(rmap) - set(cmap))
    iba_c = sorted(set(cmap) - set(rmap))

    rozdiely = []
    max_abs = {}
    mimo_tlace = []
    for b in sorted(set(rmap) & set(cmap)):
        rrow, crow = rmap[b], cmap[b]
        for f in INT_FIELDS:
            if f not in rrow or f not in crow:
                rozdiely.append({"bin": b, "pole": f,
                                 "referencia": rrow.get(f, "<chyba>"),
                                 "c": crow.get(f, "<chyba>"),
                                 "rozdiel": None,
                                 "pozn": "pole v jednom z vektorov chyba"})
                continue
            if rrow[f] != crow[f]:
                rozdiely.append({"bin": b, "pole": f,
                                 "referencia": rrow[f], "c": crow[f],
                                 "rozdiel": crow[f] - rrow[f]})
                max_abs[f] = max(max_abs.get(f, 0), abs(crow[f] - rrow[f]))
        for f in float_fields:
            if f not in rrow or f not in crow:
                rozdiely.append({"bin": b, "pole": f,
                                 "referencia": rrow.get(f, "<chyba>"),
                                 "c": crow.get(f, "<chyba>"),
                                 "rozdiel": None,
                                 "pozn": "pole v jednom z vektorov chyba"})
                continue
            d = float(crow[f]) - float(rrow[f])
            max_abs[f] = max(max_abs.get(f, 0.0), abs(d))
            # Prisnejsia otazka nez tolerancia: sedi referencia s C na VSETKY
            # miesta, ktore C vobec vytlacil? Ked ano, rozdiel je cely v
            # zaokruhleni tlace a nie v algoritme. Ked nie, tolerancia to
            # este prejde, ale vidiet to treba.
            if round(float(rrow[f]), C_DECIMALS) != float(crow[f]):
                mimo_tlace.append({"bin": b, "pole": f,
                                   "referencia": rrow[f], "c": crow[f],
                                   "referencia_zaokruhlena":
                                       round(float(rrow[f]), C_DECIMALS)})
            if abs(d) > tol:
                rozdiely.append({"bin": b, "pole": f,
                                 "referencia": rrow[f], "c": crow[f],
                                 "rozdiel": d})

    out = {
        "tolerancia": tol,
        "tolerancia_pozn": ("celociselne polia sa porovnavaju presne; "
                            "tolerancia plati iba pre changed_ratio, "
                            "zero_ratio a entropy_mean"),
        "binov_referencia": len(rmap),
        "binov_c": len(cmap),
        "hlavicka_rozdiely": hlavicka,
        "biny_iba_v_referencii": iba_ref,
        "biny_iba_v_c": iba_c,
        "rozdielov": len(rozdiely),
        "rozdiely": rozdiely,
        "max_abs_rozdiel": max_abs,
        "mimo_tlacenej_presnosti": len(mimo_tlace),
        "mimo_tlacenej_presnosti_priklady": mimo_tlace[:20],
        "mimo_tlacenej_presnosti_pozn": (
            "pocet poli, kde sa referencia zaokruhlena na %d desatinnych "
            "miest nerovna hodnote vytlacenej C. Nula znamena, ze obe "
            "implementacie sedia na vsetky miesta, ktore su v subore."
            % C_DECIMALS),
        "zhoda": (not hlavicka and not iba_ref and not iba_c
                  and not rozdiely),
    }
    if entropia_vypnuta:
        out["neporovnane_polia"] = ["entropy_mean"]
        out["neporovnane_dovod"] = (
            "C mal [features].entropy vypnutu, takze entropy_mean v jeho "
            "vystupe nie je; zhoda vo zvysnych poliach o entropii nehovori "
            "nic")
    return out


def load_c_features(path):
    """
    Nacita blok "features" z vystupu C modulu.

    Prijme sidecar snimky (features je v nom blok najvyssej urovne) aj
    samostatny subor, ktory je uz priamo tym blokom.
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc.get("features"), dict):
        return doc["features"], "%s:features" % os.path.basename(path)
    if isinstance(doc.get("bins"), list):
        return doc, os.path.basename(path)
    if isinstance(doc.get("values"), dict) and \
            isinstance(doc["values"].get("features"), dict):
        return doc["values"]["features"], \
            "%s:values.features" % os.path.basename(path)
    raise ValueError(
        "%s: nenasiel som blok per-bin vektora. Cakane: kluc 'features' "
        "(sidecar), 'values.features' alebo priamo kluc 'bins'." % path)
