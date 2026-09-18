"""
Testy per-bin priznakoveho vektora.

Delia sa na tri skupiny:

  1. kontrakt binovania - bin bez podlozenej stranky NEVZNIKNE, index binu je
     viazany na fyzicku adresu; overuje sa na vymyslenych memslotoch, kde je
     spravna odpoved spocitatelna rucne;
  2. definicie priznakov - entropia, nulovost, has_changed; overuje sa na
     strankach so znamym obsahom, nie na snimke;
  3. invarianty nad skutocnymi snimkami - sucty musia sediet s cislami, ktore
     o tej istej snimke napisal zberac.

Skupina 3 potrebuje snimky mimo repa a v cerstvom klone sa preskoci
(viz conftest.py); skupiny 1 a 2 bezia vzdy.
"""

import json
import math

import pytest

from features.perbin import (DEFAULT_BIN_BYTES, PAGE, FeatureError, Memslots,
                             _hist, check_against_sidecar, entropy_from_counts,
                             load_memslots, page_entropy, per_bin, sidecar_for)

MIB = 1024 * 1024


# ------------------------------------------------- 1. kontrakt binovania


def test_bin_bez_podlozenej_stranky_nevznikne():
    """
    Jadro dohody: binuje sa iba nad memslotmi. Medzi dvoma slotmi je diera
    velka desiatky binov a ziadny z nich sa v zozname objavit nesmie - ani
    ako nulovy riadok.
    """
    ms = Memslots([(0, 16 * MIB), (4 * 1024 * MIB - 16 * MIB, 16 * MIB)],
                  "test")
    per = ms.bin_pages(16 * MIB)
    assert sorted(per) == [0, 255]
    assert per[0] == 4096
    assert per[255] == 4096


def test_index_binu_je_viazany_na_adresu_nie_na_poradie():
    """
    Ked pribudne memslot na nizsej adrese, uz existujuci bin si musi nechat
    svoje cislo - inak by sa rady priznakov v case posunuli.
    """
    a = Memslots([(1024 * MIB, 16 * MIB)], "test").bin_pages(16 * MIB)
    b = Memslots([(0, 16 * MIB), (1024 * MIB, 16 * MIB)],
                 "test").bin_pages(16 * MIB)
    assert sorted(a) == [64]
    assert sorted(b) == [0, 64]
    assert a[64] == b[64]


def test_diera_v_memslote_zmensi_pages_total():
    """VGA diera 0xA0000-0xBFFFF: bin 0 ma o 32 stranok menej nez 4096."""
    ms = Memslots([(0, 0xA0000), (0xC0000, 16 * MIB - 0xC0000)], "test")
    per = ms.bin_pages(16 * MIB)
    assert sorted(per) == [0]
    assert per[0] == 4096 - 32


def test_memslot_cez_hranicu_binu_sa_rozdeli():
    ms = Memslots([(16 * MIB - 8 * PAGE, 16 * PAGE)], "test")
    per = ms.bin_pages(16 * MIB)
    assert per == {0: 8, 1: 8}


def test_nezarovnany_a_prekryvajuci_sa_memslot_je_chyba():
    with pytest.raises(FeatureError, match="zarovnany"):
        Memslots([(1, 4096)], "test")
    with pytest.raises(FeatureError, match="prekryvaju"):
        Memslots([(0, 8192), (4096, 8192)], "test")


def test_bin_bytes_musi_byt_mocnina_dvojky():
    ms = Memslots([(0, 16 * MIB)], "test")
    with pytest.raises(FeatureError, match="mocnina"):
        ms.bin_pages(3 * MIB)
    with pytest.raises(FeatureError, match="nasobok"):
        ms.bin_pages(2048)


def test_memsloty_sa_nehadaju(tmp_path):
    """Subor bez rozsahov = chyba s vysvetlenim, nie prazdny zoznam."""
    p = tmp_path / "prazdne.json"
    p.write_text(json.dumps({"capture": {"regions": []}}), encoding="utf-8")
    with pytest.raises(FeatureError, match="rozsahy memslotov"):
        load_memslots(str(p))


def test_memsloty_z_probe_json(probe, memslots):
    """Rozsahy z 'vmicollect probe -v' sa nacitaju a pomenuju zdroj."""
    assert memslots.source.endswith("values.memslot_ranges")
    assert memslots.pages_total * PAGE == 2164396032


# ------------------------------------------------- 2. definicie priznakov


def test_entropia_nulovej_stranky_je_nula():
    assert page_entropy(b"\0" * PAGE) == 0.0


def test_entropia_dvoch_rovnako_castych_bajtov_je_jeden_bit():
    page = (b"\x00\xff" * (PAGE // 2))
    assert page_entropy(page) == pytest.approx(1.0, abs=1e-12)


def test_entropia_vsetkych_256_hodnot_je_osem_bitov():
    page = bytes(range(256)) * (PAGE // 256)
    assert page_entropy(page) == pytest.approx(8.0, abs=1e-12)


def test_entropia_je_v_rozsahu_nula_az_osem():
    for page in (b"A" * PAGE, bytes(range(256)) * 16,
                 (b"\x01\x02\x03\x04" * (PAGE // 4))):
        h = page_entropy(page)
        assert 0.0 <= h <= 8.0


def test_entropia_obe_vetvy_rovnako():
    """
    Rychla (numpy) a zalozna (stdlib) vetva musia dat BIT PO BITE rovnaky
    float. Keby sa lisili, krizova kontrola by hlasila rozdiel, ktory nie je
    v snimke, ale v scitani.
    """
    import features.perbin as pb
    page = bytes((i * 37 + (i >> 3)) & 0xFF for i in range(PAGE))
    hist_np = _hist(page)
    povodne = pb._np
    try:
        pb._np = None
        hist_py = _hist(page)
    finally:
        pb._np = povodne
    assert hist_np == hist_py
    assert entropy_from_counts(hist_np, PAGE) == \
        entropy_from_counts(hist_py, PAGE)


def test_entropia_sedi_so_vzorcom_z_definicie():
    """Kontrola proti priamemu zapisu -sum p*log2(p), bez tabuliek."""
    page = bytes((i * 91) & 0xFF for i in range(PAGE))
    counts = _hist(page)
    rucne = -sum((c / PAGE) * math.log2(c / PAGE) for c in counts if c)
    assert page_entropy(page) == pytest.approx(rucne, abs=1e-12)


# -------------------------------------------- 3. invarianty nad snimkami


def _skontroluj_riadky(res):
    """Vlastnosti, ktore musi splnat kazdy riadok kazdeho vektora."""
    for row in res["features"]["bins"]:
        assert row["pages_total"] > 0, "bin bez podlozenej stranky vznikol"
        assert 0 <= row["pages_changed"] <= row["pages_total"]
        assert row["changed_ratio"] == row["pages_changed"] / row["pages_total"]
        assert 0.0 <= row["zero_ratio"] <= 1.0
        assert 0.0 <= row["entropy_mean"] <= 8.0
        assert row["has_changed"] == (1 if row["pages_changed"] else 0)
        if not row["has_changed"]:
            # Ticho doplnena nula je zakazana: nula tu smie byt iba preto,
            # ze sa nemalo z coho priemerovat, a hovori to has_changed.
            assert row["entropy_mean"] == 0.0
        assert row["gpa"] == row["bin"] * res["features"]["bin_bytes"]


def test_mini_snimka_sucty_sedia(mini, memslots):
    """
    mini.vmicd ma 27 stranok vybranych z realnej snimky. Sucet pages_changed
    sa musi rovnat poctu zaznamov a sucet pages_total poctu podlozenych
    stranok VM - aj ked je snimka umelo orezana.
    """
    res = per_bin(mini, memslots)
    k = res["kontrola"]
    assert k["pages_changed_sucet"] == k["zaznamov_v_poslednej_casti"] == 27
    assert k["pages_total_sucet"] == memslots.pages_total == 528417
    assert k["stranok_mimo_memslotov_v_stave"] == 0
    assert res["features"]["bins_total"] == 131
    assert res["features"]["bin_bytes"] == DEFAULT_BIN_BYTES
    _skontroluj_riadky(res)


def test_mini_ziadny_bin_sa_neopakuje(mini, memslots):
    bins = [r["bin"] for r in per_bin(mini, memslots)["features"]["bins"]]
    assert bins == sorted(bins)
    assert len(bins) == len(set(bins))


def test_vacsi_bin_je_sucet_mensich(mini, memslots):
    """
    Zmena velkosti binu nesmie zmenit, co sa napocitalo: bin 32 MiB musi mat
    presne sucet dvoch susednych 16 MiB binov. Ked to neplati, chyba je v
    prevode adresy na index, nie v datach.
    """
    maly = {r["bin"]: r for r in
            per_bin(mini, memslots, bin_bytes=16 * MIB)["features"]["bins"]}
    velky = {r["bin"]: r for r in
             per_bin(mini, memslots, bin_bytes=32 * MIB)["features"]["bins"]}
    for b, row in velky.items():
        casti = [maly[x] for x in (2 * b, 2 * b + 1) if x in maly]
        assert casti, "bin %d velkeho delenia nema ziadnu cast" % b
        assert row["pages_total"] == sum(c["pages_total"] for c in casti)
        assert row["pages_changed"] == sum(c["pages_changed"] for c in casti)


def test_plna_snimka_sedi_so_sidecarom(full_snap, memslots):
    """
    Invariant zo zadania kroku, proti cislam zberaca: sucet pages_changed cez
    biny == output.pages_changed a sucet pages_total == output.pages_total.
    """
    res = per_bin(full_snap, memslots)
    side = sidecar_for(full_snap)
    assert side, "realna snimka nema vedla seba sidecar"
    rep = check_against_sidecar(res, side)
    assert rep["zhoda"], rep
    _skontroluj_riadky(res)


def test_retazec_delt_sedi_so_sidecarmi(delta_chain, memslots):
    """To iste pre kazdu cast retazca zvlast - vratane delt, nie len plnej."""
    from features.perbin import _chain_parts
    heads = _chain_parts(delta_chain)
    assert len(heads) >= 2
    for h in heads:
        res = per_bin(delta_chain, memslots, until_seq=h["seq"])
        side = sidecar_for(delta_chain, until_seq=h["seq"])
        rep = check_against_sidecar(res, side)
        assert rep["zhoda"], (h["seq"], rep)
        _skontroluj_riadky(res)


def test_delta_bez_baseline_sa_odmietne(delta_chain):
    """
    Samotna delta sa citat neda - stav pamate po nej zavisi od predoslych
    casti. Referencia to musi odmietnut, nie dopocitat z nul.
    """
    import os
    delty = sorted(n for n in os.listdir(delta_chain)
                   if n.endswith(".vmicd") and "_000000_" not in n)
    assert delty, "v retazci nie je ziadna delta"
    ms = Memslots([(0, 16 * MIB)], "test")
    with pytest.raises(FeatureError, match="bez baseline"):
        per_bin(os.path.join(delta_chain, delty[0]), ms)
