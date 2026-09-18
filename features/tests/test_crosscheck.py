"""
Testy porovnavania C a Pythonovej implementacie.

Porovnanie je jadro kroku K14, takze sa testuje ono samo: musi najst rozdiel,
ktory tam je, a NESMIE hlasit rozdiel, ktory tam nie je. Kazdy test zavedie do
kopie vektora jednu zmenu a overi, ze hlasenie ukaze presne ten bin, presne to
pole a presnu velkost rozdielu.
"""

import copy
import json

import pytest

from features import crosscheck as cc


def _vektor():
    return {
        "schema": "hyptcn3/perbin/1",
        "bin_bytes": 16777216,
        "bins_total": 2,
        "bins": [
            {"bin": 0, "gpa": 0, "pages_total": 4064, "pages_changed": 10,
             "changed_ratio": 0.002461, "zero_ratio": 0.997539,
             "entropy_mean": 5.123456, "has_changed": 1},
            {"bin": 251, "gpa": 4211081216, "pages_total": 4096,
             "pages_changed": 0, "changed_ratio": 0.0, "zero_ratio": 1.0,
             "entropy_mean": 0.0, "has_changed": 0},
        ],
    }


def test_zhodne_vektory_su_zhoda():
    r = cc.compare(_vektor(), _vektor())
    assert r["zhoda"] is True
    assert r["rozdielov"] == 0
    assert r["biny_iba_v_referencii"] == [] and r["biny_iba_v_c"] == []


def test_rozdiel_v_celom_cisle_sa_nahlasi_presne():
    c = _vektor()
    c["bins"][0]["pages_changed"] = 12
    r = cc.compare(_vektor(), c)
    assert r["zhoda"] is False
    d = [x for x in r["rozdiely"] if x["pole"] == "pages_changed"]
    assert len(d) == 1
    assert d[0]["bin"] == 0
    assert d[0]["referencia"] == 10 and d[0]["c"] == 12
    assert d[0]["rozdiel"] == 2


def test_celociselne_pole_nema_toleranciu():
    """Tolerancia plati iba pre desatinne polia - o jednu stranku vedla je nalez."""
    c = _vektor()
    c["bins"][0]["pages_total"] = 4065
    r = cc.compare(_vektor(), c, tol=1.0)
    assert r["zhoda"] is False
    assert any(x["pole"] == "pages_total" for x in r["rozdiely"])


def test_maly_rozdiel_v_desatinnom_poli_je_zhoda():
    """C tlaci %.6f, takze zaokruhlenie na poslednom mieste nie je nalez."""
    c = _vektor()
    c["bins"][0]["entropy_mean"] += 2e-7
    r = cc.compare(_vektor(), c)
    assert r["zhoda"] is True
    assert r["max_abs_rozdiel"]["entropy_mean"] == pytest.approx(2e-7)


def test_vacsi_rozdiel_v_entropii_je_nalez():
    c = _vektor()
    c["bins"][0]["entropy_mean"] = 5.123956
    r = cc.compare(_vektor(), c)
    assert r["zhoda"] is False
    d = [x for x in r["rozdiely"] if x["pole"] == "entropy_mean"][0]
    assert d["rozdiel"] == pytest.approx(5.0e-4, abs=1e-9)


def test_chybajuci_bin_sa_nahlasi_a_nezamlci():
    c = _vektor()
    c["bins"] = c["bins"][:1]
    c["bins_total"] = 1
    r = cc.compare(_vektor(), c)
    assert r["zhoda"] is False
    assert r["biny_iba_v_referencii"] == [251]
    assert r["biny_iba_v_c"] == []
    assert any(x["pole"] == "bins_total" for x in r["hlavicka_rozdiely"])


def test_bin_navyse_v_c_sa_nahlasi():
    c = _vektor()
    c["bins"].append({"bin": 128, "gpa": 2147483648, "pages_total": 4096,
                      "pages_changed": 0, "changed_ratio": 0.0,
                      "zero_ratio": 1.0, "entropy_mean": 0.0,
                      "has_changed": 0})
    c["bins_total"] = 3
    r = cc.compare(_vektor(), c)
    assert r["biny_iba_v_c"] == [128]
    assert r["zhoda"] is False


def test_ina_velkost_binu_je_rozdiel_v_hlavicke():
    c = _vektor()
    c["bin_bytes"] = 33554432
    r = cc.compare(_vektor(), c)
    assert r["zhoda"] is False
    assert r["hlavicka_rozdiely"][0]["pole"] == "bin_bytes"


def test_vypnuta_entropia_v_c_sa_neporovnava_ale_povie():
    """
    Ked ma C [features].entropy vypnutu, entropy_mean v jeho vystupe nie je.
    Zhoda vo zvysnych poliach potom o entropii nehovori nic a musi to byt
    vo vysledku napisane.
    """
    c = _vektor()
    c["entropy"] = False
    for row in c["bins"]:
        del row["entropy_mean"]
    r = cc.compare(_vektor(), c)
    assert r["zhoda"] is True
    assert r["neporovnane_polia"] == ["entropy_mean"]
    assert "entropy" in r["neporovnane_dovod"]


def test_dvakrat_ten_isty_bin_je_chyba():
    c = _vektor()
    c["bins"].append(copy.deepcopy(c["bins"][0]))
    with pytest.raises(ValueError, match="dvakrat"):
        cc.compare(_vektor(), c)


def test_load_c_features_pozna_sidecar_aj_holy_blok(tmp_path):
    blok = _vektor()
    p1 = tmp_path / "sidecar.json"
    p1.write_text(json.dumps({"schema": "vmicollect/1", "features": blok}),
                  encoding="utf-8")
    b, src = cc.load_c_features(str(p1))
    assert b == blok and src.endswith(":features")

    p2 = tmp_path / "holy.json"
    p2.write_text(json.dumps(blok), encoding="utf-8")
    b, src = cc.load_c_features(str(p2))
    assert b == blok

    p3 = tmp_path / "nic.json"
    p3.write_text(json.dumps({"schema": "vmicollect/1"}), encoding="utf-8")
    with pytest.raises(ValueError, match="per-bin"):
        cc.load_c_features(str(p3))


def test_referencia_sama_so_sebou_je_zhoda(mini, memslots):
    """Poistka, ze porovnanie nespadne na skutocnom tvare vektora."""
    from features.perbin import per_bin
    f = per_bin(mini, memslots)["features"]
    r = cc.compare(f, json.loads(json.dumps(f)))
    assert r["zhoda"] is True
    assert r["binov_referencia"] == r["binov_c"] == 131


def test_zhoda_na_tlacenej_presnosti_sa_pocita():
    """
    Tolerancia prepusti aj rozdiel, ktory nie je iba zaokruhlenim tlace.
    Preto sa zvlast pocita, kolko poli sa lisi uz po zaokruhleni referencie
    na pocet miest, ktore C vobec vytlacil.
    """
    ref = _vektor()
    ref["bins"][0]["entropy_mean"] = 5.1234564          # tlaci sa 5.123456
    c = _vektor()
    c["bins"][0]["entropy_mean"] = 5.123456
    r = cc.compare(ref, c)
    assert r["zhoda"] is True
    assert r["mimo_tlacenej_presnosti"] == 0

    # Volnejsia tolerancia rozdiel prepusti; pocitadlo ho aj tak ukaze.
    c["bins"][0]["entropy_mean"] = 5.123460
    r = cc.compare(ref, c, tol=1e-5)
    assert r["zhoda"] is True, "pri tolerancii 1e-5 nie je rozdiel 4e-6 nalez"
    assert r["mimo_tlacenej_presnosti"] == 1
    priklad = r["mimo_tlacenej_presnosti_priklady"][0]
    assert priklad["bin"] == 0 and priklad["pole"] == "entropy_mean"
    assert priklad["referencia_zaokruhlena"] == 5.123456
    assert priklad["c"] == 5.123460
