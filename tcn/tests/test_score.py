"""
Testy skorovacieho procesu (tcn/score.py).

Testuje sa to, co nezavisi od bezicej domeny: ze sa skore pocita az z plneho
okna, ze sa na nenaplnene okno upozorni, ze sa sidecar spozna a nespracuje
dvakrat a ze je upozornenie o nenatrenovanom modeli naozaj vo vypise.

Ziadne cislo z tychto testov nie je vysledok prace - model nie je natrenovany
a skore nie je detekcia.
"""

import json

import pytest

from features.snapshot import MENA
from features.windows import DLZKA_OKNA
from tcn import score


def test_skore_ma_tvar_a_je_zopakovatelne():
    """Rovnaky seed a rovnake okno -> rovnake cislo; sucet softmaxu je 1."""
    okno = [[0.5] * len(MENA) for _ in range(DLZKA_OKNA)]
    a = score.skore(score.model_bez_treningu(DLZKA_OKNA), okno)
    b = score.skore(score.model_bez_treningu(DLZKA_OKNA), okno)
    assert len(a) == score.TRIED
    assert a == b
    assert abs(sum(a) - 1.0) < 1e-6


def test_cakam_text():
    """Kym okno plne nie je, program povie, na kolko snimok caka."""
    assert "cakam na 15 dalsich snimok" in score.cakam_text(1, 16)
    assert score.cakam_text(16, 16) == ""


def _sidecar(adresar, seq):
    meno = "dom_%06d.json" % seq
    (adresar / meno).write_text(json.dumps(
        {"seq": seq, "id": meno[:-5], "timestamp_unix": 1000.0 + seq}),
        encoding="utf-8")
    return meno


def test_nove_sidecary_nespracuje_snimku_dvakrat(tmp_path):
    videne = set()
    _sidecar(tmp_path, 1)
    _sidecar(tmp_path, 0)
    prve = score.nove_sidecary(str(tmp_path), videne)
    assert [z[0] for z in prve] == [0, 1]          # v poradi seq
    assert score.nove_sidecary(str(tmp_path), videne) == []

    _sidecar(tmp_path, 2)
    assert [z[0] for z in score.nove_sidecary(str(tmp_path), videne)] == [2]


def test_rozpisany_sidecar_sa_preskoci_a_skusi_neskor(tmp_path):
    """Sidecar, ktory sa prave pise, nie je chyba - nacita sa v dalsom kole."""
    (tmp_path / "dom_000000.json").write_text('{"seq": 0, "timest',
                                              encoding="utf-8")
    videne = set()
    assert score.nove_sidecary(str(tmp_path), videne) == []
    _sidecar(tmp_path, 0)                          # dopisany sidecar
    assert [z[0] for z in score.nove_sidecary(str(tmp_path), videne)] == [0]


def test_beh_vypise_upozornenie_a_bez_snimok_neskoruje(tmp_path):
    riadky = []
    zaznamy = score.beh(str(tmp_path), "profil-netreba", dlzka=4,
                        vypis=riadky.append)
    assert zaznamy == []
    text = " ".join(riadky)
    assert "NIE JE NATRENOVANY" in text
    assert "NIE JE detekcia" in text


def test_upozornenie_je_aj_v_docstringu():
    """P4/P7: upozornenie musi byt v kode, nielen vo vypise."""
    assert "NIE JE NATRENOVANY" in score.__doc__
    assert "nesmie" in score.__doc__


def test_suhrn_median_p95():
    z = [{"a": float(i)} for i in range(1, 11)]
    s = score.suhrn(z, "a")
    assert s == {"n": 10, "median": 5.5, "p95": 10.0, "min": 1.0, "max": 10.0}
    assert score.suhrn(z, "b")["n"] == 0


def test_main_hlasi_chybu_nad_neexistujucim_adresarom(tmp_path, capsys):
    rc = score.main(["--snapshots", str(tmp_path / "niet"),
                     "--profile", "profil-netreba"])
    assert rc == score.EXIT_ERROR


def test_prediction_cli_uses_training_window(monkeypatch, tmp_path):
    monkeypatch.setattr(score, "nacitaj_prediktor", lambda _: (None, None, {"dlzka_okna": 8}))
    observed = []
    monkeypatch.setattr(score, "beh_predikcia", lambda _a, _p, length, *args: observed.append(length) or [])
    argv = ["--snapshots", str(tmp_path), "--profile", "unused", "--uloha", "predikcia", "--model", "unused"]
    assert score.main(argv) == 0
    assert observed == [8]
    with pytest.raises(SystemExit) as error:
        score.main(argv + ["--dlzka", "16"])
    assert error.value.code == 2


@pytest.mark.parametrize("dlzka", [1, 4])
def test_skore_az_z_plneho_okna(dlzka, monkeypatch, tmp_path):
    """Skore vznikne presne vtedy, ked je v okne dlzka snimok - ani skor."""
    monkeypatch.setattr(score, "vektor_snimky",
                        lambda *a, **k: ([0.1] * len(MENA), None, []))
    for seq in range(5):
        _sidecar(tmp_path, seq)
    zaznamy = score.beh(str(tmp_path), "profil-netreba", dlzka=dlzka,
                        vypis=lambda *_: None)
    assert len(zaznamy) == 5
    so_skore = [i for i, z in enumerate(zaznamy) if z["skore"] is not None]
    assert so_skore == list(range(dlzka - 1, 5))
