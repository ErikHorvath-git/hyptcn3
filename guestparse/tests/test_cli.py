"""
Testy prikazoveho riadka: navratove kody a spravanie pri rozbitom vstupe.

Navratovy kod je jedina vec, ktoru z tohto prikazu vidi skript, ktory ho
zavola. Preto sa testuje zvlast, ze:
  - nalez konci kodom 1 (nesmie zaniknut v uspesnom behu),
  - NEUZAVRETA kontrola bez nalezov konci kodom 4, nie 0 ("neviem" nie je
    to iste, co "ciste"),
  - rozbity retazec .vmicd konci kodom 2 a hlaska povie, ktora cast chyba.
"""

import json
import os

from guestparse import cli

from .test_chain import _retazec


def _spusti(argv):
    return cli.main(argv)


# ----------------------------------------------------------- navratove kody


def test_kod_pre_nalez():
    res = {"finding_count": 2, "summary": {"inconclusive": []}}
    assert cli.checks_exit_code(res) == cli.EXIT_FINDINGS


def test_kod_pre_neuzavretu_kontrolu():
    """Nula z kontroly, ktora sa neuzavrela, sa nesmie hlasit ako uspech."""
    res = {"finding_count": 0, "summary": {"inconclusive": ["modules"]}}
    assert cli.checks_exit_code(res) == cli.EXIT_INCONCLUSIVE
    assert cli.EXIT_INCONCLUSIVE == 4


def test_kod_pre_ciste_kontroly():
    res = {"finding_count": 0, "summary": {"inconclusive": []}}
    assert cli.checks_exit_code(res) == cli.EXIT_OK


def test_nalez_prebije_neuzavretost():
    res = {"finding_count": 1, "summary": {"inconclusive": ["modules"]}}
    assert cli.checks_exit_code(res) == cli.EXIT_FINDINGS


# -------------------------------------------------------- beh nad snimkou


def test_ps_nad_malou_snimkou(mini_path, profile_dir, capsys):
    rc = _spusti(["ps", "--snapshot", mini_path, "--profile", profile_dir,
                  "--json"])
    out = capsys.readouterr()
    assert rc == cli.EXIT_OK
    res = json.loads(out.out)
    assert res["processes"][0]["comm"] == "systemd"
    # neuplny prechod sa hlasi na stderr, nie ticho
    assert "prerusil" in out.err


def test_info_nad_malou_snimkou(mini_path, profile_dir, capsys):
    rc = _spusti(["info", "--snapshot", mini_path, "--profile", profile_dir])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert "baseline ano, overeny ano" in out
    assert "zhoda" in out


def test_checks_nad_malou_snimkou_hlasi_neuzavretost(mini_path, profile_dir,
                                                     capsys):
    """
    Mala snimka drzi iba stranky, ktore testy citaju, takze krizove kontroly
    sa nad nou uzavriet nemozu - a prikaz to musi povedat.
    """
    rc = _spusti(["checks", "--snapshot", mini_path, "--profile", profile_dir])
    out = capsys.readouterr().out
    assert "NEUZAVRETE kontroly" in out
    assert rc in (cli.EXIT_FINDINGS, cli.EXIT_INCONCLUSIVE)


def test_rozbity_retazec_konci_kodom_2(tmp_path, profile_dir, capsys):
    """Chybajuca delta uprostred: prikaz skonci chybou a povie, co chyba."""
    parts = _retazec(tmp_path)
    os.remove(parts[1])
    rc = _spusti(["info", "--snapshot", str(tmp_path),
                  "--profile", profile_dir])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_ERROR
    assert "chyba snimka seq=1" in err


def test_chain_until_otvori_prefix_retazca(tmp_path, profile_dir, capsys):
    """
    Retazec bez prostrednej delty sa da otvorit po posledne suvisle seq.
    Synteticky retazec nema jadro, takze posun sa nenajde - podstatne je, ze
    otvorenie samo NEZLYHA a hlaska ukaze na spravnu pricinu.
    """
    parts = _retazec(tmp_path)
    os.remove(parts[1])
    rc = _spusti(["info", "--snapshot", str(tmp_path), "--chain-until", "0",
                  "--profile", profile_dir])
    out = capsys.readouterr()
    assert rc == cli.EXIT_ERROR              # bez jadra sa posun najst neda
    assert "banner jadra sa v snimke nenasiel" in out.out
    assert "seq 0..0" in out.out


def test_neexistujuca_snimka_konci_kodom_2(tmp_path, profile_dir, capsys):
    rc = _spusti(["ps", "--snapshot", str(tmp_path / "niet"),
                  "--profile", profile_dir])
    assert rc == cli.EXIT_ERROR
    assert "chyba:" in capsys.readouterr().err
