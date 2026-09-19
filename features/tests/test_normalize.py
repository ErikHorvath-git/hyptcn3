"""
Testy z-score normalizacie a manifestu.

Vstupy su synteticke (rovnaky generator ako v test_windows.py), aby testy
bezali aj bez zozbieraneho korpusu. Overuje sa to, co ma zachytit chybu
metodiky, nie iba to, ci kod nespadne:

  - transform bez fitu je vynimka,
  - mu/sd vzniknu IBA zo zadanych sedeni,
  - indikatory `ma_predchodcu` a `je_plna` prejdu nezmenene,
  - manifest sa pri nacitani overuje proti tomu, co caka volajuci.
"""

import json

import numpy as np
import pytest

from features.manifest import Manifest, ManifestError, hash_priznakov
from features.normalize import (BIN_BYTES_MANIFEST, NormalizeError,
                                Normalizer, NotFittedError)
from features.snapshot import MENA
from features.tests.test_windows import F, I_PLNA, I_PRED, okna, session

I_ZMENA = MENA.index("mem_changed_ratio")
NENORM = ("ma_predchodcu", "je_plna")


def norm():
    return Normalizer(priznaky=MENA, nenormalizovane=NENORM)


def data():
    """Tri sedenia: dve benigne trenovacie, jedno testovacie."""
    return (session("ben1", 20, plne=(0,), bez_predchodcu=(0,))
            + session("ben2", 20, plne=(0,), bez_predchodcu=(0,))
            + session("test1", 20, plne=(0,), bez_predchodcu=(0,)))


def labely():
    return {"ben1": "idle", "ben2": "idle", "test1": "cpu_burn"}


# -- fit / transform -----------------------------------------------------


def test_transform_bez_fitu_vyhodi():
    n = norm()
    o = okna(session("a", 10), dlzka=4)
    with pytest.raises(NotFittedError):
        n.transform(o)
    with pytest.raises(NotFittedError):
        n.transform(np.zeros((2, 4, F)))
    with pytest.raises(NotFittedError):
        n.manifest


def test_fit_pocita_mu_sd_iba_zo_zadanych_sedeni():
    snimky = data()
    n = norm().fit(snimky, sessions_fit=["ben1", "ben2"], labely=labely())
    m = n.manifest
    fit_snimky = [s for s in snimky if s.session in ("ben1", "ben2")]
    S = np.stack([s.x for s in fit_snimky], axis=0)
    assert m.mu[I_ZMENA] == pytest.approx(float(S[:, I_ZMENA].mean()))
    assert m.sd[I_ZMENA] == pytest.approx(float(S[:, I_ZMENA].std(ddof=0)))
    # kontrola, ze testovacie sedenie naozaj vysledok nemeni: mu spocitane zo
    # vsetkych troch sedeni je ine cislo
    V = np.stack([s.x for s in snimky], axis=0)
    assert float(V[:, I_ZMENA].mean()) != pytest.approx(m.mu[I_ZMENA])
    assert m.sessions == ("ben1", "ben2")
    assert m.n_snimok == 40


def test_transform_da_nulovy_priemer_na_fitovacich_datach():
    snimky = [s for s in data() if s.session in ("ben1", "ben2")]
    n = norm().fit(snimky, sessions_fit=["ben1", "ben2"])
    Y = n.transform(np.stack([s.x for s in snimky], axis=0))
    assert float(Y[:, I_ZMENA].mean()) == pytest.approx(0.0, abs=1e-9)
    assert float(Y[:, I_ZMENA].std(ddof=0)) == pytest.approx(1.0, abs=1e-9)


def test_indikatory_sa_nenormalizuju():
    snimky = data()
    n = norm().fit(snimky, sessions_fit=["ben1"])
    o = okna(snimky, dlzka=4)
    y = n.transform(o)
    for i in (I_PRED, I_PLNA):
        assert np.array_equal(y.X[:, :, i], o.X[:, :, i])
        assert set(np.unique(y.X[:, :, i])) <= {0.0, 1.0}
        assert n.manifest.mu[i] == 0.0
        assert n.manifest.sd[i] == 1.0
    assert set(n.manifest.nenormalizovane) == set(NENORM)
    # ostatne priznaky sa naopak zmenit museli
    assert not np.array_equal(y.X[:, :, I_ZMENA], o.X[:, :, I_ZMENA])


def test_transform_okien_zachova_metadata():
    snimky = data()
    n = norm().fit(snimky, sessions_fit=["ben1"])
    o = okna(snimky, dlzka=4)
    y = n.transform(o)
    assert y.meta == o.meta
    assert y.priznaky == o.priznaky
    assert y.vynechane == o.vynechane
    assert y.X.shape == o.X.shape


def test_konstantny_priznak_dostane_sd_1_a_je_v_manifeste():
    snimky = session("ben1", 10)
    for s in snimky:
        s.x[I_ZMENA] = 0.25   # priznak, ktory vo fitovacej mnozine nekolise
    n = norm().fit(snimky, sessions_fit=["ben1"])
    m = n.manifest
    assert m.sd[I_ZMENA] == 1.0
    assert "mem_changed_ratio" in m.konstantne
    y = n.transform(np.stack([s.x for s in snimky], axis=0))
    assert float(np.abs(y[:, I_ZMENA]).max()) == pytest.approx(0.0)


# -- kontroly proti uniku testovacich dat --------------------------------


def test_fit_bez_zoznamu_sedeni_je_chyba():
    with pytest.raises(NormalizeError) as e:
        norm().fit(data(), sessions_fit=None)
    assert "sessions_fit" in str(e.value)


def test_fit_odmietne_nebenigne_sedenie():
    with pytest.raises(NormalizeError) as e:
        norm().fit(data(), sessions_fit=["ben1", "test1"], labely=labely())
    assert "test1" in str(e.value)


def test_fit_odmietne_sedenie_bez_labelu():
    with pytest.raises(NormalizeError):
        norm().fit(data(), sessions_fit=["ben1", "ben2"],
                   labely={"ben1": "idle"})


def test_fit_odmietne_nezname_sedenie():
    with pytest.raises(NormalizeError):
        norm().fit(data(), sessions_fit=["neexistuje"])


def test_fit_odmietne_okna():
    o = okna(session("ben1", 10), dlzka=4)
    with pytest.raises(NormalizeError) as e:
        norm().fit(o, sessions_fit=["ben1"])
    assert "okna" in str(e.value).lower()


def test_nenormalizovany_priznak_mimo_poradia_je_chyba():
    with pytest.raises(NormalizeError):
        Normalizer(priznaky=MENA, nenormalizovane=("neexistuje",))


# -- manifest ------------------------------------------------------------


def test_manifest_roundtrip(tmp_path):
    n = norm().fit(data(), sessions_fit=["ben1", "ben2"], labely=labely(),
                   dlzka_okna=16)
    p = tmp_path / "manifest.json"
    n.save(str(p))
    n2 = Normalizer.load(str(p), priznaky=MENA)
    o = okna(data(), dlzka=4)
    assert np.array_equal(n.transform(o).X, n2.transform(o).X)
    m = Manifest.load(str(p))
    assert m.priznaky_hash == hash_priznakov(MENA)
    assert m.dlzka_okna == 16
    assert m.rezim == "priznak"
    # snimkovy vektor nema biny; bin_bytes je povinne pole manifestu a je v
    # nom neutralna 1, nie nameranu velkost
    assert m.bin_bytes == BIN_BYTES_MANIFEST
    assert m.commit is None or len(m.commit) == 40


def test_manifest_so_zlym_hashom_sa_nenacita(tmp_path):
    n = norm().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    d = json.loads(p.read_text())
    d["priznaky_hash"] = "0" * 64
    p.write_text(json.dumps(d))
    with pytest.raises(ManifestError) as e:
        Manifest.load(str(p))
    assert "hash" in str(e.value)


def test_manifest_s_prehodenym_poradim_priznakov_je_chyba(tmp_path):
    n = norm().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    d = json.loads(p.read_text())
    prehodene = [d["priznaky"][1], d["priznaky"][0]] + d["priznaky"][2:]
    d["priznaky"] = prehodene
    d["priznaky_hash"] = hash_priznakov(prehodene)
    p.write_text(json.dumps(d))
    # sam o sebe je taky manifest konzistentny (hash sedi), chybu musi odhalit
    # az porovnanie s poradim, ktore caka volajuci
    Manifest.load(str(p))
    with pytest.raises(ManifestError) as e:
        Normalizer.load(str(p), priznaky=MENA)
    assert "poradie" in str(e.value)


def test_manifest_s_inym_poctom_priznakov_je_chyba(tmp_path):
    n = norm().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    with pytest.raises(ManifestError) as e:
        Normalizer.load(str(p), priznaky=MENA[:3])
    assert "pocet" in str(e.value)


def test_manifest_s_inou_schemou_je_chyba(tmp_path):
    n = norm().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    d = json.loads(p.read_text())
    d["schema"] = "hyptcn3/normalize/2"
    p.write_text(json.dumps(d))
    with pytest.raises(ManifestError):
        Manifest.load(str(p))


def test_manifest_so_sd_nula_je_chyba(tmp_path):
    n = norm().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    d = json.loads(p.read_text())
    d["sd"][I_ZMENA] = 0.0
    p.write_text(json.dumps(d))
    with pytest.raises(ManifestError) as e:
        Manifest.load(str(p))
    assert "sd" in str(e.value)


def test_manifest_zachyti_chybajuci_kluc(tmp_path):
    with pytest.raises(ManifestError):
        Manifest.from_dict({"schema": "hyptcn3/normalize/1"})


# -- determinizmus -------------------------------------------------------


def test_determinizmus_fitu(tmp_path):
    n1 = norm().fit(data(), sessions_fit=["ben1", "ben2"], labely=labely())
    n2 = norm().fit(data(), sessions_fit=["ben1", "ben2"], labely=labely())
    a, b = n1.manifest.to_dict(), n2.manifest.to_dict()
    assert a == b
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    n1.save(str(p1))
    n2.save(str(p2))
    assert p1.read_bytes() == p2.read_bytes()


def test_determinizmus_transformu():
    n = norm().fit(data(), sessions_fit=["ben1"])
    o = okna(data(), dlzka=6)
    assert np.array_equal(n.transform(o).X, n.transform(o).X)
