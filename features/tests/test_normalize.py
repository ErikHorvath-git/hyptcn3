"""
Testy z-score normalizacie a manifestu.

Vstupy su synteticke (rovnaky generator ako v test_windows.py), aby testy
bezali aj bez zozbieraneho korpusu. Overuje sa to, co ma zachytit chybu
metodiky, nie iba to, ci kod nespadne:

  - transform bez fitu je vynimka,
  - mu/sd vzniknu IBA zo zadanych sessions,
  - has_changed prejde nezmeneny,
  - manifest sa pri nacitani overuje proti tomu, co caka volajuci.
"""

import json

import numpy as np
import pytest

from features.manifest import (NENORMALIZOVANE, PRIZNAKY, Manifest,
                               ManifestError, hash_priznakov)
from features.normalize import NormalizeError, Normalizer, NotFittedError
from features.tests.test_windows import BIN_BYTES, BINY, okna, session, snimka

I_ZMENA = PRIZNAKY.index("changed_ratio")
I_ENTROPIA = PRIZNAKY.index("entropy_mean")
I_HAS = PRIZNAKY.index("has_changed")


def data():
    """Tri sessions: dve benigne trenovacie, jedna testovacia."""
    return (session("ben1", 20) + session("ben2", 20) + session("test1", 20))


def labely():
    return {"ben1": "idle", "ben2": "idle", "test1": "cpu_burn"}


# -- fit / transform -----------------------------------------------------


def test_transform_bez_fitu_vyhodi():
    n = Normalizer()
    o = okna(session("a", 10), dlzka=4)
    with pytest.raises(NotFittedError):
        n.transform(o)
    with pytest.raises(NotFittedError):
        n.transform(np.zeros((2, 4, len(BINY), len(PRIZNAKY))))
    with pytest.raises(NotFittedError):
        n.manifest


def test_fit_pocita_mu_sd_iba_zo_zadanych_sessions():
    snimky = data()
    n = Normalizer().fit(snimky, sessions_fit=["ben1", "ben2"], labely=labely())
    m = n.manifest
    fit_snimky = [s for s in snimky if s.session in ("ben1", "ben2")]
    S = np.stack([s.x for s in fit_snimky], axis=0)
    assert m.mu[I_ZMENA] == pytest.approx(float(S[:, :, I_ZMENA].mean()))
    assert m.sd[I_ZMENA] == pytest.approx(float(S[:, :, I_ZMENA].std(ddof=0)))
    # kontrola, ze testovacia session naozaj vysledok nemeni: mu spocitane zo
    # vsetkych troch sessions je ine cislo
    V = np.stack([s.x for s in snimky], axis=0)
    assert float(V[:, :, I_ZMENA].mean()) != pytest.approx(m.mu[I_ZMENA])
    assert m.sessions == ("ben1", "ben2")
    assert m.n_snimok == 40


def test_transform_da_nulovy_priemer_na_fitovacich_datach():
    snimky = [s for s in data() if s.session in ("ben1", "ben2")]
    n = Normalizer().fit(snimky, sessions_fit=["ben1", "ben2"])
    Y = n.transform(np.stack([s.x for s in snimky], axis=0))
    assert float(Y[:, :, I_ZMENA].mean()) == pytest.approx(0.0, abs=1e-9)
    assert float(Y[:, :, I_ZMENA].std(ddof=0)) == pytest.approx(1.0, abs=1e-9)


def test_has_changed_sa_nenormalizuje():
    snimky = data()
    n = Normalizer().fit(snimky, sessions_fit=["ben1"])
    o = okna(snimky, dlzka=4)
    y = n.transform(o)
    assert np.array_equal(y.X[:, :, :, I_HAS], o.X[:, :, :, I_HAS])
    assert set(np.unique(y.X[:, :, :, I_HAS])) <= {0.0, 1.0}
    assert n.manifest.mu[I_HAS] == 0.0
    assert n.manifest.sd[I_HAS] == 1.0
    assert "has_changed" in n.manifest.nenormalizovane
    # ostatne priznaky sa naopak zmenit museli
    assert not np.array_equal(y.X[:, :, :, I_ZMENA], o.X[:, :, :, I_ZMENA])


def test_entropia_sa_fituje_iba_na_zmenenych_binoch():
    snimky = [s for s in data() if s.session == "ben1"]
    n = Normalizer().fit(snimky, sessions_fit=["ben1"])
    S = np.stack([s.x for s in snimky], axis=0)
    maska = S[:, :, I_HAS] > 0.5
    ocakavane = float(S[:, :, I_ENTROPIA][maska].mean())
    assert n.manifest.mu[I_ENTROPIA] == pytest.approx(ocakavane)
    # priemer cez vsetky biny (aj nezmenene nuly) je ine cislo
    assert float(S[:, :, I_ENTROPIA].mean()) != pytest.approx(ocakavane)
    assert n.manifest.podmienene["entropy_mean"] == "has_changed"


def test_transform_okien_zachova_metadata():
    snimky = data()
    n = Normalizer().fit(snimky, sessions_fit=["ben1"])
    o = okna(snimky, dlzka=4)
    y = n.transform(o)
    assert y.meta == o.meta
    assert y.biny == o.biny and y.priznaky == o.priznaky
    assert y.X.shape == o.X.shape


def test_konstantny_priznak_dostane_sd_1_a_je_v_manifeste():
    snimky = session("ben1", 10)
    for s in snimky:
        s.x[:, I_ZMENA] = 0.25   # priznak, ktory vo fitovacej mnozine nekolise
    n = Normalizer().fit(snimky, sessions_fit=["ben1"])
    m = n.manifest
    assert m.sd[I_ZMENA] == 1.0
    assert "changed_ratio" in m.konstantne
    y = n.transform(np.stack([s.x for s in snimky], axis=0))
    assert float(np.abs(y[:, :, I_ZMENA]).max()) == pytest.approx(0.0)


# -- kontroly proti uniku testovacich dat --------------------------------


def test_fit_bez_zoznamu_sessions_je_chyba():
    with pytest.raises(NormalizeError) as e:
        Normalizer().fit(data(), sessions_fit=None)
    assert "sessions_fit" in str(e.value)


def test_fit_odmietne_nebenignu_session():
    with pytest.raises(NormalizeError) as e:
        Normalizer().fit(data(), sessions_fit=["ben1", "test1"], labely=labely())
    assert "test1" in str(e.value)


def test_fit_odmietne_session_bez_labelu():
    with pytest.raises(NormalizeError):
        Normalizer().fit(data(), sessions_fit=["ben1", "ben2"],
                         labely={"ben1": "idle"})


def test_fit_odmietne_neznamu_session():
    with pytest.raises(NormalizeError):
        Normalizer().fit(data(), sessions_fit=["neexistuje"])


def test_fit_odmietne_okna():
    o = okna(session("ben1", 10), dlzka=4)
    with pytest.raises(NormalizeError) as e:
        Normalizer().fit(o, sessions_fit=["ben1"])
    assert "okna" in str(e.value).lower()


# -- manifest ------------------------------------------------------------


def test_manifest_roundtrip(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1", "ben2"], labely=labely(),
                         dlzka_okna=16)
    p = tmp_path / "manifest.json"
    n.save(str(p))
    n2 = Normalizer.load(str(p), priznaky=PRIZNAKY, bin_bytes=BIN_BYTES)
    o = okna(data(), dlzka=4)
    assert np.array_equal(n.transform(o).X, n2.transform(o).X)
    m = Manifest.load(str(p))
    assert m.priznaky_hash == hash_priznakov(PRIZNAKY)
    assert m.dlzka_okna == 16
    assert m.bin_bytes == BIN_BYTES
    assert m.commit is None or len(m.commit) == 40


def test_manifest_so_zlym_hashom_sa_nenacita(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    d = json.loads(p.read_text())
    d["priznaky_hash"] = "0" * 64
    p.write_text(json.dumps(d))
    with pytest.raises(ManifestError) as e:
        Manifest.load(str(p))
    assert "hash" in str(e.value)


def test_manifest_s_prehodenym_poradim_priznakov_je_chyba(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
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
        Normalizer.load(str(p), priznaky=PRIZNAKY)
    assert "poradie" in str(e.value)


def test_manifest_s_inym_poctom_priznakov_je_chyba(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    with pytest.raises(ManifestError) as e:
        Normalizer.load(str(p), priznaky=PRIZNAKY[:3])
    assert "pocet" in str(e.value)


def test_manifest_s_inou_velkostou_binu_je_chyba(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    with pytest.raises(ManifestError) as e:
        Normalizer.load(str(p), bin_bytes=4 * 1024 * 1024)
    assert "bin_bytes" in str(e.value)


def test_manifest_s_inou_schemou_je_chyba(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    d = json.loads(p.read_text())
    d["schema"] = "hyptcn3/normalize/2"
    p.write_text(json.dumps(d))
    with pytest.raises(ManifestError):
        Manifest.load(str(p))


def test_manifest_so_sd_nula_je_chyba(tmp_path):
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
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


# -- rezim po binoch -----------------------------------------------------


def test_rezim_bin_priznak_ma_mu_na_kazdy_bin():
    snimky = [s for s in data() if s.session == "ben1"]
    n = Normalizer(rezim="bin_priznak").fit(snimky, sessions_fit=["ben1"])
    m = n.manifest
    assert np.asarray(m.mu).shape == (len(BINY), len(PRIZNAKY))
    assert m.biny == BINY
    S = np.stack([s.x for s in snimky], axis=0)
    assert m.mu[2][I_ZMENA] == pytest.approx(float(S[:, 2, I_ZMENA].mean()))


def test_rezim_bin_priznak_odmietne_ine_biny(tmp_path):
    snimky = [s for s in data() if s.session == "ben1"]
    n = Normalizer(rezim="bin_priznak").fit(snimky, sessions_fit=["ben1"])
    p = tmp_path / "m.json"
    n.save(str(p))
    with pytest.raises(ManifestError) as e:
        Normalizer.load(str(p), biny=(0, 1, 2, 5, 9))
    assert "biny" in str(e.value) or "bin" in str(e.value)
    ine = okna([snimka("x", i, biny=(0, 1, 2)) for i in range(6)], dlzka=3)
    with pytest.raises(ManifestError):
        n.transform(ine)


# -- determinizmus -------------------------------------------------------


def test_determinizmus_fitu(tmp_path):
    n1 = Normalizer().fit(data(), sessions_fit=["ben1", "ben2"], labely=labely())
    n2 = Normalizer().fit(data(), sessions_fit=["ben1", "ben2"], labely=labely())
    a, b = n1.manifest.to_dict(), n2.manifest.to_dict()
    assert a == b
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    n1.save(str(p1))
    n2.save(str(p2))
    assert p1.read_bytes() == p2.read_bytes()


def test_determinizmus_transformu():
    n = Normalizer().fit(data(), sessions_fit=["ben1"])
    o = okna(data(), dlzka=6)
    assert np.array_equal(n.transform(o).X, n.transform(o).X)
