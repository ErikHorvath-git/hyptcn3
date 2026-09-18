"""
Testy skladania okien.

Vstupy su synteticke - testy musia bezat aj bez zozbieraneho korpusu, inak by
sa dali spustit iba na tomto stroji a iba po roote. Realne sidecary sa tu
napodobnuju iba tvarom (schema vmicollect/1 + blok features), nie obsahom.
"""

import hashlib
import json

import numpy as np
import pytest

from features.manifest import PRIZNAKY, SCHEMA_PERBIN
from features.windows import (DLZKA_OKNA, Snimka, WindowError,
                              nacitaj_session, okna, segmenty,
                              snimka_zo_sidecaru)

BIN_BYTES = 16 * 1024 * 1024
BINY = (0, 1, 2, 5, 6)


def vektor(session, seq, biny=BINY):
    """Deterministicky per-bin vektor: rovnaky vstup da vzdy rovnake cisla.

    Seed sa odvodzuje z SHA-256, nie z vstavaneho hash() - ten je pre retazce
    randomizovany na proces, takze test determinizmu by porovnaval iba dva
    behy v tom istom procese.
    """
    kluc = hashlib.sha256(("%s|%d" % (session, seq)).encode()).digest()
    rng = np.random.default_rng(int.from_bytes(kluc[:8], "big"))
    x = np.zeros((len(biny), len(PRIZNAKY)), dtype=np.float64)
    for i in range(len(biny)):
        zmenil = 1.0 if rng.random() > 0.3 else 0.0
        x[i, 0] = rng.random() * 0.2 if zmenil else 0.0   # changed_ratio
        x[i, 1] = rng.random()                            # zero_ratio
        # entropy_mean je definovana iba pre zmenene stranky; v nezmenenom
        # bine je v sidecari nula a has_changed povie preco
        x[i, 2] = 1.0 + rng.random() * 6.0 if zmenil else 0.0
        x[i, 3] = zmenil                                  # has_changed
    return x


def snimka(session, seq, biny=BINY, t0=1_000_000.0, perioda=2.0, full=False,
           cas_unix=None):
    t = t0 + seq * perioda if cas_unix is None else cas_unix
    return Snimka(session=session, seq=seq,
                  cas="1970-01-01T00:00:00.000Z", cas_unix=t,
                  biny=biny, x=vektor(session, seq, biny),
                  bin_bytes=BIN_BYTES, full=full)


def session(meno, n, od=0, **kw):
    return [snimka(meno, s, **kw) for s in range(od, od + n)]


def sidecar_dict(seq, biny=BINY, bin_bytes=BIN_BYTES, full=False):
    """Sidecar v tvare, v akom ho pise zberac (skratene na potrebne kluce)."""
    x = vektor("s", seq, biny)
    bins = []
    for i, b in enumerate(biny):
        bins.append({
            "bin": b,
            "gpa": b * bin_bytes,
            "pages_total": 4096,
            "pages_changed": int(round(x[i, 0] * 4096)),
            "changed_ratio": x[i, 0],
            "zero_ratio": x[i, 1],
            "entropy_mean": x[i, 2],
            "has_changed": int(x[i, 3]),
        })
    return {
        "schema": "vmicollect/1",
        "seq": seq,
        "id": "test_%06d" % seq,
        "timestamp": "2026-09-18T14:31:%02d.000Z" % (18 + seq),
        "timestamp_unix": 1789741878.0 + seq * 2.0,
        "output": {"writer": "delta", "full": full, "pages_total": 20480,
                   "pages_changed": sum(b["pages_changed"] for b in bins)},
        "features": {
            "schema": SCHEMA_PERBIN,
            "bin_bytes": bin_bytes,
            "bins_total": len(bins),
            "bins": bins,
        },
    }


# -- tvar a pocty --------------------------------------------------------


def test_tvar_je_okna_cas_biny_priznaky():
    o = okna(session("a", 20), dlzka=8)
    assert o.X.shape == (13, 8, len(BINY), len(PRIZNAKY))
    assert len(o) == 13
    assert o.priznaky == PRIZNAKY
    assert o.biny == BINY


def test_pocet_okien_pri_kroku_1_a_2():
    snimky = session("a", 20)
    assert len(okna(snimky, dlzka=8, krok=1)) == 13
    assert len(okna(snimky, dlzka=8, krok=2)) == 7


def test_ako_kanaly_je_bin_major():
    o = okna(session("a", 10), dlzka=4)
    K = o.ako_kanaly()
    B, F = len(BINY), len(PRIZNAKY)
    assert K.shape == (7, 4, B * F)
    # kanal = bin * F + priznak
    for b in range(B):
        for f in range(F):
            assert np.array_equal(K[:, :, b * F + f], o.X[:, :, b, f])


def test_metadata_okna():
    o = okna(session("a", 10, perioda=2.0), dlzka=4)
    m = o.meta[0]
    assert m["session"] == "a"
    assert (m["seq_od"], m["seq_do"]) == (0, 3)
    assert m["n_snimok"] == 4
    assert m["trvanie_s"] == pytest.approx(6.0)
    assert o.meta[-1]["seq_do"] == 9


# -- hranice -------------------------------------------------------------


def test_okno_nepresahuje_hranicu_session():
    snimky = session("a", 10) + session("b", 10)
    o = okna(snimky, dlzka=4)
    # 7 okien na session, ziadne cez hranicu
    assert len(o) == 14
    for m in o.meta:
        assert m["seq_do"] - m["seq_od"] == 3
    assert {m["session"] for m in o.meta} == {"a", "b"}
    # ziadne okno nema v metadatach dve sessions - kontrola cez usek dat:
    # posledne okno session 'a' konci na seq 9, prve okno 'b' zacina na 0
    a = [m for m in o.meta if m["session"] == "a"]
    b = [m for m in o.meta if m["session"] == "b"]
    assert a[-1]["seq_do"] == 9 and b[0]["seq_od"] == 0


def test_hranica_session_plati_aj_ked_seq_plynulo_nadvazuje():
    # 'b' pokracuje v cislovani po 'a'; spojit ich by bola presne ta chyba,
    # ktora v predchadzajucom projekte urobila confound
    snimky = session("a", 6) + session("b", 6, od=6)
    o = okna(snimky, dlzka=6)
    assert len(o) == 2
    assert {(m["session"], m["seq_od"]) for m in o.meta} == {("a", 0), ("b", 6)}


def test_diera_v_seq_reze_usek():
    snimky = session("a", 5) + session("a", 5, od=6)
    assert len(segmenty(snimky)) == 2
    o = okna(snimky, dlzka=5)
    assert len(o) == 2
    assert [m["seq_od"] for m in o.meta] == [0, 6]


def test_casova_medzera_reze_usek_iba_ked_je_zadana():
    snimky = session("a", 8, perioda=2.0)
    # zmeskany slot: seq je spojite, ale medzi seq 3 a 4 je 20 s
    for s in snimky[4:]:
        s.cas_unix += 18.0
    assert len(okna(snimky, dlzka=4)) == 5
    o = okna(snimky, dlzka=4, max_medzera_s=5.0)
    assert len(o) == 2
    assert [m["seq_od"] for m in o.meta] == [0, 4]


def test_vynechanie_plnej_snimky_je_rez():
    snimky = session("a", 9)
    snimky[0].full = True
    snimky[4].full = True
    # plna snimka ponechana: jeden spojity usek
    assert len(okna(snimky, dlzka=4, plne="ponechat")) == 6
    o = okna(snimky, dlzka=4, plne="vynechat")
    # zostanu useky seq 1..3 (kratky) a seq 5..8 (4 snimky) -> jedno okno
    assert len(o) == 1
    assert (o.meta[0]["seq_od"], o.meta[0]["seq_do"]) == (5, 8)
    assert any("kratsi" in p["dovod"] for p in o.preskocene)


def test_kratka_session_nedava_okno_a_je_v_preskocenych():
    # realny retazec z 2026-09-18 ma 6 snimok; pri vychodzej dlzke 16 z neho
    # ziadne okno nevznikne a musi to byt vidno, nie odhalit sa prazdnym polom
    o = okna(session("a", 6), dlzka=DLZKA_OKNA)
    assert len(o) == 0
    assert o.X.shape == (0, DLZKA_OKNA, len(BINY), len(PRIZNAKY))
    assert len(o.preskocene) == 1
    p = o.preskocene[0]
    assert p["session"] == "a" and p["n_snimok"] == 6
    assert "16" in p["dovod"]


def test_zmena_mnoziny_binov_je_chyba():
    snimky = session("a", 4) + [snimka("a", 4, biny=(0, 1, 2, 5))]
    with pytest.raises(WindowError) as e:
        okna(snimky, dlzka=2)
    assert "bin" in str(e.value).lower()


def test_vyber_sessions_je_po_sessions():
    o = okna(session("a", 8) + session("b", 8), dlzka=4)
    iba_a = o.vyber_sessions(["a"])
    assert len(iba_a) == 5
    assert set(iba_a.sessions) == {"a"}


# -- determinizmus -------------------------------------------------------


def test_determinizmus_dvoch_behov():
    s1 = session("a", 12) + session("b", 12)
    s2 = session("a", 12) + session("b", 12)
    o1 = okna(s1, dlzka=5)
    o2 = okna(s2, dlzka=5)
    assert np.array_equal(o1.X, o2.X)
    assert o1.meta == o2.meta


def test_poradie_na_vstupe_nemeni_vysledok():
    snimky = session("a", 10) + session("b", 10)
    o1 = okna(snimky, dlzka=4)
    o2 = okna(list(reversed(snimky)), dlzka=4)
    assert np.array_equal(o1.X, o2.X)
    assert o1.meta == o2.meta


# -- citanie sidecarov ---------------------------------------------------


def test_nacitanie_session_zo_sidecarov(tmp_path):
    d = tmp_path / "20260918_cpu_burn"
    d.mkdir()
    for seq in range(6):
        (d / ("snap_%06d.json" % seq)).write_text(
            json.dumps(sidecar_dict(seq, full=(seq == 0))))
    snimky = nacitaj_session(str(d))
    assert [s.seq for s in snimky] == list(range(6))
    assert snimky[0].session == "20260918_cpu_burn"
    assert snimky[0].full is True and snimky[1].full is False
    assert snimky[0].biny == BINY
    assert snimky[0].bin_bytes == BIN_BYTES
    o = okna(snimky, dlzka=3)
    assert o.X.shape == (4, 3, len(BINY), len(PRIZNAKY))


def test_sidecar_bez_bloku_features_je_chyba(tmp_path):
    d = sidecar_dict(0)
    del d["features"]
    p = tmp_path / "x.json"
    p.write_text(json.dumps(d))
    with pytest.raises(WindowError) as e:
        snimka_zo_sidecaru(str(p), "s")
    assert "features" in str(e.value)


def test_sidecar_s_chybajucim_priznakom_je_chyba(tmp_path):
    d = sidecar_dict(0)
    del d["features"]["bins"][2]["entropy_mean"]
    p = tmp_path / "x.json"
    p.write_text(json.dumps(d))
    with pytest.raises(WindowError) as e:
        snimka_zo_sidecaru(str(p), "s")
    assert "entropy_mean" in str(e.value)


def test_sidecar_s_inou_schemou_je_chyba(tmp_path):
    d = sidecar_dict(0)
    d["features"]["schema"] = "hyptcn3/perbin/2"
    p = tmp_path / "x.json"
    p.write_text(json.dumps(d))
    with pytest.raises(WindowError):
        snimka_zo_sidecaru(str(p), "s")


def test_sidecar_s_nesediacim_bins_total_je_chyba(tmp_path):
    d = sidecar_dict(0)
    d["features"]["bins_total"] = len(BINY) + 1
    p = tmp_path / "x.json"
    p.write_text(json.dumps(d))
    with pytest.raises(WindowError) as e:
        snimka_zo_sidecaru(str(p), "s")
    assert "bins_total" in str(e.value)


def test_biny_sa_zoradia_podla_indexu(tmp_path):
    d = sidecar_dict(0)
    d["features"]["bins"].reverse()
    p = tmp_path / "x.json"
    p.write_text(json.dumps(d))
    s = snimka_zo_sidecaru(str(p), "s")
    assert s.biny == BINY
    assert list(s.biny) == sorted(s.biny)


def test_prazdny_vstup_je_chyba():
    with pytest.raises(WindowError):
        okna([], dlzka=4)
