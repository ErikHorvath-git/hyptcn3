"""
Testy kontrolora soft real-time dokazu (H): falzifikovatelne kriteria
(latencia cyklu, zmeskane sloty, suvisle seq, p95 snímka->skóre).
"""

import json

import pytest

from scripts.soft_rt_check import skontroluj


def _side(seq, total_ms=100.0, skipped=0, chain=7):
    return {"seq": seq, "id": "x_%06d_stamp" % seq,
            "capture": {"total_ms": total_ms},
            "sched": {"lateness_s": 0.0, "skipped_before": skipped},
            "output": {"chain_id": chain}}


def test_cisty_retazec_je_ok():
    sides = [_side(i) for i in range(6)]
    res = skontroluj(sides, perioda_s=5.0)
    assert res["verdict"] == "OK"
    assert res["max_skipped_before"] == 0
    assert res["snimok"] == 6


def test_zmeskany_slot_je_neuspech():
    sides = [_side(i, skipped=(1 if i > 2 else 0)) for i in range(6)]
    res = skontroluj(sides, perioda_s=5.0)
    assert res["verdict"] == "NEUSPECH"
    assert "zmeskanych" in " ".join(res["chyby"])


def test_cyklus_nad_periodou_je_neuspech():
    sides = [_side(i, total_ms=(6000.0 if i == 3 else 100.0))
             for i in range(6)]
    res = skontroluj(sides, perioda_s=5.0)
    assert res["verdict"] == "NEUSPECH"
    assert res["cyklov_nad_periodou"] == 1


def test_diera_v_seq_je_neuspech():
    sides = [_side(i) for i in (0, 1, 2, 4, 5)]
    res = skontroluj(sides, perioda_s=5.0)
    assert res["verdict"] == "NEUSPECH"
    assert any("seq" in c for c in res["chyby"])


def test_p95_skore_nad_periodou_je_neuspech():
    sides = [_side(i) for i in range(6)]
    score = {"zaznamy": [{"latencia_od_snimky_ms": 6200.0}] * 20}
    res = skontroluj(sides, perioda_s=5.0, score_doc=score)
    assert res["verdict"] == "NEUSPECH"
    assert res["latencia_skore"]["p95_ms"] == 6200.0


def test_viac_retazcov_sa_nezmiesa():
    sides = [_side(i, chain=1) for i in range(4)]
    sides += [_side(i, chain=2) for i in range(2)]
    res = skontroluj(sides, perioda_s=5.0)
    assert res["verdict"] == "OK"
    assert res["snimok"] == 4            # najvacsi retazec
    assert res["retazcov_v_adresari"] == 2
