"""
Testy nacitania per-bin bloku zo sidecaru (blok D): perbin_zo_sidecaru().

Vstupy su synteticke sidecary v tmp_path, takze testy bezia vzdy.
"""

import json

import pytest

from features.windows import WindowError, perbin_zo_sidecaru


# -- loader zo sidecaru -----------------------------------------------------


def test_perbin_zo_sidecaru_cita_a_radi_biny(tmp_path):
    doc = {
        "features": {
            "bin_bytes": 16 * 1024 * 1024,
            "bins": [
                {"bin": 9, "gpa": 0, "pages_total": 10, "pages_changed": 2,
                 "changed_ratio": 0.2, "zero_ratio": 0.8, "entropy_mean": 1.5,
                 "has_changed": 1},
                {"bin": 1, "gpa": 0, "pages_total": 10, "pages_changed": 0,
                 "changed_ratio": 0.0, "zero_ratio": 1.0, "entropy_mean": 0.0,
                 "has_changed": 0},
            ],
        },
    }
    p = tmp_path / "side.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    biny, matica = perbin_zo_sidecaru(str(p))
    assert biny == (1, 9)
    assert matica.shape == (2, 4)
    assert list(matica[1]) == pytest.approx([0.2, 0.8, 1.5, 1.0])
    assert list(matica[0]) == pytest.approx([0.0, 1.0, 0.0, 0.0])


def test_perbin_zo_sidecaru_odmietne_blok_bez_bins(tmp_path):
    p = tmp_path / "side.json"
    p.write_text(json.dumps({"features": {}}), encoding="utf-8")
    with pytest.raises(WindowError) as e:
        perbin_zo_sidecaru(str(p))
    assert "bins" in str(e.value)


def test_perbin_zo_sidecaru_odmietne_entropiu_pri_has_changed_0(tmp_path):
    doc = {"features": {"bins": [
        {"bin": 0, "gpa": 0, "pages_total": 10, "pages_changed": 0,
         "changed_ratio": 0.0, "zero_ratio": 1.0, "entropy_mean": 0.5,
         "has_changed": 0}]}}
    p = tmp_path / "side.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(WindowError) as e:
        perbin_zo_sidecaru(str(p))
    assert "has_changed=0" in str(e.value)
