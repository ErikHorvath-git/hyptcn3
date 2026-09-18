"""
Testy citania snimok nad syntetickym obrazom zo selftestu.

Synteticky obraz je jediny vstup, ktory vieme porovnat bajt po bajte: k
retazcu .vmicd existuje aj obnoveny raw obraz, takze sa da overit, ze citanie
retazca na mieste da to iste, co obnova do suboru.
"""

import os

import pytest

from guestparse.image import (PAGE, RawImage, VmicdImage, chain_files,
                              open_image)


def test_hlavicka_vmicd(selftest_dir):
    parts = chain_files(selftest_dir)
    assert parts, "v selfteste nie je ziadny .vmicd"
    h = VmicdImage.header(parts[0])
    assert h["version"] == 1
    assert h["page_size"] == PAGE
    assert h["full"] is True, "prvy subor retazca musi byt plna snimka"
    assert h["records"] > 0
    for later in parts[1:]:
        assert VmicdImage.header(later)["full"] is False
        assert VmicdImage.header(later)["chain_id"] == h["chain_id"]


def test_chain_files_berie_jeden_retazec(selftest_dir):
    parts = chain_files(selftest_dir)
    chains = {VmicdImage.header(p)["chain_id"] for p in parts}
    assert len(chains) == 1, "zmiesane retazce by dali nekonzistentnu pamat"
    seqs = [VmicdImage.header(p)["seq"] for p in parts]
    assert seqs == sorted(seqs)
    # .raw v tom istom adresari sa do retazca nesmie dostat
    assert all(p.endswith(".vmicd") for p in parts)


def test_retazec_sa_zhoduje_s_obnovenym_obrazom(selftest_dir, selftest_restored):
    """Citanie retazca na mieste == 'vmicollect restore' bajt po bajte."""
    ref = RawImage(selftest_restored)
    img = open_image(selftest_dir)
    try:
        assert img.page_count() > 0
        different = 0
        for idx in range(ref.size // PAGE):
            if img.read(idx * PAGE, PAGE) != ref.read(idx * PAGE, PAGE):
                different += 1
        assert different == 0
    finally:
        img.close()
        ref.close()


def test_citanie_cez_hranicu_stranky(selftest_dir):
    img = open_image(selftest_dir)
    try:
        idx = sorted(img.index)[0]
        pa = idx * PAGE + PAGE - 8
        spoj = img.read(pa, 16)
        assert spoj == img.read(pa, 8) + img.read(pa + 8, 8)
    finally:
        img.close()


def test_chybajuca_stranka_je_nulova(selftest_dir):
    """Stranka, ktora v retazci nie je, sa cita ako nulova - nie ako chyba."""
    img = open_image(selftest_dir)
    try:
        chybajuca = max(img.index) + 1
        assert img.read(chybajuca * PAGE, PAGE) == b"\0" * PAGE
    finally:
        img.close()


def test_raw_mimo_rozsah(selftest_restored):
    img = RawImage(selftest_restored)
    try:
        assert img.read(img.size - 4, 8) is None
        assert img.read(-1, 8) is None
        assert img.read(0, 0) is None
    finally:
        img.close()


def test_nie_vmicd(tmp_path):
    p = tmp_path / "zle.vmicd"
    p.write_bytes(b"NIE JE TO ONO" + b"\0" * 64)
    with pytest.raises(ValueError):
        VmicdImage(str(p))


def test_prazdny_adresar(tmp_path):
    with pytest.raises(ValueError):
        open_image(str(tmp_path))


def test_open_image_raw(selftest_restored):
    img = open_image(selftest_restored)
    try:
        assert isinstance(img, RawImage)
        assert img.size == os.path.getsize(selftest_restored)
    finally:
        img.close()
