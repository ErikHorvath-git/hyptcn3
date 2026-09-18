"""
Testy overenia retazca .vmicd.

PRECO to musi byt overene: delta nesie iba stranky, ktore sa od predchadzajucej
snimky zmenili. Ked v retazci chyba delta uprostred, stranky, ktore mala
priniest, ostanu v stave spred nej - vysledkom je pamat, ktora v hostovi nikdy
naraz neexistovala. Take citanie nesmie ticho prejst.

Hlavicky sa tu skladaju rucne (synteticke subory s vymyslenym obsahom
stranok), lebo overenie retazca je kontrola formatu a poradia - na to realne
bajty netreba. Nad realnym retazcom /var/tmp/vmic-delta bezi navyse test,
ktory z kopie odstrani prostrednu deltu (znacka 'realsnap').

Semantika sa drzi vmic_delta_restore() vo vmicollect/src/writer_delta.c.
"""

import os
import struct

import pytest

from guestparse.image import (PAGE, VMICD_FLAG_FULL, VMICD_HDR, VMICD_MAGIC,
                              VMICD_VERSION, ChainError, VmicdImage,
                              chain_files, open_image, validate_chain)

SIG = 0xA5A5A5A5A5A5A5A5
MEMSIZE = 64 * PAGE


def _vmicd(path, chain_id, seq, full, pages, page_size=PAGE, region_sig=SIG,
           version=VMICD_VERSION, memsize=MEMSIZE):
    """Zapise synteticky .vmicd; `pages` je {index stranky: bajty}."""
    hdr = struct.pack("<8sIIQQQQQQ", VMICD_MAGIC, version, page_size,
                      chain_id, seq, memsize, len(pages),
                      VMICD_FLAG_FULL if full else 0, region_sig)
    with open(path, "wb") as fh:
        fh.write(hdr)
        for idx in sorted(pages):
            fh.write(struct.pack("<Q", idx))
            fh.write(pages[idx].ljust(page_size, b"\0")[:page_size])
    return path


def _retazec(d, seqs=(0, 1, 2)):
    """Retazec: seq 0 je plna snimka, ostatne su delty tej istej stranky."""
    out = []
    for s in seqs:
        p = _vmicd(os.path.join(str(d), "snap_%06d.vmicd" % s),
                   chain_id=7, seq=s, full=(s == 0),
                   pages={0: b"baseline" if s == 0 else b"delta %d" % s,
                          s + 1: b"stranka %d" % s})
        out.append(p)
    return out


# ------------------------------------------------------------- platny retazec


def test_platny_retazec_sa_otvori(tmp_path):
    _retazec(tmp_path)
    img = open_image(str(tmp_path))
    try:
        assert img.chain_id == 7
        assert (img.seq_from, img.seq_to) == (0, 2)
        assert img.full_baseline is True
        # neskorsi zaznam prepisuje starsi
        assert img.read(0, 7) == b"delta 2"
        assert img.page_count() == 4
    finally:
        img.close()


def test_chain_files_je_zoradeny_podla_seq(tmp_path):
    _retazec(tmp_path)
    parts = chain_files(str(tmp_path))
    seqs = [VmicdImage.header(p)["seq"] for p in parts]
    assert seqs == [0, 1, 2]


# ---------------------------------------------------- chybajuca cast retazca


def test_chybajuca_delta_uprostred_sa_odmietne(tmp_path):
    """Jadro nalezu: retazec bez prostrednej delty sa nesmie otvorit."""
    parts = _retazec(tmp_path)
    os.remove(parts[1])                       # zmizne seq=1
    with pytest.raises(ChainError) as exc:
        open_image(str(tmp_path))
    msg = str(exc.value)
    assert "chyba snimka seq=1" in msg
    assert "--chain-until 0" in msg           # cesta k pouzitelnemu vysledku


def test_chain_until_odreze_retazec_pred_dierou(tmp_path):
    """Ked chyba delta uprostred, prefix po posledne suvisle seq sa otvorit da."""
    parts = _retazec(tmp_path)
    os.remove(parts[1])
    img = open_image(str(tmp_path), until_seq=0)
    try:
        assert img.seq_to == 0
        assert img.read(0, 8) == b"baseline"
    finally:
        img.close()


def test_retazec_bez_plnej_snimky_sa_odmietne(tmp_path):
    parts = _retazec(tmp_path)
    os.remove(parts[0])                       # zmizne baseline
    with pytest.raises(ChainError) as exc:
        open_image(str(tmp_path))
    msg = str(exc.value)
    assert "nezacina plnou snimkou" in msg
    assert "baseline" in msg


def test_samotna_delta_ako_subor_sa_odmietne(tmp_path):
    parts = _retazec(tmp_path)
    with pytest.raises(ChainError):
        open_image(parts[1])


# ------------------------------------------------------- nekonzistentny retazec


def test_ina_velkost_stranky_v_retazci(tmp_path):
    _retazec(tmp_path, seqs=(0,))
    _vmicd(os.path.join(str(tmp_path), "snap_000001.vmicd"), chain_id=7, seq=1,
           full=False, pages={0: b"x"}, page_size=8192)
    with pytest.raises(ChainError) as exc:
        open_image(str(tmp_path))
    assert "velkost stranky" in str(exc.value)


def test_iny_region_sig_v_retazci(tmp_path):
    _retazec(tmp_path, seqs=(0,))
    _vmicd(os.path.join(str(tmp_path), "snap_000001.vmicd"), chain_id=7, seq=1,
           full=False, pages={0: b"x"}, region_sig=SIG ^ 0xFF)
    with pytest.raises(ChainError) as exc:
        open_image(str(tmp_path))
    assert "konfiguraciou oblasti" in str(exc.value)


def test_dve_casti_s_rovnakym_seq(tmp_path):
    _retazec(tmp_path, seqs=(0, 1))
    _vmicd(os.path.join(str(tmp_path), "snap_000001b.vmicd"), chain_id=7,
           seq=1, full=False, pages={0: b"x"})
    with pytest.raises(ChainError) as exc:
        open_image(str(tmp_path))
    assert "rovnakym seq=1" in str(exc.value)


def test_zmiesane_chain_id(tmp_path):
    a = _vmicd(os.path.join(str(tmp_path), "a.vmicd"), chain_id=7, seq=0,
               full=True, pages={0: b"a"})
    b = _vmicd(os.path.join(str(tmp_path), "b.vmicd"), chain_id=9, seq=1,
               full=False, pages={0: b"b"})
    with pytest.raises(ChainError) as exc:
        VmicdImage([a, b])
    assert "chain_id" in str(exc.value)
    # v adresari sa vyberie iba jeden retazec - ten najnovsi, a ten je bez
    # baseline, takze sa tiez odmietne
    with pytest.raises(ChainError):
        open_image(str(tmp_path))


def test_nezoradene_subory_sa_odmietnu(tmp_path):
    """
    Na poradi zalezi: neskorsi zaznam prepisuje starsi. Zoznam, v ktorom seq
    klesa, by dal stav, ktory v hostovi nikdy nebol.
    """
    parts = _retazec(tmp_path)
    with pytest.raises(ChainError) as exc:
        VmicdImage([parts[0], parts[1], parts[0]])
    assert "zoradene" in str(exc.value)


# --------------------------------------------------------- poskodene subory


def test_skrateny_subor_sa_odmietne(tmp_path):
    parts = _retazec(tmp_path, seqs=(0,))
    with open(parts[0], "r+b") as fh:
        fh.truncate(VMICD_HDR + 8 + PAGE // 2)     # polovica druheho zaznamu
    with pytest.raises(ChainError) as exc:
        open_image(str(tmp_path))
    assert "skrateny" in str(exc.value)


def test_nepodporovana_verzia(tmp_path):
    p = _vmicd(os.path.join(str(tmp_path), "v2.vmicd"), chain_id=7, seq=0,
               full=True, pages={0: b"x"}, version=2)
    with pytest.raises(ValueError) as exc:
        VmicdImage(p)
    assert "verzia formatu 2" in str(exc.value)


def test_necitatelny_subor_sa_nahlasi(tmp_path, capsys):
    """Subor, ktory sa preskoci, sa musi ozvat na stderr - nie zmiznut."""
    _retazec(tmp_path, seqs=(0,))
    (tmp_path / "smeti.vmicd").write_bytes(b"toto nie je snimka" + b"\0" * 64)
    parts = chain_files(str(tmp_path))
    assert len(parts) == 1
    err = capsys.readouterr().err
    assert "smeti.vmicd" in err and "preskakujem" in err


def test_prazdny_adresar_sa_odmietne(tmp_path):
    with pytest.raises(ChainError):
        open_image(str(tmp_path))


def test_validate_chain_na_prazdnom_zozname():
    with pytest.raises(ChainError):
        validate_chain([])


# ------------------------------------------------- realny retazec z /var/tmp


def _symlink_chain(src, dst, vynechaj=()):
    """
    Kopia retazca cez symbolicke odkazy (plna snimka ma 276 MiB, kopirovat
    ju netreba - overenie retazca cita iba hlavicky). `vynechaj` je zoznam
    seq, ktore sa do kopie nedostanu.
    """
    os.makedirs(dst, exist_ok=True)
    for name in sorted(os.listdir(src)):
        if not name.endswith(".vmicd"):
            continue
        p = os.path.join(src, name)
        if VmicdImage.header(p)["seq"] in vynechaj:
            continue
        os.symlink(p, os.path.join(dst, name))
    return dst


def test_realny_retazec_je_suvisly(delta_dir, tmp_path):
    kopia = _symlink_chain(delta_dir, str(tmp_path / "cely"))
    parts = chain_files(kopia)
    seqs = [VmicdImage.header(p)["seq"] for p in parts]
    assert seqs == list(range(len(seqs))), seqs
    assert VmicdImage.header(parts[0])["full"] is True


def test_realny_retazec_bez_prostrednej_delty_sa_odmietne(delta_dir, tmp_path):
    """
    Z kopie realneho retazca sa odstrani prostredna delta (seq=2). Balik to
    musi odmietnut a povedat, ktora cast chyba - nie vratit starsi obsah
    stranok, ktore mala priniest.
    """
    kopia = _symlink_chain(delta_dir, str(tmp_path / "bez_seq2"), vynechaj=(2,))
    with pytest.raises(ChainError) as exc:
        open_image(kopia)
    msg = str(exc.value)
    assert "chyba snimka seq=2" in msg, msg
    assert "--chain-until 1" in msg, msg
