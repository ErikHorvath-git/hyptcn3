"""
Testy 4. invariantu: text jadra sa po boote nesmie menit (blok A3).

Kontrola porovnava SHA-256 stranok [_stext, _etext) s baseline z cistej
snimky. Testuje sa:

  - porovnavacia logika na syntetickom view (zmena -> nalez, chybajuca
    stranka -> neuzavreta kontrola, presny vypis najblizsieho symbolu),
  - citanie baseline z profilu a jej validacia (schema, boot),
  - realna cesta na malej snimke v repe: baseline z neuplnej snimky sa
    ODMIETNE (nie ticho oreze) a injekcia do kopy snimky sa najde,
  - check_all hlasi 4. kontrolu v summary.
"""

import hashlib
import json
import os
import shutil

import pytest

from guestparse import checks
from guestparse.image import PAGE, open_image
from guestparse.view import GuestView


# ------------------------------------------------ synteticky view (logika)

class StubImg:
    """Obraz pamate: stranky v dict pa -> bytes (4096)."""

    def __init__(self, pages):
        self.pages = pages

    def read(self, pa, n):
        b = self.pages.get(pa)
        if b is None or len(b) < n:
            return None
        return b[:n]

    def page_present(self, pa):
        return pa in self.pages


class StubProf:
    """Profil: _stext=0, _etext=3 stranky; meta a dir pre load_text_baseline."""

    def __init__(self, dir=None):
        self.sym = {"_stext": 0x1000000, "_etext": 0x1000000 + 3 * PAGE,
                    "__start___jump_table": 0x5000000,
                    "__stop___jump_table": 0x5000000}   # prazdna tabulka
        self.meta = {"boot_id": "test-boot"}
        self.dir = dir or ""

    def addr(self, name):
        return self.sym.get(name)


class StubView:
    def __init__(self, pages, prof):
        self.img = StubImg(pages)
        self.p = prof

    def to_pa(self, va):
        return va            # identita - stranka va == pa


def _page(seed, size=PAGE):
    return bytes([(seed + i) % 256 for i in range(size)])


def _baseline_for(pages):
    return {"schema": checks.TEXT_BASELINE_SCHEMA, "page_size": PAGE,
            "stext": 0x1000000, "etext": 0x1000000 + 3 * PAGE,
            "boot_id": "test-boot",
            "mask_rel": [], "mask_sites": 0,   # stub: ziadne static keys
            "pages": [{"va": va, "sha256": hashlib.sha256(pages[va]).hexdigest()}
                      for va in sorted(pages)]}


def test_zmenena_stranka_textu_je_nalez():
    stext = 0x1000000
    pages = {stext: _page(1), stext + PAGE: _page(2), stext + 2 * PAGE: _page(3)}
    baseline = _baseline_for(pages)

    view = StubView(pages, StubProf())
    res = checks.text_integrity(view, baseline)
    assert res["available"] and res["conclusive"], res
    assert res["findings"] == [], res["findings"]

    zmenene = dict(pages)
    zmenene[stext + PAGE] = _page(99)
    view = StubView(zmenene, StubProf())
    res = checks.text_integrity(view, baseline)
    assert res["conclusive"], res
    assert len(res["findings"]) == 1, res["findings"]
    f = res["findings"][0]
    assert f["check"] == "text_integrity"
    assert f["va"] == stext + PAGE
    assert "lisi" in f["note"]


def test_chybajuca_stranka_je_neuzavreta_kontrola():
    """Hook v stranke, ktora v snimke nie je, je neviditelny - nula nalezov
    z takej snimky preto nic nedokazuje."""
    stext = 0x1000000
    uplne = {stext: _page(1), stext + PAGE: _page(2), stext + 2 * PAGE: _page(3)}
    baseline = _baseline_for(uplne)

    view = StubView({stext: _page(1), stext + 2 * PAGE: _page(3)}, StubProf())
    res = checks.text_integrity(view, baseline)
    assert res["available"] and not res["conclusive"]
    assert res["pages_total"] == 3
    assert res["pages_checked"] == 2
    assert res["pages_missing"] == 1
    assert res["findings"] == []
    assert "nic nedokazuje" in res["reason"]


def test_bez_baseline_je_kontrola_nedostupna():
    view = StubView({}, StubProf())
    res = checks.text_integrity(view, None)
    assert not res["available"]
    assert "text_baseline.json" in res["reason"]


def test_baseline_z_ineho_bootu_sa_odmietne():
    stext = 0x1000000
    pages = {stext: _page(1)}
    baseline = _baseline_for(pages)
    baseline["etext"] = 0x2000000        # iny rozsah = iny boot
    view = StubView(pages, StubProf())
    res = checks.text_integrity(view, baseline)
    assert not res["available"]
    assert "ine jadro" in res["reason"]


def test_baseline_sa_posuva_s_preukotvenim():
    """Baseline je na OBSAH textu, nie na boot: po preukotveni (A2) sa jej
    adresy posunu o rovnaky rozdiel ako profil a kontrola musi fungovat."""
    # baseline z bootu A: stext 0x1000000, stranka na VA 0x1000000
    pages_a = {0x1000000: _page(1)}
    baseline = _baseline_for(pages_a)
    baseline["stext"] = 0x1000000
    baseline["etext"] = 0x1010000
    # profil po preukotveni na boot B: stext 0x1200000 (delta +0x200000)
    prof = StubProf()
    prof.sym["_stext"] = 0x1200000
    prof.sym["_etext"] = 0x1210000
    view = StubView({0x1200000: _page(1)}, prof)
    view.reanchored = 0x200000
    res = checks.text_integrity(view, baseline)
    assert res["available"] and res["conclusive"], res
    assert res["pages_checked"] == 1
    assert res["findings"] == [], res["findings"]

    # zmeneny obsah na posunutej adrese -> nalez s boot-B adresou
    view2 = StubView({0x1200000: _page(99)}, prof)
    view2.reanchored = 0x200000
    res2 = checks.text_integrity(view2, baseline)
    assert len(res2["findings"]) == 1, res2
    f = res2["findings"][0]
    assert f["va"] == 0x1200000
    assert f["baseline_va"] == 0x1000000


def test_check_all_obsahuje_text_integrity(mini_view):
    """check_all musi 4. kontrolu spustit a priznat jej stav do summary.

    Profil v repe ma text_baseline.json (2026-10-05), takze na mini snimke
    je kontrola DOSTUPNA, ale neuzavreta (mini neobsahuje vsetky stranky
    textu) - nula z nej nic nedokazuje. Nedostupna zostava len bez
    baseline (kryje StubProf test vyssie)."""
    res = checks.check_all(mini_view)
    assert "text_integrity" in res
    assert res["summary"]["text_integrity_findings"] == 0
    # mini neobsahuje __jump_table - bez nej sa static keys nedaju
    # maskovat, takze 4. kontrola je nedostupna a v zozname neuzavretych
    assert res["text_integrity"]["available"] is False
    assert "text_integrity" in res["summary"]["inconclusive"]


# ------------------------------------------------- baseline z profilu

def test_load_text_baseline_z_profilu(tmp_path):
    stext, etext = 0x1000000, 0x1001000
    prof = StubProf(dir=str(tmp_path))
    prof.sym["_stext"], prof.sym["_etext"] = stext, etext
    doc = {"schema": checks.TEXT_BASELINE_SCHEMA, "stext": stext,
           "etext": etext, "pages": [{"va": stext, "sha256": "a" * 64}]}
    (tmp_path / checks.TEXT_BASELINE_FILE).write_text(json.dumps(doc))

    got = checks.load_text_baseline(prof)
    assert got == doc


def test_load_text_baseline_odmietne_ciudziu_schemu(tmp_path):
    prof = StubProf(dir=str(tmp_path))
    (tmp_path / checks.TEXT_BASELINE_FILE).write_text(
        json.dumps({"schema": "hyptcn3/nieco-ine/1", "pages": []}))
    with pytest.raises(ValueError):
        checks.load_text_baseline(prof)


# ------------------------------------------------- realna cesta na mini

def test_baseline_z_neuplnej_snimky_sa_odmietne(mini_view):
    """Mala snimka drzi iba stranky, ktore citaju testy - textu jadra v nej
    je len zlomok. Baseline z nej NESMIE vzniknut (ticho by kontrolu
    zuzila), musi to povedat chybou."""
    with pytest.raises(ValueError) as e:
        checks.build_text_baseline(mini_view)
    assert "stranok textu v snimke nie je" in str(e.value)


def test_mini_injikovat_do_textu_sa_najde(mini_path, tmp_path, profile):
    """
    Pozitivny pripad nad malou snimkou: prepis v texte jadra musi kontrola
    (d) najst - presne to, co kontrola (a) nevie, ked hook ukazuje dovnutra
    textu. Injekcia ide do KOPIE snimky, original sa nemeni.
    """
    img = open_image(mini_path)
    clean_view = GuestView(img, profile)
    assert clean_view.resolve()
    try:
        # najdi prvu stranku textu, ktoru mini snimka naozaj obsahuje
        stext = profile.addr("_stext")
        etext = profile.addr("_etext")
        va = pa = None
        for k in range(stext, etext, PAGE):
            kpa = clean_view.to_pa(k)
            if kpa is not None and img.page_present(kpa):
                va, pa = k, kpa
                break
        if pa is None:
            pytest.skip("mini snimka neobsahuje ziadnu stranku textu jadra")
        # baseline z cistej snimky: rozsah = cely text (ako realna baseline),
        # ale zaznam len o tejto jednej stranke - ostatne stranky sa tvaria
        # ako "v snimke nie su", co je pravda (mini je orezana snimka)
        b = img.read(pa, PAGE)
        assert b is not None
        baseline = {"schema": checks.TEXT_BASELINE_SCHEMA, "page_size": PAGE,
                    "stext": stext, "etext": etext,
                    "boot_id": (profile.meta or {}).get("boot_id"),
                    "pages": [{"va": va,
                               "sha256": hashlib.sha256(b).hexdigest()}]}

        kopia = str(tmp_path / "kopia")
        os.makedirs(kopia)
        kopia_file = os.path.join(kopia, os.path.basename(mini_path))
        shutil.copyfile(mini_path, kopia_file)
        with open_image(kopia_file) as img2:
            idx, off = divmod(pa, img2.page_size)
            loc = img2.index.get(idx)
            assert loc is not None, "stranka 0x%x v snimke nie je" % pa
            subor, base = loc
        with open(subor, "r+b") as fh:
            fh.seek(base + off)
            fh.write(b"\x90" * 8)        # prepis priamo v texte

        img2 = open_image(kopia_file)
        try:
            view = GuestView(img2, profile)
            assert view.resolve()
            res = checks.text_integrity(view, baseline)
            assert len(res["findings"]) == 1, res
            assert res["findings"][0]["va"] == va
            assert res["findings"][0]["check"] == "text_integrity"
        finally:
            img2.close()
    finally:
        img.close()


def test_mini_check_all_bez_baseline_je_neuzavreta(mini_view):
    """Mini snimka neobsahuje cele tabulky ani vsetky stranky textu -
    krizove kontroly aj 4. kontrola MUSIA byt v zozname neuzavretych.
    (Mini je synteticky rez: prechody sa roztrhnu a jeho stranky v rozsahu
    textu nesedia s realnou baseline - preto sa tu priznava neuzavretost,
    nie cistota.)"""
    full = checks.check_all(mini_view)
    assert "text_integrity" in full["summary"]["inconclusive"]


# ------------------------------------------------- realna snimka hosta

@pytest.fixture(scope="module")
def real_clean(val_dir, profile, tmp_path_factory):
    """Nedotknuta kopia realnej snimky + view nad nou (znacka realsnap)."""
    dst = str(tmp_path_factory.mktemp("text-cista"))
    os.makedirs(dst)
    for name in sorted(os.listdir(val_dir)):
        if name.endswith(".vmicd"):
            shutil.copyfile(os.path.join(val_dir, name),
                            os.path.join(dst, name))
    img = open_image(dst)
    view = GuestView(img, profile)
    if not view.resolve():
        pytest.fail("posun jadra sa v kopii nenasiel")
    yield dst, view
    img.close()


def test_real_cista_snimka_sedi_s_viastnou_baseline(real_clean):
    """Negativny pripad: baseline z cistej snimky proti tej istej snimke
    musi dat 0 nalezov a uzavretu kontrolu."""
    _, view = real_clean
    baseline = checks.build_text_baseline(view)
    res = checks.text_integrity(view, baseline)
    assert res["available"] and res["conclusive"], res
    assert res["findings"] == [], res["findings"]
    assert res["pages_checked"] == res["pages_total"] > 0


def test_real_injikovany_text_sa_najde(real_clean, tmp_path_factory, profile):
    """Pozitivny pripad nad realnou snimkou: prepis v texte = nalez s
    adresou stranky; zvysok textu ostane cisty."""
    src, clean_view = real_clean
    baseline = checks.build_text_baseline(clean_view)

    dst = str(tmp_path_factory.mktemp("text-inj"))
    os.makedirs(dst)
    for name in sorted(os.listdir(src)):
        if name.endswith(".vmicd"):
            shutil.copyfile(os.path.join(src, name),
                            os.path.join(dst, name))

    # prepis 8 bajtov na zaciatku _stext - typicke miesto inline hooku
    stext = profile.addr("_stext")
    pa = clean_view.to_pa(stext)
    assert pa is not None
    img2 = open_image(dst)
    idx, off = divmod(pa, img2.page_size)
    loc = img2.index.get(idx)
    assert loc is not None, "stranka 0x%x v snimke nie je" % pa
    img2.close()
    with open(loc[0], "r+b") as fh:
        fh.seek(loc[1] + off)
        fh.write(b"\x90" * 8)

    img2 = open_image(dst)
    try:
        view = GuestView(img2, profile)
        assert view.resolve()
        res = checks.text_integrity(view, baseline)
        assert res["conclusive"], res
        assert len(res["findings"]) == 1, res["findings"]
        assert res["findings"][0]["va"] == stext
        assert res["findings"][0]["nearest_symbol"] == "_stext"
    finally:
        img2.close()
