"""
Injekcny test detektora hookov v sys_call_table.

CO SA TU ROBI A CO NIE:
Test si urobi KOPIU snimky a v KOPII prepise jednu polozku tabulky volani
jadra na adresu v oblasti modulov. V hostovi sa NIC nemeni a ziadny rootkit
sa nikam neinstaluje - v tomto hostovi to ani nejde, nema gcc ani hlavicky
jadra. Ide teda o injekciu do datoveho suboru, nie o realny utok; dokazuje
sa tym iba to, ze detektor taky zapis najde a spravne ho pomenuje.

PRECO to tu musi byt: kontrola, ktora na cistom hostovi vzdy vrati nulu, je
na nerozoznanie od funkcie, ktora vzdy vracia nulu. Negativny aj pozitivny
pripad musia bezat oba.

KDE TO BEZI: nad malou snimkou verzionovanou v repe (tests/data/mini.vmicd),
teda aj v cerstvom klone bez pristupu k tomuto stroju, a navyse nad realnou
snimkou hosta, ked na stroji je (znacka 'realsnap').
"""

import os
import shutil

import pytest

from guestparse.checks import MODULES_VADDR, check_all, syscall_table
from guestparse.image import PAGE, open_image
from guestparse.view import GuestView

# Adresa, na ktoru sa polozka prepise: zaciatok oblasti modulov. Lezi mimo
# [_stext, _etext), teda presne tam, kam ukazuje klasicky hook.
FAKE_HANDLER = MODULES_VADDR + 0x1000

INJECT_INDEX = 59          # __NR_execve na x86_64 - typicky ciel hookovania


def _copy_snapshot(src, dst_dir):
    """
    Kopia snimky (jedneho .vmicd alebo celeho retazca) do docasneho adresara.
    Original sa nikdy neotvara na zapis.
    """
    os.makedirs(dst_dir, exist_ok=True)
    if os.path.isfile(src):
        dst = os.path.join(dst_dir, os.path.basename(src))
        shutil.copyfile(src, dst)
        return dst
    for name in sorted(os.listdir(src)):
        if name.endswith(".vmicd"):
            shutil.copyfile(os.path.join(src, name),
                            os.path.join(dst_dir, name))
    return dst_dir


def _poke(path, pa, value):
    """
    Prepise 8 bajtov na fyzickej adrese pa v kopii snimky.

    Zaznam sa najde cez index, ktory si VmicdImage postavi pri otvoreni:
    dvojica (subor, offset) ukazuje priamo na obsah stranky, takze zapis je
    jeden seek a 8 bajtov - nic sa nerozbaluje.
    """
    with open_image(path) as img:
        idx, off = divmod(pa, img.page_size)
        loc = img.index.get(idx)
        assert loc is not None, "stranka 0x%x v snimke nie je" % pa
        subor, base = loc
    with open(subor, "r+b") as fh:
        fh.seek(base + off)
        fh.write(value.to_bytes(8, "little"))


def _injikuj_hook(clean_view, kopia, profile):
    """
    Spolocne telo pozitivneho pripadu: prepise polozku INJECT_INDEX v kopii,
    znovu ju otvori a overi, ze detektor nahlasi presne jeden hook.

    Vracia (nalez, vysledok check_all nad injikovanou kopiou).
    """
    table_va = clean_view.p.addr("sys_call_table")
    table_pa = clean_view.to_pa(table_va)
    assert table_pa is not None
    entry_pa = table_pa + INJECT_INDEX * 8
    # polozka nesmie prekrocit hranicu stranky, inak by sa pisalo do ineho zaznamu
    assert entry_pa // PAGE == (entry_pa + 7) // PAGE

    original = clean_view.u64(entry_pa)
    assert original and original != FAKE_HANDLER

    _poke(kopia, entry_pa, FAKE_HANDLER)

    img = open_image(kopia)
    try:
        view = GuestView(img, profile)
        assert view.resolve(), "posun jadra sa v injikovanej kopii nenasiel"
        res = syscall_table(view)
        assert res["entries"] == syscall_table(clean_view)["entries"]
        assert len(res["findings"]) == 1, res["findings"]
        f = res["findings"][0]
        assert f["check"] == "syscall_table"
        assert f["table"] == "sys_call_table"
        assert f["index"] == INJECT_INDEX
        assert f["value"] == FAKE_HANDLER
        assert f["in_module_area"] is True
        full = check_all(view)
        assert full["summary"]["syscall_hooks"] == 1
    finally:
        img.close()

    # zdrojova snimka ostala nedotknuta
    assert clean_view.u64(entry_pa) == original
    return f, full


# ------------------------------------------------- mala snimka v repe


def test_mini_bez_zasahu_nema_hooky(mini_view):
    """Negativny pripad nad malou snimkou: tabulka volani musi byt cista."""
    res = syscall_table(mini_view)
    assert res["available"], res["reason"]
    assert res["entries"] >= 300, res["entries"]
    assert res["findings"] == [], res["findings"]
    assert check_all(mini_view)["summary"]["syscall_hooks"] == 0


def test_mini_injikovany_hook_sa_najde(mini_path, tmp_path, profile):
    """
    Pozitivny pripad nad malou snimkou: v kopii sa prepise jedna polozka
    tabulky na adresu v oblasti modulov. Detektor musi nahlasit presne jeden
    nalez a uviest index prepisanej polozky.
    """
    img = open_image(mini_path)
    clean_view = GuestView(img, profile)
    assert clean_view.resolve()
    try:
        kopia = _copy_snapshot(mini_path, str(tmp_path / "injikovana"))
        f, full = _injikuj_hook(clean_view, kopia, profile)
    finally:
        img.close()
    assert f["index"] == INJECT_INDEX
    # Mala snimka drzi iba stranky, ktore testy citaju - krizove kontrole
    # procesov a modulov v nej stranky chybaju a MUSIA sa priznat ako
    # neuzavrete, nie vydavat za ciste.
    assert set(full["summary"]["inconclusive"]) == {"process_cross_view",
                                                    "modules"}


def test_mini_snimka_sa_nemeni(mini_path, mini_manifest):
    """Poistka: subor v repe musi sediet s manifestom (testy ho neprepisuju)."""
    import hashlib
    h = hashlib.sha256()
    with open(mini_path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    assert h.hexdigest() == mini_manifest["result"]["sha256"]
    assert os.path.getsize(mini_path) == mini_manifest["result"]["bytes"]


# ------------------------------------------------- realna snimka hosta


@pytest.fixture(scope="module")
def clean_copy(tmp_path_factory, profile, val_dir):
    """Nedotknuta kopia realnej snimky - negativny pripad."""
    dst = _copy_snapshot(val_dir, str(tmp_path_factory.mktemp("cista")))
    img = open_image(dst)
    view = GuestView(img, profile)
    if not view.resolve():
        pytest.fail("posun jadra sa v kopii nenasiel")
    yield dst, view
    img.close()


def test_kopia_bez_zasahu_nema_nalezy(clean_copy):
    """Negativny pripad: cista kopia realnej snimky musi dat 0 nalezov."""
    _, view = clean_copy
    res = syscall_table(view)
    assert res["available"], res["reason"]
    assert res["entries"] >= 300, res["entries"]
    assert res["findings"] == [], res["findings"]

    full = check_all(view)
    assert full["summary"]["syscall_hooks"] == 0
    assert full["summary"]["inconclusive"] == [], full["summary"]


def test_injikovany_hook_sa_najde(clean_copy, tmp_path_factory, profile):
    """Pozitivny pripad nad realnou snimkou; ostatne kontroly sa menit nesmu."""
    src, clean_view = clean_copy
    dst = _copy_snapshot(src, str(tmp_path_factory.mktemp("injikovana")))
    f, full = _injikuj_hook(clean_view, dst, profile)
    assert f["index"] == INJECT_INDEX
    assert full["summary"]["process_cross_view_findings"] == 0
    assert full["summary"]["module_findings"] == 0
    assert full["finding_count"] == 1
    assert full["summary"]["inconclusive"] == []


def test_original_snimka_je_len_na_citanie(val_dir):
    """Poistka: test nesmie zapisovat do /var/tmp, aj keby sa kod zmenil."""
    if os.geteuid() == 0:
        pytest.skip("pod rootom je zapis mozny vzdy - poistka nema co overit")
    for name in sorted(os.listdir(val_dir)):
        if not name.endswith(".vmicd"):
            continue
        with pytest.raises(PermissionError):
            open(os.path.join(val_dir, name), "r+b").close()
