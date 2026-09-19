"""
Testy diagnozy "profil je z ineho startu jadra" (KASLR).

PRECO TENTO SUBOR: 2026-09-19 sa hostujuca VM restartovala a profil v repe
zostal z predchadzajuceho bootu. Nastroj neklamal - vysledok oznacil ako
NEUPLNY a krizova kontrola prekladu spadla - ale pricinu nepomenoval, takze
tichy rozdiel medzi "snimka je neuplna" a "dal si mi profil z inej snimky"
musel clovek uhadnut. Tieto testy drzia, ze sa pomenuje.

Ako sa nesulad v teste vyroba: z profilu v repe sa spravi kopia, v ktorej su
VSETKY adresy jadra posunute o rovnaku konstantu. Presne to robi KASLR pri
kazdom starte - posuva cely obraz jadra naraz - takze kopia sa sprava ako
kallsyms z ineho bootu toho isteho jadra: sken banneru posun dopocita,
init_task.comm sedi, ale tabulky stranok o tychto virtualnych adresach nevedia.
Test tak nepotrebuje druhu snimku ani odlozeny stary profil.
"""

import os

import pytest

from guestparse import cli
from guestparse.image import open_image
from guestparse.profile import Profile
from guestparse.view import GuestView

KERNEL_VA_MIN = 0xFFFFFFFF80000000
POSUN = 0x10000000          # 256 MiB: mimo obrazu jadra, stale kanonicka adresa


def _profil_z_ineho_bootu(zdroj, ciel):
    """Kopia profilu s adresami jadra posunutymi o konstantu (ako iny boot)."""
    os.makedirs(ciel, exist_ok=True)
    with open(os.path.join(zdroj, "kallsyms.txt")) as fh, \
            open(os.path.join(ciel, "kallsyms.txt"), "w") as out:
        for ln in fh:
            p = ln.split()
            try:
                addr = int(p[0], 16)
            except (IndexError, ValueError):
                out.write(ln)
                continue
            if addr >= KERNEL_VA_MIN:
                p[0] = "%016x" % (addr + POSUN)
                out.write(" ".join(p) + "\n")
            else:
                out.write(ln)                    # percpu symboly sa neposuvaju
    # BTF sa nekopiruje (9 MiB): offsety poli su viazane na verziu jadra, nie
    # na boot - prave to je rozdiel, ktory test predvadza
    os.symlink(os.path.abspath(os.path.join(zdroj, "btf.txt")),
               os.path.join(ciel, "btf.txt"))
    return ciel


@pytest.fixture(scope="module")
def profil_iny_boot(profile_dir, tmp_path_factory):
    return _profil_z_ineho_bootu(
        profile_dir, str(tmp_path_factory.mktemp("prof-iny-boot")))


@pytest.fixture(scope="module")
def pohlad_iny_boot(mini_path, profil_iny_boot):
    img = open_image(mini_path)
    view = GuestView(img, Profile.from_dir(profil_iny_boot))
    yield view, view.resolve()
    img.close()


# --------------------------------------------------- co sa deje pri nesulade


def test_posun_sa_aj_tak_najde(pohlad_iny_boot):
    """
    Jadro veci: so starym profilom sa posun NAJDE, takze cast vystupu vyzera
    normalne. Prave preto sa nesulad nesmie hlasit az tym, ze sa prechod
    neuzavrie.
    """
    view, ok = pohlad_iny_boot
    assert ok is True
    assert view.ktext_shift is not None


def test_krizova_kontrola_spadne_na_nepritomnej_polozke(pohlad_iny_boot):
    view, _ = pohlad_iny_boot
    rows = {r["symbol"]: r for r in view.translation_check()}
    for name in ("linux_banner", "init_task"):
        r = rows[name]
        assert r["linear_pa"] is not None
        assert r["walk_pa"] is None
        assert r["match"] is False
        # nie "stranka chyba v snimke", ale "jadro tuto VA nemapuje"
        assert r["walk_reason_code"] == "chyba_polozka"
        assert r["walk_level"] in ("PGD", "PUD", "PMD", "PTE")


def test_diagnoza_pomenuje_pricinu_a_poradi_skript(pohlad_iny_boot):
    view, _ = pohlad_iny_boot
    text = view.profile_boot_mismatch()
    assert text, "nesulad profilu sa nepomenoval"
    assert "NESULAD PROFILU" in text
    assert "ineho startu jadra" in text
    assert "KASLR" in text
    assert "scripts/get_profile.sh" in text
    assert "BTF" in text                 # offsety poli reboot prezivaju


def test_spravny_profil_diagnozu_nevyvola(mini_view):
    """Nad profilom z toho isteho bootu sa nesmie hlasit nic."""
    assert mini_view.profile_boot_mismatch() is None
    assert all(r["match"] for r in mini_view.translation_check())


def test_chybajuca_tabulka_nie_je_nesulad(mini_view):
    """
    Adresa, ktoru mala snimka nepokryva, sa neprelozi - a to o profile
    nehovori nic. Diagnoza smie stat iba na symbole, ktory sa linearne
    precitat DA.
    """
    d = mini_view.walk_pa_detail(0xFFFFC90000000000)   # vmalloc, mimo vyrezu
    assert d["pa"] is None
    assert mini_view.profile_boot_mismatch() is None


# ------------------------------------------------------- navratove kody CLI


def test_info_konci_kodom_5(mini_path, profil_iny_boot, capsys):
    rc = cli.main(["info", "--snapshot", mini_path,
                   "--profile", profil_iny_boot])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_PROFILE_MISMATCH == 5
    assert "NESULAD PROFILU" in out
    assert "NEZHODA" in out


def test_ps_varuje_a_konci_kodom_5(mini_path, profil_iny_boot, capsys):
    """
    Podprikaz nad prechodom zoznamu vysledok vypise (je oznaceny NEUPLNE),
    ale diagnoza ide na stderr a kod je nenulovy - inak by sa v skripte
    stratila.
    """
    rc = cli.main(["ps", "--snapshot", mini_path,
                   "--profile", profil_iny_boot])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_PROFILE_MISMATCH
    assert "NESULAD PROFILU" in err


def test_kod_5_prebije_nalez_aj_neuzavretost(mini_path, profil_iny_boot,
                                             capsys):
    """
    Nalez zo zleho profilu nalezom nie je: chyba vstupu prebija aj kod 1,
    aj kod 4.
    """
    rc = cli.main(["checks", "--snapshot", mini_path,
                   "--profile", profil_iny_boot])
    capsys.readouterr()
    assert rc == cli.EXIT_PROFILE_MISMATCH


def test_validate_sa_pri_nesulade_ani_nespusti(mini_path, profil_iny_boot,
                                               tmp_path, capsys):
    """Zo zleho profilu sa subor v data/results nevyraba."""
    out = tmp_path / "validate.json"
    rc = cli.main(["validate", "--snapshot", mini_path,
                   "--profile", profil_iny_boot,
                   "--ps-before", os.devnull, "--ps-after", os.devnull,
                   "--out", str(out)])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_PROFILE_MISMATCH
    assert not out.exists()
    assert "nezapisal" in err


# ------------------------------------------------------------ povod profilu


def test_profil_v_repe_vie_z_ktoreho_bootu_je(profile, profile_dir):
    """
    boot.json zapisuje scripts/get_profile.sh. Bez neho sa nesulad da zistit
    az zlyhanim prechodu; s nim staci porovnat s
    /proc/sys/kernel/random/boot_id hosta.
    """
    assert os.path.isfile(os.path.join(profile_dir, "boot.json")), (
        "profil v repe nema boot.json - obnov ho cez scripts/get_profile.sh")
    for kluc in ("boot_id", "captured", "guest_kernel"):
        assert profile.meta.get(kluc), "boot.json nema %s" % kluc
    assert profile.meta["boot_id"] in profile.describe()


def test_profil_bez_boot_json_to_prizna(profil_iny_boot):
    prof = Profile.from_dir(profil_iny_boot)
    assert prof.meta == {}
    assert "nema boot.json" in prof.describe()
