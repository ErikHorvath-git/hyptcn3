"""
Testy preukotvenia profilu po KASLR posune (blok A2).

Pred A2: snimka z ineho bootu nez profil = NESULAD + kod 5 a `ss` vrati 0
socketov (symbol socket_file_ops z profilu nesedi s ukazovatelmi v pamati).
Po A2: profil sa posunie o rozdiel baz (banner-anchored ktext_shift) a
pokracuje sa - prechod tabuliek sedi, `ss` rekonstruuje, `validate` bezi.

Klucovy vstup: data/sessions/20260918T154914Z_validate/snap - snimka z bootu
2026-09-18 15:49, profil v repe je z bootu 2026-09-19 10:30. Presne ten par,
na ktorom sa kod 5 predviedol v docs/AUDIT.md (posun -0x1aa00000).
"""

import json
import os
import subprocess
import sys

import pytest

from guestparse.profile import Profile
from guestparse.view import MODULES_VADDR, START_KERNEL_MAP, build_view

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
PROFILE_DIR = os.path.join(REPO, "profiles", "debian12-6.1.0-42-cloud-amd64")
SESS = os.path.join(REPO, "data", "sessions", "20260918T154914Z_validate")
SNAP = os.path.join(SESS, "snap",
                    "hyptcn-guest_000000_20260918T154916673Z.vmicd")


# --------------------------------------------------- unit: Profile.shift


def _fake_profile():
    p = Profile.__new__(Profile)
    p.sym = {
        "_stext": START_KERNEL_MAP + 0x200000,
        "init_task": START_KERNEL_MAP + 0x300000,
        "mod_symbol": MODULES_VADDR + 0x1000,      # oblast modulov
        "fixed_percpu_data": 0,                     # absolutny symbol (typ A)
        "vsyscall_page": 0xFFFFFFFFFFFF0000,        # fixmap/vsyscall
    }
    p.abs = {"fixed_percpu_data"}
    return p


def test_shift_posuva_obraz_jadra_a_nic_ine():
    p = _fake_profile()
    delta = -0x1A00000
    p.shift(delta, START_KERNEL_MAP, MODULES_VADDR)
    assert p.sym["_stext"] == START_KERNEL_MAP + 0x200000 + delta
    assert p.sym["init_task"] == START_KERNEL_MAP + 0x300000 + delta
    # mimo rozsahu obrazu jadra a absolutne symboly sa NEposuvaju
    assert p.sym["mod_symbol"] == MODULES_VADDR + 0x1000
    assert p.sym["fixed_percpu_data"] == 0
    assert p.sym["vsyscall_page"] == 0xFFFFFFFFFFFF0000


def test_shift_zrusi_cache_symtabu_checks():
    """checks.py si drzi zoradene adresy na profile - po posune by vracal
    stare adresy, preto sa cache musi zahodit."""
    p = _fake_profile()
    p._checks_symtab = ((), ())
    p.shift(0x1000, START_KERNEL_MAP, MODULES_VADDR)
    assert not hasattr(p, "_checks_symtab")


# ------------------------------ integracia: stara snimka + novsi profil


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_preukotvenie_na_par_z_auditu():
    view, img = build_view(SNAP, PROFILE_DIR)
    try:
        assert view.resolve()
        assert view.profile_boot_mismatch() is not None, \
            "par mal byt v nesulade (snimka 18.9., profil 19.9.)"
        ok, info = view.reanchor()
        assert ok, info
        # delta sa MERIA z tabuliek stranok (walk), nie zo samotneho banneru
        # (ten da spravne PA, ale VA o rezidualnych 2 MiB inak)
        assert info["delta"] == -0x1a800000
        # rezidual -0x200000 ostava: tak sa obraz jadra mapuje (VA->PA ma
        # konstantny posun 2 MiB nech je boot akykolvek)
        assert view.ktext_shift == -0x200000
        assert view.reanchored == -0x1a800000
        # po preukotveni uz ziadny nesulad - walk sedi s bannerom
        assert view.profile_boot_mismatch() is None
        # ss: pred A2 vracal 0 socketov, po preukotveni musi rekonstruovat
        socks = view.sockets()
        assert socks["count"] >= 10, socks
    finally:
        img.close()


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_reanchor_nemeni_preklad_pa():
    """Po preukotveni musi byt preklad VA->PA rovnaky ako pred nim -
    posuva sa len stary bootovy frame, nie fyzicka pravda."""
    view, img = build_view(SNAP, PROFILE_DIR)
    try:
        assert view.resolve()
        stext = view.p.addr("_stext")
        pa_pred = view.ktext_pa(stext)
        ok, info = view.reanchor()
        assert ok, info
        # adresa symbolu je po preukotveni ina, ale preklad musi dat tu istu
        # fyzicku adresu - posuva sa len bootovy frame, nie fyzicka pravda
        assert view.ktext_pa(view.p.addr("_stext")) == pa_pred
    finally:
        img.close()


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_cli_ss_preukotvi_a_vypise_sockety(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "guestparse", "ss",
         "--snapshot", SNAP, "--profile", PROFILE_DIR],
        capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stderr
    assert "preukotvenie" in r.stderr
    assert "spolu: " in r.stdout and "socketov" in r.stdout


@pytest.mark.skipif(not os.path.exists(SNAP),
                    reason="chyba snimka z ineho bootu: %s" % SNAP)
def test_cli_validate_preukotvi_a_zapise_vysledok(tmp_path):
    out = tmp_path / "validate.json"
    r = subprocess.run(
        [sys.executable, "-m", "guestparse", "validate",
         "--snapshot", SNAP, "--profile", PROFILE_DIR,
         "--ps-before", os.path.join(SESS, "ps_before.txt"),
         "--ps-after", os.path.join(SESS, "ps_after.txt"),
         "--lsmod", os.path.join(SESS, "lsmod_before.txt"),
         "--out", str(out)],
        capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stderr
    assert out.exists(), "validate mal po preukotveni zapisat vysledok"
    doc = json.loads(out.read_text(encoding="utf-8"))
    p = doc["processes"]
    # historicky artefakt (sediaci profil): found 80/80, missing 0
    assert p["found"] == p["stable"], p
    assert p["missing"] == 0, p
    m = doc["modules"]
    # s --lsmod sa porovnanie spusti a preukotveny profil musi najst vsetko
    assert m["extra"] == 0, m
    assert m["matched"] >= 40, m


# -------------------------------------- profil, ktory sedi: ziadny posun


def test_reanchor_seduceho_profilu_nie_je_potreba(profile, mini_view):
    """Ked profil a snimka sedia (alebo snimke chybaju stranky tabuliek),
    reanchor sa odmietne a nic sa nezmeni - preukotvenie nesmie byt sidlo
    tichych zmien. Mini snimka nema kompletne tabulky stranok, takze
    spatne hladanie VA pre init_task nemusi mat co najst."""
    view = mini_view
    before = dict(view.p.sym)
    shift_before = view.ktext_shift
    ok, why = view.reanchor()
    assert not ok, "reanchor na mini snimke sa nesmie podarit"
    assert view.p.sym == before
    assert view.ktext_shift == shift_before
    assert view.reanchored == 0
