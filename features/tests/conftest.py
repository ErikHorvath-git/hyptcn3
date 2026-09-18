"""
Spolocne fixture balika `features`.

Vstupy su troch druhov a lisia sa tym, ci su v repozitari:

  1. mala snimka v repe (guestparse/tests/data/mini.vmicd) a rozsahy
     memslotov z verzionovaneho probe.json - su vzdy k dispozicii, takze
     zakladne testy vektora bezia aj v cerstvom klone;
  2. sidecar realnej snimky v repe (data/sessions/.../snap/*.json) - v repe
     JE, ale .vmicd vedla neho nie (koreňovy .gitignore vylucuje *.vmicd);
  3. realne snimky (/var/tmp/vmic-val, /var/tmp/vmic-delta a .vmicd
     v data/sessions/) - existuju iba na stroji, kde sa zbieralo.

Ked chyba vstup druhu 3, test sa preskoci - ale NAHLAS: preskoceny test nie
je presiel. Na stroji, kde snimky su (teda pri finalnom behu), sa preskocenie
zakazuje premennou FEATURES_REQUIRE_REAL=1.
"""

import os

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS))

MINI = os.path.join(REPO, "guestparse", "tests", "data", "mini.vmicd")

# Rozsahy memslotov domeny hyptcn-guest. Vystup 'vmicollect probe -v' je
# v repe verzionovany, takze testy nepotrebuju bezacu VM.
PROBE = os.path.join(REPO, "data", "results", "2026-09-18_zmrazeny_host",
                     "probe.json")

# Realna plna snimka: sidecar je v repe, .vmicd vedla neho nie.
SESSION_SNAP = os.path.join(REPO, "data", "sessions", "20260918_validate2",
                            "snap")
VAL_DIR = os.environ.get("FEATURES_VAL", "/var/tmp/vmic-val")
DELTA_DIR = os.environ.get("FEATURES_DELTA", "/var/tmp/vmic-delta")

REQUIRE_REAL = os.environ.get("FEATURES_REQUIRE_REAL") == "1"


def _need(path, popis):
    if os.path.exists(path):
        return path
    msg = "%s nie je na tomto stroji: %s" % (popis, path)
    if REQUIRE_REAL:
        pytest.fail(msg + " (FEATURES_REQUIRE_REAL=1)")
    pytest.skip(msg)


def _dir_with_vmicd(path):
    return os.path.isdir(path) and any(
        n.endswith(".vmicd") for n in os.listdir(path))


@pytest.fixture(scope="session")
def mini():
    return _need(MINI, "mala snimka v repe")


@pytest.fixture(scope="session")
def probe():
    return _need(PROBE, "vystup 'vmicollect probe -v'")


@pytest.fixture(scope="session")
def memslots(probe):
    from features.perbin import load_memslots
    return load_memslots(probe)


@pytest.fixture(scope="session")
def full_snap():
    """Adresar s realnou plnou snimkou (mimo gitu)."""
    for cand in (SESSION_SNAP, VAL_DIR):
        if _dir_with_vmicd(cand):
            return cand
    msg = ("realna plna snimka nie je na tomto stroji (skusane: %s, %s)"
           % (SESSION_SNAP, VAL_DIR))
    if REQUIRE_REAL:
        pytest.fail(msg + " (FEATURES_REQUIRE_REAL=1)")
    pytest.skip(msg)


@pytest.fixture(scope="session")
def delta_chain():
    """Adresar s retazcom delta snimok (mimo gitu)."""
    if _dir_with_vmicd(DELTA_DIR):
        return DELTA_DIR
    msg = "retazec delta snimok nie je na tomto stroji: %s" % DELTA_DIR
    if REQUIRE_REAL:
        pytest.fail(msg + " (FEATURES_REQUIRE_REAL=1)")
    pytest.skip(msg)
