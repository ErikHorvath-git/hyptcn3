"""
Spolocne fixture a pravidla preskakovania.

Testy bezia bez roota a bez bezacej VM. Vstupy su troch druhov:

  1. mala snimka v repe (tests/data/mini.vmicd) - je vzdy k dispozicii,
     takze nad nou bezia zakladne testy rekonstrukcie aj injekcny test
     detektora hookov aj v cerstvom klone;
  2. realna snimka hosta (/var/tmp/vmic-val, /var/tmp/vmic-delta) - existuje
     iba na stroji, kde sa zbieralo, a do gitu sa nezmesti;
  3. vystup zo 'make -C vmicollect test' (synteticky obraz + obnoveny raw).

Ked chyba vstup druhu 2 alebo 3, test sa preskoci - ale NAHLAS: conftest
zapina '-rs' (dovody preskocenia) a na konci behu vypise varovanie, kolko
testov sa preskocilo. Preskoceny test nie je presiel.

Ak sa preskocit nesmie (napr. pri finalnom behu na tomto stroji), pouzi
GUESTPARSE_REQUIRE_REAL=1 alebo prepinac '--require-real': chybajuci vstup
potom test zhodi namiesto preskocenia. Prepinac zavadza tento conftest, takze
pytest ho pozna iba vtedy, ked je v prikaze cesta do balika
('python3 -m pytest --require-real guestparse'); premenna prostredia funguje
vzdy.

Testy nad realnou snimkou maju automaticky znacku 'realsnap', testy nad
selftestom znacku 'selftest' - da sa nimi vyberat:
    python3 -m pytest -m "not realsnap"     # ako v cerstvom klone
    python3 -m pytest -m realsnap           # iba tie nad realnou snimkou
"""

import json
import os

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS))
DATA = os.path.join(TESTS, "data")

SELFTEST = os.path.join(REPO, "vmicollect", "build", "selftest")

MINI = os.path.join(DATA, "mini.vmicd")
MINI_MANIFEST = os.path.join(DATA, "mini.json")

# Profil jadra hosta: cesta z prostredia ma prednost, inak sa berie profil
# verzionovany v repe (viz profiles/*/README.md).
PROFILE_CANDIDATES = [
    os.environ.get("GUESTPARSE_PROFILE"),
    os.path.join(REPO, "profiles", "debian12-6.1.0-42-cloud-amd64"),
]

# Realne snimky. Lezia mimo repa a nie su trvale - preto su volitelne.
VAL_DIR = os.environ.get("GUESTPARSE_VAL", "/var/tmp/vmic-val")
DELTA_DIR = os.environ.get("GUESTPARSE_DELTA", "/var/tmp/vmic-delta")

# Fixture, ktore potrebuju vstup mimo repa - podla nich sa nastavuju znacky.
REAL_FIXTURES = {"val_dir", "val_view", "delta_dir", "clean_copy"}
SELFTEST_FIXTURES = {"selftest_dir", "selftest_restored"}


# ----------------------------------------------------------- nastavenie behu


def pytest_addoption(parser):
    parser.addoption(
        "--require-real", action="store_true", default=False,
        help="chybajuca realna snimka / selftest je chyba, nie preskocenie")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "realsnap: potrebuje realnu snimku hosta mimo repa")
    config.addinivalue_line(
        "markers", "selftest: potrebuje vystup 'make -C vmicollect test'")
    # Preskocenie musi byt vidiet aj pri 'pytest -q'; bez toho vyzera beh
    # s chybajucimi vstupmi rovnako ako beh, kde vsetko prebehlo.
    chars = config.option.reportchars or ""
    if "s" not in chars and "a" not in chars and "A" not in chars:
        config.option.reportchars = chars + "s"


def pytest_collection_modifyitems(items):
    for item in items:
        names = set(getattr(item, "fixturenames", ()))
        if names & REAL_FIXTURES:
            item.add_marker(pytest.mark.realsnap)
        if names & SELFTEST_FIXTURES:
            item.add_marker(pytest.mark.selftest)


def pytest_terminal_summary(terminalreporter):
    skipped = terminalreporter.stats.get("skipped", [])
    if not skipped:
        return
    terminalreporter.write_line("")
    terminalreporter.write_line(
        "POZOR: preskocilo sa %d testov - preskoceny test NIE JE presiel."
        % len(skipped), yellow=True)
    duvody = {}
    for rep in skipped:
        text = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else str(
            rep.longrepr)
        duvody[text] = duvody.get(text, 0) + 1
    for text, n in sorted(duvody.items(), key=lambda kv: -kv[1]):
        terminalreporter.write_line("  %3dx %s" % (n, text), yellow=True)


def _chyba(request, dovod):
    """Chybajuci vstup: preskocenie, alebo pad pri --require-real."""
    if (request.config.getoption("--require-real")
            or os.environ.get("GUESTPARSE_REQUIRE_REAL")):
        pytest.fail("chyba vstup a je zapnute --require-real: %s" % dovod)
    pytest.skip(dovod)


# ------------------------------------------------------------- mala snimka


@pytest.fixture(scope="session")
def mini_path():
    """Mala snimka verzionovana v repe (viz tests/data/README.md)."""
    if not os.path.isfile(MINI):
        pytest.fail("chyba %s - je sucastou repa, vyrob ju znovu skriptom "
                    "guestparse/tests/data/make_mini.py" % MINI)
    return MINI


@pytest.fixture(scope="session")
def mini_manifest():
    """Manifest malej snimky: odkial je a co sa nad nou pri vyrobe zmeralo."""
    if not os.path.isfile(MINI_MANIFEST):
        pytest.fail("chyba %s" % MINI_MANIFEST)
    with open(MINI_MANIFEST) as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def mini_view(mini_path, profile):
    """Pohlad nad malou snimkou; drzi sa cez cely beh testov."""
    from guestparse.image import open_image
    from guestparse.view import GuestView
    img = open_image(mini_path)
    view = GuestView(img, profile)
    if not view.resolve():
        pytest.fail("posun jadra sa nad %s nenasiel" % mini_path)
    yield view
    img.close()


# --------------------------------------------------------------- selftest


@pytest.fixture(scope="session")
def selftest_dir(request):
    d = os.path.join(SELFTEST, "snapshots")
    if not os.path.isdir(d):
        _chyba(request, "chyba %s - spusti 'make -C vmicollect test'" % d)
    return d


@pytest.fixture(scope="session")
def selftest_restored(request):
    p = os.path.join(SELFTEST, "restored.raw")
    if not os.path.isfile(p):
        _chyba(request, "chyba %s - spusti 'make -C vmicollect test'" % p)
    return p


# ---------------------------------------------------------------- profil


def _profile_dir():
    for c in PROFILE_CANDIDATES:
        if c and os.path.isdir(c):
            return c
    return None


@pytest.fixture(scope="session")
def profile_dir():
    d = _profile_dir()
    if d is None:
        pytest.fail(
            "chyba profil jadra hosta - hladal som %s (nastav GUESTPARSE_PROFILE)"
            % ", ".join(c for c in PROFILE_CANDIDATES if c))
    return d


@pytest.fixture(scope="session")
def profile(profile_dir):
    from guestparse.profile import Profile
    return Profile.from_dir(profile_dir)


# ------------------------------------------------------------ realne snimky


@pytest.fixture(scope="session")
def val_dir(request):
    """Adresar s realnou validacnou snimkou (plna snimka, jeden subor)."""
    if not os.path.isdir(VAL_DIR):
        _chyba(request, "chyba validacna snimka %s (nastav GUESTPARSE_VAL)"
               % VAL_DIR)
    return VAL_DIR


@pytest.fixture(scope="session")
def delta_dir(request):
    """Adresar s realnym delta retazcom (plna snimka + delty)."""
    if not os.path.isdir(DELTA_DIR):
        _chyba(request, "chyba delta retazec %s (nastav GUESTPARSE_DELTA)"
               % DELTA_DIR)
    return DELTA_DIR


@pytest.fixture(scope="session")
def val_view(profile, val_dir):
    """Realna snimka hosta + najdeny posun jadra. Drzi sa cez cely beh testov."""
    from guestparse.image import open_image
    from guestparse.view import GuestView
    img = open_image(val_dir)
    view = GuestView(img, profile)
    if not view.resolve():
        pytest.fail("posun jadra sa nenasiel nad %s" % val_dir)
    yield view
    img.close()
