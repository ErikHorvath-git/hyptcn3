"""
Testy rekonstrukcie nad malou snimkou v repe (tests/data/mini.vmicd).

Tieto testy bezia vzdy - aj v cerstvom klone bez pristupu k stroju, na ktorom
sa zbieralo. Snimka je podmnozina jednej realnej snimky: drzi presne tie
stranky, z ktorych parser cita (viz tests/data/README.md). Preto sa nad nou
prechody zoznamov NEUZAVRU a vysledok je oznaceny ako neuplny - test to overuje
tiez, lebo mlcky polovicny zoznam je prave to, co sa nesmie stat.

Ocakavane hodnoty sa citaju z manifestu mini.json, ktory vznikol pri vyrobe
snimky spolu s nou - nie su prepisane rucne.
"""

import os

MAX_BYTES = 512 * 1024      # strop, aby snimka v repe nezacala rast


def test_mini_je_mala(mini_path):
    assert os.path.getsize(mini_path) <= MAX_BYTES, (
        "mini.vmicd prerastla strop %d B - do gitu patri iba maly vyrez"
        % MAX_BYTES)


def test_mini_posun_sa_najde(mini_view, mini_manifest):
    obs = mini_manifest["observed"]
    assert mini_view.ktext_shift == obs["ktext_shift"]
    assert mini_view.page_offset_base == obs["page_offset_base"]
    assert mini_view.banner == obs["banner"]
    assert "Linux version " in mini_view.banner


def test_mini_preklad_adries_sa_zhoduje(mini_view):
    """Linearny vypocet vs. prechod tabuliek stranok - musia dat to iste."""
    rows = {r["symbol"]: r for r in mini_view.translation_check()}
    for name in ("linux_banner", "init_task"):
        r = rows[name]
        assert r["linear_pa"] is not None
        assert r["walk_pa"] is not None
        assert r["linear_pa"] == r["walk_pa"], name


def test_mini_procesy(mini_view, mini_manifest):
    ocakavane = mini_manifest["observed"]["processes"]
    res = mini_view.processes()
    assert [(p["pid"], p["comm"]) for p in res["processes"]] == [
        (p["pid"], p["comm"]) for p in ocakavane]
    assert res["processes"][0]["comm"] == "systemd"
    # v malej snimke dalsie task_struct nie su - prechod sa NESMIE tvarit,
    # ze zoznam skoncil
    assert res["truncated"] is True
    assert res["stop_reason"]


def test_mini_moduly(mini_view, mini_manifest):
    res = mini_view.modules()
    assert [m["name"] for m in res["modules"]] == \
        mini_manifest["observed"]["modules"]
    # struct module lezi v oblasti modulov, ktora linearne mapovana nie je
    assert all(m["module_va"] >= 0xFFFFFFFFC0000000 for m in res["modules"])
    assert res["truncated"] is True


def test_mini_info(mini_view, mini_manifest):
    inf = mini_view.info()
    assert inf["resolved"] is True
    assert inf["image"]["kind"] == "vmicd"
    assert inf["image"]["pages_present"] == mini_manifest["result"]["pages"]
    assert inf["image"]["chain"]["full_baseline"] is True
    assert inf["image"]["chain"]["validated"] is True
    assert all(r["match"] for r in inf["translation_check"])


def test_mini_chybajuca_stranka_je_nulova(mini_view):
    """Stranka, ktora v snimke nie je, sa cita ako nulova - nie ako chyba."""
    img = mini_view.img
    chybajuca = max(img.index) + 1
    assert img.read(chybajuca * img.page_size, img.page_size) == \
        b"\0" * img.page_size
