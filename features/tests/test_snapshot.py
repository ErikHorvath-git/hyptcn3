"""
Testy vektora na snimku (features/snapshot.py).

Delia sa na tri skupiny:

  1. vzorce - percentil a entropia rozdelenia nad zoznamami, kde sa spravna
     odpoved da spocitat rucne;
  2. mala snimka v repe (guestparse/tests/data/mini.vmicd) - objektova cast
     bezi aj v cerstvom klone; pamatova cast nad nou bezat NEMA, lebo mini
     nema sidecar zberaca, a test overuje prave to, ze sa to povie chybou
     a nie nahradnou hodnotou;
  3. realny retazec v data/raw/ - dlzka vektora, mena, prva snimka bez
     predchodcu, proc_new a proc_gone proti rucne spocitanemu rozdielu
     mnozin PID a determinizmus.

Skupina 3 potrebuje snimky mimo repa (.gitignore vylucuje *.vmicd) a v
cerstvom klone sa preskoci - ale nahlas, rovnako ako v test_perbin.py.
Na stroji, kde snimky su, sa preskocenie zakazuje premennou
FEATURES_REQUIRE_REAL=1.
"""

import json
import math
import os

import pytest

from features.perbin import FeatureError, _chain_parts
from features.snapshot import (MENA, entropia_rozdelenia, objekty_z_pohladu,
                               pamat_zo_sidecaru, percentil95, retazec,
                               sidecar_cesta, vektor_snimky)

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS))

MINI = os.path.join(REPO, "guestparse", "tests", "data", "mini.vmicd")
PROFIL = os.path.join(REPO, "profiles", "debian12-6.1.0-42-cloud-amd64")
RAW = os.path.join(REPO, "data", "raw")

REQUIRE_REAL = os.environ.get("FEATURES_REQUIRE_REAL") == "1"


# ----------------------------------------------------------- 1. vzorce


def test_percentil_je_nameranou_hodnotou():
    """
    Najblizsie poradie, rucne: hodnoty 0..19 zoradene, poradie
    ceil(0,95 * 20) = 19, teda index 18 a hodnota 18. Interpolacia by dala
    18,05 - cislo, ktore ziadny bin nema.
    """
    assert percentil95(list(range(20))) == 18
    assert percentil95([5.0]) == 5.0
    assert percentil95([1, 1, 1, 9]) == 9


def test_percentil_z_prazdneho_je_chyba():
    with pytest.raises(FeatureError):
        percentil95([])


def test_entropia_rozdelenia_kraje():
    """Vsetko v jednom bine = 0, rovnomerne = 1."""
    assert entropia_rozdelenia([10, 0, 0, 0]) == 0.0
    assert entropia_rozdelenia([0, 0, 0, 0]) == 0.0
    assert entropia_rozdelenia([3, 3, 3, 3]) == pytest.approx(1.0)
    # Dva biny z ostmich rovnako: H = 1 bit, normalizacia log2(8) = 3.
    assert entropia_rozdelenia([1, 1, 0, 0, 0, 0, 0, 0]) == pytest.approx(
        1.0 / 3.0)


def test_mena_su_kontrakt():
    """Dvadsat priznakov + dva priznaky o riadku, mena sa neopakuju."""
    assert len(MENA) == 22
    assert len(set(MENA)) == 22
    assert MENA[-2:] == ("ma_predchodcu", "je_plna")
    assert MENA[:8] == ("mem_changed_ratio", "mem_bins_active",
                        "mem_changed_max", "mem_changed_p95",
                        "mem_changed_spread", "mem_entropy_mean",
                        "mem_entropy_max", "mem_zero_ratio")


def test_pamat_zo_sidecaru_rucne_spocitana(tmp_path):
    """
    Vymysleny sidecar, kde sa kazde z osmich cisel da spocitat na papieri:
    dva biny po 100 strankach, zmenenych 10 a 30.
    """
    sc = tmp_path / "s.json"
    sc.write_text(json.dumps({"features": {"entropy": True, "bins": [
        {"pages_total": 100, "pages_changed": 10, "zero_ratio": 0.5,
         "entropy_mean": 2.0, "has_changed": 1},
        {"pages_total": 100, "pages_changed": 30, "zero_ratio": 0.25,
         "entropy_mean": 6.0, "has_changed": 1},
    ]}}))
    v = pamat_zo_sidecaru(str(sc))
    assert v[0] == pytest.approx(40 / 200)
    assert v[1] == pytest.approx(1.0)
    assert v[2] == pytest.approx(0.30)
    assert v[3] == pytest.approx(0.30)
    # rozdelenie 10:30 -> H = -(0,25 log2 0,25 + 0,75 log2 0,75), delene log2(2)
    h = -(0.25 * math.log2(0.25) + 0.75 * math.log2(0.75))
    assert v[4] == pytest.approx(h)
    assert v[5] == pytest.approx((2.0 * 10 + 6.0 * 30) / 40)
    assert v[6] == pytest.approx(6.0)
    assert v[7] == pytest.approx((50 + 25) / 200)


def test_vypnuta_entropia_je_chyba_nie_nula(tmp_path):
    sc = tmp_path / "s.json"
    sc.write_text(json.dumps({"features": {"entropy": False, "bins": [
        {"pages_total": 10, "pages_changed": 1, "zero_ratio": 0.0,
         "has_changed": 1}]}}))
    with pytest.raises(FeatureError, match="entropia"):
        pamat_zo_sidecaru(str(sc))


# ------------------------------------------------- 2. mala snimka v repe


def test_mini_objektova_cast_bezi():
    """
    Nad mini.vmicd sa objekty citat daju. Prechody sa v nej neuzavru (je to
    vyrez), takze pocty su dolna hranica - a test overuje, ze to modul
    povie v poznamkach, nie ze to zamlci.
    """
    from guestparse.view import build_view
    view, img = build_view(MINI, PROFIL)
    try:
        hodnoty, stav, pozn = objekty_z_pohladu(view)
    finally:
        img.close()
    assert hodnoty["proc_total"] == len(stav["pids"])
    assert hodnoty["proc_user"] + hodnoty["proc_kernel"] == \
        hodnoty["proc_total"]
    assert hodnoty["mod_total"] == stav["mod_total"]
    assert any("dolna hranica" in p for p in pozn)


def test_mini_bez_sidecaru_skonci_chybou():
    """
    mini.json je manifest testovacich dat, nie sidecar zberaca - blok
    'features' v nom nie je. Pamatova cast sa v takom pripade NEDOPOCITAVA
    inou cestou, ale skonci chybou, ktora povie preco.
    """
    with pytest.raises(FeatureError) as exc:
        vektor_snimky(MINI, PROFIL)
    assert "features" in str(exc.value)


def test_sidecar_cesta():
    assert sidecar_cesta("/a/b.vmicd") == "/a/b.json"


def test_object_features_reanchor_before_reading_pointers(monkeypatch):
    from features import snapshot

    class View:
        ktext_shift = 1
        shifted = False

        def profile_boot_mismatch(self):
            return None if self.shifted else "different boot"

        def reanchor(self):
            self.shifted = True
            return True, {"delta": 4096}

        def processes(self):
            assert self.shifted
            return dict(processes=[], count=0, truncated=False, stop_reason=None)

        def modules(self):
            assert self.shifted
            return dict(modules=[], count=0, truncated=False, stop_reason=None)

        def sockets(self, **_):
            assert self.shifted
            return dict(sockets=[], count=0, truncated=False, stop_reason=None)

    monkeypatch.setattr(snapshot.checks, "check_all", lambda *a, **kw: {
        "summary": {"inconclusive": [], "syscall_hooks": 0}, "findings": []})
    _, _, notes = objekty_z_pohladu(View())
    assert any("preukotvenie KASLR" in note for note in notes)
    bad = View()
    bad.reanchor = lambda: (False, "missing tables")
    with pytest.raises(FeatureError, match="NESULAD PROFILU"):
        objekty_z_pohladu(bad)


# ----------------------------------------------------- 3. realny retazec


@pytest.mark.parametrize("incomplete", [None, "processes", "modules", "sockets"])
def test_behavior_quality_depends_on_feature_traversals_not_cross_view(monkeypatch, incomplete):
    from types import SimpleNamespace
    from features import snapshot
    def walk(name, field):
        return {field: [], "count": 0, "truncated": name == incomplete, "stop_reason": "cut"}
    view = SimpleNamespace(
        ktext_shift=1, profile_boot_mismatch=lambda: None,
        processes=lambda: walk("processes", "processes"),
        modules=lambda: walk("modules", "modules"),
        sockets=lambda **kwargs: walk("sockets", "sockets"),
    )
    monkeypatch.setattr(snapshot.checks, "check_all", lambda *args, **kwargs: {
        "summary": {"inconclusive": ["process_cross_view", "text_integrity"], "syscall_hooks": 0},
        "findings": []})
    _, state, _ = objekty_z_pohladu(view)
    assert state["quality"]["behavior_valid"] is (incomplete is None)
    assert state["quality"]["model_valid"] is False


HIDDEN = {"check": "process_cross_view", "task_va": 0xffff0000, "pid": 450961, "comm": "postgres",
          "seen_in": "tasks", "missing_in": "children/sibling"}
HOOK = {"check": "syscall_hook", "index": 59}


def _stav(*findings, inconclusive=("text_integrity",)):
    return {"quality": {"model_valid": True, "behavior_valid": True, "traversals_complete": True,
                        "inconclusive": list(inconclusive), "findings": [dict(f) for f in findings]}}


def test_single_snapshot_cross_view_difference_is_unconfirmed():
    from features.snapshot import potvrd_krizove
    stav = _stav(HIDDEN, HOOK)
    assert potvrd_krizove(stav, None) == [HIDDEN]
    q = stav["quality"]
    assert q["findings"] == [HOOK]          # other checks alarm at once
    assert q["unconfirmed_findings"] == [HIDDEN]
    assert q["inconclusive"] == ["process_cross_view", "text_integrity"]
    assert q["model_valid"] is False and q["behavior_valid"] is True


def test_cross_view_difference_confirmed_by_adjacent_snapshot():
    from features.snapshot import kluc_nalezu, potvrd_krizove
    stav = _stav(HIDDEN)
    assert potvrd_krizove(stav, frozenset({kluc_nalezu(HIDDEN)})) == []
    q = stav["quality"]
    assert q["findings"] == [HIDDEN] and q["unconfirmed_findings"] == []
    assert q["inconclusive"] == ["text_integrity"] and q["model_valid"] is True


@pytest.mark.parametrize("previous", [
    dict(HIDDEN, pid=450962),
    dict(HIDDEN, seen_in="children/sibling", missing_in="tasks"),
    {"check": "module_cross_view", "module_va": 1, "name": "x", "seen_in": "modules",
     "missing_in": "module_kset"}])
def test_other_previous_difference_does_not_confirm(previous):
    from features.snapshot import kluc_nalezu, potvrd_krizove
    stav = _stav(HIDDEN)
    assert potvrd_krizove(stav, frozenset({kluc_nalezu(previous)})) == [HIDDEN]


def test_unconfirmed_module_difference_marks_module_check():
    from features.snapshot import potvrd_krizove
    module = {"check": "module_name_mismatch", "module_va": 1, "modules_name": "a", "sysfs_name": "b"}
    stav = _stav(module)
    potvrd_krizove(stav, frozenset())
    assert stav["quality"]["inconclusive"] == ["modules", "text_integrity"]


def test_object_state_carries_raw_cross_view_keys(monkeypatch):
    from types import SimpleNamespace
    from features import snapshot
    walk = lambda field: {field: [], "count": 0, "truncated": False, "stop_reason": None}
    view = SimpleNamespace(ktext_shift=1, profile_boot_mismatch=lambda: None,
                           processes=lambda: walk("processes"), modules=lambda: walk("modules"),
                           sockets=lambda **kwargs: walk("sockets"))
    monkeypatch.setattr(snapshot.checks, "check_all", lambda *args, **kwargs: {
        "summary": {"inconclusive": [], "syscall_hooks": 1}, "findings": [HIDDEN, HOOK]})
    values, state, _ = objekty_z_pohladu(view)
    assert state["krizove_kluce"] == frozenset({snapshot.kluc_nalezu(HIDDEN)})
    assert values["chk_crossview"] == 1     # per-snapshot count, before confirmation


def test_chain_threads_cross_view_keys_independent_of_model_validity(monkeypatch, tmp_path):
    from features import snapshot
    from features.quality import LEGACY_POLICY
    regions = [{"gpa": 0, "bytes": 16384}]
    heads = []
    for seq in (1, 2, 3, 5):                 # sequence gap before 5
        path = tmp_path / ("%d.vmicd" % seq)
        heads.append({"seq": seq, "full": False, "chain_id": "c", "path": str(path)})
        (tmp_path / ("%d.json" % seq)).write_text(json.dumps({
            "schema": "vmicollect/1", "seq": seq, "timestamp_unix": seq * 5.,
            "vm": {"memsize": 16384, "num_vcpus": 2}, "stats": {"read_errors": 0, "filled_zero": 0},
            "output": {"full": False, "chain_id": "c", "pages_total": 4, "pages_changed": 1,
                       "page_size": 4096},
            "features": {"schema": "hyptcn3/perbin/1", "entropy": True, "bin_bytes": 8192,
                         "page_size": 4096, "bins_total": 2, "regions": regions, "bins": [
                             {"bin": 0, "gpa": 0, "pages_total": 2, "pages_changed": 1,
                              "changed_ratio": .5, "zero_ratio": .5, "entropy_mean": 2., "has_changed": 1},
                             {"bin": 1, "gpa": 8192, "pages_total": 2, "pages_changed": 0,
                              "changed_ratio": 0., "zero_ratio": 1., "entropy_mean": 0., "has_changed": 0}]}}))
    calls = []

    def extract(_raw, _profile, seq, predch, _cursor, predch_krizove):
        calls.append((seq, predch, predch_krizove))
        quality = _stav(inconclusive=("process_cross_view", "text_integrity"))["quality"]
        quality["model_valid"] = False      # legacy-invalid: predch is never passed on
        return [0.] * len(MENA), {"pids": frozenset(), "mod_total": 0, "quality": quality,
                                  "krizove_kluce": frozenset({"k%d" % seq})}, []
    monkeypatch.setattr(snapshot, "vektor_snimky", extract)
    snapshot._retazec_cyklus(str(tmp_path), "unused", 7.5, LEGACY_POLICY, heads, None)
    assert calls == [(1, None, None), (2, None, frozenset({"k1"})),
                     (3, None, frozenset({"k2"})), (5, None, None)]


def _najdi_retazec():
    """
    Adresar v data/raw/ s aspon dvoma snimkami retazca, ktore maju vedla
    seba sidecar s blokom 'features'. Bez dvoch snimok sa proc_new ani
    proc_gone overit nedaju.
    """
    if not os.path.isdir(RAW):
        return None
    for meno in sorted(os.listdir(RAW)):
        d = os.path.join(RAW, meno)
        if not os.path.isdir(d):
            continue
        try:
            heads = _chain_parts(d)
        except Exception:
            continue
        if len(heads) < 2:
            continue
        try:
            pamat_zo_sidecaru(sidecar_cesta(heads[0]["path"]))
        except FeatureError:
            continue
        return d
    return None


@pytest.fixture(scope="module")
def realny():
    d = _najdi_retazec()
    if d:
        return d
    msg = ("v %s nie je retazec aspon dvoch snimok so sidecarmi s blokom "
           "'features'" % RAW)
    if REQUIRE_REAL:
        pytest.fail(msg + " (FEATURES_REQUIRE_REAL=1)")
    pytest.skip(msg)


@pytest.fixture(scope="module")
def vysledok(realny):
    return retazec(realny, PROFIL)


def test_realny_tvar_matice(vysledok):
    assert vysledok["mena"] == list(MENA)
    assert len(vysledok["matica"]) == len(vysledok["snimky"])
    for riadok in vysledok["matica"]:
        assert len(riadok) == len(MENA)
        assert all(isinstance(x, float) for x in riadok)


def test_prva_snimka_nema_predchodcu(vysledok):
    """
    Prva snimka: priznak je 0 a tri priznaky, ktore predchodcu potrebuju,
    su v nej nula. Kazda dalsia ma priznak 1, ak predchadzajuci riadok je
    platny podla politiky archivu a nedeli ich vynechany slot (casova medzera
    nad max_medzera_s); realny zber so zmeskanym slotom kontext prerusi.
    """
    i = MENA.index("ma_predchodcu")
    assert vysledok["matica"][0][i] == 0.0
    for meno in ("proc_new", "proc_gone", "mod_delta"):
        assert vysledok["matica"][0][MENA.index(meno)] == 0.0
    casy, platne = vysledok["casy"], vysledok["valid"]
    for k in range(1, len(casy)):
        suvisle = 0 < casy[k] - casy[k - 1] <= vysledok["max_medzera_s"]
        ocakavane = 1.0 if suvisle and platne[k - 1] else 0.0
        assert vysledok["matica"][k][i] == ocakavane
        if not ocakavane:
            for meno in ("proc_new", "proc_gone", "mod_delta"):
                assert vysledok["matica"][k][MENA.index(meno)] == 0.0
    assert any(r[i] == 1.0 for r in vysledok["matica"][1:]), "retazec nema ziadny suvisly prechod"


def test_je_plna_sedi_s_hlavickami_retazca(realny, vysledok):
    """Priznak je_plna sa berie z hlavicky .vmicd, nie z poradia v retazci.

    Pri output.delta_full_every pride plna snimka aj uprostred sedenia, takze
    "prva v retazci" by bolo zle kriterium.
    """
    i = MENA.index("je_plna")
    plne = [1.0 if h["full"] else 0.0 for h in _chain_parts(realny)]
    assert [r[i] for r in vysledok["matica"]] == plne
    assert plne[0] == 1.0


def test_v_plnej_snimke_je_zmena_doplnkom_nuloveho_podielu(vysledok):
    """Dokaz, preco plna snimka potrebuje vlastny priznak.

    Delta writer zapise do plnej snimky vsetky NENULOVE stranky, takze
    pages_changed je ich pocet a mem_changed_ratio vyjde presne
    1 - mem_zero_ratio. V delta riadku take nieco neplati - a ked by sa obe
    dostali do jedneho okna, model by dostal dve rozne veliciny v jednom
    stlpci.
    """
    i_plna = MENA.index("je_plna")
    i_zmena = MENA.index("mem_changed_ratio")
    i_nula = MENA.index("mem_zero_ratio")
    plne = [r for r in vysledok["matica"] if r[i_plna] == 1.0]
    delty = [r for r in vysledok["matica"] if r[i_plna] == 0.0]
    assert plne, "retazec nema plnu snimku"
    for r in plne:
        assert r[i_zmena] + r[i_nula] == pytest.approx(1.0, abs=1e-9)
    assert delty, "retazec nema delta snimku"
    for r in delty:
        assert r[i_zmena] + r[i_nula] != pytest.approx(1.0, abs=1e-6)


def test_proc_new_a_gone_sedia_na_rucny_rozdiel(realny, vysledok):
    """
    Rozdiel mnozin PID medzi prvymi dvoma snimkami sa spocita znova, priamo
    z guestparse - keby sa proc_new pocital zo zleho stavu, tu to padne.
    """
    from guestparse.view import build_view
    heads = _chain_parts(realny)
    i = MENA.index("ma_predchodcu")
    # Prvy suvisly prechod; zmeskany slot predchodcu zamerne zahodi.
    k = next(k for k in range(1, len(heads)) if vysledok["matica"][k][i] == 1.0)
    pidy = []
    for h in heads[k - 1:k + 1]:
        view, img = build_view(realny, PROFIL, until_seq=h["seq"])
        try:
            pidy.append({p["pid"] for p in view.processes()["processes"]})
        finally:
            img.close()
    riadok = vysledok["matica"][k]
    assert riadok[MENA.index("proc_new")] == float(len(pidy[1] - pidy[0]))
    assert riadok[MENA.index("proc_gone")] == float(len(pidy[0] - pidy[1]))


def test_determinizmus(realny, vysledok):
    """Ten isty retazec dva razy musi dat tie iste cisla, bit po bite."""
    znova = retazec(realny, PROFIL)
    assert znova["matica"] == vysledok["matica"]
    assert znova["snimky"] == vysledok["snimky"]
