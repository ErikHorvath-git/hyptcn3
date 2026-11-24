"""The candidate modules in the return predicate and in the cleanup of the controls (package B9; finding S2 of B8).

A candidate module (lab/udalosti.py MODULE_CANDIDATES) is a residue only when it was loaded after the session's start
or a control chose it, so a candidate the kernel loaded at boot no longer fails every control of a session of
test_controls. guest_state.py levels lists the modules loaded at the session's start; the start of a control needs
that list (no default) and the occurrence keeps it for its cleanup. The level part of the predicate is unchanged.
On the fake guest of lab/tests/conftest.py (nothing loads a module or runs for real). Names package B9 adds are read
inside the tests, so this file collects on the code before B9.
"""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_state  # noqa: E402
import udalosti  # noqa: E402

BOOT = ["crc7", "fuse", "virtio_net"]  # The fake guest's modules after a boot that loaded the candidate crc7.
CLEAN = {"ok": True, "residues": [], "evidence": []}


def levels(modules):
    """The session's start as guest_state.py levels prints it (package B9: with the names of the loaded modules)."""
    return {"schema": "hyptcn3/guest-levels/1", "processes": 3, "threads": 3, "meminfo_kb": {"MemAvailable": 1500000},
            "modules": modules}


def start(kind, polarity, modules):
    return ["start", kind, "--polarity", polarity, "--levels", json.dumps(levels(modules)), "--tolerance", "null"]


def printed(capsys):
    return json.loads(capsys.readouterr().out)


def test_levels_names_the_modules_loaded_at_the_sessions_start(tmp_path, monkeypatch, capsys):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "meminfo").write_text("MemTotal: 2000000 kB\nMemAvailable: 1500000 kB\n")
    (proc / "loadavg").write_text("0.10 0.20 0.30 1/100 4242\n")
    (proc / "modules").write_text("virtio_net 61440 0 - Live 0x0\ncrc7 16384 0 - Live 0x0\nfuse 176128 1 - Live 0x0\n")
    monkeypatch.setattr(guest_state, "PROC", proc)
    monkeypatch.setattr(guest_state, "DATA", tmp_path / "data")
    monkeypatch.setattr(guest_state, "run", lambda *args, **kw: "5000|2000|200|3000|1|7500|300|500|9000000|25\n")
    guest_state.main(["levels"])
    assert printed(capsys)["modules"] == BOOT


@pytest.mark.parametrize("modules", [None, [7]], ids=["absent", "not_names"])
def test_a_control_does_not_start_without_the_modules_of_the_sessions_start(control_guest, modules):
    """Refused by name before anything runs: without the list no loaded candidate could be ruled out."""
    doc = levels(modules)
    if modules is None:
        doc.pop("modules")
    with pytest.raises(SystemExit) as refused:
        udalosti.main(["start", "kontrola_wx_memfd", "--polarity", "control", "--levels", json.dumps(doc),
                       "--tolerance", "null"])
    assert str(refused.value) == ("invalid --levels: no modules, the names of the modules loaded at the session's "
                                  "start (guest_state.py levels)")
    assert control_guest.calls == [] and control_guest.started == []


def test_a_candidate_the_kernel_loaded_at_boot_is_no_residue(control_guest, capsys):
    """Among the modules of the session's start: neither the return predicate nor the cleanup names it."""
    control_guest.load("crc7")
    assert guest_state.baseline(levels(BOOT), None)["exact"] == {"ok": True, "residues": []}
    udalosti.main(start("kontrola_wx_memfd", "control", BOOT))
    assert printed(capsys)["started"] is True
    udalosti.main(["stop", "kontrola_wx_memfd", "--polarity", "control"])
    assert printed(capsys)["cleanup"] == CLEAN


def test_a_candidate_loaded_after_the_sessions_start_is_a_residue(control_guest, capsys):
    """Before a control (the return predicate) and after an occurrence during which it was loaded (the cleanup); the
    candidate of the boot is still none."""
    control_guest.load("crc7")
    udalosti.main(start("kontrola_pocuvajuci_soket", "negative", BOOT))
    assert printed(capsys)["started"] is True
    control_guest.load("ts_kmp")
    udalosti.main(["stop", "kontrola_pocuvajuci_soket", "--polarity", "negative"])
    named = {"residues": [{"residue": "module", "name": "ts_kmp"}], "evidence": ["candidate module ts_kmp is loaded"]}
    assert printed(capsys)["cleanup"] == {"ok": False, **named}
    found = guest_state.baseline(levels(BOOT), None)
    assert (found["ok"], found["exact"]["residues"], found["evidence"]) == (False, named["residues"],
                                                                            named["evidence"])


def test_the_candidate_a_control_chose_is_a_residue(control_guest, capsys):
    """Also when it is among the modules of the session's start, which alone would pass it: here crc8 was loaded at
    the start and is not any more, so the module kind chooses it (crc7, loaded, is passed over). While the occurrence
    is in place the return predicate names it, and after a stop that cannot remove it the cleanup does; crc7 never."""
    control_guest.load("crc7")
    at_start = ["crc7", "crc8", "fuse", "virtio_net"]
    udalosti.main(start("kontrola_modul_jadra", "control", at_start))
    assert printed(capsys)["started"] is True and udalosti.remembered("kontrola_modul_jadra", "module") == "crc8"
    named = {"residues": [{"residue": "module", "name": "crc8"}], "evidence": ["candidate module crc8 is loaded"]}
    found = guest_state.baseline(levels(at_start), None)
    assert (found["ok"], found["exact"]["residues"], found["evidence"]) == (False, named["residues"],
                                                                            named["evidence"])
    control_guest.modprobe_fails.add("crc8")
    udalosti.main(["stop", "kontrola_modul_jadra", "--polarity", "control"])
    assert printed(capsys)["cleanup"] == {"ok": False, **named}


def test_a_module_a_control_chose_and_could_not_unload_stays_a_residue_of_the_boot(control_guest, capsys):
    """Finding F3 of the B9a verification, its probe sondy/s/s2_leftover.py as a case: session S starts the module
    control and crc7 loads, and modprobe -r fails at the stop. The next session of the same boot (a replacement, or
    the group's next session) lists crc7 among the modules of its own start, yet its return predicate does not hold
    and its first control does not start: halt() named crc7 in STATE, outside the kind's state files, so that is no
    state residue. Once crc7 is unloaded the record goes, and the next control starts."""
    def now():  # The levels of a session starting now (guest_state.py levels lists the loaded modules).
        return levels(sorted(udalosti.loaded_modules()))
    udalosti.main(start("kontrola_modul_jadra", "control", now()["modules"]))  # Session S.
    assert printed(capsys)["started"] is True and "crc7" in udalosti.loaded_modules()
    control_guest.modprobe_fails.add("crc7")
    udalosti.main(["stop", "kontrola_modul_jadra", "--polarity", "control"])
    named = {"residues": [{"residue": "module", "name": "crc7"}], "evidence": ["candidate module crc7 is loaded"]}
    assert printed(capsys)["cleanup"] == {"ok": False, **named}
    replacement = now()  # Session S-r1 of the same boot.
    assert replacement["modules"] == BOOT
    found = guest_state.baseline(replacement, None)
    assert (found["ok"], found["exact"]["residues"], found["evidence"]) == (False, named["residues"],
                                                                            named["evidence"])
    assert [path.name for path in control_guest.state.iterdir()] == [udalosti.LEFT_LOADED]
    udalosti.main(start("kontrola_wx_memfd", "control", replacement["modules"]))
    record = printed(capsys)
    assert (record["started"], record["error"], record["baseline"]["exact"]) == (
        False, "the return predicate does not hold", {"ok": False, "residues": named["residues"]})
    control_guest.modprobe_fails.discard("crc7")
    control_guest.unload("crc7")  # Removed by hand.
    assert guest_state.baseline(now(), None)["exact"] == {"ok": True, "residues": []}
    assert not (control_guest.state / udalosti.LEFT_LOADED).exists()
    udalosti.main(start("kontrola_wx_memfd", "control", now()["modules"]))
    assert printed(capsys)["started"] is True


def test_a_stop_without_the_modules_of_the_start_counts_every_loaded_candidate_and_says_why(control_guest, capsys):
    """Finding F6 of the B9a verification (the mutant residue_none_lenient): the stop of an occurrence whose start was
    refused remembers no modules of the session's start (None), so no loaded candidate can be ruled out, the one the
    kernel loaded at boot included. The residue names the rule it was found by (no silent default)."""
    control_guest.load("crc7")
    control_guest.failed.append("hyptcn-lab@catalog.service")
    udalosti.main(start("kontrola_wx_memfd", "control", BOOT))
    record = printed(capsys)
    assert (record["started"], record["baseline"]["exact"]["residues"]) == (
        False, [{"residue": "unit", "unit": "hyptcn-lab@catalog.service"}])  # crc7 is among the modules of the start.
    udalosti.main(["stop", "kontrola_wx_memfd", "--polarity", "control"])
    why = "the modules loaded at the session's start are not known, so it cannot be ruled out"
    assert printed(capsys)["cleanup"] == {"ok": False, "residues": [{"residue": "module", "name": "crc7", "why": why}],
                                          "evidence": [f"candidate module crc7 is loaded ({why})"]}
