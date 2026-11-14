"""Pilotna pozitivna kontrola proc_wx a proc_memfd (lab/udalosti.py, kontrola_wx_memfd).

Overuje sa, ze program kontroly naozaj drzi rwx mapovanie a otvoreny memfd a
ze ho dokaz zo strany hosta (control_evidence) najde; mimo kontroly nic.
Ziadne cislo tu nie je meranie (HONESTY P4).
"""
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import udalosti  # noqa: E402


def test_kontrola_ma_rwx_a_memfd_a_dokaz_ju_najde():
    proc = subprocess.Popen([sys.executable, "-c", udalosti.CONTROL_PROGRAM], start_new_session=True,
                            stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not udalosti.control_evidence(proc.pid):
            if proc.poll() is not None:
                err = proc.stderr.read().decode()
                pytest.skip("hostitel nepovolil rwx mapovanie: " + err[-200:])
            time.sleep(0.1)
        assert udalosti.control_evidence(proc.pid)
        assert proc.pid in udalosti.session_members(proc.pid)
    finally:
        proc.kill()
        proc.wait()
    assert not udalosti.control_evidence(proc.pid)


def test_kontrola_nie_je_beznou_udalostou():
    assert "kontrola_wx_memfd" in udalosti.CONTROLS and "kontrola_wx_memfd" not in udalosti.TYPES
