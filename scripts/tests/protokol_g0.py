"""The protocol file as the G0 record holds it, for the tests written for that state.

From Zápis 1 of stage G2 on, tcn/hodnoty.py writes the values of the later stages into config/collection-v5.json (the
four rates and the preliminary caps first). The tests that run the tools on the file as G0 recorded it (a null rate
given by --rate, the preliminary caps 500 and 250, the null values of G1, G3a and G3b) read g0_file(): the
repository's file with every path that determined_at assigns to a later stage set back to its value at G0. The copy
is checked against the bytes the G0 record bound (G0_SHA256), so a change of the file's G0 part fails here by name
and not as a changed assertion somewhere else. A test of the file's current values reads the file itself. G0_SHA256
was the file at commit 9a869c6 of the second G0 record data/results/gate_G0_20261125T164240Z.json (8fe3eea1); package
B13 adds a value of G0, audit.traffic.order_share_session_max_s with its origin in audit.traffic.note (the lead's
answer to Q73 point 1), so it is the file of B13 with its later values set back, which the next G0 record binds.
"""
import atexit
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "config/collection-v5.json"
G0_SHA256 = "4dc32413756fb7c7eac8aface35705c33176c98f0495e82242c52bdc7a2d1822"
EXCEPTIONS = ("collector_warnings", "event_traffic_exit", "event_unit_restarts", "event_window_health_checks",
              "event_window_journal", "event_window_nginx_errors", "event_window_requests", "inconclusive_integrity",
              "invalid_rows", "rule_closed_rows", "unconfirmed_findings")
EVENT_TYPES = ("naprazdno", "restart_databazy", "udrzba_zaloha", "zamok_tabulky", "zataz_pamate",
               "zla_konfiguracia_sluzby")
# Every path of determined_at G1 to G3b with its value at the G0 record.
G0_VALUES = {
    "analysis.k1.m": None, "analysis.k2a.m": None, "analysis.k2b.m": None,
    "invalid_rows.max": 3, "min_score_coverage": 0.7736111111111111,
    **{f"scenarios.{name}.rate": None for name in ("eshop_low", "eshop_high", "corp_low", "corp_high")},
    "audit.warnings_allowed": None, "audit.collector_majflt_max": None, "controls.baseline": None,
    "profiles.eshop.max_concurrent": 500, "profiles.corp.max_concurrent": 250,
    "analysis.methods.Z1.grid": None, "analysis.methods.Z3.grid": None, "analysis.methods.Z5.grid": None,
    "analysis.columns": None, **{f"exceptions.{name}.expected": None for name in EXCEPTIONS},
    "replacement.max_per_campaign": None, "audit.rule_closed_rows_max": None,
    **{f"audit.early_stop.marked_rows_rate_per_type.{name}": None for name in EVENT_TYPES}}
_FILE = []


def g0_bytes():
    """The bytes of config/collection-v5.json as the G0 record bound them (G0_SHA256, checked)."""
    doc = json.loads(REAL.read_text())
    for path, value in G0_VALUES.items():
        *parents, key = path.split(".")
        node = doc
        for part in parents:
            node = node[part]
        assert key in node, path
        node[key] = value
    raw = (json.dumps(doc, indent=2) + "\n").encode()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == G0_SHA256, (f"config/collection-v5.json with its later values set back to G0 has sha256 {sha}, "
                              f"not the G0 record's {G0_SHA256}: the file's G0 part changed")
    return raw


def g0_copy(directory):
    """config/collection-v5.json as the G0 record bound it, written as collection-v5.json in `directory`."""
    path = Path(directory) / "collection-v5.json"
    path.write_bytes(g0_bytes())
    return path


def g0_file():
    """g0_copy() once per process, in a temporary directory removed at exit; the path."""
    if not _FILE:
        directory = tempfile.mkdtemp(prefix="protokol_g0_")
        atexit.register(shutil.rmtree, directory, True)
        _FILE.append(g0_copy(directory))
    return _FILE[0]
