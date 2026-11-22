"""Effect predicates of the events (lab/udalosti.py, KOSTRA B5 section 3 and section 5 item 4).

Every type once with its effect and once without, on fakes of /proc, systemctl, psql and the service ports;
naprazdno has no effect by definition and is true on a guest where nothing happened. stop evaluates the effect
before it restores the lab and prints it; the predicate never stops the restore.
"""
import gzip
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import udalosti  # noqa: E402

REFUSED = (None, None, "ConnectionRefusedError: [Errno 111] Connection refused")


@pytest.fixture
def guest(tmp_path, monkeypatch):
    """A fake guest: unit properties, the lock count psql reports and the replies of the service ports."""
    fake = SimpleNamespace(units={}, locks=0, http={}, calls=[], proc=tmp_path / "proc", state=tmp_path / "state")

    def run(*args, check=True, timeout=90):
        fake.calls.append(args)
        if args[:2] == ("systemctl", "show"):
            return subprocess.CompletedProcess(args, 0, fake.units.get((args[2], args[4]), "") + "\n", "")
        if "psql" in args:
            return subprocess.CompletedProcess(args, 0, f"{fake.locks}\n", "")
        if args[0] in ("systemctl", "rm", "nginx"):
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected guest command {args}")

    def http(method, url, body=None, token=None, timeout=10):
        fake.calls.append((method, url))
        return fake.http.get((method, url), REFUSED)

    for name, value in (("run", run), ("http", http), ("STATE", fake.state), ("PROC", fake.proc),
                        ("BACKUPS", tmp_path / "backups"), ("NGINX", tmp_path / "nginx.conf"),
                        ("DROPIN", tmp_path / "dropin/zla-konfiguracia.conf"), ("health", lambda: 200)):
        monkeypatch.setattr(udalosti, name, value)
    fake.proc.mkdir()
    fake.state.mkdir()
    (tmp_path / "nginx.conf").write_text("location /api/catalog { proxy_pass http://127.0.0.1:8081; }\n")
    return fake


def process(fake, pid, sid, rss_kib=1000, maps="", memfd=False):
    """A fake /proc/PID of session `sid` (stat, status with VmRSS, maps, fd)."""
    entry = fake.proc / str(pid)
    (entry / "fd").mkdir(parents=True)
    (entry / "stat").write_text(f"{pid} (python3) S 1 {sid} {sid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100\n")
    (entry / "status").write_text(f"Name:\tpython3\nVmRSS:\t{rss_kib:>8} kB\n")
    (entry / "maps").write_text(maps)
    if memfd:
        (entry / "fd" / "3").symlink_to("/memfd:hyptcn-kontrola (deleted)")


def before(fake, kind, **values):
    (fake.state / f"{kind}.before.json").write_text(json.dumps(values))


def background(fake, kind, sid):
    (fake.state / f"{kind}.pid").write_text(str(sid))


def catalog_loop(fake, restarts, catalog):
    before(fake, "zla_konfiguracia_sluzby", NRestarts="0")
    fake.units[("hyptcn-lab@catalog", "NRestarts")] = restarts
    fake.http[("GET", udalosti.CATALOG_URL)] = catalog


def main_pid(kind, unit, now):
    def setup(fake):
        before(fake, kind, MainPID="4100")
        fake.units[(unit, "MainPID")] = now
    return setup


def locked(fake, locks):
    fake.locks = locks
    fake.http[("POST", udalosti.TOKEN_URL)] = (200, {"token": "t"}, None)
    fake.http[("POST", udalosti.ORDERS_URL)] = (503, None, None)


def backup(fake, dump):
    udalosti.BACKUPS.mkdir()
    if dump is not None:
        (udalosti.BACKUPS / "db.sql.gz").write_bytes(gzip.compress(dump))


def load(fake, rss_kib):
    background(fake, "zataz_pamate", 500)
    process(fake, 500, 500, rss_kib=3000)  # The runuser leader.
    process(fake, 501, 500, rss_kib=rss_kib)


def control(fake, maps):
    background(fake, "kontrola_wx_memfd", 600)
    process(fake, 600, 600, maps=maps, memfd=True)


RWX = "7f0000000000-7f0000001000 rwxp 00000000 00:00 0\n"
CASES = [
    ("zla_konfiguracia_sluzby", lambda f: catalog_loop(f, "4", REFUSED), True),
    ("zla_konfiguracia_sluzby", lambda f: catalog_loop(f, "0", (200, {"products": []}, None)), False),
    ("zla_konfiguracia_nginx", lambda f: udalosti.NGINX.write_text("proxy_pass http://127.0.0.1:8091;\n"), True),
    ("zla_konfiguracia_nginx", lambda f: None, False),
    ("restart_databazy", main_pid("restart_databazy", "postgresql@15-main", "4200"), True),
    ("restart_databazy", main_pid("restart_databazy", "postgresql@15-main", "4100"), False),
    ("restart_sluzby", main_pid("restart_sluzby", "hyptcn-lab@orders", "4200"), True),
    ("restart_sluzby", main_pid("restart_sluzby", "hyptcn-lab@orders", "4100"), False),
    ("zamok_tabulky", lambda f: locked(f, 1), True),
    ("zamok_tabulky", lambda f: locked(f, 0), False),
    ("udrzba_zaloha", lambda f: backup(f, b"--\n-- PostgreSQL database dump\n--\n"), True),
    ("udrzba_zaloha", lambda f: backup(f, b""), False),  # gzip of a failed pg_dump: a header, no dump.
    ("udrzba_zaloha", lambda f: backup(f, None), False),
    ("zataz_pamate", lambda f: load(f, 400 << 10), True),
    ("zataz_pamate", lambda f: load(f, 389 << 10), False),
    ("kontrola_wx_memfd", lambda f: control(f, RWX), True),
    ("kontrola_wx_memfd", lambda f: control(f, RWX.replace("rwxp", "r-xp")), False),
]


@pytest.mark.parametrize("kind,setup,ok", CASES,
                         ids=[f"{k}-{'effect' if ok else 'none'}-{i}" for i, (k, _, ok) in enumerate(CASES)])
def test_predicate_is_true_with_the_effect_and_false_without(guest, kind, setup, ok):
    setup(guest)
    effect = udalosti.effect(kind)
    assert effect["ok"] is ok, effect
    assert effect["predicate"] == udalosti.PREDICATES[kind] and effect["evidence"]


def test_every_type_and_control_has_a_predicate():
    assert set(udalosti.EVALUATE) == set(udalosti.PREDICATES) == set(udalosti.TYPES + udalosti.CONTROLS)
    assert "naprazdno" in udalosti.TYPES


def test_order_write_is_tried_only_while_the_lock_is_seen(guest):
    locked(guest, 0)
    udalosti.effect("zamok_tabulky")
    assert ("POST", udalosti.ORDERS_URL) not in guest.calls  # Without the lock it would place a real order.
    locked(guest, 1)
    assert udalosti.effect("zamok_tabulky")["evidence"]["order_write_status"] == 503


def test_naprazdno_has_no_effect_to_show_and_is_true_where_nothing_happened(guest):
    assert udalosti.effect("naprazdno") == {"ok": True, "predicate": udalosti.PREDICATES["naprazdno"],
                                            "evidence": "iba spúšťač"}
    assert guest.calls == []  # Nothing is asked or changed: only the trigger ran.


def test_a_predicate_that_fails_is_false_and_names_the_error(guest, monkeypatch):
    def broken(*args, **kw):
        raise OSError("psql: not found")
    monkeypatch.setattr(udalosti, "run", broken)
    assert udalosti.effect("zamok_tabulky") == {"ok": False, "predicate": udalosti.PREDICATES["zamok_tabulky"],
                                                "evidence": {"error": "OSError: psql: not found"}}


def printed(capsys):
    return json.loads(capsys.readouterr().out)


def test_stop_prints_the_effect_measured_before_the_lab_is_restored(guest, monkeypatch, capsys):
    load(guest, 400 << 10)

    def kill(name):  # The restore: the load's processes are gone afterwards.
        for pid in (500, 501):
            for path in sorted((guest.proc / str(pid)).rglob("*"), reverse=True):
                path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
            (guest.proc / str(pid)).rmdir()
        return 500
    monkeypatch.setattr(udalosti, "kill_background", kill)
    udalosti.main(["stop", "zataz_pamate"])
    record = printed(capsys)
    assert record["ok"] and record["background_pid"] == 500
    assert record["effect"]["ok"] is True and record["effect"]["evidence"]["peak_rss_kib"] == 400 << 10
    assert not (guest.proc / "501").exists()


def test_stop_restores_the_lab_also_when_the_predicate_fails(guest, monkeypatch, capsys):
    monkeypatch.setattr(udalosti, "EVALUATE", {**udalosti.EVALUATE, "udrzba_zaloha": lambda: 1 / 0})
    udalosti.main(["stop", "udrzba_zaloha"])
    record = printed(capsys)
    assert record["effect"]["ok"] is False and "ZeroDivisionError" in record["effect"]["evidence"]["error"]
    assert ("rm", "-rf", str(udalosti.BACKUPS)) in guest.calls


@pytest.mark.parametrize("action", ["start", "stop", "effect"])
def test_naprazdno_only_prints_the_record(guest, capsys, action):
    udalosti.main([action, "naprazdno"])
    record = printed(capsys)
    assert record["type"] == "naprazdno" and record["ok"] and record["error"] is None
    assert ("effect" in record) is (action != "start")
    if action != "start":
        assert record["effect"]["ok"] is True and record["effect"]["evidence"] == "iba spúšťač"
    changed = [c for c in guest.calls if c[:2] != ("systemctl", "show")]
    assert changed == []  # Only the unit states of the record were read.


@pytest.mark.parametrize("kind,unit,prop,step", [
    ("restart_databazy", "postgresql@15-main", "MainPID", ("systemctl", "restart", "postgresql")),
    ("restart_sluzby", "hyptcn-lab@orders", "MainPID", ("systemctl", "restart", "hyptcn-lab@orders")),
])
def test_start_remembers_the_main_pid_before_the_restart(guest, kind, unit, prop, step):
    guest.units[(unit, prop)] = "4100"
    udalosti.start(kind)
    reads = [i for i, c in enumerate(guest.calls) if c[:5] == ("systemctl", "show", unit, "-p", prop)]
    assert reads and reads[0] < guest.calls.index(step)
    assert udalosti.remembered(kind, prop) == "4100"


def test_start_counts_catalog_restarts_from_after_its_own_restart(guest):
    guest.units[("hyptcn-lab@catalog", "NRestarts")] = "2"
    udalosti.start("zla_konfiguracia_sluzby")
    reads = [i for i, c in enumerate(guest.calls) if c[:3] == ("systemctl", "show", "hyptcn-lab@catalog")]
    assert reads[0] > guest.calls.index(("systemctl", "restart", "hyptcn-lab@catalog"))
    assert udalosti.remembered("zla_konfiguracia_sluzby", "NRestarts") == "2"
    assert "catalgo" in udalosti.DROPIN.read_text()
