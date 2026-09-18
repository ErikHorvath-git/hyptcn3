"""
Testy kontrol a porovnania s pozemnou pravdou.

Cast bezi nad realnou snimkou (fixture val_view), cast nad vymyslenymi
vstupmi - porovnavaciu logiku treba overit aj na pripadoch, ktore cisty host
nikdy nevyrobi (chybajuci proces, falosny proces, nezhoda mena).
"""

import pytest

from guestparse import checks, validate


# --------------------------------------------------- nad realnou snimkou


def test_cisty_host_nema_nalezy(val_view):
    """Na neinfikovanom hostovi musia vyjst nuly - a musia byt uzavrete."""
    res = checks.check_all(val_view)
    assert res["finding_count"] == 0, res["findings"]
    assert res["summary"]["syscall_hooks"] == 0
    assert res["summary"]["inconclusive"] == [], res["summary"]


def test_tabulka_volani_ma_rozumnu_dlzku(val_view):
    res = checks.syscall_table(val_view)
    assert res["available"], res["reason"]
    # 6.1/x86_64 ma 451 volani; dlzka sa odvodzuje z kallsyms, nie z konstanty
    assert 300 <= res["entries"] <= 600
    assert res["padding_trimmed"] >= 0
    assert res["entries"] + res["padding_trimmed"] == res["entries_from_symbol_gap"]


def test_krizovy_pohlad_na_procesy_sedi(val_view):
    res = checks.process_cross_view(val_view)
    assert res["available"] and res["conclusive"], res["reason"]
    assert res["list_count"] == res["tree_count"]
    assert res["findings"] == []


def test_krizovy_pohlad_na_moduly_sedi(val_view):
    res = checks.module_checks(val_view)
    assert res["available"]
    assert res["sysfs_available"], res.get("reason")
    assert res["conclusive"], res.get("reason")
    # v kset su aj vstavane moduly s parametrami - tych je vzdy viac
    assert res["sysfs_kset_entries"] > res["sysfs_count"]
    assert res["list_count"] == res["sysfs_count"]
    assert res["findings"] == []


# ----------------------------------------------------- porovnavacia logika


def test_zhoda_mien():
    assert validate._name_match("sshd", "sshd") == (True, "exact")
    # `ps` tlaci cele meno vlakna jadra, comm ma len 15 znakov
    assert validate._name_match("rcu_tasks_kthre", "rcu_tasks_kthread") == (
        True, "truncated")
    # pracovne vlakno: `ps` pripaja popis aktualnej prace
    assert validate._name_match("kworker/0:0H",
                                "kworker/0:0H-events_highpri") == (
        True, "worker")
    assert validate._name_match("sshd", "bash")[0] is False


def test_citanie_ps(tmp_path):
    p = tmp_path / "ps.txt"
    p.write_text("    PID COMMAND\n      1 systemd\n    388 sshd\n\n")
    assert validate.read_ps(str(p)) == {1: "systemd", 388: "sshd"}


def test_citanie_lsmod(tmp_path):
    p = tmp_path / "lsmod.txt"
    p.write_text("Module                  Size  Used by\n"
                 "virtio_ring            16384  0\n"
                 "fat                    90112  1 vfat\n")
    assert validate.read_lsmod(str(p)) == {"virtio_ring", "fat"}


def test_citanie_ss(tmp_path):
    p = tmp_path / "ss.txt"
    p.write_text(
        "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Proc\n"
        "tcp   LISTEN 0      128          0.0.0.0:22       0.0.0.0:*     x\n"
        "tcp   LISTEN 0      128             [::]:22          [::]:*     x\n"
        "udp   UNCONN 0      0     127.0.0.53%lo:53        0.0.0.0:*     x\n"
        "nl    UNCONN 0      0               rtnl:systemd         *      x\n")
    rows, skipped = validate.read_ss(str(p))
    assert ("TCP", "0.0.0.0", 22, "0.0.0.0", 0) in rows
    assert ("TCP", "::", 22, "::", 0) in rows
    # rozsah rozhrania (%lo) sa odstrani, inak by sa adresa nedala porovnat
    assert ("UDP", "127.0.0.53", 53, "0.0.0.0", 0) in rows
    assert len(rows) == 3
    assert len(skipped) == 1, skipped


def test_porovnanie_procesov_hlasi_rozdiely():
    before = {1: "systemd", 2: "kthreadd", 9: "zanikol"}
    after = {1: "systemd", 2: "kthreadd", 77: "vznikol"}
    snap = [
        {"pid": 1, "comm": "systemd"},
        {"pid": 4242, "comm": "skryty"},        # v ziadnom `ps` - falosny
    ]
    res = validate.compare_processes(snap, before, after)
    assert res["stable"] == 2                    # pid 1 a 2
    assert res["found"] == 1
    assert res["missing"] == 1
    assert res["missing_list"][0]["pid"] == 2
    assert res["false_positive"] == 1
    assert res["false_positive_list"][0]["pid"] == 4242
    assert res["recall_percent"] == 50.0


def test_porovnanie_procesov_hlasi_nezhodu_mena():
    before = after = {1: "systemd"}
    res = validate.compare_processes([{"pid": 1, "comm": "evil"}], before, after)
    assert res["found"] == 1
    assert res["name_mismatch"] == 1
    assert res["name_mismatch_list"][0]["snapshot"] == "evil"


def test_pid_v_oboch_ps_s_inym_menom_ostava_stabilny():
    """
    `ps` meni pracovnym vlaknam popis medzi dvoma behmi. comm v pamati sa
    nemeni, takze taky pid zo stabilnej mnoziny vypadnut nesmie.
    """
    before = {50: "kworker/1:2-cgroup_free"}
    after = {50: "kworker/1:2-events"}
    res = validate.compare_processes([{"pid": 50, "comm": "kworker/1:2"}],
                                     before, after)
    assert res["stable"] == 1
    assert res["stable_name_identical"] == 0
    assert res["found"] == 1 and res["name_mismatch"] == 0


def test_porovnanie_modulov():
    res = validate.compare_modules(
        [{"name": "fat"}, {"name": "navyse"}], {"fat", "chyba"})
    assert res["matched"] == 1
    assert res["missing"] == 1 and res["missing_list"] == ["chyba"]
    assert res["extra"] == 1 and res["extra_list"] == ["navyse"]


def test_porovnanie_socketov_nerata_raw_do_navyse():
    snap = [
        {"proto": "TCP", "saddr": "0.0.0.0", "sport": 22,
         "daddr": "0.0.0.0", "dport": 0},
        {"proto": "RAW", "saddr": "::", "sport": 58, "daddr": "::", "dport": 0},
    ]
    gt = {("TCP", "0.0.0.0", 22, "0.0.0.0", 0)}
    res = validate.compare_sockets(snap, gt, [])
    assert res["matched"] == 1
    assert res["extra"] == 0
    assert res["snapshot_other_protocols"] == {"RAW": 1}


def test_neuplny_prechod_nie_je_uzavreta_kontrola(val_view):
    """
    Ked je zoznam procesov neuplny, krizovy pohlad sa NESMIE tvarit, ze nic
    nenasiel - nula z roztrhnuteho zoznamu nic nedokazuje.
    """
    plny = val_view.processes()
    orezany = {"processes": plny["processes"][:10], "truncated": True,
               "stop_reason": "umelo skrateny zoznam"}
    res = checks.process_cross_view(val_view, procs=orezany)
    assert res["available"] is True
    assert res["conclusive"] is False
    assert "prerusil" in res["reason"]
    # rozdiel sa aj tak vypise, ale je oznaceny ako neuzavrety
    assert len(res["findings"]) > 0

    full = checks.check_all(val_view, procs=orezany)
    assert "process_cross_view" in full["summary"]["inconclusive"]
