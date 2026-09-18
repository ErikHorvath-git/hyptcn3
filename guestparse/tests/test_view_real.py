"""
Testy nad realnou snimkou hosta (/var/tmp/vmic-val), bez roota a bez VM.

Snimka bola odobrata z bezacej domeny hyptcn-guest, takze presne pocty sa
medzi snimkami lisia. Testy preto overuju dolne hranice a vlastnosti, ktore
musia platit vzdy - nie konkretne cisla z jedneho behu. Cisla z porovnania
s pozemnou pravdou patria do meraneho reportu, nie do testov.
"""

import ipaddress


def test_posun_sa_nasiel(val_view):
    assert val_view.ktext_shift is not None
    assert val_view.page_offset_base
    assert "Linux version " in (val_view.banner or "")
    assert val_view.banner_candidates >= 1


def test_preklad_adries_sa_zhoduje(val_view):
    """
    Krizova kontrola: linearny vypocet vs. prechod tabuliek stranok.
    Ked sa rozidu, posun je zly a vsetko ostatne je nahoda.
    """
    rows = {r["symbol"]: r for r in val_view.translation_check()}
    for name in ("linux_banner", "init_task"):
        r = rows[name]
        assert r["linear_pa"] is not None
        assert r["walk_pa"] is not None
        assert r["linear_pa"] == r["walk_pa"], name


def test_procesy(val_view):
    res = val_view.processes()
    assert res["truncated"] is False, res["stop_reason"]
    assert res["count"] >= 70
    comms = {p["comm"] for p in res["processes"]}
    assert "systemd" in comms
    pids = [p["pid"] for p in res["processes"]]
    assert len(pids) == len(set(pids)), "ten isty pid dvakrat"
    assert any(p["kernel_thread"] for p in res["processes"])
    assert any(not p["kernel_thread"] for p in res["processes"])


def test_moduly(val_view):
    res = val_view.modules()
    assert res["truncated"] is False, res["stop_reason"]
    assert res["count"] >= 40
    names = {m["name"] for m in res["modules"]}
    assert "virtio_ring" in names
    # struct module lezi v oblasti modulov, ktora linearne mapovana nie je
    assert all(m["module_va"] >= 0xFFFFFFFFC0000000 for m in res["modules"])


def test_sokety_maju_urceny_protokol(val_view):
    """Po doplneni v6 symbolov sa socket uz nesmie reportovat ako '?'."""
    res = val_view.sockets()
    assert res["count"] > 0
    assert res.get("missing_symbols") is None
    neurcene = [s for s in res["sockets"] if s["proto"] == "?"]
    assert neurcene == [], neurcene


def test_ipv6_sokety(val_view):
    res = val_view.sockets()
    v6 = [s for s in res["sockets"] if s["family"] == "IPv6"]
    assert len(v6) >= 2, "v hostovi pocuva sshd aj resolved cez IPv6"
    for s in v6:
        # RFC 5952: skrateny zapis, male pismena; musi sa dat spatne precitat
        assert ipaddress.ip_address(s["saddr"]).version == 6
        assert ipaddress.ip_address(s["daddr"]).version == 6
        assert s["saddr"] == s["saddr"].lower()
        assert "0000" not in s["saddr"]
        assert 0 <= s["sport"] <= 65535
    # sshd pocuva na :22 cez IPv4 aj IPv6
    l22 = {s["family"] for s in res["sockets"]
           if s["sport"] == 22 and s["state"] == "LISTEN"}
    assert l22 == {"IPv4", "IPv6"}


def test_ipv6_adresa_nie_je_orezana_ipv4(val_view):
    """
    Pred doplnenim K10 sa IPv6 adresa citala zo 4-bajtoveho pola skc_rcv_saddr.
    Test drzi rozdiel: v6 adresa musi byt cela 16-bajtova a lezat na inom
    offsete nez v4.
    """
    sc = val_view.p.off["sock_common"]["members"]
    assert sc["skc_v6_rcv_saddr"] != sc["skc_rcv_saddr"]
    res = val_view.sockets()
    v6 = [s for s in res["sockets"] if s["family"] == "IPv6"]
    assert v6
    assert all(s["saddr"] == "::" or ":" in s["saddr"] for s in v6)


def test_sokety_sedia_s_procesmi(val_view):
    procs = val_view.processes()["processes"]
    znamy = {p["pid"] for p in procs}
    res = val_view.sockets(procs=procs)
    for s in res["sockets"]:
        assert s["pid"] in znamy
        assert s["fd"] >= 0


def test_info(val_view):
    inf = val_view.info()
    assert inf["resolved"] is True
    assert inf["image"]["pages_present"] > 0
    assert inf["profile"]["symbols"] > 1000
    assert all(r["match"] for r in inf["translation_check"])
