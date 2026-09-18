"""
Testy profilu jadra hosta: symboly a zostup do anonymnych unionov.

Jadro veci: v jadre 6.1 su `skc_daddr`, `skc_rcv_saddr`, `skc_dport` a
`skc_num` vnorene v ANONYMNYCH unionoch (bpftool ich vypisuje ako '(anon)').
Extraktor offsetov musi do nich zostupit - inak tieto polia chybaju uplne a
sokety nemaju adresy ani porty.
"""

import pytest

from guestparse.profile import Profile, ProfileError, btf_offsets


def test_symboly_hosta(profile):
    for s in ("linux_banner", "init_task", "modules", "page_offset_base",
              "init_top_pgt", "socket_file_ops"):
        assert profile.addr(s), "chyba symbol %s" % s
    # bez v6 symbolov by IPv6 socket nemal urceny protokol
    for s in ("tcp_prot", "udp_prot", "tcpv6_prot", "udpv6_prot"):
        assert profile.addr(s), "chyba symbol %s" % s
    assert profile.addr("tcpv6_prot") != profile.addr("tcp_prot")


def test_zostup_do_anonymnych_unionov(profile):
    """Polia vnorene v anonymnych unionoch sock_common."""
    sc = profile.off["sock_common"]["members"]
    assert sc["skc_dport"] == 12
    assert sc["skc_num"] == 14
    assert sc["skc_daddr"] == 0
    assert sc["skc_rcv_saddr"] == 4


def test_offsety_ipv6_poli(profile):
    """16-bajtove IPv6 adresy lezia mimo anonymnych unionov, ale musia byt."""
    sc = profile.off["sock_common"]["members"]
    assert sc["skc_v6_daddr"] == 56
    assert sc["skc_v6_rcv_saddr"] == 72
    assert sc["skc_v6_rcv_saddr"] + 16 <= profile.off["sock_common"]["size"]


def test_offsety_struktur(profile):
    assert profile.member("task_struct", "tasks") == 2192
    assert profile.member("task_struct", "comm") == 2976
    assert profile.member("task_struct", "pid") == 2416
    assert profile.member("module", "list") == 8
    assert profile.member("module", "name") == 24


def test_require_hlasi_chybajuce_pole(profile):
    with pytest.raises(ProfileError):
        profile.require("task_struct", "takeetopolenieje")
    with pytest.raises(ProfileError):
        profile.require("neexistujuca_struktura", "x")


def test_from_dir_chybajuci_profil(tmp_path):
    with pytest.raises(ProfileError):
        Profile.from_dir(str(tmp_path))
    with pytest.raises(ProfileError):
        Profile.from_dir(str(tmp_path / "niet"))


def test_flatten_na_umelom_vypise(tmp_path):
    """
    Zostup do anonymnych clenov na minimalnom vypise: pole vnorene dve
    urovne hlboko musi vyjst na sucet bitovych posunov.
    """
    dump = tmp_path / "btf.txt"
    dump.write_text(
        "[1] INT 'unsigned short' size=2 bits_offset=0\n"
        "[2] STRUCT 'vnorena' size=4 vlen=2\n"
        "\t'a' type_id=1 bits_offset=0\n"
        "\t'b' type_id=1 bits_offset=16\n"
        "[3] UNION '(anon)' size=4 vlen=1\n"
        "\t'(anon)' type_id=2 bits_offset=0\n"
        "[4] STRUCT 'vonkajsia' size=8 vlen=2\n"
        "\t'hlavicka' type_id=1 bits_offset=0\n"
        "\t'(anon)' type_id=3 bits_offset=32\n"
    )
    off = btf_offsets(str(dump), {"vonkajsia"})
    assert off["vonkajsia"]["members"] == {"hlavicka": 0, "a": 4, "b": 6}
