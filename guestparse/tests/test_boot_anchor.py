"""A warm reboot can leave two internally plausible kernel anchor pairs."""
import json
from uuid import UUID

import pytest

from guestparse.context import capture_boot_id
from guestparse.view import GuestView, START_KERNEL_MAP, build_view

OLD = "c01be2c5-8e02-49e7-9db3-44a88ef35d35"
CURRENT = "1602ed36-8187-4f33-bbaa-a36ebff348b4"


class Profile:
    symbols = {"linux_banner": START_KERNEL_MAP + 0x1000,
               "init_task": START_KERNEL_MAP + 0x2000,
               "sysctl_bootid": START_KERNEL_MAP + 0x3000}

    def addr(self, name):
        return self.symbols.get(name)

    def member(self, structure, field):
        return 16 if (structure, field) == ("task_struct", "comm") else None


class Memory:
    def __init__(self, boots=(OLD, CURRENT)):
        self.data = bytearray(0x20000)
        self.size = len(self.data)
        self.closed = False
        for base, boot in zip((0, 0x10000), boots):
            for offset, data in ((0x1000, b"Linux version fixture\0"),
                                 (0x2010, b"swapper/0\0"),
                                 (0x3000, UUID(boot).bytes)):
                self.data[base + offset:base + offset + len(data)] = data

    def read(self, pa, n):
        return bytes(self.data[pa:pa + n])

    def pages(self):
        return ((i // 4096, bytes(self.data[i:i + 4096])) for i in range(0, self.size, 4096))

    def close(self):
        self.closed = True


def test_stale_pair_is_not_selected_by_scan_order():
    view = GuestView(Memory(), Profile(), CURRENT)
    assert view.resolve()
    assert view.banner_pa == 0x11000
    assert view.snapshot_boot_id == CURRENT
    assert [c["boot_id"] for c in view.kernel_candidates] == [OLD, CURRENT]


@pytest.mark.parametrize("boots,expected", [((OLD, CURRENT), None),
                                          ((CURRENT, CURRENT), CURRENT),
                                          ((OLD,), CURRENT)])
def test_ambiguous_or_missing_identity_never_guesses(boots, expected):
    view = GuestView(Memory(boots), Profile(), expected)
    assert not view.resolve()
    assert view.ktext_shift is None
    assert view.resolve_problem()


def test_unique_legacy_anchor_remains_supported():
    view = GuestView(Memory((OLD,)), Profile())
    assert view.resolve()
    assert view.banner_pa == 0x1000


def test_missing_boot_symbol_does_not_drop_required_identity():
    profile = Profile()
    profile.symbols = {k: v for k, v in profile.symbols.items() if k != "sysctl_bootid"}
    view = GuestView(Memory(), profile, CURRENT)
    assert not view.resolve()
    assert "sysctl_bootid" in view.resolve_problem()


def test_boot_uuid_alone_does_not_replace_init_task_anchor():
    memory = Memory()
    memory.data[0x12010:0x12020] = b"\0" * 16
    view = GuestView(memory, Profile(), CURRENT)
    assert not view.resolve()


def native(tmp_path, *, supervisor=False, boot=CURRENT, version=1):
    raw = tmp_path / "raw"
    raw.mkdir()
    if supervisor:
        name, schema, key = "run.json", "hyptcn3/safeguard-supervisor/1", "guest"
    else:
        name, schema, key = "session.json", f"hyptcn3/collection-session/{version}", "guest_before"
    (tmp_path / name).write_text(json.dumps({"schema": schema, key: {"boot_id": boot}}))
    return raw


@pytest.mark.parametrize("supervisor", [False, True])
@pytest.mark.parametrize("file_input", [False, True])
def test_native_metadata_reaches_common_parser(tmp_path, monkeypatch, supervisor, file_input):
    raw = native(tmp_path, supervisor=supervisor)
    path = raw / "snapshot.vmicd" if file_input else raw
    memory = Memory()
    monkeypatch.setattr("guestparse.image.open_image", lambda *a, **kw: memory)
    monkeypatch.setattr("guestparse.profile.Profile.from_dir", lambda *a: Profile())
    view, image = build_view(str(path), "profile")
    try:
        assert view.expected_boot_id == view.snapshot_boot_id == CURRENT
        assert view.banner_pa == 0x11000
    finally:
        image.close()


@pytest.mark.parametrize("version", [1, 2])
def test_both_session_schema_versions_provide_boot_context(tmp_path, version):
    assert capture_boot_id(native(tmp_path, version=version)) == CURRENT


def test_unknown_session_schema_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unrecognized"):
        capture_boot_id(native(tmp_path, version=3))


def test_explicit_identity_cannot_override_capture(tmp_path):
    with pytest.raises(ValueError, match="conflicts"):
        capture_boot_id(native(tmp_path), OLD)


@pytest.mark.parametrize("boot", [None, "invalid", "00000000-0000-0000-0000-000000000000"])
def test_invalid_native_identity_is_an_input_error(tmp_path, boot):
    with pytest.raises(ValueError, match="boot_id"):
        capture_boot_id(native(tmp_path, boot=boot))


def test_corrupt_metadata_is_not_treated_as_absent(tmp_path):
    raw = native(tmp_path)
    (tmp_path / "session.json").write_text("{")
    with pytest.raises(ValueError):
        capture_boot_id(raw)


def test_standalone_explicit_identity(tmp_path):
    assert capture_boot_id(tmp_path / "snapshot.vmicd", CURRENT) == CURRENT
    assert capture_boot_id(tmp_path / "snapshot.vmicd") is None
