"""Full checkpoints replace memory, including pages omitted because they are zero."""

import pytest

from guestparse.image import ChainError, PAGE, VMICD_HDR, VmicdImage, open_image
from guestparse.tests.test_chain import MEMSIZE, _vmicd


@pytest.mark.parametrize("new_chain", [7, 9])
@pytest.mark.parametrize("full_pages", [{}, {1: b"new checkpoint"}])
def test_full_checkpoint_discards_omitted_pages(tmp_path, new_chain, full_pages):
    _vmicd(str(tmp_path / "000.vmicd"), 7, 0, True,
           {0: b"obsolete baseline", 1: b"old checkpoint"})
    _vmicd(str(tmp_path / "001.vmicd"), 7, 1, False,
           {0: b"obsolete delta", 2: b"another obsolete page"})
    full = _vmicd(str(tmp_path / "002.vmicd"), new_chain, 2, True, full_pages)
    _vmicd(str(tmp_path / "003.vmicd"), new_chain, 3, False, {2: b"new delta"})

    # The old state is still readable when the requested time precedes reset.
    with open_image(str(tmp_path), until_seq=1) as before:
        assert before.read(0, 14) == b"obsolete delta"

    with VmicdImage(full) as standalone, open_image(str(tmp_path), until_seq=2) as timeline:
        expected = standalone.read(0, MEMSIZE)
        assert timeline.read(0, MEMSIZE) == expected
        assert timeline.page_count() == len(full_pages)
        assert not timeline.page_present(0)
        assert not timeline.page_present(2 * PAGE)

    expected = bytearray(expected)
    expected[2 * PAGE:3 * PAGE] = b"new delta".ljust(PAGE, b"\0")
    with open_image(str(tmp_path), until_seq=3) as after:
        assert after.read(0, MEMSIZE) == bytes(expected)
        assert after.page_count() == len(full_pages) + 1
        assert not after.page_present(0)


@pytest.mark.parametrize("damage", ["missing_delta", "truncated_baseline"])
def test_later_full_does_not_hide_broken_history(tmp_path, damage):
    first = _vmicd(str(tmp_path / "000.vmicd"), 7, 0, True, {0: b"first"})
    delta = _vmicd(str(tmp_path / "001.vmicd"), 7, 1, False, {0: b"changed"})
    _vmicd(str(tmp_path / "002.vmicd"), 9, 2, True, {1: b"new checkpoint"})
    if damage == "missing_delta":
        import os
        os.unlink(delta)
    else:
        with open(first, "r+b") as stream:
            stream.truncate(VMICD_HDR + 8 + PAGE // 2)
    with pytest.raises(ChainError):
        open_image(str(tmp_path), until_seq=2)
