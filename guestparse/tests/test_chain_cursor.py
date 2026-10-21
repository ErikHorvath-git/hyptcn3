"""ChainCursor must reproduce open_image(dir, until_seq=s) exactly, step by step."""
import os

import pytest

from guestparse.image import ChainCursor, ChainError, PAGE, VMICD_HDR, open_image
from guestparse.tests.test_chain import MEMSIZE, _vmicd


def _session(tmp_path):
    """Two chains: deltas, a second full checkpoint omitting pages, more deltas."""
    _vmicd(str(tmp_path / "000.vmicd"), 7, 0, True, {0: b"baseline", 1: b"old one"})
    _vmicd(str(tmp_path / "001.vmicd"), 7, 1, False, {0: b"delta 1", 2: b"page two"})
    _vmicd(str(tmp_path / "002.vmicd"), 7, 2, False, {3: b"delta 2"})
    _vmicd(str(tmp_path / "003.vmicd"), 9, 3, True, {1: b"second full"})
    _vmicd(str(tmp_path / "004.vmicd"), 9, 4, False, {2: b"after reset"})
    _vmicd(str(tmp_path / "005.vmicd"), 9, 5, False, {1: b"again", 3: b"three"})
    return 6


def _state(image):
    return (image.read(0, MEMSIZE), image.page_count(), dict(image.index), image.seq_to,
            image.chain_id, image.memsize, image.page_size)


def test_each_step_equals_a_fresh_open(tmp_path):
    n = _session(tmp_path)
    with ChainCursor(str(tmp_path)) as cursor:
        for seq in range(n):
            with open_image(str(tmp_path), until_seq=seq) as fresh:
                assert _state(cursor.image_at(seq)) == _state(fresh)


def test_repeated_and_decreasing_steps_rebuild_correctly(tmp_path):
    _session(tmp_path)
    with ChainCursor(str(tmp_path)) as cursor:
        for seq in (2, 2, 4, 1, 5, 3):
            with open_image(str(tmp_path), until_seq=seq) as fresh:
                assert _state(cursor.image_at(seq)) == _state(fresh)


@pytest.mark.parametrize("damage", ["missing_delta", "truncated_delta"])
def test_broken_history_fails_at_the_same_steps(tmp_path, damage):
    n = _session(tmp_path)
    if damage == "missing_delta":
        os.unlink(tmp_path / "002.vmicd")
    else:
        with open(tmp_path / "002.vmicd", "r+b") as stream:
            stream.truncate(VMICD_HDR + 8 + PAGE // 2)
    with ChainCursor(str(tmp_path)) as cursor:
        for seq in range(n):
            try:
                with open_image(str(tmp_path), until_seq=seq):
                    expected = None
            except ChainError as exc:
                expected = type(exc)
            if expected is None:
                cursor.image_at(seq)
            else:
                with pytest.raises(expected):
                    cursor.image_at(seq)


def test_new_parts_are_seen_like_a_fresh_open(tmp_path):
    _vmicd(str(tmp_path / "000.vmicd"), 7, 0, True, {0: b"baseline"})
    with ChainCursor(str(tmp_path)) as cursor:
        cursor.image_at(0)
        _vmicd(str(tmp_path / "001.vmicd"), 7, 1, False, {1: b"live delta"})
        with open_image(str(tmp_path), until_seq=1) as fresh:
            assert _state(cursor.image_at(1)) == _state(fresh)
