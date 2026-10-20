import json
from pathlib import Path
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "vmicollect/build/vmicollect"


@pytest.mark.skipif(not BIN.exists(), reason="vmicollect is not built (make -C vmicollect)")
@pytest.mark.parametrize("fsync", ["true", "false"])
def test_fsync_setting_is_recorded_and_output_verifies(tmp_path, fsync):
    """output.fsync changes durability only; content, hashes and sidecars stay complete."""
    image = tmp_path / "img.raw"
    image.write_bytes(bytes(range(256)) * (2 * 16 * 4096))  # 32 MiB, two 16 MiB bins
    out = tmp_path / "out"
    subprocess.run([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image}",
                    "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", f"output.fsync={fsync}",
                    "-o", "schedule.interval_s=1", "-o", "schedule.max_cycles=2",
                    "-o", "features.bin_bytes=16777216"], check=True, capture_output=True, timeout=60)
    sidecars = [json.loads(p.read_text()) for p in sorted(out.glob("*.json"))]
    assert [s["seq"] for s in sidecars] == [0, 1]
    assert all(s["output"]["fsync"] is (fsync == "true") for s in sidecars)
    assert len(list(out.glob("*.vmicd"))) == 2
    subprocess.run([BIN, "verify", out], check=True, capture_output=True, timeout=60)


@pytest.mark.skipif(not BIN.exists(), reason="vmicollect is not built (make -C vmicollect)")
def test_fsync_rejects_non_boolean(tmp_path):
    result = subprocess.run([BIN, "config", "-o", "output.fsync=maybe"], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "output.fsync" in result.stderr


SHIM = r"""
#include <errno.h>
#include <stdlib.h>
static int calls;
int fsync(int fd) {
    (void)fd;
    const char *fail = getenv("FAIL_FSYNC_CALL");
    if (fail && ++calls == atoi(fail)) { errno = EIO; return -1; }
    return 0;
}
"""


@pytest.fixture
def failing_fsync(tmp_path):
    source, library = tmp_path / "shim.c", tmp_path / "libfailfsync.so"
    source.write_text(SHIM)
    try:
        subprocess.run(["cc", "-shared", "-fPIC", "-o", library, source], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("C compiler unavailable for the fsync failure shim")
    return library


@pytest.mark.skipif(not BIN.exists(), reason="vmicollect is not built (make -C vmicollect)")
def test_failed_fsync_fails_the_snapshot_and_restarts_the_chain(tmp_path, failing_fsync):
    """A failed fsync is never a published snapshot; the next one must be full."""
    image = tmp_path / "img.raw"
    image.write_bytes(bytes(range(256)) * (2 * 16 * 4096))
    out = tmp_path / "out"
    env = {"LD_PRELOAD": str(failing_fsync), "FAIL_FSYNC_CALL": "2", "PATH": "/usr/bin:/bin"}
    result = subprocess.run([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image}",
                             "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=true",
                             "-o", "output.delta_full_every=100", "-o", "schedule.interval_s=1",
                             "-o", "schedule.max_cycles=3", "-o", "features.bin_bytes=16777216"],
                            capture_output=True, text=True, timeout=60, env=env)
    assert result.returncode == 4, result.stderr  # some cycles failed: not a complete run
    assert "fsync zlyhal" in result.stderr
    sidecars = sorted((json.loads(p.read_text()) for p in out.glob("*.json")), key=lambda d: d["seq"])
    assert [s["seq"] for s in sidecars] == [0, 1]  # 3 slots, one failed and unpublished
    assert [s["output"]["full"] for s in sidecars] == [True, True]  # chain restarted after the failure
    assert len(list(out.glob("*.vmicd"))) == 2 and not list(out.glob(".*"))
    subprocess.run([BIN, "verify", out], check=True, capture_output=True, timeout=60)


@pytest.mark.skipif(not BIN.exists(), reason="vmicollect is not built (make -C vmicollect)")
def test_disabled_fsync_never_calls_fsync(tmp_path, failing_fsync):
    image = tmp_path / "img.raw"
    image.write_bytes(bytes(range(256)) * (2 * 16 * 4096))
    out = tmp_path / "out"
    env = {"LD_PRELOAD": str(failing_fsync), "FAIL_FSYNC_CALL": "1", "PATH": "/usr/bin:/bin"}
    result = subprocess.run([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image}",
                             "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=false",
                             "-o", "schedule.interval_s=1", "-o", "schedule.max_cycles=2",
                             "-o", "features.bin_bytes=16777216"], capture_output=True, text=True, timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    assert len(list(out.glob("*.vmicd"))) == 2
