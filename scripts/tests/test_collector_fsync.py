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
