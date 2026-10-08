import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503 if self.server.fail else 200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *_):
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    http.fail = False
    thread = threading.Thread(target=http.serve_forever)
    thread.start()
    yield http, f"http://127.0.0.1:{http.server_port}"
    http.shutdown()
    http.server_close()
    thread.join()


@pytest.mark.parametrize("failure", [False, True])
def test_traffic_reports_http_failures_and_observed_time(server, tmp_path, failure):
    http, target = server
    http.fail = failure
    out = tmp_path / "metrics.json"
    result = subprocess.run([sys.executable, REPO / "scripts/host_traffic.py", "--target", target,
                             "--dur", ".4", "--vlakien", "2", "--out", out], timeout=10, capture_output=True)
    doc = json.loads(out.read_text())
    assert result.returncode == int(failure)
    assert doc["final"]
    assert doc["requests"] > 0
    assert doc["ok"] + doc["errors"] == doc["requests"]
    assert doc["elapsed_s"] >= .4
    assert doc["status_codes"]["503" if failure else "200"] == doc["requests"]


def test_continuous_traffic_flushes_on_sigterm(server, tmp_path):
    _, target = server
    out = tmp_path / "metrics.json"
    process = subprocess.Popen([sys.executable, REPO / "scripts/host_traffic.py", "--target", target,
                                "--dur", "0", "--vlakien", "1", "--out", out],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not out.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert out.exists()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=6) == 0
        assert json.loads(out.read_text())["final"]
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()
