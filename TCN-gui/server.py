#!/usr/bin/env python3
"""TCN GUI server: http://127.0.0.1:8765, standard library only besides the project's own deps.

  python3 TCN-gui/server.py [--port 8765] [--data DIR ...] [--allow-during-collection]

The page lists bundles (`*/manifest.json` of safeguard) and session inputs found
one directory level deep under --data, and scores the chosen input with the
chosen bundle (analyza.py). Nothing is written to the repository or the data.
While a capture runs on this host the server refuses to score, because CPU and
disk load from a replay would disturb the measurement (docs/AUTOMATICKY_ZBER.sk.md).
"""
import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import traceback

import analyza

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8"}


def discover(roots):
    """Shallow listing only: never walks the archive or raw snapshot trees."""
    bundles, inputs = [], []
    for root in roots:
        root = Path(root).expanduser()
        for pattern in ("models/*/manifest.json", "*/manifest.json"):
            for manifest in root.glob(pattern):
                try:
                    if json.loads(manifest.read_text()).get("schema") == "hyptcn3/safeguard-bundle/1":
                        bundles.append(str(manifest.parent.resolve()))
                except (OSError, ValueError):
                    pass
        for pattern in ("collections/*/*.npz", "*/*.npz", "*.npz"):
            for archive in root.glob(pattern):
                inputs.append((archive.stat().st_mtime, str(archive.resolve())))
        for pattern in ("collections/*/raw", "*/raw"):
            for raw in root.glob(pattern):
                inputs.append((raw.stat().st_mtime, str(raw.resolve())))
    seen, ordered = set(), []
    for _, path in sorted(inputs, reverse=True):
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return {"bundles": sorted(set(bundles)), "inputs": ordered[:500]}


class Handler(BaseHTTPRequestHandler):
    server_version = "tcn-gui/1"

    def _send(self, status, body, content_type="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            name = "index.html"
        elif self.path.startswith("/static/"):
            name = self.path[len("/static/"):]
        elif self.path == "/api/discover":
            return self._send(HTTPStatus.OK, discover(self.server.roots))
        else:
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        path = (STATIC / name).resolve()
        if STATIC not in path.parents or not path.is_file():
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        return self._send(HTTPStatus.OK, path.read_bytes(), TYPES.get(path.suffix, "application/octet-stream"))

    def do_POST(self):
        if self.path != "/api/analyze":
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        try:
            request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if not self.server.allow_during_collection and analyza.busy_collecting():
                return self._send(HTTPStatus.CONFLICT, {"error": "Na tomto PC práve beží zber. Skórovanie by "
                                  "zaťažilo CPU a disk a narušilo meranie; spusti analýzu po zbere alebo na inom PC."})
            with self.server.lock:  # One model replay at a time.
                report = analyza.analyze(request["bundle"], request["input"],
                                         profile=request.get("profile") or None,
                                         allow_diagnostic=bool(request.get("allow_diagnostic")))
            return self._send(HTTPStatus.OK, report)
        except (ValueError, KeyError, OSError, RuntimeError) as exc:
            traceback.print_exc()
            return self._send(HTTPStatus.BAD_REQUEST, {"error": f"{type(exc).__name__}: {exc}"})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data", action="append", type=Path,
                        help="Directory with models/ and collections/ (repeatable); default: repo data/")
    parser.add_argument("--allow-during-collection", action="store_true")
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.roots = args.data or [analyza.ROOT / "data"]
    server.allow_during_collection = args.allow_during_collection
    server.lock = threading.Lock()
    print(f"TCN GUI: http://{args.host}:{args.port}/  (data: {', '.join(map(str, server.roots))})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
