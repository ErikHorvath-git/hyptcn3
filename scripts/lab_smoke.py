#!/usr/bin/env python3
"""Exercise real host -> nginx -> APIs -> PostgreSQL -> worker traffic."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:18080")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    checks = []

    def call(path, expected, method="GET", body=None, token=""):
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        request = urllib.request.Request(args.target + path, method=method, headers=headers,
                                         data=json.dumps(body).encode() if body is not None else None)
        started = time.monotonic()
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            code = response.status
        checks.append({"method": method, "path": path, "expected": expected, "status": code,
                       "elapsed_ms": round((time.monotonic() - started) * 1000, 3)})
        assert code == expected, checks[-1]
        return json.loads(data) if data and data.lstrip().startswith(b"{") else None

    health = call("/healthz", 200)
    assert health["status"] == "ok"
    products = call("/api/catalog", 200)["products"]
    assert len(products) >= 5
    call("/api/orders", 401)
    token = call("/api/auth/token", 200, "POST", {"user": "smoketest"})["token"]
    call("/api/orders", 401, token=token + "invalid")
    call("/api/orders", 400, "POST", {"product_id": 1, "quantity": 0}, token)
    call("/api/orders", 400, "POST", {"product_id": 1, "quantity": True}, token)
    order = call("/api/orders", 201, "POST", {"product_id": 1, "quantity": 2}, token)
    assert order["status"] == "pending"
    deadline = time.monotonic() + 10
    while True:
        orders = call("/api/orders", 200, token=token)["orders"]
        result = next(row for row in orders if row["id"] == order["id"])
        assert result["total_cents"] == products[0]["price_cents"] * 2
        if result["status"] == "completed":
            break
        assert time.monotonic() < deadline, "Worker failed to process order"
        time.sleep(.3)
    call("/does-not-exist", 404)
    git = lambda *a: subprocess.check_output(["git", "-C", str(REPO), *a], text=True).strip()
    stamp = datetime.now(timezone.utc)
    artifact = {
        "schema": "hyptcn3/lab-smoke/1", "commit": git("rev-parse", "HEAD"),
        "commit_dirty": bool(git("status", "--porcelain")), "date": stamp.isoformat(),
        "host": platform.platform(), "guest": {"domain": "hyptcn-lab", "target": args.target},
        "command": "python3 scripts/lab_smoke.py --target " + args.target,
        "n": len(checks), "values": {"checks": checks, "order_completed": True,
                                    "source_sha256": {
                                        str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in sorted((REPO / "lab").glob("*")) if p.is_file()}}}
    out = args.out or REPO / "data/results" / ("lab_smoke_" + stamp.strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x") as file:
        json.dump(artifact, file, indent=2)
        file.write("\n")
    print(f"PASS: {len(checks)} HTTP checks, order {order['id']} completed by worker. Evidence: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
