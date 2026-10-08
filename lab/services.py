#!/usr/bin/env python3
"""Benign lab workload: separate auth, catalog, orders and queue worker processes.

This is a demo shop API for generating measurable traffic, not a security agent.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import signal
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import psycopg2
from psycopg2.pool import ThreadedConnectionPool

PORTS = {"catalog": 8081, "auth": 8082, "orders": 8083}
SECRET = os.environ.get("LAB_SECRET", "").encode()
POOL = None


@contextmanager
def database():
    conn = POOL.getconn()
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout = '3s'")
                yield cursor
    finally:
        POOL.putconn(conn)


def token_for(user):
    payload = base64.urlsafe_b64encode(json.dumps({"user": user, "exp": int(time.time()) + 3600}).encode()).decode()
    return payload + "." + hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()


def token_user(token):
    try:
        payload, signature = token.split(".")
        if not hmac.compare_digest(signature, hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data["user"] if data["exp"] > time.time() else None
    except (ValueError, KeyError, TypeError):
        return None


def fetch(service, path, token=""):
    request = urllib.request.Request(f"http://127.0.0.1:{PORTS[service]}{path}",
                                     headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=4) as response:
        return json.load(response)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= 8192:
            raise ValueError("JSON body must be between 1 and 8192 bytes")
        doc = json.loads(self.rfile.read(length))
        if not isinstance(doc, dict):
            raise ValueError("JSON object required")
        return doc

    def do_GET(self):
        self.handle_api("GET")

    def do_POST(self):
        self.handle_api("POST")

    def handle_api(self, method):
        try:
            self.route(method)
        except (ValueError, TypeError, KeyError) as error:
            self.close_connection = True
            self.reply(400, {"error": str(error)})
        except urllib.error.HTTPError as error:
            self.reply(401 if error.code == 401 else 503, {"error": "upstream rejected request"})
        except (psycopg2.Error, OSError) as error:
            self.log_error("dependency error: %s", error)
            self.reply(503, {"error": "dependency unavailable"})

    def route(self, method):
        path = urlsplit(self.path).path
        service = self.server.service
        if path == "/healthz" and method == "GET":
            if service != "auth":
                with database() as cursor:
                    cursor.execute("SELECT 1")
            if service == "orders":
                fetch("catalog", "/healthz")
                fetch("auth", "/healthz")
                with database() as cursor:
                    cursor.execute("SELECT EXTRACT(EPOCH FROM now() - updated_at) FROM worker_heartbeat WHERE id=1")
                    row = cursor.fetchone()
                if not row or row[0] > 15:
                    self.reply(503, {"status": "degraded", "worker": "stale"})
                    return
            self.reply(200, {"status": "ok", "service": service, "database": service != "auth"})
            return
        if service == "auth":
            if path == "/api/auth/token" and method == "POST":
                user = self.body().get("user", "demo")
                if not isinstance(user, str) or not user.isalnum() or not 1 <= len(user) <= 32:
                    raise ValueError("user must be 1..32 alphanumeric characters")
                # Deliberately passwordless demo identities for this lab only.
                self.reply(200, {"token": token_for(user), "user": user, "expires_in": 3600, "demo": True})
                return
            if path == "/api/auth/check" and method == "GET":
                user = token_user(self.headers.get("Authorization", "").removeprefix("Bearer "))
                self.reply(200 if user else 401, {"user": user})
                return
        if service == "catalog" and method == "GET":
            if path == "/api/catalog":
                with database() as cursor:
                    cursor.execute("SELECT id, name, price_cents FROM products ORDER BY id")
                    products = [dict(zip(("id", "name", "price_cents"), row)) for row in cursor.fetchall()]
                self.reply(200, {"products": products})
                return
            if path.startswith("/api/catalog/"):
                product_id = int(path.rsplit("/", 1)[1])
                with database() as cursor:
                    cursor.execute("SELECT id, name, price_cents FROM products WHERE id=%s", (product_id,))
                    row = cursor.fetchone()
                self.reply(200 if row else 404, dict(zip(("id", "name", "price_cents"), row)) if row else {"error": "unknown product"})
                return
        if service == "orders" and path == "/api/orders":
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            user = fetch("auth", "/api/auth/check", token)["user"]
            if method == "GET":
                with database() as cursor:
                    cursor.execute("SELECT id, product_id, quantity, total_cents, status FROM orders WHERE username=%s ORDER BY id DESC LIMIT 50", (user,))
                    orders = [dict(zip(("id", "product_id", "quantity", "total_cents", "status"), row)) for row in cursor.fetchall()]
                self.reply(200, {"orders": orders})
                return
            if method == "POST":
                body = self.body()
                product_id, quantity = body.get("product_id"), body.get("quantity", 1)
                if type(product_id) is not int or type(quantity) is not int or not 1 <= quantity <= 20:
                    raise ValueError("integer product_id and quantity 1..20 required")
                product = fetch("catalog", f"/api/catalog/{product_id}")
                with database() as cursor:
                    cursor.execute("INSERT INTO orders(username,product_id,quantity,total_cents) VALUES (%s,%s,%s,%s) RETURNING id", (user, product_id, quantity, product["price_cents"] * quantity))
                    order_id = cursor.fetchone()[0]
                self.reply(201, {"id": order_id, "status": "pending"})
                return
        self.reply(404, {"error": "unknown route"})


def worker():
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        with database() as cursor:
            cursor.execute("UPDATE orders SET status='completed' WHERE id IN (SELECT id FROM orders WHERE status='pending' ORDER BY id LIMIT 50 FOR UPDATE SKIP LOCKED)")
            completed = cursor.rowcount
            cursor.execute("INSERT INTO worker_heartbeat(id,updated_at) VALUES (1,now()) ON CONFLICT (id) DO UPDATE SET updated_at=now()")
            # Keep persistent demonstration traffic bounded on disk.
            cursor.execute("DELETE FROM orders WHERE created_at < now() - interval '1 day' AND status='completed'")
        if completed:
            print(json.dumps({"service": "worker", "completed": completed}), flush=True)
        stop.wait(1)


def main():
    global POOL
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=[*PORTS, "worker"])
    service = parser.parse_args().service
    if not SECRET:
        raise SystemExit("LAB_SECRET is required")
    if service != "auth":
        POOL = ThreadedConnectionPool(1, 12, dbname="hyptcn_lab", user="hyptcnlab", host="/var/run/postgresql", connect_timeout=5)
    try:
        if service == "worker":
            worker()
        else:
            server = ThreadingHTTPServer(("127.0.0.1", PORTS[service]), Handler)
            server.service = service
            server.serve_forever()
    finally:
        if POOL:
            POOL.closeall()


if __name__ == "__main__":
    main()
