#!/usr/bin/env python3
"""Benign lab workload: separate auth, catalog, orders, docs and queue worker processes.

This is a demo shop and document API for generating measurable traffic, not a security agent.
Protocol v5 (package B5): profile `eshop` pages and searches the catalog, fills a cart and orders it
(customers stay passwordless); profile `corp` logs employees in with a password (PBKDF2, lab/seed.py),
lists, downloads and uploads documents and requests reports, which the worker runs as three
subprocesses. Every service runs on both VMs; a profile is only the traffic.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import random
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit
import uuid

import psycopg2
from psycopg2.pool import PoolError, ThreadedConnectionPool

PORTS = {"catalog": 8081, "auth": 8082, "orders": 8083, "docs": 8084}
SECRET = os.environ.get("LAB_SECRET", "").encode()
POOL = None  # The Pool of the service's process (main).
# The lead's answer to Q74 (2026-11-25T22:15Z, package B13): a request waits for a free connection of its service's
# pool at most as long as one statement of the services may run, their statement_timeout. One constant for both.
DATABASE_TIMEOUT_S = 3
STATEMENT_TIMEOUT = f"SET LOCAL statement_timeout = '{DATABASE_TIMEOUT_S}s'"
POOL_SIZE, WORKER_POOL_SIZE = 12, 1  # The connections of a service's process, and of the worker's.
# The listen backlog of every service's server and of nginx (packages B15 and B19, Q80 and Q91, the executor's decisions
# without the lead): what the lab gets in the generator's client timeout at its peak, 987.6 requests a second at the
# measured throughput of 128 sessions/s (series 39 of G2) x 10 s (scripts/host_traffic.py TIMEOUT_S), rounded up to a
# power of two; lab/hyptcn-lab-sysctl.conf raises the guests' somaxconn to it. B15's 2048 (189 x 10 s, run 17) and
# nginx's 511 overflowed at a pause of the guest of about 1 s (long run 35: TcpExtListenOverflows 1974 on VM a).
LISTEN_BACKLOG = 16384
# Journal line of a worker round that failed on a statement timeout; scripts/collection_logs.py
# admits it only inside an event window, like a traceback. A failed report stage prints the same prefix.
WORKER_ERROR = "worker dependency error: "
DATA = Path("/var/lib/hyptcn-lab")  # lab/install.sh creates it; ReadWritePaths of the units.
DOCS, REPORTS, SPOOL, LOGS = DATA / "docs", DATA / "reports", DATA / "spool", DATA / "logs"
DOCS_LOG = LOGS / "docs.log"
MAX_DOCUMENT = 8 << 20  # KOSTRA B5 section 1: upload cap 8 MiB (nginx.conf: client_max_body_size 8m).
# Executor's judgment (B5a): page sizes, query length, retained files, timeouts of the background jobs.
PAGE_SIZE, MAX_PAGE_SIZE, MAX_PAGE, MAX_QUERY, MAX_IDS = 20, 100, 1000, 64, 100
REPORTS_KEPT, DOCS_LOGS_KEPT = 100, 12
STAGE_TIMEOUT_S = 60
# KOSTRA B5 section 1: the worker loop pauses 0.8 to 1.2 s (uniform), so it has no fixed period.
PAUSE_S = (.8, 1.2)
TEMPFAIL = 75  # hyptcn-lab-udrzba.service SuccessExitStatus: the database was unreachable or locked.
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
REPORT_ID = re.compile(r"\d{8}T\d{12}Z-[0-9a-f]{8}")
# An unknown employee costs one PBKDF2 like a known one (lab/seed.py PBKDF2_ITERATIONS), so a wrong
# name and a wrong password take the same time.
UNKNOWN_EMPLOYEE = "pbkdf2_sha256$100000$" + "00" * 16 + "$" + "00" * 32

SQL_PRODUCT_PAGE = "SELECT id, name, price_cents FROM products ORDER BY id LIMIT %s OFFSET %s"
SQL_PRODUCT_COUNT = "SELECT count(*) FROM products"
SQL_PRODUCT_SEARCH = ("SELECT id, name, price_cents FROM products WHERE name ILIKE %s ESCAPE '\\' "
                      "ORDER BY id LIMIT %s OFFSET %s")
SQL_PRODUCT_SEARCH_COUNT = "SELECT count(*) FROM products WHERE name ILIKE %s ESCAPE '\\'"
SQL_PRODUCT = "SELECT id, name, price_cents, category, description FROM products WHERE id=%s"
SQL_PRICES = "SELECT id, price_cents FROM products WHERE id = ANY(%s) ORDER BY id"
SQL_PRODUCT_EXISTS = "SELECT 1 FROM products WHERE id=%s"
SQL_EMPLOYEE = "SELECT password_hash FROM employees WHERE username=%s"
SQL_CART = ("SELECT c.product_id, c.quantity, p.price_cents FROM cart_items c JOIN products p ON p.id = c.product_id "
            "WHERE c.username=%s ORDER BY c.product_id")
SQL_CART_ADD = ("INSERT INTO cart_items (username, product_id, quantity) VALUES (%s, %s, %s) "
                "ON CONFLICT (username, product_id) DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity, "
                "added_at = now() WHERE cart_items.quantity + EXCLUDED.quantity <= 20 RETURNING quantity")
SQL_CART_ITEMS = "SELECT product_id, quantity FROM cart_items WHERE username=%s ORDER BY product_id"
SQL_CART_CLEAR = "DELETE FROM cart_items WHERE username=%s"
SQL_ORDER = "INSERT INTO orders (username, total_cents) VALUES (%s, %s) RETURNING id"
SQL_ORDER_ITEM = "INSERT INTO order_items (order_id, product_id, quantity, price_cents) VALUES (%s, %s, %s, %s)"
SQL_ORDER_LIST = ("SELECT o.id, o.total_cents, o.status, i.product_id, i.quantity, i.price_cents FROM "
                  "(SELECT id, total_cents, status FROM orders WHERE username=%s ORDER BY id DESC LIMIT 50) o "
                  "LEFT JOIN order_items i ON i.order_id = o.id ORDER BY o.id DESC, i.product_id")
# psycopg2 returns numeric as decimal.Decimal, which json.dumps refuses (TypeError, answered with 400: every document
# list of the lab test on the VM, package B5c). extract() is numeric since PostgreSQL 14 (Debian 12 has 15), so it is
# cast to double precision; lab/tests/test_services.py refuses the numeric calls, literals and type it lists if uncast.
SQL_DOC_PAGE = ("SELECT id, name, owner, bytes, extract(epoch FROM created_at)::double precision FROM documents "
                "ORDER BY id DESC LIMIT %s OFFSET %s")
SQL_DOC_COUNT = "SELECT count(*) FROM documents"
SQL_DOC = "SELECT id, name, bytes, sha256 FROM documents WHERE id=%s"
SQL_DOC_ADD = "INSERT INTO documents (name, owner, bytes, sha256) VALUES (%s, %s, %s, %s) RETURNING id"
# Report of the last day of orders (stage 1). Executor's judgment (B5a): the row cap keeps a report under a few
# seconds; the select may wait 10 s for a lock (the services wait 3 s), VACUUM 10 s for a lock and 120 s in all.
REPORT_QUERY =("SELECT o.id, o.username, o.total_cents, o.status, o.created_at, count(i.product_id) FROM orders o "
                "LEFT JOIN order_items i ON i.order_id = o.id WHERE o.created_at >= now() - interval '1 day' "
                "GROUP BY o.id ORDER BY o.id LIMIT 200000")
VACUUM_TABLES = "products, customers, employees, cart_items, orders, order_items, documents, worker_heartbeat"
PSQL = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-d", "hyptcn_lab"]


class Reply(Exception):
    """A client error with its HTTP status, raised by a route and answered by handle_api."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Pool:
    """The database connections of one service process: `connections`, psycopg2's ThreadedConnectionPool of `size`
    connections kept open (main), and the count of the free ones.

    take() lends one for the length of a with block. psycopg2's getconn alone raises PoolError at once when all are
    taken: in the long run dokazy/G2/behy/07-long-a-eshop_high 7 requests got 503 right after the envelope's peak, their
    guest journal "dependency error: connection pool exhausted". The lead's answer to Q74 (2026-11-25T22:15Z, package
    B13): a thread that holds no connection waits for a free one at most DATABASE_TIMEOUT_S, as an application's pool
    waits with a time limit, and holds none while it waits. A thread that holds one already never waits for another: it
    takes a free one at once or fails at once, as before. So no wait is for a connection of its own (on the worker's
    pool of one it would be), and no requests that each hold one wait for each other's. Without a connection in time
    take() raises PoolError "connection pool exhausted", the error and the text of psycopg2, which handle_api answers
    with 503 as before. Every connection taken goes back, also on an error."""

    def __init__(self, connections, size):
        self.connections, self.free, self.held = connections, threading.BoundedSemaphore(size), threading.local()

    @contextmanager
    def take(self):
        held = getattr(self.held, "count", 0)
        if not (self.free.acquire(blocking=False) if held else self.free.acquire(timeout=DATABASE_TIMEOUT_S)):
            raise PoolError("connection pool exhausted")
        try:
            conn = self.connections.getconn()
        except BaseException:
            self.free.release()
            raise
        self.held.count = held + 1
        try:
            yield conn
        finally:
            self.held.count = held
            try:
                self.connections.putconn(conn)
            finally:
                self.free.release()


@contextmanager
def database():
    """A cursor in a transaction on a connection of POOL (Pool.take), each statement limited to DATABASE_TIMEOUT_S."""
    with POOL.take() as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(STATEMENT_TIMEOUT)
                yield cursor


def token_for(user, role="customer"):
    payload = base64.urlsafe_b64encode(json.dumps({"user": user, "role": role,
                                                   "exp": int(time.time()) + 3600}).encode()).decode()
    return payload + "." + hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()


def token_claims(token):
    """(user, role) of a valid token, (None, None) otherwise; tokens without a role are customers'."""
    try:
        payload, signature = token.split(".")
        if not hmac.compare_digest(signature, hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()):
            return None, None
        data = json.loads(base64.urlsafe_b64decode(payload))
        return (data["user"], data.get("role", "customer")) if data["exp"] > time.time() else (None, None)
    except (ValueError, KeyError, TypeError):
        return None, None


def token_user(token):
    return token_claims(token)[0]


def verify_password(password, encoded):
    """PBKDF2-SHA256 in the format of lab/seed.py hash_password: pbkdf2_sha256$<iterations>$<salt>$<hash>."""
    try:
        scheme, iterations, salt, expected = encoded.split("$")
        if scheme != "pbkdf2_sha256" or not 1 <= int(iterations) <= 10_000_000:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, AttributeError):
        return False


def valid_user(user):
    return isinstance(user, str) and user.isalnum() and 1 <= len(user) <= 32


def fetch(service, path, token="", rid=""):
    headers = {"Authorization": f"Bearer {token}"}
    if rid:
        headers["X-Request-ID"] = rid  # Keep one correlation ID across internal calls.
    request = urllib.request.Request(f"http://127.0.0.1:{PORTS[service]}{path}", headers=headers)
    with urllib.request.urlopen(request, timeout=4) as response:
        return json.load(response)


def one(query, name, default=None):
    """The single value of a query parameter, `default` when it is absent."""
    values = query.get(name)
    if values is None:
        return default
    if len(values) != 1:
        raise ValueError(f"at most one {name} parameter")
    return values[0]


def page_args(query):
    page, size = int(one(query, "page", "1")), int(one(query, "size", str(PAGE_SIZE)))
    if not 1 <= page <= MAX_PAGE or not 1 <= size <= MAX_PAGE_SIZE:
        raise ValueError(f"page 1..{MAX_PAGE} and size 1..{MAX_PAGE_SIZE} required")
    return page, size


def like_pattern(text):
    """ILIKE pattern that finds `text` anywhere, its own % _ and \\ taken literally."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def check_item(product_id, quantity):
    if type(product_id) is not int or type(quantity) is not int or not 1 <= quantity <= 20:
        raise ValueError("integer product_id and quantity 1..20 required")


def write_file(path, data):
    temp = path.with_name("." + path.name + ".part")
    temp.write_bytes(data)
    os.replace(temp, path)


def prune(directory, pattern, keep):
    """Delete all but the `keep` newest files (names sort by time)."""
    for path in sorted(directory.glob(pattern))[:-keep]:
        path.unlink(missing_ok=True)


def log_document(user, action, doc_id, size, status):
    """One line of the document access log; hyptcn-lab-udrzba compresses it."""
    with DOCS_LOG.open("a") as stream:
        stream.write(json.dumps({"ts": time.time(), "user": user, "action": action, "document": doc_id,
                                 "bytes": size, "status": status}) + "\n")


def enqueue_report(user):
    """Queue one report for the worker: a spool file that appears in queued/ only when complete. The name starts
    with the UTC time to the microsecond, so the worker takes reports in the order they were requested."""
    now = time.time()
    report = (time.strftime("%Y%m%dT%H%M%S", time.gmtime(now)) + f"{int(now * 1e6) % 1_000_000:06d}Z-"
              + uuid.uuid4().hex[:8])
    temp = SPOOL / f".{report}.json"
    temp.write_text(json.dumps({"report": report, "user": user, "requested_unix": time.time()}))
    os.rename(temp, SPOOL / "queued" / f"{report}.json")
    return report


def report_status(report):
    if REPORT_ID.fullmatch(report):
        for status in ("queued", "running", "failed"):
            if (SPOOL / status / f"{report}.json").exists():
                return {"report": report, "status": status}
        done = REPORTS / f"{report}.csv.gz"
        if done.exists():
            return {"report": report, "status": "done", "bytes": done.stat().st_size}
    raise Reply(404, "unknown report")


def report_stages(raw, packed, target):
    """One report = three stages, each one subprocess (KOSTRA B5 section 1): select from the database,
    sort and compress, write."""
    return [("select", [*PSQL, "-c", "SET statement_timeout = '10s'",
                        "-c", f"\\copy ({REPORT_QUERY}) TO '{raw}' WITH (FORMAT csv)"]),
            ("sort", ["bash", "-c", 'set -euo pipefail; LC_ALL=C sort -t, -k3,3nr -k1,1n -- "$1" | gzip -6 > "$2"',
                      "report-sort", str(raw), str(packed)]),
            ("write", ["install", "-m", "0640", "-T", str(packed), str(target)])]


def report_round(run=subprocess.run):
    """Run the oldest queued report, if there is one. One worker claims a job by renaming it, so at most one
    report runs at a time."""
    queued = sorted((SPOOL / "queued").glob("*.json"))
    if not queued:
        return None
    job, started = queued[0], time.monotonic()
    running = SPOOL / "running" / job.name
    try:
        os.rename(job, running)
    except FileNotFoundError:
        return None
    report = job.stem
    target = REPORTS / f"{report}.csv.gz"
    with tempfile.TemporaryDirectory(prefix="hyptcn-report-") as work:
        raw, packed = Path(work) / "raw.csv", Path(work) / "sorted.csv.gz"
        for stage, argv in report_stages(raw, packed, target):
            try:
                result = run(argv, capture_output=True, text=True, timeout=STAGE_TIMEOUT_S)
                failed = result.returncode and f"exit {result.returncode}: {result.stderr.strip()[:200]}"
            except (OSError, subprocess.SubprocessError) as error:
                failed = f"{type(error).__name__}: {error}"[:200]
            if failed:
                os.rename(running, SPOOL / "failed" / job.name)
                print(WORKER_ERROR + f"report {report} stage {stage}: {failed}", flush=True)
                return {"report": report, "failed": stage}
        rows = raw.read_bytes().count(b"\n")
    running.unlink()
    prune(REPORTS, "*.csv.gz", REPORTS_KEPT)
    done = {"service": "worker", "report": report, "rows": rows, "bytes": target.stat().st_size,
            "seconds": round(time.monotonic() - started, 3)}
    print(json.dumps(done), flush=True)
    return done


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def rid(self):
        value = self.headers.get("X-Request-ID", "") if getattr(self, "headers", None) else ""
        return value if value.replace("-", "").isalnum() and len(value) <= 64 else ""

    def log_request(self, code="-", size="-"):
        # One journald line per handled request; no headers, tokens or bodies.
        self.log_message("request rid=%s method=%s path=%s status=%s", self.rid() or "-",
                         getattr(self, "command", None), urlsplit(getattr(self, "path", "")).path,
                         getattr(code, "value", code))

    def reply(self, status, body):
        self.reply_bytes(status, json.dumps(body).encode(), "application/json")

    def reply_bytes(self, status, data, content_type, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def length(self):
        return int(self.headers.get("Content-Length", 0))

    def body(self):
        length = self.length()
        if not 0 < length <= 8192:
            raise ValueError("JSON body must be between 1 and 8192 bytes")
        doc = json.loads(self.rfile.read(length))
        if not isinstance(doc, dict):
            raise ValueError("JSON object required")
        return doc

    def query(self):
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True)

    def token(self):
        return self.headers.get("Authorization", "").removeprefix("Bearer ")

    def do_GET(self):
        self.handle_api("GET")

    def do_POST(self):
        self.handle_api("POST")

    def handle_api(self, method):
        try:
            self.route(method)
        except Reply as error:
            self.close_connection = True  # A refused request body may be unread.
            self.reply(error.status, {"error": str(error)})
        except (ValueError, TypeError, KeyError) as error:
            self.close_connection = True
            self.reply(400, {"error": str(error)})
        except urllib.error.HTTPError as error:
            self.close_connection = True
            code = error.code if error.code in (401, 404) else 503
            self.reply(code, {"error": "upstream rejected request"})
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
                fetch("catalog", "/healthz", rid=self.rid())
                fetch("auth", "/healthz", rid=self.rid())
                with database() as cursor:
                    cursor.execute("SELECT EXTRACT(EPOCH FROM now() - updated_at)::double precision "
                                   "FROM worker_heartbeat WHERE id=1")
                    row = cursor.fetchone()
                if not row or row[0] > 15:
                    self.reply(503, {"status": "degraded", "worker": "stale"})
                    return
            self.reply(200, {"status": "ok", "service": service, "database": service != "auth"})
            return
        done = {"auth": self.auth, "catalog": self.catalog, "orders": self.orders, "docs": self.docs}[service](
            method, path)
        if done is not True:
            self.reply(404, {"error": "unknown route"})

    def auth(self, method, path):
        if path == "/api/auth/token" and method == "POST":
            user = self.body().get("user", "demo")
            if not valid_user(user):
                raise ValueError("user must be 1..32 alphanumeric characters")
            # Deliberately passwordless demo identities (customers of profile eshop) for this lab only.
            self.reply(200, {"token": token_for(user), "user": user, "expires_in": 3600, "demo": True})
            return True
        if path == "/api/auth/login" and method == "POST":
            body = self.body()
            user, password = body.get("user"), body.get("password")
            if not valid_user(user) or type(password) is not str or not 1 <= len(password) <= 128:
                raise ValueError("user (1..32 alphanumeric) and password (1..128 characters) required")
            with database() as cursor:
                cursor.execute(SQL_EMPLOYEE, (user,))
                row = cursor.fetchone()
            if not verify_password(password, row[0] if row else UNKNOWN_EMPLOYEE) or not row:
                raise Reply(401, "wrong user or password")
            self.reply(200, {"token": token_for(user, "employee"), "user": user, "role": "employee",
                             "expires_in": 3600})
            return True
        if path == "/api/auth/check" and method == "GET":
            user, role = token_claims(self.token())
            self.reply(200 if user else 401, {"user": user, "role": role})
            return True
        return False

    def catalog(self, method, path):
        if method != "GET":
            return False
        if path == "/api/catalog":
            query = self.query()
            page, size = page_args(query)
            text = one(query, "q")
            if text is not None and (not 1 <= len(text) <= MAX_QUERY or not text.isprintable()):
                raise ValueError(f"q must be 1..{MAX_QUERY} printable characters")
            with database() as cursor:
                if text is None:
                    cursor.execute(SQL_PRODUCT_PAGE, (size, (page - 1) * size))
                    rows = cursor.fetchall()
                    cursor.execute(SQL_PRODUCT_COUNT)
                else:
                    cursor.execute(SQL_PRODUCT_SEARCH, (like_pattern(text), size, (page - 1) * size))
                    rows = cursor.fetchall()
                    cursor.execute(SQL_PRODUCT_SEARCH_COUNT, (like_pattern(text),))
                total = cursor.fetchone()[0]
            self.reply(200, {"products": [dict(zip(("id", "name", "price_cents"), row)) for row in rows],
                             "page": page, "size": size, "total": total, **({} if text is None else {"q": text})})
            return True
        if path == "/api/catalog/prices":
            # Internal: current prices of the products of a cart, one call per order (lab/services.py orders).
            ids = [int(value) for value in one(self.query(), "ids", "").split(",")]
            if not 1 <= len(ids) <= MAX_IDS or len(set(ids)) != len(ids) or min(ids) < 1:
                raise ValueError(f"ids: 1..{MAX_IDS} distinct positive product ids")
            with database() as cursor:
                cursor.execute(SQL_PRICES, (ids,))
                rows = cursor.fetchall()
            self.reply(200, {"products": [{"id": pid, "price_cents": price} for pid, price in rows]})
            return True
        if path.startswith("/api/catalog/"):
            product_id = int(path.rsplit("/", 1)[1])
            with database() as cursor:
                cursor.execute(SQL_PRODUCT, (product_id,))
                row = cursor.fetchone()
            if not row:
                raise Reply(404, "unknown product")
            self.reply(200, dict(zip(("id", "name", "price_cents", "category", "description"), row)))
            return True
        return False

    def orders(self, method, path):
        if path not in ("/api/orders", "/api/cart") or method not in ("GET", "POST"):
            return False
        user = fetch("auth", "/api/auth/check", self.token(), self.rid())["user"]
        if path == "/api/cart" and method == "POST":
            body = self.body()
            product_id, quantity = body.get("product_id"), body.get("quantity", 1)
            check_item(product_id, quantity)
            with database() as cursor:
                cursor.execute(SQL_PRODUCT_EXISTS, (product_id,))
                if not cursor.fetchone():
                    raise Reply(404, "unknown product")
                cursor.execute(SQL_CART_ADD, (user, product_id, quantity))
                if not cursor.fetchone():
                    raise ValueError("at most 20 pieces of one product in the cart")
        if path == "/api/cart":
            with database() as cursor:
                cursor.execute(SQL_CART, (user,))
                rows = cursor.fetchall()
            items = [{"product_id": pid, "quantity": quantity, "price_cents": price} for pid, quantity, price in rows]
            self.reply(200, {"items": items, "total_cents": sum(i["quantity"] * i["price_cents"] for i in items)})
            return True
        if method == "GET":
            with database() as cursor:
                cursor.execute(SQL_ORDER_LIST, (user,))
                rows = cursor.fetchall()
            orders = {}
            for order_id, total, status, product_id, quantity, price in rows:
                order = orders.setdefault(order_id, {"id": order_id, "total_cents": total, "status": status,
                                                     "items": []})
                if product_id is not None:
                    order["items"].append({"product_id": product_id, "quantity": quantity, "price_cents": price})
            self.reply(200, {"orders": list(orders.values())})
            return True
        body = self.body()
        from_cart = set(body) == {"cart"} and body["cart"] is True
        if from_cart:
            with database() as cursor:
                cursor.execute(SQL_CART_ITEMS, (user,))
                wanted = cursor.fetchall()
            if not wanted:
                raise ValueError("the cart is empty")
            if len(wanted) > MAX_IDS:
                raise ValueError(f"at most {MAX_IDS} products in one order")
            # One catalog call per order, as for a single product: the current prices of the cart.
            prices = {p["id"]: p["price_cents"] for p in fetch(
                "catalog", "/api/catalog/prices?ids=" + ",".join(str(pid) for pid, _ in wanted), rid=self.rid())["products"]}
            if set(prices) != {pid for pid, _ in wanted}:
                raise Reply(404, "unknown product in the cart")
            items = [(pid, quantity, prices[pid]) for pid, quantity in wanted]
        else:
            product_id, quantity = body.get("product_id"), body.get("quantity", 1)
            check_item(product_id, quantity)
            product = fetch("catalog", f"/api/catalog/{product_id}", rid=self.rid())
            items = [(product_id, quantity, product["price_cents"])]
        total = sum(quantity * price for _, quantity, price in items)
        with database() as cursor:
            cursor.execute(SQL_ORDER, (user, total))
            order_id = cursor.fetchone()[0]
            for product_id, quantity, price in items:
                cursor.execute(SQL_ORDER_ITEM, (order_id, product_id, quantity, price))
            if from_cart:
                cursor.execute(SQL_CART_CLEAR, (user,))
        self.reply(201, {"id": order_id, "status": "pending", "items": len(items), "total_cents": total})
        return True

    def employee(self):
        """The user of an employee token; 401 without a valid token, 403 for a customer."""
        claims = fetch("auth", "/api/auth/check", self.token(), self.rid())
        if claims.get("role") != "employee":
            raise Reply(403, "documents and reports are for employees")
        return claims["user"]

    def docs(self, method, path):
        if path == "/api/docs" and method == "GET":
            user = self.employee()
            page, size = page_args(self.query())
            with database() as cursor:
                cursor.execute(SQL_DOC_PAGE, (size, (page - 1) * size))
                rows = cursor.fetchall()
                cursor.execute(SQL_DOC_COUNT)
                total = cursor.fetchone()[0]
            log_document(user, "list", None, None, 200)
            self.reply(200, {"documents": [dict(zip(("id", "name", "owner", "bytes", "created_unix"), row))
                                           for row in rows], "page": page, "size": size, "total": total})
            return True
        if path == "/api/docs" and method == "POST":
            user = self.employee()
            length = self.length()
            if length > MAX_DOCUMENT:
                raise Reply(413, "a document has at most 8 MiB")
            name = one(self.query(), "name")
            if length < 1 or name is None or not NAME.fullmatch(name):
                raise ValueError("a non-empty body and name=[A-Za-z0-9._-] (at most 120) required")
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError("incomplete document")
            digest = hashlib.sha256(data).hexdigest()
            with database() as cursor:
                cursor.execute(SQL_DOC_ADD, (name, user, length, digest))
                doc_id = cursor.fetchone()[0]
                write_file(DOCS / f"{doc_id}.bin", data)  # A failed write rolls the row back.
            log_document(user, "upload", doc_id, length, 201)
            self.reply(201, {"id": doc_id, "name": name, "bytes": length, "sha256": digest})
            return True
        if path.startswith("/api/docs/") and method == "GET":
            user = self.employee()
            doc_id = int(path.rsplit("/", 1)[1])
            with database() as cursor:
                cursor.execute(SQL_DOC, (doc_id,))
                row = cursor.fetchone()
            if not row:
                raise Reply(404, "unknown document")
            data = (DOCS / f"{doc_id}.bin").read_bytes()
            log_document(user, "download", doc_id, len(data), 200)
            self.reply_bytes(200, data, "application/octet-stream",
                             [("Content-Disposition", f'attachment; filename="{row[1]}"'), ("X-Document-SHA256", row[3])])
            return True
        if path == "/api/reports" and method == "POST":
            user = self.employee()
            if self.length():
                raise ValueError("a report request has no body")
            self.reply(202, {"report": enqueue_report(user), "status": "queued"})
            return True
        if path.startswith("/api/reports/") and method == "GET":
            self.employee()
            self.reply(200, report_status(path.rsplit("/", 1)[1]))
            return True
        return False


def worker():
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        completed = 0
        try:
            with database() as cursor:
                cursor.execute("UPDATE orders SET status='completed' WHERE id IN (SELECT id FROM orders WHERE status='pending' ORDER BY id LIMIT 50 FOR UPDATE SKIP LOCKED)")
                completed = cursor.rowcount
                cursor.execute("INSERT INTO worker_heartbeat(id,updated_at) VALUES (1,now()) ON CONFLICT (id) DO UPDATE SET updated_at=now()")
                # Keep persistent demonstration traffic bounded on disk.
                cursor.execute("DELETE FROM orders WHERE created_at < now() - interval '1 day' AND status='completed'")
        except psycopg2.errors.QueryCanceled as error:
            # A statement that waits on a held lock runs into the 3 s timeout. The round is rolled
            # back and tried again after the usual pause. Exiting here made systemd restart the
            # worker every 6.25 s for as long as the lock was held: four restarts per five 5 s
            # snapshots, so a restart that met one capture met every fifth one (docs/LIMITACIE.md L1).
            # Any other database error still ends the process and systemd restarts it.
            print(WORKER_ERROR + str(error).strip(), flush=True)
        if completed:
            print(json.dumps({"service": "worker", "completed": completed}), flush=True)
        report_round()
        stop.wait(random.uniform(*PAUSE_S))


def rotate_log(run):
    """Rename the document access log and compress it; keep the newest DOCS_LOGS_KEPT."""
    if not DOCS_LOG.exists() or not DOCS_LOG.stat().st_size:
        return None
    rotated = LOGS / ("docs-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + ".log")
    os.rename(DOCS_LOG, rotated)
    result = run(["gzip", "-6", str(rotated)], capture_output=True, text=True, timeout=STAGE_TIMEOUT_S)
    if result.returncode:
        raise RuntimeError(f"gzip of {rotated} failed: {result.stderr.strip()[:200]}")
    prune(LOGS, "docs-*.log.gz", DOCS_LOGS_KEPT)
    return rotated.name + ".gz"


def udrzba(run=subprocess.run):
    """One run of the administrator's maintenance (hyptcn-lab-udrzba.timer): VACUUM ANALYZE of the lab tables,
    then compression of the document access log. PostgreSQL keeps its default autovacuum (lead's answer to Q3,
    2026-11-22T20:55Z); this script comes on top of it. Returns the exit code: TEMPFAIL when the
    database was unreachable or a table stayed locked (the run is skipped and recorded)."""
    started = time.monotonic()
    vacuum = run([*PSQL, "-c", "SET lock_timeout = '10s'", "-c", "SET statement_timeout = '120s'",
                  "-c", f"VACUUM (ANALYZE) {VACUUM_TABLES}"], capture_output=True, text=True, timeout=240)
    error = vacuum.stderr.strip()[:300] if vacuum.returncode else None
    transient = vacuum.returncode == 2 or bool(error and re.search(
        r"lock timeout|could not connect|connection to server|the database system is (starting|shutting) up", error))
    rotated = rotate_log(run)
    print(json.dumps({"service": "udrzba", "vacuum_rc": vacuum.returncode, "vacuum_error": error,
                      "log_compressed": rotated, "seconds": round(time.monotonic() - started, 3)}), flush=True)
    return 0 if not vacuum.returncode else TEMPFAIL if transient else 1


def main():
    global POOL
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=[*PORTS, "worker", "udrzba"])
    service = parser.parse_args().service
    if service == "udrzba":
        raise SystemExit(udrzba())
    if not SECRET:
        raise SystemExit("LAB_SECRET is required")
    # psycopg2 retains only minconn idle connections; minconn=1 closed
    # concurrent connections on return and repeatedly created PostgreSQL
    # backend processes. Keep the bounded pool alive across requests.
    # auth reads the employees' password hashes since protocol v5.
    pool_size = WORKER_POOL_SIZE if service == "worker" else POOL_SIZE
    POOL = Pool(ThreadedConnectionPool(pool_size, pool_size, dbname="hyptcn_lab", user="hyptcnlab",
                                       host="/var/run/postgresql", connect_timeout=5), pool_size)
    try:
        if service == "worker":
            worker()
        else:
            # The constructor listens, so the backlog is the class's (socketserver.TCPServer.request_queue_size).
            server_class = type("Server", (ThreadingHTTPServer,), {"request_queue_size": LISTEN_BACKLOG})
            server = server_class(("127.0.0.1", PORTS[service]), Handler)
            server.service = service
            server.serve_forever()
    finally:
        if POOL:
            POOL.connections.closeall()


if __name__ == "__main__":
    main()
