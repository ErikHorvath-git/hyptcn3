"""Services of the lab on a fake database (KOSTRA B5 section 5 item 3): the new routes, the codes 400, 401, 403, 404
and 413, the upload cap and the report that runs three subprocesses, one report at a time.

The handlers run in process (no sockets); internal calls between services go to the same in-process handlers.
The fake database holds a small seeded level of lab/seed.py and runs the named statements of lab/services.py; it
returns the Python types psycopg2 returns for the real column types (package B5c: extract() is numeric, a Decimal).
"""
import ast
from contextlib import contextmanager
import copy
from decimal import Decimal
import gzip
import http.client
import importlib.util
import io
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import types
from types import SimpleNamespace
import urllib.error

import pytest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

SMALL = {"products": 30, "customers": 5, "employees": 3, "documents": 4, "orders": 6, "carts": 2}
CREATED_UNIX = 1795397963.65049  # The creation time of the fake's first document (any time does).
EPOCH = re.compile(r"(?i)extract\(epoch from (?:now\(\) - )?\w+\)(::double precision)?")
# The worker's heartbeat age that the health check of orders reads (a statement inline in lab/services.py).
HEARTBEAT_AGE = "SELECT EXTRACT(EPOCH FROM now() - updated_at)::double precision FROM worker_heartbeat WHERE id=1"


def psycopg2_epoch(sql, seconds):
    """What psycopg2 returns for the item extract(epoch FROM ...) of `sql`: PostgreSQL 14 and later (Debian 12 has 15)
    type extract() numeric, which psycopg2 returns as decimal.Decimal with six decimals; cast to double precision it
    is a float."""
    item = EPOCH.search(sql)
    assert item, sql  # A statement of another form needs its own type here.
    return float(seconds) if item[1] else Decimal(f"{seconds:.6f}")


def load_services(monkeypatch):
    try:
        import psycopg2  # noqa: F401  The guest has it; the collection host does not.
    except ImportError:
        stub, errors, pool = (types.ModuleType(n) for n in ("psycopg2", "psycopg2.errors", "psycopg2.pool"))
        stub.Error = type("Error", (Exception,), {})
        stub.OperationalError = type("OperationalError", (stub.Error,), {})
        errors.QueryCanceled = type("QueryCanceled", (stub.OperationalError,), {})
        pool.ThreadedConnectionPool = object
        stub.errors, stub.pool = errors, pool
        for module in (stub, errors, pool):
            monkeypatch.setitem(sys.modules, module.__name__, module)
    spec = importlib.util.spec_from_file_location("lab_services_v5_under_test", LAB / "services.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeDatabase:
    """The lab tables as Python data; each named statement of lab/services.py has a handler. A statement without
    one fails the test. A transaction that raises is rolled back."""

    def __init__(self, s, data):
        self.tables = {"products": {r[0]: r for r in data["products"]},
                       "employees": {r[0]: r[3] for r in data["employees"]},
                       "cart": {}, "orders": {}, "items": {}, "documents": {}}
        t = self.tables
        self.statements = []
        self.handlers = {
            "SELECT 1": lambda: [(1,)],
            HEARTBEAT_AGE: lambda: [(psycopg2_epoch(HEARTBEAT_AGE, 1.0),)],
            s.SQL_PRODUCT_PAGE: lambda limit, offset: self.products()[offset:offset + limit],
            s.SQL_PRODUCT_COUNT: lambda: [(len(t["products"]),)],
            s.SQL_PRODUCT_SEARCH: lambda pattern, limit, offset: self.products(pattern)[offset:offset + limit],
            s.SQL_PRODUCT_SEARCH_COUNT: lambda pattern: [(len(self.products(pattern)),)],
            s.SQL_PRODUCT: lambda pid: [tuple(t["products"][pid][i] for i in (0, 1, 4, 2, 3))]
            if pid in t["products"] else [],
            s.SQL_PRICES: lambda ids: [(i, t["products"][i][4]) for i in sorted(ids) if i in t["products"]],
            s.SQL_PRODUCT_EXISTS: lambda pid: [(1,)] if pid in t["products"] else [],
            s.SQL_EMPLOYEE: lambda user: [(t["employees"][user],)] if user in t["employees"] else [],
            s.SQL_CART: lambda user: [(pid, q, t["products"][pid][4]) for (u, pid), q in sorted(t["cart"].items())
                                      if u == user],
            s.SQL_CART_ADD: self.cart_add,
            s.SQL_CART_ITEMS: lambda user: [(pid, q) for (u, pid), q in sorted(t["cart"].items()) if u == user],
            s.SQL_CART_CLEAR: lambda user: [t["cart"].pop(k) for k in [k for k in t["cart"] if k[0] == user]] and [],
            s.SQL_ORDER: self.order_add,
            s.SQL_ORDER_ITEM: lambda oid, pid, q, price: t["items"].update({(oid, pid): (q, price)}),
            s.SQL_ORDER_LIST: self.order_list,
            s.SQL_DOC_PAGE: lambda limit, offset: [(i, *t["documents"][i][:3],
                                                    psycopg2_epoch(s.SQL_DOC_PAGE, t["documents"][i][4]))
                                                   for i in sorted(t["documents"], reverse=True)][offset:offset + limit],
            s.SQL_DOC_COUNT: lambda: [(len(t["documents"]),)],
            s.SQL_DOC: lambda did: [(did, t["documents"][did][0], t["documents"][did][2], t["documents"][did][3])]
            if did in t["documents"] else [],
            s.SQL_DOC_ADD: self.document_add,
        }

    def products(self, pattern=None):
        text = None if pattern is None else re.sub(r"\\(.)", r"\1", pattern[1:-1]).lower()
        return [(r[0], r[1], r[4]) for _, r in sorted(self.tables["products"].items())
                if text is None or text in r[1].lower()]

    def cart_add(self, user, pid, quantity):
        cart = self.tables["cart"]
        total = cart.get((user, pid), 0) + quantity
        if total > 20:
            return []
        cart[(user, pid)] = total
        return [(total,)]

    def order_add(self, user, total):
        oid = max(self.tables["orders"], default=0) + 1
        self.tables["orders"][oid] = [user, total, "pending"]
        return [(oid,)]

    def order_list(self, user):
        rows = []
        for oid in sorted((o for o, row in self.tables["orders"].items() if row[0] == user), reverse=True)[:50]:
            _, total, status = self.tables["orders"][oid]
            lines = sorted((pid, q, p) for (o, pid), (q, p) in self.tables["items"].items() if o == oid)
            rows += [(oid, total, status, *line) for line in lines] or [(oid, total, status, None, None, None)]
        return rows

    def document_add(self, name, owner, size, digest):
        did = max(self.tables["documents"], default=0) + 1
        self.tables["documents"][did] = (name, owner, size, digest, CREATED_UNIX + did - 1)  # created_at as unix time
        return [(did,)]

    @contextmanager
    def transaction(self):
        saved = copy.deepcopy(self.tables)
        cursor = SimpleNamespace(rows=[], rowcount=0)

        def execute(sql, params=()):
            self.statements.append(sql)
            cursor.rows = list(self.handlers[sql](*params) or [])
            cursor.rowcount = len(cursor.rows)
        cursor.execute = execute
        cursor.fetchone = lambda: cursor.rows.pop(0) if cursor.rows else None
        cursor.fetchall = lambda: [cursor.rows.pop(0) for _ in list(cursor.rows)]
        try:
            yield cursor
        except BaseException:
            self.tables.clear()
            self.tables.update(saved)
            raise


@pytest.fixture
def lab(monkeypatch, tmp_path):
    import seed  # lab/seed.py is new in B5: imported here, so that this file collects on older code.
    s = load_services(monkeypatch)
    monkeypatch.setattr(s, "SECRET", b"lab-test-secret")
    for name, path in (("DATA", tmp_path), ("DOCS", tmp_path / "docs"), ("REPORTS", tmp_path / "reports"),
                       ("SPOOL", tmp_path / "spool"), ("LOGS", tmp_path / "logs"),
                       ("DOCS_LOG", tmp_path / "logs/docs.log")):
        monkeypatch.setattr(s, name, path)
    for directory in ("docs", "reports", "logs", "spool/queued", "spool/running", "spool/failed"):
        (tmp_path / directory).mkdir(parents=True)
    monkeypatch.setattr(seed, "SIZES", SMALL)
    data = seed.generate(7, iterations=1000)
    db = FakeDatabase(s, data)
    monkeypatch.setattr(s, "database", db.transaction)
    internal = []

    def fetch(service, path, token="", rid=""):
        internal.append((service, path.split("?")[0]))
        status, body, _ = call(s, service, "GET", path, token=token)
        if status >= 400:
            raise urllib.error.HTTPError(f"http://127.0.0.1:{s.PORTS[service]}{path}", status, "fake", {}, None)
        return body
    monkeypatch.setattr(s, "fetch", fetch)
    lab = SimpleNamespace(s=s, db=db, data=data, internal=internal, tmp=tmp_path)
    lab.call = lambda *a, **k: call(s, *a, **k)
    lab.customer = lab.call("auth", "POST", "/api/auth/token", body={"user": "zakaznik0001"})[1]["token"]
    employee = data["employees"][0][0]
    lab.employee = lab.call("auth", "POST", "/api/auth/login",
                            body={"user": employee, "password": seed.employee_password(employee)})[1]["token"]
    internal.clear()
    return lab


def call(s, service, method, path, token=None, body=None, raw=None, length=None):
    """(status, body, headers) of one request to the handler of `service`, without a socket."""
    handler = s.Handler.__new__(s.Handler)
    data = raw if raw is not None else b"" if body is None else json.dumps(body).encode()
    headers = http.client.HTTPMessage()
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if data or length is not None:
        headers["Content-Length"] = str(len(data) if length is None else length)
    handler.headers, handler.rfile, handler.wfile = headers, io.BytesIO(data), io.BytesIO()
    handler.server = SimpleNamespace(service=service)
    handler.command, handler.path, handler.request_version = method, path, "HTTP/1.1"
    handler.requestline, handler.client_address, handler.close_connection = f"{method} {path} HTTP/1.1", ("127.0.0.1", 0), False
    handler.handle_api(method)
    head, _, payload = handler.wfile.getvalue().partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    reply = dict(line.split(": ", 1) for line in lines[1:])
    return int(lines[0].split()[1]), json.loads(payload) if reply["Content-Type"] == "application/json" else payload, reply


TOKENS = {"none": None, "customer": "customer", "employee": "employee", "bad": "bad"}


@pytest.mark.parametrize("service,method,path,who,body,status", [
    ("catalog", "GET", "/api/catalog?size=0", "none", None, 400),
    ("catalog", "GET", "/api/catalog?size=101", "none", None, 400),
    ("catalog", "GET", "/api/catalog?page=x", "none", None, 400),
    ("catalog", "GET", "/api/catalog?q=", "none", None, 400),
    ("catalog", "GET", "/api/catalog?page=1&page=2", "none", None, 400),
    ("catalog", "GET", "/api/catalog/999999", "none", None, 404),
    ("catalog", "GET", "/api/catalog/abc", "none", None, 400),
    ("catalog", "GET", "/api/catalog/prices?ids=1,1", "none", None, 400),
    ("auth", "POST", "/api/auth/login", "none", {"user": "zamestnanec001", "password": "wrong"}, 401),
    ("auth", "POST", "/api/auth/login", "none", {"user": "nobody", "password": "wrong"}, 401),
    ("auth", "POST", "/api/auth/login", "none", {"user": "zamestnanec001"}, 400),
    ("orders", "GET", "/api/cart", "none", None, 401),
    ("orders", "GET", "/api/cart", "bad", None, 401),
    ("orders", "POST", "/api/cart", "customer", {"product_id": 999999, "quantity": 1}, 404),
    ("orders", "POST", "/api/cart", "customer", {"product_id": 1, "quantity": 0}, 400),
    ("orders", "POST", "/api/cart", "customer", {"product_id": 1, "quantity": 21}, 400),
    ("orders", "POST", "/api/orders", "customer", {"cart": True}, 400),
    ("orders", "POST", "/api/orders", "customer", {"product_id": 999999, "quantity": 1}, 404),
    ("orders", "POST", "/api/orders", "customer", {"product_id": 1, "quantity": True}, 400),
    ("docs", "GET", "/api/docs", "none", None, 401),
    ("docs", "GET", "/api/docs", "customer", None, 403),
    ("docs", "GET", "/api/docs?size=500", "employee", None, 400),
    ("docs", "GET", "/api/docs/999999", "employee", None, 404),
    ("docs", "GET", "/api/reports/20260101T000000000000Z-00000000", "employee", None, 404),
    ("docs", "POST", "/api/reports", "employee", {}, 400),
    ("docs", "GET", "/api/unknown", "employee", None, 404),
])
def test_bad_requests_get_their_status(lab, service, method, path, who, body, status):
    token = {"customer": lab.customer, "employee": lab.employee, "bad": lab.customer + "x"}.get(who)
    assert lab.call(service, method, path, token=token, body=body)[0] == status


def test_catalog_pages_searches_and_details(lab):
    status, page, _ = lab.call("catalog", "GET", "/api/catalog?page=2&size=3")
    assert status == 200 and [p["id"] for p in page["products"]] == [4, 5, 6] and page["total"] == SMALL["products"]
    assert lab.call("catalog", "GET", "/api/catalog")[1]["size"] == lab.s.PAGE_SIZE
    word = lab.data["products"][0][1].split()[1]  # A noun of the first product's name.
    status, found, _ = lab.call("catalog", "GET", f"/api/catalog?q={word.lower()}&size=100")
    expected = [r[0] for r in lab.data["products"] if word.lower() in r[1].lower()]
    assert status == 200 and [p["id"] for p in found["products"]] == expected and found["total"] == len(expected)
    status, product, _ = lab.call("catalog", "GET", "/api/catalog/1")
    assert status == 200 and product == dict(zip(("id", "name", "category", "description", "price_cents"),
                                                  [lab.data["products"][0][i] for i in (0, 1, 2, 3, 4)]))
    assert lab.s.like_pattern("50%_a\\") == "%50\\%\\_a\\\\%"


def test_employee_logs_in_with_the_seeded_password_and_customer_tokens_stay_passwordless(lab):
    status, reply, _ = lab.call("auth", "GET", "/api/auth/check", token=lab.employee)
    assert status == 200 and reply == {"user": "zamestnanec001", "role": "employee"}
    assert lab.call("auth", "GET", "/api/auth/check", token=lab.customer)[1] == {"user": "zakaznik0001",
                                                                                  "role": "customer"}


def test_cart_is_ordered_with_its_items_in_one_catalog_call(lab):
    for product_id, quantity in ((3, 2), (1, 1), (3, 1)):
        status, cart, _ = lab.call("orders", "POST", "/api/cart", token=lab.customer,
                                   body={"product_id": product_id, "quantity": quantity})
        assert status == 200
    price = {r[0]: r[4] for r in lab.data["products"]}
    assert cart["items"] == [{"product_id": 1, "quantity": 1, "price_cents": price[1]},
                             {"product_id": 3, "quantity": 3, "price_cents": price[3]}]
    lab.internal.clear()
    status, order, _ = lab.call("orders", "POST", "/api/orders", token=lab.customer, body={"cart": True})
    assert status == 201 and order["items"] == 2 and order["total_cents"] == price[1] + 3 * price[3]
    assert lab.internal == [("auth", "/api/auth/check"), ("catalog", "/api/catalog/prices")]
    assert lab.call("orders", "GET", "/api/cart", token=lab.customer)[1] == {"items": [], "total_cents": 0}
    status, orders, _ = lab.call("orders", "GET", "/api/orders", token=lab.customer)
    assert orders["orders"][0] == {"id": order["id"], "total_cents": order["total_cents"], "status": "pending",
                                   "items": [{"product_id": 1, "quantity": 1, "price_cents": price[1]},
                                             {"product_id": 3, "quantity": 3, "price_cents": price[3]}]}


def test_single_product_order_keeps_its_old_form(lab):
    lab.call("orders", "POST", "/api/cart", token=lab.customer, body={"product_id": 2, "quantity": 1})
    lab.internal.clear()
    status, order, _ = lab.call("orders", "POST", "/api/orders", token=lab.customer,
                                body={"product_id": 1, "quantity": 2, "cart": False})
    assert status == 201 and order["status"] == "pending" and order["items"] == 1
    assert order["total_cents"] == 2 * lab.data["products"][0][4]
    assert lab.internal == [("auth", "/api/auth/check"), ("catalog", "/api/catalog/1")]
    assert lab.call("orders", "GET", "/api/cart", token=lab.customer)[1]["items"] != []  # The cart stays.


def test_documents_upload_list_download_and_log(lab):
    content = b"%PDF-1.7 lab document\n" * 10
    status, doc, _ = lab.call("docs", "POST", "/api/docs?name=zmluva-9999.pdf", token=lab.employee, raw=content)
    assert status == 201 and doc["bytes"] == len(content)
    assert (lab.tmp / "docs" / f"{doc['id']}.bin").read_bytes() == content
    status, listing, _ = lab.call("docs", "GET", "/api/docs?size=2", token=lab.employee)
    assert status == 200 and listing["documents"][0]["id"] == doc["id"] and listing["total"] == 1
    status, data, headers = lab.call("docs", "GET", f"/api/docs/{doc['id']}", token=lab.employee)
    assert status == 200 and data == content and headers["X-Document-SHA256"] == doc["sha256"]
    log = [json.loads(line) for line in (lab.tmp / "logs/docs.log").read_text().splitlines()]
    assert [(e["action"], e["status"]) for e in log] == [("upload", 201), ("list", 200), ("download", 200)]


def test_document_list_replies_200_with_the_creation_time_as_a_json_number(lab):
    """The lab test on the VM got 400 for every document list of profile corp (package B5c): PostgreSQL 15 returned
    extract(epoch ...) as numeric, psycopg2 as a Decimal, json.dumps refused it and handle_api answered 400."""
    status, doc, _ = lab.call("docs", "POST", "/api/docs?name=smernica-0001.pdf", token=lab.employee, raw=b"x" * 64)
    assert status == 201
    status, listing, headers = lab.call("docs", "GET", "/api/docs?page=1&size=20", token=lab.employee)  # As corp asks.
    assert status == 200 and headers["Content-Type"] == "application/json"
    created = listing["documents"][0]["created_unix"]
    assert type(created) is float and created == CREATED_UNIX


# The guard (package B5c): no SQL value of the lab that psycopg2 reads may be numeric, which psycopg2 returns as
# decimal.Decimal and json.dumps refuses. Numeric are: extract() since PostgreSQL 14, avg() of integers, sum() of
# bigint, round(), trunc(), div(), ceil() and floor() of numeric, to_number(), the statistical aggregates, a decimal
# literal or one with an exponent (1e3 is numeric too), and the type numeric (decimal) itself. The guard does not know
# the types of the columns or the arguments, so every such call, literal or type name must be cast to a float or an
# integer type, itself or an expression around it, by :: or by CAST(... AS type) (also sum() of integer, which is
# bigint: the cast costs nothing and keeps the rule simple). Statements are read in any case of their keywords
# (finding F3 of the B5c verification, package B10).
NUMERIC_CALL = re.compile(r"(?i)\b(extract|avg|sum|round|trunc|div|ceil|ceiling|floor|to_number|stddev\w*|variance"
                          r"|var_pop|var_samp|percentile_cont|percentile_disc)\s*\(")
NUMERIC_TYPE = re.compile(r"(?i)\b(numeric|decimal)\b")
NUMERIC_LITERAL = re.compile(r"(?<![\w.])((?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+)(?![\w.])")
NUMBER_TYPES = r"(double precision|float8|float4|real|bigint|int8|integer|int4|smallint|int2|int)\b"
NUMBER_CAST = re.compile(r"(?i)\s*::\s*" + NUMBER_TYPES)
CAST_CALL = re.compile(r"(?i)\bCAST\s*$")  # CAST( ... AS type): what precedes its parenthesis,
CAST_TO_NUMBER = re.compile(r"(?is).*\bAS\s+" + NUMBER_TYPES + r"\s*$")  # and how its content ends.
SQL_START = re.compile(r"(?i)\s*\(?\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b")


def uncast_numeric(sql):
    """The parts of `sql` whose value PostgreSQL may type numeric with no cast to a float or an integer type right
    after them, after a parenthesis around them or by a CAST(... AS type) around them (quoted literals left out)."""
    text = re.sub(r"'(?:[^']|'')*'", "''", sql)
    pairs, opened = [], []
    for i, char in enumerate(text):
        if char == "(":
            opened.append(i)
        elif char == ")" and opened:
            pairs.append((opened.pop(), i))
    parts = [m.span() for pattern in (NUMERIC_TYPE, NUMERIC_LITERAL) for m in pattern.finditer(text)]
    for m in NUMERIC_CALL.finditer(text):
        parts.append((m.start(), next((c for o, c in pairs if o == m.end() - 1), len(text) - 1) + 1))

    def cast(end):
        return NUMBER_CAST.match(text, end) is not None

    def cast_as(opening, closing):
        return CAST_CALL.search(text[:opening]) is not None and CAST_TO_NUMBER.match(text[opening + 1:closing])
    return sorted(text[a:b] for a, b in parts if not cast(b) and not any(
        o < a and b <= c and (cast(c + 1) or cast_as(o, c)) for o, c in pairs))


def psycopg2_statements():
    """{file: [statement]} of every lab module that imports psycopg2 (today lab/services.py; guest_state.py and
    udalosti.py run psql and parse its text): every string constant that starts a statement, in any case of its
    keywords, docstrings left out."""
    found = {}
    for path in sorted(LAB.glob("*.py")):
        tree = ast.parse(path.read_text())
        modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        modules |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        if not any(name.split(".")[0] == "psycopg2" for name in modules):
            continue
        docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                      if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body
                      and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)}
        found[path.name] = [node.value for node in ast.walk(tree)
                            if isinstance(node, ast.Constant) and isinstance(node.value, str)
                            and id(node) not in docstrings and SQL_START.match(node.value)]
    return found


def test_no_sql_value_the_lab_reads_through_psycopg2_can_be_numeric():
    # The guard finds what it must: the document list of B5b, the aggregates, a literal, a cast to numeric.
    assert uncast_numeric("SELECT id, name, owner, bytes, extract(epoch FROM created_at) FROM documents") == [
        "extract(epoch FROM created_at)"]
    assert uncast_numeric("SELECT avg(price_cents), sum(total_cents::bigint) FROM orders") == [
        "avg(price_cents)", "sum(total_cents::bigint)"]
    assert uncast_numeric("SELECT round(price_cents / 100.0, 2), CAST(quantity AS numeric) FROM x") == [
        "100.0", "numeric", "round(price_cents / 100.0, 2)"]
    for good in ("SELECT extract(epoch FROM created_at)::double precision FROM documents",
                 "SELECT coalesce(extract(epoch FROM max(created_at)), 0)::float8, sum(quantity)::bigint FROM x",
                 "SELECT (price_cents * 0.9)::integer FROM products WHERE name ILIKE '%1.5%'"):
        assert uncast_numeric(good) == [], good
    statements = psycopg2_statements()  # A new module that imports psycopg2 is read as well.
    module = ast.parse((LAB / "services.py").read_text())
    named = {node.targets[0].id: ast.literal_eval(node.value) for node in module.body
             if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "").startswith("SQL_")}
    assert "SQL_DOC_PAGE" in named and set(named.values()) <= set(statements["services.py"])
    assert {sql: uncast_numeric(sql) for sqls in statements.values() for sql in sqls if uncast_numeric(sql)} == {}
    assert HEARTBEAT_AGE in statements["services.py"]  # The inline statements are read too.
    schema = "\n".join(line.split("--", 1)[0] for line in (LAB / "schema.sql").read_text().splitlines())
    assert NUMERIC_TYPE.findall(schema) == []  # No column is numeric.


@pytest.mark.parametrize("sql, uncast", [
    ("select id, extract(epoch from created_at) from documents", ["extract(epoch from created_at)"]),
    ("SELECT to_number(code, '9999') FROM x", ["to_number(code, '')"]),
    ("SELECT 1e3, 2.5E-2, .5e1 FROM x", [".5e1", "1e3", "2.5E-2"]),
    ("SELECT CAST(extract(epoch FROM created_at) AS double precision), CAST(sum(q) AS bigint) FROM x", []),
    ("SELECT cast(to_number(code, '9') as integer), 1e3::float8 FROM x", []),
    ("SELECT CAST(quantity AS numeric), CAST(extract(epoch FROM t) AS text) FROM x",
     ["extract(epoch FROM t)", "numeric"]),
], ids=["lowercase", "to_number", "exponent", "cast_as", "cast_as_lowercase", "cast_as_other_type"])
def test_the_guard_reads_every_case_to_number_exponents_and_cast_as(tmp_path, monkeypatch, sql, uncast):
    """Finding F3 of the B5c verification (package B10): the guard reads a statement whatever the case of its keywords,
    to_number() and literals with an exponent are numeric, and CAST(... AS a float or an integer type) casts what it
    holds (to text or to numeric it does not). A module of the lab (here one in tmp_path) that imports psycopg2 is read
    with its lowercase statements."""
    assert uncast_numeric(sql) == uncast
    (tmp_path / "module.py").write_text(f"import psycopg2\nQUERY = {sql.lower()!r}\n")
    monkeypatch.setattr(sys.modules[__name__], "LAB", tmp_path)
    assert psycopg2_statements() == {"module.py": [sql.lower()]}


@pytest.mark.parametrize("size,status", [(1024, 201), (1025, 413)])
def test_upload_cap_is_checked_before_the_body_is_read(lab, monkeypatch, size, status):
    assert lab.s.MAX_DOCUMENT == 8 << 20  # KOSTRA B5: 8 MiB; the boundary is tried on a smaller cap.
    monkeypatch.setattr(lab.s, "MAX_DOCUMENT", 1024)
    raw = b"x" * size if status == 201 else b""  # A refused upload is answered without reading its body.
    assert lab.call("docs", "POST", "/api/docs?name=big.bin", token=lab.employee, raw=raw, length=size)[0] == status
    assert len(list((lab.tmp / "docs").iterdir())) == (status == 201)


def queued(lab):
    status, reply, _ = lab.call("docs", "POST", "/api/reports", token=lab.employee)
    assert status == 202 and reply["status"] == "queued"
    return reply["report"]


def fake_psql(calls, rc=0):
    """subprocess.run in which psql (absent on the host) writes the CSV of its \\copy; other stages run for real."""
    real = subprocess.run

    def run(argv, **kw):
        calls.append(argv[0])
        if argv[0] == "psql":
            if rc == 0:
                target = re.search(r"TO '([^']+)'", argv[-1])[1]
                Path(target).write_text("2,zakaznik0002,500,completed,2026-01-01,1\n"
                                        "1,zakaznik0001,900,completed,2026-01-01,2\n")
            return subprocess.CompletedProcess(argv, rc, "", "" if rc == 0 else "psql: error: connection refused")
        return real(argv, **kw)
    return run


def test_report_runs_three_subprocesses_and_one_report_at_a_time(lab, capsys):
    first, second, third = queued(lab), queued(lab), queued(lab)
    assert lab.call("docs", "GET", f"/api/reports/{first}", token=lab.employee)[1]["status"] == "queued"
    calls = []
    done = lab.s.report_round(run=fake_psql(calls))
    assert calls == ["psql", "bash", "install"] and done["report"] == first and done["rows"] == 2
    with gzip.open(lab.tmp / "reports" / f"{first}.csv.gz", "rt") as stream:  # Sorted by the total, descending.
        assert [line.split(",")[0] for line in stream.read().splitlines()] == ["1", "2"]
    assert lab.call("docs", "GET", f"/api/reports/{second}", token=lab.employee)[1]["status"] == "queued"
    assert lab.call("docs", "GET", f"/api/reports/{first}", token=lab.employee)[1]["status"] == "done"
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["report"] == first
    order = [lab.s.report_round(run=fake_psql(calls))["report"] for _ in range(2)]
    assert order == [second, third] and lab.s.report_round(run=fake_psql(calls)) is None  # In request order.


def test_failed_report_stage_stops_the_report_and_prints_the_worker_error(lab, capsys):
    report = queued(lab)
    calls = []
    assert lab.s.report_round(run=fake_psql(calls, rc=2)) == {"report": report, "failed": "select"}
    assert calls == ["psql"] and (lab.tmp / "spool/failed" / f"{report}.json").exists()
    assert capsys.readouterr().out.startswith(lab.s.WORKER_ERROR + f"report {report} stage select: exit 2")
    assert lab.s.report_round(run=fake_psql(calls)) is None  # Nothing else is queued.


@pytest.mark.parametrize("rc,stderr,code", [
    (0, "", 0),
    (2, "psql: error: connection to server on socket failed: No such file or directory", 75),
    (1, "ERROR:  canceling statement due to lock timeout", 75),
    (1, "ERROR:  permission denied for table products", 1),
])
def test_maintenance_vacuums_compresses_the_document_log_and_reports_its_outcome(lab, capsys, rc, stderr, code):
    (lab.tmp / "logs/docs.log").write_text('{"action": "list"}\n')
    real, calls = subprocess.run, []

    def run(argv, **kw):
        calls.append(argv)
        if argv[0] == "psql":
            return subprocess.CompletedProcess(argv, rc, "", stderr)
        return real(argv, **kw)
    assert lab.s.udrzba(run=run) == code
    assert calls[0][-1].startswith("VACUUM (ANALYZE) products") and calls[1][0] == "gzip"
    compressed = list((lab.tmp / "logs").glob("docs-*.log.gz"))
    assert len(compressed) == 1 and not (lab.tmp / "logs/docs.log").exists()
    assert json.loads(capsys.readouterr().out)["vacuum_rc"] == rc


def test_worker_pause_is_drawn_from_0_8_to_1_2_seconds(lab, monkeypatch):
    waits = []

    class Event(threading.Event):
        def wait(self, timeout=None):  # No real pause; the fifth one stops the worker.
            waits.append(timeout)
            if len(waits) == 5:
                self.set()
            return self.is_set()

    @contextmanager
    def database():
        yield SimpleNamespace(execute=lambda sql: None, rowcount=0)
    monkeypatch.setattr(lab.s.threading, "Event", Event)
    monkeypatch.setattr(lab.s, "database", database)
    handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        lab.s.worker()
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    assert len(waits) == 5 and all(.8 <= w <= 1.2 for w in waits) and len(set(waits)) == 5
