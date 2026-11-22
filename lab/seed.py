#!/usr/bin/env python3
"""Seeded content of the benign lab (protocol v5, package B5): every row, document and static file
comes from a seed; nothing outside it is random.

  seed.py static --seed N --out DIR   write the static files nginx serves under /static/ (lab/install.sh)

lab/guest_state.py reset --seed S loads generate(S) into the database and writes its documents.
Each table and each file draws from its own stream, so a change of one count leaves the others alone.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
from pathlib import Path
import random

# Counts of the seeded level, lead's judgment (KOSTRA B5 section 1, "úsudok k počtom"): products, customers,
# employees with a password, documents. Orders with items and filled carts: executor's judgment (B5a), so that
# order lists, reports and carts have content from the first session on.
SIZES = {"products": 5000, "customers": 2000, "employees": 200, "documents": 500, "orders": 3000, "carts": 200}
# Executor's judgment: a login costs about 0.1 s of CPU, like PBKDF2 in a real application.
PBKDF2_ITERATIONS = 100_000
# Executor's judgment: seeded orders are at most 6 h old at the reset (the worker deletes completed orders older
# than one day, so none disappears while a group of three sessions runs); documents up to 30 days; prices
# lognormal around 25.00 (99 cents to 4999.00).
ORDER_AGE_S = 6 * 3600
DOCUMENT_AGE_S = 30 * 86400
DOCUMENT_MAX = 8 << 20  # The upload cap of lab/services.py.
# KOSTRA B5 section 1: 200 static files from 300 B to 2 MiB, log-uniform (here: evenly spaced on a log scale,
# so both ends are present; which name gets which size comes from the seed, popularity and size independent).
STATIC_FILES, STATIC_MIN, STATIC_MAX = 200, 300, 2 << 20
STATIC_TYPES = ("css", "js", "png", "jpg", "svg", "woff2")

ADJECTIVES = ("Basic", "Compact", "Classic", "Ergonomic", "Wireless", "Quiet", "Rugged", "Slim", "Smart", "Solid",
              "Portable", "Premium", "Rapid", "Silent", "Steel", "Travel", "Ultra", "Vintage", "Warm", "Bright")
NOUNS = ("Keyboard", "Mouse", "Monitor", "Cable", "Headphones", "Speaker", "Charger", "Lamp", "Backpack", "Bottle",
         "Chair", "Desk", "Router", "Camera", "Tablet", "Notebook", "Pen", "Kettle", "Blender", "Jacket", "Shoes",
         "Watch", "Drive", "Adapter", "Microphone")
CATEGORIES = ("electronics", "office", "home", "kitchen", "outdoor", "fashion", "sport", "garden", "toys", "books",
              "audio", "computers")
FIRST = ("Adam", "Eva", "Jana", "Peter", "Martin", "Lucia", "Tomas", "Zuzana", "Michal", "Katarina", "Juraj", "Maria",
         "Pavol", "Monika", "Robert", "Simona")
LAST = ("Novak", "Kovac", "Horvath", "Varga", "Toth", "Nagy", "Balaz", "Molnar", "Szabo", "Lukac", "Kral", "Urban")
DEPARTMENTS = ("finance", "sales", "support", "development", "legal", "operations", "marketing", "hr")
DOCUMENT_KINDS = ("zmluva", "faktura", "ponuka", "zapisnica", "smernica", "vykaz", "prezentacia", "rozpocet")
DOCUMENT_TYPES = ("pdf", "docx", "xlsx", "odt", "txt", "pptx")


def stream(seed, purpose):
    """The random stream of one purpose of one seed (independent of every other purpose)."""
    return random.Random(f"hyptcn3-lab/{seed}/{purpose}")


def employee_password(username):
    """Password of a seeded employee: fixed by the name for every seed, so the generator of profile corp can log
    in; only the PBKDF2 salt comes from the seed."""
    return hmac.new(b"hyptcn3-lab-employees", username.encode(), hashlib.sha256).hexdigest()[:16]


def hash_password(password, salt, iterations=PBKDF2_ITERATIONS):
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def document_size(r):
    """Lognormal body (median 64 KiB) with a Pareto tail (5 %, from 512 KiB), 1 KiB to 8 MiB; executor's judgment."""
    if r.random() < .05:
        size = (512 << 10) * r.paretovariate(1.2)
    else:
        size = math.exp(r.gauss(math.log(64 << 10), 1.0))
    return int(min(DOCUMENT_MAX, max(1024, size)))


def document_content(seed, doc_id, size):
    return stream(seed, f"document/{doc_id}").randbytes(size)


def generate(seed, iterations=None):
    """The seeded level: rows of every lab table (ages in seconds before the reset) and document metadata."""
    sizes = SIZES
    iterations = PBKDF2_ITERATIONS if iterations is None else iterations
    r = stream(seed, "products")
    products = []
    for pid in range(1, sizes["products"] + 1):
        name = f"{r.choice(ADJECTIVES)} {r.choice(NOUNS)} {r.randrange(100, 1000)}"
        category = r.choice(CATEGORIES)
        price = min(499_900, max(99, round(math.exp(r.gauss(math.log(2500), 1.0)))))
        products.append([pid, name, category, f"{name}, {category}", price])
    r = stream(seed, "customers")
    customers = [[f"zakaznik{i:04d}", f"{r.choice(FIRST)} {r.choice(LAST)}", f"zakaznik{i:04d}@lab.invalid"]
                 for i in range(1, sizes["customers"] + 1)]
    r = stream(seed, "employees")
    employees = []
    for i in range(1, sizes["employees"] + 1):
        user = f"zamestnanec{i:03d}"
        employees.append([user, f"{r.choice(FIRST)} {r.choice(LAST)}", r.choice(DEPARTMENTS),
                          hash_password(employee_password(user), r.randbytes(16), iterations)])
    prices = {row[0]: row[4] for row in products}
    r = stream(seed, "orders")
    orders, items = [], []
    for oid in range(1, sizes["orders"] + 1):
        chosen = r.sample(range(1, len(products) + 1), min(len(products), r.randint(1, 4)))
        lines = [[oid, pid, r.randint(1, 3), prices[pid]] for pid in sorted(chosen)]
        items += lines
        orders.append([oid, r.choice(customers)[0], sum(q * p for _, _, q, p in lines), "completed",
                       round(r.uniform(0, ORDER_AGE_S), 3)])
    r = stream(seed, "carts")
    carts = []
    for user in sorted(c[0] for c in r.sample(customers, min(len(customers), sizes["carts"]))):
        for pid in sorted(r.sample(range(1, len(products) + 1), min(len(products), r.randint(1, 3)))):
            carts.append([user, pid, r.randint(1, 3), round(r.uniform(0, 3600), 3)])
    r = stream(seed, "documents")
    documents = []
    for did in range(1, sizes["documents"] + 1):
        size = document_size(r)
        documents.append({"id": did, "name": f"{r.choice(DOCUMENT_KINDS)}-{did:04d}.{r.choice(DOCUMENT_TYPES)}",
                          "owner": r.choice(employees)[0], "bytes": size,
                          "sha256": hashlib.sha256(document_content(seed, did, size)).hexdigest(),
                          "age_s": round(r.uniform(0, DOCUMENT_AGE_S), 3)})
    return {"seed": seed, "products": products, "customers": customers, "employees": employees, "orders": orders,
            "order_items": items, "cart_items": carts, "documents": documents}


def digest(data):
    """SHA-256 of the seeded level; the same seed gives the same digest on every reset."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _copy(table, columns, rows):
    def field(value):
        return "\\N" if value is None else str(value).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
    lines = "".join("\t".join(field(v) for v in row) + "\n" for row in rows)
    return f"COPY {table} ({', '.join(columns)}) FROM STDIN;\n{lines}\\.\n"


def sql_script(data, now_unix):
    """psql script that replaces every lab table with the seeded level, in one transaction."""
    def at(age_s):
        return datetime.fromtimestamp(now_unix - age_s, timezone.utc).isoformat()
    return ("BEGIN;\nTRUNCATE order_items, cart_items, orders, documents, employees, customers, products, "
            "worker_heartbeat RESTART IDENTITY;\n"
            + _copy("products", ("id", "name", "category", "description", "price_cents"), data["products"])
            + _copy("customers", ("username", "name", "email"), data["customers"])
            + _copy("employees", ("username", "name", "department", "password_hash"), data["employees"])
            + _copy("orders", ("id", "username", "total_cents", "status", "created_at"),
                    [row[:4] + [at(row[4])] for row in data["orders"]])
            + _copy("order_items", ("order_id", "product_id", "quantity", "price_cents"), data["order_items"])
            + _copy("cart_items", ("username", "product_id", "quantity", "added_at"),
                    [row[:3] + [at(row[3])] for row in data["cart_items"]])
            + _copy("documents", ("id", "name", "owner", "bytes", "sha256", "created_at"),
                    [[d["id"], d["name"], d["owner"], d["bytes"], d["sha256"], at(d["age_s"])] for d in data["documents"]])
            + "SELECT setval('orders_id_seq', (SELECT coalesce(max(id), 0) + 1 FROM orders), false);\n"
            + "SELECT setval('documents_id_seq', (SELECT coalesce(max(id), 0) + 1 FROM documents), false);\n"
            + "COMMIT;\n")


def static_files(seed):
    """[(name, size)] of the static files: sizes evenly spaced on a log scale from STATIC_MIN to STATIC_MAX."""
    ratio = STATIC_MAX / STATIC_MIN
    sizes = [round(STATIC_MIN * ratio ** (i / (STATIC_FILES - 1))) for i in range(STATIC_FILES)]
    stream(seed, "static/sizes").shuffle(sizes)
    return [(f"{i:03d}.{STATIC_TYPES[i % len(STATIC_TYPES)]}", size) for i, size in enumerate(sizes)]


def write_static(seed, out):
    """Write the static files into `out` and remove any other file there; returns their manifest."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    files = static_files(seed)
    for path in out.iterdir():
        if path.is_file() and path.name not in {name for name, _ in files}:
            path.unlink()
    manifest = {}
    for name, size in files:
        data = stream(seed, f"static/{name}").randbytes(size)
        (out / name).write_bytes(data)
        manifest[name] = {"bytes": size, "sha256": hashlib.sha256(data).hexdigest()}
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["static"])
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = write_static(args.seed, args.out)
    print(json.dumps({"schema": "hyptcn3/lab-static/1", "seed": args.seed, "files": len(manifest),
                      "bytes": sum(f["bytes"] for f in manifest.values()),
                      "sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()}))


if __name__ == "__main__":
    main()
