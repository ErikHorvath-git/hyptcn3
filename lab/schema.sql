-- Schema of the benign lab, protocol v5 (package B5). lab/install.sh runs it on every deployment; a database of an
-- older schema (no row 5 in lab_schema) is dropped and recreated empty, and lab/guest_state.py reset --seed S
-- fills it with the seeded level (lab/seed.py). The tables hold no data that is not seeded or lab traffic.
CREATE TABLE IF NOT EXISTS lab_schema (version integer NOT NULL);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM lab_schema WHERE version = 5) THEN
        DROP TABLE IF EXISTS order_items, cart_items, orders, documents, employees, customers, products,
            worker_heartbeat CASCADE;
        DELETE FROM lab_schema;
        INSERT INTO lab_schema VALUES (5);
    END IF;
END
$$;
CREATE TABLE IF NOT EXISTS products (
    id integer PRIMARY KEY, name text NOT NULL, category text NOT NULL, description text NOT NULL,
    price_cents integer NOT NULL CHECK (price_cents > 0)
);
CREATE TABLE IF NOT EXISTS customers (username text PRIMARY KEY, name text NOT NULL, email text NOT NULL);
-- password_hash: pbkdf2_sha256$<iterations>$<salt hex>$<hash hex> (lab/seed.py hash_password).
CREATE TABLE IF NOT EXISTS employees (
    username text PRIMARY KEY, name text NOT NULL, department text NOT NULL, password_hash text NOT NULL
);
CREATE TABLE IF NOT EXISTS cart_items (
    username text NOT NULL, product_id integer NOT NULL REFERENCES products(id),
    quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 20), added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (username, product_id)
);
CREATE TABLE IF NOT EXISTS orders (
    id bigserial PRIMARY KEY, username text NOT NULL,
    total_cents integer NOT NULL CHECK (total_cents > 0),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS order_items (
    order_id bigint NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id integer NOT NULL REFERENCES products(id),
    quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 20),
    price_cents integer NOT NULL CHECK (price_cents > 0),
    PRIMARY KEY (order_id, product_id)
);
CREATE INDEX IF NOT EXISTS orders_user_id ON orders(username, id DESC);
CREATE INDEX IF NOT EXISTS orders_pending ON orders(id) WHERE status='pending';
CREATE INDEX IF NOT EXISTS orders_created ON orders(created_at);
-- The content lies in /var/lib/hyptcn-lab/docs/<id>.bin; the cap is the upload cap of lab/services.py.
CREATE TABLE IF NOT EXISTS documents (
    id bigserial PRIMARY KEY, name text NOT NULL, owner text NOT NULL,
    bytes integer NOT NULL CHECK (bytes BETWEEN 1 AND 8388608), sha256 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS worker_heartbeat (id integer PRIMARY KEY, updated_at timestamptz NOT NULL);
