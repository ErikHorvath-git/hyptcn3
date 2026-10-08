CREATE TABLE IF NOT EXISTS products (
    id integer PRIMARY KEY, name text NOT NULL, price_cents integer NOT NULL CHECK(price_cents > 0)
);
INSERT INTO products VALUES
 (1, 'Keyboard', 4900), (2, 'Mouse', 2500), (3, 'Monitor', 19900),
 (4, 'USB cable', 900), (5, 'Headphones', 5900)
ON CONFLICT (id) DO NOTHING;
CREATE TABLE IF NOT EXISTS orders (
    id bigserial PRIMARY KEY, username text NOT NULL,
    product_id integer NOT NULL REFERENCES products(id),
    quantity integer NOT NULL CHECK(quantity BETWEEN 1 AND 20),
    total_cents integer NOT NULL CHECK(total_cents > 0),
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS orders_user_id ON orders(username, id DESC);
CREATE INDEX IF NOT EXISTS orders_pending ON orders(id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS worker_heartbeat (id integer PRIMARY KEY, updated_at timestamptz NOT NULL);
