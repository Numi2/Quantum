-- Migration to create ACME tables
CREATE TABLE IF NOT EXISTS acme_accounts (
    url TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    jwk JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_orders (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    cert_url TEXT,
    cert_chain BYTEA
);

CREATE TABLE IF NOT EXISTS acme_challenges (
    token TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
    key_authorization TEXT NOT NULL,
    status TEXT NOT NULL,
    UNIQUE(order_id)
);