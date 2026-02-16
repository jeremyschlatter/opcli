-- 1Password core_db migration to version 13
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS enc_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    enc_name   BLOB    NOT NULL,
    data       BLOB    NOT NULL,
    k_bucket   INTEGER,
    UNIQUE (account_id, enc_name) ON CONFLICT REPLACE,
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_enc_k_account ON enc_resources (k_bucket, account_id);
UPDATE config SET value=13 WHERE name='version';
