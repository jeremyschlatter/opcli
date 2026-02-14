-- 1Password core_db migration to version 21
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    last_fetched INTEGER NOT NULL,
    enc_overview BLOB NOT NULL,
    UNIQUE (account_id, uuid),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
UPDATE config
SET value = 21
WHERE name = 'version';
