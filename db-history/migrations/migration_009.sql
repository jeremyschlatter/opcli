-- 1Password core_db migration to version 9
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS deleted_accounts (
    account_uuid TEXT NOT NULL,
    secret_key TEXT NOT NULL
);
UPDATE config SET value=9 WHERE name='version';
