-- 1Password core_db migration to version 6
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DROP TABLE IF EXISTS autofill;
CREATE TABLE IF NOT EXISTS autofill (
    account_id    INTEGER NOT NULL,
    vault_id      INTEGER NOT NULL,
    item_id       INTEGER NOT NULL,
    category      TEXT    NOT NULL,
    autofill_data BLOB    NOT NULL,
    PRIMARY KEY (account_id, item_id) ON CONFLICT REPLACE
    FOREIGN KEY (item_id) REFERENCES item_overviews (id) ON DELETE CASCADE
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS collection_map (
    account_id      INTEGER NOT NULL,
    collection_uuid TEXT    NOT NULL,
    vault_ids       BLOB    NOT NULL,
    PRIMARY KEY (account_id, collection_uuid) ON CONFLICT REPLACE
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);
UPDATE config SET value=6 WHERE name = 'version';
