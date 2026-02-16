-- 1Password core_db migration to version 2
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

SELECT id FROM item_overviews WHERE local_edit_count > 0 LIMIT 1;
ALTER TABLE accounts ADD COLUMN account_uuid TEXT NOT NULL DEFAULT '';
UPDATE accounts SET account_uuid = json_extract(data, '$.account_uuid');
CREATE UNIQUE INDEX accounts_uuid ON accounts (account_uuid);
DROP TABLE vault_items;
DELETE FROM account_objects WHERE object_type='vault';
CREATE TABLE item_overviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    template_uuid TEXT NOT NULL,
    changer_uuid TEXT NOT NULL,
    favorite INTEGER NOT NULL,
    trashed INTEGER NOT NULL,
    version INTEGER NOT NULL,
    local_edit_count INTEGER NOT NULL,
    rejected_build_version INTEGER NOT NULL,
    rejection_reason TEXT,
    enc_overview BLOB NOT NULL,
    UNIQUE (vault_id, uuid),
    FOREIGN KEY (vault_id) REFERENCES account_objects(id) ON DELETE CASCADE
);
CREATE TABLE item_details (
    id INTEGER PRIMARY KEY,
    enc_details BLOB NOT NULL,
    FOREIGN KEY (id) REFERENCES item_overviews(id) ON DELETE CASCADE
);
UPDATE config SET value=2 WHERE name='version';
