-- 1Password core_db migration to version 1
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_version INTEGER NOT NULL DEFAULT 0,
    data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS account_objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    object_type TEXT NOT NULL,
    local_version INTEGER NOT NULL DEFAULT 0,
    data BLOB NOT NULL,
    UNIQUE (account_id, uuid),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS account_objects_account_id_object_type ON account_objects(account_id, object_type);
CREATE TABLE IF NOT EXISTS vault_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    local_edit_count INTEGER NOT NULL,
    rejected_build_version INTEGER NOT NULL,
    rejection_reason TEXT,
    data BLOB NOT NULL,
    UNIQUE (vault_id, uuid),
    FOREIGN KEY (vault_id) REFERENCES account_objects(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_name TEXT NOT NULL,
    updated_at integer not null,
    created_at timestamp default current_timestamp,
    data BLOB NOT NULL,
    UNIQUE (key_name)
);
CREATE TABLE IF NOT EXISTS config (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS item_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    usage_type TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    vault_uuid TEXT NOT NULL,
    item_uuid TEXT NOT NULL,
    used_at INTEGER NOT NULL,
    item_version INTEGER NOT NULL
);
INSERT INTO config (name, value) VALUES ("version", 1);
