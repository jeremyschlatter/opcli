-- 1Password core_db migration to version 48
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs
-- NOTE: Rust-based migration. Reads developer_activity_log entries,
-- looks up account/vault/item UUIDs, and inserts into objects_associated.

-- (parameterized SELECT queries omitted)

INSERT INTO objects_associated(key_name, type, associated_item, associated_account, data)
VALUES(:key_name, 24, NULL, :associated_account, :data);

DROP TABLE IF EXISTS developer_activity_log;

UPDATE config SET value = 48 WHERE name = 'version';
