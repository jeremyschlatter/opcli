-- 1Password core_db migration to version 25
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- Add a foreign key constraint on item_usage table to cascade 
-- deletion with the associated account row. 
-- Fixes Issue #15268 
-- SQLite doesn't support ALTER TABLE ... ADD CONSTRAINT so we'll
-- make a new table with the constraint we need, copy the rows,
-- drop the original and rename the new table `item_usage`.
-- The SQLite ALTER TABLE docs recommend this method.
-- Just in case there is some junk about...
DROP TABLE IF EXISTS tmp_item_usage;
CREATE TABLE tmp_item_usage  (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    usage_type TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    vault_uuid TEXT NOT NULL,
    item_uuid TEXT NOT NULL,
    used_at INTEGER NOT NULL,
    item_version INTEGER NOT NULL,
    synced_at INTEGER DEFAULT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);
INSERT INTO tmp_item_usage SELECT * FROM item_usage WHERE account_id IN (SELECT id FROM accounts);
DROP TABLE item_usage;
ALTER TABLE tmp_item_usage RENAME TO item_usage;
PRAGMA foreign_key_check;
UPDATE config
SET value = 25
WHERE name = 'version';
