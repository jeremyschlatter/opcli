-- 1Password core_db migration to version 24
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

ALTER TABLE item_usage ADD COLUMN synced_at INT;
UPDATE config
SET value = 24
WHERE name = 'version';
