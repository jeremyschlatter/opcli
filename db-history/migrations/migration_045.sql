-- 1Password core_db migration to version 45
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- NB: DB version 44 is a Rust-based migration, hence why this migration's
-- file name skips a number and sets the DB version to 45
DROP TABLE IF EXISTS activation_hub_tasks;
UPDATE config
SET value = 45
WHERE name = 'version';
