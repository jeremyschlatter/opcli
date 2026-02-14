-- 1Password core_db migration to version 26
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

UPDATE config
SET value=26
WHERE name = 'version';
