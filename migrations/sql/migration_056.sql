-- 1Password core_db migration to version 56
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DELETE FROM objects_associated
WHERE type = 31 OR type = 32;
UPDATE config
SET value = 56
WHERE name = 'version';
