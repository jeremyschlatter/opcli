-- 1Password core_db migration to version 30
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DROP TABLE IF EXISTS resources;
UPDATE config
SET value = 30
WHERE name = 'version';
