-- 1Password core_db migration to version 50
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DROP TABLE IF EXISTS deleted_accounts;
DROP TABLE IF EXISTS search_weighting;
DROP TABLE IF EXISTS users;
UPDATE config
SET value = 50
WHERE name = 'version';
