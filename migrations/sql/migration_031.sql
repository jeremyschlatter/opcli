-- 1Password core_db migration to version 31
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DELETE FROM kanon_autofill;
DELETE FROM autofill;
UPDATE config
SET value = 31
WHERE name = 'version';
