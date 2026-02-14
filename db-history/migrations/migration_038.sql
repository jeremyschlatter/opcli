-- 1Password core_db migration to version 38
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DELETE FROM kanon_autofill;
DELETE FROM autofill;
UPDATE config
SET value = 38
WHERE name = 'version';
