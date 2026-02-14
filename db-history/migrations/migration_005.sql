-- 1Password core_db migration to version 5
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DELETE FROM account_objects WHERE object_type='vault';
UPDATE config SET value=5 WHERE name='version';
