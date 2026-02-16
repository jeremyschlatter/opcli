-- 1Password core_db migration to version 8
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DELETE FROM autofill WHERE category != "001" AND category != "002" AND category != "004" AND category != "005";
UPDATE config SET value=8 WHERE name='version';
