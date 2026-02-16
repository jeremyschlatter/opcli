-- 1Password core_db migration to version 7
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

ALTER TABLE item_overviews ADD COLUMN validated INTEGER NOT NULL DEFAULT 0;
UPDATE config SET value=7 WHERE name='version';
