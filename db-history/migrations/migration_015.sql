-- 1Password core_db migration to version 15
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- Redundant with the `UNIQUE` constraint on `kanon_autofill`
DROP INDEX idx_kanon;
-- Filtering `autofill` items by category
CREATE INDEX idx_autofill_category ON autofill (category);
-- Covering index for filtering `autofill` items by domain name
-- Same as `UNIQUE (item_id, data)`, but we cannot reverse the columns since
-- `kanon_autofill` is also queried by `item_id`.
CREATE INDEX idx_kanon_autofill_data_item_id ON kanon_autofill (data, item_id);
-- Getting list of accounts in `kanon_autofill`
CREATE INDEX idx_kanon_autofill_account_id ON kanon_autofill (account_id);
UPDATE config SET value=15 WHERE name='version';
