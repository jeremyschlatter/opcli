-- 1Password core_db migration to version 18
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- Converting the data column from a TEXT to INTEGER
ALTER TABLE kanon_autofill RENAME TO kanon_autofill_old;
CREATE TABLE IF NOT EXISTS kanon_autofill (
    item_id       INTEGER NOT NULL,
    account_id    INTEGER NOT NULL,
    data          INTEGER NOT NULL,
    PRIMARY KEY (item_id, data) ON CONFLICT REPLACE
    FOREIGN KEY (item_id) REFERENCES item_overviews (id) ON DELETE CASCADE
);
INSERT INTO kanon_autofill 
SELECT old.item_id, old.account_id, CAST(old.data AS INTEGER)
FROM kanon_autofill_old old
WHERE 0;
-- drop the old data 
DROP TABLE kanon_autofill_old;
-- Covering index for filtering `autofill` items by domain name
-- Same as `UNIQUE (item_id, data)`, but we cannot reverse the columns since
-- `kanon_autofill` is also queried by `item_id`.
CREATE INDEX idx_kanon_autofill_data_item_id ON kanon_autofill (data, item_id);
-- Getting list of accounts in `kanon_autofill`
CREATE INDEX idx_kanon_autofill_account_id ON kanon_autofill (account_id);
UPDATE config SET value=18 WHERE name='version';
