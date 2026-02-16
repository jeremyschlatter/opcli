-- 1Password core_db migration to version 11
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

DROP TABLE IF EXISTS kanon_autofill;
CREATE TABLE IF NOT EXISTS kanon_autofill (
    item_id       INTEGER NOT NULL,
    account_id    INTEGER NOT NULL,
    data          TEXT NOT NULL,
    PRIMARY KEY (item_id, data) ON CONFLICT REPLACE
    FOREIGN KEY (item_id) REFERENCES item_overviews (id) ON DELETE CASCADE
);
CREATE INDEX idx_kanon ON kanon_autofill (item_id, data);
UPDATE config SET value=11 WHERE name='version';
