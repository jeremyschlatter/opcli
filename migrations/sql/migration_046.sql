-- 1Password core_db migration to version 46
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS objects_unassociated (
    key_name TEXT NOT NULL,
    type INT NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (key_name, type)
);
INSERT INTO objects_unassociated (key_name, type, data)
SELECT key_name, type, data FROM objects WHERE associated_account IS NULL;
-- we can't modify table PKs and stuff so create a new table and copy the data
CREATE TABLE objects_associated (
    key_name TEXT NOT NULL,
    type INT NOT NULL,
    data BLOB NOT NULL,
    associated_item INT,
    associated_account INT NOT NULL, -- associated_account is no longer nullable
    PRIMARY KEY (key_name, type, associated_account),
    CONSTRAINT objects_associated_account_fk
        FOREIGN KEY (associated_account) REFERENCES accounts (id) ON DELETE CASCADE,
    CONSTRAINT objects_associated_item_fk
        FOREIGN KEY (associated_item) REFERENCES item_overviews (id) ON DELETE CASCADE
);
INSERT INTO objects_associated (key_name, type, data, associated_item, associated_account)
SELECT key_name, type, data, associated_item, associated_account FROM objects
WHERE associated_account IS NOT NULL;
DROP TABLE objects;
UPDATE config
SET value = 46
WHERE name = 'version';
