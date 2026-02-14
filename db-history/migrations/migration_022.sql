-- 1Password core_db migration to version 22
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE search_weighting (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    -- Encrypted search weights. These are stored encrypted with a key derived from the account and
    -- we should not treat these as high reliability data. Migrations can blow this away if/when
    -- changes are required (this is not unique user data, only the app improving itself for
    -- the user's workflow).
    enc_weights    BLOB NOT NULL
);
UPDATE config
SET value = 22
WHERE name = 'version';
