-- 1Password core_db migration to version 14
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- Table to hold a single draft per account, this will hold to two blobs. The first will contain the
-- encrypted item or the template and the second will contain the encrypted context.
CREATE TABLE IF NOT EXISTS drafts (
    -- Template or encrypted item held as a blob, this is done for simplicity and to allow replacing
    -- this with a template
    data       BLOB NOT NULL,
    -- Extra context (we dont want to know what is in here at this level, just that it is encrypted)
    context    BLOB NOT NULL,

    account_id INTEGER NOT NULL,
    -- We want there to be at most one draft per account, drop any old cruft when saving a new one
    PRIMARY KEY (account_id) ON CONFLICT REPLACE,
    -- Delete the draft if the account is deleted
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
UPDATE config SET value=14 WHERE name='version';
