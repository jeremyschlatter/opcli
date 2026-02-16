-- 1Password core_db migration to version 20
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs
-- NOTE: This is a Rust-based migration that reads data from `drafts` and
-- inserts into new tables. The parameterized SQL templates are omitted.

CREATE TABLE editing_drafts (
    -- Extra context (we dont want to know what is in here at this level, just that it is encrypted)
    context    BLOB NOT NULL,

    account_id INTEGER NOT NULL,
    -- Foreign key pointing to item_overviews
    item_id INTEGER PRIMARY KEY,
    -- These must be kept in sync with the item_overviews table!
    vault_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    template_uuid TEXT NOT NULL,
    changer_uuid TEXT NOT NULL,
    favorite INTEGER NOT NULL,
    trashed INTEGER NOT NULL,
    version INTEGER NOT NULL,
    local_edit_count INTEGER NOT NULL,
    rejection_reason INTEGER NOT NULL,
    enc_overview BLOB NOT NULL,
    -- This must be kept in sync with the item_details table!
    enc_details BLOB NOT NULL,
    -- Delete the draft if the account is deleted
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    -- Delete the draft if the item is deleted
    FOREIGN KEY (item_id) REFERENCES item_overviews(id) ON DELETE CASCADE,
    -- Delete the draft if the vault is deleted
    FOREIGN KEY (vault_id) REFERENCES account_objects(id) ON DELETE CASCADE
);

CREATE TABLE creation_drafts (
    -- Extra context (we dont want to know what is in here at this level, just that it is encrypted)
    context    BLOB NOT NULL,

    account_id INTEGER NOT NULL,
    -- Local uuid, must be locally unique (generate a new one for each new creation draft)
    uuid TEXT UNIQUE NOT NULL,
    -- Delete the draft if the account is deleted
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

UPDATE config
SET value=20
WHERE name = 'version';

DROP TABLE drafts;
