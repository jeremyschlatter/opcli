-- 1Password core_db migration to version 37
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS developer_activity_log (
    -- DeveloperActivityLogEntryType enum
    entry_type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    -- Item Row ID associated with the request; only for SSH requests,
    -- will be null for CLI requests; not adding a foreign key for this field,
    -- because if a user deletes an item, we would still want to show the activity
    -- log entry, we just wouldn't be able to show the item details, so we don't want
    -- to use `ON CASCADE DELETE` here.
    item_id INTEGER,
    -- *encrypted* application info
    enc_application_info BLOB NOT NULL,
    -- *encrypted* full process tree
    enc_process_tree BLOB NOT NULL,
    -- only for SSH requests, should always be false for CLI requests
    is_background_request INTEGER NOT NULL,
    CHECK (is_background_request = 0 OR is_background_request = 1),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
UPDATE config
SET value = 37
WHERE name = 'version';
