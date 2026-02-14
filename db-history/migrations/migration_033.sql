-- 1Password core_db migration to version 33
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- ignoring the `last_updated` and `uuid` fields makes the API much simpler,
-- but sqlite does not support dropping primary key columns so recreate the table instead
CREATE TABLE IF NOT EXISTS account_policies_tmp (
    account_uuid TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    definition_hash BLOB NOT NULL,
    definition BLOB NOT NULL,
    FOREIGN KEY (account_uuid) REFERENCES accounts (account_uuid) ON DELETE CASCADE
    UNIQUE (account_uuid, policy_name) ON CONFLICT REPLACE
-- copy the data over
);
INSERT INTO account_policies_tmp (account_uuid, policy_name, definition_hash, definition)
    SELECT account_uuid, policy_name, definition_hash, definition FROM account_policies;
-- rename the table
DROP TABLE account_policies;
ALTER TABLE account_policies_tmp RENAME TO account_policies;
UPDATE config
SET value = 33
WHERE name = 'version';
