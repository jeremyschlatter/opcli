-- 1Password core_db migration to version 19
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- Not required it's just for safety.
DELETE FROM resources where is_encrypted = 0;
CREATE UNIQUE INDEX idx_resources_name_account_id_is_encrypted ON resources (
    name, coalesce(account_id, is_encrypted));
UPDATE config
SET value=19
WHERE name = 'version';
