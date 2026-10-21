-- 1Password core_db migration to version 63
-- Extracted from 1Password 8 binary (index.node), app version 8.12.42

DROP INDEX IF EXISTS items_local_edit_count;
DROP INDEX IF EXISTS items_version;
DROP INDEX IF EXISTS items_rejection_reason;
CREATE INDEX IF NOT EXISTS items_to_push ON items(account_uuid, vault_uuid, version)
WHERE local_edit_count != 0
  AND rejection_reason = 0;
CREATE INDEX IF NOT EXISTS items_rejection_reason ON items(account_uuid)
WHERE rejection_reason != 0;
UPDATE config
SET value = 63
WHERE name = 'version';
