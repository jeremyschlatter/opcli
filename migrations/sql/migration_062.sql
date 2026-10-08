-- 1Password core_db migration to version 62
-- Extracted from 1Password 8 binary (index.node), app version 8.12.40

CREATE INDEX IF NOT EXISTS items_local_edit_count_state ON items(1)
WHERE local_edit_count = 0
  AND data ->> '$.state' = 2;
CREATE INDEX IF NOT EXISTS objects_associated_account_uuid_vault_uuid_item_uuid_type_key_name
ON objects_associated(
	account_uuid,
	vault_uuid,
	item_uuid,
	type,
	key_name
);
CREATE INDEX IF NOT EXISTS objects_unassociated_type ON objects_unassociated(type);
UPDATE config
SET value = 62
WHERE name = 'version';
