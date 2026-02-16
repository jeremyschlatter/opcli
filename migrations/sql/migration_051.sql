-- 1Password core_db migration to version 51
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

INSERT INTO objects_associated (
	key_name,
	type,
	data,
	associated_item,
	associated_account
)
SELECT
  concat(account_objects.uuid, ".", item_overviews.uuid),
  26,
  snippet_shortcuts.shortcut,
  snippet_shortcuts.item_id,
  snippet_shortcuts.account_id
FROM snippet_shortcuts
INNER JOIN item_overviews
ON item_overviews.id = snippet_shortcuts.item_id
INNER JOIN account_objects
ON account_objects.id = item_overviews.vault_id;
DROP TABLE IF EXISTS snippet_shortcuts;
UPDATE config
SET value = 51
WHERE name = 'version';
