-- 1Password core_db migration to version 47
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

UPDATE objects_associated
SET key_name = ltrim(key_name, concat(associated_account, "-"))
WHERE type IN (5, 10, 19, 20);
UPDATE objects_associated
SET key_name = subquery.new_key
FROM (
	SELECT
		objects_associated.associated_account,
		objects_associated.type,
		objects_associated.key_name as old_key,
		concat(account_objects.uuid, ".", item_overviews.uuid) as new_key
	FROM objects_associated
	INNER JOIN item_overviews
	ON item_overviews.id = objects_associated.associated_item
	INNER JOIN account_objects
	ON account_objects.id = item_overviews.vault_id
	WHERE objects_associated.type IN (4, 9)
) as subquery
WHERE objects_associated.associated_account = subquery.associated_account
	AND objects_associated.type = subquery.type
	AND objects_associated.key_name = subquery.old_key;
UPDATE config
SET value = 47
WHERE name = 'version';
