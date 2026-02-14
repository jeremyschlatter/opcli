-- 1Password core_db migration to version 52
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

INSERT INTO objects_associated (
  type,
  key_name,
  associated_account,
  associated_item,
  data
)
SELECT
  27, -- ObjectRowType::ItemUsage
  item_usage.uuid,
  item_usage.account_id,
  item_overviews.id,
  json_object(
    'usage_type', item_usage.usage_type,
    'used_at', item_usage.used_at,
    'item_version', item_usage.item_version,
    'synced_at', item_usage.synced_at
  ) as BLOB
FROM item_usage
INNER JOIN item_overviews
ON item_overviews.uuid = item_usage.item_uuid
INNER JOIN account_objects
ON account_objects.id = item_overviews.vault_id
  AND account_objects.uuid = item_usage.vault_uuid
  AND account_objects.account_id = item_usage.account_id;
DROP TABLE IF EXISTS item_usage;
UPDATE config
SET value = 52
WHERE name = 'version';
