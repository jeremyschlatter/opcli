-- 1Password core_db migration to version 54
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
  29, -- ObjectRowType::CreationDraft
  uuid,
	account_id,
	NULL,
	context
FROM creation_drafts;
DROP TABLE IF EXISTS creation_drafts;
UPDATE config
SET value = 54
WHERE name = 'version';
