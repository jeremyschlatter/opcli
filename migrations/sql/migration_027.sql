-- 1Password core_db migration to version 27
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS ssh_pubkeys (
  item_id INTEGER PRIMARY KEY,
  pubkey BLOB NOT NULL,
  integrity_hash BLOB NOT NULL,
  FOREIGN KEY (item_id) REFERENCES item_overviews(id) ON DELETE CASCADE
);
INSERT INTO ssh_pubkeys
SELECT
  associated_item as item_id,
  data as pubkey,
  -- Casting the string as a BLOB here
  x'' as integrity_hash
FROM objects
WHERE type = 3; -- the SSH key type used to be serialized as 3;
DELETE FROM objects
WHERE type = 3; -- the SSH key type used to be serialized as 3;
UPDATE config
SET value = 27
WHERE name = 'version';
