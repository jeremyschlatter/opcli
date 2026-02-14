-- 1Password core_db migration to version 28
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- config_order defines the order in which keys should be served by the SSH agent
-- it is defined by the order in which keys are referenced in the SSH agent config file
CREATE TABLE IF NOT EXISTS ssh_pubkeys_new (
  item_id INTEGER PRIMARY KEY,
  config_order INTEGER NOT NULL,
  pubkey BLOB NOT NULL,
  integrity_hash BLOB NOT NULL,
  FOREIGN KEY (item_id) REFERENCES item_overviews(id) ON DELETE CASCADE
);
INSERT INTO ssh_pubkeys_new
SELECT item_id,
  0 as config_order,
  pubkey,
  integrity_hash
FROM ssh_pubkeys;
DROP TABLE IF EXISTS ssh_pubkeys;
ALTER TABLE ssh_pubkeys_new RENAME TO ssh_pubkeys;
UPDATE config
SET value = 28
WHERE name = 'version';
