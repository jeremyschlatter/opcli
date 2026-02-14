-- 1Password core_db migration to version 29
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS feature_flags (
  account_id INT NOT NULL,
  name TEXT NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY(account_id, name)
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
-- NB: ignore migrating feature flags, they'll be refreshed at the next unlock
);
DELETE FROM objects
WHERE type = 5; -- the feature flag key type used to be serialized as 5;
UPDATE config
SET value = 29
WHERE name = 'version';
