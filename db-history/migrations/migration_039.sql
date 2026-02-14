-- 1Password core_db migration to version 39
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS account_feature_flags (
  account_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY (account_id, name),
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS pre_registration_feature_flags (
  name TEXT PRIMARY KEY NOT NULL,
  data BLOB NOT NULL
);
DROP INDEX IF EXISTS idx_account_feature_flags_account_id;
CREATE INDEX idx_account_feature_flags_account_id ON account_feature_flags (account_id);
DROP TABLE IF EXISTS feature_flags;
UPDATE config
SET value = 39
WHERE name = 'version';
