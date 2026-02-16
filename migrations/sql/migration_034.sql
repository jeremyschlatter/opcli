-- 1Password core_db migration to version 34
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS feature_flags_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER,
  name TEXT NOT NULL,
  data BLOB NOT NULL,
  UNIQUE (account_id, name),
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX idx_feature_flags_account_id ON feature_flags_new (account_id);
DROP TABLE IF EXISTS feature_flags;
ALTER TABLE feature_flags_new RENAME TO feature_flags;
UPDATE config
SET value = 34
WHERE name = 'version';
