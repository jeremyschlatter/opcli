-- 1Password core_db migration to version 40
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS activation_hub_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  uuid TEXT NOT NULL,
  name TEXT NOT NULL,
  definition BLOB NOT NULL,
  dirty INTEGER NOT NULL,
  UNIQUE (account_id, uuid, name),
  FOREIGN KEY (account_id) REFERENCES account_objects(id) ON DELETE CASCADE
);
UPDATE config
SET value = 40
WHERE name = 'version';
