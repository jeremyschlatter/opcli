-- 1Password core_db migration to version 32
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS account_policies (
	account_uuid TEXT NOT NULL,
	uuid TEXT NOT NULL,
	policy_name TEXT NOT NULL,
	definition_hash BLOB NOT NULL,
	definition BLOB NOT NULL,
	last_updated INTEGER,
	PRIMARY KEY (account_uuid, uuid) ON CONFLICT REPLACE
	FOREIGN KEY (account_uuid) REFERENCES accounts (account_uuid) ON DELETE CASCADE
	UNIQUE (account_uuid, policy_name) ON CONFLICT REPLACE
);
UPDATE config
SET value = 32
WHERE name = 'version';
