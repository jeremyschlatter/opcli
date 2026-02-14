-- 1Password resources_db migration to version 2
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/resources_db/db.rs

ALTER TABLE resources RENAME TO resources_old;

DROP INDEX IF EXISTS idx_resources_k_bucket_account_uuid;
DROP INDEX IF EXISTS idx_resources_name_account_uuid_is_encrypted;

CREATE TABLE resources(
	name          BLOB    NOT NULL,
	data          BLOB    NOT NULL,
	k_bucket      INTEGER NULL,
	account_uuid  INTEGER NULL,
	cache_control INTEGER NULL,
	is_encrypted  INTEGER NOT NULL,
	PRIMARY KEY (account_uuid, name) ON CONFLICT REPLACE
	CHECK (
		(is_encrypted = 0 OR is_encrypted = 1)
		AND
		(is_encrypted = 0 OR (account_uuid IS NOT NULL AND k_bucket IS NOT NULL))
	)
);

CREATE INDEX idx_resources_k_bucket_account_uuid
ON resources(k_bucket, account_uuid);

CREATE UNIQUE INDEX idx_resources_name_account_uuid_is_encrypted
ON resources(name, coalesce(account_uuid, is_encrypted));

INSERT INTO resources(name, data, k_bucket, account_uuid, cache_control, is_encrypted)
SELECT name, data, k_bucket, account_uuid, cache_control, is_encrypted FROM resources_old;

DROP TABLE IF EXISTS resources_old;

UPDATE config
SET value = 2
WHERE name = 'version';
