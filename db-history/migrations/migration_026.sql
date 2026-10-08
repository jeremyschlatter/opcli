-- 1Password core_db migration to version 26
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs
-- NOTE: Rust-based migration. Only the config update is in the binary as SQL.
-- The UPDATE below is reconstructed by comparing real v25 and v60 account rows:
-- the top-level secret_key and enc_unlock_key move into a sign_in_provider
-- object. The Rust code also handles SSO accounts ("NewSignInProviderSso"),
-- whose old format is unknown; those rows are left untouched here.

UPDATE accounts
SET data = CAST(json_remove(
	json_set(data, '$.sign_in_provider', json_object(
		'type', 'sk',
		'secret_key', json_extract(data, '$.secret_key'),
		'enc_unlock_key', json_extract(data, '$.enc_unlock_key'))),
	'$.secret_key', '$.enc_unlock_key') AS BLOB)
WHERE json_type(data, '$.secret_key') IS NOT NULL;
UPDATE config
SET value=26
WHERE name = 'version';
