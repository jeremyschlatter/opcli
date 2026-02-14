-- 1Password core_db migration to version 60
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs
-- NOTE: Rust-based migration. Reads keysets from account_objects,
-- converts them, and inserts into objects_associated.

-- (parameterized SELECT/INSERT queries omitted - see migration_055_autofill.rs pattern)

DELETE FROM account_objects WHERE object_type = 'keyset';

UPDATE config SET value = 60 WHERE name = 'version';
