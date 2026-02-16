# Reconstructing the Rust-Only Migrations

## Background

The 1Password 8 desktop app stores its data in a SQLite database (`1password.sqlite`). The database schema has evolved through 60 versions. Most migrations are pure SQL, embedded as string literals in the Rust binary and executed via `rusqlite`. But some migrations (versions 44, 49, 53, 55, 57, 58) are "Rust-only" — they read data from one table, transform it in Rust code, and write it to another table.

We extracted the SQL migrations from the binary using `strings`. The Rust-only migrations were initially treated as black boxes — we knew they existed but couldn't see the logic. This document explains how we reconstructed them without decompiling any ARM64 assembly.

## Sources of Information

### 1. The `strings` dump (`1p-node-strings.txt`)

Running `strings` on the `index.node` binary (a Mach-O arm64 shared library at `/Applications/1Password.app/Contents/Frameworks/index.node`) extracts all embedded string literals. This includes:

- **SQL queries**: Every `SELECT`, `INSERT`, `DELETE`, `DROP TABLE`, and `UPDATE config` statement used by the Rust migration code. These are string literals passed to `rusqlite` calls.
- **Error messages**: Like `"unable to deserialize kanon row"`, `"failed to serialize hashes"`, `"unable to deserialize category data"`. These tell us what data transformations the code performs.
- **Source file paths**: Like `1P:data/op-db/src/core_db/migration_055_autofill.rs:202`. These confirm which file each query belongs to.
- **JSON field names**: Like `pubkey`, `configOrder`, `integrityHash`, `categoryUuid`, `changerUuid`. These are serde field names used when serializing/deserializing the JSON payloads stored in the `data` column.

The critical section is lines 198670–198758 of the strings dump. The strings appear in reverse order of the migration versions (v60 first, then v44, v55, v49, v57, v53, v58).

### 2. Symbol names from `nm`

The binary is **not stripped** — running `nm` on it yields full Rust mangled symbol names. These reveal:

- **Module names**: `op_db::core_db::migration_044_policies`, `migration_049_ssh_pubkey`, `migration_053_collections`, `migration_055_autofill`, `migration_057_categories`, `migration_058_editing_drafts`
- **Struct names**: `OldRow`, `NewRow`, `OldPolicyRow`, `OldPayload`, `NewPayload`, `NewRowKey`
- **Sub-function names**: `migrate_autofill::OldRow`, `migrate_kanon::NewRowKey` (revealing that migration 055 has two sub-migrations)
- **Type relationships**: `HashMap<NewRowKey, HashSet<u16>>` in migration_055 tells us the kanon migration deduplicates by key with sets of u16 values

### 3. The SQL migration files we already had

The SQL files for adjacent versions provide crucial context:
- **What tables exist at each version**: We can trace the schema forward from v1 and know exactly what columns each table has when a Rust migration runs
- **The pattern**: Later SQL migrations (v46, v51, v52, v54) that DO have SQL follow the exact same `SELECT...INSERT INTO objects_associated...DROP TABLE...UPDATE config` pattern, confirming this is the universal migration approach

### 4. The existing Go keyset migration (`migrations/60_keysets.go`)

We already had a working Go implementation of the v60 migration in our own codebase. This was originally written by reverse-engineering the v60 migration, and it served as a template for understanding how the other Rust migrations work. Key insight: the old format uses snake_case JSON keys with string-encoded nested JSON; the new format uses camelCase with embedded JSON objects.

## Reconstruction Details

### Migration 044: account_policies → objects (type 20)

**Binary strings evidence** (lines 198675–198685):
```
SELECT account_uuid, policy_name, definition, definition_hash FROM account_policies

INSERT INTO objects (key_name, type, data, associated_account, associated_item)
VALUES (:account_id || '-' || :policy_name, 20, :data, :account_id, NULL)

SELECT account_uuid, id FROM accounts
DROP TABLE IF EXISTS account_policies
UPDATE config SET value = 44 WHERE name = 'version'
```

**Reasoning**: The SELECT reads all policies. The second SELECT maps account_uuid to account row id (needed because `objects.associated_account` is a foreign key to `accounts.id`, but `account_policies` stores `account_uuid`). The INSERT builds a key from `account_id || '-' || policy_name` (matching the pattern used in v43's feature flag migration). Type 20 is `ObjectRowType::Policy` based on the type numbering pattern. The data payload contains `policy` (the definition) and `definition_hash`.

**Symbol evidence**: `migration_044_policies::OldPolicyRow` — a single struct, suggesting a simple row-by-row transformation.

**JSON field names**: The error string `"unable to deserialize data"` plus the parameter names `:policy_name`, `:data` suggest the data blob is `{policy: <definition blob>, definition_hash: <hash blob>}`. The field name `definition_hash` appears on the same line as the migration strings. The field name `policy` is inferred from the column name `definition` being the raw policy data.

### Migration 049: ssh_pubkeys → objects_associated (type 3)

**Binary strings evidence** (lines 198710–198722):
```
SELECT item_id, config_order, pubkey, integrity_hash FROM ssh_pubkeys

SELECT account_objects.account_id, account_objects.uuid, item_overviews.uuid
FROM item_overviews
INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
WHERE item_overviews.id = :item_id

INSERT INTO objects_associated(key_name, type, associated_item, associated_account, data)
VALUES(:key_name, 3, :associated_item, :associated_account, :data)

DELETE FROM objects_associated WHERE type = 3
DROP TABLE IF EXISTS ssh_pubkeys
UPDATE config SET value = 49 WHERE name = 'version'
```

**JSON field names**: `pubkey`, `configOrder`, `integrityHash` appear on line 198710 immediately after the UPDATE config for v55 and before the SELECT. These are the camelCase serde field names for the new JSON format.

**Key construction**: The lookup query returns `account_objects.uuid` (vault UUID) and `item_overviews.uuid` (item UUID). Following the pattern of v51 and v47, the key is `concat(vault_uuid, '.', item_uuid)`.

**The DELETE before INSERT**: `DELETE FROM objects_associated WHERE type = 3` clears any existing type-3 entries before inserting. This is because ssh_pubkeys was split out of the `objects` table in v27, but some type-3 entries might have been carried over during the v46 objects→objects_associated migration.

**Error messages**: `"failed to deserialize old ssh pubkey"`, `"failed to migrate ssh pub key row"`, `"unable to deserialize ssh pubkey row"`, `"failed to serialize new ssh pubkey row"` — confirming this is a deserialization + re-serialization migration.

### Migration 053: collection_map → objects_associated (type 28)

**Binary strings evidence** (lines 198725–198732):
```
SELECT account_id, collection_uuid, vault_ids FROM collection_map

SELECT uuid FROM account_objects
WHERE account_objects.id = :vault_id AND object_type = 'vault'

INSERT INTO objects_associated(type, key_name, associated_account, data, associated_item)
VALUES(28, :key_name, :associated_account, :data, NULL)

DROP TABLE IF EXISTS collection_map
UPDATE config SET value = 53 WHERE name = 'version'
```

**Reasoning**: The `collection_map` table stores a blob of vault IDs per collection. The migration needs to resolve each vault ID to its UUID (via the lookup query). The output data is `{vaults: [uuid1, uuid2, ...]}`. The key is the collection_uuid. `associated_item` is NULL because collections aren't item-specific.

**JSON field name**: `vaults` appears on line 198732 right after `"unable to deserialize collection row"`.

**Symbol evidence**: `migration_053_collections::OldRow` — single struct, straightforward.

### Migration 055: autofill + kanon_autofill → objects_associated (types 31, 32)

This is the most complex migration with **two sub-migrations**, confirmed by the symbol names `migrate_autofill` and `migrate_kanon`.

**migrate_kanon (type 31)** — Binary strings (lines 198685–198697):
```
SELECT item_id, account_id, data FROM kanon_autofill

SELECT account_objects.uuid, item_overviews.uuid
FROM item_overviews
INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
WHERE item_overviews.id = :item_id AND account_objects.account_id = :account_id

INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data)
VALUES(31, :key_name, :associated_account, :associated_item, :data)
```

**migrate_autofill (type 32)** — Binary strings (lines 198697–198710):
```
SELECT account_id, vault_id, item_id, category, autofill_data FROM autofill

SELECT account_objects.uuid, item_overviews.uuid
FROM item_overviews
INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
WHERE item_overviews.id = :item_id
  AND item_overviews.vault_id = :vault_id
  AND account_objects.account_id = :account_id

INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data)
VALUES(32, :key_name, :associated_account, :associated_item, :data)
```

**Cleanup**:
```
DROP TABLE IF EXISTS autofill
DROP TABLE IF EXISTS kanon_autofill
UPDATE config SET value = 55 WHERE name = 'version'
```

**Symbol evidence**: `HashMap<NewRowKey, HashSet<u16>>` tells us the kanon migration groups/deduplicates by key. The `data` column in `kanon_autofill` was originally `TEXT` (v11) but was converted to `INTEGER` in v18 (migration_018.sql explicitly does `CAST(old.data AS INTEGER)`). `HashSet<u16>` suggests these are small integer hash values being collected per item.

**Error messages**: `"failed to serialize hashes"` (for kanon) and `"failed to serialize autofill data"` (for autofill). The word "hashes" confirms the kanon data is hash-related.

**Data format inference**: For kanon, the `data` column in the old table is an integer hash value (since v18). The migration groups these by (item_id, account_id) key and stores them as a sorted list: `[h1, h2, ...]`. For autofill, the old `autofill_data` blob is passed through as-is. The `:vault_id` parameter in the autofill lookup (absent from kanon) comes from the `vault_id` column that exists in `autofill` but not in `kanon_autofill`.

### Migration 057: account_objects categories → objects_associated (type 33)

**Binary strings evidence** (lines 198722–198725):
```
SELECT account_id, uuid, data FROM account_objects WHERE object_type = 'category'

INSERT INTO objects_associated(type, key_name, associated_account, data, associated_item)
VALUES(33, :key_name, :associated_account, :data, NULL)

DELETE FROM account_objects WHERE object_type = 'category'
UPDATE config SET value = 57 WHERE name = 'version'
```

**JSON field names**: `categoryUuid`, `changerUuid`, `details`, `isFavorite`, `state` appear on line 198732 after `"unable to deserialize collection row"`. These are interspersed with other migration field names but are identified as category fields by the error messages: `"unable to deserialize category data"`, `"unable to deserialize category"`, `"unable to deserialize category json"`, `"unable to reserialize category data"`.

**Data transform**: The old `data` blob in `account_objects` uses snake_case (`category_uuid`, `changer_uuid`, `is_favorite`). The new format uses camelCase. This follows the same pattern as the v60 keyset migration.

**Symbol evidence**: `OldPayload`, `NewPayload`, `OldRow` — the Payload distinction (vs just Row) suggests a JSON deserialization + re-serialization step, not just a column copy.

**Key**: The `uuid` from `account_objects` becomes the `key_name` in `objects_associated`.

### Migration 058: editing_drafts → objects_associated (type 30)

**Binary strings evidence** (lines 198733–198758):
```
SELECT
  editing_drafts.account_id,
  editing_drafts.item_id,
  editing_drafts.vault_id,
  editing_drafts.rejection_reason,
  editing_drafts.local_edit_count,
  editing_drafts.template_uuid,
  editing_drafts.changer_uuid,
  editing_drafts.created_at,
  editing_drafts.enc_details,
  editing_drafts.favorite,
  editing_drafts.enc_overview,
  editing_drafts.trashed,
  editing_drafts.updated_at,
  editing_drafts.version,
  editing_drafts.context,
  concat(account_objects.uuid, '.', item_overviews.uuid)
FROM editing_drafts
INNER JOIN item_overviews ON item_overviews.id = editing_drafts.item_id
INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id

INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data)
VALUES(30, :key_name, :associated_account, :associated_item, :data)

DROP TABLE IF EXISTS editing_drafts
UPDATE config SET value = 58 WHERE name = 'version'
```

**JSON field names from line 198732**: `item_id`, `category_uuid`, `changer_uuid`, `details`, `is_favorite`, `state`, `context`. The `NewPayload` struct wraps the editing draft's fields into a JSON object.

**Key**: `concat(account_objects.uuid, '.', item_overviews.uuid)` — the vault.item UUID pattern used by all item-associated objects.

**Data**: The new payload bundles all the editing draft columns into a single JSON blob. The `context` field (encrypted) is included as-is.

## Confidence Assessment

**High confidence** (exact SQL known):
- All SELECT queries, INSERT statements, DROP TABLE, and UPDATE config statements are verbatim from the binary.
- Table and column names are exact.
- Object type numbers (3, 20, 28, 30, 31, 32, 33, 36) are exact.
- Key construction patterns are exact.

**Medium confidence** (inferred from field names + patterns):
- JSON payload field names for each migration. These are based on serde field names found in the strings dump, cross-referenced with column names and the snake→camel pattern established by v60.
- The exact structure of the kanon_autofill data payload (whether it's `{hashes: [...]}` or just the raw hash set).

**Low confidence / unknown**:
- Any filtering or validation the Rust code performs beyond what SQL handles (e.g., `json_valid()` checks, error handling for corrupt rows). The error messages suggest rows with bad data are skipped (`filter_map` in the symbols), but we don't know the exact conditions.
- The exact binary encoding of some blob fields (e.g., whether `vault_ids` in `collection_map` is JSON, MessagePack, or raw integers).

## Implementation Notes

Things learned while implementing the Python versions:

1. **Rust-only migrations have no SQL files.** The migration runner lists SQL files to determine which versions to run. The Rust-only versions (44, 49, 53, 55, 57, 58) have no `.sql` file, so they must be injected separately into the version sequence — they can't piggyback on the SQL file loop.

2. **v57 categories are a significant data migration on real DBs.** The v25 database had 22 categories in `account_objects`. The v57 migration moved all 22 to `objects_associated`, reducing `account_objects` from 31 rows (9 vaults + 22 categories) to 9 (vaults only). This is the only Rust migration that moved non-empty data in our v25 test case.

3. **v44 writes to `objects`, not `objects_associated`.** At v44, the `objects` table still exists (it doesn't get split into `objects_unassociated`/`objects_associated` until v46). The INSERT target is `objects`, not `objects_associated`.

4. **The v49 DELETE-then-INSERT pattern.** The migration does `DELETE FROM objects_associated WHERE type = 3` before inserting. This is because type 3 (SSH keys) existed in the old `objects` table and was carried into `objects_associated` by v46. The migration replaces those entries with properly-formatted ones from `ssh_pubkeys`.

## Practical Impact

For the v25 database we're migrating, **all source tables except categories are empty**, so most Rust migrations are pure no-ops — just `DROP TABLE` + `UPDATE config`. The v57 category migration is the exception, successfully moving 22 category objects. The reconstruction matters for correctness and for future databases that might have data in these tables.
