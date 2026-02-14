# 1Password 8 SQLite Schema Migrations

Extracted from the 1Password 8 macOS app binary (`/Applications/1Password.app/Contents/Frameworks/index.node`).

The SQL migration statements are embedded as string literals in the Rust core library (`op-db` crate), compiled into the Node native addon. Source: `data/op-db/src/core_db/db.rs`.

## How this was extracted

1. Ran `strings` on the `index.node` Mach-O binary (822K string lines)
2. Found the migration SQL block at lines 198585–199542
3. Split by "Updated DB Schema to version NNN" markers
4. Cleaned Rust noise (source refs, error messages, variable names)
5. Reconstructed syntax lost by `strings` (closing parentheses on CREATE TABLE statements — `strings` drops lines shorter than 4 characters)
6. Manually fixed edge cases (concatenated statements, Rust-based migrations with adjacent SQL templates)

## Two databases

1Password 8 maintains two SQLite databases:

### `1password.sqlite` (core_db) — versions 1–60

The main database. Stores accounts, vaults, encrypted items, and various application state. Schema version tracked in `config` table (`name='version'`).

Files: `migrations/migration_NNN.sql`

### `1password_resources.sqlite` (resources_db) — versions 1–2

Caches resources (icons, etc). Much simpler schema.

Files: `migrations/resources_NNN.sql`

## Migration versions

### Core DB

| Version | Summary |
|---------|---------|
| 1 | Initial schema: `accounts`, `account_objects`, `vault_items`, `objects`, `config`, `item_usage` |
| 2 | Add `account_uuid` to accounts; replace `vault_items` with `item_overviews` + `item_details` |
| 3 | Recreate `item_overviews`: `rejection_reason` TEXT→INTEGER, drop `rejected_build_version` |
| 5 | Delete all vault objects (force re-sync) |
| 6 | Create `autofill` and `collection_map` tables |
| 7 | Add `validated` column to `item_overviews` |
| 8 | Clean autofill: keep only categories 001, 002, 004, 005 |
| 9 | Create `deleted_accounts` table |
| 11 | Create `kanon_autofill` table |
| 12 | Clear `kanon_autofill` data |
| 13 | Create `enc_resources` table |
| 14 | Create `drafts` table |
| 15 | Optimize autofill indexes |
| 16 | Add `cache_control` column to `enc_resources` |
| 17 | Rename `enc_resources` → `resources`, add `is_encrypted` flag |
| 18 | Convert `kanon_autofill.data` from TEXT to INTEGER |
| 19 | Add unique index on resources; clean unencrypted resources |
| 20 | Replace `drafts` with `editing_drafts` + `creation_drafts` (Rust-based data migration) |
| 21 | Create `users` table |
| 22 | Create `search_weighting` table |
| 23 | Restructure `objects` table: add `type`, `associated_item`, `associated_account` columns |
| 24 | Add `synced_at` to `item_usage` |
| 25 | Add FK cascade on `item_usage` → accounts |
| 26 | Data migration: update sign-in provider format in account data (Rust-based) |
| 27 | Create `ssh_pubkeys` table, migrate from objects |
| 28 | Add `config_order` to `ssh_pubkeys` |
| 29 | Create `feature_flags` table, migrate from objects |
| 30 | Drop `resources` table (moved to resources_db) |
| 31 | Clear autofill data |
| 32 | Create `account_policies` table |
| 33 | Simplify `account_policies`: drop `uuid`, `last_updated` columns |
| 34 | Evolve `feature_flags`: nullable `account_id`, add index |
| 35 | Create `snippet_shortcuts` table |
| 36 | Clear autofill data |
| 37 | Create `developer_activity_log` table |
| 38 | Clear autofill data |
| 39 | Split feature flags: `account_feature_flags` + `pre_registration_feature_flags` |
| 40 | Create `activation_hub_tasks` (FK to account_objects) |
| 41 | Recreate `activation_hub_tasks` (FK to accounts instead) |
| 42 | Migrate `activation_hub_tasks` into `objects` table |
| 43 | Migrate `account_feature_flags` + `pre_registration_feature_flags` back into `objects` |
| 44 | Migrate `account_policies` into `objects` (Rust-based) |
| 45 | Drop `activation_hub_tasks` |
| 46 | Split `objects` into `objects_unassociated` + `objects_associated` |
| 47 | Normalize `key_name` formats in `objects_associated` |
| 48 | Migrate `developer_activity_log` into `objects_associated` (Rust-based) |
| 49 | Migrate `ssh_pubkeys` into `objects_associated` (Rust-based) |
| 50 | Drop `deleted_accounts`, `search_weighting`, `users` |
| 51 | Migrate `snippet_shortcuts` into `objects_associated` |
| 52 | Migrate `item_usage` into `objects_associated` |
| 53 | Migrate `collection_map` into `objects_associated` (Rust-based) |
| 54 | Migrate `creation_drafts` into `objects_associated` |
| 55 | Migrate autofill data into `objects_associated` (Rust-based) |
| 56 | Delete autofill data from `objects_associated` |
| 57 | Migrate categories from `account_objects` into `objects_associated` (Rust-based) |
| 58 | Migrate `editing_drafts` into `objects_associated` (Rust-based) |
| 59 | Clear autofill data |
| 60 | Migrate keysets from `account_objects` into `objects_associated` (Rust-based) |

### Resources DB

| Version | Summary |
|---------|---------|
| 1 | Initial schema: `resources` table with auto-increment PK, `config` table |
| 2 | Remove auto-increment PK, use composite PK `(account_uuid, name)` instead |

## Architecture pattern

The dominant trend across v27–v60 is **table consolidation**: specialized tables (ssh_pubkeys, snippet_shortcuts, item_usage, collection_map, feature_flags, account_policies, developer_activity_log, etc.) are progressively migrated into the generic `objects_associated` / `objects_unassociated` key-value tables, distinguished by a `type` integer column.

### Final schema (v60)

Only 7 tables remain:
- `accounts` — account metadata (JSON blob + uuid)
- `account_objects` — vaults and other per-account objects
- `config` — key-value config (including schema version)
- `item_overviews` — encrypted item overviews (searchable metadata)
- `item_details` — encrypted item details (full content)
- `objects_associated` — generic typed KV store with account/item associations
- `objects_unassociated` — generic typed KV store without associations

## Skipped versions

- **v4, v10**: Never existed (version numbers were skipped)
- **v44, v48, v49, v53, v55, v57, v58**: Rust-based data migrations. These read from old tables, transform data in Rust code, and write to new tables. The SQL templates use parameterized queries (`:param` style). Only the DDL portions (DROP TABLE, UPDATE config) are captured; the SELECT/INSERT templates are partially captured or omitted.

## Caveats

- The SQL was extracted via `strings`, which has a minimum string length of 4 characters. This means lone `)`, `(`, and `;` characters were lost and had to be reconstructed.
- Some Rust-based migrations have SQL templates with `:param` or `?` placeholders. These are included where captured but aren't executable as-is.
- The v2 migration includes a precondition check (`SELECT id FROM item_overviews WHERE local_edit_count > 0 LIMIT 1`) that would fail on a fresh v1 database — in the real app this is wrapped in error handling.

## Files

- `1p-node-strings.txt` — Full `strings` output from index.node (822K lines)
- `raw-core-db-migrations.txt` — Raw migration block from core_db
- `raw-resources-db-migrations.txt` — Raw migration block from resources_db
- `extract_migrations.py` — Script used to parse raw text into SQL files
- `migrations/` — Individual migration SQL files
