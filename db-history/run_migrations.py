#!/usr/bin/env python3
"""Run extracted 1Password migrations against a SQLite database.

Usage:
  # Verify: run all migrations on empty DB, compare against reference
  python run_migrations.py

  # Migrate: upgrade an existing database from its current version to v60
  python run_migrations.py path/to/database.sqlite
"""

import json
import os
import re
import sqlite3
import sys

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")
REFERENCE_DB = os.path.join(os.path.dirname(os.path.dirname(__file__)), "1password-bak.sqlite3")


def get_migration_files():
    """Return core migration files sorted by version number."""
    files = []
    for f in os.listdir(MIGRATIONS_DIR):
        m = re.match(r"migration_(\d+)\.sql", f)
        if m:
            files.append((int(m.group(1)), os.path.join(MIGRATIONS_DIR, f)))
    files.sort()
    return files


def run_migration(conn, version, path):
    """Run a single migration file."""
    sql = open(path).read()

    # v48 has parameterized VALUES(:key_name, ...) — skip that INSERT.
    # The Rust code migrated developer_activity_log data; the DROP TABLE
    # and UPDATE config still run.
    if version == 48:
        sql = re.sub(
            r"INSERT INTO objects_associated.*?VALUES\(:key_name.*?;",
            "",
            sql,
            flags=re.DOTALL,
        )

    # These versions are handled by dedicated Python functions below.
    if version in (44, 49, 53, 55, 57, 58, 60):
        return

    # Split into individual statements for better error messages.
    statements = []
    current = []
    for line in sql.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        current.append(line)
        if stripped.endswith(";"):
            statements.append("\n".join(current))
            current = []
    if current:
        # Handle missing trailing semicolon (e.g. v59)
        statements.append("\n".join(current))

    for stmt in statements:
        # v2: the precondition SELECT fails on fresh DB (no item_overviews yet).
        # Failure means "no unsynced changes" — safe to proceed.
        if version == 2 and stmt.strip().startswith("SELECT id FROM item_overviews"):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass
            continue

        conn.execute(stmt)


# ---------------------------------------------------------------------------
# Rust-only migrations, reconstructed from binary strings + symbol names.
# See rust-migrations-reconstruction.md for the full reasoning.
# ---------------------------------------------------------------------------

def _table_exists(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def migrate_v44_policies(conn):
    """account_policies → objects (type 20).

    Reconstructed from 1p-node-strings.txt lines 198675-198685.
    """
    if not _table_exists(conn, "account_policies"):
        conn.execute("UPDATE config SET value = 44 WHERE name = 'version'")
        return

    # Build account_uuid → account row id mapping
    account_map = {}
    for row in conn.execute("SELECT account_uuid, id FROM accounts").fetchall():
        account_map[row[0]] = row[1]

    rows = conn.execute(
        "SELECT account_uuid, policy_name, definition, definition_hash FROM account_policies"
    ).fetchall()

    for account_uuid, policy_name, definition, definition_hash in rows:
        account_id = account_map.get(account_uuid)
        if account_id is None:
            continue
        data = json.dumps({"policy": json.loads(definition), "definition_hash": definition_hash.hex() if isinstance(definition_hash, bytes) else definition_hash})
        key_name = f"{account_id}-{policy_name}"
        conn.execute(
            "INSERT INTO objects (key_name, type, data, associated_account, associated_item) VALUES (?, 20, ?, ?, NULL)",
            (key_name, data, account_id),
        )

    conn.execute("DROP TABLE IF EXISTS account_policies")
    conn.execute("UPDATE config SET value = 44 WHERE name = 'version'")


def migrate_v49_ssh_pubkeys(conn):
    """ssh_pubkeys → objects_associated (type 3).

    Reconstructed from 1p-node-strings.txt lines 198710-198722.
    """
    if not _table_exists(conn, "ssh_pubkeys"):
        conn.execute("UPDATE config SET value = 49 WHERE name = 'version'")
        return

    rows = conn.execute(
        "SELECT item_id, config_order, pubkey, integrity_hash FROM ssh_pubkeys"
    ).fetchall()

    # Clear any existing type-3 entries (carried over from old objects table)
    conn.execute("DELETE FROM objects_associated WHERE type = 3")

    for item_id, config_order, pubkey, integrity_hash in rows:
        lookup = conn.execute("""
            SELECT account_objects.account_id, account_objects.uuid, item_overviews.uuid
            FROM item_overviews
            INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
            WHERE item_overviews.id = ?
        """, (item_id,)).fetchone()
        if lookup is None:
            continue
        account_id, vault_uuid, item_uuid = lookup
        import base64
        data = json.dumps({
            "pubkey": base64.b64encode(pubkey).decode() if isinstance(pubkey, bytes) else pubkey,
            "configOrder": config_order,
            "integrityHash": base64.b64encode(integrity_hash).decode() if isinstance(integrity_hash, bytes) else integrity_hash,
        })
        conn.execute(
            "INSERT INTO objects_associated(key_name, type, associated_item, associated_account, data) VALUES(?, 3, ?, ?, ?)",
            (f"{vault_uuid}.{item_uuid}", item_id, account_id, data),
        )

    conn.execute("DROP TABLE IF EXISTS ssh_pubkeys")
    conn.execute("UPDATE config SET value = 49 WHERE name = 'version'")


def migrate_v53_collections(conn):
    """collection_map → objects_associated (type 28).

    Reconstructed from 1p-node-strings.txt lines 198725-198732.
    """
    if not _table_exists(conn, "collection_map"):
        conn.execute("UPDATE config SET value = 53 WHERE name = 'version'")
        return

    rows = conn.execute(
        "SELECT account_id, collection_uuid, vault_ids FROM collection_map"
    ).fetchall()

    for account_id, collection_uuid, vault_ids_blob in rows:
        # vault_ids is a blob — try JSON first, then fall back to other encodings
        try:
            vault_id_list = json.loads(vault_ids_blob)
        except (json.JSONDecodeError, TypeError):
            continue

        # Resolve vault row IDs to UUIDs
        vault_uuids = []
        for vault_id in vault_id_list:
            row = conn.execute(
                "SELECT uuid FROM account_objects WHERE id = ? AND object_type = 'vault'",
                (vault_id,),
            ).fetchone()
            if row:
                vault_uuids.append(row[0])

        data = json.dumps({"vaults": vault_uuids})
        conn.execute(
            "INSERT INTO objects_associated(type, key_name, associated_account, data, associated_item) VALUES(28, ?, ?, ?, NULL)",
            (collection_uuid, account_id, data),
        )

    conn.execute("DROP TABLE IF EXISTS collection_map")
    conn.execute("UPDATE config SET value = 53 WHERE name = 'version'")


def migrate_v55_autofill(conn):
    """autofill + kanon_autofill → objects_associated (types 31, 32).

    Reconstructed from 1p-node-strings.txt lines 198685-198710.
    Two sub-migrations: migrate_kanon (type 31) and migrate_autofill (type 32).
    """
    # --- migrate_kanon: kanon_autofill → type 31 ---
    if _table_exists(conn, "kanon_autofill"):
        rows = conn.execute(
            "SELECT item_id, account_id, data FROM kanon_autofill"
        ).fetchall()

        # Group hashes by (item_id, account_id) since the symbol shows HashMap<NewRowKey, HashSet<u16>>
        from collections import defaultdict
        grouped = defaultdict(set)
        for item_id, account_id, hash_val in rows:
            grouped[(item_id, account_id)].add(hash_val)

        for (item_id, account_id), hashes in grouped.items():
            lookup = conn.execute("""
                SELECT account_objects.uuid, item_overviews.uuid
                FROM item_overviews
                INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
                WHERE item_overviews.id = ? AND account_objects.account_id = ?
            """, (item_id, account_id)).fetchone()
            if lookup is None:
                continue
            vault_uuid, item_uuid = lookup
            data = json.dumps(sorted(hashes))
            conn.execute(
                "INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data) VALUES(31, ?, ?, ?, ?)",
                (f"{vault_uuid}.{item_uuid}", account_id, item_id, data),
            )

    # --- migrate_autofill: autofill → type 32 ---
    if _table_exists(conn, "autofill"):
        rows = conn.execute(
            "SELECT account_id, vault_id, item_id, category, autofill_data FROM autofill"
        ).fetchall()

        for account_id, vault_id, item_id, category, autofill_data in rows:
            lookup = conn.execute("""
                SELECT account_objects.uuid, item_overviews.uuid
                FROM item_overviews
                INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
                WHERE item_overviews.id = ?
                  AND item_overviews.vault_id = ?
                  AND account_objects.account_id = ?
            """, (item_id, vault_id, account_id)).fetchone()
            if lookup is None:
                continue
            vault_uuid, item_uuid = lookup
            # autofill_data is a blob, pass it through
            conn.execute(
                "INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data) VALUES(32, ?, ?, ?, ?)",
                (f"{vault_uuid}.{item_uuid}", account_id, item_id, autofill_data),
            )

    conn.execute("DROP TABLE IF EXISTS autofill")
    conn.execute("DROP TABLE IF EXISTS kanon_autofill")
    conn.execute("UPDATE config SET value = 55 WHERE name = 'version'")


def migrate_v57_categories(conn):
    """account_objects categories → objects_associated (type 33).

    Reconstructed from 1p-node-strings.txt lines 198722-198725.
    Transforms snake_case JSON to camelCase.
    """
    rows = conn.execute(
        "SELECT account_id, uuid, data FROM account_objects WHERE object_type = 'category'"
    ).fetchall()

    field_map = {
        "category_uuid": "categoryUuid",
        "changer_uuid": "changerUuid",
        "is_favorite": "isFavorite",
    }

    for account_id, uuid, data in rows:
        old = json.loads(data)
        new = {}
        for old_key, val in old.items():
            new_key = field_map.get(old_key, old_key)
            new[new_key] = val
        conn.execute(
            "INSERT INTO objects_associated(type, key_name, associated_account, data, associated_item) VALUES(33, ?, ?, ?, NULL)",
            (uuid, account_id, json.dumps(new)),
        )

    conn.execute("DELETE FROM account_objects WHERE object_type = 'category'")
    conn.execute("UPDATE config SET value = 57 WHERE name = 'version'")


def migrate_v58_editing_drafts(conn):
    """editing_drafts → objects_associated (type 30).

    Reconstructed from 1p-node-strings.txt lines 198733-198758.
    """
    if not _table_exists(conn, "editing_drafts"):
        conn.execute("UPDATE config SET value = 58 WHERE name = 'version'")
        return

    rows = conn.execute("""
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
    """).fetchall()

    for (account_id, item_id, vault_id, rejection_reason, local_edit_count,
         template_uuid, changer_uuid, created_at, enc_details, favorite,
         enc_overview, trashed, updated_at, version, context, key_name) in rows:
        import base64
        data = json.dumps({
            "itemId": item_id,
            "categoryUuid": template_uuid,
            "changerUuid": changer_uuid,
            "createdAt": created_at,
            "updatedAt": updated_at,
            "isFavorite": favorite != 0,
            "state": "trashed" if trashed else "active",
            "version": version,
            "rejectionReason": rejection_reason,
            "localEditCount": local_edit_count,
            "encOverview": base64.b64encode(enc_overview).decode() if isinstance(enc_overview, bytes) else enc_overview,
            "encDetails": base64.b64encode(enc_details).decode() if isinstance(enc_details, bytes) else enc_details,
            "context": base64.b64encode(context).decode() if isinstance(context, bytes) else context,
        })
        conn.execute(
            "INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data) VALUES(30, ?, ?, ?, ?)",
            (key_name, account_id, item_id, data),
        )

    conn.execute("DROP TABLE IF EXISTS editing_drafts")
    conn.execute("UPDATE config SET value = 58 WHERE name = 'version'")


def migrate_keysets_v60(conn):
    """Migrate keysets from account_objects to objects_associated (v60).

    Mirrors the Go implementation in migrations/60_keysets.go:
    - Reads keysets from account_objects (snake_case, JSON-string encoded)
    - Writes to objects_associated type 36 (camelCase, embedded objects)
    - UUID moves from JSON field to key_name column
    """
    field_map = {
        "enc_sym_key": "encSymKey",
        "enc_pri_key": "encPriKey",
        "pub_key": "pubKey",
        "enc_sign_key": "encSignKey",
        "pub_sign_key": "pubSignKey",
    }

    rows = conn.execute(
        "SELECT account_id, uuid, data FROM account_objects WHERE object_type = 'keyset'"
    ).fetchall()

    for account_id, uuid, data in rows:
        old = json.loads(data)
        new = {
            "sn": old["sn"],
            "encryptedBy": old["encrypted_by"],
        }
        for old_key, new_key in field_map.items():
            val = old.get(old_key)
            if val is not None:
                # Old value is a JSON string containing JSON — unwrap it
                new[new_key] = json.loads(val)

        conn.execute(
            "INSERT INTO objects_associated (key_name, type, data, associated_account) VALUES (?, 36, ?, ?)",
            (uuid, json.dumps(new), account_id),
        )

    conn.execute("DELETE FROM account_objects WHERE object_type = 'keyset'")
    conn.execute("UPDATE config SET value = 60 WHERE name = 'version'")


# Map of version → Python migration function for Rust-only migrations.
RUST_MIGRATIONS = {
    44: migrate_v44_policies,
    49: migrate_v49_ssh_pubkeys,
    53: migrate_v53_collections,
    55: migrate_v55_autofill,
    57: migrate_v57_categories,
    58: migrate_v58_editing_drafts,
    60: migrate_keysets_v60,
}


def get_schema(conn):
    """Get the schema as a dict of (type, name) -> sql."""
    rows = conn.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' "
        "ORDER BY type, name"
    ).fetchall()
    return {(r[0], r[1]): r[2] for r in rows}


def normalize_sql(sql):
    """Normalize SQL for comparison: collapse whitespace, lowercase, strip."""
    if sql is None:
        return None
    return re.sub(r"\s+", " ", sql.strip().lower())


def compare_schemas(conn):
    """Compare the schema against the reference database."""
    if not os.path.exists(REFERENCE_DB):
        print(f"\nReference DB not found at {REFERENCE_DB}, skipping schema comparison")
        return True

    ref = sqlite3.connect(f"file:{REFERENCE_DB}?mode=ro", uri=True)
    ref_schema = get_schema(ref)
    our_schema = get_schema(conn)
    ref.close()

    print(f"\nSchema comparison (reference has {len(ref_schema)} objects, we have {len(our_schema)}):")

    ok = True
    for key in sorted(set(ref_schema) | set(our_schema)):
        t, n = key
        if key not in ref_schema:
            print(f"  EXTRA {t} {n}")
            ok = False
        elif key not in our_schema:
            print(f"  MISSING {t} {n}")
            ok = False
        elif normalize_sql(ref_schema[key]) != normalize_sql(our_schema[key]):
            print(f"  DIFFERS {t} {n}")
            print(f"    ref: {ref_schema[key]}")
            print(f"    got: {our_schema[key]}")
            ok = False
        else:
            print(f"  OK {t} {n}")
    return ok


def main():
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
        print(f"Migrating {db_path}")
        conn = sqlite3.connect(db_path)
    else:
        print("Verifying migrations on empty database")
        conn = sqlite3.connect(":memory:")

    conn.execute("PRAGMA foreign_keys = ON")

    current_version = 0
    try:
        row = conn.execute("SELECT value FROM config WHERE name='version'").fetchone()
        if row:
            current_version = int(row[0])
    except sqlite3.OperationalError:
        pass
    print(f"Starting version: {current_version}")

    migrations = get_migration_files()
    # Merge SQL file versions with Rust-only versions into a single ordered sequence.
    sql_versions = {v: p for v, p in migrations}
    all_versions = sorted(set(sql_versions) | set(RUST_MIGRATIONS))
    applicable = [v for v in all_versions if v > current_version]
    print(f"Found {len(all_versions)} total migrations, {len(applicable)} to apply")

    failures = []
    for version in applicable:
        try:
            if version in sql_versions:
                run_migration(conn, version, sql_versions[version])
            if version in RUST_MIGRATIONS:
                RUST_MIGRATIONS[version](conn)
            print(f"  v{version:3d}: OK")
        except Exception as e:
            failures.append((version, e))
            print(f"  v{version:3d}: FAILED - {e}")

    # Drop orphaned indexes whose tables no longer exist
    for row in conn.execute(
        "SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    ).fetchall():
        idx_name, tbl_name = row
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (tbl_name,)
        ).fetchone()
        if not exists:
            conn.execute(f"DROP INDEX IF EXISTS [{idx_name}]")

    conn.commit()

    config_version = conn.execute("SELECT value FROM config WHERE name='version'").fetchone()[0]
    print(f"\nConfig version: {config_version}")

    schema_ok = compare_schemas(conn)

    if len(sys.argv) > 1:
        print("\nData summary:")
        for t in ['accounts', 'account_objects', 'item_overviews', 'item_details',
                   'objects_unassociated', 'objects_associated']:
            c = conn.execute(f'SELECT count(*) FROM {t}').fetchone()[0]
            print(f'  {t}: {c} rows')

    conn.close()

    if failures or not schema_ok:
        if failures:
            print(f"\n{len(failures)} migration(s) failed")
        if not schema_ok:
            print("Schema does not match reference")
        sys.exit(1)
    else:
        print("\nAll migrations passed, schema matches reference!")


if __name__ == "__main__":
    main()
