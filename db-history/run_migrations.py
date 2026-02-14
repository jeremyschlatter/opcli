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

# Tables dropped by Rust-only migrations we don't have SQL for.
# On an empty DB these are empty; on a real DB the Rust code would have
# migrated data out before dropping them. We drop them unconditionally
# since the data either doesn't exist or has been migrated to objects_associated.
RUST_DROPPED_TABLES = [
    "account_feature_flags",
    "account_policies",
    "autofill",
    "collection_map",
    "creation_drafts",
    "deleted_accounts",
    "editing_drafts",
    "feature_flags",
    "kanon_autofill",
    "resources",
    "search_weighting",
    "snippet_shortcuts",
    "ssh_pubkeys",
    "users",
    "item_usage",
]


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

    # v60 keyset migration: skip the SQL file entirely.
    # We handle this in migrate_keysets_v60() instead.
    if version == 60:
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
    # If a database path is given, migrate it; otherwise verify on empty DB
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
    applicable = [(v, p) for v, p in migrations if v > current_version]
    print(f"Found {len(migrations)} total migrations, {len(applicable)} to apply")

    failures = []
    for version, path in applicable:
        try:
            run_migration(conn, version, path)
            print(f"  v{version:3d}: OK")
        except Exception as e:
            failures.append((version, e))
            print(f"  v{version:3d}: FAILED - {e}")

    # v60 keyset migration (Python reimplementation of the Rust/Go code)
    if current_version < 60:
        try:
            migrate_keysets_v60(conn)
            print(f"  v 60: OK (keyset migration)")
        except Exception as e:
            failures.append((60, e))
            print(f"  v 60: FAILED (keyset migration) - {e}")

    # Drop tables that Rust-only migrations would have dropped
    for table in RUST_DROPPED_TABLES:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    # Drop orphaned indexes from dropped tables
    for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    ).fetchall():
        idx_name = row[0]
        # Check if the index's table still exists
        tbl = conn.execute(
            f"SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?", (idx_name,)
        ).fetchone()
        if tbl:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (tbl[0],)
            ).fetchone()
            if not exists:
                conn.execute(f"DROP INDEX IF EXISTS [{idx_name}]")

    conn.commit()

    config_version = conn.execute("SELECT value FROM config WHERE name='version'").fetchone()[0]
    print(f"\nConfig version: {config_version}")

    schema_ok = compare_schemas(conn)

    if db_path := (sys.argv[1] if len(sys.argv) > 1 else None):
        # Show data summary for migrated real DBs
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
