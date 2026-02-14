#!/usr/bin/env python3
"""Run extracted 1Password migrations against a fresh SQLite database."""

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
    """Run a single migration file. Returns (success, error_message)."""
    sql = open(path).read()

    # v48 has parameterized VALUES(:key_name, ...) — skip that INSERT,
    # on an empty DB there's no data to migrate anyway.
    if version == 48:
        sql = re.sub(
            r"INSERT INTO objects_associated.*?VALUES\(:key_name.*?;",
            "",
            sql,
            flags=re.DOTALL,
        )

    # Split into statements. sqlite3 module's executescript commits implicitly
    # and doesn't give good error locality, so we execute one at a time.
    # We use a simple split on ';' at end of line, handling the case where
    # ';' appears inside string literals would be needed for a general parser,
    # but these migration files don't have that issue.
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
        # v2: the precondition SELECT fails on fresh DB (table doesn't exist yet).
        # Failure means "no unsynced changes" — safe to proceed.
        if version == 2 and stmt.strip().startswith("SELECT id FROM item_overviews"):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass
            continue

        conn.execute(stmt)

    return True, None


def get_schema(conn):
    """Get the schema as a sorted list of CREATE statements."""
    rows = conn.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' "
        "ORDER BY type, name"
    ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def normalize_sql(sql):
    """Normalize SQL for comparison: collapse whitespace, lowercase, strip."""
    if sql is None:
        return None
    return re.sub(r"\s+", " ", sql.strip().lower())


def main():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")

    migrations = get_migration_files()
    print(f"Found {len(migrations)} migrations")

    failures = []
    for version, path in migrations:
        try:
            run_migration(conn, version, path)
            print(f"  v{version:3d}: OK")
        except Exception as e:
            failures.append((version, e))
            print(f"  v{version:3d}: FAILED - {e}")

    # Clean up tables that Rust-only migrations (v44, v49, v53, v55, v57, v58)
    # would have dropped after migrating data out. On an empty DB there's no
    # data to migrate, so we just need the DROP statements.
    for table in [
        "account_policies",
        "autofill",
        "collection_map",
        "editing_drafts",
        "kanon_autofill",
        "ssh_pubkeys",
    ]:
        conn.execute(f"DROP TABLE IF EXISTS {table}")

    # Check final version
    config_version = conn.execute("SELECT value FROM config WHERE name='version'").fetchone()[0]
    print(f"\nConfig version: {config_version}")

    # Compare schema against reference DB
    if os.path.exists(REFERENCE_DB):
        ref = sqlite3.connect(f"file:{REFERENCE_DB}?mode=ro", uri=True)
        ref_schema = get_schema(ref)
        our_schema = get_schema(conn)
        ref.close()

        ref_by_name = {(t, n): s for t, n, s in ref_schema}
        our_by_name = {(t, n): s for t, n, s in our_schema}

        print(f"\nSchema comparison (reference has {len(ref_schema)} objects, we have {len(our_schema)}):")

        all_names = sorted(set(ref_by_name) | set(our_by_name))
        schema_ok = True
        for key in all_names:
            t, n = key
            if key not in ref_by_name:
                print(f"  EXTRA {t} {n}")
                schema_ok = False
            elif key not in our_by_name:
                print(f"  MISSING {t} {n}")
                schema_ok = False
            elif normalize_sql(ref_by_name[key]) != normalize_sql(our_by_name[key]):
                print(f"  DIFFERS {t} {n}")
                print(f"    ref: {ref_by_name[key]}")
                print(f"    got: {our_by_name[key]}")
                schema_ok = False
            else:
                print(f"  OK {t} {n}")

        if schema_ok and not failures:
            print("\nAll migrations passed, schema matches reference!")
        else:
            if failures:
                print(f"\n{len(failures)} migration(s) failed")
            if not schema_ok:
                print("Schema does not match reference")
            sys.exit(1)
    else:
        print(f"\nReference DB not found at {REFERENCE_DB}, skipping schema comparison")
        if failures:
            print(f"\n{len(failures)} migration(s) failed")
            sys.exit(1)

    conn.close()


if __name__ == "__main__":
    main()
