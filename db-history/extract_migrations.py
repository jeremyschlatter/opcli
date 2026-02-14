#!/usr/bin/env python3
"""Extract individual SQL migrations from raw 1Password binary strings dump.

The raw text comes from running `strings` on index.node. This means:
- Short strings like lone ")" or ");" are lost (strings has min length 4)
- CREATE TABLE statements are missing their closing ");"
- Some lines have Rust noise concatenated with SQL

We reconstruct the missing syntax and clean noise.
"""

import re
import os


def strip_line_numbers(text):
    """Remove line number prefixes like '  198759→'."""
    return re.sub(r'^\s*\d+→', '', text, flags=re.MULTILINE)


def split_into_migrations(text):
    """Split raw text into (version, content) pairs using 'Updated DB Schema to version NNN' markers."""
    migrations = {}

    # Extract initial schema (version 1)
    # Bounded by CREATE TABLE IF NOT EXISTS accounts ... INSERT INTO config ... version 1
    v1_match = re.search(
        r'(CREATE TABLE IF NOT EXISTS accounts \(.*?INSERT INTO config \(name, value\) VALUES \("version", 1\);)',
        text, re.DOTALL
    )
    if v1_match:
        migrations[1] = v1_match.group(1)

    # Extract version 2 migration
    # It's between "INSERT INTO config ... version 1" and "Updated DB Schema to version 003"
    # but starts with noise. The SQL starts at ALTER TABLE accounts
    v2_match = re.search(
        r'INSERT INTO config \(name, value\) VALUES \("version", 1\);(.*?)Updated DB Schema to version 003',
        text, re.DOTALL
    )
    if v2_match:
        migrations[2] = v2_match.group(1)

    # Split remaining by "Updated DB Schema to version NNN" markers
    parts = re.split(r'Updated DB Schema to version (\d{3})', text)
    for i in range(1, len(parts) - 1, 2):
        version = int(parts[i])
        migrations[version] = parts[i + 1]

    return migrations


def clean_content(content):
    """Remove Rust noise from migration content, keeping only SQL."""

    # Remove source file references
    content = re.sub(r'1P:data/op-db/src/[^\s]+:\d+', '\n', content)
    content = re.sub(r'1P:data/op-db/src/[^\s]+', '\n', content)

    # Remove known noise strings (order matters - longer patterns first)
    noise = [
        r'data did not match any variant of untagged enum OldSignInProvider',
        r"ForkedSecretKeyProvider is missing 'secret_key'",
        r"not able to modify database schema because of unsynced local changes, use previous version of 1Password to sync",
        r"account_id 's data is not an object",
        r'cannot serialize new sign in provider',
        r'failed to deserialize item or template data',
        r'failed to look up item uuids',
        r'failed to migrate ssh pub key row',
        r'failed to deserialize old ssh pubkey',
        r'unable to deserialize ssh pubkey row',
        r'failed to serialize new ssh pubkey row',
        r'unable to deserialize category data',
        r'unable to deserialize category json',
        r'unable to deserialize category\b',
        r'unable to reserialize category data',
        r'unable to deserialize collection row',
        r'\.unable to deserialize kanon row',
        r'failed to serialize autofill data',
        r'failed to serialize hashes',
        r'unable to deserialize keyset',
        r'unable to serialize keyset',
        r'unable to deserialize data',
        r'failed to checkpoint wal',
        r'failed to commit',
        r'config table was malformed',
        r'invalid db schema version \'',
        r'vacuuming db for backup',
        r'vacuuming db\b',
        r'failed to vacuum db\b',
        r'op_db::core_db::db',
        r'data/op-db/src/core_db/db\.rs',
        r'NewSignInProvider',
        r'wal_checkpoint',
        r'Db::new',
    ]
    for pat in noise:
        content = re.sub(pat, '', content)

    # Remove lines that are just Rust identifiers or field names
    # (single words, possibly with colons, not SQL)
    non_sql_line = re.compile(r'^:?[a-z_][a-zA-Z_]*$', re.MULTILINE)
    content = non_sql_line.sub('', content)

    # Remove specific noise tokens that appear inline
    content = re.sub(r'\bSso\b(?!\s+)', '', content)  # lone "Sso" not part of SQL

    # Clean excessive whitespace
    content = re.sub(r'\n{3,}', '\n\n', content)

    return content.strip()


def extract_sql_lines(content):
    """From cleaned content, extract only lines that are SQL or SQL continuations."""
    lines = content.split('\n')
    result = []
    in_sql = False

    sql_starters = re.compile(
        r'^\s*(?:CREATE |ALTER |DROP |INSERT |UPDATE |DELETE |SELECT |PRAGMA |VACUUM|BEGIN |'
        r'create |alter |drop |insert |update |delete |select |--)',
        re.IGNORECASE
    )
    sql_continuation = re.compile(
        r'^\s*(?:\(|,|\'|"|AS |as |ON |SET |VALUES|UNIQUE|FOREIGN|PRIMARY|CHECK|'
        r'INNER |LEFT |LIMIT|GROUP |ORDER |HAVING|CONSTRAINT|REFERENCES|NOT |NULL|'
        r'INTEGER|TEXT|BLOB|REAL|DEFAULT|FROM |WHERE |AND |OR |CASE|WHEN |THEN |ELSE |END|'
        r'CAST)',
        re.IGNORECASE
    )

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_sql:
                result.append('')
            continue

        if sql_starters.match(stripped):
            result.append(line)
            in_sql = True
        elif in_sql and (sql_continuation.match(stripped) or line.startswith((' ', '\t'))):
            result.append(line)
        elif re.search(r'\b(?:SELECT|FROM|WHERE|JOIN|ON CONFLICT)\b', stripped, re.IGNORECASE):
            result.append(line)
            in_sql = True
        else:
            in_sql = False

    return '\n'.join(result).strip()


def count_parens(line):
    """Count net parentheses, ignoring those inside SQL comments."""
    # Strip -- comments
    code = re.sub(r'--.*$', '', line)
    return code.count('(') - code.count(')')


def add_missing_syntax(sql):
    """Fix missing parentheses lost by `strings` (which drops lines shorter than 4 chars).

    Handles:
    1. CREATE TABLE name\\n    col...  ->  CREATE TABLE name (\\n    col...\\n);
    2. INSERT INTO t (cols\\nSELECT  ->  INSERT INTO t (cols)\\nSELECT
    3. Missing closing ); on CREATE TABLE blocks
    """
    lines = sql.split('\n')
    result = []
    in_create_table = False
    in_insert = False
    paren_depth = 0
    insert_paren_depth = 0

    new_stmt = re.compile(
        r'^\s*(?:CREATE |ALTER |DROP |INSERT |UPDATE |DELETE |PRAGMA |VACUUM)',
        re.IGNORECASE
    )

    for i, line in enumerate(lines):
        stripped = line.strip()
        next_stripped = lines[i + 1].strip() if i + 1 < len(lines) else ''

        # Fix 1: CREATE TABLE without opening (
        if re.match(r'^\s*CREATE TABLE', stripped, re.IGNORECASE) and '(' not in stripped:
            result.append(line + ' (')
            in_create_table = True
            paren_depth = 1
            in_insert = False
            continue

        # Detect CREATE TABLE with ( on same line
        if re.match(r'^\s*CREATE TABLE', stripped, re.IGNORECASE):
            in_create_table = True
            paren_depth = 0
            in_insert = False

        # Track INSERT INTO for column-list paren tracking
        if re.match(r'^\s*INSERT INTO', stripped, re.IGNORECASE):
            in_insert = True
            insert_paren_depth = 0
            in_create_table = False

        # Fix 2: SELECT after INSERT INTO with unclosed parens
        if re.match(r'^\s*SELECT\b', stripped, re.IGNORECASE) and in_insert and insert_paren_depth > 0:
            # Close the unclosed parens from INSERT INTO column list
            result.append(')')
            insert_paren_depth = 0

        if in_insert:
            insert_paren_depth += count_parens(stripped)
            if 'VALUES' in stripped.upper() or stripped.endswith(';'):
                in_insert = False
            # SELECT as part of INSERT...SELECT ends the INSERT tracking
            if re.match(r'^\s*SELECT\b', stripped, re.IGNORECASE):
                in_insert = False

        if in_create_table:
            paren_depth += count_parens(stripped)

            is_last = (i + 1 >= len(lines))
            next_is_new_stmt = bool(new_stmt.match(next_stripped)) if next_stripped else False
            next_is_select = bool(re.match(r'^\s*SELECT\b', next_stripped, re.IGNORECASE))
            next_is_blank_then_stmt = False
            if not next_stripped and i + 2 < len(lines):
                after_blank = lines[i + 2].strip()
                next_is_blank_then_stmt = bool(new_stmt.match(after_blank)) or bool(
                    re.match(r'^\s*--', after_blank))

            if paren_depth > 0 and (next_is_new_stmt or next_is_select or is_last or next_is_blank_then_stmt):
                result.append(line)
                result.append(');')
                in_create_table = False
                paren_depth = 0
                continue

            if paren_depth <= 0 and stripped.endswith(';'):
                in_create_table = False

        result.append(line)

    return '\n'.join(result)


def ensure_semicolons(sql):
    """Add missing semicolons at the end of SQL statements."""
    lines = sql.split('\n')
    result = []

    stmt_start = re.compile(
        r'^\s*(?:CREATE |ALTER |DROP |INSERT |UPDATE |DELETE |PRAGMA |VACUUM)',
        re.IGNORECASE
    )
    # SELECT can start a statement OR continue an INSERT INTO...SELECT
    select_start = re.compile(r'^\s*SELECT ', re.IGNORECASE)

    # Track whether we're in an INSERT INTO that hasn't seen VALUES yet
    in_insert_without_values = False

    for i, line in enumerate(lines):
        result.append(line)
        stripped = line.strip()

        if re.match(r'^\s*INSERT INTO', stripped, re.IGNORECASE):
            in_insert_without_values = 'VALUES' not in stripped.upper()
        elif in_insert_without_values:
            if 'VALUES' in stripped.upper():
                in_insert_without_values = False
            elif select_start.match(stripped):
                in_insert_without_values = False  # It's an INSERT...SELECT

        if not stripped:
            continue

        # Look ahead for next non-blank line
        next_stmt = None
        for j in range(i + 1, min(i + 3, len(lines))):
            ns = lines[j].strip()
            if ns:
                next_stmt = ns
                break

        if not next_stmt or stripped.endswith(';') or stripped.startswith('--'):
            continue

        # Don't add ; before SELECT that continues an INSERT INTO
        if select_start.match(next_stmt) and in_insert_without_values:
            continue

        if stmt_start.match(next_stmt) or (select_start.match(next_stmt) and not in_insert_without_values):
            result[-1] = line.rstrip() + ';'

    return '\n'.join(result)


def write_migration(version, sql, outdir):
    filepath = os.path.join(outdir, f'migration_{version:03d}.sql')
    with open(filepath, 'w') as f:
        f.write(f'-- 1Password core_db migration to version {version}\n')
        f.write(f'-- Extracted from 1Password 8 binary (index.node)\n')
        f.write(f'-- Source: data/op-db/src/core_db/db.rs\n\n')
        f.write(sql)
        f.write('\n')
    return True


def main():
    raw_file = os.path.join(os.path.dirname(__file__), 'raw-core-db-migrations.txt')
    outdir = os.path.join(os.path.dirname(__file__), 'migrations')
    os.makedirs(outdir, exist_ok=True)

    with open(raw_file) as f:
        text = f.read()
    text = strip_line_numbers(text)

    migrations = split_into_migrations(text)

    written = 0
    for version in sorted(migrations.keys()):
        content = clean_content(migrations[version])
        sql = extract_sql_lines(content)
        if not sql.strip():
            print(f'  migration_{version:03d}.sql  (EMPTY - Rust-only migration)')
            continue
        sql = add_missing_syntax(sql)
        sql = ensure_semicolons(sql)
        write_migration(version, sql, outdir)
        written += 1
        print(f'  migration_{version:03d}.sql')

    print(f'\nWrote {written} migration files to {outdir}/')


if __name__ == '__main__':
    main()
