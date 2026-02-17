// Package migrations defines schema migrations for the 1Password local DB.
// Migrations are applied in-memory only; the original DB is never modified.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//go:embed sql/*.sql
var sqlFiles embed.FS

// All maps version numbers to migration functions. All[v] migrates the DB
// to version v. Nil entries mean no migration exists for that version.
// Indexed by version number, so All[0] is unused.
var All []func(*sql.DB) error

func init() {
	entries, err := sqlFiles.ReadDir("sql")
	if err != nil {
		panic(fmt.Sprintf("migrations: read embedded sql dir: %v", err))
	}
	re := regexp.MustCompile(`^migration_(\d+)\.sql$`)

	// Find max version across SQL files and Go migrations.
	maxVersion := 0
	for _, e := range entries {
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			if v, _ := strconv.Atoi(m[1]); v > maxVersion {
				maxVersion = v
			}
		}
	}
	for v := range goMigrations {
		if v > maxVersion {
			maxVersion = v
		}
	}

	All = make([]func(*sql.DB) error, maxVersion+1)

	// SQL migrations.
	for _, e := range entries {
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			v, _ := strconv.Atoi(m[1])
			All[v] = sqlRunner(v)
		}
	}

	// Go migrations override SQL where both exist.
	for v, f := range goMigrations {
		All[v] = f
	}
}

func sqlRunner(version int) func(*sql.DB) error {
	return func(db *sql.DB) error {
		return runSQL(db, version)
	}
}

func runSQL(db *sql.DB, version int) error {
	data, err := sqlFiles.ReadFile(fmt.Sprintf("sql/migration_%03d.sql", version))
	if err != nil {
		return fmt.Errorf("read migration %d: %w", version, err)
	}

	// v48: strip parameterized INSERT that requires Rust-side binding.
	if version == 48 {
		re := regexp.MustCompile(`(?s)INSERT INTO objects_associated.*?VALUES\(:key_name.*?;`)
		data = re.ReplaceAll(data, nil)
	}

	// Split into individual statements.
	var statements []string
	var current []string
	for _, line := range strings.Split(string(data), "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "--") {
			continue
		}
		current = append(current, line)
		if strings.HasSuffix(stripped, ";") {
			statements = append(statements, strings.Join(current, "\n"))
			current = nil
		}
	}
	if len(current) > 0 {
		statements = append(statements, strings.Join(current, "\n"))
	}

	for _, stmt := range statements {
		// v2: the precondition SELECT fails on fresh DB (no item_overviews yet).
		if version == 2 && strings.HasPrefix(strings.TrimSpace(stmt), "SELECT id FROM item_overviews") {
			_, _ = db.Exec(stmt)
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d: exec %q: %w", version, truncate(stmt, 80), err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
