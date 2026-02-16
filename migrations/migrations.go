// Package migrations defines schema migrations for the 1Password local DB.
// Migrations are applied in-memory only; the original DB is never modified.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed sql/*.sql
var sqlFiles embed.FS

type Migration struct {
	Version int
	GoFunc  func(*sql.DB) error // if set, called instead of executing embedded SQL
}

// All is the ordered list of migrations (v1..v60), built at init time
// by scanning embedded SQL files and merging in Go-only migrations.
var All []Migration

func init() {
	// Scan embedded SQL files for versions.
	entries, err := sqlFiles.ReadDir("sql")
	if err != nil {
		panic(fmt.Sprintf("migrations: read embedded sql dir: %v", err))
	}
	re := regexp.MustCompile(`^migration_(\d+)\.sql$`)
	versions := map[int]bool{}
	for _, e := range entries {
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			v, _ := strconv.Atoi(m[1])
			versions[v] = true
		}
	}

	// Merge in Go-only migration versions.
	for v := range goMigrations {
		versions[v] = true
	}

	// Build sorted list.
	var sorted_ []int
	for v := range versions {
		sorted_ = append(sorted_, v)
	}
	sort.Ints(sorted_)

	All = make([]Migration, len(sorted_))
	for i, v := range sorted_ {
		All[i] = Migration{Version: v, GoFunc: goMigrations[v]}
	}
}

// Run executes a single migration against the database.
func Run(db *sql.DB, m Migration) error {
	if m.GoFunc != nil {
		return m.GoFunc(db)
	}
	return runSQL(db, m.Version)
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
