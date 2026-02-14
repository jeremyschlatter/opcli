// Package migrations defines schema migrations for the 1Password local DB.
// Migrations are applied in-memory only; the original DB is never modified.
package migrations

import "database/sql"

type Migration struct {
	Name           string
	NeedsMigration func(db *sql.DB) (bool, error)
	Up             func(db *sql.DB) error
	Down           func(db *sql.DB) error
}

// All is the ordered list of migrations. If migration N needs to run,
// all migrations after N are assumed to need to run as well.
var All = []Migration{
	keysets60,
}
