package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"

	"opcli/migrations"
)

var dbTimingEnabled = os.Getenv("OPCLI_TIMING") != ""

func logQueryTime(name string, start time.Time) {
	if dbTimingEnabled {
		fmt.Fprintf(os.Stderr, "      [sql %s: %.2fms]\n", name, float64(time.Since(start).Microseconds())/1000)
	}
}

// getDBPath returns the path to the 1Password SQLite database
func getDBPath() (string, error) {
	if p := os.Getenv("OPCLI_DB_PATH"); p != "" {
		return p, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	dbPath := filepath.Join(home,
		"Library", "Group Containers", "2BUA8C4S2C.com.1password",
		"Library", "Application Support", "1Password", "Data", "1password.sqlite")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", fmt.Errorf("1Password database not found at %s", dbPath)
	}

	return dbPath, nil
}

const (
	autoBackupDB = "OPCLI_AUTO_BACKUP_1PASSWORD_DB"
	required     = "required"
)

// openDB opens the 1Password database in read-only mode, optionally
// creating a versioned backup if OPCLI_AUTO_BACKUP_1PASSWORD_DB is set.
// If the DB has an older schema, it makes an in-memory copy of the DB
// and migrates it to the latest schema.
func openDB() (*sql.DB, error) {
	dbPath, err := getDBPath()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if v := os.Getenv(autoBackupDB); v != "" {
		if err := maybeBackupDB(db); err != nil {
			fmt.Fprintf(os.Stderr, "opcli: auto-backup of 1password db failed: %v\n", err)
			if v == required {
				db.Close()
				return nil, err
			}
		}
	}

	// Check DB version and find first applicable migration.
	version, err := getDBVersion(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	firstNeeded := -1
	for i, m := range migrations.All {
		if m.Version > version {
			firstNeeded = i
			break
		}
	}
	if firstNeeded < 0 {
		return db, nil // fast path: no migrations
	}

	// Copy to in-memory DB and apply migrations.
	t0 := time.Now()
	memDB, err := backupToMemory(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("backup to memory: %w", err)
	}
	db.Close()
	logQueryTime("backupToMemory", t0)

	for _, m := range migrations.All[firstNeeded:] {
		t0 = time.Now()
		if err := migrations.Run(memDB, m); err != nil {
			memDB.Close()
			return nil, fmt.Errorf("migration v%d: %w", m.Version, err)
		}
		logQueryTime(fmt.Sprintf("migrate:v%d", m.Version), t0)
	}

	// Drop orphaned indexes whose tables no longer exist.
	// Collect first, then drop — can't write while rows cursor holds the connection.
	{
		rows, err := memDB.Query(`
			SELECT i.name FROM sqlite_master i
			WHERE i.type='index' AND i.name NOT LIKE 'sqlite_%'
			AND NOT EXISTS (SELECT 1 FROM sqlite_master t WHERE t.type='table' AND t.name=i.tbl_name)
		`)
		if err != nil {
			memDB.Close()
			return nil, fmt.Errorf("query orphaned indexes: %w", err)
		}
		var orphaned []string
		for rows.Next() {
			var name string
			rows.Scan(&name)
			orphaned = append(orphaned, name)
		}
		rows.Close()
		for _, name := range orphaned {
			memDB.Exec(fmt.Sprintf("DROP INDEX IF EXISTS [%s]", name))
		}
	}

	return memDB, nil
}

// backupToMemory copies an open database to an in-memory database using
// SQLite's backup API, then closes the source.
func backupToMemory(src *sql.DB) (*sql.DB, error) {
	defer src.Close()
	dst, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	// In-memory databases are per-connection. If the pool opens a second
	// connection it would get a fresh, empty database. Pin to one connection.
	dst.SetMaxOpenConns(1)

	// We need raw access to both connections for the backup API.
	srcConn, err := src.Conn(context.Background())
	if err != nil {
		dst.Close()
		return nil, fmt.Errorf("get src conn: %w", err)
	}
	defer srcConn.Close()

	dstConn, err := dst.Conn(context.Background())
	if err != nil {
		dst.Close()
		return nil, fmt.Errorf("get dst conn: %w", err)
	}
	defer dstConn.Close()

	err = dstConn.Raw(func(dstRaw any) error {
		return srcConn.Raw(func(srcRaw any) error {
			dstSqlite := dstRaw.(*sqlite3.SQLiteConn)
			srcSqlite := srcRaw.(*sqlite3.SQLiteConn)

			bk, err := dstSqlite.Backup("main", srcSqlite, "main")
			if err != nil {
				return fmt.Errorf("init backup: %w", err)
			}
			defer bk.Finish()

			_, err = bk.Step(-1) // copy all pages
			if err != nil {
				return fmt.Errorf("backup step: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		dst.Close()
		return nil, err
	}

	return dst, nil
}

// getDBVersion reads the schema version from the config table.
func getDBVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow("SELECT value FROM config WHERE name = 'version'").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to read db version: %w", err)
	}
	return version, nil
}

// maybeBackupDB checks if a versioned backup exists for the current schema version,
// and creates one if not. Returns nil if a backup already existed.
func maybeBackupDB(db *sql.DB) error {
	version, err := getDBVersion(db)
	if err != nil {
		return err
	}

	dataDir, err := getDataDir()
	if err != nil {
		return err
	}

	backupDir := filepath.Join(dataDir, "versioned-db-backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return err
	}

	// Check if a backup for this version already exists
	matches, _ := filepath.Glob(filepath.Join(backupDir, fmt.Sprintf("v%d-*.sqlite3", version)))
	if len(matches) > 0 {
		return nil
	}

	date := time.Now().Format("2006-01-02")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("v%d-%s.sqlite3", version, date))

	_, err = db.Exec("VACUUM INTO ?", backupPath)
	return err
}

// AccountInfo holds basic info for account selection.
type AccountInfo struct {
	ID          int64  // internal DB id
	AccountUUID string // 1Password account UUID
	Email       string
	URL         string
	AccountType string // I=Individual, F=Family, T=Teams, B=Business
}

// getAccounts retrieves all accounts from the database.
func getAccounts(db *sql.DB) ([]AccountInfo, error) {
	t0 := time.Now()
	rows, err := db.Query(`
		SELECT id, account_uuid,
		       json_extract(data, '$.user_email'),
		       json_extract(data, '$.sign_in_url'),
		       json_extract(data, '$.account_type')
		FROM accounts
	`)
	logQueryTime("getAccounts", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts: %w", err)
	}
	defer rows.Close()

	var accounts []AccountInfo
	for rows.Next() {
		var a AccountInfo
		var email, url, accountType sql.NullString
		if err := rows.Scan(&a.ID, &a.AccountUUID, &email, &url, &accountType); err != nil {
			return nil, fmt.Errorf("failed to scan account: %w", err)
		}
		a.Email = email.String
		a.URL = url.String
		a.AccountType = accountType.String
		accounts = append(accounts, a)
	}
	return accounts, nil
}

// getAccount retrieves account data by UUID.
func getAccount(db *sql.DB, accountUUID string) (*Account, error) {
	var data []byte
	t0 := time.Now()
	err := db.QueryRow("SELECT data FROM accounts WHERE account_uuid = ?", accountUUID).Scan(&data)
	logQueryTime("getAccount", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("failed to parse account data: %w", err)
	}

	return &account, nil
}

// getAccountIDByUUID gets the internal account ID from UUID.
func getAccountIDByUUID(db *sql.DB, accountUUID string) (int64, error) {
	var id int64
	t0 := time.Now()
	err := db.QueryRow("SELECT id FROM accounts WHERE account_uuid = ?", accountUUID).Scan(&id)
	logQueryTime("getAccountIDByUUID", t0)
	if err != nil {
		return 0, fmt.Errorf("account not found: %s", accountUUID)
	}
	return id, nil
}

// getPrimaryKeyset retrieves the primary keyset (encrypted by master password) for an account.
func getPrimaryKeyset(db *sql.DB, accountID int64) (*Keyset, error) {
	var keyName string
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT key_name, data FROM objects_associated
		WHERE associated_account = ?
		AND type = 36
		AND json_extract(data, '$.encryptedBy') = 'mp'
		LIMIT 1
	`, accountID).Scan(&keyName, &data)
	logQueryTime("getPrimaryKeyset", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query primary keyset: %w", err)
	}

	var keyset Keyset
	if err := json.Unmarshal(data, &keyset); err != nil {
		return nil, fmt.Errorf("failed to parse keyset data: %w", err)
	}
	keyset.KeysetUUID = keyName

	return &keyset, nil
}

// getKeyset retrieves a keyset by UUID for an account.
func getKeyset(db *sql.DB, accountID int64, uuid string) (*Keyset, error) {
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT data FROM objects_associated
		WHERE associated_account = ? AND type = 36 AND key_name = ?
	`, accountID, uuid).Scan(&data)
	logQueryTime("getKeyset", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query keyset %s: %w", uuid, err)
	}

	var keyset Keyset
	if err := json.Unmarshal(data, &keyset); err != nil {
		return nil, fmt.Errorf("failed to parse keyset data: %w", err)
	}
	keyset.KeysetUUID = uuid

	return &keyset, nil
}

// getVaults retrieves all vaults for an account.
func getVaults(db *sql.DB, accountID int64) ([]Vault, error) {
	t0 := time.Now()
	rows, err := db.Query(`
		SELECT data FROM account_objects WHERE account_id = ? AND object_type = 'vault'
	`, accountID)
	logQueryTime("getVaults", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query vaults: %w", err)
	}
	defer rows.Close()

	var vaults []Vault
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("failed to scan vault row: %w", err)
		}

		var vault Vault
		if err := json.Unmarshal(data, &vault); err != nil {
			return nil, fmt.Errorf("failed to parse vault data: %w", err)
		}
		vaults = append(vaults, vault)
	}

	return vaults, nil
}

// getVaultByID retrieves a vault by its internal ID.
func getVaultByID(db *sql.DB, id int64) (*Vault, error) {
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT data FROM account_objects WHERE id = ? AND object_type = 'vault'
	`, id).Scan(&data)
	logQueryTime("getVaultByID", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query vault %d: %w", id, err)
	}

	var vault Vault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse vault data: %w", err)
	}

	return &vault, nil
}

// getVaultIDByUUID gets the internal vault ID from its UUID for an account.
func getVaultIDByUUID(db *sql.DB, accountID int64, vaultUUID string) (int64, error) {
	var id int64
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT id FROM account_objects
		WHERE account_id = ? AND object_type = 'vault' AND json_extract(data, '$.vault_uuid') = ?
	`, accountID, vaultUUID).Scan(&id)
	logQueryTime("getVaultIDByUUID", t0)
	if err != nil {
		return 0, fmt.Errorf("vault not found: %s", vaultUUID)
	}
	return id, nil
}

// searchItems searches for items matching the given title in the specified vault
// Returns all matching items (searches in decrypted overviews)
func getItemOverviews(db *sql.DB, vaultID int64) ([]ItemOverview, error) {
	t0 := time.Now()
	rows, err := db.Query(`
		SELECT id, uuid, vault_id, template_uuid, enc_overview
		FROM item_overviews
		WHERE vault_id = ? AND trashed = 0
	`, vaultID)
	logQueryTime("getItemOverviews", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query items: %w", err)
	}
	defer rows.Close()

	var items []ItemOverview
	for rows.Next() {
		var item ItemOverview
		var encOverview []byte
		if err := rows.Scan(&item.ID, &item.UUID, &item.VaultID, &item.TemplateUUID, &encOverview); err != nil {
			return nil, fmt.Errorf("failed to scan item row: %w", err)
		}

		if err := json.Unmarshal(encOverview, &item.EncOverview); err != nil {
			return nil, fmt.Errorf("failed to parse encrypted overview: %w", err)
		}

		items = append(items, item)
	}

	return items, nil
}

// getItemDetail retrieves the encrypted details for an item
func getItemDetail(db *sql.DB, itemID int64) (*ItemDetail, error) {
	var encDetails []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT enc_details FROM item_details WHERE id = ?
	`, itemID).Scan(&encDetails)
	logQueryTime("getItemDetail", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query item details: %w", err)
	}

	var detail ItemDetail
	detail.ID = itemID
	if err := json.Unmarshal(encDetails, &detail.EncDetails); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted details: %w", err)
	}

	return &detail, nil
}
