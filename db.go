package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

	if version <= 4 {
		db.Close()
		return nil, fmt.Errorf("unsupported database version %d (need version 5 or later)", version)
	}

	if version >= len(migrations.All)-1 {
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

	for v := version + 1; v < len(migrations.All); v++ {
		if migrations.All[v] == nil {
			continue
		}
		t0 = time.Now()
		if err := migrations.All[v](memDB); err != nil {
			memDB.Close()
			return nil, fmt.Errorf("migration v%d: %w", v, err)
		}
		logQueryTime(fmt.Sprintf("migrate:v%d", v), t0)
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

// maybeBackupDB keeps two backups per schema version: the first one we ever saw,
// and the most recent one. This way when 1Password migrates the schema, we have a
// very recent capture of the previous version for diffing.
func maybeBackupDB(db *sql.DB) error {
	if os.Getenv("OPCLI_DB_PATH") != "" {
		return nil // don't back up overridden databases
	}
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

	firstPath := filepath.Join(backupDir, fmt.Sprintf("v%d-first.sqlite3", version))
	latestPath := filepath.Join(backupDir, fmt.Sprintf("v%d-latest.sqlite3", version))

	// If we've never seen this version, create the "first" backup.
	if _, err := os.Stat(firstPath); errors.Is(err, fs.ErrNotExist) {
		if _, err = db.Exec("VACUUM INTO ?", firstPath); err != nil {
			return err
		}
		return os.Chmod(firstPath, 0600)
	}

	// Otherwise, update the "latest" backup.
	// Remove first so VACUUM INTO doesn't fail on existing file.
	os.Remove(latestPath)
	if _, err = db.Exec("VACUUM INTO ?", latestPath); err != nil {
		return err
	}
	return os.Chmod(latestPath, 0600)
}

// AccountInfo holds basic info for account selection.
type AccountInfo struct {
	AccountUUID string // 1Password account UUID
	Email       string
	URL         string
	AccountType string // I=Individual, F=Family, T=Teams, B=Business
}

// getAccounts retrieves all accounts from the database.
func getAccounts(db *sql.DB) ([]AccountInfo, error) {
	t0 := time.Now()
	rows, err := db.Query(`
		SELECT account_uuid,
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
		if err := rows.Scan(&a.AccountUUID, &email, &url, &accountType); err != nil {
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

// AgileBits does not publicly document the algorithm for de-obfuscating the Secret Key.
// We lightly obfuscate our source code for it out of respect for that.
//go:generate sh -c "base64 -d < obfuscation.b64 | gunzip > obfuscation.go"

// getSecretKeyFromDB reads and deobfuscates the secret key from the database for an account.
func getSecretKeyFromDB(db *sql.DB, accountUUID string) (string, error) {
	account, err := getAccount(db, accountUUID)
	if err != nil {
		return "", err
	}
	if account.SignInProvider.SecretKey == "" {
		return "", fmt.Errorf("no secret key in database for account %s", accountUUID)
	}
	return deobfuscateSecretKey(account.SignInProvider.SecretKey)
}

// getPrimaryKeyset retrieves the primary keyset (encrypted by account password) for an account.
func getPrimaryKeyset(db *sql.DB, accountUUID string) (*Keyset, error) {
	var keyName string
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT key_name, data FROM objects_associated
		WHERE account_uuid = ?
		AND type = 36
		AND json_extract(data, '$.encryptedBy') = 'mp'
		LIMIT 1
	`, accountUUID).Scan(&keyName, &data)
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
func getKeyset(db *sql.DB, accountUUID string, uuid string) (*Keyset, error) {
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT data FROM objects_associated
		WHERE account_uuid = ? AND type = 36 AND key_name = ?
	`, accountUUID, uuid).Scan(&data)
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
func getVaults(db *sql.DB, accountUUID string) ([]Vault, error) {
	t0 := time.Now()
	rows, err := db.Query(`
		SELECT vault_uuid, data FROM vaults WHERE account_uuid = ?
	`, accountUUID)
	logQueryTime("getVaults", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query vaults: %w", err)
	}
	defer rows.Close()

	var vaults []Vault
	for rows.Next() {
		var vault Vault
		var data []byte
		if err := rows.Scan(&vault.VaultUUID, &data); err != nil {
			return nil, fmt.Errorf("failed to scan vault row: %w", err)
		}
		if err := json.Unmarshal(data, &vault); err != nil {
			return nil, fmt.Errorf("failed to parse vault data: %w", err)
		}
		vaults = append(vaults, vault)
	}

	return vaults, nil
}

// getVaultByUUID retrieves a vault by its UUID for an account.
func getVaultByUUID(db *sql.DB, accountUUID, vaultUUID string) (*Vault, error) {
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT data FROM vaults WHERE account_uuid = ? AND vault_uuid = ?
	`, accountUUID, vaultUUID).Scan(&data)
	logQueryTime("getVaultByUUID", t0)
	if err != nil {
		return nil, fmt.Errorf("vault not found: %s", vaultUUID)
	}

	var vault Vault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse vault data: %w", err)
	}
	vault.VaultUUID = vaultUUID

	return &vault, nil
}

// getItems retrieves all non-trashed items for a vault.
func getItems(db *sql.DB, accountUUID, vaultUUID string) ([]Item, error) {
	t0 := time.Now()
	rows, err := db.Query(`
		SELECT item_uuid, data FROM items
		WHERE account_uuid = ? AND vault_uuid = ?
		AND json_extract(data, '$.state') = 0
	`, accountUUID, vaultUUID)
	logQueryTime("getItems", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query items: %w", err)
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var item Item
		var data []byte
		if err := rows.Scan(&item.UUID, &data); err != nil {
			return nil, fmt.Errorf("failed to scan item row: %w", err)
		}
		item.VaultUUID = vaultUUID

		var parsed struct {
			CategoryUUID string        `json:"category_uuid"`
			Overview     EncryptedData `json:"overview"`
			Details      EncryptedData `json:"details"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse item data: %w", err)
		}
		item.TemplateUUID = parsed.CategoryUUID
		item.EncOverview = parsed.Overview
		item.EncDetails = parsed.Details

		items = append(items, item)
	}

	return items, nil
}
