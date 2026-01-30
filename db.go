package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var dbTimingEnabled = os.Getenv("OPCLI_TIMING") != ""

func logQueryTime(name string, start time.Time) {
	if dbTimingEnabled {
		fmt.Fprintf(os.Stderr, "      [sql %s: %.2fms]\n", name, float64(time.Since(start).Microseconds())/1000)
	}
}

// testDBPath can be set by test builds to override the database path.
var testDBPath string

// getDBPath returns the path to the 1Password SQLite database
func getDBPath() (string, error) {
	if testDBPath != "" {
		return testDBPath, nil
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

// openDB opens the 1Password database in read-only mode
func openDB() (*sql.DB, error) {
	dbPath, err := getDBPath()
	if err != nil {
		return nil, err
	}

	// Open in read-only mode with WAL support
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return db, nil
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
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT data FROM account_objects
		WHERE account_id = ?
		AND object_type = 'keyset'
		AND json_extract(data, '$.encrypted_by') = 'mp'
		LIMIT 1
	`, accountID).Scan(&data)
	logQueryTime("getPrimaryKeyset", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query primary keyset: %w", err)
	}

	var keyset Keyset
	if err := json.Unmarshal(data, &keyset); err != nil {
		return nil, fmt.Errorf("failed to parse keyset data: %w", err)
	}

	return &keyset, nil
}

// getKeyset retrieves a keyset by UUID for an account.
func getKeyset(db *sql.DB, accountID int64, uuid string) (*Keyset, error) {
	var data []byte
	t0 := time.Now()
	err := db.QueryRow(`
		SELECT data FROM account_objects
		WHERE account_id = ? AND object_type = 'keyset' AND uuid = ?
	`, accountID, uuid).Scan(&data)
	logQueryTime("getKeyset", t0)
	if err != nil {
		return nil, fmt.Errorf("failed to query keyset %s: %w", uuid, err)
	}

	var keyset Keyset
	if err := json.Unmarshal(data, &keyset); err != nil {
		return nil, fmt.Errorf("failed to parse keyset data: %w", err)
	}

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

