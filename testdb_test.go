package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"opcli/migrations"

	"gopkg.in/yaml.v3"
)

// base64URLEncode encodes bytes to base64url without padding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// encryptAESGCM encrypts data using AES-256-GCM
func encryptAESGCM(plaintext, key []byte) (iv, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	iv = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, iv, plaintext, nil)
	return iv, ciphertext, nil
}

// createEncryptedData creates an EncryptedData structure
func createEncryptedData(plaintext, key []byte, kid string) (*EncryptedData, error) {
	iv, ciphertext, err := encryptAESGCM(plaintext, key)
	if err != nil {
		return nil, err
	}

	return &EncryptedData{
		Enc:  "A256GCM",
		Kid:  kid,
		IV:   base64URLEncode(iv),
		Data: base64URLEncode(ciphertext),
	}, nil
}

// createPBES2EncryptedData creates a PBES2 encrypted structure (for keyset sym key)
func createPBES2EncryptedData(plaintext []byte, secretKey, password, email string) (*EncryptedData, error) {
	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	iterations := 100000
	algorithm := "PBES2g-HS256"

	// Derive key using 2SKD (same as production)
	key, err := compute2SKD(secretKey, password, email, salt, iterations, algorithm)
	if err != nil {
		return nil, err
	}

	iv, ciphertext, err := encryptAESGCM(plaintext, key)
	if err != nil {
		return nil, err
	}

	return &EncryptedData{
		Alg:  algorithm,
		Enc:  "A256GCM",
		P2c:  iterations,
		P2s:  base64URLEncode(salt),
		IV:   base64URLEncode(iv),
		Data: base64URLEncode(ciphertext),
	}, nil
}

// rsaEncryptOAEP encrypts data using RSA-OAEP with SHA1
func rsaEncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plaintext, nil)
}

// createSymmetricKeyJWK creates a JWK for a symmetric key
func createSymmetricKeyJWK(key []byte, kid string) []byte {
	jwk := JWK{
		Kty: "oct",
		Kid: kid,
		K:   base64URLEncode(key),
	}
	data, _ := json.Marshal(jwk)
	return data
}

// createRSAPrivateKeyJWK creates a JWK for an RSA private key
func createRSAPrivateKeyJWK(key *rsa.PrivateKey, kid string) []byte {
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		N:   base64URLEncode(key.N.Bytes()),
		E:   base64URLEncode([]byte{0x01, 0x00, 0x01}), // 65537
		D:   base64URLEncode(key.D.Bytes()),
		P:   base64URLEncode(key.Primes[0].Bytes()),
		Q:   base64URLEncode(key.Primes[1].Bytes()),
		Dp:  base64URLEncode(key.Precomputed.Dp.Bytes()),
		Dq:  base64URLEncode(key.Precomputed.Dq.Bytes()),
		Qi:  base64URLEncode(key.Precomputed.Qinv.Bytes()),
	}
	data, _ := json.Marshal(jwk)
	return data
}

// TestDatabase holds all the components needed for a test database
type TestDatabase struct {
	Path     string
	Accounts []*TestAccount

	// Shorthand for Accounts[0] fields (backward compat with existing tests)
	AccountUUID string
	SecretKey   string
	Password    string
	Email       string
	Vaults      map[string]*TestVault // by vault name
}

type TestAccount struct {
	UUID      string
	SecretKey string
	Password  string
	Email     string
	Shorthand string
	URL       string
	Vaults    map[string]*TestVault
}

type TestVault struct {
	UUID   string
	Name   string
	Type   string // P=Personal, U=User vault
	Items  map[string]*TestItem
	key    []byte // vault encryption key (for adding items)
	v5DBID int64  // only used in fromV1 path for old-schema item inserts
}

type TestItem struct {
	UUID   string
	Title  string
	Fields map[string]string // field name -> value
}

// YAML schema for testdata/testdb.yaml
type testDBYAML struct {
	Accounts []testDBAccountYAML `yaml:"accounts"`
}

type testDBAccountYAML struct {
	Credentials struct {
		SecretKey   string `yaml:"secret_key"`
		Password    string `yaml:"password"`
		Email       string `yaml:"email"`
		AccountUUID string `yaml:"account_uuid"`
		Shorthand   string `yaml:"shorthand"`
		UserName    string `yaml:"user_name"`
		SignInURL   string `yaml:"sign_in_url"`
	} `yaml:"credentials"`
	Vaults []struct {
		Name  string `yaml:"name"`
		Type  string `yaml:"type"`
		Items []testDBItemYAML `yaml:"items"`
	} `yaml:"vaults"`
}

type testDBItemYAML struct {
	Title      string `yaml:"title"`
	DetailsJSON string `yaml:"details_json"` // raw JSON for item details (overrides fields/sections)
	Fields []struct {
		Name  string `yaml:"name"`
		Type  string `yaml:"type"`
		Value any    `yaml:"value"`
	} `yaml:"fields"`
	Sections []struct {
		Name   string `yaml:"name"`
		Title  string `yaml:"title"`
		Fields []struct {
			Name  string `yaml:"name"`
			Type  string `yaml:"type"`
			Value any    `yaml:"value"`
		} `yaml:"fields"`
	} `yaml:"sections"`
}

// testAccountKeys holds the generated key material for a test account.
type testAccountKeys struct {
	rsaKey     *rsa.PrivateKey
	symKey     []byte
	keysetUUID string
}

// insertAccountAndKeyset inserts the account record and keyset into the DB.
// Vault/item creation must happen separately (after migrations for fromV1).
func insertAccountAndKeyset(db *sql.DB, acctSpec testDBAccountYAML, fromV1 bool, v1AccountID int64) (*TestAccount, *testAccountKeys, error) {
	creds := acctSpec.Credentials
	keysetUUID := fmt.Sprintf("keyset-%s", creds.AccountUUID)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	accountJSON, _ := json.Marshal(map[string]interface{}{
		"account_uuid": creds.AccountUUID,
		"user_email":   creds.Email,
		"user_name":    creds.UserName,
		"sign_in_url":  creds.SignInURL,
		"sign_in_provider": map[string]interface{}{
			"type":       "sk",
			"secret_key": obfuscateSecretKey(creds.SecretKey),
		},
	})

	symKeyJWK := createSymmetricKeyJWK(symKey, keysetUUID)
	encSymKey, err := createPBES2EncryptedData(symKeyJWK, creds.SecretKey, creds.Password, creds.Email)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt sym key: %w", err)
	}
	rsaKeyJWK := createRSAPrivateKeyJWK(rsaKey, keysetUUID)
	encPriKey, err := createEncryptedData(rsaKeyJWK, symKey, keysetUUID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt RSA key: %w", err)
	}

	if fromV1 {
		_, err := db.Exec(`INSERT INTO accounts (data) VALUES (?)`, accountJSON)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to insert account: %w", err)
		}

		encSymKeyJSON, _ := json.Marshal(encSymKey)
		encPriKeyJSON, _ := json.Marshal(encPriKey)
		keysetData := map[string]interface{}{
			"sn":           1,
			"encrypted_by": "mp",
			"enc_sym_key":  string(encSymKeyJSON),
			"enc_pri_key":  string(encPriKeyJSON),
		}
		keysetJSON, _ := json.Marshal(keysetData)
		_, err = db.Exec(`INSERT INTO account_objects (account_id, uuid, object_type, data) VALUES (?, ?, 'keyset', ?)`,
			v1AccountID, keysetUUID, keysetJSON)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to insert keyset: %w", err)
		}
	} else {
		_, err := db.Exec(`INSERT INTO accounts (account_uuid, data) VALUES (?, ?)`,
			creds.AccountUUID, accountJSON)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to insert account: %w", err)
		}

		keysetData := map[string]interface{}{
			"sn":          1,
			"encryptedBy": "mp",
			"encSymKey":   encSymKey,
			"encPriKey":   encPriKey,
		}
		keysetJSON, _ := json.Marshal(keysetData)
		_, err = db.Exec(`INSERT INTO objects_associated (type, account_uuid, key_name, data) VALUES (36, ?, ?, ?)`,
			creds.AccountUUID, keysetUUID, keysetJSON)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to insert keyset: %w", err)
		}
	}

	testAcct := &TestAccount{
		UUID:      creds.AccountUUID,
		SecretKey: creds.SecretKey,
		Password:  creds.Password,
		Email:     creds.Email,
		Shorthand: creds.Shorthand,
		URL:       creds.SignInURL,
		Vaults:    make(map[string]*TestVault),
	}

	return testAcct, &testAccountKeys{rsaKey: rsaKey, symKey: symKey, keysetUUID: keysetUUID}, nil
}

// createVaultsAndItems creates vaults and items for a test account.
// Must be called after migrations for fromV1.
func createVaultsAndItems(db *sql.DB, acct *TestAccount, keys *testAccountKeys, acctSpec testDBAccountYAML, fromV1 bool, v1AccountID int64) error {
	for _, vaultSpec := range acctSpec.Vaults {
		var vault *TestVault
		var err error
		if fromV1 {
			vault, err = createTestVaultV5(db, v1AccountID, vaultSpec.Name, vaultSpec.Type, keys.keysetUUID, keys.symKey, &keys.rsaKey.PublicKey)
		} else {
			vault, err = createTestVault(db, acct.UUID, vaultSpec.Name, vaultSpec.Type, keys.keysetUUID, keys.symKey, &keys.rsaKey.PublicKey)
		}
		if err != nil {
			return fmt.Errorf("failed to create vault %s: %w", vaultSpec.Name, err)
		}
		acct.Vaults[vaultSpec.Name] = vault

		for _, itemSpec := range vaultSpec.Items {
			var detailsJSON []byte
			if itemSpec.DetailsJSON != "" {
				detailsJSON = []byte(itemSpec.DetailsJSON)
			} else {
				var fields []Field
				for _, f := range itemSpec.Fields {
					fields = append(fields, Field{Name: f.Name, Type: f.Type, Value: fmt.Sprintf("%v", f.Value)})
				}
				var sections []Section
				for _, s := range itemSpec.Sections {
					var sectionFields []Field
					for _, f := range s.Fields {
						v, _ := json.Marshal(f.Value)
						sectionFields = append(sectionFields, Field{T: f.Name, N: f.Name, K: f.Type, V: v})
					}
					sections = append(sections, Section{Name: s.Name, Title: s.Title, Fields: sectionFields})
				}
				details := DecryptedItem{
					ItemUUID: fmt.Sprintf("item-%s-uuid", itemSpec.Title),
					Fields:   fields,
					Sections: sections,
				}
				detailsJSON, _ = json.Marshal(details)
			}
			if fromV1 {
				err = addTestItemV5(db, vault, itemSpec.Title, detailsJSON)
			} else {
				err = addTestItem(db, acct.UUID, vault, itemSpec.Title, detailsJSON)
			}
			if err != nil {
				return fmt.Errorf("failed to add item %s: %w", itemSpec.Title, err)
			}
		}
	}
	return nil
}

// CreateTestDatabase creates a new test database with encrypted data.
// If fromV1 is true, the database starts at schema v1, has old-format keysets
// in account_objects, gets migrated through v2-v5, then has test data inserted.
// The CLI under test will then need to run all remaining migrations itself.
func CreateTestDatabase(dir string, fromV1 bool) (*TestDatabase, error) {
	// Read and parse YAML
	yamlData, err := os.ReadFile("testdata/testdb.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read testdb.yaml: %w", err)
	}
	var spec testDBYAML
	if err := yaml.Unmarshal(yamlData, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse testdb.yaml: %w", err)
	}

	dbPath := filepath.Join(dir, "test.sqlite")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}
	defer db.Close()

	if fromV1 {
		if err := migrations.All[1](db); err != nil {
			return nil, fmt.Errorf("failed to apply v1 migration: %w", err)
		}
	} else {
		if err := createSchema(db); err != nil {
			return nil, fmt.Errorf("failed to create schema: %w", err)
		}
	}

	testDB := &TestDatabase{
		Path: dbPath,
	}

	// Phase 1: Insert accounts and keysets (before migrations for fromV1)
	type accountSetup struct {
		acct *TestAccount
		keys *testAccountKeys
		spec testDBAccountYAML
	}
	var setups []accountSetup
	for i, acctSpec := range spec.Accounts {
		acct, keys, err := insertAccountAndKeyset(db, acctSpec, fromV1, int64(i+1))
		if err != nil {
			return nil, fmt.Errorf("failed to create account %s: %w", acctSpec.Credentials.AccountUUID, err)
		}
		setups = append(setups, accountSetup{acct, keys, acctSpec})
		testDB.Accounts = append(testDB.Accounts, acct)
	}

	if fromV1 {
		// Run migrations v2-v5 (creates item_overviews, etc.)
		for v := 2; v <= 5; v++ {
			if migrations.All[v] != nil {
				if err := migrations.All[v](db); err != nil {
					return nil, fmt.Errorf("setup migration v%d: %w", v, err)
				}
			}
		}
	}

	// Phase 2: Create vaults and items (after migrations for fromV1)
	for i, s := range setups {
		if err := createVaultsAndItems(db, s.acct, s.keys, s.spec, fromV1, int64(i+1)); err != nil {
			return nil, fmt.Errorf("failed to create vaults for account %s: %w", s.acct.UUID, err)
		}
	}

	// Populate shorthand fields from first account
	first := testDB.Accounts[0]
	testDB.AccountUUID = first.UUID
	testDB.SecretKey = first.SecretKey
	testDB.Password = first.Password
	testDB.Email = first.Email
	testDB.Vaults = first.Vaults

	return testDB, nil
}

func createSchema(db *sql.DB) error {
	schema := `
		CREATE TABLE config (
			name TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		INSERT INTO config (name, value) VALUES ('version', '61');

		CREATE TABLE accounts (
			account_uuid TEXT PRIMARY KEY NOT NULL,
			data BLOB NOT NULL
		);

		CREATE TABLE vaults (
			account_uuid TEXT NOT NULL,
			vault_uuid TEXT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (account_uuid, vault_uuid),
			FOREIGN KEY (account_uuid) REFERENCES accounts(account_uuid) ON DELETE CASCADE
		);

		CREATE TABLE items (
			account_uuid TEXT NOT NULL,
			vault_uuid TEXT NOT NULL,
			item_uuid TEXT NOT NULL,
			local_edit_count INTEGER NOT NULL,
			rejection_reason INTEGER NOT NULL,
			version INTEGER NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (account_uuid, vault_uuid, item_uuid),
			FOREIGN KEY (account_uuid, vault_uuid) REFERENCES vaults(account_uuid, vault_uuid) ON DELETE CASCADE
		);

		CREATE TABLE objects_associated (
			type INT NOT NULL,
			account_uuid TEXT NOT NULL,
			key_name TEXT NOT NULL,
			data BLOB NOT NULL,
			vault_uuid TEXT,
			item_uuid TEXT,
			PRIMARY KEY (type, account_uuid, key_name),
			FOREIGN KEY (account_uuid) REFERENCES accounts(account_uuid) ON DELETE CASCADE
		);

		CREATE TABLE objects_unassociated (
			key_name TEXT NOT NULL,
			type INT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (key_name, type)
		);
	`
	_, err := db.Exec(schema)
	return err
}

func createTestVault(db *sql.DB, accountUUID, name, vaultType, keysetUUID string, symKey []byte, rsaPub *rsa.PublicKey) (*TestVault, error) {
	vaultUUID := fmt.Sprintf("vault-%s-uuid", name)

	// Generate vault key
	vaultKey := make([]byte, 32)
	if _, err := rand.Read(vaultKey); err != nil {
		return nil, err
	}

	// Encrypt vault key with RSA
	vaultKeyJWK := createSymmetricKeyJWK(vaultKey, vaultUUID)
	encVaultKeyData, err := rsaEncryptOAEP(rsaPub, vaultKeyJWK)
	if err != nil {
		return nil, err
	}
	encVaultKey := &EncryptedData{
		Enc:  "RSA-OAEP",
		Kid:  keysetUUID,
		Data: base64URLEncode(encVaultKeyData),
	}

	// Encrypt vault attributes
	vaultAttrs := map[string]interface{}{"name": name}
	vaultAttrsJSON, _ := json.Marshal(vaultAttrs)
	encAttrs, err := createEncryptedData(vaultAttrsJSON, vaultKey, vaultUUID)
	if err != nil {
		return nil, err
	}

	// v61 format: embedded objects, no vault_uuid in JSON
	vaultData := map[string]interface{}{
		"vault_type":    vaultType,
		"enc_vault_key": encVaultKey,
		"enc_attrs":     encAttrs,
	}
	vaultJSON, _ := json.Marshal(vaultData)

	_, err = db.Exec(`INSERT INTO vaults (account_uuid, vault_uuid, data) VALUES (?, ?, ?)`,
		accountUUID, vaultUUID, vaultJSON)
	if err != nil {
		return nil, err
	}

	return &TestVault{
		UUID:  vaultUUID,
		Name:  name,
		Type:  vaultType,
		Items: make(map[string]*TestItem),
		key:   vaultKey,
	}, nil
}

func addTestItem(db *sql.DB, accountUUID string, vault *TestVault, title string, detailsJSON []byte) error {
	itemUUID := fmt.Sprintf("item-%s-uuid", title)

	// Create overview
	overview := DecryptedOverview{Title: title}
	overviewJSON, _ := json.Marshal(overview)
	encOverview, err := createEncryptedData(overviewJSON, vault.key, vault.UUID)
	if err != nil {
		return err
	}

	encDetails, err := createEncryptedData(detailsJSON, vault.key, vault.UUID)
	if err != nil {
		return err
	}

	// v61 format: single data blob with overview + details
	itemData := map[string]interface{}{
		"category_uuid": "",
		"changer_uuid":  "",
		"created_at":    0,
		"updated_at":    0,
		"overview":      encOverview,
		"details":       encDetails,
		"is_favorite":   false,
		"state":         0,
		"validated":     false,
	}
	itemDataJSON, _ := json.Marshal(itemData)

	_, err = db.Exec(
		`INSERT INTO items (account_uuid, vault_uuid, item_uuid, local_edit_count, rejection_reason, version, data) VALUES (?, ?, ?, 0, 0, 0, ?)`,
		accountUUID, vault.UUID, itemUUID, itemDataJSON)
	if err != nil {
		return err
	}

	vault.Items[title] = &TestItem{
		UUID:   itemUUID,
		Title:  title,
		Fields: make(map[string]string),
	}
	var parsed DecryptedItem
	if json.Unmarshal(detailsJSON, &parsed) == nil {
		for _, f := range parsed.Fields {
			vault.Items[title].Fields[f.Name] = f.Value
		}
	}

	return nil
}

// createTestVaultV5 creates a vault in the old v5-era schema (account_objects table, stringified encrypted data).
func createTestVaultV5(db *sql.DB, accountID int64, name, vaultType, keysetUUID string, symKey []byte, rsaPub *rsa.PublicKey) (*TestVault, error) {
	vaultUUID := fmt.Sprintf("vault-%s-uuid", name)

	vaultKey := make([]byte, 32)
	if _, err := rand.Read(vaultKey); err != nil {
		return nil, err
	}

	vaultKeyJWK := createSymmetricKeyJWK(vaultKey, vaultUUID)
	encVaultKeyData, err := rsaEncryptOAEP(rsaPub, vaultKeyJWK)
	if err != nil {
		return nil, err
	}
	encVaultKey := &EncryptedData{
		Enc:  "RSA-OAEP",
		Kid:  keysetUUID,
		Data: base64URLEncode(encVaultKeyData),
	}

	vaultAttrs := map[string]interface{}{"name": name}
	vaultAttrsJSON, _ := json.Marshal(vaultAttrs)
	encAttrs, err := createEncryptedData(vaultAttrsJSON, vaultKey, vaultUUID)
	if err != nil {
		return nil, err
	}

	encVaultKeyJSON, _ := json.Marshal(encVaultKey)
	encAttrsJSON, _ := json.Marshal(encAttrs)

	// Old format: vault_uuid in JSON, stringified encrypted data
	vaultData := map[string]interface{}{
		"vault_uuid":    vaultUUID,
		"vault_type":    vaultType,
		"enc_vault_key": string(encVaultKeyJSON),
		"enc_attrs":     string(encAttrsJSON),
	}
	vaultJSON, _ := json.Marshal(vaultData)

	res, err := db.Exec(`INSERT INTO account_objects (account_id, uuid, object_type, data) VALUES (?, ?, 'vault', ?)`,
		accountID, vaultUUID, vaultJSON)
	if err != nil {
		return nil, err
	}
	vaultDBID, _ := res.LastInsertId()

	return &TestVault{
		UUID:   vaultUUID,
		Name:   name,
		Type:   vaultType,
		Items:  make(map[string]*TestItem),
		key:    vaultKey,
		v5DBID: vaultDBID,
	}, nil
}

// addTestItemV5 adds an item in the old v5-era schema (item_overviews + item_details tables).
func addTestItemV5(db *sql.DB, vault *TestVault, title string, detailsJSON []byte) error {
	itemUUID := fmt.Sprintf("item-%s-uuid", title)

	overview := DecryptedOverview{Title: title}
	overviewJSON, _ := json.Marshal(overview)
	encOverview, err := createEncryptedData(overviewJSON, vault.key, vault.UUID)
	if err != nil {
		return err
	}

	encDetails, err := createEncryptedData(detailsJSON, vault.key, vault.UUID)
	if err != nil {
		return err
	}

	encOverviewJSON, _ := json.Marshal(encOverview)
	encDetailsJSON, _ := json.Marshal(encDetails)

	res, err := db.Exec(`INSERT INTO item_overviews (uuid, vault_id, created_at, updated_at, template_uuid, changer_uuid, favorite, trashed, version, local_edit_count, rejection_reason, enc_overview) VALUES (?, ?, 0, 0, '', '', 0, 0, 0, 0, 0, ?)`,
		itemUUID, vault.v5DBID, encOverviewJSON)
	if err != nil {
		return err
	}
	itemDBID, _ := res.LastInsertId()

	_, err = db.Exec(`INSERT INTO item_details (id, enc_details) VALUES (?, ?)`,
		itemDBID, encDetailsJSON)
	if err != nil {
		return err
	}

	vault.Items[title] = &TestItem{
		UUID:   itemUUID,
		Title:  title,
		Fields: make(map[string]string),
	}
	var parsed DecryptedItem
	if json.Unmarshal(detailsJSON, &parsed) == nil {
		for _, f := range parsed.Fields {
			vault.Items[title].Fields[f.Name] = f.Value
		}
	}
	return nil
}

// Cleanup removes the test database
func (t *TestDatabase) Cleanup() {
	os.Remove(t.Path)
}
