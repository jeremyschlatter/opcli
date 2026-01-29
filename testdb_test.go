//go:build test

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
)

// Test credentials - deterministic for reproducibility
const (
	testSecretKey = "A3-TEST01-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
	testPassword  = "test-password"
	testEmail     = "test@example.com"
	testAccountID = "test-account-uuid-1234"
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
	Path        string
	AccountUUID string
	AccountID   int64
	SecretKey   string
	Password    string
	Email       string
	Vaults      map[string]*TestVault // by vault name
}

type TestVault struct {
	UUID  string
	ID    int64
	Name  string
	Type  string // P=Personal, U=User vault
	Items map[string]*TestItem
	key   []byte // vault encryption key (for adding items)
}

type TestItem struct {
	UUID   string
	ID     int64
	Title  string
	Fields map[string]string // field name -> value
}

// CreateTestDatabase creates a new test database with encrypted data
func CreateTestDatabase(dir string) (*TestDatabase, error) {
	dbPath := filepath.Join(dir, "test.sqlite")

	// Create database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}
	defer db.Close()

	// Create schema
	if err := createSchema(db); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Generate keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	keysetUUID := "keyset-uuid-1234"

	// Create account
	accountData := map[string]interface{}{
		"account_uuid": testAccountID,
		"user_email":   testEmail,
		"user_name":    "Test User",
		"sign_in_url":  "https://test.1password.com",
	}
	accountJSON, _ := json.Marshal(accountData)

	res, err := db.Exec(`INSERT INTO accounts (account_uuid, data) VALUES (?, ?)`,
		testAccountID, accountJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to insert account: %w", err)
	}
	accountDBID, _ := res.LastInsertId()

	// Create keyset encrypted with PBES2
	symKeyJWK := createSymmetricKeyJWK(symKey, keysetUUID)
	encSymKey, err := createPBES2EncryptedData(symKeyJWK, testSecretKey, testPassword, testEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt sym key: %w", err)
	}

	rsaKeyJWK := createRSAPrivateKeyJWK(rsaKey, keysetUUID)
	encPriKey, err := createEncryptedData(rsaKeyJWK, symKey, keysetUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt RSA key: %w", err)
	}

	encSymKeyJSON, _ := json.Marshal(encSymKey)
	encPriKeyJSON, _ := json.Marshal(encPriKey)

	keysetData := map[string]interface{}{
		"keyset_uuid":  keysetUUID,
		"sn":           1,
		"encrypted_by": "mp",
		"enc_sym_key":  string(encSymKeyJSON),
		"enc_pri_key":  string(encPriKeyJSON),
	}
	keysetJSON, _ := json.Marshal(keysetData)

	_, err = db.Exec(`INSERT INTO account_objects (account_id, uuid, object_type, data) VALUES (?, ?, 'keyset', ?)`,
		accountDBID, keysetUUID, keysetJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to insert keyset: %w", err)
	}

	testDB := &TestDatabase{
		Path:        dbPath,
		AccountUUID: testAccountID,
		AccountID:   accountDBID,
		SecretKey:   testSecretKey,
		Password:    testPassword,
		Email:       testEmail,
		Vaults:      make(map[string]*TestVault),
	}

	// Create "Private" vault (type P for personal vault on Family account)
	privateVault, err := createTestVault(db, accountDBID, "Private", "P", keysetUUID, symKey, &rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Private vault: %w", err)
	}
	testDB.Vaults["Private"] = privateVault

	// Create "Work" vault (type U for regular user vault)
	workVault, err := createTestVault(db, accountDBID, "Work", "U", keysetUUID, symKey, &rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Work vault: %w", err)
	}
	testDB.Vaults["Work"] = workVault

	// Add test items to Private vault
	if err := addTestItems(db, privateVault); err != nil {
		return nil, fmt.Errorf("failed to add test items: %w", err)
	}

	return testDB, nil
}

func createSchema(db *sql.DB) error {
	schema := `
		CREATE TABLE accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_uuid TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL
		);

		CREATE TABLE account_objects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER NOT NULL,
			uuid TEXT NOT NULL,
			object_type TEXT NOT NULL,
			data TEXT NOT NULL,
			FOREIGN KEY (account_id) REFERENCES accounts(id)
		);

		CREATE TABLE item_overviews (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL,
			vault_id INTEGER NOT NULL,
			template_uuid TEXT,
			enc_overview TEXT NOT NULL,
			trashed INTEGER DEFAULT 0
		);

		CREATE TABLE item_details (
			id INTEGER PRIMARY KEY,
			enc_details TEXT NOT NULL
		);
	`
	_, err := db.Exec(schema)
	return err
}

func createTestVault(db *sql.DB, accountID int64, name, vaultType, keysetUUID string, symKey []byte, rsaPub *rsa.PublicKey) (*TestVault, error) {
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

	encVaultKeyJSON, _ := json.Marshal(encVaultKey)
	encAttrsJSON, _ := json.Marshal(encAttrs)

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
		UUID:  vaultUUID,
		ID:    vaultDBID,
		Name:  name,
		Type:  vaultType,
		Items: make(map[string]*TestItem),
		key:   vaultKey,
	}, nil
}

func addTestItems(db *sql.DB, vault *TestVault) error {
	// Test Login item
	loginFields := []Field{
		{Name: "username", Type: "string", Value: "testuser"},
		{Name: "password", Type: "concealed", Value: "secret123"},
	}
	if err := addTestItem(db, vault, "Test Login", loginFields); err != nil {
		return err
	}

	// Test API Key item
	apiFields := []Field{
		{Name: "credential", Type: "concealed", Value: "api-key-12345"},
	}
	if err := addTestItem(db, vault, "Test API Key", apiFields); err != nil {
		return err
	}

	// Test item with sections
	sectionedFields := []Field{
		{Name: "notes", Type: "string", Value: "top level note"},
	}
	sections := []Section{
		{
			Name:  "server",
			Title: "Server Details",
			Fields: []Field{
				{T: "hostname", N: "hostname", K: "string", V: "example.com"},
				{T: "port", N: "port", K: "string", V: "8080"},
			},
		},
	}
	if err := addTestItemWithSections(db, vault, "Test Sectioned", sectionedFields, sections); err != nil {
		return err
	}

	// Test item with empty field value
	emptyFields := []Field{
		{Name: "empty", Type: "string", Value: ""},
	}
	if err := addTestItem(db, vault, "Test Empty", emptyFields); err != nil {
		return err
	}

	return nil
}

func addTestItem(db *sql.DB, vault *TestVault, title string, fields []Field) error {
	return addTestItemWithSections(db, vault, title, fields, nil)
}

func addTestItemWithSections(db *sql.DB, vault *TestVault, title string, fields []Field, sections []Section) error {
	itemUUID := fmt.Sprintf("item-%s-uuid", title)

	// Create overview
	overview := DecryptedOverview{Title: title}
	overviewJSON, _ := json.Marshal(overview)
	encOverview, err := createEncryptedData(overviewJSON, vault.key, vault.UUID)
	if err != nil {
		return err
	}

	// Create details
	details := DecryptedItem{
		ItemUUID: itemUUID,
		Fields:   fields,
		Sections: sections,
	}
	detailsJSON, _ := json.Marshal(details)
	encDetails, err := createEncryptedData(detailsJSON, vault.key, vault.UUID)
	if err != nil {
		return err
	}

	encOverviewJSON, _ := json.Marshal(encOverview)
	encDetailsJSON, _ := json.Marshal(encDetails)

	res, err := db.Exec(`INSERT INTO item_overviews (uuid, vault_id, template_uuid, enc_overview) VALUES (?, ?, '', ?)`,
		itemUUID, vault.ID, encOverviewJSON)
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
		ID:     itemDBID,
		Title:  title,
		Fields: make(map[string]string),
	}
	for _, f := range fields {
		vault.Items[title].Fields[f.Name] = f.Value
	}

	return nil
}

// Cleanup removes the test database
func (t *TestDatabase) Cleanup() {
	os.Remove(t.Path)
}
