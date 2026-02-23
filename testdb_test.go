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

// YAML schema for testdata/testdb.yaml
type testDBYAML struct {
	Credentials struct {
		SecretKey   string `yaml:"secret_key"`
		Password    string `yaml:"password"`
		Email       string `yaml:"email"`
		AccountUUID string `yaml:"account_uuid"`
		UserName    string `yaml:"user_name"`
		SignInURL   string `yaml:"sign_in_url"`
	} `yaml:"credentials"`
	Vaults []struct {
		Name  string `yaml:"name"`
		Type  string `yaml:"type"`
		Items []struct {
			Title  string `yaml:"title"`
			Fields []struct {
				Name  string `yaml:"name"`
				Type  string `yaml:"type"`
				Value string `yaml:"value"`
			} `yaml:"fields"`
			Sections []struct {
				Name   string `yaml:"name"`
				Title  string `yaml:"title"`
				Fields []struct {
					Name  string `yaml:"name"`
					Type  string `yaml:"type"`
					Value string `yaml:"value"`
				} `yaml:"fields"`
			} `yaml:"sections"`
		} `yaml:"items"`
	} `yaml:"vaults"`
}

// CreateTestDatabase creates a new test database with encrypted data.
// If fromV1 is true, the database starts at schema v1, has old-format keysets
// in account_objects, gets migrated through v2-v5, then has test data inserted.
// The CLI will then run migrations v6-v60 at runtime (including the v60 keyset migration).
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
	creds := spec.Credentials

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

	// Create keyset encrypted with PBES2
	symKeyJWK := createSymmetricKeyJWK(symKey, keysetUUID)
	encSymKey, err := createPBES2EncryptedData(symKeyJWK, creds.SecretKey, creds.Password, creds.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt sym key: %w", err)
	}

	rsaKeyJWK := createRSAPrivateKeyJWK(rsaKey, keysetUUID)
	encPriKey, err := createEncryptedData(rsaKeyJWK, symKey, keysetUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt RSA key: %w", err)
	}

	var accountDBID int64

	if fromV1 {
		// V1 path: real schema, old-format keyset, migrations v1-v5
		if err := migrations.All[1](db); err != nil {
			return nil, fmt.Errorf("failed to apply v1 migration: %w", err)
		}

		// Insert account without account_uuid column (v2 extracts it from JSON)
		res, err := db.Exec(`INSERT INTO accounts (data) VALUES (?)`, accountJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to insert account: %w", err)
		}
		accountDBID, _ = res.LastInsertId()

		// Insert keyset in old format: snake_case keys, JSON-string-encoded encrypted data
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
			accountDBID, keysetUUID, keysetJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to insert keyset: %w", err)
		}

		// Run migrations v2-v5
		for v := 2; v <= 5; v++ {
			if migrations.All[v] != nil {
				if err := migrations.All[v](db); err != nil {
					return nil, fmt.Errorf("setup migration v%d: %w", v, err)
				}
			}
		}

		// Leave DB at version 5 (migrations already set this)
	} else {
		// Simplified schema path (v60)
		if err := createSchema(db); err != nil {
			return nil, fmt.Errorf("failed to create schema: %w", err)
		}

		res, err := db.Exec(`INSERT INTO accounts (account_uuid, data) VALUES (?, ?)`,
			creds.AccountUUID, accountJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to insert account: %w", err)
		}
		accountDBID, _ = res.LastInsertId()

		keysetData := map[string]interface{}{
			"sn":          1,
			"encryptedBy": "mp",
			"encSymKey":   encSymKey,
			"encPriKey":   encPriKey,
		}
		keysetJSON, _ := json.Marshal(keysetData)

		_, err = db.Exec(`INSERT INTO objects_associated (key_name, type, data, associated_account) VALUES (?, 36, ?, ?)`,
			keysetUUID, keysetJSON, accountDBID)
		if err != nil {
			return nil, fmt.Errorf("failed to insert keyset: %w", err)
		}
	}

	testDB := &TestDatabase{
		Path:        dbPath,
		AccountUUID: creds.AccountUUID,
		AccountID:   accountDBID,
		SecretKey:   creds.SecretKey,
		Password:    creds.Password,
		Email:       creds.Email,
		Vaults:      make(map[string]*TestVault),
	}

	// Create vaults and items from YAML
	for _, vaultSpec := range spec.Vaults {
		vault, err := createTestVault(db, accountDBID, vaultSpec.Name, vaultSpec.Type, keysetUUID, symKey, &rsaKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault %s: %w", vaultSpec.Name, err)
		}
		testDB.Vaults[vaultSpec.Name] = vault

		for _, itemSpec := range vaultSpec.Items {
			var fields []Field
			for _, f := range itemSpec.Fields {
				fields = append(fields, Field{Name: f.Name, Type: f.Type, Value: f.Value})
			}

			var sections []Section
			for _, s := range itemSpec.Sections {
				var sectionFields []Field
				for _, f := range s.Fields {
					sectionFields = append(sectionFields, Field{T: f.Name, N: f.Name, K: f.Type, V: f.Value})
				}
				sections = append(sections, Section{Name: s.Name, Title: s.Title, Fields: sectionFields})
			}

			if err := addTestItem(db, vault, itemSpec.Title, fields, sections); err != nil {
				return nil, fmt.Errorf("failed to add item %s: %w", itemSpec.Title, err)
			}
		}
	}

	return testDB, nil
}

func createSchema(db *sql.DB) error {
	schema := `
		CREATE TABLE config (
			name TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		INSERT INTO config (name, value) VALUES ('version', '60');

		CREATE TABLE accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_uuid TEXT NOT NULL UNIQUE,
			local_version INTEGER NOT NULL DEFAULT 0,
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

		CREATE TABLE objects_associated (
			key_name TEXT NOT NULL,
			type INT NOT NULL,
			data BLOB NOT NULL,
			associated_item INT,
			associated_account INT NOT NULL,
			PRIMARY KEY (key_name, type, associated_account),
			FOREIGN KEY (associated_account) REFERENCES accounts (id) ON DELETE CASCADE
		);

		CREATE TABLE item_overviews (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL,
			vault_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0,
			template_uuid TEXT NOT NULL DEFAULT '',
			changer_uuid TEXT NOT NULL DEFAULT '',
			favorite INTEGER NOT NULL DEFAULT 0,
			trashed INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 0,
			local_edit_count INTEGER NOT NULL DEFAULT 0,
			rejection_reason INTEGER NOT NULL DEFAULT 0,
			enc_overview TEXT NOT NULL
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

func addTestItem(db *sql.DB, vault *TestVault, title string, fields []Field, sections []Section) error {
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

	res, err := db.Exec(`INSERT INTO item_overviews (uuid, vault_id, created_at, updated_at, template_uuid, changer_uuid, favorite, trashed, version, local_edit_count, rejection_reason, enc_overview) VALUES (?, ?, 0, 0, '', '', 0, 0, 0, 0, 0, ?)`,
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
