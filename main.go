package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "read":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: opcli read <op://vault/item/field>")
			os.Exit(1)
		}
		if err := cmdRead(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := cmdList(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "unlock":
		if err := cmdUnlock(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("opcli - Fast 1Password CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  opcli read <op://vault/item/field>  - Read a field from an item")
	fmt.Println("  opcli list                          - List all vaults")
	fmt.Println("  opcli unlock                        - Test unlock (verify credentials)")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  OP_SECRET_KEY      - Your 1Password Secret Key (A3-XXXXX-...)")
	fmt.Println("  OP_MASTER_PASSWORD - Your master password")
}

func cmdUnlock() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	account, err := getAccount(db)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Account: %s (%s)\n", account.UserEmail, account.UserName)
	db.Close()

	password, secretKey, err := getCredentials()
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Unlocking vault...")
	vk, err := newVaultKeychain(password, secretKey, account.UserEmail)
	if err != nil {
		return err
	}
	defer vk.Close()

	fmt.Fprintln(os.Stderr, "Successfully unlocked!")
	fmt.Fprintf(os.Stderr, "Primary key length: %d bytes\n", len(vk.primaryKey))
	fmt.Fprintf(os.Stderr, "RSA key size: %d bits\n", vk.primaryRSA.N.BitLen())

	return nil
}

// parseOPURI parses an op://vault/item/field URI
func parseOPURI(uri string) (vault, item, field string, err error) {
	if !strings.HasPrefix(uri, "op://") {
		return "", "", "", fmt.Errorf("invalid URI: must start with op://")
	}

	parts := strings.Split(uri[5:], "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid URI: must be op://vault/item/field")
	}

	return parts[0], parts[1], parts[2], nil
}

// getCredentials prompts for master password and secret key
func getCredentials() (password, secretKey string, err error) {
	// Check for environment variables first
	secretKey = os.Getenv("OP_SECRET_KEY")
	password = os.Getenv("OP_MASTER_PASSWORD")

	if secretKey == "" {
		fmt.Fprint(os.Stderr, "Enter Secret Key (A3-XXXXX-...): ")
		var sk string
		fmt.Scanln(&sk)
		secretKey = strings.TrimSpace(sk)
	}

	if password == "" {
		fmt.Fprint(os.Stderr, "Enter Master Password: ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		password = string(pwBytes)
	}

	return password, secretKey, nil
}

// VaultKeychain holds decrypted keys for accessing vault items
type VaultKeychain struct {
	db          *DB
	primaryKey  []byte    // Decrypted primary symmetric key
	primaryRSA  *rsa.PrivateKey // Decrypted primary RSA private key
	vaultKeys   map[string][]byte // vault UUID -> symmetric key
}

type DB struct {
	*sql.DB
}

func newVaultKeychain(password, secretKey, email string) (*VaultKeychain, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}

	vk := &VaultKeychain{
		db:        &DB{db},
		vaultKeys: make(map[string][]byte),
	}

	// Get primary keyset
	keyset, err := getPrimaryKeyset(db)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary keyset: %w", err)
	}

	// Parse the encrypted symmetric key
	var encSymKey EncryptedData
	if err := json.Unmarshal([]byte(keyset.EncSymKey), &encSymKey); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted symmetric key: %w", err)
	}

	// Decrypt the symmetric key using 2SKD
	decryptedSymKeyJSON, err := decryptPBES2(&encSymKey, secretKey, password, email)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
	}

	// Extract the actual key bytes from the JWK
	vk.primaryKey, err = extractSymmetricKey(decryptedSymKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to extract symmetric key: %w", err)
	}

	// Decrypt the RSA private key
	var encPriKey EncryptedData
	if err := json.Unmarshal([]byte(keyset.EncPriKey), &encPriKey); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted private key: %w", err)
	}

	decryptedPriKeyJSON, err := decryptEncryptedData(&encPriKey, vk.primaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	vk.primaryRSA, err = parseRSAPrivateKey(decryptedPriKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return vk, nil
}

func (vk *VaultKeychain) Close() {
	if vk.db != nil {
		vk.db.Close()
	}
}

// getVaultKey retrieves or decrypts the vault key for the given vault UUID
func (vk *VaultKeychain) getVaultKey(vaultUUID string) ([]byte, error) {
	if key, ok := vk.vaultKeys[vaultUUID]; ok {
		return key, nil
	}

	// Get vault data
	vaultID, err := getVaultIDByUUID(vk.db.DB, vaultUUID)
	if err != nil {
		return nil, err
	}

	vault, err := getVaultByID(vk.db.DB, vaultID)
	if err != nil {
		return nil, err
	}

	// Parse encrypted vault key
	var encVaultKey EncryptedData
	if err := json.Unmarshal([]byte(vault.EncVaultKey), &encVaultKey); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted vault key: %w", err)
	}

	// Vault keys are RSA-OAEP encrypted with the primary RSA key
	keyData, err := base64URLDecode(encVaultKey.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault key data: %w", err)
	}

	decryptedKeyJSON, err := rsaDecryptOAEP(vk.primaryRSA, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to RSA decrypt vault key: %w", err)
	}

	// Extract the symmetric key from JWK
	key, err := extractSymmetricKey(decryptedKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to extract vault symmetric key: %w", err)
	}

	vk.vaultKeys[vaultUUID] = key
	return key, nil
}

// decryptOverview decrypts an item overview using the vault key
func (vk *VaultKeychain) decryptOverview(vaultUUID string, encOverview *EncryptedData) (*DecryptedOverview, error) {
	key, err := vk.getVaultKey(vaultUUID)
	if err != nil {
		return nil, err
	}

	decrypted, err := decryptEncryptedData(encOverview, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt overview: %w", err)
	}

	var overview DecryptedOverview
	if err := json.Unmarshal(decrypted, &overview); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted overview: %w", err)
	}

	return &overview, nil
}

// decryptDetail decrypts item details using the vault key
func (vk *VaultKeychain) decryptDetail(vaultUUID string, encDetails *EncryptedData) (*DecryptedItem, error) {
	key, err := vk.getVaultKey(vaultUUID)
	if err != nil {
		return nil, err
	}

	decrypted, err := decryptEncryptedData(encDetails, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt details: %w", err)
	}

	var item DecryptedItem
	if err := json.Unmarshal(decrypted, &item); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted details: %w", err)
	}

	return &item, nil
}

func cmdRead(uri string) error {
	vaultName, itemName, fieldName, err := parseOPURI(uri)
	if err != nil {
		return err
	}

	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Get account info for email
	account, err := getAccount(db)
	if err != nil {
		return err
	}
	db.Close()

	// Get credentials
	password, secretKey, err := getCredentials()
	if err != nil {
		return err
	}

	// Initialize keychain
	vk, err := newVaultKeychain(password, secretKey, account.UserEmail)
	if err != nil {
		return err
	}
	defer vk.Close()

	// Find the vault
	vaults, err := getVaults(vk.db.DB)
	if err != nil {
		return err
	}

	var targetVaultUUID string
	for _, v := range vaults {
		// Decrypt vault attributes to get the name
		var encAttrs EncryptedData
		if err := json.Unmarshal([]byte(v.EncAttrs), &encAttrs); err != nil {
			continue
		}

		key, err := vk.getVaultKey(v.VaultUUID)
		if err != nil {
			continue
		}

		attrsJSON, err := decryptEncryptedData(&encAttrs, key)
		if err != nil {
			continue
		}

		var attrs struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(attrsJSON, &attrs); err != nil {
			continue
		}

		if strings.EqualFold(attrs.Name, vaultName) || v.VaultUUID == vaultName {
			targetVaultUUID = v.VaultUUID
			break
		}
	}

	if targetVaultUUID == "" {
		return fmt.Errorf("vault not found: %s", vaultName)
	}

	// Get vault ID
	vaultID, err := getVaultIDByUUID(vk.db.DB, targetVaultUUID)
	if err != nil {
		return err
	}

	// Get all items in the vault
	items, err := getItemOverviews(vk.db.DB, vaultID)
	if err != nil {
		return err
	}

	// Find matching item
	var targetItem *ItemOverview
	for i := range items {
		overview, err := vk.decryptOverview(targetVaultUUID, &items[i].EncOverview)
		if err != nil {
			continue
		}

		if strings.EqualFold(overview.Title, itemName) || items[i].UUID == itemName {
			targetItem = &items[i]
			break
		}
	}

	if targetItem == nil {
		return fmt.Errorf("item not found: %s", itemName)
	}

	// Get item details
	detail, err := getItemDetail(vk.db.DB, targetItem.ID)
	if err != nil {
		return err
	}

	// Decrypt details
	decryptedItem, err := vk.decryptDetail(targetVaultUUID, &detail.EncDetails)
	if err != nil {
		return err
	}

	// Find the field
	fieldLower := strings.ToLower(fieldName)

	// Check top-level fields
	for _, f := range decryptedItem.Fields {
		name := strings.ToLower(f.Name)
		id := strings.ToLower(f.ID)
		if name == fieldLower || id == fieldLower {
			fmt.Println(f.Value)
			return nil
		}
		// Also check designation
		if f.A != nil && strings.ToLower(f.A.Designation) == fieldLower {
			fmt.Println(f.Value)
			return nil
		}
	}

	// Check sections
	for _, s := range decryptedItem.Sections {
		for _, f := range s.Fields {
			name := strings.ToLower(f.Name)
			id := strings.ToLower(f.ID)
			if name == fieldLower || id == fieldLower {
				fmt.Println(f.Value)
				return nil
			}
		}
	}

	return fmt.Errorf("field not found: %s", fieldName)
}

func cmdList() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Get account info
	account, err := getAccount(db)
	if err != nil {
		return err
	}
	db.Close()

	password, secretKey, err := getCredentials()
	if err != nil {
		return err
	}

	vk, err := newVaultKeychain(password, secretKey, account.UserEmail)
	if err != nil {
		return err
	}
	defer vk.Close()

	vaults, err := getVaults(vk.db.DB)
	if err != nil {
		return err
	}

	fmt.Println("Vaults:")
	for _, v := range vaults {
		var encAttrs EncryptedData
		if err := json.Unmarshal([]byte(v.EncAttrs), &encAttrs); err != nil {
			fmt.Printf("  %s (failed to parse attrs)\n", v.VaultUUID)
			continue
		}

		key, err := vk.getVaultKey(v.VaultUUID)
		if err != nil {
			fmt.Printf("  %s (failed to get key)\n", v.VaultUUID)
			continue
		}

		attrsJSON, err := decryptEncryptedData(&encAttrs, key)
		if err != nil {
			fmt.Printf("  %s (failed to decrypt)\n", v.VaultUUID)
			continue
		}

		var attrs struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(attrsJSON, &attrs); err != nil {
			fmt.Printf("  %s (failed to parse decrypted)\n", v.VaultUUID)
			continue
		}

		fmt.Printf("  %s (%s)\n", attrs.Name, v.VaultUUID)
	}

	return nil
}

// parseRSAPrivateKey parses a JWK JSON into an RSA private key
func parseRSAPrivateKey(jwkJSON []byte) (*rsa.PrivateKey, error) {
	var jwk JWK
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("expected RSA key, got %s", jwk.Kty)
	}

	n, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	e, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	d, err := base64URLDecode(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode D: %w", err)
	}

	p, err := base64URLDecode(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("failed to decode P: %w", err)
	}

	q, err := base64URLDecode(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Q: %w", err)
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D: new(big.Int).SetBytes(d),
		Primes: []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		},
	}

	// Precompute values
	key.Precompute()

	return key, nil
}

// rsaDecryptOAEP decrypts data using RSA-OAEP with SHA1 (standard default)
func rsaDecryptOAEP(key *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, key, ciphertext, nil)
}
