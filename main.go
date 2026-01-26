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

// Version is set at build time via -ldflags
var Version = "dev"

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
	case "get":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: opcli get <op://vault/item>")
			os.Exit(1)
		}
		if err := cmdGet(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "daemon":
		if err := cmdDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "signin":
		if err := cmdSignin(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "signout":
		if err := cmdSignout(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Printf("opcli %s\n", Version)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("opcli - Fast 1Password CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  opcli signin                        - Store credentials in Keychain")
	fmt.Println("  opcli signout                       - Remove credentials from Keychain")
	fmt.Println("  opcli read <op://vault/item/field>  - Read a field from an item")
	fmt.Println("  opcli list                          - List all vaults")
	fmt.Println("  opcli get <op://vault/item>         - Dump item as JSON")
	fmt.Println()
	fmt.Println("Sessions:")
	fmt.Println("  After signin, each terminal requires biometric auth (Touch ID) on first")
	fmt.Println("  access. Sessions last 10 minutes of inactivity, max 12 hours total.")
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

func cmdSignin() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	account, err := getAccount(db)
	if err != nil {
		return err
	}
	db.Close()

	fmt.Fprintf(os.Stderr, "Signing in to: %s (%s)\n", account.UserEmail, account.UserName)

	var password, secretKey string

	// Try daemon first for convenience during testing
	if pw, sk, ok := getCredentialsFromDaemon(); ok {
		password, secretKey = pw, sk
		fmt.Fprintln(os.Stderr, "(using credentials from daemon)")
	} else {
		// Get secret key
		fmt.Fprint(os.Stderr, "Enter Secret Key (A3-XXXXX-...): ")
		skBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to read secret key: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		secretKey = strings.TrimSpace(string(skBytes))

		// Get master password
		fmt.Fprint(os.Stderr, "Enter Master Password: ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		password = string(pwBytes)
	}

	// Verify credentials work before storing
	fmt.Fprintln(os.Stderr, "Verifying credentials...")
	vk, err := newVaultKeychain(password, secretKey, account.UserEmail)
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}
	vk.Close()

	// Store in keychain
	if err := StoreCredentials(account.UserEmail, secretKey, password); err != nil {
		return fmt.Errorf("failed to store credentials: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Credentials stored in Keychain.")
	fmt.Fprintln(os.Stderr, "Use Touch ID to authenticate in each new terminal session.")
	return nil
}

func cmdSignout() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	account, err := getAccount(db)
	if err != nil {
		return err
	}
	db.Close()

	if err := DeleteCredentials(account.UserEmail); err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Signed out of %s\n", account.UserEmail)
	return nil
}

// getCredentials gets credentials, using session-based auth if available.
func getCredentials() (password, secretKey string, err error) {
	// Try daemon first (legacy)
	if pw, sk, ok := getCredentialsFromDaemon(); ok {
		return pw, sk, nil
	}

	// Check for environment variables
	envSecretKey := os.Getenv("OP_SECRET_KEY")
	envPassword := os.Getenv("OP_MASTER_PASSWORD")
	if envSecretKey != "" && envPassword != "" {
		return envPassword, envSecretKey, nil
	}

	// Try session-based auth
	db, err := openDB()
	if err != nil {
		return "", "", err
	}
	account, err := getAccount(db)
	db.Close()
	if err != nil {
		return "", "", err
	}

	// Check for existing valid session
	session, err := GetValidSession(account.UserEmail)
	if err != nil {
		// Session error, fall through to prompt
	}

	if session == nil {
		// No valid session - need to authenticate
		// First check if we have credentials in keychain
		sk, pw, err := GetCredentials(account.UserEmail)
		if err != nil {
			// No stored credentials - prompt manually
			return getCredentialsManual()
		}

		// Have stored credentials - require biometric auth
		if err := AuthenticateBiometric(account.UserEmail, "access your 1Password credentials"); err != nil {
			return "", "", fmt.Errorf("authentication failed: %w", err)
		}

		// Create session
		if _, err := CreateSession(account.UserEmail); err != nil {
			// Non-fatal, continue without session
			fmt.Fprintf(os.Stderr, "Warning: could not create session: %v\n", err)
		}

		return pw, sk, nil
	}

	// Have valid session - get credentials without biometric
	sk, pw, err := GetCredentials(account.UserEmail)
	if err != nil {
		return "", "", fmt.Errorf("credentials not found (run 'opcli signin' first): %w", err)
	}

	return pw, sk, nil
}

// getCredentialsManual prompts for credentials without using keychain/sessions.
func getCredentialsManual() (password, secretKey string, err error) {
	secretKey = os.Getenv("OP_SECRET_KEY")
	password = os.Getenv("OP_MASTER_PASSWORD")

	if secretKey == "" {
		fmt.Fprint(os.Stderr, "Enter Secret Key (A3-XXXXX-...): ")
		skBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", "", fmt.Errorf("failed to read secret key: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		secretKey = strings.TrimSpace(string(skBytes))
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
	db              *DB
	primaryKeysetID string                       // UUID of the primary keyset
	primarySymKey   []byte                       // Decrypted primary symmetric key
	keysetRSAKeys   map[string]*rsa.PrivateKey   // keyset UUID -> RSA private key
	keysetSymKeys   map[string][]byte            // keyset UUID -> symmetric key
	vaultKeys       map[string][]byte            // vault UUID -> symmetric key
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
		db:            &DB{db},
		keysetRSAKeys: make(map[string]*rsa.PrivateKey),
		keysetSymKeys: make(map[string][]byte),
		vaultKeys:     make(map[string][]byte),
	}

	// Get primary keyset
	keyset, err := getPrimaryKeyset(db)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary keyset: %w", err)
	}
	vk.primaryKeysetID = keyset.KeysetUUID

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
	vk.primarySymKey, err = extractSymmetricKey(decryptedSymKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to extract symmetric key: %w", err)
	}
	vk.keysetSymKeys[keyset.KeysetUUID] = vk.primarySymKey

	// Decrypt the RSA private key
	var encPriKey EncryptedData
	if err := json.Unmarshal([]byte(keyset.EncPriKey), &encPriKey); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted private key: %w", err)
	}

	decryptedPriKeyJSON, err := decryptEncryptedData(&encPriKey, vk.primarySymKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	primaryRSA, err := parseRSAPrivateKey(decryptedPriKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	vk.keysetRSAKeys[keyset.KeysetUUID] = primaryRSA

	return vk, nil
}

func (vk *VaultKeychain) Close() {
	if vk.db != nil {
		vk.db.Close()
	}
}

// getKeysetRSAKey returns the RSA private key for a keyset, decrypting it if needed
func (vk *VaultKeychain) getKeysetRSAKey(keysetUUID string) (*rsa.PrivateKey, error) {
	if rsaKey, ok := vk.keysetRSAKeys[keysetUUID]; ok {
		return rsaKey, nil
	}

	// Get the keyset
	keyset, err := getKeyset(vk.db.DB, keysetUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get keyset %s: %w", keysetUUID, err)
	}

	// Check if this keyset is encrypted by our primary keyset
	if keyset.EncryptedBy != vk.primaryKeysetID {
		// Try to get the parent keyset's RSA key recursively
		parentRSA, err := vk.getKeysetRSAKey(keyset.EncryptedBy)
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt keyset %s: parent keyset %s unavailable: %w",
				keysetUUID, keyset.EncryptedBy, err)
		}

		// Decrypt this keyset's symmetric key using parent's RSA key
		var encSymKey EncryptedData
		if err := json.Unmarshal([]byte(keyset.EncSymKey), &encSymKey); err != nil {
			return nil, fmt.Errorf("failed to parse keyset sym key: %w", err)
		}

		symKeyData, err := base64URLDecode(encSymKey.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode keyset sym key: %w", err)
		}

		decryptedSymKeyJSON, err := rsaDecryptOAEP(parentRSA, symKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to RSA decrypt keyset sym key: %w", err)
		}

		symKey, err := extractSymmetricKey(decryptedSymKeyJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to extract keyset sym key: %w", err)
		}
		vk.keysetSymKeys[keysetUUID] = symKey

		// Decrypt the RSA private key using the symmetric key
		var encPriKey EncryptedData
		if err := json.Unmarshal([]byte(keyset.EncPriKey), &encPriKey); err != nil {
			return nil, fmt.Errorf("failed to parse keyset private key: %w", err)
		}

		decryptedPriKeyJSON, err := decryptEncryptedData(&encPriKey, symKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt keyset private key: %w", err)
		}

		rsaKey, err := parseRSAPrivateKey(decryptedPriKeyJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to parse keyset RSA key: %w", err)
		}

		vk.keysetRSAKeys[keysetUUID] = rsaKey
		return rsaKey, nil
	}

	// This keyset is encrypted by the primary keyset
	// Decrypt sym key using primary RSA
	var encSymKey EncryptedData
	if err := json.Unmarshal([]byte(keyset.EncSymKey), &encSymKey); err != nil {
		return nil, fmt.Errorf("failed to parse keyset sym key: %w", err)
	}

	symKeyData, err := base64URLDecode(encSymKey.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode keyset sym key: %w", err)
	}

	primaryRSA := vk.keysetRSAKeys[vk.primaryKeysetID]
	decryptedSymKeyJSON, err := rsaDecryptOAEP(primaryRSA, symKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to RSA decrypt keyset sym key: %w", err)
	}

	symKey, err := extractSymmetricKey(decryptedSymKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to extract keyset sym key: %w", err)
	}
	vk.keysetSymKeys[keysetUUID] = symKey

	// Decrypt the RSA private key
	var encPriKey EncryptedData
	if err := json.Unmarshal([]byte(keyset.EncPriKey), &encPriKey); err != nil {
		return nil, fmt.Errorf("failed to parse keyset private key: %w", err)
	}

	decryptedPriKeyJSON, err := decryptEncryptedData(&encPriKey, symKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keyset private key: %w", err)
	}

	rsaKey, err := parseRSAPrivateKey(decryptedPriKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyset RSA key: %w", err)
	}

	vk.keysetRSAKeys[keysetUUID] = rsaKey
	return rsaKey, nil
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

	// Get the RSA key for the keyset that encrypted this vault key
	rsaKey, err := vk.getKeysetRSAKey(encVaultKey.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get keyset RSA key: %w", err)
	}

	// Decrypt vault key using RSA-OAEP
	keyData, err := base64URLDecode(encVaultKey.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault key data: %w", err)
	}

	decryptedKeyJSON, err := rsaDecryptOAEP(rsaKey, keyData)
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
		designation := strings.ToLower(f.Designation)
		if name == fieldLower || id == fieldLower || designation == fieldLower {
			fmt.Println(f.Value)
			return nil
		}
	}

	// Check sections
	for _, s := range decryptedItem.Sections {
		for _, f := range s.Fields {
			name := strings.ToLower(f.Name)
			id := strings.ToLower(f.ID)
			designation := strings.ToLower(f.Designation)
			if name == fieldLower || id == fieldLower || designation == fieldLower {
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

func cmdGet(uri string) error {
	// Parse URI - allow op://vault/item (without field)
	if !strings.HasPrefix(uri, "op://") {
		return fmt.Errorf("invalid URI: must start with op://")
	}
	parts := strings.Split(uri[5:], "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid URI: must be op://vault/item")
	}
	vaultName, itemName := parts[0], parts[1]

	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

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

	// Find vault (same logic as cmdRead)
	vaults, err := getVaults(vk.db.DB)
	if err != nil {
		return err
	}

	var targetVaultUUID string
	for _, v := range vaults {
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

	vaultID, err := getVaultIDByUUID(vk.db.DB, targetVaultUUID)
	if err != nil {
		return err
	}

	items, err := getItemOverviews(vk.db.DB, vaultID)
	if err != nil {
		return err
	}

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

	detail, err := getItemDetail(vk.db.DB, targetItem.ID)
	if err != nil {
		return err
	}

	// Decrypt and dump raw JSON
	key, err := vk.getVaultKey(targetVaultUUID)
	if err != nil {
		return err
	}

	decrypted, err := decryptEncryptedData(&detail.EncDetails, key)
	if err != nil {
		return err
	}

	// Pretty print the JSON
	var raw json.RawMessage = decrypted
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Println(string(decrypted))
	} else {
		fmt.Println(string(pretty))
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
