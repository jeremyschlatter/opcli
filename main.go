package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// Timing instrumentation (enabled via OPCLI_TIMING=1)
var timingEnabled = os.Getenv("OPCLI_TIMING") != ""

type timer struct {
	start  time.Time
	last   time.Time
	events []timerEvent
}

type timerEvent struct {
	name     string
	elapsed  time.Duration
	sinceLast time.Duration
}

func newTimer() *timer {
	now := time.Now()
	return &timer{start: now, last: now}
}

func (t *timer) mark(name string) {
	if !timingEnabled {
		return
	}
	now := time.Now()
	t.events = append(t.events, timerEvent{
		name:      name,
		elapsed:   now.Sub(t.start),
		sinceLast: now.Sub(t.last),
	})
	t.last = now
}

func (t *timer) print() {
	if !timingEnabled || len(t.events) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "\n[Timing breakdown]")
	for _, e := range t.events {
		fmt.Fprintf(os.Stderr, "  %6.1fms (+%5.1fms)  %s\n",
			float64(e.elapsed.Microseconds())/1000,
			float64(e.sinceLast.Microseconds())/1000,
			e.name)
	}
	fmt.Fprintf(os.Stderr, "  %6.1fms total\n", float64(t.events[len(t.events)-1].elapsed.Microseconds())/1000)
}

// testCommands is populated by test_helpers.go in test builds
var testCommands map[string]func() error

// Version is set at build time via -ldflags
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Parse --account flag (can appear anywhere)
	var accountFlag string
	args := make([]string, 0, len(os.Args))
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--account" && i+1 < len(os.Args) {
			accountFlag = os.Args[i+1]
			i++ // skip next arg
		} else if strings.HasPrefix(arg, "--account=") {
			accountFlag = strings.TrimPrefix(arg, "--account=")
		} else {
			args = append(args, arg)
		}
	}

	if len(args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[1]

	// Check for test commands (only available in test builds)
	if testCommands != nil {
		if fn, ok := testCommands[cmd]; ok {
			if err := fn(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	switch cmd {
	case "account":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: opcli account <list|forget>")
			os.Exit(1)
		}
		switch args[2] {
		case "list":
			if err := cmdAccountList(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		case "forget":
			acct := accountFlag
			if acct == "" && len(args) > 3 {
				acct = args[3]
			}
			if err := cmdAccountForget(acct); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown account subcommand: %s\n", args[2])
			os.Exit(1)
		}
	case "read":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: opcli read <op://vault/item/field>")
			os.Exit(1)
		}
		if err := cmdRead(args[2], accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := cmdList(accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "get":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: opcli get <op://vault/item>")
			os.Exit(1)
		}
		if err := cmdGet(args[2], accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "signin":
		if err := cmdSignin(accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "signout":
		if err := cmdSignout(accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "inject":
		if err := cmdInject(args[2:], accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "run":
		code, err := cmdRun(args[2:], accountFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(code)
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
	fmt.Println("  opcli signin [--account <acct>]      - Store credentials in Keychain")
	fmt.Println("  opcli signout [--account <acct>]     - Remove credentials from Keychain")
	fmt.Println("  opcli read <op://vault/item/field>   - Read a field from an item")
	fmt.Println("  opcli read <op://vault/item/section/field>")
	fmt.Println("  opcli list [--account <acct>]        - List all vaults")
	fmt.Println("  opcli get <op://vault/item>          - Dump item as JSON")
	fmt.Println("  opcli inject [-i file] [-o file]     - Inject secrets into template")
	fmt.Println("  opcli run [--env-file=<file>]... -- <command>")
	fmt.Println("                                       - Run command with secrets as env vars")
	fmt.Println("  opcli account list                   - List all accounts")
	fmt.Println("  opcli account forget [<acct>]        - Remove an account")
	fmt.Println()
	fmt.Println("Account Selection:")
	fmt.Println("  --account <shorthand|email|uuid>     - Select account (default: most recent)")
	fmt.Println("  OP_ACCOUNT env var                   - Alternative to --account flag")
	fmt.Println()
	fmt.Println("Sessions:")
	fmt.Println("  After signin, each terminal requires biometric auth (Touch ID) on first")
	fmt.Println("  access. Sessions last 10 minutes of inactivity, max 12 hours total.")
}

// resolveAccountUUID resolves an account identifier to a UUID.
// If accountFlag is empty, uses OP_ACCOUNT env var or default account.
func resolveAccountUUID(accountFlag string) (string, error) {
	// Check --account flag
	if accountFlag != "" {
		_, uuid, err := ResolveAccount(accountFlag)
		if err != nil {
			return "", fmt.Errorf("account not found: %s (run 'opcli signin' first)", accountFlag)
		}
		return uuid, nil
	}

	// Check OP_ACCOUNT env var
	if envAcct := os.Getenv("OP_ACCOUNT"); envAcct != "" {
		_, uuid, err := ResolveAccount(envAcct)
		if err != nil {
			return "", fmt.Errorf("account not found: %s", envAcct)
		}
		return uuid, nil
	}

	// Use default account from keychain
	uuid, err := GetDefaultAccount()
	if err != nil {
		return "", fmt.Errorf("no account configured (run 'opcli signin' first)")
	}
	return uuid, nil
}

// selectDBAccount finds an account in the database matching the given criteria.
// If accountFlag is empty, returns the first account that has stored credentials.
func selectDBAccount(db *sql.DB, accountFlag string) (*AccountInfo, error) {
	accounts, err := getAccounts(db)
	if err != nil {
		return nil, err
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("no accounts found in 1Password database")
	}

	// If no account specified, try to find one with stored credentials
	if accountFlag == "" {
		// First try the default account
		if defaultUUID, err := GetDefaultAccount(); err == nil {
			for i := range accounts {
				if accounts[i].AccountUUID == defaultUUID {
					return &accounts[i], nil
				}
			}
		}
		// Otherwise return first account
		return &accounts[0], nil
	}

	// Match by UUID, email, or URL
	lower := strings.ToLower(accountFlag)
	for i := range accounts {
		a := &accounts[i]
		if a.AccountUUID == accountFlag ||
			strings.ToLower(a.Email) == lower ||
			strings.Contains(strings.ToLower(a.URL), lower) {
			return a, nil
		}
		// Also check shorthand from stored credentials
		if stored, _, err := ResolveAccount(accountFlag); err == nil {
			if stored.Email == a.Email {
				return a, nil
			}
		}
	}

	return nil, fmt.Errorf("account not found: %s", accountFlag)
}

func cmdAccountList() error {
	// List accounts from database
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	dbAccounts, err := getAccounts(db)
	if err != nil {
		return err
	}

	// Get stored credentials
	store, _ := GetStoredAccounts()

	fmt.Println("Accounts in 1Password database:")
	for _, a := range dbAccounts {
		shorthand := ExtractShorthand(a.URL)
		status := "(not signed in)"
		if store != nil {
			if stored, ok := store.Accounts[a.AccountUUID]; ok {
				status = "(signed in)"
				if stored.Shorthand != "" {
					shorthand = stored.Shorthand
				}
			}
			if store.Default == a.AccountUUID {
				status = "(signed in, default)"
			}
		}
		fmt.Printf("  %s: %s %s\n", shorthand, a.Email, status)
	}

	return nil
}

func cmdAccountForget(accountFlag string) error {
	if accountFlag == "" {
		return fmt.Errorf("specify an account to forget")
	}

	_, uuid, err := ResolveAccount(accountFlag)
	if err != nil {
		return err
	}

	store, err := GetStoredAccounts()
	if err != nil {
		return err
	}

	acct, ok := store.Accounts[uuid]
	if !ok {
		return fmt.Errorf("account not found: %s", accountFlag)
	}

	if err := DeleteCredentials(uuid); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Forgot account: %s (%s)\n", acct.Shorthand, acct.Email)
	return nil
}

func cmdSignin(accountFlag string) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Find account in database
	dbAccount, err := selectDBAccount(db, accountFlag)
	if err != nil {
		return err
	}

	// Get full account data
	account, err := getAccount(db, dbAccount.AccountUUID)
	if err != nil {
		return err
	}
	accountID, err := getAccountIDByUUID(db, dbAccount.AccountUUID)
	if err != nil {
		return err
	}

	shorthand := ExtractShorthand(account.SignInURL)
	fmt.Fprintf(os.Stderr, "Signing in to: %s (%s)\n", account.UserEmail, shorthand)

	// Get secret key
	fmt.Fprint(os.Stderr, "Enter Secret Key (A3-XXXXX-...): ")
	skBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read secret key: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	secretKey := strings.TrimSpace(string(skBytes))

	// Get master password
	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	password := string(pwBytes)

	// Verify credentials work before storing
	fmt.Fprintln(os.Stderr, "Verifying credentials...")
	vk, err := newVaultKeychain(password, secretKey, account.UserEmail, dbAccount.AccountUUID, accountID, dbAccount.AccountType)
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}
	vk.Close()

	// Store in keychain
	if err := StoreCredentials(dbAccount.AccountUUID, secretKey, password, shorthand, account.UserEmail, account.SignInURL); err != nil {
		return fmt.Errorf("failed to store credentials: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Credentials stored in Keychain.")
	fmt.Fprintln(os.Stderr, "Use Touch ID to authenticate in each new terminal session.")
	return nil
}

func cmdSignout(accountFlag string) error {
	accountUUID, err := resolveAccountUUID(accountFlag)
	if err != nil {
		return err
	}

	store, err := GetStoredAccounts()
	if err != nil {
		return err
	}

	acct, ok := store.Accounts[accountUUID]
	if !ok {
		return fmt.Errorf("account not found")
	}

	if err := DeleteCredentials(accountUUID); err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Signed out of %s\n", acct.Email)
	return nil
}

// getCredentials gets credentials for an account, using session-based auth if available.
func getCredentials(accountUUID string) (password, secretKey string, err error) {
	// Check for existing valid session
	session, _ := GetValidSession(accountUUID)

	sk, pw, err := GetCredentials(accountUUID)
	if err != nil {
		return "", "", fmt.Errorf("no account configured (run 'opcli signin' first)")
	}

	if session == nil {
		// No valid session - require biometric auth
		if err := AuthenticateBiometric("access your 1Password credentials"); err != nil {
			return "", "", fmt.Errorf("authentication failed: %w", err)
		}

		// Create session
		if _, err := CreateSession(accountUUID); err != nil {
			// Non-fatal, continue without session
			fmt.Fprintf(os.Stderr, "Warning: could not create session: %v\n", err)
		}
	}

	return pw, sk, nil
}

// VaultKeychain holds decrypted keys for accessing vault items
type VaultKeychain struct {
	db              *sql.DB
	accountID       int64                      // internal DB account ID
	accountType     string                     // I=Individual, F=Family, T=Teams, B=Business
	primaryKeysetID string                     // UUID of the primary keyset
	primarySymKey   []byte                     // Decrypted primary symmetric key
	keysetRSAKeys   map[string]*rsa.PrivateKey // keyset UUID -> RSA private key
	keysetSymKeys   map[string][]byte          // keyset UUID -> symmetric key
	vaultKeys       map[string][]byte          // vault UUID -> symmetric key
}


func newVaultKeychain(password, secretKey, email, accountUUID string, accountID int64, accountType string) (*VaultKeychain, error) {
	return newVaultKeychainTimed(password, secretKey, email, accountUUID, accountID, accountType, nil)
}

func newVaultKeychainTimed(password, secretKey, email, _ string, accountID int64, accountType string, t *timer) (*VaultKeychain, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("  open DB (keychain)")
	}

	vk := &VaultKeychain{
		db:            db,
		accountID:     accountID,
		accountType:   accountType,
		keysetRSAKeys: make(map[string]*rsa.PrivateKey),
		keysetSymKeys: make(map[string][]byte),
		vaultKeys:     make(map[string][]byte),
	}

	// Get primary keyset
	keyset, err := getPrimaryKeyset(db, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary keyset: %w", err)
	}
	vk.primaryKeysetID = keyset.KeysetUUID
	if t != nil {
		t.mark("  get primary keyset (DB)")
	}

	// Parse the encrypted symmetric key
	var encSymKey EncryptedData
	if err := json.Unmarshal([]byte(keyset.EncSymKey), &encSymKey); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted symmetric key: %w", err)
	}

	// Try to use cached symmetric key (avoids expensive PBKDF2)
	// Cache key includes salt so it invalidates if credentials change
	cacheKey := keyset.KeysetUUID + "-" + encSymKey.P2s
	if cached, err := GetCachedSymKey(cacheKey); err == nil {
		vk.primarySymKey = cached
		if t != nil {
			t.mark("  symmetric key (cached)")
		}
	} else {
		// Decrypt the symmetric key using 2SKD (PBKDF2 - expensive!)
		decryptedSymKeyJSON, err := decryptPBES2(&encSymKey, secretKey, password, email)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
		}
		if t != nil {
			t.mark("  PBKDF2 key derivation")
		}

		// Extract the actual key bytes from the JWK
		vk.primarySymKey, err = extractSymmetricKey(decryptedSymKeyJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to extract symmetric key: %w", err)
		}

		// Cache for next time (ignore errors - caching is best-effort)
		SetCachedSymKey(cacheKey, vk.primarySymKey)
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
	if t != nil {
		t.mark("  decrypt RSA key")
	}

	return vk, nil
}

func (vk *VaultKeychain) Close() {
	vk.db.Close()
}

// getKeysetRSAKey returns the RSA private key for a keyset, decrypting it if needed
func (vk *VaultKeychain) getKeysetRSAKey(keysetUUID string) (*rsa.PrivateKey, error) {
	if rsaKey, ok := vk.keysetRSAKeys[keysetUUID]; ok {
		return rsaKey, nil
	}

	// Get the keyset
	keyset, err := getKeyset(vk.db, vk.accountID, keysetUUID)
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
	vaultID, err := getVaultIDByUUID(vk.db, vk.accountID, vaultUUID)
	if err != nil {
		return nil, err
	}

	vault, err := getVaultByID(vk.db, vaultID)
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

// decryptVaultName decrypts the vault attributes and returns the display name and raw name.
func (vk *VaultKeychain) decryptVaultName(v *Vault) (displayName, rawName string, err error) {
	var encAttrs EncryptedData
	if err := json.Unmarshal([]byte(v.EncAttrs), &encAttrs); err != nil {
		return "", "", fmt.Errorf("failed to parse vault attrs: %w", err)
	}

	key, err := vk.getVaultKey(v.VaultUUID)
	if err != nil {
		return "", "", err
	}

	attrsJSON, err := decryptEncryptedData(&encAttrs, key)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt vault attrs: %w", err)
	}

	var attrs struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(attrsJSON, &attrs); err != nil {
		return "", "", fmt.Errorf("failed to parse decrypted attrs: %w", err)
	}

	return vaultDisplayName(v.VaultType, vk.accountType, attrs.Name), attrs.Name, nil
}

// findVaultByName finds a vault by name or UUID.
func (vk *VaultKeychain) findVaultByName(vaultName string) (string, error) {
	return vk.findVaultByNameTimed(vaultName, nil)
}

func (vk *VaultKeychain) findVaultByNameTimed(vaultName string, t *timer) (string, error) {
	vaults, err := getVaults(vk.db, vk.accountID)
	if err != nil {
		return "", err
	}
	if t != nil {
		t.mark(fmt.Sprintf("    getVaults (%d vaults)", len(vaults)))
	}

	for i, v := range vaults {
		displayName, rawName, err := vk.decryptVaultName(&v)
		if err != nil {
			continue
		}

		if strings.EqualFold(displayName, vaultName) || strings.EqualFold(rawName, vaultName) || v.VaultUUID == vaultName {
			if t != nil {
				t.mark(fmt.Sprintf("    decrypt %d vault names", i+1))
			}
			return v.VaultUUID, nil
		}
	}

	return "", fmt.Errorf("vault not found: %s", vaultName)
}

// findItemByName finds an item in a vault by title or UUID.
func (vk *VaultKeychain) findItemByName(vaultUUID, itemName string) (*ItemOverview, error) {
	return vk.findItemByNameTimed(vaultUUID, itemName, nil)
}

func (vk *VaultKeychain) findItemByNameTimed(vaultUUID, itemName string, t *timer) (*ItemOverview, error) {
	vaultID, err := getVaultIDByUUID(vk.db, vk.accountID, vaultUUID)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("    getVaultIDByUUID")
	}

	items, err := getItemOverviews(vk.db, vaultID)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark(fmt.Sprintf("    getItemOverviews (%d items)", len(items)))
	}

	for i := range items {
		overview, err := vk.decryptOverview(vaultUUID, &items[i].EncOverview)
		if err != nil {
			continue
		}

		if strings.EqualFold(overview.Title, itemName) || items[i].UUID == itemName {
			if t != nil {
				t.mark(fmt.Sprintf("    decrypt %d item overviews", i+1))
			}
			return &items[i], nil
		}
	}

	return nil, fmt.Errorf("item not found: %s", itemName)
}

// parseOPURI parses an op://vault/item/[section/]field URI
func parseOPURI(uri string) (vault, item, section, field string, err error) {
	if !strings.HasPrefix(uri, "op://") {
		return "", "", "", "", fmt.Errorf("invalid URI: must start with op://")
	}

	parts := strings.Split(uri[5:], "/")
	if len(parts) < 3 {
		return "", "", "", "", fmt.Errorf("invalid URI: must be op://vault/item/field or op://vault/item/section/field")
	}

	if len(parts) == 3 {
		return parts[0], parts[1], "", parts[2], nil
	}
	return parts[0], parts[1], parts[2], parts[3], nil
}

// openVaultKeychain is a helper to resolve account, get credentials, and open keychain.
func openVaultKeychain(accountFlag string) (*VaultKeychain, error) {
	return openVaultKeychainTimed(accountFlag, nil)
}

func openVaultKeychainTimed(accountFlag string, t *timer) (*VaultKeychain, error) {
	// Start DB query in background (pays cold-start cost in parallel with keychain)
	type dbResult struct {
		accounts []AccountInfo
		err      error
	}
	dbCh := make(chan dbResult, 1)
	go func() {
		db, err := openDB()
		if err != nil {
			dbCh <- dbResult{err: err}
			return
		}
		accounts, err := getAccounts(db)
		db.Close()
		dbCh <- dbResult{accounts: accounts, err: err}
	}()

	// Meanwhile, do keychain operations (pays keychain cold-start cost)
	accountUUID, err := resolveAccountUUID(accountFlag)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("resolve account")
	}

	store, err := GetStoredAccounts()
	if err != nil {
		return nil, err
	}
	storedAcct, ok := store.Accounts[accountUUID]
	if !ok {
		return nil, fmt.Errorf("account not found in stored credentials (run 'opcli signin' first)")
	}
	if t != nil {
		t.mark("get stored accounts")
	}

	password, secretKey, err := getCredentials(accountUUID)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("get credentials (session check)")
	}

	// Wait for DB result
	dbRes := <-dbCh
	if dbRes.err != nil {
		return nil, dbRes.err
	}
	if t != nil {
		t.mark("get accounts (parallel)")
	}

	var accountID int64
	var accountType string
	for _, a := range dbRes.accounts {
		if a.AccountUUID == accountUUID {
			accountID = a.ID
			accountType = a.AccountType
			break
		}
	}
	if accountID == 0 {
		return nil, fmt.Errorf("account not found in database: %s", accountUUID)
	}

	// Initialize keychain
	vk, err := newVaultKeychainTimed(password, secretKey, storedAcct.Email, accountUUID, accountID, accountType, t)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("init keychain (key derivation)")
	}
	return vk, nil
}

func cmdRead(uri string, accountFlag string) error {
	t := newTimer()

	vaultName, itemName, sectionName, fieldName, err := parseOPURI(uri)
	if err != nil {
		return err
	}
	t.mark("parse URI")

	vk, err := openVaultKeychainTimed(accountFlag, t)
	if err != nil {
		return err
	}
	defer vk.Close()

	vaultUUID, err := vk.findVaultByNameTimed(vaultName, t)
	if err != nil {
		return err
	}
	t.mark("find vault")

	item, err := vk.findItemByNameTimed(vaultUUID, itemName, t)
	if err != nil {
		return err
	}
	t.mark("find item")

	detail, err := getItemDetail(vk.db, item.ID)
	if err != nil {
		return err
	}
	t.mark("get item detail (DB)")

	decryptedItem, err := vk.decryptDetail(vaultUUID, &detail.EncDetails)
	if err != nil {
		return err
	}
	t.mark("decrypt item")

	value, err := findField(decryptedItem, sectionName, fieldName)
	if err != nil {
		return err
	}
	t.mark("find field")

	fmt.Println(value)
	t.print()
	return nil
}

// vaultDisplayName returns the display name for a vault.
// The personal vault (type P) has special display names based on account type:
// - Individual (I): "Personal"
// - Family (F): "Private"
// - Teams/Business (T/B): "Employee"
func vaultDisplayName(vaultType, accountType, storedName string) string {
	if vaultType == "P" {
		switch accountType {
		case "I":
			return "Personal"
		case "F":
			return "Private"
		case "T", "B":
			return "Employee"
		}
	}
	return storedName
}

// fieldMatches checks if a field matches the given name (case-insensitive).
func fieldMatches(f *Field, name string) bool {
	lower := strings.ToLower(name)
	return strings.ToLower(f.FieldLabel()) == lower ||
		strings.ToLower(f.FieldID()) == lower ||
		strings.ToLower(f.Designation) == lower ||
		strings.ToLower(f.Name) == lower ||
		strings.ToLower(f.ID) == lower
}

// sectionMatches checks if a section matches the given name (case-insensitive).
func sectionMatches(s *Section, name string) bool {
	lower := strings.ToLower(name)
	return strings.ToLower(s.Name) == lower || strings.ToLower(s.Title) == lower
}

// findField searches for a field in the decrypted item.
// If sectionName is specified, only searches that section.
// If sectionName is empty, searches everywhere but requires unambiguous match.
func findField(item *DecryptedItem, sectionName, fieldName string) (string, error) {
	type match struct {
		value   string
		section string // empty for top-level
	}
	var matches []match

	// If section specified, only search that section
	if sectionName != "" {
		for i := range item.Sections {
			s := &item.Sections[i]
			if !sectionMatches(s, sectionName) {
				continue
			}
			for j := range s.Fields {
				f := &s.Fields[j]
				if fieldMatches(f, fieldName) {
					return f.FieldValue(), nil
				}
			}
			return "", fmt.Errorf("field not found in section %q: %s", sectionName, fieldName)
		}
		return "", fmt.Errorf("section not found: %s", sectionName)
	}

	// No section specified - search everywhere
	// Check top-level fields first
	for i := range item.Fields {
		f := &item.Fields[i]
		if fieldMatches(f, fieldName) {
			matches = append(matches, match{value: f.FieldValue(), section: ""})
		}
	}

	// Check sections
	for i := range item.Sections {
		s := &item.Sections[i]
		sectionLabel := s.Title
		if sectionLabel == "" {
			sectionLabel = s.Name
		}
		for j := range s.Fields {
			f := &s.Fields[j]
			if fieldMatches(f, fieldName) {
				matches = append(matches, match{value: f.FieldValue(), section: sectionLabel})
			}
		}
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("field not found: %s", fieldName)
	}

	if len(matches) == 1 {
		return matches[0].value, nil
	}

	// Multiple matches - check if they all have the same value
	allSame := true
	for _, m := range matches[1:] {
		if m.value != matches[0].value {
			allSame = false
			break
		}
	}
	if allSame {
		return matches[0].value, nil
	}

	// Ambiguous - list where the field was found
	var locations []string
	for _, m := range matches {
		if m.section == "" {
			locations = append(locations, "(top-level)")
		} else {
			locations = append(locations, fmt.Sprintf("section %q", m.section))
		}
	}
	return "", fmt.Errorf("field %q is ambiguous, found in: %s", fieldName, strings.Join(locations, ", "))
}

func cmdList(accountFlag string) error {
	vk, err := openVaultKeychain(accountFlag)
	if err != nil {
		return err
	}
	defer vk.Close()

	vaults, err := getVaults(vk.db, vk.accountID)
	if err != nil {
		return err
	}

	type vaultEntry struct {
		name string
		uuid string
	}
	var entries []vaultEntry

	for _, v := range vaults {
		// Hide System vaults (like op does)
		if v.VaultType == "S" {
			continue
		}

		displayName, _, err := vk.decryptVaultName(&v)
		if err != nil {
			// Show partial info for vaults we can't decrypt
			entries = append(entries, vaultEntry{v.VaultUUID + " (decrypt failed)", v.VaultUUID})
			continue
		}

		entries = append(entries, vaultEntry{displayName, v.VaultUUID})
	}

	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
	})

	fmt.Println("Vaults:")
	for _, e := range entries {
		fmt.Printf("  %s (%s)\n", e.name, e.uuid)
	}

	return nil
}

func cmdGet(uri string, accountFlag string) error {
	if !strings.HasPrefix(uri, "op://") {
		return fmt.Errorf("invalid URI: must start with op://")
	}
	parts := strings.Split(uri[5:], "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid URI: must be op://vault/item")
	}
	vaultName, itemName := parts[0], parts[1]

	vk, err := openVaultKeychain(accountFlag)
	if err != nil {
		return err
	}
	defer vk.Close()

	vaultUUID, err := vk.findVaultByName(vaultName)
	if err != nil {
		return err
	}

	item, err := vk.findItemByName(vaultUUID, itemName)
	if err != nil {
		return err
	}

	detail, err := getItemDetail(vk.db, item.ID)
	if err != nil {
		return err
	}

	key, err := vk.getVaultKey(vaultUUID)
	if err != nil {
		return err
	}

	decrypted, err := decryptEncryptedData(&detail.EncDetails, key)
	if err != nil {
		return err
	}

	pretty, err := json.MarshalIndent(json.RawMessage(decrypted), "", "  ")
	if err != nil {
		fmt.Println(string(decrypted))
	} else {
		fmt.Println(string(pretty))
	}

	return nil
}

func cmdInject(args []string, accountFlag string) error {
	var inFile, outFile string
	var fileMode fs.FileMode = 0600
	var force bool

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--in-file":
			if i+1 >= len(args) {
				return fmt.Errorf("missing argument for %s", args[i])
			}
			i++
			inFile = args[i]
		case "-o", "--out-file":
			if i+1 >= len(args) {
				return fmt.Errorf("missing argument for %s", args[i])
			}
			i++
			outFile = args[i]
		case "--file-mode":
			if i+1 >= len(args) {
				return fmt.Errorf("missing argument for %s", args[i])
			}
			i++
			mode, err := strconv.ParseUint(args[i], 8, 32)
			if err != nil {
				return fmt.Errorf("invalid file mode: %s", args[i])
			}
			fileMode = fs.FileMode(mode)
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag: %s", args[i])
			}
		}
	}
	_ = force // unused for now, but matching op CLI interface

	// Read input
	var input []byte
	if inFile != "" {
		var err error
		input, err = os.ReadFile(inFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else {
		var err error
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
	}

	// Find op:// references - either {{ op://... }} or bare op://...
	// Allowed chars in references: a-zA-Z0-9, -, _, ., space, and / (path separator)
	// References end at any unsupported character (quotes, newlines, brackets, etc.)
	// The final character must be non-space to avoid capturing trailing spaces
	pattern := regexp.MustCompile(`\{\{\s*(op://[^}]*[^\s}])\s*\}\}|(op://[a-zA-Z0-9_./ -]*[a-zA-Z0-9_./-])`)
	matches := pattern.FindAllStringSubmatch(string(input), -1)

	if len(matches) == 0 {
		// No secrets to inject, just pass through
		if outFile != "" {
			return os.WriteFile(outFile, input, fileMode)
		}
		_, err := os.Stdout.Write(input)
		return err
	}

	// Collect unique URIs
	uris := make(map[string]bool)
	for _, m := range matches {
		uri := m[1] // braced: {{ op://... }}
		if uri == "" {
			uri = m[0] // bare: op://...
		}
		uris[uri] = true
	}

	// Open vault keychain once for all lookups
	vk, err := openVaultKeychain(accountFlag)
	if err != nil {
		return err
	}
	defer vk.Close()

	// Resolve all secrets
	secrets := make(map[string]string)
	for uri := range uris {
		value, err := readSecret(vk, uri)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", uri, err)
		}
		secrets[uri] = value
	}

	// Replace all patterns with their values
	output := pattern.ReplaceAllStringFunc(string(input), func(match string) string {
		m := pattern.FindStringSubmatch(match)
		uri := m[1] // braced
		if uri == "" {
			uri = m[0] // bare
		}
		return secrets[uri]
	})

	// Write output
	if outFile != "" {
		return os.WriteFile(outFile, []byte(output), fileMode)
	}
	_, err = os.Stdout.WriteString(output)
	return err
}

func cmdRun(args []string, accountFlag string) (int, error) {
	var envFiles []string
	var noMasking bool
	var cmdArgs []string

	// Parse flags until we hit --
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			cmdArgs = args[i+1:]
			break
		}
		if arg == "-h" || arg == "--help" {
			printRunUsage()
			return 0, nil
		}
		if arg == "--env-file" && i+1 < len(args) {
			i++
			envFiles = append(envFiles, args[i])
		} else if strings.HasPrefix(arg, "--env-file=") {
			envFiles = append(envFiles, strings.TrimPrefix(arg, "--env-file="))
		} else if arg == "--no-masking" {
			noMasking = true
		} else if strings.HasPrefix(arg, "-") {
			return 0, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	if len(cmdArgs) == 0 {
		printRunUsage()
		return 1, nil
	}

	// Collect environment: start with current env
	env := make(map[string]string)
	for _, e := range os.Environ() {
		if idx := strings.Index(e, "="); idx != -1 {
			env[e[:idx]] = e[idx+1:]
		}
	}

	// Load env files (later files override earlier)
	for _, f := range envFiles {
		fileEnv, err := parseEnvFile(f, env)
		if err != nil {
			return 0, fmt.Errorf("failed to read env file %s: %w", f, err)
		}
		for k, v := range fileEnv {
			env[k] = v
		}
	}

	// Find op:// references and collect secrets to resolve
	secretRefs := make(map[string]string) // env var name -> op:// URI
	for k, v := range env {
		// Expand variables in the value
		expanded := os.Expand(v, func(name string) string {
			if val, ok := env[name]; ok {
				return val
			}
			return ""
		})
		env[k] = expanded

		if strings.HasPrefix(expanded, "op://") {
			secretRefs[k] = expanded
		}
	}

	// Resolve secrets if any
	var secrets map[string]string
	if len(secretRefs) > 0 {
		vk, err := openVaultKeychain(accountFlag)
		if err != nil {
			return 0, err
		}
		defer vk.Close()

		secrets = make(map[string]string)
		for name, uri := range secretRefs {
			value, err := readSecret(vk, uri)
			if err != nil {
				return 0, fmt.Errorf("failed to resolve %s: %w", name, err)
			}
			secrets[uri] = value
			env[name] = value
		}
	}

	// Build final environment slice
	var finalEnv []string
	for k, v := range env {
		finalEnv = append(finalEnv, k+"="+v)
	}

	// Run the command
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = finalEnv

	var stdoutMask, stderrMask *maskingWriter
	if noMasking || len(secrets) == 0 {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		// Collect unique secret values for masking
		secretValues := make([]string, 0, len(secrets))
		for _, v := range secrets {
			secretValues = append(secretValues, v)
		}
		stdoutMask = newMaskingWriter(os.Stdout, secretValues)
		stderrMask = newMaskingWriter(os.Stderr, secretValues)
		cmd.Stdout = stdoutMask
		cmd.Stderr = stderrMask
	}

	cmd.Stdin = os.Stdin

	runErr := cmd.Run()

	// Flush masking writers
	if stdoutMask != nil {
		stdoutMask.Close()
	}
	if stderrMask != nil {
		stderrMask.Close()
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, runErr
	}
	return 0, nil
}

// parseEnvFile parses a dotenv-style file and returns key-value pairs.
// Variables in values are expanded using the provided env map.
func parseEnvFile(path string, env map[string]string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Expand variables in the value using both env and already-parsed results
		value = os.Expand(value, func(name string) string {
			if val, ok := result[name]; ok {
				return val
			}
			if val, ok := env[name]; ok {
				return val
			}
			return ""
		})

		result[key] = value
	}

	return result, nil
}

// maskingWriter replaces secret values with <concealed> in output.
// It buffers data to handle secrets that might be split across Write calls.
type maskingWriter struct {
	w            io.Writer
	replacer     *strings.Replacer
	maxSecretLen int
	buf          []byte
}

func newMaskingWriter(w io.Writer, secrets []string) *maskingWriter {
	// Build replacer pairs: secret1, <concealed>, secret2, <concealed>, ...
	var pairs []string
	maxLen := 0
	for _, s := range secrets {
		if s != "" {
			pairs = append(pairs, s, "<concealed>")
			if len(s) > maxLen {
				maxLen = len(s)
			}
		}
	}
	return &maskingWriter{
		w:            w,
		replacer:     strings.NewReplacer(pairs...),
		maxSecretLen: maxLen,
	}
}

func (m *maskingWriter) Write(p []byte) (n int, err error) {
	// If no secrets to mask, write everything
	if m.maxSecretLen == 0 {
		return m.w.Write(p)
	}

	m.buf = append(m.buf, p...)

	// Replace all complete secrets in the buffer
	m.buf = []byte(m.replacer.Replace(string(m.buf)))

	// Keep the last maxSecretLen-1 bytes (could be start of a secret)
	// Everything before that is safe to write
	safeLen := len(m.buf) - m.maxSecretLen + 1
	if safeLen <= 0 {
		return len(p), nil
	}

	if _, err := m.w.Write(m.buf[:safeLen]); err != nil {
		return len(p), err
	}

	m.buf = m.buf[safeLen:]
	return len(p), nil
}

func (m *maskingWriter) Close() error {
	if len(m.buf) == 0 {
		return nil
	}
	_, err := m.w.Write([]byte(m.replacer.Replace(string(m.buf))))
	m.buf = nil
	return err
}

func printRunUsage() {
	fmt.Fprintln(os.Stderr, "Usage: opcli run [--env-file=<file>]... [--no-masking] -- <command>...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run a command with secrets loaded as environment variables.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Scans environment variables for op:// secret references and resolves them")
	fmt.Fprintln(os.Stderr, "before running the command. Secrets in stdout/stderr are masked by default.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --env-file <file>  Load environment from a dotenv file (can be repeated)")
	fmt.Fprintln(os.Stderr, "  --no-masking       Show secrets in command output (don't mask)")
	fmt.Fprintln(os.Stderr, "  -h, --help         Show this help message")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment file precedence:")
	fmt.Fprintln(os.Stderr, "  - Later --env-file arguments override earlier ones")
	fmt.Fprintln(os.Stderr, "  - Env files override shell environment variables")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Variable substitution:")
	fmt.Fprintln(os.Stderr, "  Secret references can use $VAR syntax: op://$VAULT/item/field")
}

// readSecret reads a secret value from a URI using an already-opened vault keychain.
func readSecret(vk *VaultKeychain, uri string) (string, error) {
	vaultName, itemName, sectionName, fieldName, err := parseOPURI(uri)
	if err != nil {
		return "", err
	}

	vaultUUID, err := vk.findVaultByName(vaultName)
	if err != nil {
		return "", err
	}

	item, err := vk.findItemByName(vaultUUID, itemName)
	if err != nil {
		return "", err
	}

	detail, err := getItemDetail(vk.db, item.ID)
	if err != nil {
		return "", err
	}

	decryptedItem, err := vk.decryptDetail(vaultUUID, &detail.EncDetails)
	if err != nil {
		return "", err
	}

	return findField(decryptedItem, sectionName, fieldName)
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
