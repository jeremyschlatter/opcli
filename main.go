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
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

// AppKit requires GUI work to happen on pthread_main_np() — the process's
// initial OS thread. Go's main goroutine starts on that thread but the
// scheduler is free to migrate it at any blocking point. Locking the main
// goroutine to its starting thread keeps our cgo call into AppKit (from
// authenticateTouchID) on the right thread; without this lock we see
// intermittent SIGTRAPs inside `[NSApp run]` when the goroutine happens to
// have migrated to a non-main thread by the time we call into Cocoa.
func init() { runtime.LockOSThread() }

// Timing instrumentation (enabled via OPCLI_TIMING=1)
var timingEnabled = os.Getenv("OPCLI_TIMING") != ""

type timer struct {
	start  time.Time
	last   time.Time
	events []timerEvent
}

type timerEvent struct {
	name      string
	elapsed   time.Duration
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
	case "versioned-backup-poll":
		if err := cmdVersionedBackupPoll(); err != nil {
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
	fmt.Println("  opcli signin [--account <acct>]      - Store credentials in Keychain")
	fmt.Println("  opcli signout [--account <acct>]     - Remove credentials from Keychain")
	fmt.Println("  opcli read <op://vault/item/field>   - Read a field from an item")
	fmt.Println("  opcli read <op://vault/item/section/field>")
	fmt.Println("  opcli list [--account <acct>]        - List all vaults")
	fmt.Println("  opcli get <op://vault/item>          - Dump item as JSON")
	fmt.Println("  opcli inject [-i file] [-o file]     - Inject secrets into template")
	fmt.Println("  opcli run [--env-file=<file>]... [--tui] -- <command>")
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
	for i := range accounts {
		a := &accounts[i]
		if a.AccountUUID == accountFlag ||
			a.Email == accountFlag ||
			strings.Contains(a.URL, accountFlag) {
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

func cmdVersionedBackupPoll() error {
	os.Setenv(autoBackupDB, required)
	db, err := openDB()
	if err == nil {
		db.Close()
	}
	return err
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

	shorthand := ExtractShorthand(account.SignInURL)
	fmt.Fprintf(os.Stderr, "Signing in to: %s (%s)\n", account.UserEmail, shorthand)

	// Get secret key from database
	secretKey, err := getSecretKeyFromDB(db, dbAccount.AccountUUID)
	if err != nil {
		return fmt.Errorf("failed to read secret key from database: %w", err)
	}

	// Get account password
	fmt.Fprint(os.Stderr, "Enter account password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	password := string(pwBytes)

	// Verify credentials work before storing
	fmt.Fprintln(os.Stderr, "Verifying credentials...")
	vk, err := newAccountKeychain(db, password, secretKey, account.UserEmail, dbAccount.AccountUUID, dbAccount.AccountType, nil)
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}
	_ = vk // only used to verify credentials; db closed by defer

	// Store in keychain
	if err := StoreCredentials(dbAccount.AccountUUID, password, shorthand, account.UserEmail, account.SignInURL); err != nil {
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

// getCredentials gets the account password for an account, using session-based auth if available.
// pendingRefs lists the op:// references driving this authentication; they are
// displayed in a context window shown alongside the TouchID prompt.
func getCredentials(accountUUID string, pendingRefs []string) (password string, err error) {
	// Check for existing valid session
	session, _ := GetValidSession(accountUUID)

	pw, err := GetPassword(accountUUID)
	if err != nil {
		return "", fmt.Errorf("no account configured (run 'opcli signin' first)")
	}

	if session == nil {
		// No valid session - require biometric auth
		if err := AuthenticateBiometric("access your 1Password credentials", pendingRefs); err != nil {
			return "", fmt.Errorf("authentication failed: %w", err)
		}

		// When OPCLI_AUTO_ACCOUNT is enabled, create sessions for all stored accounts
		// so the user only needs to authenticate once via TouchID.
		if os.Getenv("OPCLI_AUTO_ACCOUNT") != "" {
			if store, err := GetStoredAccounts(); err == nil {
				for uuid := range store.Accounts {
					if _, err := CreateSession(uuid); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: could not create session for account: %v\n", err)
					}
				}
			}
		} else {
			// Create session for just this account
			if _, err := CreateSession(accountUUID); err != nil {
				// Non-fatal, continue without session
				fmt.Fprintf(os.Stderr, "Warning: could not create session: %v\n", err)
			}
		}
	}

	return pw, nil
}

// AccountKeychains manages lazily-opened account keychains sharing a single DB connection.
type AccountKeychains struct {
	getDB          func() (*sql.DB, error)     // lazy DB open (started in background by openKeychains)
	defaultAccount string                      // UUID of the default/flag-specified account
	accounts       map[string]*AccountKeychain // keyed by account UUID
	store          *CredentialStore
	pendingRefs    []string // op:// refs to show in the TouchID context window
}

func openKeychains(accountFlag string, t *timer) (*AccountKeychains, error) {
	// Start DB open in background
	dbCh := make(chan struct {
		*sql.DB
		error
	}, 1)
	go func() {
		db, err := openDB()
		dbCh <- struct {
			*sql.DB
			error
		}{db, err}
	}()

	// Meanwhile, do keychain operations (pays keychain cold-start cost in parallel with DB)
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
	if _, ok := store.Accounts[accountUUID]; !ok {
		return nil, fmt.Errorf("account not found in stored credentials (run 'opcli signin' first)")
	}
	if t != nil {
		t.mark("get stored accounts")
	}

	return &AccountKeychains{
		getDB: sync.OnceValues(func() (*sql.DB, error) {
			res := <-dbCh
			if t != nil {
				t.mark("open DB (parallel)")
			}
			return res.DB, res.error
		}),
		defaultAccount: accountUUID,
		accounts:       make(map[string]*AccountKeychain),
		store:          store,
	}, nil
}

// get returns the AccountKeychain for the given identifier (shorthand, UUID, email, or URL).
// Pass "" to get the default account. Lazily opens accounts on first access.
func (aks *AccountKeychains) get(identifier string, t *timer) (*AccountKeychain, error) {
	uuid := aks.defaultAccount
	if identifier != "" && identifier != uuid {
		// Resolve identifier to UUID
		_, resolved, err := resolveAccountFromStore(aks.store, identifier)
		if err != nil {
			return nil, err
		}
		uuid = resolved
	}

	if ak, ok := aks.accounts[uuid]; ok {
		return ak, nil
	}

	storedAcct, ok := aks.store.Accounts[uuid]
	if !ok {
		return nil, fmt.Errorf("account not found in stored credentials (run 'opcli signin' first)")
	}

	// Pass pending refs only when auth will actually be prompted (no valid
	// session). Once consumed, clear them so a second account lookup in the
	// same command doesn't reuse a stale list.
	var refsForAuth []string
	if session, _ := GetValidSession(uuid); session == nil {
		refsForAuth = aks.pendingRefs
		aks.pendingRefs = nil
	}

	password, err := getCredentials(uuid, refsForAuth)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("get credentials (session check)")
	}

	db, err := aks.getDB()
	if err != nil {
		return nil, err
	}

	accounts, err := getAccounts(db)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("get accounts")
	}

	var accountType string
	for _, a := range accounts {
		if a.AccountUUID == uuid {
			accountType = a.AccountType
			break
		}
	}

	secretKey, err := getSecretKeyFromDB(db, uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret key from database: %w", err)
	}
	if t != nil {
		t.mark("read secret key (DB)")
	}

	ak, err := newAccountKeychain(db, password, secretKey, storedAcct.Email, uuid, accountType, t)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark("init keychain (key derivation)")
	}

	aks.accounts[uuid] = ak
	return ak, nil
}

func (aks *AccountKeychains) Close() {
	if db, err := aks.getDB(); err == nil {
		db.Close()
	}
}

// AccountKeychain holds decrypted keys for accessing a single account's vault items.
type AccountKeychain struct {
	db              *sql.DB                    // borrowed from AccountKeychains
	accountUUID     string                     // 1Password account UUID
	accountType     string                     // I=Individual, F=Family, T=Teams, B=Business
	primaryKeysetID string                     // UUID of the primary keyset
	primarySymKey   []byte                     // Decrypted primary symmetric key
	keysetRSAKeys   map[string]*rsa.PrivateKey // keyset UUID -> RSA private key
	keysetSymKeys   map[string][]byte          // keyset UUID -> symmetric key
	keysetMu        sync.RWMutex               // protects keysetRSAKeys and keysetSymKeys
	vaultKeys       map[string][]byte          // vault UUID -> symmetric key
	vaultKeysMu     sync.RWMutex               // protects vaultKeys for concurrent access
}

func newAccountKeychain(db *sql.DB, password, secretKey, email, accountUUID, accountType string, t *timer) (*AccountKeychain, error) {
	vk := &AccountKeychain{
		db:            db,
		accountUUID:   accountUUID,
		accountType:   accountType,
		keysetRSAKeys: make(map[string]*rsa.PrivateKey),
		keysetSymKeys: make(map[string][]byte),
		vaultKeys:     make(map[string][]byte),
	}

	// Get primary keyset
	keyset, err := getPrimaryKeyset(db, accountUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary keyset: %w", err)
	}
	vk.primaryKeysetID = keyset.KeysetUUID
	if t != nil {
		t.mark("  get primary keyset (DB)")
	}

	// Try to use cached symmetric key (avoids expensive PBKDF2)
	// Cache key includes salt so it invalidates if credentials change
	cacheKey := keyset.KeysetUUID + "-" + keyset.EncSymKey.P2s
	if cached, err := GetCachedSymKey(accountUUID, cacheKey); err == nil {
		vk.primarySymKey = cached
		if t != nil {
			t.mark("  symmetric key (cached)")
		}
	} else {
		// Decrypt the symmetric key using 2SKD (PBKDF2 - expensive!)
		decryptedSymKeyJSON, err := decryptPBES2(&keyset.EncSymKey, secretKey, password, email)
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
		SetCachedSymKey(accountUUID, cacheKey, vk.primarySymKey)
	}
	vk.keysetSymKeys[keyset.KeysetUUID] = vk.primarySymKey

	// Decrypt the RSA private key
	decryptedPriKeyJSON, err := decryptEncryptedData(&keyset.EncPriKey, vk.primarySymKey)
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

// getKeysetRSAKey returns the RSA private key for a keyset, decrypting it if needed
func (vk *AccountKeychain) getKeysetRSAKey(keysetUUID string) (*rsa.PrivateKey, error) {
	// Check cache with read lock
	vk.keysetMu.RLock()
	if rsaKey, ok := vk.keysetRSAKeys[keysetUUID]; ok {
		vk.keysetMu.RUnlock()
		return rsaKey, nil
	}
	// Get parent RSA key while holding read lock (primary is always available)
	parentRSA := vk.keysetRSAKeys[vk.primaryKeysetID]
	vk.keysetMu.RUnlock()

	// Get the keyset (no lock needed for DB read)
	keyset, err := getKeyset(vk.db, vk.accountUUID, keysetUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get keyset %s: %w", keysetUUID, err)
	}

	// Non-primary keysets need their parent's RSA key
	if keyset.EncryptedBy != vk.primaryKeysetID {
		vk.keysetMu.RLock()
		var ok bool
		parentRSA, ok = vk.keysetRSAKeys[keyset.EncryptedBy]
		vk.keysetMu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("cannot decrypt keyset %s: parent keyset %s unavailable",
				keysetUUID, keyset.EncryptedBy)
		}
	}

	// Decrypt sym key using primary RSA (no lock needed for decryption)
	symKeyData, err := base64URLDecode(keyset.EncSymKey.Data)
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

	// Decrypt the RSA private key
	decryptedPriKeyJSON, err := decryptEncryptedData(&keyset.EncPriKey, symKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keyset private key: %w", err)
	}

	rsaKey, err := parseRSAPrivateKey(decryptedPriKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyset RSA key: %w", err)
	}

	// Cache result (write lock)
	vk.keysetMu.Lock()
	vk.keysetSymKeys[keysetUUID] = symKey
	vk.keysetRSAKeys[keysetUUID] = rsaKey
	vk.keysetMu.Unlock()

	return rsaKey, nil
}

// getVaultKey retrieves or decrypts the vault key for the given vault UUID
func (vk *AccountKeychain) getVaultKey(vaultUUID string) ([]byte, error) {
	// Check cache first (read lock)
	vk.vaultKeysMu.RLock()
	if key, ok := vk.vaultKeys[vaultUUID]; ok {
		vk.vaultKeysMu.RUnlock()
		return key, nil
	}
	vk.vaultKeysMu.RUnlock()

	// Get vault data
	vault, err := getVaultByUUID(vk.db, vk.accountUUID, vaultUUID)
	if err != nil {
		return nil, err
	}

	// Get the RSA key for the keyset that encrypted this vault key
	rsaKey, err := vk.getKeysetRSAKey(vault.EncVaultKey.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get keyset RSA key: %w", err)
	}

	// Decrypt vault key using RSA-OAEP
	keyData, err := base64URLDecode(vault.EncVaultKey.Data)
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

	// Cache the key (write lock)
	vk.vaultKeysMu.Lock()
	vk.vaultKeys[vaultUUID] = key
	vk.vaultKeysMu.Unlock()

	return key, nil
}

// decryptOverview decrypts an item overview using the vault key
func (vk *AccountKeychain) decryptOverview(vaultUUID string, encOverview *EncryptedData) (*DecryptedOverview, error) {
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
func (vk *AccountKeychain) decryptDetail(vaultUUID string, encDetails *EncryptedData) (*DecryptedItem, error) {
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
func (vk *AccountKeychain) decryptVaultName(v *Vault) (displayName, rawName string, err error) {
	key, err := vk.getVaultKey(v.VaultUUID)
	if err != nil {
		return "", "", err
	}

	attrsJSON, err := decryptEncryptedData(&v.EncAttrs, key)
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
func (vk *AccountKeychain) findVaultByName(vaultName string, displayOnly bool, t *timer) (string, error) {
	vaults, err := getVaults(vk.db, vk.accountUUID)
	if err != nil {
		return "", err
	}
	if t != nil {
		t.mark(fmt.Sprintf("    getVaults (%d vaults)", len(vaults)))
	}

	// Check for UUID match first (no decryption needed)
	for _, v := range vaults {
		if v.VaultUUID == vaultName {
			if t != nil {
				t.mark("    matched by UUID")
			}
			return v.VaultUUID, nil
		}
	}

	// Decrypt all vault names in parallel
	type vaultResult struct {
		index       int
		uuid        string
		displayName string
		rawName     string
	}
	results := make(chan vaultResult, len(vaults))
	for i, v := range vaults {
		go func(idx int, vault Vault) {
			displayName, rawName, err := vk.decryptVaultName(&vault)
			if err != nil {
				results <- vaultResult{index: idx}
				return
			}
			results <- vaultResult{idx, vault.VaultUUID, displayName, rawName}
		}(i, v)
	}

	// Collect results and check for match
	decrypted := make([]vaultResult, len(vaults))
	for range vaults {
		r := <-results
		decrypted[r.index] = r
	}
	if t != nil {
		t.mark(fmt.Sprintf("    decrypt %d vault names (parallel)", len(vaults)))
	}

	// Find match
	for _, r := range decrypted {
		if r.uuid != "" && (r.displayName == vaultName || !displayOnly && r.rawName == vaultName) {
			return r.uuid, nil
		}
	}

	return "", fmt.Errorf("vault not found: %s", vaultName)
}

// findItemByName finds an item in a vault by title or UUID.
func (vk *AccountKeychain) findItemByName(vaultUUID, itemName string, t *timer) (*Item, error) {
	items, err := getItems(vk.db, vk.accountUUID, vaultUUID)
	if err != nil {
		return nil, err
	}
	if t != nil {
		t.mark(fmt.Sprintf("    getItems (%d items)", len(items)))
	}

	for i := range items {
		overview, err := vk.decryptOverview(vaultUUID, &items[i].EncOverview)
		if err != nil {
			continue
		}

		if overview.Title == itemName || items[i].UUID == itemName {
			if t != nil {
				t.mark(fmt.Sprintf("    decrypt %d item overviews", i+1))
			}
			return &items[i], nil
		}
	}

	return nil, fmt.Errorf("item not found: %s", itemName)
}

func cmdRead(uri string, accountFlag string) error {
	t := newTimer()

	aks, err := openKeychains(accountFlag, t)
	if err != nil {
		return err
	}
	defer aks.Close()

	aks.pendingRefs = []string{uri}

	value, err := resolveRef(aks, uri, t)
	if err != nil {
		return err
	}

	fmt.Println(value)
	t.print()
	return nil
}

// resolveRef parses an op://[account:]vault/item/[section/]field URI and
// resolves it to a secret value.
func resolveRef(aks *AccountKeychains, uri string, t *timer) (string, error) {
	if !strings.HasPrefix(uri, "op://") {
		return "", fmt.Errorf("invalid URI: must start with op://")
	}
	path := uri[5:]

	// Extract optional account prefix (account:vault/...)
	var account string
	colon := strings.Index(path, ":")
	slash := strings.Index(path, "/")
	if colon != -1 && (slash == -1 || colon < slash) {
		account = path[:colon]
		path = path[colon+1:]
	}

	parts := strings.Split(path, "/")
	switch len(parts) {
	case 3:
		// vault/item/field
		return resolveRefFromAccount(aks, account, parts[0], parts[1], "", parts[2], t)
	case 4:
		// vault/item/section/field
		return resolveRefFromAccount(aks, account, parts[0], parts[1], parts[2], parts[3], t)
	default:
		return "", fmt.Errorf("invalid URI: expected op://[account:]vault/item/[section/]field")
	}
}

func resolveRefFromAccount(aks *AccountKeychains, account, vaultName, itemName, sectionName, fieldName string, t *timer) (string, error) {
	ak, err := aks.get(account, t)
	if err != nil {
		return "", err
	}
	autoAccount := account == "" && os.Getenv("OPCLI_AUTO_ACCOUNT") != ""
	vaultUUID, err := ak.findVaultByName(vaultName, autoAccount, t)
	if err != nil && autoAccount {
		// Vault not found in default account — try other signed-in accounts (display name only).
		var matches []struct {
			ak        *AccountKeychain
			vaultUUID string
		}
		for uuid := range aks.store.Accounts {
			if uuid == aks.defaultAccount {
				continue
			}
			otherAK, err2 := aks.get(uuid, t)
			if err2 != nil {
				continue
			}
			if vid, err2 := otherAK.findVaultByName(vaultName, true, t); err2 == nil {
				matches = append(matches, struct {
					ak        *AccountKeychain
					vaultUUID string
				}{otherAK, vid})
			}
		}
		switch len(matches) {
		case 0:
			return "", err // original error
		case 1:
			ak = matches[0].ak
			vaultUUID = matches[0].vaultUUID
			err = nil
		default:
			return "", fmt.Errorf("vault %q found in multiple accounts; specify account with op://account:%s/...", vaultName, vaultName)
		}
	}
	if err != nil {
		return "", err
	}
	item, err := ak.findItemByName(vaultUUID, itemName, t)
	if err != nil {
		return "", err
	}
	decryptedItem, err := ak.decryptDetail(vaultUUID, &item.EncDetails)
	if err != nil {
		return "", err
	}
	return findField(decryptedItem, sectionName, fieldName)
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

// fieldMatches checks if a field matches the given name (exact match).
func fieldMatches(f *Field, name string) bool {
	return f.FieldLabel() == name ||
		f.FieldID() == name ||
		f.Designation == name ||
		f.Name == name ||
		f.ID == name
}

// sectionMatches checks if a section matches the given name (exact match).
func sectionMatches(s *Section, name string) bool {
	return s.Name == name || s.Title == name
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

	// Fallback to extras (top-level keys) only when there's no fields array.
	// This handles Password items created without a username field, where
	// 1Password stores the password as a top-level JSON key instead.
	if len(matches) == 0 && len(item.Fields) == 0 {
		if v, ok := item.Extras[fieldName]; ok {
			matches = append(matches, match{value: v, section: ""})
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
	aks, err := openKeychains(accountFlag, nil)
	if err != nil {
		return err
	}
	defer aks.Close()

	ak, err := aks.get("", nil)
	if err != nil {
		return err
	}
	vaults, err := getVaults(ak.db, ak.accountUUID)
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

		displayName, _, err := ak.decryptVaultName(&v)
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

	aks, err := openKeychains(accountFlag, nil)
	if err != nil {
		return err
	}
	defer aks.Close()

	ak, err := aks.get("", nil) // default account
	if err != nil {
		return err
	}
	vaultUUID, err := ak.findVaultByName(vaultName, false, nil)
	if err != nil {
		return err
	}

	item, err := ak.findItemByName(vaultUUID, itemName, nil)
	if err != nil {
		return err
	}

	key, err := ak.getVaultKey(vaultUUID)
	if err != nil {
		return err
	}

	decrypted, err := decryptEncryptedData(&item.EncDetails, key)
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
	pattern := regexp.MustCompile(`\{\{\s*(op://[^}]*[^\s}])\s*\}\}|(op://(?:[a-zA-Z0-9_.-]+:)?[a-zA-Z0-9_./ -]*[a-zA-Z0-9_./-])`)
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

	// Open keychains for all lookups
	aks, err := openKeychains(accountFlag, nil)
	if err != nil {
		return err
	}
	defer aks.Close()

	for uri := range uris {
		aks.pendingRefs = append(aks.pendingRefs, uri)
	}

	// Resolve all secrets
	secrets := make(map[string]string)
	for uri := range uris {
		value, err := resolveRef(aks, uri, nil)
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
	var noMasking, tui bool
	var cmdArgs []string

	// Parse flags until we hit -- or a non-flag argument
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
		} else if arg == "--tui" {
			tui = true
		} else if strings.HasPrefix(arg, "-") {
			return 0, fmt.Errorf("unknown flag: %s", arg)
		} else {
			cmdArgs = args[i:]
			break
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

	// Check if arg substitution is enabled
	substituteArgs := env["OPCLI_RUN_SUBSTITUTE_ARGS"] == "1" || strings.EqualFold(env["OPCLI_RUN_SUBSTITUTE_ARGS"], "true")

	// Collect op:// references in args if substitution is enabled
	var argsHaveRefs bool
	if substituteArgs {
		for _, arg := range cmdArgs {
			if strings.Contains(arg, "op://") {
				argsHaveRefs = true
				break
			}
		}
	}

	// Resolve secrets if any
	var secretValues []string
	if len(secretRefs) > 0 || argsHaveRefs {
		aks, err := openKeychains(accountFlag, nil)
		if err != nil {
			return 0, err
		}

		for _, uri := range secretRefs {
			aks.pendingRefs = append(aks.pendingRefs, uri)
		}
		if argsHaveRefs {
			opRefPattern := regexp.MustCompile(`op://(?:[a-zA-Z0-9_.-]+:)?[a-zA-Z0-9_./ -]*[a-zA-Z0-9_./-]`)
			for _, arg := range cmdArgs {
				aks.pendingRefs = append(aks.pendingRefs, opRefPattern.FindAllString(arg, -1)...)
			}
		}

		for name, uri := range secretRefs {
			value, err := resolveRef(aks, uri, nil)
			if err != nil {
				aks.Close()
				return 0, fmt.Errorf("failed to resolve %s: %w", name, err)
			}
			secretValues = append(secretValues, value)
			env[name] = value
		}

		if argsHaveRefs {
			// Same pattern as inject's bare ref matching
			opRefPattern := regexp.MustCompile(`op://(?:[a-zA-Z0-9_.-]+:)?[a-zA-Z0-9_./ -]*[a-zA-Z0-9_./-]`)
			for i, arg := range cmdArgs {
				refs := opRefPattern.FindAllString(arg, -1)
				if len(refs) == 0 {
					continue
				}
				// Resolve each ref and collect for masking
				resolved := arg
				for _, uri := range refs {
					value, err := resolveRef(aks, uri, nil)
					if err != nil {
						aks.Close()
						return 0, fmt.Errorf("failed to resolve arg %q: %w", uri, err)
					}
					secretValues = append(secretValues, value)
					resolved = strings.Replace(resolved, uri, value, 1)
				}
				cmdArgs[i] = resolved
			}
		}

		aks.Close()
	}

	// Build final environment slice
	var finalEnv []string
	for k, v := range env {
		finalEnv = append(finalEnv, k+"="+v)
	}

	if tui {
		// Exec into the command (replaces this process, so TUIs work)
		binary, err := exec.LookPath(cmdArgs[0])
		if err != nil {
			return 0, err
		}
		return 0, syscall.Exec(binary, cmdArgs, finalEnv)
	}

	// Fork+exec with secret masking
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = finalEnv
	cmd.Stdin = os.Stdin

	if noMasking || len(secretValues) == 0 {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		stdoutMask := newMaskingWriter(os.Stdout, secretValues)
		stderrMask := newMaskingWriter(os.Stderr, secretValues)
		cmd.Stdout = stdoutMask
		cmd.Stderr = stderrMask
		defer stdoutMask.Close()
		defer stderrMask.Close()
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	// Catch signals and forward them to the child. This prevents Go's
	// runtime from killing us before the child finishes its cleanup.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			cmd.Process.Signal(sig)
		}
	}()

	err := cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				// Child died from a signal — re-raise so our parent sees it too.
				sig := status.Signal()
				signal.Reset(sig)
				syscall.Kill(syscall.Getpid(), sig)
				return 128 + int(sig), nil
			}
			return exitErr.ExitCode(), nil
		}
		return 0, err
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

		// Strip surrounding quotes (double or single)
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}

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

type trieNode struct {
	children map[byte]*trieNode
}

// maskingWriter replaces secret values with <concealed by opcli> in output.
// It buffers data to handle secrets that might be split across Write calls.
type maskingWriter struct {
	w            io.Writer
	replacer     *strings.Replacer
	prefixTrie   *trieNode
	maxSecretLen int
	buf          []byte
}

func newMaskingWriter(w io.Writer, secrets []string) *maskingWriter {
	var pairs []string
	maxLen := 0
	root := &trieNode{children: make(map[byte]*trieNode)}
	for _, s := range secrets {
		if s != "" {
			pairs = append(pairs, s, "<concealed by opcli>")
			if len(s) > maxLen {
				maxLen = len(s)
			}
			node := root
			for i := range len(s) {
				if node.children[s[i]] == nil {
					node.children[s[i]] = &trieNode{children: make(map[byte]*trieNode)}
				}
				node = node.children[s[i]]
			}
		}
	}
	return &maskingWriter{
		w:            w,
		replacer:     strings.NewReplacer(pairs...),
		prefixTrie:   root,
		maxSecretLen: maxLen,
	}
}

func (m *maskingWriter) Write(p []byte) (n int, err error) {
	if m.maxSecretLen == 0 {
		return m.w.Write(p)
	}

	m.buf = append(m.buf, p...)
	m.buf = []byte(m.replacer.Replace(string(m.buf)))

	// Only hold back trailing bytes that could be the start of a secret.
	// Walk the trie for each suffix (longest first); stop at the first match.
	holdBack := 0
	maxCheck := m.maxSecretLen - 1
	if maxCheck > len(m.buf) {
		maxCheck = len(m.buf)
	}
	for suffixStart := len(m.buf) - maxCheck; suffixStart < len(m.buf) && holdBack == 0; suffixStart++ {
		node := m.prefixTrie
		for i := suffixStart; i < len(m.buf); i++ {
			node = node.children[m.buf[i]]
			if node == nil {
				break
			}
		}
		if node != nil {
			holdBack = len(m.buf) - suffixStart
		}
	}
	safeLen := len(m.buf) - holdBack
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
	fmt.Fprintln(os.Stderr, "Usage: opcli run [--env-file=<file>]... [--tui] [--no-masking] -- <command>...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run a command with secrets loaded as environment variables.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Scans environment variables for op:// secret references and resolves them")
	fmt.Fprintln(os.Stderr, "before running the command. Secrets in stdout/stderr are masked by default.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --env-file <file>  Load environment from a dotenv file (can be repeated)")
	fmt.Fprintln(os.Stderr, "  --tui              Exec into the command (for TUI apps like claude)")
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
