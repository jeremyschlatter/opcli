package main

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Defined in touchid.m, linked via libtouchid.a
extern int authenticateTouchID(const char *reason, const char *payloadJSON,
                               const void *iconPNG, int iconPNGLen, void **keyContext);

// opcli keeps its keychain items in the data protection keychain, in the
// access group named by the binary's keychain-access-groups entitlement
// (macos/*.entitlements). macOS only honors that entitlement on a binary that
// is signed and carries a matching provisioning profile, which is why opcli
// ships as opcli.app. Any other process asking for these items is told they
// don't exist: no prompt, so nothing for the user to approve by mistake.
//
// Queries never name the access group. An add lands in the first group of the
// entitlement, and a search covers every group the binary has, so the code is
// the same for release builds and test builds, which are signed into
// different groups.
//
// `legacy` selects the login keychain instead, where opcli up to v0.22 kept
// its item behind an app ACL. Only the migration in loadCredentialStore uses
// it. It has to name that keychain: in an entitled binary, a query that names
// none searches the data protection keychain first. Without a login keychain
// (errSecNoDefaultKeychain) it returns NULL and sets *status.
static CFMutableDictionaryRef keychainQuery(const char *service, const char *account, int legacy, OSStatus *status) {
    SecKeychainRef loginKeychain = NULL;
    if (legacy) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        *status = SecKeychainCopyDefault(&loginKeychain);
#pragma clang diagnostic pop
        if (*status != errSecSuccess) {
            return NULL;
        }
    }
    CFStringRef serviceRef = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef accountRef = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceRef);
    CFDictionarySetValue(query, kSecAttrAccount, accountRef);
    if (legacy) {
        CFArrayRef searchList = CFArrayCreate(NULL, (const void **)&loginKeychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(query, kSecMatchSearchList, searchList);
        CFRelease(searchList);
        CFRelease(loginKeychain);
    } else {
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
    }
    CFRelease(serviceRef);
    CFRelease(accountRef);
    return query;
}

// Add or update a keychain item.
//
// Updates in place when the item exists (atomic at the securityd level:
// concurrent readers see either old or new data, never "not found"), and adds
// it otherwise. Delete + add would leave a window where concurrent readers
// see errSecItemNotFound.
static OSStatus keychainSet(const char *service, const char *account, const char *password, int passwordLen) {
    OSStatus status;
    CFMutableDictionaryRef query = keychainQuery(service, account, 0, &status);
    CFDataRef passwordRef = CFDataCreate(NULL, (const UInt8 *)password, passwordLen);
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecValueData, passwordRef);

    status = SecItemUpdate(query, attrs);
    if (status == errSecItemNotFound) {
        CFDictionarySetValue(query, kSecValueData, passwordRef);
        CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
        status = SecItemAdd(query, NULL);
        CFDictionaryRemoveValue(query, kSecValueData);
        CFDictionaryRemoveValue(query, kSecAttrAccessible);
        // Another writer created the item between our update and our add.
        if (status == errSecDuplicateItem) {
            status = SecItemUpdate(query, attrs);
        }
    }

    CFRelease(attrs);
    CFRelease(passwordRef);
    CFRelease(query);
    return status;
}

// Get a keychain item
// Returns the password in *outPassword (caller must free) and length in *outLen
// Returns errSecSuccess on success
static OSStatus keychainGet(const char *service, const char *account, int legacy, char **outPassword, int *outLen) {
    OSStatus status;
    CFMutableDictionaryRef query = keychainQuery(service, account, legacy, &status);
    if (query == NULL) {
        return status;
    }
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFDataRef result = NULL;
    status = SecItemCopyMatching(query, (CFTypeRef *)&result);

    if (status == errSecSuccess && result != NULL) {
        CFIndex len = CFDataGetLength(result);
        *outLen = (int)len;
        *outPassword = (char *)malloc(len);
        memcpy(*outPassword, CFDataGetBytePtr(result), len);
        CFRelease(result);
    }

    CFRelease(query);
    return status;
}

// Delete a keychain item
static OSStatus keychainDelete(const char *service, const char *account, int legacy) {
    OSStatus status;
    CFMutableDictionaryRef query = keychainQuery(service, account, legacy, &status);
    if (query == NULL) {
        return status;
    }
    if (legacy) {
        // SecItemDelete refuses a login keychain item found through a search
        // list (errSecInvalidOwnerEdit), so look the item up and delete that.
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFTypeRef item = NULL;
        status = SecItemCopyMatching(query, &item);
        if (status == errSecSuccess) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            status = SecKeychainItemDelete((SecKeychainItemRef)item);
#pragma clang diagnostic pop
            CFRelease(item);
        }
    } else {
        status = SecItemDelete(query);
    }
    CFRelease(query);
    return status;
}
*/
import "C"
import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

var keychainService = "opcli"

const keychainCredentials = "credentials"

// CredentialStore holds all account credentials in a single keychain entry.
type CredentialStore struct {
	Accounts map[string]*StoredAccount `json:"accounts"` // keyed by account UUID
	Default  string                    `json:"default"`  // UUID of default account

	SessionSecret string `json:"session_secret,omitempty"` // base64 HMAC key for sessions.json; see GetSessionSecret

	NoKeyCache bool `json:"no_key_cache,omitempty"` // Secure Enclave mode only: see storeSealedCredentials
}

// StoredAccount holds credentials for a single account.
type StoredAccount struct {
	SecretKey string `json:"secret_key,omitempty"` // legacy; now read from 1Password DB
	Password  string `json:"password"`
	Shorthand string `json:"shorthand"`
	Email     string `json:"email"`
	URL       string `json:"url"` // sign-in URL

	// Cached derived symmetric key (avoids PBKDF2 on each run)
	SymKeyCacheKey string `json:"symkey_cache_key,omitempty"` // keyset UUID + salt for invalidation
	SymKey         string `json:"symkey,omitempty"`           // base64-encoded symmetric key
}

var errKeychainNotFound = errors.New("not found in keychain")

// testKeychainDir, which only test builds set, swaps the keychain for plain
// files in that directory. The real keychain is out of reach of a binary that
// isn't signed into opcli's access group, and tests should run without the
// signing key. CI has the key, and runs the same tests against the keychain.
var testKeychainDir string

// testKeychainStatus, set only in test builds, makes the files above answer
// every read with this OSStatus instead, as a keychain that isn't there would.
var testKeychainStatus int

func testKeychainPath(account string) string {
	return filepath.Join(testKeychainDir, "keychain-"+keychainService+"."+account)
}

func keychainError(status C.OSStatus) error {
	switch status {
	case 0:
		return nil
	case -25300, // errSecItemNotFound
		-25307: // errSecNoDefaultKeychain: no login keychain, so nothing in it
		return errKeychainNotFound
	case -34018: // errSecMissingEntitlement
		return fmt.Errorf("keychain error: this opcli binary lacks the keychain-access-groups entitlement (it must be signed and run from opcli.app; see `make sign`)")
	}
	return fmt.Errorf("keychain error: OSStatus %d", status)
}

// keychainSet stores a value in the keychain (no biometric)
func keychainSet(account, password string) error {
	if testKeychainDir != "" {
		// Write then rename, so that a concurrent reader never sees half a file.
		path := testKeychainPath(account)
		tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
		if err := os.WriteFile(tmp, []byte(password), 0600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}

	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	return keychainError(C.keychainSet(cService, cAccount, cPassword, C.int(len(password))))
}

// keychainGet retrieves a value from the keychain, or from the login keychain
// of opcli ≤ v0.22 when legacy is set.
func keychainGet(account string, legacy bool) (string, error) {
	if testKeychainDir != "" {
		if testKeychainStatus != 0 {
			return "", keychainError(C.OSStatus(testKeychainStatus))
		}
		if legacy {
			return "", errKeychainNotFound
		}
		data, err := os.ReadFile(testKeychainPath(account))
		if os.IsNotExist(err) {
			return "", errKeychainNotFound
		}
		return string(data), err
	}

	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	var cLegacy C.int
	if legacy {
		cLegacy = 1
	}

	var outPassword *C.char
	var outLen C.int

	var t0 time.Time
	if os.Getenv("OPCLI_TIMING") != "" {
		t0 = time.Now()
	}
	status := C.keychainGet(cService, cAccount, cLegacy, &outPassword, &outLen)
	if os.Getenv("OPCLI_TIMING") != "" {
		fmt.Fprintf(os.Stderr, "      [keychainGet %q: %.2fms]\n", account, float64(time.Since(t0).Microseconds())/1000)
	}
	if err := keychainError(status); err != nil {
		return "", err
	}

	result := C.GoStringN(outPassword, outLen)
	C.free(unsafe.Pointer(outPassword))
	return result, nil
}

// keychainDelete removes a value from the keychain. Deleting what isn't there
// is not an error.
func keychainDelete(account string, legacy bool) error {
	if testKeychainDir != "" {
		if legacy {
			return nil
		}
		if err := os.Remove(testKeychainPath(account)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	var cLegacy C.int
	if legacy {
		cLegacy = 1
	}

	if err := keychainError(C.keychainDelete(cService, cAccount, cLegacy)); err != nil && err != errKeychainNotFound {
		return err
	}
	return nil
}

// GetCachedSymKey retrieves a cached derived symmetric key.
// Returns the key if cacheKey matches the stored cache key, otherwise error.
func GetCachedSymKey(accountUUID, cacheKey string) ([]byte, error) {
	if sealedMode() {
		return sealedCachedSymKey(accountUUID, cacheKey)
	}
	store, err := loadCredentialStore()
	if err != nil {
		return nil, err
	}
	acct, ok := store.Accounts[accountUUID]
	if !ok || acct.SymKeyCacheKey != cacheKey || acct.SymKey == "" {
		return nil, fmt.Errorf("cache miss")
	}
	return base64.StdEncoding.DecodeString(acct.SymKey)
}

// SetCachedSymKey stores a derived symmetric key in the credential store.
func SetCachedSymKey(accountUUID, cacheKey string, key []byte) error {
	if sealedMode() {
		return setSealedCachedSymKey(accountUUID, cacheKey, key)
	}
	store, err := loadCredentialStore()
	if err != nil {
		return err
	}
	acct, ok := store.Accounts[accountUUID]
	if !ok {
		return fmt.Errorf("account not found")
	}
	acct.SymKeyCacheKey = cacheKey
	acct.SymKey = base64.StdEncoding.EncodeToString(key)
	return saveCredentialStore(store)
}

// cachedCredentialStore caches the credential store for the lifetime of the process
var cachedCredentialStore *CredentialStore

// loadCredentialStore loads the credential store from keychain.
// Returns an empty store if no credentials exist yet.
// Results are cached for the lifetime of the process.
func loadCredentialStore() (*CredentialStore, error) {
	if cachedCredentialStore != nil {
		return cachedCredentialStore, nil
	}
	if sealedMode() {
		store, err := loadSealedStore()
		if err != nil {
			return nil, err
		}
		cachedCredentialStore = store
		return store, nil
	}

	data, err := keychainGet(keychainCredentials, false)
	if err == errKeychainNotFound {
		// opcli up to v0.22 kept the store in the login keychain. Move it over.
		// That item's ACL admits code signed as "opcli" by the same team, which
		// this binary still is (see scripts/bundle), so macOS doesn't prompt.
		data, err = keychainGet(keychainCredentials, true)
		if err == errKeychainNotFound {
			// Fresh install.
			cachedCredentialStore = &CredentialStore{Accounts: make(map[string]*StoredAccount)}
			return cachedCredentialStore, nil
		}
		if err != nil {
			return nil, fmt.Errorf("migrating credentials from the login keychain: %w", err)
		}
		if err := keychainSet(keychainCredentials, data); err != nil {
			return nil, err
		}
		if err := keychainDelete(keychainCredentials, true); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	var store CredentialStore
	if err := json.Unmarshal([]byte(data), &store); err != nil {
		return nil, fmt.Errorf("failed to parse credential store: %w", err)
	}

	if store.Accounts == nil {
		store.Accounts = make(map[string]*StoredAccount)
	}
	cachedCredentialStore = &store
	return cachedCredentialStore, nil
}

// saveCredentialStore saves the credential store to keychain.
func saveCredentialStore(store *CredentialStore) error {
	if sealedMode() {
		return saveSealedStore(store)
	}
	data, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	if err := keychainSet(keychainCredentials, string(data)); err != nil {
		return err
	}
	cachedCredentialStore = store // update cache
	return nil
}

// StoreCredentials stores credentials for an account.
// Sets this account as default if it's the first or only account.
func StoreCredentials(accountUUID, accountPassword, shorthand, email, signInURL string) error {
	if sealedMode() {
		return storeSealedCredentials(accountUUID, accountPassword, shorthand, email, signInURL, false)
	}
	store, err := loadCredentialStore()
	if err != nil {
		return err
	}

	store.Accounts[accountUUID] = &StoredAccount{
		Password:  accountPassword,
		Shorthand: shorthand,
		Email:     email,
		URL:       signInURL,
	}

	// Set as default if first account or no default set
	if store.Default == "" || len(store.Accounts) == 1 {
		store.Default = accountUUID
	}

	return saveCredentialStore(store)
}

// GetPassword retrieves the account password for an account by UUID.
func GetPassword(accountUUID string) (string, error) {
	if sealedMode() {
		return sealedPassword(accountUUID)
	}
	store, err := loadCredentialStore()
	if err != nil {
		return "", err
	}

	acct, ok := store.Accounts[accountUUID]
	if !ok {
		return "", fmt.Errorf("account not found: %s", accountUUID)
	}

	return acct.Password, nil
}

// GetStoredAccounts returns all stored accounts.
func GetStoredAccounts() (*CredentialStore, error) {
	return loadCredentialStore()
}

// ResolveAccount finds an account by shorthand, UUID, email, or URL.
func ResolveAccount(identifier string) (*StoredAccount, string, error) {
	store, err := loadCredentialStore()
	if err != nil {
		return nil, "", err
	}
	return resolveAccountFromStore(store, identifier)
}

// resolveAccountFromStore finds an account in a pre-loaded credential store.
func resolveAccountFromStore(store *CredentialStore, identifier string) (*StoredAccount, string, error) {
	// Check exact UUID match
	if acct, ok := store.Accounts[identifier]; ok {
		return acct, identifier, nil
	}

	// Check shorthand, email, or URL
	for uuid, acct := range store.Accounts {
		if acct.Shorthand == identifier ||
			acct.Email == identifier ||
			strings.Contains(acct.URL, identifier) {
			return acct, uuid, nil
		}
	}

	return nil, "", fmt.Errorf("account not found: %s", identifier)
}

// GetDefaultAccount returns the default account UUID.
func GetDefaultAccount() (string, error) {
	store, err := loadCredentialStore()
	if err != nil {
		return "", err
	}

	if store.Default == "" {
		return "", fmt.Errorf("no default account configured")
	}

	if _, ok := store.Accounts[store.Default]; !ok {
		return "", fmt.Errorf("default account not found")
	}

	return store.Default, nil
}

// SetDefaultAccount sets the default account.
func SetDefaultAccount(accountUUID string) error {
	store, err := loadCredentialStore()
	if err != nil {
		return err
	}

	if _, ok := store.Accounts[accountUUID]; !ok {
		return fmt.Errorf("account not found: %s", accountUUID)
	}

	store.Default = accountUUID
	return saveCredentialStore(store)
}

// dockIconPNG is shown in the Dock while the authorization window is up.
//
//go:embed assets/logo.png
var dockIconPNG []byte

// ErrAuthRefused means Touch ID (or its password fallback) didn't authenticate:
// the user cancelled or failed, or macOS wouldn't show the prompt at all (for
// example while the screen is locked). opcli exits with exitAuthRefused for it,
// so callers can tell "nobody approved" from opcli being broken. git's signing
// wrapper (_git-sign in Jeremy's dev env) commits unsigned on it.
var ErrAuthRefused = errors.New("authentication failed or cancelled")

// AuthenticateBiometric prompts for Touch ID (or its password fallback) to
// approve reading refs, which are listed in a window around the prompt.
//
// Refs look like "op://[account:]vault/item/[section/]field". The window
// groups them by "[account:]vault": everything up to the first '/'.
//
// sc is the scope the approval will be kept for, which the window names, or
// nil if it won't be kept.
func AuthenticateBiometric(refs []string, sc *scope) error {
	if len(refs) == 0 {
		panic("AuthenticateBiometric: nothing to approve")
	}
	type group struct {
		Vault string   `json:"vault"`
		Refs  []string `json:"refs"`
	}
	byVault := make(map[string]*group)
	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		if seen[r] {
			continue
		}
		seen[r] = true
		vault, display := splitVaultAndDisplay(r)
		g, ok := byVault[vault]
		if !ok {
			g = &group{Vault: vault}
			byVault[vault] = g
		}
		g.Refs = append(g.Refs, display)
	}
	// Deterministic order: vaults sorted, refs within each vault sorted.
	groups := make([]*group, 0, len(byVault))
	for _, g := range byVault {
		sort.Strings(g.Refs)
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Vault < groups[j].Vault })
	payload := map[string]any{"groups": groups}
	if sealedMode() {
		return unsealFor("read "+strings.Join(slices.Sorted(maps.Keys(seen)), ", "), payload)
	}
	return touchID("access your 1Password credentials", payload, sc, nil)
}

// AuthenticateBiometricEverything prompts for Touch ID to approve reading
// every item of the given accounts (named however the user should see them).
// The window says so, and looks unlike the one for individual refs.
func AuthenticateBiometricEverything(accounts []string) error {
	if sealedMode() {
		return unsealFor("read EVERY item in your 1Password vaults ("+strings.Join(accounts, ", ")+")", map[string]any{"everything": accounts})
	}
	return touchID("read every item in your 1Password vaults", map[string]any{"everything": accounts}, nil, nil)
}

// touchID shows the Touch ID prompt inside the authorization window that
// touchid.m draws from payload, to which it adds who is asking, and the scope
// (if any) that the approval will be kept for:
//
//	{"command":"make deploy",
//	 "scope":{"agent":"claude","title":"Fix the deploy script","started":"3h ago",
//	          "noun":"this Claude Code session"},
//	 "groups":[{"vault":"Employee","refs":["Item A/field", ...]}, ...]}
//
// or, for access to everything, "everything":["account", ...] in place of
// "groups". reason is the text macOS shows if it falls back to its own dialog.
//
// keyCtx, if not nil, makes the approval one to use the Secure Enclave key,
// and receives the context to unseal with (nil if the Secure Enclave is to ask
// for itself).
func touchID(reason string, payload map[string]any, sc *scope, keyCtx *unsafe.Pointer) error {
	anchor := 0
	if sc != nil {
		anchor = sc.pid
		title, noun := sc.describe()
		started := ""
		if !sc.started.IsZero() {
			switch age := time.Since(sc.started); {
			case age < time.Minute:
				started = fmt.Sprintf("%ds ago", int(age.Seconds()))
			case age < time.Hour:
				started = fmt.Sprintf("%dm ago", int(age.Minutes()))
			case age < 48*time.Hour:
				started = fmt.Sprintf("%dh ago", int(age.Hours()))
			default:
				started = fmt.Sprintf("%dd ago", int(age.Hours()/24))
			}
		}
		payload["scope"] = map[string]string{"agent": sc.agent, "title": title, "started": started, "noun": noun}
	}
	payload["command"] = describeInvokingCommand(anchor)
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	cPayload := C.CString(string(data))
	defer C.free(unsafe.Pointer(cPayload))

	rc := C.authenticateTouchID(cReason, cPayload,
		unsafe.Pointer(&dockIconPNG[0]), C.int(len(dockIconPNG)), keyCtx)
	if rc != 0 {
		return ErrAuthRefused
	}
	return nil
}

// splitVaultAndDisplay separates an op:// ref into its "[account:]vault"
// group key and the remainder used as the in-group display string.
func splitVaultAndDisplay(ref string) (vault, display string) {
	path := strings.TrimPrefix(ref, "op://")
	slash := strings.Index(path, "/")
	if slash < 0 {
		return path, ""
	}
	return path[:slash], path[slash+1:]
}

// describeInvokingCommand walks up the process tree from our parent and
// returns a display string for the first non-shell, non-opcli ancestor —
// e.g. when a coding agent invokes `opcli read …` through a shell, we want
// to surface the agent's name ("claude deploy.sh"), not the intermediate
// `sh -c …` or the outer login shell.
//
// The returned string basenames the first token (so "/usr/local/bin/claude"
// becomes "claude") and preserves any trailing args. Returns "" when only
// shells are found above us — e.g. when opcli is run directly at a prompt,
// there's no invoking command to surface. The walk stops at the process
// stopPid (the scope's anchor, which the window names separately).
func describeInvokingCommand(stopPid int) string {
	pid := os.Getppid()
	for i := 0; i < 16 && pid > 1 && pid != stopPid; i++ {
		cmd, ppid, ok := psLookup(pid)
		if !ok {
			return ""
		}
		name := baseCommandName(cmd)
		if !isShellCommand(name) && !isOpcliCommand(name) {
			return displayCommand(cmd)
		}
		pid = ppid
	}
	return ""
}

// displayCommand normalizes a full command line for display: basename the
// first token (the executable path) and keep the rest of argv as-is.
func displayCommand(cmd string) string {
	cmd = strings.TrimPrefix(cmd, "-")
	first, rest := cmd, ""
	if sp := strings.IndexByte(cmd, ' '); sp >= 0 {
		first, rest = cmd[:sp], cmd[sp:]
	}
	if slash := strings.LastIndexByte(first, '/'); slash >= 0 {
		first = first[slash+1:]
	}
	return first + rest
}

// psLookup returns (command, ppid) for pid via `ps`. ok=false on failure.
func psLookup(pid int) (string, int, bool) {
	out, err := exec.Command("ps", "-o", "ppid=,command=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err != nil {
		return "", 0, false
	}
	line := strings.TrimSpace(string(out))
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return "", 0, false
	}
	ppid, err := strconv.Atoi(line[:sp])
	if err != nil {
		return "", 0, false
	}
	cmd := strings.TrimSpace(line[sp+1:])
	return cmd, ppid, true
}

// baseCommandName returns the basename of the first token of a command line,
// with any leading '-' stripped (login shells come through as "-zsh" etc.).
func baseCommandName(cmd string) string {
	first := cmd
	if sp := strings.IndexByte(first, ' '); sp >= 0 {
		first = first[:sp]
	}
	first = strings.TrimPrefix(first, "-")
	if slash := strings.LastIndexByte(first, '/'); slash >= 0 {
		first = first[slash+1:]
	}
	return first
}

func isShellCommand(name string) bool {
	switch name {
	case "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "login":
		return true
	}
	return false
}

func isOpcliCommand(name string) bool {
	return name == "opcli" || name == "opcli-test"
}

// HasStoredCredentials checks if credentials exist for the account.
func HasStoredCredentials(accountUUID string) bool {
	store, err := loadCredentialStore()
	if err != nil {
		return false
	}
	_, ok := store.Accounts[accountUUID]
	return ok
}

// DeleteCredentials removes credentials for an account.
func DeleteCredentials(accountUUID string) error {
	if sealedMode() {
		return deleteSealedCredentials(accountUUID)
	}
	store, err := loadCredentialStore()
	if err != nil {
		return err
	}

	delete(store.Accounts, accountUUID)

	// Update default if needed
	if store.Default == accountUUID {
		store.Default = ""
		// Set first remaining account as default
		for uuid := range store.Accounts {
			store.Default = uuid
			break
		}
	}

	return saveCredentialStore(store)
}

// DeleteAllCredentials removes all stored credentials.
func DeleteAllCredentials() error {
	if sealedMode() {
		return deleteAllSealedCredentials()
	}
	return keychainDelete(keychainCredentials, false)
}

// GetSessionSecret returns the key that authenticates entries in sessions.json,
// creating it on first use. It is random and lives in the credential store, so
// it sits in the same keychain access group as the account passwords:
// forging a session takes the same access as reading the passwords directly.
func GetSessionSecret() ([]byte, error) {
	store, err := loadCredentialStore()
	if err != nil {
		return nil, err
	}
	if store.SessionSecret == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		store.SessionSecret = base64.StdEncoding.EncodeToString(secret)
		if err := saveCredentialStore(store); err != nil {
			return nil, err
		}
	}
	return base64.StdEncoding.DecodeString(store.SessionSecret)
}

// ExtractShorthand extracts the shorthand from a sign-in URL.
// e.g., "https://my.1password.com" -> "my"
func ExtractShorthand(signInURL string) string {
	u, err := url.Parse(signInURL)
	if err != nil {
		return ""
	}
	host := u.Host
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	// Get subdomain (first part before .1password.com or similar)
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
