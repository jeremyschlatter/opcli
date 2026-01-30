package main

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>

// Helper to create CFString from C string
static CFStringRef createCFString(const char *s) {
    return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

// Note: We use the legacy SecAccess/SecTrustedApplication APIs because they're
// the only way to set app-specific ACLs for Developer ID signed CLI tools.
// The modern Data Protection Keychain requires App Store entitlements.
// These APIs are deprecated but still functional.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Get path to current executable
static char* getExecutablePath() {
    static char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) {
        return NULL;
    }
    // Resolve symlinks to get the real path
    char *resolved = realpath(path, NULL);
    return resolved ? resolved : strdup(path);
}

// Create access control that restricts to current application
static SecAccessRef createAppOnlyAccess(const char *label) {
    SecAccessRef access = NULL;
    SecTrustedApplicationRef trustedApp = NULL;

    char *exePath = getExecutablePath();
    if (exePath == NULL) {
        return NULL;
    }

    OSStatus status = SecTrustedApplicationCreateFromPath(exePath, &trustedApp);
    free(exePath);

    if (status != errSecSuccess || trustedApp == NULL) {
        return NULL;
    }

    CFArrayRef trustedApps = CFArrayCreate(NULL, (const void **)&trustedApp, 1, &kCFTypeArrayCallBacks);
    CFStringRef labelRef = createCFString(label);

    status = SecAccessCreate(labelRef, trustedApps, &access);

    CFRelease(labelRef);
    CFRelease(trustedApps);
    CFRelease(trustedApp);

    if (status != errSecSuccess) {
        return NULL;
    }

    return access;
}

#pragma clang diagnostic pop

// Defined in touchid.m, linked via libtouchid.a
extern int authenticateTouchID(const char *reason);

// Add or update a keychain item with app-only access
static OSStatus keychainSet(const char *service, const char *account, const char *password, int passwordLen) {
    CFStringRef serviceRef = createCFString(service);
    CFStringRef accountRef = createCFString(account);
    CFDataRef passwordRef = CFDataCreate(NULL, (const UInt8 *)password, passwordLen);

    // Delete existing item first to reset ACL
    CFMutableDictionaryRef deleteQuery = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(deleteQuery, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(deleteQuery, kSecAttrService, serviceRef);
    CFDictionarySetValue(deleteQuery, kSecAttrAccount, accountRef);
    SecItemDelete(deleteQuery);
    CFRelease(deleteQuery);

    // Create app-only access
    SecAccessRef access = createAppOnlyAccess("opcli credentials");

    // Add new item
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceRef);
    CFDictionarySetValue(query, kSecAttrAccount, accountRef);
    CFDictionarySetValue(query, kSecValueData, passwordRef);
    if (access != NULL) {
        CFDictionarySetValue(query, kSecAttrAccess, access);
    }

    OSStatus status = SecItemAdd(query, NULL);

    CFRelease(query);
    if (access) CFRelease(access);
    CFRelease(serviceRef);
    CFRelease(accountRef);
    CFRelease(passwordRef);

    return status;
}


// Get a keychain item
// Returns the password in *outPassword (caller must free) and length in *outLen
// Returns errSecSuccess on success
static OSStatus keychainGet(const char *service, const char *account, char **outPassword, int *outLen) {
    CFStringRef serviceRef = createCFString(service);
    CFStringRef accountRef = createCFString(account);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceRef);
    CFDictionarySetValue(query, kSecAttrAccount, accountRef);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFDataRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);

    if (status == errSecSuccess && result != NULL) {
        CFIndex len = CFDataGetLength(result);
        *outLen = (int)len;
        *outPassword = (char *)malloc(len);
        memcpy(*outPassword, CFDataGetBytePtr(result), len);
        CFRelease(result);
    }

    CFRelease(query);
    CFRelease(serviceRef);
    CFRelease(accountRef);

    return status;
}


// Delete a keychain item
static OSStatus keychainDelete(const char *service, const char *account) {
    CFStringRef serviceRef = createCFString(service);
    CFStringRef accountRef = createCFString(account);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceRef);
    CFDictionarySetValue(query, kSecAttrAccount, accountRef);

    OSStatus status = SecItemDelete(query);

    CFRelease(query);
    CFRelease(serviceRef);
    CFRelease(accountRef);

    return status;
}
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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
}

// StoredAccount holds credentials for a single account.
type StoredAccount struct {
	SecretKey string `json:"secret_key"`
	Password  string `json:"password"`
	Shorthand string `json:"shorthand"`
	Email     string `json:"email"`
	URL       string `json:"url"` // sign-in URL
}

// keychainSet stores a value in the keychain (no biometric)
func keychainSet(account, password string) error {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	status := C.keychainSet(cService, cAccount, cPassword, C.int(len(password)))
	if status != 0 {
		return fmt.Errorf("keychain error: OSStatus %d", status)
	}
	return nil
}


// keychainGet retrieves a value from the keychain
func keychainGet(account string) (string, error) {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	var outPassword *C.char
	var outLen C.int

	var t0 time.Time
	if os.Getenv("OPCLI_TIMING") != "" {
		t0 = time.Now()
	}
	status := C.keychainGet(cService, cAccount, &outPassword, &outLen)
	if os.Getenv("OPCLI_TIMING") != "" {
		fmt.Fprintf(os.Stderr, "      [keychainGet %q: %.2fms]\n", account, float64(time.Since(t0).Microseconds())/1000)
	}
	if status != 0 {
		if status == -25300 { // errSecItemNotFound
			return "", fmt.Errorf("not found in keychain")
		}
		return "", fmt.Errorf("keychain error: OSStatus %d", status)
	}

	result := C.GoStringN(outPassword, outLen)
	C.free(unsafe.Pointer(outPassword))
	return result, nil
}

// keychainDelete removes a value from the keychain
func keychainDelete(account string) error {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	status := C.keychainDelete(cService, cAccount)
	if status != 0 && status != -25300 { // ignore errSecItemNotFound
		return fmt.Errorf("keychain error: OSStatus %d", status)
	}
	return nil
}

// loadCredentialStore loads the credential store from keychain.
// Returns an empty store if no credentials exist yet.
func loadCredentialStore() (*CredentialStore, error) {
	data, err := keychainGet(keychainCredentials)
	if err != nil {
		// Not found is expected for fresh installs
		if strings.Contains(err.Error(), "not found") {
			return &CredentialStore{Accounts: make(map[string]*StoredAccount)}, nil
		}
		return nil, err
	}

	var store CredentialStore
	if err := json.Unmarshal([]byte(data), &store); err != nil {
		return nil, fmt.Errorf("failed to parse credential store: %w", err)
	}

	if store.Accounts == nil {
		store.Accounts = make(map[string]*StoredAccount)
	}
	return &store, nil
}

// saveCredentialStore saves the credential store to keychain.
func saveCredentialStore(store *CredentialStore) error {
	data, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	return keychainSet(keychainCredentials, string(data))
}

// StoreCredentials stores credentials for an account.
// Sets this account as default if it's the first or only account.
func StoreCredentials(accountUUID, secretKey, masterPassword, shorthand, email, signInURL string) error {
	store, err := loadCredentialStore()
	if err != nil {
		return err
	}

	store.Accounts[accountUUID] = &StoredAccount{
		SecretKey: secretKey,
		Password:  masterPassword,
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

// GetCredentials retrieves credentials for an account by UUID.
func GetCredentials(accountUUID string) (secretKey, masterPassword string, err error) {
	store, err := loadCredentialStore()
	if err != nil {
		return "", "", err
	}

	acct, ok := store.Accounts[accountUUID]
	if !ok {
		return "", "", fmt.Errorf("account not found: %s", accountUUID)
	}

	return acct.SecretKey, acct.Password, nil
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

	// Check exact UUID match
	if acct, ok := store.Accounts[identifier]; ok {
		return acct, identifier, nil
	}

	// Check shorthand, email, or URL
	identifier = strings.ToLower(identifier)
	for uuid, acct := range store.Accounts {
		if strings.ToLower(acct.Shorthand) == identifier ||
			strings.ToLower(acct.Email) == identifier ||
			strings.Contains(strings.ToLower(acct.URL), identifier) {
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

// AuthenticateBiometric prompts for Touch ID or password using LAContext.
func AuthenticateBiometric(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	if C.authenticateTouchID(cReason) != 0 {
		return fmt.Errorf("authentication failed or cancelled")
	}
	return nil
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
	return keychainDelete(keychainCredentials)
}

// GetSessionSecret retrieves or creates a session secret for HMAC verification.
// Uses a fixed key since all accounts share the same keychain entry.
func GetSessionSecret() ([]byte, error) {
	store, err := loadCredentialStore()
	if err != nil {
		return nil, err
	}

	// Use a hash of all account UUIDs as the secret base
	// This changes if accounts change, invalidating old sessions
	h := make([]byte, 32)
	for uuid := range store.Accounts {
		for i, b := range []byte(uuid) {
			h[i%32] ^= b
		}
	}
	return h, nil
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
