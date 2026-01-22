package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication -framework Foundation -L${SRCDIR} -ltouchid

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
	"fmt"
	"unsafe"
)

const (
	keychainService        = "opcli"
	keychainSecretKeyLabel = "secret-key"
	keychainPasswordLabel  = "master-password"
)

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

	status := C.keychainGet(cService, cAccount, &outPassword, &outLen)
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

// StoreCredentials stores the secret key and master password in the keychain.
// Credentials are protected by app-only ACL (only this signed binary can read).
func StoreCredentials(accountID, secretKey, masterPassword string) error {
	if err := keychainSet(accountID+"/"+keychainSecretKeyLabel, secretKey); err != nil {
		return fmt.Errorf("failed to store secret key: %w", err)
	}
	if err := keychainSet(accountID+"/"+keychainPasswordLabel, masterPassword); err != nil {
		return fmt.Errorf("failed to store master password: %w", err)
	}
	return nil
}

// GetCredentials retrieves the secret key and master password from the keychain.
func GetCredentials(accountID string) (secretKey, masterPassword string, err error) {
	secretKey, err = keychainGet(accountID + "/" + keychainSecretKeyLabel)
	if err != nil {
		return "", "", fmt.Errorf("failed to get secret key: %w", err)
	}
	masterPassword, err = keychainGet(accountID + "/" + keychainPasswordLabel)
	if err != nil {
		return "", "", fmt.Errorf("failed to get master password: %w", err)
	}
	return secretKey, masterPassword, nil
}

// AuthenticateBiometric prompts for Touch ID or password using LAContext.
func AuthenticateBiometric(accountID, reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	if C.authenticateTouchID(cReason) != 0 {
		return fmt.Errorf("authentication failed or cancelled")
	}
	return nil
}

// HasStoredCredentials checks if credentials exist for the account.
func HasStoredCredentials(accountID string) bool {
	_, err := keychainGet(accountID + "/" + keychainSecretKeyLabel)
	return err == nil
}

// DeleteCredentials removes credentials from the keychain.
func DeleteCredentials(accountID string) error {
	keychainDelete(accountID + "/" + keychainSecretKeyLabel)
	keychainDelete(accountID + "/" + keychainPasswordLabel)
	return nil
}
