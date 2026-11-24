package main

// Secure Enclave mode (opcli signin --secure-enclave): instead of a keychain
// item, the credentials are files in the data directory, each 0600:
//
//   - credentials.json: the CredentialStore, with no passwords or keys in it
//   - se-key: the handle of a Secure Enclave key that needs Touch ID to use;
//     only this Mac's Secure Enclave can do anything with it
//   - secrets.sealed: the account passwords and cached derived keys, sealed
//     to that key (see sep.swift)
//
// The Secure Enclave, not opcli, asks for Touch ID before it will unseal, so
// a re-signed or patched binary can read the passwords only with your finger.
// No keychain item means no access group, so this mode also works in a build
// that isn't signed with opcli's certificate.
//
// The keychain functions hand over to the ones here when sealedMode() is true,
// which is while se-key exists: from the first signin with --secure-enclave
// until signing out of the last account.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

const (
	sealedCredentialsFile = "credentials.json"
	sealedSecretsFile     = "secrets.sealed"
	seKeyFile             = "se-key"
)

// sealedSecrets are what secrets.sealed holds for one account.
type sealedSecrets struct {
	Password       string `json:"password"`
	SymKeyCacheKey string `json:"symkey_cache_key,omitempty"`
	SymKey         string `json:"symkey,omitempty"`
}

var (
	unsealed map[string]*sealedSecrets // by account UUID; nil until unseal
	sealPub  []byte                    // the Secure Enclave key's public key, from seCreate or seUnwrap
)

func dataFilePath(name string) (string, error) {
	dir, err := dataDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// sealedMode reports whether credentials are sealed to the Secure Enclave
// rather than kept in the keychain.
func sealedMode() bool {
	path, err := dataFilePath(seKeyFile)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// writeDataFile writes then renames, so that a concurrent reader never sees half a file.
func writeDataFile(name string, data []byte) error {
	dir, err := getDataDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readDataFile(name string) ([]byte, error) {
	path, err := dataFilePath(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// unseal asks the Secure Enclave to open secrets.sealed, which takes Touch ID.
// With a payload, the prompt is opcli's authorization window, drawn from it as
// in keychain mode; without one it is macOS's own, showing reason. Every call
// prompts, so a command that authorizes twice is asked twice, as it would be
// in keychain mode without a session.
func unseal(reason string, payload map[string]any) error {
	key, err := readDataFile(seKeyFile)
	if err != nil {
		return fmt.Errorf("reading sealed credentials (run 'opcli signin --secure-enclave'): %w", err)
	}
	blob, err := readDataFile(sealedSecretsFile)
	if err != nil {
		return fmt.Errorf("reading sealed credentials (run 'opcli signin --secure-enclave'): %w", err)
	}
	var ctx unsafe.Pointer
	if payload != nil {
		if err := touchID(reason, payload, nil, &ctx); err != nil {
			return err
		}
	}
	msg, pub, err := seUnwrap(key, blob, reason, ctx)
	if errors.Is(err, ErrAuthRefused) {
		return err
	} else if err != nil {
		dir, _ := dataDirPath()
		return fmt.Errorf("unsealing credentials: %w (if your Touch ID fingerprints changed, the key is gone for good: delete %s, %s and %s in %s and sign in again)",
			err, seKeyFile, sealedSecretsFile, sealedCredentialsFile, dir)
	}
	var secrets map[string]*sealedSecrets
	if err := json.Unmarshal(msg, &secrets); err != nil {
		return fmt.Errorf("failed to parse sealed credentials: %w", err)
	}
	unsealed, sealPub = secrets, pub
	return nil
}

// seal writes the unsealed secrets back. It needs only the public key, so it
// never prompts. That key came from the Secure Enclave, never from a file: one
// swapped in on disk would have opcli seal your password to someone else's key.
func seal() error {
	data, err := json.Marshal(unsealed)
	if err != nil {
		return err
	}
	blob, err := seWrap(sealPub, data)
	if err != nil {
		return err
	}
	return writeDataFile(sealedSecretsFile, blob)
}

func unsealFor(what string, payload map[string]any) error {
	reason := "unlock your 1Password account password to " + what
	if cmd := describeInvokingCommand(0); cmd != "" {
		reason += ", for " + cmd
	}
	return unseal(reason, payload)
}

func loadSealedStore() (*CredentialStore, error) {
	data, err := readDataFile(sealedCredentialsFile)
	if os.IsNotExist(err) {
		// A signin that didn't finish: sign in again.
		return &CredentialStore{Accounts: make(map[string]*StoredAccount)}, nil
	} else if err != nil {
		return nil, err
	}
	var store CredentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse credential store: %w", err)
	}
	if store.Accounts == nil {
		store.Accounts = make(map[string]*StoredAccount)
	}
	return &store, nil
}

func saveSealedStore(store *CredentialStore) error {
	data, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	if err := writeDataFile(sealedCredentialsFile, data); err != nil {
		return err
	}
	cachedCredentialStore = store
	return nil
}

// storeSealedCredentials is StoreCredentials for Secure Enclave mode. With no
// other account signed in, it makes a new Secure Enclave key, and needs no
// Touch ID; otherwise it unseals the other accounts' secrets first. noKeyCache
// keeps derived keys out of secrets.sealed from now on.
func storeSealedCredentials(accountUUID, accountPassword, shorthand, email, signInURL string, noKeyCache bool) error {
	store := &CredentialStore{Accounts: make(map[string]*StoredAccount)}
	if sealedMode() {
		var err error
		if store, err = loadSealedStore(); err != nil {
			return err
		}
	}

	others := false
	for uuid := range store.Accounts {
		others = others || uuid != accountUUID
	}
	if others {
		if unsealed == nil {
			if err := unsealFor("add "+email, nil); err != nil {
				return err
			}
		}
	} else {
		key, pub, err := seCreate()
		if err != nil {
			return err
		}
		if err := writeDataFile(seKeyFile, key); err != nil {
			return err
		}
		unsealed, sealPub = map[string]*sealedSecrets{}, pub
	}
	unsealed[accountUUID] = &sealedSecrets{Password: accountPassword}
	if err := seal(); err != nil {
		return err
	}

	store.Accounts[accountUUID] = &StoredAccount{Shorthand: shorthand, Email: email, URL: signInURL}
	if store.Default == "" || len(store.Accounts) == 1 {
		store.Default = accountUUID
	}
	store.NoKeyCache = store.NoKeyCache || noKeyCache
	return saveSealedStore(store)
}

func sealedPassword(accountUUID string) (string, error) {
	acct, ok := unsealed[accountUUID]
	if !ok {
		return "", fmt.Errorf("account not found: %s", accountUUID)
	}
	return acct.Password, nil
}

// sealedCachedSymKey never prompts: without unsealed secrets, there is no cache.
func sealedCachedSymKey(accountUUID, cacheKey string) ([]byte, error) {
	acct := unsealed[accountUUID]
	if acct == nil || acct.SymKeyCacheKey != cacheKey || acct.SymKey == "" {
		return nil, fmt.Errorf("cache miss")
	}
	return base64.StdEncoding.DecodeString(acct.SymKey)
}

func setSealedCachedSymKey(accountUUID, cacheKey string, key []byte) error {
	acct := unsealed[accountUUID]
	if acct == nil {
		return fmt.Errorf("account not found")
	}
	if store, err := loadCredentialStore(); err != nil || store.NoKeyCache {
		return err
	}
	acct.SymKeyCacheKey = cacheKey
	acct.SymKey = base64.StdEncoding.EncodeToString(key)
	return seal()
}

// deleteSealedCredentials removes an account. Unless it is the last one, that
// takes Touch ID, to seal the others' secrets again.
func deleteSealedCredentials(accountUUID string) error {
	store, err := loadCredentialStore()
	if err != nil {
		return err
	}
	acct, ok := store.Accounts[accountUUID]
	if !ok {
		return nil
	}
	if len(store.Accounts) == 1 {
		return deleteAllSealedCredentials()
	}
	if unsealed == nil {
		if err := unsealFor("remove "+acct.Email, nil); err != nil {
			return err
		}
	}
	delete(unsealed, accountUUID)
	if err := seal(); err != nil {
		return err
	}

	delete(store.Accounts, accountUUID)
	if store.Default == accountUUID {
		store.Default = ""
		for uuid := range store.Accounts {
			store.Default = uuid
			break
		}
	}
	return saveSealedStore(store)
}

// deleteAllSealedCredentials removes every sealed file, the Secure Enclave
// key's handle with them (without it the key can't be used), which puts opcli
// back in keychain mode.
func deleteAllSealedCredentials() error {
	for _, name := range []string{sealedSecretsFile, seKeyFile, sealedCredentialsFile} {
		path, err := dataFilePath(name)
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	cachedCredentialStore, unsealed, sealPub = nil, nil, nil
	return nil
}
