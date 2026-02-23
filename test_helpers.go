//go:build test

package main

import (
	"fmt"
	"os"
)

func init() {
	// Register test commands
	testCommands = map[string]func() error{
		"test-store-creds":  cmdTestStoreCredentials,
		"test-delete-creds": cmdTestDeleteCredentials,
	}
}

// cmdTestStoreCredentials stores test credentials in the keychain.
// This is only available in test builds.
func cmdTestStoreCredentials() error {
	accountUUID := os.Getenv("OPCLI_TEST_ACCOUNT_UUID")
	password := os.Getenv("OPCLI_TEST_PASSWORD")
	email := os.Getenv("OPCLI_TEST_EMAIL")

	if accountUUID == "" || password == "" {
		return fmt.Errorf("OPCLI_TEST_ACCOUNT_UUID, OPCLI_TEST_PASSWORD required")
	}
	if email == "" {
		email = "test@example.com"
	}

	return StoreCredentials(accountUUID, password, "test", email, "https://test.1password.com")
}

// cmdTestDeleteCredentials deletes test credentials from the keychain.
func cmdTestDeleteCredentials() error {
	accountUUID := os.Getenv("OPCLI_TEST_ACCOUNT_UUID")
	if accountUUID == "" {
		return fmt.Errorf("OPCLI_TEST_ACCOUNT_UUID required")
	}
	return DeleteCredentials(accountUUID)
}
