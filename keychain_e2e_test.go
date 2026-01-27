//go:build test

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestKeychain_StoreAndRead tests that the signed test binary can
// store credentials in the keychain and then read using them.
func TestKeychain_StoreAndRead(t *testing.T) {
	// Create temp directory for test database and data
	tmpDir, err := os.MkdirTemp("", "opcli-keychain-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test database
	testDB, err := CreateTestDatabase(tmpDir)
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	defer testDB.Cleanup()

	binPath := "./opcli-test"
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("opcli-test binary not found")
	}

	// Use isolated data directory for sessions
	dataDir := filepath.Join(tmpDir, "data")

	// Environment for all commands - uses isolated data dir for sessions
	baseEnv := append(os.Environ(),
		"OPCLI_TEST_DB="+testDB.Path,
		"OPCLI_TEST_DATA_DIR="+dataDir,
		"OPCLI_TEST_SESSION_KEY=keychain-test-session",
	)

	// Step 1: Store credentials using the signed binary
	t.Log("Step 1: Storing credentials in keychain...")
	storeCmd := exec.Command(binPath, "test-store-creds")
	storeCmd.Env = append(baseEnv,
		"OPCLI_TEST_ACCOUNT_UUID="+testDB.AccountUUID,
		"OPCLI_TEST_SECRET_KEY="+testDB.SecretKey,
		"OPCLI_TEST_PASSWORD="+testDB.Password,
		"OPCLI_TEST_EMAIL="+testDB.Email,
	)
	var storeStderr bytes.Buffer
	storeCmd.Stderr = &storeStderr
	if err := storeCmd.Run(); err != nil {
		t.Fatalf("failed to store credentials: %v\nstderr: %s", err, storeStderr.String())
	}

	// Step 2: Read using keychain credentials (NO env var credentials)
	t.Log("Step 2: Reading using keychain credentials...")
	readCmd := exec.Command(binPath, "read", "op://Private/Test Login/password")
	readCmd.Env = baseEnv // Note: no OP_SECRET_KEY or OP_MASTER_PASSWORD
	var readStdout, readStderr bytes.Buffer
	readCmd.Stdout = &readStdout
	readCmd.Stderr = &readStderr
	if err := readCmd.Run(); err != nil {
		t.Fatalf("failed to read: %v\nstderr: %s", err, readStderr.String())
	}

	if got := readStdout.String(); got != "secret123\n" {
		t.Errorf("got %q, want %q", got, "secret123\n")
	}

	// Step 3: Clean up credentials
	t.Log("Step 3: Cleaning up credentials...")
	deleteCmd := exec.Command(binPath, "test-delete-creds")
	deleteCmd.Env = append(baseEnv, "OPCLI_TEST_ACCOUNT_UUID="+testDB.AccountUUID)
	deleteCmd.Run() // ignore errors
}
