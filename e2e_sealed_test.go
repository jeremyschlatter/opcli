package main

import (
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secure Enclave mode, through the test build's fake Secure Enclave
// (sealed_fake.go).

func setupSealedTestEnv(t *testing.T, storeEnv ...string) *testEnv {
	t.Helper()
	env := setupTestEnv(t, false, append([]string{"OPCLI_TEST_SECURE_ENCLAVE=1"}, storeEnv...)...)
	t.Cleanup(func() { env.cleanup(t) })
	return env
}

// sealedFiles returns the sealed mode's files that exist, checking that each is 0600.
func (e *testEnv) sealedFiles(t *testing.T) map[string][]byte {
	t.Helper()
	got := map[string][]byte{}
	for _, name := range []string{sealedCredentialsFile, sealedSecretsFile, seKeyFile} {
		path := filepath.Join(e.dataDir, name)
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
			t.Errorf("%s: mode %o, want 600", name, info.Mode().Perm())
		}
		got[name] = data
	}
	return got
}

// unsealed opens secrets.sealed the way the fake Secure Enclave does.
func (e *testEnv) unsealed(t *testing.T) string {
	t.Helper()
	f := e.sealedFiles(t)
	block, err := aes.NewCipher(f[seKeyFile])
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := cipher.NewGCM(block)
	blob := f[sealedSecretsFile]
	msg, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(msg)
}

// Every command behaves as in keychain mode.
func TestE2E_SecureEnclave(t *testing.T) {
	env := setupSealedTestEnv(t)
	runTestCases(t, env, loadTestCases(t))
}

// Only sealed secrets are stored, and every command asks the Secure Enclave
// once: no approval is kept, so the next command asks again.
func TestE2E_SecureEnclaveStore(t *testing.T) {
	env := setupSealedTestEnv(t)

	f := env.sealedFiles(t)
	if len(f) != 3 {
		t.Fatalf("expected %s, %s and %s, got %d files", sealedCredentialsFile, sealedSecretsFile, seKeyFile, len(f))
	}
	for name, data := range f {
		for _, acct := range env.testDB.Accounts {
			if strings.Contains(string(data), acct.Password) {
				t.Errorf("%s holds the password of %s in the clear", name, acct.Shorthand)
			}
		}
	}
	if s := env.unsealed(t); !strings.Contains(s, env.testDB.Accounts[0].Password) || !strings.Contains(s, `"symkey"`) {
		t.Errorf("sealed credentials should hold the password and a cached key: %s", s)
	}

	promptLog := filepath.Join(env.tmpDir, "prompts")
	for i := range 2 {
		if _, stderr, code := env.runCLI("", "", map[string]string{"OPCLI_TEST_TOUCHID_LOG": promptLog}, "read", "op://Private/Test Login/password"); code != 0 {
			t.Fatalf("read %d: exit code %d; stderr: %s", i, code, stderr)
		}
	}
	prompts, _ := os.ReadFile(promptLog)
	if n := strings.Count(string(prompts), "read op://Private/Test Login/password"); n != 2 {
		t.Errorf("expected 2 prompts naming the ref, got %d: %s", n, prompts)
	}
	if n := strings.Count(string(prompts), `"refs":["Test Login/password"]`); n != 2 {
		t.Errorf("expected opcli's window, listing the ref, before each unseal; got %d: %s", n, prompts)
	}
	if _, err := os.Stat(filepath.Join(env.dataDir, sessionFile)); err == nil {
		t.Errorf("%s written in Secure Enclave mode", sessionFile)
	}
	if entries, _ := filepath.Glob(filepath.Join(env.dataDir, "keychain-*")); len(entries) != 0 {
		t.Errorf("keychain items written in Secure Enclave mode: %v", entries)
	}

	_, stderr, code := env.runCLI("", "", map[string]string{"OPCLI_TEST_TOUCHID_FAIL": "1"}, "read", "op://Private/Test Login/password")
	if code != exitAuthRefused || !strings.Contains(stderr, "authentication failed or cancelled") {
		t.Errorf("refused Touch ID: exit code %d, want %d; stderr: %s", code, exitAuthRefused, stderr)
	}
}

// Signing out of one account of several takes Touch ID, to seal the others
// again. Signing out of the last removes every file, the Secure Enclave key's
// handle with them, and leaves opcli in keychain mode.
func TestE2E_SecureEnclaveSignout(t *testing.T) {
	env := setupSealedTestEnv(t)
	promptLog := filepath.Join(env.tmpDir, "prompts")
	logEnv := map[string]string{"OPCLI_TEST_TOUCHID_LOG": promptLog}

	if _, stderr, code := env.runCLI("", "", map[string]string{"OPCLI_TEST_TOUCHID_FAIL": "1"}, "signout", "--account", "work"); code != exitAuthRefused {
		t.Errorf("signout with Touch ID refused: exit code %d; stderr: %s", code, stderr)
	}
	if _, stderr, code := env.runCLI("", "", logEnv, "signout", "--account", "work"); code != 0 {
		t.Fatalf("signout work: exit code %d; stderr: %s", code, stderr)
	}
	if s := env.unsealed(t); strings.Contains(s, env.testDB.Accounts[1].Password) || !strings.Contains(s, env.testDB.Accounts[0].Password) {
		t.Errorf("after signing out of work, sealed credentials: %s", s)
	}
	if out, stderr, code := env.runCLI("", "", logEnv, "read", "op://Private/Test Login/password"); code != 0 || out == "" {
		t.Errorf("read after signing out of the other account: exit code %d; stderr: %s", code, stderr)
	}
	if prompts, _ := os.ReadFile(promptLog); !strings.Contains(string(prompts), "remove test2@example.com") {
		t.Errorf("signout should ask to unseal, naming the account: %s", prompts)
	}

	if _, stderr, code := env.runCLI("", "", nil, "signout"); code != 0 {
		t.Fatalf("signout: exit code %d; stderr: %s", code, stderr)
	}
	if f := env.sealedFiles(t); len(f) != 0 {
		t.Errorf("files left after signing out of every account: %d", len(f))
	}
	out, _, _ := env.runCLI("", "", nil, "account", "list")
	if strings.Contains(out, "(signed in") {
		t.Errorf("still signed in after signout:\n%s", out)
	}
}

// With --no-key-cache, the derived key is never kept, sealed or not.
func TestE2E_SecureEnclaveNoKeyCache(t *testing.T) {
	env := setupSealedTestEnv(t, "OPCLI_TEST_NO_KEY_CACHE=1")
	if _, stderr, code := env.runCLI("", "", nil, "read", "op://Private/Test Login/password"); code != 0 {
		t.Fatalf("read: exit code %d; stderr: %s", code, stderr)
	}
	if s := env.unsealed(t); strings.Contains(s, `"symkey"`) {
		t.Errorf("no derived key should be cached: %s", s)
	}
	if c := string(env.sealedFiles(t)[sealedCredentialsFile]); !strings.Contains(c, `"no_key_cache":true`) {
		t.Errorf("%s should record no_key_cache: %s", sealedCredentialsFile, c)
	}
}

// signin's flags are checked before it asks for a password.
func TestE2E_SecureEnclaveSigninFlags(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })

	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"signin", "--no-key-cache"}, "--no-key-cache needs --secure-enclave"},
		{[]string{"signin", "--secure-enclave"}, "sign out of them first"},
		{[]string{"signin", "--secure-enclve"}, "Usage: opcli signin"},
	} {
		_, stderr, code := env.runCLI("", "", nil, tc.args...)
		if code != 1 || !strings.Contains(stderr, tc.err) {
			t.Errorf("%v: exit code %d, stderr %q; want 1 and %q", tc.args, code, stderr, tc.err)
		}
	}
	if f := env.sealedFiles(t); len(f) != 0 {
		t.Errorf("a refused signin left %d sealed files", len(f))
	}
}

// A keychain that isn't there, or can't be read, holds no accounts for
// signin --secure-enclave to refuse over, and keychain mode fails with an
// error, not a crash.
func TestE2E_SecureEnclaveSigninWithoutKeychain(t *testing.T) {
	if len(fileKeychainEnv) == 0 {
		t.Skip("simulating keychain statuses needs the file-backed keychain")
	}
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })

	for _, status := range []string{"-25307", "-25293"} { // errSecNoDefaultKeychain, errSecAuthFailed
		_, stderr, code := env.runCLI("", "", map[string]string{"OPCLI_TEST_KEYCHAIN_STATUS": status}, "signin", "--secure-enclave")
		// It gets as far as asking for the password, which a test can't type.
		if code != 1 || !strings.Contains(stderr, "failed to read password") {
			t.Errorf("signin --secure-enclave with keychain status %s: exit code %d, stderr %q", status, code, stderr)
		}
	}
	_, stderr, code := env.runCLI("", "", map[string]string{"OPCLI_TEST_KEYCHAIN_STATUS": "-25293"}, "read", "op://Private/Test Login/password")
	if code != 1 || !strings.Contains(stderr, "Error: ") || strings.Contains(stderr, "goroutine") {
		t.Errorf("read with an unreadable keychain: exit code %d, stderr %q", code, stderr)
	}
}
