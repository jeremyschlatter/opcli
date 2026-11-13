package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	buildOnce   sync.Once
	buildErr    error
	testBinPath string
)

func buildTestBinary() (string, error) {
	buildOnce.Do(func() {
		// Get absolute path for the binary
		testBinPath, buildErr = filepath.Abs("./opcli-test")
		if buildErr != nil {
			return
		}

		// Build and sign via make
		cmd := exec.Command("make", "sign-test")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildErr = fmt.Errorf("failed to build test binary: %v\nstderr: %s", err, stderr.String())
			return
		}
	})
	return testBinPath, buildErr
}

// testEnv holds environment setup for e2e tests
type testEnv struct {
	binPath         string
	testDB          *TestDatabase
	tmpDir          string
	dataDir         string
	sessionKey      string
	keychainService string
}

func setupTestEnv(t testing.TB, fromV1 bool) *testEnv {
	t.Helper()

	// Build the test binary (cached across test runs)
	binPath, err := buildTestBinary()
	if err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "opcli-e2e-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Create test database
	testDB, err := CreateTestDatabase(tmpDir, fromV1)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create test database: %v", err)
	}

	// Create isolated data directory for sessions
	dataDir := filepath.Join(tmpDir, "data")

	// Each test env gets its own keychain namespace to avoid races between
	// TestE2E and TestE2E_Migrated (which run in parallel).
	keychainService := fmt.Sprintf("opcli-test-%s", filepath.Base(tmpDir))

	env := &testEnv{
		binPath:         binPath,
		testDB:          testDB,
		tmpDir:          tmpDir,
		dataDir:         dataDir,
		sessionKey:      "e2e-test-session",
		keychainService: keychainService,
	}

	// Store credentials in keychain for all accounts
	for _, acct := range testDB.Accounts {
		cmd := exec.Command(binPath, "test-store-creds")
		cmd.Env = append(cleanEnv(),
			"OPCLI_DB_PATH="+testDB.Path,
			"OPCLI_TEST_DATA_DIR="+dataDir,
			"OPCLI_TEST_KEYCHAIN_SERVICE="+keychainService,
			"OPCLI_TEST_ACCOUNT_UUID="+acct.UUID,
			"OPCLI_TEST_PASSWORD="+acct.Password,
			"OPCLI_TEST_EMAIL="+acct.Email,
			"OPCLI_TEST_SHORTHAND="+acct.Shorthand,
			"OPCLI_TEST_URL="+acct.URL,
		)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			testDB.Cleanup()
			os.RemoveAll(tmpDir)
			t.Fatalf("failed to store test credentials for %s: %v\nstderr: %s", acct.UUID, err, stderr.String())
		}
	}

	// Verify credentials are readable AND pre-cache each account's symmetric key.
	//
	// Parallel subtests share this env's single keychain credential entry. If any
	// subtest is the first to touch a given account, the CLI derives that account's
	// symkey and writes it back via SetCachedSymKey — that write races with other
	// subtests' concurrent reads of the same keychain entry and can surface as
	// transient OSStatus errors (observed: -67701, -25299 under load). Pre-caching
	// every account here, sequentially, makes all parallel subtest invocations
	// read-only against the shared keychain entry, eliminating the race.
	for _, acct := range testDB.Accounts {
		ref, err := firstReadableRef(acct)
		if err != nil {
			t.Fatalf("no readable ref for account %s: %v", acct.Shorthand, err)
		}
		verifyCmd := exec.Command(binPath, "read", ref)
		verifyCmd.Env = env.baseEnv()
		var verifyErr bytes.Buffer
		verifyCmd.Stderr = &verifyErr
		if err := verifyCmd.Run(); err != nil {
			t.Fatalf("credentials stored but not readable for %s: %v\nstderr: %s",
				acct.Shorthand, err, verifyErr.String())
		}
	}

	return env
}

// firstReadableRef returns an op:// reference pointing at some field of some
// item in some vault of the given account. Used by setupTestEnv to exercise
// decryption for every account (to warm the symkey cache).
func firstReadableRef(acct *TestAccount) (string, error) {
	for _, v := range acct.Vaults {
		for _, item := range v.Items {
			for fieldName := range item.Fields {
				return fmt.Sprintf("op://%s:%s/%s/%s",
					acct.Shorthand, v.Name, item.Title, fieldName), nil
			}
		}
	}
	return "", fmt.Errorf("account %s has no vault/item/field", acct.Shorthand)
}

func (e *testEnv) cleanup(t testing.TB) {
	t.Helper()

	// Delete the entire namespaced keychain entry
	cmd := exec.Command(e.binPath, "test-delete-all-creds")
	cmd.Env = append(cleanEnv(),
		"OPCLI_TEST_DATA_DIR="+e.dataDir,
		"OPCLI_TEST_KEYCHAIN_SERVICE="+e.keychainService,
	)
	cmd.Run() // ignore errors

	e.testDB.Cleanup()
	os.RemoveAll(e.tmpDir)
}

// cleanEnv returns os.Environ() with all OPCLI_ vars stripped,
// so tests aren't affected by the user's configuration.
func cleanEnv() []string {
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "OPCLI_") {
			env = append(env, v)
		}
	}
	return env
}

// baseEnv returns the base environment for CLI commands.
func (e *testEnv) baseEnv() []string {
	return append(cleanEnv(),
		"OPCLI_DB_PATH="+e.testDB.Path,
		"OPCLI_TEST_DATA_DIR="+e.dataDir,
		"OPCLI_TEST_SESSION_KEY="+e.sessionKey,
		"OPCLI_TEST_KEYCHAIN_SERVICE="+e.keychainService,
	)
}

// runCLI runs the CLI with the given args in workDir and returns stdout, stderr, and exit code
func (e *testEnv) runCLI(workDir, stdin string, extraEnv map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(e.binPath, args...)
	cmd.Env = e.baseEnv()
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = workDir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

type yamlTestCase struct {
	Name      string            `yaml:"name"`
	Args      []string          `yaml:"args"`
	Stdin     string            `yaml:"stdin"`
	Out       string            `yaml:"out"`
	OutPrefix string            `yaml:"outPrefix"`
	Err       string            `yaml:"err"`
	ErrPrefix string            `yaml:"errPrefix"`
	ErrSuffix string            `yaml:"errSuffix"`
	Code      int               `yaml:"code"`
	Files     map[string]string `yaml:"files"`
	Env       map[string]string `yaml:"env"`
	Outputs   map[string]struct {
		Content string      `yaml:"content"`
		Mode    os.FileMode `yaml:"mode"`
	} `yaml:"outputs"`
}

func loadTestCases(t *testing.T) map[string][]yamlTestCase {
	t.Helper()
	data, err := os.ReadFile("testdata/e2e_tests.yaml")
	if err != nil {
		t.Fatalf("failed to read test cases: %v", err)
	}
	var tests map[string][]yamlTestCase
	if err := yaml.Unmarshal(data, &tests); err != nil {
		t.Fatalf("failed to parse test cases: %v", err)
	}
	return tests
}

func TestE2E(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })

	runTestCases(t, env, loadTestCases(t))
}

func TestE2E_Migrated(t *testing.T) {
	env := setupTestEnv(t, true)
	t.Cleanup(func() { env.cleanup(t) })

	runTestCases(t, env, loadTestCases(t))
}

func TestE2E_UnsupportedDBVersion(t *testing.T) {
	env := setupTestEnv(t, true)
	t.Cleanup(func() { env.cleanup(t) })

	// Downgrade the DB to version 4 (unsupported)
	db, err := sql.Open("sqlite3", env.testDB.Path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("UPDATE config SET value = 4 WHERE name = 'version'")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	_, stderr, code := env.runCLI("", "", nil, "read", "op://Private/MyLogin/password")
	if code == 0 {
		t.Error("expected non-zero exit code")
	}
	if !strings.Contains(stderr, "unsupported database version 4") {
		t.Errorf("expected unsupported version error, got: %s", stderr)
	}
}

func runTestCases(t *testing.T, env *testEnv, allTests map[string][]yamlTestCase) {
	t.Helper()
	for command, tests := range allTests {
		t.Run(command, func(t *testing.T) {
			for _, tc := range tests {
				tc := tc // capture for parallel
				t.Run(tc.Name, func(t *testing.T) {
					t.Parallel()
					// Create temp dir for this test case
					workDir, err := os.MkdirTemp("", "opcli-test-*")
					if err != nil {
						t.Fatalf("failed to create work dir: %v", err)
					}
					defer os.RemoveAll(workDir)

					// Write input files
					for name, content := range tc.Files {
						if err := os.WriteFile(filepath.Join(workDir, name), []byte(content), 0600); err != nil {
							t.Fatalf("failed to write file %s: %v", name, err)
						}
					}

					stdout, stderr, code := env.runCLI(workDir, tc.Stdin, tc.Env, tc.Args...)
					// Errors on a migrated DB carry an extra note; expectations are shared with the unmigrated run.
					stderr = regexp.MustCompile(`(?m)^Note: this 1Password database is at schema.*\n`).ReplaceAllString(stderr, "")

					if code != tc.Code {
						t.Errorf("exit code: got %d, want %d\nstderr: %s", code, tc.Code, stderr)
					}

					if tc.Out != "" && stdout != tc.Out {
						t.Errorf("stdout:\ngot:  %q\nwant: %q", stdout, tc.Out)
					}

					if tc.OutPrefix != "" && !strings.HasPrefix(stdout, tc.OutPrefix) {
						t.Errorf("stdout:\ngot:  %q\nwant prefix: %q", stdout, tc.OutPrefix)
					}

					if tc.Err != "" && stderr != tc.Err {
						t.Errorf("stderr:\ngot:  %q\nwant: %q", stderr, tc.Err)
					}

					if tc.ErrPrefix != "" && !strings.HasPrefix(stderr, tc.ErrPrefix) {
						t.Errorf("stderr:\ngot:  %q\nwant prefix: %q", stderr, tc.ErrPrefix)
					}

					if tc.ErrSuffix != "" && !strings.HasSuffix(stderr, tc.ErrSuffix) {
						t.Errorf("stderr:\ngot:  %q\nwant suffix: %q", stderr, tc.ErrSuffix)
					}

					// Check output files
					for name, expected := range tc.Outputs {
						path := filepath.Join(workDir, name)
						content, err := os.ReadFile(path)
						if err != nil {
							t.Fatalf("failed to read output file %s: %v", name, err)
						}
						if string(content) != expected.Content {
							t.Errorf("file %s content:\ngot:  %q\nwant: %q", name, string(content), expected.Content)
						}
						info, err := os.Stat(path)
						if err != nil {
							t.Fatalf("failed to stat output file %s: %v", name, err)
						}
						if info.Mode().Perm() != expected.Mode {
							t.Errorf("file %s mode: got %o, want %o", name, info.Mode().Perm(), expected.Mode)
						}
					}
				})
			}
		})
	}
}

func TestE2E_AutoAccountSessionCoversAll(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })

	// Use a fresh session key so no sessions exist yet
	freshSessionKey := "auto-account-session-test"

	// Clear any existing sessions by removing the sessions file
	sessionsFile := filepath.Join(env.dataDir, "sessions.json")
	os.Remove(sessionsFile)

	// Run a command that uses OPCLI_AUTO_ACCOUNT to access a vault
	// from a non-default account. This should create sessions for ALL accounts.
	_, _, code := env.runCLI("", "", map[string]string{
		"OPCLI_AUTO_ACCOUNT":       "1",
		"OP_ACCOUNT":               "my",
		"OPCLI_TEST_SESSION_KEY":   freshSessionKey,
	}, "read", "op://Shared/Work Login/password")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Read the sessions file and verify sessions exist for all accounts
	data, err := os.ReadFile(sessionsFile)
	if err != nil {
		t.Fatalf("failed to read sessions file: %v", err)
	}

	// Verify that sessions were created for both accounts
	for _, acct := range env.testDB.Accounts {
		expectedKey := freshSessionKey + ":" + acct.UUID
		if !strings.Contains(string(data), acct.UUID) {
			t.Errorf("session not created for account %s (%s); sessions file: %s", acct.Shorthand, acct.UUID, string(data))
		}
		_ = expectedKey
	}
}

// With no cached session, a refused Touch ID must exit with exitAuthRefused,
// not 1: git's signing wrapper commits unsigned on that code alone.
func TestE2E_TouchIDFail(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })
	os.Remove(filepath.Join(env.dataDir, "sessions.json"))

	_, stderr, code := env.runCLI("", "", map[string]string{
		"OP_ACCOUNT":              "my",
		"OPCLI_TEST_SESSION_KEY":  "touchid-fail-test",
		"OPCLI_TEST_TOUCHID_FAIL": "1",
	}, "read", "op://Shared/Work Login/password")
	if code != exitAuthRefused {
		t.Errorf("expected exit code %d, got %d; stderr: %s", exitAuthRefused, code, stderr)
	}
	if !strings.Contains(stderr, "authentication failed or cancelled") {
		t.Errorf("expected the auth failure message, got stderr: %s", stderr)
	}
}

// `plugin run` provisions the configured item's credential to the executable
// the way the upstream shell plugin for it says to. (`plugin init`, which
// writes the configs, is an interactive TUI: tested by hand.)
func TestE2E_PluginRun(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })
	vault := env.testDB.Vaults["Private"]

	// Stand-ins for the real CLIs, reporting what they were given.
	binDir := filepath.Join(env.tmpDir, "bin")
	if err := os.Mkdir(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"gh":    `echo "token=$GH_TOKEN args=$*"; exit 7`,
		"mysql": `for last; do :; done; echo "args=${*%%=*}"; cat "${last#--defaults-file=}"; echo "${last#--defaults-file=}" >&2`,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"+script+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	extraEnv := map[string]string{"PATH": binDir + ":" + os.Getenv("PATH")}

	writeConfig := func(dir, exe, plugin, credType, item string, fields string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		config := fmt.Sprintf(`{"account_id": %q, "entrypoint": [%q], "credentials": [{"plugin": %q, "credential_type": %q, "usage_id": %q, "vault_id": %q, "item_id": %q, "fields": %s}]}`,
			env.testDB.AccountUUID, exe, plugin, credType, credType, vault.UUID, vault.Items[item].UUID, fields)
		if err := os.WriteFile(filepath.Join(dir, exe+".json"), []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
	}
	globalDir := filepath.Join(env.dataDir, "plugins")
	workDir := filepath.Join(env.tmpDir, "work")
	if err := os.MkdirAll(filepath.Join(workDir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	run := func(dir string, args ...string) (string, string, int) {
		return env.runCLI(dir, "", extraEnv, append([]string{"plugin", "run", "--"}, args...)...)
	}

	// Not configured: commands that need no credential still run; others fail (there's no terminal to ask in).
	if out, stderr, code := run(workDir, "gh", "--version"); out != "token= args=--version\n" || code != 7 {
		t.Errorf("unconfigured gh --version: out=%q stderr=%q code=%d", out, stderr, code)
	}
	if _, stderr, code := run(workDir, "gh", "api", "user"); code != 1 || !strings.Contains(stderr, "no credential configured for gh") {
		t.Errorf("unconfigured gh api: stderr=%q code=%d", stderr, code)
	}
	if _, stderr, code := run(workDir, "nosuchcli"); code != 1 || !strings.Contains(stderr, `no shell plugin for "nosuchcli"`) {
		t.Errorf("unknown executable: stderr=%q code=%d", stderr, code)
	}

	// Global config, with a field mapping (the item's field is "credential", the plugin wants "Token").
	// The executable's exit code and its own --account flag pass through.
	writeConfig(globalDir, "gh", "github", "personal_access_token", "Test API Key", `{"Token": "credential"}`)
	if out, stderr, code := run(workDir, "gh", "api", "--account", "x"); out != "token=api-key-12345 args=api --account x\n" || code != 7 {
		t.Errorf("gh with global config: out=%q stderr=%q code=%d", out, stderr, code)
	}

	// A directory config beats the global one, in subdirectories too.
	writeConfig(filepath.Join(workDir, ".opcli", "plugins"), "gh", "github", "personal_access_token", "Test Login", `{"Token": "password"}`)
	if out, stderr, code := run(filepath.Join(workDir, "sub"), "gh", "api"); out != "token=secret123 args=api\n" || code != 7 {
		t.Errorf("gh with directory config: out=%q stderr=%q code=%d", out, stderr, code)
	}

	// A mapping to a field that's gone is an error, not a silent omission.
	writeConfig(globalDir, "gh", "github", "personal_access_token", "Test API Key", `{"Token": "nosuchfield"}`)
	if _, stderr, code := run(env.tmpDir, "gh", "api"); code != 1 || !strings.Contains(stderr, "no longer has the field chosen as its Token") {
		t.Errorf("gh with stale mapping: stderr=%q code=%d", stderr, code)
	}

	// Fields labeled the way the plugin expects need no mapping. mysql's
	// credential is provisioned as a temp file passed by flag (appended: that's
	// upstream's provisioner), deleted afterwards.
	writeConfig(globalDir, "mysql", "mysql", "database_credentials", "Test MySQL", `null`)
	out, stderr, code := run(workDir, "mysql", "-e", "select 1")
	if out != "args=-e select 1 --defaults-file\n[client]\nuser=\"dbuser\"\npassword=\"dbpass\"\n" || code != 0 {
		t.Errorf("mysql: out=%q stderr=%q code=%d", out, stderr, code)
	}
	if _, err := os.Stat(strings.TrimSpace(stderr)); !os.IsNotExist(err) {
		t.Errorf("mysql: temp config %q should be gone after the run: %v", strings.TrimSpace(stderr), err)
	}
}
