package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func setupTestEnv(t *testing.T, fromV1 bool) *testEnv {
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

	// Verify credentials are readable (keychain can be flaky)
	verifyCmd := exec.Command(binPath, "read", "op://Private/Test Login/password")
	verifyCmd.Env = env.baseEnv()
	var verifyErr bytes.Buffer
	verifyCmd.Stderr = &verifyErr
	if err := verifyCmd.Run(); err != nil {
		t.Fatalf("credentials stored but not readable: %v\nstderr: %s", err, verifyErr.String())
	}

	return env
}

func (e *testEnv) cleanup(t *testing.T) {
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

func TestE2E_TouchIDFail(t *testing.T) {
	// This test requires a fresh session (no cached auth) and TouchID to fail.
	// Since our test setup creates a session via keychain storage, we'd need
	// to delete the session first and then test with OPCLI_TEST_TOUCHID_FAIL=1.
	// For now, skip this test.
	t.Skip("TouchID failure test not yet implemented")
}
