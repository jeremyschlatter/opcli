//go:build test

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// testEnv holds environment setup for e2e tests
type testEnv struct {
	binPath    string
	testDB     *TestDatabase
	tmpDir     string
	dataDir    string
	sessionKey string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Find the test binary first (use absolute path so it works from any workDir)
	binPath, err := filepath.Abs("./opcli-test")
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("opcli-test binary not found. Run 'make opcli-test && make sign-test' first.")
	}

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "opcli-e2e-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Create test database
	testDB, err := CreateTestDatabase(tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create test database: %v", err)
	}

	// Create isolated data directory for sessions
	dataDir := filepath.Join(tmpDir, "data")

	env := &testEnv{
		binPath:    binPath,
		testDB:     testDB,
		tmpDir:     tmpDir,
		dataDir:    dataDir,
		sessionKey: "e2e-test-session",
	}

	// Store credentials in keychain using the signed binary
	cmd := exec.Command(binPath, "test-store-creds")
	cmd.Env = append(os.Environ(),
		"OPCLI_TEST_DB="+testDB.Path,
		"OPCLI_TEST_DATA_DIR="+dataDir,
		"OPCLI_TEST_ACCOUNT_UUID="+testDB.AccountUUID,
		"OPCLI_TEST_SECRET_KEY="+testDB.SecretKey,
		"OPCLI_TEST_PASSWORD="+testDB.Password,
		"OPCLI_TEST_EMAIL="+testDB.Email,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		testDB.Cleanup()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to store test credentials: %v\nstderr: %s", err, stderr.String())
	}

	return env
}

func (e *testEnv) cleanup(t *testing.T) {
	t.Helper()

	// Delete credentials from keychain
	cmd := exec.Command(e.binPath, "test-delete-creds")
	cmd.Env = append(os.Environ(),
		"OPCLI_TEST_DATA_DIR="+e.dataDir,
		"OPCLI_TEST_ACCOUNT_UUID="+e.testDB.AccountUUID,
	)
	cmd.Run() // ignore errors

	e.testDB.Cleanup()
	os.RemoveAll(e.tmpDir)
}

// baseEnv returns the base environment for CLI commands
func (e *testEnv) baseEnv() []string {
	return append(os.Environ(),
		"OPCLI_TEST_DB="+e.testDB.Path,
		"OPCLI_TEST_DATA_DIR="+e.dataDir,
		"OPCLI_TEST_SESSION_KEY="+e.sessionKey,
	)
}

// runCLI runs the CLI with the given args in workDir and returns stdout, stderr, and exit code
func (e *testEnv) runCLI(workDir, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(e.binPath, args...)
	cmd.Env = e.baseEnv()
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
	Name   string            `yaml:"name"`
	Args   []string          `yaml:"args"`
	Stdin  string            `yaml:"stdin"`
	Out    string            `yaml:"out"`
	Err    string            `yaml:"err"`
	Code   int               `yaml:"code"`
	Files  map[string]string `yaml:"files"`
	Outputs map[string]struct {
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
	env := setupTestEnv(t)
	defer env.cleanup(t)

	allTests := loadTestCases(t)
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

					stdout, stderr, code := env.runCLI(workDir, tc.Stdin, tc.Args...)

					if code != tc.Code {
						t.Errorf("exit code: got %d, want %d\nstderr: %s", code, tc.Code, stderr)
					}

					if tc.Out != "" && stdout != tc.Out {
						t.Errorf("stdout:\ngot:  %q\nwant: %q", stdout, tc.Out)
					}

					if tc.Err != "" && !strings.Contains(stderr, tc.Err) {
						t.Errorf("stderr should contain %q, got: %q", tc.Err, stderr)
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

func TestE2E_Version(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	stdout, _, code := env.runCLI("", "", "version")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.HasPrefix(stdout, "opcli ") {
		t.Errorf("expected output to start with 'opcli ', got %q", stdout)
	}
}

func TestE2E_TouchIDFail(t *testing.T) {
	// This test requires a fresh session (no cached auth) and TouchID to fail.
	// Since our test setup creates a session via keychain storage, we'd need
	// to delete the session first and then test with OPCLI_TEST_TOUCHID_FAIL=1.
	// For now, skip this test.
	t.Skip("TouchID failure test not yet implemented")
}
