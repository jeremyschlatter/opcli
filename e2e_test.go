//go:build test

package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

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

	// Find the test binary first
	binPath := "./opcli-test"
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

// runCLI runs the CLI with the given args and returns stdout, stderr, and exit code
func (e *testEnv) runCLI(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(e.binPath, args...)
	cmd.Env = e.baseEnv()

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

// runCLIWithStdin runs the CLI with stdin input
func (e *testEnv) runCLIWithStdin(stdin string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(e.binPath, args...)
	cmd.Env = e.baseEnv()
	cmd.Stdin = strings.NewReader(stdin)

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

type testCase struct {
	name     string
	args     []string
	stdin    string // for inject
	golden   string // golden file name (if using golden files)
	wantOut  string // expected stdout (if not using golden)
	wantErr  string // expected stderr substring
	wantCode int    // exit code (default 0)
}

func TestE2E_Version(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	stdout, _, code := env.runCLI("version")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.HasPrefix(stdout, "opcli ") {
		t.Errorf("expected output to start with 'opcli ', got %q", stdout)
	}
}

func TestE2E_Read(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	tests := []testCase{
		{
			name:    "read password field",
			args:    []string{"read", "op://Private/Test Login/password"},
			wantOut: "secret123\n",
		},
		{
			name:    "read username field",
			args:    []string{"read", "op://Private/Test Login/username"},
			wantOut: "testuser\n",
		},
		{
			name:    "read credential field",
			args:    []string{"read", "op://Private/Test API Key/credential"},
			wantOut: "api-key-12345\n",
		},
		{
			name:    "read sectioned field with section path",
			args:    []string{"read", "op://Private/Test Sectioned/server/hostname"},
			wantOut: "example.com\n",
		},
		{
			name:    "read sectioned field without section (unambiguous)",
			args:    []string{"read", "op://Private/Test Sectioned/hostname"},
			wantOut: "example.com\n",
		},
		{
			name:     "vault not found",
			args:     []string{"read", "op://NoSuchVault/item/field"},
			wantErr:  "vault not found",
			wantCode: 1,
		},
		{
			name:     "item not found",
			args:     []string{"read", "op://Private/NoSuchItem/field"},
			wantErr:  "item not found",
			wantCode: 1,
		},
		{
			name:     "field not found",
			args:     []string{"read", "op://Private/Test Login/nosuchfield"},
			wantErr:  "field not found",
			wantCode: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := env.runCLI(tc.args...)

			if code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d\nstderr: %s", code, tc.wantCode, stderr)
			}

			if tc.wantOut != "" && stdout != tc.wantOut {
				t.Errorf("stdout:\ngot:  %q\nwant: %q", stdout, tc.wantOut)
			}

			if tc.wantErr != "" && !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr should contain %q, got: %q", tc.wantErr, stderr)
			}
		})
	}
}

func TestE2E_List(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	stdout, _, code := env.runCLI("list")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Check that vaults are listed
	if !strings.Contains(stdout, "Private") {
		t.Errorf("expected 'Private' vault in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Work") {
		t.Errorf("expected 'Work' vault in output, got: %s", stdout)
	}
}

func TestE2E_Inject(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	tests := []testCase{
		{
			name:    "braced reference",
			args:    []string{"inject"},
			stdin:   "password={{ op://Private/Test Login/password }}",
			wantOut: "password=secret123",
		},
		{
			name:    "braced reference with spaces",
			args:    []string{"inject"},
			stdin:   "password={{ op://Private/Test Login/password }}",
			wantOut: "password=secret123",
		},
		{
			name:    "bare reference",
			args:    []string{"inject"},
			stdin:   "password=op://Private/Test Login/password",
			wantOut: "password=secret123",
		},
		{
			name:    "no secrets passthrough",
			args:    []string{"inject"},
			stdin:   "No secrets here, just text",
			wantOut: "No secrets here, just text",
		},
		{
			name:    "multiple references",
			args:    []string{"inject"},
			stdin:   "user={{ op://Private/Test Login/username }} pass={{ op://Private/Test Login/password }}",
			wantOut: "user=testuser pass=secret123",
		},
		{
			name:     "nonexistent item",
			args:     []string{"inject"},
			stdin:    "{{ op://Private/nonexistent/field }}",
			wantErr:  "item not found",
			wantCode: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := env.runCLIWithStdin(tc.stdin, tc.args...)

			if code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d\nstderr: %s", code, tc.wantCode, stderr)
			}

			if tc.wantOut != "" && stdout != tc.wantOut {
				t.Errorf("stdout:\ngot:  %q\nwant: %q", stdout, tc.wantOut)
			}

			if tc.wantErr != "" && !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr should contain %q, got: %q", tc.wantErr, stderr)
			}
		})
	}
}

func TestE2E_InjectFile(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// Create input file
	inputPath := filepath.Join(env.tmpDir, "input.txt")
	if err := os.WriteFile(inputPath, []byte("password={{ op://Private/Test Login/password }}"), 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	// Test -i flag
	outputPath := filepath.Join(env.tmpDir, "output.txt")
	_, stderr, code := env.runCLI("inject", "-i", inputPath, "-o", outputPath)
	if code != 0 {
		t.Fatalf("inject failed: %s", stderr)
	}

	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if string(output) != "password=secret123" {
		t.Errorf("output: got %q, want %q", string(output), "password=secret123")
	}

	// Check file permissions
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat output: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file mode: got %o, want 0600", info.Mode().Perm())
	}
}

func TestE2E_InjectFileMode(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// Create input file
	inputPath := filepath.Join(env.tmpDir, "input.txt")
	if err := os.WriteFile(inputPath, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	// Test --file-mode flag
	outputPath := filepath.Join(env.tmpDir, "output.txt")
	_, stderr, code := env.runCLI("inject", "-i", inputPath, "-o", outputPath, "--file-mode", "0644")
	if code != 0 {
		t.Fatalf("inject failed: %s", stderr)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat output: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("file mode: got %o, want 0644", info.Mode().Perm())
	}
}

// TestE2E_Golden tests using golden files for expected output
func TestE2E_Golden(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	tests := []struct {
		name   string
		args   []string
		golden string
	}{
		{
			name:   "list vaults",
			args:   []string{"list"},
			golden: "list.txt",
		},
	}

	goldenDir := "testdata/golden"
	if err := os.MkdirAll(goldenDir, 0755); err != nil {
		t.Fatalf("failed to create golden dir: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := env.runCLI(tc.args...)
			if code != 0 {
				t.Fatalf("command failed with code %d: %s", code, stderr)
			}

			goldenPath := filepath.Join(goldenDir, tc.golden)

			if *update {
				if err := os.WriteFile(goldenPath, []byte(stdout), 0644); err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("failed to read golden file (run with -update to create): %v", err)
			}

			if stdout != string(want) {
				t.Errorf("output differs from golden file:\ngot:\n%s\nwant:\n%s", stdout, string(want))
			}
		})
	}
}

func TestE2E_TouchIDFail(t *testing.T) {
	// This test requires a fresh session (no cached auth) and TouchID to fail.
	// Since our test setup creates a session via keychain storage, we'd need
	// to delete the session first and then test with OPCLI_TEST_TOUCHID_FAIL=1.
	// For now, skip this test.
	t.Skip("TouchID failure test not yet implemented")
}
