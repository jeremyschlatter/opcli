package main

import (
	"database/sql"
	"os"
	"testing"
	"time"
)

// benchEnv holds a pre-built test database for benchmarks.
type benchEnv struct {
	db     *sql.DB
	testDB *TestDatabase
	tmpDir string
}

func setupBenchEnv(b *testing.B) *benchEnv {
	b.Helper()

	tmpDir, err := os.MkdirTemp("", "opcli-bench-*")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}

	testDB, err := CreateTestDatabase(tmpDir, false)
	if err != nil {
		os.RemoveAll(tmpDir)
		b.Fatalf("failed to create test database: %v", err)
	}

	db, err := sql.Open("sqlite3", testDB.Path)
	if err != nil {
		testDB.Cleanup()
		os.RemoveAll(tmpDir)
		b.Fatalf("failed to open database: %v", err)
	}

	return &benchEnv{db: db, testDB: testDB, tmpDir: tmpDir}
}

func (e *benchEnv) cleanup() {
	e.db.Close()
	e.testDB.Cleanup()
	os.RemoveAll(e.tmpDir)
}

// BenchmarkKeyDerivation measures the cost of deriving account keys from
// password + secret key (HKDF + PBKDF2 + RSA decrypt). This is the most
// expensive operation in a cold read.
func BenchmarkKeyDerivation(b *testing.B) {
	env := setupBenchEnv(b)
	b.Cleanup(env.cleanup)

	acct := env.testDB.Accounts[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ak, err := newAccountKeychain(env.db, acct.Password, acct.SecretKey, acct.Email, acct.UUID, "I", nil)
		if err != nil {
			b.Fatalf("key derivation failed: %v", err)
		}
		_ = ak
	}
}

// BenchmarkItemDecrypt measures vault lookup + item decryption after keys
// are already derived. This isolates the DB + AES-GCM + RSA-OAEP cost.
func BenchmarkItemDecrypt(b *testing.B) {
	env := setupBenchEnv(b)
	b.Cleanup(env.cleanup)

	acct := env.testDB.Accounts[0]

	// Derive keys once (not part of this benchmark)
	ak, err := newAccountKeychain(env.db, acct.Password, acct.SecretKey, acct.Email, acct.UUID, "I", nil)
	if err != nil {
		b.Fatalf("key derivation failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear cached vault keys so each iteration re-derives them
		ak.vaultKeysMu.Lock()
		ak.vaultKeys = make(map[string][]byte)
		ak.vaultKeysMu.Unlock()

		vaultUUID, err := ak.findVaultByName("Private", false, nil)
		if err != nil {
			b.Fatalf("find vault failed: %v", err)
		}
		item, err := ak.findItemByName(vaultUUID, "Test Login", nil)
		if err != nil {
			b.Fatalf("find item failed: %v", err)
		}
		decrypted, err := ak.decryptDetail(vaultUUID, &item.EncDetails)
		if err != nil {
			b.Fatalf("decrypt detail failed: %v", err)
		}
		_, err = findField(decrypted, "", "password")
		if err != nil {
			b.Fatalf("find field failed: %v", err)
		}
	}
}

// BenchmarkFullRead measures the complete end-to-end cost of reading a single
// field: key derivation + vault lookup + item decrypt + field extraction.
// This is the equivalent of `opcli read op://vault/item/field`.
func BenchmarkFullRead(b *testing.B) {
	env := setupBenchEnv(b)
	b.Cleanup(env.cleanup)

	acct := env.testDB.Accounts[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ak, err := newAccountKeychain(env.db, acct.Password, acct.SecretKey, acct.Email, acct.UUID, "I", nil)
		if err != nil {
			b.Fatalf("key derivation failed: %v", err)
		}
		vaultUUID, err := ak.findVaultByName("Private", false, nil)
		if err != nil {
			b.Fatalf("find vault failed: %v", err)
		}
		item, err := ak.findItemByName(vaultUUID, "Test Login", nil)
		if err != nil {
			b.Fatalf("find item failed: %v", err)
		}
		decrypted, err := ak.decryptDetail(vaultUUID, &item.EncDetails)
		if err != nil {
			b.Fatalf("decrypt detail failed: %v", err)
		}
		_, err = findField(decrypted, "", "password")
		if err != nil {
			b.Fatalf("find field failed: %v", err)
		}
	}
}

// Regression thresholds. Each benchmark must complete within its threshold
// (median of 3 runs). Thresholds have ~4-6x headroom above observed baselines
// to accommodate CI variance while still catching meaningful regressions.
//
// Observed baselines (mac mini, 100k PBKDF2 iterations):
//   KeyDerivation: ~12ms   (HKDF + PBKDF2 + RSA decrypt)
//   ItemDecrypt:   ~1ms    (DB queries + AES-GCM + RSA-OAEP)
//   FullRead:      ~12ms   (key derivation + item decrypt)
var regressionThresholds = map[string]time.Duration{
	"BenchmarkKeyDerivation": 50 * time.Millisecond,
	"BenchmarkItemDecrypt":   10 * time.Millisecond,
	"BenchmarkFullRead":      75 * time.Millisecond,
}

// TestBenchmarkRegressions runs each benchmark once and fails if any exceeds
// its threshold. This is a regular test (not a benchmark) so it runs as part
// of `go test` / `make test`.
func TestBenchmarkRegressions(b *testing.T) {
	env := setupRegressionEnv(b)
	b.Cleanup(env.cleanup)

	acct := env.testDB.Accounts[0]

	type benchCase struct {
		name string
		fn   func() error
	}

	// Pre-derive keys for the item-decrypt-only case
	ak, err := newAccountKeychain(env.db, acct.Password, acct.SecretKey, acct.Email, acct.UUID, "I", nil)
	if err != nil {
		b.Fatalf("key derivation failed: %v", err)
	}

	cases := []benchCase{
		{
			name: "BenchmarkKeyDerivation",
			fn: func() error {
				_, err := newAccountKeychain(env.db, acct.Password, acct.SecretKey, acct.Email, acct.UUID, "I", nil)
				return err
			},
		},
		{
			name: "BenchmarkItemDecrypt",
			fn: func() error {
				// Clear vault key cache
				ak.vaultKeysMu.Lock()
				ak.vaultKeys = make(map[string][]byte)
				ak.vaultKeysMu.Unlock()

				vaultUUID, err := ak.findVaultByName("Private", false, nil)
				if err != nil {
					return err
				}
				item, err := ak.findItemByName(vaultUUID, "Test Login", nil)
				if err != nil {
					return err
				}
				decrypted, err := ak.decryptDetail(vaultUUID, &item.EncDetails)
				if err != nil {
					return err
				}
				_, err = findField(decrypted, "", "password")
				return err
			},
		},
		{
			name: "BenchmarkFullRead",
			fn: func() error {
				freshAK, err := newAccountKeychain(env.db, acct.Password, acct.SecretKey, acct.Email, acct.UUID, "I", nil)
				if err != nil {
					return err
				}
				vaultUUID, err := freshAK.findVaultByName("Private", false, nil)
				if err != nil {
					return err
				}
				item, err := freshAK.findItemByName(vaultUUID, "Test Login", nil)
				if err != nil {
					return err
				}
				decrypted, err := freshAK.decryptDetail(vaultUUID, &item.EncDetails)
				if err != nil {
					return err
				}
				_, err = findField(decrypted, "", "password")
				return err
			},
		},
	}

	// Run 3 iterations of each and take the median
	const iterations = 3
	for _, tc := range cases {
		threshold, ok := regressionThresholds[tc.name]
		if !ok {
			b.Fatalf("no threshold defined for %s", tc.name)
		}

		durations := make([]time.Duration, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			if err := tc.fn(); err != nil {
				b.Fatalf("%s iteration %d failed: %v", tc.name, i, err)
			}
			durations[i] = time.Since(start)
		}

		// Sort and take median
		sortDurations(durations)
		median := durations[iterations/2]

		b.Logf("%s: median=%v threshold=%v", tc.name, median, threshold)
		if median > threshold {
			b.Errorf("%s regression: median %v exceeds threshold %v", tc.name, median, threshold)
		}
	}
}

// setupRegressionEnv is like setupBenchEnv but for *testing.T
func setupRegressionEnv(t *testing.T) *benchEnv {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "opcli-bench-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	testDB, err := CreateTestDatabase(tmpDir, false)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create test database: %v", err)
	}

	db, err := sql.Open("sqlite3", testDB.Path)
	if err != nil {
		testDB.Cleanup()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open database: %v", err)
	}

	return &benchEnv{db: db, testDB: testDB, tmpDir: tmpDir}
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}
