package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// tryKeychainAccess checks if the keychain is accessible from this process.
// Returns false if the binary is unsigned or keychain access is restricted.
func tryKeychainAccess() bool {
	testKey := "opcli-access-probe"
	err := keychainSet(testKey, "probe")
	if err != nil {
		return false
	}
	keychainDelete(testKey)
	return true
}

// TestKeychainConcurrentRead verifies that concurrent keychainGet calls
// on an existing item all succeed. This is the baseline — pure reads
// should never fail.
func TestKeychainConcurrentRead(t *testing.T) {
	if !tryKeychainAccess() {
		t.Skip("keychain not accessible (binary may be unsigned)")
	}

	testAccount := "concurrent-read-test"
	testValue := "test-value-for-concurrent-reads"
	if err := keychainSet(testAccount, testValue); err != nil {
		t.Fatalf("setup keychainSet failed: %v", err)
	}
	t.Cleanup(func() { keychainDelete(testAccount) })

	const goroutines = 50
	const iterations = 100

	var failures atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				val, err := keychainGet(testAccount)
				if err != nil {
					failures.Add(1)
					continue
				}
				if val != testValue {
					t.Errorf("keychainGet returned wrong value: got %q, want %q", val, testValue)
				}
			}
		}()
	}
	wg.Wait()

	if f := failures.Load(); f > 0 {
		t.Errorf("keychainGet failed %d/%d times under concurrent reads (no writes)", f, goroutines*iterations)
	}
}

// TestKeychainConcurrentReadWrite verifies that keychainSet's atomic update
// (SecItemUpdate) eliminates the errSecItemNotFound race. Concurrent readers
// should never see "not found" while writers are updating the same item.
func TestKeychainConcurrentReadWrite(t *testing.T) {
	if !tryKeychainAccess() {
		t.Skip("keychain not accessible (binary may be unsigned)")
	}

	testAccount := "concurrent-rw-test"
	if err := keychainSet(testAccount, "initial-value"); err != nil {
		t.Fatalf("setup keychainSet failed: %v", err)
	}
	t.Cleanup(func() { keychainDelete(testAccount) })

	const readers = 30
	const writers = 5
	const iterations = 100

	var readFailures atomic.Int64
	var readSuccesses atomic.Int64
	var writeFailures atomic.Int64

	var wg sync.WaitGroup
	wg.Add(readers + writers)

	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, err := keychainGet(testAccount)
				if err != nil {
					readFailures.Add(1)
				} else {
					readSuccesses.Add(1)
				}
			}
		}()
	}

	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				val := fmt.Sprintf("value-writer%d-iter%d", w, i)
				if err := keychainSet(testAccount, val); err != nil {
					writeFailures.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	rf := readFailures.Load()
	rs := readSuccesses.Load()
	wf := writeFailures.Load()
	total := int64(readers * iterations)

	t.Logf("Results: %d/%d reads succeeded, %d read failures, %d write failures",
		rs, total, rf, wf)

	if rf > 0 {
		t.Errorf("%d/%d reads failed under concurrent read/write — "+
			"keychainSet should use atomic SecItemUpdate, not delete-then-add", rf, total)
	}
}

// TestE2E_KeychainConcurrent runs concurrent CLI invocations to trigger
// the race condition at the e2e level. Each `opcli read` with a cache miss
// calls SetCachedSymKey -> saveCredentialStore -> keychainSet, creating
// the delete+add window.
func TestE2E_KeychainConcurrent(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })

	const concurrency = 20
	const iterations = 5

	var failures atomic.Int64
	var successes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for g := 0; g < concurrency; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Each invocation uses a fresh session key to force
				// authentication, which triggers SetCachedSymKey -> keychainSet
				sessionKey := fmt.Sprintf("concurrent-test-%d-%d", g, i)
				_, stderr, code := env.runCLI("", "", map[string]string{
					"OPCLI_TEST_SESSION_KEY": sessionKey,
				}, "read", "op://Private/Test Login/password")
				if code != 0 {
					failures.Add(1)
					if i == 0 && g == 0 {
						t.Logf("CLI failure (g=%d, i=%d): exit=%d stderr=%s", g, i, code, stderr)
					}
				} else {
					successes.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	total := int64(concurrency * iterations)
	f := failures.Load()
	s := successes.Load()
	t.Logf("E2E concurrent results: %d/%d succeeded, %d failures", s, total, f)

	if f > 0 {
		t.Errorf("%d/%d CLI invocations failed under concurrent access — "+
			"keychainSet should use atomic SecItemUpdate", f, total)
	}
}
