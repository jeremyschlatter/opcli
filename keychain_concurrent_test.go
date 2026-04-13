package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// useIsolatedKeychainService overrides the package-level keychainService for the
// duration of the test so we don't pollute the user's real "opcli" keychain items.
// (The stubs_testing.go init only runs under the `test` build tag used by the CLI
// binary; plain `go test` builds don't set that tag.)
func useIsolatedKeychainService(t *testing.T) {
	t.Helper()
	orig := keychainService
	keychainService = "opcli-concurrent-test"
	t.Cleanup(func() { keychainService = orig })
}

// stressIters returns the stress-test multiplier. Defaults to 1 (bounded,
// runs in default `make test`). Set OPCLI_STRESS=N (e.g. 1000) to run the
// heavier variants used to chase rare races locally.
func stressIters() int {
	s := os.Getenv("OPCLI_STRESS")
	if s == "" {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// TestKeychainConcurrentRead verifies that concurrent keychainGet calls
// on an existing item all succeed. Pure reads should never fail.
func TestKeychainConcurrentRead(t *testing.T) {
	useIsolatedKeychainService(t)

	testAccount := "opcli-concurrent-read-test"
	testValue := "test-value-for-concurrent-reads"
	if err := keychainSet(testAccount, testValue); err != nil {
		t.Fatalf("setup keychainSet failed: %v", err)
	}
	t.Cleanup(func() { keychainDelete(testAccount) })

	const goroutines = 20
	const baseIterations = 10
	iterations := baseIterations * stressIters()

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
		t.Errorf("keychainGet failed %d/%d times under concurrent reads (no writes)", f, int64(goroutines)*int64(iterations))
	}
}

// TestKeychainConcurrentReadWrite exercises the previously racy path:
// keychainSet used to do SecItemDelete + SecItemAdd, leaving a window where
// concurrent keychainGet saw errSecItemNotFound. With the SecItemUpdate fix,
// readers should see either old or new data, never "not found".
//
// Bounded for default `make test`: set OPCLI_STRESS=N to amplify iterations.
func TestKeychainConcurrentReadWrite(t *testing.T) {
	useIsolatedKeychainService(t)

	testAccount := "opcli-concurrent-rw-test"
	if err := keychainSet(testAccount, "initial-value"); err != nil {
		t.Fatalf("setup keychainSet failed: %v", err)
	}
	t.Cleanup(func() { keychainDelete(testAccount) })

	const readers = 20
	const writers = 3
	const baseIterations = 20
	iterations := baseIterations * stressIters()

	var readFailures atomic.Int64
	var writeFailures atomic.Int64

	var wg sync.WaitGroup
	wg.Add(readers + writers)

	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, err := keychainGet(testAccount); err != nil {
					readFailures.Add(1)
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

	if rf := readFailures.Load(); rf > 0 {
		t.Errorf("concurrent reads failed %d/%d times — delete/add race may have regressed",
			rf, int64(readers)*int64(iterations))
	}
	if wf := writeFailures.Load(); wf > 0 {
		t.Errorf("concurrent writes failed %d/%d times", wf, int64(writers)*int64(iterations))
	}
}

// TestKeychainSetAddThenUpdate verifies keychainSet creates items on first call
// (SecItemAdd path) and updates them on subsequent calls (SecItemUpdate path).
// Both paths must produce a readable item with the expected value.
func TestKeychainSetAddThenUpdate(t *testing.T) {
	useIsolatedKeychainService(t)

	testAccount := "opcli-add-then-update-test"
	// Ensure clean state.
	keychainDelete(testAccount)
	t.Cleanup(func() { keychainDelete(testAccount) })

	// First call: item doesn't exist → SecItemAdd path.
	if err := keychainSet(testAccount, "v1"); err != nil {
		t.Fatalf("initial keychainSet failed: %v", err)
	}
	got, err := keychainGet(testAccount)
	if err != nil {
		t.Fatalf("keychainGet after initial set: %v", err)
	}
	if got != "v1" {
		t.Errorf("after initial set: got %q, want %q", got, "v1")
	}

	// Second call: item exists → SecItemUpdate path.
	if err := keychainSet(testAccount, "v2"); err != nil {
		t.Fatalf("update keychainSet failed: %v", err)
	}
	got, err = keychainGet(testAccount)
	if err != nil {
		t.Fatalf("keychainGet after update: %v", err)
	}
	if got != "v2" {
		t.Errorf("after update: got %q, want %q", got, "v2")
	}
}
