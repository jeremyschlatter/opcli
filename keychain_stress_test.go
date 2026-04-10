package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestKeychainConcurrentRead hammers keychainGet from many goroutines to reproduce
// the transient errSecItemNotFound (-25300) under concurrent access.
//
// The macOS Keychain (via securityd XPC) can transiently return "not found" when
// multiple callers read the same item concurrently. This test stores a keychain
// entry, then fires many goroutines reading it simultaneously.
//
// Must be run via `make sign-test` (requires code signing for Keychain ACL access).
func TestKeychainConcurrentRead(t *testing.T) {
	// Use test-specific keychain service (set by stubs_testing.go init())
	const testAccount = "stress-test-creds"
	testData := `{"accounts":{"test-uuid":{"password":"test-pw"}},"default":"test-uuid"}`

	// Store test data in keychain
	if err := keychainSet(testAccount, testData); err != nil {
		t.Fatalf("setup: keychainSet failed: %v (binary may need code signing — run via make sign-test)", err)
	}
	t.Cleanup(func() {
		keychainDelete(testAccount)
	})

	// Verify single read works
	val, err := keychainGet(testAccount)
	if err != nil {
		t.Fatalf("setup: keychainGet failed: %v", err)
	}
	if val != testData {
		t.Fatalf("setup: got %q, want %q", val, testData)
	}

	const (
		goroutines = 50
		iterations = 100
	)

	var (
		failures atomic.Int64
		total    atomic.Int64
		wg       sync.WaitGroup
	)

	// Barrier: all goroutines start at approximately the same time
	ready := make(chan struct{})

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-ready // wait for barrier

			for i := 0; i < iterations; i++ {
				total.Add(1)
				val, err := keychainGet(testAccount)
				if err != nil {
					failures.Add(1)
					if failures.Load() <= 5 {
						t.Logf("goroutine %d iter %d: keychainGet error: %v", id, i, err)
					}
					continue
				}
				if val != testData {
					t.Errorf("goroutine %d iter %d: got wrong data (len=%d, want len=%d)", id, i, len(val), len(testData))
				}
			}
		}(g)
	}

	// Release all goroutines
	close(ready)
	wg.Wait()

	totalCount := total.Load()
	failCount := failures.Load()
	rate := float64(failCount) / float64(totalCount) * 100

	t.Logf("Results: %d/%d failures (%.4f%%)", failCount, totalCount, rate)

	if failCount > 0 {
		t.Logf("Reproduced transient keychain failure: %d failures in %d reads (%.4f%%)", failCount, totalCount, rate)
	} else {
		t.Logf("No failures reproduced in %d concurrent reads", totalCount)
	}
}

// TestKeychainConcurrentReadWrite exercises concurrent reads while writes are also
// happening, which is a more aggressive concurrency pattern that stresses the
// securityd XPC channel and Keychain database file locking.
func TestKeychainConcurrentReadWrite(t *testing.T) {
	const testAccount = "stress-test-rw"
	testData := `{"accounts":{"test-uuid":{"password":"test-pw"}},"default":"test-uuid"}`

	if err := keychainSet(testAccount, testData); err != nil {
		t.Fatalf("setup: keychainSet failed: %v (binary may need code signing — run via make sign-test)", err)
	}
	t.Cleanup(func() {
		keychainDelete(testAccount)
	})

	const (
		readers    = 30
		writers    = 5
		iterations = 50
	)

	var (
		failures atomic.Int64
		total    atomic.Int64
		wg       sync.WaitGroup
	)

	ready := make(chan struct{})

	// Readers
	for g := 0; g < readers; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-ready

			for i := 0; i < iterations; i++ {
				total.Add(1)
				_, err := keychainGet(testAccount)
				if err != nil {
					failures.Add(1)
					if failures.Load() <= 5 {
						t.Logf("reader %d iter %d: %v", id, i, err)
					}
				}
			}
		}(g)
	}

	// Writers (re-write same data to cause contention)
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-ready

			for i := 0; i < iterations; i++ {
				updated := fmt.Sprintf(`{"accounts":{"test-uuid":{"password":"test-pw-%d-%d"}},"default":"test-uuid"}`, id, i)
				if err := keychainSet(testAccount, updated); err != nil {
					t.Logf("writer %d iter %d: keychainSet error: %v", id, i, err)
				}
			}
		}(g)
	}

	close(ready)
	wg.Wait()

	totalCount := total.Load()
	failCount := failures.Load()
	rate := float64(failCount) / float64(totalCount) * 100

	t.Logf("Read/Write results: %d/%d failures (%.4f%%)", failCount, totalCount, rate)

	if failCount > 0 {
		t.Logf("Reproduced transient failure under read/write contention: %d failures in %d reads (%.4f%%)", failCount, totalCount, rate)
	} else {
		t.Logf("No failures reproduced in %d concurrent reads with %d writers", totalCount, writers)
	}
}
